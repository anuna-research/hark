use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{
    Result, fail,
    policy::{Argument, Policy, Program},
};
use crate::{local_api::RecvResponse, object_transport::AttestedBy};

pub(super) fn definition() -> Value {
    json!({"version":3,"kind":"contract","name":"hark-shill-experiment",
        "verbs":{
            "open":{"after":["begin"],"fields":{"session":"string"}},
            "read":{"after":["open"],"fields":{"resource":"string"}},
            "run":{"after":["open"],"fields":{"program":"string"}},
            "invoke":{"after":["open"],"fields":{"program":"string","arguments":"list"}},
            "output":{"after":["read","run","invoke"],"fields":{"seq":"number","data":"string"}},
            "done":{"after":["read","run","invoke"],"fields":{"number":"number","exit-code":"number","elapsed-micros":"number"}}
        },
        "state":{"opened":["exists","open"],"session":["last","open","session"],"reading":["exists","read"],"running":["exists","run"],"invoking":["exists","invoke"],
            "stdout":["events","output","data"],"completed":["exists","done"],"exit-code":["last","done","exit-code"]},
        "bounds":{"maxString":2048,"maxNumber":1000000000,"maxFields":16,"maxList":32}
    })
}

type NativeExport = fn(&[u8]) -> std::result::Result<Vec<u8>, Vec<u8>>;

pub(super) fn native(function: NativeExport, input: &str) -> Result<String> {
    let bytes = function(input.as_bytes())
        .map_err(|e| anyhow::anyhow!("{}", String::from_utf8_lossy(&e)))?;
    Ok(String::from_utf8(bytes)?)
}

fn native_json(function: NativeExport, input: &str) -> Result<Value> {
    Ok(serde_json::from_str(&native(function, input)?)?)
}

pub(super) struct Dialect {
    pub name: String,
    pub cbcl: String,
}
impl Dialect {
    pub fn new() -> Result<Self> {
        let compiled = native_json(cbcl_wasm::compile_contract_bytes, &definition().to_string())?;
        let name = compiled["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("compiler returned no name"))?
            .to_owned();
        let cbcl = compiled["dialect"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("compiler returned no dialect"))?
            .to_owned();
        if native(cbcl_wasm::verify_dialect_bytes, &cbcl)? != "ok" {
            return fail("dialect verification failed");
        }
        Ok(Self { name, cbcl })
    }

    fn admit(
        &self,
        thread: &str,
        records: &[String],
        signer: &str,
        message: &str,
    ) -> Result<String> {
        let frame = format!(
            "(admit {} {} (acts {}) ({} {}))",
            self.cbcl,
            json!(thread),
            records.join(" "),
            json!(signer),
            message
        );
        let verdict = native_json(cbcl_wasm::admit_bytes, &frame)?;
        Ok(verdict["verdict"].as_str().unwrap_or("rejected").to_owned())
    }

    pub fn intend(
        &self,
        thread: &str,
        records: &[String],
        signer: &str,
        verb: &str,
        fields: &Value,
    ) -> Result<String> {
        fn literal(value: &Value) -> Result<String> {
            match value {
                Value::String(_) | Value::Number(_) => Ok(value.to_string()),
                Value::Bool(value) => Ok(if *value { "#t" } else { "#f" }.into()),
                Value::Array(values) => Ok(format!(
                    "({})",
                    values
                        .iter()
                        .map(literal)
                        .collect::<Result<Vec<_>>>()?
                        .join(" ")
                )),
                _ => fail("unsupported CBCL field value"),
            }
        }
        let fields = fields
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("fields must be an object"))?
            .iter()
            .map(|(key, value)| Ok(format!(":{key} {}", literal(value)?)))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let frame = format!(
            "(intend {} {} (acts {}) {} {verb} ({fields}))",
            self.cbcl,
            json!(thread),
            records.join(" "),
            json!(signer)
        );
        native(cbcl_wasm::intend_bytes, &frame)
    }
}

// These types have no public constructor and are never deserialised. A remote ID is
// resolved into an owned snapshot / fixed program only after native admission.
pub(super) enum Effect {
    Read(Arc<str>),
    Run(Program),
    Invoke(Program, Vec<Argument>),
}
pub(super) struct Authorized {
    pub thread: String,
    pub cid: String,
    pub records: Vec<String>,
    pub effect: Effect,
}

pub(super) enum Decision {
    Ignored,
    Unknown,
    Opened,
    Valid(Authorized),
}

pub(super) struct Authority {
    pub dialect: Dialect,
    pub policy: Policy,
    pub session: String,
    pub pending: BTreeMap<String, RecvResponse>,
    openers: BTreeMap<String, (String, String)>,
    started: Instant,
    last_effect: Option<Instant>,
    issued: usize,
    expires: Instant,
}

impl Authority {
    pub fn new(policy: Policy) -> Result<Self> {
        let started = Instant::now();
        let expires = started + Duration::from_secs(policy.manifest.lifetime_seconds);
        let session = rand::random::<[u8; 32]>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self {
            dialect: Dialect::new()?,
            policy,
            session,
            pending: BTreeMap::new(),
            openers: BTreeMap::new(),
            started,
            last_effect: None,
            issued: 0,
            expires,
        })
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires
    }
    #[cfg(test)]
    pub fn expire(&mut self) {
        self.expires = Instant::now();
    }
    pub fn remaining(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }

    pub fn receive(&mut self, envelope: RecvResponse) -> Result<Decision> {
        let manifest = &self.policy.manifest;
        let Some(record) = envelope.record.as_ref() else {
            return Ok(Decision::Ignored);
        };
        if record.signer != manifest.controller
            || record.room != manifest.room
            || record.attested_by != manifest.provenance
            || record.replayed
            || record.own
        {
            return Ok(Decision::Ignored);
        }
        if self.expired() {
            return fail("worker session expired");
        }
        if envelope.message.len() > 8192 {
            return fail("request exceeds 8 KiB");
        }
        let act = native_json(cbcl_wasm::read_act_bytes, &envelope.message)?;
        if act["dialect"] != self.dialect.name {
            return Ok(Decision::Ignored);
        }
        if act["from"] != manifest.controller || act["recipients"] != json!([manifest.room]) {
            return fail(
                "act must match its authenticated signer and exact configured room recipient",
            );
        }
        let string = |key: &str| {
            act[key]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing {key}"))
        };
        let thread = string("thread")?;
        if !thread.starts_with("shill-")
            || thread.len() > 96
            || !thread
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return fail("thread must be shill- followed by a simple ID (at most 96 bytes)");
        }
        let cid = string("address")?;
        let verb = string("verb")?;
        let entry = format!("({} {})", json!(record.signer), envelope.message);
        if verb == "open" {
            if act["fields"]["session"] != self.session {
                return fail("opener is not for this live worker session");
            }
            if self
                .dialect
                .admit(thread, &[], &record.signer, &envelope.message)?
                != "accepted"
            {
                return fail("opener rejected by native CBCL");
            }
            if let Some((address, _)) = self.openers.get(thread) {
                if address != cid {
                    return fail("thread already has a different opener");
                }
                return Ok(Decision::Ignored);
            }
            if self.openers.len() >= manifest.max_commands {
                return fail("worker session quota exhausted");
            }
            self.openers
                .insert(thread.to_owned(), (cid.to_owned(), entry));
            return Ok(Decision::Opened);
        }
        if !matches!(verb, "read" | "run" | "invoke") {
            return fail("controller may only open, read, run or invoke");
        }
        let records = self
            .openers
            .get(thread)
            .map(|(_, text)| vec![text.clone()])
            .unwrap_or_default();
        match self
            .dialect
            .admit(thread, &records, &record.signer, &envelope.message)?
            .as_str()
        {
            "pending" => {
                if self.pending.len() >= 32 && !self.pending.contains_key(cid) {
                    return fail("pending ancestry buffer full");
                }
                self.pending.insert(cid.to_owned(), envelope);
                return Ok(Decision::Unknown);
            }
            "accepted" => {}
            _ => return fail("request rejected by native CBCL"),
        }
        let id = act["fields"][if verb == "read" {
            "resource"
        } else {
            "program"
        }]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("resource/program ID required"))?;
        let effect = if verb == "read" {
            Effect::Read(
                self.policy
                    .snapshots
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("resource ID is not granted by this host"))?
                    .clone(),
            )
        } else {
            let program = manifest
                .programs
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("program ID is not granted by this host"))?
                .clone();
            if verb == "invoke" {
                let arguments = self
                    .policy
                    .bind_arguments(&program, &act["fields"]["arguments"])?;
                Effect::Invoke(program, arguments)
            } else {
                if !program.parameters.is_empty() {
                    return fail("this program requires invoke with declared parameters");
                }
                Effect::Run(program)
            }
        };
        if self.issued >= manifest.max_commands {
            return fail("worker command quota exhausted");
        }
        let now = Instant::now();
        if self.last_effect.is_some_and(|last| {
            now.duration_since(last) < Duration::from_millis(manifest.min_interval_ms)
        }) {
            return fail("worker command rate limit exceeded; retry after the configured interval");
        }
        self.last_effect = Some(now);
        self.issued += 1;
        self.pending.remove(cid);
        let mut records = records;
        records.push(entry);
        Ok(Decision::Valid(Authorized {
            thread: thread.to_owned(),
            cid: cid.to_owned(),
            records,
            effect,
        }))
    }

    pub fn uptime_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }
    pub fn provenance(&self) -> AttestedBy {
        self.policy.manifest.provenance
    }
}
