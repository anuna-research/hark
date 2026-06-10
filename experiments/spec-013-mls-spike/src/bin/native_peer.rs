//! Native side of the SPEC-013 §10 cross-stack harness (NFR-001).
//!
//! A long-lived process driving NATIVE OpenMLS 0.8.1 (the hark stack) while the
//! node orchestrator drives the REAL `cbcl-mls-wasm` artifact (the web stack).
//! They exchange MLS wire bytes as hex over a JSON-line stdio protocol, proving
//! the two stacks interoperate at the byte level — not two copies of the same
//! native code, but native ⇄ the actually-compiled `.wasm`.
//!
//! Native is the group creator + committer ("native-alice"); the wasm peer is the
//! added member. Both directions are exercised: native→wasm (Welcome + an app
//! message the wasm side decrypts) and wasm→native (an app message native decrypts).
//!
//! Protocol (one JSON object per line, request → single-line response):
//!   {"cmd":"add","kp":"<hex KeyPackage>"}  -> {"welcome":"<hex>","ct":"<hex>","members":N}
//!   {"cmd":"decrypt","ct":"<hex>"}          -> {"plaintext":"<str>","sender_leaf":N} | {"error":"…"}
//!   {"cmd":"bye"}                           -> exits 0

use std::io::{BufRead, Write};

use spec_013_mls_spike::{add_member, encrypt, process, Party, Processed};

const NATIVE_TO_WASM: &[u8] = b"hi from native (native->wasm)";

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();

    // Native is the committer: create the group and wait to add the wasm member.
    let native = Party::new("native-alice");
    let mut group = native.create_group();

    let reply = |out: &mut std::io::Stdout, v: serde_json::Value| {
        writeln!(out, "{v}").expect("write reply");
        out.flush().expect("flush");
    };

    for line in stdin.lock().lines() {
        let line = line.expect("read line");
        if line.trim().is_empty() {
            continue;
        }
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                reply(&mut out, serde_json::json!({"error": format!("bad json: {e}")}));
                continue;
            }
        };
        match msg.get("cmd").and_then(|c| c.as_str()) {
            Some("add") => {
                let kp_hex = msg.get("kp").and_then(|k| k.as_str()).unwrap_or("");
                let r = (|| -> Result<serde_json::Value, String> {
                    let kp = from_hex(kp_hex)?;
                    let (_commit, welcome) = add_member(&mut group, &native, &kp)?;
                    let ct = encrypt(&mut group, &native, NATIVE_TO_WASM);
                    Ok(serde_json::json!({
                        "welcome": to_hex(&welcome),
                        "ct": to_hex(&ct),
                        "members": group.members().count(),
                    }))
                })();
                reply(&mut out, r.unwrap_or_else(|e| serde_json::json!({"error": e})));
            }
            Some("decrypt") => {
                let ct_hex = msg.get("ct").and_then(|c| c.as_str()).unwrap_or("");
                let r = (|| -> Result<serde_json::Value, String> {
                    let wire = from_hex(ct_hex)?;
                    match process(&mut group, &native, &wire)? {
                        Processed::App(pt, leaf) => Ok(serde_json::json!({
                            "plaintext": String::from_utf8_lossy(&pt),
                            "sender_leaf": leaf.u32(),
                        })),
                        Processed::Handshake => Err("expected an application message".into()),
                    }
                })();
                reply(&mut out, r.unwrap_or_else(|e| serde_json::json!({"error": e})));
            }
            Some("bye") => break,
            other => reply(
                &mut out,
                serde_json::json!({"error": format!("unknown cmd: {other:?}")}),
            ),
        }
    }
}
