//! Native side of the R5-03 cross-stack genesis-extension probe.
//!
//! Mirrors `native_peer.rs`, but the group is created with the REQ-016 genesis
//! bytes in a pinned `Unknown(GENESIS_EXT_TYPE)` GroupContext extension and the
//! creator's leaf advertising that type. The node orchestrator
//! (`cross-stack/genesis_probe.mjs`) drives two wasm artifacts against it:
//! the REAL shipped `cbcl-mls-wasm` (default capabilities — its KeyPackage must
//! be REJECTED, the fail-closed half) and a spike-local probe build whose
//! KeyPackage advertises the capability (must be ACCEPTED and read the genesis).
//!
//! Protocol (one JSON object per line, request → single-line response):
//!   {"cmd":"add","kp":"<hex KeyPackage>"} -> {"welcome":"<hex>","members":N} | {"error":"…"}
//!   {"cmd":"decrypt","ct":"<hex>"}        -> {"plaintext":"<str>","sender_leaf":N} | {"error":"…"}
//!   {"cmd":"genesis"}                     -> {"genesis":"<hex>"}
//!   {"cmd":"bye"}                         -> exits 0

use std::io::{BufRead, Write};

use spec_013_mls_spike::{add_member, process, Party, Processed};

const GENESIS: &[u8] = b"(genesis @room :creator @native-alice :group g1 :key K)";

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

    let native = Party::new("native-alice");
    let mut group = native
        .create_group_with_genesis(GENESIS, true)
        .expect("create genesis-bearing group");

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
                    Ok(serde_json::json!({
                        "welcome": to_hex(&welcome),
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
            Some("genesis") => {
                reply(&mut out, serde_json::json!({"genesis": to_hex(GENESIS)}));
            }
            Some("bye") => break,
            other => reply(
                &mut out,
                serde_json::json!({"error": format!("unknown cmd: {other:?}")}),
            ),
        }
    }
}
