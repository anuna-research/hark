#!/usr/bin/env python3
"""Independent generator for the group-bound pairing v2 known-answer vector.

Written from the decision text (pairing-domain-decision.md), NOT from hark's
Rust: lp(x) = u32-be(len(x)) || x; context = lp(label) || lp(room) ||
lp(raw group id) || lp(signer handle) || lp(signer key) || lp(subject handle) ||
lp(subject key) || u64-be(not_after_ms); Ed25519 (RFC 8032, deterministic) by the
signer's seed. hark's `tests/pairgrant_v2_vector.rs` and the browser contract
both check their implementations against the JSON this writes.

Usage: python3 tests/vectors/gen_pairgrant_v2_vector.py > tests/vectors/pairgrant-v2-context-vector.json
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def lp(b): return struct.pack(">I", len(b)) + b
def pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def sign(seed, msg): return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
b64 = lambda b: base64.b64encode(b).decode()

LABEL = b"cbcl-mls-pairgrant/v2"
room = "@research"
group_id = bytes(range(32))
signer_handle, signer_seed = "@user-qp2zs", bytes([0x5A] * 32)
subject_handle, subject_seed = "@agent6", bytes([0x6B] * 32)
not_after_ms = 1_785_000_000_000
signer_key, subject_key = pub(signer_seed), pub(subject_seed)

def context(label, gid):
    out = lp(label) + lp(room.encode())
    if gid is not None:
        out += lp(gid)
    return (out + lp(signer_handle.encode()) + lp(signer_key) + lp(subject_handle.encode())
            + lp(subject_key) + struct.pack(">Q", not_after_ms))

ctx = context(LABEL, group_id)
sig = sign(signer_seed, ctx)
grant = {
    "kind": LABEL.decode(), "room": room, "group_id_b64": b64(group_id),
    "signer_handle": signer_handle, "signer_key_b64": b64(signer_key),
    "subject_handle": subject_handle, "subject_key_b64": b64(subject_key),
    "not_after_ms": not_after_ms, "sig_b64": b64(sig),
}
other_group = group_id[:-1] + bytes([group_id[-1] ^ 0xFF])
v1_ctx = context(b"cbcl-mls-pairgrant/v1", None)
v1 = {k: v for k, v in grant.items() if k != "group_id_b64"}
v1.update(kind="cbcl-mls-pairgrant/v1", sig_b64=b64(sign(signer_seed, v1_ctx)))
compact = lambda o: json.dumps(o, separators=(",", ":"))

doc = {
    "name": "cbcl-mls-pairgrant/v2 shared known-answer vector",
    "decision": "cbcl-bus docs/planning/svelte-chat-migration/implementation/extraction/pairing-domain-decision.md",
    "layout": "lp(label) || lp(room) || lp(raw group id) || lp(signer handle) || lp(signer key) || lp(subject handle) || lp(subject key) || u64be(not_after_ms); lp(x) = u32be(len x) || x",
    "inputs": {
        "label": LABEL.decode(), "room": room, "group_id_hex": group_id.hex(),
        "signer_handle": signer_handle, "signer_seed_hex": signer_seed.hex(), "signer_key_hex": signer_key.hex(),
        "subject_handle": subject_handle, "subject_seed_hex": subject_seed.hex(), "subject_key_hex": subject_key.hex(),
        "not_after_ms": not_after_ms,
    },
    "context_hex": ctx.hex(),
    "context_sha256_hex": hashlib.sha256(ctx).hexdigest(),
    "signature_b64": b64(sig),
    "grant_json": compact(grant),
    "grant_json_key_order_normative": False,
    "verify_now_ms": not_after_ms - 1,
    "verify_live_leaves": [{"handle": signer_handle, "key_hex": signer_key.hex()}],
    "cases": [
        {"name": "genuine", "group_id_hex": group_id.hex(), "grant_json": compact(grant), "expect": "accept"},
        {"name": "other-group", "group_id_hex": other_group.hex(), "grant_json": compact(grant), "expect": "reject:group"},
        {"name": "relabelled-group", "group_id_hex": other_group.hex(),
         "grant_json": compact({**grant, "group_id_b64": b64(other_group)}), "expect": "reject:signature"},
        {"name": "v1-record", "group_id_hex": group_id.hex(), "grant_json": compact(v1), "expect": "reject:kind"},
        {"name": "v2-kind-missing-group", "group_id_hex": group_id.hex(),
         "grant_json": compact({**v1, "kind": LABEL.decode()}), "expect": "reject:record"},
        {"name": "unknown-key", "group_id_hex": group_id.hex(),
         "grant_json": compact({**grant, "extra": 1}), "expect": "reject:record"},
        {"name": "expired", "group_id_hex": group_id.hex(), "grant_json": compact(grant),
         "now_ms": not_after_ms, "expect": "reject:expired"},
    ],
}
json.dump(doc, sys.stdout, indent=2)
sys.stdout.write("\n")
