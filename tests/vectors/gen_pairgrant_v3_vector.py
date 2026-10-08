#!/usr/bin/env python3
"""Independent generator for the pairing v3 (group-state-bound) known-answer vector.

Written from the decision text (cbcl-bus copied-group-id/decision-candidate.md, as
approved), NOT from hark's Rust:

  lp(x)   = u32-be(len(x)) || x
  context = lp(label) || lp(room) || lp(raw group id) || lp(raw canonical TLS
            GroupContext) || lp(signer handle) || lp(signer key) ||
            lp(subject handle) || lp(subject key) || u64-be(not_after_ms)

Ed25519 (RFC 8032, deterministic) by the signer's seed. The GroupContext is
hand-encoded per RFC 9420 §8.1 with the §2.1.2 variable-length integer prefix:
version u16 || cipher_suite u16 || group_id<V> || epoch u64 || tree_hash<V> ||
confirmed_transcript_hash<V> || extensions<V>, each Extension being
extension_type u16 || extension_data<V>.

hark's `tests/pairgrant_v3_vector.rs` and the browser contract both check their
implementations against the JSON this writes.

Usage: python3 tests/vectors/gen_pairgrant_v3_vector.py > tests/vectors/pairgrant-v3-context-vector.json
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def lp(b): return struct.pack(">I", len(b)) + b
def pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def sign(seed, msg): return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
b64 = lambda b: base64.b64encode(b).decode()

def varint(n):  # RFC 9420 §2.1.2, minimal encoding
    if n < 1 << 6: return bytes([n])
    if n < 1 << 14: return struct.pack(">H", 0x4000 | n)
    if n < 1 << 30: return struct.pack(">I", 0x80000000 | n)
    raise ValueError(n)
def vl(b): return varint(len(b)) + b

def group_context(gid, epoch, tree_hash, transcript, extensions):
    exts = b"".join(struct.pack(">H", t) + vl(d) for t, d in extensions)
    return (struct.pack(">HH", 1, 0x0001) + vl(gid) + struct.pack(">Q", epoch)
            + vl(tree_hash) + vl(transcript) + vl(exts))

LABEL = b"cbcl-mls-pairgrant/v3"
room = "@research"
group_id = bytes(range(32))
signer_handle, signer_seed = "@user-qp2zs", bytes([0x5A] * 32)
subject_handle, subject_seed = "@agent6", bytes([0x6B] * 32)
not_after_ms = 1_785_000_000_000
signer_key, subject_key = pub(signer_seed), pub(subject_seed)
GENESIS_EXT = [(0xF013, bytes.fromhex("deadbeef"))]

gctx = group_context(group_id, 7, bytes([0x11] * 32), bytes([0x22] * 32), GENESIS_EXT)
# A rival under the COPIED group id, same epoch, different tree.
rival_ctx = group_context(group_id, 7, bytes([0xDD] * 32), bytes([0x22] * 32), GENESIS_EXT)
# The genuine group one Commit later.
stale_ctx = group_context(group_id, 8, bytes([0x11] * 32), bytes([0x33] * 32), GENESIS_EXT)
other_group = group_id[:-1] + bytes([group_id[-1] ^ 0xFF])

def context(label, gid, gc):
    out = lp(label) + lp(room.encode())
    if gid is not None:
        out += lp(gid)
    if gc is not None:
        out += lp(gc)
    return (out + lp(signer_handle.encode()) + lp(signer_key) + lp(subject_handle.encode())
            + lp(subject_key) + struct.pack(">Q", not_after_ms))

ctx = context(LABEL, group_id, gctx)
sig = sign(signer_seed, ctx)
grant = {
    "kind": LABEL.decode(), "room": room, "group_id_b64": b64(group_id),
    "group_context_b64": b64(gctx),
    "signer_handle": signer_handle, "signer_key_b64": b64(signer_key),
    "subject_handle": subject_handle, "subject_key_b64": b64(subject_key),
    "not_after_ms": not_after_ms, "sig_b64": b64(sig),
}
v2 = {k: v for k, v in grant.items() if k != "group_context_b64"}
v2.update(kind="cbcl-mls-pairgrant/v2", sig_b64=b64(sign(signer_seed, context(b"cbcl-mls-pairgrant/v2", group_id, None))))
v1 = {k: v for k, v in v2.items() if k != "group_id_b64"}
v1.update(kind="cbcl-mls-pairgrant/v1", sig_b64=b64(sign(signer_seed, context(b"cbcl-mls-pairgrant/v1", None, None))))
compact = lambda o: json.dumps(o, separators=(",", ":"))

def case(name, grant_json, expect, gid=group_id, gc=gctx, **extra):
    return {"name": name, "group_id_hex": gid.hex(), "group_context_hex": gc.hex(),
            "grant_json": grant_json, "expect": expect, **extra}

doc = {
    "name": "cbcl-mls-pairgrant/v3 shared known-answer vector",
    "decision": "cbcl-bus docs/planning/svelte-chat-migration/implementation/extraction/copied-group-id/decision-candidate.md (commit 549c0d80), approved by the human domain reviewer",
    "layout": "lp(label) || lp(room) || lp(raw group id) || lp(raw canonical TLS GroupContext) || lp(signer handle) || lp(signer key) || lp(subject handle) || lp(subject key) || u64be(not_after_ms); lp(x) = u32be(len x) || x",
    "group_context_layout": "RFC 9420 GroupContext: u16 version || u16 cipher_suite || group_id<V> || u64 epoch || tree_hash<V> || confirmed_transcript_hash<V> || extensions<V>; <V> = RFC 9420 2.1.2 varint length",
    "judged_context": "joiner: the signature-verified GroupInfo's GroupContext BEFORE its external Commit; member: its own GroupContext BEFORE merging the Commit",
    "inputs": {
        "label": LABEL.decode(), "room": room, "group_id_hex": group_id.hex(),
        "group_context_hex": gctx.hex(),
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
        case("genuine", compact(grant), "accept"),
        case("other-group", compact(grant), "reject:group", gid=other_group),
        case("copied-group-id-other-context", compact(grant), "reject:context", gc=rival_ctx),
        case("stale-epoch", compact(grant), "reject:context", gc=stale_ctx),
        case("relabelled-context", compact({**grant, "group_context_b64": b64(rival_ctx)}),
             "reject:signature", gc=rival_ctx),
        case("relabelled-group", compact({**grant, "group_id_b64": b64(other_group)}),
             "reject:signature", gid=other_group),
        case("v2-record", compact(v2), "reject:kind"),
        case("v1-record", compact(v1), "reject:kind"),
        case("v3-missing-context", compact({**v2, "kind": LABEL.decode()}), "reject:record"),
        case("unknown-key", compact({**grant, "extra": 1}), "reject:record"),
        case("expired", compact(grant), "reject:expired", now_ms=not_after_ms),
    ],
}
json.dump(doc, sys.stdout, indent=2)
sys.stdout.write("\n")
