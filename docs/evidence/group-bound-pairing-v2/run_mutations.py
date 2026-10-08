#!/usr/bin/env python3
"""Red-mutation evidence for group-bound pairing v2.

Each mutation removes or weakens ONE guard in the working tree, runs the named
tests, records whether they went red, and restores the file byte-for-byte. A
mutation that leaves every named test green is a test gap and fails this run.

Usage (from the repo root): python3 docs/evidence/group-bound-pairing-v2/run_mutations.py
"""
import pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]

MUTATIONS = [
    ("M1 drop group-id equality in PairingGrant::verify (restores v1 authority)",
     "src/mls/group.rs",
     "        if bound_group != group_id {\n            return Err(MlsError::Rejected(\n                \"pairing grant is bound to a different MLS group",
     "        if false && bound_group != group_id {\n            return Err(MlsError::Rejected(\n                \"pairing grant is bound to a different MLS group",
     ["a_rival_same_room_group_info", "a_grant_for_another_group", "a_rival_group_info_yields", "hark_decides_every_vector_case"]),
    ("M2 drop lp(group_id) from the signed context",
     "src/mls/pins.rs",
     "    lp(&mut out, room.as_bytes());\n    lp(&mut out, group_id);\n",
     "    lp(&mut out, room.as_bytes());\n    let _ = group_id;\n",
     ["pairgrant_signing_bytes_cross_stack_vector", "a_grant_for_another_group", "hark_reproduces_the_v2_context", "hark_decides_every_vector_case"]),
    ("M3 route an unsupported pairing kind to the invite path",
     "src/mls/group.rs",
     ["        Some(other) => Err(MlsError::Rejected(format!(",
      "        None => {\n            // SPEC-061 REQ-002: authorised by the creator, bearer, bound to a token."],
     ["        Some(other) if other.is_null() && false => Err(MlsError::Rejected(format!(",
      "        _ => {\n            // SPEC-061 REQ-002: authorised by the creator, bearer, bound to a token."],
     ["old_unknown_and_malformed_pairing_records", "hark_decides_every_vector_case"]),
    ("M4 joiner installs without verify_external_join",
     "src/mls/group.rs",
     "    match verify_external_join(&joined.group, identity, room, grant_json, &joined.genesis, pins, now_ms) {",
     "    match Ok::<(), MlsError>(()) {",
     ["a_rival_same_room_group_info", "a_member_authorises_an_agent", "a_grant_for_another_group", "joiner_refuses_group_info_conflicting", "a_rival_group_info_yields"]),
    ("M5 joiner refusal without provider rollback",
     "src/mls/group.rs",
     "            drop(joined);\n            provider.rollback_to_disk()?;\n            Err(e)",
     "            drop(joined);\n            Err(e)",
     ["a_rival_same_room_group_info", "a_member_authorises_an_agent", "a_rival_group_info_yields"]),
    ("M6 pairing record no longer closed (deny_unknown_fields removed)",
     "src/mls/group.rs",
     "#[serde(deny_unknown_fields)]\npub struct PairingGrant {",
     "pub struct PairingGrant {",
     ["old_unknown_and_malformed_pairing_records", "hark_decides_every_vector_case"]),
    ("M7 joiner skips tree leaf-vs-pin (REQ-012d)",
     "src/mls/group.rs",
     "            if member.signature_key != pin.key {\n                return Err(MlsError::Rejected(format!(\n                    \"group info tree leaf",
     "            if false && member.signature_key != pin.key {\n                return Err(MlsError::Rejected(format!(\n                    \"group info tree leaf",
     ["joiner_refuses_group_info_conflicting"]),
    ("M8 member (recipient) side trusts the group id the grant itself names",
     "src/mls/validation.rs",
     "        group.group_id().as_slice(),\n        &handle,",
     "        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, serde_json::from_str::<serde_json::Value>(&presented.grant_json).ok().and_then(|v| v.get(\"group_id_b64\").and_then(|g| g.as_str()).map(str::to_owned)).unwrap_or_default()).unwrap_or_default(),\n        &handle,",
     ["a_grant_for_another_group"]),
]

def run(filters):
    red = []
    for f in filters:
        r = subprocess.run(["cargo", "test", "--quiet", "--lib", "--test", "pairgrant_v2_vector", f],
                           cwd=ROOT, capture_output=True, text=True)
        out = r.stdout + r.stderr
        if "error[" in out or "could not compile" in out:
            return None, out
        ran = "test result: ok. 0 passed" not in out or "FAILED" in out
        if r.returncode != 0:
            red.append(f)
    return red, ""

failures = 0
for name, rel, old, new, filters in MUTATIONS:
    path = ROOT / rel
    original = path.read_bytes()
    text = original.decode()
    olds, news = ([old], [new]) if isinstance(old, str) else (old, new)
    if any(text.count(o) != 1 for o in olds):
        print(f"{name}: SITE NOT FOUND EXACTLY ONCE — runner is stale")
        failures += 1
        continue
    for o, n in zip(olds, news):
        text = text.replace(o, n)
    try:
        path.write_text(text)
        red, err = run(filters)
    finally:
        path.write_bytes(original)
    if red is None:
        print(f"{name}: MUTANT DID NOT COMPILE\n{err[-2000:]}")
        failures += 1
    elif red:
        print(f"{name}: KILLED by {', '.join(red)} (green: {', '.join(f for f in filters if f not in red) or '-'})")
    else:
        print(f"{name}: SURVIVED — every named test stayed green")
        failures += 1

print("ALL MUTANTS KILLED" if failures == 0 else f"{failures} mutation(s) not killed")
sys.exit(1 if failures else 0)
