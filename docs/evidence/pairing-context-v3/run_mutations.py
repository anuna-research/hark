#!/usr/bin/env python3
"""Red-mutation evidence for pairing v3 (grants bound to the MLS GroupContext).

Each mutation removes or weakens ONE guard in the working tree, runs the named
tests, records which went red, and restores the file byte-for-byte. A mutation
that leaves every named test green is a test gap and fails this run. M1-M8 are
the v2 guards, re-sited for v3; C1-C10 are the v3 group-state guards.

Usage (from the repo root): python3 docs/evidence/pairing-context-v3/run_mutations.py
"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
VEC = "pairgrant_v3_vector"

COPIED = "a_rival_under_the_copied_public_group_id"
SESSION_RIVAL = "a_rival_group_info_yields"
STALE = "a_grant_is_stale_after_any_commit"
WRONG_CTX = "a_grant_for_another_group_state"
POSITIVE = "a_member_authorises_an_agent"

MUTATIONS = [
    # ---- v2 guards, re-sited -------------------------------------------------
    ("M1 drop group-id equality in PairingGrant::verify",
     "src/mls/group.rs",
     "        if bound_group != group_id {",
     "        if false && bound_group != group_id {",
     ["a_rival_same_room_group_info", "a_grant_for_another_group_is", "hark_decides_every_vector_case"]),
    ("M2 drop lp(group_id) from the signed context",
     "src/mls/pins.rs",
     "    lp(&mut out, group_id);\n",
     "    let _ = group_id;\n",
     ["pairgrant_signing_bytes_cross_stack_vector", "a_grant_for_another_group_is", "hark_reproduces_the_v3_context", "hark_decides_every_vector_case"]),
    ("M3 route an unsupported pairing kind (v1, v2, unknown) to the invite path",
     "src/mls/group.rs",
     ["        Some(other) => Err(MlsError::Rejected(format!(",
      "        None => {\n            // SPEC-061 REQ-002: authorised by the creator, bearer, bound to a token."],
     ["        Some(other) if other.is_null() && false => Err(MlsError::Rejected(format!(",
      "        _ => {\n            // SPEC-061 REQ-002: authorised by the creator, bearer, bound to a token."],
     ["old_unknown_and_malformed_pairing_records", "hark_decides_every_vector_case"]),
    ("M4 joiner installs without verify_external_join",
     "src/mls/group.rs",
     "    match verify_external_join(&joined, identity, room, grant_json, pins, now_ms) {",
     "    match Ok::<(), MlsError>(()) {",
     [COPIED, "a_rival_same_room_group_info", POSITIVE, STALE, SESSION_RIVAL]),
    ("M5 joiner refusal without provider rollback",
     "src/mls/group.rs",
     "            drop(joined);\n            provider.rollback_to_disk()?;\n            Err(e)",
     "            drop(joined);\n            Err(e)",
     [COPIED, "a_rival_same_room_group_info", POSITIVE, SESSION_RIVAL]),
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
    ("M8 member trusts the group id the grant itself names",
     "src/mls/validation.rs",
     "        group.group_id().as_slice(),\n        &canonical_group_context(group)?,",
     "        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, serde_json::from_str::<serde_json::Value>(&presented.grant_json).ok().and_then(|v| v.get(\"group_id_b64\").and_then(|g| g.as_str()).map(str::to_owned)).unwrap_or_default()).unwrap_or_default(),\n        &canonical_group_context(group)?,",
     ["a_grant_for_another_group_is"]),
    # ---- v3 group-state guards -----------------------------------------------
    ("C1 drop the group-context equality in PairingGrant::verify (signature still binds the judged context)",
     "src/mls/group.rs",
     "        if bound_context != group_context {",
     "        if false && bound_context != group_context {",
     [COPIED, SESSION_RIVAL, STALE, WRONG_CTX, "hark_decides_every_vector_case"]),
    ("C2 drop lp(group_context) from the signed context",
     "src/mls/pins.rs",
     "    lp(&mut out, group_context);\n",
     "    let _ = group_context;\n",
     ["pairgrant_signing_bytes_cross_stack_vector", WRONG_CTX, "hark_reproduces_the_v3_context", "hark_decides_every_vector_case"]),
    ("C3 no group-state binding at all (C1 + C2): the v2 predicate, which admits the copied-id rival",
     ["src/mls/group.rs", "src/mls/pins.rs"],
     ["        if bound_context != group_context {", "    lp(&mut out, group_context);\n"],
     ["        if false && bound_context != group_context {", "    let _ = group_context;\n"],
     [COPIED, SESSION_RIVAL, STALE]),
    ("C4 joiner judges against its POST-external-Commit context",
     "src/mls/group.rs",
     "        &joined.pre_join_context,\n",
     "        &canonical_group_context(group)?,\n",
     [POSITIVE, COPIED, STALE, SESSION_RIVAL, "a_self_seat_is_not_a_membership"]),
    ("C5 member judges against the POST-merge (staged) context",
     "src/mls/validation.rs",
     "        &canonical_group_context(group)?,\n        &handle,",
     "        &tls_codec::Serialize::tls_serialize_detached(staged.group_context()).unwrap(),\n        &handle,",
     [POSITIVE, COPIED, STALE, "a_self_seat_is_not_a_membership"]),
    ("C6 member trusts the context the grant itself names",
     "src/mls/validation.rs",
     "        &canonical_group_context(group)?,\n        &handle,",
     "        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, serde_json::from_str::<serde_json::Value>(&presented.grant_json).ok().and_then(|v| v.get(\"group_context_b64\").and_then(|g| g.as_str()).map(str::to_owned)).unwrap_or_default()).unwrap_or_default(),\n        &handle,",
     [WRONG_CTX, COPIED]),
    ("C7 joiner trusts the context the grant itself names",
     "src/mls/group.rs",
     "        &joined.pre_join_context,\n",
     "        &base64::Engine::decode(&B64, serde_json::from_str::<serde_json::Value>(grant_json).ok().and_then(|v| v.get(\"group_context_b64\").and_then(|g| g.as_str()).map(str::to_owned)).unwrap_or_default()).unwrap_or_default(),\n",
     [COPIED, WRONG_CTX, STALE, SESSION_RIVAL]),
    ("C8 minting signs an empty context instead of the admitted group's",
     "src/mls/group.rs",
     "            &canonical_group_context(group)?,\n            room,",
     "            &[],\n            room,",
     [POSITIVE, "a_self_seat_is_not_a_membership", "group_info_context_is_the_pre_join_context"]),
    ("C9 GroupInfo context reader accepts a non-GroupInfo wire format",
     "src/mls/group.rs",
     "    if wire_format != 4 {",
     "    if false && wire_format != 4 {",
     ["group_info_context_is_the_pre_join_context"]),
    # EQUIVALENT under tls_codec 0.4 / OpenMLS 0.8.1: the codec itself refuses a
    # non-minimal varint (asserted directly in group_info_context_is_the_pre_join_context),
    # and every other GroupContext field has exactly one encoding, so re-serialization
    # always reproduces the wire prefix. Kept as defence in depth against a codec change;
    # run so that a future codec that accepts loose encodings turns this into a real gap.
    ("C10 GroupInfo context reader skips the canonical-encoding check [expected equivalent]",
     "src/mls/group.rs",
     "    if !rest.starts_with(&canonical) {",
     "    if false && !rest.starts_with(&canonical) {",
     ["group_info_context_is_the_pre_join_context"]),
]

def run(filters):
    red = []
    for f in filters:
        r = subprocess.run(["cargo", "test", "--quiet", "--lib", "--test", VEC, f],
                           cwd=ROOT, capture_output=True, text=True)
        out = r.stdout + r.stderr
        if "error[" in out or "could not compile" in out:
            return None, out
        ran = sum(int(p) + int(q) for p, q in re.findall(r"(\d+) passed; (\d+) failed", out))
        if ran == 0:
            return None, f"filter {f} matched no test\n{out}"
        if r.returncode != 0:
            red.append(f)
    return red, ""

failures = 0
for name, rels, old, new, filters in MUTATIONS:
    rels = [rels] if isinstance(rels, str) else rels
    olds, news = ([old], [new]) if isinstance(old, str) else (old, new)
    originals = {rel: (ROOT / rel).read_bytes() for rel in rels}
    texts = {rel: originals[rel].decode() for rel in rels}
    ok = True
    for o, n in zip(olds, news):
        hits = [rel for rel in rels if texts[rel].count(o) == 1]
        if len(hits) != 1 or any(texts[rel].count(o) > 1 for rel in rels):
            ok = False
            break
        texts[hits[0]] = texts[hits[0]].replace(o, n)
    if not ok:
        print(f"{name}: SITE NOT FOUND EXACTLY ONCE — runner is stale")
        failures += 1
        continue
    try:
        for rel in rels:
            (ROOT / rel).write_text(texts[rel])
        red, err = run(filters)
    finally:
        for rel in rels:
            (ROOT / rel).write_bytes(originals[rel])
    if red is None:
        print(f"{name}: MUTANT DID NOT COMPILE OR FILTER EMPTY\n{err[-2000:]}")
        failures += 1
    elif red:
        print(f"{name}: KILLED by {', '.join(red)} (green: {', '.join(f for f in filters if f not in red) or '-'})")
    elif "[expected equivalent]" in name:
        print(f"{name}: SURVIVED as expected (equivalent mutant; see comment in runner)")
    else:
        print(f"{name}: SURVIVED — every named test stayed green")
        failures += 1

print("ALL MUTANTS KILLED" if failures == 0 else f"{failures} mutation(s) not killed")
sys.exit(1 if failures else 0)
