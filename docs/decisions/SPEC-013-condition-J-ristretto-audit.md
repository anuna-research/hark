# SPEC-013 Condition J — `cbcl_ristretto` Point-Validation Audit

**Date:** 2026-06-10
**Auditor:** Claude Fable 5 (agent) — condition J of [[SPEC-013-tier1-signoff]]
(IMPL-016, "`cbcl_ristretto` point-validation audit (SPAKE2 dependency), before the
pairing handshake is implemented").
**Status:** **PENDING HUMAN CRYPTO SIGN-OFF.**

> This document does **not** close condition J by itself. It is an agent-produced
> evidence package: a decode-path inventory, a set of empirically-confirmed probes,
> and a findings list. Condition J remains **OPEN** until a human reviewer with
> crypto authority reads it, checks the cited `file:line` evidence, and records an
> explicit sign-off. Per the Tier-1 gate, J binds inside IMPL-016 *before* the
> pairing handshake is implemented; this audit is the input to that decision, not
> the decision.

---

## 0. Scope and environment

The audit covers every path by which **external bytes become a Ristretto255 group
element** in the SPAKE2 pairing handshake, the dependency named by condition J.

Source under audit:

- C NIF — `/Users/anuna-02/Code/cbcl-bus/apps/cbcl_router/c_src/cbcl_ristretto.c`
- Erlang facade — `/Users/anuna-02/Code/cbcl-bus/apps/cbcl_router/src/crypto_core/cbcl_ristretto.erl`
- SPAKE2 caller — `/Users/anuna-02/Code/cbcl-bus/apps/cbcl_router/src/crypto_core/cbcl-crypto-spake2.lfe`
- Wire/driver — `cbcl-auth-shell-enrollment.lfe`, `cbcl-auth-shell-ws-handler.lfe`
- Tests — `cbcl-crypto-spake2-tests.lfe`, `cbcl-crypto-fuzz-tests.lfe`,
  `cbcl-auth-shell-enrollment-path-tests.lfe`

Underlying library: **libsodium 1.0.22**. Confirmed two ways — the dependency file
`c_src/cbcl_ristretto.d` records includes from
`/opt/homebrew/Cellar/libsodium/1.0.22/include/...`, and
`otool -L priv/cbcl_ristretto.so` shows it links `libsodium.26.dylib`
(`/opt/homebrew/opt/libsodium` → `1.0.22`). All libsodium source citations below are
from the `1.0.22-RELEASE` tag, which is the code that actually runs.

The NIF is a thin shim: it does **no** validation of its own beyond fixed-size
argument checks. **All** group-membership / canonical-encoding / identity rejection
is delegated to libsodium internals. The audit's central question is therefore
whether that delegated chain is sufficient for RFC 9382, and it is verified below by
reading the libsodium source *and* by running live probes against the compiled NIF.

---

## 1. NIF entry points and underlying calls

`cbcl_ristretto.c:119-126` registers exactly six NIFs:

| NIF | libsodium call | cbcl_ristretto.c |
|-----|----------------|------------------|
| `from_hash/1` (64→32) | `crypto_core_ristretto255_from_hash` | :44 |
| `scalar_reduce/1` (64→32) | `crypto_core_ristretto255_scalar_reduce` | :57 |
| `scalarmult/2` (scalar,point→point) | `crypto_scalarmult_ristretto255` | :69 |
| `scalarmult_base/1` (scalar→point) | `crypto_scalarmult_ristretto255_base` | :82 |
| `add/2` (point,point→point) | `crypto_core_ristretto255_add` | :97 |
| `sub/2` (point,point→point) | `crypto_core_ristretto255_sub` | :112 |

Note: `crypto_core_ristretto255_is_valid_point` is **not** exposed by the NIF and is
**not** called anywhere — point validation is only ever the side effect of
`ristretto255_frombytes` running inside `scalarmult`/`add`/`sub`. This is the basis
of finding J-1.

### libsodium decode/validation semantics (cited source)

- `ristretto255_frombytes` (ed25519 `ref10.c:2705`) **first** calls
  `ristretto255_is_canonical(s)` (`ref10.c:2717`) and returns `-1` on a
  non-canonical encoding. `ristretto255_is_canonical` (`ref10.c:2686`) rejects any
  `s` whose field element is ≥ p or whose sign bit is set — i.e. non-canonical
  encodings are unrepresentable. It then returns `-1` unless the decoded point is a
  square, has non-negative `T`, and non-zero `Y` (`ref10.c:2750-2751`). This is the
  ristretto255 guarantee: **every invalid or non-canonical 32-byte string is
  rejected; there is no cofactor/torsion component to confine.**
- `crypto_scalarmult_ristretto255` (`scalarmult_ristretto255_ref10.c:18`) returns
  `-1` if `ristretto255_frombytes` rejects the input point, **and** returns `-1` if
  the *output* is the all-zero encoding via `sodium_is_zero(q, 32)`
  (`:27-29`). This second check is the load-bearing identity defense: the shared
  secret K can never be the identity element.
- `crypto_scalarmult_ristretto255_base` (`:46-49`) has the same zero-output check.
- `crypto_core_ristretto255_add` / `_sub` (`core_ristretto255.c:30-31`, `:50-51`)
  reject invalid input points via `frombytes`, **but have no zero-output check** —
  they will happily return the identity encoding (basis of finding J-2).
- `crypto_core_ristretto255_from_hash` (`core_ristretto255.c:63`) always returns 0;
  it maps any 64 bytes to a valid point (Elligator), so M/N are valid by
  construction (finding J-5).
- `crypto_core_ristretto255_scalar_reduce` (`core_ristretto255.c:128`) reduces 64
  bytes mod L; total, no failure path, no zero-scalar rejection.
- `crypto_scalarmult_ristretto255` clamps only the high bit (`t[31] &= 127`,
  `scalarmult_ristretto255_ref10.c:24`); it does **not** do ed25519 low-bit
  clamping. This is correct for ristretto255 (scalars are taken mod L), and the
  caller always passes an already-reduced scalar.

---

## 2. Decode-path inventory (external bytes → group element)

External input in the handshake is the peer message (`msg_A` on the responder,
`msg_B` on the initiator) and the peer MAC. The wire decode is
`cbcl-auth-shell-ws-handler.lfe:166-191`: JSON → base64 → raw bytes, with **no
length check** at the wire layer — length is enforced (or not) downstream.

| NIF call site | Caller (LFE) | External input? | Validation performed | Verdict |
|---|---|---|---|---|
| `scalarmult_base x` | spake2.lfe:176 (init step0) | no (local scalar x) | size check; zero-output reject | OK (see J-6) |
| `scalarmult w (m-point)` | spake2.lfe:178 | no (w local, M const) | size; zero-output reject | OK (see J-6) |
| `add x-b w-m` | spake2.lfe:178 | no | size only; no zero-output reject | OK (output re-used only as wire msg) |
| `scalarmult w (n-point)` | spake2.lfe:187,209 | no | size; zero-output reject | OK |
| `sub msg-b w-n` | spake2.lfe:188 (init step1) | **yes — peer `msg_B`** | `frombytes` canonical+validity reject on `msg_B`; **no** zero-output reject | OK — invalid encodings rejected; identity input accepted (J-1) |
| `scalarmult x msg-b-adj` | spake2.lfe:189 | **yes (derived from peer)** | `frombytes` reject + zero-output reject ⇒ K≠identity | OK — this is the guard that makes K safe |
| `sub msg-a w-m` | spake2.lfe:213 (resp step0) | **yes — peer `msg_A`** | `frombytes` reject; no zero-output reject | OK (J-1) |
| `scalarmult y msg-a-adj` | spake2.lfe:214 | **yes (derived)** | `frombytes` + zero-output reject ⇒ K≠identity | OK |
| `from_hash …M…/…N…` | spake2.lfe:40,50 | no (fixed strings) | always valid by construction | OK (J-5) |
| `scalar_reduce eph` | spake2.lfe:152,164 | no (CSPRNG 64B) | size; reduce mod L; no zero reject | OK (J-6) |
| `scalar_reduce w-bytes` | spake2.lfe:86 | no (HKDF 64B) | size; reduce mod L | OK |
| `ct-equal? msg expected` (peer MAC) | spake2.lfe:199,224 | **yes — peer MAC** | length pre-check is **non-short-circuiting** | **FINDING J-3** |

The point-decode story is sound: the only two NIFs that consume peer-controlled
bytes as points (`sub` on the raw peer message, then `scalarmult` on the adjusted
point) reject every non-canonical/invalid encoding inside `ristretto255_frombytes`,
and the subsequent `scalarmult` rejects an identity result. The one genuine defect
on an external-input path is the MAC length pre-check (J-3), which is a MAC-handling
robustness/rate-limit bug, not a point-validation break.

---

## 3. Empirical probes (run against the compiled NIF + module)

Probes were run with `erl` against
`_build/default/lib/cbcl_router/ebin` (loading the real `cbcl_ristretto.so` and the
compiled `cbcl-crypto-spake2`). Results:

| Probe | Input | Result | Interpretation |
|---|---|---|---|
| P1 | `msg_B` = 32 zero bytes (**identity**) at initiator step1 | `{ok, mac_A, …}` | Identity input is **accepted** (J-1). K = x·(−w·N) ≠ identity, so no key control; an attacker still cannot forge MAC_B. |
| P2 | `msg_B` = `0xED FF…FF 7F` (**non-canonical**, field elt = p) | `{error, invalid_msg}` | Non-canonical encoding rejected by `ristretto255_is_canonical`. |
| P3 | `msg_B` = 31 bytes (**truncated**) | `{error, invalid_msg}` | NIF size check → `enif_make_badarg` → caught by the step1 `try`. |
| P5 | `msg_B` = `w·N` exactly ⇒ `K_spake2 = x·identity` | `error` | `scalarmult` zero-output check (`:27-29`) fires ⇒ **K can never be identity**. This is the RFC 9382 §7 hardening, provided implicitly by libsodium. |
| P6a | `scalarmult(0-scalar, P)` | `{error, scalarmult_failed}` | Zero scalar ⇒ identity output ⇒ rejected. |
| P6b | `sub(non-canonical, N)` | `{error, sub_failed}` | Invalid input point rejected by `add`/`sub`. |
| P6c | `sub(P, P)` | 32 zero bytes (**identity**), **no error** | Confirms `add`/`sub` have no zero-output guard (J-2). |
| P4 | peer MAC = 3 bytes at MAC-verify step | **`badarg` crash** from `crypto:hash_equals_nif` | `ct-equal?` does not short-circuit (J-3); badarg escapes the (unwrapped) MAC step. |

Probes P2/P3/P5/P6a/P6b confirm the protective chain holds for the point paths.
P1/P6c/P4 motivate the findings below.

---

## 4. Findings

### J-1 — Group-membership / identity validation is implicit only (advisory)

The NIF exposes no `is_valid_point` and the LFE caller performs no explicit
group-membership or identity check. RFC 9382 §7 (`rfc9382.txt:433-436`):

> Elements received from a peer MUST be checked for group membership. … An endpoint
> MUST abort the protocol if any received public value is not a member of G.

**Disposition:** compliant, but by delegation. Every peer point flows through
`ristretto255_frombytes` (inside `sub` at spake2.lfe:188/213), which rejects all
non-G encodings — confirmed by source (`ref10.c:2717-2751`) and probes P2/P3/P6b.
The membership requirement is therefore met without an explicit check.

**Residual:** the identity element *is* a member of G and is **accepted** as a peer
message (probe P1; spake2.lfe:188 produces `−w·N`, a valid point). RFC 9382 does not
require rejecting identity *input*, and it cannot yield key control here (the
attacker cannot compute MAC_B, and K itself is forced non-identity by J/P5). Many
hardened SPAKE2 implementations nonetheless reject `pA`/`pB` = identity defensively.

**Recommended fix/test:** add an explicit `is_valid_point`-style guard (or an
identity comparison) on the decoded peer message in spake2.lfe step0/step1, *or*
record in the module doc that membership+identity rejection is deliberately
delegated to libsodium, with the negative tests in §6 pinning the behaviour so a
libsodium swap can't silently regress it.

### J-2 — `add`/`sub` have no zero-output (identity) guard (advisory)

`crypto_core_ristretto255_add`/`_sub` (`core_ristretto255.c:22-60`) lack the
`sodium_is_zero` check that `scalarmult` has. Probe P6c: `sub(P,P)` returns the
identity encoding with no error. In the current handshake this is safe — every
`sub` result is immediately fed to `scalarmult` (spake2.lfe:188→189, 213→214), and
`scalarmult` *does* reject an identity output (J/P5). The defense-in-depth therefore
lives entirely in `scalarmult`.

**Risk:** if future code ever consumes an `add`/`sub` output **without** a
subsequent `scalarmult` (e.g. uses `msg_b_adj` directly, or a new protocol step),
the identity could pass through unguarded.

**Recommended fix/test:** add a comment at spake2.lfe:188/213 noting the identity is
caught only by the following `scalarmult`; consider an explicit identity check if
the data flow ever changes. Add a test asserting `K_spake2` derivation aborts when
`msg_B == w·N` (currently relies on libsodium internals — make it a pinned test).

### J-3 — Constant-time MAC compare is **not short-circuiting**; wrong-length peer MAC crashes the handler (advisory, but fix before pairing ships)

`ct-equal?` (spake2.lfe:125-127):

```lfe
(defun ct-equal? (a b)
  (and (=:= (erlang:byte_size a) (erlang:byte_size b))
       (crypto:hash_equals a b)))
```

`and/2` is the **strict** boolean BIF — it evaluates *both* operands before
combining. Beam disassembly of the compiled function confirms this: the `=:=`
result is stored, then `crypto:hash_equals/2` is called **unconditionally**, then
`and` combines them. `crypto:hash_equals/2` raises `badarg` when the two binaries
differ in length (verified directly). So a peer MAC that is not exactly 32 bytes
makes `ct-equal?` throw `badarg` instead of returning `false`.

This throw occurs in **responder step1** (spake2.lfe:222-226) and **initiator
step2** (spake2.lfe:197-201), neither of which is wrapped in a `try` (only step0 /
initiator-step1 point decoding is, spake2.lfe:184-194 / 205-219). The badarg
propagates to `handle-agent-confirm` (enrollment.lfe:117) → `handle-frame` →
`drive` (ws-handler.lfe:62), which has **no** surrounding `catch`. Probe P4
reproduces the crash with a 3-byte MAC.

**Impact:** (1) a malformed-length `mac_a` crashes the websocket handler process
instead of returning a clean `{error, mac_mismatch}`; (2) the crash happens *before*
`rate-limit-bump-fail` (ws-handler.lfe:70-74), so a malformed MAC does **not** burn
the attacker's `enroll_fail` budget — a rate-limit-evasion / availability defect.
This is not a key-control or offline-dictionary break, so it is advisory under the
strict point-validation scope of condition J, but it lives inside the SPAKE2 caller
and should be fixed before the pairing handshake ships.

**Recommended fix:** make the length check truly short-circuit, e.g.

```lfe
(defun ct-equal? (a b)
  (if (=:= (erlang:byte_size a) (erlang:byte_size b))
    (crypto:hash_equals a b)
    'false))
```

(or `andalso`), so a wrong-length MAC returns `false` → `{error, mac_mismatch}`.
Add the negative test in §6.

### J-4 — No wire-layer length validation of peer points (advisory; mitigated)

`decode-spake2-init` / `decode-binary-frame` (ws-handler.lfe:166-191) pass base64-
decoded bytes straight through with no length check. For point inputs this is
mitigated: the NIF size check (`cbcl_ristretto.c:64-65, 92-93, 107-108`) returns
`badarg`, caught by the step0/step1 `try` → `{error, invalid_msg}` (probe P3).
Folded together with J-3, which is the *un*-mitigated length case (MAC path).

**Recommended fix:** optional — assert 32-byte length on `msg_a`/`msg_b` and MAC
fields at decode time for a cleaner error and uniform handling.

### J-5 — M/N generators are valid but not pinned by a test vector (advisory)

`m-point`/`n-point` (spake2.lfe:37-55) derive M and N as
`from_hash(SHA-512("SPAKE2 {M,N} Ristretto Curve25519 SHA-512 Hash v1"))`, memoised
in the process dictionary. `from_hash` always yields a valid ristretto255 point
(Elligator, `core_ristretto255.c:63-68`), so M and N are valid group elements with
no known discrete log — the nothing-up-my-sleeve property RFC 9382 §7
(`rfc9382.txt:577-581`) requires. Computed values (this libsodium build):

```
M = 0AD235C46B1D69F9FB801977562C52C11FF7DCA53C50124D704D7CD01796596F
N = E44D210C77AB1C82F4F4A202D4EEA392BC87FA12E7912A7E45925A6B38B6950B
```

These are the pyspake2 / CFRG-draft Ristretto strings (RFC 9382's named groups are
P-256/edwards, not ristretto255). **No test pins these bytes**, so a change to the
seed string — or a libsodium `from_hash` change — would silently shift both sides'
M/N and break interop without an obvious failure.

**Recommended test:** assert `m-point`/`n-point` equal the hex above (known-answer
test). This also documents the constants.

### J-6 — Local scalar/point ops in initiator step0 are not `try`-wrapped (advisory; not externally triggerable)

Initiator step0 (spake2.lfe:175-180) calls `scalarmult_base x`, `scalarmult w M`,
`add` with no `try`. If `scalarmult_base`/`scalarmult` returned `{error, …}` (only
possible if `x` or `w` reduced to a value producing an identity output — probability
~2⁻²⁵²), the `{error,…}` tuple would be passed to `add` as a non-binary →
`badarg` crash. Inputs are local (CSPRNG ephemeral, HKDF-derived `w`), so this is not
attacker-reachable; recorded for completeness.

**Recommended fix:** optional defensive `try` or zero-scalar assertion on the
reduced ephemeral/`w`.

---

## 5. Verdict

**No finding BLOCKS the pairing-handshake implementation.** The condition-J
core property holds: on every path where peer-controlled bytes become a group
element, (a) non-canonical and invalid encodings are rejected inside
`ristretto255_frombytes` (source-confirmed, probes P2/P3/P6b), and (b) the shared
secret K can never be the identity because `crypto_scalarmult_ristretto255` rejects a
zero output (source `:27-29`, probe P5). RFC 9382 §7 group-membership is satisfied,
and there is no path to peer key-control or offline-dictionary advantage from a
crafted point. ristretto255 is doing exactly the job condition J was written to
verify.

All six findings are **advisory**. J-3 (non-short-circuiting MAC compare →
handler crash + rate-limit evasion) is the most material and **should be fixed
before the pairing handshake ships**, but it is a MAC-handling/robustness defect,
not a point-validation break, so it does not keep hark `pair` un-implementable.

Per condition J's own terms, the audit's *conclusion* is **non-blocking** — but the
**audit document does not close condition J**. A human crypto reviewer must verify
the cited evidence and record sign-off. **Status remains PENDING HUMAN CRYPTO
SIGN-OFF.**

---

## 6. Recommended negative tests

Existing coverage (`cbcl-crypto-spake2-tests.lfe`): `test-spake2-tampered-msg-b-rejected`
(:156) feeds an all-zero (identity) `msg_B` and accepts *either* `{error,_}` or
`{ok,_}` — so it does **not** assert rejection and would not catch J-1/J-3.
`cbcl-crypto-fuzz-tests.lfe:81-96` fuzzes only the **responder step0 point decode**,
never the MAC-verify steps, so it misses J-3. The enrollment-path tests cover
wrong-phrase MAC mismatch (TEST-010) but always with a correctly-sized MAC.

Add the following:

1. **Non-canonical point** — feed `<<0xED, (30×0xFF), 0x7F>>` as `msg_B` to initiator
   step1 and as `msg_A` to responder step0; assert `{error, invalid_msg}` exactly
   (pins J-1 / the `is_canonical` reject).
2. **Truncated / oversized point** — 31-byte and 33-byte `msg_B`/`msg_A`; assert
   `{error, invalid_msg}` (pins J-4).
3. **Identity input point** — 32 zero bytes as `msg_B`; assert the *documented*
   behaviour (currently `{ok,…}` then a later MAC mismatch). If J-1 is fixed to
   reject identity, flip this to assert `{error, invalid_msg}`.
4. **K = identity** — drive a handshake where `msg_B = w·N` so `K_spake2` would be
   identity; assert step1 returns `{error, invalid_msg}` (pins the `scalarmult`
   zero-output guard, J-2/P5 — the single most security-relevant test).
5. **Wrong-length peer MAC** — send a non-32-byte `mac_a` to responder step1 and a
   non-32-byte `mac_b` to initiator step2; assert `{error, mac_mismatch}` and **no
   crash** (regression for J-3). Add an end-to-end variant through
   `cbcl-auth-shell-ws-handler` asserting the connection does not crash and the
   `enroll_fail` counter is bumped.
6. **M/N known-answer** — assert `m-point`/`n-point` equal the hex in J-5.
7. **Fuzz extension** — extend the SPAKE2 fuzz property to also feed garbage into the
   MAC-verify steps (initiator step2 / responder step1), not just step0.
