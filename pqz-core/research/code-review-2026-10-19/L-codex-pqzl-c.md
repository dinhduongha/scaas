# L — Codex review of the PQZL C core (round 2)

**Date:** 2026-10-19. **Reviewer:** Codex CLI 0.163.0 (one read-only task; owner-requested, after the PQZH round I–K).
**Target:** frozen detached worktree at `e9cabd1`: `pqzl/src`, `pqzl/lazer`, `ffi/src/pqzl/c.rs`, `pqzl/build.sh`.
Brief: the nine dimensions of G / H plus memory safety / UB and C = Rust verdict parity. No builds, tests or timing.
Triage: [M-agy-pqzl-c.md](M-agy-pqzl-c.md). Codex's output follows verbatim (job log header removed).

---

### C2-1 — P3 — Arena exhaustion can overflow the shared sink

**Locations:** `pqz-core/pqzl/src/pqz_arena.c:20`, `pqz-core/pqzl/src/pqz_arena.c:144`; `pqz-core/pqzl/lazer/spolymat.c:61`; `pqz-core/pqzl/lazer/lnp-tbox.c:1014`; `pqz-core/pqzl/params/pqz_txm8_params.h:162`.

**Trigger:** Exhaust the arena immediately before an `R_TXM8` generic-verifier sparse-matrix allocation. Its dimension is `2 × (254 + 11) = 530`, requiring 140,715 entries. The entry structure at `pqz-core/pqzl/lazer/lazer-in2.h:352` occupies 16 bytes on native LP64 and 8 on wasm32: respectively **2,251,440** and **1,125,720 bytes**, both exceeding the 1,048,576-byte sink. `spolymat_alloc` immediately clears the entire requested size.

**Impact:** Out-of-bounds writes occur before the caller can observe `PQZ_ERR_ARENA`. Subsequent allocations also alias the sink and can corrupt object metadata. The FFI’s post-call error check cannot contain corruption that has already happened (`pqz-core/ffi/src/pqzl/c.rs:140`).

**Confirmed or hypothesis:** Confirmed conditional memory corruption. I did not establish an input that exhausts the production 512 MiB specialised-verifier arena or 1 GiB generic-verifier arena (`pqz-core/ffi/src/pqzl/c.rs:36`). P3 reflects that reachability limitation.

The round-1 **R_TX example was overstated**: 53,956 native entries occupy 863,296 bytes, below the sink size. `R_TXM8` supplies a valid counterexample on both targets.

**Suggested fix:** Make allocation failure stop processing before any constructor writes or uses the returned object, with failure propagated to the entry point. Merely enlarging the shared sink does not fix allocation aliasing. No honest proof bytes or successful-call verdicts need change.

### C2-2 — P3 — Prover witnesses and mask seeds survive cleanup

**Locations:** `pqz-core/pqzl/src/pqz_rel.c:903`, `pqz-core/pqzl/src/pqz_rel.c:1392`; `pqz-core/pqzl/lazer/lnp-tbox.c:256`; `pqz-core/pqzl/lazer/lnp-quad.c:46`, `pqz-core/pqzl/lazer/lnp-quad.c:322`; `pqz-core/pqzl/src/pqz_arena.c:150`, `pqz-core/pqzl/src/pqz_arena.c:190`.

**Trigger:** Complete a proof, reject an inconsistent witness after copying it, or leave a prover rejection loop through its error path. Arena release changes allocation metadata without clearing payloads. `expseed[96]` and `yseed[32]` also leave scope without wiping.

**Impact:** Witness copies, commitment randomness, masks and reproducible mask seeds remain in reusable arena or stack memory. A later memory disclosure or process dump can expose them. This is not a demonstrated remote disclosure by itself.

**Confirmed or hypothesis:** Confirmed retention, including failure paths. The top-level `ex` wipe at `pqz-core/pqzl/src/pqz_rel.c:1036` does not clear these descendants. Rust has explicit guards for corresponding copies at `pqz-core/pqzl/rust/src/rel.rs:919`, `pqz-core/pqzl/rust/src/proof/tbox.rs:1083`, and `pqz-core/pqzl/rust/src/proof/quad.rs:238`.

**Suggested fix:** Use the existing volatile wiping primitive (`pqz-core/pqzl/src/pqz_rt.h:98`) for expanded seeds and secret buffers before freeing or releasing them, through common cleanup paths. Cover key/decryption scratch buffers too; preserve intentional caller-owned outputs. No proof bytes or verdicts change.

### C2-3 — P3 — Truncated proofs form out-of-object pointers despite bounded reads

**Locations:** `pqz-core/pqzl/lazer/coder.c:152`, `pqz-core/pqzl/lazer/coder.c:188`, `pqz-core/pqzl/lazer/coder.c:319`, `pqz-core/pqzl/lazer/coder.c:345`; `pqz-core/pqzl/src/pqz_rel.c:403`.

**Trigger:** Supply a canonical `R_REG` statement and **10,552 zero proof bytes**. That covers the fixed-width fields under `pqz-core/pqzl/params/pqz_reg_params.h:117`; all decoded values satisfy their ranges. The hint is absent.

`RDB` sets the error and substitutes zero, but the hint decoder continues advancing its bit cursor. After its first polynomial, `state->in += nbytes` forms a pointer beyond the proof object’s one-past boundary. The Gaussian decoders subsequently continue advancing it too.

**Impact:** Input-reachable C pointer-arithmetic undefined behavior. The read guards prevent a demonstrated out-of-bounds load, but do not make those pointer values legal.

**Confirmed or hypothesis:** Confirmed source-level UB. A crash, false accept, or compiler-induced verdict difference is a hypothesis, not demonstrated. Rust stops at the first failed read (`pqz-core/pqzl/rust/src/coder.rs:196`, `pqz-core/pqzl/rust/src/coder.rs:229`).

**Suggested fix:** Return immediately when an entropy decoder encounters a failed read, before advancing its pointer; stop subsequent component decoding once `err` is set. Honest bytes and verdicts remain unchanged; truncated proofs still reject.

## Round-1 findings: status in this tree

| Finding | Status |
|---|---|
| C-F1: `h` missing before μ | **Fixed.** Generic prover/verifier absorb `h` before `quad_many`: `pqz-core/pqzl/lazer/lnp-tbox.c:803`, `pqz-core/pqzl/lazer/lnp-tbox.c:1344`. SV does so at `pqz-core/pqzl/src/pqz_sv.c:1544`. |
| D-1: z3/z4 missing before V3/V4 | **Fixed.** Both generic paths preserve the JL seed, then hash z3/z4: `pqz-core/pqzl/lazer/lnp-tbox.c:416`, `pqz-core/pqzl/lazer/lnp-tbox.c:1183`. SV separates these seeds at `pqz-core/pqzl/src/pqz_sv.c:1593`. |
| C-F2: sink overflow | **Open**, with corrected allocation evidence in C2-1. |
| D-2: wrong z2 rejection test/variance | **Fixed.** `rej_onetime` receives `stdev2sqr`: `pqz-core/pqzl/lazer/lnp-quad.c:280`. |
| D-3: reused/out-of-range sign bit | **Fixed.** Sequential bits, refill below two remaining, explicit sign-byte wipe: `pqz-core/pqzl/lazer/lnp-tbox.c:1669`, `pqz-core/pqzl/lazer/lnp-tbox.c:1709`, `pqz-core/pqzl/lazer/lnp-tbox.c:1877`. |
| Triage A: length before hashing | **Fixed.** Exact relation length is checked at `pqz-core/pqzl/src/pqz_rel.c:1315`; verifier guards precede hashing at `pqz-core/pqzl/src/pqz_rel.c:1407` and `pqz-core/pqzl/src/pqz_rel.c:1440`. |
| Triage D: `INT64_MIN` absolute value | **Fixed.** Unsigned negation at `pqz-core/pqzl/src/pqz_sv.c:1339`. |
| Triage B / Open 8: wiping | **Open**, C2-2. |
| Fix E: constant-time arithmetic | **Present in source.** Masked add/subtract, centring, slack extraction and restoring division remain; no additional concrete secret-dependent path established. Compiler behavior remains unchecked. |
| Open 6: global state | **Contained by the production FFI lock**, `pqz-core/ffi/src/pqzl/c.rs:103`, `pqz-core/ffi/src/pqzl/c.rs:108`. Direct C callers still require serialization. |
| Open 4: UB nits | **Still present.** Zero-length `V` storage for `M=0`: `pqz-core/pqzl/lazer/lnp-tbox.c:934`, via `pqz-core/pqzl/lazer/lazer-in2.h:845`. Initial null-pointer-plus-zero: `pqz-core/pqzl/lazer/aes256ctr.c:276`, `pqz-core/pqzl/lazer/aes256ctr.c:339`. |

## Checked and clean

- **Transcript and binding:** Traced commitment → JL seed → z3/z4 → V3/V4 → tg → evaluation challenges → h → μ → final challenge. C generic ordering matches Rust at `pqz-core/pqzl/rust/src/proof/tbox.rs:778`; SV ordering matches `pqz-core/pqzl/rust/src/sv.rs:1315`. The final C SV challenge absorbs `hash2` at `pqz-core/pqzl/src/pqz_sv.c:1947`.

- **Norm checks:** Generic z3/z4 checks at `pqz-core/pqzl/lazer/lnp-tbox.c:1979`; z1, complete z2 and hint checks at `pqz-core/pqzl/lazer/lnp-quad.c:506`, `pqz-core/pqzl/lazer/lnp-quad.c:524`, `pqz-core/pqzl/lazer/lnp-quad.c:535`. SV checks their counterparts at `pqz-core/pqzl/src/pqz_sv.c:1493`, `pqz-core/pqzl/src/pqz_sv.c:1550`, `pqz-core/pqzl/src/pqz_sv.c:1959`. Exact-l2 blocks receive distinct domains at `pqz-core/pqzl/lazer/lnp-tbox.c:3279`, matching Rust at `pqz-core/pqzl/rust/src/proof/tbox.rs:711`.

- **Canonicality:** Fixed-width length/range checks, bijective hint/Gaussian encodings, stop-bit padding and exact consumption are present (`pqz-core/pqzl/lazer/coder.c:393`, `pqz-core/pqzl/lazer/coder.c:554`, `pqz-core/pqzl/lazer/coder.c:419`; `pqz-core/pqzl/src/pqz_rel.c:410`). Within `MAX_PROOF`, Gaussian magnitudes remain below approximately `2^39`, hence below `q/2`; reduction does not introduce alternate accepted encodings.

- **Statement parsing:** Exact shapes, coefficient bounds, auditor flag and leg count are enforced (`pqz-core/pqzl/src/pqz_rel.c:224`, `pqz-core/pqzl/src/pqz_rel.c:653`, `pqz-core/pqzl/src/pqz_rel.c:1274`; SV counterpart `pqz-core/pqzl/src/pqz_sv.c:1138`). The core hashes `proofSystemId`; the outer decoder enforces its allowlist before dispatch (`pqz-core/stmt/src/lib.rs:493`, `pqz-core/ffi/src/lib.rs:70`).

- **Arithmetic headroom:** SV reductions separate large integer products before further multiplication. Four near-30-bit CRT primes provide substantial headroom over the traced bounds; accumulator additions remain far below 64-bit capacity (`pqz-core/pqzl/src/pqz_sv.c:345`, `pqz-core/pqzl/src/pqz_sv.c:402`, `pqz-core/pqzl/src/pqz_sv.c:1696`, `pqz-core/pqzl/src/pqz_sv.c:1792`). `l2_sum` rejects large terms before squaring and checks each partial sum, matching Rust (`pqz-core/pqzl/src/pqz_sv.c:1345`, `pqz-core/pqzl/rust/src/sv.rs:1222`).

- **Native/wasm32 arithmetic:** Reviewed the 128-bit and 21-bit-limb multiplication paths and fixed-width decoder counters (`pqz-core/pqzl/src/pqz_ntt.c:41`, `pqz-core/pqzl/src/pqz_ntt.c:134`). No concrete width-dependent verdict difference found.

- **Build isolation:** Default library flags omit trace, ctgrind and mutation/cheating hooks; hook objects are compiled separately (`pqz-core/pqzl/build.sh:11`, `pqz-core/pqzl/build.sh:56`, `pqz-core/pqzl/build.sh:63`). FFI enables hooks only for fuzzing (`pqz-core/ffi/build.rs:76`). Symbol scanning checks file existence and `nm` failures (`pqz-core/pqzl/check_symbols.sh:9`).

- **Prover side channels after E:** Secret witness divisions use fixed-step division (`pqz-core/pqzl/src/pqz_rel.c:1082`, `pqz-core/pqzl/src/pqz_keys.c:201`); slack extraction writes every bit (`pqz-core/pqzl/lazer/int.c:262`). Prover AES uses a bitsliced circuit (`pqz-core/pqzl/lazer/aes256ctr.c:20`). Remaining observed rejection branches correspond to explicit verdicts; variable-time SV arithmetic processes public input.

## Not checked

No dynamic confirmation, generated-code inspection, timing, exhaustive differential equivalence, parameter-hardness analysis, or independent proof of the Gaussian/rejection approximation budget. Lower-level algebra and cryptographic primitives were inspected selectively, not formally verified.

Residual risks: arena exhaustion can corrupt memory; prover secrets remain recoverable from retained memory. Static inspection cannot certify compiler-level constant time or universal C/Rust verdict parity.

[exited with code 0]
