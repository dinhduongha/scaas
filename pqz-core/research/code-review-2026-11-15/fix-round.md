# pqz-core three-key delta review — fix round 3zh-core, group 1 (branch `3zh-core`)

> Research record, not a rule. Everything here is UNAUDITED. Group 1 changes no generated file, `set.toml`,
> `PqzSet.sol`, header, vector, transcript, relation or proofSystemId; those are group 2 (T-35 / T-36, 3zg), with the
> one full gate at four sets on the final core tree.

Reviews: Codex gpt-6.1-sol high on `cac043bc..a5cfe748a` (units U1 high, U2 high, U3 high; U4 not run, out of
credits); finding ids U1h-1, U1h-2, U2-1, U2-2, U3h-1, U3h-2 and the earlier triage ids T-06 and U1-01. The reports
are kept outside the repository. Owner approval of the round: 2026-11-15.

## 1. U1h-1 + T-06 — prover wiping on retry (BUILT)

**Finding.** `tbox::compute_z34` assigned `*z3v = coeffs_i64(..)` (and `*z4v`) inside the rejection loop: the inner
`Vec` of a rejected try was dropped by ordinary destruction, not through `Wiped`, so its `y + beta R s` stayed in freed
heap memory.

**Change.** Rust: `z3v = Wiped(..)`, `z4v = Wiped(..)` (the old wrapper is dropped, so wiped), and `rs3` / `rs4` the
same way. Same class in the C oracle: `_lnp_tbox_compute_z34` and `lnp_quad_prove` keep their coefficient arrays on
the stack (`INTVEC_T`: s3 / s4 images, y3 / y4 then R s3 / R' s4, z3 / z4; y1 / y2 then z, c s1, c s2, the last norm),
which `pqz_arena_wipe_release` never reaches: `explicit_bzero` of each at the function's cleanup (every exit, the
`PQZ_ERR_REJECT` cap included), and of the per-term `beta R_ij s_j` ints. No proof byte changes. wasm32 runs the same
Rust function; the specialised paths are verifier-only (no secret).

**Test.** `pqzl/rust/tests/wipe.rs` (feature `test-hooks`): the prover names every z3 / z4 / R s buffer it fills
(`set_secret_buf_hook`), the test binary's allocator checks each is all-zero when freed. Cheat mode 4 (test hook)
rejects each prove's first try, so the retry path runs every time; mode 0 is the control. Result: modes 0 / 4 name 4 /
8 buffers per prove, 0 freed uncleared.

**Mutants.** `z3v = Wiped(..)` back to `*z3v = ..`: red (`rnd 0 mode 4: 1 of 8 … freed without being cleared`); the
same for `z4v`: red. Mode 0 stays green under both (the retry is what leaks). The C stack wipe has no runtime control
(a freed stack frame cannot be observed from a test); its evidence is the code and the unchanged C = Rust = wasm32
proofs (gate rows below).

## 2. U1h-2 = U1-01 — split negatives assert the exact outcome (BUILT)

**Finding.** `tests/split.rs` accepted every outcome but `Ok(true)` (`Err(Memory)`, `Err(Internal)` included), through
boolean verifiers, and a prover refusal never reached a verifier.

**Change.** `verdict` uses `try_verify` / `try_verify_fast` (with `c-oracle`, C's two must give the same `Ok`); every
case asserts one outcome: `REJECTED` (proved, every verifier `Ok(false)`), `PROVER_CHECK` (`Err(Internal)`, the
prover's own check of an evaluation equation) or `ACCEPTED`. Found and now pinned: a false R_q row (u_f, u / u_f
swapped) is proved by the honest prover (it checks only the evaluation equations) and rejected by every verifier; a
false v_f row is refused by the prover. New `split_cheating_prover_rejected` (feature `test-hooks`): cheat mode 5 skips
the prover's own relation checks (`__check_coeff0` of the evaluation equations and accumulators, the h_i asserts), so
each one-equation statement reaches the verifiers; positive control first (mode 5 on the honest statement gives the
honest proof, accepted).

**Mutants** (`split_mutants.py`, each alone, source restored):

| mutant | build | result |
|---|---|---|
| M1 Rust generic relation: R_TXS's u_f rows dropped (prover and verifier) | generic only | red at the cheat: `u_f not from (r_f, e1_f): a cheating proof accepted` (Ok(true)); honest control green |
| M2 Rust generic relation: R_TXS's v_f rows dropped | generic only | red at the cheat: `v_f under the leg's r: a cheating proof accepted`; honest control green |
| M3 Rust specialised verifier: v_f under group 0 | default | red (`verify_fast != verify`) |
| M4 C generic relation: u_f rows dropped | `c-oracle` | red (`C pqz_verify != verify`) |
| M5 C specialised verifier: v_f under group 0 | `c-oracle` | red (`C pqz_verify_fast != verify`) |

A specialised verifier cannot drop a row alone and stay honest (the prover's garbage terms cover every row), so M3 /
M5 move the binding instead; M1 / M2 show the cheat assertions themselves fail when an equation is gone.

## 3. U2-1 — zeroize in the opening code (BUILT)

**Change.** `ml-kem` feature `zeroize` (the decapsulation key is cleared on drop; `zeroize 1.9.1` added to the five
lockfiles that resolve `ml-kem`); `seal` clears the coins, the ML-KEM message `m`, the X25519 secret `e` and `ss_X` on
every exit (the small-order exit included); `open` and `open_kem_pk` clear their copy of `sk_X`; `verify_leg` clears
the zero-message encryptions `exp.vs` (the credit's masks) on every exit; `enc_split` clears `seed_leg` when the leg's
`Enc` fails (before the clearing `Split` exists) and the amount-digit copies. Best effort as `pqzl::clear` (copies
passed by value are not reached). No test: wiping has no observable output here; the opening tests stay green and no
opening byte changes.

## 4. U2-2 — auditor and malformed-input negatives (BUILT; rejection rows not added)

**Change.** `ffi/tests/opening.rs`: `auditor_unreadable_after_opening` (O_a authenticates, the leg fails: O_a with other
coins, u off by one, v_a off by one e2, each resealed; recipient `None`, auditor `Unreadable`; control `Read`);
`malformed_opening_and_kem_key` (openings of 0, 1,568, 1,647 and 1,649 bytes for both readers; opening KEM keys of 100
bytes, scheme 2, an ek coefficient >= q, 1,602 bytes: recipient `None`, `seal` refuses; controls first).

**Mutants** (`opening_mutants.py`): Ma `check_auditor`'s last outcome `Unreadable` -> `RecipientUnreadable`: red; Mb
`open`'s length checks removed: red (panic); Mc `seal`'s kemPk length check removed: red (panic); Md `seal`'s scheme
check removed: red. 4 / 4.

**Stopped:** rejection rows in `opening.json` would change a committed vector file: group 2.

## 5. seed_enc — seal-side repeat guard (SPECIFIED, design for the owner's OK; not built)

Why: K3-6's coins are `SHAKE256(label ‖ seed_leg ‖ role ‖ keccak256(kemPk))`, so the same `seed_enc` to the same
recipient gives the same ML-KEM coins, KEK and GCM nonce; a second seal of that `seed_leg` under another `aad` reuses a
GCM key and nonce (Codex U2 point 2). The same repeat also reuses the PQZ randomness of `u`, `u_f`, `v_f`
(CTR-PQZ-19), so the guard keys on `seed_enc`, not only on `seed_leg`.

- **What counts as a repeat:** one `seed_enc` presented for a second, different credit. Credit fingerprint =
  `keccak256("SCAAS-PQZ-SEAL-GUARD-V1" ‖ chainUid ‖ token ‖ toUA ‖ keccak256(pk_t) ‖ P(u) ‖ P(v_t) ‖ [P(v_a)])`. Not a
  repeat: the recipient's and the auditor's opening of the same credit, or the same opening again (a retried build of
  the identical leg).
- **Scope:** one caller-owned `Sealer` value (per wallet session / process), in memory; no global state, nothing
  persisted. Across restarts the guarantee stays CTR-PQZ-19's fresh salt with CTR-PQZ-38 (release builds take no
  caller salt). The table is bounded (4,096 seeds); a full table refuses, it never evicts.
- **Where it is checked:** `Sealer::seal_leg(seed_enc, to_ua, pk_t, role, credit, party)` derives `seed_leg` itself
  (K3-4) and checks the table before sealing; the opening is byte-identical to `seal`'s. Plain `seal` stays for the holder
  check's re-derivation (K3-7 step 8 re-seals on purpose) and the vector generator. The table stores
  `SHA3-256(label ‖ seed_enc)` and the fingerprint, never `seed_enc`.
- **Named errors:** `SealError::SeedReused` (another credit under this `seed_enc`), `SealError::Full`,
  `SealError::Refused` (today's `None`: not scheme 1, bad length, ek >= q, small-order pk_X).
- **Fail closed:** any repeat, a full table or a refused key gives no opening; the caller rebuilds with a fresh salt.
- **Tests:** control (recipient and auditor openings of one credit: `Ok`, equal to `seal`); the same opening again:
  `Ok`, same bytes; the same `seed_enc` for another amount (other `v_t`), another recipient UA, another token:
  `SeedReused` each; the 4,097th distinct seed: `Full`. Mutants: the fingerprint comparison removed; eviction instead of
  refusal; `seal_leg` taking a caller `seed_leg` — each must turn a test red.
- **No format or vector change.** Wiring the wallet builders (`clientkeys` / `pqz-wallet-wasm`, ua-rs) to `Sealer` is
  the clients' round, not this one.

## 6. U3h-1 — provisional engine schedules (BUILT)

**Change.** `chain/engine-pqz-provisional-n2048.json`, `-n2560.json`, `-n2816.json` regenerated by
`provisional-rows.py` (corpus.py over each set's committed vectors, the file's own rows as the live schedule,
`LIVE_IDS` = the file's retired ids, factor 1.0): only the ids change (n2048 PQZL `a626d57b…` / PQZH `3cf01f83…`,
n2560 `53aa6870…` / `4b2d2ff2…`, n2816 `7a3e7679…`); prices, statement lengths and gas fields equal. New
`SpecTests.Provisional_schedule_of_this_set_passes_the_id_check` loads the build's set's provisional file and runs
`CheckIds(0, ids)`; `run-tests.sh` takes `PQZ_TEST_FILTER`, so it runs at every set (one plugin build per set).

**Controls.** New files: passed at all four sets. HEAD's files: failed at n2048, n2560, n2816 (`… is not the
library's (a626d57b… / 53aa6870… / 7a3e7679…)`).

**`chain/engine-pqz.json`** (not changed): it holds n2304's previous ids (PQZL v5 `ef1ffbcb…`, PQZH v3 `046859a8…`),
refused by today's plugin. It is written by the calibration (`calibrate.sh`, Calibrate), not by provisional-rows.py:
it needs a calibration run (owner's go) or a provisional copy. README §chain describes it as "PQZL v3 / PQZH v1 ids"
(stale wording).

## 7. U3h-2 — the plugin's fault boundary (SPECIFIED, design for the owner's OK; not built)

Today: `MlDsa.Verify` allocates its output and checks the length before its `try`; its `CryptographicException`
handler logs inside the `catch`, so a throwing logger escapes the sibling `catch (Exception)`; `NodeFault` builds the
line (Keccak, string formatting), writes stderr and the logger before `Environment.Exit`, and the caller formats
`e.Message` before `NodeFault` runs. Any of these can throw and reach Nethermind, which makes a failed call of it.

**Order of operations on a fault (both precompiles):**
1. The whole operation is inside one boundary: ML-DSA's output allocation, length check, slicing, import and verify
   (PQZ's `Run` already wraps `RunUnguarded`, allocation included).
2. `catch (Exception e)` (PQZ: `when (e is not DllNotFoundException)`, unchanged) calls `NodeFault(where, e, input)`:
   the cause is built inside `NodeFault`, not by the caller.
3. `NodeFault`: `try` { cause = `where + e.GetType().Name + ": " + e.Message` (or `status=<n>`), line = `PQZ-NODE-FAULT
   <cause> keccak=<..> len=<n>: …; exit 120`; stderr write + flush; logger Error } `catch` (anything) { one best-effort
   constant line `PQZ-NODE-FAULT (diagnostic failed); exit 120` to stderr inside its own empty `catch` } `finally` {
   `Environment.Exit(120)` }; should `Exit` return or throw, `Environment.FailFast("PQZ-NODE-FAULT")` follows (never
   returns; its exit code is the runtime's abort code, not 120).
4. Nothing returns to Nethermind on this path: no word, no failed call.

**Diagnostic failure:** building the cause or line (a throwing `Message`, Keccak), the stderr write or flush (a
throwing writer), or the logger: each is caught inside `NodeFault`; termination still happens with exit 120.

**Exit code:** 120 (unchanged); FailFast only if `Environment.Exit` itself fails.

**The owner ruling CryptographicException -> zero word (W-R):** kept. The handler returns the 32 zero bytes; its Warn
line is wrapped so that a logger exception is swallowed and the word is still returned (the word does not depend on
the log, so every node gives the same result). Only a non-cryptographic exception is a node fault.

**Tests (child processes through `Harness`, each next to the existing `mldsa-fault` control):** a throwing logger plus
the seam's `InvalidOperationException` -> exit 120; a throwing `Console.Error` writer -> exit 120 (stdout has no "must
not happen"); an exception whose `Message` getter throws -> exit 120 with the fallback line; a throwing logger plus a
`CryptographicException` -> the zero word, exit 0; the PQZ path's worker fault (hooks library) with a throwing logger
-> exit 120. Mutants: `NodeFault`'s catch removed (the throwing-logger child ends with the runtime's unhandled-exception
code, not 120); the crypto handler's log guard removed (the child sees an escaped exception, no word). The allocation
before the `try` has no injection point; it is closed by structure.

**Open (T-20):** `Environment.Exit` runs `ProcessExit` handlers; if Nethermind's shutdown handler waits on the faulting
block-processing thread, the node can hang instead of exiting. A hang seals and imports nothing (fail closed), but the
exit-120 evidence inside a running node is still T-20's drill.

## Gate

Affected steps only (owner: the full gate runs once, later, on the final core tree). Logs are local, git-ignored.

| step | commit | rc | counts |
|---|---|---|---|
| kat | e67d9e85 | 0 | 19 / 19 cases equal to the LaZer golden file |
| tbox | e67d9e85 | 0 | check_tbox_fixes: P6-SZ, P6-L2, P6-Z21, P6-FS, A-2 ok |
| sv | e67d9e85 | 0 | check_sv_fixes: tree 32 cases, 0 mismatches; both reversions detected |
| fnv | e67d9e85 | 0 | C = Rust = wasm32 proofs_fnv, 16 relations (R_TXS / R_TXS0 included) |
| vectors | e67d9e85 | 0 | `pqz-vectors --check` 18 files same (opening.json byte-identical); pqz_kat ok; tamper 212 / 225 (13 partial checkers, as before); wasm32 replay 63 cases, 0 fails |
| ffi (run 1) | e67d9e85 | 1 | only `ffi/wallet`: `clients/clientkeys/node_modules` missing in the fresh worktree (`@noble/hashes` not found) |
| ffi (resumed) | e67d9e85 | 0 | after `npm ci --ignore-scripts`: tests 32 passed, symbol scans, native = wasm32 29 lines; wallet-wasm 103 cases wasm = native, 8 / 8 node tests |
| rust | e67d9e85 | 0 | 22 test binaries with `c-oracle,test-hooks,bench`, 68 passed, 0 failed (wipe, split with the C oracle included); doc; `to_rust.py --check` 69 files; `gen_set.py --all --check` 4 sets |
| fuzz | e67d9e85 | 0 | precompile, mutate, codec, offchain 60 s each, no FINDING |
| plugin `Provisional_schedule…` | e67d9e85 | 0 | 4 sets, 1 / 1 each (`run-tests.sh`, `PQZ_TEST_FILTER`); HEAD's files: 3 sets red |
| split mutants | d16c6efd | 0 | 5 / 5 red (M1, M2 generic-only builds) |
| opening mutants | 2d94da55 | 0 | 4 / 4 red |
| wipe mutants | d16c6efd | — | 2 / 2 red (z3v, z4v) |

Not run here (not touched, or the full gate's): ct, ub, diff, cargo (pqz-stmt, Ligero), xcheck, the other three sets, the
plugin's full suite (it runs with item 7).
