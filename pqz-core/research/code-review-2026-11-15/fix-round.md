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

## 5. seed_enc — seal-side repeat guard (BUILT; owner 2026-11-15, items 5 and 7 approved)

Why: K3-6's coins are `SHAKE256(label ‖ seed_leg ‖ role ‖ keccak256(kemPk))`, so the same `seed_enc` to the same
recipient gives the same ML-KEM coins, KEK and GCM nonce; a second seal of that `seed_leg` under another `aad` reuses a
GCM key and nonce (Codex U2 point 2). The same repeat also reuses the PQZ randomness of `u`, `u_f`, `v_f`
(CTR-PQZ-19), so the guard keys on `seed_enc`, not only on `seed_leg`.

**Change** (`ffi/src/opening.rs`, as designed):
- **Repeat:** one `seed_enc` presented for a second, different credit (fingerprint: CTR-PQZ-40; widened by the Fable
  review F-2, below). Not a repeat: the recipient's and the auditor's opening of the same credit, or the same opening
  again.
- **Scope:** `Sealer`, caller-owned, in memory; no global state, nothing persisted; at most `SEALER_CAP` = 4,096 seeds,
  then it refuses (never evicts).
- **Where:** `Sealer::seal_leg(seed_enc, role, credit)` takes the party from the credit (`to`, or its auditor), derives
  `seed_leg` itself (K3-4) and checks the table before sealing; it stores `SHA3-256("SCAAS-PQZ-SEAL-GUARD-SEED-V1" ‖
  seed_enc)` and the fingerprint, never `seed_enc`. The opening is byte-identical to `seal`'s; plain `seal` stays for the
  holder check (K3-7 step 8 re-seals on purpose) and the vector generator.
- **Errors, all fail closed (no opening):** `SealError::SeedReused`, `SealError::Full`, `SealError::Refused` (`seal`'s
  own refusals, or no auditor copy for the auditor role). A refusal leaves the table unchanged.
- **No format or vector change.** Wiring the wallet builders (`clientkeys` / `pqz-wallet-wasm`, ua-rs) to `Sealer` is the
  clients' round.

**Stated limit (owner 2026-11-15):** it catches a repeat within one process only; a restart forgets. Across processes
the guarantee stays CTR-PQZ-19's fresh salt with CTR-PQZ-38 (release builds take no caller salt). Rationale (owner 2026-11-15): a deterministic per-credit `seed_enc` will not be done. `seed_enc` is already per credit and randomized (CTR-PQZ-19: `HKDF-SHA256(ikm = pqzKeySeed, info = chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖ salt)`, a fresh 16-byte random salt per build, published in the payload and the statement header); dropping the salt would reuse `r` on a re-proof at the same counter with another amount (leaking `Δ·(m − m′)`), which is why the salt exists; the amount in `info` instead would make the sender remember amounts, against the design. A repeat needs the same counter and the same 16 random bytes (about 2^-128 with a working RNG); the `Sealer` covers the residual within one process.

**Test.** `sealer_refuses_a_repeated_seed_enc`: control (O_t, O_a equal to `seal`'s), the same opening again;
`SeedReused` for another amount, another recipient UA, another token; the first credit still seals after the refusals;
`Refused` for no auditor copy and a scheme-2 key; `Full` for the 4,097th seed, a known seed still seals when full.

**Mutants** (`opening_mutants.py`): Se1 the fingerprint comparison removed: red (`another amount`); Se2 eviction when
full: red (`the 4,097th seed`); Se3 `seed_leg` not the credit's: red (`control: O_t`). 3 / 3, with Ma–Md still 4 / 4.

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

## 7. U3h-2 — the plugin's fault boundary and exit watchdog (BUILT; owner 2026-11-15, items 5 and 7 approved, the watchdog added)

Before: `MlDsa.Verify` allocated its output and checked the length before its `try`; its `CryptographicException`
handler logged inside the `catch`, so a throwing logger escaped the sibling `catch (Exception)`; `NodeFault` built the
line (Keccak, formatting), wrote stderr and the logger before `Environment.Exit`, and the caller formatted `e.Message`
first. Any of these could throw and reach Nethermind, which makes a failed call of it.

**Order of operations on a fault (both precompiles, as built):** (amended by the Fable review F-1: the watchdog now starts before step 3's diagnostic; its bound is `PQZ_EXIT_WATCHDOG_MS`, F-7)
1. The whole operation is inside one boundary: ML-DSA's output allocation, length check, slicing, import and verify
   (PQZ's `Run` already wrapped `RunUnguarded`, allocation included).
2. `catch (Exception e)` (PQZ: `when (e is not DllNotFoundException)`, unchanged) calls `NodeFault(where, e, input)`;
   the cause is built inside it.
3. `NodeFault`: `try` { cause, line `PQZ-NODE-FAULT <cause> keccak=<..> len=<n>: …; exit 120`, stderr write + flush,
   logger Error } `catch` { `FallbackLine` to stderr once, inside its own empty `catch` } `finally` { `Terminate()` }.
4. `Terminate()`: start the **exit watchdog** — a dedicated background thread (`pqz-exit-watchdog`, not the thread
   pool) that sleeps `ExitWatchdogMs` = 10,000 ms and then calls `Environment.FailFast(WatchdogLine)` — then
   `Environment.Exit(120)`; should `Exit` return or throw, `Environment.FailFast` at once. If the thread cannot start,
   `Exit` still runs.
5. Nothing returns to Nethermind on this path: no word, no failed call.

**Diagnostic failure:** a throwing `Message`, Keccak, stderr writer or logger is caught inside `NodeFault`; termination
still happens with exit 120.

**Exit code:** 120. The watchdog's FailFast (a ProcessExit handler that blocks, e.g. on the faulting thread) ends the
process with the runtime's abort status (134 in the test), not 120: termination within the bound is what it
guarantees. This closes the T-20 open point "Exit can hang in a ProcessExit handler".

**W-R kept:** a `CryptographicException` returns the 32 zero bytes; its Warn line is wrapped, so a throwing logger is
swallowed and the word is unchanged (it does not depend on the log; every node gives the same result).

**Tests** (child processes, `Harness mldsa-fault <variant>`, each with its own bound; a child past it is killed and the
test fails by that bound): `A_failing_diagnostic_still_exits_120` — `logger`, `stderr`, `message` (`FallbackLine` on
stderr): exit 120 after 40–52 ms, no word; `A_blocking_shutdown_handler_is_ended_by_the_watchdog` — a ProcessExit
handler that sleeps forever: ended after 10,253 ms (bound 30 s), `WatchdogLine` on stderr, exit 134;
`A_crypto_exception_with_a_throwing_logger_is_the_zero_word` — exit 0, the zero word; the earlier
`Another_exception_is_a_node_fault` control stays green. The PQZ seam (owner 2026-11-15, fault-hook library
`bin/test-hooks`, `Harness fault <hooks> <corpus> <variant>`): `A_failing_diagnostic_on_the_pqz_path_still_exits_120` —
`logger` and `stderr` on the worker fault (status 4), `message` = the input-panic warning throwing an exception whose
`Message` throws (Run's catch, then the fallback line): each exit 120, beside the earlier
`Node_fault_exits_120_with_the_tag` control. Full suite (`run-tests.sh`, n2304-kmax4096): 66 / 66.

**Docs** (owner 2026-11-15): decisions.md Changes under CTR-PQZ-10 (the fault boundary, watchdog, exit code) and
CTR-PQZ-40 (the `Sealer`); the exit-code note (120 normally, the runtime's abort status 134 when the watchdog fires) in
pq-zero-knowledge.md §9.1 (CTR-PQZ-10's status mapping), `docs/node/ops.md` and `chain/RUNBOOK.md`; the `Sealer` in
CTR-PQZ-40's normative text. `docs_check.py check`: 0 errors.

**Mutants** (`plugin_mutants.py`): see the gate table. The output allocation before the `try` has no injection point; it
is closed by structure.

## Fable review of group 1 (2026-11-15; 0 P0, 0 P1, 3 P2, 8 P3; owner: fix all)

Report kept outside the repository (Fable 5.2 high, `ebd6eb4a9..1d523b890`). Each finding → change → evidence.

| Finding | Change | Evidence |
|---|---|---|
| F-1 (P2) a diagnostic that blocks never reaches the watchdog | `Fault` calls `StartWatchdog()` first, then the `try` (diagnostic), then `ExitNow()` from the `finally` | children `blocking-stderr`, `blocking-logger` (a writer / logger that sleep forever): ended by the watchdog after ≥ 3,000 ms (bound via `PQZ_EXIT_WATCHDOG_MS`), the watchdog line, never a word; mutant F1b (watchdog started in the `finally`, after the diagnostic): red, both children killed by their own bound |
| F-2 (P2) the `Sealer` fingerprint missed inputs | fingerprint = `chainUid ‖ token ‖ P(u) ‖ party(to) ‖ [party(auditor)] ‖ P(u_f) ‖ P(v_f)`, `party = ua ‖ be8(keyVersion) ‖ keccak(pk) ‖ keccak(kemPk) ‖ P(v)` (each reader's AAD inputs; both roles of one credit share it); `seal_leg` takes `own_u`, `own_v` | new `SeedReused` cases, both roles each: another new balance (`v_f` only; the leg unchanged, asserted), recipient key version, auditor key version, auditor UA; mutants Se4 (own part removed), Se5 (key versions removed), Se6 (auditor UA replaced): red |
| F-3 (P2) docs: the `Sealer` read as active; decisions entry structure | CTR-PQZ-40 normative text and decisions entry: "library API only: no wallet builder uses it yet (clientkeys `sealOpening`, ua-rs: the clients' round)"; decisions CTR-PQZ-40: Status corrected (contract side SPECIFIED, `pqz-ffi`'s opening code BUILT), the Change moved after Source | docs_check 0 errors |
| F-4 (P3) stack residues (C, Rust) | C: `rej_standard` / `rej_bimodal` / `rej_onetime` clear `t1` / `t2`; `lnp_tbox_prove` clears `tmp`. Rust: the same dots cleared in `rand/rejection.rs`; `t` (tbox) and `g1` (quad) in `Wiped`. `abdlop_prove` has no caller: not touched | no proof byte change: kat, tbox, sv, fnv (C = Rust = wasm32), rust (gate rows below) |
| F-5 (P3) AES / GHASH key schedule, X25519, hash states | `aes-gcm` `zeroize`, plus `aes` / `ghash` / `polyval` with `zeroize` (the versions aes-gcm resolves, direct deps under `prove`), `curve25519-dalek` `zeroize`; the hash states (`combine`, `coins`, `kek`, the `Sealer` key) named in the module doc as not reached | lockfiles of pqz-ffi, offchain, wallet-wasm, wasm, fresh-proofs, the EVM wallet script: only `zeroize` dependency edges and pqz-ffi's three new direct deps, no new package or version; opening.json byte-identical (vectors row) |
| F-6 (P3) the PQZ input-panic warning unguarded | `WarnPanic` swallows a logger failure as `WarnCrypto` does: the word stays `…00`; Run's catch is now reached through a call seam (`Run(input, s, CallFn)`, as `MlDsa.VerifyFn`) | child `panic-logger` (the panic hook + a throwing logger): word `…00`, exit 0; the PQZ `message` child through the seam: exit 120 with the fallback line; mutant F6 (warning unguarded): red |
| F-7 (P3) watchdog in a real node; bound; core dumps | the bound is `PQZ_EXIT_WATCHDOG_MS` (1 .. 600,000, default 10,000; local, consensus-irrelevant); ops.md and RUNBOOK: keep core dumps off on sealers; `watchdog_drill.sh` | drill on a local copy (2026-11-15T09:27Z): the signer, producing block 15, logged `PQZ-NODE-FAULT ML-DSA-65 InvalidOperationException: drill` and **exited 120 after 146 ms**; the watchdog did not fire; the follower kept running (the block was never sealed). So in a node the usual outcome is 120; 134 only when a shutdown handler or a diagnostic blocks (the Harness children) |
| F-8 (P3) `Full` is permanent; the seed is not checked against the credit | the caller rule next to `SEALER_CAP` (one `Sealer` per process for its life; `Full` is permanent; across processes the fresh salt); `seal_leg` refuses (`Refused`) a `seed_enc` whose leg expansion does not give `c.u` (one extra `Enc`, K3-7 step 6; its masks cleared) | case "seed_enc not the credit's": `Refused`, and the refusal takes no slot; the `Full` case now builds a real credit per seed; mutant Se7 (the check removed): red |
| F-9 (P3) `engine-pqz.json` and the hand-run check | `matrix.sh`'s `COPY_ENGINE` default (that line only), RUNBOOK's `E=` and the spec's cite → `engine-pqz-provisional-n2304.json` until the next calibration (owner's go); `SpecTests.Engine_pqz_json_passes_the_id_check_or_is_refused_by_name`; `chain/check-provisional-ids.py` as a step of the `pqz` CI job | test green (refused by name today); the script: 4 files ok, `engine-pqz.json` reported refused (`046859a8`, `ef1ffbcb`); control: the pre-fix n2048 file → FAIL, rc 1 |
| F-10 (P3) wipe control reach | `name_buf` (a no-op without `test-hooks`) names every `Wiped` heap buffer of the prover: s3 / s4, y3 / y4, s3c / s4c, z3v / rs3 / z4v / rs4, the `intvec` / `coeffvec` copies, sv, quad's y1 .. w0, s1 / m / s2 / tA2, the digits; `wipe.rs` also on an R_TXS split row (fixture moved to `tests/common/split_fx.rs`, shared with `split.rs`) | R_REG 41–97, R_TXS 64–140 named buffers per prove, 0 dirty; mutants W-a, W-b (z3v, z4v in place), W-c, W-d (the IntVec and PolyVec wipes emptied): 4 / 4 red |
| F-11 (P3) one place per rule | exit-code values only in CTR-PQZ-10 (pq-zero-knowledge.md); ops.md and RUNBOOK say "134 with the watchdog line: treat as 120" and link; the fingerprint text only in CTR-PQZ-40, decisions links it | docs_check 0 errors |

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
| vectors (items 5, 7) | 98a3ec51 | 0 | `pqz-vectors --check` 18 files same; pqz_kat ok; tamper 212 / 225; wasm32 replay 63 cases, 0 fails (tree + this note's uncommitted edit) |
| ffi (items 5, 7) | 98a3ec51 | 0 | tests 33 passed (the Sealer test included), native = wasm32 29 lines; wallet-wasm 8 / 8 |
| Sealer mutants | 34871de6 | 0 | Se1–Se3 3 / 3 red; Ma–Md re-run 4 / 4 red |
| plugin full suite (`run-tests.sh`) | 98a3ec51 | 0 | 63 / 63 at n2304-kmax4096 (the 6 new fault-boundary children and the provisional check included) |
| plugin mutants (`plugin_mutants.py`, ML-DSA tests) | 98a3ec51 | 0 | W1 watchdog not started: red, the blocking child killed by the test's own 30 s bound; F1 the pre-fix NodeFault order: red (logger, stderr, message: 3 failed); C1 the zero word's warning unguarded: red (exit 120, not 0); 3 / 3 |
| plugin full suite, with the PQZ-seam children | c3bb8a6a (tree) | 0 | 66 / 66 at n2304-kmax4096 |
| plugin mutants (ML-DSA tests + PQZ-seam children) | c3bb8a6a (tree) | 0 | W1 red (30 s bound); F1 red (6 failed: 3 ML-DSA, 3 PQZ); C1 red; P1 `PqzPrecompile.Run` without its catch: red (`message`: the exception escapes); 4 / 4 |
| docs_check | c3bb8a6a (tree) | 0 | 0 errors (7 warnings, 16 notes, unchanged); test_docs_check ok |
| **Fable fixes:** kat, tbox, sv, fnv, vectors, ffi, rust, fuzz | e33cfc75 | 0 | gate 3zh-core-g1c PASS (summary `runs/gate/3zh-core-g1c-summary.txt`): KAT 19 / 19; fix checks ok; C = Rust = wasm32 on 16 relations; `pqz-vectors --check` 18 files same, pqz_kat ok, tamper 212 / 225, wasm32 replay 63 cases 0 fails; ffi 33 passed, native = wasm32, wallet-wasm 8 / 8; rust 22 binaries 69 passed 0 failed (wipe on R_REG and R_TXS, split with the C oracle); 4 fuzz targets 60 s, no FINDING |
| plugin full suite (Fable fixes) | a19517e6 | 0 | 70 / 70 at n2304-kmax4096 |
| plugin mutants (Fable fixes) | a19517e6 | 0 | W1, F1, C1, P1, F1b, F6: 6 / 6 red (F6 re-run after its first form did not compile: the runner now reports a build failure as INVALID, not GREEN) |
| opening + Sealer mutants (Fable fixes) | 6cc5a7f5 | 0 | Ma–Md, Se1–Se7: 11 / 11 red |
| wipe mutants | 57a9ac85 | 0 | W-a, W-b, W-c, W-d: 4 / 4 red |
| check-provisional-ids.py | a19517e6 | 0 | 4 files ok; control (pre-fix n2048 file): rc 1 |
| watchdog drill (local copy) | e33cfc75 | 0 | signer exit 120 after 146 ms; watchdog not fired; follower running |
| docs_check | this commit | 0 | 0 errors |

Not run here (not touched, or the full gate's): ct, ub, diff, cargo (pqz-stmt, Ligero), xcheck, the other three sets
(the plugin's full suite at n2304-kmax4096 only).
