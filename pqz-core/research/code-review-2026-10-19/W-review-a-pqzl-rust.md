# W — Review A: independent security review of the PQZL Rust crate

**Date:** 2026-10-20. **Reviewer:** Claude (sub-agent, review A of plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`
Task 10). **Target:** `pqz-core/pqzl/rust/` at main `a61d221` (the production PQZL core), static and dynamic.
Builds and tests ran under `scripts/capped` (`cargo -j2`) in a temporary worktree of `a61d221` and in a git-ignored
scratch copy (`scratchpad/reviewA/`); the crate itself was not modified. No timing runs.

Background read: the round-1 / round-2 reports (G, H, E, L, M, N, README triage A–E and Q-A…Q-I), `pqz-core/STATUS.md`,
`docs/research/pqz-tbox-soundness.md` §8, review B's `X-review-b-transcript.md` (B-1, at the controller's request).
Only what I confirmed myself or what is new is reported; earlier findings are not repeated.

## Findings

| # | Severity | Title | Status |
|---|---|---|---|
| A-1 | **P0** | V3 / V4 are drawn before `tg`: the JL consistency rows can be cancelled through `g` (= review B's B-1, found independently) | **Confirmed by a run** (Rust generic and specialised verifiers, all 14 relation codes); C by code reading; statement-level forgery a hypothesis |
| A-2 | P3 | Schwartz–Zippel domain collision: the last β4 row and the υ row share `(hash1, M + 2(d−1))` | Confirmed in code (all four implementations); not exploitable (argument below) |
| A-3 | P3 | Rust lags the C core's Q-B wiping: key helpers and witness parsing keep secret copies | Confirmed in code; **fixed** `aee749df` (branch `rev2-small-fixes`, verified 2026-10-20) |

---

### A-1 — P0 — V3 / V4 are drawn before `tg`, so the JL consistency rows can be cancelled through `g`

This is review B's B-1. I found it independently while reading `accumulate_all` (before B's report was available to me)
and ran a cheating-prover check on the Rust crate before the controller asked for static reasoning only on this point;
the second run (adding the C core's verdicts through `c-oracle`) was stopped unrun at that request. The full second
opinion is in the section **"Second opinion on review B's B-1"** below; this entry records the evidence.

- **Locations (Rust):** `src/proof/tbox.rs:1092–1093` (prover: `hash0` = hz), `:1104–1120` (g sampled, `tg` hashed
  after hz), `:781–783` / `:789–794` (verifier: hz, then the tg round), `:716`, `:721` (`sz_z4` / `sz_z3` seeded with
  `hash0`); `src/sv.rs:1316–1318` (hz), `:1328–1332` (hash1 = H(hz ‖ tg)), `:1393` (`g0 = &hz`), `:1449–1450`
  (`urandom_mat (v4 / v3, g0, …)`). C: `lazer/lnp-tbox.c:417–418`, `:484–499`, `:697–711` (prover), `:1185–1186`,
  `:1201–1222`, `:1283–1296` (verifier); `src/pqz_sv.c:1596` (`prg_seed (&g0, hash0)`), `:1541–1543` (tg round),
  `:1649` (`urandom_mat (V4 / V3, &g0, …)`).
- **Trigger:** a cheating prover. After `compute_z34` it publishes a `z3` / `z4` that is **not** `y + β·R·s`, derives
  V3 / V4 from hz (known before `tg`), computes the V-folded error in coefficients 0 and d/2 of each merged
  accumulator, and sets those two coefficients of `g_i` to its negative before committing `tg`. Every other equation is
  honest, so its γ-weighted part is zero in those coefficients whatever γ (drawn after `tg`) is.
- **Run (Rust, this review):** a patched copy of the crate's prover (`scratchpad/reviewA/poc`, git-ignored; only
  `tbox::prove` / `compute_z34` changed) proves the vectors' 14 honest rows (`proof_pqzl.json`, one per relation code),
  and the **unmodified** crate verifies (`Ctx::verify`, `Ctx::verify_fast`):
  - mode 0 (sanity): the patched prover's proof is byte-identical to the vector, the V-only offsets are 0;
  - mode 3 (control): `z4[0][0] += 1`, no cancellation: rejected by both verifiers on all 14 codes;
  - mode 1: `z4[0][0] += 1`, cancelled through `g`: **accepted by both verifiers on all 14 codes**;
  - mode 2: `z3 = y3` (the `β3·R·s3` term dropped, so z3 carries no information about s3), cancelled through `g`:
    **accepted by both verifiers on all 14 codes** (`scratchpad/reviewA/poc-run1.txt`).
  The C verifiers were not run on these proofs (stopped at the controller's request); the C order is the same by
  reading (locations above), and C = Rust verdict parity is what the differential and fuzz runs maintain.
- **Impact:** the approximate ℓ2 bound on s3 = (Ps s1, Es s1, υ) and the ℓ∞ bound on s4 = Ds s1 are not enforced. What
  remains is z1's norm check and the exact equations mod q. The exact-ℓ2 equations conclude over Z only while no block
  wraps (‖x‖² < q − 2^bitlen(B²), i.e. ‖x‖ ≳ 2^21). From the parameters, the z1 bound √(2·m1·64·962·2^(2·log2stdev1)/400)
  divided by a typical ‖c‖₂ ≈ 39 allows a single block of norm 2^19.9 (R_REG) … 2^20.5 (R_TX, R_TXM M ≤ 4) and
  **2^21.8 for R_TXM M = 8 (auditor on and off)**, so on the M = 8 shapes a block can wrap without any grinding.
  **Hypothesis (not run):** a mint on R_TXM M = 8: send to a recipient key whose noise vector `e` the attacker knows
  (its own second account), with an encryption randomness block `r` of norm ≈ 2^21 satisfying the exact-ℓ2 row by
  wrapping, aligned so that `(eᵀ r)_i ≈ k_i·Δ` (|eᵀ r| can reach ‖e‖·‖r‖ ≈ 164·2^21 ≈ 5Δ); the recipient then decrypts
  d_i + k_i with small noise and can spend it. For the other shapes the same would need a challenge c with small
  ‖c·r‖/‖r‖, plausibly reachable by grinding c (hypothesis). Either way this is the consequence class review D rated P0
  for D-1 (lazer#28), now shown to be reachable by an end-to-end run at the transcript level.
- **Suggested fix:** as B-1 (agreed, with one addition, see the second-opinion section): derive V3 / V4 from **hash1**
  (after `tg`), same domains; R / R' stay on `cseed`. Changes proof bytes (V, hence h, μ, c): `proofSystemId` v4,
  regenerated vectors and digests; honest verdicts of v4 proofs unchanged in kind. Regression test: the mode 1 / mode 2
  provers above as a cheating fixture (C and Rust, all four verifiers must reject), plus B's `fs_bind` check that the
  V seeds change with `tg`.

### A-2 — P3 — Schwartz–Zippel domain collision: β4 row i = 63 and the υ row

- **Locations:** Rust `src/proof/tbox.rs:638–644` (β4: `dom = M + d − 1 + i`, i = 1..63, so up to `M + 126`), `:662`
  (υ: `dom = M + 2(d − 1)` = `M + 126`); `src/sv.rs:1567` / `:1569`; C `lazer/lnp-tbox.c` `__schwartz_zippel_accumulate_beta4`
  (`dom + i`, called with `M + d − 1`, `:660`, verifier `:1250`) and `_upsilon` (`dom`, called with `M + 2·(d − 1)`, `:670`, verifier `:1259`); C SV the same
  table as Rust SV.
- **Trigger:** none needed: every proof. Both rows draw their λ challenge values from `urandom_q (·, hash1, M + 126)`,
  so the accumulators only enforce the sum `f_β4,63(s) + f_υ(s)` (constant coefficients), not each row.
- **Impact:** none found. The freed direction is one antisymmetric pair t·(X^j + X^(64−j)) of the β4 half
  B4 = (β − σβ)/2; the quadratic row `B4² = −1` that the lower protocol proves over R_q (`beta_eqs`, `tbox.rs:576–596`)
  gives B4² = −β4² − 2t² + 2β4·t·(X^(32+j) − X^(j−32)…) + t²·(…), whose non-constant coefficients force t = 0 (q odd
  prime). So `f_β4,63 = 0` is enforced anyway and υ's row stands on its own. A latent Schwartz–Zippel defect (two rows,
  one challenge), inherited from upstream's numbering, not a break.
- **Confirmed / hypothesis:** collision confirmed in code; non-exploitability is my argument (not run).
- **Suggested fix:** fold into the v4 transcript change of A-1: move υ / binary / exact-ℓ2 (and the V domains above
  them) up by one (`M + 2(d−1) + 1`, `+ 2`, `+ 3 + i`). Changes proof bytes; no verdict changes on honest proofs.

### A-3 — P3 — Rust lags the C core's Q-B wiping (key helpers, witness parsing)

- **Locations:** `src/keys.rs:159–160` (`keypair_from_secret`: `sv`, `ev` = the secret key and its noise), `:204–205`
  (`encrypt_raw`: `rv`, `ev` = the encryption randomness, which with `u` reveals every message), `:300–305`
  (`decrypt_raw`: `sv`, `vv`, `acc`: the key and the plaintext), `:175–184` / `:271–284` (`keygen` / `enc_seed`: the
  boxed s, e / r, e1, e2 dropped unwiped on the `Err(Reject)` and `?` exits); `src/rel.rs:678–688` (`dec_w`'s `acc`),
  `:708–727` (`debit_witness`: `d`, `dp`, `dsum`, `wv`, `mm`, `et`, `c`), `:777` (`dr_witness`'s `wv`), `:795–799`
  (`set_upsilon`'s `n2`, `d`, the slack). `src/lib.rs:94–102` still says these are "as in C (STATUS Open 8)".
- **Trigger:** any key derivation, encryption, decryption or prove.
- **Impact:** secret keys, encryption randomness, plaintext digits and balance values stay in freed heap / stack after
  the call. Needs a memory-read capability; no transcript leak. Since round 2 (Q-B, `d08e3f9`) the C core wipes exactly
  these (`pqz_rel.c:1176`, `:1220–1221`, `:1241`, `:1509`, `:1551`, `:1577–1578`, `pqz_keys.c:197`, `:209`), so the
  production Rust core is now the weaker of the two; review M rated the C version P1 / triaged P2.
- **Suggested fix:** `Wiped` for the `PolyVec`s and the `[i64; 16]` arrays (an `impl Wipe for [i64; N]`), a wiping
  guard for the boxed outputs on the error paths, `crate::wipe` of `dec_w`'s accumulator; update the `lib.rs` comment.
  Proof bytes, keys and verdicts unchanged.
- **Status: fixed** in `aee749df` (branch `rev2-small-fixes`): the suggested fix as above (`Wiped` guards on the key
  helpers' and witness parsing's secrets, wiping on the error exits, `Wipe` for `[T; N]`, `Vec<T>`, `Box<T>`, `Poly`;
  `lib.rs` comment updated). Verified 2026-10-20 by `scripts/capped sh pqz-core/pqzl/rust/run.sh a3`
  (`pqz-core/pqzl/rust/runs/a3-*`): every test binary ok (`c-oracle`, `test-hooks`, `bench`), KATs and native vectors
  as before, bench and wasm `proofs_fnv` equal to the pinned digests (proof bytes unchanged), native = wasm32 on 387
  digest lines, 0 fails.

---

## Second opinion on review B's B-1 (controller request, 2026-10-20)

Question: is the order as B-1 states, is the attack algebra sound (does anything bind g's coefficients 0 and d/2 before
V, or multiply the z3 / z4 rows by a post-`tg` challenge?), and is the proposed fix correct and sufficient?

**1. Order: as stated, in all four verifiers and both provers.**

| Step | Rust generic (P / V) | Rust SV | C generic (P / V) | C SV |
|---|---|---|---|---|
| hz = H(cseed ‖ z3 ‖ z4) → `hash0` | `tbox.rs:1092–1093` / `:782–783` | `sv.rs:1316–1318` | `lnp-tbox.c:417–418` / `:1185–1186` | `pqz_sv.c:1519–1533` |
| g sampled (coeff 0, d/2 = 0), `tg` hashed → hash1 | `:1104–1120` / `:789–794` | `:1328–1332` | `:462–499` / `:1201–1222` | `:1540–1544` |
| γ (input equations, β3, β4, υ, binary, ℓ2) from hash1 | `accumulate_all` `:625–707` (`hash`) | `g1` `:1552–1576` | `:639–670` + bin / ℓ2 (`hash`) | `g1` |
| **V4, V3 from `hash0`** | `:716`, `:721` (`hash0`) | `:1449–1450` (`g0 = &hz`) | `:697–711` (`hash0`) | `:1596`, `:1649` (`g0`) |
| JL rows R, R' from cseed | `rseed = cseed` | `hash0` (= cseed) `:1477`, `:1499` | `hashr` | `gr` |

**2. Algebra: sound; nothing else binds g or re-randomises the V rows.** I checked each candidate:
- *g's coefficients 0 and d/2 are not checked anywhere.* The verifier checks only `h_i` (coefficients 0, d/2:
  `tbox.rs:784–788`, `sv.rs:1321–1325`); g enters only through `tg` (a commitment, hashed) and the lower protocol's
  equation `acc_i(s) + g_i − h_i = 0` (`finish`, `tbox.rs:731–743`: `r0 −= h_i`, coefficient 1 on g_i), which holds for
  any g the prover commits. The zero coefficients are a property of the honest sampler only (`tbox.rs:1103–1108`).
- *No post-`tg` challenge multiplies the V rows.* `sz_z4` / `sz_z3` pre-multiply row k of V into accumulator k / 2 of
  pair k % 2 and call `accumulate (…, None, …)` (`tbox.rs:435`, `:517`: no γ); `sz_auto` (`:189`) is a fixed linear map
  (σ, X^(d/2), ½) that sends the constant coefficients of the two halves to coefficients 0 and d/2 of the merged
  accumulator, without randomness. μ (from hash2) folds the merged equations *after* h is fixed, so it cannot see an
  error that h already absorbed: the lower protocol only checks `acc + g − h = 0`, which the cheater satisfies exactly.
- *The γ part does not interfere.* For an otherwise honest s every γ-weighted row has zero constant coefficient, so its
  contribution to coefficients 0 and d/2 is zero for every γ: the cheater can compute the needed g before γ exists.
- *Nothing earlier binds g.* `tB` is not hashed by `abdlop_hashcomm` beyond `tB_` (l = 0: `abdlop.rs:39–43`), so `tg`
  is first absorbed in its own round, after hz.

Dynamic confirmation (done before the static-only request; see A-1): with the V part computed before `tg` and
subtracted through g, a z3 with no β3·R·s3 term and an off-by-one z4 verify in the Rust generic and specialised
verifiers on all 14 codes; the un-cancelled control is rejected.

**3. Fix: correct and sufficient for this gap, with one addition.**
- *Correct.* Seeding V3 / V4 from hash1 = H(hz ‖ tg) puts V after every prover value the V rows touch: s1 (tA1), y3 /
  y4 (ty3 / ty4, in cseed), β (tβ, in cseed), z3 / z4 (hz) and g (tg). Then Pr[V-folded error = −g at coefficients 0,
  d/2] = 1/q per accumulator half, the standard vanishing-constant-coefficient argument (LNP22 §4.4). The honest prover
  is unaffected in structure: g does not depend on V, h is computed after both γ and V and still enters hash2 before μ
  and c. R / R' must stay on cseed (z depends on them; moving them after hz would be circular).
- *Domains.* With V on hash1, the V draws use `intmat_urandom`'s row domains `dom << 32 | 256·i` with dom =
  `M + 2(d−1) + 2 + Z` (z4) and `+ 256` (z3), i.e. ≥ 2^32, while every γ draw uses `urandom_q (·, hash1, dom)` with
  dom < 2^32 (`tbox.rs:66–71`, `:55–60`, `sv.rs:577–594`); `Rng` puts dom in the nonce's first 8 bytes and the counter
  after it (`rand/rng.rs:7–11`), so the streams are disjoint. B-1's "no collision" holds for V.
- *Sufficient?* For this gap, yes: after the change every challenge that is combined into the h accumulators (γ for
  the input / β / υ / binary / ℓ2 rows, V3 / V4) is drawn after `tg`, and μ and c after h (v3). I re-derived the order
  of every other message (tA1 → hash before cseed; ty3 / ty4 / tβ → cseed before R, R'; z3 / z4 → hz; tg → hash1; h →
  hash2 before μ; t, v, w1 → c) and found no other challenge drawn before a message it is combined with.
- *Addition:* review B's statement "the domains do not collide" is true for V but not for the existing γ table: the
  last β4 row and the υ row already share `(hash1, M + 2(d−1))` (A-2). Not exploitable, but since v4 changes the
  transcript anyway, renumbering in the same bump is free.
- *Tests to add with the fix:* the cheating prover of A-1 (modes 1 and 2) as a fixture both cores must reject in all
  four verifiers; B's `fs_bind` extension (the V seeds change when `tg` changes).

---

## Checked and clean

Soundness (verifier side), re-verified at `a61d221`:
- v3 transcript (apart from A-1): z3 / z4 absorbed after their norm checks (`tbox.rs:774–783`, `sv.rs:1302–1318`), R / R'
  on cseed (`tbox.rs:716`, `:721` `rseed`; `sv.rs:1477`, `:1499` `hash0` = cseed), h → hash2 before μ and c
  (`tbox.rs:802`, `quad.rs:22`, `:141`; `sv.rs:1336`, `:1736`); early returns never resume a transcript.
- Norm checks: z1 (`quad.rs:146–151`, `sv.rs:1341`, bounds equal by `sv.rs` test `setup_limits_eq_generic`),
  `(z21, w − γ·w1)` (`quad.rs:154–157`, `sv.rs:1746–1749`), z3 ℓ2 / z4 ℓ∞ (`tbox.rs:295–308`, `sv.rs:1297–1302`), hint
  ℓ∞ ≤ m (`quad.rs:160`, `sv.rs:1345`), c ∈ [−8, 8] then c = c' (`quad.rs:141–143`, `sv.rs:1351`, `:1740`),
  h coefficients 0 and d/2 (`tbox.rs:784–788`, `sv.rs:1321–1325`), per-block ℓ2 domains (`tbox.rs:686–707`). Every
  relation has nex > 0 and nprime = 1, so the SV's unconditional z3 / z4 checks equal the generic conditional ones.
- Decoding canonicality (`coder.rs:196–309`): bounded reads (`get`), fixed-width values < modulus, ghint and grandom
  bijective, pad one + zero tail + no trailing byte; the hint bound linf ≤ m (not m/2, despite the "2 linf(h) ≤ m"
  comment) is unreachable by encoding: smallest m = 1,408,508 (R_TXM M = 8), |hint| ≤ ~393 k under MAX_PROOF, pinned by
  `sv.rs` test `hint_bound_unreachable_by_encoding`; Gaussian |z| ≤ 2^20·393 k ≈ 2^38.6 < q/2 (no alias).
- Statement parsing: exact length (`rel.rs:124–150`) before any cache, hash or slice; every `&stmt[..]` offset in
  `parse_debit` / `parse_disc` / `rd_poly` is inside the exact length; `word64` < 2^64; coefficients < q.
- SV arithmetic: `mulq` (< 2^51 before the folds), `modq` (|x| < 2^51 precondition, callers within it), `l2_sum`
  saturation, `jl_fold` |acc| < 256 q, `use_ghint` divisions on public values (`sv.rs:66–100`, `:610–645`, `:1222–1236`,
  `:1704–1720`).

Panics / overflow / casts:
- No `unwrap` / `expect` / `panic!` in production paths; the `assert!`s in `arith/{int,polyvec,polymat}.rs` index by
  parameter-derived sizes only. All `as usize` / `as u32` casts in `coder.rs`, `rel.rs`, `sv.rs`, `proof/` are on
  parameters or bounded counts (`bits` checked against the cap before `as usize`, `coder.rs:399–405`); `Rd::pos` ≤
  8·MAX_PROOF fits wasm32's usize.
- Dynamic: verify / verify_fast / the C core's verifiers on extreme and mutated proofs with overflow checks and debug
  assertions on (results under "Commands").

Allocation failure: growth sites in the decoder, the coder, the verifiers and the prover reserve fallibly
(`try_reserve*` → `Error::Memory`); `Error::Memory` is only returned for real allocation failures (no size computed from
the proof reaches an allocation: every size is a parameter or bounded by MAX_PROOF); `try_verify*` keep it apart from
verdicts (`lib.rs:201–209`). `tests/memory.rs` (sampled denial) runs in `run.sh` (results under "Commands").

`unsafe`: `forbid(unsafe_code)` unless `c-oracle` / `ctgrind` (`lib.rs:6–8`); the only `unsafe` outside `c_oracle.rs`
is `ct.rs`'s memcheck client request (feature `ctgrind`, x86-64 asm; rdi rotated by 128 bits, rbx exchanged with
itself). The wasm bench harness (`wasm/lib.rs:88–91`, a separate test-only crate) wraps `from_raw_parts` in a safe fn
`sl`; not in any production build (same pattern as review K's F6 for PQZH).

Constant time (what ctgrind cannot see): `fixexp.rs` after Q-A has no variable-amount u128 shift on secret data
(remaining u128 shifts are by constants or by the public loop index in `div_q56`); u64 shifts by secret amounts
(`bernoulli_fp`, `rej_bimodal`) are single `i64.shr_u` on wasm32. wasm32 lowering of the release harness built by `run.sh` (`wasm/`, `llvm-objdump-18 -d`): the compiler-builtins
i128 routines `__multi3`, `__ashlti3`, `__lshrti3` are linked but never called (no `call` targets them; every u128
product and shift is inlined as i64 ops); the 64-bit divisions left (`i64.div_*` / `rem_*`) sit in `sv::verify_body` /
`verify_sv`, `tbox::vr_polys` (V·R, public challenges), `coder::encode_proof` and `Coder::grandom` (`ao / 2`, a
parameter) and `bench::verify_bad`: none on prover secrets. Data-dependent `br_if` on secrets was not re-audited
beyond fix E's reading.

Round-2 changes touching the crate: Q-A (`bernoulli_fp` masked add, test `bernoulli_masked_add_eq_shift`), fix C
(`canonical` `chunks_exact`), fix A (length before caches, test `bad_length_refused_before_caches`), the Rust-port minors
(`tests/memory.rs` settings echo, two-limb S3 oracle in `tests/oracle_rand.rs`).

## Not checked

- The C verifiers on A-1's cheating proofs (stopped at the controller's request); the mint chain of A-1 (not built).
- Exhaustive allocation denial (`PQZL_MEM_SWEEP=0,1000000000,0`) on the current code: only the sampled default ran.
- Timing; engine-level wasm32 tiers (Liftoff / TurboFan / wasmtime lowering of `select`); dependency internals (`aes`,
  `sha3`); a proof of LNP22's soundness for these parameters.

## Commands run

All heavy jobs under `scripts/capped` (2 slots, `cargo -j2`), in the temporary worktree `scratchpad/reviewA/wt` (detached
at `a61d221`, removed afterwards) or the scratch copy `scratchpad/reviewA/poc` (git-ignored; logs beside it).

| Command | Result |
|---|---|
| `scripts/capped sh pqz-core/pqzl/rust/run.sh reviewA` (worktree) | **pass**: 19 `test result: ok` lines, 0 failed (incl. `oracle_*` C = Rust, `sv_eq_c_sv` / `sv_eq_generic` 4,524 cases 0 mismatches, `cheating_rejected`, `fs_bind`, `memory.rs` `exhaustion_is_error` + `peak_per_op`); kat 19/19; keys KAT `pqz_kat: ok` (free and Ctx); `to_rust.py --check` 15 files equal; FNV bench native / fast / wasm32 all `equal`, `fails 0`; native = wasm32 387 digest lines equal; clippy and wasm32 builds `[rc=0]` |
| `cargo test --release --test poc` (scratch copy, cheating prover of A-1) | **A-1 reproduced**: modes 1 / 2 accepted by `verify` and `verify_fast` on all 14 codes, control mode 3 rejected, mode 0 byte-identical to the vectors (`poc-run1.txt`, 80 s) |
| the same with the C core's verdicts (`c-oracle`) | **not run**: stopped while queued, at the controller's static-only request |
| `cargo test --test extremes` (profile with `overflow-checks` and `debug-assertions` on, crate and dependencies; unmodified `pqzl` verifiers plus `c_verify` / `c_verify_fast`) | **pass**: 2,828 cases (per code: z1, z21, z3, z4, hint, h, c set to the largest magnitude that still encodes under MAX_PROOF, half of it, ±9, ±(2^25 + 1); 150 random bit / byte / truncate / extend mutations), no panic, the four verdicts equal on every case, 7 accepted, each byte-identical to the honest proof (the value set equalled the existing coefficient, or a c value congruent mod 2ω + 1 = 17; re-run with `NMUT=0` printing them, `extremes-accepted.txt`) (`extremes-run.txt`, 2,271 s) |
| `cargo test --release --features prove,test-hooks --test fault --test verify_only` (`pqz-core/ffi`, Rust backend, worktree) | **pass**: `node faults: Ctx and core allocation failures and worker failure → status 4, out untouched; recovered`; the `TEST_PANIC` path (two intentional panics at `src/pqzl/rust.rs:77`) caught; `verify_only_arena` ok, heap after 5,000 mixed calls equal to before |
| `llvm-objdump-18 -d` of `wasm/target/wasm32-unknown-unknown/release/pqzl_wasm.wasm` + a call-index scan | no call to `__multi3` / `__ashlti3` / `__lshrti3`; division sites listed under "Checked and clean" |
