# R3 — Claude UltraCode review

Unit R3, PQZH Ligero (code), at commit 008e196c. Read-only review: nothing was built, run or modified. Every finding below survived refutation by three independent votes, and duplicates are merged. The final severity is the majority vote. P4 means below P3: informational, about documentation precision.

## Findings

| id | severity | file:line | claim | evidence | fix |
|---|---|---|---|---|---|
| R3-C1 | P3 | `pqz-core/pqzh/ligero/src/set.rs:20-25`; `pqz-core/params/sets/n2304-kmax4096/pqzh_set_fallback.rs:20-23`; `pqz-core/params/sets/n2304-kmax4096/rust/set.rs:64-66`; `pqz-core/pqzh/ligero/src/cs.rs:938-945`; `pqz-core/ffi/src/lib.rs:28`; `pqz-core/pqzh/ligero/wasm/Cargo.toml:23` | With features `set-n2304-kmax4096` and `fallback-retry`, the verifier runs THE preset (n 32,756 / k 817 / t 121) under preset B's proofSystemId. pqz-ffi has no guard that refuses this build. | The `fallback-retry` feature swaps only the `pqzh` module, to `pqzh_set_fallback.rs` (PRESET_N 32_756, PRESET_K 817, PRESET_T 121). `PQZH_LABEL` stays `scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v2`: there is one `rust/set.rs` per set, and pqzh-ligero/Cargo.toml:22 does not forward the feature to pqz-stmt. `Params::proven()` (ligero.rs:98-100) reads the fallback PRESET_*, while cs.rs:357/393 accept statements carrying preset B's `PQZH_ID`. `Tr::new` (transcript.rs:16-18) absorbs only tag, op and stmt, never n/k/t, so the id is the only binding of the parameters. pqz-ffi's only feature guard is `assert!(!pqz_stmt::OVERSIZE)`, and pqzh-ligero exports no constant that would let pqz-ffi refuse the feature. The test `ids_are_the_labels_keccak` (cs.rs:938-945) has no cfg gate and asserts that the label contains `n{p.n}k{p.k}t{p.t}`, which is `n32756k817t121` in this build, so it must fail there. The recorded fallback runs (runs/c8b-fallback-tests.txt, runs/c8c-fallback-tests.txt) are from 3248c2d9 (2026-10-23 19:02), before the per-set label commit 91b95a24 (22:38), so no run covers it. Impact is limited. No forgery: a preset-B verifier rejects THE-preset proofs (different 2k-1 lengths and length bound). The feature is documented as research only ("never in a default or production build", ligero/Cargo.toml:19-22, params/sets/README.md). The only crate that forwards it is the wasm bench crate, which has its own `[workspace]`, so feature unification cannot pull it into a node build today. A consensus split would need a deliberately misconfigured node build. | Either (a) give fallback A its own label and id (`ligero-fq46-n32756k817t121-…`), emitted by gen_set.py and selected in pqz-stmt under a forwarded `fallback-retry`; or (b) export `pub const FALLBACK: bool = cfg!(feature = "fallback-retry")` from pqzh-ligero and add `const _: () = assert!(!pqzh_ligero::FALLBACK)` next to the OVERSIZE assert, plus a const assert in set.rs that PQZH_LABEL contains the compiled n/k/t. Optionally also absorb (n, k, t, pow_bits) in `Tr::new`. Re-run `runs/c8c.sh fallback` afterwards. |
| R3-C2 | P3 | `docs/contracts/pq-zero-knowledge.md:308, 552-555, 1708-1728, 1737` | The serialization section calls itself normative ("Every byte … frozen"), yet its PQZH transcript, proof format, length bounds and self-test value hold only at n2048-kmax1024 (the retired "Ligero v1"). They are wrong at the default set n2304-kmax4096 and at n2560-kmax16384, and the id table in the same section (around line 1556) is per set, so the section contradicts itself. | Line 554 says "word masked to 42 bits", but the code masks with `fq::MASK = (1<<L)-1` with `L = set::LOG2Q`, which is 46 or 50 at those sets (transcript.rs:33-35, fq.rs:16,22). Line 308 says A uses "the low 42 bits", but ring.rs:39, pqzl keys.rs:54 and pqz_rel.c:138 use LOG2Q. Lines 1708-1710 give n 32,756 / k 817 / ℓ 695 / t 121 with 6-byte F_q. At the default set the code uses preset B: n 45,752 / k 952 / t 120 / ℓ 831, a 2^16-leaf tree, bounds 207,688–251,608. At n2560: EB 7, t 122, debit bounds 303,412–305,120 (MAX_PROOF_PQZH 327,680), not "below 262,144" as lines 1727-1728 say. Line 1737 freezes `0xed910a2c…1333d205`, which is only in smartcontracts/vectors/pqz/selftest.json (n2048). n2304's selftest.json has `23d7a1db…040c97c0` and n2560's has `167c772e…d8bb45e7`. No note in the section says the literal numbers are n2048's. Only the doc is wrong: the code, the vectors and each set's PQZH.md agree, and the spec says the code wins where they differ. | Make these paragraphs per set: the mask is LOG2Q bits, EB = ceil(LOG2Q/8), (n, k, ℓ, t) come from the set's pqzh_set.rs, the tree is padded to 2^ceil(log2 n), and the bounds and self-test value are in `params/sets/<set>/`. Rename "Ligero v1" to the per-set v2 ids. Alternatively, state at the top that the literal numbers are n2048-kmax1024's. |
| R3-C3 | P3 | `pqz-core/nethermind/chain/add-schedule.py:22-23, 29-30, 82-94` (outside R3's file list, found under the retired-id lens) | The `--id pqzl` / `--id pqzh` aliases resolve to retired ids, so they match no row on a chain built with the 8d library. | `IDS = {"pqzl": "0x8079d65b…" (PQZL v3), "pqzh": "0x0a47a768…" (PQZH v1)}`, and line 30 does `idp = IDS.get(idp, idp)`. Both hashes are in gen_set.py:81-86 RETIRED and stmt/src/tests.rs:134-137, and the library refuses them. The SCaaS testnet now runs 2.2.0-pqz4 with only the new-id provisional rows (decisions.md:3642, provisional-rows.py:1-15). So `--id pqzh` exits at lines 48-49 with "no rows of ops … id …". This fails closed (no wrong schedule is written), and the hex-prefix form still works. The self-check builds its rows from the same `IDS`, so it still passes. Keeping the old ids was a deliberate deferral to plan 5h Task 9 (decisions.md:3638), but the testnet reset on 2026-10-25 has made the stated reason stale. Ids are now per set, so one fixed alias cannot be right. | Do this together with Task 9: derive the aliases from the built set (PQZL_ID / PQZH_ID, set.json or PqzSet.sol), or drop the names and require a hex prefix. Make the self-check refuse retired ids. |
| R3-C4 | P3 | `pqz-core/pqzh/ligero/src/fft.rs:1-2, 12, 48, 188-190, 213`; `pqz-core/pqzh/ligero/src/ligero.rs:8, 94-97` | In-code spec comments still describe only n2048-kmax1024 / THE preset. The code itself is set-generic and correct. | fft.rs:1-2 says the radices are "2, 19, 43 and 431 in every set so far", fft.rs:12 gives NMAX as "2^3 * 19 * 43 * 431", and the panic message at fft.rs:48 reads "2^a 19^b 43^c 431^d". But n2304-kmax4096/pqzh_set.rs:20 has `RADICES = [2, 7, 17, 19, 43, 431]` (n 45,752 = 2^3·7·19·43, k 952 = 2^3·7·17). fft.rs:188-190 calls the radix-7/17 sizes "research spike B", but they are the production preset B (set.rs:18). fft.rs:213 says "q-1 = 2^3*19*43*431*… in every set". ligero.rs:8 says "F_q = 6 bytes", but `EB = L.div_ceil(8)` (fq.rs:20) is 7 at L = 50 (n2560). ligero.rs:94-97 says THE preset is "the same in every parameter set", but n2304 uses 45,752 / 952 / 120 (ℓ 831) and n2560 uses t 122 (ℓ 694). NMAX, `smooth()`, EB and `proven()` all read `crate::set`, so behaviour is unaffected. | Refer to `crate::set::RADICES`, PRESET_* and EB = ceil(LOG2Q/8) instead of literal values. Print RADICES in the fft.rs:48 message. Relabel "spike B" as preset B. |
| R3-C5 | P3 | `pqz-core/pqzh/ligero/src/ligero.rs:497`; size from `pqz-core/pqzh/ligero/src/ring.rs:29-32` | The try_verify doc gives the infallibly allocated matrix A as "512 KiB", which is right only at n2048-kmax1024. | ring.rs:32 allocates `vec![[0i64; D]; K * K]` inside a OnceLock, which is K·K·512 bytes. K = 32 / 36 / 40 gives 512 / 648 / 800 KiB, so the doc understates the size by up to 56 % at n2560. (n2816, K 44, has no PQZH build.) The doc also says A is built in `cs.rs`; it is built in `ring.rs` (`a_matrix`), and cs.rs:778 only calls it. | State "K·K·512 bytes (512 / 648 / 800 KiB per set), built in ring.rs". |
| R3-C6 | P4 | `pqz-core/pqzh/ligero/src/ligero.rs:493-498, 550, 555-556, 577`; `pqz-core/pqzh/ligero/src/cs.rs:734, 790-798`; `pqz-core/pqzh/ligero/src/merkle.rs:64` | Review P-D's documented Oom coverage is slightly overstated. Some small verifier buffers of the kinds the doc says are covered still use infallible allocation, which aborts on native allocation failure; catch_unwind cannot catch an abort. | ligero.rs:555-556 has `cols = try_vec(idx.len())?`, and the next line is `leaves = Vec::with_capacity(idx.len())`. `idx` (550) and `own` (577) are built with `collect()`. In cs.rs, `comb` builds `rp = vec![F4::ONE; D+1]` and `own / beta / ones = vec![…; m]` (792-798); `Bld::ring` builds `gam` with `Vec::with_capacity(nout)` (734). merkle.rs:64 `root_from` builds each level with `Vec::with_capacity`. try_verify's doc (492-498) claims coverage of "the opened columns" and "the linear test's combination vectors", and its "Not covered" list does not name these buffers. Not reachable from input: every one is sized by parameters or the layout (t ≤ 122, m a few hundred, D+1 = 65), a few KB, the same class as the "layout tables (a few KB)" the doc already exempts. comb's own doc (cs.rs:790-791) is accurate. | Add "small fixed-size scratch (index lists, Merkle levels, the m-length combination weights, rp, gam)" to the Not-covered list at ligero.rs:496-498, or switch `leaves` to `try_vec` to match `cols`. |

## Refuted

| claim | reason refuted |
|---|---|
| A PQZH verifier panic never reaches the precompile's input-panic signal (status 3): `try_verify` turns it into a plain false (ligero.rs:499-504, ffi/src/lib.rs:101-113) | The described behaviour is intentional and documented. pqz-core/ffi/README.md:113-116 says Ligero catches its own verifier panics and returns `…00` (counted in `VERIFY_PANICS`), and ffi/src/pqzh.rs:11 says the same. There is no consensus effect and no input is known that reaches a panic. What remains is an observability suggestion (`resume_unwind`, as pqzl/rust.rs:20 does): P4 at most. |

## Checked and sound

- **Field arithmetic, native u128, at every PQZH q (L = 42 / 46 / 50):**
  - Recomputed MUX = ⌊2^BARX/q⌋, R64 = 2^64 mod q, BARX = 2L+4 and 2^(L-1) < q < 2^L for every set (rust/set.rs:11-49). The const assert at fq.rs:18 holds.
  - `redx`: the Barrett error is ≤ 2, so `red3q` suffices. `(x>>(L-1))·MUX < 2^(2L+10) ≤ 2^128`.
  - `red(u128)`: q² + 2^64 < 2^X.
  - F_q^4 product sums: (1+3NR)q² = 10q² < 2^X, with NR ≤ 5 asserted.
  - X⁴ − 3 is irreducible (3 is a non-square, q ≡ 1 mod 8).
  - `from_i64`, `csub`, `red3q` and `Sub` are branch-free and in range.
  - Fq codec: EB = 6 / 6 / 7 bytes, and `Fq::get` rejects v ≥ q.
- **wasm32 limb split:**
  - (NL, W) = (2, 21) / (3, 16) / (3, 17), with CD = 3 / 4 / 3 and NH = 4 / 6 / 5.
  - Column bound NL(2^W−1)²·2^20 < 2^64; fold bound (NH+1)·2^(W(NL+1)+1) ≤ 2^XB; MU < 2^32 and x>>(L−1) < 2^32, so the Barrett product fits u64. The const asserts at fq.rs:96-102 suffice.
  - One gap-round reviewer emulated `limb::red` in Python with 20k random and extreme inputs at all three L; every result matched.
  - The 2^20-term Acc4 cap is never approached (largest sum: eval4 at 2k−1 ≤ 1,903 terms).
- **Native = wasm32:** only `Fq::mul`, `F4::mul` and `Acc4` switch on target_arch, and both paths return canonical values (test `limb_matches_u128`). FFT, transcript and Merkle code is shared. No 32-bit usize overflow: NMAX at n2304 is 335,224,904 < 2^32, and FFT indices stay below n.
- **FFT domains (radices 2 / 7 / 17 / 19 / 43 / 431):**
  - QM1 factors are prime and multiply to q−1 for n2048, n2304 preset B, the n2304 fallback and n2560. GEN = 3 generates F_q^*.
  - NMAX = 4·∏RADICES divides q−1 (const assert, fft.rs:21). n and k are smooth; n2 = 1,634 / 2,261.
  - Mixed-radix DIT recombination and inverse index are correct.
  - The sparse path is chosen from the structural `len` (ns = ⌈len/stride⌉), so the P-A fix holds.
  - Lazy sums ≤ 431·q² < 2^109.
- **GEN·H_n ∩ H_k = ∅:** the intersection is non-empty iff GEN^lcm(n,k) = 1, which is impossible because lcm < q−1 (1,408,508 for THE preset; 777,784 for preset B). gen_set.py:203 and fft.rs:215-218 check it per set, so the Lagrange denominators and Z_ζ(η) are never zero.
- **Verifier checks complete** (ligero.rs:525-646):
  - Length gate first: rel_of, then `proof_len_ok` (1..=max_len_exact). Reads are bounds-safe (`Rd::take`), decoding is canonical, trailing bytes are rejected.
  - Degree: fixed counts 2k−1 / 2k−1 / 2k−1−ℓ, with the X^(k−1) proximity shift (n ≥ 4k at every preset).
  - Linear test: Σ_{H_k} = k(q₀+q_k), and L_c(η) = ω^c(η^k−1)/(k(η−ω^c)) over c < ℓ.
  - Quadratic test: h·Z_ζ = Σ r_t(u_x u_y − u_z) + u_quad.
  - Merkle: `root_from` over sorted distinct indices < n ends at index 0; a leaf preimage (32 + (m+12)·EB bytes) is never the 64-byte node length.
  - Fiat-Shamir order: root, then all challenges, then w‖q‖h, then PoW, then nonce, then indices. Squeeze and absorb domains are separated.
  - Linear-test weights are distinct powers ρ^e with e ≥ 1, so a nonzero-sum u_lin cannot cancel a violated constraint. The ring recurrence was re-derived.
  - Constraint system: rows 1–7 are complete, c₁₅ = 0, the l2 sums cannot wrap mod q (cs.rs:67), and decryption is unique (2^EBITS < Δ in every set).
  - rel_of and parse agree on every form and on op 7.
- **Soundness bits per preset t** (proven factor, e = ⌊(n−2k+1)/2⌋), query bits + 16 grinding:

  | preset | t | bits |
  |---|---|---|
  | n2048 | 121 | 128.50 |
  | n2304 preset B | 120 | 128.94 (model minimum 119) |
  | n2304 fallback | 121 | 128.50 |
  | n2560 | 122 | 129.43 |

  These match PQZH.md, set.toml and the labels. The ZK condition t < k−ℓ holds with ℓ = k−t−1. pqz-ffi verifies with `Params::proven()`.
- **Prover constant time (review O):**
  - Branch-free: `csub`, `red3q`, `from_i64`, `modq` (ct::mask), `ct_udiv`, `round_delta`. The FFT branches only on public structure.
  - Declassification inventory: `ct::public` covers only the root, wp / qp / hp and the output bytes; `ct::verdict` covers only the Rng accept bit and the self-check verdicts. No secret row, mask or salt is marked.
  - ctgrind runs at the production presets report 0 issues (ct-c8b-a.txt at n2304-kmax4096 and ct-c8c-n2560.txt). Prover changes since then are fallback-only or test-only.
- **Gap-round items:**
  - **ZK masking:** k−ℓ uniform pads per row; u₀ uniform over 2k−1 coefficients; u_lin with v[0] = −v[k] (Σ_{H_k} = 0); u_quad = Z_ζ·h₀ with 2k−1−ℓ coefficients; one fresh salt per leaf. So w, q, h and the opened columns are simulatable.
  - **Fallback rejection:** the proof length is a function of the deduplicated indices only, each retry gets a fresh salted root, and the RNG stream continues with no reuse.
  - **Hedged RNG:** the encoding is injective (wit is the last field), the tag `SCAAS-PQZH-LIGERO-RNG-V2` is unique, and Drop overwrites the reader in place, matching P-C's documented boundary.
  - **ring.rs:** `keypair` / `encrypt` match cs.rs rows 3–6 and pqz_rel.c (A^T r, coefficients ≥ 16 are zero). `dot_int` stays below 2^63 after the norm checks, and the intermediates are wrapped in `Wiped`.
- **Prior-round fixes P-A … P-D are still in place.** P-D's coverage is incomplete only in its documentation (R3-C6).

## Not covered

- client.rs (bench feature only): lines 1–100 and `mutate` / constants were read; the rest was only scanned.
- The pqzh/ligero/wasm crate, src/bin/* beyond ct.rs marking, and the internals of the runs/ct.sh / ctgrind harness.
- Constant-time and zeroisation behaviour of the wasm32 `__multi3` path.
- pqz-stmt `parse_multi` internals beyond the length, id and coefficient checks.
- ligero_params.py beyond set loading; the test-only Solidity LigeroVerifier; pqz-ffi beyond pqzh.rs, the panic and feature wiring, and build.rs vector selection.
- No test was run (read-only unit). That the fallback test fails (R3-C1) is inferred from the source, not observed.
- `nethermind/chain/engine-pqz.json` still carries only the retired ids. This is deliberate until the Task 9 calibration (decisions.md:3638), shares its root cause with R3-C3, and is not reported separately.
