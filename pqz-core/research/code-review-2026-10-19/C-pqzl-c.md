# Code review C: PQZL C core glue and verifiers (static, read-only), 2026-10-19

Scope: `pqz-core/pqzl/src/` (`pqz_sv.c`, `pqz_rel.c`, `pqz_keys.c`, `pqz_arena.c`, `pqz_ntt.c`, `pqz_*.h`,
`pqz_wasm_rt.c`), `pqz-core/pqzl/params/`. Where needed I compared against the vendored LaZer (`pqz-core/pqzl/lazer/`)
and the Rust port (`pqz-core/pqzl/rust/src/sv.rs`, `keys.rs`, `coder.rs`, `proof/tbox.rs`, `proof/quad.rs`). Checkout
`main` @ 4c20032. I built nothing and ran nothing.

## Findings

### F1 — P0 — Fiat–Shamir does not bind `h` before `μ`: anyone can forge a proof for any PQZL statement

**Where**

- C specialised verifier `pqz-core/pqzl/src/pqz_sv.c`:
  - 1488–1493: `hash1 = H(hash0 ‖ tg)`. `h` is checked at 1484–1487 but never absorbed.
  - 1780: the `μ_k` come from `g1 = hash1`, domain `k + 1`.
  - 1785–1794: `h` enters only as `Ra −= μ_k·h_k`.
- C generic verifier and prover (vendored LaZer):
  - Verifier: `lazer/lnp-tbox.c` 1156–1192 (the h check, then the tg round) and 1281 (`r0_i −= h_i`).
    `lnp_quad_many_verify (hash, …)` is called at 1313 and derives `μ` from that same `hash` at `lazer/lnp-quad-many.c:34` (`polyvec_urandom (mu, q, log2q, hash, 0)`).
  - Prover: `h_i = g_i + SZ_i(s)` at `lnp-tbox.c` 706–725, then `lnp_quad_many_prove (hash, …)` at 779 with the same `hash1`.
- Rust (the production core):
  - `rust/src/sv.rs` 1323–1328 (hash1 without h), 1628 (`μ` from `g1`), 1638 (`h` only in `ra`).
  - `rust/src/proof/tbox.rs` 770 / 1089 and `proof/quad.rs:22` are the same.

**Defect.** The tbox's "h" polynomials are prover messages. They are sent after the γ challenges and must come before
the `μ` challenge that combines all quadratic relations (LNP22's interactive order). The transcript derives `μ` from
`hash1 = H(… ‖ tg)`, which `h` does not enter. So the prover learns `μ` and only then picks `h`. This also breaks the
spec's own rule ("each prover message … is absorbed", `docs/contracts/pq-zero-knowledge.md:507`).

**Why the forgery works (algebra; every step read in the code above).**

1. The only check that ties the witness to the statement is the one quadratic relation
   `F(s) = Σ_k μ_k F_k(s) = 0`, checked through `v` and `c = H(hash1 ‖ t ‖ v ‖ w1)`.
2. For the λ/2 = 2 Schwartz–Zippel pairs, `F_i(s) = H_i(s) + g_i − h_i` (`r1` = 1 on the g slot, `r0 −= h_i`). So
   `F(s) = W − μ_0 h_0 − μ_1 h_1`, where W is fixed once `μ` is known: the SZ accumulators, β3² − 1, β4² − 1 and every
   R_q-linear input row are all inside W.
3. The verifier's only constraint on `h` is `h_i[0] = h_i[32] = 0` (`pqz_sv.c:1486`). So the prover needs
   `μ_0 h_0 + μ_1 h_1 = W` with `h_0, h_1` in the 62-dimensional subspace V: 64 linear equations mod q in
   124 unknowns.
4. For uniform `μ_0, μ_1`, `μ_0 V + μ_1 V = R_q` except with probability about 1/q. That set is smaller than R_q only
   when `μ_1/μ_0` maps V onto itself, e.g. when it lies in span{1, X^32}. So a solution exists, found by Gaussian
   elimination mod q.
5. With `F(s) = 0` the honest `lnp_quad_prove` completes. The norm checks the verifier makes directly (z1, z21 ‖
   w − γw1, z3, z4, hint, c) are passed by any short `s`.

**What a cheater can do.** Every evaluation equation and norm proof sits inside W, and so do the R_q-linear rows:
`pk = A s + e`, `u = A^T r + e1`, the encryption rows 3–6, the balance / carry row 7, the binary, range, υ and
exact-ℓ2 equations, and the JL consistency. None of them constrains anything once `h` is free. Concretely:

- An `R_TX` / `R_TXM` whose output `v_t` encrypts any amount while `v_f` stays the old balance: minting.
- An `R_BURN` above the balance.
- An `R_DR` / `R_DS` disclosing a false amount.
- An `R_REG` for a pk with no short secret.

It costs one proof's work plus one 64×124 linear solve: no grinding. `pqz_verify` (C generic), `pqz_verify_fast` (C SV)
and the Rust SV all accept, because they share the transcript. Everything is inherited from upstream LaZer: the fork's
P6-SZ / P6-L2 / P6-Z21 fixes do not touch this.

**Fix**

- Absorb `h` before `μ`: `hash2 = SHAKE128(hash1 ‖ coder_enc_urandom3(h, q, 42))`.
- Derive `μ` from `hash2`, and feed `hash2` into the final round (`c = H(hash2 ‖ t ‖ v ‖ w1)`).
- Apply it in all of these together:
  - prover (`lnp_tbox_prove` 779 → pass `hash2`);
  - generic verifier (`lnp_tbox_verify` 1313);
  - `pqz_sv.c` (1780 `urandom_q (mu, DEG, &g2, k + 1)`, 1890);
  - Rust `sv.rs` / `proof/tbox.rs` / `proof/quad.rs`.
- Bump `proofSystemId` to v3 (CTR-PQZ-09) and update the transcript paragraph of the spec.
- Report upstream (lazer-crypto/lazer), as with #24–#26.
- Add a regression fixture in the `l2dom` / `sz` style. The cheating prover is the honest prover on a false witness
  (e.g. an `R_REG` pk = random), with `h` replaced by the solution of `μ_0 h_0 + μ_1 h_1 = W` just before
  `lnp_quad_many_prove`. Today both verifiers must accept it; after the fix both must reject it. The existing
  `CHEAT` / `POC_IGNORE_ERR` hooks in `pqz_rel.c` already allow emitting such a proof.
- The fix also removes the γ/μ domain overlap noted under F-settled-1.

**Confidence**

- High on the transcript facts (read in all three implementations).
- High on the linear algebra.
- I did not run a PoC, because the rules forbid building. Treat it as P0 until a fixture shows rejection.

### F2 — P3 — the arena sink is smaller than single LaZer allocations, so exhaustion writes out of bounds (refines Open item 2)

**Where.** `pqz-core/pqzl/src/pqz_arena.c:20,33,148–150` (`PQZ_SINK` = 1 MiB) against `lazer/spolymat.c`
`spolymat_alloc`, which does `_alloc (nelems_max · sizeof (_spolymat_t))` and then a `memset` of that size.

**Defect.** On exhaustion, an allocation larger than 1 MiB gets the 1 MiB sink and is then written in full. That is an
out-of-bounds write into adjacent static memory, not only the "garbage pointers / crash" that Open item 2 describes.

**Scenario.** Take `pqz_verify` (generic) on `R_TX`. `_schwartz_zippel_poly` asks for
nelems_max = (328² − 328)/2 + 328 = 53,956 entries, several MiB. Run it with an arena that is exhausted at that
point: the memset overruns `sink`.

- Natively it can corrupt neighbouring `.bss` (for example the SV tables `SR` / `PR`), which persist into later calls.
  That gives a later wrong accept / reject on that node only: a divergence, not just a crash.
- In wasm it writes into linear memory beyond the sink.

**Why it is low.** It needs exhaustion. `pqz-ffi` sizes the arenas from measured peaks with margin and reports
`PQZ_ERR_ARENA` as a node fault, and the C core is now the opt-in backend.

**Fix.** Make exhaustion fatal for the call. Alternatively, size `PQZ_SINK` at least as large as the largest single
allocation and clamp `len` to it, or keep the error sticky and treat the context as poisoned until `pqz_init`.

**Confidence.** Medium on the size: I did not compute `sizeof (_spolymat_t)`, but at ≥ 20 B per entry the request is
already > 1 MiB.

## Questions from the aborted Codex pass, settled with code evidence

### F-settled-1 — reused challenge domain (β4 coefficient 63 and υ): no soundness loss

**The reuse.** C and Rust have the same schedule: `pqz_sv.c` 1699–1709 and `sv.rs` 1549–1560, the same as LaZer
`lnp-tbox.c` 1215–1229 / 2536.

- β3 uses domains M + i (i = 1..63) and β4 uses M + 63 + i.
- So β4's i = 63 equation and υ both use M + 126.
- The 4 challenges are equal in all λ accumulators, so the verifier learns only E_β4,63 + E_υ = 0.

**Why the two equations cannot cancel.**

- β4 = inv2·X^32(σβ − β) is σ-invariant (σ(X^32) = −X^32 and σ(σβ − β) = −(σβ − β)). The verifier computes
  o(β) itself from z (`nt_auto`, `pqz_sv.c:1532`), so this symmetry is structural.
- Hence b_{64−j} = −b_j. E_β4,63 = −b_1 and E_β4,1 = −b_63 = b_1. The i = 1 equation has its own domain M + 64.
- In every accumulator the pair contributes (g_{β4,1} − g_shared)·b_1 + g_shared·E_υ. Both coefficients are
  independent and uniform, so b_1 = 0 and E_υ = 0 are each forced (error 1/q per accumulator, as everywhere else).
- An independent second argument: equations i = 1..62 force β4's coefficients 2..63 to zero, so β4 = a + bX. The
  full-polynomial β4² − 1 relation then gives b² = 0 at X² (no reduction below degree 64, q prime), so b = 0.
- This matches `docs/research/pqz-l2-domain.md` §8.

**Caveat.** Both arguments assume the μ layer is sound, which F1 breaks.

**A second overlap, also inherited.** `μ_k` uses `(hash1, k + 1)` (`pqz_sv.c:1780`) while the SZ equations use
`(hash1, M + i …)`. The first 4 coefficients of `μ_k` therefore equal the γ of the equation whose domain is k + 1;
for `R_REG` (M = 0) that includes μ_0 = γ_β3,1. I found no identically vanishing combination (the products are
distinct degree-2 monomials), and the F1 fix (μ from `hash2`) removes the overlap. No separate finding.

### F-settled-2 — signed representatives in decryption: correct, C = Rust

- `pqz_decrypt_raw` (`pqz_rel.c:1500–1520`):
  - `rd_poly` centres v.
  - `poly_fromcrt` centres u^T s (`lazer/poly.c` `pqz_int_set_centred`).
  - `poly_sub` on coefficient-domain inputs ends with `intvec_redc` (`lazer/poly.c` `poly_sub`).
  - So w_i ∈ [−(q−1)/2, (q−1)/2], as `pqz.h:134` states.
- `pqz_dec` (`pqz_keys.c:189–196`): t = 2w + Δ + 2Δ·2^17 > 0, since 2^44 − 2^18 > q. floor(t / 2Δ) − 2^17 =
  round(w/Δ) exactly, and there are no ties: 2w is even while (2k+1)Δ is odd.
- Rust `keys.rs:290–318` is the same, including the canonical check before `decrypt_raw`.
- M_i can be anything in about ±2^15. Range-checking the digits is the caller's job, as documented.

### F-settled-3 — proof encoding is canonical within MAX_PROOF (C `pqz_decproof`, `pqz_rel.c:400–430`; Rust `coder.rs:251`)

- **Fixed-width fields.** `tB`, `h` (mod q, 42 bits), `tA1` (mod 2^31) and `c` (mod 17, 5 bits) are decoded by
  `_udecode`, which rejects any value ≥ its modulus (`lazer/coder.c` `intvec_lt (v, m)`). Each value has one encoding.
  `c` → `redc` gives [−8, 8] one-to-one.
- **z1, z21, z3, z4 (`coder_dec_grandom`).** (unary z1, two's-complement z0) ↔ z is a bijection. An alias through
  the verifier's mod q reduction needs |z| ≥ q/2, i.e. at least about q/2^(log2stdev+1) ≥ 2^21 unary bits
  (log2stdev ≤ 19 in every `params/*.h`). That is ≥ 256 KiB against MAX_PROOF = 96 KiB.
- **hint (`coder_dec_ghint`).** Bijective. Within 96 KiB, |hint| ≤ about 393 k < m/2 = 3.1 M, so hint and hint ± m
  (the same w1) cannot both fit. The Rust unit test `hint_bound_unreachable_by_encoding` pins this.
- **End of the proof.** `coder_dec_end` requires the pad 1 bit and zeros after it, and the decoder checks the exact
  length (`(offset >> 3) == len`). No trailing bytes are accepted.

## Areas checked and found sound (apart from F1)

- **SV arithmetic.**
  - Montgomery / CRT with 4 × 30-bit primes; `lift`, `mred` and `csub` preconditions.
  - Accumulator bounds (terms < 2^31 so sums < p·2^32).
  - Integer-polynomial bounds < 2^106 against P/2 ≈ 2^119, spot-checked on the largest sums: c·acc_nt(br),
    Gz, β3/β4, w.
  - `modq` / `mulq` / `centre` input ranges at every call site I looked at.
  - The Garner sign decision in `crt`.
  - No float, and 64-bit operations only, so native and wasm32 compute the same.
- **SV PRG.** AES-256-CTR key schedule and T-tables (FIPS vector in the test hook). The domain / counter layout
  (le64 dom ‖ BE counter) cannot run into the dom bytes. `urandom` rejection and buffer padding (+8 bytes). `ctr_bulk`
  AES-NI gives the same stream.
- **SV statement parsing** against `pqz_rel.c` (lengths; the auditorOn / M words with `rd_word64` canonicality;
  coefficients < q).
- **SV equation indexing.** Bit-slot bounds are < nbin·64. `URND_MAX` covers the M = 16 auditor case. `SVPR`,
  `SVBIN` and `SVZ` are all within limits.
- **SV working memory.** `sv_alloc` errors are sticky, so checking the last pointer suffices. `nsvb` cap.
  `tab_alloc` NULL handling. The setup failure path drops `SA` only when no relation is ready.
- **`pqz_arena.c` bookkeeping.** Size overflow is caught by `len > cap`. `free` ignores pointers outside
  [base, top) and double frees. The release rebuilds the free lists.
- **`pqz_ntt.c`.** `pqz_red128` and `red_limbs` bounds, and the Karatsuba middle term ≥ 0. The u128 path and the
  limb path give the same residues.
- **`pqz_wasm_rt.c`.** `__multi3`, `__ashlti3` and `__lshrti3` are correct for 0 ≤ s < 128.
- **Statement digest.** It binds op, be32(len) and the whole statement. R_TX / R_TX0 / R_TXM(1, ·) cannot be
  replayed across each other (op, length and ABDLOP keys differ).
- **Prover hedging (gap G2).** Implemented: `pqz_prover_seeds` hashes rnd32 ‖ H(wit) ‖ hash0 and clears its
  intermediate (`pqz_rel.c:1012–1021`). `ex` is cleared after the prove. Arena-resident secrets are Open item 8 as
  stated.
- **`pqz_keys.c`.** CBD sampling, the norm-threshold resampling and the canonical checks on pk, ct and digits.
- **C SV against Rust SV.** The transcript, the challenge schedule, the h check, the c range, the hint and z1 / z21 /
  z3 / z4 bounds, the final round and `UseHint` match line for line. Behaviour differs only in that Rust returns
  `Err(Memory)` where C returns 0 on arena failure; that is documented.

## Not covered

- I did not compute `sizeof (_spolymat_t)` for F2.
- No PoC for F1, because building and running were not allowed.
- No full re-derivation of `dcompress_use_ghint` against LaZer's `dcompress_decompose` at the q − 1 edge. I relied on
  the existing SV / generic diff harness.
- No line-by-line review of `pqz_rel.c`'s `build_debit` / `debit_witness` / `set_upsilon` (prover-side witness
  construction).
- No line-by-line review of the Rust `rel.rs` / `proof/tbox.rs` beyond the transcript points.
- Not covered: `freestanding/` headers, `params/*.sage` (the parameter / knowledge-error derivations), the KAT
  files.
