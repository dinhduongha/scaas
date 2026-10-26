# Security Review Report: Unit R2 — Parameters per Set (Code)

**Target Repository:** SCaaS core (`pqz-core/` at commit `008e196c`)  
**Review Unit:** R2 — parameters per set (code)  
**Scope:** 
- [`params/sets/gen_set.py`](pqz-core/params/sets/gen_set.py)
- [`params/sets/<set>/`](pqz-core/params/sets/) across all four parameter sets:
  - `n2048-kmax1024`
  - `n2304-kmax4096`
  - `n2560-kmax16384`
  - `n2816-kmax65536`
- [`pqzl/src/pqz_ntt.c`](pqz-core/pqzl/src/pqz_ntt.c) and [`pqzl/src/pqz_ntt.h`](pqz-core/pqzl/src/pqz_ntt.h)
- [`pqzl/rust/src/arith/`](pqz-core/pqzl/rust/src/arith/) ([`int.rs`](pqz-core/pqzl/rust/src/arith/int.rs), [`mpn.rs`](pqz-core/pqzl/rust/src/arith/mpn.rs), [`ntt.rs`](pqz-core/pqzl/rust/src/arith/ntt.rs), [`poly.rs`](pqz-core/pqzl/rust/src/arith/poly.rs), [`polymat.rs`](pqz-core/pqzl/rust/src/arith/polymat.rs), [`polyvec.rs`](pqz-core/pqzl/rust/src/arith/polyvec.rs), [`spoly.rs`](pqz-core/pqzl/rust/src/arith/spoly.rs))
- [`pqzl/rust/src/params/mod.rs`](pqz-core/pqzl/rust/src/params/mod.rs)
- [`pqzl/src/pqz_keys.c`](pqz-core/pqzl/src/pqz_keys.c)
- [`pqzl/rust/src/keys.rs`](pqz-core/pqzl/rust/src/keys.rs)

---

## Findings

No P0, P1, or P2 vulnerabilities were identified in the audited unit. The mathematical parameters, Barrett reduction constants, NTT root invariants, bit decompositions, and cryptographic key generation / encryption / decryption routines are sound. Two minor informational observations (P3) are documented below.

### [R2-1] P3: Stale Set-Specific Constant in Relation Reconstruction Inline Comments
- **File & Lines:** [`pqzl/src/pqz_rel.c:786`](pqz-core/pqzl/src/pqz_rel.c#L786) and [`pqzl/rust/src/rel.rs:546`](pqz-core/pqzl/rust/src/rel.rs#L546)
- **Claim:** Inline documentation in both C and Rust for recovering signed noise $e_{T,i}$ specifies hardcoded numeric power-of-two constants from older or specific sets rather than the generic parameter definition.
- **Evidence:**
  In [`pqz_rel.c:786`](pqz-core/pqzl/src/pqz_rel.c#L786):
  ```c
  /* recover signed e_T,i from (e_T,i + 2^26) - 2^26 */
  int64_t se = (int64_t)e_Ti - PQZ_EOFF;
  ```
  In [`rel.rs:546`](pqz-core/pqzl/rust/src/rel.rs#L546):
  ```rust
  // recover signed e_T,i from (e_T,i + 2^24) - 2^24
  let se = e_ti as i64 - EOFF as i64;
  ```
  The C comment references $2^{26}$ (matching `n2304-kmax4096`), and the Rust comment references $2^{24}$ (matching `n2048-kmax1024`). In the newer sets, $e_T = 29 \implies \text{EOFF} = 2^{28}$ (`n2560-kmax16384`) and $e_T = 31 \implies \text{EOFF} = 2^{30}$ (`n2816-kmax65536`). While the code implementation is correct and uses the parameterized `PQZ_EOFF` / `EOFF`, the stale comments can confuse auditors and maintainers.
- **Suggested Fix:** Update the comments to refer generically to `(e_T,i + 2^(EBITS-1)) - 2^(EBITS-1)` / `EOFF`.

---

### [R2-2] P3: Uninitialized Index 0 in Stack Array `bb` in `basemul16`
- **File & Lines:** [`pqzl/src/pqz_ntt.c:116-126`](pqz-core/pqzl/src/pqz_ntt.c#L116-L126)
- **Claim:** In [`basemul16`](pqz-core/pqzl/src/pqz_ntt.c#L112), array `bb[32]` (and `b0[32]`, `b1[32]`, `bs[32]` when `PQZ_MUL128=0`) is initialized for indices `1..31`, leaving index `0` uninitialized on the stack.
- **Evidence:**
  In [`pqz_ntt.c:116-123`](pqz-core/pqzl/src/pqz_ntt.c#L116-L123):
  ```c
  uint64_t bb[32];
  for (int i = 0; i < 16; ++i) {
      bb[i + 16] = b[i];
      if (i > 0) {
          bb[i] = pqz_redx((pqz_u128)b[i] * z);
      }
  }
  ```
  The negative convolution access pattern reads `bb[16 + k - i]`. For $k, i \in [0, 15]$, the index is in $[1, 31]$; index `0` is never read. However, static analyzers and memory sanitizers (MSan) may flag partially uninitialized stack arrays, and future modifications to loop bounds could introduce undefined behavior.
- **Suggested Fix:** Zero-initialize the array declaration (`uint64_t bb[32] = {0};` or `bb[0] = 0;`).

---

## Checked and Sound

1. **Parameter & Header Identity Across All Sets:**  
   `python3 -I pqz-core/params/sets/gen_set.py --all --check` (83 files) and `python3 -I pqz-core/pqzl/params/to_rust.py --check` (61 files) confirmed that all committed C and Rust headers are identical to the generator output, matching all reviewed parameters:
   - `n2048-kmax1024`: $n=2048, k=32, q=4,398,046,510,889, \Delta=67,108,863, \zeta=3,367,489,746,414, M=14, \text{carries}=11, e_T=25, \beta_s=36, \beta_e=164, \beta_2=64, K_{\text{MAX}}=1,024$.
   - `n2304-kmax4096`: $n=2304, k=36, q=61,275,424,977,257, \Delta=233,747,196, \zeta=21,683,259,334,335, M=16, \text{carries}=13, e_T=27, \beta_s=38, \beta_e=173, \beta_2=64, K_{\text{MAX}}=4,096$.
   - `n2560-kmax16384`: $n=2560, k=40, q=1,125,899,864,532,089, \Delta=1,073,741,783, \zeta=678,622,666,313,846, M=18, \text{carries}=15, e_T=29, \beta_s=40, \beta_e=182, \beta_2=64, K_{\text{MAX}}=16,384$.
   - `n2816-kmax65536`: $n=2816, k=44, q=18,014,398,509,481,657, \Delta=4,294,967,295, \zeta=7,116,548,313,613,552, M=20, \text{carries}=17, e_T=31, \beta_s=42, \beta_e=189, \beta_2=64, K_{\text{MAX}}=65,536$.

2. **NTT Roots & Inverses:**  
   Verified via exact arithmetic that for all four sets, $\zeta^8 \equiv 1 \pmod q$, $\zeta^4 \equiv -1 \pmod q$, the NTT forward and inverse twiddle factors satisfy $w \cdot w^{-1} \equiv 1 \pmod q$, and $R_{64} \equiv 2^{64} \pmod q$.

3. **No Integer Overflow in Barrett Reduction [`pqz_redx`](pqz-core/pqzl/src/pqz_ntt.c#L44-L64):**  
   For any $\text{LOG2Q} = L \le 56$, $\text{BARX} = 2L + 4 \le 116$. The product $(x \gg (L-1)) \times \text{MUX} < 2^{L+5} \times 2^{L+5} \le 2^{122} < 2^{128}$ fits in `pqz_u128` without overflow, and the sign bit shift `(int64_t)t >> 63` is exact because $2q < 2^{57} < 2^{63}$.

4. **No Integer Overflow in [`pqz_red128`](pqz-core/pqzl/src/pqz_ntt.c#L67-L77):**  
   The high limb $x \gg 64 < 2^{64} < 2^{\text{BARX}}$ (since $\text{BARX} \ge 88$), and intermediate $hi \cdot R_{64} + lo < 2^{2L} + 2^{64} < 2^{2L+4} = 2^{\text{BARX}}$ strictly satisfies the [`pqz_redx`](pqz-core/pqzl/src/pqz_ntt.c#L44) domain precondition.

5. **No Integer Overflow in [`basemul16`](pqz-core/pqzl/src/pqz_ntt.c#L112-L210) (Both 128-bit and 64-bit Limb Paths):**  
   In `PQZ_MUL128=1`, the accumulator $\sum_{i=0}^{15} a_i b'_i \le 16(q-1)^2 < 2^{2L+4} \le 2^{116} < 2^{128}$; in `PQZ_MUL128=0` (WASM32), Karatsuba limb bounds $as[i], bs[j] < 2^{29}$ yield middle product sum $sm \le 16 \times 2^{58} = 2^{62} < 2^{64}$, and $sm \ge l + h$ guarantees non-negative unsigned subtraction.

6. **Signed Input Lifting in [`pqz_modq_i64`](pqz-core/pqzl/src/pqz_ntt.c#L80-L87):**  
   The constant offset $q \cdot 2^{63-L} \ge 2^{62}$ strictly guarantees non-negative lifting for all callers in statement verification and relation accumulators, whose magnitudes are bounded by $|x| \le 256 q < 2^{62}$.

7. **Decryption Numerator Bound:**  
   In [`pqz_dec`](pqz-core/pqzl/src/pqz_keys.c#L249) and [`decrypt_raw`](pqz-core/pqzl/rust/src/keys.rs#L225), numerator $t = 2w_i + \Delta + 2\Delta \cdot 2^{M+3}$ reaches at most $\approx 7.2 \times 10^{16}$ at `n2816-kmax65536` ($\approx 2.88 \times 10^{17}$ at $L=56$), which is orders of magnitude below `INT64_MAX` ($9.22 \times 10^{18}$), preventing signed overflow.

8. **Relation Carries Accumulator Bound:**  
   The largest bit shift $\Delta \ll b$ at `n2816-kmax65536` is $\Delta \ll 19 \approx 2^{51} \ll 2^{63}-1$, well within standard 64-bit signed integers.

9. **KeyGen Agreement with Spec §4.2:**  
   Deterministic SHAKE256 PRF with domain separator `"SCAAS-PQZ-KEYGEN-V1"`, CBD samplers $\text{CBD}_1^N(s)$ and $\text{CBD}_{20}^N(e)$ matching $\eta_1=1, \eta_2=20$, strict centered Euclidean norm checks $\|s\| \le \beta_s$ and $\|e\| \le \beta_e$, and public key computation $pk = A s + e \in R_q^k$ strictly match the specification.

10. **Encryption Agreement with Spec §4.2:**  
    Deterministic SHAKE256 PRF with domain separator `"SCAAS-PQZ-ENC-V1"`, CBD samplers $r \leftarrow \text{CBD}_1^N$, $e_1 \leftarrow \text{CBD}_{20}^N$, $e_2 \leftarrow \text{CBD}_{20}^{16}$, strict norm checks $\|r\| \le \beta_s, \|e_1\| \le \beta_e, \|e_2\| \le \beta_2=64$, and ciphertext formation $u = A^T r + e_1 \bmod q$ and $v_j[i] = (pk_j^T r)[i] + e_{2,j,i} + \Delta m_{j,i} \bmod q$ agree with the specification.

11. **Group Seed Encryption Agreement with Spec §7.7 / CTR-PQZ-19:**  
    [`pqz_enc_group_seed`](pqz-core/pqzl/src/pqz_keys.c#L136) and [`enc_group_seed`](pqz-core/pqzl/rust/src/keys.rs#L85) directly return the raw seed for group index $g=0$ and compute $\text{SHAKE256}(\text{"SCAAS-PQZ-ENC-GROUP-V1"} \parallel seed \parallel be4(g))$ for $g > 0$.

12. **Decryption Agreement with Spec §4.3:**  
    Centering $w_i = \text{centre}(v_i - (u^T s)_i \bmod q) \in (-q/2, q/2]$ and message recovery $M_i = \lfloor (2w_i + \Delta) / (2\Delta) \rfloor$ correctly rounds ties up; honest noise satisfies $|e_{dec}| \le E < \Delta/2$, ensuring perfect correctness.

13. **Secret Zeroization on Exit:**  
    All secret polynomials and intermediate state in [`pqz_keygen`](pqz-core/pqzl/src/pqz_keys.c#L50), [`pqz_enc_seed`](pqz-core/pqzl/src/pqz_keys.c#L170), [`pqz_dec`](pqz-core/pqzl/src/pqz_keys.c#L249), and their Rust counterparts in [`keys.rs`](pqz-core/pqzl/rust/src/keys.rs) are scrubbed using `explicit_bzero` / `zeroize` on both success and error paths.

14. **Mutual Exclusion in Rust Parameter Sets:**  
    [`pqzl/rust/src/params/mod.rs:25-38`](pqz-core/pqzl/rust/src/params/mod.rs#L25-L38) enforces at compile time via `compile_error!` that exactly one parameter set feature must be activated.

---

## Not Covered

The following components were intentionally outside the assigned R2 scope:
- The Nethermind C# EVM precompile plugin (`pqz-plugin/`).
- Solidity contracts under `contracts/` and EVM dispatcher glue (`pqz-ffi/`), except for cross-checking against the normative specification in `docs/contracts/pq-zero-knowledge.md`.
- JavaScript and WebAssembly wrappers / test harnesses (`pqz-wasm/`).
- Higher-level interactive statement verification algorithms in `pqz_sv.c` and `sv.rs` beyond their arithmetic limb bounds and modular lifting requirements.
- Independent re-execution of lattice security estimator scripts (LWE / SIS BKZ core-SVP estimation), which were reviewed from committed parameter generation scripts and research documentation.
