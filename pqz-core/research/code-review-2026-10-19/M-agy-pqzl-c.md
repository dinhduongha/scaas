# M — agy review of the PQZL C core (round 2) and triage of L + M + N

**Date:** 2026-10-19. **Reviewer:** agy 1.4.2 (`--mode plan`, no `--dangerously-skip-permissions`; conversation
`07e23981-8186-433f-bd19-1285fea31a0b`; one pass; worktree unmodified). Same brief and target as
[L](L-codex-pqzl-c.md) (Codex) and [N](N-claude-pqzl-c.md) (Claude sub-agent). agy's report follows verbatim, then the
controller's triage.

---

# Security Review Report: PQZL C Core (Round 2, 2026-10-19)

**Target Codebase:** Detached frozen worktree at commit `e9cabd1` (`rev2`, branch `pqzl-fs3` merged).  
**Scope:** `pqz-core/pqzl/src/`, `pqz-core/pqzl/lazer/`, `pqz-core/ffi/src/pqzl/c.rs`, `pqz-core/pqzl/build.sh`.  
**Review Mode:** Read-only static analysis. Nothing was edited, built, executed, or timed.  
**Severity Scale:**
- **P0:** Forgery, accepts a false statement, or consensus split between `pqzl-c` and `pqzl-rust`.
- **P1:** ZK / secret leak with a practical path, or an input-reachable crash / memory corruption in the verifier.
- **P2:** Confirmed weakness with limited reach.
- **P3:** Latent defect / hygiene issue.

---

## Findings

### C2-1 — P1 — Secret material not zeroed across early returns and exits (STATUS.md Open item 8 / Triage B)

- **Locations:**
  - [pqz-core/pqzl/src/pqz_rel.c:1027-1036](../../../pqz-core/pqzl/src/pqz_rel.c#L1027-L1036) (`do_prove`: `F->s1`, `F->s2`, `F->m`, `F->tA2` in arena)
  - [pqz-core/pqzl/src/pqz_rel.c:1388-1393](../../../pqz-core/pqzl/src/pqz_rel.c#L1388-L1393) (`pqz_prove`: arena release without wipe)
  - [pqz-core/pqzl/lazer/lnp-tbox.c:256,345](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L256-L345) (`lnp_tbox_prove`: stack `expseed[96]` never wiped)
  - [pqz-core/pqzl/lazer/lnp-quad.c:46,149,322-344](../../../pqz-core/pqzl/lazer/lnp-quad.c#L46-L344) (`lnp_quad_prove`: stack `yseed[32]` and arena-freed `s`, `w`, `cs1`, `cs2` never wiped)
  - [pqz-core/pqzl/src/pqz_rel.c:1477-1481,1497-1505,1541-1551](../../../pqz-core/pqzl/src/pqz_rel.c#L1477-L1551) (`pqz_keypair_from_secret`, `pqz_encrypt`, `pqz_decrypt_raw`: `sv`, `rv` arena buffers never wiped)
  - [pqz-core/pqzl/src/pqz_keys.c:193-206](../../../pqz-core/pqzl/src/pqz_keys.c#L193-L206) (`pqz_dec`: `w` not wiped on `rc != 0` early return)
- **Trigger:** Normal prover operations (`pqz_prove`), key derivation (`pqz_keypair_from_secret`), encryption (`pqz_encrypt`), or decryption (`pqz_dec` / `pqz_decrypt_raw`).
- **Impact:** Secret witness vectors (`s1`), commitment randomness (`s2`), masking polynomials (`m`), unmasked commitment chunks (`tA2`), stack PRG seeds (`expseed[96]`, `yseed[32]`), and plaintext decryptions (`w`) persist in memory (both in `.bss` arena memory and on the worker stack) across subsequent executions in the process. If a node or process handles proving/decryption and subsequently serves other requests or encounters inspection/debugging, private credentials and witness amounts can be harvested from memory. While the Rust core fixed this with drop guards (`Wiped`, review G/H fix B), the C core retains this gap project-wide.
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:**
  1. Add `explicit_bzero` / `pqz_zeroize` for `expseed` on exit from [lnp-tbox.c:885](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L885) and `yseed` on exit from [lnp-quad.c:343](../../../pqz-core/pqzl/lazer/lnp-quad.c#L343).
  2. In `pqz_dec` ([pqz_keys.c:195](../../../pqz-core/pqzl/src/pqz_keys.c#L195)), ensure `explicit_bzero(w, sizeof w)` executes before any early return.
  3. In `pqz_arena_release` ([pqz_arena.c:190](../../../pqz-core/pqzl/src/pqz_arena.c#L190)), wipe the memory slice between the released `top` and the old `top` via `pqz_zeroize(base + top, old_top - top)`.  
  *Proof bytes and honest verdicts are unchanged.*

---

### C2-2 — P2 — Sign-less bimodal rejection sampling on z2 with incorrect variance (`stdev1sqr`) leaks `s2` (Finding D-2)

- **Locations:**
  - [pqz-core/pqzl/lazer/lnp-quad.c:274-275](../../../pqz-core/pqzl/lazer/lnp-quad.c#L274-L275)
- **Trigger:** Prover generating proofs for any relation.
- **Impact:** `lnp_quad.c` calls `rej_bimodal(rstate_rej, z2coeffs, cs2coeffs, params->scM2, params->stdev1sqr)`. Across all 14 parameter sets, `log2stdev1` is 18 or 19 while `log2stdev2` is 12, creating a variance mismatch ratio of $\sigma_1^2 / \sigma_2^2 = 2^{12}\text{ to }2^{14}$. Because $\sigma_1^2$ is passed instead of $\sigma_2^2$, the inner products $a = \|v\|^2 / (2\sigma_1^2)$ and $y = |\langle z, v \rangle| / \sigma_1^2$ are suppressed to $\approx 10^{-4}$, making acceptance probability essentially independent of $z_2$ (acceptance rate $\approx 1/M_2 \pm 0.1\%$). The $z_2$ rejection test is effectively a no-op. Furthermore, the test is applied without a random sign (unlike $z_3/z_4$ in `lnp-tbox.c:1688,1710`). The published $z_{21}$ retains statistical dependence on $s_2$ ($KL(\text{real} \parallel \text{simulated}) \approx 0.04\text{--}0.06\text{ nats}$ per proof), breaking the strict zero-knowledge simulation reduction for $s_2$.
- **Confirmed or hypothesis:** Confirmed in source code (inherited from upstream LaZer).
- **Suggested fix:** Change rejection to standard rejection (`rej_standard` with `stdev2sqr` and re-derived $M_2$) or implement random sign sampling as in `lnp-tbox.c`.  
  *Changes honest proof bytes and parameters; must be coordinated with future protocol bumps.*

---

### C2-3 — P3 — Arena sink buffer smaller than single allocations causes out-of-bounds BSS write on exhaustion (C-F2 / Open item 2)

- **Locations:**
  - [pqz-core/pqzl/src/pqz_arena.c:20,33,144-147](../../../pqz-core/pqzl/src/pqz_arena.c#L20-L147) (`PQZ_SINK` = 1 MiB)
  - [pqz-core/pqzl/lazer/spolymat.c:61-62](../../../pqz-core/pqzl/lazer/spolymat.c#L61-L62) (`spolymat_alloc`: `_alloc` then `memset`)
  - [pqz-core/pqzl/lazer/lnp-quad-many.c:26-29,137-138](../../../pqz-core/pqzl/lazer/lnp-quad-many.c#L26-L138)
  - [pqz-core/pqzl/lazer/lnp-tbox.c:922,1336](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L922-L1336)
- **Trigger:** Arena exhaustion (`sz > cap - top`) occurring during allocations whose single block size exceeds `PQZ_SINK` (1 MiB). Specifically:
  - In `R_TXM8`, Schwartz-Zippel matrix allocation requests `nelems_max ≈ 125,000` entries $\times 16\text{ bytes} \approx 2.0\text{ MB}$.
  - In `R_TXM16`, allocation requests `nelems_max ≈ 363,000` entries $\times 16\text{ bytes} \approx 5.8\text{ MB}$.
- **Impact:** When exhausted, `pqz_arena_alloc` sets `pqz_err = PQZ_ERR_ARENA` and returns the static `sink` pointer (1 MiB). `spolymat_alloc` immediately executes `memset(r->elems, 0, nelems_max * sizeof(_spolymat_t))` without checking `pqz_err`. This writes 1.0 MB to 4.8 MB of zeroes past `sink` into adjacent `.bss` memory (or linear memory in wasm32). In a long-running process, this corrupts static tables or metadata, turning an exhaustion fault into undefined behaviour or crash before `with_core` recovers the error.
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** Return `NULL` on exhaustion in `pqz_arena_alloc` and make `_alloc` callers check for `NULL`, or size `PQZ_SINK` to at least 8 MiB and clamp write operations. Smallest correct fix: check `pqz_err` in `spolymat_alloc` before `memset` and return immediately if set.  
  *Honest proofs and verdicts with adequate arena are unchanged.*

---

### C2-4 — P3 — Zero-length Variable Length Arrays in `lnp-tbox.c` on relations with M = 0 or nbin = 0

- **Locations:**
  - [pqz-core/pqzl/lazer/lnp-tbox.c:273](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L273) (`INTVEC_T (V, M, Rq->q->nlimbs)` in `lnp_tbox_prove`, $M=0$ in `R_REG`)
  - [pqz-core/pqzl/lazer/lnp-tbox.c:934](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L934) (`INTVEC_T (V, M, Rq->q->nlimbs)` in `lnp_tbox_verify`, $M=0$ in `R_REG`)
  - [pqz-core/pqzl/lazer/lnp-tbox.c:3644](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L3644) (`INTVEC_T (f_, nbin * d, Rq->q->nlimbs)` in `_expand_R`, $\text{nbin}=0$ in `R_REG`)
- **Trigger:** Proving or verifying relations where $M = 0$ or $\text{nbin} = 0$ (e.g. `R_REG`).
- **Impact:** `_sizeof_intvec_data` evaluates to 0, expanding `INTVEC_T` into a 0-length stack array `uint8_t Vbytes__[0]`. In C99/C11 §6.7.6.2p5, a VLA whose size expression evaluates to $\le 0$ is undefined behaviour. This is the exact root cause requiring `-fno-sanitize=vla-bound` in [pqz-core/ffi/build.rs:79](../../../pqz-core/ffi/build.rs#L79).
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** In `INTVEC_T` macro ([pqz-core/pqzl/lazer/lazer-in2.h:845](../../../pqz-core/pqzl/lazer/lazer-in2.h#L845)), allocate `MAX(_sizeof_intvec_data(...), 1)`.  
  *Does not change proof bytes or verdicts.*

---

### C2-5 — P3 — Undefined null pointer arithmetic (`NULL + 0`) in `aes256ctr.c:339`

- **Locations:**
  - [pqz-core/pqzl/lazer/aes256ctr.c:339](../../../pqz-core/pqzl/lazer/aes256ctr.c#L339)
- **Trigger:** The first call to `_aes256ctr_stream` when `state->cache_ptr == NULL` and `state->nbytes == 0`.
- **Impact:** `len = MIN(outlen, state->nbytes)` evaluates to 0. The statement `state->cache_ptr += len` performs pointer arithmetic on a null pointer (`NULL + 0`), which is undefined behaviour under C99/C11 §6.5.6p8. This requires `-fno-sanitize=pointer-overflow` in [pqz-core/ffi/build.rs:79](../../../pqz-core/ffi/build.rs#L79) during sanitizer runs.
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** Wrap `state->cache_ptr += len; state->nbytes -= len;` inside `if (len > 0)`.  
  *Does not change PRG output.*

---

### C2-6 — P3 — Latent out-of-bounds read in `canonical()` in `pqz_keys.c` on unaligned lengths

- **Locations:**
  - [pqz-core/pqzl/src/pqz_keys.c:103-108](../../../pqz-core/pqzl/src/pqz_keys.c#L103-L108)
- **Trigger:** Calling `canonical(p, n)` where `n % 8 != 0`.
- **Impact:** The loop strides by 8 (`k += 8`) and unconditionally reads `p[k + i]` for $i \in [0, 8)$. When $n$ is not a multiple of 8, the final iteration reads past the buffer bound. Currently latent because all callers pass sizes that are exact multiples of 8 (`PQZ_POLYVEC_BYTES` = 16,384, `CT_BYTES` = 16,512).
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** Add `if (n % 8 != 0) return 0;` at the beginning of `canonical`. Matches Rust fix C (`chunks_exact(8)`).  
  *Does not change honest execution.*

---

### C2-7 — P3 — Latent out-of-bounds stack write and underflow in `pqz__div` if `nn < dn`

- **Locations:**
  - [pqz-core/pqzl/src/pqz_mpn.h:175-177](../../../pqz-core/pqzl/src/pqz_mpn.h#L175-L177)
- **Trigger:** Calling `pqz__div` with numerator limbs `nn` strictly smaller than denominator limbs `dn`.
- **Impact:** `rem[0..dn)` is written into `np[0..dn)`. If `np` was allocated with capacity `nn < dn`, this writes out of bounds on the stack. Furthermore, `qtop = q[nn - dn]` indexes with a negative offset. Currently latent because all call sites in `int.c` and glue enforce $nn \ge dn$.
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** Assert `ASSERT_ERR(nn >= dn);` or early-return quotient 0 and remainder `np` if `nn < dn`.  
  *Does not change valid runs.*

---

### C2-8 — P3 — Global mutable state in C core without thread safety (STATUS.md Open item 6)

- **Locations:**
  - [pqz-core/pqzl/src/pqz_arena.c:29-38](../../../pqz-core/pqzl/src/pqz_arena.c#L29-L38) (`base`, `top`, `peak`, `last`, `pqz_err`)
  - [pqz-core/pqzl/src/pqz_rel.c:90-92](../../../pqz-core/pqzl/src/pqz_rel.c#L90-L92) (`A`, `ready`, `base`)
  - [pqz-core/pqzl/src/pqz_sv.c:861-877](../../../pqz-core/pqzl/src/pqz_sv.c#L861-L877) (`SR`, `SA`, `svb`, `nsvb`, `sv_ready`)
- **Trigger:** Concurrent multi-threaded entry into `libpqz` functions without serialization.
- **Impact:** Data race corrupting arena marks, sticky errors, and precomputed tables. Mitigated at the `pqz-ffi` layer by wrapping calls in a process-wide `Mutex` and dispatching to a dedicated worker thread ([ffi/src/pqzl/c.rs:103-146](../../../pqz-core/ffi/src/pqzl/c.rs#L103-L146)). Remains an architectural constraint of the C library.
- **Confirmed or hypothesis:** Confirmed in source code.
- **Suggested fix:** Encapsulate global state into an explicit context struct `pqz_ctx_t` passed into public APIs (mirroring `pqzl::Ctx` in Rust).

---

## Round-1 Findings: Status in this Tree

| Prior Finding | Severity | Description | Status in this Tree | Verification Evidence |
|---|---|---|---|---|
| **F1 / D-1 / lazer#28** | P0 | Fiat–Shamir transcript omissions: $z_3, z_4$ absorbed after $V_3, V_4$; $h$ absorbed after $\mu$ and $c$. | **CLOSED (FIXED)** | Verified in C generic verifier ([lnp-tbox.c:1184,1344](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L1184-L1344)), C SV ([pqz_sv.c:1516-1546,1947](../../../pqz-core/pqzl/src/pqz_sv.c#L1516-L1947)), C prover ([lnp-tbox.c:417,803](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L417-L803)). `proofSystemId` is v3. |
| **D-2** | P2 | $z_2$ rejection uses $\sigma_1^2$ and lacks random sign in `lnp-quad.c`. | **OPEN** | Still present in [lnp-quad.c:274-275](../../../pqz-core/pqzl/lazer/lnp-quad.c#L274-L275). Retained as finding **C2-2**. |
| **D-3** | P3 | Sign sampler reads bit 8 of `uint8_t`, forcing $\beta_4 = +1$ on every 4th attempt. | **CLOSED (FIXED)** | Refill condition `if (nrbits < 2)` and sequential bit consumption verified in [lnp-tbox.c:1669-1714](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L1669-L1714). |
| **C-F2 / Open 2** | P3 | Arena sink smaller than single allocations, causing out-of-bounds write on exhaustion. | **OPEN** | Still present in [pqz_arena.c:20,146](../../../pqz-core/pqzl/src/pqz_arena.c#L20-L146) and [spolymat.c:61-62](../../../pqz-core/pqzl/lazer/spolymat.c#L61-L62). Retained as finding **C2-3**. |
| **Triage A** | P3 | Statement hashed and cold caches built before exact length check. | **CLOSED (FIXED)** | Strict check `stmt_len == stmt_bytes(R)` in `rel_of` ([pqz_rel.c:1315](../../../pqz-core/pqzl/src/pqz_rel.c#L1315)) runs before `pqz_stmt_hash` in `pqz_verify` ([line 1407](../../../pqz-core/pqzl/src/pqz_rel.c#L1407)) and `pqz_verify_fast` ([line 1440](../../../pqz-core/pqzl/src/pqz_rel.c#L1440)). |
| **Triage B / Open 8** | P1/P2 | Secret material in arena and stack not zeroed. | **OPEN** | Retained as finding **C2-1**. |
| **Triage C** | P3 | Latent panic on short last chunk in `canonical()`. | **CLOSED (Rust) / OPEN (C)** | Rust fixed with `chunks_exact(8)`. C retained as finding **C2-6**. |
| **Triage D** | P3 | Signed overflow on `-INT64_MIN` in SV $z_4$ check. | **CLOSED (FIXED)** | `uabs64` cast implemented in [pqz_sv.c:1339-1342](../../../pqz-core/pqzl/src/pqz_sv.c#L1339-L1342) and verified at all call sites. |
| **Triage E / Fix E** | P3 | Prover secret-dependent branches and variable-latency divisions. | **CLOSED (FIXED)** | Constant-time arithmetic and `ct_sdiv` verified in `pqz_mpn.h`, `dcompress.c`, and `pqz_rel.c`. |

---

## Checked and Clean

### 1. Verification Soundness
- **v3 Transcript Order:**
  - In `lazer/lnp-tbox.c`: `_lnp_tbox_hash_z34` absorbs centred $z_3, z_4$ into `hash0` ([lines 1183-1185](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L1183-L1185)) before $V_3, V_4$ are derived ([lines 700, 711](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L700-L711)), while $R, R'$ are derived strictly from `cseed` (`hashr`). Prover message $h$ is absorbed via `_lnp_tbox_hash_h` ([line 1344](../../../pqz-core/pqzl/lazer/lnp-tbox.c#L1344)) into `hash2` before $\mu$ is sampled in `_schwartz_zippel_poly` ([lnp-quad-many.c:34](../../../pqz-core/pqzl/lazer/lnp-quad-many.c#L34)) and before final challenge $c$ in `lnp_quad_verify` ([lnp-quad.c:489-493](../../../pqz-core/pqzl/lazer/lnp-quad.c#L489-L493)).
  - In `src/pqz_sv.c`: Identical transcript order: `cseed` $\to$ `hash0` (absorbing $z_3, z_4$, [lines 1516-1530](../../../pqz-core/pqzl/src/pqz_sv.c#L1516-L1530)) $\to$ `hash1` ($t_g$, [line 1540](../../../pqz-core/pqzl/src/pqz_sv.c#L1540)) $\to$ `hash2` ($h$, [line 1545](../../../pqz-core/pqzl/src/pqz_sv.c#L1545)). $\mu$ is derived from `g2` (seeded with `hash2`, [line 1596](../../../pqz-core/pqzl/src/pqz_sv.c#L1596)), and $c$ absorbs `hash2` ([line 1947](../../../pqz-core/pqzl/src/pqz_sv.c#L1947)).
- **Norm Checks:**
  - $z_1$ norm checked in `lnp-quad.c:512` and `pqz_sv.c:1550`.
  - Whole $z_2 = (z_{21}, w - \gamma w_1)$ norm (P6-Z21 / lazer#26) checked in `lnp-quad.c:527-528` and `pqz_sv.c:1959-1960`.
  - $z_3$ norm checked in `lnp-tbox.c:1983` and `pqz_sv.c:1493`.
  - $z_4$ norm checked in `lnp-tbox.c:1990` and `pqz_sv.c:1496`.
  - Hint $h$ norm checked in `lnp-quad.c:536` and `pqz_sv.c:1554`.
  - Challenge $c \in [-8, 8]^{64}$ checked in `pqz_sv.c:1560`.
  - Toolbox $h$ polynomials: coefficients $0$ and $d/2$ checked to be zero in `lnp-tbox.c:1194-1198` and `pqz_sv.c:1534`.
  - Exact $\ell_2$ domains: each block $i < Z$ receives distinct domain $M + 2(d-1) + 2 + i$ in `lnp-tbox.c:3280` and `pqz_sv.c:1765` (P6-L2 / lazer#25).
- **SV Arithmetic Headroom:**
  - CRT product $P = \prod_{i=0}^3 p_i > 2^{119}$ comfortably exceeds maximum coefficient accumulations ($< 2^{106}$).
  - Accumulator headroom: sum of intermediate products $< 2^{40} < p \cdot 2^{32}$.
  - `l2_sum` bounds check ([pqz_sv.c:1351](../../../pqz-core/pqzl/src/pqz_sv.c#L1351)) prevents 64-bit overflow by early-returning when single element $\ge 2^{31}$.
- **Statement & `proofSystemId` Binding:**
  - `pqz_stmt_hash` ([pqz_rel.c:290-295](../../../pqz-core/pqzl/src/pqz_rel.c#L290-L295)) absorbs `op`, `be32(len)`, and the full statement slice (including `proofSystemId` at bytes 32..63). Any alteration scrambles transcript seed `hash0`.

### 2. Decoding & Canonicality
- **Fixed-width Decoding:** `_udecode` ([coder.c:554](../../../pqz-core/pqzl/lazer/coder.c#L554)) rejects values $\ge m$. Fixed-width bit lengths are checked ahead of reading ([coder.c:393-397](../../../pqz-core/pqzl/lazer/coder.c#L393-L397)).
- **Unary Decoding Termination:** `coder_dec_grandom` and `coder_dec_ghint` ([coder.c:172,319](../../../pqz-core/pqzl/lazer/coder.c#L172-L319)) terminate immediately upon reaching EOF via `RDB` error signaling.
- **Bijective Encoding:** Distinct values produce distinct bitstrings; no aliasing within `PQZ_MAX_PROOF` (98,304 bytes).
- **Trailing Bytes:** `pqz_decproof` ([pqz_rel.c:408-410](../../../pqz-core/pqzl/src/pqz_rel.c#L408-L410)) requires `coder_dec_end` pad bit validation and enforces exact byte consumption `(coder_get_offset >> 3) == len`.

### 3. wasm32 vs. Native Parity
- Freestanding runtime ([pqz_wasm_rt.c:61-93](../../../pqz-core/pqzl/src/pqz_wasm_rt.c#L61-L93)) provides constant-time branch-free `__multi3`, `__ashlti3`, `__lshrti3`.
- In `pqz_ntt.c`, `PQZ_MUL128` cleanly selects the 21-bit limb path on wasm32 ([lines 51-71](../../../pqz-core/pqzl/src/pqz_ntt.c#L51-L71)), yielding residues identical to native `pqz_red128`.
- No signed 64-bit integer divisions remain on the wasm32 secret execution paths (`ct_sdiv` and `pqz__div` replace compiler division helpers).

### 4. Build & Symbol Isolation
- Test hooks (`PQZ_SZ_TRACE`, `PQZ_CTGRIND`, `pqz_test_mutate`, `PQZ_TEST_HOOKS`) are cleanly compiled out of production library builds ([build.sh:11,44](../../../pqz-core/pqzl/build.sh#L11-L44)).
- `check_symbols.sh` ([lines 11-24](../../../pqz-core/pqzl/check_symbols.sh#L11-L24)) runs automatically during `build.sh` and cargo build, asserting that only `memcpy`, `memset`, `__stack_chk_fail`, and `__stack_pointer` are imported.

### 5. C = Rust Parity
- Statement validation, header parsing, relation shape resolution (`rel_of`), proof field extraction, Montgomery arithmetic, NTT reduction, and verifier verdicts match between `pqz_sv.c` and `rust/src/sv.rs` without divergence.
- Both backends map out-of-memory/arena exhaustion to `NodeFault` (status 4) in `pqz-ffi`, preventing consensus splits from resource exhaustion.

---

## Not Checked

1. Mathematical tightness and concrete bit-security margins derived by parameter generation scripts (`pqz-core/pqzl/params/*.sage`).
2. Upstream golden test KAT values (`pqz-core/pqzl/kat/lazer-3330e48.json`).
3. Hardware-level physical side-channel emission (power analysis, electromagnetic radiation) outside software timing and cache side-channels.
4. Non-standard C compilers (codebase assumes clang/gcc semantics for arithmetic right shift of negative signed integers, asserted in [pqz_rt.h:36](../../../pqz-core/pqzl/src/pqz_rt.h#L36)).

---

## Triage (controller, L = Codex, M = agy, N = Claude)

Verified by the controller against `e9cabd1` (`pqz_fixexp.h:98–108`, `rust/src/rand/fixexp.rs:58–66`,
`lnp-quad.c:274–281`, `aes256ctr.c:335–341`, `pqz_keys.c:100–108`, `pqz_mpn.h:149–199`). **No P0 / P1 from any
reviewer on the verifier path; no C = Rust verdict divergence found** (N compared `pqz_verify_fast` with `verify_sv`
step by step). The pqzl-c backend is opt-in (production pqz-ffi builds the Rust crate). Fix branch `rev2-pqzl` (plan
Task 5e, with the Rust-port minors). None of Q-A…Q-H changes proof bytes or verdicts on valid inputs.

| # | Finding | Sources | Verdict | Disposition |
|---|---|---|---|---|
| Q-A | `pqz_fixexp.h:104` / Rust `fixexp.rs:63`: u128 shift by `sh & 1` with `sh` from secret data (Gaussian mask, rejection ⟨z,v⟩); on wasm32 a `__ashlti3` call, whose compiler_builtins source branches on the amount; the C wasm build has its own branch-free helper, the Rust wasm32 build does not | N-1 | Confirmed in source (both cores); leakage of the linked helper a hypothesis | Fix in **both cores**: `mant + (mant & -(sh & 1))` (masked add, no shift by a secret); proof bytes unchanged; also check the C helpers in `pqz_wasm_rt.c` / `ffi/csrc/wasm_ti3.c` |
| Q-B | C keeps secrets: `expseed[96]` (`lnp-tbox.c:256`), the witness copy `s`, `yseed` and the masks (`lnp-quad.c:46/323–342`), sampler buffers (`grandom.c:57/110`), `pf_t` `s1/s2/m/tA2` (`pqz_rel.c:883–909`), stack arrays in `debit_witness` / `dec_w` / `dr_witness`, the client helpers' secret key in the shared `ARENA_SMALL`; arena release never clears | L C2-2, M C2-1 (P1), N-2 (P2), Open item 8 | Confirmed; needs a memory-read capability (as Rust fix B) — **P2** | Fix as Rust fix B: wipe the used arena above the mark before release in `pqz_prove` and the three client helpers (volatile `pqz_wipe`, `pqz_rt.h:98`), wipe the seeds and stack arrays on every exit; Open item 8 closed for C |
| Q-C | Arena exhaustion: the 1 MiB shared sink is smaller than single allocations (R_TXM8 SZ accumulators 2.25 MB native, `rel_keys` 13–14 MB at the first `pqz_verify_fast` of a relation — the known `ffi1d` segfault —, `pqz_init`'s A ≈ 2 MB) ⇒ out-of-bounds writes before `PQZ_ERR_ARENA` is seen | C-F2, L C2-1, M C2-3, N-3, Open item 2 | Confirmed; not input-triggerable (SV sizes are input-independent), needs an undersized arena | Fix: no write can follow a failed allocation — a sink at least as large as the largest single allocation (static bound from the parameter headers, asserted) or fail-stop at the entry point; remove the unused `pqz_arena_realloc`; a test with an undersized arena under ASan |
| Q-D | Truncated proofs: the entropy decoders advance pointers past the buffer after a failed read (`coder.c:152/188/319/345`, `pqz_rel.c:403`): source-level pointer UB, reads still guarded | L C2-3 | Confirmed (UB only; no crash / verdict effect shown); Rust stops at the first failed read | Fix: return at the first failed read, stop decoding once `err` is set; test: the 10,552-zero-byte `R_REG` input under UBSan / ASan |
| Q-E | `ASSERT_ERR` sets a sticky flag and continues: the bounds asserts in `spolyvec_insert_elem` / `spolymat_insert_elem` (`spolyvec.c:328`, `spolymat.c:360`) and `coder_dec_urandom5/6` fall through into the write | N-4 | Latent (not reachable from input today) | Fix: return after the failed assert at those sites |
| Q-F | Small UB / latent bounds: `NULL + 0` in `aes256ctr.c:339–341` (`out += len` with `out == NULL`); zero-length VLAs when M = 0 / nbin = 0 (`lnp-tbox.c`, Open item 4); C `canonical()` assumes `n % 8 == 0` (`pqz_keys.c:100`; Rust fix C's twin); `pqz__div` assumes `nn ≥ dn` (`pqz_mpn.h:150`) | M C2-4…C2-7 | Confirmed, latent (callers satisfy the assumptions) | Fix (one-liners): guard the pointer advance, size-1 VLAs or early returns, `n % 8` check, `nn ≥ dn` assert |
| Q-G | Constant time of the C prover depends on the compiler: pqz-ffi uses whatever `clang` is on PATH (`ffi/build.rs`); fix E checked clang 18 only; masked selects without a value barrier (`pqz_glue.h:54`, `pqz_ntt.h:13`, `pqz_rel.c:1106/1153`) | N-5 | Hypothesis | Fix: `pqz_ct_barrier` on those selects; `ct.sh` logs record the compiler; `ffi/build.rs` prints the clang version into the build log |
| Q-H | `check_symbols.sh` never asserts that the test-hook symbols are absent; the `fuzz` feature skips the scan; comment `pqz_rel.c:288` says statements are "< 70,000 B" (R_TXM8 215,936 B) | N-6 | Confirmed, hygiene | Fix: assert absence of `pqz_test_mutate` / `pqz_sz_trace_fn` / ctgrind symbols in production objects; fix the comment |
| Q-I | Global mutable state, not thread-safe | M C2-8, Open item 6 | Known (Open item 6); the node uses the Rust crate | Recorded, no code |
| — | "z2 rejection is bimodal with σ1 (D-2)" | M C2-2 | **Refuted**: `lnp-quad.c:280–281` calls `rej_onetime (…, scM2, stdev2sqr)` (Task 4); agy read the `upstream:` comment | none |
