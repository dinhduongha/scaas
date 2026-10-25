Reviewed frozen commit `008e196c` by static inspection only. **No new production-path P0/P1/P2 finding confirmed. One P3 affects the optional fallback build.** Prior constant-time fixes remain present in source.

Paths below are relative to `pqz-core/`.

## R3-1 — P3 — Fallback preset reuses an incompatible production proof-system ID

**Locations:** `pqzh/ligero/src/set.rs:15–25`; `params/sets/n2304-kmax4096/pqzh_set_fallback.rs:19–23`; `params/sets/n2304-kmax4096/rust/set.rs:63–66`; `pqzh/ligero/src/cs.rs:352–358,935–944`.

**Claim:** Enabling `set-n2304-kmax4096,fallback-retry` changes the proof protocol’s parameters but retains the production preset’s identifier.

**Evidence:**

- `set.rs` always imports this set’s `rust/set.rs`, while `fallback-retry` selects `pqzh_set_fallback.rs`.
- The fallback specifies:

  ```rust
  PRESET_N = 32_756;
  PRESET_K = 817;
  PRESET_T = 121;
  ```

- The imported identifier instead hashes the production label:

  ```text
  scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v2
  ```

- `cs::parse` accepts that imported `PQZH_ID`; it does not distinguish fallback proofs.

This changes polynomial lengths, domains, layout and transcript challenge consumption under the same ID. For example, R_REG has 83 witness rows with the fallback versus 63 with production preset B. The builds therefore implement incompatible verification protocols while advertising the same identifier.

The current `ids_are_the_labels_keccak` test would detect this: its expected `/ligero-fq46-n32756k817t121-…/` substring is absent from the imported label. This is a source deduction; I did not run the test.

**Impact:** Fallback proofs cannot be treated as production-compatible proofs merely because their ID matches. Severity is P3 because the feature is explicitly documented as experimental and excluded from production builds; no current production consensus split is established.

**Suggested fix:** Give the fallback a distinct experimental identifier and corresponding codec wiring, or remove the retained feature and preserve it only at its historical research commit.

## Checked and sound

These conclusions concern the supported production presets and source-level behavior.

| Invariant | Evidence |
|---|---|
| Field arithmetic at every PQZH q | `fq.rs:49–72,203–208,350–362`: Barrett reduction supports the 42-, 46- and 50-bit fields; the largest F4 convolution coefficient is below `10q² < 2^(2L+4)`. Signed conversion handles `i64::MIN` by unsigned magnitude. |
| wasm32 limb arithmetic | `fq.rs:80–191`: splits are 2×21, 3×16 and 3×17 bits respectively. Carry normalization and modular folding preserve the represented integer; compile-time bounds cover column accumulation and the final Barrett product. Scoped production accumulators remain below their documented limits. |
| FFT radices 2/7/17/19/43/431 | `fft.rs:47–64,109–168`: domain roots use `GEN^((q−1)/n)`; radix stages implement the DIT decomposition with matching inverse twiddles and normalization. Lazy sums contain at most 431 products, safely within u128 at the largest field. |
| `GEN·H_n ∩ H_k = ∅` | The presets’ `lcm(n,k)` is a proper divisor of `q−1`; with primitive `GEN=3`, an intersection would require `GEN` to belong to that proper subgroup. Thus the verifier’s Lagrange denominators are nonzero (`fft.rs:213–218`; `ligero.rs:608–614`). |
| Degree checks | `ligero.rs:533–539,598–605`: serialized coefficient counts bound the test-polynomial degrees; the proximity equation includes both `p_i` and `X^(k−1)p_i`. Production agreement-set sizes exceed the `3k−2` degree-correction threshold. |
| Linear checks | `ligero.rs:571–574,608–633`; `cs.rs:706–709,792–924`: the verifier checks the sum over `H_k` and queried evaluations. Constraint weights occupy distinct exponent ranges starting at 1, preventing a fixed blind sum from cancelling a violated constraint identically. |
| Quadratic checks | `cs.rs:225–239`; `ligero.rs:636–642`: square/Boolean triples receive transcript challenges, and every queried column checks `Zζ(η)h(η) = Σr_t(U_xU_y−U_z)+u_quad(η)`. |
| Merkle checks | `ligero.rs:550–568`; `merkle.rs:62–79`: indices are verifier-derived, sorted and deduplicated; canonical columns are hashed with salts; reconstruction checks the root and rejects trailing bytes. Leaf preimages differ in length from internal-node preimages. |
| Native = wasm32 | `fq.rs:145–191,350–400`: both paths compute the same modular products and sums within the checked bounds. Encoding, transcript and verifier equations are shared. This establishes source-level equivalence, without executing either target. |
| Review O constant-time paths | `fft.rs:135–150`, `ring.rs:73–93`, `cs.rs:445–483,526–580`, `ligero.rs:434–435`: sparsity depends on public padding; secret-zero skips remain removed; centering, division and verdict accumulation retain the fixes. No source-level regression found. |

Soundness accounting in `ligero.rs:65–68,714–735` matches the selected preset constants and checked-in parameter reports:

| Set | n / k / t | Query + grinding bits | Combined classical ROM bits |
|---|---|---:|---:|
| n2048-kmax1024 | 32756 / 817 / 121 | 128.50 | ≈127.23 |
| n2304-kmax4096 | 45752 / 952 / 120 | 128.94 | ≈127.40 |
| n2560-kmax16384 | 32756 / 817 / 122 | 129.43 | ≈127.55 |

These totals sum the five documented error terms. They are **classical ROM figures**, as already documented, rather than a 128-bit quantum soundness claim.

## Not covered

I did not review the PQZL implementations, full `pqz-stmt` decoder, FFI/Nethermind integration, external hash-library internals, or wasm/runtime machine-code lowering. Supporting reads included the transcript, module wiring, imported field constants, prior review O and parameter documentation.

No files were changed; no builds, tests, benchmarks or timing checks were run. Compiler-level constant-time behavior and runtime cross-target equivalence remain unverified by this static pass.