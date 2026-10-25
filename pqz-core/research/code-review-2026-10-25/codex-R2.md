## R2 findings

**No confirmed new P0–P3 findings** in the inspected R2 code at `008e196c`. No incomplete prior fix was established within this scope.

This was a static, read-only review. No builds, tests, generators, benchmarks, or timing runs were executed.

## Checked and sound

The inspected set constants agree between `set.toml`, `pqz_set.h`, `rust/set.rs`, and the per-set parameter descriptions:

| Set | q | Δ | `K_MAX` | M / carries / noise bits | β_s / β_e / β_2 |
|---|---:|---:|---:|---|---|
| n2048-kmax1024 | 4,398,046,510,889 | 67,108,863 | 1,024 | 14 / 11 / 25 | 36 / 164 / 64 |
| n2304-kmax4096 | 61,275,424,977,257 | 233,747,196 | 4,096 | 16 / 13 / 27 | 38 / 173 / 64 |
| n2560-kmax16384 | 1,125,899,864,532,089 | 1,073,741,783 | 16,384 | 18 / 15 / 29 | 40 / 182 / 64 |
| n2816-kmax65536 | 18,014,398,509,481,657 | 4,294,967,295 | 65,536 | 20 / 17 / 31 | 42 / 189 / 64 |

- **Parameter generation:** `gen_set.py:132–168` derives Δ, widths, bounds, Barrett constants, and roots from each set; `:289–346` derives relation shapes. The inspected generated q, binary dimensions, block dimensions, and squared norm bounds match those inputs for REG, DS/DR, TX/TX0, BURN, and TXM with/without the auditor.
- **Bit layouts:** `gen_set.py:296` allocates `128 + 16m + 15(m−3) + 16eb` transfer bits. Thus **18/15/29 applies to n2560**; n2816 correctly uses **20/17/31**.
- **NTT construction:** `gen_set.py:140–146` selects a quadratic non-residue, requires `ζ⁴ = −1`, and derives the remaining roots and inverses. C and Rust consume matching constants; the n2816 root correctly uses base **5**.
- **NTT accumulator bounds:** [pqz_ntt.c:41](pqz-core/pqzl/src/pqz_ntt.c:41) uses `LB = ceil(LOG2Q/2)` and asserts `LOG2Q ≤ 56`. At the largest current set, `LB=27`: each limb-product column sum is below `16·2⁵⁶ = 2⁶⁰`; the reconstructed product sum is below `16q² < 2¹¹²`. Both fit their respective accumulators.
- **Barrett reduction:** `pqz_ntt.h:23–37` and `arith/ntt.rs:24–42` use `X=2L+4`. At `L=54`, the intermediate multiplication is below `2¹¹⁸`, while the residual is below `3q < 2⁵⁶`; intentional unsigned wrapping preserves that residual.
- **Rust limb arithmetic:** `arith/mpn.rs:30–42` bounds its multiply-add by `(2⁶⁴−1)² + 2(2⁶⁴−1) = 2¹²⁸−1`. Polynomial/vector products reduce each product and addition rather than accumulating an unreduced key-sized sum.
- **Norm accumulators:** `arith/poly.rs:324–332` and `polyvec.rs:376–382` use two limbs. Decoded response coefficients are reduced and centred before use (`coder.rs:302–308`); even the largest generated vector has fewer than `2¹⁶` coefficients, giving squared sums below `2¹⁶·(q/2)² < 2¹²²`.
- **KeyGen and Enc:** [pqz_keys.c:111](pqz-core/pqzl/src/pqz_keys.c:111) and `keys.rs:177–299` agree on SHAKE tags, big-endian counters, LSB-first CBD sampling, sample order, norm rejection, and the 64-attempt limit. The ring helpers implement `pk=As+e`, `u=Aᵀr+e1`, and the first 16 coefficients of `pkᵀr+e2+Δm`.
- **Dec:** [keys.rs:327](pqz-core/pqzl/rust/src/keys.rs:327) and `pqz_keys.c:189–212` implement the same centred subtraction and ties-up rounding. At n2816, the positive division numerator is below `5q+Δ < 2⁵⁷`, safely inside `int64`. The even Δ at n2304 causes no ambiguity for accepted noise, since `E=2²⁶ < Δ/2`.
- **Noise budget:** `budget.py:57–67` checks `2E≤Δ`, centring, and `K_MAX·B_FRESH≤E`; the four documented bounds satisfy these inequalities.
- **Prior fixes:** C and Rust canonicality helpers reject partial eight-byte coefficients. The previously reported key-helper secret buffers retain the C wiping and Rust `Wiped` guards.

## Not covered

I did not read every generated rejection/compression constant or perform a byte-for-byte regeneration comparison. Per-set estimator/codegen logs, upstream KAT artifacts, historical fallback/spike presets, and legacy parameter directories were not reviewed in full. Primality and the large modular root identities were not independently recomputed.

Proof/transcript logic, statement/accounting enforcement, FFI, and Nethermind were outside this unit, apart from the narrow caller reads noted above. **The result is static assurance for the inspected paths, not exhaustive certification of every generated field or compiled target.**