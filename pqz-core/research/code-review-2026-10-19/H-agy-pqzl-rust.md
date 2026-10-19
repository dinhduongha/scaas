# H — agy review of the PQZL Rust crate (third model) and triage of G + H

**Date:** 2026-10-19. **Reviewer:** agy 1.4.2 (Gemini via Antigravity CLI; one task, `--mode plan`, no
`--dangerously-skip-permissions`; worktree unmodified afterwards; conversation `d5f49f6e-a5d4-4061-85a6-035da77fc5f3`).
Owner-requested, same prompt and target as G (Codex): `pqz-core/pqzl/rust/` at `0dc869d`, read-only.

## Findings (agy's text, condensed)

1. **P3 — latent slice panic in `canonical()`.** `rust/src/keys.rs:117–119`, `be8` at `:74`: `p.chunks(8)` passes a
   short last chunk to `be8`, which indexes `c[..8]`. Callers pass `[u8; POLYVEC_BYTES]` / `[u8; CT_BYTES]`. Fix:
   `chunks_exact(8)` and require an empty remainder.
2. **P3 — best-effort wiping; `m`, `t_a2` not wiped.** `rust/src/lib.rs:94–97` (`wipe` = plain stores +
   `black_box`, no volatile / `zeroize` under `no_std`), `rust/src/rel.rs:913–916` (`m`, `t_a2` not wiped on exit; as
   in C, STATUS Open item 8). Fix: wipe them; document the platform boundary.
3. **P3 — C UB on `INT64_MIN` in the SV z4 norm check.** C `src/pqz_sv.c:1489`
   `(uint64_t)(z4c[j] < 0 ? -z4c[j] : z4c[j])` negates `INT64_MIN`; Rust `sv.rs:1300` `unsigned_abs()` is safe. Fix:
   negate after the cast to `uint64_t`.
4. **P3 — `stmt.len() as u32` in the statement hash.** `rust/src/rel.rs:140`: a statement ≥ 4 GiB would collide in
   the length prefix. agy assumed the exact length is checked first; it is not (see G-3).

## Checked and clean (agy)

Same areas as G, independently: the v3 transcript order in the generic verifier and the SV (hz after the z3 / z4 norm
checks, JL rows on `cseed`, h before μ and c), the v3 id; all norm bounds and the per-block l2 domains; canonical
decoding (fixed-width ranges, bijective ghint / grandom, no `z + kq` alias within `MAX_PROOF`, stop bit and padding);
SV arithmetic headroom (CRT modulus > 2^119, accumulators < 2^40, `l2_sum` < 2^63); fallible allocation and no
production `unwrap` / `expect`; wasm32 (21-bit limb products, small `as usize` casts); D-2 / D-3 rng parity; `unsafe`
and test features gated. Not checked: builds / tests, parameter hardness, the pinned `aes` / `sha3` crates.

## Triage (controller, G = Codex, H = agy)

Verified against the code at `0dc869d`. No P0 from either model; no input-reachable panic in production.

| # | Finding | Sources | Verdict | Proposed disposition |
|---|---|---|---|---|
| A | Statement hashed (and cold caches built) before the exact-length check; `as u32` length prefix | G-3, H-4 | Confirmed: `verify_rel` calls `rel_state` and `stmt_hash` before `build` checks the length (`rel.rs:864–869`); production bounded by pqz-ffi `MAX_INPUT` | Fix now, C and Rust, generic and SV: length / proof-cap check first; `u32::try_from` in `stmt_hash` |
| B | Secret copies and mask seeds not wiped (`sv`, `s`, `yseed`, 96-byte seed, `m`, `t_a2`), also on `?` exits | G-2, H-2 | Confirmed (Rust); C partly the same (Open item 8) | Fix now in Rust (wiping drop guard); C: record under Open item 8 |
| C | `canonical()` short last chunk | H-1 | Unreachable today (16,384 B is a multiple of 8) | Fix now (one line, `chunks_exact`) |
| D | C `-INT64_MIN` in the SV z4 check | H-3 | Unreachable through the decoder (coefficient sizes bounded by `MAX_PROOF`) | Fix now (one line) |
| E | Secret-dependent branches in the prover (`set_upsilon` / `binexp`, `Int` add / sub) | G-1 | Confirmed in source, exploitation a hypothesis; inherited from C (`lazer/int.c:257–266`) | ~~Open item before mainnet 22776~~ **Superseded (owner 2026-10-19): fix now, before the merge**, branch `pqzl-fs3-ct` (constant-time prover arithmetic in both cores, ctgrind-checked) |

None of A–D changes proof bytes or verdicts on valid-length inputs (A only reorders a reject).
