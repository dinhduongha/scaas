# Whole-code review 2026-10-19 (PQZH Rust, PQZL C, LaZer fork)

Owner request 2026-10-19: "codex review toàn bộ phần code rust của pqzh và pqzl C". Codex started four read-only passes; all
four stopped after about 3 minutes ("Your workspace is out of credits"). Their unverified leads are in
[codex-aborted-leads.md](codex-aborted-leads.md). The owner then chose four Claude reviewers, same scopes, static reading
only (no build, no run), started after the gas calibration of the Rust roll-out. Each verified or refuted the Codex lead of
its scope. Reviewed at main `4c20032`.

| Report | Scope | Result |
|---|---|---|
| [A-pqzh-ligero.md](A-pqzh-ligero.md) | `pqzh/ligero` + the pqz-ffi PQZH dispatch | no P0/P1. P2: sparse FFT in the prover branches on witness zeros (`fft.rs:121-124` via `ligero.rs:290`; Codex lead confirmed). P3: `dot_int` skips zero secret coefficients, sign branch at `cs.rs:485`; prover clears missing (STATUS Open 8 to name PQZH). Mask hedging per CTR-PQZ-19 compliant. |
| [B-pqzh-stark-backup.md](B-pqzh-stark-backup.md) | `pqzh/stark-backup`, `pqzh/xcheck` (backup, not live) | P1: the only preset is not zero-knowledge and proves 71.9 bits; hiding proofs exceed `MAX_PROOF`. P2: overlong length varints accepted (Codex lead a confirmed); masks seeded from `rnd32` alone (Codex lead b confirmed). P3: latent preprocessed-root cache divergence; verifier spec drift. |
| [C-pqzl-c.md](C-pqzl-c.md) | `pqzl/src` (C glue, generic and specialised verifiers) vs the Rust port | **P0: `h` is not absorbed into the Fiat–Shamir transcript before `mu`** → forgery of any PQZL statement by a linear solve (all four implementations; inherited from LaZer). P3: arena exhaustion sink smaller than single allocations. Codex leads (reused domain, signed representatives, encoding canonicality) settled: sound. |
| [D-lazer-fork.md](D-lazer-fork.md) | `pqzl/lazer` | **P0: `z3`, `z4` are never absorbed before their Schwartz–Zippel challenges `V`** (all four implementations; inherited). P2: z2 rejection test gets z1's variance and has no random sign (Codex lead a confirmed; prover-side ZK). P3: β4 sign reads bit 8 on the fourth attempt (Codex lead b confirmed; negligible). |
| [G-codex-pqzl-rust.md](G-codex-pqzl-rust.md) | `pqzl/rust` at `0dc869d` (branch `pqzl-fs3`), Codex | P1: secret-dependent branches in the prover (fix E, branch `pqzl-fs3-ct`). P2: secret copies / mask seeds not wiped (fix B); statement hashed before the length check (fix A) |
| [H-agy-pqzl-rust.md](H-agy-pqzl-rust.md) | same, agy; triage table A–E | P3: `canonical()` short chunk (fix C), wiping (fix B), C `-INT64_MIN` in the SV (fix D), `as u32` length (fix A). A–D fixed on `pqzl-fs3-fixad` (plan Task 4b, decisions CTR-PQZ-09) |

**Controller verification (2026-10-19).** Both P0 transcript facts were re-read by the controller in the Rust prover
(`pqzl/rust/src/proof/tbox.rs`: `tg` hashed at 1058, `h` computed after it, `quad.rs:22` derives `mu` from the same
hash; `sz_z3` / `sz_z4` seeded from `hash0` before `z3`/`z4` exist), in the Rust specialised verifier (`sv.rs:1323-1328`,
final challenge from `t`, `v`, `w1` only at 1723) and in upstream LaZer at `b958e24` (`lnp-tbox.c` L441–L444, L673–L708,
L748; `lnp-quad-many.c` L34; `lnp-quad.c` L458–L472). No cheating-prover proof of concept has been run yet.

**Owner rulings 2026-10-19:** fix the P0s now, ahead of the other Rust-port follow-ups and the token rename; report
upstream as a public issue at once (filed as [lazer-crypto/lazer#28](https://github.com/lazer-crypto/lazer/issues/28));
stop and roll back the Rust-backed roll-out on 7622 (live stays on `pqz2` until the fix).

**Fix E (2026-10-19, owner ruling: before the merge, both cores):** Codex finding G-1, prover control flow on secret
witness values (slack, `binexp`, `Int` add / sub). Inventory, fixes, the ctgrind check (`pqzl/test/ct.sh`) and its
limits: [E-constant-time.md](E-constant-time.md).
