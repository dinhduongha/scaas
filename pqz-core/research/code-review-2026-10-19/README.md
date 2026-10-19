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
| [I-codex-pqzh-rust.md](I-codex-pqzh-rust.md) | round 2 (owner 2026-10-19 evening): PQZH Rust at `e9cabd1` (`pqzh/ligero`, pqz-ffi PQZH path, `stmt`, `xcheck`; `stark-backup` secondary), Codex | no P0 / P1 in the live path; round-1 A-F1, A-F2, A-Note and B-F1…F5 all still present |
| [J-agy-pqzh-rust.md](J-agy-pqzh-rust.md) | same, agy; **triage table P-A…P-I** | same eight findings, nothing new; triage: fix P-A…P-H on `rev2-pqzh` (plan Task 5c), P-I a gate before the backup is promoted |
| [K-claude-pqzh-rust.md](K-claude-pqzh-rust.md) | same, Claude sub-agent | no P0 / P1; new: wasm32 `i64.rem_s` / `div_s` and conditional subtractions on secrets (F3), infallible verifier allocation (F5), unsafe pointer work in bench wasm exports (F6) |
| [L-codex-pqzl-c.md](L-codex-pqzl-c.md) | round 2: PQZL C core at `e9cabd1` (`pqzl/src`, `pqzl/lazer`, the C backend in pqz-ffi), Codex | P3 only: arena sink overflow (C-F2), secrets kept in C, pointer UB on truncated proofs |
| [M-agy-pqzl-c.md](M-agy-pqzl-c.md) | same, agy; **triage table Q-A…Q-I** | wiping (rated P1, triaged P2), D-2 claim refuted, small latent UB; triage: fix Q-A…Q-H on `rev2-pqzl` (plan Task 5e), Q-I recorded |
| [N-claude-pqzl-c.md](N-claude-pqzl-c.md) | same, Claude sub-agent | no P0 / P1, no C = Rust divergence; new: secret-amount u128 shift in fixexp (both cores, wasm32), `rel_keys` 13–14 MB through the sink, `ASSERT_ERR` fall-through, compiler dependence |
| [O-pqzh-constant-time.md](O-pqzh-constant-time.md) | round-2 fixes P-A, P-B, P-C on `rev2-pqzh` (plan Task 5c) | inventory (a) fixed / (b) declassified / (c) public of the Ligero prover, the ctgrind check `pqzh/ligero/runs/ct.sh` (0 reports, twelve relations), the wasm32 divisions before / after, the wiping and its platform boundary |
| [T-codex-chain-aborted.md](T-codex-chain-aborted.md) | on-chain review (plan Task 5f) at `7aab1fe`: Nethermind PQZ plugin + all EVM Solidity, Codex | aborted, workspace out of credits; one lead (W-A), confirmed by V1 |
| [U-agy-chain.md](U-agy-chain.md) | same, agy; **triage table W-A…W-S** | 3 P2 in the plugin (one refuted, one plausible, one P3), 3 P3 in Solidity; triage: fix on `rev2-chain` (plan Task 5g) |
| [V1-claude-plugin-pqz-zether.md](V1-claude-plugin-pqz-zether.md) | same, Claude part 1: plugin, `pqz/`, `zether/` | no P0 / P1; P2: unbound transfer mode on direct calls (W-A), creator-chosen verifier trusted (W-B); five P3 |
| [V2-claude-ua-account-wallet.md](V2-claude-ua-account-wallet.md) | same, Claude part 2: `ua/`, `account/`, `wallet/` | no P0 / P1; P2: decoy-list flooding (W-C, spec); five P3 |
| [V3-claude-common-metatx-dex.md](V3-claude-common-metatx-dex.md) | same, Claude part 3: `common/`, `metatx/`, `factory/`, `dex/`, `trade/`, `hedera/` | P3 only (forged gas selectors abort a DEX batch, cancel not nonce-bound, ERC-1271, hygiene) |
| [X-review-b-transcript.md](X-review-b-transcript.md) | plan Task 11 review B at `a61d221`: the v3 fix diff, every prover message vs LNP22, F7 (Rej1), O3 (A' budget) | **P0 B-1: V3 / V4 drawn from hz before the commitment `tg` to g** (all four verifiers and both provers; the other accumulators use the post-`tg` hash) — the v3 fix does not fully close D-1; Rej1 and the A' budget confirmed; P3 docs |
| [T2-codex-chain.md](T2-codex-chain.md) | Codex re-run of the on-chain review at `fe2faf0` (after 5g) | no new P0 / P1; W-A…W-S verified; P2 CHAIN-01 (all-zero credits defeat W-E's base — obsoleted by 5h, carry-over: refuse an all-zero `u`), P3 CHAIN-02 (historical first activation; **fixed** `88c8083`), P3 CHAIN-03 (fee overflow, `mulDiv`; **fixed** `4fae6ab`) |
| [W-review-a-pqzl-rust.md](W-review-a-pqzl-rust.md) | Task 10 review A: PQZL Rust crate at `a61d221` | P0 A-1 = B-1 **confirmed by a cheating prover** (accepted on all 14 codes; fix in the 16k regen, CTR-PQZ-09); P3 A-2 (β4 / υ share a challenge, renumber in the same bump); P3 A-3 (Rust lags the C Q-B wiping in `keys.rs` / `rel.rs`); 2,828 extreme / mutated cases: Rust = C verdicts |

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
