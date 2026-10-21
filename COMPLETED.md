# COMPLETED — scaas

Archive of finished work, moved verbatim from [TODO.md](TODO.md) and [HANDOFF.md](HANDOFF.md) on 2026-10-20 (owner
rule: backup, not delete). Apart from the full text of compacted open items (below), nothing here is open work. Original order and headings are kept (headings one level lower).
"From TODO.md" holds the done items, the superseded "Next" lines, the finished phases' narratives and the full text of
open items that TODO.md now carries in compact form (same item title there; the open remainder lives in TODO.md).
"From HANDOFF.md" holds every session note older than the newest one.

## From TODO.md

Ordered by what blocks what (shutdown 2026-10-08). Owner rule: **finish all specs before app code**.
Max 3 agents, one heavy build at a time (`scripts/capped`). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

### 00. Meta-transaction redesign — code streams (accepted 2026-10-08; rules in the component docs)

Order: contracts first (one heavy build at a time), then node, clients, the Odoo connector (bamboo-dms).
Design record: `docs/history/specs/2026-10-08-token-tree-design.md` (accepted and folded 2026-10-08; rules CTR-TOK-21…26,
CTR-MTX-25, CTR-AS-17, CTR-DEX-24, CTR-ZTH-37…47, CTR-ACC-11, CTR-PQZ-22). The MT-1…MT-9 streams are regrouped into
phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TOK-24) and the full forge suite.

| Phase | Content | Streams |
|---|---|---|
| P0 | Spec and fold into the component docs and `decisions.md` | done |
| P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NONE`, `UNDERLYING`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done, merged `d85fc8b`) | MT-5 |
| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done, merged `dc9d219`; P3b modes done) | MT-6 |
| P4 | `MandateWallet`, `SmartKeyAccount` (rename: EVM, Solana, Soroban) on `MetaTxBase`; the typed-struct line to `legacy/p4/` (done, merged `ebacaac`) | MT-7 (+ rename in NM-*) |
| P5 | Node, clientkeys, encoders for the new ABI; the v1 line to `legacy/p5/` (done; plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`) | MT-8, MT-9 |
| P6 | PQ Zether after P5 (owner 2026-10-11) and PQ signatures as compatible as possible with the Ethereum drafts, both directions (ML-DSA [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) / [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355): empty FIPS 204 context, `pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, the EIP encodings incl. the expanded key; Falcon [EIP-8052](https://eips.ethereum.org/EIPS/eip-8052); `slhdsa128s` 0x0133 behind a gas gate; precompiles by probe at the EIP addresses, the SCaaS testnet addresses out of the EIP-1352 range; no hybrid kind, owner 2026-10-12; [CTR-UA-23](docs/contracts/accounts.md#CTR-UA-23), [pq-eips-vs-scaas.md](docs/research/pq-eips-vs-scaas.md) Q1–Q8). Roadmap `docs/superpowers/plans/2026-10-12-p6-roadmap.md`: **P6a** PQ signature verifiers on the EIP formats + clientkeys PQ signing (done: `UAMldsaVerifier`, `UAFndsaVerifier`, `UASlhdsaVerifier`, `src/pq.js`, vectors `smartcontracts/vectors/ua/`; SLH-DSA gate passed at 1.32 M worst case; plan `docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`; open: final review + merge); **P6c carry-overs (closed in P6c):** ~~tighten the expanded ML-DSA-65 gas bound below 6 M when setting `verifyCap`~~ (cap 5,950,000 on the cached key, measured 5.80 M); ~~the SCaaS testnet deploy script asserts `PRECOMPILE() != 0` for the ML-DSA verifier~~ (superseded by the expanded-key cache: -65 verifies at 5.8 M in Solidity; the precompile candidate and its probe assertion move to P6g with chain 7622's precompile); ~~pin the PQ kind numbers 0x0130–0x0133 in `vectors/ua/kinds.json` (UA F0)~~ (done by UA-1); **P6c owner steps (open):** - [ ] **deferred to P6g (owner 2026-10-13: deploy once, together with `UAPqzVerifier`)**: redeploy UA registry gen 1 on the SCaaS testnet (owner-gated); block gas limit read from the chainspec 2026-10-13: genesis `gasLimit` 16,777,216, no `Blocks.TargetBlockGasLimit`, EIP-7825 on from genesis (acceptance run 2026-08-31 also saw 16,777,216; re-check on the live node with `cast block latest --field gasLimit` before the deploy), so the ML-DSA-65 cache parts fit and all four PQ kinds are usable on the SCaaS testnet; an ML-DSA-65 cache part needs a ~13.5 M-gas transaction, so with a lower limit only `fndsa512` and `slhdsa128s` are usable there; - [ ] audit the PQ verifiers and the expanded-key cache before any public chain enables a PQ kind; **P6b** E-S0 parameter spike (done 2026-10-13, gate met, branch `p6b-estimator`: every instance above Kyber-512 under ADPS16 classical and quantum, worst hint direction β 464, every FS round ≥ 128 bits; P6d must keep κ ≥ 8, λ ≥ 4, ABDLOP n ≥ 24 / m2 ≥ 66 and check the recalled LNP22/LaZer constants; `pqz-core/pqzl/params/estimator.txt`, `docs/research/pqz-parameters-e-s0.md`); **P6c** the PQ kinds (UA F9) in UA registry gen 1, after UA F0/F1 as their own phase (owner 2026-10-12); ML-DSA stored key = the FIPS 204 pk, the EIP-8051 expanded key an optional SSTORE2 cache the registry derives itself (owner 2026-10-12); plan `docs/superpowers/plans/2026-10-13-p6c-pq-kinds.md` (built: the four PQ signing kinds and the `pqz-mlwe` slot in `UARegistry` gen 1, stored keys, the registry-computed ML-DSA expanded-key cache in SSTORE2 parts, measured caps, the PQ msig bound, `pq_signatures.json`; enabled on the dev chains and the SCaaS testnet only until an audit); **P6d** E-S1 `pqz-core` spike (spike done 2026-10-13, branch `p6d-pqz-core`, not merged: LaZer `3330e48` fork with six layers rewritten, arithmetic-layer KAT 19/19 vs an upstream golden dump under Intel SDE; `R_TX` proof 42.7 KB (pass), verify 15.2 s native / 33 s wasm against 50 ms (miss), prove 17 s / 39 s against 6 s (miss; **P6d-2 optimisation (merged 2026-10-13, branch `p6d2-opt`): `R_TX` prove 1.10 s native / 1.59 s wasm (pass), verify 0.72 s / 0.82 s (miss, ≈ 14×), wasm memory 230 MiB (under the 256 MiB hard limit, 1.8× the budget), proofs byte-identical; research note §11.** limit raised from 3 s, owner 2026-10-13), symbol scan clean (pass); browser budgets (CTR-PQZ-18) missed too: wasm prove 39 s against the 30 s hard limit, wasm memory 476 MB against 256 MiB, wasm/native 2.3–2.7×; `pqz-core/README.md`, `docs/research/pqz-core-e-s1.md`; upstream cross-check done: upstream LaZer on the same `R_TX` is 2.3–2.6× faster than the fork and still misses both (prove 6.6 s, verify 6.6 s; research note §10); kill decision and any optimisation pending (owner)); **P6e** E-S2 relations; **P6f** E-S3 Nethermind precompiles on the SCaaS testnet (owner-approved chain changes); **P6g** E-S4 contracts (`PqzToken` with CTR-PQZ-23/24); **P6h** E-S5/E-S6 clients and WASM; **P6i** E-S7 node; **P6j** E-S8 review; G-LIC any time (release gate) ([pq-zero-knowledge.md](docs/contracts/pq-zero-knowledge.md)); G-LIC step 1 technical inventory done on branch glic-inventory (`docs/research/pqz-licence-inventory.md`, `pqz-core/NOTICE`; no GMP / MPFR / HEXL in any pqz-core artifact; legal review still open); UA phase roadmap `docs/superpowers/plans/2026-10-12-ua-roadmap.md` (UA-1 kind libraries, UA-2 registry and verifiers, UA-3 Zether re-point, UA-4 UA ledger) | UA PQ kinds, E-S* |

- **Mandate (owner 2026-10-14, session 4): after the three WIP branches (`pqz-artifact`, `pqzh-zkwhir`, `pqzh-ligero`) finish, carry P6 through to its end** (P6e rest, P6f, P6g, P6h, P6i, P6j, P6-PUB freeze, PQZH backend choice). Owner rulings for this mandate: (1) merge AND push each sub-phase into `main` as soon as its tests, size gate, docs checkers and review pass (no per-merge approval needed for P6); (2) decisions that come up (PQZH soundness regime / backend / proofSystemId string, freezing the PQZL `proofSystemId`, precompile addresses outside the EIP-1352 range) — the controller picks by the measurements and records each in `docs/decisions.md` as "status: controller proposal, owner may override", without waiting; (3) UA F5 is unpaused only as far as P6i needs it (`ua_metatx` for `kind = pqz`). Changed 2026-10-15 (owner, explicit: agreed to all three): the SCaaS testnet is the testnet and may be reset, so the controller makes these SCaaS testnet changes itself without asking each time: (1) once the throwaway-copy gate (P6f T7–T9) passes, back up the current the SCaaS testnet data first; (2) reset the SCaaS testnet with a fresh genesis carrying the PQZ and ML-DSA precompiles from block 0 (P6f Task 10); (3) later P6g / P6i deploys on the SCaaS testnet. Every change to chain 22776 (mainnet) stays the owner's (P6f/P6g/P6i work on a throwaway copy); posting to ethresear.ch / ePrint, the LaZer mails, Zenodo, G-LIC and the lawyer stay owner steps (controller drafts only); no built binaries on GitHub.
- **Owner 2026-10-15: `R_TXM` e2 bound = per vector ≤ 64** (P6-ANON pre-review X-1): every leg's e2 vector bounded by 64 in ℓ2 (‖e2_j‖² ≤ 4,096) as pq-zero-knowledge.md §4.3 states, not one block bound 64·√M; PQZH already does this, PQZL `p6-anon-l` changes its rows. Recorded in decisions.md CTR-PQZ-03.
- **Owner 2026-10-15: P6f gas calibration = ONE run** ("P6f đo gas một lần"; plan Task 6 two-day rule withdrawn; re-calibrate before 22776). **Concurrency: two capped heavy jobs at a time** (owner 2026-10-15, confirmed): `scripts/capped` now has 2 slots (lock files `heavy`, `heavy.2`; `CAPPED_SLOTS` overrides), each 4 GB; docker containers still need their own `--memory`.
- **Owner 2026-10-14 (session 4): the `PQZ` precompile verifies both PQZL and PQZH (Ligero)** — one address, dispatch on `proofSystemId` via `pqz-ffi` (built in P6e Task 7, branch `p6e-a3`, both ids round-trip); P6f prices each id separately and sizes node limits for the PQZH input (393,216 B). Recorded in CTR-PQZ-10 (spec + decisions.md).
- [ ] **P6e relations (plan merged 2026-10-14, `docs/superpowers/plans/2026-10-14-p6e-relations.md`)**: gaps G1 (`R_TX` without the auditor not built, CTR-PQZ-24), G2 (PQZL prover masks not hedged as CTR-PQZ-19 requires; fix changes every `proofs_fnv`), G3 (§5 transcript text ≠ v2 code), G4 (KeyGen / Enc from seeds and SHAKE256 missing in C), G5 (PQZH transfer input 345,221 B > `MAX_INPUT` 262,144), G6 (PQZH has 2 of 5 relations), G7 (Ligero max proof 262,350 B > 256 KiB). Part A (PQZL, gate A) tasks 1 → 4 → 3 → 2 → 5 → 7 → 10 → 11 → 12; Part B (PQZH, gate B) 6 → 8 → 9 → PQZH parts of 10–12 after `pqzh-ligero` merges. Decisions D1–D15 in the plan's table = controller proposals (owner may override), recorded in `docs/decisions.md` as each is implemented; controller pick on D12: **no CI workflow for now** (continuous fuzzing runs locally under `scripts/capped`, text logs committed; the CI job is decided together with the package's CI after the freeze, as the owner ruled for `pqz-artifact`). **P6-PUB freeze postponed to after gate A** (controller 2026-10-14: the run in progress was stopped because G2 changes every honest proof; `pqz-artifact` merged `a396181` with the freeze still open).
- **Priority (owner 2026-10-13): P6 / PQZ first.** Finish the work in flight (UA-5b `ua5b`: checks, mutations, owner rulings C5b-*, merge; `pqz-v2`: the two LaZer tbox fixes under one `proofSystemId` v2 bump; PQZH prototype `pqzh-proto`; PQZH Solidity gas `pqzh-sol`), then focus on PQZ in this order: the specialised-verifier line (`pqz-sv-relfix` from `pqz-sv-rel3` + `pqz-v2`, all five relations, then publish `pqz-tbox-soundness.md` and the ℓ2 note, correct pq-zero-knowledge.md §4.3 / T5 and `pqz-verifier-floor.md` Caveats), the rest of P6e (codegen, serialization v1, `pqz-ffi`, continuous fuzzing, freeze `proofSystemId`), then P6f precompiles. UA-5c and UA F5 are paused until then; P6g needs UA only for `pqzUnshield` with a `bytes32` recipient.
- ~~**bn254 MSM precompile for classical Zether (owner 2026-10-17, later, not scheduled)**: a generic bn254 G1 multi-scalar-multiplication precompile in the `Nethermind.Pqz` plugin (pattern of `pqz-ffi`: Rust cdylib + P/Invoke) for the SCaaS testnet / 22776; the Solidity Zether verifier stays the protocol (only its MSM calls change, today a `0x07` mul + `0x06` add loop, zether.md §19), so the verifier still runs on every EVM chain. **No full Zether verifier precompile** (owner: MSM only). Reason to do it: gas / throughput (single transfer ≈ 3.2–3.4 M, M = 8 ≈ 14–15 M under the 2^24 cap; block 80 M ≈ 24 transfers); estimate [not measured] 2–4× less verify gas. Revisit when 22776 needs Zether M > 8 or more throughput. Status: recorded only.~~ **Cancelled (owner 2026-10-17):** not needed — a token that wants an MSM precompile uses the BLS12-381 Zether verifier (EIP-2537 `G1MSM`, already on Prague chains); bn254 keeps the `0x06` / `0x07` loop.
- [ ] **P0 PQZL Fiat–Shamir fix (owner 2026-10-19: now, before everything below)**: **code merged to main `361a86b` (owner 2026-10-19: merge before Tasks 6–13; branch `pqzl-fs3`)**. Done: Tasks 0–5 and 8 of plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md` — binding tests P6-FS (observation only, no cheating-prover PoC, owner ruling), transcript fix in C generic, C SV, Rust generic, Rust SV and the provers (z3‖z4 → hz before V3/V4 with the JL rows on cseed; h → hash2 before μ and c), PQZL `proofSystemId` v3 `0x8079d65b…16baef` everywhere (v2 removed), D-2 (Rej1) and D-3 (β signs), vectors regenerated (self-test hash unchanged `ed910a2c…d205`), docs / spec / decisions F1–F10, STATUS Open item 11 closed on the branch; plus Task 4b / 4c: review fixes A–E from the Codex (G) and agy (H) reviews of the Rust crate, incl. constant-time prover / keys arithmetic (ctgrind 0 / 0 C and Rust; timing: verify_fast unchanged, prove +2–9 %). **Remaining, in order (owner 2026-10-19 evening: review round 2 first):** Tasks 5b–5e (plan): PQZH Rust reviewed by Codex, agy and a Claude sub-agent, fixes incl. round-1 A-F1 / A-F2 / A-Note and the small stark-backup fixes (B-F1 / B-F5 recorded as a gate before the backup is promoted); then the PQZL C core reviewed the same way, fixes incl. C-F2 (arena sink) and Open item 8 in C, together with the Rust-port minors (follow-up item 5) → (owner 2026-10-19 late: Task 5h PQZ redesign — ciphertexts in state, `K_MAX` raised by A' (q ≈ 2^54) plus B (ordered, never-skipping rollovers, credits never refused); Tasks 7 / 9 / 10 / 11 go on, Tasks 6 and 13 wait for 5h) → Task 6 reproduction package (`expected-results.json` digest lines still v2-era; Docker quick with `--memory`, run alone) → Task 7 fuzz 3 × 2 h `pqzl-diff` (three small corpus files still carry the v2 id) → Task 9 gate `scripts/capped pqz-core/gate.sh fs9` (incl. the full `sv/diff.sh` x86v3 / z21diff passes deferred from fix E) → Tasks 10 ∥ 11 reviews A (Rust crate) and B (fix diff + transcript audit; also confirm Rej1's extended-MLWE assumption) → Task 12 final gate → Task 13 SCaaS testnet reset with image `pqz4` + gas re-calibration (quiet host; `pqzl-rows.py` keys rows by v2: adapted copy that fails on 0 matches). Also pending: post the lazer#28 comment and the D-2/D-3 issue (drafts `scratchpad/lazer28-comment-draft.md`, `scratchpad/lazer-d2d3-issue-draft.md`, owner approval first). Report D is closed (D-2 / D-3 fixed in Task 4); reports A–C's open findings are in Tasks 5b–5e.
- [ ] **PQZL Rust port follow-ups — placed (2026-10-19 evening) in the fs3 plan: items 1, 2, 4 in Task 13 (roll-out, spec wording, M = 16 rows), item 5 (minors) in Task 5e, item 3 (wasm32 limb path) as Task 14 on its own branch after Task 13. (port merged 2026-10-19 `5952951`; plan `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`, ledger `.superpowers/sdd/2026-10-17-pqzl-rust-port/progress.md` on the branch)**: (1) **roll-out on the SCaaS testnet**: build the Rust-backed `Nethermind.Pqz` image (pqz-ffi default feature `pqzl-rust`), RUNBOOK steps as P6f, and **re-calibrate the PQZ gas rows with the calib image on the chain host before or with the image switch** (CTR-PQZ-09 controller proposal 2026-10-19, owner may override: live rows kept until then; Rust is faster on every PQZL row, Transfer p50 6.48 vs 8.34 ms = −22 %, over the 15 % rule of CTR-PQZ-10 but in the safe direction); (2) at the roll-out, update pq-zero-knowledge.md (lines ~1293 / 1320 / 1504: the C core named as the production core) to the Rust crate; (3) **wasm32 limb path in `pqzl/rust/src/arith/ntt.rs`**: wasm32 `verify_fast` is 1.7–2.0× slower than C (u128 64×64→128 multiplies; C uses 21-bit limbs), R_TXM8 p99 51.0 ms vs the 60 ms limit (~15 % margin), D6 `pqz-core/pqzl/rust/runs/d6/results-d6.md`; (4) M = 16 Rust rows (`--multi-bench`); (5) deferred minors: Rust heap check in `verify_only` (review C-M5), no end-to-end pqz-ffi OOM test and no test for the fallible `Ctx` allocation in `ffi/src/pqzl/rust.rs` (needs a pqz-ffi test hook), panic-path test, exhaustive logs echo `PQZL_MEM_*`, gate PASS line file, two-limb S3 oracle.
- [ ] **Zether BLS12-381 verifier precompile in Rust (owner 2026-10-17; after the PQZL Rust port)**: a full verifier precompile for the BLS12-381 Zether proofs (Σ-protocol + the two Bulletproofs, `proofSystemId` `…/bls12-381/n64-n64/v2`, zether.md §3) in the `Nethermind.Pqz` plugin (pattern of `pqz-ffi`: Rust cdylib + P/Invoke), for the SCaaS testnet / 22776. **Chains with the precompile use it; chains without it keep the Solidity verifier** (`ZetherVerifier` BLS12-381 over EIP-2537): same statement, proof bytes and verdict, so a token's verifier is chosen per chain (a precompile-backed verifier contract behind the same interface, gated like `PqzSafety`: chain allowlist + self-test). Controller notes (owner may override): verdict parity with the Solidity verifier pinned by a differential test and the Zether vectors; reuse `clients/zether-prover`'s Rust verify code; gas priced from measured native time (estimate [not measured]: transfer ≈ 1.2–2 M vs ≈ 3.6–4.0 M today, M = 8 under the 2^24 cap); bn254 stays Solidity-only. **Build option (owner 2026-10-17):** `Nethermind.Pqz` / its Rust library include the Zether BLS12-381 verifier precompile only when built with an explicit option (Cargo feature + MSBuild property, image build argument), **default: not included**. Controller note: activation stays per chain in the chainspec; a node built without the option refuses to start on a chainspec that activates it (as `PQZ-REFUSE`), so nodes never disagree on a block. Status: recorded, not scheduled before the PQZL Rust port.

- [x] **Research note: Soroban, NEAR and Algorand storage and candidate families (done 2026-10-19: `docs/research/near-algorand.md`, Solana costs in `networks/solana.md` §2.1) (owner 2026-10-19; research only, no PQZ measurement)** — `docs/research/near-algorand.md` (also covers Soroban's long-term balance storage and its cost), facts checked against official docs: account model and keys (NEAR named / implicit / ETH-implicit accounts, access keys; Algorand addresses, native multisig, rekeying, LogicSig), contract VM and limits (NEAR wasm, gas per transaction, memory, transaction size, async promises; Algorand AVM opcode budget and pooling, argument / group limits, boxes), token model and holder lists (NEP-141 + storage deposit; ASA opt-in vs ARC-200 box ledgers), storage cost and persistence (storage staking; minimum balance requirement; no TTL), meta-transactions (NEP-366 delegate actions; fee pooling), crypto available for the UA kinds (ed25519, secp256k1, P-256, BN254, BLS12-381), how UA, `msig` and balances of non-native users would be stored, PQZ / Zether feasibility by reasoning only; a comparison with Solana and the existing families. Then the owner decides on adding either family.

- [ ] **ERC-7674 temporary approvals on SCaaS tokens (owner 2026-10-18)**: add `temporaryApprove(spender, value)` (allowance in transient storage, EIP-1153, cleared at the end of the transaction; contract callers only, as `approve`) to the token base, with `transferFrom` reading the transient allowance first; the DEX and other SCaaS contracts use it on SCaaS tokens instead of approve + `approve(spender, 0)` (≈ 100 gas TSTORE instead of SSTORE writes); outside tokens keep approve + revoke. Spec in token-wrappers.md / metatx.md, forge tests, size impact; timing after P6.
- [ ] **Rename token family (owner 2026-10-13, after P6; owner 2026-10-19: moved earlier — right after the five PQZL Rust port follow-ups, before P6h / P6i / P6j / P6-PUB)**: `UnderlyingToken` → `WrappedToken`, `NoUnderlyingToken` → `NormalToken` (owner 2026-10-18; first chosen `IssuedToken` 2026-10-13, dropped as an awkward name), as one rename of the whole family: `UnderlyingZetherToken` / `NoUnderlyingZetherToken`, `UnderlyingLib`, `IUnderlyingToken`, and the `TokenKind` names (`NONE` → `NORMAL`, `UNDERLYING` → `WRAPPED`, and the `_ZETHER` / `_PQZ` / `_ZETHER_PQZ` variants). Enum numbers, ABI encoding, vectors and storage stay the same (names only; all chains are test-only, no migration). Keep the ERC-4626-style `underlying()` function names. Not "NativeToken" (clashes with the native coin and the UA "native address"). `legacy/` and `docs/history/` stay as they are; old names go to `docs/history/dropped-artifacts.tsv`. Scope measured 2026-10-13: ≈ 67 files in `smartcontracts/evm`, ≈ 40 docs, `scripts/size_gate.py`, one node test.
- **Owner 2026-10-14 (session 4): fee = 0 is accepted for both classical Zether and PQZ** (already the rule: the fee is credited / debited only when non-zero — `zether.md` §ElGamal flow, `ZetherLib.sol:600/612`, `pq-zero-knowledge.md` `plainPending[ben] += fee if fee > 0`; `multiLegFee` default 0). Vectors and tests must carry fee = 0 cases for every transfer form (P6e Task 11, P6-ANON S2/S4).
- **Owner 2026-10-15: PQZ = Post-Quantum Zero-knowledge** (the proof engine; the Zether-model token is its first application; "PQ Zether" is the historical name). Code / opTags / ids keep `pqz`. Spec file `docs/contracts/pq-zero-knowledge.md` → `docs/contracts/pq-zero-knowledge.md` in the layout move (status: name meaning recorded now in spec title, pqz-core README, decisions CTR-PQZ-01; file rename pending). Publication wording: "a post-quantum zero-knowledge proof engine — first application: Zether-style confidential tokens".
- **Owner 2026-10-15: pqz-core layout approved** (`docs/superpowers/plans/2026-10-15-pqz-core-layout.md`) with `research/` instead of `bench/`: `pqzl/`, `pqzh/{ligero,xcheck,stark-backup}`, `stmt/` `ffi/` at the top, `research/{rel3,opt,floor,upstream}`, `artifact/ glic/ fuzz/`; `git mv` only (history kept, nothing deleted); after the four WIP branches merge, before gates A / B. Status: approved, not executed. **Owner 2026-10-16: timing** — after S5 (fuzz) merges and before S6's Docker run: S5 merge → layout move + spec rename (`git mv` only, paths in scripts / docs / Dockerfile fixed) → S6 rebased onto the new layout, then its Docker run (validates the new layout; `expected-results.json` regenerated once) → S8 → S7 → gates A / B. **Owner 2026-10-16 (same day):** S6 postponed entirely until after the layout move — its code is written against the new layout (no rebase); the phase-1 agent stopped with a WIP commit on `p6-anon-s6`. **Owner 2026-10-16: PQZL → Rust port plan** — plan only (no code): port pqz-core PQZL (C core + LaZer subset) to Rust so other chains / applications can use LaZer; the C core may later not need maintaining. Write the plan AFTER the layout move (new paths). Status: plan written 2026-10-17 (`docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`, branch `pqzl-rust-plan`, D1–D8 controller proposals), approved by the owner 2026-10-17 (D1–D8 as proposed; execution subagent-driven), merged; execution after the freeze. Owner rulings (same day): (1) the Rust crate is for any third party (not only chains), licence = the repository's Vegan Community License 1.0 (LaZer's MIT notice still travels with the LaZer-derived code: NOTICE + lazer/LICENSE); (2) C vs Rust as the production PQZL is decided later — whichever is chosen, the other gets less maintenance (kept, not deleted). (3) Location (owner 2026-10-17): the Rust crate lives in `pqz-core/pqzl/rust/` (crate name `pqzl`), beside the C core under `pqzl/` — as `pqzh/ligero/` under `pqzh/`; it shares `pqzl/params/`, `pqzl/kat/` and the vectors. **Order (owner 2026-10-16):** S5 → layout move → S6 in parallel with writing the port plan (docs only) → S8 → S7 → gates A / B → freeze → the port itself, checked byte-for-byte against the C core on the frozen vectors / KAT / self-test / fuzz; the artifact later gains a "Rust = C" stage (no re-run of the existing stages).
- **Owner 2026-10-15: the SCaaS testnet is the TESTNET — its data may be reset; chain 22776 will be the MAINNET (not built yet).** Consequences (controller): P6f may bring the precompiles to the SCaaS testnet with a fresh genesis that carries `engine.Pqz` from block 0 instead of a transition on the old data (backups still taken); 22776 gets the precompiles only after the production gates (cryptographic audit, G-LIC clearance), and from its launch the "all chains are test-only, redeploy, no migration" rule no longer holds for 22776.
- **Owner 2026-10-16 ("(a), đồng ý các đề xuất, merge p6f; 7622 là testnet, toàn quyền reset; Tăng arena verify của node lên 512"): P6f DONE and LIVE on the SCaaS testnet.** Merged `a243650`; Task 10 path B run by the controller: SCaaS testnet reset from the backup-kept genesis with `engine.Pqz` from block 0, image `scaas/nethermind-pqz:1.39.0-pqz1`, PQZ-START ok, probes + e2e pass (`pqz-core/nethermind/runs/2026-10-16-live.txt`). All five P6f proposals accepted (decisions.md CTR-PQZ-10 Change 2026-10-16). Gas limit ramps to 80 M by itself (~2 h); hourly `watch.sh` check is manual. Follower + public RPC, restart policy, deleting backups: owner. L-3: node verify arena 512 MiB when op 7 lands in pqz-ffi (S3).
- [x] **UA Registry: on-chain index of UAs per kind, for wallet decoy selection in PQZ and classical Zether (owner 2026-10-17; right after S8)**. Why on chain: logs can be pruned / expire on a long-running chain (EIP-4444), state cannot; a UA serves many tokens and purposes, so the index lives in the registry, not in a token; how a wallet reads the list (all, ranges, random) is the wallet's decision. Design (controller proposal, owner may override): `_uaCount[kind]`, `_uaAt[kind][i] = ua` with `i` assigned by the registry (`count` at registration, then `count++`), the UA's own index as `uint40 index` in `Record` (its slot has 40 free bits: no extra slot); views `uaCount(kind)`, `uaAt(kind, i)`, `uaPage(kind, start, n) → bytes32[]`, `uaIndex(ua)` (names: controller proposal); cost ≈ +27k gas per registration (one new slot 22,100 + the counter 5,000; 22,100 for a kind's first registration). Single-key kinds only (PQZ, Zether bn254 / BLS12-381, the signing kinds); structures (`msig`) are not indexed (they cannot be decoys). Deployment: the registry exists only on the SCaaS testnet (P6g, gen 1) and in local tests, all test-only (owner: the SCaaS testnet may be reset) ⇒ change the code and redeploy, no second generation needed. The gen-2 rule matters only after mainnet 22776, where a deployed registry is never replaced: there each single-key kind lives in exactly one generation (gen 2's constructor refuses a kind whose keyHash group gen 1 enables) and gen 2 forwards these views for gen 1's kinds, as `kindOf` does. forge tests + vectors, accounts.md. Wallet side (P6h): decoys from `kindPage` of the token's kind (same system / curve), prefer recently active UAs, skip UAs whose pending queue is near `K_MAX` (1,024; PQZH ≤ 10 inline credits). Status: BUILT 2026-10-17 (CTR-UA-29; 1272 forge tests pass) and deployed on the SCaaS testnet (registry `0x4d2e7dbb…`, factory `0xf8466c6a…`; e2e 92 ok). The P6g deployment of 2026-10-16 stays on chain unused.
- **License (owner 2026-10-17, Vegan Community License 1.0, version unchanged):** exclusions per company (not per group), revenue threshold USD 10 M per company, a vegan company free whatever its revenue or group; at any scale: killing, food service with prohibited products, silk / leather / fur goods (new or second-hand), processing / manufacturing or financing prohibited products or killing, selling / transporting live animals for slaughter, human-derived products; below 10% of the company's own revenue allowed: selling, distributing, marketing, transporting prohibited products (owner: these four may change later); secondary general-purpose services (blockchain, node, relayer, hosting, payment) not excluded because a user is. Commits `4601454`…`7032fd8`.

- **Next (2026-10-19, PQZL Rust port merged `5952951`):** the Rust crate `pqzl` is the production PQZL core (pqz-ffi default); gate fin PASS with step `rust`; next the Rust port follow-ups (roll-out on the SCaaS testnet with gas re-calibration) then the token-family rename (`NormalToken` / `WrappedToken`; owner 2026-10-19: before the rest of P6), then the rest of P6 (P6h clients and WASM, P6i node, P6j review, P6-PUB).
- ~~**Next (2026-10-17, S7 done):** S7 merged (spec CTR-PQZ-25 / -26); UA kind `secp256k1` 0x0108 and CTR-UA-06 (every derived kind on every chain, owner 2026-10-17), registry redeployed on the SCaaS testnet; next op 7 entry points in the PQZ tokens → gates A / B → freeze → Rust port.~~
- ~~**Next (2026-10-17, UA index done):** UA registry per-kind list merged `b1fbd08` and redeployed on the SCaaS testnet; next S7 → op 7 in the PQZ tokens → gates A / B → freeze → Rust port (resume notes in HANDOFF.md).~~
- ~~**Next (2026-10-17, S8 done):** op 7 live on the SCaaS testnet (S8 merged `63e672f`); next the UA Registry per-kind index (owner: right after S8) → S7 → op 7 in P6g tokens → gates A / B → freeze → Rust port (resume notes in HANDOFF.md).~~ done 2026-10-17.
- ~~**Next (2026-10-17, S6 done):** S6 merged (op 7 in the package; Docker quick + multi-bench PASS); Rust port plan merged; next S8 → S7 → op 7 in P6g tokens → gates A / B → freeze (resume notes in HANDOFF.md).~~ done 2026-10-17.
- ~~**Next (2026-10-17, morning):** layout move + spec rename merged `9f07324`; next S6 (on the new layout) in parallel with the PQZL → Rust port plan, then S8 → S7 → gates A / B (resume notes in HANDOFF.md).~~ done 2026-10-17.
- ~~**Next (2026-10-17):** S5 merged `b547e3d` (2 h per target with op 7, no finding); next the pqz-core layout move + spec rename, then S6 (+ Rust port plan) → S8 → S7 → gates A / B (resume notes in HANDOFF.md).~~ done 2026-10-17.
- ~~**Next (2026-10-16 second shutdown):** S3, S4, S9 and P6g merged + pushed; `fix-ligero-oog` in flight; next S5 → S6 → S8 → S7 (resume notes in HANDOFF.md).~~ done 2026-10-17 (S5 merged).
- ~~**Next (2026-10-16 shutdown):** P6-ANON S3 (branch `p6-anon-s3`) and P6g (branch `p6g`, plan to write) were dispatched and stopped after reading only; resume notes in HANDOFF.md. After power-on start the SCaaS testnet node (`docker compose up -d blockchain-node`, no restart policy).~~ done 2026-10-16.
- [ ] **P6f live on the SCaaS testnet (owner 2026-10-14, session 4): build the PQZ precompile (both PQZL and PQZH via `pqz-ffi`) and the ML-DSA precompile into Nethermind and RUN IT FOR REAL on the SCaaS testnet** (`/home/dockers/mba-chain-nethermind`, chainId 0x1dc6, single node, Nethermind 1.39.0, currently stopped). This replaces the roadmap's "every change to the SCaaS testnet is the owner's" for this step (owner grant). Controller procedure (proposal, owner may override): (1) test on a throwaway copy of the SCaaS testnet first (pq-zero-knowledge.md §10 steps); (2) back up `data/`, `genesis.json`, `config.json`, `docker-compose.yml` (timestamped, as the existing `*.bak-*` files) before touching the live chain; (3) image `scaas/nethermind-pqz:<v>` built locally (never pushed), chainspec transition for the precompiles, gas / `TxPool.MaxTxSize` / block limits sized for the 393,216 B PQZH input; (4) start, run the self-test (`OP_SELFTEST`) and the PQZ e2e through the precompile on the live chain; (5) rollback = restore the backup. All chains are test-only (no migration). Chain 22776 genesis stays an owner step.
- [ ] **P6-PUB drafts (owner 2026-10-14, session 4): after P6 (incl. the precompiles running live on the SCaaS testnet) and P6-ANON are done, prepare the documents for the owner to post on ePrint and ethresear.ch** (the owner posts; the controller drafts). Controller proposals (owner may override): drafts kept private in `scratchpad/pub/` (git-ignored) until the owner posts, then the final versions are committed; ePrint as LaTeX (paper + appendix of parameters / soundness / measurements, citing the frozen package), ethresear.ch as Markdown (shorter, results-first); scope: PQZL headline numbers (frozen run) plus PQZH-Ligero as the second proof system and the multi-recipient transfer (receiver hiding) as an optional extension, with the tbox / ℓ2 / z21 findings referenced through the public lazer issues only; the results mail to the LaZer maintainers (`scratchpad/sz-private/results-letter-lazer.md`) goes before posting, as ruled 2026-10-13.
- [ ] **P6-PUB publish PQZL** (owner 2026-10-13): both an ethresear.ch post and an ePrint paper. Numbers are frozen only after the z21 fix (lazer#26, branch `pqz-z21`) is merged (merged 2026-10-14 `a8b5b66`; owner 2026-10-14: package first, then the freeze through `reproduce.sh --full`; package WIP on branch `pqz-artifact`, not tested in Docker, no freeze yet — see HANDOFF; owner 2026-10-14 session 4: no CI workflow for now (readers reproduce locally; decide again after the freeze); image build + quick / `--upstream` / `--serve` tests started, freeze not yet). Reproducibility package `pqz-core/artifact/`, SOURCE ONLY (owner: no built binaries on GitHub — no release assets, no hosted wasm, no pushed image): a pinned `Dockerfile` (docker build + run on the reader's machine), `reproduce.sh` for a local toolchain (KAT, `check_tbox_fixes.sh`, `check_sv_fixes.sh`, differential, the five relations generic + SV, native + wasm; Markdown + JSON tables against an expected-results file: `proofs_fnv` exact, sizes / ratios within tolerance, times informational), `--serve` for a local browser demo, `--upstream` to build upstream LaZer from source for the comparison; a source tag + Zenodo source snapshot (DOI); CI stores text / JSON results only. G-LIC is not a prerequisite of publication (it gates production / commercial use, pq-zero-knowledge.md); the package keeps the licence notices (`pqz-core/NOTICE`: LaZer MIT in the fork, HEXL notice if any code is retained) and builds upstream LaZer with GMP / MPFR only from source inside Docker. ~~PQZL only — no PQZH in the package (owner 2026-10-13).~~ **Superseded (owner 2026-10-14, session 4): the Docker package covers BOTH PQZL and PQZH (Ligero)** — PQZH tests, mutations, native + wasm32 bench (gate-B method), C cross-check, `pqz-ffi` (both ids) and the vectors `--check` in `reproduce.sh` and `expected-results.json` (status: in progress, branch `pqz-artifact2`); the publication text scope (PQZL) is unchanged unless the owner says otherwise. Headline line (owner 2026-10-13), added only after the z21 merge with re-measured numbers (rerun `v2full` + the SV bench): what PQZL achieves — `R_TX` proof size, prove native / wasm, specialised-verifier p50 / p99 (portable, x86-64-v3, wasm), wasm prove memory, the 128-bit target, reference machine, run files — a short PQZ subsection in the root README §11 (owner 2026-10-13: what PQZ is, PQZL vs PQZH as one `proofSystemId`, the measured PQZL headline numbers, (no LaZer-findings text in the README, owner), status: core library measured, precompile / contracts not built yet, links to the notes; also correct the §11 table's PQ Zether status and gas rows against the measurements), a five-relation table in `pqz-core/README.md`, and the opening line of the posts; not in pq-zero-knowledge.md (spec, not results). Also after the z21 merge (owner 2026-10-13): the owner sends the LaZer maintainers a separate mail sharing these results and offering a draft for review before posting (private draft kept by the controller), separate from the G-LIC patent question.
- [ ] **P6-ANON identity hiding (research only)** (owner 2026-10-14: estimate, no code): `docs/research/pqz-anonymity.md` — ring anonymity in the Anonymous Zether paradigm (Lether, ePrint 2026/076) practical at N ≈ 8 under `MAX_INPUT` / the 16.78 M tx cap (≈ 10–12 M gas, proof ≈ 50–56 KB, estimates), or one-time receiver accounts (receiver only). Next: read Lether in full (ring size, tags, refresh), size with the codegen; owner decides whether to pursue. Not part of P6. ~~Owner 2026-10-14: build it as an optional, prepared feature that is NOT enabled by default~~ (superseded the same day: SCaaS uses it, see below). **Fuzzing merged 2026-10-15 (P6e Task 10, `32e7ad3`): ≈ 3.2 M inputs, no finding; controller decision: add a malloc-path (`PQZ_DEBUG_MALLOC`) sanitizer variant later so ASan sees inside the arena (status: open, not scheduled).** **S1 + S2 merged 2026-10-15** (op 7 `R_TXM` in `pqz-stmt` / `pqz_kat.py`, groups of 4, finding 8: the hint shortcut is conservative after the q-vector step). Controller decision (owner may override): PQZH M = 4 with the auditor is kept — `5 + 132,992 + MAX_PROOF` overshoots `MAX_INPUT` by 1,925 B only if the proof exceeds 260,219 B; Track H measures Ligero's exact maximum for that shape (`R_TX` is 235,470 B) and the shape is dropped if it exceeds 260,219 B. **Owner 2026-10-15: accept β 446 (not 450) for the shared-randomness hints of R_TXM** — 4 legs + auditor = 80 hints on one (r_g, e1_g) gives β 446.0 (core-SVP 2^130.2 classical / 2^118.2 quantum), still above Kyber-512 (β 406, 2^118.6 / 2^107.6); so groups of 4 legs with or without the auditor (D4 as originally planned), PQZH M = 4 with the auditor allowed again, PQZL M = 8 in 2 groups. CTR-PQZ-03's β ≥ 450 stays for every other instance (encryption without hints 476, single-recipient R_TX 463.9, PQZL proof MSIS 452–464). The controller decisions below on 3-leg groups and PQZH M = 4 auditor-off are superseded. Earlier: **S1 finding 2026-10-15 (branch `p6-anon-s`): D4 was wrong — 4 legs + auditor = 80 hints on one (r, e1) gives β 446.0 (< 450); corrected group size 3 legs with the auditor / 4 without (β 451.9). Controller decisions (owner may override): PQZH M = 4 is built auditor-OFF only (with the auditor PQZH M ≤ 2; no lower security target, no limit raise per D20); op-7 gas keyed by the (M, auditorOn) header words, not by length (83,072 B is both M=1+auditor and M=2 no auditor).** **Plan merged `e5c919d` (`docs/superpowers/plans/2026-10-14-p6-anon.md`); owner rulings 2026-10-14: D21 freeze once after op 7 (gate A/B and P6-PUB wait for R_TXM), D20 no limit raise (PQZL M ≤ 8, PQZH M ≤ 4), D16/D17 no on-chain decoy rule (optional `multiLegFee`, default 0). Implementation started (S1 + S2).** **Owner accepted 2026-10-14: sender visible, ONE proof per transfer (R_TXM), and the PQZ precompile verifies it too (both PQZL and PQZH, live on the SCaaS testnet with P6f). Owner changed the decision 2026-10-14: SCaaS USES it (replaces the earlier "prepared but unused"); it is part of P6 (in the frozen set before gate A / the P6-PUB freeze). Controller proposal (owner may override): as classical Z7, R_TXM is THE PQZ transfer in every PQZ token (M ≥ 1), decoys are a wallet choice; ~~whether R_TX / R_TX0 stay as the M = 1 fast path is decided by measurement~~ — owner 2026-10-14: keep BOTH paths as classical Z7 + Z8: one proof for many recipients (R_TXM) AND the existing single-recipient transfers R_TX / R_TX0 unchanged (many separate transfers, each its own proof and nonce). Batching several PQZ proofs under one meta-tx nonce stays forbidden (`MtxNotBatchable`) unless the owner rules otherwise.** **Reframed 2026-10-14: 2A′ = the PQZ multi-recipient transfer** (one transfer, M legs, one proof, decoys get Enc(0)), i.e. the classical Zether multi-recipient design the owner accepted on 2026-10-08 (`docs/history/specs/2026-10-08-zether-multi-recipient-design.md`, Z1–Z13, CTR-ZTH-37…43) carried over to PQZ, which `pq-zero-knowledge.md` had left unruled; versus M separate transfers it needs one proof, one debit, shared `u` (CTR-PQZ-04). **Final scope (owner 2026-10-14): build ONLY mode 2A′, the receiver-only ring** (sender public and debited as today; credit to one of N candidates, decoys get Enc(0) into `pending`; no epoch, no tag, no receiver scanning) **for both PQZL and PQZH (Ligero)** — prepared and measured to show it works, ready for others, NOT used by SCaaS (off by default). Stealth, sender ring and both-sides ring are described alternatives only. Earlier: **Scope (owner 2026-10-14): the sender may stay visible; only the RECEIVER is hidden** — receiver-only designs: (B) one-time receiver accounts / stealth, (A′) receiver-only ring of N candidates (size / gas table for N = 2, 4, 8, 16 to be put on file; an earlier chat comparison was not saved); no sender ring. First step: read Lether in full, design and plan (both options A ring / B one-time receiver accounts, both proof systems where feasible), then build in reviewed rounds like P6e (status: planning, branch `p6-anon-plan`).
- [ ] **P6-PQZH spike (E-S1H)** (owner 2026-10-13): PQZL (lattice, `pqz-core`) and PQZH (hash-based proof) as two kinds of one PQZ — shared MLWE encryption, state, keys (`pqz-mlwe`), disclosure; only the proof system differs. Spike: `R_TX` / `R_REG` as a STARK circuit (Plonky3 first, Ligero if the mod-q emulation is too costly); measure proof bytes, prove native + wasm, p99 adversarial verify, memory, zero-knowledge mode; then settle the token kinds (eight `*_PQZL` / `*_PQZH` or four + `proofSystemId`) in pq-zero-knowledge.md. Research: `docs/research/pqz-proof-alternatives.md` §6; design study `docs/research/pqzh-design.md` (merged 2026-10-13, `475b066`; counts `pqz-core/pqzh/stark-backup/pqzh_count.py`). Owner 2026-10-13, on the study's six questions: (1) proof limit ≤ 160 KB for the PQZH kind, PQZL keeps 96 KB; (2) measure provable and conjectured soundness in the parameter sweep, leaning provable; (3) PQZH tokens register keys with a PQZH `R_REG` proof; (4) "two kinds" means only PQZL and PQZH: the proof system is one configuration value with two values (`proofSystemId` at `initialize`), the four reserved PQZ `TokenKind`s stay, no eight-kind enum; (5) Keccak / SHAKE transcript, no in-circuit hash (Poseidon2 only if recursion is wanted later); (6) start the prototype now. Prototype: Plonky3 + FRI + Goldilocks + LogUp, design D1, crate `pqz-core/pqzh/`, steps 0–5 of the study (R_REG, then R_TX go / no-go). **Prototype measured 2026-10-13** (`docs/research/pqzh-prototype.md`, branch `pqzh-proto`, not merged): default Goldilocks², blowup 16, 28 queries, arity 8: `R_TX` 141,079 B / `R_REG` 110,388 B (≤ 160 KB), prove 2.57 s native / 4.43 s wasm32, verify 11.0 ms p99 native (15.6 ms wasm32), 0 of 480 mutated inputs accepted; statement and witness bytes identical to pqz-core's `pqz_bench.c`; wasm32 builds unchanged (no imports, 499 KB gzip). Open: (a) soundness — Plonky3's `p3-security` gives the default 100.6 bits conjectured / 71.9 proven (128 only by the old ethSTARK formula); Goldilocks² caps at ≈ 100 bits (opening-batching term), Goldilocks⁵ (now built, `Params::ext5`) reaches 128; **no setting meets 128 bits provable within 160 KB** (`R_TX` ≥ 288,945 B); 128 conjectured within 160 KB only at blowup 32 / 21 queries / 24 grinding bits (160,813 B, 12.4 s prove, 1.17 GB); (b) prover memory 448 MB native / 452 MiB wasm32 for `R_TX` (> 256 MiB); (c) ZK mode ≈ 1.8× bytes, 4× time and memory (`R_TX` 253 KB, 10.3 s, 2 GB; a padding-row bug in ZK mode fixed); (d) `R_TX` layout to follow `pqz-relfix`'s §7.7 header when it merges. Prototype merged 2026-10-13. Owner decisions 2026-10-13 on the note's §10: (1) zero knowledge is required for PQZH (proofs are public; a non-hiding STARK opens evaluations of the witness polynomials — key, encryption randomness, digits — at the query points), so the ZK numbers are the real ones; (2) Goldilocks⁵ is the PQZH challenge field; (3) soundness target (proven vs conjectured) and the PQZH proof limit / precompile `MAX_INPUT` are NOT set yet — first measure the real configuration; (4) PQZH proving may be native-only for now (PQZL covers the browser, `R_TX` wasm 221 MiB); (5) next PQZH step: build and measure ZK + Goldilocks⁵ at 128 bits (proven and conjectured), Merkle caps and a WHIR commitment for proof size (`p3-whir` exists only in Plonky3 0.9.0-rc.1, not in the pinned 0.8.0: a separate branch with the upgrade, hiding WHIR since ZK is required, bits under the Johnson bound — Crites–Stewart ePrint 2025/2046 disproved the up-to-capacity conjectures; order, owner 2026-10-13: after the SV line and the full v2 pqz-core run), and move the Rust `R_TX` statement to relfix's §7.7 header layout (merged `7e6e9b0`) and re-run the C cross-check. PQZL stays the primary proof system; PQZH the second value of `proofSystemId`. **Next step measured 2026-10-14** (`docs/research/pqzh-zk-ext5.md`, branch `pqzh-next`, merged 2026-10-14 with the Plonky3 0.9.0-rc.1 upgrade; pin the final 0.9.0 when released): `R_TX` on the §7.7 layout, C cross-check byte-identical; PQZH proofSystemId proposed `keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1")` (status: proposal); EVM-friendly configuration built as the one configuration (Keccak-256 Merkle over big-endian words, Keccak-256 seed, big-endian proof encoding, `NTT(A)` and selectors preprocessed: default-parameter `R_TX` 143,128 → 143,704 B, prove 2.64 → 4.41 s, verify p99 11.8 → 9.8 ms; kept); ZK + Goldilocks⁵ built: `R_TX` at 128 bits, blowup 16, 16 grinding bits: **conjectured 340,431 B** (worst case ≈ 365 KB), **proven 622,448 B** (≈ 672 KB), prove 20 s, 2.8 GB, verify p99 15.5 / 19.1 ms native, 24.1 / 28.7 ms wasm32, 0 of 960 mutated accepted; blowup 8 halves time and memory (10.4 s, 1.4 GB; 419 / 776 KB); blowup 32 needs ≈ 5.6 GB (over the 4 GB cap); Merkle caps 4 / 6 / 8 make every proof larger (pruned multiproofs already share the top levels); Goldilocks² + ZK caps at 98–101 bits. Plonky3 0.9.0-rc.1 upgrade done as its own commit (no source change). WHIR: does not plug into the uni/batch STARK (multilinear PCS only); the multilinear `p3-multi-stark` takes only non-hiding WHIR and is not ZK — measured without ZK: Goldilocks⁵ Johnson `R_TX` 257,530 B at 125.3 composed bits (≈ 17 % under proven FRI at equal memory), Goldilocks² ≈ 91–95 bits (WHIR fold proximity-gap term and LogUp fingerprint). Open (owner, note §9): soundness regime and proof limit / `MAX_INPUT` (neither regime fits 160 KB or 262,144 B with ZK); prover memory target; the proofSystemId string; a ZK WHIR path (recommended: not now); keep or revert the 0.9.0-rc.1 upgrade. Owner 2026-10-14: PQZH is NOT shelved; next, build and measure (i) a zero-knowledge WHIR path (hiding WHIR commitment plus ZK in the multilinear STARK, or a ZK wrapper around `p3-multi-stark`; Goldilocks⁵ and Goldilocks², Johnson-bound bits) and (ii) a Ligero backend (proof size, prove, p99 verify vs the 50 ms budget, ZK, 128 bits). Still open after those measurements: soundness regime and proof limit / `MAX_INPUT`, prover memory target, the PQZH proofSystemId string, and the backend choice. **2026-10-14 (paused for shutdown, design notes only, nothing built or measured):** ZK WHIR on branch `pqzh-zkwhir` (`9d748ed`, `docs/research/pqzh-zk-whir.md`): Plonky3's ZK batch STARK unchanged plus an adapter implementing `UnivariateStarkPcs` over `p3-whir`'s `HidingWhirPcs` (HVZK WHIR, ePrint 2026/391), 3–5 days + 1–2 days measuring, expected `R_TX` ≈ 400–500 KB at Goldilocks⁵ (estimate); agent's questions: accept this path (no ZK `p3-multi-stark`), build a batched WHIR opening if it lands above FRI+ZK conjectured or settle on FRI, report Goldilocks² only at its reachable 96–100 bits. Ligero on branch `pqzh-ligero` (`11d1493`, `docs/research/pqzh-ligero.md`, model `pqz-core/pqzh/ligero/ligero_params.py`): field F_q itself, challenges in F_q^4, model `R_TX` ≈ 298 KB proven / ≈ 112 KB conjectured at 128 bits with ZK, verify ≈ 15–40 / 3–8 ms (inferred); agent's questions: add a radix-431 FFT stage for longer codes; use its modified ZK construction (blinding rows at full degree inside the proximity test) instead of the paper's §4.7 text. Resume both from §7 of their notes. **Owner decisions 2026-10-14 (session 4), on the agents' questions:** ZK WHIR — accept the chosen path (Plonky3's ZK batch STARK unchanged plus a `UnivariateStarkPcs` adapter over `p3-whir`'s `HidingWhirPcs`; no ZK `p3-multi-stark`); if `R_TX` lands above FRI+ZK conjectured (340,431 B), stop and settle on FRI (no batched multi-round WHIR opening); report Goldilocks² only at its reachable 96–100 bits. Ligero — adopt both proposals: add a radix-431 FFT stage for longer codes, and use the modified ZK construction (blinding rows at full degree inside the proximity test) instead of the paper's §4.7 text. Both builds started 2026-10-14 in parallel with the artifact tests (status: in progress, branches `pqzh-zkwhir`, `pqzh-ligero`).

- [x] **P6-SZ protocol review** (owner 2026-10-13, first): two Schwartz–Zippel soundness findings in LaZer `tbox`, confirmed upstream and public ([lazer#24](https://github.com/lazer-crypto/lazer/issues/24) one challenge pair reused for all λ/2 evaluation accumulators; [lazer#25](https://github.com/lazer-crypto/lazer/issues/25) one domain for all exact-ℓ2 equations, only the sum of block norms checked). **Fix merged 2026-10-13 (`pqz-v2`, owner)**: both fixes under one `proofSystemId` v2 bump (prover, verifier, wasm, vectors), regression check `pqz-core/pqzl/check_tbox_fixes.sh`. Then: research notes (tbox soundness, ℓ2), pq-zero-knowledge.md §4.3 / T5 corrections, `pqz-verifier-floor.md` Caveats, the `pqz-sv` line with both fixes (done, merged `dcf0da3`; see P6-SV), K_MAX revisit. **Publication done 2026-10-13 (owner-approved, branch `pqz-publish`, merged `099039a`)**: research notes `docs/research/pqz-tbox-soundness.md` (lazer#24: 2 independent tests instead of λ = 4, soundness ≈ 2^-84 instead of the stated 2^-127, fix, trace evidence) and `docs/research/pqz-l2-domain.md` (lazer#25: only the sum of block norms checked, PoC table, impact on PQZ before the fix: noise budget broken for attacker-controlled accounts, mint margin 4.1× → ≈ 1.12×, no theft or mint; the β4 / υ shared domain harmless by σ-symmetry), index rows in `docs/research/README.md`; pq-zero-knowledge.md §4.3 states that the budget needs per-block bounds and carries a dated note that v1 did not enforce them, the 4.1× sentence, threat T5 and the §8 v1 → v2 sentence say the same; `docs/decisions.md` Change lines on CTR-PQZ-03 and CTR-PQZ-09; `pqz-verifier-floor.md` Caveats now state both findings and fixes; the v2 harness outputs kept as `pqz-core/research/pqzl-measure/runs/v2full-sz-trace.txt` and `v2full-l2dom.txt`. With that all P6-SZ work is done: fixes merged `5361946`, `proofSystemId` v2 and regression check merged `98695de`, specialised verifier on v2 merged `dcf0da3`, publication on `pqz-publish`. The K_MAX revisit is a separate open item (next line).
- [ ] **Revisit the credit cap `K_MAX`** (owner 2026-10-13: keep `K_MAX = 1024` for now and revisit it later). Context: with both LaZer `tbox` fixes (`proofSystemId` v2) every ℓ2 bound is proven per block, so the worst-case noise over 1024 units is 12.16 M and the margin to the mint threshold (≈ 50.33 M) is 4.1× (pq-zero-knowledge.md §4.3, threat T5); under v1 that margin had fallen to ≈ 1.12× (`docs/research/pqz-l2-domain.md` §5). Nothing to change now. Status: open, not started.
- [x] **P6-Z21 z21 norm gap in LaZer's verifier** (owner 2026-10-13: public issue, fix both verifiers, analyse the PQZ impact, regression from the PoC, fold in the SV hardening). Finding (independent SV review, finding 1): `lnp_quad_verify` / `abdlop_verify` check ‖z1‖², ‖w − γ·w1‖² (the z22 part) and ‖h‖∞ but never bound `z21`, the A2′ part of the opening the proof carries; LNP22 Fig. 18 and the codegen (`Bound_`, `Bound2 = 2·Bound_`, `Bsq`) bound the whole z2 = (z21, z22), and the honest prover rejects on that sum. `pqz_verify_fast` mirrored LaZer, so both PQZ verifiers accepted a cheating `R_REG` proof with ‖z21‖² = 87.3 × Bsq. Upstream: [lazer-crypto/lazer#26](https://github.com/lazer-crypto/lazer/issues/26) (public, filed 2026-10-13). Impact before the fix (`docs/research/pqz-z21-norm.md` §5, `pqz-core/pqzl/params/estimator-z21.txt`, pinned estimator): bounded only by `MAX_PROOF`, z21 lifts the extracted MSIS bound from 2^35.3–2^36.0 to ≈ 2^41; MSIS β of the five relations 452–461 → 286–311 (core-SVP classical 2^132–2^134.6 → 2^83.5–2^90.8), below CTR-PQZ-03's β ≥ 450; no known attack, nothing deployed; key uniqueness, noise budget and no-mint held only at that weaker MSIS level. **Fix done on branch `pqz-z21`, merged 2026-10-14 (`a8b5b66`)**: both verifiers check ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq (`lazer/lnp-quad.c`, `lazer/abdlop.c`, `src/pqz_sv.c`); honest proofs and transcript unchanged; regression in `check_tbox_fixes.sh` (z21_big rejected by both, accepted by the control without the z21 term) and the z21 differential `sv/review/review.sh zdiff` (in `sv/diff.sh`); SV hardening from the review (findings 2, 4–7: transcript buffer sized from log2m with log2m ≤ 42 at setup, `modq` precondition stated, z1bnd guard t·2^(2·log2stdev1) < 2^62, l2 bounds < 2^62 at setup, unknown op returns before touching a table slot); research note, pq-zero-knowledge.md CTR-PQZ-03 dated note, §8 and T2, decisions.md Change lines. Owner 2026-10-14: (a) merge and push `pqz-z21` — done; (b) no `proofSystemId` bump (accepted set only, no transcript change, nothing deployed; note §6.3; decisions.md CTR-PQZ-03); (e) comment on lazer#26 with the LNP22 Fig. 18 condition, the impact numbers and the fix. Still open: (c) review finding 8 (all library state global; the P6f precompile wrapper must serialise every libpqz call) recorded in `pqz-core/STATUS.md` Open for P6f; (d) review finding 3 (β4 i = d − 1 and υ share a challenge domain) stays a note, harmless (`pqz-l2-domain.md` §8). Status: done, merged.
- [ ] **P6-SV specialised PQZL verifier spike** (owner 2026-10-13, after P6-SZ): verify `R_REG` / `R_TX` by evaluating the statement directly instead of LaZer's generic sparse matrices, same transcript and proofs; complete NTT over 30-bit CRT primes, table-based AES (public data) or AES-NI for the JL matrix, vectorised JL fold; floor ≈ 9.1 ms portable / 2.5 ms AVX2 / 12.8 ms wasm against the 50 ms limit; differential tests against the generic verifier on honest and mutated proofs. Spike done 2026-10-13, `docs/research/pqz-specialised-verifier.md` (code branch `pqz-sv`, not merged yet): `R_TX` verify 7.85 ms p50 / ≤ 12.6 ms p99 portable, 4.5 ms x86-64-v3, 11.9 ms wasm (generic 660 ms); `R_REG` 3.97 ms; arena 1.7 MB (was 273 MB); 8,782 differential cases, 0 disagreements. Owner: PQZL not killed. **On v2, all five relations (2026-10-13, branch `pqz-sv-relfix` = `pqz-sv-rel3` + main, merged `dcf0da3`; note §0, runs `pqz-core/pqzl/sv/runs/v2-*`)**: `pqz_sv.c` follows both tbox fixes (λ × M rows; dom + i per ℓ2 equation) and the v2 statements; differential test 4,420 cases (2,710 portable, 1,350 x86-64-v3, 360 wasm) over `R_REG` / `R_TX` / `R_BURN` / `R_DS` / `R_DR`, 0 disagreements; `sv/check_sv_fixes.sh` (either fix reverted in `pqz_sv.c` → every honest proof disagrees) and `check_tbox_fixes.sh` ok; p50 portable `R_TX` 8.00 / `R_BURN` 7.74 / `R_REG` 3.87 / `R_DS` 4.35 / `R_DR` 4.50 ms, worst p99 16.0 ms (`R_TX` wasm), unchanged within noise; tables built per op at first use (≤ 5.2 MB), `SV=0 ./build.sh wasm` leaves the specialised verifier out of the wallet's prover; wasm `R_TX` prover 221.1 MiB. Open: owner review and merge of `pqz-sv-relfix`; independent review of `pqz_sv.c` against `lnp-tbox.c` (status: not started); hand-written AVX2 and a run on the chain host (status: not started, not needed for the 50 ms limit). Owner 2026-10-13: (a) the browser wallet bundle (P6h) builds with `SV=0` (no specialised verifier; the wallet proves, it does not verify), the default build keeps SV for tests and benches; (b) an independent review of `pqz_sv.c` against `lnp-tbox.c` (transcript, challenge derivation incl. both fixes, statement parsing, bounds) before the precompile (P6f) relies on it — started 2026-10-13.
- [x] **P6-PQZH-SOL Solidity verifier gas for PQZH** (owner 2026-10-13: measure, write into research, push): can PQZH run on a chain without the precompile? Measured 2026-10-13, `docs/research/pqzh-solidity-verifier.md` (branch `pqzh-sol`; test-only `smartcontracts/evm/test/pqzh/`, model `pqz-core/pqzh/stark-backup/sol/`): a Solidity FRI verifier skeleton (Merkle + proof of work enforced) costs 9.8 M for `R_TX` at the prototype default (Goldilocks², ≈ 100 bits) as written, 15.0 M conjectured / 21.4 M proven at Goldilocks⁵ 128 bits [estimate from measured units]; a hand-scheduled verifier ≈ 1.4–6 M (opcode floor). Calldata decides: with EIP-7623, `R_TX` proven + ZK (506 KB) is 21.4 M of calldata floor alone, over the 16,777,216 cap whoever writes the verifier; conjectured + ZK (12.5 M) and proven without ZK (12.3 M) fit only with a tuned verifier; straightforward code fits `R_REG` / `R_BURN` / `R_DS` / `R_DR` conjectured without ZK. Conditions: an EVM variant (Keccak-256 Merkle + Keccak-256 transcript seed — SHAKE256 of the statement in Solidity is 43.3 M against 49 k for the opcode —, big-endian bytes, `NTT(A)` preprocessed, statement bound by a Horner fingerprint). Open (note §9): which chains need it, one `proofSystemId` for both paths, a tuned Yul verifier to replace the floor estimate. Merged `be81b7c`. **Owner 2026-10-14 session 4, after the StarkEx study (`docs/research/pqzh-starkex-verifier.md`, merged `72ea3a5`: StarkWare splits verification over ≈ 12 txs with a fact registry, 7.23 M gas per proof, but at ≈ 80-bit conjectured soundness and no ZK; a StarkEx-style split FRI+ZK proven verifier would fit ≈ 21.4 M gas over 4 txs, Ligero would not, 19 txs / 319 M): **do NOT build PQZH for chains without the precompile** — PQZH runs only where the PQZ precompile exists (SCaaS testnet / 22776). Status: closed (no work planned).** **Ligero measured and merged 2026-10-14 (branch `pqzh-ligero`; `docs/research/pqzh-ligero.md`; crate `pqz-core/pqzh/ligero/`): PQZH backend = Ligero over F_q, PROVEN regime (owner), radix-431 preset n = 32,756, k = 817, t = 121: `R_TX` 230,392 B (max 243,150 B), `R_REG` 186,970 B (max 198,138 B), prove 0.67 s / 43 MB, verify p99 10.5 ms native / 55.9 ms wasm32 (passes the 60 ms limit), 0 accepted of every mutation set, C cross-check byte-identical. Johnson-bound preset measured as reference only (`R_TX` 257,592 B, wasm32 p99 60.3 ms; its 128 bits need the BCIKS20 error counted once and an unverified mutual-correlated-agreement property, note §5.3). EVM without the precompile (owner rule: use it if it fits) — full test-only Solidity/Yul verifier (`smartcontracts/evm/test/pqzh/ligero/`, real proofs, 0 of 648 mutated accepted): proven `R_TX` 534.6 M gas per transaction (31.9× the 16,777,216 cap; ≈ 124 M even at the opcode floor), conjectured 179 M, no tuning or parameter choice fits (`evm_model.py`) → **PQZH needs the precompile; PQZL has no Solidity verifier either (CTR-PQZ-09), so on chains without the precompile there is no PQZ until a small-verifier design (proof system with a small verifier, or recursion) is funded (owner may reopen)**. Controller proposals (owner may override): PQZH proof limit 256 KB (proven max 243,150 B fits) with precompile `MAX_INPUT` 393,216 B (statement + proof, P6e D5); PQZH `proofSystemId` = `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")` (P6e D3); the Plonky3 STARK crate stays as backup, never linked (D11). Owner step before production: external review of the Ligero ZK argument (note §4.1) with the cryptographic audit. **ZK WHIR measured 2026-10-14 (branch `pqzh-zkwhir`, merged; `docs/research/pqzh-zk-whir.md`): `WhirUniPcs` adapter over `HidingWhirPcs` built and tested (0 of 1,440 native / 240 wasm32 mutated accepted); `R_TX` 1,948,901 B at Goldilocks⁵ Johnson 128 (124.2 composed bits), prove 206 s, 2.42 GB, verify p99 46.5 ms native / 93.5 ms wasm32 — each opening carries ≈ 360 KB of fixed masked-base-case ZK cost; Goldilocks² gives no meaningful bound (shared-γ round ≤ 27.5 bits). Owner's stop rule triggered: no batched opening, WHIR line closed as a negative result (code kept as backup, PQZH configuration unchanged).** **Owner 2026-10-14 session 4: PQZH soundness regime = PROVEN** (Ligero unique-decoding analysis, Thm 4.7: radix-431 preset n = 32,756, k = 817, t = 121, `R_TX` 230,392 B / `R_REG` 186,970 B with ZK at 128 bits); conjectured (92 KB, rests on the up-to-capacity conjecture disproved in general, Crites–Stewart 2025/2046) is not used; a Johnson-bound preset is measured and documented as reference only (status: in progress, branch `pqzh-ligero`). Consequence (controller proposal, owner may override): PQZH proof limit 160 KB → 256 KB, precompile `MAX_INPUT` 262,144 B. **Owner 2026-10-14 session 4: verify limit raised 50 → 60 ms p99 (chain host, also bounds wasm32), so Ligero passes (wasm32 `R_TX` proven 55.9 ms); CTR-PQZ-09 + decisions.md updated.** **Correction, owner 2026-10-14 session 4: ruling (1) below is withdrawn — if PQZH fits the limits without the precompile (EVM verifier gas + EIP-7623 calldata under the 16,777,216 tx cap), it is used on such chains; measure a Solidity verifier for the Ligero backend (status: in progress, branch `pqzh-ligero`).** Owner 2026-10-13 on the note's open questions: (1) no chain needs PQZH without the precompile today (SCaaS testnet / 22776 get it in P6f): record the result, build no Solidity PQZH verifier; (2) adopt the EVM-friendly choices in the one PQZH configuration (`proofSystemId`) in the next PQZH step: Keccak-256 Merkle tree, Keccak-256 transcript seed instead of SHAKE256 (amends the earlier "Keccak / SHAKE transcript" decision; still the Keccak family), big-endian field elements, `NTT(A)` in a preprocessed tree; (3) no hand-written Yul verifier to measure the floor for now.
- [x] **P6-REL PQZ relation fix-ups** (owner 2026-10-13, on `pqz-relations-burn-disclose.md` §5): burn / refresh randomness fresh (CTR-PQZ-19), R_TX on the §7.7 layout, disclosure `kind` a 32-byte word, precompile checks opTag / proofSystemId, e′ ∈ [−2^24, 2^24), lazy per-op keys. Done 2026-10-13, merged `7e6e9b0` (run f2: KAT 19/19, fails 0, native = wasm proofs; arena −38…60 MB per op, wasm R_TX 221 MiB; numbers in `pqz-relations-burn-disclose.md`).

**P1 start checklist (owner decisions 2026-10-08):**
- [x] Keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before P1, and copy the v1/v2 token
      sources and the old `ZetherToken` to `smartcontracts/evm/legacy/` (not built, not tested; a README says "reference only").
- [ ] P1 refactors in place (`git mv` + edit), not a rewrite. Reuse map: `MetaTxCore` → `MetaTxBase`/`ERC20MetaTx`;
      `MetaTokenBase` pay → `PayLib` (not built: pay is inline behind `PAYABLE`, controller ruling pending the owner); `Single`+`Multi` → `UnderlyingLib`/`UnderlyingToken`; `HederaV2Lib` → `HederaLib`;
      `ZetherToken` → `ZetherLib`/`ZetherLayer` (P3); tests ported. `TradeLib` (P2) reuses the owner's prototype
      `/home/ha/work/blockchain/metatx/contracts` (`MtxTradeOrderLib`, `ERC1776Tradeable.mtxTradeOrder`,
      `ERC1776Dex.mtxTrade`) and the `OP_TRADE` legs of `MetaToken`/`MetaTokenBase`/`MetaTxDex` (the v1 ones are in `legacy/p5/`).

**P1 — MT-1…MT-4**
- P1 is split into five plans, written one at a time: **P1a** (MetaTxBase, SigCheck, SaltedEIP712, tag + legacy) — **done 2026-10-09**, merged `1d51d22` (712 tests); plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`; **P1b** ERC20MetaTx — **done 2026-10-10** merged `fb2a234` (758 tests); **P1c** MetaTokenBase + AdminLib/HederaLib + kind NONE (no `PayLib`, C3) — **done 2026-10-10**, merged `3a43c2e` (792 tests); **P1d** UnderlyingLib + UnderlyingToken (1–8 legs, native leg, roles) — **done 2026-10-11**, merged `d03d894` (814 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`; **P1e** `OpenFactory` (`createToken`/`TokenConfig`), CREATE2 deployer + `chainUid()` gate, size gate (ratchet), v1 renamed `…V1`, factory v2 backed up — **done 2026-10-11**, merged `e433bf5` (819 tests, e2e 4/4 + e2e_hedera 1/1); plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except the partial item MT-4 (other domains) and the parked items below (MT-1/MT-3's v1 part closed in P5: the v1 line is in `legacy/p5/`).
- Asset-suite wording follow-up (P1c final re-review): `asset-suite.md` ~791/793/794/854/906 still say "minter renounced" as the precondition for bond redemption and splits; since P1c the rule is "`MINTABLE` disabled (`disableFeature`)" — `renounceRole` alone leaves the flag set and still yields `MinterLive` (fails closed). Reword when the asset-suite stream starts.
- P1b notes (2026-10-10: all done in P1b except (c), done in P5 (the node's ERC-1271 gas floor 432,349), and (g), deliberately not done; (d) done on bamboo-dms branch `scaas-metatx-v1-kat`, owner merges): (a) `MetaTxBase` alone is ≈ 9.4 KB on the mock — watch the 20,480 B token budget; (b) pin 'every allowlisted function is nonReentrant' without the mock's `poke` forwarder — resolved in P1a final review: `_selfCall` requires ticket 2; (c) relayer gas estimate for SubjectAccount/SmartKeyAccount signers must cover 400k·64/63 + 5k for the ERC-1271 call (P5 node); (d) bamboo-dms `dms_blockchain/tests/test_eip712.py:14` must be repointed to `metatx_v1_kat.json` (other repo; P5 moved it to `legacy/p5/test/vectors/`, see the bamboo-dms item under P5). (e) `ERC20MetaTx` (git mv of `MetaTxCore`) sits on `MetaTxBase`: drop `MetaTxCore`'s own `nonReentrant` and `_metaNonce`, declare `_msgSender() override(Context, MetaTxBase)`, `MetaTransfer` path uses `_checkEnvelope` + `_useNonce` (watch the order of the three adjacent uint256 args `batch, nonce, validUntil`); (f) each token re-pins `mtxSelectors()` == `_mtxRule`, and keeps the "no `mtx…` in the allowlist" test; (g) optional: fee checks before the call (`_checkFee` in step 3) so a doomed tx is cheap; a dedicated error for an unguarded allowlisted target (today `Reentrancy()`); (h) `eip712Domain` drop `virtual`; v1 KAT writer `MetaTxKat.t.sol` (now `legacy/p5/test/`) gets the `WRITE_KAT` guard.
- P1c notes (from the P1b reviews, 2026-10-10): (a) the typed path's "cannot fail after step 3" and `mtxPayReceiverFee` step 5 hold only while `_update` refuses nothing beyond `to == this`: any P1c pause/freeze/feature refusal added to `_update` must be mirrored in `_checkTransfer` (and checked before the receiver-fee transfer); (b) `_chargeFee` re-derives the fee class from `_mtxRule`, so rules must stay constant per selector (hardened in P1b: an ABSOLUTE+FIXED fee is taken as is); (c) Multi `_mtxRule` falls back to `MetaTxBase._mtxRule`, so rules P1c adds in `ERC20MetaTx`/`MetaTokenBase` are dropped on Multi (moot after P1d; otherwise switch it to `MetaTokenBase._mtxRule`); (d) `HederaAccountAuth.sol:29` `asView` safety comment names `executeMetaTransaction` as the sole call site: there are now many non-view call sites (all `nonReentrant`, non-static frames), still safe; repoint the comment in P1c (HederaLib); (e) deferred test gaps still open: Task 3 — `FeePolicy.validateRecipient` is unreachable on both paths (the resolved recipient is never 0; delete or pin), no success-path test of a relayer-filled third-party `feeRecipient` on the typed path (only the `== to` refusal, `test/v2/Base.t.sol`); Task 4 — unwrap: no raw `ERC20InsufficientBalance`-from-`_burn` case when the reserve suffices, no dirty-address-word case; Task 5 — no SmartKeyAccount-clone (400k) payee test, no single-field tamper tests (`fee`/`feeRecipient`/`rfValidUntil`), no invalid-fee-nibble shape case, no RP4 assertions after a failed co-signature. Task 6's gaps were closed in the P1b final fix wave.
- P1c notes dispositions (2026-10-10): (a) no `_update` refusal was added in P1c (flags 5–8 are refused at init, C2): carry to the asset-suite stream; (b) unchanged; (c) done in P1d (`UnderlyingToken._mtxRule` falls back to `super._mtxRule`); (d) done (`HederaLib`, `asView` comment repointed); (e) open test gaps stay as listed.
- Asset-suite stream, from the P1c final review (C2): issuer and compliance must be contract-only when flags 5–8 are built; roles are keyed by flag bit and `_grant` requires the role's own bit, which cannot express FORCE = issuer + compliance or one issuer shared by FREEZE/FORCE/PAUSE, so the stream must key roles by role id (issuer, compliance) or map bits; and any `_update` refusal (freeze/pause/allowlist) must be mirrored in `_checkTransfer` and before the receiver-fee transfer.
- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line moved to `smartcontracts/evm/legacy/p5/` in P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
      the token base `ERC20MetaTx is MetaTxBase` (absorbs `MetaTxCore`) with `MetaTokenBase` on top; kinds `NONE` and
      `UNDERLYING` (the native-coin leg, CTR-TOK-26) with `AdminLib`, `UnderlyingLib`, `HederaLib`, `SigCheck` (CTR-TOK-21…24); factory
      `createToken` (CTR-TOK-25). Back up what token-tree spec §8 deletes (the v1 names are in `legacy/p5/`): `ERC20MetaTx`(v1), `MetaToken`, `HederaMetaToken`,
      v1 `OpenFactory`, `MetaTxDex`, `MetaTxCore`, `Single`/`MultiUnderlyingToken` (merged), the `Hedera*UnderlyingToken`
      children, `SigLib`, `OpenFactoryV2.createMetaToken` (gone with factory v2, P1e), the regulated children (flags instead, CTR-AS-17).
- [x] **MT-2** (P1b built all but the UA split and `mtxWrap`; `mtxWrap` P2a; the UA path built in UA-4: `UAMetaTransaction`/`UAMetaTransfer`, `ua*`, the one `bytes32` nonce map, `metatx3.json`) Two structs, one lane space (CTR-MTX-15): `MetaTransaction{from, data, …}` + `mtxExecute` (+ alias), `mtxBatch`;
      tokens' typed `MetaTransfer{from, to, value, entryRef, …}` + `mtxExecuteTransfer`, `mtxBatchTransfer` (CTR-MTX-23/24);
      named functions keep their signatures and build their struct (CTR-MTX-09); receiver-pays on `MetaTransfer`;
      transient sender and one-shot ticket, per-implementation allowlist + `mtxSelectors()`, fee classes,
      all-or-nothing; `_msgSender()` everywhere per the `msg.sender` inventory; lint/test that no token reads
      `msg.sender` directly except the allowed spots; UA path split into `UAMetaTransaction`/`UAMetaTransfer` +
      `uaExecuteTransfer`/`uaBatchTransfer` (CTR-UA-26); KATs `metatx_kat.json`, `metatransfer_kat.json`, v3 pair.
- [x] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; the v1 line left the build in P5 (`legacy/p5/`); `mtxWrap` for a SCaaS underlying done in P2a (UnderlyingToken), inherited by `UnderlyingZetherToken` (P3); the approve rule holds on both Zether kinds (tested in P3).
- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the UA registry, UA F1; Zether digests done in P3, SmartKeyAccount and MandateWallet in P4) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
      UA registry, Zether digests); deploy scripts on a CREATE2 deployer; deploy gate checks `chainUid()`.

- UA ledger split (CTR-UA-26: `UAMetaTransaction`/`UAMetaTransfer`, `uaExecuteTransfer`/`uaBatchTransfer`) moved from P1b to UA F1 (R4).
- P1e sizes: `UnderlyingToken` 26,449 B is over EIP-170 (24,576) until the size work (owner: optimise later; baseline in `size-baseline.json`); `UnderlyingLib` 10,096 B; `NoUnderlyingToken` 20,196 B; `OpenFactory` 6,715 B; the deploy scripts deploy only `NONE` for the new factory.
- P1d follow-ups (parked test gaps, not fixed): no `mtxExecute(single-asset selector)` on a two-leg token test; native `UnderlyingTransferMismatch` untested; `addReserve` with native `msg.value > amount` untested; guardian revoke untested (these stay parked; the dead `META_MULTI` count branch is gone with factory v2: done in P1e).
- P1d follow-ups (final review): (a) the native leg is absent from the `WrapperInvariant` handler: add a 4th leg (native, with a `vm.deal` forced coin) and a §12 conformance row for CTR-TOK-26; (b) the deploy scripts must deploy `UnderlyingToken` (it links `UnderlyingLib` and `AdminLib`) once it fits EIP-170.
- P1e follow-ups (parked): (a) the size ratchet does not tighten itself: when a baselined contract shrinks, lower its entry in `smartcontracts/evm/size-baseline.json` by hand (the gate only notes an entry that now fits); (b) `smartcontracts/scripts/deploy.sh` requires `PRIVATE_KEY` (it derives `--sender` from it), so a KMS or hardware-wallet deployer needs a script change; (c) done in P3: kinds 2 and 3 are built, their creation passes the Zether gate; only the PQZ kinds 4–7 are `KindReserved`; (d) integrators: the factory's underlying index is only as truthful as the implementation, trust it for registered versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0; (e) libraries stay placed by forge from the sender's nonce, not by CREATE2 (E7); (f) the P1d parked test gaps above stay.

**P2 — MT-5**
- P2a (done, merged `6a5c6b0`): `TradeLib` (`scaas.trade`) and the trade entries on every token, `mtxWrap` + `NativeNotGasless` on `UnderlyingToken` (D1 closed; a native wrap by `mtxExecute(wrap(…))` still reverts `NativeValueMismatch(0, amount)`); 855 tests. Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. Open for P2b/P2c: the DEX side below. **F4 (owner): `NoUnderlyingToken` is 22,951 B, over its 20,480 B budget (ratchet baseline), `UnderlyingToken` 29,974 B: owner — code size is not a concern, the product waits for the Glamsterdam fork (larger code limit); the ratchet baseline records sizes.**
- P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). P2c built `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`. `SCaaSDexV1` moved to `legacy/p5/` in P5 (owner: backup, not delete).
- P2b-2 (done, merged `7049c78`): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` / `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by `SafeERC20`; 913 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14). Size baseline raised by 9 B per token (`precheck` argument). Node P7: a batch reverting with `SigCheckGasStarved` is split and simulated per settlement, never retried whole with more gas (a party's `destination` that is a hook-token recipient can forge the selector; hook tokens are never listed). `mtxSettle` success is not monotonic in gas (a settlement can fail with an empty `MatchFailed` reason at a gas above a starved-revert window), so the node never trusts plain `eth_estimateGas`: it sizes gas from a simulation that requires every planned `ok[i]` true and reads an empty `MatchFailed` reason as out of gas (retry with more gas, never mark the order invalid). Limitation: no HIP-632 branch on DEX signatures, so a Hedera ED25519 account cannot sign a `DexOrder` or a DEX-side cancel (follow-up: `IS_HEDERA` in `SCaaSDex`).
- P2c (done, merged `d85fc8b`): the exchange path on `SCaaSDex` — `mtxExchange` (interactions: never the DEX or the puller, never `mtxTrade`, data of at least 4 bytes), `mtxExchangeVia` (`IExchangeExecutor.exchangeCallback`), `setExchangeTarget` / `setListedOnly` and the `LISTED_POOLS` condition, `tokenKnown` (counted per listed market), the surplus to the signers by floor with the remainder to the last leg, `InsufficientOutput`, conservation over every snapshotted token, a pull check that refuses an inexact sell token, every `approve` interaction reset to 0, `increaseAllowance` and Permit2 `approve` refused (`ForbiddenSelector`, controller ruling, pending the owner); `ExchangeLegSettled`; 949 tests. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`. Open: the fork test with real Uniswap bytecode (dex.md section 14), the DEX invariant suite, the node's TradeEngine (NODE-DEX-17/18, P7).
- P2 notes (from P1c, P1d): (2) Named `mtxTransfer` is +9 execution gas over `mtxExecuteTransfer` (33,681 vs 33,672): the row is logged, not asserted; `mtxPay` on a fresh lane is +2.6 k (the `PAYABLE` gate's cold SLOAD, C3). (3) The asset suite's inline per-transfer admin check (CTR-TOK-24) also needs NONE bytes: it competes with the size debt in F4.
- [x] Rename `OrderBookDex` → `SCaaSDex` (owner 2026-10-09; EIP-712 domain name `SCaaS Dex`); git mv + docs + node names. (done 2026-10-09)
- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; P2b done (P2b-1, P2b-2); P2c done (merged `d85fc8b`); open: the invariant suite, the Uniswap fork test): `SCaaSDex.mtxSettle`
      (Path A/B, 1 taker + N makers, 50 % floor, fee split, conservation invariant); outside-token legs through the
      `DexPuller` (CTR-DEX-22); exchange path `mtxExchange`/`mtxExchangeVia` (CTR-DEX-20), surplus distribution
      (CTR-DEX-21), interaction blocklist + `LISTED_POOLS`/listed-only (CTR-DEX-23), admin `setExchangeTarget`/
      `setListedOnly` (CTR-DEX-03); tokens accept `receiveToken == this` and flag 4 (CTR-DEX-15).

**P3 — MT-6**
- P3 (done, merged `dc9d219`; P3b modes pending): `NoUnderlyingZetherToken` / `UnderlyingZetherToken` (`ZetherLayer is MetaTokenBase`, logic in the external `ZetherLib`, `scaas.zether`), `ZetherStatements`, `zetherShield` from the public balance, `zetherWrapShield` / `zetherUnshieldUnwrap` on `UNDERLYING_ZETHER` (nothing minted), relaying through `mtxExecute` with the envelope binding in the transient ticket (`MetaTxBase._envelopeBinding`), `chainUid` in every token-side digest and the 416-byte header, the Zether gate on `OpenFactory`, `DeployBase` registers kinds 2–3 on dev chains with `DEPLOY_ZETHER=1` (opt-in), the prover on the new header and ABI; the built `ZetherToken`, `ZetherMetaTx`, old `IZetherToken` and their tests in `smartcontracts/evm/legacy/p3/`; 977 tests. Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`. Open: a real-passkey envelope test (CTR-ZTH-21), gas of `zetherWrapShield` / `zetherUnshieldUnwrap` (the zether.md gas tables are re-measured on the new kinds), the registry's `chainUid` (UA F1), client Zether encoders (after P3b; the node relays Zether calls opaquely, P5); disclosure questions for the disclosure review (plan header).
- [x] v1 line to backup (P5): `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1`, `MetaToken`, `HederaMetaToken`, `MetaTxDex`, `SCaaSDexV1` and their tests in `smartcontracts/evm/legacy/p5/`; the Zether part moved in P3 (E1; owner: backup, not delete).
- [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zero-knowledge.md CTR-PQZ-21): with `PqzToken` (no PQZ selector exists yet; P3 left the room: the binding hook takes a PQZ tag).
- [~] **MT-6** Zether (done in P3: transient envelope binding, `zetherShield` from the public balance, `mtxWrap` inherited, the `zether*` renames, binding without `to`/`value`, prover `Header.chain_uid`, `HEADER_LEN` 416; open: `PqzToken` on the one base, PQZ selectors not batchable, CTR-PQZ-21, with the PQZ stream).
- P3b (done): `ConfidentialConfig.disclosureMode` (BUNDLE / COMPACT) and `auditorMode` (NONE / FULL / OPTIONAL) fixed at `initialize` (`BadDisclosureMode`, `BadAuditorMode`); `zetherTransfer` = the mode's default, `zetherTransferCompact` (commit-reveal), `zetherTransferNoBundle` and `zetherTransferSingle` BUNDLE-only (`TransferEntryDisabled`), `zetherTransferBundle` removed; `AuditorRequired` / `AuditorForbidden`; `s` v2 with the 16-byte salt, the 480-byte header (`…/v2` proof system id), the record `R = salt ‖ B_1 ‖ … ‖ B_M`, the sender memo next to the commitment (`transferEntry` = `keccak256(R) ‖ memo`), the registry's `keyOf`; prover `openMemo` + `recoverTransfer` (seed + storage, keys by `keyOf`, or calldata → `s`, amounts, `R`, `SENDER_S` / `SENDER_CP`), `disclosureMode` / `auditorMode` in requests; vectors regenerated; §19 re-measured. PQZ: spec only. Plan `docs/superpowers/plans/2026-10-11-p3b-zether-modes.md`.

**P4 — MT-7**
- P4 (done, merged `ebacaac`): `SmartKeyAccount` / `SmartKeyAccountFactory(chainUid)` and `MandateWallet(owner, chainUid)` / `HederaMandateWallet` on `MetaTxBase` (domains `SCaaS SmartKeyAccount`, `SCaaS MandateWallet`, `salt = chain_uid`), the account signs its own key management (`_selfSender` hook), `mtxExecuteAsOwner`, `mtxPayUnderMandate`, `mtxRevoke` with derived lanes, `revoke(token, epoch)` and `payUnderMandate(token, payee, amount, entryRef, epoch)` (selector `0x781fc8a8`; a revoke or any `setMandate` voids queued delegate pays; `setMandate` keeps the running period when delegate and period are unchanged; controller rulings, pending the owner; CTR-ACC-07), `mtxExecuteAsOwnerRaw`; Solana `state::SmartKeyAccount`; clientkeys `checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`, `mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`; the typed-struct `SubjectAccount`, `MandateWallet`, `HederaMandateWallet` and their tests in `smartcontracts/evm/legacy/p4/`. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
- [ ] bamboo-dms (other repo, P4 follow-up; before P4 contracts reach a chain Odoo uses): the Odoo owner call (`_owner_call_typed_data`, `_owner_call_digest`) becomes the account's salted `MetaTransaction` with the chain's `chainUid` (`smart_key_account_kat.json`; clientkeys `checkOwnerCall` gained a `chainUid` parameter); the mandate digests and calldata (`lib/eip712.py`, `lib/abi.py`, `test_eip712.TestMandateKat`) move to `mtxPayUnderMandate(token, payee, amount, entryRef, epoch, …)` / `mtxRevoke(token, epoch, …)` (`mandate_pay_kat.json`, `mandate_revoke_kat.json`); the relay job (`blockchain_relay_job.py`) still uses pre-P4 names such as `revokeWithSig`, must read `epoch(token)` for every pay and re-sign on `StaleEpoch`, and the kill-switch revoke job re-reads the epoch after a `setMandate`; `blockchain.subject.account._predict` reads `smart_key_account_create2.json`; deploy seeding reads `smart_key_account_factory`; wallets are deployed with `<owner> <chain_uid>`.

**P5 — MT-8, MT-9**
- [x] v1 line to backup: the node and clientkeys are on the new ABI; the v1 contracts, tests, KATs and deploy path are in `smartcontracts/evm/legacy/p5/`, the node's and clientkeys' v1 encoders in `scaas-node/legacy/p5/` and `clients/clientkeys/legacy/p5/` (E1).
- [~] **MT-8** Node (P5 built): two `sol!` structs, `metatx` jobs name their struct (`call` | `transfer`, absent = `transfer`), the call table and the selector tables from `mtxSelectors()` (NODE-JOB-19/20), `chainUid()` check (NODE-GW-07), `MinNonceNotIncreasing` on an invalidation = consumed `already_invalidated`, ERC-1271 gas floor (P1b (c)), DEX venue on the clone `mtxSettle` with outside legs and DEX-side cancels (NODE-DEX-15/16), intake `allowance(from, puller)`; after the reviews: the outbox normalizes `feeRecipient`/`relayer` for every origin and keys in-flight work by the token's own digest, the guard runs in `Submitter::submit` (a `MetaTransfer` or an order or wrap entry needs a registered token, an entry also a listed DEX: `TOKEN_NOT_SERVED`), token lists refresh every 15 s, the Hedera lane checks `chain_uid` at start, a rebuilt job after a restart passes the guard and the 2^24 clamp, a `receiver_fee` job is refused, the venue checks signatures as `SigCheck` does and probes each leg before dropping a maker. Open (review leftovers: gateway guard order, config docs, the `settle` refusal reason, padded gas above the maximum, the entry 1271 floor; a guard-refused job rebuilt after a restart is only logged, no Odoo report): breaker per `(from, selector)` and batching via `mtxBatchTransfer`/`mtxBatch` (NODE-LANE-11, NODE-LANE-25), TradeEngine with `trade_engine.*` and `/v1/dex/exchanges/{ref}` (NODE-DEX-17/18, P7), NODE-IDX-06 `repeat_of`, `ua_metatx` (UA F1), the per-poll venue check (NODE-DEX-08).
- [~] **MT-9** clientkeys (P5 built): `MetaTransfer` typed with `domain.salt` and `chainUid` (`checkPayment`, CLI-SGN-08), self-call check by allowlist, `TradeOrder`/`DexOrder`/cancel typed data, refuse an unlisted `dex`, no EOA approve, wrap by signature (CLI-SGN-05, CLI-SGN-33…36); KATs with relayed calldata (`dex_order_kat.json`). Open: the app bundle rebuild and the reference ERP's `lib/eip712.py` (bamboo-dms item below).
- [ ] bamboo-dms (other repo, P5 follow-up; before the P5 node reaches a chain Odoo uses): jobs carry `struct` and the v3 `metatx`/salted digests (`lib/eip712.py` on `metatransfer_kat.json` / `metatx_kat.json`); `metatx_v1_kat.json` moved to `legacy/p5/`, `hedera_kat.json` is v3, the KATs gained `calldata`; the DEX book rows carry `sell_token`, trades list their makers, a failed trade is `{taker: {row, fill}, makers}`, DEX cancels and invalidations come as relay jobs (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxCancelOrders`), the events are `LegSettled`, `MatchFailed` (`out_of_gas` when empty), `OrderCancelled`, `NoncesInvalidated`; `dex_markets` lose `fee_on`/`fee_recipient`; a consumed `already_invalidated` is success; an unregistered token or entry target is `dead` with `TOKEN_NOT_SERVED`, a `receiver_fee` job is `dead`; the mesh vectors are regenerated; deploy JSON keys (`demo_token`, `demo_token_2`; v1 keys gone); the portal's clientkeys bundle is rebuilt; the portal's calls pass the new required clientkeys parameters (P5 fix): `checkPayment` `payee`, `entryRef`, `expectedToken`, `amount` (refused when missing) on lane `payLane(entryRef)` nonce 0 (optional `maxFee`, `feeRecipient`, `relayer`), `checkCall` `call = {contract, data}` (+ `maxFee`, `feeRecipient`), `checkTradeOrder` the client-built `order` + `sellToken` (+ `outside`), cancels through `checkCancel`.

**Non-EVM families (NM-*)**
- [ ] **NM-APT** Aptos: `MetaCall`/`MetaTransfer` (BCS), public `scaas::metacall::verify`, `mtx_` entries incl. key and
      mandate entries, `KeyOp`/`MandateInit`/`key_nonce` removed; new immutable package (NET-APT-27, NET-ALL-26…29).
- [ ] **NM-SUI** Sui: as Aptos plus `mtx_forward` (no `ForwardOp`), client encoders byte-identical (NET-SUI-18, NET-SUI-16).
- [ ] **NM-SOR** Soroban: `mtx_` functions, SEP-41 `transfer` kept, `__check_auth` context allowlist per key (NET-SOR-16,
      NET-SOR-04); new deployments.
- [ ] **NM-COS** Cosmos: `scaas-metacall` crate, `MtxTransfer`/`MtxPay`/`MtxExecuteTransfer`/`MtxExecute` (inner
      `MtxTrade`, `CancelNonce`, mandate `PayUnderMandate`), mandate JSON removed; new code ids (NET-COS-12).
- [ ] **NM-TON** TON: `MetaCall`/`MetaTransfer` cells, `Mtx` messages replacing `SignedOp` ops and `MandatePay`, opcodes
      fixed with vectors; new code (NET-TON-20).
- [ ] **NM-SOL** Solana: fixed layouts, `scaas-metacall` crate, `mtx_` instructions incl. key and mandate entries, `KeyOp`
      and `MandateInit` removed; new program (NET-SOL-33).
- Node (adapters, `signed_op` `op_kind` `call`/`transfer`, per-contract `mtx_` lists, NODE-JOB-20) and clients (`fam/*.js`
  encoders, CLI-SGN-27 checks) follow each family stream; vectors regenerated per family.
- [x] Non-EVM generic signed call (NM-1…5) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-nonevm-metacall-design.md`.
- [x] Meta-tx generic call (GC-1…10) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-metatx-generic-call-design.md`.
- [x] DEX exchange path (DS-1…8) accepted and folded 2026-10-08; record `docs/history/specs/2026-10-08-dex-exchange-design.md`.

#### Done 2026-10-21

- **Spike A for `UnderlyingPqzToken`** (owner 2026-10-21) — done `a12cd06b` on `metatx-lib`: 61,045 → A 56,898
  (headroom 8,638 under 65,536) / A2 54,321 (11,215); relayed +7–9k gas (A), large op 7 envelope ≈ +1 M unless only
  the data hash goes to the library. HANDOFF.md top note.
- **Nethermind 2.2.0 + Glamsterdam on the SCaaS testnet** (owner 2026-10-21: "Glamsterdam đã có trên testnet eth …
  cập nhật vào chain SCaaS testnet"): branch `nethermind-2.2` merged `bf1bc7ff`, pushed. Plugin ported to 2.2.0
  (`PqzReleaseSpec` answers `IsPrecompile` for the > 32-bit `0x5caa5…` addresses, which 2.2.0 refuses; the 1.39 plugin
  `Init` became the init step `PqzStartupCheck`, fail-closed, exit 120), image `scaas/nethermind-pqz:2.2.0-pqz3`
  (local only; base `2.2.0@sha256:5cc0061e…`, reviewed library `16dd99ce…` via `FFI_REV`), 46 / 46 tests. Testnet reset
  without backup (owner), Amsterdam from block 1 (EIP-2780, 7708, 7778, 7928, 7954, 7976, 7981, 8024, 8037, 8038, 8246;
  7843 / 8282 off for Clique), genesis hash unchanged, probe + e2e 76 ok, 64 KiB deploy (65,536 B at 100.5 M gas;
  65,537 refused). Old backups deleted (owner). Review merge-ready, minors in TODO (next reset). Gas impact note
  `pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md`.
- **Chain 7622 called "SCaaS testnet" in prose** (owner 2026-10-21): living docs, old plans, COMPLETED.md and
  decisions.md (`5fb8fd15`), Nethermind README / RUNBOOK (`a5985e70`, `28af51d3`); numeric ids, `private7622`,
  `m/7622'` unchanged; `docs/history/` untouched.
- **Machine Foundry 1.3.5 → 1.8.5** (owner 2026-10-21; rollback `foundryup -u stable`).

### 0. Finish the spec phase (7 items left)

- [ ] **Template library** (owner 2026-10-12): every README use case — including economic (commercial) contracts: escrow with an arbiter, milestone service contracts, sale with delivery, leases, installment loans, subscriptions, revenue sharing, deposit with periodic withdrawal (`VestingGrant` / `MandateWallet`), provenance and family-tree registries — ships as an **implementation deployed once per chain**; a user only creates a new instance by clone (EIP-1167) / CREATE2 through a factory with its own parameters (as `OpenFactory.createToken` / `createDex` do today), and calls it by meta-transaction. Off-chain presets (CTR-AS-14 JSON) are only parameter sets for these factories. Spec first (owner rule): `docs/contracts/templates.md` — the template set, each one's init parameters and invariants, the factory (`createX`, deterministic address, `chainUid` gate, registry of instances), who pays the fee per template, client builders; then code streams per template.
- [ ] **P0 follow-ups (minor, deferred by the final review):** `zether.md` gas-cap / 2.5 M paragraphs quote only
      single-recipient figures; `zether.md` ~1327 `recipient` vs target `to`, ~216/220/238 informal `zetherShield(Y…)`
      prose; architecture sequence 5 lacks `UnderlyingLib`; `asset-suite.md` 893–897 "BUILT" next to `createToken`, `IRegulatedToken` block old names (`issuer()`, `compliance()`, `ControlsDisabled`, `RoleRenounced`);
      `clients/app.md` CLI-APP-26 cites CTR-TOK-21 for built kinds; `node/store.md`:157 SQL comments; `node/job-api.md`:328
      unlabelled `SmartKeyAccount.mtxExecuteAsOwner`; CTR-TOK-26 "the invariant" wording; `dropped-artifacts.tsv` duplicates
      and the bare token `273`; CTR-ACC-80 "(then named SubjectAccount)"; budget warnings `token-wrappers.md`, `dex.md` (owner).

Done 2026-10-07: every spec reviewed — Codex on PQZ/UA/NI/B, Claude on the 16 older specs — and every review
folded (dispositions inside each spec; review files in `docs/reviews/specs/`, git-ignored). Owner rulings today:
chainId 9000 → **7622**; `PqzToken` implements `IERC20MetaTx` (PQZ rev 1.4 R284); Move/Solana (and Cosmos
`--no-admin`) programs **immutable at deploy** (round3 CR-R3-11, NI R348).

- [x] **Docs reorg** (plan `docs/history/plans/2026-10-07-docs-reorg.md`), done 2026-10-07: component docs from
      [`docs/README.md`](docs/README.md), register + alias index in `docs/decisions.md`, history frozen in `docs/history/`,
      ledgers in `docs/history/reorg/`, Phase 4 reviews (28 findings) and a 10 % second sample (3 minor) fixed, all
      diagrams Mermaid (checker C11), CI `docs` job. Review files: `docs/reviews/reorg/` (git-ignored).
- [x] ~~**Sync `docs/SCaaS.md` + `docs/integration.md`**~~ (closed by the docs reorg; files now `docs/history/SCaaS-2026-10-07.md`,
      `docs/history/integration-2026-10-07.md`) with the latest folds — collect every "Amends"/"amendments"
      table in: NI rev 3.7 (R340–R349), PQZ rev 1.4 (R284 meta-tx, register row still says 1.2), round3 rev 1.2,
      payments rev 1.1, wallets addendum, signing-formats, infra rev 1.2, DEX rev 1.1, Zether rev 1.1, net-* rev 1.1/1.2.
      Known SCaaS.md errors: §7.7 Solana `MetaOp` is 336 B not 337; §7.6 TON TODO #8 done, `BindKey` doesn't exist
      (stateInit in `SignedOp`, R10-5); §7.4 Soroban nonce is `sha256("scaas.soroban.nonce"‖entryRef‖validUntil)`, `pay_ref`
      lock per `(from, pay_ref)` (R8-9), DEX needs relayer binding (R8-10); §7.2 `associateUnderlying()` superseded
      (R6-8, TW2 R144); §7.5 add lane-horizon client obligation (RS7-11, RS11-24, RS12-24) + Aptos multisig-wrap risk;
      §1.2/§1.3 immutability now true by ruling; admin-exception list; outbox rules into integration.md.
- [x] **NODE-IDX-06** rules in the docs (`node/indexer-feeds.md`, `integration.md`); the code is stream MT-8 (node, open after P5) and the
      client refund check.
- [x] Cross-spec nits, closed by the reorg and the meta-tx fold (checked 2026-10-08): Soroban has no open form
      (`networks/README.md`, [NET-SOR-10]); PAY-FIX6 = the 1271 cap [CTR-DEX-08]; PAY-FIX7 = fee round-up [CTR-DEX-11];
      `job.sponsor_fallback` in `node/job-api.md`, `node/sponsorship.md`.
- [ ] **Codex reviews still owed** (credit ran out after 4): AS, TW2, app, OPS, S4F, mesh, A2 (SCaaS.md and integration.md
      dropped: frozen in `docs/history/`; reorg Phase 4 reviews the new docs). Review the current component doc of each
      area (map in `docs/README.md`), not the frozen spec.
      All already have a Claude review. Run with `codex exec -m gpt-5.5 -s read-only -C <scaas> -o <out.md> "<prompt>"`
      (default `gpt-6.1-sol` is rejected for a ChatGPT account); outputs `docs/reviews/specs/*-codex-review-1.md`; fold.
- [x] **ChainId 9000 → 7622** stream CHAINID done 2026-10-07: genesis reset (`0x24e43dcb…c464`), `private7622` dir +
      foundry profile, KAT/mesh vectors regenerated, node examples, Odoo chain record + tests. Left: `private9000`
      mentions in `docs/history/SCaaS-2026-10-07.md` + `docs/history/integration-2026-10-07.md` (history: the reorg writes 7622 only); `chain_uid` = genesis hash binding (UA R330, not built);
      redeploy the dev contracts on the empty chain.
- [x] Doc nits: Zether chains set `max_gas_per_tx` ≥ 4.5 M (`contracts/zether.md` §19, re-measured in P3b as a gas limit). Left as code: `wasm-smoke.sh`
      builds `--target nodejs` only; a `--target web` build for the app is client work (S4F/app).

### 2. Ops / housekeeping

- [ ] **Foundry 1.3.5 → 1.8.5** (not scheduled; CI pins forge v1.3.5 since 2026-10-13): upgrade local and CI together. Known breaks with 1.8.5: 13 forge tests (gas pins, KAT addresses, `selfdestruct`) to re-measure / regenerate (spec gas tables follow), and `forge script` now applies the EIP-3860 initcode limit (2 × `--code-size-limit`) to the script contract itself — `Deploy.s.sol` initcode is 368,154 B > 131,072, so deploy / e2e scripts need `--disable-code-size-limit` on `forge script` (checked 2026-10-13: then the deploy runs; anvil keeps `--code-size-limit 65536`, which in 1.8.5 still lifts anvil's initcode limit to 128 KiB — no new anvil flag exists).

- [ ] **scaas-node docker-compose** (owner 2026-10-12: after node streams P2 + P3 + P4 + P6; P5, the Odoo client, not yet — P6's push e2e then runs against a test client, not Odoo): standalone, not tied to any Odoo docker — Dockerfile (multi-stage, Rust 1.90), `scaas-node` service + one-shot `store-init` (the node never creates its store), store volume, secrets via `.env`, chain RPC / chain_uid from `.env`; default gateway-only (no `[odoo]`: submit/indexer/admin off, gateway with hmac/bearer auth), a second sample config with submit + indexer for an Odoo reached by URL (legacy pull path, NODE-JOB-10 / R104: decided to be removed after the per-chain push cutover; until node streams P2–P6 land it is the only job source — once push exists the full config needs no Odoo section).

- [x] **P6a** PQ signature verifiers (SLH-DSA-SHA2-128s, Falcon-512 per EIP-8052, ML-DSA-44/65 with FIPS and EIP-8051 expanded keys, EIP-8355 probe; clientkeys PQ signing and vectors): merged 2026-10-12 (branch `p6a-pq` kept, `p6a-val` kept; owner). Reviews T1–T4, one fix wave, final review clean. Owner decisions taken (UA F0/F1 first; ML-DSA stored key form); next: P6b, UA F0/F1 phase, then P6c (carry-overs in the P6 row).
- [x] **UA-1** kind libraries (UA F0): the identity layer in Solidity `UAKinds`, clientkeys `ua.js`, `clients/scaas-ua`, `clients/ua-py`, `clients/ua-go`, `clients/ua-cs`; vectors `smartcontracts/vectors/ua/kinds.json`, `structures.json` (plan `docs/superpowers/plans/2026-10-12-ua1-kind-libraries.md`): merged 2026-10-12 (branch `ua1-kinds` kept). Next: UA-1b (below), then UA-2 (registry and verifiers, PoP signatures, `groups.json`; carry-overs in the UA roadmap's UA-2 row).
- [x] **UA-1b** bindings (owner 2026-10-12): C++ `clients/scaas-ua-cxx` (cxx), QML `clients/scaas-ua-qt` (CXX-Qt, `Scaas.Ua` / `UaKinds`), Dart `clients/scaas-ua-frb` (flutter_rust_bridge 2.13.0) and the pure-Dart port `clients/ua-dart`, all on the UA vectors (plan `docs/superpowers/plans/2026-10-12-ua1b-bindings.md`): merged 2026-10-12 (branch `ua1b-bindings` kept). Open: FRB as a Flutter plugin with Android/iOS/web builds (does `scaas-ua` build for wasm?), Qt packaging for Windows/macOS. Next: UA-2.
- [x] **P6d** E-S1 `pqz-core` spike: done and merged (`132d5c2`, branch `p6d-pqz-core`), then P6d-2 optimisation merged (`b87078a`, branch `p6d2-opt`): `R_TX` proof 42.7 KB, prove 1.10 s native / 1.59 s wasm, generic verify 0.72 s (misses 50 ms; the specialised verifier, P6-SV, is the answer); details in the P6 row above, `pqz-core/STATUS.md`, `docs/research/pqz-core-e-s1.md`. Followed by rel3 (`3ad4069`) and the relation fix-ups (`7e6e9b0`) toward P6e.
- [x] **UA-1c** C ABI via cbindgen (owner 2026-10-13): `clients/ua-c` (`scaas-ua-c`, cdylib + staticlib, committed `include/scaas_ua.h` from cbindgen 0.28.0, drift test), ctypes suite on every UA vector row + C99 smoke, CI job `ua-c` (plan `docs/superpowers/plans/2026-10-13-ua1c-c-abi.md`): merged 2026-10-13 (branch `ua1c-spike` kept). Open: none (`verify` stays unexposed until a binding needs it).
- [x] **UA-2a** registry core + classical verifiers (owner 2026-10-12: UA-2 in three sub-plans): `UARegistry` gen 1 (`src/ua/UARegistry.sol`, `IUARegistry.sol`), verifiers `src/ua/verifiers/` (P-256, WebAuthn-P256, BIP-340, Schnorr bn254/BLS12-381, BLS min-sig BLS12-381/bn254), `signatures.json` + `scaas-ua::verify` (plan `docs/superpowers/plans/2026-10-12-ua2a-registry.md`): merged 2026-10-12 (branch `ua2a-registry` kept). Open: HIP-632 in a view (R19). Next: UA-2b (ed25519), UA-2c (MuSig2/FROST, `groups.json`).
- [x] **UA-2b** `ed25519` (owner 2026-10-12): `src/common/Sha512.sol`, `src/common/Ed25519.sol`, `src/ua/verifiers/Ed25519Verifier.sol` (strict RFC 8032 = dalek `verify_strict`, ~170 k gas, cap 210 k), `signatures.json` row + RFC 8032 section, T-FUZZ `ed25519_fuzz.json`, `scaas-ua` `verify_strict` arm, registry enablement (plan `docs/superpowers/plans/2026-10-12-ua2b-ed25519.md`): merged 2026-10-12 (branch `ua2b-ed25519` kept). Next: UA-2c (MuSig2/FROST, `groups.json`).
- [x] **UA-2c** group kinds (owner 2026-10-12): `musig2-secp256k1`, `frost-secp256k1`, `musig2-bn254`, `frost-bn254` — registry stored kinds (`keyPtr`, `src/common/SSTORE2.sol`), verifiers `src/ua/verifiers/{Musig2Secp256k1,Musig2Bn254,UAFrostSecp256k1,FrostBn254}Verifier.sol`, `library Bip340`, `groups.json` from the `scaas-ua` signers (feature `signers`), noble cross-check, T-FROST; binding lockfiles refreshed (plan `docs/superpowers/plans/2026-10-12-ua2c-groups.md`): merged into main 2026-10-12 (branch `ua2c-groups` kept). Next: the UA client dirs rename, then UA-3.
  - UA-2c follow-ups (final review):
    - ~~FROST(secp256k1) repeated/cancelling `C_i0`: mirror the verifier's refusal in `clients/ua-rs/src/groups.rs` and the noble test, plus one pinned `groups.json` negative (UA F3).~~ (done 2026-10-13, branch `ua-followups`: `dkg_check` in `clients/ua-rs/src/groups.rs` and the noble `frostDkg` refuse a `C_i0` sharing its x with the partial sum, as `_addMixed` does; pinned `groups.json` negatives `c0-repeated` and `c0-cancelling` (UAPoP, PoKs and Y = Σ C_i0 valid), refused by ua-rs, noble and the registry)
    - ~~Cross-language `groups.json` negatives for `x(P_i) ≥ N`, off-curve, non-canonical and wrong-prefix group key data (UA F3).~~ (done 2026-10-13, branch `ua-followups`: 13 new negatives in the four main groups — `pk-off-curve` / `pk-non-canonical` / `pk-prefix-04` (musig2, UAKeyData), `pk-x-ge-n` (musig2-secp256k1, UAPoP), `c11-off-curve` / `c11-non-canonical` / `c11-prefix-04` (FROST `C_11`, UAKeyData; `verifyPop` alone accepts them, only `validateKeyData` refuses) — run by ua-rs `groups_verify` (70 negatives), clientkeys noble (40 secp256k1), `UARegistryGroups` / `UAFrost` / `Musig2Verifiers`; ua-py/go/cs/dart do not read `groups.json`)
    - ~~Harden the `scaas-ua` `signers` API before exposing it (panics on short secnonce/pubnonce/index, `nonce_gen` truncates `sk`) (UA F3).~~ (done 2026-10-13, branch `ua-followups`: `nonce_gen` returns `Result` and refuses `sk` ≠ 32 bytes, a wrong-width `pk` / `aggpk` (new `Curve::ALEN`); `sign` refuses a secnonce ≠ 64 + PLEN, `partial_sig_verify_internal` a pubnonce ≠ 2·PLEN, `partial_sig_verify` an index outside either list, `sign_all` unequal lengths, FROST `dkg` n < 2, `Dkg::sign` identifier 0 or unknown — errors, no panics; test `signers_refuse_malformed_input`)
    - ~~`SSTORE2.write` guard `if (data.length > 0xfffe) revert SSTORE2WriteFailed();` when PQ keys first use SSTORE2 (P6c).~~ (done in P6c)
    - ~~`MSIG_MEMBER_GAS` stored-member bound test: an `MB` member with a 96-byte sig and a near-full burn (cold margin measured 2–4 k).~~ (done 2026-10-13, branch `ua-followups`: `test_T_GAS_msigStoredMemberBound` now also runs musig2-bn254 n = 16 (1,090-byte key data) with a 96-byte sig behind a full-burn verifier, gen 1 and gen 2, within `cap + MSIG_MEMBER_GAS`, also under `--isolate`)
    - ~~CI: run `test/ua/UAGas.t.sol` and `test/ua/UARegistryGroups.t.sol` with `--isolate` (cold gas numbers).~~ (done 2026-10-13, branch `ua-followups`: CI step `forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'` after the default forge test)
    - Local Qt builds of `clients/ua-qt` need `QMAKE=~/usr/Qt/6.8.2/gcc_64/bin/qmake6`.
- [x] **UA client dirs rename** (owner 2026-10-12, option a; done 2026-10-12): `clients/scaas-ua` → `ua-rs` (crate name unchanged), `scaas-ua-cxx` → `ua-cxx`, `scaas-ua-qt` → `ua-qt`, `scaas-ua-frb` → `ua-dart-frb`; `ua-py`, `ua-go`, `ua-cs`, `ua-dart` stay. One commit after UA-2c merges: CI, Cargo/CMake/FRB paths, docs (`ua-libraries.md`: binding vs port), every suite re-run.

- [x] **UA-3** Zether re-point (UA F1, CTR-UA-22; plan `docs/superpowers/plans/2026-10-12-ua3-zether.md`): `zether-bn254` / `zether-bls12381` in `UARegistry` (stored `Y`, `keyOf`, `authRef` co-sign, `requireZetherAuthorized`, `ZetherSchnorr*Verifier`), `ZetherTypes.toUA` tagged, `registered` by `kindOf`, prover (`zether_pop`, `owner_auth`, vectors) and clientkeys (`zetherPop`, `zetherOwnerAuth`) in one change set, the old registry and `AuthScheme` in `legacy/ua3/`, `DeployBase` deploys the UA registry on every chain (`UAPrecompileProbe`), e2e `scripts/e2e-zether.sh`: merged 2026-10-12 (`520642c`, branch `ua3-zether` kept). Next: UA-4 (UA ledger) or P6c.
- [x] **UA-4** UA ledger (UA F2, CTR-UA-18/19/26; plan `docs/superpowers/plans/2026-10-12-ua4-ledger.md`): `_uaBalance` and `UA_POOL` in `ERC20MetaTx` (the registry an implementation immutable of every kind, checked against `chainUid` at `initialize`), `UATransfer`, `transferToUA`, `uaExecute`/`uaBatch`/`uaExecuteTransfer`/`uaBatchTransfer`/`uaCancelNonce` and the named `uaTransfer`/`uaTransferWithFee`/`uaPay`/`uaUnwrap`, the one `bytes32` nonce map in `MetaTxBase`, `SigCheck.isValid7702` (CTR-UA-24), clientkeys `uaMetaTxTypedData`/`uaMetaTransferTypedData`, `smartcontracts/vectors/ua/metatx3.json`, T-V3-1…3b; sizes recorded (init ratchet in `size_gate.py`), `--code-size-limit 65536` in `deploy.sh` and the node e2e: merged 2026-10-13 (`8152ee7`, branch `ua4-ledger` kept).
  - Open (UA F5): node `ua_metatx` jobs, mesh `evm.ua_meta_tx`, indexer pairing of `Transfer` to/from `UA_POOL` with `UATransfer`, `UAPaymentSettled` in payment reconciliation.
  - Open: T-V3-4 and the `ua*` fallback decoder wait for Glamsterdam (owner); real chains at 24,576 cannot take any token implementation until then. `metatx3.json` rows for the group kinds and `msig` (UA F3); the PQ kinds' rows are in `pq_signatures.json` (P6c).
- [ ] **UA-5** UA parity (owner 2026-10-13: every native-address operation for a derived UA of any SIGNING kind, PQ included; design accepted and folded, record `docs/history/specs/2026-10-13-ua-parity-design.md`; rules CTR-UA-27/28, CTR-DEX-25/26, CTR-ZTH-51, CTR-ACC-12 and the dated changes in `decisions.md`). Q1: role and admin functions stay as they are (no UA counterpart); their holders stay gasless through their own contract account. Replaces the proposals UA-DEX and "UA wrap in one step". Relayed use of every phase needs the node's UA jobs (UA F5, the open item under UA-4); each phase ends with the size gate and the full forge suite (default and `private7622`).
  - [x] **UA-5a** receivers, one-step wrap, receiver-pays: `_uaMint`, `wrapToUA` (direct + relayed; native-coin leg when direct), `unwrapToUA` (SCaaS ledger leg), `mintToUA`, `burn` on the UA allowlist, `payWithFeeToUA`, `uaPayReceiverFee`; clientkeys `receiverFeeTypedData` and the receiver calldata builders, `metatx3.json` rows `burn` / `unwrapToUA` / `receiverFee` and the PQ `receiverFee` row; sizes and gas in accounts.md CTR-UA-28 (two `mldsa65` `uaPayReceiverFee` 11,874,662); forge 97 suites, 1157 passed (default and `private7622`). Plan `docs/superpowers/plans/2026-10-13-ua5a-receivers-wrap.md` (FINAL, spiked): merged 2026-10-13 (`04bad29`, branch `ua5a-spike` kept; C5a-15 confirmed by the owner). Next: UA-5b or UA-5c, in either order.
    - Open (UA F5): relaying `ua*` jobs (`uaExecute(burn | unwrapToUA)`), a receiver-fee job with a `bytes32` payee (the address-path receiver-fee job is refused today), `UATransfer` / `UA_POOL` indexing of the new moves (`UnwrappedToUA`, `UAReceiverFeePaid`). The address-allowlist rows of `wrapToUA` / `unwrapToUA` relay as `call` jobs with no node release.
    - [x] Backlog (clientkeys, outside UA-5a): a pre-sign check for the payee's `ReceiverFee` (`receiverFeeTypedData` has no `check*` guard, so `fee`, `feeRecipient` and `paymentDigest` are signed blind), for both paths (`mtxPayReceiverFee` and `uaPayReceiverFee`): the payee's own bounds on `fee` / `feeRecipient` and a `paymentDigest` recomputed from the payment it expects (as `checkPayment` does for the payer). Done 2026-10-13 (branch `ua-followups`): `checkReceiverFee(td, {payee, amount, decimals, entryRef, expectedToken, payment, maxFee, feeRecipient, …})` in `clients/clientkeys/src/evm.js` — the payer's `MetaTransfer` / `UAMetaTransfer` rebuilt (to = the payee, receiver-pays shape mode 1 / fee 0, lane, nonce 0, token, salt), `paymentDigest` = its recomputed digest, fee non-zero, ≤ the amount and `maxFee`, the named `feeRecipient`, near deadline; tests in `evm.test.js` (address path, 20 refusals) and `ua-metatx3.test.js` (every `receiverFee` row of `metatx3.json`); CLI-SGN-05 notes it.
    - Moves on: `uaWrap` (mints through `_uaMint`) to UA-5b; `zetherUnshieldToUA` / `zetherUnshieldUnwrapToUA` (through `_uaMint` / a ledger leg's `transferToUA`) and `MandateWallet` paying a derived payee by `payWithFeeToUA` to UA-5c.
  - [x] **UA-5b** trade and DEX: `UATradeOrder` / `UAInvalidateNonces`, purpose `trade` (`UAKinds` + the six UA libraries, `kinds.json`), `TradeLib` on ids (`bytes32` `minNonce`), `uaTrade` / `uaCancelOrder` / `uaInvalidateNonces`, verify once (`pulled[h] ≠ 0`, both paths), `uaWrap`, `SCaaSDex` tagged legs with UA payouts and refunds, `UAVerifyGas` re-raised, `uaTrade` refused in interactions; `uatrade_kat.json` and clientkeys `uaTradeOrderTypedData` / `uaInvalidateNoncesTypedData`; node: tagged legs (shape 0) and `UALegSettled` indexing. Gas and sizes in dex.md CTR-DEX-25 / CTR-DEX-26 (two `mldsa65` legs 12,124,252, three revert `UAVerifyGas`; `SCaaSDex` 23,493 B, under EIP-170); forge 102 suites, 1196 passed (default and `private7622`). Plan `docs/superpowers/plans/2026-10-13-ua5b-trade-dex.md`: merged 2026-10-13 (`1b9e244`, branch `ua5b`). Owner confirmed all controller rulings 2026-10-13 (C5b-1/-7 one internal order form, trailing bytes ignored; -2 `ua*` trade reverts `UALedgerOff` when the ledger is off; -3 `SelfTrade(bytes32)`; -4 `LegShapeUnknown`; -5 "ledger on" = listing + `registry() != 0`, no ERC-165; -6 derived destination checked at payout, `MatchFailed`; -9 `uaWrap` emits only `UAWrapped`; -11 node: tagged legs + `UALegSettled` only, the rest in UA F5; -12 vector layout; -14 `SCaaSDex` 23,493 B stays out of the size baseline).
    - Open (UA F5): the node's UA order intake, the `bytes32` book / TradeEngine with committed balance from `balanceOfUA`, settlement packing by the kinds' caps, PQ order gossip; relaying `uaWrap` and `uaCancelOrder` / `uaInvalidateNonces` jobs.

- [ ] Zether prover gas cap: add an authorization allowance by `authRef` kind (UA-3: the `AuthScheme`s below map to `authRef` kinds, accounts.md §1.13) to `check_gas` (re-review of P3b: a BLS_12381 UA authorization adds ≈ 186 k direct / 192 k relayed, a passkey/1271 envelope payer ≈ +48 k; the tightest edge, bn254 NONE no-auditor relayed M = 9, has 218 k of room); proposed: 0 SELF_SCHNORR/PQ, 50 k FROST/MuSig2, 70 k 1271, 160 k BLS_BN254, 200 k BLS_12381, 10 k per multisig signature, +60 k contract payer when relayed; the node cap note likewise (≈ 4.7 M for a BLS UA on a BLS12-381 relay).

## From HANDOFF.md

### Session 2026-10-19 (afternoon; PQZL v3 fix merged) — resume here

**State:** main pushed (`361a86b` + this note). **PQZL v3 Fiat–Shamir fix merged** (branch `pqzl-fs3`; owner 2026-10-19: merge now, Tasks 6–13 continue on main). Plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`, subagent-driven with one reviewer per task; reports `.superpowers/sdd/2026-10-19-pqzl-fs3/task-*-report.md` (git-ignored, in the old worktree folders).
- Tasks 0–5, 8 done: P6-FS binding tests (C `sz/fs_bind.c`, Rust `tests/fs_bind.rs`; FAIL 10/12 before, 0/12 after); transcript fix in all four implementations (z3‖z4 → hz before V3/V4, **JL rows R/R' stay on cseed** — plan deviation from F1, accumulate_z3/_z4 take a separate rseed; h → hash2 before μ and c); `proofSystemId` v3 `0x8079d65b…16baef` everywhere, v2 removed (16 "retired v2" negative rows); D-2 Rej1 `rej_onetime` (≈2× z2 tries, `PQZ_REJ_MAX` worst case e^-42.5) and D-3 β bits, no parameter change; vectors regenerated, self-test hash unchanged `ed910a2c…d205`; C = Rust on 14 relation codes; final fnv bench 5 5 63 `b935013d…06c6a4a5`; spec / decisions F1–F10 / STATUS round "PQZL v3" / soundness note §8.
- Codex (G) and agy (H) reviews of the Rust crate (`pqz-core/research/code-review-2026-10-19/G-codex-pqzl-rust.md`, `H-agy-pqzl-rust.md`, triage A–E): no P0. Owner: fix A–E before the merge. A exact statement length / proof cap before keys and hashing; B `Wiped` drop guards on the prover's secret copies; C `canonical` chunks_exact; D C `uabs64`; E constant-time prover / keys arithmetic, C and Rust (`E-constant-time.md`; ctgrind `pqz-core/pqzl/test/ct.sh`: C 135 → 0, Rust 141 → 0, keys 18/21 → 0). Timing E (idle host, `pqz-core/pqzl/rust/runs/ct-timing/`): verify_fast unchanged (gas basis intact), generic verify +11–16 %, prove +2–9 %.
- Host changes today: Codex 0.163 sandbox needed `/etc/apparmor.d/bwrap-userns` (installed by the owner; test free with `codex sandbox`); valgrind installed. The owner stopped docker stacks for the timing run (knowledge, odoo19, mssql, timescaledb, odoo-uuidv7-refactor: `docker compose -p <name> start` to bring back). The SCaaS testnet node was not running.

**Next (plan Tasks 6 → 13, on main):** (1) Task 6 package: `pqz-core/artifact/expected-results.json` (digest lines still v2-era), `reproduce.sh` Docker quick with `--memory`, run alone (oomd); (2) Task 7 fuzz `scripts/capped pqz-core/fuzz/run.sh <t> 7200 fs7` for precompile, mutate, codec in `pqzl-diff` mode, one after another (three small corpus files still carry the v2 id); (3) Task 9 `scripts/capped pqz-core/gate.sh fs9` incl. the full `sv/diff.sh` (x86v3 / z21diff were deferred from fix E); (4) Tasks 10 ∥ 11 reviews A and B (B also confirms Rej1's extended-MLWE assumption); (5) Task 12 final gate; (6) Task 13 SCaaS testnet reset with image `pqz4` + gas re-calibration on a quiet host (ask the owner to stop other sessions first; `runs/2026-10-19-pqzl-rows.py` keys rows by v2 — use an adapted copy that fails on 0 matches); (7) post the lazer#28 comment and the D-2/D-3 issue after owner approval (drafts in `scratchpad/`). Codex reviews only on the owner's request, one type at a time. Leftover worktrees `.claude/worktrees/pqzl-fs3{,-fixad,-ct,-review}` can be removed (all merged).

### Session 2026-10-19 (P0 PQZL Fiat–Shamir finding; fix started) — resume here

**State:** main pushed (`2fff733` + this note). **Whole-code review** (PQZH Rust, PQZL C, LaZer fork; Codex aborted, out of credits; four Claude reviewers) found a **P0 in PQZL**: `h` is not absorbed before `mu`, `z3`/`z4` not before their Schwartz–Zippel challenges, in all four implementations (C generic, C SV, Rust generic, Rust SV) and the provers, inherited from LaZer. Public issue **lazer-crypto/lazer#28**. Reports `pqz-core/research/code-review-2026-10-19/`; STATUS Open item 11. Rust roll-out on the SCaaS testnet **stopped before live** (never touched; live stays `pqz2`, forgeable v2 — test chain); its calibration runs, the gas rule `min(live, max(run1, run2))` and the tooling are merged (`290806e`).

**Fix plan:** `docs/superpowers/plans/2026-10-19-pqzl-fs3.md` (Tasks 0–13, subagent-driven). Owner rulings 2026-10-19 (decisions.md): fix now, before the other Rust-port follow-ups and the token rename; SCaaS testnet reset from genesis at the v3 roll-out; D-2 with Rej1 (no parameter regeneration); z3/z4 absorbed with the proof's own encoding; binding tests instead of a cheating-prover PoC (no forging tooling); keep the id bump to v3 (v2 removed); add review A (first full security review of the Rust crate) and review B (fix diff + whole-protocol transcript audit) before the merge; wasm32 NTT speed-up on a separate branch after the merge.

**Branch `pqzl-fs3`** (worktree `.claude/worktrees/pqzl-fs3`, pushed): Task 0 done; **Task 1 WIP `c5b2c99`, not reviewed**: C side verified — `check_tbox_fixes.sh` P6-FS FAILs as expected (`pqzl/runs/fs1-before.txt`: mu / V3 / V4 seeds unchanged under h / z3 / z4 mutation, generic and SV). Rust side unconfirmed: `scripts/capped pqz-core/pqzl/rust/run.sh fs1` was interrupted for the shutdown (partial `rust/runs/fs1-test.txt`, `sv_eq_c_sv` ok).

**Next:** (1) rerun `scripts/capped pqz-core/pqzl/rust/run.sh fs1` in the worktree: `fs_bind` must fail as expected, everything else green (`oracle_codec` kind 14 C = Rust); write `.superpowers/sdd/2026-10-19-pqzl-fs3/task-1-report.md`; review Task 1 (spec + quality reviewer); (2) Tasks 2 (C fix + id) → 3 (Rust fix) → 4 (D-2 Rej1, D-3) → 5 (id everywhere, vectors) → 6 (package) → 7 (fuzz 3 × 2 h) ∥ 8 (docs, comment lazer#28, issue for D-2/D-3) → 9 (gate) → 10 ∥ 11 (reviews A, B) → 12 (gate fin, merge, push) → 13 (SCaaS testnet reset with image `pqz4`, gas re-calibration on a quiet host: pause `iii` if the owner agrees). Estimate ≈ 1.5–2 days to the merge. After that: wasm32 NTT limb path, M = 16 Rust rows, minors, then the token rename (`NormalToken` / `WrappedToken`), then P6h / P6i / P6j / P6-PUB.

### Session 2026-10-18/19 (PQZL Rust port merged) — resume here

**State:** main pushed (`5952951`). **PQZL Rust port merged** (branch `pqzl-rust`, Tasks 1–12 + 10b, subagent-driven, per-task reviews, whole-branch review by three reviewers + Codex, fix round `e030291`): crate `pqzl` at `pqz-core/pqzl/rust/` is the production PQZL core, pqz-ffi builds it by default (feature `pqzl-rust`; `pqzl-c` opt-in, fuzz mode `pqzl-diff`); proofs and digests byte-equal to the C core; verifier OOM = `NodeFault` (as the C arena); wasm32 op 7 prove limit M = 8 on Rust. `scripts/capped pqz-core/gate.sh fin` PASS at `e030291` with the new step `rust` (logs `d20cfca`, `pqz-core/runs/gate/fin-*.txt`). D6 (same-run C vs Rust, `pqz-core/pqzl/rust/runs/d6/`): native Rust faster (prove 1.6–2.5×, verify 2.0–2.9×, verify_fast 1.2–1.6×, heap 4–6× below the C arena); wasm32 verify_fast 1.7–2.0× slower (R_TXM8 p99 51.0 ms vs 60 ms). Decisions D1–D8, the wasm M = 8 ruling and the gas proposal are in docs/decisions.md.

**Owner rulings 2026-10-18:** token-family rename target `NormalToken` (TokenKind `NONE` → `NORMAL`), after P6; PQZH 128-bit post-quantum target deferred again (calldata ≈ 7 M gas).

**Next:** Rust port follow-ups in TODO.md (roll-out on the SCaaS testnet with gas re-calibration first; wasm32 limb path; M = 16 rows; minors) → token-family rename (owner 2026-10-19: before the rest of P6) → rest of P6 (P6h, P6i, P6j, P6-PUB).

### Session 2026-10-17 (op 7 in the tokens, gates A / B passed; freeze running) — resume here

**State:** main pushed (`270576b`). **P6g op 7** merged: `pqzTransfer*` = op 7 `R_TXM` (payload `… ‖ M ‖ salt ‖ UA_0 … ‖ out ‖ [memo]`), `pqzTransferSingle*` = op 1, `multiLegFee` (owner: built, default 0), disclosure by leg, statement views by DELEGATECALL into `PqzLib` (PQZ tokens 45,734 / 58,177 B); e2e on the SCaaS testnet 132 ok (op 7 M = 4 10.1 M gas, M = 2 9.29 M, M = 8 commit-reveal 9.31 M); stack redeployed (registry `0x4bfb288c19f63b71ae22d326d39c865836c40d10`, factory `0xc296183e59995cebeeb090cae53226874c83b735`, log `smartcontracts/evm/runs/2026-10-17-p6g-op7-7622.txt`). **Gates A and B passed** (`pqz-core/gate.sh 2026-10-17`; CI `pqz` job added and green; Ligero ZK review `docs/research/pqzh-ligero.md` §12); both proofSystemIds frozen (decisions CTR-PQZ-09). Also: secp256k1 kind (0x0108) and CTR-UA-06 (every derived kind on every chain); msig in the per-kind list; pre-existing harness failures fixed; 39 worktrees removed; smartcontracts/evm README rewritten; "TON default seed" PBKDF2 constant restored; ua-dart secp256k1.

**Running:** the freeze `--full` (output lands in `pqz-core/pqz-core/artifact/runs/freeze-2026-10-17`, move it to `pqz-core/artifact/runs/`, then `results.py freeze`).

**Next:** freeze → PQZL Rust port (plan `docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`, subagent-driven, 12 tasks). Open owner question: 128-bit post-quantum soundness target for PQZH (needs a new parameter set and id).

### Session 2026-10-17 (S7 done; secp256k1 kind) — resume here

**State:** main pushed. **S7 merged** (`p6-anon-s7`): pq-zero-knowledge.md §7.4.1 CTR-PQZ-25 (two transfer paths: `pqzTransfer*` = op 7, `pqzTransferSingle*` = op 1) and CTR-PQZ-26 (`R_TXM`, checks, effects, storage / memo, auditor, per-leg disclosure, decoy budget), CTR-PQZ-19 group seeds, §9.1 decoder, §9.3 live `G_7` table, §12 T21–T26, §14 op 7 vectors; decisions D1–D21 and S9 proposals recorded. **UA registry:** the per-kind list includes `msig` (owner); **CTR-UA-06 changed (owner 2026-10-17):** every derived kind is registrable on every chain, also where the key is native (a native key registers a derived id, separate from its native id, the same on every chain); **new kind `secp256k1` 0x0108** (ECDSA `x ‖ y`, sig `r ‖ s ‖ v`, low-s, `Secp256k1Verifier`, keyHash group secp256k1 shared with bip340), vectors appended, all clients (JS, Rust, Python, Go, C#, ua-c, ua-cxx; ua-qt not built here: no Qt SDK on this host). Redeployed on the SCaaS testnet — registry `0x4bfb288c19f63b71ae22d326d39c865836c40d10`, factory `0xc296183e59995cebeeb090cae53226874c83b735`, `Secp256k1Verifier` `0x30811fc2cb742e4928b94fa3edc30b33b0d41289` (log `smartcontracts/evm/runs/2026-10-17-ua-secp256k1-7622.txt`, 98 ok; secp256k1 register 143,766 gas, `requireAuthorized` ≈ 91.5 k incl. intrinsic). forge 1273 passed.

**Next:** op 7 entry points in the PQZ tokens (P6g: `pqzTransfer*` = op 7, `pqzTransferSingle*` = op 1, `INLINE_MAX_PQZH` 10, `multiLegFee`) → gates A / B → freeze → PQZL Rust port (subagent-driven).

### Session 2026-10-17 (UA index done) — resume here

**State:** main pushed. **UA registry per-kind list merged** (`ua-index`, CTR-UA-29): `uaCount` / `uaAt` / `uaPage` / `uaIndex`, every kind incl. msig (owner 2026-10-17), ≈ +27 k gas per registration, gen 2 forwards gen-1 kinds; forge 1272 passed; redeployed on the SCaaS testnet — registry `0x4bfb288c19f63b71ae22d326d39c865836c40d10`, factory `0xc296183e59995cebeeb090cae53226874c83b735`, verifiers and PQZ tokens new (log `smartcontracts/evm/runs/2026-10-17-ua-secp256k1-7622.txt`, 92 ok); the P6g deployment of 2026-10-16 stays on chain unused. Owner Q&A today: natives are not auto-registered (cannot be decoys); registration is already relayable (no `msg.sender` state).

**Next:** S7 (CTR-PQZ-25/-26, S9 proposals 1/2/4, the plan's gas tables incl. S8's `G_7` rows) → op 7 entry points in the PQZ tokens → gates A / B → freeze → PQZL Rust port (subagent-driven).

### Session 2026-10-17 (S8 done) — resume here

**State:** main pushed. **S8 merged** (`p6-anon-s8`): op 7 live in the `PQZ` precompile on the SCaaS testnet since T = 1792205116 (2026-10-17 09:45 +07) — a second `engine.Pqz` schedule with 14 op 7 rows per `(proofSystemId, M, auditorOn)` (3,625,000–6,177,000 gas), image `scaas/nethermind-pqz:1.39.0-pqz2` (library `4fc1a6a2…`), data kept; backup `/home/dockers/mba-chain-nethermind-backups/op7-20261017-093001`; probe 389 ok before / after T, e2e 76 ok; harness 60 min CLEAN; copy rehearsal logs `pqz-core/nethermind/runs/2026-10-17-s8-copy-*`. Rollback: RUNBOOK § op 7. Image `pqz1` kept locally for rollback; `pqz2-calib` kept for re-calibration.

**Also today (owner rulings, in TODO.md):** licence scope rewritten (per company; silk / leather / fur any scale incl. second-hand; processing / financing / live animals for slaughter any scale; 10% only for selling / distributing / marketing / transporting; secondary services not excluded; vegan company free whatever its revenue or group; version stays 1.0); README §3 / §12 family tables (EVM row, chains column, links, GRAM = ex-TON, NEAR / Algorand planned, Base / TRON as EVM profiles); docs TON → GRAM; token-tree / chain-families figures; pqz-core README op 7; Zether BLS12-381 precompile in Rust after the PQZL Rust port (build option, default off); bn254 MSM precompile cancelled.

**Next:** the UA Registry per-kind index (owner: right after S8; TODO item, redeploy on the SCaaS testnet) → S7 (CTR-PQZ-25/-26, S9 proposals 1/2/4, gas tables incl. the S8 `G_7` rows) → op 7 entry points in the PQZ tokens → gates A / B → freeze → PQZL Rust port (subagent-driven, plan approved).

### Session 2026-10-17 (S6 done) — resume here

**State:** main pushed. **S6 merged** (`p6-anon-s6b`; WIP branch `p6-anon-s6` kept as record): op 7 in the package's default stages, `expected-results.json` regenerated once (freeze-txm), Docker quick PASS 199 ok, `--multi-bench` Docker PASS (44 min). **PQZL Rust port plan merged** (`docs/superpowers/plans/2026-10-17-pqzl-rust-port.md`, owner-approved D1–D8, subagent-driven, after the freeze). Owner rulings today in TODO.md: Rust port in `pqzl/rust/`; bn254 MSM precompile cancelled; Zether BLS12-381 verifier precompile in Rust after the PQZL Rust port (precompile where a chain has it, Solidity elsewhere; `Nethermind.Pqz` build option, default off).

**Next:** S8 — op 7 in the live precompile (Nethermind.Pqz op 7 gas entries per built (M, A), calibration p99 over 1,000 valid + adversarial inputs on the chain-host image, throwaway SCaaS testnet copy first, then activation on the SCaaS testnet; image rebuild: libpqz_ffi.so sha256 changes with the layout) → S7 (CTR-PQZ-25/-26, S9 proposals 1/2/4, plan gas tables) → op 7 in P6g tokens → gates A / B → freeze → Rust port.

### Session 2026-10-17 (morning) — resume here

**State:** main pushed. **Layout move merged** (`pqz-layout`, merge `9f07324`): `pqz-core/pqzl/` (PQZL C core + tools), `pqzh/{ligero,xcheck,stark-backup}`, `research/{pqzl-measure,opt,floor,upstream}`, shared crates at the top; spec now `docs/contracts/pq-zero-knowledge.md`. Verified (plan §Applied): relfix `proofs_fnv` = `tx0c`, KAT 19/19, tbox / SV fix checks, ffi self-test `ed910a2c…d205`, vectors `--check` byte-identical, ligero tests, fuzz build, glic, docs_check 0 errors; two harness failures predate the move (STARK backup `tx_stmt` xcheck, `research/floor` `count.c`). The PQZL build output is now `pqzl/build/` (old `pqz-core/build/` holds only stale outputs + `build/fuzz`).

**Owner 2026-10-17:** PQZL Rust port goes to `pqz-core/pqzl/rust/` (crate `pqzl`); TODO bn254 MSM precompile for classical Zether (later, MSM only, no full Zether precompile).

**Next:** S6 from `fdfc3ce` on `p6-anon-s6` written against the new layout (paths `research/pqzl-measure/txm-bench.sh`, `pqzh/ligero`; README; regenerate the pqz-ffi digest lines 29 vs frozen 17 and `expected-results.json` once; Docker quick + multi-bench, `--memory=4g`, run alone) in parallel with the PQZL → Rust port plan (docs only) → S8 → S7 → gates A / B → freeze → Rust port.

### Session 2026-10-17 (early) — resume here

**State:** main `b547e3d`+ pushed. **S5 merged** (`p6-anon-s5`): 2-hour campaigns per target with op 7, no finding — precompile 3,012,684 execs (205,263 op 7 decoded), mutate 192,360 (473 SV = generic differentials, 108 op 7), codec 1,103,090 (137,333 PQZL proofs re-encoded byte-equal); arena peak 268,240,256 B (ARENA_SMALL 512 MiB). A machine reboot (2026-10-16 20:07) stopped the first precompile campaign after ≈ 42 min (log `-interrupted`, no finding); re-run in full. docs_check 0 errors. SCaaS testnet node restarted after the reboot (head advancing, PQZ-START ok).

**Side discussion (owner, no decision):** cross-chain transfer by an attesting UA m-of-n group (lock / burn → group signs → anyone relays → mint), Zether / PQZ ciphertexts credited without a proof on the destination, on-chain `attest` + timeout refund, bonded signers (6-month exit, destination epochs expire). Private draft `scratchpad/crosschain-bridge-draft.md`; ordered after the freeze / gates / P6h–P6j.

**Next:** layout move + spec rename (re-check `docs/superpowers/plans/2026-10-15-pqz-core-layout.md` against today's tree: `nethermind/`, `params/anon/`, fuzz `regress/`) → S6 from `fdfc3ce` written against the new layout, in parallel the PQZL → Rust port plan (docs only) → S8 → S7 → gates A / B → freeze → Rust port.

### Session 2026-10-16 (evening) — resume here

**State:** main `86a688e` (local, not pushed). SCaaS testnet node started after power-on (head advancing, `PQZ-START` selftest `ed910a2c…d205`). Stale worktrees s3 / s4 / s9 / p6g / oog removed (branches kept).

**Running:** S5 fuzz on `p6-anon-s5` (worktree `.claude/worktrees/s5`): step 1 committed `b556499` (targets cover op 7; stray `fuzz/crash-b9881dfc…` = valid input, moved to `regress/valid/`); then smoke runs, 3 × 2 h campaigns one after another (precompile → mutate → codec), expected done ≈ 02:00 on 2026-10-17. Owner: wait (no shortened / parallel campaigns; RAM ≈ 7 GB free). **Reboot 2026-10-16 20:07:** precompile campaign interrupted after ≈ 42 min (868 k execs, no finding; log kept as `runs/2026-10-16-s5-precompile-interrupted.txt`); node restarted (head advancing, PQZ-START ok); all 3 campaigns relaunched 20:11 via `scratchpad/s5-campaigns.sh` (detached, log `scratchpad/s5-campaigns.log`), expected done ≈ 02:30 on 2026-10-17.

**Owner rulings today (TODO.md l.32):** layout move after S5 merges, before S6's Docker run; S6 postponed entirely until after the layout move (written against the new layout). S6 WIP `fdfc3ce` on `p6-anon-s6` (worktree `.claude/worktrees/s6`): `--multi-bench`, op 7 checks, `freeze-txm` in results.py; remains: port paths (`rel3/txm-bench.sh`, `pqzh/ligero`), README, phase 2 Docker (quick 35–45 min + multi-bench ≈ 1 h, `--memory=4g`; M = 16 3 GiB arena untested in Docker). Finding: the artifact quick run on main fails today (wasm32 M = 8 verify-only rows — fixed in WIP; pqz-ffi digest lines 29 vs frozen 17 — needs the one-time regeneration).

**Next:** S5 report → review → merge + push → layout move + spec rename (re-check the 2026-10-15 layout plan against today's tree: `nethermind/`, `params/anon/`, fuzz `regress/`) → S6 from `fdfc3ce` (in parallel: write the PQZL → Rust port plan, docs only; facts in `scratchpad/pqzl-rust-port-notes.md`; licence Vegan Community License) → S8 → S7 → gates A / B → freeze → Rust port (TODO.md l.32).

### Session 2026-10-16 (second, shutdown afternoon) — resume here

**State:** main `b9327b6`+ pushed. Merged + pushed this session: `p6-anon-s9` (S9 node limits, all unchanged; `pqz-core/pqzl/params/anon/s9_limits.py`), `p6-anon-s3` (op 7 in pqz-stmt / pqz-ffi; arenas 512 MiB / 1 GiB; D3 PQZL {1,2,4,8} PQZH {1,2,4}), `p6g` (PQZ contracts, deployed on the SCaaS testnet, e2e real PQZL proofs 89 checks 0 failures; addresses + gas in `smartcontracts/evm/runs/2026-10-16-p6g-7622*.txt`, pq-zero-knowledge.md §9.3), `p6-anon-s4` (op 7 vectors; frozen diff = only the two `negative.json` reasons `Op` → `OpTag`). Controller checks before merge: size gate 0 errors (90 contracts), docs_check 0 errors, Ligero crate tests 38/38, `pqz_prove` example builds on merged pqz-ffi, `pqz_kat.py --check` ok.

**Owner ruling 2026-10-16:** PQZL M = 8 on a BUNDLE token — NO automatic COMPACT; the user chooses the storage mode per transfer, the contract never switches (decisions.md CTR-PQZ-23 Change, plan S9 proposal 3). S9 proposal 2 (PQZH ≤ 10 inline credits) still a controller proposal.

**Measured gas (SCaaS testnet, P6g):** `pqzTransfer` BUNDLE auditor on 10.72 M (spec's old ≈ 2.8 M was low: precompile 5.41 M + SSTORE2 bundle + ≈ 80 KB calldata); v3 envelope 11.41 M; unshield ≈ 5.55 M. S3's plan gas rows (2.9–4.6 M) use the old 0.12 M gas/ms; S9 re-based at live 0.359 M/ms (PQZL op 7 5.41–7.80 M est.) — S7 fixes the plan tables, S8 calibrates.

**Done after the handoff:** `fix-ligero-oog` merged + pushed (root cause: 108 mutations in one EVM call frame, quadratic memory gas over forge's 2^30; now one frame per mutation + 7 `test_other_*`; full forge suite 1269 passed, 0 failed). Owner rulings recorded (decisions.md CTR-PQZ-23): op 7 BUNDLE no early revert (wallet explains); PQZH op 7 ≤ 10 inline credits. Owner ruling (same day): M counts legs (real + decoys), so odd recipient counts pad with decoys (7 real ⇒ M = 8, 1 decoy); for auditor-on BUNDLE shapes over the cap the wallet (P6h) offers (a) one M = 8 COMPACT / commit-reveal transfer (default, ≈ 10.4 M) or (b) split into fitting BUNDLE transfers (e.g. 2 × M = 4, ≈ 21.4 M total), user chooses (decisions.md CTR-PQZ-23).

**Next (owner: S5 / S6 not started because of shutdown):** S5 fuzz (op 7 seeds from S4 rows; 3 × 2 h capped) → S6 artifact (Docker, run alone, `--memory`) → S8 (op 7 into Nethermind.Pqz image, calibrate `G_7`, activate on the SCaaS testnet) → S7 (CTR-PQZ-25/-26, S9 proposals 1/2/4, gas tables) → op 7 entry points in P6g tokens; PQZH token on chain (no PQZH gas yet). Open from P6g: `UnderlyingPqzToken` 62,572 B (2.9 KB under 64 KiB), no pinned storage layouts for PQZ tokens, SCaaS testnet gen-1 registry has no classical kinds. Open from S4: op 7 disclosure-bundle / per-leg opening vectors (needs a pqz-stmt codec).

**After power-on:** `cd /home/dockers/mba-chain-nethermind && docker compose up -d blockchain-node`; `python3 -I pqz-core/nethermind/chain/e2e.py head --rpc http://127.0.0.1:8545`. Stale worktrees from this session (s3, s9, s4, p6g) can be removed (`git worktree remove`), branches kept.

### Session 2026-10-16 (shutdown ~06:30 +07) — resume here

**State:** main `dee0a21`+ pushed, clean. Merged / done this session (all pushed):
- `p6-anon-h` (`67e5cca`) — Track H, PQZH Ligero `R_TXM` op 7, built M ∈ {1, 2, 4} auditor on / off (exact max 236,196 B, input 369,193 B at (4, on); verify p99 ≤ 16.05 ms native / 28.85 ms wasm32; 127.2 bits); M = 8 / 16 oversize only. pqzh-ligero.md §15.
- `p6-anon-l` (`13870e5`) — Track L, PQZL `R_TXM` op 7, built M ∈ {1, 2, 4, 8}; per-vector ℓ2 e2 ≤ 64 (owner X-1); MSIS β 452–459, MLWE β 470; proofs 42.8–61.8 KB; SV verify p50 7.9–12.9 ms native; fixed SV refusing every honest M = 8 proof (`z1bnd`); ASan + UBSan clean; SV vs generic 0 mismatches; fuzz smoke only (275 runs).
- `p6f` (`a243650`) + **Task 10 live** (`a4fb6f0`): SCaaS testnet RESET 2026-10-16 with `engine.Pqz` from block 0 (path B), image `scaas/nethermind-pqz:1.39.0-pqz1` (`c53359a69bfa`, local only), genesis hash unchanged `0x24e43dcb…c464`; PQZ-START ok, probes + e2e pass (`pqz-core/nethermind/runs/2026-10-16-live.txt`). Backup `/home/dockers/mba-chain-nethermind-backups/pqz-20261016-004736` (+ old `data/nethermind_data.bak-20260831-090830`) kept. Gas limit ramps 16.8 M → 80 M by itself.
- `pqz-core/README.md` updated (`dee0a21`): live precompiles, op 7 table §5.4, `nethermind/`.

**Owner decisions 2026-10-16** (TODO.md, decisions.md CTR-PQZ-10 and CTR-PQZ-03 Change 2026-10-16): controller ran Task 10; the five P6f proposals accepted (3 reset chainspec params; drop bogus `Mining.MinGasPrice` → clients pay baseFee + tip; follower gossip stall = known issue; keep backups, copy scratch deleted; ML-DSA 49k / 68k on the SCaaS testnet, re-measure before 22776); **node verify arena `ARENA_SMALL` 144 → 512 MiB when op 7 lands in pqz-ffi**. Controller proposals with it: `ARENA_BIG` 448 MiB → 1 GiB; wasm PQZL `R_TXM` M ≤ 4 only.

**After power-on:** the SCaaS testnet node has NO restart policy — `cd /home/dockers/mba-chain-nethermind && docker compose up -d blockchain-node`, then `python3 -I pqz-core/nethermind/chain/e2e.py head --rpc http://127.0.0.1:8545` (head advancing, `PQZ-START` in `docker logs`). Hourly 24-h watch (RUNBOOK step 5) was not automated.

**Branches waiting (both = `dee0a21`, no commits; agents stopped at shutdown after reading only; worktrees gone — re-create):**
- `p6-anon-s3` — P6-ANON S3 (op 7 into pqz-stmt / pqz-ffi). Resume plan from the agent:
  1. pqz-stmt: add `Stmt::Multi(Multi)`, route op 7 in `parse` / `decode_input` to `parse_multi` (S2 left `Reject::Op`), `proof_system_id()` = word 1; new arms in Ligero `cs.rs::parse` (~l.342) and pqz-ffi; fix `Honest::from_input` (`form().unwrap()`) and the `negatives()` "op 7 ⇒ Reject::Op" expectation.
  2. pqz-ffi dispatch is nearly free (C `pqz_verify_fast(7,…)` and Ligero `verify(7,…)` exist); no `decode.rs` (decoder lives in pqz-stmt) — record as plan deviation; `OVERSIZE` const assert keeps oversize ⇒ `…00`.
  3. Arenas in `pqzl.rs`: native `ARENA_SMALL` 512 MiB, `ARENA_BIG` 1 GiB (R_TXM8 prove ≤ 836 MB with all relations loaded); wasm32 single arena ≈ 448–512 MiB (to decide; L3 wasm `R_TXM4_0` all-loaded 432.7 MB); `prove` refuses PQZL op 7 M = 8 on wasm32 via `ProveError::Statement(Reject::Legs)`.
  4. `prove` feature: multi-group Enc wrapper (closes L-6; extern `pqz_enc_group_seed`), op 7 witness layout `s_f ‖ e_f ‖ (r_g ‖ e1_g)_g ‖ e2_j ‖ e2_f ‖ [e2_{a,j}] ‖ d_j ‖ d′`, `recipientsHash` + memo (HKDF-SHA256 per CTR-PQZ-23 / CTR-ZTH-50 — pqz-ffi has only `sha3`; check offline crates), fixtures for every built (M, A) of both ids.
  5. Tests: built op 7 ⇒ `…01`; S2 negatives ⇒ `…00`; max input ≤ `MAX_INPUT`; 8-thread determinism + new arena margin (`verify_only.rs`); wasm32 digest incl. smallest `R_TXM`; bench rows; frozen vectors unchanged (`vectors/run.sh`, `pqz_kat.py --check`, selftest `ed910a2c…d205`). One capped `pqz-core/ffi/run.sh s3a`.
  6. D3 verdict (record): PQZL {1, 2, 4, 8} (M = 16 input ≈ 469 KB > 393,216); PQZH {1, 2, 4} (M = 8 bound 281,208 > 262,144 and input 497,149 > `MAX_INPUT`; M = 16 likewise) — matches `built_legs`.
  7. `params/anon/anon_sizes.py` reads measured numbers; STATUS.md entry; plan S3 results; decisions.md lines. LH-2 stays S4.
- `p6g` — P6g contracts + SCaaS testnet deploy (owner mandate: deploy on the SCaaS testnet without per-step approval). Plan NOT written yet: `docs/superpowers/plans/2026-10-16-p6g-contracts.md`. Still to read: decisions.md CTR-PQZ-*, accounts.md, P6c / P6f plans. Agent's design notes (to become D1…, controller proposals):
  1. Mirror the Zether layer: `PqzLayer` (abstract, on `MetaTokenBase`) + `PqzLib` (external, ERC-7201) + kinds `NoUnderlyingPqzToken` (`NONE_PQZ`, 4) and `UnderlyingPqzToken` (`UNDERLYING_PQZ`, 5); `pqzShield` burns public units like `zetherShield` (spec §7.3 `transferFrom` predates the token tree — record); `pqzWrapShield` / `pqzUnshieldUnwrap` on UNDERLYING (CTR-PQZ-22); `NONE_ZETHER_PQZ` / `UNDERLYING_ZETHER_PQZ` stay reserved; `OpenFactory.pqzEnabled` + `setPqzEnabled` (gated by `PqzSafety`), `KindReserved` up to 5.
  2. `PqzSafety`: allowlist {31337, 1337, 7622} + `selfTest()` (STATICCALL op 6 on `0x…0f01`, exactly 32 B = `0xed910a2c…1333d205`).
  3. `UAPqzVerifier`: op 3 on `opTag(REGISTER) ‖ psid ‖ message ‖ pk`, psid immutable (PQZL v2); constructor self-test + R_REG vector (1, bit-flip 0); registry slot `_CFG18` exists; kind cap ≈ 2.8–3 M measured, `verifyBudget` ≥ it.
  4. v3 UA path: virtual `_uaEnvelopeBinding(m)` hook (default 0) in `ERC20MetaTx._uaExecute`, PQZ overrides with `SCAAS-PQZ-UA-ENVELOPE-V1`; PQZ selectors refused in `mtxBatch` / `uaBatch`.
  5. SCaaS testnet code size limit 64 KiB from block 0: no size work; record sizes in `size-baseline.json`.
  6. Forge: `vm.mockCall` on PQZ with a real `PqzCt`.
  7. E2E with real proofs: small `pqz-ffi` example under `--features prove` (stdin op, stmt, wit, rnd → proof), statements from the token's views, `pqz_kat.py` for keys / Enc; ML-DSA signing via `@noble/post-quantum` 0.7.1 (`clients/clientkeys/node_modules`).
  8. Op 7 entry points later (after S3–S8).
  Then deploy on the SCaaS testnet: registry gen 1 with the PQZ + ML-DSA precompile verifiers, factory, tokens; logs in `runs/`. Funded test keys in genesis: 0x…01–0x…04 (P6f e2e used 4).

**Resume:** start a session, say "resume"; start the node (above); re-dispatch S3 and P6g agents from the two notes above (capped 2 slots, never `timeout … scripts/capped`, `-j2`, docker `--memory`, commit per task, stop at branch). Agent tooling notes: in worktrees use literal absolute paths (no globs / `$VAR`), `/usr/bin/git -C <worktree>` for git, `rtk proxy grep` for raw grep. Then S4–S9, layout move + spec rename, gates A / B, freeze, P6h–P6j, publication drafts.

### Session 2026-10-15 (shutdown at 12:00) — resume here

**State:** main `7c497b6`+ pushed. Merged today: `pqz-readme` (README rewrite), `pqz-artifact2` (Docker package for PQZL + PQZH, quick PASS 148 / host 159), `p6e-a5` (fuzzing: ≈ 3.2 M inputs, no finding), `p6-anon-s` (`R_TXM` S1 hint estimate + S2 op-7 codec). Owner decisions today (all in TODO.md / decisions.md): β 446 accepted for `R_TXM` shared-randomness hints (groups of 4); PQZ = Post-Quantum Zero-knowledge (spec file → `pq-zero-knowledge.md` in the layout move); pqz-core layout approved with `research/` (`rel3/` → `research/pqzl-measure/`); SCaaS testnet = testnet (resettable), 22776 = future mainnet; fee = 0 valid; general-purpose circuits on Ligero = research only (`docs/research/pqz-general-purpose.md`).

**WIP branches (worktrees `.claude/worktrees/{anonl,anonh,p6f}`; WIP commits made just before shutdown):**
- `p6-anon-l` (WIP `56354f4`) — Track L, PQZL `R_TXM`. Done: specs `params/txm{2,4,8}[0]` + oversize `txm16[0]`, codegen (6 old headers byte-identical; estimates 45,166 / 46,222 / 62,002 B for M = 2 / 4 / 8 with auditor), general debit builder in `pqz_rel.c` (op 7 by header words; M = 1 reuses R_TX / R_TX0 with tag 0x70|A<<3|log2 M), D13 group seed, SV generalised, bench / wasm / diff harness extended; compiles native, wasm32, oversize; NOTHING run. Next: (1) capped estimator sizing `run_e_s1.sh … txm2 txm4 txm8 txm20 txm40 txm80 txm16 txm160` (LaZer + estimator checkouts were in the agent's /tmp scratchpad — re-clone if gone); (2) `build.sh all` + bench with checks + `proofs_fnv` of the six old forms unchanged; (3) rest of L2 (diff with `n_txm`, z21diff, check_sv_fixes, sv_fuzz byte); (4) L3 measurements + docs. Risk: wasm prove peak for M ≥ 2 vs 256 MiB (R_TX already 232 MB).
- `p6-anon-h` (WIP `d73f33a`) — Track H, PQZH Ligero `R_TXM`. Done: constraint system (shape from M / auditorOn words, M checked against the built set first; witness `s_f ‖ e_f ‖ (r_g ‖ e1_g)_g ‖ e2 ‖ d_j ‖ d'`, M = 1 = R_TX / R_TX0 witness), `tests/multi.rs`, bench, wasm, `xcheck/kat_multi.py`, `runs/txm.sh`; NEVER compiled. Next: fix compile errors, then one `CARGO_BUILD_JOBS=2 scripts/capped pqz-core/pqzh/ligero/runs/txm.sh l16-txm` (tests, oversize, gate-B native + wasm32, FNV of the six P6e forms, cross-checks); pin op-7 maxima in `limits_exact`; `pqzh-ligero.md` §15 + plan rows. Estimate M = 4 + auditor max ≈ 236.2 KB < 260,219 B (keep, to be measured). Deviation: each e2 bounded by 64 (stricter than the plan's 64·√M).
- `p6f` (WIP `0881759`) — Tasks 1–3 done (`0a155da`): plugin, strict `engine.Pqz`, PQZ + ML-DSA-44/65 precompiles; 36/36 tests in the pinned SDK image; ML-DSA via .NET `MLDsa` / OpenSSL 3.5.5 in the node image (host OpenSSL 3.0 lacks it — fine); precompiles may activate from block 0 (fresh SCaaS testnet genesis allowed). Written, not run: image build (T5), calibration (T6), copy-chain scripts + probes (T7), Task 10 runbook draft `pqz-core/nethermind/chain/RUNBOOK.md`. Next: 10-min harness smoke (first run's failures were a harness bug, fixed; its log will be overwritten), 1-h harness, image, calibration ×2, T7–T8 on the copy (both activation paths), T9 docs. Deviation (controller accepts): the copy is a replica from the live chainspec parameters with a throwaway signer key, not the live data / key. Task 10 (live SCaaS testnet) NOT started; live container stopped and untouched.
**Resume:** start a session, say "resume", re-dispatch the three agents from their WIP commits (each briefs: capped heavy jobs queued once, NO `timeout … scripts/capped`, `-j2` / `CARGO_BUILD_JOBS=2`, containers with `--memory`, commit after each task). Then: review + merge each; S3–S9 (pqz-ffi op 7, vectors, fuzz, artifact, SCaaS testnet precompile, spec); layout move + spec rename; gates A / B; freeze; P6f Task 10 live on the SCaaS testnet; P6g → P6j; publication drafts.

**Second checkpoint 12:25 (owner shut down again) — newest WIP heads, use these:** `p6-anon-l` `f648002` (sizing done `params/estimator-e-s1-txm.txt`; bench extended; first `txm.sh l1a` found a bench array overflow via UBSan, fixed by sizing proofs[] / lens[] for 16 relations — rerun `txm.sh l1a`); `p6-anon-h` `cc6c292` (op 7 compiles, 0 errors / 0 warnings; next: merge main, `cargo test --release --test multi`, `runs/txm.sh l16-txm`); `p6f` `006643b` (Task 4 10-min harness smoke clean, 1,040,292 inputs; redo the 1-h harness and the image build; then one calibration, T7–T8, T9). The lines below give the older heads; steps still apply.

**Owner answers 2026-10-15:** P6f gas calibration = one run. Two concurrent capped jobs: YES — `scripts/capped` has 2 slots (`heavy`, `heavy.2`).

### Session 2026-10-14/15 (session 4: P6 mandate, PQZH = Ligero, P6e nearly done, P6-ANON R_TXM, P6f) — resume here

**State:** main `1783ea8` pushed. Merged this session (all pushed): ZK WHIR negative result + re-examination; Ligero
(PQZH backend, proven, + EVM verifier measured 534.6 M gas → needs the precompile); StarkEx study; `pqz-artifact`
(Docker package, freeze postponed); P6e plan + tasks 1–9, 11, 12 (`p6e-a1`…`a4`, `p6e-a6`, `p6e-b1`…`b3`: hedged
provers, keys from seeds, R_TX0, `pqz-stmt`, Ligero six forms, D3 id, exact bounds, `pqz-ffi` (one precompile for both
ids, status 3 / 4, 144 MiB arena), vectors (15 files, generator in `pqz-core/ffi/src/bin/pqz-vectors.rs`), pq-zether
§8.1 Serialization v1); P6-ANON plan (`docs/superpowers/plans/2026-10-14-p6-anon.md`); P6f plan
(`docs/superpowers/plans/2026-10-14-p6f-precompiles.md`); README §16 use cases (prepaid service passes, item / credit
conversion recipes) + `docs/guides/item-economies.md`; `docs/research/pqzh-backend-comparison.md`.

**Owner decisions this session:** all in TODO.md (mandate: carry P6 to its end, merge + push per sub-phase after review;
controller proposals recorded in decisions.md "owner may override"; PQZH proven Ligero; verify limit 60 ms; one PQZ
precompile for PQZL + PQZH; no PQZH without the precompile; Docker package covers both systems; P6-ANON = PQZ
multi-recipient transfer `R_TXM` (sender visible, one proof, decoys Enc(0)), USED by SCaaS, both paths kept (op 7 multi +
op 1 single), D21 freeze once after op 7, D20 no limit raise (PQZL M ≤ 8, PQZH M ≤ 4), D16/D17 no on-chain decoy rule;
fee = 0 valid for Zether and PQZ; P6f precompiles run LIVE on the SCaaS testnet (controller procedure: copy first, backups, rollback);
publication drafts (ePrint + ethresear.ch, kept private in `scratchpad/pub/`) after P6 + P6-ANON + live SCaaS testnet).

**WIP branches (worktrees under `.claude/worktrees/`, agents resumed after the 2026-10-15 restart):**
`p6e-a5` (Task 10 fuzzing), `pqz-artifact2` (Docker for both systems; pinned apt snapshot required), `p6-anon-s`
(S1 hint estimate + S2 `pqz-stmt` op 7), `p6f` (Tasks 1–9 on a throwaway copy; Task 10 live NOT started — the live
SCaaS testnet container is stopped and untouched). Next: review + merge each; P6-ANON tracks L / H; gates A / B and the freeze;
P6f Task 10 live after the copy gate; P6g → P6j; publication drafts.

### HANDOFF — scaas

### Session 2026-10-14 (shutdown 3: z21 merged, PQZH next steps, artifact WIP) — resume here

**State:** main pushed at the HANDOFF commit. Merged and pushed since the last HANDOFF (`c2f2e0d`): `pqz-l2-domain` +
`pqz-tbox-soundness` (P6-SZ / P6-L2 fixes, `5361946`), `pqz-relfix` (`04ccd85`), `pqz-v2` (proofSystemId v2 =
`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`, `98695de`), `ua5b` (UA-5b trade and DEX, `1b9e244`),
`pqzh-proto` (`f78056c`), `pqzh-sol` (`be81b7c`), `pqz-sv-relfix` (P6-SV specialised verifier on all five relations,
`dcf0da3`), `pqz-v2-run` (`0e7da0c`), `pqz-publish` (tbox write-ups, `099039a`), `glic-inventory` (G-LIC step 1,
`9f6677f`), `pqz-z21` (z21 norm check, lazer#26, `a8b5b66`), `pqzh-next` (PQZH ZK + Goldilocks⁵, Merkle caps, WHIR,
Plonky3 0.9.0-rc.1, `9fc5714`); research note `pqz-anonymity.md` (`623a455`). LaZer issues public: lazer#24, #25, #26;
follow-up comment on #26 (paper condition LNP22 Fig. 18, impact β 452–461 → 286–311, fix, hint ℓ∞ side note).

**Owner decisions this session (recorded in TODO / decisions.md):** priority "P6 first, finish the WIP, then focus on
PQZ" (UA-5c and UA F5 paused); token-family rename `UnderlyingToken` → `WrappedToken`, `NoUnderlyingToken` →
`NormalToken` after P6 (owner 2026-10-18; was `IssuedToken`); z21: merge `pqz-z21` (done) and **no proofSystemId bump** (every v2 verifier checks
‖z21‖² + ‖w − γ·w1‖² ≤ Bsq; decisions.md CTR-PQZ-03); merge `pqzh-next` with the Plonky3 0.9.0-rc.1 upgrade (pin 0.9.0
final when released); **PQZH is not shelved**: next build and measure a ZK WHIR path and a Ligero backend, then decide
soundness regime, proof limit / `MAX_INPUT`, prover memory target, the PQZH proofSystemId string and the backend;
P6-PUB (ethresear.ch + ePrint, PQZL only, source-only reproducibility package, numbers frozen after the z21 merge,
README §11 PQZ subsection + headline line without LaZer-findings text, results mail to the LaZer maintainers after the
freeze, separate from the G-LIC letter); G-LIC is a production gate, not a publication prerequisite (step 1 done,
step 2 letter drafted, step 3 preliminary patent search done, step 4 lawyer = owner); order changed 2026-10-14:
Docker package before the freeze run.

**WIP branches (worktrees under `.claude/worktrees/`; local only, not pushed; agents stop at the branch):**

1. **`pqz-artifact`** (worktree `artifact`, last `ed0aa43`) — P6-PUB reproducibility package `pqz-core/artifact/`,
   written, **not tested**: `Dockerfile` (ubuntu:24.04 by digest, apt from snapshot `20261013T000000Z`, clang/lld 18.1.3,
   gcc 13.3.0, cmake 3.28.3, node 26.8.1 by sha256, LaZer 3330e48 source only), `reproduce.sh` (quick default, `--full`,
   `--serve`, `--upstream` building x86-64-v3 + AVX-512 IFMA, running the latter only with `avx512ifma`),
   `results.py` (`check` / `freeze`), `web/index.html`, `README.md` with a "Status / resume" section,
   `expected-results.json` PROVISIONAL (pre-z21 times; `proofs_fnv` match post-z21). The one image build failed at apt
   (snapshot archive is HTTPS-only, base image lacks `ca-certificates`); fixed, not rebuilt (owner: no build before
   shutdown). Risks to check first: `xcheck/shim` compiling against current headers; `http.server` serving `pqz.wasm`
   as `application/wasm`. Runs: `rel3/runs/final-*` complete post-z21 run (rc 0, KAT 19/19, tbox fixes ok, `proofs_fnv`
   equal to v2; times not compared with `v2full` yet); `sv/runs/final-*` interrupted by the owner (portable
   differential 2,710 cases / 0 mismatches kept, rest not run). Resume (owner: no measuring this session): the commands
   in `pqz-core/artifact/README.md` "Status / resume" — image build, quick / `--upstream` / `--serve` tests,
   `docker image rm`; then the freeze `OUT=pqz-core/artifact/runs/freeze-2026-10-14 scripts/capped
   pqz-core/artifact/reproduce.sh --full` + `results.py freeze` → `expected-results.json`, frozen table in
   `pqz-core/STATUS.md` and `pqz-core/README.md`; then (separate tasks) README §11 PQZ subsection + headline,
   ethresear.ch post, ePrint draft, the results mail (`scratchpad/sz-private/results-letter-lazer.md`). Agent's
   question: add a CI workflow running quick mode that stores text / JSON only?
2. **`pqzh-zkwhir`** (worktree `zkwhir`, `9d748ed`) — design note `docs/research/pqzh-zk-whir.md` only, no code. Chosen
   path: Plonky3's ZK batch STARK unchanged + an adapter (`src/whirpcs.rs`, ≈ 600–900 lines) implementing
   `UnivariateStarkPcs` over `p3-whir`'s `HidingWhirPcs` (HVZK WHIR, ePrint 2026/391); rejected: ZK `p3-multi-stark`
   (weeks of unanalysed protocol work), random rows around the non-ZK prover (leaks), recursion, BlindFold. Effort
   3–5 days + 1–2 days measuring; expected `R_TX` ≈ 400–500 KB at Goldilocks⁵ (not measured). Resume: note §7.
   Agent's questions for the owner: (1) accept this path; (2) if it lands above FRI+ZK conjectured (340,431 B), build a
   batched multi-round WHIR opening or settle on FRI; (3) report Goldilocks² only at its reachable 96–100-bit targets.
3. **`pqzh-ligero`** (worktree `ligero`, `11d1493`) — design note `docs/research/pqzh-ligero.md` + parameter model
   `pqz-core/pqzh/ligero/ligero_params.py`, no Rust yet. Field F_q itself (q − 1 = 2^3·19·43·431·1,561,243, generator 3,
   domains 2^a·19^b·43^c ≤ 6,536), challenges in F_q^4 = F_q[X]/(X^4 − 3); model `R_TX` ZK 128 bits ≈ 298 KB proven
   (rate 1/8, t = 166) / ≈ 112 KB conjectured (rate 1/19, t = 35), prove ≈ 0.1–0.3 s, verify ≈ 15–40 / 3–8 ms
   (inferred). Resume: note §7 (crate, tests ≥ 960 mutations, bench + wasm32, capped runs). Agent's questions: (1) add a
   radix-431 FFT stage for longer codes (could lower the proven size); (2) use its modified ZK construction (blinding
   rows at full degree inside the proximity test) instead of the paper's §4.7 text.

**Open owner questions:** the five above; P6e (codegen, serialization v1, `pqz-ffi`, fuzzing, freeze proofSystemId) in
parallel or after PQZH; anonymity (`docs/research/pqz-anonymity.md`: ring N ≈ 8 practical, ≈ 10–12 M gas; or one-time
receiver accounts) — read Lether in full before deciding.

**Owner steps outstanding:** send the G-LIC letter (`scratchpad/sz-private/g-lic-letter-lazer.md`); after the freeze,
the results mail; tag + Zenodo source snapshot for P6-PUB; AVX-512 IFMA run of the upstream comparison; chain 22776
genesis; SCaaS testnet registry redeploy in P6g (gas limit 16,777,216, all four PQ kinds usable); lawyer (G-LIC step 4,
scope PQZ and classical Zether, private note `scratchpad/glic/`) and a cryptographic audit before production.

**Rules in force:** no built binaries on GitHub (no release assets, hosted wasm, pushed images; the xcheck/static
bundle stays local); never push `pqz-sv-fixed`, `pqz-sv-fixed-l2`, `backup/pre-sanitize-60ec820`; `pqz-verifier-floor`
kept local; `scratchpad/` and `docs/reviews/` never committed; heavy jobs only via `scripts/capped`, agents never poll
with until/sleep or `pgrep -f`.

### Session 2026-10-13 (shutdown 2: UA-5b, PQZH, PQZ relations WIP) — resume here

**State:** main pushed at the HANDOFF commit (after `af8ccf5`). Merged and pushed this session: UA-5a (`04bad29`; C5a-15
confirmed), `ua-followups` (UA-2c follow-ups + clientkeys `checkReceiverFee`, `5c5b6f5`), `pqzh-design` (PQZH design
study, `475b066`), `pqz-rel3` (`R_BURN` / `R_DS` / `R_DR` in pqz-core with the generic verifier, `3ad4069`), research:
`pqz-specialised-verifier.md` (P6-SV results; code branch not merged yet), `pqz-proof-alternatives.md` §6 candidates and
§7 prior art (Lether, MatRiCT+, backends), pq-zero-knowledge.md "Why LaZer" refreshed. Private notes live in `scratchpad/`
(git-ignored); read them before touching PQZ branches.

**Owner decisions this session (recorded in TODO):** PQZL not killed (P6-SV: specialised verifier `R_TX` ≈ 8 ms p50
portable, all five relations ≤ 10 ms p99 portable). PQZH: six answers in TODO P6-PQZH — ≤ 160 KB proof for PQZH (PQZL
keeps 96 KB), sweep provable vs conjectured (leaning provable), PQZH tokens register with a PQZH `R_REG`, **"two kinds" =
PQZL and PQZH as one configuration value (`proofSystemId` at `initialize`), the four reserved PQZ `TokenKind`s stay**,
Keccak / SHAKE transcript, prototype now. PQZ relation points A, B, 1–5 accepted (A: merge `pqz-rel3` and push, done `3ad4069`; B: burn randomness fresh; 1: R_TX on the
§7.7 layout; disclosure `kind` a 32-byte word; precompile checks opTag / proofSystemId; e′ ∈ [−2^24, 2^24); lazy keys).
Credit cap stays 1024 units for now.

**WIP branches (resume in this order; none merged, none pushed; agents stop at the branch, owner approves merge/push):**

1. **UA-5b** — branch `ua5b`, worktree `.claude/worktrees/ua5b`, last `39cd048` (from `279b5d8`). Tasks 1–6 of 8 done
   (purpose `trade` in UAKinds + six libraries; `UATradeOrder` / `uaTrade` / `uaCancelOrder` / `uaInvalidateNonces`;
   `uaWrap`; `SCaaSDex` tagged legs; DEX conservation invariant; `uatrade_kat.json` + clientkeys typed data). Plan
   `docs/superpowers/plans/2026-10-13-ua5b-trade-dex.md`. **Node does not build until Task 7** (leg ABI changed):
   `scaas-node/src/abi.rs` tagged `Leg {sellToken, shape, order, sig, fill}`, `UATradeOrder`, `SelfTrade(bytes32)`,
   `UALegSettled`; `dex.rs::to_settlement` (shape-0 legs `abi_encode(TradeOrder)`, mtxSettle selector assertion ~l.1239,
   KAT ~l.840); `dex/venue.rs` watcher filter / `encode_event` / `book.settled` / mock decoder ~l.1312. Then Task 8 docs
   (dex.md CTR-DEX-15/16/23/25/26, accounts.md CTR-UA-14/-19/-26/-27 + §1.7, token-wrappers.md CTR-TOK-20, metatx.md
   CTR-MTX-18, decisions.md, TODO), full checks (forge default + `private7622`, `test/ua/**`, `--isolate` UAGas /
   UARegistryGroups, size gate, clientkeys, vectors regenerate byte-identical), mutations (`_uaMove` amount in
   `uaTrade`, `pulled[h] == 0`, `_sendTo` branch, `_payLeg` refund, `uaWrap` destination, `UAVerifyGas` re-raise), self-review.
   **Owner to confirm rulings** C5b-1/-7 (one internal order form, trailing bytes ignored), C5b-2 (`ua*` trade revert
   `UALedgerOff` when the ledger is off), C5b-3 (`SelfTrade(bytes32)`), C5b-4 (`LegShapeUnknown`), C5b-5 (DEX "ledger
   on" = listing + `registry() != 0`, no ERC-165), C5b-6 (derived destination checked only at payout → `MatchFailed`),
   C5b-9 (`uaWrap` emits only `UAWrapped`), C5b-11 (node: tagged legs + `UALegSettled` only; intake / bytes32 book / PQ
   gossip wait for UA F5), C5b-12, C5b-14 (`SCaaSDex` 23,493 B stays out of the size baseline). Numbers so far: two
   `mldsa65` legs 12,124,252 gas (three revert `UAVerifyGas`); `UNDERLYING` size pin raised 45,056 → 49,152.
   Then **UA-5c** (from `ua5b`).
2. **PQZ relation fix-ups** — branch `pqz-relfix`, worktree `.claude/worktrees/relfix`, `53f5ab3` WIP (from `3ad4069`).
   Decisions B, 1–5 done in code + spec; builds, KAT 19/19, tamper `fails 0`, ASan/UBSan clean, docs_check 0 errors.
   R_TX `proofs_fnv` changed by design (native `cb562b47` → `4690aaa0`, wasm `834d6853` → `f1c3e7f6`); R_REG unchanged.
   Lazy keys: wasm R_TX arena 251 → 221 MiB (13.6 % under 256 MiB); arena block-class rebuild fixed. Remaining: timing run
   (`scripts/capped pqz-core/research/pqzl-measure/relfix.sh f2`, > 10 min, background), numbers into
   `pqz-relations-burn-disclose.md` §1/§3/§4/§5 + `pqz-core/README.md` / `STATUS.md`, final non-WIP commit. Then the
   specialised-verifier part on its private branch (see the private notes).
3. **PQZH prototype** — branch `pqzh-proto`, worktree `.claude/worktrees/pqzhp`, `e1fa752` WIP. Crate `pqz-core/pqzh/`,
   Plonky3 `=0.8.0` (needs Rust 1.97.1, pinned in `rust-toolchain.toml`), Goldilocks² + FRI + Keccak Merkle, transcript
   seeded by SHAKE256(tag ‖ op ‖ be32(len) ‖ stmt); NTT(A) and the statement in periodic columns. R_REG and R_TX prove
   and verify honestly (constraint-checked). Single-run sizes: R_REG 130.7 KB; R_TX 178 KB at blowup 8 / 38 queries
   (over 160 KB), **144 KB at blowup 16 / 28 queries** (conjectured); prove ≈ 0.7–1.0 s R_REG, 1.9 s R_TX native.
   Next: default to blowup 16 / 28 queries (the first test in `tests/attacks.rs` expects ≤ 160 KB), run attacks + full
   bench, wasm build + node runner, ZK mode (pad the 16-row Digit table to ≥ 128 rows), C cross-check of statement bytes
   against `pqz_bench.c`, `p3-security` provable vs conjectured sweep, then `docs/research/pqzh-prototype.md`.
4. **PQZH Solidity verifier gas** — branch `pqzh-sol` (= main, nothing committed), worktree `.claude/worktrees/pqzhsol`
   (`smartcontracts/evm/lib` symlinked). Plan: stdlib Python references (Goldilocks, Fp2/Fp3, pure-Python keccak,
   depth-10 Merkle, FRI folds arity 2/8/16, LogUp sum) → `test/pqzh/Pqzh.sol` + `PqzhTest.t.sol` (test-only, per-component
   gas, synthetic end-to-end skeleton with Merkle checks enforced) → `pqz-core/pqzh/stark-backup/sol/model.py` grid (blowup 4/8/16 ×
   arity 2/8/16 × conjectured/Johnson, five relations) with calldata (EIP-2028 / EIP-7623) vs the 16,777,216 cap →
   `docs/research/pqzh-solidity-verifier.md`. Pre-measurement guess only: R_TX ≈ 2.3–4 M verify + ≈ 2 M calldata; risks:
   SHAKE over the statement in Solidity (≈ 15 M) — use the keccak opcode or a Horner fingerprint. Owner asked: measure,
   write into research, push.

**Owner steps outstanding:** the items in the private notes; SCaaS testnet registry redeploy after
the gas limit; PQ verifier audit; chain 22776 genesis; run the static bench tarball on an AVX-512 IFMA machine.

### Session 2026-10-13 (shutdown: P6d WIP, UA-1c draft) — resume here

**State:** main pushed. Merged this session: UA-3, UA client dirs rename, the license rename (Vegan Community / Vegan
Enterprise License), README (§10 relayer diagram, §13–§17, use cases grouped with fee payers, Free Pay), UA-4 (UA
ledger), P6c (PQ kinds in registry gen 1), P6b (E-S0 estimator, gate met). Spec edits on main (owner 2026-10-13,
pq-zero-knowledge.md): why LaZer and no equivalent (`#why-lazer`); upstream cross-check = one-shot golden dump (no AVX-512 CI
runner); no on-chain attestation for PQZ; three disclosure kinds, no `SENDER_CP`; `be32(sendCounter)` in the HKDF info,
`be8(v)` amount kept (amounts < 2^64 by encoding; Zether's 2^54 is a token-wide BSGS cap, see `shieldScale`).

**P6d WIP (resume first):** branch `p6d-pqz-core`, worktree `.claude/worktrees/p6d`, commits `c91b3ab` (LaZer 3330e48
subset, MIT), `c397a6d` (six layers rewritten + golden dump: 19/19 equal under Intel SDE 9.48 `-spr`, AVX2 build too;
upstream strict-aliasing bug in `aes256ctr-amd64.c` worked around with `-fno-strict-aliasing`), `9ba594d` (relations
driver WIP). Read `pqz-core/STATUS.md`. Resume: (1) rerun `params/run_e_s1.sh` (~20 min, capped) and
`params/codegen/run.sh` for both relations, add the ℓ∞ filler proof in `pqz_rel.c`; (2) fix the arena crash
(`spolyvec_free`; upstream enlarges `nelems_max` after allocation) with upstream's tbox test; get `pqz_bench` to prove
and verify R_REG / R_TX; (3) measure native + wasm32 (clang 18, wasm-ld-18, node), symbol scan, README, research note
`docs/research/pqz-core-e-s1.md`, roadmap P6d row (golden-dump wording), docs_check — then the owner's kill decision.
Findings so far: LaZer's default MSIS target gives β 353 < Kyber-512's 406 — the stricter target gives R_TX kmsis 23 /
m2 64 (β 456 / 470), R_REG 22 / 63 (β 452 / 470); real constants ω 8, η 140, λ 4, binding 4η√(B1²+B2²) (E-S0 assumed
8η), JL 41 confirmed; codegen estimates R_REG ≈ 27 KB, R_TX ≈ 42 KB (+2 KB filler) — not measured.

**UA-1c draft:** `docs/superpowers/plans/2026-10-13-ua1c-c-abi.md` (DRAFT, not spiked; 13 rulings U1C-1…13: caller
buffers, `int32_t` status + `scaas_ua_last_error`, `catch_unwind`, cbindgen `=0.28.0` dev-dep with a header-drift test,
surface = ua-cxx's, no `verify`). Resume at "Spike (Task 1, Step 1)"; check first that cbindgen 0.28.0 builds offline.
Existing bindings unchanged (owner: "only add ua-c").

**Owner steps open (TODO):** P6c — redeploy UA registry gen 1 on the SCaaS testnet after reading its block gas limit; audit
the PQ verifiers before any public chain. SCaaS Chain 22776 genesis hash when the chain is up. A one-time cross-check of
the golden dump on real AVX-512 hardware (recommended).

**Next steps:** finish P6d → owner kill decision → P6e/P6g; UA-1c (spike, execute); the template-library spec.

### Session 2026-10-13 (P6b merged)

**State:** P6b (E-S0 parameter spike) merged into main (`676366a`) and pushed; branch `p6b-estimator` kept. Outputs:
`pqz-core/pqzl/params/{estimator.txt,e_s0.py,run.sh,README.md}` (Sage `sagemath/sagemath:10.7` @ sha256:4f5589eb…d528,
lattice-estimator `53da598`, `RC.ADPS16`) and `docs/research/pqz-parameters-e-s0.md`. **Gate met:** every PQZ instance
beats Kyber-512 (115.5 / 106.3 bits classical / quantum) — key and encryption 136.1 / 124.3, with 32 hints 133.5 / 121.6
(DDGR20 worst direction β 464 vs the spec's 466), proof ABDLOP MLWE 132.7 / 121.1, MSIS 132.6 / 120.3 — and every
Fiat–Shamir round ≥ 128 bits (JL 128.0, Z_q λ=4 168, R_q 672, final κ=8 129.8). Constraints for P6d: keep κ ≥ 8,
λ ≥ 4, n ≥ 24, m2 ≥ 66. Approximations: the DDGR20 hint estimator was re-implemented (matches the estimator's usvp);
LNP22 / LaZer constants marked [unverified] — P6d reruns with LaZer's values; `bdd_mitm_hybrid` only on two instances;
`estimator.txt` produced once (a full byte-for-byte rerun not yet done).

**Blocked on the owner for P6d (E-S1 `pqz-core`):** the spike's KAT equality runs against upstream LaZer's AVX-512 build —
this machine has no AVX-512 (`/proc/cpuinfo`), so an AVX-512 runner is needed; and its result is the owner's kill
decision (CTR-PQZ-09). P6e / P6g follow P6d; P6f is owner-gated SCaaS testnet work.

### Session 2026-10-13 (P6c merged)

**State:** P6c merged into main (`06629d8`) and pushed; branch `p6c-pq-kinds` and worktree `.claude/worktrees/p6c` kept.
Plan `docs/superpowers/plans/2026-10-13-p6c-pq-kinds.md` (rulings C6-1…C6-19). Forge 1104 passed / 10 skipped on merged
main; `test/ua` 232; `--isolate` UARegistryPq/UAGas/UARegistryGroups 34; size gate 0 errors (UARegistry 23,658 B);
`private7622` build ok; clientkeys 101 / 99 / 2 skipped (generator rerun byte-identical); `scripts/e2e-zether.sh` 3/3;
scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (P6c):** PQ verifiers registry-ready (`verifyPop`; ML-DSA `expandKeyRows` / `expandedKeyPart` / `verifyCached` /
`verifyExpanded`; SSTORE2 length guard); `pq_signatures.json` (PoPs, signatures, 27 negatives, msig treasury / hybrid,
metatx3 rows; in the byte-for-byte regeneration test); `UARegistry` slots 0x0130–0x0133 (stored keys, registry-derived
ML-DSA expanded-key cache `cacheExpandedKey` / `expandedKeyOf` — -44 one part, -65 two parts, never caller-supplied;
an uncached ML-DSA PoP fails `UAPoP` where there is no precompile) and the `pqz-mlwe` 0x0142 slot with its authRef rule
(verifier and enabling in P6g); msig gas bound counts the caller's hold for caps > 400 k, own-generation and handed to
gen 1; PQ signers on the UA ledger; DeployBase enables the PQ kinds on dev chains + the SCaaS testnet only, caps 4.25 M / 5.95 M /
2.5 M / 1.4 M (cold headroom ML-DSA-44 75.8 k, ML-DSA-65 56.2 k, pinned ≥ 30 k by a test).

**Owner steps (open, in TODO):** redeploy UA registry gen 1 on the SCaaS testnet after reading its block gas limit (an
ML-DSA-65 cache part needs a ~13.5 M-gas tx; with a lower limit only fndsa512 / slhdsa128s are usable); audit the PQ
verifiers and the cache before any public chain enables a PQ kind.

**Controller rulings (P6c):** fixed the plan's C6-8 gap — gen 2 also holds for PQ members it hands to gen 1 (a gen-2
msig could otherwise register within budget yet need ~47 k more to authorize); the final wave removed the now-dead
hold tag bit (behaviour-identical), stated the real cap headroom and pinned it; malformed msig `authPop` still reverts
without data (fails closed). Deferred minors: `verifyCached` edge-branch tests, UAMetaTx3Pq events/gas ceilings,
UADeploy public chain ids.

**Next steps:** the P6 E-streams (P6b E-S0 spike, P6d E-S1 `pqz-core`, P6e relations; P6f SCaaS testnet precompiles is
owner-gated; P6g `PqzToken` + `UAPqzVerifier`); the template-library spec; SCaaS Chain 22776 onboarding when the
chain is up.

### Session 2026-10-13 (UA-4 merged)

**State:** UA-4 merged into main (`8152ee7`) and pushed; branch `ua4-ledger` and worktree `.claude/worktrees/ua4` kept.
Plan `docs/superpowers/plans/2026-10-12-ua4-ledger.md` (rulings L4-1…L4-20). Forge 1086 passed / 10 skipped on merged
main; `test/ua` 214; size gate 0 errors; `private7622` build ok; clientkeys 97 / 95 / 2 skipped; `scripts/e2e-zether.sh`
3/3; scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (UA-4):** `UAMetaTransaction` / `UAMetaTransfer` (MetaTxLib), `UA_POOL`, one `bytes32` nonce map with the signer
as an id (`pad(addr)` for native ids), `SigCheck.isValid7702`; the UA ledger in `ERC20MetaTx` (registry bound at
`initialize`, balances in the ERC-7201 `scaas.ua.ledger` struct, `UA_POOL`'s own ERC-20 slot = the ledger total (L4-2),
`transferToUA`, `uaExecute` / `uaBatch` / `uaExecuteTransfer` / `uaBatchTransfer`, `uaCancelNonce`, `IUALedger`, a
derived UA may self-call only the two `unwrap`s (L4-3/L4-4), a ledger move to the token itself reverts `TransferToSelf`);
named `uaTransfer` / `uaTransferWithFee` / `uaPay` / `uaUnwrap`; T-V3-1/2/3 (the invariants fuzz NONE and a 1:1
UNDERLYING clone incl. the burn under a UA, per-UA replay, reserve; a mutation check confirmed they catch ledger bugs);
`metatx3.json` + clientkeys typed data; unwrap refuses `UA_POOL` as recipient. MT-2's UA path closed. T-V3-4 (size)
deferred to Glamsterdam.

**Owner-visible consequence:** every token implementation now exceeds EIP-170 (NONE 31,770 B; UnderlyingZetherToken
49,778 B, init 51,473 B > EIP-3860) — deploys need `--code-size-limit 65536` (test chains / anvil only); public chains with
the 24 KiB limit cannot take the tokens until Glamsterdam (owner rule: no size optimisation). `deploy.sh evm` now also
runs forge `--slow` (parallel broadcast vs anvil automine left a deploy tx pending forever; per-tx gas fits 2^24).

**Controller rulings (UA-4):** fixed the plan's fee-to-token gap (CTR-MTX-18) in `_uaMove`; `--slow` on the evm deploy
path (multiplier 105 kept); final fix wave added the burn-under-UA invariant handler and the `UA_POOL` unwrap-recipient
refusal. Deferred minors: `uaBatch` / `uaPay` not fuzzed; `metatx3.json` negatives / mode-0 row; `isValid7702` malformed-sig
tests; Hedera HIP-632 UA branch test; node `ua_metatx` jobs (UA F5, L4-17).

**Next steps:** P6c (PQ kinds in registry gen 1 incl. `pqz-mlwe`), then the P6 E-streams; the template-library spec;
SCaaS Chain 22776 onboarding when the chain is up.

### Session 2026-10-12 (UA-3 merged, license, README)

**State:** UA-3 merged into main (`520642c`) and pushed; branch `ua3-zether` and worktree `.claude/worktrees/ua3` kept.
Plan `docs/superpowers/plans/2026-10-12-ua3-zether.md` (rulings Z1–Z19). Forge 1047 passed / 10 skipped on merged main;
`--isolate` UAGas 6 / UARegistryGroups 14 / UARegistryZether 13; prague verifiers 52 + 1 skipped; size gate 0 errors;
ZetherProverCross 10; zether-prover cargo + wasm-smoke 18; clientkeys green; `scripts/e2e-zether.sh` 3/3 on anvil;
scaas-node e2e 4 + e2e_hedera 1; docs and facts checks clean.

**Built (UA-3):** `zether-bn254` 0x0140 / `zether-bls12381` 0x0141 in `UARegistry` gen 1 (PoP over
`popDigest(ua, authRef)`, the authority co-signs with purpose `authref`, `Y` stored by SSTORE2, `keyOf`,
`requireZetherAuthorized(ua, digest, auth, zkCovered)`: purpose follows the digest — `zether-auth` spends, `zether-owner`
roll-over/mode), dev-only `ZetherSchnorrBn254Verifier` / `ZetherSchnorrBls12381Verifier`; tokens on tagged `toUA` +
`kindOf`; `UniversalAccountRegistry`, `AuthScheme` and their tests in `legacy/ua3/` (`test/MultiSig.t.sol` restored);
zether-prover API `pop` / `ownerAuth`, vectors regenerated (`r33_keys.json` registered on a real registry by forge);
clientkeys `zetherPop` / `zetherOwnerAuth` / `zetherKind`; `DeployBase` deploys the UA registry on every chain with the
§1.9 kind set, `script/UAPrecompileProbe.sol` via `eth_call` (subgroup rows, MSM/pairing prices, G1ADD and MAP_FP_TO_G1),
fail closed; JSON `ua_registry` (+ `zether_registry` = same with `DEPLOY_ZETHER`).

**Controller rulings this session (UA-3):** SPDX of the plan updated to the new license before execution; MultiSig's 4
tests restored (`MultiSig.sol` stays, owner rule); no CREATE2 address pin for the registry (init code carries `uid` and the
probe-dependent kind array); the probe also checks G1ADD / MAP_FP_TO_G1 (reviewer: not a CTR-UA-23 violation since a
missing precompile makes the kind unregistrable, taken anyway). Deferred minors (test gaps, e2e port hygiene, prover
`authRef` null parsing, an owner-auth cross-language vector) → UA F3 / next touch.

**Also this session (on main):** license renamed — Vegan Community License 1.0 / Vegan Enterprise License, SPDX
`LicenseRef-Vegan-Community-1.0` (terms unchanged); README §10 relayer diagram + `docs/assets/relayer-network.svg`, §15
links, §13 "Node", §16 Use cases (34 rows in 8 groups, who can pay the fee), §17 Free Pay (Tu Viện Chơn Như), License
last; `clients/ua-cs/scaas.slnx`; UA client dirs renamed (`ua-rs`, `ua-cxx`, `ua-qt`, `ua-dart-frb`).

**Owner decisions this session:** template library = implementations deployed once per chain, instances by
clone/CREATE2 with parameters, incl. commercial contracts (TODO §0, spec first); "SCaaS Chain" chain id 22776 is a new
chain beside the others (ports 22776+; SCaaS testnet and `m/7622'` unchanged; TODO); family-tree use case stores every record on
chain; `claude-code-api.txt` hidden by `.git/info/exclude`.

**Next steps:** UA-4 (UA ledger) or P6c (PQ kinds incl. `pqz-mlwe`); the template-library spec; onboarding SCaaS Chain
22776 when the owner's chain is up (genesis hash needed). P6b can run beside.

### Session 2026-10-12 (UA-2c merged)

**State:** UA-2c merged into main (`c35f494`) and pushed; branch `ua2c-groups` kept, worktree `.claude/worktrees/ua2c`
kept; then the UA client dirs rename merged (flat `clients/ua-<lang>`: `ua-rs`, `ua-cxx`, `ua-qt`, `ua-dart-frb`; branch `ua-dirs-rename` kept). Plan `docs/superpowers/plans/2026-10-12-ua2c-groups.md` (rulings C1–C19). Forge 1052 passed / 10 skipped on merged
main; `--isolate` UAGas 6 / UARegistryGroups 14; prague verifiers 52 + 1 skipped; size gate 0 errors; `scaas-ua` with and
without `signers` + clippy clean; node 13/13; docs and facts checks clean; binding crates build `--locked` again (Qt needs
`QMAKE=~/usr/Qt/6.8.2/gcc_64/bin/qmake6`).

**Built:** `src/common/SSTORE2.sol`; `UARegistry` stored kinds 0x0110–0x0113 (`keyPtr` = SSTORE2(vk), `auth.keyData` empty,
group PoP capped at `verifyBudget` without hold, gen-2 hand-off, stored msig members); verifiers `Musig2Secp256k1Verifier`
(BIP-327 KeyAgg with `ecrecover` hints), `Musig2Bn254Verifier`, `UAFrostSecp256k1Verifier` (RFC 9591), `FrostBn254Verifier`,
`library Bip340` (extracted from `Bip340Verifier`, behaviour unchanged); `scaas-ua` `src/groups.rs` (registry-side checks) and
feature `signers` (BIP-327, ZF frost-core 3.0.0, FROST(bn254, keccak256)); `smartcontracts/vectors/ua/groups.json` (20 groups,
57 negatives, T-FROST); noble cross-check `test/ua-groups.test.js`; `test/ua/UARegistryGroups.t.sol`, `UAFrost.t.sol`,
`Musig2Verifiers.t.sol`; accounts.md §1.6.1/§1.8/§1.15/§1.16 updated.

**Controller rulings (final review upheld):** a starved group registration reverts `UAPoP`, or `SSTORE2WriteFailed` when gas
runs out at the key write after the PoP passed — never a record (`test_registerStoredStarved`, spec §1.8 step 6); if the
owner wants `UAPoP` only, map the SSTORE2 failure in `UARegistry`. FROST(secp256k1) repeated/cancelling `C_i0` is refused
on chain but accepted by Rust/noble (fails closed; §1.6.1) — mirror deferred to UA F3. Follow-ups listed under UA-2c in TODO.

**Next steps:** UA-3 (deployment, Zether kinds). P6b
can run beside.

### Session 2026-10-12 (UA-2c in progress, paused)

**State:** main has UA-2a and UA-2b merged and pushed (up to `3eb2e2b`); unpushed on main since then: the README
scorecard was pushed (`8bbac31`), then `e26749a` (TODO: UA client dirs rename), `2d40f69` (plan UA-2c), `fd900ec`,
`5cf6c35`, `a670d90` (TODO: scaas-node docker-compose) and this HANDOFF commit. **UA-2c is mid-execution**
(subagent-driven): worktree `.claude/worktrees/ua2c`, branch `ua2c-groups` from `fd900ec`; Task 1 committed (`49a3aab`:
`scaas-ua` signers behind feature `signers` — BIP-327 MuSig2 + bn254 port, ZF frost-core 3.0.0 FROST secp256k1 + the
FROST(bn254, keccak256) ciphersuite — registry-side checks `src/groups.rs`, `smartcontracts/vectors/ua/groups.json`
444,457 B sha256 `92348225…`, node cross-check `test/ua-groups.test.js`); its Opus review was stopped before finishing;
Task 2 was stopped and its partial edits discarded (worktree clean).

**Resume UA-2c:** in the worktree, read `.superpowers/sdd/2026-10-12-ua2c-groups/progress.md` (ledger, preflight table,
the pause note) — then re-dispatch the Task 1 review (package `review-fd900ec..49a3aab.diff` is there) and the Task 2
implementer (BASE `49a3aab`, brief `task-2-brief.md`), and continue Tasks 3–7, final review, merge (owner). Plan:
`docs/superpowers/plans/2026-10-12-ua2c-groups.md` (task order fixed: 1 → 2 → 3 FROST → 4 MuSig2 + `library Bip340` → 5
registry on groups.json → 6 binding lockfiles → 7 docs; rulings C1–C19). The scratch dry-run under `/tmp` may be gone after
a reboot — the briefs are self-contained.

**Owner decisions this session:** UA client dirs → flat `clients/ua-<lang>` (`ua-rs` keeps crate `scaas-ua`, `ua-cxx`,
`ua-qt`, `ua-dart-frb`; ports unchanged) — one commit right after UA-2c merges; scaas-node docker-compose deferred until
node streams P2 + P3 + P4 + P6 (P5 Odoo client not yet; the legacy pull path NODE-JOB-10 is decided to go after the
per-chain push cutover, push is not built yet); README scorecard row e) Privacy & data is a chain advantage (Zether / PQZ,
immutable records).

**Known issue:** the binding crates' `Cargo.lock` (`scaas-ua-cxx`, `-qt`, `-frb/rust`) have been stale since UA-2a, so
their `--locked` CI fails on main; UA-2c Task 6 refreshes them (+7 packages, no version moves, dry-run checked).

**Next steps:** finish UA-2c → UA client dirs rename → UA-3 (deployment, Zether kinds). P6b can run beside.

### Session 2026-10-12 (UA-2b merged)

**State:** UA-2b merged into main and pushed (branch `ua2b-ed25519` kept); plan
`docs/superpowers/plans/2026-10-12-ua2b-ed25519.md` (rulings B1–B9). Next UA-2c (MuSig2 KeyAgg with hints, FROST
secp256k1/bn254 with the DKG check, `groups.json`, `keyPtr` storage, T-FROST).

**Built:** `src/common/Sha512.sol` (unrolled, 30 k gas per block), `src/common/Ed25519.sol` (Straus–Shamir 4-bit windows,
precomputed base table, MODEXP sqrt/inversion, R compared by encoding), `src/ua/verifiers/Ed25519Verifier.sol` — strict RFC
8032 = ed25519-dalek `verify_strict` (S < L, canonical and not small-order A and R, cofactorless equation; mixed-order A
accepted when the equation holds; A with y ≥ p refused on top of dalek); ~168 k gas valid, 171 k worst, cap 210 k.
`signatures.json` gained derived[7] `ed25519` and `ed25519Rfc8032`; `ed25519_fuzz.json` (2144 cases, dalek verdicts; noble
`zip215:false` differs on small-order R and torsion components — dalek is the reference); `scaas-ua` `verify_strict` arm
(`ed25519-dalek =2.2.0`). Registry tests enable ed25519 (KINDS = 8). `Bip340Verifier` reads `returndatasize()` after its
MODEXP call (Yul evaluates arguments right to left). forge 1009 passed / 10 skipped.

**Carried to UA-2c's docs task (optional minors):** test/comment wording "+~20 %" (real margin +23 %); §1.9 canonical-A
phrase; an audit note on the ed25519 per-chain row; a mixed-order key through the registry with the real verifier; the
rejecting-side cap measurement. Stale `Cargo.lock` of `scaas-ua-cxx`/`-qt`/`-frb` (missing UA-2a/2b crates): refresh when
those crates are next built.

**Next steps:** UA-2c (or UA-3 in parallel). P6b can run beside it.

### Session 2026-10-12 (UA-2a merged)

**State:** UA-2a merged into main and pushed (branch `ua2a-registry` kept); plan
`docs/superpowers/plans/2026-10-12-ua2a-registry.md` (rulings R1–R24). UA-2 is split in three (owner): UA-2a done, next
UA-2b (`ed25519` verifier in Solidity, T-FUZZ) and UA-2c (MuSig2 KeyAgg with hints, FROST secp256k1/bn254 with the DKG
check, `groups.json`, `keyPtr` storage, T-FROST).

**Built:** `src/ua/UARegistry.sol` + `IUARegistry.sol` (gen 1: records, `keyOwner`, PoP `register`, `requireAuthorized` for
derived / native ECDSA-7702-1271 with `UAAuth` / `msig` with the structure bound incl. gen 1's hold for handed members,
generations, `chainUid`, `hederaNative`, ERC-5267; kind table = one immutable per slot from `KindConfig[]`; ed25519 slot
exists, MuSig2/FROST/PQ/Zether refused with `UAConfig`), `src/ua/IUAVerifier.sol`, verifiers in `src/ua/verifiers/`
(P-256 + WebAuthn with a constructor probe of P256VERIFY, BIP-340 via the ecrecover trick, Schnorr bn254/BLS12-381 and BLS
min-sig BLS12-381/bn254 under a bounded self-call), `src/common/CurveSigs.sol`, `WebAuthnClientData.sol`;
`smartcontracts/vectors/ua/signatures.json` from `clients/clientkeys/scripts/ua-sig-vectors.mjs`, re-verified by noble and by
`scaas-ua::verify` (Rust). forge 995 passed / 10 skipped; measured gas in accounts.md §1.15.

**Open:** HIP-632 for `hedera-native` cannot run in a `view` (R19; verified as ECDSA/1271 for now); member kinds outside
MEMBER give `UAKeyData` (R20); `bls-bn254-minsig` register needs ≥ 450 k call gas plus calldata (R23); msig worst-case
cold slack ~4 k under the bound. Carry-overs for UA-3: per-chain precompile probes (0x08/0x0c/0x0e outside-subgroup rows),
EIP-2537/pairing prices ≤ 2× before enabling those kinds.

**Next steps:** UA-2b, then UA-2c (or UA-3 in parallel with UA-2b). P6b can run beside it.

### Session 2026-10-12 (UA-1b merged, license)

**State:** UA-1b (UA identity layer bindings) and the SCaaS Community License 1.0 merged into main and pushed; branches
`ua1b-bindings` and `license-community` kept. Plan `docs/superpowers/plans/2026-10-12-ua1b-bindings.md`.

**UA-1b built:** `clients/scaas-ua-cxx` (C++17 over `scaas-ua` with cxx 1.0.202; `scaas::ua::Error`; ctest 6/6),
`clients/scaas-ua-qt` (QML singleton `Scaas.Ua/UaKinds` in Rust with CXX-Qt 0.10.0, Qt 6.8.2 at `~/usr/Qt/6.8.2/gcc_64`;
hex strings + `lastError`; Qt Quick Test 12/12 offscreen), `clients/scaas-ua-frb` (flutter_rust_bridge 2.13.0, sync API,
`int` kinds/chain ids with range checks, committed generated code; `dart test` 7/7, Linux only), `clients/ua-dart`
(pure Dart, in-package Keccak; VM, node and asserts-off runs 7/7). The final review caught the pure-Dart Keccak being wrong
with asserts off (fixed; CI runs the vectors with asserts off). Open: FRB as a Flutter plugin with Android/iOS/web builds
(does `scaas-ua` build for wasm?), Qt packaging for Windows/macOS.

**License (owner 2026-10-12):** `LICENSE` (SCaaS Community License 1.0, Licensor Dinh Duong Ha), `LICENSE.vi.md`
(non-binding summary), CLA in `CONTRIBUTING.md` (`git commit -s`), README "License" section; SPDX headers
`LicenseRef-SCaaS-Community-1.0` (Solidity, UA-1b sources), clientkeys/Move manifests. Terms: prohibited at any scale for
groups that kill animals (every species, any life stage; incl. commercial pest control), food service serving any
prohibited animal product (meat, fish, seafood, insects, silk, carmine, gelatin…, fertilized eggs, honey and bee products;
milk, unfertilized eggs, shorn wool allowed), groups with > 10% revenue from such products, and anyone trading in
human-derived products (hair, organs, tissue, blood, gametes…; only donation for medical treatment excepted; human milk
allowed); free (rights as MIT or Apache-2.0, license kept on redistribution) for fully vegan groups or groups under
USD 10 M revenue (90-day grace); everyone else an Enterprise License with the same prohibitions. A lawyer's review is
recommended before relying on it; earlier public versions stay under their old headers.

**Next steps:** UA-2 (registry and verifiers, PoP signatures, `groups.json`; carry-overs in the UA roadmap's UA-2 row).
P6b (E-S0 spike) can run beside it.

### Session 2026-10-12 (UA-1 merged)

**State:** UA-1 (UA F0, Universal Account kind libraries) merged into main and pushed; branch `ua1-kinds` kept. UA phase
roadmap `docs/superpowers/plans/2026-10-12-ua-roadmap.md` (owner: UA F0/F1 + F2 as their own phase before P6c; UA-1,
UA-1b, UA-2 registry and verifiers, UA-3 Zether re-point, UA-4 UA ledger). Plan `docs/superpowers/plans/2026-10-12-ua1-kind-libraries.md`.
Forge 926 passed / 10 skipped, clientkeys 80 (78 pass, 2 skipped), scaas-ua 6, ua-py 7, ua-go ok, ua-cs 6; size gate 0
errors; docs checks clean.

**Built:** the UA identity layer (kind table, tags, ids, keyHash with `GROUP(g) = keccak256("scaas.ua.group.<g>.v1")`,
purpose tags, `ua_msg`, `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids, closed sets with
`slhdsa128s` in SIGNING/MEMBER, key-data validation incl. curve and subgroup checks, MuSig2/FROST/`msig` layouts) in six
libraries: Solidity `src/ua/UAKinds.sol` (internal; precompile calls capped at 2× the EIP price, a gas shortage reverts
`UAVerifyGas`, never `UAKeyData`), clientkeys `src/ua.js` (reference) + `scripts/ua-vectors.mjs`, Rust `clients/scaas-ua`
(independent cross-check), Python `clients/ua-py`, Go `clients/ua-go`, C# `clients/ua-cs`; vectors
`smartcontracts/vectors/ua/kinds.json` (27 valid / 201 invalid rows) and `structures.json`; CI jobs; `docs/clients/ua-libraries.md`.
The final review ran the six libraries on 6,060 inputs: identical outputs, no panics. No signatures yet (PoP signatures and
`groups.json` are UA-2). Rulings and carry-overs: plan header (U1–U10), the UA roadmap's UA-2 row (probe 0x08/0x0c/0x0e on
each target chain, `ecrecover` address(0) vs an `evm-eoa` member with id 0, ~165k gas for bn254 G2 validation, precompile
prices ≤ 2× EIP before enabling BLS / bn254-G2 kinds).

**Owner decisions 2026-10-12:** Go and C# client libraries added; Python in this repo; UA ledger as UA-4; UA-1b next:
C++ as a plain `cxx` bridge plus CXX-Qt (a `QObject` in Rust for QML; Qt 6 must be installed — not on this machine),
Dart as both flutter_rust_bridge v2 and a pure-Dart port, all on the shared vectors. ML-DSA stored key: the FIPS 204 pk;
the expanded key an optional registry-computed cache (P6c).

**Next steps:** write the UA-1b plan (bindings), then UA-2 (registry and verifiers). P6b (E-S0 spike) can run beside them.

### Session 2026-10-12 (P6a merged)

**State:** P6a (PQ signature verifiers) merged into main and pushed; branches `p6a-pq` and `p6a-val` kept (owner).
Plan `docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`. Forge 917 passed / 10 skipped, clientkeys 75 (73 pass,
2 skipped), size gate 0 errors (verifiers fit, baseline unchanged), `private7622` build ok, docs checks clean.

**Built:** `src/ua/PqUA.sol` (IUAKindVerifier, kind tags 0x0130–0x0133, `pq_msg`, probe), `SlhDsa.sol`
(SLH-DSA-SHA2-128s), `Shake.sol` + `PqNtt.sol`, `FnDsa.sol` (Falcon-512, EIP-8052), `MlDsa.sol` (ML-DSA-44/65, FIPS 204
key and EIP-8051 expanded key, EIP-8355 probe); clientkeys `src/pq.js`, generated vectors `pq_kat.json` and
`pq_external.json` (SHA-256-pinned downloads). Measured verify gas: SLH-DSA 787,953 (worst 1,321,231), Falcon 2,266,895,
ML-DSA-44/65 FIPS key 11,379,929 / 18,896,958, expanded key 4,093,867 / 5,771,287; `expandKey` 8,519,511 / 15,304,306.

**Reviews:** T1–T4 task reviews, one fix wave (pinned SHA-256 check, `u32` range, context negatives, Falcon KAT format;
tests pinning every Falcon/ML-DSA malformed-input check by mutation; `Shake` reverts `ShakeMemory()` without `reserve()`;
probe vector lengths; expanded-key NatSpec warning), final review (Opus) clean after three docs/NatSpec minors.
Deferred minors (T2 test polish, probe of wrong length falls back silently, the `reserve()` guard is a heuristic) are
non-blocking; P6c carry-overs are in the TODO P6 row.

**Owner decisions 2026-10-12:** (1) UA F0/F1 run first as their own phase; P6c then only adds the PQ kinds (UA F9) to
registry gen 1. (2) ML-DSA stored key = the FIPS 204 pk (UA id, keyHash, EIP-8355 path); the EIP-8051 expanded key is
an optional cache attachable later, computed by the registry itself with `expandKey(pk)` — never caller-supplied (the T4
review probed two universal forgeries on an unchecked expanded key) — stored once per UA id by SSTORE2 chunks under
EIP-170 (-44 one, -65 two), read by EXTCODECOPY per verify; -65's cache registration (≈ 15.3 M + ≈ 7.4 M) spans several
transactions. No hybrid (classical + PQ) kind. The verifiers are home-written and unaudited — audit before any public
chain enables them.

**Next steps:** P6b (E-S0 parameter spike, independent); write the UA F0/F1 phase plan (kind libraries in four
languages + vectors; `UARegistry` gen 1 with the classical verifiers incl. BIP-340, Schnorr-bn254/BLS12-381, MuSig2,
FROST, ed25519, msig; Zether re-point; UA ledger split); then P6c. Chain-7622 docker/chainspec changes (P6f) need the
owner's approval.

### Session 2026-10-11 (P5)

**State:** P5 merged (`d245a29`, pushed); main's P3b merged in before the merge. Plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`.
890 forge tests (main 1047 + `DexKatTest` 1 − 158 v1 tests moved to `legacy/p5/`; 10 skipped, P3b's env-gated measurements); size gate 0 errors; `scaas-node` lib 278, mesh vectors (46 cases, sha256 `bde85091870f6bea608d6e3430b70fcf00b34f73c6e6d3dc659009582b39c4ad`) + fuzz, clippy clean; e2e 4/4 and e2e_hedera 1/1; clientkeys 62 (60 pass, 2 skipped); node mutation probe 110/110 killed (fix-wave-1 95, final review W1–W10, fix wave 3 5) (private `CARGO_TARGET_DIR`; a shared target gave false survivors).

**Built:** `scaas-node` on the new tree: `src/abi.rs` (`MetaTransaction`, `MetaTransfer`, `TradeOrder`, `Leg`, `DexOrder`,
`Settlement`, `IToken`, `ISCaaSDex`, `IMandateWallet` errors), `src/metatx.rs` (`Mtx { Call, Transfer }`, salted
`Domain`, wire forms with `struct`), `src/guard.rs` (call table with the P4 rows, `chainUid()` binding, selector tables
from `mtxSelectors()`, `mtxSettle` gas by simulation, ERC-1271 floor 432,349, `already_invalidated`), `src/dex.rs` and
`src/dex/venue.rs` on the `SCaaSDex` clone (`TradeOrder`/`DexOrder`, `mtxSettle`, outside legs, cancels where the order
lives, `SigCheckGasStarved` split, empty `MatchFailed` = `out_of_gas`), the mesh EVM body with `salt`, `Chain::uid()`
(block 0 or `chain_uid`; a wrong pin refuses the lane); clientkeys `checkPayment` on `MetaTransfer` with `chainUid`,
`checkCall`, `tradeOrderTypedData`, `orderCancelTypedData`, `checkTradeOrder`; KATs with relayed calldata and the new
`dex_order_kat.json`, `hedera_kat.json` v3; deploy: two demo tokens from `OpenFactory` (`demo_token`, `demo_token_2`),
v1 keys gone. The v1 line (`MetaToken`, `HederaMetaToken`, `OpenFactoryV1`, `MetaTxDex`, `SCaaSDexV1`, their tests and
vectors, the Hedera smoke) is in `smartcontracts/evm/legacy/p5/`; the node's and clientkeys' v1 encoders in their
`legacy/p5/` (not built).

**After the reviews (fix wave).** The outbox normalizes `feeRecipient`/`relayer` for every origin (`work_from_job`) and keys
in-flight work by the token's own digest, read after the guard; the guard runs in `Submitter::submit`, and metatx/entry
targets must be registered tokens (entry: or a listed DEX), else `TOKEN_NOT_SERVED`; token lists refresh every 15 s; a job
with `receiver_fee` is refused. The venue's signature check mirrors `SigCheck` (7702 designators ECDSA only, ERC-1271 capped
by codehash, exactly 32 bytes returned); a revert naming no order probes each SCaaS leg for evidence, else 503, never 400;
pending amount per order, closing fills wait for it; drops are committed before the 503. The Hedera lane checks `chain_uid`
at start and reports `already_invalidated`; jobs rebuilt after a restart pass the guard and the 2^24 gas clamp (a refused
one is only logged and gap-filled).
Fix wave 2 changed the clientkeys API: every check takes the client-built intent (`checkPayment` needs `payee`, `entryRef`,
`expectedToken`, `amount`; `checkCall` takes `call = {contract, data}`; `checkTradeOrder` the client's `order`; new
`checkCancel`, `payLane`), pins the payment lane and returns the fee. Fix wave 3 (final review): venue/guard/adapter
chain-I/O tests; a lane whose `chain_uid` check fails stays stopped and retries with backoff (the node keeps running);
the gateway runs the guard before simulating; settle refusals name the failing settlements; a guard-refused rebuilt
job is reported (`mined` from its hash, `dead` when the gap-fill lands); `node.example.toml` pins `chain_uid`.

**Rulings N1–N18 (plan header).** **N1** `struct` absent = `transfer`, unknown fields refused; **N2** `chain_uid` from block 0
or config, a mismatch stops the lane; **N3** call table only for built contracts, `mtxExecuteAsOwner` under the wallet rule,
token entries as `metatx` jobs; **N5** `mtxSettle` gas ×1.5 until every settlement settles, a whole-call revert is final;
**N6** `MinNonceNotIncreasing` = consumed `already_invalidated`; **N7** venue rules (one settlement per taker, crossing
remainder dropped, makers restored first, `ESCROW` refused, fee rate by role); **N13** deploy without v1; **N14** v1 to
`legacy/p5/`, `MetaTxGasV2.t` against frozen v1 numbers.

**Not done / next:** bamboo-dms follows before the P5 node reaches a chain Odoo uses (TODO P5: jobs with `struct` and
salted digests, KAT repoints, DEX book shapes, events, `already_invalidated`, mesh vectors, deploy keys, the portal
bundle); deferred (TODO MT-8): batching and the per-selector breaker (NODE-LANE-11, -25), TradeEngine (P7),
NODE-IDX-06 `repeat_of`, `ua_metatx`, client Zether encoders after P3b, the per-poll market re-check; open questions in
the plan.
### Session 2026-10-11 (P3b)

**State:** P3b (Zether storage and auditor modes, owner 2026-10-11) built from the plan `docs/superpowers/plans/2026-10-11-p3b-zether-modes.md`;
the spec rules CTR-ZTH-30/38/42/48/49/50 flipped to built, §19 re-measured, PQZ (CTR-PQZ-19/23/24) spec only.

**Rulings to confirm (controller, pending the owner):** the commitment `keccak256(R)` over `R = salt ‖ B_1 ‖ … ‖ B_M` (the spec table now says so), the `…/v2` proof system id label, `seed_zether` = the R33 conf key `x`, `AuditorForbidden` for NONE, the registry's `keyOf`, the `uint8` config fields with typed errors.

**Not done / next:** R6 (archive of `TransferBundles` for receiver and auditor), transfers over the EIP-7825 cap (the prover refuses them by its measured transaction gas limits per curve, form, auditor and direct / relayed, zether.md §19; no contract cap), the client ABI (P5). Done in P5: the node's gas padding clamped to 2^24.

### Session 2026-10-11 (P4)

**State:** P4 on branch `p4-accounts`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p4-accounts-mandates.md`.
1001 forge tests; size gate 0 errors (every token +8 B for the `_selfSender` hook, baseline raised; `MandateWallet` 15,509 B, `HederaMandateWallet` 15,997 B, both under the cap); clientkeys 56 (54 pass, 2 skipped);
Solana 42, Sui 68, Aptos 105 (+ entry check), Soroban 28, Cosmos 10, TON 28; e2e 4/4 and e2e_hedera 1/1; mutation probe 79/79 killed.

**Built:** `src/account/SmartKeyAccount.sol` and `SmartKeyAccountFactory.sol` (`chainUid` constructor argument, `chainUid()`),
`src/wallet/MandateWallet.sol` (`owner`, `chainUid`; `epoch[token]`, `revoke(token, epoch)`, `payUnderMandate(…, epoch)` (selector `0x781fc8a8`), `mtxPayUnderMandate`, `mtxRevoke`,
`mtxExecuteAsOwner`, `mandatePayLane`, `mandateRevokeLane`), `src/hedera/HederaMandateWallet.sol` (HIP-632 for 64-byte signatures,
`mtxExecuteAsOwnerRaw`), `MetaTxBase._selfSender`; Solana `state::SmartKeyAccount`; clientkeys `metaTxTypedData`,
`ownerCallTypedData`/`checkOwnerCall` on the salted `MetaTransaction`; KATs `smart_key_account_kat.json`, `mandate_pay_kat.json`,
`mandate_revoke_kat.json`, `smart_key_account_create2.json`; deploy JSON `smart_key_account_factory` / `_implementation`. Tests
`test/account/SmartKeyAccount.t`, `AccountKat.t`, `test/wallet/MandateWallet.t`. The typed-struct line is in
`smartcontracts/evm/legacy/p4/` (not built).

**Rulings L1–L18 (plan header).** **L1** the `_selfSender` hook; **L2** the account checks itself through its own
`isValidSignature`; **L3** `cancelRecovery` allowlisted; **L4** `SubjectKey` keeps its name; **L6** pre-P4 clones and wallets are
redeployed (every chain is a test chain); **L7** `NotDelegate`, lane encodings; **L11** Hedera HIP-632 on every wallet entry; **L12** (reversed by the owner) the rename
covers the contract accounts (EVM, Solana, Soroban); Sui/Aptos keep `meta::Account<T>` (a per-token balance object), TON/Cosmos have none; **L13** Solana discriminator follows
the name, no state migration; **L14** deploy JSON keys renamed.
Controller rulings after the reviews, pending the owner (mandates.md CTR-ACC-07): the delegate's pay names the mandate epoch (`StaleEpoch(current, signed)`; a revoke, and any `setMandate` even a plain expiry extension, voids queued delegate pays; the pay job re-reads `epoch(token)` and re-signs); `setMandate` keeps `periodStart`/`spentInPeriod` when the delegate and `periodSeconds` are unchanged. Documented, no code: an owner hand-pay plus a delegate pay of the same `entryRef` can pay twice; the kill-switch revoke job must re-read the epoch after a `setMandate`. M1/M2 are EVM-only (TODO: one follow-up per other family).

**Not done / next:** bamboo-dms follows before P4 contracts reach a chain Odoo uses (owner call with `chainUid`, mandate digests and the pay calldata with the epoch, its relay job still on pre-P4 names like `revokeWithSig`, CREATE2 file, JSON key; TODO P4); the node's
call table for the renamed rows (P5); open questions in the plan (agent mandates from `docs/research/node-ai-agents.md`).

### Session 2026-10-11 (P3)

**State:** P3 on branch `p3-zether`, merge pending; head is the fix-wave-2 commit on `f847471` (final review I1, m1–m7). Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`.
977 forge tests; `zether-prover` `cargo test` 53 green (the `read_balance` BrokenPipe flake fixed); e2e 4/4 and 1/1; real `deploy.sh evm` broadcasts on anvil 31337 green both default and with `DEPLOY_ZETHER=1` (27 txs, BLS verifier 14.08 M gas). Fix wave 2: the Zether deploy is opt-in (`DEPLOY_ZETHER`), `deploy.sh` adds `--code-size-limit 65536 --gas-estimate-multiplier 105` and keeps the previous JSON on a failed broadcast, `ZetherDeploy.t` checks JSON keys, the SmartKeyAccount implementation and per-tx gas under EIP-7825, kind 3 `initialSupply` pinned, stale docs. Fix wave 1 (review follow-ups): S3 disclosure vectors through `ZetherDisclosure` (chain-B negative), every published selector relayed once on both kinds, the stronger invariant (legs 1:1 and 3/7, rate changes, surplus never drops), `OpenFactory._checkZether` probes low level (typed error on a permissive fallback), the prover API refuses `unwrapBinding` outside `proveBurn`.

**Built:** `src/zether/ZetherLib.sol` (external, `scaas.zether`), `ZetherLayer.sol`, `NoUnderlyingZetherToken.sol` (kind 2),
`UnderlyingZetherToken.sol` (kind 3: `zetherWrapShield`, `zetherUnshieldUnwrap`), `ZetherStatements.sol`, the new
`IZetherToken.sol`; `MetaTxBase._envelopeBinding` / `_ticketBinding` (transient `scaas.mtx.binding`); `ERC20MetaTx._domainName`
(`"SCaaS ZetherToken"`); `ConfidentialConfig.maxShielded` / `confidentialFee`; `OpenFactory` Zether gate and verifier check;
verifier header 416 B and `ZetherDisclosure` challenge with `chainUid`; `DeployBase` deploys the Zether stack on dev chains when `DEPLOY_ZETHER=1` (opt-in; `deploy.sh` adds the forge flags);
the Rust prover on the new header, digests and ABI (vectors regenerated, `envelope.json`); from the disclosure review,
HASH stored in one `bytes32` slot and the `ITransferDisclosure` NatSpec corrected (G2, G5). Tests: `ZetherNone.t`,
`ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherRelay.t`, `ZetherUnderlying.t`, `ZetherInvariant.t`, `ZetherDeploy.t`,
`v2/FactoryZether.t`. The old `ZetherToken` line is in `smartcontracts/evm/legacy/p3/` (not built). Sizes:
`NoUnderlyingZetherToken` 30,659 B, `UnderlyingZetherToken` 40,381 B, `ZetherLib` 15,662 B (ratchet baseline).

**Rulings K1-K18 (plan header).** **K1** `chainUid` in every token-side digest, the prover's `s` too; registry unchanged.
**K2** the kinds are the public kinds plus the layer. **K3** domain `"SCaaS ZetherToken"` by a hook. **K4** two config
fields. **K5** the gate on `OpenFactory`. **K6** every confidential op allowlisted `ABSOLUTE`. **K7** the ticket binding
hook, not cleared. **K8** a direct unshield-unwrap binds its leg and `minOut`. **K9** reserve invariant by construction,
`executeRate` counts the shielded part. **K10** events. **K11** shapes, standalone `IZetherToken`. **K12** statement views
take `envelopeBinding`. **K13** `TransferToSelf` for a fee to the token. **K14** old line to `legacy/p3/`, no node change.
**K15** prover ABI. **K16** deploy on dev chains. **K17** size. **K18** not built (PQZ batch hook, registry `chainUid`).
**K19** disclosure carried over, the review's G2–G5 folded (HASH one slot, relayed HASH, `chainUid` in the challenge).

**Not done / next:** P4 (`MandateWallet`, `SmartKeyAccount` on `MetaTxBase`); the disclosure review's answers (open
questions in the plan); a real-passkey Zether envelope test; gas of `zetherWrapShield` / `zetherUnshieldUnwrap` (the zether.md tables were re-measured on the new kinds, these two are not in them); open questions for the owner: the prover's `s` derivation (SHA-512, not the spec's HKDF), binding the leg and `minOut` in a relayed unshield-unwrap.

### Session 2026-10-11 (P2c)

**State:** P2c on branch `p2c-dex`, merged `d85fc8b` (code `dbf27a5`, tests `ae23be1`). Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`.
949 forge tests.

**Built:** the exchange path on `SCaaSDex` (`src/dex/SCaaSDex.sol`, `ISCaaSDex.sol` with `IExchangeExecutor`): `mtxExchange`
(interactions), `mtxExchangeVia` (executor), `setExchangeTarget`, `setListedOnly`, `exchangeTarget`, `tokenKnown`;
`ExchangeLegSettled`, `ExchangeTargetSet`, `ListedOnlySet`; `NoLegs`, `TokenNotKnown`, `ForbiddenTarget`, `ForbiddenSelector`,
`TargetNotListed`, `InsufficientOutput`. Tests `test/v2/DexExchange.t.sol` 36 (mock router, v2-style pairs, executor,
hostile targets). Sizes: `SCaaSDex` 21,826 B (was 14,722); tokens unchanged; no deploy change.

**Rulings J1-J11 (plan header).** **J1** Path A bounds at the pull (token or `TradeLib`), Path B by the DEX, as in
`mtxSettle`. **J2** known = a side of a listed market, counted per market. **J3** a pull check refuses an inexact sell
token before any interaction. **J4** every `approve` interaction reset to 0 after the last one (stricter than the spec), and `increaseAllowance` and Permit2 `approve` are refused (controller ruling, pending the owner; other raising selectors such as `increaseApproval` stay open).
**J5** leftovers fail the final conservation check. **J6** error arguments. **J7** under the listing condition the tokens
an interaction calls are targets too. **J8** `NoLegs`. **J9** `receivedFloor` is gross. **J10** no Uniswap fork test yet.
**J11** no deploy change; two storage fields appended.

**Not done / next:** the Uniswap fork test and the DEX invariant suite (dex.md section 14); the node's TradeEngine (P7);
`checkOrder` (H7) and the Hedera ED25519 limitation stay as in P2b-2.

### Session 2026-10-11 (P2b-2)

**State:** P2b-2 on branch `p2b2-dex`, merged `7049c78` (code `f4afbca`, plan `7b77cd1`, tests `6b9c645`). Plan
`docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. 913 forge tests.

**Built:** `src/dex/DexPuller.sol` (`pull(token, from, amount)`, only the DEX), `ISCaaSDex.sol` and `SCaaSDex.sol` extended: outside
legs as `DexOrder` in the DEX domain (`dexOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`, `minNonce`,
`puller()`), `TradeLib` on the DEX's own `scaas.trade` state, `mtxCancelOrders` / `mtxInvalidateNonces`, the ERC-1271 cap by
codehash (the constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes,
`SigCheckGasStarved` reverting the whole `mtxSettle`, payouts by `SafeERC20`. Tests: `Dex.t.sol` 36, `DexOutside.t.sol` 21
(19 plus a hook-token re-entry test pinning `nonReentrant` on all entries, and a starved check inside a SCaaS leg).
Sizes: `SCaaSDex` 14,722 B, `DexPuller` 624 B, every token +9 B (the `precheck` argument; baseline raised).

**Rulings H1-H10 (plan header).** **H1** an outside leg is a `DexOrder` checked by `TradeLib` on the DEX's state; `ESCROW`
refused. **H2** the `DexPuller` is deployed by `initialize` (a clone runs no constructor). **H3** the cap by codehash;
Hedera passes no implementation, so 50 k. **H4** `MatchFailed` keeps 256 bytes (an `Error(string)` of ~160 bytes whole).
**H5** `SigCheckGasStarved` reverts the whole call; a listed token, or a party's contract `destination` through a hook
token, can forge the selector, so hook tokens are never listed and the node splits such a batch per settlement. **H6** DEX
cancels: bad-signature or closed items skipped, never expire. **H7** `checkOrder` not built (pending the owner). **H8**
inexact tokens are the admin's listing job, conservation the backstop. **H9** tests. **H10** size baseline +9 B per token.

**Not done / next:** `checkOrder` for the new DEX (H7, with the node's P7 intake); the DEX invariant suite (dex.md section 14);
Hedera ED25519 accounts cannot sign `DexOrder` or DEX cancels (no HIP-632 branch; `IS_HEDERA` in `SCaaSDex` later); P2c plan:
`mtxExchange` / `mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`.

### Session 2026-10-11 (P2b-1)

**State:** P2b-1 on branch `p2b-dex`, merged `0510c7d` (code `27b9e92`, plan `80303f9`). Plan
`docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. 891 forge tests.

**Built:** `src/dex/ISCaaSDex.sol`, `SCaaSDex.sol` (clone implementation, ERC-7201 `scaas.dex`, salted domain `("SCaaS
Dex","1",chainId,clone,chain_uid)`): `mtxSettle` (one taker, many makers, each settlement a self-call `settleOne`),
`setMarket(base, quote, listed)` classifying tokens from the factory, `setFeeSplit`, `LegSettled`/`MatchFailed`;
`OpenFactory` DEX catalogue (`registerDexImplementation`, `dexImplementationOf`, `latestDexVersion`, `createDex`, `isDex`,
`dexVersionOf`, events `DexImplementationRegistered`, `DexCreated`); `script/DeployBase.sol` deploys and registers the DEX
implementation (JSON `dex_implementation`, no clone). Tests `test/v2/Dex.t.sol` (36). The built DEX is `SCaaSDexV1`
(contract and its two test files renamed), still deployed for the node (`dex.rs`, `dex_kat.json`, `scaas_dex`) until P5.

**Rulings G1–G7 (plan header).** **G1** P2b is split: P2b-1 SCaaS legs, P2b-2 outside legs, P2c exchange path; an
outside-token market lists but settles `OutsideLegNotBuilt(token)`. **G2** `SCaaSDexV1` kept for the node until P5, then
`legacy/` (owner: backup, not delete). **G3** Path A bounds are the token's; the DEX checks Path B on the matched part
(`Overfill`, `BelowMinFill`, `PriceLimit`). **G4** arrangement checks `TokenMismatch`, `SelfTrade` (a maker's `from` =
the taker's), `DuplicateOrder`, `WrongRelayer`, `DexMismatch`, `NoMakers`, `FillMismatch`. **G5** registry names with
`dexVersionOf` (the token `versionOf` stays the token one); the implementation answers `factory()`/`chainUid()`. **G6**
conservation on the settlement's two tokens, `LegSettled` per leg. **G7** scripts register the implementation, no clone.
Sizes (owner: not a concern, waiting for Glamsterdam): `SCaaSDex` 9,574 B, `OpenFactory` 8,476 B, `SCaaSDexV1` 13,204 B.

**Not done / next = P2b-2 plan:** outside-token legs (`DexOrder`, `DexPuller`), DEX-side `mtxCancelOrders` and
`mtxInvalidateNonces`, `checkOrder`, the ERC-1271 cap; then P2c (exchange path, `setExchangeTarget`, `setListedOnly`). The
spec's `FeeWouldStick` is not a named error in `SCaaSDex` (the split is validated at `setFeeSplit`/`initialize`).

### Session 2026-10-11 (P2a)

**State:** P2a merged into `main` as `6a5c6b0` and pushed (code `a78d4d8`, fixes `341e3eb`, `a930c27`; plan `dbbaed5`). Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. 855 forge tests.

**Built:** `src/trade/ITradeToken.sol` (structs, events, errors) and `TradeLib` (ERC-7201 `scaas.trade`
`0x2c9c6bfc…2f00`; `precheck` → the token's signature check → `record`); in `ERC20MetaTx` (every kind) `mtxTrade`,
`mtxCancelOrder`, `mtxInvalidateNonces`, `tradeOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `pulled`,
`minNonce`; on `UnderlyingToken` `mtxWrap` (`UnderlyingLib.wrapBySig`) with `NativeNotGasless`, `WrapOrderInvalid`,
`WrapReceivedMismatch`. Tests `Trade.t` (21), `MtxWrap.t` (16), `TradeKat.t` (1, `test/vectors/trade_kat.json`).
Neither `mtx…` trade entry nor `mtxWrap` is allowlisted; `MsgSenderLint` pins their direct `msg.sender` reads.

**Rulings F1–F6 (plan header).** **F1** `TradeLib` is split around the signature (two delegatecalls) because the
signature check, with the Hedera branch, stays the token's. **F2** error names the spec leaves open:
`MinNonceNotIncreasing(current, requested)`, `MinNonceAboveCap(requested)`, `NotDex(caller)`, `DexNotContract(dex)`.
**F3** `mtxWrap` errors; the relayer binding is the underlying's `mtxTrade` (the wrapper passes `msg.sender` as
`submitter`). **F4 (flag to the owner):** size. `NoUnderlyingToken` 22,951 B is **over its 20,480 B budget** (under
EIP-170), `UnderlyingToken` 29,974 B, `ZetherToken` 28,860 B; all in the ratchet baseline, size-pin tests NONE ≤ 23,552 and
UNDERLYING ≤ 30,720; `TradeLib` 3,104 B, `UnderlyingLib` 11,654 B. Optimise later (owner). **F5** the new KAT is
`trade_kat.json`; `dex_kat.json` stays the built `SCaaSDex` `Order` vector the node reads until P2b/P5. **F6** the trade
entries live in `ERC20MetaTx`, so every kind on `MetaTokenBase` (NONE, UNDERLYING) has them; `ZetherToken` (on `ZetherMetaTx`) and v1 `MetaToken` have no `mtxTrade` (Zether in P3). `EscrowFillShape`, `NotDex`, `DexNotContract` are named by the spec; only the arguments of the last two were open. Fix commits: 341e3eb and the final-review wave.

**Not done / next = P2b plan:** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` (Path A/B), `DexPuller`;
the old `SCaaSDex` is kept as `SCaaSDexV1` for the node until P5 (done in P2b-1 except `DexPuller`). Then P2c (exchange path). `mtxWrap` on `ZetherToken`
comes with P3.

### Session 2026-10-11 (toolchain + chains)

**State:** on `main` (pushed): solc **0.8.37**, `evm_version = "osaka"` for every profile (owner: all chains Osaka,
Celo included); BSC (56), Polygon PoS (137), Base (8453) seeded `draft` in `docs/networks/evm.md` §1 with profiles
`bsc`/`polygon`/`base` (survey of 2026-10-11, RPC-probed: EIP-2537, EIP-7702, P-256 `0x100` and the CREATE2 deployer live
on all three; Polygon: 32,768-byte code and 2^25 tx gas cap, no `safe` tag; Base: L1 data fee, `l1_batch` finality).
e2e runs anvil `--hardfork osaka --gas-limit 16777216` (EIP-7825: a tx without a gas field got the 30M block limit and
was refused). Under Osaka, forge has native P256VERIFY at `0x100`: the passkey gas tests use it (no etched stub).
Size baseline: `ZetherToken` 28,860 (solc 0.8.37). 817 forge tests (two stub/estimate passkey tests merged into one).
Not done: the Odoo `blockchain.chain` seeds for the three chains (bamboo-dms; owner asked why it matters — not needed
for SCaaS itself); EIP-7954 (64 KiB code) is a draft, the SCaaS testnet keeps `maxCodeSize` 24,576.

### Session 2026-10-11 (P1e)

**State:** P1e merged into `main` as `e433bf5` and pushed (819 forge tests; e2e 4/4 and e2e_hedera 1/1;
docs checker 0 errors). Plan `docs/superpowers/plans/2026-10-11-p1e-openfactory.md`. P1 is complete except these
parked items: MT-1 (the v1 line is kept as `…V1` until P3/P5), MT-3 (the v1 approve rule), MT-4 (`salt = chain_uid` in the other
domains, E10), and the P1d test gaps in TODO.

**P1e delivered:** `OpenFactory(registrar, chainUid)` (`createToken`, `createTokenUnregistered`, `TokenConfig`, one
`TokenCreated`, `isToken`; registration reads `kind()`, `factory()`, `chainUid()`); both token kinds implement
`initialize(creator, version, TokenConfig)` and a constant `kind()`; a field of another kind reverts
`ConfigFieldForOtherKind`; the factory indexes the same `cfg.legs` the token reads. The v1 line is renamed
`OpenFactoryV1`/`IOpenFactoryV1`/`IFactoryTokenV1`; factory v2 is backed up in `smartcontracts/evm/legacy/p1e/`.
`script/DeployBase.sol`: every contract by CREATE2 through forge's deterministic deployer (`DEPLOY_SALT`), `_setup`
requires the deployer, `_gate` checks `chainUid()`; both deploy scripts on it; JSON keys `token_factory`,
`implementation_none`, `chain_uid` (`factory_v2` and `implementation_meta_none` are gone). CI size gate
`scripts/size_gate.py` with `smartcontracts/evm/size-baseline.json`.

**Rulings E1–E10 (plan header).** For the owner: **E1** the v1 line stays in the build as `…V1` until the node and
clientkeys (P5) and Zether (P3) move, then `git mv` to `legacy/` (backup, not delete). **E7** CREATE2 for every deployed
contract, `forge script --broadcast` needs `--sender` (`deploy.sh` and the e2e pass it); linked libraries are still
placed by forge from the sender, not by CREATE2. **E9** the size gate is a ratchet: token implementations ≤ 20,480 B,
others ≤ 24,576 B, init ≤ 49,152 B; baseline `UnderlyingToken` 26,449, `ZetherToken` 28,849; it does not tighten itself.
Also: E2 v2 becomes `OpenFactory` (`git mv`); E3 no Zether or DEX creation yet (P3, P2); E4 `kind()` is a pure constant;
E5 `ConfigFieldForOtherKind`; E6 one source for the legs (the P1d D8 cross-check is gone); E8 the deploy gate; E10 other
domains' `salt = chain_uid` is not in P1e (MT-4 stays open for them).

**Sizes (forge build src --sizes, runtime B):** `NoUnderlyingToken` 20,196 (284 left of 20,480), `UnderlyingToken` 26,449
(over EIP-170), `UnderlyingLib` 10,096, `OpenFactory` 6,850, `OpenFactoryV1` 6,057, `ZetherToken` 28,849.

**For integrators:** the factory's underlying index is only as truthful as the implementation; trust it for registered
versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0.

**Parked (TODO, P1e follow-ups):** the ratchet does not auto-tighten; `deploy.sh` requires `PRIVATE_KEY`; the P1d parked
test gaps stay; `OpenFactory` accepts registration of kinds 2 and 3 before P3 (only the PQZ kinds 4–7 are reserved).
Main has a newer commit (`7c90483`, Gnosis profile `prague`, `docs/networks/evm.md` table row) that this branch lacks;
the merge should be clean (that table row was not touched).

**Next action:** write the **P2** plan (`TradeLib`, `SCaaSDex` as a clone, `createDex`): find room in `NoUnderlyingToken`
first (284 B left).

### Session 2026-10-11 (P1d)

**State:** P1d merged into `main` as `d03d894` (814 forge tests; e2e 4/4 and e2e_hedera 1/1;
docs checker 0 errors). Not pushed. Plan `docs/superpowers/plans/2026-10-11-p1d-underlyingtoken.md`.

**P1d delivered:** one `UnderlyingToken` (kind `UNDERLYING`, 1–8 legs) over the external `UnderlyingLib`
(`scaas.underlying`, slot formula in CTR-TOK-24); `SingleUnderlyingToken`, `MultiUnderlyingToken`, `HederaTokensV2` and the
Hedera children are gone (HTS check and association run in `UnderlyingLib` init under `IS_HEDERA`). Native-coin leg
(CTR-TOK-26). Rate admin and guardian are `AdminLib` roles (`renounceRole(bit)`; `rateAdmin()`, `guardian()`,
`renounceRateAdmin`, `renounceGuardian` removed). `IUnderlyingToken` carries the events and errors. `_legCount` is removed:
linear layout is ERC-20 slots 0–4. Tests: `Underlying.t.sol` (9), `NativeLeg.t.sol` (13), the rest ported.

**Rulings D1–D12 (plan header).** For the owner: **D2** size is out of scope: `UnderlyingToken` 25,408 B is over EIP-170
(24,576) and the 20,480 B budget, so it cannot be deployed on a real chain; the deploy scripts still deploy only
`META_NONE`; the size work (at the latest the P1e CI gate) must bring it down. **D4** rate admin and guardian are roles,
a role may have several holders, `renounceRole` leaves the rate and a pending change. **D6** native leg has 18 decimals,
8 on Hedera (tinybars; display only). Also: D1 `mtxWrap` and `NativeNotGasless` move to P2; D5
`disableFeature(RATE_ADJUSTABLE)` cancels a pending change; D7 `NativeValueMismatch(value, expected)`; D8 init =
`abi.encode(UnderlyingInit)`, legs must equal the factory's `underlyings`; D9 `META_SINGLE` takes 1–8 legs, nothing
implements `META_MULTI`.

**Sizes (forge build --sizes):** `UnderlyingToken` 25,408, `UnderlyingLib` 11,018, `NoUnderlyingToken` 20,038,
`AdminLib` 3,406, `HederaLib` 753; over 24,576: `UnderlyingToken` and `ZetherToken` (28,849) only.

**e2e:** the first `e2e` run failed all four ("forge script failed", 0.6 s); a second run and each test alone passed 4/4.
Cause found in P1e: `e2e.rs` did not create `deployments/` on a fresh checkout, so the script's `writeJson` failed on the
first run (not a cold forge build); fixed in P1e. `e2e_hedera` 1/1.

**Parked (TODO, P1d follow-ups):** test gaps (single-asset selector through `mtxExecute` on a two-leg token, native
`UnderlyingTransferMismatch`, native `addReserve` with value > amount, guardian revoke); `OpenFactoryV2` `META_MULTI`
count branch is dead until P1e.

**Next action:** write the P1e plan (factory
`createToken`/`TokenConfig`, CREATE2 deployer, deletions of the v1/v2 lines, size gate; D2 lands here at the latest).

### Session 2026-10-10 (P1c)

**State:** P1c merged into `main` as `3a43c2e`, not pushed (792 forge tests, e2e 4/4 + e2e_hedera 1/1, KAT vectors
unchanged, docs checker 0 errors). Base `d827062`; not pushed.

**P1c delivered:** `AdminLib` (flags, owner, roles in `scaas.token`; CTR-TOK-22) with all events and errors in the new
`ITokenAdmin` (`src/metatx/ITokenAdmin.sol`), so they are in the token ABI; new `RoleAccountZero(uint8)`. `MetaTokenBase`
on `AdminLib`: `PAYABLE` gate on `mtxPay`/`payWithFee`/`mtxPayReceiverFee`, ERC-165, `IS_HEDERA`. `HederaLib` replaces
`HederaV2Lib` (`requireValid` public view, linked); `HederaNoUnderlyingToken` deleted. `NoUnderlyingToken` uses the
`MINTABLE`/`BURNABLE` flags and roles (no `minter()`, `MinterRenounced`, `NotMinter`). Wrappers report legacy powers as flags (C5).
`test/v2/Features.t.sol` (13 tests).

**Rulings for the owner:** C1 own `AdminLib`, not OZ `AccessControlDefaultAdminRules` (two-step owner, no delay); C2 flags
5–8 refused at init with `FeatureNotBuilt` until the asset suite; C3 no external `PayLib` (pay is inline over the
`MetaTransfer` core, gated by `PAYABLE`; +2.6 k gas on a fresh lane), so PAYABLE is advisory for payments (a signed payment still settles
through `mtxExecuteTransfer`); gating `entryRef ≠ 0` would contradict T2 — owner to decide; C9 NONE has 442 B left, P2 must find room;
`ITokenAdmin` carries the admin functions, events and errors; `RoleAccountZero` refuses granting a role to address 0.

**Sizes (runtime B):** `NoUnderlyingToken` 20,038 (<= 20,480); over EIP-170: `Single` 28,296, `Multi` 29,147, `HederaSingle`
29,201, `HederaMulti` 30,052, `ZetherToken` 28,849 (until P1d); `AdminLib` 3,403, `HederaLib` 753.

**Next action:** (superseded by the P1d section above) write the **P1d** plan (`UnderlyingLib` + `UnderlyingToken`).

### Shutdown 2026-10-10

**State:** P1b merged into `main` as `fb2a234` (branch `p1b-erc20metatx`, 758 forge tests, e2e 4/4 + e2e_hedera 1/1); not pushed.
758 forge tests pass; docs checker 0 errors; the node e2e suites (`e2e`, `e2e_hedera`) pass against the deploy scripts,
which deploy only `META_NONE` on factory v2 until P1d and default `CHAIN_UID` to block 0's hash. The bamboo-dms repoint
is done on branch `scaas-metatx-v1-kat` (commit `81cea08`) in `/home/dockers/odoo19/custom-addons/bamboo-dms` — not
merged into its main; the owner merges.

**P1b delivered:** v1 names suffixed `…V1`; `MetaTransfer` + `IERC20MetaTx`/`IERC20Payment`; `ERC20MetaTx` on `MetaTxBase`; the v2
line moved onto it (named builders, per-kind allowlists, gasless burn/wrap/unwrap; `MetaTxCore` and the op dispatch removed);
receiver-pays (`mtxPayReceiverFee`, `ReceiverFee` co-signature, token as fee recipient refused as `TransferToSelf`, HIP-632 payee
test); conformance + `msg.sender` lint; KATs `metatx_kat.json` (unchanged) and `metatransfer_kat.json` (new) written on a
`NoUnderlyingToken` clone.

**Rulings for the owner:** R3 wrappers over EIP-170 until P1d; R4 UA ledger split moved to UA F1; R7 SmartKeyAccount name on the
token side now (`SMART_KEY_ACCOUNT_IMPL`; the account contract stays `SubjectAccount` until P4).

**Sizes (runtime B):** `NoUnderlyingToken` 17,602, `HederaNoUnderlyingToken` 18,057 (both <= 20,480); over EIP-170: `Single` 26,102,
`Multi` 26,951, `HederaSingle` 27,417, `HederaMulti` 28,266, `ZetherToken` 28,849.

### Shutdown 2026-10-09 (evening)

**State:** `main` = `1d51d22` (P1a merged), pushed; tag `ref/pre-token-tree` (→ `dc429c4`) pushed. Tree clean. 712 forge
tests pass; docs checker 0 errors (2 known budget warnings: `token-wrappers.md` 986 > 845, `dex.md` 538 > 520 — owner call).

**Next action:** write the **P1b** plan (`ERC20MetaTx` on `MetaTxBase`: `MetaTransfer` + `mtxExecuteTransfer`/`mtxBatchTransfer`,
fee classes on tokens, receiver-pays, approve only by contracts, UA path, KATs `metatransfer_kat.json`), against the code P1a
left; then execute subagent-driven like P1a. P1b notes (a)–(h) are in TODO §00 under P1.

**P1a delivered** (plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`, 9 tasks + final review):
- `legacy/` (27 reference copies, not built) + tag `ref/pre-token-tree`.
- `src/common/SigCheck.sol` — one signature check (ECDSA low-s; ERC-1271 capped, ≤32 B returndata, starvation guard
  `SigCheckGasStarved`; 7702 designator = EOA); the three built bases use it; `SigLib` deleted.
- `src/common/SaltedEIP712.sol` — salt = chain_uid, clone-safe, `eip712Domain()` 0x1f, `ChainUidZero()`.
- `MetaTxLib`: v3 `MetaTransaction` (typehash pinned); built struct renamed `LegacyMetaTransaction` (digests unchanged).
- `src/metatx/MetaTxBase.sol` + `IMetaTx.sol` — `mtxExecute` (+ alias), `mtxBatch`, lanes, `cancelNonce`, transient sender +
  one-shot ticket (fail-closed: an allowlisted target without `nonReentrant` reverts), allowlist + fee classes
  (1 = ABSOLUTE, 2 = AMOUNT), `_chargeFee` NONE only, `_checkEnvelope`/`_useNonce` for the P1b `MetaTransfer` path.
  Mock `MtxRegistryMock` ≈ 9.4 KB — the 20,480 B token budget needs care in P1b/P1c.
- KAT: `metatx_kat.json` = v3; `metatx_v1_kat.json` = built v1 (node + clientkeys repointed).
- **Cross-repo breakage:** bamboo-dms `dms_blockchain/tests/test_eip712.py:14` reads the old path — repoint to
  `metatx_v1_kat.json` there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`).

**Owner decisions 2026-10-09:** `OrderBookDex` → **`SCaaSDex`** (done 2026-10-09, domain `"SCaaS Dex"`); integration.md rewrite later
(TODO §0); docs: README map as per-area tables, architecture.md numbered sections + contents, §1 lists smart contracts first.

**Controller rulings during P1a** (review if you disagree): RA tag on `dc429c4`; RC/RF/RG/RH/RJ several test gaps upgraded
to required (signature refusal branches, per-flag canon, end-to-end binding, alias coverage, batch replay/rollback, fee
basis offset, fee after call, per-item fees); RE refuse zero chain_uid (NET-ALL-22); RJ feeClass ≥ 3 refused; RK
`_checkEnvelope`/`_useNonce` + fail-closed ticket added in the final review. Plan defaults: refusal error
`MetaTxUnknownMode`, ERC-1271 margin 5,000 gas, fee class checked before `supportedModes()`.

### Shutdown 2026-10-09

**State:** `main` = P0 merged and pushed (`4bad99b`) + 3 local commits (TODO note, P1a plan). Tree clean. Nothing of P1 started:
no tag `ref/pre-token-tree`, no `legacy/` yet (Task 1 of the P1a plan does both).

**Next action:** execute `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md` (9 tasks; the owner has not yet chosen
subagent-driven vs native — recommended subagent-driven). Then write P1b…P1e one at a time, each against the code P1a/b/… left:

| Plan | Scope |
|---|---|
| P1a | tag + `legacy/`; `SigCheck`; `SaltedEIP712` (salt = chain_uid); `MetaTxBase` (MetaTransaction, lanes, transient sender + ticket, allowlist, `mtxExecute`/`mtxBatch`/`cancelNonce`, fee NONE only); KAT — **plan written** |
| P1b | `ERC20MetaTx` on `MetaTxBase` (`git mv MetaTxCore`): `MetaTransfer`, `mtxExecuteTransfer`/`mtxBatchTransfer`, fee classes, receiver-pays, approve-only-by-contracts, UA path, KATs |
| P1c | `MetaTokenBase`: features + owner model (`AdminLib`, regulated flags), `PayLib`, init/provenance, `IS_HEDERA` + `HederaLib`; kind `NONE` |
| P1d | `UnderlyingLib` + `UnderlyingToken` (Single+Multi merged, native-coin leg, `mtxWrap`) |
| P1e | factory `createToken`, CREATE2 deployer, deploy scripts + `chainUid()` gate, delete v1/v2 lines, CI size gate |

**P1a plan notes:** the plan's code was run in a scratch copy (692 tests pass, KAT matches `cast`). (1) The bare
`MetaTxBase` mock is 9,410 B — almost half the 20,480 B token budget (CTR-TOK-24): watch it in P1b. (2) `metatx_kat.json`
becomes the v3 vector; the v1 vector moves to `metatx_v1_kat.json` and in-repo readers are repointed — the bamboo-dms test
`dms_blockchain/tests/test_eip712.py:14` breaks until repointed there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`). (3) Defaults taken in the plan: fee classes
1 = ABSOLUTE, 2 = AMOUNT; refusal error `MetaTxUnknownMode`; ERC-1271 starvation margin 5,000 gas + error
`SigCheckGasStarved`; KAT on a mock (P1b regenerates it on a real token).

**Done today (2026-10-08/09):**
- Zether code: multi-recipient transfer + three storage modes; Z9–Z13 (no attestation, `SENDER_CP`, per-transfer auditor
  opt-out, threshold auditor key = docs only, disclosure in a stateless `ZetherDisclosure`). `ZetherToken` still 28,939 B
  (over EIP-170) — solved by P3 (`ZetherLib`).
- P0 docs fold (9 tasks, each reviewed, plus a whole-branch review): ids CTR-ZTH-37…47, CTR-TOK-21…26, CTR-MTX-25,
  CTR-AS-17, CTR-DEX-24, CTR-ACC-11, CTR-PQZ-22; `docs/README.md` absorbed `SCaaS-v2.md`; `architecture.md` 421 → 879 lines.
- `smartcontracts/evm/chain-uids.json`: genesis hashes of 26 live EVM chains (two RPC sources each). ETH/ETC and
  Avalanche/Fuji share a genesis (a chain = `(chainId, chain_uid)`); Base Sepolia / Celo Sepolia official RPCs prune block 0;
  Hedera values derived from the mirror node (first 32 bytes) — confirm against the relay; Holesky and Alfajores are dead.

**Owner rulings 2026-10-08/09 (all folded):** features chosen at creation; one owner grants/revokes per-flag roles,
disables disableable flags, `renounceOwnership` (role holders keep roles; full lock = revoke all, then renounce);
`PAYABLE` default off; Hedera = per-chain parameter; Single+Multi merged; native-coin leg (some chains lack WETH-like
tokens); confidential layer over the public balance with direct wrap-shield / unshield-unwrap; minter never mints shielded;
regulated flags refused on confidential kinds; factory creates DEX clones, `isDex` advisory only (tokens never consult it);
`SubjectAccount` → `SmartKeyAccount`; keep old code (tag + `legacy/`); refactor in place.

**Controller rulings during P0 (review if you disagree):** R4/R8 budget warnings left as warnings (`token-wrappers.md`
986 > 845, `dex.md` 538 > 520 — owner to accept or ask for a split); R7 native leg on every `UNDERLYING*` kind incl.
`UNDERLYING_ZETHER`; R10 target `zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` order; R12 target EIP-712
domain `"SCaaS SmartKeyAccount"` (P4); R14 `PAYABLE`/`BURNABLE` always locked (`disableFeature` reverts `FeatureLocked`);
R5 owner acts on a flag only by granting itself the role, OZ `AccessControlDefaultAdminRules` is the P1 candidate.

**Open (owner):** PQZ multi-recipient (hint-count risk with shared randomness) and PQZ Z9/Z10/Z12; the two budget
warnings; `docs/integration.md` rewrite (TODO §0, later). Deferred P0 minors are listed in TODO §0 ("P0 follow-ups").

### Session 2026-10-08 (evening)

Token-tree design accepted by the owner and folded (P0 done); record frozen at `docs/history/specs/2026-10-08-token-tree-design.md`
(Status line holds the id map). The Zether multi-recipient record is frozen too. Code is unchanged: every affected
section carries a "Transitional (BUILT)" note naming the phase.

- **Tree:** `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → four kinds by code (`NONE`, `UNDERLYING`, `NONE_ZETHER`,
  `UNDERLYING_ZETHER`; `*_PQZ` reserved), features by flags (payable, mint, burn, adjustable rate, wrap-disable, freeze,
  force, pause, allowlist); one owner model; Hedera as an `IS_HEDERA` branch; the native coin as an underlying leg; libraries
  `AdminLib`, `PayLib`, `UnderlyingLib`, `HederaLib`, `TradeLib`, `ZetherLib`; `SCaaSDex` as a clone. Ids CTR-TOK-21…26,
  CTR-MTX-25, CTR-AS-17, CTR-DEX-24, CTR-ZTH-37…47, CTR-ACC-11, CTR-PQZ-22.
- **TODO §00 is now phases P1–P5** (P1 = MT-1…MT-4 on the new tree, P2 = MT-5, P3 = MT-6, P4 = MT-7 + rename, P5 = MT-8/9).
- **Owner decisions for P1:** (1) keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before
  P1, plus the v1/v2 token sources and the old `ZetherToken` copied to `smartcontracts/evm/legacy/` (not built, not
  tested; README "reference only"); (2) P1 refactors in place (`git mv` + edit), not a rewrite — reuse map in TODO §00;
  `TradeLib` (P2) reuses the prototype in `/home/ha/work/blockchain/metatx/contracts`.
- **`smartcontracts/evm/chain-uids.json`** (genesis hashes of live EVM chains, two sources each) is linked from NET-ALL-22;
  a chain is identified by `(chainId, chain_uid)`.
- PQZ multi-recipient and PQZ Z9/Z10/Z12 are not owner-ruled: recorded as `open` only.

Next: P1 plan (one plan per phase, written against the folded rules), then P1 code.

### Session 2026-10-08 (afternoon)

Three designs accepted by the owner and folded (drafts frozen in `docs/history/specs/`), root README updated:

- **Generic meta-tx call** (`2026-10-08-metatx-generic-call-design.md`): `MetaTransaction{from, data, …}` for a call of
  any allowlisted function of **any** SCaaS contract (base `MetaTxBase`, fee `NONE` unless a token overrides it; gas
  paid by a sponsor), typed `MetaTransfer{from, to, value, entryRef, …}` on tokens; named functions kept, plus
  `mtxExecuteTransfer`/`mtxBatchTransfer`; `MandateWallet`/`SubjectAccount` on `MetaTxBase` (account signs as itself);
  UA ledger split the same way; `PqzToken` relays like Zether. Ids CTR-MTX-22…24, CTR-ACC-10, CTR-UA-26, CTR-PQZ-21.
- **DEX exchange** (`2026-10-08-dex-exchange-design.md`): `mtxExchange` (DEX calls AMM interactions) and
  `mtxExchangeVia` (solver executor) fill `TradeOrder`s against AMMs, multi-hop, `receiveToken` may equal the sell token;
  surplus to signers on chain; `DexPuller` holds outside-token allowances; allowlist via order flag `LISTED_POOLS` and
  admin `setListedOnly`; node TradeEngine keeps only the relayer share. Ids CTR-DEX-20…23, NODE-DEX-17/18, CLI-SGN-37.
- **Non-EVM** (`2026-10-08-nonevm-metacall-design.md`): `MetaCall` + `MetaTransfer` per family, one verification library
  + typed `mtx_*` entries (CosmWasm/TON one `MtxExecute`), `KeyOp`/mandate structs → `MetaCall`, EVM parity. Ids
  NET-ALL-26…29 and one per family. Streams NM-APT…NM-SOL in TODO §00.
- Owner rulings: PQZ is meant for public chains but **waits for a lattice precompile there** (CTR-PQZ-01 change);
  `contracts/metatx.md` line budget accepted. Phase 4 fixes from the lost `fix-cnc`/`fix-node` worktrees landed (`9476617`).

Next: code streams in TODO §00 (MT-1 first); Codex reviews still owed (needs credit). The Odoo side (`SCAAS_ROOT` in
four `dms_blockchain` tests, compose mount) is uncommitted in bamboo-dms/odoo19, left to another instance.

**Repo moved 2026-10-08** from `bamboo-dms/scaas/` to `/home/ha/work/ainative/scaas` (standalone). The bamboo-dms
`dms_blockchain` tests read vectors via env `SCAAS_ROOT` (fallback `../../scaas`); the Odoo container mounts the repo
read-only at `/mnt/scaas` with `SCAAS_ROOT=/mnt/scaas` (`/home/dockers/odoo19/docker-compose.yml`). Older sections
below still say `bamboo-dms/scaas/`. The move also surfaced two never-committed Phase 4 fix worktrees (`fix-cnc`,
`fix-node`); their fixes are now on `main` (`9476617`), so "28 findings fixed" below holds only from that commit.

### Shutdown 2026-10-08 — read this first

**Meta-transaction redesign accepted and folded.** Design record: `docs/history/specs/2026-10-07-metatx-generic.md`
(rev 5, two Claude reviews: `docs/reviews/specs/2026-10-07-metatx-generic-claude-review-{1,2}.md`, git-ignored). Rules
now live in the component docs (`contracts/metatx.md`, `token-wrappers.md`, `dex.md`, `zether.md`, `accounts.md`,
`mandates.md`, `node/job-api.md`, `node/dex-venue.md`, `networks/README.md`, `clients/signers-clientkeys.md`, …) and
`decisions.md` (30 new ids, 58 updated, 5 superseded: CTR-TOK-12/14, CTR-DEX-06/07, CTR-ZTH-11). **Code is unchanged**:
every affected section carries a "Transitional (BUILT)" note — the code streams below implement it.

Owner rulings 2026-10-07/08 (all in decisions.md, owner: yes):
- `mtxExecute`: the token calls **itself** with the signer's calldata on a fixed per-implementation selector allowlist
  (transient sender + one-shot ticket; all or nothing; never calls another contract). No `approve`, no role functions
  in any allowlist. `executeMetaTransaction` kept as an alias. Every signed entry point starts with `mtx`.
- **Only a contract may call `approve`** on a SCaaS token (EOAs never, in any form; outside tokens excepted); wrapping a
  SCaaS underlying by signature (`mtxWrap`).
- One base **`ERC20MetaTx`**; the v1 line (`MetaToken`, `HederaMetaToken`, v1 `OpenFactory`) is deleted; one factory.
- `salt = chain_uid` (genesis hash) in **every** EIP-712 domain; implementation immutable; deploys via **CREATE2**; a
  fork of a chain we run is a new chain.
- DEX: one signed **`TradeOrder`** (`from, receiveToken, amount, receiveAmount, minFill, fee, relayer, dex,
  destination, flags, batch, nonce, validUntil`) — the owner's old `MtxTradeOrder` modernized; no role in the order;
  funds move **only into `dex`**; `relayer` = matching party (0 = anyone); minimum fill = max(minFill, 50 %); one `fee`
  paid out by the DEX in the same call per an admin-set split; Path A (resting, `pulled[orderHash]`) and Path B
  (escrow + refund, IOC); one taker + many makers per call; DEX balance-conservation invariant. **Owner-accepted
  residual risk:** `dex` only has to be a contract — clients must refuse an unlisted `dex`, the node never routes one.
- NODE-IDX-06: a repeated `entryRef` is flagged by the node (`repeat_of`) **and** checked by the client (refund decision).
- Nothing is deployed anywhere: no compatibility/migration work.

Also today (all pushed except the meta-tx commits listed in `git log origin/main..main`):
- Docs reorg closed: Phase 4 reviews (28 findings fixed), 10 % second sample (111 items, 3 minor fixed), every diagram
  Mermaid, checker **C11** (ASCII art refused), plan in `docs/history/plans/`.
- Root `README.md` rewritten: chain as infrastructure, IaaS/BaaS comparison, contracts as API services, standards
  (incl. EIP-6963), shared code/upgradeability, Universal Accounts, fee models, transaction flow, open relayers,
  Zether/PQZ, design evolution.
- `clientkeys/` and `zether-prover/` moved to **`clients/`** (app planned at `clients/app/`); CI jobs `clientkeys` and
  `zether-prover` added (first GitHub run pending).
- `contracts/accounts.md` (Universal Account + passkeys + optional SubjectAccount) and `contracts/mandates.md`.

Open for the next session: the code streams in `TODO.md` §0; points the fold left open — PqzToken's envelope on the
self-call path, the Zether statement header now 416 bytes with `chainUid` at offset 96 (verify against the prover),
ExchangeOffer's gasless leg as a `TradeOrder`; non-EVM families' equivalent of `mtxExecute`/`mtx` names (separate
draft).

### Docs reorg 2026-10-07 — read this first

The specs, `SCaaS.md` and `integration.md` were replaced by one set of self-contained component docs (plan
`docs/history/plans/2026-10-07-docs-reorg.md`, tag `docs-pre-reorg` = state before). **Reading order:**

1. [`docs/README.md`](docs/README.md) — map, precedence (owner rulings > component docs > code > history > research),
   status tags, id scheme.
2. [`docs/SCaaS-v2.md`](docs/SCaaS-v2.md) — product introduction.
3. [`docs/architecture.md`](docs/architecture.md) — system overview.
4. Component docs for the area you touch: `docs/node/`, `docs/contracts/`, `docs/networks/`, `docs/clients/`,
   `docs/integration.md` (+ `integration-odoo-example.md`).
5. [`docs/decisions.md`](docs/decisions.md) — every ruling (`<AREA>-<TOPIC>-NN`), why, and the alias index. Old ids in
   code comments (`R91`, `RS5-9`, `CR-PD-1`, `UD:§23`) stay valid: `python3 scripts/docs_check.py resolve <id>`.
   Section refs in code (`NI §5.2`, `TW2 §7`) point into the frozen copies in `docs/history/specs/` (abbreviations:
   `docs/history/README.md`).

Frozen: `docs/history/` (specs, plans, `SCaaS-2026-10-07.md`, `integration-2026-10-07.md`, `blockchain.md` + trace,
reorg ledgers in `history/reorg/`); background: `docs/research/`. Checks (CI `docs` job): `python3 scripts/docs_check.py
check`, `… facts check`, `python3 scripts/test_docs_check.py`.

| Phase | Commits | What |
|---|---|---|
| 0 | `08250aa`…`a59909a` | history frozen (pure renames), checker, old-id inventory (746), id map, fact ledger |
| 1 | `a492fa9`…`4cc227c` | node, contracts, networks/clients/integration docs + register fragments, every fact placed |
| 2 | `2e9bf4e`…`e13be84` | README, architecture, SCaaS-v2, decisions.md (merged register + alias index), history README, `_work` retired |
| — | `9513731` | owner rulings: lane keys hold no roles (NODE-JOB-01/19), `max_inflight` tunable default (NODE-LANE-24), decisions.md budget accepted |
| 3 | this commit | outside references: README, TODO (stream table → Doc/Scope), this file, scaas-node README (English, rewritten), smartcontracts READMEs, code-comment spec paths, CI `docs` job |

Left: Phase 4 reviewer pass (§6.4, ≤ 3 read-only reviewers, fixes by area); then move the plan to `docs/history/plans/`.
New design work: draft in `docs/superpowers/specs/`, rules into the component docs on acceptance (docs/README "Ids").

### Shutdown 2026-10-07 (before the docs reorg)

Spec phase is almost closed: **every spec has had at least one independent review and every review is folded**.
Remaining spec work = TODO §0 (SCaaS.md/integration.md sync, a few cross-spec nits, 9 Codex reviews owed, the
9000 → 7622 sweep). No code was written today (owner rule); all bugs the reviews found in BUILT code are now spec
rulings + named fix streams (TODO §1 "Fix first").

#### Today (2026-10-07), all pushed on `main` (head `df45e59` + this handoff)

| Commit | What |
|---|---|
| d9c227a, 4fd706c, df45e59 | NI rev 3.5 (Codex: C1 admin-user escalation, tombstones, empty token subset, live-call per namespace, `outer_tx`, atomic intake, CORS) → 3.6 (spec B + UA 1.4 sync, `chain_uid` check) → 3.7 (R340–R349: breaker meters fees/value/deposits, attempt cap, grief score, mesh sig verify, payload-sourced fields, value-out cap, deposit rule, journals in store, immutable programs, one custody key) |
| bb75ad7 | UA rev 1.4 (Codex: R330 `chain_uid` = genesis hash in PoP/domain salt; R331 EIP-7702; hedera-native member; BBS not legal evidence) |
| f3c521f, 39e42ce, 991d835 | PQZ rev 1.3 (Codex: MSG_TAG, authRef binding, hint leakage on `e1`, inline lengths, self-test price, SCaaS testnet) → 1.4 (**owner: `PqzToken` implements `IERC20MetaTx`** like ZetherToken; v3 `UAMetaTransaction` for a PQ-only payer; `wrap`/`unwrap` parity; gasless exit = envelope `burn`) |
| 9fe2534 | spec B rev 1.3 (Codex: sponsorship accounting at accept, `min_valid_secs`, per-namespace dedupe, EIP-1153 prerequisite, itemized erasure log) |
| 9e27d35 | SCaaS.md/integration.md aligned (admin API keys removed, spec register, §8.12 PQZ, §9.8 UA, SCaaS testnet) — needs one more sync (TODO §0) |
| 5ea19e6 | DEX + Zether + zether-limits + consensys-max (Claude review; DX-FIX1–5, ZF-FIX1–3) |
| a23f14a, 7e986f8 | payments, wallets addendum, round3, signing formats, infra-service (Claude review; PAY/ADW/R3/WSF-FIX streams) + **owner: programs immutable at deploy** (CR-R3-11) |
| df45e59 | net-{ton,cosmos,sui,hedera,soroban,aptos,solana} (Claude review; **TON C1 BLOCK**: unbounded forward TON) |
| 191c2ed | `blockchain.md` Mermaid fix (quoted edge label with parentheses) |

#### Owner rulings today
- Private chain id **9000 → 7622** (9000 is Evmos Testnet); dev chain gets a new genesis; `chain_uid` = genesis hash bound everywhere (UA R330).
- `PqzToken` follows `IERC20MetaTx` (PQZ R284).
- Aptos/Sui/Solana programs **immutable at deploy** (fix = new deploy + migrate); agent extended it to Cosmos `--no-admin` per SCaaS §1.3 — owner may drop that line.
- MuSig2/FROST kinds kept; Soroban `C…` keys kindNo 18.

#### Reviewer state
- Codex works **only with `-m gpt-5.5`** (default `gpt-6.1-sol` rejected for a ChatGPT account; the `codex:codex-rescue` agent fails on it). Credit ran out after 4 reviews; 9 owed (TODO §0).
- Claude reviews of the 16 older specs: `docs/reviews/specs/*-claude-review-1.md`.

#### Next session
1. TODO §0 (≈ 1 hour of docs).
2. Code: TODO §1 "Fix first" (NET-TON-FIX1 first), then NI P2 → P3, UA F0 → F1, app A1.

### Earlier: shutdown 2026-10-06

SCaaS = **SmartContract as a Service: the smart contracts themselves are the API services**. `scaas-node`
(doubles as relayer) is infrastructure anyone can run, with its own policies; it is not the product.
Repo `git@github.com:dinhduongha/scaas.git`, checked out as an independent nested repo at
`bamboo-dms/scaas/` (ignored by bamboo-dms). The Odoo addons (`dms_blockchain*`) stay in bamboo-dms and read
vectors from `scaas/…`.

#### State

| | |
|---|---|
| `main` | pushed (see `git log`). Merge commits were linearised by `pull --rebase` — content is complete |
| Layout | `smartcontracts/{evm,move/{aptos,sui},soroban,cosmos,ton,solana,scripts}`, `scaas-node/`, `clients/{clientkeys,zether-prover,app (planned)}/`, `docs/` |
| Code landed this session | mesh S0 (gateway fee binding), S1a (consumed state, in bamboo-dms), S2 (R80), S3 (envelope + 32 vectors), P1 store v2 SQLite + review fixes, TW2 token wrappers v2 (EVM + Hedera), TON tx-hash fix, `bamboo → scaas` rename |
| Last gates | scaas-node `cargo test` 239/0 + clippy + e2e 4/4 (after P1 fix); forge 550/0 (TW2); every family e2e 1/1 (after rename); Odoo blockchain suite 432/0 (after rename) |
| Not deployed anywhere | domain tags renamed `bamboo.* → scaas.*` ⇒ every dev/test contract must be redeployed; DB rows `blockchain.token.domain_name` ("Bamboo MetaToken") and Cosmos `network_key` (`bamboo-1`) need updating after redeploy; operators rename env `BAMBOO_* → SCAAS_*`; every node needs `scaas-node store init` once (migration 0001 was edited in place — recreate dev `node.db`) |
| Worktrees | `.claude/worktrees/{p1,p1fix,rename,s3,tonhash,tw2}` — all merged; remove when convenient |

#### Specs (all on `main`, frozen in `docs/history/specs/` since the 2026-10-07 docs reorg), rulings and review state

| Spec | Rulings | Rev | Review |
|---|---|---|---|
| `docs/history/SCaaS-2026-10-07.md` (system) + `docs/history/integration-2026-10-07.md` | precedence | — | PLANNED material owner-review pending |
| `2026-10-05-relayer-mesh-design.md` | R70–R86 | 3 | ×2 |
| `2026-10-06-node-independence-design.md` (NI) | R87–R111 | 3.3 | ×1 + P1 code review |
| `2026-10-06-mesh-gossip-amendment.md` (A2) | R112–R128 | 2.1 | ×1 |
| `2026-10-06-token-wrappers-v2.md` (TW2) | R129–R149 | 1.2 | ×1 + impl review — **BUILT** |
| `2026-10-06-scaas-app-design.md` | R150–R179 | 1.2 | ×1 |
| `2026-10-06-tender-sponsorship-shredding.md` | R180–R199 | 1.2 | ×1 |
| `2026-10-06-asset-suite-design.md` (AS) | R200–R217 | 1.1 | ×1 |
| `2026-10-06-operations-design.md` (OPS) | R230–R247 | 1.2 | ×1 |
| `2026-10-06-signers-followups.md` (S4F) | R250–R268 | 1.0 → 1.1 in flight at shutdown | ×1 |
| `2026-10-06-pq-zether-design.md` (PQZ) | R270–R289 | 1.1 | review in flight at shutdown |
| `2026-10-06-universal-account-design.md` (UA) | R290–R318 | 1.2 (all owner items closed) | review in flight at shutdown |

Reviews (local, git-ignored): `docs/reviews/specs/`. Owner decisions are recorded inside each spec (owner-answers tables).

#### Key owner rulings this session (details in the specs)

- Node independent of Odoo; Odoo is a client (push jobs, poll feeds). Store SQLite/PostgreSQL/MySQL (storage only).
- Admin auth: built-in users (CLI bootstrap) + optional OIDC; roles viewer ⊂ operator ⊂ admin + key_custodian.
  **API keys = external server-side clients only** (never in browser/mobile apps); automation = OIDC
  client-credentials or host CLI.
- Mesh: HTTP pull bus + libp2p gossip (QUIC default, hybrid X25519MLKEM768; TCP+Noise; HTTPS); private peers PQ-only.
- Universal Account: key-derived 32-byte kind-tagged ids, no wallet contract; native single-key accounts and 1271
  need no registration; one key = one purpose; purpose `m/7622'`; MetaToken v3 UA ledger; PQ + ed25519 everywhere;
  SubjectAccount kept as option (b); VC/eKYC optional.
- Token wrappers v2: three tiers, rates fixed/adjustable (issuer option), multi-underlying any-of, named `mtx*`
  functions, gasless unwrap with `minOut`.
- Owner wants **all specs finished before app code**.

#### Constraints that bit this session

- Max 3 sub-agents; one heavy build at a time: wrap with `scaas/scripts/capped` (also `CARGO_BUILD_JOBS=4`).
- Worktrees need gitignored deps: copy `smartcontracts/evm/lib` (OpenZeppelin is a symlink to
  `/home/ha/work/blockchain/openzeppelin-contracts`), `mkdir smartcontracts/evm/deployments`, `npm ci` where needed;
  soroban e2e needs `STELLAR_BIN=~/.local/bin/stellar28`.
- `rtk` mangles `git diff`/`grep`/`ls` output in scripts — use `rtk proxy …` or `/usr/bin/grep`.
- Never `git commit -a` in scaas while an agent edits a spec in the main checkout (happened once: 9ad8711).
- Ruling-number ranges collided twice — reserve a range per spec before dispatching.
