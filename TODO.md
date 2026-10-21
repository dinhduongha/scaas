# TODO — scaas

Open work only, ordered by what blocks what. Finished items, superseded "Next" lines and the full history of the
items compacted below were moved verbatim to [COMPLETED.md](COMPLETED.md) (2026-10-20). Resume notes: [HANDOFF.md](HANDOFF.md).
The Odoo side lives in bamboo-dms (`dms_blockchain*`).

## Standing rules

Owner rulings that still constrain open work (full text in COMPLETED.md; decisions in `docs/decisions.md`).
- **Specs before app code** (owner 2026-10-08).
- **Concurrency** (owner 2026-10-08 / 2026-10-15): max 3 agents; `scripts/capped` has 2 heavy slots (`heavy`,
  `heavy.2`; `CAPPED_SLOTS` overrides), 4 GB each; docker containers need their own `--memory`.
- **Chains** (owner 2026-10-15): SCaaS testnet = testnet, resettable — the controller backs up the chain data, then resets /
  redeploys itself; 22776 = future mainnet — every change is the owner's (work on a throwaway copy), precompiles only
  after the production gates (cryptographic audit, G-LIC), and from its launch "test-only, no migration" ends there.
- **P6 mandate** (owner 2026-10-14, session 4): carry P6 to its end; merge AND push each sub-phase once tests, size gate,
  docs checkers and review pass; decisions that come up are picked from the measurements and recorded in
  `docs/decisions.md` as "controller proposal, owner may override"; UA F5 unpaused only as far as P6i needs it
  (`ua_metatx` for `kind = pqz`). Owner steps (controller drafts only): ethresear.ch / ePrint posts, LaZer mails,
  Zenodo, G-LIC, the lawyer.
- **Priority** (owner 2026-10-13): P6 / PQZ first; UA-5c and UA F5 paused until then. Owner 2026-10-19: the P0 PQZL
  Fiat–Shamir fix first; the token-family rename before P6h / P6i / P6j / P6-PUB.
- **Gas calibration** (owner 2026-10-15): one run; re-calibrate before 22776; timing on a quiet host (ask the owner to
  stop other heavy sessions first).
- **One `PQZ` precompile for PQZL and PQZH** (owner 2026-10-14): dispatch on `proofSystemId` via `pqz-ffi`, each id
  priced separately, node limits sized for the PQZH input 393,216 B (CTR-PQZ-10).
- **`R_TXM` e2 bound per vector ≤ 64** in ℓ2, not one block bound 64·√M (owner 2026-10-15, CTR-PQZ-03).
- **fee = 0 is valid** for classical Zether and PQZ (owner 2026-10-14); vectors and tests carry fee = 0 cases for every
  transfer form.
- **PQZ = Post-Quantum Zero-knowledge** (owner 2026-10-15); code / opTags / ids keep `pqz`; wording "a post-quantum
  zero-knowledge proof engine — first application: Zether-style confidential tokens".
- **PQZL Rust crate** (owner 2026-10-17): `pqz-core/pqzl/rust/` (crate `pqzl`), for any third party, Vegan Community
  License 1.0 (LaZer's MIT notice travels: NOTICE + lazer/LICENSE); production core since 2026-10-19; the C core is kept.
- **Code size** is not a concern until the Glamsterdam fork; the ratchet baseline records sizes (owner, P2a F4).
- **Backup, not delete**; **no built binaries on GitHub**. **Licence**: Vegan Community License 1.0 (owner 2026-10-17;
  terms in COMPLETED.md, §00 "License").

## 00. Meta-transaction redesign — code streams (accepted 2026-10-08; rules in the component docs)

### Now (order)

- **Now (2026-10-22, shutdown):** 8b items 1–5 + per-set generator done on `pqz-16k` (`61b0c003` WIP; set (a) gate PASS;
  v3 gate re-run + item 6 16k / A′ via `set.toml` + `make.sh all` left); 8c part 1 + 1b on `pqz-8c` (`6e69bfa0` WIP; set (a)
  PQZH = preset B t 120, fallbacks A `fallback-retry` / C; `c8b.sh` checks left). Order in HANDOFF.md top note.
- **Earlier (2026-10-21 evening):** **5h part B** on branch `pqz-16k` (not pushed). Done: Task 7 (16k, now superseded),
  7b (Amsterdam re-measure), 7c (smaller n), 8a (B-1, A-2, `R_REG`; reviewed), spike PACK (P46) and F185 (Foundry 1.8.5,
  every profile amsterdam) — both merged into `pqz-16k`. **Task 8b paused** (parameter sets `pqz-core/params/sets/`, PQZL at set (a)). Then 8c PQZH
  (backup) → 8d stmt / contracts (P46, per-set Solidity, 32-bit precompile addresses, `ROLL_MAX`, M = 8 by measurement,
  one id bump) → Task 9. HANDOFF.md top note has every owner ruling of the day.
- [x] **Node / relayer on the Amsterdam gas model — done 2026-10-22, merged `b62a54f1`** (per-chain fork detection, regular ≤ 2^24 + EIP-7976 floor on Amsterdam chains, 2^24 clamp elsewhere, gas = estimate + 20 % capped by `max_gas_per_tx` / live block limit / 2^32 − 1, out-of-gas simulations refused, rebuilt jobs keep their gas; `DECOY_LEG_GAS` 120,000; testnet `max_gas_per_tx` 64 M, owner). Was (F185 finding): regular gas ≤ 2^24 per tx, total (regular + state)
  up to 2^32 − 1; `scaas-node` zether.rs `DECOY_LEG_GAS` 32,000 vs 116,698 measured per leg; the prover's `gas_limits` M
  table assumes total ≤ 2^24 (edge cells need 21–31 M); `docs/node/ops.md` `max_gas_per_tx` 16 M. Never assume gas
  price 0 or our block limit (owner 2026-10-21: the precompile may be deployed for customers).
- [ ] **SCaaS testnet at the next reset (plan fs3 Task 13):** ~~genesis `gasLimit` 200 M~~ **done 2026-10-22** (owner: reset now;
  genesis `0xa17faef4…2ac2`, `b62a54f1`; fail-closed drill, README v2-id note, `eth_estimateGas` probe row also done); the PQZ library v4 of the chosen set; the 32-bit precompile addresses; the
  `nethermind-2.2` review minors: fail-closed drill with a tampered library, e2e burst / fill drills under Amsterdam,
  a 200 M block load rehearsal, `.dockerignore` for the default (no `FFI_REV`) image build, README note that the
  testnet's PQZL v2 id is the forgeable one, an `eth_estimateGas` row in the probe; main's FFI library `ee2f7096…` is
  not the reviewed `16dd99ce…` (review the v4 library before building the image).
- [ ] **Dependabot alerts 19 / 20 / 21 / 36 — owner 2026-10-22: leave open (option 2), no dismiss.** All dev / test-only:
  Solana `ed25519-dalek` 1.0.1, `curve25519-dalek` 3.2.0, `rand` 0.7.3 via `litesvm` 0.17 (dev-dependency) →
  `agave-precompiles` 4.3.0 — `cargo update` once litesvm / Agave move to `ed25519-dalek` 2; TON `sprintf-js` 1.0.3 via
  jest → babel-plugin-istanbul → `js-yaml` 3 → `argparse` 1 (no patched version) — goes when jest drops `js-yaml` 3.
- [ ] **Research (owner 2026-10-21, not blocking):** PQZH proof below ≈ 170 KB at the proven soundness (the debit
  inputs must fit one tx under EIP-7976, ≈ 261,909 B with the statement); Kyber-style compression of `u` (noise vs
  `K_MAX`); both only if PQZH on chain or smaller blobs are wanted.
- [ ] **Metatx split** (owner 2026-10-20 "kiểu gì cũng phải tách"; governance goes to a lib or module): spec → plan →
  build **after 5h part B merges, before fs3 Tasks 12 / 6 / 13 and before governance code** (timing ruled 2026-10-21).
  **Owner 2026-10-21: variant A** (DELEGATECALL library, the token keeps the entry points); pass the library only the
  envelope data hash (else a ≈ 340 KB op 7 pays ≈ +1 M gas).
- [x] **`MtxRule`: allow-list vs fee class — owner 2026-10-20: keep as is.** `feeClass = 0` = not relayable,
  `ABSOLUTE` / `AMOUNT` = the fee basis (CTR-MTX-20); on contracts with `supportedModes() = 0x03` (`SmartKeyAccount`,
  `MandateWallet`, their `cancelNonce`) an `ABSOLUTE` selector can only run with fee mode `NONE` (CTR-MTX-22; node
  `guard.rs` checks both). Rollovers on the tokens are `ABSOLUTE` (fee `NONE`, `FIXED 0` or `FIXED x`). No change.
- [ ] **Review order with Codex (owner 2026-10-20; Codex credits limited — two runs only, one type at a time, each on
  the owner's go):** (1) UA-6 (contracts, clients; Claude reviews) → (2) 5h part A (PQZ state, proof-free shield,
  `SHIELD_POOL`, `mtx*` names, fees; plus UA-5c (a) the confidential ops through the UA envelope binding and (b)
  unshield to a `bytes32` UA recipient, owner 2026-10-20 — the ABI is rewritten once; contracts, today's parameters;
  Claude reviews) → (3) 5h part B: the 16k
  regeneration in pqz-core (C, Rust, PQZH Ligero, codegen, vectors; q = 2^50 − 42,310,535, B-1, A-2, `R_REG`) →
  (4) **Codex run 1: pqz-core Rust + C** — one job over the v3 → v4 pqz-core diff, focus: Fiat–Shamir transcript (B-1,
  A-2), parameters / q / Ligero subgroup, `R_REG` message, constant-time paths, secret wiping (A-3), C = Rust parity;
  hand it the gate logs, fuzz results and review A's cheating prover; free sandbox check `codex sandbox` first →
  (5) fixes → fuzz → gate fin → **freeze pqz-core** → (5a) **token-family rename** (`NormalToken` / `WrappedToken`;
  before P6h and before Codex run 2, so the review sees the final names) → (5b) **`clients/pqz-prover` (P6h)**: the
  wallet PQZ prover — a Rust crate over `pqzl` + `stmt` with wasm bindings, API shaped like `clients/zether-prover`
  (read state, decrypt the balance, build statements, prove, envelope; the wallet view list `pqzAccount`, `pqzAcc`,
  `pqzPending`, `pqzPendingCt`, `pqzEntryBlob`, `minDecoyFee`; rollover by count, with `mtxPrepareAcc` called directly
  — neither `mtxRollOver` nor `mtxPrepareAcc` is relayable) → (5c′) **UA-5c (c) + (d)**: the generic UA
  envelope pipeline in `MetaTxBase` and `MandateWallet` (+ Hedera) with `bytes32` owner / delegate / payees (needed by
  the node's `ua_metatx`) → (5c) **node relay (P6i + the needed part of
  UA F5)**: `ua_metatx` jobs (UA envelopes, `from: bytes32` — after UA-6 every Zether UA and PQ signer writes only
  through them; today the node relays address envelopes only), `pqz_call` (direct PQZ calls on the private chain),
  canonical re-encoding of Zether calldata (one intent, one id; NODE-JOB-20) → (6) **Codex run 2: contracts +
  pqz-prover + node relay** (OpenFactory 5g-Z2, UA-6 registry, PQZ / Zether after 5h; the prover's secret handling;
  the relay paths) before the SCaaS testnet redeploy → (7) plan fs3 Task 13 (SCaaS testnet reset, real e2e: wallet with pqz-prover,
  node relay, fees; ask the owner before timing).
  If credits allow only one run: pqz-core first (proof soundness); contracts keep Claude reviews.
  **Every Codex run is paired with an agy (Antigravity / Gemini) review of the same scope at the same time** (owner
  2026-10-20), then one triage of both reports (as G / H on 2026-10-19).
- **Next (2026-10-20 shutdown):** (`rev2-small-fixes` and Z2 merged 2026-10-20) → UA-6 (CTR-UA-30: PQZ key as an attribute of a PQ-signing UA, supplied in `register`; Zether key stays a UA) → 5h (+ `plainPending` removed, `SHIELD_POOL` for PQZ and Zether) → 16k parameter regen with B-1 / A-2 / R_REG under one `proofSystemId` → Task 12 → 6 → 13 → 14 (resume notes in HANDOFF.md).
- [ ] **P0 PQZL Fiat–Shamir fix — rest of plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`** (owner 2026-10-19:
  first; code merged `361a86b`, PQZL `proofSystemId` v3; full item in COMPLETED.md): Task 5h, the 16k regeneration,
  Tasks 12 → 6 → 13 → 14 in the order of the Next line. Owner approval pending: the lazer#28 comment and the D-2/D-3
  issue (drafts in `scratchpad/`).
- [x] **Zether BLS12-381 only (owner 2026-10-20, decisions CTR-ZTH-32; done inside UA-6, design U10)** — bn254 Zether (verifier, `proofSystemId`, UA kind `zether-bn254` 0x0140 + its Schnorr verifier, deploy steps, vectors, client paths) to `legacy/`; specs zether.md / accounts.md / README follow; with UA-6 and 5h. Also with 5h: drop `*_ZETHER_PQZ` kinds (CTR-TOK-21), `mtxShield` / `mtxUnshield` (CTR-ZTH-45), four flows with proof-free shield (CTR-PQZ-06). **Done on branch `ua6` (merge pending).**
- [x] **UA-6: encryption keys as UA attributes (owner 2026-10-20, decisions CTR-UA-30; research `docs/research/ua-identity.md`; spec + plan merged 2026-10-20: `docs/superpowers/{specs,plans}/2026-10-20-ua6-encryption-key-attributes.md`, owner rulings at the plan's top; next: code)** — spec + plan, then code: registry `register` takes the PQZ key (PQ signers only), `keyOwner` uniqueness incl. msig, `pqz-mlwe` kind and `authRef` removed, `R_REG` message bound to the UA id (rides the 16k id bump), PQZ account keyed by the signing UA; classical Zether unchanged (key = UA, "self" mode). Before plan Task 5h. All UA clients follow. **Done on branch `ua6` (merge pending).**
- [x] **Z2 owner questions (answers 2026-10-20; Z2 merged 2026-10-20, all applied; notice period: 3 days minimum on every mainnet, owner):** notice period defaults (10 min on the SCaaS testnet, 3 days on 22776) — **OK**;
  library pins = registrar list checked by code hash, not compared with the init code's link references — **OK**;
  `initialize` without Env — **answered**: keep the split explicit — the implementation carries what never changes for it (Env: verifier addresses, registry, chain, libraries; fixed in its constructor), the contract instance carries its own configuration from `initArgs` (e.g. a wrapped USDC → VND token at 1 : 25,000 and a USDC → RUB token at another rate; mint / burn / blacklist / … allowed or not), and both feed the governance matrix item; `deployImplementation` binds the kind's latest Env
  — **No**: to be discussed together with smart-contract governance and token governance.
- [ ] **bamboo-dms: follow the generic factory API (owner 2026-10-20, plan Task 5g-Z)** — `createToken(kind, version, bytes initArgs, salt)` / `createDex(version, bytes initArgs, salt)` replace the typed `TokenConfig` path; the confidential verifier set comes from the factory (no creator-supplied verifier); `createTokenUnregistered` is refused for confidential kinds; version 0 tokens are unvetted (`isRegisteredToken`). Encoders (plan 5g-Z2, merged 2026-10-20): `initArgs = abi.encode(TokenConfig)` with `ConfidentialConfig` **without** the `verifier` field (7 fields: auditorKey, shieldScale, maxShielded, confidentialFee, disclosureMode, auditorMode, multiLegFee), `createDex` `initArgs = abi.encode(DexConfig)`; a release may not be usable yet (`VersionNotYetUsable`: 10 minutes after its deployment on the SCaaS testnet, 3 days minimum on every mainnet) and a kind may be disabled (`KindDisabled`); factory events `EnvPublished`, `ImplementationDeployed`, `KindEnabled` replace `ImplementationRegistered` and the Zether / PQZ flags. 5g-Z2 merged 2026-10-20: update the Odoo connector encoders now.
- [ ] **PQZL Rust port follow-ups** (port merged `5952951`; placed in the fs3 plan 2026-10-19; full text in
  COMPLETED.md): (1) roll-out on the SCaaS testnet — Rust-backed `Nethermind.Pqz` image (pqz-ffi default `pqzl-rust`), RUNBOOK steps
  as P6f, PQZ gas rows re-calibrated on the chain host before or with the image switch (CTR-PQZ-09 controller proposal)
  — Task 13; (2) at the roll-out pq-zero-knowledge.md (~1293 / 1320 / 1504) names the Rust crate as the production core
  — Task 13; (3) wasm32 limb path in `pqzl/rust/src/arith/ntt.rs` (wasm32 `verify_fast` 1.7–2.0× slower than C, R_TXM8
  p99 51.0 ms vs 60 ms; D6 `pqz-core/pqzl/rust/runs/d6/results-d6.md`) — Task 14, own branch; (4) M = 16 Rust rows
  (`--multi-bench`) — Task 13; (5) deferred minors (heap check in `verify_only` C-M5, pqz-ffi OOM and fallible `Ctx`
  tests, panic-path test, `PQZL_MEM_*` echo, gate PASS line file, two-limb S3 oracle) — Task 5e.
- [ ] **Rename token family** (owner 2026-10-13 / -18 / -19: right after the PQZL Rust port follow-ups, before P6h /
  P6i / P6j / P6-PUB): `UnderlyingToken` → `WrappedToken`, `NoUnderlyingToken` → `NormalToken`, the whole family
  (`UnderlyingZetherToken` / `NoUnderlyingZetherToken`, `UnderlyingLib`, `IUnderlyingToken`, `TokenKind` `NONE` →
  `NORMAL`, `UNDERLYING` → `WRAPPED` and the `_ZETHER` / `_PQZ` / `_ZETHER_PQZ` variants); names only (enum numbers, ABI,
  vectors, storage unchanged); keep `underlying()`; not "NativeToken"; `legacy/` and `docs/history/` unchanged, old
  names to `docs/history/dropped-artifacts.tsv`. Scope (2026-10-13): ≈ 67 files in `smartcontracts/evm`, ≈ 40 docs,
  `scripts/size_gate.py`, one node test.

### P6 — what is left

Roadmap `docs/superpowers/plans/2026-10-12-p6-roadmap.md`. Done: P6a–P6g, P6-SZ, P6-Z21, P6-REL, P6-PQZH-SOL, the
`R_TXM` multi-recipient transfer (P6-ANON S1–S9, op 7 live on the SCaaS testnet and in the PQZ tokens), gates A / B and the freeze
(2026-10-17) — details in COMPLETED.md.
- [ ] **P6h** clients and WASM (browser wallet bundle builds with `SV=0`, owner 2026-10-13), **P6i** node, **P6j**
  review — after the token-family rename (owner 2026-10-19).
- [ ] **P6c owner step:** audit the PQ verifiers and the expanded-key cache before any public chain enables a PQ kind.
- [ ] **P6f follow-ups (owner):** follower + public RPC, restart policy (the SCaaS testnet node has none), deleting backups; the
  hourly `watch.sh` check is manual. (P6f done and live on the SCaaS testnet since 2026-10-16.)
- [ ] **P6-PUB drafts** (owner 2026-10-14, session 4): after P6, the live precompiles and P6-ANON, the controller drafts
  the ePrint paper (LaTeX, citing the frozen package) and the ethresear.ch post (Markdown, results-first), kept private
  in `scratchpad/pub/` until the owner posts; the results mail to the LaZer maintainers
  (`scratchpad/sz-private/results-letter-lazer.md`) goes first (ruled 2026-10-13). Full scope in COMPLETED.md.
- [ ] **P6-PUB publish PQZL** (owner 2026-10-13): ethresear.ch post + ePrint paper; source-only package
  `pqz-core/artifact/` (PQZL + PQZH, Docker + `reproduce.sh`), source tag + Zenodo DOI; re-measured headline numbers in
  README §11, a five-relation table in `pqz-core/README.md`, the posts' opening line (not the spec); the owner mails the
  LaZer maintainers first. Status: freeze `--full` 2026-10-17; fs3 Task 6 updates the package to the current id.
- [ ] **P6-ANON leftovers:** `PQZ_DEBUG_MALLOC` sanitizer variant (ASan inside the arena; not scheduled); op 7
  disclosure-bundle / per-leg opening vectors (pqz-stmt codec; from S4); identity hiding beyond the receiver ring =
  research only (`docs/research/pqz-anonymity.md`), owner decides.
- [ ] **PQZH leftovers** (backend Ligero over F_q, proven, owner 2026-10-14): external review of the Ligero ZK argument
  with the cryptographic audit; 128-bit post-quantum target deferred (owner 2026-10-18: calldata ≈ 7 M gas; new
  parameter set and id); pin Plonky3 0.9.0 final for the backup crate (`docs/research/pqzh-ligero.md`).
- [ ] **P6-SV leftovers:** independent review of `pqz_sv.c` against `lnp-tbox.c` (started 2026-10-13; result not
  recorded in TODO); hand-written AVX2 and a run on the chain host (not needed for the limit).
- [ ] **Revisit the credit cap `K_MAX`** (owner 2026-10-13: keep 1024 for now): now part of Task 5h and the 16k
  parameter regeneration (`K_MAX` raised by A', q ≈ 2^54). Context in COMPLETED.md.

### Recorded, not scheduled

- [ ] **Zether BLS12-381 verifier precompile in Rust** (owner 2026-10-17; after the PQZL Rust port, not scheduled):
  full verifier (Σ-protocol + the two Bulletproofs, `…/bls12-381/n64-n64/v2`) in `Nethermind.Pqz` (Rust cdylib +
  P/Invoke) for the SCaaS testnet / 22776; chains with it use it, others keep the Solidity `ZetherVerifier` (same statement, proof
  bytes and verdict; chain allowlist + self-test as `PqzSafety`); built only with an explicit option (Cargo feature +
  MSBuild property, image build argument; default off); a node built without it refuses a chainspec that activates it.
  bn254 stays Solidity-only. Controller notes in COMPLETED.md.
- [ ] **Family priority for UA and long-lived balances (owner 2026-10-19, late):** first EVM, Cosmos, Sui, Aptos and Solana (balances and records stay in state for good: no TTL, a one-time deposit or fee); then assess Soroban, NEAR and Algorand — whether balances can be kept long-term there and at what cost (Soroban TTL / archival and restore fees, NEAR storage staking, Algorand minimum balance and boxes). The UA F phases on non-EVM follow this order.
- [ ] **`secp256k1` UA kind: EIP-191 `personal_sign` variant (owner 2026-10-19, on-chain review W-J; after P6)**: today the kind 0x0108 verifier checks ECDSA over the raw digest, so an EOA-held key signs it only through `eth_sign` (residual risk recorded in accounts.md S23). Add a verifier for the `personal_sign` form, new vectors, the six clients.
- [ ] **ERC-7674 temporary approvals on SCaaS tokens (owner 2026-10-18; after P6)**: `temporaryApprove(spender, value)`
  (EIP-1153 transient allowance, contract callers only) in the token base, read first by `transferFrom`; SCaaS contracts
  use it on SCaaS tokens instead of approve + `approve(spender, 0)`; outside tokens keep approve + revoke. Spec in
  token-wrappers.md / metatx.md, forge tests, size impact. Full note in COMPLETED.md.

### Leftovers of P1–P5 (phases done; history in COMPLETED.md)

- [ ] **MT-4:** `salt = chain_uid` still open for the UA registry (UA F1).
- [ ] **MT-5 / DEX:** `checkOrder` for the new DEX (not specified; with the node's P7 intake), the DEX invariant suite
  (dex.md §14), the fork test with real Uniswap bytecode, `IS_HEDERA` in `SCaaSDex` (a Hedera ED25519 account cannot
  sign a `DexOrder`); the node's P7 gas rules for `mtxSettle` are in COMPLETED.md (P2b-2).
- [ ] **P3 Zether:** a real-passkey envelope test (CTR-ZTH-21), gas of `mtxWrapShield` / `mtxUnshieldUnwrap`
  (zether.md gas tables re-measured on the new kinds), client Zether encoders, the disclosure questions (P3 plan header).
- [ ] **MT-8 node:** breaker per `(from, selector)` and batching (NODE-LANE-11/25), TradeEngine (NODE-DEX-17/18, P7),
  NODE-IDX-06 `repeat_of`, `ua_metatx` (UA F1), per-poll venue check (NODE-DEX-08); review leftovers (gateway guard
  order, config docs, `settle` refusal reason, padded gas above the maximum, entry 1271 floor, no Odoo report for a
  guard-refused job rebuilt after a restart).
- [ ] **MT-9 clientkeys:** the app bundle rebuild and the reference ERP's `lib/eip712.py` (bamboo-dms item below).
  - bamboo-dms: the vendored clientkeys bundle in `dms_blockchain_bridge` is stale (`zetherSign` added, bn254 gone, new register shape with the PQZ key attribute); `npm run build` writes outside the repo (UA-6, Task 6a).
- [ ] **Controller rulings pending the owner:** pay inline behind `PAYABLE`, no `PayLib` (P1); `increaseAllowance` and
  Permit2 `approve` refused with `ForbiddenSelector` (P2c); P4 mandate rulings (a revoke or any `setMandate` voids queued
  delegate pays; `setMandate` keeps the running period when delegate and period are unchanged; CTR-ACC-07).
- [ ] **Asset-suite stream notes** (P1c reviews): reword `asset-suite.md` ~791/793/794/854/906 ("minter renounced" →
  "`MINTABLE` disabled (`disableFeature`)"); issuer and compliance contract-only when flags 5–8 are built; roles keyed
  by role id (or mapped bits); every `_update` refusal mirrored in `_checkTransfer` and before the receiver-fee transfer.
- [ ] **P1c–P1e parked:** P1c test gaps (list in COMPLETED.md "P1c notes" (e)); P1d test gaps (`mtxExecute(single-asset
  selector)` on a two-leg token, native `UnderlyingTransferMismatch`, `addReserve` with native `msg.value > amount`,
  guardian revoke); a native 4th leg in the `WrapperInvariant` handler + §12 row for CTR-TOK-26; deploy scripts deploy
  `UnderlyingToken` once it fits EIP-170; the size ratchet is lowered by hand; `deploy.sh` needs `PRIVATE_KEY` (KMS /
  hardware wallet needs a change); libraries placed from the sender's nonce (E7). Full notes in COMPLETED.md.
- [ ] bamboo-dms (P4 follow-up; before P4 contracts reach a chain Odoo uses): the owner call becomes the account's salted
  `MetaTransaction` with `chainUid`; mandate digests / calldata move to `mtxPayUnderMandate` / `mtxRevoke` (read
  `epoch(token)` per pay, re-sign on `StaleEpoch`); the relay job drops pre-P4 names (`revokeWithSig`); `_predict` reads
  `smart_key_account_create2.json`, deploy seeding `smart_key_account_factory`, wallets deployed with
  `<owner> <chain_uid>`. Full list in COMPLETED.md.
- [ ] Mandate epoch-bound pay and period-keeping `setMandate` (M1/M2) are EVM-only in P4; the other families keep their rules. One follow-up per family, owner decision first: Solana (generation binding), Sui, Aptos, Soroban, Cosmos, TON (one-shot or own pay binding).
- [ ] Agent mandates (research `docs/research/node-ai-agents.md` row c, not accepted): several delegates per token, per-payee caps, a co-sign threshold, a gateway route for mandate payments — owner decision.
- [ ] bamboo-dms (P5 follow-up; before the P5 node reaches a chain Odoo uses): jobs carry `struct` and the v3 digests
  (`lib/eip712.py` on `metatransfer_kat.json` / `metatx_kat.json`), the new DEX rows / events / relay jobs, `dead` with
  `TOKEN_NOT_SERVED` and for `receiver_fee`, regenerated mesh vectors, new deploy JSON keys, the portal's clientkeys
  bundle and its new required parameters (`checkPayment`, `checkCall`, `checkTradeOrder`, `checkCancel`). Full list in
  COMPLETED.md.
- [ ] **bamboo-dms (other repo): the `UAWrapped` field rename (plan Task 5g, review W-Q(e), 2026-10-19).** `uaWrap` now emits `UAWrapped(to, …, minted − fee)`: the first field is renamed `from` → `to` (same topic0) and carries the credited UA; `mtxWrap`'s `Wrapped` names the destination and the net amount. If bamboo-dms indexes wrap events, it must follow the rename and the net amount. No consumer in this repo.

**Non-EVM families (NM-*)** (full stream text in COMPLETED.md)
- [ ] Per-family meta-call streams, new immutable deployments each: **NM-APT** (`MetaCall`/`MetaTransfer` in BCS,
  `scaas::metacall::verify`; NET-APT-27, NET-ALL-26…29), **NM-SUI** (as Aptos + `mtx_forward`; NET-SUI-18, NET-SUI-16),
  **NM-SOR** (`mtx_` functions, SEP-41 `transfer` kept, `__check_auth` allowlist per key; NET-SOR-16, NET-SOR-04),
  **NM-COS** (`scaas-metacall` crate, `Mtx*` messages; NET-COS-12), **NM-TON** (`Mtx` messages, opcodes fixed with
  vectors; NET-TON-20), **NM-SOL** (fixed layouts, `mtx_` instructions; NET-SOL-33); key / mandate entries move to
  `mtx_` and the old op types go. Node adapters and clients (`fam/*.js`, CLI-SGN-27) follow each family; vectors per
  family.

## 0. Finish the spec phase (6 items left)

- [ ] **Governance matrix for factory-made contracts (owner 2026-10-20)** — tokens, DEX, later lending and the other
  contract families: for every property and power (verifiers and Env, rates and legs, mint, burn, blacklist, pause, fees,
  roles, upgrades of the release) state where it comes from and who may change it: **fixed by the implementation**
  (Env, constructor) × **set at creation** (`initArgs`, per instance) × **changeable after deployment** (by whom, with
  which delay, lockable or not). Covers smart-contract governance (releases, Env versions, `deployImplementation` — owner:
  it must not simply bind the kind's latest Env) and token governance (today's `features` / `lockedFeatures`, `AdminLib`
  roles, `owner = 0`, `RATE_ADJUSTABLE` with `rateDelay` / `maxRateStepBps`). Spec first (owner rule), then Z2 follows it.
  - Inputs (owner 2026-10-21, chat): (1) **mint allowance per minter** — `{total, perWindow, window, expiry}`, two-tier
    (USDC masterMinter pattern), a reduce-only role; (2) **moderator transfer** of a user's balance without the user's
    signature (loyalty points), bounded by a per-moderator total and per window (same primitive as (1)), own event,
    relayable, public balances only — never on confidential kinds (FORCE rule); proposal: enabled at INIT only;
    (3) **hybrid underlying** — wrap (citizen brings a stablecoin) plus issuer mint under one `maxSupply`; reserve
    accounting needed (proposal: unbacked units not redeemable for the underlying; alternatives pro-rata or queue P15);
    PQZ / Zether minters never mint shielded value.
- [ ] **SCaaS Chain 22776** (owner 2026-10-12): a new chain "SCaaS Chain", chain id 22776, beside the existing ones; SCaaS testnet and the UA key tree `m/7622'/…` stay unchanged. Ports in the 22776+ range (proposed RPC HTTP 22776, WS 22777, P2P 22778). Onboard like any chain: docs/networks/evm.md row, profile, finality gate, genesis/identity pin, deploy, node config. The chain itself (docker/chainspec) is run by the owner outside this repo.
- [ ] **Template library** (owner 2026-10-12): every README use case (escrow with an arbiter, milestone service
  contracts, sale with delivery, leases, installment loans, subscriptions, revenue sharing, deposit with periodic
  withdrawal, provenance and family-tree registries) as an implementation deployed once per chain, instances by clone /
  CREATE2 through a factory, called by meta-transaction. Spec first: `docs/contracts/templates.md`. Full note in
  COMPLETED.md.
- [ ] **P0 follow-ups (minor doc nits, deferred by the final review):** `zether.md` (single-recipient-only gas-cap
  figures, ~1327 `recipient` vs `to`, informal `zetherShield(Y…)` prose), architecture sequence 5 (`UnderlyingLib`),
  `asset-suite.md` 893–897 and the old `IRegulatedToken` names, `clients/app.md` CLI-APP-26, `node/store.md`:157,
  `node/job-api.md`:328, CTR-TOK-26 wording, `dropped-artifacts.tsv` duplicates / bare `273`, CTR-ACC-80, budget
  warnings in `token-wrappers.md` / `dex.md` (owner). Full list in COMPLETED.md.

- [ ] **Rewrite `docs/integration.md`** (owner 2026-10-09: later). Goal to settle when started: shorten/restructure, align with the token tree and meta-tx v3, ERP-neutral; then `integration-odoo-example.md`. Keep the 27 `INT-ERP-*` ids (supersede, never renumber). No code dependency; PQZ parts stay open.

- [ ] **Codex reviews still owed** (credit ran out after 4; Codex runs only on the owner's request): AS, TW2, app, OPS,
  S4F, mesh, A2 — review the current component doc of each area (map in `docs/README.md`), not the frozen spec; all
  already have a Claude review. Command and output paths in COMPLETED.md.

## 1. Code streams (after §0)

**Fix first (bugs found in BUILT code by the 2026-10-07 reviews):**
1. **NET-TON-FIX1** (BLOCK: unbounded forward TON drains a lane — no job API/mesh/gateway path may reach a TON lane until the node half lands), NET-TON-FIX2…4.
2. Node money safety: **NR1** breaker meters fees/value/deposits + attempt cap + grief score (R340–R342), **NR2** payload-sourced fields, value-out cap, deposit rule (R344–R346), NR3 mesh sig verify (R343, before S5), NR4 journals → `outer_tx` (R347), NR5 immutable-program check + one custody key per family (R348–R349).
3. **PAY-FIX1** Odoo outbox ACL + immutable job fields, **PAY-FIX2** node `call` target/selector table, PAY-FIX3 event-set quorum, PAY-FIX4 gateway intake, PAY-FIX5 idempotent signed report; ADW-FIX1–4.
4. DEX: DX-FIX1–5 (dust maker freeze, poison fee token, 1271 gas cap, non-EVM relayer binding).
5. Per family: R3-FIX1–15 (Cosmos passkey v2, WebAuthn vectors, event quorum, Soroban `pay_ref`, Solana build-time network, Sui `Keys`, guardians, TON domain, **R3-FIX15 immutable deploy + gate + redeploy**), WSF-FIX1–2, NET-{COSMOS,SUI,HEDERA,SOROBAN,APTOS,SOLANA}-FIXn (code-stream tables of the frozen `docs/history/specs/net-*`), ZF-FIX1–3.

Then the first feature wave: **NI P2 → P3** (money-safety core), **UA F0 → F1** (many specs depend on it), **app A1 + A0-evm**.

Stream ids are unchanged by the docs reorg. **Doc** = the current rules a stream implements; **Scope** = the frozen
stream definition (scope, gate, depends) in `docs/history/specs/` — section numbers as in those files.

| Area | Streams (spec) | Doc | Scope |
|---|---|---|---|
| Node | P2 job API + client API keys + built-in admin/CLI → P3 submit/lanes from store → P4 indexer + `/v1/events` → P5 Odoo client (bamboo-dms) → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 mTLS bus → S6′ → G1 libp2p/QUIC-PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + unbound) → S7″ → P9 remove pull path → S8″ docs. Plus N1/N2/N4 (app §9.6), N3 non-EVM DEX books, OPS OP1–OP8, SP1 sponsorship · DX-FIX1 dust maker skip, DX-FIX2 fee-token allowlist + pair-failure attribution, DX-FIX5 pending commitment + market re-check + IOC single-maker + late-Matched debit (DEX spec rev 1.1; fold into P7 if P7 starts first) · ZF-FIX3 Zether verifier/registry pin (gateway + clientkeys), cache key chain id, `schnorrSign` k test-only (Zether rev 1.1) | [node/](docs/node/README.md): [store](docs/node/store.md), [job-api](docs/node/job-api.md), [submit-lanes](docs/node/submit-lanes.md), [indexer-feeds](docs/node/indexer-feeds.md), [admin-auth](docs/node/admin-auth.md), [dex-venue](docs/node/dex-venue.md), [mesh](docs/node/mesh.md), [gossip](docs/node/gossip.md), [ops](docs/node/ops.md), [runbooks](docs/node/runbooks.md#cutover), [sponsorship](docs/node/sponsorship.md) | P*: `2026-10-06-node-independence-design.md` §17; S*: `2026-10-05-relayer-mesh-design.md` §14 + NI §13.2; G*/S6′/S7″/S8″: `2026-10-06-mesh-gossip-amendment.md` §17; OP*: `2026-10-06-operations-design.md` §13; SP1: `2026-10-06-tender-sponsorship-shredding.md` §8; N1–N4: `2026-10-06-scaas-app-design.md` §9.6; DX-FIX: `2026-10-03-dex-design.md` §8 (Claude review disposition); ZF-FIX: `2026-10-03-zether-design.md` (Claude review disposition) |
| Contracts | TW2 T7 (node/Odoo/SDK follow-ups) · AS1–AS9 asset suite · TB1–TB3 tender, RP1–RP2 receiver-pays (RP1 before production registration O3), CS1–CS2 shredding, PL1 pool (later) · UA F0–F10 · PQZ E-S0…E-S9 (spikes first; licence gate G-LIC before production) · DX-FIX3 `SCaaSDex` 1271 gas cap + bounded returndata (redeploy), DX-FIX4 non-EVM DEX relayer binding (Cosmos/Soroban/TON) + `min_nonce` caps (Sui/Aptos/Solana) · ZF-FIX1 `ZetherMetaTx` 1271 400k/50k + FeeWouldStick + disclosure NatSpec, ZF-FIX2 Zether invariant/subgroup/`D_out = O` tests | [contracts/](docs/contracts/README.md): [token-wrappers](docs/contracts/token-wrappers.md), [asset-suite](docs/contracts/asset-suite.md), [tender](docs/contracts/tender.md), [universal-account](docs/contracts/accounts.md), [pq-zether](docs/contracts/pq-zero-knowledge.md), [dex](docs/contracts/dex.md), [zether](docs/contracts/zether.md); [networks/](docs/networks/README.md) for non-EVM | T7: `2026-10-06-token-wrappers-v2.md` §15; AS*: `2026-10-06-asset-suite-design.md` §13; TB/RP/CS/PL: `2026-10-06-tender-sponsorship-shredding.md` §8; F*: `2026-10-06-universal-account-design.md` §16; E-S*: `2026-10-06-pq-zether-design.md` §16; DX-FIX/ZF-FIX: as above |
| Clients | S4F D1–D7 · app A0–A18 (order in app spec §15) | [clients/signers-clientkeys](docs/clients/signers-clientkeys.md), [clients/app](docs/clients/app.md) | D*: `2026-10-06-signers-followups.md` §10; A*: `2026-10-06-scaas-app-design.md` §15 |
| Odoo (bamboo-dms) | P5, UA F6, AS/TB/SP Odoo parts, connectors wiring (S4F finding: non-EVM portal connectors not wired) | [integration.md](docs/integration.md), [integration-odoo-example.md](docs/integration-odoo-example.md) | P5: NI §17; F6: UA §16; AS: `2026-10-06-asset-suite-design.md` §9.2; TB/SP: TSS §8; connectors: S4F §10 |

## 2. Ops / housekeeping

- [ ] **Foundry 1.3.5 → 1.8.5** (not scheduled; CI pins 1.3.5 since 2026-10-13): upgrade local and CI together; 13
  forge tests to re-measure / regenerate (gas pins, KAT addresses, `selfdestruct`); `forge script` then needs
  `--disable-code-size-limit` (EIP-3860 on the script contract: `Deploy.s.sol` initcode 368,154 B); anvil keeps
  `--code-size-limit 65536`. Full note in COMPLETED.md.

- [ ] Redeploy all dev/test contracts (tags renamed); update `blockchain.token.domain_name` / Cosmos `network_key`.
- [ ] Remove merged worktrees under `.claude/worktrees/`.
- [ ] Residual TON: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational).
- [ ] Queued research: none open beyond the specs above.
- [ ] **scaas-node docker-compose** (owner 2026-10-12: after node streams P2 + P3 + P4 + P6): standalone, not tied to an
  Odoo docker — multi-stage Dockerfile (Rust 1.90), `scaas-node` + one-shot `store-init`, store volume, `.env` for
  secrets / chain RPC / chain_uid; default gateway-only config, a second sample with submit + indexer for an Odoo by URL
  (legacy pull path until the push cutover). Full note in COMPLETED.md.

Owner/operator gates from `docs/history/HANDOFF-blockchain.md` §1 (O1–O8 are standing rules in
[node/runbooks.md#production-gates](docs/node/runbooks.md#production-gates)):

- [ ] O9 — Decide the DPIA / CI gate for landing on-chain payments into the ERP (SRS deltas #11).
- [ ] O10 — Write the onboarding procedure for `MandateWallet` / subject accounts (deployed outside the ERP, R29).
- [ ] O11 — Every collecting entity that receives on-chain needs a `chain` payment provider, a journal and an approved
  receiving wallet (after the territory consolidation; GA 2.4#4).

- [ ] wasm build for the app: `wasm-smoke.sh` builds `--target nodejs` only; a `--target web` build is client work
  (S4F/app) (from the 2026-10-07 doc nits).
- [ ] P5 leftovers: an EVM chain whose RPC errors on block 0 at boot still fails `Submitter::start` (adapter lanes retry with backoff); a guard-refused job rebuilt after a restart whose nonce was taken by a transaction the node no longer holds gets no report.
- [ ] **UA leftovers:** HIP-632 in a view (R19, UA-2a); FRB as a Flutter plugin with Android/iOS/web builds (does
  `scaas-ua` build for wasm?) and Qt packaging for Windows/macOS (UA-1b); T-V3-4 and the `ua*` fallback decoder wait for
  Glamsterdam (owner; real chains at 24,576 cannot take any token implementation until then); `metatx3.json` rows for
  the group kinds and `msig` (UA F3). Local Qt builds of `clients/ua-qt` need
  `QMAKE=~/usr/Qt/6.8.2/gcc_64/bin/qmake6`.
- [ ] **UA F5 (node UA jobs; paused by the priority rule):** node `ua_metatx` jobs, mesh `evm.ua_meta_tx`, indexing
  (`Transfer` to/from `UA_POOL` with `UATransfer`, `UnwrappedToUA`, `UAReceiverFeePaid`, `UAPaymentSettled`); relaying
  `ua*` jobs (burn, `unwrapToUA`, `uaWrap`, `uaCancelOrder`, `uaInvalidateNonces`), a receiver-fee job with a `bytes32`
  payee; UA order intake, `bytes32` book / TradeEngine on `balanceOfUA`, settlement packing by the kinds' caps, PQ order
  gossip (UA-4, UA-5a, UA-5b open lists in COMPLETED.md).
- [ ] **UA-5** UA parity (owner 2026-10-13; record `docs/history/specs/2026-10-13-ua-parity-design.md`; rules
  CTR-UA-27/28, CTR-DEX-25/26, CTR-ZTH-51, CTR-ACC-12): UA-5a and UA-5b done (COMPLETED.md); left UA-5c below. Each
  phase ends with the size gate and the full forge suite (default and `private7622`).
  - [ ] **UA-5c split (owner 2026-10-20):** (a) confidential ops via the UA envelope + (b) unshield to a UA → 5h part A;
    (c) generic UA pipeline in `MetaTxBase` + (d) `MandateWallet` `bytes32` → step 5c′ before the node relay (5c);
    `zetherShield` via `uaExecute` already built in UA-6.
  - [ ] **UA-5c** mandates (c)(d), step 5c′: the generic UA pipeline into `MetaTxBase`; `MandateWallet` (+ Hedera) with `bytes32` owner / delegate / payees and UA builders, no ERC-1271 for a derived owner. The contracts of (a)(b) are built in 5h part A (Task 3b: the confidential ops on the UA allowlist with the UA envelope binding `SCAAS-ZETHER-UA-ENVELOPE-V1`, `mtxUnshield` / `mtxUnshieldUnwrap` with a `bytes32` recipient, no `…ToUA` entry point) and the zether-prover builds a 32-byte recipient (final fix wave m3). Independent of UA-5b (needs UA-5a's `_uaMint` and `payWithFeeToUA`); the node part after UA F5.
  - Later, with their own streams: regulated tokens key compliance by `bytes32` and hook the UA ledger (asset suite, CTR-AS-07); `SealedBidTender`, `VestingGrant`, `Distribution`, `ExchangeOffer` with UA bidders and beneficiaries when built.
- [x] ~~Zether prover gas cap: an authorization allowance by `authRef` kind in `check_gas`~~ — obsolete: UA-6 removed the Zether `authRef` and `authSig`, the allowance is gone (branch `ua6`, merge pending); full note in COMPLETED.md.
