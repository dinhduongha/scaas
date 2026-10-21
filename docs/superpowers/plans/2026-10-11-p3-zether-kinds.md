# P3 — The `*_ZETHER` kinds on the token tree: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield, `ZetherToken` to `legacy/` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classical Zether as two token kinds on the one meta-transaction base (MT-6, CTR-TOK-21, CTR-ZTH-44…47):
`NONE_ZETHER` (`NoUnderlyingZetherToken`) and `UNDERLYING_ZETHER` (`UnderlyingZetherToken`), a `ZetherLayer` over the
public ERC-20 balance with its logic in the external library `ZetherLib` (`scaas.zether`), the prover views in a
stateless `ZetherStatements`; shield from the public balance (`zetherShield`), wrap-shield from a leg's underlying
(`zetherWrapShield`), unshield into public units (`zetherUnshield`) or straight out to a leg (`zetherUnshieldUnwrap`);
every confidential op relayed as an allowlisted self-call of `mtxExecute` whose statement carries the envelope binding
through the transient ticket (CTR-ZTH-34); `chainUid` in every token-side Zether digest and in the 416-byte statement
header (CTR-ZTH-36, MT-4); the factory's Zether gate on `OpenFactory` and kinds 2–3 registered by `DeployBase` on dev
chains; the built `ZetherToken` line backed up in `smartcontracts/evm/legacy/p3/` (owner: backup, not delete).

**Architecture:** `ZetherLayer is MetaTokenBase, IZetherToken` holds the immutables (registry, disclosure), the views and
one-line entry points; `ZetherLib` (public functions, `DELEGATECALL`) holds the storage and the logic, ported from the
built `ZetherToken` (`_prepare*` → `prepareSingle/Multi/Unshield`, `_header` with `chainUid`, `_credit`, `_rollOver`,
`_storeBundles`, disclosure entries unchanged). The statement builders are `internal`, so `ZetherStatements` runs the
very same code on the token's views. The kinds are the public kinds plus the layer: `NoUnderlyingZetherToken is
NoUnderlyingToken, ZetherLayer`, `UnderlyingZetherToken is UnderlyingToken, ZetherLayer` (kind ids 2/3, domain
`"SCaaS ZetherToken"` through an `ERC20MetaTx._domainName()` hook, `UnderlyingLib.initToken` takes the kind). The base gains
one hook: `MetaTxBase._envelopeBinding(m)` (0 by default) stored in a transient slot for the self-call and read by
`_ticketBinding()` only under a live ticket. Disclosure (`ZetherDisclosure`, `ITransferDisclosure`, four openings,
auditor key, per-transfer auditor opt-out, HASH/BUNDLE/NONE storage) is carried over unchanged except the `chainUid` the
spec adds to its challenge. The verifier's header grows to 416 bytes; the Rust prover follows (header, `entryRef`,
envelope, disclosure, new ABI names) and regenerates its vectors.

**Tech Stack:** Solidity 0.8.37 (`osaka`), Foundry (forge 1.3.5), OpenZeppelin 5.2.0, forge-std 1.16.2; Rust
`clients/zether-prover` (arkworks 0.5, `cargo test`, `wasm-smoke.sh`); `scaas-node` e2e (anvil) as the deploy check.

**Spec:** `docs/contracts/zether.md` (CTR-ZTH-01…47; §6 lifecycle, §7 header, §11 multi-recipient, §12 relaying
CTR-ZTH-06/08/13/21/23/34, §14 disclosure, §15 CTR-ZTH-44…47, §16 gate, §20 CTR-ZTH-22, §21 interfaces),
`docs/contracts/token-wrappers.md` (CTR-TOK-03/17/20/21/22/24/25/26), `docs/contracts/metatx.md` (CTR-MTX-02/12/15/17/18/19/20/25),
`docs/contracts/pq-zero-knowledge.md` (CTR-PQZ-15/21/22: room only), `docs/contracts/settlement.md` (Zether row, §3.7); TODO.md
§00 P3 row, MT-1/MT-3/MT-4/MT-6 and the P1e follow-up (c); HANDOFF.md.

**Base:** `main` at `cb5ebaf` (P2c merged as `d85fc8b`, then the disclosure review `docs/research/zether-disclosure.md`; 949 tests). Every code block below was applied task by task to a scratch worktree from `main` (`cb5ebaf`) and run green: full suite **969** (949 − 154 old Zether suites moved to `legacy/p3/` + 174), the Zether suites 248, `zether-prover` `cargo test` 52 and `wasm-smoke.sh` 16 checks, size gate 0 errors after each task, e2e 4/4 and 1/1, docs checkers 0 errors, mutation probe 80/80 killed.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge in `smartcontracts/evm` of worktree `.claude/worktrees/p3`
  (branch `p3-zether` from `main`; `lib/` is not tracked: `mkdir lib`, copy `smartcontracts/evm/lib/forge-std` into it
  and symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`, as in the main checkout).
  Heavy commands only through `scripts/capped`, one at a time. `/usr/bin/grep`, `rtk proxy git diff`; if a hook blocks
  bare `git`, use `/usr/bin/git`. Rust: `CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/clients/zether-prover/target` (and
  `…/scaas-node/target` for the node) reuse the main checkout's build caches.
- **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS**: every new contract says so in its NatSpec; dev chains only
  (`ZetherSafety`: 31337, 1337).
- Namespaces: `scaas.zether` = `0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00` (new, pinned by
  `test_zetherNamespaceSlot`); transient `scaas.mtx.binding` = `0x7a352a4c…59c7c12e` (`keccak256`, like the other two
  transient slots). The public kinds' linear layout is unchanged; the new kinds pin the same five ERC-20 slots.
- Tests: compute anything that makes an external call (`stm.*Statement`, `tok.envelopeBinding(m)`, `tok.mtxDigest(m)`,
  `reg.popChallenge`, `tradeOrderDigest`) **before** `vm.prank` / `vm.expectRevert`, or the call consumes the cheatcode
  (the P3 validation hit exactly this once: `reg.popChallenge` inside `register`'s arguments). Every mutant of the probe
  (Task 6) has a named killer.
- `via_ir` stays off: `ZetherLib`'s `_prepare*`/`_settle*` split and the fixture's helpers exist to stay under the stack
  limit.
- Code size is not a concern (owner: wait for the Glamsterdam fork; anvil and the SCaaS testnet run 64 KiB); the ratchet
  baseline records sizes (`NoUnderlyingToken` 22,978 B, `UnderlyingToken` 30,036 B, `NoUnderlyingZetherToken` 30,659 B, `UnderlyingZetherToken` 40,381 B (init 41,991 B), `ZetherLib` 15,662 B, `ZetherStatements` 7,311 B). The deploy of the Zether stack on an anvil needs `--code-size-limit 65536`.
- Component docs say "controller ruling, pending the owner", never a K-id. The multi-key account is `SmartKeyAccount`.
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **Money conservation, public ↔ shielded.** Shield burns exactly `amount·shieldScale` public units of `_msgSender()`
  and adds `amount` (cap `≤ maxShielded`); unshield debits `amount + fee` from `acc` and mints exactly `amount·scale`;
  wrap-shield credits `minted / scale` (exact multiple only), mints nothing; unshield-unwrap pays
  `⌊amount·scale·den/num⌋` from the leg's reserve, mints nothing; `executeRate` counts the shielded part. Pinned by
  `test_lifecycleShieldTransferRollOverUnshield` (×2 curves), `test_shieldBurnsTheCallersPublicUnits`,
  `test_wrapShield_creditsShieldedUnits_mintsNothing`, `test_unshieldUnwrap_paysTheLeg_mintsNothing`,
  `test_executeRate_countsTheShieldedValue` and the invariant handler (`invariant_balancesConservationAndReserve`: every
  ghost balance `[b]G == C − [x]D`, Σ == `totalShielded` ≤ cap, `collateralValue ≥ totalSupply + totalShielded·scale`).
- **The envelope binding (CTR-ZTH-34).** Read only under a live ticket; a proof lifted out of an envelope, moved to
  another lane, nonce or fee, or a direct proof put into an envelope, is refused; a direct call in the same transaction
  after a relayed one proves DIRECT. `test_proofLiftedOutOfEnvelopeRejected`, `test_proofMovedToAnotherEnvelopeRejected`,
  `test_directProofInsideAnEnvelopeRejected`, `test_relayedMultiTransfer_unshield_shield` (the trailing direct call),
  `test_envelopeBindingAndDigestKat` (Rust ↔ formula ↔ token).
- **`chainUid` everywhere (CTR-ZTH-36).** Header word 3, `entryRef`, roll-over and mode digests, envelope binding,
  disclosure challenge; the prover's `s` derivation too. `test_statementHeaderCarriesChainUid`,
  `test_rollOverAndModeDigestsCarryChainUid`, `test_disclosureChallengeCarriesChainUid`, the S3 vector tests (word 3
  flipped ⇒ refused), the Rust `header_binding` tamper list.
- **The direct unshield-unwrap binding (ruling K8).** A copied direct proof cannot change the leg, drop `minOut` or go
  through `zetherUnshield`: `test_unshieldUnwrap_directProofBindsLegAndMinOut`.
- **Allowlist and fees.** Every confidential op `ABSOLUTE` (PERCENT refused before the call), the roll-overs, `mint` and
  `mtxTrade` refused, the outer fee only from the signer's public balance, a fee to the token refused:
  `test_allowlistPinned`, `test_allowlistPinned_underlyingZether`, `test_percentFeeRefused`,
  `test_outerFeeOnlyFromThePublicBalance`, `test_feeToTheTokenRefused`.
- **Replay and the acc/pending race** carried over: `test_replaySameProofRejected`, `…AcrossTokens…`, `…AcrossChains…`,
  `test_rollOverBetweenProveAndSubmitRejectsCheaply`, `test_rollOverSigned*`.
- **Disclosure carried over (owner flag).** Four openings on both formats and all three storage modes, the auditor
  opt-out, `disclosure()`/`transferEntry`/`auditorKey()` on both kinds: `test_disclosureFourOpenings`,
  `test_singleAuditorOptOut`, `test_disclosure{Hash,Bundle,NoBundle}Mode…` (Multi), `test_auditorOptOut`,
  `test_disclosureOnTheUnderlyingKind`, `test_thirdPartyContractVerifiesOnChain`; HASH in one `bytes32` slot
  (disclosure review G2): `test_disclosureHashMode` reads the slot.
- **Relayed HASH (G3).** The default `zetherTransfer` relays like the single format:
  `test_relayedMultiTransfer_unshield_shield`.
- **The old line.** Nothing in `scaas-node` or the e2e reads `ZetherToken` (no Zether reference in the node): the e2e
  stays green with no node change; `OpenFactoryV1` keeps its mock-tested `ZETHER` kind until P5.

## Rulings (docs vs code) and defaults taken

- **K1 — `chainUid` scope (CTR-ZTH-36, MT-4).** Built for every token-side Zether digest: the statement header (416
  bytes, word 3; the verifier's `HEADER = 416`, `fee` at 288, `amount` at 352), `entryRef`, the roll-over and mode
  digests, the envelope binding, the disclosure challenge (`ZetherDisclosure` reads `IMetaTx(token).chainUid()`). The
  Rust prover follows (`Header.chain_uid`, `entry_ref`, `Entry.chain_uid`, `envelope_binding`) and also mixes
  `chain_uid` into `derive_s`/`derive_s_multi`: a re-created chain restarts `sendCounter` while CREATE2 keeps the token
  address, so without it two chains would reuse one `s` (leaking `v1 − v2`). The built `UniversalAccountRegistry` is not
  changed (its PoP binds `msg.sender`; the UA registry that replaces it carries `chainUid`, CTR-UA-22).
- **K2 — The kinds are the public kinds plus the layer.** `ZetherLayer is MetaTokenBase, IZetherToken`;
  `NoUnderlyingZetherToken is NoUnderlyingToken, ZetherLayer`, `UnderlyingZetherToken is UnderlyingToken, ZetherLayer`
  (the class diagram's `MetaTokenBase <|--` holds through the parent), so mint/burn, the legs, `wrap`/`unwrap`,
  `addReserve`, `mtxWrap`, the rate and guardian roles are inherited, not copied. `kind()`, `_init`, `mtxSelectors`,
  `_mtxRule`, `executeRate`, `disableFeature` become `virtual` in the public kinds (no bytecode change); the second
  base forces `disableFeature` to be restated in `UnderlyingZetherToken` (three lines). No `isHedera` on the Zether
  kinds: no Hedera chain is a dev chain.
- **K3 — Domain name.** CTR-MTX-02 / CTR-ZTH-08 give Zether `("SCaaS ZetherToken", "1", chainId, clone, chain_uid)`;
  token-wrappers.md §7's interface comment says "SCaaS MetaToken" for "all kinds". Ruled for CTR-MTX-02: a
  `_domainName()` hook in `ERC20MetaTx` (called in the base constructor's argument; Solidity resolves it to the most
  derived override), `"SCaaS ZetherToken"` in `ZetherLayer` (room for `"SCaaS PqzToken"`, CTR-PQZ-15).
- **K4 — `ConfidentialConfig` gains `maxShielded` and `confidentialFee`** (zether.md makes both per-token parameters;
  CTR-TOK-25 listed three fields). Validation as the built `initialize` (`BadInit`): scale > 0, `0 < cap ≤ 2^54`,
  `fee < 2^64` and `< cap`, auditor key empty or a valid point `≠ O` of the verifier's curve, `cap · scale` without
  overflow; `decimals` is `cfg.decimals` (no underlying to read).
- **K5 — The Zether gate moves onto `OpenFactory`** (CTR-TOK-03 "OpenFactory gets it with P3"): `zetherEnabled`
  (default false), `setZetherEnabled` (registrar; `true` only on a dev chain), and creation of kinds 2–3 checks the
  flag, the dev chain and the verifier exactly as `OpenFactoryV1` (`VerifierRequiredForZether`,
  `VerifierUnsupportedOnThisChain(verifier, curve)`); registration of kinds 2–3 stays open (P1e ruling); the token's
  `initialize` repeats the dev-chain check.
- **K6 — The allowlist (CTR-ZTH-34, CTR-MTX-19).** Spec lists `zetherTransfer`, `zetherUnshield`, `zetherShield`;
  ruled: every signer-authorised confidential op is allowlisted `ABSOLUTE` with `staticLen 0` — the four transfers,
  `zetherShield`, `zetherUnshield`, and on `UNDERLYING_ZETHER` `zetherWrapShield` (`staticLen 100`) and
  `zetherUnshieldUnwrap`. `UNDERLYING_ZETHER` keeps exactly `UnderlyingToken`'s six (no `unwrap(uint256,address)`:
  metatx.md's row predates P1d's "one intent, one digest"). The roll-overs stay out (they carry their own signature or
  none).
- **K7 — The ticket binding.** `MetaTxBase._selfCall` stores `_envelopeBinding(m)` (virtual, 0 by default, so the
  other contracts pay one comparison) in the transient slot `scaas.mtx.binding` when it is non-zero;
  `_ticketBinding()` returns it only for `msg.sender == this` under a live ticket. The slot is not cleared: it is read
  only under a live ticket, and every self-call of a contract with a binding writes it first (a clear would be dead
  code). A PQZ token plugs its own tag into the same hook (CTR-PQZ-21).
- **K8 — A direct `zetherUnshieldUnwrap` binds its leg and `minOut` (spec gap).** The unshield statement binds `amount`
  and `recipient` only, so a direct-call proof copied from the mempool could be replayed with another leg, `minOut = 0`
  or as `zetherUnshield`. Direct: tag `ZTX_V1_DIRECT`, binding word `keccak256(abi.encode(keccak256("SCAAS-ZETHER-UNWRAP-V1"),
  u, minOut))`; relayed: the envelope binding (the signature covers `data`, so `u` and `minOut`). The verifier is
  unchanged (it never reads the tag); the Rust prover decodes a non-zero DIRECT word as `Binding::Unwrap` and accepts
  `unwrapBinding` in a request; `ZetherStatements.unshieldUnwrapStatement` / `unwrapBinding` serve clients.
- **K9 — Reserve invariant by construction** (CTR-ZTH-44 "checked after every operation that moves value out"): a
  wrap-shield credits exactly `minted / scale` with `minted` a multiple of the scale, an unshield-unwrap pays at most
  the value it removes, and `UnderlyingLib` already refuses a payout above the leg's reserve; `executeRate` passes
  `totalSupply() + totalShielded·shieldScale`. The built `_checkEscrow` is not ported: a balance check is what the
  reserve model never prices, and the check could not fail (no killable mutant); the invariant handler pins it.
- **K10 — Events.** The names of CTR-ZTH-45 (`ZetherShielded`, `ZetherTransfer`, `ZetherTransferMulti`,
  `TransferBundles`, `ZetherUnshielded`, `RolledOver`, `RollOverModeChanged`). `zetherWrapShield` and
  `zetherUnshieldUnwrap` emit only `ZetherShielded` / `ZetherUnshielded`: nothing is minted or burnt, so no `Wrapped` /
  `Unwrapped` (an indexer reading those as supply moves would miscount); the leg's reserve is `legOf`.
- **K11 — Shapes and the interface.** `zetherShield(bytes encodedY, uint256)` (selector pinned by CTR-ZTH-34) and
  `zetherWrapShield(address u, uint256 amountIn, UA ua)` (§21) as specified. `IZetherToken` is standalone (not
  `is IERC20MetaTx`: the shared functions would need override lists on every kind) and holds the ops both kinds have;
  `zetherWrapShield` / `zetherUnshieldUnwrap` are on `UnderlyingZetherToken` (CTR-ZTH-45: "`NONE_ZETHER` has
  `zetherShield` / `zetherUnshield` only"). The built error names are kept, `EscrowInvariant`, `UnsupportedUnderlying`,
  `ZetherOpNotCanonical` go with the old token; `AmountNotScaled(minted, shieldScale)` is new.
- **K12 — `ZetherStatements`.** Every view takes `envelopeBinding` (`transferStatement` too: §21 has none, but a
  multi-recipient transfer now relays); the views run the token's own cheap checks (registration through the token's
  registry, shapes, the proved counters) so a client gets the same error the token would raise.
- **K13 — `FeeWouldStick` (CTR-ZTH-23).** The base's `TransferToSelf` refuses a fee to the token in step 6; no separate
  error name (`test_feeToTheTokenRefused`).
- **K14 — The old line to `legacy/p3/`** (owner rule over TODO's "delete ZetherToken"): `git mv` of `ZetherToken.sol`,
  `ZetherMetaTx.sol`, the old `IZetherToken.sol` and their tests (`ZetherToken.t`, `ZetherMulti.t`,
  `ZetherRevertPaths.t`, `ZetherGate.t`, the fixture); the new tests are ports. `scaas-node` reads nothing of it (no
  Zether reference in the node, e2e, or `clientkeys` beyond R33 keys and Schnorr vectors, which do not change), so no node
  change; `OpenFactoryV1`/`IOpenFactoryV1`/`IFactoryTokenV1` (mock-tested `ZETHER` kind) stay until P5 because the node's
  e2e deploys `OpenFactoryV1`; `MetaTxLib.LegacyMetaTransaction` stays for the v1 line.
- **K15 — The prover follows the new ABI.** `zetherTransferSingle` / `zetherTransfer*` / `zetherUnshield` calldata,
  `shieldCalldata` (was `fundCalldata`), `opData` dropped (the envelope's `data` is the direct calldata), the envelope
  module on the 9-field `MetaTransaction` and the salted `"SCaaS ZetherToken"` domain, `chainUid` required in
  every request; multi-recipient proofs may be relayed. A direct `zetherUnshieldUnwrap` calldata builder is not added
  (clients, P5).
- **K16 — Deploy.** `DeployBase._deployTokenFactory` deploys on a dev chain the registry, `ZetherDisclosure`,
  `ZetherStatements`, both verifiers and both kinds, registers kinds 2–3 as version 1 and switches the gate on (JSON keys
  `zether_*`, `implementation_*_zether`); elsewhere nothing of Zether (the registry and verifiers would revert). Because
  the script links them, forge now also deploys `UnderlyingLib` and `ZetherLib` on every chain (stateless, unused
  there). The e2e chains (319xx, 298) are not dev chains: `ZetherDeploy.t` runs the step on 31337 and checks the others.
- **K17 — Size.** `size_gate.py` treats the two kinds as token implementations (20,480 B budget); the ratchet baseline
  gains `NoUnderlyingZetherToken` and `UnderlyingZetherToken`, raises `NoUnderlyingToken` / `UnderlyingToken` by what the
  hooks cost, drops the unbuilt `ZetherToken`.
- **K18 — Not built in P3.** The `mtxBatch` not-batchable hook (CTR-PQZ-21): no PQZ selector exists, it comes with
  `PqzToken`; the registry's `chainUid` (UA F1); a real-passkey envelope test (CTR-ZTH-21; a `Mock1271Wallet` signer is
  tested); the client ABI and the node's Zether support (P5).
- **K19 — Disclosure carried over, with the disclosure review's gaps folded** (`docs/research/zether-disclosure.md`
  §7, G2–G5; controller rulings): every opening (`SENDER_S`, `RECEIVER_X`, `AUDITOR`, `SENDER_CP`), the auditor key,
  the per-transfer auditor opt-out and the three storage modes work as built, tested on both kinds. **G4:** the
  challenge binds `chainUid` (K1, MT-4) although CTR-ZTH-44 says `ZetherDisclosure` "stays as built". **G2:** HASH stores
  `keccak256(B_1 ‖ … ‖ B_M)` as a `bytes32` in one slot (`entryHashes`, CTR-ZTH-38 "one slot"; the built 32-byte `bytes`
  took two, ≈ 22 k gas more); `transferEntry` still returns the 32 bytes, so `ZetherDisclosure` is unchanged.
  **G3:** relayed transfers reach every entry point, the HASH default included (K6). **G5:** the `ITransferDisclosure`
  NatSpec no longer claims "no extra gas".

## Open questions (not blocking)

- **Disclosure (left open by the controller after `docs/research/zether-disclosure.md`):** the form of the `s`
  derivation and `chainUid` in it (G1/R7; the prover now mixes `chainUid` in, K1), the auditor opt-out policy (R3),
  auditor key rotation (R1), pinning `ZetherDisclosure` and the verifier (R8), archiving `TransferBundles` in the node
  (R6), per-leg randomness / ECDH. P3 changes none of them.
- **K8:** binding a direct `zetherUnshieldUnwrap` to its leg and `minOut` (a new binding word under `ZTX_V1_DIRECT`) is a
  controller ruling over a spec gap; the alternative is accepting the front-run (another leg, `minOut = 0`, or the
  unshield into public units) on multi-leg tokens.
- **K6:** the allowlist goes beyond the three Zether selectors CTR-ZTH-34 names (Bundle/NoBundle/Single, wrap-shield,
  unshield-unwrap): confirm, and confirm that `unwrap(uint256,address)` stays unlisted on `UNDERLYING_ZETHER`.
- **K3:** two docs disagree on the confidential domain name; the code follows CTR-MTX-02 (`"SCaaS ZetherToken"`).
- **Gas tables:** zether.md §19 still shows the measurements of the old `ZetherToken`; the new kinds add the library's
  `DELEGATECALL` and the base's pipeline (the tests log every cell): re-measure and update with the node gas-cap advice?
- **K16:** the deploy script now deploys `UnderlyingLib` and `ZetherLib` on every chain (forge links what the script can
  create). A separate `DeployZether.s.sol` for dev chains would avoid it at the cost of a second script.
- **e2e flake:** one of three e2e runs hung in `forge script Deploy.s.sol` (anvil kept 13 deploy transactions in its
  pool, unmined; an empty `evm_mine` did not include them); the rerun and the final run passed. P3 adds library
  transactions to that deploy (K16); `--slow` in the e2e's `forge script` would remove the race.

---
### Task 1: Factory and kind plumbing for the confidential kinds

**Model:** Sonnet, effort medium (small, validated diffs; the gate tests are the check).

**Files:**
- Modify: `smartcontracts/evm/src/factory/IFactoryToken.sol`, `IOpenFactory.sol`, `OpenFactory.sol`,
  `src/metatx/ERC20MetaTx.sol`, `MetaTokenBase.sol`, `NoUnderlyingToken.sol`, `UnderlyingToken.sol`, `UnderlyingLib.sol`,
  `size-baseline.json`
- Create: `smartcontracts/evm/test/v2/FactoryZether.t.sol`

**Interfaces:** Produces `ConfidentialConfig{verifier, auditorKey, shieldScale, maxShielded, confidentialFee}` (K4);
`MetaTokenBase._requireUnused(cfg, supply, legs, rate, conf)`; `ERC20MetaTx._domainName()` (K3); `virtual` on the
public kinds' `kind`, `_init`, `mtxSelectors`, `_mtxRule`, `executeRate`, `disableFeature` (K2);
`UnderlyingLib.initToken(cfg, isHedera, kind)`; `OpenFactory.zetherEnabled`, `setZetherEnabled`, `ZetherEnabled`,
`ZetherDisabled`, `VerifierRequiredForZether`, `VerifierUnsupportedOnThisChain` and the gate in `_create` (K5).

- [ ] **Step 1: the source changes** (apply the diff; the factory imports `ZetherSafety`/`IZetherVerifier`, which stay
  in `src/zether/`):

```diff
diff --git a/smartcontracts/evm/src/factory/IFactoryToken.sol b/smartcontracts/evm/src/factory/IFactoryToken.sol
index 13a45a1..5ccd681 100644
--- a/smartcontracts/evm/src/factory/IFactoryToken.sol
+++ b/smartcontracts/evm/src/factory/IFactoryToken.sol
@@ -21,11 +21,14 @@ interface IFactoryToken {
         uint16 maxRateStepBps;
     }
 
-    /// @notice `*_ZETHER` kinds only (P3); every other kind requires it empty.
+    /// @notice `*_ZETHER` kinds only; every other kind requires it empty. `maxShielded` (the total cap, `≤ 2^54`) and
+    ///         `confidentialFee` (the inner fee, `< 2^64` and `< maxShielded`) are per token (CTR-ZTH-04, CTR-ZTH-05).
     struct ConfidentialConfig {
         address verifier;
         bytes auditorKey;
         uint256 shieldScale;
+        uint256 maxShielded;
+        uint256 confidentialFee;
     }
 
     /// @notice CTR-TOK-25. Fields of another kind must be empty (`ConfigFieldForOtherKind`), so a token never carries a
diff --git a/smartcontracts/evm/src/factory/IOpenFactory.sol b/smartcontracts/evm/src/factory/IOpenFactory.sol
index 7b4e356..886c312 100644
--- a/smartcontracts/evm/src/factory/IOpenFactory.sol
+++ b/smartcontracts/evm/src/factory/IOpenFactory.sol
@@ -44,6 +44,19 @@ interface IOpenFactory {
     error DexVersionUnknown(uint64 version);
     error DexVersionAlreadyRegistered(uint64 version, address existing);
 
+    /// @notice The Zether gate (CTR-ZTH-02, CTR-TOK-03): off by default, switched by the registrar, on only on a dev
+    ///         chain (`ZetherSafety`); creating a `*_ZETHER` token needs it on, a dev chain, and a verifier this chain
+    ///         can run (`isSupportedOnThisChain()`).
+    event ZetherEnabled(bool enabled);
+    error ZetherDisabled();
+    error VerifierRequiredForZether();
+    /// @notice `curve` is the verifier's `curveName()`, empty when it has no code or no answer.
+    error VerifierUnsupportedOnThisChain(address verifier, string curve);
+
+    function zetherEnabled() external view returns (bool);
+    /// @notice Registrar only; `true` reverts `ZetherNotDevChain` outside chain ids 31337/1337, `false` always works.
+    function setZetherEnabled(bool on) external;
+
     /// @notice DEX catalogue (CTR-DEX-24): append-only, versions from 1; the implementation must answer
     ///         `factory() == this` and `chainUid() == chainUid`.
     event DexImplementationRegistered(uint64 indexed version, address indexed implementation, address registrar);
diff --git a/smartcontracts/evm/src/factory/OpenFactory.sol b/smartcontracts/evm/src/factory/OpenFactory.sol
index 9e78774..ce827b5 100644
--- a/smartcontracts/evm/src/factory/OpenFactory.sol
+++ b/smartcontracts/evm/src/factory/OpenFactory.sol
@@ -6,6 +6,8 @@ import {IOpenFactory} from "./IOpenFactory.sol";
 import {IFactoryToken} from "./IFactoryToken.sol";
 import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
 import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";
+import {IZetherVerifier} from "../zether/IZetherVerifier.sol";
+import {ZetherSafety} from "../zether/ZetherSafety.sol";
 
 /// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain.
 /// @notice Anyone creates tokens; the registrar only appends implementations to the catalogue (and marks versions
@@ -13,7 +15,8 @@ import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";
 ///         `factory() == this` and `chainUid() == chainUid` (so a clone's domain salt has one source, CTR-GEN-05);
 ///         the catalogue is append-only, so a wrong entry would be dead forever. Creation clones by `CREATE2` with
 ///         the salt scoped by the creator and calls `initialize` in the same call; flag validation is the token's.
-///         Built kinds: `NONE`, `UNDERLYING` (the `*_ZETHER` implementations come with P3, the DEX with P2).
+///         Kinds `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER`; a `*_ZETHER` creation passes the Zether gate
+///         (`zetherEnabled`, a dev chain, a verifier this chain runs). **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS.**
 contract OpenFactory is IOpenFactory {
     struct Info {
         address creator;
@@ -36,6 +39,7 @@ contract OpenFactory is IOpenFactory {
     mapping(uint64 => address) private _dexImpl;
     uint64 private _latestDex;
     mapping(address => uint64) private _dexVersion; // 0 = not a DEX made here
+    bool public zetherEnabled;
 
     constructor(address registrar_, bytes32 chainUid_) {
         if (chainUid_ == bytes32(0)) revert ChainUidZero();
@@ -75,6 +79,13 @@ contract OpenFactory is IOpenFactory {
         return _latest[kind];
     }
 
+    function setZetherEnabled(bool on) external {
+        if (msg.sender != registrar) revert NotRegistrar();
+        if (on) ZetherSafety.requireDevChain();
+        zetherEnabled = on;
+        emit ZetherEnabled(on);
+    }
+
     // ------------------------------------------------------------------ create
 
     function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
@@ -180,6 +191,21 @@ contract OpenFactory is IOpenFactory {
         if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
     }
 
+    /// @dev The gate, then the verifier: an absent precompile does not revert, it returns success with empty output,
+    ///      so a verifier this chain cannot run is refused before anyone deposits (CTR-TOK-03).
+    function _checkZether(address verifier) private view {
+        if (!zetherEnabled) revert ZetherDisabled();
+        ZetherSafety.requireDevChain(); // a flag set on a dev chain does not survive a chain id change (fork)
+        if (verifier == address(0)) revert VerifierRequiredForZether();
+        if (verifier.code.length == 0) revert VerifierUnsupportedOnThisChain(verifier, "");
+        bool ok;
+        try IZetherVerifier(verifier).isSupportedOnThisChain() returns (bool s) { ok = s; } catch {}
+        if (ok) return;
+        string memory curve;
+        try IZetherVerifier(verifier).curveName() returns (string memory c) { curve = c; } catch {}
+        revert VerifierUnsupportedOnThisChain(verifier, curve);
+    }
+
     function _word(address target, bytes4 sel) private view returns (bool ok, uint256 w) {
         bytes memory ret;
         (ok, ret) = target.staticcall(abi.encodeWithSelector(sel));
@@ -194,6 +220,7 @@ contract OpenFactory is IOpenFactory {
     function _create(TokenKind kind, uint64 version, address impl, IFactoryToken.TokenConfig calldata cfg,
         bytes32 salt) private returns (address token)
     {
+        if (kind == TokenKind.NONE_ZETHER || kind == TokenKind.UNDERLYING_ZETHER) _checkZether(cfg.conf.verifier);
         uint256 n = cfg.legs.length;
         bool wrapper = kind == TokenKind.UNDERLYING || kind == TokenKind.UNDERLYING_ZETHER;
         if (wrapper ? n == 0 || n > MAX_LEGS : n != 0) revert UnderlyingCountInvalid(n);
diff --git a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
index 1f8b625..729722c 100644
--- a/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
+++ b/smartcontracts/evm/src/metatx/ERC20MetaTx.sol
@@ -22,7 +22,12 @@ import {TradeLib} from "../trade/TradeLib.sol";
 abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment, ITradeToken {
     using MetaTxLib for MetaTxLib.MetaTransfer;
 
-    constructor(bytes32 chainUid_) ERC20("", "") MetaTxBase("SCaaS MetaToken", chainUid_) {}
+    constructor(bytes32 chainUid_) ERC20("", "") MetaTxBase(_domainName(), chainUid_) {}
+
+    /// @notice The EIP-712 domain name (CTR-MTX-02): `"SCaaS MetaToken"`; a confidential kind overrides it.
+    function _domainName() internal pure virtual returns (string memory) {
+        return "SCaaS MetaToken";
+    }
 
     // ------------------------------------------------------------------ views
 
diff --git a/smartcontracts/evm/src/metatx/MetaTokenBase.sol b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
index d8aaf98..2c6ae9e 100644
--- a/smartcontracts/evm/src/metatx/MetaTokenBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTokenBase.sol
@@ -73,13 +73,13 @@ abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IER
     function _init(TokenConfig calldata cfg) internal virtual;
 
     /// @dev `ConfigFieldForOtherKind` for a set field the kind does not use; `conf` is used only by `*_ZETHER`.
-    function _requireUnused(TokenConfig calldata cfg, bool supply, bool legs, bool rate) internal pure {
+    function _requireUnused(TokenConfig calldata cfg, bool supply, bool legs, bool rate, bool conf) internal pure {
         if (supply && (cfg.initialSupply != 0 || cfg.initialHolder != address(0))) revert ConfigFieldForOtherKind(1);
         if (legs && cfg.legs.length != 0) revert ConfigFieldForOtherKind(2);
         if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert ConfigFieldForOtherKind(3);
-        if (cfg.conf.verifier != address(0) || cfg.conf.auditorKey.length != 0 || cfg.conf.shieldScale != 0) {
-            revert ConfigFieldForOtherKind(4);
-        }
+        ConfidentialConfig calldata c = cfg.conf;
+        if (conf && (c.verifier != address(0) || c.auditorKey.length != 0 || c.shieldScale != 0 || c.maxShielded != 0
+            || c.confidentialFee != 0)) revert ConfigFieldForOtherKind(4);
     }
 
     function _setMetadata(string memory n, string memory sym, uint8 d) internal {
diff --git a/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol b/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
index c0164fa..e1dcce9 100644
--- a/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
+++ b/smartcontracts/evm/src/metatx/NoUnderlyingToken.sol
@@ -15,12 +15,12 @@ contract NoUnderlyingToken is MetaTokenBase {
         MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
     {}
 
-    function kind() public pure override returns (uint8) {
+    function kind() public pure virtual override returns (uint8) {
         return AdminLib.KIND_NONE;
     }
 
-    function _init(TokenConfig calldata cfg) internal override {
-        _requireUnused(cfg, false, true, true);
+    function _init(TokenConfig calldata cfg) internal virtual override {
+        _requireUnused(cfg, false, true, true, true);
         _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
         AdminLib.init(AdminLib.KIND_NONE, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
         if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
@@ -40,7 +40,7 @@ contract NoUnderlyingToken is MetaTokenBase {
 
     /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.
     function mtxSelectors()
-        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
+        public pure virtual override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
     {
         s = new bytes4[](2);
         c = new uint8[](2);
@@ -49,7 +49,7 @@ contract NoUnderlyingToken is MetaTokenBase {
         (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
     }
 
-    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
+    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
         if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
         return super._mtxRule(sel);
     }
diff --git a/smartcontracts/evm/src/metatx/UnderlyingLib.sol b/smartcontracts/evm/src/metatx/UnderlyingLib.sol
index e546376..36e4e1c 100644
--- a/smartcontracts/evm/src/metatx/UnderlyingLib.sol
+++ b/smartcontracts/evm/src/metatx/UnderlyingLib.sol
@@ -72,15 +72,16 @@ library UnderlyingLib {
     // ------------------------------------------------------------------ init
 
     /// @notice The token's `_init`: legs 1–8 (the factory's index reads the same `legs`), the metadata, the
-    ///         flags/owner/roles (`AdminLib.init`), the rate config, then the legs in their given order (never changes).
-    function initToken(IFactoryToken.TokenConfig calldata c, bool isHedera) public {
+    ///         flags/owner/roles of `kind` (`AdminLib.init`: `UNDERLYING` or `UNDERLYING_ZETHER`), the rate config, then
+    ///         the legs in their given order (never changes).
+    function initToken(IFactoryToken.TokenConfig calldata c, bool isHedera, uint8 kind) public {
         uint256 n = c.legs.length;
         if (n == 0 || n > MAX_LEGS) revert MetaTokenBase.UnderlyingCountInvalid(n);
         AdminLib.TokenStorage storage t = AdminLib.$();
         t.name = c.name;
         t.symbol = c.symbol;
         t.decimals = c.decimals;
-        AdminLib.init(AdminLib.KIND_UNDERLYING, c.features, c.lockedFeatures, c.owner, c.roles);
+        AdminLib.init(kind, c.features, c.lockedFeatures, c.owner, c.roles);
         bool adjustable = AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
         UnderlyingStorage storage s = $();
         IFactoryToken.RateConfig calldata rate = c.rate;
diff --git a/smartcontracts/evm/src/metatx/UnderlyingToken.sol b/smartcontracts/evm/src/metatx/UnderlyingToken.sol
index e661556..d677d65 100644
--- a/smartcontracts/evm/src/metatx/UnderlyingToken.sol
+++ b/smartcontracts/evm/src/metatx/UnderlyingToken.sol
@@ -29,14 +29,14 @@ contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
         MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
     {}
 
-    function kind() public pure override returns (uint8) {
+    function kind() public pure virtual override returns (uint8) {
         return AdminLib.KIND_UNDERLYING;
     }
 
     /// @dev `initialSupply`, `initialHolder`, `conf` must be empty; legs and rate are checked in `UnderlyingLib`.
-    function _init(TokenConfig calldata cfg) internal override {
-        _requireUnused(cfg, true, false, false);
-        UnderlyingLib.initToken(cfg, IS_HEDERA);
+    function _init(TokenConfig calldata cfg) internal virtual override {
+        _requireUnused(cfg, true, false, false, true);
+        UnderlyingLib.initToken(cfg, IS_HEDERA, AdminLib.KIND_UNDERLYING);
     }
 
     // ------------------------------------------------------------------ wrap / unwrap / reserve
@@ -117,12 +117,12 @@ contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
         UnderlyingLib.cancelRate(_msgSender());
     }
 
-    function executeRate() external {
+    function executeRate() external virtual {
         UnderlyingLib.executeRate(_msgSender(), totalSupply());
     }
 
     /// @notice `disableFeature(RATE_ADJUSTABLE)` also cancels a pending rate change (CTR-TOK-06).
-    function disableFeature(uint8 bit) external override {
+    function disableFeature(uint8 bit) external virtual override {
         AdminLib.disableFeature(bit, _msgSender());
         if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
     }
@@ -134,7 +134,7 @@ contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
     ///         `unwrap(address,uint256,address,uint256)` `AMOUNT(1)` (gasless unwrap, CTR-MTX-12). The two-argument
     ///         `unwrap` is not listed (same intent, second digest, no `minOut`).
     function mtxSelectors()
-        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
+        public pure virtual override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
     {
         s = new bytes4[](6);
         c = new uint8[](6);
@@ -147,7 +147,7 @@ contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
         (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
     }
 
-    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
+    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
         if (sel == SEL_WRAP) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
         if (sel == SEL_UNWRAP_MIN) return MtxRule(FEE_CLASS_AMOUNT, 0, 100);
         if (sel == SEL_WRAP_LEG) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
```

- [ ] **Step 2: `test/v2/FactoryZether.t.sol`** (new): mock kinds 2 and 3 (the public kinds under the confidential id,
  accepting `conf`) test the gate, the verifier check, the kind-3 flags, the `conf` refusal on public kinds and the
  domain-name hook.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {UnderlyingLib} from "../../src/metatx/UnderlyingLib.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {MockERC20, SupportedVerifier, UnsupportedVerifier} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

/// Kind 2 stand-in: the public `NONE` kind under the confidential id and domain name, accepting `conf` (the factory's
/// side only; the Zether layer is tested in `test/zether`).
contract MockNoneZether is NoUnderlyingToken {
    constructor(address f) NoUnderlyingToken(f, address(0), UID_, false) {}

    function kind() public pure override returns (uint8) { return AdminLib.KIND_NONE_ZETHER; }

    function _domainName() internal pure override returns (string memory) { return "SCaaS ZetherToken"; }

    function _init(TokenConfig calldata cfg) internal override {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
    }
}

/// Kind 3 stand-in: the public `UNDERLYING` kind under the confidential id, its flags validated for kind 3.
contract MockUnderlyingZether is UnderlyingToken {
    constructor(address f) UnderlyingToken(f, address(0), UID_, false) {}

    function kind() public pure override returns (uint8) { return AdminLib.KIND_UNDERLYING_ZETHER; }

    function _init(TokenConfig calldata cfg) internal override {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, IS_HEDERA, AdminLib.KIND_UNDERLYING_ZETHER);
    }
}

/// The Zether gate of `OpenFactory` (CTR-ZTH-02, CTR-TOK-03): off by default, registrar only, dev chains only, the
/// verifier checked at creation; the `conf` fields are the confidential kinds' only (CTR-TOK-25); the domain name hook.
contract FactoryZetherTest is Test {
    OpenFactory f;
    address registrar = address(0xF00D);
    MockNoneZether noneZ;
    MockUnderlyingZether undZ;
    MockERC20 usd = new MockERC20("USD", "USD", 6);
    SupportedVerifier okVer = new SupportedVerifier();
    UnsupportedVerifier badVer = new UnsupportedVerifier();

    IOpenFactory.TokenKind constant NZ = IOpenFactory.TokenKind.NONE_ZETHER;
    IOpenFactory.TokenKind constant UZ = IOpenFactory.TokenKind.UNDERLYING_ZETHER;

    function setUp() public {
        f = new OpenFactory(registrar, UID_);
        noneZ = new MockNoneZether(address(f));
        undZ = new MockUnderlyingZether(address(f));
        vm.startPrank(registrar);
        f.registerImplementation(NZ, 1, address(noneZ));
        f.registerImplementation(UZ, 1, address(undZ));
        vm.stopPrank();
    }

    function _conf(address verifier) internal pure returns (IFactoryToken.TokenConfig memory c) {
        c = noneInit("Zether", "Z", 6, 0, address(0), address(0));
        c.conf.verifier = verifier;
        c.conf.shieldScale = 1;
    }

    function _underlying(address verifier) internal view returns (IFactoryToken.TokenConfig memory c) {
        c.name = "Zether wrapped";
        c.symbol = "ZW";
        c.decimals = 6;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf.verifier = verifier;
    }

    function _enable() internal {
        vm.prank(registrar);
        f.setZetherEnabled(true);
    }

    function test_zetherGate_offByDefault_registrarOnly_devChainsOnly() public {
        assertFalse(f.zetherEnabled());
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createToken(NZ, 1, _conf(address(okVer)), "a");
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createTokenUnregistered(UZ, address(undZ), _underlying(address(okVer)), "a");
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.setZetherEnabled(true);
        uint256[4] memory prod = [uint256(1), 100, 42220, 7622];
        for (uint256 i; i < prod.length; ++i) {
            vm.chainId(prod[i]);
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, prod[i]));
            f.setZetherEnabled(true);
            vm.prank(registrar);
            f.setZetherEnabled(false); // switching off always works
        }
        vm.chainId(1337);
        vm.recordLogs();
        _enable();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IOpenFactory.ZetherEnabled.selector);
        assertEq(abi.decode(logs[0].data, (bool)), true);
        assertTrue(f.zetherEnabled());
        f.createToken(NZ, 1, _conf(address(okVer)), "on 1337");
        // the flag set on a dev chain does not survive a chain id change (a fork)
        vm.chainId(100);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 100));
        f.createToken(NZ, 1, _conf(address(okVer)), "fork");
        vm.chainId(31337);
        vm.prank(registrar);
        f.setZetherEnabled(false);
        vm.expectRevert(IOpenFactory.ZetherDisabled.selector);
        f.createToken(NZ, 1, _conf(address(okVer)), "off again");
    }

    function test_zetherGate_verifierCheckedAtCreation_bothKinds() public {
        _enable();
        vm.expectRevert(IOpenFactory.VerifierRequiredForZether.selector);
        f.createToken(NZ, 1, _conf(address(0)), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VerifierUnsupportedOnThisChain.selector, address(0x99), ""));
        f.createToken(NZ, 1, _conf(address(0x99)), "a");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VerifierUnsupportedOnThisChain.selector, address(badVer),
            "bls12-381"));
        f.createToken(NZ, 1, _conf(address(badVer)), "a");
        address mute = address(usd); // has code, answers neither function
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VerifierUnsupportedOnThisChain.selector, mute, ""));
        f.createTokenUnregistered(UZ, address(undZ), _underlying(mute), "a");
        vm.expectRevert(IOpenFactory.VerifierRequiredForZether.selector);
        f.createToken(UZ, 1, _underlying(address(0)), "a");
        address t = f.createToken(NZ, 1, _conf(address(okVer)), "ok");
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(t);
        assertEq(uint8(k), uint8(NZ));
        assertEq(v, 1);
        address w = f.createToken(UZ, 1, _underlying(address(okVer)), "ok");
        assertEq(f.getWrapper(address(this), address(usd)), w);
        // the public kinds never pass through the gate (no flag, no verifier)
        NoUnderlyingToken none = new NoUnderlyingToken(address(f), address(0), UID_, false);
        vm.prank(registrar);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        vm.prank(registrar);
        f.setZetherEnabled(false);
        f.createToken(IOpenFactory.TokenKind.NONE, 1, noneInit("P", "P", 0, 0, address(0), address(0)), "public");
    }

    /// The flags of kind 3 are validated for kind 3: the regulated flags are invalid there (CTR-ZTH-47), not "not built".
    function test_underlyingZether_flagsValidatedForItsKind() public {
        _enable();
        IFactoryToken.TokenConfig memory c = _underlying(address(okVer));
        c.features = 1 << AdminLib.FREEZE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
        f.createToken(UZ, 1, c, "a");
        c.features = 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        f.createToken(UZ, 1, c, "a");
    }

    /// A public kind refuses every `conf` field, the two new ones included.
    function test_publicKinds_refuseEveryConfField() public {
        OpenFactory g = new OpenFactory(registrar, UID_);
        NoUnderlyingToken none = new NoUnderlyingToken(address(g), address(0), UID_, false);
        vm.prank(registrar);
        g.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(none));
        IFactoryToken.TokenConfig memory c = noneInit("P", "P", 0, 0, address(0), address(0));
        c.conf.maxShielded = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.maxShielded = 0;
        c.conf.confidentialFee = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
        c.conf.confidentialFee = 0;
        c.conf.verifier = address(okVer);
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        g.createToken(IOpenFactory.TokenKind.NONE, 1, c, "a");
    }

    /// CTR-MTX-02: the confidential kinds sign under "SCaaS ZetherToken", the public ones under "SCaaS MetaToken".
    function test_domainNameHook() public view {
        (, string memory n,,,, bytes32 salt,) = noneZ.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
        assertEq(salt, UID_);
        (, n,,,,,) = undZ.eip712Domain();
        assertEq(n, "SCaaS MetaToken", "a kind that does not override keeps the base name");
    }
}
```

- [ ] **Step 3: the size baseline** — the hooks add bytes to the public kinds (ratchet, K17):

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index 42010b9..01b600b 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,6 +1,6 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "NoUnderlyingToken": 22960,
-  "UnderlyingToken": 29983,
+  "NoUnderlyingToken": 22972,
+  "UnderlyingToken": 30030,
   "ZetherToken": 28860
 }
```

- [ ] **Step 4: Run** (each through `scripts/capped`, one at a time):
  - `forge test --match-path "test/v2/Factory*.t.sol"` → 19 passed (FactoryZether 5).
  - `forge test` → **954 passed**, 0 failed.
  - Size gate: `forge build src --sizes --json > /tmp/sizes.json || true; python3 ../../scripts/size_gate.py
    /tmp/sizes.json size-baseline.json` → `0 error(s)`.
- [ ] **Step 5: Commit** `P3: factory Zether gate, ConfidentialConfig fields, domain-name hook, overridable public kinds` + trailer.

---

### Task 2: The Zether primitives carry `chainUid`; the old line to `legacy/p3/`; the prover follows

**Model:** Opus, effort high (byte-exact cross-implementation change: Solidity verifier/disclosure, Rust prover,
regenerated vectors).

**Files:**
- Move (`git mv`, K14): `src/zether/{ZetherToken,ZetherMetaTx,IZetherToken}.sol` → `legacy/p3/src/zether/`;
  `test/zether/{ZetherToken,ZetherMulti,ZetherRevertPaths,ZetherGate}.t.sol`, `test/zether/helpers/ZetherFixture.sol` →
  `legacy/p3/test/zether/` (same relative paths)
- Create: `src/zether/IZetherToken.sol` (the interface of the new kinds)
- Modify: `src/zether/ZetherVerifier.sol`, `ZetherDisclosure.sol`, `ITransferDisclosure.sol` (NatSpec, G5), `legacy/README.md`,
  `test/zether/helpers/ZetherProver.sol`, `test/zether/ZetherVerifier.t.sol`, `test/zether/ZetherS3Vectors.t.sol`;
  `clients/zether-prover/src/{zether,envelope,schnorr,api,vectors}.rs`, `src/bin/zether-cli.rs`,
  `tests/{envelope_disclosure,zether_proofs,read_balance,vectors}.rs`, `tools/env_ref.sh`, `smoke/smoke.cjs`
- Regenerate: `clients/zether-prover/vectors/*.json` (+ new `envelope.json`), copied to `test/vectors/zether/s3/`

**Interfaces:** Produces the 416-byte header (`HEADER`, `FEE_AT = 288`, `AMOUNT_AT = 352`), the disclosure challenge
with `chainUid` (K1), `IZetherToken` (K11), and in Rust `Header.chain_uid`, `Binding::Unwrap`, `entry_ref(chain_id,
chain_uid, …)`, `Entry.chain_uid`, the 9-field `MetaTx` with `domain_separator/digest/envelope_binding(chain_id,
chain_uid, token, …)`, `unwrap_binding`, `transfer_call`, `unshield_call`; API: `chainUid` required, `unwrapBinding`,
`shieldCalldata`, `envelope` with `chainUid` (K15). Between this task and Task 3 no Zether token exists in `src/`.

- [ ] **Step 1: move the old line**

```bash
cd smartcontracts/evm
mkdir -p legacy/p3/src/zether legacy/p3/test/zether/helpers
for f in ZetherToken ZetherMetaTx IZetherToken; do /usr/bin/git mv src/zether/$f.sol legacy/p3/src/zether/$f.sol; done
for f in ZetherToken.t ZetherMulti.t ZetherRevertPaths.t ZetherGate.t helpers/ZetherFixture; do
  /usr/bin/git mv test/zether/$f.sol legacy/p3/test/zether/$f.sol; done
```

```diff
diff --git a/smartcontracts/evm/legacy/README.md b/smartcontracts/evm/legacy/README.md
index f4fcb8f..c17a962 100644
--- a/smartcontracts/evm/legacy/README.md
+++ b/smartcontracts/evm/legacy/README.md
@@ -11,5 +11,8 @@ Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`,
 - The authoritative copy is the tag: `git show ref/pre-token-tree:smartcontracts/evm/src/<path>`.
 - Why it exists: owner decision of 2026-10-08 (CTR-MTX-07; TODO.md §00, P1 start checklist).
 - `p1e/`: `OpenFactoryV2`, `IOpenFactoryV2`, `IFactoryTokenV2` as they stood on `main` before P1e (the factory v2 that
-  P1e rewrote into `OpenFactory`); not built. (The v1 line follows into `legacy/` when node/clientkeys (P5) and Zether
-  (P3) stop using it, E1.)
+  P1e rewrote into `OpenFactory`); not built. (The v1 line follows into `legacy/` when node/clientkeys stop using it, P5, E1.)
+- `p3/`: the built `ZetherToken`, `ZetherMetaTx` and the old `IZetherToken` (384-byte statement header, own envelope,
+  own underlying) with their tests (`ZetherToken.t`, `ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherGate.t` and the
+  fixture), as they stood on `main` before P3 replaced them by the `*_ZETHER` kinds; not built. Nothing in the node or
+  the e2e read them. `OpenFactoryV1` keeps its `ZETHER` kind (mock-tested) until the v1 line moves (P5).
```

- [ ] **Step 2: `src/zether/IZetherToken.sol`** (new; the built errors kept, `AmountNotScaled` new; `envelopeBinding`
  takes the new `MetaTransaction`):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";

/// @title The confidential layer of the kinds `NONE_ZETHER` and `UNDERLYING_ZETHER` (CTR-ZTH-44, CTR-ZTH-45): ElGamal
///        `acc`/`pending` balances over the token's public ERC-20 balance.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Byte-exact contract with the prover: `docs/contracts/zether.md`.
///         The token is also an `IERC20MetaTx` on the one meta-transaction base: every proof-carrying entry point is a
///         direct call (statement `ZTX_V1_DIRECT`, binding 0) or an allowlisted self-call of `mtxExecute` whose envelope
///         binding the statement carries (`ZTX_V1_RELAYED`, CTR-ZTH-34). `zetherWrapShield` and `zetherUnshieldUnwrap`
///         are on `UNDERLYING_ZETHER` only; the prover views are in `ZetherStatements` (CTR-ZTH-46).
interface IZetherToken {
    /// @notice One account at one block. An unset point is `O`.
    struct AccountState {
        bytes accC;
        bytes accD;
        bytes pendingC;
        bytes pendingD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    event ZetherShielded(ZetherTypes.UA indexed account, uint256 amount);
    /// @notice The single-recipient format (`zetherTransferSingle`).
    event ZetherTransfer(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed to,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef
    );
    /// @notice `M` recipients (decoys included), one proof; the recipients are public, the amounts encrypted.
    event ZetherTransferMulti(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef,
        ZetherTypes.UA[] recipients,
        ZetherTypes.TransferMode mode
    );
    /// @notice Mode HASH: `B_1 ‖ … ‖ B_M`, whose hash `entryRef` stores.
    event TransferBundles(bytes32 indexed entryRef, bytes bundles);
    /// @notice `recipient` received `amount · shieldScale` public units (`zetherUnshield`) or the underlying they are
    ///         worth (`zetherUnshieldUnwrap`).
    event ZetherUnshielded(ZetherTypes.UA indexed account, uint256 amount, address indexed recipient);
    event RolledOver(ZetherTypes.UA indexed account, uint256 accSeq);
    event RollOverModeChanged(ZetherTypes.UA indexed account, ZetherTypes.RollOverMode mode);

    error AccountNotRegistered(ZetherTypes.UA account);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error ProofRejected();
    error StaleAccSeq(uint256 expected, uint256 got);
    error StaleSendCounter(uint256 expected, uint256 got);
    error SelfTransfer();
    error BadRecipientCount(uint256 count);
    error DuplicateRecipient(ZetherTypes.UA recipient);
    error BadPayload(uint256 length);
    error RollOverOwnerOnly(ZetherTypes.UA account);
    error RollOverExpired(uint256 validUntilBlock);
    error PendingSeqMismatch(uint256 expected, uint256 got);
    error ZeroRecipient();
    /// @notice With the token's auditor on, every `C_aud_j` is `O` (left out) or none is (CTR-ZTH-42).
    error AuditorLegsMixed();
    /// @notice A `ConfidentialConfig` the token refuses (CTR-ZTH-04, CTR-ZTH-26).
    error BadInit();
    /// @notice `zetherWrapShield`: the public-equivalent of the deposit is not a whole number of shielded units.
    error AmountNotScaled(uint256 minted, uint256 shieldScale);

    // ------------------------------------------------------------------ per-token parameters (immutable)

    /// @notice The total cap in shielded units, `≤ 2^54` (CTR-ZTH-26).
    function maxDecryptableShielded() external view returns (uint256);
    /// @notice Public units per shielded unit (CTR-ZTH-04).
    function shieldScale() external view returns (uint256);
    /// @notice The inner fee, `< 2^64` and `< maxDecryptableShielded`; never a function of `v` (CTR-ZTH-07).
    function confidentialFee() external view returns (uint256);
    /// @notice The auditor key (`ITransferDisclosure.AUDITOR`), empty when off (CTR-ZTH-09).
    function auditorKey() external view returns (bytes memory);
    /// @notice The canonical `ZetherDisclosure` (stateless, shared), an implementation immutable (CTR-ZTH-43).
    function disclosure() external view returns (ITransferDisclosure);
    function verifier() external view returns (IZetherVerifier);
    /// @notice The account registry, an implementation immutable (CTR-ZTH-44).
    function registry() external view returns (address);

    // ------------------------------------------------------------------ state

    /// @notice Raw record of `entryRef` for `disclosure()`: `B_1 ‖ … ‖ B_M` (single format, BUNDLE), the 32-byte hash
    ///         (HASH), empty (NONE, unknown). `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
    function transferEntry(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Σ of every `acc` and `pending` exponent (shielded units); `totalSupply()` counts public units only.
    function totalShielded() external view returns (uint256);
    function registered(ZetherTypes.UA account) external view returns (bool);
    function accountState(ZetherTypes.UA account) external view returns (AccountState memory);
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);
    /// @notice The binding a relayed proof carries (CTR-ZTH-06): every envelope field except `data`, plus `chainUid`.
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    // ------------------------------------------------------------------ roll-over (CTR-ZTH-16, CTR-ZTH-17)

    /// @notice `PUBLIC` accounts: anyone, a silent no-op without a new credit; `OWNER_ONLY` reverts.
    function zetherRollOver(ZetherTypes.UA account) external;
    /// @notice Skips `OWNER_ONLY` items.
    function zetherRollOverBatch(ZetherTypes.UA[] calldata accounts) external;
    function zetherRollOverSigned(ZetherTypes.UA account, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external;
    function zetherSetRollOverMode(
        ZetherTypes.UA account,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external;

    // ------------------------------------------------------------------ shield / transfer / unshield (CTR-ZTH-45)

    /// @notice Burns `amount · shieldScale` public units of the caller; `pending[ua] += [amount]G` (CTR-ZTH-35).
    function zetherShield(bytes calldata encodedY, uint256 amount) external;
    /// @notice `M` recipients, one proof; stores the hash of the bundles (HASH, the default, CTR-ZTH-38).
    function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    function zetherTransferBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice The single-recipient format, its bundle stored in full.
    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice Proves the unshield statement, then mints `amount · shieldScale` public units to `to`.
    function zetherUnshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        address to,
        uint256 amount
    ) external;
}
```

- [ ] **Step 3: verifier and disclosure** — header 416 bytes, `fee`/`amount` read at their new offsets, the challenge
  reads `IMetaTx(token).chainUid()` (K1, G4); the stale "no extra gas" NatSpec corrected (G5):

```diff
diff --git a/smartcontracts/evm/src/zether/ITransferDisclosure.sol b/smartcontracts/evm/src/zether/ITransferDisclosure.sol
index 47707fc..4293ce8 100644
--- a/smartcontracts/evm/src/zether/ITransferDisclosure.sol
+++ b/smartcontracts/evm/src/zether/ITransferDisclosure.sol
@@ -23,7 +23,8 @@ pragma solidity ^0.8.20;
 ///     D_transfer = g^s
 ///
 /// nên mở nó là chứng minh số tiền, và nó ràng buộc TUYỆT ĐỐI vào đúng giao dịch đó.
-/// **Chi phí thêm lúc chuyển: bằng không.** Không thêm trường, không thêm gas.
+/// Chi phí lúc chuyển: token lưu bản ghi để mở on-chain — bundle đầy đủ (định dạng một người nhận, mode BUNDLE,
+/// 4 điểm mỗi leg), một slot hash (mode HASH), hoặc không gì (mode NONE: chỉ off-chain), CTR-ZTH-14/38.
 interface ITransferDisclosure {
     /// Ba đường mở, ba chủ thể khác nhau. Giữ cả ba — mỗi cái giải một tình huống
     /// tranh chấp mà hai cái kia không giải được.
diff --git a/smartcontracts/evm/src/zether/ZetherDisclosure.sol b/smartcontracts/evm/src/zether/ZetherDisclosure.sol
index ceabd06..2f7d91c 100644
--- a/smartcontracts/evm/src/zether/ZetherDisclosure.sol
+++ b/smartcontracts/evm/src/zether/ZetherDisclosure.sol
@@ -3,12 +3,13 @@ pragma solidity ^0.8.20;
 
 import {ITransferDisclosure} from "./ITransferDisclosure.sol";
 import {IZetherToken} from "./IZetherToken.sol";
+import {IMetaTx} from "../metatx/IMetaTx.sol";
 import {IZetherVerifier} from "./IZetherVerifier.sol";
 import {ZetherTranscript} from "./ZetherTranscript.sol";
 
 /// @title Tiết lộ có chọn lọc cho MỌI Zether token (owner Z13): không state, không admin, không nâng cấp.
 /// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Đọc từ token qua view (`transferEntry`, `verifier`,
-///         `auditorKey`); đường cong do verifier của token quyết. Tách khỏi `ZetherToken` để token vừa EIP-170.
+///         `auditorKey`, `chainUid`); đường cong do verifier của token quyết. Tách khỏi token (CTR-ZTH-43).
 ///         Challenge ràng địa chỉ TOKEN, không phải contract này: opening không phụ thuộc nơi deploy.
 contract ZetherDisclosure is ITransferDisclosure {
     bytes private constant DISCLOSE_TAG = "SCAAS-ZETHER-DISCLOSE-V1";
@@ -59,7 +60,9 @@ contract ZetherDisclosure is ITransferDisclosure {
             if (ya.length == 0 || _isO(l.cAud)) return false; // token không auditor, hoặc người gửi bỏ auditor (Z12)
             (l.k, l.m, l.b) = (ya, l.cAud, l.dOut);
         }
-        bytes memory pre = abi.encodePacked(DISCLOSE_TAG, block.chainid, token, entryRef, index, amount, uint8(kind));
+        bytes memory pre = abi.encodePacked(
+            DISCLOSE_TAG, block.chainid, IMetaTx(token).chainUid(), token, entryRef, index, amount, uint8(kind)
+        );
         return _chaumPedersen(l, pre, amount, opening);
     }
 
@@ -71,7 +74,7 @@ contract ZetherDisclosure is ITransferDisclosure {
     }
 
     /// @dev `[z]G − A1 − [e]K == O` và `[z]B − A2 − [e]M + [e·amount]G == O`,
-    ///      `e = H(DISCLOSE_TAG ‖ chainid ‖ token ‖ entryRef ‖ index ‖ amount ‖ kind ‖ A1 ‖ A2)`.
+    ///      `e = H(DISCLOSE_TAG ‖ chainid ‖ chainUid ‖ token ‖ entryRef ‖ index ‖ amount ‖ kind ‖ A1 ‖ A2)` (CTR-ZTH-36).
     function _chaumPedersen(Leg memory l, bytes memory pre, uint256 amount, bytes calldata opening)
         private view returns (bool)
     {
diff --git a/smartcontracts/evm/src/zether/ZetherVerifier.sol b/smartcontracts/evm/src/zether/ZetherVerifier.sol
index 72a35a7..40d58c5 100644
--- a/smartcontracts/evm/src/zether/ZetherVerifier.sol
+++ b/smartcontracts/evm/src/zether/ZetherVerifier.sol
@@ -24,7 +24,10 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
     uint256 internal constant MAX_RECIPIENTS = 16;
     uint256 internal constant NV = 64; // limits D1 (RS-NV64-1)
     uint256 internal constant NB = 64;
-    uint256 internal constant HEADER = 384;
+    /// @dev Statement header (zether.md §7): 13 words, `chainUid` the 4th (CTR-ZTH-36); `fee` and `amount` are read here.
+    uint256 internal constant HEADER = 416;
+    uint256 internal constant FEE_AT = 288;
+    uint256 internal constant AMOUNT_AT = 352;
     uint256 internal constant NGEN = 130; // h, U, G_0..63, H_0..63
 
     address public immutable generatorStore;
@@ -177,7 +180,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
         (x.st, x.c) = T.challenge(x.st, "sigma.c", x.r);
     }
 
-    /// @dev Điểm thứ `i` của phần điểm statement (sau header 384 byte).
+    /// @dev Điểm thứ `i` của phần điểm statement (sau header 416 byte).
     function _sp(Ctx memory x, uint256 i) private pure returns (bytes memory) {
         return _slice(x.s, HEADER + i * x.p, x.p);
     }
@@ -218,7 +221,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
         // E5  [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal
         {
             uint256[] memory sc = new uint256[](6);
-            sc[0] = addmod(z[3], mulmod(x.c, _word(x.s, 256), r), r);
+            sc[0] = addmod(z[3], mulmod(x.c, _word(x.s, FEE_AT), r), r);
             sc[1] = z[0];
             sc[2] = _negS(z[0], r);
             sc[3] = nc;
@@ -265,7 +268,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
         // E5  [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal
         {
             uint256[] memory sc = new uint256[](6);
-            sc[0] = addmod(z[2], mulmod(x.c, _word(x.s, 256), r), r);
+            sc[0] = addmod(z[2], mulmod(x.c, _word(x.s, FEE_AT), r), r);
             sc[1] = z[0];
             sc[2] = _negS(z[0], r);
             sc[3] = nc;
@@ -341,7 +344,7 @@ abstract contract ZetherVerifierBase is IZetherVerifier {
         // E1  [z_x]G − [c]Y_f − A_y
         if (!_z3([g, _sp(x, 0), _pf(x, 1)], [z[0], nc, r - 1])) return false;
         // E5  [z_b + c·(amount + fee)]G + [z_x]D_acc − [c]C_acc − A_bal
-        uint256 debit = addmod(_word(x.s, 320), _word(x.s, 256), r);
+        uint256 debit = addmod(_word(x.s, AMOUNT_AT), _word(x.s, FEE_AT), r);
         if (!_z4([g, _sp(x, 2), _sp(x, 1), _pf(x, 2)], [addmod(z[1], mulmod(x.c, debit, r), r), z[0], nc, r - 1])) {
             return false;
         }
```

- [ ] **Step 4: the Solidity tests of the primitives** — the test prover's header, the hand-built verifier headers (13
  words) and two CTR-ZTH-22 tests (`D_out = O`; a BLS point outside the subgroup), the S3 vector checks (word 3, the new
  `entryRef` and challenge, `directCalldata` instead of `opData`):

```diff
diff --git a/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol b/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
index 5fa9305..cf516b3 100644
--- a/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherS3Vectors.t.sol
@@ -6,8 +6,6 @@ import {stdJson} from "forge-std/StdJson.sol";
 import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
 import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
 import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
-import {ZetherToken} from "../../src/zether/ZetherToken.sol";
-import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
 
 /// @notice Proof do prover Rust của luồng S3 (`r3-zether-prover`, chép vào `test/vectors/zether/s3/`) —
 ///         một hiện thực ĐỘC LẬP của đặc tả. Đúng thì qua verifier Solidity; lật bất kỳ bit nào thì không.
@@ -55,14 +53,15 @@ contract ZetherS3VectorsTest is Test {
         for (uint256 k = 1; k <= 7; ++k) {
             assertFalse(_ok(v, st, _flip(pr, (pr.length * k) / 8 - 1), op), "tampered proof accepted");
         }
-        uint256[5] memory fields = [uint256(95), 191, 223, 255, 287]; // chainId, binding, sendCounter, accSeq, fee
-        for (uint256 k; k < 5; ++k) {
+        // chainId, chainUid, binding, sendCounter, accSeq, fee
+        uint256[6] memory fields = [uint256(95), 127, 223, 255, 287, 319];
+        for (uint256 k; k < 6; ++k) {
             assertFalse(_ok(v, _flip(st, fields[k]), pr, op), "tampered statement accepted");
         }
         if (op == Op.MULTI) {
             // every leg point of the statement is bound; so is the mode (opTag)
             for (uint256 k = 1; k <= 5; ++k) {
-                assertFalse(_ok(v, _flip(st, st.length - (st.length - 384) * k / 6), pr, op), "tampered leg accepted");
+                assertFalse(_ok(v, _flip(st, st.length - (st.length - 416) * k / 6), pr, op), "tampered leg accepted");
             }
             assertFalse(_ok(v, _flip(st, 31), pr, op), "mode switch accepted");
         }
@@ -93,35 +92,36 @@ contract ZetherS3VectorsTest is Test {
         assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE"));
     }
 
-    /// Header statement của S3 đúng bố cục §6 với các trường của `request`.
+    /// Header statement của S3 đúng bố cục zether.md §7 (416 byte, `chainUid` là word 3) với các trường của `request`.
     function test_s3StatementHeaderMatchesRequest() public view {
         string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
         bytes memory st = j.readBytes(".statement");
-        (bytes32 op, bytes32 psid, uint256 chainId, address token, bytes32 tag, bytes32 binding) =
-            abi.decode(_head(st, 0), (bytes32, bytes32, uint256, address, bytes32, bytes32));
+        (bytes32 op, bytes32 psid, uint256 chainId, bytes32 uid, address token, bytes32 tag) =
+            abi.decode(_head(st, 0), (bytes32, bytes32, uint256, bytes32, address, bytes32));
         assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"));
         assertEq(psid, bn.proofSystemId());
         assertEq(chainId, j.readUint(".request.chainId"));
+        assertEq(uid, j.readBytes32(".request.chainUid"));
         assertEq(token, j.readAddress(".request.token"));
         assertEq(tag, keccak256("ZTX_V1_RELAYED"));
-        assertEq(binding, j.readBytes32(".request.envelopeBinding"));
+        assertEq(bytes32(_head(st, 192)), j.readBytes32(".request.envelopeBinding"));
     }
 
     function test_s3StatementCountersAndEntryRef() public view {
         string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
         bytes memory st = j.readBytes(".statement");
         (uint256 sc, uint256 accSeq, uint256 fee, bytes32 ben,,) =
-            abi.decode(_head(st, 192), (uint256, uint256, uint256, bytes32, uint256, address));
+            abi.decode(_head(st, 224), (uint256, uint256, uint256, bytes32, uint256, address));
         assertEq(sc, j.readUint(".request.sendCounter"));
         assertEq(accSeq, j.readUint(".request.accSeq"));
         assertEq(fee, j.readUint(".request.fee"));
         assertEq(ben, j.readBytes32(".request.beneficiary"));
-        // entryRef §10 = keccak(tag, chainId, token, keccak(Y_f), sendCounter)
+        // entryRef (CTR-ZTH-36) = keccak(tag, chainId, chainUid, token, keccak(Y_f), sendCounter)
         bytes memory yf = new bytes(64);
-        for (uint256 i; i < 64; ++i) yf[i] = st[384 + i];
+        for (uint256 i; i < 64; ++i) yf[i] = st[416 + i];
         assertEq(
             keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), j.readUint(".request.chainId"),
-                j.readAddress(".request.token"), keccak256(yf), sc)),
+                j.readBytes32(".request.chainUid"), j.readAddress(".request.token"), keccak256(yf), sc)),
             j.readBytes32(".entryRef")
         );
     }
@@ -131,12 +131,12 @@ contract ZetherS3VectorsTest is Test {
         for (uint256 i; i < 192; ++i) out[i] = st[off + i];
     }
 
-    /// `opData` của S3 = `OP_ZTRANSFER ‖ abi.encode(payload, proof, authSig, beneficiary)` (§10).
-    function test_s3OpDataMatchesEnvelopeOp() public {
+    /// `directCalldata` = `zetherTransferSingle(payload, proof, authSig, beneficiary)`: the direct call, and unchanged the
+    /// envelope's `data` (CTR-ZTH-34).
+    function test_s3DirectCalldataIsTheEntryPointCall() public view {
         string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
-        bytes memory op = j.readBytes(".opData");
-        ZetherToken impl = new ZetherToken(address(this), new ZetherDisclosure());
-        assertEq(bytes4(op), impl.OP_ZTRANSFER());
+        bytes memory op = j.readBytes(".directCalldata");
+        assertEq(bytes4(op), bytes4(keccak256("zetherTransferSingle(bytes,bytes,bytes,bytes32)")));
         bytes memory args = new bytes(op.length - 4);
         for (uint256 i; i < args.length; ++i) args[i] = op[4 + i];
         (bytes memory pl, bytes memory pr,, bytes32 ben) = abi.decode(args, (bytes, bytes, bytes, bytes32));
@@ -194,11 +194,11 @@ contract ZetherS3VectorsTest is Test {
         return keccak256(v.g1Mul(j.readBytes(string.concat(c, kmb[2])), z)) == keccak256(v.g1Add(a2, v.g1Mul(mMinus, e)));
     }
 
-    /// `e = H(DISCLOSE_TAG ‖ chainid ‖ token ‖ entryRef ‖ j ‖ amount ‖ kind ‖ A1 ‖ A2)`.
+    /// `e = H(DISCLOSE_TAG ‖ chainid ‖ chainUid ‖ token ‖ entryRef ‖ j ‖ amount ‖ kind ‖ A1 ‖ A2)` (CTR-ZTH-36).
     function _e(IZetherVerifier v, string memory j, string memory c, uint256 idx, bytes memory a1a2) internal view returns (uint256) {
         return T.hashToScalar(keccak256(bytes.concat(
             abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", j.readUint(string.concat(c, ".chainId")),
-                j.readAddress(string.concat(c, ".token"))),
+                j.readBytes32(string.concat(c, ".chainUid")), j.readAddress(string.concat(c, ".token"))),
             abi.encodePacked(j.readBytes32(string.concat(c, ".entryRef")), idx, j.readUint(string.concat(c, ".amount")),
                 uint8(j.readUint(string.concat(c, ".kind"))), a1a2)
         )), v.groupOrder());
diff --git a/smartcontracts/evm/test/zether/ZetherVerifier.t.sol b/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
index 74facff..19841b2 100644
--- a/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
+++ b/smartcontracts/evm/test/zether/ZetherVerifier.t.sol
@@ -7,7 +7,8 @@ import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
 import {ZetherProver} from "./helpers/ZetherProver.sol";
 
 /// @notice Verifier đứng một mình: proof đúng qua, mọi thay đổi một bit / một trường / một witness sai
-///         đều bị từ chối. Statement dựng tay theo §6 (token dựng y hệt — xem ZetherToken.t.sol).
+///         đều bị từ chối. Statement dựng tay theo zether.md §7 (header 416 byte, `chainUid` là word 3; token và
+///         `ZetherStatements` dựng y hệt — xem ZetherNone.t.sol).
 contract ZetherVerifierTest is Test {
     bytes32 constant OP_T = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
     bytes32 constant OP_B = keccak256("SCAAS-ZETHER-OP-BURN-V1");
@@ -41,7 +42,7 @@ contract ZetherVerifierTest is Test {
         internal view returns (bytes memory)
     {
         return abi.encode(
-            op, v.proofSystemId(), block.chainid, address(0x70CE), DIRECT, bytes32(0),
+            op, v.proofSystemId(), block.chainid, keccak256("verifier test chain"), address(0x70CE), DIRECT, bytes32(0),
             uint256(7), uint256(3), fee, fee == 0 ? bytes32(0) : bytes32(uint256(0xBE)), amount, recipient
         );
     }
@@ -152,8 +153,8 @@ contract ZetherVerifierTest is Test {
         bytes memory st = _transferStatement(k, k.amount);
         bytes memory pr = _proveTransfer(k, st, k.amount);
         assertTrue(bls.verifyTransfer(st, pr));
-        // chainId, token, bindingTag, binding, sendCounter, accSeq, fee, beneficiary, rồi một bit trong C_acc
-        uint256[9] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 384 + 3 * 128 + 100];
+        // chainId, chainUid, token, bindingTag, binding, sendCounter, accSeq, fee, beneficiary, rồi một bit trong C_acc
+        uint256[10] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 351, 416 + 3 * 128 + 100];
         for (uint256 i; i < offs.length; ++i) {
             bytes memory t = bytes.concat(st);
             t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
@@ -181,7 +182,7 @@ contract ZetherVerifierTest is Test {
         bytes memory st = _transferStatement(k, k.amount);
         bytes memory lie = _cts(Case(bls, 1000, 1, 5, true), 1); // C_aud của v = 1
         uint256 p = 128;
-        for (uint256 i; i < p; ++i) st[384 + 8 * p + i] = lie[3 * p + i];
+        for (uint256 i; i < p; ++i) st[416 + 8 * p + i] = lie[3 * p + i];
         assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
     }
 
@@ -199,10 +200,47 @@ contract ZetherVerifierTest is Test {
         // nhét một C_aud khác O khi auditor tắt
         bytes memory t = bytes.concat(st);
         bytes memory junk = bn.g1MulBase(42);
-        for (uint256 i; i < 64; ++i) t[384 + 8 * 64 + i] = junk[i];
+        for (uint256 i; i < 64; ++i) t[416 + 8 * 64 + i] = junk[i];
         assertFalse(_ok(bn, t, pr, true));
     }
 
+    /// CTR-ZTH-22 (c): `s = 0` gives `D_out = O` and `C_out = [v]G` (the amount in the clear); refused even with an
+    /// otherwise honest proof.
+    function test_dOutIdentityRejected() public view {
+        bytes memory st = _zeroSStatement(bn, 1000, 300, 5);
+        bytes memory pr = prover.proveTransfer(bn, st, ZetherProver.TransferWitness({
+            x: XF, v: 300, s: 0, bPrime: 1000 - 300 - 5, gammaV: 0x77, gammaB: 0x88, seed: keccak256("t")
+        }));
+        assertFalse(_ok(bn, st, pr, true));
+    }
+
+    function _zeroSStatement(IZetherVerifier v, uint256 b, uint256 amount, uint256 fee) internal view returns (bytes memory) {
+        (bytes memory cAcc, bytes memory dAcc) = _acc(v, b);
+        bytes memory head = bytes.concat(
+            _header(v, OP_T, fee, 0, address(0)), v.g1MulBase(XF), v.g1MulBase(XT), v.identity(), cAcc, dAcc
+        );
+        return bytes.concat(head, _zeroSCts(v, amount));
+    }
+
+    function _zeroSCts(IZetherVerifier v, uint256 amount) internal view returns (bytes memory) {
+        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) =
+            prover.ciphertexts(v, v.g1MulBase(XF), v.g1MulBase(XT), v.identity(), amount, 0);
+        require(keccak256(dOut) == keccak256(v.identity()), "D_out = O");
+        return bytes.concat(cOut, dOut, cDeb, cAud);
+    }
+
+    /// CTR-ZTH-22 (b): a BLS12-381 point on the curve but outside the subgroup in the statement is refused (the MSM
+    /// precompile checks the subgroup).
+    function test_blsNonSubgroupPointRejected() public view {
+        Case memory k = Case(bls, 1000, 300, 5, true);
+        bytes memory st = _transferStatement(k, k.amount);
+        bytes memory pr = _proveTransfer(k, st, k.amount);
+        assertTrue(_ok(bls, st, pr, true));
+        bytes memory bad = vm.parseJsonBytes(vm.readFile("test/vectors/zether/curve_misc.json"), ".blsNonSubgroup");
+        for (uint256 i; i < 128; ++i) st[416 + 5 * 128 + i] = bad[i]; // C_out
+        assertFalse(_ok(bls, st, pr, true));
+    }
+
     function test_nonCanonicalScalarRejected() public view {
         Case memory k = Case(bn, 1000, 300, 5, false);
         bytes memory st = _transferStatement(k, k.amount);
diff --git a/smartcontracts/evm/test/zether/helpers/ZetherProver.sol b/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
index 943a583..d8dbd40 100644
--- a/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
+++ b/smartcontracts/evm/test/zether/helpers/ZetherProver.sol
@@ -31,7 +31,7 @@ contract ZetherProver {
         bytes32 seed;
     }
 
-    uint256 constant HEADER = 384;
+    uint256 constant HEADER = 416; // zether.md §7: chainUid is word 3
 
     function _env(IZetherVerifier v, bytes32 seed) internal view returns (Env memory e) {
         e.v = v;
```

- [ ] **Step 5: the Rust prover** (`clients/zether-prover`; reference values from `tools/env_ref.sh`, run with `cast`):

```diff
diff --git a/clients/zether-prover/smoke/smoke.cjs b/clients/zether-prover/smoke/smoke.cjs
index 5d4f269..63aa25c 100644
--- a/clients/zether-prover/smoke/smoke.cjs
+++ b/clients/zether-prover/smoke/smoke.cjs
@@ -35,7 +35,7 @@ for (const curve of ["bn254", "bls12381"]) {
 
   const t0 = Date.now();
   const tx = call("proveTransfer", {
-    curve, key: k0, chainId: 31337, token, sendCounter: 0, accSeq: 1, acc, balance: 50000,
+    curve, key: k0, chainId: 31337, chainUid: "0x" + "24".repeat(32), token, sendCounter: 0, accSeq: 1, acc, balance: 50000,
     yTo: to.Y, amount: 1234, fee: 10, beneficiary: "0x" + "22".repeat(32),
   });
   const ms = Date.now() - t0;
diff --git a/clients/zether-prover/src/api.rs b/clients/zether-prover/src/api.rs
index edb5a85..d6ff2a2 100644
--- a/clients/zether-prover/src/api.rs
+++ b/clients/zether-prover/src/api.rs
@@ -129,14 +129,19 @@ fn ct_json<C: ZCurve>(c: &Ciphertext<C>) -> Value {
     json!({"C": hx(&encode_point::<C>(&c.c)), "D": hx(&encode_point::<C>(&c.d))})
 }
 
+/// `envelopeBinding` (relayed), else `unwrapBinding` (a direct `zetherUnshieldUnwrap`), else direct.
 fn header(v: &Value, amount: u64, recipient: [u8; 20]) -> R<Header> {
-    let binding = if v.get("envelopeBinding").is_some_and(|x| !x.is_null()) {
+    let has = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
+    let binding = if has("envelopeBinding") {
         Binding::Relayed(fixed(v, "envelopeBinding")?)
+    } else if has("unwrapBinding") {
+        Binding::Unwrap(fixed(v, "unwrapBinding")?)
     } else {
         Binding::Direct
     };
     Ok(Header {
         chain_id: num(v, "chainId")?,
+        chain_uid: fixed(v, "chainUid")?,
         token: fixed(v, "token")?,
         binding,
         send_counter: num(v, "sendCounter")?,
@@ -158,31 +163,16 @@ fn sc<C: ZCurve>(s: &Fr<C>) -> String {
     hx(&encode_scalar::<C>(s))
 }
 
-/// `transferConfidentialSingle(bytes,bytes,bytes,bytes32)` — direct call has no outer fee (S2 RS2-14).
-fn direct_transfer(payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
-    direct_call("transferConfidentialSingle(bytes,bytes,bytes,bytes32)", payload, proof, beneficiary)
-}
-
-/// `transferConfidential` (HASH), `transferConfidentialBundle`, `transferConfidentialNoBundle`.
-fn direct_transfer_multi(mode: TransferMode, payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
-    let f = match mode {
-        TransferMode::Hash => "transferConfidential(bytes,bytes,bytes,bytes32)",
-        TransferMode::Bundle => "transferConfidentialBundle(bytes,bytes,bytes,bytes32)",
-        TransferMode::NoBundle => "transferConfidentialNoBundle(bytes,bytes,bytes,bytes32)",
-    };
-    direct_call(f, payload, proof, beneficiary)
-}
+/// `zetherTransferSingle` — a direct call has no outer fee; relayed, the same bytes are the envelope's `data`.
+const TRANSFER_SINGLE: &str = "zetherTransferSingle(bytes,bytes,bytes,bytes32)";
 
-fn direct_call(sig: &str, payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
-    let mut d = envelope::selector(sig).to_vec();
-    d.extend_from_slice(&envelope::transfer_data(payload, proof, &[], beneficiary)[4..]);
-    d
-}
-
-fn direct_burn(payload: &[u8], amount: u64, recipient: &[u8; 20], beneficiary: &[u8; 32], proof: &[u8]) -> Vec<u8> {
-    let mut d = envelope::selector("burn(bytes,uint256,address,bytes32,bytes,bytes)").to_vec();
-    d.extend_from_slice(&envelope::burn_data(payload, amount, recipient, beneficiary, proof, &[])[4..]);
-    d
+/// `zetherTransfer` (HASH), `zetherTransferBundle`, `zetherTransferNoBundle` (CTR-ZTH-38).
+fn transfer_multi_sig(mode: TransferMode) -> &'static str {
+    match mode {
+        TransferMode::Hash => "zetherTransfer(bytes,bytes,bytes,bytes32)",
+        TransferMode::Bundle => "zetherTransferBundle(bytes,bytes,bytes,bytes32)",
+        TransferMode::NoBundle => "zetherTransferNoBundle(bytes,bytes,bytes,bytes32)",
+    }
 }
 
 pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
@@ -208,9 +198,8 @@ pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v
         "proof": hx(&proof),
         "payload": hx(&payload),
         "authDigest": hx(&zether::auth_digest(&stmt)),
-        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.token, &k.ua(), h.send_counter)),
-        "opData": hx(&envelope::transfer_data(&payload, &proof, &[], &h.beneficiary)),
-        "directCalldata": hx(&direct_transfer(&payload, &proof, &h.beneficiary)),
+        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
+        "directCalldata": hx(&envelope::transfer_call(TRANSFER_SINGLE, &payload, &proof, &[], &h.beneficiary)),
     });
     if include_witness(v) {
         out["witness"] = json!({"x": sc::<C>(&w.x), "v": sc::<C>(&w.v), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b),
@@ -222,13 +211,10 @@ pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v
 /// `recipients`: `[{"yTo", "amount"}, …]` (decoys with amount 0), `mode`: `hash` (default) | `bundle` | `none`.
 /// `yAud` absent or null leaves the auditor out (statement `Y_a = O`, every `C_aud = O`): required on a token
 /// without auditor, the sender's choice on one with it (Z12); the same holds for `proveTransfer`.
-/// Direct calls only: the meta-tx envelope carries single-recipient transfers (stream MT-6).
+/// Relayed like the single format (`envelopeBinding`, CTR-ZTH-34).
 pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
     let k = key::<C>(v)?;
     let h = header(v, 0, [0; 20])?;
-    if h.binding != Binding::Direct {
-        return Err("multi-recipient transfers are direct calls only (no envelopeBinding)".into());
-    }
     let mode = match v.get("mode").filter(|x| !x.is_null()) {
         None => TransferMode::Hash,
         Some(m) => m.as_str().and_then(TransferMode::from_name).ok_or("`mode` must be \"hash\", \"bundle\" or \"none\"")?,
@@ -253,8 +239,8 @@ pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens
         "payload": hx(&payload),
         "bundles": hx(&st.bundles()),
         "authDigest": hx(&zether::auth_digest(&stmt)),
-        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.token, &k.ua(), h.send_counter)),
-        "directCalldata": hx(&direct_transfer_multi(mode, &payload, &proof, &h.beneficiary)),
+        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
+        "directCalldata": hx(&envelope::transfer_call(transfer_multi_sig(mode), &payload, &proof, &[], &h.beneficiary)),
     });
     if include_witness(v) {
         out["witness"] = json!({"x": sc::<C>(&w.x), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b), "bPrime": sc::<C>(&w.b_prime),
@@ -278,8 +264,7 @@ pub fn prove_burn_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &V
         "proof": hx(&proof),
         "payload": hx(&payload),
         "authDigest": hx(&zether::auth_digest(&stmt)),
-        "opData": hx(&envelope::burn_data(&payload, amount, &recipient, &h.beneficiary, &proof, &[])),
-        "directCalldata": hx(&direct_burn(&payload, amount, &recipient, &h.beneficiary, &proof)),
+        "directCalldata": hx(&envelope::unshield_call(&payload, &proof, &[], &h.beneficiary, &recipient, amount)),
     });
     if include_witness(v) {
         out["witness"] = json!({"x": sc::<C>(&w.x), "b": sc::<C>(&w.b), "amount": amount.to_string(),
@@ -318,8 +303,6 @@ fn meta(v: &Value) -> R<MetaTx> {
     let m = get(v, "meta")?;
     Ok(MetaTx {
         from: fixed(m, "from")?,
-        to: opt_fixed(m, "to")?,
-        value: opt_num(m, "value")? as u128,
         data: if m.get("data").is_some() { bytes(m, "data")? } else { vec![] },
         batch: fixed(m, "batch")?,
         nonce: num(m, "nonce")?,
@@ -389,8 +372,8 @@ fn by_curve<C: ZCurve>(cmd: &str, v: &Value, rng: &mut OsRng) -> R<Value> {
                 "popSignature": hx(&schnorr::pop_signature(&pop, &[])),
             }))
         }
-        "fundCalldata" => {
-            let mut d = envelope::selector("fund(bytes,uint256)").to_vec();
+        "shieldCalldata" => {
+            let mut d = envelope::selector("zetherShield(bytes,uint256)").to_vec();
             d.extend(abi::encode(&[Tok::Bytes(encode_point::<C>(&point::<C>(v, "Y")?)), Tok::Word(abi::u256(num(v, "amount")?))]));
             Ok(json!({"calldata": hx(&d)}))
         }
@@ -403,10 +386,10 @@ pub fn call(cmd: &str, input: &str) -> R<String> {
     let v: Value = serde_json::from_str(input).map_err(e)?;
     let out = match cmd {
         "envelope" => {
-            let (chain, token) = (num(&v, "chainId")?, fixed::<20>(&v, "token")?);
+            let (chain, uid, token) = (num(&v, "chainId")?, fixed::<32>(&v, "chainUid")?, fixed::<20>(&v, "token")?);
             let m = meta(&v)?;
-            json!({"binding": hx(&envelope::envelope_binding(chain, &token, &m)),
-                   "digest": hx(&envelope::digest(chain, &token, &m))})
+            json!({"binding": hx(&envelope::envelope_binding(chain, &uid, &token, &m)),
+                   "digest": hx(&envelope::digest(chain, &uid, &token, &m))})
         }
         _ => match get(&v, "curve")?.as_str() {
             Some("bn254") => by_curve::<Bn254>(cmd, &v, &mut OsRng)?,
diff --git a/clients/zether-prover/src/bin/zether-cli.rs b/clients/zether-prover/src/bin/zether-cli.rs
index f8cfac0..2bbff3c 100644
--- a/clients/zether-prover/src/bin/zether-cli.rs
+++ b/clients/zether-prover/src/bin/zether-cli.rs
@@ -4,7 +4,7 @@
 //!   zether-cli <command>          JSON request on stdin, JSON result on stdout
 //!
 //! Commands: keygen, encrypt, decrypt, proveTransfer, verifyTransfer, proveBurn, verifyBurn,
-//! pop, fundCalldata, envelope (see `zether_prover::api`).
+//! pop, shieldCalldata, envelope (see `zether_prover::api`).
 
 use std::io::Read;
 use std::process::ExitCode;
diff --git a/clients/zether-prover/src/envelope.rs b/clients/zether-prover/src/envelope.rs
index ed262ee..6e46dc3 100644
--- a/clients/zether-prover/src/envelope.rs
+++ b/clients/zether-prover/src/envelope.rs
@@ -1,9 +1,9 @@
-//! Meta-tx envelope for Zether ops (zether-design §10): `envelopeBinding`, the EIP-712
-//! digest the subject signs (`MetaTxLib`, domain `("SCaaS ZetherToken", "1", chainId, token)`),
-//! and the op calldata carried in `m.data`.
+//! Relaying a Zether op through the token's one meta-transaction base (zether.md §12, CTR-ZTH-34): the subject signs a
+//! `MetaTransaction` whose `data` is the real calldata of an allowlisted Zether function, in the token's salted domain
+//! `("SCaaS ZetherToken", "1", chainId, token, chainUid)`; the proof binds the envelope through `envelopeBinding`.
 //!
 //! Relayed flow: build `m` without data → `binding = envelope_binding(m)` → prove with
-//! `Binding::Relayed(binding)` → `m.data = transfer_data(...)` → sign `digest(m)`.
+//! `Binding::Relayed(binding)` → `m.data = transfer_call(...)` → sign `digest(m)`.
 
 use crate::abi::{self, Tok};
 use crate::curve::keccak256;
@@ -13,16 +13,14 @@ pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
 pub const MODE_FEE_NONE: u32 = 0x00;
 pub const MODE_FEE_FIXED: u32 = 0x20;
 
-pub const METATX_TYPE: &str = "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
+pub const METATX_TYPE: &str = "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
 
-/// `MetaTxLib.MetaTransaction`.
+/// `MetaTxLib.MetaTransaction` (CTR-MTX-15): no `to`, no `value`.
 #[derive(Clone, Debug, PartialEq, Eq)]
 pub struct MetaTx {
     pub from: [u8; 20],
-    pub to: [u8; 20],
-    pub value: u128,
     pub data: Vec<u8>,
-    /// 2D-nonce lane (R9: random per `entryRef`, chosen by the client).
+    /// 2D-nonce lane (random per `entryRef`, chosen by the client).
     pub batch: [u8; 32],
     pub nonce: u64,
     pub valid_until: u64,
@@ -52,8 +50,6 @@ impl MetaTx {
             &[
                 keccak256(METATX_TYPE.as_bytes()),
                 abi::addr(&self.from),
-                abi::addr(&self.to),
-                u128w(self.value),
                 keccak256(&self.data),
                 self.batch,
                 abi::u256(self.nonce),
@@ -68,38 +64,39 @@ impl MetaTx {
     }
 }
 
-pub fn domain_separator(chain_id: u64, token: &[u8; 20]) -> [u8; 32] {
+/// The token's salted EIP-712 domain (CTR-MTX-02, CTR-GEN-05).
+pub fn domain_separator(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20]) -> [u8; 32] {
     keccak256(
         &[
-            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
+            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
             keccak256(b"SCaaS ZetherToken"),
             keccak256(b"1"),
             abi::u256(chain_id),
             abi::addr(token),
+            *chain_uid,
         ]
         .concat(),
     )
 }
 
-/// EIP-712 digest the subject's signing key signs.
-pub fn digest(chain_id: u64, token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
+/// EIP-712 digest the subject's signing key signs (`mtxDigest(m)` on the token).
+pub fn digest(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
     let mut b = vec![0x19, 0x01];
-    b.extend(domain_separator(chain_id, token));
+    b.extend(domain_separator(chain_id, chain_uid, token));
     b.extend(m.struct_hash());
     keccak256(&b)
 }
 
-/// `envelopeBinding` (§10) — every envelope field except `data`.
-pub fn envelope_binding(chain_id: u64, token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
+/// `envelopeBinding` (CTR-ZTH-06) — every envelope field except `data`, plus `chainUid`.
+pub fn envelope_binding(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
     let (r, f) = m.canon();
     keccak256(
         &[
             keccak256(b"SCAAS-ZETHER-ENVELOPE-V1"),
             abi::u256(chain_id),
+            *chain_uid,
             abi::addr(token),
             abi::addr(&m.from),
-            abi::addr(&m.to),
-            u128w(m.value),
             m.batch,
             abi::u256(m.nonce),
             abi::u256(m.valid_until),
@@ -112,13 +109,20 @@ pub fn envelope_binding(chain_id: u64, token: &[u8; 20], m: &MetaTx) -> [u8; 32]
     )
 }
 
+/// The binding word of a direct `zetherUnshieldUnwrap` (under `ZTX_V1_DIRECT`): its leg and `minOut` (`min_out` as
+/// the 32-byte ABI word). Controller ruling, pending the owner.
+pub fn unwrap_binding(underlying: &[u8; 20], min_out: &[u8; 32]) -> [u8; 32] {
+    keccak256(&[keccak256(b"SCAAS-ZETHER-UNWRAP-V1"), abi::addr(underlying), *min_out].concat())
+}
+
 pub fn selector(sig: &str) -> [u8; 4] {
     keccak256(sig.as_bytes())[..4].try_into().unwrap()
 }
 
-/// `m.data` for `OP_ZTRANSFER`: `op ‖ abi.encode(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`.
-pub fn transfer_data(payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
-    let mut d = selector("zetherTransfer(bytes,bytes,bytes,bytes32)").to_vec();
+/// Calldata of a confidential transfer (`zetherTransfer`, `…Bundle`, `…NoBundle`, `…Single`, all
+/// `(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`): the direct call and, unchanged, the envelope's `data`.
+pub fn transfer_call(sig: &str, payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
+    let mut d = selector(sig).to_vec();
     d.extend(abi::encode(&[
         Tok::Bytes(payload.to_vec()),
         Tok::Bytes(proof.to_vec()),
@@ -128,24 +132,23 @@ pub fn transfer_data(payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary:
     d
 }
 
-/// `m.data` for `OP_ZBURN`: `op ‖ abi.encode(bytes payload, uint256 amount, address recipient,
-/// bytes32 beneficiary, bytes proof, bytes authSig)`.
-pub fn burn_data(
+/// `zetherUnshield(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary, address to, uint256 amount)`.
+pub fn unshield_call(
     payload: &[u8],
-    amount: u64,
-    recipient: &[u8; 20],
-    beneficiary: &[u8; 32],
     proof: &[u8],
     auth_sig: &[u8],
+    beneficiary: &[u8; 32],
+    to: &[u8; 20],
+    amount: u64,
 ) -> Vec<u8> {
-    let mut d = selector("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)").to_vec();
+    let mut d = selector("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)").to_vec();
     d.extend(abi::encode(&[
         Tok::Bytes(payload.to_vec()),
-        Tok::Word(abi::u256(amount)),
-        Tok::Word(abi::addr(recipient)),
-        Tok::Word(*beneficiary),
         Tok::Bytes(proof.to_vec()),
         Tok::Bytes(auth_sig.to_vec()),
+        Tok::Word(*beneficiary),
+        Tok::Word(abi::addr(to)),
+        Tok::Word(abi::u256(amount)),
     ]));
     d
 }
diff --git a/clients/zether-prover/src/schnorr.rs b/clients/zether-prover/src/schnorr.rs
index 1957a3f..16cc0e6 100644
--- a/clients/zether-prover/src/schnorr.rs
+++ b/clients/zether-prover/src/schnorr.rs
@@ -99,11 +99,18 @@ pub enum OpeningKind {
     SenderCp = 3,
 }
 
-/// `entryRef = keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), chainid, token, fromUA, sendCounter))`.
-pub fn entry_ref(chain_id: u64, token: &[u8; 20], from_ua: &[u8; 32], send_counter: u64) -> [u8; 32] {
+/// `entryRef = keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), chainid, chainUid, token, fromUA, sendCounter))`.
+pub fn entry_ref(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], from_ua: &[u8; 32], send_counter: u64) -> [u8; 32] {
     keccak256(
-        &[keccak256(b"SCAAS-ZETHER-ENTRY-V1"), abi::u256(chain_id), abi::addr(token), *from_ua, abi::u256(send_counter)]
-            .concat(),
+        &[
+            keccak256(b"SCAAS-ZETHER-ENTRY-V1"),
+            abi::u256(chain_id),
+            *chain_uid,
+            abi::addr(token),
+            *from_ua,
+            abi::u256(send_counter),
+        ]
+        .concat(),
     )
 }
 
@@ -111,6 +118,7 @@ pub fn entry_ref(chain_id: u64, token: &[u8; 20], from_ua: &[u8; 32], send_count
 /// (`B_j = Y_t ‖ C_out ‖ D_out ‖ C_aud`; a single-recipient transfer has `index = 0`).
 pub struct Entry<C: ZCurve> {
     pub chain_id: u64,
+    pub chain_uid: [u8; 32],
     pub token: [u8; 20],
     pub entry_ref: [u8; 32],
     pub index: u64,
@@ -130,6 +138,7 @@ pub fn open_sender<C: ZCurve>(s: &Fr<C>) -> Vec<u8> {
 fn cp_prefix<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind) -> Vec<u8> {
     let mut b = b"SCAAS-ZETHER-DISCLOSE-V1".to_vec();
     b.extend(abi::u256(e.chain_id));
+    b.extend_from_slice(&e.chain_uid);
     b.extend_from_slice(&e.token);
     b.extend_from_slice(&e.entry_ref);
     b.extend(abi::u256(e.index));
diff --git a/clients/zether-prover/src/vectors.rs b/clients/zether-prover/src/vectors.rs
index c3eddc9..edabb53 100644
--- a/clients/zether-prover/src/vectors.rs
+++ b/clients/zether-prover/src/vectors.rs
@@ -19,6 +19,8 @@ use crate::zether::{self, BurnProof, BurnStatement, MultiTransferStatement, Tran
 pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
 const CHAIN: u64 = 31337;
+/// `chainUid` of the vectors (the forge tests' `UID_`): every chain-bound digest carries it (CTR-ZTH-36).
+const CHAIN_UID: &str = "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464";
 const TOKEN: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
 /// > 2^44 and a transfer > 2^32 (limits D1/D5): the Solidity side checks both through these files.
 const BAL: u64 = (1 << 44) + 1_000_000;
@@ -69,7 +71,7 @@ fn per_curve<C: ZCurve>(files: &mut Vec<(String, Value)>, transcripts: &mut Vec<
     let acc = encrypt(&from.y, BAL, &Fr::<C>::from(0x1234_5678_9abc_def0u64));
     let acc_j = json!({"C": hx(&encode_point::<C>(&acc.c)), "D": hx(&encode_point::<C>(&acc.d))});
     let base = json!({
-        "curve": C::NAME, "key": key_json(0, USE_CONF), "chainId": CHAIN, "token": TOKEN,
+        "curve": C::NAME, "key": key_json(0, USE_CONF), "chainId": CHAIN, "chainUid": CHAIN_UID, "token": TOKEN,
         "sendCounter": 3, "accSeq": 5, "acc": acc_j, "balance": BAL, "includeWitness": true,
     });
     let with = |extra: Value| {
@@ -97,11 +99,13 @@ fn per_curve<C: ZCurve>(files: &mut Vec<(String, Value)>, transcripts: &mut Vec<
     // RNG so the files after this one keep their bytes.
     let s = decode_scalar::<C>(&hex::decode(&tv["witness"]["s"].as_str().unwrap()[2..]).unwrap()).unwrap();
     let token: [u8; 20] = hex::decode(&TOKEN[2..]).unwrap().try_into().unwrap();
+    let uid: [u8; 32] = hex::decode(&CHAIN_UID[2..]).unwrap().try_into().unwrap();
     let mut cp_rng = ChaCha20Rng::seed_from_u64(0x5e9d_e7c9);
     let e = Entry {
         chain_id: CHAIN,
+        chain_uid: uid,
         token,
-        entry_ref: entry_ref(CHAIN, &token, &from.ua(), 3),
+        entry_ref: entry_ref(CHAIN, &uid, &token, &from.ua(), 3),
         index: 0,
         y_t: st.y_t,
         c_out: st.c_out,
@@ -173,8 +177,9 @@ fn per_curve<C: ZCurve>(files: &mut Vec<(String, Value)>, transcripts: &mut Vec<
     let leg = &st.legs[1];
     let e = Entry {
         chain_id: CHAIN,
+        chain_uid: uid,
         token,
-        entry_ref: entry_ref(CHAIN, &token, &from.ua(), 3),
+        entry_ref: entry_ref(CHAIN, &uid, &token, &from.ua(), 3),
         index: 1,
         y_t: leg.y_t,
         c_out: leg.c_out,
@@ -206,7 +211,8 @@ fn disclosure_cases<C: ZCurve>(e: &Entry<C>, amount: u64, openings: &[(OpeningKi
         .map(|(kind, opening)| {
             schnorr::verify_opening(e, amount, *kind, opening).unwrap();
             json!({
-                "entryRef": hx(&e.entry_ref), "chainId": CHAIN, "token": TOKEN, "index": e.index, "amount": amount,
+                "entryRef": hx(&e.entry_ref), "chainId": CHAIN, "chainUid": CHAIN_UID, "token": TOKEN, "index": e.index,
+                "amount": amount,
                 "kind": *kind as u8, "Yt": hx(&encode_point::<C>(&e.y_t)), "Cout": hx(&encode_point::<C>(&e.c_out)),
                 "Dout": hx(&encode_point::<C>(&e.d_out)), "Ya": hx(&encode_point::<C>(&e.y_a)),
                 "Caud": hx(&encode_point::<C>(&e.c_aud)), "opening": hx(opening), "expect": true,
@@ -325,5 +331,21 @@ pub fn generate() -> Vec<(String, Value)> {
         }),
     ));
     files.push(("r33_inputs.json".into(), r33_inputs()));
+    files.push(("envelope.json".into(), envelope_vector()));
     files
 }
+
+/// A relayed `zetherTransfer` envelope (CTR-ZTH-34): its binding and digest through the JSON API, for the forge KAT.
+fn envelope_vector() -> Value {
+    let mut req = json!({
+        "chainId": CHAIN, "chainUid": CHAIN_UID, "token": TOKEN,
+        "meta": {"from": "0x".to_string() + &"aa".repeat(20), "data": "0xdeadbeef",
+                 "batch": "0x".to_string() + &"01".repeat(32), "nonce": 7, "validUntil": 1_800_000_000u64,
+                 "mode": 0x21, "relayer": "0x".to_string() + &"bb".repeat(20), "fee": 1000,
+                 "feeRecipient": "0x".to_string() + &"cc".repeat(20)},
+    });
+    let out: Value = serde_json::from_str(&crate::api::call("envelope", &req.to_string()).unwrap()).unwrap();
+    req["binding"] = out["binding"].clone();
+    req["digest"] = out["digest"].clone();
+    req
+}
diff --git a/clients/zether-prover/src/zether.rs b/clients/zether-prover/src/zether.rs
index 5c4017e..903f389 100644
--- a/clients/zether-prover/src/zether.rs
+++ b/clients/zether-prover/src/zether.rs
@@ -1,5 +1,5 @@
 //! Statements, Σ-protocol and proofs for `transfer` and `burn`, byte-exact per zether-design
-//! §6 (statement), §7 (Σ), §8 (Bulletproofs), §9 (wire + payload). `fund` carries no proof
+//! §6 (statement), §7 (Σ), §8 (Bulletproofs), §9 (wire + payload). `zetherShield` carries no proof
 //! (public amount, §5). The verifier here mirrors the Solidity verifier for tests/vectors.
 
 use ark_ff::{PrimeField, Zero};
@@ -22,7 +22,7 @@ use crate::ZError;
 /// soundness comes from `MAX_TOTAL_SHIELDED` instead (zether-design ruling RS-NV64-1).
 pub const N_V: usize = 64;
 pub const N_B: usize = 64;
-pub const HEADER_LEN: usize = 384;
+pub const HEADER_LEN: usize = 416;
 /// `MAX_TOTAL_SHIELDED` (§1): ceiling of `maxDecryptableShielded`.
 pub const MAX_TOTAL_SHIELDED: u64 = 1 << 54;
 
@@ -39,19 +39,24 @@ pub fn op_tag_burn() -> [u8; 32] {
     keccak256(b"SCAAS-ZETHER-OP-BURN-V1")
 }
 
-/// `bindingTag` + `envelopeBinding` (§6, §10).
+/// `bindingTag` + `envelopeBinding` (zether.md §7, §12).
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum Binding {
     /// `ZTX_V1_DIRECT`, binding 0: the subject calls the token itself.
     Direct,
     /// `ZTX_V1_RELAYED` with `envelopeBinding` from [`crate::envelope::envelope_binding`].
     Relayed([u8; 32]),
+    /// `ZTX_V1_DIRECT` with [`crate::envelope::unwrap_binding`]: a direct `zetherUnshieldUnwrap` binds its leg and
+    /// `minOut` (controller ruling, pending the owner).
+    Unwrap([u8; 32]),
 }
 
-/// The 384-byte statement header (§6).
+/// The 416-byte statement header (zether.md §7): `chainUid` is word 3 (CTR-ZTH-36).
 #[derive(Clone, Debug, PartialEq, Eq)]
 pub struct Header {
     pub chain_id: u64,
+    /// The token's `chainUid()`: the chain's genesis hash (CTR-GEN-05).
+    pub chain_uid: [u8; 32],
     pub token: [u8; 20],
     pub binding: Binding,
     pub send_counter: u64,
@@ -100,11 +105,13 @@ impl Header {
         let (tag, binding) = match self.binding {
             Binding::Direct => (keccak256(b"ZTX_V1_DIRECT"), [0u8; 32]),
             Binding::Relayed(b) => (keccak256(b"ZTX_V1_RELAYED"), b),
+            Binding::Unwrap(b) => (keccak256(b"ZTX_V1_DIRECT"), b),
         };
-        let words: [[u8; 32]; 12] = [
+        let words: [[u8; 32]; 13] = [
             op_tag,
             psid,
             be32_u64(self.chain_id),
+            self.chain_uid,
             be32_addr(&self.token),
             tag,
             binding,
@@ -133,26 +140,25 @@ impl Header {
         if w(1) != psid {
             return Err(ZError::BadStatement("proofSystemId"));
         }
-        let binding = if w(4) == keccak256(b"ZTX_V1_DIRECT") {
-            if w(5) != [0u8; 32] {
-                return Err(ZError::BadStatement("DIRECT with non-zero envelopeBinding"));
-            }
-            Binding::Direct
-        } else if w(4) == keccak256(b"ZTX_V1_RELAYED") {
-            Binding::Relayed(w(5).try_into().unwrap())
+        let binding = if w(5) == keccak256(b"ZTX_V1_DIRECT") {
+            let b: [u8; 32] = w(6).try_into().unwrap();
+            if b == [0u8; 32] { Binding::Direct } else { Binding::Unwrap(b) }
+        } else if w(5) == keccak256(b"ZTX_V1_RELAYED") {
+            Binding::Relayed(w(6).try_into().unwrap())
         } else {
             return Err(ZError::BadStatement("bindingTag"));
         };
         Ok(Self {
             chain_id: u64_of(w(2))?,
-            token: addr_of(w(3))?,
+            chain_uid: w(3).try_into().unwrap(),
+            token: addr_of(w(4))?,
             binding,
-            send_counter: u64_of(w(6))?,
-            acc_seq: u64_of(w(7))?,
-            fee: u64_of(w(8))?,
-            beneficiary: w(9).try_into().unwrap(),
-            amount: u64_of(w(10))?,
-            recipient: addr_of(w(11))?,
+            send_counter: u64_of(w(7))?,
+            acc_seq: u64_of(w(8))?,
+            fee: u64_of(w(9))?,
+            beneficiary: w(10).try_into().unwrap(),
+            amount: u64_of(w(11))?,
+            recipient: addr_of(w(12))?,
         })
     }
 
@@ -508,6 +514,7 @@ pub fn derive_s<C: ZCurve>(x: &Fr<C>, h: &Header, y_to: &G<C>, v: u64) -> Fr<C>
     d.update(b"SCAAS-ZETHER-S-V1");
     d.update(encode_scalar::<C>(x));
     d.update(h.chain_id.to_be_bytes());
+    d.update(h.chain_uid);
     d.update(h.token);
     d.update(h.send_counter.to_be_bytes());
     d.update(encode_point::<C>(y_to));
@@ -599,7 +606,7 @@ impl TransferMode {
         })
     }
 
-    /// The JSON name, also the token function suffix (`transferConfidential`, `…Bundle`, `…NoBundle`).
+    /// The JSON name (the token functions are `zetherTransfer`, `…Bundle`, `…NoBundle`).
     pub fn name(self) -> &'static str {
         match self {
             Self::Hash => "hash",
@@ -945,6 +952,7 @@ pub fn derive_s_multi<C: ZCurve>(x: &Fr<C>, h: &Header, recipients: &[(G<C>, u64
     d.update(b"SCAAS-ZETHER-S-MULTI-V1");
     d.update(encode_scalar::<C>(x));
     d.update(h.chain_id.to_be_bytes());
+    d.update(h.chain_uid);
     d.update(h.token);
     d.update(h.send_counter.to_be_bytes());
     for (y, v) in recipients {
diff --git a/clients/zether-prover/tests/envelope_disclosure.rs b/clients/zether-prover/tests/envelope_disclosure.rs
index 64ab03e..f737e67 100644
--- a/clients/zether-prover/tests/envelope_disclosure.rs
+++ b/clients/zether-prover/tests/envelope_disclosure.rs
@@ -1,5 +1,5 @@
-//! Envelope binding / EIP-712 digest / op calldata against foundry `cast` (tools/env_ref.sh),
-//! relayed-binding end to end, and the four disclosure openings.
+//! Envelope binding / EIP-712 digest / calldata / entryRef / unwrap binding against foundry `cast`
+//! (tools/env_ref.sh), relayed-binding end to end, and the four disclosure openings.
 
 use rand_chacha::rand_core::SeedableRng;
 use rand_chacha::ChaCha20Rng;
@@ -10,15 +10,28 @@ use zether_prover::elgamal::encrypt;
 use zether_prover::envelope::*;
 use zether_prover::keys::ZetherKey;
 use zether_prover::schnorr::{entry_ref, open_chaum_pedersen, open_sender, open_sender_cp, verify_opening, Entry, OpeningKind};
-use zether_prover::zether::{prove_transfer, verify_transfer, Binding, Header};
+use zether_prover::zether::{prove_transfer, verify_transfer, Binding, Header, TransferStatement};
 
 const TOK: [u8; 20] = [0x11; 20];
+const UID: [u8; 32] = hex_literal(b"24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464");
+
+const fn hex_literal(s: &[u8; 64]) -> [u8; 32] {
+    let mut o = [0u8; 32];
+    let mut i = 0;
+    while i < 32 {
+        o[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
+        i += 1;
+    }
+    o
+}
+
+const fn nib(c: u8) -> u8 {
+    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
+}
 
 fn mtx() -> MetaTx {
     MetaTx {
         from: [0xaa; 20],
-        to: [0; 20],
-        value: 0,
         data: hex::decode("deadbeef").unwrap(),
         batch: [1; 32],
         nonce: 7,
@@ -33,29 +46,37 @@ fn mtx() -> MetaTx {
 #[test]
 fn envelope_matches_cast() {
     let m = mtx();
-    assert_eq!(hex::encode(envelope_binding(31337, &TOK, &m)), "4d183691f11a44b9d055aaed42a4b26d9c7b4de5b72619c6ad1f83c5675a83aa");
-    assert_eq!(hex::encode(digest(31337, &TOK, &m)), "63cc8309bee1be82025aa9f74b24113d13d2b1c3a2dfbe8003521b246d89087d");
-    // data is outside the binding, inside the digest.
+    assert_eq!(hex::encode(envelope_binding(31337, &UID, &TOK, &m)), "29764986e75d275afefd0f799cae4e8ea5b1c9771e9ed9b43ffa9cc26d81350d");
+    assert_eq!(hex::encode(digest(31337, &UID, &TOK, &m)), "0f6659afa867aae303e5e90723cdc6c803ec597a777d686a91fcd2226e962509");
+    // data is outside the binding, inside the digest; chainUid is in both.
     let mut m2 = m.clone();
     m2.data = vec![1];
-    assert_eq!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
-    assert_ne!(digest(31337, &TOK, &m), digest(31337, &TOK, &m2));
+    assert_eq!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
+    assert_ne!(digest(31337, &UID, &TOK, &m), digest(31337, &UID, &TOK, &m2));
+    assert_ne!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &[0x24; 32], &TOK, &m));
+    assert_ne!(digest(31337, &UID, &TOK, &m), digest(31337, &[0x24; 32], &TOK, &m));
     // Unbound feeRecipient does not move the binding; a bound one does.
     m2.fee_recipient = [0xcd; 20];
-    assert_eq!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
+    assert_eq!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
     m2.mode |= MODE_RESTRICT_FEE_RECIPIENT;
-    assert_ne!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
+    assert_ne!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
+    assert_eq!(
+        hex::encode(transfer_call("zetherTransferSingle(bytes,bytes,bytes,bytes32)", &[0xaa, 0xbb], &[0xcc, 0xdd, 0xee], &[], &[0x22; 32])),
+        "4d2e578f000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010022222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ccddee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
+    );
     assert_eq!(
-        hex::encode(transfer_data(&[0xaa, 0xbb], &[0xcc, 0xdd, 0xee], &[], &[0x22; 32])),
-        "d228e5c0000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010022222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ccddee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
+        hex::encode(unshield_call(&[0xaa, 0xbb], &[0xcc, 0xdd], &[], &[0; 32], &[0x44; 20], 400_000)),
+        "983c784200000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000061a800000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002ccdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
     );
     assert_eq!(
-        hex::encode(burn_data(&[0xaa, 0xbb], 400_000, &[0x44; 20], &[0; 32], &[0xcc, 0xdd], &[])),
-        "1d0a6c7c00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000061a8000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002ccdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
+        hex::encode(entry_ref(31337, &UID, &TOK, &[0x55; 32], 3)),
+        "a23a980f358bbb47c48881a7a3307f419df074facb84ed878f881d623bf7bb7e"
     );
+    let mut min_out = [0u8; 32];
+    min_out[30..].copy_from_slice(&1000u16.to_be_bytes());
     assert_eq!(
-        hex::encode(entry_ref(31337, &TOK, &[0x55; 32], 3)),
-        "77b2ecc949e3ee4236bb158750916d10eaa531605fe2f3dbe790b26ee11c1643"
+        hex::encode(unwrap_binding(&[0x44; 20], &min_out)),
+        "2c9fb536a22f965b443581f392be9ed8757762610e687fd2e4f73d2da7202591"
     );
 }
 
@@ -68,9 +89,10 @@ fn relayed_and_disclosure<C: ZCurve>() {
     let acc = encrypt(&from.y, 5000, &Fr::<C>::from(77u64));
     let mut m = mtx();
     m.data.clear();
-    let binding = envelope_binding(31337, &TOK, &m);
+    let binding = envelope_binding(31337, &UID, &TOK, &m);
     let h = Header {
         chain_id: 31337,
+        chain_uid: UID,
         token: TOK,
         binding: Binding::Relayed(binding),
         send_counter: 3,
@@ -82,22 +104,30 @@ fn relayed_and_disclosure<C: ZCurve>() {
     };
     let (st, p, w) = prove_transfer(&gens, &from, h, to.y, aud.y, acc, 5000, 1234, &mut rng).unwrap();
     verify_transfer(&gens, &st, &p).unwrap();
-    m.data = transfer_data(&st.payload(), &p.encode(), &[], &[0; 32]);
+    m.data = transfer_call("zetherTransferSingle(bytes,bytes,bytes,bytes32)", &st.payload(), &p.encode(), &[], &[0; 32]);
     // Same proof inside a different envelope (other nonce) → different binding → rejected.
     let mut m2 = m.clone();
     m2.nonce += 1;
     let mut st2 = st.clone();
-    st2.header.binding = Binding::Relayed(envelope_binding(31337, &TOK, &m2));
+    st2.header.binding = Binding::Relayed(envelope_binding(31337, &UID, &TOK, &m2));
     assert!(verify_transfer(&gens, &st2, &p).is_err());
-    // Lifted out and called directly → DIRECT statement → rejected.
+    // Lifted out and called directly → DIRECT statement → rejected; a DIRECT word that is not 0 decodes as Unwrap.
     st2.header.binding = Binding::Direct;
     assert!(verify_transfer(&gens, &st2, &p).is_err());
+    st2.header.binding = Binding::Unwrap(binding);
+    assert!(verify_transfer(&gens, &st2, &p).is_err());
+    assert_eq!(TransferStatement::<C>::decode(&st2.encode()).unwrap().header.binding, Binding::Unwrap(binding));
+    // Another chain with the same chain id (a re-created chain): chainUid differs → rejected.
+    let mut st3 = st.clone();
+    st3.header.chain_uid[0] ^= 1;
+    assert!(verify_transfer(&gens, &st3, &p).is_err());
 
     // Disclosure of this transfer, four ways.
     let e = Entry {
         chain_id: 31337,
+        chain_uid: UID,
         token: TOK,
-        entry_ref: entry_ref(31337, &TOK, &from.ua(), 3),
+        entry_ref: entry_ref(31337, &UID, &TOK, &from.ua(), 3),
         index: 0,
         y_t: st.y_t,
         c_out: st.c_out,
@@ -145,6 +175,10 @@ fn relayed_and_disclosure<C: ZCurve>() {
     assert!(verify_opening(&eo, 1234, OpeningKind::Auditor, &a_open).is_err());
     verify_opening(&eo, 1234, OpeningKind::ReceiverX, &r_open).unwrap();
     verify_opening(&eo, 1234, OpeningKind::SenderCp, &cp).unwrap();
+    // Opening bound to chainUid (CTR-ZTH-36).
+    let eu = Entry { chain_uid: [0x24; 32], ..e };
+    assert!(verify_opening(&eu, 1234, OpeningKind::ReceiverX, &r_open).is_err());
+    assert!(verify_opening(&eu, 1234, OpeningKind::SenderCp, &cp).is_err());
     // Opening bound to entryRef.
     let mut e2 = e;
     e2.entry_ref[0] ^= 1;
@@ -181,11 +215,11 @@ fn relayed_and_disclosure_bls12_381() {
 }
 
 #[test]
-fn direct_call_selectors_match_s2_spec() {
-    // zether-design §9 (RS2-14): direct transfers have 4 args, no outer fee. The selector of
-    // `transferConfidential` now belongs to the multi-recipient HASH entry; the single format is
-    // `transferConfidentialSingle` (same arguments).
-    assert_eq!(hex::encode(selector("transferConfidential(bytes,bytes,bytes,bytes32)")), "7c947e8e");
-    assert_eq!(hex::encode(selector("transferConfidentialSingle(bytes,bytes,bytes,bytes32)")), "663f4320");
-    assert_eq!(hex::encode(selector("burn(bytes,uint256,address,bytes32,bytes,bytes)")), "8938052e");
+fn entry_point_selectors_match_the_spec() {
+    // CTR-ZTH-45: the zether-prefixed names; the multi-recipient HASH transfer is `zetherTransfer`, the single format
+    // `zetherTransferSingle` (same four arguments, no outer fee on a direct call).
+    assert_eq!(hex::encode(selector("zetherTransfer(bytes,bytes,bytes,bytes32)")), "d228e5c0");
+    assert_eq!(hex::encode(selector("zetherTransferSingle(bytes,bytes,bytes,bytes32)")), "4d2e578f");
+    assert_eq!(hex::encode(selector("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)")), "983c7842");
+    assert_eq!(hex::encode(selector("zetherShield(bytes,uint256)")), "1ca6ee72");
 }
diff --git a/clients/zether-prover/tests/read_balance.rs b/clients/zether-prover/tests/read_balance.rs
index ea702fb..82ef4be 100644
--- a/clients/zether-prover/tests/read_balance.rs
+++ b/clients/zether-prover/tests/read_balance.rs
@@ -56,7 +56,8 @@ fn big_balance_cache_spend_and_cli_recovery() {
     let v: u64 = (1 << 33) + 7;
     let fee: u64 = 300;
     let t = api("proveTransfer", json!({
-        "curve": "bn254", "key": k0, "chainId": 31337, "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
+        "curve": "bn254", "key": k0, "chainId": 31337, "chainUid": hx(&[0x24; 32]),
+        "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
         "sendCounter": 0, "accSeq": 1, "acc": acc, "balance": bal.to_string(), "yTo": b["Y"],
         "amount": v.to_string(), "fee": fee, "beneficiary": hx(&[0x22; 32]),
     })).unwrap();
diff --git a/clients/zether-prover/tests/vectors.rs b/clients/zether-prover/tests/vectors.rs
index 56e8912..fef43cf 100644
--- a/clients/zether-prover/tests/vectors.rs
+++ b/clients/zether-prover/tests/vectors.rs
@@ -48,12 +48,13 @@ fn api_roundtrip_mnemonic_keygen_prove_decrypt() {
         let b = call("keygen", json!({"curve": curve, "key": k1}));
         let acc = call("encrypt", json!({"curve": curve, "Y": a["Y"], "amount": 5000}));
         let t = call("proveTransfer", json!({
-            "curve": curve, "key": k0, "chainId": 31337, "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
+            "curve": curve, "key": k0, "chainId": 31337, "chainUid": "0x".to_string() + &"24".repeat(32),
+            "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
             "sendCounter": 0, "accSeq": 1, "acc": acc, "balance": 5000, "yTo": b["Y"], "amount": 1200,
         }));
         assert!(t.get("witness").is_none(), "secrets must not leave the API unless asked");
-        let single = hex::encode(zether_prover::envelope::selector("transferConfidentialSingle(bytes,bytes,bytes,bytes32)"));
-        assert!(t["directCalldata"].as_str().unwrap().starts_with(&format!("0x{single}")), "RS2-14 direct selector");
+        let single = hex::encode(zether_prover::envelope::selector("zetherTransferSingle(bytes,bytes,bytes,bytes32)"));
+        assert!(t["directCalldata"].as_str().unwrap().starts_with(&format!("0x{single}")), "direct selector (CTR-ZTH-45)");
         let ok = call("verifyTransfer", json!({"curve": curve, "statement": t["statement"], "proof": t["proof"]}));
         assert_eq!(ok["ok"], json!(true));
         let d = call("decrypt", json!({"curve": curve, "key": k0, "ct": acc, "tableBits": 18, "boundBits": 20}));
@@ -78,5 +79,5 @@ fn api_roundtrip_mnemonic_keygen_prove_decrypt() {
     assert!(enc(json!(9007199254740991u64)).is_ok());
     assert!(enc(json!("9007199254740993")).is_ok());
     let bad_y = json!({"curve": "bn254", "Y": "0x".to_string() + &"11".repeat(64), "amount": 1});
-    assert!(zether_prover::api::call("fundCalldata", &bad_y.to_string()).is_err());
+    assert!(zether_prover::api::call("shieldCalldata", &bad_y.to_string()).is_err());
 }
diff --git a/clients/zether-prover/tests/zether_proofs.rs b/clients/zether-prover/tests/zether_proofs.rs
index 46212a6..d34cff9 100644
--- a/clients/zether-prover/tests/zether_proofs.rs
+++ b/clients/zether-prover/tests/zether_proofs.rs
@@ -22,6 +22,7 @@ fn key<C: ZCurve>(account: u32) -> ZetherKey<C> {
 fn header(fee: u64) -> Header {
     Header {
         chain_id: 31337,
+        chain_uid: [0x24; 32],
         token: [0x11; 20],
         binding: Binding::Direct,
         send_counter: 3,
@@ -207,6 +208,7 @@ fn header_binding<C: ZCurve>() {
     verify_transfer(&f.gens, &st, &p).unwrap();
     let muts: Vec<fn(&mut Header)> = vec![
         |h| h.chain_id += 1,
+        |h| h.chain_uid[31] ^= 1,
         |h| h.token[19] ^= 1,
         |h| h.binding = Binding::Direct,
         |h| h.binding = Binding::Relayed([0x34; 32]),
diff --git a/clients/zether-prover/tools/env_ref.sh b/clients/zether-prover/tools/env_ref.sh
index aee18a5..7d7b3a2 100755
--- a/clients/zether-prover/tools/env_ref.sh
+++ b/clients/zether-prover/tools/env_ref.sh
@@ -1,18 +1,21 @@
 #!/bin/bash
-# Independent (foundry cast) reference values for envelope.rs tests.
+# Independent (foundry cast) reference values for the envelope.rs tests (tests/envelope_disclosure.rs).
 set -e
 TOK=0x1111111111111111111111111111111111111111
+CUID=0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464
 FROM=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 REL=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
 ZERO=0x0000000000000000000000000000000000000000
 BATCH=0x0101010101010101010101010101010101010101010101010101010101010101
 ENV_TAG=$(cast keccak "SCAAS-ZETHER-ENVELOPE-V1")
-echo "binding $(cast keccak $(cast abi-encode 'f(bytes32,uint256,address,address,address,uint256,uint256,uint256,uint256,uint32,address,uint256,address)' $ENV_TAG 31337 $TOK $FROM $ZERO 0 $BATCH 7 1800000000 33 $REL 1000 $ZERO))"
-TH=$(cast keccak "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
-SH=$(cast keccak $(cast abi-encode 'f(bytes32,address,address,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)' $TH $FROM $ZERO 0 $(cast keccak 0xdeadbeef) $BATCH 7 1800000000 33 $REL 1000 $ZERO))
-DT=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
-DS=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' $DT $(cast keccak "SCaaS ZetherToken") $(cast keccak "1") 31337 $TOK))
+echo "binding $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,address,bytes32,uint256,uint256,uint32,address,uint256,address)' $ENV_TAG 31337 $CUID $TOK $FROM $BATCH 7 1800000000 33 $REL 1000 $ZERO))"
+TH=$(cast keccak "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
+SH=$(cast keccak $(cast abi-encode 'f(bytes32,address,bytes32,bytes32,uint256,uint256,uint32,address,uint256,address)' $TH $FROM $(cast keccak 0xdeadbeef) $BATCH 7 1800000000 33 $REL 1000 $ZERO))
+DT=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
+DS=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address,bytes32)' $DT $(cast keccak "SCaaS ZetherToken") $(cast keccak "1") 31337 $TOK $CUID))
 echo "digest $(cast keccak 0x1901${DS:2}${SH:2})"
-echo "transfer_data $(cast calldata 'zetherTransfer(bytes,bytes,bytes,bytes32)' 0xaabb 0xccddee 0x 0x2222222222222222222222222222222222222222222222222222222222222222)"
-echo "burn_data $(cast calldata 'zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)' 0xaabb 400000 0x4444444444444444444444444444444444444444 0x0000000000000000000000000000000000000000000000000000000000000000 0xccdd 0x)"
-echo "entry_ref $(cast keccak $(cast abi-encode 'f(bytes32,uint256,address,bytes32,uint256)' $(cast keccak SCAAS-ZETHER-ENTRY-V1) 31337 $TOK 0x5555555555555555555555555555555555555555555555555555555555555555 3))"
+echo "transfer_call $(cast calldata 'zetherTransferSingle(bytes,bytes,bytes,bytes32)' 0xaabb 0xccddee 0x 0x2222222222222222222222222222222222222222222222222222222222222222)"
+echo "unshield_call $(cast calldata 'zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)' 0xaabb 0xccdd 0x 0x0000000000000000000000000000000000000000000000000000000000000000 0x4444444444444444444444444444444444444444 400000)"
+echo "entry_ref $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,bytes32,uint256)' $(cast keccak SCAAS-ZETHER-ENTRY-V1) 31337 $CUID $TOK 0x5555555555555555555555555555555555555555555555555555555555555555 3))"
+echo "unwrap_binding $(cast keccak $(cast abi-encode 'f(bytes32,address,uint256)' $(cast keccak SCAAS-ZETHER-UNWRAP-V1) 0x4444444444444444444444444444444444444444 1000))"
+for s in 'zetherTransfer(bytes,bytes,bytes,bytes32)' 'zetherTransferSingle(bytes,bytes,bytes,bytes32)' 'zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)' 'zetherShield(bytes,uint256)'; do echo "sel $s $(cast sig "$s")"; done
```

- [ ] **Step 6: regenerate the vectors** (deterministic, ChaCha20-seeded) and copy them for forge:

```bash
cd clients/zether-prover
CARGO_TARGET_DIR=/home/ha/work/ainative/scaas/clients/zether-prover/target ../../scripts/capped cargo build --release --bin zether-cli
/home/ha/work/ainative/scaas/clients/zether-prover/target/release/zether-cli vectors vectors
cp vectors/{burn,disclosure,schnorr,transfer}_*.json vectors/transcript_s3.json vectors/envelope.json \
   ../../smartcontracts/evm/test/vectors/zether/s3/
sha256sum vectors/*.json | cut -c1-16
```

  Expected `sha256` prefixes (validated):

```text
ac61c981a9df15f4  burn_bls12381.json        b05a4fef6e35be1c  burn_bn254.json
955a086d397a21d0  disclosure_bls12381.json  84dceca96bce0119  disclosure_bn254.json
66f918418ae4951a  envelope.json             fe472a494c12ca4b  r33_inputs.json (unchanged)
ce6f6a1b27c22283  r33_keys.json (unchanged) ca26a8e92182fbd5  schnorr_bls12381.json (unchanged)
d6d0c56413a6888f  schnorr_bn254.json (unch.) c490bd3cc3e621c1  transcript_s3.json
e2f8982279e53c7c  transfer_bls12381.json    6075fc6d50059f7d  transfer_bn254.json
b902be8c1cf1df5c  transfer_multi_bls12381.json   9463effb52c78234  transfer_multi_bn254.json
cf134fde9fc3de50  transfer_multi_noaud_bls12381.json   27a2c684c48feb83  transfer_multi_noaud_bn254.json
856ac2e062ad59ca  transfer_noaud_bls12381.json   186035caaa85a2bf  transfer_noaud_bn254.json
```

- [ ] **Step 7: Run:**
  - `CARGO_TARGET_DIR=… scripts/capped cargo test --release` in `clients/zether-prover` → 52 passed; `./wasm-smoke.sh`
    → `wasm smoke: 16 checks passed`.
  - `forge test --match-path "test/zether/*"` → 79 passed (Kat 13, S3 17, Verifier 27, Registry 22).
  - `forge test` → **800 passed** (the old token suites left with their token); size gate 0 errors.
- [ ] **Step 8: Commit** `P3: Zether header and digests with chainUid, prover on the new ABI; ZetherToken line to legacy/p3` + trailer.

---

### Task 3: `ZetherLib`, `ZetherLayer`, `ZetherStatements` and kind `NONE_ZETHER`; the ported tests

**Model:** Opus, effort high (money and crypto path; port of the built logic with the stack-limit split).

**Files:**
- Create: `src/zether/ZetherLib.sol`, `ZetherLayer.sol`, `ZetherStatements.sol`, `NoUnderlyingZetherToken.sol`;
  `test/zether/helpers/ZetherFixture.sol`, `test/zether/ZetherNone.t.sol`, `ZetherMulti.t.sol`, `ZetherRevertPaths.t.sol`,
  `test/v2/layout/NoUnderlyingZetherToken.json`
- Modify: `test/v2/Layout.t.sol`, `test/metatx/MsgSenderLint.t.sol`, `size-baseline.json`

**Interfaces:** Consumes Task 1 (kind plumbing, gate) and Task 2 (`IZetherToken`, header 416). Produces `ZetherLib`
(`init`, `shield`, `transferSingle`, `transferMulti`, `unshield`, `rollOver`, `rollOverBatch`, `rollOverSigned`,
`setRollOverMode`; internal `ctx`, `acct`, `tagOf`, `entryRefOf`, `singleFrom`/`multiFrom`/`unshieldFrom`,
`prepareSingle`/`prepareMulti`/`prepareUnshield`; structs `Env`, `Ctx`, `Acct`, `Prepared`), `ZetherLayer` (views, entry
points, `_env()` direct only in this task, `_zetherBinding`), `ZetherStatements` (`transferStatement`,
`transferStatementSingle`, `unshieldStatement`, K12), `NoUnderlyingZetherToken(factory, smartKeyAccountImpl, chainUid,
registry, disclosure)`.

- [ ] **Step 1: `src/zether/ZetherLib.sol`** (new). Port of the built `ZetherToken` logic: the same checks in the same
  order (cheap first, then `requireAuthorized`, then the proof, then effects), `_header` with `chainUid`, `entryRefOf`
  and the roll-over/mode digests with `chainUid` (K1); the HASH record in one `bytes32` slot (`entryHashes`, G2);
  `_prepare*`/`_settle*` keep each frame under the stack limit:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUniversalAccountRegistry} from "../registry/IUniversalAccountRegistry.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherSafety} from "./ZetherSafety.sol";

/// @title The confidential layer of the `*_ZETHER` kinds (CTR-ZTH-44, CTR-TOK-24), in the ERC-7201 namespace
///        `scaas.zether`: statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** External library: the token keeps the ERC-20 side (it burns the
///         public units a shield takes and mints or pays out what an unshield gives) and the entry points
///         (`ZetherLayer`); the logic runs here by `DELEGATECALL`, so `address(this)` is the token. One implementation
///         for every curve: points are `bytes`, the group operations and the proofs go through the verifier chosen at
///         creation. The statement builders are `internal` so that `ZetherStatements` builds the very same bytes from
///         the token's views (CTR-ZTH-46). Byte layout: `docs/contracts/zether.md` §7, §11, §12.
library ZetherLib {
    /// @dev `acc`/`pending` as `bytes` points (`O` when never written); the counters of zether.md §6.
    struct Account {
        bytes accC;
        bytes accD;
        bytes pendC;
        bytes pendD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 lastRolledPendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    /// @custom:storage-location erc7201:scaas.zether
    struct ZetherStorage {
        IZetherVerifier verifier;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint256 totalShielded;
        bytes auditorKey;
        bytes32 psid;
        uint256 p;
        mapping(ZetherTypes.UA => Account) acct;
        /// @dev `B_1 ‖ … ‖ B_M` (single format, BUNDLE); NONE writes nothing.
        mapping(bytes32 => bytes) entries;
        /// @dev HASH: `keccak256(B_1 ‖ … ‖ B_M)` in one slot (CTR-ZTH-38).
        mapping(bytes32 => bytes32) entryHashes;
    }

    /// @notice The token's immutables a call needs, and the statement's binding: `(ZTX_V1_DIRECT, 0)` for a direct
    ///         call, `(ZTX_V1_RELAYED, envelopeBinding)` inside `mtxExecute`.
    struct Env {
        address registry;
        bytes32 chainUid;
        bytes32 tag;
        bytes32 binding;
    }

    /// @notice Everything a statement needs besides the payload and the sender's account: from the token's storage
    ///         (`ctx`) or from its views (`ZetherStatements`).
    struct Ctx {
        IZetherVerifier ver;
        address registry;
        address token;
        bytes32 chainUid;
        bytes32 psid;
        uint256 p;
        uint256 fee;
        uint256 maxShielded;
        bytes auditorKey;
        bytes32 tag;
        bytes32 binding;
    }

    /// @notice The sender's part of a statement (points as stored, `O` when unset).
    struct Acct {
        bytes accC;
        bytes accD;
        uint64 accSeq;
        uint64 sendCounter;
    }

    /// @notice A checked statement, before verification.
    struct Prepared {
        ZetherTypes.UA from;
        ZetherTypes.UA beneficiary;
        bytes statement;
        uint256 fee;
        uint64 sendCounter;
        ZetherTypes.UA[] to; // multi-recipient only
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;

    bytes32 internal constant TAG_DIRECT = keccak256("ZTX_V1_DIRECT");
    bytes32 internal constant TAG_RELAYED = keccak256("ZTX_V1_RELAYED");
    bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-ZETHER-ENVELOPE-V1");
    bytes32 private constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 private constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 private constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
    bytes32 private constant OP_MULTI_BUNDLE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    bytes32 private constant OP_MULTI_NONE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE");
    bytes32 private constant TAG_ENTRY = keccak256("SCAAS-ZETHER-ENTRY-V1");
    bytes32 private constant TAG_ROLLOVER = keccak256("ZETHER_ROLLOVER_V1");
    bytes32 private constant TAG_SET_MODE = keccak256("ZETHER_SET_ROLLOVER_MODE_V1");
    bytes private constant AUTH_TAG = "SCAAS-ZETHER-AUTH-V1";
    uint256 private constant MAX_RECIPIENTS = 16;
    uint256 private constant MAX_TOTAL_SHIELDED = 1 << 54;
    /// @dev `2^n_v` (n_v = 64, CTR-ZTH-18): the bound of `confidentialFee`.
    uint256 private constant VALUE_BOUND = 1 << 64;

    function $() internal pure returns (ZetherStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The kind's `_init` (dev chains only, CTR-ZTH-02): verifier, scale, cap `≤ 2^54`, inner fee `< 2^64` and
    ///         `< cap`, auditor key empty or a valid point `≠ O` of the verifier's curve; `cap · scale` must not overflow.
    function init(IFactoryToken.ConfidentialConfig calldata c) public {
        ZetherSafety.requireDevChain();
        IZetherVerifier v = IZetherVerifier(c.verifier);
        uint256 p = v.g1EncodedBytes();
        bytes calldata aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > MAX_TOTAL_SHIELDED
            || c.confidentialFee >= VALUE_BOUND || c.confidentialFee >= c.maxShielded
            || (aud.length != 0 && (aud.length != p || !v.isValidPoint(aud) || _isO(aud)))) {
            revert IZetherToken.BadInit();
        }
        if (c.maxShielded > type(uint256).max / c.shieldScale) revert IZetherToken.BadInit();
        ZetherStorage storage s = $();
        s.verifier = v;
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.auditorKey = aud;
        s.psid = v.proofSystemId();
        s.p = p;
    }

    // ------------------------------------------------------------------ shield

    /// @notice `pending[ua] += [amount]G` and `totalShielded += amount` within the cap. The token takes the public units
    ///         (`zetherShield`) or the underlying (`zetherWrapShield`); the minter never mints shielded value.
    function shield(ZetherTypes.UA ua, uint256 amount, address registry) public {
        ZetherStorage storage s = $();
        if (IUniversalAccountRegistry(registry).keyLengthOf(ua) != s.p) revert IZetherToken.AccountNotRegistered(ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IZetherToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        _credit(s, ua, s.verifier.g1MulBase(amount), "");
        emit IZetherToken.ZetherShielded(ua, amount);
    }

    // ------------------------------------------------------------------ transfer

    /// @notice The single-recipient format: checks, authority, proof, then `acc_f −= (C_deb + [fee]G, D_out)`,
    ///         `pend_t += (C_out, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++`; the bundle stored in full.
    function transferSingle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        Env memory e
    ) public returns (bytes32) {
        (Ctx memory c, Prepared memory pp) = _prepareSingle(payload, beneficiary, e);
        _check(c, pp, authSig, proof, OP_TRANSFER);
        return _settleSingle(c, pp, payload);
    }

    function _prepareSingle(bytes calldata payload, ZetherTypes.UA beneficiary, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareSingle(c, acct(s.acct[singleFrom(payload, c.p)], c.p), payload, beneficiary);
    }

    function _settleSingle(Ctx memory c, Prepared memory pp, bytes calldata payload) private returns (bytes32 entryRef) {
        ZetherStorage storage s = $();
        bytes calldata pts = payload[64:];
        uint256 p = c.p;
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        _debit(c, s.acct[pp.from], pts[4 * p:5 * p], pts[3 * p:4 * p], pp.fee);
        _credit(s, to, pts[2 * p:3 * p], pts[3 * p:4 * p]);
        _payFee(s, c, pp);
        entryRef = _sent(s, c, pp);
        s.entries[entryRef] = bytes.concat(pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
        emit IZetherToken.ZetherTransfer(pp.from, to, pp.beneficiary, pp.fee, pp.sendCounter, entryRef);
    }

    /// @notice `M` recipients, one proof (CTR-ZTH-37/38): `acc_f −= (C_deb + [fee]G, D_out)`, every
    ///         `pend_tj += (C_out_j, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++` once; the bundles by `mode`.
    function transferMulti(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        Env memory e
    ) public returns (bytes32) {
        (Ctx memory c, Prepared memory pp) = _prepareMulti(payload, beneficiary, mode, e);
        _check(c, pp, authSig, proof, OP_MULTI_HASH);
        return _settleMulti(c, pp, payload, mode);
    }

    function _prepareMulti(bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareMulti(c, acct(s.acct[multiFrom(payload, c.p)], c.p), payload, beneficiary, mode);
    }

    function _settleMulti(Ctx memory c, Prepared memory pp, bytes calldata payload, ZetherTypes.TransferMode mode)
        private returns (bytes32 entryRef)
    {
        ZetherStorage storage s = $();
        uint256 p = c.p;
        _debit(c, s.acct[pp.from], payload[96 + 2 * p:96 + 3 * p], payload[96 + p:96 + 2 * p], pp.fee);
        _creditLegs(s, pp.to, payload, p);
        _payFee(s, c, pp);
        entryRef = _sent(s, c, pp);
        if (mode != ZetherTypes.TransferMode.NONE) _storeBundles(s, p, entryRef, payload, pp.to.length, mode);
        emit IZetherToken.ZetherTransferMulti(pp.from, pp.beneficiary, pp.fee, pp.sendCounter, entryRef, pp.to, mode);
    }

    /// @dev Every `pend_tj += (C_out_j, D_out)`, decoys included.
    function _creditLegs(ZetherStorage storage s, ZetherTypes.UA[] memory to, bytes calldata payload, uint256 p) private {
        bytes calldata dOut = payload[96 + p:96 + 2 * p];
        for (uint256 j; j < to.length; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            _credit(s, to[j], payload[o + p:o + 2 * p], dOut);
        }
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement (zether.md §8.2, built name `burn`): checks, authority, proof, then
    ///         `acc_f.C −= [amount + fee]G`, `pend_ben += [fee]G`, `sendCounter_f++`, `totalShielded −= amount`. The token
    ///         then pays `amount · shieldScale` public-equivalent units to `recipient` (mint or a leg's underlying).
    function unshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        address recipient,
        Env memory e
    ) public {
        (Ctx memory c, Prepared memory pp) = _prepareUnshield(payload, amount, recipient, beneficiary, e);
        _check(c, pp, authSig, proof, OP_BURN);
        ZetherStorage storage s = $();
        Account storage a = s.acct[pp.from];
        a.accC = c.ver.g1Sub(_pt(a.accC, c.p), c.ver.g1MulBase(amount + pp.fee));
        _sent(s, c, pp);
        s.totalShielded -= amount;
        _payFee(s, c, pp);
        emit IZetherToken.ZetherUnshielded(pp.from, amount, recipient);
    }

    function _prepareUnshield(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        Env memory e
    ) private view returns (Ctx memory c, Prepared memory pp) {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareUnshield(c, acct(s.acct[unshieldFrom(payload, c.p)], c.p), payload, amount, recipient, beneficiary);
    }

    // ------------------------------------------------------------------ roll-over (zether.md §6)

    /// @notice `PUBLIC` accounts only; a silent no-op without a new credit (anti-DoS).
    function rollOver(ZetherTypes.UA ua) public {
        ZetherStorage storage s = $();
        if (s.acct[ua].mode == ZetherTypes.RollOverMode.OWNER_ONLY) revert IZetherToken.RollOverOwnerOnly(ua);
        _rollOver(s, ua);
    }

    /// @notice Skips `OWNER_ONLY` items, never reverts the batch for them.
    function rollOverBatch(ZetherTypes.UA[] calldata uas) public {
        ZetherStorage storage s = $();
        for (uint256 i; i < uas.length; ++i) {
            if (s.acct[uas[i]].mode == ZetherTypes.RollOverMode.PUBLIC) _rollOver(s, uas[i]);
        }
    }

    /// @notice CTR-ZTH-16/17: `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq`, signed by the account's
    ///         authority over `ZETHER_ROLLOVER_V1` with `chainid`, `chainUid`, the token and `accSeq`.
    function rollOverSigned(
        ZetherTypes.UA ua,
        uint64 expectedPendingSeq,
        uint64 validUntilBlock,
        bytes calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        ZetherStorage storage s = $();
        Account storage a = s.acct[ua];
        if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {
            revert IZetherToken.PendingSeqMismatch(expectedPendingSeq, a.pendingSeq);
        }
        bytes32 digest = keccak256(abi.encode(
            TAG_ROLLOVER, block.chainid, e.chainUid, address(this), ua, a.accSeq, expectedPendingSeq, validUntilBlock
        ));
        IUniversalAccountRegistry(e.registry).requireAuthorized(ua, digest, sig, false);
        _rollOver(s, ua);
    }

    /// @notice `ZETHER_SET_ROLLOVER_MODE_V1` with `chainid`, `chainUid`, the token and `modeNonce` (no replay).
    function setRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        Account storage a = $().acct[ua];
        bytes32 digest = keccak256(abi.encode(
            TAG_SET_MODE, block.chainid, e.chainUid, address(this), ua, uint8(mode), a.modeNonce, validUntilBlock
        ));
        IUniversalAccountRegistry(e.registry).requireAuthorized(ua, digest, sig, false);
        a.mode = mode;
        a.modeNonce += 1;
        emit IZetherToken.RollOverModeChanged(ua, mode);
    }

    // ------------------------------------------------------------------ statements (shared with ZetherStatements)

    /// @notice The statement context of the token itself (`address(this)` under `DELEGATECALL`).
    function ctx(ZetherStorage storage s, Env memory e) internal view returns (Ctx memory c) {
        c.ver = s.verifier;
        c.registry = e.registry;
        c.token = address(this);
        c.chainUid = e.chainUid;
        c.psid = s.psid;
        c.p = s.p;
        c.fee = s.confidentialFee;
        c.maxShielded = s.maxShielded;
        c.auditorKey = s.auditorKey;
        c.tag = e.tag;
        c.binding = e.binding;
    }

    function acct(Account storage a, uint256 p) internal view returns (Acct memory) {
        return Acct(_pt(a.accC, p), _pt(a.accD, p), a.accSeq, a.sendCounter);
    }

    /// @notice `ZTX_V1_RELAYED` for a non-zero envelope binding, else `ZTX_V1_DIRECT`.
    function tagOf(bytes32 binding) internal pure returns (bytes32) {
        return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;
    }

    /// @notice `entryRef` (zether.md §12) with `chainUid` (CTR-ZTH-36); `sendCounter` before the increment.
    function entryRefOf(Ctx memory c, ZetherTypes.UA from, uint64 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)));
    }

    /// @notice Single format: `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud`.
    function singleFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != 64 + 6 * p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[64:64 + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    function multiFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length < 96 + 3 * p) revert IZetherToken.BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[64:96]));
        if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
        if (payload.length != 96 + 3 * p * (1 + m)) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[96:96 + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f`.
    function unshieldFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != 64 + p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[64:64 + p]);
    }

    /// @notice Every cheap check before verification: self, registration, fee, `accSeq`, `sendCounter`.
    function prepareSingle(Ctx memory c, Acct memory a, bytes calldata payload, ZetherTypes.UA beneficiary)
        internal view returns (Prepared memory pp)
    {
        uint256 p = c.p;
        bytes calldata pts = payload[64:];
        pp.from = ZetherTypes.toUA(pts[0:p]);
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();
        _requireRegistered(c, pp.from);
        _requireRegistered(c, to);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(c, OP_TRANSFER, c.psid, a, pp.fee, beneficiary, 0, address(0)),
            pts[0:2 * p], _auditorPoint(c, _isO(pts[5 * p:6 * p]) ? 1 : 0, 1), a.accC, a.accD, pts[2 * p:6 * p]
        );
    }

    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender, all registered.
    function prepareMulti(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) internal view returns (Prepared memory pp) {
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[96:96 + p]);
        _requireRegistered(c, pp.from);
        pp.to = _recipients(c, payload, pp.from, uint256(bytes32(payload[64:96])));
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = _multiStatement(c, a, payload, pp.fee, beneficiary, mode);
    }

    /// @notice `0 < amount ≤ maxShielded` before the statement (`amount + fee < 2^65 < r`), recipient non-zero.
    function prepareUnshield(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary
    ) internal view returns (Prepared memory pp) {
        if (amount == 0 || amount > c.maxShielded) revert IZetherToken.AmountOutOfRange(amount, c.maxShielded);
        if (recipient == address(0)) revert IZetherToken.ZeroRecipient();
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[64:64 + p]);
        _requireRegistered(c, pp.from);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(c, OP_BURN, c.psid, a, pp.fee, beneficiary, amount, recipient), payload[64:64 + p], a.accC, a.accD
        );
    }

    // ------------------------------------------------------------------ internals

    /// @dev The 416-byte header (zether.md §7), `chainUid` at word 3.
    function _header(
        Ctx memory c,
        bytes32 op,
        bytes32 psid,
        Acct memory a,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        address recipient
    ) private view returns (bytes memory) {
        return bytes.concat(
            abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding),
            abi.encode(uint256(a.sendCounter), uint256(a.accSeq), fee, beneficiary, amount, recipient)
        );
    }

    /// @dev `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ legs`; the mode is in `opTag`.
    function _multiStatement(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) private view returns (bytes memory) {
        uint256 p = c.p;
        bytes32 op = mode == ZetherTypes.TransferMode.HASH
            ? OP_MULTI_HASH
            : mode == ZetherTypes.TransferMode.BUNDLE ? OP_MULTI_BUNDLE : OP_MULTI_NONE;
        bytes memory head = bytes.concat(
            _header(c, op, c.ver.proofSystemIdMulti(), a, fee, beneficiary, 0, address(0)),
            payload[96:96 + p], _auditorPoint(c, _audOff(payload, p), uint256(bytes32(payload[64:96]))), a.accC, a.accD
        );
        return bytes.concat(head, payload[96 + p:96 + 3 * p], payload[64:96], payload[96 + 3 * p:]);
    }

    /// @dev The recipients: none the sender, pairwise distinct, registered.
    function _recipients(Ctx memory c, bytes calldata payload, ZetherTypes.UA from, uint256 m)
        private view returns (ZetherTypes.UA[] memory to)
    {
        uint256 p = c.p;
        to = new ZetherTypes.UA[](m);
        for (uint256 j; j < m; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            to[j] = ZetherTypes.toUA(payload[o:o + p]);
            bytes32 t = ZetherTypes.UA.unwrap(to[j]);
            if (t == ZetherTypes.UA.unwrap(from)) revert IZetherToken.SelfTransfer();
            for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert IZetherToken.DuplicateRecipient(to[j]);
            _requireRegistered(c, to[j]);
        }
    }

    function _checkSeqs(Acct memory a, bytes calldata payload) private pure returns (uint64) {
        uint256 provedAccSeq = uint256(bytes32(payload[0:32]));
        uint256 provedSend = uint256(bytes32(payload[32:64]));
        if (provedAccSeq != a.accSeq) revert IZetherToken.StaleAccSeq(a.accSeq, provedAccSeq);
        if (provedSend != a.sendCounter) revert IZetherToken.StaleSendCounter(a.sendCounter, provedSend);
        return a.sendCounter;
    }

    /// @dev `confidentialFee` when a beneficiary is named; the fee is no back door to register on someone's behalf.
    function _innerFee(Ctx memory c, ZetherTypes.UA beneficiary) private view returns (uint256) {
        if (ZetherTypes.UA.unwrap(beneficiary) == bytes32(0)) return 0;
        _requireRegistered(c, beneficiary);
        return c.fee;
    }

    /// @dev Registered on the verifier's curve.
    function _requireRegistered(Ctx memory c, ZetherTypes.UA ua) private view {
        if (IUniversalAccountRegistry(c.registry).keyLengthOf(ua) != c.p) revert IZetherToken.AccountNotRegistered(ua);
    }

    /// @dev The account's spending authority over the statement (registry), then the proof (knowledge of `x`).
    function _check(Ctx memory c, Prepared memory pp, bytes calldata authSig, bytes calldata proof, bytes32 op) private view {
        IUniversalAccountRegistry(c.registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        bool ok = op == OP_TRANSFER
            ? c.ver.verifyTransfer(pp.statement, proof)
            : op == OP_BURN ? c.ver.verifyBurn(pp.statement, proof) : c.ver.verifyTransferMulti(pp.statement, proof);
        if (!ok) revert IZetherToken.ProofRejected();
    }

    /// @dev The inner fee: `[fee]G` into the beneficiary's `pending` (a public scalar, CTR-ZTH-05).
    function _payFee(ZetherStorage storage s, Ctx memory c, Prepared memory pp) private {
        if (pp.fee != 0) _credit(s, pp.beneficiary, c.ver.g1MulBase(pp.fee), "");
    }

    /// @dev `sendCounter_f++` once; the `entryRef` of this debit (with the counter before the increment).
    function _sent(ZetherStorage storage s, Ctx memory c, Prepared memory pp) private returns (bytes32) {
        s.acct[pp.from].sendCounter = pp.sendCounter + 1;
        return entryRefOf(c, pp.from, pp.sendCounter);
    }

    /// @dev `acc_f −= (C_deb + [fee]G, D_out)`.
    function _debit(Ctx memory c, Account storage a, bytes calldata cDeb, bytes calldata dOut, uint256 fee) private {
        bytes memory cc = c.ver.g1Sub(_pt(a.accC, c.p), cDeb);
        if (fee != 0) cc = c.ver.g1Sub(cc, c.ver.g1MulBase(fee));
        a.accC = cc;
        a.accD = c.ver.g1Sub(_pt(a.accD, c.p), dOut);
    }

    function _credit(ZetherStorage storage s, ZetherTypes.UA ua, bytes memory cPt, bytes memory dPt) private {
        Account storage a = s.acct[ua];
        uint256 p = s.p;
        a.pendC = s.verifier.g1Add(_pt(a.pendC, p), cPt);
        if (dPt.length != 0) a.pendD = s.verifier.g1Add(_pt(a.pendD, p), dPt);
        a.pendingSeq += 1;
    }

    /// @dev `acc += pending; pending = O; accSeq++`, only with a new credit. Never called by a transfer or an unshield.
    function _rollOver(ZetherStorage storage s, ZetherTypes.UA ua) private {
        Account storage a = s.acct[ua];
        if (a.pendingSeq == a.lastRolledPendingSeq) return;
        uint256 p = s.p;
        a.accC = s.verifier.g1Add(_pt(a.accC, p), _pt(a.pendC, p));
        a.accD = s.verifier.g1Add(_pt(a.accD, p), _pt(a.pendD, p));
        delete a.pendC;
        delete a.pendD;
        a.accSeq += 1;
        a.lastRolledPendingSeq = a.pendingSeq;
        emit IZetherToken.RolledOver(ua, a.accSeq);
    }

    function _storeBundles(
        ZetherStorage storage s,
        uint256 p,
        bytes32 entryRef,
        bytes calldata payload,
        uint256 m,
        ZetherTypes.TransferMode mode
    ) private {
        bytes memory bundles = _bundles(payload[96 + 3 * p:], payload[96 + p:96 + 2 * p], m, p);
        if (mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entries[entryRef] = bundles;
        } else {
            s.entryHashes[entryRef] = keccak256(bundles);
            emit IZetherToken.TransferBundles(entryRef, bundles);
        }
    }

    /// @dev `B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
    function _bundles(bytes calldata legs, bytes calldata dOut, uint256 m, uint256 p) private pure returns (bytes memory b) {
        for (uint256 j; j < m; ++j) {
            uint256 o = 3 * p * j;
            b = bytes.concat(b, legs[o:o + 2 * p], dOut, legs[o + 2 * p:o + 3 * p]);
        }
    }

    /// @dev `Y_a` of the statement (CTR-ZTH-42): the key when every `C_aud_j ≠ O`, `O` when every one is `O` or the
    ///      token has no auditor (the verifier then requires every `C_aud_j = O`); a mix reverts.
    function _auditorPoint(Ctx memory c, uint256 nOff, uint256 m) private pure returns (bytes memory) {
        if (c.auditorKey.length == 0 || nOff == m) return new bytes(c.p);
        if (nOff != 0) revert IZetherToken.AuditorLegsMixed();
        return c.auditorKey;
    }

    /// @dev Number of legs with `C_aud_j = O`.
    function _audOff(bytes calldata payload, uint256 p) private pure returns (uint256 n) {
        for (uint256 o = 96 + 6 * p; o <= payload.length; o += 3 * p) if (_isO(payload[o - p:o])) ++n;
    }

    /// @dev The stored point, or `O` when never written.
    function _pt(bytes storage b, uint256 p) internal view returns (bytes memory) {
        return b.length == 0 ? new bytes(p) : b;
    }

    function _isO(bytes memory a) internal pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }
}
```

- [ ] **Step 2: `src/zether/ZetherLayer.sol`** (new):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUniversalAccountRegistry} from "../registry/IUniversalAccountRegistry.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title The Zether layer of the kinds `NONE_ZETHER` and `UNDERLYING_ZETHER` (CTR-ZTH-44): the entry points of
///        CTR-ZTH-45 and the views; the state and the logic are `ZetherLib` (`scaas.zether`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only (`ZetherSafety`, CTR-ZTH-02). A layer over the
///         public ERC-20 balance: `zetherShield` burns public units, `zetherUnshield` mints them; the confidential layer
///         keeps no underlying of its own. The registry and the disclosure contract are implementation immutables; the
///         verifier (the curve) and the auditor key are chosen at creation. Every entry point is `nonReentrant`.
abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
    address internal immutable _REGISTRY;
    ITransferDisclosure private immutable _DISCLOSURE;

    constructor(address registry_, ITransferDisclosure disclosure_) {
        if (registry_.code.length == 0 || address(disclosure_).code.length == 0) revert BadInit();
        _REGISTRY = registry_;
        _DISCLOSURE = disclosure_;
    }

    /// @notice CTR-MTX-02: confidential tokens sign under `"SCaaS ZetherToken"`.
    function _domainName() internal pure virtual override(ERC20MetaTx) returns (string memory) {
        return "SCaaS ZetherToken";
    }

    // ------------------------------------------------------------------ views

    function verifier() external view returns (IZetherVerifier) { return ZetherLib.$().verifier; }
    function registry() external view returns (address) { return _REGISTRY; }
    function disclosure() external view returns (ITransferDisclosure) { return _DISCLOSURE; }
    function shieldScale() external view returns (uint256) { return ZetherLib.$().shieldScale; }
    function maxDecryptableShielded() external view returns (uint256) { return ZetherLib.$().maxShielded; }
    function confidentialFee() external view returns (uint256) { return ZetherLib.$().confidentialFee; }
    function auditorKey() external view returns (bytes memory) { return ZetherLib.$().auditorKey; }
    function totalShielded() external view returns (uint256) { return ZetherLib.$().totalShielded; }
    /// @notice The raw record for `disclosure()`: the bundles (single format, BUNDLE), the 32-byte hash (HASH, stored in
    ///         one slot), empty (NONE, unknown).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        bytes32 h = ZetherLib.$().entryHashes[entryRef];
        return h != bytes32(0) ? abi.encodePacked(h) : ZetherLib.$().entries[entryRef];
    }
    function sendCounter(ZetherTypes.UA ua) external view returns (uint256) { return ZetherLib.$().acct[ua].sendCounter; }

    /// @notice Registered on this token's curve.
    function registered(ZetherTypes.UA ua) external view returns (bool) {
        return IUniversalAccountRegistry(_REGISTRY).keyLengthOf(ua) == ZetherLib.$().p;
    }

    function accountState(ZetherTypes.UA ua) external view returns (AccountState memory) {
        ZetherLib.ZetherStorage storage s = ZetherLib.$();
        ZetherLib.Account storage a = s.acct[ua];
        uint256 p = s.p;
        return AccountState({
            accC: ZetherLib._pt(a.accC, p), accD: ZetherLib._pt(a.accD, p), pendingC: ZetherLib._pt(a.pendC, p),
            pendingD: ZetherLib._pt(a.pendD, p), accSeq: a.accSeq, pendingSeq: a.pendingSeq, sendCounter: a.sendCounter,
            modeNonce: a.modeNonce, mode: a.mode
        });
    }

    /// @notice CTR-ZTH-06: every envelope field except `data` (which carries the proof), plus `chainUid`.
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _zetherBinding(m);
    }

    // ------------------------------------------------------------------ shield (CTR-ZTH-35)

    /// @notice Burns `amount · shieldScale` public units of the caller (the signer, relayed); `pending[ua] += [amount]G`.
    function zetherShield(bytes calldata encodedY, uint256 amount) external nonReentrant {
        ZetherLib.shield(ZetherTypes.toUA(encodedY), amount, _REGISTRY);
        _burn(_msgSender(), amount * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ transfer (CTR-ZTH-37, CTR-ZTH-38)

    function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.HASH, _env());
    }

    function zetherTransferBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.BUNDLE, _env());
    }

    function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        return ZetherLib.transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.NONE, _env());
    }

    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        return ZetherLib.transferSingle(payload, proof, authSig, beneficiary, _env());
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement binds `amount` and `to`; mints `amount · shieldScale` public units to `to`.
    function zetherUnshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        address to,
        uint256 amount
    ) external nonReentrant {
        ZetherLib.unshield(payload, proof, authSig, beneficiary, amount, to, _env());
        _mint(to, amount * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ roll-over (not allowlisted, CTR-ZTH-34)

    function zetherRollOver(ZetherTypes.UA ua) external nonReentrant {
        ZetherLib.rollOver(ua);
    }

    function zetherRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {
        ZetherLib.rollOverBatch(uas);
    }

    function zetherRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external nonReentrant
    {
        ZetherLib.rollOverSigned(ua, expectedPendingSeq, validUntilBlock, sig, _env());
    }

    function zetherSetRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external nonReentrant {
        ZetherLib.setRollOverMode(ua, mode, validUntilBlock, sig, _env());
    }

    // ------------------------------------------------------------------ internals

    /// @dev The statement binding of a direct call: `ZTX_V1_DIRECT`, binding 0. The envelope binding of a relayed call
    ///      needs the base's ticket binding (next step of the plan).
    function _env() internal view returns (ZetherLib.Env memory) {
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, bytes32(0));
    }

    function _zetherBinding(MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            ZetherLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch, m.nonce, m.validUntil,
            m.mode, r, m.fee, f
        ));
    }
}
```

- [ ] **Step 3: `src/zether/ZetherStatements.sol`** (new):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IMetaTx} from "../metatx/IMetaTx.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title The prover views of every Zether token (CTR-ZTH-46): the statement a token will build at this block.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Stateless, no admin, no upgrade, one instance for every token on
///         every curve (as `ZetherDisclosure`). It reads the token's views (`verifier`, `registry`, `chainUid`,
///         `confidentialFee`, `maxDecryptableShielded`, `auditorKey`, `accountState`) and runs the token's own
///         builders (`ZetherLib`, internal), so the bytes are the token's, with the same cheap checks. The caller picks
///         the token it trusts. `envelopeBinding` 0 = a direct call (`ZTX_V1_DIRECT`), else the envelope's binding
///         (`ZTX_V1_RELAYED`, `IZetherToken.envelopeBinding`).
contract ZetherStatements {
    /// @notice The multi-recipient statement (`zetherTransfer`, `…Bundle`, `…NoBundle` by `mode`).
    function transferStatement(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.multiFrom(payload, c.p));
        return ZetherLib.prepareMulti(c, a, payload, beneficiary, mode).statement;
    }

    /// @notice The single-recipient statement (`zetherTransferSingle`).
    function transferStatementSingle(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.singleFrom(payload, c.p));
        return ZetherLib.prepareSingle(c, a, payload, beneficiary).statement;
    }

    /// @notice The unshield statement (`zetherUnshield`; built: `burnStatement`).
    function unshieldStatement(
        address token,
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
    }

    function _unshield(
        address token,
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes32 tag,
        bytes32 binding
    ) internal view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, tag, binding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.unshieldFrom(payload, c.p));
        return ZetherLib.prepareUnshield(c, a, payload, amount, recipient, beneficiary).statement;
    }

    function _ctx(address token, bytes32 tag, bytes32 binding) internal view returns (ZetherLib.Ctx memory c) {
        IZetherToken t = IZetherToken(token);
        c.ver = t.verifier();
        c.registry = t.registry();
        c.token = token;
        c.chainUid = IMetaTx(token).chainUid();
        c.psid = c.ver.proofSystemId();
        c.p = c.ver.g1EncodedBytes();
        c.fee = t.confidentialFee();
        c.maxShielded = t.maxDecryptableShielded();
        c.auditorKey = t.auditorKey();
        c.tag = tag;
        c.binding = binding;
    }

    function _acct(address token, ZetherTypes.UA from) internal view returns (ZetherLib.Acct memory) {
        IZetherToken.AccountState memory s = IZetherToken(token).accountState(from);
        return ZetherLib.Acct(s.accC, s.accD, s.accSeq, s.sendCounter);
    }
}
```

- [ ] **Step 4: `src/zether/NoUnderlyingZetherToken.sol`** (new; the allowlist stays `NoUnderlyingToken`'s until Task 4):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {NoUnderlyingToken} from "../metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title Kind `NONE_ZETHER` (CTR-TOK-21): the standalone token with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. `MINTABLE` mints public units only; shielded
///         value exists only through `zetherShield`, which burns public units. Flags: `PAYABLE`, `MINTABLE`, `BURNABLE`
///         (the regulated flags are refused, CTR-ZTH-47). Built by `OpenFactory.createToken` with `conf` set and `legs`,
///         `rate` empty. Never on Hedera (no dev chain there).
contract NoUnderlyingZetherToken is NoUnderlyingToken, ZetherLayer {
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, address registry_,
        ITransferDisclosure disclosure_)
        NoUnderlyingToken(factory_, smartKeyAccountImpl_, chainUid_, false)
        ZetherLayer(registry_, disclosure_)
    {}

    function kind() public pure override(NoUnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_NONE_ZETHER;
    }

    function _init(TokenConfig calldata cfg) internal override(NoUnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
        ZetherLib.init(cfg.conf);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    /// @notice The public allowlist until the layer's entries are relayed (`cancelNonce`, `burn`).
    function mtxSelectors()
        public pure override(NoUnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory, uint8[] memory, uint8[] memory)
    {
        return NoUnderlyingToken.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(NoUnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        return NoUnderlyingToken._mtxRule(sel);
    }
}
```

- [ ] **Step 5: the fixture** (new `test/zether/helpers/ZetherFixture.sol`: `OpenFactory` with the gate on, the
  registry, a verifier, `ZetherDisclosure`, `ZetherStatements`, clones of kind 2; public units from `mint`; proofs from
  the test prover over `ZetherStatements`' statements):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {AuthScheme} from "../../../src/common/AuthScheme.sol";
import {UniversalAccountRegistry} from "../../../src/registry/UniversalAccountRegistry.sol";
import {NoUnderlyingZetherToken} from "../../../src/zether/NoUnderlyingZetherToken.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";
import {ZetherDisclosure} from "../../../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../../../src/zether/ZetherStatements.sol";
import {ITransferDisclosure} from "../../../src/zether/ITransferDisclosure.sol";
import {ZetherTranscript} from "../../../src/zether/ZetherTranscript.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {IZetherVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../../src/zether/ZetherVerifier.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {ZetherProver} from "./ZetherProver.sol";
import {ZetherKeys} from "./ZetherKeys.sol";

bytes32 constant ZUID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

/// @notice The real stack: `OpenFactory` with the Zether gate on, the registry, a verifier, `ZetherDisclosure`,
///         `ZetherStatements` and `NoUnderlyingZetherToken` clones. The test wallet keeps `x` and the plaintext balances
///         to build witnesses and decrypt; the prover is the test-only `ZetherProver`. Public units come from `mint`
///         (the fixture is the minter); `_public` is overridden where they come from a wrap.
abstract contract ZetherFixture is Test {
    struct User {
        uint256 x;
        bytes y;
        ZetherTypes.UA ua;
        address evm;
    }

    OpenFactory internal factory;
    NoUnderlyingZetherToken internal noneImpl;
    UniversalAccountRegistry internal reg;
    IZetherVerifier internal ver;
    ZetherLayer internal tok;
    ZetherDisclosure internal dis;
    ZetherStatements internal stm;
    ZetherProver internal prover;
    bool internal bls;
    /// @dev CTR-ZTH-42: the sender leaves the auditor out (every `C_aud = O`) on a token with an auditor.
    bool internal audOut;
    /// @dev Public units the fixture created per token (`mint` or wrap): `totalSupply + totalShielded·SCALE` stays equal.
    mapping(address => uint256) internal minted;

    address internal registrar = address(0xF00D);
    address internal relayer = address(0xBEEF);
    uint256 internal constant SCALE = 10_000; // a 6-decimal unit kept to 2 decimals (CTR-ZTH-04)
    uint256 internal constant FEE = 2;
    uint256 internal constant X_AUD = 0xA0D17;

    User internal alice;
    User internal bob;
    User internal carol; // receives the inner fee (a relayer)

    function _deploy(bool useBls, bool auditor) internal virtual {
        _stack(useBls);
        tok = _newToken(auditor, "zusd");
        _users();
    }

    function _stack(bool useBls) internal {
        bls = useBls;
        factory = new OpenFactory(registrar, ZUID);
        dis = new ZetherDisclosure();
        stm = new ZetherStatements();
        reg = new UniversalAccountRegistry();
        prover = new ZetherProver();
        ver = useBls ? IZetherVerifier(address(new ZetherVerifierBls12381())) : IZetherVerifier(address(new ZetherVerifierBn254()));
        noneImpl = new NoUnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.startPrank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER, 1, address(noneImpl));
        factory.setZetherEnabled(true);
        vm.stopPrank();
    }

    function _users() internal {
        alice = _user(0xA11CE, address(0xA1));
        bob = _user(0xB0B, address(0xB2));
        carol = _user(0xCA201, address(0xC3));
    }

    /// @dev `PAYABLE | MINTABLE | BURNABLE`, the fixture is the minter, scale `SCALE`, inner fee `FEE`.
    function _cfg(bool auditor, uint256 maxShielded) internal view returns (IFactoryToken.TokenConfig memory c) {
        c.name = "Zether USD";
        c.symbol = "zUSD";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.MINTABLE) | (1 << AdminLib.BURNABLE);
        c.roles.minter = address(this);
        c.conf = IFactoryToken.ConfidentialConfig(
            address(ver), auditor ? ZetherKeys.pub(X_AUD, bls) : bytes(""), SCALE, maxShielded, FEE
        );
    }

    function _newToken(bool auditor, bytes32 salt) internal virtual returns (ZetherLayer) {
        return _newToken(auditor, salt, uint256(1) << 40);
    }

    function _newToken(bool auditor, bytes32 salt, uint256 maxShielded) internal virtual returns (ZetherLayer) {
        return ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, _cfg(auditor, maxShielded), salt));
    }

    function _user(uint256 x, address evm) internal returns (User memory u) {
        u.x = x;
        u.y = ZetherKeys.pub(x, bls);
        u.evm = evm;
        bytes memory pop = abi.encode(ZetherKeys.schnorr(x, reg.popChallenge(u.y, evm), bls), bytes(""));
        vm.prank(evm);
        u.ua = reg.register(u.y, AuthScheme.SELF_SCHNORR, "", pop, true);
    }

    // ------------------------------------------------------------------ operations

    /// @dev `units` public units to `to`.
    function _public(ZetherLayer t, address to, uint256 units) internal virtual {
        NoUnderlyingZetherToken(address(t)).mint(to, units);
        minted[address(t)] += units;
    }

    /// @dev `amount` shielded units into `u`'s pending, paid from the fixture's public balance (CTR-ZTH-35).
    function _fund(ZetherLayer t, User memory u, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.zetherShield(u.y, amount);
    }

    struct Tx {
        bytes payload;
        bytes proof;
        uint256 s;
    }

    /// @dev Payload and proof of `from → to`, value `v`, from the acc balance `b`; `binding` 0 = a direct call.
    function _proveTransfer(ZetherLayer t, User memory from, User memory to, uint256 v, uint256 b, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (Tx memory r)
    {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, v, address(t)))) % ver.groupOrder();
        r.payload = _payload(t, from, to, v, r.s, st);
        ZetherProver.TransferWitness memory w = _witness(from.x, v, r.s, b - v - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()));
        r.proof = _proveT(stm.transferStatementSingle(address(t), r.payload, ben, binding), w);
    }

    function _witness(uint256 x, uint256 v, uint256 s, uint256 bPrime) internal pure returns (ZetherProver.TransferWitness memory) {
        return ZetherProver.TransferWitness(x, v, s, bPrime, 0x1234 + v, 0x5678 + bPrime, keccak256(abi.encode(s)));
    }

    function _proveT(bytes memory statement, ZetherProver.TransferWitness memory w) internal view returns (bytes memory) {
        return prover.proveTransfer(ver, statement, w);
    }

    function _payload(ZetherLayer t, User memory from, User memory to, uint256 v, uint256 s, IZetherToken.AccountState memory st)
        internal view returns (bytes memory)
    {
        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y, to.y, _cts(t, from.y, to.y, v, s));
    }

    function _cts(ZetherLayer t, bytes memory yf, bytes memory yt, uint256 v, uint256 s) internal view returns (bytes memory) {
        bytes memory aud = t.auditorKey();
        if (aud.length == 0 || audOut) aud = ver.identity();
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) = prover.ciphertexts(ver, yf, yt, aud, v, s);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    /// @dev `from → to[j]`, value `vs[j]` (decoys 0), one shared `s`, from the acc balance `b`.
    function _proveMulti(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 b,
        ZetherTypes.UA ben,
        ZetherTypes.TransferMode mode
    ) internal view returns (Tx memory r) {
        return _proveMulti(t, from, to, vs, b, ben, mode, bytes32(0));
    }

    function _proveMulti(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 b,
        ZetherTypes.UA ben,
        ZetherTypes.TransferMode mode,
        bytes32 binding
    ) internal view returns (Tx memory r) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, vs, address(t), "multi"))) % ver.groupOrder();
        r.payload = _multiPayload(t, from, to, vs, r.s, st);
        if (ZetherTypes.UA.unwrap(ben) != 0) b -= t.confidentialFee();
        r.proof = prover.proveTransferMulti(
            ver, stm.transferStatement(address(t), r.payload, ben, mode, binding), _multiWitness(from.x, r.s, vs, b)
        );
    }

    /// @dev `bAfterFee` = the balance less the inner fee; `b' = bAfterFee − Σv`.
    function _multiWitness(uint256 x, uint256 s, uint256[] memory vs, uint256 bAfterFee)
        internal pure returns (ZetherProver.MultiWitness memory w)
    {
        uint256[] memory gv = new uint256[](vs.length);
        uint256 bPrime = bAfterFee;
        for (uint256 j; j < vs.length; ++j) {
            gv[j] = 0x1234 + 7 * j + vs[j];
            bPrime -= vs[j];
        }
        w = ZetherProver.MultiWitness(x, s, vs, bPrime, gv, 0x5678 + bPrime, keccak256(abi.encode(s)));
    }

    /// @dev `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    function _multiPayload(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 s,
        IZetherToken.AccountState memory st
    ) internal view returns (bytes memory payload) {
        bytes memory aud = t.auditorKey();
        if (aud.length == 0 || audOut) aud = ver.identity();
        bytes memory legs;
        uint256 total;
        for (uint256 j; j < to.length; ++j) {
            (bytes memory cOut,,, bytes memory cAud) = prover.ciphertexts(ver, from.y, to[j].y, aud, vs[j], s);
            legs = bytes.concat(legs, to[j].y, cOut, cAud);
            total += vs[j];
        }
        (,bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(ver, from.y, from.y, aud, total, s);
        payload = bytes.concat(
            abi.encode(uint256(st.accSeq), uint256(st.sendCounter), to.length), from.y, dOut, cDeb, legs
        );
    }

    /// @dev Payload and proof of an unshield of `amount` to `recipient` from the acc balance `b`.
    function _proveUnshield(ZetherLayer t, User memory from, uint256 amount, uint256 b, address recipient, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (bytes memory payload, bytes memory proof)
    {
        payload = _unshieldPayload(t, from);
        bytes memory statement = stm.unshieldStatement(address(t), payload, amount, recipient, ben, binding);
        proof = _proveU(from, statement, amount, b, ben, t);
    }

    function _proveU(User memory from, bytes memory statement, uint256 amount, uint256 b, ZetherTypes.UA ben, ZetherLayer t)
        internal view returns (bytes memory)
    {
        b = b - amount - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()); // from here: b'
        return prover.proveBurn(ver, statement, ZetherProver.BurnWitness(from.x, b, 0x9abc + b, keccak256(abi.encode(b, amount))));
    }

    function _unshieldPayload(ZetherLayer t, User memory from) internal view returns (bytes memory) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y);
    }

    function _direct(ZetherLayer t, Tx memory r, ZetherTypes.UA ben) internal returns (bytes32) {
        return t.zetherTransferSingle(r.payload, r.proof, "", ben);
    }

    // ------------------------------------------------------------------ disclosure (ZetherDisclosure)

    /// @dev `verifyTransferAmount` through `ZetherDisclosure`: one outside call, so `vm.expectRevert` catches it.
    function _vta(
        ZetherLayer t,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes memory opening,
        bytes memory bundles
    ) internal view returns (bool) {
        return dis.verifyTransferAmount(address(t), ref, j, amount, kind, opening, bundles);
    }

    /// @dev Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)` with key `x` on base `base` (`D_out` for
    ///      RECEIVER_X/AUDITOR, `Y_tj` for SENDER_CP), leg `j` of `ref`; the challenge carries `chainUid` (CTR-ZTH-36).
    function _cpOpening(
        ZetherLayer t,
        uint256 x,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes memory base
    ) internal view returns (bytes memory) {
        uint256 r = ver.groupOrder();
        uint256 k = uint256(keccak256(abi.encode("cp", x, ref, j, amount, kind))) % r;
        bytes memory a1 = ver.g1MulBase(k);
        bytes memory a2 = ver.g1Mul(base, k);
        uint256 e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", block.chainid, t.chainUid(), address(t)),
            abi.encodePacked(ref, j, amount, uint8(kind), a1, a2)
        )), r);
        return abi.encode(a1, a2, addmod(k, mulmod(e, x, r), r));
    }

    function _none() internal pure returns (ZetherTypes.UA) {
        return ZetherTypes.UA.wrap(bytes32(0));
    }

    /// @dev `entryRef` (CTR-ZTH-36) of `from`'s debit number `counter`.
    function _ref(ZetherLayer t, User memory from, uint256 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("SCAAS-ZETHER-ENTRY-V1"), block.chainid, t.chainUid(), address(t), from.ua, counter
        ));
    }

    // ------------------------------------------------------------------ test-side decryption

    /// @dev `[b]G = C − [x]D`, `b` found in `[0, max]` by a linear scan (small test numbers).
    function _decrypt(bytes memory c, bytes memory d, uint256 x, uint256 max) internal view returns (uint256) {
        bytes memory m = ver.g1Sub(c, ver.g1Mul(d, x));
        bytes memory g = ver.g1MulBase(1);
        bytes memory acc = ver.identity();
        for (uint256 b; b <= max; ++b) {
            if (keccak256(acc) == keccak256(m)) return b;
            acc = ver.g1Add(acc, g);
        }
        revert("decrypt: out of range");
    }

    /// @dev check_balance: `[b]G == C − [x]D`, one point comparison, any balance.
    function _holds(ZetherLayer t, User memory u, uint256 b, bool acc) internal view returns (bool) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        (bytes memory c, bytes memory d) = acc ? (s.accC, s.accD) : (s.pendingC, s.pendingD);
        return keccak256(ver.g1Sub(c, ver.g1Mul(d, u.x))) == keccak256(ver.g1MulBase(b));
    }

    function _balances(ZetherLayer t, User memory u, uint256 max) internal view returns (uint256 acc, uint256 pend) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        acc = _decrypt(s.accC, s.accD, u.x, max);
        pend = _decrypt(s.pendingC, s.pendingD, u.x, max);
    }

    /// @dev Conservation: Σ plaintext balances (acc + pending, each decrypted with its owner's key) == totalShielded,
    ///      and the public units the fixture created == `totalSupply + totalShielded·SCALE` (shield burns them, unshield
    ///      mints them back).
    function _assertConservation(ZetherLayer t, uint256 max) internal view virtual {
        User[3] memory us = [alice, bob, carol];
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            (uint256 a, uint256 p) = _balances(t, us[i], max);
            sum += a + p;
        }
        assertEq(sum, t.totalShielded(), "sum of plaintext balances == totalShielded");
        assertEq(t.totalSupply() + t.totalShielded() * SCALE, minted[address(t)], "public + shielded x scale == created");
    }
}
```

- [ ] **Step 6: `test/zether/ZetherNone.t.sol`** (new; port of the built `ZetherToken.t` minus relaying, plus shield,
  the header pin, the `chainUid` digests and challenge; both curves):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";

/// @notice The whole life of a `NONE_ZETHER` token (a factory clone, the real verifier, real proofs from the test
///         prover), on BOTH curves through the two contracts at the end: shield from the public balance, transfer,
///         roll-over, unshield into public units; replay protection; `chainUid` in every digest (CTR-ZTH-36);
///         disclosure.
abstract contract ZetherNoneSuite is ZetherFixture {
    function _curve() internal pure virtual returns (bool);

    function setUp() public {
        _deploy(_curve(), true);
    }

    function _bal(User memory u) internal view returns (uint256 a, uint256 p) {
        return _balances(tok, u, 1100);
    }

    function _vta(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening)
        internal view returns (bool)
    {
        return _vta(tok, ref, 0, amount, kind, opening, "");
    }

    // ------------------------------------------------------------------ life cycle and conservation

    function test_lifecycleShieldTransferRollOverUnshield() public {
        _fund(tok, alice, 1000);
        _assertConservation(tok, 1100);
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 0);
        assertEq(p, 1000, "shield lands in pending");
        assertEq(tok.balanceOf(address(this)), 0, "the public units were burnt");

        tok.zetherRollOver(alice.ua);
        (a, p) = _bal(alice);
        assertEq(a, 1000);
        assertEq(p, 0);
        assertEq(tok.accountState(alice.ua).accSeq, 1);

        // alice → bob 300, inner fee FEE to carol (a public scalar)
        Tx memory t1 = _proveTransfer(tok, alice, bob, 300, 1000, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t1, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherTransferSingle (direct, auditor, fee) gas", g0 - gasleft());
        (a,) = _bal(alice);
        assertEq(a, 1000 - 300 - FEE, "sender acc debited v + fee");
        (, p) = _bal(bob);
        assertEq(p, 300, "receiver pending credited");
        (, p) = _bal(carol);
        assertEq(p, FEE, "beneficiary pending credited [fee]G");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid");
        _assertConservation(tok, 1100);

        // bob spends what he received: roll-over (PUBLIC, no signature), then 100 back
        tok.zetherRollOver(bob.ua);
        _direct(tok, _proveTransfer(tok, bob, alice, 100, 300, _none(), 0), _none());
        _assertConservation(tok, 1100);

        // bob unshields 50 into public units
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, 50, 200, address(0xD00D), _none(), 0);
        g0 = gasleft();
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD00D), 50);
        console2.log(bls ? "bls12-381" : "bn254", "zetherUnshield gas", g0 - gasleft());
        assertEq(tok.balanceOf(address(0xD00D)), 50 * SCALE);
        (a,) = _bal(bob);
        assertEq(a, 150);

        // alice rolls the 100 over, then unshields 700 with a fee to carol
        tok.zetherRollOver(alice.ua);
        (pl, pr) = _proveUnshield(tok, alice, 700, 798, address(0xD00D), carol.ua, 0);
        tok.zetherUnshield(pl, pr, "", carol.ua, address(0xD00D), 700);
        (a,) = _bal(alice);
        assertEq(a, 798 - 700 - FEE);
        (, p) = _bal(carol);
        assertEq(p, 2 * FEE);
        assertEq(tok.totalShielded(), 1000 - 750);
        assertEq(tok.balanceOf(address(0xD00D)), 750 * SCALE);
        _assertConservation(tok, 1100);
    }

    function test_shieldAndRollOverGas() public {
        _public(tok, address(this), 1000 * SCALE);
        uint256 g0 = gasleft();
        tok.zetherShield(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "zetherShield (first credit) gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherShield(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "zetherShield (warm) gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherRollOver(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOver gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherRollOver(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOver no-op gas", g0 - gasleft());
    }

    /// CTR-ZTH-35: the caller's public units, exactly `amount · shieldScale`; shield to anyone registered; the cap.
    function test_shieldBurnsTheCallersPublicUnits() public {
        _public(tok, address(this), 30 * SCALE + 1);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.ZetherShielded(bob.ua, 30);
        tok.zetherShield(bob.y, 30); // to someone else's account
        assertEq(tok.balanceOf(address(this)), 1, "30 x scale burnt, the rest kept");
        assertEq(tok.totalShielded(), 30);
        assertEq(tok.totalSupply(), 1);
        assertTrue(_holds(tok, bob, 30, false));
        assertEq(tok.accountState(bob.ua).pendingSeq, 1);
        bytes memory err = abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", address(this), 1, SCALE);
        vm.expectRevert(err);
        tok.zetherShield(bob.y, 1);
        // the cap counts every account: room = max − totalShielded
        ZetherLayer small = _newToken(false, "small", 100);
        _public(small, address(this), 101 * SCALE);
        small.zetherShield(alice.y, 60);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 41, 40));
        small.zetherShield(bob.y, 41);
        small.zetherShield(bob.y, 40);
        assertEq(small.totalShielded(), 100);
    }

    // ------------------------------------------------------------------ the statement (zether.md §7)

    /// The token's statement carries the 13-word header with `chainUid` at word 3 (CTR-ZTH-36), the token, the
    /// binding tag; the view and the token build the very same bytes (a proof of the view's statement passes).
    function test_statementHeaderCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
        bytes memory st = stm.transferStatementSingle(address(tok), t.payload, carol.ua, 0);
        bytes memory head = new bytes(416);
        for (uint256 i; i < 416; ++i) head[i] = st[i];
        bytes memory expected = bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"), ver.proofSystemId(), block.chainid, ZUID, address(tok),
                keccak256("ZTX_V1_DIRECT"), bytes32(0)),
            abi.encode(uint256(0), uint256(1), FEE, carol.ua, uint256(0), address(0))
        );
        assertEq(head, expected);
        assertEq(tok.chainUid(), ZUID);
        // unshield: amount and recipient at words 11 and 12
        (bytes memory pl,) = _proveUnshield(tok, alice, 7, 500, address(0xD00D), _none(), 0);
        st = stm.unshieldStatement(address(tok), pl, 7, address(0xD00D), _none(), 0);
        (uint256 amount, address rcp) = abi.decode(_cut(st, 352, 64), (uint256, address));
        assertEq(amount, 7);
        assertEq(rcp, address(0xD00D));
        assertEq(bytes32(_cut(st, 0, 32)), keccak256("SCAAS-ZETHER-OP-BURN-V1"));
        assertEq(bytes32(_cut(st, 96, 32)), ZUID);
        _direct(tok, t, carol.ua);
    }

    // ------------------------------------------------------------------ roll-over, two modes

    function test_rollOverIsNoOpWithoutNewCredit() public {
        _fund(tok, alice, 10);
        tok.zetherRollOver(alice.ua);
        tok.zetherRollOver(alice.ua); // no revert, no bump
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](2);
        (batch[0], batch[1]) = (alice.ua, bob.ua);
        tok.zetherRollOverBatch(batch);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function _modeSig(User memory u, ZetherTypes.RollOverMode mode, uint64 nonce, uint64 until)
        internal view returns (bytes memory)
    {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, uint8(mode), nonce, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    function _rollSig(User memory u, uint64 accSeq, uint64 pendSeq, uint64 until) internal view returns (bytes memory) {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, accSeq, pendSeq, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    /// CTR-ZTH-36: a mode or roll-over signature over the digest without `chainUid` (a captured signature from a
    /// re-created chain, whose counters restarted) is refused.
    function test_rollOverAndModeDigestsCarryChainUid() public {
        uint64 until = uint64(block.number + 50);
        bytes32 noUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint8(ZetherTypes.RollOverMode.OWNER_ONLY), uint64(0), until)
        ));
        bytes memory bad = abi.encode(alice.y, ZetherKeys.schnorr(alice.x, noUid, bls));
        vm.expectRevert();
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, bad);
        _fund(tok, alice, 10);
        bytes32 rollNoUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint64(0), uint64(1), until)
        ));
        bad = abi.encode(alice.y, ZetherKeys.schnorr(alice.x, rollNoUid, bls));
        vm.expectRevert();
        tok.zetherRollOverSigned(alice.ua, 1, until, bad);
        tok.zetherRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    /// A griefer with balance 0 slips a `v = 0` transfer before `zetherRollOverSigned`: `pendingSeq` moves on but the
    /// owner's roll-over still runs (merging the new credit too); the signature cannot replay (`accSeq` moved).
    function test_rollOverSignedSurvivesFrontRunCredit() public {
        uint64 until = uint64(block.number + 50);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        bytes memory rs = _rollSig(alice, 0, 1, until);
        _direct(tok, _proveTransfer(tok, bob, alice, 0, 0, _none(), 0), _none());
        assertEq(tok.accountState(alice.ua).pendingSeq, 2);
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);
        _fund(tok, alice, 5);
        // the replay stops at the new-credit gate (1 ≤ lastRolled = 2), before the signature (accSeq moved too)
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 3));
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
    }

    /// CTR-ZTH-17: a signature that names no new credit is refused (it would be a reusable no-op ticket).
    function test_rollOverSignedWithoutNewCreditIsRejected() public {
        uint64 until = uint64(block.number + 50);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        tok.zetherRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        bytes memory stale = _rollSig(alice, 1, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 1));
        tok.zetherRollOverSigned(alice.ua, 1, until, stale);
        _fund(tok, alice, 5);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 2));
        tok.zetherRollOverSigned(alice.ua, 1, until, stale);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function test_setRollOverModeExpired() public {
        uint64 until = uint64(block.number + 5);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
    }

    function test_ownerOnlyRollOver() public {
        uint64 until = uint64(block.number + 50);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.RollOverModeChanged(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        assertEq(tok.accountState(alice.ua).modeNonce, 1);
        vm.expectRevert(); // the old signature again: modeNonce moved
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        _fund(tok, alice, 10);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverOwnerOnly.selector, alice.ua));
        tok.zetherRollOver(alice.ua);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](1);
        batch[0] = alice.ua;
        tok.zetherRollOverBatch(batch); // skipped, no revert
        assertEq(tok.accountState(alice.ua).accSeq, 0);

        bytes memory rs = _rollSig(alice, 0, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 2, 1));
        tok.zetherRollOverSigned(alice.ua, 2, until, rs);
        uint256 g0 = gasleft();
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOverSigned (Schnorr) gas", g0 - gasleft());
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);

        // an expired roll-over signature: "hold the blob" blocked by validUntilBlock
        _fund(tok, alice, 5);
        bytes memory late = _rollSig(alice, 1, 2, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.zetherRollOverSigned(alice.ua, 2, until, late);
    }

    function test_rollOverSignedRejectsForeignSignature() public {
        uint64 until = uint64(block.number + 50);
        _fund(tok, alice, 10);
        bytes memory forged = _rollSig(bob, 0, 1, until); // bob signs for alice
        vm.expectRevert();
        tok.zetherRollOverSigned(alice.ua, 1, until, forged);
    }

    // ------------------------------------------------------------------ acc/pending race

    /// A credit that arrives between proving and submitting changes only pending: the proof stays valid.
    function test_incomingCreditDoesNotKillInFlightProof() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7); // someone sends alice dust
        _direct(tok, t, _none());
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 400);
        assertEq(p, 7);
    }

    /// A roll-over in between moves `accSeq`: the old proof is refused cheaply, before verification.
    function test_rollOverBetweenProveAndSubmitRejectsCheaply() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7);
        tok.zetherRollOver(alice.ua);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleAccSeq.selector, 2, 1));
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ replay

    function test_replaySameProofRejected() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _direct(tok, t, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        _direct(tok, t, _none());
    }

    /// Same verifier, registry, accSeq/sendCounter on another token: the header (token) differs ⇒ refused.
    function test_replayAcrossTokensRejected() public {
        ZetherLayer other = _newToken(true, "zusd-2");
        _fund(tok, alice, 500);
        _fund(other, alice, 500);
        tok.zetherRollOver(alice.ua);
        other.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(other, t, _none());
        _direct(tok, t, _none()); // on the right token it passes
    }

    function test_replayAcrossChainsRejected() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.chainId(1337); // another dev chain, same state
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ disclosure (ITransferDisclosure)

    /// @dev Chaum-Pedersen opening of leg 0: RECEIVER_X/AUDITOR on base `D_out`, SENDER_CP on `Y_t` (key `s`).
    function _cpOpening(uint256 x, bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind)
        internal view returns (bytes memory)
    {
        (bytes memory ct, bytes memory yt) = dis.transferCiphertext(address(tok), ref, 0, "");
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP ? yt : _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        return _cpOpening(tok, x, ref, 0, amount, kind, base);
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function test_disclosureFourOpenings() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        // the sender opens with s
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 124, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // the recipient opens with x_to, without the sender
        bytes memory rx = _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertFalse(_vta(ref, 122, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        bytes memory wrong = _cpOpening(alice.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, wrong));
        // the auditor opens C_aud
        bytes memory au = _cpOpening(X_AUD, ref, 123, ITransferDisclosure.OpeningKind.AUDITOR);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.AUDITOR, au));
        // the sender opens the leg by Chaum-Pedersen on `s`, without handing `s` over (CTR-ZTH-40)
        bytes memory cp = _cpOpening(t.s, ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP, cp));
        assertFalse(_vta(ref, 124, ITransferDisclosure.OpeningKind.SENDER_CP, cp));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, cp), "kind is bound");
        // aliases mod r and values past n_v are refused
        assertFalse(_vta(ref, 123 + ver.groupOrder(), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 1 << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // malformed openings: s not 32 bytes, A1 of the wrong length, z ≥ r
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, new bytes(31));
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(rx, (bytes, bytes, uint256));
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, abi.encode(new bytes(1), a2, z));
        bytes memory zBig = abi.encode(a1, a2, ver.groupOrder());
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, zBig);
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 0, "");
        assertEq(yTo, bob.y);
        assertEq(ct.length, 3 * ver.g1EncodedBytes());
        assertEq(address(tok.disclosure()), address(dis), "canonical disclosure from the token");
    }

    /// CTR-ZTH-36: the disclosure challenge carries `chainUid`; an opening made without it fails.
    function test_disclosureChallengeCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0, "");
        bytes memory dOut = _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        uint256 r = ver.groupOrder();
        uint256 k = 0x5151;
        bytes memory a1 = ver.g1MulBase(k);
        bytes memory a2 = ver.g1Mul(dOut, k);
        uint256 e = uint256(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", block.chainid, address(tok)),
            abi.encodePacked(ref, uint256(0), uint256(123), uint8(1), a1, a2)
        )));
        e = _h2s(e, r);
        bytes memory noUid = abi.encode(a1, a2, addmod(k, mulmod(e, bob.x, r), r));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, noUid));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X)));
    }

    function _h2s(uint256 seed, uint256 r) internal pure returns (uint256) {
        uint256 hi = uint256(keccak256(abi.encodePacked(bytes32(seed), uint8(2))));
        uint256 lo = uint256(keccak256(abi.encodePacked(bytes32(seed), uint8(3))));
        return addmod(mulmod(hi, (type(uint256).max % r) + 1, r), lo, r);
    }

    /// CTR-ZTH-42, single format: the token has an auditor, the sender leaves it out (`C_aud = O`, statement `Y_a = O`).
    function test_singleAuditorOptOut() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        audOut = true;
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        audOut = false;
        Tx memory on = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        // a proof of one choice does not pass under the other (Y_a is in the statement)
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferSingle(t.payload, on.proof, "", _none());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferSingle(on.payload, t.proof, "", _none());
        bytes32 ref = _direct(tok, t, _none());
        assertTrue(_holds(tok, bob, 123, false));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X)));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(t.s, ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP)));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, 123, ITransferDisclosure.OpeningKind.AUDITOR)), "auditor reads nothing");
        assertFalse(_vta(ref, 0, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, 0, ITransferDisclosure.OpeningKind.AUDITOR)));
    }

    /// n_v = 64: a transfer > 2^32 units, a balance > 2^44 held, spent (the whole balance in one transfer) and
    /// unshielded; a disclosure of an amount > 2^32 with every opening. Balances checked by `_holds`.
    function test_largeValuesNv64() public {
        tok = _newToken(true, "big", uint256(1) << 54);
        uint256 b0 = (uint256(1) << 44) + 12_345;
        _fund(tok, alice, b0);
        tok.zetherRollOver(alice.ua);
        assertTrue(_holds(tok, alice, b0, true), "acc holds > 2^44");
        uint256 v = (uint256(1) << 33) + 7;
        Tx memory t = _proveTransfer(tok, alice, bob, v, b0, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherTransferSingle v > 2^32 (direct, auditor, fee) gas", g0 - gasleft());
        uint256 b1 = b0 - v - FEE;
        assertTrue(_holds(tok, alice, b1, true), "sender acc = b - v - fee");
        assertTrue(_holds(tok, bob, v, false), "receiver pending = v");
        assertTrue(_holds(tok, carol, FEE, false), "beneficiary pending = fee");
        _discloseLarge(ref, v, t.s);
        _spendAllAndUnshield(b1, v);
    }

    function _discloseLarge(bytes32 ref, uint256 v, uint256 s) internal view {
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        bytes memory rx = _cpOpening(bob.x, ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, v, ITransferDisclosure.OpeningKind.AUDITOR)));
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(s, ref, v, ITransferDisclosure.OpeningKind.SENDER_CP)));
        assertFalse(_vta(ref, v - (uint256(1) << 32), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        assertFalse(_vta(ref, uint256(1) << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
    }

    function _spendAllAndUnshield(uint256 b1, uint256 v) internal {
        _direct(tok, _proveTransfer(tok, alice, bob, b1, b1, _none(), 0), _none());
        assertTrue(_holds(tok, alice, 0, true), "sender emptied");
        tok.zetherRollOver(bob.ua);
        uint256 bb = v + b1;
        assertTrue(_holds(tok, bob, bb, true), "receiver acc = v + b1");
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, bb, bb, address(0xD00D), _none(), 0);
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD00D), bb);
        assertEq(tok.balanceOf(address(0xD00D)), bb * SCALE);
        assertEq(tok.totalShielded(), FEE, "only carol's fee left shielded");
    }

    /// The auditor decrypts the disclosed transfer, nobody's balance.
    function test_auditorSeesTransferButNoBalance() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        bytes32 ref = _direct(tok, _proveTransfer(tok, alice, bob, 321, 500, _none(), 0), _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0, "");
        uint256 p = ver.g1EncodedBytes();
        assertEq(_decrypt(_cut(ct, 2 * p, p), _cut(ct, p, p), X_AUD, 400), 321, "auditor reads C_aud");
        IZetherToken.AccountState memory s = tok.accountState(alice.ua);
        vm.expectRevert(bytes("decrypt: out of range"));
        this.decryptExt(s.accC, s.accD, X_AUD, 1100); // alice's 179: the auditor cannot read it
        assertEq(_decrypt(s.accC, s.accD, alice.x, 1100), 179);
    }

    function decryptExt(bytes memory c, bytes memory d, uint256 x, uint256 max) external view returns (uint256) {
        return _decrypt(c, d, x, max);
    }
}

contract ZetherNoneBn254Test is ZetherNoneSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherNoneBls12381Test is ZetherNoneSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
```

- [ ] **Step 7: `test/zether/ZetherMulti.t.sol`** (new; port of the built one: the renamed entry points, `entryRef`
  with `chainUid`, the statement view on `ZetherStatements`; both curves):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// @notice Multi-recipient transfers (CTR-ZTH-37/38) on a `NONE_ZETHER` token: effects, refusals, disclosure in the
///         three modes and the gas table M ∈ {1, 2, 4, 8} × {HASH, BUNDLE, NONE}, on both curves.
abstract contract ZetherMultiSuite is ZetherFixture {
    User[8] internal rs;

    function _curve() internal pure virtual returns (bool);

    function setUp() public {
        _deploy(_curve(), true);
        for (uint256 i; i < 8; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
    }

    // ------------------------------------------------------------------ tiện ích

    function _to(uint256 m) internal view returns (User[] memory to) {
        to = new User[](m);
        for (uint256 j; j < m; ++j) to[j] = rs[j];
    }

    function _send(ZetherLayer t, ZetherTypes.TransferMode mode, Tx memory x, ZetherTypes.UA ben) internal returns (bytes32) {
        if (mode == ZetherTypes.TransferMode.HASH) return t.zetherTransfer(x.payload, x.proof, "", ben);
        if (mode == ZetherTypes.TransferMode.BUNDLE) return t.zetherTransferBundle(x.payload, x.proof, "", ben);
        return t.zetherTransferNoBundle(x.payload, x.proof, "", ben);
    }

    function _selector(ZetherTypes.TransferMode mode) internal pure returns (bytes4) {
        if (mode == ZetherTypes.TransferMode.HASH) return ZetherLayer.zetherTransfer.selector;
        if (mode == ZetherTypes.TransferMode.BUNDLE) return ZetherLayer.zetherTransferBundle.selector;
        return ZetherLayer.zetherTransferNoBundle.selector;
    }

    function _modeName(ZetherTypes.TransferMode mode) internal pure returns (string memory) {
        return mode == ZetherTypes.TransferMode.HASH ? "HASH" : mode == ZetherTypes.TransferMode.BUNDLE ? "BUNDLE" : "NONE";
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    /// @dev `B_1 ‖ … ‖ B_M` dựng lại từ payload (đúng thứ một client đọc được từ calldata).
    function _bundlesOf(bytes memory payload) internal view returns (bytes memory b) {
        uint256 p = ver.g1EncodedBytes();
        uint256 m = (payload.length - 96 - 3 * p) / (3 * p);
        bytes memory dOut = _cut(payload, 96 + p, p);
        for (uint256 j; j < m; ++j) {
            uint256 o = 96 + 3 * p + 3 * p * j;
            b = bytes.concat(b, _cut(payload, o, 2 * p), dOut, _cut(payload, o + 2 * p, p));
        }
    }

    function _replacePoint(bytes memory payload, uint256 off) internal view returns (bytes memory out) {
        uint256 p = ver.g1EncodedBytes();
        out = bytes.concat(payload);
        bytes memory np = ver.g1Add(_cut(payload, off, p), ver.g1MulBase(1));
        for (uint256 i; i < p; ++i) out[off + i] = np[i];
    }

    function _funded(uint256 amount) internal {
        _fund(tok, alice, amount);
        tok.zetherRollOver(alice.ua);
    }

    // ------------------------------------------------------------------ gas (spec §7)

    /// @dev Trạng thái mới cho mỗi ô (người nhận và beneficiary nhận credit lần đầu), như số đo của bản một người nhận.
    function _gasRun(uint256 m, ZetherTypes.TransferMode mode) internal {
        uint256 b = 1_000_000;
        _funded(b);
        uint256[] memory vs = new uint256[](m);
        vs[m / 2] = 1000; // một người nhận thật, còn lại là mồi nhận 0
        Tx memory t = _proveMulti(tok, alice, _to(m), vs, b, carol.ua, mode);
        uint256 cd = abi.encodeWithSelector(_selector(mode), t.payload, t.proof, bytes(""), carol.ua).length;
        uint256 g0 = gasleft();
        _send(tok, mode, t, carol.ua);
        uint256 used = g0 - gasleft();
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " zetherTransfer M=", vm.toString(m), " ", _modeName(mode),
            audOut ? " auditor-out" : "", " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - sum(v) - fee");
    }

    /// @dev Như `_gasRun`, định dạng một người nhận.
    function _gasSingle() internal {
        uint256 b = 1_000_000;
        _funded(b);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, b, carol.ua, 0);
        uint256 cd = abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), carol.ua)).length;
        uint256 g0 = gasleft();
        _direct(tok, t, carol.ua);
        uint256 used = g0 - gasleft();
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " zetherTransferSingle", audOut ? " auditor-out" : "",
            " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - v - fee");
    }

    function test_gasSingle() public { _gasSingle(); }
    function test_gasOutSingle() public { audOut = true; _gasSingle(); }

    function test_gasM1Hash() public { _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasM1Bundle() public { _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM1None() public { _gasRun(1, ZetherTypes.TransferMode.NONE); }
    function test_gasM2Hash() public { _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasM2Bundle() public { _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM2None() public { _gasRun(2, ZetherTypes.TransferMode.NONE); }
    function test_gasM4Hash() public { _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasM4Bundle() public { _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM4None() public { _gasRun(4, ZetherTypes.TransferMode.NONE); }
    function test_gasM8Hash() public { _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasM8Bundle() public { _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM8None() public { _gasRun(8, ZetherTypes.TransferMode.NONE); }
    // Z12: token có auditor, người gửi bỏ auditor (mọi C_aud = O)
    function test_gasOutM1Hash() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM1Bundle() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM1None() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM2Hash() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM2Bundle() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM2None() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM4Hash() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM4Bundle() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM4None() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM8Hash() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM8Bundle() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM8None() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.NONE); }

    // ------------------------------------------------------------------ hiệu lực

    function test_effectsDecoysAndConservation() public {
        _funded(1000);
        uint256[] memory vs = new uint256[](4);
        (vs[0], vs[1], vs[2], vs[3]) = (0, 300, 0, 50);
        uint256 seq = tok.accountState(rs[1].ua).pendingSeq;
        Tx memory t = _proveMulti(tok, alice, _to(4), vs, 1000, carol.ua, ZetherTypes.TransferMode.HASH);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, carol.ua);
        assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid (CTR-ZTH-36)");
        assertTrue(_holds(tok, alice, 1000 - 350 - FEE, true), "sender debited sum + fee");
        for (uint256 j; j < 4; ++j) {
            assertTrue(_holds(tok, rs[j], vs[j], false), "recipient pending = its v (decoys 0)");
        }
        assertEq(tok.accountState(rs[1].ua).pendingSeq, seq + 1, "every recipient gets a credit");
        assertEq(tok.accountState(rs[0].ua).pendingSeq, 1, "decoys too");
        assertTrue(_holds(tok, carol, FEE, false), "beneficiary");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(tok.totalShielded(), 1000, "nothing created or destroyed");
    }

    function test_auditorOffToken() public {
        tok = _newToken(false, "noaud");
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (0, 40);
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 40, false));
        assertTrue(_holds(tok, alice, 460, true));
    }

    // ------------------------------------------------------------------ chặn

    function test_rejectsBadShapes() public {
        _funded(1000);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (5, 6);
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 1000, _none(), ZetherTypes.TransferMode.HASH);
        uint256 p = ver.g1EncodedBytes();
        // M = 0 and M = 17
        bytes memory pl = bytes.concat(t.payload);
        pl[95] = bytes1(0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 0));
        tok.zetherTransfer(pl, t.proof, "", _none());
        pl[95] = bytes1(uint8(17));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 17));
        tok.zetherTransfer(pl, t.proof, "", _none());
        // M = 3 with two legs: length
        pl[95] = bytes1(uint8(3));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.zetherTransfer(pl, t.proof, "", _none());
        // duplicate recipient, self, unregistered
        User[] memory dup = _to(2);
        dup[1] = dup[0];
        Tx memory d = _proveMultiUnchecked(dup, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.DuplicateRecipient.selector, rs[0].ua));
        tok.zetherTransfer(d.payload, t.proof, "", _none());
        User[] memory self = _to(2);
        self[1] = alice;
        d = _proveMultiUnchecked(self, vs);
        vm.expectRevert(IZetherToken.SelfTransfer.selector);
        tok.zetherTransfer(d.payload, t.proof, "", _none());
        User[] memory stranger = _to(2);
        stranger[1].y = _pubOf(0x5757);
        stranger[1].ua = ZetherTypes.toUA(stranger[1].y);
        d = _proveMultiUnchecked(stranger, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, stranger[1].ua));
        tok.zetherTransfer(d.payload, t.proof, "", _none());
        // tampered C_deb, C_out_2, C_aud_1
        uint256[3] memory offs = [96 + 2 * p, 96 + 3 * p + 3 * p + p, 96 + 3 * p + 2 * p];
        for (uint256 i; i < 3; ++i) {
            bytes memory tampered = _replacePoint(t.payload, offs[i]);
            vm.expectRevert(IZetherToken.ProofRejected.selector);
            tok.zetherTransfer(tampered, t.proof, "", _none());
        }
        // a HASH proof under another mode
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferBundle(t.payload, t.proof, "", _none());
        // valid, then replay
        tok.zetherTransfer(t.payload, t.proof, "", _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        tok.zetherTransfer(t.payload, t.proof, "", _none());
    }

    /// @dev Payload thôi (chưa proof) — các phép kiểm hình dạng chạy trước verify.
    function _proveMultiUnchecked(User[] memory to, uint256[] memory vs) internal view returns (Tx memory r) {
        r.payload = _multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua));
    }

    function _pubOf(uint256 x) internal view returns (bytes memory) {
        return ver.g1MulBase(x);
    }

    // ------------------------------------------------------------------ tiết lộ theo mode

    /// @dev Opening Chaum-Pedersen leg `j`: SENDER_CP trên cơ sở `Y_tj` bằng `s`, còn lại trên `D_out`.
    function _cp(uint256 x, bytes32 ref, uint256 j, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory payload)
        internal view returns (bytes memory)
    {
        uint256 p = ver.g1EncodedBytes();
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP
            ? _cut(payload, 96 + 3 * p + 3 * p * j, p)
            : _cut(payload, 96 + p, p);
        return _cpOpening(tok, x, ref, j, amount, kind, base);
    }

    function test_disclosureHashMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory bundles = _bundlesOf(t.payload);
        bytes32 expected = _ref(tok, alice, 0);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.TransferBundles(expected, bundles);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, _none());
        // HASH stores one slot (CTR-ZTH-38): `entryHashes[ref]` in `scaas.zether`, nothing under `entries[ref]`
        uint256 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 10))), keccak256(bundles));
        assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 9))), bytes32(0));
        assertEq(tok.transferEntry(ref), abi.encodePacked(keccak256(bundles)));
        _discloseAll(ref, t, bundles);
        // bundles that do not match the stored hash
        bytes memory wrong = bytes.concat(bundles);
        wrong[0] = bytes1(uint8(wrong[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), wrong);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), "");
    }

    function test_disclosureBundleMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        _discloseAll(ref, t, ""); // stored: no bundles needed
    }

    function test_disclosureNoBundleModeIsOffChainOnly() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.NONE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.NONE, t, _none());
        bytes memory bundles = _bundlesOf(t.payload);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), bundles);
        // off chain: the sender's s opens the leg read from calldata
        bytes memory b1 = _cut(_bundlesOf(t.payload), 4 * ver.g1EncodedBytes(), 4 * ver.g1EncodedBytes());
        uint256 p = ver.g1EncodedBytes();
        assertEq(ver.g1MulBase(t.s), _cut(b1, 2 * p, p), "D_out = [s]G");
        assertEq(ver.g1Add(ver.g1MulBase(77), ver.g1Mul(rs[1].y, t.s)), _cut(b1, p, p), "C_out = [v]G + [s]Y_t");
    }

    /// @dev Cả bốn opening trên leg thật, `s` mở cả leg mồi (owner Z3), opening không chuyển leg, chỉ số ngoài khoảng.
    function _discloseAll(bytes32 ref, Tx memory t, bytes memory bundles) internal {
        _discloseCp(ref, t, bundles);
        ITransferDisclosure.OpeningKind S = ITransferDisclosure.OpeningKind.SENDER_S;
        ITransferDisclosure.OpeningKind RX = ITransferDisclosure.OpeningKind.RECEIVER_X;
        assertTrue(_vta(tok, ref, 1, 77, S, abi.encode(t.s), bundles), "sender opens the real leg");
        assertFalse(_vta(tok, ref, 1, 78, S, abi.encode(t.s), bundles));
        assertTrue(_vta(tok, ref, 0, 0, S, abi.encode(t.s), bundles), "s also opens a decoy (Z3)");
        bytes memory rx = _cp(rs[1].x, ref, 1, 77, RX, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, RX, rx, bundles));
        assertFalse(_vta(tok, ref, 2, 77, RX, rx, bundles), "an opening does not move to another leg");
        bytes memory au = _cp(X_AUD, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, t.payload);
        assertEq(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, au, bundles), !audOut,
            "auditor opens unless left out (Z12)");
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BadRecipientIndex.selector, 3));
        _vta(tok, ref, 3, 0, S, abi.encode(t.s), bundles);
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 1, bundles);
        assertEq(yTo, rs[1].y);
        assertEq(ct.length, 3 * ver.g1EncodedBytes());
    }

    /// @dev SENDER_CP (Z10): chỉ leg j mở, challenge ràng j.
    function _discloseCp(bytes32 ref, Tx memory t, bytes memory bundles) internal view {
        ITransferDisclosure.OpeningKind CP = ITransferDisclosure.OpeningKind.SENDER_CP;
        bytes memory cp = _cp(t.s, ref, 1, 77, CP, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, CP, cp, bundles), "sender CP opens leg 1");
        assertFalse(_vta(tok, ref, 1, 78, CP, cp, bundles), "wrong amount");
        assertFalse(_vta(tok, ref, 0, 77, CP, cp, bundles), "wrong leg");
        assertFalse(_vta(tok, ref, 0, 0, CP, cp, bundles), "a proof for leg 1 does not open leg 0");
        assertFalse(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, cp, bundles), "kind is bound");
        bytes memory cp0 = _cp(t.s, ref, 0, 0, CP, t.payload);
        assertTrue(_vta(tok, ref, 0, 0, CP, cp0, bundles), "decoy opens with its own proof");
        assertFalse(_vta(tok, ref, 1, 0, CP, cp0, bundles));
    }

    // ------------------------------------------------------------------ bỏ auditor theo transfer (Z12)

    function test_auditorOptOut() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        audOut = true;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        audOut = false;
        Tx memory on = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        // Y_a nằm trong statement: proof của lựa chọn này không qua dưới lựa chọn kia
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferBundle(t.payload, on.proof, "", _none());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferBundle(on.payload, t.proof, "", _none());
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 77, false));
        assertTrue(_holds(tok, alice, 423, true));
        audOut = true;
        _discloseAll(ref, t, "");
    }

    function test_auditorLegsMixedReverts() public {
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[1] = 9;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        uint256 p = ver.g1EncodedBytes();
        bytes memory pl = bytes.concat(t.payload);
        for (uint256 i; i < p; ++i) pl[96 + 5 * p + i] = 0; // C_aud_1 = O, C_aud_2 ≠ O
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        tok.zetherTransfer(pl, t.proof, "", _none());
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
    }

    /// Token không có auditor: C_aud ≠ O không "bật" được auditor — statement giữ Y_a = O, verifier từ chối.
    function test_auditorOffTokenRejectsCAud() public {
        tok = _newToken(false, "noaud2");
        _funded(500);
        uint256[] memory vs = new uint256[](1);
        vs[0] = 5;
        Tx memory t = _proveMulti(tok, alice, _to(1), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory pl = _replacePoint(t.payload, 96 + 5 * ver.g1EncodedBytes());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransfer(pl, t.proof, "", _none());
    }

    // ------------------------------------------------------------------ bên thứ ba on-chain

    function test_thirdPartyContractVerifiesOnChain() public {
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[0] = 31;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        Escrow3P esc = new Escrow3P();
        bytes memory cp = _cp(t.s, ref, 0, 31, ITransferDisclosure.OpeningKind.SENDER_CP, t.payload);
        assertTrue(esc.release(IZetherToken(address(tok)), ref, 0, 31, cp));
        assertEq(esc.released(ref), 31);
        vm.expectRevert(bytes("not proven"));
        esc.release(IZetherToken(address(tok)), ref, 0, 32, cp);
    }

    // ------------------------------------------------------------------ gas tiết lộ (spec §7 b)

    /// @dev Gas on-chain của `verifyTransferAmount` gọi từ một contract (`Escrow3P.measure`), token/disclosure
    ///      làm nguội trước mỗi lần đo (như một giao dịch mới: account và slot bundle lạnh).
    function _measure(Escrow3P esc, bytes32 ref, uint256 j, uint256 k, bytes memory o, bytes memory bundles)
        internal returns (uint256)
    {
        vm.cool(address(tok));
        vm.cool(address(dis));
        vm.cool(address(ver));
        return esc.measure(IZetherToken(address(tok)), ref, j, 1000, ITransferDisclosure.OpeningKind(k), o, bundles);
    }

    function _gasKinds(string memory tag, bytes32 ref, uint256 j, bytes[4] memory o, bytes memory bundles) internal {
        Escrow3P esc = new Escrow3P();
        string[4] memory names = ["SENDER_S", "RECEIVER_X", "AUDITOR", "SENDER_CP"];
        for (uint256 k; k < 4; ++k) {
            console2.log(string.concat(
                bls ? "bls12-381" : "bn254", " disclose ", tag, " ", names[k], " gas ",
                vm.toString(_measure(esc, ref, j, k, o[k], bundles)), " bundles ", vm.toString(bundles.length)
            ));
        }
    }

    /// @dev Leg thật là leg cuối (`j = M − 1`).
    function _gasDisclose(uint256 m, ZetherTypes.TransferMode mode) internal {
        _funded(1_000_000);
        uint256[] memory vs = new uint256[](m);
        uint256 j = m - 1;
        vs[j] = 1000;
        Tx memory t = _proveMulti(tok, alice, _to(m), vs, 1_000_000, _none(), mode);
        bytes32 ref = _send(tok, mode, t, _none());
        bytes memory bundles = mode == ZetherTypes.TransferMode.HASH ? _bundlesOf(t.payload) : bytes("");
        bytes[4] memory o = [
            abi.encode(t.s),
            _cp(rs[j].x, ref, j, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, t.payload),
            _cp(X_AUD, ref, j, 1000, ITransferDisclosure.OpeningKind.AUDITOR, t.payload),
            _cp(t.s, ref, j, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, t.payload)
        ];
        _gasKinds(string.concat("M=", vm.toString(m), " ", _modeName(mode)), ref, j, o, bundles);
    }

    function test_gasDiscloseM1Bundle() public { _gasDisclose(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM8Bundle() public { _gasDisclose(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM1Hash() public { _gasDisclose(1, ZetherTypes.TransferMode.HASH); }
    function test_gasDiscloseM8Hash() public { _gasDisclose(8, ZetherTypes.TransferMode.HASH); }

    function test_gasDiscloseSingle() public {
        _funded(1_000_000);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        bytes memory dOut = _cut(t.payload, 64 + 3 * ver.g1EncodedBytes(), ver.g1EncodedBytes()); // Y_f Y_t C_out D_out …
        bytes[4] memory o = [
            abi.encode(t.s),
            _cpOpening(tok, rs[0].x, ref, 0, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut),
            _cpOpening(tok, X_AUD, ref, 0, 1000, ITransferDisclosure.OpeningKind.AUDITOR, dOut),
            _cpOpening(tok, t.s, ref, 0, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, rs[0].y)
        ];
        _gasKinds("Single", ref, 0, o, "");
    }
}

/// @notice A third-party contract: finds the canonical `ZetherDisclosure` from the token and checks on chain. No
///         attestation (CTR-ZTH-39): whoever needs an on-chain trace records it, as `released` here.
contract Escrow3P {
    mapping(bytes32 => uint256) public released;

    function release(IZetherToken token, bytes32 ref, uint256 j, uint256 amount, bytes calldata opening)
        external returns (bool)
    {
        bool ok = token.disclosure().verifyTransferAmount(
            address(token), ref, j, amount, ITransferDisclosure.OpeningKind.SENDER_CP, opening, ""
        );
        require(ok, "not proven");
        released[ref] = amount;
        return true;
    }

    /// @dev `gasleft()` quanh đúng lời gọi `verifyTransferAmount`; phải trả true.
    function measure(
        IZetherToken token,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes calldata opening,
        bytes calldata bundles
    ) external view returns (uint256 used) {
        ITransferDisclosure d = token.disclosure();
        uint256 g0 = gasleft();
        bool ok = d.verifyTransferAmount(address(token), ref, j, amount, kind, opening, bundles);
        used = g0 - gasleft();
        require(ok, "not proven");
    }
}

contract ZetherMultiBn254Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherMultiBls12381Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
```

- [ ] **Step 8: `test/zether/ZetherRevertPaths.t.sol`** (new; the built envelope/escrow cases go with the old token,
  the new ones: config at creation, constructor immutables, minter, approve rule, namespace slot, verifier gate):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {G1Bn254} from "../../src/zether/ZetherCurves.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {AuthScheme} from "../../src/common/AuthScheme.sol";

/// @notice The revert paths of the confidential layer on `NONE_ZETHER` (the relaying ones are in `ZetherRelay.t`, the
///         underlying ones in `ZetherUnderlying.t`): shield, transfer and unshield shapes, the confidential config at
///         creation, the approve rule on the public side (CTR-TOK-01), the spending authority beside the proof.
contract ZetherRevertPathsTest is ZetherFixture {
    function setUp() public {
        _deploy(false, false);
    }

    function test_shieldRevertPaths() public {
        bytes memory stranger = ZetherKeys.pub(0x5757, false);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(stranger)));
        tok.zetherShield(stranger, 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.zetherShield(alice.y, 0);
        uint256 over = (uint256(1) << 40) + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, uint256(1) << 40));
        tok.zetherShield(alice.y, over);
        // a curve the token does not run: a BLS key on a bn254 token is not registered here
        bytes memory blsKey = ZetherKeys.pub(0x7777, true);
        bytes memory pop = abi.encode(ZetherKeys.schnorr(0x7777, reg.popChallenge(blsKey, address(0xB15)), true), bytes(""));
        vm.prank(address(0xB15));
        ZetherTypes.UA blsUa = reg.register(blsKey, AuthScheme.SELF_SCHNORR, "", pop, false);
        assertFalse(tok.registered(blsUa));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, blsUa));
        tok.zetherShield(blsKey, 1);
    }

    function _aliceTx() internal returns (Tx memory) {
        _fund(tok, alice, 100);
        tok.zetherRollOver(alice.ua);
        return _proveTransfer(tok, alice, bob, 10, 100, _none(), 0);
    }

    function _call(bytes memory payload, bytes memory proof, ZetherTypes.UA ben, bytes memory err) internal {
        vm.expectRevert(err);
        tok.zetherTransferSingle(payload, proof, "", ben);
    }

    function test_transferBadPayloadLength() public {
        Tx memory t = _aliceTx();
        bytes memory longPl = bytes.concat(t.payload, hex"00");
        _call(longPl, t.proof, _none(), abi.encodeWithSelector(IZetherToken.BadPayload.selector, longPl.length));
    }

    function test_transferToSelfRejected() public {
        Tx memory t = _aliceTx();
        for (uint256 i; i < 64; ++i) t.payload[128 + i] = t.payload[64 + i]; // Y_to := Y_from
        _call(t.payload, t.proof, _none(), abi.encodeWithSelector(IZetherToken.SelfTransfer.selector));
    }

    function test_transferToUnregisteredRejected() public {
        Tx memory t = _aliceTx();
        bytes memory gy = ZetherKeys.pub(0x6057, false);
        for (uint256 i; i < 64; ++i) t.payload[128 + i] = gy[i];
        _call(t.payload, t.proof, _none(),
            abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(gy)));
    }

    /// The fee is no back door to register an account: the beneficiary must be registered.
    function test_unregisteredBeneficiaryRejected() public {
        Tx memory t = _aliceTx();
        ZetherTypes.UA ghost = ZetherTypes.toUA(ZetherKeys.pub(0x6057, false));
        _call(t.payload, t.proof, ghost, abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ghost));
    }

    /// Amount and recipient are in the statement; checks before any precompile.
    function test_unshieldRevertPaths() public {
        _fund(tok, alice, 100);
        tok.zetherRollOver(alice.ua);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, 100, address(0xD), _none(), 0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD), 0);
        uint256 over = (uint256(1) << 40) + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, uint256(1) << 40));
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD), over);
        vm.expectRevert(IZetherToken.ZeroRecipient.selector);
        tok.zetherUnshield(pl, pr, "", _none(), address(0), 10);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, pl.length - 1));
        tok.zetherUnshield(_trim(pl), pr, "", _none(), address(0xD), 10);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // another recipient than the proven one
        tok.zetherUnshield(pl, pr, "", _none(), address(0xE), 10);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // another amount
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD), 11);
        // to the token itself: the proof passes, the mint is refused (CTR-MTX-18)
        (bytes memory pl2, bytes memory pr2) = _proveUnshield(tok, alice, 10, 100, address(tok), _none(), 0);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        tok.zetherUnshield(pl2, pr2, "", _none(), address(tok), 10);
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD), 10);
        assertEq(tok.balanceOf(address(0xD)), 10 * SCALE);
        assertEq(tok.totalShielded(), 90);
    }

    function _trim(bytes memory a) internal pure returns (bytes memory out) {
        out = new bytes(a.length - 1);
        for (uint256 i; i < out.length; ++i) out[i] = a[i];
    }

    /// The inner fee `< 2^n_v` (n_v = 64) and `< maxShielded` (a fee at the cap would make every transfer with a
    /// beneficiary unprovable): 2^32 and cap − 1 create, the cap and 2^64 − 1 do not.
    function test_confidentialFeeBound() public {
        uint256 max = uint256(1) << 40;
        uint256[2] memory ok = [uint256(1) << 32, max - 1];
        for (uint256 i; i < ok.length; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(false, max);
            c.conf.confidentialFee = ok[i];
            ZetherLayer z = ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, bytes32(i + 900)));
            assertEq(z.confidentialFee(), ok[i]);
        }
        uint256[2] memory bad = [max, (uint256(1) << 64) - 1];
        for (uint256 i; i < bad.length; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(false, max);
            c.conf.confidentialFee = bad[i];
            vm.expectRevert(IZetherToken.BadInit.selector);
            factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, bytes32(i + 910));
        }
    }

    /// The confidential config at creation (CTR-ZTH-04, -09, -26); the kind's flags (CTR-ZTH-47); the dev-chain gate in
    /// `initialize` (a clone made by hand, around the factory).
    function test_initializeRevertPaths() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        noneImpl.initialize(address(this), 1, c);
        vm.prank(address(factory));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        NoUnderlyingZetherToken(address(tok)).initialize(address(this), 1, c);
        IFactoryToken.TokenConfig[6] memory bad;
        for (uint256 i; i < 6; ++i) bad[i] = _cfg(false, uint256(1) << 40);
        bad[0].conf.shieldScale = 0;
        bad[1].conf.maxShielded = (uint256(1) << 54) + 1;               // > 2^54
        bad[2].conf.maxShielded = 0;
        bad[3].conf.auditorKey = new bytes(64);                         // auditor = O
        bad[4].conf.auditorKey = abi.encodePacked(uint256(1), uint256(3)); // not on the curve
        bad[5].conf.auditorKey = ZetherKeys.pub(X_AUD, true);           // a BLS key on a bn254 token
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IZetherToken.BadInit.selector);
            factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, bad[i], bytes32(i + 100));
        }
        // cap · scale must not overflow
        IFactoryToken.TokenConfig memory big = _cfg(false, uint256(1) << 40);
        big.conf.shieldScale = type(uint256).max / (uint256(1) << 40) + 1;
        vm.expectRevert(IZetherToken.BadInit.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, big, "overflow");
        // the kind's fields: legs and rate belong to other kinds; the regulated flags are refused
        IFactoryToken.TokenConfig memory r = _cfg(false, uint256(1) << 40);
        r.rate.rateDelay = 2 days;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 3));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, r, "rate");
        r = _cfg(false, uint256(1) << 40);
        r.features |= 1 << AdminLib.PAUSE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.PAUSE));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, r, "pause");
        r = _cfg(false, uint256(1) << 40);
        r.features |= 1 << AdminLib.WRAP_DISABLEABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.WRAP_DISABLEABLE));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, r, "wrap");
        // initialize outside a dev chain (a hand-made clone, around the factory gate)
        address cl = Clones.clone(address(noneImpl));
        vm.chainId(1);
        vm.prank(address(factory));
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        NoUnderlyingZetherToken(cl).initialize(address(this), 1, c);
    }

    /// The implementation's immutables need code: a registry and a disclosure contract.
    function test_constructorNeedsRegistryAndDisclosure() public {
        vm.expectRevert(IZetherToken.BadInit.selector);
        new NoUnderlyingZetherToken(address(factory), address(0), ZUID, address(0x1234), dis);
        vm.expectRevert(IZetherToken.BadInit.selector);
        new NoUnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), ITransferDisclosure(address(0x1234)));
    }

    /// The minter never mints shielded value (CTR-ZTH-44): `mint` and the initial supply only add public units.
    function test_minterMintsPublicUnitsOnly() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        (c.initialSupply, c.initialHolder) = (7 * SCALE, address(0xA77));
        ZetherLayer z = ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "supply"));
        assertEq(z.balanceOf(address(0xA77)), 7 * SCALE);
        assertEq(z.totalShielded(), 0);
        _public(tok, address(0xA77), 5 * SCALE);
        assertEq(tok.balanceOf(address(0xA77)), 5 * SCALE);
        assertEq(tok.totalShielded(), 0);
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, AdminLib.MINTABLE, address(0xBAD)));
        NoUnderlyingZetherToken(address(tok)).mint(address(0xBAD), 1);
    }

    /// CTR-TOK-01 (MT-3) on the public side of a Zether token: only contracts grant and spend allowances.
    function test_contractOnlyAllowance() public {
        vm.prank(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, address(0xE0A)));
        tok.approve(address(this), 1);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, address(0xE0A)));
        tok.approve(address(0xE0A), 1);
        vm.prank(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, address(0xE0A)));
        tok.transferFrom(address(1), address(2), 0);
        Puller pl = new Puller();
        _public(tok, address(this), 10);
        tok.approve(address(pl), 10);
        pl.pull(address(tok), address(this), address(0xF1), 10);
        assertEq(tok.balanceOf(address(0xF1)), 10);
        // an EIP-7702 delegated EOA (code = 0xef0100 ‖ addr) is still an EOA: it holds no allowance
        address eoa = address(0x7702);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(0x1234)));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, eoa));
        tok.approve(eoa, 1);
    }

    function test_unknownEntryReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        _vta(tok, bytes32("nope"), 0, 1, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(uint256(1)), "");
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        dis.transferCiphertext(address(tok), bytes32("nope"), 0, "");
    }

    /// Security invariant: with a scheme other than SELF_SCHNORR, knowing `x` is not enough to spend; the account's
    /// authority must sign `authDigest` (over the statement, `chainUid` included).
    function test_confKeyAloneCannotSpendMultisigAccount() public {
        User memory dave = _multisigUser(0xDA7E, 0x0DD, address(0xD4));
        _fund(tok, dave, 100);
        tok.zetherRollOver(dave.ua);
        Tx memory t = _proveTransfer(tok, dave, bob, 10, 100, _none(), 0);
        vm.expectRevert(); // a valid proof, but no signature of the multisig owner
        tok.zetherTransferSingle(t.payload, t.proof, "", _none());
        bytes32 authDigest = keccak256(abi.encodePacked(
            "SCAAS-ZETHER-AUTH-V1", keccak256(stm.transferStatementSingle(address(tok), t.payload, _none(), 0))
        ));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _ecdsa(0x0DD, authDigest);
        tok.zetherTransferSingle(t.payload, t.proof, abi.encode(sigs), _none());
        assertEq(tok.sendCounter(dave.ua), 1);
    }

    function _multisigUser(uint256 x, uint256 ownerPk, address evm) internal returns (User memory u) {
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerPk);
        u.x = x;
        u.y = ZetherKeys.pub(x, false);
        u.evm = evm;
        bytes32 c = reg.popChallenge(u.y, evm);
        bytes[] memory pop = new bytes[](1);
        pop[0] = _ecdsa(ownerPk, c);
        bytes memory popSig = abi.encode(ZetherKeys.schnorr(x, c, false), abi.encode(pop));
        vm.prank(evm);
        u.ua = reg.register(u.y, AuthScheme.ECDSA_MULTISIG, abi.encode(owners, uint256(1)), popSig, false);
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    function test_curveLibBadLength() public {
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 63));
        ver.g1Add(new bytes(63), new bytes(64));
        bytes memory g = ver.g1MulBase(1);
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 63));
        ver.g1Sub(g, new bytes(63)); // neg
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 128));
        ver.g1Msm(bytes.concat(g, g), new uint256[](1)); // msm: pts ≠ k·64
    }

    /// ERC-7201 `scaas.zether` (CTR-TOK-24): where an indexer reads the verifier, the scale, `totalShielded`.
    function test_zetherNamespaceSlot() public {
        _fund(tok, alice, 30);
        bytes32 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        assertEq(ns, keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff)));
        assertEq(address(uint160(uint256(vm.load(address(tok), ns)))), address(ver));
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 1))), SCALE);
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 4))), 30);
    }

    /// CTR-ZTH-02: the verifiers refuse to deploy outside the dev chains (as the registry and `initialize`).
    function test_verifiersOnlyDeployOnDevChain() public {
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherVerifierBn254();
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherVerifierBls12381();
    }

    /// Provenance (CTR-TOK-17): the kind, the factory's record, the immutables, the curve, the parameters.
    function test_provenanceRecorded() public view {
        assertEq(address(tok.verifier()), address(ver));
        assertEq(tok.registry(), address(reg));
        NoUnderlyingZetherToken z = NoUnderlyingZetherToken(address(tok));
        assertEq(z.factory(), address(factory));
        assertEq(z.implementation(), address(noneImpl));
        assertEq(z.version(), 1);
        assertEq(z.creator(), address(this));
        assertEq(z.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(z.decimals(), 6);
        assertEq(tok.shieldScale(), SCALE);
        assertEq(tok.confidentialFee(), FEE);
        assertEq(tok.maxDecryptableShielded(), uint256(1) << 40);
        assertEq(tok.auditorKey().length, 0);
        assertEq(z.name(), "Zether USD");
        assertEq(z.symbol(), "zUSD");
        (, string memory n,,, address vc, bytes32 salt,) = z.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
        assertEq(vc, address(tok));
        assertEq(salt, ZUID);
        (IOpenFactory.TokenKind k, uint64 v) = factory.versionOf(address(tok));
        assertEq(uint8(k), uint8(IOpenFactory.TokenKind.NONE_ZETHER));
        assertEq(v, 1);
    }
}
```

- [ ] **Step 9: layout pin, lint, size baseline** (`test/v2/layout/NoUnderlyingZetherToken.json` is a copy of
  `NoUnderlyingToken.json`: the layer's state is in `scaas.zether`):

```bash
cp test/v2/layout/NoUnderlyingToken.json test/v2/layout/NoUnderlyingZetherToken.json
```

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index 5709ce1..b341560 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,5 +1,6 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
   "NoUnderlyingToken": 22972,
-  "UnderlyingToken": 30030
+  "UnderlyingToken": 30030,
+  "NoUnderlyingZetherToken": 29641
 }
diff --git a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
index 6dc812c..99cd1f3 100644
--- a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
+++ b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
@@ -9,9 +9,10 @@ import {Test} from "forge-std/Test.sol";
 /// are `//` are skipped (block comments are not). A change here is deliberate: update the pin in the same commit and
 /// say why.
 contract MsgSenderLintTest is Test {
-    string[9] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
+    string[12] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
         "src/metatx/NoUnderlyingToken.sol", "src/metatx/UnderlyingToken.sol", "src/metatx/UnderlyingLib.sol",
-        "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol"];
+        "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol", "src/zether/ZetherLayer.sol",
+        "src/zether/ZetherLib.sol", "src/zether/NoUnderlyingZetherToken.sol"];
 
     /// Occurrences of `pat` (not preceded by an identifier character); `exceptSelector` skips `pat<ident>.selector`.
     function _count(string memory path, bytes memory pat, bool exceptSelector) internal view returns (uint256 n) {
@@ -61,6 +62,9 @@ contract MsgSenderLintTest is Test {
         assertEq(_count("src/trade/TradeLib.sol", "msg.sender", false), 0, "TradeLib: the caller is a parameter");
         assertEq(_count("src/metatx/AdminLib.sol", "msg.sender", false), 0, "AdminLib");
         assertEq(_count("src/hedera/HederaLib.sol", "msg.sender", false), 0, "HederaLib");
+        assertEq(_count("src/zether/ZetherLayer.sol", "msg.sender", false), 0, "ZetherLayer");
+        assertEq(_count("src/zether/ZetherLib.sol", "msg.sender", false), 0, "ZetherLib");
+        assertEq(_count("src/zether/NoUnderlyingZetherToken.sol", "msg.sender", false), 0, "NoUnderlyingZetherToken");
     }
 
     /// CTR-MTX-18: an external self-call (`this.f(…)`) inside an allowlisted body would let a guarded callee consume
diff --git a/smartcontracts/evm/test/v2/Layout.t.sol b/smartcontracts/evm/test/v2/Layout.t.sol
index 4009bcf..10f4a73 100644
--- a/smartcontracts/evm/test/v2/Layout.t.sol
+++ b/smartcontracts/evm/test/v2/Layout.t.sol
@@ -31,6 +31,7 @@ contract LayoutTest is V2Fixture {
     function test_storageLayoutIsPinned() public view {
         _pin("NoUnderlyingToken", "NoUnderlyingToken");
         _pin("UnderlyingToken", "UnderlyingToken");
+        _pin("NoUnderlyingZetherToken", "NoUnderlyingZetherToken"); // the Zether layer lives in `scaas.zether`
     }
 
     /// Thứ indexer thật sự đọc (ERC-7201 `scaas.underlying`): chân i ở `keccak256(i ‖ NS)`: `token`, `+ 1` `num ‖ den`,
```

- [ ] **Step 10: Run:**
  - `forge test --match-path "test/zether/*"` → 220 passed (None 21 + 21, Multi 41 + 41, RevertPaths 17, Kat
    13, S3 17, Verifier 27, Registry 22).
  - `forge test` → **941 passed**; size gate 0 errors (`NoUnderlyingZetherToken` 29,641 B, `ZetherLib`
    15,662 B).
- [ ] **Step 11: Commit** `P3: ZetherLib, ZetherLayer, ZetherStatements, NONE_ZETHER kind; Zether suites ported` + trailer.

---

### Task 4: Relaying through the one base — the ticket binding and the allowlist

**Model:** Opus, effort high (the envelope-stripping defence lives here).

**Files:**
- Modify: `src/metatx/MetaTxBase.sol`, `src/zether/ZetherLayer.sol`, `src/zether/NoUnderlyingZetherToken.sol`,
  `test/metatx/MsgSenderLint.t.sol`, `size-baseline.json`
- Create: `test/zether/ZetherRelay.t.sol`

**Interfaces:** Produces `MetaTxBase._envelopeBinding(m)` (virtual, 0) and `_ticketBinding()` (K7),
`ZetherLayer._envelopeBinding` (= `_zetherBinding`), `_env()` with the ticket binding, `_isZetherOp(sel)` (K6), the
`NONE_ZETHER` allowlist (8 entries).

- [ ] **Step 1: the base hook, the layer, the allowlist:**

```diff
diff --git a/smartcontracts/evm/src/metatx/MetaTxBase.sol b/smartcontracts/evm/src/metatx/MetaTxBase.sol
index d17b6ce..1db780a 100644
--- a/smartcontracts/evm/src/metatx/MetaTxBase.sol
+++ b/smartcontracts/evm/src/metatx/MetaTxBase.sol
@@ -36,6 +36,7 @@ abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
     bytes32 private constant _GUARD = 0xf92fce36488cd980109789c37ce44669ca2ec8fc93bcd6d944c3a5544f9ce252; // keccak256("scaas.mtx.guard")
     bytes32 private constant _SENDER = 0x6f8cf97d962f34e862325b04dcb64b0eb0b06cf30b06b61c33210ec760df0f0b; // keccak256("scaas.mtx.sender")
     bytes32 private constant _TICKET = 0xdea51947149e025e6ed748bbba150c788d4bf051fa2851715a58709dbd31a816; // keccak256("scaas.mtx.ticket")
+    bytes32 private constant _BINDING = 0x7a352a4ca0b7d094432a2dbe626c3b7c08a75c6b3464420d2516ca3859c7c12e; // keccak256("scaas.mtx.binding")
 
     /// @custom:storage-location erc7201:scaas.metatx
     struct MetaTxStorage {
@@ -191,10 +192,14 @@ abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
         }
     }
 
-    /// @dev Step 5: store the ticket, call self, clear; a failed call reverts with its own revert data.
+    /// @dev Step 5: store the ticket (and the envelope binding, when the contract has one), call self, clear the ticket;
+    ///      a failed call reverts with its own revert data. The binding is read only under a live ticket, and every
+    ///      self-call of a contract that has one writes it first, so it needs no clearing.
     function _selfCall(MetaTxLib.MetaTransaction memory m) private returns (bytes memory ret) {
         _tstore(_SENDER, uint256(uint160(m.from)));
         _tstore(_TICKET, 1);
+        bytes32 binding = _envelopeBinding(m);
+        if (binding != bytes32(0)) _tstore(_BINDING, uint256(binding));
         bool ok;
         (ok, ret) = address(this).call(m.data);
         bool guarded = _tload(_TICKET) == 2;    // the target was `nonReentrant` and consumed the ticket
@@ -228,6 +233,18 @@ abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
         return SigCheck.ERC1271_GAS;
     }
 
+    /// @notice The envelope binding a proof inside the self-call carries (CTR-ZTH-34): every envelope field except
+    ///         `data`. 0 (none) by default; a confidential token returns its own (Zether, and PQZ with its own tag).
+    function _envelopeBinding(MetaTxLib.MetaTransaction memory) internal view virtual returns (bytes32) {
+        return bytes32(0);
+    }
+
+    /// @notice The envelope binding inside the one self-call of step 5 (live ticket), else 0: a direct call.
+    function _ticketBinding() internal view returns (bytes32) {
+        if (msg.sender == address(this) && _tload(_TICKET) != 0) return bytes32(_tload(_BINDING));
+        return bytes32(0);
+    }
+
     /// @notice The signer inside the one self-call of step 5 (live ticket), else `msg.sender` (CTR-MTX-18).
     function _msgSender() internal view virtual override returns (address) {
         if (msg.sender == address(this) && _tload(_TICKET) != 0) return address(uint160(_tload(_SENDER)));
diff --git a/smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol b/smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol
index 788f655..f13566c 100644
--- a/smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol
+++ b/smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol
@@ -10,6 +10,7 @@ import {AdminLib} from "../metatx/AdminLib.sol";
 import {ITransferDisclosure} from "./ITransferDisclosure.sol";
 import {ZetherLayer} from "./ZetherLayer.sol";
 import {ZetherLib} from "./ZetherLib.sol";
+import {MetaTxLib} from "../common/MetaTxLib.sol";
 
 /// @title Kind `NONE_ZETHER` (CTR-TOK-21): the standalone token with the Zether layer (CTR-ZTH-44).
 /// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. `MINTABLE` mints public units only; shielded
@@ -39,15 +40,33 @@ contract NoUnderlyingZetherToken is NoUnderlyingToken, ZetherLayer {
         return ZetherLayer._domainName();
     }
 
-    /// @notice The public allowlist until the layer's entries are relayed (`cancelNonce`, `burn`).
+    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
+        internal view override(MetaTxBase, ZetherLayer) returns (bytes32)
+    {
+        return ZetherLayer._envelopeBinding(m);
+    }
+
+    /// @notice The allowlist (CTR-MTX-19, CTR-ZTH-34): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`, then the
+    ///         Zether ops, each `ABSOLUTE`.
     function mtxSelectors()
         public pure override(NoUnderlyingToken, IMetaTx, MetaTxBase)
-        returns (bytes4[] memory, uint8[] memory, uint8[] memory)
+        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
     {
-        return NoUnderlyingToken.mtxSelectors();
+        s = new bytes4[](8);
+        c = new uint8[](8);
+        a = new uint8[](8);
+        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
+        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
+        (s[2], c[2]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
+        (s[3], c[3]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
+        (s[4], c[4]) = (this.zetherTransferBundle.selector, FEE_CLASS_ABSOLUTE);
+        (s[5], c[5]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
+        (s[6], c[6]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
+        (s[7], c[7]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
     }
 
     function _mtxRule(bytes4 sel) internal view override(NoUnderlyingToken, MetaTxBase) returns (MtxRule memory) {
+        if (_isZetherOp(sel)) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
         return NoUnderlyingToken._mtxRule(sel);
     }
 }
diff --git a/smartcontracts/evm/src/zether/ZetherLayer.sol b/smartcontracts/evm/src/zether/ZetherLayer.sol
index a49c1d2..ee4adf9 100644
--- a/smartcontracts/evm/src/zether/ZetherLayer.sol
+++ b/smartcontracts/evm/src/zether/ZetherLayer.sol
@@ -147,10 +147,25 @@ abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
 
     // ------------------------------------------------------------------ internals
 
-    /// @dev The statement binding of a direct call: `ZTX_V1_DIRECT`, binding 0. The envelope binding of a relayed call
-    ///      needs the base's ticket binding (next step of the plan).
+    /// @dev The statement binding of this call (CTR-ZTH-34): the envelope's inside `mtxExecute` (`ZTX_V1_RELAYED`),
+    ///      else 0 (`ZTX_V1_DIRECT`), so a proof lifted out of a pending envelope fails as a direct call.
     function _env() internal view returns (ZetherLib.Env memory) {
-        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, bytes32(0));
+        bytes32 b = _ticketBinding();
+        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b);
+    }
+
+    /// @dev The base stores it in the ticket for the self-call of every `mtxExecute` on this token.
+    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
+        return _zetherBinding(m);
+    }
+
+    /// @dev The allowlist entries of the layer (CTR-ZTH-34, CTR-MTX-19): every signer-authorised confidential op,
+    ///      `ABSOLUTE` (no percentage of a hidden amount, CTR-ZTH-07), dynamic arguments; the roll-over functions are not
+    ///      listed (they carry their own signature or none).
+    function _isZetherOp(bytes4 sel) internal pure returns (bool) {
+        return sel == this.zetherShield.selector || sel == this.zetherTransfer.selector
+            || sel == this.zetherTransferBundle.selector || sel == this.zetherTransferNoBundle.selector
+            || sel == this.zetherTransferSingle.selector || sel == this.zetherUnshield.selector;
     }
 
     function _zetherBinding(MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
```

- [ ] **Step 2: `test/zether/ZetherRelay.t.sol`** (new; relayed single, multi, unshield, shield; lifted, moved and
  misplaced proofs; PERCENT; fee only from the public balance; fee to the token; allowlist pin; batch; ERC-1271 signer;
  the Rust envelope KAT):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

/// @notice Zether through the one meta-transaction base (CTR-ZTH-34): every confidential op is an allowlisted self-call
///         of `mtxExecute` whose statement carries the envelope binding (`ZTX_V1_RELAYED`); a direct call proves with
///         `ZTX_V1_DIRECT` and binding 0. The outer fee is the base's step 6, `ABSOLUTE`, from the signer's public
///         balance; the inner fee stays `confidentialFee` to a beneficiary UA.
contract ZetherRelayTest is ZetherFixture {
    using stdJson for string;

    uint256 constant PAYER_PK = 0x9A7E5;
    address payer = vm.addr(PAYER_PK);
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    uint32 constant PCT = MetaTxLib.MODE_FEE_PERCENT;

    function setUp() public {
        _deploy(false, true);
        _public(tok, payer, 1000); // public units for the outer fee
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
    }

    function _mt(bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: payer, data: data, batch: batch, nonce: tok.mtxNonce(payer, batch),
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: fee, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, tok.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _exec(MetaTxLib.MetaTransaction memory m, bytes memory sig) internal returns (bytes memory) {
        vm.prank(relayer);
        return tok.mtxExecute(m, sig);
    }

    /// The proof binds the envelope: build the statement with `envelopeBinding(m)` first, then sign `m` with the proof.
    function _relayedSingle(uint256 batch, uint256 fee) internal view returns (MetaTxLib.MetaTransaction memory m, Tx memory t) {
        m = _mt("", batch, RR | FIX, fee);
        t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, tok.envelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), carol.ua));
    }

    function test_relayedTransferSingle_outerFeeFromPublicBalance_innerFeeToBeneficiary() public {
        (MetaTxLib.MetaTransaction memory m, Tx memory t) = _relayedSingle(uint256(keccak256("lane-1")), 25);
        // the statement of a relayed proof: tag ZTX_V1_RELAYED (word 5), the envelope binding (word 6)
        bytes memory st = stm.transferStatementSingle(address(tok), t.payload, carol.ua, tok.envelopeBinding(m));
        (bytes32 tag, bytes32 binding) = abi.decode(_slice(st, 160, 64), (bytes32, bytes32));
        assertEq(tag, keccak256("ZTX_V1_RELAYED"));
        assertEq(binding, tok.envelopeBinding(m));
        bytes memory sig = _sign(PAYER_PK, m);
        uint256 g0 = gasleft();
        bytes memory ret = _exec(m, sig);
        console2.log("bn254 relayed zetherTransferSingle gas", g0 - gasleft());
        assertEq(abi.decode(ret, (bytes32)), _ref(tok, alice, 0), "the self-call returns the entryRef");
        assertEq(tok.balanceOf(relayer), 25, "outer fee: public units to the relayer");
        assertEq(tok.balanceOf(payer), 975);
        assertTrue(_holds(tok, carol, FEE, false), "inner fee: [fee]G into the beneficiary's pending");
        assertTrue(_holds(tok, alice, 500 - 100 - FEE, true));
        assertTrue(_holds(tok, bob, 100, false));
        assertEq(tok.mtxNonce(payer, m.batch), 1);
        _assertConservation(tok, 1100);
    }

    function test_relayedMultiTransfer_unshield_shield() public {
        // zetherTransfer (HASH), relayed
        MetaTxLib.MetaTransaction memory m = _mt("", 1, RR | FIX, 3);
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (40, 0);
        Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.HASH, tok.envelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.zetherTransfer, (t.payload, t.proof, bytes(""), _none()));
        _exec(m, _sign(PAYER_PK, m));
        assertTrue(_holds(tok, bob, 40, false));
        assertTrue(_holds(tok, alice, 460, true));
        // zetherUnshield, relayed: public units minted to the statement's recipient
        m = _mt("", 2, RR | FIX, 3);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 60, 460, address(0xB0C), carol.ua, tok.envelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.zetherUnshield, (pl, pr, bytes(""), carol.ua, address(0xB0C), 60));
        // lifted out and called directly: DIRECT statement ⇒ refused
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherUnshield(pl, pr, "", carol.ua, address(0xB0C), 60);
        _exec(m, _sign(PAYER_PK, m));
        assertEq(tok.balanceOf(address(0xB0C)), 60 * SCALE);
        assertTrue(_holds(tok, alice, 460 - 60 - FEE, true));
        // zetherShield, relayed: the SIGNER's public units, not the relayer's
        _public(tok, payer, 7 * SCALE);
        m = _mt(abi.encodeCall(ZetherLayer.zetherShield, (bob.y, 7)), 3, RR | FIX, 4);
        uint256 before = tok.balanceOf(payer);
        _exec(m, _sign(PAYER_PK, m));
        assertEq(tok.balanceOf(payer), before - 7 * SCALE - 4, "shield and outer fee, both from the signer");
        assertEq(tok.balanceOf(relayer), 3 + 3 + 4);
        assertEq(tok.accountState(bob.ua).pendingSeq, 2);
        // a direct call in the same transaction proves DIRECT: the binding is read only under a live ticket
        _direct(tok, _proveTransfer(tok, alice, carol, 5, 400 - FEE, _none(), 0), _none());
        assertTrue(_holds(tok, alice, 400 - FEE - 5, true));
        _assertConservation(tok, 1100);
    }

    function test_proofLiftedOutOfEnvelopeRejected() public {
        (, Tx memory t) = _relayedSingle(7, 25);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // statement DIRECT ≠ RELAYED
        tok.zetherTransferSingle(t.payload, t.proof, "", carol.ua);
    }

    function test_proofMovedToAnotherEnvelopeRejected() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.batch = 8; // another envelope (another lane), same data ⇒ another binding
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxExecute(m, sig);
        (m,) = _relayedSingle(7, 25);
        m.fee = 26; // the fee is in the binding
        sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxExecute(m, sig);
    }

    /// A direct proof (binding 0) put into an envelope: the statement is RELAYED there ⇒ refused.
    function test_directProofInsideAnEnvelopeRejected() public {
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
        MetaTxLib.MetaTransaction memory m =
            _mt(abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), carol.ua)), 9, RR, 0);
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxExecute(m, sig);
        _direct(tok, t, carol.ua); // the same proof as a direct call passes
    }

    /// CTR-ZTH-07: `PERCENT` is refused on every confidential op (`ABSOLUTE` class), before the call.
    function test_percentFeeRefused() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.mode = RR | PCT;
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, ZetherLayer.zetherTransferSingle.selector, m.mode));
        tok.mtxExecute(m, sig);
    }

    /// The outer fee comes only from the signer's public balance; short ⇒ everything reverts (proof effects, nonce).
    function test_outerFeeOnlyFromThePublicBalance() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 1001);
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", payer, 1000, 1001));
        tok.mtxExecute(m, sig);
        assertEq(tok.mtxNonce(payer, 7), 0, "nonce not consumed");
        assertEq(tok.sendCounter(alice.ua), 0, "no confidential effect");
        assertTrue(_holds(tok, alice, 500, true));
    }

    /// CTR-ZTH-23: a fee to the token itself would be stuck; the base refuses every transfer to the token.
    function test_feeToTheTokenRefused() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.mode = RR | RF | FIX;
        m.feeRecipient = address(tok);
        // the binding covers the bound fee recipient: re-prove for this envelope
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, tok.envelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), carol.ua));
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        tok.mtxExecute(m, sig);
    }

    /// CTR-MTX-19: the published allowlist; the roll-over functions, `mint` and the trade entries are refused.
    function test_allowlistPinned() public {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = tok.mtxSelectors();
        bytes4[8] memory want = [
            IMetaTx.cancelNonce.selector, NoUnderlyingToken.burn.selector, ZetherLayer.zetherShield.selector,
            ZetherLayer.zetherTransfer.selector, ZetherLayer.zetherTransferBundle.selector,
            ZetherLayer.zetherTransferNoBundle.selector, ZetherLayer.zetherTransferSingle.selector,
            ZetherLayer.zetherUnshield.selector
        ];
        assertEq(s.length, 8);
        for (uint256 i; i < 8; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], i == 1 ? 2 : 1, "burn AMOUNT, the rest ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(bytes4(keccak256("zetherShield(bytes,uint256)")), ZetherLayer.zetherShield.selector);
        assertEq(bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)")), ZetherLayer.zetherTransfer.selector);
        assertEq(bytes4(keccak256("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)")),
            ZetherLayer.zetherUnshield.selector);
        bytes[4] memory refused = [
            abi.encodeCall(ZetherLayer.zetherRollOver, (alice.ua)),
            abi.encodeCall(ZetherLayer.zetherRollOverSigned, (alice.ua, 1, 1, bytes(""))),
            abi.encodeCall(ZetherLayer.zetherSetRollOverMode, (alice.ua, ZetherTypes.RollOverMode.PUBLIC, 1, bytes(""))),
            abi.encodeCall(NoUnderlyingToken.mint, (payer, 1))
        ];
        for (uint256 i; i < refused.length; ++i) {
            MetaTxLib.MetaTransaction memory m = _mt(refused[i], 100 + i, RR, 0);
            bytes memory sig = _sign(PAYER_PK, m);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(refused[i])));
            tok.mtxExecute(m, sig);
        }
    }

    /// `mtxBatch`: each item has its own ticket and binding (a shield, then a relayed transfer on the next nonce).
    function test_batch_eachItemItsOwnBinding() public {
        _public(tok, payer, 5 * SCALE);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        ms[0] = _mt(abi.encodeCall(ZetherLayer.zetherShield, (carol.y, 5)), 4, RR, 0);
        ms[1] = _mt("", 4, RR | FIX, 2);
        ms[1].nonce = 1;
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), tok.envelopeBinding(ms[1]));
        ms[1].data = abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), _none()));
        bytes[] memory sigs = new bytes[](2);
        (sigs[0], sigs[1]) = (_sign(PAYER_PK, ms[0]), _sign(PAYER_PK, ms[1]));
        vm.prank(relayer);
        tok.mtxBatch(ms, sigs);
        assertTrue(_holds(tok, carol, 5, false));
        assertTrue(_holds(tok, bob, 100, false));
        assertEq(tok.mtxNonce(payer, 4), 2);
    }

    /// An ERC-1271 signer (CTR-ZTH-21, the base's cap) relays its own shield.
    function test_contractSignerRelaysItsShield() public {
        uint256 ownerPk = 0x0DD;
        Mock1271Wallet w = new Mock1271Wallet(vm.addr(ownerPk));
        _public(tok, address(w), 3 * SCALE);
        MetaTxLib.MetaTransaction memory m = _mt(abi.encodeCall(ZetherLayer.zetherShield, (bob.y, 3)), 1, RR, 0);
        m.from = address(w);
        bytes memory sig = _sign(ownerPk, m);
        vm.prank(relayer);
        tok.mtxExecute(m, sig);
        assertEq(tok.balanceOf(address(w)), 0);
        assertTrue(_holds(tok, bob, 3, false));
    }

    /// The envelope binding and digest equal the Rust prover's (`envelope.json`, CTR-ZTH-06/36) through the spec
    /// formulas, and the token computes the same formulas for its own address.
    function test_envelopeBindingAndDigestKat() public view {
        string memory j = vm.readFile("test/vectors/zether/s3/envelope.json");
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: j.readAddress(".meta.from"), data: j.readBytes(".meta.data"), batch: uint256(j.readBytes32(".meta.batch")),
            nonce: j.readUint(".meta.nonce"), validUntil: j.readUint(".meta.validUntil"), mode: uint32(j.readUint(".meta.mode")),
            relayer: j.readAddress(".meta.relayer"), fee: j.readUint(".meta.fee"), feeRecipient: j.readAddress(".meta.feeRecipient")
        });
        uint256 chainId = j.readUint(".chainId");
        bytes32 uid = j.readBytes32(".chainUid");
        address token = j.readAddress(".token");
        assertEq(_binding(m, chainId, uid, token), j.readBytes32(".binding"));
        assertEq(_digest(m, chainId, uid, token), j.readBytes32(".digest"));
        assertEq(tok.envelopeBinding(m), _binding(m, block.chainid, ZUID, address(tok)));
        assertEq(tok.mtxDigest(m), _digest(m, block.chainid, ZUID, address(tok)));
    }

    function _slice(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function _binding(MetaTxLib.MetaTransaction memory m, uint256 chainId, bytes32 uid, address token)
        internal pure returns (bytes32)
    {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-ENVELOPE-V1"), chainId, uid, token, m.from, m.batch),
            abi.encode(m.nonce, m.validUntil, m.mode, r, m.fee, f)
        ));
    }

    function _digest(MetaTxLib.MetaTransaction memory m, uint256 chainId, bytes32 uid, address token)
        internal pure returns (bytes32)
    {
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS ZetherToken"), keccak256("1"), chainId, token, uid
        ));
        return keccak256(abi.encodePacked(hex"1901", ds, MetaTxLib.hashStruct(m)));
    }
}
```

- [ ] **Step 3: lint and size:**

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index b341560..76c78b6 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -1,6 +1,6 @@
 {
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
-  "NoUnderlyingToken": 22972,
-  "UnderlyingToken": 30030,
-  "NoUnderlyingZetherToken": 29641
+  "NoUnderlyingToken": 22978,
+  "UnderlyingToken": 30036,
+  "NoUnderlyingZetherToken": 30659
 }
diff --git a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
index 99cd1f3..b97e4f8 100644
--- a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
+++ b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
@@ -53,7 +53,8 @@ contract MsgSenderLintTest is Test {
     }
 
     function test_msgSenderReadsArePinned() public view {
-        assertEq(_count("src/metatx/MetaTxBase.sol", "msg.sender", false), 7, "MetaTxBase: guard, event, relayer binding x2, _msgSender x2, fee default");
+        assertEq(_count("src/metatx/MetaTxBase.sol", "msg.sender", false), 8,
+            "MetaTxBase: guard, event, relayer binding x2, _msgSender x2, fee default, ticket binding (CTR-ZTH-34)");
         assertEq(_count("src/metatx/ERC20MetaTx.sol", "msg.sender", false), 3, "ERC20MetaTx: event relayer, fee default, mtxTrade caller (CTR-DEX-15)");
         assertEq(_count("src/metatx/MetaTokenBase.sol", "msg.sender", false), 1, "MetaTokenBase: factory check in initialize");
         assertEq(_count("src/metatx/NoUnderlyingToken.sol", "msg.sender", false), 0, "NoUnderlyingToken");
```

- [ ] **Step 4: Run:** `forge test --match-path test/zether/ZetherRelay.t.sol` → 12 passed; `forge test --match-path
  "test/{zether/*,v2/Allowlist.t.sol,metatx/*}"` → 364 passed; `forge test` → **953 passed**; size gate 0 errors.
- [ ] **Step 5: Commit** `P3: Zether relays through mtxExecute — envelope binding in the ticket, allowlist` + trailer.

---

### Task 5: Kind `UNDERLYING_ZETHER` — wrap-shield, unshield-unwrap, the reserve invariant

**Model:** Opus, effort high (underlying legs, reserve invariant, the K8 binding).

**Files:**
- Create: `src/zether/UnderlyingZetherToken.sol`, `test/zether/ZetherUnderlying.t.sol`, `test/zether/ZetherInvariant.t.sol`,
  `test/v2/layout/UnderlyingZetherToken.json`
- Modify: `src/zether/ZetherLib.sol` (`unwrapBinding`), `src/zether/ZetherStatements.sol` (`unshieldUnwrapStatement`,
  `unwrapBinding`), `test/v2/Layout.t.sol`, `test/metatx/MsgSenderLint.t.sol`, `size-baseline.json`

**Interfaces:** Produces `UnderlyingZetherToken(factory, smartKeyAccountImpl, chainUid, registry, disclosure)` with
`zetherWrapShield(address u, uint256 amountIn, UA ua)` (payable), `zetherUnshieldUnwrap(payload, proof, authSig,
beneficiary, u, recipient, amount, minOut)`, `executeRate` counting the shielded part (K9), the 14-entry allowlist;
`ZetherLib.unwrapBinding(u, minOut)` (K8).

- [ ] **Step 1: `src/zether/UnderlyingZetherToken.sol`** (new):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {UnderlyingToken} from "../metatx/UnderlyingToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {UnderlyingLib} from "../metatx/UnderlyingLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title Kind `UNDERLYING_ZETHER` (CTR-TOK-21): the wrapper of 1–8 legs with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. The legs, rates, reserves, `wrap`/`unwrap`,
///         `mtxWrap` and the rate and guardian roles are `UnderlyingToken`'s (`UnderlyingLib`); the layer adds
///         `zetherWrapShield` (a leg's underlying straight into a shielded balance, nothing minted) and
///         `zetherUnshieldUnwrap` (a shielded balance straight out to a leg's underlying, nothing minted). Reserve
///         invariant: `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`, by construction (a wrap-shield
///         credits `minted / shieldScale` with `minted` a multiple of the scale, an unshield-unwrap pays
///         `⌊amount·shieldScale·den/num⌋`, worth at most what it removes), and `executeRate` checks it with the shielded
///         part. Flags: `PAYABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE` (CTR-ZTH-47). Never on Hedera.
contract UnderlyingZetherToken is UnderlyingToken, ZetherLayer {
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, address registry_,
        ITransferDisclosure disclosure_)
        UnderlyingToken(factory_, smartKeyAccountImpl_, chainUid_, false)
        ZetherLayer(registry_, disclosure_)
    {}

    function kind() public pure override(UnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_UNDERLYING_ZETHER;
    }

    function _init(TokenConfig calldata cfg) internal override(UnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, false, AdminLib.KIND_UNDERLYING_ZETHER);
        ZetherLib.init(cfg.conf);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-ZTH-45)

    /// @notice Pulls `amountIn` of leg `u` (native: `msg.value`) and credits the public-equivalent `minted` (the leg's
    ///         rate on the measured delta) as `minted / shieldScale` shielded units to `ua`, minting nothing;
    ///         `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount).
    function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable nonReentrant {
        (,, uint256 minted) = UnderlyingLib.wrap(UnderlyingLib.indexOf(u), amountIn, _msgSender(), msg.value);
        uint256 scale = ZetherLib.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        ZetherLib.shield(ua, minted / scale, _REGISTRY);
    }

    /// @notice The unshield proof (amount and `recipient` in the statement; a direct call also binds `u` and `minOut`),
    ///         then leg `u` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` from its reserve to `recipient`, minting nothing.
    function zetherUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        address u,
        address recipient,
        uint256 amount,
        uint256 minOut
    ) external nonReentrant {
        _unshieldUnwrap(payload, proof, authSig, beneficiary, Unwrap(u, recipient, amount, minOut));
    }

    struct Unwrap {
        address u;
        address recipient;
        uint256 amount;
        uint256 minOut;
    }

    /// @dev The leg first (cheap), the proof and the debit, then the payout from the leg's reserve (CEI: the debit
    ///      before the one outside call).
    function _unshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        Unwrap memory x
    ) private {
        uint256 i = UnderlyingLib.indexOf(x.u);
        ZetherLib.unshield(payload, proof, authSig, beneficiary, x.amount, x.recipient, _envUnwrap(x.u, x.minOut));
        (uint256 out,) = UnderlyingLib.quoteUnwrap(i, x.amount * ZetherLib.$().shieldScale, x.recipient, x.minOut);
        UnderlyingLib.payOut(i, x.recipient, out);
    }

    /// @notice As `UnderlyingToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(UnderlyingToken, MetaTokenBase) {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
    }

    /// @notice The collateral check of a rate change counts the shielded value too.
    function executeRate() external override {
        UnderlyingLib.executeRate(_msgSender(), totalSupply() + ZetherLib.$().totalShielded * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ the layer's hooks

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._envelopeBinding(m);
    }

    /// @dev Relayed: the envelope binding (the signature covers `data`, the leg and `minOut` with it); direct: the leg
    ///      and `minOut` (`ZetherLib.unwrapBinding`) under `ZTX_V1_DIRECT`.
    function _envUnwrap(address u, uint256 minOut) private view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        if (b != bytes32(0)) return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_RELAYED, b);
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, ZetherLib.unwrapBinding(u, minOut));
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-ZTH-34)

    /// @notice `UnderlyingToken`'s six, then the Zether ops and the two underlying paths, each `ABSOLUTE`.
    function mtxSelectors()
        public pure override(UnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](14);
        c = new uint8[](14);
        a = new uint8[](14);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (this.zetherTransferBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.zetherWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (this.zetherUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(UnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel) || sel == this.zetherUnshieldUnwrap.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == this.zetherWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        return UnderlyingToken._mtxRule(sel);
    }
}
```

- [ ] **Step 2: the unwrap binding in the library and the views:**

```diff
diff --git a/smartcontracts/evm/src/zether/ZetherLib.sol b/smartcontracts/evm/src/zether/ZetherLib.sol
index f2e48e8..a73db32 100644
--- a/smartcontracts/evm/src/zether/ZetherLib.sol
+++ b/smartcontracts/evm/src/zether/ZetherLib.sol
@@ -49,7 +49,8 @@ library ZetherLib {
     }
 
     /// @notice The token's immutables a call needs, and the statement's binding: `(ZTX_V1_DIRECT, 0)` for a direct
-    ///         call, `(ZTX_V1_RELAYED, envelopeBinding)` inside `mtxExecute`.
+    ///         call, `(ZTX_V1_RELAYED, envelopeBinding)` inside `mtxExecute`, `(ZTX_V1_DIRECT, unwrapBinding)` for a direct
+    ///         `zetherUnshieldUnwrap`.
     struct Env {
         address registry;
         bytes32 chainUid;
@@ -97,6 +98,7 @@ library ZetherLib {
     bytes32 internal constant TAG_DIRECT = keccak256("ZTX_V1_DIRECT");
     bytes32 internal constant TAG_RELAYED = keccak256("ZTX_V1_RELAYED");
     bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-ZETHER-ENVELOPE-V1");
+    bytes32 internal constant TAG_UNWRAP = keccak256("SCAAS-ZETHER-UNWRAP-V1");
     bytes32 private constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
     bytes32 private constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
     bytes32 private constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
@@ -357,6 +359,13 @@ library ZetherLib {
         return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;
     }
 
+    /// @notice The binding word of a direct `zetherUnshieldUnwrap`: its leg and `minOut` (controller ruling, pending
+    ///         the owner), so a proof lifted from a pending call cannot pick another leg, drop `minOut` or go through
+    ///         `zetherUnshield` instead.
+    function unwrapBinding(address u, uint256 minOut) internal pure returns (bytes32) {
+        return keccak256(abi.encode(TAG_UNWRAP, u, minOut));
+    }
+
     /// @notice `entryRef` (zether.md §12) with `chainUid` (CTR-ZTH-36); `sendCounter` before the increment.
     function entryRefOf(Ctx memory c, ZetherTypes.UA from, uint64 counter) internal view returns (bytes32) {
         return keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)));
diff --git a/smartcontracts/evm/src/zether/ZetherStatements.sol b/smartcontracts/evm/src/zether/ZetherStatements.sol
index ff58d4b..283e8e1 100644
--- a/smartcontracts/evm/src/zether/ZetherStatements.sol
+++ b/smartcontracts/evm/src/zether/ZetherStatements.sol
@@ -51,6 +51,29 @@ contract ZetherStatements {
         return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
     }
 
+    /// @notice The statement of `zetherUnshieldUnwrap` on an `UNDERLYING_ZETHER` token: relayed, the envelope binding;
+    ///         direct, `ZTX_V1_DIRECT` with the leg and `minOut` bound (`unwrapBinding`).
+    function unshieldUnwrapStatement(
+        address token,
+        bytes calldata payload,
+        uint256 amount,
+        address recipient,
+        ZetherTypes.UA beneficiary,
+        address u,
+        uint256 minOut,
+        bytes32 envelopeBinding
+    ) external view returns (bytes memory) {
+        if (envelopeBinding != bytes32(0)) {
+            return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_RELAYED, envelopeBinding);
+        }
+        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_DIRECT, unwrapBinding(u, minOut));
+    }
+
+    /// @notice The binding word of a direct `zetherUnshieldUnwrap` (controller ruling, pending the owner).
+    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
+        return ZetherLib.unwrapBinding(u, minOut);
+    }
+
     function _unshield(
         address token,
         bytes calldata payload,
```

- [ ] **Step 3: `test/zether/ZetherUnderlying.t.sol`** (new):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// A leg that calls back into the token when the token pays it out or pulls it (an ERC-777-style hook).
contract HookLeg is MockERC20 {
    address public target;
    bytes public payload;

    constructor() MockERC20("Hook", "HOOK", 6) {}

    function arm(address t, bytes calldata p) external {
        target = t;
        payload = p;
    }

    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (target != address(0) && (from == target || to == target)) {
            (bool ok, bytes memory ret) = target.call(payload);
            if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// @notice Kind `UNDERLYING_ZETHER` (CTR-ZTH-44/45): the legs' underlying straight into a shielded balance and back,
///         nothing minted either way; the reserve invariant counts the shielded value; `mtxWrap`, the native leg, the
///         direct unshield-unwrap binding its leg and `minOut`, relaying, re-entry.
contract ZetherUnderlyingTest is ZetherFixture {
    UnderlyingZetherToken internal undImpl;
    UnderlyingZetherToken internal w;
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    MockERC20 internal eur = new MockERC20("EUR", "EUR", 6);
    uint256 constant PAYER_PK = 0x9A7E5;
    address payer = vm.addr(PAYER_PK);

    function setUp() public {
        _stack(false);
        undImpl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(undImpl));
        address[] memory legs = new address[](2);
        (legs[0], legs[1]) = (address(usd), address(eur));
        uint256[] memory nums = new uint256[](2);
        (nums[0], nums[1]) = (1, 2); // 1 EUR raw = 2 public units
        w = _wrapper(legs, nums, _ones(2), "zw", true);
        tok = ZetherLayer(address(w));
        _users();
    }

    function _ones(uint256 n) internal pure returns (uint256[] memory o) {
        o = new uint256[](n);
        for (uint256 i; i < n; ++i) o[i] = 1;
    }

    /// `PAYABLE | RATE_ADJUSTABLE | WRAP_DISABLEABLE`; the test is owner, rate admin (a contract) and guardian.
    function _wrapper(address[] memory legs, uint256[] memory nums, uint256[] memory dens, bytes32 salt, bool auditor)
        internal returns (UnderlyingZetherToken)
    {
        IFactoryToken.TokenConfig memory c;
        c.name = "Zether wrapped";
        c.symbol = "zW";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.RATE_ADJUSTABLE) | (1 << AdminLib.WRAP_DISABLEABLE);
        c.owner = address(this);
        c.roles.rateAdmin = address(this);
        c.roles.guardian = address(this);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], nums[i], dens[i]);
        c.conf = IFactoryToken.ConfidentialConfig(
            address(ver), auditor ? ZetherKeys.pub(X_AUD, false) : bytes(""), SCALE, uint256(1) << 40, FEE
        );
        return UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, salt)));
    }

    /// Public units by a 1:1 USD wrap.
    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        UnderlyingToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
        minted[address(t)] += units;
    }

    /// The reserve invariant (CTR-ZTH-44) and Σ plaintext == totalShielded.
    function _assertConservation(ZetherLayer t, uint256 max) internal view override {
        User[3] memory us = [alice, bob, carol];
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            (uint256 a, uint256 p) = _balances(t, us[i], max);
            sum += a + p;
        }
        assertEq(sum, t.totalShielded(), "sum of plaintext balances == totalShielded");
        UnderlyingToken u = UnderlyingToken(payable(address(t)));
        assertGe(u.collateralValue(), t.totalSupply() + t.totalShielded() * SCALE, "reserve invariant");
    }

    function _wrapShield(MockERC20 leg, uint256 amountIn, User memory to) internal {
        leg.mint(address(this), amountIn);
        leg.approve(address(w), amountIn);
        w.zetherWrapShield(address(leg), amountIn, to.ua);
    }

    function _reserve(address leg) internal view returns (uint256 r) {
        (,, r,,) = w.legOf(leg);
    }

    // ------------------------------------------------------------------ wrap-shield

    function test_wrapShield_creditsShieldedUnits_mintsNothing() public {
        usd.mint(address(this), 30 * SCALE);
        usd.approve(address(w), 30 * SCALE);
        vm.expectEmit(true, false, false, true, address(w));
        emit IZetherToken.ZetherShielded(alice.ua, 30);
        w.zetherWrapShield(address(usd), 30 * SCALE, alice.ua);
        assertEq(w.totalSupply(), 0, "nothing minted");
        assertEq(w.totalShielded(), 30);
        assertEq(_reserve(address(usd)), 30 * SCALE);
        assertTrue(_holds(tok, alice, 30, false));
        // the EUR leg at 2 public units per raw unit: 5·SCALE EUR = 10 shielded units
        _wrapShield(eur, 5 * SCALE, bob);
        assertTrue(_holds(tok, bob, 10, false));
        assertEq(w.totalShielded(), 40);
        assertEq(w.collateralValue(), 40 * SCALE);
        _assertConservation(tok, 100);
    }

    function test_wrapShield_refusals() public {
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), 100 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountNotScaled.selector, 30 * SCALE + 1, SCALE));
        w.zetherWrapShield(address(usd), 30 * SCALE + 1, alice.ua);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.zetherWrapShield(address(0xDEAD), SCALE, alice.ua);
        ZetherTypes.UA ghost = ZetherTypes.toUA(ZetherKeys.pub(0x6057, false));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ghost));
        w.zetherWrapShield(address(usd), SCALE, ghost);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1, 0));
        w.zetherWrapShield{value: 1}(address(usd), SCALE, alice.ua);
        // a disabled leg (guardian, one-way) and a pending rate change pause the inflow
        w.disableWrap(address(eur), "depeg");
        eur.mint(address(this), SCALE);
        eur.approve(address(w), SCALE);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(eur)));
        w.zetherWrapShield(address(eur), SCALE, alice.ua);
        w.proposeRate(address(usd), 11, 10);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(usd)));
        w.zetherWrapShield(address(usd), SCALE, alice.ua);
        w.cancelRate();
        // the cap
        UnderlyingZetherToken small = _small();
        usd.mint(address(this), 101 * SCALE);
        usd.approve(address(small), 101 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 101, 100));
        small.zetherWrapShield(address(usd), 101 * SCALE, alice.ua);
    }

    /// One USD leg 1:1, cap 100.
    function _small() internal returns (UnderlyingZetherToken z) {
        IFactoryToken.TokenConfig memory c;
        c.name = "S";
        c.symbol = "S";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.RATE_ADJUSTABLE);
        c.roles.rateAdmin = address(this);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE);
        z = UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "small")));
    }

    // ------------------------------------------------------------------ unshield-unwrap

    function _shielded(uint256 usdUnits, uint256 eurRaw) internal {
        if (usdUnits != 0) _wrapShield(usd, usdUnits * SCALE, alice);
        if (eurRaw != 0) _wrapShield(eur, eurRaw, alice);
        tok.zetherRollOver(alice.ua);
    }

    function _unwrapProof(uint256 amount, uint256 b, address recipient, address u, uint256 minOut, bytes32 envB)
        internal view returns (bytes memory pl, bytes memory pr)
    {
        pl = _unshieldPayload(tok, alice);
        bytes memory st = stm.unshieldUnwrapStatement(address(w), pl, amount, recipient, _none(), u, minOut, envB);
        pr = _proveU(alice, st, amount, b, _none(), tok);
    }

    function test_unshieldUnwrap_paysTheLeg_mintsNothing() public {
        _shielded(60, 40 * SCALE); // 60 + 80 shielded
        (bytes memory pl, bytes memory pr) = _unwrapProof(40, 140, address(0xD00D), address(eur), 20 * SCALE, 0);
        vm.expectEmit(true, false, false, true, address(w));
        emit IZetherToken.ZetherUnshielded(alice.ua, 40, address(0xD00D));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 40, 20 * SCALE);
        assertEq(eur.balanceOf(address(0xD00D)), 20 * SCALE, "40 units at 2 per raw EUR");
        assertEq(_reserve(address(eur)), 20 * SCALE);
        assertEq(w.totalSupply(), 0, "nothing minted");
        assertEq(w.totalShielded(), 100);
        assertTrue(_holds(tok, alice, 100, true));
        // the USD leg, 1:1
        (pl, pr) = _unwrapProof(60, 100, address(0xD00D), address(usd), 0, 0);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 60, 0);
        assertEq(usd.balanceOf(address(0xD00D)), 60 * SCALE);
        _assertConservation(tok, 200);
    }

    function test_unshieldUnwrap_refusals() public {
        _shielded(10, 0);
        // more than the leg's reserve: EUR holds nothing
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 10, address(0xD00D), address(eur), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(eur), 5 * SCALE, 0));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 10, 0);
        // minOut above what the leg pays
        (pl, pr) = _unwrapProof(10, 10, address(0xD00D), address(usd), 10 * SCALE + 1, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 10 * SCALE, 10 * SCALE + 1));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 10 * SCALE + 1);
        // the token itself as recipient
        (pl, pr) = _unwrapProof(10, 10, address(w), address(usd), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(w)));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(w), 10, 0);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(0xDEAD), address(w), 10, 0);
    }

    /// A direct proof binds the leg and `minOut` (controller ruling, pending the owner): copied from a pending call it
    /// cannot pick another leg, drop `minOut`, or go through `zetherUnshield`; a plain unshield proof does not fit here.
    function test_unshieldUnwrap_directProofBindsLegAndMinOut() public {
        _shielded(30, 30 * SCALE);
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 90, address(0xD00D), address(usd), 10 * SCALE, 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(eur), address(0xD00D), 10, 5 * SCALE); // other leg
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 0); // minOut dropped
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshield(pl, pr, "", _none(), address(0xD00D), 10); // into public units instead
        (bytes memory pl2, bytes memory pr2) = _proveUnshield(tok, alice, 10, 90, address(0xD00D), _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        w.zetherUnshieldUnwrap(pl2, pr2, "", _none(), address(usd), address(0xD00D), 10, 0);
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xD00D), 10, 10 * SCALE);
        assertEq(stm.unwrapBinding(address(usd), 10 * SCALE),
            keccak256(abi.encode(keccak256("SCAAS-ZETHER-UNWRAP-V1"), address(usd), 10 * SCALE)));
    }

    /// Relayed: the envelope binding; the signer's signature covers the leg and `minOut` (they are in `data`).
    function test_unshieldUnwrap_relayed() public {
        _shielded(30, 0);
        _public(tok, payer, 100);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: "", batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, relayer: relayer, fee: 9,
            feeRecipient: address(0)
        });
        (bytes memory pl, bytes memory pr) = _unwrapProof(10, 30, address(0xB0C), address(usd), 0, w.envelopeBinding(m));
        m.data = abi.encodeCall(UnderlyingZetherToken.zetherUnshieldUnwrap,
            (pl, pr, bytes(""), _none(), address(usd), address(0xB0C), 10, 0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, w.mtxDigest(m));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // lifted out: the direct binding differs
        w.zetherUnshieldUnwrap(pl, pr, "", _none(), address(usd), address(0xB0C), 10, 0);
        vm.prank(relayer);
        w.mtxExecute(m, sig);
        assertEq(usd.balanceOf(address(0xB0C)), 10 * SCALE);
        assertEq(w.balanceOf(relayer), 9);
        assertTrue(_holds(tok, alice, 20, true));
    }

    // ------------------------------------------------------------------ disclosure carried over (CTR-ZTH-40/43)

    /// The disclosure reads (`disclosure()`, `transferEntry`, `auditorKey()`, `verifier()`, `chainUid()`) work on kind 3
    /// as on kind 2: every opening of a transfer opens through the canonical `ZetherDisclosure`.
    function test_disclosureOnTheUnderlyingKind() public {
        _shielded(50, 0);
        Tx memory t = _proveTransfer(tok, alice, bob, 21, 50, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        assertEq(address(w.disclosure()), address(dis));
        assertEq(w.auditorKey(), ZetherKeys.pub(X_AUD, false));
        assertEq(w.transferEntry(ref).length, 4 * 64, "the single format stores its bundle");
        (bytes memory ct,) = dis.transferCiphertext(address(w), ref, 0, "");
        bytes memory dOut = new bytes(64);
        for (uint256 i; i < 64; ++i) dOut[i] = ct[64 + i];
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(tok, bob.x, ref, 0, 21, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(tok, X_AUD, ref, 0, 21, ITransferDisclosure.OpeningKind.AUDITOR, dOut), ""));
        assertTrue(_vta(tok, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(tok, t.s, ref, 0, 21, ITransferDisclosure.OpeningKind.SENDER_CP, bob.y), ""));
        assertFalse(_vta(tok, ref, 0, 22, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), ""));
    }

    // ------------------------------------------------------------------ reserve invariant (CTR-ZTH-44)

    /// A rate decrease that the public supply alone would allow, but the shielded value would not.
    function test_executeRate_countsTheShieldedValue() public {
        UnderlyingZetherToken z = _small();
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(z), 100 * SCALE);
        z.zetherWrapShield(address(usd), 100 * SCALE, alice.ua);
        assertEq(z.totalSupply(), 0);
        z.proposeRate(address(usd), 9, 10);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateChangeUndercollateralized.selector, 90 * SCALE,
            100 * SCALE));
        z.executeRate();
    }

    /// The kind's own flag rules (CTR-ZTH-47) and `disableFeature(RATE_ADJUSTABLE)` cancelling a pending change
    /// (CTR-TOK-06), restated on this kind.
    function test_kindFlags_andDisableFeatureCancelsAPendingRate() public {
        w.proposeRate(address(usd), 11, 10);
        (address pu,,,) = w.pendingRate();
        assertEq(pu, address(usd));
        w.disableFeature(AdminLib.RATE_ADJUSTABLE);
        (pu,,,) = w.pendingRate();
        assertEq(pu, address(0), "the pending change is gone");
        assertFalse(w.rateAdjustable());
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("F", "F", 6, 1 << AdminLib.FREEZE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, 100, FEE);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.FREEZE));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "freeze");
        c.features = 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "mint");
    }

    // ------------------------------------------------------------------ mtxWrap and shield, gasless (CTR-TOK-20, MT-3)

    /// An EOA holding a SCaaS underlying cannot approve (CTR-TOK-01): it wraps by signature (`mtxWrap`, inherited) and
    /// shields through `mtxExecute`, paying no gas.
    function test_mtxWrapThenRelayedShield_noApproveAnywhere() public {
        NoUnderlyingToken pImpl = new NoUnderlyingToken(address(factory), address(0), ZUID, false);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.NONE, 1, address(pImpl));
        IFactoryToken.TokenConfig memory pc;
        (pc.name, pc.symbol, pc.decimals, pc.features) = ("Points", "PTS", 6, 1 << AdminLib.PAYABLE);
        (pc.initialSupply, pc.initialHolder) = (50 * SCALE, payer);
        NoUnderlyingToken pts = NoUnderlyingToken(factory.createToken(IOpenFactory.TokenKind.NONE, 1, pc, "pts"));
        address[] memory legs = new address[](1);
        legs[0] = address(pts);
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), _ones(1), "zpts", false);
        ITradeToken.TradeOrder memory o;
        (o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.dex) =
            (payer, address(z), 20 * SCALE, 20 * SCALE, 20 * SCALE, address(z));
        (o.batch, o.nonce, o.validUntil) = (7, 1, block.timestamp + 300);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, pts.tradeOrderDigest(o));
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.prank(relayer);
        z.mtxWrap(address(pts), o, sig);
        assertEq(z.balanceOf(payer), 20 * SCALE);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: abi.encodeCall(ZetherLayer.zetherShield, (bob.y, 20)), batch: 2, nonce: 0,
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0,
            feeRecipient: address(0)
        });
        (v, r, s) = vm.sign(PAYER_PK, z.mtxDigest(m));
        sig = abi.encodePacked(r, s, v);
        vm.prank(relayer);
        z.mtxExecute(m, sig);
        assertEq(z.balanceOf(payer), 0);
        assertEq(z.totalShielded(), 20);
        assertEq(pts.allowance(payer, address(z)), 0);
    }

    // ------------------------------------------------------------------ the native leg (CTR-TOK-26)

    function test_nativeLeg_wrapShieldPayable_notGasless() public {
        address[] memory legs = new address[](1);
        uint256[] memory dens = new uint256[](1);
        dens[0] = 1e12; // 1e12 wei = 1 public unit
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), dens, "native", false);
        vm.deal(address(this), 1 ether);
        z.zetherWrapShield{value: 3e16}(address(0), 3e16, alice.ua);
        assertEq(z.totalShielded(), 3);
        assertEq(address(z).balance, 3e16);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 3e16));
        z.zetherWrapShield(address(0), 3e16, alice.ua);
    }

    // ------------------------------------------------------------------ re-entry and the allowlist

    /// A hook leg that calls the token back mid-payout or mid-pull hits the contract-wide guard.
    function test_reentryThroughAHookLegRefused() public {
        HookLeg hook = new HookLeg();
        address[] memory legs = new address[](1);
        legs[0] = address(hook);
        UnderlyingZetherToken z = _wrapper(legs, _ones(1), _ones(1), "hook", false);
        hook.mint(address(this), 50 * SCALE);
        hook.approve(address(z), 50 * SCALE);
        z.zetherWrapShield(address(hook), 30 * SCALE, alice.ua);
        z.zetherRollOver(alice.ua);
        hook.arm(address(z), abi.encodeCall(ZetherLayer.zetherRollOver, (bob.ua)));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        z.zetherWrapShield(address(hook), SCALE, alice.ua);
        bytes memory pl = _unshieldPayload(ZetherLayer(address(z)), alice);
        bytes memory st = stm.unshieldUnwrapStatement(address(z), pl, 10, address(0xD00D), _none(), address(hook), 0, 0);
        bytes memory pr = _proveU(alice, st, 10, 30, _none(), ZetherLayer(address(z)));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(hook), address(0xD00D), 10, 0);
        hook.arm(address(0), "");
        z.zetherUnshieldUnwrap(pl, pr, "", _none(), address(hook), address(0xD00D), 10, 0);
        assertEq(hook.balanceOf(address(0xD00D)), 10 * SCALE);
    }

    function test_allowlistPinned_underlyingZether() public {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = w.mtxSelectors();
        assertEq(s.length, 14);
        assertEq(s[12], UnderlyingZetherToken.zetherWrapShield.selector);
        assertEq(s[13], UnderlyingZetherToken.zetherUnshieldUnwrap.selector);
        assertEq(s[6], ZetherLayer.zetherShield.selector);
        assertEq(s[11], ZetherLayer.zetherUnshield.selector);
        for (uint256 i = 6; i < 14; ++i) {
            assertEq(c[i], 1, "ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(c[4], 2);
        assertEq(a[4], 1, "unwrap(address,uint256,address,uint256) AMOUNT(1) as on UNDERLYING");
        // the static shape of wrap-shield is pinned: a longer `data` is refused at step 3
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: payer, data: bytes.concat(abi.encodeCall(UnderlyingZetherToken.zetherWrapShield,
                (address(usd), SCALE, alice.ua)), hex"00"), batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(PAYER_PK, w.mtxDigest(m));
        bytes memory sig = abi.encodePacked(r, sg, v);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, UnderlyingZetherToken.zetherWrapShield.selector));
        w.mtxExecute(m, sig);
        assertEq(w.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        (, string memory n,,,,,) = w.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
    }
}
```

- [ ] **Step 4: `test/zether/ZetherInvariant.t.sol`** (new; CTR-ZTH-22 (a): ghost plaintext balances, real proofs):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Random shield / wrap-shield / transfer / roll-over / unshield / unshield-unwrap / unwrap sequences on one
/// `UNDERLYING_ZETHER` token (one USD leg 1:1, bn254, no auditor), real proofs; the plaintext balances are the ghost.
contract ZetherHandler is ZetherFixture {
    UnderlyingZetherToken public w;
    MockERC20 public usd;
    User[3] internal us;
    uint256[3] public acc;
    uint256[3] public pend;
    uint256 internal constant MAX = 1 << 30;

    constructor() {
        _stack(false);
        usd = new MockERC20("USD", "USD", 6);
        UnderlyingZetherToken impl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(impl));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, MAX, FEE);
        w = UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "inv")));
        tok = ZetherLayer(address(w));
        _users();
        us[0] = alice;
        us[1] = bob;
        us[2] = carol;
    }

    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        UnderlyingToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
    }

    function shield(uint8 i, uint256 amt) external {
        i %= 3;
        amt = bound(amt, 1, 50);
        _fund(tok, us[i], amt);
        pend[i] += amt;
    }

    function wrapShield(uint8 i, uint256 amt) external {
        i %= 3;
        amt = bound(amt, 1, 50);
        usd.mint(address(this), amt * SCALE);
        usd.approve(address(w), amt * SCALE);
        w.zetherWrapShield(address(usd), amt * SCALE, us[i].ua);
        pend[i] += amt;
    }

    function rollOver(uint8 i) external {
        i %= 3;
        tok.zetherRollOver(us[i].ua);
        acc[i] += pend[i];
        pend[i] = 0;
    }

    function transfer(uint8 i, uint8 j, uint256 v) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) return;
        v = bound(v, 0, acc[i]);
        _direct(tok, _proveTransfer(tok, us[i], us[j], v, acc[i], _none(), 0), _none());
        acc[i] -= v;
        pend[j] += v;
    }

    function unshield(uint8 i, uint256 amt, bool toUnderlying) external {
        i %= 3;
        if (acc[i] == 0) return;
        amt = bound(amt, 1, acc[i]);
        if (toUnderlying) {
            bytes memory pl = _unshieldPayload(tok, us[i]);
            bytes memory st = stm.unshieldUnwrapStatement(address(w), pl, amt, address(0xD00D), _none(), address(usd), 0, 0);
            w.zetherUnshieldUnwrap(pl, _proveU(us[i], st, amt, acc[i], _none(), tok), "", _none(), address(usd),
                address(0xD00D), amt, 0);
        } else {
            (bytes memory pl, bytes memory pr) = _proveUnshield(tok, us[i], amt, acc[i], address(this), _none(), 0);
            tok.zetherUnshield(pl, pr, "", _none(), address(this), amt);
        }
        acc[i] -= amt;
    }

    function unwrap(uint256 amt) external {
        uint256 bal = w.balanceOf(address(this));
        if (bal == 0) return;
        w.unwrap(address(usd), bound(amt, 1, bal), address(0xD00D), 0);
    }

    /// Every ghost balance holds (`[b]G == C − [x]D`), Σ == totalShielded ≤ cap, and the reserve covers the public and
    /// the shielded units (CTR-ZTH-22 a).
    function check() external view {
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            require(_holds(tok, us[i], acc[i], true), "acc");
            require(_holds(tok, us[i], pend[i], false), "pending");
            sum += acc[i] + pend[i];
        }
        require(sum == w.totalShielded(), "sum == totalShielded");
        require(sum <= w.maxDecryptableShielded(), "cap");
        (,, uint256 reserve,,) = w.legOf(address(usd));
        require(usd.balanceOf(address(w)) == reserve, "balance == reserve");
        require(w.collateralValue() >= w.totalSupply() + w.totalShielded() * SCALE, "reserve invariant");
    }
}

contract ZetherInvariantTest is Test {
    ZetherHandler internal h;

    function setUp() public {
        h = new ZetherHandler();
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](7);
        (sel[0], sel[1], sel[2], sel[3]) = (h.shield.selector, h.wrapShield.selector, h.rollOver.selector, h.transfer.selector);
        (sel[4], sel[5], sel[6]) = (h.unshield.selector, h.unwrap.selector, h.shield.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    /// forge-config: default.invariant.runs = 8
    /// forge-config: default.invariant.depth = 16
    function invariant_balancesConservationAndReserve() public view {
        h.check();
    }
}
```

- [ ] **Step 5: layout pin, lint, size** (`cp test/v2/layout/UnderlyingToken.json test/v2/layout/UnderlyingZetherToken.json`):

```diff
diff --git a/smartcontracts/evm/size-baseline.json b/smartcontracts/evm/size-baseline.json
index 76c78b6..1ea808f 100644
--- a/smartcontracts/evm/size-baseline.json
+++ b/smartcontracts/evm/size-baseline.json
@@ -2,5 +2,6 @@
   "_comment": "CTR-TOK-24 size gate (scripts/size_gate.py). Contracts allowed over their limit, with the measured runtime size they may not exceed. Owner 2026-10-11: size optimised later; remove an entry once the contract fits.",
   "NoUnderlyingToken": 22978,
   "UnderlyingToken": 30036,
-  "NoUnderlyingZetherToken": 30659
+  "NoUnderlyingZetherToken": 30659,
+  "UnderlyingZetherToken": 40381
 }
diff --git a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
index b97e4f8..a7d2537 100644
--- a/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
+++ b/smartcontracts/evm/test/metatx/MsgSenderLint.t.sol
@@ -9,10 +9,10 @@ import {Test} from "forge-std/Test.sol";
 /// are `//` are skipped (block comments are not). A change here is deliberate: update the pin in the same commit and
 /// say why.
 contract MsgSenderLintTest is Test {
-    string[12] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
+    string[13] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
         "src/metatx/NoUnderlyingToken.sol", "src/metatx/UnderlyingToken.sol", "src/metatx/UnderlyingLib.sol",
         "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol", "src/zether/ZetherLayer.sol",
-        "src/zether/ZetherLib.sol", "src/zether/NoUnderlyingZetherToken.sol"];
+        "src/zether/ZetherLib.sol", "src/zether/NoUnderlyingZetherToken.sol", "src/zether/UnderlyingZetherToken.sol"];
 
     /// Occurrences of `pat` (not preceded by an identifier character); `exceptSelector` skips `pat<ident>.selector`.
     function _count(string memory path, bytes memory pat, bool exceptSelector) internal view returns (uint256 n) {
@@ -66,6 +66,7 @@ contract MsgSenderLintTest is Test {
         assertEq(_count("src/zether/ZetherLayer.sol", "msg.sender", false), 0, "ZetherLayer");
         assertEq(_count("src/zether/ZetherLib.sol", "msg.sender", false), 0, "ZetherLib");
         assertEq(_count("src/zether/NoUnderlyingZetherToken.sol", "msg.sender", false), 0, "NoUnderlyingZetherToken");
+        assertEq(_count("src/zether/UnderlyingZetherToken.sol", "msg.sender", false), 0, "UnderlyingZetherToken");
     }
 
     /// CTR-MTX-18: an external self-call (`this.f(…)`) inside an allowlisted body would let a guarded callee consume
diff --git a/smartcontracts/evm/test/v2/Layout.t.sol b/smartcontracts/evm/test/v2/Layout.t.sol
index 10f4a73..90dc5d0 100644
--- a/smartcontracts/evm/test/v2/Layout.t.sol
+++ b/smartcontracts/evm/test/v2/Layout.t.sol
@@ -32,6 +32,7 @@ contract LayoutTest is V2Fixture {
         _pin("NoUnderlyingToken", "NoUnderlyingToken");
         _pin("UnderlyingToken", "UnderlyingToken");
         _pin("NoUnderlyingZetherToken", "NoUnderlyingZetherToken"); // the Zether layer lives in `scaas.zether`
+        _pin("UnderlyingZetherToken", "UnderlyingZetherToken");
     }
 
     /// Thứ indexer thật sự đọc (ERC-7201 `scaas.underlying`): chân i ở `keccak256(i ‖ NS)`: `token`, `+ 1` `num ‖ den`,
```

- [ ] **Step 6: Run:** `forge test --match-path "test/zether/Zether{Underlying,Invariant}.t.sol"` → 14 passed
  (invariant: 8 runs × 16 calls, 0 reverts); `forge test` → **967 passed**; size gate 0 errors
  (`UnderlyingZetherToken` 40,381 B, init 41,991 B < 49,152).
- [ ] **Step 7: Commit** `P3: UNDERLYING_ZETHER kind — wrap-shield, unshield-unwrap, reserve invariant with the shielded part` + trailer.

---

### Task 6: Deploy, size gate, e2e, the mutation probe

**Model:** Sonnet, effort high (deploy check and the probe are the gate of the whole plan).

**Files:**
- Modify: `script/DeployBase.sol`, `scripts/size_gate.py`, `size-baseline.json`
- Create: `test/zether/ZetherDeploy.t.sol`

- [ ] **Step 1: `DeployBase` deploys the Zether stack on dev chains** (K16):

```diff
diff --git a/smartcontracts/evm/script/DeployBase.sol b/smartcontracts/evm/script/DeployBase.sol
index 1fc5227..5f2929c 100644
--- a/smartcontracts/evm/script/DeployBase.sol
+++ b/smartcontracts/evm/script/DeployBase.sol
@@ -6,6 +6,13 @@ import {OpenFactory} from "../src/factory/OpenFactory.sol";
 import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
 import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
 import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
+import {UniversalAccountRegistry} from "../src/registry/UniversalAccountRegistry.sol";
+import {ZetherSafety} from "../src/zether/ZetherSafety.sol";
+import {ZetherDisclosure} from "../src/zether/ZetherDisclosure.sol";
+import {ZetherStatements} from "../src/zether/ZetherStatements.sol";
+import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../src/zether/ZetherVerifier.sol";
+import {NoUnderlyingZetherToken} from "../src/zether/NoUnderlyingZetherToken.sol";
+import {UnderlyingZetherToken} from "../src/zether/UnderlyingZetherToken.sol";
 
 /// @title Shared deploy steps (CTR-GEN-05, CTR-GEN-06, NET-EVM-05): `chain_uid` from the RPC, the deterministic CREATE2
 ///        deployer, the token factory with its implementations, the `chainUid()` gate.
@@ -42,8 +49,9 @@ abstract contract DeployBase is Script {
 
     /// @notice The token factory, the `NONE` implementation and the `SCaaSDex` implementation by CREATE2, each
     ///         registered as version 1 when the deployer is the registrar; writes `token_factory`,
-    ///         `implementation_none`, `dex_implementation`, `chain_uid` into the JSON object `"deploy"`. `UNDERLYING` is
-    ///         not deployed: over EIP-170 on real chains (owner: wait for Glamsterdam).
+    ///         `implementation_none`, `dex_implementation`, `chain_uid` into the JSON object `"deploy"`; on a dev chain
+    ///         also the Zether stack (`_deployZether`). `UNDERLYING` is not deployed: over EIP-170 on real chains
+    ///         (owner: wait for Glamsterdam).
     function _deployTokenFactory(address registrar, bool register, address smartKeyAccountImpl, bool isHedera)
         internal returns (OpenFactory f)
     {
@@ -60,9 +68,41 @@ abstract contract DeployBase is Script {
         if (register) f.registerDexImplementation(1, address(dexImpl));
         _gate(address(dexImpl));
         vm.serializeAddress("deploy", "dex_implementation", address(dexImpl));
+        if (ZetherSafety.isDevChain()) _deployZether(f, register, smartKeyAccountImpl);
         vm.serializeBytes32("deploy", "chain_uid", uid);
     }
 
+    /// @notice Dev chains only (CTR-ZTH-02; elsewhere the registry and the verifiers refuse to deploy): the account
+    ///         registry, `ZetherDisclosure`, `ZetherStatements`, both verifiers, the two confidential implementations
+    ///         registered as version 1 of `NONE_ZETHER` and `UNDERLYING_ZETHER`, and the factory's Zether gate switched on
+    ///         when the deployer is the registrar. **UNAUDITED — NOT FOR PRODUCTION FUNDS.** The implementations exceed
+    ///         EIP-170: an anvil needs `--code-size-limit 65536` (owner: code size waits for Glamsterdam).
+    function _deployZether(OpenFactory f, bool register, address smartKeyAccountImpl) internal {
+        UniversalAccountRegistry reg = new UniversalAccountRegistry{salt: salt}();
+        ZetherDisclosure dis = new ZetherDisclosure{salt: salt}();
+        ZetherStatements stm = new ZetherStatements{salt: salt}();
+        ZetherVerifierBn254 bn = new ZetherVerifierBn254{salt: salt}();
+        ZetherVerifierBls12381 bls = new ZetherVerifierBls12381{salt: salt}();
+        NoUnderlyingZetherToken none =
+            new NoUnderlyingZetherToken{salt: salt}(address(f), smartKeyAccountImpl, uid, address(reg), dis);
+        UnderlyingZetherToken und =
+            new UnderlyingZetherToken{salt: salt}(address(f), smartKeyAccountImpl, uid, address(reg), dis);
+        if (register) {
+            f.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER, 1, address(none));
+            f.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(und));
+            f.setZetherEnabled(true);
+        }
+        _gate(address(none));
+        _gate(address(und));
+        vm.serializeAddress("deploy", "zether_registry", address(reg));
+        vm.serializeAddress("deploy", "zether_disclosure", address(dis));
+        vm.serializeAddress("deploy", "zether_statements", address(stm));
+        vm.serializeAddress("deploy", "zether_verifier_bn254", address(bn));
+        vm.serializeAddress("deploy", "zether_verifier_bls12381", address(bls));
+        vm.serializeAddress("deploy", "implementation_none_zether", address(none));
+        vm.serializeAddress("deploy", "implementation_underlying_zether", address(und));
+    }
+
     /// @notice The deploy gate (CTR-GEN-05): `chainUid()` of the deployed contract equals the RPC's genesis hash.
     function _gate(address c) internal view {
         (bool ok, bytes memory ret) = c.staticcall(abi.encodeWithSignature("chainUid()"));
```

- [ ] **Step 2: `test/zether/ZetherDeploy.t.sol`** (new):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployBase} from "../../script/DeployBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UniversalAccountRegistry} from "../../src/registry/UniversalAccountRegistry.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {ZetherVerifierBn254} from "../../src/zether/ZetherVerifier.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";

/// The deploy steps without the RPC parts (`_setup`): the salt and `chain_uid` set directly.
contract DeployHarness is DeployBase {
    function deploy(bytes32 uid_) external returns (OpenFactory) {
        salt = keccak256("scaas.deploy.v1");
        uid = uid_;
        return _deployTokenFactory(address(this), true, address(0), false);
    }
}

/// @notice `DeployBase` on a dev chain deploys and registers the Zether stack (kinds 2 and 3, the gate on); on any
///         other chain (the e2e's 319xx and Hedera's 298 included) it deploys none of it.
contract ZetherDeployTest is Test {
    function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
        return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
    }

    function test_devChain_registersBothConfidentialKinds() public {
        DeployHarness h = new DeployHarness();
        OpenFactory f = h.deploy(ZUID);
        assertTrue(f.zetherEnabled());
        NoUnderlyingZetherToken none = NoUnderlyingZetherToken(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1));
        UnderlyingZetherToken und =
            UnderlyingZetherToken(payable(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1)));
        assertEq(none.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(und.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        address reg = _at(h, type(UniversalAccountRegistry).creationCode);
        address dis = _at(h, type(ZetherDisclosure).creationCode);
        address bn = _at(h, type(ZetherVerifierBn254).creationCode);
        assertEq(none.registry(), reg);
        assertEq(address(und.disclosure()), dis);
        // a token from the deployed catalogue, on the deployed verifier
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.conf = IFactoryToken.ConfidentialConfig(bn, "", 1, 1 << 40, 0);
        ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "z"));
        assertEq(address(t.verifier()), bn);
        assertEq(t.chainUid(), ZUID);
    }

    function test_otherChains_noZether() public {
        uint256[3] memory ids = [uint256(31901), 298, 7622];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            OpenFactory f = h.deploy(ZUID);
            assertFalse(f.zetherEnabled());
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE, 1) == address(0), false, "the public kinds still");
        }
    }
}
```

- [ ] **Step 3: the size gate counts the new kinds as tokens; the final baseline** (K17):

```diff
diff --git a/scripts/size_gate.py b/scripts/size_gate.py
index 18cc21f..b152edd 100755
--- a/scripts/size_gate.py
+++ b/scripts/size_gate.py
@@ -10,7 +10,7 @@ usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
 import json
 import sys
 
-TOKENS = {'NoUnderlyingToken', 'UnderlyingToken'}
+TOKENS = {'NoUnderlyingToken', 'UnderlyingToken', 'NoUnderlyingZetherToken', 'UnderlyingZetherToken'}
 TOKEN_LIMIT, EIP170, EIP3860 = 20_480, 24_576, 49_152
 
 
@@ -49,6 +49,7 @@ if __name__ == '__main__':
         assert check({'A': s(24_576)}, {}) == ([], [])
         assert check({'A': s(24_577)}, {})[0]
         assert check({'NoUnderlyingToken': s(20_481)}, {})[0]
+        assert check({'UnderlyingZetherToken': s(20_481)}, {})[0]
         assert check({'X': s(26_000)}, {'X': 26_000}) == ([], [])
         assert check({'X': s(26_001)}, {'X': 26_000})[0]
         assert check({'X': s(20_000)}, {'X': 26_000})[1]
```

- [ ] **Step 4: Run** (each through `scripts/capped`, one at a time):
  - `python3 scripts/size_gate.py --self-test`; `forge test` → **969 passed**, 0 failed; size gate `0 error(s)`
    (`NoUnderlyingToken` 22,978, `UnderlyingToken` 30,036, `NoUnderlyingZetherToken` 30,659,
    `UnderlyingZetherToken` 40,381).
  - e2e: `forge build` (full), then in `scaas-node`: `cargo test --test e2e -- --ignored --test-threads=1` → 4 passed;
    `cargo test --test e2e_hedera -- --ignored` → 1 passed (no node change: the node reads nothing of Zether; the e2e
    chains are not dev chains, so the deploy skips the Zether stack). If `forge script Deploy.s.sol` hangs with
    deploy transactions pending on anvil (seen once, see Open questions), stop and rerun.
  - **Mutation probe** (not committed; save as a scratch file, run with `scripts/capped python3 <file>`; set `W` to the
    worktree). Every mutant must be `KILLED`. Validated: 80/80 killed (first run 77/79: M33 and N5 survived and were killed after the RELAYED-tag pin and the initial-supply check were added; M34 changed and Y12 was added with the one-slot HASH record, both killed on the rerun).

```python
import subprocess, sys
W='/home/ha/work/ainative/scaas/.claude/worktrees/p3/smartcontracts/evm'
L=W+'/src/zether/ZetherLib.sol'
Y=W+'/src/zether/ZetherLayer.sol'
N=W+'/src/zether/NoUnderlyingZetherToken.sol'
U=W+'/src/zether/UnderlyingZetherToken.sol'
S=W+'/src/zether/ZetherStatements.sol'
D=W+'/src/zether/ZetherDisclosure.sol'
V=W+'/src/zether/ZetherVerifier.sol'
B=W+'/src/metatx/MetaTxBase.sol'
F=W+'/src/factory/OpenFactory.sol'
Z='test/zether/*'
FZ='test/v2/FactoryZether.t.sol'
muts=[
 # ZetherLib
 ('M1 shield: registration unchecked', L, 'if (IUniversalAccountRegistry(registry).keyLengthOf(ua) != s.p) revert IZetherToken.AccountNotRegistered(ua);', '', Z),
 ('M2 shield: cap off by one', L, 'if (amount == 0 || amount > room) revert IZetherToken.AmountOutOfRange(amount, room);', 'if (amount == 0 || amount > room + 1) revert IZetherToken.AmountOutOfRange(amount, room);', Z),
 ('M3 shield: totalShielded not raised', L, '        s.totalShielded += amount;\n', '', Z),
 ('M4 shield: credit amount + 1', L, '_credit(s, ua, s.verifier.g1MulBase(amount), "");', '_credit(s, ua, s.verifier.g1MulBase(amount + 1), "");', Z),
 ('M5 init: fee < cap unchecked', L, '|| c.confidentialFee >= VALUE_BOUND || c.confidentialFee >= c.maxShielded', '|| c.confidentialFee >= VALUE_BOUND', Z),
 ('M6 init: 2^54 cap unchecked', L, 'if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > MAX_TOTAL_SHIELDED', 'if (c.shieldScale == 0 || c.maxShielded == 0', Z),
 ('M7 init: auditor key unchecked', L, '|| (aud.length != 0 && (aud.length != p || !v.isValidPoint(aud) || _isO(aud)))) {', ') {', Z),
 ('M8 init: cap x scale overflow unchecked', L, 'if (c.maxShielded > type(uint256).max / c.shieldScale) revert IZetherToken.BadInit();', '', Z),
 ('M9 init: dev chain unchecked', L, '        ZetherSafety.requireDevChain();\n        IZetherVerifier v', '        IZetherVerifier v', Z),
 ('M10 header without chainUid', L, 'abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding)', 'abi.encode(op, psid, block.chainid, bytes32(0), c.token, c.tag, c.binding)', Z),
 ('M11 entryRef without chainUid', L, 'keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)))', 'keccak256(abi.encode(TAG_ENTRY, block.chainid, bytes32(0), c.token, from, uint256(counter)))', Z),
 ('M12 roll-over digest without chainUid', L, 'TAG_ROLLOVER, block.chainid, e.chainUid, address(this)', 'TAG_ROLLOVER, block.chainid, address(this)', Z),
 ('M13 mode digest without chainUid', L, 'TAG_SET_MODE, block.chainid, e.chainUid, address(this)', 'TAG_SET_MODE, block.chainid, address(this)', Z),
 ('M14 accSeq unchecked', L, 'if (provedAccSeq != a.accSeq) revert IZetherToken.StaleAccSeq(a.accSeq, provedAccSeq);', '', Z),
 ('M15 sendCounter unchecked', L, 'if (provedSend != a.sendCounter) revert IZetherToken.StaleSendCounter(a.sendCounter, provedSend);', '', Z),
 ('M16 sendCounter not advanced', L, 's.acct[pp.from].sendCounter = pp.sendCounter + 1;', 's.acct[pp.from].sendCounter = pp.sendCounter;', Z),
 ('M17 unshield: totalShielded not lowered', L, '        s.totalShielded -= amount;\n', '', Z),
 ('M18 unshield: fee not debited', L, 'c.ver.g1MulBase(amount + pp.fee)', 'c.ver.g1MulBase(amount)', Z),
 ('M19 unshield: amount 0 allowed', L, 'if (amount == 0 || amount > c.maxShielded)', 'if (amount > c.maxShielded)', Z),
 ('M20 unshield: zero recipient allowed', L, 'if (recipient == address(0)) revert IZetherToken.ZeroRecipient();', '', Z),
 ('M21 beneficiary registration unchecked', L, '        _requireRegistered(c, beneficiary);\n        return c.fee;', '        return c.fee;', Z),
 ('M22 self transfer allowed', L, 'if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();', '', Z),
 ('M23 duplicate recipient allowed', L, 'for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert IZetherToken.DuplicateRecipient(to[j]);', '', Z),
 ('M24 proof result ignored', L, '        if (!ok) revert IZetherToken.ProofRejected();', '        ok;', Z),
 ('M25 spending authority unchecked', L, '''        IUniversalAccountRegistry(c.registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        bool ok''', '        bool ok', Z),
 ('M26 inner fee not credited', L, 'if (pp.fee != 0) _credit(s, pp.beneficiary, c.ver.g1MulBase(pp.fee), "");', '', Z),
 ('M27 transfer: fee not debited', L, 'if (fee != 0) cc = c.ver.g1Sub(cc, c.ver.g1MulBase(fee));', '', Z),
 ('M28 auditor legs mix allowed', L, 'if (nOff != 0) revert IZetherToken.AuditorLegsMixed();', '', Z),
 ('M29 OWNER_ONLY roll-over open', L, 'if (s.acct[ua].mode == ZetherTypes.RollOverMode.OWNER_ONLY) revert IZetherToken.RollOverOwnerOnly(ua);', '', Z),
 ('M30 batch rolls OWNER_ONLY', L, 'if (s.acct[uas[i]].mode == ZetherTypes.RollOverMode.PUBLIC) _rollOver(s, uas[i]);', '_rollOver(s, uas[i]);', Z),
 ('M31 signed roll-over without new credit', L, 'if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {', 'if (a.pendingSeq < expectedPendingSeq) {', Z),
 ('M32 roll-over no-op rule off', L, '        if (a.pendingSeq == a.lastRolledPendingSeq) return;\n', '', Z),
 ('M33 tag always DIRECT', L, 'return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;', 'return TAG_DIRECT;', Z),
 ('M34 HASH in two slots (as built)', L, 's.entryHashes[entryRef] = keccak256(bundles);', 's.entries[entryRef] = abi.encodePacked(keccak256(bundles));', Z),
 ('M35 mode nonce not advanced', L, '        a.modeNonce += 1;\n', '', Z),
 ('M36 roll-over signature expiry off', L, '        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);\n        ZetherStorage storage s = $();\n        Account storage a = s.acct[ua];', '        ZetherStorage storage s = $();\n        Account storage a = s.acct[ua];', Z),
 # ZetherLayer
 ('Y1 shield burns msg.sender', Y, '_burn(_msgSender(), amount * ZetherLib.$().shieldScale);', '_burn(msg.sender, amount * ZetherLib.$().shieldScale);', 'test/zether/ZetherRelay.t.sol'),
 ('Y2 shield burns unscaled', Y, '_burn(_msgSender(), amount * ZetherLib.$().shieldScale);', '_burn(_msgSender(), amount);', Z),
 ('Y3 unshield mints unscaled', Y, '_mint(to, amount * ZetherLib.$().shieldScale);', '_mint(to, amount);', Z),
 ('Y4 binding ignored', Y, '        bytes32 b = _ticketBinding();\n        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b);', '        bytes32 b;\n        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b);', Z),
 ('Y5 binding without chainUid', Y, 'ZetherLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this)', 'ZetherLib.TAG_ENVELOPE, block.chainid, bytes32(0), address(this)', Z),
 ('Y6 binding without fee', Y, '            m.mode, r, m.fee, f', '            m.mode, r, uint256(0), f', Z),
 ('Y7 transferSingle unguarded', Y, '''    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)''', '''    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32)''', Z),
 ('Y8 roll-over unguarded', Y, '    function zetherRollOver(ZetherTypes.UA ua) external nonReentrant {', '    function zetherRollOver(ZetherTypes.UA ua) external {', Z),
 ('Y9 registered on any curve', Y, 'return IUniversalAccountRegistry(_REGISTRY).keyLengthOf(ua) == ZetherLib.$().p;', 'return IUniversalAccountRegistry(_REGISTRY).keyLengthOf(ua) != 0;', Z),
 ('Y10 constructor checks off', Y, 'if (registry_.code.length == 0 || address(disclosure_).code.length == 0) revert BadInit();', '', Z),
 ('Y12 HASH record not read', Y, 'return h != bytes32(0) ? abi.encodePacked(h) : ZetherLib.$().entries[entryRef];', 'return ZetherLib.$().entries[entryRef];', Z),
 ('Y11 unshield not allowlisted', Y, '|| sel == this.zetherTransferSingle.selector || sel == this.zetherUnshield.selector;', '|| sel == this.zetherTransferSingle.selector;', Z),
 # NoUnderlyingZetherToken
 ('N1 init skips the layer', N, '        ZetherLib.init(cfg.conf);\n', '', Z),
 ('N2 conf refused', N, '_requireUnused(cfg, false, true, true, false);', '_requireUnused(cfg, false, true, true, true);', Z),
 ('N3 regulated flags valid', N, 'AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features', 'AdminLib.init(AdminLib.KIND_NONE, cfg.features', Z),
 ('N4 allowlist entry dropped', N, '(s[7], c[7]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);', '', Z),
 ('N5 initial supply ignored', N, '        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);\n', '', Z),
 # UnderlyingZetherToken
 ('U1 wrap-shield: scale remainder allowed', U, 'if (minted % scale != 0) revert AmountNotScaled(minted, scale);', '', Z),
 ('U2 wrap-shield: credits minted', U, 'ZetherLib.shield(ua, minted / scale, _REGISTRY);', 'ZetherLib.shield(ua, minted, _REGISTRY);', Z),
 ('U3 direct unwrap binds nothing', U, 'return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, ZetherLib.unwrapBinding(u, minOut));', 'return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, bytes32(0));', Z),
 ('U4 relayed unwrap not relayed', U, 'if (b != bytes32(0)) return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_RELAYED, b);', '', Z),
 ('U5 unwrap pays unscaled', U, 'UnderlyingLib.quoteUnwrap(i, x.amount * ZetherLib.$().shieldScale, x.recipient, x.minOut);', 'UnderlyingLib.quoteUnwrap(i, x.amount, x.recipient, x.minOut);', Z),
 ('U6 executeRate ignores the shielded value', U, 'UnderlyingLib.executeRate(_msgSender(), totalSupply() + ZetherLib.$().totalShielded * ZetherLib.$().shieldScale);', 'UnderlyingLib.executeRate(_msgSender(), totalSupply());', Z),
 ('U7 disableFeature keeps the pending rate', U, '        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();\n    }\n\n    /// @notice The collateral', '    }\n\n    /// @notice The collateral', Z),
 ('U8 wrap-shield unguarded', U, 'function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable nonReentrant {', 'function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable {', Z),
 ('U9 unshield-unwrap unguarded', U, '    ) external nonReentrant {\n        _unshieldUnwrap(', '    ) external {\n        _unshieldUnwrap(', Z),
 ('U10 kind 3 flags as UNDERLYING', U, 'UnderlyingLib.initToken(cfg, false, AdminLib.KIND_UNDERLYING_ZETHER);', 'UnderlyingLib.initToken(cfg, false, AdminLib.KIND_UNDERLYING);', Z),
 ('U11 wrap-shield static shape off', U, 'if (sel == this.zetherWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);', 'if (sel == this.zetherWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);', Z),
 # ZetherStatements
 ('S1 view always DIRECT', S, 'ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);\n        ZetherLib.Acct memory a = _acct(token, ZetherLib.singleFrom(payload, c.p));', 'ZetherLib.Ctx memory c = _ctx(token, ZetherLib.TAG_DIRECT, envelopeBinding);\n        ZetherLib.Acct memory a = _acct(token, ZetherLib.singleFrom(payload, c.p));', Z),
 ('S2 unwrap view binds nothing', S, 'return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_DIRECT, unwrapBinding(u, minOut));', 'return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_DIRECT, bytes32(0));', Z),
 # ZetherDisclosure, ZetherVerifier
 ('D1 disclosure challenge without chainUid', D, 'DISCLOSE_TAG, block.chainid, IMetaTx(token).chainUid(), token,', 'DISCLOSE_TAG, block.chainid, token,', Z),
 ('V1 header 384', V, 'uint256 internal constant HEADER = 416;', 'uint256 internal constant HEADER = 384;', Z),
 ('V2 fee read at the old offset', V, 'uint256 internal constant FEE_AT = 288;', 'uint256 internal constant FEE_AT = 256;', Z),
 ('V3 D_out = O allowed', V, 'if (_isZero(_sp(x, 6)) || _isZero(_sp(x, 0)) || _isZero(_sp(x, 1))', 'if (_isZero(_sp(x, 0)) || _isZero(_sp(x, 1))', Z),
 ('V4 amount read at the old offset', V, 'uint256 internal constant AMOUNT_AT = 352;', 'uint256 internal constant AMOUNT_AT = 320;', Z),
 # MetaTxBase
 ('B1 binding not stored', B, '        if (binding != bytes32(0)) _tstore(_BINDING, uint256(binding));\n', '', Z),
 ('B2 binding read without a ticket', B, 'if (msg.sender == address(this) && _tload(_TICKET) != 0) return bytes32(_tload(_BINDING));', 'return bytes32(_tload(_BINDING));', Z),
 # OpenFactory
 ('F1 gate flag ignored', F, '        if (!zetherEnabled) revert ZetherDisabled();\n', '', FZ),
 ('F2 gate dev chain ignored', F, '        ZetherSafety.requireDevChain(); // a flag set', '        // a flag set', FZ),
 ('F3 enable anywhere', F, '        if (on) ZetherSafety.requireDevChain();\n', '', FZ),
 ('F4 verifier 0 allowed', F, '        if (verifier == address(0)) revert VerifierRequiredForZether();\n', '', FZ),
 ('F5 unsupported verifier allowed', F, '        if (ok) return;\n        string memory curve;', '        return;\n        string memory curve;', FZ),
 ('F6 gate only for kind 2', F, 'if (kind == TokenKind.NONE_ZETHER || kind == TokenKind.UNDERLYING_ZETHER) _checkZether(cfg.conf.verifier);', 'if (kind == TokenKind.NONE_ZETHER) _checkZether(cfg.conf.verifier);', FZ),
 ('F7 anyone switches the gate', F, '''    function setZetherEnabled(bool on) external {
        if (msg.sender != registrar) revert NotRegistrar();''', '''    function setZetherEnabled(bool on) external {''', FZ),
]
sel=sys.argv[1:]
for name,f,a,b,path in muts:
    if sel and name.split()[0] not in sel: continue
    src=open(f).read(); assert src.count(a)==1,(name, src.count(a))
    open(f,'w').write(src.replace(a,b))
    try:
        r=subprocess.run(['forge','test','--fail-fast','--match-path',path],cwd=W,capture_output=True,text=True)
        out=r.stdout+r.stderr
        fails=[l for l in out.splitlines() if l.startswith('[FAIL')]
        comp='Compiler run failed' in out or 'Compilation failed' in out
        status='KILLED' if fails or comp or r.returncode!=0 else 'SURVIVED'
        print(name, '|', status, '|', (fails[0][:160] if fails else ('compile' if comp else '')), flush=True)
    finally:
        open(f,'w').write(src)
```

  | Mutant | Killed by (first failing test of the run) |
  |---|---|
  | M1 shield: registration unchecked | `test_shieldRevertPaths` |
  | M2 shield: cap off by one | `test_shieldRevertPaths` |
  | M3 shield: totalShielded not raised | `invariant_balancesConservationAndReserve` |
  | M4 shield: credit amount + 1 | `invariant_balancesConservationAndReserve` |
  | M5 init: fee < cap unchecked | `test_confidentialFeeBound` |
  | M6 init: 2^54 cap unchecked | `test_initializeRevertPaths` |
  | M7 init: auditor key unchecked | `test_initializeRevertPaths` |
  | M8 init: cap x scale overflow unchecked | `test_initializeRevertPaths` |
  | M9 init: dev chain unchecked | `test_initializeRevertPaths` |
  | M10 header without chainUid | `test_statementHeaderCarriesChainUid` |
  | M11 entryRef without chainUid | `test_lifecycleShieldTransferRollOverUnshield` |
  | M12 roll-over digest without chainUid | `test_ownerOnlyRollOver` |
  | M13 mode digest without chainUid | `test_ownerOnlyRollOver` |
  | M14 accSeq unchecked | `test_rollOverBetweenProveAndSubmitRejectsCheaply` |
  | M15 sendCounter unchecked | `test_replaySameProofRejected` |
  | M16 sendCounter not advanced | `test_lifecycleShieldTransferRollOverUnshield` |
  | M17 unshield: totalShielded not lowered | `test_unshieldUnwrap_paysTheLeg_mintsNothing` |
  | M18 unshield: fee not debited | `test_lifecycleShieldTransferRollOverUnshield` |
  | M19 unshield: amount 0 allowed | `test_unshieldRevertPaths` |
  | M20 unshield: zero recipient allowed | `test_unshieldRevertPaths` |
  | M21 beneficiary registration unchecked | `test_unregisteredBeneficiaryRejected` |
  | M22 self transfer allowed | `test_transferToSelfRejected` |
  | M23 duplicate recipient allowed | `test_rejectsBadShapes` |
  | M24 proof result ignored | `test_unshieldRevertPaths` |
  | M25 spending authority unchecked | `test_confKeyAloneCannotSpendMultisigAccount` |
  | M26 inner fee not credited | `test_largeValuesNv64` |
  | M27 transfer: fee not debited | `test_largeValuesNv64` |
  | M28 auditor legs mix allowed | `test_auditorLegsMixedReverts` |
  | M29 OWNER_ONLY roll-over open | `test_ownerOnlyRollOver` |
  | M30 batch rolls OWNER_ONLY | `test_ownerOnlyRollOver` |
  | M31 signed roll-over without new credit | `test_rollOverSignedSurvivesFrontRunCredit` |
  | M32 roll-over no-op rule off | `test_rollOverIsNoOpWithoutNewCredit` |
  | M33 tag always DIRECT | `test_relayedTransferSingle_outerFeeFromPublicBalance_innerFeeToBeneficiary` (the RELAYED tag pin) |
  | M34 HASH in two slots (as built) | `test_disclosureHashMode` (the one-slot pin) |
  | M35 mode nonce not advanced | `test_ownerOnlyRollOver` |
  | M36 roll-over signature expiry off | `test_ownerOnlyRollOver` |
  | Y1 shield burns msg.sender | `test_batch_eachItemItsOwnBinding` |
  | Y2 shield burns unscaled | `invariant_balancesConservationAndReserve` |
  | Y3 unshield mints unscaled | `test_unshieldRevertPaths` |
  | Y4 binding ignored | `test_batch_eachItemItsOwnBinding` |
  | Y5 binding without chainUid | `test_envelopeBindingAndDigestKat` |
  | Y6 binding without fee | `test_envelopeBindingAndDigestKat` |
  | Y7 transferSingle unguarded | `test_batch_eachItemItsOwnBinding` |
  | Y8 roll-over unguarded | `test_reentryThroughAHookLegRefused` |
  | Y9 registered on any curve | `test_shieldRevertPaths` |
  | Y10 constructor checks off | `test_constructorNeedsRegistryAndDisclosure` |
  | Y12 HASH record not read | `test_disclosureHashMode` |
  | Y11 unshield not allowlisted | `test_relayedMultiTransfer_unshield_shield` |
  | N1 init skips the layer | `test_auditorSeesTransferButNoBalance` |
  | N2 conf refused | every suite (`setUp`: creation refuses `conf`) |
  | N3 regulated flags valid | `test_initializeRevertPaths` |
  | N4 allowlist entry dropped | `test_allowlistPinned` |
  | N5 initial supply ignored | `test_minterMintsPublicUnitsOnly` (initial supply) |
  | U1 wrap-shield: scale remainder allowed | `test_wrapShield_refusals` |
  | U2 wrap-shield: credits minted | `invariant_balancesConservationAndReserve` |
  | U3 direct unwrap binds nothing | `test_reentryThroughAHookLegRefused` |
  | U4 relayed unwrap not relayed | `test_unshieldUnwrap_relayed` |
  | U5 unwrap pays unscaled | `test_reentryThroughAHookLegRefused` |
  | U6 executeRate ignores the shielded value | `test_executeRate_countsTheShieldedValue` |
  | U7 disableFeature keeps the pending rate | `test_kindFlags_andDisableFeatureCancelsAPendingRate` |
  | U8 wrap-shield unguarded | `test_reentryThroughAHookLegRefused` |
  | U9 unshield-unwrap unguarded | `test_reentryThroughAHookLegRefused` |
  | U10 kind 3 flags as UNDERLYING | `test_kindFlags_andDisableFeatureCancelsAPendingRate` |
  | U11 wrap-shield static shape off | `test_allowlistPinned_underlyingZether` |
  | S1 view always DIRECT | `test_batch_eachItemItsOwnBinding` |
  | S2 unwrap view binds nothing | `test_unshieldUnwrap_directProofBindsLegAndMinOut` |
  | D1 disclosure challenge without chainUid | `test_disclosureOnTheUnderlyingKind` |
  | V1 header 384 | `test_confKeyAloneCannotSpendMultisigAccount` |
  | V2 fee read at the old offset | `test_confKeyAloneCannotSpendMultisigAccount` |
  | V3 D_out = O allowed | `test_dOutIdentityRejected` |
  | V4 amount read at the old offset | `test_reentryThroughAHookLegRefused` |
  | B1 binding not stored | `test_batch_eachItemItsOwnBinding` |
  | B2 binding read without a ticket | `test_relayedMultiTransfer_unshield_shield` |
  | F1 gate flag ignored | `test_zetherGate_offByDefault_registrarOnly_devChainsOnly` |
  | F2 gate dev chain ignored | `test_zetherGate_offByDefault_registrarOnly_devChainsOnly` |
  | F3 enable anywhere | `test_zetherGate_offByDefault_registrarOnly_devChainsOnly` |
  | F4 verifier 0 allowed | `test_zetherGate_verifierCheckedAtCreation_bothKinds` |
  | F5 unsupported verifier allowed | `test_zetherGate_verifierCheckedAtCreation_bothKinds` |
  | F6 gate only for kind 2 | `test_zetherGate_offByDefault_registrarOnly_devChainsOnly` |
  | F7 anyone switches the gate | `test_zetherGate_offByDefault_registrarOnly_devChainsOnly` |

- [ ] **Step 5: Commit** `P3: DeployBase registers the Zether kinds on dev chains; size gate` + trailer.

---

### Task 7: Docs, TODO, HANDOFF

**Model:** Sonnet, effort medium. Component docs say "controller ruling, pending the owner", never a K-id.
`zether.md` net −15 lines (1425 → 1410, over budget), `token-wrappers.md` 948 → 948 (must not grow), `metatx.md`
968 → 968, `settlement.md` −1.

- [ ] **Step 1: the component docs, the README tables and alt texts, the two SVGs** (status chips: the `*_ZETHER`
  kinds and `ZetherLib` BUILT in P3; `TradeLib`'s stale "target (P2)" chip corrected), the dropped-artifacts ledger for
  the tokens of the old line that no current doc names any more:

````diff
diff --git a/README.md b/README.md
index 0d2c57e..b93f2e4 100644
--- a/README.md
+++ b/README.md
@@ -264,7 +264,7 @@ heavy logic sits in external libraries ([CTR-TOK-21](docs/contracts/token-wrappe
 [CTR-TOK-24](docs/contracts/token-wrappers.md#CTR-TOK-24)).
 
 <p align="center">
-  <img src="docs/assets/token-tree.svg" width="900" alt="EVM token tree: MetaTxBase, then ERC20MetaTx, then MetaTokenBase, then four kinds by code. NONE (NoUnderlyingToken) and UNDERLYING (UnderlyingToken, 1 to 8 legs, the native coin allowed) are built in phase P1; NONE_ZETHER and UNDERLYING_ZETHER are the target of phase P3. External libraries: AdminLib, UnderlyingLib and HederaLib built; TradeLib (P2) and ZetherLib (P3) target. Features are flags chosen at creation; the post-quantum kinds are reserved.">
+  <img src="docs/assets/token-tree.svg" width="900" alt="EVM token tree: MetaTxBase, then ERC20MetaTx, then MetaTokenBase, then four kinds by code. NONE (NoUnderlyingToken) and UNDERLYING (UnderlyingToken, 1 to 8 legs, the native coin allowed) are built in phase P1; NONE_ZETHER and UNDERLYING_ZETHER are built in phase P3 (unaudited, dev chains only). External libraries: AdminLib, UnderlyingLib, HederaLib, TradeLib (P2) and ZetherLib (P3), all built. Features are flags chosen at creation; the post-quantum kinds are reserved.">
 </p>
 
 <details>
@@ -273,15 +273,15 @@ heavy logic sits in external libraries ([CTR-TOK-21](docs/contracts/token-wrappe
 | Area | Contracts | Built on | Status | Read |
 |---|---|---|---|---|
 | Factory | `OpenFactory` (one factory) | EIP-1167 clones at CREATE2 addresses: shared code, separate data ([section 4](#shared-code)); the version catalogue | BUILT as `OpenFactory` (`createToken`; kinds `NONE`, `UNDERLYING`) and the v1 line `OpenFactoryV1` | [token-wrappers](docs/contracts/token-wrappers.md) |
-| Gasless contracts | `MetaTxBase` (any SCaaS contract) → `ERC20MetaTx` (every token) → `MetaTokenBase` | `EIP712`; `mtxExecute` runs a signed `MetaTransaction` as a self-call on a selector allowlist; tokens add `ERC20` + `IERC20MetaTx` and the typed `MetaTransfer` ([CTR-MTX-22](docs/contracts/metatx.md#CTR-MTX-22), [CTR-MTX-23](docs/contracts/metatx.md#CTR-MTX-23)) | BUILT (P1a–P1c): `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; the older v1 line remains until Zether (P3) and the node and clientkeys (P5) move | [metatx](docs/contracts/metatx.md) |
+| Gasless contracts | `MetaTxBase` (any SCaaS contract) → `ERC20MetaTx` (every token) → `MetaTokenBase` | `EIP712`; `mtxExecute` runs a signed `MetaTransaction` as a self-call on a selector allowlist; tokens add `ERC20` + `IERC20MetaTx` and the typed `MetaTransfer` ([CTR-MTX-22](docs/contracts/metatx.md#CTR-MTX-22), [CTR-MTX-23](docs/contracts/metatx.md#CTR-MTX-23)) | BUILT (P1a–P1c): `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; the older v1 line remains until the node and clientkeys move (P5) | [metatx](docs/contracts/metatx.md) |
 | Payments | a signed `MetaTransfer` with an `entryRef` (`mtxPay`), or `IERC20Payment.payWithFee`; both emit `PaymentSettled` | `IERC20MetaTx` | BUILT: `MetaTransfer` and `mtxPay` on `MetaTokenBase`; the v1 line keeps a `pay(bytes32)` data shape | [metatx](docs/contracts/metatx.md) |
-| Token kinds | four kinds by code: `NoUnderlyingToken` (`NONE`), `UnderlyingToken` (`UNDERLYING`, 1–8 legs, the native coin allowed), `NoUnderlyingZetherToken`, `UnderlyingZetherToken` (the two `*_ZETHER` kinds); `*_PQZ` reserved. Features by flags fixed at creation: payable, mint, burn, adjustable rate, wrap-disable, freeze, force, pause, allowlist ([CTR-TOK-21](docs/contracts/token-wrappers.md#CTR-TOK-21)) | `MetaTokenBase` | `NONE` and `UNDERLYING` BUILT (P1c–P1d) with `AdminLib`, `UnderlyingLib`, `HederaLib` (`UnderlyingToken` still over EIP-170); `*_ZETHER` kinds and `ZetherLib` SPECIFIED (P3; today the legacy `ZetherToken`) | [token-wrappers](docs/contracts/token-wrappers.md) |
+| Token kinds | four kinds by code: `NoUnderlyingToken` (`NONE`), `UnderlyingToken` (`UNDERLYING`, 1–8 legs, the native coin allowed), `NoUnderlyingZetherToken`, `UnderlyingZetherToken` (the two `*_ZETHER` kinds); `*_PQZ` reserved. Features by flags fixed at creation: payable, mint, burn, adjustable rate, wrap-disable, freeze, force, pause, allowlist ([CTR-TOK-21](docs/contracts/token-wrappers.md#CTR-TOK-21)) | `MetaTokenBase` | `NONE` and `UNDERLYING` BUILT (P1c–P1d) with `AdminLib`, `UnderlyingLib`, `HederaLib` (`UnderlyingToken` still over EIP-170); `*_ZETHER` kinds with `ZetherLib` BUILT, unaudited (P3; over EIP-170 too) | [token-wrappers](docs/contracts/token-wrappers.md) |
 | Tradable tokens | `mtxTrade`: the token pulls a signed `TradeOrder` into the DEX named in it | `IERC20MetaTx` | SPECIFIED (`TradeLib`, P2; today: the `trade` op and the legacy `MetaTxDex`, both to be removed) | [metatx](docs/contracts/metatx.md), [legacy DEX](docs/contracts/dex.md#legacy-metatxdex) |
 | DEX | `SCaaSDex`, `DexPuller` | `EIP712` + `ReentrancyGuardTransient`; one taker against many makers per call on two paths, no maker allowance; `mtxExchange` fills the same orders against AMMs (Uniswap v2/v3), multi-hop or in a cycle, surplus to the signers ([CTR-DEX-20](docs/contracts/dex.md#CTR-DEX-20)) | BUILT (P2c: the exchange path on the new `SCaaSDex`) | [dex](docs/contracts/dex.md) |
 | Mandates | `MandateWallet` | `MetaTxBase` + `IERC1271` | BUILT (own signed structs; on `MetaTxBase` in P4) | [mandates](docs/contracts/mandates.md) |
 | Smart account (optional) | `SmartKeyAccount`, `SmartKeyAccountFactory` (built: `SubjectAccount`) | `MetaTxBase` + `IERC1271`; P-256 passkeys; signs its own calls as itself ([CTR-ACC-10](docs/contracts/accounts.md#CTR-ACC-10)) | BUILT (`OwnerCall`; on `MetaTxBase` in P4) | [accounts](docs/contracts/accounts.md#subjectaccount) |
 | Universal Accounts | today the Zether-only `UniversalAccountRegistry`; next the UA registry with one verifier per kind, and MetaToken v3 with a UA ledger | the signature, multisig, BLS and hash-to-curve libraries | legacy registry BUILT; UA registry and v3 SPECIFIED | [accounts](docs/contracts/accounts.md#universal-account) |
-| Zether | `ZetherToken`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`, `ITransferDisclosure` | `ERC20MetaTx` (built: `ZetherMetaTx`); EIP-196/197 and EIP-2537 precompiles | BUILT, unaudited | [zether](docs/contracts/zether.md) |
+| Zether | the `*_ZETHER` kinds (`ZetherLayer` + `ZetherLib`), `ZetherStatements`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`, `ITransferDisclosure` | `MetaTokenBase`; EIP-196/197 and EIP-2537 precompiles | BUILT, unaudited (P3) | [zether](docs/contracts/zether.md) |
 | PQ Zether | `PqzToken` | `ERC20MetaTx`, relayed like Zether ([CTR-PQZ-21](docs/contracts/pq-zero-knowledge.md#CTR-PQZ-21)); a lattice precompile on chain 7622 — public chains once they offer one | SPECIFIED | [pq-zether](docs/contracts/pq-zero-knowledge.md) |
 | Asset suite | `ComplianceRegistry`, `VestingGrant`, `Distribution`, `ExchangeOffer` | regulated flags 5–8 on ordinary token kinds ([CTR-AS-17](docs/contracts/asset-suite.md#CTR-AS-17)); ERC-7201 namespaced storage | SPECIFIED | [asset-suite](docs/contracts/asset-suite.md) |
 | Tender | `SealedBidTender` | commit and reveal with deposits | SPECIFIED | [tender](docs/contracts/tender.md) |
diff --git a/docs/assets/token-axes.svg b/docs/assets/token-axes.svg
index 3ce6b50..38c9f5b 100644
--- a/docs/assets/token-axes.svg
+++ b/docs/assets/token-axes.svg
@@ -1,6 +1,6 @@
 <svg xmlns="http://www.w3.org/2000/svg" width="960" height="600" viewBox="0 0 960 600" role="img" aria-labelledby="t d">
   <title id="t">Token model: two axes</title>
-  <desc id="d">Axis 1, the kind, fixes the confidential layer: rows NONE (standalone) and UNDERLYING (wrapper of one to eight legs), columns plain (NONE and UNDERLYING, built in P1), ZETHER (NONE_ZETHER and UNDERLYING_ZETHER, target P3; classical Zether built and unaudited on dev chains), PQZ (NONE_PQZ and UNDERLYING_PQZ, reserved, not built; post-quantum Zether specified and unaudited) and ZETHER_PQZ (NONE_ZETHER_PQZ and UNDERLYING_ZETHER_PQZ, reserved, not built; room in the kind ids only). Axis 2, who signs, belongs to the account: an EOA (ECDSA), a SmartKeyAccount (ERC-1271), or a Universal Account with a post-quantum key (mldsa44, mldsa65, fndsa512) through the UA ledger in the token base (specified, not built). Every kind accepts the same intents from every signer.</desc>
+  <desc id="d">Axis 1, the kind, fixes the confidential layer: rows NONE (standalone) and UNDERLYING (wrapper of one to eight legs), columns plain (NONE and UNDERLYING, built in P1), ZETHER (NONE_ZETHER and UNDERLYING_ZETHER, built in P3, unaudited, dev chains only), PQZ (NONE_PQZ and UNDERLYING_PQZ, reserved, not built; post-quantum Zether specified and unaudited) and ZETHER_PQZ (NONE_ZETHER_PQZ and UNDERLYING_ZETHER_PQZ, reserved, not built; room in the kind ids only). Axis 2, who signs, belongs to the account: an EOA (ECDSA), a SmartKeyAccount (ERC-1271), or a Universal Account with a post-quantum key (mldsa44, mldsa65, fndsa512) through the UA ledger in the token base (specified, not built). Every kind accepts the same intents from every signer.</desc>
   <defs>
     <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
       <path d="M0 0 L10 5 L0 10 z" fill="#57606a"/>
@@ -30,7 +30,7 @@
   <text class="b" x="170" y="132">plain</text>
   <rect x="170" y="140" width="42" height="16" rx="8" fill="#dafbe1"/><text class="chip" x="191" y="152" text-anchor="middle" fill="#1a7f37">BUILT</text><text class="s" x="218" y="152">NONE, UNDERLYING in P1</text>
   <text class="b" x="366" y="132">ZETHER</text>
-  <text class="s" x="366" y="152">target, P3</text>
+  <rect x="366" y="140" width="42" height="16" rx="8" fill="#dafbe1"/><text class="chip" x="387" y="152" text-anchor="middle" fill="#1a7f37">BUILT</text><text class="s" x="414" y="152">in P3, unaudited</text>
   <text class="b" x="562" y="132">PQZ</text>
   <text class="s" x="562" y="152">reserved, not built</text>
   <text class="b" x="758" y="132">ZETHER_PQZ</text>
diff --git a/docs/assets/token-tree.svg b/docs/assets/token-tree.svg
index db333a7..d2bdb7a 100644
--- a/docs/assets/token-tree.svg
+++ b/docs/assets/token-tree.svg
@@ -1,6 +1,6 @@
 <svg xmlns="http://www.w3.org/2000/svg" width="960" height="620" viewBox="0 0 960 620" role="img" aria-labelledby="t d">
   <title id="t">EVM token tree</title>
-  <desc id="d">The EVM token tree: MetaTxBase, then ERC20MetaTx, then MetaTokenBase, then four kinds by code: NONE (NoUnderlyingToken) and UNDERLYING (UnderlyingToken, 1 to 8 legs, the native coin allowed), built in phase P1; NONE_ZETHER and UNDERLYING_ZETHER, target in phase P3. External libraries: AdminLib, UnderlyingLib and HederaLib built; TradeLib (P2) and ZetherLib (P3) target. Features are flags chosen at creation. The post-quantum kinds are reserved, not built.</desc>
+  <desc id="d">The EVM token tree: MetaTxBase, then ERC20MetaTx, then MetaTokenBase, then four kinds by code: NONE (NoUnderlyingToken) and UNDERLYING (UnderlyingToken, 1 to 8 legs, the native coin allowed), built in phase P1; NONE_ZETHER and UNDERLYING_ZETHER, built in phase P3 (unaudited, dev chains only). External libraries: AdminLib, UnderlyingLib, HederaLib, TradeLib (P2) and ZetherLib (P3), all built. Features are flags chosen at creation. The post-quantum kinds are reserved, not built.</desc>
   <defs>
     <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
       <path d="M0 0 L10 5 L0 10 z" fill="#57606a"/>
@@ -66,19 +66,19 @@
   <text class="s" x="268" y="453" text-anchor="middle">ERC-20s or native coin</text>
   <text class="okc" x="268" y="469" text-anchor="middle">built (P1)</text>
 
-  <rect class="target" x="356" y="380" width="156" height="96" rx="8"/>
+  <rect class="built" x="356" y="380" width="156" height="96" rx="8"/>
   <text class="k" x="434" y="401" text-anchor="middle">NONE_ZETHER</text>
   <text class="m" x="434" y="420" text-anchor="middle" font-size="10.5">NoUnderlyingZetherToken</text>
   <text class="s" x="434" y="438" text-anchor="middle">standalone +</text>
   <text class="s" x="434" y="453" text-anchor="middle">Zether layer</text>
-  <text class="tgc" x="434" y="469" text-anchor="middle">target (P3)</text>
+  <text class="okc" x="434" y="469" text-anchor="middle">built (P3)</text>
 
-  <rect class="target" x="522" y="380" width="156" height="96" rx="8"/>
+  <rect class="built" x="522" y="380" width="156" height="96" rx="8"/>
   <text class="k" x="600" y="401" text-anchor="middle">UNDERLYING_ZETHER</text>
   <text class="m" x="600" y="420" text-anchor="middle" font-size="10.5">UnderlyingZetherToken</text>
   <text class="s" x="600" y="438" text-anchor="middle">wrapper + Zether layer,</text>
   <text class="s" x="600" y="453" text-anchor="middle">wrap-shield from a leg</text>
-  <text class="tgc" x="600" y="469" text-anchor="middle">target (P3)</text>
+  <text class="okc" x="600" y="469" text-anchor="middle">built (P3)</text>
 
   <text class="s" x="24" y="500">Reserved, not built: NONE_PQZ, UNDERLYING_PQZ, NONE_ZETHER_PQZ, UNDERLYING_ZETHER_PQZ (post-quantum layer).</text>
 
@@ -104,14 +104,14 @@
   <text class="okc" x="922" y="284" text-anchor="end">built</text>
   <text class="s" x="716" y="304">HIP-632, HTS · when IS_HEDERA</text>
 
-  <rect class="target" x="702" y="330" width="234" height="58" rx="8"/>
+  <rect class="built" x="702" y="330" width="234" height="58" rx="8"/>
   <text class="b" x="716" y="352">TradeLib</text>
-  <text class="tgc" x="922" y="352" text-anchor="end">target (P2)</text>
+  <text class="okc" x="922" y="352" text-anchor="end">built</text>
   <text class="s" x="716" y="372">TradeOrder, mtxTrade · all kinds</text>
 
-  <rect class="target" x="702" y="398" width="234" height="58" rx="8"/>
+  <rect class="built" x="702" y="398" width="234" height="58" rx="8"/>
   <text class="b" x="716" y="420">ZetherLib</text>
-  <text class="tgc" x="922" y="420" text-anchor="end">target (P3)</text>
+  <text class="okc" x="922" y="420" text-anchor="end">built</text>
   <text class="s" x="716" y="440">proofs, shielding · *_ZETHER</text>
 
   <!-- features strip -->
@@ -121,8 +121,8 @@
 
   <!-- legend -->
   <rect class="built" x="24" y="596" width="22" height="12" rx="3"/>
-  <text class="s" x="52" y="607">built (as of P1)</text>
+  <text class="s" x="52" y="607">built (as of P3)</text>
   <rect class="target" x="160" y="596" width="22" height="12" rx="3"/>
   <text class="s" x="188" y="607">target, not built yet (phase)</text>
-  <text class="s" x="936" y="607" text-anchor="end">UnderlyingToken is built but still over the EIP-170 size limit</text>
+  <text class="s" x="936" y="607" text-anchor="end">UnderlyingToken and the *_ZETHER kinds are built but over the EIP-170 limit</text>
 </svg>
diff --git a/docs/contracts/README.md b/docs/contracts/README.md
index e02285d..eefbbe4 100644
--- a/docs/contracts/README.md
+++ b/docs/contracts/README.md
@@ -19,7 +19,7 @@ the rules every one of them shares. Status tags (**BUILT**, **SPECIFIED**, **PLA
 | [mandates.md](mandates.md) | `MandateWallet`: delegated, capped payment from the payer's own wallet; auto-pay client integration | **BUILT**; revocation epoch **SPECIFIED** |
 | [settlement.md](settlement.md) | map of every settlement kind: entry points, who checks what, fees, finality (adds no rules) | overview |
 
-<p align="center"><img src="../assets/token-axes.svg" width="860" alt="Token model on two axes. Kind = confidential layer: NONE and UNDERLYING (plain, built in P1), NONE_ZETHER and UNDERLYING_ZETHER (target, P3; classical Zether built and unaudited on dev chains), NONE_PQZ and UNDERLYING_PQZ (reserved, not built; PQ Zether specified and unaudited) and NONE_ZETHER_PQZ and UNDERLYING_ZETHER_PQZ (reserved, not built). Who signs = the account: an EOA (ECDSA, built), a SmartKeyAccount (ERC-1271, built) or a Universal Account with a PQ key mldsa44, mldsa65 or fndsa512 through the UA ledger in the token base (specified, not built); every kind accepts the same intents from each."></p>
+<p align="center"><img src="../assets/token-axes.svg" width="860" alt="Token model on two axes. Kind = confidential layer: NONE and UNDERLYING (plain, built in P1), NONE_ZETHER and UNDERLYING_ZETHER (built in P3, unaudited, dev chains only), NONE_PQZ and UNDERLYING_PQZ (reserved, not built; PQ Zether specified and unaudited) and NONE_ZETHER_PQZ and UNDERLYING_ZETHER_PQZ (reserved, not built). Who signs = the account: an EOA (ECDSA, built), a SmartKeyAccount (ERC-1271, built) or a Universal Account with a PQ key mldsa44, mldsa65 or fndsa512 through the UA ledger in the token base (specified, not built); every kind accepts the same intents from each."></p>
 
 How the families relate:
 
@@ -72,7 +72,7 @@ the implementation's immutables). `chain_uid` is the chain's genesis block hash
 
 | Contract | Source of `chain_uid` |
 |---|---|
-| token implementations (`NoUnderlyingToken`, `UnderlyingToken`; `ZetherToken` with P3) | constructor immutable of the **implementation**; a clone runs its code by `DELEGATECALL`, so it uses the value with no storage and no `initialize` argument and cannot declare another one |
+| token implementations (`NoUnderlyingToken`, `UnderlyingToken`, `NoUnderlyingZetherToken`, `UnderlyingZetherToken`) | constructor immutable of the **implementation**; a clone runs its code by `DELEGATECALL`, so it uses the value with no storage and no `initialize` argument and cannot declare another one |
 | `OpenFactory` | constructor immutable; `registerImplementation` refuses an implementation whose `chainUid()` differs ([CTR-TOK-03](token-wrappers.md#CTR-TOK-03)) |
 | `SmartKeyAccount` | the factory's constructor argument, passed to `new SmartKeyAccount(chainUid)` |
 | `MandateWallet`, `HederaMandateWallet` | constructor argument from the chain profile; the node checks it before relaying for that wallet |
diff --git a/docs/contracts/metatx.md b/docs/contracts/metatx.md
index 6c25ca5..4331aca 100644
--- a/docs/contracts/metatx.md
+++ b/docs/contracts/metatx.md
@@ -315,9 +315,9 @@ it. Nothing else is reachable through `mtxExecute`.
 | | `wrap(address,uint256)` | `ABSOLUTE` |
 | | `unwrap(address,uint256,address,uint256)` | `AMOUNT(1)` |
 | | `addReserve(address,uint256)` | `ABSOLUTE` |
-| `NONE_ZETHER` / `UNDERLYING_ZETHER` (built: `ZetherToken`; replaced in P1/P3) | `wrap(uint256)` (UnderlyingLib surface of `UNDERLYING_ZETHER`), `zetherShield(bytes,uint256)` | `ABSOLUTE` |
-| | `unwrap(uint256,address)` (public balance; `UNDERLYING_ZETHER`) | `AMOUNT(0)` |
-| | `zetherTransfer(bytes,bytes,bytes,bytes32)`, `zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)` | `ABSOLUTE`; envelope binding through the ticket ([CTR-ZTH-34](zether.md#CTR-ZTH-34)) |
+| `NONE_ZETHER` / `UNDERLYING_ZETHER` (built, P3) | the kind's public entries (`burn`; or `UnderlyingToken`'s six, without `unwrap(uint256,address)`) | as above |
+| | `zetherShield(bytes,uint256)`, `zetherWrapShield(address,uint256,bytes32)` (`UNDERLYING_ZETHER`) | `ABSOLUTE` |
+| | `zetherTransfer`, `…Bundle`, `…NoBundle`, `…Single` `(bytes,bytes,bytes,bytes32)`, `zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)`, `zetherUnshieldUnwrap` | `ABSOLUTE`; envelope binding through the ticket ([CTR-ZTH-34](zether.md#CTR-ZTH-34)) |
 | `PqzToken` | `pqzTransfer(bytes,bytes,bytes[],bytes,bytes)`, `pqzUnshield(bytes,bytes,bytes[],uint256,address,bytes,bytes)`, `pqzShield(bytes32,uint256)`, `pqzRollOver(bytes32,bytes,bytes[])` | `ABSOLUTE`; not batchable ([CTR-PQZ-21](pq-zero-knowledge.md#CTR-PQZ-21)) |
 | `MandateWallet` | delegate: `payUnderMandate(address,address,uint256,bytes32)`, `revoke(address,uint64)`; owner: `setMandate`, `setPayee`, `revoke(address)`, `execute` ([CTR-ACC-06](mandates.md#CTR-ACC-06)) | fee `NONE` only |
 | `SmartKeyAccount` | `addKey`, `removeKey`, `rotateKey`, `setGuardian`, `execute`, signed by the account itself ([CTR-ACC-10](accounts.md#CTR-ACC-10)) | fee `NONE` only |
@@ -339,7 +339,7 @@ sequential nonce lets only one variant execute.
 <a id="CTR-MTX-12"></a>**CTR-MTX-12** — **Gasless unwrap** is `mtxExecute` with the wrapper's real `unwrap` calldata:
 `unwrap(uint256 wrapped, address recipient, uint256 minOut)` on `UnderlyingToken` with one leg, `unwrap(address underlying,
 uint256 wrapped, address recipient, uint256 minOut)` with one or several legs, `unwrap(uint256, address)` (public
-balance) on `UNDERLYING_ZETHER` (built: `ZetherToken`; replaced in P1/P3). The function runs exactly as a direct call by `from` (checks, burn
+balance) on `UNDERLYING_ZETHER` (built in P3 with `UnderlyingToken`'s `minOut` forms only). The function runs exactly as a direct call by `from` (checks, burn
 `⌈out·q⌉`, reserve debit, the underlying's exact-amount transfer, `Unwrapped`), and `minOut` protects the signer
 against rate moves between signing and execution. Its fee class is `AMOUNT` with the wrapped amount as basis, taken
 in wrapped units after the call. The underlying's transfer failing reverts everything, fee and nonce included. The fee
@@ -560,8 +560,8 @@ signed, not the entry point, and stay. Non-EVM families follow the same rule in
 | every contract on `MetaTxBase` | `mtxExecute` (+ alias `executeMetaTransaction`), `mtxBatch`; `cancelNonce(uint256 batch)` (direct, or signed through `mtxExecute`); views `mtxNonce`, `mtxDigest`, `mtxSelectors`, `chainUid`, `supportedModes` |
 | tokens | + `mtxExecuteWithFee`, `mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayReceiverFee`; views `mtxTransferDigest`, `payLane` |
 | tokens (trade) | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces` ([dex.md](dex.md#CTR-DEX-15)) |
-| wrappers, `UNDERLYING_ZETHER` (built on `UnderlyingToken`; `ZetherToken` in P3) | `mtxWrap` ([CTR-TOK-20](token-wrappers.md#CTR-TOK-20)) |
-| `NONE_ZETHER` / `UNDERLYING_ZETHER` (built: `ZetherToken`; replaced in P1/P3) | `zetherRollOverSigned`, `zetherSetRollOverMode` ([CTR-ZTH-16](zether.md#CTR-ZTH-16)) |
+| wrappers, `UNDERLYING_ZETHER` (built on `UnderlyingToken`, inherited in P3) | `mtxWrap` ([CTR-TOK-20](token-wrappers.md#CTR-TOK-20)) |
+| `NONE_ZETHER` / `UNDERLYING_ZETHER` (built, P3) | `zetherRollOverSigned`, `zetherSetRollOverMode` ([CTR-ZTH-16](zether.md#CTR-ZTH-16)) |
 | `MandateWallet` | + `mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner`, named builders of a `MetaTransaction` ([mandates.md](mandates.md#mandatewallet)) |
 | `SmartKeyAccount` | + `mtxExecuteAsOwner`, named builder of a `MetaTransaction` ([CTR-ACC-10](accounts.md#CTR-ACC-10)) |
 | `SCaaSDex` | `mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces` ([dex.md](dex.md#CTR-DEX-16)) |
@@ -903,7 +903,7 @@ Foundry (`forge test`, default profile and `private7622`):
 <a id="transitional-built"></a>
 <a id="v1"></a>
 
-The v1 line and Zether still run on the legacy base with a hand-written op dispatch (each item is removed by the rule
+The v1 line still runs on the legacy base with a hand-written op dispatch, as Zether did until P3 (each item is removed by the rule
 named in brackets). The v2 tiers run on the new tree (last bullet).
 
 - **Bases** ([CTR-MTX-07](#CTR-MTX-07)). v1: the `ERC20MetaTxV1` mixin + `MetaToken` (kind `META`, tiers 1 and 2 in one
diff --git a/docs/contracts/settlement.md b/docs/contracts/settlement.md
index 73331d1..b2cdc5f 100644
--- a/docs/contracts/settlement.md
+++ b/docs/contracts/settlement.md
@@ -56,7 +56,7 @@ intent is a booked fact. Every kind below shares these properties:
 | Signature wrap | `mtxWrap` | holder signs a `TradeOrder` in the underlying's domain; any relayer | underlying and wrapper | order `fee` to the relayer, out of the minted units | tx | **BUILT** (P2a, `UnderlyingToken`) | [CTR-TOK-20](token-wrappers.md#CTR-TOK-20) |
 | DEX order book | `SCaaSDex.mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces`; token side `mtxTrade` | each party signs a `TradeOrder`; the venue lane | token (Path A) or DEX (Path B, outside legs); DEX conservation | one signed rate, split relayer / treasury by the DEX | tx, then the DEX watcher | token side **BUILT** (P2a); `SCaaSDex` **BUILT** (P2b-1 SCaaS legs, P2b-2 outside legs); `SCaaSDexV1` pair `settle` **BUILT** | [CTR-DEX-13](dex.md#CTR-DEX-13) to [-19](dex.md#CTR-DEX-19), [-22](dex.md#CTR-DEX-22), [-24](dex.md#CTR-DEX-24) |
 | Exchange against AMMs | `mtxExchange`, `mtxExchangeVia` | the same signed orders; the venue lane | token or DEX, DEX conservation | signed rate on the floor; surplus to the signers | tx, then the DEX watcher | **BUILT** (P2c, `SCaaSDex`) | [CTR-DEX-20](dex.md#CTR-DEX-20) to [-23](dex.md#CTR-DEX-23) |
-| Confidential (Zether) | target `zetherTransfer*`, `zetherShield`, `zetherUnshield`, roll-over; built `transferConfidential*`, `fund`, `burn` | owner signs the call, the proof binds the envelope; any relayer | token verifier | outer NONE / FIXED (never PERCENT), inner `confidentialFee` | tx (dev chains) | **BUILT, UNAUDITED** (dev chains only); target kinds P3 **SPECIFIED**; PQZ **SPECIFIED** | [zether.md](zether.md), [pq-zero-knowledge.md](pq-zero-knowledge.md) |
+| Confidential (Zether) | `zetherTransfer*`, `zetherShield`, `zetherUnshield`, roll-over; `zetherWrapShield`, `zetherUnshieldUnwrap` (`UNDERLYING_ZETHER`) | owner signs the call, the proof binds the envelope; any relayer | token verifier | outer NONE / FIXED (never PERCENT), inner `confidentialFee` | tx (dev chains) | **BUILT, UNAUDITED** (the `*_ZETHER` kinds, P3; dev chains only); PQZ **SPECIFIED** | [zether.md](zether.md), [pq-zero-knowledge.md](pq-zero-knowledge.md) |
 | Mandate | `payUnderMandate` (named `mtxPayUnderMandate`), `revoke` | delegate signs; any relayer | `MandateWallet` | NONE; relayer pays gas | tx | **BUILT**; epoch and `mtx` names **SPECIFIED** | [CTR-ACC-06](mandates.md#CTR-ACC-06), [-07](mandates.md#CTR-ACC-07) |
 | Asset-suite action | forced transfer, freeze, `VestingGrant.release`, `Distribution` claim, `ExchangeOffer` | issuer / compliance role, or a permissionless claim | token or action contract | by action | tx | **SPECIFIED**, nothing built | [asset-suite.md](asset-suite.md) |
 | Tender | `commitBid` (deposit is a `MetaTransfer`), `revealBid`, `withdrawDeposit` | bidder signs only the deposit | tender and token | NONE | tx | **SPECIFIED**, nothing built | [CTR-TND-01](tender.md#CTR-TND-01), [-03](tender.md#CTR-TND-03) |
@@ -99,7 +99,7 @@ sequenceDiagram
   batching is [NODE-LANE-11](../node/submit-lanes.md#NODE-LANE-11) (**PLANNED**). `PaymentSettled` reaches clients
   only in a final range ([indexer-feeds.md](../node/indexer-feeds.md#event-items)); booking and reconciliation are in
   [integration.md](../integration.md#payment-references).
-- **Transitional (BUILT):** the v1 token line and Zether still use the single 11-field struct with `data` ops
+- **Transitional (BUILT):** the v1 token line still uses the single 11-field struct with `data` ops (Zether left it in P3)
   ([metatx.md Transitional](metatx.md#transitional-built)).
 
 ### 3.2 Receiver pays
@@ -166,7 +166,7 @@ sequenceDiagram
 ```
 
 - **Atomic:** the wrapper requires `received == o.amount`; any failure reverts the order's `pulled` state with it.
-  `NativeNotGasless` for the native coin; Zether wrapper gets it in P3.
+  `NativeNotGasless` for the native coin; `UnderlyingZetherToken` inherits it (P3).
 - **Node:** a `metatx` job entry point. Clients refuse to build an order whose `dex` is not a registered wrapper of the
   underlying ([CTR-DEX-19](dex.md#CTR-DEX-19)).
 
@@ -251,10 +251,9 @@ fails ([CTR-ZTH-06](zether.md#CTR-ZTH-06)). PQZ mirrors the names with `pqz` and
   fee ([CTR-ZTH-13](zether.md#CTR-ZTH-13)).
 - **Node:** re-encodes the dynamic arguments and refuses non-canonical `data` before computing the mesh `intent_id`
   ([NODE-JOB-20](../node/job-api.md#NODE-JOB-20)).
-- **Status / Transitional (BUILT):** `ZetherToken` is BUILT, UNAUDITED and refuses to deploy outside chain ids 31337 and
-  1337 ([CTR-ZTH-02](zether.md#CTR-ZTH-02)); the SCaaS testnet is not on that list. It carries its own `ZetherMetaTx`
-  envelope with the built names `transferConfidential*`, `burn`, `fund`, `rollOver*`; the rename and the move onto the
-  base are P3.
+- **Status:** BUILT (P3), UNAUDITED: the `*_ZETHER` kinds refuse to initialize outside chain ids 31337 and 1337
+  ([CTR-ZTH-02](zether.md#CTR-ZTH-02)); the SCaaS testnet is not on that list. The old `ZetherToken` with its own envelope and
+  names is backed up in `smartcontracts/evm/legacy/p3/`.
 
 ### 3.8 Mandates
 
diff --git a/docs/contracts/token-wrappers.md b/docs/contracts/token-wrappers.md
index 23d5dbc..1af9a81 100644
--- a/docs/contracts/token-wrappers.md
+++ b/docs/contracts/token-wrappers.md
@@ -104,8 +104,8 @@ low-value currency token — an `UnderlyingToken` with two legs and one rate per
 
 `initData` per kind below. Fee-on-transfer underlyings are measured on the way in and must
 transfer exactly on the way out; rebasing underlyings are unsupported (a negative rebase stops wrap, exits stay
-first-come); built `ZetherToken` refuses fee-on-transfer underlyings (`UnsupportedUnderlying`,
-[CTR-ZTH-14](zether.md#CTR-ZTH-14)); target: the confidential kinds use UnderlyingLib ([CTR-TOK-11](#CTR-TOK-11)). Weighted baskets (proportional redemption) are not planned.
+first-come); the confidential kinds use the same `UnderlyingLib` (built, P3; the old `ZetherToken` refused fee-on-transfer
+with `UnsupportedUnderlying`, [CTR-ZTH-14](zether.md#CTR-ZTH-14), [CTR-TOK-11](#CTR-TOK-11)). Weighted baskets are not planned.
 
 ### 2.1 NONE — `NoUnderlyingToken`
 
@@ -454,17 +454,17 @@ cannot approve anything ([CTR-TOK-01](#CTR-TOK-01)) and wraps by signature:
 <a id="CTR-TOK-20"></a>**CTR-TOK-20** — **Signature wrap of a SCaaS underlying** (owner). The holder signs a
 `TradeOrder` ([CTR-DEX-13](dex.md#CTR-DEX-13)) in the **underlying's** domain with `dex` = the wrapper, `receiveToken`
 = the wrapper, `receiveAmount` = the minimum it accepts to receive (its `minOut`), `minFill = amount`, `fee` = the
-relayer's rate. **BUILT (P2a) on `UnderlyingToken`**; `ZetherToken` gets it with P3. `UnderlyingToken` exposes
+relayer's rate. **BUILT on `UnderlyingToken` (P2a)**, inherited by `UnderlyingZetherToken` (P3). Both expose
 
 ```solidity
 function mtxWrap(address underlying, TradeOrder calldata o, bytes calldata sig) external nonReentrant returns (uint256 minted);
 ```
 
-1. `address(0)` ⇒ `NativeNotGasless()` (checked first); resolve the leg: `_legOf(underlying)` (UnderlyingToken; Zether: `underlying == this.underlying()`), which refuses an
+1. `address(0)` ⇒ `NativeNotGasless()` (checked first); resolve the leg: `_legOf(underlying)` (both `UNDERLYING*` kinds), which refuses an
    unknown "underlying" whose `mtxTrade` could be a no-op (built: `UnknownUnderlying(u)`, controller ruling, pending the owner); require `wrapEnabled`, no pending
    rate change and no reserve shortfall;
 2. require `o.receiveToken == address(this)` (`WrapOrderInvalid`); the relayer binding is the underlying's (`submitter` = `msg.sender`, `WrongRelayer`; controller ruling, pending the owner: the wrapper does not repeat it); `o.receiveAmount` is gross, the holder receives `minted − wrapFee`;
-3. quote `minted = ⌊o.amount · num / den⌋` (Zether: `o.amount`, 1:1) and `wrapFee = ⌈minted · o.fee / 10⁶⌉`
+3. quote `minted = ⌊o.amount · num / den⌋` and `wrapFee = ⌈minted · o.fee / 10⁶⌉`
    ([CTR-DEX-11](dex.md#CTR-DEX-11) rounding; `fee = 0` ⇒ 0);
 4. call `underlying.mtxTrade(o, sig, TradeFill(o.amount, minted, wrapFee, msg.sender))` — the underlying checks the
    signature, that the wrapper is `o.dex`, the price `amount·receiveAmount ≤ minted·amount` and the fee bound, and moves
@@ -610,10 +610,10 @@ empty output — with no symptom until someone has deposited funds.
   address); `initialize` runs in the same call and requires `msg.sender == FACTORY`; implementations lock themselves
   in the constructor.
 - **Zether gate**: `zetherEnabled` default `false`; enabling and creating Zether tokens revert outside chain ids
-  31337/1337 (`ZetherSafety`, [CTR-ZTH-02](zether.md#CTR-ZTH-02)). Built on `OpenFactoryV1` (`:33`, `:65-69`, `:172-175`);
-  `OpenFactory` gets it with P3.
+  31337/1337 (`ZetherSafety`, [CTR-ZTH-02](zether.md#CTR-ZTH-02)). Built on `OpenFactory` (P3), with the verifier check;
+  `OpenFactoryV1` keeps its own until the v1 line moves (P5).
 - **Registrar** is an EOA by default (deployer); it must become a multisig before mainnet. Its only powers are
-  `registerImplementation`, `deprecate`, and (`OpenFactoryV1` today) `setZetherEnabled`.
+  `registerImplementation`, `deprecate`, and `setZetherEnabled`.
 - **Same rule on every family**: a fix to an Aptos package, Sui package, Solana program, Cosmos contract, TON or
   Soroban contract is a new deployment at a new address plus voluntary migration by the owners of the balances;
   accounts on the old deployment keep working with the old code ([CTR-GEN-02](README.md#CTR-GEN-02)).
@@ -663,7 +663,7 @@ struct TokenConfig {
     uint256 initialSupply; address initialHolder;   // NONE* only; initialHolder is ignored when initialSupply == 0
     Leg[] legs;                                // underlying (address(0) = native coin, CTR-TOK-26), num, den — UNDERLYING* only, 1..8
     RateConfig rate;                           // with RATE_ADJUSTABLE
-    ConfidentialConfig conf;                   // verifier, auditorKey (empty = no auditor), shieldScale — *_ZETHER only
+    ConfidentialConfig conf;                   // verifier, auditorKey (empty = none), shieldScale, maxShielded, confidentialFee — *_ZETHER only
 }
 struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
 ```
@@ -691,11 +691,11 @@ and `roles`.
 <a id="transitional-built-tokens"></a>
 
 **Transitional (BUILT, P1e).** `OpenFactory` (`src/factory/OpenFactory.sol`, `IOpenFactory.sol`, `IFactoryToken.sol`) is
-built as [CTR-TOK-03](#CTR-TOK-03) and [CTR-TOK-25](#CTR-TOK-25) specify, except that it creates no Zether token and has
-no `setZetherEnabled` (P3); `createDex` and the DEX catalogue are built (P2b-1, [CTR-DEX-24](dex.md#CTR-DEX-24)). `NoUnderlyingToken` and
+built as [CTR-TOK-03](#CTR-TOK-03) and [CTR-TOK-25](#CTR-TOK-25) specify, the Zether gate and kinds 2–3 included (P3); `createDex`
+and the DEX catalogue are built (P2b-1, [CTR-DEX-24](dex.md#CTR-DEX-24)). `NoUnderlyingToken` and
 `UnderlyingToken` implement `initialize(creator, version, TokenConfig)` and a constant `kind()` (0 and 1). The v1 line
-(`ERC20MetaTxV1`, `MetaToken`, `HederaMetaToken`, `ZetherToken`, `MetaTxDex`) stays in the build as `OpenFactoryV1`,
-`IOpenFactoryV1` and `IFactoryTokenV1` (`createMetaToken`, `createZetherToken`) until the node, clientkeys (P5) and Zether (P3) move; it then goes to
+(`ERC20MetaTxV1`, `MetaToken`, `HederaMetaToken`, `MetaTxDex`; `ZetherToken` went to `legacy/p3/`) stays as `OpenFactoryV1`,
+`IOpenFactoryV1` and `IFactoryTokenV1` (`createMetaToken`, `createZetherToken`) until the node and clientkeys move (P5); it then goes to
 `smartcontracts/evm/legacy/`, not deleted (controller ruling, pending the owner). Factory v2 is backed up in
 `smartcontracts/evm/legacy/p1e/` (not built).
 
@@ -704,7 +704,7 @@ no `setZetherEnabled` (P3); `createDex` and the DEX catalogue are built (P2b-1,
 - **Registration** requires `implementation.code.length > 0` and reads `kind(), `factory()` and `chainUid()` by staticcall: `ImplementationNotAContract`,
   `VersionKindMismatch(expected, got)` (`got = type(uint256).max` when there is no answer),
   `ImplementationFactoryMismatch`, `ChainUidMismatch`. `NONE_PQZ`…`UNDERLYING_ZETHER_PQZ` (4–7) revert `KindReserved`;
-  kinds 2 and 3 are accepted before P3 (controller ruling, pending the owner).
+  kinds 2 and 3 are built (P3) and their creation passes the Zether gate.
 - **Creation:** `createToken` (registered version) and `createTokenUnregistered` (same four checks, recorded with
   `version == 0`) take the leg count from `cfg.legs` (`NONE*` 0, `UNDERLYING*` 1–8, else `UnderlyingCountInvalid`),
   clone with salt `keccak256(abi.encode(msg.sender, salt))` (`SaltAlreadyUsed` when the predicted address is already in the
@@ -716,11 +716,11 @@ no `setZetherEnabled` (P3); `createDex` and the DEX catalogue are built (P2b-1,
   `creatorOf`, `versionOf`, `getWrapper(creator, underlying)` (the first; it may be a multi-leg token: read
   `underlyings()`), `getWrapperCount/At`, `deployCountFor/deployedFor`. Every leg is indexed, `address(0)` for the
   native coin.
-- **Zether creation on the v1 factory (BUILT).** `OpenFactoryV1.createZetherToken` and `createUnregistered(ZETHER)` call
-  `_checkVerifier(verifier)` (`OpenFactoryV1.sol:179-190`): a zero verifier reverts `VerifierRequiredForZether`; no code, or
+- **Zether creation (BUILT, P3).** `createToken` / `createTokenUnregistered` of kinds 2–3 check `cfg.conf.verifier` (`_checkZether`)
+  as `OpenFactoryV1.createZetherToken` / `createUnregistered(ZETHER)` do: zero reverts `VerifierRequiredForZether`; no code, or
   `verifier.isSupportedOnThisChain()` false or unanswered, reverts `VerifierUnsupportedOnThisChain(verifier, curveName)`
   with the verifier's `curveName()` (empty when it has no code or no answer), so a BLS12-381 verifier cannot be paired
-  with a chain without EIP-2537. `OpenFactory` has no such path before P3.
+  with a chain without EIP-2537; the token's `initialize` repeats the dev-chain check.
 - **Trust the index only for registered versions** (`versionOf(token).version != 0`): the factory indexes what the
   config says, and an unregistered implementation (version 0) may do anything else with it.
 
@@ -729,8 +729,8 @@ no `setZetherEnabled` (P3); `createDex` and the DEX catalogue are built (P2b-1,
 The built interface is `IOpenFactory.sol` and the `TokenConfig` block of [CTR-TOK-25](#CTR-TOK-25); the event is
 `TokenCreated(token, creator, kind, version, implementation, features, lockedFeatures, owner, underlyings)`, the
 enum `TokenKind { NONE, UNDERLYING, NONE_ZETHER, UNDERLYING_ZETHER, NONE_PQZ, UNDERLYING_PQZ, NONE_ZETHER_PQZ,
-UNDERLYING_ZETHER_PQZ }`. The deploy scripts register `NoUnderlyingToken` as version 1 of `NONE`; `UnderlyingToken` is over EIP-170 and is not
-deployed ([CTR-GEN-06](README.md#CTR-GEN-06), [CTR-TOK-24](#CTR-TOK-24)). Separate `AssetFactory` for action
+UNDERLYING_ZETHER_PQZ }`. The deploy scripts register `NoUnderlyingToken` as version 1 of `NONE` (on a dev chain also both `*_ZETHER`
+kinds, the gate on); `UnderlyingToken` is not deployed ([CTR-GEN-06](README.md#CTR-GEN-06), [CTR-TOK-24](#CTR-TOK-24)). Separate `AssetFactory` for action
 contracts: [asset-suite.md](asset-suite.md#templates).
 
 ## <a id="interfaces"></a>7. Interfaces
@@ -791,7 +791,7 @@ each library ≤ 24,576 B.
 | `TradeLib` (built, 3,104 B) | `TradeOrder` checks, `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, the token side of fills; `scaas.trade` | all |
 | `AdminLib` | flag validation, roles, owner, `disableFeature` (built, 3,406 B); later freeze / force / pause / allowlist | all |
 | `UnderlyingLib` (built, 11,654 B) | legs; the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out); rate changes with timelock; `disableWrap`; the reserve invariant | `UNDERLYING*` |
-| `ZetherLib` | statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries | `*_ZETHER` |
+| `ZetherLib` (built, 15,662 B) | statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries | `*_ZETHER` |
 | `HederaLib` | HIP-632 signature path (`requireValid`, public view, linked; 753 B), HTS associate | all (branch on `IS_HEDERA`, [CTR-TOK-23](#CTR-TOK-23)) |
 
 - **Pay stays inline** (controller ruling, pending the owner): `mtxPay`, `payWithFee` and `mtxPayReceiverFee` are thin builders over the inline `MetaTransfer` core, which a library cannot call; each checks the `PAYABLE` flag.
@@ -806,7 +806,7 @@ each library ≤ 24,576 B.
   contract exceeds its budget. **Transitional (BUILT, P1e):** `scripts/size_gate.py` runs in CI over
   `forge build src --sizes --json` as a ratchet (controller ruling, pending the owner): token implementations ≤ 20,480 B,
   other contracts ≤ 24,576 B, init code ≤ 49,152 B, and a contract named in `smartcontracts/evm/size-baseline.json`
-  may exceed its limit but never its recorded size (`NoUnderlyingToken` 22,951 B, `UnderlyingToken` 29,974 B, `ZetherToken` 28,860 B; owner decision 2026-10-11: optimise
+  may exceed its limit but never its recorded size (`NoUnderlyingToken` 22,978 B, `UnderlyingToken` 30,036 B, `NoUnderlyingZetherToken` 30,659 B, `UnderlyingZetherToken` 40,381 B; owner decision 2026-10-11: optimise
   later, wait for the Glamsterdam fork, code size is not a concern); the baseline does not tighten itself, so a smaller contract's entry is lowered by hand.
   **Flag:** with P2a `NoUnderlyingToken` is over its 20,480 B budget (still under EIP-170).
 
@@ -900,7 +900,7 @@ Unit (forge, `test/v2/`):
 |---|---|
 | Base | both typehashes pinned (`test_metaTxTypehashIsPinned`, `test_metaTransferTypehashIsPinned`, [CTR-MTX-15](metatx.md#CTR-MTX-15)); salted-domain KATs `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`; the built v1 struct is `metatx_v1_kat.json`, read by scaas-node and clientkeys until P5) and `metatransfer_kat.json` plus an `mtxpay` vector with `batch = payLane(payId)`, `nonce = 0` and `mtxExecute` calldata vectors per allowlisted selector, all checked by Solidity, node and the client library (its lane derivation already equals `payLane`); `MetaNonceCancelled`; the allowance rule on every kind (EOA caller and EOA spender of `approve` refused); ERC-1271 400 k only for `SmartKeyAccount` clones; `chainUid()` equals the implementation's; the factory refuses an implementation with another `chainUid()` |
 | Fees | percent on the basis, fee on top, 1 % cap on transfer, payment and `AMOUNT` selectors; `ABSOLUTE` selectors uncapped and `PERCENT` refused; `FeeRecipientIsPayee` for transfer, `pay`, `payWithFee`, bound and relayer-default |
-| Gasless unwrap and wrap | `mtxExecute(unwrap(…))`: fee in wrapped units after the call; `UnwrapRecipientInvalid` for 0 and `address(this)`; `UnwrapBelowMin`; underlying revert (blacklist mock) reverts fee and nonce; sender-pays fee-on-transfer ⇒ `UnderlyingTransferMismatch`; ERC-777 mock whose hook re-enters (`cancelNonce`, `transfer`) mid-unwrap ⇒ `Reentrancy`; not allowlisted on tier 1; works on a disabled leg and during a pending rate change. `mtxExecute(wrap(…))` pays its fee from minted units. `mtxWrap` on `UnderlyingToken` (built, P2a; Zether: P3): price, minimum, fee to the relayer, `WrapReceivedMismatch`, unknown underlying refused |
+| Gasless unwrap and wrap | `mtxExecute(unwrap(…))`: fee in wrapped units after the call; `UnwrapRecipientInvalid` for 0 and `address(this)`; `UnwrapBelowMin`; underlying revert (blacklist mock) reverts fee and nonce; sender-pays fee-on-transfer ⇒ `UnderlyingTransferMismatch`; ERC-777 mock whose hook re-enters (`cancelNonce`, `transfer`) mid-unwrap ⇒ `Reentrancy`; not allowlisted on tier 1; works on a disabled leg and during a pending rate change. `mtxExecute(wrap(…))` pays its fee from minted units. `mtxWrap` on `UnderlyingToken` (built, P2a; `UNDERLYING_ZETHER` P3): price, minimum, fee to the relayer, `WrapReceivedMismatch`, unknown underlying refused |
 | Named | `testFuzz_namedDigestEqualsGeneric` over random struct fields for every named function; a signature consumed by a named call fails on the generic path and vice versa; every `MtxModeShape` case; a no-fee struct signed with a leftover `fee ≠ 0` fails through `mtxTransfer`; `mtxPay` lane equals `payLane`; second `mtxPay` of a `payId` reverts `MetaTxBadNonce`; `payWithFee` with the same `entryRef` still emits `PaymentSettled` (documents the per-path limit); `mtxBatch` atomic (one bad item reverts all), length mismatch, empty |
 | `NONE` | init mint to `initialHolder`; `mint` with `MINTABLE` and `MissingRole`; `burn` with `BURNABLE`; fixed supply without `MINTABLE`; `disableFeature(MINTABLE)` |
 | `UNDERLYING`, one leg | rate 1:1 equals the removed v1 wrapper's behaviour; rounding down on wrap/unwrap; `burned = ⌈out·q⌉`; `previewWrap` `used`; `WrapTooSmall`/`UnwrapTooSmall`/`UnwrapBelowMin`; two-argument `unwrap` = `minOut 0`; fee-on-transfer inbound measured; sender-pays fee-on-transfer reverts `UnderlyingTransferMismatch`; donation not counted; `ReserveShortfall` after a negative-rebase mock stops wrap and not unwrap; `addReserve`; decimals snapshot; init refusals |
diff --git a/docs/contracts/zether.md b/docs/contracts/zether.md
index eab8a28..edf1994 100644
--- a/docs/contracts/zether.md
+++ b/docs/contracts/zether.md
@@ -1,14 +1,14 @@
 # Zether — confidential amounts (classical)
 
-**Status: BUILT, UNAUDITED — NOT FOR PRODUCTION FUNDS.** `ZetherToken`, `ZetherMetaTx`, `ZetherVerifierBn254`,
-`ZetherVerifierBls12381`, `ZetherCurves`, `ZetherTranscript`, `ZetherSafety`, the built `UniversalAccountRegistry` and
-the Rust prover `zether-prover` exist with tests (`smartcontracts/evm/src/zether/**`, `src/registry/**`; paths of the
-form `smartcontracts/src/…` (e.g. `smartcontracts/src/zether/**`) and `smartcontracts/test/…` in older references now live under `smartcontracts/evm/`). Every
-Zether contract and the registry refuse to deploy or initialize outside chain ids 31337/1337, and
-`OpenFactoryV1.zetherEnabled` defaults to `false` ([safety gate](#safety-gate)). Post-quantum confidential balances are a
-separate class ([pq-zero-knowledge.md](pq-zero-knowledge.md)). The relaying target — `ZetherToken` on the one meta-transaction base,
-confidential ops through the generic self-call, `zetherShield` from the public balance, `chainUid` in every chain-bound
-digest — is **SPECIFIED** ([relaying](#envelope)); the built `ZetherMetaTx` envelope ops are its transitional form.
+**Status: BUILT, UNAUDITED — NOT FOR PRODUCTION FUNDS.** The kinds `NONE_ZETHER` (`NoUnderlyingZetherToken`) and
+`UNDERLYING_ZETHER` (`UnderlyingZetherToken`) on the one meta-transaction base (`ZetherLayer` + `ZetherLib`),
+`ZetherStatements`, `ZetherDisclosure`, `ZetherVerifierBn254`, `ZetherVerifierBls12381`, `ZetherCurves`,
+`ZetherTranscript`, `ZetherSafety`, the built `UniversalAccountRegistry` and the Rust prover `zether-prover` exist with
+tests (P3; `smartcontracts/evm/src/zether/**`, `src/registry/**`). Every Zether contract and the registry refuse to
+deploy or initialize outside chain ids 31337/1337, and `OpenFactory.zetherEnabled` defaults to `false` ([safety
+gate](#safety-gate)). Post-quantum confidential balances are a separate class ([pq-zero-knowledge.md](pq-zero-knowledge.md)). Relaying is
+the generic self-call ([relaying](#envelope)), `chainUid` is in every chain-bound digest; the built `ZetherToken` with its
+`ZetherMetaTx` envelope is backed up, not built, in `smartcontracts/evm/legacy/p3/`.
 
 This file is the contract between the prover and the Solidity verifier: **every byte** of the statement, the
 transcript and the proof must be exactly as written here. An ambiguity is a bug of this document — report it, do not
@@ -48,7 +48,7 @@ terminator.
 ## 1. Scope
 
 <a id="scope"></a>
-<a id="CTR-ZTH-01"></a>**CTR-ZTH-01** — **Full classical Zether** (owner): `ZetherToken` clones through the factory,
+<a id="CTR-ZTH-01"></a>**CTR-ZTH-01** — **Full classical Zether** (owner): the `*_ZETHER` kinds clone through the factory,
 verifiers for bn254 **and** BLS12-381 (the curve is a deploy-time parameter of each token: the creator chooses the
 verifier at `initialize`, there is no setter and no system-wide curve; the prover is generic over the curve), ElGamal
 `acc/pending` balances, two `zetherRollOver` modes (`PUBLIC` default, `OWNER_ONLY` opt-in per account, with an on-chain
@@ -266,13 +266,11 @@ flowchart LR
 <a id="CTR-ZTH-35"></a>**CTR-ZTH-35** — **`zetherShield` draws from the caller's public balance** (owner):
 `zetherShield(encodedY, amount)` always debits `amount · shieldScale` public Zether units from `_msgSender()` and adds `amount`
 to `totalShielded`, instead of pulling the underlying a second time — one path for every Zether token. The escrow
-invariant (`underlying held ≥ totalSupply + totalShielded · shieldScale`, `ZetherToken.sol:619-623`) is unchanged by
+invariant (`underlying held ≥ totalSupply + totalShielded · shieldScale`, [CTR-ZTH-44](#CTR-ZTH-44)) is unchanged by
 construction: the underlying is already held for those public units. A holder of an outside underlying wraps, then
 funds — two direct calls, or one gasless `mtxBatch` of `mtxExecute(wrap)` and `mtxExecute(zetherShield)`; an EOA holding a
 SCaaS underlying wraps by signature (`mtxWrap`, [CTR-TOK-20](token-wrappers.md#CTR-TOK-20)), then funds. Without it, an
 EOA holding a SCaaS underlying could not shield at all (it cannot approve, [CTR-TOK-01](token-wrappers.md#CTR-TOK-01)).
-**Transitional (BUILT):** `fund` (now `zetherShield`) pulls `amount·shieldScale` underlying from `msg.sender` through `transferFrom`, the
-spender being the token contract itself.
 - **transfer:** the sender proves over `acc`. Effect:
 
 ```
@@ -333,8 +331,8 @@ protocol change that needs its own cryptographic review; epochs are not the fall
 ## <a id="statement-byte-layout"></a>7. Statement (byte layout)
 
 The token **builds** the statement from storage + payload; the prover builds exactly the same. `P` = the bytes of one
-point. Header (416 bytes, common to every op; **SPECIFIED** — the built header is 384 bytes, without the `chainUid`
-word at offset 96 and with every later field 32 bytes earlier, [CTR-ZTH-36](#CTR-ZTH-36)):
+point. Header (416 bytes, common to every op, `chainUid` at offset 96, [CTR-ZTH-36](#CTR-ZTH-36); built in P3, the
+verifier reads `fee` at 288 and `amount` at 352):
 
 | Offset | Len | Field |
 |---|---|---|
@@ -363,9 +361,9 @@ Without it a re-created chain restarts `modeNonce`, `accSeq`, `sendCounter` and
 block numbers, so a captured mode or rollover signature, a proof or a disclosure would verify there; `entryRef` gains
 it so that references never collide across chains (client reconciliation still keys by `(chain_key, entryRef)`). The
 built `UniversalAccountRegistry` takes `chainUid` as a constructor immutable and adds it to its PoP challenge; because
-it checks raw digests, every caller's digest carries `chainUid` itself. The prover builds statements with `chainUid`,
-and the statement, envelope, rollover, mode, disclosure and `entryRef` vectors are regenerated. **Transitional
-(BUILT):** these digests carry `block.chainid` only, and the registry takes no `chainUid`.
+it checks raw digests, every caller's digest carries `chainUid` itself. **Built (P3)** for every token-side digest and
+the prover (which also mixes `chainUid` into its `s`); the vectors are regenerated. **Transitional:** the built registry
+takes no `chainUid` until the UA registry replaces it ([CTR-UA-22](accounts.md#CTR-UA-22); controller ruling, pending the owner).
 
 Points:
 
@@ -516,7 +514,7 @@ every recipient: handing `s` to a checker opens every leg of that transfer, deco
 opening without `s` is [`SENDER_CP`](#CTR-ZTH-40)). The default entry point `zetherTransfer` is the
 multi-recipient transfer in mode HASH ([CTR-ZTH-38](#CTR-ZTH-38)); the single-recipient format above is kept unchanged
 (same payload, statement, proof, proof system id and full-bundle storage) under the name `zetherTransferSingle`.
-The statement header stays the BUILT 384-byte layout (the `chainUid` word is [CTR-ZTH-36](#CTR-ZTH-36)).
+The statement header is the common header of [Statement](#statement-byte-layout) (with `chainUid`).
 
 **Relation and proof.** Witness: `x, s, v_1..v_M, b' = b − Σv_j − fee, γ_vj, γ_b`. Ciphertexts (shared `s`, shared
 `D_out = [s]G`):
@@ -606,10 +604,8 @@ meta-transaction layer, not a parallel branch): Zether is a `ZetherLayer` on `Me
 ([CTR-MTX-07](metatx.md#CTR-MTX-07)). Every confidential token is relayable through the same pipeline
 ([metatx.md](metatx.md)); the post-quantum class follows the same rule ([CTR-PQZ-15](pq-zero-knowledge.md#CTR-PQZ-15)). The
 envelope (`ZetherMetaTx`, `_executeOp`, `relayed*`) is gone: every Zether entry point is an allowlisted self-call of
-`mtxExecute` ([CTR-ZTH-34](#CTR-ZTH-34), [CTR-MTX-19](metatx.md#CTR-MTX-19)). **Transitional (BUILT, removed in P3):**
-`ZetherToken` carries a separate `ZetherMetaTx` mixin that uses `MetaTxLib` read-only, with its own pipeline, domain
-`("SCaaS ZetherToken", "1", chainId, token)` and envelope ops (`m.data = op ‖ abi.encode(...)`, `m.to = address(0)`,
-`m.value = 0`); it disappears into the base.
+`mtxExecute` ([CTR-ZTH-34](#CTR-ZTH-34), [CTR-MTX-19](metatx.md#CTR-MTX-19)). **Built (P3)**; the old `ZetherToken` with
+its `ZetherMetaTx` mixin (own pipeline, envelope ops, salt-less domain) is in `legacy/p3/`, not built.
 
 Three layers:
 
@@ -631,12 +627,11 @@ envelopeBinding = keccak256(abi.encode(
 ```
 
 `MetaTransaction` has no `to`/`value` ([CTR-MTX-15](metatx.md#CTR-MTX-15)), so the binding carries none; the
-binding and statement vectors regenerate with those of [CTR-ZTH-36](#CTR-ZTH-36). **Transitional (BUILT):** the built
-binding also hashes `m.to` and `m.value` of the single 11-field struct.
+binding and statement vectors are regenerated with those of [CTR-ZTH-36](#CTR-ZTH-36) (built, P3).
 
 It is part of the statement (`ZTX_V1_RELAYED`); direct calls use `ZTX_V1_DIRECT` with binding 0. The base computes it
-in step 5 of `mtxExecute` and passes it to the self-call through the transient ticket
-([CTR-ZTH-34](#CTR-ZTH-34)); a function reads it only while `msg.sender == address(this)` and the ticket is live, else
+in step 5 of `mtxExecute` (its `_envelopeBinding` hook, which the token implements) and passes it to the self-call
+through the transient ticket ([CTR-ZTH-34](#CTR-ZTH-34)); a function reads it only while `msg.sender == address(this)` and the ticket is live, else
 it proves with binding 0. Consequences:
 stripping the proof out of its envelope and calling directly ⇒ the statement carries `ZTX_V1_DIRECT`, binding 0 ⇒ the
 transcript differs ⇒ revert; putting the proof into another envelope (other `from`/`batch`/`nonce`/expiry/fee) ⇒ the
@@ -659,12 +654,11 @@ the base's step 6, `FIXED` absolute or `NONE` (fee class `ABSOLUTE`, [CTR-MTX-20
 (`confidentialFee` to the beneficiary) is unchanged. The dynamic arguments are re-encoded canonically by the node
 before it computes the mesh `intent_id`. The `rollOver*` functions stay outside the allowlist: `zetherRollOver` needs no
 signature, and `zetherRollOverSigned`/`zetherSetRollOverMode` carry their own signature, so anyone can relay them.
-**Transitional (BUILT):** the envelope carries hand-written ops — `OP_ZTRANSFER =
-bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)"))`, args `(bytes payload, bytes proof, bytes authSig,
-bytes32 beneficiary)`, and `OP_ZBURN = bytes4(keccak256("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)"))`,
-args `(bytes payload, uint256 amount, address recipient, bytes32 beneficiary, bytes proof, bytes authSig)` — decoded
-and re-sent through the self-only `relayedTransfer`/`relayedBurn`/`relayedBurnDecoded` with an internal `OuterFee`
-(payer, recipient, amount); `zetherShield` and the `rollOver*` functions are direct calls only.
+**Built (P3)**, with every signer-authorised confidential op allowlisted `ABSOLUTE`: the four transfers, `zetherShield`,
+`zetherUnshield`, and on `UNDERLYING_ZETHER` `zetherWrapShield` and `zetherUnshieldUnwrap` beside `UnderlyingToken`'s
+wrap and unwrap entries (without `unwrap(uint256,address)`). A direct `zetherUnshieldUnwrap` proves under `ZTX_V1_DIRECT`
+with `keccak256(abi.encode(keccak256("SCAAS-ZETHER-UNWRAP-V1"), u, minOut))` as its binding word, so a copied proof can
+neither change the leg, drop `minOut` nor become a `zetherUnshield` (controller rulings, pending the owner).
 
 <a id="direct-transfer"></a>
 <a id="CTR-ZTH-13"></a>**CTR-ZTH-13** — **A direct call carries no outer fee.** The caller (`msg.sender`) pays its own
@@ -672,12 +666,12 @@ gas, statement `ZTX_V1_DIRECT`, `envelopeBinding = 0`; the outer fee lives only
 
 ```
 zetherTransfer(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary) returns (bytes32 entryRef)
-      built selector 0x7c947e8e (`transferConfidential`); the new name has another selector
+      selector 0xd228e5c0; the single format zetherTransferSingle is 0x4d2e578f
 zetherUnshield(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary, address to, uint256 amount)
 ```
 
 In short: `zetherTransfer(payload, proof, authSig, beneficiary)` and
-`zetherUnshield(payload, proof, authSig, beneficiary, to, amount)`. **Transitional (BUILT):** the function is `burn(payload, amount, recipient, beneficiary, proof, authSig)`, built selector 0x8938052e, and `to` is `recipient`.
+`zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` (selector 0x983c7842; built, P3).
 
 (A first version had 7 parameters `…, FeeMode, uint256, address` — dropped: nobody needs to pay a fee to themselves,
 and 7 parameters push every Solidity caller into *stack too deep* with legacy codegen.) `authSig` is present on
@@ -722,25 +716,20 @@ already is one constant per token, but nothing forbids an outer `FIXED` fee chos
 <a id="fee-would-stick"></a>
 <a id="CTR-ZTH-23"></a>**CTR-ZTH-23** — The outer fee recipient = m.feeRecipient or `msg.sender`; a resolved
 recipient `== address(token)` reverts `FeeWouldStick` (as in the DEX); the base also refuses every transfer **to**
-`address(this)` (`TransferToSelf`, [CTR-MTX-18](metatx.md#CTR-MTX-18)). The built `ZetherMetaTx` checks only 0
-(`ZetherMetaTx.sol:74-75`), so such a
-fee would be stuck forever in the token's own public ERC-20 balance. Status **SPECIFIED**; test included.
+`address(this)` (`TransferToSelf`, [CTR-MTX-18](metatx.md#CTR-MTX-18)). **Built (P3):** the base's `TransferToSelf`
+refuses it in step 6 (no separate `FeeWouldStick` error; controller ruling, pending the owner).
 
 <a id="erc1271-cap"></a>
 <a id="CTR-ZTH-21"></a>**CTR-ZTH-21** — Zether envelopes get the same ERC-1271 cap as every token of the base
 ([CTR-ACC-05](accounts.md#CTR-ACC-05)): 400 k when `m.from.codehash` is the `SmartKeyAccount` clone codehash
-(immutable at `initialize`/deploy), else 50 k. The built mixin uses `staticcall{gas: 50_000}` (`ZetherMetaTx.sol:123`), so a passkey
-`SmartKeyAccount` clone always fails `MetaTxBadSignature` on envelopes. The built registry is not changed (the UA
-registry replaces it and already sets 400 k, [CTR-UA-17](accounts.md#CTR-UA-17)). Test: an envelope signed by a
-real passkey `SmartKeyAccount` passes (the built `test_smartAccount1271Auth` uses only a `Mock1271Wallet` ECDSA). Status **SPECIFIED**.
+(immutable at `initialize`/deploy), else 50 k. **Built (P3)** through the base (`MetaTokenBase._erc1271Gas`); the built
+registry is not changed (the UA registry replaces it and already sets 400 k, [CTR-UA-17](accounts.md#CTR-UA-17)). An
+envelope test with a real passkey `SmartKeyAccount` is open (a `Mock1271Wallet` signer is tested).
 
 Pipeline order: the base's ([CTR-MTX-17](metatx.md#CTR-MTX-17)) — relayer → expiry → mode → nonce → signature →
 shape (allowlist, fee class) → nonce written → the self-call (cheap op checks `accSeq`, `sendCounter`, registration,
 lengths, then **proof verification**, then effects) → outer fee from the public balance → event; a failure anywhere
 reverts everything. Relayers simulate first, so an envelope whose signer lacks the fee is refused at intake.
-**Transitional (BUILT):** relayer → expiry → mode → nonce → signature → **public balance sufficient for the outer fee**
-→ cheap op checks → **proof verification** → collect the outer fee → execute → nonce++, so an envelope without enough
-for its fee reverts before any precompile.
 
 <a id="no-memo"></a>
 <a id="CTR-ZTH-12"></a>**CTR-ZTH-12** — **No AEAD memo**; the client decrypts balances itself, with the configurable BSGS
@@ -870,8 +859,7 @@ e = hashToScalar(keccak256("SCAAS-ZETHER-DISCLOSE-V1" ‖ be32(chainid) ‖ chai
 
 `j` is in the challenge for every kind (single format: `j = 0`); the disclosure vectors changed with it. The nonce `k`
 is hedged (`H(secret ‖ statement ‖ rng)`): a repeated `k` over two openings reveals the secret. The prover's
-`verify_opening` mirrors `ZetherDisclosure` (`open_sender_cp` builds `SENDER_CP`). **Transitional (BUILT):** the
-challenge carries `block.chainid` and no `chainUid` ([CTR-ZTH-36](#CTR-ZTH-36)).
+`verify_opening` mirrors `ZetherDisclosure` (`open_sender_cp` builds `SENDER_CP`); `chainUid` built in P3.
 
 Additional checks: `amount < 2^n_v = 2^64` (otherwise `amount + r` would also "pass", because `[amount]G` depends only on
 `amount mod r`; `2^64 < r`, so each `[amount]G` has exactly one valid `amount`), `z < r`, `e ≠ 0`; `A1`, `A2` go into the
@@ -885,7 +873,8 @@ sender's `s` opens only this transfer, [CTR-ZTH-30](#CTR-ZTH-30)).
 ([CTR-ZTH-38](#CTR-ZTH-38)), the single format stores the full bundle: **bn254 256 B** (≈ 9 slots, ≈ +200 k gas), **BLS12-381 512 B** (4 points × 128 B,
 ≈ 17 slots, ≈ +375 k gas — estimate); `be32(amount)` already has room for 64 bits. Unsupported underlyings (fee-on-transfer,
 rebasing) are the `UnderlyingLib` rule ([CTR-TOK-11](token-wrappers.md#CTR-TOK-11)). The built NatSpec of
-`ITransferDisclosure.sol:24` ("no extra gas at transfer") is wrong and is corrected with the next fix.
+`ITransferDisclosure.sol:24` ("no extra gas at transfer") is corrected in P3, where HASH stores its hash in one `bytes32`
+slot as CTR-ZTH-38 says (built: a 32-byte `bytes`, two slots).
 
 <a id="auditor"></a>
 <a id="CTR-ZTH-09"></a>**CTR-ZTH-09** — **The auditor key is immutable**, set at `initialize` (there is no setter, so
@@ -919,7 +908,8 @@ client exports a standalone evidence file `(entryRef, v, s, chainId, tokenAddres
 storage (per-UA `acc`/`pending`, counters, `totalShielded`, disclosure entries) and the external stubs of
 [CTR-ZTH-45](#CTR-ZTH-45); the logic is `ZetherLib`. The verifier (curve) and the auditor key are chosen at creation and
 immutable; the registry address is an implementation immutable; the dev-chain gate `ZetherSafety` stays
-([safety gate](#safety-gate)). `ZetherDisclosure` stays as built ([CTR-ZTH-43](#CTR-ZTH-43)); the prover views move to
+([safety gate](#safety-gate)). `ZetherDisclosure` stays as built but for `chainUid` in its challenge (P3, controller
+ruling, pending the owner; [CTR-ZTH-43](#CTR-ZTH-43)); the prover views move to
 `ZetherStatements` ([CTR-ZTH-46](#CTR-ZTH-46)).
 
 All rules of the multi-recipient design (Z1–Z13,
@@ -930,15 +920,15 @@ leg may be the native coin like on every `UNDERLYING*` kind ([CTR-TOK-26](token-
 ([CTR-ZTH-04](#CTR-ZTH-04); shielded amounts are bounded by `2^54`).
 
 - **Reserve invariant.** `UNDERLYING_ZETHER`: `Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`,
-  checked after every operation that moves value out. `totalSupply()` counts public balances only (the ERC-20 meaning);
-  `totalShielded()` is a separate view.
+  held by construction (a wrap-shield credits whole units, an unshield-unwrap pays at most what it removes) and checked
+  by `executeRate` with the shielded part (controller ruling, pending the owner). `totalSupply()` counts public
+  balances only (the ERC-20 meaning); `totalShielded()` is a separate view.
 - **The minter never mints shielded.** `MINTABLE` on `NONE_ZETHER` mints public balance only; shielded value exists only
   through `zetherShield` / `zetherWrapShield`, which take public units or an underlying deposit.
 - **Fees.** The inner confidential fee (fixed per token, credited to the beneficiary UA) stays in `ZetherLib`. Relaying
   goes through the base ([CTR-ZTH-34](#CTR-ZTH-34)).
-- **Removed from the built `ZetherToken`:** its own underlying and `wrap`/`unwrap`/`fund`, `_checkEscrow`,
-  `ZetherMetaTx` and the envelope, the v1 `IFactoryToken` init, the name `burn`, the prover views (to
-  `ZetherStatements`).
+- **Removed with the built `ZetherToken`** (now in `legacy/p3/`): its own underlying, `wrap`/`unwrap`/`fund`,
+  `_checkEscrow`, `UnsupportedUnderlying`, `ZetherMetaTx` and the envelope, the v1 init, `burn`, the prover views.
 
 <a id="CTR-ZTH-45"></a>**CTR-ZTH-45** — **Entry points and names** (owner, T5). Zether entry points carry the prefix
 `zether` (classical) or `pqz` ([CTR-PQZ-22](pq-zero-knowledge.md#CTR-PQZ-22)); `shieldScale` as above.
@@ -955,18 +945,17 @@ leg may be the native coin like on every `UNDERLYING*` kind ([CTR-TOK-26](token-
 `NONE_ZETHER` has `zetherShield` / `zetherUnshield` only. Events follow the names (`ZetherShielded`, `ZetherUnshielded`,
 `ZetherTransfer`, `ZetherTransferMulti`, …). There is no `zetherRegister` / `pqzRegister` (T6): the registry's
 `register` is relayable (PoP over `popDigest(ua, authRef)`, anyone submits, [accounts.md](accounts.md)), and the
-confidential kinds depend on that registry for gasless onboarding. **Transitional (BUILT, renamed in P3; node and client
-ABI in P5):** the built names are `transferConfidential`, `transferConfidentialBundle`, `transferConfidentialNoBundle`,
-`transferConfidentialSingle`, `burn`, `fund`, `rollOverPublic`, `rollOverBatch`, `rollOverSigned` (`mtxRollOver` in
-earlier text), `setRollOverMode` (`mtxSetRollOverMode`), `wrap`/`unwrap` on the token's own underlying; the built
-events are `Funded`, `ConfidentialTransfer`, `ConfidentialTransferMulti`, `Burned`.
+confidential kinds depend on that registry for gasless onboarding. **Built (P3)** under these names (before P3:
+`transferConfidential*`, `burn`, `fund`, `rollOverPublic`, `setRollOverMode`, …; node and client ABI in P5);
+`zetherShield` takes the encoded key, `zetherWrapShield` the UA; the two underlying paths emit only `ZetherShielded` /
+`ZetherUnshielded`, since nothing is minted or burnt (controller ruling, pending the owner).
 
 <a id="CTR-ZTH-46"></a>**CTR-ZTH-46** — **The prover views live in a stateless `ZetherStatements`** (owner, T14; pairs
 with `ZetherDisclosure`). It serves `transferStatement`, `transferStatementSingle` and `unshieldStatement` (built:
 `burnStatement`) from the token's `accountState`, so the token carries no prover-only view; no admin, no upgrade, one
 stateless instance, as `ZetherDisclosure` ([CTR-ZTH-43](#CTR-ZTH-43)); it reads the curve from the token. Its output is the byte layout of [Statement](#statement-byte-layout) and
-nothing else. **Transitional (BUILT):** the views are on `ZetherToken`, which is over EIP-170 ([Gas](#gas)); the move
-is P3.
+nothing else. **Built (P3)**; every view takes `envelopeBinding` (`transferStatement` too: a multi-recipient transfer
+relays), and `unshieldUnwrapStatement` / `unwrapBinding` serve `zetherUnshieldUnwrap` (controller ruling, pending the owner).
 
 <a id="CTR-ZTH-47"></a>**CTR-ZTH-47** — **Regulated flags are refused on confidential kinds** (owner, T11). The flags
 valid on `NONE_ZETHER` / `UNDERLYING_ZETHER` are `PAYABLE`; `MINTABLE` / `BURNABLE` (`NONE_ZETHER`);
@@ -994,9 +983,9 @@ chain is open ([CTR-ZTH-33](#CTR-ZTH-33)). Post-quantum Zether serves the privat
 default; the check is repeated in `initialize` and in the verifier and registry constructors. Adding a chain = a change
 of `ZetherSafety` + a new deployment, after the cryptographic audit.
 
-- `OpenFactoryV1.zetherEnabled` defaults to `false` (`OpenFactoryV1.sol:33`); `setZetherEnabled(true)` (registrar) reverts outside a dev chain;
-  `createZetherToken`/`createUnregistered(ZETHER)` on `OpenFactoryV1` revert when the flag is off **or** the chain is not a dev chain.
-- `ZetherToken.initialize`, the constructors of both verifiers and `UniversalAccountRegistry` also revert outside a dev
+- `OpenFactory.zetherEnabled` defaults to `false`; `setZetherEnabled(true)` (registrar) reverts outside a dev chain;
+  creating a `*_ZETHER` token reverts when the flag is off **or** the chain is not a dev chain (built, P3).
+- The kinds' `initialize`, the constructors of both verifiers and `UniversalAccountRegistry` also revert outside a dev
   chain (a manual deploy cannot bypass it).
 - The NatSpec of every Zether contract carries **UNAUDITED — NOT FOR PRODUCTION FUNDS**.
 
@@ -1012,8 +1001,8 @@ both stay supported per token meanwhile.
 <a id="CTR-ZTH-20"></a>**CTR-ZTH-20** — **Clients and the gateway pin the canonical verifier and registry.** A wallet
 (the client library) and the node gateway accept a Zether token only when `verifier()` is in the chain's published list
 of **canonical** verifiers and `registry()` equals the chain's canonical registry. The factory does not refuse others
-(`_checkVerifier` only requires code + `isSupportedOnThisChain()`, `OpenFactoryV1.sol:179-190`; `initialize` only
-requires the registry to have code, `ZetherToken.sol:136`) — "provenance instead of gatekeeping"
+(`OpenFactory._checkZether`, as the v1 `_checkVerifier`, only requires code + `isSupportedOnThisChain()`; the registry is
+an implementation immutable checked only for code) — "provenance instead of gatekeeping"
 ([CTR-TOK-17](token-wrappers.md#CTR-TOK-17)) — so a v1 token from a registered implementation could still carry a fake
 verifier (returning `true` for every proof ⇒ `zetherUnshield` drains the escrow) or a fake registry (`requireAuthorized` a no-op).
 
@@ -1086,7 +1075,7 @@ Limits (shielded units; for a 6-decimal stablecoin kept to 2 decimals, `shieldSc
 | Maximum balance of one account | ≤ the token's supply | ≤ 2^54 |
 | **Maximum amount of ONE transfer** (`v < 2^n_v`) | `n_v` | 2^64 − 1 ⇒ in practice bounded only by the sender's balance: the whole balance in one transaction (the former 2^32 − 1 = 4,294,967,295-unit cap — $42.9 million at one unit = $0.01 — forced large payments into several transactions, whose count revealed "amount > cap") |
 | Withdrawal (`zetherUnshield`) | `0 < amount ≤ maxDecryptableShielded` | ≤ the supply |
-| Confidential fee | `confidentialFee < 2^n_v` **and** `< maxDecryptableShielded` (else `BadInit`, `ZetherToken.sol:138-140`) | < 2^64 and < `maxDecryptableShielded` |
+| Confidential fee | `confidentialFee < 2^n_v` **and** `< maxDecryptableShielded` (else `BadInit`, `ZetherLib.init`) | < 2^64 and < `maxDecryptableShielded` |
 | Amount provable by disclosure | `amount < 2^n_v` | < 2^64 |
 | Node gas cap per transaction | `max_gas_per_tx`, default 3,000,000 | **below** a direct transfer (3,286,339) and an envelope (3,357,045) ⇒ a chain with Zether sets ≥ 4.2 M |
 
@@ -1265,16 +1254,12 @@ passed in calldata — their size in the last column; their transaction calldata
 
 **Sizes** (`forge build --sizes`, runtime bytes, optimizer 200 runs; EIP-170 limit 24,576 B):
 
-| Contract | Before the split (`c137dca`) | After (rev 6) |
-|---|---|---|
-| `ZetherToken` | 31,911 (+7,335 over) | 28,939 (+4,363 over) |
-| `ZetherDisclosure` | — | 4,916 |
-| `ZetherVerifierBn254` | 15,955 | 15,955 |
-| `ZetherVerifierBls12381` | 16,312 | 16,312 |
+| Contract | Built (P3, solc 0.8.37) |
+|---|---|
+| `NoUnderlyingZetherToken` / `UnderlyingZetherToken` | 30,659 / 40,381 (over EIP-170: ratchet baseline; owner: size waits for Glamsterdam) |
+| `ZetherLib` / `ZetherStatements` / `ZetherDisclosure` | 15,662 / 7,311 / 5,021 |
+| `ZetherVerifierBn254` / `ZetherVerifierBls12381` | 15,955 / 16,312 |
 
-**Transitional (BUILT):** the disclosure split ([CTR-ZTH-43](#CTR-ZTH-43)) takes 2,972 B off the token, which is still
-over EIP-170 by 4,363 B. The next candidates are the prover-only views (`transferStatement*`, `unshieldStatement`) and the
-meta-tx relay path; not done.
 
 **Node gas cap:** the default `max_gas_per_tx = 3,000,000` (`scaas-node/src/config.rs:415-416`) is below a classical transfer (3.29 M direct / 3.36 M in an
 envelope), so the node refuses to relay Zether with the default; a chain with Zether sets `max_gas_per_tx` ≥ 4.2 M (`max_gas_per_tx ≥ 4.2 M`; BLS
@@ -1318,7 +1303,7 @@ handler (using `test/zether/helpers/ZetherProver.sol`) over random shield/transf
 Σ of the `acc` + `pending` exponents = `totalShielded ≤ maxDecryptableShielded`, escrow `held ≥ totalSupply +
 totalShielded·shieldScale` ([CTR-ZTH-18](#CTR-ZTH-18)); (b) BLS points outside the subgroup placed in the
 statement/proof (`C_out`, `D_out`, `A_*`, `L_j`) ⇒ `verifyTransfer` false/revert (the implicit subgroup check through
-MSM); (c) `D_out = O` is refused (the check exists at `ZetherVerifier.sol:170`). Status **SPECIFIED** (the built suite has none of the three).
+MSM); (c) `D_out = O` is refused (`ZetherVerifier.sol`). **Built (P3):** (a) `ZetherInvariant.t`, (b) and (c) `ZetherVerifier.t`.
 
 ## 21. Interfaces
 
@@ -1365,7 +1350,7 @@ interface IZetherToken is IERC20MetaTx {
                                         ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);    // one recipient
     function zetherUnshield(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
                   ZetherTypes.UA beneficiary, address to, uint256 amount) external;
-    function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable;   // CTR-ZTH-45; payable for a native leg
+    function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable;   // UNDERLYING_ZETHER; payable for a native leg
     function zetherUnshieldUnwrap(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
                   ZetherTypes.UA beneficiary, address u, address recipient, uint256 amount, uint256 minOut) external;
     // wrap / unwrap / mtxWrap and the legs are the UnderlyingLib surface of UNDERLYING_ZETHER (CTR-TOK-24), not repeated here
@@ -1378,11 +1363,13 @@ interface IZetherToken is IERC20MetaTx {
     // provenance: factory(), creator(), implementation(), version()
 }
 
-interface IZetherStatements {            // stateless prover views, CTR-ZTH-46 (built: on IZetherToken)
-    function transferStatement(address token, bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode) external view returns (bytes memory);
+interface IZetherStatements {            // stateless prover views, CTR-ZTH-46 (built: ZetherStatements, P3)
+    function transferStatement(address token, bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode,
+                               bytes32 envelopeBinding) external view returns (bytes memory);
     function transferStatementSingle(address token, bytes calldata payload, ZetherTypes.UA beneficiary, bytes32 envelopeBinding) external view returns (bytes memory);
     function unshieldStatement(address token, bytes calldata payload, uint256 amount, address recipient, ZetherTypes.UA beneficiary,
                                bytes32 envelopeBinding) external view returns (bytes memory);
+    // + unshieldUnwrapStatement(…, address u, uint256 minOut, bytes32 envelopeBinding), unwrapBinding(u, minOut)
 }
 
 interface ITransferDisclosure {          // implemented by the stateless ZetherDisclosure (CTR-ZTH-43)
diff --git a/docs/history/dropped-artifacts.tsv b/docs/history/dropped-artifacts.tsv
index 4ce5423..3fdab84 100644
--- a/docs/history/dropped-artifacts.tsv
+++ b/docs/history/dropped-artifacts.tsv
@@ -767,3 +767,20 @@ FactoryV2.t.sol	renamed	P1e: smartcontracts/evm/test/v2/Factory.t.sol, contracts
 createTiered(META_SINGLE, …)	obsolete	P1e: createToken(UNDERLYING, version, cfg, salt), contracts/token-wrappers.md#CTR-TOK-25
 createMetaToken(1, underlying, abi.encode(name, symbol, 0, 0, address(0)), salt)	obsolete	P1e: createToken(UNDERLYING, version, cfg, salt) with one leg, contracts/token-wrappers.md#CTR-TOK-25; the v1 createMetaToken stays on OpenFactoryV1
 28	obsolete	solc 0.8.28 pin; the pin is 0.8.37 with evm_version osaka since 2026-10-11 (contracts/README.md build pins)
+smartcontracts/src/zether/**	internal-path	contracts/zether.md header: the sources live under smartcontracts/evm/src/zether (P3)
+smartcontracts/src/…	internal-path	contracts/zether.md header: every contract path is under smartcontracts/evm/
+smartcontracts/test/…	internal-path	contracts/zether.md header: every test path is under smartcontracts/evm/
+rollOverBatch	renamed	zetherRollOverBatch, contracts/zether.md#CTR-ZTH-45 (P3)
+("SCaaS ZetherToken", "1", chainId, token)	obsolete	salt-less domain of the built ZetherMetaTx, in legacy/p3; the salted domain is contracts/metatx.md#CTR-MTX-02
+m.data = op ‖ abi.encode(...)	obsolete	hand-written envelope ops of ZetherMetaTx (legacy/p3); m.data is the real calldata, contracts/zether.md#CTR-ZTH-34
+m.to = address(0)	obsolete	the 11-field LegacyMetaTransaction of ZetherMetaTx (legacy/p3); MetaTransaction has no to, contracts/metatx.md#CTR-MTX-15
+OP_ZTRANSFER = bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)"))	obsolete	envelope op of ZetherMetaTx (legacy/p3); zetherTransfer is the multi-recipient entry, contracts/zether.md#CTR-ZTH-34
+ZetherMetaTx.sol:74-75	obsolete	line reference into legacy/p3; the fee recipient rule is contracts/zether.md#CTR-ZTH-23
+ZetherMetaTx.sol:123	obsolete	line reference into legacy/p3; the ERC-1271 cap is contracts/zether.md#CTR-ZTH-21
+ZetherToken.sol:136	obsolete	line reference into legacy/p3; the registry is an implementation immutable, contracts/zether.md#CTR-ZTH-44
+test_smartAccount1271Auth	obsolete	test of the built ZetherToken (legacy/p3); the envelope ERC-1271 test is ZetherRelay.t, contracts/zether.md#CTR-ZTH-21
+ZetherVerifier.sol:170	obsolete	line reference; the D_out = O check is pinned by test_dOutIdentityRejected, contracts/zether.md#CTR-ZTH-22
+ZetherMetaTx.sol	obsolete	the built Zether envelope mixin, backed up in smartcontracts/evm/legacy/p3/ (P3)
+ZetherToken.sol:138-140	obsolete	line reference into legacy/p3; the fee bound is ZetherLib.init, contracts/zether.md (limits table)
+zetherBurn	renamed	zetherUnshield, contracts/zether.md#CTR-ZTH-45
+nonce++	obsolete	step of the built ZetherMetaTx pipeline (legacy/p3); the base pipeline is contracts/metatx.md#CTR-MTX-17
````

- [ ] **Step 2: `TODO.md` and `HANDOFF.md`** (the P3 row and bullets, MT-1/3/4/6, the P1e follow-up (c), the P2c
  rows now merged; a new HANDOFF top section). After the implementation, put the real code commit in the HANDOFF state
  line:

```diff
diff --git a/HANDOFF.md b/HANDOFF.md
index 0d8f214..47d76f2 100644
--- a/HANDOFF.md
+++ b/HANDOFF.md
@@ -1,8 +1,36 @@
 # HANDOFF — scaas
 
+## Session 2026-10-11 (P3)
+
+**State:** P3 on branch `p3-zether`, merge pending the final review. Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`.
+969 forge tests; `zether-prover` `cargo test` green; e2e 4/4 and 1/1.
+
+**Built:** `src/zether/ZetherLib.sol` (external, `scaas.zether`), `ZetherLayer.sol`, `NoUnderlyingZetherToken.sol` (kind 2),
+`UnderlyingZetherToken.sol` (kind 3: `zetherWrapShield`, `zetherUnshieldUnwrap`), `ZetherStatements.sol`, the new
+`IZetherToken.sol`; `MetaTxBase._envelopeBinding` / `_ticketBinding` (transient `scaas.mtx.binding`); `ERC20MetaTx._domainName`
+(`"SCaaS ZetherToken"`); `ConfidentialConfig.maxShielded` / `confidentialFee`; `OpenFactory` Zether gate and verifier check;
+verifier header 416 B and `ZetherDisclosure` challenge with `chainUid`; `DeployBase` deploys the Zether stack on dev chains;
+the Rust prover on the new header, digests and ABI (vectors regenerated, `envelope.json`); from the disclosure review,
+HASH stored in one `bytes32` slot and the `ITransferDisclosure` NatSpec corrected (G2, G5). Tests: `ZetherNone.t`,
+`ZetherMulti.t`, `ZetherRevertPaths.t`, `ZetherRelay.t`, `ZetherUnderlying.t`, `ZetherInvariant.t`, `ZetherDeploy.t`,
+`v2/FactoryZether.t`. The old `ZetherToken` line is in `smartcontracts/evm/legacy/p3/` (not built). Sizes:
+`NoUnderlyingZetherToken` 30,659 B, `UnderlyingZetherToken` 40,381 B, `ZetherLib` 15,662 B (ratchet baseline).
+
+**Rulings K1-K18 (plan header).** **K1** `chainUid` in every token-side digest, the prover's `s` too; registry unchanged.
+**K2** the kinds are the public kinds plus the layer. **K3** domain `"SCaaS ZetherToken"` by a hook. **K4** two config
+fields. **K5** the gate on `OpenFactory`. **K6** every confidential op allowlisted `ABSOLUTE`. **K7** the ticket binding
+hook, not cleared. **K8** a direct unshield-unwrap binds its leg and `minOut`. **K9** reserve invariant by construction,
+`executeRate` counts the shielded part. **K10** events. **K11** shapes, standalone `IZetherToken`. **K12** statement views
+take `envelopeBinding`. **K13** `TransferToSelf` for a fee to the token. **K14** old line to `legacy/p3/`, no node change.
+**K15** prover ABI. **K16** deploy on dev chains. **K17** size. **K18** not built (PQZ batch hook, registry `chainUid`).
+**K19** disclosure carried over, the review's G2–G5 folded (HASH one slot, relayed HASH, `chainUid` in the challenge).
+
+**Not done / next:** P4 (`MandateWallet`, `SmartKeyAccount` on `MetaTxBase`); the disclosure review's answers (open
+questions in the plan); a real-passkey Zether envelope test; zether.md gas tables re-measured on the new kinds.
+
 ## Session 2026-10-11 (P2c)
 
-**State:** P2c on branch `p2c-dex`, merge pending the final review (code `dbf27a5`, tests `ae23be1`). Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`.
+**State:** P2c on branch `p2c-dex`, merged `d85fc8b` (code `dbf27a5`, tests `ae23be1`). Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`.
 949 forge tests.
 
 **Built:** the exchange path on `SCaaSDex` (`src/dex/SCaaSDex.sol`, `ISCaaSDex.sol` with `IExchangeExecutor`): `mtxExchange`
diff --git a/TODO.md b/TODO.md
index ad47067..8c075a6 100644
--- a/TODO.md
+++ b/TODO.md
@@ -14,8 +14,8 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 |---|---|---|
 | P0 | Spec and fold into the component docs and `decisions.md` | done |
 | P1 | The complete base on the new tree: `MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer; kinds `NONE`, `UNDERLYING`; factory `createToken`; the v1/v2 lines to the backup (v2 done in P1e, v1 renamed `…V1` until P3/P5) | MT-1, MT-2, MT-3, MT-4 |
-| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done on branch `p2c-dex`, merge pending the final review) | MT-5 |
-| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; delete `ZetherToken` | MT-6 |
+| P2 | **P2a** `TradeLib` token side + `mtxWrap` (done, merged `6a5c6b0`); **P2b-1** `SCaaSDex` as a clone, `createDex`, DEX registry, `mtxSettle` for SCaaS legs (done, merged `0510c7d`; old `SCaaSDex` kept as `SCaaSDexV1` for the node until P5); **P2b-2** outside legs (`DexOrder`, `DexPuller`, DEX-side cancels, ERC-1271 cap, bounded `MatchFailed`) (done, merged `7049c78`; `checkOrder` not built, H7); **P2c** exchange path `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly` (done, merged `d85fc8b`) | MT-5 |
+| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done on branch `p3-zether`, merge pending the final review) | MT-6 |
 | P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase` | MT-7 (+ rename in NM-*) |
 | P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |
 
@@ -35,7 +35,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 - P1c notes (from the P1b reviews, 2026-10-10): (a) the typed path's "cannot fail after step 3" and `mtxPayReceiverFee` step 5 hold only while `_update` refuses nothing beyond `to == this`: any P1c pause/freeze/feature refusal added to `_update` must be mirrored in `_checkTransfer` (and checked before the receiver-fee transfer); (b) `_chargeFee` re-derives the fee class from `_mtxRule`, so rules must stay constant per selector (hardened in P1b: an ABSOLUTE+FIXED fee is taken as is); (c) Multi `_mtxRule` falls back to `MetaTxBase._mtxRule`, so rules P1c adds in `ERC20MetaTx`/`MetaTokenBase` are dropped on Multi (moot after P1d; otherwise switch it to `MetaTokenBase._mtxRule`); (d) `HederaAccountAuth.sol:29` `asView` safety comment names `executeMetaTransaction` as the sole call site: there are now many non-view call sites (all `nonReentrant`, non-static frames), still safe; repoint the comment in P1c (HederaLib); (e) deferred test gaps still open: Task 3 — `FeePolicy.validateRecipient` is unreachable on both paths (the resolved recipient is never 0; delete or pin), no success-path test of a relayer-filled third-party `feeRecipient` on the typed path (only the `== to` refusal, `test/v2/Base.t.sol`); Task 4 — unwrap: no raw `ERC20InsufficientBalance`-from-`_burn` case when the reserve suffices, no dirty-address-word case; Task 5 — no SmartKeyAccount-clone (400k) payee test, no single-field tamper tests (`fee`/`feeRecipient`/`rfValidUntil`), no invalid-fee-nibble shape case, no RP4 assertions after a failed co-signature. Task 6's gaps were closed in the P1b final fix wave.
 - P1c notes dispositions (2026-10-10): (a) no `_update` refusal was added in P1c (flags 5–8 are refused at init, C2): carry to the asset-suite stream; (b) unchanged; (c) done in P1d (`UnderlyingToken._mtxRule` falls back to `super._mtxRule`); (d) done (`HederaLib`, `asView` comment repointed); (e) open test gaps stay as listed.
 - Asset-suite stream, from the P1c final review (C2): issuer and compliance must be contract-only when flags 5–8 are built; roles are keyed by flag bit and `_grant` requires the role's own bit, which cannot express FORCE = issuer + compliance or one issuer shared by FREEZE/FORCE/PAUSE, so the stream must key roles by role id (issuer, compliance) or map bits; and any `_update` refusal (freeze/pause/allowlist) must be mirrored in `_checkTransfer` and before the receiver-fee transfer.
-- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line is kept as `…V1` until P3/P5, see the backup items under P3 and P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
+- [~] **MT-1** (built through P1e: kinds on `TokenConfig`, `OpenFactory.createToken`; the v1 line is kept as `…V1` until P5 (the node's e2e deploys it), see the backup item under P5; owner: backup, not delete) Two bases: generic `MetaTxBase` (any SCaaS contract; `_chargeFee` refuses all but `NONE`, CTR-MTX-22) and
       the token base `ERC20MetaTx is MetaTxBase` (absorbs `MetaTxCore`) with `MetaTokenBase` on top; kinds `NONE` and
       `UNDERLYING` (the native-coin leg, CTR-TOK-26) with `AdminLib`, `UnderlyingLib`, `HederaLib`, `SigCheck` (CTR-TOK-21…24); factory
       `createToken` (CTR-TOK-25). Delete what token-tree spec §8 deletes: `ERC20MetaTx`(v1), `MetaToken`, `HederaMetaToken`,
@@ -48,36 +48,34 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
       all-or-nothing; `_msgSender()` everywhere per the `msg.sender` inventory; lint/test that no token reads
       `msg.sender` directly except the allowed spots; UA path split into `UAMetaTransaction`/`UAMetaTransfer` +
       `uaExecuteTransfer`/`uaBatchTransfer` (CTR-UA-26); KATs `metatx_kat.json`, `metatransfer_kat.json`, v3 pair.
-- [ ] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; open: v1 line (P3/P5, E1); `mtxWrap` for a SCaaS underlying done in P2a (UnderlyingToken; `ZetherToken` in P3).
-- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the other domains: SmartKeyAccount, MandateWallet P4, UA registry UA F1, Zether digests P3) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
+- [ ] **MT-3** `approve` only by contracts (caller and spender) — built in P1b on the v2 line; open: v1 line (P5, E1); `mtxWrap` for a SCaaS underlying done in P2a (UnderlyingToken), inherited by `UnderlyingZetherToken` (P3); the approve rule holds on both Zether kinds (tested in P3).
+- [~] **MT-4** (built in P1e for tokens and the token factory: both deploy scripts on CREATE2, gate on `chainUid()`; open for the other domains: SmartKeyAccount, MandateWallet P4, UA registry UA F1; Zether digests done in P3) `salt = chain_uid` in every domain (implementation immutables; SmartKeyAccount, MandateWallet, SCaaSDex,
       UA registry, Zether digests); deploy scripts on a CREATE2 deployer; deploy gate checks `chainUid()`.
 
 - UA ledger split (CTR-UA-26: `UAMetaTransaction`/`UAMetaTransfer`, `uaExecuteTransfer`/`uaBatchTransfer`) moved from P1b to UA F1 (R4).
 - P1e sizes: `UnderlyingToken` 26,449 B is over EIP-170 (24,576) until the size work (owner: optimise later; baseline in `size-baseline.json`); `UnderlyingLib` 10,096 B; `NoUnderlyingToken` 20,196 B; `OpenFactory` 6,715 B; the deploy scripts deploy only `NONE` for the new factory.
 - P1d follow-ups (parked test gaps, not fixed): no `mtxExecute(single-asset selector)` on a two-leg token test; native `UnderlyingTransferMismatch` untested; `addReserve` with native `msg.value > amount` untested; guardian revoke untested (these stay parked; the dead `META_MULTI` count branch is gone with factory v2: done in P1e).
 - P1d follow-ups (final review): (a) the native leg is absent from the `WrapperInvariant` handler: add a 4th leg (native, with a `vm.deal` forced coin) and a §12 conformance row for CTR-TOK-26; (b) the deploy scripts must deploy `UnderlyingToken` (it links `UnderlyingLib` and `AdminLib`) once it fits EIP-170.
-- P1e follow-ups (parked): (a) the size ratchet does not tighten itself: when a baselined contract shrinks, lower its entry in `smartcontracts/evm/size-baseline.json` by hand (the gate only notes an entry that now fits); (b) `smartcontracts/scripts/deploy.sh` requires `PRIVATE_KEY` (it derives `--sender` from it), so a KMS or hardware-wallet deployer needs a script change; (c) `OpenFactory` accepts the registration of kinds 2 and 3 (`*_ZETHER`) before P3: only the PQZ kinds 4–7 are `KindReserved`; (d) integrators: the factory's underlying index is only as truthful as the implementation, trust it for registered versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0; (e) libraries stay placed by forge from the sender's nonce, not by CREATE2 (E7); (f) the P1d parked test gaps above stay.
+- P1e follow-ups (parked): (a) the size ratchet does not tighten itself: when a baselined contract shrinks, lower its entry in `smartcontracts/evm/size-baseline.json` by hand (the gate only notes an entry that now fits); (b) `smartcontracts/scripts/deploy.sh` requires `PRIVATE_KEY` (it derives `--sender` from it), so a KMS or hardware-wallet deployer needs a script change; (c) done in P3: kinds 2 and 3 are built, their creation passes the Zether gate; only the PQZ kinds 4–7 are `KindReserved`; (d) integrators: the factory's underlying index is only as truthful as the implementation, trust it for registered versions (`versionOf(token).version != 0`); `createTokenUnregistered` records version 0; (e) libraries stay placed by forge from the sender's nonce, not by CREATE2 (E7); (f) the P1d parked test gaps above stay.
 
 **P2 — MT-5**
 - P2a (done, merged `6a5c6b0`): `TradeLib` (`scaas.trade`) and the trade entries on every token, `mtxWrap` + `NativeNotGasless` on `UnderlyingToken` (D1 closed; a native wrap by `mtxExecute(wrap(…))` still reverts `NativeValueMismatch(0, amount)`); 855 tests. Plan `docs/superpowers/plans/2026-10-11-p2a-trade-token-side.md`. Open for P2b/P2c: the DEX side below. **F4 (owner): `NoUnderlyingToken` is 22,951 B, over its 20,480 B budget (ratchet baseline), `UnderlyingToken` 29,974 B: owner — code size is not a concern, the product waits for the Glamsterdam fork (larger code limit); the ratchet baseline records sizes.**
 - P2b-1 (done, merged `0510c7d`): `SCaaSDex` clone (`scaas.dex`, salted domain `SCaaS Dex`; MT-4 domain done for the new DEX), `OpenFactory` DEX catalogue and `createDex`/`isDex`/`dexVersionOf`, deploy key `dex_implementation`, built DEX kept as `SCaaSDexV1`; 891 tests. Plan `docs/superpowers/plans/2026-10-11-p2b1-scaasdex-clone.md`. P2b-2 built them except `checkOrder` (see P2b-2). P2c built `mtxExchange`/`mtxExchangeVia`, `setExchangeTarget`, `setListedOnly`. `SCaaSDexV1` moves to `legacy/` at P5 (owner: backup, not delete).
 - P2b-2 (done, merged `7049c78`): outside legs (`DexOrder` in the DEX domain, `TradeLib` on the DEX's own `scaas.trade` state, `ESCROW` refused), `DexPuller` deployed by `initialize`, `mtxCancelOrders` / `mtxInvalidateNonces`, ERC-1271 cap by codehash (constructor takes the `SmartKeyAccount` implementation), `MatchFailed` reason capped at 256 bytes, `SigCheckGasStarved` reverts the whole `mtxSettle` (m8 closed), payouts by `SafeERC20`; 913 tests. Plan `docs/superpowers/plans/2026-10-11-p2b2-dex-outside-legs.md`. Open: `checkOrder` for the new DEX (not specified: dex.md §10 reads are the intake; with the node's P7 intake), the DEX invariant suite (§14). Size baseline raised by 9 B per token (`precheck` argument). Node P7: a batch reverting with `SigCheckGasStarved` is split and simulated per settlement, never retried whole with more gas (a party's `destination` that is a hook-token recipient can forge the selector; hook tokens are never listed). `mtxSettle` success is not monotonic in gas (a settlement can fail with an empty `MatchFailed` reason at a gas above a starved-revert window), so the node never trusts plain `eth_estimateGas`: it sizes gas from a simulation that requires every planned `ok[i]` true and reads an empty `MatchFailed` reason as out of gas (retry with more gas, never mark the order invalid). Limitation: no HIP-632 branch on DEX signatures, so a Hedera ED25519 account cannot sign a `DexOrder` or a DEX-side cancel (follow-up: `IS_HEDERA` in `SCaaSDex`).
-- P2c (done on branch `p2c-dex`, merge pending the final review): the exchange path on `SCaaSDex` — `mtxExchange` (interactions: never the DEX or the puller, never `mtxTrade`, data of at least 4 bytes), `mtxExchangeVia` (`IExchangeExecutor.exchangeCallback`), `setExchangeTarget` / `setListedOnly` and the `LISTED_POOLS` condition, `tokenKnown` (counted per listed market), the surplus to the signers by floor with the remainder to the last leg, `InsufficientOutput`, conservation over every snapshotted token, a pull check that refuses an inexact sell token, every `approve` interaction reset to 0, `increaseAllowance` and Permit2 `approve` refused (`ForbiddenSelector`, controller ruling, pending the owner); `ExchangeLegSettled`; 949 tests. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`. Open: the fork test with real Uniswap bytecode (dex.md section 14), the DEX invariant suite, the node's TradeEngine (NODE-DEX-17/18, P7).
+- P2c (done, merged `d85fc8b`): the exchange path on `SCaaSDex` — `mtxExchange` (interactions: never the DEX or the puller, never `mtxTrade`, data of at least 4 bytes), `mtxExchangeVia` (`IExchangeExecutor.exchangeCallback`), `setExchangeTarget` / `setListedOnly` and the `LISTED_POOLS` condition, `tokenKnown` (counted per listed market), the surplus to the signers by floor with the remainder to the last leg, `InsufficientOutput`, conservation over every snapshotted token, a pull check that refuses an inexact sell token, every `approve` interaction reset to 0, `increaseAllowance` and Permit2 `approve` refused (`ForbiddenSelector`, controller ruling, pending the owner); `ExchangeLegSettled`; 949 tests. Plan `docs/superpowers/plans/2026-10-11-p2c-dex-exchange-path.md`. Open: the fork test with real Uniswap bytecode (dex.md section 14), the DEX invariant suite, the node's TradeEngine (NODE-DEX-17/18, P7).
 - P2 notes (from P1c, P1d): (2) Named `mtxTransfer` is +9 execution gas over `mtxExecuteTransfer` (33,681 vs 33,672): the row is logged, not asserted; `mtxPay` on a fresh lane is +2.6 k (the `PAYABLE` gate's cold SLOAD, C3). (3) The asset suite's inline per-transfer admin check (CTR-TOK-24) also needs NONE bytes: it competes with the size debt in F4.
 - [x] Rename `OrderBookDex` → `SCaaSDex` (owner 2026-10-09; EIP-712 domain name `SCaaS Dex`); git mv + docs + node names. (done 2026-10-09)
-- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; P2b done (P2b-1, P2b-2); P2c done on branch `p2c-dex`; open: the invariant suite, the Uniswap fork test): `SCaaSDex.mtxSettle`
+- [~] **MT-5** DEX (P2a done: `TradeOrder` + `mtxTrade`/`mtxCancelOrder`/`mtxInvalidateNonces` in the tokens, `receiveToken == this` accepted, flag 4 not read by the token; P2b done (P2b-1, P2b-2); P2c done (merged `d85fc8b`); open: the invariant suite, the Uniswap fork test): `SCaaSDex.mtxSettle`
       (Path A/B, 1 taker + N makers, 50 % floor, fee split, conservation invariant); outside-token legs through the
       `DexPuller` (CTR-DEX-22); exchange path `mtxExchange`/`mtxExchangeVia` (CTR-DEX-20), surplus distribution
       (CTR-DEX-21), interaction blocklist + `LISTED_POOLS`/listed-only (CTR-DEX-23), admin `setExchangeTarget`/
       `setListedOnly` (CTR-DEX-03); tokens accept `receiveToken == this` and flag 4 (CTR-DEX-15).
 
 **P3 — MT-6**
-- [ ] v1 line to backup: when `ZetherToken`, `ZetherMetaTx`, `IZetherToken` and `LegacyMetaTransaction` move to the new base, `git mv` `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (with `MetaToken`/`HederaMetaToken`/`MetaTxDex` if P5 is done) to `smartcontracts/evm/legacy/` (E1; owner: backup, not delete), and drop them from the deploy scripts.
-- [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zero-knowledge.md CTR-PQZ-21): a batchable flag in `MtxRule` or a `_mtxBatchable(sel)` check in the loop.
-- [ ] **MT-6** Zether: transient envelope binding, `zetherShield` from the public balance (CTR-ZTH-45), `mtxWrap`; renames (`zetherRollOverSigned`,
-      `zetherSetRollOverMode`, CTR-ZTH-45; built: `rollOverSigned`, `setRollOverMode`); envelope binding without `to`/`value` (CTR-ZTH-06); `PqzToken` on the one base like Zether,
-      no `PqzMetaTx`, PQZ selectors not batchable (CTR-PQZ-21); prover `Header` gains `chain_uid` as word 3,
-      `HEADER_LEN` 384 → 416 (`clients/zether-prover/src/zether.rs`).
+- P3 (done on branch `p3-zether`, merge pending the final review): `NoUnderlyingZetherToken` / `UnderlyingZetherToken` (`ZetherLayer is MetaTokenBase`, logic in the external `ZetherLib`, `scaas.zether`), `ZetherStatements`, `zetherShield` from the public balance, `zetherWrapShield` / `zetherUnshieldUnwrap` on `UNDERLYING_ZETHER` (nothing minted), relaying through `mtxExecute` with the envelope binding in the transient ticket (`MetaTxBase._envelopeBinding`), `chainUid` in every token-side digest and the 416-byte header, the Zether gate on `OpenFactory`, `DeployBase` registers kinds 2–3 on dev chains, the prover on the new header and ABI; the built `ZetherToken`, `ZetherMetaTx`, old `IZetherToken` and their tests in `smartcontracts/evm/legacy/p3/`; 969 tests. Plan `docs/superpowers/plans/2026-10-11-p3-zether-kinds.md`. Open: a real-passkey envelope test (CTR-ZTH-21), re-measuring the zether.md gas tables on the new kinds, the registry's `chainUid` (UA F1), client ABI (P5); disclosure questions for the disclosure review (plan header).
+- [ ] v1 line to backup (P5): `OpenFactoryV1`, `IOpenFactoryV1`, `IFactoryTokenV1` (and `MetaToken`/`HederaMetaToken`/`MetaTxDex`) wait for the node and clientkeys (the e2e deploys them); the Zether part moved in P3 (E1; owner: backup, not delete).
+- [ ] `mtxBatch` needs a not-batchable hook for PQZ selectors (`MtxNotBatchable(selector)`, pq-zero-knowledge.md CTR-PQZ-21): with `PqzToken` (no PQZ selector exists yet; P3 left the room: the binding hook takes a PQZ tag).
+- [~] **MT-6** Zether (done in P3: transient envelope binding, `zetherShield` from the public balance, `mtxWrap` inherited, the `zether*` renames, binding without `to`/`value`, prover `Header.chain_uid`, `HEADER_LEN` 416; open: `PqzToken` on the one base, PQZ selectors not batchable, CTR-PQZ-21, with the PQZ stream).
 
 **P4 — MT-7**
 - [ ] **MT-7** `MandateWallet` and `SmartKeyAccount` (renamed from `SubjectAccount`, CTR-ACC-11) on `MetaTxBase` (CTR-ACC-06/07/10): delegate/owner calls as
```

- [ ] **Step 3: Run** `python3 scripts/test_docs_check.py`, `python3 scripts/docs_check.py check`, `python3
  scripts/docs_check.py facts check` → 0 errors, 0 misses (the `dex.md` and `token-wrappers.md` budget warnings predate
  this plan).
- [ ] **Step 4: Commit** `P3: docs, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh): rerun the probe (Task 6 Step 4) and probe beyond it — a relayed
  `zetherUnshieldUnwrap` on a native leg, a hook token as the leg of a relayed wrap-shield, a beneficiary equal to the
  sender, `M = 16` with the auditor out, a direct proof submitted inside `mtxBatch`, BLS through every relayed path; the
  disclosure review's answers (Open questions) folded or parked; one fix wave; scoped re-review.
- Merge `p3-zether` into `main` `--no-ff`; push; remove the worktree `.claude/worktrees/p3`.

