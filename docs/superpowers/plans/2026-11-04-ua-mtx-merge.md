# `ua*` / `mtx*` merge (one signed entry per operation, the base token size for public chains) — build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-04):** plan, not executed; its decisions MD-1 to MD-10 accepted by the owner 2026-11-04. **Owner 2026-11-04 (after T0): build M first** (A + B + C with the router's pairs, Q2, R17, R47: tasks T1-T8 with T3b, T10-T23 without a lever), then a checkpoint: gates, the whole-branch review (Claude, Fable, Codex) and the PR of M into `main`. **T9 (levers D / L) is not started: the owner decides it after M.** M alone fits a 200 M block, not 70 M for `WrappedToken` (72.37 M asked, T0), so no public chain deploy before that decision. Nothing is built from it; this commit writes no code, contract, test or vector. **Owner 2026-11-04 (after T1): Q6 changed:** the mandate wallets are built in this round in the merged form (task T3b, MD-11); T1 is built. **Owner 2026-11-05:** the six regulated kinds 8–13 are built in this branch as task group **T24–T36**, after T18 and before T19 ([spec](../specs/2026-11-05-regulated-kinds.md), revised after the Fable and Codex reviews; 19 agent-days); T19–T23 cover the group. **Owner 2026-11-06:** group **3e** (payment metadata, free pay lanes, tax on the regulated kinds) is built as **T37–T43** after T36 and before 3c ([spec](../specs/2026-11-05-pay-meta-tax.md), approved 2026-11-06; 14.5 agent-days plus 0.5 on T19, 15 in all); T19–T23 cover it. **Owner 2026-11-06:** group **3f** (attested proof verification, PQZ only) is built as **T44–T50** after T43 and before 3c ([spec](../specs/2026-11-06-attested-verify.md), approved 2026-11-06 after the Codex and Fable reviews and rulings R1–R4; 10 agent-days, T50 its docs share in T19); T19–T23 cover it. **Owner 2026-11-06:** group **3g** (versioned PQZ keys) is built as **T51–T57** after T50 and before 3c, with 3c's registry generation ([spec](../specs/2026-11-06-pqz-key-versions.md), approved 2026-11-06 after the Codex and Fable reviews and rulings R1–R5; 19.5 agent-days, T57 its docs share in T19, plus 1 on `ua-rs-sign`); T19–T23 cover it. **Owner 2026-11-07:** group **3h** (the PQZ proof path, contract side: the debit record, `ownTag` and the key-version tail, `proofStore` `NONE` / `LOG` (SSTORE2 dropped by the owner, kept in the spec's Appendix A), bit 24 `PQZ_PROOF`, the integration gate) is built as **T58–T66** after T57 and before 3c ([spec](../specs/2026-11-06-pqz-proof-path.md), from the owner-agreed design of research `pqz-leg-proof-option.md` §15A, revised after the Codex and Fable reviews and the owner's decisions O9–O13, **approved 2026-11-07**; 19 agent-days, T66 its docs share in T19; the client side, 14–16.5 agent-days, goes to the no-oracle spec on `ua-rs-sign`). Totals of the added groups: T24–T36 19, T37–T43 with T19's share 15, T44–T50 10, T51–T57 19.5, together 63.5 agent-days; with 3h 82.5.

**Spec:** [`2026-11-04-ua-mtx-merge.md`](../specs/2026-11-04-ua-mtx-merge.md), **accepted by the owner 2026-11-04** (Q1–Q7, §10);
rules R1–R47 (§5), invariants 1–7 (§8), measurement (§9). **Ruling:** [CTR-MTX-30](../../decisions.md#CTR-MTX-30), its Q6 Change, and the Change
lines it points to (CTR-MTX-09, CTR-MTX-29, CTR-TOK-24, CTR-UA-19, CTR-DEX-25, CTR-ACC-12, CTR-UA-27). Spike: `docs/research/governance/prototype/merge-entries.md`
(branch `token-merge`, reference code only, **never merged**).

**Owner words, at the top:**

| Item | State |
|---|---|
| Q1: A + B + C and the reversals R1, R9, R12, R47 | Accepted 2026-11-04. |
| Q2: the signed cancel | Ruled: the ordered `mtxCancelNonce(UAEnvelope e, uint256 lane, UASig auth)` on tokens and the router. |
| Q3: the size levers | Target ruled (60 M and 70 M as deploy gas, total × 1.05); **the final lever choice is the owner's, after T0's report. T9 waits for it**; T1–T8 do not. |
| Q4: the public-chain deploy gate | Ruled: measured regular + state × 1.05 of the release transaction, regular × 1.05 < 2^24; the SCaaS testnet keeps `runtime × 1,530 + 2^24`. T10. |
| Q5: real-wallet display test | Ruled: before reset 2, two browser wallets and one hardware wallet. T20, owner-assisted. |
| Q6: CTR-ACC-12 | **Changed 2026-11-04, after T1.** Old: deferred, the wallets stay address-only and byte-identical. New: `MandateWallet` and `HederaMandateWallet` are built now in the merged form, one `mtx<Op>(UAEnvelope, …, UASig)` per operation, a native signer without a registry, a derived UA through `requireAuthorized`, the address bodies to legacy; CTR-ACC-12's twins are not built; `SmartKeyAccount` stays address-only and byte-identical. T3b, MD-11. |
| Q7: node doors | Ruled: the gateway's token doors (T15) and the mesh's `evm.ua_meta_tx` (T16) are built in this round. |
| One PR | Owner: the spec, CTR-MTX-30 and this plan land in the same PR as the build (T23). |
| Merge, push | The owner's word only. `main` is PR-only. |

**Goal:** on EVM, one subject-signed relayed entry per operation on the six token kinds, `MtxRelayFee`, the DEX's SCaaS legs,
`GovernanceRouter`, the mandate wallets (Q6: the address bodies widened to `bytes32`, T3b) and Hedera (the `ua<Op>` body under
the `mtx<Op>` name; the cancel per Q2); an EOA relays with no registry
call and, on `NORMAL` / `WRAPPED`, with no registry at all; the address bodies in `legacy/ua-mtx-merge/`; vectors, clients and
node move at once; the gateway doors and the mesh body built; the base token size measured and the owner's lever set built;
docs rewritten and CTR-MTX-30 BUILT.

**Architecture:** one branch `ua-mtx-merge` (worktree `.claude/worktrees/ua-mtx-merge`, HEAD `5476c76d` at this plan's parent).
T0 measures on a scratch branch from `main` and reports. Contracts then in this worktree, **sequentially** (T1–T9 share
`MtxPipelineLib`, `ERC20MetaTx`, `MetaTxLib`, the helpers and `size-baseline.json`); every task ends with the whole forge suite
green at the default set. Clients, node and docs beside each other after the ABI is final (T7). Gates (T21), review (T22),
report and PR (T23).

**Tech stack:** Solidity / Foundry 1.8.5, solc 0.8.37, Amsterdam, optimizer 200, `via_ir = false`; Rust `scaas-node` (alloy 1.6,
rustc 1.90); Node `node --test` (`clients/clientkeys`); `zether-prover`; `ua-rs` and its wrappers `ua-c`, `ua-cxx`, `ua-qt`,
`ua-dart-frb`; native `ua-py`, `ua-go`, `ua-cs`, `ua-dart`; Python 3 (`docs_check`, `size_gate`).

**Gate runner:** `smartcontracts/evm/runs/<date>-ua-mtx-merge-gates.sh [--only <step>]`, written in T21 on the step contract of
`2026-10-27-metatx-split-gates.sh` (per-step logs, resume, `named-tests`, summary). Logs `runs/<date>-ua-mtx-merge-<step>.log`
(git-ignored); `<date>-ua-mtx-merge-summary.txt` committed (`step | commit | rc | counts`, no absolute paths).

## Global constraints

- Owner rulings override code; a difference between code and CTR-MTX-30 or the accepted spec is a bug in the code. Follow a
  stated rule as stated; no added assumptions, no option tables. A controller row of the spec stands unless the owner overrides it.
- **Explicit parameters:** named, typed parameters; `UAEnvelope` first, `UASig auth` last; one entry per operation; no packed
  `bytes` but a proof, a ciphertext, a key, a signature. R47 removes the last packed `bytes auth` from the token side.
- **Every state-changing `mtx*` is relayable** at fee 0 (fee mode `NONE`), with and without a registry for a native subject,
  except the entries invariant 4 lists (§8).
- **No EIP-7702.** No gas price 0, no block limit of ours in code. **One rule on every chain:** no non-EVM contract changes here.
- **Never lose ciphertext.** No operation body changes; every PQZ and Zether ciphertext stays in contract state.
- **Zether ≠ PQZ.** Separate tasks (T4, T5), separate tests, separate binding tags, separate commits. NEAR ≠ Algorand (not touched).
- **Nothing deployed is upgraded; backup, do not delete.** Every superseded body, typehash, struct, builder, row and handler is
  copied to its area's `legacy/ua-mtx-merge/` before it leaves the build (MD-4). Never drop an API because nothing calls it.
- **Pins move only with old → new in the commit message:** typehashes (`*TypehashIsPinned`), storage layout (`test/v2/layout/`:
  must not move at all, spec §1), `MsgSenderLint` counts, gas pins, `size-baseline.json` (reason in `_comment`), KATs by their
  generators, `selector_audit.json` by reading. Never edit a pin, a bound or a test to go green.
- **Red first:** every new or changed behaviour has a test that fails before the change, its positive control first.
  **Mutants:** one change at a time on a clean tree, its suite run, restored by `git checkout -- <file>`; logged as
  `runs/<date>-ua-mtx-merge-t<n>-mutants.txt`, one row `mutant | test that went red | rc`. A mutant no test catches is a finding.
- **Same class everywhere:** a fix to a signature, digest or binding path is checked on every kind (Zether and PQZ apart), the
  router, Hedera, the node and every client that reproduces the digest.
- **Byte formats change everywhere at once** (contracts, `clientkeys`, `zether-prover`, node, vectors). Vectors only from their
  generators; a digest reproduced in a client is tested with a non-zero unbound `relayer` / `feeRecipient` (spec §6).
- **The node is open:** guarantees in the node and `docs/node/`; allow-lists equal to the contract's per kind, both directions.
- **Machine:** heavy commands through `scripts/capped`, foreground, never inside `timeout`; cargo `-j2`; the whole node suite
  `CAPPED_MEM=6G` alone; `dotnet build-server shutdown` after capped dotnet; at most 3 agents, 2 heavy at once, no two gate runs
  at once. `at-set.sh` rewrites `src/pqz/PqzSet.sol`: one run per work tree, restored. No `nohup`, `&`, `until`, `sleep`
  loops, `pgrep -f`, `git stash`, `git add -f`. No timing or gas calibration (forge gas is deterministic and needs no go). No full
  `pqz-core/gate.sh`: no `pqzl`, `pqzh`, `stmt`, `ffi` file moves; if R41 moves a set parameter, stop and ask.
- **Never touch the live testnet stack,** its containers or RPC port; e2e runs on local anvil. 22776 is the owner's.
- **Git:** commit per task on `ua-mtx-merge`, staged by explicit path, `ua-mtx-merge T<n>: …`, ending with the session's
  `Co-Authored-By` trailer; `Signed-off-by` per CONTRIBUTING; new source files carry `SPDX-License-Identifier:
  LicenseRef-Vegan-Community-1.0`. No merge, no push. English only; no consumer names; full output in `.log`, committed summaries
  only, no absolute paths.

## Plan decisions (MD-*; controller calls, owner may override; recorded in `decisions.md` by T19)

**Owner 2026-11-04: MD-1 to MD-10 accepted as written; MD-11 (after Q6's change) is a controller call, open to the owner.** ("theo khuyên"), including MD-10 (the mesh refuses a derived `from` by name until a ruling on how a peer checks a derived `UASig`) and MD-5 (the cancel's signed purpose moves to the named-op purpose).

- **MD-1 Where `executeMetaTransaction` lives.** Spec §2.5 keeps it in the `MetaTxBase` core "on tokens"; R26 puts "the address
  generic path (wallets, and `executeMetaTransaction` on tokens per R3)" in `MetaTxAddressBase`. If tokens inherited
  `MetaTxAddressBase` they would get the address `mtxExecute` / `mtxBatch` back beside the merged ones. So: `executeMetaTransaction`,
  its `_execute` and the address pipeline stay in `MetaTxBase` (tokens, router, wallets); `MetaTxAddressBase` holds only
  `mtxNonce(address,uint256)`, `mtxDigest(MetaTransaction)`, `mtxExecute(MetaTransaction,bytes)`, `mtxBatch(MetaTransaction[],bytes[])`,
  `mtxCancelNonce(Envelope,uint256,bytes)`, inherited by `WalletExecute` only. T19 writes R26's text this way.
- **MD-2 T0's M is the build's shape:** the spike's A + B + C ported, plus Q2's ordered cancel, R47's `UASig` on the generic
  entries and R17's empty-field check, so the size the owner rules Q3 on is the one T1–T8 build.
- **MD-3 Every task ends green.** An entry not yet merged keeps its old form and its tests until its task. Each test whose
  meaning reverses (a native at `registry() == 0`, a native signed cancel, a native off the UA list, an address event that
  becomes `UA…`) is edited by hand and listed in its commit as `meaning: <test> old → new`; never repaired by script.
- **MD-4 Legacy places.** Copies as they stand at local tag `ref/pre-ua-mtx-merge` (the commit T1 starts from, never pushed):
  `smartcontracts/evm/legacy/ua-mtx-merge/` (Solidity, one line in `legacy/README.md`), `smartcontracts/evm/test/vectors/legacy/ua-mtx-merge/`,
  `smartcontracts/vectors/typed/legacy/ua-mtx-merge/`, `scaas-node/legacy/ua-mtx-merge/`, `clients/clientkeys/legacy/ua-mtx-merge/`,
  `clients/zether-prover/legacy/ua-mtx-merge/`. Checked not git-ignored at this plan's commit.
- **MD-5 The merged cancel's purpose** is the one `MtxPipelineLib.preNamedUA` uses for every named op (spec §2.1: "run through
  `preNamedUA` like every named op"). `UAKinds.PURPOSE_METATX_CANCEL` stays declared, used by the legacy body only; derived
  signers of a cancel move to the named purpose (T11 rows, operator note).
- **MD-6 `MsgSenderLint` covers every merged body.** Its `FILES` (18 today) lacks `src/pqz/PqzLayer.sol`, `NormalPqzToken.sol`,
  `WrappedPqzToken.sol`, `PqzWrappedLib.sol`, `src/zether/ZetherWrappedLib.sol`, `src/metatx/MtxRelayFee.sol`, `src/dex/SCaaSDex.sol`.
  T1 adds them with their counts at the base (the pin red first with a wrong count, then the measured one); each later task
  moves its counts with old → new (R24).
- **MD-7 `typed_ops.json`'s retire rule:** an address row retires when no kind in its `on` keeps its entry. Measured at
  `5476c76d`: 112 rows (68 address, 44 `UA*`). Retire 45: `Burn`, `Unwrap`, `UnwrapLeg`, `UnwrapToUA`, `Shield`, `RollOver`,
  `PrepareAcc`, the six `Pqz*` entry rows, the five `Zether*` entry rows, `RollOverSigned`, `SetRollOverMode`, `RollOverBatch`,
  `ReceiverFee`, `RelayFee`, `WrapOrder`, `CancelOrder`, `CancelWrapOrder` and the 19 router rows. `CancelNonce` stays, its
  `on` narrowed to `MandateWallet`, `SmartKeyAccount` (**Q6, 2026-11-04:** to `SmartKeyAccount` only; the six `MandateWallet`
  address rows `SetMandate`, `SetPayee`, `RevokeMandate`, `PayUnderMandate`, `DelegateRevoke`, `Execute` retire too, and the six
  `UA<Op>` rows of T3b are added, the only added rows; `UACancelNonce`'s `on` gains `MandateWallet`). Unchanged: the account rows, `Wrap`, `WrapLeg`, `AddReserve`,
  `WrapToUA`, `WrapShield`, `CancelUAOrder`, `CancelUAWrapOrder`, `CancelDexOrder`, and the statement rows `ZetherRollOver`,
  `ZetherSetRollOverMode`, `PqzAuth` (no entry pair). `UACancelNonce` changes its type string (Q2); no row is added.
- **MD-8 `dex_order_kat.json` regenerates in every task that moves token or DEX bytecode** (`WRITE_KAT=true` of `DexKatTest`), so
  every task ends green; review check: only clone addresses, domains, signatures and the leg shape move.
- **MD-9 The `bytes32` id display has one vector file:** `smartcontracts/vectors/ua/id_display.json`, written by a `clientkeys`
  script (padded id → checksummed address, derived id → its URN per NET-ALL-21, invalid ids refused), read by every `ua-*`.
- **MD-10 Mesh, derived subjects.** R45 / Q7 make the EVM token body the UA structs but do not say how a peer checks a derived
  subject's `UASig` (today's `sig_kind`s are `eoa`, `erc1271`, `hedera_ed25519`, all local). T16 builds native subjects over the
  UA digest with today's `sig_kind`s; a derived `from` is refused by a named code until the controller rules (open item 2).
- **MD-11 The mandate wallets' merged form** (Q6 changed by the owner 2026-11-04, after T1; controller calls, the owner may
  override). Q6 fixes the entries, the signers, the legacy move and `SmartKeyAccount`; five points it leaves open:
  - **(a) The flat builders go to legacy.** `mtxPayUnderMandate(token, payee, amount, entryRef, epoch, validUntil, sig)`,
    `mtxRevoke`, `mtxExecuteAsOwner` and Hedera's `mtxExecuteAsOwnerRaw` sign an address `MetaTransaction` for an operation
    that has its named entry (`mtxPayUnderMandate(UAEnvelope, …)`, `mtxDelegateRevoke`, the generic `mtxExecute`), so under
    "exactly one signed entry" they are second entries. `mandate_pay_kat.json` and `mandate_revoke_kat.json` go with them.
    This reverses the owner's 2026-11-01 keep (CTR-ACC-05's 2026-11-02 Change) by the later ruling; **owner confirmed
    2026-11-05**. The auto-pay path (mandates.md §1.1) moves to the named UA entries (T14, T19).
  - **(b) `executeMetaTransaction` refuses** on the mandate wallets (`MtxSelectorNotAllowed`, an `_execute` override as in
    `GovernanceRouterBase`): the EIP-1776 alias is the token's exception (R3, NET-ALL-28); kept, it would be an address
    signed path to every wallet operation.
  - **(c) Base and constructor.** `MandateWallet is UAMetaTxBase, IERC1271` (no longer `WalletExecute`); constructor
    CTR-ACC-12's `(bytes32 owner, bytes32 chainUid, address registry)` plus `bool hedera_` (`HederaMandateWallet` passes
    `true`); `UAMetaTxBase` gets `smartKeyAccountImpl_ = address(0)`, so every contract signer keeps today's 50 k ERC-1271 gas.
  - **(d) Allow-lists.** `_mtxRule` and `_uaAllowed` both list the six wallet operations (`payUnderMandate`,
    `revoke(address,uint64)`, `setMandate`, `setPayee`, `revoke(address)`, `execute`); `cancelNonce` stays on `_mtxRule` only.
  - **(e) Names, events, errors.** Structs `UA<Op>` (spec §2.3); `MandateSet`, `MandateRevoked`, `PayeeSet`,
    `PaidUnderMandate` and `PayeeNotAllowed` take `bytes32` ids: one shape per path (R18's reason).

## Recount at `5476c76d` (spec §7 asks for it at the build; T0 replaces it on the merged tree)

| Area | Count, by grep at this plan's parent |
|---|---|
| `smartcontracts/evm/src` | 35 of 108 `.sol` files name a merged form. Pairs by file: `ERC20MetaTx` 7 (`ExecuteTransfer`, `BatchTransfer`, `Trade`, `CancelOrder`, `InvalidateNonces`, `Digest`, `TransferDigest`) + views `uaMinNonce`, `uaTradeOrderDigest`, `uaInvalidateNoncesDigest`, `uaCancelDigest`; `MetaTokenBase` 6 (`Transfer`, `TransferWithFee`, `Pay`, `PayMeta`, `PayReceiverFee`, `RelayFee`) + `uaReceiverFeeDigest`; `UAMetaTxBase` / `MetaTxBase` 5 (`Execute`, `Batch`, `Nonce`, `Digest`, `CancelNonce`); `NormalToken` 1 (`Burn`); `WrappedToken` 4 (`Unwrap`, `UnwrapLeg`, `UnwrapToUA`, `WrapOrder`) and 4 no-twin; `MtxRelayFee` 1 (`relay` / `uaRelay`); `ZetherLayer` 9 + `uaEnvelopeBinding`, `WrappedZetherToken` 1 (`UnshieldUnwrap`); `PqzLayer` 8 + `uaEnvelopeBinding`, `WrappedPqzToken` 1; router 19 (`GovernanceRouterBase` 9, `GovernanceRouter` 10) plus its two generic overrides. Typehash constants in 20 files |
| `smartcontracts/evm/test` | 85 of 200 `.sol` files name a merged form directly, 6 of them helpers (`V2Fixture`, `DexLegs`, `MtxFixture`, `UALedgerBase`, `OrderJson`, `ERC20MetaTxHarness`): `v2` 21, `metatx` 20, `ua` 14, `zether` 9, `pqz` 6, `governance` 5, `helpers` 3, `wallet` 2, `hedera` 2, `account` 2, `research` 1. 19 assert an address event; 33 name `TradeOrder`, `mtxTrade` or `uaTrade` |
| `smartcontracts/evm/script` | `ZetherE2E.s.sol`, `pqz/e2e.py`, `pqz/test_e2e_linked.py`; plus `DeployBase.sol` (router, `MtxRelayFee` CREATE2, release gate) |
| `scaas-node` | EVM: `src/{abi,chain,adapter,dex,gateway,guard,indexer,main,metatx,submit,typed}.rs`, `src/dex/venue.rs`, `src/adapters/hedera.rs`, `src/mesh/{digest,accept}.rs`, the legacy pull path's job decoder (the module `main.rs` marks as the legacy pull path), `node.example.toml`; tests `e2e.rs`, `e2e_hedera.rs`, `mesh_vectors.rs` (+ `tests/vectors/mesh-envelope-v1.2.json`). Non-EVM adapters hit only on their own `MetaTransfer` (R30: unchanged). `typed.rs` `TYPED`: 114 rows (38 `gov_router`, 63 on token kinds) |
| `clients` | `clientkeys` 9 files (`src/evm.js`, `scripts/{typed-ops-vectors,typed-ops-expected,ua-sig-vectors}.mjs`, `test/{evm,paymeta,relayfee,typed-ops}.test.js`, plus `ua-trade`, `ua-metatx3`, `ua-sig`, `pq-sig` tests by vector); `zether-prover` 6 (`src/{api,envelope,typed,zether}.rs`, `tests/{recover,zether_proofs}.rs`, plus `tests/{typed_ops,envelope_disclosure}.rs`). No `ua-*` holds an entry form; none renders a `bytes32` id (only `clientkeys/src/soroban.js` renders the URN) |
| Vectors | `smartcontracts/evm/test/vectors/`: `metatransfer_kat.json`, `metatx_kat.json` (`TokenKat.t`, `WRITE_KAT`), `trade_kat.json` (`TradeKat.t`), `dex_order_kat.json` (`DexKat.t`), `hedera_kat.json` (`gen_hedera_kat.py`), `metatx-parity.json` (`MetaTxParity.t`, `PARITY_WRITE`), `plus_zero_slots.json` (`PlusZero.t`), `selector_audit.json` (by reading). `smartcontracts/vectors/`: `typed/typed_ops.json` (`typed-ops-vectors.mjs`), `ua/metatx3.json`, `ua/uatrade_kat.json` (`ua-sig-vectors.mjs`), `governance/governance_bits.json` (only if a bit moves: none expected). Unchanged: `metatx/paymeta.json`, `metatx/relayref.json` |
| Docs | 37 current docs name a form; the EVM ones change (spec §7 Docs row); the non-EVM network docs only where they cite the EVM struct (R30) |

## Review focus (every task review reads these)

1. No forgery (invariant 1): a native id by its own key with no registry call; a derived id through `requireAuthorized`; a
   designator by its own key only; `UAKinds.inNativeSpace` the one dispatch.
2. The canonical signed intent (invariant 2): every operation and bound field signed; `relayer` / `feeRecipient` 0 unless bound;
   R17 refuses a native `UASig` with `keyData` or `members`.
3. Replay (invariant 3): the retired forms have no entry; `MetaTransaction` runs only through `executeMetaTransaction` with the
   address proof binding; the wraps' `Envelope` structs still run; the cancel is nonce-ordered.
4. No derived subject reaches `_mtxRule`; inside the self-call a derived subject is `UA_POOL`, a native one its address.
5. Fee 0 relayable on every merged entry and kind, with and without a registry for a native (invariant 4's list excepted).
6. `UA…` events only on merged paths (R18); address events stay on address entries.
7. A library edit (Zether, and L if taken) passes the split checklist: DELEGATECALL storage, `this`, `msg.sender`, return data,
   the guard, `LinkClosure` pins.
8. Allow-lists equal in both directions: `_uaAllowed` / `_mtxRule` / `mtxSelectors()` ↔ `typed.rs` / `guard.rs` ↔ `selector_audit.json`.
9. Lever D, if taken: invariant 7 in full.

---

## File structure

| Path | Responsibility |
|---|---|
| `smartcontracts/evm/src/common/MetaTxLib.sol` | `UACancelNonce` new type string; `MetaTransfer` and the address named-op typehashes of merged ops to legacy |
| `smartcontracts/evm/src/metatx/{MetaTxBase,UAMetaTxBase,MtxPipelineLib,IMetaTx,IUALedger}.sol`, new `MetaTxAddressBase.sol`, `IMetaTxAddress.sol`, `IUALedgerViews.sol` | the split, the merged generic path, B, C, R17, the cancel |
| `smartcontracts/evm/src/metatx/{ERC20MetaTx,MetaTokenBase,MtxRelayFee,IERC20MetaTx,IERC20Payment,IMetaTokenV2}.sol` | the transfer group, payments, relay fee |
| `smartcontracts/evm/src/metatx/{NormalToken,WrappedToken,WrappedLib,IWrappedToken}.sol` | burn, unwraps, wrap order |
| `smartcontracts/evm/src/zether/{ZetherLayer,ZetherLib,ZetherWrappedLib,NormalZetherToken,WrappedZetherToken,IZetherToken}.sol` | Zether pairs, R35 |
| `smartcontracts/evm/src/pqz/{PqzLayer,PqzCore,PqzWrappedLib,NormalPqzToken,WrappedPqzToken,IPqzToken}.sol`, `src/confidential/IConfidentialToken.sol` | PQZ pairs, R36 |
| `smartcontracts/evm/src/{trade/TradeLib,trade/ITradeToken,dex/SCaaSDex,dex/ISCaaSDex,dex/DexPuller}.sol` | DEX legs, R12, R37, R38 |
| `smartcontracts/evm/src/governance/{GovernanceRouterBase,GovernanceRouter,IGovernanceRouter}.sol` | the router's 19 pairs, its cancel |
| `smartcontracts/evm/src/hedera/{HederaAccountAuth,HederaLib}.sol` | HIP-632 entry names, R42 |
| `smartcontracts/evm/src/wallet/MandateWallet.sol`, `src/hedera/HederaMandateWallet.sol` | the mandate wallets in the merged form (Q6, T3b) |
| `smartcontracts/evm/legacy/ua-mtx-merge/` | every superseded body (MD-4) |
| `smartcontracts/evm/test/merge/` | the spike's suite, ported and extended: invariants 1–7 |
| `smartcontracts/evm/script/{DeployBase.sol,ZetherE2E.s.sol,pqz/e2e.py}`, `scripts/e2e-zether.sh`, `smartcontracts/scripts/deploy.sh` | deploy, Q4 gate, e2e |
| `smartcontracts/evm/runs/<date>-ua-mtx-merge/` | T0 harness and results (git-tracked); `<date>-ua-mtx-merge-gates.sh`, summary |
| `clients/clientkeys/{src/evm.js,scripts/*.mjs,test/*.test.js}`, `clients/zether-prover/src/*.rs`, every `ua-*` | builders, binding, renderer |
| `scaas-node/src/…`, `scaas-node/tests/…` | rows, guard, jobs, gateway, mesh, DEX, Hedera, e2e |
| `docs/…` | T19 |

## Setup (before T0)

- [ ] `git -C .claude/worktrees/ua-mtx-merge status` clean at this plan's commit. Local tag `ref/pre-ua-mtx-merge-plan`, never pushed.
- [ ] `smartcontracts/evm/lib`, `clients/clientkeys/node_modules`, `smartcontracts/algorand/out` as real directories
      (`scripts/evm_libs.sh install`, `check`).
- [ ] **Wait for the SCaaS testnet reset 1 to finish** (the machine is busy with it). Nothing heavy runs before.
- [ ] Baseline, recorded in `runs/<date>-ua-mtx-merge-base-summary.txt`: `cd smartcontracts/evm && ../../scripts/capped forge test`
      (expected green, or the failures named in the merged PR #13 summary); `size_gate.py` 0 errors. Any other failure stops the plan.

## Order (≤ 3 agents, ≤ 2 heavy at once)

| Stage | Tasks | How |
|---|---|---|
| Measure | T0 | after reset 1; report to the owner (Q3) |
| Contracts | T1 → T2 → T3 → T3b → T4 → T5 → T6 → T7 → T8 | sequential, one worktree: same files, helpers, ratchet |
| Lever | T9 | after T8 **and** the owner's Q3 answer |
| Deploy | T10 | after T9 |
| Clients | T11 → T12; T11 → T13 | from T7 (ABI final; L and D change no ABI); **beside T8–T10**, `clients/` and `smartcontracts/vectors/` only; their forge cross-checks re-run after T10 |
| Node | T14 → {T15 ∥ T16 ∥ T17} → T18 | T14 after T11; T15, T16, T17 beside each other (disjoint files); T18 after T10 and T15–T17 |
| Wallets | T20 | after T11, owner-assisted, beside T14–T19; before reset 2 |
| Regulated | T24 → T25 → T26 → T27 → T28 → T29 → T30 → T31 → T32 → T33; T34 beside T33; T35 after T33, T34; T36 after T33, beside T34–T35 | after T18, before T19 (owner 2026-11-05); contracts sequential in this worktree; T27 measures kinds 9 and 13 before T28 fills the bodies |
| Pay meta, tax (3e) | T37 → T38 → T39 → T40; T41 after T40; T42 after T41; T43 after T40, beside T41–T42 | after T36, before 3c (owner 2026-11-06); contracts sequential in this worktree; T37 and T40 measure kind 13 first |
| Attested PQZ (3f) | T44 → T45; T46 after T45; T47 after T46; T48 and T49 after T45, beside T46–T47; T50 beside, lands in T19 | after T43, before 3c (owner 2026-11-06); contracts sequential in this worktree; T45 measures kind 13 first |
| Versioned PQZ keys (3g) | T51 → T52 → T53; T54 after T53; T55 after T54; T56 after T53, beside T54–T55; T57 beside, lands in T19 | after T50, before 3c (owner 2026-11-06); contracts sequential in this worktree; T51 measures the registry's deploy gas, T52 measures kind 13 first; 3c's rebalance comes after T53 |
| PQZ proof path (3h) | T58 → T59 → T60 → T61; T62 after T61; T63 after T62; T64 and T65 after T61, beside T62–T63; T66 beside, lands in T19 | after T57, before 3c (owner approved 2026-11-07); contracts sequential in this worktree; T58 measures kind 13 first; each format moves in the task that changes it; no task waits for `ua-rs-sign` |
| Docs | T19 | drafts beside T14–T18, T24–T36, T37–T43, T44–T50, T51–T57 and T58–T66; lands after T66 and 3c (BUILT only with code and tests) |
| Close | T21 → T22 → T23 | |
| Next | TODO item 4 | SCaaS testnet reset 2 deploys the merged code (not this plan) |

---

### Task T0: measurement (spec §9)

**Depends on:** reset 1 finished; this plan. **Runs on:** scratch branch `ua-mtx-merge-t0` from `main` (`main` holds PR #9, #12,
#13), worktree `.claude/worktrees/ua-mtx-merge-t0`; harness and results committed on `ua-mtx-merge`. The scratch code is kept as a
local branch, never merged (spec Q13).

**Files:**
- Create: `smartcontracts/evm/runs/<date>-ua-mtx-merge/` with `merge_pairs.py`, `no_twin.py`, `lever3_delete.py`, `mutants.py`,
  `red_skip.py` (ported from `token-merge:docs/research/governance/prototype/merge-harness/`; `no_twin.py` ported, not run: A2 is
  out of scope, §4), `lib_split.py` (lever L), `deploy_gas.sh`, `README.md` (how to run), `sizes-<run>.json` summaries,
  `results.txt` (the dated table); `smartcontracts/evm/test/merge/MergedEntry.t.sol` (from `token-merge`, on the scratch).
- Modify (on `ua-mtx-merge`, after the run): the spec's §9 (a dated results table) and the research note's re-measure line.

**Interfaces:** the runs below; no ABI.

- [ ] **Step 1: Scratch and harness.** `git worktree add -b ua-mtx-merge-t0 .claude/worktrees/ua-mtx-merge-t0 main`, real `lib/`.
      Port the five scripts: their regexes move to today's names (`ZetherLib` / `ZetherWrappedLib` hold the Zether bodies since
      CTR-ZTH-94; the router's pairs are new). Each script prints what it changed; a pattern that matches nothing fails.
- [ ] **Step 2: M (MD-2).** `merge_pairs.py`, then by hand the spike's B (`2094aa70`) and C (`5d068cce`) on today's code, Q2's
      ordered cancel, R47, R17. Commit per lever on the scratch. `FOUNDRY_TEST=test/merge ../../scripts/capped forge test -vv`: green;
      the spike's eight mutants red as `merge-entries.md` §4 lists.
- [ ] **Step 3: L.** `lib_split.py` moves the `ERC20MetaTx` and `UAMetaTxBase` bodies into a linked library on the `ZetherLib`
      pattern (decoders and ABI stay on the token). `LinkClosure.t` green; the library's own size and deploy gas recorded.
- [ ] **Step 4: D.** `lever3_delete.py` (views by deletion, as the spike: no module built), on M and on M + L.
- [ ] **Step 5: Regulated stand-in.** On `NormalToken` and `WrappedToken`, a scratch copy with the six regulated entries and the
      hook in `_update` and `_uaMove`; measured, **not committed** (spec §9 step 2).
- [ ] **Step 6: Sizes**, `forge build src --sizes --json`, default set: every kind, `SCaaSDex`, `GovernanceRouter`, `MtxRelayFee`,
      `MtxPipelineLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzWrappedLib`, the L library, the wallets, for base, M,
      M + L (L alone first), M + D, M + L + D, and each stand-in. Wallet bytecode hashes equal to base.
- [ ] **Step 7: Deploy gas** by `GovDeploy.t.sol` `test_releaseGasPerKind`'s method ((regular × 64/63 + state) × 1.05) per
      implementation and library, each its own transaction, plus `deployImplementation`'s frame measured once on the factory path;
      reported as gas asked against 60 M and 70 M (EIP-8037: regular + state ≤ the limit, never `gas_used`), and regular × 1.05
      against 2^24.
- [ ] **Step 8: Gas** (forge, deterministic): `GovGas` rows on `NormalToken` and `WrappedToken` at `registry() == 0` and `≠ 0`;
      `MetaTxGasV2`; `PlusZero` slots on every kind; EOA → EOA and EOA → UA `mtxTransfer` per kind; the merged `mtxCancelNonce`;
      generic `mtxExecute`; `mtxPayReceiverFee`; `mtxTrade` through the DEX; one relayed Zether op; one relayed PQZ op.
- [ ] **Step 9: PQZ set parameters (R41)** at all four sets, `script/pqz/at-set.sh <set> test --match-path test/pqz/PqzStateGas.t.sol`
      on the merged `mtxExecute`: `test_gas_rollMax_relayedFullTx`, the rollscan, the `debit_min_gas` measurement, old → new. A value
      outside the 2026-10-27 rule (`ROLL_MAX` 48 if the margin is gone) goes to the owner. `PqzSet.sol` restored.
- [ ] **Step 10: Tests.** `red_skip.py` recount on the merged tree (it replaces the spec's §7 test counts); the tests of invariants
      2 and 3, invariant 7's tests and mutants on the D runs, one Hedera case, one router case.
- [ ] **Step 11: Pick by §4's rule** (smallest set meeting 60 M and 70 M for `NormalToken`, `WrappedToken` and the stand-ins; then
      no hot-path cost, D before L; then fewer mechanisms). If none fits, the gap per kind and threshold. The Zether kinds
      reported against both thresholds. Whether `WrappedPqzToken` leaves `_above64KiB`.
- [ ] **Step 12:** Commit on `ua-mtx-merge`: harness, `results.txt`, spec §9 table, research note line:
      `ua-mtx-merge T0: sizes, deploy gas and gas of the merge and levers L, D at <main sha>`.
- [ ] **Step 13: Report to the owner** for Q3's final lever choice: the table, the recommendation by §4's rule, the gap if any.
      **T9 waits for the answer.** T1 may start at once.

**Mutants:** the spike's eight on M; invariant 7's three on D (one `SSTORE`, one zero-value `CALL` moving an ERC-20, one `CALLCODE`).
**Pins:** none move on `ua-mtx-merge`. **Gates:** `test/merge` green; four sets restored.

### Task T1: the pipeline: `MetaTxLib`, `MetaTxBase` split, `UAMetaTxBase`, `MtxPipelineLib`

**Depends on:** T0 (harness and recount; not Q3).

**Files:**
- Create: `src/metatx/MetaTxAddressBase.sol`, `src/metatx/IMetaTxAddress.sol`, `src/metatx/IUALedgerViews.sol` (the ledger views
  split from `IUALedger`, spec R9 cost), `smartcontracts/evm/legacy/ua-mtx-merge/` (copies of every body below) and its
  `legacy/README.md` line, `test/merge/MergedEntry.t.sol` (ported), `test/merge/Invariants.t.sol`
- Modify: `src/common/MetaTxLib.sol`, `src/metatx/{MetaTxBase,UAMetaTxBase,MtxPipelineLib,IMetaTx,IUALedger}.sol`,
  `src/wallet/WalletExecute.sol` (inherits `MetaTxAddressBase`), `src/ua/UAKinds.sol` (the `uaAuthCall` bridge, used only by the
  pipeline's `bytes auth` branch, goes to legacy per CTR-MTX-30; `PURPOSE_METATX_CANCEL` stays, MD-5); tests
  `test/metatx/{MetaTxLib,MsgSenderLint,MtxPipelineLib,MetaTxBase,MetaTxBaseBatch,MetaTxBaseFee,MetaTxBaseLane,UAMetaTxBase}.t.sol`, helpers
  `test/ua/UALedgerBase.sol`, `test/helpers/MtxFixture.sol`, `test/v2/helpers/V2Fixture.sol`,
  `test/metatx/helpers/ERC20MetaTxHarness.sol`, and the generic-path tests the recount names

**Interfaces:**
```solidity
// MetaTxBase (core: tokens, router, wallets) — MD-1
function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool); // 0x47aea5b5
function cancelNonce(uint256 batch) external;           // unchanged
// MetaTxAddressBase / IMetaTxAddress (WalletExecute only) — unchanged bodies
function mtxNonce(address from, uint256 batch) external view returns (uint256);
function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
function mtxCancelNonce(MetaTxLib.Envelope calldata e, uint256 lane, bytes calldata sig) external returns (bytes memory);
// UAMetaTxBase (tokens, router): today's ua* under the mtx name, R47, Q2
function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
function mtxDigest(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
function mtxExecute(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata auth) external returns (bytes memory);
function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata ms, IUARegistry.UASig[] calldata auths) external returns (bool);
function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth) external returns (bytes memory);
// UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)
// emits IUALedger.UANonceCancelled(bytes32 indexed ua, uint256 indexed batch, uint256 newNonce) for lane; no self-call of cancelNonce
```
`MtxPipelineLib`: `_authorize(Ctx, bytes32 from, purpose, digest, UASig)` only (the `bytes auth` overload goes); native branch:
`0`, `UA_POOL`, `SHIELD_POOL` refused, R17 (`keyData.length != 0 || members.length != 0` → `MetaTxBadSignature`), HIP-632 as
today, `SigCheck.isValid`, no registry call; derived branch: `registry == 0` → `UALedgerOff`, else `requireAuthorized`.
`_checkTo`: native `to` free; derived `to` → `UALedgerOff` at 0, else registered and SIGNING. `_close`: `_uaAllowed` only for a
derived `e.from`, `_mtxRule` for a native one (B). `_uaOn()` leaves `preTransferUA`, `_open` and the cancel (6 call sites today:
`ERC20MetaTx` 4, `UAMetaTxBase` 2); it stays only in `_requireDerivedReceiver`.

- [ ] **Step 1: Legacy first.** Tag `ref/pre-ua-mtx-merge`; copy every body this task removes to `legacy/ua-mtx-merge/`.
- [ ] **Step 2: Failing tests** (`test/merge/`): the spike's 26 ported (`test_eoaToEoa`, `test_eoaToUA`, `test_badSignatureRefused`,
      `test_replayRefused`, `test_unregisteredReceiverRefused`, `test_derivedHighBitsAreNotTheEoa`, `test_erc1271Holder`,
      `test_designatorSignsWithItsOwnKey`, `test_nativeRunsAddressAllowlist`, `test_derivedStaysOnUAAllowlist`,
      `test_nativeSignedCancel`, the no-registry four, the slot probe) on the generic `mtxExecute`; new:
      `test_nativeUASigWithKeyDataRefused`, `test_nativeUASigWithMembersRefused` (R17, generic and named),
      `test_unboundRelayerAndFeeRecipientNotSigned` (non-zero in calldata verifies and pays where calldata says; positive control),
      `test_boundFieldChangedRefused` (each bound envelope field), `test_clientSigningNonZeroUnboundIsRefused` (invariant 2),
      `test_oldMtxExecuteSignatureRunsThroughExecuteMetaTransaction`, `test_oldUACancelNonceSignatureHasNoEntry`,
      `test_cancelIsNonceOrdered_native`, `test_cancelIsNonceOrdered_derived` (a withheld cancel at nonce n cannot land after a
      newer op consumed n), `test_cancelBumpsLaneForTheSubject`, `test_cancelFeeZeroRelayable`, `test_derivedSubjectIsPoolInSelfCall`,
      `test_nativeSubjectIsItselfInSelfCall`, `test_noRegistryNativeGenericRuns`, `test_noRegistryDerivedIsLedgerOffByName`,
      `test_walletsByteIdentical` (deployed bytecode hash of `MandateWallet`, `SmartKeyAccount`, `HederaMandateWallet` equal to the
      `ref/pre-ua-mtx-merge` build, recorded in the test), `test_UACancelNonceTypehashIsPinned`.
- [ ] **Step 3:** `../../scripts/capped forge test --match-path 'test/{merge,metatx}/*.t.sol'`: FAIL.
- [ ] **Step 4: Implement** the interfaces above; MD-6's `MsgSenderLint` files with base counts first.
- [ ] **Step 5:** PASS; repair the generic-path tests (MD-3); whole `forge test`; `--isolate` `UAGas`, `UARegistryGroups`; size
      gate; `dex_order_kat.json` (MD-8); `LinkClosure` green; layout pins unmoved.
- [ ] **Step 6: Mutants:** the spike's eight; R17 dropped; the derived `UALedgerOff` guard dropped (empty-data revert must turn a
      named-error test red); `_uaAllowed` read for a native; `_mtxRule` read for a derived; the cancel's nonce check skipped; the
      cancel self-calling `cancelNonce`; `canon` binding `relayer` with the bit off; `inNativeSpace` replaced by `from >> 160 < 2`.
- [ ] **Step 7:** Commit `ua-mtx-merge T1: one generic signed path for native and derived ids, ordered cancel, address path on the wallets`.

**Pins, old → new:** `MetaTxLib.t` (`UACancelNonce` typehash; `test_metaTransferTypehashIsPinned` moves to a legacy-pin test of
the copy, not deleted); `MsgSenderLint` counts (R24); `IMetaTx`, `IUALedger` interface ids; `size-baseline.json`; gas pins only
with old → new. **Layout:** none (`cancelUsed` stays in `UALedgerStorage`). **Gates:** whole `forge test`, `--isolate`, size gate.

### Task T2: `ERC20MetaTx`, `MetaTokenBase`, `MtxRelayFee`: the transfer group, payments, relay fee

**Depends on:** T1.

**Files:**
- Modify: `src/metatx/{ERC20MetaTx,MetaTokenBase,MtxRelayFee,IERC20MetaTx,IERC20Payment,IMetaTokenV2,IUALedger}.sol`,
  `src/common/MetaTxLib.sol` (`MetaTransfer`, `RECEIVER_FEE_TYPEHASH` and the address relay-fee struct to legacy, R46);
  tests by the recount: `test/metatx/{TokenKat,MtxCtx,PayMeta,MtxRelayFee,MetaTxParity,ERC20MetaTx,NamedEntry}.t.sol`,
  `test/ua/{UAReceiverFee,UAMetaTx3Vectors,UAMetaTx3Pq,UALedger}.t.sol`, `test/v2/{MetaTxGasV2,ReceiverPays}.t.sol`,
  `test/governance/{PlusZero,GovGas}.t.sol`, `test/wallet/*` and `test/account/*` where they call a token's transfer form
- Move to legacy: `metatransfer_kat.json`, `metatx_kat.json`, `metatx-parity.json` (and `MetaTxParity.t.sol`, which loses its point)

**Interfaces** (today's `ua*` ABI, `mtx*` name):
```solidity
function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
    uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool);     // UAMetaTransfer
// mtxTransferWithFee, mtxPay, mtxPayMeta, mtxPayReceiverFee, mtxRelayFee: today's uaTransferWithFee / uaPay / uaPayMeta /
// uaPayReceiverFee / uaRelayFee
function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth) external returns (bool);
function mtxBatchTransfer(MetaTxLib.UAMetaTransfer[] calldata ts, IUARegistry.UASig[] calldata auths) external returns (bool);
function mtxTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32);
function receiverFeeDigest(MetaTxLib.UAReceiverFee calldata f) external view returns (bytes32);   // today's uaReceiverFeeDigest
// MtxRelayFee (new CREATE2 address):
function relay(address target, bytes calldata callData, address token, bytes32 from, bytes32 payee, uint256 value, /* … as uaRelay */
    IUARegistry.UASig calldata auth) external;   // struct UARelayFee only
```
Events on these paths: `UAMetaTransactionExecuted`, `UAPaymentSettled`, `UAReceiverFeePaid`, `UATransfer` where a derived side
moves; the ERC-20 `Transfer` for a native ledger move; direct `payWithFee` keeps `PaymentSettled` (R18, R20).

- [ ] **Step 1:** Legacy copies.
- [ ] **Step 2: Failing tests:** per kind (six) `test_mtxTransfer_eoaToEoa_{registry0,registry}`, `test_mtxTransfer_eoaToUA`,
      `test_mtxTransfer_feeZero` (and `mtxPay`, `mtxPayMeta`, `mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxRelayFee` at `NONE`),
      `test_mtxTransferWithFee_needsFee`, `test_mtxPayReceiverFee_payerLegNone`, `test_relayFeeRouter_relayTakesUASig`,
      `test_oldMetaTransferSignatureRefusedOnEveryEntry` (positive control first), `test_oldReceiverFeeAndRelayFeeHaveNoEntry`,
      `test_mergedPathEmitsUAEventsOnly` (R18; no address event for a native subject), `test_payRefReadsUAPaymentSettled`,
      `test_regulatedHookSeatIsUaMove` (a mock hook in `_update` only misses a relayed transfer: the stated risk, pinned).
      `PlusZero` re-targets `mtxTransfer` and the old `uaExecuteTransfer` row to the merged entries, every kind.
- [ ] **Step 3:** `forge test --match-path 'test/{merge,metatx,ua,governance}/*.t.sol'`: FAIL.
- [ ] **Step 4: Implement.** `TokenKat.t`'s writer re-targets the UA structs (`WRITE_KAT=true`), old files to legacy.
- [ ] **Step 5:** PASS; whole `forge test`; `PLUS_ZERO_WRITE` only if a slot set moved, which is a finding (CTR-GOV-11: none may);
      size gate; MD-8.
- [ ] **Step 6: Mutants:** `_checkTo` skipped on `mtxPay`; fee taken before the call (invariant 5); `mtxBatchTransfer` length
      check dropped; `relay` reading `from` from calldata unsigned; a native ledger move through `_uaBalance`; `PaymentSettled`
      emitted on a merged path.
- [ ] **Step 7:** Commit `ua-mtx-merge T2: the transfer group, payments and the relay fee on the UA structs`.

**Pins, old → new:** `IERC20MetaTx`, `IMetaTokenV2`, `IERC20Payment` interface ids; `MsgSenderLint`; `GovGas`, `MetaTxGasV2` rows
(spike: +875 to +992 per EOA `mtxTransfer`); `plus_zero_slots.json` unchanged (slots, not ABI); `size-baseline.json`;
`MtxRelayFee` runtime. **Gates:** whole `forge test`, size gate.

### Task T3: the token kinds' own pairs: `NormalToken`, `WrappedToken`, `WrappedLib`

**Depends on:** T2.

**Files:**
- Modify: `src/metatx/{NormalToken,WrappedToken,WrappedLib,IWrappedToken}.sol`, `src/trade/ITradeToken.sol` (`WrapOrder`,
  `CancelWrapOrder`, `mtxWrapOrder(address, WrapOrder, bytes)` to legacy, R39); tests `test/v2/{Wrapped,MtxWrap,Multi,Features,Factory}.t.sol`,
  `test/ua/{UAWrap,UAAllowlist5a}.t.sol`, `test/governance/GovHybrid.t.sol` (wrap-order cap rows)

**Interfaces:** `mtxBurn(UAEnvelope, uint256, UASig)`; `mtxUnwrap`, `mtxUnwrapLeg`, `mtxUnwrapToUA` (today's `ua*`, native and derived,
R23); `mtxWrapOrder(address underlying, UAWrapOrder, UASig)` (R39). Unchanged: `mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve`
on `Envelope` + `bytes sig` with `address from`; `_mtxRule` / `_uaAllowed` rows per kind unchanged in content, re-keyed by selector.

- [ ] **Step 1:** Legacy copies.
- [ ] **Step 2: Failing tests:** `test_mtxBurn_native_registry0`, `test_mtxUnwrap_{native,derived}`, `test_mtxWrapOrder_eoaLegNoRegistry`
      (C: a ledger asked only for a derived holder), `test_noTwinWrapsStayAddress` (the four entries' selectors and structs
      unchanged, positive control), `test_wrapOrderCapStillHolds` (CTR-GOV-12 row on the merged entry), fee-0 rows for each.
- [ ] **Step 3:** FAIL. **Step 4: Implement.** **Step 5:** PASS; whole `forge test`; size gate; MD-8.
- [ ] **Step 6: Mutants:** `IUALedger` asked of every leg in `mtxWrapOrder`; the cap skipped on `mtxWrapOrder`; `mtxUnwrapToUA`
      accepting a native receiver; a no-twin entry moved onto `UAEnvelope`.
- [ ] **Step 7:** Commit `ua-mtx-merge T3: burn, unwraps and the wrap order on the UA structs; the four wraps unchanged`.

**Pins, old → new:** `IWrappedToken`, `ITradeToken` ids; `WrappedLib` runtime and `LinkClosure` if its DELEGATECALL count moves;
`MsgSenderLint` (`WrappedToken` 4 → measured). **Gates:** whole `forge test`, size gate.

### Task T3b: mandate wallets, merged form (Q6 changed 2026-11-04, MD-11)

**Depends on:** T3 (sequential in the worktree: `MsgSenderLint`, `test/merge/Invariants.t.sol`, the helpers); needs T1's
`UAMetaTxBase` and T2's `payWithFee` / `payWithFeeToUA`. Before T4.

**Files:**
- Modify: `src/wallet/MandateWallet.sol` (onto `UAMetaTxBase`, ids `bytes32`), `src/hedera/HederaMandateWallet.sol` (`IS_HEDERA`
  through the constructor; its `_requireValidSignature` override and `mtxExecuteAsOwnerRaw` leave); NatSpec only:
  `src/wallet/WalletExecute.sol`, `src/metatx/{MetaTxAddressBase,IMetaTxAddress,UAMetaTxBase}.sol` ("the wallets" → `SmartKeyAccount`).
  Not touched: `src/account/SmartKeyAccount.sol`.
- Create: `smartcontracts/evm/legacy/ua-mtx-merge/src/wallet/MandateWallet.sol`,
  `smartcontracts/evm/legacy/ua-mtx-merge/src/hedera/HederaMandateWallet.sol` (copies at T3's tip, MD-4), their tests under
  `smartcontracts/evm/legacy/ua-mtx-merge/test/wallet/`; `test/wallet/MandateWalletMerged.t.sol`;
  `test/vectors/mandate_kat.json` (written by `AccountKat.t`'s `MandateWalletKatTest`, `WRITE_KAT=true`).
- Move to `smartcontracts/evm/test/vectors/legacy/ua-mtx-merge/`: `mandate_pay_kat.json`, `mandate_revoke_kat.json` (MD-11 (a));
  their readers outside forge (node `typed.rs`, `clientkeys` `test/evm.test.js`) move in T14 and T11.
- Tests: `test/wallet/{MandateWallet,NamedWallets}.t.sol` (`MandateFixture`, also read by `test/metatx/{NamedEntry,Sweeper7702}.t.sol`),
  `test/account/AccountKat.t.sol`, `test/metatx/TypedOps.t.sol` (the six wallet rows: `…_RowHasNoWalletEntry` until T11
  regenerates, as T1 did for `CancelNonce`), `test/metatx/MsgSenderLint.t.sol` (adds `src/wallet/MandateWallet.sol` and
  `src/hedera/HederaMandateWallet.sol`, MD-6's way), `test/merge/Invariants.t.sol` (`test_walletsByteIdentical` keeps
  `SmartKeyAccount` only; the two mandate-wallet rows leave with old → removed in the commit).

**Interfaces:**
```solidity
contract MandateWallet is UAMetaTxBase, IERC1271 {               // MD-11 (c)
    constructor(bytes32 owner_, bytes32 chainUid_, address registry_, bool hedera_);
        // UAMetaTxBase("SCaaS MandateWallet", chainUid_, registry_, address(0), hedera_); domain unchanged
    bytes32 public immutable owner;
    struct Mandate { bytes32 delegate; uint64 expiry; uint64 periodSeconds; uint64 periodStart;
                     uint128 maxPerPayment; uint128 maxPerPeriod; uint128 spentInPeriod; }
    mapping(address token => Mandate) public mandates;
    mapping(address token => mapping(bytes32 payee => bool)) public payeeAllowed;
    // direct entries: authority by _subject() (the ticket's id in a self-call, else pad(msg.sender)), never _msgSender()
    function setMandate(address token, bytes32 delegate, uint128 maxPerPayment, uint128 maxPerPeriod,
        uint64 periodSeconds, uint64 expiry) external;
    function setPayee(address token, bytes32 payee, bool allowed) external;
    function revoke(address token) external;
    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory);
    function payUnderMandate(address token, bytes32 payee, uint256 amount, bytes32 entryRef, uint64 epoch_) external;
        // native payee: payWithFee(address(uint160(uint256(payee))), …); derived: payWithFeeToUA(payee, …) (CTR-UA-28)
    function revoke(address token, uint64 epoch_) external;
    // one signed entry per operation, fee mode NONE
    function mtxSetMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 delegate, uint128 maxPerPayment,
        uint128 maxPerPeriod, uint64 periodSeconds, uint64 expiry, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxSetPayee(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, bool allowed,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxRevokeMandate(MetaTxLib.UAEnvelope calldata e, address token, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxPayUnderMandate(MetaTxLib.UAEnvelope calldata e, address token, bytes32 payee, uint256 amount,
        bytes32 entryRef, uint64 epoch_, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxDelegateRevoke(MetaTxLib.UAEnvelope calldata e, address token, uint64 epoch_,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxExecute(MetaTxLib.UAEnvelope calldata e, address target, uint256 value, bytes calldata data,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    // inherited (UAMetaTxBase): mtxExecute(UAMetaTransaction, UASig), mtxBatch, mtxCancelNonce(UAEnvelope, uint256, UASig),
    // mtxNonce(bytes32, uint256), mtxDigest(UAMetaTransaction), registry(); executeMetaTransaction refuses (MD-11 (b))
    function mandatePayLane(bytes32 entryRef) external pure returns (uint256);              // unchanged
    function mandateRevokeLane(address token, uint64 epoch_) external pure returns (uint256); // unchanged
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
        // native owner: ECDSA by address(uint160(uint256(owner))); derived owner: 0xffffffff (CTR-ACC-12)
}
contract HederaMandateWallet is MandateWallet {
    constructor(bytes32 owner_, bytes32 chainUid_, address registry_);   // MandateWallet(…, true): HIP-632 on the native branch
}
// UASetMandate(bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,E)
// UASetPayee(bytes32 from,address token,bytes32 payee,bool allowed,E)
// UARevokeMandate(bytes32 from,address token,E)
// UAPayUnderMandate(bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch,E)
// UADelegateRevoke(bytes32 from,address token,uint64 epoch,E)
// UAExecute(bytes32 from,address target,uint256 value,bytes data,E)
// E = uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient
```
Events `MandateSet(address indexed token, bytes32 indexed delegate, …)`, `MandateRevoked(address indexed token, bytes32 indexed by)`,
`PayeeSet(address indexed token, bytes32 indexed payee, bool)`, `PaidUnderMandate(address indexed token, bytes32 indexed payee, uint256,
bytes32 indexed entryRef)`; error `PayeeNotAllowed(bytes32)` (MD-11 (e)). `_mtxRule` / `_uaAllowed` per MD-11 (d).

- [ ] **Step 1: Legacy first.** Copy both wallets and the tests this task rewrites to `legacy/ua-mtx-merge/`; one line in
      `legacy/README.md`.
- [ ] **Step 2: Failing tests** (`test/wallet/MandateWalletMerged.t.sol`, each with its positive control first), on `MandateWallet`
      and `HederaMandateWallet`:
      `test_nativeOwnerSetMandateNoRegistry` and `test_nativeDelegatePaysNoRegistry` (wallet `registry == 0`, and with a registry
      set, `vm.expectCall(reg, "", 0)`); `test_erc1271OwnerSignsWithItsCode` (a contract owner, 50 k cap);
      `test_derivedOwnerSetMandateViaRegistry`, `test_derivedDelegatePaysViaRegistry`, `test_derivedPayeePaidByPayWithFeeToUA`,
      `test_derivedSideAtRegistryZeroIsLedgerOffByName`; `test_nativeUASigWithKeyDataRefused`, `test_nativeUASigWithMembersRefused`
      (R17, named and generic); `test_everyEntryRelayableAtFeeZero` (the six named, generic, batch, cancel; a relayer that is
      not the signer) and `test_feeNonZeroRefused`; `test_cancelIsNonceOrdered_{native,derived}` (a withheld cancel at nonce n
      cannot land after a newer op consumed n); `test_payeeIsSigned` and `test_executeTargetIsSigned` (a changed `payee` /
      `target` in calldata fails); `test_derivedSubjectReadsUAAllowedOnly`; `test_checksReadSubjectNotMsgSender` (a derived
      delegate, `UA_POOL` as `_msgSender()`, passes the delegate check by its id); `test_derivedOwnerHasNoErc1271Answer`;
      `test_executeMetaTransactionRefused` (MD-11 (b)); `test_flatBuildersHaveNoEntry` (old `mtxPayUnderMandate(address,…)`,
      `mtxRevoke`, `mtxExecuteAsOwner`, `mtxExecuteAsOwnerRaw` selectors revert); `test_oldAddressWalletSignatureRefused`
      (a `PayUnderMandate` / `MetaTransaction` signature of the old form has no entry); `test_hederaEd25519OwnerSignsHip632`,
      `test_hip632RefusedForAContract` on `HederaMandateWallet`; `test_walletUATypehashesArePinned` (the six strings above
      and `UACancelNonce`); `test_smartKeyAccountByteIdentical` (the `ref/pre-ua-mtx-merge` hash, unchanged).
- [ ] **Step 3:** `../../scripts/capped forge test --match-path 'test/{wallet,account,merge}/*.t.sol'`: FAIL.
- [ ] **Step 4: Implement** the interfaces; the existing wallet tests move to the merged entries (MD-3, each reversed meaning
      listed as `meaning: <test> old → new`); `MandateWalletKatTest` writes `mandate_kat.json` (a delegate's `mtxPayUnderMandate`
      and `mtxDelegateRevoke` on their mandate lanes, nonce 0, both executed; EOA signer, unbound `relayer` 0).
- [ ] **Step 5:** PASS; whole `forge test`; `--isolate` `UAGas`, `UARegistryGroups`; size gate; MD-8 if a token byte moved (it
      should not); layout pins unmoved (the wallets have no row in `test/v2/layout/`, no token storage moves).
- [ ] **Step 6: Mutants** (the global mutant rule): a native subject sent to the registry (`expectCall` red); the derived branch's
      `requireAuthorized` skipped (forgery test red); R17 dropped on the wallet path; `_uaChargeFee` accepting a fee or the
      relayer bound by default (fee-0 relay red); the cancel's nonce check skipped; `payee` left out of `UAPayUnderMandate`'s
      hash; `target` left out of `UAExecute`'s hash; `_msgSender()` read for the delegate check instead of `_subject()`; the
      derived owner answered by `isValidSignature`; `executeMetaTransaction` left open; HIP-632 accepted for an account with
      code. Each turns a named test red; a mutant no test catches is a finding.
- [ ] **Step 7:** Commit `ua-mtx-merge T3b: mandate wallets in the merged form, one signed entry per operation (Q6)`.

**Pins, old → new:** wallet typehashes (six new `UA<Op>` pins; the address strings to a legacy pin of the copy, not deleted);
`AccountKat` (`mandate_pay_kat.json`, `mandate_revoke_kat.json` → legacy, `mandate_kat.json` new); `MsgSenderLint` (two files
added, red first with a wrong count); `test_walletsByteIdentical` (`MandateWallet`, `HederaMandateWallet` rows removed,
`SmartKeyAccount` unchanged); size (`MandateWallet`, `HederaMandateWallet` runtime old → new in the commit; no ratchet row
today). **Layout:** none moves. **Gates:** whole `forge test`, `--isolate`, size gate.

### Task T4: Zether

**Depends on:** T3. **Zether only;** PQZ is T5.

**Files:** `src/zether/{ZetherLayer,ZetherLib,ZetherWrappedLib,NormalZetherToken,WrappedZetherToken,IZetherToken}.sol`,
`src/confidential/IConfidentialToken.sol` (the Zether half of its interfaces); 15 test files under `test/zether/` by the recount
(`ZetherRelay`, `ZetherUA5c`, `ZetherProverCross`, `ZetherDeploy`, …), `test/zether/helpers/ZetherFixture.sol`.

**Interfaces:** `mtxShield`, `mtxConfidentialTransfer`, `mtxConfidentialTransferCompact`, `mtxConfidentialTransferSingle`,
`mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver`, `mtxRollOverBatch`, `mtxRollOverSigned`, `mtxSetRollOverMode` in today's `ua*`
form (`mtxShield` with `UASig`, R47); `envelopeBinding(UAMetaTransaction)` = `SCAAS-ZETHER-UA-ENVELOPE-V1` (today's
`uaEnvelopeBinding`); the address `envelopeBinding(MetaTransaction)` view to legacy, the internal address binding kept for
`executeMetaTransaction` (R35). Unchanged: the direct `mtxShield(bytes32,uint256)` and `mtxRollOver(bytes32,uint256)` overloads,
`mtxWrapShield`.

- [ ] **Step 1:** Legacy copies; the library-split checklist read for `ZetherLib` / `ZetherWrappedLib` before any edit.
- [ ] **Step 2: Failing tests:** `test_zetherRelayedProofBindsUATag_native`, `_derived` (each merged entry);
      `test_zetherExecuteMetaTransactionBindsAddressTag` (a proof bound to the UA tag refused there, and the reverse on
      `mtxExecute`), `test_zetherStatementLayoutUnchanged` (risk 9: the statement bytes equal at base and merge for one fixed
      input; a layout change stops the task: new `proofSystemId` is not this round), fee-0 rows, `test_zetherCiphertextInState`.
- [ ] **Step 3:** FAIL. **Step 4: Implement.** **Step 5:** PASS; `forge test --match-path 'test/zether/**'`; `zether-cross`;
      whole `forge test`; size gate; `LinkClosure`.
- [ ] **Step 6: Mutants:** the UA tag swapped for the address tag on one merged entry; the binding computed over the address
      `from`; `msg.sender` read inside `ZetherLib` instead of the passed subject; a return-data word dropped in the DELEGATECALL.
- [ ] **Step 7:** Commit `ua-mtx-merge T4: Zether pairs merged, relayed proofs bind the UA tag for every subject`.

**Pins, old → new:** Zether typehashes (`*TypehashIsPinned`: address ones to the legacy pin); `MsgSenderLint` (`ZetherLayer`,
`ZetherLib`, `ZetherWrappedLib`); `LinkClosure` release pins; `IZetherToken` id; sizes. **Gates:** whole `forge test`,
`zether-cross`, size gate.

### Task T5: PQZ

**Depends on:** T4 (sequential: shared `IConfidentialToken`, `MetaTxLib`). **PQZ only.**

**Files:** `src/pqz/{PqzLayer,PqzCore,PqzWrappedLib,NormalPqzToken,WrappedPqzToken,IPqzToken}.sol`, `src/confidential/IConfidentialToken.sol`
(the PQZ half); 13 test files under `test/pqz/` by the recount (`PqzRelay`, `PqzTyped`, `PqzStateGas`, …), `test/pqz/helpers/PqzFixture.sol`;
`script/pqz/e2e.py` (entry names, `envelopeBinding` UA form) only if its `--self-test` reads them.

**Interfaces:** `mtxShield`, `mtxConfidentialTransfer`, `…Compact`, `…Single`, `…SingleCompact`, `mtxUnshield`, `mtxUnshieldUnwrap`,
`mtxRollOver`, `mtxPrepareAcc` in today's `ua*` form; `envelopeBinding(UAMetaTransaction)` = `SCAAS-PQZ-UA-ENVELOPE-V1` (R36).
No change in `pqz-core`: the prover takes the binding value as input.

- [ ] **Step 1:** Legacy copies.
- [ ] **Step 2: Failing tests:** `test_pqzRelayedProofBindsUATag_native`, `_derived`; `test_pqzExecuteMetaTransactionBindsAddressTag`
      and the reverse; `test_pqzStatementLayoutUnchanged` (as T4); fee-0 rows; `test_pqzCiphertextInState`.
- [ ] **Step 3:** FAIL. **Step 4: Implement.**
- [ ] **Step 5:** PASS; whole `forge test`; size gate (`_above64KiB` if `WrappedPqzToken` crosses back, its jump stated);
      **all four sets, `test/{ua,pqz}` only** (owner rule): `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test
      --match-path 'test/{ua,pqz}/*'` for `n2048-kmax1024`, `n2560-kmax16384`, `n2816-kmax65536` (the default set ran whole),
      one run per work tree, `PqzSet.sol` restored; **R41**: `test_gas_rollMax_relayedFullTx` and `debit_min_gas` at four sets with
      old → new; a value outside the 2026-10-27 rule: stop and ask.
- [ ] **Step 6: Mutants:** the UA tag swapped for the address tag; `PqzCore`'s tag constant changed; `msg.sender` in `PqzWrappedLib`.
- [ ] **Step 7:** Commit `ua-mtx-merge T5: PQZ pairs merged, relayed proofs bind the UA tag for every subject, four sets`.

**Pins, old → new:** PQZ typehashes; `MsgSenderLint` (the PQZ files of MD-6); `PqzStateGas` rows per set; sizes; `PqzSet.sol`
untouched (generated). **Gates:** whole `forge test`, three other sets `test/{ua,pqz}`, size gate.

### Task T6: DEX: SCaaS legs on `UATradeOrder`

**Depends on:** T5 (sequential: `ERC20MetaTx`'s trade entries).

**Files:** `src/trade/{TradeLib,ITradeToken}.sol`, `src/metatx/ERC20MetaTx.sol` (trade entries and views), `src/dex/{SCaaSDex,ISCaaSDex,DexPuller}.sol`
(leg types, `_interact`'s refusal list, the ledger check for a derived seller only); helpers `test/helpers/{DexLegs,OrderJson,HybridHarness}.sol`;
33 test files naming `TradeOrder` / `mtxTrade` / `uaTrade` (`test/v2/Dex*.t.sol` ×9, `Trade`, `UniswapExecutor`, `test/ua/{UADex,UADexInvariant,UATrade,UATradeVectors,UALedger}.t.sol`,
`test/metatx/{TradeKat,TradeTyped}.t.sol`, `test/fork/UniswapFork.t.sol`, …); `trade_kat.json` to legacy.

**Interfaces:** `mtxTrade(UATradeOrder, UASig, …)` (today's `uaTrade`), `mtxCancelOrder`, `mtxInvalidateNonces` (UA forms),
`minNonce(bytes32, …)`, `tradeOrderDigest(UATradeOrder)`, `invalidateNoncesDigest(…)` (UA forms); `orderHash` / `cancelHash` lose
the `ua` flag on the token side, the DEX's `record`, `cancel`, `invalidate` keep it for outside legs; `TradeOrder` stays for
outside legs (`DexOrder` nests it); `LegSettled` outside legs only, `UALegSettled` for a SCaaS leg; `UATradeFilled`,
`UAOrderCancelled`, `UANoncesInvalidated` on the token.

- [ ] **Step 1:** Legacy copies.
- [ ] **Step 2: Failing tests:** `test_scaasLegShapeZeroRefused`, `test_scaasLegUATradeOrder_eoaNoRegistry` (all-native trade at
      `registry() == 0`, R9), `test_derivedSellerNeedsLedger` (`UALedgerOff` by name), `test_outsideLegKeepsTradeOrder`,
      `test_scaasLegEmitsUALegSettled`, `test_metaTxCancelDoesNotCancelTradeOrders` (separate stores), `test_interactRefusesMergedTradeSelector`,
      `test_tradeOrderDestinationIsBytes32Signed`.
- [ ] **Step 3:** FAIL. **Step 4: Implement**; the 30-odd DEX files move to shape 1 (MD-3 for the reversed ones).
- [ ] **Step 5:** PASS; whole `forge test`; `dex_order_kat.json` regenerated (now with shape-1 SCaaS legs); size gate.
- [ ] **Step 6: Mutants:** ledger asked for a native seller; `_interact` missing the merged `mtxTrade` selector; `destination`
      left out of the digest; `UALegSettled` replaced by `LegSettled` on a SCaaS leg; `ua` flag kept on the token side.
- [ ] **Step 7:** Commit `ua-mtx-merge T6: a SCaaS token leg is a UATradeOrder; TradeOrder for outside legs`.

**Pins, old → new:** `TradeLib` typehashes (address token-side to legacy pin); `ITradeToken`, `ISCaaSDex` ids; `DexGas` rows;
`SCaaSDex` size (spike +134 B for C); `trade_kat.json` → legacy, `TradeKat.t` re-targets `uatrade_kat.json` (rows unchanged,
notes renamed). **Gates:** whole `forge test`, size gate.

### Task T7: `GovernanceRouter`

**Depends on:** T1 (base) and T6 (sequential in the worktree; files disjoint, but `selector_audit.json`, `MsgSenderLint` and the
ratchet are shared).

**Files:** `src/governance/{GovernanceRouterBase,GovernanceRouter,IGovernanceRouter}.sol`; tests `test/governance/{GovRouter,GovRouterTypehash,GovIdentity,GovAttackV2,GovDeploy,SelectorAudit}.t.sol`,
`test/v2/layout/GovernanceRouter.json` (must not move); `test/vectors/selector_audit.json`.

**Interfaces:** 19 entries `mtx<Op>(MetaTxLib.UAEnvelope e, <op params>, IUARegistry.UASig auth)` over `UA<Op>` with `target`
signed (today's `_uaCall` flow; an EOA's subject `pad(addr)` as `_mtxCall` wrote it, so `_govSubject()` is unchanged);
`mtxCancelNonce(UAEnvelope, lane, UASig)` (Q2, fee mode `NONE`); `mtxExecute` / `mtxBatch` (merged names) and
`executeMetaTransaction` refuse `MtxSelectorNotAllowed`; the 19 `_mtxCall` entries and typehashes to legacy. New bytecode, new
CREATE2 address (risk 10).

- [ ] **Step 1:** Legacy copies.
- [ ] **Step 2: Failing tests:** `test_routerRow_<Op>` for the 19 on the merged entry, EOA and derived; `test_routerEoaSubjectIsPaddedAddress`;
      `test_routerCancelIsNonceOrdered_{native,derived}`; `test_routerGenericEntriesRefuseEveryCall` (`mtxExecute`, `mtxBatch`,
      `executeMetaTransaction`); `test_routerOldAddressSignatureHasNoEntry`; `GovRouterTypehash.t`: 19 `UA<Op>` pins plus the new
      `UACancelNonce`, the 19 address pins to a legacy pin.
- [ ] **Step 3:** FAIL. **Step 4: Implement.**
- [ ] **Step 5:** PASS; `selector_audit.json` re-pinned by reading (MD: every merged row `SIGNED`); whole `forge test`; size gate.
- [ ] **Step 6: Mutants:** `target` left out of the digest; the subject taken from `msg.sender`; the generic refusal dropped on
      `mtxBatch`; the cancel unordered.
- [ ] **Step 7:** Commit `ua-mtx-merge T7: the router's 19 pairs merged, ordered cancel, new CREATE2 address`.

**Pins, old → new:** 38 router typehash pins → 19 + `UACancelNonce`; `selector_audit.json` rows (19 removed, merged rows moved);
`MsgSenderLint` (`GovernanceRouterBase`, `GovernanceRouter`); router size. **Gates:** whole `forge test`, size gate.

### Task T8: Hedera (contracts)

**Depends on:** T7.

**Files:** `src/hedera/{HederaAccountAuth,HederaLib}.sol` (HIP-632 entry names; the comment block's entry list); `HederaMandateWallet`
is T3b's (Q6), not this task's; `test/hedera/{HederaKat,HederaV2}.t.sol`, `test/hedera/gen_hedera_kat.py`, `test/hedera/HederaMocks.sol`,
`test/vectors/hedera_kat.json` (regenerated; old to legacy).

**Interfaces:** `IS_HEDERA` kinds as T2–T7; `_authorizeNative` keeps HIP-632 (64-byte signature by an account `SigCheck.isContract`
classes as no contract); `MetaOp` v1 = the token's `UAMetaTransfer`, `from` the account's EVM address zero-padded (long-zero for
ED25519, alias for ECDSA) (R42).

- [ ] **Step 1: Failing tests:** `test_hederaEd25519EoaMtxTransfer` (long-zero padded `from`), `test_hederaEcdsaAliasMtxTransfer`,
      `test_hip632RefusedForAContract`, `test_hederaKatIsUAMetaTransfer` (`HederaMandateWallet`'s HIP-632 rows are T3b's).
- [ ] **Step 2:** FAIL. **Step 3: Implement**; `python3 test/hedera/gen_hedera_kat.py` writes the new KAT.
- [ ] **Step 4:** PASS; whole `forge test`; size gate.
- [ ] **Step 5: Mutants:** HIP-632 accepted for an account with code; the long-zero padding reversed; a 65-byte signature taken
      down the HIP-632 branch.
- [ ] **Step 6:** Commit `ua-mtx-merge T8: Hedera kinds on the merged entries, MetaOp v1 is UAMetaTransfer`.

**Pins, old → new:** `hedera_kat.json` by its generator; `HederaV2.t` sizes per its rule. **Gates:** whole `forge test`, size gate.

### Task T9: the size lever(s) the owner picks (Q3)

**Deferred (owner 2026-11-04): not part of the M round; the owner decides D (and L) after M's PR.** T10 and later tasks run without it.
**Deprecated (owner 2026-11-05): no lever L or D is built.** The token releases keep their size; a public chain with
EIP-8037 takes the releases whose release transaction fits its block (T10's deploy-gas summary, `RELEASE_GAS_GATE=public`);
Sepolia (200 M) and the SCaaS testnet take all. The `UARegistryLib` ↔ `UARegistry` rebalance (3c) is separate and stays.

**Depends on:** T8 **and the owner's Q3 answer** to T0's report. If the answer is "no lever", this task records that and ends.

**Files (L):** a new `src/metatx/<Name>Lib.sol` holding the `ERC20MetaTx` / `UAMetaTxBase` bodies (the `ZetherLib` pattern:
decoders and ABI on the token), `script/DeployBase.sol` (`Env.libs`, link order), `test/v2/LinkClosure.t.sol`, `size-baseline.json`.
**Files (D):** a module contract per release (`src/metatx/<Name>Views.sol`), `DeployBase` (`env.deps`, `libCodeHashes`), the tokens'
`fallback`, about 720 test call sites (T0's count), `test/merge/LeverD.t.sol`.

**Interfaces:** none seen from outside (no ABI, storage or rule change). D: `fallback() external` (not `payable`) dispatching the
module's selectors by DELEGATECALL to an immutable address pinned by hash in `Env`; `hasRole`, `pendingOwner` and every view
another contract reads on chain stay on the token.

- [ ] **Step 1: Failing tests (L):** `test_libraryOpcodes` with the new library row; a signed call through the library equals the
      token-body result (one per entry class). **(D)**, invariant 7: `test_moduleHashPinnedInEnv`, `test_moduleOpcodeCheck`
      (no `SSTORE`, `TSTORE`, `CALL`, `CALLCODE`, `DELEGATECALL`, `CREATE`, `CREATE2`, `SELFDESTRUCT`, `LOG*`; `STATICCALL` only),
      `test_fallbackNotPayable`, `test_fallbackRevertsOnUnknownSelector`, `test_fallbackNeverAnswersIsValidSignature`,
      `test_fallbackNotReachableAsSelfCall` (`_mtxRule` / `_uaAllowed` list no module selector),
      `test_executorAndDexInteractReachOnlyViews` (`MtxRelayExecutor.exec`, the DEX's `_interact`).
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; four sets `test/{ua,pqz}` if L touched the
      PQZ kinds' bases; size gate; deploy gas of every changed implementation and the library or module against 60 M and 70 M.
- [ ] **Step 5: Mutants (L):** `this` read inside the library; `msg.sender` inside the library; a storage slot computed from the
      library's own address. **(D):** module with one `SSTORE`; with one zero-value `CALL` moving an ERC-20; with one `CALLCODE`;
      `fallback` made `payable`; `isValidSignature` served by the module. Each turns its test red. The module's source and
      dispatch targets reviewed by hand (an opcode test proves no more than its list).
- [ ] **Step 6:** Commit `ua-mtx-merge T9: lever <L|D|L + D> per the owner's Q3, sizes and deploy gas old → new`.

**Pins, old → new:** `size-baseline.json` every moved row; `LinkClosure`; gas pins (L: +1 to +2 K per signed call, T0's figure).
**Gates:** whole `forge test`, size gate, `--isolate`.

### Task T10: deploy, scripts and config (Q4)

**Depends on:** T9.

**Files:** `smartcontracts/evm/script/DeployBase.sol` (`_releaseGasNeed`, `_requireReleaseGas`: the testnet keeps
`runtime × 1,530 + 2^24`; a public chain is gated on the measured release gas, Q4; the new router and `MtxRelayFee` CREATE2),
`smartcontracts/scripts/deploy.sh` (the public-chain path), `smartcontracts/evm/script/pqz/e2e.py` (`require_release_gas`, merged entry
names, the UA binding for an EOA, `--self-test`), `script/pqz/test_e2e_linked.py`, `script/ZetherE2E.s.sol`, `scripts/e2e-zether.sh`,
`scaas-node/node.example.toml` (`governance_routers`, `params.relay_fee.router` comments), `test/ua/UADeploy.t.sol`
(`test_registryDeployGate`), `test/governance/GovDeploy.t.sol`, `test/zether/ZetherDeploy.t.sol`, `smartcontracts/evm/runs/<date>-ua-mtx-merge-deploy-gas.txt`.

**Interfaces:** `DeployBase`: a public-chain gate that takes the release transaction's measured regular + state gas (fork or local
simulation through `deployImplementation`) × 1.05 against the chain's limit, and regular × 1.05 < 2^24; selected by a declared
input, not a chain id list (one rule on every chain); the testnet formula unchanged.

- [ ] **Step 1: Failing tests:** `test_publicGateUsesMeasuredReleaseGas`, `test_publicGateRefusesRegularOver2pow24`,
      `test_testnetGateFormulaUnchanged`, `test_routerAndRelayFeeNewAddresses`, `e2e.py --self-test` rows for the merged names and
      the UA binding of an EOA.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `scripts/e2e-zether.sh` (anvil, capped); `e2e.py --self-test`;
      the simulated release run against 60 M and 70 M committed as the deploy-gas summary.
- [ ] **Step 5: Mutants:** the public gate using `gas_used`; × 1.05 dropped; the regular-part check dropped; the testnet formula
      changed.
- [ ] **Step 6:** Commit `ua-mtx-merge T10: deploy gate for public chains by measured release gas; scripts on the merged entries`.

**Pins, old → new:** `_requireReleaseGas` NatSpec figures. **Gates:** `GovDeploy`, `UADeploy`, `ZetherDeploy`, `e2e-zether`.

### Task T11: vectors and `clientkeys`

**Depends on:** T7 (every ABI and struct final). Beside T8–T10 (MD-8 keeps `dex_order_kat.json` with the contract tasks).

**Files:** `clients/clientkeys/src/evm.js` (forms, `TYPED_OPS`, `OP_BUILDERS`, the canonical-0 rule for unbound fields), `scripts/{typed-ops-vectors,typed-ops-expected,typed-ops-cast-check,ua-sig-vectors}.mjs`,
`test/{evm,typed-ops,ua-metatx3,ua-sig,pq-sig,ua-trade,paymeta,relayfee}.test.js`, `clients/clientkeys/legacy/ua-mtx-merge/`;
regenerated `smartcontracts/vectors/typed/typed_ops.json` (MD-7; old rows to `smartcontracts/vectors/typed/legacy/ua-mtx-merge/`),
`smartcontracts/vectors/ua/{metatx3,uatrade_kat}.json` (rows unchanged, notes renamed); `smartcontracts/evm/test/metatx/TypedOps.t.sol`.
**Mandate wallets (Q6, T3b):** `src/evm.js`'s `WALLET` rows and builders on the six `UA<Op>` structs and `UACancelNonce` (`on`
gains `MandateWallet`), the flat-builder helpers to `clients/clientkeys/legacy/ua-mtx-merge/`; `test/evm.test.js`'s mandate KAT
test reads `smartcontracts/evm/test/vectors/mandate_kat.json` (the two old KATs from its legacy place); `TypedOps.t`'s six
`…_RowHasNoWalletEntry` tests of T3b become row tests of the `UA<Op>` rows.

**Interfaces:** builders for every merged entry with `bytes32 from` / `to` / `destination` / `payee` and `UASig auth`; the cancel
on `UACancelNonce(bytes32 from,uint256 lane,E)`; the address builders of merged entries to legacy; the wallet builders unchanged.

- [ ] **Step 1: Failing tests:** every `typed_ops.json` row against `src/evm.js`; `the mandate wallet rows are UA structs with
      bytes32 from, delegate, payee`; `mandate_kat.json equals the builders (pay and delegate revoke)`; `a merged entry's calldata carries UASig{signature}
      for an EOA`; `an unbound relayer or feeRecipient is signed as 0 and shown as unbound`; `a non-zero unbound value in the signed
      message yields the contract's refusal digest` (the forge row in `TypedOps.t`); `the cancel row is ordered and native-capable`.
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test`: FAIL.
- [ ] **Step 3: Implement;** generators run twice, files do not move the second time; cast check.
- [ ] **Step 4:** PASS; `forge test --match-path test/metatx/TypedOps.t.sol`; `git diff` of `typed_ops.json` shows only MD-7's
      45 retired rows, `CancelNonce`'s `on` and `UACancelNonce`'s type string and `on`, and Q6's six wallet rows retired and six
      `UA<Op>` rows added (MD-7 as amended).
- [ ] **Step 5: Mutants:** a field order swapped in one `UA<Op>` string; `relayer` left non-zero while unbound; the router domain
      used for a token row; a wallet row signed in the token domain; `payee` encoded as `address` in `UAPayUnderMandate`.
- [ ] **Step 6:** Commit `ua-mtx-merge T11: clientkeys builders on the merged entries, typed_ops.json regenerated`.

**Pins, old → new:** `typed_ops.json` (retired rows listed). **Gates:** `clientkeys`, `vectors-check`, `TypedOps.t`.

### Task T12: `zether-prover`

**Depends on:** T4, T11.

**Files:** `clients/zether-prover/src/{envelope,typed,api,zether}.rs`, `tests/{typed_ops,envelope_disclosure,recover,zether_proofs}.rs`,
`tools/env_ref.sh`, `clients/zether-prover/legacy/ua-mtx-merge/`.

**Interfaces:** `ua_envelope_binding(chain_id, chain_uid, token, &UAMetaTransaction) -> [u8; 32]` over `SCAAS-ZETHER-UA-ENVELOPE-V1`;
the address `envelope_binding` kept for `executeMetaTransaction`; typed builders of the merged Zether entries with `UASig`.

- [ ] **Step 1: Failing tests:** the UA binding equals the contract's `envelopeBinding` for a native and a derived subject (forge
      cross row); the address binding unchanged for `executeMetaTransaction`; `typed_ops.rs` over the regenerated rows.
- [ ] **Step 2:** `cd clients/zether-prover && ../../scripts/capped cargo test -j2`: FAIL. **Step 3: Implement.** **Step 4:** PASS;
      `zether-cross`; the wasm build and smoke.
- [ ] **Step 5: Mutants:** the UA tag swapped for the address tag; `from` hashed as an address.
- [ ] **Step 6:** Commit `ua-mtx-merge T12: zether-prover binds the UA tag on the merged entries`.

**Gates:** `cargo-zether-prover`, `zether-cross`.

### Task T13: the `bytes32` id display in every `ua-*` (spec §6, new work)

**Depends on:** T11 (`clientkeys`, MD-9). Beside T12, T14–T19.

**Files:** `clients/clientkeys/src/evm.js` (renderer), `clients/clientkeys/scripts/id-display-vectors.mjs` (new), `test/evm.test.js`;
`smartcontracts/vectors/ua/id_display.json` (new); `clients/ua-rs/src/lib.rs`, `tests/vectors.rs`; wrappers `clients/ua-c/src/lib.rs`,
`clients/ua-cxx/src/lib.rs`, `clients/ua-qt/src/ua_kinds.rs`, `clients/ua-dart-frb/rust/src/api/ua.rs` and their vector tests;
native `clients/ua-py/scaas_ua/__init__.py`, `clients/ua-go/`, `clients/ua-cs/`, `clients/ua-dart/` and their vector tests.

**Interfaces:** `idDisplay(bytes32) → { kind: "native", address: <EIP-55> } | { kind: "derived", urn: "urn:scaas:ua:v1:…" }`,
refusing a malformed id; one function per language, the same rows.

- [ ] **Step 1: Failing tests:** one reader per language over every row of `id_display.json` (a missing row fails).
- [ ] **Step 2:** each package's command: FAIL. **Step 3: Implement** (`ua-rs` first, wrappers call it; the four native ones).
- [ ] **Step 4:** each package's gate step: PASS; `dotnet build-server shutdown` after C#.
- [ ] **Step 5: Mutants:** a padded id with a high bit rendered as an address; checksum dropped; one native table off by one row.
- [ ] **Step 6:** Commit `ua-mtx-merge T13: bytes32 id display in clientkeys and every ua-*`.

**Gates:** `clientkeys`, `ua-rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`, `ua-py`, `ua-go`, `ua-cs`, `ua-dart`.

### Task T14: node core: rows, guard, jobs, chain, indexer

**Depends on:** T11 (vectors), T7 (`selector_audit.json`).

**Files:** `scaas-node/src/typed.rs` (per-kind rows: token rows on the merged forms, `gov_router` 38 → 19 + the cancel, the shared
`mtxCancelNonce` row split: `T` + `gov_router` on `UACancelNonce`, `WA` on `CancelNonce`; `InvalidateNonces` split per kind),
`src/guard.rs` (`CALL_TABLE` / `allowed` against `mtxSelectors()`, `_uaAllowed`, `selector_audit.json`, both directions; B's rule:
a derived subject on `_uaAllowed` only), `src/abi.rs`, `src/submit.rs`, `src/metatx.rs` (`Mtx`, `from_wire`), `src/chain.rs` and
`src/adapter.rs` (nonce view by kind: `mtxNonce(bytes32)` on tokens, the router and `wallet`, `mtxNonce(address)` on `account`), `src/indexer.rs`
(the `UA…` topics for EOAs; `pay_ref` on `UAPaymentSettled`), the legacy pull path's job decoder, `scaas-node/legacy/ua-mtx-merge/`;
tests in those modules. **Mandate wallets (Q6, T3b):** `typed.rs` `W` rows on the six `UA<Op>` structs, `UACancelNonce` on
`wallet`, `CancelNonce` and `Execute` on `account` only; `WA` splits (`mtxExecuteAsOwner` stays for `account`); the `PLAIN` rows
`mtxExecuteAsOwnerRaw`, flat `mtxPayUnderMandate`, `mtxRevoke` to legacy (MD-11 (a)); `mandate_shape` keeps its lanes on the UA
rows; the mandate KAT test reads `mandate_kat.json`; `guard.rs`'s wallet selector pins (lines 807–810 today) re-pinned and
`allowed` against the wallet's `_mtxRule` / `_uaAllowed`; `abi.rs`'s `IMandateWallet` errors with `bytes32`; `submit.rs`'s mandate
lane rows; every wallet op is a `ua_metatx` job.

**Interfaces:** every merged EVM entry is a `ua_metatx` job (`from` bytes32, `auth` `UASig`, `entry` the `mtx*` name); `metatx`
stays for the wallets' address entries and `executeMetaTransaction`; intake step 7a only for a derived `from` or `to` (R44); a
`metatx` job or a `struct: "transfer"` job naming a token's merged entry is refused by name (`OP_KIND_MISMATCH` per R43);
`HEX_ARGS_REFUSED` unchanged; untrusted decode bounded by length and depth.

- [ ] **Step 1: Failing tests:** `typed_ops_kat_every_entry` over the regenerated rows; `allow_lists_equal_the_selector_audit_both_directions`
      (token kinds added); `a_metatx_job_naming_a_merged_entry_is_refused_by_name`; `an_all_native_ua_metatx_runs_at_registry_zero`;
      `a_derived_side_at_registry_zero_is_refused_by_name`; `nonce_view_by_kind`; `indexer_reads_ua_topics_for_an_eoa`;
      `pay_ref_reads_ua_payment_settled`; `cancel_row_split_per_kind`; `wallet_rows_are_ua_structs` (both directions against
      the wallet's lists); `wallet_flat_builders_refused_by_name`; `wallet_nonce_view_is_bytes32`; `account_keeps_address_rows`; `never_dead_while_a_tx_may_land` unchanged.
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 typed guard metatx`: FAIL.
- [ ] **Step 3: Implement.** **Step 4:** PASS on the touched modules (the whole suite runs in T21).
- [ ] **Step 5: Mutants:** a row on the wrong kind; a derived subject allowed on `_mtxRule`; the nonce view by `address` on a
      token or a mandate wallet; the old shape accepted silently; a flat wallet builder left in `PLAIN`.
- [ ] **Step 6:** Commit `ua-mtx-merge T14: node rows, guard and jobs on the merged entries; old shapes refused by name`.

**Pins:** `submit.rs` literal selector pins moved with old → new; `the_plain_rows_are_pinned`. **Gates:** targeted `cargo test`, clippy.

### Task T15: gateway doors (Q7, R44)

**Depends on:** T14. Beside T16, T17.

**Files:** `scaas-node/src/gateway.rs` (routes at lines 117–118 today: `/v1/metatx`, `/v1/op`; `/v1/op` refuses a `ua*` entry
`FEATURE_UNSUPPORTED` at line 231), `src/gwauth.rs` if a namespace grant names the door, tests in `gateway.rs`.

**Interfaces:** `POST /v1/op` takes the merged named entries with `auth: UASig`; `POST /v1/ua-metatx` (new) takes
`UAMetaTransaction` / `UAMetaTransfer`, gate `features ∋ ua` and `registry() ≠ 0` only for a derived `from` or `to`; `POST /v1/metatx`
refuses a token and a mandate wallet by name (no address entry left, Q6) and still serves `SmartKeyAccount`.

- [ ] **Step 1: Failing tests:** `op_door_takes_a_merged_entry_with_uasig`, `ua_metatx_door_runs_an_eoa_at_registry_zero`,
      `ua_metatx_door_refuses_a_derived_side_at_registry_zero_by_name`, `metatx_door_refuses_a_token_by_name`,
      `metatx_door_serves_a_smart_key_account`, `metatx_door_refuses_a_mandate_wallet_by_name` (Q6), zero simulations on every refusal.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS. **Step 5: Mutants:** the `/v1/metatx` token refusal dropped; the
      registry gate applied to an all-native request; `auth` decoded as `bytes`.
- [ ] **Step 6:** Commit `ua-mtx-merge T15: gateway token doors on the merged entries`.

### Task T16: mesh `evm.ua_meta_tx` (Q7, R45)

**Depends on:** T14. Beside T15, T17.

**Files:** `scaas-node/src/mesh/{digest,accept,envelope}.rs`, `tests/mesh_vectors.rs`, `tests/vectors/mesh-envelope-v1.2.json`
(regenerated by `cargo test --test mesh_vectors -- --ignored regenerate`; the version per NODE-MESH-09's own rule, open item 3).

**Interfaces:** the EVM and Hedera token body `evm.ua_meta_tx` (the UA structs, camelCase named fields), intent id the UA digest;
the mandate wallets' body is the UA structs too (Q6), `SmartKeyAccount` keeps the address body; native subjects with today's `sig_kind`s over the UA digest; a derived `from` refused by name
(MD-10).

- [ ] **Step 1: Failing tests:** every regenerated KAT case through `accept()`; `a_token_address_body_is_refused_by_name`;
      `an_account_address_body_still_accepted`; `a_mandate_wallet_ua_body_accepted`; `intent_id_is_the_ua_digest`; `unbound_fields_carry_zero` (NODE-LANE-10);
      `a_derived_from_is_refused_by_name`.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, regenerate the KAT. **Step 4:** PASS.
- [ ] **Step 5: Mutants:** intent id over the address struct; the zero rule for unbound fields dropped; the old body accepted.
- [ ] **Step 6:** Commit `ua-mtx-merge T16: mesh EVM token body is the UA structs`.

### Task T17: node DEX (§3.4, new work)

**Depends on:** T14, T6. Beside T15, T16.

**Files:** `scaas-node/src/dex.rs` (book intake), `src/dex/venue.rs` (watcher), gateway's DEX routes (`/v1/dex/orders`,
`/v1/dex/cancel`, `/v1/dex/cancel-all`, in `gateway.rs` lines 251–257: route bodies only, T15 owns the token doors), tests.

**Interfaces:** `POST /v1/dex/orders` takes a `UATradeOrder` (`bytes32 from`, `bytes32 destination`, `UASig`) for a SCaaS sell
token, a `TradeOrder` for an outside leg; the UA cancel and the UA invalidate in the sell token's domain; a `UALegSettled`
watcher beside `LegSettled`; the `InvalidateNonces` row split per kind.

- [ ] **Step 1: Failing tests:** `book_takes_a_ua_trade_order_from_an_eoa`, `book_refuses_shape_zero_for_a_scaas_leg`,
      `cancel_all_signs_the_ua_invalidate`, `watcher_settles_on_ua_leg_settled`, `outside_leg_keeps_trade_order`, the DEX KAT rows.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS.
- [ ] **Step 5: Mutants:** `destination` dropped from the book's digest; `LegSettled` watched for a SCaaS leg; shape 0 accepted.
- [ ] **Step 6:** Commit `ua-mtx-merge T17: the node's book takes UATradeOrder for SCaaS legs`.

### Task T18: Hedera adapter and e2e

**Depends on:** T10, T15, T16, T17.

**Files:** `scaas-node/src/adapters/hedera.rs` (`MetaOp` v1 = `UAMetaTransfer`; its `HederaKat` reader), `tests/e2e.rs`,
`tests/e2e_hedera.rs`.

- [ ] **Step 1: Failing tests (ignored e2e, anvil):** `eoa_mtx_transfer_relayed_at_fee_zero_registry_zero`, `eoa_mtx_transfer_to_a_ua`,
      `derived_mtx_transfer_relayed`, `ordered_cancel_relayed`, `router_op_signed_by_an_eoa`, `dex_order_with_a_ua_trade_order_leg`,
      `gateway_doors_end_to_end`, `relayed_zether_proof_under_the_ua_tag`, `relayed_pqz_proof_under_the_ua_tag` (Zether and PQZ
      apart); `mandate_payment_relayed_by_an_eoa_delegate` (Q6, fee 0, no registry); Hedera: `hedera_kat_is_ua_meta_transfer`, `hedera_ed25519_eoa_relayed`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** `../scripts/capped cargo test -j2 --test e2e -- --ignored --test-threads=1`;
      `--test e2e_hedera -- --ignored`: PASS. No `anvil` left.
- [ ] **Step 5: Mutants:** the Hedera `from` padded as ECDSA for an ED25519 account; the e2e asserting `PaymentSettled` on a merged path;
      `tests/e2e.rs`'s wallet call still on `mtxExecuteAsOwnerRaw`.
- [ ] **Step 6:** Commit `ua-mtx-merge T18: Hedera adapter and e2e on the merged entries`.

### Regulated kinds 8–13 (owner 2026-11-05): tasks T24–T36

**Spec:** [`2026-11-05-regulated-kinds.md`](../specs/2026-11-05-regulated-kinds.md), revised after the Fable and Codex reviews
(2026-11-05), Q1–Q8 and F-01 answered by the owner. **Place:** after T18, before T19; T19, T21, T22, T23 cover the group.
**Order:** contracts T24 → T25 → T26 → T27 → T28 → T29 → T30 → T31 → T32 → T33, sequential in this worktree (shared
`GovernanceLib`, `ERC20MetaTx`, `UAMetaTxBase`, the layers, `size-baseline.json`); T34 (`clients/`, `smartcontracts/vectors/`)
beside T33 once T32 fixes the router ABI; T35 (node) after T33 and T34; T36 (invariants, mutants) after T33, beside T34–T35.
**Estimate:** 19 agent-days (the draft's sketch: 13). Every contracts task ends with the whole `forge test` green at the default
set and the size gate; a task touching a PQZ kind or `PqzLayer` also runs `script/pqz/at-set.sh <set> test --match-path
'test/{ua,pqz,as/confidential}/*'` at the four sets `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`
(one run per work tree, `PqzSet.sol` restored). Red first, positive control first, one change at a time; mutants one at a time on
a clean tree, logged `mutant | test that went red | rc`; heavy runs through `scripts/capped`, foreground.

### Task T24: `GovernanceLib`: the relaxation state machine, threshold holders, roles

**Depends on:** T18. **Estimate:** 3 (draft 1.5: the state machine of spec §3.6 is new work, F-03, Codex 2, Codex 3).

**Files:** `src/governance/{GovernanceLib,GovernanceBase,GovernanceBits,IGovernance}.sol`; the governed contracts' wrappers
(`src/metatx/{MetaTokenBase,WrappedToken}.sol`, `src/dex/SCaaSDex.sol`: the new arguments); tests `test/governance/GovRelax.t.sol`
(new), `test/governance/{GovDelay,GovGrant,GovAttackV2,GovRegulatedBits,GovIdentity,GovBitsVector}.t.sol` (re-pinned where the
commitment or an argument moves), `test/v2/layout/` (the `PendingGrant` label), `smartcontracts/vectors/governance/governance_bits.json`.

**Interfaces:**
- `PendingGrant.termsHash` → `commit` (same slot): `keccak256(abi.encode(action, bit, account, argsHash))`, actions `GRANT 1`,
  `SET 2`, `REVOKE 3`, `RENOUNCE 4`, `DISABLE 5`; `disableFeature` keys `account = 0`.
- `_due(s, bit, account, caller, commit)`: a live pending with another commit `GrantTermsMismatch`; another proposer
  `NotProposer(uint8 bit, bytes32 account, bytes32 proposer)` (new); before `eta` `GrantNotReady`; no live pending: propose,
  emit `GrantProposed` or `RelaxProposed(uint8 indexed bit, bytes32 indexed account, uint8 action, bytes32 proposer, uint64 eta)` (new).
- `revokeRole`, `renounceRole`, `disableFeature`, `setGrant` take the `delayedRelax` mask; on a masked bit with `grantDelay ≠ 0`
  they propose, and the effect (`barred`, `_clear`, `features`) happens at confirm only; `_narrowing` returns false on a masked bit
  for `validUntil ≠ 0 && validUntil < now + grantDelay`; the leaf path of `setGrant` takes the same delay for that edit.
  `disableFeature(uint8, bytes32) returns (bool applied)`. `cancelGrant`: the owner or the pending's proposer.
- `init`, `grantRole`, `setGrant`, `initHolder` take `address uaRegistry`; `_check` accepts a derived id on a contract-only bit in
  `GovernanceBits.REGULATED_ROLES` (5, 6, 7, 10, 21, new) iff `IUARegistry(uaRegistry).kindOf(id) == UAKinds.MSIG` (F-01); refuses
  `pad(address(this))` (`RoleAccountPool`, F-07).
- `init` grants `roles.issuer` each set bit of 5–7 and `roles.compliance` bit 10 (the `RoleWithoutFeature` refusals of today go);
  `RoleConflict(uint8 bit, bytes32 account)` (new) for one id holding 6 and 10 (init, `grantRole`, `setGrant`, a leaf); the
  `FeatureNotBuilt` refusal lifted; `GovernanceBase._delayedRelaxBits()` virtual, 0 by default; the plain kinds stop passing
  `| REGULATED`.

- [ ] **Step 1: Failing tests** (`GovRelax.t.sol`, each with its positive control): `test_relaxRevokeTakesTwoCalls`,
      `test_relaxRenounceTakesTwoCalls`, `test_relaxDisableTakesTwoCalls`, `test_relaxSetGrantShortValidUntilTakesTwoCalls`
      (owner and leaf path), `test_proposeChangesNothing` (role acts, `features` and `barred` unchanged),
      `test_grantThenRevokeExclude`, `test_revokeThenGrantExclude`, `test_ownerCannotConfirmHolderRenounce`,
      `test_holderCannotConfirmOwnerRevoke`, `test_acceptOwnershipKillsPendingRelax`, `test_confirmAfterWindowProposesAgain`,
      `test_cancelByProposer`, `test_disableReturnsAppliedOnlyAtConfirm`, `test_unmaskedBitsOneCallAsToday`,
      `test_grantDelayZeroOneCall`, `test_msigIssuerGranted`, `test_singleKeyDerivedIssuerRefused`,
      `test_msigRefusedForRateAdmin`, `test_selfRefusedAsHolder`, `test_roleConflictForceRecord_{init,grant,setGrant,leaf}`,
      `test_initGrantsIssuerAndCompliance`, `test_plainKindsRefuseRegulatedAsInvalid`; `RelaxProposed` topics.
- [ ] **Step 2:** FAIL. **Step 3: Implement.**
- [ ] **Step 4:** PASS; the existing `Gov*` suites green (re-pinned rows named in the commit); whole `forge test`; size gate
      (`GovernanceLib`, `SCaaSDex`, every token row old → new).
- [ ] **Step 5: Mutants:** the proposer not compared; the action left out of `commit`; `barred` set at propose; `features` cleared
      at propose; `ownerGeneration` not read; an `msig` accepted on `RATE_ADJUSTABLE`; any derived id accepted on bit 5;
      `RoleConflict` skipped on the leaf path.
- [ ] **Step 6:** Commit `ua-mtx-merge T24: GovernanceLib relaxation state machine, msig holders, issuer and compliance roles`.

**Pins, old → new:** `GovernanceLib` size; layout label; `GovDelay` / `GovGrant` rows whose commitment moved; gas of
`grantRole` / `setGrant` (`GovGas`). **Gates:** whole `forge test`, size gate.

### Task T25: `TokenConfig.reg`, `TokenStore` 8–13, the init ripple

**Depends on:** T24. **Estimate:** 1 (new: F-20 split out of the draft's T24).

**Files:** `src/factory/IFactoryToken.sol` (`RegulatedParams`, `TokenConfig.reg`, `ConfigFieldForOtherKind` NatSpec field 6),
`src/metatx/{TokenStore,MetaTokenBase,NormalToken,WrappedToken,WrappedLib}.sol` (constants `KIND_*_REGULATED` 8–13; a plain
kind refuses a non-zero `reg` with `ConfigFieldForOtherKind(6)`), `src/zether/ZetherWrappedLib.sol`, `src/pqz/PqzWrappedLib.sol`
(the kind id and the four masks from the token, no fixed `WRAPPED_*`), `script/DeployBase.sol`, `script/pqz/e2e.py`,
`script/ZetherE2E.s.sol`, `test/v2/{Factory,FactoryZether}.t.sol`, `scaas-node/tests/e2e.rs`.

**Interfaces:** `TokenConfig` gains `RegulatedParams reg` (spec §2.4); every `abi.encode(TokenConfig)` moves; no behaviour on
kinds 0–5 beyond the refusal.

- [ ] **Step 1: Failing tests:** `test_plainKindRefusesReg_{0..5}`, `test_wrappedZetherInitTakesKindMasks`,
      `test_wrappedPqzInitTakesKindMasks`, `e2e.py --self-test` row for the new field.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets (`PqzWrappedLib`); size gate;
      `cargo test --test e2e --no-run` compiles.
- [ ] **Step 5: Mutants:** `reg` ignored on a plain kind; `PqzWrappedLib` back on the fixed masks.
- [ ] **Step 6:** Commit `ua-mtx-merge T25: TokenConfig.reg, kinds 8-13 constants, init with the kind's masks`.

**Pins, old → new:** `Factory.t` encodings; sizes. **Gates:** whole `forge test`, four sets, size gate.

### Task T26: the eight empty hooks; "+0" pinned in slots and gas

**Depends on:** T25. **Estimate:** 1 (draft 0.5: eight hooks, more seats, the gas pin, F-10, F-35).

**Files:** `src/metatx/{UAMetaTxBase,ERC20MetaTx,MetaTokenBase,WrappedToken}.sol`, `src/zether/ZetherLayer.sol`,
`src/pqz/PqzLayer.sol`; `test/governance/PlusZero.t.sol` (every kind 0–5 and the router; slots and gas);
`smartcontracts/vectors/governance/plus_zero_slots.json` (unchanged rows for 0–5).

**Interfaces:** spec §2.2's eight hooks with empty bodies and raw arguments, at every seat of §2.2, §3.2, §4.1, §4.2: `_regPre`
before every `pre*` (`_uaExecute`, `_namedCallUA`, `mtxCancelNonce`, `_execute`, `_namedCall`, `_uaExecuteTransfer`),
`_regFeeTo` after it and in `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`, `mtxRelayFee`, `mtxWrapOrder`; `_regMove` in
`_update` and `_uaMove`; `_regPayer`, `_regSender`, `_regName`, `_regReceiver`, `_regZetherSender` at the confidential, wrap and
`approve` seats; `supportsInterface` made `virtual`. No storage, no ABI change.

- [ ] **Step 1: Failing tests:** `test_plusZeroSlots_{kind}` and `test_plusZeroGas_{kind}` for kinds 0–5 and the router on the
      four I0 entries (the gas rows fail first: the pin is written from the pre-change run, then moved old → new only if the
      compiler moves it, with the figures in the commit); `test_hookSeatsCalled` (a test-only subclass overriding each hook with a
      revert proves every seat of the spec's tables is reached, direct and relayed).
- [ ] **Step 2:** FAIL (the seat test). **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate.
- [ ] **Step 5: Mutants:** `uaOf` evaluated at the Zether call site; a `features` read in the base `_regMove`; a seat dropped
      (`mtxCancelNonce`, `mtxWrapOrder`, the `COMPACT` multi entry) — each turns `test_hookSeatsCalled` or a gas pin red.
- [ ] **Step 6:** Commit `ua-mtx-merge T26: eight empty regulated hooks at every seat; +0 pinned in slots and gas`.

**Pins, old → new:** gas of every kind's I0 entries and the router; sizes of every kind. **Gates:** whole `forge test`, four
sets, size gate.

### Task T27: measure first — kinds 9 and 13 on a skeleton

**Depends on:** T26. **Estimate:** 1 (new: F-19).

**Files:** `src/regulated/{RegulatedBase,RegulatedLib,IRegulatedToken,WrappedRegulatedToken,WrappedPqzRegulatedToken}.sol`
(skeleton: every hook override wired, the eight stubs and the views at their final arity, bodies reverting with a placeholder
error that T28 replaces), `script/DeployBase.sol` (the two releases), `size-baseline.json` (two rows, reason in
`_comment`), `smartcontracts/evm/runs/<date>-ua-mtx-merge-regulated-sizes.txt` (summary, no absolute paths).

- [ ] **Step 1:** Build the skeleton; `forge build src --sizes --json`; deploy gas of both releases by `DEPLOY_GAS` on the
      method of spec §6.2.
- [ ] **Step 2:** Report to the controller: runtime B and asked gas of kinds 9 and 13 against the §6.2 estimate. **Stop rule (owner
      2026-11-06, the pay-meta-tax spec's O18 and §6.4):** kind 13 is measured first; at or above the stop line **64,512 B** it is
      reduced lever by lever, the levers of the pay-meta-tax spec §6.4 that apply to the regulated code (thin stubs into `RegulatedLib`, bodies and events in `RegulatedLib`, one struct view, error consolidation), in order, each under that section's checklist, re-measured after each, until it is under; back to the controller only when every
      lever is used. No `_above64KiB` row. A figure more than 50 % over the estimate is still reported to the controller before
      T28.
- [ ] **Step 3:** whole `forge test`; the four sets; size gate.
- [ ] **Step 4:** Commit `ua-mtx-merge T27: regulated skeleton, kinds 9 and 13 measured first`.

**Pins:** two `size-baseline.json` rows (replaced by T33's final measurement). **Gates:** whole `forge test`, four sets, size gate.

### Task T28: `RegulatedLib`, `RegulatedBase`, kinds 8 and 9 (Hedera included): FREEZE, RECORD, FORCE, PAUSE, the fee seats

**Depends on:** T27. **Estimate:** 3 (draft 2: the transition table, RECORD disabled, the fee seats, the pause-open set, the
cancel, the mirror sync).

**Files:** `src/regulated/{RegulatedBase,RegulatedLib,IRegulatedToken,NormalRegulatedToken,WrappedRegulatedToken}.sol`;
`test/as/{Freeze,Record,Force,Pause,FeeLegs,Mirror,RegulatedInit,RegulatedHedera}.t.sol`; `test/v2/layout/namespaces.json`
(`scaas.regulated`); `script/DeployBase.sol` (kind 8 release; Hedera `IS_HEDERA` rows).

**Interfaces:** spec §2.3 storage; §2.4 init checks; §3.1 entries (`nonReentrant`, `_govSubject()` passed as a word), views,
errors, events; §3.2 rows; §3.3 transitions T1–T9; §3.4 pause; `disableFeature` override clearing the mirror only when
`applied` (on kind 9 `override(WrappedToken, RegulatedBase)`); `supportsInterface` adds `IRegulatedToken`.

- [ ] **Step 1: Failing tests** (positive control first): one test per transition cell T1–T9; `test_recordDisabledEndsBackedFreezesStopsForce`,
      `test_revokeOrderRunsWithRecordDisabled`, `test_revokeOrderEmitsAccountUnfrozen`, `test_forceZeroRefused`,
      `test_freezeTargetsRefused` (0, both pools, `this`); `test_preRefusesFrozenBeforeSignature` (a bad signature with a frozen
      `from` reverts `Frozen`, not a signature error; per signer class); the pause-open set on the named, generic and address
      paths (`unwrap` ×2, `unwrapToUA`, `burn` at fee mode `NONE` pass; each with a fee refused; `cancelNonce` refused);
      `test_cancelNonceFrozenRefused_{8,9}`; the fee seats: `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee` (frozen payee;
      frozen fee recipient), `mtxRelayFee` (frozen payee), `mtxWrapOrder` (frozen submitter; frozen `o.from` with another
      destination); `test_dexRelayerShareIsOrdinaryCredit`; the Codex 3 pins: a `disableFeature(FREEZE)` and `(PAUSE)` proposal,
      cancellation, early confirm and expired confirm leave frozen accounts frozen and the pause on;
      `test_controlsEqualFeaturesMask`; `test_supportsIRegulatedToken_{8,9}` and not on 0–5; Hedera: kinds 8, 9 freeze and pause
      under `IS_HEDERA`.
- [ ] **Step 2:** FAIL. **Step 3: Implement** (the skeleton's placeholders replaced).
- [ ] **Step 4:** PASS; whole `forge test`; size gate (kinds 8, 9, `RegulatedLib`).
- [ ] **Step 5: Mutants** (spec §9 rows FREEZE, Relaxation, FORCE, PAUSE, Fee legs): `recordId` not cleared on `unfreeze`; T4
      without the `≥ until` check; `revokeOrder` not ending the backed freeze; `counts[10].roots` read without the `RECORD` bit;
      the mirror cleared at propose; the wrapped override not composed; the open set on the outer selector; `burn` paused at fee 0;
      `_regFeeTo` dropped from `payWithFee`, from `mtxWrapOrder`, from `mtxRelayFee`; `F(from)` moved after `pre*`.
- [ ] **Step 6:** Commit `ua-mtx-merge T28: RegulatedLib and kinds 8, 9: freeze transitions, record, force, pause, fee seats`.

**Pins, old → new:** layout `scaas.regulated` (new); sizes; `WrappedToken.disableFeature` composition. **Gates:** whole `forge
test`, size gate.

### Task T29: `ComplianceRegistry`, the bounded call, the code pin; `ALLOWLIST`, `DENYLIST`

**Depends on:** T28. **Estimate:** 1.5 (draft 1: the bounded call, the codehash pin, the failure modes).

**Files:** `src/regulated/{ComplianceRegistry,IComplianceRegistry}.sol` (admin in storage, written once by the constructor);
`src/regulated/RegulatedBase.sol` (`_hasFlags`: gas cap `REGISTRY_GAS`, starvation check, 32-byte output, 0 or 1, named failure);
`REGISTRY_CODEHASH` immutable from `implArgs`; `script/DeployBase.sol` (the hash in each regulated release's `implArgs`);
`test/as/{Registry,Receiver,RegistryFailure}.t.sol`; `test/as/RegistryStubs.sol` (reverting, gas-burning, short-return,
2-returning stubs, installed by `vm.etch`).

**Interfaces:** spec §5; `REGISTRY_GAS` set to at least twice the canonical `hasFlags` measured cold, pinned in a test; the call
budget of spec §5 asserted per path.

- [ ] **Step 1: Failing tests:** the `R` truth table (both bits, `ELIGIBLE_CONTRACT` on each side, lapsed, `validUntil == now`
      passes, disabled attester); `test_registryCodehashPinned` (another code refused `RegistryCodeMismatch`);
      `test_registryFailureNeverEligible` (each stub: transfer, mint and a fee leg fail `RegistryUnavailable`; burn and unwrap pass);
      `test_registryStarvedReverts`; `test_registryGasPinned`; `test_callBudgetPerPath`; `test_attesterDisableVoids`;
      `test_eligibleContractAdminOnly`; `test_canReceiveReasons`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; size gate.
- [ ] **Step 5: Mutants:** `ELIGIBLE_CONTRACT` ignored; a lapsed attestation passes; a disabled attester passes; a failed call
      read as eligible; the gas cap removed; `ELIGIBLE_CONTRACT` passing `deniedFlags`; the codehash check skipped.
- [ ] **Step 6:** Commit `ua-mtx-merge T29: ComplianceRegistry, bounded registry call, codehash pin, allowlist and denylist`.

**Pins:** `REGISTRY_GAS`; registry runtime hash; sizes. **Gates:** whole `forge test`, size gate.

### Task T30: Zether kinds 10 and 11

**Depends on:** T29. **Estimate:** 1.

**Files:** `src/regulated/{NormalZetherRegulatedToken,WrappedZetherRegulatedToken}.sol` (the layer hooks forwarded to
`RegulatedBase`); `script/DeployBase.sol` (under `DEPLOY_ZETHER=1`); `test/as/confidential/Zether{Freeze,Pause,Receiver,Force}.t.sol`.

**Interfaces:** spec §4.1, §4.3: `_regZetherSender(t.yFrom)` and `_regName` in each direct multi entry before `_multi`
(`BUNDLE` and `COMPACT`) and in the single entry; unshield and unshield-unwrap at the top; shield and wrap-shield `_regPayer()`;
roll-over untouched. `ZetherLib` unchanged.

- [ ] **Step 1: Failing tests:** a frozen `yFrom` refused before the proof on `mtxConfidentialTransfer`, `…Compact`, `…Single`,
      direct and signed (`< 200 k` plus the signer class); a frozen and a denied decoy succeed (I9); a frozen beneficiary refused;
      the envelope subject never used as the sender; `PAUSE` stops shield, wrap-shield, transfers, unshield, unshield-unwrap, and
      roll-over stays open; a not fee-bearing relayed op by a frozen envelope `from` passes, a fee-bearing one is refused;
      `FORCE` and `MODERATE` leave `ZetherLib` state unchanged (state diff, I8).
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; `zether-cross`; size gate.
- [ ] **Step 5: Mutants:** the multi check dropped from the `COMPACT` entry; the envelope subject used as the sender; a check
      after the proof; `R` on a decoy leg; a Zether site hook in `PqzLayer`.
- [ ] **Step 6:** Commit `ua-mtx-merge T30: regulated Zether kinds 10 and 11`.

**Gates:** whole `forge test`, size gate.

### Task T31: PQZ kinds 12 and 13, four sets

**Depends on:** T30 (sequential in the worktree; Zether ≠ PQZ: separate task, tests and commit). **Estimate:** 1.5.

**Files:** `src/regulated/{NormalPqzRegulatedToken,WrappedPqzRegulatedToken}.sol`; `script/pqz/e2e.py` (kinds 12, 13);
`test/as/confidential/Pqz{Freeze,Pause,Receiver,Force,Refresh}.t.sol`.

**Interfaces:** spec §4.2, §4.3: first in `_single` / `_multi` / `_burn`, before `_pullShieldIn`; the `shieldIn` payer by
`_regPayer()`; the refresh (`amount = 0`) open under `FREEZE` and `PAUSE`; `R(recipient)` only when the amount is not 0.

- [ ] **Step 1: Failing tests:** a frozen `fromUA` refused before the proof on the four transfer entries and unshield; a frozen
      `shieldIn` payer refused; `test_refreshOpenUnderFreezeAndPause` (and its `shieldIn ≠ 0` variant refused under `P`);
      unshield-unwrap refused under `P` on 13; prepare and roll-over open; `FORCE` and `MODERATE` leave `acc`, pending and
      `totalShielded` unchanged (I8).
- [ ] **Step 2:** FAIL. **Step 3: Implement.**
- [ ] **Step 4:** PASS; whole `forge test`; `at-set.sh` at the four sets (`test/{ua,pqz,as/confidential}`); size gate (kind 13
      against the 64,512 B stop line and T27's figure; at or above it, reduce as T27's stop rule).
- [ ] **Step 5: Mutants:** `shieldIn` payer unchecked; the check after `_pullShieldIn`; refresh refused under `FREEZE`; `R` asked
      of a refresh's zero recipient.
- [ ] **Step 6:** Commit `ua-mtx-merge T31: regulated PQZ kinds 12 and 13, four sets`.

**Gates:** whole `forge test`, four sets, size gate.

### Task T32: `MODERATE` (Q1), the eight router ops, `selector_audit.json`

**Depends on:** T31 (sequential; the router ABI is final at its end). **Estimate:** 1.

**Files:** `src/regulated/RegulatedBase.sol` (`moderatedTransfer`), `src/governance/{GovernanceRouterBase,IGovernanceRouter}.sol`
(eight `mtx<Op>` over `UA<Op>`, fee mode `NONE`), `test/governance/{GovRouter,GovRouterTypehash,SelectorAudit}.t.sol`,
`test/as/Moderate.t.sol`, `test/vectors/selector_audit.json`.

- [ ] **Step 1: Failing tests:** `test_routerRow_<Op>` for the eight, a contract holder and an `msig` holder; eight `UA<Op>`
      typehash pins; `moderatedTransfer` refusals (amount 0, `from == to`, pools, `this`, a native `from` with code, a non-SIGNING
      derived `to`); a frozen `from` cannot be moderated past `F`; the eight direct entries classified as the existing powers.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; size gate (router old → new).
- [ ] **Step 5: Mutants:** moderated on `_poolMove`; `from` with code accepted; `target` out of a `UA<Op>` digest; a router row on
      the token domain.
- [ ] **Step 6:** Commit `ua-mtx-merge T32: MODERATE and the eight router control ops`.
      **Owner 2026-11-05 (CTR-GOV-20):** the transfer power is `operatorTransfer` on bit 22 `OPERATOR_TRANSFER` (any holder,
      kinds 8–13 only, router op `mtxOperatorTransfer`), in place of `moderatedTransfer` on bit 21; bit 21 gets no body.

**Pins, old → new:** router typehashes (+8); `selector_audit.json`; router size and CREATE2 address. **Gates:** whole `forge
test`, size gate.

### Task T33: deploy — releases 8–13, the registry, sizes and deploy gas

**Depends on:** T30, T31, T32. **Estimate:** 1.

**Files:** `script/DeployBase.sol` (releases 8–13, `RegulatedLib` in `Env.libs` and `libCodeHashes`, `REGISTRY_CODEHASH` in
`implArgs`), `smartcontracts/scripts/deploy.sh` (`DEPLOY_REGULATED=1`: the canonical registry with `COMPLIANCE_ADMIN`, the
`ELIGIBLE_CONTRACT` attestations of `SCaaSDex` and `DexPuller`), `script/pqz/e2e.py`, `test/v2/LinkClosure.t.sol`,
`test/governance/GovDeploy.t.sol`, `size-baseline.json` (six rows by measurement, T27's two replaced), `scaas-node/node.example.toml`
(`compliance_registry`), `smartcontracts/evm/runs/<date>-ua-mtx-merge-regulated-deploy-gas.txt`.

- [ ] **Step 1: Failing tests:** `test_regulatedReleasesPublished_{8..13}`, `test_linkClosureWithRegulatedLib`,
      `test_registryDeployedAndDexAttested`, `e2e.py --self-test` rows for 12, 13.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate (`--self-test`
      first; `_above64KiB` printed and empty for 8–13); every regulated release under the 64,512 B stop line, else reduced as
      T27's stop rule (owner 2026-11-06, no `_above64KiB` fallback); deploy gas of every regulated release against 60 M and 70 M (the TODO gap line per Q7).
- [ ] **Step 5: Mutants:** `RegulatedLib` missing from `libCodeHashes`; the registry hash left out of `implArgs`.
- [ ] **Step 6:** Commit `ua-mtx-merge T33: regulated releases 8-13, registry deploy, sizes and deploy gas`.

**Pins, old → new:** six size rows; the deploy-gas summary. **Gates:** whole `forge test`, four sets, size gate.

### Task T34: vectors and clients

**Depends on:** T32 (ABI final); beside T33. **Estimate:** 1.

**Files:** `smartcontracts/vectors/` (`typed_ops.json` +8 router rows by `typed-ops-vectors.mjs`; `governance_bits.json` bits
5–10, 21 with the `msig` rule; new `governance/regulated_kat.json`: `recordId`, the `R` truth table, transitions T1–T9, the
relaxation `commit` rows), the forge writer of `regulated_kat.json`, `clients/clientkeys` (builders and readers), `clients/ua-rs`
(signs the eight ops from the table; its wrappers re-run).

- [ ] **Step 1: Failing tests:** `clientkeys` digests of the eight `UA<Op>` with a non-zero unbound `relayer` / `feeRecipient`;
      `regulated_kat.json` rows read by `clientkeys` and `ua-rs`; the `commit` of each action reproduced.
- [ ] **Step 2:** FAIL. **Step 3: Implement**; generators write the vectors. **Step 4:** PASS; `node --test`; `ua-rs` and wrappers;
      the generators re-run, `git diff --exit-code`.
- [ ] **Step 5: Mutants:** `UAForceTransfer` field order swapped; `relayer` left non-zero in a canonical digest; a `commit` action
      tag swapped.
- [ ] **Step 6:** Commit `ua-mtx-merge T34: regulated vectors, clientkeys and ua-rs rows`.

### Task T35: node rows, guard, errors, indexer, venue

**Depends on:** T33, T34. **Estimate:** 1.5.

**Files:** `scaas-node/src/{typed,guard,indexer,dex}.rs` and the error table; `scaas-node/tests/e2e.rs` (ignored, anvil).

**Interfaces:** spec §7: kinds 8–13 on their base kind's rows, equality both directions per kind; 8 `gov_router` rows; named
decode of the §3.1 errors and `NotProposer` as refusals, never `dead` while a tx may land; topics and alerts (`OrderRecorded`,
`RelaxProposed`, `AccountFrozen`, `Paused`); the NODE-DEX-11 pre-check; a market with a regulated leg halts on `Paused` and
reopens on `Unpaused` or at `pausedUntil`; `TokenPaused` never grief-scored.

- [ ] **Step 1: Failing tests:** `regulated_kinds_rows_equal_contract_{8..13}` (both directions), `router_control_rows`,
      `frozen_revert_is_refusal_not_dead`, `registry_unavailable_is_refusal`, `market_halts_on_paused_and_reopens`,
      `token_paused_not_grief_scored`, `alert_on_relax_proposed`; e2e: `regulated_freeze_relayed_by_router`,
      `regulated_transfer_refused_frozen`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `CAPPED_MEM=6G ../scripts/capped cargo test` alone; clippy
      `-D warnings`; `--test e2e -- --ignored --test-threads=1`. No `anvil` left.
- [ ] **Step 5: Mutants:** a kind 8–13 row missing on one side; `Frozen` decoded as `dead`; the market not halted on `Paused`.
- [ ] **Step 6:** Commit `ua-mtx-merge T35: node rows, errors, alerts and venue for regulated kinds`.

### Task T36: invariant suite I1–I13 and the mutant harness

**Depends on:** T33; beside T34, T35. **Estimate:** 1.5 (draft 1: I12, I13 and the reviews' mutants).

**Files:** `test/as/invariant/Regulated{Handler,Invariants}.t.sol`; `smartcontracts/evm/runs/<date>-ua-mtx-merge-regulated/`
(`mutants.py`, `README.md`, the summary `mutant | test that went red | rc`, no absolute paths).

- [ ] **Step 1:** Handlers over every regulated entry, the relaxation calls and the ledger paths; invariants I1–I13 of spec §8.
- [ ] **Step 2:** Run at the default set; PQZ handlers at the four sets.
- [ ] **Step 3: Mutants:** every row of spec §9 not already killed in T24–T35 (the harness re-runs those too); a survivor is a
      finding for its owning task.
- [ ] **Step 4:** Commit `ua-mtx-merge T36: regulated invariants I1-I13 and the mutant harness, <n> kills`.

**Gates:** whole `forge test`, four sets.

### Payment metadata, free pay lanes, tax (group 3e, owner approved 2026-11-06): tasks T37–T43

**Spec:** [`2026-11-05-pay-meta-tax.md`](../specs/2026-11-05-pay-meta-tax.md), revised after the Codex and Fable reviews
([Codex](../../research/paytax-codex-review.md), [Fable](../../research/paytax-fable-review.md)); rulings O1–O17, every
question answered (spec §11). **Place:** after T36, before 3c (`PqChat` and the registry generation); T19, T21, T22, T23 cover
the group. **Order:** contracts T37 → T38 → T39 → T40, sequential in this worktree (shared `MetaTokenBase`, `ERC20MetaTx`,
`RegulatedLib`, `size-baseline.json`); T41 (`clients/`, `smartcontracts/vectors/`) after T40 fixes the ABI; T42 (node) after T41;
T43 (invariants, mutants) after T40, beside T41–T42. **Estimate:** 14.5 agent-days, plus 0.5 on T19 (15 in all). Every contracts
task ends with the whole `forge test` green at the default set and the size gate; T37 and T40 also run `script/pqz/at-set.sh <set>
test --match-path 'test/{ua,pqz,as/confidential}/*'` at the four sets (one run per work tree, `PqzSet.sol` restored). Red first,
positive control first, one change at a time; mutants one at a time on a clean tree, logged `mutant | test that went red | rc`;
heavy runs through `scripts/capped`, foreground. Legacy copies (MD-4) are the first commit of each task that replaces a body.

### Task T36a: PQZ op 1 memo in op 7's encoding (owner 2026-11-06, CTR-PQZ-23 Change)

**Depends on:** T36. **Estimate:** 0.5. **Why:** op 1's memo (57 B, `SEALED = 41`) and op 7's (`18 + 40·M`, M byte, keystream
label `"PQZ/memo/ks/v1"`) were two encodings, and pqz-core builds only op 7's; the owner made op 1 use op 7's encoding with
M = 1 and approved both labels. **Files:** `src/pqz/PqzCore.sol` (`SEALED` 41 → 42, i.e. `2 + 40·1`), its tests, the PQZ docs
(`pq-zero-knowledge.md` CTR-PQZ-23 text), any op 1 memo vector row or `e2e.py` builder. No statement, relation or
`proofSystemId` change (`memoHash` is a header word). - [ ] Red: an op 1 HASH transfer with a 42-byte sealed memo is
refused today; green after; a 41-byte one refused after. **Mutants:** the old length kept; op 7's length rule applied with
M = 0. **Gates:** whole `forge test`, the four sets on `test/{ua,pqz,as/confidential}`, size gate. **Commit:** `ua-mtx-merge
T36a: PQZ op 1 memo in op 7's encoding`. The client side (ua-rs facade op 1 memo through `memo::seal` with one leg) is a
`ua-rs-sign` follow-up of T15.

### Task T37: pay entries with `PayMeta`, free pay lanes, the mandate wallets

**Depends on:** T36. **Estimate:** 3.

**Files:** `src/metatx/{MetaTokenBase,ERC20MetaTx,IMetaTokenV2,IERC20Payment}.sol`, `src/common/MetaTxLib.sol` (`PayMeta`),
`src/wallet/MandateWallet.sol`, `src/hedera/HederaMandateWallet.sol`; `legacy/ua-mtx-merge/` (flat `mtxPay`, `mtxPayMeta`,
`_uaPayMeta`, `_uaPay`, `metaPayId(bytes32,bytes)`, the old `PaymentMeta`, the six-argument `payWithFee` / `payWithFeeToUA`, the
receiver-fee lane shape, the wallets' old pay entries); tests `test/metatx/{PayMeta,PayLanes}.t.sol` (new / rewritten),
`test/metatx/MtxRelayFee.t.sol`, `test/wallet/{MandateWallet,MandateWalletMerged}.t.sol`, `test/hedera/{HederaV2,HederaKat}.t.sol`,
every `test/` and `script/` caller of `mtxPay(`, `metaPayId`, `payWithFee`, `payLane`; `test/v2/MetaTxGasV2.t.sol`; the mandate KAT;
`smartcontracts/vectors/metatx/paymeta.json` (regenerated; old copy to `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/`) and its
generator; `size-baseline.json`.

**Interfaces:**
- `struct PayMeta { bytes32 salt; string payNo; uint16 schema; bytes body; }`; `metaPayId(PayMeta) = keccak256(abi.encodePacked(
  "scaas.pay.meta.v2", salt, keccak256(abi.encode(payNo, schema, body))))`; `_payMeta(entryRef, meta)`: `salt ≠ 0`, `schema == 0 ⇔
  body empty` (`PayMetaShape`), `bytes(payNo).length ≤ 256` (`PayNoTooLong`), `entryRef == metaPayId(meta)` (`PayMetaMismatch`),
  then `PaymentMeta(bytes32 indexed payId, string payNo, uint16 schema, bytes body)`.
- `mtxPay(UAMetaTransfer t, UASig auth, PayMeta meta)`; `mtxPayReceiverFee(…, UASig payeeAuth, PayMeta meta)` without the
  `payLane` / nonce-0 terms; `payWithFee(…, bytes32 entryRef, PayMeta meta)`; `payWithFeeToUA(…, bytes32 entryRef, PayMeta meta)`;
  free `batch` / `nonce` on every pay entry; `payLane` kept as a view; `mtxExecuteTransfer` / `mtxBatchTransfer` unchanged (O12).
- `MandateWallet` / `HederaMandateWallet`: the pay entries gain `PayMeta meta` last (unsigned, bound by `entryRef`); `refUsed`
  unchanged.

- [ ] **Step 1: Failing tests** (each with its positive control): `test_payMeta_saltZeroRefused`, `test_payMeta_schemaZeroWithBody`,
      `test_payMeta_schemaWithEmptyBody`, `test_payMeta_payNo256Passes`, `test_payMeta_payNo257Refused`, `test_payMeta_otherPayNoMismatch`,
      `test_payMeta_oldTagRefused`, `test_payMeta_emittedBeforeSettled`, `test_mtxPay_freeLane`, `test_mtxPay_payLaneConventionStillWorks`,
      `test_mtxPay_twoPartialsSameRef`, `test_mtxPayMeta_selectorAbsent`, `test_payWithFee_entryRefZeroRefused`,
      `test_payWithFeeToUA_metaMismatch`, `test_receiverFee_freeLane`, `test_receiverFee_coSignDeadAfterNonceUsed`,
      `test_genericPath_landsWithoutPaymentMeta` (O12 pinned), `test_mandateWallet_payWithMeta`, `test_mandateWallet_metaMismatch`
      (and the Hedera twin); `paymeta.json` rows read by the forge test.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, kind 13 first (one pay entry converted, size measured, then the rest).
- [ ] **Step 4:** PASS; whole `forge test`; the four sets; size gate. **Stop rule (spec §6.4, O18):** kind 13 first, then every
      kind; a kind at or above **64,512 B** is reduced by spec §6.4's levers in order (5 and 7 are the ones that touch T37's code),
      one at a time, re-measured after each, until it is under; back to the controller only when every lever is applied. No
      `_above64KiB` row.
- [ ] **Step 5: Mutants:** `payNo` left out of the hash; the old tag; the salt-0 refusal dropped; the schema/body rule dropped;
      `_payMeta` after the transfer; the 256-byte bound off by one; `PaymentMeta` skipped; `payLane` still enforced in receiver-fee;
      the wallet passing an empty `PayMeta`.
- [ ] **Step 6:** Commit `ua-mtx-merge T37: PayMeta on every pay entry, free pay lanes, mandate wallets`.

**Pins, old → new:** `MetaTxGasV2` `mtxPay` rows (and every kind's pay entries if lever 5 is applied); `UA*` typehash pins unchanged (checked); ERC-165 ids of `IMetaTokenV2`,
`IERC20Payment`; sizes of every kind and both wallets; mandate KAT; wallet CREATE2 addresses. **Gates:** whole `forge test`, four
sets, size gate.

### Task T38: relay fee on free lanes

**Depends on:** T37. **Estimate:** 1.

**Files:** `src/metatx/{MetaTokenBase,MtxRelayFee,IERC20MetaTx}.sol`, `script/DeployBase.sol`, `legacy/ua-mtx-merge/` (old
`UA_RELAY_FEE_TYPEHASH`, `_relayHash`, the old `mtxRelayFee` and `relay`), `test/metatx/MtxRelayFee.t.sol`, the typehash pin test.

**Interfaces:** `UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256
nonce,uint256 validUntil,address relayer)`; token `mtxRelayFee(…, uint256 batch, uint256 nonce, uint256 validUntil, UASig)`;
`MtxRelayFee.relay(…, uint256 batch, uint256 nonce, uint256 validUntil, UASig)`, with a `RelayPay` struct only if the legacy
decoder runs out of stack (measured here); `relayRef` unchanged; open mode unchanged on every kind (O14).

- [ ] **Step 1: Failing tests:** `test_relayFee_staleNonce`, `test_relayFee_oldTypehashRefused`, `test_relayFee_dedicatedLane`,
      `test_relayFee_twoSignaturesReplayableTargetPaysTwice`, `test_relayFee_guardedTargetSecondReverts`,
      `test_relayFee_openModeFrozenSubmitterPaid` (O14's limitation pinned on a regulated kind), the typehash pin.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; size gate.
- [ ] **Step 5: Mutants:** `batch` or `nonce` left out of the hash; the router not passing `nonce`; `relayRef` changed.
- [ ] **Step 6:** Commit `ua-mtx-merge T38: relay fee with batch and nonce`.

**Pins, old → new:** `UARelayFee` typehash; `MtxRelayFee` and executor CREATE2 addresses; sizes. **Gates:** whole `forge test`,
size gate.

### Task T39: bit 23 `TAX`, `RegulatedLib` tax bodies, router ops

**Depends on:** T38. **Estimate:** 1.5.

**Files:** `src/governance/{GovernanceBits,GovernanceLib,GovernanceRouterBase,IGovernanceRouter}.sol`,
`src/regulated/{RegulatedBase,RegulatedLib,IRegulatedToken}.sol` and the six kind contracts (masks, stubs, view),
`src/factory/IFactoryToken.sol` (`RegulatedParams.taxRecipient`) and the `TokenConfig` ripple of the regulated spec §2.4
(`ZetherWrappedLib`, `PqzWrappedLib`, `DeployBase`, `script/pqz/e2e.py`, `script/ZetherE2E.s.sol`, the factory tests,
`scaas-node/tests/e2e.rs`); `test/as/Tax.t.sol` (new), `test/governance/{GovRouter,GovRouterTypehash,SelectorAudit,GovRegulatedBits}.t.sol`,
`test/v2/layout/` (`scaas.regulated` +5, +6), `test/vectors/selector_audit.json`, `smartcontracts/vectors/governance/governance_bits.json`.

**Interfaces:** `GovernanceBits.TAX = 23` in `ISSUER_BITS` and `_roleBits()` of 8–13, not in `_contractOnlyBits()`,
`REGULATED_ROLES` or `_delayedRelaxBits()` (O9, O16); `init` grants `roles.issuer` bit 23 and accepts an issuer holding only 23;
storage +5 `taxRecipient`, +6 `TaxRate { uint32 ratePpm; uint32 pendingPpm; uint64 eta; }`; `setTaxRate(uint32)` (≤ 10^6; a
decrease at once, an increase pending `eta = now + IOpenFactory(FACTORY).noticePeriod()`, the period read in the token and passed
to the library), `setTaxRecipient(bytes32)` (not 0, pools, the token; a derived id SIGNING; `!F`, `R` at set time), events
`TaxRateSet`, `TaxRecipientSet`; view `taxConfig()`; router ops `mtxSetTaxRate`, `mtxSetTaxRecipient` over `UASetTaxRate`,
`UASetTaxRecipient`, fee mode `NONE`.

- [ ] **Step 1: Failing tests:** `test_taxBit_plainKindRefuses_{0..5}`, `test_taxBit_validOn_{8..13}`, `test_taxBit_eoaHolderGrantedAfterCreation`,
      `test_taxBit_issuerOnlyBit23Init`, `test_taxRecipientZeroInitRefused_{11,13}`, `test_setTaxRate_decreaseImmediate`,
      `test_setTaxRate_increaseNotBeforeEta`, `test_setTaxRate_increaseAtEta`, `test_setTaxRate_decreaseCancelsPending`,
      `test_setTaxRate_noticeZeroImmediate`, `test_setTaxRecipient_{pool,token,unregistered,frozen,unattested}Refused`,
      `test_setTaxRecipient_paddedNativeAccepted`, `test_routerRow_{SetTaxRate,SetTaxRecipient}` (EOA, `msig`, contract holders,
      fee 0); two typehash pins; `RoleRevoked(23)` and `disableFeature(23)` immediate.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets (`PqzWrappedLib`); size gate.
- [ ] **Step 5: Mutants:** bit 23 accepted on a plain kind; in `_contractOnlyBits()`; missing from `ISSUER_BITS`; in
      `_delayedRelaxBits()`; an increase effective before `eta`; a decrease delayed; the recipient set without the `R` check.
- [ ] **Step 6:** Commit `ua-mtx-merge T39: bit 23 TAX, the tax rate and recipient, router ops`.

**Pins, old → new:** layout of `scaas.regulated`; router typehashes (+2), router size and CREATE2 address; `selector_audit.json`;
`governance_bits.json`; `Factory.t` encodings; sizes. **Gates:** whole `forge test`, four sets, size gate.

### Task T40: `mtxPayWithTax` and `payWithTax` on kinds 8–13

**Depends on:** T39. **Estimate:** 2.5.

**Files:** `src/metatx/ERC20MetaTx.sol` (`_uaExecuteTransfer` gains `uint256 withheld, bytes32 withheldTo`; every caller passes
`0, 0`), `src/regulated/{RegulatedBase,RegulatedLib}.sol` and the six kind contracts, `IRegulatedToken`; `test/as/Tax.t.sol`,
`test/as/confidential/TaxConfidential.t.sol` (new), `test/governance/PlusZero.t.sol` (gas old → new), the `paytax.json` writer;
`smartcontracts/vectors/metatx/paytax.json` (new); `size-baseline.json`; `runs/<date>-ua-mtx-merge-paytax-sizes.txt` (summary).

**Interfaces:** `UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)`; `mtxPayWithTax(UAMetaTransfer t, uint8 taxMode,
uint256 tax, UASig auth, PayMeta meta)` and `payWithTax(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef,
PayMeta meta)` (caller is the payer), both `PAYABLE` and `TAX` gated, steps of spec §5.3: `_payMeta`; mode 1 PERCENT (`tax ==
floor(value × rate / 10^6)`, `TaxMismatch`) or 2 AMOUNT; `tax ≤ value`; `r ≠ to`; `_regFeeTo(r, tax)`; the split payer → payee
`value − tax`, payer → `r` `tax` (O13), both on `_uaMove`; `UAPaymentSettled` gross; `PaymentTaxed(entryRef, payee, taxRecipient,
from, taxMode, tax, digest)` even at 0.

- [ ] **Step 1: Failing tests:** `test_payWithTax_percentExact`, `test_payWithTax_percentOffByOne_{up,down}`, `test_payWithTax_amountAsSigned`,
      `test_payWithTax_taxAboveAmount`, `test_payWithTax_mode{0,3}`, `test_payWithTax_taxOff`, `test_payWithTax_recipientIsPayee`,
      `test_payWithTax_recipientFrozen`, `test_payWithTax_recipientUnattested`, `test_payWithTax_frozenPayeePasses`,
      `test_payWithTax_books` (J3, coinciding roles), `test_payWithTax_zeroTaxEmits`, `test_payWithTax_inFlightRateLowered`,
      `test_payWithTax_inFlightIncreaseMatured`, `test_payWithTax_on_{10,11,12,13}`, `test_confidentialOps_noTaxLeg_{10,11,12,13}`
      (shielded transfer and unshield with `TAX` set: no `PaymentTaxed`, no read of +5, +6), `test_directPayWithTax_{contractCaller,eoaCaller,frozenCaller,mismatchedMeta}`,
      `test_directPayWithTax_notInMtxSelectors`; `UAPayWithTax` digest with a non-zero unbound `relayer` / `feeRecipient`;
      `test_plusZeroGas_{kind}` re-pinned.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, kind 13 first (the entry, then the stubs, then the direct twin), then 8–12.
- [ ] **Step 4:** PASS; whole `forge test`; the four sets; size gate and deploy gas of the six releases, the router and
      `RegulatedLib` on the regulated spec's §6.2 method. **Stop rule (spec §6.4, O18):** kind 13 first; a kind at or above
      **64,512 B** is reduced by spec §6.4's levers 1–8 in order, one at a time, size and whole `forge test` re-run after each,
      until it is under; back to the controller only when every lever is applied (the `_above64KiB` row is not a fallback). A
      deploy-gas figure more than 50 % over spec §6.4 is reported, without stopping.
- [ ] **Step 5: Mutants:** PERCENT rounding up; `tax ≤ amount` dropped; the tax leg from the payee; the payee credited `amount`;
      the recipient from calldata; `_regFeeTo` skipped; `PaymentTaxed` skipped at 0 or without `from`; `taxRecipient` hashed into
      the struct; the confidential fee rule applied to PERCENT on 10–13; `payWithTax` taking the payer from an argument.
- [ ] **Step 6:** Commit `ua-mtx-merge T40: mtxPayWithTax and payWithTax on kinds 8-13`.

**Pins, old → new:** gas of every kind's I0 entries (the two internal arguments) and of the pay and tax entries for each lever
applied; sizes of 0–13, the router, `RegulatedLib`, `MtxPipelineLib`; `LinkClosure` codehashes of each library a lever grows;
deploy-gas summary. **Gates:** whole `forge test`, four sets, size gate.

### Task T41: vectors and clients

**Depends on:** T40. **Estimate:** 2.

**Files:** `smartcontracts/vectors/` (`typed/typed_ops.json` by `typed-ops-vectors.mjs`: `UARelayFee` moves, `UAPayWithTax` per
contract class, two router rows; `metatx/paytax.json` readers; `metatx/famvec.py`); `clients/clientkeys` (`buildPay`,
`buildPayReceiverFee`, `buildPayWithTax`, `metaPayId` v2, `encodeMetaBody` / `decodeMetaBody`, `buildRelayFee` with `batch` /
`nonce`, the clear-metadata warning once per payee per session, `payNo` text checks and the 256-byte bound); `clients/ua-rs` and
its wrappers `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`; `clients/zether-prover/src/typed.rs` (relay-fee builder); the ~35 non-EVM
consumers of `paymeta.json` repointed to the legacy copy (8 node adapters' tests, 7 contract families' tests and generators,
`clientkeys` `near` / `algorand` tests, `ua-qt` `tst_ua.qml`, `.github/ci_changes.py`, two older gate runners): paths only.

- [ ] **Step 1: Failing tests:** `clientkeys` digests of `UAPayWithTax` and the new `UARelayFee` with a non-zero unbound `relayer` /
      `feeRecipient`; `paymeta.json` v2 rows (256 accepted, 257 refused); `paytax.json` rows; the warning shown once per payee per
      session; a `payNo` with a bidi override refused; `ua-rs` signs both structs.
- [ ] **Step 2:** FAIL. **Step 3: Implement**; generators write the vectors. **Step 4:** PASS; `node --test`; `ua-rs` and wrappers;
      `zether-prover`; every repointed non-EVM test still green on the legacy file; generators re-run, `git diff --exit-code`.
- [ ] **Step 5: Mutants:** `UARelayFee` field order swapped; `relayer` left non-zero in a canonical digest; schema 2 encoded with
      `invoiceNo`; the old tag in `metaPayId`.
- [ ] **Step 6:** Commit `ua-mtx-merge T41: pay-meta and tax vectors, clientkeys and ua-rs rows`.

### Task T42: node

**Depends on:** T41. **Estimate:** 3.

**Files:** `scaas-node/src/{typed,guard,submit,indexer,gateway,adapter}.rs`, `src/mesh/accept.rs`, the error table,
`node.example.toml` (no new secret), `tests/e2e.rs` (ignored, anvil); `docs/node/` drafts for T19.

**Interfaces:** spec §7.1: a pay job `{op: {entry: "mtxPay" | "mtxPayReceiverFee" | "mtxPayWithTax", token, args: {t, …, meta},
auth}}` with `meta` named per schema (old hex form `HEX_ARGS_REFUSED`, `mtxPayMeta` `ENTRY_RETIRED`); pre-checks
(`PAY_META_MISMATCH`, `PAY_NO_TOO_LONG` > 256 B, `PAY_META_TOO_LONG`, `TAX_MISMATCH` with `expected`); the `payLane` / nonce-0
checks removed; a pay job sent only as its pay entry, never downgraded; `UAPayWithTax`: signer `payment.from`, outer digest as
job id and execution match (receiver-fee behaviour unchanged); rows in `token`, `zether`, `pqz` × kinds 8–13, two router rows, the
mandate rows; relay-fee `batch` / `nonce`; pricing counts `payNo + body`; indexer join of `PaymentTaxed` (spec §5.4) and the feed
fields `tax`, `tax_mode`, `tax_recipient`, `net`, `withheld_by`; alerts on `TaxRateSet`, `TaxRecipientSet`, `FeatureDisabled(23)`,
`RoleRevoked(23)`; gateway `/v1/op`; the mesh refuses a pay by name; non-EVM adapters on the old formula.

- [ ] **Step 1: Failing tests:** `pay_job_named_meta_builds_body`, `pay_job_hex_meta_refused`, `pay_job_payno_257_refused`,
      `pay_job_never_downgraded_on_retry`, `pay_job_free_lane_accepted`, `tax_job_signer_is_payer_distinct_payee`,
      `tax_job_outer_digest_is_job_id`, `tax_job_landed_elsewhere_is_landed_not_superseded`, `receiver_fee_job_unchanged`,
      `tax_mismatch_after_rate_change_refused_by_name`, `pay_tax_rows_equal_contract_{8..13}` (both directions, per class),
      `router_tax_rows`, `indexer_joins_payment_taxed`, `mesh_refuses_pay`, `relay_fee_job_batch_nonce`; e2e: `pay_with_meta_on_anvil`,
      `pay_with_tax_on_anvil`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `CAPPED_MEM=6G ../scripts/capped cargo test` alone; clippy
      `-D warnings`; `--test e2e -- --ignored --test-threads=1`. No `anvil` left.
- [ ] **Step 5: Mutants:** the tax signer taken as `payment.to`; the inner digest as the tax job id; `PAY_META_MISMATCH` decoded as
      `dead`; the node still checking `payLane`; a meta job downgraded to `mtxExecuteTransfer`.
- [ ] **Step 6:** Commit `ua-mtx-merge T42: node pay-meta, tax and relay-fee jobs`.

### Task T43: invariants J1–J8 and the mutant harness

**Depends on:** T40; beside T41, T42. **Estimate:** 1.5.

**Files:** `test/as/invariant/PayTax{Handler,Invariants}.t.sol`; `smartcontracts/evm/runs/<date>-ua-mtx-merge-paytax/`
(`mutants.py`, `README.md`, the summary `mutant | test that went red | rc`, no absolute paths).

- [ ] **Step 1:** Handlers over every pay entry, the relay fee, the two tax powers and the confidential entries of 10–13;
      invariants J1–J8 of spec §13.
- [ ] **Step 2:** Run at the default set; the PQZ handlers at the four sets.
- [ ] **Step 3: Mutants:** every row of spec §14 not already killed in T37–T42 (the harness re-runs those too); a survivor is a
      finding for its owning task.
- [ ] **Step 4:** Commit `ua-mtx-merge T43: pay-meta and tax invariants J1-J8 and the mutant harness, <n> kills`.

**Gates:** whole `forge test`, four sets.

### Attested proof verification for PQZ (group 3f, owner approved 2026-11-06): tasks T44–T50

**Spec:** [`2026-11-06-attested-verify.md`](../specs/2026-11-06-attested-verify.md), revised after the Codex and Fable reviews
([Codex](../../research/attest-codex-review.md), [Fable](../../research/attest-fable-review.md)); rulings O1, O2, O5 and R1–R4
(PQZ only, the attestation inline, unproven keys in ATTESTED mode, an immediate revocation); one question open (spec §12, Q1:
revoking a fixed verifier, recommended no). **Place:** after T43, before 3c (`PqChat` and the registry generation); T19, T21, T22,
T23 cover the group. **Order:** contracts T44 → T45, sequential in this worktree (shared `PqzCore`, `PqzLayer`,
`size-baseline.json`); T46 (`clients/`, `smartcontracts/vectors/`) after T45 fixes the ABI; T47 (node) after T46; T48 (the
reference verifier service, its own crate) and T49 (invariants, mutants) after T45, beside T46–T47; T50 (docs share) drafts beside
them and lands in T19. **Estimate:** 10 agent-days. Every contracts task ends with the whole `forge test` green at the default set
and the size gate, and runs `script/pqz/at-set.sh <set> test --match-path 'test/{ua,pqz,as/confidential}/*'` at the four sets (one
run per work tree, `PqzSet.sol` restored). Red first, positive control first, one change at a time; mutants one at a time on a
clean tree, logged `mutant | test that went red | rc`; heavy runs through `scripts/capped`, foreground. Legacy copies (MD-4) are
the first commit of each task that replaces a body.

### Task T44: the ATTESTED core in `PqzCore`, `PqzStateLib`, `PqzLayer`

**Depends on:** T43. **Estimate:** 2.

**Files:** `src/factory/IFactoryToken.sol` (`ConfidentialConfig`: `verifyMode`, `attestVerifier`, `attestFixed`) and the
`TokenConfig` decode of every kind; `src/pqz/{PqzCore,PqzStateLib,PqzWrappedLib,PqzLayer,IPqzToken}.sol`; `src/ua/UAKinds.sol`
(`PURPOSE_PROOF_ATTEST`); `script/pqz/e2e.py` (the zero-dep release form); `test/pqz/{AttestCore,AttestVerifier}.t.sol` (new);
the layout pin.

**Interfaces:** spec §3–§6: `verifyMode` in byte 22 of `PqzStorage` slot 0; the verifier state appended (§4.4); `PqzLayer`'s
constructor admits `releaseProofVerifier = 0`; PRECOMPILE init refuses it `SelfTestFailed(address(0))` before any call, ATTESTED
init reads nothing from it (`psid = PqzSet.PQZL_ID`); `attesterUA` checked (§4.1: kinds, `AttestVerifierUnregistered`,
`AttestVerifierKind`, the frozen shape); `_check(o, buf, proof, authSig, att, attSig)` with spec §5.3's ATTESTED branch, the
`UAVerifyGas` `try`/`catch` shape, `ProofAttested`; `_keyPtr` / `_creditKey` without `proven` in ATTESTED mode, the set length
kept; the auditor rule; the bodies of `setAttestVerifier`, `cancelAttestVerifier`, `revokeAttestVerifier` (owner, the factory's
`noticePeriod()`, same proposer and owner generation, epoch bump, immediate revocation); `PqzAttest` typehash pin.

- [ ] **Step 1: Failing tests:** `test_attest_positiveControl`, `test_attest_wrong{Token,Chain,Psid,Epoch,Statement,Proof}`,
      `test_attest_expired`, `test_attest_rejectedSignature`, `test_attest_starvedIsUAVerifyGas`, `test_attest_epochABA`,
      `test_attest_revokedRefuses`, `test_attest_shapeChanged_{nativeCode,msigMemberCode,slotAccepted}`,
      `test_verifierKind_{refused,unregistered,controls}`, `test_transfer_{notReady,atEta,notProposer,ownerChanged,fixed,same,zeroNotice}`,
      `test_revoke_{immediate,deletesPending,fixedRefused}`, `test_mode_{immutable,configInvalid,valueInvalid}`,
      `test_release_zeroDep_{precompileRefused,attestedInits}`, `test_attested_neverCallsPrecompile`,
      `test_precompile_ignoresAttestation`, `test_keys_unproven_{attestedAccepts,precompileRefuses,wrongLength}`,
      `test_auditor_unproven_{attested,precompile}`, `test_ciphertexts_sameInBothModes`, `test_PqzAttestTypehashIsPinned`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate.
- [ ] **Step 5: Mutants:** spec §15's Binding, Verifier, Mode and Keys rows.
- [ ] **Step 6:** Commit `ua-mtx-merge T44: PQZ ATTESTED core, verifier transfer and revocation`.

### Task T45: the entries, the view, the stubs; kind 13 first

**Depends on:** T44. **Estimate:** 2.5.

**Files:** `src/pqz/{PqzLayer,WrappedPqzToken,NormalPqzToken,IPqzToken,PqzTransferLib,PqzBurnLib,PqzViewLib}.sol`,
`src/regulated/{NormalPqzRegulatedToken,WrappedPqzRegulatedToken}.sol`, `src/governance/GovernanceRouter*.sol` (three ops);
`test/vectors/selector_audit.json`; gas and layout pins; `size-baseline.json`; `runs/<date>-ua-mtx-merge-attest-sizes.txt`
(summary).

**Interfaces:** spec §5.3–§5.4: `PqzAttest calldata att, IUARegistry.UASig calldata attSig` last on every proof-carrying entry
(direct and signed forms; twelve on 5, 13, ten on 4, 12), outside every `UA*` struct (no typehash moves); the struct fallback
`PqzAttestation` only if the legacy decoder runs out of stack; `verifyTransferAmount` five-argument form `AttestationRequired()`
in ATTESTED mode, seven-argument form; stubs `setAttestVerifier(bytes32)`, `cancelAttestVerifier()`, `revokeAttestVerifier()`,
the view `attestConfig()`; router `mtxSetAttestVerifier`, `mtxCancelAttestVerifier`, `mtxRevokeAttestVerifier` over
`UASetAttestVerifier`, `UACancelAttestVerifier`, `UARevokeAttestVerifier`.

- [ ] **Step 1: Failing tests:** `test_entry_{transfer,compact,single,singleCompact,unshield,refresh,unshieldUnwrap}_{direct,signed}_attested`,
      the same `_precompile` with an empty attestation, `test_signedForms_typehashesUnchanged`, `test_attestationSwapByRelayer_harmless`,
      `test_disclosure_{fiveArgCannotVerify,sevenArgTrue,sevenArgWrongAmount,sevenArgRevoked}`, `test_router_attestOps`,
      `test_mtxSelectors_attest_{4,5,12,13}`.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, kind 13 first (the parameters on one entry, then the rest, then the view, then the
      stubs), then 12, 5, 4, then every other kind (the config decode).
- [ ] **Step 4:** PASS; whole `forge test`; the four sets; size gate and deploy gas on the regulated spec's §6.2 method. **Stop
      rule (spec §9, 3e O18):** a kind at or above **64,512 B** is reduced by spec §9's levers 1–5 in order, one at a time, size
      and whole `forge test` re-run after each, until it is under; back to the controller only when every lever is applied (the
      `_above64KiB` row is not a fallback). A deploy-gas figure more than 50 % over spec §9 is reported, without stopping.
- [ ] **Step 5: Mutants:** spec §15's Disclosure row; the attestation decoded but not passed to `_check`.
- [ ] **Step 6:** Commit `ua-mtx-merge T45: PQZ attested entries, disclosure, verifier stubs and router ops`.

**Pins, old → new:** gas of every PQZ entry in both modes (the comments name the mode; spec §10 row 8); sizes of 0–13, the router,
the PQZ libraries; `LinkClosure` codehashes; layout. **Gates:** whole `forge test`, four sets, size gate.

### Task T46: vectors and clients

**Depends on:** T45. **Estimate:** 1.

**Files:** `smartcontracts/vectors/pqz/attest.json` (new, by a forge writer), `typed/typed_ops.json` (three router rows);
`clients/clientkeys` (`PqzAttest` digest and builder, `statementHash` / `proofHash`, the entries' calldata with the pair, the
creation fields); `clients/ua-rs` and `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb` (sign `PqzAttest` under `proof-attest`).

- [ ] **Step 1:** Failing readers in `clientkeys` and `ua-rs` against `attest.json`. **Step 2:** FAIL. **Step 3: Implement.**
- [ ] **Step 4:** PASS; generators re-run, `git diff --exit-code`.
- [ ] **Step 5:** Commit `ua-mtx-merge T46: PqzAttest vectors and clients`.

### Task T47: node

**Depends on:** T46. **Estimate:** 1.5.

**Files:** `scaas-node/src/{typed,guard,submit,indexer,gateway,adapter}.rs`, the error table, `node.example.toml` (endpoint names
and the shield-refusal switch, no secret), `tests/e2e.rs` (ignored, anvil); `docs/node/` drafts for T50.

**Interfaces:** spec §11.1: the named `attest: {verifierEpoch, validUntil, auth}` on the PQZ entries; `PqzAttest` rebuilt by the
node from the token, the chain, `proofSystemId()`, the simulated statement and the job's proof; `ATTESTATION_MISSING`,
`ATTESTATION_NOT_EXPECTED`, `HEX_ARGS_REFUSED`; fetching from `[attest] endpoints` with the bounded `UASig` decoder, a size limit
and a timeout; the indexer's `lastAttestationAt`, epoch and revoked state; `[attest] refuse_shield_when_unserved` (off by default)
and `VERIFIER_UNREACHABLE`; alerts on `AttestVerifierProposed` and `AttestVerifierRevoked`. The node holds no verifier key.

- [ ] **Step 1: Failing tests:** `attest_subobject_builds_struct`, `attest_hex_refused`, `attested_job_without_attest_fetches_or_refuses`,
      `precompile_job_with_attest_refused`, `attest_epoch_mismatch_refetch_once`, `attestation_mismatch_not_dead`,
      `shield_refused_when_unserved_and_enabled`, `shield_sent_when_disabled`, `pqz_attest_rows_equal_contract_{4,5,12,13}`,
      `router_attest_rows`, `indexer_joins_proof_attested_with_position`; e2e: `pqz_attested_transfer_on_anvil`,
      `pqz_revoked_verifier_on_anvil`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `CAPPED_MEM=6G ../scripts/capped cargo test` alone; clippy
      `-D warnings`; `--test e2e -- --ignored --test-threads=1`. No `anvil` left.
- [ ] **Step 5: Mutants:** spec §15's Node row.
- [ ] **Step 6:** Commit `ua-mtx-merge T47: node attested PQZ jobs and the verifier health signal`.

### Task T48: `scaas-attestd`, the reference verifier service

**Depends on:** T45; beside T46, T47. **Estimate:** 1.

**Files:** a new crate and binary `scaas-attestd/` (never linked into `scaas-node`), its example config (keystore name only, no
secret), its tests; `docs/node/ops.md` draft (a separately operated trust role).

**Interfaces:** spec §11.2: `POST /v1/attest` `{token, chainId, op, statement, proof, verifierEpoch}`, the set-derived body limit,
depth ≤ 4; release address → set; statement rebuilt from state and compared; `pqz-ffi`'s `pqz_precompile`; spec §6's key checks
(stored `pqzPop` bytes, the `R_REG` message per path, single ownership) cached by `(ua, pqzKeyHash)`; signs only on verdict 1;
the probe signature; logs every signature.

- [ ] **Step 1: Failing tests:** `signs_valid_statement`, `refuses_verdict_zero`, `refuses_tampered_statement`,
      `refuses_key_without_stored_pop`, `refuses_key_owned_by_other_ua`, `cache_keyed_by_ua_and_keyhash`,
      `refuses_oversized_and_deep_body`, `refuses_wrong_set_length`, `probe_signature`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS under `scripts/capped`; clippy `-D warnings`.
- [ ] **Step 5: Mutants:** spec §15's Service row.
- [ ] **Step 6:** Commit `ua-mtx-merge T48: scaas-attestd reference verifier service`.

### Task T49: invariants I1–I6 and the mutant harness

**Depends on:** T45; beside T46–T48. **Estimate:** 1.

**Files:** `test/pqz/invariant/Attest{Handler,Invariants}.t.sol`; `smartcontracts/evm/runs/<date>-ua-mtx-merge-attest/`
(`mutants.py`, `README.md`, the summary `mutant | test that went red | rc`, no absolute paths).

- [ ] **Step 1:** Handlers over every proof-carrying entry in both modes, transfers A → B → A, revocations, shape changes;
      invariants I1–I6 of spec §14.
- [ ] **Step 2:** Run at the default set and the four sets.
- [ ] **Step 3: Mutants:** every row of spec §15 not already killed in T44–T48 (the harness re-runs those too); a survivor is a
      finding for its owning task.
- [ ] **Step 4:** Commit `ua-mtx-merge T49: attested-verify invariants I1-I6 and the mutant harness, <n> kills`.

**Gates:** whole `forge test`, four sets.

### Task T50: the docs share of group 3f

**Depends on:** T44–T49 for BUILT tags (drafts beside them). **Estimate:** 1. Lands inside T19's commit.

**Files:** the spec's §10 Change lines and §13 entries (CTR-PQZ-27…30, NODE-JOB-22; `docs_check.py` confirms they are next-free) in
`docs/decisions.md`; `pq-zero-knowledge.md` §1, §9 (CTR-PQZ-01, -10, -11 Changes), §12 (the verifier threat row), §14;
`accounts.md` CTR-UA-16's Change; `docs/networks/evm.md`; `integration.md` (the off-chain disclosure check and the audit replay at
the exact transaction position); `docs/node/job-api.md`, `ops.md` (the verifier service as a separate trust role, the shield
switch), `indexer-feeds.md`; the operator note's attested rows.

- [ ] **Step 1:** Write each change; figures quoted from T44–T49 logs; BUILT only where code and tests exist.
- [ ] **Step 2:** `docs_check.py check`, `paths`, `resolve` on each new id: rc 0. Committed with T19.

### Versioned PQZ keys (group 3g, owner approved 2026-11-06): tasks T51–T57

**Spec:** [`2026-11-06-pqz-key-versions.md`](../specs/2026-11-06-pqz-key-versions.md), revised after the Codex and Fable reviews
([Codex](../../research/pqzver-codex-review.md), [Fable](../../research/pqzver-fable-review.md)); rulings O1–O7 and R1–R5 (no
`keyVersion` in `PqzAuth`; R-cross-set's version-0 replacement retired; receiver and auditor versions not named, with the decoy
filter and the intake refusal; 60 M accepted if 57 M is missed; every other finding adopted); no question open. **Place:** after
T50, before 3c, with 3c's registry generation (3c's rebalance after T53, measured with 3g in); T19, T21, T22, T23 cover the group.
**Order:** contracts T51 → T52 → T53, sequential in this worktree (shared `UARegistryLib`, `UAStore`, `PqzCore`, `PqzLayer`,
`size-baseline.json`); T54 (`clients/`, `smartcontracts/vectors/`) after T53 fixes the ABI; T55 (node) after T54; T56 (invariants,
mutants) after T53, beside T54–T55; T57 (docs share) drafts beside them and lands in T19. The `ua-rs-sign` items (T15
`pqz_key(version)`, T16a's header with the version) belong to that branch's stream. **Estimate:** 19.5 agent-days, plus 1 on
`ua-rs-sign`. Every contracts task ends with the whole `forge test` green at the default set and the size gate, and runs
`script/pqz/at-set.sh <set> test --match-path 'test/{ua,pqz,as/confidential}/*'` at the four sets (one run per work tree,
`PqzSet.sol` restored). Red first, positive control first, one change at a time; mutants one at a time on a clean tree, logged
`mutant | test that went red | rc`; heavy runs through `scripts/capped`, foreground. Legacy copies (MD-4) are the first commit of
each task that replaces a body.

### Task T51: the registry: versioned PQZ key records

**Depends on:** T50. **Estimate:** 3.5.

**Files:** `src/ua/{UAStore,UARegistryLib,UARegistry,IUARegistry,UAKinds}.sol`; `legacy/ua-mtx-merge/` (the four- and two-argument
`setPqzKey` / `storePqzPop`, R-cross-set's replacement); `script/DeployBase.sol`, `script/pqz/e2e.py` (callers);
`test/ua/{PqzKeyVersions,UAStoreLayout}.t.sol` (new); typehash pins; `size-baseline.json`;
`runs/<date>-ua-mtx-merge-pqzver-registry.txt` (summary).

**Interfaces:** spec §2: `setPqzKey(bytes32 ua, uint64 version, bytes pqzKey, bytes32 pqzPopHash, UASig sig)`, `storePqzPop(bytes32
ua, uint64 version, bytes pqzPop)`; `UAPqzKeyVersion`, `UAPqzKeyVersionRecord` and their digests; version 0 write-once (R2,
`UAPqzKeySet`), v ≥ 1 `== latest + 1` (`UAPqzKeyVersion`); the per-UA marker `pqzKeyUsed` (`UAKeyInUse`, the predecessor read on a
host); eligibility (proven; without the verifier, the set length and the proof bytes stored) and `current`, moving only in
`register` with `pqzPop` and `storePqzPop`; `UAPqzKeyCurrent`; `keyOwner` per version; the list once per UA; views `pqzKeyOf`
(version first), `pqzKeyAt`, `pqzKeyLatest`, `pqzKeyUsed`, `pqzPopOf(ua, v)`, `pqzKeySigOf(ua, v)`; the events with `version`;
`register` emits no `UAPqzKeyAdded`; the host rules 1–4 of spec §2.3; `UAStore` slots 2, 7, 8, 9 nested, 13 and 14 retired
placeholders, 17 `PqzVersions`, 18 `pqzKeyUsed`.

- [ ] **Step 1: Failing tests:** spec §14's registry rows: `test_v1_{single,msig}_stored`, `test_v1_{fewMembers,operator,keyData,v0Struct,forV2}_refused`,
      `test_consent_otherUA_refused`, `test_record_crossChain_accepted`, `test_sequence_{gap,noV0,twice}_refused`,
      `test_rreg_{v2Message,unversioned,popV2,otherUA}_refused`, `test_repeatedKey_refused_{verifier,noVerifier,host}`,
      `test_current_{notAtSetPqzKey,atStorePqzPop,otherSetNever,noBytesNotCurrent,lateProofKeeps,registerWithPop}`,
      `test_list_once`, `test_v0_secondKey_refused` (R2) with its control `test_v0_noVerifier_nothingReplaced`,
      `test_host_{latestMax,readsOwnFirst,stableAsGen1Grows,provesBytesItself,gen1Divergence}`, `test_register_noPqzKeyAdded`,
      `test_UAPqzKeyVersion{,Record}TypehashIsPinned`, `test_UAStoreLayout`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate; both registry
      contracts' deploy gas on T10's public-gate formula at the four sets (spec §6.2), rows old → new.
- [ ] **Step 5: Mutants:** spec §14's M-R1 … M-R7.
- [ ] **Step 6:** Commit `ua-mtx-merge T51: versioned PQZ key records in the registry`.

**Pins, old → new:** the `UAStore` layout (the new active pin), the two typehashes, `selector_audit.json`'s registry rows, the
registry and library sizes and deploy gas. **Gates:** whole `forge test`, four sets, size gate.

### Task T52: the token: per-version state; kind 13 first

**Depends on:** T51. **Estimate:** 4.

**Files:** `src/pqz/{PqzCore,PqzStateLib,PqzTransferLib,PqzBurnLib,PqzViewLib,PqzLayer,IPqzToken,WrappedPqzToken,NormalPqzToken}.sol`,
`src/regulated/{NormalPqzRegulatedToken,WrappedPqzRegulatedToken}.sol`, the factory catalogue rows (`OpenFactory` / `DeployBase`);
`test/pqz/PqzKeyVersionsToken.t.sol` (new); `test/vectors/selector_audit.json`; gas, typehash and layout pins;
`size-baseline.json`; `runs/<date>-ua-mtx-merge-pqzver-sizes.txt` (summary).

**Interfaces:** spec §3: `acct[ua][version]`, `sendCounter[ua]`; `uint64 keyVersion` after `fromUA` in `PqzTransferArgs`,
`PqzMultiArgs`, `PqzBurnArgs`; credits to `pqzKeyOf(to)` read once; the capture-once debit; `StaleKeyVersion`, `KeyVersionUnknown`;
the op 1 migration; the pairwise `KeyReused`; `mtxRollOver(bytes32, uint64, uint256)`, `mtxPrepareAcc(bytes32, uint64, uint256)`
direct and signed (100-byte static rule in `_pqzRule`, `_isPqzOp`); views with `keyVersion`; `Credited`, `Debited` with
`keyVersion`, `PqzRolledOver`.

- [ ] **Step 1: Failing tests:** spec §14's token rows: `test_credit_afterRotation_lands_vPlus1`,
      `test_inflight_{precompile,attested}_refused`, `test_burn_v0_notRetargetable`, `test_stale_{payment,op7,burnAmount}_refused`,
      `test_stale_{refresh,migration}_ok`, `test_selfTransfer_{current,op7Leg}_refused`, `test_keyReused_{legs,auditor,migration}`,
      `test_keyVersion_{above,unprovenStale}_refused`, `test_equalTrivial_accountSettled`, `test_replay_afterMigration_refused`,
      `test_counter_sharedAcrossVersions`, `test_rollover_{stale,neverChecked}`, `test_static_{100ok,68refused}`,
      `test_decoys_landOnCurrent`, `test_auditorRotation`, `test_restore_twoVersions`, typehash pins, `test_mtxSelectors_pqzver_{4,5,12,13}`.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, kind 13 first (the state and one entry, then the rest, then the views and events),
      then 12, 5, 4, then the four libraries.
- [ ] **Step 4:** PASS; whole `forge test`; the four sets; size gate and deploy gas. **Stop rule (spec §6.3, 3e O18):** a kind at
      or above **64,512 B** is reduced by spec §6.3's levers 1–5 in order, one at a time, size and whole `forge test` re-run after
      each, until it is under; back to the controller only when every lever is applied (`_above64KiB` is not a fallback).
- [ ] **Step 5: Mutants:** spec §14's M-T1 … M-T10.
- [ ] **Step 6:** Commit `ua-mtx-merge T52: PQZ state per key version, the stale rule, migration`.

**Pins, old → new:** gas of every PQZ entry; the `UA*` typehashes; sizes of 4, 5, 12, 13 and the PQZ libraries; `LinkClosure`
codehashes; the `scaas.pqz` layout. **Gates:** whole `forge test`, four sets, size gate.

### Task T53: disclosure, ATTESTED, the local rotation run

**Depends on:** T52. **Estimate:** 2.

**Files:** `src/pqz/{PqzLayer,PqzViewLib,PqzCore}.sol` (disclosure with `keyVersion`, both 3f forms), the 3f ATTESTED paths
(`_keyPtr` per version); `script/pqz/e2e.py` (the rotation scenario); `test/pqz/PqzKeyVersionsAttest.t.sol` (new).

- [ ] **Step 1: Failing tests:** `test_disclosure_{right,unknown}`, `test_disclosure_attested_withVersion`,
      `test_attested_{currentProvenOnVerifier,v0UnprovenWhileNoneProven,noVerifierNeedsBytes}`, `test_attested_outstanding_notRetargetable`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; the e2e rotation run (an
      `msig` holder: register v1, prove, credit, migrate, disclose) on a local chain with the PQZ precompile brought up for the task,
      never the live testnet stack; no node left running.
- [ ] **Step 5: Mutants:** M-T7.
- [ ] **Step 6:** Commit `ua-mtx-merge T53: PQZ disclosure by key version, ATTESTED versions, local rotation run`.

### Task T54: vectors and clients

**Depends on:** T53. **Estimate:** 4.5.

**Files:** `smartcontracts/vectors/ua/{portable,pq_kat}.json`, `smartcontracts/vectors/typed/typed_ops.json` (generators
`ua-portable-vectors.mjs`, `pq-vectors.mjs`, `typed-ops-vectors.mjs`); `clients/clientkeys` (`ua.js`, `ua-verify.js`, `evm.js`, `pq.js`:
record builders, derivation, wallet rules, additive recovery); `clients/ua-rs` and the wrappers `ua-c`, `ua-cxx`, `ua-qt`,
`ua-dart-frb`; `ua-py`, `ua-go`, `ua-cs`, `ua-dart`.

- [ ] **Step 1:** Failing readers of the new rows in every package; `clientkeys` tests for the stale rule, the pending decoy
      filter, the repeated-key refusal, backups keyed with `pqzKeyHash`, and the audited op 7 recovery after rotations.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; generators re-run, `git diff --exit-code`;
      `smartcontracts/vectors/pqz/<set>/` byte-equal (J8).
- [ ] **Step 5: Mutants:** M-C1.
- [ ] **Step 6:** Commit `ua-mtx-merge T54: PQZ key version vectors and clients`.

### Task T55: node

**Depends on:** T54. **Estimate:** 2.

**Files:** `scaas-node/src/{typed,guard,submit,indexer,adapter}.rs`, the error table, `tests/e2e.rs` (ignored, anvil);
`docs/node/` drafts for T57.

**Interfaces:** spec §7.3: `key_version` on PQZ debit, rollover and prepare jobs; `call` rows for the two registry entries; the
allow-lists both directions with the static lengths and per-kind rollover rows; `PQZ_KEY_VERSION_UNKNOWN`, `PQZ_KEY_STALE`,
`PQZ_KEY_REUSED`, `PQZ_KEY_ROTATION_PENDING`, `PQZ_KEY_ROTATED` (after a `UAPqzKeyCurrent` since intake, with the simulation
error, never `dead`); the indexer's version events and feeds; keepers per `(ua, version)`.

- [ ] **Step 1: Failing tests:** `pqz_key_version_named`, `pqz_hex_refused`, `pqz_rows_equal_contract_{4,5,12,13}`,
      `rollover_rows_per_kind`, `rotation_pending_refused_at_intake`, `rotated_after_event_not_dead`, `rotated_needs_event`,
      `stale_refused_by_name`, `indexer_current_feed`, `keeper_rolls_every_version`; e2e `pqz_rotation_on_anvil`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `CAPPED_MEM=6G ../scripts/capped cargo test` alone; clippy
      `-D warnings`; `--test e2e -- --ignored --test-threads=1`. No `anvil` left.
- [ ] **Step 5: Mutants:** M-N1.
- [ ] **Step 6:** Commit `ua-mtx-merge T55: node PQZ key versions`.

### Task T56: invariants J1–J10 and the mutant harness

**Depends on:** T53; beside T54–T55. **Estimate:** 2.5.

**Files:** `test/pqz/invariant/PqzVer{Handler,Invariants}.t.sol`; `smartcontracts/evm/runs/<date>-ua-mtx-merge-pqzver/`
(`mutants.py`, `README.md`, the summary `mutant | test that went red | rc`, no absolute paths).

- [ ] **Step 1:** Handlers over credits, shields, debits of every version, rotations, proofs and the host; invariants J1–J10 of
      spec §13.
- [ ] **Step 2:** Run at the default set and the four sets.
- [ ] **Step 3: Mutants:** every row of spec §14 not already killed in T51–T55 (the harness re-runs those too); a survivor is a
      finding for its owning task.
- [ ] **Step 4:** Commit `ua-mtx-merge T56: PQZ key version invariants J1-J10 and the mutant harness, <n> kills`.

**Gates:** whole `forge test`, four sets.

### Task T57: the docs share of group 3g

**Depends on:** T51–T56 for BUILT tags (drafts beside them). **Estimate:** 1. Lands inside T19's commit.

**Files:** spec §9's docs; the spec's §10 Change lines (R2's Change line on the owner ruling R-cross-set included) and §12 entries
(CTR-UA-41, CTR-PQZ-31, CTR-PQZ-32, NODE-JOB-23, CLI-SGN-43; `docs_check.py` confirms they are next-free) in `docs/decisions.md`;
the operator note's rotation runbook.

- [ ] **Step 1:** Write each change; figures quoted from T51–T56 logs; BUILT only where code and tests exist.
- [ ] **Step 2:** `docs_check.py check`, `paths`, `resolve` on each new id: rc 0. Committed with T19.

### PQZ proof path, contract side (group 3h, owner approved 2026-11-07): tasks T58–T66

**Spec:** [`2026-11-06-pqz-proof-path.md`](../specs/2026-11-06-pqz-proof-path.md), from the owner-agreed design of research
[`pqz-leg-proof-option.md`](../../research/pqz-leg-proof-option.md) §15A with §14, §15 (b′) and §9.2; owner names of 2026-11-06;
revised 2026-11-07 after the Codex and Fable reviews (no P0; every item accepted, spec §15; R1, R2 required) and for the owner's
decisions of 2026-11-07 (O9 `proofStore` is `NONE` or `LOG`, SSTORE2 dropped and kept in the spec's Appendix A; O10 bit 24; O11
`PQZ_DEBIT_MIN_GAS` with `LOG`; O12 the MPC quorum's dependence on history; O13 the wizard refuses unsupported combinations);
**approved by the owner 2026-11-07**, no question open. **Starts after 3e, 3f and 3g (T57)** per the work order. **Place:** after T57, before 3c (3h touches no registry code; 3c's
rebalance still comes after every PQZ contract change); T19, T21, T22, T23 cover the group. **Order:** contracts T58 → T59 → T60 →
T61, sequential in this worktree (shared `PqzCore`, `PqzLayer`, the PQZ libraries, `size-baseline.json`); T62 (the remaining
vectors) after T61; T63 (node) after T62; T64 (invariants, mutants) and T65 (integration gate) after T61, beside T62–T63, at most
two heavy at once; T66 (docs share) drafts beside them and lands in T19. **Formats move in the task that changes them** (Codex C5):
the generator, the fixture and every reader of a changed format are in that task. **The client side** (spec §13.3, 14–16.5
agent-days) goes to the no-oracle spec on `ua-rs-sign`, where it waits for that branch's T15e; no task here waits for
`ua-rs-sign`. **Estimate:** 19 agent-days. **PQZ only:** no Zether contract, statement, gas pin or vector moves. Every contracts
task ends with the whole `forge test` green at the default set and the size gate, and runs `script/pqz/at-set.sh <set> test
--match-path 'test/{ua,pqz,as/confidential}/*'` at the four sets (one run per work tree, `PqzSet.sol` restored). Red first,
positive control first, one change at a time; mutants one at a time on a clean tree, logged `mutant | test that went red | rc`;
heavy runs through `scripts/capped`, foreground. Spec gas figures are on paper; forge gas pins move old → new (deterministic; no
timing or calibration); a forge run under the raised `gas_limit` is not inclusion (spec §7). Legacy copies (MD-4) are the first
commit of each task that replaces a body. No `pqz-core` change, so no full gate.

### Task T58: the debit record

**Depends on:** T57. **Estimate:** 3.5.

**Files:** `src/pqz/{PqzCore,PqzStateLib,PqzViewLib,PqzLayer,IPqzToken}.sol`, the four PQZ token sources for forwards;
`test/pqz/PqzDebitRecord.t.sol` (new); `test/v2/layout/namespaces.json` (`scaas.pqz`, pinned here if T52 did not); the PQZ gas
pins; `size-baseline.json`; `runs/<date>-ua-mtx-merge-proofpath-sizes.txt` (summary).

**Interfaces:** spec §2: both deletion loops removed (`_debit`, `rollOver`), `cleared` and `floor` updates kept;
`debitRec[ua][counter]`: `w0 = prevBlob ‖ p ‖ Δp ‖ proofStore ‖ flags` (`RECORD` always set; `proofStore` 0 until T60), `w1 =
shieldIn ‖ keyVersion ‖ prevCounter ‖ 0` when `shieldIn ≠ 0`, `keyVersion ≠ 0` or the predecessor is not `k − 1` (R1); the
account's `lastDebit` in the slot 3g freed; `pqzDebitRecord` (`DebitRecordView`, `DebitRecordUnknown`); `pqzAccount` gains
`lastDebit`; `pqzPending` / `pqzPendingCt` below `cleared`.

- [ ] **Step 1: Failing tests:** spec §11.1's record rows: `test_debit_keepsPendingSlots`, `test_rollover_keepsPendingSlots`
      (controls: today's code deletes), `test_pendingCt_belowCleared`, `test_record_{op1,op7,burn,refresh,unwrap,migration}`,
      `test_record_wide_{shieldIn,keyVersion,prevNotPrevious}`, `test_record_narrow`, `test_record_deltaP_{first,afterRollover,unroll}`,
      `test_record_prevBlob_afterRollover`, `test_lastDebit_{perVersion,interleaved}`, `test_record_unknown_reverts`,
      `test_T_fromOneRecord_equalsStatement` (random runs of credits, shields with same-block merges, rollovers, un-rolls and every
      debit form), `test_layout_scaasPqz`.
- [ ] **Step 2:** FAIL. **Step 3: Implement**, kind 13 measured first (`forge build src --sizes --json`); size lever 1 of spec §8
      pulled in this task (the views and the setter as forwards into the libraries); then, at or above 64,512 B, levers 2 and 3 in
      order, re-measured after each; `_above64KiB` is not a fallback.
- [ ] **Step 4:** PASS; whole `forge test`; the four sets; size gate. Gas pins old → new: the debit rows move either way (the
      record and `lastDebit` add, the skipped deletions remove); the rollover rows can only fall.
- [ ] **Step 5: Mutants:** spec §11.3 M1–M6, M17, M18, M21.
- [ ] **Step 6:** Commit `ua-mtx-merge T58: PQZ debit record, pending slots kept`.

**Pins, old → new:** `scaas.pqz` layout; PQZ gas pins; sizes of 4, 5, 12, 13 and the PQZ libraries; `LinkClosure` codehashes.
**Gates:** whole `forge test`, four sets, size gate.

### Task T59: `ownTag`, the key-version tail, `memoHash`; their vectors and readers

**Depends on:** T58. **Estimate:** 3.5.

**Files:** `src/pqz/{IPqzToken,PqzCore,PqzViewLib,PqzLayer}.sol`, the PQZ `UA*` typed structs and their typehash pins,
`test/pqz/PqzOwnTag.t.sol` (new), the PQZ statement-view tests; `smartcontracts/vectors/typed/typed_ops.json`
(`typed-ops-vectors.mjs`: the PQZ `UA*` rows with `ownTag`, each with a non-zero unbound `relayer` / `feeRecipient`, tagged
`"release": "3h"`); `smartcontracts/vectors/ua/pq_kat.json` (`pq-vectors.mjs`: the shared `ownTag` KAT, label `PQZ/owntag/v1`,
and `memoHash` on HASH, BUNDLE and burn); `clients/clientkeys` (`evm.js`: args builders, `ownTag`, `memoHash`); every reader of
those rows: `ua-rs` and the wrappers `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`; `ua-py`, `ua-go`, `ua-cs`, `ua-dart`.

**Interfaces:** spec §3: `bytes32 ownTag` after `salt` in `PqzTransferArgs` and `PqzMultiArgs`, after `beneficiaryUA` in
`PqzBurnArgs`; the blob tail `… ‖ P(v_f) ‖ ownTag ‖ kv(8·n) ‖ u8(n)`, `kv` the versions the call read for the keys after `pk_f` in
statement order; `rOf` the one reader and writer of the tail (the three `_debit` call sites, `transferEntry`,
`transferCiphertextHash`, the views); `memoHash = keccak256(memo ‖ ownTag)`.

- [ ] **Step 1: Failing tests:** `test_ownTag_inBlob_{op1,op7,burn,refresh}`, `test_kv_{op1,op1Auditor,op7,op7Rotated,auditorRotated}`,
      `test_rOf_{burn,op1,op7}`, `test_memoHash_{hash,bundle,burn}`, `test_ownTag_swapped_refused`, `test_transferEntry_unchanged`,
      `test_disclosure_offsetsUnchanged`, the moved typehash pins; failing readers of the new rows in every package; a forge
      cross-check that the statement view's `memoHash` equals `clientkeys`'.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate; generators re-run,
      `git diff --exit-code`; `smartcontracts/vectors/pqz/<set>/` byte-equal.
- [ ] **Step 5: Mutants:** M7–M9, M22; `memoHash` without `ownTag` in `clientkeys`.
- [ ] **Step 6:** Commit `ua-mtx-merge T59: PQZ ownTag and key-version tail, bound by memoHash, vectors and readers`.

**Pins, old → new:** the PQZ `UA*` typehashes; PQZ gas pins; sizes. **Gates:** whole `forge test`, four sets, size gate,
`clientkeys`, every reader's suite.

### Task T60: `proofStore` `NONE` / `LOG`, the measurement matrix, the min-gas pin

**Depends on:** T59. **Estimate:** 2.5.

**Files:** `src/factory/IFactoryToken.sol` (`ConfidentialConfig.proofStore`), `src/pqz/{PqzCore,PqzStateLib,PqzLayer,IPqzToken}.sol`,
the shared config check T44 uses for `verifyMode` on non-PQZ kinds, the `TokenConfig` ripple (`script/DeployBase.sol`,
`script/pqz/e2e.py`, test builders) with its vector rows and their readers; `test/pqz/PqzProofStore.t.sol` (new); layout pin;
`size-baseline.json`; `test/research/PqzProofStoreGas.t.sol` (the matrix); `pqz-core/params/sets/*/set.toml` `debit_min_gas` and
the files `gen_set.py` regenerates from it (O11, owner 2026-11-07); `runs/<date>-ua-mtx-merge-proofpath-matrix.txt` (summary).

**Interfaces:** spec §4, §7: `proofStore ∈ {0 NONE, 1 LOG}` at slot 0 byte 23 (confirm the byte against T44's built layout),
`ProofStoreInvalid` for 2 and above; the record's mode; `PqzDebitProof(address indexed blob, bytes32 indexed ua, uint64 indexed
sendCounter, bytes header, bytes proof)` with the verified `statement[0:640]` and the calldata proof; `proofStore()`; both verify
modes, PQZL and PQZH.

- [ ] **Step 1: Failing tests:** `test_proofStore_{none,log}_{op1,op7,burn}`, `test_proofStore_attested`,
      `test_proofStore_noneLogNone_creditsBetween`, `test_proofStore_invalid`, `test_proofStore_zether_refused`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate.
- [ ] **Step 5: The measurement matrix (spec §7, Codex C4):** per set, every debit form (op 1 with and without the auditor, op 7
      M = 1, 2, 4, 8 with and without, burn, refresh, unshield, unwrap on 5 and 13, the migration), direct and relayed
      (`mtxExecute`, `uaExecute`), at its largest proof, PQZL and PQZH, under `NONE` and `LOG`, record narrow and wide: `regular`,
      `state`, the calldata floor, verdicts against 2^24, a 60 M block, the SCaaS testnet's 200 M block and its node's 64 M
      `max_gas_per_tx`. The rows over a limit are the unsupported-combination table T66 publishes and the wizard refuses (O13);
      the matrix also confirms or refutes spec §5's claim that `NONE` and `LOG` fit wherever today's forms fit (a refuted row goes to
      the controller). Forge gas is deterministic; no timing.
- [ ] **Step 6: `PQZ_DEBIT_MIN_GAS` (O11):** the cheapest PQZL debit as a full relayed transaction under `LOG`, at the four sets;
      `debit_min_gas` in each `set.toml` moved to it, regenerated by `gen_set.py`, the pin test red first; rows old → new in the
      commit.
- [ ] **Step 7: Mutants:** M10, M11.
- [ ] **Step 8:** Commit `ua-mtx-merge T60: PQZ proofStore NONE / LOG, the measurement matrix, PQZ_DEBIT_MIN_GAS with LOG`.

**Pins, old → new:** `scaas.pqz` layout; `TokenConfig` encoding rows; `PQZ_DEBIT_MIN_GAS` per set; PQZ gas pins; sizes. **Gates:**
whole `forge test`, four sets, size gate, the readers of the `TokenConfig` rows.

### Task T61: bit 24 `PQZ_PROOF` and the router op

**Depends on:** T60. **Estimate:** 1.5.

**Files:** `src/governance/{GovernanceBits,GovernanceLib,GovernanceRouterBase,IGovernanceRouter}.sol` (as T39 touched them for
bit 23), the `_validBits()` / `_roleBits()` of kinds 4, 5, 12, 13, `src/pqz/{PqzLayer,PqzStateLib}.sol` (`setProofStore`),
`test/governance/GovProofBit.t.sol` (new), router typehash pins, `test/vectors/selector_audit.json`,
`smartcontracts/vectors/governance/governance_bits.json` (bit 24 with its sentence), the `UASetProofStore` row of
`typed_ops.json` and its readers.

**Interfaces:** spec §5 (O10): `GovernanceBits.PQZ_PROOF = 24` in `ISSUER_BITS` and the four kinds' `_roleBits()`, not in
`_contractOnlyBits()` or `_delayedRelaxBits()`; `setProofStore(uint8 next)` gated by `GovernanceUse.use(PQZ_PROOF, …)`, `NONE` ↔
`LOG` effective at the next debit in both directions, a same-value call a no-op; disabling the bit freezes the value;
`ProofStoreSet(previous, next)`; `mtxSetProofStore(UAEnvelope e, address target, uint8 next, UASig auth)` over
`UASetProofStore(uint8 next)`, fee mode `NONE`.

- [ ] **Step 1: Failing tests:** `test_bit24_validKinds_{4,5,12,13}`, `test_bit24_otherKindsRefused`, `test_bit24_anyHolder_{eoa,
      singleKey,msig,contract}`, `test_bit24_plainKindIssuerGrant`, `test_bit24_notDelayed`, `test_setProofStore_{gated,noop}`,
      `test_proofStore_change_appliesNextDebit`, `test_disable24_freezesValue_{none,log}`, `test_router_UASetProofStore` (non-zero
      unbound relayer), `test_UASetProofStoreTypehashIsPinned`, `test_mtxSelectors_unchanged`; the readers of the new typed row.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; whole `forge test`; the four sets; size gate (router too);
      generators re-run, `git diff --exit-code`.
- [ ] **Step 5: Mutants:** M13–M15, M20.
- [ ] **Step 6:** Commit `ua-mtx-merge T61: bit 24 PQZ_PROOF, setProofStore and its router op`.

**Pins, old → new:** router typehashes (+1), router size and CREATE2 address; `selector_audit.json`; sizes. **Gates:** whole
`forge test`, four sets, size gate.

### Task T62: the remaining vectors

**Depends on:** T61. **Estimate:** 1.

**Files:** a `clientkeys` generator's rows for the record words (narrow and wide), the blob tail of each form and logged P (the
event's fields), at the default set and one other, tagged `"release": "3h"`; any reader of a moved row not yet
moved in T59–T61.

- [ ] **Step 1:** Failing readers of the new rows. **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; every generator of
      T59–T62 re-run, `git diff --exit-code`.
- [ ] **Step 5:** Commit `ua-mtx-merge T62: PQZ proof-path record and tail vectors`.

### Task T63: node

**Depends on:** T62. **Estimate:** 1.5.

**Files:** `scaas-node/src/{typed,guard,submit,indexer}.rs`, the error table (`PROOF_STORE_OVER_LANE_CAP`), `tests/e2e.rs` (the
`TokenConfig` encoder; ignored, anvil); `docs/node/` drafts for T66.

**Interfaces:** spec §10: `own_tag` a named field of the PQZ debit jobs, old shapes refused by name (never `dead`); the
`UASetProofStore` row and `mtxSetProofStore` selector, allow-lists equal to the contract's both directions; NODE-JOB-24: at submit
the lane reads `proofStore()`, estimates regular + state for the job's form, and refuses above its cap
with `PROOF_STORE_OVER_LANE_CAP`, never `dead` while the job may land; the indexer derives `ProofStoreSet` and raises it as an
alert; no `PqzDebitProof` data indexed, no archive.

- [ ] **Step 1: Failing tests:** `pqz_own_tag_named`, `pqz_old_shape_refused_by_name`, `proof_store_router_row_equal_contract`,
      `proof_store_over_lane_cap_refused`, `proof_store_over_cap_not_dead`,
      `indexer_proof_store_set_alert`; e2e `pqz_debit_with_own_tag_on_anvil`.
- [ ] **Step 2:** FAIL. **Step 3: Implement.** **Step 4:** PASS; `CAPPED_MEM=6G ../scripts/capped cargo test` alone; clippy
      `-D warnings`; `--test e2e -- --ignored --test-threads=1`. No `anvil` left.
- [ ] **Step 5: Mutants:** the router row missing on one side; `own_tag` defaulted to zero; the lane check ignoring `proofStore()`.
- [ ] **Step 6:** Commit `ua-mtx-merge T63: node PQZ ownTag, proofStore rows and the lane cap`.

### Task T64: invariants P1–P7, P1′ and the mutant harness

**Depends on:** T61; beside T62–T63. **Estimate:** 2.

**Files:** `test/pqz/invariant/ProofPath{Handler,Invariants}.t.sol`; `smartcontracts/evm/runs/<date>-ua-mtx-merge-proofpath/`
(`mutants.py`, `README.md`, the summary `mutant | test that went red | rc`, no absolute paths).

- [ ] **Step 1:** Handlers over credits, shields (same-block merges), rollovers, un-rolls, every debit form, 3g rotations and
      migrations interleaved across versions, `setProofStore`, `disableFeature(24)`; invariants P1–P7 and P1′ of spec §11.2 (P2
      rebuilds each debit's `T` from its one record; P5: `LOG` ⇔ exactly one event with the verified header and the calldata proof).
- [ ] **Step 2:** Run at the default set and the four sets.
- [ ] **Step 3: Mutants:** M1–M22 without M12, M19 (the harness re-runs those T58–T61 killed); a survivor is a finding for its owning task.
- [ ] **Step 4:** Commit `ua-mtx-merge T64: PQZ proof-path invariants P1-P7 and the mutant harness, <n> kills`.

**Gates:** whole `forge test`, four sets.

### Task T65: the integration gate, real proofs rebuilt and verified

**Depends on:** T61; beside T62–T64. **Estimate:** 2.5.

**Files:** `script/pqz/e2e.py` (the proof-path scenario and a reference rebuild from the spec §9 interface: test code, not a
client library); `smartcontracts/evm/runs/<date>-ua-mtx-merge-proofpath-e2e/` (per-step logs git-ignored, the summary committed).

- [ ] **Step 1:** On a local chain with the PQZ precompile brought up for the task (never the live testnet stack), at the default
      set and one other: real proofs of op 1 (auditor on and off), op 7 M = 4 with the auditor, burn, refresh, unwrap (kind 5) and
      a 3g migration, after rollovers, un-rolls, later debits and rotations of the sender, a receiver, a leg and the auditor, under
      `NONE` and `LOG` and across `NONE → LOG → NONE`.
- [ ] **Step 2: Positive control:** every statement rebuilt from the interface alone (record, pending, blob with `kv`, P from the
      log or the transaction's calldata) and verified with `pqz-ffi`'s verifier.
- [ ] **Step 3: Negatives,** one at a time, each must fail the verification or the lookup: a wrong historical key version, a
      swapped leg, a wrong auditor window, a wrong `shieldIn`, a wrong predecessor or `Δp`, a version boundary crossed, P of another
      debit, a mode read from the wrong record.
- [ ] **Step 4:** No node or chain left running. Commit `ua-mtx-merge T65: PQZ proof-path integration gate, real proofs rebuilt and verified`.

### Task T66: the docs share of group 3h

**Depends on:** T58–T65 for BUILT tags (drafts beside them). **Estimate:** 1. Lands inside T19's commit.

**Files:** spec §12's files, including the table of unsupported combinations from T60's matrix (refused by the wizard, O13), the MPC quorum's dependence on
history (spec §9.6) and SSTORE2's drop (spec Appendix A, a one-line note); its five `decisions.md` entries
(CTR-PQZ-33, CTR-PQZ-34, CTR-PQZ-35, CTR-GOV-22, NODE-JOB-24; `docs_check.py` confirms they are next-free) and Change lines (the plan
5h deletion entries, CTR-PQZ-07, CTR-PQZ-23 with the HASH `memoHash` preimage, CTR-PQZ-12 for O11's pin; the state
spec §5.5 note); the operator note's `own_tag` and `PROOF_STORE_OVER_LANE_CAP` rows; a dated status line in the research note.

- [ ] **Step 1:** Write each change; figures quoted from T58–T65 logs; BUILT only where code and tests exist.
- [ ] **Step 2:** `docs_check.py check`, `paths`, `resolve` on each new id: rc 0. Committed with T19.

### Task T19: docs, decisions, operator note

**Depends on:** T1–T18, T24–T36, T37–T43, T44–T50, T51–T57 and T58–T66 for BUILT tags (drafts beside T14–T18, T24–T36, T37–T43, T44–T50, T51–T57 and T58–T66). **Estimate:** +0.5 for group 3e; group 3f's share is T50 (1), group 3g's is T57 (1) and group 3h's is T66 (1), committed here.

**Files, each rule rewritten once, linked elsewhere:**
- `docs/contracts/metatx.md` (CTR-MTX-01, -05, -06, -09, -11, -12, -14, -15, -17, -18, -21, -22, -23, -24, -26, -27, -28, -29), `accounts.md`
  (CTR-UA-19, -26, -27), `dex.md` (CTR-DEX-13, -15, -25, -26), `zether.md` (CTR-ZTH-06, -34, -51, entry names), `pq-zero-knowledge.md`
  (CTR-PQZ-21, entry names), `token-wrappers.md` (CTR-TOK-20; the router entries), `settlement.md`, `tender.md` (CTR-TND-01, R33: spec
  text only, no tender contract is built), `asset-suite.md` (CTR-AS-13, R34: spec text only), `mandates.md` (Q6 changed: CTR-ACC-12 in
  the merged form, CTR-ACC-06 / -07's entry table, §1.1 the auto-pay path on the named UA entries, the status line; MD-11),
  `contracts/README.md`; `accounts.md`'s CTR-UA-27 `MandateWallet` row (owner, delegate, payee U through the merged entries).
- `docs/networks/README.md` (NET-ALL-26, -28 with the one-rule sentence and the EVM alias, -84 the question row), `evm.md` (NET-EVM-06
  per Q4, the `ua_metatx` relay rows), `hedera.md` (§2 Payload, the DEX row, NET-HED-03's `HederaMandateWallet`); the other network docs only where they cite the EVM struct.
- `docs/node/job-api.md` (job shape, step 7a, the error table R43, the call table, the mandate wallet's named entries), `gateway.md` (the three doors BUILT with code and
  tests), `mesh.md` (NODE-MESH-08, -09, -16), `submit-lanes.md`, `dex-venue.md`, `indexer-feeds.md`, `sponsorship.md`, `ops.md`.
- `docs/clients/signers-clientkeys.md` (the mandate ops, Q6), `app.md`, `ua-libraries.md` (the id display); `docs/architecture.md`, `docs/integration.md` and
  the integration example doc; `assets/settlement-kinds.svg`, `assets/token-tree.svg`; `README.md`; `AGENTS.md` only if a line names
  a merged form.
- `docs/decisions.md`: CTR-MTX-30 to BUILT with commits (its Q6 Change too); a Change line on every rule R1–R47 rewrote, with its
  commit; CTR-ACC-12 and CTR-UA-27 to BUILT; CTR-ACC-05 / CTR-ACC-06 for the flat builders (MD-11 (a)); MD-1 to MD-11;
  `normative:` of each moved rule pointing at its component doc; the size outcome (Q3) and, if a gap remains, the TODO line.
- **Regulated kinds (T24–T36):** `asset-suite.md` §2 to BUILT (CTR-AS-02…09, -16, -17 with commits), `token-wrappers.md` (kinds
  8–13, `TokenConfig.reg`), `zether.md` and `pq-zero-knowledge.md` (the confidential sites, apart), `docs/node/dex-venue.md` (the
  pause halt); `docs/decisions.md`: CTR-GOV-03, -08, -09, -13, -16, -17, -18 to BUILT with commits, the CTR-AS-03 Change
  (owner 2026-11-05) to BUILT, an entry per rule RK-1…RK-11 of the spec's §13; the operator note carries the spec's §3.6 runbook.
- **Pay meta and tax (T37–T43, +0.5):** the doc changes of the 3e spec §9 (`architecture.md` §10 and the four-condition test to a
  recommendation; `metatx.md` CTR-MTX-01, -03, -04, -06, -09, -10, -11, -26, -27; `accounts.md`, `mandates.md`, `asset-suite.md`
  §2, `integration.md` with the taxed reconciliation formula, `docs/node/`, `docs/clients/`); `decisions.md`: the Change lines of
  the spec's §10 and its rules PT-1…PT-7 (CTR-MTX-31, the CTR-MTX-26 / -27 Changes, CTR-AS-18, CTR-AS-19, CTR-GOV-21,
  ARCH-POS-13), ARCH-POS-04's wording; the operator note's pay, relay-fee and tax rows.
- **Operator note** (in `docs/node/ops.md` and the release notes section of `job-api.md`): EVM clients of the address token forms move
  to `ua_metatx`; the gateway doors; the public DEX API takes `UATradeOrder` and the UA cancel forms; the mesh body; a derived cancel
  signs the named purpose (MD-5); mandate wallets: new ids, `ua_metatx` jobs, the flat builders gone (Q6, MD-11); an old shape is refused by name, never silently `dead`; new router and `MtxRelayFee` addresses.
- The spec's status line; `TODO.md` with this commit (never alone).

- [ ] **Step 1:** Write each change; figures quoted from T0–T18 logs; status tags BUILT only where code and tests exist.
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths`:
      rc 0, read directly; `docs_check.py resolve` on each moved id.
- [ ] **Step 3:** Commit `ua-mtx-merge T19: docs, CTR-MTX-30 BUILT, Change lines, operator note`.

### Task T20: the real-wallet display test (Q5, owner-assisted)

**Depends on:** T11 (regenerated rows), T13 (our renderer, for comparison). Before reset 2; beside T14–T19.

**Files:** `docs/research/ua-mtx-merge-wallet-display.md` (new, with the research banner; screenshots stay local, git-ignored or
outside the repo).

- [ ] **Step 1:** The controller prepares the four signing requests from the regenerated vectors: `UAMetaTransfer`, one `UA<Op>` row of
      `typed_ops.json`, a `UATradeOrder` with a non-zero `destination`, a `UARelayFee` row, and a mandate payment
      (`UAPayUnderMandate` in the `SCaaS MandateWallet` domain, a non-zero `payee`, Q6); each with an unbound `relayer` at 0.
- [ ] **Step 2: Owner:** signs each in two widely used browser wallets and one hardware wallet; no key with value, a test account only.
- [ ] **Step 3:** Record per wallet and row what is shown for each `bytes32` field (`from`, `to`, `destination`, `payee`, `delegate`), whether a
      checksum or address book applies, and the primary type title; whether a clear-signing descriptor can render `bytes32` as an
      address is noted as not checked unless the owner checks it.
- [ ] **Step 4:** `docs_check` rc 0; commit `ua-mtx-merge T20: real-wallet display of the merged structs (owner-assisted)`.

### Task T21: the gate runner

**Depends on:** T19 (it may be written earlier; it runs after T19).

**Files:** Create `smartcontracts/evm/runs/<date>-ua-mtx-merge-gates.sh` in the form of `2026-11-03-governance-gates.sh`: it sets `P`,
`LOGEXT=log`, `STEPS`, `FAMILIES`, `NEW_TESTS`, `extra_step`, then sources `2026-10-27-metatx-split-gates.sh`.

**Interfaces:**
- `P=<date>-ua-mtx-merge`; `FORGE_DIRS="ua zether pqz governance v2 metatx as"`; `SETS="n2048-kmax1024 n2560-kmax16384 n2816-kmax65536"`.
- `STEPS="build forge-ua forge-zether forge-pqz forge-governance forge-v2 forge-metatx forge-as forge-rest at-set-n2048-kmax1024
  at-set-n2560-kmax16384 at-set-n2816-kmax65536 forge-isolate sizes zether-cross clientkeys vectors-check cargo-zether-prover
  ua-rs ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs ua-dart cargo-scaas-node node-e2e-anvil node-e2e-hedera zether-e2e docs
  named-tests summary"`. The `forge-*` steps are the default set's whole suite (`forge-rest` covers `test/merge` and the rest);
  `forge-as` the regulated suite `test/as` (T24–T36, T39, T40, T43); `at-set-<set>` runs `script/pqz/at-set.sh <set> test --match-path
  'test/{ua,pqz,as/confidential}/*'` (owner rule: the other three sets
  `test/{ua,pqz}` only, with `test/as/confidential` added for kinds 12, 13); `sizes` runs `size_gate.py --self-test` first and prints `_above64KiB`; `vectors-check` runs every
  generator of T2, T6, T8, T11, T13, T34, T37, T40, T41 (`regulated_kat.json`'s, `paymeta.json`'s and `paytax.json`'s writers included) and `dex_order_kat.json`'s writer, then `git diff --exit-code`; `cargo-scaas-node` under
  `CAPPED_MEM=6G` alone (the whole node suite, clippy `-D warnings`); `docs` runs `test_docs_check.py`, `docs_check.py check`
  and `paths`.
- `NEW_TESTS`: every test name of T1–T18, T24–T36, T37–T43 and T44–T49 in its pass form (`forge|forge|…`, `cargo-scaas-node|cargo|…`, `node-e2e-anvil|cargo|…`,
  `clientkeys|node|…`, one row per language of T13), written from the diff, not from this plan.

- [ ] **Step 1:** Write the runner and the names.
- [ ] **Step 2: Self-check the guard:** remove one forge PASS line from a scratch copy of the logs; `NAMED_TESTS_LOG_DIR=<scratch>
      … --only named-tests` exits non-zero.
- [ ] **Step 3: Run,** nothing else heavy, one step at a time, foreground; `rc` read from each log. On resume read the logs and
      `runs/gate/last` first; a step done at the same commit with a clean tree is skipped. A failure is fixed in its owning task's
      files, committed, re-run.
- [ ] **Step 4:** Commit the runner and `<date>-ua-mtx-merge-summary.txt` only: `ua-mtx-merge T21: closing gates at <sha>`.

### Task T22: review and fix wave

**Depends on:** T21.

- [ ] **Step 1: Whole-branch review, Claude lenses** (superpowers:requesting-code-review) over `main..ua-mtx-merge`, readers given the
      code and the specs (the merge spec, the regulated-kinds spec with its invariants I0–I13, and the pay-meta-tax spec with J1–J8), not this plan's conclusions: security (invariants 1–7, review focus 1–9), rules (each R row against its
      doc and the code), blast radius (every caller of a retired form: contracts, scripts, node, clients, docs), wallet display
      (§6 and T20's note). Same-class rule: a finding on one kind, family or language is checked on every other.
- [ ] **Step 2: Fable, then Codex** on security, signatures and EIP-712 (spec §2, §5, §6, §8, the merged bodies, the node's digest
      reproduction), as for the spec; Codex only on the owner's word (credits).
- [ ] **Step 3: Fix wave:** each confirmed finding with a failing test first, in its owning task's files; commits
      `ua-mtx-merge fix: …`. A finding that changes an R row, a Q answer or an MD goes to the controller (owner rows to the owner).
- [ ] **Step 4:** Re-run T21's steps whose inputs changed; commit the summary; re-review the fixes only, until "ready". The review
      is by AI readers, named as such; everything cryptographic stays `UNAUDITED`.

### Task T23: report and the PR

**Depends on:** T22.

- [ ] **Step 1: Report** to the controller: commits per task; T0's table and the owner's Q3 choice; sizes and deploy gas against
      60 M and 70 M (old → new); whether `WrappedPqzToken` left `_above64KiB`; the regulated releases 8–13 (sizes, deploy gas, the TODO gap line, Q7); R41's figures; the gate summary; the review verdicts
      and the fix wave; T20's findings; what stays open (the 60 M gap if any, recorded in TODO; MD-10).
- [ ] **Step 2: The PR**, on the owner's go: `ua-mtx-merge` into `main` by PR (`main` is PR-only), carrying **the spec, CTR-MTX-30 and
      this plan with the build** (owner). Before the push: a secret scan of the outgoing diff (JSON and `runs/` included), the hits
      read; the push a separate step, by explicit SHA. No merge or push without the word.
- [ ] **Step 3: Next:** TODO item 4, the SCaaS testnet reset 2, deploys the merged code (spec §11: every kind, `DEPLOY_ZETHER=1`,
      the new `MtxRelayFee` and `GovernanceRouter`, the Zether e2e and the PQZ e2e each with an EOA relaying a proof under the
      kind's UA binding, an EOA `mtxTransfer` to an EOA and to a UA, a router op by an EOA, a DEX order with a `UATradeOrder` SCaaS
      leg, Blockscout re-verification). Not this plan's work.

---

## Open items found while planning (none blocks T0)

1. **`executeMetaTransaction`'s home:** spec §2.5 and R26 disagree; MD-1 resolves it for the build. Owner may override.
2. **Mesh, derived subjects:** R45 / Q7 do not say how a peer checks a derived `UASig`; MD-10 refuses it by name until ruled.
3. **Mesh envelope version:** a new body key may need `scaas-intent/1.3` under NODE-MESH-09's versioning; T16 reads that rule.
4. **The cancel's purpose:** "through `preNamedUA` like every named op" changes a derived signer's purpose from
   `PURPOSE_METATX_CANCEL` to the named-op purpose (MD-5); the spec does not say it.
5. **Four sets:** spec §3.3 reads as the whole suite at all four sets; the owner's rule (other three sets `test/{ua,pqz}` only)
   governs the build and the runner; R41's measurement runs at all four.
6. **`MsgSenderLint`** pins no PQZ file, `MtxRelayFee`, `SCaaSDex` or the two wrapped libraries today (MD-6).
7. **"One meaning per name"** (spec §2.3) holds per operation, not per selector: the direct `mtxShield(bytes32,uint256)` and
   `mtxRollOver(bytes32,uint256)` overload the merged signed entries, as today; the node and the selector audit key on full signatures.
8. **`typed_ops.json`:** spec §7 says address rows of merged ops retire; `CancelNonce` stays for the wallets with a narrowed `on`,
   and `CancelOrder` / `CancelWrapOrder` retire without being named in §7 (MD-7).
9. **R33 and R34** (tender, asset-suite) are spec text only: no `SealedBidTender` or `ExchangeOffer` contract is in `src/`.
