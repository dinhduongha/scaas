# `ua*` / `mtx*` merge (one signed entry per operation, the base token size for public chains) — build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-04):** plan, not executed; its decisions MD-1 to MD-10 accepted by the owner 2026-11-04. **Owner 2026-11-04 (after T0): build M first** (A + B + C with the router's pairs, Q2, R17, R47: tasks T1-T8 with T3b, T10-T23 without a lever), then a checkpoint: gates, the whole-branch review (Claude, Fable, Codex) and the PR of M into `main`. **T9 (levers D / L) is not started: the owner decides it after M.** M alone fits a 200 M block, not 70 M for `WrappedToken` (72.37 M asked, T0), so no public chain deploy before that decision. Nothing is built from it; this commit writes no code, contract, test or vector. **Owner 2026-11-04 (after T1): Q6 changed:** the mandate wallets are built in this round in the merged form (task T3b, MD-11); T1 is built.

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
| Docs | T19 | drafts beside T14–T18; lands after T18 (BUILT only with code and tests) |
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

### Task T19: docs, decisions, operator note

**Depends on:** T1–T18 for BUILT tags (drafts beside T14–T18).

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
- `P=<date>-ua-mtx-merge`; `FORGE_DIRS="ua zether pqz governance v2 metatx"`; `SETS="n2048-kmax1024 n2560-kmax16384 n2816-kmax65536"`.
- `STEPS="build forge-ua forge-zether forge-pqz forge-governance forge-v2 forge-metatx forge-rest at-set-n2048-kmax1024
  at-set-n2560-kmax16384 at-set-n2816-kmax65536 forge-isolate sizes zether-cross clientkeys vectors-check cargo-zether-prover
  ua-rs ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs ua-dart cargo-scaas-node node-e2e-anvil node-e2e-hedera zether-e2e docs
  named-tests summary"`. The `forge-*` steps are the default set's whole suite (`forge-rest` covers `test/merge` and the rest);
  `at-set-<set>` runs `script/pqz/at-set.sh <set> test --match-path 'test/{ua,pqz}/*'` (owner rule: the other three sets
  `test/{ua,pqz}` only); `sizes` runs `size_gate.py --self-test` first and prints `_above64KiB`; `vectors-check` runs every
  generator of T2, T6, T8, T11, T13 and `dex_order_kat.json`'s writer, then `git diff --exit-code`; `cargo-scaas-node` under
  `CAPPED_MEM=6G` alone (the whole node suite, clippy `-D warnings`); `docs` runs `test_docs_check.py`, `docs_check.py check`
  and `paths`.
- `NEW_TESTS`: every test name of T1–T18 in its pass form (`forge|forge|…`, `cargo-scaas-node|cargo|…`, `node-e2e-anvil|cargo|…`,
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
      code and the spec, not this plan's conclusions: security (invariants 1–7, review focus 1–9), rules (each R row against its
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
      60 M and 70 M (old → new); whether `WrappedPqzToken` left `_above64KiB`; R41's figures; the gate summary; the review verdicts
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
