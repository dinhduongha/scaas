> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Measured on the governance prototype D1+D2 before the governance build; re-measured on main after PR #9 (`bf6f3d04`) by T0 of the merge plan, 2026-11-04: spec docs/superpowers/specs/2026-11-04-ua-mtx-merge.md §9.1, harness and tables smartcontracts/evm/runs/2026-11-04-ua-mtx-merge/results.txt. The figures below stay as the spike measured them.

# One entry per operation: every `ua*` + `mtx*` pair merged (2026-11-03)

A spike for an owner decision, not a build. The owner's idea, as stated: for every pair of `ua*` + `mtx*` entries, keep the `ua*` implementation and rename it to the `mtx*` name; the old `mtx*` implementation goes, because the pair is a duplicate of one feature. One entry per operation: `bytes32 from`, `UAEnvelope`, `UASig`, named `mtx*`. A native address is the padded id, an EOA signs through `signature`. Direct ERC-20 entries such as `transfer` stay.

Base: branch `token-merge` at `6e09e008`, the governance prototype D1 + D2 (`WrappedPqzToken` 65,520 B, `WrappedZetherToken` 64,284 B; stop line 64,500 B). The earlier options are in `docs/research/governance/prototype/size-options.md` on branch `token-core`. Foundry 1.8.5, solc 0.8.37, Amsterdam, optimizer 200, default set `n2304-kmax4096`, `src/pqz/PqzSet.sol` untouched.

Tags: **[M]** measured by `forge build src --sizes --json` or a forge test, **[R]** read from the code, not run, **[P]** projected. Everything cryptographic stays `UNAUDITED`.

## 1. Verdict

- **It works, and it is the largest lever measured.** Merging every pair frees 11,266 B on `WrappedPqzToken` and 11,510 B on `WrappedZetherToken` [M], where the earlier note read "~8-10 KB" without a deletion. Room to the stop line: 10,246 B and 11,726 B. That covers the 1.7 to 1.9 KB still to fit [P] and leaves the cliff far away. The hybrid is not measured.
- **The EOA path needs no registry.** The UA path already takes a native id, and `_authorize` sends it to the signature check with no registry call [M: 0 calls]. Only the `UALedgerOff` guards at the head of each entry stopped a `registry() == 0` token. Moving the guard to the derived branch costs +7 B (C). So the merge does **not** need a registry on every chain.
- **The cost to an EOA is calldata, not a read.** `mtxTransfer` +875 to +992 gas (1.0 to 1.1 %) [M], the same three slots read and written as the base [M]. The direct `transfer` moves by the dispatcher only, −45 to +55 [M].
- **The price is everything outside the bytes.** 86 test files with 1,383 tests stop compiling. It changes the ABI, every typed struct and every event an EOA path emits. It contradicts `CTR-MTX-09` ("nothing merged"), `CTR-UA-26`, `CTR-MTX-23`, `CTR-MTX-28`, and it takes the `address` out of what an EOA signs (§8). Those are the owner's to weigh.

## 2. The table

Runtime bytes. Room is to 64,500 B. "Others" is `NormalToken` / `WrappedToken` / `NormalZetherToken` / `NormalPqzToken`. Gas rows are `transfer` / `mtxTransfer`, EOA to EOA, on `WrappedPqzToken`.

| Option | `WrappedPqzToken` | Room | `WrappedZetherToken` | Room | Others | Gas | Tests red | Risk |
|---|---:|---:|---:|---:|---|---|---|---|
| Base D1 + D2 | 65,520 [M] | −1,020 | 64,284 [M] | 216 | 40,575 / 50,166 / 55,974 / 56,088 | 49,840 / 87,343 [M] | 3 of 2,142 [M] | — |
| **A**: every pair merged, no-twin entries left on `Envelope` | 54,345 [M] | 10,155 | 52,865 [M] | 11,635 | 32,232 / 40,696 / 46,134 / 46,641 | not run on A alone | test tree does not compile | high |
| **A + B**: an EOA runs it | 54,247 [M] | 10,253 | 52,767 [M] | 11,733 | 31,872 / 40,336 / 46,036 / 46,543 | 49,807 / 88,441 [M] | as tip | high |
| **A + B + C**: branch tip, only a derived side needs a registry | **54,254** [M] | **10,246** | **52,774** [M] | **11,726** | 31,879 / 40,343 / 46,043 / 46,550 | 49,807 / 88,218 (+875) [M] | §6: 1,383 do not compile, 1 red of the 759 that do | high: every signed path, owner rules |
| A + B + C + **A2**: no-twin entries on the one path too (reverted) | 52,867 [M] | 11,633 | 51,339 [M] | 13,161 | 31,238 / 39,177 / 45,008 / 45,530 | 49,829 / 88,191 [M] | `test/merge` only, 26 green | high, and `executeMetaTransaction`'s ruling |
| A + B + C + **D**: lever 3 by deletion (reverted) | 47,455 [M] | 17,045 | 49,579 [M] | 14,921 | 31,889 / 37,148 / 44,436 / 41,948 | not run | not run, no module | high, plus lever 3's |
| A + B + C + A2 + D (scratch copy) | 46,128 [M] | 18,372 | 48,208 [M] | 16,292 | 31,248 / 35,982 / 43,453 / 40,976 | not run | not run | as above |
| For scale, `token-core`: lever 3 alone | 58,801 [M] | 5,699 | 61,137 [M] | 3,363 | 40,820 / 47,174 / 54,987 / 52,185 | view +3,082, off chain | not run | medium |

Every other contract [M]:

| Contract | Base | A | A + B | A + B + C | + A2 | + D | + A2 + D |
|---|---:|---:|---:|---:|---:|---:|---:|
| `SCaaSDex` | 32,757 | 32,243 | 32,243 | 32,377 | 32,377 | 32,198 | 32,198 |
| `WrappedLib` | 17,161 | 15,985 | 15,985 | 16,002 | 16,002 | 16,002 | 16,002 |
| `MtxPipelineLib` | 11,377 | 10,932 | 10,947 | 10,976 | 10,523 | 10,976 | 10,523 |
| `TradeLib` | 5,049 | 4,842 | 4,842 | 4,842 | 4,842 | 4,842 | 4,842 |
| `MtxRelayFee` | 3,090 | 2,349 | 2,349 | 2,349 | 2,349 | 2,349 | 2,349 |
| `MandateWallet` | 17,528 | 17,528 | 17,528 | 17,528 | 17,528 | 17,528 | 17,528 |
| `SmartKeyAccount` | 21,003 | 21,003 | 21,003 | 21,003 | 21,003 | 21,003 | 21,003 |

`SCaaSDex` 32,198 in the two lever 3 columns is the artefact of §11 of `size-options.md`: the deletion takes `hasRole` and `pendingOwner` from `GovernanceBase`; the DEX has no `fallback`, so its true figure stays 32,377 B. `WrappedPqzToken` has 152 selectors, down from 188 [M]. Init code 68,154 → 56,878 B, `WrappedZetherToken` 67,863 → 56,343 B [M].

## 3. Spike A: what was merged

`merge-harness/merge_pairs.py` deletes the address bodies and renames; commit `77fb0ef9`. All 30 pairs of §7 of `size-options.md`, and the pairs that table does not list because they are not on `WrappedPqzToken`: `RollOverBatch`, `RollOverSigned`, `SetRollOverMode` on the Zether kinds, `Burn` on `NORMAL`. `mtxCancelNonce` takes `uaCancelNonce`'s form, `(ua, batch, validUntil, UASig)`.

Twins of the same pairs that are not `mtx*` by name went too, since their struct has no entry left: `tradeOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `receiverFeeDigest`, `minNonce`, `restorePulled(TradeOrder, …)`, `MtxRelayFee.relay`; each name now holds the id form. Internal twins gone: `_executeTransfer`, `_padded`, `_pay`, `_payMeta`, `_notPool`, `wrapBySig`, `_tradeOf`, `preTransfer`, the address `requireSignature` and typehashes. `UA*` structs and typehashes keep their names, as allowed for the spike.

**The wallets keep the address surface.** `MetaTxBase` holds the core; `mtxNonce`, `mtxDigest`, `mtxExecute`, `mtxBatch` and `mtxCancelNonce` moved to `MetaTxAddressBase` and `IMetaTxAddress`, which `WalletExecute` inherits. `MandateWallet` and `SmartKeyAccount` do not move a byte [M]. They have no registry and no `ua*` twins.

**Entries with no twin stayed** on `Envelope` and `bytes`:

| Entry | Note |
|---|---|
| `mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve` | wrapper kinds; off the UA allowlist |
| `mtxWrapShield` | `WRAPPED_*`; off the UA allowlist |
| `executeMetaTransaction` | `MetaTransaction`, `address from`; an owner ruling keeps it (§8) |

Their cost is the address pipeline kept on the token: `_execute`, `_named`, `_namedCall`, `_settle`, `preCall(false)`, `preNamed`, `_requireSignature`, `_envelopeBinding`, `envelopeBinding` and `uaEnvelopeBinding` side by side. **A2** (commit `771015b7`, reverted by `db20e170`) moves them to the one path too, with the alias on `UAMetaTransaction`, and removes that pipeline: −1,387 B on `WrappedPqzToken`, −1,435 B on `WrappedZetherToken`. Other direct entries stay as they are: `transfer`, `transferFrom`, `approve`, `transferToUA`, `payWithFee`, `payWithFeeToUA`, `wrap*`, `unwrap*`, `addReserve`, `cancelNonce`, the direct confidential ops, the role functions.

## 4. Spike B: does the merged path work for an EOA

Yes, with two fixes (commit `2094aa70`), both in the merged code and both in the byte figures.

Positive tests, `test/merge/MergedEntry.t.sol`, 26 green [M]: EOA to EOA, EOA to a registered UA on `WrappedPqzToken`, a contract holder by ERC-1271, a designator by its own key, refusals. Each can fail, shown one change at a time on a scratch copy of the tip:

| Mutant (`merge-harness/mutants.py`) | Goes red [M] |
|---|---|
| `native-on-ua-list`: the fix below undone | `test_nativeRunsAddressAllowlist` |
| `derived-off-ua-list`: a derived id off the UA list | `test_derivedStaysOnUAAllowlist` |
| `no-signature-check` | `test_badSignatureRefused` twice, `test_erc1271Holder`, `test_designatorSignsWithItsOwnKey` |
| `no-receiver-check` | `test_unregisteredReceiverRefused` |
| `registry-read-for-native`: a registry call on a native receiver | `MergedPqz.test_eoaToEoa` (the count of 0), `test_eoaToUA` (the count of 1) |
| `registry-for-every-receiver`: C undone at the receiver | `MergedNoRegistry.test_eoaToEoa`, the `setUp` of both no-registry gas suites |
| `cancel-refuses-native` | `test_nativeSignedCancel` |
| `no-ua-credit` | `test_eoaToUA` |

### Obstacles, from the code

| Asked | Found | Fixed in spike |
|---|---|---|
| `_requireDerivedReceiver` refusing native ids | **Not on this path.** It guards `transferToUA`, `_uaMint`, `wrapToUA`, `payWithFeeToUA` and a derived unshield recipient, the "…ToUA" set. The merged transfer uses `_checkTo`, which takes both spaces [R, M by the two tests] | none needed |
| `UAKinds.inNativeSpace` | The one dispatch: `id >> 160 == 0`. A padded address with a stray high bit is a derived id and is refused [M] | none |
| `_uaOn()` at `registry() == 0` | **Blocks an EOA for no reason**: at the head of `preTransferUA`, `_open`, `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, `mtxCancelNonce`. No native branch reads the registry. §5 | C |
| Ledgers | Native sides read and write the ERC-20 ledger: `balanceOfUA(pad(a)) == balanceOf(a)`. `_uaMove` calls `ERC20._update` directly, so it **skips `ERC20MetaTx._update`**. Today's checks there are repeated in `_checkTo`, `_uaMove`, `_poolMove`. A future regulated hook is not: every signed transfer goes through `_uaMove` now (§7) | none |
| `requireAuthorized` on a native id | Not reached: `_authorize` branches first. The one direct call was `uaCancelNonce`, which also refused native ids | B |
| The UA allowlist | **Real obstacle.** `_close` refused any selector off `_uaAllowed`, so a native id lost `wrap`, `addReserve`, `wrapToUA`, `cancelNonce` on the one `mtxExecute`. Fix: the list reads for a derived id only; a native id keeps the `_mtxRule` list | B |
| ERC-1271 holders | `_authorizeNative` is the same `SigCheck.isValid` with the same cap by code hash [M] | none |
| EIP-7702 designators | `CTR-UA-24` holds: its own key signs, the delegate is not asked [M] | none |
| `_msgSender`, `UA_POOL` | A native subject reads as its address inside the self-call, `UA_POOL` only for a derived one; unchanged [M: `cancelNonce` run through the generic entry] | none |
| Self-calls | `_uaSettle` carries a native subject as `_settle` did. The envelope binding becomes the UA one, tag `TAG_UA_ENVELOPE`, for every relayed proof: a client change, not a contract one [R] | none |
| The DEX | **Real obstacle.** Shape 0 on a SCaaS token called `mtxTrade(TradeOrder, bytes, …)`, which is gone. A SCaaS leg is now shape 1 only, `UATradeOrder`, its `sig` carried in `auth`. `TradeOrder` stays for outside legs: `DexOrder` nests it. `LegSettled` is left to outside legs, a SCaaS leg emits `UALegSettled`. Compiled, **not run**: the DEX tests do not compile | edited in A |
| Order types | `orderHash` and `cancelHash` lose their `ua` flag and four typehashes; `record`, `cancel`, `invalidate` keep it, for the DEX's outside legs | A |
| `MtxRelayFee` | The router's two entries merge the same way: `relay` takes `bytes32 from, payee` and a `UASig`; open mode unchanged. A new init code, so a new CREATE2 address [R] | A |
| `WrappedLib` | `wrapBySig` goes; `mtxWrapOrder` asked the leg for `IUALedger` by ERC-165, false on a leg with no registry. Only a derived holder needs it now | C |
| `MandateWallet`, `SmartKeyAccount` | Neither calls a merged entry: the wallet pays by `payWithFee`, directly. Byte-identical [M] | split of `MetaTxBase` |

### What it costs an EOA

| Row, `test/governance/GovGas.t.sol`'s method | Base [M] | Merged, tip [M] | Change |
|---|---:|---:|---:|
| `NormalToken` `transfer` | 49,705 | 49,748 | +43 |
| `WrappedToken` `transfer` | 49,727 | 49,682 | −45 |
| `WrappedZetherToken` `transfer` | 49,734 | 49,789 | +55 |
| `WrappedPqzToken` `transfer` | 49,840 | 49,807 | −33 |
| `NormalToken` `mtxTransfer` | 87,223 | 88,215 | +992 |
| `WrappedToken` `mtxTransfer` | 87,266 | 88,258 | +992 |
| `WrappedZetherToken` `mtxTransfer` | 87,293 | 88,284 | +991 |
| `WrappedPqzToken` `mtxTransfer` | 87,343 | 88,218 | +875 |
| `WrappedPqzToken` `mtxTransfer`, EOA to a UA | no such path | 108,919 | +20,701 on the row above |

Base figures reproduced at `6e09e008` by the same test. `NormalToken` and `WrappedToken` are measured with `registry() == 0`, so they need C.

- **Reads.** Every storage slot of the token touched by a merged `mtxTransfer`, compared with the base's on `WrappedPqzToken`: the same three slots, 8 reads, 3 writes, line for line [M: `MergedPqzSlots`, a same-shape probe on the base].
- **Calldata.** 420 B → 580 B [R]: a 65-byte signature travels in a three-field `UASig`, five more words, nearly all zero. At 4 and 16 gas a byte that is about +690 gas [P]; the rest is the decoder and the longer dispatcher path, not split further.
- **The registry call.** EOA to EOA: **none** [M: `vm.expectCall(reg, "", 0)`]. EOA to a UA: exactly one, the receiver's `kindOf`, 5,873 gas cold [M], plus one per `predecessor` generation when the id is older [R]. That is today's `uaTransfer` too. The rest of the +20,701 is the ledger entry, the `UA_POOL` slot and the `UATransfer` log; not split further.
- **Not measured:** generic `mtxExecute`, `mtxPayReceiverFee`, `mtxTrade` through the DEX, `MetaTxGasV2`'s rows.

## 5. Spike C: plain tokens with no registry

Commit `5d068cce`. `NORMAL` and `WRAPPED` take `env.registry == 0`; the Zether and PQZ kinds refuse it in their constructors. `accounts.md`, at `CTR-UA-19`: "0 = the ledger is off: every `ua*` reverts `UALedgerOff`".

**What breaks without C** [M]: `MergedNoRegistry` red at commit B: `test_eoaToEoa` `UALedgerOff`, and every gas row in `setUp`. On a chain without a registry the merged token has no relayed path at all: an EOA keeps only direct `transfer` and, in A, the address generic `executeMetaTransaction`, which cannot carry a transfer (no such selector on `_mtxRule`). Without a guard a derived `to` would call `address(0)` and revert with empty data, not a named error.

**The rule.** A registry is needed by a derived side, and only there. One guard moved into the two places that call the registry: the derived branch of `_authorize` and of `_checkTo`. `_uaOn()` stays only in `_requireDerivedReceiver`.

| [M] | `registry() == 0` |
|---|---|
| EOA to EOA | works, `test_eoaToEoa`, gas 88,215 on `NormalToken` |
| Bad signature | `MetaTxBadSignature` |
| Derived receiver | `UALedgerOff`, named |
| Derived sender | `UALedgerOff`, named |

**Bytes:** +7 B on every token kind against B, +29 B on `MtxPipelineLib`, +134 B on `SCaaSDex`, +17 B on `WrappedLib` [M]. Gas falls: the check left the hot path, −223 on `WrappedPqzToken`'s `mtxTransfer` (88,441 → 88,218) [M].

The DEX and `mtxWrapOrder` ask for a ledger only for a derived seller. `supportsInterface(IUALedger)` stays false at `registry() == 0`, though `IUALedger` now names the entries an EOA uses there: a real build splits that interface [R]. Hedera is on the same branch, `_authorizeNative` keeps HIP-632; not run. The merge does not need a registry everywhere. An EOA-only chain gets the same entries with its derived branch dead.

## 6. Tests

The test tree does not compile on the tip. `test/merge` is the kept minimal set, run with `FOUNDRY_TEST=test/merge FOUNDRY_SCRIPT=test/merge`. **Nothing in the tree was repaired.** To count, a scratch copy of the tip dropped each file with a compile error until the rest built (`merge-harness/red_skip.py`, 17 passes), then ran.

| [M] | Files | Tests |
|---|---:|---:|
| Base, full suite | 180 suites | 2,142: 2,125 pass, 3 fail, 14 skip |
| Do not compile on the tip | 86 test files, 6 helpers, 1 script | 1,383 |
| — own compile error | 15 | 249 |
| — only through a helper (`V2Fixture`, `DexLegs`, `MtxFixture`, `UALedgerBase`, `OrderJson`, `ERC20MetaTxHarness`) or another test file | 71 | 1,134 |
| Compile and run | 59 | 759: 752 pass, 1 fail, 6 skip |
| New, `test/merge` | 1 | 26 pass |

By directory: `v2` 459, `metatx` 226, `zether` 191, `pqz` 150, `ua` 131, `wallet` 71, `account` 54, `research` 43, `governance` 41, `hedera` 16, `fork` 1. The base's three reds (`DexKat`, `Factory.test_sizes`, `HederaV2.test_implementationSizes`) are among those that do not compile.

**The one red that compiles:** `MsgSenderLint.test_msgSenderReadsArePinned`, `4 != 7`: the deleted twins took three `msg.sender` reads with them. A source pin. Not moved.

**Green that matters:** `LinkClosure` three of three, including `test_libraryOpcodes`; `MetaTxLib` typehash pins. `test/v2/Layout.t.sol` does not compile, so the artifacts were compared directly: all six kinds, same labels, slots and offsets [M].

Class of the repair, read from the 86 files, overlapping [R]:

| Class | Files | What it needs |
|---|---:|---|
| Call shape only: rename, `Envelope` to `UAEnvelope`, `bytes` to `UASig` | most | mechanical; the six helpers carry most of it |
| Assert an address event | 19 | `MetaTransactionExecuted`, `PaymentSettled`, `TradeFilled` and siblings become `UA…` on these paths |
| DEX leg shape | 30 | a SCaaS leg at shape 0 is refused |
| Meaning reversed | 7 by `UALedgerOff`, more by hand | a native id at `registry() == 0` now works; a native `uaCancelNonce` no longer refuses; a native off the UA list no longer refuses |
| Gas or size ceilings | 33 | `MetaTxGasV2` and others: pins move with old and new figures |
| Typehash or interface pins | 5 | `IMetaTx`, `IERC20MetaTx`, `IUALedger` ids changed |
| Lose their point | `MetaTxParity` and each twin's own test | a pair's parity needs a pair |

## 7. Risks found

- **Every EOA path is now the path a native id used least.** The `ua*` bodies were tested with native ids, not as the main road. Review it as new code [R].
- **`_uaMove` is the only hot move of signed transfers.** Its comment already says a regulated hook "must also hook here". After the merge a hook only in `_update` would miss every relayed transfer, not only the UA ones [R].
- **A native `UASig` ignores `keyData` and `members`.** The registry refuses them, TS-D12: "a native id only `signature`"; `_authorize` reads `auth.signature` alone. So a relayer can add junk to calldata. It moves nothing, the digest does not cover `UASig`, and `uaTransfer` does the same today. It becomes every EOA's path [R].
- **Selectors in the DEX refusal list.** `_interact` refuses `ITradeToken.mtxTrade.selector`. With old-release tokens on a chain, the old `mtxTrade` and `uaTrade` selectors would need a place on that list, and so would an order of the old shape [R]. Nothing is live with value today.
- **`mtxCancelNonce` carries no envelope:** no relayer binding and no token fee, where the address form had both. Each signature works once. A native id still has `cancelNonce` through generic `mtxExecute`, with a fee [M for the path, R for the rest].
- **`mtxTransfer` now reaches a derived `to` from an EOA.** New on the address side, the receiver rule is the UA path's [M].

## 8. Rules this touches

Quoted, not decided.

| Rule | Text | Effect of the merge |
|---|---|---|
| `CTR-MTX-09` | "keep their signatures (owner: kept separate, nothing merged)"; `decisions.md`, 2026-10-08: "nothing is merged (owner)" | Opposite of the merge |
| `CTR-MTX-15` | "Two structs, one nonce space"; "`MetaTxLib.MetaTransfer` exists on tokens only and is the typed transfer or payment that outside wallets display field by field ("send `value` to `to`")" | The token's `MetaTransfer` entries go; the nonce space stays one |
| `CTR-MTX-17` | "`executeMetaTransaction` stays in `MetaTxBase` and `IMetaTx` beside `mtxExecute`, on every contract as before …: it signs `address from`, so it is not part of `UAMetaTxBase`" | Kept in A, B, C. A2 would reverse it |
| `CTR-MTX-23`, `-24` | "The typed path: `mtxExecuteTransfer(MetaTransfer t, bytes sig)`"; "`mtxBatchTransfer(MetaTransfer[] ts, bytes[] sigs)`" | Signatures and structs change; steps stay |
| `CTR-MTX-28`, TS-D14 | "`mtx<Op>(MetaTxLib.Envelope e, <explicit op parameters>, bytes sig)` and, where it was UA-allowed, `ua<Op>(MetaTxLib.UAEnvelope e, <parameters>, UASig auth)`"; why: "so a wallet shows the operation's own fields" | One form, the second; the fields stay named, `from` is `bytes32` |
| `CTR-MTX-14` | "EIP-712 typed data is what wallets display"; cost if wrong: "Users would sign blind hashes" | Still typed data, no blind hash. The `address` type in it goes |
| `CTR-UA-26` | "The UA path splits like the address path"; "The `ua*` functions keep their signatures and build the struct of their kind"; `uaExecuteTransfer` "mirror" of `mtxExecuteTransfer` | Nothing left to mirror; the `ua*` names go |
| `CTR-UA-27` | "every function a native calls or signs has a signed UA form"; "**Own struct, any id.** … it takes a native id too (zero-padded, **U**): a native signs the digest itself (ECDSA, ERC-1271 by CTR-UA-24, HIP-632 on Hedera)" | **Holds, by construction**: this text is the merged path. Parity stops being two forms |
| `CTR-UA-19` | "The UA-ledger meta-transactions have their own structs and typehashes" | The structs become the only ones; `MetaTransaction` stays on the wallets |
| `CTR-UA-18` | "EVM balances of derived UAs live in a separate `bytes32` ledger" | Holds; no balance moved |
| `CTR-UA-24` | "it signs by its own key only" | Holds [M] |
| `CTR-DEX-25` | "`TradeOrder` and its vectors do not change. A native id may sign it too" | The first part breaks on SCaaS tokens; outside legs keep `TradeOrder` |
| `CTR-GOV-11` | "a plain `transfer` and `mtxTransfer` add no storage read, on every kind" | Holds on the one kind probed [M]; the pin reads a new ABI |
| `AGENTS.md` | "Backup, do not delete. Superseded code moves to `legacy/`"; "One rule on every chain" | A build moves the bodies to `legacy/`. The EVM family would name one entry where others may keep two |

**Typed-signing readability, "an EOA reads what it signs".** Today an EOA's wallet gets `MetaTransfer(address from,address to,…)`. After the merge, `UAMetaTransfer(bytes32 from,bytes32 to,…)`. The operation, amounts, lanes and names stay on screen; `from` and `to` become 32-byte words with 12 leading zero bytes. A wallet handles an `address` field as an address (checksum, address book, a scam list) and a `bytes32` as hex. That last sentence is an expectation: no wallet was tested. Every EIP-712 field stays named, no opaque blob returns. This is the loss, and it is the one thing the bytes cannot pay back.

## 9. What a build would still need

Not done here, listed.

| Area | Needs |
|---|---|
| Node | `guard.rs`, `typed.rs`, `abi.rs`, `submit.rs`, `gateway.rs`, `metatx.rs`, `indexer.rs`, `chain.rs`, `dex/venue.rs`, `adapters/hedera.rs`: selectors, `CALL_TABLE`, typed builders, the allow-lists per kind, the events. A note for operators on the job shape |
| Events | On merged paths `MetaTransactionExecuted` → `UAMetaTransactionExecuted`, `PaymentSettled` → `UAPaymentSettled`, `TradeFilled`, `OrderCancelled`, `NoncesInvalidated` → `UA…`, `ReceiverFeePaid` → `UAReceiverFeePaid`, `LegSettled` → `UALegSettled`: new topics, a `bytes32` subject. Direct `payWithFee` keeps `PaymentSettled` |
| Clients | `clientkeys` (`src/evm.js`), every `ua-*`, `zether-prover` (`src/typed.rs`): structs, digests, the UA envelope tag on relayed proofs |
| Vectors | `vectors/metatx/typed_ops.json`, `paymeta.json`, `relayref.json`, `vectors/ua/metatx3.json`, `uatrade_kat.json`, the DEX order KAT. Regenerate, not edit |
| Docs | The rules of §8; `decisions.md` entries |
| Contracts | Interface ids, a split of `IUALedger`; `MetaTxLib.MetaTransfer` is dead on tokens, left in for the pin; `mtxWrapShield` and the wraps if A2 is taken; the bodies in `legacy/` |
| Tests | §6 |

## 10. How to run

```text
# from smartcontracts/evm
../../scripts/capped forge build src --sizes --json > sizes.json
FOUNDRY_TEST=test/merge FOUNDRY_SCRIPT=test/merge ../../scripts/capped forge test -vv
```

| Commit | What | Harness |
|---|---|---|
| `6e09e008` | base | |
| `77fb0ef9` | A | `merge_pairs.py`, plus the hand edits in the commit |
| `2094aa70` | B | `test/merge/MergedEntry.t.sol` |
| `5d068cce` | C; the tree tip's code | `red_skip.py`, `mutants.py` on scratch copies |
| `771015b7`, reverted `db20e170` | A2 | `no_twin.py` |
| `5582de40`, reverted `43dd312c` | D, 47 of the 48 views: the merge left one digest view fewer | `lever3_delete.py` |

Ran: `forge build src --sizes --json` at each commit, the full suite on a scratch copy of the base, the suite left on a scratch copy of the tip, `test/merge` at B, C, A2, eight mutants. `scripts/size_gate.py` on the tip: 2 errors, `SCaaSDex` over its baseline, as at the base, and `AdminLib` absent; the baseline was not moved.

Not run: the node suite, any client, any non-EVM build, `script/pqz/at-set.sh`, any gate at the other three sets, a DEX test, a suite on a lever 3 row. No pin, `size-baseline.json`, KAT or vector moved.
