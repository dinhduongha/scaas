# legacy/ua-mtx-merge — reference only, not built

The files as they stood at local tag `ref/pre-ua-mtx-merge` (owner: backup, not delete; plan MD-4), before T11 moved the
EVM builders onto the merged entries (CTR-MTX-30: one signed entry per operation, `mtx<Op>(UAEnvelope, …, UASig)` over
`UA<Op>`):

- `src/evm.js`: the address twins of every merged entry and their builders (`burnTypedData` / `burnCalldata` … the six
  `Pqz*`, five `Zether*`, `RollOverSigned`, `SetRollOverMode`, `RollOverBatch`, `ReceiverFee`, `RelayFee`, `WrapOrder`,
  `CancelOrder`, `CancelWrapOrder`, the router's 19 address ops, the mandate wallets' five address ops and `Execute` on the
  wallet), the `ua*` entry names (`uaBurn`, `uaShield` with `bytes auth`, `uaCancelNonce` over the unordered
  `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)`, …), `metaTransferTypedData` and the address `checkPayment`,
  `checkReceiverFee`'s `ReceiverFee` branch, `buildMtxPayMeta` (`mtxPay` / `mtxPayMeta` on addresses) and `buildUaPayMeta`
  (`uaPay` / `uaPayMeta`), `buildRelayFee`'s address `RelayFee` and the router's `uaRelay`, `tradeOrderTypedData` /
  `checkTradeOrder` / `checkCancel` on the token's address `TradeOrder`, `checkWrapOrder` on the address `WrapOrder`.
- `src/zether.js`: the export list of the address Zether / PQZ builders.
- `scripts/typed-ops-vectors.mjs`, `scripts/typed-ops-expected.mjs`: the generator and decoder of the 112-row
  `typed_ops.json` (its copy: `smartcontracts/vectors/typed/legacy/ua-mtx-merge/typed_ops.json`).
- `scripts/ua-sig-vectors.mjs`: the generator of `metatx3.json` / `uatrade_kat.json` with the `ua*` entry names in their
  notes (copies: `smartcontracts/vectors/ua/legacy/ua-mtx-merge/`).
- `test/{typed-ops,evm,relayfee,paymeta,ua-metatx3,seed}.test.js`: the tests whose meaning T11 changes.

Not exported, not tested, not bundled.
- `router-create/{src/evm.js,scripts/typed-ops-vectors.mjs}` (plan T76): as they stood before the router's three creation
  rows (`UACreateToken`, `UACreateDex`, `UACreateInstance`; chain-neutral spec §4.4); their vector copy:
  `smartcontracts/vectors/typed/legacy/ua-mtx-merge/router-create/typed_ops.json`.
- `t66a/{src/ua.js,scripts/ua-portable-vectors.mjs}` (plan T66a, CTR-UA-32): as they stood at 05f23be2, a PQ-eligible `msig` a KEM
  holder (`holds` for the KEM key, `kemRecordMessage` for any kind); their vector copy:
  `smartcontracts/vectors/ua/legacy/ua-mtx-merge/t66a/{portable,nested}.json`.
- `t83/{src/evm.js,test/paymeta.test.js,scripts/typed-ops-vectors.mjs,scripts/typed-ops-expected.mjs}` (plan T83, owner
  2026-11-09): as they stood at 32d73310, `PayMeta {salt, payNo: text, schema, body}` under `scaas.pay.meta.v2`, `checkPayNo`
  (UTF-8, control and bidi rules, 256 bytes); their vector copies: `smartcontracts/vectors/{metatx,typed,ua}/legacy/
  ua-mtx-merge/t83/`.
