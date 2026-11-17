# legacy/ua-mtx-merge/3e — reference only, not built

The files as they stood at bc6592b1 (the T40 tip, pay-meta-tax group 3e), before T41 moved clientkeys onto `PayMeta` v2:

- `src/evm.js`: `metaPayId(salt, meta)` over `scaas.pay.meta` (kept as `metaPayIdV1` for the non-EVM families),
  `encodeMeta` / `decodeMeta` (the `abi.encode(uint16, bytes)` envelope, schema 2 with `invoiceNo`), `buildUaPayMeta`
  (`mtxPayMeta` / the flat `mtxPay`), `checkPayMeta(td, {salt, meta})`, `buildRelayFee` and `UARelayFee` without `batch` /
  `nonce`, `payWithFeeToUACalldata` without `PayMeta`, `GOVERNANCE_BITS` 0-22.
- `src/passkey-signer.js`, `src/seed-signer.js`: their export lists.
- `scripts/typed-ops-vectors.mjs`, `scripts/ua-sig-vectors.mjs`: the generators before the pay rows carried a `PayMeta`
  (copies of their output: `smartcontracts/vectors/{typed,ua}/legacy/ua-mtx-merge/3e/`).
- `test/{paymeta,relayfee,evm,typed-ops}.test.js`: the tests whose meaning T41 changes.

Not exported, not tested, not bundled.
