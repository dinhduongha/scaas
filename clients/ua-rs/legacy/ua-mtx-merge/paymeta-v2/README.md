# legacy/ua-mtx-merge/paymeta-v2 — reference only, not built

`pay.rs.v2.txt` and `tests-pay.rs.v2.txt` are `src/pay.rs` and `tests/pay.rs` as they stood at ca8a4773: `PayMeta {salt, payNo,
schema, body}` with a `string payNo` and its commitment `meta_pay_id_v2` (`"scaas.pay.meta.v2" ‖ salt ‖ keccak256(abi.encode(string
payNo, uint16 schema, bytes body))`), the `payNo` text rules (`check_pay_no`, 256 bytes, no control or bidirectional character),
tested against `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`. The contract moved to v3 in T83 (`bytes32
payNo`, `bool save` committed); `src/pay.rs` now computes `meta_pay_id_v3` against `metatx/paymeta.json`. The wrappers' `metaPayId`
exports (`ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`) follow. Not built.
