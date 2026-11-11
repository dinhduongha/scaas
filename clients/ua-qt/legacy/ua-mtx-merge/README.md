# legacy/ua-mtx-merge — reference only, not built

`ua_kinds.rs.paymeta-v2.txt` and `tst_ua.qml.paymeta-v2.txt`: `src/ua_kinds.rs` and `tests/tst_ua.qml` as they stood at ca8a4773,
with the invokable `metaPayIdV2` (`PayMeta` v2: `string payNo`, `scaas.pay.meta.v2`) tested against
`smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`. It is now `metaPayIdV3` (`bytes32 payNo`, `bool save`) against
`metatx/paymeta.json`. `metaPayId(salt, meta)`, the old `scaas.pay.meta` form the non-EVM families keep, is unchanged. Not built.
