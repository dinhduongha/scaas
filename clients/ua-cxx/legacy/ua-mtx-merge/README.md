# legacy/ua-mtx-merge — reference only, not built

`vectors_test.cpp.paymeta-v2.txt`: `tests/vectors_test.cpp` as it stood at ca8a4773, whose `pay_rows` read the `PayMeta` v2 rows
(`string payNo`, `scaas.pay.meta.v2`) of `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`. `metaPayId` now
computes v3 (`bytes32 payNo`, `bool save`) and the test reads `metatx/paymeta.json`. Not built.
