# legacy/ua-mtx-merge — reference only, not run

`vectors_test.dart.paymeta-v2.txt`: `test/vectors_test.dart` as it stood at ca8a4773, whose `pay rows` test read the `PayMeta` v2
rows (`string payNo`, `scaas.pay.meta.v2`) of `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`. `metaPayId` now
computes v3 (`bytes32 payNo`, `bool save`) and the test reads `metatx/paymeta.json`. Not run.
