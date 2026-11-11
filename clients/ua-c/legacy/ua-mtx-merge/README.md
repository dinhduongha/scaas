# legacy/ua-mtx-merge — reference only, not run

`test_vectors.py.paymeta-v2.txt`: `tests/test_vectors.py` as it stood at ca8a4773, whose `test_pay_digest_and_meta_pay_id` read the
`PayMeta` v2 rows (`string payNo`, `scaas.pay.meta.v2`) of `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`.
`scaas_ua_meta_pay_id` now computes v3 (`bytes32 payNo`, `bool save`) and the test reads `metatx/paymeta.json`. Not run.
