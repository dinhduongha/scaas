# legacy/ua-mtx-merge/3e — reference only, not built

`tests/metatx.rs` as it stood at bc6592b1 (the T40 tip): `meta_pay_id` (the old `scaas.pay.meta` commitment) against
`smartcontracts/vectors/metatx/paymeta.json`, which T37 regenerated under `scaas.pay.meta.v2`. T41 reads the legacy file for
`meta_pay_id` and adds `scaas_ua::pay` (v2, `UAPayWithTax`, `UARelayFee` with `batch` / `nonce`). Not built.
