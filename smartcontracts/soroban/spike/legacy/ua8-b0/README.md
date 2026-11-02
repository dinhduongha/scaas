# legacy/ua8-b0: reference only, not built

The B0 models of `ua8-soroban` (2026-10-31): `register_pqz_kem_model`, `store_pqz_pop_model`, `set_kem_key_model`,
`set_pqz_key_model`, `keccak_model`, their six budget tests and their `measure.py` rows. They estimated UA-8 Part B on
Soroban before the registry existed, on the digests of that date.

Superseded by `contracts/ua-registry` and the host measurements in `scaas-node/tests/e2e_ua8.rs`
(`e2e_ua8_network_fit`, `e2e_ua8_relayer_table`), which are the figures in `docs/networks/soroban.md`. The models were
left behind by typed-signing: `attrs.kemVersion` left `portable.json`, a KEM key at registration is version 0, and the
portable digests became typed, so keeping them would mean a second copy of the registry. The B0 run log stays in
`../../../runs/2026-10-31-ua8-soroban-b0-spike.txt`.
