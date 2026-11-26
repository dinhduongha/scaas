# Polygon Amoy (`polygon-testnet`)

Public EVM testnet. Row `polygon-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **80002**, chain_uid
`0x7202b2b53c5a0836e773e319d18922cc756dd67432f9a1f65352b61f4406c697`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

**EVM tier** ([NET-EVM-20](../../../../../docs/networks/evm.md#NET-EVM-20), owner 2026-11-26): *Tier 3: not yet eligible.* Not measured: no `profile.json` (controller classification, owner may move it).

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** Polygonscan (Etherscan v2 API), `amoy.polygonscan.com`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
