# Base Sepolia (`base-testnet`)

Public EVM testnet. Row `base-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **84532**, chain_uid
`0x0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** Basescan (Etherscan v2 API), `sepolia.basescan.org`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
