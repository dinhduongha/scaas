# Polygon PoS (`polygon-mainnet`)

Public EVM mainnet. Row `polygon-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **137**, chain_uid
`0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** Polygonscan (Etherscan v2 API), `polygonscan.com`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
- Mainnet deploys are the owner's.
