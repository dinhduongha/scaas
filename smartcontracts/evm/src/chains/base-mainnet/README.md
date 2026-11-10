# Base (`base-mainnet`)

Public EVM mainnet. Row `base-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **8453**, chain_uid
`0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** Basescan (Etherscan v2 API), `basescan.org`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
- Mainnet deploys are the owner's.
