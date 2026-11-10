# BNB Smart Chain testnet (`bsc-testnet`)

Public EVM testnet. Row `bsc-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **97**, chain_uid
`0x6d3c66c5357ec91d5c43af47e234a939b22557cbb552dc45bebbceeed90fbe34`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** BscScan (Etherscan v2 API), `testnet.bscscan.com`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
