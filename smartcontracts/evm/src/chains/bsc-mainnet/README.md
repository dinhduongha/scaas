# BNB Smart Chain (`bsc-mainnet`)

Public EVM mainnet. Row `bsc-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **56**, chain_uid
`0x0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

**EVM tier** ([NET-EVM-20](../../../../../docs/networks/evm.md#NET-EVM-20), owner 2026-11-26): Tier 2: deployable once the chain raises its code size. Named by the owner; Mendel = Osaka, runtime 24,576 B, until its Glamsterdam fork.

- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; nothing here assumes a precompile.
- **Explorer:** BscScan (Etherscan v2 API), `bscscan.com`; verification (NET-EVM-12) with `VERIFY_EXPLORER=etherscan` and the API key named by
  `VERIFY_API_KEY_ENV` (e.g. `ETHERSCAN_API_KEY`); the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- A real deploy needs this chain's Amsterdam fork (`evm_version = "amsterdam"`, `foundry.toml`).
- Mainnet deploys are the owner's.
