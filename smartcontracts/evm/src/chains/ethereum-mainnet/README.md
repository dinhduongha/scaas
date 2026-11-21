# Ethereum (`ethereum-mainnet`)

Public EVM mainnet. Row `ethereum-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **1**, chain_uid
`0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22). **Ethereum (1) and Ethereum Classic (61) share block 0**: the chain id separates them (NET-ALL-25).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `osaka` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06).
- **Caps:** runtime 24,576 B, init code 49,152 B; block gas limit 59,941,408 (read 2026-11-22);
  per-transaction cap 16,777,216.
- **Finality:** `tag finalized`: H7 served it and never moved back in the first sample.
- **Transaction type:** 2 (the head carries an EIP-1559 base fee).
- **L1 fee:** none.
- **EIP-2537:** present (Zether on the precompile).
- **Note:** txGasCap: EIP-7825 of Osaka (an eth_call on geth does not apply it).
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Etherscan v2, `etherscan.io`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
