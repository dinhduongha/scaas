# Ethereum Sepolia (`ethereum-testnet`)

Public EVM testnet. Row `ethereum-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **11155111**, chain_uid
`0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `amsterdam` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06); the chain is there.
- **Caps:** runtime 65,536 B, init code 131,072 B; block gas limit 199,802,400 (read 2026-11-22);
  per-transaction cap 16,777,216.
- **Finality:** `tag finalized`: H7 served it and never moved back in the first sample.
- **Transaction type:** 2 (the head carries an EIP-1559 base fee).
- **L1 fee:** none.
- **EIP-2537:** present (Zether on the precompile).
- **Note:** Sepolia at Amsterdam: runtime 65,536 B, init 131,072 B measured; txGasCap EIP-7825.
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Etherscan v2, `sepolia.etherscan.io`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- **Code size** (owner 2026-11-22, decisions CLI-SDK-32 (3): "look at optimising the code to reduce the code size"): at Amsterdam
  Sepolia creates a 65,536 B runtime and refuses 65,537 B, accepts 131,072 B of init code and refuses 131,073 B (measured
  2026-11-22). The size study (branch `evm-size-64k`, `56c8b3dbe`, `docs/research/2026-11-22-evm-size-64k.md`) found no contract in `src/` above
  those caps: the kinds are releases plus body modules since T66b (`WrappedPqzToken` a 27,437 B release), the largest runtime
  `OpenFactory` at 35,238 B.
