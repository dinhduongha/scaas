# Arbitrum One (`arbitrum-mainnet`)

Public EVM mainnet. Row `arbitrum-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **42161**, chain_uid
`0x7ee576b35482195fc49205cec9af72ce14f003b9ae69f6ba0faef4514be8b442`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `osaka` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06).
- **Caps:** runtime 24,576 B, init code 49,152 B; block gas limit 1,125,899,906,842,624 (read 2026-11-22);
  per-transaction cap 32,000,000.
- **Finality:** `tag finalized`: H7 served it and never moved back in the first sample.
- **Transaction type:** 2 (the head carries an EIP-1559 base fee).
- **L1 fee:** inside `eth_estimateGas` (ArbGasInfo at 0x6c answers): the estimate carries the L1 component.
- **EIP-2537:** present (Zether on the precompile).
- **Note:** txGasCap: ArbGasInfo.getGasAccountingParams max tx gas limit; the header's gas limit is not a block cap.
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Etherscan v2, `arbiscan.io`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
