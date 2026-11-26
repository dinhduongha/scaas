# Linea Sepolia (`linea-testnet`)

Public EVM testnet. Row `linea-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **59141**, chain_uid
`0x65a64c825d7c13ce1bf077801d0b6b2a89853e19e4a89a5433d7d85d2102a20b`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

**EVM tier** ([NET-EVM-20](../../../../../docs/networks/evm.md#NET-EVM-20), owner 2026-11-26): Tier 2: deployable once the chain raises its code size. Block 2,000 M, every kind fits; `osaka`, runtime 24,576 B (controller classification, owner may move it).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `osaka` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06).
- **Caps:** runtime 24,576 B, init code 49,152 B; block gas limit 2,000,000,000 (read 2026-11-22);
  per-transaction cap none detected.
- **Finality:** `tag finalized`: H7 served it and never moved back in the first sample.
- **Transaction type:** 2 (the head carries an EIP-1559 base fee).
- **L1 fee:** priced in the gas price Linea gives (`linea_estimateGas`, served by the chain's own RPC, not by every provider).
- **EIP-2537:** present (Zether on the precompile).
- **Note:** finalized is L1 finality only on providers that serve it (rpc.sepolia.linea.build); one provider answered finalized = head (H5 FAIL); txGasCap none detected.
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Etherscan v2, `sepolia.lineascan.build`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
