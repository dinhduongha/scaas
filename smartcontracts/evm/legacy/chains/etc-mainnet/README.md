# Ethereum Classic (`etc-mainnet`)

**Dropped** by the owner on 2026-11-22 ("ETC has no finalized block: drop it",
decisions CLI-SDK-32): no longer a supported chain. Kept here as the record of its
probes (SDK plan T40); not read by any tool.

Public EVM mainnet. Row `etc-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **61**, chain_uid
`0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22). **Ethereum (1) and Ethereum Classic (61) share block 0**: the chain id separates them (NET-ALL-25).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `shanghai` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06).
- **Caps:** runtime 24,576 B, init code 49,152 B; block gas limit 8,000,000 (read 2026-11-22);
  per-transaction cap none detected.
- **Finality:** **none stated**: the chain serves no `finalized` block (proof of work; H5 and H7 FAIL), so the profile names no depth; a PoW chain's depth is the owner's risk choice, never assumed here, and nothing decisive is read on this chain until it is set.
- **Transaction type:** 0 (no EIP-1559 base fee: legacy transactions, type 2 refused).
- **L1 fee:** none.
- **EIP-2537:** absent: Zether needs the software BLS12-381 path, measured under ARCH-POS-18 (nothing disabled).
- **Note:** no finalized tag (proof of work): the depth is the owner's; no EIP-1559 base fee.
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Blockscout, `etc.blockscout.com`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
