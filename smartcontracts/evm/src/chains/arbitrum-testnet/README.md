# Arbitrum Sepolia (`arbitrum-testnet`)

Public EVM testnet. Row `arbitrum-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **421614**, chain_uid
`0x77194da4010e549a7028a9c3c51c3e277823be6ac7d138d0bb8a70197b5c004c`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

**EVM tier** ([NET-EVM-20](../../../../../docs/networks/evm.md#NET-EVM-20), owner 2026-11-26): *Tier 3: not yet eligible.* A transaction at most 32 M: `mldsa44`, `mldsa65`, `mldsa87` and PQZ disabled.

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
- **Explorer:** Etherscan v2, `sepolia.arbiscan.io`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- **Disabled kinds** (owner 2026-11-22, "disable the kinds": ARCH-POS-18 confirmed, decisions CLI-SDK-32):
  each PQ kind's largest transaction, regular and regular + EIP-8037 state gas (Amsterdam, measured), against the per-transaction limit 32,000,000 (ArbGasInfo) by
  accounts.md's MD-5 rule (regular × 1.05 < 2^24, total × 1.05 within the limit); `profile.json` `disabledKinds`; the SDK
  refuses a disabled kind `KindDisabled` before anything is signed:

  | Kind | Largest transaction | Regular | Total | Total × 1.05 | Verdict |
  |---|---|---|---|---|---|
  | `mldsa44` | cache part 0 | 9,740,000 | 41,455,370 | 43,528,138 | **disabled** |
  | `mldsa65` | cache part 1 | 10,230,000 | 43,512,090 | 45,687,694 | **disabled** |
  | `mldsa87` | cache part 2 | 10,730,000 | 45,578,810 | 47,857,750 | **disabled** |
  | `fndsa512` | register | 2,734,649 | 9,119,339 | 9,575,305 | fits |
  | `slhdsa128s` | register | 1,116,222 | 14,362,962 | 15,081,110 | fits |
  | `fndsa1024` | verify cap (register not measured) | 5,250,000 | 5,250,000 | 5,512,500 | fits |
  | PQZ (`pqz`) | an operation ≈ 43 M; `storePqzPop` 49.1 M at `n2304-kmax4096` | — | ≈ 43,000,000 | ≈ 45,150,000 | **disabled** |

  `mldsa44` is disabled by the same rule: its cache part (41.5 M) is above the limit too (the ruling's text names
  `mldsa65`, `mldsa87` and PQZ; the probe table had not carried `mldsa44` then).
