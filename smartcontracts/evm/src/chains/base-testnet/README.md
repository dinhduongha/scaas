# Base Sepolia (`base-testnet`)

Public EVM testnet. Row `base-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **84532**, chain_uid
`0x0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22).

**EVM tier** ([NET-EVM-20](../../../../../docs/networks/evm.md#NET-EVM-20), owner 2026-11-26): Tier 2: deployable once the chain raises its code size. Block 120 M, every kind fits; `osaka`, runtime 24,576 B (controller classification, owner may move it).

Profile [`profile.json`](profile.json) (`draft`, SDK plan T40), from the probes of 2026-11-22
(`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`; summary `2026-11-22-evm-probes-summary.txt` beside it; one sample each, the
24-h and 7-day windows of NET-EVM-19 still to run):

- **Fork:** `osaka` by opcodes and the head's fields. A SCaaS set deploys after the chain's Amsterdam fork (NET-EVM-06).
- **Caps:** runtime 24,576 B, init code 49,152 B; block gas limit 120,000,000 (read 2026-11-22);
  per-transaction cap none detected.
- **Finality:** `tag finalized`: H7 served it and never moved back in the first sample.
- **Transaction type:** 2 (the head carries an EIP-1559 base fee).
- **L1 fee:** `op-stack`: `GasPriceOracle.getL1Fee` (0x420…000F) over the unsigned transaction, added to the quote (the node: `params.l1_fee = "op-stack"`; the SDK: plan T38).
- **EIP-2537:** present (Zether on the precompile).
- **Note:** txGasCap none detected.
- **No PQZ or ML-DSA precompile** on this chain: PQZ runs OFFCHAIN (the proof checked by the contract verifier) or the PQZ
  kinds stay off; ML-DSA runs on the registry's expanded-key cache; nothing here assumes a precompile.
- **Explorer:** Basescan (Etherscan v2), `sepolia.basescan.org`; verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`; the key
  itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
- **Disabled kinds** (owner 2026-11-22, "disable the kinds that do not fit on Base and Celo": ARCH-POS-18 confirmed,
  decisions CLI-SDK-32 (2)): each PQ kind's largest transaction, regular and regular + EIP-8037 state gas (Amsterdam,
  measured), against this chain's block gas limit 120,000,000 by accounts.md's MD-5 rule (regular × 1.05 < 2^24, total × 1.05
  within the limit); `profile.json` `disabledKinds`; the SDK refuses a disabled kind `KindDisabled` before anything is signed:

  | Kind | Largest transaction | Regular | Total | Total × 1.05 | Verdict |
  |---|---|---|---|---|---|
  | `mldsa44` | cache part 0 | 9,740,000 | 41,455,370 | 43,528,138 | fits |
  | `mldsa65` | cache part 1 | 10,230,000 | 43,512,090 | 45,687,694 | fits |
  | `mldsa87` | cache part 2 | 10,730,000 | 45,578,810 | 47,857,750 | fits |
  | `fndsa512` | register | 2,734,649 | 9,119,339 | 9,575,305 | fits |
  | `slhdsa128s` | register | 1,116,222 | 14,362,962 | 15,081,110 | fits |
  | `fndsa1024` | verify cap (register not measured) | 5,250,000 | 5,250,000 | 5,512,500 | fits |
  | PQZ (`pqz`) | an operation ≈ 43 M (`storePqzPop` 49.1 M at `n2304-kmax4096`) | — | ≈ 43,000,000 | ≈ 45,150,000 | fits |

  Nothing is disabled here: every kind fits this chain's limit (the same rule disables them on Base mainnet).
