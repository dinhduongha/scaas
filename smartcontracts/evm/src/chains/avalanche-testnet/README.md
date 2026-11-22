# Avalanche Fuji (`avalanche-testnet`)

Public EVM testnet. Row `avalanche-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **43113**, chain_uid
`0x31ced5b9beb7f8782b014660da0cb18cc409f121f408186886e1ca3e8eeca96b`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22). **It shares block 0 with C-Chain (43114)**: the chain id separates them (NET-ALL-25); NET-EVM-16.

Profile [`profile.json`](profile.json) (`draft`, chains-arweave plan T2; the format of SDK plan T40), from the probes of
2026-11-22 (`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`, chains-arweave T12; summary `2026-11-22-evm-probes-summary.txt`
beside it; **one sample each**: the 24-h and 7-day windows of NET-EVM-19 are the operator's scheduler's, still to run):

- **Fork:** `cancun` by opcodes (`libevm` v1.13.14), P-256 at `0x100`; no Prague, Osaka or Amsterdam. No SCaaS contract set deploys
  before the chain's Amsterdam fork and EIP-7954 (NET-EVM-06); a single contract may deploy earlier under NET-EVM-18
  (`PqChatStore`, its deploy waiting for the owner's word: chains-arweave T10).
- **Caps:** runtime 24,576 B, init code 49,152 B (measured); block gas limit 32,000,000 (read 2026-11-22; the sum of the
  transactions' gas limits, ACP-194, read again by the deploy gate, never a constant); no per-transaction cap (ACP-176).
- **Charge:** a transaction pays `max(gasUsed, gasLimit / 2)` (ACP-194): the lane's gas limit is its estimate with its margin,
  never a fixed padding. A header's `gasUsed` sums gas limits: real gas comes from receipts.
- **Finality:** `tag finalized` (= `safe`, the last settled block): `latest` − `finalized` 3–4 blocks, 6–8 s in the sample (H5); H7
  served it. A block is accepted before it executes: logs are read at or below the final block only.
- **Reads by hash:** H2 and H4 passed on both providers (a made-up hash refused or null).
- **Logs:** `eth_getLogs` answered spans of 10,000 blocks on one provider and 100 on the other (H6).
- **Transaction type:** 2 (the head carries an EIP-1559 base fee; `eth_baseFee` is an upper bound, not the price paid).
- **L1 fee:** none.
- **EIP-2537:** absent: Zether waits for the software BLS12-381 path (ARCH-POS-18, the `bls12381-multi` plan); no kind disabled.
- **No PQZ or ML-DSA precompile:** PQZ runs OFFCHAIN or waits; ML-DSA runs on the registry's expanded-key cache.
- **PQ fit** (the probe's `caps`: each PQ kind's largest transaction measured at Amsterdam, regular + EIP-8037 state gas, × 1.05,
  against the block limit 32,000,000; this chain is Cancun, without EIP-8037, so its own figures are measured at deploy time,
  never compared with the Amsterdam pins):

  | Kind | Largest transaction | Regular | Total | Total × 1.05 | Within 32,000,000 |
  |---|---|---|---|---|---|
  | `mldsa44` | cache part 0 | 9,740,000 | 41,455,370 | 43,528,138 | **no** |
  | `mldsa65` | cache part 1 | 10,230,000 | 43,512,090 | 45,687,694 | **no** |
  | `mldsa87` | cache part 2 | 10,730,000 | 45,578,810 | 47,857,750 | **no** |
  | `fndsa512` | register | 2,734,649 | 9,119,339 | 9,575,305 | yes |
  | `slhdsa128s` | register | 1,116,222 | 14,362,962 | 15,081,110 | yes |
  | `fndsa1024` | verify cap (register not measured) | 5,250,000 | 5,250,000 | 5,512,500 | yes |
  | PQZ (`pqz`) | an operation ≈ 43 M (`storePqzPop` 49.1 M at `n2304-kmax4096`) | — | ≈ 43,000,000 | ≈ 45,150,000 | **no** |

  **Nothing is disabled** (no owner ruling for this chain; ARCH-POS-18): `mldsa44`, `mldsa65`, `mldsa87` and PQZ do not fit this
  block and are reported to the owner with these numbers.
- **Deterministic deployer:** `0x4e59b44847b379578588920cA78FbF26c0B4956C` present (the research note §2).
- **Lanes** (NET-EVM-16, node audit of chains-arweave T3): a transaction accepted but without a receipt is `Pending`, never
  `dead`; a lane key keeps at most 16 in flight (`max_inflight`, NODE-LANE-24; the pool's executable slots per account);
  acceptance checks balance ≥ gas limit × worst-case price + value, which the lane's in-flight cost alert follows.
- **Explorer:** Snowtrace / Routescan (Etherscan-compatible); verification (NET-EVM-12) with the API key named by
  `VERIFY_API_KEY_ENV`; the key itself never enters the repo.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
