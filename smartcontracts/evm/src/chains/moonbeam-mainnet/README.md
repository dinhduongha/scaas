# Moonbeam (`moonbeam-mainnet`)

Public EVM mainnet. Row `moonbeam-mainnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **1284**, chain_uid
`0x7e6b3bbed86828a558271c9c9f62354b1d8b5aa15ff85fd6f1e7cbe9af9dde7e`, network `mainnet`. A chain is (chainId, chain_uid) (NET-ALL-22). Frontier on a Polkadot parachain; Ethereum gas; the second Polkadot EVM after Polkadot Hub (NET-EVM-17).

Profile [`profile.json`](profile.json) (`draft`, chains-arweave plan T11; the format of SDK plan T40), from the probes of
2026-11-22 (`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`, chains-arweave T12; summary `2026-11-22-evm-probes-summary.txt`
beside it; **one sample each**: the 24-h and 7-day windows of NET-EVM-19 are the operator's scheduler's, still to run):

- **Sources:** `moonbeam.api.onfinality.io` over TLS; `rpc.api.moonbeam.network` refused this client's TLS handshake that day and
  answered over plain HTTP through a third-party metered gateway (its headers name one), so it is no independent provider: H1's
  second source is weak, the owner's question.

- **H2 FAIL:** on both providers, a read pinned by a **made-up** block hash (`{blockHash, requireCanonical: true}`) is answered
  (balance 0, empty code) instead of refused: CLI-RPC-05's pinned reads cannot tell a wrong hash here. A stop condition of the
  plan: the owner decides; the profile stays `draft`.
- **Fork:** `osaka` by opcodes (CLZ answered); no `blockAccessListHash`. No SCaaS set deploys before NET-EVM-06 holds here.
- **Caps:** runtime 24,576 B, init code 49,152 B (measured); block gas limit 60,000,000 (read 2026-11-22); per-transaction cap
  52,000,000 (moonbeam-docs, the research note §3.2; an `eth_call` does not apply it). Gas adds storage growth (366 gas per byte,
  160 KiB per block, MBIP-5), effective gas `max(legacy, PoV, storage)`, not EIP-8037.
- **PQ fit** (the probe's `caps`, Amsterdam figures × 1.05 against 52,000,000): every kind fits; nothing is disabled. The
  storage-growth gas of a kind's largest transaction (a cache part's SSTORE2 bytes) is checked at deploy time (T15).

  | Kind | Largest transaction | Regular | Total | Total × 1.05 | Within 52,000,000 |
  |---|---|---|---|---|---|
  | `mldsa44` | cache part 0 | 9,740,000 | 41,455,370 | 43,528,138 | yes |
  | `mldsa65` | cache part 1 | 10,230,000 | 43,512,090 | 45,687,694 | yes |
  | `mldsa87` | cache part 2 | 10,730,000 | 45,578,810 | 47,857,750 | yes |
  | `fndsa512` | register | 2,734,649 | 9,119,339 | 9,575,305 | yes |
  | `slhdsa128s` | register | 1,116,222 | 14,362,962 | 15,081,110 | yes |
  | `fndsa1024` | verify cap (register not measured) | 5,250,000 | 5,250,000 | 5,512,500 | yes |
  | PQZ (`pqz`) | an operation ≈ 43 M (`storePqzPop` 49.1 M at `n2304-kmax4096`) | — | ≈ 43,000,000 | ≈ 45,150,000 | yes |

- **Finality:** `tag finalized` (relay-finalized; `safe` = `finalized`): `latest` − `finalized` 0–3 blocks in the sample (H5); H7 served it.
- **H4:** passed (a made-up hash answered null). **Logs:** `eth_getLogs` answered 1,000-block spans (H6).
- **Transaction type:** 2. **L1 fee:** none.
- **EIP-2537:** present at `0x0b`–`0x11` (Zether's precompile path); P-256 at `0x100`.
- **No PQZ or ML-DSA precompile.**
- **EIP-7702** is live on Moonbeam: a SCaaS EOA still signs with its own key and runs no code (evm.md §5).
- **Deploy:** a Moonbase deploy of `PqChatStore` is chains-arweave T15, on the owner's word (no deploy before the freeze, owner
  2026-11-22).
- **Explorer:** Moonscan (Etherscan v2); verification (NET-EVM-12) with the API key named by `VERIFY_API_KEY_ENV`.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
