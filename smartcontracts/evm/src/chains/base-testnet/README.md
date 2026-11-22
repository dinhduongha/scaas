
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
