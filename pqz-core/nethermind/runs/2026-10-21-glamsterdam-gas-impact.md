# Glamsterdam (Amsterdam) gas rules and our pins — impact report (2026-10-21)

Context: the SCaaS testnet moved to Nethermind 2.2.0 with Amsterdam active from timestamp 1 (log
`2026-10-21-testnet-2.2.0.txt`). This note lists the Amsterdam EIPs that change gas accounting our pins rely on, and
what each means for (a) the rule "a `ROLL_MAX` rollover fits 0.75 · 2^24 as a relayed transaction" (`ROLL_MAX` = 192
measured 11,934,843 gas under today's rules, `pqz-core/pqzl/params/p16k/gas-16k-r192.txt` on branch `pqz-16k`), (b) the
rule "op 7 M = 8 fits the transaction cap" (16k, G = 1: ≈ 15.69 M relayed, input 309,591 B), and (c) the precompile gas.

**Sources.** Facts are from the Nethermind 2.2.0 source (tag `2.2.0`, commit `1d2aff00`; file names below), the 2.0.0 /
2.1.0 / 2.2.0 release notes and the EIP numbers they name; **[measured]** = measured on the SCaaS testnet today;
**[inference]** = computed here from the measured breakdowns, not measured. No timing benchmark and no precompile
calibration was run (owner's go needed).

## Amsterdam on Nethermind 2.2.0: which EIPs

`Nethermind.Specs/Forks/25_Amsterdam.cs`: EIP-2780, 7708, 7778, 7843, 7928, 7954, 7976, 7981, 8024, 8037, 8038, 8246,
8282. The testnet enables all of them **except EIP-7843** (SLOTNUM: the slot number comes from a consensus layer; the
Clique producer sets none and `HeaderValidator.ValidateSlotNumber` rejects such a block) **and EIP-8282** (builder
deposit / exit requests: end-of-block system calls into CL predeploys), for the same reason 4788 / 6110 / 7002 / 7251 are
off today. In a Parity chainspec the per-EIP keys are `eip<N>TransitionTimestamp`; the label `amsterdam` would fan out
to all thirteen and an explicit conflicting key is a start-up error (`HardforkLabels.cs`).

## The rules that change

| # | EIP (Nethermind) | Before (Osaka, today's pins) | Amsterdam | Source |
|---|---|---|---|---|
| 1 | **EIP-8037** state gas, 2-D gas | tx gas ≤ 2^24 (EIP-7825) | `tx.gas` ≤ 2^32 − 1 (`TX_MAX_TOTAL_GAS_LIMIT`, PR #13627); **execution** gas still ≤ 2^24 (`gas_left` capped at 2^24 − intrinsic execution, the rest is a state-gas reservoir); state gas spills into execution gas when the reservoir is empty; **an intrinsic execution or calldata floor over 2^24 makes the tx invalid at any gas limit** | `Eip8037Constants.cs`, `EthereumGasPolicy.TryCreateAvailableFromIntrinsic`, `TransactionProcessor.cs` (`TX_INTRINSIC_GAS_EXCEEDS_CAP`) |
| 2 | EIP-8037 state prices | SSTORE 0→x 20,000; new account 25,000; CREATE 32,000; code deposit 200 / byte | cost per state byte **1,530**: new slot 64 B = **97,920 state + 10,000 execution**; new account 120 B = **183,600 state**; code deposit **1,530 / byte state** + 6 / word execution | `GasCostOf.cs`, `CodeDepositHandler.cs` |
| 3 | EIP-8037 block gas | gasUsed ≤ gasLimit | block gas = max(Σ execution, Σ state) ≤ gasLimit; inclusion reserves min(2^24, tx.gas) execution **and tx.gas state**: a tx needs `tx.gas` ≤ block gasLimit | `Eip8037BlockGasInclusionCheck.cs` |
| 4 | **EIP-7976** calldata floor | floor 21,000 + 10 / token (EIP-7623; 40 / non-zero byte) | floor = 12,000 + 3,000 (cold recipient) + **64 gas per calldata byte**, zero bytes too | `IntrinsicGasCalculator.CalculateFloorCost`, `GasCostOf.TotalCostFloorPerTokenEip7976` |
| 5 | **EIP-2780** intrinsic | 21,000 | 12,000 + 3,000 for a non-self recipient (+ 6,000 with value); create 12,000 + `CREATE_ACCESS` 12,000 | `EthereumGasPolicy.CalculateIntrinsicGasWithoutMemo`, `GasCostOf.TransactionEip2780` |
| 6 | **EIP-8038** state access | cold account 2,600; cold SLOAD 2,100; SSTORE reset 2,900 (+ cold 2,100); access list 2,400 / 1,900 | cold account **3,000**; cold slot 2,100; **storage write 10,000** on the first change of a slot (+ 100 warm on SSTORE); access list 2,900 / 2,000; call with value 11,300 | `Eip8038Constants.cs`, `EthereumGasPolicy.TryConsumeStorageWriteCore` |
| 7 | EIP-7981 | access-list bytes not in the floor | access-list bytes join the floor (64 / byte) | `IntrinsicGasCalculator.CalculateFloorTokensInAccessList` |
| 8 | EIP-7778 | block gasUsed after refunds | block gas counts gas before refunds (the user still gets the refund) | release notes 2.0.0 |
| 9 | **EIP-7954** code size | 24,576 (testnet: `maxCodeSize` 0x10000 override) | **65,536** native, initcode 131,072 | `CodeSizeConstants.MaxCodeSizeEip7954` |
| 10 | EIP-7928 / 7708 / 8024 / 8246 | — | block access list in the header; ETH-transfer logs; DUPN / SWAPN / EXCHANGE; 7708 finalization logs off. No effect on our gas pins | `25_Amsterdam.cs` |

**Measured on the testnet [measured]:** the calldata floor is the binding limit for large PQZ inputs. Every input whose
call carries more than (2^24 − 15,000) / 64 = **261,909 calldata bytes** is refused — by `eth_call` (`Intrinsic gas
(execution 3715872, floor 17798040) exceeded cap of 16777216`) and by the pool — while the same input fitted before.
Refused today: every PQZH TRANSFER / TRANSFER0 / BURN / REFRESH (280–315 KB) and every PQZH op 7 (299–366 KB), and
PQZL op 7 M = 8 with the auditor (277,735 B); PQZL op 7 M = 8 without the auditor (257,508 B) still fits. A direct
transaction to `PQZ` with a 220,415 B PQZH disclosure used exactly the floor, 14,121,560 = 15,000 + 64 · 220,415
(standard 6,244,368). The precompile prices are unchanged: every probed row's gas equals the schedule formula.

## (a) `ROLL_MAX` fits 0.75 · 2^24 = 12,582,912 relayed

The rollover writes no new slot (`ACC_MARK`) and creates no account, so EIP-8037 state gas does not enter; its
calldata is 612 B (floor 54,168, not binding). What changes is EIP-8038 storage-write pricing:

- fixed part: 644 `acc` words rewritten in place, each cold: 2,100 + 2,900 = 5,000 → 2,100 + 10,000 = 12,100,
  **+7,100 × 644 = +4.57 M**: the 16k fit's fixed part 3,541,348 → **≈ 8.11 M** [inference];
- per entry (16k fit 43,203): + 400 (the entry's blob is a cold account, 2,600 → 3,000) and, where the entry's
  pending slot is deleted, + 7,100 (+ 100 warm): **≈ 43.6–50.8 k** [inference; how many slots one entry deletes
  depends on `INLINE_MAX` and was not traced here];
- intrinsic 21,000 → 15,000 (EIP-2780), the envelope's own writes + 7,100 each [inference].

**`ROLL_MAX` = 192 under Amsterdam ≈ 16.6–18.0 M — over 0.75 · 2^24, and at the high end over 2^24 itself**
[inference]. The largest multiple of 16 that keeps the rule: **≈ 80–96** ((12.58 M − 8.11 M − ≈ 0.12 M) / 43.6–50.8 k)
[inference]. The fixed part alone becomes ≈ 64 % of the budget. Re-measure before re-pinning (a Foundry with Amsterdam
rules, or the rollover itself on the testnet); Foundry 1.3.5 on this host has no Amsterdam EVM.

## (b) op 7 M = 8 fits the transaction cap

Not a gas-price question any more: **the 16k op 7 M = 8 (G = 1) input of 309,591 B cannot be carried by any
transaction under Amsterdam** — its relayed calldata floor is ≥ 15,000 + 64 · 309,591 = 19,828,824 > 2^24 (EIP-7976 +
EIP-8037), independent of the precompile row and of `tx.gas`. The same holds for every PQZH op 1 / 2 at 16k (≈ 302.7 KB
debit proofs) and today. The ceiling is **≈ 261,909 calldata bytes per transaction** (minus the envelope), i.e. a
precompile input of ≈ 255 KB after a relayed envelope of a few KB [inference for the envelope size]. Ways out (owner
decisions, not taken here): smaller proofs / statements (PQZL op 7 M ≤ 4, or M = 8 without the auditor at today's
parameters), splitting a proof across transactions into state (expensive: 97,920 state gas per new slot, 1,530 per
byte as code), or a chain that does not enable EIP-7976 (the testnet could drop `eip7976TransitionTimestamp`; mainnet
22776 would then differ from Ethereum's rules).

What does improve: the op's SSTORE2 code deposit moves out of the 2^24 execution budget (200 / byte execution →
6 / word execution + 1,530 / byte state) [fact: EIP-8037], so the execution part of a relayed transfer *drops* by
≈ 3.3 M (today's 16.7 KB blob) to ≈ 4.2 M (16k's ≈ 20.8 KB blob) [inference].

## (c) the precompile gas

- **Unchanged**: no Amsterdam EIP reprices a precompile, and `PQZ` / `MLDSA44` / `MLDSA65` are priced from our
  chainspec schedule; the gas is charged in the execution dimension (`IGasPolicy.TryConsumePrecompileGas`), so it
  counts against the 2^24 execution cap as before. A call to a precompile is still warm (100; the probe's constant is
  22, the same as on 1.39.0) [measured: every row = formula].
- Nethermind 2.x prices precompiles in `ulong` and requires precompile addresses to fit 32 bits for its fast index;
  the plugin keeps the `0x5caa5…` addresses by re-implementing `IReleaseSpec.IsPrecompile` (commit `e1998f0d`).
- The cost a user sees for a large-input verification becomes the calldata floor, not the precompile row: the
  220 KB PQZH disclosure paid 14.12 M (floor) for a 2.9 M row [measured].

## Other consequences worth a decision

- **Every op that stores an SSTORE2 blob pays ≈ 25.6 M (today, 16.7 KB) / ≈ 31.8 M (16k, 20.8 KB) state gas**, plus
  183,600 for the blob account and 97,920 per new pending slot [inference from rule 2]. A relayer must set `tx.gas` ≈
  execution + state (above 2^24 is allowed and needed), and a block holds only gasLimit / ≈ 32 M such ops in its state
  dimension (6 at 200 M). On mainnet the fee per transfer scales with it.
- **64 KiB code** is native (EIP-7954), but deploying it costs ≈ 100.3 M state gas (65,536 × 1,530) + 183,600 — the
  block gas limit must exceed the deploying transaction's `tx.gas`. The testnet's target is raised to 200 M for this.
  `UnderlyingPqzToken` (61,045 B runtime) ≈ 93.6 M state gas to deploy [inference].
- `docs/node/ops.md` (`max_gas_per_tx = 16_000_000` on the testnet) and the relayer's gas-limit logic assume the old
  single-dimension cap; they need the 2-D rule (execution ≤ 2^24, total ≤ 2^32 − 1, floor ≤ 2^24) [not changed here].
