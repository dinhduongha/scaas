# T66b: the library organisation and the 60 M fit (registry pair, body modules) — design

**Status:** SPECIFIED; nothing is built. Plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md) task **T66b**,
Steps 1 and 2 (parts 1, 2 and 5 were built as T66a; 3h, T58–T65, has landed). Branch `ua-mtx-merge`, tree `7d653925` (the later
commits touch docs only). **Before any code: a Fable review** (a body module reached by `DELEGATECALL` is security-relevant).
Measurements: [`runs/2026-11-09-ua-mtx-merge-t66b-sizes-deploy-gas.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b-sizes-deploy-gas.txt)
(Step 1, commit `fba4dbb7`) and [`runs/2026-11-09-ua-mtx-merge-t66b/`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/README.md)
(Step 2). Background: research [`evm-library-organisation.md`](../../research/evm-library-organisation.md) (`db93393b`, measured
at `937b454f`; its tools rerun here at the tip). **Everything cryptographic here is UNAUDITED.** Tags: [measured] a build or a
forge run of this step; [estimate] arithmetic over measured figures; [inference] follows from the EVM's rules.

**Owner rulings this spec applies, not reopens (2026-11-07, CTR-GOV-19's Change):** every deployed contract, libraries
included, fits one transaction of **60 M** on T10's formula, `asked = (regular + state) × 1.05`, EIP-8037 inclusion (regular +
state within the limit, never a block's `gas_used`), and regular × 1.05 < 2^24; **lever L in its forward form** (every body but
the ERC-20 core in `DELEGATECALL` body modules, typed stubs and the one `nonReentrant` kept); **per-kind modules and their
release cost accepted**; **the registry pair rebalanced first** (3g's R4: if both still miss 57 M, 60 M is accepted); the PQZ
calldata cost (+0.2 % to +4.8 %) accepted; **lever D deprecated**; the owner's 2026-11-01 ruling of one registry library. The
owner's suggestions (split `TradeLib`, a payable library, the shared parts on their own, reduce each kind) are evaluated in §7,
not taken as rulings. Repository rules kept: explicit parameters, every state-changing `mtx*` relayable, no EIP-7702, one rule
on every chain, nothing deployed upgraded, backup to `legacy/`, chain-neutral releases (CTR-TOK-29, proposed).

## 1. Step 1: where the tip stands — SPECIFIED (measured inputs)

Every deployed contract, each its own CREATE2 transaction (the T33 / T51 probe; under `isolate` the probe call is a transaction,
so intrinsic gas and calldata are in it); a release adds the factory frame of `deployImplementation`, measured at **0.31 M**
asked (T10 had 0.37 M) [measured]. Old = the plan block's `d2552671` figures.

| Contract | runtime B old → new | asked | 60 M | over by |
|---|---|---:|---|---|
| `WrappedPqzRegulatedToken` (13) | 64,996 → **73,511** | 123.86 M | no | 63.86 M (≈ 38.1 KB) |
| `WrappedPqzToken` (5) | 57,026 → 61,174 | 103.19 M | no | 43.19 M |
| `WrappedZetherRegulatedToken` (11) | 59,678 → 60,724 | 102.45 M | no | 42.45 M |
| `NormalPqzRegulatedToken` (12) | 55,472 → 59,371 | 100.18 M | no | 40.18 M |
| `WrappedZetherToken` (3) | 51,522 → 52,709 | 89.02 M | no | 29.02 M |
| `WrappedRegulatedToken` (9) | 51,292 → 52,302 | 88.34 M | no | 28.34 M |
| `NormalPqzToken` (4) | 47,714 → 51,821 | 87.53 M | no | 27.53 M |
| `NormalZetherRegulatedToken` (10) | 49,020 → 50,030 | 84.54 M | no | 24.54 M |
| `WrappedToken` (1) | 43,503 → 44,635 | 75.49 M | no | 15.49 M |
| `NormalZetherToken` (2) | 41,076 → 42,222 | 71.45 M | no | 11.45 M |
| `NormalRegulatedToken` (8) | 40,638 → 41,561 | 70.35 M | no | 10.35 M |
| `UARegistryLib` | 37,536 → 38,070 | 63.98 M | no | 3.98 M (≈ 2.4 KB) |
| `SCaaSDex` | 33,704 → 34,929 | 59.20 M | yes | 0.8 M left |
| `NormalToken` (0) | 32,870 → 33,889 | 57.49 M | yes | 2.5 M left |
| `UARegistry` | 31,438 → 33,151 | 56.38 M | yes | 3.6 M left |
| `OpenFactory` | 15,821 → 28,438 | 47.96 M | yes | |
| `ZetherLib`, `PqzTransferLib`, `PqzViewLib` | 25,351 / 19,724 / 19,886 → 26,991 / 24,456 / 24,201 | 45.42 / 41.18 / 40.75 M | yes | |
| every other library and contract | ≤ 21,003 B | ≤ 38 M | yes | |

Regular × 1.05 < 2^24 everywhere (largest 5.16 M, kind 13). A cross-check on T65's local Nethermind copy (real receipts, frame and
calldata included) gives 2 to 2.5 % less than forge's regular + state for the same releases: the table errs on the safe side.
Since `d2552671` the PQZ kinds grew 3.9–8.5 KB (3f, 3h, chain-neutral), the others 0.9–1.2 KB, `OpenFactory` 12.6 KB; kind 13 is
5.0 KB above the research note's projection.

**The 60 M line in runtime bytes** (fitted on these rows): a release through `deployImplementation` **35,386 B** (1,675.1 gas/B +
0.42 M + 0.31 M frame); a body module (a contract on the token's bases, no frame) **35,570 B**; a library **35,694 B** (1,674.8
gas/B + 0.22 M); `UARegistry` with its constructor ≈ **35,286 B** (1,694.7 gas/B + 0.2 M). At **57 M** (the margin line, §2):
33,594 / 33,780 / 33,903 / 33,516 B [estimate].

**Kind 13's `DeployFailed()` in T65:** gas, not size, not init. The release needs 117.97 M (regular + state, frame included);
`e2e.py` estimates every transaction with `eth_estimateGas`, the copy's Nethermind configs set no `JsonRpc.GasCap`, so the
estimate ran under the default 100 M cap: the CREATE2 inside `deployImplementation` ran out of gas, returned 0 with no data, and
`_deploy` reverted `DeployFailed()` (the only place that raises it). The copy allows the size (its genesis: `maxCodeSize`
0x20000, EIP-7954 off) and the init code runs (forge deploys it). This organisation removes the cause (every transaction ≤ 60
M); the e2e rerun of kind 13 is a task (§12).

**Hedera's code limit [measured, simulation]:** the public Hedera testnet (chain 296, the JSON-RPC relay) accepts a 24,576 B
runtime and refuses 24,577 B (`CONTRACT_EXECUTION_EXCEPTION`): Hedera keeps EIP-170
([`hedera-codesize.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/hedera-codesize.txt)). Step 5 deploys on
Hedera; owner question Q1 (§11).

## 2. Targets — SPECIFIED

- **T-1, hard:** every deployed contract (each token implementation, each body module, each library, each plain contract) asks
  ≤ 60 M as its own transaction, regular × 1.05 < 2^24.
- **T-2, the margin of Step 3:** each new or changed contract aims at ≤ 57 M (the byte lines of §1). A contract between 57 M and
  60 M is reported with its figure, not a stop; the registry pair follows R4 (60 M accepted if both miss 57 M).
- **T-3, Hedera:** per Q1. Recommended: every contract the Hedera release set deploys fits 24,576 B of runtime.
- **The size window closes:** no contract above 65,536 B, the `_above64KiB` pin of kind 13 removed, `size-baseline.json` rows
  old → new with the reason; the size gate's stop line becomes T-1's line per form (release 35,386 B, module 35,570 B, library
  35,694 B, an error above it; T-2's line a notice); CTR-GOV-19's ceiling (131,072 B / 262,144 B) stays above everything.

## 3. The measured map at the tip — SPECIFIED (measured inputs)

Function-level and domain sizes come from the library study's tools rerun on the tip in a scratch worktree (solc's rerun equals
forge's 189 runtime objects byte for byte): `size-map.out` (§1 every contract by domain, §2 functions across the twelve kinds,
§3 shared against unique, §4 entries per domain, §5 kinds 0 and 13 entry by entry, §6 library top functions, §7 coders).

### 3.1 Each kind by domain (runtime B) [measured]

| kind | runtime | dispatch + coders | guard | ERC-20 core | pipeline | named + pay | trade | governance | init, tables, meta | wrapped | Zether | PQZ | regulated | other |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 33,889 | 15,945 | 571 | 1,918 | 5,490 | 2,170 | 1,813 | 2,254 | 2,316 | | | | | 1,412 |
| 1 | 44,635 | 19,796 | 863 | 2,084 | 5,993 | 2,280 | 2,146 | 2,367 | 2,714 | 4,916 | | | | 1,476 |
| 2 | 42,222 | 19,591 | 837 | 1,914 | 5,774 | 2,162 | 1,656 | 2,178 | 1,938 | | 4,632 | | | 1,540 |
| 3 | 52,709 | 22,755 | 1,160 | 2,085 | 6,257 | 2,272 | 2,105 | 2,286 | 1,754 | 4,136 | 6,327 | | | 1,572 |
| 4 | 51,821 | 25,298 | 859 | 1,898 | 5,690 | 2,134 | 1,857 | 2,182 | 3,313 | | | 7,009 | | 1,581 |
| 5 | 61,174 | 27,880 | 1,177 | 2,065 | 6,260 | 2,217 | 2,146 | 2,291 | 2,000 | 4,078 | | 9,492 | | 1,568 |
| 8 | 41,561 | 19,001 | 751 | 1,941 | 5,610 | 3,285 | 1,775 | 2,131 | 2,568 | | | | 3,055 | 1,444 |
| 9 | 52,302 | 22,695 | 1,040 | 2,107 | 6,122 | 3,439 | 2,166 | 2,347 | 3,013 | 4,466 | | | 3,399 | 1,508 |
| 10 | 50,030 | 22,506 | 1,011 | 1,937 | 5,909 | 3,260 | 1,656 | 2,057 | 2,194 | | 4,797 | | 3,131 | 1,572 |
| 11 | 60,724 | 25,672 | 1,335 | 2,108 | 6,389 | 3,423 | 2,125 | 2,276 | 2,053 | 4,100 | 6,163 | | 3,476 | 1,604 |
| 12 | 59,371 | 28,009 | 1,029 | 1,921 | 5,812 | 3,264 | 1,819 | 2,078 | 3,600 | | | 7,143 | 3,083 | 1,613 |
| 13 | 73,511 | 32,025 | 1,621 | 2,291 | 6,811 | 3,675 | 2,317 | 2,446 | 2,474 | 4,333 | | 10,103 | 3,708 | 1,707 |

"Other" holds the chain-neutral reader `ChainEnvCode` (924–1,075 B in every kind), math and metadata. The dispatcher and the ABI
coders are 44–47 % of every kind: they grow with the entry count (86 entries on kind 0, 188 on kind 13) and with arguments
re-encoded for a library call (the encoders, 4.8–10.5 KB). 24.2–27.8 KB of each kind is code present in all twelve; 0.2–0.9 KB
is a kind's own.

### 3.2 The libraries (runtime B; the largest functions) [measured]

| Library | B | holds | largest functions |
|---|---:|---|---|
| `UARegistryLib` | 38,070 | registration writers of the registry (11 entries) | `UAKinds.name` 1,193; `setPqzKey` 1,096; `setKemKey` 695; `_slotCap` 606 |
| `ZetherLib` | 26,991 | Zether bodies (16 entries) | `init` 1,184; `normalSelectors` 1,045; `validateEnv` 742 |
| `PqzTransferLib` | 24,456 | PQZ transfers (2) | `PqzCore._parseMulti` 1,301; `_multiBuffer` 992; `_bundleMulti` 831 |
| `PqzViewLib` | 24,201 | PQZ views and statements (11) | `_parseMulti` 1,314; `_multiBuffer` 1,034; `verifierShape` 732 |
| `WrappedLib` | 17,095 | legs, wrap, unwrap, rate, rescue (20) | `_addLeg` 978; `initToken` 663; `rescue` 581 |
| `PqzBurnLib` | 15,404 | PQZ burn (1) | `verifierShape` 732; `verdictStatus` 588 |
| `GovernanceLib` | 14,513 | roles, grants, features (14) | `_write` 905; `init` 649 |
| `PqzStateLib` | 14,062 | PQZ state, setters, rollover (12) | `init` 1,221; `verifierShape` 737 |
| `ZetherWrappedLib` | 12,067 | wrapped Zether (4) | `selectors` 1,888 |
| `MtxPipelineLib` | 11,069 | the signed pipeline (13) | `_authorizeNative` 317; `_close` 314; `payMeta` 296 |
| `RegulatedLib` | 10,418 | regulated powers, tax (14) | `freeze` 558; `init` 438 |
| `PqzWrappedLib` | 5,563 | wrapped PQZ (2) | `selectors` 1,808 |
| `TradeLib` | 4,842 | trade state (6) | `record` 555; `precheck` 462 |
| `HederaLib` | 767 | HIP-632 (1) | |

Every library but `UARegistryLib` fits T-1; all but `UARegistryLib` fit T-2. They stay as they are (§4.3).

### 3.3 The forms of the token [measured]

`fwd_spike.py` keeps every entry's signature, modifiers and ABI and turns the chosen bodies into one forward
([`token-forms.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/token-forms.txt)):

| kind | 0 | 1 | 2 | 3 | 4 | 5 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| today | 33,889 | 44,635 | 42,222 | 52,709 | 51,821 | 61,174 | 41,561 | 52,302 | 50,030 | 60,724 | 59,371 | 73,511 |
| V6: all but the pipeline and the ERC-20 core forwarded | 20,461 | 24,289 | 25,760 | 29,818 | 27,937 | 33,393 | 23,939 | 27,726 | 29,024 | 33,249 | 31,273 | **36,853** |
| **V7: all but the ERC-20 core (the owner's form)** | **13,031** | **16,373** | **17,939** | **21,405** | **19,998** | **24,784** | **16,198** | **19,472** | **20,831** | **24,438** | **23,010** | **27,920** |
| floor: the whole ABI as bare stubs | 7,405 | 10,541 | 10,027 | 13,252 | 11,556 | 15,405 | 9,229 | 12,301 | 11,590 | 14,959 | 13,104 | 17,066 |

V6 misses T-1 on kind 13 (36,853 > 35,386 B); V7 fits every kind, at most 47.5 M (kind 13). Eleven entries stay whole in every
spike because another kept routine calls them (§4.4).

### 3.4 The body modules [measured bounds]

A module is measured as the kind built with every entry outside the module forwarded, less the forwarded stubs at the kind's
floor cost per entry (`mod_est.py`, [`modules.out`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/modules.out)); a
complement build also keeps a residue no real module holds (everything forwarded: 4.0 KB on kind 0 to 10.3 KB on kind 13). The
table gives lower–upper KB, before the library code the modules take in (§4.2: + `MtxPipelineLib` in P, + `TradeLib` in T):

| kind | token V7 / asked | P: pipeline, named, pay | T: trade | A: admin | W: wrapped, regulated | Z: Zether | Q: PQZ | modules | release asked (sum) | today |
|---|---|---|---|---|---|---|---|---:|---|---:|
| 0 | 13.0 KB / 22.6 M | 13.7–17.7 | 5.3–9.3 | 15.9–19.9 | | | | 3 | 82–103 M | 57.5 M |
| 1 | 16.4 / 28.2 | 14.3–18.5 | 7.0–11.3 | 11.1–15.4 | 14.9–19.1 | | | 4 | 109–138 | 75.5 |
| 2 | 17.9 / 30.8 | 14.0–20.3 | 4.6–10.9 | 14.1–20.4 | | 13.0–19.3 | | 4 | 109–151 | 71.5 |
| 3 | 21.4 / 36.6 | 14.6–21.2 | 6.3–12.8 | 7.5–14.0 | 14.4–20.9 | 18.0–24.5 | | 5 | 140–195 | 89.0 |
| 4 | 20.0 / 34.2 | 13.1–21.1 | 4.4–12.3 | 16.2–24.1 | | | 18.1–26.0 | 4 | 123–176 | 87.5 |
| 5 | 24.8 / 42.2 | 13.9–22.8 | 5.3–14.1 | 7.9–16.8 | 13.5–22.4 | | 23.5–32.3 | 5 | 152–226 | 103.2 |
| 8 | 16.2 / 27.9 | 16.2–21.6 | 5.4–10.7 | 16.3–21.7 | 4.9–10.2 | | | 4 | 101–137 | 70.3 |
| 9 | 19.5 / 33.3 | 16.9–22.5 | 7.2–12.7 | 11.5–17.1 | 18.6–24.2 | | | 4 | 126–163 | 88.3 |
| 10 | 20.8 / 35.6 | 16.6–24.2 | 4.6–12.3 | 14.4–22.1 | 4.8–12.4 | 13.7–21.3 | | 5 | 128–192 | 84.5 |
| 11 | 24.4 / 41.7 | 17.3–25.2 | 6.4–14.3 | 7.8–15.7 | 18.8–26.6 | 18.0–25.8 | | 5 | 158–224 | 102.5 |
| 12 | 23.0 / 39.3 | 15.8–25.2 | 4.4–13.8 | 16.5–25.9 | 3.9–13.3 | | 18.4–27.8 | 5 | 140–219 | 100.2 |
| 13 | 27.9 / 47.5 | 16.6–26.9 | 5.4–15.7 | 8.3–18.6 | 18.0–28.3 | | 23.2–33.5 | 5 | 169–256 | 123.9 |

Every module fits T-1 at its upper bound (largest: kind 13's Q, 33.5 KB, 56.5 M). At T-2 the upper bounds of 5's and 13's Q
miss 33,780 B; the build measures the real module and splits Q (§4.2) when it misses. P and T together (the study's MAB) reach
31.7 KB on kind 13 before `MtxPipelineLib` and `TradeLib` join: they stay apart.

## 4. The organisation — SPECIFIED

### 4.1 The rule (lever L, forward form)

1. **The token keeps every entry point:** signature, modifiers (the one `nonReentrant`, the governance gates), mutability, ABI,
   events and errors as today. It keeps these bodies itself (size-map's `erc20-core`): `transfer`, `transferFrom`, `approve`,
   `balanceOf`, `allowance`, `totalSupply`, `name`, `symbol`, `decimals`, the UA ledger's `balanceOfUA` and `transferToUA`, plus
   `kind`, `implementation` (it reads the implementation's own `_SELF`) and `modules` (§4.5), `_update` with its hooks,
   `_msgSender`, the guard. **Every other entry's body is one forward:** the unchanged calldata by
   `DELEGATECALL` to one module of the kind, its return or revert data returned verbatim (views and pure entries forward through
   the registry's R2 cast, `_libView`).
2. **A body module** is a contract compiled from the kind's own bases and hooks, holding one group of bodies, reached only by
   `DELEGATECALL` from the token's stubs, its code hash pinned in the release as a library's is (§4.5).
3. **One cold account per operation where it is one today:** a module takes in, as internal code, the library code its group
   calls today when no other contract needs that call (P holds the pipeline's code; T `TradeLib`'s and the trade authorisation);
   libraries that hold state rules for several kinds, or are too large to take in, stay libraries (§4.3).
4. **Bodies are written once,** as internal functions in their domain's base file; the token's entry forwards, the module's
   entry calls the body (no guard). A stub never re-encodes its arguments (the research note's G3).

### 4.2 The modules of each kind

| Module | domains (size-map) | entries (kind 13; the others hold the subset their kind has) | takes in | links / reaches |
|---|---|---|---|---|
| **P** pipeline | pipeline, named-transfer, pay | `mtxExecute`, `mtxBatch`, `mtxCancelNonce`, `executeMetaTransaction`, `cancelNonce`, `mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayReceiverFee`, `payWithFee`, `payWithFeeToUA`, `mtxRelayFee`, `metaPayId`, `payLane`, `receiverFeeDigest`, on 8–13 the tax (`mtxPayWithTax`, `payWithTax`, `setTaxRate`, `setTaxRecipient`, `taxConfig`), the digests, nonce views, `registry`, `IS_HEDERA`, `supportedModes` (28 entries on 8–13, 23 on 0–5) | `MtxPipelineLib`'s code (+3–6 KB [estimate]) | `HederaLib`; `RegulatedLib` on 8–13 |
| **T** trade | trade | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, `tradeOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `minNonce`, `pulled`, `restorePulled`, `mtxWrapOrder` (9–10) | `TradeLib`'s code (4.8 KB) and the authorisation of the trade path | — |
| **A** admin | governance, init, tables, token-meta, kind-normal | governance entries (21–22), `initialize`, `mtxSelectors`, `supportsInterface`, `chainEnv`, `validateEnv`, `chainUid`, `factory`, `creator`, `eip712Domain`, metadata views, `rescue`, `mint`, `mintToUA`, `burn` on the normal kinds (35–42) | — | `GovernanceLib`, `WrappedLib` (rescue) |
| **W** wrapped / regulated (1, 3, 5, 8–13) | wrapped, regulated | `wrap` ×2, `wrapToUA`, `mtxWrap*`, `unwrap*`, `mtxUnwrap*`, rates, reserve (`addReserve`), legs, `mint` / `mintToUA` of the wrapped kinds; the regulated powers (freeze, pause, force and operator transfers, orders, `regulatedConfig`, the regulated `rescue` and `disableFeature`) (15–49) | — | `WrappedLib`, `RegulatedLib`, `ZetherWrappedLib` / `PqzWrappedLib` where the kind has them |
| **Z** Zether (2, 3, 10, 11) | zether | the Zether entries, `mtxWrapShield` and the unshield-unwraps on 3 and 11 (35–43) | — | `ZetherLib`, `ZetherWrappedLib` |
| **Q** PQZ (4, 5, 12, 13) | pqz | the PQZ entries, 3f's and 3h's included, `mtxWrapShield` and `mtxUnshieldUnwrap` on 5 and 13 (47–57) | — | `PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`, `PqzWrappedLib` |

**Modules per kind:** 3 (kind 0), 4 (1, 2, 4, 8, 9), 5 (3, 5, 10, 11, 12, 13): 53 modules for the twelve kinds. On the normal
regulated kinds (8, 10, 12) W holds only the regulated powers (3.9–13.3 KB) and may join A when their sum fits T-2. **Splitting
rule:** a module that misses T-2 when built splits along its domains (Q: the PQZ ops and their verdict entries / the PQZ state,
setters and views; P: the signed pipeline and named transfers / pay and the relay fee); a module that splits never forwards to
its sibling (§4.6 M7). Which entry goes to which module is fixed per kind by `size_map.entry_domain` (`size-map.out` §4, §5),
recorded in a table the build writes into the contracts doc.

### 4.3 Which library holds what

| Library | Stays | Why |
|---|---|---|
| `GovernanceLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`, `PqzWrappedLib`, `RegulatedLib`, `HederaLib` | unchanged, each its own transaction | shared by several kinds, or too large to take into a module (the PQZ libraries are 5.6–24.5 KB each beside a Q of 18–33 KB) |
| `MtxPipelineLib` | unchanged | `GovernanceRouter`, `MandateWallet`, `HederaMandateWallet` and the DEX call it; its functions become thin `external` wrappers of `internal` ones, which P compiles in (rule 3) |
| `TradeLib` | unchanged | the DEX's path; T compiles its `internal` core in |
| `UARegistryLib` | rebalanced (§5) | part 3 |

### 4.4 Source structure

- **Per kind, one abstract core:** the kind's bases (today's `MetaTokenBase` → … → layers) and its hook overrides (`_mtxRule`,
  `_uaAllowed`, `_batchable`, `_envelopeBinding`, `_update`, the regulated hooks), **with no external entry but the kept ERC-20
  core.** Storage is declared only in the bases (OZ `ERC20` slots 0–4 and the ERC-7201 namespaces `scaas.*`), so the token and
  every module of the kind share one layout by construction (§8).
- **Faces:** the token face (every entry as a stub; it inherits the kind's interfaces, `IPqzToken`, `IZetherToken`, …) and one
  face per module (its entries calling the bodies; it inherits no interface it does not implement).
- **The eleven entries another routine calls** (`supportedModes` ×2, `setGrant`, `receiverFeeDigest`, `validateEnv`,
  `mtxUnshield`, `mtxUnshieldUnwrap`, `unwrapBinding`, `mtxRollOverBatch`, `mtxRollOverSigned`, `mtxSetRollOverMode`) each become
  an `external` entry and an `internal` helper (the research note's G2), so their stubs forward too.
- Today's bodies move to `legacy/ua-mtx-merge/t66b/` (backup, not delete) before the rewrite.

### 4.5 Wiring, pins and the release

- **Module addresses** are implementation immutables, passed in `implArgs` (a fixed list per kind; the regulated kinds keep their
  `REGISTRY_CODEHASH` beside it). The implementation's constructor refuses a module without code (`ModuleMissing(i)`), so a stub
  never `DELEGATECALL`s an empty account (which would succeed and return nothing).
- **Pins:** each kind's `Env.libs` / `libCodeHashes` lists its modules beside its libraries; `deployImplementation` checks every
  code hash before the release exists (`LibraryCodeHashMismatch`, as today). The token answers `modules()` (a kept view, the
  immutables in a fixed order) and `_checkImplementation` requires each of them in the env's `libs` (`ModuleNotPinned`), so a
  release cannot name a module whose code the factory did not check. The trust is a library's today: the registrar publishes the
  env and deploys the release. `LinkClosure`: a release's closure is its link
  references, its module immutables and their link references, recursively.
- **Chain-neutral:** a module has no chain value (the env is read from the clone's code, `ChainEnvCode`'s clone test from the
  code itself, CN-1; `FACTORY` is the same on every chain); it is deployed by the deterministic deployer with `DEPLOY_SALT`, at
  the same address on every chain. `releases.json` gains a row per module.
- **Deploy order:** libraries, then modules (each its own transaction and its own public gate), then the implementation through
  `deployImplementation`. `DeployBase`, `deploy.sh`, `e2e.py`, `script/hedera/DeployHedera.s.sol` follow.

### 4.6 Module rules

| # | Rule |
|---|---|
| M1 | Constructor `(address factory_)` as the token's: it locks the module's own storage (`initialized`), the same EIP-712 name; nothing else |
| M2 | Every module entry is `onlyDelegated` (`address(this) != _SELF`, the module's own immutable; ≈ 20 B and ≈ 30 gas per entry): a direct call reverts `NotDelegated()` |
| M3 | No `nonReentrant` in a module; the stub's guard covers the frame |
| M4 | A module entry has the token entry's mutability exactly (`payable` for `wrap` ×2, `wrapToUA`, `addReserve` in W, `mtxWrapShield` in Z or Q): under `DELEGATECALL` `msg.value` is the caller's, and a non-payable entry would revert on it |
| M5 | Opcodes: no `SELFDESTRUCT`, no `CALLCODE`; `DELEGATECALL` only to the release's libraries; `CALL` / `STATICCALL` as the bodies do today (self-call, registry, verifiers, underlyings) |
| M6 | No state variable of its own; its layout equals its kind's (§8) |
| M7 | One hop: a module never forwards to another module; a body that needs another group's body reaches it only by the self-call it makes today (`address(this).call`, `this.disclosureStatement`) |
| M8 | `_SELF` never decides "is this the implementation" in a module body; `implementation()` stays a kept view of the token |

## 5. Part 3: the registry pair — SPECIFIED

**Measured:** `UARegistryLib` 38,070 B (63.98 M), `UARegistry` 33,151 B (56.38 M); the pair 71,221 B against 70,980 B for both 60 M
lines: **moving code from one to the other cannot fit both**; at least ≈ 0.25 KB must go, ≈ 3.8 KB for both at 57 M. The two
share ≈ 9.4 KB of duplicated code (156 labels in both: `UAKinds.name` 1,193 B, `keyHashOf` 452, `groupName` 358, the `UAStore`
readers ≈ 1.5 KB, `SSTORE2.readChunks`, ECDSA, the record decoders) [measured,
[`registry-dex-factory-entries.out`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/registry-dex-factory-entries.out)].

**Chosen, in this order, each measured before the next (one library stays, the owner's 2026-11-01 ruling):**

1. **R-1, one copy of the pure helpers:** the registry's pure views whose code the library already holds become `_libView`
   forwards into `UARegistryLib`: `keyHashOf`, `uaOf`, `uaMessage`, `kindName`, `portableDomainSeparator`,
   `registrationDigest`, `pqzKeyDigest`, `pqzKeyRecordDigest`, `pqzKeyVersionDigest`, `pqzKeyVersionRecordDigest`,
   `portableRecordDigest`, `kemRecordDigest`, `kemRecordHash`, `uaAuthDigest` (2,269 B exclusive in the registry [measured]). No
   contract calls them on chain (they serve `eth_call`); the hot views (`requireAuthorized`, `requirePortable`, `kindOf`,
   `recordOf`, `checkedOf`, the key and member readers) stay in the registry. [estimate] registry −1.9 to −2.1 KB, library +0.3
   to +0.6 KB: the pair ≈ 69.6 KB, ≈ 1.4 KB under both lines together.
2. **R-2, rebalance:** whole library writers move into the registry, largest exclusive code first, until the library is under
   its line with the larger share of room: `storePqzPop` (1,955 B exclusive), `setKemKey` (1,090), `acceptMembership` (981); each
   reads its kind's configuration from `_cfg` in place of the appended words. [estimate] after the first two: registry ≈ 34.2 KB
   (≈ 58.1 M), library ≈ 35.5 KB (≈ 59.7 M); after the third, ≈ 35.1 / 34.5 KB (≈ 59.8 / 58.0 M).
3. **Stop:** both ≤ 60 M (R4 accepts 60 M: neither is expected at 57 M). If both cannot reach 60 M without changing a verification
   rule, the build stops and asks the owner (a second registry library, or the forward form on more registry entries).

The registry's storage, events, errors, ABI and every verification rule are unchanged; vectors, clients and the node do not
move. `UAGas` / `UARegistryGroups` pins move old → new (`--isolate`). Hedera (24,576 B) needs at least three contracts for the
pair: Q1.

## 6. What each split costs per call — SPECIFIED (measured forward, estimated net)

**The forward, measured** ([`ForwardGas.t.sol`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/ForwardGas.t.sol);
forge gas inside one transaction: stub → module against the same body called directly):

| calldata | 0 | 256 B | 1 KB | 4 KB | 21 KB | 100 KB | 340 KB |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold module (its 2,600 included) | 3,439 | 3,487 | 3,633 | 4,241 | 8,234 | 41,311 | 287,844 |
| warm module | 539 | 587 | 733 | 1,341 | 5,334 | 38,411 | 284,944 |

The quadratic part is the memory of the copy (`3w + w²/512`): a hop of a large calldata pays it once more. The transaction's
own calldata is paid once either way (at 340 KB the EIP-7976 floor alone is 21.78 M [measured]).

**Per operation, old → new** (hops from §4; today's figures from T40's `MetaTxGasV2` and T65's chain receipts; the net is
[estimate] until Step 4 moves the pins with measured old → new):

| Operation | today | what changes | Δ |
|---|---|---|---|
| ERC-20 `transfer`, `transferFrom`, `approve` | in the token | nothing | 0 |
| relayed transfer (`mtxTransfer`, `mtxExecuteTransfer`: 191,312 fresh lane) | token re-encodes ≈ 35 words into `MtxPipelineLib` (cold) | one forward of ≈ 1 KB to P (cold, 3.6 k), pipeline code inside P, nothing re-encoded | ≈ −0.6 to 0 k; +3.6 k if P did not take the pipeline in |
| `mtxPay` (202,216 fresh lane) | `payMeta` (cold) + `preTransferUA` with `PayMeta` re-encoded | one forward to P | ≈ −1.5 to −0.3 k |
| `mtxTrade`, first fill | `TradeLib` and `MtxPipelineLib`, both cold | one forward to T (cold) | ≈ −2.6 k |
| generic signed op (`mtxExecute`) | pipeline library cold, op in the token | stub → P (cold) → self-call → the op's stub → its module | +0.7 k (op in P, warm) to +3.4 k (op in A or W, cold) |
| governance, admin, wrap / unwrap, regulated powers (direct or through the router) | the op's library, cold, or in the token | + the module (cold) | +3.4 to +3.6 k |
| PQZ op 1 (≈ 70 KB, 26.7 M on the copy) | two copies today (self-call, library call) | + one forward direct, + two relayed (≈ 27 k each) | +27 k / +55 k: +0.1 % / +0.2 % |
| PQZ op 7, M = 4 (≈ 121 KB, 52.8 M) | as above | ≈ +52 k per hop | +0.1 % / +0.2 % |
| largest PQZ op (≈ 340 KB; ≥ 21.8 M by its calldata floor alone) | as above | +0.29 M per hop | ≤ +1.3 % direct / ≤ +2.6 % relayed |
| Zether shielded transfer (a few KB) | as above | + the Z module, two small copies | ≈ +4 to +8 k |

Within the owner's accepted PQZ range. A forward keeps 1/64 of the gas at each hop: a body's gas floor (`SigCheck`'s ERC-1271
caps, the verify budget, `UAVerifyGas`) sees 63/64 of the stub's gas, so a relayer's estimate grows by that share.

## 7. The owner's suggestions, evaluated — SPECIFIED

| Suggestion | Verdict | Numbers |
|---|---|---|
| Split `TradeLib` | **Yes, as module T** (the trade entries with `TradeLib`'s internal core and the trade authorisation); `TradeLib` stays for the DEX | token −1.7 to −2.3 KB of trade bodies plus their coders (study: −2.84 to −3.58 KB at `937b454f`; the trade code has not changed since); T 4.4–15.7 KB; first fill ≈ −2.6 k |
| A payable library | **Not a Solidity library** (a library function cannot be `payable`; today `msg.value` is passed as an argument to `WrappedLib`). **The payable bodies go in the module of their domain** (W: `wrap` ×2, `wrapToUA`, `addReserve`; Z or Q: `mtxWrapShield`), whose entries mirror the stubs' payability (M4) and read `msg.value` themselves; no separate payable module | no gas change beyond the forward |
| Pay on its own (a pay library) | **Inside P, not on its own** | alone (Mpay) 10.8–18.0 KB and +2.6–2.9 k per pay call (its own cold account and its own copy of the transfer pipeline); inside P −1.5 to −0.3 k |
| The shared parts on their own | **Yes, behind forward stubs (P and A per kind)**; one module per family across kinds is a later release-cost lever (the hooks would become data), not a size lever | the ≈ 24–28 KB every kind carries |
| Reduce each kind | **Yes: V7** | tokens 13.0–27.9 KB (22.6–47.5 M) |

Not taken: a `fallback` dispatcher (the owner chose typed entries, variant A, 2026-10-21; it saves bytes, no gas, and loses the
typed ABI); `optimizer_runs` or `via_ir` (they move every kind's gas and re-verify the tree); lever D (deprecated); micro-levers
on single functions.

## 8. The split checklist (3e spec §6.4) — SPECIFIED

| Item | How the organisation meets it | Test |
|---|---|---|
| `DELEGATECALL` storage | a module is compiled from its kind's core, which declares all storage (OZ `ERC20` slots 0–4, the ERC-7201 namespaces); no module declares its own (M6) | `test/v2/layout/` gains a row per module, equal to its kind's; `namespaces.json` unchanged |
| `this` | under `DELEGATECALL` `address(this)` is the clone in every frame: the self-call re-enters the token's dispatcher, the stub's guard consumes the ticket in the clone's transient storage, as today; `this.f.selector` is compile-time | the ticket path relayed through P into an op of another module |
| `msg.sender`, `msg.value`, `msg.data` | kept by `DELEGATECALL`: `_msgSender()`, the ticket, `requireNotDelegated` read the same values; the forwarded calldata equals the stub's, so calldata offsets and appended words read the same; payability mirrored (M4) | `msg.value` to each payable entry; a non-payable module entry mutant |
| Return data | the stub returns the module's return and revert data verbatim, never re-encoded; a revert's selector and arguments pass through | the differential test (§10): return, revert data, logs, slots, calls out, per entry |
| The one `nonReentrant` | in the stub only (M3); `_selfCall`'s fail-closed check (`guarded`) unchanged | a module guard mutant reverts every call (`Reentrancy`) |
| `LinkClosure` pins | modules join the release's closure with code-hash pins (§4.5), the opcode rule M5 for modules; the libraries' rule (no `DELEGATECALL`) unchanged | `LinkClosure.t.sol` rows per kind; opcode scan of every module |
| Immutables | a module's own: `FACTORY` (the same everywhere) and `_SELF` (M2, M8); no chain value | `implementation()` on the token, a clone and a module |
| A direct call to a module | refused (`onlyDelegated`, M2); its storage is locked by its constructor anyway | a direct call of every module entry |
| An empty or unpinned module address | refused at construction (`ModuleMissing`) and at release (`LibraryCodeHashMismatch`, `ModuleNotPinned`) | all three |
| Gas forwarding | each hop keeps 1/64 (§6) | the gas-floor tests at their boundary move old → new |
| Typehash pins | no struct, typehash or digest changes; `*TypehashIsPinned` unchanged | run as is |
| Gas pins | move only with old → new figures in the commit (`PlusZero`, `MetaTxGasV2`, `GovGas`, `UAGas`, `UARegistryGroups`, `DexGas`, `PqzStateGas`, the `test_T_GAS*` rows at four sets) | as listed |
| EIP-8037 inclusion | every module, library and token its own transaction, each asked ≤ 60 M (T-1) | the deploy-gas table of every contract (Step 4) |

## 9. Families, node, clients, vectors — SPECIFIED

- **Every family's rule is unaffected:** this is the EVM's code organisation, not a rule. Soroban, Solana, NEAR, Algorand, Move,
  TON and Cosmos keep their contracts; no rule id changes meaning. On EVM the ABI (but `modules()`), selectors, argument and return types, events (a
  `DELEGATECALL`'s log carries the clone's address), errors, `mtxSelectors()` answers, typed EIP-712 digests and storage are
  unchanged.
- **One added view** on every kind, `modules()` (§4.5): `selector_audit.json` gains its row; no `mtx*` entry, no allowlist row.
- **Node:** `typed.rs`, `guard.rs`, `CALL_TABLE` and the job API unchanged; its gas estimates of the operations in §6 move (a
  re-measure, not a code change, where a figure is hard-coded); `releases.json`'s module rows are read like library rows.
- **Clients and vectors:** none (no byte format moves). `selector_audit.json` unchanged.
- **What moves:** `src/` (§4.4), deploy tooling (§4.5), tests (§10), pins (§8), `size-baseline.json` and the size gate (§2), docs.

## 10. Tests and mutants — SPECIFIED

- **Differential test per entry** (the registry's R2 `test_diff` pattern): the legacy body against stub + module on the same
  state: return data, revert data, logs, every slot written, every call out; every kind, every entry.
- **Path tests:** a relayed op through P into an op in A, W, Z or Q (the ticket); `mtxBatch` items across modules; a payable
  entry with value; a module called directly (every entry, `NotDelegated`); an implementation constructed with a module without
  code (`ModuleMissing`); a release whose module hash differs (`LibraryCodeHashMismatch`) or whose `modules()` names an address outside
  the env (`ModuleNotPinned`); `chainEnv()` read through a module (the
  clone's code); `implementation()` on the token, a clone and a module.
- **Layout and closure:** a layout row per module equal to its kind's; `LinkClosure` rows per kind; an opcode scan of each module.
- **Mutants, one at a time:** a guard left in a module; `onlyDelegated` dropped; a stub to the wrong module; a payable stub on a
  non-payable module entry; `implementation()` forwarded (returns the module); a state variable added to a module; a module
  `DELEGATECALL` outside its closure; a stub that re-encodes; a stub that drops the return data; a stub that swallows the revert
  data; the constructor's module check dropped; the factory's `ModuleNotPinned` check dropped; R-1's forward to the wrong library entry.
- **Gates:** `forge test` per test directory (never a whole-tree compile: plan T21's runner), the four PQZ sets by
  `script/pqz/at-set.sh` (one run at a time, `PqzSet.sol` restored), the size gate, gas pins old → new, the deploy-gas table of
  every contract against 60 M, `e2e.py --self-test`, the T65 e2e on the local copy with kind 13 (no `--skip-kind`).

## 11. Questions for the owner (each with a recommendation)

**Q1. Hedera keeps EIP-170 (24,576 B), and Step 5 deploys there.** Measured today by simulation: 24,577 B is refused. Step 5's
release set (`DeployHedera.s.sol`: the factory, the router, the registry pair, the DEX, `MtxRelayFee`, the Hedera kinds 0, 1, 8,
9 and their modules, the libraries they link, the wallets) holds four contracts above 24,576 B after this organisation: the
registry pair (≈ 69.6 KB together after R-1: at least three contracts), `SCaaSDex` (34.9 KB), `OpenFactory` (28.4 KB). The kinds
0, 1, 8, 9 fit with V7 (13.0–19.5 KB) and their modules mostly fit (largest upper bounds P 22.5 KB on kind 9 before the pipeline
code joins it, W 24.2 KB on kind 9). Chain-neutral releases are the same bytecode on every chain, so a contract fits Hedera
everywhere or nowhere.
- (a) Every contract of the Hedera release set fits 24,576 B: part 4 builds kinds 0, 1, 8, 9 and their modules within it (P
  splits into pipeline and pay where the pipeline code would push it over); a new **part 4b** splits the factory (the generic
  catalogue's `deployRelease` / `createInstance` / class envs into a factory module), the DEX (its exchange and governance
  bodies into DEX modules) and the registry into three contracts, which lifts the one-library ruling for the registry; Step 5
  after 4b. **+6 to 8.5 agent-days.**
- (b) This spec as is (60 M); Step 5 waits for a later Hedera round.
- (c) Step 5 deploys only what fits: not a working stack (no factory, registry or DEX).
- **Recommendation: (a)**, and its registry part as a second registry library (`UARegistryViewLib`: the readers and pure views
  behind `_libView`), since the 24 KB limit, not a preference, forces the third contract. One rule on every chain holds: each
  contract fits the code and gas limits of every chain it is released on.

**Q2. `SCaaSDex`'s margin.** It fits 60 M with 0.8 M (59.20 M), not T-2. Under Q1 (a) the DEX split of 4b gives the margin. Under
(b): forward its governance entries into a DEX admin module (study: −1.7 KB, ≈ 56.3 M; governance calls on the DEX +3.4 k) or
leave it at 59.20 M. **Recommendation:** follow Q1; under (b), forward the governance entries (the same pattern as the tokens).

Not questions (decided by rules already given): `onlyDelegated` on module entries (fail closed); P taking the pipeline code in
(rule 3, the gas-neutral form); the registry's 57 M (R4); per-kind modules (accepted 2026-11-07).

## 12. Tasks and estimates — SPECIFIED

| # | Task | Agent-days |
|---|---|---:|
| R | Fable review of this spec (design, security), then its revision; Codex if the owner asks | 0.5–1 |
| 3.1 | Part 3: R-1 forwards, R-2 moves, measured one at a time; registry tests, `UAGas` / `UARegistryGroups` pins old → new, the deploy gas of both against 60 M | 2–2.5 |
| 4.1 | Source: bodies to internal functions in their base files (rule 4), the per-kind cores and faces, the eleven G2 splits, `MtxPipelineLib` / `TradeLib` internals, the 53 module contracts; legacy copy first | 6.5–8 |
| 4.2 | Deploy: `implArgs` module lists, `Env.libs` pins, `DeployBase`, `deploy.sh`, `e2e.py`, `DeployHedera.s.sol`, `releases.json`, one public gate per transaction | 2–3 |
| 4.3 | Tests and mutants of §10 | 4.5–5.5 |
| 4.4 | Gates: forge per directory, the four PQZ sets, size gate, `size-baseline.json` and the stop line (§2), gas pins old → new, the deploy-gas table of every contract against 60 M; the T65 e2e with kind 13 | 2–2.5 |
| 4.5 | **Re-measure `ROLL_MAX` at the four sets** after the split (the known red `test_gas_rollMax_relayedFullTx` at n2048-kmax1024, n2304-kmax4096, n2816-kmax65536; owner 2026-11-09 kept 96 / 80 / 64 / 32): the figures go to the owner, no bound moves without the owner | 0.5 |
| 4.6 | Docs: a `decisions.md` entry (the body-module rule, proposed CTR-TOK-30; `docs_check.py` reports it unknown today) and CTR-GOV-19's Change (the stop line, the window closed), contracts docs (the entry → module table), the research note's status line, an operator note (module rows in `releases.json`, the deploy order) | 1 |
| 4b | **Only under Q1 (a):** the factory, the DEX and the registry set within 24,576 B; the Hedera kinds' modules checked against it | 6–8.5 |
| 5 | **Step 5, the Hedera testnet deploy** (after 4.4, and 4b under Q1 (a)): one small consensus transaction confirming the code limit; HBAR from the faucet first (owner-assisted); `DeployHedera.s.sol` in full from the testnet-only account (`SCAAS_TESTNET_MNEMONIC_FILE`), each transaction within 15 M (estimate + 20 %: Hedera charges at least 80 % of the limit); the HIP-632 checks of `docs/networks/hedera.md`; addresses, hashes and costs in a runs note | 1–1.5 |
| | **Part 3 + part 4 with the review (without 4b and Step 5)** | **19–24** |

## 13. Risks — SPECIFIED

| Risk | Handling |
|---|---|
| A module lands above its bound (the bounds are a complement build's; kind 13's Q is 33.5 KB at the top) | the splitting rule of §4.2; T-1 is a hard stop per module, T-2 a notice |
| A body behaves differently once moved (an override not in the module's core, a hook missing) | the cores carry every hook; the differential test per entry and per kind |
| `DELEGATECALL` into an empty or wrong module | `ModuleMissing`, `ModuleNotPinned`, the release's code-hash pins |
| A forgotten `payable` or an extra guard | M3, M4; their mutants |
| The registry pair stays tight (≈ 0.6–1.2 KB of room each) | R4 accepts 60 M; a later registry change measures against the line first |
| Release cost per chain grows (82–256 M per kind against 57–124 M today, each transaction ≤ 60 M) | accepted by the owner 2026-11-07; per-family modules later as a cost lever |
| Hedera's 24,576 B | Q1 |
| Gas pins move on every kind | old → new in each commit; §6's estimates replaced by forge figures |
