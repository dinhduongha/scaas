# T66b: the library organisation and the 60 M fit (registry pair, body modules) — design

**Status:** SPECIFIED, **approved by the owner 2026-11-09 with the rulings of §11** (the DEX's governance entries forwarded now,
≈ 59 token modules accepted, the four-set gate with the known-red `ROLL_MAX` rows listed, R-1 then R-2 measured per step;
Hedera not in T66b). **Fable review applied** (approve with fixes, no P0) **and its re-check** (fixed with notes, no P0 / P1; P2-A, P2-B and
the notes applied); every finding's outcome in §14. Nothing is built;
**build after group 3i** (plan order T82 → 3i → T66b build → 3c). Plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md)
task **T66b** Steps 1 and 2 (parts 1, 2 and 5 were built as T66a; 3h, T58–T65, and T82 have landed). Branch `ua-mtx-merge`,
measured at `7d653925` (the later commits up to T82 move no size). Measurements:
[`runs/2026-11-09-ua-mtx-merge-t66b-sizes-deploy-gas.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b-sizes-deploy-gas.txt)
(Step 1, `fba4dbb7`) and [`runs/2026-11-09-ua-mtx-merge-t66b/`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/README.md)
(Step 2). Background: research [`evm-library-organisation.md`](../../research/evm-library-organisation.md) (`db93393b`, measured
at `937b454f`; its tools rerun here at the tip). **Everything cryptographic here is UNAUDITED.** Tags: [measured] a build or a
forge run of this step; [estimate] arithmetic over measured figures; [inference] follows from the EVM's rules.

**Owner rulings this spec applies, not reopens (2026-11-07, CTR-GOV-19's Change):** every deployed contract, libraries
included, fits one transaction of **60 M** on T10's formula, `asked = (regular + state) × 1.05`, EIP-8037 inclusion (regular +
state within the limit, never a block's `gas_used`), and regular × 1.05 < 2^24; **lever L in its forward form** (every body but
the ERC-20 core in `DELEGATECALL` body modules, typed stubs and the one guard kept); **per-kind modules and their release cost
accepted**; **the registry pair rebalanced first** (3g's R4: if both still miss 57 M, 60 M is accepted); the PQZ calldata cost
(+0.2 % to +4.8 %) accepted; **lever D deprecated**; the owner's 2026-11-01 ruling of one registry library. The owner's
suggestions (split `TradeLib`, a payable library, the shared parts on their own, reduce each kind) are evaluated in §7, not taken
as rulings. Repository rules kept: explicit parameters, every state-changing `mtx*` relayable, no EIP-7702, one rule on every
chain, nothing deployed upgraded, backup to `legacy/`, chain-neutral releases (CTR-TOK-29, proposed). Names after T82: the relay
fee router is `RelayFeeRouter`, its executor `RelayFeeExecutor`.

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

**A public chain (owner 2026-11-09):** the deploy condition is per contract, the chain's max code size and its gas limit; the
public Hedera testnet refused a runtime above 24,576 B in a simulation
([`hedera-codesize.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/hedera-codesize.txt)), so such a chain
waits for its own code-size fork; T66b follows 60 M only.

## 2. Targets — SPECIFIED

- **T-1, hard:** every deployed contract (each token implementation, each body module, each library, each plain contract) asks
  ≤ 60 M as its own transaction, regular × 1.05 < 2^24.
- **T-2, the margin of Step 3:** each new or changed contract aims at ≤ 57 M (the byte lines of §1). A contract between 57 M and
  60 M is reported with its figure, not a stop; the registry pair follows R4 (60 M accepted if both miss 57 M).
- **The size window closes:** no contract above 65,536 B; `_above64KiB` and its pin check leave `size-baseline.json` and
  `scripts/size_gate.py`; `size-baseline.json` rows move old → new with the reason. The gate's stop line becomes T-1's line per
  form, so each contract's row names its form (`release`, `module`, `library`, `plain`): release 35,386 B, module 35,570 B,
  library 35,694 B, plain by its own fitted line (the registry ≈ 35,286 B), an error above it; T-2's line a notice. CTR-GOV-19's
  ceiling (131,072 B / 262,144 B) stays above everything.

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

Every library but `UARegistryLib` fits T-1 and T-2. They stay as they are (§4.3).

### 3.3 The forms of the token [measured]

`fwd_spike.py` keeps every entry's signature, modifiers and ABI and turns the chosen bodies into one forward
([`token-forms.txt`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/token-forms.txt)):

| kind | 0 | 1 | 2 | 3 | 4 | 5 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| today | 33,889 | 44,635 | 42,222 | 52,709 | 51,821 | 61,174 | 41,561 | 52,302 | 50,030 | 60,724 | 59,371 | 73,511 |
| V6: all but the pipeline and the ERC-20 core forwarded | 20,461 | 24,289 | 25,760 | 29,818 | 27,937 | 33,393 | 23,939 | 27,726 | 29,024 | 33,249 | 31,273 | **36,853** |
| **V7: all but the ERC-20 core (the owner's form)** | **13,031** | **16,373** | **17,939** | **21,405** | **19,998** | **24,784** | **16,198** | **19,472** | **20,831** | **24,438** | **23,010** | **27,920** |
| floor: the whole ABI as bare stubs | 7,405 | 10,541 | 10,027 | 13,252 | 11,556 | 15,405 | 9,229 | 12,301 | 11,590 | 14,959 | 13,104 | 17,066 |

V6 misses T-1 on kind 13 (36,853 > 35,386 B); V7 fits every kind, at most 47.5 M (kind 13); keeping `registry`, `chainUid`,
`IS_HEDERA` and `SMART_KEY_ACCOUNT_IMPL` in the token (re-check P2-B) adds ≈ 0.2–0.3 KB to each kind [estimate]: kind 13 ≈ 28.2 KB,
≈ 48 M, with ≥ 7 KB of room. The spike's stubs carry the
modifiers with an assembly return, a form §4.1 replaces (Fable P1-1): the real stubs differ by tens of bytes per guarded entry
[estimate]. Eleven entries stay whole in every spike because another kept routine calls them (§4.4). The same spike forwards
`SCaaSDex`'s governance entries: 34,929 → **33,202 B** [measured], ≈ 56.3 M with the frame (§4.2).

### 3.4 The body modules [measured bounds + estimate]

A module is measured as the kind built with every entry outside the module forwarded, less the forwarded stubs at the kind's
floor cost per entry (`mod_est.py`, [`modules.out`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/modules.out)); a
complement build also keeps a residue no real module holds (everything forwarded: 4.0 KB on kind 0 to 10.3 KB on kind 13), so a
real module lies between the lower and the upper figure. The table adds two terms to both: M2's `onlyDelegated`, ≈ 20 B per
module entry (the count in brackets), and the library code a module takes in (P: `MtxPipelineLib`'s, 3–6 KB; T: `TradeLib`'s,
3.5–4.5 KB) [estimate]. KB; **bold** = above T-2's 33,780 B at the top, or within 2.1 KB of it (≥ 31.7 KB):

| kind | token V7 / asked | P: pipeline, named, pay | T: trade | A: admin | W: wrapped, regulated | Z: Zether | Q: PQZ | modules |
|---|---|---|---|---|---|---|---|---:|
| 0 | 13.0 KB / 22.6 M | 17.1–24.2 (23) | 9.0–14.0 (9) | 16.8–20.8 (43) | | | | 3 |
| 1 | 16.4 / 28.2 | 17.8–25.0 (23) | 10.7–16.0 (10) | 11.9–16.1 (36) | 15.6–19.8 (35) | | | 4 |
| 2 | 17.9 / 30.8 | 17.4–26.8 (23) | 8.2–15.6 (9) | 14.9–21.3 (43) | | 13.7–20.0 (35) | | 4 |
| 3 | 21.4 / 36.6 | 18.1–27.6 (23) | 10.0–17.5 (10) | 8.2–14.7 (36) | 15.0–21.6 (31) | 18.8–25.4 (43) | | 5 |
| 4 | 20.0 / 34.2 | 16.6–27.6 (23) | 8.0–17.0 (9) | 17.0–25.0 (43) | | | 19.0–27.0 (47) | 4 |
| 5 | 24.8 / 42.2 | 17.4–29.3 (23) | 9.0–18.8 (10) | 8.7–17.5 (36) | 14.1–23.0 (31) | | **24.6–33.5** (57) | 5 → 6 |
| 8 | 16.2 / 27.9 | 19.8–28.2 (28) | 9.1–15.4 (9) | 17.1–22.5 (42) | 5.2–10.5 (15) | | | 4 |
| 9 | 19.5 / 33.3 | 20.5–29.0 (28) | 10.9–17.4 (10) | 12.2–17.8 (36) | 19.6–25.2 (49) | | | 4 |
| 10 | 20.8 / 35.6 | 20.2–30.8 (28) | 8.3–16.9 (9) | 15.3–22.9 (42) | 5.1–12.7 (15) | 14.4–22.0 (35) | | 5 |
| 11 | 24.4 / 41.7 | **20.9–31.7** (28) | 10.1–19.0 (10) | 8.6–16.4 (36) | 19.8–27.6 (48) | 18.8–26.6 (40) | | 5 → 6 |
| 12 | 23.0 / 39.3 | **19.3–31.7** (28) | 8.1–18.5 (9) | 17.3–26.7 (42) | 4.2–13.6 (15) | | 19.4–28.8 (47) | 5 → 6–7 |
| 13 | 27.9 / 47.5 | **20.2–33.5** (28) | 9.1–20.4 (10) | 9.0–19.3 (36) | 18.9–29.3 (48) | | **24.3–34.6** (54) | 5 → 7 |

Every module fits T-1 at its upper bound (largest: kind 13's Q, 34.6 KB, ≈ 58.4 M; its P 33.5 KB). At T-2, kind 13's Q misses at
the top; P on 11, 12, 13 and Q on 5 sit within 2.1 KB of the line at the top and are expected to split once growth and the stub
form land (§4.2's splitting rule); kind 12's Q (28.8 KB at the top) splits only if the build measures it there, as the review
counted. **Module count: 53 before the splits, 58–59 after them** (owner 2026-11-09: ≈ 59 accepted), plus the DEX's admin
module. Per-kind release gas (token + modules, each transaction ≤ 60 M): ≈ 96–123 M (kind 0) to ≈ 186–280 M (kind 13) against
57.5–123.9 M today [estimate]. P and T together (the study's MAB) reach
31.7 KB on kind 13 before the library code joins: they stay apart.

## 4. The organisation — SPECIFIED

### 4.1 The rule (lever L, forward form)

1. **The token keeps every entry point:** signature, mutability, ABI, events and errors as today. It keeps these bodies itself:
   size-map's `erc20-core` (`transfer`, `transferFrom`, `approve`, `balanceOf`, `allowance`, `totalSupply`, `name`, `symbol`,
   `decimals`, the UA ledger's `balanceOfUA` and `transferToUA`), the identity views `kind`, `factory`, `FACTORY`,
   `implementation` (it reads the implementation's own `_SELF`) and `modules` (§4.5), the one-word env views `registry`,
   `chainUid`, `IS_HEDERA` and `SMART_KEY_ACCOUNT_IMPL` (each one `extcodecopy` word of the clone's code; read on chain by the
   DEX per UA leg and in `_ledgerOn`, `SCaaSDex.sol:462, 472`, by `OpenFactory._create`, `:733`, and by `ZetherDisclosure.verify`,
   `:64`; re-check P2-B), `_update` with its hooks, `_msgSender`, the guard. **Every other entry's body is one forward:** the unchanged calldata by `DELEGATECALL` to one module of the kind.
2. **The stub form (Fable P1-1).** A forwarded entry carries **no modifier**: a modifier's epilogue (`nonReentrant`'s
   `_exit(outer)`, `MetaTxBase.sol:51-55`; `governed`'s `_guardOut(outer)`, `GovernanceBase.sol:46-50`) would never run behind an
   assembly `return`, leaving the transient `_GUARD` set, and every later call into the token in the same transaction would
   revert `Reentrancy`. Each guarded stub calls one internal `_forward(module)`: `bool outer = _enter()` (`_guardIn()` for a
   `governed` entry; on a token both are `_enter`) → `(ok, ret) = module.delegatecall(msg.data)` → on failure revert with `ret`
   verbatim (the revert undoes `_enter`'s transient write with the frame, so the failure path needs no exit) → `_exit(outer)`
   (`_guardOut`) → assembly `return(ret)`. On the token face `_enter` / `_guardIn` appear only inside `_forward`. A stub guards
   exactly when today's entry does (`nonReentrant` or `governed`); an unguarded state-changing entry forwards through a second
   internal, `_forwardRaw(module)` (the same copy and return, no guard). **Views** forward through `_forwardRaw` under the
   registry's R2 cast (`_libView`) and keep `view`; **pure** entries through the same cast to `pure`, so the ABI's mutability
   does not move. An assembly block is `memory-safe` only when it writes at the free pointer, never past the scratch space at 0.
3. **A body module** is a contract compiled from the kind's own core (bases and hooks), holding one group of bodies, reached only
   by `DELEGATECALL` from the token's stubs, its code hash pinned in the release as a library's is (§4.5).
4. **One cold account per operation where it is one today:** a module takes in, as internal code, the library code its group
   calls today when no other contract needs that call (P holds the pipeline's code; T `TradeLib`'s and the trade authorisation);
   libraries that hold rules for several kinds, or are too large to take in, stay libraries (§4.3).
5. **Bodies are written once,** as internal functions in their domain's base file; the token's entry forwards, the module's
   entry calls the body (no guard, M3). A stub never re-encodes its arguments (the research note's G3).

### 4.2 The modules of each kind, and the DEX's

| Module | domains (size-map) | entries (kind 13; the others hold the subset their kind has) | takes in | links / reaches |
|---|---|---|---|---|
| **P** pipeline | pipeline, named-transfer, pay | `mtxExecute`, `mtxBatch`, `mtxCancelNonce`, `executeMetaTransaction`, `cancelNonce`, `mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxPayReceiverFee`, `payWithFee`, `payWithFeeToUA`, `mtxRelayFee`, `metaPayId`, `payLane`, `receiverFeeDigest`, on 8–13 the tax (`mtxPayWithTax`, `payWithTax`, `setTaxRate`, `setTaxRecipient`, `taxConfig`), the digests, nonce views, `supportedModes` (26 entries on 8–13, 21 on 0–5; `registry` and `IS_HEDERA` stay in the token) | `MtxPipelineLib`'s code | `HederaLib`; `RegulatedLib` on 8–13 |
| **T** trade | trade | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, `tradeOrderDigest`, `cancelOrderDigest`, `invalidateNoncesDigest`, `minNonce`, `pulled`, `restorePulled`, `mtxWrapOrder` (9–10) | `TradeLib`'s code and the authorisation of the trade path | — |
| **A** admin | governance, init, tables, token-meta, kind-normal | governance entries (21–22), `initialize`, `validateEnv`, `mtxSelectors`, `supportsInterface`, `chainEnv`, `creator`, `version`, `eip712Domain`, `rescueTo`, `mint`, `mintToUA`, `burn` on the normal kinds (33–40) | — | `GovernanceLib`; `WrappedLib` (`rescue`; `initToken` on 1, 9); `initialize` → `_initRaw`: `RegulatedLib.init` (8–13), `ZetherLib.initNormal` / `initNormalConf` (2, 10), `ZetherWrappedLib.init` (3, 11), `PqzStateLib.init` (4, 12), `PqzWrappedLib.init` (5, 13); `validateEnv` → `ZetherLib.validateEnv` (2, 3, 10, 11), `PqzStateLib.validateEnv` (4, 5, 12, 13) (`ZetherLayer.sol:60`, `PqzLayer.sol:75`) |
| **W** wrapped / regulated (1, 3, 5, 8–13) | wrapped, regulated | `wrap` ×2, `wrapToUA`, `mtxWrap*`, `unwrap*`, `mtxUnwrap*`, rates, reserve (`addReserve`), legs, `mint` / `mintToUA` of the wrapped kinds; the regulated powers (freeze, pause, force and operator transfers, orders, `regulatedConfig`, the regulated `rescue` and `disableFeature`) (15–49) | — | `WrappedLib`, `RegulatedLib`, `ZetherWrappedLib` / `PqzWrappedLib` where the kind has them |
| **Z** Zether (2, 3, 10, 11) | zether | the Zether entries, `mtxWrapShield` and the unshield-unwraps on 3 and 11 (35–43) | — | `ZetherLib`, `ZetherWrappedLib` |
| **Q** PQZ (4, 5, 12, 13) | pqz | the PQZ entries, 3f's and 3h's included, `mtxWrapShield` and `mtxUnshieldUnwrap` on 5 and 13 (47–57) | — | `PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`, `PqzWrappedLib` |
| **D** the DEX's admin (owner 2026-11-09) | `SCaaSDex`'s governance | its 22 governance entries | — | `GovernanceLib` |

**Modules per kind** after the expected splits: 3 (kind 0), 4 (1, 2, 4, 8, 9), 5 (3, 10), 6 (5, 11), 6–7 (12), 7 (13): 58–59 for
the twelve kinds; D for the DEX (≈ 5–9 KB [estimate]; the DEX 33,202 B, ≈ 56.3 M, T-2 met). On the normal regulated kinds (8, 10, 12)
W holds only the regulated powers (4.2–13.6 KB) and may join A when their sum fits T-2. **Splitting rule:** a module that misses
T-2 when built splits along its domains (Q: the PQZ ops and their verdict entries / the PQZ state, setters and views; P: the
signed pipeline and named transfers / pay and the relay fee), or, where that is not enough, its core's inherited `ERC20` entries
move to a storage-only base (≈ 1.9–2.3 KB per module, §4.4); a module that splits never forwards to its sibling (M7). Which
entry goes to which module is fixed per kind by `size_map.entry_domain` (`size-map.out` §4, §5) and recorded in a table the build
writes into the contracts doc. The DEX follows the same rules: its stubs guard through `_guardIn` / `_guardOut` (on the DEX a
`view` check of the transient guard and an empty exit, `SCaaSDex.sol:183-188`), its env's `libs` pin D, D's constructor is the
DEX's `(factory_, bytes)` (`FACTORY` its only immutable). The DEX has no `kind()`: its constructor checks D's `moduleGroup()` and
`factory()` (beside the factory's own DEX checks of `factory()` and `validateEnv`, `OpenFactory.sol:292-294`).

### 4.3 Which library holds what

| Library | Stays | Why |
|---|---|---|
| `GovernanceLib`, `WrappedLib`, `ZetherLib`, `ZetherWrappedLib`, `PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`, `PqzWrappedLib`, `RegulatedLib`, `HederaLib` | unchanged, each its own transaction | shared by several kinds, or too large to take into a module (the PQZ libraries are 5.6–24.5 KB each beside a Q of 19–35 KB) |
| `MtxPipelineLib` | unchanged | `GovernanceRouter`, `MandateWallet`, `HederaMandateWallet` and the DEX call it; its functions become thin `external` wrappers of `internal` ones, which P compiles in (rule 4) |
| `TradeLib` | unchanged | the DEX's path; T compiles its `internal` core in |
| `UARegistryLib` | rebalanced (§5) | part 3 |

The PQZ libraries are compiled at one PQZ set like the PQZ modules; a library built at another set is pinned by the env's code
hash only, as today (the same class as re-check P2-A; out of T66b).

### 4.4 Source structure

- **Per kind, one abstract core:** the kind's bases (today's `MetaTokenBase` → … → layers) and its hook overrides (`_mtxRule`,
  `_uaAllowed`, `_batchable`, `_envelopeBinding`, `_update`, the regulated hooks), the identity views (`kind`, `factory`,
  `FACTORY`, `REGISTRY_CODEHASH` on 8–13, `pqzSet` on 4, 5, 12, 13) and no other entry. Storage is declared only in the bases (OZ `ERC20` slots 0–4 and the
  ERC-7201 namespaces `scaas.*`), so the token and every module of the kind share one layout by construction (§8). OZ `ERC20`
  brings its public entries into every module too (inside the upper bounds of §3.4): in a module they run only on its own empty,
  locked storage; a storage-only `ERC20` base is the splitting rule's last lever.
- **Faces:** the token face (every entry as a stub, `implementation` and `modules`; it inherits the kind's interfaces,
  `IPqzToken`, `IZetherToken`, …) and one face per module (its entries calling the bodies, `onlyDelegated`, and a constant
  `moduleGroup()`; it inherits no interface it does not implement).
- **The eleven entries another routine calls** (`supportedModes` ×2, `setGrant`, `receiverFeeDigest`, `validateEnv`,
  `mtxUnshield`, `mtxUnshieldUnwrap`, `unwrapBinding`, `mtxRollOverBatch`, `mtxRollOverSigned`, `mtxSetRollOverMode`) each become
  an `external` entry and an `internal` helper (the research note's G2), so their stubs forward too.
- Today's bodies move to `legacy/ua-mtx-merge/t66b/` (backup, not delete) before the rewrite.

### 4.5 Wiring, immutables, pins and the release

- **Module addresses** are implementation immutables, passed in `implArgs` as **one named struct per kind, `abi.encode(<Kind>ImplArgs)`,
  decoded once** (the explicit-parameters rule; never a concatenation): `ImplArgs { address[] modules; }` on 0–5 and
  `RegulatedImplArgs { bytes32 registryCodehash; address[] modules; }` on 8–13 (today 8–13 decode `abi.encode(bytes32)`,
  `RegulatedBase.sol:54`). **A module takes its kind's constructor arguments but no module list** (Fable P1-2, re-check note):
  `(factory_)` on 0–5; `(factory_, abi.encode(bytes32 registryCodehash))` on 8–13, so every immutable a moved body reads holds
  the implementation's value and a module never holds a sibling's address (M7).
- **Immutables a moved body reads, and how each is tied to the implementation (Fable P1-2):**

  | Immutable | declared in | read by moved bodies | in a module | tie |
  |---|---|---|---|---|
  | `FACTORY` | `MetaTokenBase` | `initialize` (`NotFactory`) | the kind's constructor argument | the implementation checks `factory()` of each module; `factory()` / `FACTORY` stay kept views |
  | `REGISTRY_CODEHASH` | `RegulatedBase` (8–13) | `initialize` → `_initRaw` → `RegulatedLib.init` (`RegistryCodeMismatch`) | from `implArgs` | the implementation checks each module's `REGISTRY_CODEHASH()` |
  | `_name`, `_version`, `_hashedName`, `_hashedVersion`, `_cached*` | `SaltedEIP712` | `eip712Domain()`, every digest in P and T | the kind's `_domainName()`, a constant of its core; the kind's override `_domainSeparatorV4()` (`MetaTokenBase.sol:115`) rebuilds the separator under the clone's `chain_uid` on every call, so the cache is dead code on a factory-made contract, as today | by construction; the parity row of §10 |
  | `CHAIN_UID`, `_GOV_ROUTER`, `_REGISTRY`, `_SMART_KEY_CLONE_CODEHASH`, `_IS_HEDERA` | `SaltedEIP712`, `GovernanceBase`, `UAMetaTxBase` | domain, governance, `_mtxCtx` | 0, as on every factory-made implementation (the values come from the clone's code) | by construction; the parity row |
  | `_SELF` | `MetaTokenBase` | `implementation()` (kept in the token) | the module's own, used only by `onlyDelegated` (M2, M8) | — |
- **The implementation's constructor checks each module (Fable P2-1, re-check P2-A):** code present (`ModuleMissing(i)`);
  `kind()` equals its own; `moduleGroup()` equals the group its slot expects; `factory()` equals `FACTORY`; on 8–13
  `REGISTRY_CODEHASH()` equals its own; on the PQZ kinds 4, 5, 12, 13, `pqzSet()` (`pure`, `PqzSet.SELFTEST`, the set's
  self-test hash, rewritten by `at-set.sh`) equals its own, on every module of the kind (Q holds the ops, P the rollover bounds,
  A `validateEnv` and `initialize`), else `ModuleMismatch(i)`. Three to five staticcalls at construction, no byte on the hot path;
  a swapped, foreign or other-set module fails at the release, not at the first user call. The identity views read no storage,
  so they answer a direct call (M2).
- **Pins:** each kind's `Env.libs` / `libCodeHashes` lists its modules beside its libraries; `deployImplementation` checks every
  code hash before the release exists (`LibraryCodeHashMismatch`, as today), and `_checkImplementation` requires each address of
  the token's `modules()` in the env's `libs` (`ModuleNotPinned`). The trust is a library's today: the registrar publishes the
  env and deploys the release.
- **`LinkClosure` (Fable P2-3):** modules are immutables, not link references, so the test's closure becomes: the
  implementation's link references ∪ `modules()` (read from a deployed implementation, or a per-kind module list in
  `test/helpers/Catalogue.sol`) ∪ each module's link references, recursively; `e2e.py --self-test`'s closure list reads the same.
  **Opcode scan** of each module: no `SELFDESTRUCT` (`0xff`), no `CALLCODE` (`0xf2`), the `DELEGATECALL` (`0xf4`) count equals the
  module's library call sites and every `PUSH20` before one is a closure address. The scan proves the opcodes and their targets;
  that a body does what it did today is the differential test's and the mutants' to show (§10).
- **Chain-neutral:** a module has no chain value (the env is read from the clone's code, `ChainEnvCode`'s clone test from the
  code itself, CN-1; `FACTORY` is the same on every chain); it is deployed by the deterministic deployer with `DEPLOY_SALT`, at
  the same address on every chain. `releases.json` gains a row per module.
- **Deploy order:** libraries, then modules (each its own transaction and its own public gate), then the implementation through
  `deployImplementation`. `DeployBase`, `deploy.sh`, `e2e.py` follow.

### 4.6 Module and stub rules

| # | Rule |
|---|---|
| M1 | A module's constructor takes its kind's constructor arguments without the module list (`(factory_)` on 0–5; `(factory_, abi.encode(bytes32 registryCodehash))` on 8–13, the hash alone) and runs its kind's constructor: it locks the module's own storage (`initialized`) and sets the same immutables (§4.5) |
| M2 | Every entry of a module face is `onlyDelegated` (`address(this) != _SELF`, the module's own immutable; ≈ 20 B and ≈ 30 gas per entry, counted in §3.4): a direct call reverts `NotDelegated()`. The identity views (`kind`, `moduleGroup`, `factory`, `FACTORY`, `REGISTRY_CODEHASH`, `pqzSet`) and the inherited `ERC20` entries read no value-bearing state and are not module-face entries |
| M3 | No `nonReentrant` and no `governed` on a module entry; the stub's `_forward` holds the guard for the frame; module entries call `GovernanceLib` with `_govSubject()` directly (Fable P2-5) |
| M4 | A module entry has the token entry's mutability exactly (`payable` for `wrap` ×2, `wrapToUA`, `addReserve` in W, `mtxWrapShield` in Z or Q): under `DELEGATECALL` `msg.value` is the caller's, and a non-payable entry would revert on it |
| M5 | Opcodes: no `SELFDESTRUCT`, no `CALLCODE`; `DELEGATECALL` only to the release's libraries; `CALL` / `STATICCALL` as the bodies do today (self-call, registry, verifiers, underlyings) |
| M6 | No state variable of its own; its layout equals its kind's (§8) |
| M7 | One hop: a module never forwards to another module (it holds no sibling's address); a body that needs another group's body reaches it only by the self-call it makes today (`address(this).call`, `this.disclosureStatement`) |
| M8 | `_SELF` never decides "is this the implementation" in a module body; `implementation()` stays a kept view of the token |
| S1 | A guarded stub is `_forward(module)` (§4.1 rule 2): enter, `DELEGATECALL` of `msg.data`, revert data verbatim on failure (the revert undoes the enter), exit, return data verbatim; never a modifier with an assembly return |
| S2 | An unguarded state-changing stub is `_forwardRaw(module)`; view and pure stubs are `_forwardRaw` under the R2 cast and keep their mutability; none takes a guard |

## 5. Part 3: the registry pair — SPECIFIED

**Measured:** `UARegistryLib` 38,070 B (63.98 M), `UARegistry` 33,151 B (56.38 M); the pair 71,221 B against 70,980 B for both 60 M
lines: **moving code from one to the other cannot fit both**; at least ≈ 0.25 KB must go, ≈ 3.8 KB for both at 57 M. The two
share ≈ 9.4 KB of duplicated code (156 labels in both: `UAKinds.name` 1,193 B, `keyHashOf` 452, `groupName` 358, the `UAStore`
readers ≈ 1.5 KB, `SSTORE2.readChunks`, ECDSA, the record decoders) [measured,
[`registry-dex-factory-entries.out`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/registry-dex-factory-entries.out)].

**Chosen (owner 2026-11-09: R-1 then R-2, measured per step; one library stays, the owner's 2026-11-01 ruling):**

1. **R-1, one copy of the pure helpers:** the registry's `pure` views whose code the library already holds become forwards into
   `UARegistryLib` through a `_libPure(sel)` cast, which appends none of `_lib`'s three configuration words, **only where an
   entry's exclusive bytes exceed its stub** (≈ 45–80 B: selector, cast, dispatcher row; re-check note): `keyHashOf` (1,172 B
   exclusive), `pqzKeyVersionRecordDigest` (237), `registrationDigest` (191), `pqzKeyVersionDigest` (164), `pqzKeyRecordDigest`
   (119), `portableRecordDigest` (85), `uaOf` (83) [measured]. The other six `pure` views stay (`pqzKeyDigest` 44, `kemRecordHash`
   42, `portableDomainSeparator` 38, `uaMessage` 31, `kindName` 30, `kemRecordDigest` 14: each smaller than its stub). No contract
   calls them on chain (they serve `eth_call`). **`uaAuthDigest` stays** (Fable P2-2): it is `view` on the registry's EIP-712
   immutables, which the library cannot read, and `_native` calls it on every native authorization (`UARegistry.sol:291-293`,
   `:776-778`). The hot views (`requireAuthorized`, `requirePortable`, `kindOf`, `recordOf`, `checkedOf`, the key and member
   readers) stay too. [estimate] the registry nets ≈ −1.5 to −1.7 KB (2,051 B less seven stubs); the library +0.2 to +0.4 KB; the
   pair then clears both lines together by ≈ 0.8–1.2 KB.
2. **R-2, rebalance:** whole library writers move into the registry, largest exclusive code first, until both are under their
   lines with the room shared: `storePqzPop` (1,955 B exclusive), then `setKemKey` (1,090), `acceptMembership` (981),
   `cacheExpandedKey` (811) as the measurement asks; each reads its kind's configuration from `_cfg` in place of the appended
   words. [estimate, lower bound: a writer's exclusive bytes leave out the helpers it shares with another writer, and the
   registry pays for those it lacks] after the first two, the registry ≈ 34.5–34.7 KB (≈ 58.7–59.0 M), the library ≈ 35.2–35.4 KB
   (≈ 59.2–59.5 M).
3. **Stop:** both ≤ 60 M (R4 accepts 60 M: neither is expected at 57 M). If both cannot reach 60 M without changing a verification
   rule, the build stops and asks the owner (a second registry library, or the forward form on more registry entries).

The registry's storage, events, errors, ABI and every verification rule are unchanged; vectors, clients and the node do not
move. `UAGas` / `UARegistryGroups` pins move old → new (`--isolate`).

## 6. What each split costs per call — SPECIFIED (measured forward, estimated net)

**The forward, measured** ([`ForwardGas.t.sol`](../../../smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b/ForwardGas.t.sol);
forge gas inside one transaction: a bare assembly stub → module against the same body called directly):

| calldata | 0 | 256 B | 1 KB | 4 KB | 21 KB | 100 KB | 340 KB |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold module (its 2,600 included) | 3,439 | 3,487 | 3,633 | 4,241 | 8,234 | 41,311 | 287,844 |
| warm module | 539 | 587 | 733 | 1,341 | 5,334 | 38,411 | 284,944 |

The quadratic part is the memory of the copy (`3w + w²/512`): a hop of a large calldata pays it once more. The transaction's
own calldata is paid once either way (at 340 KB the EIP-7976 floor alone is 21.78 M [measured]). The guard of S1 costs what the
modifier costs today; `_forward`'s Solidity copy of the return data adds its memory (≈ 0.1 k for a short return) [estimate].

**Per operation, old → new** (hops from §4; today's figures from T40's `MetaTxGasV2` and T65's chain receipts; the net is
[estimate] until Step 4 moves the pins with measured old → new):

| Operation | today | what changes | Δ |
|---|---|---|---|
| ERC-20 `transfer`, `transferFrom`, `approve` | in the token | nothing | 0 |
| relayed transfer (`mtxTransfer`, `mtxExecuteTransfer`: 191,312 fresh lane) | token re-encodes ≈ 35 words into `MtxPipelineLib` (cold) | one forward of ≈ 1 KB to P (cold, 3.6 k), pipeline code inside P, nothing re-encoded | ≈ −0.6 to 0 k; +3.6 k if P did not take the pipeline in |
| `mtxPay` (202,216 fresh lane) | `payMeta` (cold) + `preTransferUA` with `PayMeta` re-encoded | one forward to P | ≈ −1.5 to −0.3 k |
| `mtxTrade`, first fill | `TradeLib` and `MtxPipelineLib`, both cold | one forward to T (cold) | ≈ −2.6 k |
| generic signed op (`mtxExecute`) | pipeline library cold, op in the token | stub → P (cold) → self-call → the op's stub → its module | +0.7 k (op in P, warm) to +3.4 k (op in A or W, cold) |
| governance, admin, wrap / unwrap, regulated powers (direct or through the router); the DEX's governance | the op's library, cold, or in the contract | + the module (cold) | +3.4 to +3.6 k |
| a DEX leg's `registry()`, `OpenFactory._create`'s `chainUid()`, `ZetherDisclosure`'s `chainUid()` | in the token | kept in the token (re-check P2-B) | 0 |
| PQZ op 1 (≈ 70 KB, 26.7 M on the copy) | two copies today (self-call, library call) | + one forward direct, + two relayed (≈ 27 k each) | +27 k / +55 k: +0.1 % / +0.2 % |
| PQZ op 7, M = 4 (≈ 121 KB, 52.8 M) | as above | ≈ +52 k per hop | +0.1 % / +0.2 % |
| largest PQZ op (≈ 340 KB; ≥ 21.8 M by its calldata floor alone) | as above | +0.29 M per hop | ≤ +1.3 % direct / ≤ +2.6 % relayed |
| Zether shielded transfer (a few KB) | as above | + the Z module, two small copies | ≈ +4 to +8 k |

Within the owner's accepted PQZ range. **The 63/64 rule (Fable P3-1):** each call frame keeps 1/64 of the gas it passes on. A
relayed PQZ op runs clone → implementation → P → self-call → clone → implementation → Q → PQZ library → precompile: 7 frames
holding back their 64th, ≈ 10.4 % of the gas sent, against 5 today (≈ 7.6 %). So a body's gas floor (`SigCheck`'s ERC-1271 caps,
the 400 k cap of a `SmartKeyAccount`, the verify budget, `UAVerifyGas`) sees less of what the relayer sent, and a relayer's gas
*limit* must grow by ≈ 3 % more than the op's own gas; the build re-measures those boundaries from inside P (§10).

## 7. The owner's suggestions, evaluated — SPECIFIED

| Suggestion | Verdict | Numbers |
|---|---|---|
| Split `TradeLib` | **Yes, as module T** (the trade entries with `TradeLib`'s internal core and the trade authorisation); `TradeLib` stays for the DEX | token −1.7 to −2.3 KB of trade bodies plus their coders (study: −2.84 to −3.58 KB at `937b454f`; the trade code has not changed since); T 8.0–20.4 KB; first fill ≈ −2.6 k |
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
| `this` | under `DELEGATECALL` `address(this)` is the clone in every frame: the self-call re-enters the token's dispatcher, the target stub's `_enter` consumes the ticket in the clone's transient storage (`_TICKET = 2`), and `_selfCall`'s fail-closed `guarded` check holds; `this.f.selector` is compile-time | the ticket path relayed through P into an op of another module |
| `msg.sender`, `msg.value`, `msg.data` | kept by `DELEGATECALL`: `_msgSender()`, the ticket, `requireNotDelegated`, `_govSubject()` (the router's transient pair keyed on `msg.sender`) read the same values; the forwarded calldata equals the stub's, so calldata offsets and appended words read the same; payability mirrored (M4) | `msg.value` to each payable entry; a non-payable module entry mutant |
| Return data | the stub returns the module's return and revert data verbatim, never re-encoded; a revert's selector and arguments pass through | the differential test (§10): return, revert data, logs, slots, calls out, per entry |
| The one guard | in the stub's `_forward` only (S1, M3), `nonReentrant` and `governed` alike; its exit runs before the return, so the transaction can call the token again | two calls into one token in one transaction after a forwarded entry; mutants: a guard left in a module, `governed` left on a module entry, a stub with a modifier and an assembly return |
| `LinkClosure` pins | modules join the release's closure through `modules()` (§4.5), with code-hash pins, the opcode rule M5 for modules; the libraries' rule (no `DELEGATECALL`) unchanged | `LinkClosure.t.sol` on the new closure; `e2e.py --self-test`; the opcode scan of every module |
| Immutables | each one a moved body reads is set from the kind's constructor arguments and tied by the implementation's checks (§4.5's inventory) | `RegistryCodeMismatch` through A on a regulated clone; a module built with another `REGISTRY_CODEHASH` refused; the parity row |
| A wrong module | `ModuleMissing`, `ModuleMismatch` (kind, group, factory, registry hash, PQZ set) at construction; `LibraryCodeHashMismatch`, `ModuleNotPinned` at release | each, a swap of two pinned modules within a release, a PQZ module built at another set |
| A direct call to a module | refused (`onlyDelegated`, M2); its storage is locked by its constructor anyway | a direct call of every module-face entry |
| Gas forwarding | each frame keeps 1/64 (§6) | the gas-floor tests at their boundary, from inside P, old → new |
| Typehash pins | no struct, typehash or digest changes; `*TypehashIsPinned` unchanged | run as is |
| Gas pins | move only with old → new figures in the commit (`PlusZero`, `MetaTxGasV2`, `GovGas`, `UAGas`, `UARegistryGroups`, `DexGas`, `PqzStateGas`, the `test_T_GAS*` rows at four sets) | as listed |
| EIP-8037 inclusion | every module, library and token its own transaction, each asked ≤ 60 M (T-1) | the deploy-gas table of every contract (Step 4) |

## 9. Families, node, clients, vectors — SPECIFIED

- **Every family's rule is unaffected:** this is the EVM's code organisation, not a rule. Soroban, Solana, NEAR, Algorand, Move,
  TON and Cosmos keep their contracts; no rule id changes meaning. On EVM the selectors, argument and return types, events (a
  `DELEGATECALL`'s log carries the clone's address), errors, `mtxSelectors()` answers, typed EIP-712 digests and storage are
  unchanged.
- **One added view** on every kind, `modules()` (§4.5): `selector_audit.json` gains that row and no other; no `mtx*` entry, no
  allowlist row.
- **Node:** `typed.rs`, `guard.rs`, `CALL_TABLE` and the job API unchanged; it reads nothing from `releases.json` (only
  `DeployBase` and the deploy dry run do). Every log query of `scaas-node` filters by configured contract addresses
  (`indexer.rs`, `chain.rs`, `dex/venue.rs`), never by event signature alone, so a module body run by a third party's
  `DELEGATECALL` (its log carries that party's address) is not taken for a token's. The relayer's gas estimates of §6's
  operations move, and its gas limit grows by the 63/64 share (§6): a re-measure, not a code change, where a figure is
  hard-coded.
- **Clients and vectors:** none (no byte format moves).
- **What moves:** `src/` (§4.4), deploy tooling (§4.5), tests (§10), pins (§8), `size-baseline.json` and the size gate (§2), docs.

## 10. Tests and mutants — SPECIFIED

- **Differential test per entry** (the registry's R2 `test_diff` pattern): the legacy body against stub + module on the same
  state: return data, revert data, logs, every slot written, every call out; every kind, every entry.
- **Parity row (Fable P1-2):** `eip712Domain()`, `factory()`, `registry()`, `IS_HEDERA()`, `chainUid()` through the token equal
  the legacy values, on a clone and on the implementation.
- **Path tests:** a relayed op through P into an op in A, W, Z or Q (the ticket); **two calls into one token in one transaction
  after a forwarded entry** (a contract calling it twice, the router's op then `mtxRelayFee`); `mtxBatch` items across modules; a
  payable entry with value; a module called directly (every module-face entry, `NotDelegated`); `initialize` of a regulated clone
  against a registry of other code (`RegistryCodeMismatch` through A); an implementation constructed with a module without code
  (`ModuleMissing`), with another kind's module, another group in a slot, another factory, another registry hash, a PQZ
  module built at another set (`ModuleMismatch`); a release whose module hash differs (`LibraryCodeHashMismatch`), whose `modules()` names an address outside
  the env (`ModuleNotPinned`), or whose two pinned modules are swapped; `chainEnv()` read through a module (the clone's code);
  `implementation()` on the token, a clone and a module; the gas-floor boundaries (`UAVerifyGas`, the 400 k ERC-1271 cap) from
  inside P; the DEX's governance entries through D, and a DEX constructed with a D of another group or factory; the DEX's per-leg
  `registry()` read on a kept token view (`DexGas` unchanged by the token split).
- **Layout and closure:** a layout row per module equal to its kind's; `LinkClosure` on the closure of §4.5; the opcode scan.
- **Mutants, one at a time:** a guard left in a module; `governed` left on a module entry; a stub with a modifier and an assembly
  return; `onlyDelegated` dropped; a stub to the wrong module; a payable stub on a non-payable module entry; `implementation()`
  forwarded (returns the module); a state variable added to a module; a module `DELEGATECALL` outside its closure; a stub that
  re-encodes; a stub that drops the return data; a stub that swallows the revert data; the constructor's module checks dropped
  (each of code, kind, group, factory, registry hash, PQZ set); `registry()` forwarded instead of kept; the factory's `ModuleNotPinned` check dropped; R-1's forward to the wrong
  library entry.
- **Gates:** `forge test` per test directory (never a whole-tree compile: plan T21's runner), the four PQZ sets by
  `script/pqz/at-set.sh` (one run at a time, `PqzSet.sol` restored), the size gate, gas pins old → new, the deploy-gas table of
  every contract against 60 M, `e2e.py --self-test`, the T65 e2e on the local copy with kind 13 (no `--skip-kind`). **The
  four-set gate passes with the three known-red `test_gas_rollMax_relayedFullTx` rows listed** (n2048-kmax1024, n2304-kmax4096,
  n2816-kmax65536) and their figures reported to the owner; no bound moves (owner 2026-11-09: `ROLL_MAX` kept at 96 / 80 / 64 /
  32, the move decided later). Any other red row fails the gate.

## 11. Owner rulings (2026-11-09, as recommended)

| # | Question | Ruling |
|---|---|---|
| a | `SCaaSDex` fits 60 M with 0.8 M (59.20 M), not T-2 | **Forward its governance entries into a DEX admin module now** (D, §4.2): the DEX 33,202 B, ≈ 56.3 M; governance calls on the DEX +3.4 k |
| b | P on kinds 11–13 and Q on 5, 12, 13 are likely to split | **Accepted: ≈ 59 token modules after the splits** (58–59 by §3.4), each ≤ 60 M (a cost item, per the 2026-11-07 acceptance of per-kind modules) |
| c | The four-set gate while `test_gas_rollMax_relayedFullTx` is red at three sets | **Passes with those three rows listed and their figures reported; no bound moved** (`ROLL_MAX` 96 / 80 / 64 / 32 kept, the move decided later) |
| d | R-1's scope once `uaAuthDigest` is out and the stubs are counted | **R-1 then R-2 as specified, measured per step** (§5) |
| e | Room for later governance (owner 2026-11-09: as recommended, with the figures written out) | **No separate governance module now.** A later governance version grows `GovernanceLib` first: a library, 14,513 B at `5e5fbce2`, margin line 33,903 B of runtime (≈ 57 M asked), hard line 35,694 B (≈ 60 M asked). When a kind's admin module A passes 33,780 B of runtime (≈ 57 M asked; hard line 35,570 B ≈ 60 M asked), A splits along its domains into A (init, tables, token-meta, mint / burn) and G (the governance entries); the DEX's D the same. The byte figures are §1's fitted estimates; the asked gas decides. Recorded in 4.6's docs (the body-module rule) |
| f | §5 item 3 reached after R-1 (`cb4abd33`): `UARegistry` 31,497 B / 53.61 M, `UARegistryLib` 39,028 B / 65.58 M; R-2's first move (`storePqzPop`) grew the pair by 1,784 B (shared helpers), registry 59.94 M, library 62.24 M | **(a) A second registry library, split by domain** (owner 2026-11-09, as recommended; supersedes the owner's 2026-11-01 ruling of one library): **names (owner 2026-11-09):** `UARegistryCoreLib` (the `register` forms, the `msig`, `acceptMembership`, `requirePortable`, the pure digests) and **`UARegistryAuxLib`** (owner 2026-11-09, final; a general name whatever the measured split): the writes after registration that leave the core, at least `setPqzKey` and `storePqzPop`, with `setKemKey`, `cacheExpandedKey` and, if the core still misses its line, `acceptMembership` as the measurement asks; `UARegistryLib` retires (its copy in `legacy/`, `a1353950`); **the next registry growth's first lever (owner 2026-11-09, as recommended; not built now):** `UARegistryAuxLib` calls the shared helpers in `UARegistryCoreLib` (a nested `DELEGATECALL`, or a third shared library such as an external `UAKinds`) instead of compiling its own copy, about 6–10 KB less in the Aux library for about +3–6 k gas per operation [estimate]; it relaxes "one `DELEGATECALL` per operation" and needs its own guard, mutants and `LinkClosure` pins; **built now (owner 2026-11-09, after 3.1b measured 19,662 B of the Aux library shared with the core, task 3.1c):** `UARegistryAuxLib` calls the shared helpers in `UARegistryCoreLib` through a nested `DELEGATECALL` (the core's helpers become `external`, callable only by delegation, the Aux library links the core's address; deploy order core → Aux); an Aux operation may make one nested call into the core; the core's growth from its new external entries is measured against 33,903 B / 35,694 B (60 M accepted for the registry pair, R4; past 35,694 B the build stops and reports); per-call gas old → new for every Aux writer and read (≈ +3–6 k [estimate], ≈ $0.007–0.015 on Ethereum at 1 gwei); mutants: the Aux library linked to a wrong core, a core helper reachable by a direct call, a helper's result ignored; `LinkClosure` pins (the Aux library's closure includes the core); **considered and deferred (owner 2026-11-09: "tạm thời chưa chuyển, để xét chuyển sau"):** moving entries from the core to the Aux library after 3.1c to rebalance them, in this order: `acceptMembership` (≈ 981 B exclusive), the reads `registrationOf` and `uaCount`, the pure digest entries (`uaOf`, `keyHashOf`, `registrationDigest`, `pqzKey*Digest`, `portableRecordDigest`; eth_call only), and only if the core still misses its line `registerFrost`, `registerMuSig2`, `registerWebAuthn`; `register`, `registerMsig`, the `msig` verification, `requirePortable` and the shared helpers stay [estimate: core −3 to −4.5 KB, Aux +3 to +4.5 KB]; **of these, the PQZ key digest entries move now (owner 2026-11-09, after 3.1c left the core at 34,608 B / 58.18 M asked; task 3.1d, narrowed by the owner the same day):** `pqzKeyRecordDigest`, `pqzKeyVersionDigest`, `pqzKeyVersionRecordDigest` become Aux library entries, beside `setPqzKey`; **then also `registrationDigest` and `portableRecordDigest`** (owner 2026-11-09, the same day: all five external `*Digest` entries of the core move; their internal twins stay in the core for `register` and `requirePortable`) (the registry's `_libPure` forwards for them target the Aux library; their internal twins stay in the core for `register` and `requirePortable`); `registrationOf`, `uaCount`, `uaOf`, `keyHashOf` and the rest of the list stay deferred; sizes and the per-call gas of the moved entries old → new; a core still between 57 M and 60 M is accepted (R4); for example one library for `register`, the `msig` and the `pop`, one for the PQZ keys, the KEM key, `acceptMembership` and `cacheExpandedKey`, the split fixed by measurement; each library aims at ≤ 33,903 B of runtime (≈ 57 M asked), hard line 35,694 B (≈ 60 M asked); `UARegistry` also shrinks (owner 2026-11-09: "thế thì cũng làm nhỏ UARegistry được"): every registry body not on a hot read path and not bound to the registry's immutables moves into the two libraries, measured per move; the hot views (`requireAuthorized`, `requirePortable`, `kindOf`, `recordOf`, `checkedOf`, the key and member readers) and `uaAuthDigest` (Fable P2-2) stay, so no hot read gains a `DELEGATECALL`; the registry's line is 33,516 B (≈ 57 M asked), hard 35,286 B (≈ 60 M asked); R-2 dropped, its patch not committed; one `DELEGATECALL` per operation as today; one more deploy transaction per chain and one more `LinkClosure` pin; the registry's storage, events, errors, ABI and verification rules unchanged. `decisions.md` records the change of the 2026-11-01 ruling (4.6) |
| g | A pay module shared across kinds (owner 2026-11-09: "không có chung à?") | **Kept as specified for now (A):** pay stays in P; on the kinds whose P passes 33,780 B (≈ 57 M asked; expected 10–13 after T83) P splits by §4.2's rule into (pipeline, named transfers) and (pay, relay fee), one pay module per kind. **Recorded for a later switch** [estimate; one pay module 10.8–18 KB, ≈ 18–31 M gas to deploy; a pay through its own module +2.6–2.9 k gas]: **C** one regulated pay module shared by the kinds that split anyway (10–13): ≈ 54–93 M less deploy gas per chain, no gas change per pay; **B** two family modules (normal 0–5, regulated 8–13) for every kind: ≈ 36–62 M less than A, but +2.6–2.9 k per pay on kinds 0–9 (≈ +1.3 % of a 203 k `mtxPay`; break-even ≈ 62k–119k pays per chain against per-kind copies). Either needs a cross-kind check in the module (`moduleGroup`, the factory pin), one storage layout for the pay namespaces across the group, a mutant "a kind outside the group calls in", a short spec addendum and a Fable review (≈ 1.5–3 agent-days); a switch is a new release of the kinds (nothing deployed is upgraded). To make it cheap later, 4.1 keeps the pay cut on its own domain and 4.4 reports whether the per-kind pay modules' runtime is identical apart from immutables and metadata |
| h | `test_c0_gasNamedVsGeneric` after rule 4: the named `mtxUnwrap` (module W, library call) 160,958 → 160,749 gas, the generic `mtxExecute(unwrap)` (module P, pipeline compiled in) 163,269 → 154,866; named − generic −2,311 → +5,883 | **The bound `named < generic + 2,000` becomes `+ 7,000`** (owner 2026-11-09): the named path did not get dearer (−209), the generic path got cheaper; keeping 2,000 would need the pipeline in A, W, Z and Q (+3.3 to +3.4 KB each; kind 12's Q 35,663 B, past its 35,570 B line) |
| i | `test_splitOverhead_dataSizeBound` after the split, at `n2304-kmax4096`: the large − small overhead PQZL 75,487 / 77,225 / 75,774 (ecdsa / mldsa65 / fndsa512) against 9,000, PQZH 299,515 / 303,659 / 300,232 against 14,000; each forward frame (stub → P, then stub → Q) copies the whole envelope into fresh memory | **The bounds move to the measured figures plus about 10 %** (owner 2026-11-09): PQZL ≈ 85,000, PQZH ≈ 335,000, old → new in the commit; inside the PQZ calldata cost the owner accepted 2026-11-07 (+0.2 % to +4.8 %; ≈ +0.7 % PQZL, ≈ +2.5–3 % PQZH [estimate]) |
| j | `debit_min_gas` (`set.toml` → `PqzSet.PQZ_DEBIT_MIN_GAS`) after the split: pinned 7,468,120, measured 7,513,388 at `n2304-kmax4096` | **Set to the measured value at every set** (owner 2026-11-09): `set.toml` edited and `PqzSet.sol` regenerated by `gen_set.py` (never by hand), the four sets measured the same way; the PQ `msig` holder cap that follows from it tightens by the difference (≈ 45 k at `n2304-kmax4096`), its boundary tests move old → new; a gas parameter, not a cryptographic one: the affected steps only, not the full `gate.sh` |
| — | Hedera | **Not in T66b:** no Hedera question, no Hedera-specific split, no Hedera deploy step; T66b follows 60 M only (§1's last paragraph) |

Not questions (decided by rules already given): `onlyDelegated` on module-face entries (fail closed); P taking the pipeline code
in (rule 4, the gas-neutral form); the registry's 57 M (R4); per-kind modules (accepted 2026-11-07).

## 12. Tasks and estimates — SPECIFIED

| # | Task | Agent-days |
|---|---|---:|
| 3.1 | Part 3: R-1's seven forwards (`_libPure`), R-2 moves, measured one at a time; registry tests, `UAGas` / `UARegistryGroups` pins old → new, the deploy gas of both against 60 M | 2–2.5 |
| 4.1 | Source: legacy copy first; bodies to internal functions in their base files (rule 5), the per-kind cores and faces, the eleven G2 splits, `MtxPipelineLib` / `TradeLib` internals, the `_forward` stubs (S1, S2), 58–59 module contracts and the DEX's D, the modules' constructors and the implementation's module checks (§4.5), `modules()`; and the line item T82 left: the comment `src/metatx/IERC20MetaTx.sol:31` names `MtxRelayFee.relayRef` (now `RelayFeeRouter.relayRef`), changed here because it moves every token's metadata hash | 7–8.5 |
| 4.2 | Deploy: `implArgs` module lists, `Env.libs` pins, `DeployBase`, `deploy.sh`, `e2e.py` (its self-test closure from `modules()`), `releases.json`, one public gate per transaction; the factory's `ModuleNotPinned` | 2–3 |
| 4.3 | Tests and mutants of §10 | 5–6 |
| 4.4 | Gates: forge per directory, the four PQZ sets (pass criterion of §10), size gate (per-form rows, `_above64KiB` removed), `size-baseline.json` and the stop line (§2), gas pins old → new, the deploy-gas table of every contract against 60 M; the T65 e2e with kind 13 | 2–2.5 |
| 4.5 | **Re-measure `ROLL_MAX` at the four sets** after the split: the figures go to the owner, no bound moves without the owner | 0.5 |
| 4.6 | Docs: a `decisions.md` entry (the body-module rule, proposed CTR-TOK-30; `docs_check.py` reports it unknown today) and CTR-GOV-19's Change (the stop line, the window closed), contracts docs (the entry → module table), the research note's status line, an operator note (module rows in `releases.json`, the deploy order, the relayer's gas share) | 1 |
| 5 | **Step 5, the full deploy on the SCaaS testnet** (plan `d2a06143`, `16659cb0`, `56fb0f3b`; after Step 4): chain 7622 through its RPC only (no container, config or port of the live stack changed); the controller confirms with the owner right before the first transaction. First the node's PQZ precompile answers `OP_SELFTEST` for the release's set; then `DeployBase` and every release of the split (kinds 0–13, their modules and libraries, the DEX and D, the registry pair, the factory), each transaction within 60 M asked and the chain's own limits; after it each deployed code hash equals the build's, and a smoke of one relayed transfer, one relay-fee call (`RelayFeeRouter`) and one PQZ op 1; addresses, tx hashes and gas in a runs note (no key, no absolute path) | 1–1.5 |
| | **Part 3 + part 4 (3.1–4.6)** | **19.5–24** |
| | **With Step 5** | **20.5–25.5** |

## 13. Risks — SPECIFIED

| Risk | Handling |
|---|---|
| A module lands above its bound (the bounds are a complement build's; kind 13's Q is 34.6 KB at the top with M2) | the splitting rule of §4.2; T-1 is a hard stop per module, T-2 a notice |
| A body behaves differently once moved (an override not in the module's core, a hook missing, an immutable unset) | the cores carry every hook; §4.5's inventory and checks; the differential test and the parity row per kind |
| A stub leaves the guard set | S1; the two-calls test and its mutant |
| `DELEGATECALL` into an empty, foreign or swapped module | `ModuleMissing`, `ModuleMismatch`, `ModuleNotPinned`, the release's code-hash pins |
| A forgotten `payable` or an extra guard | M3, M4; their mutants |
| The registry pair stays tight (≈ 0.3–0.6 KB of room each) | R4 accepts 60 M; a later registry change measures against the line first |
| Release cost per chain grows (≈ 96–280 M per kind against 57–124 M today, each transaction ≤ 60 M) | accepted by the owner 2026-11-07; per-family modules later as a cost lever |
| The relayer's gas limit grows by the 63/64 share | §6; the node's operator note |
| Gas pins move on every kind | old → new in each commit; §6's estimates replaced by forge figures |

## 14. Fable review: findings and outcomes (approve with fixes, no P0)

Review of `8855be41` by Claude Fable 5.1, 2026-11-09 (read-only against `src/`); each finding checked against the code here.

| # | Finding | Outcome |
|---|---|---|
| P1-1 | A stub with a modifier and an assembly `return` skips `nonReentrant`'s `_exit` and `governed`'s `_guardOut` (`MetaTxBase.sol:51-55`, `GovernanceBase.sol:46-50`): `_GUARD` stays set, the next call into the token in the transaction reverts | **Applied:** no modifier on stubs; `_forward(module)` (§4.1 rule 2, S1); the two-calls test and the modifier-with-asm-return mutant (§10); `memory-safe` only at the free pointer |
| P1-2 | Moved bodies read immutables: `REGISTRY_CODEHASH` (`RegulatedBase.sol:50-56, 71-72`), `FACTORY`, `SaltedEIP712`'s name and version | **Applied:** modules take the kind's constructor arguments (M1); the inventory and the implementation's checks (§4.5); `RegistryCodeMismatch` through A and the parity row (§10) |
| P2-1 | The pins cannot tell a swapped or foreign module of the right release | **Applied:** `kind()` / `moduleGroup()` / `factory()` (and `REGISTRY_CODEHASH()` on 8–13) checked by the implementation's constructor (`ModuleMismatch`); `factory()` and `FACTORY` kept in the token (`_checkImplementation` reads `factory()`) |
| P2-2 | R-1 listed `uaAuthDigest`, a `view` on the registry's immutables on the hot path (`UARegistry.sol:291-293, :778`); the stubs were not counted | **Applied:** `uaAuthDigest` stays; 13 `pure` views through `_libPure`; the estimate restated with the stubs (§5) |
| P2-3 | `LinkClosure` walks link references only; modules are immutables | **Applied:** the closure through `modules()`, `e2e.py --self-test` the same; what the opcode scan proves stated (§4.5) |
| P2-4 | The module bounds omitted M2's bytes | **Applied:** ≈ 20 B per module-face entry and the taken-in library code in §3.4; the likely splits and the count 53 → 58–59 (owner ruling b: ≈ 59) |
| P2-5 | M3 named only `nonReentrant`; `governed` is the same guard | **Applied:** M3 names both; module entries call `GovernanceLib` with `_govSubject()`; the `governed` mutant |
| P3-1 | The 63/64 chain of a relayed PQZ op | **Applied:** 7 frames against 5 (≈ 10.4 % / 7.6 %), the relayer's ≈ 3 %, the boundaries re-measured from inside P (§6, §9, §10) |
| P3-2 | Missing tests and gates; contradictions | **Applied:** the tests listed (§10); the `ROLL_MAX` pass criterion (owner ruling c); `selector_audit.json` stated once (§9); the size gate's per-form rows and `_above64KiB` removed (§2); the node reads nothing from `releases.json` and filters logs by address (§9); pure stubs keep `pure` through the cast (S2) |
| P3-3 | R-2's exclusive bytes undercount what moves | **Applied:** the figures labelled [estimate, lower bound]; each move measured before the next (§5) |
| Hedera | Mark deferred | **Applied (owner 2026-11-09, stronger):** Hedera removed from T66b; one line in §1 |
| Owner questions 1–4 | DEX, module count, `ROLL_MAX` gates, R-1 scope | **Answered by the owner 2026-11-09 as recommended** (§11) |

**Re-check of `61171e92`** (Claude Fable 5.1, 2026-11-09: fixed with notes, no P0 / P1; both P1s correctly fixed), each note
checked against the code here:

| # | Note | Outcome |
|---|---|---|
| P2-A | A module built at another PQZ set passes every constructor check (`PqzSet.sol`'s constants, `at-set.sh`) | **Applied:** `pqzSet()` (`PqzSet.SELFTEST`) on every module of kinds 4, 5, 12, 13, compared by the implementation's constructor; its test and mutant; the PQZ libraries noted as the same class, pinned by the env only (§4.3, §4.5, §10) |
| P2-B | `registry`, `chainUid`, `IS_HEDERA` moved out of the token though read on chain (`SCaaSDex.sol:462, 472`, `OpenFactory.sol:733`, `ZetherDisclosure.sol:64`) | **Applied:** kept in the token with `SMART_KEY_ACCOUNT_IMPL` (≈ 0.2–0.3 KB per kind); §6's row; `DexGas` unaffected; the mutant (§4.1, §3.3, §6, §10) |
| P3 | `_forwardRaw` unnamed; the failure path's exit | **Applied:** `_forwardRaw` named (S2); "a revert undoes `_enter`" (§4.1 rule 2, S1) |
| P3 | the `_cached*` reason | **Applied:** the kind's override rebuilds under the clone's `chain_uid`; the cache is dead code (§4.5) |
| P3 | R-1 forwards entries smaller than their stub | **Applied:** the threshold; seven forwards, six stay; ≈ 1.5–1.7 KB net (§5) |
| P3 | D's checks unnamed; the DEX has no `kind()` | **Applied:** `moduleGroup()`, `factory()`; the factory's DEX checks cited (§4.2) |
| P3 | A's links incomplete | **Applied:** the `init` and `validateEnv` library calls per kind (§4.2) |
| P3 | `implArgs` shape; what a module on 8–13 gets | **Applied:** `abi.encode(<Kind>ImplArgs)` with named fields, decoded once; a module gets the registry hash alone, never the module list (§4.5, M1) |
