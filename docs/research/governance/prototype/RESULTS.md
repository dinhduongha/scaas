> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance prototype: measured results (2026-11-02)

What was measured: D1 (`GovernanceBase`, `GovernanceLib`, the storage split, the DEX on the base) and D2 (the `Grant` record), against `main` at `2a864638`. Prototype code on branch `governance`:
commit `66c3e74b` (D1), `0e1cf3ac` (D2). D4 (`grantDelay`), D5 and D6 are **not** in it, so every room figure below is before them. `holderCount` is in, because D2's renounce rule needs it. Tool chain: Foundry
1.8.5, solc 0.8.37, Amsterdam, optimizer 200 runs, OpenZeppelin at the pinned commit, sources verified with `scripts/evm_libs.sh check`. No per-set PQZ run was needed: `src/pqz/PqzSet.sol` was not touched.

**Verdict.** As designed, D2 does **not** fit: `WrappedPqzToken` measures 65,520 B, 1,020 B over the 64,500 stop line and 16 B under a cliff (§3). The stated fallback, grants on `NORMAL*` and the DEX only, fits with 485 B of room. A plain transfer
reads no governance slot, and its gas still moved on two of four kinds, by the dispatcher (§4).

## 1. Bytes

Runtime bytes. **Fallback** = v2 §7: `setGrant` and `grantOf` on `NORMAL*` and the DEX only, every `WRAPPED*` kind flat ([patch](fallback-grants-on-normal-and-dex.patch), not committed as code). Each cell's delta is against `main`.

| Contract | `main` | D1 | D1 + D2 | Fallback |
|---|---|---|---|---|
| `NormalToken` | 37,228 | 37,638 (+410) | 40,575 (+3,347) | 40,575 (+3,347) |
| `WrappedToken` | 48,015 | 48,500 (+485) | 50,166 (+2,151) | 48,640 (+625) |
| `NormalZetherToken` | 52,741 | 53,115 (+374) | 55,974 (+3,233) | 55,974 (+3,233) |
| `WrappedZetherToken` | 62,169 | 62,635 (+466) | 64,284 (+2,115) | 62,775 (+606) |
| `NormalPqzToken` | 52,891 | 53,257 (+366) | 56,088 (+3,197) | 56,088 (+3,197) |
| `WrappedPqzToken` | 63,423 | 63,875 (+452) | **65,520 (+2,097)** | 64,015 (+592) |
| `SCaaSDex` | 27,957 | 29,893 (+1,936) | 32,757 (+4,800) | 32,757 (+4,800) |
| `AdminLib` → `GovernanceLib` | 3,272 | 3,474 | 7,634 | 7,634 |
| `WrappedLib` | 15,684 | 15,722 | 17,161 | 17,161 |

Init code, the two tightest: `WrappedPqzToken` 66,060 → 66,509 → 68,154 → 66,649; `WrappedZetherToken` 65,751 → 66,214 → 67,863 → 66,354. All under the 131,072 B of Amsterdam.

`setGrant` plus `grantOf` cost 1,505 B on `WrappedPqzToken`, 1,509 B on `WrappedZetherToken`: the difference between the last two columns. `scripts/size_gate.py` reports 13 errors, as expected: every kind and the DEX over its ratchet, and `AdminLib` gone from the baseline. `size-baseline.json` was not moved.

## 2. Room to the stop line (64,500 B)

This is also **the room a regulated form of each contract would have**: the owner stated on 2026-11-02 that both will have one, and how they work is open, owner, not designed. No regulated form was measured.

| Contract | `main` | D1 | D1 + D2 | Fallback |
|---|---|---|---|---|
| `WrappedPqzToken` | 1,077 | 625 | **−1,020** | 485 |
| `WrappedZetherToken` | 2,331 | 1,865 | 216 | 1,725 |

**Said plainly: there is too little.** Before D4, D5 and D6, the fallback leaves 485 B on `WrappedPqzToken`. A regulated form needs at least the hook in `_update` and `_uaMove` and an entry for each of freeze, unfreeze, pause, unpause, a forced transfer and the order records. One signed entry measured 287-301 B (§6); the direct stubs are smaller but not measured. On `WrappedPqzToken` that does not fit; on `WrappedZetherToken` the 1,725 B must also carry D4 and D6, and it very likely does not fit either [est., not measured]. A regulated
version of either needs code moved out of the token, which nobody has designed and the owner has not ruled on; it is not a question of levers.

## 3. A cliff at 65,536 B

The relay probe (§6) pushed `WrappedPqzToken` over 65,536 B and it grew by **4,675 B** where the other kinds grew by 287-301 B. Past 65,535 a jump target no longer fits `PUSH2`, every tag becomes `PUSH3`, and the code jumps by about one byte per tag. [I from the figures; the push width was not read in the bytecode.] So 65,536 is not only the
chain's limit: a contract at 65,520 cannot take one more entry and then be trimmed back a little.

## 4. Gas

`test/governance/GovGas.t.sol`, the same file on every commit, one row per test from a fresh `setUp`, with intrinsic and calldata cost. A balance on both sides, lane past nonce 0.

| Row | `main` | D1 | D1 + D2 | Fallback |
|---|---|---|---|---|
| `NormalToken` `transfer` | 49,682 | 49,705 (+23) | 49,705 (+23) | 49,705 |
| `WrappedToken` `transfer` | 49,727 | 49,727 (0) | 49,727 (0) | 49,705 (−22) |
| `WrappedZetherToken` `transfer` | 49,734 | 49,734 (0) | 49,734 (0) | 49,734 |
| `WrappedPqzToken` `transfer` | 49,730 | 49,730 (0) | **49,840 (+110)** | 49,840 |
| `NormalToken` `mtxTransfer` | 87,332 | 87,322 | 87,235 | 87,235 |
| `WrappedToken` `mtxTransfer` | 87,256 | 87,256 | 87,254 | 87,256 |
| `WrappedZetherToken` `mtxTransfer` | 87,283 | 87,283 | 87,305 | 87,259 |
| `WrappedPqzToken` `mtxTransfer` | 87,343 | 87,331 | 87,343 | 87,343 |
| `mint`, whole-shape holder | 54,420 | 54,432 | 54,498 | 54,498 |
| `createToken`, with one minter | 1,324,432 | 1,324,249 | 1,434,671 | 1,434,671 |

`mtxTransfer` signature bytes change with the clone's address, so a few gas of calldata noise sit in those rows.

**The "+0" rule.** `test_transferTouchesNoGovernanceSlot` pins what the design promises: a transfer reads and writes no `scaas.governance` slot. The figure still moved: **+23 on `NormalToken`, +110 on `WrappedPqzToken`**, and −22 on `WrappedToken` in the fallback. That is the dispatcher: solc splits the selector table by value, so every new external
entry reshapes the path to `transfer` in units of about 22 gas. The fallback shows it: dropping two entries left `WrappedPqzToken` at +110 and moved `WrappedToken`, with no change on the path. v2's "`assertEq(gasAfter, gasBefore)`" (§2.4) cannot hold for any added entry. Whether "+0" means "no new read" (met, pinned by a test) or the literal figure (not met, and not reachable by adding entries) is the owner's.

Limited holders, D1 + D2:

| Row | Gas | v2's estimate |
|---|---|---|
| `setGrant`, fresh holder, every field | **812,687** | 90-110 k |
| `mint`, limited, every bound, second use | 99,778 | whole-shape + 10-15 k |
| `mint`, leaf, parent debited, second use | 124,812 | — |
| one `holderCount` slot, first grant at `createToken` | +110,183 (D1 → D2) | 0 extra |

New slots dominate: Amsterdam's state gas prices each new slot (EIP-8037, EIP-8038), and a fresh grant writes six.

Existing tables, `main` → D1 + D2. `test/v2/MetaTxGasV2.t.sol`: every row −10 or −22 (A 87,971 → 87,961, B 185,891 → 185,869, C 103,786 → 103,764, D 103,713 → 103,691, E 104,092 → 104,070, F 185,891 → 185,881). `test/v2/DexGas.t.sol`, regular gas: `mtxSettle` 1×1 319,245 → 317,492, `mtxExchange` 298,026 → 296,255, `mtxHybrid` 1×1 413,874 → 412,249; state gas unchanged. The drop of about 1.7 k was not traced: `admin` shared a slot in `DexStorage`, so a removed slot does not explain it.

Cold `SLOAD` at this `evm_version`: 2,100, warm 100 (probe overhead 12 subtracted), so A17's +2,100 for a `features` read on the hot path stands.

## 5. What contradicts v2

| v2 says | Measured or found |
|---|---|
| Tokens ≈ 0 B for D1 (§2.4, D1) | +366 to +485 B. `validBits`, `bitLabel`, the interface id and the masks as arguments are not free |
| DEX +1.2-1.6 KB for D1 | +1,936 B |
| `Grant`: each kind +300-450 B, lib +1.0-1.5 KB | wrapped kinds +1,645 to +1,666 B, `NORMAL*` +2,831 to +2,937 B, DEX +2,864 B, lib +4,160 B |
| `Grant` is 4 slots; the window words share one; "the one write" (§1.3, §5.2) | 6 slots; a limited `use` writes up to 3 |
| `setGrant` ≈ 90-110 k; limited mint +10-15 k | 812,687; +45,280 |
| A plain transfer rises by 0 (`assertEq`) | §4 |
| `use` on a whole-shape holder is unchanged | +78 on `mint` (D1 +12, D2 +66), dispatch and the compare; one SLOAD as stated |
| `init`: 0 extra if packed | `holderCount` is a new slot: +110,183 on a `createToken` with a minter |
| KATs stay byte-identical (§2.3) | `dex_order_kat.json` **breaks**: any DEX bytecode change moves its CREATE2 address and its domain, as `HANDOFF` warned. The other KATs pass. The vector was not regenerated: that is every client's, with the build |
| `GovernanceLib` replaces `AdminLib` in the DEX's env | the DEX had no `AdminLib`: its env gains a second library, `DeployBase` and `Catalogue` changed |
| A stub ≈ 256 B per named `mtx` entry | 287-301 B with its rule row (§6) |
| `holderCount` is D4's | D2's renounce rule needs it, so it moved into the prototype |

Things v2 does not say, found building it:

- **`hasRole` is true for a limited holder.** Every power must run through `use`, or a limited holder is whole-shape on that path. `WrappedLib`'s three rate and guardian checks read `hasRole`; they now also call `use`. A mutant that drops it is caught (M4).
- **A leaf needs a revoker.** v2 lets a delegable holder grant and says nothing of revoking. The prototype lets the grantor revoke its own leaf.
- **A revoke must keep the record**, or revoke then grant refreshes a budget. The prototype keeps it and bumps the epoch.
- **`_scopeNarrows` cannot run in the library**, which is DELEGATECALLed and cannot reach an internal virtual. The stub checks it after the library returns.
- **The parent is debited with the same function as the leaf**, so its `min`, `max`, `maxUses` and expiry bind too. That is stricter than v2's "total / window", and shorter.
- **`perWindow` without `window`** divides by zero: refused at `setGrant`.
- **A virtual modifier is deprecated** in this solc: the base takes two hooks instead.
- **`_uaMove` is untouched**, and it bypasses `_update`, as v2 §2.5 noted.

## 6. The relay probe

One named entry `mtxGrantRole(Envelope, bit, account, sig)` with its typehash and rule row, on `MetaTokenBase`, built once on D1 + D2 and thrown away:

| Contract | Delta |
|---|---|
| `NormalToken` | +301 |
| `WrappedToken` | +287 |
| `WrappedZetherToken` | +289 |
| `WrappedPqzToken` | +4,675 (over the cliff, §3) |

One such entry leaves 190 B of the fallback's 485 B; eight do not fit. It would also be useless for a derived UA: this is the measured reason for the rule in [permission-model-gaps.md §2](../permission-model-gaps.md#2-gap-3-relayed-owner-operations).

## 7. Tests

`test/governance/GovGrant.t.sol`, 23 tests: every bound with its positive control, two levels, spent carried across an edit and a revoke, the renounce rule, holder counts, the refusals, a limited holder on a wrapped kind and on the DEX, no governance slot on a transfer.

Mutants, each with the suite run:

| Mutant | Caught by |
|---|---|
| no parent debit | `test_leafDebitsItsParent` |
| no epoch bump | `test_revokingTheParentKillsLeaves_andAGrantBackDoesNotRevive` |
| an edit refreshes spent | `test_editNeverRefreshesABudget` |
| a wrapped power skips `use` | `test_wrappedPowerIsBound` |
| no renounce rule | `test_renounceRefusedWhileAnUnlockedBitHasHolders` |
| `narrows` skips `total` | `test_leafMustNarrow` |
| a leaf may delegate | `test_leafMustNarrow` |

Full suite on `0e1cf3ac`: §8. Three failures stay on purpose, a pin is not moved to go green:

| Test | Why |
|---|---|
| `test/v2/DexKat.t.sol` `test_dexKat...` | `dex_order_kat.json`, §5 |
| `test/v2/Factory.t.sol` `test_sizes` | `assertLe(NormalToken, 39,945)`; 40,575 |
| `test/hedera/HederaV2.t.sol` `test_implementationSizes` | the same pin |

Two tests of the old rule "role holders survive a renounce" (`test_ownerAdministersThroughTheToken`, `test_twoStepTransferAndRenounce_rolesSurvive`) now lock the flag first: that is the rule D2 decided, and their intent, a holder surviving, is kept.

## 8. How to run it

```text
cd smartcontracts/evm
../../scripts/capped forge build src --sizes --json > sizes.json
python3 ../../scripts/size_gate.py sizes.json size-baseline.json
../../scripts/capped forge test --match-path 'test/governance/*.t.sol' -vv     # the GOVGAS rows
../../scripts/capped forge test --match-path 'test/v2/MetaTxGasV2.t.sol' -vv
../../scripts/capped forge test --match-path 'test/v2/DexGas.t.sol' -vv
../../scripts/capped forge test
```

The `main` column is the same file run at `2a864638`; `GovGas.t.sol` is written on ABI strings and literal bits for that. The fallback column: `git apply` the patch under `docs/research/governance/prototype/` from the repository root.

Full suite on `0e1cf3ac`: 179 suites, 2,095 passed, 3 failed (the three pins of §7), 14 skipped. The full suite was not run on `main`. On D1 alone it gave 2,071 passed, 4 failed: `DexKat` and three wiring failures fixed in the D2 commit; the two size pins first fail at D2.
