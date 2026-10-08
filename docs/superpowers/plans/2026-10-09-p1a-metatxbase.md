# P1a — `SigCheck`, `SaltedEIP712`, `MetaTxBase` (generic meta-tx base) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the generic meta-transaction base of the token tree — the one signature check `SigCheck`, the salted
EIP-712 domain `SaltedEIP712`, the v3 `MetaTransaction` struct and the abstract `MetaTxBase` (`mtxExecute`, alias,
`mtxBatch`, `cancelNonce`, lanes, transient sender + one-shot ticket, selector allowlist, fee classes, `_chargeFee`
refusing all but `NONE`) — tested on a mock registry, with the KAT `metatx_kat.json`, while every built token stays
unchanged and green. The v1/v2 code is kept for reference (tag + `legacy/`).

**Architecture:** New files only for the base (`src/common/SigCheck.sol`, `src/common/SaltedEIP712.sol`,
`src/metatx/IMetaTx.sol`, `src/metatx/MetaTxBase.sol`); the built meta-tx bases (`ERC20MetaTx` v1, `MetaTxCore`,
`ZetherMetaTx`) only swap their signature check for `SigCheck`; `MetaTxLib` gains the v3 struct under its normative
name and the built 11-field struct becomes `LegacyMetaTransaction` (mechanical rename, no hash change). No token
inherits `MetaTxBase` yet (P1b moves the token base onto it). `MetaTxBase` keeps its nonces in the ERC-7201
namespace `scaas.metatx` and its sender/ticket in the transient slots of CTR-MTX-18.

**Tech Stack:** Solidity 0.8.28, Foundry (forge 1.3.5), OpenZeppelin Contracts 5.2.0, forge-std 1.16.2; `cast` for
the independent KAT cross-check; Rust (`scaas-node`) and Node (`clients/clientkeys`) only for a path rename.

**Spec:** `docs/history/specs/2026-10-08-token-tree-design.md` (T1, T7, T10, §3, §4 "Signature check", §9 P1);
normative rules in `docs/contracts/metatx.md` (CTR-MTX-02, -07, -11, -13…-25, Interfaces, Security, Conformance,
Transitional (BUILT)) and `docs/contracts/README.md` (CTR-GEN-05, build pins); register entries in
`docs/decisions.md` (CTR-MTX-15…25, CTR-GEN-05, CTR-TOK-24); TODO.md §00 (P1 start checklist).

## Global Constraints

- All paths are relative to the repository root `/home/ha/work/ainative/scaas`; every forge command runs in
  `smartcontracts/evm`.
- **Heavy commands only through `scripts/capped`, one at a time** (`scripts/capped`: "ONE capped command at a time
  machine-wide"): `../../scripts/capped forge build`, `../../scripts/capped forge test …`, `../scripts/capped cargo …`.
  Never two capped commands in parallel. `forge test` also rewrites the vectors its KAT writers own — run
  `git status --short` before each commit.
- Build pins (foundry.toml / CTR-GEN-01, unchanged): `solc_version = "0.8.28"`, `optimizer = true`,
  `optimizer_runs = 200`, `via_ir = false`; OpenZeppelin `v5.2.0`, forge-std `v1.16.2`; forge 1.3.5 default EVM
  `prague` (TSTORE/TLOAD needed). New files use `pragma solidity ^0.8.24;` (transient opcodes in assembly).
- Typehashes (verbatim, pinned by tests):
  - v3: `MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` = `0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888`
  - built (renamed `LEGACY_METATX_TYPEHASH`, string unchanged): `MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)`
  - domain: `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)`; version
    always `"1"`; `eip712Domain()` fields `0x1f` (CTR-GEN-05, CTR-MTX-02).
- Transient slots (CTR-MTX-18): `keccak256("scaas.mtx.guard")` = `0xf92fce36488cd980109789c37ce44669ca2ec8fc93bcd6d944c3a5544f9ce252`,
  `keccak256("scaas.mtx.sender")` = `0x6f8cf97d962f34e862325b04dcb64b0eb0b06cf30b06b61c33210ec760df0f0b`,
  `keccak256("scaas.mtx.ticket")` = `0xdea51947149e025e6ed748bbba150c788d4bf051fa2851715a58709dbd31a816`.
  ERC-7201 `scaas.metatx` = `0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00` (`cast index-erc7201 scaas.metatx`).
- Error names (metatx.md "Interfaces", verbatim): `MetaTxExpired(uint256 validUntil, uint256 nowTs)`,
  `MetaTxBadNonce(uint256 expected, uint256 got)`, `MetaTxBadSignature()`,
  `MetaTxUnauthorizedRelayer(address allowed, address caller)`, `MetaTxUnknownMode(uint32 mode)`,
  `MtxSelectorNotAllowed(bytes4 selector)`, `MtxDataShape(bytes4 selector)`, `MtxFeeClass(bytes4 selector, uint32 mode)`,
  `Reentrancy()`, `SelfSender()`, `MtxBatchEmpty()`, `MtxBatchLengthMismatch()`; events
  `MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch, uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee)`,
  `MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce)`. New in this plan (not named
  by the docs): `SigCheck.SigCheckGasStarved(uint256 cap, uint256 gasLeft)`.
- Signature rule (CTR-MTX-14, -25, CTR-ACC-05, CTR-DEX-08): EOA = OZ `ECDSA.tryRecover`, 65 bytes, low-s; contract =
  ERC-1271 `staticcall` capped at 50 000 gas (400 000 only for `SmartKeyAccount` clones, by override), ≤ 32 bytes of
  returndata, caller must hold `cap·64/63 + margin`; an EIP-7702 designator (`0xef0100‖address`, 23 bytes) is an EOA.
- Size budget (CTR-TOK-24): each token implementation ≤ **20,480 B** runtime; each library and every contract ≤
  24,576 B (EIP-170). Built baseline: `ZetherToken` is already 28,939 B (over EIP-170, removed in P3), so
  `forge build --sizes` exits non-zero before and after this plan; the gate of Task 9 is stated there.
- Chain constants used by tests: chain id `7622`, `chain_uid` =
  `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464` (`smartcontracts/evm/chain-uids.json`,
  `private7622`). Test key `0xA11CE` (address `0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7`).
- Foundry runs one test function as **one transaction**: transient slots carry over between the calls inside a
  test, exactly like calls inside one production transaction. Tests rely on it (ticket clearing).
- Work on branch `p1a-metatxbase` (Task 1). Do not push; do not run `forge fmt` on built files.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- Transient sender/ticket not cleared after step 5, so a later call from `this` in the same transaction is taken as the signer — pinned by `test_msgSender_outsideTheSelfCall_isTheCaller` and `test_everyAllowlistedSelectorIsNonReentrant` (Task 5).
- A clone hashing with the implementation's cached separator (cross-clone replay) or a name that silently falls back to storage — pinned by `test_cloneUsesItsOwnAddressAndTheImplementationSalt` and `test_longNameRefused` (Task 3).
- A relayer starving the ERC-1271 call (EIP-150) so a valid wallet signature reads as invalid — pinned by `test_1271_starvedCallReverts` (Task 2).
- `AMOUNT(i)` basis read at the wrong offset, or a fee failure after the call that does not undo the call — pinned by `test_feeHook_basisAndEvent` and `test_feeFailure_revertsTheCall` (Task 7).
- The mechanical `LegacyMetaTransaction` rename or the KAT file move changing a built digest or leaving a reader on the old file — pinned by `test_legacyMetaTxTypehashIsPinned` + `BaseKatTest` (Task 4) and the node/clientkeys runs on `metatx_v1_kat.json` (Task 8).

## Rulings (docs vs code) and defaults taken

- **`MetaTxLib.MetaTransaction` name.** The docs make it the 9-field v3 struct; the built v1/v2/Zether lines use the
  name for the 11-field struct (Zether until P3). Ruling: rename the built one to `LegacyMetaTransaction` /
  `LEGACY_METATX_TYPEHASH` (Task 4, sed over 37 files, digest unchanged) so the v3 struct sits at its normative name now.
- **`metatx_kat.json`.** Normatively the v3 `MetaTransaction` vector; today it is the v1 vector read by `scaas-node`,
  clientkeys and the Odoo connector. Ruling: `git mv` the v1 file to `metatx_v1_kat.json` and repoint the in-repo
  readers (Task 8). The Odoo reader (`bamboo-dms/dms_blockchain/tests/test_eip712.py`, other repo) goes red until it
  is repointed — report it to the owner.
- **"`MetaTxBase` by `git mv` of `MetaTxCore`".** `MetaTxCore` is still the base of the built v2 tokens that must stay
  green, and CTR-MTX-07 names `ERC20MetaTx` as "the built `MetaTxCore`, renamed". Ruling: `MetaTxBase` is a new file
  whose pipeline is lifted from `MetaTxCore`; `MetaTxCore` keeps its history and is `git mv`'d to `ERC20MetaTx.sol`
  in P1b (after the v1 `ERC20MetaTx.sol` is deleted).
- **Size gate.** `forge build --sizes` already fails on `ZetherToken`; Task 9 gates "only `ZetherToken` over
  EIP-170" plus "the `MetaTxBase` mock ≤ 20,480 B".
- **Defaults (docs silent):** fee classes in `mtxSelectors()` are `1 = ABSOLUTE`, `2 = AMOUNT` (0 = not listed,
  internal); `_chargeFee` refuses with `MetaTxUnknownMode(mode)`; step 3 checks the fee class before
  `supportedModes()`; gas-cap margin `GAS_MARGIN = 5_000`; the `scaas.mtx.binding` slot is left to P3 (its only
  consumer is Zether); `from ≠ address(this)` is not yet a virtual hook (P4 adds it for `SmartKeyAccount`); the
  pipeline takes a memory struct so the named builders (P1b, P4) can reuse it.

---

### Task 1: Reference prep — tag `ref/pre-token-tree`, `legacy/`, branch

**Files:**
- Create (copied from the tag, 27 files): `smartcontracts/evm/legacy/src/metatx/{ERC20MetaTx,IERC20MetaTx,IERC20Payment,IMetaTokenV2,MetaToken,MetaTokenBase,MetaTxCore,MultiUnderlyingToken,NoUnderlyingToken,SingleUnderlyingToken}.sol`,
  `smartcontracts/evm/legacy/src/factory/{IFactoryToken,IFactoryTokenV2,OpenFactory,OpenFactoryV2}.sol`,
  `smartcontracts/evm/legacy/src/common/{MetaTxLib,FeePolicy,SigLib,IOpenFactory,IOpenFactoryV2}.sol`,
  `smartcontracts/evm/legacy/src/hedera/{HederaMetaToken,HederaTokensV2,HederaV2Lib,HederaAccountAuth}.sol`,
  `smartcontracts/evm/legacy/src/dex/MetaTxDex.sol`,
  `smartcontracts/evm/legacy/src/zether/{ZetherToken,ZetherMetaTx,IZetherToken}.sol`
- Create: `smartcontracts/evm/legacy/README.md`
- Modify: `TODO.md` (tick the first P1 start-checklist box)
- Not modified: `smartcontracts/evm/foundry.toml` — checked: `src = "src"`, `test = "test"`, `script` default
  `script`, `libs = ["lib"]`, remappings point only into `lib/`, no `skip`; nothing imports `legacy/`, so forge never
  compiles it (Step 5 proves it).

**Interfaces:**
- Consumes: the clean `main` HEAD.
- Produces: annotated tag `ref/pre-token-tree` (= that HEAD), branch `p1a-metatxbase`, the `legacy/` tree.

- [ ] **Step 1: Baseline on a clean `main`**

```bash
cd /home/ha/work/ainative/scaas
git status --short                  # expected: no output
git rev-parse --abbrev-ref HEAD     # expected: main
cd smartcontracts/evm
../../scripts/capped forge test 2>&1 | tail -1
```

Expected: `Ran 50 test suites in …: 639 tests passed, 0 failed, 0 skipped (639 total tests)`.

```bash
../../scripts/capped forge build --sizes --json 2>/dev/null > /tmp/p1a-sizes-before.json
jq -r 'to_entries[] | select(.value.runtime_size > 24576) | .key' /tmp/p1a-sizes-before.json
```

Expected: `ZetherToken` (only).

- [ ] **Step 2: Tag and branch**

```bash
cd /home/ha/work/ainative/scaas
git tag -a ref/pre-token-tree -m "Last commit before P1 of the token tree: v1/v2 token lines and the old ZetherToken, kept for reference (CTR-MTX-07)"
test "$(git rev-parse 'ref/pre-token-tree^{commit}')" = "$(git rev-parse HEAD)" && echo tag-ok
git switch -c p1a-metatxbase
```

Expected: `tag-ok`, `Switched to a new branch 'p1a-metatxbase'`.

- [ ] **Step 3: Copy the reference sources from the tag**

```bash
cd /home/ha/work/ainative/scaas
mkdir -p smartcontracts/evm/legacy
git archive ref/pre-token-tree -- \
  smartcontracts/evm/src/metatx smartcontracts/evm/src/factory \
  smartcontracts/evm/src/common/MetaTxLib.sol smartcontracts/evm/src/common/FeePolicy.sol \
  smartcontracts/evm/src/common/SigLib.sol smartcontracts/evm/src/common/IOpenFactory.sol \
  smartcontracts/evm/src/common/IOpenFactoryV2.sol \
  smartcontracts/evm/src/hedera/HederaMetaToken.sol smartcontracts/evm/src/hedera/HederaTokensV2.sol \
  smartcontracts/evm/src/hedera/HederaV2Lib.sol smartcontracts/evm/src/hedera/HederaAccountAuth.sol \
  smartcontracts/evm/src/dex/MetaTxDex.sol \
  smartcontracts/evm/src/zether/ZetherToken.sol smartcontracts/evm/src/zether/ZetherMetaTx.sol \
  smartcontracts/evm/src/zether/IZetherToken.sol \
  | tar -x --strip-components=2 -C smartcontracts/evm/legacy
find smartcontracts/evm/legacy -name '*.sol' | wc -l
```

Expected: `27`.

- [ ] **Step 4: Write `smartcontracts/evm/legacy/README.md`**

```markdown
# legacy/ — reference only, not built, not tested

Copies of the token code as it stood at tag `ref/pre-token-tree`, the last commit before P1 of the token tree
(`docs/history/specs/2026-10-08-token-tree-design.md`): the v1 line (`ERC20MetaTx` mixin, `MetaToken`,
`HederaMetaToken`, v1 `OpenFactory`, `MetaTxDex`), the v2 line (`MetaTxCore`, `MetaTokenBase`, the three tiers, their
Hedera children, `OpenFactoryV2`) and the old `ZetherToken` with `ZetherMetaTx`, plus the shared files they import
(`MetaTxLib`, `FeePolicy`, `SigLib`, the factory interfaces, `HederaAccountAuth`).

- **Not compiled.** Foundry builds only `src/`, `test/` and `script/` (`foundry.toml`); nothing imports this tree.
- **Not tested, not maintained, never deployed.** Relative imports point at their old neighbours and may not resolve.
- The authoritative copy is the tag: `git show ref/pre-token-tree:smartcontracts/evm/src/<path>`.
- Why it exists: owner decision of 2026-10-08 (CTR-MTX-07; TODO.md §00, P1 start checklist).
```

- [ ] **Step 5: Prove forge ignores `legacy/`**

```bash
cd smartcontracts/evm
../../scripts/capped forge build 2>&1 | grep -E 'No files changed|Compiling'
```

Expected: `No files changed, compilation skipped` (a `Compiling …` line means something under `legacy/` is reached —
stop and find the importer).

- [ ] **Step 6: Tick the checklist**

```bash
cd /home/ha/work/ainative/scaas
sed -i 's/^- \[ \] Keep the old code for reference/- [x] Keep the old code for reference/' TODO.md
grep -n 'Keep the old code for reference' TODO.md
```

Expected: the line starts with `- [x]`.

- [ ] **Step 7: Commit**

```bash
git add smartcontracts/evm/legacy TODO.md
git commit -m "$(cat <<'EOF'
chore(evm): keep the v1/v2 token lines and old ZetherToken under legacy/ (reference only)

Tag ref/pre-token-tree marks the last commit before P1; legacy/ is outside
src/test/script and never compiled.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `SigCheck` — one signature check; the three meta-tx bases use it; `SigLib` deleted

**Files:**
- Create: `smartcontracts/evm/src/common/SigCheck.sol`
- Create: `smartcontracts/evm/test/metatx/SigCheck.t.sol`
- Modify: `smartcontracts/evm/src/metatx/ERC20MetaTx.sol`, `smartcontracts/evm/src/metatx/MetaTxCore.sol`,
  `smartcontracts/evm/src/zether/ZetherMetaTx.sol` (signature check and `_isContract` delegate to `SigCheck`)
- Modify (comments only): `smartcontracts/evm/src/common/AuthScheme.sol:51`, `smartcontracts/evm/src/common/MultiSig.sol:10`
- Delete: `smartcontracts/evm/src/common/SigLib.sol` (`git rm`; no importer)
- Not touched (later phases): `OrderBookDex` (P2), `MandateWallet`, `SubjectAccount` (P4); the four Hedera
  `_requireValidSignature` overrides (P1b/P1c).

**Interfaces:**
- Consumes: OZ `ECDSA.tryRecover(bytes32, bytes memory) returns (address, RecoverError, bytes32)`, `IERC1271`.
- Produces:

```solidity
library SigCheck {
    uint256 internal constant ERC1271_GAS = 50_000;
    uint256 internal constant GAS_MARGIN = 5_000;
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
    function isContract(address a) internal view returns (bool);
    function isValid(address signer, bytes32 digest, bytes memory sig, uint256 cap1271) internal view returns (bool ok);
}
```

- [ ] **Step 1: Write the failing test** `smartcontracts/evm/test/metatx/SigCheck.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

contract SigCheckHarness {
    function isValid(address signer, bytes32 digest, bytes calldata sig, uint256 cap) external view returns (bool) {
        return SigCheck.isValid(signer, digest, sig, cap);
    }

    function isContract(address a) external view returns (bool) {
        return SigCheck.isContract(a);
    }
}

/// CTR-MTX-25: EOA low-s, ERC-1271 with the gas-cap rule, EIP-7702 designator = EOA.
contract SigCheckTest is Test {
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant PK = 0xA11CE;
    SigCheckHarness internal h;
    Mock1271Wallet internal wallet;
    address internal signer;
    bytes32 internal constant D = keccak256("digest");

    function setUp() public {
        h = new SigCheckHarness();
        signer = vm.addr(PK);
        wallet = new Mock1271Wallet(signer);
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_eoa_valid() public view {
        assertTrue(h.isValid(signer, D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    function test_eoa_wrongSigner() public view {
        assertFalse(h.isValid(signer, D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
    }

    function test_eoa_highS_refused() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, D);
        bytes memory high = abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        assertEq(ecrecover(D, v == 27 ? 28 : 27, r, bytes32(N - uint256(s))), signer); // raw ecrecover accepts it
        assertFalse(h.isValid(signer, D, high, SigCheck.ERC1271_GAS));
    }

    function test_eoa_64byteCompact_refused() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, D);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        assertFalse(h.isValid(signer, D, abi.encodePacked(r, vs), SigCheck.ERC1271_GAS));
    }

    function test_7702Designator_isEoa() public {
        address delegated = vm.addr(0xD7702);
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(wallet)));
        assertFalse(h.isContract(delegated));
        assertTrue(h.isValid(delegated, D, _sig(0xD7702, D), SigCheck.ERC1271_GAS));
        assertTrue(h.isContract(address(wallet)));
    }

    function test_1271_valid() public view {
        assertTrue(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    function test_1271_refusals() public {
        assertFalse(h.isValid(address(wallet), D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.WrongMagic);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.Reverts);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.Short);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    /// The cap is what the wallet gets: a wallet that needs more than the cap fails, not the whole call.
    function test_1271_capIsEnforced() public view {
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), 2_000));
    }

    /// EIP-150: a caller holding less than cap·64/63 + margin reverts instead of answering "invalid".
    function test_1271_starvedCallReverts() public {
        bytes memory sig = _sig(PK, D);
        vm.expectPartialRevert(SigCheck.SigCheckGasStarved.selector);
        h.isValid{gas: 52_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS);
        assertTrue(h.isValid{gas: 80_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS));
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
cd smartcontracts/evm
../../scripts/capped forge test --match-path test/metatx/SigCheck.t.sol 2>&1 | grep -E '^Error|Source .* not found' | head -3
```

Expected: `Error: Compiler run failed` / `Source "src/common/SigCheck.sol" not found`.

- [ ] **Step 3: Write `smartcontracts/evm/src/common/SigCheck.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title The one signature check of every SCaaS contract (CTR-MTX-25).
/// @notice EOA ⇒ OpenZeppelin `ECDSA.tryRecover` (65 bytes, low-s, CTR-MTX-14). Contract ⇒ ERC-1271
///         `isValidSignature` by `staticcall` with a per-signer gas cap (50 000 by default; 400 000 only for
///         `SmartKeyAccount` clones, CTR-ACC-05), at most 32 bytes of returndata read, and the EIP-150 rule of
///         CTR-DEX-08: the caller must hold `cap·64/63 + GAS_MARGIN` gas, so a relayer cannot starve the call to
///         turn a valid signature into an invalid one. "Contract" excludes an EIP-7702 delegated EOA
///         (`0xef0100‖address`): its key still signs.
/// @dev HIP-632 hook (P1c, CTR-TOK-23): `isValid` gains a `bool hedera` argument (the implementation's
///      `IS_HEDERA`); when it is set, `sig.length == 64` and `signer` has no code, the answer is HIP-632
///      `isAuthorizedRaw(signer, digest, sig)` (built: `HederaAccountAuth.asView()`; moved into `HederaLib` in
///      P1c) and nothing below runs. Every other signature on Hedera takes the EVM path unchanged. P1a has no
///      Hedera path: the built Hedera children keep their `_requireValidSignature` overrides until P1b/P1c.
library SigCheck {
    uint256 internal constant ERC1271_GAS = 50_000;
    uint256 internal constant GAS_MARGIN = 5_000;

    /// @notice The caller holds too little gas to give an ERC-1271 wallet its cap (EIP-150, CTR-DEX-08).
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);

    function isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }

    function isValid(address signer, bytes32 digest, bytes memory sig, uint256 cap1271)
        internal view returns (bool ok)
    {
        if (!isContract(signer)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            return err == ECDSA.RecoverError.NoError && rec == signer;
        }
        bytes memory payload = abi.encodeCall(IERC1271.isValidSignature, (digest, sig));
        uint256 left = gasleft();
        if (left < cap1271 * 64 / 63 + GAS_MARGIN) revert SigCheckGasStarved(cap1271, left);
        bytes4 magic = IERC1271.isValidSignature.selector;
        assembly ("memory-safe") {
            mstore(0, 0)
            let success := staticcall(cap1271, signer, add(payload, 0x20), mload(payload), 0, 0x20)
            ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(0), magic))
        }
    }
}
```

- [ ] **Step 4: Run it — expect pass**

```bash
../../scripts/capped forge test --match-path test/metatx/SigCheck.t.sol 2>&1 | tail -2
```

Expected: `Suite result: ok. 9 passed; 0 failed; 0 skipped`.

- [ ] **Step 5: Point the three built meta-tx bases at `SigCheck`**

In `src/metatx/ERC20MetaTx.sol` and `src/metatx/MetaTxCore.sol` replace the two imports

```solidity
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
```

with

```solidity
import {SigCheck} from "../common/SigCheck.sol";
```

and in `src/zether/ZetherMetaTx.sol` the same two imports with the same line (`"../common/SigCheck.sol"`).

In all three files replace the body of `_isContract`:

```solidity
    function _isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }
```

with

```solidity
    function _isContract(address a) internal view returns (bool) {
        return SigCheck.isContract(a);
    }
```

In `src/metatx/ERC20MetaTx.sol` replace the body of `_requireValidSignature` (keep its NatSpec and signature
`internal view virtual`):

```solidity
    {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: _erc1271Gas(from)}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 ||
                abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }
```

with

```solidity
    {
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }
```

In `src/metatx/MetaTxCore.sol` replace

```solidity
    /// @dev EOA (65 byte, low-s) hoặc ERC-1271, phân biệt bằng `_isContract(from)` (như v1). `virtual`: Hedera
    ///      thêm HIP-632 (R63, R144).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: _erc1271Gas(from)}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }
```

with

```solidity
    /// @dev `SigCheck` (CTR-MTX-25). `virtual`: Hedera thêm HIP-632 (R63, R144).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }
```

In `src/zether/ZetherMetaTx.sol` replace

```solidity
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: 50_000}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }
```

with

```solidity
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view {
        if (!SigCheck.isValid(from, digest, sig, SigCheck.ERC1271_GAS)) revert MetaTxBadSignature();
    }
```

Comments: in `src/common/AuthScheme.sol:51` replace `// SigLib.requireValid -> ERC-1271` with
`// SigCheck.isValid -> ERC-1271`; in `src/common/MultiSig.sol:10` replace `` `SigLib.requireValid` gọi `` with
`` `SigCheck.isValid` gọi ``. Then:

```bash
git rm src/common/SigLib.sol
grep -rn 'tryRecover\|IERC1271\|SigLib' src/metatx/ERC20MetaTx.sol src/metatx/MetaTxCore.sol src/zether/ZetherMetaTx.sol src/common
```

Expected grep output: only `src/common/SigCheck.sol` lines (its own `ECDSA.tryRecover` / `IERC1271` uses).

- [ ] **Step 6: Full suite — the built lines unchanged in behaviour**

```bash
../../scripts/capped forge test 2>&1 | tail -1
```

Expected: `Ran 51 test suites …: 648 tests passed, 0 failed, 0 skipped (648 total tests)` (639 + 9; `Erc1271Test`,
`SubjectAccountTest` gas-burner cases, `HederaMetaTokenTest`, `MetaTxGasV2Test` budgets all green).

- [ ] **Step 7: Commit**

```bash
git add src/common/SigCheck.sol test/metatx/SigCheck.t.sol src/metatx/ERC20MetaTx.sol src/metatx/MetaTxCore.sol \
        src/zether/ZetherMetaTx.sol src/common/AuthScheme.sol src/common/MultiSig.sol
git status --short   # expected: only the files above staged, SigLib.sol deleted
git commit -m "$(cat <<'EOF'
feat(evm): SigCheck, the one signature check (CTR-MTX-25); delete SigLib

ECDSA low-s, ERC-1271 with a per-signer gas cap, <=32 bytes of returndata and
the EIP-150 starvation guard (CTR-DEX-08); the HIP-632 hook point is documented
for P1c. ERC20MetaTx (v1), MetaTxCore and ZetherMetaTx delegate to it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `SaltedEIP712` — salted, clone-safe EIP-712 domain (CTR-GEN-05)

**Files:**
- Create: `smartcontracts/evm/src/common/SaltedEIP712.sol`
- Create: `smartcontracts/evm/test/metatx/SaltedEIP712.t.sol`

**Interfaces:**
- Consumes: OZ `IERC5267`, `MessageHashUtils.toTypedDataHash`, `ShortStrings` (`toShortString` reverts
  `StringTooLong(string)` above 31 bytes).
- Produces:

```solidity
abstract contract SaltedEIP712 is IERC5267 {
    bytes32 internal immutable CHAIN_UID;
    constructor(string memory name_, string memory version_, bytes32 chainUid_);
    function eip712Domain() public view virtual returns (bytes1 fields, string memory name, string memory version,
        uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions);   // fields = 0x1f
    function _domainSeparatorV4() internal view returns (bytes32);
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32);
}
```

- [ ] **Step 1: Write the failing test** `smartcontracts/evm/test/metatx/SaltedEIP712.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";

contract SaltedHarness is SaltedEIP712 {
    constructor(string memory n, bytes32 uid) SaltedEIP712(n, "1", uid) {}

    function separator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function typed(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }
}

/// CTR-GEN-05: domain (name, version, chainId, verifyingContract, salt = chain_uid), fields 0x1f, clone-safe.
contract SaltedEIP712Test is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    SaltedHarness internal h;

    function setUp() public {
        vm.chainId(7622);
        h = new SaltedHarness("SCaaS TestRegistry", UID);
    }

    function _expected(address verifying) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS TestRegistry"), keccak256("1"), block.chainid, verifying, UID));
    }

    function test_separatorIsSalted() public view {
        assertEq(h.separator(), _expected(address(h)));
        bytes32 sh = keccak256("struct");
        assertEq(h.typed(sh), keccak256(abi.encodePacked(hex"1901", _expected(address(h)), sh)));
    }

    function test_eip712Domain_fields0x1f() public view {
        (bytes1 f, string memory n, string memory v, uint256 cid, address vc, bytes32 salt, uint256[] memory ext) =
            h.eip712Domain();
        assertEq(f, bytes1(0x1f));
        assertEq(n, "SCaaS TestRegistry");
        assertEq(v, "1");
        assertEq(cid, 7622);
        assertEq(vc, address(h));
        assertEq(salt, UID);
        assertEq(ext.length, 0);
    }

    function test_cloneUsesItsOwnAddressAndTheImplementationSalt() public {
        SaltedHarness c = SaltedHarness(Clones.clone(address(h)));
        assertEq(c.separator(), _expected(address(c)));
        (,,,, address vc, bytes32 salt,) = c.eip712Domain();
        assertEq(vc, address(c));
        assertEq(salt, UID);
        assertTrue(c.separator() != h.separator());
    }

    function test_chainIdChangeRebuilds() public {
        vm.chainId(1);
        assertEq(h.separator(), _expected(address(h)));
    }

    function test_longNameRefused() public {
        vm.expectRevert(abi.encodeWithSelector(ShortStrings.StringTooLong.selector, "SCaaS A Name Longer Than 31 Bytes"));
        new SaltedHarness("SCaaS A Name Longer Than 31 Bytes", UID);
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
../../scripts/capped forge test --match-path test/metatx/SaltedEIP712.t.sol 2>&1 | grep -E '^Error|not found' | head -3
```

Expected: `Source "src/common/SaltedEIP712.sol" not found`.

- [ ] **Step 3: Write `smartcontracts/evm/src/common/SaltedEIP712.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

/// @title EIP-712 domain with `salt = chain_uid` (CTR-GEN-05) — OpenZeppelin `EIP712` has no salt.
/// @notice Domain `(name, version, chainId, verifyingContract = address(this), salt = chain_uid)`;
///         `eip712Domain()` (ERC-5267) reports fields `0x1f`. Everything is an immutable of the implementation, so
///         an EIP-1167 clone (which runs this code by `DELEGATECALL`) uses the same name, version and `chain_uid`
///         with no storage, and the separator is rebuilt whenever `address(this)` or `block.chainid` differs from
///         the cached one. Name and version must fit 31 bytes (`ShortStrings`; longer reverts at deploy):
///         a storage fallback would read the clone's empty storage.
abstract contract SaltedEIP712 is IERC5267 {
    using ShortStrings for ShortString;

    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );

    /// @notice The chain's genesis block hash (NET-ALL-22), fixed by the implementation's constructor.
    bytes32 internal immutable CHAIN_UID;

    ShortString private immutable _name;
    ShortString private immutable _version;
    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;
    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedThis;

    constructor(string memory name_, string memory version_, bytes32 chainUid_) {
        _name = ShortStrings.toShortString(name_);
        _version = ShortStrings.toShortString(version_);
        _hashedName = keccak256(bytes(name_));
        _hashedVersion = keccak256(bytes(version_));
        CHAIN_UID = chainUid_;
        _cachedChainId = block.chainid;
        _cachedThis = address(this);
        _cachedDomainSeparator = _buildDomainSeparator();
    }

    function eip712Domain()
        public view virtual returns (
            bytes1 fields, string memory name, string memory version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] memory extensions
        )
    {
        return (hex"1f", _name.toString(), _version.toString(), block.chainid, address(this), CHAIN_UID,
            new uint256[](0));
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) return _cachedDomainSeparator;
        return _buildDomainSeparator();
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this), CHAIN_UID));
    }
}
```

- [ ] **Step 4: Run it — expect pass**

```bash
../../scripts/capped forge test --match-path test/metatx/SaltedEIP712.t.sol 2>&1 | tail -2
```

Expected: `Suite result: ok. 5 passed; 0 failed; 0 skipped`.

- [ ] **Step 5: Commit**

```bash
git add src/common/SaltedEIP712.sol test/metatx/SaltedEIP712.t.sol
git commit -m "$(cat <<'EOF'
feat(evm): SaltedEIP712, the salted clone-safe EIP-712 domain (CTR-GEN-05)

Domain (name, version, chainId, verifyingContract, salt = chain_uid),
eip712Domain() fields 0x1f, separator rebuilt when address(this) or the chain
id differs from the cached one; names fit 31 bytes (no storage fallback).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `MetaTxLib` — the v3 `MetaTransaction`; the built struct becomes `LegacyMetaTransaction`

**Files:**
- Create: `smartcontracts/evm/test/metatx/MetaTxLib.t.sol`
- Modify: `smartcontracts/evm/src/common/MetaTxLib.sol` (v3 struct, typehash, `canon`, `hashStruct`; legacy rename)
- Modify (mechanical `MetaTxLib.MetaTransaction` → `MetaTxLib.LegacyMetaTransaction`, 222 occurrences in 37 files):
  `script/hedera/HederaSmoke.sol`, `src/dex/MetaTxDex.sol`, `src/metatx/{ERC20MetaTx,IERC20MetaTx,IMetaTokenV2,MetaTokenBase,MetaToken,MetaTxCore}.sol`,
  `src/zether/{IZetherToken,ZetherMetaTx,ZetherToken}.sol`,
  `test/{ContractOnlyAllowance,Erc1271,Invariants,MandateWallet,MetaApprove,MetaToken,MetaTxDex,MetaTxGas,MetaTxKat,OrderBookDex,SubjectAccount}.t.sol`,
  `test/hedera/{HederaKat,HederaMetaToken,HederaV2}.t.sol`, `test/helpers/Fixtures.sol`,
  `test/v2/{BaseKat,Base,MetaTxGasV2,Multi,Tier1,UnwrapOp,WrapperInvariant}.t.sol`, `test/v2/helpers/V2Fixture.sol`,
  `test/zether/helpers/ZetherFixture.sol`, `test/zether/{ZetherRevertPaths,ZetherToken}.t.sol`
- Modify: `smartcontracts/evm/test/FeePolicy.t.sol` (pin of the legacy typehash renamed)

**Interfaces:**
- Consumes: nothing new.
- Produces (in `library MetaTxLib`):

```solidity
struct MetaTransaction { address from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
                         address relayer; uint256 fee; address feeRecipient; }
bytes32 internal constant METATX_TYPEHASH;          // v3 string, Global Constraints
function canon(MetaTransaction memory m) internal pure returns (address r, address f);
function hashStruct(MetaTransaction memory m) internal pure returns (bytes32);
struct LegacyMetaTransaction { /* the built 11 fields, unchanged */ }
bytes32 internal constant LEGACY_METATX_TYPEHASH;   // the built string, unchanged
function canon(LegacyMetaTransaction memory m) internal pure returns (address r, address f);
function hashStruct(LegacyMetaTransaction memory m) internal pure returns (bytes32);
```

- [ ] **Step 1: Write the failing test** `smartcontracts/evm/test/metatx/MetaTxLib.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-15: the generic `MetaTransaction` and its pinned typehash; canonical zeroing; `data` hashed.
contract MetaTxLibTest is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    function _m(uint32 mode) internal pure returns (MetaTxLib.MetaTransaction memory) {
        return MetaTxLib.MetaTransaction({
            from: address(0xA), data: hex"cfdd7aea0000000000000000000000000000000000000000000000000000000000000007",
            batch: 1, nonce: 2, validUntil: 3, mode: mode, relayer: address(0xB), fee: 4, feeRecipient: address(0xC)
        });
    }

    function test_metaTxTypehashIsPinned() public pure {
        assertEq(
            MetaTxLib.METATX_TYPEHASH,
            keccak256(
                "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
            )
        );
        assertEq(MetaTxLib.METATX_TYPEHASH, 0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888);
    }

    function test_hashStruct_encoding() public pure {
        MetaTxLib.MetaTransaction memory m = _m(MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT);
        assertEq(m.hashStruct(), keccak256(abi.encode(
            MetaTxLib.METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode,
            m.relayer, m.fee, m.feeRecipient)));
    }

    function test_unboundFieldsAreHashedAsZero() public pure {
        MetaTxLib.MetaTransaction memory a = _m(MetaTxLib.MODE_OPEN);
        MetaTxLib.MetaTransaction memory b = _m(MetaTxLib.MODE_OPEN);
        b.relayer = address(0xDEAD);
        b.feeRecipient = address(0xBEEF);
        assertEq(a.hashStruct(), b.hashStruct());
        a.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        b.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        assertTrue(a.hashStruct() != b.hashStruct());
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxLib.t.sol 2>&1 | grep -E '^Error' -A3 | head -5
```

Expected: `Error: Compiler run failed` (the struct literal names `data` without `to`/`value`, or the typehash differs).

- [ ] **Step 3: Rename the built struct everywhere it is used (not in the new test)**

```bash
grep -rl 'MetaTxLib\.MetaTransaction\b' src test script | grep -v '^test/metatx/' | wc -l     # expected: 37
grep -rl 'MetaTxLib\.MetaTransaction\b' src test script | grep -v '^test/metatx/' \
  | xargs sed -i 's/MetaTxLib\.MetaTransaction\b/MetaTxLib.LegacyMetaTransaction/g'
sed -i 's/MetaTxLib\.METATX_TYPEHASH/MetaTxLib.LEGACY_METATX_TYPEHASH/; s/function test_metaTxTypehashIsPinned/function test_legacyMetaTxTypehashIsPinned/' test/FeePolicy.t.sol
grep -c LegacyMetaTransaction test/metatx/MetaTxLib.t.sol     # expected: 0
```

- [ ] **Step 4: Edit `src/common/MetaTxLib.sol`**

First rename the built declarations (each pattern below occurs exactly once in the file now):

```bash
sed -i \
  -e 's/^    struct MetaTransaction {$/    struct LegacyMetaTransaction {/' \
  -e 's/function canon(MetaTransaction memory m)/function canon(LegacyMetaTransaction memory m)/' \
  -e 's/bytes32 internal constant METATX_TYPEHASH = keccak256(/bytes32 internal constant LEGACY_METATX_TYPEHASH = keccak256(/' \
  -e 's/Ghim bởi `test_metaTxTypehashIsPinned`/Ghim bởi `test_legacyMetaTxTypehashIsPinned`/' \
  -e 's/function hashStruct(MetaTransaction memory m)/function hashStruct(LegacyMetaTransaction memory m)/' \
  -e 's/^                METATX_TYPEHASH,$/                LEGACY_METATX_TYPEHASH,/' \
  src/common/MetaTxLib.sol
```

Then replace the line just renamed

```solidity
    struct LegacyMetaTransaction {
```

with the block below, which ends with that same line (the eleven built field lines after it stay as they are):

```solidity
    /// @notice v3 (CTR-MTX-15): the signed call of one of THIS contract's allowlisted functions.
    struct MetaTransaction {
        address from;           // signer; the authority the call runs under
        bytes   data;           // a call of THIS contract, allowlisted selector
        uint256 batch;          // nonce dimension 1: lane
        uint256 nonce;          // nonce dimension 2: sequence inside the lane
        uint256 validUntil;     // unix seconds
        uint32  mode;           // constraint flags + fee mode
        address relayer;        // bound relayer when MODE_RESTRICT_RELAYER
        uint256 fee;            // only where the contract charges it (tokens); elsewhere fee mode NONE
        address feeRecipient;   // bound fee recipient when MODE_RESTRICT_FEE_RECIPIENT
    }

    /// @dev Pinned by `test_metaTxTypehashIsPinned` (test/metatx/MetaTxLib.t.sol).
    bytes32 internal constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    function canon(MetaTransaction memory m) internal pure returns (address r, address f) {
        r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
        f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
    }

    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        (address r, address f) = canon(m);
        return keccak256(abi.encode(
            METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f
        ));
    }

    /// @notice v1/v2 struct (Transitional, BUILT): deleted with the v1/v2 lines (P1b) and `ZetherMetaTx` (P3).
    struct LegacyMetaTransaction {
```

Check: `grep -n 'METATX_TYPEHASH\|struct .*MetaTransaction\|function canon\|function hashStruct' src/common/MetaTxLib.sol`
shows exactly: v3 `struct MetaTransaction`, `METATX_TYPEHASH`, `canon(MetaTransaction`, `hashStruct(MetaTransaction`,
then `struct LegacyMetaTransaction`, `canon(LegacyMetaTransaction`, `LEGACY_METATX_TYPEHASH` (twice: declaration
and use), `hashStruct(LegacyMetaTransaction`.

- [ ] **Step 5: Run the new test and the full suite**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxLib.t.sol 2>&1 | tail -2
../../scripts/capped forge test 2>&1 | tail -1
git status --short test/vectors
```

Expected: `3 passed`; full suite `Ran 53 test suites …: 656 tests passed, 0 failed` (the v1 and v2 KATs
`MetaTxKatTest`, `BaseKatTest`, `HederaKatTest` prove the legacy digests did not move); no vector file changed.

- [ ] **Step 6: Commit**

```bash
git add -A src test script
git status --short    # expected: 39 modified files (37 + MetaTxLib.sol + FeePolicy.t.sol) + test/metatx/MetaTxLib.t.sol
git commit -m "$(cat <<'EOF'
feat(evm): v3 MetaTransaction in MetaTxLib; built struct renamed LegacyMetaTransaction

MetaTransaction{from, data, batch, nonce, validUntil, mode, relayer, fee,
feeRecipient} with its pinned typehash (CTR-MTX-15). The built 11-field struct
keeps its typehash string as LegacyMetaTransaction/LEGACY_METATX_TYPEHASH until
P1b/P3 delete its users (mechanical rename, no digest change).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `IMetaTx` + `MetaTxBase` — `mtxExecute`, lanes, ticket, allowlist, `cancelNonce`

**Files:**
- Create: `smartcontracts/evm/src/metatx/IMetaTx.sol`
- Create: `smartcontracts/evm/src/metatx/MetaTxBase.sol`
- Create: `smartcontracts/evm/test/helpers/MtxRegistryMock.sol` (mock on `MetaTxBase` + `ReenterHook`)
- Create: `smartcontracts/evm/test/helpers/MtxFixture.sol`
- Create: `smartcontracts/evm/test/metatx/MetaTxBase.t.sol`

**Interfaces:**
- Consumes: `SigCheck.isValid`, `SigCheck.ERC1271_GAS` (Task 2); `SaltedEIP712`, `CHAIN_UID`, `_hashTypedDataV4`,
  `eip712Domain()` (Task 3); `MetaTxLib.MetaTransaction`, `hashStruct`, `MODE_*` (Task 4); OZ `Context`.
- Produces:

```solidity
interface IMetaTx {  // as metatx.md "Interfaces" minus mtxBatch, MtxBatchEmpty, MtxBatchLengthMismatch (Task 6)
    function mtxNonce(address from, uint256 batch) external view returns (uint256);
    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool success);
    function mtxSelectors() external view returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg);
    function chainUid() external view returns (bytes32);
    function supportedModes() external view returns (uint32);
    function cancelNonce(uint256 batch) external;
}
abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
    uint8 internal constant FEE_CLASS_ABSOLUTE = 1;
    uint8 internal constant FEE_CLASS_AMOUNT = 2;
    struct MtxRule { uint8 feeClass; uint8 amountArg; uint32 staticLen; }
    constructor(string memory domainName, bytes32 chainUid_);
    modifier nonReentrant();
    function supportedModes() public view virtual returns (uint32);                       // 0x03
    function mtxSelectors() public view virtual returns (bytes4[] memory, uint8[] memory, uint8[] memory);
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature) internal returns (bytes memory ret);
    function _checkIntent(MetaTxLib.MetaTransaction memory m, bytes calldata signature) internal view returns (bytes32 digest);
    function _checkCall(MetaTxLib.MetaTransaction memory m) internal view;               // returns the basis from Task 7
    function _mtxRule(bytes4 sel) internal view virtual returns (MtxRule memory r);
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual;
    function _erc1271Gas(address) internal view virtual returns (uint256);
    function _msgSender() internal view virtual override returns (address);
    function _feeRecipientOf(MetaTxLib.MetaTransaction memory m) internal view returns (address);
}
contract MtxRegistryMock is MetaTxBase {   // test helper
    constructor(string memory domainName, bytes32 chainUid_);
    function setName(string calldata name) external;          // ABSOLUTE, dynamic
    function bump(uint256 by) external returns (uint256);     // AMOUNT(0), static 36; reverts ZeroBump() on 0
    function poke(address target, bytes calldata data) external;   // ABSOLUTE, dynamic; test-only probe
    function whoAmI() external view returns (address);        // not allowlisted
    function exposedRule(bytes4 sel) external view returns (MtxRule memory);
}
```

- [ ] **Step 1: Write the test helpers and the failing test**

`smartcontracts/evm/test/helpers/MtxRegistryMock.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// A registry-like contract on `MetaTxBase` (the "family-tree registry" of CTR-MTX-22): fee `NONE` only.
/// Allowlist: `cancelNonce(uint256)` (base), `setName(string)` (dynamic, ABSOLUTE), `bump(uint256)` (static 36,
/// AMOUNT(0)), `poke(address,bytes)` (dynamic, ABSOLUTE): a test-only probe that calls out from inside the
/// self-call. A real allowlist never forwards calldata (CTR-MTX-16).
contract MtxRegistryMock is MetaTxBase {
    error ZeroBump();

    mapping(address => string) public nameOf;
    mapping(address => uint256) public count;

    constructor(string memory domainName, bytes32 chainUid_) MetaTxBase(domainName, chainUid_) {}

    function setName(string calldata name) external nonReentrant {
        nameOf[_msgSender()] = name;
    }

    function bump(uint256 by) external nonReentrant returns (uint256) {
        if (by == 0) revert ZeroBump();
        return count[_msgSender()] += by;
    }

    function poke(address target, bytes calldata data) external nonReentrant {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    /// Not allowlisted, not guarded: shows what `_msgSender()` answers outside a self-call.
    function whoAmI() external view returns (address) {
        return _msgSender();
    }

    function exposedRule(bytes4 sel) external view returns (MtxRule memory) {
        return _mtxRule(sel);
    }

    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
        if (sel == this.setName.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == this.bump.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        if (sel == this.poke.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    function mtxSelectors()
        public view virtual override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](4);
        c = new uint8[](4);
        a = new uint8[](4);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.setName.selector, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (this.bump.selector, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (this.poke.selector, FEE_CLASS_ABSOLUTE);
    }
}

/// Re-enters the registry from outside while a self-call is live.
contract ReenterHook {
    function hit(MtxRegistryMock r) external {
        r.setName("evil");
    }
}
```

`smartcontracts/evm/test/helpers/MtxFixture.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MtxRegistryMock} from "./MtxRegistryMock.sol";

/// Shared setup of the `MetaTxBase` tests: chain 7622 with its real `chain_uid` (chain-uids.json, private7622).
abstract contract MtxFixture is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    address internal alice = vm.addr(ALICE_PK);
    address internal bob = vm.addr(BOB_PK);
    address internal relayer = address(0xBEEF);
    MtxRegistryMock internal reg;

    function setUp() public virtual {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        reg = new MtxRegistryMock("SCaaS TestRegistry", UID);
    }

    function _m(address from, bytes memory data, uint256 batch, uint256 nonce)
        internal view returns (MetaTxLib.MetaTransaction memory)
    {
        return MetaTxLib.MetaTransaction({
            from: from, data: data, batch: batch, nonce: nonce, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_OPEN, relayer: address(0), fee: 0, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, reg.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _setName(string memory n) internal pure returns (bytes memory) {
        return abi.encodeCall(MtxRegistryMock.setName, (n));
    }
}
```

`smartcontracts/evm/test/metatx/MetaTxBase.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock, ReenterHook} from "../helpers/MtxRegistryMock.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-16…19, CTR-MTX-22: the generic pipeline of `MetaTxBase` on a registry-like contract.
contract MetaTxBaseTest is MtxFixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _run(MetaTxLib.MetaTransaction memory m, bytes memory sig) internal returns (bytes memory) {
        vm.prank(relayer);
        return reg.mtxExecute(m, sig);
    }

    // ---------------------------------------------------------------- domain and digest

    function test_digestIsSaltedEip712() public view {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("alice"), 1, 0);
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS TestRegistry"), keccak256("1"), uint256(7622), address(reg), UID));
        assertEq(reg.mtxDigest(m), keccak256(abi.encodePacked(hex"1901", sep, m.hashStruct())));
        assertEq(reg.chainUid(), UID);
        (bytes1 fields,, string memory version,,, bytes32 salt,) = reg.eip712Domain();
        assertEq(fields, bytes1(0x1f));
        assertEq(version, "1");
        assertEq(salt, UID);
    }

    // ---------------------------------------------------------------- happy path

    function test_execute_runsTheCallAsTheSigner() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("alice"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, reg.mtxDigest(m), relayer, 0);
        _run(m, sig);
        assertEq(reg.nameOf(alice), "alice");
        assertEq(reg.nameOf(relayer), "");
        assertEq(reg.mtxNonce(alice, 1), 1);
    }

    function test_execute_returnsTheInnerReturnData() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (5)), 1, 0);
        assertEq(abi.decode(_run(m, _sign(ALICE_PK, m)), (uint256)), 5);
    }

    function test_alias_returnsTrue() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        assertTrue(reg.executeMetaTransaction(m, sig));
        assertEq(reg.nameOf(alice), "a");
    }

    // ---------------------------------------------------------------- signature (step 2)

    function test_wrongSigner_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(BOB_PK, m);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m, sig);
    }

    function test_highS_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, reg.mtxDigest(m));
        bytes memory high = abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m, high);
    }

    function test_erc1271_wallet() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        MetaTxLib.MetaTransaction memory m = _m(address(w), _setName("wallet"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        _run(m, sig);
        assertEq(reg.nameOf(address(w)), "wallet");

        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        MetaTxLib.MetaTransaction memory m2 = _m(address(w), _setName("x"), 1, 1);
        bytes memory sig2 = _sign(ALICE_PK, m2);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m2, sig2);
    }

    // ---------------------------------------------------------------- step 1: lanes, replay, expiry, relayer, mode

    function test_replay_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        _run(m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(m, sig);
    }

    /// Anti-lock (networks/README.md#head-of-line): a stuck lane never blocks another lane.
    function test_lanesAreIndependent() public {
        MetaTxLib.MetaTransaction memory stuck = _m(alice, _setName("a"), 1, 3);
        bytes memory s1 = _sign(ALICE_PK, stuck);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 0, 3));
        _run(stuck, s1);
        MetaTxLib.MetaTransaction memory other = _m(alice, _setName("b"), 2, 0);
        _run(other, _sign(ALICE_PK, other));
        assertEq(reg.mtxNonce(alice, 1), 0);
        assertEq(reg.mtxNonce(alice, 2), 1);
        assertEq(reg.mtxNonce(bob, 2), 0);
    }

    function test_expired_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.validUntil = block.timestamp - 1;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, block.timestamp - 1, block.timestamp));
        _run(m, sig);
        m.validUntil = block.timestamp;                          // inclusive
        _run(m, _sign(ALICE_PK, m));
    }

    function test_relayerBinding() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        m.relayer = relayer;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, bob));
        reg.mtxExecute(m, sig);
        _run(m, sig);
        assertEq(reg.nameOf(alice), "a");
    }

    /// Flags off ⇒ `relayer`/`feeRecipient` are hashed as 0: a submitter may rewrite them (NODE-LANE-10).
    function test_unboundFieldsAreNotSigned() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        m.relayer = bob;
        m.feeRecipient = address(0xFEE);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, reg.mtxDigest(m), address(0xFEE), 0);
        _run(m, sig);
    }

    function test_unknownMode_refused() public {
        uint32[3] memory bad = [uint32(0x04), 0x30, 0x100];
        for (uint256 i; i < 3; ++i) {
            MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
            m.mode = bad[i];
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, bad[i]));
            _run(m, sig);
        }
    }

    function test_selfSender_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(address(reg), _setName("a"), 1, 0);
        vm.expectRevert(IMetaTx.SelfSender.selector);
        _run(m, hex"");
    }

    // ---------------------------------------------------------------- step 3: allowlist and shape

    function test_notAllowlisted_refused() public {
        bytes[3] memory datas = [
            abi.encodeCall(MtxRegistryMock.whoAmI, ()),
            abi.encodeCall(IMetaTx.mtxExecute, (_m(alice, _setName("a"), 1, 0), hex"")),   // no nesting
            abi.encodeCall(IMetaTx.executeMetaTransaction, (_m(alice, _setName("a"), 1, 0), hex""))
        ];
        for (uint256 i; i < 3; ++i) {
            MetaTxLib.MetaTransaction memory m = _m(alice, datas[i], 1, 0);
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(datas[i])));
            _run(m, sig);
        }
    }

    function test_dataShape_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, hex"cfdd7a", 1, 0);   // 3 bytes
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(0xcfdd7a00)));
        _run(m, sig);

        bytes memory longBump = abi.encodePacked(abi.encodeCall(MtxRegistryMock.bump, (1)), uint8(0));
        m = _m(alice, longBump, 1, 0);
        sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, MtxRegistryMock.bump.selector));
        _run(m, sig);
    }

    function test_mtxSelectors_isPinnedAndMatchesTheRules() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = reg.mtxSelectors();
        assertEq(s.length, 4);
        assertEq(s[0], IMetaTx.cancelNonce.selector);
        assertEq(s[1], MtxRegistryMock.setName.selector);
        assertEq(s[2], MtxRegistryMock.bump.selector);
        assertEq(s[3], MtxRegistryMock.poke.selector);
        for (uint256 i; i < s.length; ++i) {
            MetaTxBase.MtxRule memory r = reg.exposedRule(s[i]);
            assertEq(r.feeClass, c[i]);
            assertEq(r.amountArg, a[i]);
        }
        assertEq(reg.exposedRule(MtxRegistryMock.whoAmI.selector).feeClass, 0);
    }

    // ---------------------------------------------------------------- all or nothing

    function test_innerRevert_bubblesAndLeavesTheNonce() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (0)), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        _run(m, sig);
        assertEq(reg.mtxNonce(alice, 1), 0);
    }

    // ---------------------------------------------------------------- ticket and _msgSender (CTR-MTX-18)

    function test_msgSender_outsideTheSelfCall_isTheCaller() public {
        vm.prank(bob);
        reg.setName("bob");
        assertEq(reg.nameOf(bob), "bob");
        // after a self-call in the same transaction the ticket is cleared: `this` is just `msg.sender`
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        _run(m, _sign(ALICE_PK, m));
        vm.prank(address(reg));
        assertEq(reg.whoAmI(), address(reg));
    }

    function test_directSelfCallWithoutTicket_isNotTheSigner() public {
        vm.prank(address(reg));
        reg.setName("self");
        assertEq(reg.nameOf(address(reg)), "self");
    }

    function test_ticketAdmitsOneSelfCall() public {
        bytes memory inner = _setName("twice");
        MetaTxLib.MetaTransaction memory m =
            _m(alice, abi.encodeCall(MtxRegistryMock.poke, (address(reg), inner)), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        _run(m, sig);
    }

    function test_reentryFromOutsideDuringTheSelfCall_refused() public {
        ReenterHook hook = new ReenterHook();
        MetaTxLib.MetaTransaction memory m = _m(
            alice, abi.encodeCall(MtxRegistryMock.poke, (address(hook), abi.encodeCall(ReenterHook.hit, (reg)))), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        _run(m, sig);
    }

    /// Every allowlisted function is `nonReentrant` (CTR-MTX-18): re-entered with the ticket spent, each reverts.
    function test_everyAllowlistedSelectorIsNonReentrant() public {
        (bytes4[] memory s,,) = reg.mtxSelectors();
        for (uint256 i; i < s.length; ++i) {
            MetaTxLib.MetaTransaction memory m =
                _m(alice, abi.encodeCall(MtxRegistryMock.poke, (address(reg), _sample(s[i]))), 1, 0);
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(IMetaTx.Reentrancy.selector);
            _run(m, sig);
        }
    }

    function _sample(bytes4 sel) internal view returns (bytes memory) {
        if (sel == IMetaTx.cancelNonce.selector) return abi.encodeCall(IMetaTx.cancelNonce, (9));
        if (sel == MtxRegistryMock.setName.selector) return _setName("x");
        if (sel == MtxRegistryMock.bump.selector) return abi.encodeCall(MtxRegistryMock.bump, (1));
        if (sel == MtxRegistryMock.poke.selector) return abi.encodeCall(MtxRegistryMock.poke, (address(reg), ""));
        revert("no sample for an allowlisted selector");
    }

    // ---------------------------------------------------------------- cancelNonce

    function test_cancelNonce_direct() public {
        MetaTxLib.MetaTransaction memory pending = _m(alice, _setName("a"), 7, 0);
        bytes memory sig = _sign(ALICE_PK, pending);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaNonceCancelled(alice, 7, 1);
        vm.prank(alice);
        reg.cancelNonce(7);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(pending, sig);
    }

    /// A subject without gas cancels lane 7 by a signed self-call on lane 8.
    function test_cancelNonce_signedOnAnotherLane() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(IMetaTx.cancelNonce, (7)), 8, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaNonceCancelled(alice, 7, 1);
        _run(m, sig);
        assertEq(reg.mtxNonce(alice, 7), 1);
        assertEq(reg.mtxNonce(alice, 8), 1);
        assertEq(reg.mtxNonce(relayer, 7), 0);
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBase.t.sol 2>&1 | grep -E '^Error|not found' | head -3
```

Expected: `Source "src/metatx/MetaTxBase.sol" not found`.

- [ ] **Step 3: Write `smartcontracts/evm/src/metatx/IMetaTx.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The meta-transaction surface of every SCaaS contract on `MetaTxBase` (metatx.md, Interfaces).
interface IMetaTx {
    event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
                                  uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
    event MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce);

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownMode(uint32 mode);
    error MtxSelectorNotAllowed(bytes4 selector);
    error MtxDataShape(bytes4 selector);
    error MtxFeeClass(bytes4 selector, uint32 mode);
    error Reentrancy();
    error SelfSender();

    function mtxNonce(address from, uint256 batch) external view returns (uint256);
    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external returns (bool success);
    function mtxSelectors()
        external view returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg);
    function chainUid() external view returns (bytes32);
    function supportedModes() external view returns (uint32);   // 0xF3 on tokens, 0x03 elsewhere
    function cancelNonce(uint256 batch) external;
}
```

- [ ] **Step 4: Write `smartcontracts/evm/src/metatx/MetaTxBase.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The generic meta-transaction base of every SCaaS contract (CTR-MTX-22).
/// @notice The subject signs a `MetaTransaction` (CTR-MTX-15) whose `data` is one call of one of THIS contract's
///         allowlisted functions; anyone submits it through `mtxExecute`, and the contract runs it on itself
///         (CTR-MTX-16, CTR-MTX-17). The signer travels in a transient slot and one ticket admits exactly one
///         self-call (CTR-MTX-18). The allowlist is fixed per implementation (CTR-MTX-19): an implementation
///         overrides `_mtxRule` (ending in `return super._mtxRule(sel);`) and `mtxSelectors` (the base entry
///         `cancelNonce` first). A contract that holds no charged balance accepts fee mode `NONE` only
///         (`supportedModes() = 0x03`, CTR-MTX-22).
abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    /// @notice Fee classes published by `mtxSelectors()` (CTR-MTX-20). 0 = not allowlisted.
    uint8 internal constant FEE_CLASS_ABSOLUTE = 1;
    uint8 internal constant FEE_CLASS_AMOUNT = 2;

    /// @param feeClass  0 (not allowlisted), FEE_CLASS_ABSOLUTE or FEE_CLASS_AMOUNT
    /// @param amountArg for FEE_CLASS_AMOUNT: index of the uint256 argument that is the fee basis
    /// @param staticLen the selector's static ABI length of `data` (4 + 32·args); 0 = has dynamic arguments
    struct MtxRule {
        uint8 feeClass;
        uint8 amountArg;
        uint32 staticLen;
    }

    // Transient slots (CTR-MTX-18), written as literals: assembly takes no keccak256 constant.
    bytes32 private constant _GUARD = 0xf92fce36488cd980109789c37ce44669ca2ec8fc93bcd6d944c3a5544f9ce252; // keccak256("scaas.mtx.guard")
    bytes32 private constant _SENDER = 0x6f8cf97d962f34e862325b04dcb64b0eb0b06cf30b06b61c33210ec760df0f0b; // keccak256("scaas.mtx.sender")
    bytes32 private constant _TICKET = 0xdea51947149e025e6ed748bbba150c788d4bf051fa2851715a58709dbd31a816; // keccak256("scaas.mtx.ticket")

    /// @custom:storage-location erc7201:scaas.metatx
    struct MetaTxStorage {
        mapping(address from => mapping(uint256 batch => uint256)) nonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.metatx")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00;

    /// @param domainName "SCaaS <Contract>" (CTR-MTX-02); the domain version is always "1".
    /// @param chainUid_  the chain's genesis block hash (CTR-GEN-05)
    constructor(string memory domainName, bytes32 chainUid_) SaltedEIP712(domainName, "1", chainUid_) {}

    /// @notice One contract-wide guard; the one self-call of step 5 may enter once and consumes the ticket.
    modifier nonReentrant() {
        bool outer = _tload(_GUARD) == 0;
        if (outer) {
            _tstore(_GUARD, 1);
        } else {
            if (msg.sender != address(this) || _tload(_TICKET) != 1) revert Reentrancy();
            _tstore(_TICKET, 2);
        }
        _;
        if (outer) _tstore(_GUARD, 0);
    }

    // ------------------------------------------------------------------ views

    function mtxNonce(address from, uint256 batch) public view returns (uint256) {
        return _mtxStorage().nonce[from][batch];
    }

    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _hashTypedDataV4(m.hashStruct());
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    /// @notice `0x03`: flags only, fee mode `NONE`. A token (which overrides `_chargeFee`) returns `0xF3`.
    function supportedModes() public view virtual returns (uint32) {
        return MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    }

    /// @notice The allowlist (CTR-MTX-19). An override returns the base entry first, then its own.
    function mtxSelectors()
        public view virtual returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg)
    {
        selectors = new bytes4[](1);
        feeClass = new uint8[](1);
        amountArg = new uint8[](1);
        selectors[0] = IMetaTx.cancelNonce.selector;
        feeClass[0] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ entry points

    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        return _execute(m, signature);
    }

    /// @notice EIP-1776 alias of `mtxExecute` (CTR-MTX-17); returns `true`.
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        _execute(m, signature);
        return true;
    }

    /// @notice Direct, or signed through `mtxExecute` on another lane (a subject without gas can cancel).
    function cancelNonce(uint256 batch) external nonReentrant {
        address from = _msgSender();
        uint256 n;
        unchecked { n = ++_mtxStorage().nonce[from][batch]; }
        emit MetaNonceCancelled(from, batch, n);
    }

    // ------------------------------------------------------------------ pipeline (CTR-MTX-17)

    /// @dev Every entry (generic, alias, batch, later the named builders) goes through here.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal returns (bytes memory ret)
    {
        bytes32 digest = _checkIntent(m, signature);            // 1, 2
        _checkCall(m);                                          // 3
        unchecked { _mtxStorage().nonce[m.from][m.batch] = m.nonce + 1; }   // 4
        ret = _selfCall(m);                                     // 5
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), 0); // 7
    }

    /// @dev Steps 1 (cheap) and 2 (signature).
    function _checkIntent(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal view returns (bytes32 digest)
    {
        if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 && m.relayer != msg.sender) {
            revert MetaTxUnauthorizedRelayer(m.relayer, msg.sender);
        }
        if (block.timestamp > m.validUntil) revert MetaTxExpired(m.validUntil, block.timestamp);
        if (m.mode & ~MetaTxLib.MODE_KNOWN_MASK != 0 || m.mode & MetaTxLib.MODE_FEE_MASK > MetaTxLib.MODE_FEE_FIXED) {
            revert MetaTxUnknownMode(m.mode);
        }
        uint256 expected = _mtxStorage().nonce[m.from][m.batch];
        if (expected != m.nonce) revert MetaTxBadNonce(expected, m.nonce);
        if (m.from == address(this)) revert SelfSender();
        digest = _hashTypedDataV4(m.hashStruct());
        _requireValidSignature(m.from, digest, signature);
    }

    /// @dev Step 3: shape, allowlist, `supportedModes()`.
    function _checkCall(MetaTxLib.MetaTransaction memory m) internal view {
        bytes memory data = m.data;
        bytes4 sel = bytes4(data);
        if (data.length < 4) revert MtxDataShape(sel);
        MtxRule memory r = _mtxRule(sel);
        if (r.feeClass == 0) revert MtxSelectorNotAllowed(sel);
        if (r.staticLen != 0 && data.length != r.staticLen) revert MtxDataShape(sel);
        if (m.mode & ~supportedModes() != 0) revert MetaTxUnknownMode(m.mode);
    }

    /// @dev Step 5: store the ticket, call self, clear; a failed call reverts with its own revert data.
    function _selfCall(MetaTxLib.MetaTransaction memory m) private returns (bytes memory ret) {
        _tstore(_SENDER, uint256(uint160(m.from)));
        _tstore(_TICKET, 1);
        bool ok;
        (ok, ret) = address(this).call(m.data);
        _tstore(_TICKET, 0);
        _tstore(_SENDER, 0);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    // ------------------------------------------------------------------ hooks

    /// @notice The rule of `sel`; feeClass 0 = not allowlisted. Overrides end with `return super._mtxRule(sel);`.
    function _mtxRule(bytes4 sel) internal view virtual returns (MtxRule memory r) {
        if (sel == IMetaTx.cancelNonce.selector) r = MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
    }

    /// @notice EOA, ERC-1271 or (P1c) HIP-632, through `SigCheck` (CTR-MTX-25).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }

    /// @notice 50 000 for every contract wallet; `SmartKeyAccount` clones get 400 000 where an override knows them.
    function _erc1271Gas(address) internal view virtual returns (uint256) {
        return SigCheck.ERC1271_GAS;
    }

    /// @notice The signer inside the one self-call of step 5 (live ticket), else `msg.sender` (CTR-MTX-18).
    function _msgSender() internal view virtual override returns (address) {
        if (msg.sender == address(this) && _tload(_TICKET) != 0) return address(uint160(_tload(_SENDER)));
        return msg.sender;
    }

    /// @dev `m.feeRecipient`, or `msg.sender` when 0 (CTR-MTX-13).
    function _feeRecipientOf(MetaTxLib.MetaTransaction memory m) internal view returns (address) {
        return m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
    }

    // ------------------------------------------------------------------ storage

    function _mtxStorage() private pure returns (MetaTxStorage storage $) {
        assembly ("memory-safe") { $.slot := _STORAGE }
    }

    function _tload(bytes32 slot) private view returns (uint256 v) {
        assembly ("memory-safe") { v := tload(slot) }
    }

    function _tstore(bytes32 slot, uint256 v) private {
        assembly ("memory-safe") { tstore(slot, v) }
    }
}
```

- [ ] **Step 5: Run it — expect pass**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBase.t.sol 2>&1 | tail -2
```

Expected: `Suite result: ok. 25 passed; 0 failed; 0 skipped`.

- [ ] **Step 6: Full suite**

```bash
../../scripts/capped forge test 2>&1 | tail -1
```

Expected: `Ran 54 test suites …: 681 tests passed, 0 failed, 0 skipped (681 total tests)`.

- [ ] **Step 7: Commit**

```bash
git add src/metatx/IMetaTx.sol src/metatx/MetaTxBase.sol test/helpers/MtxRegistryMock.sol test/helpers/MtxFixture.sol \
        test/metatx/MetaTxBase.t.sol
git commit -m "$(cat <<'EOF'
feat(evm): MetaTxBase, the generic meta-tx base (CTR-MTX-17/18/19/22)

mtxExecute (+ executeMetaTransaction alias) runs an allowlisted self-call
under a transient sender with a one-shot ticket; 2D lanes in the ERC-7201
namespace scaas.metatx; cancelNonce direct or signed; SigCheck and the salted
domain. Pipeline lifted from MetaTxCore; no token uses it yet (P1b).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `mtxBatch` — atomic batch of `MetaTransaction`s (CTR-MTX-11)

**Files:**
- Modify: `smartcontracts/evm/src/metatx/IMetaTx.sol`, `smartcontracts/evm/src/metatx/MetaTxBase.sol`
- Create: `smartcontracts/evm/test/metatx/MetaTxBaseBatch.t.sol`

**Interfaces:**
- Consumes: `_execute` (Task 5), `MtxFixture`, `MtxRegistryMock` (Task 5).
- Produces:

```solidity
error MtxBatchEmpty();
error MtxBatchLengthMismatch();
function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
```

- [ ] **Step 1: Write the failing test** `smartcontracts/evm/test/metatx/MetaTxBaseBatch.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-11: `mtxBatch` is atomic, runs items in order, a fresh ticket per item.
contract MetaTxBaseBatchTest is MtxFixture {
    function _batch(MetaTxLib.MetaTransaction[] memory ms, bytes[] memory sigs) internal {
        vm.prank(relayer);
        reg.mtxBatch(ms, sigs);
    }

    function test_batch_runsEachItemAsItsSigner() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](3);
        bytes[] memory sigs = new bytes[](3);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(bob, _setName("bob"), 1, 0);
        ms[2] = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (2)), 1, 1);
        ms[2].mode = MetaTxLib.MODE_RESTRICT_RELAYER;   // bound to the submitting relayer: still fine in a batch
        ms[2].relayer = relayer;
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(BOB_PK, ms[1]);
        sigs[2] = _sign(ALICE_PK, ms[2]);
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "alice");
        assertEq(reg.nameOf(bob), "bob");
        assertEq(reg.count(alice), 2);
        assertEq(reg.mtxNonce(alice, 1), 2);
        assertEq(reg.mtxNonce(bob, 1), 1);
    }

    function test_batch_isAllOrNothing() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _m(alice, _setName("alice"), 1, 0);
        ms[1] = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (0)), 1, 1);
        sigs[0] = _sign(ALICE_PK, ms[0]);
        sigs[1] = _sign(ALICE_PK, ms[1]);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        _batch(ms, sigs);
        assertEq(reg.nameOf(alice), "");
        assertEq(reg.mtxNonce(alice, 1), 0);
    }

    function test_batch_empty() public {
        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        _batch(new MetaTxLib.MetaTransaction[](0), new bytes[](0));
    }

    function test_batch_lengthMismatch() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        ms[0] = _m(alice, _setName("a"), 1, 0);
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        _batch(ms, new bytes[](0));
    }

    function test_batch_isNotAllowlisted() public {
        MetaTxLib.MetaTransaction[] memory inner = new MetaTxLib.MetaTransaction[](1);
        inner[0] = _m(alice, _setName("a"), 2, 0);
        bytes memory data = abi.encodeCall(IMetaTx.mtxBatch, (inner, new bytes[](1)));
        MetaTxLib.MetaTransaction memory m = _m(alice, data, 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, IMetaTx.mtxBatch.selector));
        reg.mtxExecute(m, sig);
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBaseBatch.t.sol 2>&1 | grep -E '^Error' -A3 | head -4
```

Expected: `Member "mtxBatch" not found` (or `MtxBatchEmpty` not found).

- [ ] **Step 3: Implement**

In `src/metatx/IMetaTx.sol` replace

```solidity
    error SelfSender();
```

with

```solidity
    error SelfSender();
    error MtxBatchEmpty();
    error MtxBatchLengthMismatch();
```

and replace

```solidity
        external returns (bool success);
    function mtxSelectors()
```

with

```solidity
        external returns (bool success);
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
    function mtxSelectors()
```

In `src/metatx/MetaTxBase.sol` insert, directly before `/// @notice Direct, or signed through \`mtxExecute\``:

```solidity
    /// @notice Atomic: items run in order, each with a fresh ticket; any failure reverts all (CTR-MTX-11).
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _execute(ms[i], signatures[i]);
        return true;
    }
```

- [ ] **Step 4: Run it — expect pass; then the full suite**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBaseBatch.t.sol 2>&1 | tail -2
../../scripts/capped forge test 2>&1 | tail -1
```

Expected: `5 passed`; full suite `Ran 55 test suites …: 686 tests passed, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add src/metatx/IMetaTx.sol src/metatx/MetaTxBase.sol test/metatx/MetaTxBaseBatch.t.sol
git commit -m "$(cat <<'EOF'
feat(evm): mtxBatch on MetaTxBase — atomic, in order, fresh ticket per item

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Fee classes and `_chargeFee` — `NONE` only unless overridden (CTR-MTX-20, CTR-MTX-22)

**Files:**
- Modify: `smartcontracts/evm/src/metatx/MetaTxBase.sol`
- Create: `smartcontracts/evm/test/metatx/MetaTxBaseFee.t.sol`

**Interfaces:**
- Consumes: `MtxRule`, `FEE_CLASS_*`, `_checkCall`, `_execute`, `supportedModes()` (Task 5); `FeeMode`,
  `MetaTxLib.feeModeOf` (built).
- Produces:

```solidity
function _checkCall(MetaTxLib.MetaTransaction memory m) internal view returns (uint256 basis);   // was: no return
function _chargeFee(address from, uint256 basis, MetaTxLib.MetaTransaction memory m) internal virtual returns (uint256);
```

Contract for P1b: `_chargeFee` runs **after** the self-call (step 6); `basis` = argument `amountArg` of `data` for
`AMOUNT`, 0 for `ABSOLUTE`; its return value is the `fee` field of `MetaTransactionExecuted`; a revert in it reverts
the call and the nonce.

- [ ] **Step 1: Write the failing test** `smartcontracts/evm/test/metatx/MetaTxBaseFee.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Exposes `_chargeFee` of the base (no override).
contract ChargeFeeHarness is MtxRegistryMock {
    constructor(bytes32 uid) MtxRegistryMock("SCaaS TestRegistry", uid) {}

    function exposedChargeFee(MetaTxLib.MetaTransaction calldata m) external returns (uint256) {
        return _chargeFee(m.from, 0, m);
    }
}

/// What a token does in P1b: overrides `_chargeFee` and reports `0xF3`. Records the basis it was given.
contract FeeProbe is MtxRegistryMock {
    error FeeFailed();

    uint256 public lastBasis;
    uint256 public calls;

    constructor(bytes32 uid) MtxRegistryMock("SCaaS TestRegistry", uid) {}

    function supportedModes() public pure override returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function _chargeFee(address, uint256 basis, MetaTxLib.MetaTransaction memory m)
        internal override returns (uint256)
    {
        if (m.fee == 99) revert FeeFailed();
        lastBasis = basis;
        calls += 1;
        return m.fee;
    }
}

/// CTR-MTX-20, CTR-MTX-22: fee classes; a contract without a fee override accepts fee mode NONE only.
contract MetaTxBaseFeeTest is MtxFixture {
    function _modeRun(MetaTxLib.MetaTransaction memory m, uint32 mode, bytes memory err) internal {
        m.mode = mode;
        m.fee = 1;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        if (err.length != 0) vm.expectRevert(err);
        reg.mtxExecute(m, sig);
    }

    function test_supportedModes_flagsOnly() public view {
        assertEq(reg.supportedModes(), 0x03);
    }

    function test_feeModes_refusedWithoutOverride() public {
        bytes4 setNameSel = MtxRegistryMock.setName.selector;
        // ABSOLUTE refuses PERCENT by class
        _modeRun(_m(alice, _setName("a"), 1, 0), MetaTxLib.MODE_FEE_PERCENT,
            abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, setNameSel, MetaTxLib.MODE_FEE_PERCENT));
        // ABSOLUTE admits FIXED by class; supportedModes() = 0x03 refuses it
        _modeRun(_m(alice, _setName("a"), 1, 0), MetaTxLib.MODE_FEE_FIXED,
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        // AMOUNT admits PERCENT by class; supportedModes() refuses it
        _modeRun(_m(alice, abi.encodeCall(MtxRegistryMock.bump, (1)), 1, 0), MetaTxLib.MODE_FEE_PERCENT,
            abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_PERCENT));
        // NONE with both flags passes
        MetaTxLib.MetaTransaction memory ok = _m(alice, _setName("a"), 1, 0);
        ok.relayer = relayer;
        ok.feeRecipient = address(0xFEE);
        _modeRun(ok, MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, "");
        assertEq(reg.nameOf(alice), "a");
    }

    function test_chargeFee_refusesAllButNone() public {
        ChargeFeeHarness h = new ChargeFeeHarness(UID);
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        assertEq(h.exposedChargeFee(m), 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_PERCENT));
        h.exposedChargeFee(m);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        h.exposedChargeFee(m);
    }

    /// The hook contract P1b relies on: fee after the call, basis = argument i for AMOUNT(i), 0 for ABSOLUTE.
    function test_feeHook_basisAndEvent() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (7)), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 3;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(p));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, p.mtxDigest(m), relayer, 3);
        vm.prank(relayer);
        p.mtxExecute(m, sig);
        assertEq(p.lastBasis(), 7);

        MetaTxLib.MetaTransaction memory a = _m(alice, _setName("a"), 1, 1);
        a.mode = MetaTxLib.MODE_FEE_FIXED;
        bytes memory sigA = _sign(ALICE_PK, a);
        vm.prank(relayer);
        p.mtxExecute(a, sigA);
        assertEq(p.lastBasis(), 0);
        assertEq(p.calls(), 2);

        a.nonce = 2;
        a.mode = MetaTxLib.MODE_FEE_PERCENT;
        sigA = _sign(ALICE_PK, a);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, MtxRegistryMock.setName.selector,
            MetaTxLib.MODE_FEE_PERCENT));
        p.mtxExecute(a, sigA);
    }

    /// Step 6 runs after the call: a failing fee reverts the call's effects and the nonce (all or nothing).
    function test_feeFailure_revertsTheCall() public {
        FeeProbe p = new FeeProbe(UID);
        reg = p;
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("paid"), 1, 0);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 99;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        vm.expectRevert(FeeProbe.FeeFailed.selector);
        p.mtxExecute(m, sig);
        assertEq(p.nameOf(alice), "");
        assertEq(p.mtxNonce(alice, 1), 0);
    }
}
```

- [ ] **Step 2: Run it — expect a compile failure**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBaseFee.t.sol 2>&1 | grep -E '^Error' -A3 | head -4
```

Expected: `Function has override specified but does not override anything` / `Undeclared identifier` for `_chargeFee`.

- [ ] **Step 3: Implement in `src/metatx/MetaTxBase.sol`**

Add the import after `import {MetaTxLib} from "../common/MetaTxLib.sol";`:

```solidity
import {FeeMode} from "../common/FeePolicy.sol";
```

Replace in `_execute`

```solidity
        _checkCall(m);                                          // 3
        unchecked { _mtxStorage().nonce[m.from][m.batch] = m.nonce + 1; }   // 4
        ret = _selfCall(m);                                     // 5
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), 0); // 7
```

with

```solidity
        uint256 basis = _checkCall(m);                          // 3
        unchecked { _mtxStorage().nonce[m.from][m.batch] = m.nonce + 1; }   // 4
        ret = _selfCall(m);                                     // 5
        uint256 fee = _chargeFee(m.from, basis, m);             // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), fee); // 7
```

Replace `_checkCall`

```solidity
    /// @dev Step 3: shape, allowlist, `supportedModes()`.
    function _checkCall(MetaTxLib.MetaTransaction memory m) internal view {
        bytes memory data = m.data;
        bytes4 sel = bytes4(data);
        if (data.length < 4) revert MtxDataShape(sel);
        MtxRule memory r = _mtxRule(sel);
        if (r.feeClass == 0) revert MtxSelectorNotAllowed(sel);
        if (r.staticLen != 0 && data.length != r.staticLen) revert MtxDataShape(sel);
        if (m.mode & ~supportedModes() != 0) revert MetaTxUnknownMode(m.mode);
    }
```

with

```solidity
    /// @dev Step 3: shape, allowlist, fee class, `supportedModes()`. Returns the fee basis.
    function _checkCall(MetaTxLib.MetaTransaction memory m) internal view returns (uint256 basis) {
        bytes memory data = m.data;
        bytes4 sel = bytes4(data);
        if (data.length < 4) revert MtxDataShape(sel);
        MtxRule memory r = _mtxRule(sel);
        if (r.feeClass == 0) revert MtxSelectorNotAllowed(sel);
        uint256 basisEnd = 36 + 32 * uint256(r.amountArg);
        if ((r.staticLen != 0 && data.length != r.staticLen)
            || (r.feeClass == FEE_CLASS_AMOUNT && data.length < basisEnd)) revert MtxDataShape(sel);
        if (r.feeClass == FEE_CLASS_ABSOLUTE && MetaTxLib.feeModeOf(m.mode) == FeeMode.PERCENT) {
            revert MtxFeeClass(sel, m.mode);
        }
        if (m.mode & ~supportedModes() != 0) revert MetaTxUnknownMode(m.mode);
        if (r.feeClass == FEE_CLASS_AMOUNT) {
            assembly ("memory-safe") { basis := mload(add(data, basisEnd)) }
        }
    }
```

Insert, directly before `/// @notice EOA, ERC-1271 or (P1c) HIP-632`:

```solidity
    /// @notice Step 6, after the call. Default: no balance to charge ⇒ every mode but `NONE` reverts (CTR-MTX-22).
    ///         A token overrides it to charge `fee` in this token (P1b, `ERC20MetaTx`).
    function _chargeFee(address, uint256, MetaTxLib.MetaTransaction memory m) internal virtual returns (uint256) {
        if (MetaTxLib.feeModeOf(m.mode) != FeeMode.NONE) revert MetaTxUnknownMode(m.mode);
        return 0;
    }
```

- [ ] **Step 4: Run it — expect pass; then the full suite**

```bash
../../scripts/capped forge test --match-path test/metatx/MetaTxBaseFee.t.sol 2>&1 | tail -2
../../scripts/capped forge test 2>&1 | tail -1
```

Expected: `5 passed`; full suite `Ran 56 test suites …: 691 tests passed, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add src/metatx/MetaTxBase.sol test/metatx/MetaTxBaseFee.t.sol
git commit -m "$(cat <<'EOF'
feat(evm): fee classes and _chargeFee on MetaTxBase (CTR-MTX-20/22)

ABSOLUTE refuses PERCENT (MtxFeeClass); supportedModes() = 0x03 refuses every
fee mode on a contract without a fee override; _chargeFee runs after the call
with the AMOUNT(i) basis and reverts unless the fee mode is NONE.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: KAT `metatx_kat.json` for the v3 `MetaTransaction`; the v1 vector moves to `metatx_v1_kat.json`

**Files:**
- Move: `smartcontracts/evm/test/vectors/metatx_kat.json` → `smartcontracts/evm/test/vectors/metatx_v1_kat.json` (`git mv`)
- Modify (path only, `metatx_kat.json` → `metatx_v1_kat.json`): `smartcontracts/evm/test/MetaTxKat.t.sol` (lines 9, 55),
  `smartcontracts/evm/test/v2/BaseKat.t.sol` (line 68), `scaas-node/src/metatx.rs` (line 142),
  `scaas-node/tests/mesh_vectors.rs` (line 65), `clients/clientkeys/test/evm.test.js` (lines 16, 144)
- Create: `smartcontracts/evm/test/metatx/MetaTxBaseKat.t.sol`
- Create (generated): `smartcontracts/evm/test/vectors/metatx_kat.json`
- Out of repo, report only: `/home/dockers/odoo19/custom-addons/bamboo-dms/dms_blockchain/tests/test_eip712.py:14`
  reads `metatx_kat.json` (v1 format) and goes red; it must read `metatx_v1_kat.json` (or move to v3 in P5).

**Interfaces:**
- Consumes: `MtxFixture`, `MtxRegistryMock` (Task 5), `MetaTxLib.hashStruct`, `METATX_TYPEHASH` (Task 4).
- Produces: `test/vectors/metatx_kat.json` with keys `domain_name, domain_version, chain_id, verifying_contract,
  salt, from, data, batch, nonce, valid_until, mode, relayer, fee, fee_recipient, type_hash, domain_separator,
  struct_hash, digest, signer, signature`; regenerated only with `WRITE_KAT=1`, otherwise checked.

- [ ] **Step 1: Move the v1 vector and repoint its readers**

```bash
cd /home/ha/work/ainative/scaas
git mv smartcontracts/evm/test/vectors/metatx_kat.json smartcontracts/evm/test/vectors/metatx_v1_kat.json
sed -i 's#test/vectors/metatx_kat\.json#test/vectors/metatx_v1_kat.json#g' \
  smartcontracts/evm/test/MetaTxKat.t.sol smartcontracts/evm/test/v2/BaseKat.t.sol \
  scaas-node/src/metatx.rs scaas-node/tests/mesh_vectors.rs
sed -i "s#read('metatx_kat\.json')#read('metatx_v1_kat.json')#g" clients/clientkeys/test/evm.test.js
grep -rn "metatx_kat\.json" smartcontracts/evm/test scaas-node clients/clientkeys/test --include=*.sol --include=*.rs --include=*.js
```

Expected grep output: only `smartcontracts/evm/test/v2/BaseKat.t.sol:12` (a comment naming the v1 file's struct).

```bash
cd smartcontracts/evm
../../scripts/capped forge test --match-contract 'MetaTxKatTest|BaseKatTest' 2>&1 | tail -1
git status --short test/vectors       # expected: only the rename
cd ../../scaas-node && ../scripts/capped cargo test digest_matches_forge_kat 2>&1 | grep -E 'test result'
../scripts/capped cargo test --test mesh_vectors 2>&1 | grep -E 'test result'
cd ../clients/clientkeys && node --test test/evm.test.js 2>&1 | grep -E '^# (pass|fail)'
```

Expected: forge `2 tests passed`; cargo `test result: ok.` twice; node `# pass N`, `# fail 0`.

- [ ] **Step 2: Write the failing test** `smartcontracts/evm/test/metatx/MetaTxBaseKat.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// KAT of the generic `MetaTransaction` digest (metatx.md "One rule, four places"): writes
/// `test/vectors/metatx_kat.json`, which the node, clientkeys and the Odoo connector read (P5). The vector is
/// `cancelNonce(uint256)` (allowlisted on every contract on `MetaTxBase`) in the token domain "SCaaS MetaToken"
/// on chain 7622 with its real `chain_uid`; `feeRecipient` is set with its flag off, so it is hashed as 0.
contract MetaTxBaseKatTest is MtxFixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    string internal constant OUT = "./test/vectors/metatx_kat.json";

    function test_metaTxKat() public {
        MtxRegistryMock tok = new MtxRegistryMock("SCaaS MetaToken", UID);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(ALICE_PK), data: abi.encodeCall(IMetaTx.cancelNonce, (42)),
            batch: 7, nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: relayer, fee: 0, feeRecipient: address(0xFEE)
        });
        bytes32 structHash = m.hashStruct();
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok), UID));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.mtxDigest(m));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);                                   // the vector really executes
        tok.mtxExecute(m, sig);
        assertEq(tok.mtxNonce(m.from, 7), 1);

        string memory k = "kat";
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATX_TYPEHASH));
        vm.serializeString(k, "domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer", vm.toString(m.from));
        string memory out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        assertEq(vm.parseJsonBytes32(onDisk, ".type_hash"), MetaTxLib.METATX_TYPEHASH);
        assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(tok));
        assertEq(vm.parseJsonBytes32(onDisk, ".struct_hash"), structHash);
        assertEq(vm.parseJsonBytes32(onDisk, ".digest"), digest);
        assertEq(vm.parseJsonBytes(onDisk, ".signature"), sig);
    }
}
```

- [ ] **Step 3: Run it — expect failure (no v3 file yet)**

```bash
cd /home/ha/work/ainative/scaas/smartcontracts/evm
../../scripts/capped forge test --match-test test_metaTxKat 2>&1 | grep -E 'FAIL|PASS'
```

Expected: `[FAIL: vm.readFile: failed to read from ".../test/vectors/metatx_kat.json": No such file or directory …]`.

- [ ] **Step 4: Generate the vector (the exact command), then check it**

```bash
WRITE_KAT=1 ../../scripts/capped forge test --match-test test_metaTxKat 2>&1 | grep -E 'FAIL|PASS'
../../scripts/capped forge test --match-test test_metaTxKat 2>&1 | grep -E 'FAIL|PASS'
cat test/vectors/metatx_kat.json
```

Expected: `[PASS] test_metaTxKat()` twice, and the file (keys sorted by forge):

```json
{
  "batch": "7",
  "chain_id": "7622",
  "data": "0xcfdd7aea000000000000000000000000000000000000000000000000000000000000002a",
  "digest": "0xc48ce070181907bf93b1f7969a4f99d85239bd9e61a99e9123440e7359660694",
  "domain_name": "SCaaS MetaToken",
  "domain_separator": "0x5308595090be14cab58d51d1a29c78dc374e4e3b21743fd647b1978298615128",
  "domain_version": "1",
  "fee": "0",
  "fee_recipient": "0x0000000000000000000000000000000000000FEE",
  "from": "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7",
  "mode": "1",
  "nonce": "0",
  "relayer": "0x000000000000000000000000000000000000bEEF",
  "salt": "0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464",
  "signature": "0x15614a77cc0728d945506eb23c7ca339d61cea682283964193c0f8aeec849d574eabfcf485537a6f00630763072eb662b452d055427013df10cce3e9bd23f0451b",
  "signer": "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7",
  "struct_hash": "0x01ca29f8f56ded33a41efc822a99d5bcf1d783ff583b72db2c90700f7a75870e",
  "type_hash": "0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888",
  "valid_until": "1800000300",
  "verifying_contract": "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
}
```

- [ ] **Step 5: Cross-check the digest without Solidity (cast)**

```bash
TH=$(cast keccak 'MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)')
DH=$(cast keccak 0xcfdd7aea000000000000000000000000000000000000000000000000000000000000002a)
SH=$(cast keccak $(cast abi-encode 'f(bytes32,address,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)' \
  $TH 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7 $DH 7 0 1800000300 1 0x000000000000000000000000000000000000bEEF 0 0x0000000000000000000000000000000000000000))
DS=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address,bytes32)' \
  $(cast keccak 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)') \
  $(cast keccak 'SCaaS MetaToken') $(cast keccak '1') 7622 \
  $(jq -r .verifying_contract test/vectors/metatx_kat.json) 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464))
echo "$SH"; cast keccak 0x1901${DS#0x}${SH#0x}
```

Expected: `0x01ca29f8f56ded33a41efc822a99d5bcf1d783ff583b72db2c90700f7a75870e` (= `struct_hash`, the fee recipient
hashed as 0 because its flag is off) and `0xc48ce070181907bf93b1f7969a4f99d85239bd9e61a99e9123440e7359660694`
(= `digest`).

- [ ] **Step 6: Full suite**

```bash
../../scripts/capped forge test 2>&1 | tail -1
git status --short test/vectors    # expected: metatx_kat.json added, metatx_v1_kat.json renamed, nothing else
```

Expected: `Ran 57 test suites …: 692 tests passed, 0 failed, 0 skipped (692 total tests)`.

- [ ] **Step 7: Commit**

```bash
cd /home/ha/work/ainative/scaas
git add smartcontracts/evm/test/vectors/metatx_kat.json smartcontracts/evm/test/vectors/metatx_v1_kat.json \
        smartcontracts/evm/test/metatx/MetaTxBaseKat.t.sol smartcontracts/evm/test/MetaTxKat.t.sol \
        smartcontracts/evm/test/v2/BaseKat.t.sol scaas-node/src/metatx.rs scaas-node/tests/mesh_vectors.rs \
        clients/clientkeys/test/evm.test.js
git commit -m "$(cat <<'EOF'
test(evm): metatx_kat.json is the v3 MetaTransaction KAT; v1 vector -> metatx_v1_kat.json

Salted domain, cancelNonce(42) on lane 7, relayer bound, unbound fee
recipient hashed as 0; regenerate with WRITE_KAT=1 forge test --match-test
test_metaTxKat. Node and clientkeys keep reading the v1 file until P5.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Gate — full suite, both profiles, size check, Transitional notes

**Files:**
- Modify: `docs/contracts/metatx.md` (Transitional (BUILT): "Signature checks", "Structs", "Tests" bullets)

**Interfaces:**
- Consumes: everything above.
- Produces: the P1a gate result (sizes recorded for P1b's budget).

- [ ] **Step 1: Full forge suite (default profile) and the CI build profile**

```bash
cd /home/ha/work/ainative/scaas/smartcontracts/evm
../../scripts/capped forge test 2>&1 | tail -1
FOUNDRY_PROFILE=private7622 ../../scripts/capped forge build 2>&1 | grep -E '^Error' ; echo "exit=${PIPESTATUS[0]}"
```

Expected: `692 tests passed, 0 failed, 0 skipped`; no `Error` line, `exit=0`.

- [ ] **Step 2: Size gate**

```bash
../../scripts/capped forge build --sizes --json 2>/dev/null > /tmp/p1a-sizes-after.json
jq -r 'to_entries[] | select(.value.runtime_size > 24576) | .key' /tmp/p1a-sizes-after.json
jq -r '.MtxRegistryMock.runtime_size' /tmp/p1a-sizes-after.json
jq -r --slurpfile b /tmp/p1a-sizes-before.json 'to_entries[] | select($b[0][.key] != null and .value.runtime_size > $b[0][.key].runtime_size) | "\(.key) \($b[0][.key].runtime_size) -> \(.value.runtime_size)"' /tmp/p1a-sizes-after.json
```

Expected: first command prints only `ZetherToken` (pre-existing, P3); second prints `9410` (≤ 20,480: the
`MetaTxBase` overhead a P1b token starts from — record it in the P1b plan); third prints nothing (no built contract
grew; `SigCheck` shrinks the bases by ≈ 100 B each).

- [ ] **Step 3: Update the Transitional (BUILT) notes in `docs/contracts/metatx.md`**

Replace the "Signature checks" bullet

```markdown
- **Signature checks** ([CTR-MTX-25](#CTR-MTX-25)). Built: the check is repeated in `ERC20MetaTx`, `MetaTxCore`,
  `ZetherMetaTx`, `OrderBookDex`, `MandateWallet` and `SmartKeyAccount`, the HIP-632 override four times, and `SigLib` has
  no importer; one `SigCheck` replaces them in P1.
```

with

```markdown
- **Signature checks** ([CTR-MTX-25](#CTR-MTX-25)). Built (P1a): `SigCheck` serves `MetaTxBase` and the built bases
  `ERC20MetaTx`, `MetaTxCore`, `ZetherMetaTx`; `SigLib` is deleted. `OrderBookDex`, `MandateWallet` and
  `SmartKeyAccount` keep their own checks until P2/P4, and the HIP-632 override stays in the four Hedera children
  until P1c.
```

In the "Structs" bullet replace

```markdown
  (`data = pay(bytes32)`) and the ops below; there is no `MetaTransfer`, no `mtxExecuteTransfer`/`mtxBatchTransfer`
  and no `MetaTxBase`: `MandateWallet` and `SmartKeyAccount` verify their own typed structs (`PayUnderMandate`,
  `RevokeMandate`, `OwnerCall`) with their own nonces.
```

with

```markdown
  (`data = pay(bytes32)`) and the ops below, named `MetaTxLib.LegacyMetaTransaction` since P1a (typehash unchanged,
  vector `metatx_v1_kat.json`); there is no `MetaTransfer` and no `mtxExecuteTransfer`/`mtxBatchTransfer`.
  `MetaTxBase` with the v3 `MetaTransaction` is built (P1a) but no token or account sits on it yet: `MandateWallet` and
  `SmartKeyAccount` verify their own typed structs (`PayUnderMandate`, `RevokeMandate`, `OwnerCall`) with their own
  nonces.
```

In the "Tests" bullet replace `` the v2 KAT `` with `` the v1 KAT `test/vectors/metatx_v1_kat.json`, the v2 KAT ``.

```bash
cd /home/ha/work/ainative/scaas
python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check 2>&1 | tail -1
```

Expected: tests OK; `check: 0 error(s), …`.

- [ ] **Step 4: Commit**

```bash
git add docs/contracts/metatx.md
git status --short     # expected: nothing else modified
git commit -m "$(cat <<'EOF'
docs(metatx): Transitional notes after P1a (SigCheck, LegacyMetaTransaction, MetaTxBase built)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Hand-off note** — report: test count 692 (57 suites), `MtxRegistryMock` runtime 9,410 B, the Odoo
  reader of `metatx_kat.json` (out of repo) to repoint, and that P1b starts by `git mv src/metatx/MetaTxCore.sol
  src/metatx/ERC20MetaTx.sol` after deleting the v1 `ERC20MetaTx.sol`.
