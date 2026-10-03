# Contracts + DEX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cloneable `MetaToken` v1 (standalone + 1:1 wrapper, `pay`/`trade` ops), `OpenFactory` implementing `IOpenFactory`, and `MetaTxDex` (atomic two-leg settlement, no allowance), with fuzz/invariant tests, a cross-language digest KAT and a deploy script.

**Architecture:** Everything builds on the existing `ERC20MetaTx` mixin (9-step pipeline, already gas-measured). Ops are selector-tagged `data` inside the pinned `MetaTransaction` struct — no new typehash. Tokens are EIP-1167 clones initialised atomically by the factory. The DEX executes two `trade` legs whose signatures restrict the relayer to the DEX itself.

**Tech Stack:** Solidity 0.8.28, Foundry (forge 1.3.5), OpenZeppelin 5.2 (`lib/` copied from main checkout, gitignored).

**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` §2, §6, §9, §10.

## Global Constraints

- Solidity `^0.8.20`, compiler pinned `0.8.28` by `foundry.toml`; default profile EVM = cancun (TSTORE used); `private9000` = prague.
- `MetaTxLib.METATX_TYPEHASH` and the struct MUST NOT change (`test_metaTxTypehashIsPinned` stays green, untouched).
- No upgrade path anywhere: no proxy other than EIP-1167 clones, no owner, no pause, no sweep.
- No `CALL` to a foreign contract inside a token's meta-tx path (canon §C8.5).
- Fee denominator ppm, hard cap 1% (`FeePolicy`, unchanged).
- EIP-712 domain of every v1 clone: name `"Bamboo MetaToken"`, version `"1"`, `verifyingContract = clone`.
- Op selectors: `OP_PAY = bytes4(keccak256("pay(bytes32)"))`, `OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"))`.
- Comments in the style of the surrounding code (Vietnamese prose, English identifiers).

## Review Focus

- A `data` shorter than 4 bytes must revert cleanly with `MetaTxUnknownOp(0)`, not panic on slicing — pinned in Task 2.
- Two signatures for the same payment lane (same `batch`, nonce 0, different `validUntil`) — only one may ever execute (spec §5 guarantee 2) — pinned in Task 2.
- A wrapper whose underlying charges a transfer fee must mint only what it actually received — pinned in Task 3.
- A `trade` leg leaked to the public must not be executable by anyone but the DEX — pinned in Task 5.
- A DEX leg with a fee and `feeRecipient == 0` would strand the fee inside the DEX — pinned in Task 5.

## File Structure

| File | Responsibility |
|---|---|
| `smartcontracts/src/metatx/ERC20MetaTx.sol` (modify) | `_executeOp` receives `(feeAmount, feeRecipient)` |
| `smartcontracts/src/factory/IFactoryToken.sol` | the one function the factory calls on any implementation |
| `smartcontracts/src/metatx/MetaToken.sol` | v1 META implementation: init, metadata, mint, wrap/unwrap, `pay`/`trade` ops, `payWithFee` |
| `smartcontracts/src/factory/OpenFactory.sol` | `IOpenFactory` |
| `smartcontracts/src/dex/MetaTxDex.sol` | `settle(Leg, Leg)` |
| `smartcontracts/test/helpers/Fixtures.sol` | deploy factory+impl, create tokens, build/sign meta-tx |
| `smartcontracts/test/helpers/Mocks.sol` | plain ERC20, fee-on-transfer ERC20, verifier mocks, Zether impl mock |
| `smartcontracts/test/MetaToken.t.sol`, `OpenFactory.t.sol`, `MetaTxDex.t.sol`, `Invariants.t.sol`, `MetaTxKat.t.sol` | tests |
| `smartcontracts/test/vectors/metatx_kat.json` | generated KAT read by Python and Rust |
| `smartcontracts/script/Deploy.s.sol` | deploy + write `deployments/<chainid>.json` |
| `smartcontracts/foundry.toml` (modify) | `fs_permissions` for vectors + deployments |

---

### Task 1: `IFactoryToken`, `_executeOp` fee args, `MetaToken` init + metadata + standalone mint

**Files:**
- Create: `smartcontracts/src/factory/IFactoryToken.sol`, `smartcontracts/src/metatx/MetaToken.sol`, `smartcontracts/src/factory/OpenFactory.sol` (minimal: register + createMetaToken — completed in Task 4), `smartcontracts/test/helpers/Fixtures.sol`, `smartcontracts/test/helpers/Mocks.sol`, `smartcontracts/test/MetaToken.t.sol`
- Modify: `smartcontracts/src/metatx/ERC20MetaTx.sol` (`_executeOp` signature + call site)

**Interfaces:**
- Produces: `IFactoryToken.initialize(address creator, address underlying, address verifier, uint64 version, bytes initData)`; `MetaToken(address factory_)`; `initData = abi.encode(string name, string symbol, uint8 decimals, uint256 initialSupply, address minter)`; `MetaToken.mint(address,uint256)`; provenance getters `factory() creator() underlying() verifier() implementation() version() minter()`.

- [ ] **Step 1: Write the failing tests** — `test/helpers/Mocks.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";

contract MockERC20 is ERC20 {
    uint8 private immutable _d;
    constructor(string memory n, string memory s, uint8 d) ERC20(n, s) { _d = d; }
    function decimals() public view override returns (uint8) { return _d; }
    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Đốt 1% mỗi lần chuyển: wrapper phải mint theo số THỰC nhận, không theo số yêu cầu.
contract FeeOnTransferERC20 is MockERC20 {
    constructor() MockERC20("Fee", "FEE", 18) {}
    function _update(address from, address to, uint256 v) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 burnt = v / 100;
            super._update(from, address(0), burnt);
            v -= burnt;
        }
        super._update(from, to, v);
    }
}

contract SupportedVerifier {
    function isSupportedOnThisChain() external pure returns (bool) { return true; }
    function curveName() external pure returns (string memory) { return "bn254"; }
}

contract UnsupportedVerifier {
    function isSupportedOnThisChain() external pure returns (bool) { return false; }
    function curveName() external pure returns (string memory) { return "bls12-381"; }
}

/// Implementation ZETHER giả: chỉ để chứng minh factory xử lý kind ZETHER qua cùng
/// `IFactoryToken`. Không có gì bảo mật ở đây.
contract MockZetherImpl is IFactoryToken {
    address public immutable FACTORY;
    address public verifier;
    bool private _done;
    constructor(address f) { FACTORY = f; _done = true; }
    function initialize(address, address, address verifier_, uint64, bytes calldata) external {
        require(msg.sender == FACTORY && !_done, "init");
        _done = true;
        verifier = verifier_;
    }
}
```

`test/helpers/Fixtures.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

abstract contract Fixtures is Test {
    OpenFactory internal factory;
    MetaToken internal impl;
    address internal registrar = address(0xF00D);
    address internal relayer = address(0xBEEF);

    function _deployFactory() internal {
        factory = new OpenFactory(registrar);
        impl = new MetaToken(address(factory));
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
    }

    function _standalone(address creator, string memory sym, uint8 dec, uint256 supply, address minter)
        internal returns (MetaToken t)
    {
        bytes memory init = abi.encode(string.concat("Token ", sym), sym, dec, supply, minter);
        vm.prank(creator);
        t = MetaToken(factory.createMetaToken(1, address(0), init, keccak256(bytes(sym))));
    }

    function _wrapper(address creator, address underlying, string memory sym) internal returns (MetaToken t) {
        bytes memory init = abi.encode(string.concat("Wrapped ", sym), sym, uint8(0), uint256(0), address(0));
        vm.prank(creator);
        t = MetaToken(factory.createMetaToken(1, underlying, init, keccak256(bytes(sym))));
    }

    function _mt(address from, address to, uint256 value, bytes memory data, uint256 batch, uint32 mode)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: from, to: to, value: value, data: data, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer,
            fee: 0, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, MetaToken t, MetaTxLib.MetaTransaction memory m)
        internal view returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _payData(bytes32 ref) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref);
    }

    function _tradeData(address counterToken, uint256 minCounter, address counterparty)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSelector(
            bytes4(keccak256("trade(address,uint256,address)")), counterToken, minCounter, counterparty);
    }
}
```

`test/MetaToken.t.sol` (Task 1 part):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MockERC20, FeeOnTransferERC20} from "./helpers/Mocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../src/metatx/IERC20Payment.sol";
import {FeeMode} from "../src/common/FeePolicy.sol";

contract MetaTokenTest is Fixtures {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice;
    address shop = address(0x5409);
    address minterAddr = address(0x313);
    MetaToken tok;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(ALICE_PK);
        _deployFactory();
        tok = _standalone(address(this), "BUSD", 6, 1_000_000e6, minterAddr);
        tok.transfer(alice, 1_000e6);
    }

    // ---- Task 1: init, metadata, provenance, mint ----

    function test_implementationIsLockedAtConstruction() public {
        vm.prank(address(factory));
        vm.expectRevert(MetaToken.AlreadyInitialized.selector);
        impl.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_onlyFactoryInitializes() public {
        vm.expectRevert(MetaToken.NotFactory.selector);
        tok.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_cloneInitializesOnce() public {
        vm.prank(address(factory));
        vm.expectRevert(MetaToken.AlreadyInitialized.selector);
        tok.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_metadataIsPerClone() public {
        MetaToken other = _standalone(address(this), "PTS", 0, 5, address(0));
        assertEq(tok.name(), "Token BUSD");
        assertEq(tok.symbol(), "BUSD");
        assertEq(tok.decimals(), 6);
        assertEq(other.symbol(), "PTS");
        assertEq(other.decimals(), 0);
    }

    function test_provenance() public view {
        assertEq(tok.factory(), address(factory));
        assertEq(tok.creator(), address(this));
        assertEq(tok.implementation(), address(impl));
        assertEq(tok.version(), 1);
        assertEq(tok.underlying(), address(0));
        assertEq(tok.verifier(), address(0));
        assertEq(tok.minter(), minterAddr);
    }

    function test_domainIsImplementationNameAndCloneAddress() public view {
        (, string memory n, string memory v, uint256 cid, address vc,,) = tok.eip712Domain();
        assertEq(n, "Bamboo MetaToken");
        assertEq(v, "1");
        assertEq(cid, block.chainid);
        assertEq(vc, address(tok));
    }

    function test_initialSupplyGoesToCreatorAndMinterMints() public {
        assertEq(tok.totalSupply(), 1_000_000e6);
        vm.prank(minterAddr);
        tok.mint(shop, 7);
        assertEq(tok.balanceOf(shop), 7);
    }

    function test_nonMinterCannotMint() public {
        vm.expectRevert(MetaToken.NotMinter.selector);
        tok.mint(shop, 7);
    }

    function test_zeroMinterMeansFixedSupply() public {
        MetaToken fixedTok = _standalone(address(this), "FIX", 0, 10, address(0));
        vm.prank(address(0));
        vm.expectRevert(MetaToken.NotMinter.selector);
        fixedTok.mint(shop, 1);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest`
Expected: compile error — `MetaToken`, `OpenFactory`, `IFactoryToken` not found.

- [ ] **Step 3: Implement**

`src/factory/IFactoryToken.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Hợp đồng giữa `OpenFactory` và MỌI implementation, kể cả kind ZETHER.
/// @notice Một hàm. Factory gọi nó trong CÙNG lời gọi với `CREATE2` (01-token-factory
///         §1.4.3 lớp 1), và implementation phải từ chối mọi người gọi khác factory
///         (lớp 2). Tham số per-token chỉ có đúng một đường đến: ở đây.
interface IFactoryToken {
    function initialize(
        address creator,
        address underlying,
        address verifier,
        uint64 version,
        bytes calldata initData
    ) external;
}
```

`src/metatx/ERC20MetaTx.sol` — two edits. Call site in `executeMetaTransaction`:

```solidity
        // --- 8. thực thi ---
        _executeOp(m, feeAmount, feeRecipient);
```

and the hook:

```solidity
    /// @dev Bước 8. Không được fail — mọi điều kiện đã kiểm ở `_checkOp`. Nhận phí đã
    ///      thu để op nào cần báo phí trong event (`pay`) không phải tính lại.
    function _executeOp(MetaTxLib.MetaTransaction calldata m, uint256, address) internal virtual {
        _transfer(m.from, m.to, m.value);
    }
```

`src/metatx/MetaToken.sol` (Task 1 subset — ops and wrapper are added in Tasks 2–3; the full file after Task 3 is shown there):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";

/// @title MetaToken v1 — implementation của kind META, deploy bằng clone EIP-1167.
contract MetaToken is ERC20MetaTx, IFactoryToken {
    address public immutable FACTORY;
    address private immutable _SELF;

    bool private _initialized;
    string private _tokenName;
    string private _tokenSymbol;
    uint8 private _tokenDecimals;

    address public creator;
    address public underlying;
    address public minter;
    uint64 public version;

    error NotFactory();
    error AlreadyInitialized();
    error VerifierNotAllowed();
    error WrapperHasNoMint();
    error NotMinter();

    /// @dev Constructor chạy MỘT lần, trên implementation. Immutable của nó đúng cho mọi
    ///      clone; storage của nó thì không — nên khoá luôn implementation để không ai
    ///      `initialize` được chính nó (01-token-factory §1.3.5 mục 1).
    constructor(address factory_) ERC20("", "") EIP712("Bamboo MetaToken", "1") {
        FACTORY = factory_;
        _SELF = address(this);
        _initialized = true;
    }

    function initialize(
        address creator_,
        address underlying_,
        address verifier_,
        uint64 version_,
        bytes calldata initData
    ) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        if (verifier_ != address(0)) revert VerifierNotAllowed();
        _initialized = true;
        (string memory n, string memory s, uint8 d, uint256 supply, address minter_) =
            abi.decode(initData, (string, string, uint8, uint256, address));
        creator = creator_;
        underlying = underlying_;
        version = version_;
        _tokenName = n;
        _tokenSymbol = s;
        if (underlying_ == address(0)) {
            _tokenDecimals = d;
            minter = minter_;
            if (supply != 0) _mint(creator_, supply);
        } else {
            // Tầng 2: cung CHỈ đến từ wrap, nếu không bất biến dự trữ không giữ được.
            if (supply != 0 || minter_ != address(0)) revert WrapperHasNoMint();
            _tokenDecimals = ERC20(underlying_).decimals();
        }
    }

    function name() public view override returns (string memory) { return _tokenName; }
    function symbol() public view override returns (string memory) { return _tokenSymbol; }
    function decimals() public view override returns (uint8) { return _tokenDecimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function verifier() external pure returns (address) { return address(0); }

    /// @notice Tầng 1 thôi. `minter == 0` ⇒ cung cố định (msg.sender không bao giờ là 0).
    function mint(address to, uint256 amount) external {
        if (msg.sender != minter) revert NotMinter();
        _mint(to, amount);
    }
}
```

`src/factory/OpenFactory.sol` — minimal version so the fixture compiles (finished in Task 4):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {IOpenFactory} from "../common/IOpenFactory.sol";

abstract contract OpenFactoryBase is IOpenFactory {
    address public immutable registrar;
    mapping(TokenKind => mapping(uint64 => address)) internal _impl;

    error NotRegistrar();

    constructor(address registrar_) { registrar = registrar_; }

    function registerImplementation(TokenKind kind, uint64 version, address implementation) public virtual {
        if (msg.sender != registrar) revert NotRegistrar();
        _impl[kind][version] = implementation;
    }

    function createMetaToken(uint64 version, address underlying, bytes calldata initData, bytes32 salt)
        public virtual returns (address token)
    {
        token = Clones.cloneDeterministic(_impl[TokenKind.META][version], keccak256(abi.encode(msg.sender, salt)));
        IFactoryToken(token).initialize(msg.sender, underlying, address(0), version, initData);
    }
}
```

Note: Task 1 ships `OpenFactory` as the complete contract from Task 4 if implementing in one sitting is simpler; the split above only exists so Task 1 is reviewable alone. When executing natively, write the Task 4 file directly and run Task 1's tests against it.

- [ ] **Step 4: Run to verify it passes**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest && forge test --match-contract MetaTxGasTest`
Expected: all Task 1 tests PASS; gas tests still PASS (envelope unchanged).

- [ ] **Step 5: Commit**

```bash
git add smartcontracts/src smartcontracts/test
git commit -m "feat(contracts): MetaToken v1 clone init, metadata and standalone mint"
```

---

### Task 2: `pay` and `trade` ops, `payWithFee`

**Files:**
- Modify: `smartcontracts/src/metatx/MetaToken.sol`
- Test: `smartcontracts/test/MetaToken.t.sol`

**Interfaces:**
- Consumes: Task 1 fixture helpers `_mt`, `_sign`, `_payData`, `_tradeData`.
- Produces: `MetaToken.OP_PAY`, `MetaToken.OP_TRADE`; errors `MetaTxUnknownOp(bytes4)`, `PayToZero()`, `TradeLegNotRestricted()`; event `IERC20Payment.PaymentSettled(from,to,amount,feeAmount,feeRecipient,entryRef)`.

- [ ] **Step 1: Write the failing tests** — append to `MetaTokenTest`:

```solidity
    // ---- Task 2: ops ----

    bytes32 constant REF = keccak256("order-42");
    uint256 constant LANE = uint256(keccak256("lane"));

    function _exec(MetaTxLib.MetaTransaction memory m) internal {
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
    }

    function test_payEmitsPaymentSettled() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 250e6, _payData(REF), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        vm.expectEmit(address(tok));
        emit IERC20Payment.PaymentSettled(alice, shop, 250e6, 0, relayer, REF);
        _exec(m);
        assertEq(tok.balanceOf(shop), 250e6);
        assertEq(tok.balanceOf(alice), 750e6);
    }

    function test_payReportsTheFeeActuallyCharged() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 100e6, _payData(REF), LANE,
            MetaTxLib.MODE_FEE_FIXED);
        m.fee = 1e6;
        m.feeRecipient = relayer;
        vm.expectEmit(address(tok));
        emit IERC20Payment.PaymentSettled(alice, shop, 100e6, 1e6, relayer, REF);
        _exec(m);
        assertEq(tok.balanceOf(relayer), 1e6);
        assertEq(tok.balanceOf(alice), 899e6);
    }

    function test_payLaneExecutesAtMostOnce() public {
        MetaTxLib.MetaTransaction memory m1 = _mt(alice, shop, 10e6, _payData(REF), LANE, 0);
        MetaTxLib.MetaTransaction memory m2 = _mt(alice, shop, 10e6, _payData(REF), LANE, 0);
        m2.validUntil = m1.validUntil + 60;            // second signature, same lane
        bytes memory s2 = _sign(ALICE_PK, tok, m2);
        _exec(m1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxBadNonce.selector, 1, 0));
        tok.executeMetaTransaction(m2, s2);
        assertEq(tok.balanceOf(shop), 10e6);
    }

    function test_payAfterExpiryIsRefused() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 1, _payData(REF), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.warp(m.validUntil + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxExpired.selector, m.validUntil, block.timestamp));
        tok.executeMetaTransaction(m, sig);
    }

    function test_payToZeroIsRefused() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, address(0), 1, _payData(REF), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.PayToZero.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_payWithWrongLengthIsUnknownOp() public {
        bytes memory bad = abi.encodePacked(bytes4(keccak256("pay(bytes32)")), bytes31(0));
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 1, bad, LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(keccak256("pay(bytes32)"))));
        tok.executeMetaTransaction(m, sig);
    }

    function test_shortDataIsUnknownOpNotPanic() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 1, hex"01", LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(0)));
        tok.executeMetaTransaction(m, sig);
    }

    function test_unknownSelectorIsRefused() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 1, hex"deadbeef", LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(0xdeadbeef)));
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeNeedsRestrictedRelayer() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, relayer, 1, _tradeData(address(9), 1, address(0)), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.TradeLegNotRestricted.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeProceedsGoOnlyToTheExecutor() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, 1, _tradeData(address(9), 1, address(0)), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.TradeLegNotRestricted.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeMovesToExecutor() public {
        MetaTxLib.MetaTransaction memory m = _mt(alice, relayer, 5e6, _tradeData(address(9), 1, address(0)), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        _exec(m);
        assertEq(tok.balanceOf(relayer), 5e6);
    }

    function test_payWithFeeDirectPath() public {
        vm.prank(alice);
        vm.expectEmit(address(tok));
        emit IERC20Payment.PaymentSettled(alice, shop, 100e6, 1e6, relayer, REF);
        tok.payWithFee(shop, 100e6, FeeMode.FIXED, 1e6, relayer, REF);
        assertEq(tok.balanceOf(shop), 100e6);
        assertEq(tok.balanceOf(relayer), 1e6);
    }

    function testFuzz_payConservesSupply(uint96 value, uint16 feePpm) public {
        value = uint96(bound(value, 1, 1_000e6));
        feePpm = uint16(bound(feePpm, 0, 10_000));
        MetaTxLib.MetaTransaction memory m = _mt(alice, shop, value, _payData(REF), LANE, MetaTxLib.MODE_FEE_PERCENT);
        m.fee = feePpm;
        m.feeRecipient = relayer;
        uint256 fee = uint256(value) * feePpm / 1_000_000;
        if (uint256(value) + fee > tok.balanceOf(alice)) return;
        uint256 supply = tok.totalSupply();
        _exec(m);
        assertEq(tok.totalSupply(), supply);
        assertEq(tok.balanceOf(shop), value);
        assertEq(tok.balanceOf(relayer), fee);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest`
Expected: compile errors — `PayToZero`, `MetaTxUnknownOp`, `TradeLegNotRestricted`, `payWithFee` undefined.

- [ ] **Step 3: Implement** — in `MetaToken.sol` change the contract line and add:

```solidity
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {IERC20Payment} from "./IERC20Payment.sol";

contract MetaToken is ERC20MetaTx, IERC20Payment, IFactoryToken {
    /// @dev Op là `data` có tag selector, nằm TRONG struct đã ghim — không typehash thứ
    ///      hai, ví hiển thị một loại giao dịch (ruling R2).
    bytes4 public constant OP_PAY = bytes4(keccak256("pay(bytes32)"));
    bytes4 public constant OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"));

    error MetaTxUnknownOp(bytes4 op);
    error PayToZero();
    error TradeLegNotRestricted();

    /// @dev Bước 6. Mọi thứ fail được thì fail ở đây, TRƯỚC khi thu phí.
    function _checkOp(MetaTxLib.MetaTransaction calldata m) internal view override {
        uint256 len = m.data.length;
        if (len == 0) return;
        if (len < 4) revert MetaTxUnknownOp(bytes4(0));
        bytes4 op = bytes4(m.data[:4]);
        if (op == OP_PAY) {
            if (len != 36) revert MetaTxUnknownOp(op);
            if (m.to == address(0)) revert PayToZero();
            return;
        }
        if (op == OP_TRADE) {
            if (len != 100) revert MetaTxUnknownOp(op);
            // Chân lệnh chỉ thực thi được bởi đúng contract khớp lệnh mà người ký đã
            // chọn, và tiền chỉ đi VÀO chính contract đó. Lệnh bị lộ thì vô dụng với
            // mọi người khác.
            if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || m.to != msg.sender) {
                revert TradeLegNotRestricted();
            }
            return;
        }
        revert MetaTxUnknownOp(op);
    }

    /// @dev Bước 8. Ba op cùng một chuyển; chỉ `pay` thêm event đối soát.
    function _executeOp(MetaTxLib.MetaTransaction calldata m, uint256 feeAmount, address feeRecipient)
        internal override
    {
        _transfer(m.from, m.to, m.value);
        if (m.data.length == 36 && bytes4(m.data[:4]) == OP_PAY) {
            emit PaymentSettled(m.from, m.to, m.value, feeAmount, feeRecipient, bytes32(m.data[4:36]));
        }
    }

    /// @notice Đường gọi thẳng: `msg.sender` tự trả gas, phí thu THÊM, `amount` nguyên vẹn.
    function payWithFee(
        address to,
        uint256 amount,
        FeeMode feeMode,
        uint256 fee,
        address feeRecipient,
        bytes32 entryRef
    ) external returns (bool) {
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) _transfer(msg.sender, feeRecipient, feeAmount);
        _transfer(msg.sender, to, amount);
        emit PaymentSettled(msg.sender, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest`
Expected: PASS (fuzz 256 runs).

- [ ] **Step 5: Commit**

```bash
git add smartcontracts/src/metatx/MetaToken.sol smartcontracts/test/MetaToken.t.sol
git commit -m "feat(contracts): pay and trade ops on MetaToken, direct payWithFee"
```

---

### Task 3: Tier-2 wrapper (`wrap`/`unwrap`)

**Files:**
- Modify: `smartcontracts/src/metatx/MetaToken.sol`
- Test: `smartcontracts/test/MetaToken.t.sol`

**Interfaces:**
- Produces: `MetaToken.wrap(uint256 amount) returns (uint256 minted)`, `MetaToken.unwrap(uint256 amount, address recipient)`, error `NotAWrapper()`.

- [ ] **Step 1: Write the failing tests** — append:

```solidity
    // ---- Task 3: wrapper ----

    function test_wrapperTakesDecimalsFromUnderlyingAndRefusesMint() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        MetaToken w = _wrapper(address(this), address(usdc), "wUSDC");
        assertEq(w.decimals(), 6);
        assertEq(w.minter(), address(0));
        bytes memory bad = abi.encode("x", "x", uint8(0), uint256(1), address(0));
        vm.expectRevert(MetaToken.WrapperHasNoMint.selector);
        factory.createMetaToken(1, address(usdc), bad, bytes32("bad"));
    }

    function test_wrapAndUnwrapRoundTrip() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        MetaToken w = _wrapper(address(this), address(usdc), "wUSDC");
        usdc.mint(alice, 100e6);
        vm.startPrank(alice);
        usdc.approve(address(w), 100e6);
        assertEq(w.wrap(100e6), 100e6);
        w.unwrap(40e6, shop);
        vm.stopPrank();
        assertEq(w.balanceOf(alice), 60e6);
        assertEq(usdc.balanceOf(shop), 40e6);
        assertEq(usdc.balanceOf(address(w)), w.totalSupply());
    }

    function test_wrapMintsWhatActuallyArrived() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        MetaToken w = _wrapper(address(this), address(fot), "wFEE");
        fot.mint(alice, 1000);
        vm.startPrank(alice);
        fot.approve(address(w), 1000);
        uint256 minted = w.wrap(1000);
        vm.stopPrank();
        assertEq(minted, 990);
        assertEq(w.balanceOf(alice), 990);
        assertGe(fot.balanceOf(address(w)), w.totalSupply());
    }

    function test_wrapOnStandaloneReverts() public {
        vm.expectRevert(MetaToken.NotAWrapper.selector);
        tok.wrap(1);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest`
Expected: compile error — `wrap`, `unwrap`, `NotAWrapper` undefined.

- [ ] **Step 3: Implement** — add to `MetaToken.sol`:

```solidity
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// inside the contract:
    using SafeERC20 for IERC20;
    error NotAWrapper();

    /// @notice Tầng 2. Mint đúng phần THỰC nhận (token phí-chuyển), để
    ///         `underlying.balanceOf(this) >= totalSupply` không bao giờ vỡ.
    function wrap(uint256 amount) external nonReentrant returns (uint256 minted) {
        address u = underlying;
        if (u == address(0)) revert NotAWrapper();
        uint256 before = IERC20(u).balanceOf(address(this));
        IERC20(u).safeTransferFrom(msg.sender, address(this), amount);
        minted = IERC20(u).balanceOf(address(this)) - before;
        _mint(msg.sender, minted);
    }

    function unwrap(uint256 amount, address recipient) external nonReentrant {
        address u = underlying;
        if (u == address(0)) revert NotAWrapper();
        _burn(msg.sender, amount);
        IERC20(u).safeTransfer(recipient, amount);
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd smartcontracts && forge test --match-contract MetaTokenTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add smartcontracts/src/metatx/MetaToken.sol smartcontracts/test/MetaToken.t.sol
git commit -m "feat(contracts): tier-2 wrapper minting the received delta"
```

---

### Task 4: `OpenFactory` (full `IOpenFactory`)

**Files:**
- Modify (replace): `smartcontracts/src/factory/OpenFactory.sol`
- Test: `smartcontracts/test/OpenFactory.t.sol`

**Interfaces:**
- Consumes: `IFactoryToken`, `IOpenFactory`, mocks `SupportedVerifier`, `UnsupportedVerifier`, `MockZetherImpl`.
- Produces: `OpenFactory(address registrar)`, effective salt `keccak256(abi.encode(creator, salt))`, error `NotRegistrar()`.

- [ ] **Step 1: Write the failing tests** — `test/OpenFactory.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {SupportedVerifier, UnsupportedVerifier, MockZetherImpl, MockERC20} from "./helpers/Mocks.sol";
import {IOpenFactory} from "../src/common/IOpenFactory.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";

contract OpenFactoryTest is Fixtures {
    IOpenFactory.TokenKind constant META = IOpenFactory.TokenKind.META;
    IOpenFactory.TokenKind constant ZETHER = IOpenFactory.TokenKind.ZETHER;
    bytes init = abi.encode("Points", "PTS", uint8(0), uint256(100), address(0));

    function setUp() public { _deployFactory(); }

    function test_onlyRegistrarRegisters() public {
        vm.expectRevert(OpenFactory.NotRegistrar.selector);
        factory.registerImplementation(META, 2, address(impl));
    }

    function test_catalogueIsAppendOnly() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionAlreadyRegistered.selector, META, 1, address(impl)));
        factory.registerImplementation(META, 1, address(0x1234));
    }

    function test_versionZeroIsReservedForUnregistered() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, META, 0));
        factory.registerImplementation(META, 0, address(impl));
    }

    function test_implementationMustHaveCode() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationNotAContract.selector, address(0x1234)));
        factory.registerImplementation(META, 2, address(0x1234));
    }

    function test_deprecateMarksButDoesNotBlock() public {
        vm.prank(registrar);
        factory.deprecate(META, 1, "bug #1");
        assertTrue(factory.isDeprecated(META, 1));
        address t = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertTrue(factory.isDeployedHere(t));
    }

    function test_unknownVersionReverts() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, META, 9));
        factory.createMetaToken(9, address(0), init, bytes32("s"));
    }

    function test_predictMatchesDeployedAndProvenanceIsRecorded() public {
        address predicted = factory.predictAddress(address(impl), address(this), bytes32("s"));
        address t = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertEq(t, predicted);
        assertEq(factory.creatorOf(t), address(this));
        (IOpenFactory.TokenKind k, uint64 v) = factory.versionOf(t);
        assertEq(uint8(k), uint8(META));
        assertEq(v, 1);
        assertEq(factory.latestVersion(META), 1);
        assertEq(factory.implementationOf(META, 1), address(impl));
    }

    function test_saltIsScopedByCreator() public {
        address a = factory.createMetaToken(1, address(0), init, bytes32("s"));
        vm.prank(address(0xB0B));
        address b = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertTrue(a != b);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, a));
        factory.createMetaToken(1, address(0), init, bytes32("s"));
    }

    function test_wrapperLookupIsPerCreator() public {
        MockERC20 dai = new MockERC20("Dai", "DAI", 18);
        bytes memory w = abi.encode("zDAI", "zDAI", uint8(0), uint256(0), address(0));
        address a1 = factory.createMetaToken(1, address(dai), w, bytes32("1"));
        address a2 = factory.createMetaToken(1, address(dai), w, bytes32("2"));
        vm.prank(address(0xB0B));
        address b1 = factory.createMetaToken(1, address(dai), w, bytes32("1"));
        assertEq(factory.getWrapper(address(this), address(dai)), a1);
        assertEq(factory.getWrapperCount(address(this), address(dai)), 2);
        assertEq(factory.getWrapperAt(address(this), address(dai), 1), a2);
        assertEq(factory.getWrapper(address(0xB0B), address(dai)), b1);
        assertEq(factory.getWrapper(address(0xC0C), address(dai)), address(0));
        assertEq(factory.deployCountFor(address(dai)), 3);
        assertEq(factory.deployedFor(address(dai), 2), b1);
    }

    function test_createUnregisteredIsVersionZero() public {
        address t = factory.createUnregistered(META, address(impl), address(0), address(0), init, bytes32("u"));
        (, uint64 v) = factory.versionOf(t);
        assertEq(v, 0);
        assertEq(MetaToken(t).version(), 0);
    }

    function test_createUnregisteredNeedsCode() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationNotAContract.selector, address(0x77)));
        factory.createUnregistered(META, address(0x77), address(0), address(0), init, bytes32("u"));
    }

    function test_zetherNeedsAVerifier() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        vm.expectRevert(IOpenFactory.VerifierRequiredForZether.selector);
        factory.createZetherToken(1, address(0), address(0), "", bytes32("z"));
    }

    function test_zetherRefusesAVerifierThisChainCannotRun() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        UnsupportedVerifier bad = new UnsupportedVerifier();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        vm.expectRevert(abi.encodeWithSelector(
            IOpenFactory.VerifierUnsupportedOnThisChain.selector, address(bad), "bls12-381"));
        factory.createZetherToken(1, address(0), address(bad), "", bytes32("z"));
    }

    function test_zetherWithSupportedVerifier() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        SupportedVerifier ok = new SupportedVerifier();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        address t = factory.createZetherToken(1, address(0), address(ok), "", bytes32("z"));
        assertEq(MockZetherImpl(t).verifier(), address(ok));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd smartcontracts && forge test --match-contract OpenFactoryTest`
Expected: compile error (`OpenFactory` is abstract / missing members).

- [ ] **Step 3: Implement** — replace `src/factory/OpenFactory.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "../common/IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {IZetherVerifier} from "../zether/IZetherVerifier.sol";

/// @title Factory mở — hiện thực `IOpenFactory`. Đọc docstring của interface trước.
/// @notice Catalogue là DANH MỤC, không phải cổng: `registrar` chỉ thêm được version
///         mới, không sửa được version cũ, và `createUnregistered` đi vòng hoàn toàn.
///         Không có quyền nào ở đây chạm được một token đã deploy.
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    address public immutable registrar;

    mapping(TokenKind => mapping(uint64 => address)) private _impl;
    mapping(TokenKind => mapping(uint64 => bool)) private _deprecated;
    mapping(TokenKind => uint64) private _latest;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;

    error NotRegistrar();

    constructor(address registrar_) {
        registrar = registrar_;
    }

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert NotRegistrar();
        _;
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation)
        external onlyRegistrar
    {
        // version 0 là dấu của `createUnregistered`; cho đăng ký thì nó mất nghĩa.
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        _impl[kind][version] = implementation;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationRegistered(kind, version, implementation, msg.sender);
    }

    function deprecate(TokenKind kind, uint64 version, string calldata reason) external onlyRegistrar {
        if (_impl[kind][version] == address(0)) revert VersionUnknown(kind, version);
        _deprecated[kind][version] = true;
        emit ImplementationDeprecated(kind, version, reason);
    }

    function implementationOf(TokenKind kind, uint64 version) external view returns (address) {
        return _impl[kind][version];
    }

    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool) {
        return _deprecated[kind][version];
    }

    function latestVersion(TokenKind kind) external view returns (uint64) {
        return _latest[kind];
    }

    // ------------------------------------------------------------------ create

    function createMetaToken(uint64 version, address underlying, bytes calldata initData, bytes32 salt)
        external returns (address)
    {
        return _create(TokenKind.META, version, _registered(TokenKind.META, version),
                       underlying, address(0), initData, salt);
    }

    function createZetherToken(
        uint64 version,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address) {
        address impl = _registered(TokenKind.ZETHER, version);
        _checkVerifier(verifier);
        return _create(TokenKind.ZETHER, version, impl, underlying, verifier, initData, salt);
    }

    function createUnregistered(
        TokenKind kind,
        address implementation,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address) {
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        if (kind == TokenKind.ZETHER) _checkVerifier(verifier);
        return _create(kind, 0, implementation, underlying, verifier, initData, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt)
        public view returns (address)
    {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isDeployedHere(address token) external view returns (bool) { return _info[token].exists; }

    function creatorOf(address token) external view returns (address) { return _info[token].creator; }

    function versionOf(address token) external view returns (TokenKind kind, uint64 version) {
        Info storage i = _info[token];
        return (i.kind, i.version);
    }

    function getWrapper(address creator, address underlying) external view returns (address) {
        address[] storage w = _wrappers[creator][underlying];
        return w.length == 0 ? address(0) : w[0];
    }

    function getWrapperCount(address creator, address underlying) external view returns (uint256) {
        return _wrappers[creator][underlying].length;
    }

    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address) {
        return _wrappers[creator][underlying][index];
    }

    function deployCountFor(address underlying) external view returns (uint256) {
        return _byUnderlying[underlying].length;
    }

    function deployedFor(address underlying, uint256 index) external view returns (address) {
        return _byUnderlying[underlying][index];
    }

    // ------------------------------------------------------------------ internal

    function _registered(TokenKind kind, uint64 version) private view returns (address impl) {
        impl = _impl[kind][version];
        if (impl == address(0)) revert VersionUnknown(kind, version);
    }

    /// @dev Precompile vắng mặt không revert — nó trả rỗng. Hỏi verifier trước khi có
    ///      ai nạp tiền vào một token bất biến không bao giờ verify được (IOpenFactory).
    function _checkVerifier(address verifier) private view {
        if (verifier == address(0)) revert VerifierRequiredForZether();
        bool ok;
        try IZetherVerifier(verifier).isSupportedOnThisChain() returns (bool s) { ok = s; } catch {}
        if (ok) return;
        string memory curve;
        try IZetherVerifier(verifier).curveName() returns (string memory c) { curve = c; } catch {}
        revert VerifierUnsupportedOnThisChain(verifier, curve);
    }

    /// @dev `creator` là `msg.sender` trong salt: không ai chiếm được địa chỉ của người khác.
    function _salt(address creator, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    function _create(
        TokenKind kind,
        uint64 version,
        address impl,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) private returns (address token) {
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
        // CÙNG hàm với CREATE2: không có khe nào để front-run initialize().
        IFactoryToken(token).initialize(msg.sender, underlying, verifier, version, initData);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        _wrappers[msg.sender][underlying].push(token);
        _byUnderlying[underlying].push(token);
        emit TokenDeployed(token, msg.sender, underlying, kind, version, impl, verifier);
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd smartcontracts && forge test --match-contract 'OpenFactoryTest|MetaTokenTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add smartcontracts/src/factory/OpenFactory.sol smartcontracts/test/OpenFactory.t.sol smartcontracts/test/helpers/Mocks.sol
git commit -m "feat(contracts): OpenFactory - append-only catalogue, creator-scoped clones"
```

---

### Task 5: `MetaTxDex`

**Files:**
- Create: `smartcontracts/src/dex/MetaTxDex.sol`
- Test: `smartcontracts/test/MetaTxDex.t.sol`

**Interfaces:**
- Consumes: `MetaToken.OP_TRADE` encoding (`trade(address counterToken, uint256 minCounterValue, address counterparty)`), `IERC20MetaTx.executeMetaTransaction`.
- Produces: `MetaTxDex.Leg {IERC20MetaTx token; MetaTxLib.MetaTransaction m; bytes sig;}`, `settle(Leg a, Leg b)`, event `TradeSettled(address indexed partyA, address indexed partyB, address tokenA, address tokenB, uint256 valueA, uint256 valueB)`, errors `NotATradeLeg SameToken SameParty CounterTokenMismatch PriceNotMet(uint256,uint256) CounterpartyMismatch LegNotRoutedHere FeeWouldStick DeltaMismatch(address,uint256,uint256)`.

- [ ] **Step 1: Write the failing tests** — `test/MetaTxDex.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";

contract MetaTxDexTest is Fixtures {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    address alice;
    address bob;
    MetaToken tA;
    MetaToken tB;
    MetaTxDex dex;
    uint32 constant R = MetaTxLib.MODE_RESTRICT_RELAYER;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        _deployFactory();
        dex = new MetaTxDex();
        tA = _standalone(address(this), "AAA", 18, 1_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 1_000 ether, address(0));
        tA.transfer(alice, 500 ether);
        tB.transfer(bob, 500 ether);
    }

    function _leg(uint256 pk, MetaToken sell, uint256 value, MetaToken buy, uint256 minBuy, address cp)
        internal view returns (MetaTxDex.Leg memory l)
    {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), to: address(dex), value: value,
            data: _tradeData(address(buy), minBuy, cp), batch: uint256(keccak256(abi.encode(pk, value))),
            nonce: 0, validUntil: block.timestamp + 300, mode: R, relayer: address(dex),
            fee: 0, feeRecipient: address(0)
        });
        l = MetaTxDex.Leg({token: IERC20MetaTx(address(sell)), m: m, sig: ""});
        l.sig = _signLeg(pk, sell, m);
    }

    function _signLeg(uint256 pk, MetaToken t, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function test_settleSwapsAtomically() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectEmit(address(dex));
        emit MetaTxDex.TradeSettled(alice, bob, address(tA), address(tB), 100 ether, 60 ether);
        vm.prank(relayer);
        dex.settle(a, b);
        assertEq(tB.balanceOf(alice), 60 ether);
        assertEq(tA.balanceOf(bob), 100 ether);
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
    }

    function test_priceNotMetReverts() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 70 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(abi.encodeWithSelector(MetaTxDex.PriceNotMet.selector, 60 ether, 70 ether));
        dex.settle(a, b);
    }

    function test_counterpartyIsEnforced() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0xCAFE));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.CounterpartyMismatch.selector);
        dex.settle(a, b);
    }

    function test_counterTokenMustMatch() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tA, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.CounterTokenMismatch.selector);
        dex.settle(a, b);
    }

    function test_samePartyRefused() public {
        tB.transfer(alice, 100 ether);
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(ALICE_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.SameParty.selector);
        dex.settle(a, b);
    }

    function test_secondLegFailureMovesNothing() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        b.sig = a.sig;                                   // wrong signer for b
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        dex.settle(a, b);
        assertEq(tA.metaNonce(alice, a.m.batch), 0);
        assertEq(tA.balanceOf(alice), 500 ether);
    }

    function test_legMustBeRoutedThroughThisDex() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.relayer = address(0xD1);
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.LegNotRoutedHere.selector);
        dex.settle(a, b);
    }

    function test_leakedLegCannotRunOutsideTheDex() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxUnauthorizedRelayer.selector, address(dex), relayer));
        tA.executeMetaTransaction(a.m, a.sig);
    }

    function test_feeThatWouldStickInTheDexIsRefused() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.mode = R | MetaTxLib.MODE_FEE_FIXED;
        a.m.fee = 0.1 ether;                             // feeRecipient stays 0 -> would go to DEX
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.FeeWouldStick.selector);
        dex.settle(a, b);
    }

    function test_relayerFillsFeeRecipientAndIsPaid() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.mode = R | MetaTxLib.MODE_FEE_FIXED;
        a.m.fee = 0.1 ether;
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        a.m.feeRecipient = relayer;                      // not restricted: outside the digest
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.prank(relayer);
        dex.settle(a, b);
        assertEq(tA.balanceOf(relayer), 0.1 ether);
        assertEq(tA.balanceOf(alice), 399.9 ether);
    }

    function test_nonTradeLegRefused() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.data = _payData(bytes32("x"));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.NotATradeLeg.selector);
        dex.settle(a, b);
    }

    function testFuzz_settleConservesOrReverts(uint96 va, uint96 vb, uint96 minA, uint96 minB) public {
        va = uint96(bound(va, 1, 500 ether));
        vb = uint96(bound(vb, 1, 500 ether));
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, va, tB, minB, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, vb, tA, minA, address(0));
        bool crosses = vb >= minB && va >= minA;
        if (!crosses) vm.expectRevert();
        dex.settle(a, b);
        if (crosses) {
            assertEq(tA.balanceOf(bob), va);
            assertEq(tB.balanceOf(alice), vb);
        }
        assertEq(tA.totalSupply(), 1_000 ether);
        assertEq(tA.balanceOf(address(dex)) + tB.balanceOf(address(dex)), 0);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd smartcontracts && forge test --match-contract MetaTxDexTest`
Expected: compile error — `MetaTxDex` not found.

- [ ] **Step 3: Implement** — `src/dex/MetaTxDex.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20MetaTx} from "../metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Khớp lệnh nguyên tử P2P (SRS §3.3) — KHÔNG allowance, KHÔNG giữ tiền.
/// @notice Mỗi lệnh là một meta-tx `trade(...)` trên token bán, ký với
///         `relayer == to == address(this)`. Token tự ép điều đó (MetaToken._checkOp), nên
///         một lệnh bị lộ chỉ chạy được ở đây, và ở đây nó chỉ chạy CÙNG chân đối ứng
///         thoả giá người ký đã đặt. Không owner, không sweep, không upgrade.
contract MetaTxDex is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    bytes4 public constant OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"));

    struct Leg {
        IERC20MetaTx token;
        MetaTxLib.MetaTransaction m;
        bytes sig;
    }

    struct Terms {
        address counterToken;
        uint256 minCounterValue;
        address counterparty;
    }

    event TradeSettled(
        address indexed partyA,
        address indexed partyB,
        address tokenA,
        address tokenB,
        uint256 valueA,
        uint256 valueB
    );

    error NotATradeLeg();
    error SameToken();
    error SameParty();
    error CounterTokenMismatch();
    error PriceNotMet(uint256 got, uint256 min);
    error CounterpartyMismatch();
    error LegNotRoutedHere();
    error FeeWouldStick();
    error DeltaMismatch(address token, uint256 got, uint256 expected);

    /// @notice Fill-or-kill: `value` mỗi chân đã ký chính xác, nên không có khớp một phần.
    function settle(Leg calldata a, Leg calldata b) external nonReentrant {
        Terms memory ta = _terms(a.m);
        Terms memory tb = _terms(b.m);
        if (address(a.token) == address(b.token)) revert SameToken();
        if (a.m.from == b.m.from) revert SameParty();
        if (ta.counterToken != address(b.token) || tb.counterToken != address(a.token)) {
            revert CounterTokenMismatch();
        }
        if (b.m.value < ta.minCounterValue) revert PriceNotMet(b.m.value, ta.minCounterValue);
        if (a.m.value < tb.minCounterValue) revert PriceNotMet(a.m.value, tb.minCounterValue);
        if ((ta.counterparty != address(0) && ta.counterparty != b.m.from)
            || (tb.counterparty != address(0) && tb.counterparty != a.m.from)) {
            revert CounterpartyMismatch();
        }
        _checkRouting(a.m);
        _checkRouting(b.m);

        _pull(a);
        _pull(b);
        IERC20(address(a.token)).safeTransfer(b.m.from, a.m.value);
        IERC20(address(b.token)).safeTransfer(a.m.from, b.m.value);
        emit TradeSettled(a.m.from, b.m.from, address(a.token), address(b.token), a.m.value, b.m.value);
    }

    function _terms(MetaTxLib.MetaTransaction calldata m) private pure returns (Terms memory t) {
        bytes calldata d = m.data;
        if (d.length != 100 || bytes4(d[:4]) != OP_TRADE) revert NotATradeLeg();
        (t.counterToken, t.minCounterValue, t.counterparty) = abi.decode(d[4:], (address, uint256, address));
    }

    /// @dev `ERC20MetaTx` gửi phí cho `msg.sender` khi `feeRecipient == 0`; ở đây
    ///      `msg.sender` là contract này, và nó không có cách nào trả lại.
    function _checkRouting(MetaTxLib.MetaTransaction calldata m) private view {
        if (m.to != address(this) || m.relayer != address(this)
            || m.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0) {
            revert LegNotRoutedHere();
        }
        if (MetaTxLib.feeModeOf(m.mode) != FeeMode.NONE
            && (m.feeRecipient == address(0) || m.feeRecipient == address(this))) {
            revert FeeWouldStick();
        }
    }

    /// @dev Đo delta thật: token phí-chuyển hay token "giả chuyển" bị từ chối ở đây.
    function _pull(Leg calldata l) private {
        IERC20 t = IERC20(address(l.token));
        uint256 before = t.balanceOf(address(this));
        l.token.executeMetaTransaction(l.m, l.sig);
        uint256 got = t.balanceOf(address(this)) - before;
        if (got != l.m.value) revert DeltaMismatch(address(t), got, l.m.value);
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd smartcontracts && forge test --match-contract MetaTxDexTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add smartcontracts/src/dex smartcontracts/test/MetaTxDex.t.sol
git commit -m "feat(contracts): MetaTxDex atomic two-leg settlement without allowance"
```

---

### Task 6: Invariants, KAT vector, deploy script

**Files:**
- Create: `smartcontracts/test/Invariants.t.sol`, `smartcontracts/test/MetaTxKat.t.sol`, `smartcontracts/test/vectors/metatx_kat.json` (generated), `smartcontracts/script/Deploy.s.sol`
- Modify: `smartcontracts/foundry.toml` (`fs_permissions`, `[invariant]`), `smartcontracts/.gitignore` (ignore `deployments/`), `smartcontracts/README.md` (status table)

**Interfaces:**
- Produces: `test/vectors/metatx_kat.json` with string fields `domain_name, domain_version, chain_id, verifying_contract, from, to, value, data, batch, nonce, valid_until, mode, relayer, fee, fee_recipient, struct_hash, digest, signature, signer`; `script/Deploy.s.sol` writing `deployments/<chainid>.json` with `factory, implementation, dex, demo_token`.

- [ ] **Step 1: Write the tests**

`test/Invariants.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Fixtures} from "./helpers/Fixtures.sol";
import {MockERC20} from "./helpers/Mocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";

/// Handler: thao tác ngẫu nhiên trên một wrapper, một token standalone và DEX.
contract Handler is Test {
    MetaToken public tA;
    MetaToken public wrapped;
    MockERC20 public usdc;
    MetaToken public tB;
    MetaTxDex public dex;
    uint256[3] public pks = [uint256(0xA1), 0xB2, 0xC3];
    uint256 public batchSeq;

    constructor(MetaToken a, MetaToken b, MetaToken w, MockERC20 u, MetaTxDex d) {
        tA = a; tB = b; wrapped = w; usdc = u; dex = d;
    }

    function actor(uint256 i) public view returns (address) { return vm.addr(pks[i % 3]); }

    function transfer(uint256 from, uint256 to, uint256 v) external {
        address f = actor(from);
        v = bound(v, 0, tA.balanceOf(f));
        vm.prank(f);
        tA.transfer(actor(to), v);
    }

    function wrap(uint256 who, uint256 v) external {
        address w = actor(who);
        v = bound(v, 0, 1_000e6);
        usdc.mint(w, v);
        vm.startPrank(w);
        usdc.approve(address(wrapped), v);
        wrapped.wrap(v);
        vm.stopPrank();
    }

    function unwrap(uint256 who, uint256 v) external {
        address w = actor(who);
        v = bound(v, 0, wrapped.balanceOf(w));
        vm.prank(w);
        wrapped.unwrap(v, w);
    }

    function trade(uint256 sellerA, uint256 sellerB, uint256 va, uint256 vb) external {
        uint256 pa = pks[sellerA % 3];
        uint256 pb = pks[(sellerA + 1 + sellerB % 2) % 3];
        va = bound(va, 1, tA.balanceOf(vm.addr(pa)) == 0 ? 1 : tA.balanceOf(vm.addr(pa)));
        vb = bound(vb, 1, tB.balanceOf(vm.addr(pb)) == 0 ? 1 : tB.balanceOf(vm.addr(pb)));
        MetaTxDex.Leg memory a = _leg(pa, tA, va, tB, vb);
        MetaTxDex.Leg memory b = _leg(pb, tB, vb, tA, va);
        try dex.settle(a, b) {} catch {}
    }

    function _leg(uint256 pk, MetaToken sell, uint256 v, MetaToken buy, uint256 minBuy)
        internal returns (MetaTxDex.Leg memory l)
    {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), to: address(dex), value: v,
            data: abi.encodeWithSelector(bytes4(keccak256("trade(address,uint256,address)")), address(buy), minBuy, address(0)),
            batch: ++batchSeq, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: address(dex), fee: 0, feeRecipient: address(0)
        });
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, sell.metaTxDigest(m));
        l = MetaTxDex.Leg({token: IERC20MetaTx(address(sell)), m: m, sig: abi.encodePacked(r, s, vv)});
    }
}

contract InvariantsTest is StdInvariant, Fixtures {
    Handler h;
    MetaToken tA;
    MetaToken tB;
    MetaToken w;
    MockERC20 usdc;
    MetaTxDex dex;

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployFactory();
        dex = new MetaTxDex();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        tA = _standalone(address(this), "AAA", 18, 3_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 3_000 ether, address(0));
        w = _wrapper(address(this), address(usdc), "wUSDC");
        h = new Handler(tA, tB, w, usdc, dex);
        for (uint256 i; i < 3; ++i) {
            tA.transfer(h.actor(i), 1_000 ether);
            tB.transfer(h.actor(i), 1_000 ether);
        }
        targetContract(address(h));
    }

    function invariant_supplyEqualsBalances() public view {
        uint256 sum = tA.balanceOf(address(dex));
        for (uint256 i; i < 3; ++i) sum += tA.balanceOf(h.actor(i));
        assertEq(sum, tA.totalSupply());
    }

    function invariant_wrapperIsFullyReserved() public view {
        assertGe(usdc.balanceOf(address(w)), w.totalSupply());
    }

    function invariant_dexHoldsNothing() public view {
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
    }
}
```

`test/MetaTxKat.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

/// @title Vector KAT cho ba bản sao của digest (Python ở Odoo, Rust ở node, ví).
/// @notice Sinh `test/vectors/metatx_kat.json`. File được commit; đổi typehash, đổi quy
///         tắc canonical-zeroing hay đổi domain là test Python và Rust đỏ ngay.
contract MetaTxKatTest is Fixtures {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    function test_writeKat() public {
        vm.chainId(9000);
        vm.warp(1_800_000_000);
        _deployFactory();
        MetaToken tok = _standalone(address(this), "BUSD", 6, 0, address(0));
        uint256 pk = 0xA11CE;
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), to: address(0x5409), value: 250e6,
            data: _payData(bytes32(uint256(0x42))), batch: uint256(keccak256("bamboo.pay.lane")),
            nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: relayer, fee: 0,
            feeRecipient: address(0xFEE)        // flag off -> canonical-zeroed in the hash
        });
        bytes32 structHash = m.hashStruct();
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Bamboo MetaToken"), keccak256("1"), uint256(9000), address(tok)));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.metaTxDigest(m));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        string memory k = "kat";
        vm.serializeString(k, "domain_name", "Bamboo MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "9000");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "to", vm.toString(m.to));
        vm.serializeString(k, "value", vm.toString(m.value));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer", vm.toString(m.from));
        string memory out = vm.serializeString(k, "signature", vm.toString(abi.encodePacked(r, s, v)));
        vm.writeJson(out, "./test/vectors/metatx_kat.json");
    }
}
```

`foundry.toml` — add under `[profile.default]`:

```toml
fs_permissions = [
  { access = "read-write", path = "./test/vectors" },
  { access = "read-write", path = "./deployments" },
]

[invariant]
runs = 64
depth = 32
fail_on_revert = false
```

- [ ] **Step 2: Run to verify**

Run: `cd smartcontracts && mkdir -p test/vectors deployments && forge test --match-contract 'InvariantsTest|MetaTxKatTest' -vv`
Expected: PASS; `test/vectors/metatx_kat.json` written. (Invariant tests are written against Tasks 1–5 code, so they pass on first run — the "red" step for invariants is to temporarily break `wrap` to mint `amount` instead of the delta and see `invariant_wrapperIsFullyReserved` fail with the fee-on-transfer mock… which the invariant handler does NOT use; therefore verify instead by `forge test --match-test invariant -vvv` showing non-zero calls per invariant.)

- [ ] **Step 3: Deploy script** — `script/Deploy.s.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/common/IOpenFactory.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
/// env: PRIVATE_KEY (deployer = registrar by default), REGISTRAR (optional),
///      DEMO_SUPPLY (optional; 0 = no demo token), DEMO_HOLDER (optional)
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        vm.startBroadcast(pk);
        OpenFactory factory = new OpenFactory(registrar);
        MetaToken impl = new MetaToken(address(factory));
        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
        MetaTxDex dex = new MetaTxDex();
        address demo;
        if (demoSupply != 0 && registrar == deployer) {
            demo = factory.createMetaToken(1, address(0),
                abi.encode("Bamboo Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
            if (demoHolder != deployer) MetaToken(demo).transfer(demoHolder, demoSupply / 2);
        }
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "factory", address(factory));
        vm.serializeAddress(k, "implementation", address(impl));
        vm.serializeAddress(k, "dex", address(dex));
        string memory out = vm.serializeAddress(k, "demo_token", demo);
        vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
```

`smartcontracts/.gitignore` append `deployments/` and `broadcast/`.

- [ ] **Step 4: Verify the deploy script on anvil**

Run:
```bash
anvil --chain-id 9000 --hardfork prague --port 18545 > /tmp/anvil.log 2>&1 &
cd smartcontracts && PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 DEMO_SUPPLY=1000000000000 \
  FOUNDRY_PROFILE=private9000 forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:18545 --broadcast
cat deployments/9000.json; kill %1
```
Expected: JSON with four non-zero addresses.

- [ ] **Step 5: Full suite, both profiles**

Run: `cd smartcontracts && forge test && FOUNDRY_PROFILE=private9000 forge test`
Expected: all PASS, including the pre-existing 39.

- [ ] **Step 6: Commit**

```bash
git add smartcontracts/test smartcontracts/script smartcontracts/foundry.toml smartcontracts/.gitignore smartcontracts/README.md
git commit -m "test(contracts): invariants, cross-language digest KAT and deploy script"
```

---

## Self-review

| Spec item | Task |
|---|---|
| §2.1 clone-safe init, metadata, provenance, domain | 1 |
| §2.1 tiers (mint / wrap delta) | 1, 3 |
| §2.1 ops `pay`/`trade`, `PaymentSettled` with fee | 2 |
| §2.1 `payWithFee` | 2 |
| §2.2 factory (append-only, salt by creator, verifier check, unregistered v0, lookups) | 4 |
| §2.3 DEX (routing, price, counterparty, fee-stick, delta, atomic) | 5 |
| §2.4 deploy | 6 |
| §5 guarantee 2 (lane at most once) | 2 `test_payLaneExecutesAtMostOnce` |
| §6 KAT | 6 |
| §9 T9–T13, T16–T17 | 1, 4, 5, 3/6 |
| §10 invariants | 6 |

Type consistency: `Leg` field names `token, m, sig` used identically in Tasks 5–6; `OP_TRADE` string identical in token, DEX, fixture and handler.
