// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MockERC20, FeeOnTransferERC20} from "./helpers/Mocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTxV1} from "../src/metatx/IERC20MetaTxV1.sol";
import {IERC20PaymentV1} from "../src/metatx/IERC20PaymentV1.sol";
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
        assertEq(n, "SCaaS MetaToken");
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

    // ---- Task 2: ops ----

    bytes32 constant REF = keccak256("order-42");
    uint256 constant LANE = uint256(keccak256("lane"));

    function _exec(MetaTxLib.LegacyMetaTransaction memory m) internal {
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
    }

    function test_payEmitsPaymentSettled() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 250e6, _payData(REF), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        vm.expectEmit(address(tok));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 250e6, 0, relayer, REF);
        _exec(m);
        assertEq(tok.balanceOf(shop), 250e6);
        assertEq(tok.balanceOf(alice), 750e6);
    }

    function test_payReportsTheFeeActuallyCharged() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 100e6, _payData(REF), LANE,
            MetaTxLib.MODE_FEE_FIXED);
        m.fee = 1e6;
        m.feeRecipient = relayer;
        vm.expectEmit(address(tok));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 100e6, 1e6, relayer, REF);
        _exec(m);
        assertEq(tok.balanceOf(relayer), 1e6);
        assertEq(tok.balanceOf(alice), 899e6);
    }

    function test_payLaneExecutesAtMostOnce() public {
        MetaTxLib.LegacyMetaTransaction memory m1 = _mt(alice, shop, 10e6, _payData(REF), LANE, 0);
        MetaTxLib.LegacyMetaTransaction memory m2 = _mt(alice, shop, 10e6, _payData(REF), LANE, 0);
        m2.validUntil = m1.validUntil + 60;            // second signature, same lane
        bytes memory s2 = _sign(ALICE_PK, tok, m2);
        _exec(m1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        tok.executeMetaTransaction(m2, s2);
        assertEq(tok.balanceOf(shop), 10e6);
    }

    function test_payAfterExpiryIsRefused() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, _payData(REF), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.warp(m.validUntil + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxExpired.selector, m.validUntil, block.timestamp));
        tok.executeMetaTransaction(m, sig);
    }

    function test_payToZeroIsRefused() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, address(0), 1, _payData(REF), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.PayToZero.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_payWithWrongLengthIsUnknownOp() public {
        bytes memory bad = abi.encodePacked(bytes4(keccak256("pay(bytes32)")), bytes31(0));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, bad, LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(keccak256("pay(bytes32)"))));
        tok.executeMetaTransaction(m, sig);
    }

    function test_shortDataIsUnknownOpNotPanic() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, hex"01", LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(0)));
        tok.executeMetaTransaction(m, sig);
    }

    function test_unknownSelectorIsRefused() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, hex"deadbeef", LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(0xdeadbeef)));
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeNeedsRestrictedRelayer() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, relayer, 1, _tradeData(address(9), 1, address(0)), LANE, 0);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.TradeLegNotRestricted.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeProceedsGoOnlyToTheExecutor() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, _tradeData(address(9), 1, address(0)), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        bytes memory sig = _sign(ALICE_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.TradeLegNotRestricted.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_tradeMovesToExecutor() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, relayer, 5e6, _tradeData(address(9), 1, address(0)), LANE,
            MetaTxLib.MODE_RESTRICT_RELAYER);
        _exec(m);
        assertEq(tok.balanceOf(relayer), 5e6);
    }

    function test_payWithFeeDirectPath() public {
        vm.prank(alice);
        vm.expectEmit(address(tok));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 100e6, 1e6, relayer, REF);
        tok.payWithFee(shop, 100e6, FeeMode.FIXED, 1e6, relayer, REF);
        assertEq(tok.balanceOf(shop), 100e6);
        assertEq(tok.balanceOf(relayer), 1e6);
    }

    function testFuzz_payConservesSupply(uint96 value, uint16 feePpm) public {
        value = uint96(bound(value, 1, 1_000e6));
        feePpm = uint16(bound(feePpm, 0, 10_000));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, value, _payData(REF), LANE, MetaTxLib.MODE_FEE_PERCENT);
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
}
