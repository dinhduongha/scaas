// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {HederaHts} from "../../src/hedera/HederaV2Lib.sol";
import {HederaNoUnderlyingToken, HederaSingleUnderlyingToken, HederaMultiUnderlyingToken}
    from "../../src/hedera/HederaTokensV2.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MockHederaAccountService, MockHts} from "./HederaMocks.sol";

/// T5: con Hedera của ba tầng (TW2 §11, R144) — HIP-632 trên mỗi tầng, associate lúc init, kiểm phí HTS fail-closed.
contract HederaV2Test is Test {
    address constant HAS = address(0x16a);
    address constant HTS = address(0x167);
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint256 constant ALICE_KEY = 0xA11CE5;
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address relayer = address(0xBEEF);
    address registrar = address(0xF00D);
    address shop = address(0x5409);
    address alice; // 0.0.1234567, ED25519 key (simulated, see MockHederaAccountService)
    OpenFactoryV2 f;
    MockERC20 usdc;   // stands in for an HTS token's ERC-20 facade
    MockERC20 plain;  // a plain EVM ERC-20 on Hedera

    function setUp() public {
        vm.chainId(296);
        vm.warp(1_800_000_000);
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        vm.etch(HTS, type(MockHts).runtimeCode);
        alice = address(uint160(1_234_567));
        MockHederaAccountService(HAS).setEdKey(alice, vm.addr(ALICE_KEY));
        f = new OpenFactoryV2(registrar);
        vm.startPrank(registrar);
        f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1, address(new HederaNoUnderlyingToken(address(f), UID)));
        f.registerImplementation(IOpenFactoryV2.TokenKind.META_SINGLE, 1,
            address(new HederaSingleUnderlyingToken(address(f), UID)));
        f.registerImplementation(IOpenFactoryV2.TokenKind.META_MULTI, 1,
            address(new HederaMultiUnderlyingToken(address(f), UID)));
        vm.stopPrank();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        plain = new MockERC20("Plain", "PLN", 6);
        MockHts(HTS).setHts(address(usdc), true);
    }

    function _edSign(bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(ALICE_KEY, digest);
        return abi.encodePacked(r, vs);
    }

    function _tr(address to, uint256 value, bytes32 ref, uint256 batch)
        internal view returns (MetaTxLib.MetaTransfer memory)
    {
        return MetaTxLib.MetaTransfer({from: alice, to: to, value: value, entryRef: ref, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
    }

    function _single(address u) internal returns (address) {
        address[] memory us = new address[](1);
        us[0] = u;
        SingleUnderlyingToken.RateConfig memory c;
        return f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us,
            abi.encode("Wrapped", "W", uint8(6), uint256(1), uint256(1), c), keccak256(abi.encode(u)));
    }

    function _wrapFor(address t, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(t, v);
        SingleUnderlyingToken(t).wrap(v);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ HIP-632 on each tier

    function test_tier1NativeAccountPays() public {
        vm.prank(alice);
        address t = f.createTiered(IOpenFactoryV2.TokenKind.META_NONE, 1, new address[](0),
            abi.encode("Points", "PTS", uint8(0), uint256(1000), address(0)), "n");
        MetaTxLib.MetaTransfer memory x = _tr(shop, 250, 0, 1);
        bytes memory sig = _edSign(IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        IERC20MetaTx(t).mtxExecuteTransfer(x, sig);
        assertEq(IERC20MetaTx(t).balanceOf(shop), 250);
    }

    function test_tier2NativeAccountUnwrapsGasless() public {
        address t = _single(address(usdc));
        assertTrue(MockHts(HTS).associated(t, address(usdc)));
        _wrapFor(t, usdc, alice, 100e6);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
            data: abi.encodeWithSignature("unwrap(uint256,address,uint256)", 40e6, shop, 40e6), batch: 2, nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes memory sig = _edSign(IMetaTx(t).mtxDigest(m));
        vm.prank(relayer);
        IMetaTx(t).mtxExecute(m, sig);
        assertEq(usdc.balanceOf(shop), 40e6);
    }

    function test_tier3NativeAccountPaysAndEveryHtsLegIsAssociated() public {
        MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
        MockHts(HTS).setHts(address(usdt), true);
        address[] memory us = new address[](3);
        (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(plain));
        uint256[] memory n = new uint256[](3);
        (n[0], n[1], n[2]) = (1, 1, 1);
        SingleUnderlyingToken.RateConfig memory c;
        address t = f.createTiered(IOpenFactoryV2.TokenKind.META_MULTI, 1, us,
            abi.encode("Any", "ANY", uint8(6), n, n, c, address(0)), "m");
        assertTrue(MockHts(HTS).associated(t, address(usdc)));
        assertTrue(MockHts(HTS).associated(t, address(usdt)));
        assertFalse(MockHts(HTS).associated(t, address(plain))); // not an HTS token: nothing to associate
        usdt.mint(alice, 10e6);
        vm.startPrank(alice);
        usdt.approve(t, 10e6);
        HederaMultiUnderlyingToken(t).wrap(address(usdt), 10e6);
        vm.stopPrank();
        bytes32 payId = keccak256("inv");
        MetaTxLib.MetaTransfer memory x = _tr(shop, 3e6, payId, HederaMultiUnderlyingToken(t).payLane(payId));
        bytes memory sig = _edSign(IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        HederaMultiUnderlyingToken(t).mtxPay(alice, shop, 3e6, payId, x.validUntil, RR, relayer, 0, address(0), sig);
        assertEq(IERC20MetaTx(t).balanceOf(shop), 3e6);
    }

    function test_otherKeyIsRejected() public {
        address t = _single(address(plain));
        _wrapFor(t, plain, alice, 10);
        MetaTxLib.MetaTransfer memory x = _tr(shop, 1, 0, 1);
        (bytes32 r, bytes32 vs) = vm.signCompact(0xBAD, IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        IERC20MetaTx(t).mtxExecuteTransfer(x, abi.encodePacked(r, vs));
    }

    // ------------------------------------------------------------------ fail-closed HTS checks at init

    function _refuse(bytes memory err) internal {
        address[] memory us = new address[](1);
        us[0] = address(usdc);
        SingleUnderlyingToken.RateConfig memory c;
        bytes memory init = abi.encode("Wrapped", "W", uint8(6), uint256(1), uint256(1), c);
        vm.expectRevert(err);
        f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us, init, "x");
    }

    function test_isTokenFailureRefuses() public {
        MockHts(HTS).setIsTokenRc(address(usdc), 21);
        _refuse(abi.encodeWithSelector(HederaHts.HtsQueryFailed.selector, address(usdc), int64(21)));
    }

    function test_customFeeQueryFailureRefuses() public {
        MockHts(HTS).setFeesRc(address(usdc), 167);
        _refuse(abi.encodeWithSelector(HederaHts.HtsQueryFailed.selector, address(usdc), int64(167)));
    }

    function test_undecodableCustomFeesRefuse() public {
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Malformed);
        _refuse(abi.encodeWithSelector(HederaHts.HtsQueryFailed.selector, address(usdc), int64(22)));
    }

    function test_anyCustomFeeRefuses() public {
        bytes memory e = abi.encodeWithSelector(SingleUnderlyingToken.UnderlyingInvalid.selector, address(usdc));
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fixed);
        _refuse(e);
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fractional);
        _refuse(e);
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Royalty);
        _refuse(e);
    }

    function test_associationFailureRefuses() public {
        MockHts(HTS).force(15);
        _refuse(abi.encodeWithSelector(HederaHts.AssociateFailed.selector, int64(15)));
    }

    function test_absentPrecompileRefuses() public {
        vm.etch(HTS, "");
        _refuse(abi.encodeWithSelector(HederaHts.HtsQueryFailed.selector, address(usdc), int64(-1)));
    }
}
