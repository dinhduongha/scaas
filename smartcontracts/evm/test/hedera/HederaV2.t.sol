// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MockERC20, StubUARegistry} from "../helpers/Mocks.sol";
import {normalInit, wrappedInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {MockHederaAccountService, MockHts} from "./HederaMocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

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
    OpenFactory f;
    MockERC20 usdc;   // stands in for an HTS token's ERC-20 facade
    MockERC20 plain;  // a plain EVM ERC-20 on Hedera

    function setUp() public {
        vm.chainId(296);
        vm.warp(1_800_000_000);
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        vm.etch(HTS, type(MockHts).runtimeCode);
        alice = address(uint160(1_234_567));
        MockHederaAccountService(HAS).setEdKey(alice, vm.addr(ALICE_KEY));
        f = EnvKit.factory(registrar, UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), true);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), true);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        plain = new MockERC20("Plain", "PLN", 6);
        MockHts(HTS).setHts(address(usdc), true);
    }

    function test_implementationSizes() public view {
        // owner: size later (Glamsterdam); budget 20,480 (P2a ruling); +8.7 KB for the UA ledger (UA-4); +1.2 / +2.5 KB
        // for the UA-5a receivers; +2.3 / +3.4 KB for UA-5b (UATradeOrder, uaWrap); +1.6 KB for the guard on every entry
        // (review W-Q, CTR-MTX-18); +13 B for MetaTxBase on MtxPipelineLib's internals (metatx split T2; T3 moves the
        // tokens onto the library); +964 / +973 B for typed-signing R1's `UAKinds.uaSig` (the tokens' `bytes auth` as the
        // registry's `UASig`, removed when C2 types the parameters); +56 / +1,118 B for typed-signing C0's named path
        // (size-baseline.json holds the exact ratchet); governance T7 (GD-18): past 39,945 B, the literal reads the baseline
        assertLe(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1).code.length, vm.parseJsonUint(vm.readFile("./size-baseline.json"), ".NormalToken"));
        // Transitional (P1d D2): over EIP-170 until the size work (the only ceiling: 65,536 B, owner 2026-10-21)
        assertLe(f.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1).code.length, vm.parseJsonUint(vm.readFile("./size-baseline.json"), ".WrappedToken"));
    }

    function _edSign(bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(ALICE_KEY, digest);
        return abi.encodePacked(r, vs);
    }

    /// A native id's `UASig`: its own (here 64-byte HIP-632 ed25519) signature only (R17).
    function _n(bytes memory sig) internal pure returns (IUARegistry.UASig memory u) {
        u.signature = sig;
    }

    /// ua-mtx-merge T2: the token's one typed struct, `UAMetaTransfer`; the Hedera account long-zero, padded.
    function _tr(address to, uint256 value, bytes32 ref, uint256 batch)
        internal view returns (MetaTxLib.UAMetaTransfer memory)
    {
        return MetaTxLib.UAMetaTransfer({from: MetaTxLib.pad(alice), to: MetaTxLib.pad(to), value: value, entryRef: ref,
            batch: batch, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
            feeRecipient: address(0)});
    }

    function _single(address u) internal returns (address) {
        address[] memory us = new address[](1);
        us[0] = u;
        return f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(_init(us)), keccak256(abi.encode(u)));
    }

    /// One leg at 1:1, rates fixed, no owner.
    function _init(address[] memory us) internal pure returns (IFactoryToken.TokenConfig memory) {
        uint256[] memory one = new uint256[](1);
        one[0] = 1;
        Rate memory c;
        return wrappedInit(us, one, one, 6, c, address(0), address(0));
    }

    function _wrapFor(address t, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(t, v);
        WrappedToken(t).wrap(v);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ HIP-632 on each tier

    function test_tier1NativeAccountPays() public {
        vm.prank(alice);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("Points", "PTS", 0, 1000, alice, address(0))), "n");
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 250, 0, 1);
        bytes memory sig = _edSign(IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(sig));
        assertEq(IERC20MetaTx(t).balanceOf(shop), 250);
    }

    /// HIP-632 payee: a native Hedera account co-signs the `UAPayeeFee` (64-byte ed25519) for an EVM payer's payment.
    function test_tier1NativeAccountPayeeCoSignsPayeeFee() public {
        vm.prank(alice);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("Points", "PTS", 0, 1000, alice, address(0))), "n");
        uint256 payerPk = 0xB0B;
        address payer = vm.addr(payerPk);
        address feeTo = address(0xFEE);
        vm.prank(alice);
        IERC20MetaTx(t).transfer(payer, 500);
        bytes32 ref = PayMetaKit.ref("request-1"); // pay-meta-tax T37: the commitment of its `PayMeta`
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: MetaTxLib.pad(payer),
            to: MetaTxLib.pad(alice), value: 200, entryRef: ref, batch: IMetaTokenV2(t).payLane(ref), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes32 d = IERC20MetaTx(t).mtxTransferDigest(x);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerPk, d);
        bytes memory payerSig = abi.encodePacked(r, s, v);
        bytes memory payeeSig = _edSign(IMetaTokenV2(t).payeeFeeDigest(x, 30, feeTo, block.timestamp));
        uint256 aliceBefore = IERC20MetaTx(t).balanceOf(alice);
        vm.prank(relayer);
        IMetaTokenV2(t).mtxPayWithPayeeFee(x, _n(payerSig), 30, feeTo, block.timestamp, _n(payeeSig),
            PayMetaKit.meta("request-1"));
        assertEq(IERC20MetaTx(t).balanceOf(payer), 300);
        assertEq(IERC20MetaTx(t).balanceOf(alice), aliceBefore + 200 - 30);
        assertEq(IERC20MetaTx(t).balanceOf(feeTo), 30);
    }

    function test_tier2NativeAccountUnwrapsGasless() public {
        address t = _single(address(usdc));
        assertTrue(MockHts(HTS).associated(t, address(usdc)));
        _wrapFor(t, usdc, alice, 100e6);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
            data: abi.encodeWithSignature("unwrap(uint256,address,uint256)", 40e6, shop, 40e6), batch: 2, nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes memory sig = _edSign(MtxDigest.metaTx(t, m));
        vm.prank(relayer);
        IMetaTx(t).executeMetaTransaction(m, sig);
        assertEq(usdc.balanceOf(shop), 40e6);
    }

    function test_tier3NativeAccountPaysAndEveryHtsLegIsAssociated() public {
        MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
        MockHts(HTS).setHts(address(usdt), true);
        address[] memory us = new address[](3);
        (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(plain));
        uint256[] memory n = new uint256[](3);
        (n[0], n[1], n[2]) = (1, 1, 1);
        Rate memory c;
        address t = f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(wrappedInit(us, n, n, 6, c, address(0), address(0))), "m");
        assertTrue(MockHts(HTS).associated(t, address(usdc)));
        assertTrue(MockHts(HTS).associated(t, address(usdt)));
        assertFalse(MockHts(HTS).associated(t, address(plain))); // not an HTS token: nothing to associate
        usdt.mint(alice, 10e6);
        vm.startPrank(alice);
        usdt.approve(t, 10e6);
        WrappedToken(t).wrap(address(usdt), 10e6);
        vm.stopPrank();
        bytes32 payId = PayMetaKit.ref("inv");
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 3e6, payId, WrappedToken(t).payLane(payId));
        bytes memory sig = _edSign(IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        WrappedToken(t).mtxPay(x, _n(sig), PayMetaKit.meta("inv"));
        assertEq(IERC20MetaTx(t).balanceOf(shop), 3e6);
    }

    function test_otherKeyIsRejected() public {
        address t = _single(address(plain));
        _wrapFor(t, plain, alice, 10);
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 1, 0, 1);
        (bytes32 r, bytes32 vs) = vm.signCompact(0xBAD, IERC20MetaTx(t).mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(abi.encodePacked(r, vs)));
    }

    // ------------------------------------------------------------------ ua-mtx-merge T8 (R42): the merged entries

    function _points() internal returns (address t) {
        vm.prank(alice);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("Points", "PTS", 0, 1000, alice, address(0))), "n");
        assertEq(IUALedger(t).registry(), address(0), "version 1: no registry");
    }

    /// `executeMetaTransaction` (the token's address path, R3) of `cancelNonce(42)` on lane 7 by `from`.
    function _cancelMeta(address from) internal view returns (MetaTxLib.MetaTransaction memory) {
        return MetaTxLib.MetaTransaction({from: from, data: abi.encodeCall(IMetaTx.cancelNonce, (42)), batch: 7, nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
    }

    /// R42: an ED25519 account 0.0.1234567 relays its own `UAMetaTransfer`, `from` its long-zero EVM address zero-padded,
    /// at fee 0 with no registry: HIP-632 is asked about that account over the merged entry's digest.
    function test_hederaEd25519EoaMtxTransfer() public {
        address t = _points();
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 250, 0, 1);
        assertEq(x.from, bytes32(uint256(1_234_567)), "from: the long-zero address, zero-padded");
        bytes32 d = IERC20MetaTx(t).mtxTransferDigest(x);
        bytes memory sig = _edSign(d);
        vm.expectCall(HAS, abi.encodeWithSelector(bytes4(0xb2a31da4), alice, abi.encodePacked(d), sig));
        vm.prank(relayer);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(sig));
        assertEq(IERC20MetaTx(t).balanceOf(shop), 250);
        assertEq(IERC20MetaTx(t).balanceOf(alice), 750);
    }

    /// R42: an ECDSA account signs with the key of its EVM alias (65 bytes), `from` the alias zero-padded; the EVM path
    /// takes it and HIP-632 is never asked, on the merged entry and on the address path alike.
    function test_hederaEcdsaAliasMtxTransfer() public {
        address t = _points();
        uint256 pk = 0xEC0A;
        address ec = vm.addr(pk);
        assertTrue(uint160(ec) >> 64 != 0, "an alias, not a long-zero address");
        vm.prank(alice);
        IERC20MetaTx(t).transfer(ec, 500);
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 200, 0, 1);
        x.from = MetaTxLib.pad(ec);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, IERC20MetaTx(t).mtxTransferDigest(x));
        vm.expectCall(HAS, bytes(""), 0);
        vm.prank(relayer);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(abi.encodePacked(r, s, v)));
        assertEq(IERC20MetaTx(t).balanceOf(shop), 200);
        MetaTxLib.MetaTransaction memory m = _cancelMeta(ec);
        (v, r, s) = vm.sign(pk, MtxDigest.metaTx(t, m));
        vm.prank(relayer);
        IMetaTx(t).executeMetaTransaction(m, abi.encodePacked(r, s, v));
        assertEq(UAMetaTxBase(t).mtxNonce(MetaTxLib.pad(ec), 42), 1, "the address path ran its cancelNonce");
    }

    /// HIP-632 only for an account without code: a contract whose address has an ED25519 key at the precompile is
    /// refused a 64-byte signature by that key (HIP-632 is never asked), on the merged entry and on the address path; its
    /// ERC-1271 answer is the positive control.
    function test_hip632RefusedForAContract() public {
        address t = _points();
        uint256 ownerPk = 0xC0DE;
        Mock1271Wallet cw = new Mock1271Wallet(vm.addr(ownerPk));
        MockHederaAccountService(HAS).setEdKey(address(cw), vm.addr(ALICE_KEY));
        vm.prank(alice);
        IERC20MetaTx(t).transfer(address(cw), 500);
        MetaTxLib.UAMetaTransfer memory x = _tr(shop, 200, 0, 1);
        x.from = MetaTxLib.pad(address(cw));
        bytes32 d = IERC20MetaTx(t).mtxTransferDigest(x);
        vm.expectCall(HAS, bytes(""), 0);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(_edSign(d)));
        MetaTxLib.MetaTransaction memory m = _cancelMeta(address(cw));
        bytes memory edSig = _edSign(MtxDigest.metaTx(t, m));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        IMetaTx(t).executeMetaTransaction(m, edSig);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, d);
        vm.prank(relayer);
        IERC20MetaTx(t).mtxExecuteTransfer(x, _n(abi.encodePacked(r, s, v)));
        assertEq(IERC20MetaTx(t).balanceOf(shop), 200, "positive control: its ERC-1271");
    }

    // ------------------------------------------------------------------ UA-5a on Hedera (CTR-UA-28, R5a-14)

    bytes32 constant UA = keccak256("scaas.hedera.ua"); // a derived id: the stub registry calls it a p256 UA

    /// Version 2 of NORMAL and WRAPPED with the UA ledger on (a stub registry: native signers only).
    function _ledgerOn() internal {
        StubUARegistry stub = new StubUARegistry(UID);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 2, type(NormalToken).creationCode, address(stub), address(0), true);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 2, type(WrappedToken).creationCode, address(stub), address(0), true);
    }

    function _singleV2(address u) internal returns (address) {
        address[] memory us = new address[](1);
        us[0] = u;
        return f.createToken(IOpenFactory.TokenKind.WRAPPED, 2, abi.encode(_init(us)), keccak256(abi.encode(u, 2)));
    }

    /// An HTS leg wraps straight into a UA: the wrapper's association is unchanged, the UA needs none.
    function test_wrapToUA_htsLeg() public {
        _ledgerOn();
        address t = _singleV2(address(usdc));
        assertTrue(MockHts(HTS).associated(t, address(usdc)));
        usdc.mint(alice, 10e6);
        vm.startPrank(alice);
        usdc.approve(t, 10e6);
        WrappedToken(t).wrapToUA(address(usdc), 10e6, UA);
        vm.stopPrank();
        assertEq(WrappedToken(t).balanceOfUA(UA), 10e6);
        assertEq(usdc.balanceOf(t), 10e6);
    }

    /// An HTS leg is not a SCaaS ledger token: `unwrapToUA` refuses it before anything moves.
    function test_unwrapToUA_htsLegRefused() public {
        _ledgerOn();
        address t = _singleV2(address(usdc));
        _wrapFor(t, usdc, alice, 10e6);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(usdc)));
        vm.prank(alice);
        WrappedToken(t).unwrapToUA(address(usdc), 1e6, UA, 0);
        assertEq(IERC20MetaTx(t).balanceOf(alice), 10e6);
    }

    /// HIP-632 payee on the UA path: a native Hedera account co-signs the `UAPayeeFee` (64-byte ed25519) of an EVM payer's
    /// `UAMetaTransfer` through `MtxPipelineLib.authorize(PURPOSE_PAYEE_FEE)` (its HIP-632 branch).
    function test_uaPayWithPayeeFee_hip632Payee() public {
        _ledgerOn();
        vm.prank(alice);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL, 2, abi.encode(normalInit("Points", "PTS", 0, 1000, alice, address(0))), "n2");
        uint256 payerPk = 0xB0B;
        address payer = vm.addr(payerPk);
        address feeTo = address(0xFEE);
        vm.prank(alice);
        IERC20MetaTx(t).transfer(payer, 500);
        bytes32 ref = PayMetaKit.ref("request-ua");
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: bytes32(uint256(uint160(payer))),
            to: bytes32(uint256(uint160(alice))), value: 200, entryRef: ref, batch: IMetaTokenV2(t).payLane(ref), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes32 d = IERC20MetaTx(t).mtxTransferDigest(x);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerPk, d);
        bytes memory payeeSig = _edSign(IMetaTokenV2(t).payeeFeeDigest(x, 30, feeTo, block.timestamp));
        uint256 aliceBefore = IERC20MetaTx(t).balanceOf(alice);
        vm.prank(relayer);
        IMetaTokenV2(t).mtxPayWithPayeeFee(x, UACall.auth(x.from, abi.encodePacked(r, s, v)), 30, feeTo, block.timestamp, UACall.auth(x.to, payeeSig),
            PayMetaKit.meta("request-ua"));
        assertEq(IERC20MetaTx(t).balanceOf(payer), 300);
        assertEq(IERC20MetaTx(t).balanceOf(alice), aliceBefore + 200 - 30);
        assertEq(IERC20MetaTx(t).balanceOf(feeTo), 30);
    }

    // ------------------------------------------------------------------ fail-closed HTS checks at init

    function _refuse(bytes memory err) internal {
        address[] memory us = new address[](1);
        us[0] = address(usdc);
        IFactoryToken.TokenConfig memory init = _init(us);
        vm.expectRevert(err);
        f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(init), "x");
    }

    function test_isTokenFailureRefuses() public {
        MockHts(HTS).setIsTokenRc(address(usdc), 21);
        _refuse(abi.encodeWithSelector(HederaLib.HtsQueryFailed.selector, address(usdc), int64(21)));
    }

    function test_customFeeQueryFailureRefuses() public {
        MockHts(HTS).setFeesRc(address(usdc), 167);
        _refuse(abi.encodeWithSelector(HederaLib.HtsQueryFailed.selector, address(usdc), int64(167)));
    }

    function test_undecodableCustomFeesRefuse() public {
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Malformed);
        _refuse(abi.encodeWithSelector(HederaLib.HtsQueryFailed.selector, address(usdc), int64(22)));
    }

    function test_anyCustomFeeRefuses() public {
        bytes memory e = abi.encodeWithSelector(IWrappedToken.UnderlyingInvalid.selector, address(usdc));
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fixed);
        _refuse(e);
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fractional);
        _refuse(e);
        MockHts(HTS).setFees(address(usdc), MockHts.Fees.Royalty);
        _refuse(e);
    }

    function test_associationFailureRefuses() public {
        MockHts(HTS).force(15);
        _refuse(abi.encodeWithSelector(HederaLib.AssociateFailed.selector, int64(15)));
    }

    function test_absentPrecompileRefuses() public {
        vm.etch(HTS, "");
        _refuse(abi.encodeWithSelector(HederaLib.HtsQueryFailed.selector, address(usdc), int64(-1)));
    }
}
