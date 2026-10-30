// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// dex.md CTR-DEX-25 (UA-5b): the sell token's side of a `UATradeOrder` — CTR-DEX-15 steps 1–8 on ids, step 4 under the
/// UA purpose `trade`, the move through the UA ledger, one `minNonce` floor per id across both structs, and the
/// signature checked once (`pulled[h] ≠ 0`, both paths). This test contract plays the DEX (a contract, `o.dex`).
contract UATradeTest is UALedgerBase {
    address internal constant OTHER = address(0x07E5);

    function setUp() public override {
        super.setUp();
        _fund(uaP, 10_000);
        _fund(uaB, 10_000);
    }

    // ----- orders and auths -----

    function _o(bytes32 from, uint256 amount, uint256 receiveAmount)
        internal view returns (ITradeToken.UATradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = address(wrp);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(this);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _native(uint256 amount, uint256 receiveAmount) internal view returns (ITradeToken.TradeOrder memory o) {
        o.from = alice;
        o.receiveToken = address(wrp);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(this);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    /// A native id signs `digest` itself; a derived one through the registry under `purpose`.
    function _authP(bytes32 from, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        if (from == _pad(alice)) return _ecdsa(ALICE_PK, digest);
        if (from == _pad(bob)) return _ecdsa(BOB_PK, digest);
        if (from == uaZ) return _zAuth(purpose, digest);
        uint16 kind = lreg.kindOf(from);
        return _auth(lreg, kind, _key(kind), purpose, digest);
    }

    function _a(ITradeToken.UATradeOrder memory o) internal view returns (bytes memory) {
        return _authP(o.from, UAKinds.PURPOSE_TRADE, tok.uaTradeOrderDigest(o));
    }

    function _f(uint256 sell, uint256 recv, uint256 fee) internal pure returns (ITradeToken.TradeFill memory) {
        return ITradeToken.TradeFill(sell, recv, fee, RELAYER);
    }

    function _trade(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        tok.uaTrade(o, _a(o), f);
    }

    function _expect(bytes4 sel, ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        bytes memory auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(sel, tok.uaTradeOrderDigest(o)));
        tok.uaTrade(o, auth, f);
    }

    // ----- digests -----

    function test_digests_typehashes() public view {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        assertEq(TradeLib.UA_TRADE_ORDER_TYPEHASH, keccak256(
            "UATradeOrder(bytes32 from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,"
            "uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,"
            "uint256 validUntil)"));
        assertEq(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH,
            keccak256("UAInvalidateNonces(bytes32 from,uint256 batch,uint256 minNonce)"));
        assertEq(UAKinds.PURPOSE_TRADE, keccak256("scaas.ua.purpose.trade.v1"));
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = tok.eip712Domain();
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
        // a static struct encodes inline: the typehash then the 13 fields in order
        bytes32 sh = keccak256(abi.encode(TradeLib.UA_TRADE_ORDER_TYPEHASH, o));
        assertEq(tok.uaTradeOrderDigest(o), keccak256(abi.encodePacked(hex"1901", sep, sh)));
        assertEq(tok.uaInvalidateNoncesDigest(uaP, 1, 5), keccak256(abi.encodePacked(hex"1901", sep,
            keccak256(abi.encode(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH, uaP, uint256(1), uint256(5))))));
        // the same fields as a `TradeOrder` (a padded native) hash differently: another typehash
        o.from = _pad(alice);
        assertTrue(tok.uaTradeOrderDigest(o) != tok.tradeOrderDigest(_native(1000, 2000)));
    }

    // ----- Path A, Path B, the move -----

    function test_derived_pathA_movesToTheDex_thenTheRemainderCloses() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.uaTradeOrderDigest(o);
        uint256 pool = tok.balanceOf(POOL);
        vm.expectEmit(address(tok));
        emit ITradeToken.UATradeFilled(h, uaP, 600, 1200, 0);
        vm.expectEmit(address(tok));
        emit IERC20.Transfer(POOL, address(this), 600);
        vm.expectEmit(address(tok));
        emit IUALedger.UATransfer(uaP, _pad(address(this)), 600);
        _trade(o, _f(600, 1200, 0));
        assertEq(tok.balanceOfUA(uaP), 10_000 - 600);
        assertEq(tok.balanceOf(address(this)), 600);
        assertEq(tok.balanceOf(POOL), pool - 600);
        assertEq(tok.pulled(h), 600);
        _trade(o, _f(400, 800, 0)); // the remainder may close below the minimum
        assertEq(tok.pulled(h), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(1, 2, 0));
        assertEq(tok.balanceOf(POOL), pool - 1000);
    }

    function test_nativeId_signsItself_andSellsItsErc20Balance() public {
        ITradeToken.UATradeOrder memory o = _o(_pad(alice), 1000, 2000);
        bytes32 h = tok.uaTradeOrderDigest(o);
        uint256 before = tok.balanceOf(alice);
        uint256 pool = tok.balanceOf(POOL);
        vm.expectEmit(address(tok));
        emit ITradeToken.UATradeFilled(h, _pad(alice), 1000, 2000, 0);
        _trade(o, _f(1000, 2000, 0));
        assertEq(tok.balanceOf(alice), before - 1000);
        assertEq(tok.balanceOf(address(this)), 1000);
        assertEq(tok.balanceOf(POOL), pool);
        // a registry `trade` auth is not a native signature
        ITradeToken.UATradeOrder memory o2 = _o(_pad(alice), 1000, 2000);
        o2.nonce = 2;
        bytes memory bad = _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_TRADE, tok.uaTradeOrderDigest(o2));
        vm.expectRevert();
        tok.uaTrade(o2, bad, _f(1000, 2000, 0));
    }

    function test_pathB_escrow_onTheUAShape() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        o.flags = 3; // IOC | ESCROW
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(999, 0, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(1000, 2000, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(1000, 0, 1));
        _trade(o, _f(1000, 0, 0));
        assertEq(tok.balanceOfUA(uaB), 9_000);
        assertEq(tok.pulled(tok.uaTradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(1000, 0, 0));
    }

    function test_ioc_closesAtItsSinglePull() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        o.flags = 1;
        _trade(o, _f(600, 1200, 0));
        assertEq(tok.pulled(tok.uaTradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(400, 800, 0));
    }

    /// Every CTR-DEX-15 error on the UA shape, in the spec's order of checks.
    function test_matrix_everyCheck() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes memory auth = _a(o);
        // 1. caller and identities
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, OTHER));
        tok.uaTrade(o, auth, _f(600, 1200, 0));
        o.dex = OTHER; // an EOA
        auth = _a(o);
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.DexNotContract.selector, OTHER));
        tok.uaTrade(o, auth, _f(600, 1200, 0));
        o = _o(_pad(address(tok)), 1000, 2000);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, tok.uaTradeOrderDigest(o)));
        tok.uaTrade(o, "", _f(600, 1200, 0));
        o = _o(uaP, 1000, 2000);
        o.dex = address(tok);
        auth = _a(o);
        bytes32 h = tok.uaTradeOrderDigest(o);
        vm.prank(address(tok));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, h));
        tok.uaTrade(o, auth, _f(600, 1200, 0));
        // 2. relayer
        o = _o(uaP, 1000, 2000);
        o.relayer = OTHER;
        auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, tok.uaTradeOrderDigest(o), RELAYER));
        tok.uaTrade(o, auth, _f(600, 1200, 0));
        // 3. shape
        o = _o(uaP, 1000, 2000);
        o.validUntil = block.timestamp - 1;
        _expect(ITradeToken.OrderExpired.selector, o, _f(600, 1200, 0));
        o = _o(uaP, 1000, 2000);
        o.flags = 2; // ESCROW without IOC
        _expect(ITradeToken.BadFlags.selector, o, _f(1000, 0, 0));
        o.flags = 8;
        _expect(ITradeToken.BadFlags.selector, o, _f(600, 1200, 0));
        o = _o(uaP, 0, 2000);
        _expect(ITradeToken.ZeroAmount.selector, o, _f(0, 0, 0));
        o = _o(uaP, 1000, 0);
        _expect(ITradeToken.ZeroAmount.selector, o, _f(600, 0, 0));
        o = _o(uaP, 1000, 2000);
        o.minFill = 1001;
        _expect(ITradeToken.BadMinFill.selector, o, _f(1000, 2000, 0));
        o = _o(uaP, 1000, 2000);
        o.fee = 10_001;
        _expect(ITradeToken.FeeAboveCap.selector, o, _f(600, 1200, 0));
        // 6. Path A bounds
        o = _o(uaP, 1000, 2000);
        _expect(ITradeToken.ZeroFill.selector, o, _f(0, 0, 0));
        _expect(ITradeToken.Overfill.selector, o, _f(1001, 2002, 0));
        o.minFill = 500;
        _expect(ITradeToken.BelowMinFill.selector, o, _f(499, 998, 0));
        _expect(ITradeToken.PriceLimit.selector, o, _f(600, 1199, 0));
        _expect(ITradeToken.FeeAboveSigned.selector, o, _f(600, 1200, 1));
        o.minFill = 800;
        _expect(ITradeToken.BelowMinFill.selector, o, _f(700, 1400, 0));
        o.fee = 3_000; // ceil(1600 * 0.3 %) = 5
        _expect(ITradeToken.FeeAboveSigned.selector, o, _f(800, 1600, 6));
        _trade(o, _f(800, 1600, 5));
    }

    function test_uaTrade_belowHalfSettles() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000); // minFill 0: no floor
        _trade(o, _f(100, 200, 0));
        assertEq(tok.pulled(tok.uaTradeOrderDigest(o)), 100);
    }

    function test_ua_minFill_remainderClosesBelowMinFill() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        o.minFill = 300;
        _trade(o, _f(800, 1600, 0));
        _trade(o, _f(200, 400, 0)); // the remainder, below minFill
        assertEq(tok.pulled(tok.uaTradeOrderDigest(o)), 1000);
    }

    function test_nonceFloor_and_balance() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        tok.uaInvalidateNonces(uaP, 1, 2, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.uaInvalidateNoncesDigest(uaP, 1, 2)));
        _expect(ITradeToken.NonceInvalidated.selector, o, _f(600, 1200, 0));
        o.batch = 2; // another lane
        _trade(o, _f(600, 1200, 0));
        o = _o(uaP, 20_000, 40_000);
        o.batch = 3;
        bytes memory auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAInsufficientBalance.selector, uaP, 9_400, 20_000));
        tok.uaTrade(o, auth, _f(20_000, 40_000, 0));
    }

    // ----- step 4: the UA rule under `trade` -----

    function test_auth_purposeSignerAndKind() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.uaTradeOrderDigest(o);
        // a `metatx` auth over the same digest is refused (purposes separate uses)
        bytes memory wrongPurpose = _authP(uaP, UAKinds.PURPOSE_METATX, h);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.uaTrade(o, wrongPurpose, _f(600, 1200, 0));
        // another UA's auth
        bytes memory other = _authP(uaB, UAKinds.PURPOSE_TRADE, h);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.uaTrade(o, other, _f(600, 1200, 0));
        // the Zether UA signs under `trade` like any SIGNING UA (UA-6 U8): its `metatx` signature is refused
        o.from = uaZ;
        bytes memory zWrong = _authP(uaZ, UAKinds.PURPOSE_METATX, tok.uaTradeOrderDigest(o));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaZ));
        tok.uaTrade(o, zWrong, _f(600, 1200, 0));
        // UA_POOL as a native id
        o.from = _pad(POOL);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.uaTrade(o, "", _f(600, 1200, 0));
    }

    /// C5-2: the native id 0 is not a signer on the UA path (its fee move would be a mint).
    function test_C5_2_nativeIdZeroRefused() public {
        ITradeToken.UATradeOrder memory o = _o(bytes32(0), 1000, 2000);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, bytes32(0)));
        tok.uaTrade(o, "", _f(600, 1200, 0));
    }

    function test_ledgerOff_everyUATradeFunction() public {
        NormalToken off = NormalToken(Clones.clone(address(
            new NormalToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), ""))));
        off.initialize(address(this), 1, abi.encode(normalInit("Off", "OFF", 6, 1_000_000, alice, address(this))));
        ITradeToken.UATradeOrder memory o = _o(_pad(alice), 1000, 2000);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.uaTrade(o, "", _f(600, 1200, 0));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.uaCancelOrder(o, "");
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.uaInvalidateNonces(_pad(alice), 1, 2, "");
    }

    // ----- UP-12: verified once -----

    function test_verifiedOnce_uaPath() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes memory other = _authP(uaP, UAKinds.PURPOSE_TRADE, bytes32(0)); // a valid auth over another digest
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.uaTrade(o, other, _f(600, 1200, 0)); // the first pull always verifies
        bytes memory auth = _a(o);
        uint256 g = gasleft();
        tok.uaTrade(o, auth, _f(600, 1200, 0));
        uint256 first = g - gasleft();
        g = gasleft();
        tok.uaTrade(o, hex"00", _f(400, 800, 0)); // pulled[h] ≠ 0: no second check
        uint256 second = g - gasleft();
        emit log_named_uint("uaTrade first fill (p256 stand-in verify)", first);
        emit log_named_uint("uaTrade second fill (no verify)", second);
        assertEq(tok.balanceOfUA(uaP), 9_000);
    }

    function test_verifiedOnce_addressPath() public {
        ITradeToken.TradeOrder memory o = _native(1000, 2000);
        vm.expectRevert();
        tok.mtxTrade(o, hex"00", _f(600, 1200, 0));
        tok.mtxTrade(o, _ecdsa(ALICE_PK, tok.tradeOrderDigest(o)), _f(600, 1200, 0));
        tok.mtxTrade(o, hex"00", _f(400, 800, 0));
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 1000);
    }

    /// A cancelled order is closed: the skipped check never opens it (pulled = amount ⇒ `OrderClosed`).
    function test_verifiedOnce_neverAfterACancel() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.uaTradeOrderDigest(o);
        tok.uaCancelOrder(o, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.cancelOrderDigest(h)));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.OrderClosed.selector, h));
        tok.uaTrade(o, hex"00", _f(600, 1200, 0));
    }

    // ----- cancel and invalidate -----

    function test_cancel_neverExpires_idempotent_signerBound() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        bytes32 h = tok.uaTradeOrderDigest(o);
        bytes32 cd = tok.cancelOrderDigest(h);
        bytes memory wrong = _authP(uaP, UAKinds.PURPOSE_TRADE, cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.uaCancelOrder(o, wrong);
        bytes memory meta = _authP(uaB, UAKinds.PURPOSE_METATX, cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.uaCancelOrder(o, meta);
        vm.warp(o.validUntil + 365 days); // a cancel never expires
        bytes memory auth = _authP(uaB, UAKinds.PURPOSE_TRADE, cd);
        vm.expectEmit(address(tok));
        emit ITradeToken.UAOrderCancelled(h, uaB);
        vm.prank(OTHER); // anyone submits
        tok.uaCancelOrder(o, auth);
        assertEq(tok.pulled(h), 1000);
        vm.recordLogs();
        tok.uaCancelOrder(o, auth); // closed: a no-op
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_cancel_aPartlyFilledOrder_closesTheRemainder() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        _trade(o, _f(600, 1200, 0));
        bytes32 h = tok.uaTradeOrderDigest(o);
        tok.uaCancelOrder(o, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.cancelOrderDigest(h)));
        assertEq(tok.pulled(h), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(400, 800, 0));
    }

    function test_invalidate_strictlyUp_cap_events() public {
        bytes memory a5 = _authP(uaP, UAKinds.PURPOSE_TRADE, tok.uaInvalidateNoncesDigest(uaP, 1, 5));
        vm.expectEmit(address(tok));
        emit ITradeToken.UANoncesInvalidated(uaP, 1, 5);
        tok.uaInvalidateNonces(uaP, 1, 5, a5);
        assertEq(tok.uaMinNonce(uaP, 1), 5);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 5, 5));
        tok.uaInvalidateNonces(uaP, 1, 5, a5);
        uint256 big = 2 ** 128 + 1;
        bytes memory ab = _authP(uaP, UAKinds.PURPOSE_TRADE, tok.uaInvalidateNoncesDigest(uaP, 1, big));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceAboveCap.selector, big));
        tok.uaInvalidateNonces(uaP, 1, big, ab);
        bytes memory wrong = _authP(uaB, UAKinds.PURPOSE_TRADE, tok.uaInvalidateNoncesDigest(uaP, 1, 6));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.uaInvalidateNonces(uaP, 1, 6, wrong);
    }

    /// One floor per id: the address path raises the padded id's floor and the UA path the address's.
    function test_sharedFloors_bothWays() public {
        vm.expectEmit(address(tok));
        emit ITradeToken.NoncesInvalidated(alice, 1, 3);
        tok.mtxInvalidateNonces(alice, 1, 3, _ecdsa(ALICE_PK, tok.invalidateNoncesDigest(alice, 1, 3)));
        assertEq(tok.uaMinNonce(_pad(alice), 1), 3);
        ITradeToken.UATradeOrder memory o = _o(_pad(alice), 1000, 2000);
        o.nonce = 2;
        _expect(ITradeToken.NonceInvalidated.selector, o, _f(600, 1200, 0));
        bytes32 d = tok.uaInvalidateNoncesDigest(_pad(alice), 1, 7);
        vm.expectEmit(address(tok));
        emit ITradeToken.UANoncesInvalidated(_pad(alice), 1, 7);
        tok.uaInvalidateNonces(_pad(alice), 1, 7, _ecdsa(ALICE_PK, d));
        assertEq(tok.minNonce(alice, 1), 7);
        ITradeToken.TradeOrder memory n = _native(1000, 2000);
        n.nonce = 6;
        bytes memory sig = _ecdsa(ALICE_PK, tok.tradeOrderDigest(n));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NonceInvalidated.selector, tok.tradeOrderDigest(n)));
        tok.mtxTrade(n, sig, _f(600, 1200, 0));
        bytes memory back = _ecdsa(ALICE_PK, tok.invalidateNoncesDigest(alice, 1, 7));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 7, 7));
        tok.mtxInvalidateNonces(alice, 1, 7, back);
    }

    /// The same fields as a `TradeOrder` and as a `UATradeOrder` are two orders (two digests): cancelling one leaves the
    /// other open.
    function test_twoStructs_twoOrders() public {
        ITradeToken.TradeOrder memory n = _native(1000, 2000);
        ITradeToken.UATradeOrder memory u = _o(_pad(alice), 1000, 2000);
        bytes32 hn = tok.tradeOrderDigest(n);
        tok.mtxCancelOrder(n, _ecdsa(ALICE_PK, tok.cancelOrderDigest(hn)));
        assertEq(tok.pulled(hn), 1000);
        _trade(u, _f(600, 1200, 0));
        assertEq(tok.pulled(tok.uaTradeOrderDigest(u)), 600);
    }
}
