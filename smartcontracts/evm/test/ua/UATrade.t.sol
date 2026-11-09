// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {DexLegs} from "../helpers/DexLegs.sol";
import {OrderJson} from "../helpers/OrderJson.sol";
import {domainOf} from "../metatx/NamedEntry.t.sol";
import {UACall} from "./UACall.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

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
        return _authP(o.from, UAKinds.PURPOSE_TRADE, tok.tradeOrderDigest(o));
    }

    function _f(uint256 sell, uint256 recv, uint256 fee) internal pure returns (ITradeToken.TradeFill memory) {
        return ITradeToken.TradeFill(sell, recv, fee, RELAYER);
    }

    function _trade(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        tok.mtxTrade(o, UACall.auth(o.from, _a(o)), f);
    }

    function _expect(bytes4 sel, ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        bytes memory auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(sel, tok.tradeOrderDigest(o)));
        tok.mtxTrade(o, UACall.auth(o.from, auth), f);
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
        assertEq(tok.tradeOrderDigest(o), keccak256(abi.encodePacked(hex"1901", sep, sh)));
        assertEq(tok.invalidateNoncesDigest(uaP, 1, 5), keccak256(abi.encodePacked(hex"1901", sep,
            keccak256(abi.encode(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH, uaP, uint256(1), uint256(5))))));
        // ua-mtx-merge T6 (R12), meaning: the token has one order struct; an address-shaped order is the padded
        // `UATradeOrder` (was: the same fields as a `TradeOrder` hashed differently, another typehash)
        o.from = _pad(alice);
        assertEq(tok.tradeOrderDigest(o), tok.tradeOrderDigest(DexLegs.ua(_native(1000, 2000))));
    }

    // ----- Path A, Path B, the move -----

    function test_derived_pathA_movesToTheDex_thenTheRemainderCloses() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
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

    /// T66b rule 4 (spec §4.1): the token's trade body runs `TradeLib`'s code compiled into module T, no DELEGATECALL to the
    /// library; positive control: the library's own entry still answers a call (the DEX's path).
    /// The trade authorisation too (`_pipeAuthorize`, `MtxPipelineLib`'s code compiled into T): no call to that library.
    function test_rule4_tokenTradeCallsNoTradeLib() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        TradeLib.cancelHash(o); // control: the library is linked here and answers
        MtxPipelineLib.Envelope memory none;
        MtxPipelineLib.callDigest(bytes32(0), bytes32(0), none); // control
        vm.expectCall(address(TradeLib), "", 0);
        vm.expectCall(address(MtxPipelineLib), "", 0);
        _trade(o, _f(600, 1200, 0));
        tok.cancelOrderDigest(o);
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 600);
    }

    function test_nativeId_signsItself_andSellsItsErc20Balance() public {
        ITradeToken.UATradeOrder memory o = _o(_pad(alice), 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
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
        bytes memory bad = _auth(lreg, UAKinds.P256, _key(UAKinds.P256), UAKinds.PURPOSE_TRADE, tok.tradeOrderDigest(o2));
        vm.expectRevert();
        tok.mtxTrade(o2, UACall.auth(o2.from, bad), _f(1000, 2000, 0));
    }

    function test_pathB_escrow_onTheUAShape() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        o.flags = 3; // IOC | ESCROW
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(999, 0, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(1000, 2000, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _f(1000, 0, 1));
        _trade(o, _f(1000, 0, 0));
        assertEq(tok.balanceOfUA(uaB), 9_000);
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(1000, 0, 0));
    }

    function test_ioc_closesAtItsSinglePull() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        o.flags = 1;
        _trade(o, _f(600, 1200, 0));
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(400, 800, 0));
    }

    /// Every CTR-DEX-15 error on the UA shape, in the spec's order of checks.
    function test_matrix_everyCheck() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes memory auth = _a(o);
        // 1. caller and identities
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, OTHER));
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(600, 1200, 0));
        o.dex = OTHER; // an EOA
        auth = _a(o);
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.DexNotContract.selector, OTHER));
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(600, 1200, 0));
        o = _o(_pad(address(tok)), 1000, 2000);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, tok.tradeOrderDigest(o)));
        tok.mtxTrade(o, UACall.auth(o.from, ""), _f(600, 1200, 0));
        o = _o(uaP, 1000, 2000);
        o.dex = address(tok);
        auth = _a(o);
        bytes32 h = tok.tradeOrderDigest(o);
        vm.prank(address(tok));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, h));
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(600, 1200, 0));
        // 2. relayer
        o = _o(uaP, 1000, 2000);
        o.relayer = OTHER;
        auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, tok.tradeOrderDigest(o), RELAYER));
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(600, 1200, 0));
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
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 100);
    }

    function test_ua_minFill_remainderClosesBelowMinFill() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        o.minFill = 300;
        _trade(o, _f(800, 1600, 0));
        _trade(o, _f(200, 400, 0)); // the remainder, below minFill
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 1000);
    }

    function test_nonceFloor_and_balance() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        tok.mtxInvalidateNonces(uaP, 1, 2, UACall.auth(uaP, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.invalidateNoncesDigest(uaP, 1, 2))));
        _expect(ITradeToken.NonceInvalidated.selector, o, _f(600, 1200, 0));
        o.batch = 2; // another lane
        _trade(o, _f(600, 1200, 0));
        o = _o(uaP, 20_000, 40_000);
        o.batch = 3;
        bytes memory auth = _a(o);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAInsufficientBalance.selector, uaP, 9_400, 20_000));
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(20_000, 40_000, 0));
    }

    // ----- step 4: the UA rule under `trade` -----

    function test_auth_purposeSignerAndKind() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
        // a `metatx` auth over the same digest is refused (purposes separate uses)
        bytes memory wrongPurpose = _authP(uaP, UAKinds.PURPOSE_METATX, h);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.mtxTrade(o, UACall.auth(o.from, wrongPurpose), _f(600, 1200, 0));
        // another UA's auth
        bytes memory other = _authP(uaB, UAKinds.PURPOSE_TRADE, h);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.mtxTrade(o, UACall.auth(o.from, other), _f(600, 1200, 0));
        // the Zether UA signs under `trade` like any SIGNING UA (UA-6 U8): its `metatx` signature is refused
        o.from = uaZ;
        bytes memory zWrong = _authP(uaZ, UAKinds.PURPOSE_METATX, tok.tradeOrderDigest(o));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaZ));
        tok.mtxTrade(o, UACall.auth(o.from, zWrong), _f(600, 1200, 0));
        // UA_POOL as a native id
        o.from = _pad(POOL);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.mtxTrade(o, UACall.auth(o.from, ""), _f(600, 1200, 0));
    }

    /// C5-2: the native id 0 is not a signer on the UA path (its fee move would be a mint).
    function test_C5_2_nativeIdZeroRefused() public {
        ITradeToken.UATradeOrder memory o = _o(bytes32(0), 1000, 2000);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, bytes32(0)));
        tok.mtxTrade(o, UACall.auth(o.from, ""), _f(600, 1200, 0));
    }

    function test_ledgerOff_everyUATradeFunction() public {
        NormalToken off = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))),
            EnvKit.env(chainUidA, address(0), address(0), false)));
        off.initialize(nid(address(this)), 1, abi.encode(normalInit("Off", "OFF", 6, 1_000_000, alice, address(this))));
        ITradeToken.UATradeOrder memory o = _o(_pad(alice), 1000, 2000);
        // ua-mtx-merge T3, meaning (C, R9; pulled forward from T6 for R39's `mtxWrapOrder`): `uaTrade` needs a registry only
        // for a derived seller; a native seller's order is checked by its own key (here an empty signature, refused), the
        // derived seller is `UALedgerOff` by name
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        off.mtxTrade(o, UACall.auth(o.from, ""), _f(600, 1200, 0));
        ITradeToken.UATradeOrder memory d = _o(uaP, 1000, 2000);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mtxTrade(d, UACall.auth(d.from, ""), _f(600, 1200, 0));
        // ua-mtx-merge T6, meaning (C; carried from T3): the merged cancel and invalidate need a registry only for a
        // derived id too; a native id's empty signature is refused by its own rule (was: `UALedgerOff` for every id)
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        off.mtxCancelOrder(o, UACall.auth(o.from, ""));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        off.mtxInvalidateNonces(_pad(alice), 1, 2, UACall.auth(_pad(alice), ""));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mtxCancelOrder(d, UACall.auth(d.from, ""));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mtxInvalidateNonces(uaP, 1, 2, UACall.auth(uaP, ""));
    }

    // ----- UP-12: verified once -----

    function test_verifiedOnce_uaPath() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes memory other = _authP(uaP, UAKinds.PURPOSE_TRADE, bytes32(0)); // a valid auth over another digest
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.mtxTrade(o, UACall.auth(o.from, other), _f(600, 1200, 0)); // the first pull always verifies
        bytes memory auth = _a(o);
        uint256 g = gasleft();
        tok.mtxTrade(o, UACall.auth(o.from, auth), _f(600, 1200, 0));
        uint256 first = g - gasleft();
        g = gasleft();
        tok.mtxTrade(o, UACall.auth(o.from, hex"00"), _f(400, 800, 0)); // pulled[h] ≠ 0: no second check
        uint256 second = g - gasleft();
        emit log_named_uint("uaTrade first fill (p256 stand-in verify)", first);
        emit log_named_uint("uaTrade second fill (no verify)", second);
        assertEq(tok.balanceOfUA(uaP), 9_000);
    }

    /// ua-mtx-merge T6 (R12), meaning: was `_addressPath` (the address `mtxTrade(TradeOrder, bytes, …)`, now in
    /// legacy/ua-mtx-merge/); the same check on the one entry for a native id (its address zero-padded).
    function test_verifiedOnce_native() public {
        ITradeToken.UATradeOrder memory o = DexLegs.ua(_native(1000, 2000));
        vm.expectRevert();
        tok.mtxTrade(o, DexLegs.sigOf(hex"00"), _f(600, 1200, 0));
        tok.mtxTrade(o, DexLegs.sigOf(_ecdsa(ALICE_PK, tok.tradeOrderDigest(o))), _f(600, 1200, 0));
        tok.mtxTrade(o, DexLegs.sigOf(hex"00"), _f(400, 800, 0));
        assertEq(tok.pulled(tok.tradeOrderDigest(o)), 1000);
    }

    /// A cancelled order is closed: the skipped check never opens it (pulled = amount ⇒ `OrderClosed`).
    function test_verifiedOnce_neverAfterACancel() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
        tok.mtxCancelOrder(o, UACall.auth(o.from, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.cancelOrderDigest(o))));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.OrderClosed.selector, h));
        tok.mtxTrade(o, UACall.auth(o.from, hex"00"), _f(600, 1200, 0));
    }

    // ----- cancel and invalidate -----

    function test_cancel_neverExpires_idempotent_signerBound() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
        bytes32 cd = tok.cancelOrderDigest(o);
        bytes memory wrong = _authP(uaP, UAKinds.PURPOSE_TRADE, cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.mtxCancelOrder(o, UACall.auth(o.from, wrong));
        bytes memory meta = _authP(uaB, UAKinds.PURPOSE_METATX, cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.mtxCancelOrder(o, UACall.auth(o.from, meta));
        vm.warp(o.validUntil + 365 days); // a cancel never expires
        bytes memory auth = _authP(uaB, UAKinds.PURPOSE_TRADE, cd);
        vm.expectEmit(address(tok));
        emit ITradeToken.UAOrderCancelled(h, uaB);
        vm.prank(OTHER); // anyone submits
        tok.mtxCancelOrder(o, UACall.auth(o.from, auth));
        assertEq(tok.pulled(h), 1000);
        vm.recordLogs();
        tok.mtxCancelOrder(o, UACall.auth(o.from, auth)); // closed: a no-op
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// `CancelUAOrder` nests the order (TS-D19): the wallet's JSON is the digest, authorized under `trade`. The pre-C6
    /// `CancelOrder(bytes32 orderHash)` of the same order, the only change, is `UAUnauthorized`; the nested one closes it.
    function test_cancelUAOrderNested() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        bytes32 h = tok.tradeOrderDigest(o);
        bytes32 wallet = OrderJson.cancelTrade(address(tok), o, true);
        assertEq(tok.cancelOrderDigest(o), wallet);
        bytes32 flat = keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)),
            keccak256(abi.encode(keccak256("CancelOrder(bytes32 orderHash)"), h))));
        bytes memory old = _authP(uaB, UAKinds.PURPOSE_TRADE, flat);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.mtxCancelOrder(o, UACall.auth(o.from, old));
        assertEq(tok.pulled(h), 0);
        tok.mtxCancelOrder(o, UACall.auth(o.from, _authP(uaB, UAKinds.PURPOSE_TRADE, wallet)));
        assertEq(tok.pulled(h), 1000);
    }

    /// A UA's wrap order: `UAWrapOrder`, cancelled as `CancelUAWrapOrder`; `CancelUAOrder` of its order form is refused.
    function test_cancelUAWrapOrderNested() public {
        ITradeToken.UATradeOrder memory o = _o(uaB, 1000, 2000);
        o.receiveToken = o.dex;
        assertEq(tok.tradeOrderDigest(o), OrderJson.wrap(address(tok), o, true));
        bytes32 h = tok.tradeOrderDigest(o);
        bytes32 wallet = OrderJson.cancelWrap(address(tok), o, true);
        assertEq(tok.cancelOrderDigest(o), wallet);
        bytes memory asTrade = _authP(uaB, UAKinds.PURPOSE_TRADE, OrderJson.cancelTrade(address(tok), o, true));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaB));
        tok.mtxCancelOrder(o, UACall.auth(o.from, asTrade));
        assertEq(tok.pulled(h), 0);
        tok.mtxCancelOrder(o, UACall.auth(o.from, _authP(uaB, UAKinds.PURPOSE_TRADE, wallet)));
        assertEq(tok.pulled(h), 1000);
    }

    function test_cancel_aPartlyFilledOrder_closesTheRemainder() public {
        ITradeToken.UATradeOrder memory o = _o(uaP, 1000, 2000);
        _trade(o, _f(600, 1200, 0));
        bytes32 h = tok.tradeOrderDigest(o);
        tok.mtxCancelOrder(o, UACall.auth(o.from, _authP(uaP, UAKinds.PURPOSE_TRADE, tok.cancelOrderDigest(o))));
        assertEq(tok.pulled(h), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _f(400, 800, 0));
    }

    function test_invalidate_strictlyUp_cap_events() public {
        bytes memory a5 = _authP(uaP, UAKinds.PURPOSE_TRADE, tok.invalidateNoncesDigest(uaP, 1, 5));
        vm.expectEmit(address(tok));
        emit ITradeToken.UANoncesInvalidated(uaP, 1, 5);
        tok.mtxInvalidateNonces(uaP, 1, 5, UACall.auth(uaP, a5));
        assertEq(tok.minNonce(uaP, 1), 5);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 5, 5));
        tok.mtxInvalidateNonces(uaP, 1, 5, UACall.auth(uaP, a5));
        uint256 big = 2 ** 128 + 1;
        bytes memory ab = _authP(uaP, UAKinds.PURPOSE_TRADE, tok.invalidateNoncesDigest(uaP, 1, big));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceAboveCap.selector, big));
        tok.mtxInvalidateNonces(uaP, 1, big, UACall.auth(uaP, ab));
        bytes memory wrong = _authP(uaB, UAKinds.PURPOSE_TRADE, tok.invalidateNoncesDigest(uaP, 1, 6));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.mtxInvalidateNonces(uaP, 1, 6, UACall.auth(uaP, wrong));
    }

    /// ua-mtx-merge T6 (R12), meaning: was `_bothWays` (the address `mtxInvalidateNonces(address, …)` and the UA one
    /// raising one floor); one entry now: a native id raises its padded id's floor by its own key, and an order under
    /// it is refused; the floor never goes back.
    function test_sharedFloors_nativeId() public {
        bytes32 me = _pad(alice);
        vm.expectEmit(address(tok));
        emit ITradeToken.UANoncesInvalidated(me, 1, 3);
        tok.mtxInvalidateNonces(me, 1, 3, UACall.auth(me, _ecdsa(ALICE_PK, tok.invalidateNoncesDigest(me, 1, 3))));
        assertEq(tok.minNonce(me, 1), 3);
        ITradeToken.UATradeOrder memory o = _o(me, 1000, 2000);
        o.nonce = 2;
        _expect(ITradeToken.NonceInvalidated.selector, o, _f(600, 1200, 0));
        bytes memory back = _ecdsa(ALICE_PK, tok.invalidateNoncesDigest(me, 1, 3));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 3, 3));
        tok.mtxInvalidateNonces(me, 1, 3, UACall.auth(me, back));
    }

    /// The address `TradeOrder` struct hash of `n` and its `CancelOrder` digest in `tok`'s domain (the retired forms).
    function _addressDigests(ITradeToken.TradeOrder memory n) internal view returns (bytes32 hn, bytes32 cn) {
        bytes32 sh = keccak256(abi.encode(keccak256("TradeOrder(address from,address receiveToken,uint256 amount,"
            "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,"
            "uint256 batch,uint256 nonce,uint256 validUntil)"), n)); // a static struct: its 13 words inline
        hn = keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)), sh));
        cn = keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)), keccak256(abi.encode(keccak256(
            "CancelOrder(TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,"
            "uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,"
            "uint256 nonce,uint256 validUntil)"), sh))));
    }

    /// ua-mtx-merge T6 (R12), meaning: was `test_twoStructs_twoOrders` (a `TradeOrder` and a `UATradeOrder` of the same
    /// fields, two orders); the token takes one struct: a signature over the address `TradeOrder` (and its
    /// `CancelOrder`) of the same fields is refused, nothing moves; the `UATradeOrder` signature settles.
    function test_addressStructRefused() public {
        ITradeToken.UATradeOrder memory u = _o(_pad(alice), 1000, 2000);
        (bytes32 hn, bytes32 cn) = _addressDigests(_native(1000, 2000));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxTrade(u, UACall.auth(u.from, _ecdsa(ALICE_PK, hn)), _f(600, 1200, 0));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxCancelOrder(u, UACall.auth(u.from, _ecdsa(ALICE_PK, cn)));
        assertEq(tok.pulled(tok.tradeOrderDigest(u)), 0);
        _trade(u, _f(600, 1200, 0));
        assertEq(tok.pulled(tok.tradeOrderDigest(u)), 600);
    }
}
