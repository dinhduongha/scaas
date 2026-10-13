// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {Burner1271, Bomb1271} from "./Dex.t.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

/// ERC-1271 wallet that needs ~100 k gas to say "valid": passes under 400 k (a `SmartKeyAccount` clone), not under 50 k.
contract Work1271 {
    function isValidSignature(bytes32 d, bytes calldata) external pure returns (bytes4) {
        for (uint256 i; i < 600; i++) d = keccak256(abi.encode(d, i));
        return d == bytes32(0) ? bytes4(0) : bytes4(0x1626ba7e);
    }
}

/// Credits the recipient 1 % more than sent (a positive rebase on transfer).
contract RebaseUpERC20 is MockERC20 {
    constructor() MockERC20("Up", "UP", 18) {}
    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && to != address(0)) super._update(address(0), to, v / 100);
    }
}

/// USDT-style: `transfer`/`transferFrom` return nothing.
contract NoReturnERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 v) external { balanceOf[to] += v; }
    function approve(address s, uint256 v) external { allowance[msg.sender][s] = v; }
    function transfer(address to, uint256 v) external { balanceOf[msg.sender] -= v; balanceOf[to] += v; }
    function transferFrom(address from, address to, uint256 v) external {
        allowance[from][msg.sender] -= v;
        balanceOf[from] -= v;
        balanceOf[to] += v;
    }
}

/// Reverts every pull with 320 000 bytes of revert data.
contract BombERC20 {
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        assembly { revert(0, 320000) }
    }
}

/// Code, no functions: "succeeds" at everything with no return data.
contract FallbackOnly {
    fallback() external {}
}

/// ERC-777-style hook token: every transfer calls `hook(from, to)` on `hookTarget`.
contract HookERC20 is MockERC20 {
    address public hookTarget;
    constructor() MockERC20("Hook", "HK", 18) {}
    function setHook(address h) external { hookTarget = h; }
    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && hookTarget != address(0)) Reenter(hookTarget).hook();
    }
}

/// Re-enters the DEX's four external entries from a token hook and records the first selector each reverts with.
contract Reenter {
    ISCaaSDex immutable dex;
    bytes4[] public errs;
    constructor(ISCaaSDex d) { dex = d; }
    function n() external view returns (uint256) { return errs.length; }
    function hook() external {
        if (errs.length != 0) return;
        DexLegs.Settlement[] memory ss = new DexLegs.Settlement[](0);
        try dex.mtxSettle(DexLegs.wire(ss)) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.mtxCancelOrders(new ISCaaSDex.DexOrder[](0), new bytes[](0)) { errs.push(0); }
        catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.mtxInvalidateNonces(address(1), 0, 1, "") { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        DexLegs.Settlement memory st;
        try SCaaSDex(address(dex)).settleOne(DexLegs.wire(st), address(this)) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        DexLegs.ExchangePlan memory ep;
        try dex.mtxExchange(DexLegs.wire(ep), new ISCaaSDex.Interaction[](0)) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.mtxExchangeVia(DexLegs.wire(ep), address(this), "") { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
    }
}

/// Outside-token legs (CTR-DEX-18, -22, -08, -02): the same `TradeOrder` signed in the DEX's domain as `DexOrder`, the
/// token's checks run by the DEX on its own state, the fill pulled through the `DexPuller` under the party's allowance
/// to the puller, `ESCROW` refused, cancels per DEX, the ERC-1271 cap by codehash, a bounded `MatchFailed` reason, a
/// starved signature check reverting the whole call, conservation catching inexact tokens.
contract DexOutsideTest is Test {
    // Starves the SCaaS taker's 400 k ERC-1271 check (the token's cap for a `work` clone). Measured (5 k steps) for that
    // batch: 305 k-745 k revert `SigCheckGasStarved` (below 305 k no data, from 750 k both settle); 530 k is mid-window.
    uint256 constant GAS_STARVED = 530_000;
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant DAVE_PK = 0xDA7E;
    address alice = vm.addr(ALICE_PK);
    address dave = vm.addr(DAVE_PK);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);
    OpenFactory f;
    SCaaSDex dex;
    address work;             // the "SmartKeyAccount implementation" of this chain
    NoUnderlyingToken a;      // SCaaS: Alice, the taker, sells it
    MockERC20 usdc;           // outside: Dave, the maker, sells it

    function setUp() public {
        work = address(new Work1271());
        f = new OpenFactory(address(this), UID_);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1,
            address(new NoUnderlyingToken(address(f), work, UID_, address(0), false)));
        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, work)));
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1,
            noneInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 0, treasury, false), "dex"));
        usdc = _list(new MockERC20("USD Coin", "USDC", 6));
        _fund(usdc, dave);
    }

    // ------------------------------------------------------------------ helpers

    function _list(MockERC20 t) internal returns (MockERC20) {
        vm.prank(admin);
        dex.setMarket(address(a), address(t), true);
        return t;
    }

    /// `who` holds 1e6 of `t` and approves the puller (read before the prank: an external call would consume it).
    function _fund(MockERC20 t, address who) internal {
        t.mint(who, 1e6);
        address p = dex.puller();
        vm.prank(who);
        t.approve(p, type(uint256).max);
    }

    function _order(address from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 nonce)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = nonce;
        o.validUntil = block.timestamp + 300;
    }

    function _outsideLeg(uint256 pk, address token, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (DexLegs.Leg memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dex.dexOrderDigest(token, o));
        return DexLegs.Leg(token, o, abi.encodePacked(r, s, v), fill);
    }

    /// Dave's order: sells 2000 of `token` for 1000 A.
    function _dave(address token, uint256 nonce, uint256 fill) internal view returns (DexLegs.Leg memory) {
        return _outsideLeg(DAVE_PK, token, _order(dave, address(a), 2000, 1000, nonce), fill);
    }

    /// Alice sells 1000 A for at least 2000 of the maker's token, filled at the maker's price.
    function _settlement(DexLegs.Leg memory maker, uint256 takerNonce)
        internal view returns (DexLegs.Settlement memory s)
    {
        s.ref = bytes32(takerNonce);
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = maker;
        s.taker = _taker(_order(alice, maker.sellToken, 1000, 2000, takerNonce), (maker.fill + 1) / 2);
    }

    function _taker(ITradeToken.TradeOrder memory t, uint256 fill) internal view returns (DexLegs.Leg memory) {
        return DexLegs.Leg(address(a), t, _sig(ALICE_PK, a.tradeOrderDigest(t)), fill);
    }

    function _one(DexLegs.Settlement memory s) internal pure returns (DexLegs.Settlement[] memory ss) {
        ss = new DexLegs.Settlement[](1);
        ss[0] = s;
    }

    function _two(DexLegs.Settlement memory s0, DexLegs.Settlement memory s1)
        internal pure returns (DexLegs.Settlement[] memory ss)
    {
        ss = new DexLegs.Settlement[](2);
        ss[0] = s0;
        ss[1] = s1;
    }

    function _expectOne(DexLegs.Settlement memory s, bytes memory err) internal {
        vm.prank(address(dex));
        vm.expectRevert(err);
        dex.settleOne(DexLegs.wire(s), relayer);
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------------ the leg

    function test_outsideMaker_pulledThroughThePuller() public {
        DexLegs.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        bytes32 h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        address p = dex.puller();
        DexLegs.Settlement[] memory ss = _one(s);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.TradeFilled(h, dave, 2000, 1000, 0);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(usdc.balanceOf(alice), 2000);
        assertEq(a.balanceOf(dave), 1000);
        assertEq(usdc.balanceOf(dave), 1e6 - 2000);
        assertEq(usdc.balanceOf(address(dex)), 0);
        assertEq(usdc.balanceOf(p), 0);
        assertEq(dex.pulled(h), 2000);
        assertEq(usdc.allowance(dave, address(dex)), 0); // the DEX holds no allowance
    }

    function test_outsideOrder_isCheckedByTheDex() public {
        ITradeToken.TradeOrder memory mo = _order(dave, address(a), 2000, 1000, 1);
        mo.flags = 3; // IOC | ESCROW: refused for outside legs
        DexLegs.Settlement memory s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        bytes32 h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadFlags.selector, h));
        s = _settlement(_dave(address(usdc), 1, 2000), 1);
        s.makers[0].sig[0] = bytes1(uint8(s.makers[0].sig[0]) ^ 1);
        h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
        mo = _order(dave, address(a), 2000, 1000, 1);
        mo.validUntil = block.timestamp - 1;
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OrderExpired.selector, h));
        mo = _order(address(usdc), address(a), 2000, 1000, 1); // `from` is the sell token itself
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1);
        h = dex.dexOrderDigest(address(usdc), mo);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.SelfOrder.selector, h));
        mo = _order(dave, address(a), 2000, 1000, 1);
        mo.flags = 1; // IOC alone is allowed
        s = _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 1000), 1);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(dex.pulled(dex.dexOrderDigest(address(usdc), mo)), 2000); // IOC: closed at its one pull
    }

    /// Path A bounds on an outside leg are the DEX's (`TradeLib.record` on its own state): minimum fill, accumulation,
    /// remainder, close.
    function test_outsidePartialFills_accumulateOnTheDex_thenClosed() public {
        DexLegs.Settlement memory s = _settlement(_dave(address(usdc), 1, 998), 1);
        s.taker = _taker(_order(alice, address(usdc), 499, 998, 1), 499); // the taker whole, Dave below half
        bytes32 h = dex.dexOrderDigest(address(usdc), s.makers[0].o);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BelowMinFill.selector, h));
        DexLegs.Settlement[] memory ss = _two(
            _settlement(_dave(address(usdc), 1, 1000), 1), _settlement(_dave(address(usdc), 1, 1000), 2));
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(dex.pulled(h), 2000);
        assertEq(usdc.balanceOf(alice), 2000);
        s = _settlement(_dave(address(usdc), 1, 1000), 3);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, h));
    }

    /// The digest is EIP-712 over the DEX's salted domain and binds the sell token.
    function test_dexOrderDigest_isEip712OverTheDexDomain_andBindsTheSellToken() public {
        ITradeToken.TradeOrder memory o = _order(dave, address(a), 2000, 1000, 1);
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS Dex"), keccak256("1"), block.chainid, address(dex), UID_));
        bytes32 orderStruct = keccak256(abi.encode(keccak256(
            "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,"
            "uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,"
            "uint256 validUntil)"), o));
        bytes32 dexOrderType = keccak256(
            "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
            "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,"
            "uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)");
        bytes32 h = keccak256(abi.encodePacked(
            "\x19\x01", domain, keccak256(abi.encode(dexOrderType, address(usdc), orderStruct))));
        assertEq(dex.dexOrderDigest(address(usdc), o), h);
        assertEq(dex.cancelOrderDigest(h), keccak256(abi.encodePacked(
            "\x19\x01", domain, keccak256(abi.encode(keccak256("CancelOrder(bytes32 orderHash)"), h)))));
        assertEq(dex.invalidateNoncesDigest(dave, 1, 5), keccak256(abi.encodePacked("\x19\x01", domain, keccak256(
            abi.encode(keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)"), dave, 1, 5)))));
        // signed for another sell token: refused
        DexLegs.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        s.makers[0].sig = _sig(DAVE_PK, dex.dexOrderDigest(address(a), o));
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
    }

    /// The spender is the puller: an allowance to the DEX moves nothing.
    function test_pullUsesTheAllowanceToThePuller_notToTheDex() public {
        address p = dex.puller();
        vm.startPrank(dave);
        usdc.approve(p, 0);
        usdc.approve(address(dex), type(uint256).max);
        vm.stopPrank();
        DexLegs.Settlement memory s = _settlement(_dave(address(usdc), 1, 2000), 1);
        _expectOne(s, abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, p, 0, 2000));
    }

    function test_onlyTheDexPulls() public {
        DexPuller p = DexPuller(dex.puller());
        assertEq(p.dex(), address(dex));
        vm.expectRevert(abi.encodeWithSelector(DexPuller.NotDex.selector, address(this)));
        p.pull(address(usdc), dave, 1);
    }

    // ------------------------------------------------------------------ tokens that are not exact

    function test_feeOnTransferToken_conservationCatchesIt() public {
        MockERC20 fot = _list(new FeeOnTransferERC20());
        _fund(fot, dave);
        DexLegs.Settlement[] memory ss = _one(_settlement(_dave(address(fot), 1, 2000), 1));
        // the DEX receives 1 % less than it pulled: paying the taker fails, nothing moves
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(DexLegs.wire(ss));
        // with a donated balance the payment goes through and conservation reverts the settlement
        fot.mint(address(dex), 10_000);
        _expectOne(ss[0], abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }

    function test_rebasingUpToken_conservationCatchesIt() public {
        MockERC20 up = _list(new RebaseUpERC20());
        _fund(up, dave);
        DexLegs.Settlement memory s = _settlement(_dave(address(up), 1, 2000), 1);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(up)));
    }

    /// `transfer`/`transferFrom` without a return value (USDT): settles through `SafeERC20`.
    function test_noReturnValueToken_settles() public {
        NoReturnERC20 t = new NoReturnERC20();
        vm.prank(admin);
        dex.setMarket(address(a), address(t), true);
        t.mint(dave, 5000);
        address p = dex.puller();
        vm.prank(dave);
        t.approve(p, 2000);
        DexLegs.Settlement[] memory ss = _one(_settlement(_dave(address(t), 1, 2000), 1));
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(t.balanceOf(alice), 2000);
        assertEq(t.balanceOf(dave), 3000);
        assertEq(t.balanceOf(address(dex)), 0);
    }

    /// A contract with only a fallback is outside (the factory did not make it), so it never goes down `mtxTrade`;
    /// its empty answers fail the settlement.
    function test_fallbackOnlyToken_isOutside_andFails() public {
        address fb = address(new FallbackOnly());
        vm.prank(admin);
        dex.setMarket(address(a), fb, true);
        assertEq(dex.tokenKind(fb), 2);
        DexLegs.Settlement[] memory ss = _one(_settlement(_dave(fb, 1, 2000), 1));
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(DexLegs.wire(ss));
    }

    // ------------------------------------------------------------------ MatchFailed

    function test_matchFailed_carriesTheRevertData() public {
        ITradeToken.TradeOrder memory mo = _order(dave, address(a), 2000, 1000, 1);
        mo.validUntil = block.timestamp - 1;
        bytes32 h = dex.dexOrderDigest(address(usdc), mo);
        DexLegs.Settlement[] memory ss = _two(
            _settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1), _settlement(_dave(address(usdc), 2, 2000), 2));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.MatchFailed(bytes32(uint256(1)), abi.encodeWithSelector(ITradeToken.OrderExpired.selector, h));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertFalse(ok[0]);
        assertTrue(ok[1]);
    }

    /// An outside token reverting with 320 000 bytes: `MatchFailed` keeps 256, and the copy is cheap enough that the
    /// next settlement still runs under a gas limit an unbounded copy would exhaust.
    function test_returnbombToken_reasonIsBounded_othersSettle() public {
        address bomb = address(new BombERC20());
        vm.prank(admin);
        dex.setMarket(address(a), bomb, true);
        DexLegs.Settlement[] memory ss = _two(
            _settlement(_dave(bomb, 1, 2000), 1), _settlement(_dave(address(usdc), 2, 2000), 2));
        vm.recordLogs();
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle{gas: 3_000_000}(DexLegs.wire(ss));
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory reason;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == ISCaaSDex.MatchFailed.selector) reason = abi.decode(logs[i].data, (bytes));
        }
        assertEq(reason.length, 256);
    }

    // ------------------------------------------------------------------ ERC-1271 (CTR-DEX-08)

    /// The DEX exposes the `SmartKeyAccount` implementation it was built with, as the tokens do (the deploy compares).
    function test_smartKeyAccountImpl_isExposed() public view {
        assertEq(dex.SMART_KEY_ACCOUNT_IMPL(), work);
        assertEq(a.SMART_KEY_ACCOUNT_IMPL(), dex.SMART_KEY_ACCOUNT_IMPL());
    }

    function test_erc1271OutsideSigner_settles() public {
        Mock1271Wallet w = new Mock1271Wallet(dave);
        _fund(usdc, address(w));
        ITradeToken.TradeOrder memory mo = _order(address(w), address(a), 2000, 1000, 1);
        DexLegs.Settlement[] memory ss = _one(_settlement(_outsideLeg(DAVE_PK, address(usdc), mo, 2000), 1));
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(a.balanceOf(address(w)), 1000);
    }

    /// 400 k for a clone of this chain's `SmartKeyAccount` implementation, 50 k for any other contract: in settle,
    /// cancel and invalidate alike.
    function test_erc1271Cap_400kOnlyForSmartKeyClones() public {
        address clone = Clones.clone(work);
        _fund(usdc, clone);
        _fund(usdc, work);
        ITradeToken.TradeOrder memory co = _order(clone, address(a), 2000, 1000, 1);
        ITradeToken.TradeOrder memory wo = _order(work, address(a), 2000, 1000, 1);
        bytes32 hc = dex.dexOrderDigest(address(usdc), co);
        bytes32 hw = dex.dexOrderDigest(address(usdc), wo);
        DexLegs.Settlement memory sw = _settlement(DexLegs.Leg(address(usdc), wo, hex"00", 2000), 1);
        _expectOne(sw, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, hw));
        DexLegs.Settlement[] memory ss = _one(_settlement(DexLegs.Leg(address(usdc), co, hex"00", 1000), 1));
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(dex.pulled(hc), 1000);
        // cancel: the clone's item closes, the bare contract's is skipped
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](2);
        os[0] = ISCaaSDex.DexOrder(address(usdc), co);
        os[1] = ISCaaSDex.DexOrder(address(usdc), wo);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = hex"00";
        sigs[1] = hex"00";
        dex.mtxCancelOrders(os, sigs);
        assertEq(dex.pulled(hc), 2000);
        assertEq(dex.pulled(hw), 0);
        // invalidate
        dex.mtxInvalidateNonces(clone, 1, 5, hex"00");
        assertEq(dex.minNonce(clone, 1), 5);
        bytes32 d = dex.invalidateNoncesDigest(work, 1, 5);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, d));
        dex.mtxInvalidateNonces(work, 1, 5, hex"00");
    }

    /// m8 (CTR-DEX-08): a submitter that leaves too little gas for a capped ERC-1271 check reverts the whole call, even
    /// when another settlement in it succeeded; with enough gas the same call settles both.
    function test_starvedSigCheck_revertsTheWholeCall() public {
        address clone = Clones.clone(work);
        _fund(usdc, clone);
        ITradeToken.TradeOrder memory co = _order(clone, address(a), 2000, 1000, 1);
        DexLegs.Settlement[] memory ss = _two(
            _settlement(_dave(address(usdc), 1, 2000), 1),
            _settlement(DexLegs.Leg(address(usdc), co, hex"00", 2000), 2));
        vm.prank(relayer);
        vm.expectPartialRevert(ISCaaSDex.SigCheckGasStarved.selector);
        dex.mtxSettle{gas: 700_000}(DexLegs.wire(ss));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertTrue(ok[0] && ok[1]);
    }

    function _hostileMaker(address w) internal {
        DexLegs.Settlement[] memory ss = _two(
            _settlement(DexLegs.Leg(address(usdc), _order(w, address(a), 2000, 1000, 1), hex"00", 2000), 1),
            _settlement(_dave(address(usdc), 1, 2000), 2));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle{gas: 3_000_000}(DexLegs.wire(ss));
        assertFalse(ok[0]);
        assertTrue(ok[1]);
    }

    function test_gasBurning1271OutsideMaker_othersStillSettle() public { _hostileMaker(address(new Burner1271())); }
    function test_returndataBomb1271OutsideMaker_othersStillSettle() public { _hostileMaker(address(new Bomb1271())); }

    // ------------------------------------------------------------------ cancels (CTR-DEX-02, CTR-DEX-18)

    function test_cancelOrders_skipsBadItems_andInvalidateNonces() public {
        ITradeToken.TradeOrder memory good = _order(dave, address(a), 2000, 1000, 1);
        ITradeToken.TradeOrder memory bad = _order(dave, address(a), 2000, 1000, 2);
        bytes32 hg = dex.dexOrderDigest(address(usdc), good);
        bytes32 hb = dex.dexOrderDigest(address(usdc), bad);
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](2);
        os[0] = ISCaaSDex.DexOrder(address(usdc), good);
        os[1] = ISCaaSDex.DexOrder(address(usdc), bad);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sig(DAVE_PK, dex.cancelOrderDigest(hg));
        sigs[1] = _sig(0xBAD, dex.cancelOrderDigest(hb));
        vm.expectRevert(ISCaaSDex.LengthMismatch.selector);
        dex.mtxCancelOrders(os, new bytes[](1));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.OrderCancelled(hg, dave);
        dex.mtxCancelOrders(os, sigs);
        assertEq(dex.pulled(hg), 2000);
        assertEq(dex.pulled(hb), 0);
        dex.mtxCancelOrders(os, sigs); // replay: a no-op, not an error
        DexLegs.Settlement memory st = _settlement(_dave(address(usdc), 1, 2000), 1);
        _expectOne(st, abi.encodeWithSelector(ISCaaSDex.OrderClosed.selector, hg));
        bytes memory inv = _sig(DAVE_PK, dex.invalidateNoncesDigest(dave, 1, 5));
        dex.mtxInvalidateNonces(dave, 1, 5, inv);
        assertEq(dex.minNonce(dave, 1), 5);
        st = _settlement(_dave(address(usdc), 2, 2000), 1);
        _expectOne(st, abi.encodeWithSelector(ISCaaSDex.NonceInvalidated.selector, hb));
        bytes32 d6 = dex.invalidateNoncesDigest(dave, 1, 6);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, d6)); // signed for 5, replayed for 6
        dex.mtxInvalidateNonces(dave, 1, 6, inv);
    }

    /// A gas-burning or returndata-bomb ERC-1271 signer in a cancel batch is skipped; the others are cancelled.
    function test_hostile1271InACancelBatch_isSkipped() public {
        address burner = address(new Burner1271());
        address bomb = address(new Bomb1271());
        ITradeToken.TradeOrder memory good = _order(dave, address(a), 2000, 1000, 1);
        bytes32 hg = dex.dexOrderDigest(address(usdc), good);
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](3);
        os[0] = ISCaaSDex.DexOrder(address(usdc), _order(burner, address(a), 2000, 1000, 1));
        os[1] = ISCaaSDex.DexOrder(address(usdc), _order(bomb, address(a), 2000, 1000, 1));
        os[2] = ISCaaSDex.DexOrder(address(usdc), good);
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = hex"00";
        sigs[1] = hex"00";
        sigs[2] = _sig(DAVE_PK, dex.cancelOrderDigest(hg));
        dex.mtxCancelOrders{gas: 1_000_000}(os, sigs);
        assertEq(dex.pulled(hg), 2000);
        assertEq(dex.pulled(dex.dexOrderDigest(address(usdc), os[0].order)), 0);
    }

    /// A hook token re-entering the DEX during a pull is refused on every entry: `nonReentrant` on `mtxSettle`,
    /// `mtxCancelOrders`, `mtxInvalidateNonces`, `mtxExchange` and `mtxExchangeVia`, `NotSelf` on `settleOne`.
    function test_hookTokenReentry_isRefused() public {
        HookERC20 hk = new HookERC20();
        _list(MockERC20(address(hk)));
        _fund(MockERC20(address(hk)), dave);
        Reenter r = new Reenter(ISCaaSDex(address(dex)));
        hk.setHook(address(r));
        DexLegs.Settlement[] memory ss = _one(_settlement(_dave(address(hk), 1, 2000), 1));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertTrue(ok[0]);
        assertEq(r.n(), 6);
        bytes4 guard = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        assertEq(r.errs(0), guard);
        assertEq(r.errs(1), guard);
        assertEq(r.errs(2), guard);
        assertEq(r.errs(3), ISCaaSDex.NotSelf.selector);
        assertEq(r.errs(4), guard);
        assertEq(r.errs(5), guard);
    }

    /// `SigCheckGasStarved` raised by a SCaaS token's own check (Path A taker that is a `SmartKeyAccount` clone, so the
    /// token grants 400 k, with too little gas left at the token) reverts the whole `mtxSettle`, not just that
    /// settlement and not as `MatchFailed`.
    function test_starvedCheckInsideASCaaSLeg_revertsTheBatch() public {
        address w = Clones.clone(work);
        vm.prank(alice);
        a.transfer(w, 1000);
        ITradeToken.TradeOrder memory t = _order(w, address(usdc), 1000, 2000, 2);
        DexLegs.Settlement memory sw = _settlement(_dave(address(usdc), 2, 2000), 2);
        sw.taker = DexLegs.Leg(address(a), t, hex"00", 1000);
        DexLegs.Settlement[] memory ss = _two(_settlement(_dave(address(usdc), 1, 2000), 1), sw);
        vm.prank(relayer);
        vm.expectPartialRevert(ISCaaSDex.SigCheckGasStarved.selector);
        dex.mtxSettle{gas: GAS_STARVED}(DexLegs.wire(ss));
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertTrue(ok[0] && ok[1]);
    }
}
