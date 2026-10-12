// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Random shield / wrap-shield / transfer / roll-over / unshield / unshield-unwrap / unwrap / rate-change sequences on one
/// `UNDERLYING_ZETHER` token (legs 1:1 and 3/7, rate-adjustable, bn254, no auditor), real proofs; the plaintext balances
/// are the ghost. Every value op does work (`_ensureAcc` rolls over, wrap-shields or shields first), the surplus
/// `collateral − (supply + shielded·S)` never drops except by a rate change (rounding against the holder), and the
/// underlying paid out equals a ghost per leg (CTR-ZTH-22 a, review T5 I1).
contract ZetherHandler is ZetherFixture {
    UnderlyingZetherToken public w;
    MockERC20[2] public leg;
    User[3] internal us;
    uint256[3] public acc;
    uint256[3] public pend;
    uint256[2] public paid;
    uint256 internal constant MAX = 1 << 30;

    function init() external {
        _stack(false);
        leg[0] = new MockERC20("USD", "USD", 6);
        leg[1] = new MockERC20("ODD", "ODD", 6);
        UnderlyingZetherToken impl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(impl));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("Z", "Z", 6);
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.RATE_ADJUSTABLE);
        c.roles.rateAdmin = address(this);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](2);
        c.legs[0] = IFactoryToken.Leg(address(leg[0]), 1, 1);
        c.legs[1] = IFactoryToken.Leg(address(leg[1]), 3, 7);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, MAX, FEE, 0, 0);
        w = UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "inv")));
        tok = ZetherLayer(address(w));
        _users();
        (us[0], us[1], us[2]) = (alice, bob, carol);
    }

    /// @dev At least `units` public units by a leg-0 wrap of `⌈units·den/num⌉` (the rate may have changed).
    function _public(ZetherLayer t, address to, uint256 units) internal override {
        (uint96 num, uint96 den,,,) = w.legOf(address(leg[0]));
        uint256 inAmt = (units * den + num - 1) / num;
        leg[0].mint(address(this), inAmt);
        leg[0].approve(address(t), inAmt);
        UnderlyingToken(payable(address(t))).wrap(address(leg[0]), inAmt);
        if (to != address(this)) t.transfer(to, units);
    }

    function surplus() public view returns (uint256) {
        return w.collateralValue() - w.totalSupply() - w.totalShielded() * SCALE;
    }

    modifier noLoss() {
        uint256 s0 = surplus();
        _;
        require(surplus() >= s0, "surplus dropped");
    }

    function _ensureAcc(uint256 i) internal {
        if (acc[i] != 0) return;
        if (pend[i] == 0) _ws(i, 0, 7);
        if (pend[i] == 0) {
            _fund(tok, us[i], 7);
            pend[i] += 7;
        }
        tok.zetherRollOver(us[i].ua);
        acc[i] += pend[i];
        pend[i] = 0;
    }

    function _ws(uint256 i, uint256 l, uint256 amt) internal {
        (uint96 num, uint96 den,,,) = w.legOf(address(leg[l]));
        uint256 inAmt = (amt * SCALE * den + num - 1) / num; // ⌈k·S·den/num⌉
        (uint256 m,) = w.previewWrap(address(leg[l]), inAmt);
        if (m != amt * SCALE) return; // no exact amount at this rate
        leg[l].mint(address(this), inAmt);
        leg[l].approve(address(w), inAmt);
        w.zetherWrapShield(address(leg[l]), inAmt, us[i].ua);
        pend[i] += amt;
    }

    function wrapShield(uint8 i, uint8 l, uint256 amt) external noLoss {
        if (w.rateAdjustable() && _pendingRate()) return;
        _ws(i % 3, l % 2, bound(amt, 1, 50));
    }

    function shield(uint8 i, uint256 amt) external noLoss {
        amt = bound(amt, 1, 50);
        _fund(tok, us[i % 3], amt);
        pend[i % 3] += amt;
    }

    function rollOver(uint8 i) external noLoss {
        i %= 3;
        tok.zetherRollOver(us[i].ua);
        acc[i] += pend[i];
        pend[i] = 0;
    }

    function transfer(uint8 i, uint8 j, uint256 v) external noLoss {
        (i, j) = (i % 3, j % 3);
        if (i == j) j = (i + 1) % 3;
        if (_pendingRate()) return;
        _ensureAcc(i);
        v = bound(v, 1, acc[i]);
        _direct(tok, _proveTransfer(tok, us[i], us[j], v, acc[i], _none(), 0), _none());
        acc[i] -= v;
        pend[j] += v;
    }

    function unshieldUnwrap(uint8 i, uint8 l, uint256 amt) external noLoss {
        (i, l) = (i % 3, l % 2);
        if (_pendingRate()) return; // the fixture's _ensureAcc would wrap-shield
        _ensureAcc(i);
        amt = bound(amt, 1, acc[i]);
        (uint256 out,) = w.previewUnwrap(address(leg[l]), amt * SCALE);
        (,, uint256 r,,) = w.legOf(address(leg[l]));
        if (out == 0 || out > r) return;
        bytes memory pl = _unshieldPayload(tok, us[i]);
        bytes memory st = stm.unshieldUnwrapStatement(address(w), pl, amt, address(0xD00D), _none(), address(leg[l]), out, 0);
        w.zetherUnshieldUnwrap(pl, _proveU(us[i], st, amt, acc[i], _none(), tok), "", _none(), address(leg[l]),
            address(0xD00D), amt, out);
        acc[i] -= amt;
        paid[l] += out;
    }

    function unshieldPublic(uint8 i, uint256 amt) external noLoss {
        i %= 3;
        if (_pendingRate()) return;
        _ensureAcc(i);
        amt = bound(amt, 1, acc[i]);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, us[i], amt, acc[i], address(this), _none(), 0);
        tok.zetherUnshield(pl, pr, "", _none(), address(this), amt);
        acc[i] -= amt;
    }

    function unwrap(uint8 l, uint256 amt) external noLoss {
        l %= 2;
        uint256 bal = w.balanceOf(address(this));
        if (bal == 0) return;
        (uint256 out,) = w.previewUnwrap(address(leg[l]), bound(amt, 1, bal));
        (,, uint256 r,,) = w.legOf(address(leg[l]));
        if (out == 0 || out > r) return;
        (uint256 o,) = w.unwrap(address(leg[l]), bound(amt, 1, bal), address(0xD00D), 0);
        paid[l] += o;
    }

    /// Propose ±(1..10)% on a leg, wait, execute; an undercollateralised decrease must be refused, nothing else.
    function rate(uint8 l, uint256 bps, bool up) external {
        l %= 2;
        bps = bound(bps, 1, 1000);
        (uint96 n, uint96 d,,,) = w.legOf(address(leg[l]));
        (uint256 sn, uint256 sd) = n < 1e6 ? (uint256(n) * 1000, uint256(d) * 1000) : (uint256(n), uint256(d));
        uint256 nn = up ? sn * (10_000 + bps) / 10_000 : sn * (10_000 - bps) / 10_000;
        if (nn == 0 || nn > type(uint96).max || sd > type(uint96).max) return;
        w.proposeRate(address(leg[l]), uint96(nn), uint96(sd));
        vm.warp(block.timestamp + 2 days);
        try w.executeRate() {} catch {
            w.cancelRate();
        }
        require(w.collateralValue() >= w.totalSupply() + w.totalShielded() * SCALE, "rate broke the invariant");
    }

    function _pendingRate() internal view returns (bool) {
        (address pu,,,) = w.pendingRate();
        return pu != address(0);
    }

    /// Every ghost balance holds (`[b]G == C − [x]D`), Σ == totalShielded, each reserve is the leg's balance, the
    /// payouts match, and the reserve covers the public and the shielded units.
    function check() external view {
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            require(_holds(tok, us[i], acc[i], true), "acc");
            require(_holds(tok, us[i], pend[i], false), "pending");
            sum += acc[i] + pend[i];
        }
        require(sum == w.totalShielded(), "sum == totalShielded");
        for (uint256 l; l < 2; ++l) {
            (,, uint256 r,,) = w.legOf(address(leg[l]));
            require(leg[l].balanceOf(address(w)) == r, "balance == reserve");
            require(leg[l].balanceOf(address(0xD00D)) == paid[l], "paid ghost");
        }
        require(w.collateralValue() >= w.totalSupply() + w.totalShielded() * SCALE, "reserve invariant");
    }
}

contract ZetherInvariantTest is Test {
    ZetherHandler internal h;

    function setUp() public {
        h = new ZetherHandler();
        h.init();
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](8);
        (sel[0], sel[1], sel[2], sel[3]) = (h.shield.selector, h.wrapShield.selector, h.rollOver.selector, h.transfer.selector);
        (sel[4], sel[5], sel[6], sel[7]) = (h.unshieldUnwrap.selector, h.unshieldPublic.selector, h.unwrap.selector, h.rate.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    /// forge-config: default.invariant.runs = 16
    /// forge-config: default.invariant.depth = 24
    function invariant_balancesConservationAndReserve() public view {
        h.check();
    }
}
