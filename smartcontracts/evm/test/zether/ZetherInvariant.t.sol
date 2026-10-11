// SPDX-License-Identifier: Apache-2.0
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

/// Random shield / wrap-shield / transfer / roll-over / unshield / unshield-unwrap / unwrap sequences on one
/// `UNDERLYING_ZETHER` token (one USD leg 1:1, bn254, no auditor), real proofs; the plaintext balances are the ghost.
contract ZetherHandler is ZetherFixture {
    UnderlyingZetherToken public w;
    MockERC20 public usd;
    User[3] internal us;
    uint256[3] public acc;
    uint256[3] public pend;
    uint256 internal constant MAX = 1 << 30;

    constructor() {
        _stack(false);
        usd = new MockERC20("USD", "USD", 6);
        UnderlyingZetherToken impl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(impl));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(address(ver), "", SCALE, MAX, FEE);
        w = UnderlyingZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, c, "inv")));
        tok = ZetherLayer(address(w));
        _users();
        us[0] = alice;
        us[1] = bob;
        us[2] = carol;
    }

    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        UnderlyingToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
    }

    function shield(uint8 i, uint256 amt) external {
        i %= 3;
        amt = bound(amt, 1, 50);
        _fund(tok, us[i], amt);
        pend[i] += amt;
    }

    function wrapShield(uint8 i, uint256 amt) external {
        i %= 3;
        amt = bound(amt, 1, 50);
        usd.mint(address(this), amt * SCALE);
        usd.approve(address(w), amt * SCALE);
        w.zetherWrapShield(address(usd), amt * SCALE, us[i].ua);
        pend[i] += amt;
    }

    function rollOver(uint8 i) external {
        i %= 3;
        tok.zetherRollOver(us[i].ua);
        acc[i] += pend[i];
        pend[i] = 0;
    }

    function transfer(uint8 i, uint8 j, uint256 v) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) return;
        v = bound(v, 0, acc[i]);
        _direct(tok, _proveTransfer(tok, us[i], us[j], v, acc[i], _none(), 0), _none());
        acc[i] -= v;
        pend[j] += v;
    }

    function unshield(uint8 i, uint256 amt, bool toUnderlying) external {
        i %= 3;
        if (acc[i] == 0) return;
        amt = bound(amt, 1, acc[i]);
        if (toUnderlying) {
            bytes memory pl = _unshieldPayload(tok, us[i]);
            bytes memory st = stm.unshieldUnwrapStatement(address(w), pl, amt, address(0xD00D), _none(), address(usd), 0, 0);
            w.zetherUnshieldUnwrap(pl, _proveU(us[i], st, amt, acc[i], _none(), tok), "", _none(), address(usd),
                address(0xD00D), amt, 0);
        } else {
            (bytes memory pl, bytes memory pr) = _proveUnshield(tok, us[i], amt, acc[i], address(this), _none(), 0);
            tok.zetherUnshield(pl, pr, "", _none(), address(this), amt);
        }
        acc[i] -= amt;
    }

    function unwrap(uint256 amt) external {
        uint256 bal = w.balanceOf(address(this));
        if (bal == 0) return;
        w.unwrap(address(usd), bound(amt, 1, bal), address(0xD00D), 0);
    }

    /// Every ghost balance holds (`[b]G == C − [x]D`), Σ == totalShielded ≤ cap, and the reserve covers the public and
    /// the shielded units (CTR-ZTH-22 a).
    function check() external view {
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            require(_holds(tok, us[i], acc[i], true), "acc");
            require(_holds(tok, us[i], pend[i], false), "pending");
            sum += acc[i] + pend[i];
        }
        require(sum == w.totalShielded(), "sum == totalShielded");
        require(sum <= w.maxDecryptableShielded(), "cap");
        (,, uint256 reserve,,) = w.legOf(address(usd));
        require(usd.balanceOf(address(w)) == reserve, "balance == reserve");
        require(w.collateralValue() >= w.totalSupply() + w.totalShielded() * SCALE, "reserve invariant");
    }
}

contract ZetherInvariantTest is Test {
    ZetherHandler internal h;

    function setUp() public {
        h = new ZetherHandler();
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](7);
        (sel[0], sel[1], sel[2], sel[3]) = (h.shield.selector, h.wrapShield.selector, h.rollOver.selector, h.transfer.selector);
        (sel[4], sel[5], sel[6]) = (h.unshield.selector, h.unwrap.selector, h.shield.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    /// forge-config: default.invariant.runs = 8
    /// forge-config: default.invariant.depth = 16
    function invariant_balancesConservationAndReserve() public view {
        h.check();
    }
}
