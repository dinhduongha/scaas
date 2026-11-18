// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {ZetherRegFixture} from "../as/confidential/ZetherRegFixture.sol";
import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

uint256 constant SCA_BIT = uint256(1) << GovernanceBits.SUPPLY_CAP_ADJUSTABLE;

function overCap(uint256 next, uint256 cap) pure returns (bytes memory) {
    return abi.encodeWithSelector(IWrappedToken.MaxWrapSupplyExceeded.selector, next, cap);
}

/// Round 3zc (spec 2026-11-13-burner-wrap-caps.md §3, §6), the wrapped kinds beside kind 1 (`SupplyCaps.t.sol`): on each, a
/// pure wrap with `maxWrapSupply` and bit 31 counts its wraps (the shield-wrap `mtxWrapShield` on 3, 5, 11, 13), refuses one
/// unit over the cap by name, and its admin raises the cap through the kind's own `setMaxWrapSupply` (after `grantDelay`
/// where the fixture has one). UNAUDITED.
contract SupplyCapsKind3Test is ZetherFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        Catalogue.release(
            factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode
        );
        _users();
    }

    function test_kind3_capCounterSetter() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        (c.features, c.admin, c.lockedFeatures, c.roles.minter) = (1 | SCA_BIT, nid(address(this)), 0, 0);
        c.maxWrapSupply = 10 * SCALE;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedZetherToken w = WrappedZetherToken(
            payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "c3"))
        );
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        bytes32 to = ZetherTypes.UA.unwrap(alice.ua);
        w.mtxWrapShield(address(usd), 10 * SCALE, to);
        IWrappedToken iw = IWrappedToken(address(w));
        assertEq(iw.totalWrapped(), 10 * SCALE, "the shield-wrap counted");
        assertEq(iw.totalWrapped(), w.totalSupply());
        vm.expectRevert(overCap(11 * SCALE, 10 * SCALE));
        w.mtxWrapShield(address(usd), SCALE, to);
        iw.setMaxWrapSupply(20 * SCALE, EnvKit.codeUidOf(address(w)));
        w.mtxWrapShield(address(usd), SCALE, to);
        assertEq(iw.totalWrapped(), 11 * SCALE);
    }
}

/// Fable F-5: a hybrid of kind 3 with bit 31: `setMaxSupply` raises and lowers through the face, the views agree.
contract SupplyCapsKind3HybridTest is ZetherFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        Catalogue.release(
            factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode
        );
        _users();
    }

    function test_kind3_hybridSetMaxSupplyAndViews() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        (c.features, c.admin, c.lockedFeatures) =
        (1 | (uint256(1) << GovernanceBits.MINTABLE) | SCA_BIT, nid(address(this)), 0);
        (c.maxSupply, c.maxWrapSupply) = (1000 * SCALE, 100 * SCALE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        address t = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "h3");
        IWrappedToken iw = IWrappedToken(t);
        bytes32 u = EnvKit.codeUidOf(t);
        iw.setMaxSupply(2000 * SCALE, u);
        assertEq(iw.maxSupply(), 2000 * SCALE, "raised");
        iw.setMaxSupply(500 * SCALE, u);
        assertEq(iw.maxSupply(), 500 * SCALE, "lowered");
        usd.mint(address(this), 10 * SCALE);
        usd.approve(t, type(uint256).max);
        WrappedZetherToken(payable(t)).mtxWrapShield(address(usd), 10 * SCALE, ZetherTypes.UA.unwrap(alice.ua));
        assertEq(iw.reserveValue(), iw.collateralValue());
        assertEq(iw.reserveValue(), 10 * SCALE);
        (, uint64 e1, bool l1,, uint64 e2, bool l2) = iw.pendingSupplyCaps();
        assertTrue(e1 == 0 && e2 == 0 && !l1 && !l2, "no delay, no pending");
    }
}

contract SupplyCapsKind5Test is PqzFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function test_kind5_capCounterSetter() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (c.features, c.admin, c.lockedFeatures, c.roles.minter) = (1 | SCA_BIT, nid(address(this)), 0, 0);
        c.maxWrapSupply = 10 * SCALE;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedPqzToken w =
            WrappedPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "c5")));
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 10 * SCALE, alice);
        IWrappedToken iw = IWrappedToken(address(w));
        assertEq(iw.totalWrapped(), 10 * SCALE, "the shield-wrap counted");
        vm.expectRevert(overCap(11 * SCALE, 10 * SCALE));
        w.mtxWrapShield(address(usd), SCALE, alice);
        iw.setMaxWrapSupply(20 * SCALE, EnvKit.codeUidOf(address(w)));
        w.mtxWrapShield(address(usd), SCALE, alice);
        assertEq(iw.totalWrapped(), 11 * SCALE);
    }
}

contract SupplyCapsKind9Test is RegFixture {
    function test_kind9_capCounterSetter() public {
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features |= SCA_BIT;
        c.maxWrapSupply = 10;
        address t = f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), "c9");
        _wrapFor(t, alice, 10);
        IWrappedToken iw = IWrappedToken(t);
        assertEq(iw.totalWrapped(), 10);
        usd.mint(alice, 1);
        vm.startPrank(alice);
        usd.approve(t, 1);
        vm.expectRevert(overCap(11, 10));
        WrappedToken(payable(t)).wrap(address(usd), 1);
        vm.stopPrank();
        bytes32 u = EnvKit.codeUidOf(t);
        vm.prank(ownerA);
        iw.setMaxWrapSupply(20, u); // proposes: grantDelay `GD`
        assertEq(iw.maxWrapSupply(), 10);
        vm.warp(block.timestamp + GD);
        vm.prank(ownerA);
        iw.setMaxWrapSupply(20, u);
        assertEq(iw.maxWrapSupply(), 20);
        vm.prank(alice);
        WrappedToken(payable(t)).wrap(address(usd), 1);
        assertEq(iw.totalWrapped(), 11);
    }
}

/// Fable F-5: a hybrid of kind 9 with bit 31 and the fixture's grantDelay: `setMaxSupply` proposed, then applied.
contract SupplyCapsKind9HybridTest is RegFixture {
    function test_kind9_hybridSetMaxSupplyAndViews() public {
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features |= (uint256(1) << GovernanceBits.MINTABLE) | SCA_BIT;
        (c.maxSupply, c.roles.minter) = (1000, nid(address(this)));
        address t = f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), "h9");
        IWrappedToken iw = IWrappedToken(t);
        bytes32 u = EnvKit.codeUidOf(t);
        vm.prank(ownerA);
        iw.setMaxSupply(2000, u);
        (uint256 p, uint64 eta, bool live,,,) = iw.pendingSupplyCaps();
        assertTrue(p == 2000 && eta == block.timestamp + GD && live, "proposed");
        vm.warp(block.timestamp + GD);
        vm.prank(ownerA);
        iw.setMaxSupply(2000, u);
        assertEq(iw.maxSupply(), 2000, "applied");
        _wrapFor(t, alice, 10);
        assertEq(iw.reserveValue(), iw.collateralValue());
        assertEq(iw.totalWrapped(), 10);
    }
}

contract SupplyCapsKind11Test is ZetherRegFixture {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    function test_kind11_capCounterSetter() public {
        IFactoryToken.TokenConfig memory c = _regCfg(false, uint256(1) << 40);
        c.features |= SCA_BIT;
        c.maxWrapSupply = 10 * SCALE;
        WrappedZetherToken z = WrappedZetherToken(payable(factory.createToken(_kind(), 1, abi.encode(c), "c11")));
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(z), type(uint256).max);
        bytes32 to = ZetherTypes.UA.unwrap(alice.ua);
        z.mtxWrapShield(address(usd), 10 * SCALE, to);
        IWrappedToken iw = IWrappedToken(address(z));
        assertEq(iw.totalWrapped(), 10 * SCALE);
        vm.expectRevert(overCap(11 * SCALE, 10 * SCALE));
        z.mtxWrapShield(address(usd), SCALE, to);
        bytes32 u = EnvKit.codeUidOf(address(z));
        vm.prank(ownerA);
        iw.setMaxWrapSupply(0, u); // propose: 0 removes the wrap cap
        vm.warp(block.timestamp + 1 days);
        vm.prank(ownerA);
        iw.setMaxWrapSupply(0, u);
        z.mtxWrapShield(address(usd), SCALE, to);
        assertEq(iw.totalWrapped(), 11 * SCALE);
    }
}

contract SupplyCapsKind13Test is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    /// Controller 2026-11-15 (Fable F-5): the regulated PQZ path's own unshield-unwrap (its hooks) leaves the counter by all of
    /// `amount · shieldScale`, as on kind 5; a pure wrap's counter stays its supply.
    function test_kind13_unshieldUnwrapCounter() public {
        _shieldTo(alice, 100);
        IWrappedToken iw = IWrappedToken(address(tok));
        uint256 w0 = iw.totalWrapped();
        assertEq(w0, tok.totalSupply(), "a pure wrap");
        (bool ok, bytes memory ret) = address(tok).call(_unwrapCall(10, 0));
        assertTrue(ok, string(ret));
        assertEq(usd.balanceOf(address(0xD00D)), 10 * SCALE, "paid out");
        assertEq(iw.totalWrapped(), w0 - 10 * SCALE, "the counter follows the burn from the pool");
        assertEq(iw.totalWrapped(), tok.totalSupply());
    }

    function test_kind13_capCounterSetter() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= SCA_BIT;
        c.maxWrapSupply = 10 * SCALE;
        WrappedPqzToken z = WrappedPqzToken(payable(factory.createToken(_kind(), 1, abi.encode(c), "c13")));
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(z), type(uint256).max);
        z.mtxWrapShield(address(usd), 10 * SCALE, alice);
        IWrappedToken iw = IWrappedToken(address(z));
        assertEq(iw.totalWrapped(), 10 * SCALE);
        vm.expectRevert(overCap(11 * SCALE, 10 * SCALE));
        z.mtxWrapShield(address(usd), SCALE, alice);
        bytes32 u = EnvKit.codeUidOf(address(z));
        vm.prank(ownerA);
        iw.setMaxWrapSupply(20 * SCALE, u);
        vm.warp(block.timestamp + 1 days);
        vm.prank(ownerA);
        iw.setMaxWrapSupply(20 * SCALE, u);
        z.mtxWrapShield(address(usd), SCALE, alice);
        assertEq(iw.totalWrapped(), 11 * SCALE);
    }
}
