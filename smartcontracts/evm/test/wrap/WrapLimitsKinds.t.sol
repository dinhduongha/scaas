// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {ZetherRegFixture} from "../as/confidential/ZetherRegFixture.sol";
import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";
import {nid} from "../helpers/Ids.sol";

uint256 constant WL_MINT = uint256(1) << GovernanceBits.MINTABLE;
uint256 constant WL_CONTROLS = GovernanceBits.WRAP_CONTROLS;

function lim(uint24 perUser, uint32 period) pure returns (IWrappedToken.WrapLimit memory l) {
    l = IWrappedToken.WrapLimit(perUser, 0, period);
}

function legs1(address u, IWrappedToken.WrapLimit memory ws) pure returns (IWrappedToken.WrapLegLimits[] memory r) {
    IWrappedToken.WrapLimit memory off;
    r = new IWrappedToken.WrapLegLimits[](1);
    r[0] = IWrappedToken.WrapLegLimits(u, 0, 0, ws, off, off, off);
}

/// Group 3l, kind `WRAPPED_ZETHER` (row 12, 34, 36; spec 2026-11-10-wrap-limits.md §1, §4): the wrap-shield counts on the
/// payer and credits `toUA`; the unshield-unwrap counts the proof's sender `uaOf(yFrom)`, refused before the proof; the
/// normal kind 2 refuses the bits. UNAUDITED.
contract WrapLimitsZetherTest is ZetherFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        _users();
    }

    function _token(uint256 features, bool hybrid, bytes32 salt) internal returns (WrappedZetherToken) {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = 1 | features | (hybrid ? WL_MINT : 0);
        c.owner = nid(address(this));
        c.lockedFeatures = 0;
        if (!hybrid) c.roles.minter = 0;
        c.maxSupply = hybrid ? 1e30 : 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        return WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), salt)));
    }

    function test_r34_pureWrapRefusesTheBits_kind3() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            this.mk(uint256(1) << bit, false, bytes32(uint256(bit)));
            _token(uint256(1) << bit, true, bytes32(uint256(bit) + 100)); // the same hybrid passes
        }
    }

    function mk(uint256 features, bool hybrid, bytes32 salt) external returns (address) {
        return address(_token(features, hybrid, salt));
    }

    function test_r19_normalKind2RefusesTheBits() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), bytes32(uint256(bit)));
        }
    }

    function test_r12_wrapShieldCountsThePayerCreditsToUA() public {
        WrappedZetherToken w = _token(WL_CONTROLS, true, "h");
        IWrappedToken.WrapLegLimits[] memory a = legs1(address(usd), lim(30, 1 days));
        a[0].unitExp = 4; // a quantum is SCALE raw units: 30 per window
        WrappedToken(payable(address(w))).setWrapLimits(a, false, false, false);
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 30 * SCALE, ZetherTypes.UA.unwrap(alice.ua));
        WrappedToken t = WrappedToken(payable(address(w)));
        assertEq(t.wrapQuotaOf(MetaTxLib.pad(address(this)), address(usd)).wrapShort.left, 0, "the payer's window");
        assertEq(t.wrapQuotaOf(ZetherTypes.UA.unwrap(alice.ua), address(usd)).netWrapped, 30 * SCALE, "toUA credited");
        assertEq(t.wrapQuotaOf(MetaTxLib.pad(address(this)), address(usd)).netWrapped, 0, "the payer not");
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, address(usd), uint8(0),
            MetaTxLib.pad(address(this)), SCALE, 0));
        w.mtxWrapShield(address(usd), SCALE, ZetherTypes.UA.unwrap(alice.ua));
    }

    function _unshieldUnwrap(WrappedZetherToken w, IZetherToken.ZetherBurn memory b) internal returns (bytes memory ret) {
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 10, 0);
        try w.mtxUnshieldUnwrap(b, x, "") {
            revert("no proof behind it");
        } catch (bytes memory e) {
            ret = e;
        }
    }

    /// Row 12, row 36 (Q17): the proof's sender is the subject; with the net rule a Zether id that wrapped nothing is refused
    /// before the proof, the matched path (a wrap-shield into it) passes the check and reaches the proof.
    function test_r12_r36_unshieldUnwrapRefusedBeforeTheProof() public {
        WrappedZetherToken w = _token(WL_CONTROLS, true, "h");
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 50 * SCALE); // a public wrap: the reserve, credited to this test's public id
        WrappedToken(payable(address(w))).setWrapLimits(legs1(address(usd), lim(0, 0)), true, false, false);
        IZetherToken.ZetherBurn memory b;
        (b.yFrom.x0, b.yFrom.x1) = (bytes32(uint256(1)), bytes32(uint256(2)));
        bytes32 sender = ZetherTypes.UA.unwrap(ZetherTypes.toUA(abi.encode(b.yFrom)));
        assertEq(_unshieldUnwrap(w, b), abi.encodeWithSelector(IWrappedToken.UnwrapAboveNetWrapped.selector, address(usd),
            sender, 10 * SCALE, 0), "the shielded id is not the public id");
        // the matched path: a wrap-shield credits alice's Zether id, whose check passes; the proof stage refuses
        w.mtxWrapShield(address(usd), 20 * SCALE, ZetherTypes.UA.unwrap(alice.ua));
        b.yFrom = abi.decode(alice.y, (IZetherToken.G1));
        bytes memory ret = _unshieldUnwrap(w, b);
        assertTrue(bytes4(ret) != IWrappedToken.UnwrapAboveNetWrapped.selector, "the check passed, the proof refuses");
    }
}

/// Group 3l, kind `WRAPPED_PQZ` (row 12, 34): the same rows with `fromUA`; the normal kind 4 refuses the bits. UNAUDITED.
contract WrapLimitsPqzTest is PqzFixture {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _token(uint256 features, bool hybrid, bytes32 salt) internal returns (WrappedPqzToken) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1 | features | (hybrid ? WL_MINT : 0);
        c.owner = nid(address(this));
        c.lockedFeatures = 0;
        if (!hybrid) c.roles.minter = 0;
        c.maxSupply = hybrid ? 1e30 : 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        return WrappedPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), salt)));
    }

    function mk(uint256 features, bool hybrid, bytes32 salt) external returns (address) {
        return address(_token(features, hybrid, salt));
    }

    function test_r34_pureWrapRefusesTheBits_kind5() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            this.mk(uint256(1) << bit, false, bytes32(uint256(bit)));
            _token(uint256(1) << bit, true, bytes32(uint256(bit) + 100));
        }
    }

    function test_r19_normalKind4RefusesTheBits() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), bytes32(uint256(bit)));
        }
    }

    function test_r12_wrapShieldCountsThePayerCreditsToUA() public {
        WrappedPqzToken w = _token(WL_CONTROLS, true, "h");
        IWrappedToken.WrapLegLimits[] memory a = legs1(address(usd), lim(30, 1 days));
        a[0].unitExp = 4;
        WrappedToken(payable(address(w))).setWrapLimits(a, false, false, false);
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 30 * SCALE, alice);
        WrappedToken t = WrappedToken(payable(address(w)));
        assertEq(t.wrapQuotaOf(MetaTxLib.pad(address(this)), address(usd)).wrapShort.left, 0);
        assertEq(t.wrapQuotaOf(alice, address(usd)).netWrapped, 30 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, address(usd), uint8(0),
            MetaTxLib.pad(address(this)), SCALE, 0));
        w.mtxWrapShield(address(usd), SCALE, alice);
    }

    /// The burn on the fixture's mocked precompile: `ret` empty when it passes.
    function _unshieldUnwrap(WrappedPqzToken w, bytes32 fromUA) internal returns (bytes memory ret) {
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), fromUA, bytes32(0)),
            _blob(21, PqzCt.CT));
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 10, 0);
        try w.mtxUnshieldUnwrap(_bs(pl), x, hex"c0de", _pqAuth(), "", noVerdict()) {}
        catch (bytes memory e) {
            ret = e;
        }
    }

    function test_r12_r36_unshieldUnwrapRefusedBeforeTheBurn() public {
        WrappedPqzToken w = _token(WL_CONTROLS, true, "h");
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 50 * SCALE);
        WrappedToken(payable(address(w))).setWrapLimits(legs1(address(usd), lim(0, 0)), true, false, false);
        bytes32 bad = bytes32(uint256(0xBAD));
        assertEq(_unshieldUnwrap(w, bad), abi.encodeWithSelector(IWrappedToken.UnwrapAboveNetWrapped.selector, address(usd),
            bad, 10 * SCALE, 0));
        w.mtxWrapShield(address(usd), 20 * SCALE, alice); // the matched path: alice's PQZ id credited
        bytes memory r = _unshieldUnwrap(w, alice);
        assertTrue(r.length < 4 || bytes4(r) != IWrappedToken.UnwrapAboveNetWrapped.selector, "the check passed");
    }
}

/// Group 3l, kinds `WRAPPED_REGULATED` and `NORMAL_REGULATED` (rows 19, 24, 34). UNAUDITED.
contract WrapLimitsRegulatedTest is RegFixture {
    function _hyb9(uint256 extra, bytes32 salt) internal returns (address) {
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features |= WL_MINT | extra;
        (c.maxSupply, c.roles.minter) = (1e30, nid(address(this)));
        return f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), salt);
    }

    function mk9(uint256 extra, bytes32 salt) external returns (address) {
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features |= extra;
        return f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), salt);
    }

    function test_r34_pureWrapRefusesTheBits_kind9() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            this.mk9(uint256(1) << bit, bytes32(uint256(bit)));
            _hyb9(uint256(1) << bit, bytes32(uint256(bit) + 100));
        }
    }

    function test_r19_normalKind8RefusesTheBits() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            IFactoryToken.TokenConfig memory c = _cfg8();
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), bytes32(uint256(bit)));
        }
    }

    /// Row 24 (spec §4): a relayed frozen sender gets `Frozen` before any limit (`_regPre`); a direct unwrap meets the limits
    /// in the quote, before the burn, and a frozen unwrapper within them gets `Frozen` at the burn.
    function test_r24_orderOnKind9() public {
        address t = _hyb9(WL_CONTROLS, "h");
        _wrapFor(t, alice, 100);
        IWrappedToken.WrapLegLimits[] memory a = legs1(address(usd), lim(0, 0));
        a[0].unwrapShort = lim(10, 1 days);
        vm.prank(ownerA);
        WrappedToken(payable(t)).setWrapLimits(a, false, false, false);
        _freeze(t, nid(alice));
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, address(usd), uint8(2), nid(alice),
            50, 10));
        vm.prank(alice);
        WrappedToken(payable(t)).unwrap(address(usd), 50, alice, 0);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(alice)));
        vm.prank(alice);
        WrappedToken(payable(t)).unwrap(address(usd), 5, alice, 0);
        MetaTxLib.UAMetaTransaction memory m =
            _uaTx(alice, abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(usd), 50, alice, 0), 0, 0);
        IUARegistry.UASig memory sig = _uaSig(ALICE_PK, t, m);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(alice)));
        WrappedToken(payable(t)).mtxExecute(m, sig);
    }

    /// The disable refusal on the regulated W module (`_disableFeatureBody` of kind 9).
    function test_r18_disableRefusedOnKind9() public {
        address t = _hyb9(WL_CONTROLS, "h");
        vm.prank(ownerA);
        WrappedToken(payable(t)).setWrapLimits(legs1(address(usd), lim(10, 1 days)), false, false, false);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlActive.selector, uint8(25)));
        vm.prank(ownerA);
        WrappedToken(payable(t)).disableFeature(25);
    }
}

/// Group 3l, kind `WRAPPED_ZETHER_REGULATED` (row 34). UNAUDITED.
contract WrapLimitsZetherRegTest is ZetherRegFixture {
    function _isWrapped() internal pure override returns (bool) { return true; }

    function mk(uint256 extra, bool hybrid, bytes32 salt) external returns (address) {
        IFactoryToken.TokenConfig memory c = _regCfg(false, uint256(1) << 40);
        c.features |= extra | (hybrid ? WL_MINT : 0);
        if (hybrid) (c.maxSupply, c.roles.minter) = (1e30, nid(address(this)));
        return factory.createToken(_kind(), 1, abi.encode(c), salt);
    }

    function test_r34_pureWrapRefusesTheBits_kind11() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            this.mk(uint256(1) << bit, false, bytes32(uint256(bit)));
            this.mk(uint256(1) << bit, true, bytes32(uint256(bit) + 100));
        }
    }
}

/// Group 3l, kind `NORMAL_ZETHER_REGULATED` (row 19). UNAUDITED.
contract WrapLimitsZetherRegNormalTest is ZetherRegFixture {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_r19_normalKind10RefusesTheBits() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            IFactoryToken.TokenConfig memory c = _regCfg(false, uint256(1) << 40);
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            factory.createToken(_kind(), 1, abi.encode(c), bytes32(uint256(bit)));
        }
    }
}

/// Group 3l, kind `WRAPPED_PQZ_REGULATED` (row 34). UNAUDITED.
contract WrapLimitsPqzRegTest is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) { return true; }

    function mk(uint256 extra, bool hybrid, bytes32 salt) external returns (address) {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= extra | (hybrid ? WL_MINT : 0);
        if (hybrid) (c.maxSupply, c.roles.minter) = (1e30, nid(address(this)));
        return factory.createToken(_kind(), 1, abi.encode(c), salt);
    }

    function test_r34_pureWrapRefusesTheBits_kind13() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            this.mk(uint256(1) << bit, false, bytes32(uint256(bit)));
            this.mk(uint256(1) << bit, true, bytes32(uint256(bit) + 100));
        }
    }
}

/// Group 3l, kind `NORMAL_PQZ_REGULATED` (row 19). UNAUDITED.
contract WrapLimitsPqzRegNormalTest is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_r19_normalKind12RefusesTheBits() public {
        for (uint8 bit = 25; bit <= 27; ++bit) {
            IFactoryToken.TokenConfig memory c = _regCfg();
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            factory.createToken(_kind(), 1, abi.encode(c), bytes32(uint256(bit)));
        }
    }
}
