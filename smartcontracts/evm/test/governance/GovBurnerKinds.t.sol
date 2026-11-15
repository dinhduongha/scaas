// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {ZetherRegFixture} from "../as/confidential/ZetherRegFixture.sol";
import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

uint8 constant B30 = GovernanceBits.BURNER;
uint8 constant B2 = GovernanceBits.BURNABLE;

/// `features` with `BURNABLE` swapped for `BURNER`.
function toBurner(uint256 features) pure returns (uint256) {
    return (features & ~(uint256(1) << B2)) | (uint256(1) << B30);
}

function missing30(address who) pure returns (bytes memory) {
    return abi.encodeWithSelector(IGovernance.MissingRole.selector, B30, nid(who));
}

/// Round 3zb (spec 2026-11-13-burner-wrap-caps.md §1, §2, §6), the Normal kinds beside kind 0 (`GovBurner.t.sol`): on each, a
/// `BURNER` token's seat burns its own balance (`totalSupply` falls), a non-holder with a balance is `MissingRole(30, id)`,
/// `BURNABLE | BURNER` is `FeatureConflict(30, 2)` and `maxWrapSupply` is refused at the kind's own refusal site
/// (`ConfigFieldForOtherKind(5)`: `ZetherLib.initNormal` on 2 and 10, `MetaTokenBase._requireUnused` on 4, 8, 12).
/// Kind 8 also: `enableFeature(30)` never; a frozen burner refused, a pause does not stop a burn. Kind 4: the unshield of a
/// non-holder is not gated (O1), the supply unchanged. UNAUDITED.
contract GovBurnerKind8Test is RegFixture {
    function _b8(bytes32 salt) internal returns (NormalToken t) {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features = toBurner(c.features);
        c.roles.burner = nid(alice);
        t = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), salt));
    }

    function test_kind8_seatBurnsNonHolderRefused() public {
        NormalToken t = _b8("b8");
        vm.prank(alice);
        t.transfer(bob, 100);
        uint256 s0 = t.totalSupply();
        vm.prank(alice);
        t.burn(10);
        assertEq(t.totalSupply(), s0 - 10);
        vm.expectRevert(missing30(bob));
        vm.prank(bob);
        t.burn(1);
    }

    function test_kind8_initRefusals() public {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features |= uint256(1) << B30; // BURNABLE stays
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureConflict.selector, B30, B2));
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "c");
        c = _cfg8();
        c.maxWrapSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "m");
    }

    /// Never set after creation: `enableFeature(30)` on an off token and on a `BURNABLE` token (kinds 8-13 alone have
    /// `enableFeature`).
    function test_kind8_neverEnabledLater() public {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features &= ~(uint256(1) << B2);
        address off = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "off");
        address[2] memory ts = [off, t8]; // t8: the fixture's BURNABLE token
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotEnableable.selector, B30));
            vm.prank(ownerA);
            IRegulatedToken(ts[i]).enableFeature(B30, EnvKit.codeUidOf(ts[i]));
        }
    }

    /// The regulated hooks run on the burn row: a frozen burner cannot burn; a pause does not stop a burn.
    function test_kind8_frozenBurnerRefusedPauseDoesNotStop() public {
        NormalToken t = _b8("fz");
        _pause(address(t), uint64(block.timestamp + 1 hours));
        vm.prank(alice);
        t.burn(1); // burn is not paused
        _freeze(address(t), nid(alice));
        vm.prank(alice);
        (bool ok,) = address(t).call(abi.encodeWithSignature("burn(uint256)", uint256(1)));
        assertFalse(ok, "a frozen burner burnt");
    }
}

contract GovBurnerKind2Test is ZetherFixture {
    function setUp() public {
        _stack();
    }

    function _b2(bytes32 salt) internal returns (NormalToken t) {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = toBurner(c.features);
        c.roles.burner = nid(address(this));
        c.lockedFeatures |= uint256(1) << B30; // no admin: the seat lives on a locked bit
        t = NormalToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), salt));
    }

    function test_kind2_seatBurnsNonHolderRefused() public {
        NormalToken t = _b2("b2");
        t.mint(address(this), 100, EnvKit.codeUidOf(address(t)));
        t.mint(address(0xB0B), 100, EnvKit.codeUidOf(address(t)));
        t.burn(40);
        assertEq(t.totalSupply(), 160);
        vm.expectRevert(missing30(address(0xB0B)));
        vm.prank(address(0xB0B));
        t.burn(1);
    }

    function test_kind2_initRefusals() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features |= uint256(1) << B30;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureConflict.selector, B30, B2));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "c");
        c = _cfg(false, uint256(1) << 40);
        c.maxWrapSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "m");
    }
}

contract GovBurnerKind4Test is PqzFixture {
    function setUp() public {
        _stack();
    }

    function _b4(bytes32 salt) internal returns (NormalPqzToken t) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = toBurner(c.features);
        c.roles.burner = nid(address(this));
        c.lockedFeatures |= uint256(1) << B30;
        t = NormalPqzToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), salt));
    }

    function test_kind4_seatBurnsNonHolderRefused() public {
        NormalPqzToken t = _b4("b4");
        _public(t, address(this), 100);
        _public(t, address(0xB0B), 100);
        t.burn(40);
        assertEq(t.totalSupply(), 160);
        vm.expectRevert(missing30(address(0xB0B)));
        vm.prank(address(0xB0B));
        t.burn(1);
    }

    function test_kind4_initRefusals() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features |= uint256(1) << B30;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureConflict.selector, B30, B2));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "c");
        c = _cfg(uint256(1) << 40);
        c.maxWrapSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "m");
    }

    /// O1: the unshield (`R_BURN`) of a non-holder is not gated by `BURNER` and leaves `totalSupply()` unchanged; the burn
    /// after it is role-checked.
    function test_kind4_unshieldNotGated() public {
        NormalPqzToken t = _b4("u4");
        _fund(t, alice, 1_000);
        uint256 s0 = t.totalSupply();
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(31, PqzCt.CT));
        t.mtxUnshield(_bs(pl), 100, bytes32(uint256(uint160(address(0xD00D)))), hex"c0de", _pqAuth(), "", noVerdict());
        assertEq(t.balanceOf(address(0xD00D)), 100 * SCALE, "unshielded by a non-holder");
        assertEq(t.totalSupply(), s0, "an unshield is not a burn");
        vm.expectRevert(missing30(address(0xD00D)));
        vm.prank(address(0xD00D));
        t.burn(1);
    }
}

contract GovBurnerKind10Test is ZetherRegFixture {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_kind10_seatBurnsNonHolderRefused() public {
        IFactoryToken.TokenConfig memory c = _regCfg(false, uint256(1) << 40);
        c.features = toBurner(c.features);
        c.roles.burner = nid(address(this));
        NormalToken t = NormalToken(factory.createToken(_kind(), 1, abi.encode(c), "b10"));
        t.mint(address(this), 100, EnvKit.codeUidOf(address(t)));
        t.mint(address(0xB0B), 100, EnvKit.codeUidOf(address(t)));
        t.burn(40);
        assertEq(t.totalSupply(), 160);
        vm.expectRevert(missing30(address(0xB0B)));
        vm.prank(address(0xB0B));
        t.burn(1);
    }

    function test_kind10_initRefusals() public {
        IFactoryToken.TokenConfig memory c = _regCfg(false, uint256(1) << 40);
        c.features |= uint256(1) << B30;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureConflict.selector, B30, B2));
        factory.createToken(_kind(), 1, abi.encode(c), "c");
        c = _regCfg(false, uint256(1) << 40);
        c.maxWrapSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        factory.createToken(_kind(), 1, abi.encode(c), "m");
    }
}

contract GovBurnerKind12Test is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_kind12_seatBurnsNonHolderRefused() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features = toBurner(c.features);
        c.roles.burner = nid(address(this));
        NormalPqzToken t = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "b12"));
        _public(t, address(this), 100);
        _public(t, address(0xB0B), 100);
        t.burn(40);
        assertEq(t.totalSupply(), 160);
        vm.expectRevert(missing30(address(0xB0B)));
        vm.prank(address(0xB0B));
        t.burn(1);
    }

    function test_kind12_initRefusals() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= uint256(1) << B30;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureConflict.selector, B30, B2));
        factory.createToken(_kind(), 1, abi.encode(c), "c");
        c = _regCfg();
        c.maxWrapSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        factory.createToken(_kind(), 1, abi.encode(c), "m");
    }
}
