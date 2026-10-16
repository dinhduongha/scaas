// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzLib} from "../../src/pqz/PqzLib.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";

/// `UNDERLYING_PQZ` (P6g plan Task 6): a leg's underlying straight into `plainPending` and a burn straight out to a
/// leg, the direct binding of the leg and `minOut` (D12), the reserve invariant.
contract PqzUnderlyingTest is PqzFixture {
    MockERC20 internal usd;
    UnderlyingPqzToken internal w;

    function setUp() public {
        _stack();
        UnderlyingPqzToken impl = new UnderlyingPqzToken(address(factory), address(0), PQZ_UID_(), address(reg));
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, address(impl));
        usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << AdminLib.PAYABLE);
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        w = UnderlyingPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, c, "w")));
        tok = PqzLayer(address(w));
    }

    function PQZ_UID_() internal pure returns (bytes32) {
        return 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    }

    function test_wrapShieldAndUnshieldUnwrap() public {
        assertEq(w.kind(), 5);
        usd.mint(address(this), 1_000 * SCALE + 1);
        usd.approve(address(w), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountNotScaled.selector, SCALE + 1, SCALE));
        w.pqzWrapShield(address(usd), SCALE + 1, alice);
        uint256 g = gasleft();
        w.pqzWrapShield(address(usd), 1_000 * SCALE, alice);
        console2.log("pqzWrapShield gas", g - gasleft());
        assertEq(w.accountState(alice).plainPending, 1_000);
        assertEq(w.totalSupply(), 0, "nothing minted");
        assertEq(w.totalShielded(), 1_000);
        assertEq(usd.balanceOf(address(w)), 1_000 * SCALE);

        bytes memory nb = _blob(21, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(1_000), alice, bytes32(0)), nb);
        UnderlyingPqzToken.Unwrap memory x = UnderlyingPqzToken.Unwrap(address(usd), address(0xD00D), 400, 400 * SCALE);
        bytes memory st = w.unshieldUnwrapStatement(pl, _acc(alice), new bytes[](0), x, 0);
        assertEq(bytes32(_cut(st, 544, 32)), w.unwrapBinding(address(usd), 400 * SCALE), "direct: leg and minOut bound");
        assertEq(uint256(bytes32(_cut(st, 288, 32))), 400);
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(50_048), st, hex"c0de"));
        g = gasleft();
        w.pqzUnshieldUnwrap(pl, _acc(alice), new bytes[](0), x, hex"c0de", _mlAuth());
        console2.log("pqzUnshieldUnwrap (mocked proof) gas", g - gasleft());
        assertEq(usd.balanceOf(address(0xD00D)), 400 * SCALE);
        assertEq(w.totalShielded(), 600);
        assertGe(usd.balanceOf(address(w)), w.totalSupply() + w.totalShielded() * SCALE, "reserve invariant");
        // minOut above the quote
        accOf[alice] = nb;
        pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), alice, bytes32(0)), _blob(22, PqzCt.CT));
        x = UnderlyingPqzToken.Unwrap(address(usd), address(0xD00D), 10, 10 * SCALE + 1);
        vm.expectRevert();
        w.pqzUnshieldUnwrap(pl, _acc(alice), new bytes[](0), x, hex"c0de", _mlAuth());
        // an unknown leg
        x = UnderlyingPqzToken.Unwrap(address(0xBAD), address(0xD00D), 10, 0);
        vm.expectRevert();
        w.pqzUnshieldUnwrap(pl, _acc(alice), new bytes[](0), x, hex"c0de", _mlAuth());
    }

    function test_publicWrapThenShield() public {
        usd.mint(address(this), 50 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 50 * SCALE);
        w.pqzShield(bob, 20);
        assertEq(w.totalSupply(), 30 * SCALE);
        assertEq(w.totalShielded(), 20);
        // burn through pqzUnshield mints public units (reserve still covers them)
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(20), bob, bytes32(0)),
            _blob(23, PqzCt.CT));
        w.pqzUnshield(pl, _acc(bob), new bytes[](0), 5, address(this), hex"c0de", _mlAuth());
        assertEq(w.totalSupply(), 35 * SCALE);
        assertEq(usd.balanceOf(address(w)), w.totalSupply() + w.totalShielded() * SCALE);
    }
}
