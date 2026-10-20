// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {IConfidentialUnderlyingToken} from "../../src/confidential/IConfidentialToken.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {HookLeg} from "../zether/ZetherUnderlying.t.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// `UNDERLYING_PQZ` (P6g plan Task 6): a leg's underlying straight into a TRIVIAL pending entry (plan 5h D18) and a burn straight out to a
/// leg, the direct binding of the leg and `minOut` (D12), the reserve invariant.
contract PqzUnderlyingTest is PqzFixture {
    MockERC20 internal usd;
    UnderlyingPqzToken internal w;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.UNDERLYING_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID_(), address(reg), address(pqv)), type(UnderlyingPqzToken).creationCode);
        usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << AdminLib.PAYABLE);
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        w = UnderlyingPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, abi.encode(c), "w")));
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
        w.mtxWrapShield(address(usd), SCALE + 1, alice);
        uint256 g = gasleft();
        w.mtxWrapShield(address(usd), 1_000 * SCALE, alice);
        console2.log("mtxWrapShield gas", g - gasleft());
        assertEq((w.pqzPending(alice, 0) >> 96) & type(uint64).max, 1_000, "the same TRIVIAL entry as a shield");
        assertEq(w.totalSupply(), 1_000 * SCALE, "minted to SHIELD_POOL (D19)");
        assertEq(w.totalShielded(), 1_000);
        assertEq(usd.balanceOf(address(w)), 1_000 * SCALE);

        bytes memory nb = _blob(21, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), nb);
        IConfidentialUnderlyingToken.Unwrap memory x = IConfidentialUnderlyingToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 400, 400 * SCALE);
        bytes memory st = w.unshieldUnwrapStatement(pl, x, 0);
        assertEq(bytes32(_cut(st, 544, 32)), w.unwrapBinding(address(usd), 400 * SCALE), "direct: leg and minOut bound");
        assertEq(uint256(bytes32(_cut(st, 288, 32))), 400);
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(50_048), st, hex"c0de"));
        g = gasleft();
        w.mtxUnshieldUnwrap(pl, hex"c0de", _mlAuth(), _benM(pl), "", x);
        console2.log("mtxUnshieldUnwrap (mocked proof) gas", g - gasleft());
        assertEq(usd.balanceOf(address(0xD00D)), 400 * SCALE);
        assertEq(w.totalShielded(), 600);
        assertGe(usd.balanceOf(address(w)), w.totalSupply(), "reserve invariant (the pool is in totalSupply)");
        // minOut above the quote
        pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(22, PqzCt.CT));
        x = IConfidentialUnderlyingToken.Unwrap(address(usd), bytes32(uint256(uint160(address(0xD00D)))), 10, 10 * SCALE + 1);
        vm.expectRevert();
        w.mtxUnshieldUnwrap(pl, hex"c0de", _mlAuth(), _benM(pl), "", x);
        // an unknown leg
        x = IConfidentialUnderlyingToken.Unwrap(address(0xBAD), bytes32(uint256(uint160(address(0xD00D)))), 10, 0);
        vm.expectRevert();
        w.mtxUnshieldUnwrap(pl, hex"c0de", _mlAuth(), _benM(pl), "", x);
    }

    /// W-Q(f) / CTR-MTX-18: the kind's restated `disableFeature` and `executeRate` carry the guard too; a hook leg that
    /// calls either mid-pull gets `Reentrancy` (before 5g: the entry's own refusal).
    function test_reentryIntoTheRestatedAdminEntriesRefused() public {
        HookLeg hook = new HookLeg();
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << AdminLib.PAYABLE);
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(hook), 1, 1);
        UnderlyingPqzToken z =
            UnderlyingPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, abi.encode(c), "hook")));
        hook.mint(address(this), SCALE);
        hook.approve(address(z), SCALE);
        bytes[2] memory calls =
            [abi.encodeCall(z.disableFeature, (AdminLib.RATE_ADJUSTABLE)), abi.encodeCall(z.executeRate, ())];
        for (uint256 i; i < 2; ++i) {
            hook.arm(address(z), calls[i]);
            vm.expectRevert(IMetaTx.Reentrancy.selector);
            z.mtxWrapShield(address(hook), SCALE, alice);
        }
    }

    function test_publicWrapThenShield() public {
        usd.mint(address(this), 50 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.wrap(address(usd), 50 * SCALE);
        w.mtxShield(bob, 20);
        assertEq(w.totalSupply(), 50 * SCALE, "the shield moved 20 to the pool");
        assertEq(w.totalShielded(), 20);
        // burn through mtxUnshield moves public units out of the pool (supply unchanged)
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), bob, bytes32(0)),
            _blob(23, PqzCt.CT));
        w.mtxUnshield(pl, hex"c0de", _mlAuth(), _benM(pl), "", 5, bytes32(uint256(uint160(address(this)))));
        assertEq(w.totalSupply(), 50 * SCALE);
        assertEq(w.balanceOf(address(this)), 35 * SCALE);
        assertEq(usd.balanceOf(address(w)), w.totalSupply());
    }

    /// The largest implementation (`UnderlyingPqzToken`, plan 5g-Z) fits one Osaka transaction as `deploy.sh` sends a
    /// deploy (gas limit = forge's estimate × `--gas-estimate-multiplier 105`; forge's estimate ran ~1.05× the measured
    /// CREATE2 + intrinsic + calldata, ZetherDeploy.t): not with forge's default ×1.30. Init code over EIP-3860's 49,152
    /// fits 7622 / anvil (131,072 with `--code-size-limit 65536`).
    /// Plan 5g-Z2: measured through `OpenFactory.deployImplementation` itself (the env appended, the release's checks),
    /// as the registrar's transaction: intrinsic + calldata + the call.
    function test_largestImplementationFitsOneOsakaTx() public {
        bytes memory code = type(UnderlyingPqzToken).creationCode;
        bytes memory data_ = abi.encodeCall(factory.deployImplementation, (IOpenFactory.TokenKind.UNDERLYING_PQZ, 2, 1, code, ""));
        vm.prank(registrar);
        uint256 g = gasleft();
        address a = factory.deployImplementation(IOpenFactory.TokenKind.UNDERLYING_PQZ, 2, 1, code, "");
        g -= gasleft();
        uint256 data;
        for (uint256 j; j < data_.length; ++j) data += data_[j] == 0 ? 4 : 16;
        uint256 txGas = 21_000 + data + g;
        uint256 init = code.length + abi.encode(uint16(1), factory.envOf(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1),
            bytes("")).length;
        emit log_named_uint("UnderlyingPqzToken init code bytes (with the env)", init);
        emit log_named_uint("UnderlyingPqzToken runtime bytes", a.code.length);
        emit log_named_uint("UnderlyingPqzToken deployImplementation tx gas", txGas);
        assertGt(init, 49_152, "over EIP-3860: 64 KiB chains only");
        assertLe(init, 131_072);
        assertLt(txGas * 105 * 105 / 10_000, 1 << 24, "fits EIP-7825 with --gas-estimate-multiplier 105");
        assertGt(txGas * 105 * 130 / 10_000, 1 << 24, "forge's default x1.30 would not");
    }
}
