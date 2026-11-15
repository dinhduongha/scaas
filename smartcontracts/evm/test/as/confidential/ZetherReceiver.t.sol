// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedPqzRegulatedTokenCore} from "../../../src/regulated/WrappedPqzRegulatedTokenCore.sol";

import {NormalPqzTokenCore} from "../../../src/pqz/NormalPqzTokenCore.sol";

import {WrappedPqzTokenCore} from "../../../src/pqz/WrappedPqzTokenCore.sol";

import {NormalToken} from "../../../src/metatx/NormalToken.sol";

import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {TokenStore} from "../../../src/metatx/TokenStore.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {nid} from "../../helpers/Ids.sol";

/// Plan T30 (regulated-kinds spec §4, §4.1; CTR-GOV-17, CTR-GOV-18; I9): on kinds 10 and 11 with `DENYLIST` and `FREEZE`, no
/// check reads a ring member, a leg or a `yTo`: a transfer whose decoys are a frozen and a denied account succeeds, and each
/// leg's `decoyFee` reaches them (the owner's decoy-fee exception). The public names are checked: a denied beneficiary and a
/// denied unshield recipient are refused `NotEligible`. `ALLOWLIST` is outside the kinds' mask.
abstract contract ZetherReceiverSuite is ZetherRegFixture {
    uint256 internal constant BAL = 500;
    uint256 internal constant DECOY_FEE = 1;
    address internal constant DENIED = address(0xDE41ED);

    function _denylist() internal pure override returns (bool) { return true; }

    function setUp() public override {
        (decoyFee, minDecoy) = (DECOY_FEE, DECOY_FEE);
        super.setUp();
        _funded(BAL);
        _attestDenied(dId);
        _attestDenied(nid(DENIED));
    }

    /// I9: legs `bob` (10), `dave` (denied, 0), `carol` (frozen, 0); every leg is paid its `decoyFee`. Controls: the same two
    /// accounts named as the beneficiary are refused, so the list and the freeze are live.
    function test_frozenAndDeniedDecoysReceive() public {
        _freeze(cId);
        User[] memory to = new User[](3);
        (to[0], to[1], to[2]) = (bob, dave, carol);
        uint256[] memory vs = new uint256[](3);
        vs[0] = 10;
        (bool ok, bytes memory r,) = _try(_multiTo(to, vs, BAL, _none()));
        assertTrue(ok, string(r));
        assertEq(tok.balanceOfUA(dId), DECOY_FEE * SCALE, "the denied decoy's decoyFee");
        assertEq(tok.balanceOfUA(cId), DECOY_FEE * SCALE, "the frozen decoy's decoyFee");
        assertTrue(_holds(tok, bob, 10, false));

        User[] memory one = new User[](1);
        one[0] = bob;
        uint256[] memory v1 = new uint256[](1);
        v1[0] = 1;
        (bool ok2, bytes memory ret,) = _try(_multiTo(one, v1, BAL - 10 - 3 * DECOY_FEE, dave.ua));
        assertFalse(ok2);
        assertEq(ret, _deniedErr(dId), "control: a denied beneficiary");
        (ok2, ret,) = _try(_multiTo(one, v1, BAL - 10 - 3 * DECOY_FEE, carol.ua));
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, cId), "control: a frozen beneficiary");
    }

    /// The unshield's `recipient` passes `R` when the amount is not 0; the denied one is refused, an undenied one passes.
    function test_deniedUnshieldRecipientRefused() public {
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, BAL, address(0xB0C), _none(), 0);
        (bool ok,,) = _try(abi.encodeWithSelector(IZetherToken.mtxUnshield.selector, _zBurn(pl, _none()), 10,
            MetaTxLib.pad(address(0xB0C)), pr));
        assertTrue(ok, "control: an undenied recipient");
        (pl, pr) = _proveUnshield(tok, alice, 10, BAL - 10, DENIED, _none(), 0);
        (bool ok2, bytes memory ret,) = _try(abi.encodeWithSelector(IZetherToken.mtxUnshield.selector,
            _zBurn(pl, _none()), 10, nid(DENIED), pr));
        assertFalse(ok2);
        assertEq(ret, _deniedErr(nid(DENIED)));
    }

    /// Round 3s (spec §4.3, M5): the proof's sender (`_regZetherSender` → `_regSender`) is checked by the deny list before the
    /// proof (`Denied(uaOf(yFrom))`); the registry's check is receiver-only (CTR-AS-07), so a sender the registry denies
    /// sends. Each with its control: the sender not denied passes.
    function test_deniedSender() public {
        for (uint256 k; k < 4; ++k) {
            bytes memory cd = _opCall(k, BAL, 0);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control: the sender not denied");
            vm.revertToState(snap);
            _attestDenied(aId);
            (bool ok2, bytes memory ret,) = _try(cd);
            if (_lists()) {
                assertFalse(ok2);
                assertEq(ret, _deniedErr(aId), "the list checks the sender");
            } else {
                assertTrue(ok2, "the registry checks receivers only");
            }
            vm.revertToState(snap);
        }
    }

    /// CTR-GOV-17: bit 8 is outside the confidential kinds' mask; the kind answers its id and `IRegulatedToken`.
    function test_allowlistInvalidAndKind() public {
        IFactoryToken.TokenConfig memory c = _regCfg(true, uint256(1) << 40);
        c.features |= 1 << GovernanceBits.ALLOWLIST;
        c.reg.requiredFlags = 1;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(GovernanceBits.ALLOWLIST)));
        factory.createToken(_kind(), 1, abi.encode(c), "allow");
        assertEq(NormalToken(address(tok)).kind(), _isWrapped() ? TokenStore.KIND_WRAPPED_ZETHER_REGULATED
            : TokenStore.KIND_NORMAL_ZETHER_REGULATED);
        assertTrue(NormalToken(address(tok)).supportsInterface(type(IRegulatedToken).interfaceId));
    }
}

contract ZetherReceiver10Test is ZetherReceiverSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }

    /// Zether ≠ PQZ (spec §4.3, §9 "a Zether site hook in `PqzLayer`"): the Zether sender hook lives in `ZetherLayer` and the
    /// two Zether kinds only; no PQZ source names it. Control: `ZetherLayer` does.
    function test_zetherHookNotInPqz() public view {
        assertTrue(vm.contains(vm.readFile("src/zether/ZetherLayer.sol"), "_regZetherSender"), "control");
        string[8] memory pqz = ["src/pqz/PqzLayer.sol", "src/pqz/NormalPqzTokenCore.sol", "src/pqz/WrappedPqzTokenCore.sol",
            "src/pqz/PqzTransferLib.sol", "src/pqz/PqzBurnLib.sol", "src/pqz/PqzWrappedLib.sol",
            "src/regulated/WrappedPqzRegulatedTokenCore.sol", "src/regulated/RegulatedBase.sol"];
        for (uint256 i; i < pqz.length; ++i) assertFalse(vm.contains(vm.readFile(pqz[i]), "_regZetherSender"), pqz[i]);
    }
}

contract ZetherReceiver11Test is ZetherReceiverSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}

/// Round 3s (spec 2026-11-10-token-lists.md §4.3, §13 (2)): the same suite with `DENYLIST` as the token's own list: the
/// confidential sites (sender, beneficiary, unshield recipient) refuse `Denied`; a denied decoy still receives (I9, M28).
contract ZetherLists10Test is ZetherReceiver10Test {
    function _lists() internal pure override returns (bool) { return true; }
}

contract ZetherLists11Test is ZetherReceiver11Test {
    function _lists() internal pure override returns (bool) { return true; }
}
