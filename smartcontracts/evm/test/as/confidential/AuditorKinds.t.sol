// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {ZetherKeys} from "../../zether/helpers/ZetherKeys.sol";
import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";
import {nid} from "../../helpers/Ids.sol";

/// Set-auditor (spec §5.5, plan A2 / A4): the regulated twins 10, 11 (Zether) and 12, 13 (PQZ) take the setter and the views
/// from their base layer, nothing regulated-specific: bit 32 granted by the admin under its grant delay, a proposal waits
/// `max(noticePeriod, grantDelay)` (here the fixture's grant delay, 1 day), the confirm applies, an audited transfer at
/// epoch 1 records its epoch and answers the new auditor. UNAUDITED.
abstract contract ZetherAuditorKinds is ZetherRegFixture {
    function test_auditorReplaced_regulatedZether() public {
        IFactoryToken.TokenConfig memory c = _regCfg(true, uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.AUDITOR;
        tok = NormalZetherToken(factory.createToken(_kind(), 1, abi.encode(c), "zr-aud"));
        bytes32 uid = EnvKit.codeUidOf(address(tok));
        address h = address(0xA0D);
        for (uint256 i; i < 2; ++i) {
            vm.prank(ownerA);
            IGovernance(address(tok)).grantRole(GovernanceBits.AUDITOR, nid(h), uid);
            if (i == 0) vm.warp(block.timestamp + 1 days);
        }
        bytes memory y = ZetherKeys.pub(0xB0D1E5, bls);
        bytes memory pop = _auditorPop(tok, 0xB0D1E5, 1);
        vm.prank(h);
        tok.setAuditorKey(y, 1, pop, uid);
        (,, uint64 eta,, uint8 st) = tok.auditorState();
        assertEq(st, 1);
        assertEq(eta, block.timestamp + 1 days, "the grant delay");
        vm.warp(eta);
        vm.prank(h);
        tok.setAuditorKey(y, 1, pop, uid);
        assertEq(tok.auditorKey(), y);
        _funded(100);
        bytes32 ref = _direct(tok, _proveTransfer(tok, alice, bob, 10, 100, _none(), 0), _none());
        assertEq(tok.auditorKeyOf(ref), y, "the entry's auditor: epoch 1");
        assertEq(tok.auditorKeyOf(bytes32(0)), ZetherKeys.pub(X_AUD, bls), "an unknown ref: epoch 0's");
    }
}

contract ZetherAuditorKind10Test is ZetherAuditorKinds {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }
}

contract ZetherAuditorKind11Test is ZetherAuditorKinds {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }
}

abstract contract PqzAuditorKinds is PqzRegFixture {
    function test_auditorReplaced_regulatedPqz() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= uint256(1) << GovernanceBits.AUDITOR;
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "pr-aud"));
        bytes32 uid = EnvKit.codeUidOf(address(tok));
        address h = address(0xA0D);
        for (uint256 i; i < 2; ++i) {
            vm.prank(ownerA);
            IGovernance(address(tok)).grantRole(GovernanceBits.AUDITOR, nid(h), uid);
            if (i == 0) vm.warp(block.timestamp + 1 days);
        }
        bytes32 next = _pqzUA(_pk(41), 41);
        vm.prank(h);
        tok.setAuditorUA(next, 1, _pqAuth(), uid);
        (,, uint64 eta,, uint8 st) = tok.auditorState();
        assertEq(st, 1);
        assertEq(eta, block.timestamp + 1 days, "the grant delay");
        vm.warp(eta);
        vm.prank(h);
        tok.setAuditorUA(next, 1, _pqAuth(), uid);
        assertEq(tok.auditorUA(), next);
        _shieldTo(alice, BAL);
        IPqzToken.PqzTransferArgs memory t = _ts(_payloadFor(tok, alice, bob, bytes32(0), _out(5, true)));
        bytes32 ref = tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict());
        assertEq(tok.auditorUAOf(ref), next, "the entry's auditor: epoch 1");
        assertEq(tok.auditorUAOf(bytes32(0)), aud, "an unknown ref: epoch 0's");
    }
}

contract PqzAuditorKind12Test is PqzAuditorKinds {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }
}

contract PqzAuditorKind13Test is PqzAuditorKinds {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }
}
