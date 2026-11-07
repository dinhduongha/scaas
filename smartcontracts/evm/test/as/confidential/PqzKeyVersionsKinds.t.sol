// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IMetaTx} from "../../../src/metatx/IMetaTx.sol";
import {UACall} from "../../ua/UACall.sol";

/// Group 3g T52 on the regulated PQZ kinds 12 and 13 (spec §3.5, §10 row 21): `mtxSelectors()` lists the versioned PQZ
/// rollover and prepare and no two-argument form; a stale version pays no one there either (KV-8). UNAUDITED.
abstract contract PqzKeyVersionsKinds is PqzRegFixture {
    function _has(bytes4 sel) internal view returns (bool found) {
        (bytes4[] memory s,,) = IMetaTx(address(tok)).mtxSelectors();
        for (uint256 i; i < s.length; ++i) if (s[i] == sel) found = true;
    }

    function _selectors() internal view {
        assertTrue(_has(IPqzToken.mtxRollOver.selector), "mtxRollOver(bytes32,uint64,uint256)");
        assertTrue(_has(IPqzToken.mtxPrepareAcc.selector), "mtxPrepareAcc(bytes32,uint64,uint256)");
        assertFalse(_has(bytes4(keccak256("mtxRollOver(bytes32,uint256)"))), "no two-argument rollover");
        assertFalse(_has(bytes4(keccak256("mtxPrepareAcc(bytes32,uint256)"))), "no two-argument prepare");
    }

    function test_staleKeyVersion_refused() public {
        _shieldTo(alice, BAL);
        bytes memory proof = abi.encodePacked("pqzver", alice, uint64(1));
        reg.setPqzKey(alice, 1, _pk(91), keccak256(proof), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(alice, 1, proof);
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), ""));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.StaleKeyVersion.selector, alice, uint64(0), uint64(1)));
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
    }
}

contract PqzKeyVersionsKind12Test is PqzKeyVersionsKinds {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_mtxSelectors_pqzver_12() public view { _selectors(); }
}

contract PqzKeyVersionsKind13Test is PqzKeyVersionsKinds {
    function _isWrapped() internal pure override returns (bool) { return true; }

    function test_mtxSelectors_pqzver_13() public view { _selectors(); }
}
