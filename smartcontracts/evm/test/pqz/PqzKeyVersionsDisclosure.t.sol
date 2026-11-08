// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {UACall} from "../ua/UACall.sol";

/// Group 3g, T53 (spec 2026-11-06-pqz-key-versions §3.6 KV-11, §14): the PQZ disclosure names the key version it checks.
/// `keyVersion` selects which registered key of the leg's owner (the auditor's for `AUDITOR`) the opening is checked
/// against; a version not stored reverts `KeyVersionUnknown`. The verdict says whether the leg opens to `amount` under
/// that key; it does not attest which version the leg was encrypted for. The precompile is mocked (`PqzFixture`): op 5
/// (`RECEIVER_X`) answers 1 for exactly the statement under the version the credit was made for. UNAUDITED.
contract PqzKeyVersionsDisclosureTest is PqzFixture {
    bytes internal constant PROOF = hex"d15c";

    function setUp() public {
        _stack();
        tok = _newToken("pqzver-disc");
    }

    function _keyAt(bytes32 ua, uint64 v) internal view returns (bytes memory) {
        (address p,,) = reg.pqzKeyAt(ua, v);
        return SSTORE2.read(p);
    }

    /// bob's credit under version 0, then bob rotates; the receiver disclosure with `keyVersion` 0 checks version 0's
    /// key (true), with 1 checks version 1's (another statement: false under the exact-input precompile).
    function test_disclosure_right() public {
        _public(tok, address(this), 100 * SCALE);
        tok.mtxShield(alice, 100);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), "")),
            hex"c0de", _pqAuth(), "");
        bytes memory proof = abi.encodePacked("pqzver", bob, uint64(1));
        reg.setPqzKey(bob, 1, _pk(51), keccak256(proof), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(bob, 1, proof);
        bytes memory s0 = tok.disclosureStatement(ref, 0, 7, 1, 0);
        bytes memory s1 = tok.disclosureStatement(ref, 0, 7, 1, 1);
        assertEq(_slice(s0, 288, PqzCt.PK), _keyAt(bob, 0), "version 0's key");
        assertEq(_slice(s1, 288, PqzCt.PK), _pk(51), "version 1's key");
        vm.mockCall(PQZ, abi.encodePacked(uint8(5)), abi.encode(uint256(0)));
        vm.mockCall(PQZ, abi.encodePacked(uint8(5), uint32(s0.length), s0, PROOF), abi.encode(uint256(1)));
        assertTrue(tok.verifyTransferAmount(ref, 0, 7, 1, 0, PROOF), "the right version");
        assertFalse(tok.verifyTransferAmount(ref, 0, 7, 1, 1, PROOF), "another version's key: another statement");
    }

    /// A version not stored: `KeyVersionUnknown`, from the statement view and from the verdict.
    function test_disclosure_unknown() public {
        _public(tok, address(this), 100 * SCALE);
        tok.mtxShield(alice, 100);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_ts(_payload(1, 0, alice, bob, bytes32(0), _out(5, false), "")),
            hex"c0de", _pqAuth(), "");
        tok.disclosureStatement(ref, 0, 7, 1, 0); // control
        bytes memory err = abi.encodeWithSelector(IPqzToken.KeyVersionUnknown.selector, bob, uint64(1));
        vm.expectRevert(err);
        tok.disclosureStatement(ref, 0, 7, 1, 1);
        vm.expectRevert(err);
        tok.verifyTransferAmount(ref, 0, 7, 1, 1, PROOF);
        // `SENDER_S` checks the leg owner's key too (the sender opens with the randomness)
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyVersionUnknown.selector, bob, uint64(3)));
        tok.disclosureStatement(ref, 0, 7, 0, 3);
    }
}
