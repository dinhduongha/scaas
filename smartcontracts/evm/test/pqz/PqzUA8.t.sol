// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "./helpers/PqzFixture.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// UA-8 Task A6 (UA8-D8, D9; ruling A5-c1): a PQZ token holds only proven PQZ keys. `PqzCore._keyPtr` reads
/// `pqzKeyOf(ua)` and refuses an unproven key with `AccountNotRegistered(ua)`, as for a UA without a key.
contract PqzUA8Test is PqzFixture {
    function setUp() public {
        _stack();
        tok = _newToken("pqz");
    }

    /// An `mldsa65` UA registered with a PQZ key and its proof hash but without the proof bytes: unproven.
    function _unproven(uint8 seed) internal returns (bytes32 u) {
        u = reg.register(UAKinds.MLDSA65, _mlPk(seed), _pqzAttrs(_pk(seed)), new bytes(ML65_SIG), "");
        (address ptr,, bool proven) = reg.pqzKeyOf(u);
        assertTrue(ptr != address(0), "the key is stored");
        assertFalse(proven);
    }

    /// `u` is no PQZ account: shield target, recipient leg and sender alike.
    function _assertNoAccount(bytes32 u) internal {
        bytes memory err = abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, u);
        _public(tok, address(this), SCALE);
        vm.expectRevert(err);
        tok.mtxShield(u, 1);
        _transfer(tok, carol, alice, bytes32(0), 100, false); // alice: one pending entry
        bytes memory out = _out(60, true);
        bytes memory pl = _payload(1, 0, alice, u, bytes32(0), out, "");
        vm.expectRevert(err); // credit to `u`
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        pl = _payload(0, 0, u, bob, bytes32(0), out, "");
        vm.expectRevert(err); // `u` as sender
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
    }

    function test_ua8_pqzTokenRefusesUnproven() public {
        _assertNoAccount(_unproven(30));
    }
}
