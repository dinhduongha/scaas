// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {nid} from "../../helpers/Ids.sol";

/// Plan T31 (regulated-kinds spec §3.3, §4.3; CTR-GOV-17, never lose ciphertext; I8): on kinds 12 and 13 `FORCE` moves the
/// subject's public balance only. A frozen PQZ UA holding a public (UA-ledger) balance and a shielded one is forced: its
/// public balance moves to the beneficiary, and the call reads and writes no slot of `scaas.pqz` (the fields,
/// `totalShielded` among them; the subject's `Account`, its pending entries and `acc` words), by state diff; `acc`, the
/// pending entries, `totalShielded` and the pool are unchanged. Control: a shield to the subject touches those slots, so the
/// diff sees them. `MODERATE` has no body (CTR-GOV-20); its replacement `operatorTransfer` is T32's.
abstract contract PqzForceSuite is PqzRegFixture {
    uint256 internal constant PUBLIC = 50_000;
    address internal constant BENEFICIARY = address(0xBEE);

    function setUp() public override {
        super.setUp();
        _shieldTo(alice, 300);
        _pub(address(this), PUBLIC);
        tok.transferToUA(alice, PUBLIC);
    }

    function test_forceMovesPublicOnly_pqzStateUntouched() public {
        // control: a shield to alice touches her Account and totalShielded
        uint256 snap = vm.snapshotState();
        _pub(address(this), SCALE);
        vm.startStateDiffRecording();
        tok.mtxShield(alice, 1);
        assertGt(_pqzAccesses(alice, true), 0, "control: the diff sees the PQZ slots");
        vm.revertToState(snap);

        vm.prank(compliance);
        _r().recordOrder(keccak256("order"), keccak256("document"), alice, nid(BENEFICIARY), PUBLIC,
            uint64(block.timestamp + 10 days));
        bytes32 rid = keccak256(abi.encode(keccak256("order"), alice, nid(BENEFICIARY)));
        vm.prank(issuer);
        _r().freeze(alice, REF, rid);

        IPqzToken.AccountState memory before = tok.pqzAccount(alice, 0);
        bytes memory acc = tok.pqzAcc(alice, 0);
        uint256 p0 = tok.pqzPending(alice, 0, 0);
        uint256 shielded = tok.totalShielded();
        uint256 pool = tok.balanceOf(MetaTxLib.SHIELD_POOL);
        vm.startStateDiffRecording();
        vm.prank(issuer);
        _r().forceTransfer(rid, 20_000);
        assertEq(_pqzAccesses(alice, true), 0, "FORCE reads and writes no PQZ state (I8)");

        assertEq(tok.balanceOfUA(alice), PUBLIC - 20_000, "the subject's public balance");
        assertEq(tok.balanceOf(BENEFICIARY), 20_000);
        assertEq(keccak256(abi.encode(tok.pqzAccount(alice, 0))), keccak256(abi.encode(before)), "the Account unchanged");
        assertEq(tok.pqzAcc(alice, 0), acc, "acc unchanged");
        assertEq(tok.pqzPending(alice, 0, 0), p0, "the pending entry unchanged");
        assertEq(tok.totalShielded(), shielded);
        assertEq(tok.balanceOf(MetaTxLib.SHIELD_POOL), pool);
    }
}

contract PqzForce12Test is PqzForceSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzForce13Test is PqzForceSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
