// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {nid} from "../../helpers/Ids.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

/// Plan T32 (owner 2026-11-05, CTR-GOV-20; CTR-GOV-13, CTR-GOV-17, never lose ciphertext; I8), the row T31 left open: on
/// kinds 12 and 13 `operatorTransfer` moves public balances only. A PQZ UA holding a public (UA-ledger) balance and a
/// shielded one is moved by an EOA holder of bit 22: its public balance moves, and the call reads and writes no slot of
/// `scaas.pqz` (the fields, `totalShielded` among them; the subject's `Account`, its pending entries and `acc` words), by
/// state diff. Control: a shield to the subject touches those slots, so the diff sees them. PQZ only (Zether ≠ PQZ:
/// `ZetherOperator.t.sol`).
abstract contract PqzOperatorSuite is PqzRegFixture {
    uint256 internal constant PUBLIC = 50_000;
    address internal constant BENEFICIARY = address(0xBEE);
    address internal constant CLERK = address(0xC1E2);

    function setUp() public override {
        super.setUp();
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= uint256(1) << GovernanceBits.OPERATOR_TRANSFER;
        c.grantDelay = 0; // the grant applies at once
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "pop"));
        w = WrappedPqzToken(payable(address(tok)));
        vm.prank(ownerA);
        IGovernance(address(tok)).grantRole(GovernanceBits.OPERATOR_TRANSFER, nid(CLERK), EnvKit.codeUidOf(address(IGovernance(address(tok)))));
        _shieldTo(alice, 300);
        _pub(address(this), PUBLIC);
        tok.transferToUA(alice, PUBLIC);
    }

    function test_operatorTransferMovesPublicOnly_pqzStateUntouched() public {
        uint256 snap = vm.snapshotState();
        _pub(address(this), SCALE);
        vm.startStateDiffRecording();
        tok.mtxShield(alice, 1);
        assertGt(_pqzAccesses(alice, true), 0, "control: the diff sees the PQZ slots");
        vm.revertToState(snap);

        IPqzToken.AccountState memory before = tok.pqzAccount(alice, 0);
        bytes memory acc = tok.pqzAcc(alice, 0);
        uint256 p0 = tok.pqzPending(alice, 0, 0);
        uint256 shielded = tok.totalShielded();
        uint256 pool = tok.balanceOf(MetaTxLib.SHIELD_POOL);
        vm.startStateDiffRecording();
        vm.prank(CLERK);
        _r().operatorTransfer(alice, nid(BENEFICIARY), 20_000, REF);
        assertEq(_pqzAccesses(alice, true), 0, "operatorTransfer reads and writes no PQZ state (I8)");

        assertEq(tok.balanceOfUA(alice), PUBLIC - 20_000, "the public balance");
        assertEq(tok.balanceOf(BENEFICIARY), 20_000);
        assertEq(keccak256(abi.encode(tok.pqzAccount(alice, 0))), keccak256(abi.encode(before)), "the Account unchanged");
        assertEq(tok.pqzAcc(alice, 0), acc, "acc unchanged");
        assertEq(tok.pqzPending(alice, 0, 0), p0, "the pending entry unchanged");
        assertEq(tok.totalShielded(), shielded);
        assertEq(tok.balanceOf(MetaTxLib.SHIELD_POOL), pool);
    }

    /// The public balance is the bound: past it the move fails, the shielded units are never reached.
    function test_operatorTransferCannotReachShielded() public {
        uint256 shielded = tok.totalShielded();
        vm.prank(CLERK);
        vm.expectRevert();
        _r().operatorTransfer(alice, nid(BENEFICIARY), PUBLIC + 1, REF);
        vm.prank(CLERK);
        _r().operatorTransfer(alice, nid(BENEFICIARY), PUBLIC, REF); // the control
        assertEq(tok.totalShielded(), shielded);
    }
}

contract PqzOperator12Test is PqzOperatorSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzOperator13Test is PqzOperatorSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
