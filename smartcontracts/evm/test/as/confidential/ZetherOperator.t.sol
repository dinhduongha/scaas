// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";
import {nid} from "../../helpers/Ids.sol";

/// Plan T32 (owner 2026-11-05, CTR-GOV-20; CTR-GOV-13, CTR-GOV-17, never lose ciphertext; I8), the row T30 left open: on
/// kinds 10 and 11 `operatorTransfer` moves public balances only. A Zether UA holding a public (UA-ledger) balance and a
/// shielded one is moved by an EOA holder of bit 22: its public balance moves, and the call reads and writes no slot of
/// `scaas.zether` (the fields, the subject's `Account`), by state diff; the account state, `totalShielded` and the pool are
/// unchanged. Control: a shield to the subject touches its `Account` slots, so the diff sees them. Zether only (Zether ≠
/// PQZ: `PqzOperator.t.sol`).
abstract contract ZetherOperatorSuite is ZetherRegFixture {
    uint256 internal constant PUBLIC = 50_000;
    address internal constant BENEFICIARY = address(0xBEE);
    address internal constant CLERK = address(0xC1E2);
    bytes32 internal constant ZETHER_SLOT = keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff));
    uint256 internal constant ACCT_FIELD = 8; // ZetherStorage.acct
    uint256 internal constant FIELDS = 13; // verifier … minDecoyFee
    uint256 internal constant ACCOUNT_SLOTS = 6; // accC, accD, pendC, pendD, the seqs, modeNonce ‖ mode

    function setUp() public override {
        super.setUp();
        IFactoryToken.TokenConfig memory c = _regCfg(true, uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.OPERATOR_TRANSFER;
        c.grantDelay = 0; // the grant applies at once
        tok = NormalZetherToken(factory.createToken(_kind(), 1, abi.encode(c), "zop"));
        vm.prank(ownerA);
        IGovernance(address(tok)).grantRole(GovernanceBits.OPERATOR_TRANSFER, nid(CLERK));
        _funded(300);
        _public(tok, address(this), PUBLIC);
        tok.transferToUA(aId, PUBLIC);
    }

    function _shieldedSlot(bytes32 slot) internal view returns (bool) {
        uint256 s = uint256(slot);
        uint256 base = uint256(ZETHER_SLOT);
        if (s >= base && s < base + FIELDS) return true;
        uint256 acct = uint256(keccak256(abi.encode(aId, base + ACCT_FIELD)));
        return s >= acct && s < acct + ACCOUNT_SLOTS;
    }

    function _shieldedAccesses() internal returns (uint256 n) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 i; i < acc.length; ++i) {
            VmSafe.StorageAccess[] memory sa = acc[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) if (sa[j].account == address(tok) && _shieldedSlot(sa[j].slot)) ++n;
        }
    }

    function test_operatorTransferMovesPublicOnly_zetherStateUntouched() public {
        // control: a shield to alice touches her Account slots
        uint256 snap = vm.snapshotState();
        _public(tok, address(this), SCALE);
        vm.startStateDiffRecording();
        tok.mtxShield(aId, 1);
        assertGt(_shieldedAccesses(), 0, "control: the diff sees the Account slots");
        vm.revertToState(snap);

        IZetherToken.AccountState memory before = tok.accountState(alice.ua);
        uint256 shielded = tok.totalShielded();
        uint256 pool = tok.balanceOf(SHIELD_POOL_);
        vm.startStateDiffRecording();
        vm.prank(CLERK);
        _r().operatorTransfer(aId, nid(BENEFICIARY), 20_000, REF);
        assertEq(_shieldedAccesses(), 0, "operatorTransfer reads and writes no shielded state (I8)");

        assertEq(tok.balanceOfUA(aId), PUBLIC - 20_000, "the public balance");
        assertEq(tok.balanceOf(BENEFICIARY), 20_000);
        IZetherToken.AccountState memory a_ = tok.accountState(alice.ua);
        assertEq(keccak256(abi.encode(a_)), keccak256(abi.encode(before)), "the Account (ciphertexts, seqs) unchanged");
        assertEq(tok.totalShielded(), shielded);
        assertEq(tok.balanceOf(SHIELD_POOL_), pool);
        assertTrue(_holds(tok, alice, 300, true), "the shielded balance");
    }

    /// The public balance is the bound: past it the move fails, the shielded units are never reached.
    function test_operatorTransferCannotReachShielded() public {
        vm.prank(CLERK);
        vm.expectRevert();
        _r().operatorTransfer(aId, nid(BENEFICIARY), PUBLIC + 1, REF);
        vm.prank(CLERK);
        _r().operatorTransfer(aId, nid(BENEFICIARY), PUBLIC, REF); // the control
        assertTrue(_holds(tok, alice, 300, true), "the shielded balance");
    }
}

contract ZetherOperator10Test is ZetherOperatorSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract ZetherOperator11Test is ZetherOperatorSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
