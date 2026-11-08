// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {nid} from "../../helpers/Ids.sol";

/// Plan T30 (regulated-kinds spec §3.3, §4.3; CTR-GOV-17, never lose ciphertext; I8): on kinds 10 and 11 `FORCE` moves the
/// subject's public balance only. A frozen Zether UA holding a public (UA-ledger) balance and a shielded one is forced:
/// its public balance moves to the beneficiary, and the call reads and writes no slot of `scaas.zether` (the fields, the
/// subject's `Account`), by state diff; the account state, `totalShielded` and the pool are unchanged. Control: a shield to
/// the subject touches its `Account` slots, so the diff sees them.
abstract contract ZetherForceSuite is ZetherRegFixture {
    uint256 internal constant PUBLIC = 50_000;
    address internal constant BENEFICIARY = address(0xBEE);
    /// keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant ZETHER_SLOT = keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff));
    uint256 internal constant ACCT_FIELD = 8; // ZetherStorage.acct
    uint256 internal constant FIELDS = 13; // verifier … minDecoyFee
    uint256 internal constant ACCOUNT_SLOTS = 6; // accC, accD, pendC, pendD, the seqs, modeNonce ‖ mode
    bytes32 internal subject; // whose Account `_shieldedSlot` names

    function setUp() public override {
        super.setUp();
        _funded(300);
        _public(tok, address(this), PUBLIC);
        tok.transferToUA(aId, PUBLIC);
    }

    /// The `scaas.zether` slots a forced transfer of `alice` must not touch.
    function _shieldedSlot(bytes32 slot) internal view returns (bool) {
        uint256 s = uint256(slot);
        uint256 base = uint256(ZETHER_SLOT);
        if (s >= base && s < base + FIELDS) return true;
        uint256 acct = uint256(keccak256(abi.encode(subject, base + ACCT_FIELD)));
        return s >= acct && s < acct + ACCOUNT_SLOTS;
    }

    /// The token's storage accesses (its own frames and the libraries' `DELEGATECALL`s) between `vm.startStateDiffRecording` and now that fall in `_shieldedSlot`.
    function _shieldedAccesses() internal returns (uint256 n) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 i; i < acc.length; ++i) {
            VmSafe.StorageAccess[] memory sa = acc[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) if (sa[j].account == address(tok) && _shieldedSlot(sa[j].slot)) ++n;
        }
    }

    function test_forceMovesPublicOnly_zetherStateUntouched() public {
        subject = aId;
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ZETHER_SLOT) + 1))), SCALE, "the namespace (shieldScale at +1)");
        // control: a shield to alice touches her Account slots
        uint256 snap = vm.snapshotState();
        _public(tok, address(this), SCALE);
        vm.startStateDiffRecording();
        tok.mtxShield(aId, 1);
        assertGt(_shieldedAccesses(), 0, "control: the diff sees the Account slots");
        vm.revertToState(snap);

        vm.prank(compliance);
        _r().recordOrder(keccak256("order"), keccak256("document"), aId, nid(BENEFICIARY), PUBLIC, uint64(block.timestamp + 10 days));
        bytes32 rid = keccak256(abi.encode(keccak256("order"), aId, nid(BENEFICIARY)));
        vm.prank(issuer);
        _r().freeze(aId, REF, rid);

        IZetherToken.AccountState memory before = tok.accountState(alice.ua);
        uint256 shielded = tok.totalShielded();
        uint256 pool = tok.balanceOf(SHIELD_POOL_);
        vm.startStateDiffRecording();
        vm.prank(issuer);
        _r().forceTransfer(rid, 20_000);
        assertEq(_shieldedAccesses(), 0, "FORCE reads and writes no shielded state (I8)");

        assertEq(tok.balanceOfUA(aId), PUBLIC - 20_000, "the subject's public balance");
        assertEq(tok.balanceOf(BENEFICIARY), 20_000);
        IZetherToken.AccountState memory a_ = tok.accountState(alice.ua);
        assertEq(keccak256(abi.encode(a_)), keccak256(abi.encode(before)), "the Account (ciphertexts, seqs) unchanged");
        assertEq(tok.totalShielded(), shielded);
        assertEq(tok.balanceOf(SHIELD_POOL_), pool);
        assertTrue(_holds(tok, alice, 300, true), "the shielded balance");
    }
}

contract ZetherForce10Test is ZetherForceSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract ZetherForce11Test is ZetherForceSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
