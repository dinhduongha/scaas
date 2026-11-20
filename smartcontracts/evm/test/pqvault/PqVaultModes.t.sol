// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V3 / V4 (spec §5.15, CTR-PQV-16, CTR-PQV-17; review r2 R5, R6, R11, R14): the two modes. Every write in mode 0
/// and mode 1 (positive controls); a mode-1 vault naming another home, `mode = 2`, a mode-1 record replayed into a second
/// instance, `mode` flipped after signing: refused; the ids of one creator and nonce differ by mode; an `msig` admin with a
/// native member in each mode; a native member's signature of one mode refused in the other; a record naming another vault
/// than its stored epoch's refused.
contract PqVaultModesTest is PqVaultBase {
    function _admins() internal view returns (bytes32[] memory) {
        return _list(ids[0]);
    }

    /// The group writes in `mode`: create, rekey, leave, remove, addVaultWraps; each lands.
    function _groupWrites(uint8 mode) internal returns (bytes32 vid, bytes32 e1) {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 11, mode, address(vault));
        vid = vault.createVault(v, _slice(w, 0, 2), _createSig(v, address(vault)));
        vault.addVaultWraps(vid, 2, _slice(w, 2, 3));
        assertTrue(vault.epochComplete(vid));
        _removeThird(vid, mode);
        e1 = _rekeyTwo(vid, mode);
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, e1, ids[1], 5);
        vault.leaveVault(l, _sig(ids[1], h.leave(l, _ds(mode, address(vault)))));
        assertTrue(vault.leftIn(e1, ids[1]));
    }

    function _removeThird(bytes32 vid, uint8 mode) internal {
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(vid, vid, 1, _list(ids[2]), ids[0], 3);
        vault.removeVaultMembers(r, _sig(ids[0], h.remove(r, _ds(mode, address(vault)))));
    }

    function _rekeyTwo(bytes32 vid, uint8 mode) internal returns (bytes32) {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(vid, ids[0], 4, 1, vid, _admins(), _without(_members(3), ids[2]));
        return _rekey(vault, e, ew, mode);
    }

    function test_groupWrites_mode0() public {
        _groupWrites(0);
    }

    /// Mode 1: the same writes, `modes[vaultId] = 1` in state (slot +12).
    function test_groupWrites_mode1() public {
        (bytes32 vid,) = _groupWrites(1);
        bytes32 slot = keccak256(abi.encode(vid, uint256(PqVaultTypesSlot.ROOT) + 12));
        assertEq(uint256(vm.load(address(vault), slot)), 1);
    }

    /// Mode 0 writes nothing for the mode.
    function test_mode0_noModeSlot() public {
        (bytes32 vid,) = _groupWrites(0);
        bytes32 slot = keccak256(abi.encode(vid, uint256(PqVaultTypesSlot.ROOT) + 12));
        assertEq(uint256(vm.load(address(vault), slot)), 0);
    }

    function test_mode1_otherHomeRefused() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 1, 1, address(vaultB));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.createVault(v, w, sig); // names B, submitted at A
        v.homeVaultContract = address(vault);
        v.homeChain = keccak256("another chain");
        sig = _createSig(v, address(vault));
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.createVault(v, w, sig); // names A on another chain
        (v, w) = _vault(1, 1, 1, address(vault));
        _create(vault, v, w); // the control
    }

    function test_mode2Refused() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 1, 2, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault)); // a DS_B digest: mode != 0
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.createVault(v, w, sig);
        (v, w) = _vault(1, 1, 1, address(vault));
        _create(vault, v, w); // the control
    }

    /// Review r2 R5: the two ids of one creator and nonce (and home) in mode 0 and mode 1 differ; both vaults exist side by side.
    function test_idsDifferByMode() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory w0) = _vault(1, 7, 0, address(vault));
        bytes32 a = _create(vault, v0, w0);
        (IPqVault.PqVaultCreate memory v1, IPqChat.Wrap[] memory w1) = _vault(1, 8, 1, address(vault));
        bytes32 b = _create(vault, v1, w1);
        assertTrue(a != b);
        assertTrue(
            PqVaultTypes.vaultId(ids[0], 7, 0, chainUidA, address(vault))
                != PqVaultTypes.vaultId(ids[0], 7, 1, chainUidA, address(vault))
        );
    }

    /// A mode-1 record replayed into a second instance: the create refused by the home check; a rekey there finds no vault.
    function test_mode1_replayIntoAnotherInstance() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 1, 1, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        bytes32 vid = vault.createVault(v, w, sig);
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vaultB.createVault(v, w, sig);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e, h.dsB(address(vault))));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid));
        vaultB.rekeyVault(e, ew, es);
        vault.rekeyVault(e, ew, es); // the control, at home
    }

    /// `mode` flipped after signing: the contract builds the digest of the record it is given, in that record's mode's domain.
    function test_modeFlippedAfterSigning() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 1, 0, address(vault));
        IUARegistry.UASig memory sig0 = _createSig(v, address(vault)); // signed in mode 0
        v.mode = 1;
        w = _wraps(v.members, PqVaultTypes.vaultId(v.creator, 1, 1, chainUidA, address(vault)));
        vm.expectRevert(_unauthorized(v.creator));
        vault.createVault(v, w, sig0);
        IUARegistry.UASig memory sig1 = _createSig(v, address(vault)); // signed in mode 1
        v.mode = 0;
        w = _wraps(v.members, PqVaultTypes.vaultId(v.creator, 1, 0, chainUidA, address(vault)));
        vm.expectRevert(_unauthorized(v.creator));
        vault.createVault(v, w, sig1);
        vault.createVault(v, w, sig0); // the control
    }

    /// A native member's mode-0 signature refused in mode 1 and the reverse (R6); each accepted in its own mode.
    function test_nativeMsigMember_eachMode() public {
        bytes32 ms = _nativeMsig();
        for (uint8 mode; mode < 2; ++mode) {
            (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 20 + mode, mode, address(vault));
            v.admins = _list(ms, ids[0]);
            bytes32 vid = _create(vault, v, w);
            (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
                _epoch(vid, ms, 1, 1, vid, v.admins, _without(_members(3), ids[2]));
            bytes32 t = h.epoch(e, _ds(mode, address(vault)));
            IUARegistry.UASig memory other = _nativeMsigSig(ms, t, 1 - mode);
            vm.expectRevert(_unauthorized(ms));
            vault.rekeyVault(e, ew, other);
            vault.rekeyVault(e, ew, _nativeMsigSig(ms, t, mode));
        }
    }

    /// A record naming a vault other than its stored epoch's (R11): `leaveVault` and `removeVaultMembers` (the rekey's is in
    /// PqVaultEpochs `test_rekey_parentRules`), in mode 1, where the other vault is mode 0.
    function test_recordVaultMustMatchItsEpoch() public {
        (bytes32 v1,) = _newVault(3, 1);
        (IPqVault.PqVaultCreate memory o, IPqChat.Wrap[] memory ow) = _vault(3, 2, 0, address(vault));
        bytes32 v0 = _create(vault, o, ow);
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(v0, v1, ids[1], 1);
        IUARegistry.UASig memory sig = _sig(ids[1], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, v1));
        vault.leaveVault(l, sig);
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(v0, v1, 1, _list(ids[2]), ids[0], 1);
        sig = _sig(ids[0], h.remove(r, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, v1));
        vault.removeVaultMembers(r, sig);
        l.vaultId = v1; // the controls, in v1's own mode
        vault.leaveVault(l, _sig(ids[1], h.leave(l, h.dsB(address(vault)))));
        r.vaultId = v1;
        vault.removeVaultMembers(r, _sig(ids[0], h.remove(r, h.dsB(address(vault)))));
    }

    /// A mode-1 record signed in mode 0's domain is refused, and the reverse, for a later write (the stored mode decides).
    function test_storedModeDecides() public {
        (bytes32 v1,) = _newVault(3, 1);
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(v1, v1, ids[1], 1);
        IUARegistry.UASig memory sig = _sig(ids[1], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(ids[1]));
        vault.leaveVault(l, sig);
        vault.leaveVault(l, _sig(ids[1], h.leave(l, h.dsB(address(vault)))));
    }
}

library PqVaultTypesSlot {
    bytes32 internal constant ROOT = 0x5bab91edb5f7201959ccc400acb38a4632e4bb30c3ed3cf98f817b8f10b48800;
}
