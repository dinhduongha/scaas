// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3r R3 (spec docs/superpowers/specs/2026-11-10-admin-not-owner.md §4.1, §4.2, §8 (1); CTR-GOV-23): on each of the
/// 12 token kinds and the DEX, the five admin entries answer and the five ownership selectors of before have no entry (a
/// call reverts with no data: no kind has a fallback). Raw selectors from §4.2, so the file does not name an identifier of
/// either side. Each kind is a bare clone of its release (the test plays the factory), its admin written into the
/// governance namespace (`scaas.governance`, `admin` at +2, `pendingAdmin` at +3; the layout pin `test/v2/Layout.t.sol`):
/// a stranger is refused by name with its own id, and the admin's two-step transfer and the renounce run. UNAUDITED.
contract AdminNamesTest is Test {
    bytes32 internal constant NS = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;
    address internal constant STRANGER = address(0x5742A9E5);
    address internal constant A1 = address(0xA11CE);
    address internal constant A2 = address(0xB0B);

    // the new five (§4.2) and the errors they raise
    bytes4 internal constant ADMIN = 0xf851a440; // admin()
    bytes4 internal constant PENDING_ADMIN = 0x26782247; // pendingAdmin()
    bytes4 internal constant TRANSFER_ADMIN = 0xe923bc3d; // transferAdmin(bytes32)
    bytes4 internal constant ACCEPT_ADMIN = 0x0e18b681; // acceptAdmin()
    bytes4 internal constant RENOUNCE_ADMIN = 0x4fa3ed14; // renounceAdmin(bytes32) (Fable recheck-2 P3-1; was 0x8bad0c0a, renounceAdmin())
    bytes4 internal constant RENOUNCE_ADMIN_OLD = 0x8bad0c0a; // renounceAdmin(): no entry since recheck-2 P3-1
    bytes4 internal constant CHAIN_UID_MISMATCH = 0x14767f45; // ChainUidMismatch(bytes32,bytes32)
    bytes32 internal constant UID = bytes32(uint256(0x3A)); // the clones' chain word (`_clone`)
    bytes32 internal constant SIB = bytes32(uint256(0x3B)); // a sibling's, the same chain id
    bytes4 internal constant NOT_ADMIN = 0xba963c12; // NotAdmin(bytes32)
    bytes4 internal constant NOT_PENDING_ADMIN = 0x16600d0b; // NotPendingAdmin(bytes32)

    function _old() internal pure returns (bytes4[5] memory) {
        // owner(), pendingOwner(), transferOwnership(bytes32), acceptOwnership(), renounceOwnership()
        return [bytes4(0x8da5cb5b), 0xe30c3978, 0xf807e3da, 0x79ba5097, 0x715018a6];
    }

    function test_selectorValues() public pure {
        assertEq(ADMIN, bytes4(keccak256("admin()")));
        assertEq(PENDING_ADMIN, bytes4(keccak256("pendingAdmin()")));
        assertEq(TRANSFER_ADMIN, bytes4(keccak256("transferAdmin(bytes32)")));
        assertEq(ACCEPT_ADMIN, bytes4(keccak256("acceptAdmin()")));
        assertEq(RENOUNCE_ADMIN, bytes4(keccak256("renounceAdmin(bytes32)")));
        assertEq(RENOUNCE_ADMIN_OLD, bytes4(keccak256("renounceAdmin()")));
        assertEq(CHAIN_UID_MISMATCH, bytes4(keccak256("ChainUidMismatch(bytes32,bytes32)")));
        assertEq(NOT_ADMIN, bytes4(keccak256("NotAdmin(bytes32)")));
        assertEq(NOT_PENDING_ADMIN, bytes4(keccak256("NotPendingAdmin(bytes32)")));
        bytes4[5] memory o = _old();
        assertEq(o[0], bytes4(keccak256("owner()")));
        assertEq(o[1], bytes4(keccak256("pendingOwner()")));
        assertEq(o[2], bytes4(keccak256("transferOwnership(bytes32)")));
        assertEq(o[3], bytes4(keccak256("acceptOwnership()")));
        assertEq(o[4], bytes4(keccak256("renounceOwnership()")));
    }

    // ------------------------------------------------------------------ fixtures

    function _clone(address impl) internal returns (address) {
        return EnvKit.clone(impl, EnvKit.env(UID, address(0x5Ca0000000000000000000000000000000000003),
            address(0), false, address(0)));
    }

    function _kind(string memory name, uint8 kind) internal returns (address) {
        bytes memory core = kind >= 8 ? regArgs() : bytes("");
        return _clone(vm.deployCode(string.concat(name, ".sol:", name), abi.encode(address(this), kindArgs(kind, address(this), core))));
    }

    function _call(address t, address from, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(from);
        (ok, ret) = t.call(cd);
    }

    function _word(address t, bytes4 sel) internal returns (bytes32) {
        (bool ok, bytes memory ret) = _call(t, STRANGER, abi.encodePacked(sel));
        assertTrue(ok && ret.length == 32, "a view of the new five answers");
        return abi.decode(ret, (bytes32));
    }

    function _refused(string memory name, address t, bytes memory cd, bytes4 err) internal {
        (bool ok, bytes memory ret) = _call(t, STRANGER, cd);
        assertFalse(ok, string.concat(name, ": the stranger passed"));
        assertEq(ret, abi.encodeWithSelector(err, nid(STRANGER)), string.concat(name, ": refused by name, the stranger's id"));
    }

    function _check(string memory name, address t) internal {
        bytes4[5] memory o = _old();
        for (uint256 i; i < o.length; ++i) {
            (bool ok, bytes memory ret) = _call(t, STRANGER, abi.encodePacked(o[i], bytes32(0)));
            assertFalse(ok, string.concat(name, ": an ownership selector answers"));
            assertEq(ret.length, 0, string.concat(name, ": an ownership selector reverts with data"));
        }
        vm.store(t, bytes32(uint256(NS) + 2), nid(A1));
        assertEq(_word(t, ADMIN), nid(A1), string.concat(name, ": admin()"));
        assertEq(_word(t, PENDING_ADMIN), 0, string.concat(name, ": pendingAdmin()"));
        _refused(name, t, abi.encodeWithSelector(TRANSFER_ADMIN, nid(A2)), NOT_ADMIN);
        _refused(name, t, abi.encodePacked(ACCEPT_ADMIN), NOT_PENDING_ADMIN);
        _refused(name, t, abi.encodeWithSelector(RENOUNCE_ADMIN, UID), NOT_ADMIN);
        (bool ok1,) = _call(t, A1, abi.encodeWithSelector(TRANSFER_ADMIN, nid(A2)));
        assertTrue(ok1, string.concat(name, ": transferAdmin"));
        assertEq(_word(t, PENDING_ADMIN), nid(A2), string.concat(name, ": pending after transferAdmin"));
        assertEq(_word(t, ADMIN), nid(A1), string.concat(name, ": two steps"));
        (bool ok2,) = _call(t, A2, abi.encodePacked(ACCEPT_ADMIN));
        assertTrue(ok2, string.concat(name, ": acceptAdmin"));
        assertEq(_word(t, ADMIN), nid(A2), string.concat(name, ": admin after acceptAdmin"));
        assertEq(_word(t, PENDING_ADMIN), 0, string.concat(name, ": pending cleared"));
        // Fable recheck-2 P3-1: the admin's renounce made for a sibling (another chain word) is refused by name, nothing
        // written; the old selector has no entry; the same call with the clone's own word is the control.
        (bool okS, bytes memory retS) = _call(t, A2, abi.encodeWithSelector(RENOUNCE_ADMIN, SIB));
        assertFalse(okS, string.concat(name, ": a sibling's word renounced"));
        assertEq(retS, abi.encodeWithSelector(CHAIN_UID_MISMATCH, UID, SIB), string.concat(name, ": ChainUidMismatch"));
        assertEq(EnvKit.codeUidOf(t), UID, string.concat(name, ": EnvKit.codeUidOf reads the clone's word"));
        (bool okO, bytes memory retO) = _call(t, A2, abi.encodePacked(RENOUNCE_ADMIN_OLD));
        assertTrue(!okO && retO.length == 0, string.concat(name, ": renounceAdmin() has no entry"));
        assertEq(_word(t, ADMIN), nid(A2), string.concat(name, ": admin kept"));
        (bool ok3,) = _call(t, A2, abi.encodeWithSelector(RENOUNCE_ADMIN, UID));
        assertTrue(ok3, string.concat(name, ": renounceAdmin"));
        assertEq(_word(t, ADMIN), 0, string.concat(name, ": admin after renounceAdmin"));
    }

    // ------------------------------------------------------------------ the 12 kinds and the DEX

    function test_kind0_NormalToken() public { _check("NormalToken", _kind("NormalToken", 0)); }

    function test_kind1_WrappedToken() public { _check("WrappedToken", _kind("WrappedToken", 1)); }

    function test_kind2_NormalZetherToken() public { _check("NormalZetherToken", _kind("NormalZetherToken", 2)); }

    function test_kind3_WrappedZetherToken() public { _check("WrappedZetherToken", _kind("WrappedZetherToken", 3)); }

    function test_kind4_NormalPqzToken() public { _check("NormalPqzToken", _kind("NormalPqzToken", 4)); }

    function test_kind5_WrappedPqzToken() public { _check("WrappedPqzToken", _kind("WrappedPqzToken", 5)); }

    function test_kind8_NormalRegulatedToken() public { _check("NormalRegulatedToken", _kind("NormalRegulatedToken", 8)); }

    function test_kind9_WrappedRegulatedToken() public { _check("WrappedRegulatedToken", _kind("WrappedRegulatedToken", 9)); }

    function test_kind10_NormalZetherRegulatedToken() public {
        _check("NormalZetherRegulatedToken", _kind("NormalZetherRegulatedToken", 10));
    }

    function test_kind11_WrappedZetherRegulatedToken() public {
        _check("WrappedZetherRegulatedToken", _kind("WrappedZetherRegulatedToken", 11));
    }

    function test_kind12_NormalPqzRegulatedToken() public {
        _check("NormalPqzRegulatedToken", _kind("NormalPqzRegulatedToken", 12));
    }

    function test_kind13_WrappedPqzRegulatedToken() public {
        _check("WrappedPqzRegulatedToken", _kind("WrappedPqzRegulatedToken", 13));
    }

    function test_dex_SCaaSDex() public {
        _check("SCaaSDex", _clone(vm.deployCode("SCaaSDex.sol:SCaaSDex", abi.encode(address(this), dexArgs(address(this))))));
    }
}
