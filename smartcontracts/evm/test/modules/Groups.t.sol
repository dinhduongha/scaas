// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {kindModuleNames, deployKindModules, kindImplArgs} from "../../script/KindModules.sol";
import {regArgs} from "../helpers/Catalogue.sol";

/// Owner 2026-11-10 (CTR-TOK-30's Change, the body modules by function): W holds the wrap entries only, R the regulated
/// layer's entries only (8-13), S the PQZ state, setters and views (5, 13; was Q2). Pins which module holds which entry, and
/// that every stub of every face forwards to the module that declares its entry (each module's code replaced, after the
/// face's constructor checked it, by one that answers its own index).
contract GroupsTest is Test {
    address internal constant F = address(0xFAC);
    uint8[12] internal kinds = [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13];
    string[14] internal faces = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
        "WrappedPqzToken", "", "", "NormalRegulatedToken", "WrappedRegulatedToken", "NormalZetherRegulatedToken",
        "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken"];
    /// R on 8-13: the regulated layer's entries (`RegulatedBase` and the kind's `disableFeature`), the same on every kind.
    string[14] internal rNames = ["canReceive", "disableFeature", "forceTransfer", "freeze", "freezeOf", "isFrozen",
        "operatorTransfer", "order", "pause", "recordOrder", "regulatedConfig", "revokeOrder", "unfreeze", "unpause"];
    /// S on 5 and 13: the PQZ state, the four setters and the views but `verifyTransferAmount`; on 13 without `underlyings`
    /// (kind 13 restates it from the wrapped layer: its W holds it).
    string[33] internal sNames = ["auditorMode", "auditorUA", "burnStatement", "confidentialFee", "disclosureMode",
        "disclosureStatement", "envelopeBinding", "maxShielded", "minDecoyFee", "pqzAcc", "pqzAccount", "pqzCancelVerifier",
        "pqzDebitRecord", "pqzEntryBlob", "pqzPending", "pqzPendingCt", "pqzRevokeVerifier", "pqzSetVerifier",
        "pqzVerifyConfig", "precompile", "proofStore", "proofSystemId", "setProofStore", "shieldScale", "totalShielded",
        "transferCiphertextHash", "transferEntry", "transferSingleStatement", "transferStatement", "unshieldUnwrapStatement",
        "unwrapBinding", "verifier", "underlyings"];

    function create(bytes memory init) external returns (address a) {
        assembly ("memory-safe") {
            a := create(0, add(init, 32), mload(init))
            if iszero(a) {
                let m := mload(0x40)
                returndatacopy(m, 0, returndatasize())
                revert(m, returndatasize())
            }
        }
    }

    function _core(uint8 k) internal pure returns (bytes memory) {
        return k >= 8 ? regArgs() : bytes("");
    }

    function _json(string memory artifact) internal view returns (string memory) {
        string[] memory p = vm.split(artifact, ":");
        return vm.readFile(string.concat(vm.envOr("FOUNDRY_OUT", string("out")), "/", p[0], "/", p[1], ".json"));
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// The module's own entries (its group's), by signature: the ABI less the identity views and what every core inherits
    /// and the token keeps (`ModulesTest._exempt`'s list).
    function _entries(string memory artifact) internal view returns (string[] memory out) {
        string[] memory sigs = vm.parseJsonKeys(_json(artifact), ".methodIdentifiers");
        out = new string[](sigs.length);
        uint256 n;
        for (uint256 i; i < sigs.length; ++i) if (!_kept(keccak256(bytes(sigs[i])))) out[n++] = sigs[i];
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function _kept(bytes32 s) internal pure returns (bool) {
        return s == keccak256("kind()") || s == keccak256("moduleGroup()") || s == keccak256("factory()")
            || s == keccak256("FACTORY()") || s == keccak256("REGISTRY_CODEHASH()") || s == keccak256("pqzSet()")
            || s == keccak256("name()") || s == keccak256("symbol()") || s == keccak256("decimals()")
            || s == keccak256("totalSupply()") || s == keccak256("balanceOf(address)")
            || s == keccak256("allowance(address,address)") || s == keccak256("transfer(address,uint256)")
            || s == keccak256("transferFrom(address,address,uint256)") || s == keccak256("approve(address,uint256)")
            || s == keccak256("balanceOfUA(bytes32)") || s == keccak256("transferToUA(bytes32,uint256)")
            || s == keccak256("implementation()") || s == keccak256("registry()") || s == keccak256("chainUid()")
            || s == keccak256("IS_HEDERA()") || s == keccak256("SMART_KEY_ACCOUNT_IMPL()") || s == keccak256("RATE_WINDOW()");
    }

    function _has(string[] memory sigs, string memory name) internal pure returns (bool) {
        for (uint256 i; i < sigs.length; ++i) if (_eq(vm.split(sigs[i], "(")[0], name)) return true;
        return false;
    }

    /// The index in `kind`'s module list of the module whose artifact name ends in `group` (one letter), or `type(uint256).max`.
    function _find(uint8 k, string memory group) internal view returns (uint256) {
        string[] memory n = kindModuleNames(k);
        for (uint256 i; i < n.length; ++i) if (_eq(n[i], string.concat(faces[k], "Modules.sol:", faces[k], group))) return i;
        return type(uint256).max;
    }

    /// R holds exactly the regulated layer's entries on 8-13; W is gone on 8, 10, 12 and holds none of them on 9, 11, 13;
    /// the other kinds have no R.
    function test_g_regulatedEntriesRunInR() public view {
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            uint256 r = _find(k, "R");
            uint256 w = _find(k, "W");
            if (k < 8) {
                assertEq(r, type(uint256).max, string.concat(faces[k], ": no R"));
                assertEq(w != type(uint256).max, k % 2 == 1, string.concat(faces[k], ": W on the wrapped kinds only"));
                continue;
            }
            assertTrue(r != type(uint256).max, string.concat(faces[k], ": R"));
            string[] memory rs = _entries(kindModuleNames(k)[r]);
            assertEq(rs.length, rNames.length, string.concat(faces[k], "R: the regulated entries and no other"));
            for (uint256 i; i < rNames.length; ++i) assertTrue(_has(rs, rNames[i]), string.concat(faces[k], "R: ", rNames[i]));
            if (k % 2 == 0) {
                assertEq(w, type(uint256).max, string.concat(faces[k], ": W renamed R"));
                continue;
            }
            string[] memory ws = _entries(kindModuleNames(k)[w]);
            for (uint256 i; i < rNames.length; ++i) assertFalse(_has(ws, rNames[i]), string.concat(faces[k], "W: ", rNames[i]));
            assertTrue(_has(ws, "wrap") && _has(ws, "rescue") && _has(ws, "underlyings"), string.concat(faces[k], "W: the wrap bodies"));
        }
    }

    /// S holds exactly the PQZ state, setters and views on 5 and 13, and Q none of them; no other kind has S.
    function test_g_stateEntriesRunInS() public view {
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            uint256 s = _find(k, "S");
            if (k != 5 && k != 13) {
                assertEq(s, type(uint256).max, string.concat(faces[k], ": no S"));
                continue;
            }
            assertTrue(s != type(uint256).max, string.concat(faces[k], ": S"));
            string[] memory ss = _entries(kindModuleNames(k)[s]);
            string[] memory qs = _entries(kindModuleNames(k)[_find(k, "Q")]);
            uint256 want = k == 5 ? sNames.length : sNames.length - 1;
            assertEq(ss.length, want, string.concat(faces[k], "S: the state, setters and views and no other"));
            for (uint256 i; i < want; ++i) {
                assertTrue(_has(ss, sNames[i]), string.concat(faces[k], "S: ", sNames[i]));
                assertFalse(_has(qs, sNames[i]), string.concat(faces[k], "Q: ", sNames[i]));
            }
            assertTrue(_has(qs, "verifyTransferAmount") && _has(qs, "mtxShield"), string.concat(faces[k], "Q: the ops and verdicts"));
        }
    }

    /// Every entry of every module of every kind, called on the kind's implementation with zero arguments, reaches that
    /// module: each module's code is swapped (after the constructor's checks) for one that answers `index + 1`.
    function test_g_everyStubForwardsToItsModule() public {
        uint256 routed;
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            (address[] memory ms,) = deployKindModules(k, F, _core(k));
            string memory n = faces[k];
            address impl = this.create(bytes.concat(vm.getCode(string.concat(n, ".sol:", n)), abi.encode(F, kindImplArgs(k, ms, _core(k)))));
            string[] memory names = kindModuleNames(k);
            for (uint256 i; i < ms.length; ++i) vm.etch(ms[i], abi.encodePacked(hex"60", uint8(i + 1), hex"60005260206000f3"));
            for (uint256 i; i < ms.length; ++i) {
                string[] memory sigs = _entries(names[i]);
                for (uint256 j; j < sigs.length; ++j) {
                    (bool ok, bytes memory ret) = impl.call(bytes.concat(bytes4(keccak256(bytes(sigs[j]))), new bytes(2048)));
                    string memory what = string.concat(n, ".", sigs[j], " -> ", vm.split(names[i], ":")[1]);
                    assertTrue(ok, what);
                    assertEq(ret, abi.encode(i + 1), what);
                    ++routed;
                }
            }
        }
        emit log_named_uint("T66B-3P | stubs routed to their module", routed);
    }
}
