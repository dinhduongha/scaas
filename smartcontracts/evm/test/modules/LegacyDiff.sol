// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ITokenModules} from "../../src/metatx/ITokenModule.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

interface ILive {
    function kind() external view returns (uint8);
    function factory() external view returns (address);
    function COMPLIANCE_REGISTRY_CODEHASH() external view returns (bytes32);
}

/// @notice T66b §10, the differential test per entry (the registry's R2 `test_diff` pattern): the pre-split body (the
///         release at d142b57c, built by `script/modules/legacy_artifacts.py build` into out/t66b-legacy/, its libraries by
///         CREATE2) against stub + module, on the same clone, state and caller. The clone's code is the EIP-1167 proxy with
///         its env; swapping the 20-byte implementation address in it (`vm.etch`) runs the same address and storage
///         through the other implementation. Per call: success, return or revert data, logs (emitter, topics, data), every
///         storage write (the clone's and any other account's) in order, and every call out (CALL / STATICCALL / CALLCODE / CREATE, value and data)
///         to an account that is neither a library nor a module, in order. The rows are one call per external function with
///         sample arguments (`legacy_artifacts.py`), from each caller the test names; a fuzz row takes any selector of the
///         kind with any tail.
abstract contract LegacyDiff is Test {
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    string internal constant DIR = "out/t66b-legacy/";
    /// @dev Old implementation per (kind, factory, core args).
    mapping(bytes32 => address) internal legacyImpl;
    address[] internal routing; // libraries (old and new) and modules: accesses to them are routing, not behaviour
    uint256 internal diffed;
    uint256 internal bothOk;
    /// @dev The token under `_diff`'s chain word: its new side's `renounceAdmin(bytes32)` takes it (CTR-GOV-27).
    bytes32 internal r3Uid;

    function _legacyLibs() internal {
        if (routing.length != 0) return;
        string memory j = vm.readFile(string.concat(DIR, "libs.json"));
        bytes32 s = vm.parseJsonBytes32(j, ".salt");
        for (uint256 i;; ++i) {
            string memory p = string.concat(".libs[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) break;
            address a = vm.parseJsonAddress(j, string.concat(p, ".addr"));
            if (a.code.length == 0) {
                (bool ok,) = CREATE2_DEPLOYER.call(bytes.concat(s, vm.parseJsonBytes(j, string.concat(p, ".init"))));
                require(ok && a.code.length != 0, "legacy library");
            }
            routing.push(a);
        }
    }

    function _kindFile(uint8 k) internal view returns (string memory) {
        return vm.readFile(string.concat(DIR, k == type(uint8).max ? "dex" : string.concat("k", vm.toString(k)), ".json"));
    }

    /// @dev The pre-split implementation of `token`'s kind for its factory (the regulated kinds with the registry code hash).
    function _legacyFor(address token, uint8 k) internal returns (address impl) {
        _legacyLibs();
        address f = ILive(token).factory();
        bytes memory core =
            k >= 8 && k != type(uint8).max ? abi.encode(ILive(token).COMPLIANCE_REGISTRY_CODEHASH()) : bytes("");
        bytes32 id = keccak256(abi.encode(k, f, core));
        impl = legacyImpl[id];
        if (impl != address(0)) return impl;
        bytes memory init = bytes.concat(vm.parseJsonBytes(_kindFile(k), ".init"), abi.encode(f, core));
        assembly ("memory-safe") {
            impl := create(0, add(init, 32), mload(init))
        }
        require(impl != address(0), "legacy implementation");
        legacyImpl[id] = impl;
        address[] memory ms = ITokenModules(_implOf(token)).modules();
        for (uint256 i; i < ms.length; ++i) routing.push(ms[i]);
    }

    /// @dev The implementation in an EIP-1167 clone's code (bytes 10..30).
    function _implOf(address token) internal view returns (address a) {
        bytes memory c = token.code;
        require(c.length >= 45 && c[0] == 0x36 && c[9] == 0x73, "not a clone");
        assembly ("memory-safe") {
            a := shr(96, mload(add(c, 42)))
        }
    }

    function _withImpl(bytes memory c, address impl) internal pure returns (bytes memory out) {
        out = bytes.concat(c);
        for (uint256 i; i < 20; ++i) out[10 + i] = bytes20(impl)[i];
    }

    struct Run {
        bool ok;
        bytes ret;
        Vm.Log[] logs;
        bytes32[] writes; // account, slot, value, account, slot, value, ...
        bytes[] calls; // abi.encode(kind, account, value, data)
    }

    function _run(address token, address caller, bytes memory data) internal returns (Run memory r) {
        vm.recordLogs();
        vm.startStateDiffRecording();
        vm.prank(caller);
        (r.ok, r.ret) = token.call(data);
        VmSafe.AccountAccess[] memory acc = _from(vm.stopAndReturnStateDiff(), token, caller);
        r.logs = vm.getRecordedLogs();
        // writes from every frame (a module's or a library's frame writes the clone's storage); calls out only from frames
        // that are not routing
        uint256 nw;
        uint256 nc;
        for (uint256 i; i < acc.length; ++i) {
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                if (acc[i].storageAccesses[j].isWrite && !acc[i].storageAccesses[j].reverted) ++nw;
            }
            if (_behaviour(acc[i].kind) && !_routing(acc[i].account)) ++nc;
        }
        r.writes = new bytes32[](3 * nw);
        r.calls = new bytes[](nc);
        (nw, nc) = (0, 0);
        for (uint256 i; i < acc.length; ++i) {
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                VmSafe.StorageAccess memory s = acc[i].storageAccesses[j];
                if (!s.isWrite || s.reverted) continue;
                (r.writes[nw], r.writes[nw + 1], r.writes[nw + 2]) = (bytes32(uint256(uint160(s.account))), s.slot, s.newValue);
                nw += 3;
            }
            if (_behaviour(acc[i].kind) && !_routing(acc[i].account)) {
                r.calls[nc++] = abi.encode(acc[i].kind, acc[i].account, acc[i].value, acc[i].data, acc[i].reverted);
            }
        }
    }

    /// @dev The accesses from the call under test on (the recording can hold earlier ones of the same test, e.g. the
    ///      legacy libraries' deployment).
    function _from(VmSafe.AccountAccess[] memory acc, address token, address caller)
        internal pure returns (VmSafe.AccountAccess[] memory out)
    {
        uint256 s;
        while (s < acc.length && !(acc[s].kind == VmSafe.AccountAccessKind.Call && acc[s].account == token
            && acc[s].accessor == caller)) ++s;
        require(s < acc.length, "the call under test is not in the recording");
        out = new VmSafe.AccountAccess[](acc.length - s);
        for (uint256 i; i < out.length; ++i) out[i] = acc[s + i];
    }

    function _behaviour(VmSafe.AccountAccessKind k) internal pure returns (bool) {
        return k == VmSafe.AccountAccessKind.Call || k == VmSafe.AccountAccessKind.StaticCall
            || k == VmSafe.AccountAccessKind.CallCode || k == VmSafe.AccountAccessKind.Create
            || k == VmSafe.AccountAccessKind.SelfDestruct;
    }

    function _routing(address a) internal view returns (bool) {
        for (uint256 i; i < routing.length; ++i) if (routing[i] == a) return true;
        return false;
    }

    /// @dev One differential call: the clone through its own (new) implementation, then through the pre-split one, from
    ///      the same state.
    function _diff(address token, address oldImpl, address caller, bytes memory data, string memory what) internal {
        bytes memory code = token.code;
        r3Uid = EnvKit.codeUidOf(token);
        uint256 snap = vm.snapshotState();
        Run memory n = _run(token, caller, _r3Call(data));
        vm.revertToState(snap);
        vm.etch(token, _withImpl(code, oldImpl));
        Run memory o = _run(token, caller, data);
        vm.revertToStateAndDelete(snap);
        o.ret = _intended(token, data, o);
        _r3Old(o);
        assertEq(n.ok, o.ok, string.concat(what, ": outcome"));
        assertEq(n.ret, o.ret, string.concat(what, ": return / revert data"));
        assertEq(n.logs.length, o.logs.length, string.concat(what, ": log count"));
        for (uint256 i; i < n.logs.length; ++i) {
            assertEq(n.logs[i].emitter, o.logs[i].emitter, string.concat(what, ": log emitter"));
            assertEq(n.logs[i].topics, o.logs[i].topics, string.concat(what, ": log topics"));
            assertEq(n.logs[i].data, o.logs[i].data, string.concat(what, ": log data"));
        }
        assertEq(n.writes, o.writes, string.concat(what, ": storage writes"));
        if (n.calls.length != o.calls.length) {
            for (uint256 i; i < n.calls.length && i < 6; ++i) {
                (VmSafe.AccountAccessKind ck, address ca,,,) = abi.decode(n.calls[i], (VmSafe.AccountAccessKind, address, uint256, bytes, bool));
                emit log_named_address(string.concat("new call out kind ", vm.toString(uint8(ck))), ca);
            }
            for (uint256 i; i < o.calls.length && i < 6; ++i) {
                (VmSafe.AccountAccessKind ck, address ca,,,) = abi.decode(o.calls[i], (VmSafe.AccountAccessKind, address, uint256, bytes, bool));
                emit log_named_address(string.concat("old call out kind ", vm.toString(uint8(ck))), ca);
            }
        }
        assertEq(n.calls.length, o.calls.length, string.concat(what, ": calls out"));
        for (uint256 i; i < n.calls.length; ++i) assertEq(n.calls[i], o.calls[i], string.concat(what, ": call out"));
        ++diffed;
        if (n.ok) ++bothOk;
    }

    /// @dev The expected side: the pre-split answer (d142b57c) with the behaviour added on purpose after it, each named with
    ///      its rule; every other byte is compared as before. Group 3l (CTR-TOK-31, docs/superpowers/specs/2026-11-10-wrap-
    ///      limits.md §2, commit 7ba002dc): `validBits()` of the six wrapped kinds 1, 3, 5, 9, 11, 13 adds bits 25
    ///      `WRAP_LIMIT`, 26 `WRAP_LIST`, 27 `REDEEMER` (`GovernanceBits.WRAP_CONTROLS`) to the old answer. Bit 24 `PQZ_PROOF`
    ///      of the PQZ kinds predates d142b57c (3h T61) and is in both answers. Round 3s (CTR-GOV-24, spec
    ///      2026-11-10-token-lists.md §3): `validBits()` of the regulated kinds 8-13 adds bit 28 `KYC`
    ///      (`GovernanceBits.REGULATED`). Round 3t (CTR-PQZ-36, spec 2026-11-11-verifier-fee.md §7.3): `pqzVerifyConfig()` of
    ///      the PQZ kinds 4, 5, 12, 13 appends `verifierFee`, `verifierFeeMax`, `verifierFeePending`, `verifierFeeEta` to the
    ///      seven old words; a token created without a fee reads 0 for the four.
    function _intended(address token, bytes memory data, Run memory o) internal view returns (bytes memory) {
        if (o.ok && o.ret.length == 7 * 32 && bytes4(data) == bytes4(keccak256("pqzVerifyConfig()"))) {
            return bytes.concat(o.ret, new bytes(4 * 32));
        }
        if (!o.ok || o.ret.length != 32 || bytes4(data) != bytes4(keccak256("validBits()"))) return o.ret;
        uint8 k = _kindOf(token);
        uint256 b = abi.decode(o.ret, (uint256));
        if (k >= 8 && k <= 13) b |= uint256(1) << GovernanceBits.KYC;
        if (k == 1 || k == 3 || k == 5 || k == 9 || k == 11 || k == 13) b |= GovernanceBits.WRAP_CONTROLS;
        return abi.encode(b);
    }

    /// @dev Round 3r R3 (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §4.1-§4.3): d142b57c's ownership names are the admin
    ///      names now, same arguments, storage and rules. A row of an old entry runs on the new side under its new selector;
    ///      the old side's revert selector, event topic0 and the selector of each call it records (the call under test is the
    ///      first) are read under the new names. T6 (§4.1's row "Compliance registry names in the regulated code"): the
    ///      regulated kinds' `REGISTRY_CODEHASH()` and three registry errors likewise. Nothing else is mapped.
    function _r3Sel(bytes4 s) internal pure returns (bytes4) {
        if (s == bytes4(keccak256("owner()"))) return bytes4(keccak256("admin()"));
        if (s == bytes4(keccak256("pendingOwner()"))) return bytes4(keccak256("pendingAdmin()"));
        if (s == bytes4(keccak256("transferOwnership(bytes32)"))) return bytes4(keccak256("transferAdmin(bytes32)"));
        if (s == bytes4(keccak256("acceptOwnership()"))) return bytes4(keccak256("acceptAdmin()"));
        if (s == bytes4(keccak256("renounceOwnership()"))) return bytes4(keccak256("renounceAdmin(bytes32)"));
        if (s == bytes4(keccak256("NotOwner(bytes32)"))) return bytes4(keccak256("NotAdmin(bytes32)"));
        if (s == bytes4(keccak256("NotPendingOwner(bytes32)"))) return bytes4(keccak256("NotPendingAdmin(bytes32)"));
        if (s == bytes4(keccak256("OwnerAccountPool(bytes32)"))) return bytes4(keccak256("AdminAccountPool(bytes32)"));
        if (s == bytes4(keccak256("OwnerHasHolders(uint8)"))) return bytes4(keccak256("AdminHasHolders(uint8)"));
        if (s == bytes4(keccak256("REGISTRY_CODEHASH()"))) return bytes4(keccak256("COMPLIANCE_REGISTRY_CODEHASH()"));
        if (s == bytes4(keccak256("RegistryCodeMismatch(address,bytes32)"))) {
            return bytes4(keccak256("ComplianceRegistryCodeMismatch(address,bytes32)"));
        }
        if (s == bytes4(keccak256("RegistryUnavailable(address)"))) {
            return bytes4(keccak256("ComplianceRegistryUnavailable(address)"));
        }
        if (s == bytes4(keccak256("RegistryGasStarved(uint256,uint256)"))) {
            return bytes4(keccak256("ComplianceRegistryGasStarved(uint256,uint256)"));
        }
        return s;
    }

    function _r3Call(bytes memory data) internal view returns (bytes memory out) {
        out = bytes.concat(data);
        if (out.length < 4) return out;
        // Fable recheck-2 P3-1 (CTR-GOV-27): the renounce names the token's chain word, `r3Uid`, its first argument (the
        // old entry took none and ignored any bytes after its selector, so they follow the word)
        if (bytes4(out) == bytes4(keccak256("renounceOwnership()"))) {
            bytes memory rest = new bytes(out.length - 4);
            for (uint256 i; i < rest.length; ++i) rest[i] = out[i + 4];
            out = bytes.concat(bytes4(out), r3Uid, rest);
        }
        bytes4 s = _r3Sel(bytes4(out));
        for (uint256 i; i < 4; ++i) out[i] = s[i];
    }

    function _r3Old(Run memory o) internal view {
        if (!o.ok) o.ret = _r3Call(o.ret);
        for (uint256 i; i < o.calls.length; ++i) {
            (VmSafe.AccountAccessKind k, address a, uint256 v, bytes memory d, bool r) =
                abi.decode(o.calls[i], (VmSafe.AccountAccessKind, address, uint256, bytes, bool));
            o.calls[i] = abi.encode(k, a, v, _r3Call(d), r);
        }
        for (uint256 i; i < o.logs.length; ++i) {
            if (o.logs[i].topics.length == 0) continue;
            bytes32 t = o.logs[i].topics[0];
            if (t == keccak256("OwnershipTransferStarted(bytes32,bytes32)")) {
                o.logs[i].topics[0] = keccak256("AdminTransferStarted(bytes32,bytes32)");
            } else if (t == keccak256("OwnershipTransferred(bytes32,bytes32)")) {
                o.logs[i].topics[0] = keccak256("AdminTransferred(bytes32,bytes32)");
            }
        }
    }

    /// @dev `_diff` as its own call, so a positive control can expect its assertion to fail.
    function diffWith(address token, address oldImpl, address caller, bytes calldata data) external {
        _diff(token, oldImpl, caller, data, "control");
    }

    /// @dev Every row of `token`'s kind (but `implementation()`, which answers each implementation's own address by
    ///      design), from each of `callers`.
    function _diffRows(address token, address[] memory callers) internal {
        uint8 k = _kindOf(token);
        address oldImpl = _legacyFor(token, k);
        string memory j = _kindFile(k);
        for (uint256 i;; ++i) {
            string memory p = string.concat(".rows[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) break;
            string memory sig = vm.parseJsonString(j, string.concat(p, ".sig"));
            if (keccak256(bytes(sig)) == keccak256("implementation()")) continue;
            bytes memory data = vm.parseJsonBytes(j, string.concat(p, ".data"));
            for (uint256 c; c < callers.length; ++c) _diff(token, oldImpl, callers[c], data, sig);
        }
        emit log_named_uint(string.concat("T66B-DIFF | kind ", vm.toString(k), " | calls compared"), diffed);
        emit log_named_uint(string.concat("T66B-DIFF | kind ", vm.toString(k), " | calls that succeeded"), bothOk);
    }

    /// @dev Any selector of the kind (`which`), any argument bytes.
    function _diffFuzz(address token, address caller, uint256 which, bytes memory tail) internal {
        uint8 k = _kindOf(token);
        address oldImpl = _legacyFor(token, k);
        string memory j = _kindFile(k);
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".rows[", vm.toString(n), "]"))) ++n;
        string memory p = string.concat(".rows[", vm.toString(which % n), "]");
        string memory sig = vm.parseJsonString(j, string.concat(p, ".sig"));
        vm.assume(keccak256(bytes(sig)) != keccak256("implementation()"));
        bytes memory row = vm.parseJsonBytes(j, string.concat(p, ".data"));
        _diff(token, oldImpl, caller, bytes.concat(bytes4(row), tail), sig);
    }

    /// @dev The DEX has no `kind()`: `type(uint8).max` names it.
    function _kindOf(address token) internal view virtual returns (uint8) {
        return ILive(token).kind();
    }
}
