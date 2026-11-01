// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";

/// typed-signing R2: one run of a scenario as a list of row hashes, in memory (it outlives `vm.revertToState`), so the same
/// scenario on the pre-split registry and on the split one compares row by row. A read's row is its success flag and raw
/// return or revert data. A write's row is that, plus its logs (emitter, topics, data), every storage write in order (account,
/// slot, new value), every contract it created (address, code), and every call out of the registry (kind, callee, calldata:
/// which verifier the immutables named, what it was asked): the stored bytes themselves, not only what a view shows.
library SplitDiff {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Run {
        address lib; // calls to it, and a registry's calls to itself, are the split's own: left out of a row
        string[] labels;
        bytes32[] rows;
        uint256 n;
        uint256 writes; // successful writes
        uint256 reverts; // expected reverts
    }

    function start(uint256 cap, address lib) internal returns (Run memory r) {
        vm.startStateDiffRecording();
        vm.stopAndReturnStateDiff(); // a test's first recording also holds what came before it (the linked library's creation)
        r.lib = lib;
        r.labels = new string[](cap);
        r.rows = new bytes32[](cap);
    }

    function push(Run memory r, string memory label, bytes32 h) internal pure {
        require(r.n < r.rows.length, "SplitDiff: more rows than cap");
        r.labels[r.n] = label;
        r.rows[r.n++] = h;
    }

    function read(Run memory r, string memory label, address to, bytes memory data) internal view {
        uint256 fp;
        assembly ("memory-safe") {
            fp := mload(0x40)
        }
        (bool ok, bytes memory ret) = to.staticcall(data);
        bytes32 h = keccak256(abi.encode(ok, ret));
        assembly ("memory-safe") {
            mstore(0x40, fp)
        }
        push(r, label, h);
    }

    function _writes(Run memory r, address to, VmSafe.AccountAccess[] memory d)
        private
        pure
        returns (bytes32 slots, bytes32 created, bytes32 calls)
    {
        uint256 total;
        for (uint256 i; i < d.length; ++i) total += d[i].storageAccesses.length;
        bytes32[] memory key = new bytes32[](total);
        bytes32[] memory value = new bytes32[](total);
        uint256 n;
        for (uint256 i; i < d.length; ++i) {
            if (d[i].kind == VmSafe.AccountAccessKind.Call || d[i].kind == VmSafe.AccountAccessKind.StaticCall) {
                if (d[i].account != to && d[i].account != r.lib) {
                    calls = keccak256(abi.encode(calls, d[i].kind, d[i].account, d[i].data));
                }
            }
            if (d[i].reverted) continue;
            if (d[i].kind == VmSafe.AccountAccessKind.Create) {
                created = keccak256(abi.encode(created, d[i].account, d[i].deployedCode));
            }
            VmSafe.StorageAccess[] memory a = d[i].storageAccesses;
            for (uint256 j; j < a.length; ++j) {
                if (!a[j].isWrite || a[j].reverted) continue;
                bytes32 k = keccak256(abi.encode(a[j].account, a[j].slot));
                uint256 m;
                while (m < n && key[m] != k) ++m;
                if (m == n) key[n++] = k;
                value[m] = a[j].newValue;
            }
        }
        // the slots in the order of their first write, each with its last value: a packed struct may be stored field by field
        for (uint256 i; i < n; ++i) slots = keccak256(abi.encode(slots, key[i], value[i]));
    }

    function _logs(Vm.Log[] memory l) private pure returns (bytes32 h) {
        for (uint256 i; i < l.length; ++i) h = keccak256(abi.encode(h, l[i].emitter, l[i].topics, l[i].data));
    }

    /// The call `data` on `to` as a row, whatever it does.
    function attempt(Run memory r, string memory label, address to, bytes memory data)
        internal
        returns (bool ok, bytes memory ret)
    {
        vm.recordLogs();
        vm.startStateDiffRecording();
        (ok, ret) = to.call(data);
        VmSafe.AccountAccess[] memory d = vm.stopAndReturnStateDiff();
        Vm.Log[] memory l = vm.getRecordedLogs();
        (bytes32 slots, bytes32 created, bytes32 calls) = _writes(r, to, d);
        push(r, string.concat(label, " [result]"), keccak256(abi.encode(ok, ret)));
        push(r, string.concat(label, " [logs]"), _logs(l));
        push(r, string.concat(label, " [storage]"), slots);
        push(r, string.concat(label, " [created]"), created);
        push(r, string.concat(label, " [calls]"), calls);
    }

    /// A write that must go through. Returns its return data.
    function write(Run memory r, string memory label, address to, bytes memory data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = attempt(r, label, to, data);
        if (!ok) revert(string.concat("SplitDiff: write failed: ", label, " ", vm.toString(ret)));
        ++r.writes;
    }

    /// A write that must revert with exactly `err`.
    function refused(Run memory r, string memory label, address to, bytes memory data, bytes memory err) internal {
        (bool ok, bytes memory ret) = attempt(r, label, to, data);
        if (ok) revert(string.concat("SplitDiff: no revert: ", label));
        if (keccak256(ret) != keccak256(err)) {
            revert(string.concat("SplitDiff: wrong revert: ", label, " got ", vm.toString(ret), " want ", vm.toString(err)));
        }
        ++r.reverts;
    }

    /// The first row where `a` and `b` differ, by label; "" when none.
    function firstDiff(Run memory a, Run memory b) internal pure returns (string memory) {
        if (a.n != b.n) return "row count";
        for (uint256 i; i < a.n; ++i) {
            if (keccak256(bytes(a.labels[i])) != keccak256(bytes(b.labels[i]))) return string.concat("labels at ", a.labels[i]);
            if (a.rows[i] != b.rows[i]) return a.labels[i];
        }
        return "";
    }
}
