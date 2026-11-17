// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrapLimitsBase} from "./WrapLimitsBase.sol";

/// Group 3l, plan T102: `smartcontracts/vectors/wraplimits/wraplimits.json` (its generator `gen_wraplimits.py`) replayed on a
/// hybrid: after every step the id's `base`, `startMin` (the quota word, spec §5) and `entitlement` (the view) equal the row,
/// so the generator, `clientkeys` and `ua-rs` compute what the contract computes. UNAUDITED.
contract WrapLimitsVectorsTest is WrapLimitsBase {
    using stdJson for string;

    function test_decayRowsEqualTheContract() public {
        string memory j = vm.readFile("../vectors/wraplimits/wraplimits.json");
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".rows[", vm.toString(n), "]"))) ++n;
        assertEq(n, 8, "rows");
        for (uint256 r; r < n; ++r) _row(j, string.concat(".rows[", vm.toString(r), "]"));
    }

    function _row(string memory j, string memory p) internal {
        vm.warp(j.readUint(string.concat(p, ".t0")));
        WrappedToken w = _hyb();
        uint8 e = uint8(j.readUint(string.concat(p, ".unitExp")));
        uint16 d = uint16(j.readUint(string.concat(p, ".decayDays")));
        _set(w, _cfg1(e, d, OFF(), OFF(), OFF(), OFF()), true, false, false);
        string memory name = j.readString(string.concat(p, ".name"));
        for (uint256 k; vm.keyExistsJson(j, string.concat(p, ".steps[", vm.toString(k), "]")); ++k) {
            string memory s = string.concat(p, ".steps[", vm.toString(k), "]");
            bytes32 op = keccak256(bytes(j.readString(string.concat(s, ".op"))));
            uint256 v = vm.parseUint(j.readString(string.concat(s, ".value")));
            if (op == keccak256("warp")) vm.warp(block.timestamp + v);
            else if (op == keccak256("wrap")) _wrap(w, alice, v);
            else _unwrap(w, alice, v);
            _check(j, string.concat(p, ".after[", vm.toString(k), "]"), w, name);
        }
    }

    function _check(string memory j, string memory a, WrappedToken w, string memory name) internal view {
        uint256 word = _word(w, _pad(alice), 0);
        assertEq(block.timestamp, j.readUint(string.concat(a, ".time")), name);
        assertEq(uint32(word >> 160), j.readUint(string.concat(a, ".base")), name);
        assertEq(word >> 192, j.readUint(string.concat(a, ".startMin")), name);
        assertEq(_q(w, alice).entitlement, vm.parseUint(j.readString(string.concat(a, ".entitlement"))), name);
    }
}
