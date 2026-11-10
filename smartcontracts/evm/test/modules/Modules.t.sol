// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {kindModuleNames, deployKindModules, kindImplArgs} from "../../script/KindModules.sol";
import {ITokenModule, ITokenModules} from "../../src/metatx/ITokenModule.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {regArgs} from "../helpers/Catalogue.sol";

/// T66b §4.5, §10 (M1, M2, Fable P2-1, P2-A): each kind's implementation checks its modules at construction (`ModuleMissing`:
/// count, code; `ModuleMismatch`: kind, group, factory, registry code hash, PQZ set), each with its control; every module-face
/// entry refuses a direct call (`NotDelegated`), the identity views and the inherited `ERC20` entries answer one.
contract ModulesTest is Test {
    address internal constant F = address(0xFAC);
    uint8[12] internal kinds = [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13];
    string[14] internal faces = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
        "WrappedPqzToken", "", "", "NormalRegulatedToken", "WrappedRegulatedToken", "NormalZetherRegulatedToken",
        "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken"];

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

    function _impl(uint8 k, address[] memory ms, bytes memory core) internal view returns (bytes memory) {
        string memory n = faces[k];
        return bytes.concat(vm.getCode(string.concat(n, ".sol:", n)), abi.encode(F, kindImplArgs(k, ms, core)));
    }

    function _copy(address[] memory ms) internal pure returns (address[] memory c) {
        c = new address[](ms.length);
        for (uint256 i; i < ms.length; ++i) c[i] = ms[i];
    }

    function _refused(uint8 k, address[] memory ms, bytes memory err) internal {
        vm.expectRevert(err);
        this.create(_impl(k, ms, _core(k)));
    }

    function test_m_constructorChecksEveryModule() public {
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            (address[] memory ms,) = deployKindModules(k, F, _core(k));
            uint256 n = ms.length;
            // control: the kind's own modules, in order
            address impl = this.create(_impl(k, ms, _core(k)));
            assertEq(ITokenModules(impl).modules(), ms, faces[k]);
            // count
            address[] memory short = new address[](n - 1);
            for (uint256 i; i + 1 < n; ++i) short[i] = ms[i];
            _refused(k, short, abi.encodeWithSelector(MetaTokenBase.ModuleMissing.selector, n - 1));
            // no code
            address[] memory c = _copy(ms);
            c[1] = address(0xDEAD);
            _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMissing.selector, 1));
            // another kind's module of the same group (P of NORMAL, or of WRAPPED on NORMAL)
            (address[] memory other,) = deployKindModules(k == 0 ? 1 : 0, F, "");
            c = _copy(ms);
            c[0] = other[0];
            _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMismatch.selector, 0));
            // two pinned modules swapped: another group in a slot
            c = _copy(ms);
            (c[0], c[n - 1]) = (ms[n - 1], ms[0]);
            _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMismatch.selector, 0));
            // a module built for another factory
            (address[] memory far,) = deployKindModules(k, address(0xF00), _core(k));
            c = _copy(ms);
            c[n - 1] = far[n - 1];
            _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMismatch.selector, n - 1));
            if (k >= 8) { // a module built with another registry code hash
                (address[] memory reg,) = deployKindModules(k, F, abi.encode(bytes32(uint256(1))));
                c = _copy(ms);
                c[2] = reg[2];
                _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMismatch.selector, 2));
            }
            if (k == 4 || k == 5 || k == 12 || k == 13) { // every module answers this set; one of another set is refused
                for (uint256 i; i < n; ++i) assertEq(ITokenModule(ms[i]).pqzSet(), PqzSet.SELFTEST);
                for (uint256 i; i < n; ++i) {
                    c = _copy(ms);
                    c[i] = _otherSet(ms[i]);
                    _refused(k, c, abi.encodeWithSelector(MetaTokenBase.ModuleMismatch.selector, i));
                }
            }
        }
    }

    function _art(string memory file, string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.envOr("FOUNDRY_OUT", string("out")), "/", file, "/", name, ".json"));
    }

    /// §8, M6: every module's storage layout (solc `storageLayout`: label, slot, offset, type) equals its kind's face's
    /// entry for entry and has none past it (the faces of kinds 0-5 are pinned by test/v2/Layout.t.sol).
    function test_m_layoutEqualsTheKind() public view {
        uint256 rows;
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            string memory face = _art(string.concat(faces[k], ".sol"), faces[k]);
            string[] memory names = kindModuleNames(k);
            for (uint256 i; i < names.length; ++i) {
                string[] memory p = vm.split(names[i], ":");
                string memory m = _art(p[0], p[1]);
                uint256 n;
                for (;; ++n) {
                    string memory e = string.concat(".storageLayout.storage[", vm.toString(n), "]");
                    if (!vm.keyExistsJson(face, e)) break;
                    string[4] memory f = ["label", "slot", "offset", "type"];
                    for (uint256 j; j < 4; ++j) {
                        string memory q = string.concat(e, ".", f[j]);
                        assertEq(vm.parseJsonString(m, q), vm.parseJsonString(face, q), string.concat(p[1], q));
                    }
                }
                assertGt(n, 0, faces[k]);
                assertFalse(vm.keyExistsJson(m, string.concat(".storageLayout.storage[", vm.toString(n), "]")),
                    string.concat(p[1], ": a variable past its kind's layout"));
                ++rows;
            }
        }
        // owner 2026-11-10 (group 3p): 55 -> 58, kinds 9, 11, 13 split W into W (wrap) and R (regulated)
        assertEq(rows, 58, "every module of the twelve kinds");
    }

    /// @dev `m`'s runtime with its set's self-test hash changed, at a new address: a module answering another PQZ set and
    ///      nothing else different (P2-A's case, a module built at another set).
    function _otherSet(address m) internal returns (address a) {
        bytes memory code = m.code;
        bytes32 h = PqzSet.SELFTEST;
        uint256 hits;
        for (uint256 i; i + 32 <= code.length; ++i) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(code, 32), i))
            }
            if (w == h) {
                code[i + 31] = code[i + 31] ^ 0x01;
                ++hits;
            }
        }
        assertGt(hits, 0, "the set's self-test hash is in the module's code");
        a = address(uint160(uint256(keccak256(abi.encode("t66b.other-set", m)))));
        vm.etch(a, code);
        assertTrue(ITokenModule(a).pqzSet() != h);
    }

    /// @dev Not a module-face entry (M2): the identity views; the kept token entries every core inherits (OZ `ERC20`, the
    ///      UA ledger's `balanceOfUA` / `transferToUA`, `implementation`, the one-word env views), which run on the module's
    ///      own locked storage and code; and the `pure` entries, which read nothing (accepted without `onlyDelegated`).
    function _exempt(bytes32 s, string memory name, string[] memory pures) internal pure returns (bool) {
        for (uint256 i; i < pures.length; ++i) if (keccak256(bytes(pures[i])) == keccak256(bytes(name))) return true;
        return s == keccak256("kind()") || s == keccak256("moduleGroup()") || s == keccak256("factory()")
            || s == keccak256("FACTORY()") || s == keccak256("REGISTRY_CODEHASH()") || s == keccak256("pqzSet()")
            || s == keccak256("name()") || s == keccak256("symbol()") || s == keccak256("decimals()")
            || s == keccak256("totalSupply()") || s == keccak256("balanceOf(address)")
            || s == keccak256("allowance(address,address)") || s == keccak256("transfer(address,uint256)")
            || s == keccak256("transferFrom(address,address,uint256)") || s == keccak256("approve(address,uint256)")
            || s == keccak256("balanceOfUA(bytes32)") || s == keccak256("transferToUA(bytes32,uint256)")
            || s == keccak256("implementation()") || s == keccak256("registry()") || s == keccak256("chainUid()")
            || s == keccak256("IS_HEDERA()") || s == keccak256("SMART_KEY_ACCOUNT_IMPL()")
            || s == keccak256("RATE_WINDOW()"); // a constant (its getter is `view` in the ABI)
    }

    /// @dev The names of the `pure` functions of an artifact's ABI; a name also used by a non-pure overload is refused.
    function _pures(string memory j) internal view returns (string[] memory out) {
        string[] memory tmp = new string[](64);
        uint256 n;
        for (uint256 k;; ++k) {
            string memory p = string.concat(".abi[", vm.toString(k), "]");
            if (!vm.keyExistsJson(j, p)) break;
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(p, ".type")))) != keccak256("function")) continue;
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(p, ".stateMutability")))) != keccak256("pure")) continue;
            tmp[n++] = vm.parseJsonString(j, string.concat(p, ".name"));
        }
        out = new string[](n);
        for (uint256 i; i < n; ++i) out[i] = tmp[i];
    }

    function _nameOf(string memory sig) internal pure returns (string memory) {
        return vm.split(sig, "(")[0];
    }

    /// M2: every entry of every module of every kind, called directly with zero arguments, reverts `NotDelegated()`; the
    /// exempt ones (identity views, inherited `ERC20`) are the only others, and the count of each is logged.
    function test_m_directCallRefused() public {
        uint256 refused;
        uint256 exempt;
        for (uint256 x; x < kinds.length; ++x) {
            uint8 k = kinds[x];
            (address[] memory ms,) = deployKindModules(k, F, _core(k));
            string[] memory names = kindModuleNames(k);
            for (uint256 i; i < ms.length; ++i) {
                string[] memory p = vm.split(names[i], ":");
                string memory j = vm.readFile(string.concat(vm.envOr("FOUNDRY_OUT", string("out")), "/", p[0], "/", p[1],
                    ".json"));
                string[] memory sigs = vm.parseJsonKeys(j, ".methodIdentifiers");
                string[] memory pures = _pures(j);
                for (uint256 s; s < sigs.length; ++s) {
                    bytes32 h = keccak256(bytes(sigs[s]));
                    if (_exempt(h, _nameOf(sigs[s]), pures)) {
                        ++exempt;
                        continue;
                    }
                    (bool ok, bytes memory ret) = ms[i].call(bytes.concat(bytes4(h), new bytes(2048)));
                    if (vm.envOr("T66B_LIST", false) && (ok || keccak256(ret) != keccak256(abi.encodeWithSelector(MetaTokenBase.NotDelegated.selector)))) {
                        emit log(string.concat("ANSWERS | ", p[1], " | ", sigs[s], " | ", ok ? "ok" : vm.toString(ret)));
                        continue;
                    }
                    assertFalse(ok, string.concat(p[1], ".", sigs[s], ": answered a direct call"));
                    assertEq(ret, abi.encodeWithSelector(MetaTokenBase.NotDelegated.selector),
                        string.concat(p[1], ".", sigs[s], ": NotDelegated"));
                    ++refused;
                }
            }
        }
        emit log_named_uint("T66B-M2 | module-face entries refused", refused);
        emit log_named_uint("T66B-M2 | identity / ERC20 entries answering", exempt);
    }
}
