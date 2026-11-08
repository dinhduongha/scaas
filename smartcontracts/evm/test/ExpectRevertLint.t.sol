// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {GovernanceRouter} from "../src/governance/GovernanceRouter.sol";
import {SaltedEIP712} from "../src/common/SaltedEIP712.sol";

/// A deploy right after `vm.expectRevert` must be a real CREATE one frame down, so the test goes on after it (audit
/// 2026-11-04). With Foundry's dynamic test linking, `new <src contract>` in a test becomes `vm.deployCode`, whose
/// constructor revert ends the test frame itself and passes as the expected revert: nothing after it runs.
/// `foundry.toml` sets `dynamic_test_linking = false`; the canary fails when that setting is lost (positive control:
/// `FOUNDRY_DYNAMIC_TEST_LINKING=true` turns it red). An explicit `vm.deployCode` has the same hole under either setting,
/// so the shape check refuses it after an expectation; forge-std `deployCode` (a real CREATE) is fine.
contract ExpectRevertLintTest is Test {
    function test_expectRevertThenDeployRunsTheTail() public {
        (bool ok, bytes memory ret) = address(this).call(abi.encodeCall(this.probeTail, ()));
        assertFalse(ok, "probe frame must revert with the tail's reason");
        assertEq(ret, abi.encodeWithSignature("Error(string)", "tail reached"), "the tail after expectRevert ran");
    }

    /// A src contract whose constructor reverts (the router's `chain_uid` 0; chain-neutral releases moved the factory's
    /// to `configureChain`, plan T71).
    function probeTail() external {
        vm.expectRevert(SaltedEIP712.ChainUidZero.selector);
        new GovernanceRouter(bytes32(0), address(0), address(0), false);
        revert("tail reached");
    }

    /// The shape check on known text, so it can fail: one positive per form, the allowed forms negative.
    function test_shapeCheckFindsTheShape() public pure {
        (uint256 n, uint256 bad) = _scan(bytes("vm.expectRevert(X.E.selector);\n vm.deployCode(\"src/A.sol:A\", a);"));
        assertEq(n, 1);
        assertEq(bad, 1, "direct");
        (, bad) = _scan(bytes("vm.expectRevertPartial(X.E.selector); vm.prank(u);\n a = A(vm.deployCode(\"A\"));"));
        assertEq(bad, 1, "after another cheatcode");
        (, bad) = _scan(bytes("vm.expectRevert(); deployCode(\"A\"); vm.deployCode(\"A\");"));
        assertEq(bad, 0, "forge-std deployCode, and a later statement");
        (, bad) = _scan(bytes("// vm.expectRevert(); vm.deployCode(\"A\");\n /* vm.expectRevert(); vm.deployCode(\"A\"); */ x;"));
        assertEq(bad, 0, "comments");
        (n, bad) = _scan(bytes("s = \"vm.expectRevert(); vm.deployCode(\";"));
        assertEq(n + bad, 0, "strings");
    }

    /// Every `vm.expectRevert…;` in `test/`: its next statement that is not another cheatcode holds no `vm.deployCode(`.
    function test_noExplicitDeployCodeAfterExpectRevert() public view {
        Vm.DirEntry[] memory es = vm.readDir("test", 8);
        uint256 sites;
        for (uint256 i; i < es.length; ++i) {
            bytes memory p = bytes(es[i].path);
            if (es[i].isDir || p.length < 4 || bytes4(_word(p, p.length - 4)) != bytes4(".sol")) continue;
            (uint256 n, uint256 bad) = _scan(bytes(vm.readFile(es[i].path)));
            assertEq(bad, 0, es[i].path);
            sites += n;
        }
        assertGt(sites, 1000, "the scan sees the suite's expectations");
    }

    /// (expectRevert sites, sites whose next non-cheatcode statement holds `vm.deployCode(`), outside comments and strings.
    function _scan(bytes memory s) internal pure returns (uint256 n, uint256 bad) {
        for (uint256 i; i < s.length;) {
            uint256 k = _skip(s, i);
            if (k != i) { i = k; continue; }
            if (s[i] == "v" && (i == 0 || !_ident(s[i - 1])) && _at(s, i, "vm.expectRevert")) {
                ++n;
                uint256 j = _end(s, i) + 1;
                while (true) {
                    j = _space(s, j);
                    if (_at(s, j, "vm.") && !_at(s, j, "vm.deployCode") && !_at(s, j, "vm.expect")) j = _end(s, j) + 1;
                    else break;
                }
                if (_has(s, j, _end(s, j), "vm.deployCode(")) ++bad;
                i = _end(s, i) + 1;
            } else {
                ++i;
            }
        }
    }

    /// Past a comment or string literal at `i`, else `i`. No literal `bytes` here: each would allocate per byte.
    function _skip(bytes memory s, uint256 i) internal pure returns (uint256) {
        bytes1 next = i + 1 < s.length ? s[i + 1] : bytes1(0);
        if (s[i] == "/" && next == "/") { while (i < s.length && s[i] != "\n") ++i; return i; }
        if (s[i] == "/" && next == "*") {
            for (i += 2; i + 1 < s.length; ++i) {
                if (s[i] == "*" && s[i + 1] == "/") return i + 2;
            }
            return s.length;
        }
        if (s[i] == '"') {
            ++i;
            while (i < s.length && s[i] != '"') i += s[i] == "\\" ? 2 : 1;
            return i + 1;
        }
        return i;
    }

    /// Past whitespace and comments.
    function _space(bytes memory s, uint256 i) internal pure returns (uint256) {
        while (i < s.length) {
            uint256 k = _skip(s, i);
            if (k != i && s[i] != '"') { i = k; continue; }
            if (s[i] != " " && s[i] != "\n" && s[i] != "\t" && s[i] != "\r") break;
            ++i;
        }
        return i;
    }

    /// The `;` ending the statement at `i` (outside comments and strings), or `s.length`.
    function _end(bytes memory s, uint256 i) internal pure returns (uint256) {
        while (i < s.length) {
            uint256 k = _skip(s, i);
            if (k != i) { i = k; continue; }
            if (s[i] == ";") return i;
            ++i;
        }
        return s.length;
    }

    function _has(bytes memory s, uint256 from, uint256 to, bytes memory pat) internal pure returns (bool) {
        for (uint256 i = from; i + pat.length <= to; ++i) {
            if (_at(s, i, pat)) return true;
        }
        return false;
    }

    function _at(bytes memory s, uint256 i, bytes memory pat) internal pure returns (bool) {
        if (i + pat.length > s.length) return false;
        for (uint256 j; j < pat.length; ++j) {
            if (s[i + j] != pat[j]) return false;
        }
        return true;
    }

    function _word(bytes memory s, uint256 i) internal pure returns (bytes32 w) {
        assembly { w := mload(add(add(s, 32), i)) }
    }

    function _ident(bytes1 c) internal pure returns (bool) {
        return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "_" || c == "$";
    }
}
