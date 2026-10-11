// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// CTR-MTX-18: authority and balance owners are read through `_msgSender()`; the reads that stay `msg.sender`
/// are exactly: the reentrancy guard and `_msgSender()` itself, the relayer binding, the default fee recipient and
/// the event `relayer` (both pipelines), and the factory check in `initialize`. Lines whose first non-blank characters
/// are `//` are skipped (block comments are not). A change here is deliberate: update the pin in the same commit and
/// say why.
contract MsgSenderLintTest is Test {
    string[9] internal FILES = ["src/metatx/MetaTxBase.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
        "src/metatx/NoUnderlyingToken.sol", "src/metatx/UnderlyingToken.sol", "src/metatx/UnderlyingLib.sol",
        "src/metatx/AdminLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol"];

    /// Occurrences of `pat` (not preceded by an identifier character); `exceptSelector` skips `pat<ident>.selector`.
    function _count(string memory path, bytes memory pat, bool exceptSelector) internal view returns (uint256 n) {
        bytes memory s = bytes(vm.readFile(path));
        bool lineStart = true;
        bool comment;
        for (uint256 i; i < s.length; ++i) {
            bytes1 c = s[i];
            if (c == "\n") { lineStart = true; comment = false; continue; }
            if (lineStart) {
                if (c == " " || c == "\t") continue;
                lineStart = false;
                comment = c == "/" && i + 1 < s.length && s[i + 1] == "/";
            }
            if (comment || i + pat.length > s.length) continue;
            bool hit = true;
            for (uint256 j; j < pat.length; ++j) {
                if (s[i + j] != pat[j]) { hit = false; break; }
            }
            if (hit && (i == 0 || !_ident(s[i - 1])) && !(exceptSelector && _selectorRead(s, i + pat.length))) ++n;
        }
    }

    function _ident(bytes1 c) internal pure returns (bool) {
        return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "_" || c == "$";
    }

    /// `s[k..]` is `<identifier>.selector`.
    function _selectorRead(bytes memory s, uint256 k) internal pure returns (bool) {
        uint256 start = k;
        while (k < s.length && _ident(s[k])) ++k;
        bytes memory sel = ".selector";
        if (k == start || k + sel.length > s.length) return false;
        for (uint256 j; j < sel.length; ++j) {
            if (s[k + j] != sel[j]) return false;
        }
        return true;
    }

    function test_msgSenderReadsArePinned() public view {
        assertEq(_count("src/metatx/MetaTxBase.sol", "msg.sender", false), 7, "MetaTxBase: guard, event, relayer binding x2, _msgSender x2, fee default");
        assertEq(_count("src/metatx/ERC20MetaTx.sol", "msg.sender", false), 3, "ERC20MetaTx: event relayer, fee default, mtxTrade caller (CTR-DEX-15)");
        assertEq(_count("src/metatx/MetaTokenBase.sol", "msg.sender", false), 1, "MetaTokenBase: factory check in initialize");
        assertEq(_count("src/metatx/NoUnderlyingToken.sol", "msg.sender", false), 0, "NoUnderlyingToken");
        assertEq(_count("src/metatx/UnderlyingToken.sol", "msg.sender", false), 2, "UnderlyingToken: mtxWrap submitter x2 (CTR-TOK-20)");
        assertEq(_count("src/metatx/UnderlyingLib.sol", "msg.sender", false), 0, "UnderlyingLib");
        assertEq(_count("src/trade/TradeLib.sol", "msg.sender", false), 0, "TradeLib: the caller is a parameter");
        assertEq(_count("src/metatx/AdminLib.sol", "msg.sender", false), 0, "AdminLib");
        assertEq(_count("src/hedera/HederaLib.sol", "msg.sender", false), 0, "HederaLib");
    }

    /// CTR-MTX-18: an external self-call (`this.f(…)`) inside an allowlisted body would let a guarded callee consume
    /// the ticket for an unguarded body and defeat `_selfCall`'s fail-closed check. The only `this.` uses are
    /// `this.<fn>.selector` reads (counted too, so the scan is not vacuous).
    function test_noExternalSelfCalls() public view {
        uint256 all;
        for (uint256 i; i < FILES.length; ++i) {
            assertEq(_count(FILES[i], "this.", true), 0, FILES[i]);
            all += _count(FILES[i], "this.", false);
        }
        assertGt(all, 0);
    }
}
