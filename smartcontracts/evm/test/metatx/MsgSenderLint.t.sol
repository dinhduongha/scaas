// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// CTR-MTX-18: authority and balance owners are read through `_msgSender()`; the reads that stay `msg.sender`
/// are exactly: the reentrancy guard and `_msgSender()` itself, the relayer binding, the default fee recipient and
/// the event `relayer` (both pipelines), and the factory check in `initialize`. Comment lines are skipped. A change
/// here is deliberate: update the pin in the same commit and say why.
contract MsgSenderLintTest is Test {
    function _count(string memory path) internal view returns (uint256 n) {
        bytes memory s = bytes(vm.readFile(path));
        bytes memory pat = bytes("msg.sender");
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
            if (hit) ++n;
        }
    }

    function test_msgSenderReadsArePinned() public view {
        assertEq(_count("src/metatx/MetaTxBase.sol"), 7, "MetaTxBase: guard, event, relayer binding x2, _msgSender x2, fee default");
        assertEq(_count("src/metatx/ERC20MetaTx.sol"), 2, "ERC20MetaTx: event relayer, fee default");
        assertEq(_count("src/metatx/MetaTokenBase.sol"), 1, "MetaTokenBase: factory check in initialize");
        assertEq(_count("src/metatx/NoUnderlyingToken.sol"), 0, "NoUnderlyingToken");
        assertEq(_count("src/metatx/SingleUnderlyingToken.sol"), 0, "SingleUnderlyingToken");
        assertEq(_count("src/metatx/MultiUnderlyingToken.sol"), 0, "MultiUnderlyingToken");
        assertEq(_count("src/hedera/HederaTokensV2.sol"), 0, "HederaTokensV2");
    }
}
