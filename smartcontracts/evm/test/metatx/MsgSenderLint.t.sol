// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// CTR-MTX-18: authority and balance owners are read through `_msgSender()`; the reads that stay `msg.sender`
/// are exactly: the reentrancy guard, `_msgSender()` and `_ticketSubject()` themselves (with `_msgSender()`'s EIP-7702
/// designator refusal), the relayer binding (with its designator refusal), the
/// default fee recipient and the event `relayer` (every pipeline, the UA ledger's two included), and the factory check
/// in `initialize`, the governance subject and the router's target compare. Lines whose first non-blank characters
/// are `//` are skipped (block comments are not). A change here is deliberate: update the pin in the same commit and
/// say why.
contract MsgSenderLintTest is Test {
    // ua-mtx-merge MD-6: + MetaTxAddressBase (the address bodies moved out of MetaTxBase), MtxRelayFee, the PQZ token files,
    // ZetherWrappedLib; `PqzLayer` and `SCaaSDex` read `this.` on purpose (pinned in `test_noExternalSelfCalls`)
    string[24] internal FILES = ["src/metatx/MetaTxAddressBase.sol", "src/metatx/MtxRelayFee.sol", "src/pqz/NormalPqzToken.sol",
        "src/pqz/WrappedPqzToken.sol", "src/pqz/PqzWrappedLib.sol", "src/zether/ZetherWrappedLib.sol", "src/metatx/MetaTxBase.sol", "src/metatx/UAMetaTxBase.sol", "src/metatx/MtxPipelineLib.sol", "src/metatx/ERC20MetaTx.sol", "src/metatx/MetaTokenBase.sol",
        "src/metatx/NormalToken.sol", "src/metatx/WrappedToken.sol", "src/metatx/WrappedLib.sol",
        "src/governance/GovernanceLib.sol", "src/hedera/HederaLib.sol", "src/trade/TradeLib.sol", "src/zether/ZetherLayer.sol",
        "src/zether/ZetherLib.sol", "src/zether/NormalZetherToken.sol", "src/zether/WrappedZetherToken.sol",
        "src/governance/GovernanceBase.sol", "src/governance/GovernanceRouterBase.sol", "src/governance/GovernanceRouter.sol"];

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
        // metatx split T2: the relayer binding x2 moved into MtxPipelineLib._checkEnvelope (inlined into MetaTxBase).
        // no7702 (owner ruling 2026-10-30, D2 / D3): `_msgSender()` and the relayer binding refuse a designator caller.
        assertEq(_count("src/metatx/MetaTxBase.sol", "msg.sender", false), 8,
            "MetaTxBase: guard, event, _msgSender x3 (incl. the designator refusal), fee default, ticket binding (CTR-ZTH-34), _ticketSubject");
        assertEq(_count("src/metatx/MtxPipelineLib.sol", "msg.sender", false), 5,
            "MtxPipelineLib: relayer binding x3 (incl. the designator refusal), fee default x2 (preCall, _checkTransfer)");
        // metatx split T4: the fee defaults left with `_checkTransfer` / `_checkUATransfer` / `_callFee` (now in
        // MtxPipelineLib); the event of `_execute` came down from MetaTxBase in T3.
        // dex-round T4 (DX7): the two `restorePulled` overloads read their caller directly (`o.dex`), as `mtxTrade`.
        assertEq(_count("src/metatx/ERC20MetaTx.sol", "msg.sender", false), 7,
            "ERC20MetaTx: event relayer x3 (_execute, _executeTransfer, _uaExecuteTransfer), mtxTrade and uaTrade caller (CTR-DEX-15, -25), restorePulled caller x2 (DX7)");
        // ua-mtx-merge T1 (Q2): 1 -> 2, the ordered `mtxCancelNonce` emits its own `UAMetaTransactionExecuted` (no self-call)
        assertEq(_count("src/metatx/UAMetaTxBase.sol", "msg.sender", false), 2,
            "UAMetaTxBase: event relayer (_uaSettle, mtxCancelNonce)");
        // ua-mtx-merge MD-6: the files the merge rewrites, at their base counts (MetaTxAddressBase: new, the address
        // bodies moved out of MetaTxBase, which kept its 8)
        assertEq(_count("src/metatx/MetaTxAddressBase.sol", "msg.sender", false), 0, "MetaTxAddressBase");
        assertEq(_count("src/metatx/MtxRelayFee.sol", "msg.sender", false), 4,
            "MtxRelayFee: ROUTER at construction, the router check, the open-mode payee x2 (pay and pad)");
        assertEq(_count("src/pqz/PqzLayer.sol", "msg.sender", false), 0, "PqzLayer");
        assertEq(_count("src/pqz/NormalPqzToken.sol", "msg.sender", false), 0, "NormalPqzToken");
        assertEq(_count("src/pqz/WrappedPqzToken.sol", "msg.sender", false), 0, "WrappedPqzToken");
        assertEq(_count("src/pqz/PqzWrappedLib.sol", "msg.sender", false), 0, "PqzWrappedLib");
        assertEq(_count("src/zether/ZetherWrappedLib.sol", "msg.sender", false), 0, "ZetherWrappedLib");
        assertEq(_count("src/dex/SCaaSDex.sol", "msg.sender", false), 14,
            "SCaaSDex: the factory check, _msgSender x2 (with its designator refusal), the self-call guard x2, the submitter x9");
        assertEq(_count("src/metatx/MetaTokenBase.sol", "msg.sender", false), 4,
            "MetaTokenBase: factory check in initialize; the relayer of mtxRelayFee, uaRelayFee (struct word x2, `_relayHash`), bound to the direct caller");
        assertEq(_count("src/metatx/NormalToken.sol", "msg.sender", false), 0, "NormalToken");
        assertEq(_count("src/metatx/WrappedToken.sol", "msg.sender", false), 4, "WrappedToken: mtxWrapOrder and uaWrapOrder submitter x2 (CTR-TOK-20)");
        // governance T8 (spec §6.1, GD-20): `_addLeg` asks the factory, `msg.sender` through the DELEGATECALL, `isRegisteredToken`
        assertEq(_count("src/metatx/WrappedLib.sol", "msg.sender", false), 1, "WrappedLib: the factory in _addLeg's leg check (CTR-GOV-05)");
        assertEq(_count("src/trade/TradeLib.sol", "msg.sender", false), 0, "TradeLib: the caller is a parameter");
        assertEq(_count("src/governance/GovernanceLib.sol", "msg.sender", false), 0, "GovernanceLib");
        assertEq(_count("src/hedera/HederaLib.sol", "msg.sender", false), 0, "HederaLib");
        assertEq(_count("src/zether/ZetherLayer.sol", "msg.sender", false), 0, "ZetherLayer");
        assertEq(_count("src/zether/ZetherLib.sol", "msg.sender", false), 0, "ZetherLib");
        assertEq(_count("src/zether/NormalZetherToken.sol", "msg.sender", false), 0, "NormalZetherToken");
        assertEq(_count("src/zether/WrappedZetherToken.sol", "msg.sender", false), 0, "WrappedZetherToken");
        // governance T10b / T11 (CTR-GOV-01 and CTR-GOV-15 Changes): the subject of a governance check is the caller's native
        // id, or, from the release's GOV_ROUTER, the UA the router names; the router names it only to its live target
        assertEq(_count("src/governance/GovernanceBase.sol", "msg.sender", false), 2,
            "GovernanceBase: _govSubject's router compare and the subject asked of it");
        assertEq(_count("src/governance/GovernanceRouterBase.sol", "msg.sender", false), 3,
            "GovernanceRouterBase: subject()'s target compare, the event relayer x2 (mtx, ua)");
        assertEq(_count("src/governance/GovernanceRouter.sol", "msg.sender", false), 0, "GovernanceRouter");
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
        // ua-mtx-merge MD-6: two files read `this.` outside a selector on purpose, outside any allowlisted body
        assertEq(_count("src/pqz/PqzLayer.sol", "this.", true), 1, "PqzLayer: `try this.disclosureStatement` (a view)");
        assertEq(_count("src/dex/SCaaSDex.sol", "this.", true), 2,
            "SCaaSDex: `abi.encodeCall(this.settleOne / this.exchangeOne, ...)`, calldata for its own `_selfCall`");
    }
}
