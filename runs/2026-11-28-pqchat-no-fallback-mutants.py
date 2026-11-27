# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat with no fallback (CTR-CHAT-32, ARCH-POS-29, owner 2026-11-27/28): the tree views declared in PqChat's ABI and the
signed-record step in the linked library PqChatRecordLib. One mutant per new check, each killed by its named test.
python3 runs/2026-11-28-pqchat-no-fallback-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main  # noqa: E402

C = "smartcontracts/evm/src/pqchat/PqChat.sol"
L = "smartcontracts/evm/src/pqchat/PqChatRecordLib.sol"
D = "smartcontracts/evm/script/DeployBase.sol"
F = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path "
V = F + "test/pqchat/PqChatTreeViews.t.sol --match-test "
S = F + "test/pqchat/PqChat.t.sol --match-test "
GD = F + "test/governance/GovDeploy.t.sol --match-test test_deployPqChatPath"
FALLBACK = """    fallback() external {
        address v = VIEWS;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), v, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    /// @dev A tree view: `_forward`"""
GONE_OWN = """    /// @inheritdoc IPqChatTreeViews
    function goneOwnKeyOf(bytes32 sessionId, bytes32 ua, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch)
    {
        _treeView();
    }
"""
MUTANTS = [
    ("a view routed to the topics module", [(C, "        _forward(VIEWS);\n", "        _forward(TOPICS);\n")],
     V + "test_viewsReadTheTree", "test_viewsReadTheTree"),
    ("a view missing from the ABI (goneOwnKeyOf undeclared)",
     [(C, "contract PqChat is IPqChat, IPqChatTreeViews, PqChatCore {", "contract PqChat is IPqChat, PqChatCore {"),
      (C, "returns (TreeLeafView[] memory)", "returns (IPqChatTreeViews.TreeLeafView[] memory)"),
      (C, "returns (TreeNodeView[] memory)", "returns (IPqChatTreeViews.TreeNodeView[] memory)"),
      (C, "    /// @inheritdoc IPqChatTreeViews\n    uint256 public constant TREE_RANGE_MAX",
       "    uint256 public constant TREE_RANGE_MAX"),
      (C, "    /// @inheritdoc IPqChatTreeViews\n    uint256 public constant TREE_LEAF_PAGE_MAX",
       "    uint256 public constant TREE_LEAF_PAGE_MAX"),
      (C, GONE_OWN, "")]
     + [(C, f"    /// @inheritdoc IPqChatTreeViews\n    function {f}(", f"    function {f}(") for f in (
         "treeOf", "treeLeaves", "treeNodes", "treeNodeKey", "commitOf", "pathListOf", "pathKeys", "pathCtAt", "goneOf",
         "goneKeyOf")],
     V + "test_abiListsTheViewsAndNoFallback", "test_abiListsTheViewsAndNoFallback"),
    ("the fallback back", [(C, "    /// @dev A tree view: `_forward`", FALLBACK)],
     V + "test_abiListsTheViewsAndNoFallback", "test_abiListsTheViewsAndNoFallback"),
    ("the library unpinned from the class env",
     [(D, "        e.libs = new address[](5);\n        (e.libs[0], e.libs[1], e.libs[2], e.libs[3], e.libs[4]) =\n"
          "        (address(PqChatRecordLib), topics, tree, views, members);\n        e.libCodeHashes = new bytes32[](5);\n"
          "        for (uint256 i; i < 5; ++i) {",
       "        e.libs = new address[](4);\n        (e.libs[0], e.libs[1], e.libs[2], e.libs[3]) = (topics, tree, views, members);\n"
       "        e.libCodeHashes = new bytes32[](4);\n        for (uint256 i; i < 4; ++i) {")],
     GD, "test_deployPqChatPath"),
    ("createSession through the epoch record",
     [(C, "_record(PqChatRecordLib.sessionRecord.selector)", "_record(PqChatRecordLib.epochRecord.selector)")],
     S + "test_createSession_forgedRecordBurnsNoNonce", "test_createSession_forgedRecordBurnsNoNonce"),
    ("the library skips the session signature",
     [(L, "        _auth(s.creator, PqChatTypes.hashSession(s), sig);\n", "")],
     S + "test_createSession_forgedRecordBurnsNoNonce", "test_createSession_forgedRecordBurnsNoNonce"),
    ("the library signs the message under another UA",
     [(L, "        _auth(m.sender, hm, sig);", "        _auth(m.epochId, hm, sig);")],
     F + "test/pqchat/PqChatMessages.t.sol --match-test test_postMessage_forgedBurnsNoNonce",
     "test_postMessage_forgedBurnsNoNonce"),
    ("the nonce before the signature (createSession)",
     [(C, "            bytes memory rec = _record(PqChatRecordLib.sessionRecord.selector);\n"
          "            _useNonce(PqChatTypes.scopeSession(s.creator), s.nonce);",
       "            _useNonce(PqChatTypes.scopeSession(s.creator), s.nonce);\n"
       "            bytes memory rec = _record(PqChatRecordLib.sessionRecord.selector);")],
     S + "test_createSession_signatureBeforeNonce", "test_createSession_signatureBeforeNonce"),
    ("the library's message inputs reordered (no longer the entry's)",
     [(L, "    function messageRecord(IPqChat.PqChatMessage calldata m, IUARegistry.UASig calldata sig)",
       "    function messageRecord(IUARegistry.UASig calldata sig, IPqChat.PqChatMessage calldata m)")],
     F + "test/pqchat/PqChatRecordLib.t.sol --match-test test_entriesAndLibraryTakeTheSameInputs",
     "test_entriesAndLibraryTakeTheSameInputs"),
    ("the tree path stores the message in another form",
     [("smartcontracts/evm/src/pqchat/PqChatCore.sol", "bytes memory blob = _blob(abi.encode(m), sig);",
       "bytes memory blob = abi.encode(m, keccak256(abi.encode(sig)));")],
     V + "test_treeMessageBlobIsTheFlatForm", "test_treeMessageBlobIsTheFlatForm"),
    ("a library revert swallowed",
     [(C, "            if iszero(ok) { revert(add(ret, 32), mload(ret)) }\n        }\n        return sel ==",
       "        }\n        return sel ==")],
     S + "test_createSession_forgedRecordBurnsNoNonce", "test_createSession_forgedRecordBurnsNoNonce"),
]

if __name__ == "__main__":
    main("all", MUTANTS, prefix="2026-11-28-pqchat-no-fallback")
