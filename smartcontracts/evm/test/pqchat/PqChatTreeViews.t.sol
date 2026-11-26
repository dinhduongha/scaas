// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {VmSafe} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqChatTreeViews} from "../../src/pqchat/IPqChatTreeViews.sol";
import {PqChatTreeViews} from "../../src/pqchat/PqChatTreeViews.sol";
import {PqChatTree} from "../../src/pqchat/PqChatTree.sol";
import {PqChatTreeModel} from "./PqChatTreeModel.sol";

/// A writing variant of the module: the read-only scan must refuse it (the scan's positive control).
contract PqChatTreeViewsWriting is PqChatTreeViews {
    constructor(address f) PqChatTreeViews(f) {}

    function poke() external {
        _s().ownerUA = 0;
    }
}

/// A variant that sends value: the scan must refuse it too.
contract PqChatTreeViewsPaying is PqChatTreeViews {
    constructor(address f) PqChatTreeViews(f) {}

    function sweep() external {
        payable(msg.sender).transfer(1);
    }
}

/// Owner 2026-11-24 (option A): the tree views of spec §6 in the read-only body module `PqChatTreeViews`, reached through
/// `PqChat`'s `fallback`. The module's runtime holds no writing opcode; a view through the instance writes no slot of any
/// account; the fallback refuses value and reaches no selector of `PqChat`, `PqChatTopics` or `PqChatTree`; each view is
/// checked against the test's own tree model and the clone's storage read slot by slot; the pages keep their caps (C36).
/// **UNAUDITED.**
contract PqChatTreeViewsTest is PqChatTreeModel {
    using stdJson for string;

    bytes32 internal A;
    bytes32 internal B;
    bytes32 internal C;
    bytes32 internal E;

    function setUp() public override {
        super.setUp();
        (A, B, C, E) = (person["A"], person["B"], person["C"], person["E"]);
    }

    function _v() internal view returns (IPqChatTreeViews) {
        return IPqChatTreeViews(address(vchat));
    }

    // ----- the read-only module -----

    /// The first opcode of `code` that writes state, makes code, calls with value or hands the frame to other code (SSTORE,
    /// TSTORE, LOG0-4, CREATE, CALL, CALLCODE, DELEGATECALL, CREATE2, SELFDESTRUCT), PUSH data skipped and the CBOR tail (its
    /// length in the last two bytes) cut; `(type(uint256).max, 0)` when there is none. CALL is refused whatever its value:
    /// the views read through STATICCALL only.
    function _writes(bytes memory code) internal pure returns (uint256 pc, uint8 op) {
        uint256 end = code.length - 2 - (uint256(uint8(code[code.length - 2])) << 8 | uint8(code[code.length - 1]));
        for (uint256 i; i < end; ++i) {
            uint8 o = uint8(code[i]);
            if (o >= 0x60 && o <= 0x7f) {
                i += o - 0x5f;
            } else if (
                o == 0x55 || o == 0x5d || (o >= 0xa0 && o <= 0xa4) || o == 0xf0 || o == 0xf1 || o == 0xf2 || o == 0xf4
                    || o == 0xf5 || o == 0xff
            ) {
                return (i, o);
            }
        }
        return (type(uint256).max, 0);
    }

    function _readOnly(address a) internal view returns (bool ok, uint256 pc, uint8 op) {
        (pc, op) = _writes(a.code);
        ok = op == 0;
    }

    /// The deployed module holds none of the opcodes above; a writing variant and a paying variant are refused (the scan can
    /// fail), and so is the writing module `PqChatTree`.
    function test_viewsModuleIsReadOnly() public {
        (bool ok, uint256 pc, uint8 op) = _readOnly(address(viewsModule));
        if (!ok) emit log_named_bytes32("opcode at pc", bytes32(pc << 8 | op));
        assertTrue(ok, "PqChatTreeViews: no writing opcode");
        (ok,, op) = _readOnly(address(new PqChatTreeViewsWriting(address(f))));
        assertFalse(ok, "the writing variant refused");
        assertEq(op, 0x55, "its SSTORE found");
        (ok,, op) = _readOnly(address(new PqChatTreeViewsPaying(address(f))));
        assertFalse(ok, "the paying variant refused");
        assertEq(op, 0xf1, "its CALL found");
        (ok,, op) = _readOnly(address(treeModule));
        assertFalse(ok, "PqChatTree writes");
    }

    // ----- a session to read -----

    /// [A, B, E] with admin A; A adds C at leaf 3 and B's second key at leaf 4 (epoch 1); `n` the model after it.
    function _grown() internal returns (M memory m, Step memory st, M memory n) {
        _open(); // the vectors in this call's memory
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](3);
        (mk[0], mk[1], mk[2]) = (_mk(A, 1), _mk(B, 1), _mk(E, 1));
        m = _open(mk, _list(A));
        (st, n) = _build(m, 0, _chs(Ch(true, 3, C, 1), Ch(true, 4, B, 2)), _list(A));
        n = _land(st, n, m);
    }

    /// Every view through the instance against the model, the stored record and pieces, and the clone's slots.
    function test_viewsReadTheTree() public {
        (M memory m, Step memory st, M memory n) = _grown();
        IPqChatTreeViews v = _v();
        {
            (bytes32 tid, uint32 leaves, uint32 used, bytes32 root, bytes32 gen, bytes32 head, uint32 owed,) =
                v.treeOf(m.sid);
            assertEq(tid, n.treeId, "treeId");
            assertEq((uint256(leaves) << 32) | used, (n.leaves << 32) | n.used, "leaves, used");
            assertEq(root, _mRoot(n), "treeHash: the model's");
            assertEq(root, _root(vchat, m.sid), "treeHash: the stored root");
            assertEq(gen, bytes32(_at(vchat, _t(m.sid) + 1)), "genesisTreeHash");
            assertEq(head, st.epochId, "the head");
            assertEq(owed, 0, "owed");
        }
        IPqChatTreeViews.TreeLeafView[] memory l = v.treeLeaves(m.sid, 0, 64);
        assertEq(l.length, n.used, "one entry per used leaf");
        for (uint256 i; i < l.length; ++i) {
            assertEq(l[i].ua, n.ua[i], "ua");
            assertEq(l[i].keyId, n.kid[i], "keyId");
            assertEq(l[i].kemHash, n.kem[i], "kemHash from the registry");
            assertEq(l[i].joinEpoch, i < 3 ? 0 : 1, "joinEpoch");
            assertEq(l[i].wrapIndex, i < 3 ? i : i - 3, "wrapIndex");
        }
        IPqChatTreeViews.TreeNodeView[] memory x = v.treeNodes(m.sid, 0, 256);
        assertEq(x.length, 2 * n.leaves - 1, "every node");
        for (uint256 i; i < x.length; ++i) {
            assertEq(x[i].hash, _th(n, i), "th");
            if (i % 2 == 0) {
                assertEq(x[i].keyHash, n.live[i / 2] ? n.kem[i / 2] : bytes32(0), "a leaf's kemHash");
                assertEq(x[i].epoch, n.live[i / 2] && i / 2 >= 3 ? 1 : 0, "a leaf's joinEpoch");
            } else {
                assertEq(x[i].keyHash, n.key[i], "a parent's keyHash");
                assertEq(x[i].epoch, n.key[i] != 0 ? 1 : 0, "the commit that set it");
                assertEq(keccak256(v.treeNodeKey(m.sid, i)), n.key[i] != 0 ? n.key[i] : keccak256(""), "treeNodeKey");
            }
        }
        assertEq(v.treeNodeKey(m.sid, 0).length, 0, "a leaf has no node key");
        (IPqChat.PqChatCommit memory c, bytes32 sh) = v.commitOf(st.epochId);
        assertEq(keccak256(abi.encode(c)), keccak256(abi.encode(st.c)), "commitOf: the record");
        assertEq(sh, keccak256(abi.encode(_signC(st.c))), "commitOf: its sigHash");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, 0));
        v.commitOf(m.sid); // epoch 0 is the session record
        (uint32[] memory tg, bytes32[] memory hs) = v.pathListOf(st.epochId);
        assertEq(keccak256(abi.encode(tg, hs)), keccak256(abi.encode(st.ctTargets, st.ctHashes)), "pathListOf");
        assertEq(keccak256(abi.encode(v.pathKeys(st.epochId))), keccak256(abi.encode(st.nodeKeys)), "pathKeys");
        for (uint256 i; i < st.cts.length; ++i) {
            assertEq(keccak256(abi.encode(v.pathCtAt(st.epochId, i))), keccak256(abi.encode(st.cts[i])), "pathCtAt");
        }
        assertEq(v.pathCtAt(st.epochId, st.cts.length).mlkemCt.length, 0, "past the last: empty");
        (tg, hs) = v.pathListOf(m.sid);
        assertEq(tg.length + hs.length + v.pathKeys(m.sid).length, 0, "no pieces: empty");
    }

    /// `goneOf`, `goneKeyOf`, `goneOwnKeyOf` against the clone's slots: E removed (kind 2, the head's number, owed 1), then
    /// a commit takes E's leaf (the session-wide set) and B's second key (the pair set: B stays).
    function test_goneViews() public {
        (M memory m,, M memory n) = _grown();
        IPqChatTreeViews v = _v();
        _removeT(n, A, _list(E));
        (uint8 kind, uint64 ep) = v.goneOf(m.sid, E);
        (uint256 rk, uint256 re) = _gone(vchat, m.sid, E);
        assertEq((uint256(kind) << 64) | ep, (rk << 64) | re, "goneOf: the slot");
        assertEq((uint256(kind) << 64) | ep, (2 << 64) | n.epoch, "removed at the head");
        (,,,,,, uint32 owed,) = v.treeOf(m.sid);
        assertEq(owed, 1, "E's leaf owed");
        (kind, ep) = v.goneOf(m.sid, B);
        assertEq(uint256(kind) + ep, 0, "B a member");
        (Step memory st, M memory n2) = _build(n, 0, _chs(Ch(false, 2, E, 1), Ch(false, 4, B, 2)), _list(A));
        _land(st, n2, n);
        IPqChatTreeViews.TreeLeafView[] memory l = v.treeLeaves(m.sid, 2, 3);
        assertEq(keccak256(abi.encode(l[0], l[2])), keccak256(new bytes(320)), "a blank leaf is all zero");
        assertEq(l[1].ua, C, "C stays");
        bytes32 ke = _kemHash(E, 1);
        bytes32 kb = _kemHash(B, 2);
        assertEq(_vKey(m.sid, 0, ke), _rKey(m.sid, 0, ke), "goneKeyOf: the slot");
        assertEq(_vKey(m.sid, 0, ke) >> 128, 1, "E's key session-wide");
        assertEq(_vKey(m.sid, E, ke), 0, "not as a pair");
        assertEq(_vKey(m.sid, B, kb), _rKey(m.sid, B, kb), "goneOwnKeyOf: the slot");
        assertEq(_vKey(m.sid, B, kb), 1 << 128 | 1 << 64 | 2, "B's second key as a pair, 1 to 2");
        assertEq(_vKey(m.sid, 0, kb), 0, "not session-wide");
    }

    /// `goneKeyOf` (`ua` 0) or `goneOwnKeyOf`, packed: set << 128 | joinEpoch << 64 | endEpoch.
    function _vKey(bytes32 sid, bytes32 ua, bytes32 k) internal view returns (uint256) {
        (bool g, uint64 j, uint64 e) = ua == 0 ? _v().goneKeyOf(sid, k) : _v().goneOwnKeyOf(sid, ua, k);
        return (g ? 1 << 128 : 0) | uint256(j) << 64 | e;
    }

    /// The same from the clone's slot.
    function _rKey(bytes32 sid, bytes32 ua, bytes32 k) internal view returns (uint256) {
        (bool g, uint256 j, uint256 e) = ua == 0 ? _goneKey(vchat, sid, k) : _goneOwnKey(vchat, sid, ua, k);
        return (g ? 1 << 128 : 0) | j << 64 | e;
    }

    /// The pages (C36): `treeLeaves` at most 64, `treeNodes` at most 256, a page past the end empty, a page cut at the end;
    /// the caps read on a tree whose `used` and `leaves` are set past them in the clone's slot (the leaves above 4 blank).
    function test_viewPages() public {
        (M memory m,,) = _grown();
        IPqChatTreeViews v = _v();
        assertEq(v.TREE_LEAF_PAGE_MAX(), 64);
        assertEq(v.TREE_RANGE_MAX(), 256);
        assertEq(v.treeLeaves(m.sid, 3, 10).length, 2, "cut at used (5)");
        assertEq(v.treeLeaves(m.sid, 5, 1).length, 0, "at used: empty");
        assertEq(v.treeLeaves(m.sid, type(uint256).max, 1).length, 0, "far past: empty");
        assertEq(v.treeNodes(m.sid, 14, 5).length, 1, "cut at 2 * leaves - 1 (15)");
        assertEq(v.treeNodes(m.sid, 15, 1).length, 0, "at the end: empty");
        assertEq(v.treeNodes(m.sid, type(uint256).max, 1).length, 0, "far past: empty");
        uint256 slot = _t(m.sid) + 3;
        uint256 w = _at(vchat, slot);
        vm.store(address(vchat), bytes32(slot), bytes32(w & ~uint256(2 ** 64 - 1) | 512 << 32 | 300));
        assertEq(v.treeLeaves(m.sid, 0, 1000).length, 64, "treeLeaves capped at 64");
        assertEq(v.treeLeaves(m.sid, 250, 1000).length, 50, "cut at used (300)");
        assertEq(v.treeNodes(m.sid, 0, 1000).length, 256, "treeNodes capped at 256");
        assertEq(v.treeNodes(m.sid, 1000, 1000).length, 23, "cut at 1023");
    }

    /// A flat session and an unknown id: `PqChatModeEntry(0)` and `PqChatUnknown`.
    function test_viewsOfAFlatSession() public {
        (bytes32 sid,) = _newSession(2);
        IPqChatTreeViews v = IPqChatTreeViews(address(chat));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, 0));
        v.treeOf(sid);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, bytes32(uint256(7))));
        v.treeLeaves(bytes32(uint256(7)), 0, 1);
    }

    // ----- through the instance: no write, no value, no other module -----

    /// A view through the instance writes no slot of any account, creates nothing and moves no value; the recording's
    /// positive control, a `treeLeave`, writes.
    function test_viewsChangeNoStorage() public {
        (M memory m, Step memory st, M memory n) = _grown();
        IPqChatTreeViews v = _v();
        vm.startStateDiffRecording();
        v.treeOf(m.sid);
        v.treeLeaves(m.sid, 0, 64);
        v.treeNodes(m.sid, 0, 256);
        v.treeNodeKey(m.sid, n.leaves - 1);
        v.commitOf(st.epochId);
        v.pathListOf(st.epochId);
        v.pathKeys(st.epochId);
        v.pathCtAt(st.epochId, 0);
        v.goneOf(m.sid, B);
        v.goneKeyOf(m.sid, n.kem[0]);
        v.goneOwnKeyOf(m.sid, A, n.kem[0]);
        assertEq(_written(vm.stopAndReturnStateDiff()), 0, "the views write nothing");
        vm.startStateDiffRecording();
        _leaveT(n, B);
        assertGt(_written(vm.stopAndReturnStateDiff()), 0, "the control writes");
    }

    /// Slots written, accounts created or value moved in `d`. Not counted: forge's own CREATE2 of a linked library through
    /// the deterministic deployer, which `isolate = true` records in the window since `OpenFactory` links `OpenFactoryLib`
    /// (G-3's split); a view's static frame can create nothing.
    function _written(VmSafe.AccountAccess[] memory d) internal pure returns (uint256 w) {
        for (uint256 i; i < d.length; ++i) {
            if (d[i].kind == VmSafe.AccountAccessKind.Create && d[i].accessor == CREATE2_FACTORY) continue;
            if (d[i].kind == VmSafe.AccountAccessKind.Create || d[i].value != 0) ++w;
            for (uint256 j; j < d[i].storageAccesses.length; ++j) {
                if (d[i].storageAccesses[j].isWrite) ++w;
            }
        }
    }

    /// Not payable: a view with value, and value with no calldata, refused; a selector nobody has reverts with no data.
    function test_fallbackRefusesValueAndUnknown() public {
        (M memory m,,) = _grown();
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(vchat).call{value: 1}(abi.encodeCall(IPqChatTreeViews.treeOf, (m.sid)));
        assertFalse(ok, "a view with value");
        (ok,) = address(vchat).call{value: 1}("");
        assertFalse(ok, "value alone");
        bytes memory ret;
        (ok, ret) = address(vchat).call(abi.encodeWithSelector(bytes4(0xdeadbeef), m.sid));
        assertFalse(ok, "an unknown selector");
        assertEq(ret.length, 0, "with no data");
        (ok, ret) = address(vchat).call("");
        assertFalse(ok, "no calldata");
        assertEq(ret.length, 0, "with no data");
        (ok,) = address(vchat).call(abi.encodeCall(IPqChatTreeViews.treeOf, (m.sid)));
        assertTrue(ok, "the view itself");
    }

    /// The selectors of `<out>/<file>/<name>.json` (`methodIdentifiers`; `FOUNDRY_OUT` as `PqChatLayout.t.sol` reads it, so a
    /// run with its own output directory, the mutant runner's, reads its own build).
    function _sels(string memory art) internal view returns (bytes4[] memory s) {
        string memory out = vm.envOr("FOUNDRY_OUT", string("out"));
        string[] memory k =
            vm.parseJsonKeys(vm.readFile(string.concat("./", out, "/", art, ".json")), ".methodIdentifiers");
        s = new bytes4[](k.length);
        for (uint256 i; i < k.length; ++i) {
            s[i] = bytes4(keccak256(bytes(k[i])));
        }
    }

    function _in(bytes4[] memory a, bytes4 x) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] == x) return true;
        }
        return false;
    }

    /// The module's selectors are the interface's and `FACTORY()` (which `PqChat` answers itself), none of `PqChat`'s,
    /// `PqChatTopics`' or `PqChatTree`'s: the fallback serves no selector another part handles. Every selector of the two
    /// writing modules that `PqChat` lacks (`treeCreate` among them) reaches neither of them through the instance: it
    /// reverts with no data, nothing written.
    function test_fallbackReachesNoOtherModule() public {
        (M memory m,,) = _grown();
        bytes4[] memory chatS = _sels("PqChat.sol/PqChat");
        bytes4[] memory viewS = _sels("PqChatTreeViews.sol/PqChatTreeViews");
        bytes4[] memory topicS = _sels("PqChatTopics.sol/PqChatTopics");
        bytes4[] memory treeS = _sels("PqChatTree.sol/PqChatTree");
        assertEq(viewS.length, 14, "12 views, 2 caps, FACTORY");
        for (uint256 i; i < viewS.length; ++i) {
            if (viewS[i] == bytes4(keccak256("FACTORY()"))) continue;
            assertFalse(_in(chatS, viewS[i]) || _in(topicS, viewS[i]) || _in(treeS, viewS[i]), "a view of its own");
        }
        assertTrue(
            _in(treeS, PqChatTree.treeCreate.selector) && !_in(chatS, PqChatTree.treeCreate.selector), "treeCreate"
        );
        bytes4[][2] memory writers = [topicS, treeS];
        uint256 tried;
        for (uint256 w; w < 2; ++w) {
            for (uint256 i; i < writers[w].length; ++i) {
                bytes4 s = writers[w][i];
                if (_in(chatS, s)) continue;
                ++tried;
                vm.record();
                (bool ok, bytes memory ret) = address(vchat).call(abi.encodePacked(s, new bytes(1024)));
                (, bytes32[] memory wr) = vm.accesses(address(vchat));
                assertFalse(ok, "a writing module's selector refused");
                assertEq(ret.length, 0, "by the views module: no data");
                assertEq(wr.length, 0, "nothing written");
            }
        }
        assertGt(tried, 0, "treeCreate at least");
        (bool ok2,) = address(vchat).call(abi.encodeCall(IPqChatTreeViews.treeOf, (m.sid)));
        assertTrue(ok2, "a view reached");
    }

    /// The interface ids (pins): `IPqChat`'s unchanged by the views, which have their own; both reported.
    function test_interfaceIdsArePinned() public view {
        assertEq(type(IPqChatTreeViews).interfaceId, bytes4(0xec42e734), "IPqChatTreeViews (new)");
        // the path-less delta (C41-C43, `createSession` and `commit` take the new records): 0x7b7acc12 -> 0x8412b2f1
        assertEq(type(IPqChat).interfaceId, bytes4(0x8412b2f1), "IPqChat (unchanged by the views)");
        assertTrue(chat.supportsInterface(type(IPqChatTreeViews).interfaceId));
        assertTrue(chat.supportsInterface(type(IPqChat).interfaceId));
    }
}
