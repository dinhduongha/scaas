// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqChatTreeViews} from "../../src/pqchat/IPqChatTreeViews.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {MockVerifier} from "../ua/UARegistryBase.sol";
import {PqChatTreeModel} from "./PqChatTreeModel.sol";

/// The positive control's loads: `burn`, regular gas and no state; `fill`, `n` new slots (state gas) for little regular gas.
contract TreeGasBurner {
    mapping(uint256 => uint256) internal m;

    function burn(uint256 n) external pure returns (uint256 y) {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(0, y)
                y := keccak256(0, 32)
            }
        }
    }

    function fill(uint256 n) external {
        for (uint256 i; i < n; ++i) {
            m[i] = 1;
        }
    }
}

/// Spec 2026-11-23-pqchat-treekem §13 measured (plan T3c/T3d): each piece of a tree session and of its commits as its own
/// transaction (`isolate = true`), on trees the test builds through the entries themselves, each asserted against EIP-7825
/// (regular < 2^24) and the EIP-8037 inclusion rule ((regular + state) x 1.05 within a 60 M block), the rows the spec
/// expects over the line asserted over it and logged with their figures. Signatures: the stand-in verifier accepts every
/// signature, sent at its real size (ML-DSA-65 3,309 B, ML-DSA-87 4,627 B; kept at the `sstore2` home), and the verify's
/// own regular gas is added from `docs/contracts/accounts.md`: the `mldsa65` cache's cap 5,950,000 and the `mldsa87`
/// cache's 8,860,000 (controller call: an ML-DSA-87 row is the ML-DSA-65 author's record with a 4,627-B signature and the
/// ML-DSA-87 verify). The completion fixtures count their new slots in the clone's state diff (spec's table, codex-r3-6).
/// The rows run without `--enable-tx-gas-limit` and assert regular < 2^24 each (spec §13: forge does not enforce 2^24 by
/// default): forge 1.8.5's flag holds a transaction's whole gas, state gas included, to 2^24, where EIP-8037 holds only its
/// regular gas there, so under the flag every row above 2^24 of state fails for a reason no chain has (the positive control
/// `PqChatTreeGasCapTest`, run with the flag and `TREE_GAS_CAP=1`, shows both: the cap is in force, and it takes state gas).
/// **UNAUDITED.**
contract PqChatTreeGasTest is PqChatTreeModel {
    using stdJson for string;

    uint256 internal constant CAP = 1 << 24;
    uint256 internal constant BLOCK = 60_000_000;
    uint256 internal constant SIG65 = 3309;
    uint256 internal constant SIG87 = 4627;
    uint256 internal constant VERIFY65 = 5_950_000;
    uint256 internal constant VERIFY87 = 8_860_000;
    /// Pieces per transaction of the fixtures: 16 ciphertexts ask about 46 M, 12 wraps about 45 M.
    uint256 internal constant CT_PER = 16;
    uint256 internal constant WRAP_PER = 12;

    uint8 internal seedN = 100;

    /// The completion pins (new, T3d): state exact, regular within `SLACK`; a move needs old -> new figures in its commit.
    uint256 internal constant SLACK = 2_000;
    uint256 internal constant FIXTURE_REGULAR = 8_110_908;
    uint256 internal constant FIXTURE_STATE = 25_032_330; // the spec's 25,030,800 + 1 B
    uint256 internal constant BOUND_REGULAR = 10_657_386;
    uint256 internal constant BOUND_STATE = 37_272_330; // the spec's 37,270,800 + 1 B

    function _pin(uint256 r, uint256 s, uint256 pr, uint256 ps, string memory what) internal {
        if (vm.envOr("GAS_MEASURE", false)) return;
        assertApproxEqAbs(r, pr, SLACK, string.concat(what, " regular (pin)"));
        assertEq(s, ps, string.concat(what, " state (pin)"));
    }

    function setUp() public override {
        super.setUp();
        vm.mockCall(address(mock), abi.encodeWithSelector(MockVerifier.verify.selector), abi.encode(true));
        vm.mockCall(address(mock), abi.encodeWithSelector(MockVerifier.verifyPop.selector), abi.encode(true));
    }

    // ----- rows -----

    /// The last call's regular and state gas, logged.
    function _row(string memory what) internal returns (uint256 r, uint256 s) {
        Vm.Gas memory g = vm.lastCallGas();
        (r, s) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
        emit log_named_uint(string.concat("GAS ", what, " regular"), r);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        emit log_named_uint(string.concat("GAS ", what, " asked x 1.05"), (r + s) * 105 / 100);
    }

    /// `_row` with `extra` regular gas (a verify), asserted to fit: regular < 2^24, asked within the block.
    function _fits(string memory what, uint256 extra) internal returns (uint256 r, uint256 s) {
        (r, s) = _row(what);
        r += extra;
        if (extra != 0) emit log_named_uint(string.concat("GAS ", what, " regular with the verify"), r);
        assertLt(r, CAP, string.concat(what, ": regular under 2^24"));
        assertLe((r + s) * 105 / 100, BLOCK, string.concat(what, ": asked within a 60 M block"));
    }

    function _sized(uint256 len) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(len);
        for (uint256 i; i < len; ++i) {
            s.signature[i] = bytes1(uint8(i * 31 + 7));
        }
    }

    // ----- people and sessions -----

    /// `n` new UAs (sorted), each with KEM versions `1..keys` (admitted keys, `pk_X` apart).
    function _people(uint256 n, uint64 keys) internal returns (bytes32[] memory u) {
        u = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            u[i] = _member(seedN++);
            for (uint64 v = 1; v <= keys; ++v) {
                _setKem(u[i], v, _variant("A", uint256(u[i]) + v));
            }
        }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && u[j - 1] > u[j]; --j) {
                (u[j - 1], u[j]) = (u[j], u[j - 1]);
            }
        }
    }

    function _keysOf(bytes32[] memory u, uint64 keys) internal pure returns (IPqChat.MemberKey[] memory mk) {
        mk = new IPqChat.MemberKey[](u.length * keys);
        for (uint256 i; i < u.length; ++i) {
            for (uint64 v = 1; v <= keys; ++v) {
                mk[i * keys + v - 1] = _mk(u[i], v);
            }
        }
    }

    /// The record of a tree session of `members` with `admins`, sent alone (a row; over the block when `fits` is false).
    function _sessionRecord(IPqChat.MemberKey[] memory members, bytes32[] memory admins, bool fits)
        internal
        returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) =
        (members[0].ua, ++nonceN, _j().readBytes32(".scenarios[0].genesis.record.homeChain"), address(vchat));
        (s.admins, s.members, s.groupMode, s.sealedInfo) = (admins, members, 1, hex"5ea1");
        w = _wraps(members, PqChatTypes.sessionId(s.creator, s.nonce));
        s.wrapHashes = _hashes(w);
        vchat.createSession(s, new IPqChat.Wrap[](0), _sized(SIG65));
        string memory what = string.concat("the session record, ", vm.toString(members.length), " member keys");
        if (fits) {
            _fits(what, VERIFY65);
        } else {
            (uint256 r, uint256 st) = _row(what);
            assertGt(
                (r + VERIFY65 + st) * 105 / 100, BLOCK, string.concat(what, ": over a 60 M block, as the spec says")
            );
        }
    }

    /// A tree session: its record (`_sessionRecord`), then its wraps `WRAP_PER` a transaction; the model of its tree.
    function _session(IPqChat.MemberKey[] memory members, bytes32[] memory admins, bool fits)
        internal
        returns (M memory m)
    {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionRecord(members, admins, fits);
        m.sid = PqChatTypes.sessionId(s.creator, s.nonce);
        for (uint256 i; i < w.length; i += WRAP_PER) {
            uint256 to = i + WRAP_PER < w.length ? i + WRAP_PER : w.length;
            vchat.addWraps(m.sid, uint32(i), _slice(w, i, to));
        }
        assertTrue(vchat.epochComplete(m.sid), "the session complete");
        (m.treeId, m.head, m.used) = (th2.sessionHash(s), m.sid, members.length);
        m.leaves = 1;
        while (m.leaves < m.used) m.leaves <<= 1;
        (m.ua, m.kid, m.kem, m.live, m.key) =
        (new bytes32[](256), new uint64[](256), new bytes32[](256), new bool[](256), new bytes32[](511));
        for (uint256 i; i < members.length; ++i) {
            (m.ua[i], m.kid[i], m.kem[i], m.live[i]) =
            (members[i].ua, members[i].keyId, _kemHash(members[i].ua, members[i].keyId), true);
        }
        assertEq(_root(vchat, m.sid), _mRoot(m), "the model's genesis root");
    }

    // ----- a commit in pieces (C37) -----

    function _record(Step memory st, uint256 sigLen) internal {
        vchat.commit(
            st.c,
            new uint32[](0),
            new bytes32[](0),
            new bytes[](0),
            new IPqChat.PathCt[](0),
            new IPqChat.Wrap[](0),
            _sized(sigLen)
        );
    }

    function _cts(Step memory st, uint256 from, uint256 to) internal {
        IPqChat.PathCt[] memory c = new IPqChat.PathCt[](to - from);
        for (uint256 i; i < c.length; ++i) {
            c[i] = st.cts[from + i];
        }
        vchat.addPath(st.epochId, uint32(from), c);
    }

    function _list(Step memory st) internal {
        vchat.addPathList(st.epochId, st.ctTargets, st.ctHashes);
    }

    function _keys(Step memory st) internal {
        vchat.addPathKeys(st.epochId, st.nodeKeys);
    }

    /// Every ciphertext from `from` but the last, `CT_PER` a transaction, then the Welcome wraps.
    function _middle(Step memory st, uint256 from) internal {
        uint256 n = st.cts.length;
        for (uint256 i = from; i + 1 < n; i += CT_PER) {
            _cts(st, i, i + CT_PER < n - 1 ? i + CT_PER : n - 1);
        }
        for (uint256 i; i < st.wraps.length; i += WRAP_PER) {
            uint256 to = i + WRAP_PER < st.wraps.length ? i + WRAP_PER : st.wraps.length;
            vchat.addWraps(st.epochId, uint32(i), _slice(st.wraps, i, to));
        }
    }

    /// The record, the list, the node keys, the middle, the held ciphertext: the commit landed in the order of C37.
    function _landPieces(Step memory st, M memory n, M memory m) internal returns (M memory) {
        ++nonceN;
        _record(st, SIG65);
        if (st.c.ctCount != 0) {
            _list(st);
            if (st.nodeKeys.length != 0) _keys(st);
            _middle(st, 0);
            _cts(st, st.cts.length - 1, st.cts.length);
        }
        assertTrue(vchat.epochComplete(st.epochId), "complete");
        assertEq(_root(vchat, m.sid), _mRoot(n), "stored root is the model's");
        return n;
    }

    /// Slots of `a` that the diff takes from zero to non-zero (each once: its first previous value, its last new one).
    function _freshSlots(VmSafe.AccountAccess[] memory d, address a) internal pure returns (uint256 fresh) {
        bytes32[] memory slot = new bytes32[](4096);
        bool[] memory wasZero = new bool[](4096);
        bool[] memory isSet = new bool[](4096);
        uint256 k;
        for (uint256 i; i < d.length; ++i) {
            for (uint256 j; j < d[i].storageAccesses.length; ++j) {
                VmSafe.StorageAccess memory sa = d[i].storageAccesses[j];
                if (sa.account != a || !sa.isWrite || sa.reverted) continue;
                uint256 at = k;
                for (uint256 q; q < k; ++q) {
                    if (slot[q] == sa.slot) at = q;
                }
                if (at == k) (slot[k], wasZero[k], k) = (sa.slot, sa.previousValue == 0, k + 1);
                isSet[at] = sa.newValue != 0;
            }
        }
        for (uint256 q; q < k; ++q) {
            if (wasZero[q] && isSet[q]) ++fresh;
        }
    }

    /// The held ciphertext alone with the completion: a row, its new slots in the clone counted.
    function _completion(Step memory st, string memory what) internal returns (uint256 fresh, uint256 r, uint256 s) {
        vm.startStateDiffRecording();
        _cts(st, st.cts.length - 1, st.cts.length);
        (r, s) = _fits(what, 0);
        fresh = _freshSlots(vm.stopAndReturnStateDiff(), address(vchat));
        emit log_named_uint(string.concat("SLOTS ", what), fresh);
        assertTrue(vchat.epochComplete(st.epochId), "complete");
    }

    function _addsTo(bytes32[] memory uas, uint32[] memory leaves) internal pure returns (Ch[] memory c) {
        c = new Ch[](uas.length);
        for (uint256 i; i < uas.length; ++i) {
            c[i] = Ch(true, leaves[i], uas[i], 1);
        }
    }

    /// The Removes of every key `1..keys` of `uas[from..to)`, at their leaves in `m`.
    function _removesOf(M memory m, bytes32[] memory uas, uint256 from, uint256 to)
        internal
        pure
        returns (Ch[] memory c)
    {
        uint256 n;
        for (uint256 i; i < m.used; ++i) {
            for (uint256 j = from; j < to; ++j) {
                if (m.live[i] && m.ua[i] == uas[j]) ++n;
            }
        }
        c = new Ch[](n);
        n = 0;
        for (uint256 i; i < m.used; ++i) {
            for (uint256 j = from; j < to; ++j) {
                if (m.live[i] && m.ua[i] == uas[j]) c[n++] = Ch(false, uint32(i), m.ua[i], m.kid[i]);
            }
        }
    }

    // ----- the completion fixtures (codex-r3-6) -----

    /// codex-r3-6's fixture: a full tree of 32 keys (4 UAs x 8) whose author's path is warm grows to 64 by 32 Adds of UAs
    /// with no session; the held ciphertext's transaction completes it: the spec's 227 new slots (192 for the leaves and
    /// the index, 32 parent hashes, the new root's `keyAt`, `childOf` and `epochsOf`) and the ciphertext's own slot. Then
    /// `treeLeave` and `treeRemove` with their `gone` slots.
    function test_completionFixture32To64() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(4, 8);
        M memory m = _session(_keysOf(p, 8), _list(p[0]), true);
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(p[0])); // the author's path made warm
        m = _landPieces(st, n, m);
        bytes32[] memory q = _people(32, 1);
        uint32[] memory at = new uint32[](32);
        for (uint256 i; i < 32; ++i) {
            at[i] = uint32(32 + i);
        }
        (st, n) = _build(m, 0, _addsTo(q, at), _list(p[0]));
        ++nonceN;
        _record(st, SIG65);
        _fits("commit record, 32 Adds on a tree of 32", VERIFY65);
        _list(st);
        _keys(st);
        _middle(st, 0);
        (uint256 fresh, uint256 cr, uint256 cs) =
            _completion(st, "completion with the held ciphertext, 32 -> 64 keys (codex-r3-6)");
        assertEq(fresh, 227 + 1, "the spec's 227 new slots and the ciphertext's own");
        _pin(cr, cs, FIXTURE_REGULAR, FIXTURE_STATE, "the fixture's completion");
        assertEq(_root(vchat, m.sid), _mRoot(n), "stored root is the model's");
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(m.sid, m.treeId, n.head, p[1], ++nonceN);
        vchat.treeLeave(l, _sized(SIG65));
        _fits("treeLeave with its gone slot", VERIFY65);
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, n.head, n.epoch + 1, _list(q[0]), p[0], ++nonceN);
        vchat.treeRemove(r, _sized(SIG65));
        _fits("treeRemove of one UA with its gone slot", VERIFY65);
    }

    /// The bound (codex-r3-6) and every piece at 256 keys: a session of 256 keys (32 UAs x 8; its record over a 60 M block,
    /// as the spec says), the four `treeLeaves` pages, a cold commit (its record with the tree check on a cold tree of 256,
    /// the list of 255 targets, the node keys of depth 8, one ciphertext; then undone), the reachability of fable-3 (`treeRemove`s to
    /// `owed` = 32, then the next commit's pieces, each fitting, in the order of C37), the removals down to one live leaf
    /// (the last of them the commit of the last live leaf at its bounds, one transaction), then 32 Adds of UAs with no
    /// session in 32 subtrees of 8, the admins 1 -> 32, 4,124 B of info: the record at its bounds, the node keys as the
    /// last piece (over the block, C37), and the completion with the held ciphertext: the spec's 352 new slots and the
    /// ciphertext's own.
    function test_completionAtTheBound() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(32, 8);
        M memory m = _session(_keysOf(p, 8), _list(p[0]), false);
        _pages(m);
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(p[0]));
        uint256 snap = vm.snapshotState(); // the cold commit's pieces measured, then undone (the test's gas)
        _record(st, SIG65);
        _fits("commit record, plain, the tree check on a cold tree of 256", VERIFY65);
        _list(st);
        _fits("the list of a cold commit, 255 targets", 0);
        _keys(st);
        _fits("the node keys, depth 8", 0);
        _cts(st, 0, 1);
        _fits("one ciphertext in addPath", 0);
        vm.revertToState(snap);
        m = _reach(m, p);
        for (uint256 g = 5; g < 25; g += 4) {
            (st, n) = _build(m, 0, _removesOf(m, p, g, g + 4), _list(p[0]));
            m = _landPieces(st, n, m);
        }
        m = _lastLeaf(m, p);
        _bound(m, p);
    }

    /// fable-3: `treeRemove` of four UAs (32 leaves owed), then the next commit, 32 forced Removes and the path to the 223
    /// live leaves left; each piece fits, sent in the order of C37.
    function _reach(M memory m, bytes32[] memory p) internal returns (M memory) {
        bytes32[] memory four = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            four[i] = p[1 + i];
        }
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, four, p[0], ++nonceN);
        vchat.treeRemove(r, _sized(SIG65));
        _fits("treeRemove of four UAs (32 leaves owed)", VERIFY65);
        (Step memory st, M memory n) = _build(m, 0, _removesOf(m, p, 1, 5), _list(p[0]));
        assertEq(st.c.removes.length, 32, "the owed leaves");
        ++nonceN;
        _record(st, SIG65);
        _fits("reachability: the record, 32 forced Removes", VERIFY65);
        _list(st);
        _fits("reachability: the list", 0);
        _keys(st);
        _fits("reachability: the node keys", 0);
        uint256 k = st.cts.length;
        for (uint256 i; i + 1 < k; i += CT_PER) {
            _cts(st, i, i + CT_PER < k - 1 ? i + CT_PER : k - 1);
            _fits("reachability: a chunk of ciphertexts", 0);
        }
        _cts(st, k - 1, k);
        _fits("reachability: the held ciphertext with the completion", 0);
        assertTrue(vchat.epochComplete(st.epochId), "complete");
        return n;
    }

    /// The author's own seven other keys and three UAs, then the commit of the last live leaf at its bounds: 32 Removes
    /// that evict four UAs by the commit alone (their `gone` and `goneKey` slots), 4,124 B of info; no piece, so one
    /// transaction, with ML-DSA-65 and with ML-DSA-87.
    function _lastLeaf(M memory m, bytes32[] memory p) internal returns (M memory) {
        Ch[] memory three = _removesOf(m, p, 25, 28);
        Ch[] memory c = new Ch[](three.length + 7);
        for (uint256 i; i < 7; ++i) {
            c[i] = Ch(false, uint32(1 + i), p[0], uint64(2 + i));
        }
        for (uint256 i; i < three.length; ++i) {
            c[7 + i] = three[i];
        }
        (Step memory st, M memory n) = _build(m, 0, c, _list(p[0]));
        m = _landPieces(st, n, m);
        (st, n) = _build(m, 0, _removesOf(m, p, 28, 32), _list(p[0]));
        st.c.sealedInfo = new bytes(4124);
        assertEq(st.c.ctCount + st.nodeKeys.length, 0, "no piece");
        ++nonceN;
        uint256 snap = vm.snapshotState();
        _record(st, SIG87);
        _fits("the commit of the last live leaf at its bounds, ML-DSA-87, one transaction", VERIFY87);
        vm.revertToState(snap);
        _record(st, SIG65);
        _fits("the commit of the last live leaf at its bounds, ML-DSA-65, one transaction", VERIFY65);
        assertTrue(vchat.epochComplete(st.epochId), "complete in the one transaction");
        return n;
    }

    /// The bound: 32 Adds of UAs with no session in 32 subtrees of 8 of the tree of 256 with one live leaf, the admins
    /// 1 -> 32, 4,124 B of info, the author's path blank.
    function _bound(M memory m, bytes32[] memory p) internal {
        bytes32[] memory q = _people(32, 1);
        uint32[] memory at = new uint32[](32);
        at[0] = 4; // in the author's subtree of 8, not its sibling: the spec's layout (6 keyAt, 121 parent hashes)
        for (uint256 i = 1; i < 32; ++i) {
            at[i] = uint32(8 * i);
        }
        bytes32[] memory admins = new bytes32[](32);
        admins[0] = p[0];
        for (uint256 i = 1; i < 32; ++i) {
            admins[i] = q[i - 1];
        }
        for (uint256 i = 1; i < 32; ++i) {
            for (uint256 j = i; j > 0 && admins[j - 1] > admins[j]; --j) {
                (admins[j - 1], admins[j]) = (admins[j], admins[j - 1]);
            }
        }
        (Step memory st, M memory n) = _build(m, 0, _addsTo(q, at), admins);
        st.c.sealedInfo = new bytes(4124);
        assertEq(st.c.ctCount, 32, "one ciphertext per Add");
        assertEq(st.nodeKeys.length, 6, "six node keys");
        ++nonceN;
        (uint256 r65, uint256 r87) = _boundRecord(st);
        _list(st);
        _fits("the list at the bound, 32 targets", 0);
        _keysLast(st);
        _keys(st);
        _fits("the node keys at the bound, six", 0);
        _middle(st, 0);
        (uint256 fresh, uint256 rc, uint256 sc) = _completion(st, "completion at its bounds with the held ciphertext");
        assertEq(fresh, 352 + 1, "the spec's 352 new slots and the ciphertext's own");
        _pin(rc, sc, BOUND_REGULAR, BOUND_STATE, "the completion at its bounds");
        assertEq(_root(vchat, m.sid), _mRoot(n), "stored root is the model's");
        emit log_named_uint("GAS acceptance and completion in one transaction, ML-DSA-65, regular", r65 + rc);
        emit log_named_uint("GAS acceptance and completion in one transaction, ML-DSA-87, regular", r87 + rc);
        assertGt(r65 + rc, CAP, "over 2^24: the record goes alone (spec s13)");
    }

    /// The record at its bounds with ML-DSA-87 (then undone) and with ML-DSA-65; their regular gas with the verify.
    function _boundRecord(Step memory st) internal returns (uint256 r65, uint256 r87) {
        uint256 snap = vm.snapshotState();
        _record(st, SIG87);
        (r87,) = _fits("commit record at its bounds, ML-DSA-87", VERIFY87);
        vm.revertToState(snap);
        _record(st, SIG65);
        (r65,) = _fits("commit record at its bounds, ML-DSA-65", VERIFY65);
    }

    /// C37's counter-case, then undone: every other piece first and the node keys last, which then pay the completion.
    function _keysLast(Step memory st) internal {
        uint256 snap = vm.snapshotState();
        _middle(st, 0);
        _cts(st, st.cts.length - 1, st.cts.length);
        _keys(st);
        (uint256 r, uint256 s) = _row("the node keys as the last piece at the bound (C37: not this order)");
        assertGt((r + s) * 105 / 100, BLOCK, "over a 60 M block, as the spec says");
        vm.revertToState(snap);
    }

    /// The four `treeLeaves` pages of the full tree at one block (fable-r2-U1): each 64 leaves of versions above 0, under
    /// 4 M (the plan's line) and 2^24 (Nethermind's `eth_call` cap).
    function _pages(M memory m) internal {
        IPqChatTreeViews v = IPqChatTreeViews(address(vchat));
        uint256 sum;
        for (uint256 k; k < 4; ++k) {
            assertEq(v.treeLeaves(m.sid, 64 * k, 64).length, 64, "a full page");
            (uint256 r,) = _row(string.concat("treeLeaves page ", vm.toString(k), ", 64 leaves"));
            assertLt(r, 4_000_000, "a page under 4 M");
            sum += r;
        }
        emit log_named_uint("GAS treeLeaves, the full tree in four calls", sum);
    }

    /// The session records at 64, 128 and 192 member keys fit; 15 genesis wraps in one transaction.
    function test_sessionRecords() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(24, 8);
        IPqChat.MemberKey[] memory all = _keysOf(p, 8);
        for (uint256 k = 64; k <= 192; k += 64) {
            IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](k);
            for (uint256 i; i < k; ++i) {
                mk[i] = all[i];
            }
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionRecord(mk, _list(p[0]), true);
            if (k == 64) {
                vchat.addWraps(PqChatTypes.sessionId(s.creator, s.nonce), 0, _slice(w, 0, 15));
                _fits("15 genesis wraps in one transaction", 0);
            }
        }
    }
}

/// The positive control of the cap, apart from the rows' world (whose setUp deploys more than 2^24 of gas, state included,
/// in one transaction). **UNAUDITED.**
contract PqChatTreeGasCapTest is Test {
    /// Under `--enable-tx-gas-limit` (the gate sets `TREE_GAS_CAP=1`): a call of more than 2^24 regular gas fails, so the cap
    /// is in force; and a call of about 2.9 M regular and 24.5 M state gas (250 new slots) fails too, so forge's flag takes
    /// state gas into the cap, which EIP-8037 does not: why the rows run without it. Without the variable it is skipped.
    function test_txCapInForce() public {
        vm.skip(!vm.envOr("TREE_GAS_CAP", false));
        TreeGasBurner b = new TreeGasBurner();
        (bool ok,) = address(b).call{gas: 1_000_000}(abi.encodeCall(TreeGasBurner.burn, (500)));
        assertTrue(ok, "a small call passes");
        (ok,) = address(b).call(abi.encodeCall(TreeGasBurner.burn, (300_000)));
        assertFalse(ok, "a call over 2^24 of regular gas fails: the cap is in force");
        (ok,) = address(b).call(abi.encodeCall(TreeGasBurner.fill, (250)));
        assertFalse(ok, "state gas counted into forge's cap");
    }
}
