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

    /// One transaction of `n` hash rounds and `k` new slots under `salt`: a row's (regular, state) pair, for the 2^24
    /// measurement on a Nethermind copy (`runs/2026-11-25-treekem512-nethermind.py`).
    function burnFill(uint256 n, uint256 k, uint256 salt) external returns (uint256 y) {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(0, y)
                y := keccak256(0, 32)
            }
        }
        for (uint256 i; i < k; ++i) {
            m[uint256(keccak256(abi.encode(salt, i)))] = 1;
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

    /// C10 (owner 2026-11-25: 32 -> 20): adds plus removes per commit, and the leaves a head may owe (C21).
    uint256 internal constant CHANGES = 20;

    uint8 internal seedN = 10; // above the base world's seeds 1-5

    /// The completion pins (new, T3d): state exact, regular within `SLACK`; a move needs old -> new figures in its commit.
    uint256 internal constant SLACK = 2_000;
    /// C10 32 -> 20 (owner 2026-11-25): 20 Adds, leaves 32-51. Old -> new: regular 8,110,908 -> 5,285,585, state
    /// 25,032,330 -> 17,002,890, new slots 227 -> 145.
    uint256 internal constant FIXTURE_REGULAR = 5_285_585;
    uint256 internal constant FIXTURE_STATE = 17_002_890;
    uint256 internal constant FIXTURE_SLOTS = 145;
    /// The bound on a tree of 512 (R8) at 20 changes (C10, owner 2026-11-25), 20 Adds spread over 20 subtrees of 16 and 16
    /// of 32. Old -> new: at 256 and 32 changes regular 10,657,386, state 37,272,330, 352 slots; at 512 and 32 changes
    /// 11,623,478, 40,405,770, 384; at 512 and 20 changes 7,960,311, 28,655,370 (asked x 1.05 38.4 M), 264 slots.
    uint256 internal constant BOUND_REGULAR = 7_960_311;
    uint256 internal constant BOUND_STATE = 28_655_370;
    uint256 internal constant BOUND_SLOTS = 264;
    /// A-8: the last live leaf at the spec's bound, the verify's regular gas included, on a tree of 512 at 20 changes (C10,
    /// owner 2026-11-25). Old -> new: the first pin (32 changes, a tree of 64 leaves, which understated the bound: the
    /// layout was over 2^24 already on a tree of 256, 17,322,116) ML-DSA-87 15,588,376 / 31,716,900, ML-DSA-65 12,637,463
    /// / 29,709,540; at 512 and 32 changes ML-DSA-87 18,087,866 (over 2^24) / 31,521,060, ML-DSA-65 15,130,972 /
    /// 29,513,700; at 512 and 20 changes ML-DSA-87 15,782,531 (994,685 under 2^24) / 27,408,420, ML-DSA-65 12,829,777 /
    /// 25,401,060.
    uint256 internal constant LAST87_REGULAR = 15_782_531;
    uint256 internal constant LAST65_REGULAR = 12_829_777;
    uint256 internal constant LAST87_STATE = 27_408_420;
    uint256 internal constant LAST65_STATE = 25_401_060;
    /// A-17 (the re-review of 2026-11-25), new pins: A-8's row on the worst head (32 admins replaced, the live leaves at
    /// positions 12 to 499 of 512), the verify included: ML-DSA-87 16,158,289 (618,927 under 2^24; the light head's
    /// 15,782,531 + 375,758) / 24,372,900, ML-DSA-65 13,205,502 / 22,365,540; the closing `treeRemove` (an ML-DSA-87
    /// keyless admin, 512 positions scanned) 10,518,373 / 8,656,740.
    uint256 internal constant WORST87_REGULAR = 16_158_289;
    uint256 internal constant WORST65_REGULAR = 13_205_502;
    uint256 internal constant WORST87_STATE = 24_372_900;
    uint256 internal constant WORST65_STATE = 22_365_540;
    uint256 internal constant CLOSE87_REGULAR = 10_518_373;
    uint256 internal constant CLOSE87_STATE = 8_656_740;

    /// Gas metering off for calls that are no row (the test's own gas stays under the suite's 2^33), nested.
    uint256 internal pauses;

    function _pause() internal {
        if (pauses++ == 0) vm.pauseGasMetering();
    }

    function _resume() internal {
        if (--pauses == 0) vm.resumeGasMetering();
    }

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
        _pause(); // the wraps: no row
        for (uint256 i; i < w.length; i += WRAP_PER) {
            uint256 to = i + WRAP_PER < w.length ? i + WRAP_PER : w.length;
            vchat.addWraps(m.sid, uint32(i), _slice(w, i, to));
        }
        _resume();
        assertTrue(vchat.epochComplete(m.sid), "the session complete");
        (m.treeId, m.head, m.used) = (th2.sessionHash(s), m.sid, members.length);
        m.leaves = 1;
        while (m.leaves < m.used) m.leaves <<= 1;
        (m.ua, m.kid, m.kem, m.live, m.key) =
        (
            new bytes32[](MODEL_LEAVES),
            new uint64[](MODEL_LEAVES),
            new bytes32[](MODEL_LEAVES),
            new bool[](MODEL_LEAVES),
            new bytes32[](MODEL_NODES)
        );
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
        _pause();
        uint256 n = st.cts.length;
        for (uint256 i = from; i + 1 < n; i += CT_PER) {
            _cts(st, i, i + CT_PER < n - 1 ? i + CT_PER : n - 1);
        }
        for (uint256 i; i < st.wraps.length; i += WRAP_PER) {
            uint256 to = i + WRAP_PER < st.wraps.length ? i + WRAP_PER : st.wraps.length;
            vchat.addWraps(st.epochId, uint32(i), _slice(st.wraps, i, to));
        }
        _resume();
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

    /// codex-r3-6's fixture at C10's bound of 20 (owner 2026-11-25): a full tree of 32 keys (4 UAs x 8) whose author's path
    /// is warm grows to 64 by 20 Adds of UAs with no session (leaves 32-51); the held ciphertext's transaction completes it:
    /// its new slots (`FIXTURE_SLOTS`: the leaves and the index, the parent hashes of the new subtree and the new root, the
    /// new root's `keyAt`, `childOf` and `epochsOf`) and the ciphertext's own slot. Then `treeLeave` and `treeRemove` with
    /// their `gone` slots.
    function test_completionFixture32To64() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(4, 8);
        M memory m = _session(_keysOf(p, 8), _list(p[0]), true);
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(p[0])); // the author's path made warm
        m = _landPieces(st, n, m);
        bytes32[] memory q = _people(CHANGES, 1);
        uint32[] memory at = new uint32[](CHANGES);
        for (uint256 i; i < CHANGES; ++i) {
            at[i] = uint32(32 + i);
        }
        (st, n) = _build(m, 0, _addsTo(q, at), _list(p[0]));
        ++nonceN;
        _record(st, SIG65);
        _fits("commit record, 20 Adds on a tree of 32", VERIFY65);
        _list(st);
        _keys(st);
        _middle(st, 0);
        (uint256 fresh, uint256 cr, uint256 cs) =
            _completion(st, "completion with the held ciphertext, 32 -> 52 keys (codex-r3-6)");
        assertEq(fresh, FIXTURE_SLOTS + 1, "the fixture's new slots and the ciphertext's own");
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

    /// The bound (codex-r3-6) and every piece at 512 keys (R8, owner 2026-11-25: 256 -> 512, depth 9) and 20 changes (C10,
    /// owner 2026-11-25: 32 -> 20): a session of 512 keys (128 UAs x 4; its record over a 60 M block, as the spec says), the
    /// eight `treeLeaves` pages, a cold commit (its record with the tree check on a cold tree of 512, the list of 511
    /// targets, the node keys of depth 9, one ciphertext; then undone), the reachability of fable-3 (`treeRemove`s to
    /// `owed` = 20, then the next commit's pieces, each fitting, in the order of C37), the removals down to one live leaf
    /// (the last of them the commit of the last live leaf at its bounds, one transaction), then 20 Adds of UAs with no
    /// session spread over the tree (20 different subtrees of 16, 16 different subtrees of 32), the admins 1 -> 32, 4,124 B
    /// of info: the record at its bounds, the node keys as the last piece (over the block, C37), and the completion with
    /// the held ciphertext: its new slots (`BOUND_SLOTS`) and the ciphertext's own. The removals send thousands of
    /// ciphertexts, past the suite's 2^33 of gas for one test: their commits (no row) run with gas metering paused.
    function test_completionAtTheBound() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(128, 4);
        M memory m = _session(_keysOf(p, 4), _list(p[0]), false);
        _pages(m);
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(p[0]));
        uint256 snap = vm.snapshotState(); // the cold commit's pieces measured, then undone (the test's gas)
        _record(st, SIG65);
        _fits("commit record, plain, the tree check on a cold tree of 512", VERIFY65);
        _list(st);
        assertEq(st.ctTargets.length, 511, "511 targets");
        _fits("the list of a cold commit, 511 targets", 0);
        _keys(st);
        assertEq(st.nodeKeys.length, 9, "depth 9");
        _fits("the node keys, depth 9", 0);
        _cts(st, 0, 1);
        _fits("one ciphertext in addPath", 0);
        vm.revertToState(snap);
        m = _reach(m, p);
        uint256 z = p.length;
        _pause();
        for (uint256 g = 6; g < z - 9; g += 5) {
            (st, n) = _build(m, 0, _removesOf(m, p, g, g + 5 < z - 9 ? g + 5 : z - 9), _list(p[0]));
            m = _landPieces(st, n, m);
        }
        _resume();
        m = _lastLeaf(m, p);
        _bound(m, p);
    }

    /// fable-3: `treeRemove` of five UAs of 4 keys (20 leaves owed), then the next commit, 20 forced Removes and the path to
    /// the 491 live leaves left; each piece fits, sent in the order of C37.
    function _reach(M memory m, bytes32[] memory p) internal returns (M memory) {
        bytes32[] memory five = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            five[i] = p[1 + i];
        }
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, five, p[0], ++nonceN);
        vchat.treeRemove(r, _sized(SIG65));
        _fits("treeRemove of five UAs (20 leaves owed)", VERIFY65);
        (Step memory st, M memory n) = _build(m, 0, _removesOf(m, p, 1, 6), _list(p[0]));
        assertEq(st.c.removes.length, CHANGES, "the owed leaves");
        ++nonceN;
        _record(st, SIG65);
        _fits("reachability: the record, 20 forced Removes", VERIFY65);
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

    /// The author's own three other keys and four UAs, then the commit of the last live leaf at its bounds: 20 Removes that
    /// evict the last five UAs by the commit alone (their `gone` and `goneKey` slots), 4,124 B of info; no piece, so one
    /// transaction, with ML-DSA-65 and with ML-DSA-87.
    function _lastLeaf(M memory m, bytes32[] memory p) internal returns (M memory) {
        uint256 z = p.length;
        Ch[] memory four = _removesOf(m, p, z - 9, z - 5);
        Ch[] memory c = new Ch[](four.length + 3);
        for (uint256 i; i < 3; ++i) {
            c[i] = Ch(false, uint32(1 + i), p[0], uint64(2 + i));
        }
        for (uint256 i; i < four.length; ++i) {
            c[3 + i] = four[i];
        }
        (Step memory st, M memory n) = _build(m, 0, c, _list(p[0]));
        _pause(); // no row
        m = _landPieces(st, n, m);
        _resume();
        (st, n) = _build(m, 0, _removesOf(m, p, z - 5, z), _list(p[0]));
        assertEq(st.c.removes.length, CHANGES, "at the bound");
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

    /// A-8 (spec §13's row): the commit of the last live leaf at its bounds, one transaction, on a tree of 512 (R8, depth
    /// 9) at C10's 20 changes (owner 2026-11-25): 20 Removes that evict 20 UAs of one key each by the commit alone (20
    /// `gone` and 20 `goneKey` slots), the admins 1 -> 32 (the author and 31 registered UAs with no leaf), 4,124 B of info,
    /// no piece; ML-DSA-65 and ML-DSA-87, pinned, each under 2^24. The tree: the 21 UAs and 60 of 4 keys (261 keys, so 512
    /// leaf positions), the 60 removed first, five a commit.
    function test_lastLiveLeafAtTheSpecBound() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory p = _people(CHANGES + 1, 1);
        bytes32[] memory f = _people(60, 4);
        IPqChat.MemberKey[] memory mk = _merged(p, f, 4);
        // the creator is the first member (`_sessionRecord`), an admin beside the author; the first commit drops it
        bytes32 c0 = mk[0].ua;
        M memory m = _session(mk, c0 == p[0] ? _list(p[0]) : c0 < p[0] ? _list(c0, p[0]) : _list(p[0], c0), false);
        assertEq(m.leaves, 512, "depth 9");
        uint32 at;
        while (m.ua[at] != p[0]) ++at;
        _pause(); // the fillers' removals: no row
        for (uint256 g; g < 60; g += 5) {
            (Step memory sf, M memory nf) = _build(m, at, _removesOf(m, f, g, g + 5), _list(p[0]));
            m = _landPieces(sf, nf, m);
        }
        _resume();
        Ch[] memory c = new Ch[](CHANGES);
        uint256 k;
        for (uint256 i; i < m.used; ++i) {
            if (i != at && m.live[i]) c[k++] = Ch(false, uint32(i), m.ua[i], 1);
        }
        assertEq(k, CHANGES, "20 one-key UAs left beside the author");
        bytes32[] memory q = _people(31, 0);
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
        (Step memory st,) = _build(m, at, c, admins);
        st.c.sealedInfo = new bytes(4124);
        assertEq(st.c.ctCount + st.nodeKeys.length, 0, "no piece");
        ++nonceN;
        uint256 snap = vm.snapshotState();
        _record(st, SIG65);
        (uint256 r65, uint256 s65) =
            _fits("the last live leaf at the spec's bound, ML-DSA-65, one transaction", VERIFY65);
        _pin(r65, s65, LAST65_REGULAR, LAST65_STATE, "the last live leaf at the spec's bound, ML-DSA-65");
        assertTrue(vchat.epochComplete(st.epochId), "complete in the one transaction");
        (uint256 kind,) = _gone(vchat, m.sid, c[CHANGES - 1].ua);
        assertEq(kind, 2, "evicted by the commit alone");
        vm.revertToState(snap);
        _record(st, SIG87);
        (uint256 r87, uint256 s87) =
            _fits("the last live leaf at the spec's bound, ML-DSA-87, one transaction", VERIFY87);
        _pin(r87, s87, LAST87_REGULAR, LAST87_STATE, "the last live leaf at the spec's bound, ML-DSA-87");
        emit log_named_uint("GAS the last live leaf at the spec's bound, ML-DSA-87: under 2^24 by", CAP - r87);
    }

    /// A-17 (the re-review of 2026-11-25): A-8's row on the worst head. The head holds 32 admins (the author and 31
    /// registered UAs with no leaf) and the commit replaces the 31 by 31 others (`_keepsAdmins` reads the head's 32, the
    /// commit rewrites 32 non-zero slots); the 21 one-key UAs sit spread over all 512 leaf positions (512 keys at creation:
    /// 21 + 3 one-key fillers and 122 fillers of 4, in id order), so the 20 blanked paths share the fewest parents; 4,124 B
    /// of info, no piece; ML-DSA-65 and ML-DSA-87, pinned, each under 2^24. Then the `treeRemove` that closes the session:
    /// a keyless admin's ML-DSA-87 removal of the author, the last UA with a leaf, whose C24 test scans all 512 positions
    /// (`_treeHasMember`) after `_treeLeafyAdmin` read the 32 admins.
    function test_lastLiveLeafOnTheWorstHead() public {
        _open(); // the vectors in this call's memory
        (M memory m, uint32 at, bytes32 author, bytes32[] memory q2) = _worstHead();
        Step memory st = _worstCommit(m, at, _withAuthor(author, q2));
        // the closing removal: a keyless admin removes the author, the last UA with a leaf
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, st.epochId, m.epoch + 2, _one(author), q2[0], ++nonceN);
        vchat.treeRemove(r, _sized(SIG87));
        (uint256 rr, uint256 rs) = _fits("the closing treeRemove, 512 positions scanned, ML-DSA-87", VERIFY87);
        _pin(rr, rs, CLOSE87_REGULAR, CLOSE87_STATE, "the closing treeRemove, ML-DSA-87");
        (uint256 kind,) = _gone(vchat, m.sid, author);
        assertEq(kind, 2, "the session closed");
    }

    /// The worst head of A-17: 512 keys (21 + 3 one-key UAs and 122 of 4), the fillers removed (no row) by commits that set
    /// the admins to the author and 31 keyless UAs; returns the model, the author's leaf, the author and 31 other keyless UAs.
    function _worstHead() internal returns (M memory m, uint32 at, bytes32 author, bytes32[] memory q2) {
        bytes32[] memory p = _people(CHANGES + 1, 1);
        bytes32[] memory g = _people(3, 1);
        bytes32[] memory f = _people(122, 4);
        IPqChat.MemberKey[] memory mk = _merged(_sortedCat(p, g), f, 4);
        assertEq(mk.length, 512, "512 keys");
        bytes32[] memory head = _withAuthor(p[0], _people(31, 0));
        q2 = _people(31, 0);
        author = p[0];
        // the creator, an admin at creation beside the author and 30 of the 31 when it is not the author
        bytes32[] memory admins0 =
            mk[0].ua == author ? head : _sortedCat(_withAuthor(author, _firstOf(head, author, 30)), _one(mk[0].ua));
        m = _session(mk, admins0, false);
        assertEq(m.leaves, 512, "depth 9");
        assertEq(m.used, 512, "every leaf position used");
        while (m.ua[at] != author) ++at;
        _pause(); // the fillers' removals: no row
        for (uint256 i; i < 122; i += 5) {
            m = _removeAll(m, at, _removesOf(m, f, i, i + 5 < 122 ? i + 5 : 122), head);
        }
        m = _removeAll(m, at, _removesOf(m, g, 0, 3), head);
        _resume();
    }

    function _removeAll(M memory m, uint32 at, Ch[] memory c, bytes32[] memory admins) internal returns (M memory) {
        (Step memory st, M memory n) = _build(m, at, c, admins);
        return _landPieces(st, n, m);
    }

    /// A-8's commit on the worst head, `admins` the new list: ML-DSA-65 and ML-DSA-87, pinned; the state after the -87 one.
    function _worstCommit(M memory m, uint32 at, bytes32[] memory admins) internal returns (Step memory st) {
        Ch[] memory c = new Ch[](CHANGES);
        uint256 k;
        (uint256 lo, uint256 hi) = (m.used, 0);
        for (uint256 i; i < m.used; ++i) {
            if (i != at && m.live[i]) c[k++] = Ch(false, uint32(i), m.ua[i], 1);
            if (m.live[i]) (lo, hi) = (i < lo ? i : lo, i > hi ? i : hi);
        }
        assertEq(k, CHANGES, "20 one-key UAs left beside the author");
        emit log_named_uint("A-17 the live leaves from position", lo);
        emit log_named_uint("A-17 the live leaves to position", hi);
        (st,) = _build(m, at, c, admins);
        st.c.sealedInfo = new bytes(4124);
        assertEq(st.c.ctCount + st.nodeKeys.length, 0, "no piece");
        ++nonceN;
        uint256 snap = vm.snapshotState();
        _record(st, SIG65);
        (uint256 r65, uint256 s65) = _fits("the last live leaf on the worst head, ML-DSA-65, one transaction", VERIFY65);
        _pin(r65, s65, WORST65_REGULAR, WORST65_STATE, "the last live leaf on the worst head, ML-DSA-65");
        vm.revertToState(snap);
        _record(st, SIG87);
        (uint256 r87, uint256 s87) = _fits("the last live leaf on the worst head, ML-DSA-87, one transaction", VERIFY87);
        _pin(r87, s87, WORST87_REGULAR, WORST87_STATE, "the last live leaf on the worst head, ML-DSA-87");
        emit log_named_uint("GAS the last live leaf on the worst head, ML-DSA-87: under 2^24 by", CAP - r87);
        assertTrue(vchat.epochComplete(st.epochId), "complete in the one transaction");
    }

    function _one(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    /// The first `n` entries of `a` other than `x`.
    function _firstOf(bytes32[] memory a, bytes32 x, uint256 n) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](n);
        uint256 k;
        for (uint256 i; k < n; ++i) {
            if (a[i] != x) r[k++] = a[i];
        }
    }

    /// `a` and `b` (each sorted) as one sorted list.
    function _sortedCat(bytes32[] memory a, bytes32[] memory b) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](a.length + b.length);
        (uint256 i, uint256 j) = (0, 0);
        for (uint256 k; k < r.length; ++k) {
            r[k] = j == b.length || (i < a.length && a[i] < b[j]) ? a[i++] : b[j++];
        }
    }

    /// The author and `others` (sorted) as one sorted list.
    function _withAuthor(bytes32 author, bytes32[] memory others) internal pure returns (bytes32[] memory) {
        return _sortedCat(_one(author), others);
    }

    /// The member keys of `one` (key 1 each) and of `many` (keys 1..`keys` each), both sorted, merged in `(ua, keyId)` order.
    function _merged(bytes32[] memory one, bytes32[] memory many, uint64 keys)
        internal
        pure
        returns (IPqChat.MemberKey[] memory mk)
    {
        mk = new IPqChat.MemberKey[](one.length + keys * many.length);
        (uint256 i, uint256 j, uint256 k) = (0, 0, 0);
        while (k < mk.length) {
            if (j == many.length || (i < one.length && one[i] < many[j])) {
                mk[k++] = _mk(one[i++], 1);
            } else {
                for (uint64 v = 1; v <= keys; ++v) {
                    mk[k++] = _mk(many[j], v);
                }
                ++j;
            }
        }
    }

    /// The bound: 20 Adds of UAs with no session on the tree of 512 with one live leaf, spread for the most new parents (20
    /// different subtrees of 16 and 16 of 32: 111 parents on their paths), the admins 1 -> 32 (the 20 added UAs and 11
    /// registered ones with no leaf), 4,124 B of info, the author's path blank.
    function _bound(M memory m, bytes32[] memory p) internal {
        bytes32[] memory q = _people(CHANGES, 1);
        bytes32[] memory more = _people(11, 0);
        uint32[] memory at = new uint32[](CHANGES);
        at[0] = 8; // in the author's subtree of 16, not its sibling
        for (uint256 i = 1; i < 16; ++i) {
            at[i] = uint32(32 * i);
        }
        for (uint256 i; i < 4; ++i) {
            at[16 + i] = uint32(16 + 32 * i);
        }
        bytes32[] memory admins = new bytes32[](32);
        admins[0] = p[0];
        for (uint256 i; i < CHANGES; ++i) {
            admins[1 + i] = q[i];
        }
        for (uint256 i; i < 11; ++i) {
            admins[1 + CHANGES + i] = more[i];
        }
        for (uint256 i = 1; i < 32; ++i) {
            for (uint256 j = i; j > 0 && admins[j - 1] > admins[j]; --j) {
                (admins[j - 1], admins[j]) = (admins[j], admins[j - 1]);
            }
        }
        (Step memory st, M memory n) = _build(m, 0, _addsTo(q, at), admins);
        st.c.sealedInfo = new bytes(4124);
        assertEq(st.c.ctCount, CHANGES, "one ciphertext per Add");
        assertEq(st.nodeKeys.length, 6, "six node keys");
        ++nonceN;
        (uint256 r65, uint256 r87) = _boundRecord(st);
        _list(st);
        _fits("the list at the bound, 20 targets", 0);
        _keysLast(st);
        _keys(st);
        _fits("the node keys at the bound, six", 0);
        _middle(st, 0);
        (uint256 fresh, uint256 rc, uint256 sc) = _completion(st, "completion at its bounds with the held ciphertext");
        assertEq(fresh, BOUND_SLOTS + 1, "the spec's new slots and the ciphertext's own");
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
        (uint256 r, uint256 s) = _row("the node keys as the last piece at the bound (C37's counter-case)");
        // at 32 changes this asked 68.3 M, over a 60 M block; at C10's 20 (owner 2026-11-25) it fits (C37's order kept)
        assertLe((r + s) * 105 / 100, BLOCK, "within a 60 M block at 20 changes");
        vm.revertToState(snap);
    }

    /// The eight `treeLeaves` pages of the full tree at one block (fable-r2-U1): each 64 leaves of versions above 0, under
    /// 4 M (the plan's line) and 2^24 (Nethermind's `eth_call` cap).
    function _pages(M memory m) internal {
        IPqChatTreeViews v = IPqChatTreeViews(address(vchat));
        uint256 sum;
        for (uint256 k; k < m.used / 64; ++k) {
            assertEq(v.treeLeaves(m.sid, 64 * k, 64).length, 64, "a full page");
            (uint256 r,) = _row(string.concat("treeLeaves page ", vm.toString(k), ", 64 leaves"));
            assertLt(r, 4_000_000, "a page under 4 M");
            sum += r;
        }
        emit log_named_uint("GAS treeLeaves, the full tree in eight calls", sum);
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

/// The rows near the limits at 512 as `burnFill` arguments (with `TREE_REPLICA=1`): for each row's forge figures (the verify
/// included in regular), the hash rounds and new slots whose one transaction has the same regular gas (within 0.1 %) and
/// state gas (within one slot), printed for the Nethermind run. **UNAUDITED.**
contract PqChatTreeGasReplicaTest is Test {
    function _gas(TreeGasBurner b, uint256 n, uint256 k, uint256 salt) internal returns (uint256 r, uint256 s) {
        b.burnFill(n, k, salt);
        Vm.Gas memory g = vm.lastCallGas();
        (r, s) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
    }

    function _row(TreeGasBurner b, string memory what, uint256 rr, uint256 ss, uint256 salt) internal {
        (, uint256 s1) = _gas(b, 0, 1, salt);
        (, uint256 s2) = _gas(b, 0, 2, salt + 1);
        uint256 perSlot = s2 - s1;
        uint256 k = ss / perSlot;
        (uint256 rk,) = _gas(b, 0, k, salt + 2);
        (uint256 rn,) = _gas(b, 100_000, k, salt + 3);
        uint256 n = (rr - rk) * 100_000 / (rn - rk);
        (uint256 r, uint256 s) = _gas(b, n, k, salt + 4);
        emit log_named_string("REPLICA", string.concat(what, " n=", vm.toString(n), " k=", vm.toString(k)));
        emit log_named_uint(string.concat("REPLICA ", what, " regular"), r);
        emit log_named_uint(string.concat("REPLICA ", what, " state"), s);
        assertApproxEqRel(r, rr, 0.001e18, "regular");
        assertApproxEqAbs(s, ss, perSlot, "state");
    }

    function test_replicaArguments() public {
        vm.skip(!vm.envOr("TREE_REPLICA", false));
        TreeGasBurner b = new TreeGasBurner();
        // at 512 and 20 changes (C10, owner 2026-11-25); the rows at 32 changes were run on 2026-11-25 too (summary file)
        _row(b, "completion at its bounds", 7_960_311, 28_655_370, 1e6);
        _row(b, "last live leaf A-8 ML-DSA-87", 15_782_531, 27_408_420, 5e6);
        _row(b, "last live leaf A-8 ML-DSA-65", 12_829_777, 25_401_060, 6e6);
        // A-17 (the re-review of 2026-11-25): the worst head and the closing removal
        _row(b, "last live leaf A-17 worst head ML-DSA-87", 16_158_289, 24_372_900, 9e6);
        _row(b, "last live leaf A-17 worst head ML-DSA-65", 13_205_502, 22_365_540, 10e6);
        _row(b, "closing treeRemove A-17 ML-DSA-87", 10_518_373, 8_656_740, 11e6);
        _row(b, "control under 2^24", 16_700_000, 1_000_000, 7e6);
        _row(b, "control over 2^24", 16_850_000, 1_000_000, 8e6);
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
