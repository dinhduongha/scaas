// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqGroupTree} from "../../src/pqgroup/IPqGroupTree.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PqChatTreeWorld} from "./PqChatTreeCommit.t.sol";

/// A tree session built by the test, with a model of its tree that is independent of the contract's: the whole `th` is
/// recomputed from the leaves and node keys (RFC 9420 §7.8 as spec §4 types it), the filtered path and the resolutions
/// from the array layout's own formulas. A commit is built on a copy of the model: its record, list, node keys, stand-in
/// ciphertexts and Welcome wraps (the contract checks their shape and hash only), signed by the mock verifier.
/// **UNAUDITED.**
abstract contract PqChatTreeModel is PqChatTreeWorld {
    using stdJson for string;

    struct M {
        bytes32 sid;
        bytes32 treeId;
        bytes32 head;
        uint64 epoch;
        uint256 used;
        uint256 leaves;
        bytes32[] ua;
        uint64[] kid;
        bytes32[] kem;
        bool[] live;
        bytes32[] key; // a parent's keyHash, 0 blank
    }

    /// A change: `add` true for a `TreeAdd`.
    struct Ch {
        bool add;
        uint32 leaf;
        bytes32 ua;
        uint64 keyId;
    }

    uint64 internal nonceN = 1000;
    bytes internal nodeKey; // an admitted key, every path node's

    function setUp() public virtual override {
        super.setUp();
        nodeKey = _j().readBytes(".devices.H.kemPk");
    }

    // ----- keys -----

    function _kemHash(bytes32 ua, uint64 kid) internal view returns (bytes32) {
        (IUARegistry.KemKey memory k,) = p.kemKeyAt(ua, kid);
        return keccak256(abi.encodePacked(k.scheme, k.mlkemEk, k.x25519));
    }

    /// An admitted key: device `name`'s bytes with another canonical `pk_X`.
    function _variant(string memory name, uint256 seed) internal view returns (IUARegistry.KemKey memory k) {
        k = _kemOf(_j().readBytes(string.concat(".devices.", name, ".kemPk")));
        k.x25519 = bytes32(uint256(keccak256(abi.encode(name, seed))) & ~uint256(0xff) | 1); // pk_X < 2^249, little-endian
    }

    // ----- sessions -----

    /// A tree session on `vchat` of `members` (sorted by `(ua, keyId)`), created by `members[0].ua` with `admins`.
    function _open(IPqChat.MemberKey[] memory members, bytes32[] memory admins) internal returns (M memory m) {
        IPqChat.PqChatSession memory s;
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) =
        (members[0].ua, ++nonceN, _j().readBytes32(".scenarios[0].genesis.record.homeChain"), address(vchat));
        (s.admins, s.members, s.groupMode, s.sealedInfo) = (admins, members, 1, hex"5ea1");
        IPqChat.Wrap[] memory w = _wraps(members, PqChatTypes.sessionId(s.creator, s.nonce));
        s.wrapHashes = _hashes(w);
        m.sid = vchat.createSession(s, w, _sig(s.creator, h.session(s)));
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

    function _mk(bytes32 ua, uint64 kid) internal pure returns (IPqChat.MemberKey memory) {
        return IPqChat.MemberKey(ua, kid, bytes32(0));
    }

    // ----- the model -----

    function _lv(uint256 x) internal pure returns (uint256 k) {
        while ((x >> k) & 1 == 1) ++k;
    }

    function _par(uint256 x) internal pure returns (uint256) {
        uint256 k = _lv(x);
        return (x >> (k + 1)) & 1 == 0 ? x + (1 << k) : x - (1 << k);
    }

    function _sib(uint256 x) internal pure returns (uint256) {
        uint256 q = _par(x);
        return x < q ? q + (q - x) : q - (x - q);
    }

    function _th(M memory m, uint256 x) internal pure returns (bytes32) {
        if (x & 1 == 0) {
            uint256 i = x / 2;
            if (!m.live[i]) return 0;
            return keccak256(abi.encode(PqChatTypes.TREE_LEAF_TYPEHASH, uint32(i), m.ua[i], m.kid[i], m.kem[i]));
        }
        uint256 h = 1 << (_lv(x) - 1);
        (bytes32 l, bytes32 r) = (_th(m, x - h), _th(m, x + h));
        if (m.key[x] == 0 && l == 0 && r == 0) return 0;
        return keccak256(abi.encode(PqChatTypes.TREE_PARENT_TYPEHASH, m.key[x], l, r));
    }

    function _mRoot(M memory m) internal pure returns (bytes32) {
        return _th(m, m.leaves - 1);
    }

    function _res(M memory m, uint256 x, uint32[] memory out, uint256 n) internal pure returns (uint256) {
        if (x & 1 == 0) {
            if (m.live[x / 2]) out[n++] = uint32(x);
            return n;
        }
        if (m.key[x] != 0) {
            out[n++] = uint32(x);
            return n;
        }
        uint256 h = 1 << (_lv(x) - 1);
        return _res(m, x + h, out, _res(m, x - h, out, n));
    }

    function _copy(M memory a) internal pure returns (M memory b) {
        (b.sid, b.treeId, b.head, b.epoch, b.used, b.leaves) = (a.sid, a.treeId, a.head, a.epoch, a.used, a.leaves);
        (b.ua, b.kid, b.kem, b.live, b.key) =
        (new bytes32[](256), new uint64[](256), new bytes32[](256), new bool[](256), new bytes32[](511));
        for (uint256 i; i < 256; ++i) {
            (b.ua[i], b.kid[i], b.kem[i], b.live[i]) = (a.ua[i], a.kid[i], a.kem[i], a.live[i]);
        }
        for (uint256 i; i < 511; ++i) {
            b.key[i] = a.key[i];
        }
    }

    function _blank(M memory m, uint256 x) internal pure {
        while (x != m.leaves - 1) {
            x = _par(x);
            m.key[x] = 0;
        }
    }

    // ----- building a commit -----

    /// The commit of `author` from `leaf` with `changes` and `admins` on `m`'s head; `n` the model after it.
    function _build(M memory m, uint32 leaf, Ch[] memory changes, bytes32[] memory admins)
        internal
        view
        returns (Step memory st, M memory n)
    {
        n = _copy(m);
        IPqChat.PqChatCommit memory c = st.c;
        (c.sessionId, c.author, c.nonce, c.epoch, c.parentEpochId) =
        (m.sid, m.ua[leaf], nonceN + 1, m.epoch + 1, m.head);
        (c.treeId, c.parentTreeHash, c.leaf, c.keyId, c.admins) = (m.treeId, _mRoot(m), leaf, m.kid[leaf], admins);
        uint256 na;
        for (uint256 i; i < changes.length; ++i) {
            if (changes[i].add) ++na;
        }
        (c.removes, c.adds) = (new IPqGroupTree.TreeRemove[](changes.length - na), new IPqGroupTree.TreeAdd[](na));
        (uint256 ir, uint256 ia) = (0, 0);
        for (uint256 i; i < changes.length; ++i) {
            Ch memory x = changes[i];
            if (!x.add) {
                c.removes[ir++] = IPqGroupTree.TreeRemove(x.leaf, x.ua, x.keyId);
                n.live[x.leaf] = false;
                _blank(n, 2 * x.leaf);
            }
        }
        for (uint256 i; i < changes.length; ++i) {
            Ch memory x = changes[i];
            if (!x.add) continue;
            bytes32 k = _kemHash(x.ua, x.keyId);
            c.adds[ia++] = IPqGroupTree.TreeAdd(x.leaf, x.ua, x.keyId, bytes32(0), k);
            if (x.leaf >= n.used) n.used = x.leaf + 1;
            while (n.leaves < n.used) n.leaves <<= 1;
            (n.ua[x.leaf], n.kid[x.leaf], n.kem[x.leaf], n.live[x.leaf]) = (x.ua, x.keyId, k, true);
            _blank(n, 2 * x.leaf);
        }
        c.leaves = uint32(n.leaves);
        _path(n, st);
        st.epochId = PqChatTypes.epochId(c.sessionId, c.author, c.nonce);
        st.wraps = new IPqChat.Wrap[](na);
        c.wrapHashes = new bytes32[](na);
        for (uint256 i; i < na; ++i) {
            st.wraps[i] = _wrap(_mk(c.adds[i].ua, c.adds[i].keyId), st.epochId);
            c.wrapHashes[i] = h.wrap(st.wraps[i]);
        }
        c.sealedInfo = hex"c0de";
        c.treeHash = _mRoot(n);
        st.treeHash = c.treeHash;
        (n.head, n.epoch) = (st.epochId, c.epoch);
    }

    /// The author's filtered path on `n` (after the changes): node keys, targets, stand-in ciphertexts, the list.
    function _path(M memory n, Step memory st) internal view {
        IPqChat.PqChatCommit memory c = st.c;
        uint32[] memory tg = new uint32[](256);
        bytes32[] memory nk = new bytes32[](9);
        (uint256 t, uint256 k, uint256 x) = (0, 0, 2 * uint256(c.leaf));
        while (x != n.leaves - 1) {
            uint256 q = _par(x);
            uint256 before = t;
            t = _res(n, _sib(x), tg, t);
            n.key[q] = t != before ? keccak256(nodeKey) : bytes32(0);
            if (t != before) nk[k++] = keccak256(nodeKey);
            x = q;
        }
        assembly ("memory-safe") {
            mstore(tg, t)
            mstore(nk, k)
        }
        (c.nodeKeyHashes, c.ctCount, st.ctTargets) = (nk, uint32(t), tg);
        st.nodeKeys = new bytes[](k);
        for (uint256 i; i < k; ++i) {
            st.nodeKeys[i] = nodeKey;
        }
        st.cts = new IPqChat.PathCt[](t);
        st.ctHashes = new bytes32[](t);
        for (uint256 i; i < t; ++i) {
            st.cts[i] = IPqChat.PathCt(new bytes(1568), keccak256(abi.encode(c.nonce, i)), new bytes(48));
            st.cts[i].mlkemCt[0] = bytes1(uint8(i));
            st.ctHashes[i] = th2.pathCt(st.cts[i]);
        }
        c.ctListHash = th2.pathList(st.ctTargets, st.ctHashes);
    }

    /// Signs and lands `st` whole; the model moves to `n`.
    function _land(Step memory st, M memory n, M memory m) internal returns (M memory) {
        ++nonceN;
        _commitAll(vchat, st);
        assertTrue(vchat.epochComplete(st.epochId), "complete");
        assertEq(_root(vchat, m.sid), _mRoot(n), "stored root is the model's");
        return n;
    }

    /// `st` refused with `err`, nothing written: the author's nonce still free.
    function _refused(Step memory st, bytes memory err) internal {
        IUARegistry.UASig memory sg = _signC(st.c);
        vm.expectRevert(err);
        vchat.commit(st.c, st.ctTargets, st.ctHashes, st.nodeKeys, st.cts, st.wraps, sg);
        assertFalse(vchat.nonceUsed(PqChatTypes.scopeEpoch(st.c.sessionId, st.c.author), st.c.nonce), "no state");
    }

    function _chs(Ch memory a) internal pure returns (Ch[] memory r) {
        r = new Ch[](1);
        r[0] = a;
    }

    function _chs(Ch memory a, Ch memory b) internal pure returns (Ch[] memory r) {
        r = new Ch[](2);
        (r[0], r[1]) = (a, b);
    }

    function _noCh() internal pure returns (Ch[] memory) {}

    function _leaveT(M memory m, bytes32 ua) internal {
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(m.sid, m.treeId, m.head, ua, ++nonceN);
        vchat.treeLeave(l, _sig(ua, th2.treeLeave(l)));
    }

    function _removeT(M memory m, bytes32 admin, bytes32[] memory uas) internal {
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, uas, admin, ++nonceN);
        vchat.treeRemove(r, _sig(admin, th2.treeRemove(r)));
    }
}
