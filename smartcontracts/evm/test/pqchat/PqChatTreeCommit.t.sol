// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqGroupTree} from "../../src/pqgroup/IPqGroupTree.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";

/// The tree records' typed hashes, as the contract signs them.
contract TreeHasher {
    function sessionHash(IPqChat.PqChatSession calldata s) external pure returns (bytes32) {
        return PqChatTypes.hashSession(s);
    }

    function commit(IPqChat.PqChatCommit calldata c) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashCommit(c));
    }

    function treeLeave(IPqChat.PqChatTreeLeave calldata l) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashTreeLeave(l));
    }

    function treeRemove(IPqChat.PqChatTreeRemove calldata r) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashTreeRemove(r));
    }

    function pathList(uint32[] calldata t, bytes32[] calldata h) external pure returns (bytes32) {
        return PqChatTypes.hashPathList(t, h);
    }

    function pathCt(IPqChat.PathCt calldata c) external pure returns (bytes32) {
        return PqChatTypes.hashPathCt(c);
    }
}

/// What the tree tests share: the world of `tree-secrets.json` (its people registered under their ML-DSA-65 keys, their
/// devices' KEM versions, a `PqChat` instance at the vectors' home, as its chain uid), the reading of a step's pieces, and
/// the tree's state read from the clone's storage (namespace `scaas.pqchat.tree`; the views are T3c's). Signatures are the
/// mock verifier's over the same digests. **UNAUDITED.**
abstract contract PqChatTreeWorld is PqChatBase {
    using stdJson for string;

    uint256 internal constant TREE_ROOT = 0x6dbf1a211620db3f6ac9abbc89a5beccc42b16cce14417bf002a104ad4e19c00;
    uint256 internal constant CHAT_SLOT = 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000;

    /// A commit step with every piece.
    struct Step {
        IPqChat.PqChatCommit c;
        uint32[] ctTargets;
        bytes32[] ctHashes;
        bytes[] nodeKeys;
        IPqChat.PathCt[] cts;
        IPqChat.Wrap[] wraps;
        bytes32 treeHash;
        bytes32 epochId;
    }

    TreeHasher internal th2;
    PqChat internal vchat; // the vectors' home
    /// The vectors' JSON in this call's memory (1.5 MB: in storage it would not fit a block), opened by `_open`.
    uint256 internal sjAt;
    mapping(string => bytes32) internal person;
    /// The kind of a keyless admin registered by `_keyless` (0: an ML-DSA-65 person or member).
    mapping(bytes32 => uint16) internal kindOf;

    function setUp() public virtual override {
        super.setUp();
        th2 = new TreeHasher();
        _open();
        string[8] memory names = ["A", "B", "C", "D", "E", "F", "G", "H"];
        for (uint256 i; i < names.length; ++i) {
            string memory k = string.concat(".people.", names[i]);
            bytes memory pk = _j().readBytes(string.concat(k, ".publicKey"));
            IUARegistry.UAAttrs memory a;
            bytes32 ua = _register(p, ML, pk, a, _pop(p, ML, pk, a), "");
            assertEq(ua, _j().readBytes32(string.concat(k, ".ua")), names[i]);
            keyOf_[ua] = pk;
            person[names[i]] = ua;
        }
        string[] memory devs = vm.parseJsonKeys(_j(), ".devices");
        for (uint256 i; i < devs.length; ++i) {
            string memory k = string.concat(".devices.", devs[i]);
            bytes32 ua = _j().readBytes32(string.concat(k, ".ua"));
            _setKem(
                ua,
                uint64(_j().readUint(string.concat(k, ".keyId"))),
                _kemOf(_j().readBytes(string.concat(k, ".kemPk")))
            );
        }
        // the vectors' home: an instance's code at their contract address, under their chain uid
        PqChat base = _instance("vectors", bytes32(0));
        address home = _j().readAddress(".scenarios[0].genesis.record.homeChatContract");
        bytes memory code = address(base).code;
        bytes32 uid = _j().readBytes32(".scenarios[0].genesis.record.homeChain");
        assembly ("memory-safe") {
            mstore(add(code, 77), uid) // ChainEnvCode.OFF_CHAIN_UID = 45
        }
        vm.etch(home, code);
        for (uint256 i; i < 2; ++i) {
            vm.store(home, bytes32(CHAT_SLOT + i), vm.load(address(base), bytes32(CHAT_SLOT + i)));
        }
        vchat = PqChat(home);
    }

    function _open() internal {
        string memory j = vm.readFile("../vectors/pqchat/tree-secrets.json");
        uint256 at;
        assembly ("memory-safe") {
            at := j
        }
        sjAt = at;
    }

    function _j() internal view returns (string memory j) {
        uint256 at = sjAt;
        assembly ("memory-safe") {
            j := at
        }
    }

    function _kemOf(bytes memory pk) internal pure returns (IUARegistry.KemKey memory k) {
        k.scheme = uint8(pk[0]);
        k.mlkemEk = new bytes(1568);
        for (uint256 i; i < 1568; ++i) {
            k.mlkemEk[i] = pk[1 + i];
        }
        bytes32 x;
        assembly ("memory-safe") {
            x := mload(add(pk, 1601))
        }
        k.x25519 = x;
    }

    // ----- reading the vectors -----

    function _sc(uint256 si) internal pure returns (string memory) {
        return string.concat(".scenarios[", vm.toString(si), "]");
    }

    function _has(string memory key) internal view returns (bool) {
        return vm.keyExistsJson(_j(), key);
    }

    function _genesis(uint256 si) internal view returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) {
        string memory g = string.concat(_sc(si), ".genesis.record");
        s.creator = _j().readBytes32(string.concat(g, ".creator"));
        s.nonce = uint64(_j().readUint(string.concat(g, ".nonce")));
        s.homeChain = _j().readBytes32(string.concat(g, ".homeChain"));
        s.homeChatContract = _j().readAddress(string.concat(g, ".homeChatContract"));
        s.admins = _j().readBytes32Array(string.concat(g, ".admins"));
        s.members = new IPqChat.MemberKey[](_len(string.concat(g, ".members")));
        for (uint256 i; i < s.members.length; ++i) {
            string memory k = _ix(string.concat(g, ".members"), i);
            s.members[i] = IPqChat.MemberKey(_b32(k, ".ua"), uint64(_u(k, ".keyId")), _b32(k, ".via"));
        }
        s.groupMode = uint8(_j().readUint(string.concat(g, ".groupMode")));
        s.wrapHashes = _j().readBytes32Array(string.concat(g, ".wrapHashes"));
        s.sealedInfo = _j().readBytes(string.concat(g, ".sealedInfo"));
        w = _wrapsAt(string.concat(_sc(si), ".genesis.wraps"));
    }

    function _len(string memory key) internal view returns (uint256 n) {
        while (_has(_ix(key, n))) ++n;
    }

    function _ix(string memory key, uint256 i) internal pure returns (string memory) {
        return string.concat(key, "[", vm.toString(i), "]");
    }

    function _b32(string memory k, string memory f) internal view returns (bytes32) {
        return _j().readBytes32(string.concat(k, f));
    }

    function _u(string memory k, string memory f) internal view returns (uint256) {
        return _j().readUint(string.concat(k, f));
    }

    function _wrapsAt(string memory key) internal view returns (IPqChat.Wrap[] memory w) {
        w = new IPqChat.Wrap[](_len(key));
        for (uint256 i; i < w.length; ++i) {
            string memory k = _ix(key, i);
            w[i].member = _j().readBytes32(string.concat(k, ".member"));
            w[i].keyId = uint64(_j().readUint(string.concat(k, ".keyId")));
            w[i].mlkemCt = _j().readBytes(string.concat(k, ".mlkemCt"));
            w[i].x25519Eph = _j().readBytes32(string.concat(k, ".x25519Eph"));
            w[i].sealedKey = _j().readBytes(string.concat(k, ".sealedKey"));
        }
    }

    function _nSteps(uint256 si) internal view returns (uint256 n) {
        while (_has(string.concat(_sc(si), ".steps[", vm.toString(n), "]"))) ++n;
    }

    function _stepKey(uint256 si, uint256 k) internal pure returns (string memory) {
        return string.concat(_sc(si), ".steps[", vm.toString(k), "]");
    }

    function _isCommit(uint256 si, uint256 k) internal view returns (bool) {
        return _has(string.concat(_stepKey(si, k), ".record"));
    }

    function _step(uint256 si, uint256 k) internal view returns (Step memory st) {
        string memory s = _stepKey(si, k);
        st.c = _record(string.concat(s, ".record"));
        st.treeHash = _j().readBytes32(string.concat(s, ".treeHash"));
        st.epochId = _j().readBytes32(string.concat(s, ".epochId"));
        if (_has(string.concat(s, ".ctTargets[0]"))) {
            uint256[] memory t = _j().readUintArray(string.concat(s, ".ctTargets"));
            st.ctTargets = new uint32[](t.length);
            for (uint256 i; i < t.length; ++i) {
                st.ctTargets[i] = uint32(t[i]);
            }
            st.ctHashes = _j().readBytes32Array(string.concat(s, ".ctHashes"));
            st.nodeKeys = _j().readBytesArray(string.concat(s, ".nodeKeys"));
            st.cts = new IPqChat.PathCt[](t.length);
            for (uint256 i; i < t.length; ++i) {
                string memory k = string.concat(s, ".cts[", vm.toString(i), "]");
                st.cts[i] = IPqChat.PathCt(
                    _j().readBytes(string.concat(k, ".mlkemCt")),
                    _j().readBytes32(string.concat(k, ".x25519Eph")),
                    _j().readBytes(string.concat(k, ".sealedSecret"))
                );
            }
        }
        st.wraps = _wrapsAt(string.concat(s, ".wraps"));
    }

    function _record(string memory r) internal view returns (IPqChat.PqChatCommit memory c) {
        c.sessionId = _j().readBytes32(string.concat(r, ".sessionId"));
        c.author = _j().readBytes32(string.concat(r, ".author"));
        c.nonce = uint64(_j().readUint(string.concat(r, ".nonce")));
        c.epoch = uint64(_j().readUint(string.concat(r, ".epoch")));
        c.parentEpochId = _j().readBytes32(string.concat(r, ".parentEpochId"));
        c.treeId = _j().readBytes32(string.concat(r, ".treeId"));
        c.parentTreeHash = _j().readBytes32(string.concat(r, ".parentTreeHash"));
        c.leaf = uint32(_j().readUint(string.concat(r, ".leaf")));
        c.keyId = uint64(_j().readUint(string.concat(r, ".keyId")));
        c.leaves = uint32(_j().readUint(string.concat(r, ".leaves")));
        c.admins = _j().readBytes32Array(string.concat(r, ".admins"));
        c.removes = new IPqGroupTree.TreeRemove[](_len(string.concat(r, ".removes")));
        for (uint256 i; i < c.removes.length; ++i) {
            string memory k = _ix(string.concat(r, ".removes"), i);
            c.removes[i] = IPqGroupTree.TreeRemove(uint32(_u(k, ".leaf")), _b32(k, ".ua"), uint64(_u(k, ".keyId")));
        }
        c.adds = new IPqGroupTree.TreeAdd[](_len(string.concat(r, ".adds")));
        for (uint256 i; i < c.adds.length; ++i) {
            string memory k = _ix(string.concat(r, ".adds"), i);
            c.adds[i] = IPqGroupTree.TreeAdd(
                uint32(_u(k, ".leaf")), _b32(k, ".ua"), uint64(_u(k, ".keyId")), _b32(k, ".via"), _b32(k, ".kemHash")
            );
        }
        c.wrapHashes = _j().readBytes32Array(string.concat(r, ".wrapHashes"));
        c.nodeKeyHashes = _j().readBytes32Array(string.concat(r, ".nodeKeyHashes"));
        c.ctCount = uint32(_j().readUint(string.concat(r, ".ctCount")));
        c.ctListHash = _j().readBytes32(string.concat(r, ".ctListHash"));
        c.treeHash = _j().readBytes32(string.concat(r, ".treeHash"));
        c.sealedInfo = _j().readBytes(string.concat(r, ".sealedInfo"));
    }

    /// A `treeLeave` or `treeRemove` step, landed.
    function _landGone(PqChat c, uint256 si, uint256 k) internal {
        string memory g = string.concat(_stepKey(si, k), ".gone");
        string memory r = string.concat(g, ".record");
        bytes32 sid = _j().readBytes32(string.concat(r, ".sessionId"));
        bytes32 head = _head(c, sid);
        if (keccak256(bytes(_j().readString(string.concat(g, ".struct")))) == keccak256("PqChatTreeLeave")) {
            IPqChat.PqChatTreeLeave memory l = _leaveRec(r);
            uint256 n0 = c.leaveCount(head);
            c.treeLeave(l, _sigBy(l.member, th2.treeLeave(l)));
            (uint256 kind,) = _gone(c, sid, l.member);
            assertEq(kind, 1, string.concat(_stepKey(si, k), ": the leaver gone"));
            assertEq(c.leaveCount(head), n0 + 1, "the record under the head");
        } else {
            IPqChat.PqChatTreeRemove memory x = _removeRec(r);
            uint256 n0 = c.removalCount(head);
            c.treeRemove(x, _sigBy(x.admin, th2.treeRemove(x)));
            for (uint256 i; i < x.members.length; ++i) {
                (uint256 kind,) = _gone(c, sid, x.members[i]);
                assertEq(kind, 2, string.concat(_stepKey(si, k), ": a removed UA gone"));
            }
            assertEq(c.removalCount(head), n0 + 1, "the record under the head");
        }
    }

    function _leaveRec(string memory r) internal view returns (IPqChat.PqChatTreeLeave memory l) {
        (l.sessionId, l.treeId, l.epochId) = (_b32(r, ".sessionId"), _b32(r, ".treeId"), _b32(r, ".epochId"));
        (l.member, l.nonce) = (_b32(r, ".member"), uint64(_u(r, ".nonce")));
    }

    function _removeRec(string memory r) internal view returns (IPqChat.PqChatTreeRemove memory x) {
        (x.sessionId, x.treeId, x.epochId) = (_b32(r, ".sessionId"), _b32(r, ".treeId"), _b32(r, ".epochId"));
        (x.nonce, x.nextEpoch, x.admin) = (uint64(_u(r, ".nonce")), uint64(_u(r, ".nextEpoch")), _b32(r, ".admin"));
        x.members = _j().readBytes32Array(string.concat(r, ".members"));
    }

    /// `ua`'s signature over `digest` in the mock verifier's form by its kind: an ML-DSA-65 person or member, the WebAuthn
    /// admin, or the `msig` admin by every slot of its structure.
    function _sigBy(bytes32 ua, bytes32 digest) internal view returns (IUARegistry.UASig memory s) {
        uint16 kind = kindOf[ua];
        if (kind == 0) return _sig(ua, digest);
        if (kind != UAKinds.MSIG) {
            s.signature = _sig(keyOf_[ua], UAKinds.uaMessage(kind, UAKinds.PURPOSE_PQCHAT, digest));
            return s;
        }
        s.members = _slots(ua, keyOf_[ua], UAKinds.PURPOSE_PQCHAT, digest);
    }

    /// Every slot's member signature of the `msig` `ua` (structure `d`, ML-DSA-65 members) over `purpose` and `digest`.
    function _slots(bytes32 ua, bytes memory d, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (IUARegistry.MemberSig[] memory sigs)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        uint256 m = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        sigs = new IUARegistry.MemberSig[](m);
        for (uint256 i; i < m; ++i) {
            sigs[i] = IUARegistry.MemberSig(
                uint16(i),
                new IUARegistry.InnerSig[](0),
                _sig(keyOf_[_slotId(d, i)], UAKinds.uaMessage(ML, UAKinds.PURPOSE_MEMBER, md))
            );
        }
    }

    // ----- C-4 of the re-review of 2026-11-25 (the contract part): the worlds of this round's rules, on the contract -----

    /// The keyless admins of `tree-secrets.json` (`signers`, kinds 0x0120 and 0x0100, beside their two ML-DSA-65 members):
    /// registered here under their vector key data, so their UA ids are the vectors'; each signs by the mock verifier's form
    /// (`_sigBy`).
    function _keyless() internal {
        uint256 n = _len(".signers");
        for (uint256 i; i < n; ++i) {
            string memory k = _ix(".signers", i);
            bytes32 ua = _b32(k, ".ua");
            uint16 kind = uint16(_u(k, ".kind"));
            bytes memory d = _j().readBytes(string.concat(k, ".keyData"));
            if (kind == ML && keyOf_[ua].length == 0) {
                IUARegistry.UAAttrs memory a;
                assertEq(_register(p, ML, d, a, _pop(p, ML, d, a), ""), ua, "a member of the msig");
                keyOf_[ua] = d;
            } else if (kind == UAKinds.WEBAUTHN_P256) {
                IUARegistry.UAAttrs memory a;
                assertEq(_register(p, kind, d, a, _pop(p, kind, d, a), ""), ua, "the WebAuthn admin");
                (keyOf_[ua], kindOf[ua]) = (d, kind);
            }
        }
        for (uint256 i; i < n; ++i) {
            string memory k = _ix(".signers", i);
            if (uint16(_u(k, ".kind")) != UAKinds.MSIG) continue;
            bytes32 ua = _b32(k, ".ua");
            bytes memory d = _j().readBytes(string.concat(k, ".keyData"));
            // PQ-eligible (two ML-DSA-65 members): registered by its members' PoP over the registration digest
            IUARegistry.MemberSig[] memory pop = _slots(ua, d, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
            assertEq(UACall.register(p, UAKinds.MSIG, d, _none(), abi.encode(pop), ""), ua, "the msig admin");
            (keyOf_[ua], kindOf[ua]) = (d, UAKinds.MSIG);
        }
    }

    /// Slot `s`'s member id of an `msig` structure (`_msigKey`: threshold, count, then per slot kind, id, weight).
    function _slotId(bytes memory d, uint256 s) internal pure returns (bytes32 id) {
        uint256 o = 4 + s * 36 + 2;
        assembly ("memory-safe") {
            id := mload(add(add(d, 32), o))
        }
    }

    // ----- landing -----

    function _signC(IPqChat.PqChatCommit memory c) internal view returns (IUARegistry.UASig memory) {
        return _sig(c.author, th2.commit(c));
    }

    function _commitAll(PqChat c, Step memory st) internal returns (bytes32) {
        return c.commit(st.c, st.ctTargets, st.ctHashes, st.nodeKeys, st.cts, st.wraps, _signC(st.c));
    }

    function _commitAlone(PqChat c, Step memory st) internal returns (bytes32) {
        return c.commit(
            st.c,
            new uint32[](0),
            new bytes32[](0),
            new bytes[](0),
            new IPqChat.PathCt[](0),
            new IPqChat.Wrap[](0),
            _signC(st.c)
        );
    }

    // ----- the tree's state (namespace `scaas.pqchat.tree`) -----

    function _t(bytes32 sid) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(sid, TREE_ROOT)));
    }

    function _m(bytes32 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    function _at(PqChat c, uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(address(c), bytes32(slot)));
    }

    /// `used`, `leaves`, `owed`.
    function _sizes(PqChat c, bytes32 sid) internal view returns (uint256 used, uint256 leaves, uint256 owed) {
        uint256 w = _at(c, _t(sid) + 3);
        (used, leaves, owed) = (w & 0xffffffff, w >> 32 & 0xffffffff, w >> 64 & 0xffffffff);
    }

    function _root(PqChat c, bytes32 sid) internal view returns (bytes32) {
        (, uint256 leaves,) = _sizes(c, sid);
        return bytes32(_at(c, _m(bytes32(leaves - 1), _t(sid) + 5)));
    }

    function _head(PqChat c, bytes32 sid) internal view returns (bytes32) {
        return bytes32(_at(c, _t(sid) + 2));
    }

    /// `goneOf`: (kind, epoch).
    function _gone(PqChat c, bytes32 sid, bytes32 ua) internal view returns (uint256 kind, uint256 epoch) {
        uint256 w = _at(c, _m(ua, _t(sid) + 8));
        (kind, epoch) = (w & 0xff, w >> 8 & 0xffffffffffffffff);
    }

    /// `goneOwnKeyOf` / `goneKeyOf`: (set, joinEpoch, endEpoch).
    function _goneOwnKey(PqChat c, bytes32 sid, bytes32 ua, bytes32 kemHash)
        internal
        view
        returns (bool, uint256, uint256)
    {
        return _gk(_at(c, _m(kemHash, _m(ua, _t(sid) + 9))));
    }

    function _goneKey(PqChat c, bytes32 sid, bytes32 kemHash) internal view returns (bool, uint256, uint256) {
        return _gk(_at(c, _m(kemHash, _t(sid) + 10)));
    }

    function _gk(uint256 w) internal pure returns (bool, uint256, uint256) {
        return (w >> 128 & 1 == 1, w & 0xffffffffffffffff, w >> 64 & 0xffffffffffffffff);
    }

    function _liveCount(PqChat c, bytes32 sid, bytes32 ua) internal view returns (uint256) {
        return _at(c, _m(ua, _t(sid) + 6)) & 0xffffffff;
    }
}

/// CTR-CHAT-27 (plan 2026-11-23-pqchat-treekem T3b): every commit scenario of `tree-secrets.json` landed on chain from its
/// vector rows, its signed records, pieces and `treeLeave` / `treeRemove` steps, each completion's stored root equal to the
/// row's `treeHash`; whole in one transaction, and chunked through the piece entries by a third party in another order.
/// **UNAUDITED.**
contract PqChatTreeScenarioTest is PqChatTreeWorld {
    /// Lands scenario `si`. `chunked`: each commit's record alone by a third party, then by it the node keys, the list, the
    /// wraps and the ciphertexts one by one from the last to the first; the epoch completes only with the last piece.
    function _run(uint256 si, bool chunked) internal {
        _open();
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _genesis(si);
        bytes32 sid = vchat.createSession(s, w, _sig(s.creator, h.session(s)));
        assertTrue(vchat.epochComplete(sid));
        uint256 n = _nSteps(si);
        for (uint256 k; k < n; ++k) {
            if (!_isCommit(si, k)) {
                _landGone(vchat, si, k);
                continue;
            }
            Step memory st = _step(si, k);
            assertEq(_root(vchat, sid), st.c.parentTreeHash, "parentTreeHash is the stored root");
            bytes32 eid;
            if (!chunked) {
                eid = _commitAll(vchat, st);
            } else {
                vm.prank(STRANGER);
                eid = _commitAlone(vchat, st);
                bool none = st.c.ctCount == 0 && st.wraps.length == 0;
                assertEq(vchat.epochComplete(eid), none, "complete before its pieces");
                vm.startPrank(STRANGER);
                if (st.nodeKeys.length != 0) vchat.addPathKeys(eid, st.nodeKeys);
                if (st.ctTargets.length != 0) vchat.addPathList(eid, st.ctTargets, st.ctHashes);
                if (st.wraps.length != 0) vchat.addWraps(eid, 0, st.wraps);
                for (uint256 j = st.cts.length; j > 0; --j) {
                    assertFalse(vchat.epochComplete(eid));
                    IPqChat.PathCt[] memory one = new IPqChat.PathCt[](1);
                    one[0] = st.cts[j - 1];
                    vchat.addPath(eid, uint32(j - 1), one);
                }
                vm.stopPrank();
            }
            assertEq(eid, st.epochId, "epochId");
            assertTrue(vchat.epochComplete(eid), "complete");
            assertEq(_head(vchat, sid), eid, "head");
            assertEq(_root(vchat, sid), st.treeHash, string.concat(_stepKey(si, k), " treeHash"));
        }
    }

    /// The tree records' typehashes (`*TypehashIsPinned`) against `tree.json`, and the empty list's hash (codex-r2-14).
    function test_treeRecordTypehashesArePinned() public view {
        string memory tj = vm.readFile("../vectors/pqchat/tree.json");
        string[8] memory names = [
            "PqChatCommit",
            "TreeAdd",
            "TreeRemove",
            "PathList",
            "PathCt",
            "PqChatTreeLeave",
            "PqChatTreeRemove",
            "TreeGenesis"
        ];
        bytes32[8] memory got = [
            PqChatTypes.COMMIT_TYPEHASH,
            PqChatTypes.TREE_ADD_TYPEHASH,
            PqChatTypes.TREE_REMOVE_TYPEHASH,
            PqChatTypes.PATH_LIST_TYPEHASH,
            PqChatTypes.PATH_CT_TYPEHASH,
            PqChatTypes.TREE_LEAVE_RECORD_TYPEHASH,
            PqChatTypes.TREE_REMOVE_RECORD_TYPEHASH,
            PqChatTypes.TREE_GENESIS_TYPEHASH
        ];
        for (uint256 i; i < 8; ++i) {
            assertEq(got[i], vm.parseJsonBytes32(tj, string.concat(".typehashes.", names[i], ".hash")), names[i]);
        }
        bytes32 empty = th2.pathList(new uint32[](0), new bytes32[](0));
        assertEq(empty, vm.parseJsonBytes32(tj, ".digests.emptyPathList"));
        assertEq(
            empty, 0x314f8c453563644126ee2ba7f65398ffecccac5e0b863019a52ec0f677f605da, "PqChatTree.EMPTY_PATH_LIST"
        );
    }

    function test_scenario_main() public {
        _run(0, false);
    }

    function test_scenario_main_chunked() public {
        _run(0, true);
    }

    function test_scenario_joiner() public {
        _run(1, false);
    }

    function test_scenario_heal() public {
        _run(2, true);
    }

    function test_scenario_behind() public {
        _run(3, false);
    }

    function test_scenario_gap() public {
        _run(4, false);
    }

    function test_scenario_gapControl() public {
        _run(5, true);
    }

    function test_scenario_retired() public {
        _run(6, false);
    }

    function test_scenario_retired_chunked() public {
        _run(6, true);
    }

    function test_scenario_foreign() public {
        _run(7, false);
    }

    function test_scenario_emptyPath() public {
        _run(8, false);
    }

    function test_scenario_emptyPathForeign() public {
        _run(9, true);
    }

    function test_scenario_adminGap() public {
        _run(10, false);
    }

    // C-4 of the re-review of 2026-11-25 (the contract part): worlds 11 to 16, this round's rules, played whole; each exit
    // step's UAs gone with its kind and its record under the head (`_landGone`)

    /// The keyless admins' exits (an `msig`'s and a WebAuthn admin's `treeRemove`, an ancestor two below the head, a
    /// removal of a keyless admin and of its own signer, a removal and its signer's leave on one head).
    function test_scenario_exits() public {
        _open();
        _keyless();
        _run(11, false);
    }

    function test_scenario_smallOrder() public {
        _run(12, false);
    }

    function test_scenario_small() public {
        _run(13, true);
    }

    function test_scenario_pinExit() public {
        _run(14, false);
    }

    function test_scenario_returned() public {
        _run(15, false);
    }

    /// The lag world (17 commits), then C9's lag on its head: a leave naming epoch 0, 17 below the head, is
    /// `PqChatExitLag(0, 17)`; naming epoch 1 (the first commit) it lands at the head (the control).
    function test_scenario_lag() public {
        _run(16, false);
        string memory r = string.concat(_sc(16), ".genesis.record");
        bytes32 sid = PqChatTypes.sessionId(_b32(r, ".creator"), uint64(_u(r, ".nonce")));
        bytes32 tid = _b32(_stepKey(16, 0), ".record.treeId");
        bytes32 c = person["C"];
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(sid, tid, sid, c, 9_000);
        IUARegistry.UASig memory ls = _sig(c, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatExitLag.selector, uint64(0), uint64(17)));
        vchat.treeLeave(l, ls);
        l.epochId = _b32(_stepKey(16, 0), ".epochId");
        vchat.treeLeave(l, _sig(c, th2.treeLeave(l)));
        (uint256 kind,) = _gone(vchat, sid, c);
        assertEq(kind, 1, "the control lands");
    }
}
