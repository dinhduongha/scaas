// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatCore} from "../../src/pqchat/PqChatCore.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// A registry that answers `kemKeyAt` from keys set by the test: the vector UAs of `tree.json` are not registered UAs.
contract VectorKems {
    mapping(bytes32 => mapping(uint64 => bytes)) internal pk;

    function set(bytes32 ua, uint64 keyId, bytes memory kemPk) external {
        pk[ua][keyId] = kemPk;
    }

    function kemKeyAt(bytes32 ua, uint64 keyId) external view returns (IUARegistry.KemKey memory k, bytes memory sig) {
        bytes memory b = pk[ua][keyId];
        if (b.length == 0) return (k, sig);
        k.scheme = uint8(b[0]);
        k.mlkemEk = new bytes(1568);
        for (uint256 i; i < 1568; ++i) {
            k.mlkemEk[i] = b[1 + i];
        }
        bytes32 x;
        assembly ("memory-safe") {
            x := mload(add(b, 1601))
        }
        k.x25519 = x;
    }
}

/// `PqGroupTree` under PqChat's hooks, outside a clone: the tree hash and the admission check against the vectors, and the
/// namespace written field by field for the layout pin.
contract TreeHarness is PqChatCore {
    function admissible(bytes memory kemPk) external pure returns (bool) {
        return _admissible(kemPk);
    }

    function open(bytes32 gid, uint256 used, bytes32[] calldata admins) external {
        _treeOpen(gid, keccak256(abi.encode(gid)), used, admins);
    }

    function setLeaf(IUARegistry reg, bytes32 gid, uint256 i, bytes32 ua, uint64 keyId) external returns (bool) {
        return _treeSetLeaf(reg, gid, i, ua, keyId, 0, uint32(i));
    }

    function thParent(bytes32 keyHash, bytes32 l, bytes32 r) external pure returns (bytes32) {
        return _thParent(keyHash, l, r);
    }

    function treeHash(IUARegistry reg, bytes32 gid) external view returns (bytes32) {
        return _treeHash(reg, _tree(gid));
    }

    function nodeHash(bytes32 gid, uint256 x) external view returns (bytes32) {
        return _tree(gid).nodeAt[x].hash;
    }

    /// Every field the cold tree does not write, at distinct values (the layout pin).
    function poke(bytes32 gid, bytes32 ua, bytes32 kemHash) external {
        Tree storage t = _tree(gid);
        (t.genesisTreeHash, t.head, t.owed) = (bytes32(uint256(0x61)), bytes32(uint256(0x62)), 5);
        t.nodeAt[3] = Node(bytes32(uint256(0x63)), 0x64);
        t.gone[ua] = Gone(2, 7);
        t.goneOwnKey[ua][kemHash] = GoneKey(3, 7, true);
        t.goneKey[kemHash] = GoneKey(4, 8, true);
    }

    /// A staged commit's four fields (A-9): `targetsHash`, `list`, `keys`, `ctAt[2]`.
    function stage(bytes32 eid) external {
        Staged storage g = _staged(eid);
        (g.targetsHash, g.list, g.keys) = (bytes32(uint256(0x65)), address(0x66), address(0x67));
        g.ctAt[2] = 0x68;
    }
}

/// CTR-CHAT-26, CTR-CHAT-27 (plan 2026-11-23-pqchat-treekem T3a): a tree session (`groupMode = 1`) in the body module
/// `PqChatTree`: an `sstore2` home only, the home instance only, the caps; leaf `i`, `liveKey`, `keysOf`, the hashes above it
/// and the UA's `sessionsOf` entry written when wrap `i` lands, its key admitted; the genesis tree hash at completion.
/// The tree hash and the admission check against `smartcontracts/vectors/pqchat/tree.json`. **UNAUDITED.**
contract PqChatTreeTest is PqChatBase {
    using stdJson for string;

    /// `tree.json`'s `keys` rows, read once (the file is large: a storage string copied per read runs out of gas).
    mapping(bytes32 => uint256) internal keyRow; // keccak256(name) => row + 1
    bytes[] internal keyPks;
    bytes32[] internal keyUas;
    uint256[] internal keyIds;
    TreeHarness internal th;
    VectorKems internal vk;
    /// Tree members: registered `mldsa65` UAs whose KEM key (version 0) is a vector key that passes the check, sorted.
    bytes32[] internal tm;

    function setUp() public override {
        super.setUp();
        string memory tj = _tj();
        // field by field: forge's order of a JSON object's keys in a decoded struct is not stable (a flaky setUp)
        for (uint256 i; vm.keyExistsJson(tj, string.concat(".keys[", vm.toString(i), "]")); ++i) {
            string memory k = string.concat(".keys[", vm.toString(i), "]");
            keyRow[keccak256(bytes(tj.readString(string.concat(k, ".name"))))] = i + 1;
            keyPks.push(tj.readBytes(string.concat(k, ".kemPk")));
            keyUas.push(tj.readBytes32(string.concat(k, ".ua")));
            keyIds.push(tj.readUint(string.concat(k, ".keyId")));
        }
        th = new TreeHarness();
        vk = new VectorKems();
        string[5] memory names = ["A", "B", "C", "D", "E"];
        for (uint256 i; i < names.length; ++i) {
            tm.push(_tmember(uint8(40 + i), _kemOf(_keyPk(names[i]))));
        }
        for (uint256 i = 1; i < tm.length; ++i) {
            for (uint256 j = i; j > 0 && tm[j - 1] > tm[j]; --j) {
                (tm[j - 1], tm[j]) = (tm[j], tm[j - 1]);
            }
        }
    }

    // ----- helpers -----

    function _tj() internal view returns (string memory) {
        return vm.readFile("../vectors/pqchat/tree.json");
    }

    function _row(string memory name) internal view returns (uint256 r) {
        r = keyRow[keccak256(bytes(name))];
        require(r != 0, name);
        --r;
    }

    function _keyPk(string memory name) internal view returns (bytes memory) {
        return keyPks[_row(name)];
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

    /// An `mldsa65` UA with KEM key `k` as version 0 (not in `ids`).
    function _tmember(uint8 seed, IUARegistry.KemKey memory k) internal returns (bytes32 ua) {
        bytes memory key = _mlKey(seed);
        IUARegistry.UAAttrs memory a;
        a.kem = k;
        ua = _register(p, ML, key, a, _pop(p, ML, key, a), "");
        keyOf_[ua] = key;
    }

    /// A tree session of `members` (version 0 each), created by `members[0].ua`, its only admin, homed at `home`.
    function _tsession(IPqChat.MemberKey[] memory members, uint64 nonce, address home)
        internal
        view
        returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) = (members[0].ua, nonce, chainUidA, home);
        s.admins = _list(members[0].ua);
        s.members = members;
        w = _wraps(members, PqChatTypes.sessionId(s.creator, nonce));
        s.wrapHashes = _hashes(w);
        s.sealedInfo = new bytes(284);
        s.groupMode = 1;
    }

    function _mk(bytes32[] memory uas) internal pure returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](uas.length);
        for (uint256 i; i < uas.length; ++i) {
            m[i] = IPqChat.MemberKey(uas[i], 0, bytes32(0));
        }
    }

    function _first(uint256 n) internal view returns (IPqChat.MemberKey[] memory) {
        bytes32[] memory u = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            u[i] = tm[i];
        }
        return _mk(u);
    }

    function _one(IPqChat.Wrap memory w) internal pure returns (IPqChat.Wrap[] memory r) {
        r = new IPqChat.Wrap[](1);
        r[0] = w;
    }

    // the clone's tree namespace (`scaas.pqchat.tree`, pinned in test_treeNamespaceIsPinned)
    uint256 internal constant TREE_ROOT = 0x6dbf1a211620db3f6ac9abbc89a5beccc42b16cce14417bf002a104ad4e19c00;

    function _t(bytes32 sid) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(sid, TREE_ROOT)));
    }

    function _at(address a, uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(a, bytes32(slot)));
    }

    function _m(bytes32 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    function _genesis(bytes32 sid) internal view returns (bytes32) {
        return bytes32(_at(address(chat), _t(sid) + 1));
    }

    function _leafLive(bytes32 sid, uint256 i) internal view returns (bool) {
        return _at(address(chat), _m(bytes32(i), _t(sid) + 4) + 1) >> 160 & 1 == 1;
    }

    /// The root over `members` computed by the harness (validated against the vectors) from the registry.
    function _expectedRoot(IPqChat.MemberKey[] memory members, bytes32 gid) internal returns (bytes32) {
        th.open(gid, members.length, new bytes32[](0));
        for (uint256 i; i < members.length; ++i) {
            th.setLeaf(IUARegistry(address(p)), gid, i, members[i].ua, members[i].keyId);
        }
        return th.treeHash(IUARegistry(address(p)), gid);
    }

    // ----- the tree hash and the admission check (vectors) -----

    /// Spec §4, T1a's `treeHash.cold` rows: the root and every parent's `th` of a cold tree, its leaves set in order and in
    /// reverse (a leaf's hash covers its index and its `kemHash`, from the registry).
    function test_coldTreeHashMatchesVectors() public {
        string memory tj = _tj();
        for (uint256 r; r < 6; ++r) {
            string memory row = string.concat(".treeHash.cold[", vm.toString(r), "]");
            string[] memory names = tj.readStringArray(string.concat(row, ".members"));
            bytes32 want = tj.readBytes32(string.concat(row, ".tree.treeHash"));
            bytes32[] memory nodes = tj.readBytes32Array(string.concat(row, ".tree.nodeHashes"));
            bytes32[] memory uas = new bytes32[](names.length);
            uint64[] memory kids = new uint64[](names.length);
            for (uint256 i; i < names.length; ++i) {
                (uas[i], kids[i]) = (keyUas[_row(names[i])], uint64(keyIds[_row(names[i])]));
                vk.set(uas[i], kids[i], _keyPk(names[i]));
            }
            for (uint256 order; order < 2; ++order) {
                bytes32 gid = keccak256(abi.encode(r, order));
                th.open(gid, names.length, new bytes32[](0));
                for (uint256 j; j < names.length; ++j) {
                    uint256 i = order == 0 ? j : names.length - 1 - j;
                    th.setLeaf(IUARegistry(address(vk)), gid, i, uas[i], kids[i]);
                }
                assertEq(th.treeHash(IUARegistry(address(vk)), gid), want, string.concat(row, " treeHash"));
                for (uint256 x = 1; x < nodes.length; x += 2) {
                    assertEq(th.nodeHash(gid, x), nodes[x], string.concat(row, " node ", vm.toString(x)));
                }
            }
        }
    }

    /// Spec §8 (C19, C32): every `admission` row, accepted and refused, as clientkeys' `admitKemKey`.
    function test_admissionRowsMatchVectors() public view {
        string memory tj = _tj();
        for (uint256 i; i < 3; ++i) {
            string memory row = string.concat(".admission.accepted[", vm.toString(i), "]");
            assertTrue(
                th.admissible(tj.readBytes(string.concat(row, ".kemPk"))), tj.readString(string.concat(row, ".name"))
            );
        }
        for (uint256 i; i < 13; ++i) {
            string memory row = string.concat(".admission.refused[", vm.toString(i), "]");
            assertFalse(
                th.admissible(tj.readBytes(string.concat(row, ".kemPk"))), tj.readString(string.concat(row, ".name"))
            );
        }
    }

    /// Spec §4: `th(parent)` is 0 for a blank parent over two empty subtrees (padding and growth cost no slot), else the
    /// typed hash; a blank parent over one member is hashed.
    function test_blankParentOverEmptySubtreesHashesToZero() public view {
        assertEq(th.thParent(0, 0, 0), 0);
        bytes32 x = keccak256("x");
        assertEq(
            th.thParent(0, x, 0), keccak256(abi.encode(PqChatTypes.TREE_PARENT_TYPEHASH, bytes32(0), x, bytes32(0)))
        );
        assertEq(
            th.thParent(x, 0, 0), keccak256(abi.encode(PqChatTypes.TREE_PARENT_TYPEHASH, x, bytes32(0), bytes32(0)))
        );
    }

    /// FIPS 203 §7.2 on both 12-bit coefficients of a 3-byte group (the vector's refused row sets a first one): the base key
    /// with coefficient `k` set to 3,329 is refused and to 3,328 admitted, for the first and second of a group, first and last.
    function test_admissionEveryCoefficientOfAGroup() public view {
        bytes memory base = _tj().readBytes(".admission.accepted[0].kemPk");
        uint256[4] memory ks = [uint256(0), 1, 1022, 1023];
        for (uint256 j; j < 4; ++j) {
            for (uint256 v = 3328; v <= 3329; ++v) {
                bytes memory pk = bytes.concat(base);
                uint256 o = 1 + 3 * (ks[j] / 2);
                if (ks[j] % 2 == 0) {
                    (pk[o], pk[o + 1]) = (bytes1(uint8(v & 0xff)), bytes1((uint8(pk[o + 1]) & 0xf0) | uint8(v >> 8)));
                } else {
                    (pk[o + 1], pk[o + 2]) =
                    (bytes1((uint8(pk[o + 1]) & 0x0f) | uint8((v & 15) << 4)), bytes1(uint8(v >> 4)));
                }
                assertEq(th.admissible(pk), v == 3328, string.concat("coefficient ", vm.toString(ks[j])));
            }
        }
    }

    // ----- the cold tree, written with the wraps (C15, C34) -----

    /// Every `treeHash.cold` row of `tree.json` created on chain as a session of the row's members, in the row's order (its
    /// people registered under their vector UAs, each member key its KEM version `keyId`): one root whatever the order of
    /// the wraps (all with the record, in reverse one per transaction, in order one per transaction), equal to the row's
    /// `treeHash`; `treeId` the session's struct hash, the head epoch 0, `used` and `leaves` the row's.
    function test_genesisTreeHashWithTheWraps() public {
        string memory tj = _tj();
        for (uint256 r; r < 6; ++r) {
            string memory row = string.concat(".treeHash.cold[", vm.toString(r), "]");
            IPqChat.MemberKey[] memory m = _vectorMembers(tj, tj.readStringArray(string.concat(row, ".members")));
            bytes32 want = tj.readBytes32(string.concat(row, ".tree.treeHash"));
            uint256 shape =
                tj.readUint(string.concat(row, ".tree.used")) | tj.readUint(string.concat(row, ".tree.leaves")) << 32;
            for (uint64 order; order < 3; ++order) {
                (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) =
                    _tsession(m, uint64(100 + 3 * r + order), address(chat));
                bytes32 sid = _create(chat, s, order == 0 ? w : new IPqChat.Wrap[](0));
                for (uint256 j; order != 0 && j < w.length; ++j) {
                    uint256 i = order == 1 ? w.length - 1 - j : j;
                    assertEq(_genesis(sid), 0, "no genesis hash before the last wrap");
                    chat.addWraps(sid, uint32(i), _one(w[i]));
                }
                assertTrue(chat.epochComplete(sid));
                assertEq(_genesis(sid), want, string.concat(row, " genesisTreeHash"));
                assertEq(bytes32(_at(address(chat), _t(sid) + 2)), sid, "the head is epoch 0");
                (bytes32 hs,) = h.structHashes(s, _anyMessage());
                assertEq(bytes32(_at(address(chat), _t(sid))), hs, "treeId = hashStruct(PqChatSession)");
                assertEq(_at(address(chat), _t(sid) + 3), shape, "used, leaves, owed 0");
            }
        }
    }

    /// (ua, keyId) => its KEM version is set
    mapping(bytes32 => bool) internal vectorKemSet;

    /// The members `names` of a `tree.json` row as they are listed: each person registered once under its vector UA (the
    /// mldsa65 key of `people`, KEM version 0 a stand-in), each key set once as its KEM version `keyId`.
    function _vectorMembers(string memory tj, string[] memory names) internal returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](names.length);
        for (uint256 i; i < names.length; ++i) {
            string memory who = string(abi.encodePacked(bytes(names[i])[0]));
            bytes32 ua = tj.readBytes32(string.concat(".people.", who, ".ua"));
            if (keyOf_[ua].length == 0) {
                bytes memory key = tj.readBytes(string.concat(".people.", who, ".publicKey"));
                IUARegistry.UAAttrs memory a;
                a.kem = _kem(uint8(bytes(who)[0]));
                assertEq(_register(p, ML, key, a, _pop(p, ML, key, a), ""), ua, "the vector UA registered");
                keyOf_[ua] = key;
            }
            uint64 keyId = uint64(keyIds[_row(names[i])]);
            assertEq(keyUas[_row(names[i])], ua);
            bytes32 k = keccak256(abi.encode(ua, keyId));
            if (!vectorKemSet[k]) {
                _setKem(ua, keyId, _kemOf(_keyPk(names[i])));
                vectorKemSet[k] = true;
            }
            m[i] = IPqChat.MemberKey(ua, keyId, bytes32(0));
        }
    }

    function _anyMessage() internal pure returns (IPqChat.PqChatMessage memory msg_) {}

    /// C15, C34: the record writes no leaf and lists only its creator; each wrap writes its leaf, `liveKey`, `keysOf` and
    /// lists its UA.
    function test_leavesAndListingLandWithTheirWraps() public {
        IPqChat.MemberKey[] memory m = _first(3);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(m, 1, address(chat));
        bytes32 sid = _create(chat, s, new IPqChat.Wrap[](0));
        assertEq(chat.sessionCount(m[0].ua), 1, "the creator, with the record");
        for (uint256 i; i < 3; ++i) {
            assertFalse(_leafLive(sid, i), "no leaf before its wrap");
            if (i > 0) assertEq(chat.sessionCount(m[i].ua), 0, "a member before its wrap");
        }
        chat.addWraps(sid, 1, _one(w[1]));
        assertTrue(_leafLive(sid, 1), "leaf 1 with wrap 1");
        assertEq(bytes32(_at(address(chat), _m(bytes32(uint256(1)), _t(sid) + 4))), m[1].ua, "leaf 1's ua");
        assertFalse(_leafLive(sid, 2));
        assertEq(chat.sessionCount(m[1].ua), 1, "listed at its first wrap");
        assertEq(chat.sessionCount(m[2].ua), 0);
        assertEq(_at(address(chat), _m(m[1].ua, _t(sid) + 6)), 1 | 1 << 32, "keysOf: one live, listed");
        bytes32 kh = keccak256(abi.encodePacked(uint8(1), _kemPkOf(m[1].ua, 0)));
        assertEq(_at(address(chat), _m(kh, _t(sid) + 7)), 2, "liveKey = leaf + 1");
        chat.addWraps(sid, 0, _slice(w, 0, 1));
        assertEq(chat.sessionCount(m[0].ua), 1, "the creator listed once");
        assertEq(_genesis(sid), 0);
        chat.addWraps(sid, 2, _one(w[2]));
        assertTrue(chat.epochComplete(sid) && _genesis(sid) != 0);
    }

    function _kemPkOf(bytes32 ua, uint64 keyId) internal view returns (bytes memory) {
        (IUARegistry.KemKey memory k,) = p.kemKeyAt(ua, keyId);
        return abi.encodePacked(k.mlkemEk, k.x25519);
    }

    /// (M): two keys of one UA are two leaves, the UA listed once.
    function test_twoKeysOfOneUaListedOnce() public {
        _setKem(tm[1], 1, _kemOf(_keyPk("C2")));
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](3);
        (m[0], m[1], m[2]) =
        (IPqChat.MemberKey(tm[0], 0, 0), IPqChat.MemberKey(tm[1], 0, 0), IPqChat.MemberKey(tm[1], 1, 0));
        bytes32 want = _expectedRoot(m, "m");
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(m, 1, address(chat));
        bytes32 sid = _create(chat, s, w);
        assertEq(chat.sessionCount(tm[1]), 1, "listed once");
        assertEq(_at(address(chat), _m(tm[1], _t(sid) + 6)), 2 | 1 << 32, "keysOf: two live");
        assertEq(_genesis(sid), want);
    }

    /// C18: two members with one key: the second wrap is `PqChatTreeKeyLive`, epoch 0 never completes; the control lands.
    function test_twoMembersWithOneKeyNeverComplete() public {
        bytes32 twin = _tmember(60, _kemOf(_keyPk("A")));
        bytes32[] memory u = new bytes32[](2);
        bytes32 holder = _holderOf("A");
        (u[0], u[1]) = twin < holder ? (twin, holder) : (holder, twin);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_mk(u), 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 1));
        bytes32 kh = keccak256(_keyPk("A"));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatTreeKeyLive.selector, kh));
        chat.addWraps(sid, 1, _one(w[1]));
        assertFalse(chat.epochComplete(sid));
        // the control: two members with their own keys complete
        (s, w) = _tsession(_first(2), 2, address(chat));
        assertTrue(chat.epochComplete(_create(chat, s, w)));
    }

    function _holderOf(string memory name) internal view returns (bytes32) {
        bytes32 kh = keccak256(_keyPk(name));
        for (uint256 i; i < tm.length; ++i) {
            if (keccak256(abi.encodePacked(uint8(1), _kemPkOf(tm[i], 0))) == kh) return tm[i];
        }
        revert("no holder");
    }

    /// C19, C32: a member whose registry key fails the admission check: its wrap is `PqChatKemKey(ua, keyId)`.
    function test_keyFailingTheCheckRefusedAtItsWrap() public {
        bytes memory bad = _tj().readBytes(".admission.refused[0].kemPk"); // a coefficient at 3,329
        bytes32 x = _tmember(61, _kemOf(bad));
        bytes32 a = _holderOf("A");
        bytes32[] memory u = new bytes32[](2);
        (u[0], u[1]) = x < a ? (x, a) : (a, x);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_mk(u), 1, address(chat));
        uint256 bi = u[0] == x ? 0 : 1;
        bytes32 sid = _create(chat, s, new IPqChat.Wrap[](0));
        chat.addWraps(sid, uint32(1 - bi), _one(w[1 - bi]));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, x, uint64(0)));
        chat.addWraps(sid, uint32(bi), _one(w[bi]));
        // mode 0 takes the same key (its check is scheme and length, P3)
        s.groupMode = 0;
        s.nonce = 2;
        w = _wraps(s.members, PqChatTypes.sessionId(s.creator, 2));
        s.wrapHashes = _hashes(w);
        assertTrue(chat.epochComplete(_create(chat, s, w)));
    }

    // ----- where a tree session may be, and its caps -----

    /// C1: a tree session on a `none` home is `PqChatTreeSigStore()`; the same session on an `sstore2` home lands.
    function test_noneHomeRefused() public {
        PqChat none = _instanceWith("none", bytes32(0), 0);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(none));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatTreeSigStore.selector);
        none.createSession(s, w, sig);
        (s, w) = _tsession(_first(2), 1, address(chat));
        assertTrue(chat.epochComplete(_create(chat, s, w)));
    }

    /// C4: a tree session created outside its home is `PqChatTreeHome()`; at its home it lands.
    function test_replicaRefused() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatTreeHome.selector);
        chatB.createSession(s, w, sig);
        assertTrue(chat.epochComplete(_create(chat, s, w)));
    }

    /// C24: `sealedInfo` at most 4,124 B, at creation too.
    function test_infoCap() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(chat));
        s.sealedInfo = new bytes(4125);
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.createSession(s, w, sig);
        s.sealedInfo = new bytes(4124);
        assertTrue(chat.epochComplete(_create(chat, s, w)));
    }

    /// C24: at most 32 admins (each registered, P8; the registry's answer stubbed for the made-up ids).
    function test_adminCap() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(chat));
        vm.mockCall(address(p), abi.encodeWithSelector(IUARegistry.isRegistered.selector), abi.encode(true));
        for (uint256 n = 33; n >= 32; --n) {
            bytes32[] memory a = new bytes32[](n);
            for (uint256 i; i < n - 1; ++i) {
                a[i] = bytes32(i + 1);
            }
            a[n - 1] = s.creator; // above the small ids
            s.admins = a;
            s.nonce = uint64(n);
            w = _wraps(s.members, PqChatTypes.sessionId(s.creator, s.nonce));
            s.wrapHashes = _hashes(w);
            if (n == 33) {
                IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
                vm.expectRevert(IPqChat.PqChatShape.selector);
                chat.createSession(s, w, sig);
            } else {
                assertTrue(chat.epochComplete(_create(chat, s, w)), "32 admins");
            }
        }
    }

    /// C10 (owner, R8): at most 256 leaf positions: 257 member keys refused, 256 accepted (no wrap sent; the registry's
    /// key answer stubbed for the made-up ids, 8 keys each).
    function test_leafCap() public {
        bytes32 c = tm[tm.length - 1]; // the creator, above the made-up ids
        IUARegistry.KemKey memory k = _kemOf(_keyPk("A"));
        vm.mockCall(address(p), abi.encodeWithSelector(IUARegistry.kemKeyAt.selector), abi.encode(k, bytes("")));
        for (uint256 n = 257; n >= 256; --n) {
            IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](n);
            for (uint256 i; i < n - 1; ++i) {
                m[i] = IPqChat.MemberKey(bytes32(i / 8 + 1), uint64(i % 8), 0);
            }
            m[n - 1] = IPqChat.MemberKey(c, 0, 0);
            IPqChat.PqChatSession memory s;
            (s.creator, s.nonce, s.homeChain, s.homeChatContract, s.groupMode) =
            (c, uint64(n), chainUidA, address(chat), 1);
            s.admins = _list(c);
            s.members = m;
            s.wrapHashes = new bytes32[](n);
            s.sealedInfo = new bytes(284);
            IUARegistry.UASig memory sig = _sig(c, h.session(s));
            if (n == 257) vm.expectRevert(IPqChat.PqChatShape.selector);
            bytes32 sid = chat.createSession(s, new IPqChat.Wrap[](0), sig);
            if (n == 256) assertEq(_at(address(chat), _t(sid) + 3), 256 | 256 << 32, "used 256, leaves 256");
        }
    }

    // ----- the modes -----

    /// CTR-CHAT-27: `rekey` on a tree session is `PqChatModeEntry(1)`; on a flat one it lands.
    function test_rekeyOnATreeSessionRefused() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(chat));
        bytes32 sid = _create(chat, s, w);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(sid, s.creator, 1, 1, sid, s.admins, s.members);
        IUARegistry.UASig memory sig = _sig(s.creator, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(1)));
        chat.rekey(e, ew, sig);
        (bytes32 fid, IPqChat.PqChatSession memory f) = _newSession(2);
        (e, ew) = _epoch(fid, f.creator, 1, 1, fid, f.admins, f.members);
        chat.rekey(e, ew, _sig(f.creator, h.epoch(e)));
    }

    /// CTR-TOK-30: the release lists its four modules; the tree module and the exits module called directly have no env.
    function test_treeModuleListedAndNoEnvAlone() public {
        address[] memory m = chat.modules();
        assertEq(m.length, 4);
        assertEq(m[0], address(topics));
        assertEq(m[1], address(treeModule));
        assertEq(m[2], address(viewsModule));
        assertEq(m[3], address(membersModule));
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(_first(2), 1, address(chat));
        IUARegistry.UASig memory sig;
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        treeModule.treeCreate(s, w, sig);
        IPqChat.PqChatTreeLeave memory l;
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        membersModule.treeLeave(l, sig);
        IPqChat.PqChatTreeRemove memory r;
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        membersModule.treeRemove(r, sig);
    }

    // ----- the layout (R16: the pair set and the group-wide set apart) -----

    /// `PqGroupTree`'s namespace for PqChat is ERC-7201 of `scaas.pqchat.tree`, each field at its pinned slot
    /// (`test/v2/layout/namespaces.json`, `pqchatTree`), read with `vm.load` after a write through the source.
    function test_treeNamespaceIsPinned() public {
        string memory pin = vm.readFile("./test/v2/layout/namespaces.json");
        assertEq(pin.readString(".pqchatTree.id"), "scaas.pqchat.tree");
        bytes32 root = keccak256(abi.encode(uint256(keccak256("scaas.pqchat.tree")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(pin.readBytes32(".pqchatTree.root"), root);
        assertEq(bytes32(TREE_ROOT), root);
        // a written tree (the clone) and the fields the cold tree does not write (the harness, the same struct)
        IPqChat.MemberKey[] memory m = _first(2);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _tsession(m, 1, address(chat));
        bytes32 sid = _create(chat, s, w);
        bytes32 kh = keccak256(abi.encodePacked(uint8(1), _kemPkOf(m[0].ua, 0)));
        th.open(sid, 2, s.admins);
        th.setLeaf(IUARegistry(address(p)), sid, 0, m[0].ua, 0);
        th.poke(sid, m[0].ua, kh);
        th.stage(keccak256("epoch E"));
        (bytes32 hs,) = h.structHashes(s, _anyMessage());
        _checkRows(pin, sid, uint256(root), m[0].ua, kh, hs);
        _checkStaged(pin, uint256(root));
    }

    /// A-9: the rows of `staged[E]` (`stagedSlot`, after `trees`): the four fields of `Staged`, `ctAt` by index.
    function _checkStaged(string memory pin, uint256 root) internal view {
        string[] memory labels = pin.readStringArray(".pqchatTree.labels");
        uint256[] memory slots = pin.readUintArray(".pqchatTree.slots");
        uint256[] memory inner = pin.readUintArray(".pqchatTree.inner");
        assertEq(labels.length, 18, "rows");
        assertEq(pin.readUint(".pqchatTree.stagedSlot"), 1, "staged after trees");
        uint256 base = uint256(keccak256(abi.encode(keccak256("epoch E"), root + 1)));
        uint256[4] memory want = [uint256(0x65), 0x66, 0x67, 0x68];
        for (uint256 i; i < 4; ++i) {
            uint256 slot = base + slots[14 + i];
            if (i == 3) slot = _m(bytes32(uint256(2)), slot); // ctAt[2]
            assertEq(_at(address(th), slot + inner[14 + i]), want[i], labels[14 + i]);
        }
    }

    /// Each row of the pin: the value written, where (the clone for `treeId`, else the harness) and the mapping key.
    function _checkRows(string memory pin, bytes32 sid, uint256 root, bytes32 ua, bytes32 kh, bytes32 hs)
        internal
        view
    {
        string[] memory labels = pin.readStringArray(".pqchatTree.labels");
        uint256[] memory slots = pin.readUintArray(".pqchatTree.slots");
        uint256[] memory inner = pin.readUintArray(".pqchatTree.inner");
        uint256[14] memory want = [
            uint256(hs), // treeId (the clone)
            0x61, // genesisTreeHash
            0x62, // head
            2 | 2 << 32 | 5 << 64, // used | leaves | owed
            uint256(ua), // leafAt[0].ua
            1 << 160, // leafAt[0]: keyId 0, joinEpoch 0, wrapIndex 0, live
            0x63, // nodeAt[3].hash
            0x64, // nodeAt[3].keyAt
            1 | 1 << 32, // keysOf[U]: one live, listed
            1, // liveKey[K]: leaf 0 + 1
            2 | 7 << 8, // gone[U]
            3 | 7 << 64 | 1 << 128, // goneOwnKey[U][K]
            4 | 8 << 64 | 1 << 128, // goneKey[K]
            1 // admins.length
        ];
        bytes32[14] memory key =
            [bytes32(0), 0, 0, 0, 0, 0, bytes32(uint256(3)), bytes32(uint256(3)), ua, kh, ua, 0, kh, 0];
        assertEq(labels.length, 18, "rows: 14 of trees[G], 4 of staged[E]");
        for (uint256 i; i < 14; ++i) {
            uint256 base = uint256(keccak256(abi.encode(sid, root))) + slots[i];
            uint256 slot = key[i] == 0 ? base : _m(key[i], base);
            if (i == 4 || i == 5) slot = _m(bytes32(0), base); // leafAt[0]
            if (i == 11) slot = _m(kh, _m(ua, base)); // the pair set: by UA, then by kemHash
            assertEq(_at(i == 0 ? address(chat) : address(th), slot + inner[i]), want[i], labels[i]);
        }
        assertTrue(slots[11] != slots[12], "R16: the pair set and the group-wide set at distinct slots");
    }
}
