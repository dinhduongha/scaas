// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTopics} from "../../src/pqchat/PqChatTopics.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";

/// The typed digests and ids of `PqChatTypes` over calldata, as the contract computes them (the tests build records in memory).
contract PqChatHasher {
    function session(IPqChat.PqChatSession calldata s) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashSession(s));
    }

    function epoch(IPqChat.PqChatEpoch calldata e) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashEpoch(e));
    }

    function remove(IPqChat.PqChatRemove calldata r) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashRemove(r));
    }

    function leave(IPqChat.PqChatLeave calldata l) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashLeave(l));
    }

    function message(IPqChat.PqChatMessage calldata m) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashMessage(m));
    }

    function wrap(IPqChat.Wrap calldata w) external pure returns (bytes32) {
        return PqChatTypes.hashWrap(w);
    }

    function topic(IPqChat.PqTopic calldata t) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashTopic(t));
    }

    function topicUpdate(IPqChat.PqTopicUpdate calldata u) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashTopicUpdate(u));
    }

    function topicWriter(IPqChat.PqTopicWriter calldata w) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashTopicWriter(w));
    }

    function entry(IPqChat.PqTopicEntry calldata e) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashEntry(e));
    }

    function edit(IPqChat.PqTopicEdit calldata e) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashEdit(e));
    }

    function vote(IPqChat.PqTopicVote calldata v) external pure returns (bytes32) {
        return PqChatTypes.typed(PqChatTypes.hashVote(v));
    }

    function structHashes(IPqChat.PqChatSession calldata s, IPqChat.PqChatMessage calldata m)
        external pure returns (bytes32, bytes32)
    {
        return (PqChatTypes.hashSession(s), PqChatTypes.hashMessage(m));
    }
}

/// The fixture of the `PqChat` suites: a registry with the PQ holder kinds behind the stand-in verifier (`MockVerifier`: a
/// signature is the keccak of key and message), an `OpenFactory` with class 3 registered on the generic path (env v1:
/// the registry, the code-size limit `params[0]`), the release and two instances. Members are `mldsa65` UAs with a KEM key
/// (version 0, by `register`). **UNAUDITED.**
abstract contract PqChatBase is UARegistryBase {
    address internal constant REGISTRAR = address(0xF00D);
    address internal constant REG_P = 0x5cA0000000000000000000000000000000000009;
    address internal constant STRANGER = address(0x5757);
    bytes32 internal constant OWNER_UA = bytes32(uint256(0x0A11CE));
    uint256 internal constant LIMIT = 131_072;
    uint16 internal constant ML = UAKinds.MLDSA65;

    UARegistry internal p;
    OpenFactory internal f;
    PqChatHasher internal h;
    PqChatTopics internal topics; // the body module (CTR-TOK-30), pinned in the class env
    address internal impl;
    PqChat internal chat; // instance A, the home of the sessions the tests create unless they say otherwise
    PqChat internal chatB; // instance B, a replica

    /// The registered members, sorted by id.
    bytes32[] internal ids;
    mapping(bytes32 => bytes) internal keyOf_;

    function setUp() public virtual override {
        super.setUp();
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 3);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        c[base.length] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mock), 50_000);
        c[base.length + 1] = UARegistry.KindConfig(UAKinds.FNDSA512, address(mock), 50_000);
        c[base.length + 2] = UARegistry.KindConfig(UAKinds.MLDSA44, address(mock), 50_000);
        p = _deploy(REG_P, chainUidA, address(0), false, BUDGET, address(0), true, c);
        h = new PqChatHasher();
        f = EnvKit.factory(REGISTRAR, chainUidA, 0);
        topics = new PqChatTopics(address(f));
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 1, _classEnv(address(p), LIMIT));
        vm.prank(REGISTRAR);
        impl = f.deployImplementation(IOpenFactory.ReleaseId(3, 0, 1), 1, IPqChat.initialize.selector,
            type(IPqChat).interfaceId, type(PqChat).creationCode, _args());
        vm.prank(REGISTRAR);
        f.setClassKindEnabled(3, 0, true);
        chat = _instance("a", OWNER_UA);
        chatB = _instance("b", bytes32(0));
        for (uint8 i = 1; i <= 5; ++i) _member(i);
    }

    /// The class env: the registry, the code-size limit `params[0]`, the body module pinned in `libs` (3C-D2).
    function _classEnv(address registry, uint256 limit) internal view returns (IFactoryToken.Env memory e) {
        e.registry = registry;
        e.params = new bytes32[](1);
        e.params[0] = bytes32(limit);
        e.libs = new address[](1);
        e.libs[0] = address(topics);
        e.libCodeHashes = new bytes32[](1);
        e.libCodeHashes[0] = address(topics).codehash;
    }

    /// The release's `implArgs`: its body module.
    function _args() internal view returns (bytes memory) {
        return abi.encode(address(topics));
    }

    function _instance(bytes32 salt, bytes32 ownerUA) internal returns (PqChat) {
        return PqChat(f.createInstance(IOpenFactory.ReleaseId(3, 0, 1), salt, abi.encodeCall(IPqChat.initialize, (ownerUA))));
    }

    // ----- members -----

    function _mlKey(uint8 seed) internal pure returns (bytes memory d) {
        d = new bytes(1952);
        for (uint256 i; i < d.length; ++i) d[i] = bytes1(uint8(i) ^ seed);
    }

    function _kem(uint8 seed) internal pure returns (IUARegistry.KemKey memory k) {
        k.scheme = 1;
        k.mlkemEk = new bytes(1568);
        for (uint256 i; i < 1568; ++i) k.mlkemEk[i] = bytes1(uint8(i * 7) ^ seed);
        k.x25519 = bytes32(uint256(seed) << 8 | 0x09);
    }

    /// An `mldsa65` UA with KEM key version 0, kept in `ids` (sorted).
    function _member(uint8 seed) internal returns (bytes32 ua) {
        bytes memory key = _mlKey(seed);
        IUARegistry.UAAttrs memory a;
        a.kem = _kem(seed);
        ua = _register(p, ML, key, a, _pop(p, ML, key, a), "");
        keyOf_[ua] = key;
        ids.push(ua);
        for (uint256 i = ids.length - 1; i > 0 && ids[i - 1] > ids[i]; --i) (ids[i - 1], ids[i]) = (ids[i], ids[i - 1]);
    }

    /// The portable signature of `ua` over `digest` (`uaMessage(kind, PURPOSE_PQCHAT, digest)`).
    function _sig(bytes32 ua, bytes32 digest) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(keyOf_[ua], UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQCHAT, digest));
    }

    // ----- session records -----

    function _list(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    function _list(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    /// The first `n` registered members, sorted, KEM version 0, `via` 0.
    function _members(uint256 n) internal view returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) m[i] = IPqChat.MemberKey(ids[i], 0, bytes32(0));
    }

    /// The wrap of `m` in epoch `epochId` (stand-in bytes: the contract checks shape and hash only).
    function _wrap(IPqChat.MemberKey memory m, bytes32 epochId) internal pure returns (IPqChat.Wrap memory w) {
        w.member = m.ua;
        w.keyId = m.keyId;
        w.mlkemCt = new bytes(1568);
        for (uint256 i; i < 1568; i += 32) {
            bytes32 x = keccak256(abi.encode(epochId, m.ua, i));
            for (uint256 j; j < 32; ++j) w.mlkemCt[i + j] = x[j];
        }
        w.x25519Eph = keccak256(abi.encode("eph", epochId, m.ua));
        w.sealedKey = abi.encodePacked(keccak256(abi.encode("k", epochId, m.ua)), bytes16(keccak256(abi.encode(m.ua))));
    }

    function _wraps(IPqChat.MemberKey[] memory m, bytes32 epochId) internal pure returns (IPqChat.Wrap[] memory w) {
        w = new IPqChat.Wrap[](m.length);
        for (uint256 i; i < m.length; ++i) w[i] = _wrap(m[i], epochId);
    }

    function _hashes(IPqChat.Wrap[] memory w) internal view returns (bytes32[] memory hs) {
        hs = new bytes32[](w.length);
        for (uint256 i; i < w.length; ++i) hs[i] = h.wrap(w[i]);
    }

    function _slice(IPqChat.Wrap[] memory w, uint256 from, uint256 to) internal pure returns (IPqChat.Wrap[] memory r) {
        r = new IPqChat.Wrap[](to - from);
        for (uint256 i = from; i < to; ++i) r[i - from] = w[i];
    }

    /// A session of the first `n` members, created by `ids[0]` (member and only admin), homed at `home`.
    function _session(uint256 n, uint64 nonce, address home)
        internal view returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        s.creator = ids[0];
        s.nonce = nonce;
        s.homeChain = chainUidA;
        s.homeChatContract = home;
        s.admins = _list(ids[0]);
        s.members = _members(n);
        w = _wraps(s.members, PqChatTypes.sessionId(s.creator, nonce));
        s.wrapHashes = _hashes(w);
        s.sealedInfo = hex"5ea1ed";
    }

    function _create(PqChat c, IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) internal returns (bytes32) {
        return c.createSession(s, w, _sig(s.creator, h.session(s)));
    }

    /// A complete session of the first `n` members on `chat`.
    function _newSession(uint256 n) internal returns (bytes32 sid, IPqChat.PqChatSession memory s) {
        IPqChat.Wrap[] memory w;
        (s, w) = _session(n, 1, address(chat));
        sid = _create(chat, s, w);
    }

    /// An epoch record over `members` and `admins`, its wraps (all given unless `given` < members).
    function _epoch(bytes32 sid, bytes32 author, uint64 nonce, uint64 number, bytes32 parent, bytes32[] memory admins,
        IPqChat.MemberKey[] memory members) internal view returns (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w)
    {
        (e.sessionId, e.author, e.nonce, e.epoch, e.parentEpochId) = (sid, author, nonce, number, parent);
        e.admins = admins;
        e.members = members;
        w = _wraps(members, PqChatTypes.epochId(sid, author, nonce));
        e.wrapHashes = _hashes(w);
        e.sealedInfo = hex"e90c";
    }

    function _rekey(PqChat c, IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) internal returns (bytes32) {
        return c.rekey(e, w, _sig(e.author, h.epoch(e)));
    }

    function _without(IPqChat.MemberKey[] memory m, bytes32 ua) internal pure returns (IPqChat.MemberKey[] memory r) {
        r = new IPqChat.MemberKey[](m.length - 1);
        uint256 k;
        for (uint256 i; i < m.length; ++i) if (m[i].ua != ua) r[k++] = m[i];
    }

    function _unauthorized(bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua);
    }
}
