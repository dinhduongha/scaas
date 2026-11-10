// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {OnchainBase} from "./OnchainBase.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChat as PqChatFace} from "../../src/pqchat/PqChat.sol";
import {PqChatTopics} from "../../src/pqchat/PqChatTopics.sol";

/// @dev `PqChatTypes` over calldata, run in the script's own EVM (never broadcast): the typed digests and ids.
contract PqChatDigests {
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

    function sessionId(bytes32 creator, uint64 nonce) external pure returns (bytes32) {
        return PqChatTypes.sessionId(creator, nonce);
    }

    function epochId(bytes32 sid, bytes32 author, uint64 nonce) external pure returns (bytes32) {
        return PqChatTypes.epochId(sid, author, nonce);
    }

    function scopeSession(bytes32 creator) external pure returns (bytes32) {
        return PqChatTypes.scopeSession(creator);
    }
}

/// @notice Plan 3c T95 (owner 2026-11-10), group `pqchat` of the Step 5b framework: every external entry of `PqChat` on a
///         real node. The release and an instance come from the deploy (`deploy.sh evm` with DEPLOY_PQCHAT=1, plan T92:
///         `pqchat_implementation`, `pqchat_instance`); this run creates a second instance through the factory
///         (`createInstance`, class 3), owned by no UA. Three ML-DSA-65 UAs with a KEM key (version 0, by `register`) are
///         the members; their keys and signatures come from script/pqz/mldsa.mjs through `vm.ffi` (run with `--ffi`; the
///         seeds are the run's). The 2-person chat first: a session of A and B whole, one in chunks (`addWraps` relayed
///         unsigned through `RelayFeeRouter`, test key 1 paying the fee on a kind-0 token), two plain rekeys, a membership
///         change adding C, a leave, the admin's `remove` of C (UA-7 P48), a rekey dropping both, messages, a `storeMessage` (relayed through the router
///         and direct), then a topic, its writer, a post, a reply, an edit and votes. Every signed write is sent by test key
///         2 (anyone submits); the state is read back through the views after each step. Negatives by eth_call after the
///         broadcast (`_neg`): the P9 removal attack, a second child at home, a nonce reuse, a non-member's message, a vote
///         value of 2. Test chains only. UNAUDITED.
contract PqChatOnchain is OnchainBase {
    uint16 internal constant ML65 = UAKinds.MLDSA65;
    bytes32 internal constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    uint256 internal constant LANE_FEE = 31; // test key 1's relay-fee lane on this run's token
    /// @dev A UA registration (ML-DSA-65 PoP through the cached key) and each part of `cacheExpandedKey`: a fixed 56 M (under
    ///      60 M), as Tokens.s.sol: the estimate undershoots regular + state gas (EIP-8037).
    uint256 internal constant REGISTER_GAS = 56_000_000;
    /// @dev The release transaction (`deployImplementation`), when this run makes it: at most 60 M asked (NET-EVM-11).
    uint256 internal constant RELEASE_GAS = 59_000_000;

    IUARegistry reg;
    OpenFactory f;
    IPqChat chat; // the deploy's instance (home of every session here)
    IPqChat chat2; // this run's instance (a replica)
    PqChatDigests h;
    address router;
    address tok; // a kind-0 token of the deploy's factory, test key 1 holds its supply
    bytes32 uid;
    bytes32[3] uas; // sorted
    bytes32[3] seeds; // the ML-DSA seed of uas[i]
    uint64 sn; // this run's session nonce base
    bytes32 sid; // the 2-person session
    bytes32 sid2; // the session made in chunks
    bytes32 e1;
    bytes32 e2;
    bytes16 dv; // the device id
    bytes32 tid;
    bytes32 pid;

    function run() external {
        _init("pqchat");
        reg = IUARegistry(_dep("ua_registry"));
        f = OpenFactory(_dep("token_factory"));
        router = _dep("relay_fee_router");
        uid = vm.parseJsonBytes32(dj, ".chain_uid");
        h = new PqChatDigests(); // the script's EVM only
        _release();
        _book(address(f), "OpenFactory");
        _book(address(reg), "UARegistry");
        _book(router, "RelayFeeRouter");
        _instance();
        _members();
        _token();
        _sessions();
        _messages();
        _topics();
        _writeBook();
    }

    // ------------------------------------------------------------------ setup

    /// @dev The deploy's release and instance (`deploy.sh evm` with DEPLOY_PQCHAT=1, plan T92); on a chain deployed before T92
    ///      (the SCaaS testnet's Step 5 deploy) the same steps as `DeployBase._deployPqChat`, sent by the factory's registrar
    ///      (PRIVATE_KEY, the deployer): the class env 1 of `(3, 0)`, release 1 with an explicit gas limit (at most 60 M
    ///      asked), the switch on, one instance owned by no UA.
    function _release() internal {
        address impl;
        if (vm.keyExistsJson(dj, ".pqchat_instance")) {
            (impl, chat) = (_dep("pqchat_implementation"), IPqChat(_dep("pqchat_instance")));
        } else {
            IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
            uint256 dk = vm.envUint("PRIVATE_KEY");
            impl = f.classReleaseOf(id).implementation;
            if (impl == address(0)) {
                vm.startBroadcast(dk);
                address topics = address(new PqChatTopics{salt: _salt("pqchat-topics")}(address(f)));
                IFactoryToken.Env memory e;
                e.registry = address(reg);
                e.params = new bytes32[](1);
                e.params[0] = bytes32(vm.envOr("CHAIN_CODE_LIMIT", uint256(131_072)));
                (e.libs, e.libCodeHashes) = (new address[](1), new bytes32[](1));
                (e.libs[0], e.libCodeHashes[0]) = (topics, topics.codehash);
                f.publishClassEnv(3, 0, 1, e);
                impl = f.deployImplementation{gas: RELEASE_GAS}(id, 1, IPqChat.initialize.selector, type(IPqChat).interfaceId,
                    vm.getCode("PqChat.sol:PqChat"), abi.encode(topics));
                f.setClassKindEnabled(3, 0, true);
                vm.stopBroadcast();
            }
            vm.broadcast(k1);
            chat = IPqChat(f.createInstance(id, _salt("pqchat-1"), abi.encodeCall(IPqChat.initialize, (bytes32(0)))));
        }
        _book(address(chat), "PqChat");
        _book(impl, "PqChat");
        _book(PqChatFace(impl).modules()[0], "PqChatTopics");
    }

    function _instance() internal {
        vm.broadcast(k1);
        chat2 = IPqChat(f.createInstance(IOpenFactory.ReleaseId(3, 0, 1), _salt("pqchat-2"),
            abi.encodeCall(IPqChat.initialize, (bytes32(0)))));
        _book(address(chat2), "PqChat");
        require(chat2.owner() == 0, "instance 2 owner");
        (IOpenFactory.Created[] memory page, uint256 total) = f.contractsPage(3, 0, 64);
        bool found;
        for (uint256 i; i < page.length; ++i) found = found || page[i].addr == address(chat2);
        require(found && total >= 2, "contractsPage(3) lists the instance");
    }

    function _ml(string memory job) internal returns (bytes memory) {
        string[] memory c = new string[](3);
        (c[0], c[1]) = ("sh", "-c");
        c[2] = string.concat("printf '%s\\n' '", job,
            "' | node script/pqz/mldsa.mjs ../../clients/clientkeys | sed 's/^/0x/'");
        return vm.ffi(c);
    }

    function _bare(bytes32 x) internal pure returns (string memory) {
        bytes memory s = bytes(vm.toString(x));
        bytes memory o = new bytes(64);
        for (uint256 i; i < 64; ++i) o[i] = s[i + 2];
        return string(o);
    }

    function _kem(bytes32 seed) internal pure returns (IUARegistry.KemKey memory k) {
        bytes memory ek;
        for (uint256 i; i < 49; ++i) ek = bytes.concat(ek, keccak256(abi.encode(seed, i))); // 1,568 B (ML-KEM-1024 ek)
        k = IUARegistry.KemKey(UAKinds.KEM_SCHEME_MLKEM1024_X25519, ek, keccak256(abi.encode(seed, "x25519")));
    }

    /// @dev Three ML-DSA-65 UAs, each with its KEM key at version 0 (`UAAttrs.kem`), registered by test key 1.
    function _members() internal {
        for (uint256 i; i < 3; ++i) {
            bytes32 seed = keccak256(abi.encode(runSalt, "pqchat-mldsa65", i));
            bytes memory pk = _ml(string.concat("keygen 65 ", _bare(seed)));
            require(pk.length == 1952, "ML-DSA-65 key");
            bytes32 ua = UAKinds.uaOf(ML65, pk);
            IUARegistry.UAAttrs memory a;
            a.kem = _kem(keccak256(abi.encode(seed, "kem")));
            bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, UAKinds.kemPk(a.kem)), 0);
            bytes memory pop = _mlRaw(seed, reg.uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd));
            vm.startBroadcast(k1);
            reg.cacheExpandedKey{gas: REGISTER_GAS}(ML65, pk, 0);
            reg.cacheExpandedKey{gas: REGISTER_GAS}(ML65, pk, 1);
            require(reg.register{gas: REGISTER_GAS}(ML65, pk, a, pop, "") == ua, "ML-DSA UA");
            vm.stopBroadcast();
            (IUARegistry.KemKey memory k,) = reg.kemKeyAt(ua, 0);
            require(k.scheme != 0, "KEM key version 0");
            (uas[i], seeds[i]) = (ua, seed);
        }
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && uas[j - 1] > uas[j]; --j) {
                (uas[j - 1], uas[j]) = (uas[j], uas[j - 1]);
                (seeds[j - 1], seeds[j]) = (seeds[j], seeds[j - 1]);
            }
        }
    }

    function _mlRaw(bytes32 seed, bytes32 uaMsg) internal returns (bytes memory) {
        return _ml(string.concat("sign 65 ", _bare(seed), " ", _bare(PqUA.pqMessage(PqUA.tag(ML65), uaMsg))));
    }

    /// @dev Member `i`'s portable signature over the typed digest `d` (`uaMessage(ML65, PURPOSE_PQCHAT, d)`).
    function _sigOf(uint256 i, bytes32 d) internal returns (IUARegistry.UASig memory s) {
        s.signature = _mlRaw(seeds[i], reg.uaMessage(ML65, UAKinds.PURPOSE_PQCHAT, d));
    }

    function _token() internal {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("Onchain pqchat", "oPC", 6);
        c.features = 1 << GovernanceBits.PAYABLE;
        (c.owner, c.initialSupply, c.initialHolder) = (_pad(a1), 1e12, a1);
        vm.broadcast(k1);
        tok = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), _salt("fee-token"));
        _book(tok, "NormalToken");
    }

    /// @dev `RelayFeeRouter.relay` of the unsigned call `cd` on `target`: test key 1 pays 1 (open mode: the router forwards
    ///      it to the sender, test key 3).
    function _relayed(address target, bytes memory cd) internal {
        uint256 fn = NormalToken(tok).mtxNonce(_pad(a1), LANE_FEE);
        bytes32 payee = _pad(router);
        bytes32 d = _digest(tok, keccak256(abi.encode(UA_RELAY_FEE, _pad(a1), target, keccak256(cd), payee, uint256(1),
            LANE_FEE, fn, vu, router)));
        vm.broadcast(k3);
        RelayFeeRouter(router).relay(target, cd, tok, _pad(a1), payee, 1, LANE_FEE, fn, vu, _sig(k1, d));
        require(NormalToken(tok).mtxNonce(_pad(a1), LANE_FEE) == fn + 1, "relay fee lane");
    }

    // ------------------------------------------------------------------ sessions and epochs

    function _mk(uint256[] memory idx) internal view returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](idx.length);
        for (uint256 i; i < idx.length; ++i) m[i] = IPqChat.MemberKey(uas[idx[i]], 0, bytes32(0));
    }

    function _ids(uint256 a, uint256 b) internal pure returns (uint256[] memory l) {
        l = new uint256[](2);
        (l[0], l[1]) = (a, b);
    }

    function _ids(uint256 a) internal pure returns (uint256[] memory l) {
        l = new uint256[](1);
        l[0] = a;
    }

    function _uas(uint256[] memory idx) internal view returns (bytes32[] memory u) {
        u = new bytes32[](idx.length);
        for (uint256 i; i < idx.length; ++i) u[i] = uas[idx[i]];
    }

    /// @dev Stand-in wrap bytes (the contract checks shape and hash only): 1,568 B ciphertext, 48 B sealed key.
    function _wraps(IPqChat.MemberKey[] memory m, bytes32 tag) internal view returns (IPqChat.Wrap[] memory w, bytes32[] memory hs)
    {
        (w, hs) = (new IPqChat.Wrap[](m.length), new bytes32[](m.length));
        for (uint256 i; i < m.length; ++i) {
            bytes memory ct;
            for (uint256 j; j < 49; ++j) ct = bytes.concat(ct, keccak256(abi.encode(tag, m[i].ua, j)));
            bytes memory sk = bytes.concat(keccak256(abi.encode(tag, m[i].ua, "k")), bytes16(keccak256(abi.encode(tag, "s"))));
            w[i] = IPqChat.Wrap(m[i].ua, m[i].keyId, ct, keccak256(abi.encode(tag, m[i].ua, "x")), sk);
            hs[i] = h.wrap(w[i]);
        }
    }

    function _slice(IPqChat.Wrap[] memory w, uint256 from, uint256 to) internal pure returns (IPqChat.Wrap[] memory s) {
        s = new IPqChat.Wrap[](to - from);
        for (uint256 i; i < s.length; ++i) s[i] = w[from + i];
    }

    function _session(uint256 creator, uint64 nonce, uint256[] memory idx)
        internal view returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) = (uas[creator], nonce, uid, address(chat));
        s.admins = _uas(_ids(creator));
        s.members = _mk(idx);
        (w, s.wrapHashes) = _wraps(s.members, keccak256(abi.encode(runSalt, "session", nonce)));
        s.sealedInfo = bytes.concat(keccak256(abi.encode(runSalt, "info", nonce)));
    }

    function _epoch(bytes32 sid_, uint256 author, uint64 nonce, uint64 n, bytes32 parent, bytes32[] memory admins,
        uint256[] memory idx) internal view returns (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w)
    {
        e.sessionId = sid_;
        e.author = uas[author];
        e.nonce = nonce;
        e.epoch = n;
        e.parentEpochId = parent;
        e.admins = admins;
        e.members = _mk(idx);
        (w, e.wrapHashes) = _wraps(e.members, keccak256(abi.encode(runSalt, "epoch", sid_, n, nonce)));
    }

    function _sessions() internal {
        sn = uint64(uint256(_salt("session-nonce")) >> 200);
        _whole();
        _chunks();
        _rekeys();
        _replica();
    }

    /// @dev The 2-person chat, whole: A creates with A and B, every wrap in the call.
    function _whole() internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(0, sn, _ids(0, 1));
        IUARegistry.UASig memory sg = _sigOf(0, h.session(s));
        vm.broadcast(k2);
        sid = chat.createSession(s, w, sg);
        require(sid == h.sessionId(s.creator, s.nonce) && chat.epochComplete(sid), "session complete");
        require(chat.sessionCount(uas[1]) >= 1 && chat.latestEpoch(sid) == sid, "recovery views at create");
        _neg(a2, address(chat), abi.encodeCall(IPqChat.createSession, (s, w, sg)), IPqChat.PqChatNonceUsed.selector,
            "pqchat: createSession with a used (creator, nonce)");
    }

    /// @dev In chunks: one wrap with the record, the other by `addWraps`, relayed unsigned through RelayFeeRouter.
    function _chunks() internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(0, sn + 1, _ids(0, 1));
        IUARegistry.UASig memory sg = _sigOf(0, h.session(s));
        vm.broadcast(k2);
        sid2 = chat.createSession(s, _slice(w, 0, 1), sg);
        require(!chat.epochComplete(sid2), "incomplete after one wrap");
        _relayed(address(chat), abi.encodeCall(IPqChat.addWraps, (sid2, uint32(1), _slice(w, 1, 2))));
        require(chat.epochComplete(sid2), "complete at the last wrap");
        require(h.wrap(chat.wrapAt(sid2, 1)) == s.wrapHashes[1], "wrapAt");
    }

    /// @dev A plain rekey by B (a member), the P9 removal attack refused, then a membership change by A (the admin) adding C.
    function _rekeys() internal {
        bytes32[] memory admins = _uas(_ids(0));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, 1, sn, 1, sid, admins, _ids(0, 1));
        IUARegistry.UASig memory sg = _sigOf(1, h.epoch(e));
        vm.broadcast(k2);
        e1 = chat.rekey(e, ew, sg);
        require(chat.childOf(sid) == e1 && chat.latestEpoch(sid) == e1, "the home slot and latestEpoch");
        (e, ew) = _epoch(sid, 0, sn + 7, 1, sid, admins, _ids(0));
        sg = _sigOf(0, h.epoch(e));
        _neg(a2, address(chat), abi.encodeCall(IPqChat.rekey, (e, ew, sg)), IPqChat.PqChatEpochTaken.selector,
            "pqchat: a second child at home (the P9 removal attack)");
        uint256[] memory abc = new uint256[](3);
        (abc[0], abc[1], abc[2]) = (0, 1, 2);
        (e, ew) = _epoch(sid, 0, sn + 1, 2, e1, admins, abc);
        sg = _sigOf(0, h.epoch(e));
        vm.broadcast(k2);
        e2 = chat.rekey(e, ew, sg);
        require(chat.epochCount(sid) == 3 && chat.sessionCount(uas[2]) == 1, "epochsOf and sessionsOf after the add");
        bytes32[] memory page = chat.epochsOf(sid, 0, 8); // epoch 0 first, then each as it completed
        require(page.length == 3 && page[0] == sid && page[1] == e1 && page[2] == e2, "epochsOf");
        page = chat.sessionsOf(uas[2], 0, 8);
        require(page.length == 1 && page[0] == sid, "sessionsOf");
        (IPqChat.PqChatEpoch memory eb,) = chat.epochOf(e2);
        require(eb.epoch == 2, "epochOf");
    }

    /// @dev A replica: the same session record stored on the second instance (not its home).
    function _replica() internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(0, sn, _ids(0, 1));
        IUARegistry.UASig memory sg = _sigOf(0, h.session(s));
        vm.broadcast(k2);
        require(chat2.createSession(s, w, sg) == sid, "replica session");
        (IPqChat.PqChatSession memory back,) = chat2.sessionOf(sid);
        require(back.creator == s.creator && chat2.childOf(sid) == 0, "sessionOf on the replica");
    }

    // ------------------------------------------------------------------ leave, messages, the chain as a store

    function _msg(bytes32 eid, uint256 sender, uint64 counter) internal view returns (IPqChat.PqChatMessage memory m) {
        return _msgAt(sid, eid, sender, counter);
    }

    function _msgAt(bytes32 session, bytes32 eid, uint256 sender, uint64 counter)
        internal view returns (IPqChat.PqChatMessage memory m)
    {
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) = (session, eid, uas[sender], dv, counter);
        m.parents = new bytes32[](1);
        m.parents[0] = keccak256(abi.encode(runSalt, "head"));
        m.ciphertext = bytes.concat(keccak256(abi.encode(runSalt, "ct", counter)), keccak256(abi.encode(dv)));
    }

    function _messages() internal {
        // the device id: a 16-byte UUID, v7 here (owner 2026-11-10: v7 or v4, never parsed)
        dv = bytes16(uint128(uint256(_salt("device")))) & 0xffffffffffff0fff3fffffffffffffff | 0x00000000000070008000000000000000;
        _post();
        _postChunked();
        _leaveAndDrop();
        _removeRace();
        _store();
    }

    /// @dev A message in the chunked session (whose epoch 0 keeps no child to the end, so its counter-reuse negative holds
    ///      against the final state, where coverage.py runs every negative).
    function _postChunked() internal {
        IPqChat.PqChatMessage memory m = _msgAt(sid2, sid2, 0, 0);
        IUARegistry.UASig memory sg = _sigOf(0, h.message(m));
        vm.broadcast(k2);
        chat.postMessage(m, sg);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.postMessage, (m, sg)), IPqChat.PqChatNonceUsed.selector,
            "pqchat: postMessage with a used (epoch, sender, device) counter");
    }

    /// @dev UA-7 P48, the race of the Fable review P1-2: a session of A, B, C where A removes C from epoch 0 and no child
    ///      follows, so the refusals hold against the final state: C's rekey (PqChatNotMember), B's plain rekey keeping C
    ///      (PqChatRemovedKept), the remove replayed (PqChatNonceUsed).
    function _removeRace() internal {
        uint256[] memory abc = new uint256[](3);
        (abc[0], abc[1], abc[2]) = (0, 1, 2);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(0, sn + 2, abc);
        IUARegistry.UASig memory sg = _sigOf(0, h.session(s));
        vm.broadcast(k2);
        bytes32 s3 = chat.createSession(s, w, sg);
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(s3, s3, 1, _uas(_ids(2)), uas[0], 1);
        sg = _sigOf(0, h.remove(r));
        vm.broadcast(k2);
        chat.remove(r, sg);
        require(chat.removedIn(s3, uas[2]), "removedIn");
        _neg(a2, address(chat), abi.encodeCall(IPqChat.remove, (r, sg)), IPqChat.PqChatNonceUsed.selector,
            "pqchat: remove replayed");
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(s3, 2, 1, 1, s3, s.admins, abc);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.rekey, (e, ew, _sigOf(2, h.epoch(e)))),
            IPqChat.PqChatNotMember.selector, "pqchat: the removed member's rekey (the race of the Fable review P1-2)");
        (e, ew) = _epoch(s3, 1, 1, 1, s3, s.admins, abc);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.rekey, (e, ew, _sigOf(1, h.epoch(e)))),
            IPqChat.PqChatRemovedKept.selector, "pqchat: a child keeping a removed member");
    }

    function _post() internal {
        IPqChat.PqChatMessage memory m = _msg(e2, 0, 0);
        IUARegistry.UASig memory sg = _sigOf(0, h.message(m));
        vm.broadcast(k2);
        require(chat.postMessage(m, sg) == 0, "message index");
        (IPqChat.PqChatMessage memory back, bytes32 sh) = chat.messageAt(sid, 0);
        require(back.device == dv && sh == keccak256(abi.encode(sg)) && chat.messageCount(sid) == 1, "messageAt");
        require(chat.nonceUsed(PqChatTypes.scopeMessage(e2, uas[0], dv), 0), "nonceUsed");
    }

    /// @dev B leaves epoch 2; A (the admin) removes C from it (UA-7 P48); C's rekey of epoch 2 and a child keeping C are
    ///      refused; A's rekey dropping both lands (plain: B left, C was removed); B is then no member.
    function _leaveAndDrop() internal {
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, e2, uas[1], 9);
        IUARegistry.UASig memory sg = _sigOf(1, h.leave(l));
        vm.broadcast(k2);
        chat.leave(l, sg);
        require(chat.leftIn(e2, uas[1]), "leftIn");
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid, e2, 3, _uas(_ids(2)), uas[0], sn + 20);
        sg = _sigOf(0, h.remove(r));
        vm.broadcast(k2);
        chat.remove(r, sg);
        require(chat.removedIn(e2, uas[2]) && chat.removalCount(e2) == 1, "removedIn, removalCount");
        (IPqChat.PqChatRemove memory rb,) = chat.removalAt(e2, 0);
        require(rb.admin == uas[0] && rb.members.length == 1, "removalAt");
        bytes32[] memory admins = _uas(_ids(0));
        (IPqChat.PqChatEpoch memory e3, IPqChat.Wrap[] memory w3) = _epoch(sid, 0, sn + 21, 3, e2, admins, _ids(0));
        sg = _sigOf(0, h.epoch(e3));
        vm.broadcast(k2);
        bytes32 id3 = chat.rekey(e3, w3, sg);
        require(chat.latestEpoch(sid) == id3 && chat.epochComplete(id3), "latestEpoch after the drop");
        IPqChat.PqChatMessage memory nm = _msg(id3, 1, 0);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.postMessage, (nm, _sigOf(1, h.message(nm)))),
            IPqChat.PqChatNotMember.selector, "pqchat: postMessage by a non-member");
        nm = _msg(e2, 0, 1);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.postMessage, (nm, _sigOf(0, h.message(nm)))),
            IPqChat.PqChatEpochTaken.selector, "pqchat: postMessage under a superseded epoch (Fable P1-1)");
    }

    /// @dev storeMessage: direct by test key 3, and relayed unsigned through the router.
    function _store() internal {
        bytes8 hint = bytes8(_salt("hint"));
        bytes memory env = bytes.concat(keccak256("envelope a"), keccak256("envelope b"));
        vm.broadcast(k3);
        require(chat.storeMessage(1, hint, env) == 0, "stored index");
        _relayed(address(chat), abi.encodeCall(IPqChat.storeMessage, (uint8(1), hint, env)));
        require(chat.storedCount(hint) == 2, "storedCount");
        require(keccak256(chat.storedAt(hint, 1)) == keccak256(abi.encode(uint8(1), hint, env)), "storedAt");
        require(chat.storedRange(hint, 0, 100).length == 2 && chat.STORED_RANGE_MAX() == 16, "storedRange");
        _neg(a3, address(chat), abi.encodeCall(IPqChat.storeMessage, (uint8(2), hint, env)), IPqChat.PqChatShape.selector,
            "pqchat: storeMessage of a version other than 1");
    }

    // ------------------------------------------------------------------ public topics and votes (the module)

    function _topics() internal {
        _topic();
        _entries();
        _votes();
    }

    function _topic() internal {
        IPqChat.PqTopic memory t;
        (t.owner, t.nonce, t.homeChain, t.homeChatContract, t.name, t.about, t.openReplies) =
            (uas[0], uint64(uint256(_salt("topic")) >> 200), uid, address(chat), "onchain", bytes("matrix"), true);
        IUARegistry.UASig memory sg = _sigOf(0, h.topic(t));
        vm.broadcast(k2);
        tid = chat.createTopic(t, sg);
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(tid, 1, "onchain 2", bytes("matrix 2"), true);
        sg = _sigOf(0, h.topicUpdate(u));
        vm.broadcast(k2);
        chat.updateTopic(u, sg);
        (IPqChat.PqTopic memory tb, uint64 seq) = chat.topicOf(tid);
        require(seq == 1 && keccak256(bytes(tb.name)) == keccak256("onchain 2"), "topicOf");
        IPqChat.PqTopicWriter memory wr = IPqChat.PqTopicWriter(tid, uas[1], true, 1);
        sg = _sigOf(0, h.topicWriter(wr));
        vm.broadcast(k2);
        chat.setTopicWriter(wr, sg);
        (bool granted,) = chat.writerOf(tid, uas[1]);
        require(granted, "writerOf");
    }

    function _entries() internal {
        IPqChat.PqTopicEntry memory p;
        (p.topicId, p.author, p.nonce, p.mediaType, p.body) = (tid, uas[1], 1, "text/markdown", bytes("a post"));
        IUARegistry.UASig memory sg = _sigOf(1, h.entry(p));
        vm.broadcast(k2);
        pid = chat.postEntry(p, sg);
        IPqChat.PqTopicEntry memory q;
        (q.topicId, q.author, q.nonce, q.parentId, q.mediaType, q.body) = (tid, uas[2], 1, pid, "text/plain", bytes("a reply"));
        sg = _sigOf(2, h.entry(q));
        vm.broadcast(k2);
        chat.postEntry(q, sg);
        IPqChat.PqTopicEdit memory d = IPqChat.PqTopicEdit(pid, uas[1], 2, 2, "text/markdown", bytes("a post, edited"));
        sg = _sigOf(1, h.edit(d));
        vm.broadcast(k2);
        chat.editEntry(d, sg);
        IPqChat.EntryView memory ev = chat.entryOf(pid);
        require(ev.versionCount == 2 && keccak256(ev.body) == keccak256("a post, edited"), "entryOf");
        (, uint256 n) = chat.replies(pid, 0, 0);
        require(n == 1, "replies");
    }

    function _votes() internal {
        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(pid, uas[0], 1, 1);
        IUARegistry.UASig memory sg = _sigOf(0, h.vote(v));
        vm.broadcast(k2);
        chat.voteEntry(v, sg);
        v = IPqChat.PqTopicVote(pid, uas[0], -1, 2);
        sg = _sigOf(0, h.vote(v));
        vm.broadcast(k2);
        chat.voteEntry(v, sg);
        (uint128 up, uint128 down) = chat.scoreOf(pid);
        require(up == 0 && down == 1, "scoreOf: one count moved");
        v = IPqChat.PqTopicVote(pid, uas[2], 2, 1);
        _neg(a2, address(chat), abi.encodeCall(IPqChat.voteEntry, (v, _sigOf(2, h.vote(v)))),
            IPqChat.PqTopicVoteValue.selector, "pqchat: a vote value of 2");
    }
}
