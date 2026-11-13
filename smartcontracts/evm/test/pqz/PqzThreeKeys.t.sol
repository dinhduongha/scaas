// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {nid} from "../helpers/Ids.sol";

/// @notice The three-key model on the token (spec 2026-11-13 pqz-three-keys, CTR-PQZ-37 .. -41, CTR-UA-43; §14 items 3, 4,
///         5, 6, 11, 15, 16, 17, 20, contract side). Four tokens: `pre` class `registry` (`PRECOMPILE`), `c2`
///         `offchain-shared`, `c3o` `offchain-token` with the sealed opening, `c3` without it. Holders' signatures are the
///         fixture's mocked ML-DSA, so where a test needs the signed digest to matter it lets the registry accept exactly
///         one digest (`_onlyDigest`). Every negative has its control next to it and changes one thing. UNAUDITED.
contract PqzThreeKeysTest is PqzOffchainBase {
    NormalPqzToken internal pre;
    NormalPqzToken internal c2;
    NormalPqzToken internal c3o;
    NormalPqzToken internal c3;

    bytes32 internal constant ROLL_TH = keccak256(
        "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)"
    );
    uint256 internal constant RKEY = 0x5E1A; // an address envelope's signer (the relayed path of `executeMetaTransaction`)

    function setUp() public {
        vm.pauseGasMetering(); // one transaction (Amsterdam's 2^24 cap): four tokens and their holders' 18 KB records
        _offStack();
        pre = _newToken("tk-pre");
        c2 = _mk(false, true, "tk-c2");
        c3o = _mk(true, true, "tk-c3o");
        c3 = _mk(true, false, "tk-c3");
        vm.resumeGasMetering();
    }

    function _mk(bool own, bool open, bytes32 s) internal returns (NormalPqzToken t) {
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, vA, own, open);
        t = _newToken(s);
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
    }

    // ------------------------------------------------------------------ helpers

    function _bytesN(uint256 seed, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i / 32))) >> (8 * (i % 32))));
    }

    function _opening(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
            (_bytesN(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _bytesN(seed + 1, PqzCore.SEALED_SEED));
    }

    function _oBytes(IPqzToken.PqzOpening memory o) internal pure returns (bytes memory) {
        return abi.encodePacked(o.mlkemCt, o.x25519Eph, o.sealedSeed);
    }

    /// Op 1 of `from` to `to` at `p` (no fee, BUNDLE): on an opening token with `uFrom` and the openings.
    function _op1At(NormalPqzToken t, bytes32 from, bytes32 to, uint256 p, uint256 seed, bool withAud)
        internal view returns (IPqzToken.PqzTransferArgs memory a)
    {
        a = _ts(_payload(p, 0, from, to, bytes32(0), _out(seed, withAud), ""));
        if (t.pqzVerifyConfig().pqzOpening) {
            a.uFrom = _blob(seed + 7, PqzCt.PK);
            a.openingTo = _opening(seed);
            if (withAud) a.openingAuditor = _opening(seed + 3);
        }
    }

    function _op1(NormalPqzToken t, bytes32 from, bytes32 to, uint256 seed, bool withAud)
        internal view returns (IPqzToken.PqzTransferArgs memory a, bytes memory st)
    {
        a = _op1At(t, from, to, t.pqzAccount(from, 0).pendingCount, seed, withAud);
        st = t.transferSingleStatement(a, 0);
    }

    function _send(NormalPqzToken t, IPqzToken.PqzTransferArgs memory a) internal returns (bytes32) {
        return t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, t.transferSingleStatement(a, 0)));
    }

    function _key(address ptr) internal view returns (bytes memory) {
        return _slice(ptr.code, 1, PqzCt.PK);
    }

    function _scopedKey(bytes32 ua, address scope, uint64 v) internal view returns (bytes memory) {
        (address p,,) = reg.pqzScopedKeyAt(ua, scope, v);
        return _key(p);
    }

    /// The registry accepts `ua`'s `zether-auth` signature `_pqAuth()` over `d` only (exact calldata wins over the prefix).
    function _onlyDigest(bytes32 ua, bytes32 d) internal {
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, ua,
            UAKinds.PURPOSE_ZETHER_AUTH), "another digest");
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_ZETHER_AUTH, d, _pqAuth())), "");
    }

    /// Every `zether-auth` signature of `ua` accepted again (the prefix mock replaced).
    function _anyDigest(bytes32 ua) internal {
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, ua,
            UAKinds.PURPOSE_ZETHER_AUTH), "");
    }

    /// The client's `h(i)` (CTR-PQZ-41): the slot without the mark, the blob's code hash or 0 for a TRIVIAL entry.
    function _eh(NormalPqzToken t, bytes32 ua, uint64 v, uint256 i) internal view returns (bytes32) {
        uint256 e = t.pqzPending(ua, v, uint64(i)) & ~uint256(PqzCore.SKIP);
        bytes32 c = uint16(e >> 64) == 0 ? bytes32(0) : address(uint160(e >> 96)).codehash;
        return keccak256(abi.encode(i, e, c));
    }

    function _entries(NormalPqzToken t, bytes32 ua, uint64 v, uint64 n, uint64[] memory skip) internal view returns (bytes32) {
        uint64 r = t.pqzAccount(ua, v).rolled;
        bytes32[] memory h = new bytes32[](n + skip.length);
        for (uint256 k; k < n; ++k) h[k] = _eh(t, ua, v, r + k);
        for (uint256 j; j < skip.length; ++j) h[n + j] = _eh(t, ua, v, skip[j]);
        return keccak256(abi.encodePacked(h));
    }

    /// The `PqzRollOver` digest a wallet signs (key version 0), from the token's state, in `domainOf`'s domain with
    /// `chainUid_`.
    function _rollDigestAt(NormalPqzToken t, address domainOf, bytes32 chainUid_, bytes32 ua, uint64 n,
        uint64[] memory skip, uint64 vub, bytes32 eh) internal view returns (bytes32)
    {
        bytes memory head = _rollHead(t, ua, n);
        return MessageHashUtils.toTypedDataHash(_sepOf(domainOf), keccak256(bytes.concat(head,
            abi.encode(keccak256(abi.encodePacked(skip)), eh, vub, chainUid_))));
    }

    function _rollHead(NormalPqzToken t, bytes32 ua, uint64 n) internal view returns (bytes memory) {
        IPqzToken.AccountState memory s = t.pqzAccount(ua, 0);
        return abi.encode(ROLL_TH, ua, uint64(0), s.rollSeq, s.rolled, n);
    }

    function _rollDigest(NormalPqzToken t, bytes32 ua, uint64 v, uint64 n, uint64[] memory skip, uint64 vub)
        internal view returns (bytes32)
    {
        bytes32 eh = _entries(t, ua, v, n, skip);
        return _rollDigestAt(t, address(t), t.chainUid(), ua, n, skip, vub, eh);
    }

    function _sk(uint64 a) internal pure returns (uint64[] memory s) {
        s = new uint64[](1);
        s[0] = a;
    }

    function _none() internal pure returns (uint64[] memory) {
        return new uint64[](0);
    }

    /// alice on `t`: a TRIVIAL entry (0, 100), then credits 1 (bob), 2 (carol: the planted credit, a junk opening is all
    /// the contract would see), 3 (bob); both halves of her `acc` words prepared; `ROLL_AGE` blocks later.
    function _aliceFour(NormalPqzToken t) internal {
        _shieldOn(t, bob, 50);
        _shieldOn(t, carol, 50);
        _shieldOn(t, alice, 100);
        vm.roll(block.number + 1);
        _send(t, _op1At(t, bob, alice, 1, 31, false));
        _send(t, _op1At(t, carol, alice, 1, 32, false));
        _send(t, _op1At(t, bob, alice, 1, 33, false)); // bob's second debit: p = floor = pendingCount = 1
        assertEq(t.pqzAccount(alice, 0).pendingCount, 4);
        t.mtxPrepareAcc(alice, 0, 0);
        t.mtxPrepareAcc(alice, 0, 1);
        vm.roll(block.number + ROLL_AGE);
    }

    function _rollSigned(NormalPqzToken t, bytes32 ua, uint64 n, uint64[] memory skip) internal {
        uint64 vub = uint64(block.number + 10);
        _onlyDigest(ua, _rollDigest(t, ua, 0, n, skip, vub));
        t.mtxRollOverSigned(ua, 0, n, skip, vub, _pqAuth());
        _anyDigest(ua);
    }

    // ------------------------------------------------------------------ pins (§14 item 11)

    /// The typed structs this round adds or moves: `PqzRollOver` (new) and `PqzTransferArgs` (+ `uFrom`, the two
    /// `PqzOpening`s; its typehash and the signed single forms' move for every class). Old values in the comments.
    function test_typehashesArePinned() public pure {
        assertEq(PqzCore.ROLL_OVER_TYPEHASH, ROLL_TH);
        assertEq(PqzCore.ROLL_OVER_TYPEHASH, 0x1517899d2260def4be647ef16ee4cfb902ab2d450c3f90a4f2c14250625c41cb);
        assertEq(TH_TRANSFER_ARGS, 0x8be951c049f08446782d4e32d7e67c56807ccfd5d52ebf3f72d4515587cc429e); // was 0x377ed76d…
        assertEq(TH_OPENING, 0x531c26a9402850f12c237b772bf09bf156f7bf937147adf294049087a5237e4e);
    }

    // ------------------------------------------------------------------ the classes (CTR-PQZ-37; §14 items 3, 6)

    function _cfgWith(uint8 mode, bool own, bool open) internal returns (IFactoryToken.TokenConfig memory c) {
        (vMode, vUA) = (mode, mode == PqzCore.OFFCHAIN ? vA : bytes32(0));
        c = _cfg(uint256(1) << 40);
        (vMode, vUA) = (0, bytes32(0));
        (c.conf.pqzOwnKey, c.conf.pqzOpening) = (own, open);
    }

    function _create(IFactoryToken.TokenConfig memory c, bytes32 s) internal returns (address) {
        return factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), s);
    }

    /// The refusal on the factory path (owner 2026-11-13: no `OpenFactory` config check; the token's `init` refuses):
    /// `createToken` reverts `PqzVerifyConfigInvalid` and leaves no instance at the predicted address.
    function _refused(IFactoryToken.TokenConfig memory c, bytes32 s) internal {
        address at = factory.predictAddress(nid(address(this)), 1, uint16(uint8(IOpenFactory.TokenKind.NORMAL_PQZ)), s);
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _create(c, s);
        assertEq(at.code.length, 0, "no instance at the predicted address");
    }

    function test_config_invalidCombinations() public {
        _refused(_cfgWith(PqzCore.PRECOMPILE, true, false), "x1"); // registry + pqzOwnKey
        _refused(_cfgWith(PqzCore.PRECOMPILE, false, true), "x2"); // registry + pqzOpening
        _refused(_cfgWith(PqzCore.PRECOMPILE, true, true), "x3");
        IFactoryToken.TokenConfig memory c = _cfgWith(PqzCore.PRECOMPILE, false, false);
        c.conf.pqzVerifierUA = vA; // registry + a verifier
        _refused(c, "x4");
        c = _cfgWith(PqzCore.PRECOMPILE, false, false);
        c.conf.pqzVerifierFixed = true; // registry + fixed
        _refused(c, "x5");
        c = _cfgWith(PqzCore.PRECOMPILE, false, false);
        (c.conf.verifierFee, c.conf.verifierFeeMax) = (0, 1); // registry + a fee cap
        _refused(c, "x6");
        _refused(_cfgWith(PqzCore.OFFCHAIN, false, false), "x7"); // the shared key without the opening (ARCH-POS-13)
        c = _cfgWith(PqzCore.OFFCHAIN, true, false);
        c.conf.pqzVerifierUA = 0; // OFFCHAIN without a verifier
        _refused(c, "x8");
        // controls, one change each: the four classes, each at its predicted address
        bytes32[4] memory ss = [bytes32("y1"), "y2", "y3", "y4"];
        IFactoryToken.TokenConfig[4] memory cs = [_cfgWith(PqzCore.PRECOMPILE, false, false),
            _cfgWith(PqzCore.OFFCHAIN, false, true), _cfgWith(PqzCore.OFFCHAIN, true, false), _cfgWith(PqzCore.OFFCHAIN, true, true)];
        for (uint256 i; i < 4; ++i) {
            address at = factory.predictAddress(nid(address(this)), 1, uint16(uint8(IOpenFactory.TokenKind.NORMAL_PQZ)), ss[i]);
            assertEq(_create(cs[i], ss[i]), at, "the class's instance at the predicted address");
        }
    }

    function _word(address t, uint256 i) internal view returns (uint256) {
        (bool ok, bytes memory r) = t.staticcall(abi.encodeWithSignature("pqzVerifyConfig()"));
        assertTrue(ok);
        return uint256(bytes32(_slice(r, 32 * i, 32)));
    }

    /// The id by the flag (CTR-PQZ-38) and the two flags at words 11 and 12 (the registry's read of `pqzOpening`).
    function test_config_idsAndWords() public view {
        assertEq(pre.proofSystemId(), PqzSet.PQZL_ID);
        assertEq(c2.proofSystemId(), PqzSet.PQZL_SPLIT_ID);
        assertEq(c3o.proofSystemId(), PqzSet.PQZL_SPLIT_ID);
        assertEq(c3.proofSystemId(), PqzSet.PQZL_ID);
        NormalPqzToken[4] memory ts = [pre, c2, c3o, c3];
        uint8[4] memory own = [0, 0, 1, 1];
        uint8[4] memory open = [0, 1, 1, 0];
        for (uint256 i; i < 4; ++i) {
            assertEq(_word(address(ts[i]), 11), own[i], "pqzOwnKey, word 11");
            assertEq(_word(address(ts[i]), 12), open[i], "pqzOpening, word 12");
            assertEq(ts[i].pqzVerifyConfig().pqzOwnKey, own[i] == 1);
            assertEq(ts[i].pqzVerifyConfig().pqzOpening, open[i] == 1);
        }
    }

    // ------------------------------------------------------------------ reads by scope (CTR-UA-43; §14 item 6, review C-3)

    bytes32 internal dan;

    /// `dan`: registry versions 0, 1 (current 1); scope 0 versions 0 .. 3 (current 3): a wrong read cannot pass by accident.
    function _dan() internal {
        dan = _pqzUA(_pk(60), 60);
        reg.setPqzKey(dan, 1, _pk(61), keccak256("d1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(dan, 1, "d1");
        for (uint256 v; v < 4; ++v) _scoped(dan, address(0), _spk(0x6000 + v), true);
        (uint64 rc,,,) = reg.pqzKeyOf(dan);
        (uint64 sc,,,) = reg.pqzScopedKeyOf(dan, address(0));
        assertEq(rc, 1, "registry current");
        assertEq(sc, 3, "scoped current");
    }

    function test_reads_creditByShield() public {
        _dan();
        _shieldOn(c2, dan, 5);
        assertEq(c2.pqzAccount(dan, 3).pendingCount, 1, "offchain-shared: scope 0's current");
        _shieldOn(pre, dan, 5);
        assertEq(pre.pqzAccount(dan, 1).pendingCount, 1, "registry: the registry's current");
    }

    function test_reads_creditByTransfer() public {
        _dan();
        _shieldOn(c2, alice, 10);
        _send(c2, _op1At(c2, alice, dan, 0, 5, true));
        assertEq(c2.pqzAccount(dan, 3).pendingCount, 1, "the credit in scope 0's current version");
    }

    function test_reads_debitCurrentAndAuditor() public {
        _dan();
        _shieldOn(c2, dan, 10);
        IPqzToken.PqzTransferArgs memory a = _op1At(c2, dan, bob, 1, 6, true);
        a.keyVersion = 3;
        bytes memory st = c2.transferSingleStatement(a, 0);
        assertEq(_slice(st, 640, PqzCt.PK), _scopedKey(dan, address(0), 3), "pk_f: scope 0 version 3");
        assertEq(_slice(st, 640 + 2 * PqzCt.PK, PqzCt.PK), _scopedKey(aud, address(0), 0), "pk_a: the auditor's scope-0 key");
        c2.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(c2, st));
    }

    /// The migration (`to == from`) from stale version 2, which the registry does not have.
    function test_reads_debitStale() public {
        _dan();
        IPqzToken.PqzTransferArgs memory a = _op1At(c2, dan, dan, 0, 7, false);
        a.keyVersion = 2;
        bytes memory st = c2.transferSingleStatement(a, 0);
        assertEq(_slice(st, 640, PqzCt.PK), _scopedKey(dan, address(0), 2), "pk_f: scope 0 version 2");
        assertEq(_slice(st, 640 + PqzCt.PK, PqzCt.PK), _scopedKey(dan, address(0), 3), "pk_t: scope 0 current");
    }

    function test_reads_prepareAcc() public {
        _dan();
        c2.mtxPrepareAcc(dan, 3, 0); // version 3 exists in scope 0 only
        assertEq(c2.pqzAccount(dan, 3).flags & 2, 2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, dan));
        c2.mtxPrepareAcc(dan, 4, 0); // control: no version 4
    }

    function test_reads_disclosure() public {
        _dan();
        _shieldOn(c2, alice, 10);
        bytes32 ref = _send(c2, _op1At(c2, alice, dan, 0, 8, false));
        bytes memory st = c2.disclosureStatement(ref, 0, 3, 0, 3);
        assertEq(_slice(st, 288, PqzCt.PK), _scopedKey(dan, address(0), 3), "the owner's scope-0 key of version 3");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyVersionUnknown.selector, dan, uint64(4)));
        c2.disclosureStatement(ref, 0, 3, 0, 4);
    }

    /// An opening token reads no registry key on any path (§14 item 6).
    function test_reads_neverRegistryKey() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.pqzKeyOf.selector), 0);
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.pqzKeyAt.selector), 0);
        _shieldOn(c2, alice, 20);
        bytes32 ref = _send(c2, _op1At(c2, alice, bob, 1, 9, true));
        c2.disclosureStatement(ref, 0, 3, 0, 0);
        c2.mtxPrepareAcc(alice, 0, 0);
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(c2, alice, 0, 0, 10);
        c2.mtxUnshield(b, 0, 0, VPROOF, _pqAuth(), "", _sv(c2, bst));
    }

    /// `offchain-token`: the token's own scope; a record of token A is not usable on token B.
    function test_reads_class3OwnScope() public {
        bytes32 ed = _mldsaUA(62);
        _public(c3, address(this), 2 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, ed));
        c3.mtxShield(ed, 1);
        _scoped(ed, address(c3o), _spk(0x6100), true); // token A's record
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, ed));
        c3.mtxShield(ed, 1); // not token B's
        _shieldOn(c3o, ed, 1);
        assertEq(c3o.pqzAccount(ed, 0).pendingCount, 1);
    }

    // ------------------------------------------------------------------ op 1 with the opening (CTR-PQZ-38, -40)

    function _checkOpening(NormalPqzToken t, bool withAud) internal {
        _shieldOn(t, alice, 20);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1(t, alice, bob, 11, withAud);
        assertEq(st.length, withAud ? PqzSet.STMT_TRANSFER_SPLIT : PqzSet.STMT_TRANSFER_SPLIT0, "the split statement");
        assertEq(_slice(st, st.length - PqzCt.PK, PqzCt.PK), a.uFrom, "u_f last");
        bytes memory os = withAud ? bytes.concat(_oBytes(a.openingTo), _oBytes(a.openingAuditor)) : _oBytes(a.openingTo);
        assertEq(bytes32(_slice(st, 608, 32)), keccak256(abi.encodePacked(abi.encodePacked(a.ownTag), keccak256(os))),
            "memoHash covers the openings");
        bytes32 ref = t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, st));
        bytes memory out = _out(11, withAud);
        bytes memory r = _rOf(out, bob);
        bytes memory blob = t.pqzEntryBlob(ref);
        assertEq(_slice(blob, 0, r.length), r, "R unchanged");
        bytes memory tail = bytes.concat(_packed(a.uFrom), _packed(a.vFrom), os);
        assertEq(_slice(blob, r.length, tail.length), tail, "P(u_f) | P(v_f) | O_t | [O_a]");
        assertEq(blob.length, r.length + tail.length + 33 + 8 * (withAud ? 2 : 1), "then ownTag | kv | n");
        assertEq(t.transferEntry(ref), r, "transferEntry is R");
        assertEq(t.transferCiphertextHash(ref), keccak256(r));
        assertEq(t.pqzAcc(alice, 0), bytes.concat(a.uFrom, a.vFrom), "acc = (u_f, v_f)");
        uint64 i = t.pqzAccount(bob, 0).pendingCount - 1;
        assertEq(t.pqzPendingCt(bob, 0, i), _slice(out, 0, PqzCt.CT), "the credit (u, v_t)");
    }

    function test_opening_op1_class2() public {
        _checkOpening(c2, true);
        _checkOpening(c2, false);
    }

    function test_opening_op1_class3() public {
        _checkOpening(c3o, true);
        _checkOpening(c3o, false);
    }

    /// The statement and the blob of an opening-off token are today's (control of the flag mutant, §14 item 11).
    function test_opening_off_unchanged() public {
        _shieldOn(c3, alice, 20);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1(c3, alice, bob, 12, true);
        assertEq(st.length, PqzSet.STMT_TRANSFER);
        assertEq(bytes32(_slice(st, 608, 32)), keccak256(abi.encodePacked(a.ownTag)), "memoHash without the openings");
        bytes32 ref = c3.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(c3, st));
        assertEq(c3.pqzEntryBlob(ref).length, _rOf(_out(12, true), bob).length + PqzCt.VP + 33 + 16);
    }

    function _refuse(NormalPqzToken t, IPqzToken.PqzTransferArgs memory a, bytes memory err) internal {
        vm.expectRevert(err);
        t.transferSingleStatement(a, 0);
    }

    function _bp(uint256 n) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IPqzToken.BadPayload.selector, n);
    }

    /// §14 item 3: the opening's parts by length, each against its control.
    function test_opening_lengths() public {
        _shieldOn(c2, alice, 20);
        (IPqzToken.PqzTransferArgs memory g,) = _op1(c2, alice, bob, 13, true); // control: builds
        IPqzToken.PqzTransferArgs memory a = g;
        a.uFrom = "";
        _refuse(c2, a, _bp(0));
        (a,) = _op1(c2, alice, bob, 13, true);
        a.uFrom = _slice(a.uFrom, 0, PqzCt.PK - 8);
        _refuse(c2, a, _bp(PqzCt.PK - 8));
        (a,) = _op1(c2, alice, bob, 13, true);
        a.openingTo.mlkemCt = _slice(a.openingTo.mlkemCt, 0, 1567);
        _refuse(c2, a, _bp(1567));
        (a,) = _op1(c2, alice, bob, 13, true);
        a.openingTo.sealedSeed = _slice(a.openingTo.sealedSeed, 0, 47);
        _refuse(c2, a, _bp(47));
        (a,) = _op1(c2, alice, bob, 13, true);
        delete a.openingAuditor; // the auditor copy on, its opening missing
        _refuse(c2, a, _bp(0));
        (a,) = _op1(c2, alice, bob, 13, false);
        a.openingAuditor = _opening(5); // no auditor copy, an opening for it
        _refuse(c2, a, _bp(PqzCore.MLKEM_CT));
        (a,) = _op1(c2, alice, bob, 13, true);
        a.uFrom = new bytes(PqzCt.PK);
        _refuse(c2, a, abi.encodeWithSelector(IPqzToken.ZeroU.selector));
        (a,) = _op1(c2, alice, bob, 13, true);
        a.uFrom[0] = 0xff;
        _refuse(c2, a, abi.encodeWithSelector(IPqzToken.NonCanonical.selector));
        // opening off: every part empty
        _shieldOn(c3, alice, 20);
        (a,) = _op1(c3, alice, bob, 13, true);
        a.uFrom = _blob(1, PqzCt.PK);
        _refuse(c3, a, _bp(PqzCt.PK));
        (a,) = _op1(c3, alice, bob, 13, true);
        a.openingTo = _opening(6);
        _refuse(c3, a, _bp(PqzCore.MLKEM_CT));
        (a,) = _op1(c3, alice, bob, 13, true);
        a.openingTo.x25519Eph = bytes32(uint256(1));
        _refuse(c3, a, _bp(0));
        (a,) = _op1(c3, alice, bob, 13, true);
        c3.transferSingleStatement(a, 0); // control
    }

    /// §14 item 3: a relayer that swaps `openingTo` changes the statement (header word 19): the verdict and `pqzAuth`
    /// over it no longer match.
    function test_opening_swapRefused() public {
        _shieldOn(c2, alice, 20);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1(c2, alice, bob, 14, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(c2, st);
        IPqzToken.PqzTransferArgs memory b = a;
        b.openingTo = _opening(99);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerdictMismatch.selector, uint8(3)));
        c2.mtxConfidentialTransferSingle(b, VPROOF, _pqAuth(), "", sv);
        (a,) = _op1(c2, alice, bob, 14, true);
        c2.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv); // control
    }

    /// CTR-PQZ-40: an opening blob with the auditor at the build's set stays below the `uint16` offsets and 64 KiB.
    function test_opening_blobSize() public pure {
        uint256 len = 16 + PqzCt.PKP + 3 * PqzCt.VP + 32 + PqzCt.PKP + 2 * PqzCore.OPEN + 33 + 16;
        assertLt(len, 1 << 16);
    }

    // ------------------------------------------------------------------ op 7 and the disclosures (CTR-PQZ-39, -14)

    function test_op7_unsupportedWithOpening() public {
        bytes32[] memory legs = new bytes32[](1);
        legs[0] = bob;
        IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(0, 0, alice, bytes32(0), legs, _blob(15, _outLen(1, false)), ""));
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c2.transferStatement(m, 0);
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c3o.transferStatement(m, 0);
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c2.mtxConfidentialTransfer(m, VPROOF, _pqAuth(), "", noVerdict());
        c3.transferStatement(m, 0); // control: opening off
    }

    function test_disclosure_senderOnlyWithOpening() public {
        _shieldOn(c2, alice, 20);
        bytes32 ref = _send(c2, _op1At(c2, alice, bob, 1, 16, true));
        bytes memory st = c2.disclosureStatement(ref, 0, 3, 0, 0);
        assertEq(bytes32(_slice(st, 32, 32)), PqzSet.PQZL_SPLIT_ID, "SENDER_S under the split id");
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c2.disclosureStatement(ref, 0, 3, 1, 0);
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c2.disclosureStatement(ref, 0, 3, 2, 0);
        IPqzToken.PqzSignedVerdict memory sv = _sv(c2, st);
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        c2.verifyTransferAmount(ref, 0, 3, 1, 0, VPROOF, sv);
        // control: opening off, all three kinds
        _shieldOn(c3, alice, 20);
        bytes32 r3 = _send(c3, _op1At(c3, alice, bob, 1, 17, true));
        c3.disclosureStatement(r3, 0, 3, 1, 0);
        c3.disclosureStatement(r3, 0, 3, 2, 0);
    }

    // ------------------------------------------------------------------ the signed rollover (CTR-PQZ-41; §14 items 4, 5, 15, 20)

    function test_roll_publicRefusedWithOpening() public {
        vm.expectRevert(IPqzToken.RollOverSignedOnly.selector);
        c2.mtxRollOver(alice, 0, 1);
        vm.expectRevert(IPqzToken.RollOverSignedOnly.selector);
        c3o.mtxRollOver(alice, 0, 1);
        vm.expectRevert(IPqzToken.OpUnsupported.selector); // the signed form without the opening
        c3.mtxRollOverSigned(alice, 0, 1, _none(), uint64(block.number), _pqAuth());
        vm.expectRevert(IPqzToken.OpUnsupported.selector);
        pre.mtxRollOverSigned(alice, 0, 1, _none(), uint64(block.number), _pqAuth());
    }

    /// The planted credit (§14 item 1, contract side): marked by the holder's signed rollover, it adds zero; it still counts
    /// one unit; the slot, its blob and its ciphertext stay; the next debit proves over a `T` without it.
    function test_roll_markAndRoll() public {
        _aliceFour(c2);
        bytes memory want = ct.sumMixed(new bytes(PqzCt.CT), _two(c2, 1, 3), _amt(100));
        uint64 vub = uint64(block.number + 10);
        bytes32 d = _rollDigest(c2, alice, 0, 4, _sk(2), vub);
        _onlyDigest(alice, d);
        vm.expectEmit(address(c2));
        emit IPqzToken.PqzSkipped(alice, 0, 2);
        vm.expectEmit(true, true, false, false, address(c2));
        emit IPqzToken.PqzRolledOver(alice, 0, 4, 4, 0);
        c2.mtxRollOverSigned(alice, 0, 4, _sk(2), vub, _pqAuth());
        assertTrue(c2.pqzSkipped(alice, 0, 2));
        assertFalse(c2.pqzSkipped(alice, 0, 1));
        assertEq(c2.pqzPending(alice, 0, 2) & PqzCore.SKIP, PqzCore.SKIP, "the mark in the slot's block field");
        assertEq(c2.pqzAcc(alice, 0), want, "the marked credit adds zero");
        IPqzToken.AccountState memory s = c2.pqzAccount(alice, 0);
        assertEq(s.rolled, 4);
        assertEq(s.accUnits, 4, "four entries rolled: the mark counts one unit");
        assertEq(s.rollSeq, 1);
        assertEq(c2.pqzPendingCt(alice, 0, 2).length, PqzCt.CT, "the ciphertext stays");
        // the same call again: the state moved (nothing left to roll)
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, uint256(4)));
        c2.mtxRollOverSigned(alice, 0, 4, _sk(2), vub, _pqAuth());
        _anyDigest(alice);
        // the next debit proves over `acc` (rolled = pendingCount)
        IPqzToken.PqzTransferArgs memory a = _op1At(c2, alice, bob, 4, 18, false);
        bytes memory st = c2.transferSingleStatement(a, 0);
        assertEq(_slice(st, 640 + 2 * PqzCt.PK, PqzCt.CT), want, "T without the marked credit");
        c2.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(c2, st));
    }

    function _two(NormalPqzToken t, uint64 i, uint64 j) internal view returns (bytes[] memory c) {
        c = new bytes[](2);
        (c[0], c[1]) = (t.pqzPendingCt(alice, 0, i), t.pqzPendingCt(alice, 0, j));
    }

    function _amt(uint256 x) internal pure returns (uint256[] memory a) {
        a = new uint256[](1);
        a[0] = x;
    }

    /// §14 items 5, 20: a debit's window skips a marked slot, before and after an un-roll; marks are never cleared.
    function test_roll_marksInWindowsAndUnroll() public {
        _aliceFour(c2);
        uint64 vub = uint64(block.number + 10);
        _onlyDigest(alice, _rollDigest(c2, alice, 0, 0, _sk(2), vub));
        c2.mtxRollOverSigned(alice, 0, 0, _sk(2), vub, _pqAuth()); // mark only: no rollover
        assertEq(c2.pqzAccount(alice, 0).rolled, 0);
        assertEq(c2.pqzAccount(alice, 0).rollSeq, 1);
        // replay (§14 item 4): the same signature, every other input as signed; only `rollSeq` moved
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        c2.mtxRollOverSigned(alice, 0, 0, _sk(2), vub, _pqAuth());
        _anyDigest(alice);
        IPqzToken.PqzTransferArgs memory a = _op1At(c2, alice, bob, 4, 19, false);
        bytes memory st = c2.transferSingleStatement(a, 0);
        assertEq(_slice(st, 640 + 2 * PqzCt.PK, PqzCt.CT), ct.sumMixed(new bytes(PqzCt.CT), _two(c2, 1, 3), _amt(100)),
            "a debit's window: the mark adds zero");
        // roll all four, then a debit below `rolled` (un-roll [2, 4)): T = acc - entry 3 (entry 2 adds zero both ways)
        _rollSigned(c2, alice, 4, _none());
        bytes[] memory one = new bytes[](1);
        one[0] = c2.pqzPendingCt(alice, 0, 1);
        a = _op1At(c2, alice, bob, 2, 20, false);
        st = c2.transferSingleStatement(a, 0);
        assertEq(_slice(st, 640 + 2 * PqzCt.PK, PqzCt.CT), ct.sumMixed(new bytes(PqzCt.CT), one, _amt(100)), "un-roll");
        c2.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(c2, st));
        assertTrue(c2.pqzSkipped(alice, 0, 2), "never cleared by a debit");
        // re-roll [2, 4): acc = (u_f, v_f) + entry 3
        vm.roll(block.number + ROLL_AGE);
        _rollSigned(c2, alice, 2, _none());
        bytes[] memory p = new bytes[](2);
        (p[0], p[1]) = (bytes.concat(a.uFrom, a.vFrom), c2.pqzPendingCt(alice, 0, 3));
        uint256[] memory z = new uint256[](0);
        assertEq(c2.pqzAcc(alice, 0), ct.sumMixed(new bytes(PqzCt.CT), p, z), "re-roll: the mark adds zero again");
        assertTrue(c2.pqzSkipped(alice, 0, 2), "never cleared by a rollover");
    }

    /// §14 item 20: a mark below `rolled` is refused (nothing in `acc` can be marked).
    function test_roll_markBelowRolledRefused() public {
        _aliceFour(c2);
        _rollSigned(c2, alice, 3, _none());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.SkipRange.selector, uint256(2)));
        c2.mtxRollOverSigned(alice, 0, 0, _sk(2), uint64(block.number + 5), _pqAuth());
        _rollSigned(c2, alice, 0, _sk(3)); // control: at `rolled`
    }

    function test_roll_skipListRules() public {
        _aliceFour(c2);
        uint64 vub = uint64(block.number + 5);
        uint64[] memory s = new uint64[](2);
        (s[0], s[1]) = (3, 2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.SkipRange.selector, uint256(2)));
        c2.mtxRollOverSigned(alice, 0, 0, s, vub, _pqAuth()); // not ascending
        (s[0], s[1]) = (2, 2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.SkipRange.selector, uint256(2)));
        c2.mtxRollOverSigned(alice, 0, 0, s, vub, _pqAuth()); // not strictly
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.SkipRange.selector, uint256(4)));
        c2.mtxRollOverSigned(alice, 0, 0, _sk(4), vub, _pqAuth()); // past pendingCount
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.SkipTrivial.selector, uint256(0)));
        c2.mtxRollOverSigned(alice, 0, 0, _sk(0), vub, _pqAuth()); // a TRIVIAL entry
        uint64[] memory long = new uint64[](PqzCore.ROLL_MAX + 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, PqzCore.ROLL_MAX + 1));
        c2.mtxRollOverSigned(alice, 0, 0, long, vub, _pqAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, PqzCore.ROLL_MAX + 1));
        c2.mtxRollOverSigned(alice, 0, uint64(PqzCore.ROLL_MAX + 1), _none(), vub, _pqAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, uint256(0)));
        c2.mtxRollOverSigned(alice, 0, 0, _none(), vub, _pqAuth()); // nothing to do
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, uint256(5)));
        c2.mtxRollOverSigned(alice, 0, 5, _none(), vub, _pqAuth()); // past pendingCount
        vm.roll(vub + 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.Expired.selector, uint256(vub)));
        c2.mtxRollOverSigned(alice, 0, 0, _sk(2), vub, _pqAuth());
        s[1] = 3;
        (s[0], s[1]) = (1, 3);
        _rollSigned(c2, alice, 0, s); // control
        assertTrue(c2.pqzSkipped(alice, 0, 1) && c2.pqzSkipped(alice, 0, 3));
    }

    /// §14 items 4, 15: the signature binds the token (domain), the chain word, `rolled` and the entries' contents.
    function test_roll_signatureBinds() public {
        _aliceFour(c2);
        uint64 vub = uint64(block.number + 10);
        bytes32[] memory bad = _badDigests(vub);
        for (uint256 i; i < bad.length; ++i) {
            _onlyDigest(alice, bad[i]);
            vm.expectRevert(IPqzToken.AuthRejected.selector);
            c2.mtxRollOverSigned(alice, 0, 4, _sk(2), vub, _pqAuth());
        }
        _onlyDigest(alice, _rollDigest(c2, alice, 0, 4, _sk(2), vub));
        c2.mtxRollOverSigned(alice, 0, 4, _sk(2), vub, _pqAuth()); // control
    }

    /// Digests of the call `(alice, 0, 4, [2], vub)` with one thing changed each.
    function _badDigests(uint64 vub) internal view returns (bytes32[] memory bad) {
        uint64[] memory sk = _sk(2);
        bytes32 eh = _entries(c2, alice, 0, 4, sk);
        bytes32 cu = c2.chainUid();
        bad = new bytes32[](5);
        bad[0] = _rollDigestAt(c2, address(c3o), cu, alice, 4, sk, vub, eh); // another token's domain
        bad[1] = _rollDigestAt(c2, address(c2), keccak256("other chain"), alice, 4, sk, vub, eh); // another chain word
        bad[2] = _rollDigestAt(c2, address(c2), cu, alice, 4, sk, vub, keccak256("other contents")); // a reorg's entries
        bad[3] = _rollDigestAt(c2, address(c2), cu, alice, 4, sk, vub + 1, eh); // another expiry than the call's
        bad[4] = _rollDigestAt(c2, address(c2), cu, alice, 3, sk, vub, _entries(c2, alice, 0, 3, sk)); // another n
    }

    /// §14 item 15: the same index holding other contents (another blob, here: the credit at index 1 replaced by a
    /// same-index credit of a parallel history) is `AuthRejected`; a TRIVIAL entry whose amount a same-block shield merged
    /// after the signature is refused too.
    function test_roll_contentBinding() public {
        _aliceFour(c2);
        uint64 vub = uint64(block.number + 20);
        // a wallet that saw entry 1 as another blob: its h(1) differs
        bytes32[] memory h = new bytes32[](4);
        for (uint256 k; k < 4; ++k) h[k] = _eh(c2, alice, 0, k);
        uint256 e1 = c2.pqzPending(alice, 0, 1);
        address other = address(uint160(c2.pqzPending(alice, 0, 3) >> 96));
        h[1] = keccak256(abi.encode(uint256(1), e1, other.codehash));
        bytes32 d = _rollDigestAt(c2, address(c2), c2.chainUid(), alice, 4, _none(), vub, keccak256(abi.encodePacked(h)));
        _onlyDigest(alice, d);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        c2.mtxRollOverSigned(alice, 0, 4, _none(), vub, _pqAuth());
        _anyDigest(alice);
        // a TRIVIAL tail of this block, signed, then merged
        _shieldOn(c2, alice, 7);
        uint64 n = c2.pqzAccount(alice, 0).pendingCount;
        assertEq(n, 5);
        bytes32 d5 = _rollDigest(c2, alice, 0, 5, _none(), vub);
        _shieldOn(c2, alice, 1); // merged into entry 4 (same block)
        assertEq(c2.pqzAccount(alice, 0).pendingCount, 5);
        vm.roll(block.number + ROLL_AGE);
        _onlyDigest(alice, d5);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        c2.mtxRollOverSigned(alice, 0, 5, _none(), vub, _pqAuth());
        _onlyDigest(alice, _rollDigest(c2, alice, 0, 5, _none(), vub));
        c2.mtxRollOverSigned(alice, 0, 5, _none(), vub, _pqAuth()); // control: over the merged amount
    }

    /// §14 item 4: a stale `rolled` after an un-roll (a debit below `rolled` between the signature and the call).
    function test_roll_staleRolledRefused() public {
        _aliceFour(c2);
        _rollSigned(c2, alice, 3, _none());
        uint64 vub = uint64(block.number + 20);
        bytes32 d = _rollDigest(c2, alice, 0, 1, _none(), vub); // rolled 3
        _send(c2, _op1At(c2, alice, bob, 2, 21, false)); // rolled = 2
        _onlyDigest(alice, d);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        c2.mtxRollOverSigned(alice, 0, 1, _none(), vub, _pqAuth());
        vm.roll(block.number + ROLL_AGE);
        _onlyDigest(alice, _rollDigest(c2, alice, 0, 1, _none(), vub));
        c2.mtxRollOverSigned(alice, 0, 1, _none(), vub, _pqAuth()); // control
    }

    /// §14 item 4: relayed on both paths (the UA envelope `mtxExecute`, the address envelope `executeMetaTransaction`),
    /// fee 0, by anyone; the holder's signature is the one that matters.
    function test_roll_relayedBothPathsFeeZero() public {
        _aliceFour(c3o);
        uint64 vub = uint64(block.number + 20);
        bytes memory data = abi.encodeCall(IPqzToken.mtxRollOverSigned, (alice, 0, 2, _sk(1), vub, _pqAuth()));
        _onlyDigest(alice, _rollDigest(c3o, alice, 0, 2, _sk(1), vub));
        MetaTxLib.UAMetaTransaction memory u;
        (u.from, u.data, u.validUntil) = (_mldsaUA(63), data, block.timestamp + 1 hours);
        vm.prank(address(0x7E1A));
        c3o.mtxExecute(u, UACall.auth(u.from, _mlAuth()));
        assertTrue(c3o.pqzSkipped(alice, 0, 1));
        assertEq(c3o.pqzAccount(alice, 0).rolled, 2);
        _onlyDigest(alice, _rollDigest(c3o, alice, 0, 2, _none(), vub));
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (vm.addr(RKEY), abi.encodeCall(IPqzToken.mtxRollOverSigned, (alice, 0, 2, _none(),
            vub, _pqAuth())), block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(RKEY, MtxDigest.metaTx(address(c3o), m));
        vm.prank(address(0x7E1B));
        c3o.executeMetaTransaction(m, abi.encodePacked(r, s, v));
        assertEq(c3o.pqzAccount(alice, 0).rolled, 4);
        assertEq(c3o.pqzAccount(alice, 0).rollSeq, 2);
    }

    /// §14 item 20: `_window`'s age test reads the creation block, not the marked word.
    function test_roll_overMarkedSlotAfterAge() public {
        _aliceFour(c3o);
        _rollSigned(c3o, alice, 0, _sk(2));
        _rollSigned(c3o, alice, 4, _none()); // a marked word would read as a block in the far future: RollTooYoung
        assertEq(c3o.pqzAccount(alice, 0).rolled, 4);
    }
}
