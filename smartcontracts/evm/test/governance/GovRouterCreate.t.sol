// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovRouterFixture} from "./GovRouter.t.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {plainEnv, withModules} from "../helpers/Catalogue.sol";
import {deployKindModules, deployDexModules} from "../../script/KindModules.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {NoteKind, BadKind, INoteKind} from "../v2/mocks/GenericKinds.sol";

/// A stand-in for a chain's router: it answers `chainUid()` and a `subject()` it is told, and calls the factory.
contract SubjectRouter {
    bytes32 public chainUid;
    address public registry; // `configureChain` reads it and its `smartKeyCloneHash()` (spec 2026-11-10-admin-not-owner.md §13.3)
    bytes32 internal _subject;

    constructor(bytes32 uid, address registry_) { (chainUid, registry) = (uid, registry_); }

    function smartKeyCloneHash() external view returns (bytes32) { return IUARegistry(registry).smartKeyCloneHash(); }

    function subject() external view returns (bytes32) { return _subject; }

    function create(OpenFactory f, bytes32 s, bytes calldata initArgs) external returns (address) {
        _subject = s;
        return f.createToken(IOpenFactory.TokenKind.NORMAL, 1, initArgs, "r");
    }
}

/// Chain-neutral releases spec §4.4 (S3, owner 2026-11-07; plan T76): the signing UA creates through the chain's router.
/// `mtxCreateToken`, `mtxCreateDex`, `mtxCreateInstance` (`UAEnvelope`, the creation's named parameters, `initHash`), the
/// factory reading `subject()` once at entry. Native and derived signers, the replay on another chain and on the same lane
/// refused, `subject() = 0` refused, a non-router claiming a subject ignored, the reentrant `initialize`. **UNAUDITED.**
contract GovRouterCreateTest is GovRouterFixture {
    string constant CTAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 constant CREATE_TOKEN = keccak256(bytes(string.concat(
        "UACreateToken(bytes32 from,address target,uint8 kind,uint64 version,bytes32 initHash,bytes32 salt", CTAIL)));
    bytes32 constant CREATE_DEX = keccak256(bytes(string.concat(
        "UACreateDex(bytes32 from,address target,uint64 version,bytes32 initHash,bytes32 salt", CTAIL)));
    bytes32 constant CREATE_INSTANCE = keccak256(bytes(string.concat(
        "UACreateInstance(bytes32 from,address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,"
        "bytes32 salt", CTAIL)));
    address constant REGISTRAR = address(0x5E6);
    OpenFactory f;

    function setUp() public override {
        super.setUp();
        f = EnvKit.factory(REGISTRAR, chainUidA, 0, address(router));
        // T66b: the releases' body modules (the token's, the DEX's D), pinned in their envs
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(f), "");
        (address[] memory dm, bytes memory dargs) = deployDexModules(address(f));
        vm.startPrank(REGISTRAR);
        f.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, withModules(plainEnv(address(f), address(0), chainUidA, PREG, false), ms));
        f.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, args, EnvKit.uidOf(address(f)));
        f.publishDexEnv(1, withModules(plainEnv(address(f), address(0), chainUidA, address(0), false), dm));
        f.deployDexImplementation(1, 1, type(SCaaSDex).creationCode, dargs, EnvKit.uidOf(address(f)));
        f.publishClassEnv(4, 0, 1, plainEnv(address(f), address(0), chainUidA, address(0), false));
        f.deployImplementation(IOpenFactory.ReleaseId(4, 0, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId,
            type(NoteKind).creationCode, "", EnvKit.uidOf(address(f)));
        f.setClassKindEnabled(4, 0, true, EnvKit.uidOf(address(f)));
        f.publishClassEnv(4, 1, 1, plainEnv(address(f), address(0), chainUidA, address(0), false));
        f.deployImplementation(IOpenFactory.ReleaseId(4, 1, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId,
            type(BadKind).creationCode, abi.encode(uint8(16)), EnvKit.uidOf(address(f))); // NESTED: its initialize creates a (4, 0, 1) instance
        f.setClassKindEnabled(4, 1, true, EnvKit.uidOf(address(f)));
        vm.stopPrank();
    }

    function _otherArgs() internal pure returns (bytes memory) {
        return abi.encode(normalInit("D", "D", 6, 1000, address(0xCAFE), address(0)));
    }

    function _tokenArgs() internal pure returns (bytes memory) {
        return abi.encode(normalInit("C", "C", 6, 1000, address(0xCAFE), address(0)));
    }

    function _d(bytes32 th, MetaTxLib.UAEnvelope memory e, bytes memory words) internal view returns (bytes32) {
        bytes32 h = keccak256(bytes.concat(abi.encode(th, e.from, address(f)), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(router), h));
    }

    function _createToken(bytes32 from, bytes memory initArgs, bytes32 salt) internal returns (address) {
        MetaTxLib.UAEnvelope memory e = _envelope(router, from, 0);
        bytes32 d = _d(CREATE_TOKEN, e, abi.encode(uint8(0), uint64(1), keccak256(initArgs), salt));
        IUARegistry.UASig memory a = _auth(from, d);
        vm.prank(address(0xBEEF)); // a relayer, fee 0
        router.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, initArgs, salt, a);
        return f.predictAddress(from, 1, 0, salt);
    }

    function test_create_nativeSigner_sameAddressAsItsDirectCall() public {
        address t = _createToken(eoa, _tokenArgs(), "s");
        assertGt(t.code.length, 0);
        IOpenFactory.Created memory c = f.infoOf(t);
        assertEq(c.creatorId, eoa, "the signing UA");
        assertEq(f.creatorOf(t), address(uint160(uint256(eoa))), "a native id's address");
        assertEq(c.contractClass, 1);
        // the same id's direct call with another salt lands where predictAddress says, for the same formula
        address direct = address(uint160(uint256(eoa)));
        vm.prank(direct);
        address t2 = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, _tokenArgs(), "s2");
        assertEq(t2, f.predictAddress(eoa, 1, 0, "s2"));
        // the same (creator, class, kind, salt) by its direct call: taken already
        vm.prank(direct);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, _tokenArgs(), "s");
    }

    function test_create_derivedSigners() public {
        address t = _createToken(pq, _tokenArgs(), "pq");
        assertEq(f.infoOf(t).creatorId, pq, "a PQ key's id");
        assertEq(f.creatorOf(t), address(0), "a derived id has no address");
        address m = _createToken(msig, _tokenArgs(), "msig");
        assertEq(f.infoOf(m).creatorId, msig);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsOfCreator(msig, 1, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, m);
    }

    function test_create_dexAndInstance() public {
        bytes memory dexArgs = abi.encode(ISCaaSDex.DexConfig(eoa, 0, TREASURY, false, 0, address(0)));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        bytes32 d = _d(CREATE_DEX, e, abi.encode(uint64(1), keccak256(dexArgs), bytes32("dex")));
        router.mtxCreateDex(e, address(f), 1, dexArgs, "dex", _auth(pq, d));
        address dex = f.predictAddress(pq, 2, 0, "dex");
        assertEq(f.infoOf(dex).creatorId, pq);
        assertEq(f.infoOf(dex).contractClass, 2);
        bytes memory initCall = abi.encodeCall(INoteKind.initialize, (pq, "by router"));
        e = _envelope(router, pq, 0);
        d = _d(CREATE_INSTANCE, e, abi.encode(uint16(4), uint16(0), uint64(1), keccak256(initCall), bytes32("note")));
        router.mtxCreateInstance(e, address(f), 4, 0, 1, initCall, "note", _auth(pq, d));
        address note = f.predictAddress(pq, 4, 0, "note");
        assertEq(f.infoOf(note).creatorId, pq);
        assertEq(NoteKind(note).seenCreator(), pq, "creating() the signing UA");
    }

    function test_create_replayRefused() public {
        bytes memory initArgs = _tokenArgs();
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, 0);
        bytes32 d = _d(CREATE_TOKEN, e, abi.encode(uint8(0), uint64(1), keccak256(initArgs), bytes32("s")));
        IUARegistry.UASig memory a = _auth(eoa, d);
        uint256 snap = vm.snapshotState();
        // another chain (the router's domain names the chain id): refused
        vm.chainId(block.chainid + 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        router.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, initArgs, "s", a);
        vm.revertToState(snap);
        // another initArgs under the same signature: refused (initHash is signed)
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        router.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, _otherArgs(), "s", a);
        // the signature as signed: accepted once, then its lane nonce is spent
        router.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, initArgs, "s", a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        router.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, initArgs, "s", a);
    }

    function test_create_subjectZeroRefused_nonRouterSubjectIgnored() public {
        SubjectRouter r = new SubjectRouter(chainUidA, PREG);
        OpenFactory g = EnvKit.factory(REGISTRAR, chainUidA, 0, address(r));
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(g), ""); // T66b
        vm.startPrank(REGISTRAR);
        g.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, withModules(plainEnv(address(g), address(0), chainUidA, PREG, false), ms));
        g.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, args, EnvKit.uidOf(address(g)));
        vm.stopPrank();
        vm.expectRevert(IOpenFactory.RouterSubjectZero.selector);
        r.create(g, bytes32(0), _tokenArgs());
        address t = r.create(g, pq, _tokenArgs()); // positive control: the router's subject is the creator
        assertEq(g.infoOf(t).creatorId, pq);
        // a contract that is not this factory's router claims a subject: its own address is the creator
        SubjectRouter other = new SubjectRouter(chainUidA, PREG);
        address u = other.create(g, pq, _tokenArgs());
        assertEq(g.infoOf(u).creatorId, nid(address(other)));
    }

    /// Fable P3-6: a router-signed creation whose `initialize` creates again: the nested record's creator is the outer
    /// instance, the outer one the signing UA; `creating()` right in both and restored.
    function test_create_reentrantInitialize() public {
        bytes memory initCall = abi.encodeCall(INoteKind.initialize, (eoa, "outer"));
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, 0);
        bytes32 d = _d(CREATE_INSTANCE, e, abi.encode(uint16(4), uint16(1), uint64(1), keccak256(initCall), bytes32("o")));
        router.mtxCreateInstance(e, address(f), 4, 1, 1, initCall, "o", _auth(eoa, d));
        address outer = f.predictAddress(eoa, 4, 1, "o");
        address inner = f.predictAddress(nid(outer), 4, 0, "nested");
        assertEq(f.infoOf(outer).creatorId, eoa, "the outer creator: the signing UA");
        assertEq(f.infoOf(inner).creatorId, nid(outer), "the nested creator: the outer instance");
        assertEq(BadKind(outer).seenCreator(), eoa);
        assertEq(BadKind(outer).seenAfter(), eoa, "creating() restored after the nested creation");
        assertEq(NoteKind(inner).seenCreator(), nid(outer));
        assertEq(f.creating(), bytes32(0), "restored");
        (IOpenFactory.Created[] memory p,) = f.contractsPage(4, 0, 10);
        assertEq(p[0].addr, inner, "the nested record first");
        assertEq(p[1].addr, outer);
    }
}
