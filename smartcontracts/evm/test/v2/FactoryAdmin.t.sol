// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {DeploySend} from "../../script/DeploySend.s.sol";
import {GenericKindBase, NoteKind, INoteKind, IRosterKind} from "./mocks/GenericKinds.sol";

/// The factory's admin and release-approval ABI (spec 2026-11-10-admin-not-owner.md §5.1, §5.2, §5.6), written out here so
/// the test pins it apart from the source's declarations (and compiles against the factory before T5: the red run).
interface IFactoryAdmin {
    event AdminTransferStarted(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event AdminTransferred(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event ReleaseApproved(bytes32 indexed key, uint32 adminGeneration, uint64 until);
    event ReleaseApprovalRevoked(bytes32 indexed key);

    error NotAdmin(bytes32 caller);
    error NotPendingAdmin(bytes32 caller);
    error AdminNotNative(bytes32 admin);
    error ApprovalFieldMismatch(uint8 field); // 0 chainUid, 1 factory, 2 adminGeneration
    error ApprovalTooLong(uint64 until);
    error ApprovalLive(bytes32 key);
    error ApprovalNotRevocable(bytes32 key);
    error ReleaseNotApproved(bytes32 key);
    error ProbeGasLow(uint256 gasLeft);

    function admin() external view returns (bytes32);
    function pendingAdmin() external view returns (bytes32);
    function adminGeneration() external view returns (uint32);
    function transferAdmin(bytes32 newAdmin, bytes32 chainUid_) external;
    function acceptAdmin() external;
    function renounceAdmin(bytes32 chainUid_) external;
    function approveTokenRelease(IOpenFactory.TokenKind kind, uint64 version, uint16 envVersion, bytes32 initcodeHash,
        bytes32 implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until) external;
    function approveDexRelease(uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash,
        bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until) external;
    function approveRelease(IOpenFactory.ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until)
        external;
    function revokeApproval(bytes32 key, bytes32 chainUid_) external;
    /// `state` 0 none, 1 live, 2 consumed.
    function approvalOf(bytes32 key) external view returns (uint8 state, uint32 adminGeneration, uint64 until);
}

/// A stand-in for the chain's router (T5; T7 adds the real router's release ops and their tests): it names `chainUid()`,
/// `registry()` and its registry's `smartKeyCloneHash()` for `configureChain` (spec §13.3, §13.4) and answers `subject()`
/// with the UA it is told to act for, to its live target only, as `GovernanceRouter.subject()` does. It checks no
/// signature. Not configured as a factory's router, it is the fake router of §8 (a contract answering `subject() = admin`).
contract TestRouter {
    bytes32 public immutable chainUid;
    address public immutable registry;
    bytes32 private _subject;
    address private _target;

    constructor(bytes32 uid, address registry_) {
        (chainUid, registry) = (uid, registry_);
    }

    function smartKeyCloneHash() external view returns (bytes32) {
        return IUARegistry(registry).smartKeyCloneHash();
    }

    function subject() external view returns (bytes32) {
        return msg.sender == _target ? _subject : bytes32(0);
    }

    function exec(bytes32 s, address target, bytes calldata data) external {
        (_subject, _target) = (s, target);
        (bool ok, bytes memory ret) = target.call(data);
        (_subject, _target) = (bytes32(0), address(0));
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }
}

/// A token (kind 0) or DEX release for the catalogue's checks and nothing more: `kind()` 0, `factory()`, `validateEnv`
/// (nothing), `modules()` (none).
contract MockRelease {
    address public immutable factory;

    constructor(address factory_, bytes memory) {
        factory = factory_;
    }

    function kind() external pure returns (uint8) { return 0; }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    function modules() external pure returns (address[] memory) {}
}

/// A class release whose ERC-165 answer for `0x01ffc9a7` spends 25,000 of the probe's 30,000 gas: a probe that starts
/// below its floor is told apart from one that had its stipend (§5.6 item 3).
contract BurnKind is GenericKindBase {
    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory) GenericKindBase(id, factory_) {}

    function _interfaceId() internal pure override returns (bytes4) { return type(INoteKind).interfaceId; }

    function supportsInterface(bytes4 id) external view override returns (bool) {
        if (id == 0x01ffc9a7) {
            uint256 g = gasleft();
            while (g - gasleft() < 25_000) {}
        }
        return id == 0x01ffc9a7 || id == _interfaceId();
    }
}

/// `OpenFactory`'s UA admin (round 3r, CTR-GOV-23; spec §5.1, §5.2, §8) and its release deploys (§5.6): a native first
/// admin from the constructor, every admin op `onlyAdmin` (direct as the native id, or the configured router's `subject()`),
/// `configureChain` direct only, the two-step transfer and the renounce under `configured`; one release approved by hash and
/// deployed by anyone, each approval used once, dead at `until` or at an admin change; the native admin's own deploy is its
/// own approval. The router of the accept and transfer rows is the real `GovernanceRouter` over the registry with derived
/// secp256k1, mldsa44 and an `msig` of three mldsa44 at 2-of-3 (the stand-in verifier of `UARegistryBase`); every other op
/// through a router here uses `TestRouter`; the real router's ops for them, with every derived kind of §8, are
/// `test/governance/GovRouterAdmin.t.sol` (T7). **UNAUDITED.**
contract FactoryAdminTest is UARegistryBase {
    uint16 constant ML44 = 0x0130;
    uint16 constant K1 = 0x0108;
    uint64 constant CAP = 4_250_000;
    address constant PREG = 0x5CA00000000000000000000000000000000000A5;
    address constant RELAYER = address(0xBEEF);
    address constant STRANGER = address(0x5757);
    uint8 constant NONE = 0;
    uint8 constant LIVE = 1;
    uint8 constant CONSUMED = 2;
    uint16 constant CLS = 4; // NoteKind's class
    string constant TAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    address deployer = makeAddr("deployer");
    address next = makeAddr("next");
    UARegistry preg;
    GovernanceRouter router;
    TestRouter trouter;

    bytes k1Key;
    bytes32 k1;
    bytes mlKey;
    bytes32 ml;
    bytes[3] mkeys;
    bytes msigData;
    bytes32 msig;

    /// A release of one of the three deploys (`d` 0 token, 1 DEX, 2 class): every field the deploy stores from its caller.
    struct Rel {
        uint8 d;
        uint16 cls;
        uint16 knd;
        uint64 version;
        uint16 envVersion;
        bytes4 sel;
        bytes4 iface;
        bytes code;
        bytes args;
    }

    function setUp() public override {
        super.setUp();
        vm.warp(1_800_000_000);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](2);
        c[0] = UARegistry.KindConfig(K1, address(mock), 50_000);
        c[1] = UARegistry.KindConfig(ML44, address(mock), CAP);
        preg = _deploy(PREG, chainUidA, address(0), false, BUDGET, address(0), true, c);
        router = new GovernanceRouter(chainUidA, PREG, address(0), false);
        trouter = new TestRouter(chainUidA, PREG);
        Vm.Wallet memory w = vm.createWallet("k1 signer");
        k1Key = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        k1 = _register(preg, K1, k1Key);
        mlKey = _ml(1);
        ml = _register(preg, ML44, mlKey);
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) {
            mkeys[i] = _ml(10 + i);
            m[i] = Member(ML44, _register(preg, ML44, mkeys[i]), 1);
        }
        msigData = _msigKey(2, m);
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msigData);
        msig = UACall.register(preg, UAKinds.MSIG, msigData, _none(),
            abi.encode(_memberSigs(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG), 2)), "");
        for (uint256 i; i < 3; ++i) preg.acceptMembership(msig, _acceptKeySig(msigData, ML44, mkeys[i]));
    }

    // ------------------------------------------------------------------ fixture

    /// An mldsa44 public key of the right length (the stand-in verifier reads no structure).
    function _ml(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1312);
        for (uint256 i; i < 1312; i += 32) {
            bytes32 w = keccak256(abi.encode(ML44, salt, i));
            for (uint256 j; j < 32 && i + j < 1312; ++j) pk[i + j] = w[j];
        }
    }

    /// `new OpenFactory(admin_)` by CREATE (not `deployCode`: a refused constructor returns its revert data here).
    function _create(bytes32 admin_) internal returns (address a, bytes memory err) {
        bytes memory code = abi.encodePacked(type(OpenFactory).creationCode, abi.encode(admin_));
        assembly ("memory-safe") {
            a := create(0, add(code, 32), mload(code))
            if iszero(a) {
                err := mload(0x40)
                mstore(err, returndatasize())
                returndatacopy(add(err, 32), 0, returndatasize())
                mstore(0x40, add(add(err, 32), returndatasize()))
            }
        }
    }

    function _new(bytes32 admin_) internal returns (OpenFactory f) {
        (address a,) = _create(admin_);
        require(a != address(0), "factory not created");
        f = OpenFactory(a);
    }

    /// A factory of `deployer`, configured with `router_` on chain A, env 1 of `NORMAL`, the DEX and class 4 kind 0
    /// published (empty envs), class 4 kind 1 and class 5 kind 1 too (the one-field rows).
    function _ready(address router_) internal returns (OpenFactory f) {
        f = _new(nid(deployer));
        _configure(f, router_);
        IFactoryToken.Env memory e;
        vm.startPrank(deployer);
        f.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, EnvKit.uidOf(address(f)), e);
        f.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 2, EnvKit.uidOf(address(f)), e);
        f.publishTokenEnv(IOpenFactory.TokenKind.WRAPPED, 1, EnvKit.uidOf(address(f)), e);
        f.publishDexEnv(1, EnvKit.uidOf(address(f)), e);
        f.publishDexEnv(2, EnvKit.uidOf(address(f)), e);
        f.publishClassEnv(CLS, 0, 1, EnvKit.uidOf(address(f)), e);
        f.publishClassEnv(CLS, 0, 2, EnvKit.uidOf(address(f)), e);
        f.publishClassEnv(CLS, 1, 1, EnvKit.uidOf(address(f)), e);
        f.publishClassEnv(CLS + 1, 0, 1, EnvKit.uidOf(address(f)), e);
        vm.stopPrank();
    }

    function _configure(OpenFactory f, address router_) internal {
        EnvKit.genesis(chainUidA);
        vm.prank(deployer);
        f.configureChain(chainUidA, 0, router_, EnvKit.codeHashOf(router_), 0, bytes32(0));
    }

    function _a(OpenFactory f) internal pure returns (IFactoryAdmin) {
        return IFactoryAdmin(address(f));
    }

    function _tok() internal pure returns (Rel memory r) {
        (r.d, r.knd, r.version, r.envVersion, r.code, r.args) = (0, 0, 1, 1, type(MockRelease).creationCode, hex"0123");
    }

    function _dex() internal pure returns (Rel memory r) {
        (r.d, r.version, r.envVersion, r.code, r.args) = (1, 1, 1, type(MockRelease).creationCode, hex"4567");
    }

    function _cls() internal pure returns (Rel memory r) {
        (r.d, r.cls, r.knd, r.version, r.envVersion) = (2, CLS, 0, 1, 1);
        (r.sel, r.iface, r.code, r.args) =
            (INoteKind.initialize.selector, type(INoteKind).interfaceId, type(NoteKind).creationCode, hex"89");
    }

    function _rels() internal pure returns (Rel[3] memory) {
        return [_tok(), _dex(), _cls()];
    }

    function _id(Rel memory r) internal pure returns (IOpenFactory.ReleaseId memory) {
        return IOpenFactory.ReleaseId(r.cls, r.knd, r.version);
    }

    /// The key of spec §5.6's table: one tag per domain, then `chainUid`, the factory and the deploy's stored fields, the
    /// init code's and `implArgs`' hashes from the bytes; fixed-width `abi.encode`.
    function _key(OpenFactory f, Rel memory r) internal view returns (bytes32) {
        bytes32 h1 = keccak256(r.code);
        bytes32 h2 = keccak256(r.args);
        if (r.d == 0) {
            return keccak256(abi.encode(keccak256("scaas.factory.release.token"), f.chainUid(), address(f), r.knd,
                r.version, r.envVersion, h1, h2));
        }
        if (r.d == 1) {
            return keccak256(abi.encode(keccak256("scaas.factory.release.dex"), f.chainUid(), address(f), r.version,
                r.envVersion, h1, h2));
        }
        return keccak256(abi.encode(keccak256("scaas.factory.release.class"), f.chainUid(), address(f), r.cls, r.knd,
            r.version, r.envVersion, r.sel, r.iface, h1, h2));
    }

    function _approveCd(OpenFactory f, Rel memory r, uint64 until) internal view returns (bytes memory) {
        return _approveWith(r, f.chainUid(), address(f), _a(f).adminGeneration(), until);
    }

    function _approveWith(Rel memory r, bytes32 uid, address fac, uint32 gen, uint64 until)
        internal pure returns (bytes memory)
    {
        bytes32 h1 = keccak256(r.code);
        bytes32 h2 = keccak256(r.args);
        if (r.d == 0) {
            return abi.encodeCall(IFactoryAdmin.approveTokenRelease,
                (IOpenFactory.TokenKind(uint8(r.knd)), r.version, r.envVersion, h1, h2, uid, fac, gen, until));
        }
        if (r.d == 1) {
            return abi.encodeCall(IFactoryAdmin.approveDexRelease, (r.version, r.envVersion, h1, h2, uid, fac, gen, until));
        }
        return abi.encodeCall(IFactoryAdmin.approveRelease,
            (_id(r), r.envVersion, r.sel, r.iface, h1, h2, uid, fac, gen, until));
    }

    /// @dev The deploy of `r` on `fac`, with `fac`'s chain word (Fable recheck-2 P3-1).
    function _deployCd(Rel memory r, address fac) internal view returns (bytes memory) {
        bytes32 u = EnvKit.uidOf(fac);
        if (r.d == 0) {
            return abi.encodeCall(OpenFactory.deployTokenImplementation,
                (IOpenFactory.TokenKind(uint8(r.knd)), r.version, r.envVersion, r.code, r.args, u));
        }
        if (r.d == 1) return abi.encodeCall(OpenFactory.deployDexImplementation, (r.version, r.envVersion, r.code, r.args, u));
        return abi.encodeCall(OpenFactory.deployImplementation, (_id(r), r.envVersion, r.sel, r.iface, r.code, r.args, u));
    }

    function _until() internal view returns (uint64) {
        return uint64(block.timestamp + 1 days);
    }

    /// `from` calls `to` with `cd`; a revert is bubbled.
    function _call(address from, address to, bytes memory cd) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    /// `from` calls `to` with `cd`, which must revert with exactly `err`.
    function _refused(address from, address to, bytes memory cd, bytes memory err) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        assertFalse(ok, "refused");
        assertEq(ret, err);
    }

    /// `r` (a router: the test router, the fake one) acts for `s` on `f` with `cd`.
    function _via(TestRouter r, bytes32 s, OpenFactory f, bytes memory cd) internal {
        _call(RELAYER, address(r), abi.encodeCall(TestRouter.exec, (s, address(f), cd)));
    }

    function _viaRefused(TestRouter r, bytes32 s, OpenFactory f, bytes memory cd, bytes memory err) internal {
        _refused(RELAYER, address(r), abi.encodeCall(TestRouter.exec, (s, address(f), cd)), err);
    }

    function _notAdmin(bytes32 c) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IFactoryAdmin.NotAdmin.selector, c);
    }

    function _notApproved(bytes32 key) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IFactoryAdmin.ReleaseNotApproved.selector, key);
    }

    function _state(OpenFactory f, bytes32 key) internal view returns (uint8 s) {
        (s,,) = _a(f).approvalOf(key);
    }

    /// Every admin op of the factory but the transfer, the renounce and the deploys (spec §5.2), each a fresh write on
    /// `_ready`'s factory (`r` the release the approval and the revoke name, unapproved).
    function _adminOps(OpenFactory f) internal view returns (bytes[] memory c) {
        IFactoryToken.Env memory e;
        Rel memory t = _tok();
        c = new bytes[](11);
        c[0] = abi.encodeCall(OpenFactory.publishTokenEnv, (IOpenFactory.TokenKind.NORMAL, 9, EnvKit.uidOf(address(f)), e));
        c[1] = abi.encodeCall(OpenFactory.publishDexEnv, (9, EnvKit.uidOf(address(f)), e));
        c[2] = abi.encodeCall(OpenFactory.publishClassEnv, (CLS, 0, 9, EnvKit.uidOf(address(f)), e));
        bytes32 u = EnvKit.uidOf(address(f));
        c[3] = abi.encodeCall(OpenFactory.setTokenKindEnabled, (IOpenFactory.TokenKind.WRAPPED, true, u));
        c[4] = abi.encodeCall(OpenFactory.setClassKindEnabled, (CLS, 0, true, u));
        c[5] = _approveCd(f, t, _until());
        c[6] = _approveCd(f, _dex(), _until());
        c[7] = _approveCd(f, _cls(), _until());
        c[8] = abi.encodeCall(OpenFactory.deprecateToken, (IOpenFactory.TokenKind.NORMAL, 1, u, "x"));
        c[9] = abi.encodeCall(OpenFactory.deprecateDex, (1, u, "x"));
        c[10] = abi.encodeCall(OpenFactory.deprecateRelease, (IOpenFactory.ReleaseId(CLS, 0, 1), u, "x"));
    }

    // ------------------------------------------------------------------ the real router: signing

    function _domain() internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            router.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _env(bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, 0, router.mtxNonce(from, 0), block.timestamp + 1 hours, 0, address(0), 0,
            address(0));
    }

    /// The digest of `UA<op>(bytes32 from,address target<params>,E)` over `words` in the router's domain.
    function _digest(string memory op, string memory params, MetaTxLib.UAEnvelope memory e, address target,
        bytes memory words) internal view returns (bytes32)
    {
        bytes32 th = keccak256(bytes(string.concat("UA", op, "(bytes32 from,address target", params, TAIL)));
        bytes32 h = keccak256(bytes.concat(abi.encode(th, e.from, target), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(), h));
    }

    function _auth(bytes32 id, bytes32 d) internal view returns (IUARegistry.UASig memory a) {
        if (id == k1) (a.keyData, a.signature) = (k1Key, _sig(k1Key, UAKinds.uaMessage(K1, UAKinds.PURPOSE_METATX, d)));
        else if (id == ml) a.signature = _sig(mlKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, d));
        else if (id == msig) a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, d, 2);
        else revert("no signer");
    }

    /// Slots 0..n-1 of the `msig` (index order), each over `(purpose, digest)` under `PURPOSE_MEMBER`.
    function _memberSigs(bytes32 ua, bytes32 purpose, bytes32 digest, uint256 n)
        internal view returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](n);
        bytes32 md = _memberDigest(ua, purpose, digest);
        for (uint16 i; i < n; ++i) {
            for (uint256 j; j < 3; ++j) {
                if (_indexOf(msigData, UAKinds.uaOf(ML44, mkeys[j])) != i) continue;
                s[i] = IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0),
                    _sig(mkeys[j], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md)));
            }
        }
    }

    /// `by`'s signed `mtxAcceptAdmin` of `f`, sent by a stranger relayer (fee 0).
    function _accept(bytes32 by, OpenFactory f) internal {
        MetaTxLib.UAEnvelope memory e = _env(by);
        IUARegistry.UASig memory a = _auth(by, _digest("AcceptAdmin", "", e, address(f), ""));
        vm.prank(RELAYER);
        router.mtxAcceptAdmin(e, address(f), a);
    }

    function _acceptCd(bytes32 by, OpenFactory f) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(by);
        return abi.encodeCall(router.mtxAcceptAdmin, (e, address(f), _auth(by, _digest("AcceptAdmin", "", e, address(f), ""))));
    }

    function _transferCd(bytes32 by, OpenFactory f, bytes32 to) internal view returns (bytes memory) {
        return _transferCd(by, f, to, EnvKit.uidOf(address(f)));
    }

    function _transferCd(bytes32 by, OpenFactory f, bytes32 to, bytes32 u) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(by);
        IUARegistry.UASig memory a =
            _auth(by, _digest("TransferAdmin", ",bytes32 newAdmin,bytes32 chainUid", e, address(f), abi.encode(to, u)));
        return abi.encodeCall(router.mtxTransferAdmin, (e, address(f), to, u, a));
    }

    function _renounceCd(bytes32 by, OpenFactory f) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(by);
        bytes32 u = EnvKit.uidOf(address(f));
        IUARegistry.UASig memory a = _auth(by, _digest("RenounceAdmin", ",bytes32 chainUid", e, address(f), abi.encode(u)));
        return abi.encodeCall(router.mtxRenounceAdmin, (e, address(f), u, a));
    }

    // ------------------------------------------------------------------ the constructor (§5.2)

    function test_constructor_nativeAdmin() public {
        bytes32 a = nid(deployer);
        address at = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectEmit(true, true, true, true, at);
        emit IFactoryAdmin.AdminTransferred(bytes32(0), a);
        (address got,) = _create(a);
        assertEq(got, at);
        assertEq(_a(OpenFactory(got)).admin(), a);
        assertEq(_a(OpenFactory(got)).pendingAdmin(), bytes32(0));
        assertEq(_a(OpenFactory(got)).adminGeneration(), 0);
        (bool ok, bytes memory ret) = got.staticcall(abi.encodeWithSelector(bytes4(0x2b20e397))); // registrar()
        assertFalse(ok, "registrar() is gone");
        assertEq(ret.length, 0);
    }

    /// M10: 0 and a derived id (high 96 bits set) are refused; the first admin is a native id on every chain.
    function test_constructor_refusesZeroAndDerived() public {
        bytes32[3] memory bad = [bytes32(0), ml, bytes32(uint256(1) << 160)];
        for (uint256 i; i < 3; ++i) {
            (address a, bytes memory err) = _create(bad[i]);
            assertEq(a, address(0));
            assertEq(err, abi.encodeWithSelector(IFactoryAdmin.AdminNotNative.selector, bad[i]));
        }
        (address ok,) = _create(bytes32(uint256(type(uint160).max)));
        assertTrue(ok != address(0), "the largest native id");
    }

    // ------------------------------------------------------------------ the direct native admin (§8)

    /// Every admin op, directly by the native admin: the publishes, the switches, the approvals and a revoke, the three
    /// deploys (the shortcut), the deprecations, the two-step transfer, the renounce.
    function test_directAdmin_everyOp() public {
        OpenFactory f = _ready(address(trouter));
        bytes[] memory c = _adminOps(f);
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) _call(deployer, address(f), _deployCd(rs[i], address(f)));
        for (uint256 i; i < c.length; ++i) _call(deployer, address(f), c[i]);
        assertEq(f.latestTokenEnvVersion(IOpenFactory.TokenKind.NORMAL), 9);
        assertEq(f.latestDexEnvVersion(), 9);
        assertEq(f.latestClassEnvVersion(CLS, 0), 9);
        assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.WRAPPED));
        assertTrue(f.classKindEnabled(CLS, 0));
        assertTrue(f.isTokenDeprecated(IOpenFactory.TokenKind.NORMAL, 1));
        assertTrue(f.isDexDeprecated(1));
        assertTrue(f.classReleaseOf(IOpenFactory.ReleaseId(CLS, 0, 1)).deprecated);
        for (uint256 i; i < 3; ++i) assertEq(_state(f, _key(f, rs[i])), LIVE, "approved after its deploy: live, unused");
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (_key(f, rs[0]), EnvKit.uidOf(address(f)))));
        assertEq(_state(f, _key(f, rs[0])), NONE);
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))));
        assertEq(_a(f).admin(), nid(deployer), "M18: the transfer is two steps");
        assertEq(_a(f).pendingAdmin(), nid(next));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        assertEq(_a(f).admin(), nid(next));
        assertEq(_a(f).pendingAdmin(), bytes32(0));
        assertEq(_a(f).adminGeneration(), 1);
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))));
        assertEq(_a(f).admin(), bytes32(0));
        assertEq(_a(f).adminGeneration(), 2);
    }

    function test_stranger_notAdmin() public {
        OpenFactory u = _new(nid(deployer));
        EnvKit.genesis(chainUidA);
        _refused(STRANGER, address(u), abi.encodeCall(OpenFactory.configureChain, (chainUidA, 0, address(0), bytes32(0), 0, bytes32(0))),
            _notAdmin(nid(STRANGER)));
        OpenFactory f = _ready(address(trouter));
        bytes[] memory c = _adminOps(f);
        for (uint256 i; i < c.length; ++i) _refused(STRANGER, address(f), c[i], _notAdmin(nid(STRANGER)));
        _refused(STRANGER, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(STRANGER), EnvKit.uidOf(address(f)))), _notAdmin(nid(STRANGER)));
        _refused(STRANGER, address(f), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))), _notAdmin(nid(STRANGER)));
        _refused(STRANGER, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (bytes32(uint256(1)), EnvKit.uidOf(address(f)))),
            _notAdmin(nid(STRANGER)));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
    }

    /// M4: an admin EOA that is an EIP-7702 designator is no direct authority (D2): every direct op `CallerDelegated`.
    function test_designatorAdmin_callerDelegated() public {
        OpenFactory u = _new(nid(deployer));
        OpenFactory f = _ready(address(trouter));
        bytes[] memory c = _adminOps(f);
        vm.etch(deployer, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        bytes memory d = abi.encodeWithSelector(SigCheck.CallerDelegated.selector, deployer);
        EnvKit.genesis(chainUidA);
        _refused(deployer, address(u), abi.encodeCall(OpenFactory.configureChain, (chainUidA, 0, address(0), bytes32(0), 0, bytes32(0))), d);
        for (uint256 i; i < c.length; ++i) _refused(deployer, address(f), c[i], d);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))), d);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))), d);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (bytes32(uint256(1)), EnvKit.uidOf(address(f)))), d);
    }

    /// `configureChain` is direct only (§5.2): before it the factory has no router, so a router naming the admin is its
    /// own native id; and after it, the second call is refused for everyone.
    function test_configureChain_directOnly() public {
        OpenFactory u = _new(nid(deployer));
        EnvKit.genesis(chainUidA);
        bytes memory cd = abi.encodeCall(OpenFactory.configureChain, (chainUidA, 0, address(trouter), address(trouter).codehash, 0,
            bytes32(0)));
        _viaRefused(trouter, nid(deployer), u, cd, _notAdmin(nid(address(trouter))));
        assertEq(u.chainUid(), bytes32(0));
        _call(deployer, address(u), cd);
        assertEq(u.govRouter(), address(trouter));
        _viaRefused(trouter, nid(deployer), u, cd, abi.encodeWithSelector(IOpenFactory.ChainAlreadyConfigured.selector));
    }

    // ------------------------------------------------------------------ derived admins through the real router (§8)

    /// M2 (each kind): the native admin transfers, the derived UA accepts by its signed `mtxAcceptAdmin` (a stranger
    /// relayer, fee 0), then transfers on through the router; the deployer is no longer the admin.
    function test_derivedAdmin_k1() public {
        _derivedAccepts(k1);
    }

    function test_derivedAdmin_mldsa() public {
        _derivedAccepts(ml);
    }

    function test_derivedAdmin_msig() public {
        _derivedAccepts(msig);
    }

    function _derivedAccepts(bytes32 id) internal {
        OpenFactory f = _ready(address(router));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (id, EnvKit.uidOf(address(f)))));
        assertEq(_a(f).admin(), nid(deployer), "two steps");
        assertEq(_a(f).pendingAdmin(), id);
        bytes memory cd = _acceptCd(id, f);
        vm.expectEmit(true, true, true, true, address(f));
        emit IFactoryAdmin.AdminTransferred(nid(deployer), id);
        _call(RELAYER, address(router), cd);
        assertEq(_a(f).admin(), id);
        assertEq(_a(f).pendingAdmin(), bytes32(0));
        assertEq(_a(f).adminGeneration(), 1);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(deployer), EnvKit.uidOf(address(f)))), _notAdmin(nid(deployer)));
        _call(RELAYER, address(router), _transferCd(id, f, nid(next)));
        assertEq(_a(f).pendingAdmin(), nid(next));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        assertEq(_a(f).admin(), nid(next));
    }

    /// Another signer through the router is its own subject: `NotAdmin(signer)` (transfer and renounce); the derived
    /// admin's renounce through the router ends the admin.
    function test_router_anotherSignerNotAdmin() public {
        OpenFactory f = _ready(address(router));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (ml, EnvKit.uidOf(address(f)))));
        _accept(ml, f);
        _refused(RELAYER, address(router), _transferCd(k1, f, k1), _notAdmin(k1));
        _refused(RELAYER, address(router), _renounceCd(msig, f), _notAdmin(msig));
        _call(RELAYER, address(router), _renounceCd(ml, f));
        assertEq(_a(f).admin(), bytes32(0));
        _refused(RELAYER, address(router), _transferCd(ml, f, ml), _notAdmin(ml));
    }

    /// A derived admin acts on every op through the router (the test router: T7 builds the real router's ops).
    function test_derivedAdmin_everyOpThroughRouter() public {
        OpenFactory f = _ready(address(trouter));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (ml, EnvKit.uidOf(address(f)))));
        _via(trouter, ml, f, abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        assertEq(_a(f).admin(), ml);
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _via(trouter, ml, f, _approveCd(f, rs[i], _until()));
            _call(STRANGER, address(f), _deployCd(rs[i], address(f)));
        }
        bytes[] memory c = _adminOps(f);
        for (uint256 i; i < c.length; ++i) {
            if (i >= 5 && i <= 7) continue; // the three approvals: their keys are used above
            _via(trouter, ml, f, c[i]);
            _refused(deployer, address(f), c[i], _notAdmin(nid(deployer)));
        }
        assertTrue(f.isTokenDeprecated(IOpenFactory.TokenKind.NORMAL, 1));
        _via(trouter, ml, f, abi.encodeCall(IFactoryAdmin.transferAdmin, (k1, EnvKit.uidOf(address(f)))));
        assertEq(_a(f).pendingAdmin(), k1);
        _via(trouter, ml, f, abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))));
        assertEq(_a(f).admin(), bytes32(0));
    }

    /// M1: a contract answering `subject() = admin` that is not the factory's router is its own native id.
    function test_fakeRouter_refused() public {
        OpenFactory f = _ready(address(router));
        TestRouter fake = new TestRouter(chainUidA, PREG);
        bytes[] memory c = _adminOps(f);
        bytes memory e = _notAdmin(nid(address(fake)));
        for (uint256 i; i < c.length; ++i) _viaRefused(fake, nid(deployer), f, c[i], e);
        _viaRefused(fake, nid(deployer), f, abi.encodeCall(IFactoryAdmin.transferAdmin, (ml, EnvKit.uidOf(address(f)))), e);
        _viaRefused(fake, nid(deployer), f, abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))), e);
        _viaRefused(fake, nid(next), f, abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(address(fake))));
    }

    /// M9, M19: a non-pending caller, a second accept, and a router answering 0 with no pending are refused.
    function test_acceptAdmin_nonPending() public {
        OpenFactory f = _ready(address(trouter));
        _refused(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(next)));
        _viaRefused(trouter, bytes32(0), f, abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, bytes32(0)));
        assertEq(_a(f).admin(), nid(deployer), "M19: the admin stays");
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))));
        _refused(STRANGER, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(STRANGER)));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        _refused(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(next)));
        assertEq(_a(f).adminGeneration(), 1, "M9: one accept, one generation");
        // a pending cancelled by `transferAdmin(0)` cannot accept
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(deployer), EnvKit.uidOf(address(f)))));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (bytes32(0), EnvKit.uidOf(address(f)))));
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(deployer)));
    }

    /// M3, M17: the renounce clears the admin and the pending for good; every op is refused, directly and through a router
    /// answering 0.
    function test_renounce_endsEveryOp() public {
        OpenFactory f = _ready(address(trouter));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))));
        vm.expectEmit(true, true, true, true, address(f));
        emit IFactoryAdmin.AdminTransferred(nid(deployer), bytes32(0));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))));
        assertEq(_a(f).admin(), bytes32(0));
        assertEq(_a(f).pendingAdmin(), bytes32(0), "M17: the pending is cleared");
        assertEq(_a(f).adminGeneration(), 1);
        _refused(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(next)));
        bytes[] memory c = _adminOps(f);
        for (uint256 i; i < c.length; ++i) {
            _refused(deployer, address(f), c[i], _notAdmin(nid(deployer)));
            _viaRefused(trouter, bytes32(0), f, c[i], _notAdmin(bytes32(0)));
        }
        _viaRefused(trouter, bytes32(0), f, abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))), _notAdmin(bytes32(0)));
        _viaRefused(trouter, bytes32(0), f, abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))), _notAdmin(bytes32(0)));
        _viaRefused(trouter, bytes32(0), f, abi.encodeCall(IFactoryAdmin.revokeApproval, (bytes32(uint256(1)), EnvKit.uidOf(address(f)))),
            _notAdmin(bytes32(0)));
        Rel memory t = _tok();
        _refused(deployer, address(f), _deployCd(t, address(f)), _notApproved(_key(f, t)));
    }

    /// M22: before `configureChain`, the admin can neither transfer nor renounce (nor approve, revoke or deploy).
    function test_unconfigured_refused() public {
        OpenFactory f = _new(nid(deployer));
        bytes memory nc = abi.encodeWithSelector(IOpenFactory.ChainNotConfigured.selector);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))), nc);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(f)))), nc);
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _refused(deployer, address(f), _approveWith(rs[i], bytes32(0), address(f), 0, _until()), nc);
            _refused(deployer, address(f), _deployCd(rs[i], address(f)), nc);
        }
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (bytes32(uint256(1)), EnvKit.uidOf(address(f)))), nc);
        assertEq(_a(f).admin(), nid(deployer));
    }

    /// A derived pending on a factory without a router has no path to accept: the admin stays.
    function test_routerless_derivedPendingCannotAccept() public {
        OpenFactory f = _ready(address(0));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (ml, EnvKit.uidOf(address(f)))));
        _refused(RELAYER, address(router), _acceptCd(ml, f),
            abi.encodeWithSelector(IFactoryAdmin.NotPendingAdmin.selector, nid(address(router))));
        assertEq(_a(f).admin(), nid(deployer));
        assertEq(_a(f).pendingAdmin(), ml);
    }

    // ------------------------------------------------------------------ the deploy ruling (§5.6, §8): passing

    /// Row 1: the native admin sends each deploy itself, one transaction, no approval.
    function test_shortcut_nativeAdminDeploysItself() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _call(deployer, address(f), _deployCd(rs[i], address(f)));
            assertEq(_state(f, _key(f, rs[i])), NONE, "no approval written");
        }
        assertTrue(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1) != address(0));
        assertTrue(f.dexImplementationOf(1) != address(0));
        assertTrue(f.classReleaseOf(IOpenFactory.ReleaseId(CLS, 0, 1)).implementation != address(0));
    }

    /// Row 2, directly: a native EOA admin approves each release, another account deploys it; the approval is consumed.
    function test_shortcut_eoaApprovesDirectly() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            bytes32 k = _key(f, rs[i]);
            uint64 u = _until();
            bytes memory cd = _approveCd(f, rs[i], u);
            vm.expectEmit(true, true, true, true, address(f));
            emit IFactoryAdmin.ReleaseApproved(k, 0, u);
            _call(deployer, address(f), cd);
            (uint8 s, uint32 g, uint64 un) = _a(f).approvalOf(k);
            assertEq(s, LIVE);
            assertEq(g, 0);
            assertEq(un, u);
            _call(STRANGER, address(f), _deployCd(rs[i], address(f)));
            assertEq(_state(f, k), CONSUMED);
        }
        assertTrue(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1) != address(0));
    }

    /// Row 2, through the router: the native EOA's signed approval (the router's subject is its id), anyone deploys.
    function test_shortcut_eoaApprovesThroughRouter() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _via(trouter, nid(deployer), f, _approveCd(f, rs[i], _until()));
            _call(STRANGER, address(f), _deployCd(rs[i], address(f)));
            assertEq(_state(f, _key(f, rs[i])), CONSUMED);
        }
    }

    /// Row 3: a derived admin (`mldsa65`, an `msig` of three ML-DSA-65 at 2-of-3, `webauthn-p256`: their ids; the test
    /// router stands for the router's verification) approves, sent by a stranger, and another account deploys.
    function test_shortcut_derivedApprovesThroughRouter() public {
        bytes32[3] memory ids = [UAKinds.uaOf(UAKinds.MLDSA65, abi.encode("mldsa65")),
            UAKinds.uaOf(UAKinds.MSIG, abi.encode("3 x mldsa65, 2-of-3")),
            UAKinds.uaOf(UAKinds.WEBAUTHN_P256, abi.encode("webauthn-p256"))];
        for (uint256 j; j < 3; ++j) {
            OpenFactory f = _ready(address(trouter));
            _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (ids[j], EnvKit.uidOf(address(f)))));
            _via(trouter, ids[j], f, abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
            Rel[3] memory rs = _rels();
            for (uint256 i; i < 3; ++i) {
                _via(trouter, ids[j], f, _approveCd(f, rs[i], _until()));
                assertEq(_state(f, _key(f, rs[i])), LIVE);
                _call(next, address(f), _deployCd(rs[i], address(f)));
                assertEq(_state(f, _key(f, rs[i])), CONSUMED);
            }
        }
    }

    /// A native admin's own deploy with a live approval of the same key consumes it (none left dangling).
    function test_shortcut_consumesLiveApproval() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _call(deployer, address(f), _approveCd(f, rs[i], _until()));
            _call(deployer, address(f), _deployCd(rs[i], address(f)));
            assertEq(_state(f, _key(f, rs[i])), CONSUMED);
        }
    }

    /// An admin EOA that is a 7702 designator never takes the shortcut (D2): its deploy needs a live approval, which its
    /// signed router op gives.
    function test_designatorAdmin_deploysOnlyThroughApproval() public {
        OpenFactory f = _ready(address(trouter));
        vm.etch(deployer, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _refused(deployer, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
            _via(trouter, nid(deployer), f, _approveCd(f, rs[i], _until()));
            _call(deployer, address(f), _deployCd(rs[i], address(f)));
            assertEq(_state(f, _key(f, rs[i])), CONSUMED);
        }
    }

    /// M25 (tag, chainUid, factory): the stored key is the spec's formula, field for field.
    function test_keys_areTheSpecFormula() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            uint64 u = _until();
            _call(deployer, address(f), _approveCd(f, rs[i], u));
            (uint8 s, uint32 g, uint64 un) = _a(f).approvalOf(_key(f, rs[i]));
            assertEq(s, LIVE);
            assertEq(g, 0);
            assertEq(un, u);
        }
        assertTrue(_key(f, rs[0]) != _key(f, rs[1]) && _key(f, rs[1]) != _key(f, rs[2]), "one tag per domain");
    }

    // ------------------------------------------------------------------ the deploy ruling: refused

    /// M24: no approval, a sender that is not the admin: refused before anything else (the version included).
    function test_deploy_withoutApprovalRefused() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
            Rel memory v0 = rs[i];
            v0.version = 0;
            _refused(STRANGER, address(f), _deployCd(v0, address(f)), _notApproved(_key(f, v0)));
        }
    }

    /// M24, M25 (envVersion, initSelector, interfaceId): a deploy one byte or one field off its approval is refused; the
    /// exact one then passes (positive control).
    function test_deploy_oneByteOrFieldRefused() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) _call(deployer, address(f), _approveCd(f, rs[i], _until()));
        for (uint256 i; i < 3; ++i) {
            Rel[] memory off = _offByOne(rs[i]);
            for (uint256 j; j < off.length; ++j) {
                _refused(STRANGER, address(f), _deployCd(off[j], address(f)), _notApproved(_key(f, off[j])));
            }
            _call(STRANGER, address(f), _deployCd(rs[i], address(f)));
        }
    }

    /// The variants of `r` one byte or one field off: the init code, `implArgs`, `envVersion`, the version, the kind; the
    /// class release also its class, `initSelector` and `interfaceId`.
    function _offByOne(Rel memory r) internal pure returns (Rel[] memory v) {
        v = new Rel[](r.d == 2 ? 8 : (r.d == 0 ? 5 : 4));
        for (uint256 j; j < v.length; ++j) v[j] = _copy(r);
        v[0].code[v[0].code.length - 1] ^= 0x01;
        v[1].args[0] ^= 0x01;
        v[2].envVersion = 2;
        v[3].version = 2;
        if (r.d == 0) v[4].knd = uint16(IOpenFactory.TokenKind.WRAPPED);
        if (r.d == 2) {
            v[4].knd = 1;
            v[5].cls = CLS + 1;
            v[6].sel = IRosterKind.initialize.selector;
            v[7].iface = type(IRosterKind).interfaceId;
        }
    }

    function _copy(Rel memory r) internal pure returns (Rel memory c) {
        c = Rel(r.d, r.cls, r.knd, r.version, r.envVersion, r.sel, r.iface, bytes.concat(r.code), bytes.concat(r.args));
    }

    /// M27: an approval is used once (the check precedes the version check).
    function test_deploy_usedTwiceRefused() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _call(deployer, address(f), _approveCd(f, rs[i], _until()));
            _call(STRANGER, address(f), _deployCd(rs[i], address(f)));
            _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
        }
    }

    function test_deploy_revokedRefused() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            bytes32 k = _key(f, rs[i]);
            _call(deployer, address(f), _approveCd(f, rs[i], _until()));
            vm.expectEmit(true, true, true, true, address(f));
            emit IFactoryAdmin.ReleaseApprovalRevoked(k);
            _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k, EnvKit.uidOf(address(f)))));
            assertEq(_state(f, k), NONE);
            _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(k));
        }
    }

    /// M26 (until): live through `until`, dead after it.
    function test_deploy_expiredRefused() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        uint64 u = uint64(block.timestamp + 1 hours);
        for (uint256 i; i < 3; ++i) _call(deployer, address(f), _approveCd(f, rs[i], u));
        vm.warp(u);
        _call(STRANGER, address(f), _deployCd(rs[0], address(f)));
        vm.warp(u + 1);
        for (uint256 i = 1; i < 3; ++i) _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
    }

    /// M26 (generation): an approval of the previous admin term opens nothing, after a transfer and after a renounce.
    function test_deploy_previousTermRefused() public {
        OpenFactory f = _ready(address(trouter));
        OpenFactory g = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _call(deployer, address(f), _approveCd(f, rs[i], _until()));
            _call(deployer, address(g), _approveCd(g, rs[i], _until()));
        }
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        _call(deployer, address(g), abi.encodeCall(IFactoryAdmin.renounceAdmin, (EnvKit.uidOf(address(g)))));
        for (uint256 i; i < 3; ++i) {
            _refused(STRANGER, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
            _refused(STRANGER, address(g), _deployCd(rs[i], address(g)), _notApproved(_key(g, rs[i])));
        }
    }

    /// M23: after the admin moves to an `msig`, the original deployer EOA has no shortcut.
    function test_deploy_deployerAfterMoveToMsigRefused() public {
        OpenFactory f = _ready(address(router));
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (msig, EnvKit.uidOf(address(f)))));
        _accept(msig, f);
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) _refused(deployer, address(f), _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
    }

    /// M23 (the router's subject): a deploy through a router acting for the admin is no shortcut (no deploy is a router
    /// op; the shortcut reads `msg.sender` only).
    function test_deploy_throughRouterIsNoShortcut() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _viaRefused(trouter, nid(deployer), f, _deployCd(rs[i], address(f)), _notApproved(_key(f, rs[i])));
        }
    }

    /// M29: `chainUid`, the factory and `adminGeneration` must be the factory's own.
    function test_approve_fieldMismatch() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _refused(deployer, address(f), _approveWith(rs[i], keccak256("chain B"), address(f), 0, _until()),
                abi.encodeWithSelector(IFactoryAdmin.ApprovalFieldMismatch.selector, uint8(0)));
            _refused(deployer, address(f), _approveWith(rs[i], chainUidA, address(0xF2), 0, _until()),
                abi.encodeWithSelector(IFactoryAdmin.ApprovalFieldMismatch.selector, uint8(1)));
            _refused(deployer, address(f), _approveWith(rs[i], chainUidA, address(f), 1, _until()),
                abi.encodeWithSelector(IFactoryAdmin.ApprovalFieldMismatch.selector, uint8(2)));
        }
    }

    /// M25 (factory): an approval on another factory of the same admin and chain opens nothing here.
    function test_approve_otherFactoryOpensNothing() public {
        OpenFactory f = _ready(address(trouter));
        OpenFactory g = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            _call(deployer, address(f), _approveCd(f, rs[i], _until()));
            assertTrue(_key(f, rs[i]) != _key(g, rs[i]));
            _refused(STRANGER, address(g), _deployCd(rs[i], address(g)), _notApproved(_key(g, rs[i])));
            _refused(deployer, address(g), _approveCd(f, rs[i], _until()),
                abi.encodeWithSelector(IFactoryAdmin.ApprovalFieldMismatch.selector, uint8(1)));
        }
    }

    /// M25 (chainUid): the same factory address on another chain (another `chain_uid`): the approval of chain A is not
    /// there, its replayed call is refused, and the key is chain B's.
    function test_approve_otherChainOpensNothing() public {
        bytes32 uidB = keccak256("chain B");
        uint256 snap = vm.snapshotState();
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        bytes[3] memory cds;
        bytes32[3] memory keysA;
        for (uint256 i; i < 3; ++i) {
            cds[i] = _approveCd(f, rs[i], _until());
            keysA[i] = _key(f, rs[i]);
            _call(deployer, address(f), cds[i]);
        }
        vm.revertToState(snap);
        OpenFactory fb = _new(nid(deployer));
        assertEq(address(fb), address(f), "one address on both chains");
        EnvKit.genesis(uidB);
        TestRouter rb = new TestRouter(uidB, PREG);
        IFactoryToken.Env memory e;
        vm.startPrank(deployer);
        fb.configureChain(uidB, 0, address(rb), address(rb).codehash, 0, bytes32(0));
        fb.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, EnvKit.uidOf(address(fb)), e);
        fb.publishDexEnv(1, EnvKit.uidOf(address(fb)), e);
        fb.publishClassEnv(CLS, 0, 1, EnvKit.uidOf(address(fb)), e);
        vm.stopPrank();
        for (uint256 i; i < 3; ++i) {
            assertEq(_state(fb, keysA[i]), NONE);
            assertTrue(_key(fb, rs[i]) != keysA[i]);
            _refused(deployer, address(fb), cds[i], abi.encodeWithSelector(IFactoryAdmin.ApprovalFieldMismatch.selector, uint8(0)));
            _refused(STRANGER, address(fb), _deployCd(rs[i], address(fb)), _notApproved(_key(fb, rs[i])));
        }
    }

    /// M28: `revokeApproval` is the admin's, and only for a stored entry not consumed (live or not).
    function test_revoke_rules() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        bytes32 k0 = _key(f, rs[0]);
        bytes memory nr = abi.encodeWithSelector(IFactoryAdmin.ApprovalNotRevocable.selector, k0);
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k0, EnvKit.uidOf(address(f)))), nr);
        _call(deployer, address(f), _approveCd(f, rs[0], _until()));
        _refused(STRANGER, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k0, EnvKit.uidOf(address(f)))), _notAdmin(nid(STRANGER)));
        _call(STRANGER, address(f), _deployCd(rs[0], address(f)));
        _refused(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k0, EnvKit.uidOf(address(f)))), nr);
        assertEq(_state(f, k0), CONSUMED);
        // an expired entry and one of an earlier term are stored, not consumed: revocable
        bytes32 k1_ = _key(f, rs[1]);
        _call(deployer, address(f), _approveCd(f, rs[1], uint64(block.timestamp + 1)));
        vm.warp(block.timestamp + 2);
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k1_, EnvKit.uidOf(address(f)))));
        assertEq(_state(f, k1_), NONE);
    }

    /// `until` in the future and at most 30 days ahead.
    function test_approve_tooLong() public {
        OpenFactory f = _ready(address(trouter));
        Rel memory t = _tok();
        uint64[2] memory bad = [uint64(block.timestamp + 30 days + 1), uint64(block.timestamp)];
        for (uint256 i; i < 2; ++i) {
            _refused(deployer, address(f), _approveCd(f, t, bad[i]),
                abi.encodeWithSelector(IFactoryAdmin.ApprovalTooLong.selector, bad[i]));
        }
        _call(deployer, address(f), _approveCd(f, t, uint64(block.timestamp + 30 days)));
    }

    /// M30: a live approval is not approved again (`ApprovalLive`); one no longer live is overwritten: after expiry, after
    /// a transfer of the admin, after a revoke.
    function test_reapproval() public {
        OpenFactory f = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        bytes32 k = _key(f, rs[0]);
        _call(deployer, address(f), _approveCd(f, rs[0], uint64(block.timestamp + 1 hours)));
        _refused(deployer, address(f), _approveCd(f, rs[0], _until()),
            abi.encodeWithSelector(IFactoryAdmin.ApprovalLive.selector, k));
        vm.warp(block.timestamp + 2 hours);
        _call(deployer, address(f), _approveCd(f, rs[0], _until())); // after expiry
        assertEq(_state(f, k), LIVE);
        _call(deployer, address(f), abi.encodeCall(IFactoryAdmin.transferAdmin, (nid(next), EnvKit.uidOf(address(f)))));
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.acceptAdmin, ()));
        _call(next, address(f), _approveCd(f, rs[0], _until())); // after a transfer
        (, uint32 g,) = _a(f).approvalOf(k);
        assertEq(g, 1);
        _call(next, address(f), abi.encodeCall(IFactoryAdmin.revokeApproval, (k, EnvKit.uidOf(address(f)))));
        _call(next, address(f), _approveCd(f, rs[0], _until())); // after a revoke
        assertEq(_state(f, k), LIVE);
        _call(STRANGER, address(f), _deployCd(rs[0], address(f)));
    }

    // ------------------------------------------------------------------ gas independence (§5.6 item 3, Fable re-check N3)

    function _burn() internal pure returns (Rel memory r) {
        r = _cls();
        r.code = type(BurnKind).creationCode;
    }

    /// The lowest gas limit at which `from`'s `cd` to `f` succeeds (state restored).
    function _lowestGas(OpenFactory f, address from, bytes memory cd) internal returns (uint256 lo) {
        uint256 hi = 16_000_000; // under EIP-7825's per-transaction cap
        lo = 100_000;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            (bool ok,) = _try(f, from, cd, mid);
            if (ok) hi = mid;
            else lo = mid + 1;
        }
    }

    function _try(OpenFactory f, address from, bytes memory cd, uint256 gas_) internal returns (bool ok, bytes memory ret) {
        uint256 snap = vm.snapshotState();
        vm.prank(from);
        (ok, ret) = address(f).call{gas: gas_}(cd);
        vm.revertToState(snap);
    }

    /// The deploy at the lowest gas that succeeds stores what the deploy at ample gas stores: the same code, the same
    /// release record. The release's first probe spends 25,000 of its 30,000 gas.
    function test_lowestGasDeployEqualsAmple() public {
        OpenFactory f = _ready(address(trouter));
        Rel memory r = _burn();
        uint256 low = _lowestGas(f, deployer, _deployCd(r, address(f)));
        console2.log("lowest gas of the class deploy (shortcut)", low);
        uint256 snap = vm.snapshotState();
        vm.prank(deployer);
        (bool ok,) = address(f).call{gas: low}(_deployCd(r, address(f)));
        assertTrue(ok);
        IOpenFactory.ClassRelease memory a = f.classReleaseOf(_id(r));
        bytes32 ha = a.implementation.codehash;
        vm.revertToState(snap);
        _call(deployer, address(f), _deployCd(r, address(f)));
        IOpenFactory.ClassRelease memory b = f.classReleaseOf(_id(r));
        assertEq(abi.encode(a), abi.encode(b));
        assertEq(ha, b.implementation.codehash);
    }

    /// M31: below its floor a probe is refused (`ProbeGasLow`), never counted: between the lowest gas that reaches the
    /// probes and the lowest that passes them, the deploy fails with `ProbeGasLow` and nothing else from the probes.
    function test_supportsBelowFloorProbeGasLow() public {
        OpenFactory f = _ready(address(trouter));
        bytes memory cd = _deployCd(_burn(), address(f));
        uint256 low = _lowestGas(f, deployer, cd);
        bool seen;
        for (uint256 g = low - 1; g > 150_000 && !seen; g -= 10_000) {
            (bool ok, bytes memory ret) = _try(f, deployer, cd, g);
            assertFalse(ok);
            if (ret.length >= 4 && bytes4(ret) == IFactoryAdmin.ProbeGasLow.selector) seen = true;
            if (ret.length >= 4) {
                assertTrue(bytes4(ret) != IOpenFactory.InterfaceNotSupported.selector, "a starved probe counted");
            }
        }
        assertTrue(seen, "ProbeGasLow below the floor");
    }

    // ------------------------------------------------------------------ the approval keys of typed_ops.json (T8)

    /// The three approval rows' `approvalKey` (clientkeys' `releaseApprovalKey`, reproduced by ua-rs) is the factory's own: a
    /// factory at the row's `factory`, configured with the row's `chainUid`, approves the row's release directly and
    /// `approvalOf` answers LIVE under that key (none before).
    function test_approvalKeys_equalTypedOpsRows() public {
        string memory j = vm.readFile("../vectors/typed/typed_ops.json");
        string[3] memory ops = ["UAApproveTokenRelease", "UAApproveDexRelease", "UAApproveRelease"];
        for (uint256 i; i < 3; ++i) {
            string memory m = string.concat(".ops.", ops[i], ".message.");
            bytes32 uid = vm.parseJsonBytes32(j, string.concat(m, "chainUid"));
            address fac = vm.parseJsonAddress(j, string.concat(m, "factory"));
            bytes32 key = vm.parseJsonBytes32(j, string.concat(".ops.", ops[i], ".approvalKey"));
            deployCodeTo("OpenFactory.sol:OpenFactory", abi.encode(nid(deployer)), fac);
            EnvKit.genesis(uid);
            vm.prank(deployer);
            OpenFactory(fac).configureChain(uid, 0, address(0), bytes32(0), 0, bytes32(0));
            (uint8 st,,) = _a(OpenFactory(fac)).approvalOf(key);
            assertEq(st, NONE, ops[i]);
            bytes memory cd = _approveRowCd(j, m, i, uid, fac, _a(OpenFactory(fac)).adminGeneration());
            vm.prank(deployer);
            (bool ok,) = fac.call(cd);
            assertTrue(ok, ops[i]);
            (st,,) = _a(OpenFactory(fac)).approvalOf(key);
            assertEq(st, LIVE, ops[i]);
        }
    }

    /// Row `i` of the three approval rows of `typed_ops.json` (`m` its message path) as the factory's direct approve call:
    /// every argument is static, so the call is the selector and the words in order.
    function _approveRowCd(string memory j, string memory m, uint256 i, bytes32 uid, address fac, uint32 gen)
        internal view returns (bytes memory)
    {
        bytes4[3] memory sel = [IFactoryAdmin.approveTokenRelease.selector, IFactoryAdmin.approveDexRelease.selector,
            IFactoryAdmin.approveRelease.selector];
        return bytes.concat(sel[i], _rowHead(j, m, i), abi.encode(vm.parseJsonBytes32(j, string.concat(m, "initcodeHash")),
            vm.parseJsonBytes32(j, string.concat(m, "implArgsHash"))), abi.encode(uid, fac, gen, _until()));
    }

    /// The domain's own words before the two hashes: token `kind, version, envVersion`; DEX `version, envVersion`; class
    /// `contractClass, kind, version, envVersion, initSelector, interfaceId`.
    function _rowHead(string memory j, string memory m, uint256 i) internal pure returns (bytes memory) {
        bytes memory ve = abi.encode(uint64(vm.parseJsonUint(j, string.concat(m, "version"))),
            uint16(vm.parseJsonUint(j, string.concat(m, "envVersion"))));
        if (i == 1) return ve;
        uint16 k = uint16(vm.parseJsonUint(j, string.concat(m, "kind")));
        if (i == 0) return bytes.concat(abi.encode(uint8(k)), ve);
        return bytes.concat(abi.encode(uint16(vm.parseJsonUint(j, string.concat(m, "contractClass"))), k), ve,
            abi.encode(bytes4(vm.parseJsonBytes(j, string.concat(m, "initSelector"))),
                bytes4(vm.parseJsonBytes(j, string.concat(m, "interfaceId")))));
    }

    /// T10: `DeploySend.releaseAt` is the address each of the three deploys lands at (the plan's "already deployed" check).
    function test_deploySend_releaseAtIsTheDeploysAddress() public {
        OpenFactory f = _ready(address(trouter));
        DeploySend ds = new DeploySend();
        Rel[3] memory rs = _rels();
        for (uint256 i; i < 3; ++i) {
            address want = ds.releaseAt(address(f), _deployCd(rs[i], address(f)));
            assertEq(want.code.length, 0);
            vm.prank(deployer);
            (bool ok, bytes memory ret) = address(f).call(_deployCd(rs[i], address(f)));
            assertTrue(ok);
            assertEq(abi.decode(ret, (address)), want);
        }
        assertEq(ds.releaseAt(address(f), abi.encodeCall(OpenFactory.setTokenKindEnabled,
            (IOpenFactory.TokenKind.NORMAL, true, EnvKit.uidOf(address(f))))), address(0));
    }

    // ------------------------------------------------------------------ gas (§5.6 "Gas", §9)

    /// An approval and a deploy through it against the native admin's shortcut, each its own transaction (`isolate`).
    function test_gas_approvalAndDeploy() public {
        OpenFactory f = _ready(address(trouter));
        OpenFactory g = _ready(address(trouter));
        Rel[3] memory rs = _rels();
        string[3] memory names = [string("token"), "dex", "class"];
        for (uint256 i; i < 3; ++i) {
            (uint256 ar, uint256 as_) = _gasOf(deployer, address(f), _approveCd(f, rs[i], _until()));
            (uint256 dr, uint256 ds) = _gasOf(STRANGER, address(f), _deployCd(rs[i], address(f)));
            (uint256 sr, uint256 ss) = _gasOf(deployer, address(g), _deployCd(rs[i], address(g)));
            console2.log(string.concat("FACTORYGAS ", names[i], " approve: regular / state"), ar, as_);
            console2.log(string.concat("FACTORYGAS ", names[i], " deploy through the approval: regular / state"), dr, ds);
            console2.log(string.concat("FACTORYGAS ", names[i], " deploy by the admin (shortcut): regular / state"), sr, ss);
        }
    }

    function _gasOf(address from, address to, bytes memory cd) internal returns (uint256 reg, uint256 st) {
        _call(from, to, cd);
        Vm.Gas memory g = vm.lastCallGas();
        (reg, st) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
    }
}
