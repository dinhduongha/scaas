// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {IComplianceRegistry} from "../../src/regulated/IComplianceRegistry.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {TYPED_OPS, msgField, domainField} from "../metatx/NamedEntry.t.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {NoteKind, INoteKind} from "../v2/mocks/GenericKinds.sol";

/// The router's fifteen admin ops of round 3r (spec 2026-11-10-admin-not-owner.md §5.4), written out here so the test pins
/// the ABI apart from the source's declarations (and compiles against the router before T7: the red run).
interface IRouterAdminOps {
    function mtxPublishTokenEnv(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind, uint16 envVersion,
        IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxPublishDexEnv(MetaTxLib.UAEnvelope calldata e, address target, uint16 envVersion,
        IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxPublishClassEnv(MetaTxLib.UAEnvelope calldata e, address target, uint16 contractClass, uint16 kind,
        uint16 envVersion, IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxApproveTokenRelease(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind,
        uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid, address factory,
        uint32 adminGeneration, uint64 until, IUARegistry.UASig calldata auth) external;
    function mtxApproveDexRelease(MetaTxLib.UAEnvelope calldata e, address target, uint64 version, uint16 envVersion,
        bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until,
        IUARegistry.UASig calldata auth) external;
    function mtxApproveRelease(MetaTxLib.UAEnvelope calldata e, address target, GovernanceRouter.ReleaseApproval calldata approval,
        IUARegistry.UASig calldata auth) external;
    function mtxRevokeApproval(MetaTxLib.UAEnvelope calldata e, address target, bytes32 key, IUARegistry.UASig calldata auth)
        external;
    function mtxDeprecateToken(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind, uint64 version,
        string calldata reason, IUARegistry.UASig calldata auth) external;
    function mtxDeprecateDex(MetaTxLib.UAEnvelope calldata e, address target, uint64 version, string calldata reason,
        IUARegistry.UASig calldata auth) external;
    function mtxDeprecateRelease(MetaTxLib.UAEnvelope calldata e, address target, uint16 contractClass, uint16 kind,
        uint64 version, string calldata reason, IUARegistry.UASig calldata auth) external;
    function mtxSetTokenKindEnabled(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind, bool on,
        IUARegistry.UASig calldata auth) external;
    function mtxSetClassKindEnabled(MetaTxLib.UAEnvelope calldata e, address target, uint16 contractClass, uint16 kind,
        bool on, IUARegistry.UASig calldata auth) external;
    function mtxSetKycProvider(MetaTxLib.UAEnvelope calldata e, address target, bytes32 provider, bool enabled,
        IUARegistry.UASig calldata auth) external;
    function mtxSetCompliance(MetaTxLib.UAEnvelope calldata e, address target, bytes32[] calldata accounts,
        uint64[] calldata flags, uint64[] calldata until, IUARegistry.UASig calldata auth) external;
    function mtxSetChainEntries(MetaTxLib.UAEnvelope calldata e, address target, address relayFeeRouter,
        bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash, address complianceRegistry,
        bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory, bytes32 smartKeyAccountFactoryCodeHash,
        address zetherStatements, bytes32 zetherStatementsCodeHash, IUARegistry.UASig calldata auth) external;
}

/// A token (kind 0) or DEX release for the catalogue's checks and nothing more.
contract RouterOpsRelease {
    address public immutable factory;

    constructor(address factory_, bytes memory) {
        factory = factory_;
    }

    function kind() external pure returns (uint8) { return 0; }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    function modules() external pure returns (address[] memory) {}
}

/// A target whose `setTokenKindEnabled` re-enters the router with prepared calldata: a nested router op (spec §5.5).
contract RouterReenter {
    address internal immutable _router;
    bytes internal _cd;

    constructor(address router_) {
        _router = router_;
    }

    function arm(bytes calldata cd) external {
        _cd = cd;
    }

    function setTokenKindEnabled(uint8, bool) external {
        (bool ok, bytes memory ret) = _router.call(_cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }
}

/// ERC-1271 that answers yes to every signature: the delegate of an EIP-7702 designator admin, and, as a contract admin
/// itself, the positive control that ERC-1271 would say yes.
contract YesSigner {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// Records the call it receives (the typed_ops.json rows' target).
contract RouterOpsSink {
    bytes public last;

    fallback() external {
        last = msg.data;
    }
}

/// CREATE in a call: the router's deploy as one top-level call (`vm.lastCallGas`).
contract RouterCreator {
    function create(bytes memory code) external returns (address a) {
        assembly ("memory-safe") { a := create(0, add(code, 32), mload(code)) }
        require(a != address(0), "create");
    }
}

/// Round 3r (CTR-GOV-23; spec 2026-11-10-admin-not-owner.md §5.4, §5.5, §5.6 items 1-2, §8): the router's fifteen admin ops
/// of `OpenFactory` and `ComplianceRegistry`, each `mtx<Op>(UAEnvelope e, address target, <params>, UASig auth)` over
/// `UA<Op>(bytes32 from,address target,<words>,E)`, fee mode `NONE`, relayable at fee 0, on a real factory, registry, UA
/// registry and router (the stand-in verifier of `UARegistryBase` for the derived kinds: their paths are real, the PQ math is
/// the stand-in's). Every op by a stranger relayer for a derived admin (secp256k1, mldsa65, an `msig` of three mldsa65 at
/// 2-of-3); the field-binding matrix of every signed struct (each scalar; per array one element, the length, the order; the
/// bytes of `reason`; every `Env` field; `target`), each word changed alone against the signature and refused by the router,
/// with the untouched call as the positive control; replay on a second factory, registry, chain; a nested router op; a
/// 7702-delegated native admin checked by its own key only. The test's own EIP-712 encoding (type strings written here,
/// not read from the router). **UNAUDITED.**
contract GovRouterAdminTest is UARegistryBase {
    uint16 constant K1 = 0x0108;
    uint16 constant ML65 = 0x0131;
    uint16 constant WA = 0x0100; // webauthn-p256
    uint64 constant CAP = 4_250_000;
    address constant PREG = 0x5ca00000000000000000000000000000000000B7;
    address constant RELAYER = address(0xBEEF); // a stranger relayer: no role anywhere
    address constant STRANGER = address(0x5757);
    uint16 constant CLS = 4; // NoteKind's class
    uint64 constant MAX = type(uint64).max;
    bytes32 constant PROV = bytes32(uint256(0x9A0F));
    string constant TAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant ENV_T =
        "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)";

    // the fifteen ops, in the order of spec §5.4's table
    uint8 constant PUBLISH_ENV = 0;
    uint8 constant PUBLISH_DEX_ENV = 1;
    uint8 constant PUBLISH_CLASS_ENV = 2;
    uint8 constant APPROVE_TOKEN = 3;
    uint8 constant APPROVE_DEX = 4;
    uint8 constant APPROVE_CLASS = 5;
    uint8 constant REVOKE = 6;
    uint8 constant DEPRECATE = 7;
    uint8 constant DEPRECATE_DEX = 8;
    uint8 constant DEPRECATE_RELEASE = 9;
    uint8 constant SET_KIND = 10;
    uint8 constant SET_CLASS_KIND = 11;
    uint8 constant SET_KYC = 12;
    uint8 constant SET_COMPLIANCE = 13;
    uint8 constant SET_ENTRIES = 14;

    UARegistry preg;
    GovernanceRouter router;
    SmartKeyAccountFactory skaf;
    address impl;
    RelayFeeRouter relay;
    ZetherStatements zs;
    address deployer;
    mapping(bytes32 => uint256) pkOf; // native ids: the ECDSA key

    bytes k1Key;
    bytes32 k1;
    bytes mlKey;
    bytes32 ml;
    bytes waKey;
    bytes32 wa;
    bytes[3] mkeys;
    bytes msigData;
    bytes32 msig;

    /// One signed op: its id, `target`, its static words after `target` (each the ABI word: the struct's EIP-712 word), and
    /// its dynamic part (`env`, `reason`, the three row arrays) where it has one.
    struct P {
        uint8 op;
        address target;
        uint256[] w;
        IFactoryToken.Env env;
        string reason;
        bytes32[] accounts;
        uint64[] flags;
        uint64[] until;
    }

    function setUp() public override {
        super.setUp();
        vm.warp(1_800_000_000);
        skaf = new SmartKeyAccountFactory(chainUidA);
        impl = skaf.IMPLEMENTATION();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](3);
        c[0] = UARegistry.KindConfig(K1, address(mock), 50_000);
        c[1] = UARegistry.KindConfig(ML65, address(mock), CAP);
        c[2] = UARegistry.KindConfig(WA, address(mock), 400_000);
        preg = _deploy(PREG, chainUidA, address(0), false, BUDGET, impl, true, c);
        router = new GovernanceRouter(chainUidA, PREG, impl, false);
        relay = new RelayFeeRouter();
        zs = new ZetherStatements();
        uint256 pk;
        (deployer, pk) = makeAddrAndKey("deployer");
        pkOf[nid(deployer)] = pk;
        Vm.Wallet memory w = vm.createWallet("k1 signer");
        k1Key = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        k1 = _register(preg, K1, k1Key);
        mlKey = _mlKey(1);
        ml = _register(preg, ML65, mlKey);
        waKey = _key(WA);
        wa = _register(preg, WA, waKey);
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) {
            mkeys[i] = _mlKey(10 + i);
            m[i] = Member(ML65, _register(preg, ML65, mkeys[i]), 1);
        }
        msigData = _msigKey(2, m);
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msigData);
        msig = UACall.register(preg, UAKinds.MSIG, msigData, _none(),
            abi.encode(_memberSigs(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG), 2)), "");
        for (uint256 i; i < 3; ++i) preg.acceptMembership(msig, _acceptKeySig(msigData, ML65, mkeys[i]));
    }

    // ------------------------------------------------------------------ fixture

    /// An mldsa65 public key of the right length (the stand-in verifier reads no structure).
    function _mlKey(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1952);
        for (uint256 i; i < 1952; i += 32) {
            bytes32 x = keccak256(abi.encode(ML65, salt, i));
            for (uint256 j; j < 32 && i + j < 1952; ++j) pk[i + j] = x[j];
        }
    }

    /// A factory of `deployer` on chain A with the router, env 1 of `NORMAL`, the DEX and class 4 kind 0 (empty envs) and a
    /// release of each (the native admin's own deploys), its admin then moved to `admin_` (the derived UA's signed accept,
    /// a stranger relayer); and a `ComplianceRegistry(admin_, router)`.
    function _stack(bytes32 admin_) internal returns (OpenFactory f, ComplianceRegistry cr) {
        f = new OpenFactory(nid(deployer));
        EnvKit.genesis(chainUidA);
        IFactoryToken.Env memory e;
        vm.startPrank(deployer);
        f.configureChain(chainUidA, 0, address(router), address(router).codehash, 0, bytes32(0));
        f.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, e);
        f.publishDexEnv(1, e);
        f.publishClassEnv(CLS, 0, 1, e);
        f.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(RouterOpsRelease).creationCode, hex"01");
        f.deployDexImplementation(1, 1, type(RouterOpsRelease).creationCode, hex"02");
        f.deployImplementation(IOpenFactory.ReleaseId(CLS, 0, 1), 1, INoteKind.initialize.selector,
            type(INoteKind).interfaceId, type(NoteKind).creationCode, hex"03");
        if (admin_ != nid(deployer)) f.transferAdmin(admin_);
        vm.stopPrank();
        if (admin_ != nid(deployer)) _acceptVia(admin_, address(f));
        cr = new ComplianceRegistry(admin_, address(router));
    }

    function _call(address from, address to, bytes memory cd) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _refused(address from, address to, bytes memory cd, bytes memory err) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        assertFalse(ok, "refused");
        assertEq(ret, err);
    }

    function _unauthorized(bytes32 id) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, id);
    }

    // ------------------------------------------------------------------ signing (the test's own EIP-712)

    function _name(uint8 op) internal pure returns (string memory) {
        return [string("PublishTokenEnv"), "PublishDexEnv", "PublishClassEnv", "ApproveTokenRelease", "ApproveDexRelease",
            "ApproveRelease", "RevokeApproval", "DeprecateToken", "DeprecateDex", "DeprecateRelease", "SetTokenKindEnabled",
            "SetClassKindEnabled", "SetKycProvider", "SetCompliance", "SetChainEntries"][op];
    }

    /// The words after `target` in the type string (spec §5.4's table, verbatim).
    function _params(uint8 op) internal pure returns (string memory) {
        return [string(",uint8 kind,uint16 envVersion,Env env"), ",uint16 envVersion,Env env",
            ",uint16 contractClass,uint16 kind,uint16 envVersion,Env env",
            ",uint8 kind,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until",
            ",uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until",
            ",uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until",
            ",bytes32 key", ",uint8 kind,uint64 version,string reason", ",uint64 version,string reason",
            ",uint16 contractClass,uint16 kind,uint64 version,string reason", ",uint8 kind,bool on",
            ",uint16 contractClass,uint16 kind,bool on", ",bytes32 provider,bool enabled",
            ",bytes32[] accounts,uint64[] flags,uint64[] until",
            ",address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash"][op];
    }

    function _typeString(uint8 op) internal pure returns (string memory s) {
        s = string.concat("UA", _name(op), "(bytes32 from,address target", _params(op), TAIL);
        if (op <= PUBLISH_CLASS_ENV) s = string.concat(s, ENV_T);
    }

    function _domain(GovernanceRouter r) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) = r.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _env(bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, 0, router.mtxNonce(from, 0), block.timestamp + 1 hours, 0, address(0), 0,
            address(0));
    }

    /// EIP-712 `Env`: each array the `keccak256` of its 32-byte words.
    function _envHash(IFactoryToken.Env memory v) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(ENV_T)), v.registry, v.smartKeyAccountImpl, v.hedera,
            keccak256(abi.encodePacked(v.deps)), keccak256(abi.encodePacked(v.params)), keccak256(abi.encodePacked(v.libs)),
            keccak256(abi.encodePacked(v.libCodeHashes))));
    }

    /// The struct's words after `target`: the static words, then the env's hash, the reason's or the three arrays'.
    function _words(P memory p) internal pure returns (bytes memory b) {
        b = abi.encodePacked(p.w);
        if (p.op <= PUBLISH_CLASS_ENV) b = bytes.concat(b, _envHash(p.env));
        else if (p.op >= DEPRECATE && p.op <= DEPRECATE_RELEASE) b = bytes.concat(b, keccak256(bytes(p.reason)));
        else if (p.op == SET_COMPLIANCE) {
            b = abi.encode(keccak256(abi.encodePacked(p.accounts)), keccak256(abi.encodePacked(p.flags)),
                keccak256(abi.encodePacked(p.until)));
        }
    }

    function _digestOn(GovernanceRouter r, P memory p, MetaTxLib.UAEnvelope memory e) internal view returns (bytes32) {
        bytes32 h = keccak256(bytes.concat(abi.encode(keccak256(bytes(_typeString(p.op))), e.from, p.target), _words(p),
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(r), h));
    }

    function _auth(bytes32 id, bytes32 d) internal view returns (IUARegistry.UASig memory a) {
        if (id == k1) (a.keyData, a.signature) = (k1Key, _sig(k1Key, UAKinds.uaMessage(K1, UAKinds.PURPOSE_METATX, d)));
        else if (id == ml) a.signature = _sig(mlKey, UAKinds.uaMessage(ML65, UAKinds.PURPOSE_METATX, d));
        else if (id == wa) (a.keyData, a.signature) = (waKey, _sig(waKey, UAKinds.uaMessage(WA, UAKinds.PURPOSE_METATX, d)));
        else if (id == msig) a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, d, 2);
        else if (pkOf[id] != 0) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkOf[id], d);
            a.signature = abi.encodePacked(r, s, v);
        } else {
            a.signature = hex"00"; // a contract admin: its ERC-1271 decides
        }
    }

    /// Slots 0..n-1 of the `msig` (index order), each over `(purpose, digest)` under `PURPOSE_MEMBER`.
    function _memberSigs(bytes32 ua, bytes32 purpose, bytes32 digest, uint256 n)
        internal view returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](n);
        bytes32 md = _memberDigest(ua, purpose, digest);
        for (uint16 i; i < n; ++i) {
            for (uint256 j; j < 3; ++j) {
                if (_indexOf(msigData, UAKinds.uaOf(ML65, mkeys[j])) != i) continue;
                s[i] = IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0),
                    _sig(mkeys[j], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
            }
        }
    }

    function _tail(bytes memory enc) internal pure returns (bytes memory t) {
        t = new bytes(enc.length - 32);
        for (uint256 i; i < t.length; ++i) t[i] = enc[i + 32];
    }

    function _sel(uint8 op) internal pure returns (bytes4) {
        if (op == APPROVE_TOKEN) return IRouterAdminOps.mtxApproveTokenRelease.selector;
        if (op == APPROVE_DEX) return IRouterAdminOps.mtxApproveDexRelease.selector;
        if (op == APPROVE_CLASS) return IRouterAdminOps.mtxApproveRelease.selector;
        if (op == REVOKE) return IRouterAdminOps.mtxRevokeApproval.selector;
        if (op == SET_KIND) return IRouterAdminOps.mtxSetTokenKindEnabled.selector;
        if (op == SET_CLASS_KIND) return IRouterAdminOps.mtxSetClassKindEnabled.selector;
        if (op == SET_KYC) return IRouterAdminOps.mtxSetKycProvider.selector;
        return IRouterAdminOps.mtxSetChainEntries.selector;
    }

    /// The router's calldata of `p` under `e` and `a`; a static op's words are its call's ABI words.
    function _cd(P memory p, MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) internal pure returns (bytes memory) {
        uint8 op = p.op;
        if (op == PUBLISH_ENV) {
            return abi.encodeCall(IRouterAdminOps.mtxPublishTokenEnv,
                (e, p.target, IOpenFactory.TokenKind(p.w[0]), uint16(p.w[1]), p.env, a));
        }
        if (op == PUBLISH_DEX_ENV) return abi.encodeCall(IRouterAdminOps.mtxPublishDexEnv, (e, p.target, uint16(p.w[0]), p.env, a));
        if (op == PUBLISH_CLASS_ENV) {
            return abi.encodeCall(IRouterAdminOps.mtxPublishClassEnv,
                (e, p.target, uint16(p.w[0]), uint16(p.w[1]), uint16(p.w[2]), p.env, a));
        }
        if (op == DEPRECATE) {
            return abi.encodeCall(IRouterAdminOps.mtxDeprecateToken,
                (e, p.target, IOpenFactory.TokenKind(p.w[0]), uint64(p.w[1]), p.reason, a));
        }
        if (op == DEPRECATE_DEX) return abi.encodeCall(IRouterAdminOps.mtxDeprecateDex, (e, p.target, uint64(p.w[0]), p.reason, a));
        if (op == DEPRECATE_RELEASE) {
            return abi.encodeCall(IRouterAdminOps.mtxDeprecateRelease,
                (e, p.target, uint16(p.w[0]), uint16(p.w[1]), uint64(p.w[2]), p.reason, a));
        }
        if (op == SET_COMPLIANCE) {
            return abi.encodeCall(IRouterAdminOps.mtxSetCompliance, (e, p.target, p.accounts, p.flags, p.until, a));
        }
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(p.target), abi.encodePacked(p.w));
        return bytes.concat(_sel(op), head, abi.encode(head.length + 32), _tail(abi.encode(a)));
    }

    /// `p` signed by `by` (the router's current nonce), sent by the stranger relayer at fee 0.
    function _send(P memory p, bytes32 by) internal {
        MetaTxLib.UAEnvelope memory e = _env(by);
        _call(RELAYER, address(router), _cd(p, e, _auth(by, _digestOn(router, p, e))));
    }

    /// `by`'s signed `mtxAcceptAdmin` of `target` (the router's renamed op), sent by the stranger relayer.
    function _acceptVia(bytes32 by, address target) internal {
        MetaTxLib.UAEnvelope memory e = _env(by);
        bytes32 th = keccak256(bytes(string.concat("UAAcceptAdmin(bytes32 from,address target", TAIL)));
        bytes32 h = keccak256(abi.encode(th, e.from, target, e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee,
            address(0)));
        IUARegistry.UASig memory a = _auth(by, keccak256(abi.encodePacked("\x19\x01", _domain(router), h)));
        _call(RELAYER, address(router), abi.encodeCall(router.mtxAcceptAdmin, (e, target, a)));
    }

    // ------------------------------------------------------------------ the ops' values

    function _w(uint256 a) internal pure returns (uint256[] memory w) {
        w = new uint256[](1);
        w[0] = a;
    }

    function _w(uint256 a, uint256 b) internal pure returns (uint256[] memory w) {
        w = new uint256[](2);
        (w[0], w[1]) = (a, b);
    }

    function _w(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory w) {
        w = new uint256[](3);
        (w[0], w[1], w[2]) = (a, b, c);
    }

    function _u(address a) internal pure returns (uint256) {
        return uint256(uint160(a));
    }

    function _h(address a) internal view returns (uint256) {
        return uint256(a.codehash);
    }

    /// An env the factory takes with every array of two: the router's registry, its `SmartKeyAccount` implementation.
    function _fullEnv() internal view returns (IFactoryToken.Env memory e) {
        e.registry = PREG;
        e.smartKeyAccountImpl = impl;
        e.deps = new address[](2);
        (e.deps[0], e.deps[1]) = (address(0xD1), address(0xD2));
        e.params = new bytes32[](2);
        (e.params[0], e.params[1]) = (keccak256("param 0"), keccak256("param 1"));
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(0x11B1), address(0x11B2));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (keccak256("lib 1"), keccak256("lib 2"));
    }

    /// The release of the approvals: version 2 of each (version 1 is the stack's), env 1.
    function _code(uint8 op) internal pure returns (bytes memory) {
        return op == APPROVE_CLASS ? type(NoteKind).creationCode : type(RouterOpsRelease).creationCode;
    }

    function _args(uint8 op) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0xA0) | bytes1(op));
    }

    /// The key `OpenFactory` stores for the approval `p` (spec §5.6's table).
    function _key(OpenFactory f, P memory p) internal view returns (bytes32) {
        if (p.op == APPROVE_TOKEN) {
            return keccak256(abi.encode(keccak256("scaas.factory.release.token"), f.chainUid(), address(f), p.w[0], p.w[1],
                p.w[2], p.w[3], p.w[4]));
        }
        if (p.op == APPROVE_DEX) {
            return keccak256(abi.encode(keccak256("scaas.factory.release.dex"), f.chainUid(), address(f), p.w[0], p.w[1],
                p.w[2], p.w[3]));
        }
        return keccak256(bytes.concat(abi.encode(keccak256("scaas.factory.release.class"), f.chainUid(), address(f)),
            abi.encode(p.w[0], p.w[1], p.w[2], p.w[3], p.w[4], p.w[5], p.w[6], p.w[7])));
    }

    /// The words of the approval `op`: version 2 of its release (version 1 is the stack's) on env 1, the hashes of its bytes,
    /// this factory's own `chainUid`, address and admin term, `until` a day ahead.
    function _approval(uint8 op, OpenFactory f) internal view returns (uint256[] memory w) {
        uint256[] memory head;
        if (op == APPROVE_TOKEN) head = _w(0, 2, 1);
        else if (op == APPROVE_DEX) head = _w(2, 1);
        else {
            head = new uint256[](6);
            (head[0], head[1], head[2], head[3]) = (CLS, 0, 2, 1);
            head[4] = uint256(bytes32(INoteKind.initialize.selector));
            head[5] = uint256(bytes32(type(INoteKind).interfaceId));
        }
        uint256 n = head.length;
        w = new uint256[](n + 6);
        for (uint256 i; i < n; ++i) w[i] = head[i];
        w[n] = uint256(keccak256(_code(op)));
        w[n + 1] = uint256(keccak256(_args(op)));
        w[n + 2] = uint256(chainUidA);
        w[n + 3] = _u(address(f));
        w[n + 4] = f.adminGeneration();
        w[n + 5] = block.timestamp + 1 days;
    }

    /// The four directory entries with their code hashes (`setChainEntries`' nine words).
    function _entries(ComplianceRegistry cr) internal view returns (uint256[] memory w) {
        w = new uint256[](9);
        w[0] = _u(address(relay));
        w[1] = _h(address(relay));
        w[2] = _h(relay.EXECUTOR());
        w[3] = _u(address(cr));
        w[4] = _h(address(cr));
        w[5] = _u(address(skaf));
        w[6] = _h(address(skaf));
        w[7] = _u(address(zs));
        w[8] = _h(address(zs));
    }

    /// The untouched op `op` on `f` / `cr`, valid there now (the positive control).
    function _base(uint8 op, OpenFactory f, ComplianceRegistry cr) internal view returns (P memory p) {
        (p.op, p.target) = (op, address(f));
        if (op == PUBLISH_ENV) (p.w, p.env) = (_w(0, 9), _fullEnv());
        else if (op == PUBLISH_DEX_ENV) (p.w, p.env) = (_w(9), _fullEnv());
        else if (op == PUBLISH_CLASS_ENV) (p.w, p.env) = (_w(CLS, 0, 9), _fullEnv());
        else if (op >= APPROVE_TOKEN && op <= APPROVE_CLASS) p.w = _approval(op, f);
        else if (op == REVOKE) p.w = _w(uint256(_key(f, _base(APPROVE_TOKEN, f, cr))));
        else if (op == DEPRECATE) (p.w, p.reason) = (_w(0, 1), "a release found bad");
        else if (op == DEPRECATE_DEX) (p.w, p.reason) = (_w(1), "a release found bad");
        else if (op == DEPRECATE_RELEASE) (p.w, p.reason) = (_w(CLS, 0, 1), "a release found bad");
        else if (op == SET_KIND) p.w = _w(1, 1);
        else if (op == SET_CLASS_KIND) p.w = _w(CLS, 0, 1);
        else if (op == SET_KYC) (p.target, p.w) = (address(cr), _w(uint256(PROV), 1));
        else if (op == SET_COMPLIANCE) {
            p.target = address(cr);
            (p.accounts, p.flags, p.until) = (new bytes32[](2), new uint64[](2), new uint64[](2));
            (p.accounts[0], p.accounts[1]) = (bytes32(uint256(0xACC1)), bytes32(uint256(0xACC2)));
            (p.flags[0], p.flags[1]) = (1, 3);
            (p.until[0], p.until[1]) = (MAX, uint64(block.timestamp + 365 days));
        } else p.w = _entries(cr);
    }

    /// The op's effect, read on its target after it ran.
    function _effect(P memory p, OpenFactory f, ComplianceRegistry cr) internal view {
        string memory n = _name(p.op);
        if (p.op == PUBLISH_ENV) assertEq(abi.encode(f.tokenEnvOf(IOpenFactory.TokenKind.NORMAL, 9)), abi.encode(p.env), n);
        else if (p.op == PUBLISH_DEX_ENV) assertEq(abi.encode(f.dexEnvOf(9)), abi.encode(p.env), n);
        else if (p.op == PUBLISH_CLASS_ENV) assertEq(abi.encode(f.classEnvOf(CLS, 0, 9)), abi.encode(p.env), n);
        else if (p.op >= APPROVE_TOKEN && p.op <= APPROVE_CLASS) {
            IOpenFactory.Approval memory a = f.approvalOf(_key(f, p));
            assertEq(uint8(a.state), uint8(IOpenFactory.ApprovalState.LIVE), n);
            assertEq(a.adminGeneration, f.adminGeneration(), n);
            assertEq(a.until, p.w[p.w.length - 1], n);
        } else if (p.op == REVOKE) {
            assertEq(uint8(f.approvalOf(bytes32(p.w[0])).state), uint8(IOpenFactory.ApprovalState.NONE), n);
        } else if (p.op == DEPRECATE) assertTrue(f.isTokenDeprecated(IOpenFactory.TokenKind.NORMAL, 1), n);
        else if (p.op == DEPRECATE_DEX) assertTrue(f.isDexDeprecated(1), n);
        else if (p.op == DEPRECATE_RELEASE) assertTrue(f.classReleaseOf(IOpenFactory.ReleaseId(CLS, 0, 1)).deprecated, n);
        else if (p.op == SET_KIND) assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.WRAPPED), n);
        else if (p.op == SET_CLASS_KIND) assertTrue(f.classKindEnabled(CLS, 0), n);
        else if (p.op == SET_KYC) {
            assertEq(cr.kycProviderId(PROV), 1, n);
            assertTrue(cr.kycProviderEnabled(1), n);
        } else if (p.op == SET_COMPLIANCE) {
            for (uint256 i; i < 2; ++i) {
                (uint64 fl, uint64 u, uint32 id) = cr.complianceOf(p.accounts[i]);
                assertEq(abi.encode(fl, u, id), abi.encode(p.flags[i], p.until[i], uint32(0)), n);
            }
        } else {
            IOpenFactory.Directory memory d = f.directory();
            assertEq(abi.encode(d.relayFeeRouter, d.relayFeeExecutor, d.complianceRegistry, d.smartKeyAccountFactory,
                d.zetherStatements), abi.encode(relay, relay.EXECUTOR(), cr, skaf, zs), n);
        }
    }

    // ------------------------------------------------------------------ every op through the router (§8)

    /// The fifteen ops in order, each signed by `by` and sent by the stranger relayer at fee 0, its effect read; each
    /// approval's release then deployed by another account. `log`: the gas of each op (its own transaction).
    function _everyOp(bytes32 by, bool log) internal {
        (OpenFactory f, ComplianceRegistry cr) = _stack(by);
        string memory who = by == ml ? "mldsa65" : by == msig ? "msig 2-of-3 mldsa65" : by == k1 ? "secp256k1"
            : "native ECDSA";
        for (uint8 op; op < 15; ++op) {
            P memory p = _base(op, f, cr);
            _send(p, by);
            if (log) {
                Vm.Gas memory g = vm.lastCallGas();
                console2.log(string.concat("ROUTERGAS ", _name(op), " (", who, "): regular / state"), g.gasTotalUsed,
                    uint256(int256(g.gasStateUsed)));
            }
            _effect(p, f, cr);
            if (op >= APPROVE_TOKEN && op <= APPROVE_CLASS && op != APPROVE_TOKEN) _deployApproved(f, p);
        }
        assertEq(router.mtxNonce(by, 0), 15 + (by == nid(deployer) ? 0 : 1), "one nonce per op (and the accept)");
        // the token approval was revoked (REVOKE); the deployer is no admin of either (a derived admin)
        if (by != nid(deployer)) {
            vm.prank(deployer);
            vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(deployer)));
            f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED, false);
        }
    }

    /// Another account deploys the release `p` approved; the approval is consumed.
    function _deployApproved(OpenFactory f, P memory p) internal {
        vm.prank(STRANGER);
        if (p.op == APPROVE_DEX) f.deployDexImplementation(2, 1, _code(p.op), _args(p.op));
        else {
            f.deployImplementation(IOpenFactory.ReleaseId(CLS, 0, 2), 1, INoteKind.initialize.selector,
                type(INoteKind).interfaceId, _code(p.op), _args(p.op));
        }
        assertEq(uint8(f.approvalOf(_key(f, p)).state), uint8(IOpenFactory.ApprovalState.CONSUMED));
    }

    function test_everyOp_secp256k1() public {
        _everyOp(k1, false);
    }

    function test_everyOp_mldsa65() public {
        _everyOp(ml, false);
    }

    function test_everyOp_msig() public {
        _everyOp(msig, false);
    }

    /// Spec §5.6 row (3): a derived admin (`webauthn-p256` too) approves each release through the router, sent by a
    /// stranger, and another account deploys it.
    function test_everyOp_webauthn() public {
        _everyOp(wa, false);
    }

    /// The gas of every op through the router (each its own transaction, `isolate`): a native ECDSA admin (the real
    /// `ecrecover`) and an `msig` of three mldsa65 at 2-of-3 (the registry's `msig` path; the PQ math is the stand-in's).
    function test_gas_everyOp() public {
        _everyOp(nid(deployer), true);
        _everyOp(msig, true);
    }

    /// The router's deploy (a CREATE in one call: intrinsic 21,000 and the init code as calldata; a CREATE transaction adds
    /// 32,000), against NET-EVM-11's 60 M: asked `(regular + state) x 1.05`.
    function test_gas_routerDeploy() public {
        RouterCreator c = new RouterCreator();
        bytes memory code = abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(chainUidA, PREG, impl, false));
        address r = c.create(code);
        Vm.Gas memory g = vm.lastCallGas();
        uint256 st = uint256(int256(g.gasStateUsed));
        console2.log("ROUTERGAS deploy: runtime bytes, init bytes", r.code.length, code.length);
        console2.log("ROUTERGAS deploy: regular / state", g.gasTotalUsed, st);
        console2.log("ROUTERGAS deploy: asked (regular + state) x 1.05 (+ 32,000 of a CREATE transaction)",
            (g.gasTotalUsed + st) * 105 / 100 + 32_000);
        assertLt((g.gasTotalUsed + st) * 105 / 100 + 32_000, 60_000_000, "NET-EVM-11: under 60 M");
    }

    // ------------------------------------------------------------------ the field-binding matrix (§8, Fable P1-3)

    function _copy(P memory p) internal pure returns (P memory c) {
        (c.op, c.target) = (p.op, p.target);
        c.w = new uint256[](p.w.length);
        for (uint256 i; i < p.w.length; ++i) c.w[i] = p.w[i];
        c.env = IFactoryToken.Env(p.env.registry, p.env.smartKeyAccountImpl, p.env.hedera, p.env.deps, p.env.params,
            p.env.libs, p.env.libCodeHashes);
        (c.reason, c.accounts, c.flags, c.until) = (p.reason, p.accounts, p.flags, p.until);
    }

    /// A fresh copy of `a` (32-byte words) with change `m`: 0 one element, 1 the length (one more), 2 the order.
    function _mut(bytes32[] memory a, uint256 m) internal pure returns (bytes32[] memory b) {
        b = new bytes32[](a.length + (m == 1 ? 1 : 0));
        for (uint256 i; i < a.length; ++i) b[i] = a[i];
        if (m == 0) b[0] ^= bytes32(uint256(1));
        else if (m == 1) b[a.length] = bytes32(uint256(0xE1));
        else (b[0], b[1]) = (b[1], b[0]);
    }

    /// The same words under another element type (address[], uint64[]: one word per element in memory).
    function _wa(address[] memory a) internal pure returns (bytes32[] memory b) {
        assembly ("memory-safe") { b := a }
    }

    function _aw(bytes32[] memory a) internal pure returns (address[] memory b) {
        assembly ("memory-safe") { b := a }
    }

    function _wu(uint64[] memory a) internal pure returns (bytes32[] memory b) {
        assembly ("memory-safe") { b := a }
    }

    function _uw(bytes32[] memory a) internal pure returns (uint64[] memory b) {
        assembly ("memory-safe") { b := a }
    }

    function _mutReason(string memory s, uint256 m) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        bytes memory c = new bytes(b.length + (m == 1 ? 1 : 0) - (m == 2 ? 1 : 0));
        for (uint256 i; i < c.length && i < b.length; ++i) c[i] = b[i];
        if (m == 0) c[0] ^= 0x01;
        else if (m == 1) c[b.length] = "!";
        return string(c);
    }

    /// Every variant of `p` one signed word off: `target` (`other`, a second factory or registry of the same admin), each
    /// static word (a `bytes4` by its first byte, else its last bit), every `Env` field (the three scalars; per array one
    /// element, the length, the order), the bytes of `reason` (one byte, one more, one fewer), per row array one element,
    /// the length and the order.
    function _variants(P memory p, address other) internal pure returns (P[] memory v) {
        v = new P[](40);
        uint256 n;
        P memory c = _copy(p);
        c.target = other;
        v[n++] = c;
        for (uint256 i; i < p.w.length; ++i) {
            c = _copy(p);
            c.w[i] ^= p.op == APPROVE_CLASS && (i == 4 || i == 5) ? 1 << 255 : 1;
            v[n++] = c;
        }
        if (p.op <= PUBLISH_CLASS_ENV) {
            c = _copy(p);
            c.env.registry = address(uint160(c.env.registry) ^ 1);
            v[n++] = c;
            c = _copy(p);
            c.env.smartKeyAccountImpl = address(uint160(c.env.smartKeyAccountImpl) ^ 1);
            v[n++] = c;
            c = _copy(p);
            c.env.hedera = !c.env.hedera;
            v[n++] = c;
            for (uint256 m; m < 3; ++m) {
                (v[n] = _copy(p)).env.deps = _aw(_mut(_wa(p.env.deps), m));
                (v[n + 1] = _copy(p)).env.params = _mut(p.env.params, m);
                (v[n + 2] = _copy(p)).env.libs = _aw(_mut(_wa(p.env.libs), m));
                (v[n + 3] = _copy(p)).env.libCodeHashes = _mut(p.env.libCodeHashes, m);
                n += 4;
            }
        }
        if (p.op >= DEPRECATE && p.op <= DEPRECATE_RELEASE) {
            for (uint256 m; m < 3; ++m) (v[n++] = _copy(p)).reason = _mutReason(p.reason, m);
        }
        if (p.op == SET_COMPLIANCE) {
            for (uint256 m; m < 3; ++m) {
                (v[n] = _copy(p)).accounts = _mut(p.accounts, m);
                (v[n + 1] = _copy(p)).flags = _uw(_mut(_wu(p.flags), m));
                (v[n + 2] = _copy(p)).until = _uw(_mut(_wu(p.until), m));
                n += 3;
            }
        }
        assembly ("memory-safe") { mstore(v, n) }
    }

    /// Each variant sent with the untouched call's envelope and signature: refused by the router, `UAUnauthorized(ml)`.
    function _refuseAll(P[] memory v, MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) internal returns (uint256) {
        for (uint256 i; i < v.length; ++i) {
            string memory where = string.concat(_name(v[i].op), ": variant ", vm.toString(i));
            vm.prank(RELAYER);
            (bool ok, bytes memory ret) = address(router).call(_cd(v[i], e, a));
            assertFalse(ok, string.concat(where, " passed"));
            assertEq(ret, _unauthorized(ml), where);
        }
        return v.length;
    }

    /// The matrix of `op` (B1-B15): `ml` the admin of a fresh stack, every variant sent with the untouched call's signature
    /// is refused by the router (`UAUnauthorized(ml)`, no nonce spent); then the untouched call passes (the positive
    /// control) and has its effect. Answers the number of variants.
    function _matrix(uint8 op) internal returns (uint256 n) {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        (OpenFactory g, ComplianceRegistry cr2) = _stack(ml);
        if (op == REVOKE) _send(_base(APPROVE_TOKEN, f, cr), ml); // a stored approval to revoke
        P memory p = _base(op, f, cr);
        address other = p.target == address(f) ? address(g) : address(cr2);
        MetaTxLib.UAEnvelope memory e = _env(ml);
        IUARegistry.UASig memory a = _auth(ml, _digestOn(router, p, e));
        n = _refuseAll(_variants(p, other), e, a);
        assertEq(router.mtxNonce(ml, 0), e.nonce, "no nonce spent");
        _call(RELAYER, address(router), _cd(p, e, a)); // the positive control
        assertEq(router.mtxNonce(ml, 0), e.nonce + 1);
        _effect(p, f, cr);
        console2.log(string.concat("BINDING ", _name(op), ": variants refused"), n);
    }

    function test_binding_PublishTokenEnv() public { assertEq(_matrix(PUBLISH_ENV), 18); }
    function test_binding_PublishDexEnv() public { assertEq(_matrix(PUBLISH_DEX_ENV), 17); }
    function test_binding_PublishClassEnv() public { assertEq(_matrix(PUBLISH_CLASS_ENV), 19); }
    function test_binding_ApproveTokenRelease() public { assertEq(_matrix(APPROVE_TOKEN), 10); }
    function test_binding_ApproveDexRelease() public { assertEq(_matrix(APPROVE_DEX), 9); }
    function test_binding_ApproveRelease() public { assertEq(_matrix(APPROVE_CLASS), 13); }
    function test_binding_RevokeApproval() public { assertEq(_matrix(REVOKE), 2); }
    function test_binding_DeprecateToken() public { assertEq(_matrix(DEPRECATE), 6); }
    function test_binding_DeprecateDex() public { assertEq(_matrix(DEPRECATE_DEX), 5); }
    function test_binding_DeprecateRelease() public { assertEq(_matrix(DEPRECATE_RELEASE), 7); }
    function test_binding_SetTokenKindEnabled() public { assertEq(_matrix(SET_KIND), 3); }
    function test_binding_SetClassKindEnabled() public { assertEq(_matrix(SET_CLASS_KIND), 4); }
    function test_binding_SetKycProvider() public { assertEq(_matrix(SET_KYC), 3); }
    function test_binding_SetCompliance() public { assertEq(_matrix(SET_COMPLIANCE), 10); }
    function test_binding_SetChainEntries() public { assertEq(_matrix(SET_ENTRIES), 10); }

    // ------------------------------------------------------------------ replay, nesting, delegation (§5.5, §8)

    /// The same signature on a second factory and a second registry of the same admin (in the matrix: `target`), on the
    /// router of another chain (another `chain_uid`) and on another chain id is refused; the control passes once.
    function test_replay_otherChainRefused() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        GovernanceRouter other = new GovernanceRouter(keccak256("another chain"), PREG, impl, false);
        uint8[2] memory ops = [SET_KIND, SET_KYC];
        for (uint256 i; i < 2; ++i) {
            P memory p = _base(ops[i], f, cr);
            MetaTxLib.UAEnvelope memory e = _env(ml);
            (e.batch, e.nonce) = (5 + i, 0); // a lane fresh on both routers: the signature decides
            bytes memory cd = _cd(p, e, _auth(ml, _digestOn(router, p, e)));
            _refused(RELAYER, address(other), cd, _unauthorized(ml));
            uint256 id = block.chainid;
            vm.chainId(id + 1);
            _refused(RELAYER, address(router), cd, _unauthorized(ml));
            vm.chainId(id);
            _call(RELAYER, address(router), cd); // the control
            _refused(RELAYER, address(router), cd, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        }
    }

    /// A nested router op is refused by the router's guard (`MetaTxBase._enter`): the admin's signed op whose target
    /// re-enters the router with another of the admin's signed ops reverts whole (`Reentrancy`); the inner op alone passes.
    function test_nestedRouterOpRefused() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        RouterReenter t = new RouterReenter(address(router));
        P memory outer = _base(SET_KIND, f, cr);
        outer.target = address(t);
        MetaTxLib.UAEnvelope memory e = _env(ml);
        bytes memory outerCd = _cd(outer, e, _auth(ml, _digestOn(router, outer, e)));
        P memory inner = _base(SET_CLASS_KIND, f, cr);
        MetaTxLib.UAEnvelope memory e2 = _env(ml);
        e2.batch = 1;
        e2.nonce = router.mtxNonce(ml, 1);
        bytes memory innerCd = _cd(inner, e2, _auth(ml, _digestOn(router, inner, e2)));
        t.arm(innerCd);
        _refused(RELAYER, address(router), outerCd, abi.encodeWithSelector(IMetaTx.Reentrancy.selector));
        assertFalse(f.classKindEnabled(CLS, 0));
        assertEq(router.mtxNonce(ml, 0), e.nonce);
        _call(RELAYER, address(router), innerCd); // the control
        assertTrue(f.classKindEnabled(CLS, 0));
    }

    /// CTR-UA-24, D1: a native admin EOA that is an EIP-7702 designator is verified through the router by its own key only:
    /// a delegate whose ERC-1271 says yes to everything changes nothing (another key's signature refused, the own key's
    /// passes); the positive control: that ERC-1271 contract as a contract admin passes with any bytes.
    function test_designatorAdmin_ownKeyOnly() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(nid(deployer));
        YesSigner yes = new YesSigner();
        vm.etch(deployer, abi.encodePacked(hex"ef0100", address(yes)));
        P memory p = _base(SET_KIND, f, cr);
        MetaTxLib.UAEnvelope memory e = _env(nid(deployer));
        bytes32 d = _digestOn(router, p, e);
        (, uint256 otherPk) = makeAddrAndKey("not the admin");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, d);
        IUARegistry.UASig memory junk;
        junk.signature = abi.encodePacked(r, s, v);
        _refused(RELAYER, address(router), _cd(p, e, junk), abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
        _call(RELAYER, address(router), _cd(p, e, _auth(nid(deployer), d))); // its own key
        assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.WRAPPED));
        // the positive control: a contract admin whose ERC-1271 says yes passes with any bytes (the delegate would have)
        vm.etch(deployer, "");
        vm.prank(deployer);
        f.transferAdmin(nid(address(yes)));
        _acceptVia(nid(address(yes)), address(f));
        p = _base(SET_CLASS_KIND, f, cr);
        e = _env(nid(address(yes)));
        _call(RELAYER, address(router), _cd(p, e, junk));
        assertTrue(f.classKindEnabled(CLS, 0));
    }

    /// Another signer through the router is its own subject: `NotAdmin(signer)` on the factory and the registry.
    function test_anotherSignerNotAdmin() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        P memory p = _base(SET_KIND, f, cr);
        MetaTxLib.UAEnvelope memory e = _env(msig);
        _refused(RELAYER, address(router), _cd(p, e, _auth(msig, _digestOn(router, p, e))),
            abi.encodeWithSelector(IAdmin.NotAdmin.selector, msig));
        p = _base(SET_KYC, f, cr);
        e = _env(k1);
        _refused(RELAYER, address(router), _cd(p, e, _auth(k1, _digestOn(router, p, e))),
            abi.encodeWithSelector(IAdmin.NotAdmin.selector, k1));
    }

    /// A derived KYC provider writes its rows through the router's `mtxSetCompliance` under its own id (spec §5.3.1).
    function test_kycProvider_derivedWritesThroughRouter() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        P memory p = _base(SET_KYC, f, cr);
        p.w[0] = uint256(msig);
        _send(p, ml);
        p = _base(SET_COMPLIANCE, f, cr);
        _send(p, msig);
        (,, uint32 id) = cr.complianceOf(p.accounts[0]);
        assertEq(id, cr.kycProviderId(msig));
        assertEq(id, 1);
    }

    /// Spec §8 (FactoryDirectory): a derived admin writes the directory through `mtxSetChainEntries`, in two calls (0 leaves
    /// an entry open); the deployer is no longer the admin.
    function test_directory_derivedAdminWritesThroughRouter() public {
        (OpenFactory f, ComplianceRegistry cr) = _stack(ml);
        P memory p = _base(SET_ENTRIES, f, cr);
        (p.w[7], p.w[8]) = (0, 0); // Zether later
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(deployer)));
        f.setChainEntries(address(relay), bytes32(p.w[1]), bytes32(p.w[2]), address(cr), bytes32(p.w[4]), address(skaf),
            bytes32(p.w[6]), address(0), bytes32(0));
        _send(p, ml);
        assertEq(f.zetherStatements(), address(0));
        p = _base(SET_ENTRIES, f, cr);
        (p.w[0], p.w[1], p.w[2], p.w[3], p.w[4], p.w[5], p.w[6]) = (0, 0, 0, 0, 0, 0, 0);
        _send(p, ml);
        IOpenFactory.Directory memory d = f.directory();
        assertEq(abi.encode(d), abi.encode(IOpenFactory.Directory(PREG, address(router), address(relay), relay.EXECUTOR(),
            address(cr), address(skaf), address(zs))));
    }

    // ------------------------------------------------------------------ the router's table (§5.4)

    /// The router's typed entries go from 38 to 53: every `mtx` entry of its ABI but the ordered cancel and the two generic
    /// refusals.
    function test_routerHas53TypedOps() public view {
        string memory a = vm.readFile(string.concat(vm.envOr("FOUNDRY_OUT", string("out")),
            "/GovernanceRouter.sol/GovernanceRouter.json"));
        string[] memory sigs = vm.parseJsonKeys(a, ".methodIdentifiers");
        uint256 n;
        for (uint256 i; i < sigs.length; ++i) {
            bytes memory s = bytes(sigs[i]);
            if (s[0] != "m" || s[1] != "t" || s[2] != "x") continue;
            if (_starts(s, "mtxCancelNonce(") || _starts(s, "mtxExecute(") || _starts(s, "mtxBatch(")) continue;
            if (_starts(s, "mtxNonce(") || _starts(s, "mtxDigest(") || _starts(s, "mtxSelectors(")) continue; // the views
            ++n;
        }
        assertEq(n, 53);
    }

    function _starts(bytes memory s, string memory p) internal pure returns (bool) {
        bytes memory b = bytes(p);
        if (s.length < b.length) return false;
        for (uint256 i; i < b.length; ++i) if (s[i] != b[i]) return false;
        return true;
    }
}

/// The fifteen rows of `typed_ops.json` (clientkeys' own EIP-712 encoder, T7) run verbatim on a real router at the row's
/// `verifyingContract` (context A): each row's native signature is the router's, so the digests agree across the two
/// encoders; the router then calls the row's `target` (a sink) with the entry's selector.
contract GovRouterAdminRowsTest is UALedgerBase {
    string internal constant K = "gov_router";
    string internal j;
    address internal router;

    function setUp() public override {
        super.setUp();
        j = vm.readFile(TYPED_OPS);
        router = vm.parseJsonAddress(j, domainField("UAPublishTokenEnv", K, "domain.verifyingContract"));
        deployCodeTo("GovernanceRouter.sol:GovernanceRouter", abi.encode(chainUidA, REG_L, address(0), false), router);
    }

    function test_rows_runOnTheRouter() public {
        string[15] memory ops = ["UAPublishTokenEnv", "UAPublishDexEnv", "UAPublishClassEnv", "UAApproveTokenRelease",
            "UAApproveDexRelease", "UAApproveRelease", "UARevokeApproval", "UADeprecateToken", "UADeprecateDex", "UADeprecateRelease",
            "UASetTokenKindEnabled", "UASetClassKindEnabled", "UASetKycProvider", "UASetCompliance", "UASetChainEntries"];
        bytes4[15] memory calls = [OpenFactory.publishTokenEnv.selector, OpenFactory.publishDexEnv.selector,
            OpenFactory.publishClassEnv.selector, OpenFactory.approveTokenRelease.selector, OpenFactory.approveDexRelease.selector,
            OpenFactory.approveRelease.selector, OpenFactory.revokeApproval.selector, OpenFactory.deprecateToken.selector,
            OpenFactory.deprecateDex.selector, OpenFactory.deprecateRelease.selector, OpenFactory.setTokenKindEnabled.selector,
            OpenFactory.setClassKindEnabled.selector, IComplianceRegistry.setKycProvider.selector,
            IComplianceRegistry.setCompliance.selector, OpenFactory.setChainEntries.selector];
        bytes32 me = vm.parseJsonBytes32(j, ".key.ua");
        for (uint256 i; i < 15; ++i) {
            address target = vm.parseJsonAddress(j, msgField(ops[i], "target"));
            vm.etch(target, address(new RouterOpsSink()).code);
            address relayer = vm.parseJsonAddress(j, msgField(ops[i], "relayer"));
            uint256 batch = vm.parseJsonUint(j, msgField(ops[i], "batch"));
            uint256 snap = vm.snapshotState(); // every row signs nonce 0 of its lane
            vm.prank(relayer == address(0) ? address(0xBEEF) : relayer);
            (bool ok, bytes memory ret) = router.call(vm.parseJsonBytes(j, domainField(ops[i], K, "calldata")));
            if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
            assertEq(bytes4(RouterOpsSink(target).last()), calls[i], ops[i]);
            assertEq(GovernanceRouter(router).mtxNonce(me, batch), 1, ops[i]);
            vm.revertToState(snap);
        }
    }
}
