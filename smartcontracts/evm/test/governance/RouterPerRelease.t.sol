// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovRouterFixture} from "./GovRouter.t.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterBase} from "../../src/governance/GovernanceRouterBase.sol";
import {GovernanceBase, GovernanceBaseCore, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {IGovernanceRouter} from "../../src/governance/IGovernanceRouter.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The new kind's class interface (its ERC-165 id).
interface IThing {
    function initialize(bytes32 admin_, bytes32 doer) external;
    function doThing(uint256 id, bytes32 chainUid_) external;
    function doneBy(uint256 id) external view returns (bytes32);
}

/// P3's second router: a child of `GovernanceRouterBase` with one typed entry for the new power. Deployed after the freeze, no
/// frozen code touched; it inherits every admin and holder op. Test-only. **UNAUDITED.**
contract ThingRouter is GovernanceRouterBase {
    bytes32 internal constant UA_DO_THING = keccak256(
        "UADoThing(bytes32 from,address target,uint256 id,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    constructor(bytes32 chainUid_, address registry_, address ska_, bool hedera_)
        GovernanceRouterBase("SCaaS ThingRouter", chainUid_, registry_, ska_, hedera_)
    {}

    function mtxDoThing(
        MetaTxLib.UAEnvelope calldata e,
        address target,
        uint256 id,
        bytes32 chainUid_,
        IUARegistry.UASig calldata auth
    ) external {
        _ua(UA_DO_THING, e, target, IThing.doThing.selector, abi.encode(id, chainUid_), auth);
    }
}

/// A router that answers any subject it is told: the rogue a release could name.
contract RogueRouter {
    bytes32 internal _s;
    bytes32 public immutable chainUid;
    address public immutable registry;

    constructor(bytes32 uid, address registry_) {
        (chainUid, registry) = (uid, registry_);
    }

    function subject() external view returns (bytes32) {
        return _s;
    }

    function act(address target, bytes32 s, bytes calldata data) external {
        _s = s;
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// A generic release (class 6, kind 0) whose governed contract takes its router from its env `deps[0]`, not
/// `ChainEnv.govRouter`: only code in the release. `implArgs` pins the router's code hash; `validateEnv` checks it, the router's
/// chain word and its registry. Application bit 128 is the new power. Test-only. **UNAUDITED.**
contract ThingKind is GovernanceBase, IThing {
    error RouterDepInvalid(address dep);

    uint8 internal constant DO_THING = 128;
    uint256 internal constant BITS = uint256(1) << DO_THING;

    address public immutable FACTORY;
    bytes32 public immutable ROUTER_CODEHASH;
    uint16 internal immutable CLASS;
    uint16 internal immutable KIND;
    uint64 internal immutable VERSION;
    bool internal _initialized;
    mapping(uint256 => bytes32) public doneBy;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs)
        GovernanceBaseCore(address(0))
    {
        (FACTORY, CLASS, KIND, VERSION) = (factory_, id.contractClass, id.kind, id.version);
        ROUTER_CODEHASH = abi.decode(implArgs, (bytes32));
        _initialized = true; // the implementation locked
    }

    // ---- P3: the router is the release's own env dep
    function _govRouter() internal view override returns (address) {
        return ChainEnvCode.dep(0);
    }

    function validateEnv(IFactoryToken.ChainEnv calldata env) external view virtual {
        address r = env.deps.length == 1 ? env.deps[0] : address(0);
        if (
            r.code.length == 0 || r.codehash != ROUTER_CODEHASH || ThingRouter(r).chainUid() != env.chainUid
                || ThingRouter(r).registry() != env.registry
        ) revert RouterDepInvalid(r);
    }

    function initialize(bytes32 admin_, bytes32 doer) external {
        require(msg.sender == FACTORY && !_initialized, "init");
        ChainEnvCode.requirePresent();
        _initialized = true;
        GovernanceLib.Roles memory none;
        GovernanceLib.init(BITS, 0, admin_, 0, address(0), none, BITS, BITS, 0, address(0));
        if (doer != 0) GovernanceLib.initHolder(DO_THING, doer, BITS, 0, address(0));
    }

    function doThing(uint256 id, bytes32 chainUid_) external governed {
        bytes32 c = _holderOnChain(DO_THING, chainUid_);
        GovernanceUse.use(DO_THING, c, 0);
        doneBy[id] = c;
    }

    function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory) {
        return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION, _initialized);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == 0x01ffc9a7 || i == type(IThing).interfaceId;
    }

    function modules() external pure returns (address[] memory) {}

    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }

    function _guardIn() internal pure override returns (bool) {
        return false;
    }

    function _guardOut(bool) internal pure override {}

    function _caller() internal view override returns (address) {
        return msg.sender;
    }

    function _govChainUid() internal view override returns (bytes32) {
        return ChainEnvCode.chainUid();
    }

    function _validBits() internal pure override returns (uint256) {
        return BITS;
    }

    function _roleBits() internal pure override returns (uint256) {
        return BITS;
    }

    function _contractOnlyBits() internal pure override returns (uint256) {
        return 0;
    }

    function _scalarBits() internal pure override returns (uint256) {
        return 0;
    }

    function _scopeBits() internal pure override returns (uint256) {
        return 0;
    }
}

function _uidOf(bytes memory implArgs) pure returns (bytes32 u) {
    (u,) = abi.decode(implArgs, (bytes32, address));
}

function _regOf(bytes memory implArgs) pure returns (address r) {
    (, r) = abi.decode(implArgs, (bytes32, address));
}

/// Option R-b: a router **version** as a row of today's generic catalogue (CTR-TOK-28), class 7: `deployImplementation` CREATE2s
/// it under the registrar's approval (init-code hash and `implArgs` hash bound), `_checkRelease` reads the views below. The
/// router is used at its catalogue address, never cloned (its kind stays disabled). Test-only. **UNAUDITED.**
contract CatalogueRouter is ThingRouter {
    address public immutable FACTORY;
    uint16 internal immutable CLASS;
    uint16 internal immutable KIND;
    uint64 internal immutable VERSION;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs)
        ThingRouter(_uidOf(implArgs), _regOf(implArgs), address(0), false)
    {
        (FACTORY, CLASS, KIND, VERSION) = (factory_, id.contractClass, id.kind, id.version);
    }

    function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory) {
        return IOpenFactory.FactoryInfo(FACTORY, this.chainUid(), CLASS, KIND, VERSION, true);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == 0x01ffc9a7 || i == type(IGovernanceRouter).interfaceId;
    }

    function validateEnv(IFactoryToken.ChainEnv calldata env) external view {
        require(env.registry == registry() && env.chainUid == this.chainUid(), "router env");
    }

    function modules() external pure returns (address[] memory) {}
}

/// The release of option R-b: its router is the catalogue row `(7, 0, ROUTER_VERSION)`, read from the factory at release
/// deployment (`validateEnv`); the pin is the catalogue address, not a code hash. Test-only. **UNAUDITED.**
contract CatalogueThingKind is ThingKind {
    uint16 internal constant ROUTER_CLASS = 7;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs)
        ThingKind(id, factory_, implArgs)
    {}

    function validateEnv(IFactoryToken.ChainEnv calldata env) external view override {
        address r = env.deps.length == 1 ? env.deps[0] : address(0);
        IOpenFactory.ClassRelease memory c = IOpenFactory(FACTORY)
            .classReleaseOf(IOpenFactory.ReleaseId(ROUTER_CLASS, 0, uint64(uint256(ROUTER_CODEHASH))));
        if (r == address(0) || c.implementation != r || c.deprecated) revert RouterDepInvalid(r);
    }
}

/// Pre-freeze question P3 (research note 2026-11-24-nft-multi-token §7, TODO N2): a generic release names its own router in its
/// env `deps` and uses it instead of `ChainEnv.govRouter`, with no change to deployed or frozen code. **UNAUDITED.**
contract RouterPerReleaseTest is GovRouterFixture {
    address constant REGISTRAR = address(0x5E6);
    uint16 constant CLS = 6;
    uint8 constant DO_THING = 128;
    string constant DO_THING_TYPE =
        "UADoThing(bytes32 from,address target,uint256 id,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    OpenFactory f;
    ThingRouter r2;
    ThingKind inst;
    NormalToken tok; // an existing kind on the chain's router

    function setUp() public override {
        super.setUp();
        f = EnvKit.factory(REGISTRAR, chainUidA, 0, address(router));
        r2 = new ThingRouter(chainUidA, PREG, _fixtureSka(), false);
        _release(1, 1, address(r2), address(r2).codehash);
        vm.prank(REGISTRAR);
        f.setClassKindEnabled(CLS, 0, true, EnvKit.uidOf(address(f)));
        inst = ThingKind(
            f.createInstance(IOpenFactory.ReleaseId(CLS, 0, 1), "t", abi.encodeCall(IThing.initialize, (eoa, pq)))
        );
        tok = _normal(eoa, eoa, 0);
    }

    /// Env `envVersion` with `deps = [dep]`, then release `version` on it pinning `pin`.
    function _release(uint16 envVersion, uint64 version, address dep, bytes32 pin) internal {
        IFactoryToken.Env memory env = plainEnv(address(f), address(0), chainUidA, PREG, false);
        env.deps = new address[](1);
        env.deps[0] = dep;
        vm.startPrank(REGISTRAR);
        f.publishClassEnv(CLS, 0, envVersion, EnvKit.uidOf(address(f)), env);
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, version),
            envVersion,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(ThingKind).creationCode,
            abi.encode(pin),
            EnvKit.uidOf(address(f))
        );
        vm.stopPrank();
    }

    function _g(address r) internal pure returns (GovernanceRouter) {
        return GovernanceRouter(r); // the base's ops and views have the same ABI on every child
    }

    function _doThingDigest(MetaTxLib.UAEnvelope memory e, address target, uint256 id, bytes32 word)
        internal
        view
        returns (bytes32)
    {
        bytes32 h = keccak256(
            bytes.concat(
                abi.encode(keccak256(bytes(DO_THING_TYPE)), e.from, target, id, word),
                abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domain(_g(address(r2))), h));
    }

    function _doThing(bytes32 from, uint256 id) internal {
        MetaTxLib.UAEnvelope memory e = _envelope(_g(address(r2)), from, 0);
        bytes32 word = EnvKit.codeUidOf(address(inst));
        r2.mtxDoThing(e, address(inst), id, word, _auth(from, _doThingDigest(e, address(inst), id, word)));
    }

    function _grantOn(GovernanceRouter r, address target, bytes32 account) internal view returns (bytes memory) {
        return _grantBit(r, target, target == address(tok) ? MINT : DO_THING, account);
    }

    function _grantBit(GovernanceRouter r, address target, uint8 bit, bytes32 account)
        internal
        view
        returns (bytes memory)
    {
        bytes memory a = abi.encode(bit, account, EnvKit.codeUidOf(target));
        return _signed(r, GRANT_ROLE, eoa, 0, target, a, a);
    }

    // ---- 1, 2: the env dep is accepted; the instance reads its router from it

    function test_p3_instanceReadsItsRouterFromDeps() public view {
        IFactoryToken.ChainEnv memory e = inst.chainEnv();
        assertEq(e.govRouter, address(router), "ChainEnv.govRouter: the chain's router, unchanged");
        assertEq(e.deps.length, 1);
        assertEq(e.deps[0], address(r2), "the release's own router in deps");
        assertEq(inst.GOV_ROUTER(), address(r2), "the governed contract's router: deps[0]");
        assertEq(tok.GOV_ROUTER(), address(router), "an existing kind: the chain's router");
        assertEq(f.govRouter(), address(router));
    }

    // ---- 3: a PQ / msig role holder through the second router; a non-holder refused; the inherited admin ops

    function test_p3_pqHolderActs_nonHolderRefused() public {
        _doThing(pq, 7);
        assertEq(inst.doneBy(7), pq, "the PQ holder acted through its router");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DO_THING, msig));
        this.doThingExt(msig, 8);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DO_THING, eoa));
        this.doThingExt(eoa, 8); // the admin holds no power bit
        // a direct call: the caller's own id, no holder
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DO_THING, nid(address(this))));
        inst.doThing(8, EnvKit.codeUidOf(address(inst)));
    }

    function doThingExt(bytes32 from, uint256 id) external {
        _doThing(from, id);
    }

    function test_p3_inheritedAdminOp_grantsMsig() public {
        _runOn(_g(address(r2)), _grantOn(_g(address(r2)), address(inst), msig));
        assertTrue(inst.hasRole(DO_THING, msig));
        _doThing(msig, 9);
        assertEq(inst.doneBy(9), msig, "the msig holder acted through its router");
    }

    // ---- 4: the chain's router and the existing kind are unaffected; each router binds only its own contracts

    function test_p3_mainRouterHasNoPowerOnInstance_r2NoneOnExistingKind() public {
        // the chain's router on the new instance: its subject is not asked, the caller is the router itself
        bytes memory main = _grantOn(router, address(inst), msig);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(address(router))));
        _run(main);
        // the second router on the existing kind: likewise
        bytes memory cd = _grantOn(_g(address(r2)), address(tok), next);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(address(r2))));
        _runOn(_g(address(r2)), cd);
        // the control: the chain's router still governs the existing kind
        _run(_grantOn(router, address(tok), next));
        assertTrue(tok.hasRole(MINT, next));
    }

    function test_p3_existingKindMint_unchanged() public {
        _do(OP_MINT, eoa, address(tok), abi.encode(BOB, uint256(5)));
        assertEq(tok.balanceOf(BOB), 5, "the chain's router mints on the existing kind");
    }

    // ---- replay across the two routers

    function test_p3_replayAcrossRouters_refused() public {
        bytes memory forMain = _grantOn(router, address(inst), msig);
        bytes memory forR2 = _grantOn(_g(address(r2)), address(inst), msig);
        assertEq(router.mtxNonce(eoa, 0), r2.mtxNonce(eoa, 0), "same lane, same nonce: only the domain differs");
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _runOn(_g(address(r2)), forMain); // signed for the chain's router, sent to the second
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(forR2); // signed for the second, sent to the chain's router
        // a derived signer: the digest names the router, the registry refuses the other one's
        MetaTxLib.UAEnvelope memory e = _envelope(_g(address(r2)), pq, 0);
        bytes32 word = EnvKit.codeUidOf(address(inst));
        bytes32 dMain = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domain(router),
                keccak256(
                    bytes.concat(
                        abi.encode(keccak256(bytes(DO_THING_TYPE)), pq, address(inst), uint256(1), word),
                        abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
                    )
                )
            )
        );
        IUARegistry.UASig memory a = _auth(pq, dMain);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        r2.mtxDoThing(e, address(inst), 1, word, a);
        // the controls: each as signed, on its own router
        _runOn(_g(address(r2)), forR2);
        assertTrue(inst.hasRole(DO_THING, msig));
        assertEq(router.mtxNonce(eoa, 0), 0, "the chain's router's lane untouched");
    }

    // ---- security: the pin, and a rogue router's reach

    /// The factory takes any address in `deps` (it checks only the count); the release's `validateEnv` is the pin.
    function test_p3_releasePinsItsRouter_rogueDepRefused() public {
        RogueRouter rogue = new RogueRouter(chainUidA, PREG);
        IFactoryToken.Env memory env = plainEnv(address(f), address(0), chainUidA, PREG, false);
        env.deps = new address[](1);
        env.deps[0] = address(rogue);
        vm.startPrank(REGISTRAR);
        f.publishClassEnv(CLS, 0, 2, EnvKit.uidOf(address(f)), env); // accepted by the factory
        vm.expectRevert(abi.encodeWithSelector(ThingKind.RouterDepInvalid.selector, address(rogue)));
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 2),
            2,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(ThingKind).creationCode,
            abi.encode(address(r2).codehash),
            EnvKit.uidOf(address(f))
        );
        // another ThingRouter on another chain word: same code, other immutables, other code hash
        ThingRouter other = new ThingRouter(bytes32(uint256(1)), PREG, _fixtureSka(), false);
        env.deps[0] = address(other);
        f.publishClassEnv(CLS, 0, 3, EnvKit.uidOf(address(f)), env);
        vm.expectRevert(abi.encodeWithSelector(ThingKind.RouterDepInvalid.selector, address(other)));
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 2),
            3,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(ThingKind).creationCode,
            abi.encode(address(r2).codehash),
            EnvKit.uidOf(address(f))
        );
        vm.stopPrank();
    }

    /// A release whose creator pins a rogue router: that release's instances trust it (its choice), nothing else does.
    function test_p3_rogueRouter_bindsOnlyItsRelease() public {
        RogueRouter rogue = new RogueRouter(chainUidA, PREG);
        _release(2, 2, address(rogue), address(rogue).codehash);
        ThingKind bad = ThingKind(
            f.createInstance(IOpenFactory.ReleaseId(CLS, 0, 2), "b", abi.encodeCall(IThing.initialize, (eoa, pq)))
        );
        bytes32 bw = EnvKit.codeUidOf(address(bad));
        rogue.act(address(bad), pq, abi.encodeCall(IThing.doThing, (1, bw)));
        assertEq(bad.doneBy(1), pq, "the rogue speaks for anyone on its own release");
        // on the honest release, the existing kind and the chain's router's subject: the rogue is only its own address
        bytes32 w = EnvKit.codeUidOf(address(inst));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, DO_THING, nid(address(rogue))));
        rogue.act(address(inst), pq, abi.encodeCall(IThing.doThing, (1, w)));
        bytes32 tw = EnvKit.codeUidOf(address(tok));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(address(rogue))));
        rogue.act(address(tok), eoa, abi.encodeCall(IGovernance.grantRole, (MINT, next, tw)));
    }
    // ---- option R-b: a router version registered in today's catalogue, picked by a release; no factory change

    function test_rb_routerVersionInCatalogue_pickedByRelease() public {
        bytes32 u = EnvKit.uidOf(address(f));
        IFactoryToken.Env memory renv = plainEnv(address(f), address(0), chainUidA, PREG, false);
        vm.startPrank(REGISTRAR);
        f.publishClassEnv(7, 0, 1, u, renv);
        address cr = f.deployImplementation(
            IOpenFactory.ReleaseId(7, 0, 1),
            1,
            ThingRouter.mtxDoThing.selector, // a non-zero initializer the catalogue requires; the kind is never enabled
            type(IGovernanceRouter).interfaceId,
            type(CatalogueRouter).creationCode,
            abi.encode(chainUidA, PREG),
            u
        );
        IFactoryToken.Env memory env = plainEnv(address(f), address(0), chainUidA, PREG, false);
        env.deps = new address[](1);
        env.deps[0] = cr;
        f.publishClassEnv(CLS, 0, 4, u, env);
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 4),
            4,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(CatalogueThingKind).creationCode,
            abi.encode(bytes32(uint256(1))), // router version 1
            u
        );
        // the same router code at an address outside the catalogue: refused (the pin is the catalogue row)
        address twin =
            address(new CatalogueRouter(IOpenFactory.ReleaseId(7, 0, 1), address(f), abi.encode(chainUidA, PREG)));
        // `SaltedEIP712` caches `address(this)` and the separator as immutables: a router's code hash names its address too
        assertNotEq(twin.codehash, cr.codehash, "a code-hash pin of a router is a pin of one deployment");
        env.deps[0] = twin;
        f.publishClassEnv(CLS, 0, 5, u, env);
        vm.expectRevert(abi.encodeWithSelector(ThingKind.RouterDepInvalid.selector, twin));
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 5),
            5,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(CatalogueThingKind).creationCode,
            abi.encode(bytes32(uint256(1))),
            u
        );
        vm.stopPrank();
        ThingKind c = ThingKind(
            f.createInstance(IOpenFactory.ReleaseId(CLS, 0, 4), "c", abi.encodeCall(IThing.initialize, (eoa, pq)))
        );
        assertEq(c.GOV_ROUTER(), cr);
        // a PQ holder through the catalogued router
        MetaTxLib.UAEnvelope memory e = _envelope(_g(cr), pq, 0);
        bytes32 word = EnvKit.codeUidOf(address(c));
        bytes32 h = keccak256(
            bytes.concat(
                abi.encode(keccak256(bytes(DO_THING_TYPE)), pq, address(c), uint256(3), word),
                abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
            )
        );
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domain(_g(cr)), h));
        ThingRouter(cr).mtxDoThing(e, address(c), 3, word, _auth(pq, d));
        assertEq(c.doneBy(3), pq);
    }
}

/// The owner's addition (2026-11-24): does the chain's router follow the multi-generation registry line? The router is bound to
/// one generation (`UAMetaTxBaseCore` `registry_`, immutable); the line walks **back** only (`predecessor`), so generation N
/// cannot find a record of N + 1. **UNAUDITED.**
contract RouterRegistryLineTest is GovRouterFixture {
    address constant GEN2 = address(0x5cA0000000000000000000000000000000000008);
    uint16 constant ML65 = UAKinds.MLDSA65; // a kind only generation 2 has
    UARegistry gen2;
    bytes pq65Key;
    bytes32 pq65; // held in generation 2, kind only there
    bytes msig2Data;
    bytes32 msig2; // an msig (re-enabled in every generation) held in generation 2, members in generation 1
    GovernanceRouter router2; // a router bound to generation 2

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(ML65, address(mock), CAP, false, 0);
        gen2 = _deploy(GEN2, chainUidA, PREG, false, BUDGET, address(0), true, k);
        assertEq(gen2.predecessor(), PREG);
        pq65Key = new bytes(1952);
        for (uint256 i; i < 1952; ++i) {
            pq65Key[i] = bytes1(uint8(i * 7 + 3));
        }
        pq65 = _register(gen2, ML65, pq65Key);
        Member[] memory m = new Member[](2);
        for (uint256 i; i < 2; ++i) {
            m[i] = Member(ML44, UAKinds.uaOf(ML44, mkeys[i]), 1);
        }
        msig2Data = _msigKey(2, m); // members 0 and 1, t=2: another id than generation 1's msig
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msig2Data);
        msig2 = UACall.register(
            gen2,
            UAKinds.MSIG,
            msig2Data,
            _none(),
            abi.encode(_m2Sigs(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG))),
            ""
        );
        for (uint256 i; i < 2; ++i) {
            gen2.acceptMembership(msig2, _acceptKeySig(msig2Data, ML44, mkeys[i]));
        }
        router2 = new GovernanceRouter(chainUidA, GEN2, _fixtureSka(), false);
    }

    function _auth(bytes32 id, bytes32 digest) internal view override returns (IUARegistry.UASig memory a) {
        if (id == pq65) a.signature = _sig(pq65Key, UAKinds.uaMessage(ML65, UAKinds.PURPOSE_METATX, digest));
        else if (id == msig2) a.members = _m2Sigs(msig2, UAKinds.PURPOSE_METATX, digest);
        else a = super._auth(id, digest);
    }

    /// Both slots of `msig2Data`, in index order, over `(purpose, digest)` for `ua`.
    function _m2Sigs(bytes32 ua, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        s = new IUARegistry.MemberSig[](2);
        for (uint256 j; j < 2; ++j) {
            uint16 idx = uint16(_indexOf(msig2Data, UAKinds.uaOf(ML44, mkeys[j])));
            s[idx] = IUARegistry.MemberSig(
                idx, new IUARegistry.InnerSig[](0), _sig(mkeys[j], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md))
            );
        }
    }

    function _mintBy(GovernanceRouter r, NormalToken t, bytes32 from) internal {
        bytes memory a = abi.encode(BOB, uint256(5));
        _runOn(r, _signed(r, OP_MINT, from, 0, address(t), a, a));
    }

    function _tokenOn(address r, bytes32 minter) internal returns (NormalToken t) {
        t = _normal(eoa, minter, 0);
        if (r != address(router)) {
            IFactoryToken.ChainEnv memory e = EnvKit.env(chainUidA, PREG, _fixtureSka(), false, r);
            t = NormalToken(EnvKit.clone(normalImpl, e));
            IFactoryToken.TokenConfig memory c;
            (c.name, c.symbol, c.decimals, c.features, c.admin) = ("G", "G", 6, 1 | (uint256(1) << MINT), eoa);
            c.roles.minter = minter;
            t.initialize(nid(address(this)), 1, abi.encode(c));
        }
    }

    function test_line_gen2SeesGen1_gen1DoesNotSeeGen2() public view {
        (address h,,) = gen2.holderOf(pq);
        assertEq(h, PREG, "a later generation walks back to the holder");
        (h,,) = preg.holderOf(pq65);
        assertEq(h, address(0), "an earlier generation has no successor: a later record is unknown");
        assertEq(router.registry(), PREG, "the chain's router: generation 1, immutable");
    }

    /// Q2: a kind only generation 2 has. Refused by the chain's router (generation 1): `UAUnauthorized`, not `UAConfig`.
    function test_line_gen2OnlyKind_chainRouterRefuses() public {
        NormalToken t = _tokenOn(address(router), pq65);
        bytes memory a = abi.encode(BOB, uint256(5));
        bytes memory cd = _signed(router, OP_MINT, pq65, 0, address(t), a, a);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq65));
        _run(cd);
        // the control: a generation-1 PQ holder on the same router
        _mintBy(router, _tokenOn(address(router), pq), pq);
    }

    /// Q1: a kind generation 1 also has (`msig`, its members generation-1 keys), the record held in generation 2. Refused alike:
    /// generation 1 forwards nothing forward, neither the views nor the signature check.
    function test_line_gen2Record_gen1Kind_chainRouterRefuses() public {
        NormalToken t = _tokenOn(address(router), msig2);
        bytes memory a = abi.encode(BOB, uint256(5));
        bytes memory cd = _signed(router, OP_MINT, msig2, 0, address(t), a, a);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, msig2));
        _run(cd);
        _mintBy(router, _tokenOn(address(router), msig), msig); // the control: generation 1's msig
    }

    /// The direction that works: a router bound to generation 2 authenticates both generations' holders (the walk back hands the
    /// signature check to the holder, CTR-UA-60). A token reaches it only if its `ChainEnv.govRouter` names it.
    function test_line_routerOnGen2_servesBoth() public {
        _mintBy(router2, _tokenOn(address(router2), pq65), pq65);
        _mintBy(router2, _tokenOn(address(router2), msig2), msig2);
        _mintBy(router2, _tokenOn(address(router2), pq), pq);
        _mintBy(router2, _tokenOn(address(router2), msig), msig);
        // a token on the chain's router does not listen to it
        NormalToken t = _tokenOn(address(router), pq65);
        bytes memory a = abi.encode(BOB, uint256(5));
        bytes memory cd = _signed(router2, OP_MINT, pq65, 0, address(t), a, a);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, nid(address(router2))));
        _runOn(router2, cd);
    }
}
