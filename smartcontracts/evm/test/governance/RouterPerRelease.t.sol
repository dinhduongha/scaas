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
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {IGovernanceRouter} from "../../src/governance/IGovernanceRouter.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
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
        GovernanceRouterBase("SCaaS ThingRouter", chainUid_, registry_, ska_, hedera_, address(0))
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
    function _govRouter() internal view virtual override returns (address) {
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
        _routerNaming(EnvKit.nextCreate(2)); // G-3: the router names the factory built next
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

/// The owner's addition (2026-11-24): the chain's router and the multi-generation registry line. The line walks **back** only
/// (`predecessor`), so generation N cannot find a record of N + 1. G1 (CTR-GOV-33, owner 2026-11-24): the router checks a derived
/// signer on the registry its target's env names when the factory made the target, so a token on a generation-2 env is governed
/// on generation 2 by the one chain router. Here the fixture plays the factory (`infoOf`), as it is the clones' `FACTORY`.
/// **UNAUDITED.**
abstract contract RegistryLineFixture is GovRouterFixture {
    address constant GEN2 = address(0x5cA0000000000000000000000000000000000008);
    uint16 constant ML65 = UAKinds.MLDSA65; // a kind only generation 2 has
    UARegistry gen2;
    bytes pq65Key;
    bytes32 pq65; // held in generation 2, kind only there
    bytes msig2Data;
    bytes32 msig2; // an msig (re-enabled in every generation) held in generation 2, members in generation 1
    GovernanceRouter router2; // a router bound to generation 2
    mapping(address => bool) internal made; // the fixture's index, as `OpenFactory.infoOf`

    function setUp() public virtual override {
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
        router2 = new GovernanceRouter(chainUidA, GEN2, _fixtureSka(), false, address(this));
        // the chain's router under G1: generation 1, the fixture as its factory
        router = new GovernanceRouter(chainUidA, PREG, _fixtureSka(), false, address(this));
    }

    function infoOf(address c) external view returns (IOpenFactory.Created memory x) {
        if (made[c]) (x.addr, x.contractClass) = (c, 1);
    }

    function _auth(bytes32 id, bytes32 digest) internal view virtual override returns (IUARegistry.UASig memory a) {
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

    /// `op` by `from` on `target` through `r`, at the nonce `r` checks for that target (`mtxNonceFor`).
    function _sFor(GovernanceRouter r, uint256 op, bytes32 from, address target, bytes memory args)
        internal
        view
        returns (bytes memory)
    {
        MetaTxLib.UAEnvelope memory e = _envelope(r, from, 0);
        e.nonce = r.mtxNonceFor(target, from, 0);
        return _signedAt(r, op, e, target, args, args);
    }

    function _mintBy(GovernanceRouter r, address t, bytes32 from) internal {
        uint256 b = NormalToken(t).balanceOf(BOB);
        _runOn(r, _sFor(r, OP_MINT, from, t, abi.encode(BOB, uint256(5))));
        assertEq(NormalToken(t).balanceOf(BOB), b + 5, "minted");
    }

    function _mintRefused(GovernanceRouter r, address t, bytes32 from) internal {
        bytes memory cd = _sFor(r, OP_MINT, from, t, abi.encode(BOB, uint256(5)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, from));
        _runOn(r, cd);
    }

    /// A NormalToken clone on env `(reg, r)`, minter `minter`; `listed`: in the fixture's index.
    function _token(address reg, address r, bytes32 minter, bool listed) internal returns (NormalToken t) {
        if (normalImpl == address(0)) _normal(eoa, eoa, 0);
        t = NormalToken(EnvKit.clone(normalImpl, EnvKit.env(chainUidA, reg, _fixtureSka(), false, r)));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("G", "G", 6, 1 | (uint256(1) << MINT), eoa);
        c.roles.minter = minter;
        t.initialize(nid(address(this)), 1, abi.encode(c));
        made[address(t)] = listed;
    }
}

/// The four registry-line tests at G1's expectations: red on the router before G1 (its one registry), green with it.
contract RouterRegistryLineTest is RegistryLineFixture {
    function test_line_gen2SeesGen1_gen1DoesNotSeeGen2() public {
        (address h,,) = gen2.holderOf(pq);
        assertEq(h, PREG, "a later generation walks back to the holder");
        (h,,) = preg.holderOf(pq65);
        assertEq(h, address(0), "an earlier generation has no successor: a later record is unknown");
        assertEq(router.registry(), PREG, "the chain's router: generation 1, immutable");
        assertEq(router.factory(), address(this));
        assertEq(router.registryFor(address(_token(GEN2, address(router), pq65, true))), GEN2, "a gen-2 env: gen 2");
        assertEq(router.registryFor(address(_token(PREG, address(router), pq65, true))), PREG, "a gen-1 env: gen 1");
    }

    /// Q2: a kind only generation 2 has. On a generation-2 env token the chain's router serves it; on a generation-1 env token it
    /// is refused, `UAUnauthorized`, as on that token's own path (CTR-UA-27 parity).
    function test_line_gen2OnlyKind_gen2EnvServed_gen1EnvRefused() public {
        _mintBy(router, address(_token(GEN2, address(router), pq65, true)), pq65);
        _mintRefused(router, address(_token(PREG, address(router), pq65, true)), pq65);
        _mintBy(router, address(_token(PREG, address(router), pq, true)), pq); // the control: a gen-1 holder, gen-1 env
    }

    /// Q1: a kind generation 1 also has (`msig`, its members generation-1 keys), the record held in generation 2: likewise.
    function test_line_gen2Record_gen1Kind_gen2EnvServed_gen1EnvRefused() public {
        _mintBy(router, address(_token(GEN2, address(router), msig2, true)), msig2);
        _mintRefused(router, address(_token(PREG, address(router), msig2, true)), msig2);
        _mintBy(router, address(_token(PREG, address(router), msig, true)), msig); // the control: generation 1's msig
    }

    /// The chain's router serves both generations' holders on a generation-2 env (the walk back hands the check to the holder,
    /// CTR-UA-60), as a router bound to generation 2 does; a token on the chain's router still does not listen to that one.
    function test_line_chainRouter_gen2Env_servesBoth() public {
        bytes32[4] memory who = [pq65, msig2, pq, msig];
        for (uint256 i; i < 4; ++i) {
            _mintBy(router, address(_token(GEN2, address(router), who[i], true)), who[i]);
            _mintBy(router2, address(_token(GEN2, address(router2), who[i], true)), who[i]);
        }
        NormalToken t = _token(GEN2, address(router), pq65, true);
        bytes memory cd = _sFor(router2, OP_MINT, pq65, address(t), abi.encode(BOB, uint256(5)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, nid(address(router2))));
        _runOn(router2, cd);
    }
}

/// A registry that passes any id: the bad env registry an admin could publish (it answers the env checks: the chain word and a
/// line reaching the router's registry).
contract YesRegistry {
    bytes32 public immutable chainUid;

    constructor(bytes32 uid) {
        chainUid = uid;
    }

    function lineReaches(address) external pure returns (uint256) {
        return 1;
    }

    function requireAuthorized(bytes32, bytes32, bytes32, IUARegistry.UASig calldata) external pure {}
}

/// A generic release (class 6) governed by the chain's router (`ChainEnv.govRouter`), as today's kinds are. Test-only.
contract ChainThingKind is ThingKind {
    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs)
        ThingKind(id, factory_, implArgs)
    {}

    function _govRouter() internal view override returns (address) {
        return ChainEnvCode.govRouter();
    }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure override {}
}

/// G1 on the real router and a real `OpenFactory`, per factory-made form (a token, the DEX, a generic catalogue class), a chain
/// contract the factory did not make (the factory itself), a clone the factory did not make, the nonce keying by registry
/// (CTR-GOV-33). Deploy order: the factory, the router naming it, `configureChain`. **UNAUDITED.**
contract RouterG1Test is RegistryLineFixture {
    address constant REGISTRAR = address(0x5E6);
    uint16 constant CLS = 6;
    uint8 constant DO_THING = 128;
    OpenFactory f;
    YesRegistry yes;
    bytes32 u;

    function setUp() public override {
        super.setUp();
        f = new OpenFactory(nid(REGISTRAR));
        router = new GovernanceRouter(chainUidA, PREG, _fixtureSka(), false, address(f));
        EnvKit.configure(f, chainUidA, 0, address(router));
        u = EnvKit.uidOf(address(f));
        yes = new YesRegistry(chainUidA);
        // NORMAL releases: 1 on a generation-2 env, 2 on generation 1, 3 on the bad registry
        address[3] memory regs = [GEN2, PREG, address(yes)];
        for (uint256 i; i < 3; ++i) {
            Catalogue.plain(
                f,
                IOpenFactory.TokenKind.NORMAL,
                uint64(i + 1),
                type(NormalToken).creationCode,
                regs[i],
                _fixtureSka(),
                false
            );
        }
    }

    function _version(address reg) internal view returns (uint64) {
        return reg == GEN2 ? 1 : reg == PREG ? 2 : 3;
    }

    function _ftoken(address reg, bytes32 minter, bytes32 salt) internal returns (address) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("G", "G", 6, 1 | (uint256(1) << MINT), eoa);
        c.roles.minter = minter;
        return f.createToken(IOpenFactory.TokenKind.NORMAL, _version(reg), abi.encode(c), salt);
    }

    function _fdex(address reg, bytes32 admin_, bytes32 salt) internal returns (SCaaSDex d) {
        uint64 v = reg == GEN2 ? 1 : 2;
        if (f.latestDexVersion() < v) Catalogue.dex(f, v, type(SCaaSDex).creationCode, _fixtureSka(), reg);
        d = SCaaSDex(
            f.createDex(v, abi.encode(ISCaaSDex.DexConfig(admin_, 0, TREASURY, false, 0, address(0), 0, 0)), salt)
        );
    }

    function _fthing(address reg, bytes32 admin_, bytes32 salt) internal returns (ThingKind t) {
        uint64 v = reg == GEN2 ? 1 : 2;
        if (f.latestClassVersion(CLS, 0) < v) {
            vm.startPrank(REGISTRAR);
            f.publishClassEnv(CLS, 0, uint16(v), u, plainEnv(address(f), _fixtureSka(), chainUidA, reg, false));
            f.deployImplementation(
                IOpenFactory.ReleaseId(CLS, 0, v),
                uint16(v),
                IThing.initialize.selector,
                type(IThing).interfaceId,
                type(ChainThingKind).creationCode,
                abi.encode(bytes32(0)),
                u
            );
            f.setClassKindEnabled(CLS, 0, true, u);
            vm.stopPrank();
        }
        t = ThingKind(
            f.createInstance(IOpenFactory.ReleaseId(CLS, 0, v), salt, abi.encodeCall(IThing.initialize, (admin_, 0)))
        );
    }

    function _refused(uint256 op, bytes32 from, address target, bytes memory args) internal {
        bytes memory cd = _sFor(router, op, from, target, args);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, from));
        _run(cd);
    }

    // ---- the factory-made forms: each reads its env registry; a gen-1 env stays on generation 1

    function test_g1_token_gen2Env_bothGenerations_gen1EnvStays() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        assertEq(router.registryFor(t2), GEN2);
        _mintBy(router, t2, pq65);
        _mintBy(router, _ftoken(GEN2, msig2, "b"), msig2);
        _mintBy(router, _ftoken(GEN2, pq, "c"), pq); // a gen-1 holder on a gen-2 env (the walk back)
        _mintBy(router, _ftoken(GEN2, msig, "d"), msig);
        address t1 = _ftoken(PREG, pq65, "e");
        assertEq(router.registryFor(t1), PREG);
        _mintRefused(router, t1, pq65);
        _mintBy(router, _ftoken(PREG, pq, "f"), pq);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 1, "the gen-2 holder's nonce, at generation 2");
        assertEq(router.mtxNonce(pq65, 0), 0, "the router's own registry's map untouched");
    }

    function test_g1_dex_gen2Env_bothGenerations_gen1EnvStays() public {
        SCaaSDex d2 = _fdex(GEN2, pq65, "a");
        assertEq(router.registryFor(address(d2)), GEN2);
        _runOn(router, _sFor(router, SET_LISTED_ONLY, pq65, address(d2), abi.encode(true)));
        assertTrue(d2.listedOnly(), "a gen-2 admin on a gen-2 env DEX");
        SCaaSDex d2b = _fdex(GEN2, pq, "b");
        _runOn(router, _sFor(router, SET_LISTED_ONLY, pq, address(d2b), abi.encode(true)));
        assertTrue(d2b.listedOnly(), "a gen-1 admin on a gen-2 env DEX");
        SCaaSDex d1 = _fdex(PREG, pq65, "c");
        assertEq(router.registryFor(address(d1)), PREG);
        _refused(SET_LISTED_ONLY, pq65, address(d1), abi.encode(true));
        SCaaSDex d1b = _fdex(PREG, pq, "d");
        _runOn(router, _sFor(router, SET_LISTED_ONLY, pq, address(d1b), abi.encode(true)));
        assertTrue(d1b.listedOnly(), "a gen-1 admin on a gen-1 env DEX");
    }

    function test_g1_genericClass_gen2Env_bothGenerations_gen1EnvStays() public {
        ThingKind i2 = _fthing(GEN2, pq65, "a");
        assertEq(i2.GOV_ROUTER(), address(router), "governed by the chain's router");
        assertEq(router.registryFor(address(i2)), GEN2);
        bytes memory a = abi.encode(DO_THING, msig, EnvKit.codeUidOf(address(i2)));
        _runOn(router, _sFor(router, GRANT_ROLE, pq65, address(i2), a));
        assertTrue(i2.hasRole(DO_THING, msig), "a gen-2 admin on a gen-2 env instance");
        ThingKind i2b = _fthing(GEN2, pq, "b");
        a = abi.encode(DO_THING, msig, EnvKit.codeUidOf(address(i2b)));
        _runOn(router, _sFor(router, GRANT_ROLE, pq, address(i2b), a));
        assertTrue(i2b.hasRole(DO_THING, msig), "a gen-1 admin on a gen-2 env instance");
        ThingKind i1 = _fthing(PREG, pq65, "c");
        assertEq(router.registryFor(address(i1)), PREG);
        _refused(GRANT_ROLE, pq65, address(i1), abi.encode(DO_THING, msig, EnvKit.codeUidOf(address(i1))));
        ThingKind i1b = _fthing(PREG, pq, "d");
        a = abi.encode(DO_THING, msig, EnvKit.codeUidOf(address(i1b)));
        _runOn(router, _sFor(router, GRANT_ROLE, pq, address(i1b), a));
        assertTrue(i1b.hasRole(DO_THING, msig), "a gen-1 admin on a gen-1 env instance");
    }

    // ---- not factory-made: the router's own registry

    /// A chain contract the factory did not make (the factory itself, an `IAdmin`): its own registry, generation 1. A gen-2
    /// pending admin cannot accept through the router (the known limit: factory ops keep the router's generation).
    function test_g1_notFactoryMade_chainContract_ownRegistry() public {
        assertEq(router.registryFor(address(f)), PREG);
        vm.prank(REGISTRAR);
        f.transferAdmin(pq65, u);
        bytes memory cd = _sFor(router, ACCEPT_ADMIN, pq65, address(f), "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq65));
        _run(cd);
        vm.prank(REGISTRAR);
        f.transferAdmin(pq, u);
        _run(_sFor(router, ACCEPT_ADMIN, pq, address(f), ""));
        assertEq(f.admin(), pq, "a gen-1 admin accepts through the router");
    }

    /// A clone-form contract the factory did not make, whose code names generation 2: not believed (own registry, no nonce
    /// spent in either map).
    function test_g1_fakeInstance_ignored() public {
        NormalToken fake = _token(GEN2, address(router), pq65, false);
        assertEq(router.registryFor(address(fake)), PREG);
        _mintRefused(router, address(fake), pq65);
        assertEq(router.mtxNonce(pq65, 0), 0);
        assertEq(router.mtxNonceFor(address(fake), pq65, 0), 0);
        assertEq(router.registryFor(BOB), PREG, "no code: own");
    }

    // ---- the nonce keying (CTR-GOV-33)

    /// A token whose env names a registry that passes any id: a forged op as a real gen-1 id lands on that token (the env
    /// publication's trust), but it spends that registry's nonce only; the id's nonce at the real registry stays, and its
    /// own op on a real token still runs at nonce 0.
    function test_g1_badEnvRegistry_burnsOnlyItsOwnNonces() public {
        address bad = _ftoken(address(yes), pq, "x");
        address real = _ftoken(PREG, pq, "y");
        assertEq(router.registryFor(bad), address(yes));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        IUARegistry.UASig memory forged;
        forged.signature = hex"00";
        bytes memory args = abi.encode(BOB, uint256(5));
        for (uint256 i; i < 3; ++i) {
            e.nonce = i;
            _run(_calldata(OP_MINT, e, bad, args, _tail(abi.encode(forged))));
        }
        assertEq(router.mtxNonceFor(bad, pq, 0), 3, "the bad registry's map");
        assertEq(router.mtxNonce(pq, 0), 0, "the real registry's nonce of the id: untouched");
        assertEq(router.mtxNonceFor(real, pq, 0), 0);
        _mintBy(router, real, pq);
        assertEq(router.mtxNonce(pq, 0), 1);
        // the forgery does not reach the real token
        e.nonce = 1;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(_calldata(OP_MINT, e, real, args, _tail(abi.encode(forged))));
    }

    /// Replay across registries: the signature names `target`, which fixes the registry. An op spent at generation 2 replays
    /// nowhere: again on its target `MetaTxBadNonce`; on a gen-1 target, whose map is still at the same nonce, refused.
    function test_g1_replayAcrossRegistries_refused() public {
        address t2 = _ftoken(GEN2, pq, "a");
        address t1 = _ftoken(PREG, pq, "b");
        bytes memory cd = _sFor(router, OP_MINT, pq, t2, abi.encode(BOB, uint256(5)));
        _run(cd);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(cd);
        assertEq(router.mtxNonceFor(t1, pq, 0), 0, "the gen-1 map: still at nonce 0");
        bytes memory swapped = bytes.concat(_slice(cd, 0, 4 + 256), abi.encode(t1), _slice(cd, 4 + 288, cd.length));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(swapped);
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory r) {
        r = new bytes(to - from);
        for (uint256 i; i < r.length; ++i) {
            r[i] = b[from + i];
        }
    }

    /// `UACancelNonce` keeps its semantics: the router's own map (a native id everywhere, a derived id at the router's
    /// registry); a gen-2 env map is not touched by it.
    function test_g1_cancelNonce_ownMapOnly() public {
        address t2 = _ftoken(GEN2, pq, "a");
        address t1 = _ftoken(PREG, pq, "b");
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        bytes32 c = keccak256(
            abi.encode(
                MetaTxLib.UA_CANCEL_NONCE_TYPEHASH,
                e.from,
                uint256(0),
                e.batch,
                e.nonce,
                e.validUntil,
                e.mode,
                address(0),
                e.fee,
                address(0)
            )
        );
        router.mtxCancelNonce(e, 0, _auth(pq, keccak256(abi.encodePacked("\x19\x01", _domain(router), c))));
        // the cancel ran on lane 0 at nonce 0 and bumped lane 0: lane 0 is at 2
        assertEq(router.mtxNonce(pq, 0), 2);
        assertEq(router.mtxNonceFor(t1, pq, 0), 2, "gen-1 env: the router's own map");
        assertEq(router.mtxNonceFor(t2, pq, 0), 0, "gen-2 env: its own map");
        _mintBy(router, t2, pq);
        _mintBy(router, t1, pq);
    }

    /// The namespace `scaas.govrouter.nonce` (ERC-7201) and its key order `(registry, id, lane)`: read with `vm.load` after a
    /// write through the router's own path.
    function test_g1_nonceNamespacePinned() public {
        bytes32 root = keccak256(abi.encode(uint256(keccak256("scaas.govrouter.nonce")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(root, 0x3b7181b4a1cb09fc268151c43768a834fdadbe3ebbd3b129e4bbaea7d311e100);
        address t2 = _ftoken(GEN2, pq65, "a");
        _mintBy(router, t2, pq65);
        bytes32 slot = keccak256(abi.encode(uint256(0), keccak256(abi.encode(pq65, keccak256(abi.encode(GEN2, root))))));
        assertEq(uint256(vm.load(address(router), slot)), 1, "nonce[GEN2][pq65][0]");
    }

    /// The gas of one router op (`mtxMint`, fresh lane 0, a first mint), each a transaction (`isolate`): G1's full path (a
    /// derived signer on a factory-made target of another generation: the code copy, `infoOf`, the keyed nonce) against
    /// the same op where the env is the router's own (the code copy only) and on a router without a factory.
    function test_g1_gas() public {
        uint256[7] memory g;
        g[0] = _mintGas(_ftoken(GEN2, pq65, "a"), pq65); // full path, a gen-2 holder
        g[1] = _mintGas(_ftoken(GEN2, pq, "b"), pq); // full path, a gen-1 holder (gen 2 walks back)
        g[2] = _mintGas(_ftoken(PREG, pq, "c"), pq); // a gen-1 env: the code copy, then the one map
        g[3] = _mintGas(_ftoken(GEN2, eoa, "d"), eoa); // a native signer: no lookup
        // the same op on a router with no factory (every target its own registry), on a clone governed by it
        GovernanceRouter r0 = new GovernanceRouter(chainUidA, PREG, _fixtureSka(), false, address(0));
        g[4] = _mintGasOn(r0, address(_token(PREG, address(r0), pq, false)), pq);
        g[5] = _mintGasOn(r0, address(_token(PREG, address(r0), eoa, false)), eoa);
        // a gen-2 holder on a router whose own registry is generation 2 (the code copy, then the one map): g[0] less this is
        // G1's lookup and keyed nonce
        g[6] = _mintGasOn(router2, address(_token(GEN2, address(router2), pq65, false)), pq65);
        string[7] memory n = [
            "gen2 env, pq65",
            "gen2 env, pq",
            "gen1 env, pq",
            "gen2 env, eoa",
            "no factory, pq",
            "no factory, eoa",
            "router on gen2, pq65"
        ];
        uint256[7] memory pin = [uint256(123_827), 138_864, 122_413, 105_559, 121_931, 105_559, 123_018];
        for (uint256 i; i < 7; ++i) {
            emit log_named_uint(n[i], g[i]);
        }
        for (uint256 i; i < 7; ++i) {
            assertEq(g[i], pin[i], n[i]);
        }
    }

    function _mintGas(address t, bytes32 from) internal returns (uint256) {
        return _mintGasOn(router, t, from);
    }

    function _mintGasOn(GovernanceRouter r, address t, bytes32 from) internal returns (uint256) {
        bytes memory cd = _sFor(r, OP_MINT, from, t, abi.encode(BOB, uint256(5)));
        (bool ok,) = address(r).call(cd);
        assertTrue(ok, "minted");
        return vm.lastCallGas().gasTotalUsed;
    }

    /// The keyed path's envelope (`_preAt`) refuses as `preNamedUA` does, by the same errors: an expired envelope, a bound
    /// relayer that is not the sender, an unknown mode, a fee mode the router does not support; the control runs.
    function test_g1_keyedPath_envelopeRefusals() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory args = abi.encode(BOB, uint256(5));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq65, 0);
        e.validUntil = block.timestamp - 1;
        bytes memory cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, block.timestamp));
        _run(cd);
        e = _envelope(router, pq65, 0);
        (e.mode, e.relayer) = (MetaTxLib.MODE_RESTRICT_RELAYER, address(0xdead));
        cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.expectRevert(
            abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(0xdead), address(this))
        );
        _run(cd);
        e = _envelope(router, pq65, 0);
        e.mode = 0x100;
        cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, uint32(0x100)));
        _run(cd);
        e = _envelope(router, pq65, 0);
        e.mode = MetaTxLib.MODE_FEE_FIXED;
        cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 0, "nothing spent");
        _mintBy(router, t2, pq65);
    }

    /// A native id uses no registry: one map for every target (`mtxNonce`), on any env.
    function test_g1_nativeId_oneMap() public {
        address t2 = _ftoken(GEN2, eoa, "a");
        assertEq(router.mtxNonceFor(t2, eoa, 0), router.mtxNonce(eoa, 0));
        _mintBy(router, t2, eoa);
        assertEq(router.mtxNonce(eoa, 0), 1);
        assertEq(router.mtxNonceFor(t2, eoa, 0), 1, "a native id on a gen-2 env target: the one map (G-2)");
        assertEq(router.mtxNonceFor(address(f), eoa, 0), 1);
    }

    // ---- the keyed path's own checks, each on a generation-2 env target (Fable G-2, 2026-11-24): the signature, the envelope
    //      order, the delegated relayer, `registryFor`'s zero and suffix checks

    /// A signature over another digest by the holder's own key, on a gen-2 target: `UAUnauthorized` from generation 2, nothing
    /// spent in either map; the control (the right digest) runs.
    function test_g1_keyedPath_wrongSignatureRefused() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory args = abi.encode(BOB, uint256(5));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq65, 0);
        bytes32 wrong = _digest(router, OP_MINT, e, t2, abi.encode(BOB, uint256(6)));
        bytes memory cd = _calldata(OP_MINT, e, t2, args, _tail(abi.encode(_auth(pq65, wrong))));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq65));
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 0, "the keyed map: nothing spent");
        assertEq(router.mtxNonce(pq65, 0), 0, "the one map: nothing spent");
        _mintBy(router, t2, pq65);
    }

    /// `preNamedUA`'s order on the keyed path: a bad nonce and a bad signature together give `MetaTxBadNonce`.
    function test_g1_keyedPath_nonceBeforeSignature() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq65, 0);
        e.nonce = 7;
        IUARegistry.UASig memory forged;
        forged.signature = hex"00";
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 0, 7));
        _run(_calldata(OP_MINT, e, t2, abi.encode(BOB, uint256(5)), _tail(abi.encode(forged))));
    }

    /// Fee bits 3 (no such fee mode) on the keyed path: `MetaTxUnknownMode` at the envelope, before the call check.
    function test_g1_keyedPath_feeBits3Refused() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory args = abi.encode(BOB, uint256(5));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq65, 0);
        e.mode = 0x30;
        bytes memory cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, uint32(0x30)));
        _run(cd);
    }

    /// A bound relayer with an EIP-7702 delegation designator as its code, on the keyed path: `CallerDelegated`, before the
    /// signature (the fixture signs relayer 0, so without the check the refusal would be `UAUnauthorized`).
    function test_g1_keyedPath_delegatedRelayerRefused() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory args = abi.encode(BOB, uint256(5));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq65, 0);
        (e.mode, e.relayer) = (MetaTxLib.MODE_RESTRICT_RELAYER, address(0x7702));
        bytes memory cd = _signedAt(router, OP_MINT, e, t2, args, args);
        vm.etch(address(0x7702), abi.encodePacked(hex"ef0100", address(0xdead)));
        vm.prank(address(0x7702));
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, address(0x7702)));
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 0, "nothing spent");
    }

    /// `registryFor` on an indexed clone (the fixture as factory): an env registry 0 is the router's own; a clone whose
    /// EIP-1167 suffix is broken is not the clone form, so its code's registry (generation 2) is not read.
    function test_g1_registryFor_zeroAndSuffixChecks() public {
        GovernanceRouter rf = new GovernanceRouter(chainUidA, PREG, _fixtureSka(), false, address(this));
        NormalToken z = _token(address(0), address(rf), pq, true);
        assertEq(rf.registryFor(address(z)), PREG, "an env registry 0: the router's own");
        NormalToken t2 = _token(GEN2, address(rf), pq65, true);
        assertEq(rf.registryFor(address(t2)), GEN2, "the control: an indexed gen-2 clone");
        bytes memory c = address(t2).code;
        c[31] = bytes1(uint8(c[31]) ^ 0x01);
        address odd = address(0x0dd);
        vm.etch(odd, c);
        made[odd] = true;
        assertEq(rf.registryFor(odd), PREG, "the suffix broken: not the clone form");
    }

    // ---- the keyed cancel (CTR-GOV-33 Change, owner 2026-11-24): `mtxCancelNonceFor`

    string constant CANCEL_FOR =
        "UACancelNonceFor(bytes32 from,address target,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    address constant RELAYER = address(0x5E1A);

    /// The cancel's calldata: `e.from` cancels `lane` in the map the router checks for an op on `target`; `e` the cancel's own
    /// envelope (an unbound relayer and fee recipient 0 in the message, as the contract hashes them).
    function _cancelFor(MetaTxLib.UAEnvelope memory e, address target, uint256 lane)
        internal
        view
        returns (bytes memory)
    {
        bytes32 h = keccak256(
            bytes.concat(
                abi.encode(keccak256(bytes(CANCEL_FOR)), e.from, target, lane),
                abi.encode(
                    e.batch,
                    e.nonce,
                    e.validUntil,
                    e.mode,
                    e.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? e.relayer : address(0),
                    e.fee,
                    e.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? e.feeRecipient : address(0)
                )
            )
        );
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domain(router), h));
        return abi.encodeCall(router.mtxCancelNonceFor, (e, target, lane, _auth(e.from, d)));
    }

    /// The cancel's envelope on lane `batch`, at the nonce the router checks for `target` there.
    function _envFor(bytes32 from, address target, uint256 batch)
        internal
        view
        returns (MetaTxLib.UAEnvelope memory e)
    {
        e = _envelope(router, from, batch);
        e.nonce = router.mtxNonceFor(target, from, batch);
    }

    /// `cd` with its `target` word (after the eight envelope words) replaced.
    function _withTarget(bytes memory cd, address t) internal pure returns (bytes memory) {
        return bytes.concat(_slice(cd, 0, 4 + 256), abi.encode(t), _slice(cd, 4 + 288, cd.length));
    }

    /// G-7 (the re-review of 2026-11-25; CTR-GOV-33 Replay): a keyed cancel naming an address with no code (a target not
    /// created yet) is `TargetHasNoCode`, before anything moves, so one signature cannot run in the router's own map now and
    /// again in the keyed map once the factory creates the target. The control: the same signer's cancel after the creation
    /// runs once, in generation 2's map, and the router's own map is untouched.
    function test_g7_cancelForACodeLessTargetRefused() public {
        address p = f.predictAddress(nid(address(this)), 1, 0, "a");
        assertEq(p.code.length, 0);
        bytes memory cd = _cancelFor(_envFor(pq, p, 1), p, 0);
        vm.expectRevert(abi.encodeWithSelector(GovernanceRouterBase.TargetHasNoCode.selector, p));
        _run(cd);
        assertEq(router.mtxNonce(pq, 0), 0, "own map: nothing cancelled");
        assertEq(router.mtxNonce(pq, 1), 0, "own map: the cancel's nonce unspent");
        address t2 = _ftoken(GEN2, pq, "a");
        assertEq(t2, p, "the predicted address");
        _run(_cancelFor(_envFor(pq, t2, 1), t2, 0)); // the control
        assertEq(router.mtxNonceFor(t2, pq, 0), 1, "keyed map: lane 0 cancelled once");
        assertEq(router.mtxNonce(pq, 0), 0, "own map: untouched");
    }

    /// The twin of the next test: a gen-2 holder's op, signed at its keyed nonce and held back, lands later when nothing cancels it.
    function test_cancelFor_twin_heldOpLands() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory held = _sFor(router, OP_MINT, pq65, t2, abi.encode(BOB, uint256(5)));
        _run(held);
        assertEq(NormalToken(t2).balanceOf(BOB), 5, "the held op landed");
    }

    /// A holder only generation 2 knows, on a target whose env is generation 2, cancels lane 0 in that registry's map (the
    /// cancel sent on lane 1): the op it signed at lane 0 and never sent is then refused; the next nonce runs.
    function test_cancelFor_gen2Env_heldOpRefused() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        bytes memory held = _sFor(router, OP_MINT, pq65, t2, abi.encode(BOB, uint256(5)));
        bytes memory cd = _cancelFor(_envFor(pq65, t2, 1), t2, 0);
        vm.expectEmit(address(router));
        emit GovernanceRouterBase.UANonceCancelledAt(pq65, GEN2, 0, 1);
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 1, "lane 0 cancelled at generation 2");
        assertEq(router.mtxNonceFor(t2, pq65, 1), 1, "the cancel's own lane spent");
        assertEq(router.mtxNonce(pq65, 0), 0, "the router's own map: untouched");
        assertEq(router.mtxNonce(pq65, 1), 0);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(held);
        assertEq(NormalToken(t2).balanceOf(BOB), 0, "the held op did not land");
        _mintBy(router, t2, pq65);
    }

    /// One map per registry: a cancel naming one gen-2 target cancels the lane for every target of generation 2, and for a
    /// target of generation 1 nothing.
    function test_cancelFor_oneMapPerRegistry() public {
        address t2 = _ftoken(GEN2, pq, "a");
        address t2b = _ftoken(GEN2, pq, "b");
        address t1 = _ftoken(PREG, pq, "c");
        bytes memory held = _sFor(router, OP_MINT, pq, t2b, abi.encode(BOB, uint256(5)));
        _run(_cancelFor(_envFor(pq, t2, 1), t2, 0));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(held);
        assertEq(router.mtxNonceFor(t1, pq, 0), 0, "generation 1: untouched");
        _mintBy(router, t1, pq);
    }

    /// A hostile env registry (it passes any id): a forged cancel as a real holder naming a token on that registry lands in that
    /// registry's map only; the holder's held op at generation 2 still lands. The same forgery naming a gen-2 target is refused.
    function test_cancelFor_badEnvRegistry_cannotCancelRealNonce() public {
        address bad = _ftoken(address(yes), pq, "x");
        address t2 = _ftoken(GEN2, pq, "y");
        bytes memory held = _sFor(router, OP_MINT, pq, t2, abi.encode(BOB, uint256(5)));
        IUARegistry.UASig memory forged;
        forged.signature = hex"00";
        router.mtxCancelNonceFor(_envFor(pq, bad, 0), bad, 0, forged);
        assertEq(router.mtxNonceFor(bad, pq, 0), 2, "the bad registry's map: the cancel's nonce and the lane");
        assertEq(router.mtxNonceFor(t2, pq, 0), 0, "generation 2's map: untouched");
        assertEq(router.mtxNonce(pq, 0), 0, "the router's own map: untouched");
        MetaTxLib.UAEnvelope memory e = _envFor(pq, t2, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        router.mtxCancelNonceFor(e, t2, 0, forged);
        _run(held);
        assertEq(NormalToken(t2).balanceOf(BOB), 5, "the held op still lands");
    }

    /// The cancel is spent once: sent again, `MetaTxBadNonce`. Its signature names `target`, so the registry: the same bytes with
    /// another target, on a map still at that nonce, are refused by the signature, a target of the same registry (gen 2) and of
    /// another (gen 1), before and after it is spent.
    function test_cancelFor_replay_refused() public {
        address t2 = _ftoken(GEN2, pq, "a");
        address t2b = _ftoken(GEN2, pq, "b");
        address t1 = _ftoken(PREG, pq, "c");
        bytes memory cd = _cancelFor(_envFor(pq, t2, 1), t2, 0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(_withTarget(cd, t2b));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(_withTarget(cd, t1));
        _run(cd);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(_withTarget(cd, t1));
        assertEq(router.mtxNonceFor(t2, pq, 0), 1);
        assertEq(router.mtxNonceFor(t1, pq, 0), 0, "generation 1: untouched");
        assertEq(router.mtxNonceFor(t1, pq, 1), 0);
    }

    /// The router's own map: a keyed cancel leaves it; `mtxCancelNonce` still bumps it and leaves the keyed map.
    function test_cancelFor_ownMapUnaffected_mtxCancelNonceWorks() public {
        address t2 = _ftoken(GEN2, pq, "a");
        _run(_cancelFor(_envFor(pq, t2, 0), t2, 0));
        assertEq(router.mtxNonceFor(t2, pq, 0), 2, "the cancel on lane 0 at nonce 0, then lane 0 bumped");
        assertEq(router.mtxNonce(pq, 0), 0, "the router's own map: untouched");
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        bytes32 c = keccak256(
            abi.encode(
                MetaTxLib.UA_CANCEL_NONCE_TYPEHASH,
                e.from,
                uint256(0),
                e.batch,
                e.nonce,
                e.validUntil,
                e.mode,
                address(0),
                e.fee,
                address(0)
            )
        );
        router.mtxCancelNonce(e, 0, _auth(pq, keccak256(abi.encodePacked("\x19\x01", _domain(router), c))));
        assertEq(router.mtxNonce(pq, 0), 2, "mtxCancelNonce: the own map");
        assertEq(router.mtxNonceFor(t2, pq, 0), 2, "the keyed map: unchanged by it");
    }

    /// Controller call (2026-11-24): where the router checks an op on its own map (a native id on any target; a derived id on a
    /// target of the router's own registry, the factory itself, a contract the factory did not create), `mtxCancelNonceFor` is
    /// `mtxCancelNonce`:
    /// the cancel's nonce and `lane` in the one map, `UANonceCancelled`; no keyed map moves.
    function test_cancelFor_nativeAndOwnRegistry_asMtxCancelNonce() public {
        address t2 = _ftoken(GEN2, eoa, "a");
        vm.expectEmit(address(router));
        emit IUALedger.UANonceCancelled(eoa, 0, 2);
        _run(_cancelFor(_envFor(eoa, t2, 0), t2, 0));
        assertEq(router.mtxNonce(eoa, 0), 2, "a native id: the one map");
        assertEq(router.mtxNonceFor(t2, eoa, 0), 2);
        // G-7 (the re-review of 2026-11-25): an address with no code is refused (`test_g7_cancelForACodeLessTargetRefused`);
        // the router itself stands for a target with code outside the factory's index
        address[3] memory on = [_ftoken(PREG, pq, "b"), address(f), address(router)];
        for (uint256 i; i < 3; ++i) {
            bytes memory cd = _cancelFor(_envFor(pq, on[i], 0), on[i], 5);
            vm.expectEmit(address(router));
            emit IUALedger.UANonceCancelled(pq, 5, i + 1);
            _run(cd);
        }
        assertEq(router.mtxNonce(pq, 0), 3, "the cancels' own lane, in the one map");
        assertEq(router.mtxNonce(pq, 5), 3, "the cancelled lane, in the one map");
        assertEq(router.mtxNonceFor(_ftoken(GEN2, pq, "c"), pq, 5), 0, "generation 2's map: untouched");
    }

    /// Fee 0 from any sender; a paid mode refused on both paths as on every router op (fee mode `NONE`); a bound relayer: only
    /// it; an expired envelope refused. Nothing is spent by a refusal.
    function test_cancelFor_feeAndRelayer() public {
        address t2 = _ftoken(GEN2, pq65, "a");
        address t1 = _ftoken(PREG, pq, "b");
        bytes memory cd = _cancelFor(_envFor(pq65, t2, 1), t2, 0);
        vm.prank(address(0xBEEF));
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 1, "fee 0, any sender");
        MetaTxLib.UAEnvelope memory e = _envFor(pq65, t2, 1);
        (e.mode, e.fee) = (MetaTxLib.MODE_FEE_FIXED, 1);
        cd = _cancelFor(e, t2, 0);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        _run(cd);
        e = _envFor(pq, t1, 1);
        (e.mode, e.fee) = (MetaTxLib.MODE_FEE_FIXED, 1);
        cd = _cancelFor(e, t1, 0);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, MetaTxLib.MODE_FEE_FIXED));
        _run(cd);
        e = _envFor(pq65, t2, 1);
        (e.mode, e.relayer) = (MetaTxLib.MODE_RESTRICT_RELAYER, RELAYER);
        cd = _cancelFor(e, t2, 0);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, RELAYER, address(this)));
        _run(cd);
        e = _envFor(pq65, t2, 1);
        e.validUntil = block.timestamp - 1;
        bytes memory expired = _cancelFor(e, t2, 0);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, block.timestamp));
        _run(expired);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 1, "nothing spent by a refusal");
        assertEq(router.mtxNonceFor(t2, pq65, 1), 1);
        assertEq(router.mtxNonce(pq, 1), 0);
        vm.prank(RELAYER);
        _run(cd);
        assertEq(router.mtxNonceFor(t2, pq65, 0), 2, "the bound relayer's send");
    }

    /// The gas of one cancel, each a transaction (`isolate`): the keyed path (a gen-2 holder on a gen-2 env target) and the own
    /// map (a gen-1 holder on a gen-1 env target; a native id), against `mtxCancelNonce` of the same gen-1 holder.
    function test_cancelFor_gas() public {
        uint256[4] memory g;
        address t2 = _ftoken(GEN2, pq65, "a");
        address t1 = _ftoken(PREG, pq, "b");
        g[0] = _gasOf(_cancelFor(_envFor(pq65, t2, 1), t2, 0));
        g[1] = _gasOf(_cancelFor(_envFor(pq, t1, 1), t1, 0));
        g[2] = _gasOf(_cancelFor(_envFor(eoa, t2, 1), t2, 0));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 2);
        bytes32 c = keccak256(
            abi.encode(
                MetaTxLib.UA_CANCEL_NONCE_TYPEHASH,
                e.from,
                uint256(3),
                e.batch,
                e.nonce,
                e.validUntil,
                e.mode,
                address(0),
                e.fee,
                address(0)
            )
        );
        g[3] = _gasOf(
            abi.encodeCall(
                router.mtxCancelNonce, (e, 3, _auth(pq, keccak256(abi.encodePacked("\x19\x01", _domain(router), c))))
            )
        );
        string[4] memory n = ["keyed, gen2 env, pq65", "own, gen1 env, pq", "own, native", "mtxCancelNonce, pq"];
        // G-7 (the re-review of 2026-11-25: `TargetHasNoCode` at the head, the target's code read first): 94,086 -> 94,326,
        // 92,199 -> 92,439, 72,445 -> 75,585 (a native signer's target was not read before: its cold account), 88,894 unchanged
        uint256[4] memory pin = [uint256(94_326), 92_439, 75_585, 88_894];
        for (uint256 i; i < 4; ++i) {
            emit log_named_uint(n[i], g[i]);
        }
        for (uint256 i; i < 4; ++i) {
            assertEq(g[i], pin[i], n[i]);
        }
    }

    function _gasOf(bytes memory cd) internal returns (uint256) {
        (bool ok,) = address(router).call(cd);
        assertTrue(ok, "cancelled");
        return vm.lastCallGas().gasTotalUsed;
    }
}
