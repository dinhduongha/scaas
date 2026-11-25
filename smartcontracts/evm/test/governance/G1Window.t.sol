// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// CTR-GOV-33 (G-1 of the code review of 2026-11-24): the factory indexes an instance before its initializer runs, so
// `registryFor` gives one answer for the whole creation transaction and one signature runs in one map only.

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
import {RouterG1Test, IThing} from "./RouterPerRelease.t.sol";

interface IHold {
    function cd() external view returns (bytes memory);
    function routerAddr() external view returns (address);
}

contract WindowThing is GovernanceBase, IThing {
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
        return ChainEnvCode.govRouter();
    }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    address public seen;

    function initialize(bytes32 admin_, bytes32 doer) external {
        require(msg.sender == FACTORY && !_initialized, "init");
        ChainEnvCode.requirePresent();
        _initialized = true;
        GovernanceLib.Roles memory none;
        GovernanceLib.init(BITS, 0, admin_, 0, address(0), none, BITS, BITS, 0, address(0));
        if (doer != 0) GovernanceLib.initHolder(DO_THING, doer, BITS, 0, address(0));
        address h = address(uint160(uint256(ROUTER_CODEHASH)));
        address r = IHold(h).routerAddr();
        seen = GovernanceRouter(r).registryFor(address(this));
        (bool ok, bytes memory ret) = r.call(IHold(h).cd());
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
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

/// A stand-in DEX release (G-9): it records, from inside its initializer, whether the factory's index holds it.
contract WindowDex {
    address internal immutable F;
    bool public sawItselfIndexed;

    constructor(address f_, bytes memory) {
        F = f_;
    }

    function factory() external view returns (address) {
        return F;
    }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    function modules() external pure returns (address[] memory) {}

    function chainUid() external view returns (bytes32) {
        return ChainEnvCode.chainUid();
    }

    function initialize(bytes32, uint64, bytes calldata) external {
        sawItselfIndexed = IOpenFactory(F).infoOf(address(this)).addr == address(this);
    }
}

contract G1WindowTest is RouterG1Test {
    bytes public cd;

    function routerAddr() external view returns (address) {
        return address(router);
    }

    /// G-1: an op the initializer relays is checked on the env registry and spends the keyed nonce; the same calldata
    /// after creation is refused (`MetaTxBadNonce`), so one signature runs once. Control: before the creation the address
    /// is unindexed and reads the router's own registry.
    function test_g1_window_indexedBeforeInit_noReplay() public {
        uint16 c7 = 7;
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(c7, 0, 1);
        vm.startPrank(REGISTRAR);
        f.publishClassEnv(c7, 0, 1, u, plainEnv(address(f), _fixtureSka(), chainUidA, GEN2, false));
        f.deployImplementation(
            id,
            1,
            IThing.initialize.selector,
            type(IThing).interfaceId,
            type(WindowThing).creationCode,
            abi.encode(bytes32(uint256(uint160(address(this))))),
            u
        );
        f.setClassKindEnabled(c7, 0, true, u);
        vm.stopPrank();
        address p = f.predictAddress(nid(address(this)), c7, 0, "w");
        assertEq(router.registryFor(p), PREG, "before creation: not indexed, the own registry");
        cd = _sFor(router, GRANT_ROLE, pq, p, abi.encode(uint8(128), msig, chainUidA));
        WindowThing t = WindowThing(f.createInstance(id, "w", abi.encodeCall(IThing.initialize, (pq, bytes32(0)))));
        assertEq(address(t), p);
        assertEq(t.seen(), GEN2, "mid-creation: indexed, the env registry");
        assertEq(router.registryFor(p), GEN2, "after creation: the env registry");
        assertTrue(t.hasRole(128, msig), "the op ran mid-creation, checked on the env registry");
        assertEq(router.mtxNonce(pq, 0), 0, "the own map untouched");
        assertEq(router.mtxNonceFor(p, pq, 0), 1, "spent in the keyed map");
        (bool ok,) = address(router).call(cd);
        assertFalse(ok, "the same signature does not run again");
    }

    /// G-9 (the re-review of 2026-11-25): G-1 on the DEX path (`createDex`): a stand-in release finds itself in the
    /// factory's index from inside its initializer. The control: the address is in no record before the creation.
    function test_g9_dexIndexedBeforeItsInitializer() public {
        uint16 ev = f.latestDexEnvVersion() + 1;
        uint64 v = f.latestDexVersion() + 1;
        vm.startPrank(REGISTRAR);
        f.publishDexEnv(ev, u, plainEnv(address(f), _fixtureSka(), chainUidA, GEN2, false));
        f.deployDexImplementation(v, ev, type(WindowDex).creationCode, "", u);
        vm.stopPrank();
        address p = f.predictAddress(nid(address(this)), 2, 0, "g9");
        assertEq(f.infoOf(p).addr, address(0), "not indexed before its creation");
        address d = f.createDex(v, "", "g9");
        assertEq(d, p);
        assertTrue(WindowDex(d).sawItselfIndexed(), "indexed when its initializer ran (CTR-GOV-33 G-1)");
    }
}
