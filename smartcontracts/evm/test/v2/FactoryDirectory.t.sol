// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {StubUARegistry} from "../helpers/Mocks.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {TestRouter} from "./FactoryAdmin.t.sol";

/// The directory's ABI (spec 2026-11-10-admin-not-owner.md §13.3, §13.4, §13.6), written out here so the test pins it apart
/// from the source's declarations (and compiles against the factory before T15: the red run).
interface IFactoryDirectory {
    struct Directory {
        address uaRegistry;
        address govRouter;
        address relayFeeRouter;
        address relayFeeExecutor;
        address complianceRegistry;
        address smartKeyAccountFactory;
        address zetherStatements;
    }

    event ChainEntrySet(bytes4 indexed view_, address at_, bytes32 codeHash);

    error EntryAlreadySet(bytes4 view_);
    error CodeHashMismatch(address at_, bytes32 expected, bytes32 got);
    error EntryMismatch(bytes4 view_);
    error RouterRegistryInvalid(address registry);
    error SmartKeyCloneHashMismatch(bytes32 expected, bytes32 got);
    error EnvRegistryMismatch(address expected, address got);
    error EnvSmartKeyAccountMismatch(bytes32 cloneHash, address got);

    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, bytes32 govRouterCodeHash,
        uint256 refBlock, bytes32 refHash) external;
    function setChainEntries(IOpenFactory.ChainEntries calldata entries, bytes32 chainUid_) external;
    function directory() external view returns (Directory memory);
    function uaRegistry() external view returns (address);
    function govRouter() external view returns (address);
    function relayFeeRouter() external view returns (address);
    function relayFeeExecutor() external view returns (address);
    function complianceRegistry() external view returns (address);
    function smartKeyAccountFactory() external view returns (address);
    function zetherStatements() external view returns (address);
}

/// The router's view of spec §13.4 (T15).
interface IRouterCloneHash {
    function smartKeyCloneHash() external view returns (bytes32);
}

/// A relay router stand-in whose `EXECUTOR()` is another router's executor: that executor's `ROUTER()` is not it.
contract ForeignExecutorRouter {
    address public immutable EXECUTOR;

    constructor(address executor) {
        EXECUTOR = executor;
    }
}

/// `OpenFactory` as the chain's directory (round 3r, CTR-GOV-23; spec §13, owner 2026-11-10, option (a), no constants): the
/// router's code hash, registry and `SmartKeyAccount` clone hash at `configureChain`; the four write-once entries of
/// `setChainEntries` (the relay pair, the compliance registry, the account factory, `ZetherStatements`), each by its code
/// hash and its own cross-check, every view call failing closed; the views and `directory()`; the env publishes bound to
/// the router's registry and implementation (§13.4); `MAX_LIBS`. Mutants D1-D14 (§13.9). The two-chain row is in
/// `ChainNeutralFactory.t.sol`; the deploy flow's (`DEPLOY_SALT`, `RELAY_SALT`) is T10's. **UNAUDITED.**
contract FactoryDirectoryTest is Test {
    bytes32 constant UID = keccak256("directory chain A");
    bytes32 constant UID_B = keccak256("directory chain B");
    address constant STRANGER = address(0x5757);
    uint16 constant CLS = 4;

    address deployer = makeAddr("deployer");
    StubUARegistry ureg;
    SmartKeyAccountFactory skaf;
    address impl; // skaf's implementation: the router's and the registry's clone hash
    GovernanceRouter router;
    TestRouter trouter;
    RelayFeeRouter relay;
    ComplianceRegistry creg; // names `router`
    ZetherStatements zs;

    /// The nine arguments of `setChainEntries`.
    struct E {
        address relay;
        bytes32 relayHash;
        bytes32 execHash;
        address creg;
        bytes32 cregHash;
        address skaf;
        bytes32 skafHash;
        address zs;
        bytes32 zsHash;
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        skaf = new SmartKeyAccountFactory(UID);
        impl = skaf.IMPLEMENTATION();
        ureg = new StubUARegistry(UID);
        ureg.setSmartKeyCloneHash(EnvKit.cloneHash(impl));
        router = new GovernanceRouter(UID, address(ureg), impl, false);
        trouter = new TestRouter(UID, address(ureg));
        relay = new RelayFeeRouter();
        creg = new ComplianceRegistry(nid(deployer), address(router), UID);
        zs = new ZetherStatements();
    }

    // ------------------------------------------------------------------ fixture

    function _d(OpenFactory f) internal pure returns (IFactoryDirectory) {
        return IFactoryDirectory(address(f));
    }

    function _h(address a) internal view returns (bytes32) {
        return a == address(0) ? bytes32(0) : a.codehash;
    }

    function _ccd(address r, bytes32 h) internal pure returns (bytes memory) {
        return abi.encodeCall(IFactoryDirectory.configureChain, (UID, 0, r, h, 0, bytes32(0)));
    }

    /// A factory of `deployer` on chain A, configured with router `r` (its own code hash).
    function _factory(address r) internal returns (OpenFactory f) {
        f = new OpenFactory(nid(deployer));
        EnvKit.genesis(UID);
        _call(deployer, address(f), _ccd(r, _h(r)));
    }

    /// The four entries of this chain, each with its own code hash.
    function _all() internal view returns (E memory e) {
        e = E(address(relay), _h(address(relay)), _h(relay.EXECUTOR()), address(creg), _h(address(creg)), address(skaf),
            _h(address(skaf)), address(zs), _h(address(zs)));
    }

    function _only(uint256 i) internal view returns (E memory e) {
        E memory a = _all();
        if (i == 0) (e.relay, e.relayHash, e.execHash) = (a.relay, a.relayHash, a.execHash);
        if (i == 1) (e.creg, e.cregHash) = (a.creg, a.cregHash);
        if (i == 2) (e.skaf, e.skafHash) = (a.skaf, a.skafHash);
        if (i == 3) (e.zs, e.zsHash) = (a.zs, a.zsHash);
    }

    function _cd(E memory e) internal pure returns (bytes memory) {
        return _cd(e, UID);
    }

    /// The entries `e` as the named struct (CTR-GOV-27), with the chain word `uid`.
    function _cd(E memory e, bytes32 uid) internal pure returns (bytes memory) {
        return abi.encodeCall(IFactoryDirectory.setChainEntries, (IOpenFactory.ChainEntries(e.relay, e.relayHash, e.execHash,
            e.creg, e.cregHash, e.skaf, e.skafHash, e.zs, e.zsHash), uid));
    }

    /// The view selector of entry `i` (0 relay, 1 compliance registry, 2 account factory, 3 Zether statements).
    function _sel(uint256 i) internal pure returns (bytes4) {
        return [IFactoryDirectory.relayFeeRouter.selector, IFactoryDirectory.complianceRegistry.selector,
            IFactoryDirectory.smartKeyAccountFactory.selector, IFactoryDirectory.zetherStatements.selector][i];
    }

    function _entryAt(OpenFactory f, uint256 i) internal view returns (address) {
        (bool ok, bytes memory ret) = address(f).staticcall(abi.encodeWithSelector(_sel(i)));
        require(ok && ret.length == 32, "entry view");
        return abi.decode(ret, (address));
    }

    /// Entry `i` of `e` replaced by `a` with code hash `h`.
    function _with(E memory e, uint256 i, address a, bytes32 h) internal pure returns (E memory) {
        if (i == 0) (e.relay, e.relayHash) = (a, h);
        if (i == 1) (e.creg, e.cregHash) = (a, h);
        if (i == 2) (e.skaf, e.skafHash) = (a, h);
        if (i == 3) (e.zs, e.zsHash) = (a, h);
        return e;
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

    function _chm(address a, bytes32 expected, bytes32 got) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IFactoryDirectory.CodeHashMismatch.selector, a, expected, got);
    }

    function _mismatch(bytes4 v) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IFactoryDirectory.EntryMismatch.selector, v);
    }

    function _cloneErr(bytes32 expected, bytes32 got) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IFactoryDirectory.SmartKeyCloneHashMismatch.selector, expected, got);
    }

    // ------------------------------------------------------------------ configureChain (§13.3, §13.4)

    /// D6: the router's code hash must be the argument, which pins something (not 0, not `keccak256("")`); router 0 with
    /// hash 0 is no router, router 0 with a hash is refused.
    function test_configureChain_routerCodeHash() public {
        OpenFactory u = new OpenFactory(nid(deployer));
        EnvKit.genesis(UID);
        bytes32 h = _h(address(router));
        bytes32[3] memory bad = [_h(address(trouter)), bytes32(0), keccak256("")];
        for (uint256 i; i < 3; ++i) _refused(deployer, address(u), _ccd(address(router), bad[i]), _chm(address(router), bad[i], h));
        _refused(deployer, address(u), _ccd(address(0), h), _chm(address(0), h, bytes32(0)));
        _call(deployer, address(u), _ccd(address(router), h)); // positive control
        assertEq(u.govRouter(), address(router));
        OpenFactory n = _factory(address(0)); // 0 with 0: no router
        assertEq(n.govRouter(), address(0));
        assertEq(n.chainUid(), UID);
    }

    /// D12 (0, no code): the router's `registry()` must be an account with code; a router that answers no `registry()`
    /// fails closed.
    function test_configureChain_routerRegistryZeroOrNoCode() public {
        OpenFactory u = new OpenFactory(nid(deployer));
        EnvKit.genesis(UID);
        GovernanceRouter r0 = new GovernanceRouter(UID, address(0), address(0), false);
        GovernanceRouter rn = new GovernanceRouter(UID, address(0xD1), address(0), false);
        bytes4 e = IFactoryDirectory.RouterRegistryInvalid.selector;
        _refused(deployer, address(u), _ccd(address(r0), _h(address(r0))), abi.encodeWithSelector(e, address(0)));
        _refused(deployer, address(u), _ccd(address(rn), _h(address(rn))), abi.encodeWithSelector(e, address(0xD1)));
        StubUARegistry noRegistryView = new StubUARegistry(UID); // answers chainUid(), not registry()
        _refused(deployer, address(u), _ccd(address(noRegistryView), _h(address(noRegistryView))),
            abi.encodeWithSelector(e, address(0)));
        _call(deployer, address(u), _ccd(address(router), _h(address(router)))); // positive control
    }

    /// D9: the router's `smartKeyCloneHash()` must be its registry's; a registry that answers none fails closed.
    function test_configureChain_cloneHashOfTheRegistry() public {
        OpenFactory u = new OpenFactory(nid(deployer));
        EnvKit.genesis(UID);
        GovernanceRouter rx = new GovernanceRouter(UID, address(ureg), address(0xBEEF), false);
        _refused(deployer, address(u), _ccd(address(rx), _h(address(rx))),
            _cloneErr(EnvKit.cloneHash(address(0xBEEF)), EnvKit.cloneHash(impl)));
        GovernanceRouter r0 = new GovernanceRouter(UID, address(ureg), address(0), false);
        _refused(deployer, address(u), _ccd(address(r0), _h(address(r0))), _cloneErr(bytes32(0), EnvKit.cloneHash(impl)));
        GovernanceRouter mute = new GovernanceRouter(UID, address(relay), address(0), false); // relay: no smartKeyCloneHash()
        _refused(deployer, address(u), _ccd(address(mute), _h(address(mute))), _cloneErr(bytes32(0), bytes32(0)));
        assertEq(IRouterCloneHash(address(router)).smartKeyCloneHash(), EnvKit.cloneHash(impl), "the router's view");
        _call(deployer, address(u), _ccd(address(router), _h(address(router)))); // positive control
    }

    // ------------------------------------------------------------------ setChainEntries: write once (§13.3)

    /// D1 (each entry): each entry written once into its zero slot (`ChainEntrySet`), the others left open; a second write
    /// of it, the same address or another, `EntryAlreadySet`.
    function test_setChainEntries_eachEntryOnce() public {
        OpenFactory f = _factory(address(router));
        E memory a = _all();
        address[4] memory ats = [a.relay, a.creg, a.skaf, a.zs];
        bytes32[4] memory hs = [a.relayHash, a.cregHash, a.skafHash, a.zsHash];
        for (uint256 i; i < 4; ++i) {
            for (uint256 j = i; j < 4; ++j) assertEq(_entryAt(f, j), address(0), "open until written");
            vm.expectEmit(true, true, true, true, address(f));
            emit IFactoryDirectory.ChainEntrySet(_sel(i), ats[i], hs[i]);
            _call(deployer, address(f), _cd(_only(i)));
            assertEq(_entryAt(f, i), ats[i]);
            bytes memory again = abi.encodeWithSelector(IFactoryDirectory.EntryAlreadySet.selector, _sel(i));
            _refused(deployer, address(f), _cd(_only(i)), again);
            _refused(deployer, address(f), _cd(_with(_only(i), i, address(router), _h(address(router)))), again);
        }
        _refused(deployer, address(f), _cd(a), abi.encodeWithSelector(IFactoryDirectory.EntryAlreadySet.selector, _sel(0)));
    }

    /// D2: an entry whose code hash is not its argument is refused (each entry), the factory's own too.
    function test_setChainEntries_wrongCodeHash() public {
        OpenFactory f = _factory(address(router));
        bytes32 wrong = _h(address(f));
        E memory a = _all();
        address[4] memory ats = [a.relay, a.creg, a.skaf, a.zs];
        for (uint256 i; i < 4; ++i) {
            _refused(deployer, address(f), _cd(_with(_only(i), i, ats[i], wrong)), _chm(ats[i], wrong, _h(ats[i])));
        }
        _call(deployer, address(f), _cd(a)); // positive control
    }

    /// D3: no code is no entry: an account that does not exist (code hash 0) and one with a balance and no code (code hash
    /// `keccak256("")`), each given its own hash, are refused (each entry).
    function test_setChainEntries_noCode() public {
        OpenFactory f = _factory(address(router));
        address none = address(0xC0DE0);
        address empty = address(0xC0DE1);
        vm.deal(empty, 1);
        assertEq(none.codehash, bytes32(0));
        assertEq(empty.codehash, keccak256(""));
        for (uint256 i; i < 4; ++i) {
            _refused(deployer, address(f), _cd(_with(_only(i), i, none, bytes32(0))), _chm(none, bytes32(0), bytes32(0)));
            _refused(deployer, address(f), _cd(_with(_only(i), i, empty, keccak256(""))),
                _chm(empty, keccak256(""), keccak256("")));
        }
        _call(deployer, address(f), _cd(_all())); // positive control
    }

    /// The admin's alone (`NotAdmin`), and only after `configureChain`.
    function test_setChainEntries_strangerAndUnconfigured() public {
        OpenFactory f = _factory(address(router));
        _refused(STRANGER, address(f), _cd(_all()), abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(STRANGER)));
        OpenFactory u = new OpenFactory(nid(deployer));
        _refused(deployer, address(u), _cd(_all()), abi.encodeWithSelector(IOpenFactory.ChainNotConfigured.selector));
        _call(deployer, address(f), _cd(_all())); // positive control
    }

    /// CTR-GOV-27: the admin's call made for a sibling factory (the same address, another chain word) is refused by name
    /// before any write, after `NotAdmin` for a stranger; the same entries with the factory's own word are the control.
    function test_setChainEntries_siblingWordRefused() public {
        OpenFactory f = _factory(address(router));
        vm.recordLogs();
        _refused(deployer, address(f), _cd(_all(), UID_B),
            abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, UID, UID_B));
        _refused(STRANGER, address(f), _cd(_all(), UID_B), abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(STRANGER)));
        assertEq(vm.getRecordedLogs().length, 0, "nothing written");
        for (uint256 i; i < 4; ++i) assertEq(_entryAt(f, i), address(0));
        _call(deployer, address(f), _cd(_all())); // positive control
        assertEq(_d(f).zetherStatements(), address(zs));
    }

    /// 0 leaves an entry open and writes nothing; a later call fills it.
    function test_setChainEntries_zeroLeavesOpenLaterFills() public {
        OpenFactory f = _factory(address(router));
        vm.recordLogs();
        _call(deployer, address(f), _cd(E(address(0), 0, 0, address(0), 0, address(0), 0, address(0), 0)));
        assertEq(vm.getRecordedLogs().length, 0, "nothing written");
        for (uint256 i; i < 4; ++i) assertEq(_entryAt(f, i), address(0));
        E memory a = _all();
        _call(deployer, address(f), _cd(_only(3)));
        E memory two = _only(1);
        (two.skaf, two.skafHash) = (a.skaf, a.skafHash);
        _call(deployer, address(f), _cd(two));
        _call(deployer, address(f), _cd(_only(0)));
        assertEq(_d(f).zetherStatements(), a.zs);
        assertEq(_d(f).complianceRegistry(), a.creg);
        assertEq(_d(f).smartKeyAccountFactory(), a.skaf);
        assertEq(_d(f).relayFeeRouter(), a.relay);
    }

    // ------------------------------------------------------------------ the relay pair (§13.3)

    /// D13 (executor hash): the relay router's `EXECUTOR()` must have the executor's code hash (not 0).
    function test_relayPair_executorCodeHash() public {
        OpenFactory f = _factory(address(router));
        address x = relay.EXECUTOR();
        bytes32[2] memory bad = [_h(address(relay)), bytes32(0)];
        for (uint256 i; i < 2; ++i) {
            E memory e = _only(0);
            e.execHash = bad[i];
            _refused(deployer, address(f), _cd(e), _chm(x, bad[i], _h(x)));
        }
        _call(deployer, address(f), _cd(_only(0))); // positive control
    }

    /// D13 (`ROUTER()`): a relay router whose `EXECUTOR()` answers `ROUTER()` with another address is refused.
    function test_relayPair_executorRouter() public {
        OpenFactory f = _factory(address(router));
        ForeignExecutorRouter fake = new ForeignExecutorRouter(relay.EXECUTOR());
        E memory e = _only(0);
        (e.relay, e.relayHash) = (address(fake), _h(address(fake)));
        _refused(deployer, address(f), _cd(e), _mismatch(IFactoryDirectory.relayFeeExecutor.selector));
        _call(deployer, address(f), _cd(_only(0))); // positive control
    }

    /// Fable 3r3s3t P3-10: writing the relay router also emits `ChainEntrySet` for its executor, with the checked code hash
    /// (`view_` = `relayFeeExecutor.selector`), after the router's own.
    function test_relayPair_executorEvent() public {
        OpenFactory f = _factory(address(router));
        E memory a = _all();
        vm.recordLogs();
        _call(deployer, address(f), _cd(_only(0)));
        Vm.Log[] memory l = vm.getRecordedLogs();
        bytes32 topic = IFactoryDirectory.ChainEntrySet.selector;
        uint256 n;
        for (uint256 i; i < l.length; ++i) {
            if (l[i].emitter != address(f) || l[i].topics[0] != topic) continue;
            bytes4 v = bytes4(l[i].topics[1]);
            (address at, bytes32 h) = abi.decode(l[i].data, (address, bytes32));
            if (n == 0) assertEq(v, _sel(0), "the router first");
            if (n == 0) assertEq(at, a.relay);
            if (n == 1) {
                assertEq(v, IFactoryDirectory.relayFeeExecutor.selector, "then the executor");
                assertEq(at, relay.EXECUTOR());
                assertEq(h, a.execHash);
            }
            ++n;
        }
        assertEq(n, 2, "two entries");
    }

    /// D14: `relayFeeExecutor()` is 0 until the relay router is written, then its `EXECUTOR()`.
    function test_relayFeeExecutor_view() public {
        OpenFactory f = _factory(address(router));
        assertEq(_d(f).relayFeeExecutor(), address(0));
        _call(deployer, address(f), _cd(_only(1)));
        assertEq(_d(f).relayFeeExecutor(), address(0), "another entry written: still 0");
        _call(deployer, address(f), _cd(_only(0)));
        assertEq(_d(f).relayFeeExecutor(), relay.EXECUTOR());
        assertTrue(relay.EXECUTOR() != address(relay));
    }

    // ------------------------------------------------------------------ the other entries' cross-checks (§13.3)

    /// D7: the compliance registry must name the factory's router (`govRouter()`): another router and no router are
    /// refused; on a router-less factory a registry without a router is the one taken.
    function test_complianceRegistry_otherRouterRefused() public {
        OpenFactory f = _factory(address(router));
        ComplianceRegistry other = new ComplianceRegistry(nid(deployer), address(trouter), UID);
        ComplianceRegistry none = new ComplianceRegistry(nid(deployer), address(0), UID);
        bytes memory err = _mismatch(IFactoryDirectory.complianceRegistry.selector);
        _refused(deployer, address(f), _cd(_with(_only(1), 1, address(other), _h(address(other)))), err);
        _refused(deployer, address(f), _cd(_with(_only(1), 1, address(none), _h(address(none)))), err);
        _call(deployer, address(f), _cd(_only(1))); // positive control
        OpenFactory n = _factory(address(0));
        _refused(deployer, address(n), _cd(_only(1)), err);
        _call(deployer, address(n), _cd(_with(_only(1), 1, address(none), _h(address(none)))));
    }

    /// D8: an account factory of another `chainUid` is refused (`ChainUidMismatch`, before its implementation).
    function test_accountFactory_otherChainUidRefused() public {
        OpenFactory f = _factory(address(router));
        SmartKeyAccountFactory b = new SmartKeyAccountFactory(UID_B);
        _refused(deployer, address(f), _cd(_with(_only(2), 2, address(b), _h(address(b)))),
            abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, UID, UID_B));
        _call(deployer, address(f), _cd(_only(2))); // positive control
    }

    /// D11: an account factory whose `IMPLEMENTATION()` is another implementation than the router's is refused; without a
    /// router there is no binding (spec §13.4).
    function test_accountFactory_otherImplementationRefused() public {
        OpenFactory f = _factory(address(router));
        SmartKeyAccountFactory other = new SmartKeyAccountFactory(UID);
        _refused(deployer, address(f), _cd(_with(_only(2), 2, address(other), _h(address(other)))),
            _cloneErr(EnvKit.cloneHash(impl), EnvKit.cloneHash(other.IMPLEMENTATION())));
        _call(deployer, address(f), _cd(_only(2))); // positive control
        OpenFactory n = _factory(address(0));
        _call(deployer, address(n), _cd(_with(_only(2), 2, address(other), _h(address(other)))));
    }

    // ------------------------------------------------------------------ a derived admin (§13.3: relayable)

    /// A derived admin writes through the real router's `mtxSetChainEntries`: round 3r T7 moved the test, with a real UA
    /// registry that verifies the derived signature, to `test/governance/GovRouterAdmin.t.sol`
    /// (`test_directory_derivedAdminWritesThroughRouter`).

    // ------------------------------------------------------------------ the views (§13.6)

    /// D5: every view 0 until written (`uaRegistry()` the router's `registry()` from `configureChain`, 0 without a router),
    /// `directory()` equal to the named views before and after.
    function test_views_zeroUntilWritten_directoryEqualsViews() public {
        OpenFactory n = _factory(address(0));
        _eqViews(n, IFactoryDirectory.Directory(address(0), address(0), address(0), address(0), address(0), address(0),
            address(0)));
        OpenFactory f = _factory(address(router));
        _eqViews(f, IFactoryDirectory.Directory(address(ureg), address(router), address(0), address(0), address(0), address(0),
            address(0)));
        _call(deployer, address(f), _cd(_all()));
        _eqViews(f, IFactoryDirectory.Directory(address(ureg), address(router), address(relay), relay.EXECUTOR(), address(creg),
            address(skaf), address(zs)));
    }

    function _eqViews(OpenFactory f, IFactoryDirectory.Directory memory want) internal view {
        IFactoryDirectory d = _d(f);
        IFactoryDirectory.Directory memory got = d.directory();
        assertEq(abi.encode(got), abi.encode(want), "directory()");
        assertEq(d.uaRegistry(), want.uaRegistry);
        assertEq(d.govRouter(), want.govRouter);
        assertEq(d.relayFeeRouter(), want.relayFeeRouter);
        assertEq(d.relayFeeExecutor(), want.relayFeeExecutor);
        assertEq(d.complianceRegistry(), want.complianceRegistry);
        assertEq(d.smartKeyAccountFactory(), want.smartKeyAccountFactory);
        assertEq(d.zetherStatements(), want.zetherStatements);
    }

    // ------------------------------------------------------------------ the env publishes, bound to the router (§13.4)

    function _env(address reg, address ska) internal pure returns (IFactoryToken.Env memory e) {
        (e.registry, e.smartKeyAccountImpl) = (reg, ska);
    }

    /// `p` 0 `publishTokenEnv`, 1 `publishDexEnv`, 2 `publishClassEnv`, of env version `v`.
    function _pub(uint256 p, uint16 v, IFactoryToken.Env memory e) internal pure returns (bytes memory) {
        if (p == 0) return abi.encodeCall(OpenFactory.publishTokenEnv, (IOpenFactory.TokenKind.NORMAL, v, UID, e));
        if (p == 1) return abi.encodeCall(OpenFactory.publishDexEnv, (v, UID, e));
        return abi.encodeCall(OpenFactory.publishClassEnv, (CLS, 0, v, UID, e));
    }

    /// D4, D10 (publish entry `p`): another registry `EnvRegistryMismatch`, another implementation
    /// `EnvSmartKeyAccountMismatch`; 0 and the router's pass; without a router both are free.
    function _bound(uint256 p) internal {
        OpenFactory f = _factory(address(router));
        StubUARegistry other = new StubUARegistry(UID);
        _refused(deployer, address(f), _pub(p, 1, _env(address(other), address(0))),
            abi.encodeWithSelector(IFactoryDirectory.EnvRegistryMismatch.selector, address(ureg), address(other)));
        _refused(deployer, address(f), _pub(p, 1, _env(address(0), address(0xBEEF))),
            abi.encodeWithSelector(IFactoryDirectory.EnvSmartKeyAccountMismatch.selector, EnvKit.cloneHash(impl), address(0xBEEF)));
        _refused(deployer, address(f), _pub(p, 1, _env(address(ureg), address(0xBEEF))),
            abi.encodeWithSelector(IFactoryDirectory.EnvSmartKeyAccountMismatch.selector, EnvKit.cloneHash(impl), address(0xBEEF)));
        _call(deployer, address(f), _pub(p, 1, _env(address(0), address(0))));
        _call(deployer, address(f), _pub(p, 2, _env(address(ureg), impl)));
        _call(deployer, address(f), _pub(p, 3, _env(address(ureg), address(0))));
        _call(deployer, address(f), _pub(p, 4, _env(address(0), impl)));
        OpenFactory n = _factory(address(0));
        _call(deployer, address(n), _pub(p, 1, _env(address(other), address(0xBEEF))));
    }

    function test_publishEnv_boundToTheRouter() public {
        _bound(0);
    }

    function test_publishDexEnv_boundToTheRouter() public {
        _bound(1);
    }

    function test_publishClassEnv_boundToTheRouter() public {
        _bound(2);
    }

    /// `MAX_LIBS` (spec §5.4, the node's decode bound): 32 libraries pass, 33 are `EnvInvalid`.
    function test_publishEnv_maxLibs() public {
        OpenFactory f = _factory(address(router));
        for (uint256 n = 32; n <= 33; ++n) {
            IFactoryToken.Env memory e;
            (e.libs, e.libCodeHashes) = (new address[](n), new bytes32[](n));
            for (uint256 i; i < n; ++i) (e.libs[i], e.libCodeHashes[i]) = (address(uint160(0x1000 + i)), keccak256(abi.encode(i)));
            if (n == 32) _call(deployer, address(f), _pub(0, 1, e));
            else _refused(deployer, address(f), _pub(0, 2, e), abi.encodeWithSelector(IOpenFactory.EnvInvalid.selector));
        }
    }

    // ------------------------------------------------------------------ gas (§13.8)

    /// `configureChain` with a router and `setChainEntries` of the four entries, each its own transaction (`isolate`).
    function test_gas_configureChainAndEntries() public {
        OpenFactory n = new OpenFactory(nid(deployer));
        OpenFactory f = new OpenFactory(nid(deployer));
        EnvKit.genesis(UID);
        _call(deployer, address(n), _ccd(address(0), bytes32(0)));
        Vm.Gas memory g0 = vm.lastCallGas();
        _call(deployer, address(f), _ccd(address(router), _h(address(router))));
        Vm.Gas memory g1 = vm.lastCallGas();
        _call(deployer, address(f), _cd(_all()));
        Vm.Gas memory g2 = vm.lastCallGas();
        console2.log("DIRGAS configureChain without a router: regular / state", g0.gasTotalUsed, uint256(int256(g0.gasStateUsed)));
        console2.log("DIRGAS configureChain with a router: regular / state", g1.gasTotalUsed, uint256(int256(g1.gasStateUsed)));
        console2.log("DIRGAS setChainEntries, four entries: regular / state", g2.gasTotalUsed, uint256(int256(g2.gasStateUsed)));
    }
}
