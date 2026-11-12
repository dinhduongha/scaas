// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;


import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {MockERC20, StubUARegistry} from "../helpers/Mocks.sol";
import {Catalogue, plainEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";

/// EIP-2935's history contract stand-in: answers `h` for block 0, or reverts, or a short word.
contract HistoryStub {
    bytes32 public h;
    uint8 public mode; // 0 answer, 1 revert, 2 a 31-byte answer

    function set(bytes32 h_, uint8 m) external { (h, mode) = (h_, m); }

    fallback(bytes calldata) external returns (bytes memory) {
        if (mode == 1) revert("history");
        if (mode == 2) return abi.encodePacked(bytes31(h));
        return abi.encode(h);
    }
}

/// Plan T71 (chain-neutral spec §3.1, §4, §6.1; CTR-TOK-29): `OpenFactory(registrar)`, `configureChain` once with the
/// genesis and reference-block checks, `ChainNotConfigured` before it, CREATE3 creation (`predictAddress`, the proxy salt
/// check, `InstanceNotCreated`), the clone's code `proxy ‖ ChainEnv`, the creator as a `bytes32` id in the events.
/// **UNAUDITED.**
contract ChainNeutralFactoryTest is Test {
    address constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    address registrar = address(0xF00D);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    OpenFactory f;
    StubUARegistry ureg;
    GovernanceRouter router;
    NormalToken normalImpl;

    IOpenFactory.TokenKind constant NORMAL = IOpenFactory.TokenKind.NORMAL;

    function setUp() public {
        vm.warp(1_800_000_000);
        ureg = new StubUARegistry(UID_);
        // the router and its registry name one SmartKeyAccount implementation, 0xBEEF, the DEX env's (spec §13.4)
        ureg.setSmartKeyCloneHash(EnvKit.cloneHash(address(0xBEEF)));
        router = new GovernanceRouter(UID_, address(ureg), address(0xBEEF), false);
        f = EnvKit.factory(registrar, UID_, 0, address(router));
        normalImpl = NormalToken(Catalogue.plain(f, NORMAL, 1, type(NormalToken).creationCode, address(ureg), address(0xBEEF),
            false));
    }

    function _cfg(address holder) internal pure returns (bytes memory) {
        return abi.encode(normalInit("N", "N", 0, 1000, holder, address(0)));
    }

    function _configure(OpenFactory g, bytes32 uid, uint256 refBlock, bytes32 refHash) internal {
        vm.prank(registrar);
        g.configureChain(uid, 0, address(0), bytes32(0), refBlock, refHash);
    }

    // ------------------------------------------------------------------ configureChain

    function test_configureChain_onceAndAdminOnly() public {
        OpenFactory g = new OpenFactory(nid(registrar));
        assertEq(g.admin(), nid(registrar));
        assertEq(g.chainUid(), bytes32(0));
        EnvKit.genesis(UID_);
        vm.prank(alice);
        vm.expectPartialRevert(IAdmin.NotAdmin.selector);
        g.configureChain(UID_, 0, address(0), bytes32(0), 0, bytes32(0));
        vm.etch(registrar, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, registrar));
        g.configureChain(UID_, 0, address(0), bytes32(0), 0, bytes32(0));
        vm.etch(registrar, "");
        vm.expectEmit(true, false, false, true, address(g));
        emit IOpenFactory.ChainConfigured(UID_, 10 minutes, address(router));
        vm.prank(registrar);
        g.configureChain(UID_, 10 minutes, address(router), address(router).codehash, 0, bytes32(0));
        assertEq(g.chainUid(), UID_);
        assertEq(g.noticePeriod(), 10 minutes);
        assertEq(g.govRouter(), address(router));
        vm.prank(registrar);
        vm.expectRevert(IOpenFactory.ChainAlreadyConfigured.selector);
        g.configureChain(UID_, 0, address(0), bytes32(0), 0, bytes32(0));
    }

    function test_configureChain_zeroAndLongNoticeRefused() public {
        OpenFactory g = new OpenFactory(nid(registrar));
        EnvKit.genesis(UID_);
        vm.startPrank(registrar);
        vm.expectRevert(IOpenFactory.ChainUidZero.selector);
        g.configureChain(bytes32(0), 0, address(0), bytes32(0), 0, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.NoticePeriodTooLong.selector, 30 days + 1));
        g.configureChain(UID_, 30 days + 1, address(0), bytes32(0), 0, bytes32(0));
        g.configureChain(UID_, 30 days, address(0), bytes32(0), 0, bytes32(0)); // positive control
        vm.stopPrank();
    }

    /// Within 256 blocks of genesis `BLOCKHASH(0)` proves it: another value is refused.
    function test_configureChain_genesisProvableByBlockhash() public {
        OpenFactory g = new OpenFactory(nid(registrar));
        vm.roll(200);
        vm.setBlockhash(0, UID_);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidNotGenesis.selector, keccak256("other"), UID_));
        g.configureChain(keccak256("other"), 0, address(0), bytes32(0), 0, bytes32(0));
        _configure(g, UID_, 0, bytes32(0));
        assertEq(g.chainUid(), UID_);
    }

    /// Past 256 blocks, EIP-2935 (raw 32-byte input): an answer must match; a revert, a short answer or no contract is
    /// nothing to compare (Fable P3-2).
    function test_configureChain_genesisByHistory() public {
        vm.roll(1000);
        HistoryStub hs = new HistoryStub();
        vm.etch(HISTORY, address(hs).code);
        HistoryStub(HISTORY).set(UID_, 0);
        OpenFactory g = new OpenFactory(nid(registrar));
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidNotGenesis.selector, keccak256("other"), UID_));
        g.configureChain(keccak256("other"), 0, address(0), bytes32(0), 0, bytes32(0));
        for (uint8 m = 1; m <= 2; ++m) {
            HistoryStub(HISTORY).set(UID_, m);
            OpenFactory gm = new OpenFactory(nid(registrar));
            _configure(gm, keccak256("other"), 0, bytes32(0)); // nothing to compare: accepted
            assertEq(gm.chainUid(), keccak256("other"));
        }
        vm.etch(HISTORY, "");
        OpenFactory g3 = new OpenFactory(nid(registrar));
        _configure(g3, keccak256("other"), 0, bytes32(0)); // no history contract: nothing to compare
        vm.etch(HISTORY, address(hs).code);
        HistoryStub(HISTORY).set(UID_, 0);
        _configure(g, UID_, 0, bytes32(0)); // positive control: the matching answer
    }

    /// A supplied reference block must have that hash on this chain (Fable P1-1); no answer is a mismatch.
    function test_configureChain_referenceBlock() public {
        vm.roll(300); // past BLOCKHASH(0): EIP-2935 proves the genesis here
        EnvKit.genesis(UID_);
        vm.setBlockhash(290, keccak256("block 290"));
        OpenFactory g = new OpenFactory(nid(registrar));
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.RefBlockMismatch.selector, 290, keccak256("a sibling"),
            keccak256("block 290")));
        g.configureChain(UID_, 0, address(0), bytes32(0), 290, keccak256("a sibling"));
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.RefBlockMismatch.selector, 400, bytes32(0), bytes32(0)));
        g.configureChain(UID_, 0, address(0), bytes32(0), 400, bytes32(0)); // a future block: no answer, even for refHash 0
        _configure(g, UID_, 290, keccak256("block 290"));
        assertEq(g.chainUid(), UID_);
    }

    function test_configureChain_routerOfAnotherChainRefused() public {
        OpenFactory g = new OpenFactory(nid(registrar));
        EnvKit.genesis(UID_);
        GovernanceRouter other = new GovernanceRouter(keccak256("other"), address(0), address(0), false);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("other")));
        g.configureChain(UID_, 0, address(other), address(other).codehash, 0, bytes32(0));
        vm.prank(registrar);
        g.configureChain(UID_, 0, address(router), address(router).codehash, 0, bytes32(0));
        assertEq(g.govRouter(), address(router));
    }

    /// Nothing is published, deployed or created before `configureChain`; reads answer.
    function test_notConfigured_everyEntryRefused() public {
        OpenFactory g = new OpenFactory(nid(registrar));
        IFactoryToken.Env memory e = plainEnv(address(g), address(0), UID_, address(0), false);
        bytes memory code = type(NormalToken).creationCode;
        vm.startPrank(registrar);
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.publishTokenEnv(NORMAL, 1, e);
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.publishDexEnv(1, e);
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.deployTokenImplementation(NORMAL, 1, 1, code, "", EnvKit.uidOf(address(g)));
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.deployDexImplementation(1, 1, type(SCaaSDex).creationCode, "", EnvKit.uidOf(address(g)));
        vm.stopPrank();
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.createToken(NORMAL, 1, _cfg(alice), "s");
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.createTokenUnregistered(NORMAL, address(normalImpl), _cfg(alice), "s");
        vm.expectRevert(IOpenFactory.ChainNotConfigured.selector);
        g.createDex(1, "", "s");
        assertEq(g.latestTokenEnvVersion(NORMAL), 0, "views answer");
        EnvKit.configure(g, UID_, 0, address(0)); // positive control
        vm.prank(registrar);
        g.publishTokenEnv(NORMAL, 1, e);
    }

    // ------------------------------------------------------------------ CREATE3 (spec §4)

    /// The spec's formula, written out here: `s` over the creator, class, kind and salt; the proxy by CREATE2; the
    /// instance at the proxy's nonce 1.
    function _expect(address factory_, bytes32 creatorId, uint16 cls, uint16 kind, bytes32 salt)
        internal pure returns (address proxy, address instance)
    {
        bytes32 s = keccak256(abi.encode(creatorId, cls, kind, salt));
        proxy = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory_, s,
            keccak256(hex"67363d3d37363d34f03d5260086018f3"))))));
        instance = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    function test_create3_predictAddressIsTheCreation() public {
        (address proxy, address want) = _expect(address(f), nid(alice), 1, 0, "s");
        assertEq(f.predictAddress(nid(alice), 1, 0, "s"), want);
        vm.prank(alice);
        address t = f.createToken(NORMAL, 1, _cfg(alice), "s");
        assertEq(t, want, "the instance");
        assertEq(proxy.code, hex"363d3d37363d34f0", "the proxy stays");
        // every input of `s` moves it
        assertTrue(f.predictAddress(nid(bob), 1, 0, "s") != want, "creator");
        assertTrue(f.predictAddress(nid(alice), 2, 0, "s") != want, "class");
        assertTrue(f.predictAddress(nid(alice), 1, 1, "s") != want, "kind");
        assertTrue(f.predictAddress(nid(alice), 1, 0, "t") != want, "salt");
        (, address d) = _expect(address(f), nid(alice), 2, 0, "s");
        assertEq(f.predictAddress(nid(alice), 2, 0, "s"), d, "the DEX path's");
    }

    /// The version, the implementation and the env are not in the address: another release of the kind, an
    /// unregistered implementation, on another env, meets the same address (`SaltAlreadyUsed`), also across
    /// `createToken` and `createTokenUnregistered`.
    function test_create3_versionImplementationEnvNotInTheAddress() public {
        // env 2 differs by its registry: none (the router binds a named registry to its own, spec §13.4), release 2
        Catalogue.plain(f, NORMAL, 2, type(NormalToken).creationCode, address(0), address(0), false);
        vm.prank(alice);
        address t = f.createToken(NORMAL, 1, _cfg(alice), "same");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createToken(NORMAL, 2, _cfg(alice), "same");
        NormalToken mine = new NormalToken(address(f), Catalogue.argsOn(f, NORMAL, f.latestTokenEnvVersion(NORMAL), "")); // pinned
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createTokenUnregistered(NORMAL, address(mine), _cfg(alice), "same");
        vm.prank(alice);
        address t2 = f.createToken(NORMAL, 2, _cfg(alice), "other"); // positive control: another salt
        assertEq(NormalToken(t2).registry(), address(0), "release 2 on env 2");
        assertEq(NormalToken(t).registry(), address(ureg), "release 1 on env 1");
    }

    /// The proxy exists exactly when `s` was used: a proxy without a record is refused before any CREATE2.
    function test_create3_saltCheckedOnTheProxy() public {
        (address proxy, address want) = _expect(address(f), nid(alice), 1, 0, "p");
        vm.etch(proxy, hex"00");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, want));
        f.createToken(NORMAL, 1, _cfg(alice), "p");
        vm.etch(proxy, "");
        vm.prank(alice);
        assertEq(f.createToken(NORMAL, 1, _cfg(alice), "p"), want); // positive control
    }

    /// A `CREATE` that fails inside the proxy answers success there: the factory checks the instance's code.
    function test_create3_instanceNotCreated() public {
        (, address want) = _expect(address(f), nid(alice), 1, 0, "n");
        vm.setNonce(want, 1); // an address collision (EIP-7610): the proxy's CREATE fails
        vm.prank(alice);
        vm.expectRevert(IOpenFactory.InstanceNotCreated.selector);
        f.createToken(NORMAL, 1, _cfg(alice), "n");
        vm.prank(alice);
        f.createToken(NORMAL, 1, _cfg(alice), "m"); // positive control
    }

    // ------------------------------------------------------------------ the clone's env (spec §2.1)

    /// The instance's code is the EIP-1167 proxy and the env the factory composed: its own `chain_uid` and router, the
    /// release's published env; `chainEnv()` decodes it.
    function test_cloneCode_isProxyAndTheFactorysEnv() public {
        vm.prank(alice);
        address t = f.createToken(NORMAL, 1, _cfg(alice), "c");
        IFactoryToken.ChainEnv memory want = EnvKit.env(UID_, address(ureg), address(0xBEEF), false, address(router));
        assertEq(t.code, abi.encodePacked(hex"363d3d373d3d3d363d73", address(normalImpl), hex"5af43d82803e903d91602b57fd5bf3",
            UID_, address(ureg), address(router), address(0xBEEF), false, uint8(0), uint8(0)), "proxy || env, byte for byte");
        assertEq(t.code.length, 45 + 95, "a plain kind's env: 95 B");
        assertEq(keccak256(abi.encode(NormalToken(t).chainEnv())), keccak256(abi.encode(want)), "chainEnv()");
        assertEq(keccak256(abi.encode(normalImpl.chainEnv())), keccak256(abi.encode(EnvKit.env(0, address(0), address(0), false))),
            "the implementation: all zero");
        assertEq(NormalToken(t).chainUid(), UID_);
        assertEq(normalImpl.chainUid(), bytes32(0));
    }

    /// The DEX path: CREATE3 under class 2, kind 0; its env the DEX env's and the factory's.
    function test_createDex_create3AndEnv() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0xBEEF));
        (, address want) = _expect(address(f), nid(alice), 2, 0, "d");
        vm.recordLogs();
        vm.prank(alice);
        address d = f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(alice), 0, address(0xD7), false, 0, address(0))), "d");
        assertEq(d, want);
        assertEq(SCaaSDex(d).chainUid(), UID_);
        assertEq(SCaaSDex(d).SMART_KEY_ACCOUNT_IMPL(), address(0xBEEF));
        assertEq(SCaaSDex(d).GOV_ROUTER(), address(router));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory l = logs[logs.length - 1];
        assertEq(l.topics[0], IOpenFactory.DexCreated.selector);
        assertEq(l.topics[0], 0x7333afd911188665cfba5b0921a9d82a15bf753c9c60a1fdf384df1f502670bf, "DexCreated: no owner (3r R1)");
        assertEq(l.topics[2], nid(alice), "DexCreated: bytes32 creatorId");
    }

    /// `TokenCreated`'s creator is the `bytes32` id (spec §6.3: the topic of a native creator is its padded address).
    function test_tokenCreated_creatorId() public {
        vm.recordLogs();
        vm.prank(bob);
        address t = f.createToken(NORMAL, 1, _cfg(bob), "e");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory l = logs[logs.length - 1];
        assertEq(l.topics[0], IOpenFactory.TokenCreated.selector);
        assertEq(l.topics[0], keccak256(
            "TokenCreated(address,bytes32,uint8,uint64,address,uint256,uint256,address[])"), "the new ABI (3r R1: no owner)");
        assertEq(l.topics[0], 0x0ed419464185dced9c79d21177ebc4059e7d04c325b97fd771d3f3e290c95dae);
        assertEq(address(uint160(uint256(l.topics[1]))), t);
        assertEq(l.topics[2], nid(bob));
        assertEq(f.creatorOf(t), bob);
        assertEq(NormalToken(t).creator(), bob);
    }

    /// The wrapper index is keyed by the creator's id (spec §6.3: new selectors).
    function test_getWrapper_byCreatorId() public {
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("W", "W", 6, 1);
        c.lockedFeatures = 1;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        vm.prank(alice);
        address w = f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w");
        assertEq(f.getWrapper(nid(alice), address(usd)), w);
        assertEq(f.getWrapperCount(nid(alice), address(usd)), 1);
        assertEq(f.getWrapperAt(nid(alice), address(usd), 0), w);
        assertEq(f.getWrapper(nid(bob), address(usd)), address(0));
        assertEq(f.getWrapper.selector, bytes4(keccak256("getWrapper(bytes32,address)")));
    }

    // ------------------------------------------------------------------ the directory on two chains (spec §13.9)

    /// One factory address on two chains, each with its own directory: its router, UA registry, account factory and
    /// compliance registry (each takes the chain's `chain_uid`); the relay pair, with no argument, has one address on both.
    function test_directory_twoChainsOneAddressOwnEntries() public {
        bytes32 uidB = keccak256("chain B");
        uint256 snap = vm.snapshotState();
        (OpenFactory ga, IOpenFactory.Directory memory a) = _chainWithEntries(UID_);
        vm.revertToState(snap);
        (OpenFactory gb, IOpenFactory.Directory memory b) = _chainWithEntries(uidB);
        assertEq(address(ga), address(gb), "one factory address");
        assertEq(a.relayFeeRouter, b.relayFeeRouter, "the relay pair: one address");
        assertEq(a.relayFeeExecutor, b.relayFeeExecutor);
        assertTrue(a.govRouter != b.govRouter && a.uaRegistry != b.uaRegistry, "each chain its router and registry");
        assertTrue(a.smartKeyAccountFactory != b.smartKeyAccountFactory && a.complianceRegistry != b.complianceRegistry,
            "each chain its account factory and compliance registry");
        assertEq(gb.chainUid(), uidB);
        assertEq(SmartKeyAccountFactory(b.smartKeyAccountFactory).chainUid(), uidB);
        assertEq(ComplianceRegistry(b.complianceRegistry).govRouter(), b.govRouter);
    }

    /// Chain `uid`'s shared contracts by CREATE2 (salt 0, so an argument moves the address), the factory, `configureChain`
    /// with the router and `setChainEntries`.
    function _chainWithEntries(bytes32 uid) internal returns (OpenFactory g, IOpenFactory.Directory memory d) {
        EnvKit.genesis(uid);
        SmartKeyAccountFactory skaf = new SmartKeyAccountFactory{salt: 0}(uid);
        StubUARegistry reg = new StubUARegistry{salt: 0}(uid);
        reg.setSmartKeyCloneHash(EnvKit.cloneHash(skaf.IMPLEMENTATION()));
        GovernanceRouter r = new GovernanceRouter{salt: 0}(uid, address(reg), skaf.IMPLEMENTATION(), false);
        RelayFeeRouter relay = new RelayFeeRouter{salt: 0}();
        ComplianceRegistry c = new ComplianceRegistry{salt: 0}(nid(registrar), address(r));
        g = new OpenFactory{salt: 0}(nid(registrar));
        vm.startPrank(registrar);
        g.configureChain(uid, 0, address(r), address(r).codehash, 0, bytes32(0));
        g.setChainEntries(address(relay), address(relay).codehash, relay.EXECUTOR().codehash, address(c), address(c).codehash,
            address(skaf), address(skaf).codehash, address(0), bytes32(0));
        vm.stopPrank();
        d = g.directory();
        assertEq(d.uaRegistry, address(reg));
        assertEq(d.govRouter, address(r));
    }
}
