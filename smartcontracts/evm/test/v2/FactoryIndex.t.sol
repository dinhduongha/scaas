// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../src/regulated/WrappedZetherRegulatedToken.sol";
import {NormalPqzRegulatedToken} from "../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {MockERC20, StubUARegistry} from "../helpers/Mocks.sol";
import {Catalogue, plainEnv, regArgs, pqzEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";

/// A contract id for the regulated contract-only bits (`_check` reads its code only).
contract IxHolder {}

/// An unregistered implementation for the index's negatives (factory index spec §7): answers what the factory reads, its
/// `admin()` whatever the test set (a claim the factory never reads, 3r R1), optionally reverting, and its `initialize`
/// optionally creating a nested token.
contract IndexImpl {
    address immutable F;
    bytes32 immutable U;
    bytes32 public adminClaim;
    bool public adminReverts;
    address public nestedImpl; // when set, `initialize` creates one unregistered token of it first

    constructor(address f_, bytes32 u_) { (F, U) = (f_, u_); }

    function set(bytes32 a, bool r, address nested) external { (adminClaim, adminReverts, nestedImpl) = (a, r, nested); }

    function kind() external pure returns (uint8) { return 0; }
    function factory() external view returns (address) { return F; }
    function modules() external pure returns (address[] memory) {} // T66b: no body module
    function chainUid() external view returns (bytes32) { return U; }
    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}
    function features() external pure returns (uint256) { return 0; }
    function lockedFeatures() external pure returns (uint256) { return 0; }
    function underlyings() external pure returns (address[] memory) {}

    /// Read through the implementation: a clone has no storage of its own for these.
    function admin() external view returns (bytes32) {
        if (IndexImpl(_impl()).adminReverts()) revert("admin reverts");
        return IndexImpl(_impl()).adminClaim();
    }

    function initialize(bytes32, uint64, bytes calldata) external {
        address n = IndexImpl(_impl()).nestedImpl();
        if (n != address(0)) IOpenFactory(F).createTokenUnregistered(IOpenFactory.TokenKind.NORMAL, n, "", "nested");
    }

    /// The EIP-1167 clone's implementation (bytes 10..30 of its code), or this contract itself.
    function _impl() internal view returns (address i) {
        if (!ChainEnvCode.isClone()) return address(this);
        bytes memory c = address(this).code;
        assembly ("memory-safe") { i := shr(96, mload(add(c, 42))) }
    }
}

/// The checks every index test shares: `infoOf` field by field (seven words, no owner: round 3r R1), and `t` the last
/// entry of the class's two lists.
abstract contract IndexAsserts is Test {
    function _assertIndexed(OpenFactory f, address t, bytes32 creatorId, uint16 cls, uint16 kind, uint64 version)
        internal view
    {
        assertEq(_rawInfo(f, t).length, 7 * 32, "Created: seven words, no owner (3r R1)");
        IOpenFactory.Created memory c = f.infoOf(t);
        assertEq(c.addr, t, "addr");
        assertEq(c.creatorId, creatorId, "creatorId");
        assertEq(c.contractClass, cls, "class");
        assertEq(c.kind, kind, "kind");
        assertEq(c.version, version, "version");
        assertEq(c.createdBlock, block.number, "createdBlock");
        assertEq(c.createdAt, block.timestamp, "createdAt");
        (IOpenFactory.Created[] memory p, uint256 total) = f.contractsPage(cls, 0, f.MAX_PAGE());
        assertGt(total, 0, "all: total");
        assertEq(p[p.length - 1].addr, t, "all: last");
        (p, total) = f.contractsOfCreator(creatorId, cls, 0, f.MAX_PAGE());
        assertEq(p[p.length - 1].addr, t, "by creator: last");
        assertEq(keccak256(abi.encode(p[p.length - 1])), keccak256(abi.encode(c)), "by creator: the record");
    }

    /// `infoOf(t)`'s return data as the factory answers it, whatever its shape.
    function _rawInfo(OpenFactory f, address t) internal view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = address(f).staticcall(abi.encodeCall(IOpenFactory.infoOf, (t)));
        assertTrue(ok, "infoOf");
    }

    /// The old views (factory index spec §2.1): their answers exactly as before the record.
    function _assertOldViews(OpenFactory f, address t, address creator, uint8 kind, uint64 version) internal view {
        assertTrue(f.isToken(t), "isToken");
        assertEq(f.isRegisteredToken(t), version != 0, "isRegisteredToken");
        assertEq(f.creatorOf(t), creator, "creatorOf");
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(t);
        assertEq(uint8(k), kind, "versionOf kind");
        assertEq(v, version, "versionOf version");
        assertFalse(f.isDex(t), "isDex");
        assertEq(f.dexVersionOf(t), 0, "dexVersionOf");
    }

    /// The new slots (`0` before, non-zero after) the factory wrote between `startStateDiffRecording` and now.
    function _newSlots(address f) internal returns (uint256 n) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        bytes32[] memory seen = new bytes32[](64);
        uint256 m;
        for (uint256 i; i < acc.length; ++i) {
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                VmSafe.StorageAccess memory s = acc[i].storageAccesses[j];
                if (s.account != f || !s.isWrite || s.reverted || s.previousValue != 0 || s.newValue == 0) continue;
                bool dup;
                for (uint256 k; k < m; ++k) if (seen[k] == s.slot) dup = true;
                if (!dup) seen[m++] = s.slot;
            }
        }
        return m;
    }
}

/// Plan T67 (factory index spec §2, §7): the record, the per-class lists, the paged views, on the plain kinds 0, 1, 8, 9 and
/// the DEX; the old views keep their answers; the creator authenticated. Round 3r R1 (spec 2026-11-10-admin-not-owner.md
/// §3, CTR-GOV-23): the factory keeps no owner information and reads no admin of what it creates.
contract FactoryIndexTest is IndexAsserts {
    OpenFactory f;
    address registrar = address(0xF00D);
    StubUARegistry ureg;
    MockERC20 usd;
    address issuer;
    address compliance;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address relayer = address(0xBEEF);
    bytes32 constant DERIVED = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;

    uint16 constant TOKEN = 1;
    uint16 constant DEX = 2;
    IOpenFactory.TokenKind constant NORMAL = IOpenFactory.TokenKind.NORMAL;
    IOpenFactory.TokenKind constant WRAPPED = IOpenFactory.TokenKind.WRAPPED;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.roll(77);
        f = EnvKit.factory(registrar, UID_, 0);
        ureg = new StubUARegistry(UID_);
        Catalogue.plain(f, NORMAL, 1, type(NormalToken).creationCode, address(ureg), address(0), false);
        Catalogue.plain(f, WRAPPED, 1, type(WrappedToken).creationCode, address(ureg), address(0), false);
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_REGULATED, 1,
            plainEnv(address(f), address(0), UID_, address(ureg), false), type(NormalRegulatedToken).creationCode, regArgs());
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_REGULATED, 1,
            plainEnv(address(f), address(0), UID_, address(ureg), false), type(WrappedRegulatedToken).creationCode, regArgs());
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        vm.startPrank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_REGULATED, true);
        vm.stopPrank();
        usd = new MockERC20("USD", "USD", 6);
        (issuer, compliance) = (address(new IxHolder()), address(new IxHolder()));
    }

    // ------------------------------------------------------------------ configs

    function _normal(bytes32 admin_) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = normalInit("N", "N", 0, 1000, alice, address(0));
        c.admin = admin_;
    }

    function _wrapped(bytes32 admin_) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals) = ("W", "W", 6);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.admin = admin_;
        if (admin_ == 0) c.lockedFeatures = c.features;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
    }

    function _regulated(IFactoryToken.TokenConfig memory c) internal view returns (IFactoryToken.TokenConfig memory) {
        c.features |= (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
        c.lockedFeatures = 0;
        c.grantDelay = 1 days;
        (c.roles.issuer, c.roles.compliance) = (nid(issuer), nid(compliance));
        c.reg.termsHash = keccak256("terms");
        return c;
    }

    function _dexCfg(bytes32 admin_) internal pure returns (bytes memory) {
        return abi.encode(ISCaaSDex.DexConfig(admin_, 0, address(0xD7), false, 0, address(0)));
    }

    function _token(address creator, IOpenFactory.TokenKind k, IFactoryToken.TokenConfig memory c, bytes32 salt)
        internal returns (address t)
    {
        vm.prank(creator);
        t = f.createToken(k, 1, abi.encode(c), salt);
    }

    function _impl() internal returns (IndexImpl) {
        return new IndexImpl(address(f), UID_);
    }

    // ------------------------------------------------------------------ every class and kind

    function test_index_everyKind_0() public {
        address t = _token(bob, NORMAL, _normal(nid(alice)), "k0");
        _assertIndexed(f, t, nid(bob), TOKEN, 0, 1);
        _assertOldViews(f, t, bob, 0, 1);
    }

    function test_index_everyKind_1() public {
        address t = _token(bob, WRAPPED, _wrapped(nid(alice)), "k1");
        _assertIndexed(f, t, nid(bob), TOKEN, 1, 1);
        _assertOldViews(f, t, bob, 1, 1);
        assertEq(f.getWrapper(nid(bob), address(usd)), t, "the leg index (by creatorId since T71)");
    }

    function test_index_everyKind_8() public {
        address t = _token(bob, IOpenFactory.TokenKind.NORMAL_REGULATED, _regulated(_normal(nid(alice))), "k8");
        _assertIndexed(f, t, nid(bob), TOKEN, 8, 1);
        _assertOldViews(f, t, bob, 8, 1);
    }

    function test_index_everyKind_9() public {
        address t = _token(bob, IOpenFactory.TokenKind.WRAPPED_REGULATED, _regulated(_wrapped(nid(alice))), "k9");
        _assertIndexed(f, t, nid(bob), TOKEN, 9, 1);
        _assertOldViews(f, t, bob, 9, 1);
    }

    function test_index_dex() public {
        vm.prank(bob);
        address d = f.createDex(1, _dexCfg(nid(alice)), "d");
        _assertIndexed(f, d, nid(bob), DEX, 0, 1);
        assertTrue(f.isDex(d));
        assertEq(f.dexVersionOf(d), 1);
        assertFalse(f.isToken(d), "a DEX is not a token");
        assertFalse(f.isRegisteredToken(d));
        assertEq(f.creatorOf(d), address(0), "creatorOf answers tokens only");
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(d);
        assertEq(uint8(k), 0);
        assertEq(v, 0, "versionOf answers tokens only");
        (, uint256 n) = f.contractsPage(TOKEN, 0, 0);
        assertEq(n, 0, "no token listed");
    }

    function test_index_unregisteredVersionZero() public {
        IndexImpl impl = _impl();
        impl.set(nid(alice), false, address(0));
        vm.prank(bob);
        address t = f.createTokenUnregistered(NORMAL, address(impl), "", "u");
        _assertIndexed(f, t, nid(bob), TOKEN, 0, 0);
        _assertOldViews(f, t, bob, 0, 0);
    }

    function test_index_oldViewsUnchanged() public {
        address t = _token(bob, NORMAL, _normal(0), "o");
        _assertOldViews(f, t, bob, 0, 1);
        address none = address(0xD00D);
        assertFalse(f.isToken(none));
        assertFalse(f.isRegisteredToken(none));
        assertEq(f.creatorOf(none), address(0));
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(none);
        assertEq(uint8(k), 0);
        assertEq(v, 0);
        assertFalse(f.isDex(none));
        assertEq(f.dexVersionOf(none), 0);
        IOpenFactory.Created memory c = f.infoOf(none);
        assertEq(c.contractClass, 0, "not made here");
        assertEq(c.addr, address(0));
        assertEq(c.creatorId, 0);
    }

    // ------------------------------------------------------------------ the creator; no admin (3r R1)

    function test_index_relayerIsTheCreator() public {
        address t = _token(relayer, NORMAL, _normal(nid(alice)), "r");
        assertEq(f.infoOf(t).creatorId, nid(relayer), "the submitter is the creator");
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsOfCreator(nid(relayer), TOKEN, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, t, "listed under the relayer");
        (, n) = f.contractsOfCreator(nid(alice), TOKEN, 0, 10);
        assertEq(n, 0, "the admin it names did not create it");
        assertEq(IGovernance(t).admin(), nid(alice), "the admin is the contract's own answer");
    }

    /// `contractsOfOwner` is gone: its selector reverts with no data; `contractsOfCreator` answers (positive control).
    function test_index_noContractsOfOwner() public {
        _token(bob, NORMAL, _normal(nid(alice)), "no");
        bytes4 sel = bytes4(keccak256("contractsOfOwner(bytes32,uint16,uint256,uint256)"));
        assertEq(sel, bytes4(0x9fbde75c));
        (bool ok, bytes memory ret) = address(f).staticcall(abi.encodeWithSelector(sel, nid(alice), TOKEN, 0, 10));
        assertFalse(ok, "contractsOfOwner answers");
        assertEq(ret.length, 0, "no data");
        (ok,) = address(f).staticcall(abi.encodeCall(IOpenFactory.contractsOfCreator, (nid(bob), TOKEN, 0, 10)));
        assertTrue(ok, "contractsOfCreator");
    }

    /// The record names no admin: tokens of one creator in one block naming admin 0, a native id or a derived UA (a
    /// non-native id) have equal records but for `addr`, and every one is in the class list.
    function test_index_recordNamesNoAdmin() public {
        bytes32[3] memory admins = [bytes32(0), nid(alice), DERIVED];
        address[3] memory ts;
        for (uint256 i; i < 3; ++i) {
            ts[i] = _token(bob, NORMAL, _normal(admins[i]), bytes32(i + 1));
            _assertIndexed(f, ts[i], nid(bob), TOKEN, 0, 1);
            assertEq(IGovernance(ts[i]).admin(), admins[i], "the admin is the contract's own answer");
        }
        bytes32 h0 = _noAddr(_rawInfo(f, ts[0]));
        for (uint256 i = 1; i < 3; ++i) assertEq(_noAddr(_rawInfo(f, ts[i])), h0, "the same record but for addr");
        (, uint256 n) = f.contractsPage(TOKEN, 0, 0);
        assertEq(n, 3, "all three in the class list");
    }

    function _noAddr(bytes memory ret) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            mstore(add(ret, 32), 0)
        }
        return keccak256(ret);
    }

    /// The admin moves in the contract; the record does not change (it holds no admin).
    function test_index_adminMovedRecordUnchanged() public {
        address t = _token(bob, NORMAL, _normal(nid(alice)), "m");
        bytes32 before = keccak256(_rawInfo(f, t));
        vm.prank(alice);
        IGovernance(t).transferAdmin(nid(bob));
        vm.prank(bob);
        IGovernance(t).acceptAdmin();
        assertEq(IGovernance(t).admin(), nid(bob), "the contract's own admin moved");
        assertEq(keccak256(_rawInfo(f, t)), before, "the record unchanged");
    }

    /// An unregistered implementation claiming a victim's UA as admin is listed under its creator only, flagged by
    /// version 0; nothing is listed under the UA it claims.
    function test_index_spamClaimListedUnderItsCreatorOnly() public {
        IndexImpl impl = _impl();
        impl.set(nid(alice), false, address(0));
        address spammer = address(0x5BA4);
        vm.prank(spammer);
        address t = f.createTokenUnregistered(NORMAL, address(impl), "", "spam");
        address real = _token(bob, NORMAL, _normal(nid(alice)), "real");
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsOfCreator(nid(spammer), TOKEN, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, t);
        assertEq(p[0].version, 0);
        (, n) = f.contractsOfCreator(nid(alice), TOKEN, 0, 10);
        assertEq(n, 0, "nothing under the claimed UA");
        (p, n) = f.contractsPage(TOKEN, 0, 10);
        assertEq(n, 2);
        assertEq(p[0].addr, t);
        assertEq(p[1].addr, real);
        assertEq(p[1].version, 1);
        assertEq(p[1].creatorId, nid(bob));
    }

    /// A creation nested inside an unregistered implementation's `initialize` is appended first; neither record is corrupted.
    function test_index_nestedCreationOrder() public {
        IndexImpl inner = _impl();
        inner.set(nid(bob), false, address(0));
        IndexImpl outer = _impl();
        outer.set(nid(alice), false, address(inner));
        vm.prank(relayer);
        address t = f.createTokenUnregistered(NORMAL, address(outer), "", "outer");
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 0, 10);
        assertEq(n, 2);
        address nested = p[0].addr;
        assertEq(p[1].addr, t, "the outer one last");
        assertEq(p[0].creatorId, nid(t), "the nested creation's creator is the outer clone");
        assertEq(p[1].creatorId, nid(relayer));
        assertEq(f.creatorOf(nested), t);
        assertEq(f.creatorOf(t), relayer);
    }

    /// The factory reads no admin of what it creates (3r R1, M6): an implementation whose `admin()` reverts is still
    /// created and indexed; its `admin()` still reverts after (positive control: the factory never asked).
    function test_index_adminRevertStillCreates() public {
        IndexImpl impl = _impl();
        impl.set(nid(alice), true, address(0));
        address t = f.createTokenUnregistered(NORMAL, address(impl), "", "rv");
        _assertIndexed(f, t, nid(address(this)), TOKEN, 0, 0);
        vm.expectRevert(bytes("admin reverts"));
        IGovernance(t).admin();
    }

    // ------------------------------------------------------------------ paging

    /// `k` tokens by `bob` for `alice`.
    function _many(uint256 k) internal returns (address[] memory ts) {
        ts = new address[](k);
        for (uint256 i; i < k; ++i) ts[i] = _token(bob, NORMAL, _normal(nid(alice)), bytes32(i + 1));
    }

    function test_index_page_nZero() public {
        _many(3);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 0, 0);
        assertEq(p.length, 0);
        assertEq(n, 3, "n = 0 is the count");
        (p, n) = f.contractsOfCreator(nid(bob), TOKEN, 2, 0);
        assertEq(p.length, 0);
        assertEq(n, 3);
    }

    function test_index_page_maxPage() public {
        assertEq(f.MAX_PAGE(), 100);
        address[] memory ts = _many(101);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 0, 100);
        assertEq(n, 101);
        assertEq(p.length, 100);
        for (uint256 i; i < 100; ++i) assertEq(p[i].addr, ts[i], "creation order, oldest first");
        (p, n) = f.contractsOfCreator(nid(bob), TOKEN, 1, 100);
        assertEq(p.length, 100);
        assertEq(p[0].addr, ts[1]);
        assertEq(p[99].addr, ts[100]);
    }

    function test_index_page_overMax() public {
        _many(1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.PageTooLarge.selector, 101));
        f.contractsPage(TOKEN, 0, 101);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.PageTooLarge.selector, type(uint256).max));
        f.contractsOfCreator(nid(bob), TOKEN, 0, type(uint256).max);
        f.contractsPage(TOKEN, 0, 100); // positive control
    }

    function test_index_page_lastPartial() public {
        address[] memory ts = _many(5);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 3, 10);
        assertEq(n, 5);
        assertEq(p.length, 2);
        assertEq(p[0].addr, ts[3]);
        assertEq(p[1].addr, ts[4]);
        (p,) = f.contractsPage(TOKEN, n - 2, 2); // the newest page: from = total - n
        assertEq(p[0].addr, ts[3]);
        assertEq(p[1].addr, ts[4]);
        (p,) = f.contractsOfCreator(nid(bob), TOKEN, 4, 3);
        assertEq(p.length, 1);
        assertEq(p[0].addr, ts[4]);
    }

    function test_index_page_fromAtTotal() public {
        _many(2);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 2, 10);
        assertEq(p.length, 0);
        assertEq(n, 2);
        (p, n) = f.contractsOfCreator(nid(bob), TOKEN, 2, 10);
        assertEq(p.length, 0);
        assertEq(n, 2);
        (p,) = f.contractsPage(TOKEN, 1, 10); // positive control
        assertEq(p.length, 1);
    }

    function test_index_page_fromPastTotal() public {
        _many(2);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(TOKEN, 3, 10);
        assertEq(p.length, 0);
        assertEq(n, 2);
        (p, n) = f.contractsOfCreator(nid(bob), TOKEN, type(uint256).max, 100);
        assertEq(p.length, 0);
        assertEq(n, 2);
    }

    function test_index_classUnknown_0() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 0));
        f.contractsPage(0, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 0));
        f.contractsOfCreator(nid(bob), 0, 0, 1);
        f.contractsPage(TOKEN, 0, 1); // positive controls: both built classes answer, even empty
        f.contractsPage(DEX, 0, 1);
    }

    function test_index_classUnknown_3() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 3));
        f.contractsPage(3, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 3));
        f.contractsOfCreator(nid(bob), 3, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, type(uint16).max));
        f.contractsPage(type(uint16).max, 0, 1);
    }

    /// One creator with a token and a DEX: each list answers only the class asked.
    function test_index_classFilter() public {
        address t = _token(bob, NORMAL, _normal(nid(alice)), "cf");
        vm.prank(bob);
        address d = f.createDex(1, _dexCfg(nid(alice)), "cf");
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsOfCreator(nid(bob), TOKEN, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, t);
        assertEq(p[0].contractClass, TOKEN);
        (p, n) = f.contractsOfCreator(nid(bob), DEX, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, d);
        assertEq(p[0].contractClass, DEX);
        (p, n) = f.contractsPage(TOKEN, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, t);
    }

    function test_index_saltAlreadyUsed() public {
        address t = _token(bob, NORMAL, _normal(nid(alice)), "s");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, t));
        f.createToken(NORMAL, 1, abi.encode(_normal(nid(alice))), "s");
        vm.prank(bob);
        address d = f.createDex(1, _dexCfg(nid(alice)), "s");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, d));
        f.createDex(1, _dexCfg(nid(alice)), "s");
        _token(alice, NORMAL, _normal(nid(alice)), "s"); // positive control: another creator's salt
        (, uint256 n) = f.contractsPage(TOKEN, 0, 0);
        assertEq(n, 2, "nothing recorded twice");
    }

    // ------------------------------------------------------------------ slots (3r R1: +4 steady, +5 first; T67 +6, +8)

    function test_index_slotCount_first() public {
        _token(relayer, NORMAL, _normal(nid(bob)), "seed"); // the class list exists: its length is not new
        vm.startStateDiffRecording();
        _token(bob, NORMAL, _normal(nid(alice)), "first");
        assertEq(_newSlots(address(f)), 5, "record 2, two elements, the creator list's first length");
    }

    function test_index_slotCount_steady() public {
        _token(bob, NORMAL, _normal(nid(alice)), "a");
        vm.startStateDiffRecording();
        _token(bob, NORMAL, _normal(nid(alice)), "b");
        assertEq(_newSlots(address(f)), 4, "record 2, two elements");
        vm.startStateDiffRecording();
        _token(bob, NORMAL, _normal(0), "c");
        assertEq(_newSlots(address(f)), 4, "admin 0: the same four (the record names no admin)");
    }
}

/// Plan T67, the Zether kinds 2, 3, 10, 11 (Zether ≠ PQZ: their own fixture).
contract FactoryIndexZetherTest is ZetherFixture, IndexAsserts {
    address issuerZ;
    address complianceZ;
    MockERC20 usdZ;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, 1, _zenv(),
            type(NormalZetherRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, 1, _zenv(),
            type(WrappedZetherRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, true);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, true);
        vm.stopPrank();
        (issuerZ, complianceZ) = (address(new IxHolder()), address(new IxHolder()));
        usdZ = new MockERC20("USD", "USD", 6);
    }

    function _z(bool wrapped, bool regulated) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(false, uint256(1) << 40);
        c.admin = nid(address(0x0A11));
        c.lockedFeatures = 0;
        if (regulated) {
            c.grantDelay = 1 days;
            c.features |= (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
            (c.roles.issuer, c.roles.compliance) = (nid(issuerZ), nid(complianceZ));
            c.reg.termsHash = keccak256("terms");
        }
        if (wrapped) {
            c.features = (1 << GovernanceBits.PAYABLE) | (c.features & ~uint256(0x1F));
            c.roles.minter = 0;
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(usdZ), 1, 1);
        }
    }

    function _kind(uint8 k, bool wrapped, bool regulated) internal {
        vm.prank(address(0xB0B));
        address t = factory.createToken(IOpenFactory.TokenKind(k), 1, abi.encode(_z(wrapped, regulated)), bytes32(uint256(k)));
        _assertIndexed(factory, t, nid(address(0xB0B)), 1, k, 1);
        _assertOldViews(factory, t, address(0xB0B), k, 1);
    }

    function test_index_everyKind_2() public { _kind(2, false, false); }
    function test_index_everyKind_3() public { _kind(3, true, false); }
    function test_index_everyKind_10() public { _kind(10, false, true); }
    function test_index_everyKind_11() public { _kind(11, true, true); }
}

/// Plan T67, the PQZ kinds 4, 5, 12, 13.
contract FactoryIndexPqzTest is PqzFixture, IndexAsserts {
    address issuerP;
    address complianceP;
    MockERC20 usdP;

    function setUp() public {
        _stack();
        _releaseWrapped();
        IFactoryToken.Env memory e = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, e,
            type(NormalPqzRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, e,
            type(WrappedPqzRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true);
        vm.stopPrank();
        (issuerP, complianceP) = (address(new IxHolder()), address(new IxHolder()));
        usdP = new MockERC20("USD", "USD", 6);
    }

    function _p(bool wrapped, bool regulated) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        c.admin = nid(address(0x0A11));
        c.lockedFeatures = 0;
        if (regulated) {
            c.grantDelay = 1 days;
            c.features |= (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
            (c.roles.issuer, c.roles.compliance) = (nid(issuerP), nid(complianceP));
            c.reg.termsHash = keccak256("terms");
        }
        if (wrapped) {
            c.features = (1 << GovernanceBits.PAYABLE) | (c.features & ~uint256(0x1F));
            c.roles.minter = 0;
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(usdP), 1, 1);
        }
    }

    function _kind(uint8 k, bool wrapped, bool regulated) internal {
        vm.prank(address(0xB0B));
        address t = factory.createToken(IOpenFactory.TokenKind(k), 1, abi.encode(_p(wrapped, regulated)), bytes32(uint256(k)));
        _assertIndexed(factory, t, nid(address(0xB0B)), 1, k, 1);
        _assertOldViews(factory, t, address(0xB0B), k, 1);
    }

    function test_index_everyKind_4() public { _kind(4, false, false); }
    function test_index_everyKind_5() public { _kind(5, true, false); }
    function test_index_everyKind_12() public { _kind(12, false, true); }
    function test_index_everyKind_13() public { _kind(13, true, true); }
}
