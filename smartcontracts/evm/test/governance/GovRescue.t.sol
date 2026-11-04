// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IRescuable} from "../../src/governance/IRescuable.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";
import {HookLeg} from "../zether/ZetherWrapped.t.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {nid} from "../helpers/Ids.sol";

/// A leg whose sender pays twice what it sends: the balance after a transfer is short of what the reserve needs.
contract GreedyLeg is MockERC20 {
    constructor() MockERC20("Greedy", "GRD", 6) {}

    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && to != address(0)) super._update(from, address(0), v);
    }
}

/// A second address of the same ledger (a double-entry token): `transfer` here moves `main`'s balances.
contract AliasOf {
    MainLeg public immutable main;

    constructor(MainLeg m) {
        main = m;
    }

    function decimals() external pure returns (uint8) { return 6; }
    function balanceOf(address a) external view returns (uint256) { return main.balanceOf(a); }

    function transfer(address to, uint256 v) external returns (bool) {
        main.aliasMove(msg.sender, to, v);
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        main.aliasMove(from, to, v); // test only: no allowance
        return true;
    }
}

contract MainLeg is MockERC20 {
    address public alias_;

    constructor() MockERC20("Main", "MAIN", 6) {
        alias_ = address(new AliasOf(this));
    }

    function aliasMove(address from, address to, uint256 v) external {
        require(msg.sender == alias_, "alias");
        _transfer(from, to, v);
    }
}

/// @notice D6, rescue (spec §6.2; CTR-GOV-06, -14; A15, A16, R-16): `RESCUABLE` (17) iff `rescueTo != 0`, always locked;
///         `rescue(asset)`, anyone, `nonReentrant`, pays what the token does not owe to the immutable `rescueTo`, the first
///         row of §6.2 that matches deciding; `DexPuller.rescue` moves its whole balance of a token, and spends no allowance.
///         `NORMAL` and `WRAPPED` here (the test plays the factory); the DEX on a real factory; the confidential kinds below.
contract GovRescueTest is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address constant OWNER = address(0x0A);
    address constant TO = address(0x5AFE);
    address constant BOB = address(0xB0B);
    address constant ANYONE = address(0xA11);
    uint256 constant RESCUABLE = uint256(1) << GovernanceBits.RESCUABLE;

    address internal normalImpl;
    address internal wrappedImpl;
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    MockERC20 internal foo = new MockERC20("FOO", "FOO", 18);

    /// The test plays the factory: it registered no token, so every leg is outside to the leg check.
    function isRegisteredToken(address) external pure returns (bool) { return false; }

    function _base(address rescueTo) internal pure returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.owner, c.rescueTo) = ("R", "R", 6, nid(OWNER), rescueTo);
        c.features = 1 | (rescueTo != address(0) ? RESCUABLE : 0);
    }

    function _normalClone() internal returns (NormalToken) {
        if (normalImpl == address(0)) normalImpl = address(new NormalToken(1, plainEnv(address(this), address(0), UID, address(0), false), ""));
        return NormalToken(Clones.clone(normalImpl));
    }

    function _wrappedClone() internal returns (WrappedToken) {
        if (wrappedImpl == address(0)) {
            wrappedImpl = address(new WrappedToken(1, plainEnv(address(this), address(0), UID, address(0), false), ""));
        }
        return WrappedToken(payable(Clones.clone(wrappedImpl)));
    }

    function _normal(address rescueTo) internal returns (NormalToken t) {
        t = _normalClone();
        t.initialize(address(this), 1, abi.encode(_base(rescueTo)));
    }

    function _wrappedCfg(address[] memory legs, address rescueTo) internal pure returns (IFactoryToken.TokenConfig memory c) {
        c = _base(rescueTo);
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], 1, 1);
    }

    function _wrapped(address[] memory legs, address rescueTo) internal returns (WrappedToken w) {
        w = _wrappedClone();
        w.initialize(address(this), 1, abi.encode(_wrappedCfg(legs, rescueTo)));
    }

    function _one(address a) internal pure returns (address[] memory l) {
        l = new address[](1);
        l[0] = a;
    }

    function _wrapUsd(WrappedToken w, uint256 amount) internal {
        usd.mint(BOB, amount);
        vm.startPrank(BOB);
        usd.approve(address(w), amount);
        w.wrap(address(usd), amount);
        vm.stopPrank();
    }

    function _reserve(WrappedToken w, address leg) internal view returns (uint256 r) {
        (,, r,,) = w.legOf(leg);
    }

    function _rescue(address t, address asset) internal {
        vm.prank(ANYONE); // anyone: no role, no signature
        IRescuable(t).rescue(asset);
    }

    // ------------------------------------------------------------------ the table of §6.2, `WRAPPED`

    function test_rescueForeignToken() public {
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        _wrapUsd(w, 100);
        foo.mint(address(w), 50);
        vm.expectEmit(address(w));
        emit IRescuable.Rescued(address(foo), TO, 50);
        _rescue(address(w), address(foo));
        assertEq(foo.balanceOf(TO), 50);
        assertEq(usd.balanceOf(address(w)), 100);
        assertEq(_reserve(w, address(usd)), 100);
    }

    function test_rescueNativeLessReserve() public {
        address[] memory legs = new address[](2);
        (legs[0], legs[1]) = (address(0), address(usd));
        WrappedToken w = _wrapped(legs, TO);
        vm.deal(BOB, 1 ether);
        vm.prank(BOB);
        w.wrap{value: 1 ether}(address(0), 1 ether);
        vm.deal(address(w), 1.5 ether); // 0.5 a stray
        _rescue(address(w), address(0));
        assertEq(TO.balance, 0.5 ether);
        assertEq(address(w).balance, 1 ether);
        assertEq(_reserve(w, address(0)), 1 ether);
    }

    function test_rescueLegSurplusOnly() public {
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        _wrapUsd(w, 100);
        usd.mint(address(w), 30);
        _rescue(address(w), address(usd));
        assertEq(usd.balanceOf(TO), 30);
        assertEq(usd.balanceOf(address(w)), 100);
        assertEq(_reserve(w, address(usd)), 100);
        _rescue(address(w), address(usd)); // nothing more: the reserve is owed
        assertEq(usd.balanceOf(TO), 30);
    }

    /// A16: a second address of a leg's ledger is foreign by address, and moving its balance moves the leg's.
    function test_rescueAliasOfALegRefused() public {
        MainLeg m = new MainLeg();
        WrappedToken w = _wrapped(_one(address(m)), TO);
        m.mint(BOB, 100);
        vm.startPrank(BOB);
        m.approve(address(w), 100);
        w.wrap(address(m), 100);
        vm.stopPrank();
        address a = m.alias_();
        assertEq(IERC20(a).balanceOf(address(w)), 100, "the alias reads the leg's ledger");
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueTouchedLeg.selector, address(m)));
        _rescue(address(w), a);
        assertEq(m.balanceOf(address(w)), 100);
    }

    /// Review 2026-11-04 M-1: two legs over one ledger (a double-entry token, legs A and a front of A) each read the shared
    /// balance, so one leg's `balance − reserve` holds the other's reserve. The rescue of either leg moves the other leg's
    /// balance and is refused (`RescueTouchedLeg`), as the foreign row refuses an alias (A16).
    function test_rescueOfALegSharingALedgerWithAnotherLegRefused() public {
        MainLeg m = new MainLeg();
        address b = m.alias_();
        address[] memory legs = new address[](2);
        (legs[0], legs[1]) = (address(m), b);
        WrappedToken w = _wrapped(legs, TO);
        m.mint(BOB, 150);
        vm.startPrank(BOB);
        m.approve(address(w), 100);
        w.wrap(address(m), 100);
        w.wrap(b, 50);
        vm.stopPrank();
        assertEq(_reserve(w, address(m)) + _reserve(w, b), 150);
        assertEq(m.balanceOf(address(w)), 150);
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueTouchedLeg.selector, b));
        _rescue(address(w), address(m));
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueTouchedLeg.selector, address(m)));
        _rescue(address(w), b);
        assertEq(m.balanceOf(TO), 0);
        assertEq(m.balanceOf(address(w)), 150, "every reserve still held");
    }

    /// Positive control of M-1: a leg's surplus goes while the other legs (the native one included) stay untouched.
    function test_rescueLegSurplusBesideOtherLegs() public {
        MockERC20 eur = new MockERC20("EUR", "EUR", 6);
        address[] memory legs = new address[](3);
        (legs[0], legs[1], legs[2]) = (address(0), address(usd), address(eur));
        WrappedToken w = _wrapped(legs, TO);
        _wrapUsd(w, 100);
        vm.deal(BOB, 1 ether);
        vm.prank(BOB);
        w.wrap{value: 1 ether}(address(0), 1 ether);
        eur.mint(address(w), 40);
        usd.mint(address(w), 30);
        _rescue(address(w), address(usd));
        assertEq(usd.balanceOf(TO), 30);
        assertEq(usd.balanceOf(address(w)), 100);
        assertEq(eur.balanceOf(address(w)), 40);
        assertEq(address(w).balance, 1 ether);
    }

    /// A16: a leg short of its reserve does not trap the rescue of a foreign token.
    function test_rescuePastAShortLeg() public {
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        _wrapUsd(w, 100);
        deal(address(usd), address(w), 60); // the leg lost 40
        foo.mint(address(w), 50);
        _rescue(address(w), address(foo));
        assertEq(foo.balanceOf(TO), 50);
    }

    function test_rescueLegShortfallNamesItsError() public {
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        _wrapUsd(w, 100);
        deal(address(usd), address(w), 60);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.ReserveShortfall.selector, address(usd), 60, 100));
        _rescue(address(w), address(usd));
        // after the transfer: a leg whose sender pays twice leaves the balance short
        GreedyLeg g = new GreedyLeg();
        WrappedToken v = _wrapped(_one(address(g)), TO);
        g.mint(BOB, 200); // the wrap's transfer costs BOB 200 for 100 received
        vm.startPrank(BOB);
        g.approve(address(v), 100);
        v.wrap(address(g), 100);
        vm.stopPrank();
        assertEq(_reserve(v, address(g)), 100);
        g.mint(address(v), 10); // a surplus of 10, whose transfer costs the token 20
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.ReserveShortfall.selector, address(g), 90, 100));
        _rescue(address(v), address(g));
    }

    function test_rescueReentrantAssetRefused() public {
        HookLeg hook = new HookLeg();
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        hook.mint(address(w), 10);
        foo.mint(address(w), 5);
        hook.arm(address(w), abi.encodeCall(IRescuable.rescue, (address(foo))));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        _rescue(address(w), address(hook));
        hook.arm(address(0), ""); // positive control: no re-entry
        _rescue(address(w), address(hook));
        assertEq(hook.balanceOf(TO), 10);
    }

    function test_rescueOwnTokenRefused() public {
        WrappedToken w = _wrapped(_one(address(usd)), TO);
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueAssetInvalid.selector, address(w)));
        _rescue(address(w), address(w));
        NormalToken n = _normal(TO);
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueAssetInvalid.selector, address(n)));
        _rescue(address(n), address(n));
    }

    function test_rescueToDesignatorRefusedNative() public {
        address d = address(0xDE51);
        vm.etch(d, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        NormalToken n = _normal(d);
        vm.deal(address(n), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueAssetInvalid.selector, address(0)));
        _rescue(address(n), address(0));
        foo.mint(address(n), 5); // control: an ERC-20 goes
        _rescue(address(n), address(foo));
        assertEq(foo.balanceOf(d), 5);
        WrappedToken w = _wrapped(_one(address(usd)), d);
        vm.deal(address(w), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueAssetInvalid.selector, address(0)));
        _rescue(address(w), address(0));
    }

    function test_rescueOffWithoutTheBit() public {
        NormalToken n = _normal(address(0));
        foo.mint(address(n), 5);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, GovernanceBits.RESCUABLE));
        _rescue(address(n), address(foo));
        WrappedToken w = _wrapped(_one(address(usd)), address(0));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, GovernanceBits.RESCUABLE));
        _rescue(address(w), address(foo));
        assertEq(n.rescueTo(), address(0));
    }

    /// `NORMAL*`: the whole balance, nothing to prove. `rescueTo` has no writer: an owner change leaves it.
    function test_rescueOnNormalTakesAll() public {
        NormalToken n = _normal(TO);
        vm.prank(OWNER);
        n.transferOwnership(nid(BOB));
        vm.prank(BOB);
        n.acceptOwnership();
        assertEq(n.rescueTo(), TO);
        foo.mint(address(n), 50);
        vm.expectEmit(address(n));
        emit IRescuable.Rescued(address(foo), TO, 50);
        _rescue(address(n), address(foo));
        assertEq(foo.balanceOf(TO), 50);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, GovernanceBits.RESCUABLE));
        n.disableFeature(GovernanceBits.RESCUABLE); // always locked
    }

    function test_rescueNativeOnNormal() public {
        NormalToken n = _normal(TO);
        vm.deal(address(n), 1 ether);
        _rescue(address(n), address(0));
        assertEq(TO.balance, 1 ether);
        assertEq(address(n).balance, 0);
    }

    // ------------------------------------------------------------------ init (spec §6.2)

    function test_rescueToThisOrAPoolRefusedAtInit() public {
        NormalToken n = _normalClone();
        address[3] memory bad = [address(n), MetaTxLib.UA_POOL, MetaTxLib.SHIELD_POOL];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
            n.initialize(address(this), 1, abi.encode(_base(bad[i])));
        }
        WrappedToken w = _wrappedClone();
        bad[0] = address(w);
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
            w.initialize(address(this), 1, abi.encode(_wrappedCfg(_one(address(usd)), bad[i])));
        }
        IFactoryToken.TokenConfig memory c = _base(TO); // the bit and the address go together
        c.features = 1;
        vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
        n.initialize(address(this), 1, abi.encode(c));
        c = _base(address(0));
        c.features = 1 | RESCUABLE;
        vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
        n.initialize(address(this), 1, abi.encode(c));
        n.initialize(address(this), 1, abi.encode(_base(TO))); // positive control
        assertEq(n.rescueTo(), TO);
        assertEq(n.lockedFeatures() & RESCUABLE, RESCUABLE, "always locked");
    }

    function test_tokenAnswersIRescuableOnlyWithTheBit() public {
        bytes4 id = type(IRescuable).interfaceId;
        assertTrue(MetaTokenBase(address(_normal(TO))).supportsInterface(id));
        assertFalse(MetaTokenBase(address(_normal(address(0)))).supportsInterface(id));
        assertTrue(MetaTokenBase(address(_wrapped(_one(address(usd)), TO))).supportsInterface(id));
        assertFalse(MetaTokenBase(address(_wrapped(_one(address(usd)), address(0)))).supportsInterface(id));
    }
}

/// `DexPuller.rescue` (spec §6.2): the DEX's `rescueTo`, immutable; not on `SCaaSDex` itself.
contract GovRescueDexTest is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address constant OWNER = address(0x0A);
    address constant TO = address(0x5AFE);
    address constant ALICE = address(0xA11CE);
    OpenFactory f;
    MockERC20 internal foo = new MockERC20("FOO", "FOO", 18);

    function setUp() public {
        f = new OpenFactory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
    }

    function _dex(address rescueTo, bytes32 salt) internal returns (SCaaSDex) {
        return SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, rescueTo)), salt));
    }

    function test_pullerRescueWholeBalance() public {
        DexPuller p = DexPuller(_dex(TO, "d").puller());
        assertEq(p.rescueTo(), TO);
        foo.mint(address(p), 70);
        vm.prank(address(0xBEEF)); // anyone
        p.rescue(address(foo));
        assertEq(foo.balanceOf(TO), 70);
        assertEq(foo.balanceOf(address(p)), 0);
    }

    function test_pullerRescueOff() public {
        DexPuller p = DexPuller(_dex(address(0), "d").puller());
        foo.mint(address(p), 70);
        vm.expectRevert(DexPuller.RescueOff.selector);
        p.rescue(address(foo));
    }

    /// R-16: the puller holds users' allowances; its rescue calls only `balanceOf` and `transfer`, so none is spent.
    function test_pullerRescueCannotSpendAllowances() public {
        DexPuller p = DexPuller(_dex(TO, "d").puller());
        foo.mint(ALICE, 100);
        vm.prank(ALICE);
        foo.approve(address(p), type(uint256).max);
        vm.expectCall(address(foo), abi.encodeWithSelector(IERC20.transferFrom.selector), 0);
        p.rescue(address(foo));
        assertEq(foo.balanceOf(ALICE), 100);
        assertEq(foo.balanceOf(TO), 0);
    }

    /// Review 2026-11-04 M-2: `DexConfig.rescueTo` follows the tokens' rule (spec §6.2): never `UA_POOL`, `SHIELD_POOL`, the
    /// DEX or its puller (`RescueConfigInvalid`); the test plays the factory of a bare clone, so the DEX's address is known.
    function test_dexRescueToThisOrAPoolRefusedAtInit() public {
        SCaaSDex impl = new SCaaSDex(1, plainEnv(address(this), address(0), UID, address(0), false), "");
        SCaaSDex d = SCaaSDex(Clones.clone(address(impl)));
        address p = vm.computeCreateAddress(address(d), 1); // the puller: the clone's first CREATE
        address[4] memory bad = [MetaTxLib.UA_POOL, MetaTxLib.SHIELD_POOL, address(d), p];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
            d.initialize(address(this), 1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, bad[i])));
        }
        d.initialize(address(this), 1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, TO))); // control
        assertEq(d.puller(), p);
        assertEq(DexPuller(p).rescueTo(), TO);
    }

    /// `IRescuable` is its own interface, so `IGovernance`'s id is one on the DEX and on a token.
    function test_interfaceIdIsOneOnDexAndToken() public {
        SCaaSDex d = _dex(TO, "d");
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.owner, c.rescueTo) =
            ("N", "N", 6, 1 | (uint256(1) << GovernanceBits.RESCUABLE), nid(OWNER), TO);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "t");
        assertTrue(d.supportsInterface(type(IGovernance).interfaceId));
        assertTrue(MetaTokenBase(t).supportsInterface(type(IGovernance).interfaceId));
        assertTrue(MetaTokenBase(t).supportsInterface(type(IRescuable).interfaceId));
        assertFalse(d.supportsInterface(type(IRescuable).interfaceId), "not on SCaaSDex");
        assertTrue(type(IGovernance).interfaceId != type(IRescuable).interfaceId);
    }
}

/// The confidential kinds, Zether and PQZ apart: one direct entry on every kind (`NORMAL*` by `GovernanceLib`, `WRAPPED*` by
/// `WrappedLib`).
abstract contract GovRescueConfRows is Test {
    address constant TO_ = address(0x5AFE);
    MockERC20 internal usd_ = new MockERC20("USD", "USD", 6);
    MockERC20 internal foo_ = new MockERC20("FOO", "FOO", 18);

    function _conf(bool wrapped) internal virtual returns (IFactoryToken.TokenConfig memory);
    function _make(bool wrapped, IFactoryToken.TokenConfig memory c) internal virtual returns (address);

    function _rows() internal {
        IFactoryToken.TokenConfig memory c = _conf(false);
        (c.features, c.rescueTo) = (c.features | (uint256(1) << GovernanceBits.RESCUABLE), TO_);
        address n = _make(false, c);
        foo_.mint(n, 7);
        IRescuable(n).rescue(address(foo_));
        assertEq(foo_.balanceOf(TO_), 7);
        c = _conf(true);
        (c.features, c.rescueTo) = (c.features | (uint256(1) << GovernanceBits.RESCUABLE), TO_);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd_), 1, 1);
        address w = _make(true, c);
        usd_.mint(address(this), 100);
        usd_.approve(w, 100);
        IWrappedToken(w).wrap(address(usd_), 100);
        usd_.mint(w, 30);
        IRescuable(w).rescue(address(usd_));
        assertEq(usd_.balanceOf(TO_), 30, "the surplus only");
        assertEq(usd_.balanceOf(w), 100);
        assertTrue(MetaTokenBase(w).supportsInterface(type(IRescuable).interfaceId));
    }
}

contract GovRescueZetherTest is GovRescueConfRows, ZetherFixture {
    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
    }

    function _conf(bool wrapped) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(false, uint256(1) << 40);
        if (wrapped) (c.features, c.lockedFeatures, c.roles.minter) = (1, 0, 0);
    }

    function _make(bool wrapped, IFactoryToken.TokenConfig memory c) internal override returns (address) {
        IOpenFactory.TokenKind k = wrapped ? IOpenFactory.TokenKind.WRAPPED_ZETHER : IOpenFactory.TokenKind.NORMAL_ZETHER;
        return factory.createToken(k, 1, abi.encode(c), wrapped ? bytes32("w") : bytes32("n"));
    }

    function test_rescueOnTheZetherKinds() public {
        _rows();
    }
}

contract GovRescuePqzTest is GovRescueConfRows, PqzFixture {
    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _conf(bool wrapped) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        if (wrapped) (c.features, c.lockedFeatures, c.roles.minter) = (1, 0, 0);
    }

    function _make(bool wrapped, IFactoryToken.TokenConfig memory c) internal override returns (address) {
        IOpenFactory.TokenKind k = wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ : IOpenFactory.TokenKind.NORMAL_PQZ;
        return factory.createToken(k, 1, abi.encode(c), wrapped ? bytes32("w") : bytes32("n"));
    }

    function test_rescueOnThePqzKinds() public {
        _rows();
    }
}
