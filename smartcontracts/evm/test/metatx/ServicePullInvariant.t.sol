// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {RefServiceEscrow} from "./helpers/RefServiceEscrow.sol";
import {spDepositRef, spPull} from "./helpers/ServicePullKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";

/// The fuzzed actions on one `RefServiceEscrow` over a kind-8 token (spec 2026-11-09-service-pull §11 "Invariant fuzz"):
/// deposits by four native payers (some short of funds), replays of a landed operation on a fresh nonce, releases at any
/// time, plain transfers into S outside a pull, and recorded forced moves out of S (`recordOrder`, a record freeze,
/// `forceTransfer`, `unfreeze`). Every outcome is asserted where it happens: a deposit lands iff the payer can pay and S is
/// not frozen; a replay never lands; a release lands iff it is due and S holds the amount (fail closed, custody intact
/// otherwise).
contract ServicePullHandler is Test {
    uint256 internal constant LANE = 7;
    bytes32 internal constant REF = bytes32(uint256(0x5EF));

    RefServiceEscrow internal s;
    address internal t;
    address internal issuer;
    address internal compliance;
    uint256[4] internal pks = [uint256(0x5001), 0x5002, 0x5003, 0x5004];

    bytes32[] public refs;
    mapping(bytes32 => RefServiceEscrow.Deposit) internal opOf;
    mapping(bytes32 => uint256) public landed;
    mapping(address => uint256) public outsideBy;
    uint256 public forced;
    uint256 public outside;
    uint256 internal salt;
    uint256 internal orders;
    // reach counters (the positive control asserts every path is taken)
    uint256 public deposits;
    uint256 public depositsRefused;
    uint256 public replaysRefused;
    uint256 public releases;
    uint256 public releasesRefused;
    uint256 public forces;

    constructor(RefServiceEscrow s_, address issuer_, address compliance_) {
        (s, t, issuer, compliance) = (s_, s_.TOKEN(), issuer_, compliance_);
    }

    function payer(uint256 i) public view returns (address) {
        return vm.addr(pks[i]);
    }

    function refCount() external view returns (uint256) {
        return refs.length;
    }

    function _sign(uint256 pk, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, MetaTokenBase(t).mtxTransferDigest(x));
        a.signature = abi.encodePacked(r, ss, v);
    }

    function _frozenS() internal view returns (bool) {
        return IRegulatedToken(t).isFrozen(MetaTxLib.pad(address(s)));
    }

    function _try(RefServiceEscrow.Deposit memory op, uint256 pk) internal returns (bool ok, bytes memory ret, bytes32 ref) {
        ref = spDepositRef(address(s), block.chainid, op);
        MetaTxLib.UAMetaTransfer memory x = spPull(op.payer, address(s), op.amount, ref, LANE,
            MetaTokenBase(t).mtxNonce(op.payer, LANE), block.timestamp + 300);
        IUARegistry.UASig memory a = _sign(pk, x);
        (ok, ret) = address(s).call(abi.encodeCall(RefServiceEscrow.deposit, (op, x, a)));
    }

    function deposit(uint256 who, uint256 amount, uint256 lock) external {
        uint256 i = who % 4;
        address p = payer(i);
        amount = bound(amount, 1, 6_000);
        RefServiceEscrow.Deposit memory op =
            RefServiceEscrow.Deposit(MetaTxLib.pad(p), amount, uint64(block.timestamp + bound(lock, 0, 2 days)), bytes32(++salt));
        bool can = IERC20(t).balanceOf(p) >= amount && !_frozenS();
        (bool ok,, bytes32 ref) = _try(op, pks[i]);
        assertEq(ok, can, "a deposit lands iff the payer can pay and S is not frozen");
        if (!ok) {
            ++depositsRefused;
            return;
        }
        ++deposits;
        refs.push(ref);
        opOf[ref] = op;
        ++landed[ref];
    }

    /// The same operation signed again on the payer's next nonce: never lands (Q4).
    function replay(uint256 k) external {
        if (refs.length == 0) return;
        bytes32 ref = refs[k % refs.length];
        RefServiceEscrow.Deposit memory op = opOf[ref];
        uint256 i;
        while (MetaTxLib.pad(payer(i)) != op.payer) ++i;
        (bool ok, bytes memory ret,) = _try(op, pks[i]);
        assertFalse(ok, "an operation lands at most once");
        assertEq(bytes4(ret), RefServiceEscrow.ServicePullReplayed.selector);
        ++replaysRefused;
    }

    function release(uint256 k, uint256 dt) external {
        if (refs.length == 0) return;
        vm.warp(block.timestamp + bound(dt, 0, 1 days));
        bytes32 ref = refs[k % refs.length];
        (bytes32 p, uint256 amount, uint64 ra) = s.custody(ref);
        if (amount == 0) return;
        bool can = block.timestamp >= ra && IERC20(t).balanceOf(address(s)) >= amount && !_frozenS();
        uint256 owed0 = s.owed();
        (bool ok,) = address(s).call(abi.encodeCall(RefServiceEscrow.release, (ref)));
        assertEq(ok, can, "a release lands iff due and covered (fail closed)");
        if (!ok) {
            (bytes32 p1, uint256 a1,) = s.custody(ref);
            assertEq(p1, p, "custody intact");
            assertEq(a1, amount, "custody intact");
            assertEq(s.owed(), owed0, "custody intact");
            ++releasesRefused;
            return;
        }
        ++releases;
    }

    /// Tokens sent to S outside a pull: they belong to no one in S's books.
    function sendOutside(uint256 who, uint256 amount) external {
        address p = payer(who % 4);
        amount = bound(amount, 0, IERC20(t).balanceOf(p) / 4);
        if (amount == 0) return;
        vm.prank(p);
        IERC20(t).transfer(address(s), amount);
        outside += amount;
        outsideBy[p] += amount;
    }

    /// A recorded order on S executed: `recordOrder`, the record freeze, `forceTransfer`, `unfreeze`.
    function force(uint256 amount) external {
        uint256 bal = IERC20(t).balanceOf(address(s));
        if (bal == 0) return;
        amount = bound(amount, 1, bal);
        bytes32 sid = MetaTxLib.pad(address(s));
        bytes32 orderId = keccak256(abi.encode("sp-inv-order", ++orders));
        vm.prank(compliance);
        IRegulatedToken(t).recordOrder(orderId, keccak256("document"), sid, bytes32(uint256(0xBE)), amount,
            uint64(block.timestamp + 30 days));
        bytes32 rid = keccak256(abi.encode(orderId, sid, bytes32(uint256(0xBE))));
        vm.prank(issuer);
        IRegulatedToken(t).freeze(sid, REF, rid);
        vm.prank(issuer);
        IRegulatedToken(t).forceTransfer(rid, amount);
        vm.prank(issuer);
        IRegulatedToken(t).unfreeze(sid, REF);
        forced += amount;
        ++forces;
    }
}

/// @notice The service-pull invariants (spec §11, plan T77) over `ServicePullHandler`: `balanceOf(S) >= Σ custody` while
///         nothing was forced; with forced moves, `balanceOf(S) + forced == Σ custody + outside` (so the shortfall is the
///         forced amount, less what was sent outside), payouts failing closed (asserted in the handler); every payer's
///         balance plus its custody plus what it sent outside is its initial balance; an operation (`entryRef`) lands at
///         most once and `used` says so. `test_handler_reachesEveryPath` is the positive control. UNAUDITED.
contract ServicePullInvariantTest is RegFixture {
    uint256 internal constant FUND = 20_000;
    RefServiceEscrow internal s;
    ServicePullHandler internal h;
    mapping(address => uint256) internal initial;

    function setUp() public override {
        super.setUp();
        s = new RefServiceEscrow(t8);
        h = new ServicePullHandler(s, issuer, compliance);
        for (uint256 i; i < 4; ++i) {
            address p = h.payer(i);
            vm.prank(alice);
            IERC20(t8).transfer(p, FUND * (i + 1) / 4);
            initial[p] = IERC20(t8).balanceOf(p);
        }
        bytes4[] memory sel = new bytes4[](5);
        (sel[0], sel[1], sel[2], sel[3], sel[4]) = (ServicePullHandler.deposit.selector, ServicePullHandler.replay.selector,
            ServicePullHandler.release.selector, ServicePullHandler.sendOutside.selector, ServicePullHandler.force.selector);
        targetSelector(FuzzSelector(address(h), sel));
        targetContract(address(h));
    }

    function _sumCustody(bytes32 who) internal view returns (uint256 sum) {
        uint256 n = h.refCount();
        for (uint256 k; k < n; ++k) {
            (bytes32 p, uint256 a,) = s.custody(h.refs(k));
            if (who == 0 || p == who) sum += a;
        }
    }

    function invariant_custodyCovered() public view {
        uint256 bal = IERC20(t8).balanceOf(address(s));
        assertEq(s.owed(), _sumCustody(0), "owed = the sum of the custody records");
        if (h.forced() == 0) assertGe(bal, s.owed(), "balanceOf(S) >= sum of custody");
        assertEq(bal + h.forced(), s.owed() + h.outside(), "the shortfall is the forced amount (less outside sends)");
    }

    function invariant_payerConservation() public view {
        for (uint256 i; i < 4; ++i) {
            address p = h.payer(i);
            assertEq(IERC20(t8).balanceOf(p) + _sumCustody(MetaTxLib.pad(p)) + h.outsideBy(p), initial[p], "conservation");
        }
    }

    function invariant_landsOnce() public view {
        uint256 n = h.refCount();
        for (uint256 k; k < n; ++k) {
            bytes32 r = h.refs(k);
            assertEq(h.landed(r), 1, "an operation lands at most once");
            assertTrue(s.used(r));
        }
    }

    /// The positive control: every path of the handler is reached (a deposit, a refused one, a refused replay, a release,
    /// a refused release by the shortfall, an outside send, a forced move), and the invariants hold after it.
    function test_handler_reachesEveryPath() public {
        h.deposit(0, 1_000, 0);
        h.deposit(1, 2_000, 1 days);
        h.deposit(0, 6_000, 0); // payer 0 holds 20_000 / 4 - 1_000 = 4_000: refused
        h.replay(0);
        h.release(0, 0);
        h.sendOutside(2, 100);
        h.force(1_500);
        h.deposit(2, 500, 0);
        h.release(1, 1 days); // due, but S holds 2_100 - 1_500 + 500 = 1_100 < 2_000: refused
        assertEq(h.deposits(), 3);
        assertEq(h.depositsRefused(), 1);
        assertEq(h.replaysRefused(), 1);
        assertEq(h.releases(), 1);
        assertEq(h.releasesRefused(), 1);
        assertEq(h.forces(), 1);
        assertEq(h.outside(), 100);
        invariant_custodyCovered();
        invariant_payerConservation();
        invariant_landsOnce();
    }
}
