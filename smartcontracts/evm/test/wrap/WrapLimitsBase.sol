// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// Group 3l (spec 2026-11-10-wrap-limits.md): a hybrid `WRAPPED` token over `und` (1:1 unless set), the test the factory
/// (its `noticePeriod()` is `notice`), owner `OWNER`, minter `MINTER`, bits 25, 26, 27 unless left out. UNAUDITED.
abstract contract WrapLimitsBase is UALedgerBase {
    address internal constant OWNER = address(0x0A);
    address internal constant MINTER = address(0x313);
    address internal constant LISTER = address(0x515);
    address internal constant MERCHANT = address(0x3E2);
    uint8 internal constant WL = GovernanceBits.WRAP_LIMIT;
    uint8 internal constant WLIST = GovernanceBits.WRAP_LIST;
    uint8 internal constant RED = GovernanceBits.REDEEMER;
    uint256 internal constant CONTROLS = GovernanceBits.WRAP_CONTROLS;
    uint256 internal constant CAP = 1e30;
    // keccak256(abi.encode(uint256(keccak256("scaas.wraplimit")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant WLNS = 0x8338ae7a3cc0bfc024cc8dc02945ad44a577ebed1c8a715e7136501207e79700;
    bytes32 internal constant UNS = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000; // scaas.underlying

    uint64 internal notice;
    address internal impl;
    address internal u; // the default leg

    function noticePeriod() external view returns (uint64) {
        return notice;
    }

    function setUp() public virtual override {
        super.setUp();
        u = address(und);
    }

    function OFF() internal pure returns (IWrappedToken.WrapLimit memory l) {}

    function L(uint24 perUser, uint64 tokenWide, uint32 period) internal pure returns (IWrappedToken.WrapLimit memory l) {
        l = IWrappedToken.WrapLimit(perUser, tokenWide, period);
    }

    function _cfg(address[] memory legs, uint256[] memory num, uint256 features)
        internal pure returns (IFactoryToken.TokenConfig memory c)
    {
        (c.name, c.symbol, c.decimals, c.admin, c.maxSupply) = ("H", "H", 6, nid(OWNER), CAP);
        c.features = features;
        if (features & (uint256(1) << GovernanceBits.MINTABLE) != 0) c.roles.minter = nid(MINTER);
        else c.maxSupply = 0;
        c.legs = new IFactoryToken.Leg[](legs.length);
        for (uint256 i; i < legs.length; ++i) c.legs[i] = IFactoryToken.Leg(legs[i], num[i], 1);
    }

    function _clone() internal returns (WrappedToken) {
        if (impl == address(0)) impl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        return WrappedToken(payable(EnvKit.clone(impl, EnvKit.env(chainUidA, REG_L, address(0), false))));
    }

    function _make(IFactoryToken.TokenConfig memory c) internal returns (WrappedToken w) {
        w = _clone();
        w.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _one(address leg) internal pure returns (address[] memory l, uint256[] memory n) {
        (l, n) = (new address[](1), new uint256[](1));
        (l[0], n[0]) = (leg, 1);
    }

    /// The default hybrid: `PAYABLE`, `MINTABLE`, bits 25-27, one leg `und` 1:1.
    function _hyb() internal returns (WrappedToken) {
        (address[] memory l, uint256[] memory n) = _one(u);
        return _make(_cfg(l, n, 1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS));
    }

    function _hybWith(uint256 features, address leg, uint256 num) internal returns (WrappedToken) {
        (address[] memory l, uint256[] memory n) = _one(leg);
        n[0] = num;
        return _make(_cfg(l, n, features));
    }

    function _leg(address leg, uint8 unitExp, uint16 decayDays, IWrappedToken.WrapLimit memory ws,
        IWrappedToken.WrapLimit memory wl, IWrappedToken.WrapLimit memory us, IWrappedToken.WrapLimit memory ul)
        internal pure returns (IWrappedToken.WrapLegLimits memory)
    {
        return IWrappedToken.WrapLegLimits(leg, unitExp, decayDays, ws, wl, us, ul);
    }

    function _legs1(IWrappedToken.WrapLegLimits memory a) internal pure returns (IWrappedToken.WrapLegLimits[] memory r) {
        r = new IWrappedToken.WrapLegLimits[](1);
        r[0] = a;
    }

    /// One leg `u` at unit `10^e`, decay `d`, four limits.
    function _cfg1(uint8 e, uint16 d, IWrappedToken.WrapLimit memory ws, IWrappedToken.WrapLimit memory wl,
        IWrappedToken.WrapLimit memory us, IWrappedToken.WrapLimit memory ul)
        internal view returns (IWrappedToken.WrapLegLimits[] memory)
    {
        return _legs1(_leg(u, e, d, ws, wl, us, ul));
    }

    function _set(WrappedToken w, IWrappedToken.WrapLegLimits[] memory a, bool net, bool wrapList, bool unwrapList) internal {
        vm.prank(OWNER);
        w.setWrapLimits(a, net, wrapList, unwrapList);
    }

    /// The tracking on with nothing else (the first configuration, every limit off).
    function _track(WrappedToken w) internal {
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), false, false, false);
    }

    function _fundW(WrappedToken w, address who, uint256 amount) internal {
        MockERC20(u).mint(who, amount);
        vm.prank(who);
        MockERC20(u).approve(address(w), type(uint256).max);
    }

    function _wrap(WrappedToken w, address who, uint256 amount) internal {
        _fundW(w, who, amount);
        vm.prank(who);
        w.wrap(u, amount);
    }

    function _wrapRev(WrappedToken w, address who, uint256 amount, bytes memory err) internal {
        _fundW(w, who, amount);
        vm.expectRevert(err);
        vm.prank(who);
        w.wrap(u, amount);
    }

    function _unwrap(WrappedToken w, address who, uint256 wrapped) internal {
        vm.prank(who);
        w.unwrap(u, wrapped, who, 0);
    }

    function _unwrapRev(WrappedToken w, address who, uint256 wrapped, bytes memory err) internal {
        vm.expectRevert(err);
        vm.prank(who);
        w.unwrap(u, wrapped, who, 0);
    }

    function _over(uint8 limit, address who, uint256 amount, uint256 left) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, u, limit, _pad(who), amount, left);
    }

    function _capOver(uint8 limit, uint256 amount, uint256 left) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapCapExceeded.selector, u, limit, amount, left);
    }

    function _aboveNet(address who, uint256 amount, uint256 e) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.UnwrapAboveNetWrapped.selector, u, _pad(who), amount, e);
    }

    function _q(WrappedToken w, address who) internal view returns (IWrappedToken.WrapQuota memory) {
        return w.wrapQuotaOf(_pad(who), u);
    }

    /// The raw quota word of `id` on leg `i` (spec §5, R26).
    function _word(WrappedToken w, bytes32 id, uint256 i) internal view returns (uint256) {
        bytes32 inner = keccak256(abi.encode(id, uint256(WLNS) + 2));
        return uint256(vm.load(address(w), keccak256(abi.encode(i, inner))));
    }

    function _grant(WrappedToken w, uint8 bit, address who) internal {
        vm.prank(OWNER);
        w.grantRole(bit, _pad(who));
    }
}
