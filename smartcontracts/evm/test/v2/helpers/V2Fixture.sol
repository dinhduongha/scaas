// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {NormalToken} from "../../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {plainEnv} from "../../helpers/Catalogue.sol";

bytes32 constant UID_ = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

/// Minimal kind on `MetaTokenBase` for the base tests: name, symbol, decimals, `initialSupply` to `initialHolder`;
/// `PAYABLE` set as built (P1c), whatever `cfg.features` says.
contract BaseHarness is MetaTokenBase {
    constructor(address f, address s) MetaTokenBase(plainEnv(f, s, UID_, address(0), false)) {}

    function kind() public pure override returns (uint8) {
        return AdminLib.KIND_NORMAL;
    }

    function _init(TokenConfig memory cfg) internal override {
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.Roles memory none;
        AdminLib.init(AdminLib.KIND_NORMAL, 1 << AdminLib.PAYABLE, 0, address(0), none);
        _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Kind-NORMAL `TokenConfig` with the behaviour built before P1c: `PAYABLE | MINTABLE | BURNABLE`, nothing locked, no
/// owner, `minter` (0 = none), `supply` to `holder`. Callers `abi.encode` it (after adjusting fields).
function normalInit(string memory n, string memory s, uint8 d, uint256 supply, address holder, address minter)
    pure returns (IFactoryToken.TokenConfig memory c)
{
    c.name = n;
    c.symbol = s;
    c.decimals = d;
    c.features = 7;
    c.roles.minter = minter;
    c.initialSupply = supply;
    c.initialHolder = holder;
}

/// Test-side rate setup (the shape of the removed `Rate`): `adjustable` sets
/// `RATE_ADJUSTABLE` and grants `rateAdmin` the role.
struct Rate {
    bool adjustable;
    address rateAdmin;
    uint32 rateDelay;
    uint16 maxRateStepBps;
}

/// `TokenConfig` of kind WRAPPED for legs `us` at `nums/dens`: `PAYABLE` (as built), `RATE_ADJUSTABLE` with `cfg.adjustable`,
/// `WRAP_DISABLEABLE` with a non-zero `guardian`; nothing locked; `owner` (0 = none).
function wrappedInit(address[] memory us, uint256[] memory nums, uint256[] memory dens, uint8 dec, Rate memory cfg,
    address guardian, address owner) pure returns (IFactoryToken.TokenConfig memory c)
{
    c.name = "Wrapped";
    c.symbol = "WRP";
    c.decimals = dec;
    c.features = 1 << AdminLib.PAYABLE;
    if (cfg.adjustable) c.features |= 1 << AdminLib.RATE_ADJUSTABLE;
    if (guardian != address(0)) c.features |= 1 << AdminLib.WRAP_DISABLEABLE;
    c.owner = owner;
    c.roles.rateAdmin = cfg.rateAdmin;
    c.roles.guardian = guardian;
    c.legs = new IFactoryToken.Leg[](us.length);
    for (uint256 i; i < us.length; ++i) c.legs[i] = IFactoryToken.Leg(us[i], nums[i], dens[i]);
    c.rate = IFactoryToken.RateConfig(cfg.rateDelay, cfg.maxRateStepBps);
}

/// ERC-1271 đốt ~100k gas rồi trả magic: qua được với 400k, không qua với 50k.
contract GasBurner1271 {
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        uint256 g = gasleft();
        while (g - gasleft() < 100_000) {}
        return 0x1626ba7e;
    }
}

/// The test plays the factory: clone + `initialize` in the same call, as `OpenFactory`.
abstract contract V2Fixture is Test {
    address internal relayer = address(0xBEEF);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;

    /// `cfgData` = `abi.encode(TokenConfig)`; `us` must equal its legs (what the factory would index).
    function _clone(address impl, address creator_, address[] memory us, bytes memory cfgData)
        internal returns (address t)
    {
        IFactoryToken.TokenConfig memory cfg = abi.decode(cfgData, (IFactoryToken.TokenConfig));
        assertEq(cfg.legs.length, us.length, "fixture: legs vs underlyings");
        for (uint256 i; i < us.length; ++i) assertEq(cfg.legs[i].underlying, us[i], "fixture: leg order");
        t = Clones.clone(impl);
        MetaTokenBase(t).initialize(creator_, 1, abi.encode(cfg));
    }

    function _harness(address creator_, uint256 supply) internal returns (BaseHarness) {
        BaseHarness impl = new BaseHarness(address(this), address(0));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.initialSupply, c.initialHolder) = ("Harness", "HRN", 6, supply, creator_);
        return BaseHarness(_clone(address(impl), creator_, new address[](0), abi.encode(c)));
    }

    address internal normalImpl;
    address internal wrappedImpl;
    /// Owner the fixture gives every wrapper it builds (`disableFeature`, `grantRole` in tests).
    address internal wrapperOwner = address(0x0A11);

    function _normal(address creator_, uint256 supply, address minter) internal returns (NormalToken) {
        if (normalImpl == address(0)) {
            normalImpl = address(new NormalToken(1, plainEnv(address(this), address(0), UID_, address(0), false), ""));
        }
        return NormalToken(_clone(normalImpl, creator_, new address[](0),
            abi.encode(normalInit("Points", "PTS", 0, supply, creator_, minter))));
    }

    function _fixedRate() internal pure returns (Rate memory c) {}

    function _adjustable(address admin) internal pure returns (Rate memory c) {
        c = Rate({adjustable: true, rateAdmin: admin, rateDelay: 7 days, maxRateStepBps: 100});
    }

    function _one(address a) internal pure returns (address[] memory us) {
        us = new address[](1);
        us[0] = a;
    }

    function _oneU(uint256 x) internal pure returns (uint256[] memory xs) {
        xs = new uint256[](1);
        xs[0] = x;
    }

    /// `abi.encode(TokenConfig)` for one leg `u`.
    function _singleInit(address u, uint8 dec, uint256 num, uint256 den, Rate memory cfg)
        internal view returns (bytes memory)
    {
        return abi.encode(wrappedInit(_one(u), _oneU(num), _oneU(den), dec, cfg, address(0), wrapperOwner));
    }

    function _wrappedImpl() internal returns (address) {
        if (wrappedImpl == address(0)) {
            wrappedImpl = address(new WrappedToken(1, plainEnv(address(this), address(0), UID_, address(0), false), ""));
        }
        return wrappedImpl;
    }

    function _single(address u, uint8 dec, uint256 num, uint256 den, Rate memory cfg)
        internal returns (WrappedToken)
    {
        return WrappedToken(_clone(_wrappedImpl(), address(this), _one(u), _singleInit(u, dec, num, den, cfg)));
    }

    function _multiInit(address[] memory us, uint256[] memory nums, uint256[] memory dens, Rate memory cfg,
        address guardian) internal view returns (bytes memory)
    {
        return abi.encode(wrappedInit(us, nums, dens, 18, cfg, guardian, wrapperOwner));
    }

    function _multi(address[] memory us, uint256[] memory nums, uint256[] memory dens, Rate memory cfg,
        address guardian) internal returns (WrappedToken)
    {
        return WrappedToken(_clone(_wrappedImpl(), address(this), us, _multiInit(us, nums, dens, cfg, guardian)));
    }

    /// A `MetaTransfer` from `from` on lane `batch`, nonce 0, valid 300 s, relayer `relayer`, no fee.
    function _tr(address from, address to, uint256 value, bytes32 ref, uint256 batch, uint32 mode)
        internal view returns (MetaTxLib.MetaTransfer memory x)
    {
        x = MetaTxLib.MetaTransfer({
            from: from, to: to, value: value, entryRef: ref, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _signTr(uint256 pk, address t, MetaTxLib.MetaTransfer memory x) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MetaTokenBase(t).mtxTransferDigest(x));
        return abi.encodePacked(r, s, v);
    }

    /// Signs with `pk` and submits through `mtxExecuteTransfer` as `relayer`.
    function _xfer(uint256 pk, address t, MetaTxLib.MetaTransfer memory x) internal {
        bytes memory s = _signTr(pk, t, x);
        vm.prank(relayer);
        MetaTokenBase(t).mtxExecuteTransfer(x, s);
    }

    /// A `MetaTransaction` (self-call `data`) from `from` on lane `batch`, nonce 0, valid 300 s, no fee.
    function _call(address from, bytes memory data, uint256 batch, uint32 mode)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: from, data: data, batch: batch, nonce: 0, validUntil: block.timestamp + 300,
            mode: mode, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _signCall(uint256 pk, address t, MetaTxLib.MetaTransaction memory m)
        internal view returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MetaTokenBase(t).mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    /// Signs with `pk` and submits through `mtxExecute` as `relayer`; returns the inner call's bytes.
    function _execCall(uint256 pk, address t, MetaTxLib.MetaTransaction memory m) internal returns (bytes memory) {
        bytes memory s = _signCall(pk, t, m);
        vm.prank(relayer);
        return MetaTokenBase(t).mtxExecute(m, s);
    }
}
