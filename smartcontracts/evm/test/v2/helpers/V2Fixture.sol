// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {IOpenFactoryV2} from "../../../src/common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {NoUnderlyingToken} from "../../../src/metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../../../src/metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../../../src/metatx/MultiUnderlyingToken.sol";

bytes32 constant UID_ = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

/// Tầng tối thiểu trên `MetaTokenBase` cho test của T1: `initData = (name, symbol, decimals, supply)`; `PAYABLE` bật
/// như khi build (P1c).
contract BaseHarness is MetaTokenBase {
    constructor(address f, address s) MetaTokenBase(f, s, UID_, false) {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_NONE;
    }

    function _init(address creator_, address[] calldata, bytes calldata initData) internal override {
        (string memory n, string memory s, uint8 d, uint256 supply) =
            abi.decode(initData, (string, string, uint8, uint256));
        _setMetadata(n, s, d);
        AdminLib.Roles memory none;
        AdminLib.init(AdminLib.KIND_NONE, 1 << AdminLib.PAYABLE, 0, address(0), none);
        _mint(creator_, supply);
    }

    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Kind-NONE init (P1c `NoneInit`) with the behaviour built before P1c: `PAYABLE | MINTABLE | BURNABLE`, nothing
/// locked, no owner, `minter` (0 = none), `supply` to `holder`. Callers `abi.encode` it (after adjusting fields).
function noneInit(string memory n, string memory s, uint8 d, uint256 supply, address holder, address minter)
    pure returns (NoUnderlyingToken.NoneInit memory c)
{
    c.name = n;
    c.symbol = s;
    c.decimals = d;
    c.features = 7;
    c.roles.minter = minter;
    c.initialSupply = supply;
    c.initialHolder = holder;
}

/// ERC-1271 đốt ~100k gas rồi trả magic: qua được với 400k, không qua với 50k.
contract GasBurner1271 {
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        uint256 g = gasleft();
        while (g - gasleft() < 100_000) {}
        return 0x1626ba7e;
    }
}

/// Test đóng vai factory: clone + `initialize` trong cùng lời gọi, như `OpenFactoryV2`.
abstract contract V2Fixture is Test {
    address internal relayer = address(0xBEEF);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;

    function _clone(address impl, address creator_, address[] memory us, bytes memory initData)
        internal returns (address t)
    {
        t = Clones.clone(impl);
        MetaTokenBase(t).initialize(creator_, us, 1, initData);
    }

    function _harness(address creator_, uint256 supply) internal returns (BaseHarness) {
        BaseHarness impl = new BaseHarness(address(this), address(0));
        return BaseHarness(_clone(address(impl), creator_, new address[](0),
            abi.encode("Harness", "HRN", uint8(6), supply)));
    }

    address internal noneImpl;
    address internal singleImpl;

    function _none(address creator_, uint256 supply, address minter) internal returns (NoUnderlyingToken) {
        if (noneImpl == address(0)) {
            noneImpl = address(new NoUnderlyingToken(address(this), address(0), UID_, false));
        }
        return NoUnderlyingToken(_clone(noneImpl, creator_, new address[](0),
            abi.encode(noneInit("Points", "PTS", 0, supply, creator_, minter))));
    }

    function _fixedRate() internal pure returns (SingleUnderlyingToken.RateConfig memory c) {}

    function _adjustable(address admin) internal pure returns (SingleUnderlyingToken.RateConfig memory c) {
        c = SingleUnderlyingToken.RateConfig({adjustable: true, rateAdmin: admin, rateDelay: 7 days, maxRateStepBps: 100});
    }

    function _singleInit(uint8 dec, uint256 num, uint256 den, SingleUnderlyingToken.RateConfig memory cfg)
        internal pure returns (bytes memory)
    {
        return abi.encode("Wrapped", "WRP", dec, num, den, cfg);
    }

    function _single(address u, uint8 dec, uint256 num, uint256 den, SingleUnderlyingToken.RateConfig memory cfg)
        internal returns (SingleUnderlyingToken)
    {
        if (singleImpl == address(0)) {
            singleImpl = address(new SingleUnderlyingToken(address(this), address(0), UID_, false));
        }
        address[] memory us = new address[](1);
        us[0] = u;
        return SingleUnderlyingToken(_clone(singleImpl, address(this), us, _singleInit(dec, num, den, cfg)));
    }

    address internal multiImpl;

    function _multiInit(uint256[] memory nums, uint256[] memory dens, SingleUnderlyingToken.RateConfig memory cfg,
        address guardian) internal pure returns (bytes memory)
    {
        return abi.encode("Any USD", "aUSD", uint8(18), nums, dens, cfg, guardian);
    }

    function _multi(address[] memory us, uint256[] memory nums, uint256[] memory dens,
        SingleUnderlyingToken.RateConfig memory cfg, address guardian) internal returns (MultiUnderlyingToken)
    {
        if (multiImpl == address(0)) {
            multiImpl = address(new MultiUnderlyingToken(address(this), address(0), UID_, false));
        }
        return MultiUnderlyingToken(_clone(multiImpl, address(this), us, _multiInit(nums, dens, cfg, guardian)));
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
