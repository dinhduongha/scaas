// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {IOpenFactoryV2} from "../../../src/common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {NoUnderlyingToken} from "../../../src/metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../../../src/metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../../../src/metatx/MultiUnderlyingToken.sol";

/// Tầng tối thiểu trên `MetaTokenBase` cho test của T1: `initData = (name, symbol, decimals, supply)`.
contract BaseHarness is MetaTokenBase {
    constructor(address f, address s) MetaTokenBase(f, s) {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_NONE;
    }

    function _init(address creator_, address[] calldata, bytes calldata initData) internal override {
        (string memory n, string memory s, uint8 d, uint256 supply) =
            abi.decode(initData, (string, string, uint8, uint256));
        _setMetadata(n, s, d);
        _mint(creator_, supply);
    }

    function mint(address to, uint256 v) external { _mint(to, v); }
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
        if (noneImpl == address(0)) noneImpl = address(new NoUnderlyingToken(address(this), address(0)));
        return NoUnderlyingToken(_clone(noneImpl, creator_, new address[](0),
            abi.encode("Points", "PTS", uint8(0), supply, minter)));
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
        if (singleImpl == address(0)) singleImpl = address(new SingleUnderlyingToken(address(this), address(0)));
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
        if (multiImpl == address(0)) multiImpl = address(new MultiUnderlyingToken(address(this), address(0)));
        return MultiUnderlyingToken(_clone(multiImpl, address(this), us, _multiInit(nums, dens, cfg, guardian)));
    }

    function _mt(address from, address to, uint256 value, bytes memory data, uint256 batch, uint32 mode)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: from, to: to, value: value, data: data, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _sig(uint256 pk, address t, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MetaTokenBase(t).metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _payData(bytes32 ref) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref);
    }

    /// Calldata của `mtxUnwrapWithFee` dựng tay (bộ mã hoá ABI không via-IR không chứa nổi 13 giá trị). `m`
    /// mang from, to (= recipient), value (= wrapped), batch, nonce, validUntil, mode, relayer, fee, feeRecipient.
    function _unwrapFeeCalldata(MetaTxLib.MetaTransaction memory m, address u, uint256 minOut, bytes memory sig)
        internal pure returns (bytes memory)
    {
        bytes4 sel = bytes4(keccak256(
            "mtxUnwrapWithFee(address,address,uint256,address,uint256,uint256,uint256,uint256,uint32,address,uint256,address,bytes)"));
        return abi.encodePacked(
            abi.encodePacked(sel, abi.encode(m.from, u, m.value, m.to, minOut, m.batch, m.nonce)),
            abi.encode(m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient, uint256(13 * 32), sig.length),
            sig, new bytes((32 - sig.length % 32) % 32));
    }

    /// Gọi `mtxUnwrapWithFee`; revert thì đẩy nguyên lý do lên. (Dưới `vm.expectRevert` lời gọi thấp trả
    /// `ok = true` với dữ liệu revert, nên không giải mã kết quả.)
    function _mtxUnwrapWithFee(address t, MetaTxLib.MetaTransaction memory m, address u, uint256 minOut,
        bytes memory sig) internal
    {
        (bool ok, bytes memory ret) = t.call(_unwrapFeeCalldata(m, u, minOut, sig));
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _unwrapData(address u, address recipient, uint256 minOut) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(keccak256("unwrap(address,address,uint256)")), u, recipient, minOut);
    }
}
