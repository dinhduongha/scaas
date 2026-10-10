// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IFactoryTokenV2} from "../factory/IFactoryTokenV2.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the struct of their kind and run its pipeline. Transitional: features, roles, `PayLib` and provenance land in P1c.
///
///         No owner, no pause, no upgrade. The two init-time exceptions (R142) live in the wrapper tiers: the rate
///         admin (only when `adjustable`) and the guardian (only `disableWrap`).
abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2 {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SmartKeyAccount implementation of this chain (built: `SubjectAccount`, renamed in P4; 0 = none). Only its EIP-1167 clones get 400k gas for
    ///         ERC-1271; every other contract wallet 50k.
    address public immutable SMART_KEY_ACCOUNT_IMPL;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    // one slot: creator ‖ version ‖ _tokenDecimals ‖ _initialized ‖ _legCount
    address public creator;
    uint64 public version;
    uint8 private _tokenDecimals;
    bool private _initialized;
    /// @dev Number of underlying legs (0 on tier 1); here so it shares the init slot.
    uint8 internal _legCount;
    string private _tokenName;
    string private _tokenSymbol;

    error NotFactory();
    error AlreadyInitialized();
    error MtxModeShape(uint32 mode);
    /// @notice Wrong underlying count for the tier (0 / 1 / 2–8).
    error UnderlyingCountInvalid(uint256 n);

    /// @dev Runs ONCE on the implementation and locks it, so nobody can `initialize` it.
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_) ERC20MetaTx(chainUid_) {
        FACTORY = factory_;
        _SELF = address(this);
        SMART_KEY_ACCOUNT_IMPL = smartKeyAccountImpl_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        _initialized = true;
    }

    /// @notice The factory calls it in the SAME call as CREATE2. `initData` per tier (TW2 §4, §5.1, §8.1).
    function initialize(address creator_, address[] calldata underlyings, uint64 version_, bytes calldata initData)
        external
    {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        creator = creator_;
        version = version_;
        _init(creator_, underlyings, initData);
    }

    /// @dev The tier decodes `initData`, calls `_setMetadata`, checks `underlyings`.
    function _init(address creator_, address[] calldata underlyings, bytes calldata initData) internal virtual;

    function _setMetadata(string memory n, string memory s, uint8 d) internal {
        _tokenName = n;
        _tokenSymbol = s;
        _tokenDecimals = d;
    }

    function tokenKind() external pure virtual returns (IOpenFactoryV2.TokenKind);

    function name() public view override returns (string memory) { return _tokenName; }
    function symbol() public view override returns (string memory) { return _tokenSymbol; }
    function decimals() public view override returns (uint8) { return _tokenDecimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }

    function payLane(bytes32 payId) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)));
    }

    // ------------------------------------------------------------------ named functions (CTR-MTX-09)

    function mtxTransfer(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature
    ) external nonReentrant returns (bool) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        _executeTransfer(t, signature);
        return true;
    }

    function mtxTransferWithFee(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        _requireFeeShape(mode, feeRecipient);
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        t.fee = fee;
        t.feeRecipient = feeRecipient;
        _executeTransfer(t, signature);
        return true;
    }

    /// @notice `mtxExecute` that says "this intent pays a fee": fee nibble ≠ `NONE`.
    function mtxExecuteWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        if (m.mode & MetaTxLib.MODE_FEE_MASK == 0) revert MtxModeShape(m.mode);
        return _execute(m, signature);
    }

    /// @notice Payment `payId` on its own lane `payLane(payId)`, nonce 0 (CTR-MTX-10).
    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.entryRef = payId;
        t.batch = payLane(payId);
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        t.fee = fee;
        t.feeRecipient = feeRecipient;
        _executeTransfer(t, signature);
        return true;
    }

    /// @dev Fee `PERCENT`/`FIXED`, recipient bound by the signer and non-zero.
    function _requireFeeShape(uint32 mode, address feeRecipient) private pure {
        uint32 f = mode & MetaTxLib.MODE_FEE_MASK;
        if ((f != MetaTxLib.MODE_FEE_PERCENT && f != MetaTxLib.MODE_FEE_FIXED)
            || mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT == 0 || feeRecipient == address(0)) {
            revert MtxModeShape(mode);
        }
    }

    // ------------------------------------------------------------------ direct path

    /// @notice The caller pays gas itself; the fee is on top, `amount` arrives whole; never to the payee (CTR-MTX-08).
    function payWithFee(
        address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef
    ) external returns (bool) {
        address payer = _msgSender();
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) {
            if (feeRecipient == to) revert FeeRecipientIsPayee();
            _transfer(payer, feeRecipient, feeAmount);
        }
        _transfer(payer, to, amount);
        emit PaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }

    function _erc1271Gas(address from) internal view override returns (uint256) {
        bytes32 h = _SMART_KEY_CLONE_CODEHASH;
        return h != bytes32(0) && from.codehash == h ? 400_000 : 50_000;
    }
}
