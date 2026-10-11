// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {AdminLib} from "./AdminLib.sol";
import {ITokenAdmin} from "./ITokenAdmin.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {HederaLib} from "../hedera/HederaLib.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the struct of their kind and run its pipeline; receiver-pays
///         (CTR-MTX-05/06). Features, owner and roles (CTR-TOK-22) live in `AdminLib`, init and provenance in the
///         ERC-7201 namespace `scaas.token`. Pay (`mtxPay`, `payWithFee`, `mtxPayReceiverFee`) works only with
///         `PAYABLE`; a `MetaTransfer` (with or without `entryRef`) is never gated. Hedera is the immutable
///         `IS_HEDERA` (CTR-TOK-23): HIP-632 signatures through `HederaLib`.
abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, ITokenAdmin {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    bytes32 internal constant RECEIVER_FEE_TYPEHASH =
        keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SmartKeyAccount implementation of this chain (0 = none). Only its EIP-1167 clones get 400k gas for
    ///         ERC-1271; every other contract wallet 50k.
    address public immutable SMART_KEY_ACCOUNT_IMPL;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    /// @notice Set on implementations deployed for Hedera (CTR-TOK-23): 64-byte signatures from accounts without code
    ///         take the HIP-632 path.
    bool public immutable IS_HEDERA;

    error NotFactory();
    error AlreadyInitialized();
    error MtxModeShape(uint32 mode);
    /// @notice Wrong underlying count for the tier (0 / 1 / 2–8).
    error UnderlyingCountInvalid(uint256 n);

    /// @dev Runs ONCE on the implementation and locks it, so nobody can `initialize` it.
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        ERC20MetaTx(chainUid_)
    {
        FACTORY = factory_;
        _SELF = address(this);
        SMART_KEY_ACCOUNT_IMPL = smartKeyAccountImpl_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        IS_HEDERA = isHedera_;
        AdminLib.$().initialized = true;
    }

    /// @notice The factory calls it in the SAME call as CREATE2 (CTR-TOK-25).
    function initialize(address creator_, uint64 version_, TokenConfig calldata cfg) external {
        if (msg.sender != FACTORY) revert NotFactory();
        AdminLib.TokenStorage storage t = AdminLib.$();
        if (t.initialized) revert AlreadyInitialized();
        t.initialized = true;
        t.creator = creator_;
        t.version = version_;
        _init(cfg);
    }

    /// @dev The kind checks its fields of `cfg` (`ConfigFieldForOtherKind` for another kind's), calls `_setMetadata`
    ///      and `AdminLib.init`.
    function _init(TokenConfig calldata cfg) internal virtual;

    /// @dev `ConfigFieldForOtherKind` for a set field the kind does not use; `conf` is used only by `*_ZETHER`.
    function _requireUnused(TokenConfig calldata cfg, bool supply, bool legs, bool rate, bool conf) internal pure {
        if (supply && (cfg.initialSupply != 0 || cfg.initialHolder != address(0))) revert ConfigFieldForOtherKind(1);
        if (legs && cfg.legs.length != 0) revert ConfigFieldForOtherKind(2);
        if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert ConfigFieldForOtherKind(3);
        ConfidentialConfig calldata c = cfg.conf;
        if (conf && (c.verifier != address(0) || c.auditorKey.length != 0 || c.shieldScale != 0 || c.maxShielded != 0
            || c.confidentialFee != 0 || c.disclosureMode != 0 || c.auditorMode != 0)) revert ConfigFieldForOtherKind(4);
    }

    function _setMetadata(string memory n, string memory sym, uint8 d) internal {
        AdminLib.TokenStorage storage t = AdminLib.$();
        t.name = n;
        t.symbol = sym;
        t.decimals = d;
    }

    function name() public view override returns (string memory) { return AdminLib.$().name; }
    function symbol() public view override returns (string memory) { return AdminLib.$().symbol; }
    function decimals() public view override returns (uint8) { return AdminLib.$().decimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function creator() external view returns (address) { return AdminLib.$().creator; }
    function version() external view returns (uint64) { return AdminLib.$().version; }
    /// @notice CTR-TOK-21 kind: 0 `NONE`, 1 `UNDERLYING`, 2 `NONE_ZETHER`, 3 `UNDERLYING_ZETHER`; a constant of the
    ///         implementation, so the factory can check it before any clone exists.
    function kind() public pure virtual returns (uint8);

    // ------------------------------------------------------------------ features, owner, roles (CTR-TOK-22)

    function features() external view returns (uint256) { return AdminLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return AdminLib.$().lockedFeatures; }
    function owner() external view returns (address) { return AdminLib.$().owner; }
    function pendingOwner() external view returns (address) { return AdminLib.$().pendingOwner; }
    function hasRole(uint8 bit, address account) external view returns (bool) { return AdminLib.hasRole(bit, account); }

    function grantRole(uint8 bit, address account) external { AdminLib.grantRole(bit, account, _msgSender()); }
    function revokeRole(uint8 bit, address account) external { AdminLib.revokeRole(bit, account, _msgSender()); }
    function renounceRole(uint8 bit) external { AdminLib.renounceRole(bit, _msgSender()); }
    function disableFeature(uint8 bit) external virtual { AdminLib.disableFeature(bit, _msgSender()); }
    function transferOwnership(address newOwner) external { AdminLib.transferOwnership(newOwner, _msgSender()); }
    function acceptOwnership() external { AdminLib.acceptOwnership(_msgSender()); }
    function renounceOwnership() external { AdminLib.renounceOwnership(_msgSender()); }

    /// @notice ERC-165; `IERC20Payment` only while `PAYABLE` is set.
    function supportsInterface(bytes4 id) external view returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IERC20).interfaceId || id == type(IMetaTx).interfaceId
            || id == type(IERC20MetaTx).interfaceId
            || (id == type(IERC20Payment).interfaceId && AdminLib.hasFeature(AdminLib.PAYABLE));
    }

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
        AdminLib.requireFeature(AdminLib.PAYABLE);
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

    // ------------------------------------------------------------------ receiver-pays (CTR-MTX-05, CTR-MTX-06)

    function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(RECEIVER_FEE_TYPEHASH, paymentDigest, fee, feeRecipient, validUntil)));
    }

    /// @notice The payer's payment runs untouched; then the payee, who co-signed `ReceiverFee` over the payer's
    ///         digest, pays `fee` to `feeRecipient` in the same transaction.
    function mtxPayReceiverFee(
        MetaTxLib.MetaTransfer calldata t, bytes calldata payerSig,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig
    ) external nonReentrant returns (bool) {
        AdminLib.requireFeature(AdminLib.PAYABLE);
        if (t.entryRef == 0 || t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || t.batch != payLane(t.entryRef) || t.nonce != 0
            || feeRecipient == address(0)) revert ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert ReceiverFeeAmount(fee, t.value);
        if (feeRecipient == t.to) revert FeeRecipientIsPayee();
        if (feeRecipient == address(this)) revert TransferToSelf();
        bytes32 d = _executeTransfer(t, payerSig);
        _requireValidSignature(t.to, receiverFeeDigest(d, fee, feeRecipient, rfValidUntil), payeeSig);
        _transfer(t.to, feeRecipient, fee);
        emit ReceiverFeePaid(d, t.to, feeRecipient, fee);
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
        AdminLib.requireFeature(AdminLib.PAYABLE);
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

    /// @dev Hedera (CTR-TOK-23): a 64-byte signature from an account without code is HIP-632; all else is EVM.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (IS_HEDERA && sig.length == 64 && !_isContract(from)) return HederaLib.requireValid(from, digest, sig);
        super._requireValidSignature(from, digest, sig);
    }

    function _erc1271Gas(address from) internal view override returns (uint256) {
        bytes32 h = _SMART_KEY_CLONE_CODEHASH;
        return h != bytes32(0) && from.codehash == h ? 400_000 : 50_000;
    }
}
