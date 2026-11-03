// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "./TokenStore.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IRescuable} from "../governance/IRescuable.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IUALedger} from "./IUALedger.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the struct of their kind and run its pipeline; receiver-pays
///         (CTR-MTX-05/06). Features, owner and roles (CTR-GOV-01) live in `GovernanceBase`, init and provenance in the
///         ERC-7201 namespace `scaas.token`. Pay (`mtxPay`, `mtxPayMeta`, their `ua*` twins, `payWithFee`,
///         `mtxPayReceiverFee`) works only with
///         `PAYABLE`; a `MetaTransfer` (with or without `entryRef`) is never gated. Hedera is the immutable
///         `IS_HEDERA` (CTR-TOK-23): HIP-632 signatures through `MtxPipelineLib` (which calls `HederaLib`).
abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, GovernanceBase, IRescuable {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    bytes32 private constant RELAY_FEE_TYPEHASH = keccak256(
        "RelayFee(address from,address target,bytes32 callDataHash,address payee,uint256 value,uint256 validUntil,address relayer)"
    );
    bytes32 private constant UA_RELAY_FEE_TYPEHASH = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 validUntil,address relayer)"
    );

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SmartKeyAccount implementation of this chain (0 = none). Only its EIP-1167 clones get 400k gas for
    ///         ERC-1271; every other contract wallet 50k.
    address public immutable SMART_KEY_ACCOUNT_IMPL;

    error NotFactory();
    error AlreadyInitialized();
    error MtxModeShape(uint32 mode);
    /// @notice Wrong underlying count for the tier (0 / 1 / 2–8).
    error UnderlyingCountInvalid(uint256 n);

    /// @dev Runs ONCE on the implementation and locks it, so nobody can `initialize` it. `env` is the release's
    ///      deployment environment (plan 5g-Z2, `OpenFactory.deployImplementation` appends it): the factory, `chain_uid`,
    ///      the chain's UA registry (0 = no UA ledger), the `SmartKeyAccount` implementation, Hedera.
    constructor(Env memory env)
        ERC20MetaTx(env.chainUid, env.registry, env.smartKeyAccountImpl, env.hedera)
    {
        FACTORY = env.factory;
        _SELF = address(this);
        SMART_KEY_ACCOUNT_IMPL = env.smartKeyAccountImpl;
        TokenStore.$().initialized = true;
    }

    /// @notice The factory calls it in the SAME call as CREATE2 (CTR-TOK-25). `initArgs = abi.encode(TokenConfig)`
    ///         (the kinds of this repository). A UA registry must name this chain's `chain_uid` (CTR-UA-19).
    function initialize(address creator_, uint64 version_, bytes calldata initArgs) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_REGISTRY != address(0)) {
            bytes32 u = IUARegistry(_REGISTRY).chainUid();
            if (u != CHAIN_UID) revert UARegistryChainUid(u, CHAIN_UID);
        }
        TokenStore.TokenStorage storage t = TokenStore.$();
        if (t.initialized) revert AlreadyInitialized();
        t.initialized = true;
        t.creator = creator_;
        t.version = version_;
        _initRaw(initArgs);
    }

    /// @notice No underlying (the `NORMAL*` kinds); `WrappedToken` lists its legs. Read by the factory's index.
    function underlyings() public view virtual returns (address[] memory us) {}

    /// @dev The kind checks its fields of `cfg` (`ConfigFieldForOtherKind` for another kind's), calls `_setMetadata`
    ///      and `GovernanceLib.init`.
    function _init(TokenConfig memory cfg) internal virtual;

    /// @dev `_init` of the decoded config; a kind near the size ceiling hands the raw bytes to a library instead, so no
    ///      `TokenConfig` coder stays in it (`ZetherWrappedLib`, size lever 1, owner 2026-11-01).
    function _initRaw(bytes calldata initArgs) internal virtual {
        _init(abi.decode(initArgs, (TokenConfig)));
    }

    /// @dev `ConfigFieldForOtherKind` for a set field the kind does not use; `conf` is used only by `*_ZETHER`; `maxSupply`
    ///      only by `WRAPPED*`, as `legs`.
    function _requireUnused(TokenConfig memory cfg, bool supply, bool legs, bool rate, bool conf) internal pure {
        if (supply && (cfg.initialSupply != 0 || cfg.initialHolder != address(0))) revert ConfigFieldForOtherKind(1);
        if (legs && cfg.legs.length != 0) revert ConfigFieldForOtherKind(2);
        if (legs && cfg.maxSupply != 0) revert ConfigFieldForOtherKind(5);
        if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert ConfigFieldForOtherKind(3);
        ConfidentialConfig memory c = cfg.conf;
        if (conf && (c.auditorKey.length != 0 || c.shieldScale != 0 || c.maxShielded != 0
            || c.confidentialFee != 0 || c.disclosureMode != 0 || c.auditorMode != 0 || c.minDecoyFee != 0)) {
            revert ConfigFieldForOtherKind(4);
        }
    }

    function _setMetadata(string memory n, string memory sym, uint8 d) internal {
        TokenStore.TokenStorage storage t = TokenStore.$();
        t.name = n;
        t.symbol = sym;
        t.decimals = d;
        t.kind = kind();
    }

    function name() public view override returns (string memory) { return TokenStore.$().name; }
    function symbol() public view override returns (string memory) { return TokenStore.$().symbol; }
    function decimals() public view override returns (uint8) { return TokenStore.$().decimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function creator() external view returns (address) { return TokenStore.$().creator; }
    function version() external view returns (uint64) { return TokenStore.$().version; }
    /// @notice CTR-TOK-21 kind: 0 `NORMAL`, 1 `WRAPPED`, 2 `NORMAL_ZETHER`, 3 `WRAPPED_ZETHER`; a constant of the
    ///         implementation, so the factory can check it before any clone exists.
    function kind() public pure virtual returns (uint8);

    // ------------------------------------------------------------------ features, owner, roles (CTR-TOK-22)

    /// @dev One guard over every entry point (CTR-MTX-18), the role and owner functions too (W-Q).
    function _guardIn() internal override returns (bool) { return _enter(); }
    function _guardOut(bool outer) internal override { _exit(outer); }

    function _caller() internal view override returns (address) { return _msgSender(); }
    /// @dev The `NORMAL*` masks (spec §1.2): roles bit 1, no contract-only bit; `WrappedToken` overrides both. Every token
    ///      kind: scalar bit 1, no scope.
    function _roleBits() internal pure virtual override returns (uint256) { return GovernanceBits.NORMAL_ROLES; }
    function _contractOnlyBits() internal pure virtual override returns (uint256) { return 0; }
    function _scalarBits() internal pure override returns (uint256) { return GovernanceBits.TOKEN_SCALAR; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }

    /// @notice ERC-165; `IERC20Payment` only while `PAYABLE` is set, `IRescuable` only while `RESCUABLE` is.
    function supportsInterface(bytes4 id) external view returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IERC20).interfaceId || id == type(IMetaTx).interfaceId
            || id == type(IERC20MetaTx).interfaceId || id == type(IGovernance).interfaceId
            || (id == type(IERC20Payment).interfaceId && GovernanceLib.hasFeature(GovernanceBits.PAYABLE))
            || (id == type(IRescuable).interfaceId && GovernanceLib.hasFeature(GovernanceBits.RESCUABLE))
            || (id == type(IUALedger).interfaceId && _REGISTRY != address(0));
    }

    /// @notice CTR-GOV-06 (spec §6.2): one direct entry on every kind, anyone, not allowlisted; `NORMAL*` pays the whole
    ///         balance (`GovernanceLib.rescue`), `WRAPPED*` overrides it with `WrappedLib.rescue`.
    function rescue(address asset) external virtual nonReentrant {
        GovernanceLib.rescue(asset);
    }

    /// @notice Immutable: set by `init` with bit 17, no writer after.
    function rescueTo() external view returns (address) {
        return GovernanceLib.$().rescueTo;
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
        _executeTransfer(t, 0, signature);
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
        _executeTransfer(t, 0, signature);
        return true;
    }

    /// @notice Payment `payId` on its own lane `payLane(payId)`, nonce 0 (CTR-MTX-10).
    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _executeTransfer(_pay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient), 0, signature);
        return true;
    }

    /// @notice CTR-MTX-26: the payment id that commits to its metadata `meta = abi.encode(uint16 schema, bytes body)`.
    function metaPayId(bytes32 salt, bytes memory meta) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)));
    }

    /// @notice `mtxPay` with `payId = metaPayId(salt, meta)` (CTR-MTX-26): the same `MetaTransfer`, digest, lane and
    ///         nonce; `PaymentMeta` before `PaymentSettled`. `meta` is hashed and logged, never parsed.
    function mtxPayMeta(
        address from, address to, uint256 amount, bytes32 salt, bytes memory meta, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(from, to, amount, salt, meta, validUntil, mode, relayer, fee, feeRecipient, signature);
        return true;
    }

    /// @dev `PaymentMeta`, then `mtxPay`'s struct and pipeline. Spec R11 (`via_ir` off): with `bytes calldata meta` the
    ///      entry has 13 argument slots, one too many for the legacy ABI decoder; `bytes memory` is the same ABI type
    ///      (`bytes`, same selector) in one slot. The 12 slots, the return and the `nonReentrant` flag leave no room
    ///      for a local in the entry, so it passes its arguments here in order (each one DUP15) and `payId` lives here.
    function _payMeta(
        address from, address to, uint256 amount, bytes32 salt, bytes memory meta, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) private {
        bytes32 payId = metaPayId(salt, meta);
        emit PaymentMeta(payId, meta);
        _executeTransfer(_pay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient), 0, signature);
    }

    /// @dev The struct of `mtxPay` and `mtxPayMeta`: `MetaTransfer{entryRef: payId, batch: payLane(payId), nonce: 0}`.
    function _pay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient
    ) private pure returns (MetaTxLib.MetaTransfer memory t) {
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
    }

    // ------------------------------------------------------------------ named UA functions (CTR-UA-26)

    /// @notice `uaExecuteTransfer(UAMetaTransfer{from, to, amount, 0, batch, nonce, validUntil, mode, relayer, 0, 0})`.
    function uaTransfer(
        bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, IUARegistry.UASig calldata auth
    ) external nonReentrant returns (bool) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        MetaTxLib.UAMetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        _uaExecuteTransfer(t, 0, auth);
        return true;
    }

    function uaTransferWithFee(
        bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth
    ) external nonReentrant returns (bool) {
        _requireFeeShape(mode, feeRecipient);
        MetaTxLib.UAMetaTransfer memory t;
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
        _uaExecuteTransfer(t, 0, auth);
        return true;
    }

    /// @notice Payment `payId` on its lane `payLane(payId)`, nonce 0, as `mtxPay`.
    function uaPay(
        bytes32 from, bytes32 to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _uaExecuteTransfer(_uaPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient), 0, auth);
        return true;
    }

    /// @notice `uaPay` with `payId = metaPayId(salt, meta)` (CTR-MTX-26), as `mtxPayMeta`.
    function uaPayMeta(
        bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes memory meta, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _uaPayMeta(from, to, amount, salt, meta, validUntil, mode, relayer, fee, feeRecipient, auth);
        return true;
    }

    /// @dev `PaymentMeta`, then `uaPay`'s struct and pipeline (the stack as `_payMeta`).
    function _uaPayMeta(
        bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes memory meta, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth
    ) private {
        bytes32 payId = metaPayId(salt, meta);
        emit PaymentMeta(payId, meta);
        _uaExecuteTransfer(_uaPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient), 0, auth);
    }

    /// @dev The struct of `uaPay` and `uaPayMeta`: `UAMetaTransfer{entryRef: payId, batch: payLane(payId), nonce: 0}`.
    function _uaPay(
        bytes32 from, bytes32 to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient
    ) private pure returns (MetaTxLib.UAMetaTransfer memory t) {
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
    }

    // ------------------------------------------------------------------ receiver-pays (CTR-MTX-05, CTR-MTX-06)

    function receiverFeeDigest(MetaTxLib.MetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return MtxPipelineLib.receiverFeeDigest(_domainSeparatorV4(), false, _padded(t), fee, feeRecipient, validUntil);
    }

    function uaReceiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return MtxPipelineLib.receiverFeeDigest(_domainSeparatorV4(), true, t, fee, feeRecipient, validUntil);
    }

    /// @notice The payer's payment runs untouched; then the payee, who co-signed `ReceiverFee` nesting that payment, pays
    ///         `fee` to `feeRecipient` in the same transaction.
    function mtxPayReceiverFee(
        MetaTxLib.MetaTransfer calldata t, bytes calldata payerSig,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        if (t.entryRef == 0 || t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || t.batch != payLane(t.entryRef) || t.nonce != 0
            || feeRecipient == address(0)) revert ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert ReceiverFeeAmount(fee, t.value);
        if (feeRecipient == t.to) revert FeeRecipientIsPayee();
        if (feeRecipient == address(this)) revert TransferToSelf();
        _notPool(feeRecipient); // C5-3
        bytes32 d = _executeTransfer(t, 0, payerSig);
        MtxPipelineLib.requireSignature(
            _mtxCtx(), t.to, receiverFeeDigest(t, fee, feeRecipient, rfValidUntil), payeeSig);
        _transfer(t.to, feeRecipient, fee);
        emit ReceiverFeePaid(d, t.to, feeRecipient, fee);
        return true;
    }

    /// @notice The UA twin of `mtxPayReceiverFee` (CTR-MTX-05/06 on ids): the same shape on `t`, then the payer's
    ///         `UAMetaTransfer` through the typed UA pipeline; the payee `t.to` co-signs `UAReceiverFee` nesting it —
    ///         a native id itself (ECDSA, ERC-1271, HIP-632), a derived one through the registry under `receiver-fee` —
    ///         and pays `fee` out of what it received. A `UA_POOL` recipient is refused before any move (a move to the
    ///         pool's address would credit its slot with no UA balance behind it).
    function uaPayReceiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        if (t.entryRef == 0 || t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || t.batch != payLane(t.entryRef) || t.nonce != 0
            || feeRecipient == address(0)) revert ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert ReceiverFeeAmount(fee, t.value);
        bytes32 to = MetaTxLib.pad(feeRecipient);
        if (to == t.to) revert FeeRecipientIsPayee();
        // early only: without it the fee's `_uaMove` reverts the whole call with the same `TransferToSelf`
        if (feeRecipient == address(this)) revert TransferToSelf();
        if (feeRecipient == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        bytes32 d = _uaExecuteTransfer(t, 0, payerAuth);
        MtxPipelineLib.authorize(_mtxCtx(), t.to, UAKinds.PURPOSE_RECEIVER_FEE,
            uaReceiverFeeDigest(t, fee, feeRecipient, rfValidUntil), payeeAuth);
        _uaMove(t.to, to, fee);
        emit UAReceiverFeePaid(d, t.to, feeRecipient, fee);
        return true;
    }

    // ------------------------------------------------------------------ relay fee (CTR-MTX-27, TS-D19)

    /// @notice The payment a relay's router takes (never allowlisted: `relayer` is the direct caller). `from` signed
    ///         `RelayFee` with the router as `relayer`, so only the router's own call matches the signature; `payee` gets
    ///         `value` on lane `payLane(ref)`, nonce 0, fee `NONE`, `ref` = the router's `relayRef(target, callData)`.
    function mtxRelayFee(address from, address target, bytes32 callDataHash, address payee, uint256 value,
        uint256 validUntil, bytes calldata sig) external nonReentrant
    {
        _executeTransfer(_pay(from, payee, value, _relayRef(target, callDataHash), validUntil,
            MetaTxLib.MODE_RESTRICT_RELAYER, msg.sender, 0, address(0)),
            _relayHash(RELAY_FEE_TYPEHASH, MetaTxLib.pad(from), target, callDataHash, MetaTxLib.pad(payee), value, validUntil), sig);
    }

    /// @notice `mtxRelayFee` on ids.
    function uaRelayFee(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value,
        uint256 validUntil, IUARegistry.UASig calldata auth) external nonReentrant
    {
        _uaExecuteTransfer(_uaPay(from, payee, value, _relayRef(target, callDataHash), validUntil,
            MetaTxLib.MODE_RESTRICT_RELAYER, msg.sender, 0, address(0)),
            _relayHash(UA_RELAY_FEE_TYPEHASH, from, target, callDataHash, payee, value, validUntil), auth);
    }

    function _relayRef(address target, bytes32 callDataHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, callDataHash));
    }

    /// @dev The struct both entries sign; `relayer` is `msg.sender` (an address and its padded id hash alike).
    function _relayHash(bytes32 typehash, bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value,
        uint256 validUntil) private view returns (bytes32)
    {
        return keccak256(abi.encode(typehash, from, target, callDataHash, payee, value, validUntil, msg.sender));
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
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
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

    /// @notice `payWithFee` to a derived payee (CTR-UA-28): the caller pays `amount` into `to`'s UA balance and the fee
    ///         on top to `feeRecipient` (an address: never the payee; `UA_POOL` and the token are refused by `_update`).
    function payWithFeeToUA(
        bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _requireDerivedReceiver(to);
        bytes32 payer = MetaTxLib.pad(_msgSender());
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) _transfer(_msgSender(), feeRecipient, feeAmount);
        _uaMove(payer, to, amount);
        emit UAPaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }
}
