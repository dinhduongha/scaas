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
import {IFactoryToken, requireRegOfKind} from "../factory/IFactoryToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the `UAMetaTransfer` of their operation and run its pipeline;
///         receiver-pays (CTR-MTX-05/06); one form per operation for native and derived ids (ua-mtx-merge T2: today's
///         `ua*` bodies under the `mtx*` names, the address bodies in legacy/ua-mtx-merge/). Features, owner and roles
///         (CTR-GOV-01) live in `GovernanceBase`, init and provenance in the ERC-7201 namespace `scaas.token`. Pay
///         (`mtxPay`, `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`, each with `PayMeta` last) works only with `PAYABLE`; a
///         `UAMetaTransfer` through `mtxExecuteTransfer` (with or without `entryRef`) is never gated. Hedera is the immutable
///         `IS_HEDERA` (CTR-TOK-23): HIP-632 signatures through `MtxPipelineLib` (which calls `HederaLib`).
abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, GovernanceBase, IRescuable {
    /// @dev Pay-meta-tax spec §4 (O4): the payer's own lane `(from, batch)` and `nonce`; the struct without them is in
    ///      legacy/ua-mtx-merge/3e/.
    bytes32 private constant UA_RELAY_FEE_TYPEHASH = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"
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
        GovernanceBase(env.govRouter)
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
    ///      only by `WRAPPED*`, as `legs`; `reg` only by the regulated kinds (`requireRegOfKind` on `kind()`).
    function _requireUnused(TokenConfig memory cfg, bool supply, bool legs, bool rate, bool conf) internal pure {
        requireRegOfKind(kind(), cfg.reg);
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
    function _scalarBits() internal pure virtual override returns (uint256) { return GovernanceBits.TOKEN_SCALAR; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }
    function _uaRegistry() internal view override returns (address) { return _REGISTRY; }

    /// @notice ERC-165; `IERC20Payment` only while `PAYABLE` is set, `IRescuable` only while `RESCUABLE` is.
    function supportsInterface(bytes4 id) public view virtual returns (bool) {
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

    /// @notice A client convention, not enforced (pay-meta-tax spec O3): a client that wants one payment per request
    ///         signs on this lane at nonce 0; the contract does not care.
    function payLane(bytes32 payId) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)));
    }

    // ------------------------------------------------------------------ named functions (CTR-MTX-09, CTR-UA-26)

    /// @notice `mtxExecuteTransfer(UAMetaTransfer{from, to, amount, 0, batch, nonce, validUntil, mode, relayer, 0, 0})`.
    function mtxTransfer(
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
        _uaExecuteTransfer(t, 0, auth, 0, 0);
        return true;
    }

    function mtxTransferWithFee(
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
        _uaExecuteTransfer(t, 0, auth, 0, 0);
        return true;
    }

    /// @notice The payment `t` with its metadata (CTR-MTX-10, CTR-MTX-26; pay-meta-tax spec §2.1): any lane, the nonce
    ///         space of `mtxExecuteTransfer` (O3); `t.entryRef == metaPayId(meta)` (O11), `PaymentMeta` first.
    function mtxPay(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth, MetaTxLib.PayMeta calldata meta)
        external nonReentrant returns (bool)
    {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(t.entryRef, meta);
        _uaExecuteTransfer(t, 0, auth, 0, 0);
        return true;
    }

    /// @notice CTR-MTX-26 (spec §3.1): the commitment of a `PayMeta`, under the versioned tag `scaas.pay.meta.v2`.
    function metaPayId(MetaTxLib.PayMeta calldata meta) public pure returns (bytes32) {
        return MtxPipelineLib.metaPayId(meta);
    }

    /// @dev Spec §3.2, in order: a non-zero salt, `schema == 0` iff the body is empty, `payNo` at most 256 bytes,
    ///      `entryRef == metaPayId(m)`; then `PaymentMeta`. Every pay entry calls it after its gates, before any signature.
    function _payMeta(bytes32 entryRef, MetaTxLib.PayMeta calldata m) internal {
        MtxPipelineLib.payMeta(entryRef, m); // lever 5 (pay-meta-tax spec §6.4): the body in the linked library
    }

    // ------------------------------------------------------------------ receiver-pays (CTR-MTX-05, CTR-MTX-06)

    function receiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return MtxPipelineLib.receiverFeeDigest(_domainSeparatorV4(), t, fee, feeRecipient, validUntil);
    }

    /// @notice CTR-MTX-05/06 on ids: the shape on `t`, then the payer's `UAMetaTransfer` through the typed pipeline,
    ///         untouched; the payee `t.to` co-signs `UAReceiverFee` nesting it — a native id itself (ECDSA, ERC-1271,
    ///         HIP-632), a derived one through the registry under `receiver-fee` — and pays `fee` out of what it
    ///         received. A `UA_POOL` recipient is refused before any move (a move to the pool's address would credit its
    ///         slot with no UA balance behind it).
    function mtxPayReceiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth,
        MetaTxLib.PayMeta calldata meta
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(t.entryRef, meta); // `entryRef` ≠ 0 with it; any lane (spec §2.5, O3)
        _receiverFee(t, payerAuth, fee, feeRecipient, rfValidUntil, payeeAuth);
        return true;
    }

    /// @dev `mtxPayReceiverFee`'s body after `_payMeta` (its seven arguments leave no stack for the locals).
    function _receiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth
    ) private {
        if (t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || feeRecipient == address(0)) revert ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert ReceiverFeeAmount(fee, t.value);
        bytes32 to = MetaTxLib.pad(feeRecipient);
        if (to == t.to) revert FeeRecipientIsPayee();
        // early only: without it the fee's `_uaMove` reverts the whole call with the same `TransferToSelf`
        if (feeRecipient == address(this)) revert TransferToSelf();
        if (feeRecipient == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        _regFeeTo(to, fee);
        bytes32 d = _uaExecuteTransfer(t, 0, payerAuth, 0, 0);
        MtxPipelineLib.authorize(_mtxCtx(), t.to, UAKinds.PURPOSE_RECEIVER_FEE,
            receiverFeeDigest(t, fee, feeRecipient, rfValidUntil), payeeAuth);
        _uaMove(t.to, to, fee);
        emit UAReceiverFeePaid(d, t.to, feeRecipient, fee);
    }

    // ------------------------------------------------------------------ relay fee (CTR-MTX-27, TS-D19)

    /// @notice The payment a relay's router takes (never allowlisted: `relayer` is the direct caller). `from` signed
    ///         `UARelayFee` with the router as `relayer`, so only the router's own call matches the signature; `payee`
    ///         gets `value` on the payer's lane `(from, batch)` at `nonce` (pay-meta-tax spec §4, O4: one signature runs
    ///         once, a call may be paid by several), fee `NONE`, `ref` = the router's `relayRef(target, callData)`.
    function mtxRelayFee(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value, uint256 batch,
        uint256 nonce, uint256 validUntil, IUARegistry.UASig calldata auth) external nonReentrant
    {
        _regFeeTo(payee, value);
        MetaTxLib.UAMetaTransfer memory t;
        t.from = from;
        t.to = payee;
        t.value = value;
        t.entryRef = _relayRef(target, callDataHash);
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        t.relayer = msg.sender;
        _uaExecuteTransfer(t, _relayHash(t, target, callDataHash), auth, 0, 0);
    }

    function _relayRef(address target, bytes32 callDataHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, callDataHash));
    }

    /// @dev The struct the payer signs, `UARelayFee`, from the payment `t` built of it; `relayer` is `msg.sender` (the
    ///      router).
    function _relayHash(MetaTxLib.UAMetaTransfer memory t, address target, bytes32 callDataHash)
        private view returns (bytes32)
    {
        return keccak256(abi.encode(UA_RELAY_FEE_TYPEHASH, t.from, target, callDataHash, t.to, t.value, t.batch, t.nonce,
            t.validUntil, msg.sender));
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
        address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(entryRef, meta);
        address payer = _msgSender();
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
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
        bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta
    ) external nonReentrant returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(entryRef, meta);
        _requireDerivedReceiver(to);
        bytes32 payer = MetaTxLib.pad(_msgSender());
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
        if (feeAmount != 0) _transfer(_msgSender(), feeRecipient, feeAmount);
        _uaMove(payer, to, amount);
        emit UAPaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }
}
