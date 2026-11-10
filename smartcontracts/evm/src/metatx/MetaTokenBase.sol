// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "./TokenStore.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IRescuable} from "../governance/IRescuable.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxBase, MetaTxBaseCore} from "./MetaTxBase.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IUALedger} from "./IUALedger.sol";
import {ILiquidityPullToken} from "../trade/ITradeToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IFactoryToken, requireRegOfKind} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the `UAMetaTransfer` of their operation and run its pipeline;
///         receiver-pays (CTR-MTX-05/06); one form per operation for native and derived ids (ua-mtx-merge T2: today's
///         `ua*` bodies under the `mtx*` names, the address bodies in legacy/ua-mtx-merge/). Features, admin and roles
///         (CTR-GOV-01) live in `GovernanceBase`, init and provenance in the ERC-7201 namespace `scaas.token`. Pay
///         (`mtxPay`, `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`, each with `PayMeta` last) works only with `PAYABLE`; a
///         `UAMetaTransfer` through `mtxExecuteTransfer` (with or without `entryRef`) is never gated. Chain-neutral code
///         (CTR-TOK-29): the chain values (`chain_uid`, the UA registry, the router, the `SmartKeyAccount` implementation,
///         Hedera, the dependencies) are the instance's `ChainEnv`, appended to its clone's code by the factory and read
///         from there (`ChainEnvCode`); the implementation reads an all-zero env and can sign nothing. Hedera
///         (`IS_HEDERA()`, CTR-TOK-23): HIP-632 signatures through `MtxPipelineLib` (which calls `HederaLib`).
abstract contract MetaTokenBase is ERC20MetaTx, GovernanceBaseCore {
    /// @dev Pay-meta-tax spec §4 (O4): the payer's own lane `(from, batch)` and `nonce`; the struct without them is in
    ///      legacy/ua-mtx-merge/3e/.
    bytes32 private constant UA_RELAY_FEE_TYPEHASH = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"
    );

    /// @notice The factory, at the same address on every chain (chain-neutral spec §2.1): a chain-neutral immutable.
    address public immutable FACTORY;
    address private immutable _SELF;

    error NotFactory();
    error AlreadyInitialized();
    error MtxModeShape(uint32 mode);
    /// @notice Wrong underlying count for the tier (0 / 1 / 2–8).
    error UnderlyingCountInvalid(uint256 n);
    /// @notice T66b (spec 2026-11-09-t66b-library-organisation.md §4.5): module `i` of `implArgs` has no code.
    error ModuleMissing(uint256 i);
    /// @notice Module `i` is of another kind, group, factory, registry code hash or PQZ set (§4.5, Fable P2-1, P2-A).
    error ModuleMismatch(uint256 i);
    /// @notice A module-face entry called other than by DELEGATECALL from its token (M2).
    error NotDelegated();

    /// @dev M2: a body module's entry runs only by DELEGATECALL from a token's stub; called directly, `address(this)` is the
    ///      module itself (`_SELF`, its own immutable), and it reverts.
    modifier onlyDelegated() {
        if (address(this) == _SELF) revert NotDelegated();
        _;
    }

    /// @dev Runs ONCE on the implementation and locks it, so nobody can `initialize` it. Chain-neutral (chain-neutral spec
    ///      §2.1, plan T72): the factory's address and `implArgs` (values the same on every chain; plain kinds take none)
    ///      are the only arguments `OpenFactory.deployTokenImplementation` appends.
    constructor(address factory_) ERC20MetaTx(bytes32(0), address(0), address(0), false) GovernanceBaseCore(address(0)) {
        FACTORY = factory_;
        _SELF = address(this);
        TokenStore.$().initialized = true;
    }

    /// @notice The factory calls it in the SAME call as the clone's creation (CTR-TOK-25), on a clone carrying its env
    ///         (`EnvMissing`, Fable P3-4). `creatorId` the creator's UA id; `creator()` keeps an address, 0 for a derived
    ///         creator (whose id is in the factory's record; spec §4.4, Fable P2-3). `initArgs = abi.encode(TokenConfig)`
    ///         (the kinds of this repository). The registry's `chain_uid` is the factory's check, once per env (P3-1).
    function _initializeBody(bytes32 creatorId_, uint64 version_, bytes calldata initArgs) internal {
        if (msg.sender != FACTORY) revert NotFactory();
        ChainEnvCode.requirePresent();
        TokenStore.TokenStorage storage t = TokenStore.$();
        if (t.initialized) revert AlreadyInitialized();
        t.initialized = true;
        if (uint256(creatorId_) >> 160 == 0) t.creator = address(uint160(uint256(creatorId_)));
        t.version = version_;
        _initRaw(initArgs);
    }

    // ------------------------------------------------------------------ the chain environment (CTR-TOK-29)

    /// @notice This instance's env, decoded from its code; all zero on the implementation.
    function _chainEnvBody() internal view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }

    /// @notice The kind's checks of an env, by the factory at release deployment (the constructor checks of before).
    function _validateEnvBody(IFactoryToken.ChainEnv calldata env) internal view {
        _validateEnv(env);
    }

    /// @notice SmartKeyAccount implementation of this chain (0 = none). Only its EIP-1167 clones get 400k gas for
    ///         ERC-1271; every other contract wallet 50k.
    function SMART_KEY_ACCOUNT_IMPL() external view returns (address) {
        return ChainEnvCode.smartKeyAccountImpl();
    }

    /// @dev Plain kinds check nothing; a confidential layer overrides it (its library holds the body).
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view virtual {}

    function _chainUidInCode() internal pure override returns (bool) { return true; }

    function _chainUidRaw() internal view override returns (bytes32) { return ChainEnvCode.chainUid(); }

    /// @notice This instance's `chain_uid`; 0 on the implementation (a view: no revert).
    function chainUid() external view  returns (bytes32) { return ChainEnvCode.chainUid(); }

    /// @notice ERC-5267 under the clone's `chain_uid` (`ChainUidZero` on the implementation): the salt every digest uses.
    function _eip712DomainBody() internal view override returns (
        bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory
    ) {
        return _eip712DomainUnder(_chainUid());
    }

    /// @dev No cache (chain-neutral spec §2.4): rebuilt under the clone's `chain_uid` on every call.
    function _domainSeparatorV4() internal view override returns (bytes32) { return _separator(_chainUid()); }

    function _registry() internal view override returns (address) { return ChainEnvCode.registry(); }

    function _hedera() internal view override returns (bool) { return ChainEnvCode.hedera(); }

    function _govRouter() internal view override returns (address) { return ChainEnvCode.govRouter(); }

    /// @dev The one reader of the pipeline's values: the head once, the separator under its `chain_uid` (0: the
    ///      implementation, `ChainUidZero`), the `SmartKeyAccount` clone code hash recomputed (chain-neutral spec §2.2).
    function _mtxCtx() internal view override returns (MtxPipelineLib.Ctx memory) {
        ChainEnvCode.Head memory h = ChainEnvCode.head();
        if (h.chainUid == bytes32(0)) revert ChainUidZero();
        address ska = h.smartKeyAccountImpl;
        return MtxPipelineLib.Ctx(_separator(h.chainUid), h.registry, ska == address(0) ? bytes32(0) : keccak256(
            abi.encodePacked(hex"363d3d373d3d3d363d73", ska, hex"5af43d82803e903d91602b57fd5bf3")), h.hedera);
    }

    /// @notice No underlying (the `NORMAL*` kinds); `WrappedToken` lists its legs. Read by the factory's index.
    function _underlyingsBody() internal view virtual returns (address[] memory us) {}

    /// @dev The kind checks its fields of `cfg` (`ConfigFieldForOtherKind` for another kind's), calls `_setMetadata`
    ///      and `GovernanceLib.init`.
    function _init(IFactoryToken.TokenConfig memory cfg) internal virtual;

    /// @dev `_init` of the decoded config; a kind near the size ceiling hands the raw bytes to a library instead, so no
    ///      `TokenConfig` coder stays in it (`ZetherWrappedLib`, size lever 1, owner 2026-11-01).
    function _initRaw(bytes calldata initArgs) internal virtual {
        _init(abi.decode(initArgs, (IFactoryToken.TokenConfig)));
    }

    /// @dev `ConfigFieldForOtherKind` for a set field the kind does not use; `conf` is used only by `*_ZETHER`; `maxSupply`
    ///      only by `WRAPPED*`, as `legs`; `reg` only by the regulated kinds (`requireRegOfKind` on `kind()`).
    function _requireUnused(IFactoryToken.TokenConfig memory cfg, bool supply, bool legs, bool rate, bool conf) internal pure {
        requireRegOfKind(kind(), cfg.reg);
        if (supply && (cfg.initialSupply != 0 || cfg.initialHolder != address(0))) revert IFactoryToken.ConfigFieldForOtherKind(1);
        if (legs && cfg.legs.length != 0) revert IFactoryToken.ConfigFieldForOtherKind(2);
        if (legs && cfg.maxSupply != 0) revert IFactoryToken.ConfigFieldForOtherKind(5);
        if (rate && (cfg.rate.rateDelay != 0 || cfg.rate.maxRateStepBps != 0)) revert IFactoryToken.ConfigFieldForOtherKind(3);
        IFactoryToken.ConfidentialConfig memory c = cfg.conf;
        if (conf && (c.auditorKey.length != 0 || c.shieldScale != 0 || c.maxShielded != 0
            || c.confidentialFee != 0 || c.disclosureMode != 0 || c.auditorMode != 0 || c.minDecoyFee != 0
            || c.pqzVerifyMode != 0 || c.pqzVerifierUA != 0 || c.pqzVerifierFixed || c.proofStore != 0)) {
            revert IFactoryToken.ConfigFieldForOtherKind(4);
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
    function IS_HEDERA() external view returns (bool) { return _IS_HEDERABody(); }
    function _creatorBody() internal view returns (address) { return TokenStore.$().creator; }
    function _versionBody() internal view returns (uint64) { return TokenStore.$().version; }
    /// @notice CTR-TOK-21 kind: 0 `NORMAL`, 1 `WRAPPED`, 2 `NORMAL_ZETHER`, 3 `WRAPPED_ZETHER`; a constant of the
    ///         implementation, so the factory can check it before any clone exists.
    function kind() public pure virtual returns (uint8);

    // ------------------------------------------------------------------ features, admin, roles (CTR-TOK-22)

    // ------------------------------------------------------------------ the forward stubs (T66b, spec §4.1 rule 2, S1, S2)

    /// @dev S1: a guarded entry (today's `nonReentrant` or `governed`; on a token `_guardIn` is `_enter`): enter the one guard,
    ///      DELEGATECALL this call's calldata to `module`, its revert data verbatim on failure (the revert undoes the enter), else
    ///      exit the guard and return its return data verbatim. Never a modifier with an assembly return (Fable P1-1): its exit
    ///      would not run, the guard would stay set for the rest of the transaction.
    function _forward(address module) internal {
        bool outer = _enter();
        (bool ok, bytes memory ret) = module.delegatecall(msg.data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
        _exit(outer);
        assembly ("memory-safe") {
            return(add(ret, 32), mload(ret))
        }
    }

    /// @dev S2: an unguarded entry: the same copy and return, no guard.
    function _forwardRaw(address module) internal {
        (bool ok, bytes memory ret) = module.delegatecall(msg.data);
        assembly ("memory-safe") {
            if iszero(ok) { revert(add(ret, 32), mload(ret)) }
            return(add(ret, 32), mload(ret))
        }
    }

    /// @dev S2: a `view` entry (the module's body writes nothing): `_forwardRaw` under the registry's R2 cast.
    function _forwardView(address module) internal view {
        function(address) f = _forwardRaw;
        function(address) view v;
        assembly ("memory-safe") {
            v := f
        }
        v(module);
    }

    /// @dev S2: a `pure` entry, the same cast.
    function _forwardPure(address module) internal pure {
        function(address) f = _forwardRaw;
        function(address) pure v;
        assembly ("memory-safe") {
            v := f
        }
        v(module);
    }

    /// @dev One guard over every entry point (CTR-MTX-18), the role and admin functions too (W-Q).
    function _guardIn() internal override returns (bool) { return _enter(); }
    function _guardOut(bool outer) internal override { _exit(outer); }

    function _caller() internal view override returns (address) { return _msgSender(); }
    /// @dev The `NORMAL*` masks (spec §1.2): roles bit 1, no contract-only bit; `WrappedToken` overrides both. Every token
    ///      kind: scalar bit 1, no scope.
    function _roleBits() internal pure virtual override returns (uint256) { return GovernanceBits.NORMAL_ROLES; }
    function _contractOnlyBits() internal pure virtual override returns (uint256) { return 0; }
    function _scalarBits() internal pure virtual override returns (uint256) { return GovernanceBits.TOKEN_SCALAR; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }
    function _uaRegistry() internal view override returns (address) { return _registry(); }

    /// @notice ERC-165; `IERC20Payment` only while `PAYABLE` is set, `IRescuable` only while `RESCUABLE` is;
    ///         `ILiquidityPullToken` on every kind (CTR-DEX-30: the node's pre-check of a liquidity input).
    function _supportsInterfaceBody(bytes4 id) internal view virtual returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IERC20).interfaceId || id == type(IMetaTx).interfaceId
            || id == type(IERC20MetaTx).interfaceId || id == type(IGovernance).interfaceId
            || id == type(ILiquidityPullToken).interfaceId
            || (id == type(IERC20Payment).interfaceId && GovernanceLib.hasFeature(GovernanceBits.PAYABLE))
            || (id == type(IRescuable).interfaceId && GovernanceLib.hasFeature(GovernanceBits.RESCUABLE))
            || (id == type(IUALedger).interfaceId && _registry() != address(0));
    }

    /// @notice CTR-GOV-06 (spec §6.2): one direct entry on every kind, anyone, not allowlisted; `NORMAL*` pays the whole
    ///         balance (`GovernanceLib.rescue`), `WRAPPED*` overrides it with `WrappedLib.rescue`.
    function _rescueBody(address asset) internal virtual {
        GovernanceLib.rescue(asset);
    }

    /// @notice Immutable: set by `init` with bit 17, no writer after.
    function _rescueToBody() internal view returns (address) {
        return GovernanceLib.$().rescueTo;
    }

    /// @notice A client convention, not enforced (pay-meta-tax spec O3): a client that wants one payment per request
    ///         signs on this lane at nonce 0; the contract does not care.
    function _payLaneBody(bytes32 payId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)));
    }

    // ------------------------------------------------------------------ named functions (CTR-MTX-09, CTR-UA-26)

    /// @notice `mtxExecuteTransfer(UAMetaTransfer{from, to, amount, 0, batch, nonce, validUntil, mode, relayer, 0, 0})`.
    function _mtxTransferBody(
        bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, IUARegistry.UASig calldata auth
    ) internal returns (bool) {
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

    function _mtxTransferWithFeeBody(
        bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth
    ) internal returns (bool) {
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
    function _mtxPayBody(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth, MetaTxLib.PayMeta calldata meta) internal returns (bool)
    {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(t.entryRef, meta);
        _uaExecuteTransfer(t, 0, auth, 0, 0);
        _payRecord(meta, t.to, t.value); // the fee is on top: `to` received `value`
        return true;
    }

    /// @notice CTR-MTX-26 (spec §3.1): the commitment of a `PayMeta`, under the versioned tag `scaas.pay.meta.v3`.
    function _metaPayIdBody(MetaTxLib.PayMeta calldata meta) internal pure returns (bytes32) {
        return _pipeMetaPayId(meta);
    }

    /// @dev Spec §3.2, in order: a non-zero salt, `schema == 0` iff the body is empty, no `save` without a `payNo`,
    ///      `entryRef == metaPayId(m)`; then `PaymentMeta`. Every pay entry calls it after its gates, before any signature.
    function _payMeta(bytes32 entryRef, MetaTxLib.PayMeta calldata m) internal {
        _pipePayMeta(entryRef, m); // lever 5 (pay-meta-tax spec §6.4); T66b: compiled into module P
    }

    /// @dev Plan T83 (owner 2026-11-09): with `m.save`, `payNo`'s record of what `to` received; every public pay entry calls
    ///      it last, after its transfer (the body in the linked library, `scaas.pay.records`).
    function _payRecord(MetaTxLib.PayMeta calldata m, bytes32 to, uint256 received) internal {
        if (m.save) _pipePayRecord(m.payNo, to, received);
    }

    /// @notice Plan T83: the stored payments of `payNo` (`PayMeta.save`); a confidential pay is never recorded.
    function _paymentCountBody(bytes32 payNo) internal view returns (uint256) {
        return _pipePaymentCount(payNo);
    }

    /// @notice Records `[offset, offset + limit)` of `payNo`, cut at the end; the reader filters `to` and adds up itself.
    function _paymentsOfBody(bytes32 payNo, uint256 offset, uint256 limit) internal view returns (MetaTxLib.PayRecord[] memory)
    {
        return _pipePaymentsOf(payNo, offset, limit);
    }

    // ------------------------------------------------------------------ receiver-pays (CTR-MTX-05, CTR-MTX-06)

    function _receiverFeeDigestBody(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil) internal view returns (bytes32)
    {
        return _pipeReceiverFeeDigest(_domainSeparatorV4(), t, fee, feeRecipient, validUntil);
    }

    /// @notice CTR-MTX-05/06 on ids: the shape on `t`, then the payer's `UAMetaTransfer` through the typed pipeline,
    ///         untouched; the payee `t.to` co-signs `UAReceiverFee` nesting it — a native id itself (ECDSA, ERC-1271,
    ///         HIP-632), a derived one through the registry under `receiver-fee` — and pays `fee` out of what it
    ///         received. A `UA_POOL` recipient is refused before any move (a move to the pool's address would credit its
    ///         slot with no UA balance behind it).
    function _mtxPayReceiverFeeBody(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth,
        MetaTxLib.PayMeta calldata meta
    ) internal returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(t.entryRef, meta); // `entryRef` ≠ 0 with it; any lane (spec §2.5, O3)
        _receiverFee(t, payerAuth, fee, feeRecipient, rfValidUntil, payeeAuth);
        _payRecord(meta, t.to, t.value - fee); // the payee paid `fee` out of `value` (`fee <= value` checked)
        return true;
    }

    /// @dev `mtxPayReceiverFee`'s body after `_payMeta` (its seven arguments leave no stack for the locals).
    function _receiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth
    ) private {
        if (t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || feeRecipient == address(0)) revert IMetaTokenV2.ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert IMetaTokenV2.ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert IMetaTokenV2.ReceiverFeeAmount(fee, t.value);
        bytes32 to = MetaTxLib.pad(feeRecipient);
        if (to == t.to) revert IERC20MetaTx.FeeRecipientIsPayee();
        // early only: without it the fee's `_uaMove` reverts the whole call with the same `TransferToSelf`
        if (feeRecipient == address(this)) revert IERC20MetaTx.TransferToSelf();
        if (feeRecipient == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
        _regFeeTo(to, fee);
        bytes32 d = _uaExecuteTransfer(t, 0, payerAuth, 0, 0);
        _pipeAuthorize(_mtxCtx(), t.to, UAKinds.PURPOSE_RECEIVER_FEE,
            _receiverFeeDigestBody(t, fee, feeRecipient, rfValidUntil), payeeAuth);
        _uaMove(t.to, to, fee);
        emit IMetaTokenV2.UAReceiverFeePaid(d, t.to, feeRecipient, fee);
    }

    // ------------------------------------------------------------------ relay fee (CTR-MTX-27, TS-D19)

    /// @notice The payment a relay's router takes (never allowlisted: `relayer` is the direct caller). `from` signed
    ///         `UARelayFee` with the router as `relayer`, so only the router's own call matches the signature; `payee`
    ///         gets `value` on the payer's lane `(from, batch)` at `nonce` (pay-meta-tax spec §4, O4: one signature runs
    ///         once, a call may be paid by several), fee `NONE`, `ref` = the router's `relayRef(target, callData)`.
    function _mtxRelayFeeBody(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value, uint256 batch,
        uint256 nonce, uint256 validUntil, IUARegistry.UASig calldata auth) internal {
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
    function _payWithFeeBody(
        address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta
    ) internal returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(entryRef, meta);
        address payer = _msgSender();
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
        if (feeAmount != 0) {
            if (feeRecipient == to) revert IERC20MetaTx.FeeRecipientIsPayee();
            _transfer(payer, feeRecipient, feeAmount);
        }
        _transfer(payer, to, amount);
        emit IERC20Payment.PaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        _payRecord(meta, MetaTxLib.pad(to), amount); // the fee is on top
        return true;
    }

    /// @notice `payWithFee` to a derived payee (CTR-UA-28): the caller pays `amount` into `to`'s UA balance and the fee
    ///         on top to `feeRecipient` (an address: never the payee; `UA_POOL` and the token are refused by `_update`).
    function _payWithFeeToUABody(
        bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta
    ) internal returns (bool) {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        _payMeta(entryRef, meta);
        _requireDerivedReceiver(to);
        bytes32 payer = MetaTxLib.pad(_msgSender());
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
        if (feeAmount != 0) _transfer(_msgSender(), feeRecipient, feeAmount);
        _uaMove(payer, to, amount);
        emit IUALedger.UAPaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        _payRecord(meta, to, amount);
        return true;
    }
}
