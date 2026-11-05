// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../metatx/WrappedToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {ZetherWrappedLib} from "./ZetherWrappedLib.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IZetherToken, IZetherWrappedToken} from "./IZetherToken.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `WRAPPED_ZETHER` (CTR-TOK-21): the wrapper of 1–8 legs with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED.** Any chain with EIP-2537 (BLS12-381). The legs, rates, reserves, `wrap`/`unwrap`,
///         `mtxWrap` and the rate and guardian roles are `WrappedToken`'s (`WrappedLib`); the layer adds
///         `mtxWrapShield` (a leg's underlying straight into a shielded balance, minted to the pool) and
///         `mtxUnshieldUnwrap` (a shielded balance straight out to a leg's underlying, burnt from the pool; to an
///         address or, through a SCaaS ledger leg, a UA). Reserve
///         invariant: `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` (the shielded value is public units in `SHIELD_POOL`, D19), by
///         construction (a wrap-shield mints `minted`, a multiple of the scale, to the pool, an unshield-unwrap burns
///         `amount·shieldScale` from it and pays `⌊amount·shieldScale·den/num⌋`, worth at most what it removes), and
///         `executeRate` checks it. Flags: `PAYABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE` (CTR-ZTH-47). Never on Hedera.
contract WrappedZetherToken is WrappedToken, ZetherLayer, IZetherWrappedToken {
    bytes32 private constant WRAP_SHIELD_TYPEHASH = keccak256(
        "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    // The typehashes of the unshield-unwrap entries are `ZetherWrappedLib`'s (CTR-ZTH-94).

    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env` (Hedera off: `ZetherLayer`
    ///      refuses a Hedera env); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        WrappedToken(envVersion, env, implArgs)
        ZetherLayer(env)
    {}

    /// @dev The legs (`WrappedToken`), restated for the second base.
    function underlyings() public view override(WrappedToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function kind() public pure override(WrappedToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_WRAPPED_ZETHER;
    }

    function _validBits() internal pure override(WrappedToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS;
    }

    /// @dev `WrappedToken`'s masks, restated for the second base.
    function _roleBits() internal pure override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES;
    }

    function _contractOnlyBits() internal pure override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY;
    }

    /// @dev Never reached: `_initRaw` is the kind's init.
    function _init(TokenConfig memory) internal override(WrappedToken, MetaTokenBase) {}

    function _initRaw(bytes calldata initArgs) internal override {
        ZetherWrappedLib.init(initArgs, TRANSFER_VERIFIER, _REGISTRY);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-ZTH-45)

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`) and credits the public-equivalent `minted`
    ///         (the leg's rate on the measured delta) as `minted / shieldScale` shielded units to `toUA`, minting `minted`
    ///         to `SHIELD_POOL`; `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount).
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable nonReentrant {
        address m = _msgSender();
        (,, uint256 minted) = WrappedLib.wrap(WrappedLib.indexOf(underlying), amountIn, m, msg.value, totalSupply());
        uint256 scale = ZetherLib.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        ZetherLib.shield(ZetherTypes.UA.wrap(toUA), minted / scale, _REGISTRY, m);
        _poolMove(bytes32(0), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), minted); // D19: minted to the pool
    }

    /// @notice The signed `mtxWrapShield`; as on the generic path, relayed it takes no coin (the native leg reverts).
    function mtxWrapShield(MetaTxLib.Envelope calldata e, address underlying, uint256 amountIn, bytes32 toUA, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(WRAP_SHIELD_TYPEHASH, IConfidentialWrappedToken.mtxWrapShield.selector, e, abi.encode(underlying, amountIn, toUA), sig);
    }

    /// @notice The unshield proof (`x.amount` and `x.recipient` in the statement; a direct call also binds
    ///         `x.underlying` and `x.minOut`), then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` from
    ///         its reserve to `x.recipient` — an address, or a derived UA through the leg's `transferToUA`
    ///         (`UALegNotLedger` otherwise, CTR-ZTH-51) — burning `amount·shieldScale` from `SHIELD_POOL`.
    ///         The leg first (cheap), the proof and the debit, then the payout from the leg's reserve (CEI: the debit
    ///         before the one outside call).
    function mtxUnshieldUnwrap(ZetherBurn calldata b, Unwrap calldata x, bytes calldata proof) external nonReentrant {
        proof;
        uint256 i = WrappedLib.indexOf(x.underlying);
        // a derived recipient: the leg's `transferToUA` checks it
        if (UAKinds.inNativeSpace(x.recipient)) _requirePayee(address(uint160(uint256(x.recipient))));
        uint256 wrapped = x.amount * ZetherLib.$().shieldScale;
        // the leg's quote before the proof: on a hybrid an empty reserve is ordinary (spec §5.4)
        WrappedLib.quoteTo(i, x.recipient, wrapped, x.minOut);
        // the binding and the proof: `ZetherWrappedLib`, from this call's own arguments (CTR-ZTH-94)
        uint256 fee = abi.decode(
            _lib(address(ZetherWrappedLib), ZetherWrappedLib.unshieldUnwrap.selector, abi.encode(_env())), (uint256));
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped); // D19: burn from the pool
        _fromPool(ZetherTypes.UA.wrap(b.beneficiaryUA), fee);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut);
    }

    /// @notice The signed form over `UAZetherUnshieldUnwrap` (R35: native and derived ids), the `Unwrap` leg a nested
    ///         struct; `ZetherWrappedLib` builds the struct's words and the op's call from this call's own arguments
    ///         (CTR-ZTH-94).
    function mtxUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, ZetherBurn calldata b, Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        (b, x, proof);
        (bytes32 th, bytes memory words, bytes memory data) =
            _built(address(ZetherWrappedLib), ZetherWrappedLib.uaUnwrapCall.selector, false);
        return _namedCallUA(th, e, words, data, auth);
    }

    /// @notice As `WrappedToken` (spec §6.2); restated for the second base.
    function rescue(address asset) external override(WrappedToken, MetaTokenBase) nonReentrant {
        WrappedLib.rescue(asset);
    }

    /// @notice As `WrappedToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(WrappedToken, GovernanceBase) nonReentrant {
        bool applied = GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());
        if (applied && bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    /// @notice The collateral check of a rate change counts the shielded value too.
    function executeRate() external override nonReentrant {
        WrappedLib.executeRate(_govSubject(), totalSupply()); // the shielded value sits in SHIELD_POOL (D19)
    }

    // ------------------------------------------------------------------ the layer's hooks

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(UAMetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._uaEnvelopeBinding(m);
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-ZTH-34)

    /// @notice `WrappedToken`'s first six, then the Zether ops and the two underlying paths, each `ABSOLUTE`, then
    ///         `WrappedToken`'s UA-5a two (`wrapToUA` `ABSOLUTE`, `unwrapToUA` `AMOUNT(1)`, CTR-UA-28).
    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return ZetherWrappedLib.selectors();
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel) || sel == IZetherWrappedToken.mtxUnshieldUnwrap.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == IConfidentialWrappedToken.mtxWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        return WrappedToken._mtxRule(sel);
    }

    /// @notice `WrappedToken`'s UA allowlist, the Zether ops and `mtxUnshieldUnwrap` (CTR-ZTH-51, UA-5c, as
    ///         `NormalZetherToken`); not `mtxWrapShield` (a UA wrap-shields in two signed steps, `uaWrap` then
    ///         `mtxShield`).
    function _uaAllowed(bytes4 sel) internal view override(WrappedToken, UAMetaTxBase) returns (bool) {
        return _isZetherOp(sel) || sel == IZetherWrappedToken.mtxUnshieldUnwrap.selector || WrappedToken._uaAllowed(sel);
    }
}
