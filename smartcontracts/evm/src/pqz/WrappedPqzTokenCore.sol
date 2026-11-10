// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";

import {WrappedTokenCore} from "../metatx/WrappedTokenCore.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";
import {PqzWrappedLib} from "./PqzWrappedLib.sol";
import {IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IPqzToken, IPqzWrappedToken} from "./IPqzToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `WRAPPED_PQZ` (CTR-TOK-21, CTR-PQZ-22): the wrapper of 1–8 legs with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED.** Any chain whose `PQZ` precompile passes the self-test (`PqzSafety`); never on Hedera.
///         Legs, rates, reserves,
///         `wrap` / `unwrap` and the roles are `WrappedToken`'s; the layer adds `mtxWrapShield` (a leg's underlying
///         into a TRIVIAL pending entry, the public-equivalent minted to `SHIELD_POOL`; plan 5h D18, D19) and
///         `mtxUnshieldUnwrap` (a burn: `amount · shieldScale` burnt from `SHIELD_POOL`, then paid out of a leg's
///         reserve to an address or, through a SCaaS ledger leg, to a UA), as on `WRAPPED_ZETHER`. Reserve invariant
///         `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` (the shielded value is the pool's public units).
abstract contract WrappedPqzTokenCore is WrappedTokenCore, PqzLayer {
    bytes32 private constant WRAP_SHIELD_TYPEHASH = keccak256(
        "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_UNSHIELD_UNWRAP_TYPEHASH = keccak256(
        "UAPqzUnshieldUnwrap(bytes32 from,PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom)Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)"
    );

    /// @dev The factory's append (`OpenFactory.deployTokenImplementation`, chain-neutral spec §2.1): its address; no
    ///      `implArgs`. The env (`deps[ENV_PQZ_VERIFIER]` the release's `UAPqzVerifier`, CTR-ZTH-20 / CTR-PQZ-10; a
    ///      registry) is checked by `validateEnv` (`PqzStateLib`).
    constructor(address factory_, bytes memory implArgs) WrappedTokenCore(factory_, implArgs) {}

    /// @dev The legs (`WrappedToken`), restated for the second base.
    function _underlyingsBody() internal view virtual override(MetaTokenBase, WrappedTokenCore) returns (address[] memory) {
        return super._underlyingsBody();
    }

    function kind() public pure virtual override(MetaTokenBase, WrappedTokenCore) returns (uint8) {
        return TokenStore.KIND_WRAPPED_PQZ;
    }

    function _validBits() internal pure virtual override(GovernanceBaseCore, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | GovernanceBits.PQZ_KIND_BITS; // bit 24 (group 3h, PQZ proof path spec §5)
    }

    /// @dev `WrappedToken`'s masks, restated for the second base.
    function _roleBits() internal pure virtual override(MetaTokenBase, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | GovernanceBits.PQZ_KIND_BITS;
    }

    function _contractOnlyBits() internal pure virtual override(MetaTokenBase, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY;
    }

    /// @dev `WrappedToken`'s scalars (bit 27, group 3l R27), restated for the second base.
    function _scalarBits() internal pure virtual override(MetaTokenBase, WrappedTokenCore) returns (uint256) {
        return WrappedTokenCore._scalarBits();
    }

    /// @dev Never reached: `_initRaw` is the kind's init.
    function _init(IFactoryToken.TokenConfig memory) internal override(MetaTokenBase, WrappedTokenCore) {}

    function _initRaw(bytes calldata initArgs) internal virtual override {
        PqzWrappedLib.init(initArgs, _registry(), _pqzVerifier(), FACTORY, kind(), _validBits(), _roleBits(),
            _contractOnlyBits());
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-PQZ-22)

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`); the public-equivalent `minted`, a multiple of
    ///         `shieldScale` (`AmountNotScaled`), is minted to `SHIELD_POOL` (D19) and becomes a TRIVIAL entry of
    ///         `minted / shieldScale` for `toUA`.
    function _mtxWrapShieldBody(address underlying, uint256 amountIn, bytes32 toUA) internal {
        _regPayer();
        address m = _msgSender();
        (,, uint256 minted) = WrappedLib.wrap(WrappedLib.indexOf(underlying), amountIn, m, msg.value, totalSupply(), toUA);
        uint256 scale = PqzCore.$().shieldScale;
        if (minted % scale != 0) revert IPqzToken.AmountNotScaled(minted, scale);
        PqzStateLib.shield(toUA, minted / scale, m, _registry());
        _poolMove(bytes32(0), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), minted);
    }

    /// @notice The signed `mtxWrapShield`; as on the generic path, relayed it takes no coin (the native leg reverts).
    function _mtxWrapShieldBody(MetaTxLib.Envelope calldata e, address underlying, uint256 amountIn, bytes32 toUA, bytes calldata sig) internal returns (bytes memory)
    {
        return _named(WRAP_SHIELD_TYPEHASH, IConfidentialWrappedToken.mtxWrapShield.selector, e, abi.encode(underlying, amountIn, toUA), sig);
    }

    /// @notice The burn of `x.amount` (statement: `amount`, `recipient`; `envelopeBinding` binds `x.underlying` and
    ///         `x.minOut`, direct P6g D12, relayed folded with the envelope's D15), `amount · shieldScale` burnt from
    ///         `SHIELD_POOL`, txFee to the beneficiary, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥
    ///         minOut` to `x.recipient`: an address, or a derived UA through the leg's `transferToUA` (`UALegNotLedger`
    ///         otherwise).
    function _mtxUnshieldUnwrapBody(IPqzToken.PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal {
        uint256 i = WrappedLib.indexOf(x.underlying);
        uint256 wrapped = x.amount * PqzCore.$().shieldScale;
        WrappedLib.quoteTo(i, x.recipient, wrapped, x.minOut, b.fromUA); // before the proof (spec §5.4); 3l: the proof's sender
        _burn(_envUnwrap(x, _ticketBinding()), b, proof, pqzAuth, accHint, pqzVerdict);
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut, b.fromUA);
    }

    /// @notice The signed form over `UAPqzUnshieldUnwrap` (R36: native and derived ids), the `Unwrap` leg a nested struct.
    function _mtxUnshieldUnwrapBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _unwrapCall(b, x, proof, pqzAuth, accHint, pqzVerdict);
        return _namedCallUA(UA_UNSHIELD_UNWRAP_TYPEHASH, e, words, data, auth);
    }

    /// @dev The words the struct hashes (TS-D17) and the op's call.
    function _unwrapCall(IPqzToken.PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory, bytes memory)
    {
        return (abi.encode(PqzViewLib.hashBurn(b), PqzViewLib.hashUnwrap(x), keccak256(proof), keccak256(accHint)),
            abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (b, x, proof, pqzAuth, accHint, pqzVerdict)));
    }

    /// @notice The `envelopeBinding` word of a direct `mtxUnshieldUnwrap` (P6g plan D12).
    function _unwrapBindingBody(address u, uint256 minOut) internal pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_UNWRAP, u, minOut));
    }

    /// @notice The burn statement of `mtxUnshieldUnwrap` (`binding` 0 = direct, else the relayed call's envelope binding).
    function _unshieldUnwrapStatementBody(IPqzToken.PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes32 binding) internal view returns (bytes memory)
    {
        return PqzViewLib.burnStatement(_envUnwrap(x, binding), b);
    }

    /// @dev The binding word: `unwrapBinding(u, minOut)` direct, `keccak256(abi.encode(envelope, unwrapBinding(u,
    ///      minOut)))` relayed (plan 5h D15).
    function _envUnwrap(IConfidentialWrappedToken.Unwrap calldata x, bytes32 b) private view returns (PqzCore.Env memory e) {
        bytes32 w = _unwrapBindingBody(x.underlying, x.minOut);
        e = _envOf(b == 0 ? w : keccak256(abi.encode(b, w)));
        (e.amount, e.recipient) = (x.amount, x.recipient);
    }

    /// @notice As `WrappedToken` (spec §6.2); restated for the second base.
    function _rescueBody(address asset) internal virtual override(MetaTokenBase, WrappedTokenCore) {
        WrappedLib.rescue(asset);
    }

    /// @notice As `WrappedToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function _disableFeatureBody(uint8 bit) internal virtual override(GovernanceBaseCore, WrappedTokenCore) {
        _wrapControlsOff(bit); // group 3l
        bool applied = GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());
        if (applied && bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    /// @notice The collateral check of a rate change: `totalSupply()` (the shielded value sits in `SHIELD_POOL`, D19).
    function _executeRateBody() internal override {
        WrappedLib.executeRate(_govSubject(), totalSupply());
    }

    // ------------------------------------------------------------------ the layer's hooks


    /// @dev The layer's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view virtual override(MetaTokenBase, PqzLayer) {
        PqzLayer._validateEnv(env);
    }
    function _domainName() internal pure virtual override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view virtual override(MetaTxBaseCore, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override(PqzLayer, UAMetaTxBaseCore) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _isPqzOp(bytes4 sel) internal pure override returns (bool) {
        return PqzLayer._isPqzOp(sel) || sel == IConfidentialWrappedToken.mtxWrapShield.selector
            || sel == IPqzWrappedToken.mtxUnshieldUnwrap.selector;
    }

    function _batchable(bytes4 sel) internal view virtual override(MetaTxBaseCore, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-PQZ-21)

    /// @notice `WrappedToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE` (incl. the rollover
    ///         and `mtxPrepareAcc`).
    function _mtxSelectorsBody() internal pure virtual override(MetaTxBaseCore, WrappedTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return PqzWrappedLib.selectors();
    }

    function _mtxRule(bytes4 sel) internal view virtual override(MetaTxBaseCore, WrappedTokenCore) returns (MtxRule memory) {
        if (sel == IConfidentialWrappedToken.mtxWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return WrappedTokenCore._mtxRule(sel);
    }

    /// @notice The leg paths of `WrappedToken` and the PQZ ops; not `mtxWrapShield` (the pool holds no leg).
    function _uaAllowed(bytes4 sel) internal view virtual override(UAMetaTxBaseCore, WrappedTokenCore) returns (bool) {
        return (_isPqzOp(sel) && sel != IConfidentialWrappedToken.mtxWrapShield.selector) || WrappedTokenCore._uaAllowed(sel);
    }
}
