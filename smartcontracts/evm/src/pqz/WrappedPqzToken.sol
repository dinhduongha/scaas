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
import {SigCheck} from "../common/SigCheck.sol";
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";
import {PqzWrappedLib} from "./PqzWrappedLib.sol";
import {IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IPqzWrappedToken} from "./IPqzToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `WRAPPED_PQZ` (CTR-TOK-21, CTR-PQZ-22): the wrapper of 1–8 legs with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED.** Any chain whose `PQZ` precompile passes the self-test (`PqzSafety`); never on Hedera.
///         Legs, rates, reserves,
///         `wrap` / `unwrap` and the roles are `WrappedToken`'s; the layer adds `mtxWrapShield` (a leg's underlying
///         into a TRIVIAL pending entry, the public-equivalent minted to `SHIELD_POOL`; plan 5h D18, D19) and
///         `mtxUnshieldUnwrap` (a burn: `amount · shieldScale` burnt from `SHIELD_POOL`, then paid out of a leg's
///         reserve to an address or, through a SCaaS ledger leg, to a UA), as on `WRAPPED_ZETHER`. Reserve invariant
///         `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` (the shielded value is the pool's public units).
contract WrappedPqzToken is WrappedToken, PqzLayer, IPqzWrappedToken {
    bytes32 private constant WRAP_SHIELD_TYPEHASH = keccak256(
        "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_UNSHIELD_UNWRAP_TYPEHASH = keccak256(
        "UAPqzUnshieldUnwrap(bytes32 from,PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom)Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)"
    );

    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`, whose
    ///      `deps[ENV_PQZ_VERIFIER]` is the release's `UAPqzVerifier` (CTR-ZTH-20 / CTR-PQZ-10); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        WrappedToken(envVersion, env, implArgs)
        PqzLayer(env)
    {
        if (!SigCheck.isContract(env.registry)) revert BadInit();
    }

    /// @dev The legs (`WrappedToken`), restated for the second base.
    function underlyings() public view override(WrappedToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function kind() public pure virtual override(WrappedToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_WRAPPED_PQZ;
    }

    function _validBits() internal pure virtual override(WrappedToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS;
    }

    /// @dev `WrappedToken`'s masks, restated for the second base.
    function _roleBits() internal pure virtual override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES;
    }

    function _contractOnlyBits() internal pure virtual override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY;
    }

    /// @dev Never reached: `_initRaw` is the kind's init.
    function _init(TokenConfig memory) internal override(WrappedToken, MetaTokenBase) {}

    function _initRaw(bytes calldata initArgs) internal override {
        PqzWrappedLib.init(initArgs, _REGISTRY, PQZ_VERIFIER, kind(), _validBits(), _roleBits(), _contractOnlyBits());
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-PQZ-22)

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`); the public-equivalent `minted`, a multiple of
    ///         `shieldScale` (`AmountNotScaled`), is minted to `SHIELD_POOL` (D19) and becomes a TRIVIAL entry of
    ///         `minted / shieldScale` for `toUA`.
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable nonReentrant {
        _regPayer();
        address m = _msgSender();
        (,, uint256 minted) = WrappedLib.wrap(WrappedLib.indexOf(underlying), amountIn, m, msg.value, totalSupply());
        uint256 scale = PqzCore.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        PqzStateLib.shield(toUA, minted / scale, m, _REGISTRY);
        _poolMove(bytes32(0), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), minted);
    }

    /// @notice The signed `mtxWrapShield`; as on the generic path, relayed it takes no coin (the native leg reverts).
    function mtxWrapShield(MetaTxLib.Envelope calldata e, address underlying, uint256 amountIn, bytes32 toUA, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(WRAP_SHIELD_TYPEHASH, IConfidentialWrappedToken.mtxWrapShield.selector, e, abi.encode(underlying, amountIn, toUA), sig);
    }

    /// @notice The burn of `x.amount` (statement: `amount`, `recipient`; `envelopeBinding` binds `x.underlying` and
    ///         `x.minOut`, direct P6g D12, relayed folded with the envelope's D15), `amount · shieldScale` burnt from
    ///         `SHIELD_POOL`, txFee to the beneficiary, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥
    ///         minOut` to `x.recipient`: an address, or a derived UA through the leg's `transferToUA` (`UALegNotLedger`
    ///         otherwise).
    function mtxUnshieldUnwrap(PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint) external nonReentrant
    {
        uint256 i = WrappedLib.indexOf(x.underlying);
        uint256 wrapped = x.amount * PqzCore.$().shieldScale;
        WrappedLib.quoteTo(i, x.recipient, wrapped, x.minOut); // before the proof (spec §5.4)
        _burn(_envUnwrap(x, _ticketBinding()), b, proof, pqzAuth, accHint);
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut);
    }

    /// @notice The signed form over `UAPqzUnshieldUnwrap` (R36: native and derived ids), the `Unwrap` leg a nested struct.
    function mtxUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _unwrapCall(b, x, proof, pqzAuth, accHint);
        return _namedCallUA(UA_UNSHIELD_UNWRAP_TYPEHASH, e, words, data, auth);
    }

    /// @dev The words the struct hashes (TS-D17) and the op's call.
    function _unwrapCall(PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint) private pure returns (bytes memory, bytes memory)
    {
        return (abi.encode(PqzViewLib.hashBurn(b), PqzViewLib.hashUnwrap(x), keccak256(proof), keccak256(accHint)),
            abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (b, x, proof, pqzAuth, accHint)));
    }

    /// @notice The `envelopeBinding` word of a direct `mtxUnshieldUnwrap` (P6g plan D12).
    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_UNWRAP, u, minOut));
    }

    /// @notice The burn statement of `mtxUnshieldUnwrap` (`binding` 0 = direct, else the relayed call's envelope binding).
    function unshieldUnwrapStatement(PqzBurnArgs calldata b, Unwrap calldata x, bytes32 binding)
        external view returns (bytes memory)
    {
        return PqzViewLib.burnStatement(_envUnwrap(x, binding), b);
    }

    /// @dev The binding word: `unwrapBinding(u, minOut)` direct, `keccak256(abi.encode(envelope, unwrapBinding(u,
    ///      minOut)))` relayed (plan 5h D15).
    function _envUnwrap(Unwrap calldata x, bytes32 b) private view returns (PqzCore.Env memory e) {
        bytes32 w = unwrapBinding(x.underlying, x.minOut);
        e = _envOf(b == 0 ? w : keccak256(abi.encode(b, w)));
        (e.amount, e.recipient) = (x.amount, x.recipient);
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

    /// @notice The collateral check of a rate change: `totalSupply()` (the shielded value sits in `SHIELD_POOL`, D19).
    function executeRate() external override nonReentrant {
        WrappedLib.executeRate(_govSubject(), totalSupply());
    }

    // ------------------------------------------------------------------ the layer's hooks

    function _domainName() internal pure override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(UAMetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _isPqzOp(bytes4 sel) internal pure override returns (bool) {
        return PqzLayer._isPqzOp(sel) || sel == IConfidentialWrappedToken.mtxWrapShield.selector
            || sel == IPqzWrappedToken.mtxUnshieldUnwrap.selector;
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBase, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-PQZ-21)

    /// @notice `WrappedToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE` (incl. the rollover
    ///         and `mtxPrepareAcc`).
    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return PqzWrappedLib.selectors();
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedToken, MetaTxBase) returns (MtxRule memory) {
        if (sel == IConfidentialWrappedToken.mtxWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return WrappedToken._mtxRule(sel);
    }

    /// @notice The leg paths of `WrappedToken` and the PQZ ops; not `mtxWrapShield` (the pool holds no leg).
    function _uaAllowed(bytes4 sel) internal view override(WrappedToken, UAMetaTxBase) returns (bool) {
        return (_isPqzOp(sel) && sel != IConfidentialWrappedToken.mtxWrapShield.selector) || WrappedToken._uaAllowed(sel);
    }
}
