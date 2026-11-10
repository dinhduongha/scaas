// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IZetherToken} from "../zether/IZetherToken.sol";

import {WrappedZetherTokenCore} from "../zether/WrappedZetherTokenCore.sol";
import {ZetherLayer} from "../zether/ZetherLayer.sol";
import {ZetherLib} from "../zether/ZetherLib.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {WrappedTokenCore} from "../metatx/WrappedTokenCore.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `WRAPPED_ZETHER_REGULATED` (11, CTR-GOV-16, CTR-GOV-17, regulated-kinds spec §2.1, §4.1, §4.3):
///        `WrappedZetherToken` with the regulated layer. Zether only (Zether ≠ PQZ).
/// @notice **UNAUDITED.** As kind 10, plus the wrap payer (`_wrap` with another destination, `mtxWrapShield`: `_regPayer()`)
///         and `mtxUnshieldUnwrap` (the Zether sender and the beneficiary at the top, before the reserve quote and the
///         proof; `x.recipient` gets another asset, unchecked). No confidential selector is pause-open (RK-7).
abstract contract WrappedZetherRegulatedTokenCore is WrappedZetherTokenCore, RegulatedBase {
    /// @dev `implArgs = abi.encode(REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        WrappedZetherTokenCore(factory_, implArgs)
        RegulatedBase(implArgs)
    {}


    /// @dev The base kind's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view override(MetaTokenBase, WrappedZetherTokenCore) {
        WrappedZetherTokenCore._validateEnv(env);
    }
    function kind() public pure override(MetaTokenBase, WrappedZetherTokenCore) returns (uint8) {
        return TokenStore.KIND_WRAPPED_ZETHER_REGULATED;
    }

    function _validBits() internal pure override(GovernanceBaseCore, WrappedZetherTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS_CONFIDENTIAL;
    }

    function _roleBits() internal pure override(MetaTokenBase, WrappedZetherTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override(MetaTokenBase, WrappedZetherTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(RegulatedBase, WrappedZetherTokenCore) {
        super._initRaw(initArgs);
    }

    /// @notice As kind 9: the pending-rate drop and the mirror sync, each only once the disable applied.
    function _disableFeatureBody(uint8 bit) internal override(RegulatedBase, WrappedZetherTokenCore) {
        _wrapControlsOff(bit); // group 3l
        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);
    }

    // ------------------------------------------------------------------ restated for the two bases (solc: a function both
    // paths mention): the regulated layer's, then the base kind's

    /// @dev The regulated scalars and bit 27 (group 3l, R27).
    function _scalarBits() internal pure override(WrappedZetherTokenCore, RegulatedBase) returns (uint256) {
        return super._scalarBits() | (uint256(1) << GovernanceBits.REDEEMER);
    }

    function _delayedRelaxBits() internal pure override(GovernanceBaseCore, RegulatedBase) returns (uint256) {
        return super._delayedRelaxBits();
    }

    function _supportsInterfaceBody(bytes4 id) internal view override(MetaTokenBase, RegulatedBase) returns (bool) {
        return super._supportsInterfaceBody(id);
    }

    /// @dev The pre row of the confidential kinds (spec §3.2): fee-bearing ⇒ `P`, `F(from)`; not fee-bearing: nothing
    ///      read (U4), so a frozen envelope `from` may submit another's proof at fee `NONE`.
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);
    }

    /// @dev Spec §4.1, F-10: the proof's sender `uaOf(yFrom)`, computed here from the raw `G1`, then `P` and `F` (never the
    ///      envelope's subject, U4); `ZetherLayer` calls it at each direct transfer and unshield entry before the proof.
    function _regZetherSender(IZetherToken.G1 calldata yFrom) internal view override {
        _regSender(ZetherTypes.UA.unwrap(ZetherLib.uaOf(yFrom)));
    }

    function _regFeeTo(bytes32 feeTo, uint256 fee) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        super._regFeeTo(feeTo, fee);
    }

    function _regMove(bytes32 from, bytes32 to, uint256 value) internal view override(ERC20MetaTx, RegulatedBase) {
        super._regMove(from, to, value);
    }

    function _regPayer() internal view override(ERC20MetaTx, RegulatedBase) {
        super._regPayer();
    }

    function _regSender(bytes32 a) internal view override(ERC20MetaTx, RegulatedBase) {
        super._regSender(a);
    }

    function _regName(bytes32 beneficiary) internal view override(ERC20MetaTx, RegulatedBase) {
        super._regName(beneficiary);
    }

    function _regReceiver(bytes32 recipient) internal view override(ERC20MetaTx, RegulatedBase) {
        super._regReceiver(recipient);
    }

    function _underlyingsBody() internal view override(MetaTokenBase, WrappedZetherTokenCore) returns (address[] memory) {
        return super._underlyingsBody();
    }

    function _rescueBody(address asset) internal override(MetaTokenBase, WrappedZetherTokenCore) {
        WrappedLib.rescue(asset);
    }

    function _mtxSelectorsBody() internal pure override(MetaTxBaseCore, WrappedZetherTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super._mtxSelectorsBody();
    }

    function _mtxRule(bytes4 sel) internal view override(MetaTxBaseCore, WrappedZetherTokenCore) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(UAMetaTxBaseCore, WrappedZetherTokenCore) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(ERC20MetaTx, WrappedZetherTokenCore) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBaseCore, WrappedZetherTokenCore) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(UAMetaTxBaseCore, WrappedZetherTokenCore) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }
}
