// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";

import {WrappedTokenCore} from "../metatx/WrappedTokenCore.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {WrappedPqzTokenCore} from "../pqz/WrappedPqzTokenCore.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `WRAPPED_PQZ_REGULATED` (13, CTR-GOV-16, CTR-GOV-17, regulated-kinds spec §2.1, §4.2): `WrappedPqzToken` with
///        the regulated layer; the tight one under the 64,512 B stop line (owner 2026-11-06).
/// @notice **UNAUDITED.** Measured first (plan T27); `RegulatedBase`'s controls built (T28). The PQZ seats
///         (`_regSender(fromUA)`, the `shieldIn` payer, the beneficiary, the unshield recipient) reach `RegulatedBase`'s
///         hooks through `PqzLayer` and `WrappedPqzToken`; the refresh and the roll-over take none (U1, U2). `ALLOWLIST` (8)
///         is outside the kind's mask (CTR-GOV-17).
abstract contract WrappedPqzRegulatedTokenCore is WrappedPqzTokenCore, RegulatedBase {
    /// @dev `implArgs = abi.encode(COMPLIANCE_REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        WrappedPqzTokenCore(factory_, implArgs)
        RegulatedBase(implArgs)
    {}


    /// @dev The base kind's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view override(MetaTokenBase, WrappedPqzTokenCore) {
        WrappedPqzTokenCore._validateEnv(env);
    }
    function kind() public pure override(MetaTokenBase, WrappedPqzTokenCore) returns (uint8) {
        return TokenStore.KIND_WRAPPED_PQZ_REGULATED;
    }

    function _validBits() internal pure override(GovernanceBaseCore, WrappedPqzTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS_CONFIDENTIAL | GovernanceBits.PQZ_KIND_BITS;
    }

    function _roleBits() internal pure override(MetaTokenBase, WrappedPqzTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES | GovernanceBits.PQZ_KIND_BITS;
    }

    function _contractOnlyBits() internal pure override(MetaTokenBase, WrappedPqzTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(RegulatedBase, WrappedPqzTokenCore) {
        super._initRaw(initArgs);
    }

    /// @notice As kind 9: the pending-rate drop and the mirror sync, each only once the disable applied.
    function _disableFeatureBody(uint8 bit) internal override(RegulatedBase, WrappedPqzTokenCore) {
        _wrapControlsOff(bit); // group 3l
        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);
    }

    /// @dev The pre row of the confidential kinds (spec §3.2): fee-bearing ⇒ `P`, `F(from)`; not fee-bearing: nothing
    ///      read (U4), so a frozen envelope `from` may submit another's proof at fee `NONE`.
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);
    }

    // ------------------------------------------------------------------ restated for the two bases (solc: a function both
    // paths mention): the regulated layer's, then the base kind's

    /// @dev The regulated scalars and bit 27 (group 3l, R27).
    function _scalarBits() internal pure override(WrappedPqzTokenCore, RegulatedBase) returns (uint256) {
        return super._scalarBits() | (uint256(1) << GovernanceBits.REDEEMER);
    }

    function _delayedRelaxBits() internal pure override(GovernanceBaseCore, RegulatedBase) returns (uint256) {
        return super._delayedRelaxBits();
    }

    function _supportsInterfaceBody(bytes4 id) internal view override(MetaTokenBase, RegulatedBase) returns (bool) {
        return super._supportsInterfaceBody(id);
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

    function _underlyingsBody() internal view override(MetaTokenBase, WrappedPqzTokenCore) returns (address[] memory) {
        return super._underlyingsBody();
    }

    function _rescueBody(address asset) internal override(MetaTokenBase, WrappedPqzTokenCore) {
        WrappedLib.rescue(asset);
    }

    function _mtxSelectorsBody() internal pure override(MetaTxBaseCore, WrappedPqzTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super._mtxSelectorsBody();
    }

    function _mtxRule(bytes4 sel) internal view override(MetaTxBaseCore, WrappedPqzTokenCore) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(UAMetaTxBaseCore, WrappedPqzTokenCore) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(ERC20MetaTx, WrappedPqzTokenCore) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBaseCore, WrappedPqzTokenCore) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(UAMetaTxBaseCore, WrappedPqzTokenCore) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBaseCore, WrappedPqzTokenCore) returns (bool) {
        return super._batchable(sel);
    }
}
