// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../metatx/WrappedToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {WrappedPqzToken} from "../pqz/WrappedPqzToken.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `WRAPPED_PQZ_REGULATED` (13, CTR-GOV-16, CTR-GOV-17, regulated-kinds spec §2.1, §4.2): `WrappedPqzToken` with
///        the regulated layer; the tight one under the 64,512 B stop line (owner 2026-11-06).
/// @notice **UNAUDITED.** Measured first (plan T27); `RegulatedBase`'s controls built (T28). The PQZ seats
///         (`_regSender(fromUA)`, the `shieldIn` payer, the beneficiary, the unshield recipient) reach `RegulatedBase`'s
///         hooks through `PqzLayer` and `WrappedPqzToken`; the refresh and the roll-over take none (U1, U2). `ALLOWLIST` (8)
///         is outside the kind's mask (CTR-GOV-17).
contract WrappedPqzRegulatedToken is WrappedPqzToken, RegulatedBase {
    /// @dev `implArgs = abi.encode(REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        WrappedPqzToken(factory_, implArgs)
        RegulatedBase(implArgs)
    {}


    /// @dev The base kind's env checks, restated for the second base.
    function _validateEnv(ChainEnv calldata env) internal view override(MetaTokenBase, WrappedPqzToken) {
        WrappedPqzToken._validateEnv(env);
    }
    function kind() public pure override(WrappedPqzToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_WRAPPED_PQZ_REGULATED;
    }

    function _validBits() internal pure override(WrappedPqzToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS_CONFIDENTIAL;
    }

    function _roleBits() internal pure override(WrappedPqzToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override(WrappedPqzToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(WrappedPqzToken, RegulatedBase) {
        super._initRaw(initArgs);
    }

    /// @notice As kind 9: the pending-rate drop and the mirror sync, each only once the disable applied.
    function disableFeature(uint8 bit) external override(WrappedPqzToken, RegulatedBase) nonReentrant {
        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);
    }

    /// @dev The pre row of the confidential kinds (spec §3.2): fee-bearing ⇒ `P`, `F(from)`; not fee-bearing: nothing
    ///      read (U4), so a frozen envelope `from` may submit another's proof at fee `NONE`.
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(UAMetaTxBase, RegulatedBase) {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);
    }

    // ------------------------------------------------------------------ restated for the two bases (solc: a function both
    // paths mention): the regulated layer's, then the base kind's

    function _scalarBits() internal pure override(MetaTokenBase, RegulatedBase) returns (uint256) {
        return super._scalarBits();
    }

    function _delayedRelaxBits() internal pure override(GovernanceBase, RegulatedBase) returns (uint256) {
        return super._delayedRelaxBits();
    }

    function supportsInterface(bytes4 id) public view override(MetaTokenBase, RegulatedBase) returns (bool) {
        return super.supportsInterface(id);
    }

    function _regFeeTo(bytes32 feeTo, uint256 fee) internal view override(UAMetaTxBase, RegulatedBase) {
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

    function underlyings() public view override(WrappedPqzToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function rescue(address asset) external override(WrappedPqzToken, MetaTokenBase) nonReentrant {
        WrappedLib.rescue(asset);
    }

    function mtxSelectors()
        public pure override(WrappedPqzToken, IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedPqzToken, MetaTxBase) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(WrappedPqzToken, UAMetaTxBase) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(WrappedPqzToken, ERC20MetaTx) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(WrappedPqzToken, MetaTxBase) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(WrappedPqzToken, UAMetaTxBase) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view override(WrappedPqzToken, MetaTxBase) returns (bool) {
        return super._batchable(sel);
    }
}
