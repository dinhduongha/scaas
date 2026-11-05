// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../metatx/WrappedToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `WRAPPED_REGULATED` (9, CTR-GOV-16, regulated-kinds spec §2.1): `WrappedToken` with the regulated layer.
/// @notice **UNAUDITED.** Skeleton (plan T27): measured first with kind 13; creation reverts `RegulatedNotBuilt` until T28.
///         The wrap payer and the wrap order reach the regulated hooks through `WrappedToken`'s seats.
contract WrappedRegulatedToken is WrappedToken, RegulatedBase {
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs) WrappedToken(envVersion, env, implArgs) {}

    function kind() public pure override(WrappedToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_WRAPPED_REGULATED;
    }

    function _validBits() internal pure override(WrappedToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS;
    }

    function _roleBits() internal pure override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override(WrappedToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    /// @notice `WrappedToken`'s pending-rate drop and the regulated mirror sync, each only once the disable applied.
    function disableFeature(uint8 bit) external override(WrappedToken, RegulatedBase) nonReentrant {
        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);
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

    function underlyings() public view override(WrappedToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function rescue(address asset) external override(WrappedToken, MetaTokenBase) nonReentrant {
        WrappedLib.rescue(asset);
    }

    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedToken, MetaTxBase) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(WrappedToken, UAMetaTxBase) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(UAMetaTxBase, RegulatedBase) {
        super._regPre(from, sel, mode);
    }

    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);
    }
}
