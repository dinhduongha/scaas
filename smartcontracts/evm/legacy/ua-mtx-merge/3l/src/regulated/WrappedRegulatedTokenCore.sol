// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedTokenCore} from "../metatx/WrappedTokenCore.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `WRAPPED_REGULATED` (9, CTR-GOV-16, regulated-kinds spec §2.1): `WrappedToken` with the regulated layer.
/// @notice **UNAUDITED.** Measured first with kind 13 (plan T27); FREEZE, RECORD, FORCE, PAUSE and the fee seats built
///         (T28). The wrap payer and the wrap order reach the regulated hooks through `WrappedToken`'s seats.
abstract contract WrappedRegulatedTokenCore is WrappedTokenCore, RegulatedBase {
    /// @dev `implArgs = abi.encode(REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        WrappedTokenCore(factory_, implArgs)
        RegulatedBase(implArgs)
    {}

    function kind() public pure override(MetaTokenBase, WrappedTokenCore) returns (uint8) {
        return TokenStore.KIND_WRAPPED_REGULATED;
    }

    function _validBits() internal pure override(GovernanceBaseCore, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS;
    }

    function _roleBits() internal pure override(MetaTokenBase, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override(MetaTokenBase, WrappedTokenCore) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    /// @notice `WrappedToken`'s pending-rate drop and the regulated mirror sync, each only once the disable applied.
    function _disableFeatureBody(uint8 bit) internal override(RegulatedBase, WrappedTokenCore) {
        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);
    }

    // ------------------------------------------------------------------ restated for the two bases (solc: a function both
    // paths mention): the regulated layer's, then the base kind's

    function _scalarBits() internal pure override(MetaTokenBase, RegulatedBase) returns (uint256) {
        return super._scalarBits();
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

    function _underlyingsBody() internal view override(MetaTokenBase, WrappedTokenCore) returns (address[] memory) {
        return super._underlyingsBody();
    }

    function _rescueBody(address asset) internal override(MetaTokenBase, WrappedTokenCore) {
        WrappedLib.rescue(asset);
    }

    function _mtxSelectorsBody() internal pure override(MetaTxBaseCore, WrappedTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super._mtxSelectorsBody();
    }

    function _mtxRule(bytes4 sel) internal view override(MetaTxBaseCore, WrappedTokenCore) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(UAMetaTxBaseCore, WrappedTokenCore) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        super._regPre(from, sel, mode);
    }

    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);
    }
}
