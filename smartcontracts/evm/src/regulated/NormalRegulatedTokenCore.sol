// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalTokenCore} from "../metatx/NormalTokenCore.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {RegulatedBase} from "./RegulatedBase.sol";

/// @title Kind `NORMAL_REGULATED` (8, CTR-GOV-16, regulated-kinds spec §2.1): `NormalToken` with the regulated layer.
/// @notice **UNAUDITED.** `_initRaw` runs `RegulatedLib.init` before `NormalToken`'s init, so before the initial-supply mint.
abstract contract NormalRegulatedTokenCore is NormalTokenCore, RegulatedBase {
    /// @dev `implArgs = abi.encode(COMPLIANCE_REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        NormalTokenCore(factory_, implArgs)
        RegulatedBase(implArgs)
    {}

    function kind() public pure override(MetaTokenBase, NormalTokenCore) returns (uint8) {
        return TokenStore.KIND_NORMAL_REGULATED;
    }

    function _validBits() internal pure override(GovernanceBaseCore, NormalTokenCore) returns (uint256) {
        return GovernanceBits.NORMAL_BITS | REG_BITS;
    }

    function _roleBits() internal pure override returns (uint256) {
        return GovernanceBits.NORMAL_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override returns (uint256) {
        return REG_CONTRACT_ONLY;
    }

    // ------------------------------------------------------------------ restated for the two bases (solc: a function both
    // paths mention): the regulated layer's, then the base kind's

    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);
    }

    function _scalarBits() internal pure override(MetaTokenBase, RegulatedBase) returns (uint256) {
        return super._scalarBits();
    }

    function _delayedRelaxBits() internal pure override(GovernanceBaseCore, RegulatedBase) returns (uint256) {
        return super._delayedRelaxBits();
    }

    function _supportsInterfaceBody(bytes4 id) internal view override(MetaTokenBase, RegulatedBase) returns (bool) {
        return super._supportsInterfaceBody(id);
    }

    /// @notice The regulated mirror sync, only once the disable applied (Codex 3).
    function _disableFeatureBody(uint8 bit) internal override(GovernanceBaseCore, RegulatedBase) {
        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);
    }

    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        super._regPre(from, sel, mode);
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

    function _mtxSelectorsBody() internal pure override(MetaTxBaseCore, NormalTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super._mtxSelectorsBody();
    }

    function _mtxRule(bytes4 sel) internal view override(MetaTxBaseCore, NormalTokenCore) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(NormalTokenCore, UAMetaTxBaseCore) returns (bool) {
        return super._uaAllowed(sel);
    }
}
