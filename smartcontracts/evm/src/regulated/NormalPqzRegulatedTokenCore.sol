// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";

import {NormalPqzTokenCore} from "../pqz/NormalPqzTokenCore.sol";
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

/// @title Kind `NORMAL_PQZ_REGULATED` (12, CTR-GOV-16, CTR-GOV-17, regulated-kinds spec §2.1, §4.2, §4.3): `NormalPqzToken`
///        with the regulated layer. PQZ only (Zether ≠ PQZ).
/// @notice **UNAUDITED.** Every refusal runs before the proof (spec §4): `PqzLayer` names the sender `fromUA` (an explicit
///         field) by `_regSender`, the `shieldIn` payer by `_regPayer()`, the beneficiary by `_regName`, first in `_single`,
///         `_multi` and `_burn`, before `_pullShieldIn`; an unshield's recipient by `_regReceiver` when the amount is not 0;
///         the shield payer by `_regPayer()`. A refresh (`amount = 0`) names no sender, so it stays open under `FREEZE` and
///         `PAUSE` (U1, U2); roll-over and prepare take no hook. No leg, `toUA` or entry is read (I9). `FORCE` moves the public
///         balance only (`_poolMove`); `acc`, pending and `totalShielded` are never touched (I8). `ALLOWLIST` (8) is outside
///         the kind's mask (CTR-GOV-17).
abstract contract NormalPqzRegulatedTokenCore is NormalPqzTokenCore, RegulatedBase {
    /// @dev `implArgs = abi.encode(COMPLIANCE_REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        NormalPqzTokenCore(factory_, implArgs)
        RegulatedBase(implArgs)
    {}


    /// @dev The base kind's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view override(MetaTokenBase, NormalPqzTokenCore) {
        NormalPqzTokenCore._validateEnv(env);
    }
    function kind() public pure override(MetaTokenBase, NormalPqzTokenCore) returns (uint8) {
        return TokenStore.KIND_NORMAL_PQZ_REGULATED;
    }

    function _validBits() internal pure override(GovernanceBaseCore, NormalPqzTokenCore) returns (uint256) {
        return GovernanceBits.NORMAL_BITS | REG_BITS_CONFIDENTIAL | GovernanceBits.PQZ_KIND_BITS;
    }

    function _roleBits() internal pure override(MetaTokenBase, NormalPqzTokenCore) returns (uint256) {
        return GovernanceBits.NORMAL_ROLES | REG_ROLES | GovernanceBits.PQZ_KIND_BITS;
    }

    function _contractOnlyBits() internal pure override returns (uint256) {
        return REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);
    }

    /// @notice The regulated mirror sync, only once the disable applied (Codex 3).
    function _disableFeatureBody(uint8 bit) internal override(GovernanceBaseCore, RegulatedBase) {
        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);
    }

    /// @dev The pre row of the confidential kinds (spec §3.2): fee-bearing ⇒ `P`, `F(from)`; not fee-bearing: nothing
    ///      read (U4), so a frozen envelope `from` may submit another's proof at fee `NONE`.
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(RegulatedBase, UAMetaTxBaseCore) {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);
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

    function _mtxSelectorsBody() internal pure override(MetaTxBaseCore, NormalPqzTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super._mtxSelectorsBody();
    }

    function _mtxRule(bytes4 sel) internal view override(MetaTxBaseCore, NormalPqzTokenCore) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(NormalPqzTokenCore, UAMetaTxBaseCore) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(ERC20MetaTx, NormalPqzTokenCore) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBaseCore, NormalPqzTokenCore) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(NormalPqzTokenCore, UAMetaTxBaseCore) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBaseCore, NormalPqzTokenCore) returns (bool) {
        return super._batchable(sel);
    }
}
