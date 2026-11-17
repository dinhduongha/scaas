// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../pqz/NormalPqzToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
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
contract NormalPqzRegulatedToken is NormalPqzToken, RegulatedBase {
    /// @dev `implArgs = abi.encode(REGISTRY_CODEHASH)` (plan T29).
    constructor(address factory_, bytes memory implArgs)
        NormalPqzToken(factory_, implArgs)
        RegulatedBase(implArgs)
    {}


    /// @dev The base kind's env checks, restated for the second base.
    function _validateEnv(ChainEnv calldata env) internal view override(MetaTokenBase, NormalPqzToken) {
        NormalPqzToken._validateEnv(env);
    }
    function kind() public pure override(NormalPqzToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_NORMAL_PQZ_REGULATED;
    }

    function _validBits() internal pure override(NormalPqzToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.NORMAL_BITS | REG_BITS_CONFIDENTIAL | GovernanceBits.PQZ_KIND_BITS;
    }

    function _roleBits() internal pure override(NormalPqzToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.NORMAL_ROLES | REG_ROLES | GovernanceBits.PQZ_KIND_BITS;
    }

    function _contractOnlyBits() internal pure override returns (uint256) {
        return REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);
    }

    /// @notice The regulated mirror sync, only once the disable applied (Codex 3).
    function disableFeature(uint8 bit) external override(GovernanceBase, RegulatedBase) nonReentrant {
        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);
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

    function mtxSelectors()
        public pure override(NormalPqzToken, IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(NormalPqzToken, MetaTxBase) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(NormalPqzToken, UAMetaTxBase) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(NormalPqzToken, ERC20MetaTx) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(NormalPqzToken, MetaTxBase) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(NormalPqzToken, UAMetaTxBase) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view override(NormalPqzToken, MetaTxBase) returns (bool) {
        return super._batchable(sel);
    }
}
