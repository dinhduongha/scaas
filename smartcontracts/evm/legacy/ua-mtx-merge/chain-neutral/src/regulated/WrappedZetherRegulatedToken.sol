// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedZetherToken} from "../zether/WrappedZetherToken.sol";
import {ZetherLayer} from "../zether/ZetherLayer.sol";
import {ZetherLib} from "../zether/ZetherLib.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {WrappedToken} from "../metatx/WrappedToken.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
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

/// @title Kind `WRAPPED_ZETHER_REGULATED` (11, CTR-GOV-16, CTR-GOV-17, regulated-kinds spec §2.1, §4.1, §4.3):
///        `WrappedZetherToken` with the regulated layer. Zether only (Zether ≠ PQZ).
/// @notice **UNAUDITED.** As kind 10, plus the wrap payer (`_wrap` with another destination, `mtxWrapShield`: `_regPayer()`)
///         and `mtxUnshieldUnwrap` (the Zether sender and the beneficiary at the top, before the reserve quote and the
///         proof; `x.recipient` gets another asset, unchecked). No confidential selector is pause-open (RK-7).
contract WrappedZetherRegulatedToken is WrappedZetherToken, RegulatedBase {
    /// @dev `implArgs = abi.encode(REGISTRY_CODEHASH)` (plan T29).
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        WrappedZetherToken(envVersion, env, implArgs)
        RegulatedBase(implArgs)
    {}

    function kind() public pure override(WrappedZetherToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_WRAPPED_ZETHER_REGULATED;
    }

    function _validBits() internal pure override(WrappedZetherToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.WRAPPED_BITS | REG_BITS_CONFIDENTIAL;
    }

    function _roleBits() internal pure override(WrappedZetherToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_ROLES | REG_ROLES;
    }

    function _contractOnlyBits() internal pure override(WrappedZetherToken, MetaTokenBase) returns (uint256) {
        return GovernanceBits.WRAPPED_CONTRACT_ONLY | REG_CONTRACT_ONLY;
    }

    function _initRaw(bytes calldata initArgs) internal override(WrappedZetherToken, RegulatedBase) {
        super._initRaw(initArgs);
    }

    /// @notice As kind 9: the pending-rate drop and the mirror sync, each only once the disable applied.
    function disableFeature(uint8 bit) external override(WrappedZetherToken, RegulatedBase) nonReentrant {
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

    /// @dev The pre row of the confidential kinds (spec §3.2): fee-bearing ⇒ `P`, `F(from)`; not fee-bearing: nothing
    ///      read (U4), so a frozen envelope `from` may submit another's proof at fee `NONE`.
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view override(UAMetaTxBase, RegulatedBase) {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);
    }

    /// @dev Spec §4.1, F-10: the proof's sender `uaOf(yFrom)`, computed here from the raw `G1`, then `P` and `F` (never the
    ///      envelope's subject, U4); `ZetherLayer` calls it at each direct transfer and unshield entry before the proof.
    function _regZetherSender(G1 calldata yFrom) internal view override {
        _regSender(ZetherTypes.UA.unwrap(ZetherLib.uaOf(yFrom)));
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

    function underlyings() public view override(WrappedZetherToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function rescue(address asset) external override(WrappedZetherToken, MetaTokenBase) nonReentrant {
        WrappedLib.rescue(asset);
    }

    function mtxSelectors()
        public pure override(WrappedZetherToken, IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return super.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedZetherToken, MetaTxBase) returns (MtxRule memory) {
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(WrappedZetherToken, UAMetaTxBase) returns (bool) {
        return super._uaAllowed(sel);
    }

    function _domainName() internal pure override(WrappedZetherToken, ERC20MetaTx) returns (string memory) {
        return super._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(WrappedZetherToken, MetaTxBase) returns (bytes32)
    {
        return super._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(WrappedZetherToken, UAMetaTxBase) returns (bytes32)
    {
        return super._uaEnvelopeBinding(m);
    }
}
