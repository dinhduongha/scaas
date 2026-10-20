// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NoUnderlyingToken} from "../metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzStateLib} from "./PqzStateLib.sol";

/// @title Kind `NONE_PQZ` (CTR-TOK-21, CTR-PQZ-22): the standalone token with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chains 31337 / 1337 / 7622 only. `MINTABLE` mints public units
///         only; shielded value exists only through `pqzShield`, which burns public units. Flags: `PAYABLE`,
///         `MINTABLE`, `BURNABLE`. Built by `OpenFactory.createToken` with `conf` set and `legs`, `rate` empty.
contract NoUnderlyingPqzToken is NoUnderlyingToken, PqzLayer {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`, whose
    ///      `deps[ENV_PQZ_VERIFIER]` is the release's `UAPqzVerifier` (CTR-ZTH-20 / CTR-PQZ-10); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        NoUnderlyingToken(envVersion, env, implArgs)
        PqzLayer(env)
    {
        if (env.registry.code.length == 0) revert BadInit();
    }

    function kind() public pure override(NoUnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_NONE_PQZ;
    }

    function _init(TokenConfig memory cfg) internal override(NoUnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_PQZ, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
        PqzStateLib.init(cfg.conf, _REGISTRY, PQZ_VERIFIER);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function _domainName() internal pure override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(ERC20MetaTx, PqzLayer) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBase, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-PQZ-21): `cancelNonce`, `burn(uint256)` `AMOUNT(0)`, the PQZ ops `ABSOLUTE`.
    function mtxSelectors()
        public pure override(NoUnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](11);
        c = new uint8[](11);
        a = new uint8[](11);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (this.pqzShield.selector, FEE_CLASS_ABSOLUTE);
        (s[3], c[3]) = (this.pqzTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[4], c[4]) = (this.pqzTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[5], c[5]) = (this.pqzTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.pqzUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.pqzRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (this.pqzTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.pqzTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.pqzTransferSingleNoBundle.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(NoUnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return NoUnderlyingToken._mtxRule(sel);
    }

    /// @notice `burn` and the PQZ ops (CTR-PQZ-15: the PQ-complete path).
    function _uaAllowed(bytes4 sel) internal view override(NoUnderlyingToken, ERC20MetaTx) returns (bool) {
        return _isPqzOp(sel) || NoUnderlyingToken._uaAllowed(sel);
    }
}
