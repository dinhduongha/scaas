// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../metatx/NormalToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {GovernanceBase} from "../governance/GovernanceBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {IPqzToken} from "./IPqzToken.sol";

/// @title Kind `NORMAL_PQZ` (CTR-TOK-21, CTR-PQZ-22): the standalone token with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED.** Any chain whose `PQZ` precompile passes the self-test (`PqzSafety`); never on Hedera.
///         `MINTABLE` mints public units
///         only; shielded value exists only through `mtxShield`, which moves public units to `SHIELD_POOL` (D19). Flags: `PAYABLE`,
///         `MINTABLE`, `BURNABLE`. Built by `OpenFactory.createToken` with `conf` set and `legs`, `rate` empty.
contract NormalPqzToken is NormalToken, PqzLayer {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`, whose
    ///      `deps[ENV_PQZ_VERIFIER]` is the release's `UAPqzVerifier` (CTR-ZTH-20 / CTR-PQZ-10); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        NormalToken(envVersion, env, implArgs)
        PqzLayer(env)
    {
        if (!SigCheck.isContract(env.registry)) revert BadInit();
    }

    function kind() public pure virtual override(NormalToken, MetaTokenBase) returns (uint8) {
        return TokenStore.KIND_NORMAL_PQZ;
    }

    function _validBits() internal pure virtual override(NormalToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.NORMAL_BITS;
    }

    function _init(TokenConfig memory cfg) internal override(NormalToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        GovernanceLib.init(cfg.features, cfg.lockedFeatures, cfg.owner, cfg.grantDelay, cfg.rescueTo, cfg.roles, _validBits(),
            _roleBits(), _contractOnlyBits(), _REGISTRY);
        PqzStateLib.init(cfg.conf, _REGISTRY, PQZ_VERIFIER);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function _domainName() internal pure virtual override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view virtual override(MetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override(UAMetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view virtual override(MetaTxBase, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-PQZ-21): `cancelNonce`, `burn(uint256)` `AMOUNT(0)`, the PQZ ops
    ///         `ABSOLUTE` (incl. the rollover and `mtxPrepareAcc`).
    function mtxSelectors()
        public pure virtual override(NormalToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](10);
        c = new uint8[](10);
        a = new uint8[](10);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (IConfidentialToken.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[3], c[3]) = (IPqzToken.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[4], c[4]) = (IPqzToken.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[5], c[5]) = (IPqzToken.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (IPqzToken.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (IPqzToken.mtxConfidentialTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (IPqzToken.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (IPqzToken.mtxPrepareAcc.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view virtual override(NormalToken, MetaTxBase) returns (MtxRule memory) {
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return NormalToken._mtxRule(sel);
    }

    /// @notice `burn` and the PQZ ops (CTR-PQZ-15: the PQ-complete path).
    function _uaAllowed(bytes4 sel) internal view virtual override(NormalToken, UAMetaTxBase) returns (bool) {
        return _isPqzOp(sel) || NormalToken._uaAllowed(sel);
    }
}
