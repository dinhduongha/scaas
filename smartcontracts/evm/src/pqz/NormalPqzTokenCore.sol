// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";

import {NormalTokenCore} from "../metatx/NormalTokenCore.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../metatx/UAMetaTxBase.sol";
import {MetaTxBase, MetaTxBaseCore} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {GovernanceBase, GovernanceBaseCore} from "../governance/GovernanceBase.sol";
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
abstract contract NormalPqzTokenCore is NormalTokenCore, PqzLayer {
    /// @dev The factory's append (`OpenFactory.deployTokenImplementation`, chain-neutral spec §2.1): its address; no
    ///      `implArgs`. The env (`deps[ENV_PQZ_VERIFIER]` the release's `PqzKeyVerifier`, CTR-ZTH-20 / CTR-PQZ-10; a
    ///      registry) is checked by `validateEnv` (`PqzStateLib`).
    constructor(address factory_, bytes memory implArgs) NormalTokenCore(factory_, implArgs) {}

    function kind() public pure virtual override(MetaTokenBase, NormalTokenCore) returns (uint8) {
        return TokenStore.KIND_NORMAL_PQZ;
    }

    /// @dev `NormalToken`'s masks and bit 24 `PQZ_PROOF` (any holder; group 3h, PQZ proof path spec §5).
    function _validBits() internal pure virtual override(GovernanceBaseCore, NormalTokenCore) returns (uint256) {
        return GovernanceBits.NORMAL_BITS | GovernanceBits.PQZ_KIND_BITS;
    }

    function _roleBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.NORMAL_ROLES | GovernanceBits.PQZ_KIND_BITS;
    }

    function _init(IFactoryToken.TokenConfig memory cfg) internal override(MetaTokenBase, NormalTokenCore) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        GovernanceLib.init(cfg.features, cfg.lockedFeatures, cfg.admin, cfg.grantDelay, cfg.rescueTo, cfg.roles, _validBits(),
            _roleBits(), _contractOnlyBits(), _registry());
        PqzStateLib.init(cfg.conf, _registry(), _pqzVerifier(), FACTORY);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }


    /// @dev The layer's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view virtual override(MetaTokenBase, PqzLayer) {
        PqzLayer._validateEnv(env);
    }
    function _domainName() internal pure virtual override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view virtual override(MetaTxBaseCore, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override(PqzLayer, UAMetaTxBaseCore) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _batchable(bytes4 sel) internal view virtual override(MetaTxBaseCore, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-PQZ-21): `cancelNonce`, `burn(uint256)` `AMOUNT(0)`, the PQZ ops
    ///         `ABSOLUTE` (incl. the rollover and `mtxPrepareAcc`).
    function _mtxSelectorsBody() internal pure virtual override(MetaTxBaseCore, NormalTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](10);
        c = new uint8[](10);
        a = new uint8[](10);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (BURN_SELECTOR, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (IConfidentialToken.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[3], c[3]) = (IPqzToken.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[4], c[4]) = (IPqzToken.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[5], c[5]) = (IPqzToken.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (IPqzToken.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (IPqzToken.mtxConfidentialTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (IPqzToken.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (IPqzToken.mtxPrepareAcc.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view virtual override(MetaTxBaseCore, NormalTokenCore) returns (MtxRule memory) {
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return NormalTokenCore._mtxRule(sel);
    }

    /// @notice `burn` and the PQZ ops (CTR-PQZ-15: the PQ-complete path).
    function _uaAllowed(bytes4 sel) internal view virtual override(NormalTokenCore, UAMetaTxBaseCore) returns (bool) {
        return _isPqzOp(sel) || NormalTokenCore._uaAllowed(sel);
    }
}
