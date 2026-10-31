// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../metatx/NormalToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Kind `NORMAL_ZETHER` (CTR-TOK-21): the standalone token with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED.** Any chain with EIP-2537 (BLS12-381). `MINTABLE` mints public units only; shielded
///         value exists only through `mtxShield`, which moves public units to `SHIELD_POOL`. Flags: `PAYABLE`, `MINTABLE`, `BURNABLE`
///         (the regulated flags are refused, CTR-ZTH-47). Built by `OpenFactory.createToken` with `conf` set and `legs`,
///         `rate` empty. Never on Hedera (`ZetherLayer` refuses a Hedera env).
contract NormalZetherToken is NormalToken, ZetherLayer {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env` (Hedera off: `ZetherLayer`
    ///      refuses a Hedera env); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        NormalToken(envVersion, env, implArgs)
        ZetherLayer(env)
    {}

    function kind() public pure override(NormalToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_NORMAL_ZETHER;
    }

    function _init(TokenConfig memory cfg) internal override(NormalToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NORMAL_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
        ZetherLib.init(cfg.conf, TRANSFER_VERIFIER);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(ERC20MetaTx, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._uaEnvelopeBinding(m);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-ZTH-34): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`, then the
    ///         Zether ops, each `ABSOLUTE`.
    function mtxSelectors()
        public pure override(NormalToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](11);
        c = new uint8[](11);
        a = new uint8[](11);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (this.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[3], c[3]) = (this.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[4], c[4]) = (this.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[5], c[5]) = (this.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (this.mtxRollOverBatch.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.mtxRollOverSigned.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.mtxSetRollOverMode.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(NormalToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel)) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return NormalToken._mtxRule(sel);
    }

    /// @notice `NormalToken`'s UA allowlist (`burn`) and the Zether ops (CTR-ZTH-51, UA-5c): `mtxShield` (no proof,
    ///         no binding; the Zether UA shields its own public units, UA-6 U8) and the proof-carrying ones, whose
    ///         statement carries the UA envelope binding; the outer fee from the signer's UA balance.
    function _uaAllowed(bytes4 sel) internal view override(NormalToken, ERC20MetaTx) returns (bool) {
        return _isZetherOp(sel) || NormalToken._uaAllowed(sel);
    }
}
