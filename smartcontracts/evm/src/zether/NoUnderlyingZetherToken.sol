// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NoUnderlyingToken} from "../metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Kind `NONE_ZETHER` (CTR-TOK-21): the standalone token with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. `MINTABLE` mints public units only; shielded
///         value exists only through `zetherShield`, which moves public units to `SHIELD_POOL`. Flags: `PAYABLE`, `MINTABLE`, `BURNABLE`
///         (the regulated flags are refused, CTR-ZTH-47). Built by `OpenFactory.createToken` with `conf` set and `legs`,
///         `rate` empty. Never on Hedera (no dev chain there).
contract NoUnderlyingZetherToken is NoUnderlyingToken, ZetherLayer {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env` (Hedera off: no
    ///      dev chain there); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        NoUnderlyingToken(envVersion, env, implArgs)
        ZetherLayer(env)
    {}

    function kind() public pure override(NoUnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_NONE_ZETHER;
    }

    function _init(TokenConfig memory cfg) internal override(NoUnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
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

    /// @notice The allowlist (CTR-MTX-19, CTR-ZTH-34): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`, then the
    ///         Zether ops, each `ABSOLUTE`.
    function mtxSelectors()
        public pure override(NoUnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](8);
        c = new uint8[](8);
        a = new uint8[](8);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
        (s[2], c[2]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
        (s[3], c[3]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[4], c[4]) = (this.zetherTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[5], c[5]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(NoUnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel)) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return NoUnderlyingToken._mtxRule(sel);
    }

    /// @notice `NoUnderlyingToken`'s UA allowlist (`burn`) and `zetherShield` (CTR-ZTH-51: no proof, no binding; the Zether
    ///         UA shields its own public units, UA-6 U8); the proof-carrying Zether ops join it in UA-5c.
    function _uaAllowed(bytes4 sel) internal view override(NoUnderlyingToken, ERC20MetaTx) returns (bool) {
        return sel == this.zetherShield.selector || NoUnderlyingToken._uaAllowed(sel);
    }
}
