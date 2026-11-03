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
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {IZetherToken} from "./IZetherToken.sol";

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
        return TokenStore.KIND_NORMAL_ZETHER;
    }

    function _validBits() internal pure override(NormalToken, GovernanceBase) returns (uint256) {
        return GovernanceBits.NORMAL_BITS;
    }

    /// @dev Never reached: `_initRaw` is the kind's init.
    function _init(TokenConfig memory) internal override(NormalToken, MetaTokenBase) {}

    /// @dev The init path in `ZetherLib` (CTR-ZTH-94, size lever 1 as on `WrappedZetherToken`): no `TokenConfig` coder
    ///      stays here. In `NormalToken`'s order: the unused fields and the metadata, `GovernanceLib.init`, the Zether config,
    ///      the initial mint.
    function _initRaw(bytes calldata initArgs) internal override {
        (uint256 features_, uint256 locked, bytes32 owner_, uint64 delay, address rescueTo_, GovernanceLib.Roles memory roles) =
            ZetherLib.initNormal(initArgs);
        GovernanceLib.init(features_, locked, owner_, delay, rescueTo_, roles, _validBits(), _roleBits(), _contractOnlyBits());
        (address holder, uint256 supply) = ZetherLib.initNormalConf(initArgs, TRANSFER_VERIFIER);
        if (supply != 0) _mint(holder, supply);
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
        internal view override(UAMetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._uaEnvelopeBinding(m);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-ZTH-34): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`, then the
    ///         Zether ops, each `ABSOLUTE`; the table is `ZetherLib.normalSelectors` (CTR-ZTH-94).
    function mtxSelectors()
        public pure override(NormalToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return ZetherLib.normalSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(NormalToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel)) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return NormalToken._mtxRule(sel);
    }

    /// @notice `NormalToken`'s UA allowlist (`burn`) and the Zether ops (CTR-ZTH-51, UA-5c): `mtxShield` (no proof,
    ///         no binding; the Zether UA shields its own public units, UA-6 U8) and the proof-carrying ones, whose
    ///         statement carries the UA envelope binding; the outer fee from the signer's UA balance.
    function _uaAllowed(bytes4 sel) internal view override(NormalToken, UAMetaTxBase) returns (bool) {
        return _isZetherOp(sel) || NormalToken._uaAllowed(sel);
    }
}
