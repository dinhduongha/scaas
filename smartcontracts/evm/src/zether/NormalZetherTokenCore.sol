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
abstract contract NormalZetherTokenCore is NormalTokenCore, ZetherLayer {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, chain-neutral spec §2.1): its address; no
    ///      `implArgs`. The env (Hedera off) is checked by `validateEnv` (`ZetherLib`).
    constructor(address factory_, bytes memory implArgs) NormalTokenCore(factory_, implArgs) {}

    function kind() public pure virtual override(MetaTokenBase, NormalTokenCore) returns (uint8) {
        return TokenStore.KIND_NORMAL_ZETHER;
    }

    function _validBits() internal pure virtual override(GovernanceBaseCore, NormalTokenCore) returns (uint256) {
        return GovernanceBits.NORMAL_BITS;
    }

    /// @dev Never reached: `_initRaw` is the kind's init.
    function _init(IFactoryToken.TokenConfig memory) internal override(MetaTokenBase, NormalTokenCore) {}

    /// @dev The init path in `ZetherLib` (CTR-ZTH-94, size lever 1 as on `WrappedZetherToken`): no `TokenConfig` coder
    ///      stays here. In `NormalToken`'s order: the unused fields and the metadata, `GovernanceLib.init`, the Zether config,
    ///      the initial mint.
    function _initRaw(bytes calldata initArgs) internal virtual override {
        (uint256 features_, uint256 locked, bytes32 owner_, uint64 delay, address rescueTo_, GovernanceLib.Roles memory roles) =
            ZetherLib.initNormal(initArgs, kind());
        GovernanceLib.init(features_, locked, owner_, delay, rescueTo_, roles, _validBits(), _roleBits(), _contractOnlyBits(),
            _registry());
        (address holder, uint256 supply) = ZetherLib.initNormalConf(initArgs, _transferVerifier());
        if (supply != 0) _mint(holder, supply);
    }


    /// @dev The layer's env checks, restated for the second base.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view virtual override(MetaTokenBase, ZetherLayer) {
        ZetherLayer._validateEnv(env);
    }
    function _domainName() internal pure virtual override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view virtual override(MetaTxBaseCore, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override(UAMetaTxBaseCore, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._uaEnvelopeBinding(m);
    }

    /// @notice The allowlist (CTR-MTX-19, CTR-ZTH-34): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`, then the
    ///         Zether ops, each `ABSOLUTE`; the table is `ZetherLib.normalSelectors` (CTR-ZTH-94).
    function _mtxSelectorsBody() internal pure virtual override(MetaTxBaseCore, NormalTokenCore) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        return ZetherLib.normalSelectors();
    }

    function _mtxRule(bytes4 sel) internal view virtual override(MetaTxBaseCore, NormalTokenCore) returns (MtxRule memory) {
        if (_isZetherOp(sel)) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return NormalTokenCore._mtxRule(sel);
    }

    /// @notice `NormalToken`'s UA allowlist (`burn`) and the Zether ops (CTR-ZTH-51, UA-5c): `mtxShield` (no proof,
    ///         no binding; the Zether UA shields its own public units, UA-6 U8) and the proof-carrying ones, whose
    ///         statement carries the UA envelope binding; the outer fee from the signer's UA balance.
    function _uaAllowed(bytes4 sel) internal view virtual override(NormalTokenCore, UAMetaTxBaseCore) returns (bool) {
        return _isZetherOp(sel) || NormalTokenCore._uaAllowed(sel);
    }
}
