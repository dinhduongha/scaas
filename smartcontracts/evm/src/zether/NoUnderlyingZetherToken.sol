// SPDX-License-Identifier: Apache-2.0
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

/// @title Kind `NONE_ZETHER` (CTR-TOK-21): the standalone token with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. `MINTABLE` mints public units only; shielded
///         value exists only through `zetherShield`, which burns public units. Flags: `PAYABLE`, `MINTABLE`, `BURNABLE`
///         (the regulated flags are refused, CTR-ZTH-47). Built by `OpenFactory.createToken` with `conf` set and `legs`,
///         `rate` empty. Never on Hedera (no dev chain there).
contract NoUnderlyingZetherToken is NoUnderlyingToken, ZetherLayer {
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, address registry_,
        ITransferDisclosure disclosure_)
        NoUnderlyingToken(factory_, smartKeyAccountImpl_, chainUid_, false)
        ZetherLayer(registry_, disclosure_)
    {}

    function kind() public pure override(NoUnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_NONE_ZETHER;
    }

    function _init(TokenConfig calldata cfg) internal override(NoUnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, false, true, true, false);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NONE_ZETHER, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
        ZetherLib.init(cfg.conf);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    /// @notice The public allowlist until the layer's entries are relayed (`cancelNonce`, `burn`).
    function mtxSelectors()
        public pure override(NoUnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory, uint8[] memory, uint8[] memory)
    {
        return NoUnderlyingToken.mtxSelectors();
    }

    function _mtxRule(bytes4 sel) internal view override(NoUnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        return NoUnderlyingToken._mtxRule(sel);
    }
}
