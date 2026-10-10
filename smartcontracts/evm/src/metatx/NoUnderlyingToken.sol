// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Kind `NONE` (CTR-TOK-21): a standalone token, no underlying.
/// @notice Flags valid here: `PAYABLE`, `MINTABLE` (role `minter`), `BURNABLE` (holder burn). A supply cap or a mint
///         rate limit, if an issuer needs one, lives in its minter contract. Built by the factory through
///         `initialize(creator, [], version, abi.encode(NoneInit))`; P1e switches to `TokenConfig`.
contract NoUnderlyingToken is MetaTokenBase {
    /// @notice The NONE subset of `TokenConfig` (CTR-TOK-25).
    struct NoneInit {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        AdminLib.Roles roles;
        uint256 initialSupply;
        address initialHolder;
    }

    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_NONE;
    }

    /// @param initData `abi.encode(NoneInit)`.
    function _init(address, address[] calldata underlyings, bytes calldata initData) internal override {
        if (underlyings.length != 0) revert UnderlyingCountInvalid(underlyings.length);
        NoneInit memory c = abi.decode(initData, (NoneInit));
        _setMetadata(c.name, c.symbol, c.decimals);
        AdminLib.init(AdminLib.KIND_NONE, c.features, c.lockedFeatures, c.owner, c.roles);
        if (c.initialSupply != 0) _mint(c.initialHolder, c.initialSupply);
    }

    /// @notice `MINTABLE` and the `minter` role; never allowlisted (a minter contract's caps run on its own call).
    function mint(address to, uint256 amount) external {
        AdminLib.requireRole(AdminLib.MINTABLE, _msgSender());
        _mint(to, amount);
    }

    /// @notice Allowlisted `AMOUNT(0)` (CTR-MTX-19): gasless through `mtxExecute`.
    function burn(uint256 amount) external nonReentrant {
        AdminLib.requireFeature(AdminLib.BURNABLE);
        _burn(_msgSender(), amount);
    }

    /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.
    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](2);
        c = new uint8[](2);
        a = new uint8[](2);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        return super._mtxRule(sel);
    }
}
