// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `NORMAL` (CTR-TOK-21): a standalone token, no underlying.
/// @notice Flags valid here: `PAYABLE`, `MINTABLE` (role `minter`), `BURNABLE` (holder burn). A supply cap or a mint
///         rate limit, if an issuer needs one, lives in its minter contract. Built by `OpenFactory.createToken`
///         (CTR-TOK-25): `initialSupply` is minted to `initialHolder`; `legs`, `rate`, `conf` must be empty.
contract NormalToken is MetaTokenBase {
    bytes32 internal constant BURN_TYPEHASH = keccak256(
        "Burn(address from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_BURN_TYPEHASH = keccak256(
        "UABurn(bytes32 from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`; this kind takes
    ///      no `implArgs`.
    constructor(uint16, Env memory env, bytes memory) MetaTokenBase(env) {}

    function kind() public pure virtual override returns (uint8) {
        return AdminLib.KIND_NORMAL;
    }

    function _init(TokenConfig memory cfg) internal virtual override {
        _requireUnused(cfg, false, true, true, true);
        _setMetadata(cfg.name, cfg.symbol, cfg.decimals);
        AdminLib.init(AdminLib.KIND_NORMAL, cfg.features, cfg.lockedFeatures, cfg.owner, cfg.roles);
        if (cfg.initialSupply != 0) _mint(cfg.initialHolder, cfg.initialSupply);
    }

    /// @notice `MINTABLE` and the `minter` role; never allowlisted (a minter contract's caps run on its own call).
    function mint(address to, uint256 amount) external nonReentrant {
        AdminLib.requireRole(AdminLib.MINTABLE, _msgSender());
        _mint(to, amount);
    }

    /// @notice `mint` into the registered SIGNING UA `to` (CTR-UA-28): the same flag and role; never allowlisted.
    function mintToUA(bytes32 to, uint256 amount) external nonReentrant {
        AdminLib.requireRole(AdminLib.MINTABLE, _msgSender());
        _uaMint(to, amount);
    }

    /// @notice Allowlisted `AMOUNT(0)` (CTR-MTX-19): gasless through `mtxExecute`.
    function burn(uint256 amount) external nonReentrant {
        AdminLib.requireFeature(AdminLib.BURNABLE);
        _burn(_msgSender(), amount);
    }

    /// @notice The signed `burn(amount)` (TS-D14), `AMOUNT(0)` as on the generic path.
    function mtxBurn(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(BURN_TYPEHASH, this.burn.selector, e, abi.encode(amount), sig);
    }

    function uaBurn(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(UA_BURN_TYPEHASH, this.burn.selector, e, abi.encode(amount), auth);
    }

    /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.
    function mtxSelectors()
        public pure virtual override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](2);
        c = new uint8[](2);
        a = new uint8[](2);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
    }

    /// @notice The UA allowlist (CTR-UA-26): `burn` (a derived signer burns its UA balance through `UA_POOL`).
    function _uaAllowed(bytes4 sel) internal view virtual override returns (bool) {
        return sel == this.burn.selector;
    }

    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
        if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        return super._mtxRule(sel);
    }
}
