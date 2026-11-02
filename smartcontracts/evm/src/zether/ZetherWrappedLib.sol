// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IZetherToken, IZetherWrappedToken} from "./IZetherToken.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The wrapped-only code of `WrappedZetherToken` behind external calls: the init path and the selector table (size
///        lever 1, owner 2026-11-01), and the body of `mtxUnshieldUnwrap` and its signed forms (CTR-ZTH-94).
/// @notice **UNAUDITED.** External library in the release's link closure of `WRAPPED_ZETHER` only. `init` chains
///         `WrappedLib` and `ZetherLib` by DELEGATECALL, still in the token's context: `LinkClosure.test_libraryOpcodes`
///         pins exactly these two; the unshield runs `ZetherLib`'s internal code inlined here. No state of its own, no
///         immutable.
library ZetherWrappedLib {
    uint8 private constant ABSOLUTE = MtxPipelineLib.FEE_CLASS_ABSOLUTE;
    uint8 private constant AMOUNT = MtxPipelineLib.FEE_CLASS_AMOUNT;
    /// @dev Moved from `WrappedZetherToken` (CTR-ZTH-94), unchanged.
    bytes32 private constant UNSHIELD_UNWRAP_TYPEHASH = keccak256(
        "ZetherUnshieldUnwrap(address from,ZetherBurn args,Unwrap unwrap,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)"
    );
    bytes32 private constant UA_UNSHIELD_UNWRAP_TYPEHASH = keccak256(
        "UAZetherUnshieldUnwrap(bytes32 from,ZetherBurn args,Unwrap unwrap,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)"
    );

    /// @notice The kind's init from the factory's raw `initArgs`: `initialSupply` and `initialHolder` empty, `legs`, the
    ///         rate and `conf` are checked by the two libraries. Never on Hedera (`ZetherLayer` refuses that env).
    function init(bytes calldata initArgs, IZetherVerifier v) public {
        IFactoryToken.TokenConfig memory cfg = abi.decode(initArgs, (IFactoryToken.TokenConfig));
        if (cfg.initialSupply != 0 || cfg.initialHolder != address(0)) revert IFactoryToken.ConfigFieldForOtherKind(1);
        WrappedLib.initToken(cfg, false, TokenStore.KIND_WRAPPED_ZETHER, GovernanceBits.WRAPPED_BITS);
        ZetherLib.init(cfg.conf, v);
    }

    /// @notice `mtxSelectors()` of the kind (`WrappedZetherToken`'s comment): `WrappedToken`'s first six, the Zether ops, the
    ///         two underlying paths, `WrappedToken`'s UA-5a two, the roll-overs.
    function selectors() public pure returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {
        s = new bytes4[](19);
        c = new uint8[](19);
        a = new uint8[](19);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, ABSOLUTE);
        (s[1], c[1]) = (bytes4(keccak256("wrap(uint256)")), ABSOLUTE);
        (s[2], c[2]) = (bytes4(keccak256("unwrap(uint256,address,uint256)")), AMOUNT);
        (s[3], c[3]) = (bytes4(keccak256("wrap(address,uint256)")), ABSOLUTE);
        (s[4], c[4], a[4]) = (bytes4(keccak256("unwrap(address,uint256,address,uint256)")), AMOUNT, 1);
        (s[5], c[5]) = (bytes4(keccak256("addReserve(address,uint256)")), ABSOLUTE);
        (s[6], c[6]) = (IConfidentialToken.mtxShield.selector, ABSOLUTE);
        (s[7], c[7]) = (IZetherToken.mtxConfidentialTransfer.selector, ABSOLUTE);
        (s[8], c[8]) = (IZetherToken.mtxConfidentialTransferCompact.selector, ABSOLUTE);
        (s[9], c[9]) = (IZetherToken.mtxConfidentialTransferSingle.selector, ABSOLUTE);
        (s[10], c[10]) = (IZetherToken.mtxUnshield.selector, ABSOLUTE);
        (s[11], c[11]) = (IConfidentialWrappedToken.mtxWrapShield.selector, ABSOLUTE);
        (s[12], c[12]) = (IZetherWrappedToken.mtxUnshieldUnwrap.selector, ABSOLUTE);
        (s[13], c[13]) = (bytes4(keccak256("wrapToUA(address,uint256,bytes32)")), ABSOLUTE);
        (s[14], c[14], a[14]) = (bytes4(keccak256("unwrapToUA(address,uint256,bytes32,uint256)")), AMOUNT, 1);
        (s[15], c[15]) = (IConfidentialToken.mtxRollOver.selector, ABSOLUTE);
        (s[16], c[16]) = (IZetherToken.mtxRollOverBatch.selector, ABSOLUTE);
        (s[17], c[17]) = (IZetherToken.mtxRollOverSigned.selector, ABSOLUTE);
        (s[18], c[18]) = (IZetherToken.mtxSetRollOverMode.selector, ABSOLUTE);
    }

    // ------------------------------------------------------------------ unshield-unwrap (CTR-ZTH-45, CTR-ZTH-94)

    /// @notice The proof part of a direct `mtxUnshieldUnwrap`, forwarded: its arguments as the token got them, then the
    ///         token's `Env`. A direct call (binding 0) binds the leg and `minOut` (`ZetherLib.unwrapBinding`); returns
    ///         the inner fee. The token checked the leg and the payee before, and pays out after.
    function unshieldUnwrap(IZetherToken.ZetherBurn calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof)
        public returns (uint256)
    {
        ZetherLib.Env memory env = ZetherLib.envTail();
        if (env.binding == 0) env.binding = ZetherLib.unwrapBinding(x.underlying, x.minOut);
        return ZetherLib.unshieldWith(b, proof, x.amount, x.recipient, env);
    }

    /// @notice What the signed `mtxUnshieldUnwrap` signs and runs (as `ZetherLib.multiCall`): the `Unwrap` leg a nested
    ///         struct.
    function unwrapCall(MetaTxLib.Envelope calldata, IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, bytes calldata)
        public pure returns (bytes32, bytes memory, bytes memory)
    {
        return (UNSHIELD_UNWRAP_TYPEHASH, _unwrapWords(b, x, proof), _unwrapOp(b, x, proof));
    }

    function uaUnwrapCall(MetaTxLib.UAEnvelope calldata, IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata)
        public pure returns (bytes32, bytes memory, bytes memory)
    {
        return (UA_UNSHIELD_UNWRAP_TYPEHASH, _unwrapWords(b, x, proof), _unwrapOp(b, x, proof));
    }

    function _unwrapWords(IZetherToken.ZetherBurn calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof)
        private pure returns (bytes memory)
    {
        return abi.encode(ZetherLib.hashBurn(b), ZetherLib.hashUnwrap(x), keccak256(proof));
    }

    function _unwrapOp(IZetherToken.ZetherBurn calldata b, IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof)
        private pure returns (bytes memory)
    {
        return abi.encodeCall(IZetherWrappedToken.mtxUnshieldUnwrap, (b, x, proof));
    }
}
