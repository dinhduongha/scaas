// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "./ITradeToken.sol";

/// @title The liquidity order's hashing (CTR-DEX-30; spec 2026-11-10-dex-liquidity.md §4.2, §4.3): internal only, compiled
///        into module T of every token kind and into the DEX's liquidity module, so every verifier computes the digest
///        itself. The domain is the DEX's (`"SCaaS Dex"`, `"1"`, `verifyingContract`, the chain's `chain_uid` as `salt`):
///        a token passes `msg.sender`, the DEX's module `address(this)` (the clone, under DELEGATECALL). UNAUDITED.
library LiquidityLib {
    bytes32 internal constant LIQUIDITY_TOKEN_TYPEHASH = keccak256("LiquidityToken(address token,uint256 amount)");
    bytes32 internal constant LIQUIDITY_ORDER_TYPEHASH = keccak256(
        "LiquidityOrder(bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,address positionManager,"
        "address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,int24 tickUpper,uint128 minLiquidity,"
        "bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
        "LiquidityToken(address token,uint256 amount)"
    );
    /// @dev `SaltedEIP712`'s domain type, and the DEX's name and version hashes (`SCaaSDex`'s `SaltedEIP712Core("SCaaS
    ///      Dex", "1", …)`; the KAT `test/v2/LiquidityKat.t.sol` pins the parity).
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );
    bytes32 internal constant DEX_NAME_HASH = keccak256("SCaaS Dex");
    bytes32 internal constant DEX_VERSION_HASH = keccak256("1");

    function hashTokens(ITradeToken.LiquidityToken[] calldata ts) internal pure returns (bytes32) {
        bytes32[] memory hs = new bytes32[](ts.length);
        for (uint256 i; i < ts.length; ++i) {
            hs[i] = keccak256(abi.encode(LIQUIDITY_TOKEN_TYPEHASH, ts[i].token, ts[i].amount));
        }
        return keccak256(abi.encodePacked(hs));
    }

    /// @dev Two `abi.encode` halves of static words, concatenated: the one encoding of the 18 words, under the stack limit.
    function hashOrder(ITradeToken.LiquidityOrder calldata o) internal pure returns (bytes32) {
        bytes memory a = abi.encode(LIQUIDITY_ORDER_TYPEHASH, o.from, hashTokens(o.inputs), hashTokens(o.outputs),
            o.positionManager, o.positionReader, o.positionIn, o.positionPool, o.tickLower);
        bytes memory b = abi.encode(o.tickUpper, o.minLiquidity, o.recipient, o.fee, o.relayer, o.flags, o.batch, o.nonce,
            o.validUntil);
        return keccak256(bytes.concat(a, b));
    }

    function separator(address dex, bytes32 chainUid) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, DEX_NAME_HASH, DEX_VERSION_HASH, block.chainid, dex, chainUid));
    }

    /// @notice The order's digest `h` in the domain of the DEX at `dex`.
    function digest(ITradeToken.LiquidityOrder calldata o, address dex, bytes32 chainUid) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", separator(dex, chainUid), hashOrder(o)));
    }
}
