// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title CREATE3 (CTR-TOK-29, chain-neutral spec §4.1; the layout of Solady's and 0xSequence's `CREATE3`, no dependency):
///        an address that depends only on the deployer and the salt, never on the init code.
/// @notice `proxy = CREATE2(deployer, s, PROXY_INITCODE)`, whose 8-byte runtime `363d3d37363d34f0` `CREATE`s its calldata
///         as init code at nonce 1, so `instance = address(keccak256(rlp([proxy, 1]))[12:])`. The proxy stays (no
///         `SELFDESTRUCT`): it exists exactly when `s` was used. A `CREATE` that fails inside the proxy returns 0 there
///         without reverting the outer call, so the caller checks the instance's code (`deploy` answers 0).
library Create3 {
    /// @dev `PUSH8 363d3d37363d34f0 RETURNDATASIZE MSTORE PUSH1 8 PUSH1 24 RETURN`: deposits the 8-byte runtime.
    bytes internal constant PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f3";
    bytes32 internal constant PROXY_INITCODE_HASH = keccak256(hex"67363d3d37363d34f03d5260086018f3");

    function proxyOf(address deployer, bytes32 s) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, s, PROXY_INITCODE_HASH)))));
    }

    /// @dev `rlp([proxy, 1]) = 0xd6 0x94 ‖ proxy ‖ 0x01`.
    function instanceOf(address proxy) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes2(0xd694), proxy, bytes1(0x01))))));
    }

    function addressOf(address deployer, bytes32 s) internal pure returns (address) {
        return instanceOf(proxyOf(deployer, s));
    }

    /// @dev The proxy of `s` (this contract's), then `initCode` through it; 0 when the proxy or the instance was not created.
    function deploy(bytes32 s, bytes memory initCode) internal returns (address instance) {
        bytes memory p = PROXY_INITCODE;
        address proxy;
        assembly ("memory-safe") {
            proxy := create2(0, add(p, 0x20), mload(p), s)
        }
        if (proxy == address(0)) return address(0);
        (bool ok,) = proxy.call(initCode);
        instance = instanceOf(proxy);
        if (!ok || instance.code.length == 0) return address(0);
    }
}
