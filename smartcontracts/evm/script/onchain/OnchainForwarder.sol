// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @notice A contract holder for the entries that take a contract (the allowance rule CTR-TOK-01: `approve` and
///         `transferFrom` from a contract only; `RATE_ADJUSTABLE`'s holder a native id with code). Its deployer alone calls.
///         A file of its own, no imports (owner 2026-11-10): its standard JSON on the explorer is this file alone; inside
///         Tokens.s.sol it carried that script's whole import closure (1.7 MB) and the SCaaS testnet's Blockscout refused it.
///         Renamed (owner 2026-11-10): was `OnchainFwd.exec(address,bytes)`, selector 0xbe6002c2, in Tokens.s.sol (the
///         records and books of the deploy before the SCaaS testnet's reset 2 keep that name); behaviour unchanged.
contract OnchainForwarder {
    address internal immutable O;

    constructor() {
        O = msg.sender;
    }

    function forwardCall(address target, bytes calldata data) external returns (bytes memory r) {
        require(msg.sender == O, "OnchainForwarder: not the deployer");
        bool ok;
        (ok, r) = target.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(r, 32), mload(r)) }
    }
}
