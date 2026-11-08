// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {Create3} from "./Create3.sol";

/// Creation-only probe: its constructor returns the check words as "runtime code", so an eth_call without `to` reads them.
contract Probe {
    constructor() {
        // R: runtime that returns keccak256(EXTCODECOPY(ADDRESS)), then a 32-byte marker (like an appended env).
        bytes memory r = hex"303b8060006000303c60002060005260206000f3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // init code: copy R from the init code's own tail and return it.
        bytes memory init = abi.encodePacked(hex"6034600c60003960346000f3", r);
        bytes32 s = keccak256("scaas-hedera-probe");
        address predicted = Create3.addressOf(address(this), s);
        address proxy = Create3.proxyOf(address(this), s);
        address actual = Create3.deploy(s, init);
        bytes32 outer = actual.code.length == 0 ? bytes32(0) : keccak256(actual.code);
        (bool ok, bytes memory self) = actual == address(0) ? (false, bytes("")) : actual.staticcall("");
        bytes32 inner = ok && self.length == 32 ? abi.decode(self, (bytes32)) : bytes32(0);
        bytes memory out = abi.encode(predicted, actual, proxy, proxy.code.length, outer, inner, keccak256(r), r.length);
        assembly { return(add(out, 0x20), mload(out)) }
    }
}
