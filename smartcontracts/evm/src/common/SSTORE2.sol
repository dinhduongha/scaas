// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Bytes stored once as contract code (SSTORE2): runtime = `0x00` (STOP) ‖ data, so the data contract cannot
///        be called into anything; read back with EXTCODECOPY (accounts.md CTR-UA-17 `keyPtr`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
library SSTORE2 {
    error SSTORE2WriteFailed();

    /// Deploys `0x00 ‖ data` with CREATE; reverts if the deployment fails (out of gas, data over the EIP-170 limit).
    function write(bytes memory data) internal returns (address ptr) {
        if (data.length > 0xfffe) revert SSTORE2WriteFailed(); // PUSH2 len+1 below
        // init: PUSH2 len+1, DUP1, PUSH1 0x0c, PUSH1 0, CODECOPY, PUSH1 0, RETURN (12 bytes), then the runtime
        bytes memory init = abi.encodePacked(hex"61", uint16(data.length + 1), hex"80600c6000396000f3", hex"00", data);
        assembly ("memory-safe") {
            ptr := create(0, add(init, 32), mload(init))
        }
        if (ptr == address(0)) revert SSTORE2WriteFailed();
    }

    /// The data `write` stored at `ptr` (the code after the STOP byte); empty if `ptr` has no code.
    function read(address ptr) internal view returns (bytes memory data) {
        uint256 len = ptr.code.length;
        if (len == 0) return data;
        data = new bytes(len - 1);
        assembly ("memory-safe") {
            extcodecopy(ptr, add(data, 32), 1, sub(len, 1))
        }
    }
}
