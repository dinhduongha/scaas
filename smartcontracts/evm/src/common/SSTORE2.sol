// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Bytes stored once as contract code (SSTORE2): runtime = `0x00` (STOP) ‖ data, so the data contract cannot
///        be called into anything; read back with EXTCODECOPY (accounts.md CTR-UA-17 `keyPtr`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** It holds UA key records and the Zether / PQZ ciphertext records
///         (`R`, sender memos, stored keys), so it is in the audit scope of every confidential token.
library SSTORE2 {
    error SSTORE2WriteFailed();

    /// The largest piece `writeChunks` stores in one code blob (UA-8 UA8-D7): a blob of any length is split into pieces
    /// of at most 32,768 B, far under the 65,536 B code limit (EIP-7954) and `write`'s 65,534 B bound.
    uint256 internal constant BLOB_CHUNK = 32_768;

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

    /// `data` in pieces of `BLOB_CHUNK` bytes (the last one shorter), one `write` each; no pointer for empty data.
    function writeChunks(bytes memory data) internal returns (address[] memory ptrs) {
        uint256 n = (data.length + BLOB_CHUNK - 1) / BLOB_CHUNK;
        ptrs = new address[](n);
        for (uint256 i; i < n; ++i) {
            uint256 o = i * BLOB_CHUNK;
            uint256 len = data.length - o < BLOB_CHUNK ? data.length - o : BLOB_CHUNK;
            bytes memory piece = new bytes(len);
            assembly ("memory-safe") {
                mcopy(add(piece, 32), add(add(data, 32), o), len)
            }
            ptrs[i] = write(piece);
        }
    }

    /// The bytes `writeChunks` stored at `ptrs`, in order; empty for no pointer.
    function readChunks(address[] storage ptrs) internal view returns (bytes memory data) {
        uint256 n = ptrs.length;
        uint256 total;
        for (uint256 i; i < n; ++i) total += ptrs[i].code.length - 1;
        data = new bytes(total);
        uint256 o;
        for (uint256 i; i < n; ++i) {
            address p = ptrs[i];
            uint256 len = p.code.length - 1;
            assembly ("memory-safe") {
                extcodecopy(p, add(add(data, 32), o), 1, len)
            }
            o += len;
        }
    }
}
