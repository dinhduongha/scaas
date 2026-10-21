// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// Plan 5h Task 7b, measurement only (never deployed outside the SCaaS testnet cross-check): the as-built rollover,
// `mtxPrepareAcc` and op 1 library paths (`PqzStateLib`, `PqzTransferLib`, `PqzCore` at the 16k sizes of the work tree)
// behind a contract that is its own registry (`recordOf`, `requireAuthorized`) and whose `pqz` is `PqzOk` (answers 1).
// The same transactions run on Nethermind 2.2.0 (receipts, eth_estimateGas) and on Foundry 1.8.5 (`cast run`).
// Copied into the gas16k.sh work tree by xcheck7622.sh.

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";

contract PqzOk {
    fallback(bytes calldata) external returns (bytes memory) { return abi.encode(uint256(1)); }
}

contract PqzGasHarness {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    mapping(bytes32 => address) internal keyOf;

    constructor(address pqz, bytes32 auditor) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        s.pqz = pqz;
        s.auditorUA = auditor;
        s.auditorMode = ZetherTypes.AuditorMode.OPTIONAL;
        s.shieldScale = 10_000;
        s.maxShielded = uint256(1) << 40;
        s.confidentialFee = 3;
        s.totalShielded = 1_000_000; // the pool holds the fees the measured debit pays out
    }

    /// CREATE with `code` as the runtime (an op blob or an SSTORE2 key pointer).
    function make(bytes calldata code) external returns (address a) {
        bytes memory init = abi.encodePacked(hex"61", uint16(code.length), hex"80600c6000396000f3", code);
        assembly ("memory-safe") { a := create(0, add(init, 32), mload(init)) }
        require(a != address(0), "create");
    }

    function setKey(bytes32 ua, address ptr) external { keyOf[ua] = ptr; }

    /// The gas test's `_seed`: `blobs.length` credits of `ua` at indices `from…`, each `(blob, 16, 16 + PK, block 1)`.
    function seed(bytes32 ua, uint64 from, address[] calldata blobs, uint256 pk) external {
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        for (uint256 i; i < blobs.length; ++i) {
            a.pending[from + uint64(i)] = uint256(uint160(blobs[i])) << 96 | uint256(16) << 80 | (16 + pk) << 64 | 1;
        }
        a.pendingCount = from + uint64(blobs.length);
    }

    function rollOver(bytes32 ua, uint256 n) external { PqzStateLib.rollOver(ua, n); }

    function prepareAcc(bytes32 ua, uint256 half) external { PqzStateLib.prepareAcc(ua, half, address(this)); }

    function transferSingle(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes calldata hint)
        external returns (bytes32 ref)
    {
        PqzCore.Env memory e = PqzCore.Env(address(this), UID, 0, 0, 0, ZetherTypes.TransferMode.BUNDLE);
        (ref,) = PqzTransferLib.transfer(e, payload, hint, proof, auth);
    }

    // ------------------------------------------------------------------ the registry part

    function recordOf(bytes32 ua) external view returns (IUARegistry.Record memory r, address pqzKey) {
        pqzKey = keyOf[ua];
        r.keyPtr = pqzKey;
    }

    function requireAuthorized(bytes32, bytes32, bytes32, bytes calldata) external pure {}

    function account(bytes32 ua) external view returns (uint64 pendingCount, uint64 rolled, uint8 flags) {
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        return (a.pendingCount, a.rolled, a.flags);
    }
}
