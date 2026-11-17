// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

/// The body: what a body module's entry does after the stub's forward (here a trivial body, so the figure is the forward).
contract FwdBody {
    function op(bytes calldata blob, uint256 x) external pure returns (uint256) {
        return x + blob.length;
    }
}

/// The token's stub: the same signature, its body one forward of the unchanged calldata by DELEGATECALL (lever L, forward
/// form), the return and revert data passed verbatim.
contract FwdStub {
    address immutable MODULE;

    constructor(address m) {
        MODULE = m;
    }

    function op(bytes calldata, uint256) external returns (uint256) {
        address m = MODULE;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), m, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

/// Two calls in one transaction: the second forward finds the module warm.
contract FwdTwice {
    function twice(address t, bytes calldata blob) external returns (uint256 first, uint256 second) {
        uint256 g = gasleft();
        FwdBody(t).op(blob, 1);
        first = g - gasleft();
        g = gasleft();
        FwdBody(t).op(blob, 2);
        second = g - gasleft();
    }
}

/// @notice ua-mtx-merge T66b Step 2: the per-call cost of a forward stub, by calldata size, in forge's deterministic gas
///         (Amsterdam). Inside one transaction (`FwdTwice`, gasleft around each call): `cold` = gas(stub -> module) -
///         gas(the same body called directly), each account touched for the first time (the module's 2,600 included);
///         `warm` = the same on a second call. The calldata itself is paid once by the transaction either way, so the
///         figure is what the forward adds: the copy into memory, its expansion, DELEGATECALL, the return copy. Not a timing
///         calibration.
contract T66bForwardGasTest is Test {
    function test_t66bForwardGas() public {
        FwdBody module = new FwdBody();
        FwdStub stub = new FwdStub(address(module));
        FwdTwice two = new FwdTwice();
        FwdBody directTwo = new FwdBody();
        uint32[7] memory sizes = [uint32(0), 256, 1_024, 4_096, 21_000, 100_000, 340_000];
        for (uint256 i; i < sizes.length; ++i) {
            bytes memory blob = new bytes(sizes[i]);
            for (uint256 j; j < blob.length; j += 32) blob[j] = 0x01; // non-zero words, as a proof's
            (uint256 s1, uint256 s2) = two.twice(address(stub), blob);
            (uint256 d1, uint256 d2) = two.twice(address(directTwo), blob);
            emit log(string.concat("FWD | ", vm.toString(uint256(sizes[i])), " B | cold ", vm.toString(s1 - d1), " | warm ",
                vm.toString(s2 - d2)));
        }
    }
}
