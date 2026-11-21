// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.37;

/// NET-EVM-18 check (4)'s control at Cancun (script/forkcheck.py CONTROL): its `amsterdam` artifact runs CLZ (0x1e, EIP-7939),
/// which Cancun lacks, so `lz(1)` must be red there; a run where it is green is void.
contract ForkcheckClz {
    function lz(uint256 x) external pure returns (uint256 r) {
        assembly {
            r := clz(x)
        }
    }
}
