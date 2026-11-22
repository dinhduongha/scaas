// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.37;

/// NET-EVM-18's fixture (script/forkcheck.py, test/forkcheck/cases.json): a contract that runs at Cancun. `addClzByte` pushes
/// 0x1e (CLZ's byte) as PUSH data, which the scan must skip; `set` / `stored` change and read state; `fail` reverts.
contract ForkcheckPlain {
    error ForkcheckNope();

    uint256 public stored;

    function set(uint256 x) external {
        stored = x;
    }

    function addClzByte(uint256 x) external pure returns (uint256) {
        return x + 0x1e;
    }

    function fail() external pure {
        revert ForkcheckNope();
    }
}
