// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzCt} from "../../../src/pqz/PqzCt.sol";

/// Calldata entry to the library (its inputs are calldata on every token path).
contract PqzCtHarness {
    function sum(bytes calldata acc, bytes[] calldata plus_, bytes[] calldata minus_, uint256 plain)
        external pure returns (bytes memory c)
    {
        c = PqzCt.load(acc);
        for (uint256 i; i < plus_.length; ++i) PqzCt.plus(c, plus_[i]);
        for (uint256 i; i < minus_.length; ++i) PqzCt.minus(c, minus_[i]);
        PqzCt.addTrivial(c, plain);
        PqzCt.reduce(c);
    }

    function canonical(bytes calldata b) external pure returns (bool) {
        return PqzCt.isCanonical(b);
    }
}
