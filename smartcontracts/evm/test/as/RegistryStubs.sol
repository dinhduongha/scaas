// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// Plan T29 (regulated-kinds spec §5, §9): registry stand-ins installed by `vm.etch` over the canonical registry's address
/// after a token pinned it, so the token's bounded call meets each failure. None of them is a valid `hasFlags`.

/// Every call reverts.
contract RevertingRegistry {
    fallback() external {
        revert("registry down");
    }
}

/// Every call spends all the gas it is given.
contract GasBurningRegistry {
    fallback() external {
        uint256 x;
        while (true) x++;
    }
}

/// Returns 31 bytes of a true word: shorter than a word.
contract ShortReturnRegistry {
    fallback() external {
        assembly {
            mstore(0, 1)
            return(1, 31)
        }
    }
}

/// Returns the word 2: neither false nor true.
contract TwoReturningRegistry {
    fallback() external {
        assembly {
            mstore(0, 2)
            return(0, 32)
        }
    }
}

/// Returns 64 bytes whose first word is true: longer than a word.
contract LongReturnRegistry {
    fallback() external {
        assembly {
            mstore(0, 1)
            mstore(32, 0)
            return(0, 64)
        }
    }
}

/// True only when it was given at least `CAP - 1,000` gas (the dispatch before `GAS` takes less), else a revert: shows
/// whether the starvation check leaves the callee its whole cap.
contract GasProbeRegistry {
    uint256 internal constant CAP = 50_000;

    fallback() external {
        if (gasleft() + 1_000 < CAP) revert("starved");
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}
