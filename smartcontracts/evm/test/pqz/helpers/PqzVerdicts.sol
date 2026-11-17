// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";

/// @notice Group 3f (PQZ verifier mode spec §5.1): the empty verdict a `PRECOMPILE` token's proof-carrying entries take (every
///         field 0, an empty `UASig`); the token never reads it.
function noVerdict() pure returns (IPqzToken.PqzSignedVerdict memory v) {}
