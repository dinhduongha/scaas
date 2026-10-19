// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";

/// @notice An `OpenFactory` without confidential verifiers (CTR-ZTH-20: no confidential release can be registered).
function noVerifiers() pure returns (IOpenFactory.Canonical memory c) {}

/// @notice An `OpenFactory` whose Zether curve `curve` (0 bn254, 1 BLS12-381) has this transfer / burn verifier pair and
///         disclosure contract.
function zetherCanon(uint8 curve, address verifier, address burnVerifier, address disclosure)
    pure returns (IOpenFactory.Canonical memory c)
{
    (c.zetherVerifier[curve], c.zetherBurnVerifier[curve], c.zetherDisclosure[curve]) = (verifier, burnVerifier, disclosure);
}

/// @notice An `OpenFactory` whose PQZ proof system `ps` (0 PQZL, 1 PQZH) has this `UAPqzVerifier`.
function pqzCanon(uint8 ps, address verifier) pure returns (IOpenFactory.Canonical memory c) {
    c.pqzVerifier[ps] = verifier;
}
