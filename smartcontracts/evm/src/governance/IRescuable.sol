// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Rescue of what a token does not owe (CTR-GOV-06, spec §6.2): `RESCUABLE` is set exactly when `rescueTo != 0`.
///        Until the rescue is built, a non-zero `rescueTo` at creation fails closed.
interface IRescuable {
    error RescueConfigInvalid();
}
