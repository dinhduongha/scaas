// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// the QML invokables take the registry's explicit parameters one by one (no packed input), up to nine
#[allow(clippy::too_many_arguments)]
mod ua_kinds;
// ua-rs-sign T13b: the QML wallet singleton (public data, seal to a public key, sign by handle id)
mod ua_wallet;
