// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// @notice Test kit for the pay entries' `PayMeta` (pay-meta-tax spec §3.1): a salt-only `PayMeta` from a seed and its
///         commitment, computed here from the formula (not by the token), so a token on another formula fails.
library PayMetaKit {
    /// A salt-only `PayMeta` (schema 0, `payNo` 0, `save` off, empty body), the salt derived from `seed`.
    function meta(bytes32 seed) internal pure returns (MetaTxLib.PayMeta memory m) {
        m.salt = keccak256(abi.encode("scaas.test.paymeta", seed));
    }

    /// `metaPayId(m)` under `scaas.pay.meta.v3` (plan T83: `payNo` a `bytes32`, `save` committed).
    function id(MetaTxLib.PayMeta memory m) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.pay.meta.v3", m.salt,
            keccak256(abi.encode(m.payNo, m.save, m.schema, m.body))));
    }

    /// A `PayMeta` that stores its record: `meta(seed)` with `payNo` and `save` set.
    function saved(bytes32 seed, bytes32 payNo) internal pure returns (MetaTxLib.PayMeta memory m) {
        m = meta(seed);
        (m.payNo, m.save) = (payNo, true);
    }

    /// The `entryRef` of `meta(seed)`.
    function ref(bytes32 seed) internal pure returns (bytes32) {
        return id(meta(seed));
    }
}
