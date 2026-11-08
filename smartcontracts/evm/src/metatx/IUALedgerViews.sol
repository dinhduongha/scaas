// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The views of the one nonce map on ids, split from `IUALedger` (ua-mtx-merge, R9 cost): they answer with the
///        ledger on or off, so they are not under `IUALedger`'s ERC-165 report, which stays false at `registry() == 0`.
interface IUALedgerViews {
    /// @notice The lane's next nonce of an id: a native address zero-padded, a derived UA as itself (CTR-UA-26).
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
    /// @notice The EIP-712 digest of a `UAMetaTransaction` in this contract's domain.
    function mtxDigest(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
}
