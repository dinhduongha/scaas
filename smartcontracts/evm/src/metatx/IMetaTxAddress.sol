// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The address generic entries (ua-mtx-merge MD-1): the wallets only (`MetaTxAddressBase`); tokens and the router
///        take ids on the same names (`UAMetaTxBase`). Beside `IMetaTx`, not derived from it: the core is the wallets'
///        `MetaTxBase`'s, so their sources need no new override list.
interface IMetaTxAddress {
    function mtxNonce(address from, uint256 batch) external view returns (uint256);
    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
    function mtxCancelNonce(MetaTxLib.Envelope calldata e, uint256 lane, bytes calldata sig) external returns (bytes memory);
}
