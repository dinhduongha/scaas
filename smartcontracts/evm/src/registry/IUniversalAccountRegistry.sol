// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {AuthScheme} from "../common/AuthScheme.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";

/// @title Sổ đăng ký Universal Account (SRS §7.5, §9.5) — 8 AuthScheme, PoP chống rogue key.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Đặc tả: `2026-10-03-zether-design.md` §11.
///         `UA = keccak256(encodedY)`; `|encodedY|` = 64 (bn254) hoặc 128 (BLS12-381) chọn đường cong.
interface IUniversalAccountRegistry {
    struct AccountConfig {
        bool registered;
        AuthScheme scheme;
        address linkedEVMAddress;
        bytes authData;
    }

    event AccountRegistered(
        ZetherTypes.UA indexed ua,
        AuthScheme indexed scheme,
        address indexed linkedEVM,
        bytes authData
    );

    error AccountAlreadyRegistered(ZetherTypes.UA ua);
    error InvalidProofOfPossession();
    error UnauthorizedScheme(AuthScheme scheme);
    error EVMAlreadyLinked(address evmAddress);
    error InvalidPublicKey();
    error InvalidAuthData();
    error Unauthorized(ZetherTypes.UA ua);

    /// @notice Đăng ký với PoP trên `c = keccak256(abi.encodePacked(registry, encodedY, msg.sender))`.
    /// @param popSignature `abi.encode(bytes schnorrPop, bytes authPop)` (§11.2).
    /// @dev `c` trói `msg.sender` ⇒ chủ thể tự gọi (EOA hoặc smart account của mình).
    function register(
        bytes calldata encodedY,
        AuthScheme authScheme,
        bytes calldata authData,
        bytes calldata popSignature,
        bool linkEVM
    ) external returns (ZetherTypes.UA ua);

    function accounts(ZetherTypes.UA ua)
        external view returns (bool registered, AuthScheme scheme, address linkedEVMAddress, bytes memory authData);

    function links(address evmAddress) external view returns (ZetherTypes.UA);

    // solhint-disable-next-line func-name-mixedcase
    function link_eth(ZetherTypes.UA ua) external view returns (address);

    function isRegistered(ZetherTypes.UA ua) external view returns (bool);

    /// @notice 64 (bn254) | 128 (BLS12-381) | 0 (chưa đăng ký). Token so với `verifier.g1EncodedBytes()`.
    function keyLengthOf(ZetherTypes.UA ua) external view returns (uint256);

    /// @notice `encodedY` of a registered UA (empty otherwise): the recipient keys of a sender's storage-only recovery
    ///         (zether.md CTR-ZTH-50).
    function keyOf(ZetherTypes.UA ua) external view returns (bytes memory);

    /// @notice Thông điệp PoP mà `account` phải ký cho `encodedY`.
    function popChallenge(bytes calldata encodedY, address account) external view returns (bytes32);

    /// @notice Bất biến an ninh #1 (§02.4.2): revert `Unauthorized` trừ khi `sig` uỷ quyền `digest` theo
    ///         `authScheme` của `ua`. `zkCovered = true` khi một ZK proof biết `x` đã đi kèm (transfer/burn):
    ///         khi đó `SELF_SCHNORR`/`PQ_COMMITMENT` không cần chữ ký ngoài (và `sig` phải rỗng).
    function requireAuthorized(ZetherTypes.UA ua, bytes32 digest, bytes calldata sig, bool zkCovered) external view;
}
