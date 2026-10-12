// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Bls12381} from "./Bls12381.sol";

/// @title RFC 9380 hash-to-curve cho BLS12-381 G1, suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`.
/// @notice Đây là nửa còn thiếu của xác minh BLS. EIP-2537 cho `MAP_FP_TO_G1`, tức bước
///         `map_to_curve`; phần trước nó — `expand_message_xmd` rồi `hash_to_field` — phải
///         viết tay, và nó là chỗ dễ sai mà không có triệu chứng.
///
/// **Vì sao đúng khi bỏ `clear_cofactor`.** RFC 9380 làm:
///
///     Q0 = map_to_curve(u0);  Q1 = map_to_curve(u1)
///     R  = Q0 + Q1
///     P  = clear_cofactor(R)
///
/// `MAP_FP_TO_G1` của EIP-2537 **đã** clear cofactor (nó trả về một điểm trong G1). Nên ta
/// tính `h·Q0 + h·Q1` thay vì `h·(Q0 + Q1)`. Hai cái **bằng nhau**: nhân vô hướng là một
/// đồng cấu nhóm, `h·A + h·B = h·(A+B)`. Không phải một xấp xỉ — một đẳng thức.
///
/// **Domain separation là tham số, không phải hằng số.** DST khác nhau cho chữ ký, cho PoP,
/// cho mỗi ứng dụng. Dùng chung một DST giữa hai mục đích là cho phép lấy chữ ký ở ngữ cảnh
/// này dùng lại ở ngữ cảnh kia.
library HashToCurve {
    /// @dev Modulus của trường cơ sở BLS12-381, 48 byte.
    ///      **Đã kiểm trên chain 7622 (formerly 9000)**: `MAP_FP_TO_G1(p-1)` thành công, `MAP_FP_TO_G1(p)`
    ///      revert — đúng hành vi EIP-2537 quy định (input phải < p). Xem
    ///      `test_fieldModulusIsPinnedByThePrecompile` và README-chainspec.md.
    bytes internal constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    address internal constant MODEXP = address(0x05);

    uint256 internal constant B_IN_BYTES = 32;   // SHA-256: kích thước output
    uint256 internal constant S_IN_BYTES = 64;   // SHA-256: kích thước block
    uint256 internal constant L = 64;            // RFC 9380 §8.8.1 cho BLS12-381
    uint256 internal constant FP_PAD = 16;       // 64 - 48, đệm 0 ở ĐẦU cho EIP-2537

    error DstTooLong(uint256 len);
    error TooManyBlocks(uint256 ell);
    error ModexpFailed();

    /// @notice RFC 9380 §5.3.1 `expand_message_xmd` với SHA-256.
    /// @dev Bốn chi tiết mà bỏ một cái là ra byte khác, và không có gì báo:
    ///      - `Z_pad` là **64** byte 0 (block size của SHA-256), không phải 32.
    ///      - `l_i_b_str` là `lenInBytes` **big-endian 2 byte**.
    ///      - Giữa `l_i_b_str` và `DST_prime` có **một byte 0x00**.
    ///      - `DST_prime` = `DST ‖ len(DST)` — độ dài **đi sau**, một byte.
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 lenInBytes)
        internal pure returns (bytes memory)
    {
        if (dst.length > 255) revert DstTooLong(dst.length);
        uint256 ell = (lenInBytes + B_IN_BYTES - 1) / B_IN_BYTES;
        if (ell > 255) revert TooManyBlocks(ell);

        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));

        bytes32 b0 = sha256(
            bytes.concat(
                new bytes(S_IN_BYTES),               // Z_pad
                message,
                bytes2(uint16(lenInBytes)),          // l_i_b_str, big-endian
                bytes1(0x00),
                dstPrime
            )
        );

        bytes32 bi = sha256(bytes.concat(b0, bytes1(0x01), dstPrime));
        bytes memory out = bytes.concat(bi);
        for (uint256 i = 2; i <= ell; ++i) {
            bi = sha256(bytes.concat(b0 ^ bi, bytes1(uint8(i)), dstPrime));
            out = bytes.concat(out, bi);
        }

        // Cắt về đúng lenInBytes: khối cuối thường thừa.
        assembly { mstore(out, lenInBytes) }
        return out;
    }

    /// @notice Rút gọn 64 byte về một phần tử Fp, trả về dạng 64 byte của EIP-2537.
    /// @dev Rút gọn `mod p` bằng **precompile MODEXP** với số mũ 1. Viết phép chia 512-bit
    ///      mod 381-bit bằng tay trong Solidity là vài trăm dòng và một chỗ để sai; MODEXP
    ///      làm đúng việc đó và đã có sẵn từ Byzantium.
    ///      EIP-2537 đòi phần tử Fp mã hoá **64 byte: 16 byte 0 ở đầu, rồi 48 byte giá trị**.
    function _reduceToFp(bytes memory tv64) private view returns (bytes memory) {
        bytes memory input = bytes.concat(
            bytes32(uint256(64)),   // độ dài base
            bytes32(uint256(1)),    // độ dài exponent
            bytes32(uint256(48)),   // độ dài modulus
            tv64,
            bytes1(0x01),           // exponent = 1  ⇒  base^1 mod p  =  base mod p
            P
        );
        (bool ok, bytes memory out) = MODEXP.staticcall(input);
        if (!ok || out.length != 48) revert ModexpFailed();
        return bytes.concat(new bytes(FP_PAD), out);
    }

    /// @notice RFC 9380 §5.2 `hash_to_field(msg, 2)` cho Fp.
    function hashToField2(bytes memory message, bytes memory dst)
        internal view returns (bytes memory u0, bytes memory u1)
    {
        bytes memory ub = expandMessageXmd(message, dst, 2 * L);
        bytes memory t0 = new bytes(L);
        bytes memory t1 = new bytes(L);
        for (uint256 i; i < L; ++i) {
            t0[i] = ub[i];
            t1[i] = ub[L + i];
        }
        u0 = _reduceToFp(t0);
        u1 = _reduceToFp(t1);
    }

    /// @notice RFC 9380 hash-to-curve đầy đủ, ánh xạ một thông điệp vào G1.
    /// @dev Đây là `H(m)` trong `e(sig, -G2) · e(H(m), pk) == 1`. Nó **phải** ở trong
    ///      contract: nhận một điểm G1 do caller đưa là cho caller chọn `H(m)`, tức là
    ///      cho họ ký bất cứ thứ gì.
    function hashToG1(bytes memory message, bytes memory dst)
        internal view returns (bytes memory)
    {
        (bytes memory u0, bytes memory u1) = hashToField2(message, dst);
        bytes memory q0 = Bls12381.mapFpToG1(u0);
        bytes memory q1 = Bls12381.mapFpToG1(u1);
        return Bls12381.g1Add(q0, q1);   // cofactor đã clear trong từng map — xem đầu file
    }
}
