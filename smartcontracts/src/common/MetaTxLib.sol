// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {FeeMode} from "./FeePolicy.sol";

/// @title Struct và typehash EIP-712 cho meta-transaction EIP-1776.
/// @notice Bản hợp nhất ba biến thể đang cùng tồn tại trong dự án. Những gì đã đổi
///         so với `metatx/MtxTradeOrderLib.sol` và vì sao:
///
///  - `address contract` -> BỎ HẲN. Nó là **từ khoá Solidity**, file cũ không
///    compile được (`Error 2314: Expected identifier but got 'contract'`). Và nó
///    không cần thay tên: `verifyingContract` thuộc về **EIP-712 domain**, không
///    thuộc struct. Để trong struct là ký hai lần cùng một dữ kiện.
///  - `uint256 chainId` -> BỎ HẲN, cùng lý do: nó là trường của domain.
///  - `bytes signature` -> TÁCH RA KHỎI STRUCT. Chữ ký không thể là một phần của
///    thứ được ký. Truyền như tham số riêng.
///  - `mode` bitmask -> BỎ. Thay bằng wildcard `relayer == address(0)`. Bitmask đòi
///    đổi nội dung digest theo mode (loại `relayer`/`feeRecipient` khỏi hash khi
///    OPEN), tạo ra cross-mode replay. Wildcard giữ digest cố định.
///  - nonce 2D `(batch, nonce)` -> GIỮ. Nó giải quyết head-of-line blocking thật:
///    một intent kẹt trên batch 0 không chặn batch 1.
///  - `fee` -> GIỮ TRONG STRUCT. Relayer phải đọc được phí từ intent trên mesh mà
///    không gọi thêm hàm nào. `feeMode` đi kèm để `fee` có nghĩa xác định.
library MetaTxLib {
    struct MetaTransaction {
        address from;           // người ký, người chịu hiệu lực
        address to;             // đích của inner call
        uint256 value;          // native value kèm inner call (thường 0)
        bytes   data;           // calldata của inner call
        uint256 batch;          // nonce chiều 1 — luồng độc lập
        uint256 nonce;          // nonce chiều 2 — thứ tự trong luồng
        uint256 validUntil;     // hạn, giây epoch
        address relayer;        // address(0) = ai cũng gửi được (wildcard)
        FeeMode feeMode;
        uint256 fee;            // ppm nếu PERCENT, tuyệt đối nếu FIXED, bỏ qua nếu NONE
        address feeRecipient;
    }

    /// @dev Thứ tự và kiểu ở đây phải khớp TỪNG KÝ TỰ với chuỗi type trong SDK
    ///      client. `FeeMode` là enum ⇒ ABI của nó là `uint8`, và trong chuỗi
    ///      EIP-712 phải viết là `uint8`, không phải `FeeMode`.
    bytes32 internal constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,address relayer,uint8 feeMode,uint256 fee,address feeRecipient)"
    );

    /// @notice structHash theo EIP-712. `bytes data` phải được keccak, không encode thẳng.
    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                METATX_TYPEHASH,
                m.from,
                m.to,
                m.value,
                keccak256(m.data),
                m.batch,
                m.nonce,
                m.validUntil,
                m.relayer,
                uint8(m.feeMode),
                m.fee,
                m.feeRecipient
            )
        );
    }
}
