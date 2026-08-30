// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {FeeMode} from "./FeePolicy.sol";

/// @title Struct và typehash EIP-712 cho meta-transaction trên token.
/// @notice **BẢN 3 — không còn là một forwarder.** Xem `_USER-DECISIONS.md` §24.
///
/// Bản trước mang `to` / `value` / `data` và thực hiện một `call` tới địa chỉ tuỳ ý.
/// Đó là hình dạng của một **generic forwarder** đặt nhầm chỗ: nó nằm trong token,
/// nhưng lại nhận việc gọi bất cứ contract nào. Hệ quả là nó kéo theo toàn bộ bề mặt
/// tấn công của forwarder (allowance drain, return-bomb, 63/64 griefing, allowlist
/// target) trong khi mọi token trong hệ chỉ phơi ra **thao tác có kiểu**:
/// `payWithFee`, `transferConfidential`, `fund`, `burn`, `rollOverPublic`.
/// Không token nào cần gọi contract lạ.
///
/// Nên struct mang một **mã thao tác** cộng tham số đã ABI-encode, và bộ điều phối
/// gọi một **internal function**, không phải opcode `CALL`. Những gì chết theo:
///
///  - `to`, `value`, `data`  -> `op` + `args`. Người nhận nằm trong `args`.
///  - `innerGasLimit`        -> không có inner call thì không có gas để giới hạn.
///  - guard 63/64 (EIP-150)  -> cùng lý do.
///  - `MAX_RETURN_BYTES`     -> không có returndata từ contract lạ để mà bomb.
///  - `feeToken`             -> phí trả bằng CHÍNH token này. Một token khác nằm
///                              ngoài contract này, và contract này không cầm
///                              allowance của nó.
///  - `MODE_REQUIRE_SUCCESS` -> xem ghi chú "phí và thất bại" dưới đây.
///
/// Giữ lại từ bản trước, vì chúng không đến từ mô hình forwarder:
///  - nonce 2D `(batch, nonce)`: một intent kẹt ở batch 0 không chặn batch 1.
///  - wildcard `relayer == address(0)`: giữ digest cố định, không cross-mode replay.
///  - `fee` + `feeMode` trong struct: relayer đọc được phí từ intent trên mesh mà
///    không phải gọi thêm hàm nào.
///
/// **Phí và thất bại.** Forwarder không bao giờ biết trước inner call sẽ fail hay
/// không, nên nó phải chọn: thu phí trước (user mất tiền cho việc không xảy ra) hoặc
/// bubble revert (relayer mất gas). Với thao tác có kiểu, contract **biết chính xác**
/// cái gì có thể fail, nên nó kiểm hết trước rồi mới thu phí — và sau điểm đó thao
/// tác không thể fail. Bất biến trở thành **"phí đã thu ⟺ thao tác đã xảy ra"**, đạt
/// được mà không cần try/catch và không cần một mode nào.
library MetaTxLib {
    /// @dev Mã thao tác. Append-only: không bao giờ đổi số của một mã đã phát hành,
    ///      vì nó nằm trong digest đã ký. `verifyingContract` của EIP-712 domain
    ///      quyết định token nào, nên hai token khác nhau dùng lại cùng số là an toàn.
    ///      Đây cũng là "selector" mà bộ lọc của node tra ở §22.4 — một `uint8` đọc
    ///      được ngay, không phải 4 byte đầu của một blob phải decode.
    uint8 internal constant OP_TRANSFER      = 1;  // args: (address to, uint256 amount)
    uint8 internal constant OP_APPROVE       = 2;  // args: (address spender, uint256 amount)
    uint8 internal constant OP_PAY_WITH_REF  = 3;  // args: (address to, uint256 amount, bytes32 entryRef)
    uint8 internal constant OP_FUND          = 10; // args: (bytes encodedY, uint256 amount)
    uint8 internal constant OP_TRANSFER_CONF = 11; // args: (bytes payload, bytes proof)
    uint8 internal constant OP_BURN          = 12; // args: (bytes payload, uint256 amount, bytes proof)
    uint8 internal constant OP_ROLLOVER      = 13; // args: (bytes32 account, uint64 expectedPendingSeq, uint64 validUntilBlock)

    struct MetaTransaction {
        address from;           // người ký, người chịu hiệu lực
        uint8   op;             // thao tác của CHÍNH token này. Không phải địa chỉ để gọi.
        bytes   args;           // tham số đã ABI-encode cho `op`
        uint256 batch;          // nonce chiều 1 — luồng độc lập
        uint256 nonce;          // nonce chiều 2 — thứ tự trong luồng
        uint256 validUntil;     // hạn, giây epoch
        address relayer;        // address(0) = ai cũng gửi được (wildcard)
        FeeMode feeMode;
        uint256 fee;            // ppm nếu PERCENT, tuyệt đối nếu FIXED, bỏ qua nếu NONE
        address feeRecipient;   // trả bằng CHÍNH token này
    }

    /// @dev Thứ tự và kiểu ở đây phải khớp TỪNG KÝ TỰ với chuỗi type trong SDK
    ///      client. `FeeMode` là enum ⇒ ABI của nó là `uint8`, và trong chuỗi
    ///      EIP-712 phải viết là `uint8`, không phải `FeeMode`.
    bytes32 internal constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,uint8 op,bytes args,uint256 batch,uint256 nonce,uint256 validUntil,address relayer,uint8 feeMode,uint256 fee,address feeRecipient)"
    );

    /// @notice structHash theo EIP-712. `bytes args` phải được keccak, không encode thẳng.
    /// @dev Bỏ keccak ở đây là lỗ hổng injectivity: `("ab","c")` và `("a","bc")` cho
    ///      cùng một digest. Fuzz không tìm ra (xác suất 0); solver tìm ra trong vài giây.
    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                METATX_TYPEHASH,
                m.from,
                m.op,
                keccak256(m.args),
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
