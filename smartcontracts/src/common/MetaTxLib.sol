// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {FeeMode} from "./FeePolicy.sol";

/// @title Struct và typehash EIP-712 cho meta-transaction.
/// @notice Không có forwarder ở đây, và sẽ không bao giờ có. Mọi token trong hệ **tự**
///         hiện thực meta-transaction (native mixin), nên `verifyingContract` của EIP-712
///         domain **luôn là chính token contract**.
///
/// Quyết định của user: *"những contract mà không support gasless là sai triết lý. Nếu
/// đã lỡ phát hành thì wrap sang MetaTx."* Nghĩa là không tồn tại nhu cầu
/// "gasless-hoá một contract ta không kiểm soát" — thứ duy nhất một forwarder giải.
/// Token bên ngoài đã phát hành thì bọc thành `MetaToken` (archetype WRAP_1_1), và
/// wrapper là contract của ta nên nó có sẵn mixin này.
///
/// Những gì KHÔNG có trong struct, và vì sao:
///
///  - `feeToken`      -> BỎ. Phí trả bằng CHÍNH token này. Một token khác nằm ngoài
///                       contract này và contract này không cầm allowance của nó.
///  - `innerGasLimit` -> BỎ. Nó tồn tại để chặn relayer bóp gas làm inner call OOG
///                       trong khi frame ngoài sống sót (quy tắc 63/64). Không có
///                       forwarder thì không có kịch bản đó.
///  - `address contract` / `uint256 chainId` -> BỎ. Chúng là trường của EIP-712
///                       **domain**, không phải của struct. Để trong struct là ký hai
///                       lần cùng một dữ kiện. (Và `contract` là từ khoá Solidity,
///                       file cũ không compile được: `Error 2314`.)
///  - `bytes signature` -> TÁCH RA. Chữ ký không thể là một phần của thứ được ký.
library MetaTxLib {
    /// @dev `mode` điều khiển **đúng hai trường**: `relayer` và `feeRecipient`.
    ///      Bit tắt = trường đó không ràng buộc, và verifier canonical-zero hoá nó
    ///      trước khi băm (xem `canon`). Bit bật = trường đó nằm trong digest, relayer
    ///      sửa là chữ ký chết.
    uint32 internal constant MODE_OPEN                   = 0x0000_0000; // không bit nào
    uint32 internal constant MODE_RESTRICT_RELAYER       = 0x0000_0001;
    uint32 internal constant MODE_RESTRICT_FEE_RECIPIENT = 0x0000_0002;
    uint32 internal constant MODE_KNOWN_MASK             = 0x0000_0003;

    struct MetaTransaction {
        address from;           // người ký, người chịu hiệu lực
        address to;             // đích của thao tác trên chính token này
        uint256 value;          // số lượng token cho thao tác (0 nếu chỉ gọi logic)
        bytes   data;           // payload của thao tác
        uint256 batch;          // nonce chiều 1 — luồng độc lập
        uint256 nonce;          // nonce chiều 2 — thứ tự trong luồng
        uint256 validUntil;     // hạn, giây epoch
        uint32  mode;           // bitmask, xem hằng số ở trên
        address relayer;        // chỉ ràng buộc khi mode & MODE_RESTRICT_RELAYER
        FeeMode feeMode;
        uint256 fee;            // ppm nếu PERCENT, tuyệt đối nếu FIXED, bỏ qua nếu NONE
        address feeRecipient;   // chỉ ràng buộc khi mode & MODE_RESTRICT_FEE_RECIPIENT
    }

    /// @notice Chuẩn hoá hai trường do relayer điền, trước khi băm.
    /// @dev Đây là quy tắc PHẢI giống hệt nhau ở ba nơi: verifier Solidity, SDK client,
    ///      và builder phía Odoo. Lệch một chỗ thì mọi chữ ký fail — fail-closed nên
    ///      không mất tiền, nhưng là một nguy cơ tích hợp phải nhớ mãi.
    ///
    ///      Chọn "băm với address(0)" chứ KHÔNG phải "bỏ trường khỏi struct". Lý do
    ///      quyết định: `TYPEHASH` là hash của type string, và type string phải cố
    ///      định. Bỏ trường ra khi MODE_OPEN nghĩa là một type KHÁC, cần một
    ///      `TYPEHASH` thứ hai, và ví EIP-712 sẽ hiển thị hai loại giao dịch khác nhau
    ///      cho cùng một hành động. Ngoài ra encoding độ dài thay đổi phá injectivity.
    ///      Một type string, hai giá trị canonical.
    function canon(MetaTransaction memory m)
        internal pure returns (address r, address f)
    {
        r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
        f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
    }

    /// @dev Thứ tự và kiểu ở đây phải khớp TỪNG KÝ TỰ với chuỗi type trong SDK client.
    ///      `FeeMode` là enum ⇒ ABI của nó là `uint8`, và trong chuỗi EIP-712 phải viết
    ///      là `uint8`, không phải `FeeMode`.
    bytes32 internal constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint8 feeMode,uint256 fee,address feeRecipient)"
    );

    /// @notice structHash theo EIP-712.
    /// @dev `bytes data` PHẢI được keccak, không encode thẳng. Bỏ là vỡ injectivity:
    ///      `("ab","c")` và `("a","bc")` cho cùng một digest. Fuzz không tìm ra (xác
    ///      suất 0); solver tìm ra trong vài giây.
    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        (address r, address f) = canon(m);
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
                m.mode,
                r,
                uint8(m.feeMode),
                m.fee,
                f
            )
        );
    }
}
