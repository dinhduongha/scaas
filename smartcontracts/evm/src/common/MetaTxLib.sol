// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
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
    /// @dev `mode` chia làm hai nửa byte, mỗi nửa một nhiệm vụ.
    ///
    ///      Nửa byte ĐẦU (bit 0–3) — ràng buộc `relayer` / `feeRecipient`. Đây là các
    ///      **cờ độc lập**, bật được cùng lúc. Bit tắt = trường đó không ràng buộc, và
    ///      verifier canonical-zero hoá nó trước khi băm (xem `canon`). Bit bật =
    ///      trường đó nằm trong digest, relayer sửa là chữ ký chết.
    ///
    ///      Nửa byte SAU (bit 4–7) — cách tính phí. Đây là một **giá trị liệt kê**,
    ///      không phải cờ: ba chế độ loại trừ nhau, nên đọc bằng mask + shift chứ
    ///      không bằng phép AND từng bit.
    ///
    ///          bit:  7 6 5 4 | 3 2 1 0
    ///                └──┬──┘   └──┬──┘
    ///                 fee mode   cờ ràng buộc
    uint32 internal constant MODE_OPEN                   = 0x0000_0000; // không bit nào

    // --- nửa byte đầu: cờ ràng buộc ---
    uint32 internal constant MODE_RESTRICT_RELAYER       = 0x0000_0001;
    uint32 internal constant MODE_RESTRICT_FEE_RECIPIENT = 0x0000_0002;
    uint32 internal constant MODE_FLAGS_MASK             = 0x0000_000F;

    // --- nửa byte sau: cách tính phí (giá trị, không phải cờ) ---
    uint32 internal constant MODE_FEE_MASK               = 0x0000_00F0;
    uint32 internal constant MODE_FEE_SHIFT              = 4;
    uint32 internal constant MODE_FEE_NONE               = 0x0000_0000; // FeeMode.NONE
    uint32 internal constant MODE_FEE_PERCENT            = 0x0000_0010; // FeeMode.PERCENT
    uint32 internal constant MODE_FEE_FIXED              = 0x0000_0020; // FeeMode.FIXED

    uint32 internal constant MODE_KNOWN_MASK             = 0x0000_00F3;

    error ModeFeeInvalid(uint32 mode);
    error ModeUnknownBits(uint32 mode);

    /// @notice v3 (CTR-MTX-15): the signed call of one of THIS contract's allowlisted functions.
    struct MetaTransaction {
        address from;           // signer; the authority the call runs under
        bytes   data;           // a call of THIS contract, allowlisted selector
        uint256 batch;          // nonce dimension 1: lane
        uint256 nonce;          // nonce dimension 2: sequence inside the lane
        uint256 validUntil;     // unix seconds
        uint32  mode;           // constraint flags + fee mode
        address relayer;        // bound relayer when MODE_RESTRICT_RELAYER
        uint256 fee;            // only where the contract charges it (tokens); elsewhere fee mode NONE
        address feeRecipient;   // bound fee recipient when MODE_RESTRICT_FEE_RECIPIENT
    }

    /// @dev Pinned by `test_metaTxTypehashIsPinned` (test/metatx/MetaTxLib.t.sol).
    bytes32 internal constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

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
    function canon(MetaTransaction memory m) internal pure returns (address r, address f) {
        r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
        f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
    }

    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        (address r, address f) = canon(m);
        return keccak256(abi.encode(
            METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f
        ));
    }

    /// @notice CTR-MTX-15/23 (tokens only): the typed transfer (`entryRef == 0`) or payment (`entryRef != 0`).
    struct MetaTransfer {
        address from;           // signer and payer
        address to;             // payee
        uint256 value;          // amount moved
        bytes32 entryRef;       // 0 = transfer; != 0 = payment reference (PaymentSettled)
        uint256 batch;          // lane, shared with MetaTransaction (one nonce space)
        uint256 nonce;
        uint256 validUntil;
        uint32  mode;
        address relayer;
        uint256 fee;
        address feeRecipient;
    }

    /// @dev Pinned by `test_metaTransferTypehashIsPinned` (test/metatx/MetaTxLib.t.sol).
    bytes32 internal constant METATRANSFER_TYPEHASH = keccak256(
        "MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    function canon(MetaTransfer memory t) internal pure returns (address r, address f) {
        r = (t.mode & MODE_RESTRICT_RELAYER)       != 0 ? t.relayer      : address(0);
        f = (t.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? t.feeRecipient : address(0);
    }

    function hashStruct(MetaTransfer memory t) internal pure returns (bytes32) {
        (address r, address f) = canon(t);
        return keccak256(abi.encode(
            METATRANSFER_TYPEHASH, t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, r, t.fee, f
        ));
    }

    /// @notice Đọc cách tính phí từ nửa byte sau của `mode`.
    /// @dev Trả về `FeeMode` để `FeePolicy` dùng nguyên như cũ — enum vẫn là kiểu
    ///      chuẩn tắc của tầng phí, chỉ không còn là một trường riêng trong struct.
    function feeModeOf(uint32 mode) internal pure returns (FeeMode) {
        uint32 v = (mode & MODE_FEE_MASK) >> MODE_FEE_SHIFT;
        if (v == 0) return FeeMode.NONE;
        if (v == 1) return FeeMode.PERCENT;
        if (v == 2) return FeeMode.FIXED;
        revert ModeFeeInvalid(mode);
    }

    /// @notice Từ chối mọi bit không hiểu. Gọi ở bước 3 của §04.6.1, TRƯỚC verify chữ ký.
    /// @dev Hai kiểm tra khác nhau, vì hai nửa byte có bản chất khác nhau:
    ///      nửa đầu là cờ nên chỉ cần bit lạ = 0; nửa sau là giá trị liệt kê nên
    ///      `0x30`–`0xF0` là bit hợp lệ nhưng giá trị vô nghĩa, và phải revert.
    ///      Chấp nhận bit/giá trị không hiểu nghĩa là khoá chết ngữ nghĩa tương lai.
    function validateMode(uint32 mode) internal pure {
        if (mode & ~MODE_KNOWN_MASK != 0) revert ModeUnknownBits(mode);
        feeModeOf(mode);  // revert ModeFeeInvalid nếu nửa byte sau > 2
    }
}
