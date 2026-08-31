// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Bọc precompile EIP-2537 (BLS12-381).
/// @notice Địa chỉ và kích thước I/O dưới đây **đã đo trên chain 9000** (Nethermind
///         1.39.0, Fusaka, 2026-08-31), không chép từ draft:
///
///         | addr | tên              | input                | output |
///         |------|------------------|----------------------|--------|
///         | 0x0b | G1ADD            | 2 × 128 = 256        | 128    |
///         | 0x0c | G1MSM            | k × (128 + 32)       | 128    |
///         | 0x0d | G2ADD            | 2 × 256 = 512        | 256    |
///         | 0x0e | G2MSM            | k × (256 + 32)       | 256    |
///         | 0x0f | PAIRING_CHECK    | k × 384              | 32     |
///         | 0x10 | MAP_FP_TO_G1     | 64                   | 128    |
///         | 0x11 | MAP_FP2_TO_G2    | 128                  | 256    |
///
/// **Bản cuối của EIP đánh số lại so với draft**: G2ADD là `0x0d` chứ không phải `0x0e`,
/// và MAP_FP_TO_G1 là `0x10` chứ không phải `0x11`. Dùng số của draft thì gọi trúng một
/// precompile khác, và với input toàn 0 nó vẫn trả về byte — tức là **sai im lặng**.
///
/// **Mã hoá:** một phần tử Fp là 64 byte (48 byte giá trị, đệm 16 byte 0 ở ĐẦU). Một điểm
/// G1 là 128 byte (x‖y), G2 là 256 byte. Điểm vô cực là toàn 0. Đây là lý do §20.1 nói
/// interface phải nhận `bytes`: G1 của bn254 là 64 byte, của BLS12-381 là **128 byte**.
///
/// **Subgroup check:** cofactor của BLS12-381 G1 khác 1, nên subgroup check là **bắt buộc**
/// (§12.3.4). `G1MSM`/`G2MSM`/`PAIRING_CHECK` tự kiểm subgroup cho input của chúng;
/// `G1ADD`/`G2ADD` **chỉ** kiểm on-curve. Nghĩa là tổng hợp khoá bằng một chuỗi `G2ADD` rẻ
/// tiền là **không** được bảo vệ — phải ép qua `G2MSM` k=1 một lần lúc đăng ký (§02.5.3).
library Bls12381 {
    address internal constant G1ADD         = address(0x0b);
    address internal constant G1MSM         = address(0x0c);
    address internal constant G2ADD         = address(0x0d);
    address internal constant G2MSM         = address(0x0e);
    address internal constant PAIRING_CHECK = address(0x0f);
    address internal constant MAP_FP_TO_G1  = address(0x10);
    address internal constant MAP_FP2_TO_G2 = address(0x11);

    uint256 internal constant FP_BYTES = 64;
    uint256 internal constant G1_BYTES = 128;
    uint256 internal constant G2_BYTES = 256;
    uint256 internal constant PAIR_BYTES = G1_BYTES + G2_BYTES; // 384

    error PrecompileFailed(address at);
    error BadLength(uint256 got, uint256 want);
    error NotSupportedOnThisChain();

    /// @notice EIP-2537 có mặt trên chain này không.
    /// @dev Cách duy nhất đáng tin: **gọi thử**. Một precompile chưa bật là một account
    ///      rỗng — `staticcall` THÀNH CÔNG và trả 0 byte. Một precompile đã bật với input
    ///      hợp lệ trả đúng số byte. Nên điều kiện là `returndatasize`, KHÔNG phải `success`.
    ///      Input toàn 0 = hai điểm vô cực, hợp lệ, nên đây là một probe rẻ và an toàn.
    function isSupported() internal view returns (bool) {
        (bool ok, bytes memory out) = G1ADD.staticcall(new bytes(2 * G1_BYTES));
        return ok && out.length == G1_BYTES;
    }

    function pairingCheck(bytes memory pairs) internal view returns (bool) {
        if (pairs.length == 0 || pairs.length % PAIR_BYTES != 0) {
            revert BadLength(pairs.length, PAIR_BYTES);
        }
        (bool ok, bytes memory out) = PAIRING_CHECK.staticcall(pairs);
        if (!ok || out.length != 32) revert PrecompileFailed(PAIRING_CHECK);
        return abi.decode(out, (uint256)) == 1;
    }

    function mapFpToG1(bytes memory fp) internal view returns (bytes memory) {
        if (fp.length != FP_BYTES) revert BadLength(fp.length, FP_BYTES);
        (bool ok, bytes memory out) = MAP_FP_TO_G1.staticcall(fp);
        if (!ok || out.length != G1_BYTES) revert PrecompileFailed(MAP_FP_TO_G1);
        return out;
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        if (a.length != G1_BYTES) revert BadLength(a.length, G1_BYTES);
        if (b.length != G1_BYTES) revert BadLength(b.length, G1_BYTES);
        (bool ok, bytes memory out) = G1ADD.staticcall(bytes.concat(a, b));
        if (!ok || out.length != G1_BYTES) revert PrecompileFailed(G1ADD);
        return out;
    }

    /// @notice Ép subgroup check cho một điểm G2 bằng MSM k=1 với vô hướng 1.
    /// @dev `G2ADD` KHÔNG kiểm subgroup. Gọi hàm này **một lần lúc đăng ký** một khoá công
    ///      khai; sau đó cộng bằng `G2ADD` là an toàn, vì tổng các phần tử trong subgroup
    ///      vẫn nằm trong subgroup. Bỏ bước này mở small-subgroup attack (§12.3.4).
    function requireInG2Subgroup(bytes memory p) internal view returns (bytes memory) {
        if (p.length != G2_BYTES) revert BadLength(p.length, G2_BYTES);
        bytes memory one = new bytes(32);
        one[31] = 0x01;
        (bool ok, bytes memory out) = G2MSM.staticcall(bytes.concat(p, one));
        if (!ok || out.length != G2_BYTES) revert PrecompileFailed(G2MSM);
        return out;
    }

    /// @notice Verify một chữ ký BLS, biến thể **min-signature-size**: sig ∈ G1, pk ∈ G2.
    /// @param negG2Generator Điểm sinh của G2 đã lấy đối, mã hoá 256 byte.
    /// @param hashedMsgG1    Thông điệp đã hash-to-curve vào G1, 128 byte.
    /// @param pubkeyG2       Khoá công khai (hoặc khoá TỔNG HỢP), 256 byte.
    /// @param sigG1          Chữ ký (hoặc chữ ký TỔNG HỢP), 128 byte.
    /// @dev Kiểm `e(sig, -G2) · e(H(m), pk) == 1`, tương đương `e(sig, G2) == e(H(m), pk)`.
    ///      §02.5.2 chốt biến thể min-sig: hash-to-G1 rẻ hơn hash-to-G2 khoảng 37k gas/verify.
    ///
    ///      `negG2Generator` là **tham số, không phải hằng số trong file này** — có chủ ý.
    ///      256 byte toạ độ viết tay là đúng loại dữ liệu mà một lỗi đánh máy làm mọi chữ ký
    ///      fail (hoặc tệ hơn: verify sai). Nó phải đến từ một nguồn có thẩm quyền và được
    ///      ghim bằng một known-answer test, không phải gõ từ trí nhớ.
    function verifyMinSig(
        bytes memory negG2Generator,
        bytes memory hashedMsgG1,
        bytes memory pubkeyG2,
        bytes memory sigG1
    ) internal view returns (bool) {
        if (sigG1.length != G1_BYTES) revert BadLength(sigG1.length, G1_BYTES);
        if (hashedMsgG1.length != G1_BYTES) revert BadLength(hashedMsgG1.length, G1_BYTES);
        if (pubkeyG2.length != G2_BYTES) revert BadLength(pubkeyG2.length, G2_BYTES);
        if (negG2Generator.length != G2_BYTES) revert BadLength(negG2Generator.length, G2_BYTES);
        return pairingCheck(bytes.concat(sigG1, negG2Generator, hashedMsgG1, pubkeyG2));
    }
}
