// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Bọc precompile EIP-2537 (BLS12-381).
/// @notice Địa chỉ và kích thước I/O dưới đây **đã đo trên chain 7622 (formerly 9000)** (Nethermind
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

    /// @notice Điểm sinh của G2 đã lấy đối, mã hoá 256 byte theo EIP-2537.
    /// @dev **Xuất xứ, vì đây đúng là loại hằng số không được gõ từ trí nhớ:** sinh bằng
    ///      `py_ecc.optimized_bls12_381.neg(G2)`, rồi **xác nhận độc lập bằng chính chain**
    ///      — một chữ ký BLS thật verify qua `PAIRING_CHECK` với hằng số này trả về 1, và
    ///      trả 0 khi đổi thông điệp. Hằng số sai thì phép kiểm dương tính đã không qua.
    ///      Toạ độ Fp2 xếp `c0` TRƯỚC `c1`, mỗi Fp là 64 byte (16 byte 0 ở đầu).
    bytes internal constant NEG_G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
        hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
        hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bc"
        hex"b679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
        hex"0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d"
        hex"993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

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
        if (_isZero(sigG1) || _isZero(pubkeyG2)) return false; // C1-3: the identity pairs to 1 = 1
        return pairingCheck(bytes.concat(sigG1, negG2Generator, hashedMsgG1, pubkeyG2));
    }

    /// @notice Như `verifyMinSig` nhưng dùng sẵn `NEG_G2_GENERATOR`.
    function verifyMinSig(bytes memory hashedMsgG1, bytes memory pubkeyG2, bytes memory sigG1)
        internal view returns (bool)
    {
        return verifyMinSig(NEG_G2_GENERATOR, hashedMsgG1, pubkeyG2, sigG1);
    }

    function _isZero(bytes memory b) private pure returns (bool z) {
        z = true;
        for (uint256 i; i < b.length; ++i) if (b[i] != 0) return false;
    }
}
