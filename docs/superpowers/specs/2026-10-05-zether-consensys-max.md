# `MAX = 2^32 − 1` trong Zether của ConsenSys thực ra là gì

> Ghi lại theo yêu cầu owner (2026-10-05). Nguồn đã đọc: `anonymous-zether/packages/protocol/contracts/ZSC.sol`
> (ba fork trên máy: cnxtech, libby, iquerejeta — giống nhau ở phần này), `ZetherVerifier.sol`,
> `BurnVerifier.sol`, `packages/anonymous.js/src/utils/{utils,bn128}.js`. Liên quan:
> `2026-10-05-zether-limits.md` (giới hạn của bản Bamboo), `blockchain-research/01-token-factory.md` §1.8.3,
> `blockchain-research/03-zether-crypto.md`.

## 1. Code gốc

```solidity
// ZSC.sol
uint256 constant MAX = 4294967295; // 2^32 - 1 // no sload for constants...!
...
// fund (nạp vào phần bí mật)
require(bTransfer <= MAX, "Deposit amount out of range.");
require(bTransfer + bTotal <= MAX, "Fund pushes contract past maximum value.");
...
// burn (rút ra)
require(0 <= bTransfer && bTransfer <= MAX, "Transfer amount out of range.");
```

```javascript
// anonymous.js utils.readBalance — client đọc số dư
var gB = CL.add(CR.mul(x.neg()));          // g^b
var accumulator = bn128.zero;
for (var i = 0; i < bn128.B_MAX; i++) {     // B_MAX = 4294967295
    if (accumulator.eq(gB)) return i;       // dò tuyến tính b = 0, 1, 2, …
    accumulator = accumulator.add(bn128.curve.g);
}
```

Range proof gốc: `ZetherVerifier` `m = 64` (= 2 giá trị × 32 bit: số tiền chuyển và số dư còn lại),
`n = 6` vòng; `BurnVerifier` `m = 32`, `n = 5` vòng — tức mọi giá trị được chứng minh nằm trong `[0, 2^32)`.

## 2. Nó thực sự là gì: **cận giải mã** (decryption bound)

Kết luận của nghiên cứu trước (`blockchain-research/03-zether-crypto.md` §3.2.1), giữ nguyên:
*"`MAX` trong Zether **không phải** tham số của range proof. Nó là **cận giải mã**."*

1. **Cận giải mã.** Số dư lưu dạng ElGamal `(C, D) = (g^b·y^r, g^r)`; chủ tài khoản chỉ tính được
   `g^b = C·D^{-x}`, rồi phải giải **logarit rời rạc** để lấy `b`. Bài toán này chỉ giải được khi biết trước
   `b` nằm trong một khoảng nhỏ — `MAX` chính là khoảng đó. Bản gốc giải bằng **vòng lặp vét cạn tuyến tính**
   `b = 0 … B_MAX` (`utils.readBalance`, `B_MAX = 2^32 − 1`); BSGS/kangaroo làm nhanh hơn (O(√MAX)) nhưng vẫn
   bị chặn bởi MAX.
2. **Contract bảo đảm cận đó bằng cách chặn TỔNG.** `fund` kiểm `bTransfer + bTotal <= MAX`, với `bTotal`
   là tổng mọi số dư bí mật; vì mọi số dư ≤ tổng ≤ MAX nên ví nào cũng đọc được số dư của mình. Đây là cơ
   chế thực thi, không phải bản chất của hằng số.
3. **Không phải "số coin tối đa mỗi lần chuyển".** Nó chỉ *trùng giá trị* với độ rộng range proof 32 bit
   của bản gốc, và `burn`/`transfer` cũng kiểm `≤ MAX` với thông báo "amount out of range" — đó là nguồn
   của cách hiểu nhầm. Mỗi lần chuyển bị chặn bởi range proof và bởi số dư; MAX là cận để số dư còn
   **đọc được**.
4. Hệ quả kèm theo (nghiên cứu §01 / §08): với token 18 decimals, 2^32 − 1 đơn vị chỉ là 4,29e-9 token —
   và vì là `constant` nên không đặt riêng được cho từng token.

Hệ quả nếu chỉ "tăng MAX" (ví dụ `MAX = 2^128 − 1` như một bản ghi chú cũ đề xuất): contract chấp nhận,
nhưng vòng lặp giải mã cần tới 2^128 bước — số dư không đọc được, và ví không chi được (prover cần số dư
dạng rõ). Đây là lỗi `blockchain-research/_MANIFESTS.md` đã bác.

## 3. Bản Bamboo tách MAX thành ba đại lượng độc lập

| Vai trò của MAX gốc | ConsenSys | Bamboo (sau quyết định 2026-10-05) |
|---|---|---|
| Soundness: giá trị chứng minh được của **một lần chuyển** | range proof 32 bit | `n_v = 64` (6 vòng) — mỗi lần chuyển chỉ còn bị chặn bởi số dư |
| Soundness: **số dư còn lại** sau chi | range proof 32 bit | `n_b = 64` (6 vòng) |
| Trần tổng tiền của token (cách contract thực thi cận giải mã) | 2^32 (≈ 4,29 tỷ đơn vị) | `MAX_TOTAL_SHIELDED = 2^54` (≈ 18 triệu tỷ ₫ với 1 đơn vị = 1 ₫); mỗi token đặt `maxDecryptableShielded ≤ 2^54` |
| **Cận giải mã** (cái `MAX` thật) — chủ tài khoản giải log rời rạc số dư | vét cạn tuyến tính tới 2^32 (O(2^32)), thực thi bằng trần tổng 2^32 | BSGS O(√bound), client tự cấu hình bảng 2^18–2^27, trần dò ≤ 2^54; + cache số dư trên thiết bị (`2026-10-05-zether-limits.md` §4–§5) |

## 4. Có tăng thêm nữa không?

Đã tăng: tổng 2^32 → **2^54** (×4,2 triệu), một lần chuyển 2^32 → **giới hạn bởi số dư**, giải mã tuyến tính
→ BSGS. **Không đề xuất tăng tổng vượt 2^54**, vì hai ràng buộc cùng lúc:
- soundness: canon giữ `2^n_b > tổng × 1024` (khoảng an toàn 10 bit) với `n_b = 64` ⇒ tổng ≤ 2^54; lên
  `n_b = 128` thì gas range proof số dư tăng mạnh (~+65–70% một transfer);
- giải mã: dò tới 2^60 cần ~2^33 bước với bảng 2^27 (~50 phút desktop) — không còn dùng được để khôi phục.
Cần lớn hơn ⇒ chia token thành nhiều **series** (mỗi series một sổ cái riêng, `01-token-factory.md` §1.8.3).
