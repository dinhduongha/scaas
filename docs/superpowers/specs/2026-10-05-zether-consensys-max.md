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

## 4. Nâng cận giải mã lên 2^60, 2^64 — và với GPU

Giải mã = tìm `b` từ `g^b` khi biết `b < bound`. Hai thuật toán:
- **BSGS**: O(√bound) phép cộng điểm, cần bảng; đánh đổi bộ nhớ ↔ thời gian (`2026-10-05-zether-limits.md` §4).
- **Pollard kangaroo**: ≈ 2·√bound phép cộng điểm, **bộ nhớ gần như không đổi** (chỉ lưu "distinguished
  points"), song song hoá tốt trên nhiều lõi và trên **GPU**.

Ước tính (số phép cộng điểm bn254; CPU ≈ 0,35 µs/phép/lõi; GPU cao cấp ≈ 2–5 × 10^9 phép/s — ước theo các
bộ kangaroo GPU công khai trên secp256k1, cùng cỡ trường 256 bit; **phải đo trên phần cứng thật**):

| Cận | √cận | Desktop 1 lõi | CPU 16 lõi | 1 GPU cao cấp |
|---|---|---|---|---|
| 2^54 | 1,3e8 | ~1–6 phút (BSGS bảng 2^24–2^27) | ~5–20 s | < 0,1 s |
| 2^60 | 1,1e9 | ~12 phút | ~45 s | ~0,5–1 s |
| 2^64 | 4,3e9 | ~50 phút | ~3 phút | ~2–4 s |
| 2^72 | 6,9e10 | ~13 giờ | ~50 phút | ~30–70 s |
| 2^80 | 1,1e12 | ~9 ngày | ~14 giờ | ~7–18 phút |

**Kết luận về khả năng tính:** với CPU nhiều lõi, 2^60 khả thi; với GPU, **2^64 dễ dàng, 2^72 vẫn dùng được**.
Riêng về giải mã thì không còn là rào cản.

**Nhưng cận giải mã không phải ràng buộc duy nhất của tổng cung — muốn tổng > 2^54 phải xử lý cả ba:**
1. **Soundness (`n_b`)**: canon giữ `2^n_b > tổng × 1024` (khoảng an toàn 10 bit) với `n_b = 64` ⇒ tổng ≤ 2^54.
   Lên 2^60/2^64 cần: (a) `n_b = 128` — range proof số dư 7 vòng, gas transfer tăng ~65–70% (ước tính); hoặc
   (b) nới hệ số 1024 bằng một ruling có lập luận từng phương trình (như RS-NV64-1) — chưa phân tích, không
   mặc định an toàn.
2. **Mobile**: điện thoại không có GPU dùng được cho việc này; ví mobile vẫn dùng cache + BSGS nhỏ, và chỉ
   cần dò lớn khi mất cache.
3. **Thuê/ dùng chung GPU làm lộ số dư**: phép dò chỉ cần `g^b` (tính tại máy từ khoá bí mật), nên có thể giao
   việc dò cho một máy GPU khác **mà không lộ khoá** — nhưng máy đó **biết được số dư `b`**. Chỉ giao cho máy
   thuộc quyền chủ tài khoản (GPU nội bộ của doanh nghiệp), không giao cho dịch vụ bên ngoài.

**Khuyến nghị:** giữ tổng 2^54 cho v1. Nếu một token cần tổng lớn hơn (ví dụ VND quy mô quốc gia), mở một
thay đổi riêng: tổng 2^60–2^64 + `n_b = 128` (hoặc ruling nới hệ số) + công cụ kangaroo GPU nội bộ; đo gas và
thời gian trên phần cứng thật trước khi chốt. Phương án thay thế không đổi crypto: nhiều **series**.

## 5. Có tăng thêm nữa không?

Đã tăng: tổng 2^32 → **2^54** (×4,2 triệu), một lần chuyển 2^32 → **giới hạn bởi số dư**, giải mã tuyến tính
→ BSGS. **Không đề xuất tăng tổng vượt 2^54**, vì hai ràng buộc cùng lúc:
- soundness: canon giữ `2^n_b > tổng × 1024` (khoảng an toàn 10 bit) với `n_b = 64` ⇒ tổng ≤ 2^54; lên
  `n_b = 128` thì gas range proof số dư tăng mạnh (~+65–70% một transfer);
- giải mã: dò tới 2^60 cần ~2^33 bước với bảng 2^27 (~50 phút desktop) — không còn dùng được để khôi phục.
Cần lớn hơn ⇒ chia token thành nhiều **series** (mỗi series một sổ cái riêng, `01-token-factory.md` §1.8.3).
