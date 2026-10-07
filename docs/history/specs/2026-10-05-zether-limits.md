# Zether — giới hạn số tiền, số dư, tổng cung (quyết định owner 2026-10-05)

> Tài liệu này chốt các giới hạn sau khi owner xem xét `n_v`, trần giải mã và tổng cung. Nó bổ sung và
> **thay thế** phần tương ứng trong `2026-10-03-zether-design.md` §1 (bảng tham số), §8 (Bulletproofs),
> §12 (tiết lộ) và ruling RS2-13 về giải mã. Đơn vị: **đơn vị che giấu** = raw unit của underlying chia
> `shieldScale`. Ví dụ dùng: Z-VND `shieldScale = 1` (1 đơn vị = 1 ₫), Z-USDT `shieldScale = 10^4`
> (1 đơn vị = $0,01). Quy đổi USD theo ≈ 25.500 ₫/USD, chỉ để tham khảo.

## 1. Quyết định

| # | Quyết định | Trước | Sau |
|---|---|---|---|
| D1 | Range proof số tiền chuyển `n_v` | 32 (5 vòng inner-product) | **64** (6 vòng) |
| D2 | Range proof số dư sau chi `n_b` | 64 | **64** — nới quy tắc SRS §7.3 `n_b − n_v ≥ 24` (xem §3) |
| D3 | Trần tổng cứng `MAX_TOTAL_SHIELDED` | 2^54 | **2^54** (không đổi) |
| D4 | Giải mã số dư (BSGS) | hằng `DECRYPT_BOUND = 2^40` | **client tự cấu hình**: `bound_bits ≤ 54`, `table_bits` 18–27 |
| D5 | Đọc số dư lớn | — | **cache số dư trên thiết bị** (không on-chain, không sao lưu lên server) + BSGS trên `pending` + công cụ đọc khi mất cache |
| D6 | Bundle tiết lộ | lưu đủ mỗi transfer: bn254 256 B (≈ 9 slot, ≈ +200k gas), BLS12-381 512 B (≈ 17 slot, ≈ +375k, ước tính) (RS2-15) | **giữ nguyên** (đúng SRS §9.4) |

## 2. Bảng giới hạn

### 2.1 On-chain (contract)

| Giới hạn | Nơi quyết định | Trước | Sau | Z-VND | Z-USDT |
|---|---|---|---|---|---|
| Tổng cung che giấu tối đa của một token (trần cứng) | `MAX_TOTAL_SHIELDED` | 2^54 | 2^54 | ≈ 18.014.398 tỷ ₫ (≈ 18 triệu tỷ ₫, ≈ $706 tỷ) | ≈ $180 nghìn tỷ |
| Tổng cung thực tế của token | `maxDecryptableShielded`, người tạo đặt lúc `initialize`, ≤ 2^54 | tuỳ token | tuỳ token | — | — |
| Số dư tối đa một ví (on-chain) | ≤ tổng cung của token | ≤ 2^54 | ≤ 2^54 | ≈ 18 triệu tỷ ₫ | ≈ $180 nghìn tỷ |
| **Số tiền tối đa của MỘT giao dịch chuyển** (`v < 2^n_v`) | `n_v` | 2^32 − 1 = 4.294.967.295 đơn vị ⇒ khoản lớn hơn phải tách nhiều giao dịch; số giao dịch công khai nên lộ "khoản > trần" | 2^64 − 1 ⇒ thực tế chỉ bị chặn bởi số dư người gửi | 4,29 tỷ ₫/giao dịch → **cả số dư trong một giao dịch** | $42,9 triệu/giao dịch → cả số dư |
| Rút ra (`burn`) | `0 < amount ≤ maxDecryptableShielded` | ≤ tổng cung | ≤ tổng cung | — | — |
| Phí confidential | `confidentialFee < 2^n_v` **và** `< maxDecryptableShielded` (`ZetherToken.sol:138-140`, không thì `BadInit`) | < 2^32 | < 2^64 và < `maxDecryptableShielded` | — | — |
| Số tiền chứng minh được khi tiết lộ | `amount < 2^n_v` | < 2^32 | < 2^64 | — | — |
| Gas một transfer `transferConfidential` thẳng (thực thi, auditor + phí trong) | đo (design §15) | bn254 2.748.019; BLS12-381 3.400.986 | **bn254 3.286.339; BLS12-381 3.919.760** (đo 2026-10-05, +538k / +519k) | | |
| Gas `verifyTransfer` (auditor tắt) | đo | bn254 2.162.249; BLS 2.411.138 | **bn254 2.700.151; BLS 2.928.567** | | |
| Gas `burn` | đo | bn254 1.396.398; BLS 1.521.199 | không đổi (bn254 1.396.358; BLS 1.521.169) | | |
| Trần gas mỗi tx của node (vận hành) | `max_gas_per_tx`, mặc định 3.000.000 (`scaas-node/src/config.rs:415-416`) | — | **thấp hơn** transfer thẳng (3.286.339) và phong bì (3.357.045) ⇒ node từ chối relay Zether với mặc định; chain có Zether đặt ≥ 4,2M (design §15) | | |

Ví dụ: trả 10 tỷ ₫ — trước: 3 giao dịch (4,29 + 4,29 + 1,42 tỷ), người ngoài thấy 3 giao dịch nên biết khoản
> 4,29 tỷ; sau: 1 giao dịch, không lộ gì.

### 2.2 Phía ví (client)

| Giới hạn | Trước | Sau (mặc định) | Z-VND | Z-USDT |
|---|---|---|---|---|
| Số dư ví tự đọc được khi KHÔNG có cache | 2^40 | mobile 2^44; desktop tới 2^54 | 1,1 nghìn tỷ → 17,6 nghìn tỷ ₫ (mobile) / ≈ 18 triệu tỷ ₫ (desktop) | $11 tỷ → $176 tỷ / $180 nghìn tỷ |
| Số dư ví đọc và chi được khi CÓ cache | = trần BSGS | tới 2^54 | ≈ 18 triệu tỷ ₫ | ≈ $180 nghìn tỷ |
| Tiền đến tối đa giữa hai lần `rollOver` mà ví mobile tự giải mã (`pending`) | 2^40 | 2^44 | 17,6 nghìn tỷ ₫ mỗi đợt | $176 tỷ mỗi đợt |

Vượt mức `pending` của mobile: tiền không mất; rollOver thường xuyên hơn, hoặc đọc bằng desktop/CLI.

## 3. Vì sao nới `n_b − n_v ≥ 24`

Quy tắc SRS §7.3 giữ một khoảng 24 bit giữa giá trị chuyển và số dư để không tổ hợp hợp lệ nào của các
giá trị đã chứng minh có thể vượt `r` (bậc nhóm) khi cộng/trừ trên ciphertext. Với `n_v = n_b = 64`:
mọi số dư thật ≤ tổng cung ≤ `maxDecryptableShielded` ≤ 2^54 (contract kiểm khi `fund`), mọi `v`
được chứng minh < 2^64 nhưng `b' = b − fee − v ≥ 0` được chứng minh < 2^64 cùng lúc, nên `v ≤ b ≤ 2^54`;
tổng các đại lượng đã chứng minh trong một phương trình (`b' + v + fee`, ba số hạng) < 3·2^64 < 2^66 ≪ r (≈ 2^254 với bn254, ≈ 2^255 với BLS12-381).
Chống quấn mod `r` đến từ chính `3·2^64 ≪ r` (đúng với mọi số dư `< r`); trần tổng 2^54 cho phần còn lại: tính đầy đủ
(mọi `b'` thật `< 2^64` nên luôn chứng minh được), chống grief (không ai đẩy số dư người khác vượt `2^n_b` — lý do gốc
của khoảng 24 bit) và trần BSGS. Không cái nào cần hiệu `n_b − n_v`. Đã kiểm với từng phương trình E1–E8 (design §7.1), burn, fund,
rollOver và tiết lộ: lập luận đứng vững — ruling **RS-NV64-1** (design §16).

## 4. Giải mã số dư — BSGS cấu hình được

- Số dư lưu dạng ElGamal `(C, D) = ([b]G + [r]Y, [r]G)`; chủ tài khoản tính `[b]G = C − [x]D` rồi tìm `b`
  (logarit rời rạc) bằng baby-step giant-step.
- **Bảng baby-step là dữ liệu công khai** (bội `[j]G`, không có bí mật, như nhau cho mọi tài khoản):
  sinh trên client hoặc tải bản tính sẵn rồi kiểm; lưu lại và sinh lại lúc nào cũng được.
- Client chọn `table_bits` theo RAM; số bước dò = 2^(bound_bits − table_bits). Entry 16 byte;
  desktop ≈ 0,35 µs/bước, Android ≈ 4× chậm hơn — **ước tính**, chưa có bench trong `zether-prover`; mọi thời
  gian dưới đây là ước tính từ hằng số này:

| `table_bits` | Bộ nhớ | Sinh bảng (một lần) | Dò xấu nhất tới 2^54 (desktop) |
|---|---|---|---|
| 22 | ~64 MiB | ~1,5 s | ~25 phút |
| 24 | ~256 MiB | ~6 s | ~6 phút |
| 25 | ~512 MiB | ~12 s | ~3 phút |
| 26 | ~1 GiB | ~24 s | ~1,5 phút |
| 27 | ~2 GiB | ~47 s | ~47 s |

- Mặc định: mobile/wasm `table_bits 22, bound_bits 44`; desktop chọn 24–26 theo RAM với `bound_bits 54`;
  wasm từ chối bảng 2^27 (đúng 2 GiB — `Vec` 32-bit không chứa nổi) và mặc định dừng ở 2^24 (256 MiB) trừ khi
  gọi với `allowLargeTable`; API native từ chối bảng không đủ RAM; CLI native `zether-read-balance` cho chọn tới 27.

## 5. Cache số dư (trên thiết bị)

- Lưu `{ua, token, accSeq, balance}` trong vault mã hoá của ví (cùng lớp bảo vệ với seed). Không on-chain,
  không gửi lên server.
- Kiểm cache: `[b]G == C − [x]D` trên `acc` hiện tại — một phép nhân điểm, vài ms. Cache sai/cũ bị phát
  hiện ngay, không thể dẫn tới chi sai (prover và contract cùng từ chối proof dựng trên số dư sai).
- Cập nhật: rollOver ⇒ `b += pending` (BSGS chỉ trên `pending`); tự chi ⇒ `b −= v + fee`.
- `acc` đổi mà ví không biết (ai cũng gọi được `rollOverPublic`/`rollOverBatch` — `fund(nạn nhân, 1)` +
  `rollOverPublic` là grief gần như miễn phí; credit đến muộn bị `rollOverSigned` gộp; tự chi chưa ghi): giá trị cuối
  cùng đã kiểm được giữ làm mốc, ví giải BSGS **phần chênh** `(C − [x]D) − [b_cache]G` (thử tăng rồi giảm) trong trần
  thiết bị, kiểm lại rồi cập nhật — không cần CLI dù số dư > 2^44 (review M1).
- Mất cache: số dư ≤ trần BSGS của thiết bị thì tự đọc lại; lớn hơn thì dùng desktop/CLI.

## 6. Claude review disposition — review 1 (2026-10-07, `docs/reviews/specs/2026-10-05-zether-limits-claude-review-1.md`)

Verdict của review: GO; mọi số liệu đã kiểm khớp code. **4 nhận, 0 từ chối**, đều là văn bản (không có lỗi code).

| # | Sev | Kiểm với code | Kết luận | Xử lý |
|---|---|---|---|---|
| L1 | low | `ZetherToken.sol:138-140`: `fee >= VALUE_BOUND` **và** `fee >= maxShielded` ⇒ `BadInit` | Đúng | §2.1 dòng phí ghi cả hai biên |
| L2 | low | BLS12-381: 4 điểm × 128 B = 512 B | Đúng | §1 D6 ghi hai curve |
| L3 | low | `default_max_gas()` = 3.000.000 (`config.rs:415-416`) < 3.286.339 / 3.357.045 | Đúng | §2.1 thêm dòng trần gas node |
| L4 | low | `zether-prover/` không có `benches/` hay số đo 0,35 µs | Đúng | §4 ghi "ước tính"; không thêm bench (đo khi cần chốt UX) |

## 7. Lịch sử bản

| Rev | Ngày | Thay đổi |
|---|---|---|
| 1.0 | 2026-10-05 | Quyết định owner D1–D6, bảng giới hạn, BSGS, cache |
| 1.1 | 2026-10-07 | Gộp review Claude 1 (L1–L4): biên phí thứ hai, bundle hai curve, trần gas node, thời gian BSGS là ước tính |
