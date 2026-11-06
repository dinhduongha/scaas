> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

> **Ghi chú nghiên cứu — chỉ là bối cảnh và lý do, không mang tính quy phạm; các quy tắc hiện hành nằm trong docs/ (xem decisions.md).**

> Bản tiếng Việt là bản phụ, theo phán quyết của chủ dự án (owner, 2026-11-06), ngoại lệ đối với quy tắc "docs bằng tiếng
> Anh" của AGENTS.md. Bản tham chiếu là bản tiếng Anh: [pqz-leg-proof-option.md](pqz-leg-proof-option.md); khi hai bản
> khác nhau, bản tiếng Anh được ưu tiên.

# PQZ `legProof`: một chứng minh tự kiểm cho mọi bản mã trong state (2026-11)

Viết ngày 2026-11-06 theo yêu cầu của chủ dự án. **Chỉ nói về PQZ**; Zether cổ điển là hệ riêng và chỉ được nhắc ở §11.4.
Chỉ là nghiên cứu: không có gì ở đây là quy tắc, không có gì trong pqz-core, hợp đồng, node hay client bị thay đổi, và mọi
phần mật mã đều **UNAUDITED**. Không đo gì cả: các con số là tính toán trên giấy từ số liệu repository đã ghi
([`pqz-leg-proof-option/`](pqz-leg-proof-option/), script và output). Không chạy đo gas hay thời gian nào (việc đó cần lời
của chủ dự án).

**Ý tưởng (owner, 2026-11-06).** Một tuỳ chọn bất biến theo token, chọn lúc tạo, `legProof ∈ {NONE, CALLDATA}` (không có
biến thể STATE: chứng minh tự kiểm được nên bất kỳ nguồn không tin cậy nào cũng phục vụ được). Với `CALLDATA` mọi khoản ghi
có (leg người nhận, bản sao cho auditor, các leg của op 7) đi kèm một chứng minh mà hợp đồng đã kiểm, nên mọi khoản ghi có
trong state đều có chứng minh. Thư viện của người giữ khoá (`ua-rs`) hay một thành viên quorum MPC khi đó chỉ giải mã tổng
của tối đa `K_MAX` phần đã được chứng minh, lấy từ bất kỳ nguồn nào, sau khi tự kiểm từng chứng minh; kết quả vẫn chỉ đến
người giữ khoá.

**Đầu vào coi là đã cho:** [ARCH-POS-13](../decisions.md#ARCH-POS-13) (owner: không bao giờ là decryption oracle); oracle
làm tròn 8·K và oracle trong quorum còn mở của [pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md) §12.1,
§12.5, §12.6; spec sửa lỗi no-oracle (`docs/superpowers/specs/2026-11-06-no-decryption-oracle.md` trên nhánh
`ua-rs-sign`), đã chọn phương án (A) "state đã chứng minh, kiểm ở tầng đọc chain" với các nghĩa vụ R1 đến R6 của tầng đọc,
và loại phương án (B), chứng chỉ, vì không xây được; quyết định của owner về phương án dự phòng của quorum MPC (§9.2).

**Nhãn bằng chứng:** [repo] đọc từ repository này; [paper] đã bình duyệt; [inference] suy luận của chúng tôi; [estimate]
tính toán trên giấy của chúng tôi.

## 1. Tóm tắt

| Câu hỏi | Trả lời |
|---|---|
| Q1 Một chứng minh hợp lệ cho mỗi phần cộng `≤ K_MAX` phần có xoá được oracle §12.1 không? | **Có, đối với khoá** [inference]: mỗi phần đã chứng minh giải mã ra đúng các chữ số mà người chứng minh đã chọn, dù `s` là gì, nên câu trả lời là hàm của bản mã, không bao giờ là hàm của `s`. Chứng minh phải ràng buộc miền chữ số `[0, 16)`; thiếu nó quan hệ không nói gì. Nó **không** làm cho một tổ hợp trở nên xác thực: nguồn vẫn có thể bỏ bớt hay thêm phần, đó là chuyện riêng tư số dư, không phải chuyện khoá (§3.3). |
| Q2 `v_f` của chính người giữ khoá và `acc` đã cuộn? | Phép kiểm mã hoá lại với tính ngẫu nhiên dẫn xuất của CTR-PQZ-19 dùng được cho ghi nợ op 1 / op 7 và không lộ gì về `s`, nhưng **không dùng được cho burn và refresh** (tính ngẫu nhiên mới) và cần seed (quorum không có). Chứng minh ghi nợ của chính người giữ khoá phủ mọi ghi nợ, khi `T` của nó được công bố (§4). `acc` được dựng lại từ các phần đã chứng minh, không bao giờ giải mã nguyên như được đưa. |
| Phát hiện: chứng minh ghi nợ đã là chứng minh gộp cho các leg | Các hàng 2, 3, 4, 5 của `R_TX` / `R_TXM` / `R_BURN` chứng minh mọi bản mã mà một ghi nợ ghi ra (mỗi leg, mỗi bản sao auditor, `v_f`). Thứ phương án (B) thiếu chỉ là `T` của người gửi. Nếu token **ghi log 640 byte header và `T`** của mọi ghi nợ (≈ 0,15–0,20 M gas), ai cũng dựng lại được statement và kiểm chứng minh từ lịch sử: **không quan hệ mới, không `proofSystemId` mới, không đổi precompile** (§5). Ta gọi là *debit-T*. |
| Q3 Oracle MPC trong quorum của §12.5? | **Đóng đối với khoá** nếu mỗi thành viên tự kiểm chứng minh của mọi phần và tự cộng các phần trước khi góp một phần giải mã [inference]. Còn lại: quorum đồng ý mở những tổng nào (chuyện chính sách và riêng tư) và phương án dự phòng khi mất chứng minh (§9.2, quyết định của owner). |
| Q4 Kích thước và gas ở bốn bộ tham số | Chứng minh leg độc lập ≈ `R_DS` + 0,5 KB (29,5 / 31,3 / 33,5 / 36,5 KB); mỗi leg một cái tốn ≈ 4,2–4,5 M gas, nên op 1 có auditor, op 7 M ≥ 2 có auditor và op 7 M ≥ 4 không auditor không còn vừa 2^24. Một chứng minh gộp cho mỗi giao dịch vừa mọi dạng trừ op 7 M = 8 (có auditor thì không bao giờ; không auditor chỉ vừa ở ước lượng thấp). debit-T vừa mọi dạng đang vừa hôm nay (§6). PQZH không mang thêm được chứng minh nào (giới hạn calldata); debit-T không cần. |
| Q5 Gộp, kiểm theo lô | Một chứng minh cho mỗi giao dịch (`R_LEGS`, hàng 2, 3, 5 của `R_TXM`) là được nhưng đó chính là chứng minh ghi nợ; kiểm theo lô trong ví là kiểm song song, chưa biết cách gộp đại số cho chứng minh LNP22 [inference]. |
| Q6 Chi phí ví | `n2304-kmax4096`, 4.096 khoản ghi có: độc lập ≈ 204 MB phải tải, debit-T ≈ 0,42–0,72 GB; kiểm ≈ 90 s (độc lập) hoặc 185–211 s (debit-T) đơn luồng, ước lượng theo p99 [estimate]. Kiểm một lần khi khoản đến và giữ chứng minh; khôi phục mới chỉ cần các phần từ lần ghi nợ cuối. |
| Q7 Thay đổi gì | debit-T: một log mỗi ghi nợ, một cờ bất biến trong phiên bản catalogue mới, một đường chứng minh trong `ua-rs`, vector cho bố cục log. Quan hệ độc lập: `proofSystemId` mới, op precompile mới, vector trong mọi client, full gate ở bốn bộ, và cắt bớt op 7. Zether: không cần cho khoá (§11.4). |
| Kết luận | **Xây `legProof = CALLDATA` dưới dạng debit-T**; không thêm quan hệ leg độc lập. Nó cho người giữ khoá một đường giải mã thứ hai dựa trên chứng minh, cho quorum MPC một đường an toàn về khoá, và giữ (A) làm dự phòng cho người giữ khoá đơn lẻ (§12). |
| Bổ sung 2026-11-06: `T` từ state (§14) | Nếu hợp đồng thôi xoá các slot pending và ghi một slot bản ghi cho mỗi lần ghi nợ, thì mọi `T` trong quá khứ là một hàm của state (≈ 0,10 M gas mỗi ghi nợ, như nhau ở mọi bộ, thay cho log `T` 0,15–0,20 M). Cách này chỉ bỏ được phần phụ thuộc lịch sử của `T`: chứng minh ghi nợ nằm trong calldata, và giữ nó trong state tốn ≈ 65–131 M gas mỗi ghi nợ PQZL, không vừa. Dự phòng §9 và quy tắc kho lưu vẫn cần. Bên ngoài sẽ không lưu chứng minh, nên ở cả hai dạng, tính sẵn có dựa vào việc ví người nhận giữ dữ liệu. Lý do chọn hướng 2 là chi phí và việc tổ hợp nằm trong state: chỉ là ưu tiên nhẹ (§14.7, §14.8). |

## 2. Tuỳ chọn dựa trên điều gì

**Vì sao state trên chain hôm nay an toàn** [repo]. Mọi bản mã vào state PQZ đều kèm chứng minh chuẩn chính xác; nhiễu của
tổng `K_MAX` đơn vị tối đa là `K_MAX · B_FRESH` (trường hợp xấu nhất trên các chuẩn đã chứng minh), dưới `Δ/2`, và phép giải
mã là duy nhất ([pq-zero-knowledge.md §4.3](../contracts/pq-zero-knowledge.md#noise),
[CTR-PQZ-03](../contracts/pq-zero-knowledge.md#CTR-PQZ-03)): "một state đã chấp nhận không bao giờ giải mã sai hay thất
bại". Oracle §12.1 cần bản mã nằm ngoài tập đó: `u` là đa thức đơn vị và `v_i = ⌈Δ/2⌉ + off`, để việc làm tròn
`−s_j[16w + i] + off` quanh `Δ/2` lộ một hệ số mỗi truy vấn; 8·K truy vấn khôi phục `s` (288 ở `n2304-kmax4096`).

**Vì sao (B) bị loại** (spec no-oracle §3) [repo]: chứng minh duy nhất của một khoản ghi có là chứng minh ghi nợ của người
gửi, mà statement chứa `T` của người gửi ở block đó, không có trong state; chứng minh nằm trong calldata (lịch sử hết hạn);
chứng minh op 4 `SENDER_S` chứng nhận được khoản ghi có không cần `T` nhưng cần người gửi; một keeper cuộn một khoản ghi có
chưa chứng nhận sẽ làm kẹt tài khoản; và một tổ hợp giả nhưng đúng dạng vẫn lộ số dư qua hành động sau đó của người giữ
khoá. Tuỳ chọn của owner trả lời ba điều đầu (mỗi khoản ghi có một chứng minh, hợp đồng kiểm, lấy từ lịch sử); §5 cho thấy
điều đầu được trả lời rẻ hơn bằng cách công bố `T`; §3.3 cho thấy điều cuối vẫn còn và cái giá của nó.

## 3. Q1: một phần đã chứng minh bảo đảm điều gì

### 3.1 Lập luận

Gọi một phần là bản mã `(u, v)` có chứng minh hợp lệ cho

```
u = Aᵀ·r + e1,  v[i] = (pkᵀ·r)[16w + i] + e2[i] + Δ·d_i  (i < 16),  d_i ∈ [0, 16),
‖r‖ ≤ β_s, ‖e1‖ ≤ β_e, ‖e2‖ ≤ β_2  (mỗi cận là một phương trình riêng, chính xác)
```

với khoá đã đăng ký của người giữ `pk = A·s + e` (chuẩn đã chứng minh bằng `R_REG`). Khi đó
`v − (uᵀ s)[window] = Δ·d + (eᵀ r − e1ᵀ s + e2)`, nhiễu tối đa `B_FRESH`. Với tổng tối đa `K_MAX` đơn vị do chính thư viện
dựng (các phần đã chứng minh, các số hạng `Trivial` nhiễu 0), nhiễu vẫn dưới `K_MAX · B_FRESH < Δ/2` và phép làm tròn trả
về đúng `Σ d`, với mọi khoá thoả các chuẩn đã đăng ký [repo, §4.3]. Vậy [inference]:

1. **Không làm tròn gần `Δ/2`, không thất bại.** Câu trả lời là tổng chữ số mà những người chứng minh đã chọn, một hàm của
   bản mã chứ không của `s`. Một truy vấn §12.1 (`u` là đa thức đơn vị) không có `(r, e1)` ngắn với `Aᵀr + e1 = u` (điều
   đó là phá MSIS / MLWE), nên không có chứng minh.
2. **Người truy vấn học được gì.** Với phần do chính nó chứng minh, câu trả lời là witness của nó (knowledge soundness:
   extractor lấy lại `d`). Với phần thật của người khác (chép từ chain kèm chứng minh), nó học được bản rõ của bản mã trung
   thực đó: một cặp known-plaintext trên một mẫu MLWE mới, không nói gì về `s`, nhưng là số tiền riêng của bên kia. Các tổng
   trộn hai loại.
3. **Tình trạng hình thức.** Đây là con đường cổ điển "mã hoá rồi chứng minh biết bản rõ" tới an toàn chosen-ciphertext
   (Naor–Yung 1990; Sahai 1999; Shoup–Gennaro 1998 cho ElGamal với chứng minh Fiat–Shamir) [paper]. Một chứng minh đầy đủ
   cho PQZ cần simulation-sound extractability của chứng minh Fiat–Shamir dưới truy vấn thích nghi; PQZL hấp thụ digest
   của statement trước (Fiat–Shamir mạnh, `hash0` của CTR-PQZ-19) [repo], tính chất mà thiếu nó đã làm hỏng các cách dùng
   Fiat–Shamir yếu (Bernhard–Pereira–Warinschi 2012) [paper]. Theo chỗ chúng tôi đọc, chưa có chứng minh như vậy cho LNP22
   / LaZer: **đây là hạng mục kiểm toán, không phải khẳng định**.

### 3.2 Chứng minh phải ràng buộc những gì

| Mục | Vì sao | Với debit-T (§5) |
|---|---|---|
| `u`, `v` (làn 64 bit, mọi hệ số `< q`), đúng các byte thư viện sẽ giải mã | chứng minh nói về các byte này; thư viện so từng byte | vị trí của leg trong `out`, `u_{g(j)}`, `v_j` hoặc `v_{a,j}` |
| `pk`, do **người kiểm** đưa (khoá của chính nó), không bao giờ do nguồn đưa | chứng minh dưới khoá khác không chứng nhận gì cho khoá này | từ `pk_t` của statement (hoặc `pk_a`, hoặc `pk_f` cho `v_f`) so với khoá của handle |
| cửa sổ `w` của bản sao auditor | bản sao nằm ở `(pk_aᵀ r)[16w + i]` | hàng 5, `w = j mod s_aud` |
| chữ số `d_i ∈ [0, 16)` | **thiết yếu**: `Δ` khả nghịch mod `q`, nên với `d ∈ Z_q` mọi `v` đều có witness và chứng minh trở nên rỗng | các hàng chữ số nhị phân của `R_TX` / `R_TXM` |
| chuẩn chính xác theo từng khối | ngân sách nhiễu giả định từng cận (phép kiểm chỉ-tổng của v1 cho phép 3,7 × `B_FRESH`) | như hôm nay (v2 trở đi) |
| `proofSystemId` (bộ tham số, transcript và chuẩn) và `opTag` | ngân sách tính theo bộ; tách miền với các quan hệ khác | từ header 0 và 32 |
| vị trí (chain, token, entry, leg) | không cần cho khoá; có ích để gắn chứng minh với chỗ của nó | các từ header, `entryRef` từ bộ đếm của người gửi |

**Các mục trivial** (`Trivial(digits(amount))` của một lần shield, số hạng `shieldIn`, đơn vị công khai được shield của
token lai) không bao giờ được nhận dưới dạng byte: thư viện dựng lại từ số tiền công khai (`< 2^64`), một đơn vị, nhiễu 0.
Số tiền sai từ nguồn cho số dư sai, không bao giờ lộ khoá.

### 3.3 Điều chứng minh không cho: tổ hợp

Một chứng minh chứng nhận một bản mã, không chứng nhận nó nằm trong tài khoản, cũng không chứng nhận tài khoản không có phần
nào khác. Nguồn có thể bỏ một khoản ghi có thật, thêm một phần đã chứng minh của chính nó hay phát lại một phần cũ. Giải mã
tổ hợp đó an toàn về khoá, nhưng kết quả sai, và bất kỳ **hành động ra ngoài nào phụ thuộc vào nó** (một ghi nợ mà ví thử
gửi hay không, chain sau đó từ chối vì `T` của hợp đồng khác) cho nguồn một bit về số dư thật. Đó là phản bác cuối của (B),
và nó vẫn còn [inference]. Hệ quả:

- **Xem** (kết quả chỉ đến người giữ khoá, không gì đi ra ngoài): nguồn nào cũng được.
- **Một ghi nợ**: các từ tài khoản quyết định tổ hợp (`pendingCount`, `rolled`, `floor`, `sendCounter`, `accUnits`,
  `accBlob`, `entryRef` của lần ghi nợ cuối) đến từ tầng đọc theo R1 (nguồn người giữ khoá tin). Bản mã và chứng minh vẫn
  có thể đến từ bất kỳ đâu. Điều này thu hẹp R1 từ "mọi từ" xuống vài từ tài khoản.

## 4. Q2: `v_f` của chính người giữ khoá và `acc` đã cuộn

Mọi ghi nợ ghi số dư mới `v_f` của người giữ khoá dưới `u_0` (op 1, nhóm 0 của op 7) hoặc `u′` (burn, refresh). Không chứng
minh ghi có nào phủ nó.

| Cách | Dùng được cho | An toàn về khoá? | Ghi chú |
|---|---|---|---|
| (i) **Kiểm mã hoá lại**: dẫn xuất lại `r, e1, e2_f` từ `pqzKeySeed`, bộ đếm và salt đã công bố (CTR-PQZ-19); đòi `u_0 = Aᵀr + e1` khớp từng byte và `v_f − pkᵀr − e2_f ∈ Δ·[0, 16)^16`; đọc `d′` từ đó | op 1, op 7 | có: `s` không bao giờ được dùng; việc từ chối phụ thuộc một phép so sánh PRF mà nguồn không đoán được và vào các chữ số | **không dùng được cho burn và refresh**: tính ngẫu nhiên của chúng là đầu ra CSPRNG mới, không dẫn xuất (CTR-PQZ-19, owner 2026-10-13). Một nguồn giữ `u_0` thật và cộng `Δ·k` vào một hệ số của `v_f` sẽ được chấp nhận hay bị từ chối tuỳ chữ số của người giữ khoá (một bit số dư, không phải bit khoá). Quorum không có seed, nên phải tính HKDF trong MPC. |
| (ii) **Chứng minh ghi nợ của chính người giữ khoá** (`R_TX` / `R_TXM` / `R_BURN`, hàng 2 và 4) | mọi ghi nợ | có; chỉ ai có `s_f` mới làm được chứng minh mà statement có `pk_f` = khoá của người giữ (hàng 1) | cần `T` của ghi nợ đó, như với khoản ghi có: §5 |
| (iii) Một chứng minh độc lập cho `v_f` ở mọi ghi nợ | mọi ghi nợ | có | thêm một chứng minh mỗi ghi nợ (≈ 4,2 M gas, §6) |

Đây không phải Fujisaki–Okamoto theo nghĩa CCA (FO dẫn xuất tính ngẫu nhiên từ thông điệp, Fujisaki–Okamoto 1999,
Hofheinz–Hövelmanns–Kiltz 2017 [paper]); nó là một phép kiểm kiểu MAC trên bản mã của chính người giữ khoá, cùng loại với
đường công bố `SENDER_S` của spec no-oracle §4.6 [repo].

**Một `acc` đã cuộn hay đã vật chất hoá** là `v_f` của lần ghi nợ cuối cộng các mục đã cuộn từ đó, bằng phép cộng mod `q`
(CTR-PQZ-08) [repo]. Thư viện không bao giờ giải mã các từ đã vật chất hoá nguyên như được đưa: nó dựng lại `acc` từ các phần
(`v_f` kiểm như trên, mỗi khoản ghi có đã chứng minh, mỗi mục TRIVIAL dựng lại) và có thể so byte, hoặc `accHash`, với thứ
nguồn đưa. Để hiển thị nó có thể giải mã từng phần riêng (mỗi phần một đơn vị, nên `K_MAX` không bao giờ chặn); `T` của một
ghi nợ có `unitsOf(T) ≤ K_MAX` theo quy tắc của chính hợp đồng.

**Khuyến nghị:** (ii) cho mọi người. (i) là lối tắt rẻ hơn cho người giữ khoá đơn lẻ chỉ ở op 1 / op 7; nó không phủ burn
và refresh, nên không thể là cách duy nhất.

## 5. Phát hiện: công bố `T` của ghi nợ, và chứng minh hiện có chính là chứng minh leg (debit-T)

Statement của ghi nợ là `header (640 B) ‖ pk_f ‖ [pk_t] ‖ [pk_a] ‖ T ‖ out` (op 7: khoá của mọi leg)
([§7.7](../contracts/pq-zero-knowledge.md#statement)) [repo]. `out` và chứng minh nằm trong calldata của giao dịch; các khoá
là state của registry, bất biến; các từ header có trong calldata và receipt trừ `envelopeBinding` (dẫn xuất từ envelope bên
ngoài), còn `T` chỉ tồn tại trong state của block đó. Nếu token, với token `CALLDATA`, **phát một log
`DebitStatement(entryRef, header ‖ T)` cho mỗi ghi nợ** (op 1, op 7, burn, refresh, unwrap), mọi mảnh của statement đều nằm
trong lịch sử, và:

- mỗi leg ghi có được chứng nhận bởi hàng 2, 3 (và bản sao auditor bởi hàng 5) của một chứng minh hợp đồng đã kiểm;
- `v_f` của chính người giữ khoá bởi hàng 2 và 4, với mọi loại ghi nợ;
- `T` không lộ gì mới: ai cũng tính được nó từ state công khai ở block đó (`acc`, cửa sổ, `shieldIn`) [inference];
- nguồn có thể không tin cậy với mọi đầu vào trừ khoá của chính người kiểm: `T`, header hay `pk_f` giả chỉ làm phép kiểm
  thất bại, hoặc chứng nhận một phần do chính kẻ giả làm ra (bản rõ của chính nó).

Chi phí: dữ liệu LOG 8 gas mỗi byte, `8 · (640 + CT)` cộng phần gốc và topic của log và một ít thực thi (giả định 10.000) ≈
0,15 / 0,16 / 0,18 / 0,20 M gas mỗi ghi nợ [estimate]; không thêm calldata, nên sàn EIP-7976 và các ghi nợ PQZH không bị ảnh
hưởng. Có một biến thể không đổi gì: dựng lại `T` từ state lịch sử của một archive node (view statement ở vị trí của giao
dịch); mong manh, vì phần lớn node cắt state cũ, nên không khuyến nghị.

| | Quan hệ leg độc lập (phác thảo của owner) | debit-T |
|---|---|---|
| Quan hệ mới, `proofSystemId`, op precompile, full gate | có | không |
| Chi phí on-chain | +1 chứng minh mỗi leg (hoặc mỗi giao dịch, gộp) | một log |
| Vừa 2^24 | cắt op 7 (§6) | mọi dạng đang vừa hôm nay |
| Token PQZH | không vừa (một chứng minh PQZH cỡ công bố là 190–234 KB) | vừa |
| Phủ `v_f` của burn / refresh | không, cần (iii) hoặc đổi giao thức | có |
| Byte ví tải mỗi khoản ghi có | ≈ 46–59 KB | ≈ 93–186 KB |
| Thời gian kiểm của ví mỗi khoản (ước lượng p99) | ≈ 22 ms | ≈ 45–51 ms |

## 6. Q4 và Q5: kích thước và gas ở bốn bộ tham số

**Cách lập số** ([`leg_proof_cost.py`](pqz-leg-proof-option/leg_proof_cost.py),
[`.out`](pqz-leg-proof-option/leg_proof_cost.out)) [estimate]:

- **Chứng minh leg độc lập `R_LEG`** = `R_DS` (công bố phía người gửi: cùng các hàng với số tiền công khai) cộng phần tăng
  mỗi leg của `R_TXM` không auditor từ M = 1 lên 2 (16 chữ số ẩn, một `e2`, một hàng): 29.469 / 31.320 / 33.485 /
  36.458 B. Giá kiểm = hàng PQZL `R_DS` tạm thời, 3.381.000 gas (bằng nhau ở mọi bộ: tạm thời, chưa hiệu chỉnh theo bộ).
  Dựng statement ≈ 0,37 / 0,42 / 0,48 / 0,53 M, lấy từ hàng đo `verifyTransferAmount` trừ intrinsic, calldata và
  precompile.
- **`R_LEGS(M, A)` gộp** (hàng 2, 3, 5 của `R_TXM`): kích thước giữa `R_TXM(M, A) − (R_TX − R_DS)` và `R_TXM(M, A)`, giá giữa
  hàng `R_DS` và hàng `R_TXM(M, A)`.
- **Gas thường** = max(dạng đo hôm nay + phần thêm, 15.000 + 64 × calldata); vừa = ≤ 2^24 và calldata ≤ 261.909 B. Gas
  state không đổi ở biến thể nào (chứng minh không được lưu).

Gas thường tính bằng M ở `n2304-kmax4096` (cả bốn bộ trong output; kết luận như nhau ở mọi bộ):

| Dạng | Hôm nay | (a) một `R_LEG` mỗi leg | (b) một `R_LEGS` mỗi giao dịch | (c) debit-T |
|---|---|---|---|---|
| op 1, auditor (2 leg) | 9,17 | 17,79 ✗ | 13,48–15,06 | 9,33 |
| op 1, không auditor | 8,88 | 13,19 | 13,18–15,19 | 9,04 |
| op 7 M = 1, auditor / không | 6,87 / 7,25 | 15,49 / 11,56 | 11,18–12,76 / 11,55–13,56 | 7,03 / 7,41 |
| op 7 M = 2, auditor / không | 7,08 / 7,17 | 24,32 ✗ / 15,79 | 11,40–13,10 / 11,48–13,33 | 7,24 / 7,33 |
| op 7 M = 4, auditor / không | 8,70 / 7,52 | 43,18 ✗ (calldata) / 24,76 ✗ | 13,29–15,52 / 11,85–13,88 | 8,86 / 7,68 |
| op 7 M = 8, auditor / không | 12,73 / 10,57 | 81,69 ✗ / 45,05 ✗ | 17,59–22,49 ✗ / 15,18–18,99 (✗ ở đầu cao) | 12,89 / 10,73 |
| burn / refresh | 6,85 | — | — | 7,01 |

- **Kích thước chứng minh, mọi bộ:** `R_LEG` 29,5 / 31,3 / 33,5 / 36,5 KB; `R_LEGS` ở op 7 M = 8 có auditor 71–85 / 64–80 /
  55–73 / 60–79 KB.
- **PQZH:** một chứng minh Ligero cỡ công bố là 207.688 B ở `n2304-kmax4096` (cận) [repo]; các ghi nợ PQZH đã bị sàn chặn
  gần 2^24, nên (a) và (b) không mang được ở bộ nào; (c) không thêm calldata.
- **Giới hạn kích thước giao dịch:** sàn 2^24 cho phép 261.909 B calldata; `MaxTxSize` 2 MiB của Nethermind là khoảng dư,
  không phải giới hạn chặn trước [repo].
- **USD**, dưới dạng công thức: `USD = gas × giá_gwei × 10⁻⁹ × ETH_USD`. Với 1 gwei và 3.000 USD/ETH (giả định, không phải
  dự báo): debit-T 0,17 M ≈ 0,51 USD mỗi ghi nợ; một `R_LEG` ≈ 4,2 M ≈ 12,60 USD mỗi leg.

**Q5, gộp.** Một chứng minh cho mọi leg của một giao dịch là `R_LEGS`; kích thước tăng theo `M` như `R_TXM` (một hàng `u_g`
mỗi nhóm, một hàng `v` và 64 bit chữ số mỗi leg và bản sao). Chứng minh ghi nợ đã có các hàng này, nên với debit-T phần gộp
là miễn phí. **Kiểm theo lô trong ví** là chạy bộ kiểm trên nhiều chứng minh song song; chúng tôi không biết cách gộp đại số
các phép kiểm LNP22 (khác với gộp MSM của Bulletproofs) [inference], nên chi phí tuyến tính theo số chứng minh và chia
được cho các lõi.

## 7. Q6: chi phí ví và tính sẵn có

| Bộ (`K_MAX`) | Độc lập, mỗi khoản / tất cả | debit-T, mỗi khoản / tất cả |
|---|---|---|
| `n2048-kmax1024` | 46,0 KB / 47 MB | 93–186 KB / 95–191 MB |
| `n2304-kmax4096` | 49,9 KB / 204 MB | 103–175 KB / 422–718 MB |
| `n2560-kmax16384` | 54,1 KB / 886 MB | 113–158 KB / 1,9–2,6 GB |
| `n2816-kmax65536` | 59,1 KB / 3,9 GB | 124–172 KB / 8,1–11,3 GB |

(debit-T tính khoá người gửi mỗi lần; cache khoá người gửi làm giảm số này.) **Thời gian kiểm** [estimate]: hàng tạm thời ÷
1,3 (hệ số tạm thời) ÷ 0,12 M gas mỗi ms kiểm p99 (tỉ lệ hiệu chỉnh của [§9](../contracts/pq-zero-knowledge.md#gas)) cho
≈ 22 ms với `R_DS`, 45 ms với `R_TX`, 51 ms với `R_TXM` M = 8 có auditor, p99 trên máy chủ chain: 4.096 khoản ≈ 90 s hoặc
185–211 s trên một lõi, chia cho số lõi dùng. Ví wasm chậm hơn. Không đo.

**Ví thật sự kiểm những gì.** Chỉ các phần của số dư hiện tại: lần ghi nợ cuối và các mục từ `p` của nó. Mỗi phần kiểm một lần,
khi đến, và giữ lại dữ liệu chứng minh: chi phí khối lớn ở trên là việc khôi phục mới một tài khoản đầy. Hàng đợi pending
không giới hạn (CTR-PQZ-06), nên một trận lũ mồi nhử bắt lần khôi phục mới kiểm nhiều chứng minh hơn; mỗi mồi nhử tốn cho
người gửi một ghi nợ và trả cho nạn nhân `decoyFee`, như hôm nay.

**Lịch sử hết hạn** (EIP-4444): chứng minh, payload và log nằm trong thân block và receipt, chúng hết hạn; state thì không.
Một phần mà dữ liệu chứng minh không còn ai phục vụ thì đường chứng minh không kiểm được nữa; §9 bàn phương án dự phòng.

## 8. Hai đường giải mã trong `ua-rs`, hai lệnh

Tham số tường minh: mỗi thao tác một lệnh, không có cờ chế độ. Cả hai nhận các trường vị trí có tên và chỉ trả
`{value, ...}` cho bên gọi; mọi từ chối trước khi dùng khoá là một trạng thái duy nhất `Argument` không kèm chi tiết (như spec
no-oracle §4.3).

**Đường (A), mọi token** (spec no-oracle §4.3 đến §4.5, không đổi): `balance {chainUid, token, ua, block, words}` và các
lệnh ghi nợ với `words`; tầng đọc chịu R1 đến R6 cho mọi từ.

**Đường chứng minh, chỉ cho token tạo với `legProof = CALLDATA`** (dạng debit-T):

```
balanceProven {
  chainUid, token, ua, proofSystemId,
  lastDebit: { entryRef, header, t, out, proof, pkFrom } | null,        // null: chưa ghi nợ, acc = Trivial(0)
  credits:   [ { index, entryRef, leg, header, t, out, proof, pkFrom, pkOthers[] } ],
  trivials:  [ { index, amount } ]
}
```

Các phép kiểm, tất cả trước khi dùng khoá: bộ tham số của token bằng `proofSystemId` của handle; mỗi statement do thư viện
dựng lại (`header ‖ keys ‖ t ‖ out`, khoá của chính người giữ chèn vào chỗ statement nêu; `pkOthers` là khoá của các leg khác
và của auditor) và kiểm bằng bộ kiểm của chính thư viện; `(u, v)` của khoản ghi có đọc từ `out` ở vị trí của leg; statement
của `lastDebit` nêu người giữ là người gửi; các chỉ số liền nhau từ `p` của lần ghi nợ cuối; mọi hệ số `< q`. Đầu ra:
`{value, parts}`. Các lệnh ghi nợ của đường chứng minh (`proveTransferProven` và các lệnh khác) nhận cùng các danh sách cộng
các từ tài khoản của §3.3 (`pendingCount`, `rolled`, `floor`, `sendCounter`, `accUnits`, `accBlob`), do tầng đọc cung cấp
theo R1. Từ chối sau khi dùng khoá chỉ có ở ghi nợ (số dư nhỏ hơn số tiền + phí) và đi đến bên gọi.

**Ai dùng đường nào** [inference]. Người giữ khoá đơn lẻ có thể dùng đường nào cũng được cho token `CALLDATA`: (A) khi có
nguồn tin cậy, đường chứng minh khi không có hoặc muốn ít từ phải tin hơn. Thành viên quorum MPC **chỉ** dùng đường chứng
minh; không bao giờ giải mã qua (A) (đó lại là §12.5).

**Hạ cấp.** `legProof` bất biến, nên không ai đổi được token. Với `CALLDATA` chính hợp đồng phát log ở mọi ghi nợ sau khi kiểm
chứng minh (người gửi không bỏ hay sửa được), nên mọi bản mã một ghi nợ ghi ra đều được chứng nhận; mọi thao tác ghi khác là
mục TRIVIAL hoặc tổng của các phần có sẵn. Một bất biến forge phải kiểm điều này trên mọi đường ghi (op 1, op 7, burn,
refresh, unwrap, shield, rollover, un-roll, migration). Kẻ tấn công giữ lại dữ liệu chứng minh có thể đẩy người giữ khoá về
(A): với người giữ khoá đơn lẻ, (A) theo R1 đến R6 là an toàn, và không có nguồn tin cậy thì người giữ khoá chỉ không xem
được (tính sống, không phải khoá). Đường được chọn tuỳ vào tính sẵn có, không bao giờ tuỳ vào một phép giải mã, nên bản thân
lựa chọn không phải một bit oracle.

## 9. Khi mất dữ liệu chứng minh

### 9.1 Người giữ khoá đơn lẻ: quay về (A) (khuyến nghị của controller, 2026-11-06)

Khi dữ liệu chứng minh của một phần cần thiết đã mất khỏi mọi nguồn, người giữ khoá dùng đường (A). An toàn theo R1 đến R6
(cách xây dựng đã chọn của spec no-oracle): các từ đến từ nguồn người giữ khoá tin và không gì quay về. Không có nguồn như
vậy thì ví từ chối (một trạng thái) thay vì giải mã.

### 9.2 Quorum MPC: không dùng (A); dựng lại seed và xoay khoá (quyết định của owner, 2026-11-06)

Quay về (A) sẽ đem §12.5 trở lại: một thành viên cung cấp "state" cho các thành viên khác chính là oracle trong quorum.
**Quyết định của owner (2026-11-06):** khi mất chứng minh leg, `k` thành viên dựng lại `seed32` từ bản sao lưu k-of-n (T16a
/ T16b, đã xây trên `ua-rs-sign`), một thành viên trở thành operator của phương án (A), và operator xoay tài khoản sang một
phiên bản khoá mới (spec 3g, `docs/superpowers/specs/2026-11-06-pqz-key-versions.md`, migration KV-9). Nó khớp với mô hình
dealer của ghi chú nghiên cứu: mỗi phiên bản khoá đi kèm các phần (A) mới của `seed32` của nó.

- **Cái giá:** từ lúc dựng lại đến lúc xoay, operator giữ toàn bộ khoá (ngưỡng không bảo vệ gì trong khoảng đó); các phần
  của phiên bản cũ được giữ, không bao giờ xoá; migration là một ghi nợ, nên operator giải mã số dư cũ một lần, như người giữ
  khoá đơn lẻ theo R1 đến R6.
- **Điều operator không bao giờ làm:** giải mã một bản mã do thành viên đưa (§12.6, quy tắc của (A)): nó tự đọc chain.

### 9.3 Làm cho dự phòng hiếm xảy ra

| Biện pháp | Thuộc về đâu |
|---|---|
| Ví giữ dữ liệu chứng minh của mọi phần đã kiểm khi đến (cache cục bộ); khi đó mất lịch sử chỉ ảnh hưởng lần khôi phục mới | quy tắc client (`ua-libraries.md`, tầng ví); thư viện nhận dữ liệu làm đầu vào và không tự I/O |
| Mỗi thành viên quorum giữ mọi chứng minh đã kiểm; cache của một thành viên bất kỳ phục vụ được mọi thành viên khác, vì dữ liệu tự kiểm | spec của dịch vụ quorum (C3, chưa lên lịch) |
| Một kho lưu: indexer của `scaas-node`, hoặc bất kỳ indexer không tin cậy nào, lưu và phục vụ log ghi nợ, payload và chứng minh theo `entryRef` | **spec của node** (`docs/node/store.md`, `gateway.md`), ở mức PLANNED: bảo đảm của node thuộc về node, và nó không cần tin cậy; node vẫn không bao giờ giải mã (NODE-GEN-01) |

**Giữ lại làm đòn tấn công** [inference]. Với người giữ khoá đơn lẻ: không thu được gì về `s`; tối đa là buộc dùng (A) hoặc
bị từ chối. Với quorum: có thể đẩy về §9.2, một khoảng thời gian một operator giữ khoá. Cache của một thành viên trung thực
hay một kho lưu bất kỳ là đủ để chặn, và việc dựng lại cần `k` thành viên, nên người ngoài không tự kích hoạt được; các thành
viên chỉ nên tuyên bố mất dữ liệu sau khi đã thử cache của mọi thành viên và các kho lưu.

## 10. Q3: oracle trong quorum của §12.5

Với đường chứng minh, một thành viên chỉ góp phần giải mã cho một tổng nó tự dựng từ các phần nó tự kiểm (mỗi phần là một
khoản ghi có đã chứng minh tới khoá của quorum, `v_f` của chính tài khoản kèm chứng minh ghi nợ, hoặc một mục TRIVIAL từ số
tiền công khai), tối đa `K_MAX` đơn vị. Khi đó `M` được mở là một tổng chữ số do những người chứng minh các phần ấn định, và
phép làm tròn C1 chỉ mở một mặt nạ đều và `M` (§12.1) [repo]; nên một thành viên không khôi phục được `s` [inference]. Trước
đây owner không chọn "tự đọc state" cũng không chọn "kiểm một chứng minh đúng dạng" (§12.5), khi chưa có chứng minh như vậy
cho khoản ghi có; debit-T cho lựa chọn thứ hai một nội dung thật. Còn lại:

- **Chính sách, không phải khoá:** một thành viên có thể đòi mở một khoản ghi có thật, biết số tiền của nó. Quorum mở những
  tổng nào, và cho ai, là quy tắc truy cập của quorum (mỗi lần mở do các thành viên phê duyệt).
- **Tổ hợp** (§3.3): các thành viên thống nhất các từ tài khoản cho một ghi nợ; tổ hợp sai làm ghi nợ thất bại trên chain;
  trong quorum điều đó không lộ gì mà các thành viên chưa thấy.
- **Tính sẵn có:** §9.2.
- **An toàn trước kẻ ác ý của C3, dealer (C2), chứng minh của §3.1:** các hạng mục mở không đổi; quorum chưa được xây.

## 11. Q7: thay đổi gì

### 11.1 debit-T (khuyến nghị)

- **Hợp đồng:** một `legProof` bất biến đặt ở `initialize`, một phiên bản catalogue mới (không nâng cấp gì đã triển khai);
  log trong bước ghi nợ chung (`PqzCore`, gọi từ `PqzTransferLib` và `PqzBurnLib`). Kích thước mã: nhỏ; `size-baseline.json`
  của worktree này cho `WrappedPqzToken` 56.721 B, `WrappedPqzRegulatedToken` 62.285 B (sát 64 KiB nhất) và `PqzTransferLib`
  17.697 B; thay đổi nằm trong các thư viện [repo] [estimate]. Các pin layout và typehash không đổi (không thêm storage).
- **pqz-core:** không: không đổi quan hệ, transcript, `proofSystemId` hay precompile, nên không cần full gate.
- **Vector:** bố cục log và "statement dựng lại từ lịch sử bằng statement của hợp đồng" ở bộ mặc định và một bộ khác, do
  `ua-rs` và C ABI (`ua-c`) mà các binding gọi đọc.
- **`ua-rs`:** các lệnh của đường chứng minh ở §8, bộ kiểm trên thiết bị (đã được liên kết qua `pqz-ffi`).
- **Node:** quy tắc kho lưu PLANNED (§9.3); indexer chuẩn hoá event mới.

### 11.2 Một quan hệ độc lập (không khuyến nghị)

Quan hệ mới là `proofSystemId` mới, vector mới trong mọi client, op precompile mới trong pqz-ffi và plugin Nethermind (một
lịch chainspec mới, cả trên chain của khách hàng), full gate ở bốn bộ (mỗi bộ vài giờ), chỉ PQZL (PQZH không vừa), cắt bớt
op 7 (§6), và burn và refresh vẫn cần debit-T hoặc (iii) cho `v_f`.

### 11.3 PQZH

debit-T áp dụng nguyên vẹn: ví kiểm chứng minh Ligero (≈ 250 KB mỗi ghi nợ phải tải) [repo, kích thước].

### 11.4 Zether

ElGamal nâng của Zether không có oracle khôi phục khoá (ARCH-POS-13) [repo]; chứng minh chuyển của nó cũng chứa bản mã số dư
của người gửi (hàng Σ `A_bal` trên `D_acc`, [zether.md §8.1](../contracts/zether.md)) [repo], nên "chứng minh mỗi leg" sẽ gặp
cùng vấn đề về hình dạng. Phía riêng tư của quy tắc được (A) đáp ứng. **Không cần cho Zether**; Zether ≠ PQZ, nên không gì ở
đây áp dụng cho nó.

## 12. Kết luận và lộ trình

**Kết luận.** Tuỳ chọn của owner là đúng đắn đối với khoá [inference, UNAUDITED]: một phần đã chứng minh cộng phép cộng và
đếm `K_MAX` của chính thư viện xoá oracle §12.1, cho người giữ khoá, bàn auditor và thành viên quorum như nhau. Dạng rẻ nhất
của nó là **debit-T**: chứng minh ghi nợ hiện có, được làm cho kiểm được từ lịch sử bằng cách ghi log `header ‖ T`. Nó không
xoá nhu cầu một nguồn tin cậy cho các từ tài khoản trước một hành động ra ngoài (§3.3), và nó phụ thuộc lịch sử (§9).

| Bước | Công việc | Ngày-agent [estimate] |
|---|---|---|
| R1 | Fable + Codex review ghi chú này (quy tắc spec mật mã), rồi mục decisions | 1–2 |
| R2 | Hợp đồng: `legProof` bất biến, log `DebitStatement` ở mọi dạng ghi nợ, test forge (log bằng statement đã kiểm; đường từ chối; bất biến của §8), size gate ở bốn bộ | 3–4 |
| R3 | Vector: bố cục log và dựng lại statement, bộ mặc định + một bộ khác; bộ đọc `ua-c` | 1–2 |
| R4 | Đường chứng minh `ua-rs`: `balanceProven` và các lệnh ghi nợ, một trạng thái, test âm (`T` giả, sai khoá, đổi leg, vượt `K_MAX`, hệ số không chính tắc), mutant, harness 8·K làm test âm | 5–7 |
| R5 | Node: quy tắc kho lưu PLANNED, lưu ở indexer và đọc qua gateway theo `entryRef` | 2–4 |
| R6 | Docs: `pq-zero-knowledge.md` (tuỳ chọn, log, đường chứng minh), `ua-libraries.md` (cache client), trạng thái §12.5, bản tiếng Việt | 1–2 |
| | **Tổng** | **13–21** |

Bản thân dịch vụ quorum vẫn là C3 (chưa lên lịch). Một quan hệ độc lập sẽ tốn ≈ 30–45 ngày-agent cộng bốn full gate và không
phủ burn và refresh.

## 13. Câu hỏi mở cho owner

1. **Xây `legProof = CALLDATA` dưới dạng debit-T** (token ghi log `header ‖ T`; chứng minh ghi nợ chứng nhận mọi bản mã) thay
   vì một quan hệ leg độc lập mới? *Khuyến nghị:* có: không quan hệ hay op precompile mới, vừa mọi dạng và PQZH, phủ `v_f`
   của mọi ghi nợ.
2. **§12.5 cho khoá tài khoản:** ghi nhận đường chứng minh (mỗi thành viên tự kiểm và tự cộng các phần; dự phòng §9.2) là lời
   giải, trạng thái "đã giải trên giấy, UNAUDITED", chờ review của R1? *Khuyến nghị:* có; quorum vẫn chưa xây cho đến khi C3
   được lên lịch.
3. **Kho lưu trong node:** thêm một quy tắc PLANNED rằng indexer của `scaas-node` lưu và phục vụ dữ liệu ghi nợ của token
   `CALLDATA` theo `entryRef`? *Khuyến nghị:* có; dữ liệu tự kiểm, nên không thêm sự tin cậy nào vào node.

## 14. debit-T từ state: giữ các phần của T và lưu tham chiếu (2026-11-06)

**Câu hỏi (owner, 2026-11-06, hướng 2).** Ghi log `header ‖ T` (§5) phụ thuộc lịch sử (EIP-4444). Lưu nguyên `T` tốn
≈ 21 M (SSTORE2) hoặc ≈ 41 M (slot mới) ở `n2304-kmax4096` và đã bị loại. Thay vào đó, hợp đồng có thể giữ các phần tạo nên
`T` (vốn đã nằm trong state) và lưu một tham chiếu ngắn cho mỗi lần ghi nợ, để mọi `T` trong quá khứ dựng lại được chỉ từ
state hay không? Phần này đọc theo `PqzCore.sol` và `PqzStateLib.sol` trên nhánh `ua-mtx-merge` (số dòng bên dưới). Phần
tính toán nằm trong [`debit_t_state.py`](pqz-leg-proof-option/debit_t_state.py) và
[`.out`](pqz-leg-proof-option/debit_t_state.out). Không đo gì cả.

### 14.1 `T` gồm những gì, và hôm nay mất gì

`_total` (`PqzCore.sol` 748–767) [repo]: `T = reduce(acc ± Σ pending[window) + Trivial(digits(shieldIn)))`. Cửa sổ là
`[rolled, p)` khi `p ≥ rolled`, và `[p, rolled)` (bị trừ) khi `p < rolled`; `|p − rolled| ≤ INLINE_MAX` (10 với op 7 của
PQZH).

| Phần của `T` | Nằm ở đâu | Ghi hoặc đổi | Hôm nay mất gì [repo] |
|---|---|---|---|
| `acc` dạng tham chiếu `(accBlob, accU, accV)`: `(u_0, v_f)` của lần ghi nợ trước (burn, refresh: `(u′, v_f)`) | op blob của lần ghi nợ trước (SSTORE2, không bao giờ xoá) và ba trường tài khoản | `_debit` 861 | blob còn; các trường tài khoản bị lần ghi nợ sau ghi đè (861), và `p` của lần ghi nợ đó chỉ còn đến khi rollover kế tiếp dời `rolled` / `floor` (862; `PqzStateLib` 100–108) |
| `acc` vật chất hoá: `accWords` (339 / 417 / 504 / 598 slot) và `accHash`, hoặc hint calldata có keccak bằng `accHash` | slot | mỗi rollover ghi đè mọi từ tại chỗ (`PqzStateLib` 92–96, 99); một lần ghi nợ xoá cờ `MAT` (861) | bị ghi đè ở mỗi rollover; chỉ là cache: bằng `v_f` trước cộng các mục đã cuộn, mod `q` |
| một khoản ghi có: `pending[i] = blob ‖ uOff ‖ vOff ‖ block` | một slot trỏ vào blob của người gửi | `_credit` 334–340 | slot bị lần ghi nợ sau xoá với `[cleared, p)` (863) và bị rollover xoá với `[cleared, rolled − INLINE_MAX)` (`PqzStateLib` 106); bản mã vẫn ở trong blob của người gửi |
| mục TRIVIAL `(amount, block)` | chỉ trong slot | `_trivial` 348–364 (chỉ gộp vào mục cuối khi mục đó còn pending, cùng block) | bị xoá cùng slot; số tiền chỉ còn trong event `Shielded` |
| `Trivial(digits(shieldIn))` | từ header 480 (calldata) | — | không bao giờ nằm trong state |

Các event (`Debited(ua, p, p, blob)`, `Credited`, `Shielded`, `RolledOver`) mang đủ tất cả, nhưng chúng là lịch sử.

**Một đẳng thức** [inference, từ mã]. Gọi `p_k` là `p` của lần ghi nợ có bộ đếm `k` của người giữ khoá và `B_k` là op blob
của nó (`B_{−1}` = `Trivial(0)`, `p_{−1}` = 0). Đẳng thức sau đúng với mọi đường đi: `acc` dạng tham chiếu hay vật chất hoá,
có hay không có hint, cửa sổ lên hay xuống, bao nhiêu rollover ở giữa cũng vậy.

```
T_k = reduce( (u, v_f) của B_{k−1}  +  Σ_{i ∈ [p_{k−1}, p_k)} entry_i  +  Trivial(digits(shieldIn_k)) )
```

Sau lần ghi nợ `k − 1`, `acc = B_{k−1}` và `rolled = floor = p_{k−1}` (861–862). Rollover cộng các mục theo thứ tự
(`PqzStateLib` 86–88). Cửa sổ xuống trừ dưới dạng `+ (q − y)` (`PqzCt.addBlob`, `neg`). Mọi lane được rút gọn mod `q` ở
cuối, nên kết quả là thặng dư chính tắc và các tổng rút gọn về đoạn `[p_{k−1}, p_k)`; đoạn này tồn tại vì
`p ≥ floor ≥ p_{k−1}` (752). Quy tắc đơn vị (762–766) cho `unitsOf(T_k) = (p_k − p_{k−1}) + 2 ≤ K_MAX`, nên
`Δp_k ≤ K_MAX − 2` (lần ghi nợ đầu: `p ≤ K_MAX − 1`). Một mục đã tiêu không bao giờ đổi, vì phép gộp TRIVIAL chỉ chạm mục
cuối ở chỉ số `≥ max(floor, rolled)` (354–355). **Vậy `acc` vật chất hoá, `accHash`, hint và các rollover chỉ là cache:
không cái nào cần để dựng lại `T`.** Cái cần là: blob của lần ghi nợ trước, `p_{k−1}`, `p_k`, các mục ở giữa, và
`shieldIn_k`.

**Chứng minh ràng buộc `T` thế nào** [repo]. `T` nằm nguyên văn trong statement, ngay sau các khoá (op 1: 271, op 7: 481,
burn và refresh: 604). `PqzAuth` đã ký phủ nó qua `bodyHash = keccak256(statement[640:])` (`authDigest`, 839–851). Precompile
kiểm chứng minh trên toàn bộ statement (PQZL hấp thụ digest của statement trước tiên, CTR-PQZ-19). Hôm nay không lưu và
không log hash nào của `T`, và cũng không cần: một `T` dựng sai làm phép kiểm thất bại, như ở §5.

### 14.2 Thay đổi tối thiểu

1. **Bỏ hai chỗ xoá** (`PqzCore.sol` 863, `PqzStateLib.sol` 106). `cleared` và `floor` vẫn cập nhật như cũ: `floor` vẫn
   giới hạn un-roll ở `INLINE_MAX`, còn `cleared` chỉ đánh dấu chỗ hợp đồng thôi đọc. Không slot hiện có nào bị dời.
2. **Một bản ghi cho mỗi lần ghi nợ**, ghi trong `_debit`, khoá theo `entryRef` của lần ghi nợ (id của CTR-PQZ-23; burn tính
   nó trong `_sent` và hôm nay bỏ đi, dòng 555): `debitRec[entryRef] = { blob(160) ‖ p(64), shieldIn }`, từ thứ hai chỉ ghi
   khi `shieldIn ≠ 0`. Không lưu `uOff` / `vOff`: `v_f` nằm ở `blobLength − VP`; `u` nằm ở 0 với blob burn hoặc refresh
   (dài đúng `CTP`) và ở 16 với blob chuyển khoản (luôn dài hơn). Có một biến thể một từ `blob ‖ Δp(32) ‖ shieldIn(64)`
   (`Δp < 2^16` ở mọi bộ, `shieldIn ≤ 2^62`), nhưng khi đó người đọc phải cộng dồn `Δp` qua mọi lần ghi nợ trước; ta chọn
   dạng hai từ. Một view với trường có tên: `pqzDebitRecord(ua, counter) → (blob, p, shieldIn)`.
3. **Chỉ log header** (tuỳ chọn, §14.6): `DebitHeader(entryRef, header)`, 640 B.

**Dựng lại** (do ví, hoặc do bất kỳ server không tin cậy nào làm; chứng minh sẽ kiểm câu trả lời), cho lần ghi nợ của `from`
có bộ đếm `k`:

1. đọc `rec_k` và `rec_{k−1}` (với `k = 0` thì không có: `Trivial(0)`, `p = 0`);
2. lấy `(u, v_f)` từ `blob_{k−1}` (`eth_getCode`; các hệ số nén được bung ra lane 64 bit);
3. với mỗi `i` trong `[p_{k−1}, p_k)`, đọc `pending[from][i]` (`pqzPending`, hoặc `pendingCt`): khoản ghi có thì lấy `(u, v)`
   từ blob của nó, mục TRIVIAL thì dùng `Trivial(digits(amount))`;
4. cộng theo lane 64 bit, cộng `Trivial(digits(shieldIn_k))`, rút gọn mod `q`: được `T_k`;
5. dựng statement (`out` cũng lấy từ `blob_k`: `u_g`, `v_j`, `v_{a,j}`, `v_f`; khoá lấy từ registry; các từ header theo
   §14.6) rồi kiểm chứng minh.

### 14.3 Chi phí trên giấy, cả bốn bộ

Bản ghi là một slot ở mọi bộ, nên các con số như nhau ở mọi bộ, trừ cột rollover [estimate]:

| Hạng mục | State gas (EIP-8037) | Regular gas |
|---|---|---|
| bản ghi, mỗi lần ghi nợ (op 1, op 7, burn, refresh, unwrap) | +97.920; thêm +97.920 khi `shieldIn ≠ 0` | ≈ +5.000 |
| các lần xoá mà ghi nợ không làm nữa (0 đến `2·INLINE_MAX` = 32 slot) | 0: xoá một slot đã có từ trước giao dịch không hoàn lại state gas (EIP-8037) | −12.100 gộp mỗi slot (EIP-8038 2.100 + 10.000): tới −0,39 M. Người trả phí cũng mất phần hoàn khi xoá (4.800 mỗi slot ở Osaka; con số Amsterdam chưa có trong repo) |
| rollover (các lần xoá không làm nữa, tới `ROLL_MAX`) | 0 | tới −1,16 / −0,97 / −0,77 / −0,39 M gộp |
| `mtxPrepareAcc` | 0 | 0 |
| log chỉ header (tuỳ chọn) | 0 | ≈ +0,01 M |

Chênh lệch ròng mỗi lần ghi nợ, theo góc nhìn người trả phí: +0,10 M khi không bỏ được lần xoá nào, giảm tới ≈ −0,13 M khi bỏ
được 32. So sánh: log `header ‖ T` tốn 0,15 / 0,16 / 0,18 / 0,20 M (tăng theo `CT`); lưu nguyên `T` tốn 16,8 / 20,6 / 24,8 /
29,4 M bằng SSTORE2, hoặc 33,2 / 40,8 / 49,4 / 58,6 M bằng slot mới. Hướng 2 kèm log header tốn nhiều nhất ≈ 0,11 M, như nhau
ở mọi bộ: rẻ hơn log khoảng một phần ba, và rẻ hơn lưu `T` khoảng 200 lần.

**Vừa giới hạn.** Regular gas đổi nhiều nhất +5.000 và thường giảm, nên không dạng nào tiến gần 2^24 hơn (EIP-7825).
`tx.gas` tăng ≈ 0,1 M state gas. Một lần ghi nợ vốn đã mang 17,6–70,5 M state gas, nên phần thêm nhiều nhất là 0,6 %; không
kết luận nào về việc được đưa vào block theo EIP-8037 thay đổi. `PQZ_DEBIT_MIN_GAS` và các ghim gas chỉ đổi sau khi đo, và
việc đo cần lời của owner.

### 14.4 Tăng trưởng state và các giới hạn bị chạm tới

- **Mỗi khoản ghi có:** +32 B, giữ mãi. 97.920 state gas của nó đã trả lúc ghi khoản ghi có, và việc xoá chưa bao giờ hoàn
  lại phần đó. **Mỗi lần ghi nợ:** +32 B, hoặc +64 B khi có `shieldIn`. Blob op 1 có auditor hôm nay là 11.052 / 13.572 /
  16.348 / 19.380 B (CTR-PQZ-07), nên phần tăng mỗi lần ghi nợ dưới 0,6 %. Mỗi tài khoản tăng `32 · (số khoản ghi có + số
  lần ghi nợ)` B: 32 MB cho 10^6 khoản ghi có [estimate].
- **Hàng đợi không giới hạn** (CTR-PQZ-06): mỗi khoản mồi nhử giờ để lại 32 B vĩnh viễn. Như hôm nay, mỗi khoản mồi nhử tốn
  của người gửi một lần ghi nợ và trả `decoyFee` cho nạn nhân. Việc này đảo ngược lý do ghi ở
  [pq-zero-knowledge.md §7.4](../contracts/pq-zero-knowledge.md#transfer) ("giữ state khỏi tăng 32 B mỗi khoản ghi có mãi
  mãi") và ở spec state (§5.5), nên là một thay đổi quy tắc và cần một mục trong decisions.
- **`ROLL_MAX`, `mtxPrepareAcc`, `K_MAX`:** quy tắc không đổi. Rollover rẻ hơn vì không còn xoá, nên các con số rollover đã
  ghim (`PqzStatePinGasTest`) chỉ có thể giảm, và biên hẹp của `n2560-kmax16384` (6.032 gas) không thể tệ hơn. Nâng
  `ROLL_MAX` cần một lần rollscan, và rollscan cần lời của owner. `Δp ≤ K_MAX − 2` đã suy ra từ phép kiểm đơn vị hiện có.
- **Kích thước mã:** bỏ hai vòng lặp; thêm một lệnh ghi, view và event tuỳ chọn, tức vài trăm byte trong `PqzTransferLib`
  (17.697 B), `PqzBurnLib` (10.074 B) và `PqzStateLib`, cộng selector của view trên các token. Hàng token PQZ lớn nhất,
  `WrappedPqzRegulatedToken`, là 62.285 B, còn xa trần 131.072 B (CTR-GOV-19) [estimate].
- **Ví không có server:** để tự dựng `T` của một bên thứ ba, ví phải tải `Δp` mục. Thường là 1 đến 16 mục (13–213 KB ở
  `n2304-kmax4096`). Trường hợp xấu nhất là `K_MAX − 1` mục: 11 MB / 55 MB / 264 MB / 1,25 GB, so với 18,5 KB cho `T` trong
  một log. Bất kỳ indexer nào cũng có thể tính `T` một lần và phục vụ nó, và chứng minh sẽ kiểm, nên chỉ ví hoàn toàn không
  có server mới chịu trường hợp xấu nhất.

### 14.5 Đối chiếu với các quy tắc

- **Không bao giờ mất bản mã:** được củng cố. Bản mã vốn đã còn, vì blob không bao giờ bị xoá. Cái mất hôm nay là tổ hợp:
  bản mã nào đã tạo nên `T`, và các số tiền TRIVIAL. Hướng 2 giữ lại tổ hợp đó, nên mọi `T` mà một lần ghi nợ đã chứng minh
  trên đó đều là hàm của state.
- **Tham số tường minh:** không thêm entry point hay tham số nào. Bản ghi là lưu trữ nội bộ; view trả về các trường có tên.
- **Ghim bố cục:** hôm nay `scaas.pqz` (`PqzStorage`) không có trong `test/v2/layout/namespaces.json` [repo]. Thêm một mapping
  ở cuối không dời slot nào; nên ghim `scaas.pqz` trong cùng thay đổi. Typehash, `PqzAuth`, statement và `proofSystemId`
  không đổi, nên không cần vector quan hệ và không cần full gate. Chỉ cần vector mới cho bản ghi và phép dựng lại.
- **Bất biến:** một phiên bản catalogue mới cho các kind PQZ và các thư viện; không gì đã triển khai bị đổi. Mọi chain đều
  chỉ để thử nghiệm, nên không cần di chuyển dữ liệu.
- **Một quy tắc trên mọi chain:** token PQZ chỉ có trên EVM. Soroban không có (NET-SOR-26), và cây mã của các họ khác không có
  token PQZ nào [repo]. Nếu sau này xây ở đó, cùng quy tắc vẫn áp dụng (giữ các mục, mỗi lần ghi nợ một bản ghi), nhưng chi phí
  giữ state khác nhau [inference]: entry persistent của Soroban cần gia hạn TTL (entry bị lưu trữ có thể khôi phục), NEAR khoá
  số dư theo mỗi byte lưu (xoá thì được nhả lại), và box của Algorand nâng số dư tối thiểu.

### 14.6 Có bỏ được phụ thuộc lịch sử không? Không, chỉ phần của `T`

Chứng minh nằm trong calldata. Một `T` dựng từ state là thông tin công khai, vì ai cũng tính được. Cái chứng nhận một khoản
ghi có là chứng minh `P` được kiểm trên statement, nên một `T` chỉ từ state mà không có `P` thì không chứng nhận gì.
[inference]

- **Vẫn cần từ lịch sử:** chính giao dịch ghi nợ. Nó mang `P` và các từ header không có trong state: `beneficiary`, `fee`
  (op 7: `txFee + M·decoyFee`), `amount` và `recipient` (burn; chúng cũng phân biệt `opTag` của burn với refresh),
  `validUntilBlock`, và `envelopeBinding` (phong bì relay và chế độ). Mọi đầu vào khác của statement đều có trong state theo
  hướng 2: các từ định danh của header; `to` hoặc `recipientsHash`, `auditorOn` và `salt` từ blob; `memoHash` từ `memos`;
  `p` và `shieldIn` từ bản ghi; khoá từ registry; `out` từ blob; và `T` theo §14.2.
- **Giữ cả `P` trong state** [estimate]: op 1 có auditor cần thêm 65,8 / 71,8 / 77,6 / 84,5 M state gas, burn thêm
  64,5–83,2 M, op 7 M = 8 có auditor thêm 111,9–131,0 M, và một lần ghi nợ PQZH ≈ +385 M ở `n2304-kmax4096`. Khi đó một op 1
  cần `tx.gas` ≈ 92–125 M. Con số này vượt một block 60 M (mốc tham chiếu C0-10) và vượt `max_gas_per_tx` 64 M của node SCaaS
  testnet; với quy tắc "không giả định giới hạn block của ta" thì không thể dựa vào nó ở đâu cả. Nó còn cần 2 đến 4 mảnh code
  theo giới hạn công khai 24.576 B, và state mỗi lần ghi nợ tăng lên 2,8–3,9 lần blob hôm nay. **Không khả thi.** Lưu các từ
  header còn thiếu (khoảng sáu từ) mà không có `P` thì vô ích.
- **Kết luận:** hướng 2 chỉ bỏ được phụ thuộc lịch sử của `T`. Dự phòng §9 vẫn còn: (A) cho người giữ khoá đơn lẻ, còn với
  quorum thì dựng lại seed và xoay khoá. Quy tắc kho lưu của §9.3 cũng còn, nhưng thứ phải giữ thu hẹp lại thành giao dịch
  ghi nợ (calldata của nó), không cần receipt. Log `header ‖ T` không còn cần nữa; log chỉ header là một tiện ích, để mọi
  client khỏi phải tự dựng `envelopeBinding` từ giao dịch bên ngoài.
- **Cái nó thật sự mang lại:** (1) chi phí mỗi lần ghi nợ giảm từ 0,15–0,20 M xuống ≈ 0,10–0,11 M, như nhau ở mọi bộ; (2) `T`
  không phụ thuộc receipt lẫn node lưu state lưu trữ (biến thể không đổi gì của §5); (3) tổ hợp của mọi lần ghi nợ cũ nằm
  trong state, nên các từ tài khoản của §3.3 cho một lần ghi nợ cũ kiểm được với state; (4) bất kỳ server nào cũng phục vụ
  được `T`, và chứng minh sẽ kiểm nó.

### 14.7 Lưu giữ: ai giữ chứng minh (nhận xét của owner, 2026-11-06)

Nhận xét của owner: "bên ngoài sẽ không lưu các chứng minh". Coi điều đó là đã cho [inference trừ chỗ có thẻ khác]:

1. **Người giữ khoá thật sự cần gì.** Chỉ dữ liệu ghi nợ (giao dịch ghi nợ có `P`, cộng `T` hoặc bản ghi của nó) của các
   khoản ghi có kể từ lần ghi nợ cuối của chính mình, cùng với lần ghi nợ cuối đó. Một lần ghi nợ tiêu nhiều nhất
   `K_MAX − 2` mục; hàng đợi không giới hạn, nên mồi nhử vượt quá số đó thuộc về lần ghi nợ sau. Không cần gì cũ hơn: tổ hợp
   cũ chỉ quan trọng khi kiểm toán.
   - **Lần ghi nợ cuối của chính mình:** với op 1 và op 7, `v_f` được kiểm bằng phép kiểm mã hoá lại của §4 (i). Phép kiểm
     này cần seed, bộ đếm và salt từ blob, tất cả đều trong state, và không cần `P`. Với **burn hoặc refresh** thì không được:
     tính ngẫu nhiên của chúng là mới (CTR-PQZ-19), nên phép kiểm dựa trên chứng minh duy nhất là chính `P` của người giữ
     khoá. Ví đã tạo `P` và có thể giữ nó. Sau khi khôi phục mới từ seed, nếu lần ghi nợ cuối là burn hoặc refresh, người giữ
     khoá cần `P` đó từ lịch sử, hoặc phải quay về (A) [repo, §4].
   - **Một quorum MPC** không có seed, nên cần `P` cho lần ghi nợ cuối của chính nó, ở mọi loại (§4).
2. **Ai có lợi ích giữ nó.**
   - Ví người nhận: tải và kiểm khi nhận, rồi giữ dữ liệu (§9.3). Đây là bản chính, và không tốn gì trên chain.
   - Người gửi trao `P` cho người nhận qua một kênh kiểu memo: **owner đã loại (2026-11-06)**, vì không làm và không hợp lý.
     Hôm nay cũng không có kênh như vậy [repo]: sealed memo chỉ 41 B trên chain (CTR-PQZ-23).
   - Các node SCaaS vận hành: một quy tắc PLANNED trong spec node (§9.3). Node là mở, nên đây là bảo đảm của chính
     `scaas-node`, không phải của một bên tiêu thụ.
   - Các chain SCaaS vận hành (22776, SCaaS testnet): có thể cấu hình để giữ lịch sử. Node `rpc` của SCaaS testnet chạy archive
     cho state (NET-EVM-10) [repo]; giữ thân block và receipt cần một thiết lập riêng được ghi rõ, và với 22776 thì chỉ owner
     quyết. Chain của khách hàng do họ tự chọn.
3. **Mất dữ liệu thì mất gì:** chỉ mất đường chứng minh. Tiền vẫn tiêu được qua các phương án dự phòng: (A) cho người giữ khoá
   đơn lẻ; với quorum MPC thì dựng lại `seed32` theo k-of-n, rồi đến operator, rồi xoay khoá (quyết định của owner, §9.2).
4. **Trường hợp còn sót lại:** một ví ngoại tuyến lâu hơn cửa sổ lịch sử của một chain bên ngoài, và không kho lưu nào phục vụ
   giao dịch (không node SCaaS nào theo dõi chain đó, và chính chain đó cho lịch sử hết hạn). Trường hợp này như nhau ở cả hai
   dạng. Hướng 2 dựng lại `T` từ state, nhưng `P` và các từ header vẫn mất y như vậy, nên cả hai dạng đều kết thúc ở cùng phương
   án dự phòng.

**Điều này nghĩa là gì khi so hướng 2 với việc log `T`.** Lợi ích về tính sẵn có của hướng 2 là nhỏ. Với trường hợp đáng kể,
hoặc người nhận đã giữ dữ liệu khi nhận, hoặc chính chứng minh đã mất. Phần còn lại là chi phí (≈ 0,10–0,11 M so với
0,15–0,20 M mỗi lần ghi nợ), không phụ thuộc receipt, tổ hợp của mọi lần ghi nợ nằm trong state, và một indexer có thể phục vụ
`T` mà không cần đã theo dõi log. Đổi lại là +32 B vĩnh viễn cho mỗi khoản ghi có và mỗi lần ghi nợ, và việc đảo ngược một quy
tắc đã ghi.

### 14.8 Kết luận, công sức, câu hỏi cho owner

**Kết luận** [inference, UNAUDITED]. Hướng 2 đúng đắn và rẻ. `T` của mọi lần ghi nợ trở thành hàm của state nếu hợp đồng thôi
xoá các slot pending và ghi một bản ghi cho mỗi lần ghi nợ; `acc` vật chất hoá và các rollover không cần cho việc dựng lại. Nó
thay nửa `T` của log debit-T với khoảng hai phần ba chi phí, như nhau ở mọi bộ. Nó **không** bỏ được phụ thuộc lịch sử: chứng
minh và sáu từ header vẫn nằm trong calldata, và chứng minh không vừa trong state. Vì bên ngoài sẽ không lưu chứng minh
(§14.7), ở cả hai dạng tính sẵn có đều dựa vào việc người nhận giữ dữ liệu khi nhận, và ở cả hai dạng trường hợp còn sót lại
đều quay về (A) hoặc việc xoay khoá của §9.2. Vì vậy lựa chọn dựa trên chi phí và việc tổ hợp nằm trong state, không dựa trên
tính sẵn có. Đây là ưu tiên nhẹ, không phải quyết định dứt khoát. Dạng debit-T được khuyến nghị: **`T` từ state cộng log chỉ
header**, thay cho log `header ‖ T`. Log `header ‖ T` mà không tăng state vẫn là lựa chọn hợp lý nếu owner muốn giữ quy tắc xoá.

| Bước | Việc | Ngày-agent [estimate] |
|---|---|---|
| D2-1 | Hợp đồng: bỏ hai chỗ xoá, thêm bản ghi, view và log header. Test forge: `T` dựng từ state bằng `T` của statement sau các chuỗi ngẫu nhiên gồm khoản ghi có, shield (kể cả gộp cùng block), rollover, un-roll, op 1, op 7, burn, refresh và unwrap. Ghim `scaas.pqz`; size gate ở bốn bộ; ghim gas cũ → mới sau khi đo (theo lời owner) | 3–4 (thay cho R2 ở §12) |
| D2-2 | Vector: từ bản ghi và một hàng dựng lại, ở bộ mặc định và một bộ khác; phép dựng lại trong `ua-rs` và `ua-c` | +1–2 |
| D2-3 | Node: indexer tính `T` và phục vụ theo `entryRef`; thứ kho lưu phải giữ là giao dịch ghi nợ | +1 |
| D2-4 | Tài liệu: `pq-zero-knowledge.md` §7.1, §7.4, CTR-PQZ-07; một mục decisions đảo ngược việc xoá; các bản tiếng Việt | +1 |
| | **debit-T ở dạng này, tổng cộng** | **≈ 16–25** (so với 13–21 ở §12) |

**Câu hỏi cho owner**

1. **Giữ mọi slot pending vĩnh viễn** (+32 B cho mỗi khoản ghi có và mỗi lần ghi nợ), để mọi `T` là hàm của state? Việc này
   đảo ngược §5.5 của spec state. *Khuyến nghị:* có. Nó không tốn state gas (theo EIP-8037, việc xoá chưa bao giờ hoàn lại
   state gas) và giảm regular gas; nó cần một mục trong decisions.
2. **Header:** log header 640 byte (≈ 0,01 M), hay để mọi client tự dựng nó từ calldata của giao dịch, kể cả binding của phong
   bì relay? *Khuyến nghị:* log nó.
3. **Tính sẵn có của chứng minh:** chấp nhận rằng chứng minh ghi nợ ở lại trong lịch sử (trong state nó tốn ≈ 65–131 M mỗi
   lần ghi nợ PQZL và không vừa), nên dự phòng §9 và quy tắc kho lưu vẫn còn, với thứ kho lưu phải giữ thu hẹp thành các giao
   dịch ghi nợ? *Khuyến nghị:* có.

## 15. Nguồn

- Naor, Yung, "Public-key cryptosystems provably secure against chosen ciphertext attacks", STOC 1990 [paper].
- Sahai, "Non-malleable non-interactive zero knowledge and adaptive chosen-ciphertext security", FOCS 1999 [paper].
- Shoup, Gennaro, "Securing threshold cryptosystems against chosen ciphertext attack", EUROCRYPT 1998 [paper].
- Bernhard, Pereira, Warinschi, "How not to prove yourself: pitfalls of the Fiat–Shamir heuristic and applications to
  Helios", ASIACRYPT 2012 [paper].
- Fujisaki, Okamoto, "Secure integration of asymmetric and symmetric encryption schemes", CRYPTO 1999 [paper];
  Hofheinz, Hövelmanns, Kiltz, "A modular analysis of the Fujisaki–Okamoto transformation", TCC 2017 [paper].
- [EIP-4444](https://eips.ethereum.org/EIPS/eip-4444) (lịch sử hết hạn), [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825),
  [EIP-7976](https://eips.ethereum.org/EIPS/eip-7976), [EIP-8037](https://eips.ethereum.org/EIPS/eip-8037).
- Repository: [pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md) §4.3, §7, §9.3;
  `pqz-core/params/sets/README.md`; `pqz-core/nethermind/chain/engine-pqz-provisional-n*.json`;
  [pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md) §12; spec no-oracle và plan ua-rs-sign (T16a, T16b) trên
  nhánh `ua-rs-sign`; `docs/superpowers/specs/2026-11-06-pqz-key-versions.md`.
