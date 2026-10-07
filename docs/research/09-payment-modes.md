## 09. Payment API và 5+ chế độ tích hợp, chọn bằng cấu hình

### 09.0. Nguyên tắc và ranh giới

Kế thừa `dms/models/orders/dms_vietqr.py`: *"Quét QR không phải là đã thu tiền"*.
Bản dịch blockchain: **broadcast không phải là đã thanh toán; mined cũng chưa phải.**
`payment.transaction._set_done()` chỉ được gọi tại trạng thái `final` của Finality Gate (§05.8,
§10.4 của note). Mọi trạng thái trước đó là `_set_pending()`, kể cả khi ví của người trả đã hiện
"Success" và Metamask đã báo "Confirmed".

Ràng buộc #7 (standalone) khiến section này **không thể** là một addon. `payment` kéo theo
`onboarding` + `portal` (kiểm chứng: `odoo-src-19/addons/payment/__manifest__.py`, `depends:
['onboarding', 'portal']`); `account.payment` kéo theo `account`. Nếu core `dms_blockchain` depend
`payment`, thì một deployment chỉ muốn anchor hash cũng phải cài cả payment engine. Vì vậy chế độ
tích hợp không phải là một `Selection` trong một addon, mà là **một trục addon**:

| Addon | `depends` | Chứa gì | Chế độ mở khoá |
|---|---|---|---|
| `dms_blockchain` (core) | `base`, `web` | `blockchain.chain`, `blockchain.token`, `blockchain.payment.request`, `blockchain.payment.observation`, `blockchain.money.flow`, `blockchain.payment.quote`, watcher ingest, Finality Gate | M4, M12, M18 |
| `dms_blockchain_payment` | + `payment` | `payment.provider` `code='chain'`, `payment.transaction` overrides, `payment.method` data | M1, M6, M11 |
| `dms_blockchain_acquirer` | + `payment` | Adapter cho acquirer bên thứ ba (Coinbase Commerce / Triple-A / BitPay-class) | M2 |
| `dms_blockchain_account` | + `account` | `account.payment`, batch reconcile vào `account.move`, FX/impairment journal | M3, M4 (nửa kế toán), M15 |
| `dms_blockchain_mandate` | + `payment` | Allowance / ERC-2612 permit / session-key mandate, stream, escrow | M7, M8, M9, M10 |
| `dms_blockchain_dms` | + `dms`, `dms_blockchain` | Bridge tới `dms.payment.collection`, `dms.trade.settlement`, `dms.outlet.credit` | — |

Chế độ không cài = code không tồn tại. Đó là cơ chế open/closed tầng một; tầng hai ở §09.4.

Đường dẫn: `custom-addons/dms_blockchain*/`, `smartcontracts/` ở gốc repo theo quyết định #9.

> **[SỬA] Bẫy `auto_install` mà bản nháp bỏ qua.** `account_payment/__manifest__.py` khai
> `'auto_install': ['account']`. Nghĩa là: trên bất kỳ database nào đã cài `account`, việc cài
> `dms_blockchain_payment` (depend `payment`) sẽ **tự động** kéo `account_payment` vào. Ta không
> chọn được "M1 không kế toán" trên một DB có Accounting. Hệ quả bắt buộc:
> `account_payment._post_process()` sẽ chạy, sẽ gọi `_create_payment()`, và sẽ đọc
> `self.provider_id.journal_id`. Nếu journal chưa cấu hình, mọi giao dịch `done` sẽ ném exception
> **bên trong post-processing**, tức là tiền đã về chain, tx đã `done`, và Odoo im lặng fail ở cron.
> Vì vậy: `dms_blockchain_payment` phải có một preflight check chặn `state='enabled'` khi
> `journal_id` rỗng (§09.5).

> Bất nhất quán cần chốt: §05 đặt tên model `dms.blockchain.intent`, §01/§02/§06 đặt
> `blockchain.token` / `blockchain.relay.job`. Section này dùng tiền tố **`blockchain.`** (không
> `dms.`), theo đa số và theo §06.0 — vì addon standalone không được mang tên miền `dms` trong
> model name khi `dms` có thể không tồn tại.

> **[SỬA] Đặt tên số tiền.** §15 đã chốt hậu tố `_base` cho số nguyên đơn vị cơ sở lưu dạng `Char`
> (`total_base`, `delta_base`, `drift_base`). Section này đổi `amount_token_units` →
> **`amount_base`** để đồng bộ. Lý do kỹ thuật không đổi: `fields.Integer` của Odoo là `int64`,
> `1e18 × 1000` = `1e21` đã tràn từ lâu; `fields.Float` mất chính xác từ `2^53`. Áp thêm một
> constraint định dạng, vì `Char` không tự bảo vệ:
>
> ```python
> _amount_base_is_uint = models.Constraint(
>     "CHECK (amount_base ~ '^(0|[1-9][0-9]{0,77})$')",
>     'amount_base phai la so nguyen khong dau, toi da 78 chu so.')
> ```

> **[BẢN 2] Phạm vi của section này đã hẹp lại một cách có lợi.** `_USER-DECISIONS.md` §20 chốt
> factory mở: ta deploy protocol, không phát hành token. Nghĩa là phần lớn các chế độ dưới đây mô tả
> **bản triển khai DMS đóng vai người dùng của protocol**, không phải một tính năng của protocol.
> Cụ thể: `blockchain.token` mà `blockchain.money.flow` trỏ tới có thể là token **của người khác**
> (một zDAI-B nào đó), và điều đó hoàn toàn bình thường. Hệ quả thực tế nằm ở §09.4 (handler phải
> đọc `verifier()`/`version()` của token chứ không giả định) và §09.6 (reference phải chịu được một
> token không có event ta thiết kế).

---

### 09.0b. Những giả định bản nháp **không nói ra** (và hệ quả nếu sai)

| # | Giả định ngầm | Vì sao nó không hiển nhiên | Xử lý ở bản này |
|---|---|---|---|
| A1 | Một `payment.provider` phục vụ được nhiều chain × nhiều token | `account_payment` gắn **một** `journal_id` cho **một** provider. Nhiều token dưới một provider = tất cả tiền vào một journal, mất khả năng đối soát theo token | §09.5c: **một provider cho mỗi (company, chain, settlement token)**, hoặc override `_create_payment` |
| A2 | Tiền tệ của `payment.transaction` là tiền tệ của token | Không. `amount` là **fiat** (`res.currency`), on-chain là base units. Giữa hai cái có một **tỷ giá** và một **cửa sổ hiệu lực** | §09.7b: model `blockchain.payment.quote` |
| A3 | Watcher → cron → `_set_done` đủ nhanh cho `ENDUSER_PAY` | `ir.cron` có độ phân giải **1 phút**; cron post-process của Odoo mặc định **10 phút**. Độ trễ yêu cầu là **giây** | §09.5d: `cron._trigger()` + `_post_process()` gọi trực tiếp + bus notification |
| A4 | `_set_done` kéo theo `_post_process` | Không. `_post_process` chỉ chạy từ `/payment/status/poll` (người dùng mở trình duyệt) hoặc từ cron `payment.cron_post_process_payment_tx`. Người trả không bao giờ mở app ⇒ **không ai poll** | §09.5d |
| A5 | Handler interface public là an toàn | Method public trên một model Odoo **là RPC endpoint**. `on_final(request, observation)` public = bất kỳ user có ACL read cũng ép được một `_set_done` | §09.4: đổi thành `_on_final`, thêm facade public mỏng |
| A6 | Reference 40 bit là "gần đủ" | Sai số xác suất 3 bậc. Với 10^7 request, va chạm gần như **chắc chắn** | §09.6: tính lại, chốt 64 bit |
| A7 | Một mã QR EIP-681 quét được bằng mọi ví | Gần như không ví nào hỗ trợ gọi hàm tuỳ ý qua EIP-681; chỉ `transfer` của ERC-20 được hỗ trợ một phần | §09.6: R1 + WalletConnect, EIP-681 chỉ là tiện ích |
| A8 | Zether transfer ~200k gas | Sai 15–20 lần; §03.3.7 đã bắt được. Con số thật: **1,88 M** (32/64) | §09.9, §09.10 |
| A9 | Người trả luôn là một `res.partner` tồn tại | `payment.transaction.partner_id` **required**, `payment.token` cấm partner public | §09.8b: chính sách tạo partner từ ví |
| A10 | Expiry + `_set_canceled` là đủ để đóng một request | Tiền vẫn có thể về sau đó. Và nếu tx đã liên kết invoice, `account_payment._post_process` sẽ `payment_id.action_cancel()` | §09.7 |
| A11 | Reorg là trường hợp hiếm | Với `finality_mode='soft'` trên Gnosis (1 block) thì không | §09.7, có công thức tổn thất kỳ vọng |
| A12 | Một cron loop là đủ bền | `for obs in ...: _process(); commit()` — một observation lỗi làm chết cả vòng lặp ⇒ head-of-line blocking, hàng đợi đứng yên | §09.5d: try/except/rollback từng dòng |
| A13 | Trả thừa/thiếu là ngoại lệ | Với thanh toán từ ví tự do, trả thiếu do phí và làm tròn là **bình thường** | §09.7 bảng tolerance |
| A14 | Chi phí xây = số person-week | Thiếu chi phí vận hành: node/RPC, kiểm toán hợp đồng, giám sát 24/7, quỹ dự phòng reorg | §09.10c |
| A15 | **[BẢN 2]** Token mà ta nhận tiền là token của ta | Trên factory mở, không. Một `money.flow` hoàn toàn có thể trỏ tới một token do người lạ tạo, chạy một version ta chưa audit | §09.4: handler đọc `factory()`/`version()`/`verifier()` và từ chối token không đạt chính sách; §09.6: đừng giả định event schema |

---

### 09.1. Trục thứ hai: money-flow. Chế độ được chọn **theo từng dòng tiền**, không theo hệ thống

Quyết định #8 nói "combination per money-flow". Để làm được điều đó phải có danh sách dòng tiền
đồng nhất, đặt trong core:

| `flow_code` | Hướng | Đối tượng Odoo điển hình | Độ trễ chấp nhận được | Chế độ khả thi |
|---|---|---|---|---|
| `LOYALTY_ACCRUE` | issuer → outlet/consumer | không có (sub-ledger) | phút | M4, M12, M18 |
| `LOYALTY_REDEEM` | consumer → outlet | `sale.order` discount | giây | M4, M9, M18 |
| `B2B_PAYOUT` | brand → distributor | `dms.trade.settlement.payout_line_ids` | giờ | M3, M4, M9, M17 |
| `B2B_INVOICE_PAY` | distributor → brand | `account.move` (`out_invoice`) | giờ | M1, M6, M7, M15 |
| `OUTLET_COLLECT` | outlet → distributor | `dms.payment.collection` | phút | M0, M1, M6, M11 |
| `ENDUSER_PAY` | consumer → outlet | `pos.order` / `sale.order` | **giây** | M1, M11, M2, M14 |
| `RELAYER_FEE` | issuer → relayer | `account.move` (`in_invoice`), §05.8 | ngày | M4 |
| `REFUND` | ngược lại bất kỳ flow nào | `payment.transaction` con | giờ | M1 (có điều kiện), M3 |
| `ESCROW_MILESTONE` | brand → distributor theo mốc | `dms.trade.claim` | ngày | M9 |
| `SUBSCRIPTION` | distributor → brand định kỳ | `sale.subscription` | ngày | M7, M8, M10 |
| `FIAT_ONRAMP` | consumer/distributor → treasury (VND → token) | `account.payment` + `blockchain.settlement` | giờ | M16 |
| `FIAT_OFFRAMP` | treasury → ngân hàng (token → VND) | `account.payment` | ngày | M16 |

`ENDUSER_PAY` là dòng duy nhất có ràng buộc độ trễ **giây**, và đó là lý do kỹ thuật lớn nhất để
Gnosis/Celo đi trước: soft finality 5s. Trên Ethereum L1, `ENDUSER_PAY` với hard finality 12,8 phút
là không thể bán tại quầy — phải chấp nhận soft-final (§09.7) hoặc dùng M2.

#### Trục thứ ba mà bản nháp bỏ sót: `chain_profile`

Quyết định #5 đặt `public` vs `private` là một trục kiến trúc. §08.1 đã có
`blockchain.chain.chain_profile`. Trục đó **phải** đổi mặc định của lớp payment, không chỉ của lớp
adapter:

| Tham số | `chain_profile = 'public'` | `chain_profile = 'private'` | Lý do |
|---|---|---|---|
| `finality_mode` mặc định | `hard` | **`soft` — nhưng xem cảnh báo dưới** | Bản 1 viết "BFT instant = final ngay" |
| `confirm_depth` mặc định | theo `blockchain.chain.finality_depth` | **không phải `1`** | Xem cảnh báo dưới |
| `ref_mode` mặc định | `hash` | `plain` | Không có đối thủ đọc chain; debug dễ hơn nhiều |
| `receiving_mode` mặc định | `derived` (CREATE2) | `router` | Gas ~0, không cần tiết kiệm; router cho log giàu hơn |
| Kế toán phí gas | có dòng chi phí | **không có** (`MinGasPrice = 0`) | §08.1 `fee_token_mode='free'` |
| Zether khả thi cho `ENDUSER_PAY` | không (§09.9) | **có** | §09.9 |
| `soft_final_max_amount` | hữu hạn, xem §09.7 | **hữu hạn, không phải vô hạn** | Xem cảnh báo dưới |

> **[BẢN 2] Ba ô trong bảng trên dựa trên một giả định đã bị đo là sai.** Bản 1 giả định private
> chain là **BFT (QBFT/IBFT)**, nơi một block đã vote là final và không bao giờ reorg. Chain private
> thật là **Nethermind + Clique, một signer** (§01.1.16). Clique là proof-of-authority theo lượt,
> **không phải BFT**: nó không cho instant finality, và nó có thể reorg ngắn khi signer đổi lượt.
>
> Nghĩa là `confirm_depth = 1` và `soft_final_max_amount = ∞` là **chép từ một stack khác**. Phải
> đặt một `confirm_depth` bảo thủ có cơ sở đo được, và ghi rõ cơ sở đó. Với **một** signer thì thứ
> đảm bảo tính chung cuộc không phải giao thức mà là chính signer đó — điều này đúng, dùng được, và
> phải được gọi đúng tên trong tài liệu vận hành.

Ràng buộc bắt buộc, viết dưới dạng `@api.constrains`, không phải dưới dạng lời khuyên:
`payment.provider.state == 'enabled'` ⇒ mọi `chain_id` trong `chain_ids` phải có
`is_production = True`. Thiếu nó, một lần copy database staging sang production là đủ để nhận
tiền thật trên Chiado testnet (cảnh báo này lấy từ §08.1, áp dụng vào lớp payment).

---

### 09.2. Danh sách đầy đủ 20 chế độ

Đánh số M0..M19. **Không đổi số M1..M13** để các section khác còn tham chiếu được.

#### M0 — `payment_custom` (`code='custom'`, `custom_mode='wire_transfer'`), không viết dòng nào

Odoo 19 đã có sẵn addon `payment_custom`: người trả chuyển tiền ngoài hệ thống, Odoo đặt
`_set_pending()`, kế toán xác nhận tay. Đọc `payment_custom/models/payment_transaction.py`: nó
`return None` trong `_extract_amount_data` (bỏ qua kiểm tra số tiền) và `_set_pending()` trong
`_apply_updates` — **đúng y hệt cái ta cần làm với chain**, và đã chạy production trên hàng chục
nghìn DB.

Chạm: không gì, chỉ cấu hình + một dòng text trong `pending_msg` chứa địa chỉ ví.
Cost: **0,2 person-week** (chính là cấu hình + một `payment.method` icon).
Suits: `OUTLET_COLLECT`, `B2B_INVOICE_PAY` giai đoạn pilot.
Failure mode: không có đối soát tự động; khối lượng > ~50 giao dịch/ngày là không thể làm tay.
**Đây là đường lui bắt buộc phải giữ**: nếu watcher chết 6 tiếng, vẫn thu được tiền. Và nó là
đường ngắn nhất để chạy pilot trước khi M1 xong.

Còn một lý do thứ hai để đọc `payment_custom` trước khi viết M1: method `_get_communication()`.
Nó là **hook sẵn có** của Odoo cho "chuỗi mã mà người trả phải ghi kèm" (ưu tiên
`invoice_ids[0].payment_reference`, rồi `sale_order_ids[0].reference`, rồi `tx.reference`). Scheme
memo ở §09.6 phải **mở rộng** method này chứ không dùng một tên khác.

#### M1 — In-house `payment.provider` với `code='chain'`

Chain là lớp reconciliation; Odoo là người phát hành payment request và người quyết định khi nào
tiền được coi là thu. Chạm: `payment.provider`, `payment.transaction`, `payment.method`,
`account.payment` (qua `account_payment`, **bắt buộc** nếu DB có `account` — xem §09.0),
`sale.order`/`account.move` qua portal.
Cost: ~5–7 person-week (§09.10). Chi tiết ở §09.5.
Failure mode: reorg sau `_set_done` (giải ở §09.7); `_validate_amount` hạ gục mọi giao dịch
Zether (§09.9); `partner_id` là `required` nên người trả là khách vãng lai phải có partner
placeholder (§09.8b); một provider = một journal (A1).

#### M2 — Acquirer crypto bên thứ ba

Acquirer nhận crypto, chịu biến động giá, trả fiat về tài khoản ngân hàng. Odoo chỉ thấy một
`payment.provider` HTTP bình thường + webhook. Chạm: `payment.provider`, `payment.transaction`,
không chạm chain.
Cost: ~2 person-week. Rẻ nhất và là con đường đúng cho `ENDUSER_PAY` giai đoạn đầu.
Phí thực tế: **0,5–1,0%** trên doanh số (cơ sở: biểu phí công khai của nhóm Coinbase
Commerce/BitPay/Triple-A, ước tính 2026). So sánh: chi phí on-chain tự chạy trên Gnosis là
~$0,0002/giao dịch, tức **dưới 0,01%** ở giá trị đơn $5. Ngưỡng hoà vốn: nếu doanh số crypto
> ~$300k/năm thì 1% phí acquirer (= $3.000/năm) đã vượt chi phí vận hành một watcher + RPC
(ước ~$1.500–3.000/năm, §09.10c). Dưới ngưỡng đó, M2 rẻ hơn thật.
Failure mode: **không còn là blockchain project** — mất quyền kiểm soát token, không dùng được
Zether, không dùng được EIP-1776, không chạy được trên private chain. Chỉ hợp khi mục tiêu là nhận
tiền, không phải xây hạ tầng.

#### M3 — `account.payment` trực tiếp, bỏ qua module `payment`

Watcher thấy transfer → tạo thẳng `account.payment` (`payment_type='inbound'`,
`partner_type='customer'`) và `action_post()`, reconcile với `account.move.line`.
Chạm: `account.payment`, `account.journal` (một journal riêng cho mỗi chain × token),
`account.payment.method.line`, `account.move`.
Cost: ~3 person-week.
Suits: `B2B_PAYOUT`, `REFUND`, `FIAT_OFFRAMP` — nơi không có checkout UI, không có portal,
không cần token/redirect.
Failure mode: mất toàn bộ state machine của `payment.transaction` (pending/error/expiry), phải tự
viết lại; không có refund tree; không có idempotency sẵn — phải tự thêm constraint. Và: một
`account.payment` đã `posted` không xoá được, chỉ `action_draft` + reverse — nên một observation
bị reorg sau khi post là một bút toán điều chỉnh, không phải một delete.

#### M4 — Sub-ledger độc lập, đối soát theo lô

`blockchain.payment.entry` là một sub-ledger riêng (dòng tiền theo base units, không theo
`res.currency`), chạy độc lập, định kỳ sinh **một** `account.move` tổng hợp theo (chain, token,
ngày) thay vì một move mỗi transfer.
Chạm: không gì cả trong core; `dms_blockchain_account` sinh `account.move`; đối soát dùng
`blockchain.reconciliation.run` của §15.
Cost: ~4 person-week core + 2 cho bridge kế toán.
Suits: `LOYALTY_ACCRUE`/`LOYALTY_REDEEM` (khối lượng cao, giá trị đơn vị nhỏ), `RELAYER_FEE`,
**và mọi thứ Zether** (§09.9).
Failure mode: đối soát lệch thì phát hiện chậm (theo lô, không theo giao dịch); cần một
`blockchain.reconciliation.run` có trạng thái `clean`/`drift` và một ngưỡng drift chặn việc
posting move.

**[SỬA] Định lượng storage.** Bản nháp viết "400 B/dòng ⇒ 330 MB/năm" — sai hai lần: (a) bỏ qua
index, (b) tính nhầm tháng thành năm. Cơ sở đúng, lấy từ §11.9 (dòng effect ≈ 400 B payload,
**≈ 800 B thực tế** kể cả overhead dòng Postgres và 3 index):

| Kịch bản | Dòng/tháng | Postgres/tháng | Postgres/năm |
|---|---|---|---|
| Sub-ledger M4, 200k outlet × 4 giao dịch/tháng | 800.000 | **640 MB** | **7,7 GB** |
| Nếu sinh `account.move` 1-1 (move + 2 line + index ≈ 2,5 KB) | 800.000 move | **2,0 GB** | **24 GB** |
| M4 + một move tổng hợp/ngày/token (2 token) | 60 move | ~0,2 MB | ~2 MB |

24 GB/năm `account.move` là không chấp nhận được — không phải vì dung lượng mà vì **mọi báo cáo
kế toán đều quét bảng đó**. Đó là lý do M4 tồn tại, và lập luận đó bây giờ có con số.

#### M5 — Kết hợp theo từng dòng tiền

Không phải một chế độ; là **chế độ mặc định của hệ thống**. Bảng ở §09.1 chính là cấu hình. Cơ chế
kỹ thuật ở §09.4.

#### M6 — "Pay by link" mang reference on-chain

Odoo gửi link portal; trang portal hiện địa chỉ nhận + `ref` + QR EIP-681 + nút WalletConnect.
Người trả có thể trả từ ví bất kỳ, kể cả không mở link. Chạm: `payment.transaction` (M1) +
`payment.link.wizard` (`wizards/payment_link_wizard.py`, đã có sẵn — chỉ cần override
`_prepare_query_params`) + `portal` template.
Cost: +1 person-week trên M1.
Failure mode: người dùng copy địa chỉ mà bỏ `ref` → observation `unmatched` (§09.8). Tỷ lệ này
thực tế không nhỏ; đó là lý do R1 (địa chỉ riêng mỗi request) được ưu tiên hơn memo (§09.6).

#### M7 — Pull payment qua `approve` / ERC-2612 `permit`

Người trả ký `permit(owner, spender, value, deadline, v, r, s)` off-chain (không tốn gas), backend
gọi `transferFrom` khi đến hạn. Chạm: `payment.token` (lưu allowance như một token),
`payment.transaction` với `operation='offline'`, `_send_payment_request()`.
Cost: ~3 person-week trên M1.
Suits: `B2B_INVOICE_PAY`, `SUBSCRIPTION`.
Ánh xạ đẹp nhất trong cả section: **`approve`/`permit` = `_set_authorized()`, `transferFrom` =
capture, `_set_done()`**. Đây là trường hợp duy nhất manual capture có nghĩa trên chain.
Failure mode: USDT mainnet **không** có `permit` (và còn có quirk `approve` phải về 0 trước) → phải
fallback Permit2 hoặc `approve` thường. Allowance có thể bị thu hồi bất kỳ lúc nào và không có
thông báo → trước mỗi capture bắt buộc đọc `allowance()` và `balanceOf()`, không tin state cũ.
Thêm một ràng buộc Odoo mà bản nháp bỏ qua: `payment.token._check_partner_is_never_public` cấm gắn
token cho partner public ⇒ M7 không dùng được cho khách vãng lai, chỉ cho đối tác đã định danh.
Và `payment.token.provider_ref` là `required` — ở đây nó là `keccak(owner ++ spender ++ token)`,
không phải địa chỉ ví trần.

**[BẢN 2] Một cái bẫy mới của factory mở ở đúng chế độ này.** M7 đọc `permit` từ token — nhưng trên
factory mở, một token có thể là bất kỳ implementation nào. Nó có thể không có `permit`, có `permit`
với semantics khác, hoặc có một `permit` **cố tình** trả về thành công mà không set allowance.
Trước khi bật M7 cho một token, bắt buộc: đọc `factory()` và `version()`, đối chiếu với catalogue,
và chạy một `permit` thử với `value = 1` rồi kiểm `allowance()` thật sự tăng. Đây không phải sự
hoang tưởng — nó là hệ quả trực tiếp của việc nhận tiền bằng token người khác tạo.

#### M8 — Streaming / subscription

Hợp đồng stream tuyến tính (Sablier/Superfluid-class, hoặc một `LinearStream.sol` ~200 dòng tự
viết). Chạm: sub-ledger M4 + `sale.subscription`.
Cost: ~4 person-week kể cả contract.
Failure mode: không khớp mô hình kỳ kế toán Odoo (doanh thu chảy liên tục, invoice chạy theo
tháng) → bắt buộc phải có một bước "chốt kỳ" đọc `streamedAmount(t)` tại `t = kỳ kết thúc`. Nếu
người trả huỷ stream giữa kỳ, số tiền chốt < invoice → phát sinh công nợ, không phải lỗi thanh toán.
Định lượng: một stream chỉ là 2 giao dịch on-chain (`create`, `withdraw`) cho cả kỳ, so với 1
giao dịch/tháng của M7 — **stream chỉ rẻ hơn khi tần suất thu > 1 lần/tháng**. Dưới đó nó chỉ là
độ phức tạp không trả tiền.

#### M9 — Escrow giải ngân theo mốc

Tiền khoá trong hợp đồng, giải ngân khi arbiter/oracle xác nhận mốc. Chạm: `dms.trade.claim`
(qua bridge), `blockchain.escrow.deal` + `.milestone`.
Cost: ~5 person-week (contract + audit chiếm phần lớn).
Suits: `B2B_PAYOUT`, `ESCROW_MILESTONE`, `LOYALTY_REDEEM` có điều kiện.
Failure mode: arbiter là một single point of trust — nếu là một khoá của chính doanh nghiệp thì
escrow không còn ý nghĩa trustless, chỉ còn là một cái khoá thời gian. Nói thẳng điều đó trong
spec thay vì bán nó như decentralization. Rủi ro thứ hai, nghiêm trọng hơn: **tiền nằm trong hợp
đồng là tiền mất nếu hợp đồng có bug**. Escrow là chế độ duy nhất trong danh sách này giữ số dư,
nên nó là chế độ duy nhất **bắt buộc** audit bên ngoài trước khi bật.

Với contract bất biến (§01.1.3), câu cuối nặng thêm một bậc: một bug trong escrow **không vá được**,
và tiền đang nằm trong đó. Đường duy nhất là một escrow v2 cộng một cuộc di cư — mà tiền đang bị
khoá thì di cư bằng gì? Kết luận thực dụng: escrow phải có một **lối thoát khẩn cấp có thời hạn**
(sau `T` không ai giải ngân thì người gửi rút lại được), và `T` đó là một cam kết với đối tác chứ
không phải một tham số kỹ thuật.

#### M10 — Mandate uỷ quyền trước (kiểu direct debit)

Session key / smart account với hạn mức và thời hạn (§10.3 note: 1–8 giờ; với mandate B2B phải là
30–90 ngày + `daily_cap`). EIP-7702 hoặc smart account cho phép uỷ quyền một `spender` với scope
hẹp. Chạm: `payment.token` (mandate lưu như token), `blockchain.mandate`.
Cost: ~4 person-week.
Failure mode: khác biệt pháp lý với direct debit ngân hàng — **không có quyền đòi lại tiền
(chargeback)**. Nếu bán mandate cho người tiêu dùng mà không nói rõ điều đó, đây là rủi ro tuân thủ,
không phải rủi ro kỹ thuật. Hạn chế mandate cho `B2B_*`.

#### M11 — QR payment request mang URI EIP-681

QR chứa `ethereum:<token>@<chainId>/transfer?address=<to>&uint256=<amount>`. Chạm: portal/POS view.
Cost: ~0,5 person-week (EIP-681 là text thuần, không CRC — không tái sử dụng được `_emv` của
VietQR ngoài phần render QR).
Suits: `ENDUSER_PAY`, `OUTLET_COLLECT`.
**[SỬA] Failure mode nặng hơn bản nháp viết.** Bản nháp đề xuất
`ethereum:<router>@100/pay?address=...&uint256=...&bytes32=<ref>`. Trong thực tế, **hỗ trợ EIP-681
cho lời gọi hàm tuỳ ý gần như bằng không**: các ví di động phổ biến chỉ nhận dạng được dạng
`transfer` của ERC-20 (và nhiều ví còn bỏ qua cả `uint256`, chỉ lấy địa chỉ). Một QR gọi
`pay(...)` với tham số `bytes32` sẽ không quét được ở hầu hết ví. Hệ quả thiết kế: **QR chỉ được
trỏ tới địa chỉ R1 (derived) với hàm `transfer`** — đó là dạng duy nhất có cơ hội hoạt động. Cho
những ví không đọc được URI, luôn hiện thêm địa chỉ + số tiền dạng text để người dùng tự nhập, và
một nút **WalletConnect v2** (pairing URI) — đây mới là đường đáng tin cậy cho ví di động.
`chainId`: Gnosis = 100, Celo = 42220.
Và: quét QR không phải là đã thu tiền.

#### M12 — Anchor-only (chain là bằng chứng, tiền đi đường fiat)

Không có đồng tiền nào trên chain. Chỉ hash của chứng từ được neo (Hedera HCS hoặc một
`AnchorRegistry.sol`). Chạm: `blockchain.anchor`.
Cost: ~1 person-week.
Suits: `LOYALTY_ACCRUE` giai đoạn đầu, audit trail cho `dms.trade.settlement`.
Đáng được gọi tên vì đây thường là câu trả lời đúng cho loyalty: điểm thưởng không cần là token
cho tới khi nó cần chuyển nhượng được giữa các chủ thể độc lập. Nếu điểm chỉ tiêu trong hệ sinh
thái của chính issuer, một token ERC-20 không thêm giá trị gì ngoài chi phí.

#### M13 — Zether confidential settlement

Như M4 nhưng số tiền không đọc được từ chain. Xem §09.9. Đây không phải biến thể của M1.

#### M14 — Nhận token bất kỳ, tự quy đổi về token ngân quỹ (auto-convert at receipt)

Người trả gửi USDT, treasury muốn USDC. Một `PaymentRouter.payAndSwap(tokenIn, amountIn, minOut,
ref)` gọi DEX (Curve/Balancer trên Gnosis) trong cùng transaction.
Chạm: `blockchain.token` (danh sách token chấp nhận), router contract.
Cost: ~3 person-week + audit router.
Suits: `ENDUSER_PAY` trên public chain.
Failure mode: (a) **slippage làm số tiền nhận được khác số tiền trả** ⇒ `_validate_amount` sẽ
`_set_error` nếu ta so sánh `amountOut`; phải so sánh `amountIn` và ghi slippage như một khoản chi
phí tài chính. (b) MEV sandwich: `minOut` phải được đặt, và trên một public mempool nó vẫn bị
sandwich trong biên `minOut`. (c) Thanh khoản mỏng trên chain nhỏ là rủi ro thật: một swap $50k
trên một pool $500k ăn ~1–2% slippage. Kết luận: M14 chỉ bật khi giá trị giao dịch nhỏ
(< ~$1.000/tx) hoặc trên private chain có AMM nội bộ.

#### M15 — Bù trừ song phương, chỉ thanh toán phần ròng (netting)

Brand và distributor phát sinh công nợ hai chiều (invoice bán hàng vs. trade claim/rebate). Thay vì
N giao dịch, tính vị thế ròng theo kỳ và chỉ chuyển phần chênh lệch.
Chạm: `dms.trade.settlement`, `account.move` (bù trừ công nợ), `blockchain.settlement.batch` (§15).
Cost: ~3 person-week (logic netting) + 0 contract (chỉ là một transfer).
Suits: `B2B_INVOICE_PAY` + `B2B_PAYOUT` **cùng một đối tác**.
Định lượng: với 500 distributor × 20 chứng từ/tháng mỗi chiều, netting theo tháng giảm từ
**20.000 giao dịch** xuống **500 giao dịch**/tháng — giảm 97,5% cả gas lẫn số dòng sub-ledger. Đây
là đòn bẩy lớn nhất trong cả danh sách, và nó không cần thêm một dòng Solidity nào.
Failure mode: netting là một **thoả thuận pháp lý**, không phải một tính năng phần mềm. Phải có
điều khoản bù trừ trong hợp đồng; nếu không, một bên phá sản thì phần bù trừ có thể bị toà lật
lại. Và nó làm mờ dấu vết từng hoá đơn ⇒ bắt buộc lưu bảng kê netting như chứng từ.

#### M16 — Cầu fiat on/off-ramp (VND ↔ stablecoin)

Outlet thu tiền mặt VND; treasury muốn token. Hoặc ngược lại. Một đối tác được cấp phép thực hiện
quy đổi; Odoo ghi nhận hai chân: chân fiat (`account.payment` / `dms.cash.handover`) và chân chain
(`blockchain.settlement`).
Chạm: `dms.payment.collection`, `dms.bank.reconciliation`, `account.payment`, `blockchain.token`.
Cost: ~4 person-week + thời gian pháp lý (không ước lượng được bằng person-week).
Suits: `FIAT_ONRAMP`, `FIAT_OFFRAMP`, và **thực tế là điều kiện cần** cho `OUTLET_COLLECT` tại
Việt Nam, nơi tiền mặt vẫn chiếm phần lớn.
Failure mode: đây là chỗ toàn bộ kiến trúc chạm vào quy định pháp lý VN (§13). Không có đối tác
hợp pháp = không có off-ramp = token bị kẹt trong hệ sinh thái. **Đây là rủi ro nghiêm trọng nhất
của cả dự án, và nó không phải rủi ro kỹ thuật.** Ghi vào roadmap như một cổng (gate), không phải
một task.

#### M17 — Giải ngân theo lô bằng multicall (Disperse-style)

Một transaction chuyển cho N người nhận.
Chạm: `blockchain.settlement.batch` (§15 đã có `chunk_size = 150`), `dms.trade.settlement`.
Cost: ~1 person-week (contract ~60 dòng) + audit nhẹ.
Suits: `B2B_PAYOUT`, `LOYALTY_ACCRUE`.
Định lượng (cơ sở: base tx 21.000 + ~30.000/`transfer` warm, EIP-1108/EIP-2929):

| N người nhận | N tx riêng | 1 tx batch | Tiết kiệm |
|---|---|---|---|
| 10 | 10 × 51.000 = 510.000 | 21.000 + 10 × 30.000 = 321.000 | 37% |
| 150 | 7.650.000 | 4.521.000 | 41% |

Tiết kiệm gas chỉ ~40%, không ngoạn mục. Nhưng tiết kiệm **nonce management, số lần retry, và số
dòng log** thì lớn hơn nhiều — đó mới là lý do dùng nó. Failure mode: một người nhận là contract
revert làm hỏng cả lô ⇒ phải `try/catch` từng transfer trong contract và phát event thất/bại theo
từng dòng, hoặc dùng `atomicity='chunked'` của §15.

Với pool khoá (`_USER-DECISIONS.md` §21.5), câu "tiết kiệm nonce management" nhẹ đi một bậc: nhiều
khoá cũng giải được cùng vấn đề, theo một cách khác. Hai cơ chế cộng dồn được — batch 150 người
nhận trên mỗi khoá của một pool 10 khoá là 1.500 người nhận song song — và đó là hình dạng đúng cho
`LOYALTY_ACCRUE` quy mô lớn.

#### M18 — Voucher ký off-chain (bearer claim)

Issuer ký một phiếu `(recipient, amount, nonce, expiry)` bằng EIP-712; người nhận tự `claim()` khi
muốn. Không tốn gas cho issuer cho tới khi có người claim, và phiếu không bao giờ claim thì không
tốn gì.
Chạm: `blockchain.voucher` (core, không cần `payment`), `AnchorRegistry`/`VoucherClaim.sol`.
Cost: ~2 person-week.
Suits: `LOYALTY_ACCRUE` (phát 200k phiếu, thực tế ~5–15% được claim ⇒ tiết kiệm 85–95% gas so với
mint trước), `LOYALTY_REDEEM`.
Failure mode: phiếu là **bearer instrument** — ai có chữ ký thì claim được nếu contract không ràng
buộc `recipient`. Phải ràng buộc. Và kế toán: một phiếu đã phát nhưng chưa claim là một **khoản
phải trả tiềm tàng**, phải trích trước, không được để ngoài sổ. Ngược lại với trực giác, chế độ "rẻ
nhất về gas" lại là chế độ **khó nhất về kế toán**.

#### M19 — Payment channel / state channel

Được gọi tên để **bác bỏ**. Hai bên mở kênh, giao dịch off-chain không giới hạn, đóng kênh một lần.
Lý do bác bỏ: chi phí giao dịch trên Gnosis đã là $0,0002; kênh giải quyết một vấn đề (phí giao
dịch cao) mà ta không có, đổi lấy một vấn đề ta không muốn (watchtower, thời hạn thách thức, vốn
bị khoá). M15 (netting) đạt được 97% lợi ích với 5% độ phức tạp. **Không xây.**

---

### 09.3. Bảng so sánh nén

| | Chi phí xây | Độ trễ đến `done` | Chargeback | Chạy trên private chain | Hỗ trợ Zether | Cần contract mới |
|---|---|---|---|---|---|---|
| M0 | 0,2 pw | thủ công | không | có | n/a | không |
| M1 | 5–7 pw | finality gate | không | có | không (xem M13) | không |
| M2 | 2 pw | acquirer quyết định | có (acquirer chịu) | không | không | không |
| M3 | 3 pw | finality gate | không | có | một phần | không |
| M4 | 4+2 pw | theo lô | không | có | có | không |
| M6 | +1 pw | như M1 | không | có | không | không |
| M7 | +3 pw | finality gate | không | có | không | không (Permit2 nếu cần) |
| M8 | 4 pw | chốt kỳ | không | có | không | **có** |
| M9 | 5 pw | khi giải ngân | một phần (arbiter) | có | phức tạp | **có, phải audit** |
| M10 | 4 pw | như M7 | không | có | không | **có** (smart account) |
| M11 | 0,5 pw | như M1 | không | có | không | không |
| M12 | 1 pw | n/a | n/a | có | n/a | có (nhẹ) |
| M13 | 6 pw | epoch + finality | không | **có, ưu tiên** | có | **có, phải audit** |
| M14 | 3 pw | như M1 | không | có (nếu có AMM) | không | **có** |
| M15 | 3 pw | theo kỳ | không | có | có | không |
| M16 | 4 pw + pháp lý | ngày (T+1) | theo đối tác | không liên quan | không liên quan | không |
| M17 | 1 pw | finality gate | không | có | không | **có** (nhẹ) |
| M18 | 2 pw | khi claim | không | có | không | **có** |
| M19 | — | — | — | — | — | **không xây** |

**[BẢN 2] Cột "cần contract mới" đọc khác đi trên factory mở.** Trước đây "cần contract mới" nghĩa
là "ta phải viết, audit và deploy". Bây giờ nó có thể nghĩa là "chọn một version trong catalogue" —
nếu ai đó đã đăng ký một `MigrationSink`, một `LinearStream` hay một `VoucherClaim` phù hợp, ta chỉ
cần trỏ tới nó. Đổi lại: **ta phải kiểm ai viết nó và nó đã audit chưa** (`factory()`, `version()`,
`implCodeHash` — §01.1.5). Cột này vì thế nên đọc là "cần một contract mà ta chưa có", không phải
"cần một dự án Solidity".

Ngoại lệ giữ nguyên: M9 (escrow) giữ tiền, nên nó **luôn** cần audit bất kể ai viết. Không có
catalogue nào thay thế được điều đó.

---

### 09.4. Cơ chế cấu hình: `blockchain.money.flow` + handler registry

Note gốc không nói gì về việc chọn chế độ. Đây là đề xuất cụ thể.

**Một record cho một (company, flow_code, chain).** Fallback: `company_id = False` là mặc định
toàn hệ thống. Độ phân giải: `(company, flow, chain)` → `(company, flow, False)` →
`(False, flow, False)` → `UserError`. Không bao giờ fallback im lặng về một handler tuỳ ý.

```python
class BlockchainMoneyFlow(models.Model):
    _name = 'blockchain.money.flow'
    _description = 'Money flow to payment-integration handler binding'
    _inherit = ['mail.thread']          # doi handler la mot su kien phai co vet

    company_id   = fields.Many2one('res.company', index=True)          # False = default
    flow_code    = fields.Selection(
        selection=[
            ('LOYALTY_ACCRUE', "Loyalty accrual"), ('LOYALTY_REDEEM', "Loyalty redemption"),
            ('B2B_PAYOUT', "B2B payout"), ('B2B_INVOICE_PAY', "B2B invoice payment"),
            ('OUTLET_COLLECT', "Outlet collection"), ('ENDUSER_PAY', "End-user payment"),
            ('RELAYER_FEE', "Relayer fee"), ('REFUND', "Refund"),
            ('ESCROW_MILESTONE', "Escrow milestone"), ('SUBSCRIPTION', "Subscription"),
            ('FIAT_ONRAMP', "Fiat on-ramp"), ('FIAT_OFFRAMP', "Fiat off-ramp"),
        ], required=True, index=True, tracking=True)
    chain_id     = fields.Many2one('blockchain.chain', index='btree_not_null')
    token_id     = fields.Many2one('blockchain.token', index='btree_not_null')   # [BAN 2]
    handler_code = fields.Selection(
        selection=[('none', "Not configured")], required=True, default='none', tracking=True,
        help="Extended by each bridge addon via selection_add.")
    handler_config_ref = fields.Many2oneReference(model_field='handler_config_model')
    handler_config_model = fields.Char()
    active       = fields.Boolean(default=True)

    _unique_binding = models.Constraint(
        'UNIQUE(company_id, flow_code, chain_id)',
        'Mot dong tien chi duoc gan mot handler tren mot chain trong mot company.')
```

**[BẢN 2] `token_id` là trường mới, và nó là hệ quả trực tiếp của factory mở.** Trước đây "chain +
flow" là đủ để xác định handler, vì token là của ta và chỉ có một. Bây giờ trên cùng một chain có
thể có zDAI-A và zDAI-B, và ta hoàn toàn có thể chấp nhận cái này mà không chấp nhận cái kia. Handler
phải biết nó đang xử lý token nào.

Kèm theo một luật bắt buộc mà §09.0b A15 đã báo: **trước khi kích hoạt một `money.flow` trỏ tới một
token, hệ thống phải kiểm xuất xứ** — `token.factory()` khớp factory đã biết, `token.version()` nằm
trong danh sách version ta chấp nhận, và với Zether thì `token.verifier()` là verifier đã audit. Ba
lời gọi `eth_call`, chạy một lần lúc cấu hình, và ghi kết quả vào record. Không có bước này, "nhận
tiền bằng token của người lạ" nghĩa là tin một implementation chưa ai đọc.

dùng method-based selection; nhưng `selection_add` (cơ chế để bridge addon thêm flow riêng của
`dms`) **chỉ hoạt động khi base là một list**. Đổi lại, và thêm `ondelete` ở phía bridge:

```python
# trong dms_blockchain_dms
flow_code = fields.Selection(
    selection_add=[('DMS_OUTLET_CREDIT', "Outlet credit repayment")],
    ondelete={'DMS_OUTLET_CREDIT': 'set default'})
```

**[SỬA] `provider_id` không thể nằm trong core** (comodel `payment.provider` chưa tồn tại) — bản
nháp đề xuất `fields.Reference`. Dùng được, nhưng §15 đã chốt idiom khác cho đúng vấn đề này:
`fields.Many2oneReference(model_field='...')`. Dùng theo §15 để cả bộ tài liệu một kiểu. Khác biệt
thực tế: `Reference` lưu `'model,id'` trong một `Char` và cho phép widget chọn model;
`Many2oneReference` lưu `Integer` + một `Char` model riêng, index tốt hơn và không cần `selection`.
Ở đây ta biết model từ `handler_code` nên không cần widget chọn — `Many2oneReference` là lựa chọn
đúng.

#### 09.4a. Dispatch không có `if` — và lỗ hổng RPC của bản nháp

```python
def _get_handler(self):
    self.ensure_one()
    model = 'blockchain.payment.handler.%s' % self.handler_code
    if model not in self.env:                      # module bi go sau khi da cau hinh
        raise UserError(_("Handler %s khong con duoc cai dat.", self.handler_code))
    return self.env[model].with_context(money_flow_id=self.id)
```

> **[SỬA] `with_context(flow=self)` của bản nháp là một bug.** Context bị serialize (đi qua
> `call_kw`, lưu vào `ir.cron`, cho vào `queue_job`); một recordset trong context không serialize
> được và sẽ hỏng ngay khi handler gọi một method chạy ở cursor khác. Truyền **id**, đọc lại trong
> handler.

**Lỗ hổng bảo mật trong interface của bản nháp.** Bản nháp đặt tên method là `open_request`,
`on_observation`, `on_final`, `on_reorg`, `on_expire`. Theo CLAUDE.md §6, **mọi method public trên
một model Odoo là một RPC endpoint**: bất kỳ user nào có ACL read trên model handler đều gọi được
`POST /json/2/blockchain.payment.handler.chain_provider/on_final` và **ép một `_set_done`**. Đó là
đường ngắn nhất tới việc ai đó tự xác nhận đã trả tiền cho hoá đơn của chính họ. Interface phải
private:

```python
class BlockchainPaymentHandler(models.AbstractModel):
    _name = 'blockchain.payment.handler'
    _description = 'Payment integration handler interface (private, not RPC-reachable)'

    def _open_request(self, flow, amount_base, token, origin_model, origin_res_id,
                      origin_ref, partner_id=None, expiry_minutes=None):
        """Tao yeu cau thanh toan. Tra ve blockchain.payment.request.
           Idempotent theo (company_id, origin_model, origin_ref)."""
        raise NotImplementedError

    def _on_observation(self, request, observation):
        """Watcher thay mot transfer khop. observation.obs_state con la 'mined'."""
        raise NotImplementedError

    def _on_final(self, request, observation):
        """Da qua Finality Gate. Day la NOI DUY NHAT duoc phep bao 'da thu tien'."""
        raise NotImplementedError

    def _on_reorg(self, request, observation):
        """observation da final bi day nguoc. Bat buoc hien thuc, khong duoc pass."""
        raise NotImplementedError

    def _on_expire(self, request):
        raise NotImplementedError
```

Và **một** entry point public duy nhất, mỏng, trên `blockchain.payment.request` — theo mẫu CLAUDE.md
§6 (public facade + private logic), phục vụ cả `call_kw` lẫn `/json/2`:

```python
@api.model
def payment_request_open(self, flow_code, amount_base, token_caip19,
                         origin_model, origin_ref, partner_id=None,
                         chain_caip2=None, expiry_minutes=None):
    """POST /web/dataset/call_kw/blockchain.payment.request/payment_request_open
       POST /json/2/blockchain.payment.request/payment_request_open

    KHONG nhan company_id, KHONG nhan allowed_company_ids tu client:
    company suy ra tu self.env.company (da duoc server giao voi assignment cua user).
    """
    self.check_access('create')
    flow = self.env['blockchain.money.flow']._resolve(self.env.company, flow_code, chain_caip2)
    return self._request_open_payload(
        flow._get_handler()._open_request(flow, amount_base, ..., origin_ref=origin_ref, ...))
```
`_request_open_payload` tra ve dict thuan (`request_uuid`, `receiving_address`, `ref_display`,
`amount_base`, `caip2`, `expiry_datetime`, `eip681_uri`, `wc_uri`) — khong tra recordset qua RPC.
**Năm điều này giữ code open/closed:**

1. `handler_code` là `Selection` mở rộng bằng `selection_add` — đúng y hệt `payment.provider.code`
   (`selection=[('none', ...)]`, xác nhận tại `payment/models/payment_provider.py:34`). Một chế độ
   không cài thì không xuất hiện trong dropdown, và nếu không còn trong registry thì `_get_handler`
   raise rõ ràng thay vì chạy nhầm nhánh khác.
2. Dispatch bằng tên model, không bằng `if`. Thêm chế độ = thêm một addon, không sửa file nào có sẵn.
3. Core gọi handler qua interface, không bao giờ import bridge.
4. `_on_reorg` bắt buộc.
5. Entry point public duy nhất ⇒ bề mặt RPC bằng **một** method, kiểm được bằng một dòng grep.

**[SỬA] "Fail lúc cài đặt" của bản nháp không tự xảy ra.** `raise NotImplementedError` trong
AbstractModel fail lúc **gọi**, tức là lúc reorg — đúng cái thời điểm không được phép fail. Muốn
fail lúc cài đặt thì phải có một kiểm tra registry thật:

```python
def _register_hook(self):
    super()._register_hook()
    base = self.env.registry['blockchain.payment.handler']
    for name, Model in self.env.registry.items():
        if name.startswith('blockchain.payment.handler.') and name != '...handler.none':
            for m in ('_open_request', '_on_observation', '_on_final', '_on_reorg', '_on_expire'):
                if getattr(Model, m, None) is getattr(base, m):
                    raise ValueError("Handler %s chua hien thuc %s()" % (name, m))
```

Đặt trong core, chạy mỗi lần load registry. Một handler thiếu `_on_reorg` làm **server không khởi
động được**, đó là đúng mức độ nghiêm trọng.

#### 09.4b. Bốn tầng cấu hình, và ai được sửa tầng nào

| Thứ | Sống ở đâu | Nhóm được sửa | Ví dụ |
|---|---|---|---|
| Handler cho từng dòng tiền | `blockchain.money.flow` (record, có ACL, có `mail.thread`) | `group_blockchain_treasury_manager` | `ENDUSER_PAY` → `chain_provider` |
| Tham số kỹ thuật toàn hệ thống | `ir.config_parameter` | `base.group_system` | `blockchain.payment.ref_mode` = `hash`\|`plain` |
| Tham số của một provider | `payment.provider` (§09.5) | `payment.group_payment_manager` | `finality_mode`, `overpay_policy` |
| Bí mật (RPC key, HSM slot, acquirer secret) | **ngoài DB** — `ir.config_parameter` chỉ giữ `secret_ref` | không ai qua UI | CLAUDE.md §5 mục 5 |

Nhóm mới khai báo trong `security/blockchain_security.xml`; nhớ Odoo 19 đổi
`res.users.groups_id` → **`group_ids`** khi viết data cho user mẫu. Và thêm một `ir.rule` trên
`blockchain.money.flow` theo `company_id` (`['|', ('company_id','=',False),
('company_id','in',company_ids)]`) — thiếu nó, một company đọc được cấu hình của company khác.

---

### 09.5. `payment.provider` `code='chain'` — đặc tả cụ thể

```python
class PaymentProvider(models.Model):
    _inherit = 'payment.provider'

    code = fields.Selection(selection_add=[('chain', "Blockchain")],
                            ondelete={'chain': 'set default'})

    chain_id             = fields.Many2one('blockchain.chain', required_if_provider='chain')
    settlement_token_id  = fields.Many2one('blockchain.token', required_if_provider='chain')
    accepted_token_ids   = fields.Many2many('blockchain.token', 'ppr_token_accept_rel')
    receiving_mode       = fields.Selection([
        ('derived', "Dia chi rieng moi request (HD/CREATE2)"),
        ('router',  "Dia chi chung + PaymentRouter.pay(ref)"),
        ('memo',    "Dia chi chung + memo native cua chain")], default='derived')
    router_address       = fields.Char()
    finality_mode        = fields.Selection([('soft', "Soft"), ('hard', "Hard")], default='hard')
    confirm_depth_override = fields.Integer(default=0)      # 0 = dung mac dinh cua chain
    request_expiry_minutes = fields.Integer(default=30)
    quote_validity_seconds = fields.Integer(default=900)    # §09.7b
    soft_final_max_amount  = fields.Monetary(currency_field='main_currency_id')
    tolerance_bps        = fields.Integer(default=10)
    overpay_policy       = fields.Selection([
        ('accept', "Nhan du, ghi thua vao credit"),
        ('accept_refund', "Nhan du, hoan phan thua"),
        ('hold', "Giu, cho nguoi xu ly")], default='accept')
    underpay_policy      = fields.Selection([
        ('partial', "Ghi nhan mot phan, giu request mo"),
        ('hold', "Giu, cho nguoi xu ly")], default='partial')
    refund_address_policy = fields.Selection([
        ('none', "Khong hoan on-chain"),
        ('observed_sender', "Chi hoan ve dia chi da gui, neu da xac minh")], default='none')
```

Tên field đã tránh trùng tên kiểu Odoo: `request_expiry_minutes` (không `date`),
`payload_text`, `ref_hash_hex` (không `binary`/`json`).

`required_if_provider='chain'` là cơ chế sẵn có của Odoo (`payment_provider._valid_field_parameter`
cho phép tham số này, và `_check_required_if_provider()` chạy trong `create`/`write`): field bỏ
trống ⇒ **không enable được provider**. Dùng nó cho `chain_id`, `settlement_token_id`, và — quan
trọng nhất — cho `journal_id` khi `account_payment` có mặt.

**[BẢN 2] `accepted_token_ids` cần một cột trạng thái kiểm xuất xứ.** Trên factory mở, danh sách
token chấp nhận là danh sách **token của người khác**. Thêm vào bảng nối một cờ
`provenance_verified` cùng ba giá trị đã đọc (`factory_address`, `impl_version`, `verifier_address`)
và ngày kiểm. Một token trong danh sách mà `provenance_verified = False` thì provider **không
enable được** — cùng cơ chế `required_if_provider`, cùng lý do: đừng để một cấu hình dở lọt ra
production im lặng.

#### 09.5a. `_get_supported_currencies` — chỗ khó nhất, và một bug ngầm
#### 09.5a. `_get_supported_currencies` — chỗ khó nhất, và một bug ngầm

Một ERC-20 stablecoin không phải `res.currency`. Hai đường:

- (a) Tạo `res.currency` cho từng token (USDC, Z-VND…). Sai: `res.currency` là đơn vị kế toán;
  hai token cùng neo USD trên hai chain sẽ thành hai currency và mọi báo cáo consolidated sẽ hỏng.

  Trên factory mở, cái sai này nặng hơn hẳn: zDAI-A và zDAI-B là **hai token khác nhau neo cùng một
  tài sản**, và biến chúng thành hai `res.currency` là biến một chi tiết triển khai thành một đơn vị
  kế toán. Chúng phải cùng trỏ về một `res.currency`, và khác nhau ở `blockchain.token`.
- (b) **Chọn phương án này:** provider hỗ trợ đúng những `res.currency` có ít nhất một
  `blockchain.token` `active` map tới, qua model `blockchain.token` (`currency_id`, `decimals`,
  `caip19`, `contract_address`). Số tiền trên `payment.transaction` là **fiat**; số base units là
  `amount_base`.

```python
def _get_supported_currencies(self):
    currencies = super()._get_supported_currencies()
    if self.code == 'chain':
        currencies = currencies.filtered(
            lambda c: c.id in self.accepted_token_ids.mapped('currency_id').ids)
    return currencies

@api.depends('code', 'accepted_token_ids')          # <= dong nay la phan sua
def _compute_available_currency_ids(self):
    super()._compute_available_currency_ids()
```

> **[MỚI] Bug mà bản nháp không thấy.** `available_currency_ids` là field **store=True** với
> `@api.depends('code')` (`payment/models/payment_provider.py:195`). Chỉ `code` đổi mới recompute.
> Admin thêm một token vào `accepted_token_ids` ⇒ `_get_supported_currencies` đổi, nhưng
> `available_currency_ids` **không recompute**, và `_get_compatible_providers` lọc theo field
> stored đó ⇒ provider biến mất khỏi checkout mà không có lỗi nào. Cách sửa: override chính method
> compute với `@api.depends` mới (Odoo lấy depends từ định nghĩa mới nhất của method).

```python
def _compute_feature_support_fields(self):
    super()._compute_feature_support_fields()
    for p in self.filtered(lambda p: p.code == 'chain'):
        p.support_tokenization     = False   # True chi khi cai dms_blockchain_mandate
        p.support_express_checkout = False
        p.support_manual_capture   = False   # xem ghi chu SUA ben duoi
        p.support_refund = 'partial' if p.refund_address_policy != 'none' else 'none'

def _get_default_payment_method_codes(self):
    if self.code != 'chain':
        return super()._get_default_payment_method_codes()
    return {'chain_transfer'}
```

> **[SỬA] `support_manual_capture = 'none'` của bản nháp là giá trị không hợp lệ.** Selection của
> **`payment.provider`** chỉ có `[('full_only', ...), ('partial', ...)]` — không có `'none'`
> (`payment/models/payment_provider.py:163`). Base compute đặt `None`. Ghi `'none'` vào sẽ qua
> được write (Selection không validate ở tầng ORM cho giá trị compute) nhưng mọi nơi đọc nó sẽ
> lệch, và `_check_manual_capture_supported_by_payment_methods` so sánh với `'none'` **trên
> `payment.method`** — nơi `'none'` **là** hợp lệ. Hai model, hai tập giá trị, cùng tên field. Dùng
> `False` cho provider, `'none'` cho method.

`data/payment_method_data.xml`: `<record model="payment.method">` với `code = chain_transfer`,
`support_tokenization = False`, `support_manual_capture = none`, `support_refund = partial`,
`active = False` (Odoo tự bật khi provider được enable, qua `_activate_default_pms`).

`__init__.py` phải có `post_init_hook` theo đúng mẫu của `payment_demo`:

```python
from odoo.addons.payment import setup_provider, reset_payment_provider

def post_init_hook(env):
    setup_provider(env, 'chain')       # tao provider cho moi company + account.payment.method

def uninstall_hook(env):
    reset_payment_provider(env, 'chain')
```

Bỏ hook này ⇒ không có bản ghi `account.payment.method` với `code='chain'` ⇒
`_ensure_payment_method_line()` **return im lặng** ⇒ `journal_id` không gán được ⇒
`_create_payment()` tạo payment với `payment_method_line_id = False` ⇒ lỗi ở post-process, sau khi
tiền đã về. Đây là chuỗi thật, đọc được từ `account_payment/models/payment_provider.py:23-32`.

#### 09.5b. Nguồn notification không phải webhook

Không có controller. Watcher (§11) ghi `blockchain.payment.observation`, Finality Gate nâng trạng
thái, rồi một cron một dòng gọi (CLAUDE.md bẫy #4: body cron nằm trong method của model):

```xml
<field name="state">code</field>
<field name="code">model._cron_process_final_observations()</field>
Biên giới tin cậy ở đây không phải chữ ký webhook mà là **quorum RPC + finality depth**: một
observation chỉ lên `final` khi ≥ `blockchain.chain.finality_quorum` (mặc định 2) RPC endpoint độc
lập trả về cùng receipt tại cùng block hash (§08/§11). Một RPC nói dối không đủ để tạo ra một
`_set_done`.

Trên chain private 9000 hiện chỉ có **một** endpoint, nên `finality_quorum = 2` không thoả được và
provider sẽ không bao giờ lên `final`. Hai đường: hạ quorum về 1 và **ghi nhận đó là một rủi ro tồn
dư** (một node nói dối là đủ), hoặc thêm một node thứ hai. Đừng hạ quorum im lặng trong code — nó
phải là một giá trị cấu hình nhìn thấy được, vì nó là mức tin cậy của toàn bộ luồng tiền.

#### 09.5c. Một provider cho mỗi (company, chain, settlement token)

`account_payment._create_payment()` đọc `self.provider_id.journal_id` — **một** journal cho **một**
provider. Nếu một provider nhận cả USDC lẫn Z-VND trên cả Gnosis lẫn Celo, toàn bộ tiền vào một
journal và không thể đối soát `balanceOf(treasury)` theo từng token (kiểm tra (C) của §15).

Quyết định: **một `payment.provider` cho mỗi (company, chain, settlement token)**, mỗi cái trỏ tới
một `account.journal` type `bank` riêng, currency = currency của token, và một outstanding account
riêng. `accepted_token_ids` vẫn có thể nhiều (nhận USDT, quy đổi về USDC bằng M14) nhưng
`settlement_token_id` là một.

Trên factory mở, "settlement token" còn phải phân biệt được **zDAI-A với zDAI-B**: chúng cùng
`res.currency` nhưng là hai `blockchain.token` khác nhau, hai địa chỉ contract khác nhau, và tiền
của cái này không tiêu được ở cái kia. Nên đơn vị của quyết định trên là `blockchain.token.id`,
không phải `currency_id` — và điều đó vốn đã đúng trong câu chữ; chỉ là bây giờ nó có hệ quả thật.

Chi phí của quyết định này: N provider hiện trong danh sách checkout. Giảm thiểu bằng
`is_published = False` cho các provider chỉ dùng backend, và bằng `available_currency_ids` (đã lọc
theo token) — `_get_compatible_providers` sẽ tự loại những provider không khớp currency của đơn.

Phương án thay thế nếu N quá lớn (> ~6): giữ một provider và override:

```python
def _create_payment(self, **extra):
    if self.provider_code == 'chain':
        extra.setdefault('journal_id', self.blockchain_request_id.token_id.journal_id.id)
    return super()._create_payment(**extra)
```

Rẻ hơn về UX, đắt hơn về rủi ro: `payment_method_line_id` vẫn lấy từ provider, nên phải override
cả nó, và đó là lúc bắt đầu đi lệch khỏi framework.

#### 09.5d. Độ trễ: vì sao một cron 10 phút không phục vụ được `ENDUSER_PAY`

Ba con số, tất cả đều đọc được trong source:

| Nguồn độ trễ | Giá trị | Ở đâu |
|---|---|---|
| Độ phân giải tối thiểu của `ir.cron` | **60 giây** | `interval_type` nhỏ nhất là `minutes` |
| Cron post-process của Odoo | **10 phút** (`interval_number=10`), và `active=False` cho tới khi có provider enabled | `payment/data/payment_cron.xml` |
| `_cron_post_process` chỉ lấy tx có `last_state_change >= now - 4 ngày` | bỏ qua tx cũ hơn | `payment_transaction.py:1085` |

`ENDUSER_PAY` yêu cầu **giây**. Ba việc phải làm:

1. **Watcher gọi `_trigger()`**, không đợi lịch cron. `ir.cron._trigger()` tồn tại trong Odoo 19
   (`odoo/addons/base/models/ir_cron.py`) và đánh thức cron worker ngay lần wake kế tiếp, độ trễ
   thực tế dưới một giây khi `--max-cron-threads > 0`:

   ```python
   self.env.ref('dms_blockchain_payment.cron_process_final_observations')._trigger()
   ```
2. **Gọi `_post_process()` trực tiếp** ngay sau `_set_done()`. Người trả không mở trình duyệt ⇒
   không ai gọi `/payment/status/poll` ⇒ không ai post-process. Đợi cron 10 phút nghĩa là hoá đơn
   không được xác nhận trong 10 phút sau khi tiền đã về.
3. **Bus notification** cho màn hình thu ngân: `self.env['bus.bus']._sendone(channel, 'chain.paid',
   {...})`. POS không được poll REST mỗi giây cho 50 quầy.

Và vòng lặp cron phải chịu được một dòng hỏng — bản nháp không chịu được:

```python
def _cron_process_final_observations(self, limit=200):
    Obs = self.env['blockchain.payment.observation']
    for obs in Obs.search([('obs_state', '=', 'final'), ('is_processed', '=', False)],
                          order='id', limit=limit):
        try:
            tx = self.env['payment.transaction']._process('chain', obs._payment_data())
            obs.is_processed = True
            if tx and tx.state == 'done' and not tx.is_post_processed:
                tx._post_process()
            self.env.cr.commit()
        except Exception:                      # noqa: BLE001 - mot dong hong khong duoc chan hang doi
            self.env.cr.rollback()
            obs.sudo().write({'error_text': traceback.format_exc()[-2000:],
                              'retry_count': obs.retry_count + 1})
            self.env.cr.commit()
        if obs.retry_count >= 5:
            obs.sudo().activity_schedule(...)   # dua cho nguoi, khong retry vo han
```

Throughput: `limit=200` moi lan chay. Voi `_trigger()` sau moi block (Gnosis 5s) ⇒ tran
**~144,000 observation/gio**, du xa. Voi lich cron 1 phut khong `_trigger` ⇒ 12,000/gio. Ghi con
so nay vao runbook de nguoi van hanh biet nguong.

#### 09.5e. Overrides trên `payment.transaction`

```python
def _extract_reference(self, provider_code, payment_data):
    if provider_code != 'chain':
        return super()._extract_reference(provider_code, payment_data)
    return payment_data.get('odoo_reference')      # giai ma tu ref_hash / dia chi, xem §09.6

def _extract_amount_data(self, payment_data):
    if self.provider_code != 'chain':
        return super()._extract_amount_data(payment_data)
    if payment_data.get('is_confidential'):
        return None            # Zether: opt out kiem tra so tien — xem §09.9
    return {'amount': payment_data['fiat_amount'],
            'currency_code': payment_data['currency_code'],
            'precision_digits': payment_data['currency_decimals']}

def _apply_updates(self, payment_data):
    if self.provider_code != 'chain':
        return super()._apply_updates(payment_data)
    self.provider_reference = '%s:%s:%s' % (payment_data['caip2'],
                                            payment_data['tx_hash'],
                                            payment_data['log_index'])
    state = payment_data['chain_state']
    if state in ('broadcast', 'mined'):
        self._set_pending(state_message=_("On-chain, cho du do sau chot khoi."))
    elif state == 'final':
        self._set_done()
    elif state == 'reverted':
        self._set_error(_("Giao dich revert tren chain."))
```

Ba ghi chú kỹ thuật, tất cả lấy từ source:

- `_extract_amount_data` của base trả **`{}`**, không phải `None`. Nếu quên override,
  `_validate_amount` chạy `amount_data['amount']` ⇒ **`KeyError`**, không phải một lỗi sạch. Vì vậy
  nhánh `if self.provider_code != 'chain'` phải là dòng đầu tiên, luôn luôn.
- `_process()` gọi `_validate_amount()` **trước** `_apply_updates()` và thoát sớm nếu state chuyển
  sang `error`. Nghĩa là: nếu số tiền lệch, `_apply_updates` **không chạy**, `provider_reference`
  **không được ghi**, và ta mất con trỏ tới tx_hash. Phải ghi `provider_reference` ở chỗ khác —
  cụ thể là trên `blockchain.payment.observation`, luôn luôn, trước khi gọi `_process`.
- `_set_done` không tự gọi `_post_process`. Xem §09.5d.

---

### 09.6. Reference/memo: nối on-chain transfer với record Odoo

Trường hợp khó: người trả mở ví của họ, chuyển USDC, không bao giờ chạm app. Bốn kỹ thuật, xếp
theo độ tin cậy:

**R1 — Địa chỉ nhận riêng cho từng request (khuyến dùng).** Không cần memo. EVM: `CREATE2`
counterfactual — địa chỉ tính trước bằng `keccak256(0xff ++ factory ++ salt ++ initCodeHash)` với
`salt = ref32`; contract chỉ được deploy khi quét tiền về. Chi phí: deploy EIP-1167 clone + sweep
≈ **100–120k gas**; trên Gnosis ở 2 gwei = ~0,00022 xDAI ≈ $0,00022/request. Với 1 triệu request
loyalty/năm: ~$220. Chấp nhận được. Ưu điểm quyết định: **hoạt động với mọi ví, mọi token, không
cần người dùng làm gì đúng.**

Ba chi tiết triển khai mà bản nháp bỏ qua, và cả ba đều làm hỏng R1 nếu sai:

1. **Factory phải ở cùng một địa chỉ trên mọi chain EVM.** Địa chỉ CREATE2 phụ thuộc `factory`.
   Nếu factory trên Gnosis và trên Celo khác địa chỉ, cùng một `salt` cho ra hai địa chỉ khác nhau
   ⇒ khi khách gửi nhầm chain, tiền rơi vào một địa chỉ **ta không tính được và không sở hữu**.
   Cách làm: deploy factory qua deterministic deployment proxy
   `0x4e59b44847b379578588920cA78FbF26c0B4956C` (có sẵn trên gần như mọi chain EVM), với cùng
   `initCode` và cùng `salt`. Kiểm tra bằng một test CI so khớp địa chỉ factory trên tất cả chain
   đã cấu hình.

   **[BẢN 2] Cảnh báo:** chain private 9000 **chưa được kiểm** là có deterministic deployer đó hay
   không. Nó được bootstrap bằng một pre-EIP-155 legacy tx, và một chain từ chối legacy tx thì
   không có nó (§01.1.4.5). Kiểm bằng `cast code 0x4e59...` trước khi tin R1 chạy được ở đó.
2. **`initCodeHash` phải giống nhau**, tức implementation của clone phải cùng địa chỉ trên mọi
   chain. Cùng lý do, cùng cách.
3. **SELFDESTRUCT không còn hoàn gas.** EIP-3529 (London) đã xoá refund của SELFDESTRUCT; EIP-6780
   (Cancun) chỉ giữ hành vi xoá khi contract được tạo trong **cùng transaction** — đúng với
   deploy+sweep của ta, nên storage vẫn được dọn, nhưng **không có đồng tiền nào được hoàn lại**.
   Đừng tính refund vào mô hình chi phí.

   Trên chain 9000 (trước London) thì EIP-3529 **chưa áp dụng**, nên ở đó refund vẫn còn — nhưng
   đừng xây mô hình chi phí quanh một hành vi chỉ đúng trên một chain và sẽ biến mất khi chain đó
   được nâng cấp.

**R2 — Địa chỉ chung + reference.** Tuỳ chain:

| Chain | Có chỗ để memo? | Cách dùng |
|---|---|---|
| EVM (Gnosis, Celo, …) | **Không** trên `ERC20.transfer` | Phải gọi `PaymentRouter.pay(token, amount, bytes32 ref)` phát `PaymentReceived(payer, token, amount, ref)` |
| Stellar / Soroban | Có | `MEMO_TEXT` 28 bytes hoặc `MEMO_HASH` 32 bytes |
| Hedera | Có | transaction memo, 100 bytes |
| Cosmos / CosmWasm | Có | tx-level `memo`, mặc định `max_memo_characters = 256` |
| TON | Có | text comment trong body của message |
| SUI | **Không** | PTB gọi module phát event; hoặc R1 |

Độ dài `bytes32` là vừa đủ cho EVM. Nhưng không đặt plaintext reference lên public chain: một
`SO/2026/0413` cộng với địa chỉ đối tác lộ ra khối lượng đơn hàng cho đối thủ. Vậy:

```python
# ir.config_parameter blockchain.payment.ref_mode = 'hash' | 'plain'
def ref32(db_uuid, tx_reference):
    return keccak256(b'odoo:' + db_uuid.encode() + b':' + tx_reference.encode())   # bytes32
```

`ref32` là một chiều → phải lưu `ref_hash_hex` (Char(66), index unique) trên
`blockchain.payment.request` để tra ngược. Trên `chain_profile = private` (quyết định #5), đặt
`ref_mode = 'plain'`: không có đối thủ đọc chain, và debug dễ hơn nhiều.

**Thứ tự tính toán quan trọng.** `ref32` băm trên `tx.reference`, mà `tx.reference` chỉ có giá trị
cuối cùng **sau khi** `_compute_reference()` đã xử lý va chạm (`payment_transaction.py:370` thêm
hậu tố `-1`, `-2`… khi trùng). Vì vậy: tạo `payment.transaction` trước → đọc `tx.reference` →
tính `ref32` → tính địa chỉ CREATE2 → lưu vào `blockchain.payment.request`. Tính `ref32` trước khi
tạo tx là một lỗi im lặng: địa chỉ in trên hoá đơn sẽ không khớp request.

**[BẢN 2] Một cảnh báo mới cho R2 trên factory mở.** `PaymentRouter.pay(...)` phát một event mà
**ta** thiết kế — nhưng nếu người trả dùng một token của người khác và gọi thẳng `transfer` của
token đó, event là của **họ**, với schema của họ. Watcher không được giả định một schema event duy
nhất. Chốt: R2 chỉ dùng được khi người trả đi qua router của ta; với token lạ, **R1 là đường duy
nhất đáng tin**, vì địa chỉ nhận là thứ không phụ thuộc vào contract nào phát event gì.

**[SỬA] Độ dài reference đọc được cho người — tính lại xác suất va chạm.** Bản nháp viết: 40 bit,
không gian 1,1e12, với 10^7 request thì va chạm theo birthday ≈ 4,5e-2. **Sai ba bậc.** Công thức
xấp xỉ `p ≈ n²/(2N)`:

| Số bit | N | n = 10^6 | n = 10^7 |
|---|---|---|---|
| 40 | 1,10e12 | **0,45** | **≈ 1 (chắc chắn)** |
| 48 | 2,81e14 | 1,8e-3 | 0,18 |
| 64 | 1,84e19 | 2,7e-8 | **2,7e-6** |
| 80 | 1,21e24 | 4,1e-13 | 4,1e-11 |
Kết luận của bản nháp (dùng 64 bit) **đúng**, nhưng con số dẫn tới nó thì sai và phải sửa, vì ai đó
sẽ dùng con số 4,5e-2 đó để biện luận cho 40 bit ở một chỗ khác. Chốt: **64 bit** = 13 ký tự
Crockford base32 + 1 ký tự checksum → `BC-XXXXXXXXXXXXX-C`. Crockford (bỏ I, L, O, U) dễ đọc qua
điện thoại và chống nhầm `0/O`, `1/I`. Và vẫn giữ unique constraint trên `ref_hash_hex` làm chốt
chặn cuối — xác suất không phải là bảo đảm.

**R3 — Uniquify bằng số lẻ của số tiền.** Bác bỏ dứt khoát. USDC 6 decimals: 3 chữ số cuối cho
1000 khoá; fee-on-transfer token và các router sẽ làm lệch số tiền; hai request cùng giá sẽ đâm
nhau. Không dùng.

**R4 — Người trả khai báo `tx_hash` trên portal.** Fallback thủ công, luôn phải có, không bao giờ
là cơ chế chính. Phải verify: `tx.to == expected`, `tx.value/amount`, `tx_hash` chưa được claim
(unique constraint), và chỉ accept khi đã `final`. Thêm một chi tiết chống lạm dụng: chỉ cho phép
khai báo `tx_hash` có `block_timestamp` **sau** thời điểm tạo request — nếu không, ai đó sẽ khai
một transfer cũ của chính họ để đóng một hoá đơn mới.

Constraint idempotency bốn tầng:

```python
_unique_onchain_leg = models.Constraint(
    'UNIQUE(caip2, tx_hash, log_index)',
    'Mot log on-chain chi duoc ghi nhan mot lan.')                    # observation
_unique_ref_hash = models.Constraint(
    'UNIQUE(ref_hash_hex)', 'ref_hash phai duy nhat.')                # request
_unique_origin_ref = models.Constraint(
    'UNIQUE(company_id, origin_model, origin_ref)',
    'origin_ref cua consumer phai duy nhat.')                          # request
_unique_receiving_address = models.Constraint(
    'UNIQUE(caip2, receiving_address)',
    'Mot dia chi nhan chi phuc vu mot request.')                       # request, che do derived
```

Kiểm chứng bắt buộc bằng SQL, không tin code (bẫy #2 CLAUDE.md):
`SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_payment_observation'::regclass;`
Kỳ vọng: một dòng `u` cho `_unique_onchain_leg`. Không có dòng nào = constraint chưa bao giờ được
tạo, và idempotency của cả hệ thống là một ảo tưởng.

---

### 09.7. State machine: broadcast → pending → finality → done

| Sự kiện on-chain | `blockchain.payment.request.request_state` | `payment.transaction.state` | Gọi |
|---|---|---|---|
| Request tạo ra | `open` | `draft` | — |
| Người trả broadcast, thấy trong mempool | `seen` | `pending` | `_set_pending()` |
| Có receipt, `status == 1` | `mined` | `pending` | `_set_pending()` (không đổi state, chỉ đổi message) |
| Đạt finality depth | `final` | `done` | `_set_done()` rồi gọi `_post_process()` |
| Receipt `status == 0` | `failed` | `error` | `_set_error()` |
| `mined` rồi bị reorg đẩy ra | `reorged` | tuỳ: xem dưới | `_on_reorg()` |
| Hết hạn, chưa có tiền | `expired` | `cancel` | `_set_canceled()` |
| Hết hạn, sau đó tiền về | `late_paid` | — | activity, không tự động `done` |

Bảng chuyển trạng thái hợp lệ của Odoo 19 (đọc từ `_set_*`, để biết cái gì **không** làm được):

| Method | Source states cho phép |
|---|---|
| `_set_pending` | `draft` |
| `_set_authorized` | `draft`, `pending` |
| `_set_done` | `draft`, `pending`, `authorized`, `error` |
| `_set_canceled` | `draft`, `pending`, `authorized` |
| `_set_error` | `draft`, `pending`, `authorized` |

Đọc bảng này kỹ: **không có đường từ `done` đi đâu cả** (trừ khi truyền `extra_allowed_states`, là
một cửa sau chứ không phải một thiết kế). `_update_state` không raise khi state không hợp lệ — nó
**ghi một `_logger.warning` và bỏ qua**. Nghĩa là một chuyển trạng thái sai sẽ **không** làm đỏ
test, chỉ để lại một dòng log mà không ai đọc. Mọi handler phải tự kiểm tra `tx.state` sau khi gọi
`_set_*` nếu kết quả quan trọng.

**Reorg sau `_set_done` là trường hợp phải thiết kế, không phải trường hợp hiếm.** Với
`finality_mode = 'soft'` trên Gnosis (1 block, 5s) — chế độ bắt buộc cho `ENDUSER_PAY` — reorg độ
sâu 1–2 block xảy ra thực tế. Đảo ngược một `done` đã `_post_process` (đã tạo `account.payment`, đã
xác nhận đơn) là sai. Quy tắc:

- `finality_mode = 'hard'`: reorg sau `done` coi như không xảy ra.
- `finality_mode = 'soft'`: `_set_done` vẫn chạy, nhưng `_on_reorg` **không** đảo ngược — nó tạo một
  `blockchain.payment.reversal` và một activity cho kế toán, và bridge `dms_blockchain_account`
  sinh bút toán điều chỉnh. Tiền đã giao hàng rồi thì cái cần là một bút toán, không phải một
  rollback.

**Đặt `soft_final_max_amount` bằng một phép tính, không bằng cảm giác.** Tổn thất kỳ vọng năm:

```
E[loss/nam] = P(reorg vuot depth) × so_tx/nam × gia_tri_tb_moi_tx
```

Ví dụ làm việc, cho `ENDUSER_PAY` trên Gnosis ở soft finality (depth 1):
`P ≈ 1e-4/tx` (**ước tính** — Gnosis có reorg độ sâu 1 thỉnh thoảng xảy ra; con số thật phải lấy
từ histogram độ sâu reorg mà indexer §11 tự ghi trong 30 ngày, dùng ước tính này làm giá trị khởi
động), 1.000.000 tx/năm, trung bình $5/tx ⇒ **E[loss] ≈ $500/năm**. So với doanh số $5M, đó là
1e-4 — rẻ hơn nhiều so với chi phí mất khách vì bắt khách đợi 2,7 phút ở quầy.

Cùng phép tính cho một khoản $50.000: E[loss] cho **một** giao dịch = $5. Vẫn nhỏ, nhưng phương sai
thì không: một lần mất $50.000 không bù được bằng 10.000 lần tiết kiệm 2,7 phút. **Quy tắc đặt
ngưỡng: `soft_final_max_amount` = số tiền mà bạn chịu được khi mất một lần, không phải số tiền có
tổn thất kỳ vọng thấp.** Đề xuất mặc định: **$200** cho `ENDUSER_PAY`, `False` (không cho soft)
cho mọi flow B2B. Và một mạch ngắt tổng: nếu tổng giá trị soft-final chưa qua hard finality vượt
`soft_final_exposure_cap` (đề xuất $5.000), mọi request mới tự động chuyển sang `hard`.

**Giá trị hard finality thực tế, đã sửa:**

| Chain | Soft | Hard | Ghi chú |
|---|---|---|---|
| Gnosis xDAI | 1 block ≈ 5s | 2 epoch = **2 × 16 slot × 5s ≈ 160s (~2,7 phút)** | **[SỬA]** note ghi "12,8 phút" — đó là con số của Ethereum (32 slot × 12s × 2). Gnosis có **16 slot/epoch** và slot 5s |
| Ethereum L1 | 1 block ≈ 12s | 2 epoch ≈ **12,8 phút** | đúng |
| Celo | ~1s (sequencer) | **đến khi batch được finalize trên L1 ≈ 15–20 phút** | **[SỬA]** note mô tả Celo là "IBFT 2.0, 1 block immediate finality". Celo đã chuyển thành **L2 OP-Stack trên Ethereum (2025)**; §03.3.8 của bộ tài liệu này cũng đã coi Celo là L2 block 1s. Một Celo adapter viết theo mô tả cũ sẽ coi soft là hard |
| **Chain private 9000 (Clique)** | 1 block ≈ 5s | **không có finality theo giao thức** | **[BẢN 2]** Bản 1 ghi "private QBFT/IBFT — instant, không reorg khi < 1/3 validator lỗi". Chain thật là **Clique một signer** (§01.1.16): không phải BFT, có thể reorg ngắn, và thứ đảm bảo tính chung cuộc là chính signer đó. Đặt một `finality_depth` bảo thủ và ghi rõ cơ sở |

**Expiry không được làm mất tiền.** `_cron_expire_payment_requests` đặt `expired` + `_set_canceled`,
nhưng địa chỉ/ref **vẫn được watch vĩnh viễn**. Tiền về muộn → observation `late_paid`, tạo
activity, không bao giờ tự động `_set_done` một transaction đã `cancel`. Xử lý: người vận hành chọn
"áp dụng vào request mới" hoặc "hoàn trả". Lưu ý hệ quả kế toán: nếu tx đã liên kết invoice,
`account_payment._post_process()` sẽ gọi `tx.payment_id.action_cancel()` cho mọi tx `cancel` — với
một request chưa từng có tiền thì không sao (chưa có payment), nhưng đừng cancel một tx đã từng
`done`.

**Overpay / underpay / sai token / sai chain:**

| Tình huống | Hành động |
|---|---|
| Trả thừa ≤ `tolerance_bps` (mặc định 10 bps) | Coi là đủ, ghi chênh vào thu nhập khác |
| Trả thừa > tolerance, `overpay_policy = accept` | `_set_done`, phần thừa vào `blockchain.credit.balance` của partner |
| Trả thiếu, `underpay_policy = partial` | Request giữ `open`, `amount_received_base` cộng dồn; `_set_done` khi đủ. Nhiều transfer → nhiều observation cùng một request: đúng |
| Trả thiếu ≤ `tolerance_bps` | Coi là đủ. Đây là trường hợp **phổ biến nhất** trong thực tế: ví trừ phí, hoặc người dùng gõ tròn số |
| Sai token (USDT thay vì USDC) trên đúng địa chỉ | `unmatched_token`, không bao giờ tự quy đổi. Tỷ giá phải là một quyết định của người, không phải của cron |
| Đúng địa chỉ nhưng sai chain (địa chỉ EVM giống nhau trên mọi chain) | `unmatched_chain`. Đây là lỗi người dùng phổ biến nhất. Nếu ta không kiểm soát khoá của địa chỉ trên chain đó → **tiền mất thật**. Vì vậy `receiving_mode = 'derived'` phải deploy CREATE2 trên **mọi** chain EVM mà ta chấp nhận, cùng factory, cùng salt, cùng initCodeHash (§09.6 R1) |
| **Đúng địa chỉ, đúng chain, nhưng sai token vì có hai zDAI** | **[BẢN 2]** `unmatched_token` như trên. Nhưng đây là trường hợp mới của factory mở và nó **sẽ xảy ra**: khách gửi zDAI-B khi ta chỉ nhận zDAI-A. Thông báo lỗi phải nói rõ *địa chỉ contract* nào được chấp nhận, không chỉ tên token — hai token cùng tên là chuyện bình thường |
| Tiền về một địa chỉ đã `expired` | `late_paid`, xem trên |
| Giá trị sau khi sweep < `sweep_min_value` | Không sweep ngay; gom. Trên Gnosis sweep tốn ~$0,0002 nên ngưỡng này gần như bằng 0; trên Ethereum L1 nó là **$1–3** ⇒ mọi khoản dưới $10 là không đáng sweep riêng |

`blockchain.credit.balance` (core, không cần `account`):

```python
class BlockchainCreditBalance(models.Model):
    _name = 'blockchain.credit.balance'
    _description = 'Overpayment credit held for a partner, per token'

    company_id = fields.Many2one('res.company', required=True, index=True)
    partner_id = fields.Many2one('res.partner', required=True, index=True)
    token_id   = fields.Many2one('blockchain.token', required=True, index=True)
    balance_base = fields.Char(required=True, default='0')
    _unique_credit = models.Constraint(
        'UNIQUE(company_id, partner_id, token_id)',
        'Mot partner chi co mot so du tin dung tren mot token.')
```

`balance_base` là plain field có `default`, **không** phải stored computed — vì một stored computed
không nhận `default`, và nếu compute có nhánh không gán gì thì cột `required` nhận NULL và INSERT
chết (bẫy CLAUDE.md, §15 đã bắt được ở ba chỗ).

**Refund là một giao dịch mới, không phải đảo ngược.** `_create_child_transaction(amount,
is_refund=True)` của Odoo 19 đã làm đúng phần Odoo (amount âm, prefix `R-`). Phần chain:

```python
def _send_refund_request(self):
    if self.provider_code != 'chain':
        return super()._send_refund_request()
    src = self.source_transaction_id
    addr = src.blockchain_refund_address
    if not addr or not src.blockchain_refund_address_verified:
        raise ValidationError(_(
            "Khong co dia chi hoan tien da xac minh. Dia chi gui tien co the la vi nong cua "
            "san giao dich; hoan ve do la mat tien."))
    self.env['blockchain.relay.job'].relay_submit_intent(
        caip2=src.blockchain_caip2, target_address=src.blockchain_token_address,
        calldata_hex=encode_transfer(addr, self.blockchain_amount_base),
        origin_model='payment.transaction', origin_res_id=self.id,
        origin_ref='refund:%s' % self.reference)     # idempotency, khop _unique_origin cua §06
```

`blockchain_refund_address_verified` chỉ `True` khi: (a) địa chỉ đã ký một challenge trong portal
(EIP-191 `personal_sign` một nonce có hạn, lưu nonce để chống replay), hoặc (b) địa chỉ khớp một
`blockchain.wallet` đã KYC gắn với `partner_id`. `from` của transfer **không** đủ: rút từ Binance
thì `from` là ví nóng của Binance và tiền hoàn sẽ không bao giờ về tay khách. Đó là lý do
`support_refund` mặc định là `'none'`.

Và một điều bản nháp không nói: **hoàn tiền một phần trên chain không tồn tại như một khái niệm**.
`support_refund = 'partial'` chỉ có nghĩa là Odoo cho phép tạo child tx với số tiền nhỏ hơn; on-chain
nó vẫn là một transfer mới. Nghĩa là không có gì ràng buộc tổng các lần hoàn ≤ số tiền gốc **ở phía
chain** — chỉ Odoo ràng buộc (`_update_source_transaction_state` cộng dồn child). Nếu ai đó gọi
`relay_submit_intent` trực tiếp, ràng buộc đó biến mất. Đó là lý do `relay_submit_intent` phải kiểm
tra `origin_model='payment.transaction'` có child tương ứng ở state `pending`.

---

### 09.7b. Tỷ giá và báo giá — chỗ bản nháp bỏ trống hoàn toàn

`payment.transaction.amount` là fiat (`res.currency`, thường VND). On-chain là base units của một
token. Giữa hai cái là một tỷ giá. Bản nháp không nói ai đặt tỷ giá, đặt lúc nào, và ai chịu rủi ro
khi nó đổi giữa lúc tạo request và lúc tiền về. Đó là một lỗ hổng thực thi, không phải chi tiết.

Ba tình huống, độ rủi ro khác hẳn nhau:

| Cặp | Biến động trong 30 phút | Xử lý |
|---|---|---|
| USD invoice ↔ USDC | ~0 (stablecoin) | Tỷ giá 1:1, không cần quote |
| VND invoice ↔ USDC | tỷ giá USD/VND, biến động ngày ~0,1–0,3% | Khoá tỷ giá lúc tạo request, hạn hiệu lực |
| VND invoice ↔ token biến động (không khuyến nghị) | 2–10%/giờ | Không cho phép trên `B2B_*`; nếu cho, quote 120 giây |

```python
class BlockchainPaymentQuote(models.Model):
    _name = 'blockchain.payment.quote'
    _description = 'Locked fiat-to-token rate for one payment request'

    request_id      = fields.Many2one('blockchain.payment.request', required=True,
                                      ondelete='cascade', index=True)
    currency_id     = fields.Many2one('res.currency', required=True)
    token_id        = fields.Many2one('blockchain.token', required=True)
    rate_numerator_base   = fields.Char(required=True)   # base units token
    rate_denominator_cent = fields.Char(required=True)   # don vi nho nhat cua fiat
    rate_source     = fields.Char(required=True)         # 'ecb', 'sbv', 'chainlink:...', 'fixed'
    locked_datetime = fields.Datetime(required=True)
    expiry_datetime = fields.Datetime(required=True, index=True)
    quote_state     = fields.Selection([('live', "Live"), ('used', "Used"),
                                        ('expired', "Expired")], default='live', required=True)
```

Tỷ giá lưu dưới dạng **phân số hai số nguyên**, không phải float — vì một `Float` VND/USDC với 6
decimals làm tròn sai ở hàng đồng. `rate_source` là bắt buộc và phải được lưu: khi kiểm toán hỏi
"tại sao hoá đơn 25.000.000 ₫ lại là 1.000 USDC", câu trả lời phải là một dòng dữ liệu, không phải
một phép tính làm lại bây giờ.

Chính sách khi quote hết hạn trước khi tiền về:

- Trong `tolerance_bps`: chấp nhận, chênh lệch vào tài khoản chênh lệch tỷ giá (`account.account`
  loại `income`/`expense`, cấu hình trên `dms_blockchain_account`).
- Ngoài `tolerance_bps` và `quote_reprice_policy = 'reprice'`: request giữ `open`, sinh quote mới,
  yêu cầu trả bù phần thiếu.
- Ngoài `tolerance_bps` và `quote_reprice_policy = 'accept'`: chấp nhận, ghi lãi/lỗ tỷ giá.

`quote_validity_seconds` mặc định **900** (15 phút) cho cặp fiat-stablecoin, **120** cho token biến
động. `request_expiry_minutes` mặc định 30 nên một request có thể phải reprice một lần giữa đời —
đó là cố ý, và UI phải hiện ngược đồng hồ của quote, không phải của request.

---

### 09.8. Người trả không bao giờ mở app

```
Ke toan brand   ->  dms_blockchain_payment: tao payment.transaction (reference duoc chot)
                    -> blockchain.payment.request: ref32 = keccak(db_uuid, tx.reference)
                       receiving_mode='derived' -> dia chi D (CREATE2, chua deploy)
                    -> blockchain.payment.quote: khoa ty gia VND/USDC, han 15 phut
                ->  Gui email/portal link: "chuyen 5,000 USDC (Gnosis) toi D truoc <expiry>"
Distributor     ->  Mo Safe cua ho, transfer USDC -> D.   (Khong biet Odoo la gi)
Watcher (§11)   ->  Log Transfer(to=D) -> blockchain.payment.observation (obs_state=mined)
                    (ghi provider_reference vao observation NGAY, truoc moi buoc sau)
Finality Gate   ->  quorum RPC >= 2, depth du -> obs_state=final -> cron._trigger()
Cron            ->  payment.transaction._process('chain', obs._payment_data())
                    _search_by_reference: D -> request -> tx.reference     <- ANH XA O DAY
                    _validate_amount -> _apply_updates -> _set_done
                ->  tx._post_process()  (goi truc tiep, khong doi cron 10 phut)
                ->  bus._sendone(...) cho man hinh dang mo, neu co
Sweep job       ->  deploy clone tai D, transfer USDC -> treasury (gom lo neu duoi nguong)
```

Ánh xạ không dựa vào memo, không dựa vào `from`, không dựa vào số tiền. Địa chỉ là reference.

Tiền về **trước khi** có request (trả sớm, hoặc chuyển nhầm) → observation `unmatched`. Quy tắc
cứng: **không bao giờ tự động tạo `payment.transaction` từ một observation `unmatched`.** Một
wizard cho người vận hành gắn nó vào một invoice. Tự động ở đây là con đường ngắn nhất tới việc ghi
nhận doanh thu cho một khoản tiền không biết của ai. (Cùng kết luận với §11.8, và cùng mô hình với
`dms.bank.reconciliation`: tiền chưa khớp vào tài khoản treo.)

#### 09.8b. `partner_id` là `required`, còn người trả thì vô danh

`payment.transaction.partner_id` là `required=True, ondelete='restrict'`. `payment.token` còn chặt
hơn: `_check_partner_is_never_public` cấm gắn token cho partner public. Ba lựa chọn, phải chọn một
ở mức deployment:

| Chính sách | Cách làm | Hợp với |
|---|---|---|
| `anonymous_partner` | Một `res.partner` kỹ thuật "Walk-in crypto payer" cho mỗi company. Mọi tx vô danh trỏ vào nó | `ENDUSER_PAY` khối lượng lớn, giá trị nhỏ |
| `partner_per_wallet` | Lần đầu thấy một địa chỉ, tạo `res.partner` + `blockchain.wallet` gắn với nó; lần sau tái sử dụng | `B2B_*`, và bắt buộc nếu cần Travel Rule |
| `require_known_partner` | Từ chối mọi observation từ địa chỉ chưa có trong `blockchain.wallet`. Tiền vào tài khoản treo | Chain private, và môi trường tuân thủ chặt |

Mặc định đề xuất: `require_known_partner` cho `B2B_*` và `chain_profile='private'`;
`anonymous_partner` cho `ENDUSER_PAY`. `partner_per_wallet` nghe hay nhưng tạo rác: một chiến dịch
loyalty có thể sinh 200.000 `res.partner` trong một tháng, và `res.partner` là model nặng nhất
trong Odoo. Nếu chọn nó, phải có ngưỡng (chỉ tạo partner khi tổng giá trị từ một ví vượt một mức).

Liên quan pháp lý (§13): ngưỡng Travel Rule của FATF là **$1.000/EUR 1.000** cho giao dịch VASP.
Nếu deployment rơi vào phạm vi đó, `require_known_partner` không còn là tuỳ chọn.

---

### 09.9. Zether phá vỡ M1 — và vì sao M13 phải là M4, không phải M1

`payment.transaction._validate_amount()` (Odoo 19, `payment/models/payment_transaction.py:794`)
so sánh số tiền từ payment_data với `tx.amount` và `_set_error` nếu lệch. Với Zether, chain không
hề lộ số tiền: chỉ có `(C_transfer, D_transfer)` và một `fee` công khai. Không có gì để so sánh.

May mắn là Odoo 19 đã mở sẵn cửa: `_extract_amount_data` trả `None` → *"Skip validation for
transactions where the provider opts out of amount check"* (`payment_transaction.py:807`). Đó là
đường hợp pháp duy nhất, và section này dùng nó (§09.5e). Tiền lệ: `payment_custom` làm **đúng y
như vậy** cho wire transfer.

Nhưng kết quả là một `payment.transaction` `done` mà **không ai chứng minh được số tiền**. Chain
chỉ chứng minh: một khoản chuyển nào đó, từ `fromSchnorrAddress` tới `toSchnorrAddress`, tại epoch
`e`, hợp lệ về range proof. Số tiền đến từ **client của người nhận giải mã `(C, D)` bằng khoá riêng
của chính họ**, rồi Odoo **xác minh** `C_transfer == g^v · y_recv^s` (§11.10 — một phép kiểm tra rẻ,
không cần khoá bí mật). Đường thứ hai là một receipt off-chain do người trả ký bằng viewing key.

**[BẢN 2] Và giờ có một đường thứ ba, mạnh hơn hẳn hai đường trên: `transferWithProof`**
(`_USER-DECISIONS.md` §12). Nó là chính phép kiểm tra `C · g^{-v} == y_to^s` ở trên, nhưng được đặt
tên, có `entryRef` ràng buộc vào đúng giao dịch, và có ba chủ thể mở được (người gửi biết `s`,
người nhận biết `x_to`, auditor biết khoá auditor). Nghĩa là:

- Số tiền của một giao dịch Zether **chứng minh được với bên thứ ba**, không chỉ "người nhận nói vậy".
- `verifyTransferAmount` là `view` — gọi **miễn phí** qua `eth_call`, không giới hạn số lần, không
  để lại vết on-chain. Đối soát hàng tháng không tự nó trở thành dữ liệu công khai.
- Người gửi chứng minh được **mà không cần người nhận hợp tác**, và ngược lại (§12.7).

Điều đó không đổi kết luận dưới đây — mô hình vẫn là sub-ledger — nhưng nó đổi *chất lượng* của
cột "số tiền đối soát từ": từ "tin người nhận" thành "kiểm chứng được độc lập".

Kết luận kỹ thuật: với Zether, **nguồn sự thật về số tiền là số dư giải mã được của người nhận**,
không phải một sự kiện. Đó là mô hình sub-ledger, không phải mô hình payment gateway. Vì vậy:

| | M1 + Zether | M4/M13 + Zether |
|---|---|---|
| Số tiền đối soát từ | receipt off-chain (tin người trả) | delta số dư giải mã của chính mình, **cộng `verifyTransferAmount` khi cần chứng minh** |
| Phát hiện thiếu tiền | không, cho tới khi ai đó đối chiếu | ngay ở bước reconcile lô |
| Reorg | phải đảo ngược một `done` | chỉ làm lệch một lô, sửa ở lô sau |
| Khuyến nghị | **không** | **có** |

Thêm một ràng buộc thực tế: Zether cần `rollOver()` và `simulateAccounts()` (note §10.5.3) — số dư
chỉ chính thức ở epoch sau. Nghĩa là ngay cả soft finality cũng không đủ: `_on_final` cho Zether
phải đợi **epoch boundary + finality depth**. Trên Gnosis với epoch = 5 block × 5s = 25s, cộng hard
finality 2 epoch beacon (~160s, đã sửa ở §09.7) → **~3 phút**, không phải 13 phút như bản nháp ước.
Vẫn là quá lâu cho `ENDUSER_PAY`.

Trên chain private, bản 1 viết "block time 1s và instant finality → ~5–10s: khả thi". **Con số đó
sai theo hai hướng** (§01.1.16): chain thật có block **5s** (không phải 1s) và Clique **không có
instant finality**. Ước tính đúng hơn: epoch 25s + một `finality_depth` bảo thủ ⇒ vẫn **hàng chục
giây**, không phải 5–10s. Khả thi cho `OUTLET_COLLECT`, **không** khả thi cho `ENDUSER_PAY` tại quầy.
Đây là một chỗ mà quyết định #5 vẫn đúng nhưng lý do phải được phát biểu lại cho khớp thực tế.

**Và ràng buộc thật sự chặn `ENDUSER_PAY` bằng Zether trên public chain không phải độ trễ, mà là
block space.** Theo §03.3.6/§03.3.8: một confidential transfer cấu hình 32/64 tốn **~1,88 M gas**;
Gnosis có block gas limit 17 M và block 5s ⇒ ở mức chiếm 20% block space của cả mạng, trần là
**~31.300 tx/ngày toàn hệ thống**. Một chuỗi bán lẻ 200.000 outlet không nằm vừa trong con số đó.

Bản 1 kết luận "private chain (QBFT, precompile native) cho ~500 tx/s. Không có lựa chọn thứ ba."
**Con số 500 tx/s không có cơ sở** và §01.1.12.2 đã đo lại: trần trên chain private là **CPU
validator, ~45 confidential tx/s** — cao hơn Gnosis 100 lần, nhưng thấp hơn 500 một bậc. 45 tx/s =
3,9 triệu giao dịch/ngày, vẫn thừa cho mọi khối lượng B2B, và vẫn không đủ cho thanh toán bán lẻ
quy mô quốc gia. Kết luận không đổi; con số thì phải đúng.
quy mô quốc gia. Kết luận không đổi; con số thì phải đúng.

---

### 09.10. Định lượng

#### 09.10a. Gas

Công thức đúng cho cả bảng: `chi_phi_USD = gas × gas_price_gwei × 1e-9 × gia_native_USD`.
Giả định: xDAI = $1,00, CELO = $0,50, Gnosis 2 gwei, Celo 5 gwei.
Celo cộng **+50.000 gas intrinsic** cho giao dịch khai `feeCurrency` (**ước tính**, cơ sở:
overhead thêm của tx type CIP-64 cho việc ghi nợ/có đồng stablecoin ở tầng validator; phải đo lại
trên mainnet Celo hiện tại trước khi đưa vào SLA).

| Thao tác | Gas | Gnosis @2 gwei | Celo: gas+50k | Celo @5 gwei |
|---|---|---|---|---|
| `ERC20.transfer` (đích đã warm) | 45.000 | $0,000090 | 95.000 | $0,000238 |
| `ERC20.transfer` (đích lần đầu, ghi slot mới) | 65.000 | $0,000130 | 115.000 | $0,000288 |
| `PaymentRouter.pay(token, amount, ref)` + event | 85.000 | $0,000170 | 135.000 | $0,000338 |
| CREATE2 clone deploy + sweep | 110.000 | $0,000220 | 160.000 | $0,000400 |
| EIP-1776 envelope: ecrecover + EIP-712 + nonce | +9.000 … +24.000 | +$0,00002…0,00005 | — | — |
| EIP-1776 envelope + trả fee bằng ERC-20 | +39.000 … +69.000 | +$0,00008…0,00014 | — | — |
| Zether `transferConfidential` 32/64 (§03.3.6) | **1.880.000** | **$0,00376** | 1.930.000 | **$0,00483** |
| Zether `transferConfidential` 128/128 | 3.870.000 | $0,00774 | 3.920.000 | $0,00980 |
| `permit` + `transferFrom` | 100.000 | $0,000200 | 150.000 | $0,000375 |
| Batch 150 người nhận (M17) | 4.521.000 | $0,00904 | — | — |
| **Mọi dòng trên, chain private 9000** | như cột gas | **$0** | — | **$0** |

**[SỬA] Hai lỗi trong bảng của bản nháp:**

1. **Zether 180.000–250.000 gas: sai 15–20 lần.** §03.3.7 đã truy ra nguồn gốc: `45.000 + 4 ×
   34.000 = 181.000` là chi phí verify một **Groth16 SNARK trên alt_bn128** (4 pairing), không phải
   Bulletproofs — Bulletproofs không dùng pairing. Con số đúng là 1,88 M (32/64) đến 3,87 M
   (128/128). Bảng trên đã sửa theo §03 để cả bộ tài liệu nhất quán.
2. **Cột Celo của bản nháp không khớp chính giả định của nó.** Với CELO = $0,50 và +50k intrinsic,
   dòng `65.000` phải ra $0,000288 chứ không phải $0,00033; dòng `110.000` phải ra $0,000400 chứ
   không phải $0,00053. Đã tính lại toàn bộ bảng bằng một công thức duy nhất, viết rõ ở trên.
3. **EIP-1776 "+32.000"** là một con số không chia nhỏ được. Chia ra: `ecrecover` 3.000 +
   keccak/EIP-712 ~1.000 + SSTORE nonce 5.000 (slot warm nonzero→nonzero) hoặc 20.000 (slot mới)
   = **9.000–24.000**. Nếu fee trả bằng một `ERC20.transfer` riêng cho relayer thì cộng thêm
   30.000–45.000 ⇒ **39.000–69.000**. Bản nháp gộp nửa chừng.

#### 09.10b. Độ trễ và throughput

| Đại lượng | Giá trị | Cơ sở |
|---|---|---|
| Độ trễ `ENDUSER_PAY` tốt nhất (Gnosis soft) | ~5–8s | 1 block 5s + quorum RPC + `_trigger` |
| Độ trễ `ENDUSER_PAY` nếu quên `_trigger` | **đến 10 phút** | cron post-process mặc định |
| Độ trễ hard finality Gnosis | ~160s | 2 epoch × 16 slot × 5s |
| Độ trễ Zether trên Gnosis (epoch + hard) | ~185s | 25s epoch + 160s |
| Độ trễ Zether trên chain private 9000 | **hàng chục giây** | **[SỬA]** bản 1 ghi "5–10s, block 1s, instant finality". Chain thật: block 5s, Clique không instant-final (§01.1.16) |
| Trần xử lý observation (cron 1 phút, limit 200) | 12.000/giờ | — |
| Trần xử lý observation (`_trigger` mỗi block) | ~144.000/giờ | 720 lần chạy/giờ × 200 |
| Trần Zether toàn mạng Gnosis @20% block space | 31.300 tx/ngày | §03.3.8 |
| Trần Zether chain private | **~45 tx/s** | **[SỬA]** bản 1 ghi ~500 tx/s không có cơ sở. Trần là CPU validator (§01.1.12.2) |

#### 09.10c. Công sức và chi phí vận hành

Effort (person-week, một dev senior, chưa tính audit contract):

| Gói | pw |
|---|---|
| M0 `payment_custom` cấu hình (chạy được trong tuần đầu) | 0,2 |
| Core: `blockchain.money.flow`, handler interface + registry check, request/observation/quote, Finality Gate binding | 5 |
| `dms_blockchain_payment` (M1 + M6 + M11) | 6 |
| `dms_blockchain_account` (M3 + M4 kế toán + M15 netting) | 6 |
| `dms_blockchain_mandate` (M7 + M10) | 4 |
| M8 stream, M9 escrow (kể cả contract, chưa audit) | 8 |
| M14 auto-convert, M17 batch, M18 voucher (contract + Odoo) | 5 |
| M16 fiat ramp (phần phần mềm; phần pháp lý không ước lượng được) | 4 |
| **[BẢN 2]** Kiểm xuất xứ token (§09.4, §09.5): đọc `factory()`/`version()`/`verifier()`, lưu, chặn enable | 1 |
| **Tổng phần mềm** | **~39 pw** |
| Audit contract bên ngoài cho router + escrow + voucher | ~$25–40k, 3–5 tuần lịch |

Dòng audit đọc khác đi trên factory mở: nếu router/escrow/voucher lấy từ catalogue và **đã có audit
công khai với đúng `implCodeHash`**, chi phí đó bằng 0 và việc phải làm là *đọc bản audit đó* chứ
không phải đặt một bản mới. Nhưng nó chỉ đúng khi ta kiểm được hash — nếu không, coi như chưa audit.

Chi phí vận hành/năm (**ước tính**, cơ sở: giá niêm yết 2026 của nhóm nhà cung cấp phổ biến):

| Mục | $/năm |
|---|---|
| 2 RPC endpoint độc lập (bắt buộc cho quorum) trên Gnosis + Celo | $1.200–3.600 |
| Node tự chạy (tuỳ chọn, thay 1 endpoint) | ~$1.000 (VPS) + công vận hành |
| Giám sát/alerting (watcher lag, reorg, số dư gas relayer) | $300–1.200 |
| Gas cho 1M request loyalty R1 (deploy+sweep) trên Gnosis | ~$220 |

---

### 09.10d. Kiểm chứng: cái gì phải xanh trước khi gọi là xong

Không phải test plan đầy đủ (§14 lo đó), chỉ là những phép đo mà **nếu thiếu thì không biết là
mình sai**:

```
1. SQL, khong phai code:
   SELECT conname, contype FROM pg_constraint
   WHERE conrelid IN ('blockchain_payment_request'::regclass,
                      'blockchain_payment_observation'::regclass);
   -> phai co du 4 dong 'u' cua §09.6. Zero dong = idempotency khong ton tai.

2. Registry check cua §09.4a phai lam server KHONG khoi dong duoc khi mot handler
   thieu _on_reorg. Test bang cach tam xoa method va chay `odoo -u`.

3. available_currency_ids: them mot token vao accepted_token_ids, doc lai field.
   Neu no khong doi -> depends chua duoc override (§09.5a).

4. Reorg: chay anvil, tao mot payment, _set_done o soft, roi `anvil_reorg` 2 block.
   Ky vong: mot blockchain.payment.reversal + mot activity. KHONG phai tx.state doi.

5. Do tre end-to-end tren testnet Chiado: tu luc broadcast den luc invoice.state='paid'.
   Ky vong < 15s voi _trigger, < 10 phut neu quen no. Do ca hai de con so co y nghia.

6. forge test --gas-report tren PaymentRouter, CREATE2 factory, VoucherClaim,
   va Zether verifier. Snapshot gas vao CI: bang §09.10a la uoc tinh cho toi khi co snapshot.

7. Sai chain: gui USDC toi dia chi derived tren Celo trong khi request o Gnosis.
   Ky vong: unmatched_chain + van sweep duoc (cung factory, cung salt).
   Neu khong sweep duoc -> R1 chua trien khai dung (§09.6).

8. [BAN 2] Kiem xuat xu token: tao mot money.flow tro toi mot token co factory() tra
   ve mot dia chi la. Ky vong: provider KHONG enable duoc, va thong bao noi ro dia chi
   factory nao duoc chap nhan (§09.4, §09.5).

9. [BAN 2] Hai token cung ten: dang ky zDAI-A va zDAI-B tren cung mot chain, chi chap
   nhan A. Gui B toi dia chi derived. Ky vong: unmatched_token, va thong bao neu DIA CHI
   CONTRACT duoc chap nhan, khong chi ten token (§09.7).

10. [BAN 2] Deterministic deployer tren chain private:
    cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC_9000
    Khong co code -> R1 khong chay duoc o do, phai bootstrap deployer truoc (§09.6 R1).
```

---

### 09.11. Chỗ note gốc chưa đủ, và quyết định đã chọn

| Chỗ thiếu / rủi ro trong `blockchain.md` | Quyết định ở section này |
|---|---|
| Note không hề nói đến lớp payment của Odoo — chỉ nói "ERP/SoR" chung chung | Phân lớp 6 addon (§09.0); một deployment có thể chỉ cài core |
| Note nói *"chỉ phát tín hiệu xác nhận cho ERP khi đạt Finality Depth"* nhưng không nói làm gì khi soft-final bị reorg **sau khi** đã ghi sổ | `blockchain.payment.reversal` + bút toán điều chỉnh; không đảo ngược `done`; `soft_final_max_amount` đặt bằng công thức tổn thất kỳ vọng (§09.7) |
| Note giả định mọi giao dịch đều đi qua Gateway của ta. Trường hợp người trả dùng ví riêng, không chạm app — chiếm phần lớn giao dịch B2B thực tế — không được nhắc đến | R1 địa chỉ CREATE2 riêng mỗi request, cùng factory/salt/initCodeHash trên mọi chain EVM (§09.6, §09.8) |
| Note không có cơ chế reference/memo nào. EVM `ERC20.transfer` không có trường memo — đây là lỗ hổng thực thi, không phải chi tiết | Router contract `pay(token, amount, bytes32 ref)` cho EVM; memo native cho 5 chain còn lại (bảng §09.6); mở rộng `_get_communication()` có sẵn thay vì đặt tên mới |
| Note không nói về refund | Refund là tx mới; `support_refund='none'` mặc định; chỉ hoàn về địa chỉ đã xác minh bằng chữ ký challenge, không bao giờ về `from` (§09.7) |
| Zether + payment gateway không tương thích — note không nhận ra | `_extract_amount_data` trả `None` (tiền lệ `payment_custom`); khuyến nghị M4 thay vì M1 (§09.9) |
| Note không đặt giới hạn trên số tiền cho soft finality | `soft_final_max_amount` (đề xuất $200) + `soft_final_exposure_cap` (đề xuất $5.000) |
| **Note ghi Gnosis hard finality "12,8 phút"** | Sai: đó là con số Ethereum. Gnosis 16 slot/epoch × 5s ⇒ 2 epoch ≈ **160s** (§09.7) |
| **Note mô tả Celo là "IBFT 2.0, 1 block immediate finality"** | Lỗi thời: Celo đã là **L2 OP-Stack** từ 2025 (§03.3.8 cũng coi vậy). Soft ~1s từ sequencer, hard = khi batch finalize trên L1 (~15–20 phút). Adapter viết theo mô tả cũ sẽ coi soft là hard |
| Note cite **CIP-52** cho fee currency | CIP-52 là thư mục fee currency; **CIP-64** mới là tx type mang trường `feeCurrency`. Adapter cần đúng số hiệu tx type, không phải số hiệu CIP của thư mục |
| **Note ước Zether 180–250k gas** | Sai 15–20 lần; đã sửa theo §03.3.6/§03.3.7 (1,88 M / 3,87 M). Hệ quả thật: trần **31.300 tx/ngày** trên Gnosis, không phải chi phí (§09.9, §09.10a) |
| Note không nói gì về tỷ giá fiat/token | `blockchain.payment.quote`, tỷ giá lưu dạng phân số nguyên, `rate_source` bắt buộc (§09.7b) |
| Note không nói ai là người trả khi khách vãng lai | Ba chính sách partner, mặc định theo flow, ngưỡng Travel Rule $1.000 (§09.8b) |
| Note không nhắc fiat on/off-ramp — nhưng outlet VN thu tiền mặt | M16, và nó là **cổng pháp lý**, không phải task kỹ thuật |
| §05 dùng `dms.blockchain.*`, §01/02/06 dùng `blockchain.*` | Chốt `blockchain.*`; và `amount_base` (Char) theo §15, không phải `amount_token_units` |
| **[BẢN 2] Cả note lẫn bản 1 giả định token là của ta** | Trên factory mở, `money.flow` có thể trỏ tới token của người lạ. Thêm `token_id` vào binding, thêm kiểm xuất xứ bắt buộc trước khi enable, và đừng giả định schema event (§09.4, §09.5, §09.6) |
| **[BẢN 2] Bản 1 mô tả chain private là QBFT/IBFT instant-final, block 1s, ~500 tx/s** | Cả bốn con số sai. Thật: **Nethermind + Clique, một signer, block 5s, không instant-final, trần ~45 confidential tx/s** (§01.1.16, §01.1.12.2). Kết luận "private trước" không đổi; lý do phải phát biểu lại |

#### Lộ trình mặc định (nếu không ai quyết định gì khác)

| Giai đoạn | Chế độ bật | Chain | Lý do dừng ở đây |
|---|---|---|---|
| P0 (tuần 1–2) | **M0** | — | Thu được tiền thật trước khi viết dòng code nào. Và nó là đường lui vĩnh viễn |
| P1 (tháng 1–3) | M1 + M6 + M11 + M4 | Gnosis, `chain_profile='public'`, `finality_mode='hard'` | Đường xuống nguồn nóng nhất, chưa có Zether |
| P2 (tháng 3–5) | + M17, M15, M12 | Gnosis | Giảm 97% số giao dịch B2B trước khi tối ưu gas |
| P3 (tháng 5–8) | + M13/M4 Zether | **Private chain trước** (quyết định #5) | Public chain không cho đủ block space (§09.9) |
| P4 | + M7/M10, Celo adapter | Celo | Chỉ khi đã có nhu cầu thật; Celo là L2, không phải IBFT |
| Bất kỳ lúc nào | M2 | — | Nếu doanh số crypto < ~$300k/năm thì M2 rẻ hơn tự chạy (§09.2 M2) |
| Không bao giờ | M19 | — | M15 đạt 97% lợi ích với 5% độ phức tạp |