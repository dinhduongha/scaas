## 15. Lớp settlement thống nhất và đối soát với kế toán

> Section 10 là canonical về tên model và ACL. Section này **không định nghĩa lại** `blockchain.settlement`; nó
> bổ sung những thứ section 10 chưa có: (a) tầng batch và hệ quả atomicity on-chain, (b) crash-safety từng bước,
> (c) cầu kế toán `account.move` và FX, (d) routine đối soát drift, (e) hợp đồng callback ngược về consumer.
> Chỗ nào lệch với §10 được đánh dấu **[SỬA §10]**. Chỗ nào bản nháp cũ của chính section này sai được đánh dấu
> **[SỬA §15 v1]** — có bảy chỗ, và ba trong số đó là sai sự thật về model `dms` chứ không phải sai thiết kế.

---

### 15.0. Mười giả định bản nháp không nói ra

Mỗi dòng dưới đây là một thứ bản nháp **coi là hiển nhiên**. Nếu một trong chúng sai ở deployment thật, thiết kế
hỏng theo một cách không có cảnh báo.

| # | Giả định ngầm | Nếu sai thì sao | Chốt ở đây |
|---|---|---|---|
| A1 | Một `blockchain.settlement` có đúng một người nhận | Payout "1 brand → 300 NPP" không còn là 300 settlement mà là 300 line trong một record, và toàn bộ lập luận §15.1 sụp | Giữ A1 **là một bất biến có thể kiểm tra**: `payee_account_id` là `required` khi `transport='onchain'` |
| A2 | Consumer luôn có thể sinh một `origin_key` **ổn định** trước khi gọi | Retry sau crash sinh key mới ⇒ chi trả hai lần. Đây là chế độ hỏng đắt nhất trong cả section | §15.3.4: key phải là hàm thuần của chứng từ, **không** chứa timestamp, không chứa `uuid4()` |
| A3 | Chain là nguồn sự thật về **đã xảy ra**, Odoo là nguồn sự thật về **định làm gì** | Nếu đảo chiều, một reorg sẽ ghi đè một quyết định nghiệp vụ | §15.2.6 |
| A4 | Một settlement `final` không bao giờ quay lại | `finalized` tag nói dối được (§11.3b), chain private rewind được | Thêm state `disputed`. **`final` không còn là terminal tuyệt đối** |
| A5 | Odoo đọc được số tiền của mọi settlement | Với Zether và không giữ khoá, không đọc được | §15.4.8 + §15.5.5 |
| A6 | `account` đã được cài và cấu hình xong | Mode 4 mặc định chạy không có `account`; và khi có `account`, vẫn còn **bốn** thứ phải cấu hình trước khi post được dòng đầu tiên | §15.4.1 |
| A7 | Một settlement sinh đúng một bút toán | Netting sinh ba; compensation sinh một bút toán độc lập; batch mode 4 sinh một bút toán cho **N** settlement | `gl_state` là một máy trạng thái **riêng**, không phải một Boolean |
| A8 | Tỷ giá trong ngày là đủ | USDC rơi về ~$0.87 trong phiên 11/03/2023 (depeg SVB), lệch ~13% so với rate cuối ngày | §15.4.5: rate phải có `fx_rate_datetime`, không chỉ `date` |
| A9 | Relayer fee và gas là chi phí của ai đó khác | Chúng là chi phí thật, bằng token thật, và nếu không vào sổ thì sub-ledger và GL không bao giờ khớp | §15.4.2 có bút toán cho cả hai |
| A10 | Đối soát chạy được bằng cách "hỏi chain" | Không RPC nào trả lời "mọi transfer đến địa chỉ X từ trước tới nay". Phải có indexer | §15.5.3: hướng (A) là anti-join với `blockchain.chain.effect` của §11, **không** phải một lệnh gọi RPC |
| **A11** | **[BẢN 3] Một `token_symbol` xác định được một token** | Factory mở: mười người wrap xDAI ra mười contract khác nhau, tất cả tự gọi mình là `zDAI` (§20.3). Một settlement ghi `token_symbol='zDAI'` không nói được nó là zDAI của ai | `token_id` (Many2one tới `blockchain.token`, tức tới một **địa chỉ**) là bắt buộc; `token_symbol` chỉ là nhãn hiển thị. §09.4 đã sửa; ghi lại ở đây vì batch cũng khoá theo token |

---

### 15.1. Settlement là "ý định chuyển giá trị", không phải "giao dịch"

#### 15.1.1. Ba trục độc lập

Một ràng buộc phải nói trước vì nó quyết định mọi thứ còn lại: **`blockchain.settlement` không tương ứng 1-1 với
một transaction on-chain.** Ánh xạ thật là N-1: nhiều settlement dùng chung một `blockchain.transaction` (batch
payout), và một settlement có thể trải qua nhiều transaction (replace-by-fee, retry sau khi drop). Nếu ai đó thiết
kế với giả định 1-1, bước đầu tiên làm vỡ nó là brand trả 300 nhà phân phối trong một tx.

| Trục | Model | Đơn vị | Ai sở hữu |
|---|---|---|---|
| **Ý định nghiệp vụ** | `blockchain.settlement` | Một khoản tiền, một bên nhận, một `origin_key`. Đơn vị idempotency và đơn vị kế toán. | Consumer (bridge) |
| **Vận chuyển** | `blockchain.settlement.batch` | Một lô được gửi cùng nhau. Đơn vị tối ưu gas, **đơn vị lane 2D nonce**, đơn vị retry. | Core |
| **Sự thật on-chain** | `blockchain.transaction` / `blockchain.chain.effect` (§11) | Cái đã xảy ra. Đơn vị finality và đơn vị reorg. | Indexer |

Trục thứ hai là thứ §10 thiếu. Bổ sung.

#### 15.1.2. `blockchain.settlement.batch`

```python
class BlockchainSettlementBatch(models.Model):
    _name = 'blockchain.settlement.batch'
    _description = 'Transport batch for settlements'
    _inherit = ['mail.thread']
    _order = 'id desc'

    name            = fields.Char(required=True, copy=False, default='/')
    company_id      = fields.Many2one('res.company', required=True, index=True,
                                      default=lambda s: s.env.company)
    origin_key      = fields.Char(required=True, index=True)      # idempotency cua chinh lo
    chain_id        = fields.Many2one('blockchain.chain', required=True, index=True)
    token_id        = fields.Many2one('blockchain.token', required=True, index=True)
    payer_account_id= fields.Many2one('blockchain.account', required=True, index=True)
    settlement_ids  = fields.One2many('blockchain.settlement', 'batch_id')
    atomicity       = fields.Selection([('atomic', 'Mot tx, tat ca hoac khong'),
                                        ('chunked', 'Nhieu tx, thanh cong tung phan la binh thuong')],
                                       required=True, default='chunked')
    chunk_size      = fields.Integer(required=True, default=150)
    line_count      = fields.Integer(compute='_compute_totals', store=True)
    total_base      = fields.Char(compute='_compute_totals', store=True)
    settled_count   = fields.Integer(compute='_compute_totals', store=True)
    failed_count    = fields.Integer(compute='_compute_totals', store=True)
    batch_state     = fields.Selection([
        ('draft', 'Draft'), ('authorized', 'Authorized'), ('submitted', 'Submitted'),
        ('partial', 'Partially final'), ('final', 'Final'),
        ('failed', 'Failed'), ('compensating', 'Compensating')],
        required=True, default='draft', index=True, tracking=True)
    chunk_ids       = fields.One2many('blockchain.settlement.batch.chunk', 'batch_id')

    _unique_batch_origin = models.Constraint(
        'UNIQUE(company_id, origin_key)', 'origin_key cua batch phai duy nhat trong mot cong ty.')
    _check_chunk_size = models.Constraint(
        'CHECK (chunk_size BETWEEN 1 AND 500)', 'chunk_size phai trong khoang 1..500.')


class BlockchainSettlementBatchChunk(models.Model):
    """Mot chunk = mot metatx = mot lane 2D nonce = (co the) mot transaction.

    Ban nhap khong co model nay va do la mot lo hong: khong co no thi mot batch
    `chunked` khong co cho nao de ghi "chunk 3/7 that bai, chunk 4..7 chua gui".
    """
    _name = 'blockchain.settlement.batch.chunk'
    _description = 'One transport chunk of a settlement batch'
    _order = 'batch_id, sequence'

    batch_id       = fields.Many2one('blockchain.settlement.batch', required=True,
                                     index=True, ondelete='cascade')
    sequence       = fields.Integer(required=True, default=0)
    settlement_ids = fields.One2many('blockchain.settlement', 'chunk_id')
    metatx_id      = fields.Many2one('blockchain.metatx', index=True)
    transaction_id = fields.Many2one('blockchain.transaction', index=True)
    chunk_state    = fields.Selection([
        ('draft', 'Draft'), ('signed', 'Signed'), ('submitted', 'Submitted'),
        ('broadcast', 'Broadcast'), ('final', 'Final'),
        ('reverted', 'Reverted'), ('dropped', 'Dropped'), ('expired', 'Expired')],
        required=True, default='draft', index=True)
    attempt_count  = fields.Integer(required=True, default=0)

    _unique_chunk = models.Constraint(
        'UNIQUE(batch_id, sequence)', 'Mot chunk sequence chi ton tai mot lan trong mot batch.')
```

`_compute_totals` là stored computed: **phải gán giá trị ở mọi nhánh**, kể cả khi `settlement_ids` rỗng, và
**không được nhận `default=`** (Odoo bỏ qua `default` trên stored computed). Đặt bốn dòng gán mặc định ở **đầu**
method, trước mọi `if`:

```python
@api.depends('settlement_ids.amount_base', 'settlement_ids.settle_state')
def _compute_totals(self):
    for rec in self:
        rec.line_count = 0
        rec.total_base = '0'
        rec.settled_count = 0
        rec.failed_count = 0
        lines = rec.settlement_ids
        if not lines:
            continue
        rec.line_count = len(lines)
        rec.total_base = str(sum(int(s.amount_base or '0') for s in lines))   # int Python, khong float
        rec.settled_count = len(lines.filtered(lambda s: s.settle_state == 'final'))
        rec.failed_count = len(lines.filtered(lambda s: s.settle_state in ('failed', 'expired')))
```

Hai chi tiết không hiển nhiên:

1. `sum(int(...))` dùng số nguyên Python (không giới hạn bit), **không** `float`. Một tổng 300 × 10^24 base units
   vượt `2^53` và `float` sẽ làm tròn im lặng. Đây là cùng lý do §10.4.1 cấm `fields.Float` cho `amount_base`.
2. `total_base` là `Char` nên **không group by hay so sánh số học được trong domain**. Báo cáo tổng theo lô phải
   dùng `amount_display` (Float, §10.4.1) hoặc `read_group` trên một cột Numeric phụ. Cách dùng: một index biểu thức
   `CREATE INDEX ... ON blockchain_settlement ((amount_base::numeric))` khai qua `init()`, và các truy vấn đối soát
   của §15.5 dùng SQL trực tiếp chứ không qua ORM. Viết ra vì đây là thứ sẽ bị phát hiện vào đúng lúc một báo cáo
   tổng đầu tiên được yêu cầu.
#### 15.1.3. Vì sao không phải "một settlement, nhiều line"

Đề xuất header/line nghe hợp lý và sai ở đúng một chỗ: **trạng thái**. Một payout tới 300 nhà phân phối có 300 kết
cục độc lập — một địa chỉ bị đóng băng KYC, một địa chỉ gõ sai, một bên chưa register Zether. Nếu cả 300 nằm trong
một record thì `settle_state` phải nói dối về 299 dòng còn lại, `origin_key` không còn là khoá idempotency của từng
khoản chi, và bridge không có chỗ để ghi ngược trạng thái về từng chứng từ gốc. Ngược lại, batch chỉ là một nhãn
vận chuyển: mất nó không mất gì, tạo lại nó không mất gì.

**[SỬA §15 v1] Và có một lý do mạnh hơn bản nháp không biết: trong `dms`, "300 nhà phân phối" vốn đã là 300 record.**
`dms.trade.settlement` có đúng một `beneficiary_partner_id` (`required=True`), và `amount` là computed từ
`claim_ids.approved_amount`. Không tồn tại một chứng từ DMS nào mang N người nhận. Vậy ánh xạ 1 settlement ↔ 1 chứng
từ là **ánh xạ tự nhiên**, không phải một lựa chọn phải biện hộ. Bản nháp dẫn `dms.trade.settlement.line` làm ví dụ
"payout line" — sai, xem §15.6.0.

#### 15.1.4. Độ lớn: bao nhiêu record, bao nhiêu batch

Ước tính, cơ sở: deployment DMS 5,000 outlet, 500 nhà phân phối, chu kỳ settlement tháng.

| Đối tượng | Số lượng/năm | Ghi chú |
|---|---|---|
| `blockchain.settlement` (B2B payout) | 500 × 12 = 6,000 | 1/NPP/tháng |
| `blockchain.settlement` (outlet collection) | 5,000 × 250 ngày = 1,250,000 | dòng lớn nhất |
| `blockchain.settlement` (loyalty) | ~200,000 | phụ thuộc chương trình |
| `blockchain.settlement.batch` | 12 (B2B) + 250 (collection theo ngày) + 12 (loyalty) ≈ 274 | rất ít |
| `blockchain.settlement.batch.chunk` | 12 × ceil(500/150) = 48, cộng collection | |
| Dung lượng `blockchain_settlement` + index | ~1.2 GB/năm (ước tính, cơ sở ~400 B/dòng kể cả 8 index) | |

Kết luận làm việc: **bảng settlement là bảng lớn, bảng batch là bảng nhỏ.** Mọi index đặt trên settlement phải
được biện hộ; mọi index trên batch là miễn phí.

---

### 15.2. Vòng đời và nơi crash

#### 15.2.1. Bảng chuyển trạng thái đầy đủ

Bản nháp vẽ một sơ đồ và bỏ trống cột "ai được phép". Đó là cột quan trọng nhất: một máy trạng thái không nói ai
bấm nút là một máy trạng thái chưa được thiết kế.

**[SỬA §10]** `reversed` đổi thành `compensated`; thêm `disputed`. Lý do `compensated` không phải thẩm mỹ:
`reversed` gợi ý một phép đảo trên chính bản ghi cũ, mà sổ cái on-chain không có UNDO. `compensated` mô tả đúng cơ
chế: một settlement mới, chiều ngược, có `origin_key` riêng, có tx riêng, trỏ về bản gốc bằng `compensation_of_id`.
Bản gốc vẫn `final` vĩnh viễn — vì nó *đã* xảy ra.

```
draft ──authorize──▶ authorized ──submit──▶ submitted ──worker claim──▶ broadcast
  │                      │                      │                          │
  │                      └──cancel──▶ failed    └──expiry──▶ expired  mined │
  │                                                                          ▼
  └──expiry sweep──▶ expired                              pending_finality ──Finality Gate──▶ final
                                          reverted/dropped ──▶ failed                          │
                                                                          reorg / anchor gap ──┤
                                                                                                ▼
                                                                                            disputed
final ──(mot settlement nguoc chieu, khong bao gio write nguoc)──▶ ban goc van final, ban moi la compensated
```

| Từ | Đến | Ai/cái gì kích hoạt | Nhóm | Điều kiện cứng |
|---|---|---|---|---|
| `draft` | `authorized` | `blockchain_authorize_payout` | **treasury** | pre-flight pass (dưới) |
| `draft` | `expired` | `_cron_expire_settlements` | hệ thống | `create_date + settlement_ttl_hours < now` |
| `authorized` | `submitted` | `_cron_advance_authorized` hoặc `blockchain_submit_settlement` | operator/hệ thống | có metatx đã ký, có `blockchain.relay.job` |
| `authorized` | `failed` | `blockchain_cancel_settlement` | treasury | chưa có tx nào |
| `submitted` | `broadcast` | relay worker ghi `tx_hash` | hệ thống | `UNIQUE(chain_id, tx_hash)` |
| `submitted` | `expired` | `_cron_expire_metatx` | hệ thống | `metatx.expiry_datetime < now` và chưa có tx |
| `broadcast` | `pending_finality` | `_cron_poll_receipts` | hệ thống | receipt `status == 1` |
| `broadcast` | `failed` | `_cron_poll_receipts` | hệ thống | receipt `status == 0` (reverted) |
| `broadcast` | `submitted` | replace-by-fee | hệ thống | quá `finality_warn_seconds`, cùng lane |
| `pending_finality` | `final` | **chỉ** `_set_finality` | hệ thống | §11.3 gate: `finality_source` thoả + hash check |
| `pending_finality` | `failed` | `_cron_poll_receipts` | hệ thống | tx bị `dropped` và lane đã bị một tx khác chiếm |
| `final` | `disputed` | `_cron_reorg_watch` (§11.4) hoặc `_cron_anchor_verify` | hệ thống | block chứa tx không còn trên canonical chain |
| `disputed` | `final` | `blockchain_resolve_dispute` | **treasury** + auditor | người thật xác nhận sau khi đọc bằng chứng |
| `disputed` | `compensated` | tạo settlement ngược | treasury | |

**Pre-flight trước khi cho `authorized`** — bản nháp không có, và thiếu nó thì tiền đi ra rồi mới biết địa chỉ sai:

```python
def _preflight(self):
    """Tra ve list ly do khong the authorize. Rong = pass. KHONG raise: caller can biet TAT CA ly do."""
    self.ensure_one()
    r = []
    if self.chain_id.state != 'enabled':                      r.append('chain_not_enabled')
    if self.transport == 'onchain' and not self.payee_account_id: r.append('no_payee_account')
    if self.payee_account_id.state != 'active':               r.append('payee_frozen')
    if self.token_id not in self.chain_id.token_ids:          r.append('token_not_on_chain')
    if not self.token_id.provenance_verified:                 r.append('token_provenance_unverified')
    if self.confidential and not self.payee_account_id.zether_registered: r.append('payee_not_registered')
    if int(self.amount_base) <= 0:                            r.append('non_positive_amount')
    if int(self.amount_base) > int(self.token_id.max_amount_base or '0'): r.append('exceeds_token_max')
    return r
```

`payee_not_registered` là lý do đúng nhất để một batch Zether 300 người thất bại ở dòng thứ 47, và nó phát hiện
được **trước** khi trả một xu gas. Với Zether, `registry.isRegistered(to)` là một `eth_call` — 300 lần gọi là một
multicall, không phải 300 round-trip.

**[BẢN 3] `token_provenance_unverified` là dòng mới, và nó là dòng quan trọng nhất trong danh sách này.** Trong một
factory mở, `token_id` trỏ tới một địa chỉ mà bất kỳ ai cũng deploy được. §10.4.4 bắt Odoo đọc `factory()`,
`version()` và `EXTCODEHASH` từ chuỗi và so với catalogue trước khi đặt `provenance_verified = True`. Không có dòng
này thì một nhân viên gõ nhầm địa chỉ zDAI-B thay vì zDAI-A sẽ chi trả bằng một token khác, cùng ký hiệu, khác giá
trị, và không có gì trong hệ thống kêu lên.

#### 15.2.2. Ép bằng code, không bằng tài liệu

§10.11 kiểm chứng #8 đòi một test rằng không đường nào ghi `final` ngoài `_set_finality`. Cơ chế:

```python
_ALLOWED = {
    'draft': {'authorized', 'expired', 'failed'},
    'authorized': {'submitted', 'failed', 'expired'},
    'submitted': {'broadcast', 'expired', 'failed'},
    'broadcast': {'pending_finality', 'failed', 'submitted'},
    'pending_finality': {'final', 'failed'},
    'final': {'disputed'},
    'disputed': {'final', 'compensated'},
    'failed': set(), 'expired': set(), 'compensated': set(),
}

def write(self, vals):
    new = vals.get('settle_state')
    if new:
        privileged = self.env.context.get('blockchain_state_engine')
        for rec in self:
            if new == rec.settle_state:
                continue
            if new not in _ALLOWED[rec.settle_state]:
                raise UserError(_('Chuyen trang thai %s -> %s khong hop le.', rec.settle_state, new))
            if new == 'final' and not privileged:
                raise UserError(_('Chi Finality Gate duoc ghi final.'))
    return super().write(vals)
```

`_set_finality` là bên duy nhất đặt sentinel này vào context. **[BẢN 3] Và nó phải là một object sentinel của
module, không phải giá trị `True`** — một khoá boolean trong context là thứ client gửi lên được qua `call_kw` hoặc
`/json/2`, nên `context.get('blockchain_state_engine') is _STATE_ENGINE` là điều kiện đúng, còn
`context.get(...) == True` là một lỗ hổng. Hàng rào thật vẫn là ACL: `perm_write` trên `blockchain.settlement`
không bao giờ cấp cho `group_blockchain_viewer`, và `_set_finality` chỉ được gọi từ cron chạy bằng `sudo()`.

Ba field vòng đời bắt buộc phải có, §10 chưa liệt kê:

```python
authorized_uid      = fields.Many2one('res.users', readonly=True)
authorized_datetime = fields.Datetime(readonly=True)          # khong dat ten 'date'
gl_state            = fields.Selection([('not_required', 'Khong sinh but toan'),
                                        ('queued', 'Cho post'), ('posted', 'Da post'),
                                        ('failed', 'Post that bai'), ('reversed', 'Da dao')],
                                       required=True, default='not_required', index=True)
gl_move_ref         = fields.Many2oneReference(model_field='gl_move_model')  # khong depend account o core
gl_move_model       = fields.Char()
gl_error            = fields.Char()
batch_id            = fields.Many2one('blockchain.settlement.batch', index=True, ondelete='set null')
chunk_id            = fields.Many2one('blockchain.settlement.batch.chunk', index=True, ondelete='set null')
compensation_of_id  = fields.Many2one('blockchain.settlement', index=True)
notified_datetime   = fields.Datetime(readonly=True, index=True)
```

`gl_state` tách rời khỏi `settle_state` là quyết định quan trọng nhất của mục này. Xem §15.4.4.

#### 15.2.3. Lane 2D nonce thuộc về BATCH, không thuộc về settlement

**[SỬA §15 v1]** Bản nháp suy lane từ `origin_key` của **settlement**. Sai khi có batch: một chunk 150 settlement
là **một** metatx, nên nó chỉ có **một** `(batchId, batchNonce)`. Nếu mỗi settlement suy ra một lane riêng thì hoặc
lane bị bỏ qua, hoặc ta phải chọn tuỳ tiện lane của settlement nào trong 150.

Chốt lại:

```python
def _lane(self):
    """batchId la ham thuan cua (chain, company, origin_key CUA DON VI VAN CHUYEN).
    Don vi van chuyen = chunk neu co batch, = chinh settlement neu di le.
    Retry sau crash sinh ra DUNG lane cu, nen hai chu ky hop le cua cung mot khoan chi
    khong bao gio cung ton tai tren hai lane khac nhau."""
    self.ensure_one()
    unit_key = self.chunk_id and f"chunk:{self.chunk_id.batch_id.origin_key}:{self.chunk_id.sequence}" \
        or f"settlement:{self.origin_key}"
    seed = f"{self.chain_id.caip2}|{self.company_id.id}|{unit_key}".encode()
    return '0x' + keccak(seed).hex()          # eth_utils.keccak, da co trong external_dependencies

# batch_nonce = 0 luon cho mot lane don le. Chuoi phu thuoc (escrow -> deposit -> settle) moi tang
# batch_nonce trong CUNG mot lane, va khi do lane la cua CHUOI chu khong cua tung buoc.
```

Ba hệ quả:

1. `chain_id.caip2` có trong seed ⇒ cùng một `origin_key` settle trên hai chain khác nhau cho hai lane khác nhau.
   Không có nó, một retry sau khi đổi chain sẽ dùng lại lane cũ trên chain mới — vô hại nhưng gây nhầm lẫn khi debug.
2. Một chữ ký bị rò rỉ, bị phát lại, hoặc được hai relayer cùng nộp → tx thứ hai revert vì
   `meta_nonce(from, batchId)` đã tăng. **On-chain là trọng tài, không phải Odoo.** Đây cũng là lý do
   `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` của §10 phải giữ — dưới dạng partial index, để
   một lane đã hết hạn còn thử lại được.
3. Một chi tiết bản nháp không nói: khi metatx hết hạn (`expiry_datetime`) và ta ký lại, digest **khác** (expiry
   khác) nhưng lane **giống**. Kết quả: hai chữ ký hợp lệ trên cùng lane. Nếu cả hai cùng được nộp, cái thứ hai
   revert. Đúng, nhưng phải ghi rõ trong runbook, vì một relayer sẽ báo "tx của tôi revert" và đó là hành vi đúng.

#### 15.2.4. Outbox, không phải RPC trong request

Lệnh gọi relay worker **không được** nằm trong transaction của `blockchain_submit_settlement`. Nếu gọi, hai chế độ
hỏng đều thật: HTTP thành công rồi transaction rollback (worker broadcast một khoản chi Odoo không còn biết), hoặc
transaction commit rồi HTTP timeout (không ai biết worker có nhận hay không).

Chốt: ghi một dòng `blockchain.relay.job` trong **cùng** transaction với `settle_state='submitted'`; worker poll.
Đó là transactional outbox, và nó là lý do `bamboo_idempotency` (§11.5) phải là dependency.

Model này bản nháp gọi tên mà không định nghĩa:

```python
class BlockchainRelayJob(models.Model):
    _name = 'blockchain.relay.job'
    _description = 'Transactional outbox row for the relay worker'
    _order = 'priority desc, id'

    chunk_id     = fields.Many2one('blockchain.settlement.batch.chunk', index=True, ondelete='cascade')
    settlement_id= fields.Many2one('blockchain.settlement', index=True, ondelete='cascade')
    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True)
    payload_attachment_id = fields.Many2one('ir.attachment')   # metatx + signature, len Garage
    payload_sha256 = fields.Char(index=True)                   # khong dung size=: xem §10.4.0(1)
    priority     = fields.Integer(required=True, default=0)
    job_state    = fields.Selection([('ready', 'Ready'), ('claimed', 'Claimed'), ('done', 'Done'),
                                     ('dead', 'Dead letter')], required=True, default='ready', index=True)
    claimed_by   = fields.Char()                    # worker id
    claimed_datetime = fields.Datetime(index=True)
    attempt_count= fields.Integer(required=True, default=0)
    last_error   = fields.Char()
    bamboo_uuid  = fields.Uuid(index=True)          # bamboo_idempotency, §11.5

    _check_target = models.Constraint(
        'CHECK (chunk_id IS NOT NULL OR settlement_id IS NOT NULL)',
        'Mot relay job phai tro toi mot chunk hoac mot settlement.')
```

Bốn chi tiết vận hành bản nháp bỏ qua:

1. **Worker claim bằng `SELECT ... FOR UPDATE SKIP LOCKED`**, không bằng `write({'job_state': 'claimed'})` sau một
   `search`. `search` rồi `write` là một race được trang trí thành một bảo đảm. Odoo cho phép SQL thô ở đây; đây là
   đúng chỗ để dùng nó.
2. **`claimed` có timeout.** Một worker chết giữa chừng để lại một job `claimed` vĩnh viễn. Cron
   `_cron_reap_stale_jobs()` trả job về `ready` khi `claimed_datetime < now - 5 min` **và** chunk chưa có `tx_hash`.
   Nếu chunk **đã có** `tx_hash`, không trả về — đó là trường hợp worker đã broadcast xong.
3. **Dead letter sau 5 lần.** Backoff 1/5/15/60/240 phút rồi `job_state='dead'` + `mail.activity` cho
   `group_blockchain_treasury`. Một cron retry vô hạn trên một lỗi cấu hình tạo 1,440 activity/ngày và không ai đọc.
   (Cùng quy tắc §11.5.)
4. **Độ trễ.** Poll 1 phút là quá chậm cho `ENDUSER_PAY` (§09.5d). Dùng
   `self.env.ref('dms_blockchain.cron_relay_dispatch').sudo()._trigger()` ngay sau khi tạo job — `_trigger()` của
   Odoo 19 lập lịch một lần chạy ngay mà **không** gọi HTTP trong transaction; nó chỉ ghi một dòng
   `ir_cron_trigger`, và dòng đó rollback cùng transaction nếu transaction hỏng. Đó là đúng tính chất ta cần.

#### 15.2.5. Bảng crash

Đọc theo cột giữa: "sau crash, trên đĩa có gì". Mọi dòng đều phải an toàn **mà không cần người**.

| Crash tại | Trên đĩa | Phục hồi |
|---|---|---|
| Sau `submit` RPC, trước commit | Không có gì | Client retry cùng `origin_key`; `_submit` trả bản ghi cũ hoặc tạo mới. Idempotent. |
| Sau khi tạo settlement `draft` | `draft` | Không làm gì. `draft` không tiêu tốn tài nguyên nào. Expiry sweep dọn sau `settlement_ttl_hours`. |
| Sau `authorized`, trước khi build metatx | `authorized` | `_cron_advance_authorized()` build lại metatx từ lane suy diễn. |
| Sau khi gọi custody ký, trước commit | `authorized`, chữ ký mất | Ký lại. Digest giống hệt khi expiry chưa đổi; nếu đổi thì digest khác nhưng **lane giống** (§15.2.3). Chữ ký cũ nếu đã rò rỉ thì vô hại. |
| Sau commit `submitted` + `relay.job`, trước khi worker đọc | `submitted` + job `ready` | Worker poll thấy job. **Không bao giờ gọi worker trong cùng request transaction.** |
| Worker đã claim, chết trước khi broadcast | job `claimed`, không có tx | `_cron_reap_stale_jobs()` trả về `ready` sau 5 phút. An toàn vì lane chưa bị tiêu. |
| Worker đã broadcast, Odoo chưa ghi `tx_hash` | `submitted`, chain có tx | Worker retry ghi; `UNIQUE(chain_id, tx_hash)` chặn trùng. Nếu worker cũng chết: `_cron_reconcile_orphan_tx()` quét tx từ `payer_account` có `ref` khớp lane → gắn lại. |
| Batch `chunked`: chunk 3/7 broadcast, crash | 3 chunk có tx, 4 chunk `draft` | Cron tiếp tục từ `sequence` nhỏ nhất còn `draft`. **Không** gửi lại chunk đã có tx. `batch_state='partial'`. |
| Batch `atomic`: chunk duy nhất revert | 0 settlement `final` | Cả batch → `failed`. Không có gì để bù. Đây là lý do `atomic` chỉ được dùng khi nghiệp vụ đòi vậy. |
| Sau `broadcast`, node drop tx | `broadcast` quá `finality_warn_seconds` | Cảnh báo. Quá `finality_stuck_seconds` (§11.3) → replace-by-fee cùng lane, hoặc `failed` + page người thật. |
| Giữa `_set_finality` và post `account.move` | `final` + `gl_state='queued'` | Cron `_cron_post_gl()` post sau. **Đây là chỗ duy nhất cần hai transaction.** Xem §15.4.4. |
| Sau khi post `account.move`, trước khi ghi `gl_state='posted'` | move đã post, `gl_state='queued'` | **Post lần hai là một bút toán trùng.** Chặn bằng `bamboo_create_idempotent` trên một khoá `uuid5(NS_GL, settlement.uuid)` **cùng transaction** với `move.action_post()`, dùng nguyên mẫu §11.5b. |
| Sau `final`, trước callback bridge | `final`, consumer chưa biết | `_cron_notify_origin()` đọc `notified_datetime IS NULL`, không qua post-commit hook. |
| Reorg xoá block chứa tx đã `final` | `final` sai sự thật | §15.2.6: `disputed`, **không** tự động quay về. |
| Compensation đã tạo, chưa broadcast, crash | settlement mới `draft` có `compensation_of_id` | Bình thường. Bản gốc vẫn `final`. |

**Cái bẫy tinh vi nhất, viết ra vì nó không nhìn thấy được:** `_apply` của GL và callback bridge đều có thể chạm
hệ thống ngoài và đều **phải idempotent theo chính nó**, không chỉ dựa vào việc được gọi một lần. Mẫu:

```python
def _post_gl(self):
    self.ensure_one()
    if self.gl_state == 'posted':
        return                                  # goi lai la vo hai
    ...
```

#### 15.2.6. Reorg sau `final`: state `disputed`

Bản nháp không có mục này và đó là một lỗ hổng nghiêm trọng: nó giả định Finality Gate không bao giờ sai. §11.3b
liệt kê ba cách `finalized` tag nói dối, và §11.3 ghi rõ chain private **rewind được bởi chính operator**.

Quy tắc:

- Khi `_cron_reorg_watch` (§11.4) thấy block chứa `transaction_id` không còn trên canonical chain:
  `settle_state: final → disputed`, `gl_state` **không đổi**, `mail.activity` cho treasury và auditor.
- **Không tự động đảo bút toán.** Một bút toán đảo tự động trên một sự kiện có thể là lỗi của node là cách nhanh
  nhất để biến một sự cố RPC thành một sự cố kế toán.
- `blockchain_resolve_dispute(origin_key, resolution)` với `resolution ∈ {'confirmed', 'compensate'}`, nhóm
  **treasury**, ghi `mail.thread` lý do. `confirmed` → về `final`. `compensate` → giữ `disputed`, tạo settlement
  ngược, và **khi settlement ngược `final`** thì bản gốc chuyển sang `compensated`.
- Trên chain private, `_cron_anchor_verify()` đối chiếu head hash đã neo (§11.3, HCS 60 s) với head hiện tại. Lệch
  ⇒ mọi settlement `final` sau điểm neo cuối cùng → `disputed`. Chi phí: $53/năm. Giá trị: biến "tôi hứa không
  rewind" thành "rewind quá 60 s là chứng minh được".

  **[BẢN 3] Trên chain 9000 thật, đây không phải phòng xa mà là đường duy nhất.** Nethermind + Clique một signer
  không có `finalized` tag có nghĩa và reorg được bất cứ lúc nào bởi chính người vận hành node. Nếu không neo ra
  ngoài, `final` trên chain đó chỉ là một dòng trong DB của chính ta.

---

### 15.3. Liên kết ngược về chứng từ nghiệp vụ, không depend `dms`

#### 15.3.1. Ba lựa chọn Odoo chuẩn

| Cơ chế | Lưu gì | Search/join | Uninstall consumer | Callback | ondelete |
|---|---|---|---|---|---|
| `fields.Reference` | một `Char` `'model,id'` | **Không** index được theo id; `search` phải so sánh chuỗi; không group by được | Để lại chuỗi trỏ tới model không còn tồn tại | Không | Không có |
| `fields.Many2oneReference` + `Char` model | `int4` id + `Char` model riêng | Index được trên id; `[('origin_model','=',m),('origin_id','in',ids)]` chạy nhanh | Dòng còn lại nhưng không vỡ | Không | **Không có FK, không có ondelete** |
| `models.AbstractModel` mixin | Không lưu gì; định nghĩa hợp đồng method | n/a | n/a | **Có** | n/a |

**Chốt: dùng cả ba, mỗi cái một việc.**

```python
# CORE. Khong depend gi ngoai base + mail + bamboo_idempotency.
class BlockchainSettlement(models.Model):
    _inherit = 'blockchain.settlement'

    origin_key   = fields.Char(required=True, index=True)     # KHOA THAT. Ben nay noi tren RPC.
    origin_model = fields.Char(index=True)                    # 'dms.trade.settlement'
    origin_id    = fields.Many2oneReference(model_field='origin_model', index=True)
    origin_ref   = fields.Reference(selection='_selection_origin_ref', compute='_compute_origin_ref',
                                    inverse='_inverse_origin_ref', store=False)  # CHI de mo record tu UI

    def init(self):
        # Index tong hop: moi truy van nguoc deu la (model, id) doi mot luot.
        tools.create_index(self.env.cr, 'blockchain_settlement_origin_idx',
                           self._table, ['origin_model', 'origin_id'])

    def _notify_origin(self):
        """Goi nguoc consumer. Core khong biet ten model nao ca."""
        Mixin = self.env.registry.get('blockchain.settlement.origin')
        for rec in self:
            model = rec.origin_model
            if not model or model not in rec.env:          # consumer da bi go
                rec.notified_datetime = fields.Datetime.now()
                continue
            cls = rec.env.registry.get(model)
            if not (cls and Mixin and issubclass(cls, Mixin)):
                _logger.warning('settlement %s tro toi %s khong inherit mixin; bo qua callback',
                                rec.id, model)
                rec.notified_datetime = fields.Datetime.now()
                continue
            target = rec.env[model].sudo().browse(rec.origin_id).exists()
            if not target:
                rec.notified_datetime = fields.Datetime.now()
                continue
            if target.company_id and target.company_id != rec.company_id:
                _logger.error('settlement %s (company %s) tro toi %s cua company %s. Tu choi.',
                              rec.id, rec.company_id.id, model, target.company_id.id)
                continue
            target._on_blockchain_settlement(rec)
            rec.notified_datetime = fields.Datetime.now()


class BlockchainSettlementOrigin(models.AbstractModel):
    """Mixin O CORE. Consumer (bridge DMS, hay bat ky ai) inherit no."""
    _name = 'blockchain.settlement.origin'
    _description = 'Business document that can originate a settlement'

    def _blockchain_origin_key(self):
        """Mac dinh on dinh, khong doi khi record duoc sua."""
        self.ensure_one()
        return f"{self._name}:{self.id}"

    def _on_blockchain_settlement(self, settlement):
        """Goi khi settlement doi sang mot trang thai terminal
        (final / failed / expired / compensated / disputed).
        Bat buoc idempotent: co the duoc goi lai sau crash."""
        return

    def blockchain_settlement_ids(self):
        """Khong the khai bao One2many nguoc tren Many2oneReference. Tra ve bang search."""
        self.ensure_one()
        return self.env['blockchain.settlement'].search(
            [('origin_model', '=', self._name), ('origin_id', '=', self.id)])
```

**[SỬA §15 v1]** Bản nháp viết `isinstance(target, type(rec.env['blockchain.settlement.origin']))`. Đúng *tình cờ*
(vì `type()` của một recordset là lớp registry), nhưng nó phụ thuộc một chi tiết nội bộ và đọc ra thì không ai biết
nó kiểm gì. Dạng trên dùng `self.env.registry.get(name)` — đây là API công khai của registry, là idiom Odoo dùng ở
`mail` và `account`, và nó không cần instantiate một recordset chỉ để lấy lớp.

Lý do mixin nằm ở **core** chứ không ở bridge: core là bên *gọi* callback. Nếu hợp đồng nằm trong bridge, core phải
`hasattr`-sniff, và một consumer không phải DMS (một addon khác, một hệ thống ngoài qua RPC) không có chỗ để cắm
vào. Mixin trong core không tạo dependency nào: một `AbstractModel` không có bảng, không có ACL, không có gì để gỡ.

#### 15.3.2. Ba bẫy bảo mật bản nháp không nói

1. **`origin_model` là một chuỗi do client đặt.** `blockchain_submit_settlement` nhận `meta` từ RPC. Nếu bridge
   hoặc client set `origin_model='res.users'`, core sẽ gọi `_on_blockchain_settlement` trên một model không có
   method đó → `AttributeError` trong cron, cron chết, mọi settlement khác dừng lại. Chặn bằng kiểm `issubclass`
   như trên, **và** bằng cách **không** cho `origin_model`/`origin_id` đi qua bề mặt RPC công khai: chúng chỉ được
   đặt bởi code Python trong cùng DB (bridge). RPC ngoài chỉ cung cấp `origin_key`.
2. **Callback chạy `sudo()`.** Bắt buộc, vì cron chạy bằng user hệ thống và record rule của consumer có thể lọc nó
   ra. Nhưng `sudo()` có nghĩa bridge có thể ghi bất cứ đâu — nên callback phải kiểm `company_id` trước, như trên.
3. **`_on_blockchain_settlement` có thể raise.** Một bridge viết vụng sẽ làm cron `_cron_notify_origin` chết giữa
   chừng và các settlement còn lại không bao giờ được thông báo. Bắt từng record trong savepoint:
```python
for rec in batch:
    try:
        with self.env.cr.savepoint():
            rec._notify_origin()
    except Exception:
        _logger.exception('callback origin that bai cho settlement %s', rec.id)
        rec.sudo().notify_error = tools.ustr(sys.exc_info()[1])[:500]
```

#### 15.3.3. `origin_key`: quy ước khi một chứng từ sinh nhiều settlement

`UNIQUE(company_id, origin_producer, origin_key)` là chốt chặn cuối. Netting sinh **ba** settlement từ một cặp
chứng từ; một payout bị compensate sinh **hai**. Nên `origin_key` phải có hậu tố có cấu trúc, không phải một số
tăng dần:

```
<origin_model>:<origin_id>[:<role>][:<attempt>]

dms.trade.settlement:4471                      # payout thuong
dms.trade.settlement:4471:gross_out            # chan gross cua netting
dms.trade.claim:9912:gross_in                  # chan gross nguoc chieu
netting:2026-03:P12345                         # chan net, khoa theo (ky, partner)
dms.trade.settlement:4471:comp:1               # compensation lan 1
```

**Cấm tuyệt đối**: `uuid4()`, `fields.Datetime.now()`, `time.time()` trong `origin_key`. Một key không ổn định là
một key không idempotent, và hệ quả là chi hai lần. Kiểm bằng một test: gọi `_blockchain_origin_key()` hai lần
cách nhau một `write()` lên chứng từ gốc và so sánh.

Trong `dms`, **đã có sẵn một khoá đúng**: `dms.trade.settlement._dms_event_uuid()` là một UUIDv7 sinh một lần,
`readonly=True, copy=False`, lưu ở `event_uuid`. Bridge dùng nó, **không** tự chế khoá mới (§15.6.1).

#### 15.3.4. Không có FK: chứng từ gốc bị xoá

`Many2oneReference` không tạo FK, nên không có `ondelete`. Ba hậu quả, và chốt cho từng cái:

| Tình huống | Hậu quả | Chốt |
|---|---|---|
| Chứng từ gốc bị `unlink` | `origin_id` trỏ tới một id không còn | `.exists()` ở mọi chỗ đọc. Đã có trong `_notify_origin`. |
| Consumer addon bị gỡ | `origin_model` là một tên model không còn trong registry | `model not in rec.env` → skip im lặng. Đã có. |
| Chứng từ bị xoá **trước khi** settlement `final` | Tiền vẫn đi, không ai nhận trạng thái | `_cron_orphan_settlements()` hàng ngày: settlement chưa terminal mà `origin` không `.exists()` → `mail.activity` cho treasury. **Không** tự huỷ settlement: tiền có thể đã trên đường đi. |

Một lựa chọn **đã bị bác bỏ**: thêm một `ir.model.constraint` giả hoặc một `@api.ondelete` trên consumer để chặn
xoá. Nó đòi core biết tên model consumer (vi phạm ràng buộc standalone), và nó biến một ràng buộc của core thành
một rào cản trong workflow của người khác.

---

### 15.4. Cầu kế toán: `account.move` nào, lúc nào

Module `dms_blockchain_account` (`depends: ['dms_blockchain', 'account']`). Core **không** biết `account.move` tồn
tại. Bằng chứng: `_gl_required()` sống trong module này, và §10.11 kiểm chứng #4 đòi cái core một mình phải chạy.

#### 15.4.1. Ví là một `account.journal`, indexer là một bank feed — và bốn thứ phải cấu hình trước

Không tự viết cơ chế đối soát. Odoo đã có đầy đủ:

- Một `account.journal` `type='bank'` cho mỗi **(company, chain, token) có giữ tiền**. `currency_id` = currency của
  token (§15.4.5). Tài khoản mặc định = tài khoản tài sản "Crypto wallet — <token> — <chain>".
- **Outstanding Payments / Outstanding Receipts** của journal đó chính là **biểu diễn kế toán của một chuyển khoản
  đã broadcast nhưng chưa final**. Đó đúng là thứ chúng sinh ra để làm: một tấm séc đã phát nhưng chưa được lấy tiền.
- `blockchain.chain.effect` đã `final` → `account.bank.statement.line`. Từ đó trở đi là reconciliation widget,
  `account.reconcile.model`, và `dms.bank.reconciliation` của DMS chạy nguyên vẹn.

**[BẢN 3] Một journal cho mỗi (company, chain, token) — và "token" nghĩa là địa chỉ, không phải ký hiệu.** zDAI-A
và zDAI-B là hai tài sản khác nhau với hai journal khác nhau, dù cả hai đều hiện chữ "zDAI" trên màn hình. Gộp
chúng vào một journal là trộn hai loại tiền và làm đối soát vĩnh viễn không khớp.

**[SỬA §15 v1] Bản nháp đúng ở hình dạng và bỏ trắng cái khó: Odoo 19 không tự có outstanding account.**
`account.payment._compute_outstanding_account_id` trong Odoo 19 là đúng một dòng:

```python
pay.outstanding_account_id = pay.payment_method_line_id.payment_account_id
```

**Không có fallback nào.** Nếu `payment_account_id` trên `account.payment.method.line` của journal chưa được đặt,
`_prepare_move_line_default_vals` raise:

> "You can't create a new payment without an outstanding payments/receipts account set either on the company or the
> %(payment_method)s payment method in the %(journal)s journal."

Bốn thứ phải có trước khi post được dòng đầu tiên, kiểm bằng một `_check_setup()` chạy lúc cài và trước mọi lô post:

| # | Thứ | Nếu thiếu |
|---|---|---|
| 1 | `journal.inbound_payment_method_line_ids[0].payment_account_id` | `action_post()` raise, lô GL kẹt ở `gl_state='failed'` |
| 2 | `journal.outbound_payment_method_line_ids[0].payment_account_id` | như trên, cho chiều chi |
| 3 | `company.currency_exchange_journal_id` + `income_/expense_currency_exchange_account_id` | reconcile hai dòng khác tỷ giá raise, **không** sinh exchange move |
| 4 | Tài khoản "Crypto dust / rounding" (loại `expense`) | dust không có chỗ đi, sub-ledger và GL không bao giờ khớp (§15.4.6) |

`_check_setup()` trả về list mã lỗi và hiện trên dashboard đối soát §15.5, **không** raise lúc cài module — cài
module trên một DB chưa cấu hình chart of accounts không được phép thất bại.

#### 15.4.2. Bút toán cụ thể: cái bản nháp nói "sinh bút toán" mà không nói bút toán gì

Đây là lỗ hổng lớn nhất của bản nháp. Dưới đây là bút toán cho từng sự kiện, chính sách `on_final` (mặc định),
một brand trả một NPP 100,000,000 VND bằng Z-VND, phí relayer 500 VND.

**Luồng OUT (B2B payout), `direction='out'`, `transport='onchain'`:**

| Sự kiện | Bút toán | Ghi chú |
|---|---|---|
| Chứng từ gốc posted (ngoài phạm vi settlement layer) | Dr Trade payable 100,000,000 / Cr Rebate expense hoặc Accrual | Do `dms.trade.settlement._dms_create_credit_note()` làm, không phải chúng ta |
| `authorized` | **không bút toán** | Một cam kết chưa phải một sự kiện kế toán |
| `broadcast` | **không bút toán** (mode `on_final`) | Rủi ro nằm ở sub-ledger; báo cáo riêng, xem dưới |
| `final` | `account.payment` outbound posted:<br>Dr Trade payable (`destination_account_id`) 100,000,000<br>Cr Outstanding Payments 100,000,000 | Rồi `account.bank.statement.line` −100,000,000 trên journal Z-VND, reconcile với Outstanding Payments |
| Phí relayer (`fee_base` = 500) | Dr Bank/transaction fee expense 500<br>Cr Crypto wallet Z-VND 500 | Một dòng riêng trên cùng statement line, hoặc một statement line thứ hai. **Không được gộp vào 100,000,000** — nó làm sai số dư công nợ |
| Gas native (chain profile `public`, relayer nội bộ) | Dr Bank/transaction fee expense (native, quy đổi)<br>Cr Crypto wallet <native> | Journal khác (token native). Nếu `fee_mode='gasless'` (private chain) thì không có bút toán nào |
| `failed` sau `broadcast`, mode `on_final` | **không có gì để đảo** | Đó là toàn bộ lý do `on_final` là mặc định |
| `disputed` | **không bút toán tự động** | §15.2.6 |
| `compensated` | Bút toán của settlement ngược (chiều `in`), độc lập, `ref` trỏ về bản gốc | Không bao giờ `unlink` |

**Luồng IN (outlet collection), `direction='in'`:**

| Sự kiện | Bút toán |
|---|---|
| `final` | `account.payment` inbound posted: Dr Outstanding Receipts / Cr Trade receivable. Rồi statement line +amount, reconcile. |
| Trong DMS: `dms_post_payment` đã tạo `account.payment` rồi | **Không tạo thêm.** Bridge gọi thẳng `dms_post_payment`, và `dms_blockchain_account` bỏ qua settlement có `gl_state='not_required'` do bridge đặt. Xem §15.6.2 — đây là chỗ hai module dễ đâm nhau nhất. |

**Luồng OFFSET (`transport='offset'`, netting):**

| | Bút toán |
|---|---|
| Chân gross out 100,000,000 | Dr Trade payable 100,000,000 / Cr **Netting clearing** 100,000,000 |
| Chân gross in 30,000,000 | Dr **Netting clearing** 30,000,000 / Cr Trade receivable 30,000,000 |
| Chân net 70,000,000 on-chain | Dr **Netting clearing** 70,000,000 / Cr Outstanding Payments 70,000,000, rồi statement line |
| Tổng trên Netting clearing | 100 − 30 − 70 = **0** | Nếu không bằng 0, netting set không cân bằng. Đây là chỗ `@api.constrains` của §15.6.3 phải bắt. |

Tài khoản **Netting clearing** là tài khoản trung gian, loại `current_liability`, `reconcile=True`. Nó là thứ biến
"netting là một ý tưởng" thành "netting là một số dư kiểm tra được": số dư cuối kỳ của nó phải bằng 0 cho mọi kỳ đã
đóng. Một báo cáo một dòng.

**Mode 4 (sub-ledger, post theo lô) — bút toán tổng hợp hàng ngày:**

```
Dr Trade payable          Σ(payout final trong ngay)
    Cr Crypto wallet Z-VND    Σ(payout final trong ngay) + Σ(fee)
Dr Transaction fee expense   Σ(fee)
```

Một `account.move` cho mỗi `(journal, direction, ngày)`. `ref` = `BLK/<chain>/<token>/<YYYY-MM-DD>/<direction>`.
`narration` chứa số lượng settlement và khoảng id, để tra ngược. **Không** liệt kê 5,000 dòng chi tiết vào
`narration` — chúng ở sub-ledger, và sub-ledger là nơi tra cứu.

#### 15.4.3. Chính sách post

`ir.config_parameter blockchain.account.posting_policy` ∈ `{on_final, on_broadcast}`.

| Sự kiện | `on_final` (mặc định) | `on_broadcast` |
|---|---|---|
| `authorized` | không bút toán | không bút toán |
| `broadcast` | không bút toán; rủi ro nằm ở sub-ledger, báo cáo riêng | `account.payment` posted → Dr Payable / Cr **Outstanding Payments** |
| `final` | `account.payment` posted **+** statement line **+** reconcile trong cùng một bước | statement line → reconcile với outstanding |

`on_final` là mặc định vì nó giữ GL sạch khỏi những giao dịch chưa từng xảy ra. Đổi lại, treasury mất tầm nhìn về
tiền đã cam kết — bù bằng một **báo cáo** đọc từ sub-ledger, không bằng bút toán:

```
Tien dang tren duong (committed, not settled)
  = Σ amount_display  WHERE settle_state IN ('broadcast', 'pending_finality')
  GROUP BY company, chain, token, direction
```

Báo cáo này phải ở cùng dashboard với §15.5, và phải có cột "già nhất của khoản cũ nhất" — một khoản `broadcast`
từ ba ngày trước là một sự cố, không phải một con số.

`on_broadcast` dành cho deployment mà kiểm toán đòi tiền mặt cam kết phải hiện trên bảng cân đối; giá phải trả là
những bút toán đảo khi tx fail. Định lượng: với tỷ lệ revert quan sát được ~0.5% (ước tính, cơ sở: simulation gate
bắt gần hết, phần còn lại là race về số dư và allowance), 6,000 payout/năm ⇒ ~30 bút toán đảo/năm. Ít. Với
1,250,000 collection/năm ⇒ ~6,250 bút toán đảo/năm. Nhiều. Kết luận: `on_broadcast` chỉ hợp lý cho luồng B2B, và
đây là một lý do nữa để `posting_policy` có thể đặt **theo money-flow** chứ không chỉ toàn hệ thống.

**[SỬA §10]** `blockchain.account.posting_policy` nên là một field trên `blockchain.money.flow` (§09.4) với fallback
về `ir.config_parameter`, không phải một khoá toàn cục duy nhất.

#### 15.4.4. Kỳ kế toán bị khoá, và tại sao GL phải là một transaction khác

**Bước `final` sinh bút toán không được nằm trong transaction của `_set_finality`.** Kỳ kế toán bị khoá
(`account.move` raise `UserError` khi post vào kỳ đã lock qua `fiscalyear_lock_date` / `tax_lock_date`) là một sự
cố **thường xuyên**, không phải hiếm — đặc biệt trong ba ngày đầu tháng. Nếu post nằm cùng transaction, cả
`settle_state='final'` bị rollback và settlement kẹt vĩnh viễn ở `pending_finality` — Odoo nói dối về một khoản
tiền đã nằm trên chain. Chốt:

```python
def _set_finality(self):
    """Transaction 1: su that on-chain. Khong goi account.* o day."""
    self.with_context(**_STATE_ENGINE_CTX).write({
        'settle_state': 'final',
        'finality_datetime': fields.Datetime.now(),
        'gl_state': 'queued' if self._gl_required() else 'not_required',
    })

# ir.cron 'Blockchain: post GL', 5 phut, tren blockchain.settlement:
#   model._cron_post_gl()   -> doc gl_state='queued', post theo lo, bat UserError -> gl_state='failed'
```

Khi kỳ bị khoá, ba lựa chọn và chốt:

| Lựa chọn | Hậu quả | Chốt |
|---|---|---|
| Post vào đúng `finality_datetime` | raise, `gl_state='failed'`, chờ người mở kỳ | **Mặc định.** Trung thực, và kế toán là người quyết định |
| Đổi `move.date` sang ngày đầu kỳ mở | GL khớp kỳ, nhưng ngày kế toán khác ngày sự kiện | Cho phép bằng `blockchain.account.late_posting = 'shift'`; **bắt buộc** ghi `finality_datetime` vào `ref` để truy ngược |
| Bỏ qua | Tiền mất khỏi sổ | Không bao giờ |

`gl_state='failed'` là một hàng đợi người thật phải xử lý. Nó hiện trên dashboard đối soát §15.5, có `gl_error`
mang nguyên văn thông điệp `UserError`, **không im lặng**, và không retry vô hạn: sau 3 lần thất bại liên tiếp,
cron ngừng thử lại record đó và tạo một `mail.activity` duy nhất.

#### 15.4.5. FX khi token không phải currency của công ty

Ba trường hợp, ba cách xử lý khác hẳn. Gộp chung là sai:

| Trường hợp | Ví dụ | Xử lý |
|---|---|---|
| Token neo đúng currency sổ sách | Z-VND trên sổ VND | **Không** tạo `res.currency` mới. Token là *phương tiện thanh toán*, journal dùng company currency, không có FX. |
| Token neo một fiat khác | USDC trên sổ VND | Tạo `res.currency` riêng tên `USDC` (**không** dùng `USD`: USDC không phải USD, và một sự kiện depeg phải thể hiện được trên sổ). Nạp `res.currency.rate` từ oracle. FX theo cơ chế chuẩn của Odoo. |
| Token biến động / điểm thưởng | reward point, native coin | **Không phải currency.** Xem §15.4.8 — bản nháp chốt sai ở đây. |

**[BẢN 3] Ánh xạ là nhiều-một, không phải một-một.** Nhiều `blockchain.token` (zDAI-A, zDAI-B, cả hai neo DAI) trỏ
về **cùng** một `res.currency`. Đó là quan hệ đúng: `res.currency` là đơn vị đo, `blockchain.token` là công cụ. Điều
này cũng nghĩa là một `res.currency` không đủ để định danh tiền trong một settlement — `token_id` mới là thứ định
danh, và §15.4.1 vì thế đòi một journal cho mỗi token chứ không cho mỗi currency.

Ngày tính tỷ giá: **`finality_datetime`, không phải ngày chứng từ gốc, không phải `broadcast`.** Sự kiện kế toán là
finality. Đóng băng nó trên record:

```python
fx_rate          = fields.Float(digits=(16, 12), readonly=True)
fx_rate_source   = fields.Char(readonly=True)      # 'res.currency.rate' | 'oracle:<name>' | 'fixed'
fx_rate_datetime = fields.Datetime(readonly=True)
```

**[SỬA §15 v1] Một rate theo NGÀY là không đủ, và bản nháp không nói.** `res.currency.rate` khoá theo `name`
(một `Date`), nên mọi settlement trong ngày dùng cùng một tỷ giá. Với một stablecoin bình thường đó là vô hại. Với
một sự kiện depeg thì không: USDC giao dịch quanh **$0.87** trong phiên 11/03/2023, tức lệch **~13%** so với rate
$1.00 sẽ được dùng cho cả ngày. Trên 1,250,000 collection/năm, một ngày depeg có thể sai lệch hàng trăm triệu VND
trên sổ.

Chốt: một bảng snapshot riêng, và `res.currency.rate` chỉ để Odoo tự chạy máy FX của nó:

```python
class BlockchainTokenRate(models.Model):
    _name = 'blockchain.token.rate'
    _description = 'Intraday token rate snapshot'
    _order = 'rate_datetime desc'

    token_id      = fields.Many2one('blockchain.token', required=True, index=True)
    currency_id   = fields.Many2one('res.currency', required=True, index=True)
    rate_datetime = fields.Datetime(required=True, index=True)
    rate          = fields.Float(digits=(16, 12), required=True)
    source_code   = fields.Char(required=True)      # 'chainlink:<feed>', 'binance', 'manual'
    deviation_pct = fields.Float(digits=(6, 3))     # so voi rate ngay, de bat depeg

    _unique_rate = models.Constraint(
        'UNIQUE(token_id, currency_id, rate_datetime, source_code)',
        'Mot snapshot ty gia chi ghi mot lan.')
```

Chu kỳ nạp: 15 phút (96 dòng/token/ngày ≈ 35,000 dòng/token/năm — không đáng kể). Quy tắc chọn rate cho một
settlement: snapshot gần `finality_datetime` nhất trong vòng ±30 phút; nếu không có, fallback `res.currency.rate`
của ngày đó và đặt `fx_rate_source='res.currency.rate'` — **khác biệt này phải hiện trong báo cáo**, không được chìm.
Và một cảnh báo khi `abs(deviation_pct) > 2`: một stablecoin lệch 2% là một sự kiện nghiệp vụ, không phải một con số.

**[BẢN 3] Và trong factory mở, `token_id` trong bảng này là bắt buộc chứ không phải tiện lợi.** zDAI-A và zDAI-B có
thể lệch giá với nhau — chúng là hai contract khác nhau với hai vault khác nhau, và thị trường không buộc phải định
giá chúng bằng nhau. Một bảng rate khoá theo ký hiệu sẽ trộn hai giá thành một.
Chênh lệch tỷ giá giữa ngày ghi nhận công nợ và ngày settlement **để Odoo tự làm**: khi `account.move.line` của
payable và của payment cùng `currency_id` nhưng khác tỷ giá được reconcile, Odoo sinh exchange difference move.
Điều kiện: cả hai dòng đều mang `currency_id` và `amount_currency` đúng, **và** `company.currency_exchange_journal_id`
cùng hai tài khoản gain/loss đã được đặt (§15.4.1 mục 3). Không tự tính FX.

#### 15.4.6. Bụi (dust) là có thật, và Odoo đặt một trần cứng ở 6 chữ số

`amount_base` là chuỗi wei chính xác tuyệt đối; `res.currency` thì không thể theo kịp. **[SỬA §15 v1] Lý do mạnh
hơn bản nháp nói**: `res.currency.rounding` được khai báo `digits=(12, 6)` trong `odoo/addons/base/models/res_currency.py`,
và `decimal_places = int(math.ceil(math.log10(1/rounding)))`. Nghĩa là **giá trị rounding min biểu diễn được là `1e-6`**,
và `decimal_places` tối đa là **6**, đó là một giới hạn của framework chứ không phải một lựa chọn của ta. Không có
cách cấu hình nào vượt qua.

Hệ quả số học, token 18 decimals trên currency 6 decimals:

| Đại lượng | Giá trị | Cơ sở |
|---|---|---|
| Dust tối đa một settlement | `10^12 − 1` base units = 0.000000999999 token | 18 − 6 = 12 chữ số bị cắt |
| 1.83 triệu settlement/năm, lệch một chiều | ≤ 1.83 token/năm | tích luỹ tối đa |
| Quy ra tiền, Z-VND | ≤ 1.83 VND/năm | không đáng kể về tiền |
| Quy ra tiền, USDC | ≤ $1.83/năm | không đáng kể về tiền |
| **Ảnh hưởng đối soát** | **đáng kể** | một ngưỡng tolerance = 0 sẽ báo drift mỗi ngày |

```python
dust_base = fields.Char(readonly=True, default='0',
                        help='amount_base - (amount_currency quy nguoc ve base units). Luon >= 0.')
```

**Và dust phải có chỗ đi trong GL**, không chỉ được đo. Nếu không, số dư tài khoản "Crypto wallet" trong GL sẽ
lệch dần khỏi `balanceOf` on-chain và không ai giải thích được. Chốt: một bút toán quét dust hàng tháng,

```
Dr Crypto rounding expense    Σ dust quy ra currency
    Cr Crypto wallet <token>      Σ dust
```

chạy bởi `_cron_sweep_dust()`, chỉ khi `Σ dust >= 1` đơn vị currency (nếu không thì chính bút toán bị làm tròn về 0).
Với số liệu trên, bút toán này chạy khoảng **1 lần/năm** cho Z-VND. Đó là kết quả đúng: nó gần như không bao giờ
chạy, nhưng khi nó chạy thì đối soát khớp.

#### 15.4.7. Khối lượng: vì sao mode 4 là mặc định

Ước tính, cơ sở: deployment DMS 5,000 outlet, 1 collection/outlet/ngày, 250 ngày làm việc.

| | Mode 3: post từng settlement | Mode 4: post theo lô ngày |
|---|---|---|
| `account.move`/năm | 1.25 triệu (collection) + 6,000 (B2B) ≈ **1.26 triệu** | 250 × (số journal × số direction) ≈ **1,000 – 4,400** |
| `account.move.line`/năm | ~3.8 triệu (3 dòng/move) | ~13,000 |
| Dung lượng `account_move` + `account_move_line` + index | ~4 – 6 GB/năm (ước tính, cơ sở ~1 KB/dòng `account_move_line` kể cả 12 index của Odoo) | ~15 MB/năm |
| Thời gian đóng sổ cuối tháng | phút đến chục phút | giây |
| Thời gian mở báo cáo "sổ cái chi tiết" 1 năm | không mở được trong UI | tức thì |
| Tra cứu "khoản thu của outlet X ngày Y" | trên `account.move.line` | trên `blockchain.settlement` (vẫn đủ chi tiết) |

Sub-ledger `blockchain.settlement` vẫn giữ đủ 1.25 triệu dòng chi tiết (~400 B/dòng + index ≈ 1.2 GB/năm), và đó là
nơi tra cứu từng khoản. GL nhận tổng hợp. Đây là lý do §10.8 chốt mode 4 mặc định, và con số trên là biện hộ thực.

**Ngưỡng quyết định, viết ra để deployment tự chọn:** dưới **20,000 settlement/năm** một money-flow, mode 3
(một `account.payment`/settlement) chạy tốt và cho kế toán cái họ quen thuộc. Trên ngưỡng đó, mode 4. Với số liệu
DMS: B2B (6,000/năm) → mode 3; collection (1.25 triệu/năm) → mode 4. **Đó là lý do mode 5 "kết hợp theo luồng tiền"
không phải một tuỳ chọn xa xỉ mà là cấu hình đúng cho deployment DMS đầy đủ.**

#### 15.4.8. Loyalty: `_gl_required() = False` là sai kế toán

**[SỬA §15 v1]** Bản nháp viết: token biến động / điểm thưởng ⇒ `_gl_required()` trả `False`, giá trị vào GL chỉ
khi đổi ra tiền thật. Đúng về *transfer*, sai về *tổng thể*.

Một điểm thưởng đã phát hành là một **nghĩa vụ hợp đồng** (contract liability): doanh nghiệp nợ khách hàng một
khoản trong tương lai. IFRS 15 (và VAS tương đương) đòi trích trước phần doanh thu phân bổ cho điểm thưởng tại
thời điểm **phát hành**, không phải thời điểm đổi thưởng. Nếu settlement layer nói "không sinh bút toán" mà không
ai khác làm việc đó, thì bảng cân đối thiếu một khoản phải trả tăng dần theo quy mô chương trình.

Chốt, và nó không làm nặng settlement layer:

```python
gl_policy = fields.Selection([
    ('none',      'Khong but toan (token khong phai tai san ke toan)'),
    ('cash',      'Nhu tien: but toan day du tai finality'),
    ('liability', 'Nghia vu hop dong: phat hanh la but toan, doi thuong la giai phong'),
], required=True, default='cash')          # tren blockchain.token, khong tren settlement
```

| `gl_policy` | `direction='out'` (phát hành điểm) | `direction='in'` (thu về / đổi thưởng) |
|---|---|---|
| `none` | không gì | không gì |
| `cash` | Dr Payable / Cr Wallet | Dr Wallet / Cr Receivable |
| `liability` | Dr Marketing expense / **Cr Loyalty liability** | Dr **Loyalty liability** / Cr Revenue (hoặc Cr Wallet nếu đổi ra tiền) |

Và một con số để deployment biết mình đang ở đâu: với 200,000 điểm phát/năm và tỷ lệ đổi thưởng quan sát được
5–15% (§09 M18), số dư `Loyalty liability` ở trạng thái ổn định ≈ 85–95% của tổng phát hành luỹ kế. Đó là một con
số tăng không giới hạn nếu điểm không hết hạn. **Điểm thưởng phải có hạn sử dụng, và đó là một quyết định kế toán
trước khi là một quyết định marketing.** Xem §15.10.

---

### 15.5. Đối soát: tìm drift giữa chain và sổ kế toán

#### 15.5.1. Năm hướng, không phải ba

Bản nháp có ba. Hai hướng còn lại bắt những lỗi ba hướng đầu không bắt được.

```
(A) chain  -> sub-ledger : co transfer nao tren dia chi cua ta ma khong co settlement?
(B) sub-ledger -> GL     : co settlement final nao khong co but toan (hoac nguoc lai)?
(C) so du                : balanceOf(treasury) == sum(sub-ledger) == so du tai khoan GL?
(D) batch  -> settlement : sum(settlement trong batch) == so tien tx cua batch da phat?
(E) sub-ledger -> origin : settlement terminal nao chua duoc callback (notified_datetime IS NULL)?
```

(D) bắt lỗi tính chunk: một chunk 150 dòng mà calldata chỉ mang 149 người nhận. On-chain thành công, sub-ledger nói
150 dòng `final`, và một NPP không nhận được tiền — không hướng nào trong ba hướng đầu bắt được nó vì tổng số dư
vẫn khớp nếu dòng thứ 150 có số tiền nhỏ.

(E) bắt lỗi "tiền đã đến nhưng chứng từ gốc không biết": DMS vẫn báo một payout đang chờ trong khi tiền đã trả.
Đây là loại lỗi không làm mất tiền nhưng sinh một khoản trả lần hai khi ai đó bấm nút lại.

#### 15.5.2. Model

```python
class BlockchainReconciliationRun(models.Model):
    _name = 'blockchain.reconciliation.run'
    _description = 'Chain vs ledger reconciliation run'
    _order = 'as_of_datetime desc'

    company_id     = fields.Many2one('res.company', required=True, index=True)
    chain_id       = fields.Many2one('blockchain.chain', required=True, index=True)
    token_id       = fields.Many2one('blockchain.token', required=True, index=True)
    account_id     = fields.Many2one('blockchain.account', index=True)
    as_of_block    = fields.Integer(required=True)      # snapshot tai mot block da final
    as_of_block_hash = fields.Char(required=True)       # de chung minh khong doi soat tren fork
    as_of_datetime = fields.Datetime(required=True)
    chain_balance_base     = fields.Char()
    subledger_balance_base = fields.Char()
    gl_balance_base        = fields.Char()
    drift_base     = fields.Char(compute='_compute_drift', store=True)
    tolerance_base = fields.Char(readonly=True, default='0')  # tinh tai luc chay, khong phai hang so
    duration_ms    = fields.Integer()
    line_ids       = fields.One2many('blockchain.reconciliation.line', 'run_id')
    run_state      = fields.Selection([('running', 'Running'), ('clean', 'Clean'),
                                       ('partial', 'Clean trong pham vi kiem duoc'),
                                       ('drift', 'Drift found'), ('error', 'Error')],
                                      required=True, default='running', index=True)


class BlockchainReconciliationLine(models.Model):
    _name = 'blockchain.reconciliation.line'
    _description = 'One drift row'

    run_id      = fields.Many2one('blockchain.reconciliation.run', required=True,
                                  index=True, ondelete='cascade')
    kind        = fields.Selection([
        ('unattributed_chain',  'Transfer on-chain khong co settlement'),
        ('missing_onchain',     'Settlement final khong tim thay tren chain'),
        ('amount_mismatch',     'So tien lech'),
        ('missing_gl',          'Final nhung gl_state != posted'),
        ('orphan_move',         'But toan khong co settlement'),
        ('pending_over_sla',    'Ket o broadcast/pending_finality qua han'),
        ('batch_short',         'Tong settlement cua chunk khac so tien tx'),
        ('not_notified',        'Terminal nhung chua callback ve origin'),
        ('fx_only',             'Chi lech do ty gia'),
        ('dust',                'Lech trong nguong lam tron'),
        ('zether_nonce_gap',    'Nonce Zether khong lien tuc'),
        ('zether_sum_mismatch', 'Tong dong hinh khong khop so du ma hoa'),
        ('token_provenance',    'Token khong con khop catalogue cua factory')],
        required=True, index=True)
    severity      = fields.Selection([('info', 'Info'), ('warn', 'Warn'), ('block', 'Blocking')],
                                     required=True, default='warn', index=True)
    settlement_id = fields.Many2one('blockchain.settlement', index=True)
    transaction_id= fields.Many2one('blockchain.transaction', index=True)
    move_id_ref   = fields.Many2oneReference(model_field='move_model')  # khong depend account o core
    move_model    = fields.Char()
    delta_base    = fields.Char(default='0')
    note_text     = fields.Char()                       # khong dat ten 'text'
```

**`severity` là cột bản nháp thiếu và nó quyết định ai bị đánh thức.** `dust` là `info`; `pending_over_sla` là
`warn`; `unattributed_chain`, `zether_nonce_gap` và **[BẢN 3]** `token_provenance` là `block` — chúng nghĩa là tiền

#### 15.5.3. Cơ chế từng hướng

Bản nháp viết "có transfer nào trên địa chỉ của ta mà không có settlement?" và không nói làm thế nào. **Không RPC
nào trả lời câu hỏi đó.** `eth_getLogs` trả về log theo khoảng block, không theo "từ trước tới nay"; và trên một
chain có retention giới hạn (§11.1) thì cả khoảng đó cũng không có sẵn. Cơ chế thật: đối soát với **bảng của chính
ta** mà indexer §11 đã xây, và đó là lý do indexer là dependency của đối soát chứ không phải một tuỳ chọn.

```sql
-- (A) unattributed_chain: effect da final nhung khong settlement nao nhan
SELECT e.id, e.ref_hex, e.amount_base
FROM   blockchain_chain_effect e
LEFT   JOIN blockchain_settlement s ON s.effect_id = e.id
WHERE  e.chain_id = %(chain)s AND e.token_id = %(token)s
  AND  e.block_number <= %(as_of_block)s
  AND  e.effect_state = 'final'
  AND  s.id IS NULL;

-- (B) missing_gl
SELECT id, origin_key, amount_base
FROM   blockchain_settlement
WHERE  company_id = %(co)s AND settle_state = 'final'
  AND  gl_state IN ('queued', 'failed')
  AND  finality_datetime < now() - interval '1 hour';

-- (D) batch_short
SELECT c.id, c.sequence,
       SUM(s.amount_base::numeric) AS subledger_sum,
       t.value_base::numeric       AS onchain_sum
FROM   blockchain_settlement_batch_chunk c
JOIN   blockchain_settlement s ON s.chunk_id = c.id
JOIN   blockchain_transaction t ON t.id = c.transaction_id
WHERE  c.chunk_state = 'final'
GROUP  BY c.id, c.sequence, t.value_base
HAVING SUM(s.amount_base::numeric) <> t.value_base::numeric;

-- (E) not_notified
SELECT id, origin_model, origin_id
FROM   blockchain_settlement
WHERE  settle_state IN ('final','failed','expired','compensated')
  AND  origin_model IS NOT NULL
  AND  notified_datetime IS NULL
  AND  write_date < now() - interval '15 minutes';
```

`amount_base::numeric` là lý do §15.1.2 đòi một index biểu thức trên `(amount_base::numeric)`: không có nó, (D)
làm một seq scan trên 1.25 triệu dòng mỗi lần chạy.

Cron `_cron_reconcile_ledger()` chạy hàng ngày sau khi Finality Gate đã xử lý xong block của ngày hôm trước.
Snapshot **phải lấy tại một block đã final**, và phải lưu **cả hash** — đối soát tại tip sẽ báo drift mỗi lần chạy
chỉ vì tip đã đi tiếp, và đối soát trên một block đã bị reorg sẽ báo "clean" trên một nhánh không tồn tại.

*Ước tính thời gian chạy, cơ sở: 1.25 triệu settlement/năm, index đúng, PostgreSQL trên SSD:* (A) và (D) là hash
join trên tập đã lọc theo `(chain, token, block_number)` ⇒ **2 – 8 giây**; (B), (C), (E) là index scan ⇒ **< 1 giây**.
Toàn bộ run cho một `(company, chain, token)`: **dưới 15 giây**. Với 3 token × 2 chain × 5 company = 30 run ⇒
**~7 phút/đêm**. Nằm trong ngân sách; không cần chia nhỏ.

#### 15.5.4. Ngưỡng

**[SỬA §15 v1] Bản nháp tự mâu thuẫn:** nó nói "ngưỡng tolerance phải là `sum(dust_base)`, không phải 0" rồi định
nghĩa `recon_tolerance_base` là một hằng số `10^(token_decimals − currency_decimals)`. Hai thứ khác nhau: hằng số
là dust của **một** settlement, còn drift luỹ kế là dust của **tất cả**.

Chốt: `tolerance_base` được tính **tại lúc chạy**, và lưu vào run để báo cáo có thể giải thích được:

```python
tolerance = sum(int(s.dust_base) for s in settlements_in_scope) \
            + int(token.recon_slack_base or '0')      # slack cau hinh, mac dinh 0
```

`recon_slack_base` tồn tại cho một trường hợp duy nhất: token có phí chuyển khoản on-chain (fee-on-transfer). Nếu
token không có, đặt 0 và giữ 0. Một slack được nới rộng "cho chắc" là một chỗ để giấu drift.

| Điều kiện | Kết quả |
|---|---|
| `|drift| ≤ tolerance` | `kind='dust'`, `severity='info'`, `run_state='clean'` |
| `tolerance < |drift|` | `run_state='drift'`, `mail.activity` cho `group_blockchain_treasury`, và **`group_blockchain_auditor` được CC** |

Đối soát **không bao giờ tự sửa**. Nó mở một activity và dừng lại. Một routine đối soát có quyền ghi là một routine
có thể che giấu chính lỗi của nó.

#### 15.5.5. Zether phá vỡ hướng (C), và cái gì còn lại

Số dư bảo mật không đọc được từ chain nếu công ty không giữ khoá giải mã; `getEncryptedBalance` trả về một cặp điểm
đường cong, không trả về một số. Nhưng **[SỬA §15 v1] bản nháp kết luận quá bi quan**: nó viết "khi không giữ khoá,
nonce-continuity là tất cả những gì còn lại" và bỏ qua cả hai trường hợp quan trọng hơn.

Ba mức độ, xếp theo cái ta thực sự biết:

| Ta là gì với tài khoản đó | Đối soát làm được gì | Cơ chế |
|---|---|---|
| **Chủ tài khoản** (treasury của chính mình) | **Đối soát đầy đủ**, ngang một token công khai | §03.2.5 memo AEAD: giải `memoTo`/`memoFrom` cho ra `v` trong ~60 µs; rồi kiểm tổng đồng hình `g^{Σv} == C_acc · D_acc^{−x}` sau mỗi rollOver (§03.2.6). Odoo không giữ `x`: HSM expose một phép `ecdh(D) -> compress(D^x)` duy nhất (§11.10) |
| **Đối tác công bố** | Đối soát từng dòng, có xác minh | `recipient_decrypted`: đối tác gửi `(v, s)`, ta kiểm `C_out == g^v · y_recv^s` — 2 scalar mul, không cần khoá bí mật. **[BẢN 3]** Hoặc `transferWithProof` / `verifyTransferAmount` (§09): đối tác mở ciphertext bằng một chứng minh gắn với `entryRef`, và ta xác minh on-chain thay vì tin lời |
| **Không biết gì** | **Chỉ phát hiện được mất mát, không phát hiện được sai số tiền** | Tính liên tục của `zetherNonce`, cộng `accSeq` |
```
Voi moi (token, zether_account) ma ta KHONG giu khoa:
    spend_nonces = [e.zether_nonce for e in entries if direction in ('transfer_out', 'withdraw')]
    Neu sorted(spend_nonces) != list(range(min, max + 1)):  ->  zether_nonce_gap  (severity='block')
```

Một lỗ hổng trong dãy nonce nghĩa là có đúng một giao dịch ra khỏi tài khoản này mà sub-ledger không ghi — đó là
tín hiệu đối soát mạnh ngang một chênh lệch số dư, và nó đọc được từ chain công khai (nonce không bị mã hoá).

**[SỬA §10] Và constraint của §10 sai ở đây.** §10.4.7 khai:

```python
_unique_zether_nonce = models.Constraint(
    'UNIQUE(token_id, account_id, zether_nonce, direction)', ...)
```

`direction` trong khoá cho phép cùng một `zether_nonce` tồn tại đồng thời cho `transfer_out` **và** `withdraw` của
cùng một tài khoản. On-chain điều đó không thể xảy ra: `zetherNonce[schnorrAddress]` là một bộ đếm duy nhất, tăng
ở **cả hai** thao tác tiêu tiền (§03, `transferConfidential` và `withdraw` đều `++`). Một khoá có `direction` biến
một sự cố "hai bản ghi cho một nonce" thành hai dòng hợp lệ, và chính là thứ đối soát đang đi tìm. Sửa:

```python
_unique_zether_spend_nonce = models.Constraint(
    "UNIQUE(token_id, account_id, zether_nonce)", 'Nonce Zether da duoc dung cho tai khoan/token nay.')
# ap dung cho cac direction tieu tien; deposit/transfer_in khong tieu nonce cua chinh minh
```

Vì `deposit` và `transfer_in` **không** tăng nonce của chủ tài khoản, chúng không được mang `zether_nonce` của
tài khoản đó. Để `zether_nonce` NULL cho hai direction đó, và PostgreSQL UNIQUE cho phép nhiều NULL — đúng tính
chất ta cần, không cần partial index.

**[SỬA §15 v1] `epoch` đã biến mất khỏi thiết kế.** Bản nháp nói "epoch rollOver" và "300 người nhận đều nhận được
trong cùng một epoch". §03.5.4 đã bỏ hoàn toàn mô hình epoch và thay bằng `accSeq` — một đại lượng không phụ thuộc
thời gian, chỉ đổi khi `rollOver` chạy (**[BẢN 5, 2026-09-03]** bất kỳ ai gọi được với tài khoản `PUBLIC`; tài
khoản treasury của luồng R3/R4 đăng ký `OWNER_ONLY` nên với **chính các tài khoản mà §15 đối soát**
thì vế "chỉ chủ" vẫn đúng). Hệ quả cho đối soát: không còn "epoch boundary" nào để đợi; thay
vào đó, đối soát phải đọc **cả** `accSeq` và `pendingSeq` (`viewAccounts`, §03.6) và báo `zether_sum_mismatch` khi
`g^{Σv_da_rollOver} != C_acc · D_acc^{−x}`. Tiền nằm trong `pending` **không** là drift — nó là tiền chưa rollOver,
và báo cáo phải thể hiện nó thành một cột riêng chứ không trộn vào số dư.

Báo cáo cho token `is_confidential` phải nói rõ nó đang ở mức nào trong ba mức trên. `run_state='partial'` tồn tại
chính vì điểm này: báo "clean" khi ta chỉ kiểm được nonce là một lối nói dối.

#### 15.5.6. Khi tìm thấy drift

| `kind` | Ai xử lý | Bước đầu tiên |
|---|---|---|
| `unattributed_chain` | treasury + auditor | Tra `ref_hex` ngược về `blockchain.payment.request` (§09.6). Nếu không có: ai đó gửi tiền vào ví của ta mà không qua hệ thống — ghi nhận như một khoản phải trả chưa xác định, **không** tự động cấp cho ai |
| `missing_onchain` | treasury | Kiểm `finality_source` (§11.3b). Gần như luôn là node nói dối, không phải tiền mất |
| `amount_mismatch` | treasury | Dừng mọi settlement của cùng `payer_account` cho tới khi rõ |
| `missing_gl` | kế toán | Mở kỳ, hoặc `late_posting='shift'` |
| `orphan_move` | kế toán | Bút toán tay do ai đó tạo. Không tự xoá |
| `batch_short` | treasury | So sánh calldata đã lưu (`ir.attachment` của chunk) với `settlement_ids`. Đây là lỗi code, không phải lỗi dữ liệu |
| `zether_nonce_gap` | treasury + auditor | **Dừng** mọi settlement trên tài khoản Zether đó. Một nonce biến mất có thể là một lần chi không được ghi |
| **[BẢN 3]** `token_provenance` | treasury | Gỡ token khỏi `accepted_token_ids` ngay, rồi tra: `EXTCODEHASH` đổi là không thể (contract immutable), nên lệch nghĩa là **địa chỉ trong DB đã bị sửa**, không phải contract đã đổi. Đó là một sự cố bảo mật của Odoo, không của chain |

---

### 15.6. Ba luồng DMS cắm vào qua bridge, core không biết gì

`dms_blockchain_bridge` (`depends: ['dms_blockchain', 'dms']`, `auto_install: True`). Toàn bộ nội dung của nó là:
`_inherit` mixin, sinh settlement, và nhận callback. Không một dòng nào trong core đọc chuỗi `dms`.

#### 15.6.0. Sự thật về model DMS — ba chỗ bản nháp sai

Đọc thẳng từ `dms/models/trade/dms_trade_settlement.py` và `dms/models/orders/dms_payment_collection.py`:

| Bản nháp nói | Sự thật | Hệ quả |
|---|---|---|
| `dms.trade.settlement.line` là "payout line" cho nhiều người nhận | Nó là **dòng hàng tặng**: `product_id` + `quantity`, docstring *"Một dòng hàng tặng. Chỉ có nghĩa khi `settlement_method = goods`"*. `payout_line_ids` có `string="Free goods"` | Bridge phải gắn vào `dms.trade.settlement`, không phải `.line`. Ánh xạ là 1 settlement ↔ 1 chứng từ |
| Bridge ghi `payout_state`, `payout_datetime` | **Hai field này không tồn tại.** `dms.trade.settlement` có `state ∈ {draft, posted, settled_external, cancelled}` | Bridge phải dùng `state` có sẵn, hoặc thêm field mới và nói rõ là thêm |
| Bridge tự chế idempotency | DMS **đã có** `dms.sync.operation._dms_once(uuid, type, payload, run)` trả `(record, replayed)`, và `_dms_event_uuid()` sinh UUIDv7 ổn định lưu ở `event_uuid` (`readonly`, `copy=False`) | Dùng lại. Một lớp idempotency thứ hai là một lớp có thể lệch với lớp thứ nhất |

Một phát hiện có lợi: **`state='settled_external'` đã tồn tại** với ý nghĩa *"Settled outside the Odoo ledger"*, và
`dms_settle` dùng nó cho topology `lightweight`. Đó đúng là hình dạng của một settlement on-chain ở mode 4. Bridge
không cần phát minh trạng thái mới cho trường hợp đó.

#### 15.6.1. Trade settlement payout

| | |
|---|---|
| Model gốc | `dms.trade.settlement` (**không** phải `.line`) |
| Chiều | `out` |
| Ánh xạ | 1 `blockchain.settlement` / 1 `dms.trade.settlement`; gom vào 1 `blockchain.settlement.batch` theo `(chain, token, payer_account, kỳ)` |
| `origin_key` | `dms.trade.settlement._dms_event_uuid()` — UUIDv7 đã có, ổn định, `copy=False` |
| Kích hoạt | `settlement_method = 'onchain'` (thêm bằng `selection_add`) |
| Điểm tinh tế | Batch `atomic` chỉ khi **toàn bộ** payee đã qua `_preflight()`; ngược lại `chunked` |

```python
class DmsTradeSettlement(models.Model):
    _name = 'dms.trade.settlement'
    _inherit = ['dms.trade.settlement', 'blockchain.settlement.origin']

    settlement_method = fields.Selection(
        selection_add=[('onchain', 'On-chain transfer')],
        ondelete={'onchain': 'set default'})
    blockchain_settle_state = fields.Char(readonly=True, copy=False)   # bong cua settle_state, de hien tren form

    def _blockchain_origin_key(self):
        self.ensure_one()
        return self._dms_event_uuid()          # on dinh, khong doi khi record duoc sua

    def _on_blockchain_settlement(self, settlement):
        """Idempotent: co the goi lai. Chi ghi khi settlement da terminal."""
        self.ensure_one()
        self.sudo().blockchain_settle_state = settlement.settle_state
        if settlement.settle_state == 'final' and self.state == 'draft':
            # KHONG goi dms_settle() lai: no da chay va da tao chung tu.
            # O day chi dong so cai: tien da chuyen.
            super(DmsTradeSettlement, self.sudo()).write({'state': 'settled_external'})
        elif settlement.settle_state in ('failed', 'expired') and self.state == 'draft':
            self.sudo().message_post(
                body=self.env._("On-chain payout failed: %s", settlement.failure_reason or '-'))
        # 'disputed' va 'compensated': KHONG doi state. Mot nguoi phai nhin.
```

Ba quyết định trong 12 dòng trên, viết rõ vì chúng không hiển nhiên:

1. **Bridge không gọi `dms_settle()`.** `dms_settle` sinh credit note / gift order và `action_settle()` claim — đó
   là bước *nghiệp vụ*, xảy ra trước, độc lập với việc tiền đi đường nào. Bridge chỉ đóng bước *tiền*.
2. **`super(...).write()` bỏ qua override của `dms.trade.settlement`** nếu nó có guard trên `state`. Nếu model gốc
   không có guard, dùng `self.sudo().write()` bình thường. Kiểm trước khi viết — một `super()` không cần thiết là
   một cửa hậu mở sẵn.
3. **`disputed` không đổi `state`.** Một chứng từ DMS nhảy qua nhảy lại theo một tín hiệu RPC là cách nhanh nhất để
   mất niềm tin vào hệ thống.

Chiều đi (sinh settlement) không nằm trong `_on_blockchain_settlement` mà trong một method riêng, gọi từ
`dms_settle` khi `settlement_method == 'onchain'`:

```python
def _dms_create_blockchain_settlement(self):
    self.ensure_one()
    flow = self.env['blockchain.money.flow']._resolve(self.company_id, 'B2B_PAYOUT')
    return self.env['blockchain.settlement'].sudo()._submit(
        self.company_id, self._blockchain_origin_key(),
        use_case='b2b', direction='out',
        chain_code=flow.chain_id.code, token_id=flow.token_id.id,      # token_id, KHONG token_symbol
        amount_base=flow.token_id._to_base(self.amount, self.currency_id),
        payee=self.beneficiary_partner_id,
        origin_model=self._name, origin_id=self.id)
```

**[BẢN 3] `token_id`, không phải `token_symbol`.** Xem A11 ở §15.0: một ký hiệu không định danh được token trong
một factory mở. `blockchain.money.flow` đã giữ `token_id`, nên bridge chỉ việc chuyển tiếp nó.

`_to_base` là chỗ quy đổi tiền → base units xảy ra, và nó phải **làm tròn xuống** (`ROUND_DOWN`): làm tròn lên chi
nhiều hơn 1 wei so với số tiền được duyệt. Chênh lệch đi vào `dust_base`.

#### 15.6.2. Outlet payment collection

| | |
|---|---|
| Model gốc | `dms.payment.collection` |
| Chiều | `in` |
| Ánh xạ | 1 `blockchain.settlement` / 1 collection; `blockchain.payment.request` (§09.6 R1) cấp địa chỉ CREATE2 derived |
| `origin_key` | `dms.payment.collection:<id>` (model này chưa có `event_uuid`; xem §15.10) |
| Điểm tinh tế | Nguyên tắc `dms_vietqr` nguyên vẹn, và `status` đã có đúng trạng thái cần dùng |

`dms.payment.collection.status` đã có **`pending_reconciliation`** với ý nghĩa *"Awaiting bank reconciliation"*, và
`dms_post_payment` chấp nhận `status in ('validated', 'confirmed', 'pending_reconciliation')`. Ánh xạ tự nhiên:

| `settle_state` | `collection.status` | Ai ghi |
|---|---|---|
| `submitted`, `broadcast`, `pending_finality` | `pending_reconciliation` | bridge |
| `final` | gọi `dms_post_payment(operation_uuid=<settlement uuid>)` → `payment_posted` | bridge |
| sau đó | `dms_allocate(...)` → `allocated` | **người**, không tự động |
| `failed`, `expired` | `exception` + `message_post` | bridge |

```python
def _on_blockchain_settlement(self, settlement):
    self.ensure_one()
    if settlement.settle_state in ('submitted', 'broadcast', 'pending_finality'):
        if self.status in ('validated', 'confirmed'):
            self.sudo().status = 'pending_reconciliation'
    elif settlement.settle_state == 'final':
        if self.status != 'payment_posted':
            self.sudo().dms_post_payment(operation_uuid=settlement.settlement_uuid)
    elif settlement.settle_state in ('failed', 'expired'):
        self.sudo().message_post(body=self.env._("On-chain collection failed."))
```

Bốn điều phải nói rõ:

1. **`broadcast` KHÔNG phải là đã thu tiền.** Đây là nguyên tắc `dms_vietqr` ("quét QR không phải là đã thu tiền")
   áp thẳng: một tx đã phát sóng là một QR đã hiện, không hơn. `pending_reconciliation` là trạng thái đúng, và nó
   đã có sẵn — không cần phát minh.
2. **`dms_post_payment` tự tạo `account.payment`.** Nghĩa là với luồng này, `dms_blockchain_account` **không** được
   tạo thêm bút toán. Bridge đặt `gl_state='not_required'` trên settlement lúc tạo. Nếu quên, mỗi khoản thu sẽ có
   **hai** bút toán — một của DMS, một của module account bridge — và đối soát hướng (B) sẽ báo `orphan_move` hàng
   loạt. Đây là chỗ hai module dễ đâm nhau nhất trong cả thiết kế, và nó phải có một test riêng.
3. **`operation_uuid` là settlement uuid**, nên một callback gọi lại sau crash đi vào `_dms_once` và trả về
   `replayed=True` thay vì post lần hai. Hai lớp idempotency **cùng một khoá** — đó là cách chúng không lệch nhau.
4. **`dms_allocate` không tự động.** Phân bổ một khoản thu vào hoá đơn nào là một quyết định, không phải một hệ quả.
   Bản nháp nói "`dms.collection.allocation` chỉ được tạo khi `final`" — đúng nhưng chưa đủ: nó chỉ được tạo khi
   `final` **và** có người bấm.

#### 15.6.3. B2B claim offset (netting)

Một brand nợ distributor 100 triệu (payout) và distributor nợ brand 30 triệu (claim bị từ chối). Hai cách:

1. Hai transfer on-chain gross (100 và 30 ngược chiều). Trung thực, tốn gas gấp đôi, và **cần distributor thực sự
   có 30 triệu token trong ví** — thường là không.
2. Netting off-chain: một transfer 70 triệu.

Chốt phương án 2, nhưng **sổ kế toán vẫn phải là gross**. Cụ thể: ba settlement — hai `transport='offset'`
(100 out, 30 in, không tx, `settle_state` đi thẳng `draft → final` khi net settlement `final`) và một
`transport='onchain'` 70 out. `_gl_required()` trả `True` cho cả ba; bút toán gross giữ nguyên trình bày công nợ
(§15.4.2, tài khoản **Netting clearing**), còn dòng tiền chỉ 70. Nếu bỏ hai dòng gross, báo cáo công nợ với
distributor mất 30 triệu và không ai tìm ra tại sao.

```python
transport = fields.Selection([('onchain', 'On-chain transfer'),
                              ('offset', 'Netting offset, khong co tx'),
                              ('external', 'Fiat / ngoai chain, chain chi anchor')],
                             required=True, default='onchain', index=True)
netting_set_id = fields.Many2one('blockchain.netting.set', index=True)
```

Ràng buộc bắt buộc trên `blockchain.netting.set`:

```python
@api.constrains('settlement_ids')
def _check_balanced(self):
    for ns in self:
        gross_out = sum(int(s.amount_base) for s in ns.settlement_ids
                        if s.transport == 'offset' and s.direction == 'out')
        gross_in  = sum(int(s.amount_base) for s in ns.settlement_ids
                        if s.transport == 'offset' and s.direction == 'in')
        net       = sum(int(s.amount_base) * (1 if s.direction == 'out' else -1)
                        for s in ns.settlement_ids if s.transport == 'onchain')
        if gross_out - gross_in != net:
            raise ValidationError(_(
                'Netting set khong can bang: gross_out %s - gross_in %s != net %s',
                gross_out, gross_in, net))
```

Kiểm bằng **một test thật**, không bằng đọc code. Một netting set không cân bằng là một lối thất thoát tiền.

Và hai ràng buộc không phải kỹ thuật, lấy từ §09 M15, phải ghi vào spec vì không ai khác sẽ ghi:

- **Netting phải có điều khoản bù trừ trong hợp đồng.** Nếu không, một bên phá sản thì phần bù trừ có thể bị toà
  lật lại và brand mất toàn bộ 100 triệu thay vì 70.
- **`dms.trade.claim` đã settle là immutable.** Bridge **không sửa claim**, chỉ ghi settlement mới. Một claim đã
  `settled` đi vào netting set bằng `claim_ids` của chứng từ gốc, không bằng một `write` lên chính nó.

#### 15.6.4. Cây file của bridge

```
dms_blockchain_bridge/
├── __manifest__.py                       # depends: ['dms_blockchain', 'dms'], auto_install: True
├── models/
│   ├── dms_trade_settlement.py           # _inherit mixin, selection_add 'onchain'
│   ├── dms_payment_collection.py         # _inherit mixin, anh xa status
│   ├── dms_trade_claim.py                # netting set builder
│   ├── blockchain_money_flow.py          # selection_add flow_code cua DMS
│   └── blockchain_settlement.py          # _selection_origin_ref: them cac model dms.*
├── data/blockchain_money_flow_data.xml   # binding mac dinh, noupdate=1
├── security/ir.model.access.csv          # KHONG cap quyen moi; chi mo rong nhom da co
└── tests/
    ├── test_bridge_payout.py
    ├── test_bridge_collection_no_double_move.py   # bay §15.6.2 muc 2
    └── test_netting_balanced.py
```

```python
# blockchain_money_flow.py
class BlockchainMoneyFlow(models.Model):
    _inherit = 'blockchain.money.flow'

    flow_code = fields.Selection(
        selection_add=[('DMS_OUTLET_CREDIT', 'Outlet credit repayment'),
                       ('DMS_TRADE_PAYOUT',  'DMS trade settlement payout')],
        ondelete={'DMS_OUTLET_CREDIT': 'set default',
                  'DMS_TRADE_PAYOUT': 'set default'})
```

**Toàn bộ bridge dưới 400 dòng Python.** Nếu nó vượt 800, một phần logic đang thuộc về core hoặc về DMS chứ không
về cầu nối — đó là tín hiệu để dừng lại và chia lại.

---

### 15.7. Định lượng batch: khi nào lô có lợi, khi nào không

Ước tính, cơ sở: chi phí opcode EVM (SSTORE 20,000 cho slot 0→nonzero, 5,000 warm nonzero→nonzero, 2,900 warm
SLOAD), 21,000 base/tx, 16 gas/byte calldata khác 0. **Giá gas thống nhất với §09.10a: Gnosis 2 gwei, xDAI = $1.00.**
(Bản nháp dùng 1.5 gwei — đã sửa để cả bộ tài liệu dùng một con số.)

| Kịch bản, 300 người nhận | Gas | Gnosis @2 gwei | Ethereum L1 @20 gwei, ETH $3,000 |
|---|---|---|---|
| 300 tx `ERC20.transfer` riêng lẻ (người nhận chưa có token) | 300 × 65,000 = 19,500,000 | 0.039 xDAI = **$0.039** | **$1,170** |
| 2 tx `disperseToken` × 150 | 2 × (21,000 + 150 × 30,000) = 9,042,000 | 0.018 xDAI = **$0.018** | **$542** |
| 300 `transferConfidential` (Zether 32/64) | 300 × 1,880,000 = **564,000,000** | 1.128 xDAI = **$1.13** | **$33,840** |

**[SỬA §15 v1] Con số Zether của bản nháp sai 7.5 lần theo hướng lạc quan.** Nó dùng 250,000 gas/transfer, con số
mà §03.3.7 đã truy ra là chi phí verify một **Groth16 SNARK trên alt_bn128** (4 pairing), không phải Bulletproofs.
Con số đúng là **1,880,000** cho cấu hình 32/64 (§03.3.6, §09.10a). Sửa ở đây để cả bộ tài liệu nhất quán.

Bốn kết luận đọc được từ bảng trên, và ba trong số đó ngược với trực giác:

1. **Trên Gnosis, batch không tiết kiệm tiền.** $0.039 xuống $0.018 là vô nghĩa. Cái batch tiết kiệm trên Gnosis là
   **số nonce, số lần chờ finality, và số dòng `blockchain.transaction`**.

   **[SỬA §15 v1] Và lý do "300 tx tuần tự mất 25 phút" của bản nháp là sai.** Một relayer **có thể** nộp nhiều tx
   với nonce liên tiếp vào cùng một block; nonce tuần tự không có nghĩa một tx mỗi block. Trần thật là
   **số tx pending tối đa một tài khoản** mà mempool chấp nhận: geth mặc định `txpool.accountslots = 16`
   (Nethermind và Erigon đặt ngưỡng tương đương). Với 300 tx trên một địa chỉ relayer:

   | | 300 tx riêng lẻ | 2 chunk |
   |---|---|---|
   | Vòng nộp (16 pending/vòng) | 19 | 1 |
   | Thời gian tối thiểu (block 5 s) | ~95 s | ~5 s |
   | Rủi ro head-of-line | **một tx kẹt chặn 299 cái sau** | một chunk kẹt chặn 1 chunk |
   | Dòng `blockchain.transaction` | 300 | 2 |
   | Lần chờ finality (240 s hard) | 300 lần theo dõi | 2 |

   Đó mới là lý do batch. Làm batch vì lý do đó, đừng nói dối rằng là vì gas.

   **[BẢN 3] Và đây là chỗ key pool (§21.5) giao với batching, hai thứ giải hai nút thắt khác nhau.** Trần 16
   pending/tài khoản là trần của **một khoá**; N khoá cho 16N. Batching gộp 300 việc thành 2 chữ ký — làm được vì
   ta tự sinh cả 300. Một node relayer mở nhận việc của người lạ không gộp được, nên nó xoay khoá. Số 6 EOA của
   §06.6.1 và số 50 khoá của §21.5 không mâu thuẫn: chúng trả lời hai câu hỏi.

2. **Block gas limit là trần cứng, và `chunk_size = 150` còn rộng hơn bản nháp nghĩ.** Một chunk 150 tốn
   **4,521,000 gas**, không phải 9M (bản nháp đọc nhầm tổng hai chunk thành một). Gnosis ~17M gas/block ⇒ một chunk
   chiếm **27%** block. Có thể đẩy lên 300/chunk (~9M, 53% block) nhưng **không nên**: một revert khi đó đốt 9M gas
   thay vì 4.5M, và một block có thể bị một tx khác chiếm chỗ. Giữ 150 làm mặc định; `chunk_size` phải được
   simulation gate (§10) xác nhận từng lần, không được hard-code tin tưởng.

   *Kiểm tra một ràng buộc ít ai nhớ:* với 150 người nhận, calldata ≈ 150 × 52 B = 7,800 B, gần như toàn byte khác 0
   ⇒ ~31,200 token calldata ⇒ sàn calldata theo EIP-7623 = 21,000 + 40 × 31,200 = **1,269,000 gas**, thấp hơn
   4,521,000 rất nhiều. Sàn không ràng buộc. Nếu chunk_size tăng quá ~500, phải tính lại.

   **[CẬP NHẬT 2026-08-31] Chain 9000 đã nâng lên Nethermind 1.39.0, Fusaka + BPO2.** gasLimit vẫn 16,7M.
   EIP-1559 **đã bật**, nhưng `baseFeePerGas` đặt 0 ngay ở genesis và công thức 1559 giữ nó dính vĩnh viễn
   ở 0 (`next = base + base·delta/target/denom`, base = 0 ⇒ mọi số hạng bằng 0) — **gas vẫn miễn phí**.
   EIP-7623 **đã bật**, nên sàn calldata nay **có** áp: phải tính lại cho chunk lớn. PUSH0/TSTORE/MCOPY
   dùng được; `foundry.toml` profile `private9000` đổi sang `evm_version = "prague"`.

3. **Zether không batch được, và khoảng cách lớn hơn bản nháp nghĩ.** 564M gas là **33 block Gnosis liên tiếp**
   (17M/block), tức ~2.8 phút chiếm **toàn bộ** không gian block của cả mạng lưới. Không thể. Mỗi
   `transferConfidential` phải là một tx riêng. Đó không phải nhược điểm của thiết kế — đó là lý do chain profile
   chốt **private chain đi trước cho Zether**: trên chain private `fee_mode='gasless'`, trần duy nhất còn lại là
   thời gian sinh proof (**30–50 ms/proof** trên server Rust native cho cấu hình 32/64, §03; không phải 30–60 ms
   như bản nháp ước, và con số 300–800 ms của bản nháp là của **WASM trong browser**, không phải của prover server)
   và throughput verify. **[BẢN 3] Trần thật đo được trên chain 9000 là ~45 tx bảo mật/giây, giới hạn bởi CPU của
   validator, không bởi gas** — con số ~500 tx/s của §03.3.8 là của một cấu hình nhiều validator với MSM Pippenger,
   không phải của một signer Clique duy nhất.

   300 proof trên một core = **9–15 giây**; chạy song song 8 core = **1.2–1.9 giây**. Không phải nút cổ chai.

4. **[SỬA §15 v1] "Epoch" không còn tồn tại.** Bản nháp kết bằng một câu về "epoch rollOver" không còn đúng sau
   §03.5.4. Cái thay thế nó là `accSeq`, và cái giá phải trả là **một transaction thừa**: để tiêu tiền vừa nhận,
   ví phải `rollOver(self)` trước (~28k gas ≈ $0.00006 trên Gnosis). Với một batch 300 người nhận, 300 lần rollOver
   là **8.4M gas ≈ $0.017** — cùng bậc với chính batch transfer, và **relayer-driven được** (§03.5.5): worker theo
   dõi `pendingSeq` và tự gọi `rollOver` gasless. Chi phí này phải nằm trong mô hình chi phí của batch Zether;
   bản nháp bỏ qua nó hoàn toàn.

**`atomicity='atomic'`: khi nào, và nó thực sự nghĩa là gì.**

`atomic` chỉ dùng khi nghiệp vụ **thực sự** đòi tất-cả-hoặc-không — ví dụ một đợt chi thưởng mà chỉ một phần là vi
phạm chính sách. Mặc định `chunked`, vì trong payout B2B thực tế, 299 người được trả và 1 người bị giữ lại là kết
quả **đúng**, không phải lỗi.

**Nhưng "một tx" không tự động có nghĩa atomic.** §09 M17 chốt rằng `disperseToken` phải `try/catch` từng transfer
và phát event thành/bại theo từng dòng — nếu không, một người nhận là contract revert làm hỏng cả lô. Nghĩa là một
tx có thể chứa cả thành công lẫn thất bại. Vậy:

| Ta muốn | Contract phải | `atomicity` |
|---|---|---|
| Tất cả hoặc không | **không** try/catch; revert toàn bộ | `atomic` |
| Tối đa số người được trả | try/catch từng dòng, event `TransferFailed(ref, reason)` | `chunked` |

Hai hành vi này là **hai hàm khác nhau trên contract** (`disperseStrict` và `disperseBestEffort`), không phải một
cờ truyền vào. Một cờ bố-cục khiến một lần đọc audit không trả lời được câu hỏi "hàm này có thể trả một phần
không". Chốt: hai hàm, hai selector, hai đường test.

---

### 15.8. Cái settlement layer KHÔNG làm

Viết ra vì một lớp "thống nhất" luôn bị đề nghị làm thêm, và mỗi lần thêm một thứ là một lần `depends` mới.

| Không làm | Ai làm | Vì sao không ở đây |
|---|---|---|
| Tính số tiền | Chứng từ gốc (`dms.trade.settlement.amount` computed từ claim) | "Amount không lấy từ client" là nguyên tắc của chính DMS. Settlement layer nhận một số, không tính một số |
| Thuế / VAT | Chứng từ gốc | Thuế thuộc về giao dịch thương mại, không thuộc về phương tiện thanh toán |
| Duyệt nghiệp vụ | Chứng từ gốc | `blockchain_authorize_payout` là duyệt **chi tiền**, không phải duyệt **khoản chi** |
| Chọn chain / token | `blockchain.money.flow` (§09.4) | Một settlement nhận chain và token đã được quyết |
| Ký | Custody provider (§07) | Core không bao giờ thấy khoá |
| Broadcast | Relay worker (§06) | Odoo không mở socket tới chain từ HTTP worker (§10.1) |
| Quyết định finality | Finality Gate (§11) | Settlement chỉ **nhận** tín hiệu |
| Đối soát ngân hàng fiat | `dms.bank.reconciliation`, `account.reconcile.model` | Đã có, và tốt hơn cái ta sẽ viết |
| **[BẢN 3]** Xác minh provenance của token | `blockchain.token._verify_provenance()` (§10.4.4) | Settlement chỉ **đọc** `provenance_verified`. Một lớp thanh toán tự đi kiểm contract là một lớp thanh toán có quyền quyết định tiền nào hợp lệ |

---

### 15.9. Kiểm chứng bắt buộc cho section này

Mỗi mục phải xanh trước khi gọi section này là xong. Mục có SQL thì **chạy SQL**, không đọc code (bẫy #2 CLAUDE.md).

1. `SELECT conname, contype FROM pg_constraint WHERE conrelid = 'blockchain_settlement_batch'::regclass;` — phải có
   `UNIQUE(company_id, origin_key)` và CHECK `chunk_size`. `_sql_constraints` dạng list bị Odoo 19 bỏ qua.
2. `SELECT conname FROM pg_constraint WHERE conrelid = 'blockchain_settlement_batch_chunk'::regclass;` — phải có
   `UNIQUE(batch_id, sequence)`.
3. `SELECT indexname FROM pg_indexes WHERE indexname = 'blockchain_settlement_origin_idx';` — một dòng. Không có
   dòng nào nghĩa là mọi truy vấn ngược về chứng từ là seq scan trên 1.25 triệu dòng.
4. Tạo settlement, kill worker giữa broadcast, restart → `_cron_reconcile_orphan_tx()` gắn lại tx, không sinh
   settlement thứ hai, không sinh tx thứ hai.
5. Kill worker sau khi `claim` trước khi broadcast → `_cron_reap_stale_jobs()` trả job về `ready` sau 5 phút.
   Nhưng nếu chunk **đã có** `tx_hash`, job **không** được trả về `ready`.
6. Khoá kỳ kế toán rồi ép một settlement sang `final` → `settle_state='final'` **và** `gl_state='failed'` **và**
   `gl_error` chứa nguyên văn thông điệp. Không được rollback về `pending_finality`.
7. Post GL thành công rồi kill process trước khi ghi `gl_state='posted'` → chạy lại cron: **không** sinh bút toán
   thứ hai (`bamboo_create_idempotent` trên `uuid5(NS_GL, settlement_uuid)`).
8. Cài `dms_blockchain` không có `account`: không lỗi import, mọi settlement `gl_state='not_required'`,
   `_cron_post_gl` không tồn tại hoặc không làm gì.
9. Cài `dms_blockchain_account` **trước khi** cấu hình `payment_account_id` → `_check_setup()` trả về 4 mã lỗi,
   module cài được, không raise. Post một settlement → `gl_state='failed'` với đúng thông điệp của Odoo.
10. Gỡ `dms`: `origin_model='dms.trade.settlement'` còn trong bảng; `_notify_origin()` skip im lặng (có log WARNING),
    không raise, và `notified_datetime` được đặt.
11. Đặt `origin_model='res.users'` bằng SQL trực tiếp rồi chạy `_cron_notify_origin()` → log WARNING, cron **không
    chết**, các settlement khác vẫn được thông báo.
12. Netting set không cân bằng → `@api.constrains` raise. Viết test thật, không tin đọc code.
13. Đối soát trên token `is_confidential` với một entry bị xoá thủ công → phải ra `zether_nonce_gap` với
    `severity='block'`, và `run_state` phải là `drift`, không phải `clean`.
14. Đối soát trên token `is_confidential` mà ta **không** giữ khoá → `run_state='partial'`, **không bao giờ**
    `clean`. Báo "clean" ở đây là một lối nói dối.
15. Luồng collection: bắt một settlement `final` → có đúng **một** `account.payment`, không phải hai. Chạy đối soát
    hướng (B) → 0 dòng `orphan_move`.
16. `_blockchain_origin_key()` gọi hai lần cách nhau một `write()` lên chứng từ gốc → cùng một chuỗi.
17. Ép một settlement `final` → `disputed` bằng cron reorg giả lập → `gl_state` **không đổi**, không có bút toán
    đảo nào được sinh tự động.
18. Chạy `_cron_reconcile_ledger()` trên 1 triệu dòng settlement giả lập → dưới 15 giây/run. Nếu quá, index biểu
    thức trên `(amount_base::numeric)` chưa được tạo.
19. **[BẢN 3]** Tạo hai `blockchain.token` cùng `symbol='zDAI'` khác `address` → hai journal khác nhau, hai dòng
    `blockchain.token.rate` khác nhau, và một settlement trỏ token A **không** khớp được với một effect của token B.
20. **[BẢN 3]** Đặt `provenance_verified = False` trên token của một settlement `draft` → `_preflight()` trả về
    `token_provenance_unverified` và `blockchain_authorize_payout` từ chối.

---

### 15.10. Còn phải người quyết

1. **Điểm thưởng có hạn sử dụng không?** Nếu không, `Loyalty liability` tăng không giới hạn và không bao giờ được
   giải phóng. Đây là một quyết định kế toán và pháp lý, không phải kỹ thuật, và nó chặn §15.4.8.
2. **`posting_policy` theo money-flow hay toàn hệ thống?** §15.4.3 đề xuất theo flow. Nếu kế toán đòi một chính
   sách duy nhất cho dễ kiểm toán, chốt toàn hệ thống và chấp nhận 6,250 bút toán đảo/năm ở luồng collection.
3. **`dms.payment.collection` có nên có `event_uuid` như `dms.trade.settlement` không?** Hiện tại không có, nên
   `origin_key` phải là `dms.payment.collection:<id>` — ổn định nhưng không mang ý nghĩa nghiệp vụ, và không dùng
   được làm `operation_uuid` cho `_dms_once` nếu ai đó đổi chính sách. Thêm một field là một thay đổi trong `dms`,
   không trong bridge.
4. **Netting: có điều khoản bù trừ trong hợp đồng với NPP chưa?** Nếu chưa, §15.6.3 không được bật lên ở production
   dù code chạy đúng.
5. **Ai là người thứ hai trong `blockchain_resolve_dispute`?** §15.2.6 đòi treasury. Với một số tiền đủ lớn, đòi
   hai người (four-eyes) — nhưng Odoo không có cơ chế four-eyes sẵn. Xây hay chấp nhận một người?
6. **Ngưỡng `recon_slack_base`: 0 hay khác 0?** Chốt mặc định 0 ở đây. Nếu một token có fee-on-transfer được đưa
   vào, phải quyết lại và phải ghi lý do vào `mail.thread` của token.
7. **Chain private rewind: ai có quyền, và có bị log không?** `_cron_anchor_verify` phát hiện được, nhưng nếu chính
   operator là người rewind thì anchor cũng do operator ký. Cần một bên thứ ba giữ khoá neo, hoặc chấp nhận rằng
   đảm bảo chỉ là "chứng minh được với bên ngoài", không phải "chặn được từ bên trong".
8. **[BẢN 3] Ai quyết một token của người lạ được vào `accepted_token_ids`?** Provenance verify chứng minh được
   contract do factory sinh ra và khớp bản đã audit — nó **không** chứng minh được người tạo sẽ không bỏ rơi vault.
   Đó là một phán đoán thương mại, và §10.13 mục 10 để ngỏ giữa "danh sách thủ công" và "điểm tin cậy suy ra".
   Settlement layer chỉ đọc kết quả; ai đó phải là người quyết.

---

### 15.11. Mâu thuẫn cần đồng bộ giữa các section

| Chỗ | Hiện tại | Phải sửa thành | Ai sửa |
|---|---|---|---|
| §10.4.8 `settle_state` | có `reversed` | bỏ `reversed`, thêm `compensated` và `disputed` | §10 |
| §10.4.7 nonce Zether | `UNIQUE(token_id, account_id, zether_nonce, direction)` | `UNIQUE(token_id, account_id, zether_nonce)`; `zether_nonce` NULL cho `deposit`/`transfer_in` | §10 |
| §10.8 `posting_policy` | một khoá `ir.config_parameter` toàn cục | field trên `blockchain.money.flow`, fallback về config param | §10, §09 |
| §10.4.8 | không có `batch_id`, `chunk_id`, `gl_state`, `transport` | thêm (liệt kê ở §15.2.2) | §10 |
| §15 v1 gas Zether | 250,000/transfer | 1,880,000 (32/64), theo §03.3.6 | **đã sửa ở đây** |
| §15 v1 giá gas Gnosis | 1.5 gwei | 2 gwei, theo §09.10a | **đã sửa ở đây** |
| §15 v1 chunk 150 | "9M gas" | 4,521,000 gas/chunk | **đã sửa ở đây** |
| §15 v1 epoch Zether | còn nói về epoch rollOver | `accSeq`, theo §03.5.4 | **đã sửa ở đây** |
| §15 v1 model DMS | `dms.trade.settlement.line` + `payout_state` | `dms.trade.settlement` + `state`/`settled_external` | **đã sửa ở đây** |
| **[BẢN 3]** Chain private | §15 v1 giả định QBFT, instant finality | Nethermind + Clique, một signer, pre-London, reorg được | **đã sửa ở đây** |
| §11.5 dependency | `depends: ['base', 'bamboo_idempotency']` | phải khớp `__manifest__` của §10.1 (`['base', 'mail']`) — **một trong hai sai** | §10 hoặc §11 |

---

## 15.12. Cập Nhật Chuẩn Tắc V3: Giao Thức Đấu Thầu Phong Bao Kín & Quỹ Dòng Tiền Vesting Streaming

*(Chi tiết đầy đủ xem `SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md` §2 và `ai-enterprise-blockchain-architecture.md` §3.6, Chapter 10)*

### 15.12.1. Giao Thức Đấu Thầu Phong Bao Kín (Sealed-Bid Tender — `ISealedBidTender`)
Để tự động hóa và bảo mật quy trình Mua sắm Doanh nghiệp (Procure-to-Pay), loại trừ thông đồng và chậm trễ hoàn tiền ký quỹ:
1. **Pha 1 (Commit):** Nhà thầu nộp tiền cọc escrow vào hợp đồng (`deposit >= minDeposit`) và gửi cam kết giá thầu kín:
   $$\text{bidCommitment} = \text{keccak256}(\text{abi.encodePacked}(\text{price}, \text{salt}, \text{bidder}))$$
2. **Pha 2 (Reveal):** Khi hết hạn nộp thầu, các bên nộp `(price, salt)` để mở thầu công khai.
3. **Pha 3 (Quyết toán & Hoàn cọc 100%):** Hợp đồng xác định nhà thầu thắng cuộc để tạo Purchase Order trong Odoo ERP. **Hợp đồng tự động mở lệnh hoàn trả 100% tiền cọc cho toàn bộ nhà thầu trượt thầu** (`withdrawDeposit()`), không giữ cọc và không cần nhân sự kế toán duyệt thủ công. Nhà thầu cố tình không mở thầu bị tịch thu tiền cọc (slash).

### 15.12.2. Quỹ Dòng Tiền Rút Định Kỳ (Vesting Streaming Vaults — `IVestingVault`)
- Tự động hóa giải ngân liên tục theo dòng thời gian thực (block-by-block streaming hoặc các mốc cliff) cho hợp đồng lao động, thưởng cổ phiếu ESOP hoặc nghiệm thu thầu theo tiến độ.
- Người thụ hưởng rút tiền bất kỳ lúc nào qua Meta-Tx hoàn toàn gasless. Doanh nghiệp có thể cấu hình tính năng thu hồi (Revoke) để hoàn trả phần token chưa mở khóa về ngân quỹ công ty.