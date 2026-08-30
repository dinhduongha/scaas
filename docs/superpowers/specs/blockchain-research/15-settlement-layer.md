## 15. Lop settlement thong nhat va doi soat voi ke toan

> Section 10 la canonical ve ten model va ACL. Section nay **khong dinh nghia lai** `blockchain.settlement`; no
> bo sung nhung thu section 10 chua co: (a) tang batch va he qua atomicity on-chain, (b) crash-safety tung buoc,
> (c) cau ke toan `account.move` va FX, (d) routine doi soat drift, (e) hop dong callback nguoc ve consumer.
> Cho nao lech voi §10 duoc danh dau **[SUA §10]**. Cho nao ban nhap cu cua chinh section nay sai duoc danh dau
> **[SUA §15 v1]** — co bay cho, va ba trong so do la sai su that ve model `dms` chu khong phai sai thiet ke.

---

### 15.0. Muoi gia dinh ban nhap khong noi ra

Moi dong duoi day la mot thu ban nhap **coi la hien nhien**. Neu mot trong chung sai o deployment that, thiet ke
hong theo mot cach khong co canh bao.

| # | Gia dinh ngam | Neu sai thi sao | Chot o day |
|---|---|---|---|
| A1 | Mot `blockchain.settlement` co dung mot nguoi nhan | Payout "1 brand → 300 NPP" khong con la 300 settlement ma la 300 line trong mot record, va toan bo lap luan §15.1 sup | Giu A1 **la mot bat bien co the kiem tra**: `payee_account_id` la `required` khi `transport='onchain'` |
| A2 | Consumer luon co the sinh mot `origin_key` **on dinh** truoc khi goi | Retry sau crash sinh key moi ⇒ chi tra hai lan. Day la che do hong dat nhat trong ca section | §15.3.4: key phai la ham thuan cua chung tu, **khong** chua timestamp, khong chua `uuid4()` |
| A3 | Chain la nguon su that ve **da xay ra**, Odoo la nguon su that ve **dinh lam gi** | Neu dao chieu, mot reorg se ghi de mot quyet dinh nghiep vu | §15.2.6 |
| A4 | Mot settlement `final` khong bao gio quay lai | `finalized` tag noi doi duoc (§11.3b), chain private rewind duoc | Them state `disputed`. **`final` khong con la terminal tuyet doi** |
| A5 | Odoo doc duoc so tien cua moi settlement | Voi Zether va khong giu khoa, khong doc duoc | §15.4.8 + §15.5.5 |
| A6 | `account` da duoc cai va cau hinh xong | Mode 4 mac dinh chay khong co `account`; va khi co `account`, van con **bon** thu phai cau hinh truoc khi post duoc dong dau tien | §15.4.1 |
| A7 | Mot settlement sinh dung mot but toan | Netting sinh ba; compensation sinh mot but toan doc lap; batch mode 4 sinh mot but toan cho **N** settlement | `gl_state` la mot may trang thai **rieng**, khong phai mot Boolean |
| A8 | Ty gia trong ngay la du | USDC roi ve ~$0.87 trong phien 11/03/2023 (depeg SVB), lech ~13% so voi rate cuoi ngay | §15.4.5: rate phai co `fx_rate_datetime`, khong chi `date` |
| A9 | Relayer fee va gas la chi phi cua ai do khac | Chung la chi phi that, bang token that, va neu khong vao so thi sub-ledger va GL khong bao gio khop | §15.4.2 co but toan cho ca hai |
| A10 | Doi soat chay duoc bang cach "hoi chain" | Khong RPC nao tra loi "moi transfer den dia chi X tu truoc toi nay". Phai co indexer | §15.5.3: huong (A) la anti-join voi `blockchain.chain.effect` cua §11, **khong** phai mot lenh goi RPC |

---

### 15.1. Settlement la "y dinh chuyen gia tri", khong phai "giao dich"

#### 15.1.1. Ba truc doc lap

Mot rang buoc phai noi truoc vi no quyet dinh moi thu con lai: **`blockchain.settlement` khong tuong ung 1-1 voi
mot transaction on-chain.** Anh xa that la N-1: nhieu settlement dung chung mot `blockchain.transaction` (batch
payout), va mot settlement co the trai qua nhieu transaction (replace-by-fee, retry sau khi drop). Neu ai do thiet
ke voi gia dinh 1-1, buoc dau tien lam vo no la brand tra 300 nha phan phoi trong mot tx.

| Truc | Model | Don vi | Ai so huu |
|---|---|---|---|
| **Y dinh nghiep vu** | `blockchain.settlement` | Mot khoan tien, mot ben nhan, mot `origin_key`. Don vi idempotency va don vi ke toan. | Consumer (bridge) |
| **Van chuyen** | `blockchain.settlement.batch` | Mot lo duoc gui cung nhau. Don vi toi uu gas, **don vi lane 2D nonce**, don vi retry. | Core |
| **Su that on-chain** | `blockchain.transaction` / `blockchain.chain.effect` (§11) | Cai da xay ra. Don vi finality va don vi reorg. | Indexer |

Truc thu hai la thu §10 thieu. Bo sung.

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
    line_count      = fields.Integer(compute='_compute_totals', store=True, default=0)
    total_base      = fields.Char(compute='_compute_totals', store=True, default='0')
    settled_count   = fields.Integer(compute='_compute_totals', store=True, default=0)
    failed_count    = fields.Integer(compute='_compute_totals', store=True, default=0)
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

`_compute_totals` la stored computed: **phai gan gia tri o moi nhanh**, ke ca khi `settlement_ids` rong. Dat bon
dong gan mac dinh o **dau** method, truoc moi `if`:

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

Hai chi tiet khong hien nhien:

1. `sum(int(...))` dung so nguyen Python (khong gioi han bit), **khong** `float`. Mot tong 300 × 10^24 base units
   vuot `2^53` va `float` se lam tron im lang. Day la cung ly do §10.4.1 cam `fields.Float` cho `amount_base`.
2. `total_base` la `Char` nen **khong group by hay so sanh so hoc duoc trong domain**. Bao cao tong theo lo phai
   dung `amount_display` (Float, §10.4.1) hoac `read_group` tren mot cot Numeric phu. Neu ai do can so sanh chinh
   xac trong SQL, them mot cot `total_numeric = fields.Float(digits=(38, 0))`? **Khong** — dung
   `column_type` mac dinh khong du. Cach dung: mot index bieu thuc
   `CREATE INDEX ... ON blockchain_settlement ((amount_base::numeric))` khai qua `init()`, va cac truy van doi soat
   cua §15.5 dung SQL truc tiep chu khong qua ORM. Viet ra vi day la thu se bi phat hien vao dung luc mot bao cao
   tong dau tien duoc yeu cau.

#### 15.1.3. Vi sao khong phai "mot settlement, nhieu line"

De xuat header/line nghe hop ly va sai o dung mot cho: **trang thai**. Mot payout toi 300 nha phan phoi co 300 ket
cuc doc lap — mot dia chi bi dong bang KYC, mot dia chi go sai, mot ben chua register Zether. Neu ca 300 nam trong
mot record thi `settle_state` phai noi doi ve 299 dong con lai, `origin_key` khong con la khoa idempotency cua tung
khoan chi, va bridge khong co cho de ghi nguoc trang thai ve tung chung tu goc. Nguoc lai, batch chi la mot nhan
van chuyen: mat no khong mat gi, tao lai no khong mat gi.

**[SUA §15 v1] Va co mot ly do manh hon ban nhap khong biet: trong `dms`, "300 nha phan phoi" von da la 300 record.**
`dms.trade.settlement` co dung mot `beneficiary_partner_id` (`required=True`), va `amount` la computed tu
`claim_ids.approved_amount`. Khong ton tai mot chung tu DMS nao mang N nguoi nhan. Vay anh xa 1 settlement ↔ 1 chung
tu la **anh xa tu nhien**, khong phai mot lua chon phai bien ho. Ban nhap dan `dms.trade.settlement.line` lam vi du
"payout line" — sai, xem §15.6.0.

#### 15.1.4. Do lon: bao nhieu record, bao nhieu batch

Uoc tinh, co so: deployment DMS 5,000 outlet, 500 nha phan phoi, chu ky settlement thang.

| Doi tuong | So luong/nam | Ghi chu |
|---|---|---|
| `blockchain.settlement` (B2B payout) | 500 × 12 = 6,000 | 1/NPP/thang |
| `blockchain.settlement` (outlet collection) | 5,000 × 250 ngay = 1,250,000 | dong lon nhat |
| `blockchain.settlement` (loyalty) | ~200,000 | phu thuoc chuong trinh |
| `blockchain.settlement.batch` | 12 (B2B) + 250 (collection theo ngay) + 12 (loyalty) ≈ 274 | rat it |
| `blockchain.settlement.batch.chunk` | 12 × ceil(500/150) = 48, cong collection | |
| Dung luong `blockchain_settlement` + index | ~1.2 GB/nam (uoc tinh, co so ~400 B/dong ke ca 8 index) | |

Ket luan lam viec: **bang settlement la bang lon, bang batch la bang nho.** Moi index dat tren settlement phai
duoc bien ho; moi index tren batch la mien phi.

---

### 15.2. Vong doi va noi crash

#### 15.2.1. Bang chuyen trang thai day du

Ban nhap ve mot so do va bo trong cot "ai duoc phep". Do la cot quan trong nhat: mot may trang thai khong noi ai
bam nut la mot may trang thai chua duoc thiet ke.

**[SUA §10]** `reversed` doi thanh `compensated`; them `disputed`. Ly do `compensated` khong phai tham my:
`reversed` goi y mot phep dao tren chinh ban ghi cu, ma so cai on-chain khong co UNDO. `compensated` mo ta dung co
che: mot settlement moi, chieu nguoc, co `origin_key` rieng, co tx rieng, tro ve ban goc bang `compensation_of_id`.
Ban goc van `final` vinh vien — vi no *da* xay ra.

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

| Tu | Den | Ai/cai gi kich hoat | Nhom | Dieu kien cung |
|---|---|---|---|---|
| `draft` | `authorized` | `blockchain_authorize_payout` | **treasury** | pre-flight pass (duoi) |
| `draft` | `expired` | `_cron_expire_settlements` | he thong | `create_date + settlement_ttl_hours < now` |
| `authorized` | `submitted` | `_cron_advance_authorized` hoac `blockchain_submit_settlement` | operator/he thong | co metatx da ky, co `blockchain.relay.job` |
| `authorized` | `failed` | `blockchain_cancel_settlement` | treasury | chua co tx nao |
| `submitted` | `broadcast` | relay worker ghi `tx_hash` | he thong | `UNIQUE(chain_id, tx_hash)` |
| `submitted` | `expired` | `_cron_expire_metatx` | he thong | `metatx.expiry_datetime < now` va chua co tx |
| `broadcast` | `pending_finality` | `_cron_poll_receipts` | he thong | receipt `status == 1` |
| `broadcast` | `failed` | `_cron_poll_receipts` | he thong | receipt `status == 0` (reverted) |
| `broadcast` | `submitted` | replace-by-fee | he thong | qua `finality_warn_seconds`, cung lane |
| `pending_finality` | `final` | **chi** `_set_finality` | he thong | §11.3 gate: `finality_source` thoa + hash check |
| `pending_finality` | `failed` | `_cron_poll_receipts` | he thong | tx bi `dropped` va lane da bi mot tx khac chiem |
| `final` | `disputed` | `_cron_reorg_watch` (§11.4) hoac `_cron_anchor_verify` | he thong | block chua tx khong con tren canonical chain |
| `disputed` | `final` | `blockchain_resolve_dispute` | **treasury** + auditor | nguoi that xac nhan sau khi doc bang chung |
| `disputed` | `compensated` | tao settlement nguoc | treasury | |

**Pre-flight truoc khi cho `authorized`** — ban nhap khong co, va thieu no thi tien di ra roi moi biet dia chi sai:

```python
def _preflight(self):
    """Tra ve list ly do khong the authorize. Rong = pass. KHONG raise: caller can biet TAT CA ly do."""
    self.ensure_one()
    r = []
    if self.chain_id.state != 'enabled':                      r.append('chain_not_enabled')
    if self.transport == 'onchain' and not self.payee_account_id: r.append('no_payee_account')
    if self.payee_account_id.state != 'active':               r.append('payee_frozen')
    if self.token_id not in self.chain_id.token_ids:          r.append('token_not_on_chain')
    if self.confidential and not self.payee_account_id.zether_registered: r.append('payee_not_registered')
    if int(self.amount_base) <= 0:                            r.append('non_positive_amount')
    if int(self.amount_base) > int(self.token_id.max_amount_base or '0'): r.append('exceeds_token_max')
    return r
```

`payee_not_registered` la ly do dung nhat de mot batch Zether 300 nguoi that bai o dong thu 47, va no phat hien
duoc **truoc** khi tra mot xu gas. Voi Zether, `registry.isRegistered(to)` la mot `eth_call` — 300 lan goi la mot
multicall, khong phai 300 round-trip.

#### 15.2.2. Ep bang code, khong bang tai lieu

§10.11 kiem chung #8 doi mot test rang khong duong nao ghi `final` ngoai `_set_finality`. Co che:

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

`_set_finality` la ben duy nhat dat `blockchain_state_engine=True` trong context. Mot cai co trong context la mot
hang rao yeu — **co y**: no chan nham lan, khong chan ac y (ai co quyen write thi cung set context duoc). Hang rao
that la ACL: `perm_write` tren `blockchain.settlement` khong bao gio cap cho `group_blockchain_viewer`, va
`_set_finality` chi duoc goi tu cron chay bang `sudo()`.

Ba field vong doi bat buoc phai co, §10 chua liet ke:

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

`gl_state` tach roi khoi `settle_state` la quyet dinh quan trong nhat cua muc nay. Xem §15.4.4.

#### 15.2.3. Lane 2D nonce thuoc ve BATCH, khong thuoc ve settlement

**[SUA §15 v1]** Ban nhap suy lane tu `origin_key` cua **settlement**. Sai khi co batch: mot chunk 150 settlement
la **mot** metatx, nen no chi co **mot** `(batchId, batchNonce)`. Neu moi settlement suy ra mot lane rieng thi hoac
lane bi bo qua, hoac ta phai chon tuy tien lane cua settlement nao trong 150.

Chot lai:

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

Ba he qua:

1. `chain_id.caip2` co trong seed ⇒ cung mot `origin_key` settle tren hai chain khac nhau cho hai lane khac nhau.
   Khong co no, mot retry sau khi doi chain se dung lai lane cu tren chain moi — vo hai nhung gay nham lan khi debug.
2. Mot chu ky bi ro ri, bi phat lai, hoac duoc hai relayer cung nop → tx thu hai revert vi
   `meta_nonce(from, batchId)` da tang. **On-chain la trong tai, khong phai Odoo.** Day cung la ly do
   `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` cua §10 phai giu.
3. Mot chi tiet ban nhap khong noi: khi metatx het han (`expiry_datetime`) va ta ky lai, digest **khac** (expiry
   khac) nhung lane **giong**. Ket qua: hai chu ky hop le tren cung lane. Neu ca hai cung duoc nop, cai thu hai
   revert. Dung, nhung phai ghi ro trong runbook, vi mot relayer se bao "tx cua toi revert" va do la hanh vi dung.

#### 15.2.4. Outbox, khong phai RPC trong request

Lenh goi relay worker **khong duoc** nam trong transaction cua `blockchain_submit_settlement`. Neu goi, hai che do
hong deu that: HTTP thanh cong roi transaction rollback (worker broadcast mot khoan chi Odoo khong con biet), hoac
transaction commit roi HTTP timeout (khong ai biet worker co nhan hay khong).

Chot: ghi mot dong `blockchain.relay.job` trong **cung** transaction voi `settle_state='submitted'`; worker poll.
Do la transactional outbox, va no la ly do `bamboo_idempotency` (§11.5) phai la dependency.

Model nay ban nhap goi ten ma khong dinh nghia:

```python
class BlockchainRelayJob(models.Model):
    _name = 'blockchain.relay.job'
    _description = 'Transactional outbox row for the relay worker'
    _order = 'priority desc, id'

    chunk_id     = fields.Many2one('blockchain.settlement.batch.chunk', index=True, ondelete='cascade')
    settlement_id= fields.Many2one('blockchain.settlement', index=True, ondelete='cascade')
    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True)
    payload_attachment_id = fields.Many2one('ir.attachment')   # metatx + signature, len Garage
    payload_sha256 = fields.Char(size=64, index=True)
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

Bon chi tiet van hanh ban nhap bo qua:

1. **Worker claim bang `SELECT ... FOR UPDATE SKIP LOCKED`**, khong bang `write({'job_state': 'claimed'})` sau mot
   `search`. `search` roi `write` la mot race duoc trang tri thanh mot bao dam. Odoo cho phep SQL tho o day; day la
   dung cho de dung no.
2. **`claimed` co timeout.** Mot worker chet giua chung de lai mot job `claimed` vinh vien. Cron
   `_cron_reap_stale_jobs()` tra job ve `ready` khi `claimed_datetime < now - 5 min` **va** chunk chua co `tx_hash`.
   Neu chunk **da co** `tx_hash`, khong tra ve — do la truong hop worker da broadcast xong.
3. **Dead letter sau 5 lan.** Backoff 1/5/15/60/240 phut roi `job_state='dead'` + `mail.activity` cho
   `group_blockchain_treasury`. Mot cron retry vo han tren mot loi cau hinh tao 1,440 activity/ngay va khong ai doc.
   (Cung quy tac §11.5.)
4. **Do tre.** Poll 1 phut la qua cham cho `ENDUSER_PAY` (§09.5d). Dung `self.env.ref('dms_blockchain.cron_relay_dispatch').sudo()._trigger()`
   ngay sau khi tao job — `_trigger()` cua Odoo 19 lap lich mot lan chay ngay ma **khong** goi HTTP trong
   transaction; no chi ghi mot dong `ir_cron_trigger`, va dong do rollback cung transaction neu transaction hong.
   Do la dung tinh chat ta can.

#### 15.2.5. Bang crash

Doc theo cot giua: "sau crash, tren dia co gi". Moi dong deu phai an toan **ma khong can nguoi**.

| Crash tai | Tren dia | Phuc hoi |
|---|---|---|
| Sau `submit` RPC, truoc commit | Khong co gi | Client retry cung `origin_key`; `_submit` tra ban ghi cu hoac tao moi. Idempotent. |
| Sau khi tao settlement `draft` | `draft` | Khong lam gi. `draft` khong tieu ton tai nguyen nao. Expiry sweep don sau `settlement_ttl_hours`. |
| Sau `authorized`, truoc khi build metatx | `authorized` | `_cron_advance_authorized()` build lai metatx tu lane suy dien. |
| Sau khi goi custody ky, truoc commit | `authorized`, chu ky mat | Ky lai. Digest giong het khi expiry chua doi; neu doi thi digest khac nhung **lane giong** (§15.2.3). Chu ky cu neu da ro ri thi vo hai. |
| Sau commit `submitted` + `relay.job`, truoc khi worker doc | `submitted` + job `ready` | Worker poll thay job. **Khong bao gio goi worker trong cung request transaction.** |
| Worker da claim, chet truoc khi broadcast | job `claimed`, khong co tx | `_cron_reap_stale_jobs()` tra ve `ready` sau 5 phut. An toan vi lane chua bi tieu. |
| Worker da broadcast, Odoo chua ghi `tx_hash` | `submitted`, chain co tx | Worker retry ghi; `UNIQUE(chain_id, tx_hash)` chan trung. Neu worker cung chet: `_cron_reconcile_orphan_tx()` quet tx tu `payer_account` co `ref` khop lane → gan lai. |
| Batch `chunked`: chunk 3/7 broadcast, crash | 3 chunk co tx, 4 chunk `draft` | Cron tiep tuc tu `sequence` nho nhat con `draft`. **Khong** gui lai chunk da co tx. `batch_state='partial'`. |
| Batch `atomic`: chunk duy nhat revert | 0 settlement `final` | Ca batch → `failed`. Khong co gi de bu. Day la ly do `atomic` chi duoc dung khi nghiep vu doi vay. |
| Sau `broadcast`, node drop tx | `broadcast` qua `finality_warn_seconds` | Canh bao. Qua `finality_stuck_seconds` (§11.3) → replace-by-fee cung lane, hoac `failed` + page nguoi that. |
| Giua `_set_finality` va post `account.move` | `final` + `gl_state='queued'` | Cron `_cron_post_gl()` post sau. **Day la cho duy nhat can hai transaction.** Xem §15.4.4. |
| Sau khi post `account.move`, truoc khi ghi `gl_state='posted'` | move da post, `gl_state='queued'` | **Post lan hai la mot but toan trung.** Chan bang `bamboo_create_idempotent` tren mot khoa `uuid5(NS_GL, settlement.uuid)` **cung transaction** voi `move.action_post()`, dung nguyen mau §11.5b. |
| Sau `final`, truoc callback bridge | `final`, consumer chua biet | `_cron_notify_origin()` doc `notified_datetime IS NULL`, khong qua post-commit hook. |
| Reorg xoa block chua tx da `final` | `final` sai su that | §15.2.6: `disputed`, **khong** tu dong quay ve. |
| Compensation da tao, chua broadcast, crash | settlement moi `draft` co `compensation_of_id` | Binh thuong. Ban goc van `final`. |

**Cai bay tinh vi nhat, viet ra vi no khong nhin thay duoc:** `_apply` cua GL va callback bridge deu co the cham
he thong ngoai va deu **phai idempotent theo chinh no**, khong chi dua vao viec duoc goi mot lan. Mau:

```python
def _post_gl(self):
    self.ensure_one()
    if self.gl_state == 'posted':
        return                                  # goi lai la vo hai
    ...
```

#### 15.2.6. Reorg sau `final`: state `disputed`

Ban nhap khong co muc nay va do la mot lo hong nghiem trong: no gia dinh Finality Gate khong bao gio sai. §11.3b
liet ke ba cach `finalized` tag noi doi, va §11.3 ghi ro chain private **rewind duoc boi chinh operator**.

Quy tac:

- Khi `_cron_reorg_watch` (§11.4) thay block chua `transaction_id` khong con tren canonical chain:
  `settle_state: final → disputed`, `gl_state` **khong doi**, `mail.activity` cho treasury va auditor.
- **Khong tu dong dao but toan.** Mot but toan dao tu dong tren mot su kien co the la loi cua node la cach nhanh
  nhat de bien mot su co RPC thanh mot su co ke toan.
- `blockchain_resolve_dispute(origin_key, resolution)` voi `resolution ∈ {'confirmed', 'compensate'}`, nhom
  **treasury**, ghi `mail.thread` ly do. `confirmed` → ve `final`. `compensate` → giu `disputed`, tao settlement
  nguoc, va **khi settlement nguoc `final`** thi ban goc chuyen sang `compensated`.
- Tren chain private, `_cron_anchor_verify()` doi chieu head hash da neo (§11.3, HCS 60 s) voi head hien tai. Lech
  ⇒ moi settlement `final` sau diem neo cuoi cung → `disputed`. Chi phi: $53/nam. Gia tri: bien "toi hua khong
  rewind" thanh "rewind qua 60 s la chung minh duoc".

---

### 15.3. Lien ket nguoc ve chung tu nghiep vu, khong depend `dms`

#### 15.3.1. Ba lua chon Odoo chuan

| Co che | Luu gi | Search/join | Uninstall consumer | Callback | ondelete |
|---|---|---|---|---|---|
| `fields.Reference` | mot `Char` `'model,id'` | **Khong** index duoc theo id; `search` phai so sanh chuoi; khong group by duoc | De lai chuoi tro toi model khong con ton tai | Khong | Khong co |
| `fields.Many2oneReference` + `Char` model | `int4` id + `Char` model rieng | Index duoc tren id; `[('origin_model','=',m),('origin_id','in',ids)]` chay nhanh | Dong con lai nhung khong vo | Khong | **Khong co FK, khong co ondelete** |
| `models.AbstractModel` mixin | Khong luu gi; dinh nghia hop dong method | n/a | n/a | **Co** | n/a |

**Chot: dung ca ba, moi cai mot viec.**

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

**[SUA §15 v1]** Ban nhap viet `isinstance(target, type(rec.env['blockchain.settlement.origin']))`. Dung *tinh co*
(vi `type()` cua mot recordset la lop registry), nhung no phu thuoc mot chi tiet noi bo va doc ra thi khong ai biet
no kiem gi. Dang tren dung `self.env.registry.get(name)` — day la API cong khai cua registry, la idiom Odoo dung o
`mail` va `account`, va no khong can instantiate mot recordset chi de lay lop.

Ly do mixin nam o **core** chu khong o bridge: core la ben *goi* callback. Neu hop dong nam trong bridge, core phai
`hasattr`-sniff, va mot consumer khong phai DMS (mot addon khac, mot he thong ngoai qua RPC) khong co cho de cam
vao. Mixin trong core khong tao dependency nao: mot `AbstractModel` khong co bang, khong co ACL, khong co gi de go.

#### 15.3.2. Ba bay bao mat ban nhap khong noi

1. **`origin_model` la mot chuoi do client dat.** `blockchain_submit_settlement` nhan `meta` tu RPC. Neu bridge
   hoac client set `origin_model='res.users'`, core se goi `_on_blockchain_settlement` tren mot model khong co
   method do → `AttributeError` trong cron, cron chet, moi settlement khac dung lai. Chan bang kiem `issubclass`
   nhu tren, **va** bang cach **khong** cho `origin_model`/`origin_id` di qua be mat RPC cong khai: chung chi duoc
   dat boi code Python trong cung DB (bridge). RPC ngoai chi cung cap `origin_key`.
2. **Callback chay `sudo()`.** Bat buoc, vi cron chay bang user he thong va record rule cua consumer co the loc no
   ra. Nhung `sudo()` co nghia bridge co the ghi bat cu dau — nen callback phai kiem `company_id` truoc, nhu tren.
3. **`_on_blockchain_settlement` co the raise.** Mot bridge viet vung se lam cron `_cron_notify_origin` chet giua
   chung va cac settlement con lai khong bao gio duoc thong bao. Bat tung record trong savepoint:

```python
for rec in batch:
    try:
        with self.env.cr.savepoint():
            rec._notify_origin()
    except Exception:
        _logger.exception('callback origin that bai cho settlement %s', rec.id)
        rec.sudo().notify_error = tools.ustr(sys.exc_info()[1])[:500]
```

#### 15.3.3. `origin_key`: quy uoc khi mot chung tu sinh nhieu settlement

`UNIQUE(company_id, origin_key)` la chot chan cuoi. Netting sinh **ba** settlement tu mot cap chung tu; mot payout
bi compensate sinh **hai**. Nen `origin_key` phai co hau to co cau truc, khong phai mot so tang dan:

```
<origin_model>:<origin_id>[:<role>][:<attempt>]

dms.trade.settlement:4471                      # payout thuong
dms.trade.settlement:4471:gross_out            # chan gross cua netting
dms.trade.claim:9912:gross_in                  # chan gross nguoc chieu
netting:2026-03:P12345                         # chan net, khoa theo (ky, partner)
dms.trade.settlement:4471:comp:1               # compensation lan 1
```

**Cam tuyet doi**: `uuid4()`, `fields.Datetime.now()`, `time.time()` trong `origin_key`. Mot key khong on dinh la
mot key khong idempotent, va he qua la chi hai lan. Kiem bang mot test: goi `_blockchain_origin_key()` hai lan
cach nhau mot `write()` len chung tu goc va so sanh.

Trong `dms`, **da co san mot khoa dung**: `dms.trade.settlement._dms_event_uuid()` la mot UUIDv7 sinh mot lan,
`readonly=True, copy=False`, luu o `event_uuid`. Bridge dung no, **khong** tu che khoa moi (§15.6.1).

#### 15.3.4. Khong co FK: chung tu goc bi xoa

`Many2oneReference` khong tao FK, nen khong co `ondelete`. Ba hau qua, va chot cho tung cai:

| Tinh huong | Hau qua | Chot |
|---|---|---|
| Chung tu goc bi `unlink` | `origin_id` tro toi mot id khong con | `.exists()` o moi cho doc. Da co trong `_notify_origin`. |
| Consumer addon bi go | `origin_model` la mot ten model khong con trong registry | `model not in rec.env` → skip im lang. Da co. |
| Chung tu bi xoa **truoc khi** settlement `final` | Tien van di, khong ai nhan trang thai | `_cron_orphan_settlements()` hang ngay: settlement chua terminal ma `origin` khong `.exists()` → `mail.activity` cho treasury. **Khong** tu huy settlement: tien co the da tren duong di. |

Mot lua chon **da bi bac bo**: them mot `ir.model.constraint` gia hoac mot `@api.ondelete` tren consumer de chan
xoa. No doi core biet ten model consumer (vi pham rang buoc standalone), va no bien mot rang buoc cua core thanh
mot rao can trong workflow cua nguoi khac.

---

### 15.4. Cau ke toan: `account.move` nao, luc nao

Module `dms_blockchain_account` (`depends: ['dms_blockchain', 'account']`). Core **khong** biet `account.move` ton
tai. Bang chung: `_gl_required()` song trong module nay, va §10.11 kiem chung #4 doi cai core mot minh phai chay.

#### 15.4.1. Vi la mot `account.journal`, indexer la mot bank feed — va bon thu phai cau hinh truoc

Khong tu viet co che doi soat. Odoo da co day du:

- Mot `account.journal` `type='bank'` cho moi **(company, chain, token) co giu tien**. `currency_id` = currency cua
  token (§15.4.5). Tai khoan mac dinh = tai khoan tai san "Crypto wallet — <token> — <chain>".
- **Outstanding Payments / Outstanding Receipts** cua journal do chinh la **bieu dien ke toan cua mot chuyen khoan
  da broadcast nhung chua final**. Do dung la thu chung sinh ra de lam: mot tam sec da phat nhung chua duoc lay tien.
- `blockchain.chain.effect` da `final` → `account.bank.statement.line`. Tu do tro di la reconciliation widget,
  `account.reconcile.model`, va `dms.bank.reconciliation` cua DMS chay nguyen ven.

**[SUA §15 v1] Ban nhap dung o hinh dang va bo trang cai kho: Odoo 19 khong tu co outstanding account.**
`account.payment._compute_outstanding_account_id` trong Odoo 19 la dung mot dong:

```python
pay.outstanding_account_id = pay.payment_method_line_id.payment_account_id
```

**Khong co fallback nao.** Neu `payment_account_id` tren `account.payment.method.line` cua journal chua duoc dat,
`_prepare_move_line_default_vals` raise:

> "You can't create a new payment without an outstanding payments/receipts account set either on the company or the
> %(payment_method)s payment method in the %(journal)s journal."

Bon thu phai co truoc khi post duoc dong dau tien, kiem bang mot `_check_setup()` chay luc cai va truoc moi lo post:

| # | Thu | Neu thieu |
|---|---|---|
| 1 | `journal.inbound_payment_method_line_ids[0].payment_account_id` | `action_post()` raise, lo GL ket o `gl_state='failed'` |
| 2 | `journal.outbound_payment_method_line_ids[0].payment_account_id` | nhu tren, cho chieu chi |
| 3 | `company.currency_exchange_journal_id` + `income_/expense_currency_exchange_account_id` | reconcile hai dong khac ty gia raise, **khong** sinh exchange move |
| 4 | Tai khoan "Crypto dust / rounding" (loai `expense`) | dust khong co cho di, sub-ledger va GL khong bao gio khop (§15.4.6) |

`_check_setup()` tra ve list ma loi va hien tren dashboard doi soat §15.5, **khong** raise luc cai module — cai
module tren mot DB chua cau hinh chart of accounts khong duoc phep that bai.

#### 15.4.2. But toan cu the: cai ban nhap noi "sinh but toan" ma khong noi but toan gi

Day la lo hong lon nhat cua ban nhap. Duoi day la but toan cho tung su kien, chinh sach `on_final` (mac dinh),
mot brand tra mot NPP 100,000,000 VND bang Z-VND, phi relayer 500 VND.

**Luong OUT (B2B payout), `direction='out'`, `transport='onchain'`:**

| Su kien | But toan | Ghi chu |
|---|---|---|
| Chung tu goc posted (ngoai pham vi settlement layer) | Dr Trade payable 100,000,000 / Cr Rebate expense hoac Accrual | Do `dms.trade.settlement._dms_create_credit_note()` lam, khong phai chung ta |
| `authorized` | **khong but toan** | Mot cam ket chua phai mot su kien ke toan |
| `broadcast` | **khong but toan** (mode `on_final`) | Rui ro nam o sub-ledger; bao cao rieng, xem duoi |
| `final` | `account.payment` outbound posted:<br>Dr Trade payable (`destination_account_id`) 100,000,000<br>Cr Outstanding Payments 100,000,000 | Roi `account.bank.statement.line` −100,000,000 tren journal Z-VND, reconcile voi Outstanding Payments |
| Phi relayer (`fee_base` = 500) | Dr Bank/transaction fee expense 500<br>Cr Crypto wallet Z-VND 500 | Mot dong rieng tren cung statement line, hoac mot statement line thu hai. **Khong duoc gop vao 100,000,000** — no lam sai so du cong no |
| Gas native (chain profile `public`, relayer noi bo) | Dr Bank/transaction fee expense (native, quy doi)<br>Cr Crypto wallet <native> | Journal khac (token native). Neu `fee_mode='gasless'` (private chain) thi khong co but toan nao |
| `failed` sau `broadcast`, mode `on_final` | **khong co gi de dao** | Do la toan bo ly do `on_final` la mac dinh |
| `disputed` | **khong but toan tu dong** | §15.2.6 |
| `compensated` | But toan cua settlement nguoc (chieu `in`), doc lap, `ref` tro ve ban goc | Khong bao gio `unlink` |

**Luong IN (outlet collection), `direction='in'`:**

| Su kien | But toan |
|---|---|
| `final` | `account.payment` inbound posted: Dr Outstanding Receipts / Cr Trade receivable. Roi statement line +amount, reconcile. |
| Trong DMS: `dms_post_payment` da tao `account.payment` roi | **Khong tao them.** Bridge goi thang `dms_post_payment`, va `dms_blockchain_account` bo qua settlement co `gl_state='not_required'` do bridge dat. Xem §15.6.2 — day la cho hai module de dam nhau nhat. |

**Luong OFFSET (`transport='offset'`, netting):**

| | But toan |
|---|---|
| Chan gross out 100,000,000 | Dr Trade payable 100,000,000 / Cr **Netting clearing** 100,000,000 |
| Chan gross in 30,000,000 | Dr **Netting clearing** 30,000,000 / Cr Trade receivable 30,000,000 |
| Chan net 70,000,000 on-chain | Dr **Netting clearing** 70,000,000 / Cr Outstanding Payments 70,000,000, roi statement line |
| Tong tren Netting clearing | 100 − 30 − 70 = **0** | Neu khong bang 0, netting set khong can bang. Day la cho `@api.constrains` cua §15.6.3 phai bat. |

Tai khoan **Netting clearing** la tai khoan trung gian, loai `current_liability`, `reconcile=True`. No la thu bien
"netting la mot y tuong" thanh "netting la mot so du kiem tra duoc": so du cuoi ky cua no phai bang 0 cho moi ky da
dong. Mot bao cao mot dong.

**Mode 4 (sub-ledger, post theo lo) — but toan tong hop hang ngay:**

```
Dr Trade payable          Σ(payout final trong ngay)
    Cr Crypto wallet Z-VND    Σ(payout final trong ngay) + Σ(fee)
Dr Transaction fee expense   Σ(fee)
```

Mot `account.move` cho moi `(journal, direction, ngay)`. `ref` = `BLK/<chain>/<token>/<YYYY-MM-DD>/<direction>`.
`narration` chua so luong settlement va khoang id, de tra nguoc. **Khong** liet ke 5,000 dong chi tiet vao
`narration` — chung o sub-ledger, va sub-ledger la noi tra cuu.

#### 15.4.3. Chinh sach post

`ir.config_parameter blockchain.account.posting_policy` ∈ `{on_final, on_broadcast}`.

| Su kien | `on_final` (mac dinh) | `on_broadcast` |
|---|---|---|
| `authorized` | khong but toan | khong but toan |
| `broadcast` | khong but toan; rui ro nam o sub-ledger, bao cao rieng | `account.payment` posted → Dr Payable / Cr **Outstanding Payments** |
| `final` | `account.payment` posted **+** statement line **+** reconcile trong cung mot buoc | statement line → reconcile voi outstanding |
| `failed` sau `broadcast` | khong co gi de dao | `_reverse_moves(default_values_list=[{'date': ...,'ref': ...}], cancel=True)` — **khong bao gio unlink** |
| `disputed` | khong tu dong | khong tu dong |
| `compensated` | but toan cua settlement nguoc, doc lap | nhu tren |

`on_final` la mac dinh vi no giu GL sach khoi nhung giao dich chua tung xay ra. Doi lai, treasury mat tam nhin ve
tien da cam ket — bu bang mot **bao cao** doc tu sub-ledger, khong bang but toan:

```
Tien dang tren duong (committed, not settled)
  = Σ amount_display  WHERE settle_state IN ('broadcast', 'pending_finality')
  GROUP BY company, chain, token, direction
```

Bao cao nay phai o cung dashboard voi §15.5, va phai co cot "gia nhat cua khoan cu nhat" — mot khoan `broadcast`
tu ba ngay truoc la mot su co, khong phai mot con so.

`on_broadcast` danh cho deployment ma kiem toan doi tien mat cam ket phai hien tren bang can doi; gia phai tra la
nhung but toan dao khi tx fail. Dinh luong: voi ty le revert quan sat duoc ~0.5% (uoc tinh, co so: simulation gate
bat gan het, phan con lai la race ve so du va allowance), 6,000 payout/nam ⇒ ~30 but toan dao/nam. It. Voi
1,250,000 collection/nam ⇒ ~6,250 but toan dao/nam. Nhieu. Ket luan: `on_broadcast` chi hop ly cho luong B2B, va
day la mot ly do nua de `posting_policy` co the dat **theo money-flow** chu khong chi toan he thong.

**[SUA §10]** `blockchain.account.posting_policy` nen la mot field tren `blockchain.money.flow` (§09.4) voi fallback
ve `ir.config_parameter`, khong phai mot khoa toan cuc duy nhat.

#### 15.4.4. Ky ke toan bi khoa, va tai sao GL phai la mot transaction khac

**Buoc `final` sinh but toan khong duoc nam trong transaction cua `_set_finality`.** Ky ke toan bi khoa
(`account.move` raise `UserError` khi post vao ky da lock qua `fiscalyear_lock_date` / `tax_lock_date`) la mot su
co **thuong xuyen**, khong phai hiem — dac biet trong ba ngay dau thang. Neu post nam cung transaction, ca
`settle_state='final'` bi rollback va settlement ket vinh vien o `pending_finality` — Odoo noi doi ve mot khoan
tien da nam tren chain. Chot:

```python
def _set_finality(self):
    """Transaction 1: su that on-chain. Khong goi account.* o day."""
    self.with_context(blockchain_state_engine=True).write({
        'settle_state': 'final',
        'finality_datetime': fields.Datetime.now(),
        'gl_state': 'queued' if self._gl_required() else 'not_required',
    })

# ir.cron 'Blockchain: post GL', 5 phut, tren blockchain.settlement:
#   model._cron_post_gl()   -> doc gl_state='queued', post theo lo, bat UserError -> gl_state='failed'
```

Khi ky bi khoa, ba lua chon va chot:

| Lua chon | Hau qua | Chot |
|---|---|---|
| Post vao dung `finality_datetime` | raise, `gl_state='failed'`, cho nguoi mo ky | **Mac dinh.** Trung thuc, va ke toan la nguoi quyet dinh |
| Doi `move.date` sang ngay dau ky mo | GL khop ky, nhung ngay ke toan khac ngay su kien | Cho phep bang `blockchain.account.late_posting = 'shift'`; **bat buoc** ghi `finality_datetime` vao `ref` de truy nguoc |
| Bo qua | Tien mat khoi so | Khong bao gio |

`gl_state='failed'` la mot hang doi nguoi that phai xu ly. No hien tren dashboard doi soat §15.5, co `gl_error`
mang nguyen van thong diep `UserError`, **khong im lang**, va khong retry vo han: sau 3 lan that bai lien tiep,
cron ngung thu lai record do va tao mot `mail.activity` duy nhat.

#### 15.4.5. FX khi token khong phai currency cua cong ty

Ba truong hop, ba cach xu ly khac han. Gop chung la sai:

| Truong hop | Vi du | Xu ly |
|---|---|---|
| Token neo dung currency so sach | Z-VND tren so VND | **Khong** tao `res.currency` moi. Token la *phuong tien thanh toan*, journal dung company currency, khong co FX. |
| Token neo mot fiat khac | USDC tren so VND | Tao `res.currency` rieng ten `USDC` (**khong** dung `USD`: USDC khong phai USD, va mot su kien depeg phai the hien duoc tren so). Nap `res.currency.rate` tu oracle. FX theo co che chuan cua Odoo. |
| Token bien dong / diem thuong | reward point, native coin | **Khong phai currency.** Xem §15.4.8 — ban nhap chot sai o day. |

Ngay tinh ty gia: **`finality_datetime`, khong phai ngay chung tu goc, khong phai `broadcast`.** Su kien ke toan la
finality. Dong bang no tren record:

```python
fx_rate          = fields.Float(digits=(16, 12), readonly=True)
fx_rate_source   = fields.Char(readonly=True)      # 'res.currency.rate' | 'oracle:<name>' | 'fixed'
fx_rate_datetime = fields.Datetime(readonly=True)
```

**[SUA §15 v1] Mot rate theo NGAY la khong du, va ban nhap khong noi.** `res.currency.rate` khoa theo `name`
(mot `Date`), nen moi settlement trong ngay dung cung mot ty gia. Voi mot stablecoin binh thuong do la vo hai. Voi
mot su kien depeg thi khong: USDC giao dich quanh **$0.87** trong phien 11/03/2023, tuc lech **~13%** so voi rate
$1.00 se duoc dung cho ca ngay. Tren 1,250,000 collection/nam, mot ngay depeg co the sai lech hang tram trieu VND
tren so.

Chot: mot bang snapshot rieng, va `res.currency.rate` chi de Odoo tu chay may FX cua no:

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

Chu ky nap: 15 phut (96 dong/token/ngay ≈ 35,000 dong/token/nam — khong dang ke). Quy tac chon rate cho mot
settlement: snapshot gan `finality_datetime` nhat trong vong ±30 phut; neu khong co, fallback `res.currency.rate`
cua ngay do va dat `fx_rate_source='res.currency.rate'` — **khac biet nay phai hien trong bao cao**, khong duoc chim.
Va mot canh bao khi `abs(deviation_pct) > 2`: mot stablecoin lech 2% la mot su kien nghiep vu, khong phai mot con so.

Chenh lech ty gia giua ngay ghi nhan cong no va ngay settlement **de Odoo tu lam**: khi `account.move.line` cua
payable va cua payment cung `currency_id` nhung khac ty gia duoc reconcile, Odoo sinh exchange difference move.
Dieu kien: ca hai dong deu mang `currency_id` va `amount_currency` dung, **va** `company.currency_exchange_journal_id`
cung hai tai khoan gain/loss da duoc dat (§15.4.1 muc 3). Khong tu tinh FX.

#### 15.4.6. Bui (dust) la co that, va Odoo dat mot tran cung o 6 chu so

`amount_base` la chuoi wei chinh xac tuyet doi; `res.currency` thi khong the theo kip. **[SUA §15 v1] Ly do manh
hon ban nhap noi**: `res.currency.rounding` duoc khai bao `digits=(12, 6)` trong `odoo/addons/base/models/res_currency.py`,
va `decimal_places = int(math.ceil(math.log10(1/rounding)))`. Nghia la **gia tri rounding min biet duoc la `1e-6`**,
va `decimal_places` toi da la **6**, do la mot gioi han cua framework chu khong phai mot lua chon cua ta. Khong co
cach cau hinh nao vuot qua.

He qua so hoc, token 18 decimals tren currency 6 decimals:

| Dai luong | Gia tri | Co so |
|---|---|---|
| Dust toi da mot settlement | `10^12 − 1` base units = 0.000000999999 token | 18 − 6 = 12 chu so bi cat |
| 1.83 trieu settlement/nam, lech mot chieu | ≤ 1.83 token/nam | tich luy toi da |
| Quy ra tien, Z-VND | ≤ 1.83 VND/nam | khong dang ke ve tien |
| Quy ra tien, USDC | ≤ $1.83/nam | khong dang ke ve tien |
| **Anh huong doi soat** | **dang ke** | mot nguong tolerance = 0 se bao drift moi ngay |

```python
dust_base = fields.Char(readonly=True, default='0',
                        help='amount_base - (amount_currency quy nguoc ve base units). Luon >= 0.')
```

**Va dust phai co cho di trong GL**, khong chi duoc do. Neu khong, so du tai khoan "Crypto wallet" trong GL se
lech dan khoi `balanceOf` on-chain va khong ai giai thich duoc. Chot: mot but toan quet dust hang thang,

```
Dr Crypto rounding expense    Σ dust quy ra currency
    Cr Crypto wallet <token>      Σ dust
```

chay boi `_cron_sweep_dust()`, chi khi `Σ dust >= 1` don vi currency (neu khong thi chinh but toan bi lam tron ve 0).
Voi so lieu tren, but toan nay chay khoang **1 lan/nam** cho Z-VND. Do la ket qua dung: no gan nhu khong bao gio
chay, nhung khi no chay thi doi soat khop.

#### 15.4.7. Khoi luong: vi sao mode 4 la mac dinh

Uoc tinh, co so: deployment DMS 5,000 outlet, 1 collection/outlet/ngay, 250 ngay lam viec.

| | Mode 3: post tung settlement | Mode 4: post theo lo ngay |
|---|---|---|
| `account.move`/nam | 1.25 trieu (collection) + 6,000 (B2B) ≈ **1.26 trieu** | 250 × (so journal × so direction) ≈ **1,000 – 4,400** |
| `account.move.line`/nam | ~3.8 trieu (3 dong/move) | ~13,000 |
| Dung luong `account_move` + `account_move_line` + index | ~4 – 6 GB/nam (uoc tinh, co so ~1 KB/dong `account_move_line` ke ca 12 index cua Odoo) | ~15 MB/nam |
| Thoi gian dong so cuoi thang | phut den chuc phut | giay |
| Thoi gian mo bao cao "so cai chi tiet" 1 nam | khong mo duoc trong UI | tuc thi |
| Tra cuu "khoan thu cua outlet X ngay Y" | tren `account.move.line` | tren `blockchain.settlement` (van du chi tiet) |

Sub-ledger `blockchain.settlement` van giu du 1.25 trieu dong chi tiet (~400 B/dong + index ≈ 1.2 GB/nam), va do la
noi tra cuu tung khoan. GL nhan tong hop. Day la ly do §10.8 chot mode 4 mac dinh, va con so tren la bien so thuc.

**Nguong quyet dinh, viet ra de deployment tu chon:** duoi **20,000 settlement/nam** mot money-flow, mode 3
(mot `account.payment`/settlement) chay tot va cho ke toan cai ho quen thuoc. Tren nguong do, mode 4. Voi so lieu
DMS: B2B (6,000/nam) → mode 3; collection (1.25 trieu/nam) → mode 4. **Do la ly do mode 5 "ket hop theo luong tien"
khong phai mot tuy chon xa xi ma la cau hinh dung cho deployment DMS day du.**

#### 15.4.8. Loyalty: `_gl_required() = False` la sai ke toan

**[SUA §15 v1]** Ban nhap viet: token bien dong / diem thuong ⇒ `_gl_required()` tra `False`, gia tri vao GL chi
khi doi ra tien that. Dung ve *transfer*, sai ve *tong the*.

Mot diem thuong da phat hanh la mot **nghia vu hop dong** (contract liability): doanh nghiep no khach hang mot
khoan trong tuong lai. IFRS 15 (va VAS tuong duong) doi trich truoc phan doanh thu phan bo cho diem thuong tai
thoi diem **phat hanh**, khong phai thoi diem doi thuong. Neu settlement layer noi "khong sinh but toan" ma khong
ai khac lam viec do, thi bang can doi thieu mot khoan phai tra tang dan theo quy mo chuong trinh.

Chot, va no khong lam nang settlement layer:

```python
gl_policy = fields.Selection([
    ('none',      'Khong but toan (token khong phai tai san ke toan)'),
    ('cash',      'Nhu tien: but toan day du tai finality'),
    ('liability', 'Nghia vu hop dong: phat hanh la but toan, doi thuong la giai phong'),
], required=True, default='cash')          # tren blockchain.token, khong tren settlement
```

| `gl_policy` | `direction='out'` (phat hanh diem) | `direction='in'` (thu ve / doi thuong) |
|---|---|---|
| `none` | khong gi | khong gi |
| `cash` | Dr Payable / Cr Wallet | Dr Wallet / Cr Receivable |
| `liability` | Dr Marketing expense / **Cr Loyalty liability** | Dr **Loyalty liability** / Cr Revenue (hoac Cr Wallet neu doi ra tien) |

Va mot con so de deployment biet minh dang o dau: voi 200,000 diem phat/nam va ty le doi thuong quan sat duoc
5–15% (§09 M18), so du `Loyalty liability` o trang thai on dinh ≈ 85–95% cua tong phat hanh luy ke. Do la mot con
so tang khong gioi han neu diem khong het han. **Diem thuong phai co han su dung, va do la mot quyet dinh ke toan
truoc khi la mot quyet dinh marketing.** Xem §15.10.

---

### 15.5. Doi soat: tim drift giua chain va so ke toan

#### 15.5.1. Nam huong, khong phai ba

Ban nhap co ba. Hai huong con lai bat nhung loi ba huong dau khong bat duoc.

```
(A) chain  -> sub-ledger : co transfer nao tren dia chi cua ta ma khong co settlement?
(B) sub-ledger -> GL     : co settlement final nao khong co but toan (hoac nguoc lai)?
(C) so du                : balanceOf(treasury) == sum(sub-ledger) == so du tai khoan GL?
(D) batch  -> settlement : sum(settlement trong batch) == so tien tx cua batch da phat?
(E) sub-ledger -> origin : settlement terminal nao chua duoc callback (notified_datetime IS NULL)?
```

(D) bat loi tinh chunk: mot chunk 150 dong ma calldata chi mang 149 nguoi nhan. On-chain thanh cong, sub-ledger noi
150 dong `final`, va mot NPP khong nhan duoc tien — khong huong nao trong ba huong dau bat duoc no vi tong so du
van khop neu dong thu 150 co so tien nho.

(E) bat loi "tien da den nhung chung tu goc khong biet": DMS van bao mot payout dang cho trong khi tien da tra.
Day la loai loi khong lam mat tien nhung sinh mot khoan tra lan hai khi ai do bam nut lai.

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
    as_of_block_hash = fields.Char(size=66, required=True)   # de chung minh khong doi soat tren fork
    as_of_datetime = fields.Datetime(required=True)
    chain_balance_base     = fields.Char()
    subledger_balance_base = fields.Char()
    gl_balance_base        = fields.Char()
    drift_base     = fields.Char(compute='_compute_drift', store=True, default='0')
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
        ('zether_sum_mismatch', 'Tong dong hinh khong khop so du ma hoa')],
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

**`severity` la cot ban nhap thieu va no quyet dinh ai bi danh thuc.** `dust` la `info`; `pending_over_sla` la
`warn`; `unattributed_chain` va `zether_nonce_gap` la `block` — chung nghia la tien di chuyen ma ta khong biet.

#### 15.5.3. Co che tung huong

Ban nhap viet "co transfer nao tren dia chi cua ta ma khong co settlement?" va khong noi lam the nao. **Khong RPC
nao tra loi cau hoi do.** `eth_getLogs` tra ve log theo khoang block, khong theo "tu truoc toi nay"; va tren mot
chain co retention gioi han (§11.1) thi ca khoang do cung khong co san. Co che that: doi soat voi **bang cua chinh
ta** ma indexer §11 da xay, va do la ly do indexer la dependency cua doi soat chu khong phai mot tuy chon.

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

`amount_base::numeric` la ly do §15.1.2 doi mot index bieu thuc tren `(amount_base::numeric)`: khong co no, (D)
lam mot seq scan tren 1.25 trieu dong moi lan chay.

Cron `_cron_reconcile_ledger()` chay hang ngay sau khi Finality Gate da xu ly xong block cua ngay hom truoc.
Snapshot **phai lay tai mot block da final**, va phai luu **ca hash** — doi soat tai tip se bao drift moi lan chay
chi vi tip da di tiep, va doi soat tren mot block da bi reorg se bao "clean" tren mot nhanh khong ton tai.

*Uoc tinh thoi gian chay, co so: 1.25 trieu settlement/nam, index dung, PostgreSQL tren SSD:* (A) va (D) la hash
join tren tap da loc theo `(chain, token, block_number)` ⇒ **2 – 8 giay**; (B), (C), (E) la index scan ⇒ **< 1 giay**.
Toan bo run cho mot `(company, chain, token)`: **duoi 15 giay**. Voi 3 token × 2 chain × 5 company = 30 run ⇒
**~7 phut/dem**. Nam trong ngan sach; khong can chia nho.

#### 15.5.4. Nguong

**[SUA §15 v1] Ban nhap tu mau thuan:** no noi "nguong tolerance phai la `sum(dust_base)`, khong phai 0" roi dinh
nghia `recon_tolerance_base` la mot hang so `10^(token_decimals − currency_decimals)`. Hai thu khac nhau: hang so
la dust cua **mot** settlement, con drift luy ke la dust cua **tat ca**.

Chot: `tolerance_base` duoc tinh **tai luc chay**, va luu vao run de bao cao co the giai thich duoc:

```python
tolerance = sum(int(s.dust_base) for s in settlements_in_scope) \
            + int(token.recon_slack_base or '0')      # slack cau hinh, mac dinh 0
```

`recon_slack_base` ton tai cho mot truong hop duy nhat: token co phi chuyen khoan on-chain (fee-on-transfer). Neu
token khong co, dat 0 va giu 0. Mot slack duoc noi rong "cho chac" la mot cho de giau drift.

| `|drift| ≤ tolerance` | `kind='dust'`, `severity='info'`, `run_state='clean'` |
| `tolerance < |drift|` | `run_state='drift'`, `mail.activity` cho `group_blockchain_treasury`, va **`group_blockchain_auditor` duoc CC** |

Doi soat **khong bao gio tu sua**. No mo mot activity va dung lai. Mot routine doi soat co quyen ghi la mot routine
co the che giau chinh loi cua no.

#### 15.5.5. Zether pha vo huong (C), va cai gi con lai

So du bao mat khong doc duoc tu chain neu cong ty khong giu khoa giai ma; `getEncryptedBalance` tra ve mot cap diem
duong cong, khong tra ve mot so. Nhung **[SUA §15 v1] ban nhap ket luan qua bi quan**: no viet "khi khong giu khoa,
nonce-continuity la tat ca nhung gi con lai" va bo qua ca hai truong hop quan trong hon.

Ba muc do, xep theo cai ta thuc su biet:

| Ta la gi voi tai khoan do | Doi soat lam duoc gi | Co che |
|---|---|---|
| **Chu tai khoan** (treasury cua chinh minh) | **Doi soat day du**, ngang mot token cong khai | §03.2.5 memo AEAD: giai `memoTo`/`memoFrom` cho ra `v` trong ~60 µs; roi kiem tong dong hinh `g^{Σv} == C_acc · D_acc^{−x}` sau moi rollOver (§03.2.6). Odoo khong giu `x`: HSM expose mot phep `ecdh(D) -> compress(D^x)` duy nhat (§11.10) |
| **Doi tac cong bo** | Doi soat tung dong, co xac minh | `recipient_decrypted`: doi tac gui `(v, s)`, ta kiem `C_out == g^v · y_recv^s` — 2 scalar mul, khong can khoa bi mat |
| **Khong biet gi** | **Chi phat hien duoc mat mat, khong phat hien duoc sai so tien** | Tinh lien tuc cua `zetherNonce`, cong `accSeq` |

```
Voi moi (token, zether_account) ma ta KHONG giu khoa:
    spend_nonces = [e.zether_nonce for e in entries if direction in ('transfer_out', 'withdraw')]
    Neu sorted(spend_nonces) != list(range(min, max + 1)):  ->  zether_nonce_gap  (severity='block')
```

Mot lo hong trong day nonce nghia la co dung mot giao dich ra khoi tai khoan nay ma sub-ledger khong ghi — do la
tin hieu doi soat manh ngang mot chenh lech so du, va no doc duoc tu chain cong khai (nonce khong bi ma hoa).

**[SUA §10] Va constraint cua §10 sai o day.** §10.4.7 khai:

```python
_unique_zether_nonce = models.Constraint(
    'UNIQUE(token_id, account_id, zether_nonce, direction)', ...)
```

`direction` trong khoa cho phep cung mot `zether_nonce` ton tai dong thoi cho `transfer_out` **va** `withdraw` cua
cung mot tai khoan. On-chain dieu do khong the xay ra: `zetherNonce[schnorrAddress]` la mot bo dem duy nhat, tang
o **ca hai** thao tac tieu tien (§03, `transferConfidential` va `withdraw` deu `++`). Mot khoa co `direction` bien
mot su co "hai ban ghi cho mot nonce" thanh hai dong hop le, va chinh la thu doi soat dang di tim. Sua:

```python
_unique_zether_spend_nonce = models.Constraint(
    "UNIQUE(token_id, account_id, zether_nonce)", 'Nonce Zether da duoc dung cho tai khoan/token nay.')
# ap dung cho cac direction tieu tien; deposit/transfer_in khong tieu nonce cua chinh minh
```

Vi `deposit` va `transfer_in` **khong** tang nonce cua chu tai khoan, chung khong duoc mang `zether_nonce` cua
tai khoan do. De `zether_nonce` NULL cho hai direction do, va PostgreSQL UNIQUE cho phep nhieu NULL — dung tinh
chat ta can, khong can partial index.

**[SUA §15 v1] `epoch` da bien mat khoi thiet ke.** Ban nhap noi "epoch rollOver" va "300 nguoi nhan deu nhan duoc
trong cung mot epoch". §03.5.4 da bo hoan toan mo hinh epoch va thay bang `accSeq` — mot dai luong khong phu thuoc
thoi gian, chi doi khi chinh chu goi `rollOver`. He qua cho doi soat: khong con "epoch boundary" nao de doi; thay
vao do, doi soat phai doc **ca** `accSeq` va `pendingSeq` (`viewAccounts`, §03.6) va bao `zether_sum_mismatch` khi
`g^{Σv_da_rollOver} != C_acc · D_acc^{−x}`. Tien nam trong `pending` **khong** la drift — no la tien chua rollOver,
va bao cao phai the hien no thanh mot cot rieng chu khong tron vao so du.

Bao cao cho token `is_confidential` phai noi ro no dang o muc nao trong ba muc tren. `run_state='partial'` ton tai
chinh vi diem nay: bao "clean" khi ta chi kiem duoc nonce la mot lo noi doi.

#### 15.5.6. Khi tim thay drift

| `kind` | Ai xu ly | Buoc dau tien |
|---|---|---|
| `unattributed_chain` | treasury + auditor | Tra `ref_hex` nguoc ve `blockchain.payment.request` (§09.6). Neu khong co: ai do gui tien vao vi cua ta ma khong qua he thong — ghi nhan nhu mot khoan phai tra chua xac dinh, **khong** tu dong cap cho ai |
| `missing_onchain` | treasury | Kiem `finality_source` (§11.3b). Gan nhu luon la node noi doi, khong phai tien mat |
| `amount_mismatch` | treasury | Dung moi settlement cua cung `payer_account` cho toi khi ro |
| `missing_gl` | ke toan | Mo ky, hoac `late_posting='shift'` |
| `orphan_move` | ke toan | But toan tay do ai do tao. Khong tu xoa |
| `batch_short` | treasury | So sanh calldata da luu (`ir.attachment` cua chunk) voi `settlement_ids`. Day la loi code, khong phai loi du lieu |
| `zether_nonce_gap` | treasury + auditor | **Dung** moi settlement tren tai khoan Zether do. Mot nonce bien mat co the la mot lan chi khong duoc ghi |

---

### 15.6. Ba luong DMS cam vao qua bridge, core khong biet gi

`dms_blockchain_bridge` (`depends: ['dms_blockchain', 'dms']`, `auto_install: True`). Toan bo noi dung cua no la:
`_inherit` mixin, sinh settlement, va nhan callback. Khong mot dong nao trong core doc chuoi `dms`.

#### 15.6.0. Su that ve model DMS — ba cho ban nhap sai

Doc thang tu `dms/models/trade/dms_trade_settlement.py` va `dms/models/orders/dms_payment_collection.py`:

| Ban nhap noi | Su that | He qua |
|---|---|---|
| `dms.trade.settlement.line` la "payout line" cho nhieu nguoi nhan | No la **dong hang tang**: `product_id` + `quantity`, docstring *"Mot dong hang tang. Chi co nghia khi `settlement_method = goods`"*. `payout_line_ids` co `string="Free goods"` | Bridge phai gan vao `dms.trade.settlement`, khong phai `.line`. Anh xa la 1 settlement ↔ 1 chung tu |
| Bridge ghi `payout_state`, `payout_datetime` | **Hai field nay khong ton tai.** `dms.trade.settlement` co `state ∈ {draft, posted, settled_external, cancelled}` | Bridge phai dung `state` co san, hoac them field moi va noi ro la them |
| Bridge tu che idempotency | DMS **da co** `dms.sync.operation._dms_once(uuid, type, payload, run)` tra `(record, replayed)`, va `_dms_event_uuid()` sinh UUIDv7 on dinh luu o `event_uuid` (`readonly`, `copy=False`) | Dung lai. Mot lop idempotency thu hai la mot lop co the lech voi lop thu nhat |

Mot phat hien co loi: **`state='settled_external'` da ton tai** voi y nghia *"Settled outside the Odoo ledger"*, va
`dms_settle` dung no cho topology `lightweight`. Do dung la hinh dang cua mot settlement on-chain o mode 4. Bridge
khong can phat minh trang thai moi cho truong hop do.

#### 15.6.1. Trade settlement payout

| | |
|---|---|
| Model goc | `dms.trade.settlement` (**khong** phai `.line`) |
| Chieu | `out` |
| Anh xa | 1 `blockchain.settlement` / 1 `dms.trade.settlement`; gom vao 1 `blockchain.settlement.batch` theo `(chain, token, payer_account, ky)` |
| `origin_key` | `dms.trade.settlement._dms_event_uuid()` — UUIDv7 da co, on dinh, `copy=False` |
| Kich hoat | `settlement_method = 'onchain'` (them bang `selection_add`) |
| Diem tinh te | Batch `atomic` chi khi **toan bo** payee da qua `_preflight()`; nguoc lai `chunked` |

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

Ba quyet dinh trong 12 dong tren, viet ro vi chung khong hien nhien:

1. **Bridge khong goi `dms_settle()`.** `dms_settle` sinh credit note / gift order va `action_settle()` claim — do
   la buoc *nghiep vu*, xay ra truoc, doc lap voi viec tien di duong nao. Bridge chi dong buoc *tien*.
2. **`super(...).write()` bo qua override cua `dms.trade.settlement`** neu no co guard tren `state`. Neu model goc
   khong co guard, dung `self.sudo().write()` binh thuong. Kiem truoc khi viet — mot `super()` khong can thiet la
   mot cua hau mo san.
3. **`disputed` khong doi `state`.** Mot chung tu DMS nhay qua nhay lai theo mot tin hieu RPC la cach nhanh nhat de
   mat niem tin vao he thong.

Chieu di (sinh settlement) khong nam trong `_on_blockchain_settlement` ma trong mot method rieng, goi tu
`dms_settle` khi `settlement_method == 'onchain'`:

```python
def _dms_create_blockchain_settlement(self):
    self.ensure_one()
    flow = self.env['blockchain.money.flow']._resolve(self.company_id, 'B2B_PAYOUT')
    return self.env['blockchain.settlement'].sudo()._submit(
        self.company_id, self._blockchain_origin_key(),
        use_case='b2b', direction='out',
        chain_code=flow.chain_id.code, token_symbol=flow.token_id.symbol,
        amount_base=flow.token_id._to_base(self.amount, self.currency_id),
        payee=self.beneficiary_partner_id,
        origin_model=self._name, origin_id=self.id)
```

`_to_base` la cho quy doi tien → base units xay ra, va no phai **lam tron xuong** (`ROUND_DOWN`): lam tron len chi
nhieu hon 1 wei so voi so tien duoc duyet. Chenh lech di vao `dust_base`.

#### 15.6.2. Outlet payment collection

| | |
|---|---|
| Model goc | `dms.payment.collection` |
| Chieu | `in` |
| Anh xa | 1 `blockchain.settlement` / 1 collection; `blockchain.payment.request` (§09.6 R1) cap dia chi CREATE2 derived |
| `origin_key` | `dms.payment.collection:<id>` (model nay chua co `event_uuid`; xem §15.10) |
| Diem tinh te | Nguyen tac `dms_vietqr` nguyen ven, va `status` da co dung trang thai can dung |

`dms.payment.collection.status` da co **`pending_reconciliation`** voi y nghia *"Awaiting bank reconciliation"*, va
`dms_post_payment` chap nhan `status in ('validated', 'confirmed', 'pending_reconciliation')`. Anh xa tu nhien:

| `settle_state` | `collection.status` | Ai ghi |
|---|---|---|
| `submitted`, `broadcast`, `pending_finality` | `pending_reconciliation` | bridge |
| `final` | goi `dms_post_payment(operation_uuid=<settlement uuid>)` → `payment_posted` | bridge |
| sau do | `dms_allocate(...)` → `allocated` | **nguoi**, khong tu dong |
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

Bon dieu phai noi ro:

1. **`broadcast` KHONG phai la da thu tien.** Day la nguyen tac `dms_vietqr` ("quet QR khong phai la da thu tien")
   ap thang: mot tx da phat song la mot QR da hien, khong hon. `pending_reconciliation` la trang thai dung, va no
   da co san — khong can phat minh.
2. **`dms_post_payment` tu tao `account.payment`.** Nghia la voi luong nay, `dms_blockchain_account` **khong** duoc
   tao them but toan. Bridge dat `gl_state='not_required'` tren settlement luc tao. Neu quen, moi khoan thu se co
   **hai** but toan — mot cua DMS, mot cua module account bridge — va doi soat huong (B) se bao `orphan_move` hang
   loat. Day la cho hai module de dam nhau nhat trong ca thiet ke, va no phai co mot test rieng.
3. **`operation_uuid` la settlement uuid**, nen mot callback goi lai sau crash di vao `_dms_once` va tra ve
   `replayed=True` thay vi post lan hai. Hai lop idempotency **cung mot khoa** — do la cach chung khong lech nhau.
4. **`dms_allocate` khong tu dong.** Phan bo mot khoan thu vao hoa don nao la mot quyet dinh, khong phai mot he qua.
   Ban nhap noi "`dms.collection.allocation` chi duoc tao khi `final`" — dung nhung chua du: no chi duoc tao khi
   `final` **va** co nguoi bam.

#### 15.6.3. B2B claim offset (netting)

Mot brand no distributor 100 trieu (payout) va distributor no brand 30 trieu (claim bi tu choi). Hai cach:

1. Hai transfer on-chain gross (100 va 30 nguoc chieu). Trung thuc, ton gas gap doi, va **can distributor thuc su
   co 30 trieu token trong vi** — thuong la khong.
2. Netting off-chain: mot transfer 70 trieu.

Chot phuong an 2, nhung **so ke toan van phai la gross**. Cu the: ba settlement — hai `transport='offset'`
(100 out, 30 in, khong tx, `settle_state` di thang `draft → final` khi net settlement `final`) va mot
`transport='onchain'` 70 out. `_gl_required()` tra `True` cho ca ba; but toan gross giu nguyen trinh bay cong no
(§15.4.2, tai khoan **Netting clearing**), con dong tien chi 70. Neu bo hai dong gross, bao cao cong no voi
distributor mat 30 trieu va khong ai tim ra tai sao.

```python
transport = fields.Selection([('onchain', 'On-chain transfer'),
                              ('offset', 'Netting offset, khong co tx'),
                              ('external', 'Fiat / ngoai chain, chain chi anchor')],
                             required=True, default='onchain', index=True)
netting_set_id = fields.Many2one('blockchain.netting.set', index=True)
```

Rang buoc bat buoc tren `blockchain.netting.set`:

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

Kiem bang **mot test that**, khong bang doc code. Mot netting set khong can bang la mot lo that thoat tien.

Va hai rang buoc khong phai ky thuat, lay tu §09 M15, phai ghi vao spec vi khong ai khac se ghi:

- **Netting phai co dieu khoan bu tru trong hop dong.** Neu khong, mot ben pha san thi phan bu tru co the bi toa
  lat lai va brand mat toan bo 100 trieu thay vi 70.
- **`dms.trade.claim` da settle la immutable.** Bridge **khong sua claim**, chi ghi settlement moi. Mot claim da
  `settled` di vao netting set bang `claim_ids` cua chung tu goc, khong bang mot `write` len chinh no.

#### 15.6.4. Cay file cua bridge

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

**Toan bo bridge duoi 400 dong Python.** Neu no vuot 800, mot phan logic dang thuoc ve core hoac ve DMS chu khong
ve cau noi — do la tin hieu de dung lai va chia lai.

---

### 15.7. Dinh luong batch: khi nao lo co loi, khi nao khong

Uoc tinh, co so: chi phi opcode EVM (SSTORE 20,000 cho slot 0→nonzero, 5,000 warm nonzero→nonzero, 2,900 warm
SLOAD), 21,000 base/tx, 16 gas/byte calldata khac 0. **Gia gas thong nhat voi §09.10a: Gnosis 2 gwei, xDAI = $1.00.**
(Ban nhap dung 1.5 gwei — da sua de ca bo tai lieu dung mot con so.)

| Kich ban, 300 nguoi nhan | Gas | Gnosis @2 gwei | Ethereum L1 @20 gwei, ETH $3,000 |
|---|---|---|---|
| 300 tx `ERC20.transfer` rieng le (nguoi nhan chua co token) | 300 × 65,000 = 19,500,000 | 0.039 xDAI = **$0.039** | **$1,170** |
| 2 tx `disperseToken` × 150 | 2 × (21,000 + 150 × 30,000) = 9,042,000 | 0.018 xDAI = **$0.018** | **$542** |
| 300 `transferConfidential` (Zether 32/64) | 300 × 1,880,000 = **564,000,000** | 1.128 xDAI = **$1.13** | **$33,840** |

**[SUA §15 v1] Con so Zether cua ban nhap sai 7.5 lan theo huong lac quan.** No dung 250,000 gas/transfer, con so
ma §03.3.7 da truy ra la chi phi verify mot **Groth16 SNARK tren alt_bn128** (4 pairing), khong phai Bulletproofs.
Con so dung la **1,880,000** cho cau hinh 32/64 (§03.3.6, §09.10a). Sua o day de ca bo tai lieu nhat quan.

Bon ket luan doc duoc tu bang tren, va ba trong so do nguoc voi truc giac:

1. **Tren Gnosis, batch khong tiet kiem tien.** $0.039 xuong $0.018 la vo nghia. Cai batch tiet kiem tren Gnosis la
   **so nonce, so lan cho finality, va so dong `blockchain.transaction`**.

   **[SUA §15 v1] Va ly do "300 tx tuan tu mat 25 phut" cua ban nhap la sai.** Mot relayer **co the** nop nhieu tx
   voi nonce lien tiep vao cung mot block; nonce tuan tu khong co nghia mot tx moi block. Tran that la
   **so tx pending toi da mot tai khoan** ma mempool chap nhan: geth mac dinh `txpool.accountslots = 16`
   (Nethermind va Erigon dat nguong tuong duong). Voi 300 tx tren mot dia chi relayer:

   | | 300 tx rieng le | 2 chunk |
   |---|---|---|
   | Vong nop (16 pending/vong) | 19 | 1 |
   | Thoi gian toi thieu (block 5 s) | ~95 s | ~5 s |
   | Rui ro head-of-line | **mot tx ket chan 299 cai sau** | mot chunk ket chan 1 chunk |
   | Dong `blockchain.transaction` | 300 | 2 |
   | Lan cho finality (240 s hard) | 300 lan theo doi | 2 |

   Do moi la ly do batch. Lam batch vi ly do do, dung noi doi rang la vi gas.

2. **Block gas limit la tran cung, va `chunk_size = 150` con rong hon ban nhap nghi.** Mot chunk 150 ton
   **4,521,000 gas**, khong phai 9M (ban nhap doc nham tong hai chunk thanh mot). Gnosis ~17M gas/block ⇒ mot chunk
   chiem **27%** block. Co the day len 300/chunk (~9M, 53% block) nhung **khong nen**: mot revert khi do dot 9M gas
   thay vi 4.5M, va mot block co the bi mot tx khac chiem cho. Giu 150 lam mac dinh; `chunk_size` phai duoc
   simulation gate (§10) xac nhan tung lan, khong duoc hard-code tin tuong.

   *Kiem tra mot rang buoc it ai nho:* voi 150 nguoi nhan, calldata ≈ 150 × 52 B = 7,800 B, gan nhu toan byte khac 0
   ⇒ ~31,200 token calldata ⇒ san calldata theo EIP-7623 = 21,000 + 40 × 31,200 = **1,269,000 gas**, thap hon
   4,521,000 rat nhieu. San khong rang buoc. Neu chunk_size tang qua ~500, phai tinh lai.

3. **Zether khong batch duoc, va khoang cach lon hon ban nhap nghi.** 564M gas la **33 block Gnosis lien tiep**
   (17M/block), tuc ~2.8 phut chiem **toan bo** khong gian block cua ca mang luoi. Khong the. Moi
   `transferConfidential` phai la mot tx rieng. Do khong phai nhuoc diem cua thiet ke — do la ly do chain profile
   chot **private chain di truoc cho Zether**: tren chain private `fee_mode='gasless'`, tran duy nhat con lai la
   thoi gian sinh proof (**30–50 ms/proof** tren server Rust native cho cau hinh 32/64, §03; khong phai 30–60 ms
   nhu ban nhap uoc, va con so 300–800 ms cua ban nhap la cua **WASM trong browser**, khong phai cua prover server)
   va throughput verify (~500 tx/s voi MSM Pippenger, §03.3.8).

   300 proof tren mot core = **9–15 giay**; chay song song 8 core = **1.2–1.9 giay**. Khong phai nut co chai.

4. **[SUA §15 v1] "Epoch" khong con ton tai.** Ban nhap ket bang mot cau ve "epoch rollOver" khong con dung sau
   §03.5.4. Cai thay the no la `accSeq`, va cai gia phai tra la **mot transaction thua**: de tieu tien vua nhan,
   vi phai `rollOver(self)` truoc (~28k gas ≈ $0.00006 tren Gnosis). Voi mot batch 300 nguoi nhan, 300 lan rollOver
   la **8.4M gas ≈ $0.017** — cung bac voi chinh batch transfer, va **relayer-driven duoc** (§03.5.5): worker theo
   doi `pendingSeq` va tu goi `rollOver` gasless. Chi phi nay phai nam trong mo hinh chi phi cua batch Zether;
   ban nhap bo qua no hoan toan.

**`atomicity='atomic'`: khi nao, va no thuc su nghia la gi.**

`atomic` chi dung khi nghiep vu **thuc su** doi tat-ca-hoac-khong — vi du mot dot chi thuong ma chi mot phan la vi
pham chinh sach. Mac dinh `chunked`, vi trong payout B2B thuc te, 299 nguoi duoc tra va 1 nguoi bi giu lai la ket
qua **dung**, khong phai loi.

**Nhung "mot tx" khong tu dong co nghia atomic.** §09 M17 chot rang `disperseToken` phai `try/catch` tung transfer
va phat event thanh/bai theo tung dong — neu khong, mot nguoi nhan la contract revert lam hong ca lo. Nghia la mot
tx co the chua ca thanh cong lan that bai. Vay:

| Ta muon | Contract phai | `atomicity` |
|---|---|---|
| Tat ca hoac khong | **khong** try/catch; revert toan bo | `atomic` |
| Toi da so nguoi duoc tra | try/catch tung dong, event `TransferFailed(ref, reason)` | `chunked` |

Hai hanh vi nay la **hai ham khac nhau tren contract** (`disperseStrict` va `disperseBestEffort`), khong phai mot
co truyen vao. Mot co bo-luc khien mot lan doc audit khong tra loi duoc cau hoi "ham nay co the tra mot phan
khong". Chot: hai ham, hai selector, hai duong test.

---

### 15.8. Cai settlement layer KHONG lam

Viet ra vi mot lop "thong nhat" luon bi de nghi lam them, va moi lan them mot thu la mot lan `depends` moi.

| Khong lam | Ai lam | Vi sao khong o day |
|---|---|---|
| Tinh so tien | Chung tu goc (`dms.trade.settlement.amount` computed tu claim) | "Amount khong lay tu client" la nguyen tac cua chinh DMS. Settlement layer nhan mot so, khong tinh mot so |
| Thue / VAT | Chung tu goc | Thue thuoc ve giao dich thuong mai, khong thuoc ve phuong tien thanh toan |
| Duyet nghiep vu | Chung tu goc | `blockchain_authorize_payout` la duyet **chi tien**, khong phai duyet **khoan chi** |
| Chon chain / token | `blockchain.money.flow` (§09.4) | Mot settlement nhan chain va token da duoc quyet |
| Ky | Custody provider (§07) | Core khong bao gio thay khoa |
| Broadcast | Relay worker (§06) | Odoo khong mo socket toi chain tu HTTP worker (§10.1) |
| Quyet dinh finality | Finality Gate (§11) | Settlement chi **nhan** tin hieu |
| Doi soat ngan hang fiat | `dms.bank.reconciliation`, `account.reconcile.model` | Da co, va tot hon cai ta se viet |

---

### 15.9. Kiem chung bat buoc cho section nay

Moi muc phai xanh truoc khi goi section nay la xong. Muc co SQL thi **chay SQL**, khong doc code (bay #2 CLAUDE.md).

1. `SELECT conname, contype FROM pg_constraint WHERE conrelid = 'blockchain_settlement_batch'::regclass;` — phai co
   `UNIQUE(company_id, origin_key)` va CHECK `chunk_size`. `_sql_constraints` dang list bi Odoo 19 bo qua.
2. `SELECT conname FROM pg_constraint WHERE conrelid = 'blockchain_settlement_batch_chunk'::regclass;` — phai co
   `UNIQUE(batch_id, sequence)`.
3. `SELECT indexname FROM pg_indexes WHERE indexname = 'blockchain_settlement_origin_idx';` — mot dong. Khong co
   dong nao nghia la moi truy van nguoc ve chung tu la seq scan tren 1.25 trieu dong.
4. Tao settlement, kill worker giua broadcast, restart → `_cron_reconcile_orphan_tx()` gan lai tx, khong sinh
   settlement thu hai, khong sinh tx thu hai.
5. Kill worker sau khi `claim` truoc khi broadcast → `_cron_reap_stale_jobs()` tra job ve `ready` sau 5 phut.
   Nhung neu chunk **da co** `tx_hash`, job **khong** duoc tra ve `ready`.
6. Khoa ky ke toan roi ep mot settlement sang `final` → `settle_state='final'` **va** `gl_state='failed'` **va**
   `gl_error` chua nguyen van thong diep. Khong duoc rollback ve `pending_finality`.
7. Post GL thanh cong roi kill process truoc khi ghi `gl_state='posted'` → chay lai cron: **khong** sinh but toan
   thu hai (`bamboo_create_idempotent` tren `uuid5(NS_GL, settlement_uuid)`).
8. Cai `dms_blockchain` khong co `account`: khong loi import, moi settlement `gl_state='not_required'`,
   `_cron_post_gl` khong ton tai hoac khong lam gi.
9. Cai `dms_blockchain_account` **truoc khi** cau hinh `payment_account_id` → `_check_setup()` tra ve 4 ma loi,
   module cai duoc, khong raise. Post mot settlement → `gl_state='failed'` voi dung thong diep cua Odoo.
10. Go `dms`: `origin_model='dms.trade.settlement'` con trong bang; `_notify_origin()` skip im lang (co log WARNING),
    khong raise, va `notified_datetime` duoc dat.
11. Dat `origin_model='res.users'` bang SQL truc tiep roi chay `_cron_notify_origin()` → log WARNING, cron **khong
    chet**, cac settlement khac van duoc thong bao.
12. Netting set khong can bang → `@api.constrains` raise. Viet test that, khong tin doc code.
13. Doi soat tren token `is_confidential` voi mot entry bi xoa thu cong → phai ra `zether_nonce_gap` voi
    `severity='block'`, va `run_state` phai la `drift`, khong phai `clean`.
14. Doi soat tren token `is_confidential` ma ta **khong** giu khoa → `run_state='partial'`, **khong bao gio**
    `clean`. Bao "clean" o day la mot lo noi doi.
15. Luong collection: bat mot settlement `final` → co dung **mot** `account.payment`, khong phai hai. Chay doi soat
    huong (B) → 0 dong `orphan_move`.
16. `_blockchain_origin_key()` goi hai lan cach nhau mot `write()` len chung tu goc → cung mot chuoi.
17. Ep mot settlement `final` → `disputed` bang cron reorg gia lap → `gl_state` **khong doi**, khong co but toan
    dao nao duoc sinh tu dong.
18. Chay `_cron_reconcile_ledger()` tren 1 trieu dong settlement gia lap → duoi 15 giay/run. Neu qua, index bieu
    thuc tren `(amount_base::numeric)` chua duoc tao.

---

### 15.10. Con phai nguoi quyet

1. **Diem thuong co han su dung khong?** Neu khong, `Loyalty liability` tang khong gioi han va khong bao gio duoc
   giai phong. Day la mot quyet dinh ke toan va phap ly, khong phai ky thuat, va no chan §15.4.8.
2. **`posting_policy` theo money-flow hay toan he thong?** §15.4.3 de xuat theo flow. Neu ke toan doi mot chinh
   sach duy nhat cho de kiem toan, chot toan he thong va chap nhan 6,250 but toan dao/nam o luong collection.
3. **`dms.payment.collection` co nen co `event_uuid` nhu `dms.trade.settlement` khong?** Hien tai khong co, nen
   `origin_key` phai la `dms.payment.collection:<id>` — on dinh nhung khong mang y nghia nghiep vu, va khong dung
   duoc lam `operation_uuid` cho `_dms_once` neu ai do doi chinh sach. Them mot field la mot thay doi trong `dms`,
   khong trong bridge.
4. **Netting: co dieu khoan bu tru trong hop dong voi NPP chua?** Neu chua, §15.6.3 khong duoc bat len o production
   du code chay dung.
5. **Ai la nguoi thu hai trong `blockchain_resolve_dispute`?** §15.2.6 doi treasury. Voi mot so tien du lon, doi
   hai nguoi (four-eyes) — nhung Odoo khong co co che four-eyes san. Xay hay chap nhan mot nguoi?
6. **Nguong `recon_slack_base`: 0 hay khac 0?** Chot mac dinh 0 o day. Neu mot token co fee-on-transfer duoc dua
   vao, phai quyet lai va phai ghi ly do vao `mail.thread` cua token.
7. **Chain private rewind: ai co quyen, va co bi log khong?** `_cron_anchor_verify` phat hien duoc, nhung neu chinh
   operator la nguoi rewind thi anchor cung do operator ky. Can mot ben thu ba giu khoa neo, hoac chap nhan rang
   dam bao chi la "chung minh duoc voi ben ngoai", khong phai "chan duoc tu ben trong".

---

### 15.11. Mau thuan can dong bo giua cac section

| Cho | Hien tai | Phai sua thanh | Ai sua |
|---|---|---|---|
| §10.4.8 `settle_state` | co `reversed` | bo `reversed`, them `compensated` va `disputed` | §10 |
| §10.4.7 nonce Zether | `UNIQUE(token_id, account_id, zether_nonce, direction)` | `UNIQUE(token_id, account_id, zether_nonce)`; `zether_nonce` NULL cho `deposit`/`transfer_in` | §10 |
| §10.8 `posting_policy` | mot khoa `ir.config_parameter` toan cuc | field tren `blockchain.money.flow`, fallback ve config param | §10, §09 |
| §10.4.8 | khong co `batch_id`, `chunk_id`, `gl_state`, `transport` | them (liet ke o §15.2.2) | §10 |
| §15 v1 gas Zether | 250,000/transfer | 1,880,000 (32/64), theo §03.3.6 | **da sua o day** |
| §15 v1 gia gas Gnosis | 1.5 gwei | 2 gwei, theo §09.10a | **da sua o day** |
| §15 v1 chunk 150 | "9M gas" | 4,521,000 gas/chunk | **da sua o day** |
| §15 v1 epoch Zether | con noi ve epoch rollOver | `accSeq`, theo §03.5.4 | **da sua o day** |
| §15 v1 model DMS | `dms.trade.settlement.line` + `payout_state` | `dms.trade.settlement` + `state`/`settled_external` | **da sua o day** |
| §15 v1 lane 2D nonce | suy tu `origin_key` cua settlement | suy tu don vi van chuyen (chunk khi co batch) | **da sua o day** |
| §11.5 dependency | `depends: ['base', 'bamboo_idempotency']` | phai khop `__manifest__` cua §10.1 (`['base', 'mail']`) — **mot trong hai sai** | §10 hoac §11 |
