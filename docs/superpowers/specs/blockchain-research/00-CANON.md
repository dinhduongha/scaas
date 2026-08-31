# 00. CANON — the settled spine

Tài liệu này là **xương sống chuẩn tắc** của bộ 16 section. Nó không thay thế
section nào; nó quyết định điểm nào đúng khi hai section nói khác nhau.

> **Tham chiếu `§` đọc thế nào:** `§00`–`§16` là file spec cùng số; **`§17`–`§23` nằm trong
> `_USER-DECISIONS.md`** (không có file `21-*.md` nào cả); `§C…` là chính file này. Bảng tra đầy đủ:
> `_USER-DECISIONS.md` §0.

**Quy tắc ưu tiên (đọc trước khi tranh luận bất cứ điều gì):**

1. Quyết định người dùng đã khoá (locked #1–#9) đứng trên tất cả. Canon không
   mở lại chúng.
2. Canon đứng trên mọi section. Nếu một section mâu thuẫn canon, section sai.
3. Section sở hữu một artefact đứng trên mọi section khác **về chi tiết** của
   artefact đó — nhưng chỉ trong khuôn khổ canon đã chốt.
4. Một section **tham chiếu**, không **định nghĩa lại**. Không có `_name`,
   không có bảng field, không có bảng gas nào được viết hai lần trong bộ tài liệu.
5. Con số nào canon đã chốt thì mọi nơi khác **trích dẫn**, kèm chữ
   *"derived, do not edit"*. Không ai được tự dẫn lại từ đầu.

**Cách dùng:** cần schema của `blockchain.settlement` → §C10.4. Cần con số gas
của `transferConfidential` → §C7.2. Cần biết addon nào depends gì → §C3.

---

## Bảng sở hữu artefact

| Artefact chuẩn tắc | Section sở hữu | Mục canon |
|---|---|---|
| Sizing baseline (khối lượng, giá trị, tăng trưởng) | `16-decomposition-roadmap.md` | §C1 |
| Quy ước đặt tên (model, field, XML id, module, contract, service) | `10-odoo-addon-design.md` | §C2 |
| Topology addon + `__manifest__.py` | `10-odoo-addon-design.md` | §C3 |
| Bố cục repo (`smartcontracts/` + 4 service) | `14-contracts-repo-testing.md` | §C4 |
| Mô hình trạng thái Zether (`accSeq`, `rollOver`) | `03-zether-crypto.md` | §C5 |
| Hằng số Zether, curve, range statement, phí, memo, auditor | `03-zether-crypto.md` | §C6 |
| Bảng gas — một con số cho mỗi thao tác | `03-zether-crypto.md` §3.3.6 | §C7 |
| Struct EIP-1776, `mode` bitmask, ngữ nghĩa thất bại, expiry | `04-eip1776-metatx.md` | §C8 |
| `blockchain.chain`, `blockchain.rpc.endpoint`, số finality | `10-odoo-addon-design.md` §10.4.2 | §C9 |
| Sổ đăng ký model canonical (đầy đủ) | `10-odoo-addon-design.md` §10.3 | §C10.1 |
| `blockchain.account` + custody wiring | `10-odoo-addon-design.md` §10.4.3 | §C10.2 |
| `blockchain.token` + `blockchain.zether.token` | `10-odoo-addon-design.md` §10.4.4 | §C10.3 |
| `blockchain.metatx` | `10-odoo-addon-design.md` §10.4.5 | §C10.5 |
| `blockchain.transaction` + `blockchain.chain.event` / `.effect` | `11-indexer-finality.md` | §C10.6 |
| `blockchain.zether.entry` | `10-odoo-addon-design.md` §10.4.7 | §C10.7 |
| `blockchain.settlement` | `10-odoo-addon-design.md` §10.4.8 | §C10.4 |
| `blockchain.relay.job` (outbox + attempt, một model) | `06-relay-pool-enterprise.md` §06.9 | §C10.8 |
| `blockchain.payment.request` / `.observation` / `.quote` | `09-payment-modes.md` | §C10.9 |
| Idiom Odoo 19 bắt buộc | `10-odoo-addon-design.md` §10.4.0 | §C11 |
| Bảng ánh xạ state machine liên đối tượng | `15-settlement-layer.md` §15.2.1 | §C12 |
| Vận chuyển Odoo ↔ worker (outbox) | `08-chain-adapters.md` §08.2b | §C13 |
| Nhóm quyền + ma trận ACL + bề mặt RPC | `10-odoo-addon-design.md` §10.5, §10.6 | §C14 |
| Trục custody + lớp rủi ro R1–R4 | `07-custody-providers.md` | §C15 |
| Compliance profile × use case | `13-legal-vn.md` | §C16 |
| Private chain: client, genesis, DR | `08-chain-adapters.md` §08.10 | §C17 |
| Phạm vi: cái gì KHÔNG làm trong 24 tháng đầu | `16-decomposition-roadmap.md` §16.0.3 | §C18 |

---

## C1. Sizing baseline — một bộ số cho toàn bộ tài liệu

Mọi bảng tăng trưởng trong mọi section **trích dẫn bảng này**, không tự đặt giả
định. Cơ sở: deployment DMS thật (§15.1.4: 5,000 outlet, 500 nhà phân phối),
mở rộng thành ba mốc thời gian.

### C1.1. Khối lượng theo dòng tiền

| `flow_code` | Launch (M0 + 6 tháng) | Year 1 | Year 3 | Giá trị TB | Giá trị p99 | Bảo mật số tiền? |
|---|---|---|---|---|---|---|
| `OUTLET_COLLECT` | 200 outlet × 1/ngày = **200/ngày** | 5,000/ngày (**1.25 M/năm**) | 12,000/ngày (3.0 M/năm) | 2 tr ₫ | 30 tr ₫ | không |
| `LOYALTY_ACCRUE` | 2,000/ngày | 30,000/ngày (11 M/năm) | 100,000/ngày | 5,000 điểm | 200,000 điểm | **không** (xem C1.4) |
| `LOYALTY_REDEEM` | 200/ngày | 3,000/ngày | 10,000/ngày | 20,000 điểm | 500,000 điểm | không |
| `B2B_PAYOUT` | 20/tháng | 500/tháng (6,000/năm) | 1,200/tháng | 400 tr ₫ | 8 tỷ ₫ | **có** |
| `B2B_INVOICE_PAY` | 40/tháng | 2,000/tháng (24,000/năm) | 5,000/tháng | 200 tr ₫ | 4 tỷ ₫ | **có** |
| `ENDUSER_PAY` | 0 (record-only, §C16) | 0 | pilot 1,000/ngày | 150 k ₫ | 3 tr ₫ | không |
| `RELAYER_FEE` | 1/tháng | 1/tháng | 1/tháng | — | — | không |
| **Tổng thao tác on-chain** | **~2,400/ngày** | **~38,000/ngày** | **~123,000/ngày** | | | |
| **Tổng `blockchain.settlement`** | ~0.9 M/năm | **~14 M/năm** | ~45 M/năm | | | |

TVL đỉnh dùng cho mọi tính toán rủi ro: **$2 M** (Year 1), $6 M (Year 3).
Đây là con số §12.0.4 dùng và nó giữ nguyên.

### C1.2. Bốn ngưỡng kiến trúc, chạy lại theo bảng trên

| Quyết định | Ngưỡng đã nêu | Year 1 rơi vào đâu | **Chốt** |
|---|---|---|---|
| `mail.thread` trên `blockchain.settlement` (§10.4.12) | > 100 k settlement/tháng thì bỏ | ~1.2 M/tháng | **Bỏ ngay từ ngày đầu.** Thay bằng `blockchain.settlement.log` (**6 cột**: `settlement_id`, **`company_id`**, `from_state`, `to_state`, `uid`, `log_datetime`). `mail.thread` chỉ giữ trên **mười** model cấu hình khối lượng thấp (§C3). |
| Finality Gate trong `ir.cron` hay service (§10.4.12) | > 100 k/ngày thì tách service | 38 k/ngày | **`ir.cron` giữ tới Year 3**, cộng đường đẩy `chain_event_ingest` + `cron._trigger()` cho mọi flow có `blockchain.money.flow.latency_budget = 'seconds'` (§C9.1 cuối mục). Tách `chain-indexer` thành service khi vượt 100 k/ngày, không sớm hơn. |
| Partition `blockchain.chain.event` (§11.9) | > 1 M event/tháng | ~1.7 M/tháng (1.5 log/thao tác) | **KHÔNG partition. §11.9 đúng và canon bản 1 đã lật nó trên một tiền đề sai** — xem khối "Vì sao không partition" ngay dưới bảng. Thay bằng BRIN trên `observed_datetime` + cron archival hằng tháng + `autovacuum_vacuum_scale_factor = 0.02` trên bảng đó. ClickHouse **chưa cần** — câu hỏi archive, hoãn tới Year 3. |
| Zether trên Gnosis cho loyalty (§3.3.8) | trần ~30,000 tx/ngày toàn mạng | loyalty Year 1 = 33,000/ngày | **Loyalty KHÔNG chạy Zether.** ERC-20 công khai + EIP-1776, `is_confidential = False` trong seed của Z-POINT. Chain khởi điểm của loyalty là **Gnosis (public)** — chốt ở §C16. Xem C1.4. |

**Vì sao không partition — cơ chế, đã kiểm trên source của addon này.**

`bamboo_idempotency/models/base.py:163-171` chạy **không có guard**, trong
`_auto_init` của **mọi** model non-abstract non-transient:

```sql
CREATE UNIQUE INDEX "{table}_bamboo_uuid_uniq" ON "{table}" (bamboo_uuid)
WHERE bamboo_uuid IS NOT NULL
```

PostgreSQL từ chối một unique index trên bảng partition khi index **không chứa
đủ mọi cột khoá partition**. Câu lệnh trên raise, và `-u dms_blockchain` **chết
giữa chừng schema**. `_auto_init` của chính Odoo hỏng ở một tầng cao hơn: nó tạo
`PRIMARY KEY(id)`, cũng bất hợp lệ trên bảng partition theo `observed_datetime`.

Và nếu ai đó lách được phần DDL, `_bamboo_uuid_enforced()` (`base.py:115-127`,
một truy vấn `pg_indexes` `ormcache` đúng theo tên index đó) trả `False`, nên
`bamboo_create_idempotent` **raise `UserError` ở mọi lời gọi**. Đó chính xác là
chế độ hỏng §C3 và §C11.10 cảnh báo: cron indexer **chết**, không degrade — tức
mất đường ingest exactly-once của §C10.6, tức mất **đường quan sát tiền**, ở
~21 M dòng/năm. §C3 đặt `bamboo_idempotency` làm dependency cứng và §C10.6 đặt
`bamboo_uuid = uuid5(NS_CHAIN_EVENT, …)` làm khoá dedup, nên "partition ngay từ
migration đầu" và "dedup bằng `bamboo_uuid`" là **hai quyết định loại trừ nhau**.

Ước lượng "ba dòng DDL" của bản 1 **bị xoá**: con số thật gồm cả việc vá cách
Odoo sinh PRIMARY KEY, và đó không phải một chi phí ai muốn trả ở migration đầu.

Nếu tới Year 3 vẫn muốn partition, nó thuộc về **một bảng Odoo không sở hữu**:
một bảng archive do `chain-indexer` ghi dưới DB role của chính nó, ngoài ORM.
Bảng đó **không mang được** `bamboo_uuid` dedup, nên khi đó phải chọn một cơ chế
dedup khác (khuyến nghị: `UNIQUE (caip2, block_hash, tx_hash, log_index,
observed_month)` do indexer tự ép, không qua `bamboo_create_idempotent`).

### C1.3. Hệ quả lưu trữ (Year 1, dùng để duyệt hạ tầng)

| Bảng | Dòng/năm | Dung lượng kể cả index |
|---|---|---|
| `blockchain.settlement` | 14 M | ~5.6 GB/năm (400 B/dòng) |
| `blockchain.settlement.log` | 70 M | ~5.2 GB/năm (74 B/dòng, kể cả `company_id`) |
| `blockchain.chain.event` | 21 M | ~10.5 GB/năm (500 B/dòng) |
| `blockchain.transaction` | 14 M | ~8.4 GB/năm (600 B/dòng) |
| `blockchain.zether.entry` | 60 k | ~50 MB/năm |
| Zether raw log (giữ **vĩnh viễn**, §11) | | ~0.4 GB/năm |
| Trace/receipt trên Garage | | 60–600 GB/năm, retention 90 ngày (400 ngày cho `reverted`/`orphaned`) |

### C1.4. Loyalty và Zether — kết luận rút ra từ số

Ở khối lượng Year 1, loyalty confidential trên Gnosis là bất khả thi
(33,000/ngày so với trần ~30,000/ngày **của cả mạng Gnosis**), và trên private
chain nó chiếm toàn bộ ngân sách CPU validator mà không mua được gì: số dư điểm
thưởng không phải bí mật thương mại. Chốt kiến trúc: **`LOYALTY_ACCRUE` và
`LOYALTY_REDEEM` dùng ERC-20 công khai + EIP-1776**, `blockchain.token.is_confidential
= False` cho Z-POINT. Nếu nghiệp vụ khẳng định điểm thưởng cần bảo mật số dư thì
đó là một quyết định của người dùng (§C21 D9), và nó buộc loyalty rời
khỏi Gnosis sang private chain hoặc Celo.

**Chain của loyalty là Gnosis, không phải private.** Lập luận trần 30,000/ngày ở
trên chỉ có nghĩa nếu loyalty thật sự ở trên Gnosis, và nó thật sự ở đó: §C1.2
hàng bốn, §C19 điểm hoà vốn, và §C16 đều dựng trên giả định ấy. Hệ quả archetype
được giải ở **§C16** (loyalty là ngoại lệ freeze có biện minh viết ra, dùng
`ZTokenOpen` trên Gnosis) — bản 1 của canon vừa bắt loyalty dùng
`ZTokenPermissioned` (chỉ deploy được trên private, §1.10) vừa tính dung lượng
nó trên Gnosis, tức giao cho P21 hai chain loại trừ nhau.

---

## C2. Quy ước đặt tên

### C2.1. Model

- Prefix **`blockchain.`**, không bao giờ `dms.blockchain.`. Lý do không phải
  thẩm mỹ: `dms.` là một lời nói dối về phạm vi trên một addon từ bỏ
  `depends: dms` (locked #7), và nó khiến người đọc đi tìm một model cha không
  tồn tại.
- Dạng `blockchain.<danh_từ>[.<danh_từ_con>]`, số ít, chữ thường, phân cách bằng dấu chấm.
- Class Python là CamelCase của `_name` bỏ dấu chấm: `blockchain.zether.entry`
  → `BlockchainZetherEntry`.
- Một `_name` được **định nghĩa đúng một lần**. Mở rộng từ section khác dùng
  `_inherit = '<name>'` **không kèm `_name`**. (Sửa §03.9.4, §11.9.)

### C2.2. Field

| Quy tắc | Đúng | Sai |
|---|---|---|
| Không trùng tên kiểu Odoo (`date`, `datetime`, `char`, `text`, `float`, `integer`, `boolean`, `binary`, `html`, `json`, `selection`, `monetary`, `reference`) | `broadcast_datetime`, `rotate_due_date` | `datetime`, `date` |
| uint256 là `Char` + CHECK, hậu tố `_base` | `amount_base`, `fee_base`, `drift_base` | `amount_wei`, `fee_wei`, `amount_token_units` |
| Bản hiển thị của uint256 là `Float(digits=(38, 18))`, luôn `compute`, không bao giờ là nguồn sự thật | `fee_native_display` | `net_display` với `digits=(24, 8)` |
| Chuỗi hex có hậu tố `_hex`; hash có `_hash` hoặc `_sha256` | `calldata_hex`, `digest_hash`, `proof_sha256` | `calldata`, `digest` |
| Integer **không** phải khoá ngoại thì không được kết thúc bằng `_id` | `evm_chain_number` | `evm_chain_id` |
| Trường vòng đời: `<danh_từ>_state` khi model đã có một `state` kế thừa hoặc khi tên `state` mơ hồ | `settle_state`, `metatx_state`, `tx_state`, `deploy_state`, `pool_state`, `health_state`, `applied_state`, `gl_state`, `job_state` bị xoá (xem C10.8) | hai cột `state` và `job_state` trên cùng bảng |
| Model sở hữu đúng **một** vòng đời và không có model cha thì được dùng `state` trần | `blockchain.chain.state`, `blockchain.account.state` | **Phản ví dụ: `blockchain.relay.job` có HAI vòng đời** (`chain_state` + `business_state`, §C10.8) nên **không** có `state` trần. Thêm một cột `state` bên cạnh `chain_state` là đúng con bug odoo-conventions-3 mà §C10.8 tồn tại để đóng, và Odoo gộp nó **im lặng** |
| **Không bao giờ** `fields.Char(size=N)` | `fields.Char()` + `models.Constraint('CHECK (length(...) ...)')` | `fields.Char(size=42)` |
| **Không bao giờ** `default=` trên stored computed field | compute gán ở dòng đầu, trước mọi nhánh | `compute=..., store=True, default=0.0` |
| Regex uint256 duy nhất | `'^(0|[1-9][0-9]{0,77})$'` | `'^[0-9]{1,78}$'` (nhận số 0 dẫn đầu) |

### C2.3. XML id

| Loại | Mẫu | Ví dụ |
|---|---|---|
| Nhóm quyền | `group_blockchain_<role>` | `group_blockchain_treasury` |
| Record rule | `rule_<model_short>_<role>` | `rule_settlement_operator_company` |
| View | `view_<model_short>_<type>` | `view_settlement_form`, `view_chain_list` |
| Action | `action_<model_short>[_<qualifier>]` | `action_settlement_pending_finality` |
| Cron | `cron_<động_từ>_<danh_từ>` | `cron_poll_receipts`, `cron_finality_gate` |
| Sequence | `seq_<model_short>` | `seq_blockchain_settlement` |
| Data record | `data_<model_short>_<key>` | `data_chain_gnosis` |
| Menu | `menu_blockchain_<...>` | `menu_blockchain_root` |

`<model_short>` = `_name` bỏ prefix `blockchain.` và bỏ dấu chấm:
`blockchain.settlement.batch.chunk` → `settlement_batch_chunk`.

### C2.4. Tên object SQL

Odoo 19 sinh tên từ tên thuộc tính: `{table}_{attribute_name_bỏ_gạch_dưới_đầu}`.
Nghĩa là **tên thuộc tính CHÍNH LÀ tên constraint**. Hệ quả bắt buộc: dict
`EXPECTED` của test "constraint có thật" (§14.11) phải **sinh ra** từ registry
theo công thức đó, không được gõ tay — bản gõ tay hiện tại sai ở ít nhất ba
dòng và làm required check fail ngay lần build xanh đầu tiên.

### C2.5. Module, contract, service

- Addon: `dms_blockchain`, `dms_blockchain_<đích_cầu_nối>`. Giữ tên
  `dms_blockchain` (đổi tên sau lần cài đầu tốn ~700 dòng `ir_model_data` +
  24 `ALTER TABLE RENAME`; `dms` đọc như vendor prefix).
- Contract: `PascalCase.sol`, một contract một file, tên contract == tên file.
  Interface `I<Name>`, library `<Name>Lib`.
- Service: thư mục kebab-case — `relay-pool`, `confidential-signer`,
  `intent-hub`, `chain-indexer`.

### C2.6. Ngoại lệ duy nhất về hai tên cho một khái niệm

EIP-712 digest của `MetaTransaction` được gọi là **`digest_hash`** trong Odoo
và **`intent_id`** trên intent bus. Cùng một giá trị. Ngoại lệ này được cho
phép vì `intent_id` là tên relayer nhìn thấy, và nó **phải** được ghi trong
docstring của cả hai phía. Mọi cặp tên khác cho cùng một khái niệm là lỗi.
Cụ thể đã bị xoá: `metatx_digest` (§04.12, §5.8.2) — cột đó không tồn tại.

**Va chạm đã xử lý, ghi ra để nó không quay lại: `origin_ref` vs `origin_key`.**
Bản 1 của canon dùng `origin_ref` cho **hai** thứ khác loại trong cùng một addon:
một `fields.Reference` trỏ record nguồn trên `blockchain.settlement` (§C10.4), và
một **chuỗi khoá idempotency** trên `blockchain.relay.job` (§C10.8). Chốt:

- **`origin_key`** — luôn là `Char`, luôn là khoá idempotency, luôn nằm trong
  `UNIQUE(company_id, origin_producer, origin_key)`. Dùng trên **cả**
  `blockchain.settlement` **và** `blockchain.relay.job`.
- **`origin_ref`** — chỉ tồn tại trên `blockchain.settlement`, luôn là
  `fields.Reference` không stored, luôn là "record nào sinh ra dòng này".
- `blockchain.relay.job.origin_ref` **bị đổi tên thành `origin_key`** (§C10.8).
  Với job cấp chunk, `origin_key` giữ đúng **`unit_key`** của §C10.5
  (`chunk:<batch.origin_key>:<sequence>`), không phải `origin_key` của một
  settlement lẻ trong chunk.

---

## C3. Topology addon và `depends`

Bốn addon. Không phải sáu (§09.0), không phải ba.

```
custom-addons/bamboo-dms/
├── dms_blockchain/            CORE
├── dms_blockchain_payment/    BRIDGE -> payment
├── dms_blockchain_account/    BRIDGE -> account
└── dms_blockchain_bridge/     BRIDGE -> dms
```

| Module | `depends` | `auto_install` | Chứa gì | Mở khoá mode |
|---|---|---|---|---|
| `dms_blockchain` | `['base', 'mail', 'bamboo_idempotency']` | `False` | Toàn bộ §C10 trừ reconciliation run | M4, M12, M13 |
| `dms_blockchain_payment` | `['dms_blockchain', 'payment']` | `False` | `payment.provider` `code='chain'`, override `payment.transaction`, adapter acquirer bên thứ ba | M1, M2, M6, M11 |
| `dms_blockchain_account` | `['dms_blockchain', 'account']` | `False` | `account.move` / `account.payment`, `blockchain.reconciliation.run`/`.line`, FX | M3, M15 |
| `dms_blockchain_bridge` | `['dms_blockchain', 'dms']` | **`True`** | mixin `blockchain.settlement.origin` trên `dms.trade.settlement`, `dms.payment.collection`, `dms.trade.claim`, **`dms.incentive.line`** | — |

**`dms.incentive.rule.line` KHÔNG TỒN TẠI.** Đã grep
`custom-addons/bamboo-dms/dms/models/`: ba model incentive là
`dms.incentive.rule` (`analytics/dms_incentive.py:17`), `dms.incentive.tier`
(`:85`), `dms.incentive.line` (`:115`). Đích đúng là **`dms.incentive.line`** —
nó là *dòng phải trả* (`state: calculated → reviewed → approved → payable →
paid/reversed`, `amount`, `currency_id`, `user_id`), tức đúng thứ một settlement
B2B/incentive khởi nguồn từ. `dms.incentive.rule` là **quy tắc có version** và
không bao giờ mang settlement origin.

Vì sao đây là lỗi nghiêm trọng chứ không phải một typo: một class bridge viết
`_inherit = ['dms.incentive.rule.line', 'blockchain.settlement.origin']` **fail
lúc registry setup**, nên `dms_blockchain_bridge` không bao giờ cài được; và vì
nó `auto_install: True`, lỗi đó nổ đúng lúc ai đó cài `dms_blockchain` lên một
database **đã có `dms`** — tức trên production, không phải trong job CI
standalone. Đây cùng lớp lỗi với odoo-conventions-14
(`dms.trade.settlement.line`) mà canon tuyên bố đã sửa **trong chính bảng này**.

**Ba điều đã chốt và không mở lại:**

1. **Tên cầu nối DMS là `dms_blockchain_bridge`**, không phải `dms_blockchain_dms`.
   Lý do: required check `odoo-bridge` của §14.11b cài đúng tên đó; đổi tên
   nghĩa là một required check không bao giờ chạy trên code thật.
2. **`auto_install: True`**, không phải `auto_install: ['dms']`. Kiểm trên
   source `odoo/modules/module.py:445-458`: dạng list biến trigger set thành
   chỉ `{'dms'}`, tức cài `dms` một mình sẽ **kéo `dms_blockchain` vào theo**.
   Dạng `True` = `set(depends)` = chỉ tự cài khi cả hai đã installed. Đó là
   hành vi mong muốn.
3. **`dms_blockchain_acquirer` và `dms_blockchain_mandate` bị xoá.** M2 (acquirer)
   là một adapter bên trong `dms_blockchain_payment`, không phải một addon.
   M7–M10 và M18–M19 (mandate, streaming, escrow, voucher, payment channel) ra
   khỏi phạm vi 24 tháng đầu (§C18) — chúng cần contract chưa ai scope và M9
   cần một vòng audit riêng $25–40 k.

**`depends` của core, giải thích từng phần tử:**

- `base` — hiển nhiên.
- `mail` — **mười** model khai `_inherit = ['mail.thread']`, đếm theo dòng:
  `blockchain.chain`, `blockchain.token`, `blockchain.custody.provider`,
  `blockchain.custody.key`, `blockchain.custody.policy`, `blockchain.relayer`,
  `blockchain.approval.policy`, `blockchain.approval.request`,
  `blockchain.contract.deployment`, `blockchain.upgrade.proposal`. Bỏ `mail` là
  gãy cả mười. **`blockchain.settlement` KHÔNG còn `mail.thread`** (§C1.2) nhưng
  `mail` vẫn cần cho phần còn lại. (Bản 1 viết "tám" và liệt kê chín, trong khi
  §C1.2 hàm ý mười — `custody.*` là ba model, `approval.*` là hai.)
- `bamboo_idempotency` — `bamboo_create_idempotent()` là cơ chế exactly-once của
  §11.5 và §15.2.4. Nó **raise `UserError`** chứ không degrade khi partial
  unique index vắng mặt, nên thiếu dependency nghĩa là một cron **chết**, không
  phải chạy chậm.
- **Không khai `web`, không khai `bus`.** Cả hai đến gián tiếp qua `mail`. Khai
  lại là nhiễu, và §09.0 phải sửa theo.
- **Không khai `account`, `payment`, `onboarding`, `portal`, `dms`.** Đó là
  locked #7.

**Hệ quả của `bamboo_idempotency` phải nói ra trước:** addon đó
`_inherit = 'base'`, nên nó thêm cột `bamboo_uuid` và một partial unique index
vào **mọi model trong database**, không riêng model của ta. Đó là một thay đổi
schema toàn DB, và job CI standalone phải thực sự chạy qua nó.

**Job CI `odoo-standalone` (required check, bảo vệ locked #7):**

```bash
createdb bc_standalone
odoo -d bc_standalone -i dms_blockchain --stop-after-init --without-demo=all
psql bc_standalone -c "SELECT 1 FROM ir_module_module WHERE name='dms' AND state='installed'" | grep -q '0 rows'
psql bc_standalone -c "SELECT indexname FROM pg_indexes WHERE indexname LIKE 'blockchain%bamboo_uuid_uniq'" > idx.txt
python tools/assert_idempotent_models_have_index.py idx.txt
```

Dòng cuối là phần §14.11b đang thiếu: gate hiện tại pass ngay cả khi index
không tồn tại, tức nó bảo vệ đúng một nửa thứ nó nghĩ nó bảo vệ.

**Job CI `odoo-bridge` (required check thứ hai, bắt buộc — `odoo-standalone`
chứng minh được đúng vế phủ định và không bao giờ bắt được một `_inherit` sai
trong bridge):**

```bash
createdb bc_bridge
odoo -d bc_bridge -i dms --stop-after-init --without-demo=all
odoo -d bc_bridge -i dms_blockchain --stop-after-init --without-demo=all
psql bc_bridge -c "SELECT state FROM ir_module_module WHERE name='dms_blockchain_bridge'" \
  | grep -q installed          # auto_install phai da keo no vao
python -m pytest tests/bridge/  # mixin co mat tren ca 4 model nguon
```

Cộng một test standalone rẻ nhất chứng minh locked #7 đứng vững **lúc chạy**,
không chỉ lúc cài (§C10.4, `origin_ref`):

```bash
psql bc_standalone -c "INSERT INTO blockchain_settlement
  (name, company_id, origin_producer, origin_key, origin_model, origin_id,
   use_case, direction, transport, amount_base, currency_id, settle_state, gl_state)
  VALUES ('T/1', 1, 'ci', 'k1', 'dms.trade.settlement', 1,
          'b2b', 'out', 'external', '0', 1, 'draft', 'not_required')"
odoo shell -d bc_standalone --stop-after-init <<'PY'
env['blockchain.settlement'].search_read([], ['origin_ref', 'origin_model'])
PY
```

---

## C4. Bố cục repo

Locked #9 đặt `smartcontracts/` ở gốc repo. Gốc repo của một deployment là
`/home/dockers/odoo19`, không phải thư mục addons — ba trong năm cây dưới đây
**không phải addon** và không thể nằm dưới `custom-addons/`.

```
/home/dockers/odoo19/
├── custom-addons/bamboo-dms/     # 4 addon Odoo (§C3)
├── smartcontracts/               # §14.1 — cây chuẩn tắc, Foundry + Rust + KAT
├── relay-pool/                   # §06, §08  — Python asyncio
├── confidential-signer/          # §07       — Rust (chứa ZetherKeyOracle)
├── intent-hub/                   # §05       — Python asyncio
└── chain-indexer/                # §11       — Python asyncio
```

§01.14 và §10.2 sửa theo bố cục này. §14.1 giữ nguyên nội dung cây
`smartcontracts/`; nó là bản chuẩn tắc.

**Đường dẫn trong CI phải qua biến, không hard-code**, vì hai cây sẽ tách thành
hai repo: `SMARTCONTRACTS_DIR` (mặc định `/home/dockers/odoo19/smartcontracts`).
ABI-drift gate (§14.12b) đọc `${SMARTCONTRACTS_DIR}/evm/abi/*.json`;
`fs_permissions` trong `foundry.toml` giữ đường dẫn tương đối trong cây
`smartcontracts/`.

**Bốn service ngoài Odoo — nhà kỹ thuật của chúng, phần §14 đang bỏ trống:**

| Service | Runtime | Đơn vị triển khai | Cấu hình | Test tier | DB role |
|---|---|---|---|---|---|
| `relay-pool` | Python 3.12 asyncio | container, N replica theo shard | env var thuần; không đọc `ir_config_parameter` | unit, contract-test với RPC surface Odoo, chaos (§06.11) | `bc_relay`: **SELECT** trên `blockchain_relay_job` + `blockchain_metatx`, cộng quyền lấy row lock (`SELECT … FOR UPDATE SKIP LOCKED`). **Không INSERT, không UPDATE** |
| `confidential-signer` | Rust | container hoặc Nitro enclave | vsock/env; không có network stack trong enclave | unit, KAT chéo với `zether-core`, fuzz | không kết nối DB Odoo |
| `intent-hub` | Python 3.12 asyncio | container, 1–3 replica | env var | unit, conformance với `relayer-ref` | `bc_hub`: chỉ **SELECT** trên `blockchain_relayer` |
| `chain-indexer` | Python 3.12 asyncio | container, 1 replica/chain | env var | unit, fork-replay, reorg injection | `bc_indexer`: **SELECT** trên event/effect/block_header/transaction. **Không INSERT, không UPDATE** |

**Một quy tắc cho mỗi chiều, và không có chiều thứ ba** (§C13 là bản chuẩn tắc,
đây là mặt hạ tầng của nó): **đọc và claim** đi qua kết nối Postgres trực tiếp;
**mọi ghi** đi qua `/json/2` với service JWT. Bản 1 của canon mô tả cùng một
đường đi bằng ba cách loại trừ nhau — grant SQL trực tiếp ở §C4, `/json/2` ở
§C13.3, cron `sudo()` trong Odoo ở §C10.6/§C11.10 — và người xây P06/P11 phải
biết một state transition là một câu SQL hay một lời gọi RPC, vì hai thứ đó có
tính nguyên tử khác nhau và chế độ hỏng khác nhau.

Lý do phải là RPC ở chiều ghi: một `UPDATE` SQL trực tiếp **bỏ qua ORM**, nên
`models.Constraint` CHECK vẫn nổ nhưng **compute, record rule, ghi
`blockchain.settlement.log` và giao thức `owner_fence` thì không chạy**. Với
role chỉ-SELECT ở trên, điều đó không còn khả thi — và ma trận ACL §C14 mới thật
sự là ma trận ACL, không phải trang trí.

**Intent bus sống ở đây, không trong Odoo.** `intent-hub/` là service standalone
trong cây này: nó là ranh giới tin cậy của §12 (một bề mặt tấn công **ngoài**
process Odoo), nó có `/healthz` riêng, CI riêng, DB role riêng. Annexe controller
`auth='public'` của bản 1 §C14.2 **bị xoá**: relayer không bao giờ chạm HTTP của
Odoo. Endpoint nào của bus cần ghi một model `blockchain.*` thì đi qua `/json/2`
như mọi client khác.

Ba service Python vì on-call là một đội; một runtime thứ hai là một chuỗi cung
ứng thứ hai phải audit. `confidential-signer` là Rust vì key oracle
(`crates/zether-oracle-*`) đã là Rust và TCB phải nhỏ.
Mỗi service: một workflow CI riêng, một `/healthz` (liveness) + `/readyz`
(readiness bao gồm kết nối RPC và độ trễ watermark), một dòng DoD trong §16.3.2.

---

## C5. Mô hình trạng thái Zether — epoch đã chết, `accSeq` thắng

### C5.1. Quyết định

**Epoch không tồn tại trong thiết kế này.** `acc` và `pending` là hai slot tách
rời; `transferConfidential` và `withdraw` không bao giờ tự gộp; `pending → acc`
chỉ xảy ra trong `rollOver()` mang chữ ký Schnorr của chủ tài khoản; `accSeq`
được băm vào Fiat-Shamir transcript và contract `require(accSeq == provedAccSeq)`.

**Vì sao trên mặt kỹ thuật:** epoch tồn tại để đóng băng `acc` cho proof của
người gửi sống sót. Nó mua điều đó bằng ba cái giá mà `accSeq` không phải trả:
(a) relayer mất 1–3 block giữa `eth_call` và inclusion, nên trên Gnosis với
`EPOCH = 5 block` khoảng **40% transaction đã simulate-pass bị revert vì trôi
epoch** — không dùng được; (b) một khoản 1 xu gửi tới nạn nhân làm đổi `acc` và
giết proof đang bay; (c) `rollOver` permissionless cho phép grief ~30 k gas
($0.00006) lặp vô hạn. `accSeq` xoá cả ba **với đúng một điều kiện**, viết ở khối
dưới. Cái giá là **một transaction thừa** (`rollOver` trước khi tiêu tiền vừa
nhận), ~66 k gas execution + 21 k intrinsic ≈ **91 k gas gross** (§C7.3 — con số
28 k/49 k của bản 1 sai, xem đó), và nó có thể chạy nền, gasless, không ai thấy.

**Phát biểu đúng, hẹp hơn bản 1, và điều kiện của nó.** Tính chất thật sự đứng
vững là: **chỉ chủ tài khoản mới *cho phép* được một lần đổi `accSeq`.** *Ai*
phát sóng cái cho phép đó, và *khi nào*, thì không được kiểm soát — ký và phát
sóng là hai việc rời nhau. §3.5.5 khuyến nghị 1 lại đặt rollOver nền do relayer
đẩy làm mặc định, nên các blob rollOver đã ký **tồn tại thường trực** và đi qua
mempool công khai. Bắt được một cái, kẻ tấn công **giữ lại**, chờ chủ tài khoản
phát một `transferConfidential` gắn `accSeq = k`, front-run bằng blob đã giữ
(~91 k gas), và transfer revert ở `require(accSeq == provedAccSeq)`. Đó **đúng
là** con grief mà canon giết epoch để thoát, ở **đúng mức giá** đó.

**Chốt, và nó rẻ hơn con bug: thông điệp Schnorr của `rollOver` mang một hạn.**
`H(chainId, address(this), "ZETHER_ROLLOVER_V1", acct, accSeq[acct],
expectedPendingSeq, validUntilBlock)`, contract `require(block.number <=
validUntilBlock)` — vài trăm gas. §C5.2 biến thể A ký cùng trường đó. Cộng một
**quy tắc ví, là quy tắc chứ không phải giả định**:

> Ví **không bao giờ** giữ một rollOver đã ký trong khi còn một proof transfer
> chưa lên chain. Ký rollOver ⇒ phát ngay; đã phát transfer ⇒ không ký rollOver
> cho tới khi transfer final hoặc hết hạn.

Với hai thứ đó, phát biểu đúng là: **xác suất revert do race về ~0 *với điều kiện*
`validUntilBlock` đủ chặt và quy tắc ví được tôn trọng.** Không phải vô điều
kiện. §C5.4 định giá đường lui epoch ở **+6 ew** so với một "~0" có điều kiện,
không so với một "~0" tuyệt đối. Single-flight của relay pool trên
`zether.from_schnorr` (§C5.3) chỉ quản hàng đợi **của chính pool** — nó không
chạm được một blob đã bị bên thứ ba bắt giữ.

### C5.2. Trạng thái mỗi (account, token)

| Slot | Kiểu | Ai đổi được | Vai trò |
|---|---|---|---|
| `acc[a]` | `(C, D)` | chỉ tx được `a` uỷ quyền | nguồn của mọi proof |
| `pending[a]` | `(C, D)` | bất kỳ ai (credit) | nơi tiền đến nằm chờ |
| `accSeq[a]` | `uint64` | chỉ `rollOver(a)` | **vào Fiat-Shamir**; `require(accSeq == provedAccSeq)` |
| `pendingSeq[a]` | `uint64` | mỗi credit | client biết có tiền mới |
| `zetherNonce[a]` | `uint64` | mỗi debit thành công | anti-replay của proof |

Tổng slot mỗi (account, token): `acc` (C,D) = **4 slot**, `pending` (C,D) =
**4 slot**, `accSeq` 1, `pendingSeq` 1, `zetherNonce` 1 = **11 slot**. Một
`rollOver` ghi 10 trong số đó. Con số "5 SSTORE" của §3.5.4 là nguồn của cả hai
sai số ở §C7.3, và bảng này là bản chuẩn tắc để dẫn lại.

`rollOver` biến thể **A (Schnorr, mặc định)**: không cần EOA gắn với tài khoản,
tương thích custody MPC/smart-account (locked #6). Thông điệp ký **bắt buộc
gồm `validUntilBlock`** (§C5.1). Biến thể B (`rollOverByController`) chỉ cho
profile custodial, cùng trường hạn.
`rollOver` **relay được** (bọc trong `metaTx.data`) và **batch được**
(`rollOverBatch`, mỗi phần tử một chữ ký), nhưng **không permissionless**.
Đóng luôn §14.13(17) và §14.15 Q8: câu trả lời là *không permissionless*.

### C5.3. Hệ quả bắt buộc, theo từng nơi

| Nơi | Phải xoá | Phải thêm |
|---|---|---|
| Struct meta-tx (§04.10) | `targetEpoch` | — |
| Envelope intent bus (§5.2) | `zether.target_epoch` | `zether.acc_seq`, `zether.pending_seq`; single-flight khoá theo `zether.from_schnorr` |
| §06 relay pool | `zether_target_epoch`, `zether_epoch_deadline_block`, state `epoch_expired`, metric `relay_zether_epoch_miss_total`, chính sách "cancel thay vì speed-up khi hết epoch" | pre-broadcast check `accSeq == provedAccSeq` đọc tại block đã ghim; single-flight theo `schnorr_address` |
| `blockchain.zether.entry` (§10.4.7) | `epoch_number` (đang `required=True`, tức một cột NOT NULL không có nguồn giá trị) và `_order = 'epoch_number desc, id desc'` | `acc_seq` (Integer, index), `pending_seq` (Integer), `_order = 'id desc'` |
| §10.7 cron | `_cron_zether_rollover` dạng Odoo tự gọi | `_cron_zether_rollover_request` chỉ **tạo** một `blockchain.relay.job` mang chữ ký Schnorr do custody ký; **Odoo không bao giờ giữ `x`** (§3.9.5) |
| §5.4.3, §09.9, §09.10b | trần 3,456 tx/ngày/address, độ trễ "25 s epoch + 160 s" | trần **17,280 tx/ngày/address** trên Gnosis (1 tx/block, block 5 s); độ trễ Zether = prove + relay + finality, không có thành phần epoch |
| §15.5.5, §03.5 | mọi phát biểu "300 người nhận cùng một epoch" | chi phí batch cộng thêm một `rollOver` cho mỗi tài khoản nhận: **+70 k gas/phần tử khi batch** ở trạng thái ổn định, **+186 k cho lần rollOver đầu tiên của một tài khoản mới** (§C7.3). **Không** phải 49 k |

### C5.4. Đường lui, viết đúng một lần

Owner-signed `rollOver` là một sai lệch cấp giao thức so với paper FC 2020 và
nó **chưa có chữ ký của một nhà mật mã** (§3.11.1 U3). Nếu review bác bỏ, năm
section revert **cùng nhau**, và đây là toàn bộ nội dung của việc revert:

> Epoch quay lại. `targetEpoch` quay lại `EncryptedTransfer` và quay lại
> `blockchain.metatx`. `expiry` của Zether tụt về **≤ 1 epoch**. Mô hình tỷ lệ
> revert ~40% của §3.5.5 quay lại và trở thành một bài toán phải giải trước
> khi có luồng tiền. `blockchain.zether.entry.acc_seq` đổi thành `epoch_number`.
> Chi phí ước tính: **+6 ew** (P06 và P10) và một vòng thiết kế lại
> `simulateAccounts`.

Không nơi nào khác trong bộ tài liệu được giữ một nửa của đường lui này.
Review mật mã cho `rollOver` chuyển vào **S0** như một hợp đồng 2–3 tuần trả
tiền (cùng loại vấn đề lead time với S9), không để tới audit phase B.

---

## C6. Tham số Zether

### C6.1. Curve — parametric ngay, gate G1 chốt giá trị

Không một dòng code nào được hard-code hằng số curve. §02 và §07 hiện đang
hard-code alt_bn128 (số nguyên tố `P`, phương trình `y² = x³ + 3`, cofactor 1,
enum `FROST_BN254` / `MUSIG2_BN254` / `BLS_BN254`, kiểu `G1Affine` trong
`ZetherKeyOracle`) và **phải** đổi thành:

- một hằng `CURVE` cấu hình theo deployment (`P`, `A`, `B`, `ORDER`, `COFACTOR`);
- **subgroup check bắt buộc khi `COFACTOR != 1`** — Baby Jubjub có cofactor 8,
  bỏ check là một lỗ hổng (§12.3.4);
- enum scheme bỏ hậu tố curve: `SCHNORR`, `MUSIG2`, `FROST`,
  `ECDSA_MULTISIG`, cộng một cột `curve` riêng.

#### Bảng quyết định curve — ba cột, và cột thứ ba là bảo mật

| Curve | Precompile G1 trên EVM | Chi phí `transferConfidential` 32/64 | **Mức bảo mật** |
|---|---|---|---|
| **BN254 G1** (`bn254`) | **có** — `0x06` `ecAdd` 150, `0x07` `ecMul` 6,000 (EIP-1108) | **1,905,000** (§C7.2) | **~100 bit** sau exTNFS |
| Baby Jubjub (`babyjubjub`) | **KHÔNG CÓ, ở bất kỳ giá nào** | **≈ 7 M** — không dùng được trên public (§3.3.9) | ~125 bit |
| BLS12-381 (`bls12_381`) | **có** — EIP-2537, gồm **`BLS12_G1MSM` `0x0c`** | **≈ 1,050,000** thận trọng / **≈ 770,000** nếu gộp một MSM (§C7.2) | 117–126 bit |

**Mặc định ghi trong seed data: `curve_profile = 'bn254'`** cho
`chain_profile = 'public'`. Bản 1 của canon seed `babyjubjub` và đó là một mâu
thuẫn nội tại, không phải một lựa chọn: Baby Jubjub là một twisted Edwards curve
trên **scalar field** của BN254, còn `0x06`/`0x07` chạy trên alt_bn128 G1 trên
**Fp**. Không có precompile nào cho Baby Jubjub — chính §3.3.9 nói thế: *"mỗi
scalar mul ~30k gas thuần Solidity thay vì 6k, ⇒ MSM 230 điểm ≈ 7 M gas, không
dùng được trên public"*. 7 M vượt **mọi** trần canon đã đặt (kill criterion S1
2.5 M, `maxInnerGas`, `max_gas_per_tx`) và bằng ~41% một block Gnosis. Locked #4
(Gnosis trước) và seed `babyjubjub` **không thể cùng đứng**.

Lý do bản 1 đưa ra cho Baby Jubjub — giữ đường Groth16 ~215 k gas verify — là
chi phí **verify SNARK**, chỉ thành hiện thực nếu profile Groth16 public ship,
mà §3.3.9 đánh dấu *"ship sau"*, tức **không phải trong pha Gnosis-first mà toàn
bộ bảng gas được viết cho**. Nó không mua được gì ở M0–P10 và nó giết Zether trên
public. Chấp nhận **mất đường Groth16** trong 24 tháng đầu.

**G1 chưa đóng, và bây giờ nó có một ứng viên mạnh hơn cả `bn254`.** §C7.2 dẫn
BLS12-381 với `BLS12_G1MSM` batched: rẻ hơn BN254 **và** bảo mật cao hơn. Gate G1
phải đóng **trước dòng đầu tiên của P10** (prover Rust cũng bị khoá vào curve,
không chỉ contract), và nó **phải** so ba dòng ở trên, không phải hai. Migrate
curve sau khi có số dư nghĩa là **withdraw toàn bộ và lộ số dư của tất cả mọi
người trong một snapshot** — đó là lý do G1 không được để trôi, **không** phải lý
do để chốt vội một giá trị sai.

Preflight bắt buộc của S1, một dòng mỗi chain, kết quả ghi vào `mail.thread` của
record `blockchain.chain`: `eth_call` tới `0x0c` với input hợp lệ k=1 trên
**Gnosis sau Pectra** và trên **Celo op-geth sau Isthmus**. Nếu `0x0c` không
sống trên một chain thì dòng BLS12-381 bị loại **trên chain đó**, không phải trên
giấy. Canon **không** khẳng định sẵn kết quả: đó là một fact on-chain, và một
fact on-chain phải được đo, không được nhớ.

#### Bảo mật, chân trời bảo mật, và guard lúc deploy

Canon đứng trên mọi section (quy tắc ưu tiên 2), nên nếu §C6 không nói mức bảo
mật thì người đọc chỉ §C6 chọn curve mà **không có con số bảo mật nào đi kèm**.
Ba con số ở bảng trên là chuẩn tắc. Ghi chú kèm theo, vì §3.11.1 U4 viết sai:
**Baby Jubjub KHÔNG phải ~100 bit** — nó không pairing-friendly nên exTNFS không
áp dụng, subgroup nguyên tố ~2^251 ⇒ **~125 bit**. Tức lập luận bảo mật *ủng hộ*
Baby Jubjub đúng lúc lập luận gas giết nó; canon phải chép đúng cả hai.

BN254 là **~100 bit** vì embedding degree 12 cho phép đẩy G1-DLP sang F_p^12 —
**bất kể** contract có gọi pairing hay không. Phát biểu trung thực của §3.1.3
được chép nguyên vào canon:

> Trên public chain với BN254, **phải giả định mọi số tiền confidential đều có
> thể bị giải mã trong khoảng 2035–2045.**

Ciphertext Zether là **bất biến và vĩnh viễn**, nên đây là harvest-now-
decrypt-later nhắm vào số tiền hoá đơn B2B (p99 **8 tỷ ₫**, §C1.1), không phát
hiện được và không có thời gian phản ứng. `blockchain.zether.token` mang
**`confidentiality_horizon_years`** (đã có trong field list §C10.3) và guard sau
là **chuẩn tắc**, không phải khuyến nghị:

```python
@api.constrains('curve_profile', 'confidentiality_horizon_years', 'chain_id')
def _check_confidentiality_horizon(self):
    for rec in self:
        if (rec.curve_profile == 'bn254'
                and rec.chain_id.chain_profile == 'public'
                and rec.confidentiality_horizon_years > 10):
            raise ValidationError(_(
                'BN254 tren public chain la ~100 bit sau exTNFS. Moi so tien '
                'confidential phai duoc gia dinh giai ma duoc trong 2035-2045. '
                'Khong the gan chan troi > 10 nam cho token nay: doi curve '
                '(bls12_381) hoac ha confidentiality_horizon_years.'))
```

Câu 2035–2045 cũng phải đi vào **§C16** để nó tới được hợp đồng dịch vụ, không
chỉ nằm trong §03.

#### `BLS` bị cấm trên tài khoản giữ số dư Zether

Trong Zether, cùng một `x` **vừa** là khoá giải mã ElGamal **vừa** là khoá xác
thực tài khoản (§3.1.4: *"y = g^x vừa là khoá công khai ElGamal vừa là khoá xác
thực Schnorr"*). §02 định nghĩa `BLS_BN254` là min-signature-size — chữ ký ở G1,
**khoá công khai ở G2**. Đăng ký một tài khoản dưới scheme đó nghĩa là **công bố
`g2^x`** trên cùng đường cong pairing.

Ngay khoảnh khắc đó, DDH trong G1 **quyết định được bằng pairing**: với bất kỳ
transfer nào tới tài khoản ấy, `e(C_out · g^{-v'}, g2) == e(D_out, pk_G2)` thử
một ứng viên `v'` bằng **một** pairing, và với `n_v = 32` toàn bộ không gian số
tiền là một BSGS nhanh trong G_T. **Mọi** transfer tới tài khoản đó — quá khứ và
tương lai, hồi tố — trở thành công khai.

Chốt, và nó là một `require` ở tầng registry, **không phải một quy ước**:

> `blockchain.zether.account` **không được** liên kết tới một
> `blockchain.custody.key` mang scheme `BLS` — hay bất kỳ scheme nào công bố một
> phần tử G2 cho cùng khoá đó, trên cùng đường cong. `ZetherRegistry.register`
> revert. Muốn BLS aggregation thì nó cần **một khoá khác trên một curve khác**.

Vì vậy `BLS` **bị gỡ khỏi enum scheme** ở đầu mục này. §02.5 có gắn cờ
BLS-trên-bn254 là yếu nhưng đóng khung nó như một vấn đề **chữ ký** ("quy về
co-CDH") và cho phép nó trên private chain; không ai nối nó với tính che giấu
của ElGamal. Đây là chỗ nối đó.

### C6.2. Ba hằng số, và bảng theo token

Không có hằng số nào tên `MAX`. Ba thứ độc lập:

| Hằng số | Ai biết | Ràng buộc |
|---|---|---|
| `range_bits_value` (n_v) | contract, verifier | `n_v <= n_b`, **`n_b - n_v >= 24`** |
| `range_bits_balance` (n_b) | contract, verifier | `n_b <= 64`; `2^n_b > total_supply_scaled * 1024` |
| `DECRYPT_BOUND` | **chỉ client** | **`2^40`** (§3.2.2) — không xuất hiện trong contract |

**`n_v` phải là luỹ thừa của 2.** Inner-product argument của Bulletproof đệ quy
bằng cách **chia đôi**, nên `n` không phải luỹ thừa của 2 thì bị **pad lên luỹ
thừa của 2 kế tiếp**. Bảng proof size §3.3.2 chỉ có 32/64/128 vì đó là các giá
trị hợp lệ duy nhất; không nơi nào nói ra điều đó, và bản 1 của canon đã chốt
`n_v = 40` cho Z-VND B2B trong bảng tham số **mà không chạy lại bảng gas**.
Công thức `2n + 2·log2(n) + 7` thậm chí **không đánh giá được** tại n = 40.

| Token | underlying decimals | `scale_exponent` | 1 đơn vị ledger | `n_v` | `n_b` | Trần một giao dịch |
|---|---|---|---|---|---|---|
| Z-USDT / Z-USDC | 6 | 2 | $0.01 | 32 | 64 | $42.9 M |
| **Z-VND (B2B)** | **0** | **0** | 1 ₫ | **32** | 64 | **4.29 tỷ ₫ — chia nhỏ ở trên mức này** |
| Z-VND (bán lẻ) | 0 | 0 | 1 ₫ | 32 | 64 | 4.29 tỷ ₫ |
| Z-DAI / Z-xDAI | 18 | 2 | $0.01 | 32 | 64 | $42.9 M |

Z-POINT **không còn dòng ở đây**: §C1.4 đưa loyalty ra khỏi Zether hoàn toàn
(`is_confidential = False`, ERC-20 công khai + EIP-1776), nên một dòng tham số
Zether cho nó chỉ dẫn người đọc dựng một token confidential mà canon đã bỏ. Hệ
quả kèm theo ở §C6.5 (`memoAud`).

#### Chốt `n_v = 32` đồng nhất, và Z-VND B2B chia nhỏ

§3.11.2 Q5 để mở hai nhánh (*"chấp nhận n_v = 40 … hay chia nhỏ giao dịch lớn?"*).
Canon chọn **chia nhỏ**, và đây là số liệu của cả hai nhánh:

| | `n_v = 32` (chốt) | `n_v = 40` → pad **64** |
|---|---|---|
| Điểm MSM | 81 + 147 = **228** (làm tròn 230) | 147 + 147 = **294** (làm tròn 296) |
| Bulletproofs | 1,506,500 | 1,938,800 |
| Full-tx, auditor ON | **1,905,000** | **2,340,000** |
| Đỉnh band ±25% | 2.38 M | **2.93 M** |
| Kill criterion S1 (2.5 M) | qua | **fail** |
| `maxInnerGas`, `max_gas_per_tx` | vừa | **vượt cả hai** |

Nhánh `n_v = 40` phá **cùng lúc** kill criterion, `maxInnerGas` và
`max_gas_per_tx`, và nó buộc `requiredOuterGas` lên ~3.33 M (19.6% một block
Gnosis) — tức nó biến kill criterion S1 thành một con số vô nghĩa, vì nó được
đặt ở "ngay trên đỉnh band" của cấu hình cũ.

Nhánh chia nhỏ tốn bao nhiêu, tính thật trên khối lượng §C1.1 chứ không đoán:
trần `n_v = 32` với `scale_exponent = 0` là **4.29 tỷ ₫**. `B2B_PAYOUT` trung
bình 400 tr ₫ (1 transfer), p99 8 tỷ ₫ (**2** transfer). `B2B_INVOICE_PAY` trung
bình 200 tr ₫, p99 4 tỷ ₫ (**1** transfer). Hệ số nhân thật là **≈ 1.01×**, tức
~300 transfer thừa mỗi năm trên 30,000 — không phải 5–20× như lo ngại ban đầu,
vì phép chia là `ceil(v / 2^32)` chứ không phải chia đều thành lô nhỏ. Người
nhận không tốn thêm rollOver: mọi mảnh dồn vào cùng một `pending`, một
`rollOver` rút hết.

**Cái giá thật của chia nhỏ là rò rỉ, và nó phải được ghi ra:** số mảnh là công
khai, nên người quan sát học được `ceil(v / 2^32)`. Trên dải B2B 0–8 tỷ ₫ con số
đó nhận đúng hai giá trị, tức **rò rỉ một bit: "trên hay dưới 4.29 tỷ ₫"**, và
chỉ trên ~1% payout nằm ở đuôi. Một bit đó có chấp nhận được hay không là một
quyết định nghiệp vụ, không phải kỹ thuật — **§C21 D13**.

**Z-VND có `decimals = 0` và `scale_exponent = 0`.** §01.8's `decimals = 2` bị
thay thế. Lý do: VND không có đơn vị con, `res.currency` VND có `rounding = 1.0`,
và giữ 2 chữ số thập phân là vứt 6.64 bit dải để mua một biên rounding
Odoo ↔ chain không có nghĩa nghiệp vụ. §01's `maxSupply <= 2^44` giữ nguyên **ý
định** nhưng viết lại theo `n_b`: `require((1 << n_b) > totalSupplyScaled * 1024)`.
Xoá đề xuất "6 decimals nội bộ" ở §06.4.5 và §08.4b — nó đã bị thay bằng
`scale_exponent` theo token, giải đúng cùng bài toán mà không đụng range proof.

### C6.3. Đúng **hai** range statement, phí là public scalar

```
R6  v  ∈ [0, 2^n_v)      Bulletproof #1
R7  b' ∈ [0, 2^n_b)      Bulletproof #2      với b' = b − fee − v
```

`fee >= 0` và `b − fee >= 0` **được suy ra**, không phải mệnh đề độc lập.
`C_fee` bị **xoá khỏi struct và khỏi selector**. Phí là `uint256` công khai;
contract tự trừ đồng hình `C_acc' = C_acc · g^(-fee)` (~7 k gas) và tự
`require(fee < (1 << n_v))`. Phí trả cho relayer bằng **ERC-20 công khai trực
tiếp từ escrow** (`totalDepositedScaled -= fee`), tới một `address` EOA thường —
relayer không cần tài khoản Zether, không cần register, không cần prover.

Đóng dứt điểm: **§08.11 Q2 và §16 Q11 đã có câu trả lời, không phải câu hỏi mở.**
Xoá mô hình ba range statement (padding lên bốn → 6.6 M gas) khỏi §06.4.5, mô
hình ba statement (2.7 M) khỏi §08.4b, và cột `C_fee` khỏi bảng proof size ở
§10.4.7.

`fee_model` cho Zether là **`flat`**, và đó là một **ràng buộc giao thức, không
phải một chính sách v1**. Lý do là hình dạng của proof, không phải khẩu vị:
`fee` nằm trong Fiat-Shamir transcript (§3.4.2), mệnh đề số dư là
`b' = b − fee − v` với `b'` được range-prove, và contract áp nó đồng hình
`C_acc' = C_acc · g^{-fee}`. Verifier **buộc** phải dùng đúng con số `fee` đã
khai, nếu không verification fail. Một khoản phí **đo được sau khi chạy** —
metered hay ad valorem — **không biểu diễn được** trong một khoản trừ bị proof
ràng buộc: nó chưa tồn tại vào lúc ký proof.

Hai hệ quả cứng:

- `bps_of_value` bị **cấm** trên mọi luồng confidential: phí ad valorem cho
  `v = fee / rate` bằng một phép chia, tức nó xoá đúng thứ giao thức tồn tại để
  bảo vệ (§12.6.1).
- `MODE_METERED_FEE` bị **cấm trên target confidential**, ép bằng `require` ở
  contract (§C8.3). Nếu forwarder trả relayer `min(fee, gasUsed × rate)` trong
  khi proof đã trừ `fee` đầy đủ khỏi số dư bảo mật, thì `totalDepositedScaled`
  và tổng số dư confidential **phân kỳ đúng bằng phần chênh, im lặng, ở mọi
  giao dịch metered** — mà bất biến escrow đó chính là cơ chế phát hiện **duy
  nhất** §3.1.3 dựa vào cho một cú vỡ soundness.

### C6.4. Memo AEAD là đường giải mã chính, BSGS là oracle đối chiếu

Memo 32 B mỗi chiều (`memoTo`, `memoFrom`), khoá dẫn xuất từ shared secret
`y_to^s = D_out^{x_to}`, ~1.6 k gas. Giải mã là **1 scalar-mul + HKDF +
ChaCha20 ≈ 60 µs**, O(1). Nó thay BSGS trên happy path và rút recovery 10,000
giao dịch từ giờ xuống **~0.6 s**.

`memoTo`/`memoFrom` **phải vào Fiat-Shamir transcript** (không có ràng buộc ZK,
nhưng nếu không băm thì relayer đổi memo được và grief recovery của người nhận).

Hệ quả bắt buộc lên §07 (yêu cầu chưa section nào nêu):
`ICustodyProvider` nhóm B thêm **`ecdh(point) -> compress(point^x)`**, cùng một
dòng caps-matrix với `zk_mul_by_x`, tức **chỉ khả dụng với
`kind in ('enclave', 'custodial', 'on_device')`**. Với `hsm`, `kms`, `mpc`,
`tee_saas`, `smart_account`: memo decryption **không tồn tại**.

**Đường thay thế của người nhận, viết đúng.** Bản 1 ghi *"recipient công bố
`(v, s)` để đối chiếu với `C_out`"* và đó là một vòng luẩn quẩn: `s` là
randomness transfer **của người gửi**, người nhận không bao giờ biết nó. Chỉ
người gửi công bố được — đó là một đường **sender-disclosure** bị dán nhãn
recipient. Phép kiểm mà người nhận thật sự chạy được, không cần `s`:

```
C_out · g^{-v} == D_out^{x_to}          # mot scalar mul tren D_out
```

Nó chỉ cần **`zk_mul_by_x`**, đúng cái capability mà cùng ba `kind` kia đã gate.
Nên phát biểu trung thực là:

> **Khôi phục Zether cần `zk_mul_by_x` dưới bất kỳ hình thức nào.** Mọi custody
> kind thiếu nó **không dùng được cho một tài khoản giữ số dư Zether** — không
> phải "degrade", mà là không dùng được.

BSGS **không cứu được B2B**: §3.2.5 chỉ chạy nó trên số dư *"khi b < 2^40, hoặc
bỏ qua nếu vượt"*, mà một distributor tier-1 ở 20–80 tỷ ₫/tháng nằm ở 2^44–2^46.
Nếu để nguyên tổ hợp `hsm`/`kms`/`mpc`/`tee_saas`/`smart_account` + Zether thì
memo không có, BSGS bất khả thi, fallback không phải hành động của người nhận —
tức **chủ tài khoản nhìn thấy số dư của chính mình ít hơn auditor nhìn thấy**, và
đối soát vĩnh viễn `partial`. Locked #6 nói mọi custody model đều được hỗ trợ, và
điều đó đúng; nó **không** phải giấy phép để tồn tại một tổ hợp không lấy lại
được tiền của chính nó. Guard lúc deploy nằm ở **§C15.1**; ô tương ứng trong ma
trận caps của §07 đổi từ *degrade* thành **blocking**.

`blockchain.zether.entry.amount_source` ghi lại đường nào đã dùng; khi không
đường nào chạy được, run đối soát báo **`partial`**, không bao giờ `clean`.

Sửa §07.4b: viết lại quanh memo; giữ BSGS làm oracle cross-check. CI gate #19
và #20 đo **memo decryption throughput**; bench BSGS thành non-blocking. SLA
recovery là **dưới một giây**, không phải 3–15 phút.

### C6.5. Auditor ciphertext — chọn dạng shared-`s`, và nó vào struct ngay

Ba đề xuất đang cùng tồn tại. Chốt **§02.7.6: `C_aud = g^v · y_aud^{s}` dùng
chung randomness `s` với `C_out`/`C_debit`, không có `D_aud`.**

Lý do trên mặt kỹ thuật: `D_out = g^s` đã có trên calldata, nên auditor tính
`g^v = C_aud · D_out^{-x_aud}` mà không cần một điểm thứ hai. Đẳng thức với
`C_out` là một Chaum–Pedersen trên **cùng `s`, cùng `v`, khác base** — đúng
hình dạng mà R4 (`C_debit` với base `y_from`) đã có, nên nó là **một base nữa
trong Sigma đang có**, không phải một sub-protocol mới. Tiết kiệm 64 B calldata
và một phương trình verifier so với biến thể `s_a` riêng của §3.4.8.

**Giả định che giấu, gọi đúng tên nó.** Ba ciphertext `g^v · pk^s` không phân
biệt được với người ngoài **dưới XDH — DDH trong G1 của một đường cong
pairing-friendly — không phải DDH trơn.** Sự khác biệt không phải học thuật:
XDH đứng **chỉ khi không có phần tử G2 nào cho khoá đó được công bố**. Ngay khi
có một, pairing quyết định được DDH và toàn bộ tính che giấu biến mất, hồi tố.
Đó chính xác là lý do §C6.1 cấm scheme `BLS` (khoá công khai ở G2) trên tài
khoản giữ số dư Zether, và cả hai chỗ phải được đọc cùng nhau.

```
R9  C_aud = g^v · y_aud^{s}        (cùng v của R3, cùng s của R2)
V8  g^{z_v} · y_aud^{z_s} == A_aud · C_aud^c
```

- Chi phí: **≈ +27,500 gas** = **128 B calldata (2,048 gas)** cho hai điểm
  uncompressed `C_aud` + `A_aud`, cộng 4 `ecMul` (24,000) + 2 `ecAdd` (300),
  cộng 6 × ~200 overhead staticcall (1,200). §02.7.6, §07.10 và §13 đang trích
  **25,300** và con số đó phải đổi.

  Vì sao bản 1 sai, ghi ra vì đây là **dòng duy nhất trong tài liệu đối chiếu
  hai ước tính cạnh tranh** và nó sai đơn vị ngay trong phép đối chiếu: §02.7.6
  viết *"+64 bytes calldata (**1,024 gas**) + 4 ecMul + 2 ecAdd (24,300 gas) ≈
  25,300"*, canon chép **1,024 gas thành 1,024 byte**. Sau khi chép, dấu ngoặc
  không còn cộng ra chính tổng của nó (1,024 B × 16 = 16,384 ⇒ 40,684, không
  phải 25,300). Đồng thời canon **gọi đúng hai điểm** (`C_aud` **và** `A_aud`)
  trong khi giữ con số 64 B của §02, vốn chỉ phủ một. Hai điểm uncompressed là
  128 B = 2,048 gas.
- **Xoá** biến thể R9/V8 với `s_a` và `D_aud` khỏi §3.4.8.
- **Sửa** danh sách validation §3.1.6: validate `C_aud` khi `auditorKey != 0`;
  không có `D_aud` để validate.
- **Thêm** `C_aud` vào struct `ConfidentialTransferData` ở §3.2.5 ngay bây giờ.
  Nó là gate **G2**, phải đóng cùng G1, trước dòng đầu tiên của P10 — struct và
  selector không retrofit được.
- **`memoAud` bị xoá khỏi phạm vi.** Bản 1 giới hạn nó vào
  `token_legal_class = 'loyalty_point'` — đúng cái class §C1.4 vừa đưa ra khỏi
  Zether. Một ERC-20 công khai không có auditor ciphertext và không có memo, nên
  fallback ấy **không còn consumer nào tồn tại**. Xoá nó khỏi §11.12 cùng với
  dòng Z-POINT ở §C6.2: một bề mặt contract ít hơn phải audit. Nếu sau này
  loyalty confidential quay lại trên private chain (§C21 D9), `memoAud` quay lại
  **cùng lúc** và gắn với cùng quyết định `chain_profile` đó, không sớm hơn.
- `auditor_pubkey` **bật từ block đầu tiên** của mọi token có `use_case`
  chạm `b2b` hoặc `payment` — không có cách nào cho auditor thấy giao dịch quá
  khứ. Đổi khoá auditor: **timelock 7 ngày + event công khai**.
- Hệ quả lên §C7: sau §C1.4, luồng còn lại trên Zether là `B2B_PAYOUT` và
  `B2B_INVOICE_PAY`, **cả hai auditor-bắt buộc**. Không luồng nào chạy ở cấu
  hình auditor OFF, nên con số chuẩn tắc là **auditor ON** (§C7.2).

### C6.6. Ràng buộc còn lại của giao thức, giữ nguyên từ §03

Generators là NUMS và phải chứng minh được là NUMS. Transcript phải chứa
`chainId`, `address(this)`, domain tag, `proofSystemId`, `zetherNonce`,
`accSeq`, `memoTo`, `memoFrom`. Điểm trong calldata truyền **uncompressed**
(compressed rẻ 512 gas nhưng tốn 1,349 gas modexp để decompress — đắt hơn
1.8×); lưu trữ off-chain trên Garage dùng compressed. Vector generator dùng
**SSTORE2 data contract** (cấu hình 32/64 cần 8,192 B trên BN254, 16,384 B trên
BLS12-381 — cả hai vừa một contract dưới trần 24,576).

### Ràng buộc mới: transcript phải trói phong bì, nếu không `MODE_RESTRICT_RELAYER` là trang trí

Bản 1 bán `MODE_RESTRICT_RELAYER` + private orderflow như biện pháp giảm thiểu
đua phí relayer. Nó không phải, và lý do là **không có gì trói inner call của
Zether vào phong bì meta-tx**. Transcript §3.4.2 gồm `chainId, address(this)[=
token], domain tag, proofSystemId, y_from, y_to, C_acc, D_acc, C_out, D_out,
C_debit, fee, zetherNonce, accSeq, memoTo, memoFrom` — **không có digest metatx,
không có địa chỉ forwarder**, và `feeRecipient` bị cố tình để ngoài để
`MODE_OPEN` chạy được. `transferConfidential` lại **gọi trực tiếp được**
(§3.4.3 hỗ trợ có chủ ý trường hợp người dùng tự trả gas) và không chỗ nào trong
§03 có `msg.sender == trustedForwarder`.

Nghĩa là inner calldata là một **bearer payload tự xác thực**. Ai thấy một phong
bì `MODE_RESTRICT_RELAYER` trong mempool cũng nhấc được `metaTx.data`, gọi thẳng
token với `feeRecipient = chính mình`, và ăn phí; transfer vẫn lên,
`zetherNonce` vẫn tiến, còn phong bì của relayer được chỉ định thì revert sau khi
đã đốt gas. `MODE_RESTRICT_RELAYER` hạn chế ai gửi **phong bì**, mà phong bì
không phải thứ chuyển tiền. §3.4.4 mô tả bản MODE_OPEN của cuộc đua này và gọi
nó là có chủ ý; nó không nhận ra chế độ restricted bị đi vòng theo đúng cách đó.

**Chốt — `proofSystemId` có hai biến thể, và transcript khác nhau giữa chúng:**

| Biến thể | Transcript thêm | Contract require |
|---|---|---|
| `ZTX_V1_DIRECT` | — | `msg.sender != trustedForwarder` |
| `ZTX_V1_RELAYED` | **`digest_hash`** (EIP-712 digest của `MetaTransaction`) | `msg.sender == trustedForwarder` |

Forwarder ghi `digest_hash` vào **transient storage** (`TSTORE`, ~100 gas) ngay
trước inner call; token đọc bằng `TLOAD` (~100 gas) và nạp vào Fiat-Shamir. Tổng
~200 gas. Transient storage đã là điều kiện sẵn có: §C17.2 ép `cancunTime: 0` và
§C8.5 đã dựa vào `ReentrancyGuardTransient`.

Điều này đồng thời giải xong câu hỏi `feeRecipient`, **không cần một nhánh theo
profile**: `digest_hash` được `_canon()` (§C8.2) tính trên đúng những trường mà
`mode` nói là ràng buộc. Dưới `MODE_RESTRICT_FEE_RECIPIENT`, `feeRecipient` nằm
trong digest ⇒ nằm trong transcript ⇒ **không nhấc được**. Dưới `MODE_OPEN` nó
bị zero hoá trong digest ⇒ cuộc đua mở vẫn chạy đúng như thiết kế Open Relayer.
Một cơ chế, cả hai profile, không có runtime branch. Bản 1 trả giá "relayer thua
cuộc đua vẫn mất gas" cho **mọi** luồng, kể cả những luồng §C16 cấm `MODE_OPEN`;
sau thay đổi này, `p = 0` cho profile restricted và §05.3.3 dẫn lại
`margin' = (1 + margin)/(1 − p) − 1` với `p = 0`, tức sàn phí giảm đúng phần đó.

Đây là **gate G2**, chốt cùng G1, **trước dòng đầu tiên của P10**: nó đổi
transcript, tức đổi `proofSystemId`, tức không retrofit được.

Cho tới khi biến thể `ZTX_V1_RELAYED` tồn tại, §C6.6 phải nói thẳng: **private
orderflow là biện pháp giảm thiểu DUY NHẤT, và `MODE_RESTRICT_RELAYER` không
đóng góp gì trên target Zether** — nên mặc định của §13/§C16 bắt buộc nó cũng
không mua được gì trên đường Zether (nó vẫn mua thứ khác: khấu trừ thuế nhà
thầu, §C16).

---

## C7. Gas — một con số cho mỗi thao tác

Sáu con số đang tồn tại cho `transferConfidential`. Đây là con số duy nhất, và
đây là cách nó được dẫn ra.

### C7.1. Tham số đã chốt để dẫn số

| Tham số | Giá trị | Nguồn |
|---|---|---|
| Cấu hình | `n_v = 32`, `n_b = 64` **cho mọi token đã ship**, hai proof, một transcript chung | §C6.2 |
| Số range statement | **2** | §C6.3 |
| Phí | public scalar, ERC-20 trực tiếp, **không** `C_fee`, **không** range proof cho phí | §C6.3 |
| **Curve của phép dẫn dưới đây** | **BN254 G1** — và **chỉ** BN254 G1 | §C6.1 |
| Giá mỗi điểm MSM | `6,000` (`ecMul`, EIP-1108) + `150` (`ecAdd`) + `~400` (staticcall + memory) = **6,550** | §3.3.3 |
| Điểm trong calldata | uncompressed, 64 B | §3.3.4 |
| Auditor ciphertext | **bật** (`C_aud`, shared `s`) — mọi luồng còn lại trên Zether là B2B, và B2B auditor-bắt buộc | §C6.5 |

**§C7.2 và §C7.3 chỉ có hiệu lực cho một curve có precompile EVM native cho
phép toán của nó.** Chúng **không** áp cho Baby Jubjub, vốn không có precompile
nào ở bất kỳ giá nào (§C6.1). Bản 1 viết dòng curve là *"BN254 G1 hoặc Baby
Jubjub — cùng chi phí precompile bậc nhất"* trong khi seed `babyjubjub` làm mặc
định; hai nửa của tài liệu khi đó mô tả **hai sản phẩm khác nhau**, một cái
1.9 M gas và một cái 7 M.

#### Vì sao không Pippenger trên BN254 — lý do đúng, vì nó là lý do có tải trọng

Bản 1 viết *"MSM precompile không tồn tại ⇒ không Pippenger, không windowing…
đây là ràng buộc kiến trúc của EVM"*. **Kết luận đúng, lý do sai.** Pippenger
chỉ cần phép **cộng nhóm** — viết trọn bằng `ecAdd` được, việc thiếu một
precompile batching không cấm nó. Cái chặn thật là **tỷ giá**: `ecAdd` 150 so
với `ecMul` 6,000, tỷ lệ 40, trong khi Pippenger 254 bit tốn hơn 100 phép cộng
cho mỗi cặp (điểm, scalar). Chạy số trên 230 điểm:

| `c` (window) | Số cộng | Ở 150 gas | Ở 550 gas (kèm overhead staticcall) |
|---|---|---|---|
| 8 | 32 × (230 + 510) = 23,680 | 3.55 M | 13.0 M |
| **5 (tối ưu)** | 51 × (230 + 62) = 14,892 | **2.23 M** | **8.19 M** |
| 4 | 64 × (230 + 30) = 16,640 | 2.50 M | 9.15 M |

So với **230 × 6,550 = 1.51 M** của cách ngây thơ. Naive thắng vì precompile
định giá một scalar mult **thấp hơn nhiều** số phép toán thật của nó — một
`ecMul` 6,000 gas làm công việc của ~380 `ecAdd`, mà 380 `ecAdd` qua staticcall
tốn 209,000.

Ghi lý do đúng ra là bắt buộc, vì nó viết ra **điều kiện làm kết luận lật**:

> Bất kỳ curve nào định giá MSM **theo lô** thay vì **theo điểm** đều đảo ngược
> kết luận này.

Chính vì bản 1 phát biểu rào cản là "không có precompile batching" mà §C7.1 gọi
tên `BLS12_G1MSM` trong cùng một câu rồi đi qua nó. Dòng BLS12-381 dưới đây tồn
tại vì câu trên.

### C7.2. Dẫn số cho `transferConfidential`

**Đọc bảng này với một phân biệt mà bản 1 không có: *thi hành inner* và *toàn
giao dịch* là hai con số khác nhau.** `21,000` intrinsic và phí calldata là phí
**cấp giao dịch**; một inner CALL **không trả cái nào**. Bản 1 gộp cả hai vào
một tổng rồi dùng tổng đó vừa để dẫn `innerGasLimit` (thừa, vô hại) vừa để dẫn
`requiredOuterGas` (thiếu, và thiếu đúng chỗ nguy hiểm).

**(A) BN254 G1 — 32/64, auditor ON. Đây là con số chuẩn tắc.**

```
Kích thước MSM = 2n + 2·log2(n) + 7 điểm cho mỗi statement
  BP over v,  n = 32 :  64 + 10 + 7  =  81 điểm
  BP over b', n = 64 : 128 + 12 + 7  = 147 điểm
                                      ---------
                                       228 điểm  (làm tròn 230)

--- THI HANH (mot inner CALL tra dung phan nay) -----------------
Bulletproofs   230 × 6,550                               = 1,506,500
Sigma          ~25 ecMul + ~20 ecAdd + validation        =   171,000
Auditor        4 ecMul + 2 ecAdd + 6 staticcall          =    25,500
Storage        sender acc 4 slot + receiver pending 4 slot
               + zetherNonce + accSeq (nonzero→nonzero)  =    70,000
Fee ERC-20     safeTransfer warm                          =    30,000
Event + generator extcodecopy + registry SLOAD            =    24,000
Transcript digest_hash TLOAD (ZTX_V1_RELAYED, §C6.6)      =       200
                                                            ---------
  inner execution                                           1,827,200
--- CAP GIAO DICH (chi tra khi goi TRUC TIEP) --------------------
Base tx intrinsic                                         =    21,000
Calldata       3,456 B × 16                               =    55,296
Auditor calldata 128 B × 16                               =     2,048
                                                            ---------
  full transaction, goi truc tiep                           1,905,544
```

| Con số | Giá trị | Dùng ở đâu |
|---|---|---|
| **`transferConfidential`, thi hành inner, auditor ON** | **1,827,000** | dẫn `innerGasLimit` (§C7.4) |
| **`transferConfidential`, full-tx gọi trực tiếp, auditor ON** | **1,905,000** | **con số chuẩn tắc mọi section trích dẫn** |
| `transferConfidential`, auditor OFF | 1,880,000 | **chỉ là một sub-case, không luồng nào đã ship dùng nó** (§C6.5) |
| người nhận **lần đầu** (pending 4 slot zero→nonzero) | +45,000 | inner **và** full-tx; phải hiện trên UI |
| **Band** | **1.43 M – 2.38 M** | ±25% quanh 1.905 M, cơ sở là ước tính bottom-up §3.3.6, **không** phải đo |
| Envelope EIP-1776 (lane warm, chữ ký EOA) | +25,000 | §C8.5 |
| Envelope, lane dùng lần đầu (SSTORE zero→nonzero) | +42,000 | |
| Envelope với EIP-1271 qua precompile RIP-7212 | +9,000 nữa | |
| Calldata của **giao dịch ngoài** (struct 14 field + chữ ký + `data` 3,584 B + khung ABI ≈ **4,300 B**) | +68,800 | §C7.4 |
| **Gas một block Gnosis thật sự tiêu cho một transfer relay** | **1,940,000** | `21,000 + 68,800 + 25,000 + 1,827,000` — dùng cho block space và chi phí |

Cấu hình **128/128 = 3.87 M** chỉ tồn tại như cấu hình **đã bị loại**; không
trích dẫn nó ở bất kỳ đâu như một phương án.

**(B) BN254 G1 — 40 (→pad 64) / 64. Cấu hình đã bị loại ở §C6.2, giữ ở đây để
quyết định có thể kiểm lại được.**

MSM 147 + 147 = 294 (làm tròn 296) ⇒ Bulletproofs 296 × 6,550 = 1,938,800;
calldata 3,584 B (BP#1 thêm 2 điểm L/R) ⇒ full-tx auditor ON ≈ **2,340,000**,
inner ≈ **2,261,000**, đỉnh band **2.93 M**, `requiredOuterGas` ≈ **3.33 M**
(19.6% một block Gnosis). Phá kill criterion S1, `maxInnerGas` và
`max_gas_per_tx` **cùng lúc**. Đó là lý do §C6.2 chọn chia nhỏ.

**(C) BLS12-381 với `BLS12_G1MSM` (`0x0c`, EIP-2537) — dòng bản 1 chưa bao giờ
tính, và nó rẻ hơn dòng đã chọn.**

Bản 1 định giá BLS12-381 ở *"≈2.05× gas"* từ tỷ lệ mỗi-thao-tác k=1
(12,000/6,000, 375/150) — tức nó **gọi tên đúng cái precompile giải bài toán chi
phí trung tâm của mình rồi định giá nó như một scalar mult theo điểm**.
`BLS12_G1MSM` tính `k × 12,000 × discount[k] / 1000`, và discount **bão hoà ở
174 với k ≥ 128**. Toàn bộ verifier Bulletproof là **một MSM 230 điểm** — đúng
hình dạng mà bảng discount tồn tại để phục vụ.

```
--- THI HANH -----------------------------------------------------
BP MSM      mot staticcall 0x0c, k=230:
            230 × 12,000 × 174/1000                      =   480,240
Memory      input 230 × (128 B diem + 32 B scalar) = 36,800 B
            ⇒ 1,150 word: 3×1150 + 1150²/512            =     6,033
Sigma       25 G1MUL + 20 G1ADD, KHONG batch              =   307,500
            (neu gop Sigma vao mot G1MSM k≈25, discount ≈480: 151,500)
Validation  subgroup check nam TRONG precompile           =         0
Storage                                                    =    70,000
Fee ERC-20                                                 =    30,000
Event + extcodecopy 16,384 B generator + SLOAD             =    26,000
                                                             ---------
  inner, Sigma khong batch                                    919,773
  inner, Sigma batch                                          763,773
--- CAP GIAO DICH ------------------------------------------------
Base tx intrinsic                                          =    21,000
Calldata    3,456 B + ~30 diem proof × 64 B them = 5,376 B  =    86,016
                                                             ---------
  full-tx, Sigma khong batch  ≈ 1,027,000   →  lam tron  1,050,000
  full-tx, Sigma batch        ≈   871,000
  full-tx, gop TAT CA vao mot MSM k≈255      ≈   770,000
```

Con số bản 1 lệch khoảng **6 lần theo đúng chiều quyết định curve**. Vector
`g_i`/`h_i` **không** vào calldata — chúng từ SSTORE2 data contract vào memory,
nên chúng tốn ~6 k memory expansion chứ không phải 590 k calldata; chỉ ~30 điểm
proof lớn lên 128 B (+~31 k). Cộng vào đó là **117–126 bit** bảo mật thay cho
~100 (§C6.1).

**Hệ quả: gate G1 phải mở lại, và nó đã bị đóng trên một lỗi số học.** Canon
**không** tự chốt BLS12-381 ở đây — nó cần preflight `0x0c` của §C6.1 và nó khoá
prover Rust. Nhưng canon ghi ra rằng con số thận trọng nhất của BLS12-381
(1.05 M) đã **thấp hơn** con số đã chọn (1.905 M) **45%**, và bản batch đầy đủ
thấp hơn 60%. §C21 D1.

### C7.3. Các thao tác còn lại, dẫn cùng công thức (BN254, auditor ON)

| Thao tác | Điểm MSM | Thi hành inner | Full-tx | Band ±25% (full-tx) | Ghi chú |
|---|---|---|---|---|---|
| `transferConfidential` | 230 | **1,827,000** | **1,905,000** | 1.43 – 2.38 M | con số chuẩn tắc |
| `withdraw` | 147 (chỉ `b' ∈ [0,2^64)`; `v` công khai) | 1,178,000 | **1,240,000** | 0.93 – 1.55 M | + ERC-20 transfer ra ngoài |
| `deposit` | 0 | 62,000 | **85,000** | — | 170,000 nếu `pending` lần đầu |
| `register` (PoP Schnorr) | 0 | ~72,000 | **~95,000** | — | một lần cho mỗi (account, token registry) |
| Meta-tx ERC-20 thường qua forwarder | 0 | ~105,000 | **~130,000** | — | §04.6.8 |

#### `rollOver` — ba con số, không một

Con số **49,000** của bản 1 (28 k thi hành + 21 k intrinsic) sai ở **cả hai**
thành phần, và §15 dựng cost model batch thẳng trên nó.

*Thi hành sai.* 28 k đến từ §3.5.4 *"2 ecMul + 1 ecAdd + keccak + 5 SSTORE ≈ 13k
+ 15k"*. Bảng slot của §C5.2 nói **10 slot bị ghi**, không phải 5, và 5 × 2,900
còn giả định mọi slot đều warm nonzero→nonzero. Dẫn lại từ danh sách slot:

```
SSTORE   acc 4 slot (2,900)          = 11,600      | lan dau: 4 × 22,100 = 88,400
         pending 4 slot ve 0 (2,900) = 11,600      | 11,600
         accSeq                      =  2,900      | 22,100 (0→1)
         pendingSeq                  =  2,900      |  2,900
SLOAD    10 slot cold × 2,100        = 21,000      | 21,000
Crypto   Schnorr 2 ecMul + 1 ecAdd   = 12,150      | 12,150
         acc' = acc·pending: 2 ecAdd =    300      |    300
Event + keccak + validUntilBlock     =  ~3,550     | ~3,550
                                       --------      --------
  thi hanh                              66,000       161,400
```

Hoàn tiền khi zero hoá 4 slot `pending` (tới 19,200, trần `gasUsed/5`) hạ **chi
phí thực trả** xuống, nhưng **không** hạ gas limit phải đặt. Dùng số **gross**
để định cỡ limit, số **net** để báo giá.

*Intrinsic sai theo hai chiều ngược nhau.* Một con số không đúng cho cả ba ngữ
cảnh §C5.2 bắt buộc:

| Ngữ cảnh | Gas | Cách dẫn |
|---|---|---|
| **standalone, trạng thái ổn định** | **91,000** gross / ~73,000 net | 21,000 intrinsic + 4,160 calldata + 66,000 |
| **standalone, lần rollOver ĐẦU TIÊN của một tài khoản** | **~186,000** gross | 21,000 + 4,160 + 161,400 |
| **batch (`rollOverBatch`), mỗi phần tử** | **~70,000** + 21,000/N | không intrinsic riêng; 66,000 + ~3,680 calldata phần tử |
| **relay trong `metaTx.data`, một cái một phong bì** | **~117,000** | không intrinsic riêng; 66,000 + envelope 25,000 + 21,000 intrinsic ngoài + ~4,800 calldata ngoài |
| biến thể B (controller), standalone ổn định | ~80,000 | chỉ profile custodial; bỏ 2 ecMul Schnorr |

**§15 dùng `+70,000/tài khoản nhận` trong cost model batch**, và **`+186,000`
cho mỗi tài khoản nhận lần đầu**. S1 phải đo cả hai — chênh lệch 2× giữa lần đầu
và trạng thái ổn định là một sự thật về UI và về chi phí, không phải nhiễu.

### C7.4. Hằng số cấu hình dẫn ra từ bảng trên

> **[BẢN 4 — ba hằng số đầu bảng đã chết, và cái thay chúng là SỐ ĐO, không phải
> phép dẫn.]** `innerGasLimit`, `maxInnerGas`, `requiredOuterGas` cùng chết với inner
> `CALL` (`_USER-DECISIONS.md` §24). Phong bì bây giờ **đo được**, vì đã có contract để
> đo: `smartcontracts/src/metatx/ERC20MetaTx.sol` + `test/MetaTxGas.t.sol`, và một bản
> deploy thật trên chain 9000. Số ở **§C7.6**.
>
> Cái còn lại của bảng này — throughput, chi phí tiền mặt, `max_gas_per_tx` — vẫn dẫn
> từ §C7.2 và vẫn đúng, vì chúng nói về chi phí *thi hành Zether*, không về phong bì.
>
> Quy tắc thay cho `requiredOuterGas`: **relayer chọn `tx.gasLimit` từ bảng tĩnh theo
> selector** (§04.10), không từ một trường người dùng ký. Công thức mới, không có 63/64
> và không có `FLOOR_GAS`:
>
> ```
> tx_gas_limit = 21,000 + calldata_gas + envelope + op_gas   (rồi × 1.15 biên)
> ```
>
> `envelope` lấy từ §C7.6; `op_gas` từ §C7.2/§C7.3.

Dẫn từ cấu hình **lớn nhất đã ship** (32/64, auditor ON, người nhận lần đầu), và
mỗi hằng số dẫn từ **đúng một** trong hai con số của §C7.2.

| Hằng số | Giá trị | Cách dẫn |
|---|---|---|
| ~~`innerGasLimit`~~ | ~~2,600,000~~ | **chết** — không còn inner call, không còn trường đã ký |
| ~~`targets[ZetherToken].maxInnerGas`~~ | ~~2,800,000~~ | **chết** cùng lý do |
| ~~**`requiredOuterGas`**~~ | ~~≈ 2,820,000~~ | **chết** — thay bằng công thức ở khối trên |
| **Relayer đặt tx gas limit** | **2,900,000** | vẫn là con số đúng cho `transferConfidential`, nhưng dẫn lại: `(21,000 + 68,800 + 15,160 + 1,872,000) × 1.15 = 2,272,000`; giữ 2,900,000 vì §04.10 chốt trần 3,2 M và biên rộng ở đây rẻ hơn một lần OOG |
| `blockchain.chain.max_gas_per_tx` (Gnosis) | **3,000,000** | phải `>=` gas limit của relayer. §06.4.5's 3,500,000 là một trần đặt lên **inner**, tức nó **thấp hơn** outer requirement và sẽ từ chối mọi meta-tx Zether của chính pool |
| Trần throughput Gnosis, 20% block space | **~30,000 tx/ngày toàn mạng** | 17 M gas/block ÷ 5 s = 3.40 M gas/s; 20% = 680 k gas/s; ÷ **1.94 M** = 0.350 tx/s |
| Chi phí tiền mặt Gnosis | **$0.002 – $0.006/tx** | 1.94 M × 1–3 gwei, xDAI = $1 |

```
# [BẢN 4] Công thức cũ, giữ lại để đối chiếu — hai dòng giữa không còn đối tượng:
#   requiredOuterGas = 21,000 + calldata×16 + 25,000
#                    + innerGasLimit × 64/63     <- CHẾT: không còn inner call
#                    + FLOOR_GAS 60,000          <- CHẾT: không còn frame ngoài để cứu
#
# Công thức đang dùng:
tx_gas_limit = 21,000                    # intrinsic cua GIAO DICH NGOAI
             + calldata_gas              # phu thuoc payload, xem §C7.6 dong I
             + envelope                  # 15,160 warm / 32,260 batch moi  <- DO, §C7.6
             + op_gas                    # 1,872,000 cho transferConfidential (§C7.2)
             ; roi × 1.15 va lam tron len 10 k

max_gas_per_tx >= tx_gas_limit
```

Bản 1 dẫn `requiredOuterGas ≈ 2,730,000` **bỏ mất intrinsic 21,000 và toàn bộ
calldata của giao dịch ngoài**, rồi đặt gas limit của relayer ở 2,800,000 — tức
**con số relayer gõ vào trường `gas` thấp hơn con số chính canon đã dẫn**, và
`max_gas_per_tx` 3.0 M còn dưới 7% biên so với một hình mà canon dán nhãn ±25%.
Đó là một revert ở đỉnh band trên **mọi** meta-tx Zether, phát hiện ra bằng
production.

**Không hằng số nào ở trên được xuất hiện dưới dạng literal trong code.**
Chúng nằm trong `blockchain.chain` / `blockchain.token` và được seed từ bảng
này. Sau khi **spike S1** đo `gasUsed` thật, giá trị đo **back-fill cả bốn**
(`innerGasLimit`, `maxInnerGas`, `max_gas_per_tx`, gas limit của relayer) trong
**một commit**, và `requiredOuterGas` được **tính lại từ công thức**, không
back-fill như một literal.

**Kill criterion S1: đo được `gasUsed` của TOÀN BỘ giao dịch relay > 2.5 M ⇒
giết Zether trên public chain.** Nói rõ đo trên hình nào, vì bản 1 không nói:
hình đó là **1,940,000** ở cấu hình 32/64 auditor ON, đỉnh band **2.43 M**. 2.5 M
nằm ngay trên đỉnh band, nên đó là một gate thật, có thể fail thật. Ở cấu hình
40(→64)/64 đã bị loại, chính hình đó là 2.93 M — tức criterion sẽ fail trước khi
spike chạy, và đó là một trong hai lý do §C6.2 loại nó.

Thêm ngưỡng wall-time: > 40 ms/proof trên validator ⇒ giết
private-với-Solidity-verifier và biến S8 (native precompile) từ tuỳ chọn thành
bắt buộc.

### C7.5. Nơi phải xoá bảng gas tự dẫn

| Section | Con số sai | Thay bằng |
|---|---|---|
| §04.10 | 1.72–2.62 M; `innerGasLimit = 3,000,000`; `maxInnerGas = 3,200,000`; `requiredOuterGas ≈ 3,178,000` | bảng C7.4. **[BẢN 4]** ba hằng số sau đã chết; dòng "chuyển token công khai ~50.000–90.000" của §04.10 thì **đúng** và nay có số đo: 58.702–75.802 (§C7.6) |
| §05.3.1 | 342 k – 422 k | xoá dòng, trích C7.2 |
| §06.4.5 | 3.5 M (n=64) / 6.6 M (n=128), ba range statement | xoá cả bảng, trích C7.2 |
| §08.4b, §08.9b | 2.7 M (3 × 64-bit) | xoá cả bảng, trích C7.2 |
| §10.4.7 | 1.2 – 2.5 M, giả định Pippenger batching | xoá; Pippenger **thua** naive trên BN254 vì tỷ giá `ecAdd`/`ecMul`, không phải vì thiếu precompile (§C7.1) |
| §15.7 | mọi con số dẫn lại, kể cả `rollOver` 49 k | trích C7.2 và C7.3: **`rollOver` +70 k/tài khoản nhận khi batch, +186 k cho tài khoản lần đầu** |
| **§12, §09, §14, §16** | **1.88 M** | **SAI — đổi thành `1,905,000`.** 1.88 M là hình auditor **OFF**, mà sau §C1.4 mọi luồng còn lại trên Zether đều auditor-**bắt buộc** (§C6.5), tức **không luồng nào đã ship chạy ở 1.88 M**. Bản 1 bảo bốn section này *giữ* 1.88 M và chỉ đổi thành trích dẫn — tức lan con số auditor-OFF vào threat model, payment mode, ngưỡng CI và roadmap. Dùng **1,905,000** (full-tx trực tiếp) hoặc **1,940,000** (gas một block tiêu cho một transfer relay), tuỳ hình mà section đó cần |


### C7.6. Phong bì meta-transaction — **ĐO, không dẫn** (2026-08-31)

Mọi con số phong bì ở §C7.2 và §C7.4 trước đây là phép tính tay. Chúng bây giờ đo được,
vì đã có contract để đo. Hai nguồn, và chúng khớp nhau:

- `smartcontracts/test/MetaTxGas.t.sol` — `forge test`, `evm_version = prague`. Đo **chi
  phí thi hành**.
- Deploy thật lên **chain 9000** (Nethermind 1.39.0, Fusaka+BPO2), `gasUsed` lấy từ
  receipt. Đo **toàn giao dịch**.

Contract đo là `src/metatx/ERC20MetaTx.sol`: bản cài đặt tham chiếu đúng thứ tự chín bước
của §04.6.1, thao tác mặc định là chuyển ERC-20 công khai.

| # | Hình | forge (thi hành) | chain 9000 (`gasUsed` toàn tx) |
|---|---|---|---|
| A | batch **ấm**, `MODE_OPEN`, không phí | **35.241** | **58.702** |
| B | batch **mới** (nonce slot 0→1), không phí | **52.341** | **75.802** |
| C | batch ấm, phí **FIXED** | **43.565** | **67.362** |
| D | batch ấm, phí **PERCENT** | **43.511** | **67.260** |
| E | batch ấm, FIXED + ràng buộc relayer + feeRecipient | **43.763** | **67.560** |
| F | batch ấm, người nhận **chưa từng giữ token** | **52.341** | — |
| G | batch mới, chữ ký **ERC-1271** (verifier tầm thường) | **54.530** | — |
| H | `cancelMetaNonce` (batch mới) | **27.579** | — |
| J | **đường cơ sở**: `transfer` thường, cùng độ ấm | **20.081** | — |
| I | calldata của giao dịch ngoài | 580 B → 4.180 gas (425 byte 0 / 155 byte khác 0) | |

**Phong bì = A − J**, không phải A. Đo A rồi gọi nó là phong bì là cộng cả chi phí của
thao tác vào phong bì — chính là lỗi §C7.2 mắc khi trộn "thi hành inner" với "toàn giao
dịch".

| Đại lượng | Canon bản cũ | **Đo được** | Sai bao nhiêu |
|---|---|---|---|
| Phong bì, lane ấm, chữ ký EOA | +25.000 | **+15.160** | thừa 65% |
| Phong bì, batch dùng lần đầu | +42.000 | **+32.260** | thừa 30% |
| Thêm cho ERC-1271 | +9.000 | **+2.189** | thừa 4,1× |
| Thêm cho một lần thu phí | (không có dòng) | **+8.324** | thiếu hẳn |
| PERCENT so với FIXED | (không có dòng) | **−54** | — |
| Ràng buộc relayer + feeRecipient | (không có dòng) | **+198** | — |

Bốn điều đọc ra từ bảng, mỗi cái đổi một quyết định:

1. **Phong bì rẻ hơn canon tưởng, và điều đó làm yếu một lập luận của chính canon.** 15.160
   trên nền một `transfer` 20.081 nghĩa là gasless **tăng gấp 1,76 lần** chi phí của một
   chuyển token thường. Với Zether 1,87 M thì phong bì là nhiễu (0,8%); với chuyển token
   công khai thì nó là **thứ đắt nhất trong giao dịch**. Bảng phí sàn của §05.3 phải chia
   theo thao tác, không một con số cho mọi thao tác.
2. **Thu phí đắt hơn cả phần còn lại của phong bì trừ chữ ký** (+8.324 cho một `_transfer`
   thứ hai). `MODE_FEE_NONE` không phải một trường hợp biên cần chiều — nó là **cấu hình rẻ
   nhất một khoảng lớn**, và sponsor trả gas ngoài băng nên chọn nó.
3. **`mode` gần như miễn phí** (+198 cho hai ràng buộc, −54 giữa hai nhánh tính phí). Lập
   luận "gộp `feeMode` vào `mode` để tiết kiệm gas" **không** phải lý do đúng để gộp — lý
   do đúng là một trường ít hơn trong digest và trong SDK. Nếu ai đó dẫn con số gas để biện
   hộ cho quyết định đó, đây là bằng chứng phản lại.
4. **ERC-1271 rẻ hơn canon tưởng 4 lần**, nhưng con số +2.189 là của một verifier **tầm
   thường** — nó đo *đường đi* (staticcall + returndata), không đo ví thật. Một Safe hay một
   passkey wallet cộng phần của nó lên trên. Dùng 2.189 làm sàn, không làm ước tính.

#### Hai lỗi đo mắc phải trong chính lần đo này, ghi lại vì chúng vô hình

Cả hai đều cho ra một con số **trông hợp lý** và **sai**:

1. **Đo năm kịch bản nối tiếp trong một hàm test.** Forge chạy trọn một hàm test trong một
   frame, nên access list của EIP-2929 **không** reset giữa các lời gọi. Lời gọi thứ hai
   trở đi thấy slot đã dirty và trả 100 gas thay vì 5.000 cho cùng một SSTORE. Kết quả: phí
   FIXED rẻ hơn PERCENT **4.744 gas** — một khác biệt không tồn tại, nó chỉ là thứ tự. Đảo
   thứ tự hai kịch bản thì con số đi theo vị trí chứ không theo mode; đó là cách phát hiện.
   Sửa: **một kịch bản một hàm test.**
2. **Tạo smart account của phép đo ERC-1271 bên trong hàm test.** Địa chỉ vừa tạo là warm và
   slot số dư vừa mint là dirty, nên ERC-1271 đo ra **rẻ hơn ECDSA 9.611 gas**. Sửa: tạo và
   cấp vốn trong `setUp`, và con số lật dấu thành +2.189.

Quy tắc rút ra: **một phép đo gas mà thứ tự chạy đổi được kết quả thì nó đang đo access
list, không đo code.**

#### Cái vẫn CHƯA đo, và đừng giả vờ là đã đo

§C7.2 dòng Bulletproofs (230 điểm × 6.550) và toàn bộ §C7.3 **vẫn là phép dẫn**. Không có
verifier Zether nào được viết, nên không có gì để đo. Cái đã đo được của phần đó là **giá
precompile**, trên chính chain 9000: `ecMul` **6.342** gas (EIP-1108 đang bật, không phải
40.813 của EIP-196 gốc). Giá đó xác nhận hằng số 6.550/điểm là hợp lý (6.342 + `ecAdd`
150 chia đều), nhưng số điểm và số sigma vẫn là ước tính bottom-up. Band ±25% giữ nguyên,
và **spike S1 vẫn phải chạy**.

---

## C8. EIP-1776

> **[BẢN 3 — `_USER-DECISIONS.md` §24 GHI ĐÈ toàn bộ mục C8, C7.4 và C7.5.]**
>
> Quyết định của user: **không có forwarder**, và lý do là triết lý chứ không phải kỹ thuật —
> *"những contract mà không support gasless là sai triết lý; nếu đã lỡ phát hành thì wrap sang
> MetaTx."* Mọi token tự hiện thực meta-transaction (native mixin), nên `verifyingContract`
> **luôn là chính token contract** và không tồn tại lời gọi `CALL` tới contract lạ.
>
> Nguồn chuẩn tắc của struct bây giờ là **code**: `smartcontracts/src/common/MetaTxLib.sol`,
> ghim bởi `test_metaTxTypehashIsPinned`. Bảng dưới đây nói cái gì trong C8/C7 còn hiệu lực.
>
> | Mục canon | Trạng thái |
> |---|---|
> | C8.1 struct | **Thay** — bỏ `tokenContract`, `feeToken`, `innerGasLimit`; đổi `amount`→`value`, `expiry`→`validUntil`, `batchId`/`batchNonce`→`batch`/`nonce` |
> | C8.2 bảng `mode` | **Thay** — còn 2 cờ (`0x01`, `0x02`) ở nửa byte đầu, cộng **nửa byte sau** cho cách tính phí. `MODE_KNOWN_MASK = 0xF3` |
> | C8.3 ngữ nghĩa thất bại | **Thay** — không còn bubble-vs-swallow. Kiểm đủ **trước** khi thu phí ⇒ *"phí đã thu ⟺ thao tác đã xảy ra"*. `_CRITIQUES.md` contradiction-2 đóng vì hết đối tượng |
> | C8.4 expiry | **Giữ nguyên** — đổi tên trường thành `validUntil`, ngữ nghĩa không đổi |
> | C8.5 63/64, return-bomb, allowance | **Chết** — cả ba chặn hệ quả của `CALL` tới contract lạ |
> | C7.4 `innerGasLimit`/`maxInnerGas`/`requiredOuterGas` | **Chết** — thay bằng bảng gas tĩnh phía relayer (§04.10) |
> | C7.1–C7.3 dẫn số gas Zether | **Giữ nguyên** — chúng nói về chi phí *thi hành*, không về phong bì. **Và đã kiểm trên chain 9000: `ecMul` = 6.342 gas, đúng giá EIP-1108** |
>
> Struct chuẩn tắc:
>
> ```solidity
> struct MetaTransaction {
>     address from; address to; uint256 value; bytes data;
>     uint256 batch; uint256 nonce; uint256 validUntil;
>     uint32  mode; address relayer;
>     uint256 fee; address feeRecipient;
> }
> ```
>
> Bảng `mode` chuẩn tắc — **hai nửa byte, hai bản chất khác nhau**:
>
> | Bit | Hằng | Nghĩa |
> |---|---|---|
> | 0 | `MODE_RESTRICT_RELAYER = 0x01` | **cờ** — ràng buộc `relayer` |
> | 1 | `MODE_RESTRICT_FEE_RECIPIENT = 0x02` | **cờ** — ràng buộc `feeRecipient` |
> | 4–7 | `MODE_FEE_NONE 0x00` / `PERCENT 0x10` / `FIXED 0x20` | **giá trị liệt kê** — cách tính phí |
> | | `MODE_FLAGS_MASK = 0x0F`, `MODE_FEE_MASK = 0xF0`, `MODE_KNOWN_MASK = 0xF3` | |
>
> Nửa đầu đọc bằng `mode & FLAG`; nửa sau bằng mask + shift. `if (mode & MODE_FEE_PERCENT)` là
> **bug**: `MODE_FEE_FIXED = 0x20` không chứa bit `0x10`, nhưng một giá trị tương lai `0x30` thì
> có. Và `validateMode` phải kiểm **hai** thứ — bit lạ ở nửa đầu, **và** giá trị > 2 ở nửa sau;
> `0x30` là bit hợp lệ nhưng giá trị vô nghĩa, bỏ qua nó hôm nay là khoá chết ngữ nghĩa của nó
> ngày mai bằng những chữ ký đã phát hành.
>
> Ba bit đã chết: `MODE_REQUIRE_SUCCESS 0x04` (không còn inner call), `MODE_METERED_FEE 0x08`
> (thay bằng nửa byte phí), `MODE_APPEND_SENDER 0x10` (không có target). Tranh chấp cấp bit giữa
> §04.4 / §05.3.3 / §5.12 — mà C8.2 từng phải phân xử — **đóng theo**.
>
> **Đính chính một khẳng định của bản trước:** có chỗ nói bitmask tạo *cross-mode replay*. **Sai.**
> Canonical zeroing với `mode` **trong** hash cho `(OPEN)` và `(RESTRICT, relayer=0)` hai digest
> khác nhau — không va chạm. Lý do bỏ bitmask là dư thừa, trạng thái mâu thuẫn biểu diễn được,
> quy tắc canonical phải khớp ba nơi, và bit đã va chạm thật giữa các section. Xem §04.4.


### C8.1. Struct — chuẩn tắc

```solidity
struct MetaTransaction {
    address from; address to; address tokenContract; address feeToken;
    uint256 amount; bytes data;
    uint256 batchId; uint256 batchNonce;
    uint256 fee; uint256 innerGasLimit; uint256 expiry;
    uint32  mode; address relayer; address feeRecipient;
}
```

**Không có `targetEpoch`** (§C5). `mode` là `uint32`, không `uint8` (chi phí 0
gas — ABI pad cả hai về 32 byte; `uint8` chỉ còn 3 bit trống cho cả vòng đời
contract). `feeToken == address(0)` nghĩa là dùng `tokenContract`.

### C8.2. Bảng `mode` — bảng duy nhất trong toàn bộ tài liệu

| Bit | Hằng | Nghĩa |
|---|---|---|
| — | `MODE_OPEN = 0x0000_0000` | không bit nào; bất kỳ ai relay |
| `0x01` | `MODE_RESTRICT_RELAYER` | `relayer` vào digest |
| `0x02` | `MODE_RESTRICT_FEE_RECIPIENT` | `feeRecipient` vào digest |
| `0x04` | `MODE_REQUIRE_SUCCESS` | bubble revert (§C8.3) |
| `0x08` | `MODE_METERED_FEE` | `fee` là **trần**; chuyển `min(fee, gasUsed × rate)`. **Cấm trên target confidential** (§C6.3, §C8.3) |
| `0x10` | *reserve* | (từng là `MODE_APPEND_SENDER` — **đã xoá**, xem dưới) |
| `0x20` | *reserve* | commit-reveal MEV |
| `0x40` | *reserve* | multi-call inner |
| | **`MODE_KNOWN_MASK = 0x0000_000F`** | |

`MODE_RESTRICT_BOTH = 0x03` là một **tổ hợp**, không phải một chế độ: giữ trong
tài liệu, **bỏ khỏi `.sol`**, để không ai viết `if (mode == MODE_RESTRICT_BOTH)`.

**`MODE_APPEND_SENDER` bị xoá khỏi mask.** Bản 1 vừa cấp `0x10` trong bitmask đã
ký vừa tuyên bố ở §C8.5 rằng cờ sender suffix nằm ở `TargetPolicy` và **không
phải mode bit**. Nếu cả hai cùng ship, một bit per-tx và một cờ per-target có thể
**mâu thuẫn nhau**, forwarder append hai lần hoặc không lần nào, và `_msgSender()`
trên target đọc sai địa chỉ — trong khi `mode` nằm **trong digest**, tức đóng
băng lúc ký. Cùng lớp lỗi với `MODE_RESTRICT_BOTH` mà canon đã bắt. Chốt:
**`TargetPolicy.appendsSender` là nguồn sự thật duy nhất**; `0x10` thành reserve;
`MODE_KNOWN_MASK = 0x0F`. Foundry test đi kèm, đặt cạnh hai test mode của §C8.3:
một target có `appendsSender = true` và một mode mang bit `0x10` phải bị
`INVALID_MODE` từ chối, tức mâu thuẫn là **không biểu diễn được**.

**Xoá ở nơi khác:** §05.4.4c đòi `0x10` cho commit-reveal (nay `0x10` là reserve,
commit-reveal vẫn ở `0x20`); §05.12 đòi `MODE_KNOWN_MASK = 0x0F` — **§05.12 đúng**,
canon bản 1 sai; §10.4.5 comment `0x00/0x01/0x02/0x03`.

**Canonical zeroing (bắt buộc cả hai phía, một TYPEHASH duy nhất):**

```solidity
function _canon(MetaTransaction calldata m) internal pure returns (address r, address f) {
    r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
    f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
}
```

Chữ "hoặc" trong note ("bỏ trường ra khỏi digest **hoặc** hash `address(0)`")
là một lỗi spec: hai digest khác nhau ⇒ 100% chữ ký fail. Chốt hash
`address(0)`. `mode` **bắt buộc nằm trong hash**, nếu không MODE_OPEN và
MODE_RESTRICT_* với `relayer = 0` trùng digest.

**Ràng buộc DB tương ứng (§10.4.5 sửa):**

```python
mode_flags = fields.Integer(required=True, default=0)
_check_mode_range = models.Constraint(
    'CHECK (mode_flags >= 0 AND mode_flags <= 2147483647)',
    'mode_flags phai la uint31 khong am.')
```

cộng một `@api.constrains` đối chiếu `MODE_KNOWN_MASK` **import từ
`lib/eip1776.py`** — nơi duy nhất giữ mask, cũng là nơi builder digest đọc.
Không dùng `CHECK (mode_flags & ~31 = 0)`: `models.Constraint` drop-and-recreate
khi định nghĩa đổi, nên mỗi lần contract mở rộng mask là một migration schema;
bound cấu trúc thì không bao giờ phải đổi. **Bit 31 vĩnh viễn không dùng** vì
Odoo `Integer` là `int4`.

### C8.3. Ngữ nghĩa thất bại — một quy tắc, và lý do

**Quy tắc, viết một lần cho toàn bộ tài liệu:**

> **Fee được trả khi và chỉ khi transaction ngoài không revert.**
> `MODE_REQUIRE_SUCCESS` bật ⇒ inner revert bubble ⇒ cả tx revert ⇒
> **nonce KHÔNG tiêu, fee KHÔNG trả**, relayer mất gas.
> `MODE_REQUIRE_SUCCESS` tắt ⇒ inner revert bị nuốt ⇒
> **nonce tiêu, fee trả**, event ghi `success = false`.

Contract ép hai điều kiện:

```solidity
require(m.amount == 0 || (m.mode & MODE_REQUIRE_SUCCESS) != 0, "AMOUNT_NEEDS_SUCCESS");
require(!targets[m.to].requireSuccess || (m.mode & MODE_REQUIRE_SUCCESS) != 0, "TARGET_NEEDS_SUCCESS");
require((m.mode & MODE_METERED_FEE) == 0 || !targets[m.to].isConfidential,   "METERED_FEE_NOT_CONFIDENTIAL");
```

Require thứ ba tồn tại vì `fee` của Zether **không phải một tham số thanh toán,
nó là một đầu vào của proof** (§C6.3): nó nằm trong Fiat-Shamir transcript, mệnh
đề số dư `b' = b − fee − v` được range-prove trên nó, và contract áp nó đồng
hình. Verifier **buộc** dùng con số `fee` đã khai. Nếu forwarder rồi trả relayer
`min(fee, gasUsed × rate)`, số dư bảo mật của người gửi bị trừ **đủ `fee`** trong
khi rời escrow **ít hơn**, và `totalDepositedScaled` phân kỳ với tổng số dư
confidential đúng bằng phần chênh — **im lặng, ở mọi giao dịch metered**. Bất
biến escrow đó là cơ chế phát hiện **duy nhất** §3.1.3 có cho một cú vỡ soundness.

`TargetPolicy.requireSuccess = true` cho **mọi target mang giá trị**:
`ZetherToken*`, `WrappedToken`, `PeggedToken`, `IssuerNativeToken`, contract
disperse. Đây là bổ sung duy nhất canon thêm vào §04, và nó cần thiết vì tiền
của Zether đi qua **inner call**, không qua `m.amount` — `AMOUNT_NEEDS_SUCCESS`
một mình không phủ được Zether. `TargetPolicy` đã tồn tại (nó giữ
`appendsSender` và `maxInnerGas`), nên đây là một boolean trên một struct đã có.

**Vì sao chọn bubble cho luồng tiền, chống lại §08.4c / §06.6(c) / §16 P03 DoD.**
Hai bên đang cân hai chi phí khác loại:

- Swallow bảo vệ relayer khỏi một vector grief gần miễn phí (ký hàng loạt
  meta-tx chắc chắn revert, đốt gas của mọi relayer).
- Bubble bảo vệ người dùng khỏi mất **principal**: trong swallow mode với
  `amount > 0`, tiền đã chuyển cho `to`, inner call revert, tx *thành công*,
  nonce tiêu, fee trả. Người dùng mất cả gốc lẫn phí cho một hành động không
  xảy ra, và `to` giữ tiền mà không có nghĩa vụ on-chain nào.

Chi phí của relayer là **có trần, định giá được, và do một doanh nghiệp gánh**:
$0.00375 một lần revert trên Gnosis, và §05.3.3 đã có công thức cộng nó vào
sàn phí — `margin' = (1 + margin)/(1 − p) − 1`. Mất principal là **không có
trần, không định giá trước được, và do một chủ outlet gánh**. Không có tỷ giá
nào giữa hai thứ đó. Đây cũng là dạng on-chain của nguyên tắc `dms_vietqr`:
trong bubble mode, nếu hành động không xảy ra thì **không có trạng thái nào tồn
tại** — cách diễn đạt sạch nhất của "broadcast không phải là thanh toán".

Vector grief của §08 được **định giá, không xoá**, bằng bốn lớp đã có:
Simulation Gate (§06.3) làm kẻ tấn công phải chủ động đổi state giữa simulate
và inclusion, tức chính họ cũng phải trả gas; `MODE_RESTRICT_RELAYER` + private
orderflow là **mặc định cho mọi luồng tiền** (§C6.6) và ở
`compliance_profile = 'vn_conservative'` là **bắt buộc** (§C16), nên không có
mempool để grief qua; sàn phí có hệ số rủi ro; và relay pool rate-limit theo
`from` khi tỷ lệ revert của địa chỉ đó vượt ngưỡng.

**Hệ quả phải sửa:**

- §08.4c: `_chargeFee` vô điều kiện đổi thành "fee thu khi inner revert **chỉ
  trong swallow mode**, tức chỉ khi `amount == 0` và target không
  `requireSuccess`".
- §06.6(1)(c): thứ tự `_consumeNonce` → `_collectFee` → inner call **giữ nguyên**
  (nó đúng, và cần thiết: fee sau inner call hỏng khi inner rút sạch số dư
  `feeToken`) — nhưng trong bubble mode cả ba đều bị revert cùng nhau, nên
  "thu phí trước" không có nghĩa là "thu phí kể cả khi revert".
- §06.12.3: câu hỏi đã đóng. `antiGriefBond = 3 × fee` bị **loại**: nó không
  nằm trong struct đã ký, thêm nó là một TYPEHASH thứ hai, và nó chuyển gánh
  nặng vốn sang người dùng để giải một bài toán đã được định giá bằng phí.
- §14 invariant **I7** viết lại: *"fee đã trả ⟺ transaction không revert"*.
  **I20**: *"trong nhánh thành công, fee transfer đứng trước inner call"*.
- §16 P03 DoD: *"fuzz chứng minh fee LUÔN được thu kể cả khi inner call revert"*
  đổi thành *"fuzz chứng minh: với `MODE_REQUIRE_SUCCESS` bật, inner revert ⇒
  toàn bộ tx revert và fee không chuyển; với bit tắt và `amount == 0`, inner
  revert ⇒ fee chuyển và nonce tiêu"* — **một Foundry test cho mỗi mode, cả hai
  là required check**.
- `blockchain.relay.job` giữ **cả hai** cột `chain_state` và `business_state`
  (§08.4c đúng ở điểm này): bubble mode cho `chain_state = 'reverted'`,
  swallow mode cho `chain_state = 'final'` cộng `business_state = 'failed'`.
  Quy tắc duy nhất: **`_set_done()` yêu cầu `chain_state == 'final' AND
  business_state == 'success'`**.

### C8.4. Expiry

| Loại | `expiry` | Lý do |
|---|---|---|
| Zether | **60 s** | ràng buộc thật là single-flight (§5.4.3) + cửa sổ revoke EIP-1271, **không** phải epoch |
| Call có đọc state | 120 s | |
| ERC-20 công khai | 300 s | |
| Anchor / log | 900 s | |

Thứ tự check: **mode → expiry (0 gas) → nonce (2,100 gas)**. Note đặt nonce
trước; 15 phút cho mọi meta-tx là một free option 900 giây cho relayer.

**`W = 0` và poll 5 Hz: đã trả lời, không còn để mở.** Với `expiry = 60 s`, ngân
sách chia ra: prove client ~2 s, hub→relayer ~1 s, claim + simulate ~2 s, ký ~1 s
(hoặc tới 3 s với MPC SaaS, §C15.1), broadcast + inclusion 1–3 block Gnosis =
5–15 s. Tổng p99 ≈ 24 s, tức **dư ~36 s**. Chốt:

> **`W = 3 s`** (cửa sổ gom, không phải 0) và **poll 1 Hz**.

`W = 0` cộng 5 Hz tồn tại để bóp một ngân sách 20 s; ở 60 s nó chỉ mua ~2 s trên
p99 và đổi lại là **5× tải poll trên Postgres** cùng đường mã không gom được. Đó
là đơn giản hoá thật của phần mềm relayer mà §C8.4 bản 1 hỏi lại thay vì trả
lời. §5.1.1 dựng lại toàn bộ bảng latency theo `expiry = 60 s`, `W = 3 s`,
`poll = 1 Hz`, và bỏ mọi biến thể `W = 0`.

### C8.5. Những thứ còn lại đã chốt trong §04 và không mở lại

- **63/64:** `require(gasleft() >= (m.innerGasLimit * 64) / 63 + FLOOR_GAS)`.
  Thiếu hệ số 64/63 là thiếu 41,270 gas ở `innerGasLimit = 2.6 M`. Post-check
  nằm **trong nhánh `!success`**, không vô điều kiện.
- **Return-bomb:** `MAX_RETURN_BYTES = 1024`, `call` với `out = 0, outsize = 0`
  rồi `returndatacopy` thủ công. High-level call của Solidity làm mất biện pháp này.
- **Không giữ allowance:** `require(m.to != address(this))`,
  `!targets[m.to].isFeeToken`, target allowlist, ưu tiên permit / native mixin.
- **Forwarder generic KHÔNG upgradeable** (UUPS + allowance = rug).
- **Sender suffix:** hash `data` **chưa** có suffix, forwarder append, cờ nằm
  ở `TargetPolicy.appendsSender` — **nguồn duy nhất**. `MODE_APPEND_SENDER` đã
  bị xoá khỏi mask (§C8.2), nên không còn hai chỗ để mâu thuẫn.
- **`ReentrancyGuardTransient`** (~200 gas) khi chain có Cancun; kiểm per-chain
  trong `blockchain.chain`, có fallback compile-time.
- **`SignatureChecker.isValidSignatureNow`** (fallback EIP-1271), reject
  `s > n/2`, `require(recovered == m.from && m.from != address(0))`,
  `require(signature.length <= 2048)`.
- **`lane_slot` sentinel của §04.3 bị xoá** — Odoo 19 **có**
  `models.UniqueIndex` (§C11.2), nên workaround đó giải một bài toán không tồn tại.
- **Khoá idempotency off-chain duy nhất là EIP-712 digest**, không bao giờ
  `keccak256(signature)` hay `keccak256(calldata)` — trong MODE_OPEN, calldata
  malleable.
- **`metaTx.fee = 0` cho mọi meta-tx Zether.** Phí Zether được token trả trực
  tiếp bằng ERC-20 từ escrow (§C6.3); để `metaTx.fee > 0` là thu phí hai lần.

---

## C9. `blockchain.chain`, endpoint, và số finality

`blockchain.chain` là model được tham chiếu nhiều nhất trong bộ tài liệu và
hiện đang có **bốn** định nghĩa. §10.4.2 là bản chuẩn tắc; §08.1, §11.3 và
§02.8.5 viết lại thành **delta ngữ nghĩa**, không phải định nghĩa field.

### C9.1. Field chuẩn tắc

Giữ nguyên §10.4.2, cộng **mười** bổ sung và ba sửa (bản 1 viết "bảy" rồi dùng
ba field soft-finality không có trong bảng — chúng nằm ở cuối bảng dưới đây):

| Field | Kiểu | Ghi chú |
|---|---|---|
| `sequence`, `name`, `code`, `caip2` | | `_order = 'sequence, id'` cần `sequence` |
| `chain_family` | Selection | `evm, hedera, ton, sui, soroban, cosmwasm` + **reserve `fabric`, `corda`** (§13.5.1, chưa có adapter) |
| `chain_profile` | Selection | **hai giá trị `private` / `public`, `default='private'`** |
| `evm_chain_number` | Integer | **không** `evm_chain_id` (§C2.2) |
| `is_testnet` | Boolean | **thắng `is_production`.** §09.1 sửa constraint thành `is_testnet = False` |
| `native_symbol`, `native_decimals` | | |
| `fee_mode` | Selection | `native`, `native_stable`, **`fee_currency` (Celo **CIP-64**, tx type `0x7b`)**, `sponsored`, `gasless`. Bỏ `native_is_stable` — nó đã nằm trong `native_stable` |
| `block_time_ms`, `block_gas_limit` | Integer | |
| **`max_gas_per_tx`** | Integer | *(mới)* trần outer gas pool tự áp; phải `>= requiredOuterGas` (§C7.4) |
| `finality_mode` | Selection | **`bft_instant`, `depth`, `tag`, `l1_batch`.** `checkpoint` gộp vào `tag` (Gnosis, Ethereum, Polygon đều trả milestone/finalized qua tag). **`finality_source` của §11 chính là field này** — xoá tên thứ hai |
| `finality_soft_blocks/_seconds`, `finality_hard_blocks/_seconds` | Integer | Gate lấy **AND** của hai trục |
| **`finality_quorum`** | Integer, default 2 | *(mới, từ §08)* số endpoint **độc lập** phải khớp block hash; §11.3b phụ thuộc nó |
| **`finality_warn_seconds`**, **`finality_stuck_seconds`** | Integer | *(mới, từ §11)* hai ngưỡng tách rời. Arbitrum `stuck = 26 h` vì cửa sổ force-inclusion là 24 h |
| `reorg_watch_blocks` | Integer | **tên duy nhất**; xoá `reorg_window_blocks` của §11 |
| **`anchor_interval_seconds`** | Integer, default 3600 | *(mới, từ §11/§08)* HCS anchor |
| **`token_ids`** | One2many `blockchain.token` | *(mới)* §15.2.1 `_preflight` đọc nó |
| **`max_public_intent_value_base`** | Char uint256 | *(mới, từ §05)* chặn `MODE_OPEN` trên public bus cho giao dịch lớn |
| `has_bls12381`, `compliance_freeze_enabled` | Boolean | từ §02, đặt trên chain — **không** trên một model profile |
| `max_calldata_bytes`, `explorer_base_url`, `relay_worker_ref`, `capability_json` | | |
| `state` | Selection | **`draft, enabled, degraded, halted, retired`**. Xoá `live/paused` của §08 |
| `company_ids` | Many2many `res.company` | rỗng = mọi công ty |
| **`soft_final_max_amount`** | Monetary | *(mới)* trần một giao dịch cho đường soft finality, mặc định **5,000,000 ₫** (§C9.4). Bản 1 dùng tên này ở §C9.4 mà **không khai** nó ở đâu |
| **`soft_final_exposure_cap`** | Monetary | *(mới)* trần **tổng** đang mở của mọi settlement đã `final` từ soft mà chưa đạt hard, mặc định **125,000,000 ₫** (§C9.4) |
| **`soft_final_exposure`** | Monetary, `compute`, `store=True` | *(mới)* tổng đang mở hiện tại — `SUM(amount_fiat)` trên settlement của chain này có `settle_state = 'final'` **và** `finality_grade = 'soft'` **và** chưa đủ `finality_hard_*`. Finality Gate là bên duy nhất ghi lại nó, trong cùng transaction với `settle_state`. **Stored compute ⇒ không `default=`** (§C11.6) |

Ba field cuối cùng và **`r2_max_fiat`** cùng một họ, nhưng `r2_max_fiat` **không**
thuộc `blockchain.chain`: nó là ranh giới lớp rủi ro, nên nó nằm trên
**`blockchain.money.flow`** (§C15.2, và §C10.1 hàng money-flow ghi nó).
`blockchain.money.flow` cũng nhận **`latency_budget`**
(Selection `seconds` / `minutes` / `hours`, `required`, default `minutes`) — §C1.2
đọc nó để quyết flow nào được `cron._trigger()` đẩy, và bản 1 dùng nó mà không
khai ở đâu.

`blockchain.rpc.endpoint` giữ §10.4.2, cộng **`is_independent`** (Boolean) — hai
API key Alchemy **không** độc lập; `finality_quorum` đếm trên endpoint có
`is_independent = True`. Không có field `url`: `endpoint_ref` là **tên khoá**,
URL thật nằm trong biến môi trường của relay worker, không trong
`ir_config_parameter` (bảng đó nằm trong mọi bản backup và đọc được bởi mọi
`group_system`).

**`blockchain.chain.profile` bị xoá hoàn toàn.** Áp dụng cơ học ở §02.8.5:
xoá class, `blockchain.zether.account.chain.profile_id` →
`chain_id = fields.Many2one('blockchain.chain', required=True, index=True)`,
constraint → `UNIQUE(account_id, chain_id)`, `is_private` →
`chain_id.chain_profile == 'private'`. Sửa §12.10 runbook và §14.11 (`EXPECTED`
dict, route RPC `/json/2/blockchain.chain.profile/...`). Thêm một grep gate cho
chuỗi `blockchain.chain.profile`.

### C9.2. Seed data — và ràng buộc chặn bật chain khi chưa đo

| code | caip2 | family | profile | fee_mode | block_ms | finality_mode | soft_blocks | hard_blocks | hard_seconds | state |
|---|---|---|---|---|---|---|---|---|---|---|
| `gnosis` | `eip155:100` | evm | public | `native_stable` | 5000 | `tag` | 1 | 64 | **240** | `draft` |
| `celo` | `eip155:42220` | evm | public | `fee_currency` | 1000 | `l1_batch` | 1 | 0 | **0 (chưa đo)** | `draft` |
| `besu-priv-01` | `eip155:1337001` | evm | private | `gasless` | 2000 | `bft_instant` | 1 | 1 | 0 | `draft` |

**Gnosis hard finality là ~160–240 giây, không phải 12.8 phút.** Gnosis Beacon
dùng **16 slot × 5 s = 80 s một epoch**; 2 epoch ≈ 160 s. 12.8 phút là con số
của Ethereum (32 slot × 12 s × 2). Seed 240 s (160 s + biên). **Xoá 780 giây**
khỏi §10.4.2 và **xoá 12.8 phút** khỏi §01.2 và §3.9.5. Sai 4.8 lần trên chính
chain #1, và nó bắt khách hàng chờ gấp 4 lần cần thiết.

**Celo là Ethereum L2 trên OP Stack từ 3/2025.** Mọi giả định IBFT 2.0 /
immediate finality / 5 giây bị bỏ. `finality_hard_seconds` chưa có con số dùng
được ở bất kỳ đâu; ước tính rải rác 15–20 phút. Nhiệm vụ đo vào **S0** (lấy mẫu
`latest` vs `finalized` trên mainnet 7 ngày, lấy p99) và kết quả là **đầu vào
bắt buộc của DoD P16**.

```python
@api.constrains('state', 'finality_mode', 'finality_hard_seconds', 'finality_hard_blocks')
def _check_finality_configured(self):
    for rec in self:
        if rec.state != 'enabled':
            continue
        if rec.finality_mode == 'bft_instant':
            continue                      # hard_seconds = 0 la CAU HINH HOP LE, khong phai chua dat
        if not rec.finality_hard_seconds and not rec.finality_hard_blocks:
            raise ValidationError(_('Chain khong the enabled khi chua do finality.'))
```

Đó cũng là cách canon trả lời yêu cầu §13.5.1(1): `finality_hard_blocks = 1`
kèm `finality_hard_seconds = 0` là **hợp lệ** khi `finality_mode = 'bft_instant'`;
"chưa cấu hình" được biểu diễn bằng `state = 'draft'`, không bằng một Integer
nullable.

Điều kiện chuyển Gnosis sang `enabled`: **đo p99 khoảng cách `latest` →
`finalized` trong 7 ngày trên mainnet**, ghi kết quả vào `mail.thread` của
record chain.

### C9.3. Celo — ba ràng buộc phải nằm trong §08 trước khi ai viết adapter

1. Cơ chế fee currency đang chạy là **CIP-64** (transaction type `0x7b`) cộng
   **CIP-66** (`maxFeeInFeeCurrency`). **CIP-52 là đề xuất thư mục**, không phải
   cơ chế. Nhãn ở §08.1 và §10.4.2 sửa thành `fee_currency (Celo CIP-64)`.
2. **ethers.js và web3.py không serialize được type `0x7b`** — adapter phải tự
   dựng RLP bằng tay (§06.2.3).
3. `intrinsicGasForFeeCurrency` ≈ 50 k, đọc từ `FeeCurrencyDirectory`, cộng vào
   mọi ước tính gas trên Celo.

### C9.4. Điều kiện `final` — một cổng cho mỗi `transport`

Bản 1 viết năm điều kiện **vô điều kiện**, tức một settlement `transport =
'offset'` hay `'external'` **không bao giờ tới được `final`** — không có
`blockchain.transaction`, không có receipt, không có confirmations, không có
relay job. §C16 lại đặt hình thái **record-only** làm hình dạng của **hai trong
ba** use case đã khoá (P22 B2B qua M12/M13, P23 ENDUSER_PAY qua M12/M1), và
§C15.2 đặt netting B2B là luồng R3. Nghĩa là hai vertical duy nhất có thể ra mắt
là hai vertical mà settlement mắc kẹt dưới `final` vĩnh viễn. Cổng phải chia
theo `transport`.

#### `transport = 'onchain'` — năm điều kiện, giữ nguyên

`settle_state = 'final'` chỉ xảy ra khi **tất cả**:

1. `blockchain.transaction.tx_state == 'final'` và receipt `status == 1`;
2. `confirmations >= chain.finality_hard_blocks` **AND** tuổi block
   `>= chain.finality_hard_seconds` (AND, không phải OR);
3. block hash khớp trên `chain.finality_quorum` endpoint **độc lập**;
4. `relay.job.business_state == 'success'` (§C8.3);
5. với `chain_profile = 'private'`: ít nhất **2 validator độc lập** (khác chủ sở
   hữu hạ tầng) đã ký — biểu diễn bằng `finality_quorum = 2` trên endpoint độc lập.

#### `transport = 'offset'` (netting, không tx) — hai điều kiện

1. `netting_set_id.state == 'closed'`;
2. **mọi** leg của netting set đó đã hạch toán: với mỗi settlement trong set,
   `gl_state in ('posted', 'not_required')`, và tổng đại số các leg bằng 0
   (hoặc bằng đúng leg on-chain còn lại nếu set có leg thanh toán ròng).

Bằng chứng nằm ở **`blockchain.netting.set`**, không ở chain. Trong năm điều
kiện onchain, `_set_done` của §C12 chỉ còn đọc điều kiện 4 → **không đọc gì**:
offset không có relay job, nên quy tắc §C12 đọc `netting_set_id.state` thay thế.

#### `transport = 'external'` (fiat, chỉ neo) — hai điều kiện

1. xác nhận phía fiat: một `blockchain.payment.observation` được chấp nhận
   (VietQR / sao kê ngân hàng / acquirer callback), hoặc `gl_move_ref` đã
   reconcile ở `dms_blockchain_account`;
2. **anchor** của nó đã `final`: `blockchain.anchor` mang record đó đạt điều kiện
   `onchain` ở trên **trên chain neo**.

Điều kiện 1 là thứ chấm dứt nghĩa vụ; điều kiện 2 là thứ làm nó **chứng minh
được sau này**. Thiếu (2) thì `final` vẫn hợp lệ về nghiệp vụ nhưng
`settle_state` dừng ở `pending_finality` cho tới khi anchor final — đó là hành vi
đúng và nó phải được nói ra để không ai đọc `pending_finality` như một lỗi.

#### Đường soft finality — ngoại lệ duy nhất, và điều kiện thứ sáu

`settle_state` được phép lên `final` từ soft khi **cả bốn**:

1. `transport == 'onchain'`;
2. `amount_fiat <= chain.soft_final_max_amount` (mặc định **5,000,000 ₫**);
3. `money_flow.risk_class <= 'r2'`;
4. `chain.soft_final_exposure + amount_fiat <= chain.soft_final_exposure_cap`
   (mặc định **125,000,000 ₫**);
5. **`money_flow.is_payment_bound == False`** — điều kiện thứ sáu, mới, và nó là
   thứ hoà giải §C10.9.

Cơ sở của (2)–(4): E[loss] chấp nhận được nhưng **phương sai** thì không — cùng
phép tính cho một giao dịch 1 tỷ ₫ cho E nhỏ mà đuôi thì không chịu được.
P(reorg vượt depth 1) trên Gnosis: con số 1e-4 là **ước tính khởi động**, phải
thay bằng histogram thật từ indexer sau 30 ngày trước khi chốt ngưỡng.

**Cơ sở của (5), và vì sao nó không thể ở chỗ khác.** §C10.9 chứng minh từ source
rằng `payment.transaction._set_error` có
`allowed_states = ('draft','pending','authorized')`, nên sau một reorg trên một
tx đã `done` nó **log warning rồi không làm gì**. Hệ quả §C10.9 rút ra —
*"Finality Gate dùng ngưỡng hard"* — mâu thuẫn thẳng với đường soft ở đây, và
§C15.2 đặt `LOYALTY_ACCRUE`, `LOYALTY_REDEEM`, `OUTLET_COLLECT` đúng vào ô soft,
tức **~38,000 giao dịch/ngày**, tức gần như toàn bộ khối lượng ra mắt. Chốt bằng
cách chia theo *có bị ràng buộc vào một `payment.transaction` hay không*, chứ
không theo lớp rủi ro:

> **Soft finality bị cấm cho mọi settlement lái một `payment.transaction`.**
> Ngược lại: một flow đã đánh dấu `latency_budget = 'seconds'` và muốn soft thì
> **không được** gắn `payment.transaction`.

Luồng ra mắt nào payment-bound, viết ra để không ai đoán: **`OUTLET_COLLECT` và
`ENDUSER_PAY`** (cả hai qua `dms_blockchain_payment`, `payment.provider`
`code='chain'`) ⇒ **hard**. **`LOYALTY_ACCRUE`, `LOYALTY_REDEEM`** không đi qua
`payment.transaction` (không có tiền pháp định nào chuyển) ⇒ **soft hợp lệ**.
`B2B_PAYOUT` / `B2B_INVOICE_PAY` là R3 ⇒ **hard** theo (3) dù sao.
`blockchain.money.flow.is_payment_bound` là Boolean stored, ghi bởi
`dms_blockchain_payment` lúc gắn handler, không do client gửi.

---

## C10. Model Odoo — sổ đăng ký và schema chuẩn tắc

### C10.1. Sổ đăng ký đầy đủ

Mọi `_name` bắt đầu bằng `blockchain.` trong toàn hệ thống. Cột "Sở hữu" là
section **được phép định nghĩa** model đó; mọi section khác chỉ tham chiếu hoặc
`_inherit`.

Cột **`ACL`** phân biệt model có bảng với AbstractModel — generator ACL và gate
tier-0 đọc **cùng một cột này**, nên chúng không thể lệch nhau.

| Model | Sở hữu | Module | `company_id` | ACL | Ghi chú |
|---|---|---|---|---|---|
| `blockchain.chain` | §10.4.2 | core | không (`company_ids` M2M) | có | §C9 |
| `blockchain.rpc.endpoint` | §10.4.2 | core | không | có | + `is_independent` |
| `blockchain.contract.deployment` | §10.4.9 | core | không | có | **`blockchain.contract` của §14.12b là cùng một thứ — xoá tên thứ hai** |
| `blockchain.contract.abi` | §11.6 | core | không | có | versioning ABI |
| `blockchain.account` | §10.4.3 | core | **có** | có | §C10.2 |
| `blockchain.relayer.account` | §06.9 | core | **kế thừa, KHÔNG phải cột của model này** | có | `_inherits = {'blockchain.account': 'account_id'}`; `account_id` phải được **khai tường minh** (§C10.2). `ir.rule` company viết trên **`blockchain.account`**, không trên model này |
| `blockchain.custody.provider` / `.key` / `.policy` | §07.12 | core | có / related / có | có | `.policy` khoá theo `flow_code` + `chain_id` (§C15) |
| `blockchain.signing.request` | §07.1b | core | có | có | hàng đợi trước signer, có `idem` key |
| `blockchain.key.ceremony` | §07.8 | core | có | có | |
| `blockchain.enclave.image` | §07 | core | không | có | allowlist PCR attestation |
| `blockchain.environment` | §07.12.4 | core | không | có | chặn dump production → staging |
| `blockchain.token` | §10.4.4 | core | không (`company_ids`) | có | §C10.3 |
| `blockchain.zether.token` | §03.9.2 | core | **kế thừa, KHÔNG phải cột của model này** | có | `_inherits = {'blockchain.token': 'token_id'}`; `token_id` phải được **khai tường minh** (§C10.3). `ir.rule` company viết trên **`blockchain.token`**, không trên model này |
| `blockchain.token.rate` | §15 | core | không | có | feed tỷ giá, append-only |
| `blockchain.metatx` | §10.4.5 | core | **có** (index, ghi bởi relay worker) | có | §C10.5. Bản 1 ghi "suy từ settlement" — **không suy được**: `settlement.metatx_id` là Many2one không có One2many nghịch đảo, nên cả domain traversal cũng không viết được |
| `blockchain.relayer` | §10.4.5 | core | có khi `kind='internal'` | có | registry bên thứ ba |
| `blockchain.relayer.address` | §10.4.5 | core | không | có | |
| `blockchain.relayer.statement` / `.line` | §05.8.2 | core | có | có | **định nghĩa thật, không phải hai dòng trong một bảng** |
| `blockchain.intent.hub` | §05 | core | không | có | |
| `blockchain.sponsorship.pool` | §05 | core | có | có | |
| `blockchain.target.policy` | §06/§04 | core | không | có | gương của `TargetPolicy` on-chain, gồm `require_success` (§C8.3) |
| `blockchain.relay.job` | §06.9 | core | **có** | có | **outbox row + attempt, một model** — §C10.8 |
| `blockchain.refill.request` | §06.5 | core | có | có | nạp gas relayer, maker-checker |
| `blockchain.sim.divergence` | §06.3.2 | core | có | có | bằng chứng của SLO divergence |
| `blockchain.transaction` | §10.4.6 | core | **có** (index, ghi bởi Finality Gate) | có | §C10.6 |
| `blockchain.chain.event` | §11.5 | core | **có** (index, ghi bởi indexer) | có | **thay `blockchain.event` của §10.4.6 — một tên**. **Không partition** (§C1.2) |
| `blockchain.chain.effect` | §11.5 | core | **có** | có | khoá `(caip2, ref)` |
| `blockchain.block.header` | §11.4 | core | không | có | phát hiện reorg |
| `blockchain.reorg.event` | §11.4 | core | không | có | |
| `blockchain.ref.collision` | §11.5 | core | có | có | sự cố, không phải dữ liệu bình thường |
| `blockchain.index.cursor` | §11.2 | core | không | có | `position_key` Char 64, **không** `size=` |
| `blockchain.watched.address` | §11.8 | core | có | có | |
| `blockchain.anchor` | §11.3 / §08.5 | core | không | có | HCS anchor, có `prev` móc xích |
| `blockchain.zether.account` | §02.8.5 | core | **có** | có | §C10.7 |
| `blockchain.zether.account.chain` | §02.8.5 | core | qua parent | có | `chain_id`, không `profile_id` |
| `blockchain.zether.entry` | §10.4.7 | core | **có** | có | §C10.7 — **thay cả `blockchain.zether.transfer`** |
| `blockchain.settlement` | §10.4.8 | core | **có** | có | §C10.4 |
| `blockchain.settlement.log` | **§10.4.8** | core | **có** (stored related từ `settlement_id.company_id`, index) | có | **6 cột**, thay `mail.thread` (§C1.2). Sở hữu là §10.4.8 vì nó là phụ lục của `blockchain.settlement` — bản 1 ghi sở hữu là "§C1.2", tức **không section nào được bảo viết nó** |
| `blockchain.settlement.batch` | §15.1.2 | core | **có** | có | |
| `blockchain.settlement.batch.chunk` | §15.1.2 | core | **có** | có | |
| `blockchain.settlement.origin` | §15.3 | core | AbstractModel | n/a | mixin callback, không có bảng |
| `blockchain.netting.set` | §15.6.3 | core | **có** | có | |
| `blockchain.money.flow` | §09.4 | core | có (nullable = default) | có | + `token_id`, + `risk_class`, + **`r2_max_fiat`** (Monetary, default 5,000,000 ₫), + **`latency_budget`** (Selection `seconds`/`minutes`/`hours`, required, default `minutes`), + **`is_payment_bound`** (Boolean, ghi bởi `dms_blockchain_payment`) — cả ba được §C15.2, §C1.2 và §C9.4 dùng mà bản 1 không khai ở đâu |
| `blockchain.payment.handler` / `.none` | §09.4 | core | AbstractModel | n/a | interface + impl rỗng |
| `blockchain.payment.request` | §09.6 | core | **có** | có | §C10.9 |
| `blockchain.payment.observation` | §09.5d | core | **có** | có | §C10.9 |
| `blockchain.payment.quote` | §09.7b | core | **có** | có | tỷ giá giữ, hai số nguyên |
| `blockchain.approval.policy` / `.request` | §10.4.10 | core | **có** | có | khoá theo `flow_code` + `chain_id` |
| `blockchain.security.event` | §10.4.11 | core | **có** | có | **hấp thụ `blockchain.breaker.event`** qua `event_kind` |
| `blockchain.governance.signer` | §01.11.1 | core | không | có | ai trên Safe |
| `blockchain.upgrade.proposal` | §01 | core | không | có | |
| `blockchain.validator.change` | §08.10 | core | không | có | lịch sử validator set private chain |
| `blockchain.audit.disclosure` | §13 | core | **có** | có | `write`/`unlink` override raise, ACL là lớp hai |
| `blockchain.travel.rule.message` | §13 | core | **có** | có | |
| `blockchain.erasure.log` | §13.7.3 | core | **có** | có | |
| `blockchain.reconciliation.run` / `.line` | §15.5 | `_account` | **có** | có | `.line` hấp thụ `blockchain.balance.drift` |

**Model bị xoá, và thay bằng gì:**

| Xoá | Vì sao | Thay bằng |
|---|---|---|
| `blockchain.chain.profile` | §10.3 đã quyết, chưa ai áp dụng | field trên `blockchain.chain` |
| `blockchain.event` | tên quá chung, §11 sở hữu ingestion | `blockchain.chain.event` |
| `blockchain.outbox.job` | hai dòng cho một hop = hai state handoff, hai khoá dedup | `blockchain.relay.job` state `queued` |
| `blockchain.zether.transfer` | hai `_name` cho một đối tượng, ba quy tắc unique | `blockchain.zether.entry` |
| `blockchain.contract` | trùng `blockchain.contract.deployment` | `blockchain.contract.deployment` |
| `blockchain.payment.reversal` | sổ cái on-chain không có UNDO | `blockchain.settlement` với `compensation_of_id` |
| `blockchain.settlement.transition` | | `blockchain.settlement.log` |
| `blockchain.balance.drift` | | `blockchain.reconciliation.line` với `check_direction='balance'` |
| `blockchain.breaker.event` | | `blockchain.security.event` với `event_kind='breaker'` |
| `blockchain.credit.balance` | số dư là read model, không phải bảng | SQL view trên settlement + effect |
| `blockchain.escrow.deal`, `blockchain.mandate`, `blockchain.voucher` | M7–M10, M18 ngoài phạm vi (§C18) | — |
| `blockchain.session.key` | §C15.3 | cùng đường custody + `blockchain.approval.policy` |

**Bốn CI gate bắt buộc, tier 0:**

1. Mọi model **cụ thể** trong `models/` phải có **ít nhất một dòng** trong
   `ir.model.access.csv`. Odoo chỉ log warning; ở đây là **fail build**. Model
   không có dòng ACL là model không ai truy cập được trừ superuser.

   **Gate duyệt registry và bỏ qua `_abstract` và `_transient`** — cùng vị từ mà
   `bamboo_idempotency._bamboo_uuid_enforced()` dùng (`base.py:120`:
   `if not self._auto or self._abstract or self._transient`). AbstractModel
   không có bảng, nên một dòng `ir.model.access` trên nó **cấp quyền vào hư
   không**, và cảnh báo "model has no access rules" của chính Odoo cũng cố tình
   bỏ qua abstract/transient. Bản 1 viết gate vô điều kiện, tức nó **fail build
   vĩnh viễn** hoặc ép ba dòng ACL vô nghĩa cho ba AbstractModel — rồi ba dòng
   đó lại làm nhiễu con số "~55 model" mà chính CSV được sinh từ. Một required
   check phải đi vòng là một required check dạy cả đội cách đi vòng.

   ```python
   for name, model in env.registry.items():
       if not model._auto or model._abstract or model._transient:
           continue                     # cot ACL = n/a trong bang C10.1
       assert acl_rows_for(name), f'{name} khong co dong ir.model.access'
   ```

2. Mọi `_name` trong `models/` phải có một hàng trong bảng C10.1, **và cột `ACL`
   của hàng đó phải khớp với vị từ ở gate 1**. Bảng này sinh ra `EXPECTED` của
   §14.11.
3. **Mọi model có cột `company_id` = "có" trong bảng C10.1 phải có ít nhất một
   `ir.rule`.** Xem bảng record rule ở §C14.1 — một ma trận nhóm quyền không có
   bảng đó chỉ là một nửa mô hình bảo mật.
4. Số hàng của bảng C10.1 phải khớp số `_name` trong registry, và số hàng bảng
   nhóm ở §C14.1 phải khớp số XML id `res.groups` được khai. Cả hai bảng đều
   được tuyên bố là "sinh ra"; một danh sách đóng mà kích thước tự khai bị sai
   sẽ được người ta chỉnh tay đúng theo cách §C2.4 cảnh báo (§C14.1 bản 1 viết
   "chín nhóm" và liệt kê mười).

### C10.2. `blockchain.account`

Giữ §10.4.3 nguyên vẹn. Ba điểm là chuẩn tắc và các section khác phải theo:

- **Không `size=`.** Hai tầng validation: một CHECK thô cho mọi họ
  (`length(address) BETWEEN 20 AND 128`) cộng một CHECK **có điều kiện theo
  `chain_family`** (stored related, nên là cột thật) cho từng họ, cộng
  `@api.constrains` gọi `adapter.validate_address()` (bắt checksum EIP-55,
  bech32, StrKey CRC16). **Không** ép `lower()` toàn cục: Stellar StrKey là
  base32 hoa, CosmWasm hex hoa.
- **Custody một taxonomy:** `custody_key_id = Many2one('blockchain.custody.key')`
  cộng `custody_mode = Selection(related='custody_key_id.provider_id.kind',
  store=True)`. **Xoá `custody_model` và `secret_ref` khỏi
  `blockchain.zether.account` (§02.8.5)** — một Selection 5 giá trị ở §02 và
  một registry 8 giá trị ở §07 là hai nguồn sự thật cho cùng một sự thật, và
  hôm nay một tài khoản có thể khai `custody_model='hsm'` trong khi key handle
  trỏ vào một provider `kind='tee_saas'` mà không gì phát hiện.
- `signer_ref` bảo vệ bằng **`groups=` trong định nghĩa field**, không bằng
  record rule (rule lọc dòng, không lọc cột). `groups` **đi theo qua
  `_inherits`** (`orm/fields.py:777`), nên `blockchain.relayer.account` không
  rò rỉ nó — nhưng đây là lần duy nhất một tính chất bảo mật phụ thuộc một dòng
  trong ORM, nên nó phải có test.

Thêm một helper mà §15.2.1 đang gọi vào hư không:

```python
def _zether_registered(self, chain):
    """§15.2.1 dang doc payee_account_id.zether_registered — field do khong ton tai."""
    self.ensure_one()
    return bool(self.env['blockchain.zether.account.chain'].search_count([
        ('account_id.blockchain_account_id', '=', self.id),
        ('chain_id', '=', chain.id),
        ('onchain_state', '=', 'registered'),
    ]))
```

**Ai ghi `onchain_state`?** Không ai, hôm nay — helper trên đọc một state mà
không section nào đặt. Người ghi có tên là **relay pool của issuer**, qua
`/json/2`, khi receipt của `register` (PoP Schnorr) đạt §C9.4: `unregistered →
pending → registered`, cộng `failed`. Đó là một máy trạng thái **duy nhất** trên
`blockchain.zether.account.chain`, và toàn bộ luồng onboarding gasless quanh nó
là **§C21 D14** (+6 ew, pha P04), do §02 viết.

### C10.3. `blockchain.token` và `blockchain.zether.token`

`blockchain.token` giữ §01.13 / §10.4.4, cộng bốn nhóm field từ ba section:

| Field | Từ | Ghi chú |
|---|---|---|
| `chain_id` | §01 | inverse là `blockchain.chain.token_ids` (§C9.1) |
| `is_confidential`, `registry_address`, `underlying_token_id`, `peg_numerator`, `peg_denominator`, `token_decimals`, `deploy_state` | §10.4.4 | `peg_*` là Char uint256, không Float |
| **`token_legal_class`**, **`transfer_policy`** | §13.1.2 | `transfer_policy` là ranh giới duy nhất cả ba phân tích pháp lý đi qua, nên nó là **một field được ép**, cộng một revert ở tầng contract |
| **`token_quirk`**, **`approval_state`** | §11.8b | `fee_on_transfer`, `rebasing`, `blacklist`, `no_return_value`; allowlist tự động chỉ chạy khi `approval_state = 'approved'` |
| **`max_amount_base`** | §15.2.1 | Char uint256; `_preflight` đọc nó |
| `contract_address` | §01 | **bỏ `size=42`** — `chain_id` có thể trỏ Sui (66) hoặc TON (48), và một địa chỉ 66 ký tự bị cắt còn 42 **không lỗi**, rồi `UNIQUE(chain_id, contract_address)` vui vẻ nhận hai token khác nhau là một |

`blockchain.zether.token` là **`_inherits = {'blockchain.token': 'token_id'}`**.
Field list, và **`token_id` nằm trong list**:

```python
token_id = fields.Many2one('blockchain.token', required=True,
                           ondelete='cascade', index=True)
```

cộng **chỉ** field mật mã: `curve_profile`, `verifier_kind`, `proof_system_id`,
`scale_exponent`, `range_bits_value`, `range_bits_balance`, `auditor_pubkey`,
`auditor_key_timelock_datetime`, `keep_proof_blob`,
`confidentiality_horizon_years`, `deployed_block`. Không lặp lại
`contract_address`, `chain_id`, `token_decimals` — chúng ở parent.

**Field uỷ quyền phải được khai, và bản 1 không khai nó ở cả hai chỗ.**
`_inherits = {'blockchain.token': 'token_id'}` **bắt buộc** model con khai
`token_id`; Odoo raise ngay lúc registry setup khi field được đặt tên đó không
tồn tại, nên đọc field list của bản 1 theo đúng chữ sẽ dựng ra một model **không
load được**. `ondelete='cascade'` là thứ ngăn một record con sống lâu hơn record
cha của nó. Điều tương tự áp cho
`blockchain.relayer.account`: `_inherits = {'blockchain.account': 'account_id'}`
với `account_id = fields.Many2one('blockchain.account', required=True,
ondelete='cascade', index=True)`.

Hệ quả về record rule, phải viết ra: `company_id` kế thừa qua `_inherits` là một
**related không stored**, nên một `ir.rule` đặt trên model con sẽ trả giá bằng
một subquery vào bảng cha **và** rule của chính cha vẫn áp khi đọc field kế
thừa. Chốt: **`ir.rule` company cho hai model này viết trên CHA**
(`blockchain.token`, `blockchain.account`), không trên con. §C10.1 đã sửa hai
hàng đó theo.

### C10.4. `blockchain.settlement` — schema chuẩn tắc

Model **duy nhất** mọi consumer (bridge DMS, payment, account, RPC ngoài) được
phép dùng. §10.4.8 sở hữu định nghĩa; §15.2.1–15.2.2 thắng về **ngữ nghĩa** và
những thay đổi dưới đây đã được áp vào.

```python
class BlockchainSettlement(models.Model):
    _name = 'blockchain.settlement'
    _description = 'Unified on-chain settlement'
    _order = 'id desc'
    # KHONG _inherit = ['mail.thread'] — xem §C1.2

    name            = fields.Char(required=True, copy=False, default='/', readonly=True)
    company_id      = fields.Many2one('res.company', required=True, index=True,
                                      default=lambda s: s.env.company)

    # --- Idempotency & lien ket nguoc ---
    origin_producer = fields.Char(required=True, index=True, readonly=True)
    origin_key      = fields.Char(required=True, index=True)
    origin_model    = fields.Char(index=True)
    origin_id       = fields.Many2oneReference(model_field='origin_model', index=True)
    origin_ref      = fields.Reference(selection='_selection_origin_ref',
                                       compute='_compute_origin_ref',
                                       inverse='_inverse_origin_ref', store=False)
    #  _selection_origin_ref() dung tu REGISTRY luc goi, khong phai mot list tinh
    #  _compute_origin_ref() gan False khi origin_model khong co trong self.env
    #  (xem khoi "origin_ref phai chiu duoc mot model vang mat" ben duoi)

    # --- Ban chat giao dich ---
    use_case        = fields.Selection([('loyalty', 'Loyalty / reward points'),
                                        ('b2b', 'B2B settlement'),
                                        ('payment', 'End-user payment')],
                                       required=True, index=True)
    direction       = fields.Selection([('out', 'Outbound / payout'),
                                        ('in', 'Inbound / collection')],
                                       required=True, index=True)
    transport       = fields.Selection([('onchain', 'On-chain transfer'),
                                        ('offset', 'Netting offset, no tx'),
                                        ('external', 'Fiat / off-chain, anchor only')],
                                       required=True, default='onchain', index=True)
    chain_id        = fields.Many2one('blockchain.chain', index=True)
    token_id        = fields.Many2one('blockchain.token', index=True)
    payer_account_id = fields.Many2one('blockchain.account', index=True)
    payee_account_id = fields.Many2one('blockchain.account', index=True)
    partner_id      = fields.Many2one('res.partner', index=True)
    amount_base     = fields.Char(required=True, default='0')
    currency_id     = fields.Many2one('res.currency', required=True,
                                      default=lambda s: s.env.company.currency_id)
    amount_fiat     = fields.Monetary(currency_field='currency_id')
    confidential    = fields.Boolean(default=False)
    risk_class      = fields.Selection([('r1', 'R1'), ('r2', 'R2'),
                                        ('r3', 'R3'), ('r4', 'R4')],
                                       required=True, default='r2', index=True)
    finality_grade  = fields.Selection([('soft', 'Soft'), ('hard', 'Hard')],
                                       readonly=True, index=True)

    # --- Lien ket ky thuat ---
    metatx_id       = fields.Many2one('blockchain.metatx', index=True)
    transaction_id  = fields.Many2one('blockchain.transaction', index=True)
    zether_entry_id = fields.Many2one('blockchain.zether.entry', index=True)
    effect_id       = fields.Many2one('blockchain.chain.effect', index=True)
    batch_id        = fields.Many2one('blockchain.settlement.batch', index=True,
                                      ondelete='set null')
    chunk_id        = fields.Many2one('blockchain.settlement.batch.chunk', index=True,
                                      ondelete='set null')
    netting_set_id  = fields.Many2one('blockchain.netting.set', index=True)
    money_flow_id   = fields.Many2one('blockchain.money.flow', index=True)
    payment_request_id = fields.Many2one('blockchain.payment.request', index=True)
    compensation_of_id = fields.Many2one('blockchain.settlement', index=True,
                                         ondelete='restrict')

    # --- Vong doi ---
    settle_state    = fields.Selection([
        ('draft', 'Draft'), ('authorized', 'Authorized'), ('submitted', 'Submitted'),
        ('broadcast', 'Broadcast'), ('pending_finality', 'Pending finality'),
        ('final', 'Final'), ('disputed', 'Disputed'), ('compensated', 'Compensated'),
        ('failed', 'Failed'), ('expired', 'Expired')],
        required=True, default='draft', index=True)
    authorized_uid      = fields.Many2one('res.users', readonly=True)
    authorized_datetime = fields.Datetime(readonly=True)
    broadcast_datetime  = fields.Datetime(readonly=True)
    finality_datetime   = fields.Datetime(readonly=True, index=True)
    notified_datetime   = fields.Datetime(readonly=True, index=True)
    notify_error        = fields.Char()
    failure_code        = fields.Char(index=True)
    failure_reason      = fields.Char()

    # --- Ke toan, tach roi khoi settle_state ---
    gl_state        = fields.Selection([('not_required', 'No GL entry'),
                                        ('queued', 'Queued'), ('posted', 'Posted'),
                                        ('failed', 'Post failed'), ('reversed', 'Reversed')],
                                       required=True, default='not_required', index=True)
    gl_move_model   = fields.Char()
    gl_move_ref     = fields.Many2oneReference(model_field='gl_move_model')
    gl_error        = fields.Char()

    _unique_origin = models.Constraint(
        'UNIQUE(company_id, origin_producer, origin_key)',
        'origin_key phai duy nhat trong (company, producer).')
    _check_transport_chain = models.Constraint(
        "CHECK (transport <> 'onchain' OR chain_id IS NOT NULL)",
        'Settlement onchain phai co chain.')
    _check_amount_base = models.Constraint(
        "CHECK (amount_base ~ '^(0|[1-9][0-9]{0,77})$')",
        'amount_base phai la so nguyen khong dau toi da 78 chu so.')
    _origin_idx = models.Index('(origin_model, origin_id)')

    @api.constrains('risk_class')
    def _check_risk_class_no_downgrade(self):
        """R1-R4 nang len duoc, khong bao gio ha xuong (§C15.2)."""
        order = {'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4}
        for rec in self:
            prev = rec._origin.get('risk_class') if rec._origin else None
            if prev and order[rec.risk_class] < order[prev]:
                raise ValidationError(_('risk_class chi duoc nang len.'))
```

**Bảy thay đổi so với §10.4.8, tất cả đã chốt:**

1. `reversed` → **`compensated`**, thêm **`disputed`**. Sổ cái on-chain không có
   UNDO: một settlement mới, chiều ngược, `origin_key` riêng, tx riêng, trỏ về
   bản gốc bằng `compensation_of_id`. `reversal_of_id` và `_check_reversal` bị
   xoá (constraint đó đang canh một state mà state engine của §15 không bao giờ
   tới được).

   **`compensated` được ghi lên BẢN GỐC**, đúng lúc settlement bù trừ của nó đạt
   `final`. Bản 1 viết *"bản gốc vẫn `final` vĩnh viễn"* và đồng thời giữ
   `compensated` trong Selection bắt buộc, trong bảng §C12 (*"`compensated` (bản
   mới)"*) và trong bảng state dẫn xuất §C10.9 (→ `refunded`) — tức một state
   **không bao giờ có record nào ghi vào**. Chốt câu này thay:

   > Bản gốc chuyển `final → compensated`. Sự thật rằng nó *đã* xảy ra không
   > nằm ở `settle_state` mà ở **`compensation_of_id`** cộng dòng
   > `blockchain.settlement.log` mang `from_state = 'final'`. Đó là chỗ audit
   > trail sống, và nó sống ở đó chính xác vì `mail.thread` đã bị bỏ (§C1.2).

   `disputed` có lối ra, xem §C12.
2. Một cách viết: **`authorized_uid` / `authorized_datetime`**. §10's
   `authorize_uid`/`authorize_datetime` sẽ tạo một cặp cột thứ hai.
3. Thêm `gl_state` + 3 field kèm theo — tách kế toán khỏi vòng đời chain là
   quyết định quan trọng nhất của §15.4.4.
4. Thêm `batch_id`, `chunk_id`, `notified_datetime`, **`notify_error`**
   (`_notify_origin` đang viết vào nó mà chưa ai khai).
5. Thêm **`effect_id`** — không có nó, hướng đối soát (A) của §15.5.3
   (`LEFT JOIN ... ON s.effect_id = e.id`, "tiền chạy on-chain mà ta không biết
   vì sao") **không viết được**. Finality Gate là bên ghi nó, đúng lúc khớp
   `ref` của effect với settlement.
6. Bỏ `mail.thread` (§C1.2); `blockchain.settlement.log` thay thế.
7. Thêm **`risk_class`** (§C15.2 nói "nâng lên được cho từng settlement" mà
   schema bản 1 không có cột nào để nâng — chỉ `money.flow` và `relay.job` mang
   nó, tức lời hứa đó **không hiện thực hoá được**) và **`finality_grade`**
   (§C9.1 `soft_final_exposure` tính trên nó).

**`origin_producer` do server cấp, không bao giờ là tham số.** §10.13 Q6 để mở
và ghi nhận đúng hậu quả: nếu client tự khai, một client giả mạo được namespace
của client khác và **nuốt một settlement** — tức là tái tạo lại đúng con bug mà
field này tồn tại để chặn. Chốt: suy từ service account đang gọi (một record
`blockchain.producer` gắn với `self.env.user`).
Chữ ký method ở §10.6.4 đổi thành `blockchain_submit_settlement(origin_key, ...)`
**không có** `origin_producer`.
§06.9 (`UNIQUE(company_id, origin_ref)`) và §09.6
(`UNIQUE(company_id, origin_model, origin_ref)`) đổi sang cùng khoá ba phần.

**Facade không phải cánh cửa duy nhất, nên chốt phải nằm ở `create()`.**
§C14.1 cấp `perm_create` trên `blockchain.settlement` cho
`group_blockchain_operator`. Một operator có quyền đó gọi thẳng
`blockchain.settlement.create` qua `/web/dataset/call_kw` hoặc `/json/2` và
truyền `origin_producer` trong vals. **`readonly=True` trên field là một thuộc
tính UI** — nó không chặn một ORM write, và `_unique_origin` vui vẻ nhận
namespace giả. Đó đúng là con bug mà khoá ba phần tồn tại để đóng. Bỏ
`origin_key` ra khỏi facade **không đóng được nó**:

```python
@api.model_create_multi
def create(self, vals_list):
    producer = self.env.user._blockchain_producer_code()   # raise neu user khong co
    for vals in vals_list:
        vals['origin_producer'] = producer   # ghi de VO DIEU KIEN, bo gia tri client gui
    return super().create(vals_list)
```

Cùng khuôn với cách §C10.4 đã bảo vệ `settle_state` bằng sentinel cấp module.

**Hai test bắt buộc, không phải một:**

1. Cùng một `origin_key` gửi bởi hai service account khác nhau **qua facade**
   phải tạo **hai** settlement, không trả về cái đầu tiên.
2. `env['blockchain.settlement'].with_user(operator).create({'origin_producer':
   'other_service', ...})` phải hạ cánh với producer **của chính operator**,
   không phải `other_service`. Test 1 một mình pass trong khi lỗ vẫn mở.

**`origin_ref` phải chịu được một model vắng mặt.** `Reference.convert_to_cache`
tách `"model,id"` và, khi `validate=True` và `res_model` không nằm trong
`self.get_values(env)`, rơi thẳng xuống `raise ValueError`;
`convert_to_record` browse `record.env[res_model]`, tức `KeyError` cho một model
registry không có. Dòng mang `origin_model = 'dms.trade.settlement'` **tồn tại
trên mọi database từng chạy bridge**. Đọc dòng đó trên profile standalone —
đúng cái database mà required check `odoo-standalone` của §C3 tạo ra — hoặc sau
khi gỡ `dms`, và mở list hay form settlement là một **500 không bắt được**.
§15.3.1's `_notify_origin` được viết **có** guard
(`if not model or model not in rec.env`); field `Reference` ngay cạnh nó thì
không, và bản 1 chép đúng bản không guard vào khối chuẩn tắc. Chốt:

```python
def _compute_origin_ref(self):
    for rec in self:
        rec.origin_ref = (f'{rec.origin_model},{rec.origin_id}'
                          if rec.origin_model and rec.origin_id
                          and rec.origin_model in rec.env else False)

@api.model
def _selection_origin_ref(self):
    """Dung tu REGISTRY luc goi. Mot list tinh se lech voi tap model thuc su
    resolve duoc ngay khi mot bridge duoc cai hoac go."""
    return [(n, m._description) for n, m in self.env.registry.items()
            if issubclass(m, self.pool['blockchain.settlement.origin'])]
```

Test rẻ nhất chứng minh locked #7 đứng **lúc chạy** chứ không chỉ lúc cài nằm ở
§C3 (job `odoo-standalone`): `INSERT` một settlement với
`origin_model='dms.trade.settlement'` bằng SQL, rồi `search_read`.

**Cổng `final`:** `_set_finality()` là method private duy nhất được ghi
`final`, và điều kiện là §C9.4. Ép bằng sentinel `object()` cấp module trong
context (client chỉ gửi được JSON nên không giả mạo được), cộng ACL: `perm_write`
trên `blockchain.settlement` không bao giờ cấp cho `group_blockchain_viewer`.

### C10.5. `blockchain.metatx`

Giữ §10.4.5, với ba sửa:

- `mode_flags` CHECK theo §C8.2.
- Xoá `epoch`/`target_epoch` nếu có.
- `_one_open_lane` là **`models.UniqueIndex`** partial
  `WHERE metatx_state NOT IN ('expired','failed')` cộng
  `_unique_attempt = UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce, attempt_seq)`.
  UNIQUE tuyệt đối trên lane làm **không thể thử lại** một metatx hết hạn: hợp
  đồng chỉ tăng `meta_nonce` khi thực thi thành công, nên lane không bị tiêu, và
  lần thử thứ hai **bắt buộc** dùng lại đúng `batchNonce` đó.
- `_unique_digest = UNIQUE(chain_id, digest_hash)`. Cột tên là **`digest_hash`**;
  §04.12 và §5.8.2 đang viết `UNIQUE(metatx_digest)` — cột đó không tồn tại.
- `_unique_statement_period` và `_check_fee_base` **không thuộc model này**
  (§5.8.2 đặt nhầm chúng trong `class BlockchainMetatx`; `relayer_id` và
  `period_start_date` là field của `blockchain.relayer.statement`, nên
  PostgreSQL sẽ từ chối và module không cài được). Chuyển sang model của chúng.

**Lane 2D nonce suy từ ĐƠN VỊ VẬN CHUYỂN**, không từ `origin_key` của từng
settlement: một chunk 150 settlement là **một** metatx và do đó đúng **một**
`(batchId, batchNonce)`.

```python
unit_key = (f"chunk:{self.chunk_id.batch_id.origin_key}:{self.chunk_id.sequence}"
            if self.chunk_id else f"settlement:{self.origin_key}")
batch_id_hex = '0x' + keccak(f"{chain.caip2}|{company.id}|{unit_key}".encode()).hex()
```

### C10.6. `blockchain.transaction`, `blockchain.chain.event`, `blockchain.chain.effect`

`blockchain.transaction` giữ §10.4.6: không `size=` trên `tx_hash`, CHECK theo
`chain_family`, **không** ép lowercase toàn cục (CosmWasm dùng hoa), raw
receipt/trace vào `ir.attachment` trên Garage với retention 90 ngày (400 ngày
cho `reverted`/`orphaned`), chỉ `receipt_sha256` ở lại trong bảng vĩnh viễn.

`blockchain.chain.event` (§11) thay `blockchain.event`. Ba điều là chuẩn tắc:

- Khoá decoder là **`(chain, contract_address, topic0, block_range)`**, không
  bao giờ `topic0` một mình: `Transfer(address,address,uint256)` có cùng
  `topic0` trên mọi ERC-20 từng tồn tại. Bảng tra theo `topic0` trần chỉ được
  dùng để **đọc byte**, không bao giờ để ghi có tiền.
- `bamboo_uuid = uuid5(NS_CHAIN_EVENT, f"{caip2}|{block_hash}|{tx_hash}|{log_index}")`
  — khoá theo **block hash**, nên một reorg sinh một dòng khác, và đó là đúng:
  nó là một quan sát khác.
- Cursor là `position_key`, Char 64 zero-padded, **không `size=`**, không
  `Integer` (`Integer` là int4, TON `lt` ~5e10 và Hedera nanos ~1.7e18 tràn).

`blockchain.chain.effect`: khoá `bamboo_uuid = uuid5(NS_CHAIN_EFFECT, f"{caip2}|{ref}")`
— **hẹp có chủ ý**, không gồm `token` hay `amount`: cùng một `ref` với hai số
tiền khác nhau không phải hai effect, đó là một **sự cố**, và nó phải sinh
`blockchain.ref.collision`, không được biến thành hai bút toán im lặng.
`applied_state` là state machine riêng; `_apply()` phải idempotent theo
chính nó; `bamboo_create_idempotent` và `_apply()` nằm **trong cùng một
savepoint và cùng một COMMIT** — crash ở giữa hai cái đó làm tiền biến mất khỏi
sổ mà không có cảnh báo nào.

**`bamboo_create_idempotent` TRẢ VỀ, nó không raise — nên collision phải do
caller phát hiện.** Đã đọc `bamboo_idempotency/models/base.py:60-112`: khi gặp
`UniqueViolation`, method **không** re-raise; nó search lại theo uuid và, nếu
tìm thấy record thắng, trả `{'id': winner.id, 'created': False}` cộng một
`_logger.info`. Nó chỉ re-raise khi violation đến từ **một constraint khác**.
Nghĩa là quan sát thứ hai — cái mang một số tiền khác cho cùng một `ref` — bị
**âm thầm nhận vào effect đầu tiên rồi vứt đi**. Bản 1 của §C10.6 tin rằng nó
nhận một exception để biến thành `blockchain.ref.collision`; nó nhận một
`return` thành công. Sự cố mà canon thiết kế khoá hẹp để phơi ra trở thành **vô
hình**, trên chính bảng lái bút toán GL.

Chốt: caller **bắt buộc** rẽ nhánh trên `created is False`.

```python
res = self.env['blockchain.chain.effect'].sudo().bamboo_create_idempotent(vals, uid5)
if not res['created']:
    prior = self.env['blockchain.chain.effect'].sudo().browse(res['id'])
    if (prior.token_id != vals.get('token_id')
            or prior.amount_base != vals.get('amount_base')
            or prior.applied_state != vals.get('applied_state')):
        self.env['blockchain.ref.collision'].sudo().create({
            'effect_id': prior.id, 'caip2': vals['caip2'], 'ref': vals['ref'],
            'incoming_json': ...,      # metadata nho, KHONG phai anh/file
        })
```

Test bắt buộc đi kèm: cùng một `ref`, **hai số tiền khác nhau**, khẳng định
đúng **một** effect **và** đúng **một** `blockchain.ref.collision`. Văn bản bản 1
sẽ pass một test chỉ khẳng định nửa đầu.

**`chain_event_ingest` là RPC công khai và phải có gate quyền** (nó hiện không
có): `self.check_access('create')` cộng
`if not self.env.user.has_group('dms_blockchain.group_blockchain_indexer'): raise AccessError(...)`.
Docstring "event nạp qua đường này chỉ ở trạng thái `observed`, KHÔNG được đặt
`final`" **không phải một biện pháp**: `_cron_apply_effects` rút observed thành
effect, và dedup key là `(caip2, ref)`, nên một event giả với `ref` chưa dùng
trở thành một effect thật. Kèm theo: `blockchain.chain.event` phải có một dòng
`create` cho `group_blockchain_indexer` trong ACL — bảng ACL của §11 hiện nói
"không ai" có quyền đó, mâu thuẫn với chính sự tồn tại của endpoint.

### C10.7. Zether — `blockchain.zether.entry`

Một model duy nhất. `blockchain.zether.transfer` (§03.9.3 và §11.9, hai schema
khác nhau dưới một tên) bị xoá; field của cả hai gộp vào đây.

```python
class BlockchainZetherEntry(models.Model):
    _name = 'blockchain.zether.entry'
    _description = 'Confidential ledger entry'
    _order = 'id desc'                       # KHONG epoch_number

    company_id      = fields.Many2one('res.company', required=True, index=True,
                                      default=lambda s: s.env.company)
    token_id        = fields.Many2one('blockchain.token', required=True, index=True)
    account_id      = fields.Many2one('blockchain.zether.account', required=True, index=True)
    counterparty_id = fields.Many2one('blockchain.zether.account', index=True)
    direction       = fields.Selection([('deposit', 'Deposit'), ('withdraw', 'Withdraw'),
                                        ('transfer_in', 'Transfer in'),
                                        ('transfer_out', 'Transfer out'),
                                        ('rollover', 'Roll over'),
                                        ('fee', 'Relayer fee')],
                                       required=True, index=True)
    c_hex           = fields.Char(required=True)
    d_hex           = fields.Char(required=True)
    c_debit_hex     = fields.Char()
    c_aud_hex       = fields.Char()
    memo_hex        = fields.Char(help='AEAD memo 32 B. Nguon giai ma so tien (§C6.4).')
    zether_nonce    = fields.Integer(index=True)          # NULL cho huong inbound
    acc_seq         = fields.Integer(index=True)          # thay epoch_number
    pending_seq     = fields.Integer()
    attempt_no      = fields.Integer(required=True, default=0)
    fee_scaled      = fields.Char(default='0')
    proof_attachment_id = fields.Many2one('ir.attachment', ondelete='restrict')
    proof_sha256    = fields.Char(index=True)
    proof_bytes     = fields.Integer(readonly=True)
    attestation_attachment_ids = fields.Many2many('ir.attachment',
                                                  'bc_zether_entry_attest_rel')
    transaction_id  = fields.Many2one('blockchain.transaction', index=True)
    settlement_id   = fields.Many2one('blockchain.settlement', index=True)
    entry_state     = fields.Selection([('pending', 'Pending'), ('mined', 'Mined'),
                                        ('final', 'Final'), ('failed', 'Failed')],
                                       required=True, default='pending', index=True)
    amount_clear_base = fields.Char()
    amount_source   = fields.Selection([('none', 'Unknown'),
                                        ('memo_decrypted', 'Memo AEAD'),
                                        ('bsgs', 'BSGS cross-check'),
                                        ('counterparty_disclosed', 'Counterparty disclosed'),
                                        ('audit_key', 'Audit view key')],
                                       required=True, default='none', index=True)
    amount_verified = fields.Boolean(default=False,
        help='Da doi chieu amount_clear_base voi C_out bang 2 scalar mul.')

    _unique_attempt = models.Constraint(
        'UNIQUE(token_id, account_id, zether_nonce, attempt_no)',
        'Mot lan thu tren mot nonce chi duoc ghi mot lan.')
    _final_nonce_uniq = models.UniqueIndex(
        "(token_id, account_id, zether_nonce) WHERE entry_state = 'final' "
        "AND direction IN ('withdraw', 'transfer_out')",
        'Mot nonce Zether chi co dung mot lan chi tieu thanh cong.')
    _check_clear = models.Constraint(
        "CHECK (amount_source <> 'none' OR amount_clear_base IS NULL)",
        'amount_clear_base chi duoc dien khi co nguon giai ma.')
```

Vì sao không phải `UNIQUE(token_id, account_id, zether_nonce, direction)` của
§10.4.7: nó **chặn thử lại** một lần chi tiêu thất bại (§03.9.3 đã bác), và cột
`direction` trong khoá làm nó **quá yếu** (cùng nonce dùng lại được ở một
direction khác). Vì sao không phải `UNIQUE(token_id, account_id, zether_nonce)`
của §15: nó dựa vào NULL cho hướng inbound và vẫn chặn retry.

**Nhưng `_unique_attempt` cũng chứa `zether_nonce`, mà nó NULL cho hướng
inbound** — tức canon bản 1 bác constraint của §15 vì đúng lý do đó rồi ship
đúng cái lỗ đó. PostgreSQL coi NULL là **phân biệt** trong UNIQUE, nên
`deposit`, `transfer_in` và `fee` **không có dedup nào cả**: một replay của
indexer hay một quan sát lại sau reorg ghi có **hai lần** vào sổ cái bảo mật,
im lặng, trên đúng cái sổ không ai đọc được để kiểm. §C10.6 chỉ định khoá
`bamboo_uuid` cho `chain.event` và `chain.effect`, **không** cho
`zether.entry`, nên không gì khác phủ nó.

Chốt, cùng khuôn với §C10.6:

```python
bamboo_uuid = uuid5(NS_ZETHER_ENTRY,
                    f"{caip2}|{tx_hash}|{log_index}|{direction}|{account_id}")
```

Ghi bởi **`chain-indexer` qua `/json/2`, chạy `sudo()`** (§C11.10 — `search` đầy
đủ nên nó chịu record rule), trong cùng savepoint với `_apply()`. Hướng outbound
giữ nguyên `_unique_attempt` như một lớp thứ hai; hướng inbound dựa hoàn toàn
vào khoá này.

`amount_clear_base` rỗng **không phải lỗi** — một số dư bảo mật mà Odoo đọc
được rõ ràng là một lỗ hổng thiết kế. Mọi báo cáo đối soát phải chịu được cột
rỗng, và run đối soát báo **`partial`** thay vì `clean` khi có dòng như vậy.

`blockchain.zether.account` (§02.8.5) giữ nguyên trừ ba sửa đã nêu: bỏ
`custody_model`/`secret_ref` (§C10.2), `profile_id` → `chain_id` (§C9.1), và
curve-parametric (§C6.1). §03.9.4 dùng `_inherit = 'blockchain.zether.account'`
**không kèm `_name`** — mở lại một `_name` chỉ để treo ba method RPC làm người
đọc không biết class nào sở hữu field, và một lỗi gõ `_name` trong tương lai sẽ
tách model làm hai mà không báo lỗi.

### C10.8. `blockchain.relay.job` — một model, vừa outbox vừa attempt

Ba định nghĩa đang tồn tại (§06.9 attempt, §15.2.4 outbox row, §10.4.11
`blockchain.outbox.job`), hai trong số đó dùng **cùng một `_name`** với schema
rời rạc — Odoo sẽ gộp thành một bảng có **cả** `state` **và** `job_state`, và
một `_order` thắng im lặng.

**Chốt hai model, không phải ba:**

- `blockchain.metatx` = **phong bì EIP-1776 đã ký**, bất biến sau khi ký:
  digest, lane, mode, expiry, fee, `innerGasLimit`, chữ ký.
- `blockchain.relay.job` = **một đơn vị công việc của worker**, và `state='queued'`
  **chính là dòng outbox**. Nó được ghi trong **cùng transaction** với
  `settle_state='submitted'`.
- `blockchain.outbox.job` **bị xoá**. Hai dòng cho một hop nghĩa là hai state
  handoff, hai khoá dedup và hai chế độ hỏng; lập luận nguyên tử của §08.2b đã
  được thoả bằng một dòng.

Field gộp: `job_uuid`, `job_kind` (Selection, default `relay_metatx`),
`metatx_id`, `settlement_id`, `chunk_id`, `chain_id`, `company_id`,
`relayer_id`, `risk_class`, `priority`, `origin_producer`, **`origin_key`**,
`payload_attachment_id`, `payload_sha256`, `calldata_ref`, `raw_tx_ref`,
`nonce`, `nonce_gen`, `owner_fence`, `tx_hash`, `replaces_job_id`,
`sim_block_hash`, `sim_block_height`, `sim_gas`, `meta_nonce_block`,
`est_cost_uusd`, `actual_cost_uusd`, `l1_fee_base`, `claimed_by`,
`claimed_datetime`, `attempt_count`, `next_attempt_datetime`, `last_error`,
**`chain_state`**, **`business_state`**.

Một cột trạng thái chain (`chain_state`) cộng một cột trạng thái nghiệp vụ
(`business_state`) — **`job_state` của §15 bị xoá**. Xoá luôn
`zether_target_epoch`, `zether_epoch_deadline_block`, và state `epoch_expired`
(§C5.3). Xoá mọi `size=`. Xoá `bamboo_uuid = fields.Uuid(...)`: `fields.Uuid`
không phải là `odoo.fields.Uuid` (nó ở
`addons/bamboo_idempotency/models/fields.py:7`, một subclass của `fields.Char`),
viết như §15.2.4 sẽ raise `AttributeError` lúc import — và nó **thừa**, cột đến
từ `bamboo_idempotency` qua `_inherit = 'base'`.

Hai partial unique index, viết bằng `models.UniqueIndex`:

```python
_unique_origin = models.Constraint(
    'UNIQUE(company_id, origin_producer, origin_key)',
    'origin_key phai duy nhat trong (company, producer): day la khoa idempotency.')
_unique_nonce_live = models.UniqueIndex(
    "(relayer_id, nonce) WHERE chain_state IN "
    "('nonce_leased','signed','signed_orphan','broadcast','mined')",
    'Chi mot job song tren mot nonce cua mot relayer.')
```

**`origin_ref` của bản 1 đổi tên thành `origin_key`** (§C2.6): trên
`blockchain.settlement`, `origin_ref` là một `fields.Reference` trỏ record, và
hai nghĩa cho một tên trong cùng addon là chính con lỗi §C2.6 tuyên bố chỉ có
đúng một ngoại lệ. Khoá thành `UNIQUE(company_id, origin_producer, origin_key)`,
**khớp §C10.4 từng chữ**. Với job cấp chunk, `origin_key` giữ **`unit_key`** của
§C10.5 (`chunk:<batch.origin_key>:<sequence>`), không phải `origin_key` của một
settlement lẻ.

**Tập giá trị `chain_state`, chuẩn tắc, vì hai bảng đang lệch nhau:**
`queued`, `nonce_leased`, `signed`, **`signed_orphan`**, `broadcast`, `mined`,
`final`, `reverted`, `orphaned`, `dead`. `signed_orphan` xuất hiện trong vị từ
`_unique_nonce_live` ở trên nhưng **vắng mặt** ở bảng state §C12 — mà §C12 là
bảng Selection được sinh ra từ đó, nên một
`write({'chain_state': 'signed_orphan'})` sẽ raise. §C12 đã bổ sung hàng cho nó.

`models.Constraint("UNIQUE (col) WHERE ...")` của §06.9 **không phải cú pháp
`ALTER TABLE ADD CONSTRAINT` hợp lệ** và sẽ làm module fail lúc cài — nghĩa là
hai guard idempotency quan trọng nhất của relay pool đơn giản là **không tồn
tại**. Bước kiểm chứng trong §06.11 phải đọc **`pg_indexes`**, không phải
`pg_constraint`.

Worker claim bằng `SELECT ... FOR UPDATE SKIP LOCKED`, không bằng
`write({'chain_state': 'claimed'})` sau một search.

### C10.9. Lớp payment — `request`, `observation`, `quote`

`blockchain.payment.request` **không** bị gộp vào `blockchain.settlement`, và
lý do là vòng đời: một request có thể **hết hạn mà không có settlement nào**, và
một request có thể được trả **hai lần** (trả thiếu rồi trả bù, trả muộn sau khi
hết hạn). Đó là hai đối tượng có cardinality 1–n, không phải hai tên cho một thứ.

**Hợp đồng giữa hai model, viết một lần:**

- `blockchain.payment.request` là **chuyên biệt hoá cho luồng thu vào**
  (`direction = 'in'`): nó tồn tại **trước** khi có tiền.
- Mỗi lần quan sát tiền về sinh một `blockchain.payment.observation`; observation
  được chấp nhận sinh **một `blockchain.settlement` với `direction='in'`** và
  `payment_request_id` trỏ ngược.
- **Finality Gate lái `blockchain.settlement.settle_state`.** `request_state` là
  hàm dẫn xuất từ tập settlement của nó, không phải một state machine song song
  do ai đó ghi tay.
- **`_set_done()` là một hàm của TỔNG, không phải của một settlement.** Bản 1
  viết *"`payment.transaction._set_done()` chỉ được gọi từ settlement đạt
  `final`"*, mà bảng ngay dưới nói `final` (thiếu số tiền) →
  `request_state = 'partial'`, `payment.transaction = 'pending'`. Hai câu không
  cùng đúng được. Và chính §C10.9 nói một request trả **hai lần** được (trả
  thiếu rồi trả bù), nên cổng thật là một tổng. Chốt:

  ```python
  #  blockchain.payment.request.amount_settled_base : Char uint256, compute,
  #  store=True, index — TONG chay cua request. Finality Gate ghi lai no trong
  #  cung transaction voi settle_state. Stored compute ⇒ KHONG default= (§C11.6).
  def _payment_gate(self):
      self.ensure_one()
      finals = self.settlement_ids.filtered(lambda s: s.settle_state == 'final')
      return (all(s._finality_gate_ok() for s in finals)          # §C9.4 cho tung cai
              and int(self.amount_settled_base) >= int(self.amount_base))
  ```

  `_set_done()` chạy khi và chỉ khi `_payment_gate()` True. Một settlement
  `final` lẻ **không** đủ.
- **Trả bù đến sau `expiry_datetime`.** Settlement `final` sớm hơn **giữ nguyên
  `final`** — chúng đã xảy ra, và §C10.4 không cho phép ghi ngược. Cái thay đổi
  là `request_state`: nó đi `partial → expired` lúc hết hạn, rồi **`expired →
  final`** khi tổng đủ, và `_set_done()` chạy khi đó. `payment.transaction` đi
  `pending → done` chứ không qua `cancel`; nếu nó đã bị đặt `cancel` thì
  `_set_done` **không làm gì** (cùng cơ chế `allowed_states` như `_set_error`
  dưới đây), nên `expiry_datetime` **không được** tự động `cancel` một
  transaction có settlement `final` nào. Đó là điều kiện phải viết vào cron hết
  hạn, không phải một trường hợp biên bỏ ngỏ.
- `payment.transaction._set_done()` **không bao giờ** được gọi từ một settlement
  có `finality_grade = 'soft'` — §C9.4 điều kiện (5) chặn ở đầu nguồn.

| `settle_state` | `request_state` dẫn xuất | `payment.transaction.state` | `chain.effect.applied_state` |
|---|---|---|---|
| — (chưa có settlement) | `open` | `pending` | — |
| `submitted` / `broadcast` | `seen` | `pending` | `pending` |
| `pending_finality` | `mined` | `pending` | `pending` |
| `final` (đủ số tiền) | `final` | **`done`** | `applied` |
| `final` (thiếu số tiền) | `partial` | `pending` | `applied` |
| `failed` / `expired` | `expired` | `error` / `cancel` | `failed` |
| `disputed` | `disputed` | **giữ `done`** — xem dưới | `applied` |
| `compensated` | `refunded` | `done` + một tx hoàn tiền riêng | `applied` |

Dòng `disputed` là chỗ dễ sai nhất và nó đã được kiểm: `payment.transaction._set_error`
có `allowed_states = ('draft','pending','authorized')` — **`done` không nằm
trong đó**, và `_update_state` chỉ log warning rồi bỏ qua khi state nguồn sai.
Nghĩa là sau một reorg, `_set_error` trên một tx đã `done` **không làm gì và
không ai biết**. Hệ quả bắt buộc, viết lại cho khớp §C9.4:

> **Finality Gate dùng ngưỡng `hard` cho mọi flow gắn với một
> `payment.transaction`; flow soft-final KHÔNG được gắn với một cái nào.**

Bản 1 viết *"Finality Gate dùng ngưỡng hard"* trơn, mà §C9.4 lại cho phép `final`
(và do đó `_set_done`) từ soft finality ở ≤ 5,000,000 ₫ và lớp rủi ro ≤ r2, còn
§C15.2 đặt `LOYALTY_ACCRUE`, `LOYALTY_REDEEM`, `OUTLET_COLLECT` đúng vào ô đó —
tức chế độ hỏng mà câu này nói đã được ngăn thì lại **với tới được trên gần như
toàn bộ khối lượng ra mắt**. Ranh giới đúng là *payment-bound*, không phải lớp
rủi ro; §C9.4 điều kiện (5) và danh sách flow payment-bound nằm ở đó.

`_on_reorg` **sinh một giao dịch hoàn tiền / bút toán đảo**, không đổi trạng thái.

Ba model này phải được **khai đầy đủ trong §09** (hiện chúng được gọi tên mà
chưa bao giờ có `_name`, field list hay Selection): `blockchain.payment.request`
(`request_uuid`, `flow_code`, `receiving_address`, `ref_display`, `ref32`,
`amount_base`, **`amount_settled_base`**, `amount_fiat`, `quote_id`,
`expiry_datetime`, `request_state`, `company_id`),
`blockchain.payment.observation` (`request_id`, `effect_id`, `amount_base`,
`from_address`, `observed_datetime`, `retry_count`, `observation_state`),
`blockchain.payment.quote` (tỷ giá lưu dạng **hai số nguyên**
`rate_numerator`/`rate_denominator` Char, không Float; `rate_source` bắt buộc;
`quote_validity_seconds` mặc định 900 cho cặp fiat-stablecoin, 120 cho token
biến động).

**`eip681_uri` và `wc_uri` bị xoá.** Chúng chỉ tồn tại cho đường end-user thanh
toán **on-chain** — ví người dùng cuối quét một URI và ký — mà §C18 đã descope
ứng dụng ví và mặt POS, và §C16 chốt `ENDUSER_PAY` chạy hình thái **M12/M1**
(chain ghi nhận, VietQR/thẻ thu tiền). Không luồng nào còn lại render chúng, nên
giữ lại là hai cột chết trên bảng nóng nhất của lớp payment. Nếu ví on-chain
quay lại sau 24 tháng thì chúng quay lại cùng nó.

Interface handler: mọi method là **`_on_observation` / `_on_final` / `_on_reorg`
private**; facade public duy nhất là `payment_request_open(...)` và nó **không
nhận `company_id` hay `allowed_company_ids` từ client**. Một method public trên
một Odoo model **là một RPC endpoint** — `on_final(...)` public nghĩa là bất kỳ
user có ACL read cũng ép được một `_set_done`.

---

## C11. Idiom Odoo 19 bắt buộc

Danh sách này là **luật**, không phải khuyến nghị, và mỗi mục có một CI guard.

### C11.1. `models.Constraint`, không bao giờ list `_sql_constraints`

Odoo 19 **bỏ qua hoàn toàn** `_sql_constraints = [(name, definition, message)]`:
constraint **không bao giờ được tạo trong PostgreSQL**. Kiểm bằng SQL, đừng tin
code: `SELECT conname FROM pg_constraint WHERE conrelid = '<table>'::regclass;`

### C11.2. `models.UniqueIndex` / `models.Index` tồn tại — dùng chúng

Đã kiểm trên source: `odoo/orm/table_objects.py`, class `Constraint`,
`Index` (dòng 125), `UniqueIndex` (dòng 185). Ba nơi đang khẳng định điều ngược
lại và tự chế workaround, **cả ba phải xoá**:

| Nơi | Workaround sai | Thay bằng |
|---|---|---|
| §04.3 | cột sentinel nullable `lane_slot` + `UNIQUE NULLS NOT DISTINCT` | `models.UniqueIndex` partial (§C10.5) |
| §5.4.3, §03.9.3, §15.3.1 | `CREATE UNIQUE INDEX ... WHERE` trong `init()` | `models.UniqueIndex` / `models.Index` |
| §06.9, §06.5 | `models.Constraint("UNIQUE (col) WHERE ...")` — không phải cú pháp hợp lệ, module fail lúc cài | `models.UniqueIndex` (§C10.8) |

Index tạo trong `init()` **không** được TableObject theo dõi: nó không bao giờ
bị drop-and-recreate khi mệnh đề `WHERE` đổi, nên một lần siết predicate về sau
để lại index cũ và constraint **âm thầm có nghĩa khác code**.

Kiểm chứng: constraint đọc `pg_constraint`, index đọc **`pg_indexes`**.

### C11.3. `models.Constraint` drop-and-recreate ⇒ mọi lần siết cần migration

`ADD CONSTRAINT` fail trên dữ liệu cũ vi phạm. Danh sách thay đổi **bắt buộc có
pre-migration dọn dữ liệu trước**: siết một CHECK, thêm `required=True` vào cột
đã có, đổi tên model hoặc field, thu hẹp một Selection.

**Chính sách migration (chưa section nào sở hữu):**
`dms_blockchain/migrations/<version>/pre-*.py` và `post-*.py`; bump version ở
chữ số thứ tư cho mọi thay đổi chạm schema; **đường từ M0 sang P04 là drop và
seed lại**, không phải upgrade — M0 được đánh dấu THROWAWAY (§16.2) và điều đó
phải được viết ra để không ai lên kế hoạch nâng cấp một database pilot.

### C11.4. uint256

Không field số nào của Odoo chứa được `2^256 - 1` (`Integer` là int4/int8,
`Float` mất chính xác từ `2^53`). Chốt: `Char` + CHECK
**`'^(0|[1-9][0-9]{0,77})$'`** — regex này **chặn số 0 dẫn đầu**, nếu không
`'007'` và `'7'` là hai khoá cho cùng một số và mọi dedup vỡ. §01's
`_check_maxsupply` và §05's `_check_fee_base` đang dùng `'^[0-9]{1,78}$'` —
sửa cả hai. Bản hiển thị là `Float(digits=(38, 18))`, không `(24, 8)`
(§05's `net_display` dùng cho đối soát lợi nhuận relayer sẽ làm 1 wei của một
token 18 decimals biến mất ở tầng rounding). `SUM()` trên cột `Char` cần một
expression index trên `(amount_base::numeric)`.

### C11.5. `fields.Char(size=N)` bị cấm tuyệt đối

`size=N` là **hai** chế độ hỏng, không phải một — bản 1 mô tả sai đúng cái nửa
nó tuyên bố đã kiểm trên source, và một reviewer đi kiểm sẽ chiết khấu phần còn
lại của §C11:

1. **Cột là `varchar(N)` thật.** `odoo/orm/fields_textual.py:492`:
   `return ('varchar', pg_varchar(self.size))`, và `odoo/tools/sql.py:638-651`
   phát `VARCHAR(n)` cho mọi size khác 0. **Không** phải "VARCHAR không giới hạn"
   như bản 1 viết. Nới nó ra về sau là một **migration DDL**.
2. **`convert_to_cache` cắt chuỗi im lặng** (`fields_textual.py:110`:
   `value = s[:self.size]`). Nửa này bản 1 đúng.

Hai cái cộng lại làm lệnh ghi **mất dữ liệu trước khi Postgres nhìn thấy nó**, và
điều đó **siết** lệnh cấm chứ không nới. Ví dụ `contract_address` phải đọc lại
theo đó: một địa chỉ Sui 66 ký tự trên `size=42` **không** chỉ bị lưu ngắn — bản
ghi đã lossy ngay ở tầng ORM, không có lỗi, rồi
`UNIQUE(chain_id, contract_address)` vui vẻ nhận hai token khác nhau là một.

28 khai báo còn lại ở sáu section phải bỏ. Hai cái nguy hiểm thật:
`blockchain.token.contract_address` với `size=42` trên một model mà `chain_id`
có thể trỏ Sui (66) hoặc TON (48); `blockchain.index.cursor.position_key` với
`size=64` đúng bằng độ dài format của §11.2, nên ký tự thứ 65 làm mất thứ tự
watermark im lặng.

### C11.6. Stored computed field không nhận `default=`

`default=` trên computed field là **inert**. Cột `required=True` chỉ được bảo vệ
bởi việc compute gán trên **mọi** nhánh — một nhánh không gán đặt NULL vào cột
required và INSERT chết. Xoá `default=` khỏi mọi stored compute ở §02
(`divergent`), §05 (`net_base`, `net_display`), §06 (`runway_hours`, hai nơi),
§07 (`can_prove_zether`, `can_decrypt` — khai báo này nằm ngay dưới chính lời
cảnh báo của nó), §15 (`line_count`, `total_base`, `settled_count`,
`failed_count`, `drift_base`).

### C11.7. Bí mật

- **`password=True` không tồn tại ở Odoo 19** và chưa bao giờ chặn
  `read()`/RPC/export.
- Bảo vệ cột duy nhất là **`field.groups` trong định nghĩa field**. Record rule
  lọc **dòng**. Ở Odoo 19, `read(['signer_ref'])`, `search_read` và domain trên
  field bị chặn đều **raise `AccessError`**, và `groups` **đi theo qua related
  và `_inherits`**.
- **URL là bí mật khi nó nhúng API key.** `blockchain.rpc.endpoint` không có
  field `url`; `endpoint_ref` là tên khoá. Giá trị thật nằm trong **biến môi
  trường của worker**, không trong `ir_config_parameter` — bảng đó nằm trong mọi
  bản backup và đọc được bởi mọi `group_system`, và §12.6.1 chỉ ra
  `base.group_system` tương đương RCE trong process Odoo.
- **`tracking=True` bị cấm trên mọi field mang tham chiếu bí mật**:
  `mail_message` bỏ qua `field.groups`. §07.12.1's
  `endpoint_url = fields.Char(required=True, tracking=True)` trên
  `blockchain.custody.provider` — địa chỉ của dịch vụ giữ khoá ký, trên một
  record, và mọi lần đổi được sao vào `mail_message` — đổi thành
  `endpoint_ref = fields.Char(required=True)` không tracking.

### C11.8. `ir.cron`

Eval context **không có `fields`, không có `relativedelta`**; body nằm trong
method của model, XML chỉ gọi một dòng. `_toggle_crons()` cần `.sudo()`
(`ir.cron` chỉ cho `base.group_system`). Mỗi cron tự giới hạn lô, `cr.commit()`
theo từng bản ghi hoặc từng chunk, và gọi `_trigger()` khi đầy lô. Guarantee
"không chồng lấn" là một row lock **không phủ** một method RPC quét cùng dữ
liệu — cần `pg_try_advisory_xact_lock`. `limit_time_real_cron` giết backfill dài
— cần deadline wall-clock ~50 s. **Interval là tối thiểu, không phải lịch**:
SLA phải đọc `scan_datetime`, không đọc interval.

### C11.9. RPC

Method công khai không bắt đầu bằng `_`, không mang `@api.private`, phục vụ cả
`call_kw` và `/json/2`. `/json/2` chỉ nhận **kwargs**. `@api.readonly` trên mọi
method chỉ đọc (nó quyết định cursor read-only, có thể trỏ replica). Lỗi trả về
khác nhau giữa hai đường (`UserError` → 200+JSON-RPC error trên `call_kw`,
**422** trên `/json/2`; `AccessError` 403, `MissingError` 404, `LockError` 409),
nên client phải biết cả hai.

Quy tắc company, viết đúng: **không nhận `company_id` làm tham số method**, và
không `sudo()` một method resolve company từ context. Quy tắc "không nhận
`allowed_company_ids`" như bản 1 viết là **không thực thi được** (`/json/2`
truyền `context` vào `with_context()`), nhưng nó **an toàn** vì
`environments.py:266-272` raise `AccessError` khi client xin một company ngoài
`user._get_company_ids()`.

### C11.10. `bamboo_idempotency`

Cột là **`uuid` native của Postgres** ⇒ truyền chuỗi UUID chuẩn
(`uuid.uuid5(ns, key)`), không phải hex digest. **Không redeclare `bamboo_uuid`**
— nó đến từ `_inherit = 'base'`. `_bamboo_uuid_enforced()` là một truy vấn
`pg_indexes` thật; index vắng mặt ⇒ `bamboo_create_idempotent` **raise
`UserError`**, tức một cron **chết** chứ không chạy chậm — test phải bắt điều
này lúc install. `bamboo_create_idempotent` chạy một ORM `search` đầy đủ nên nó
**chịu record rule** ⇒ **indexer chạy `sudo()`**, và điều đó phải được viết ra.
`UniqueViolation` có thể đến từ constraint khác — caller phải phân loại, không
`except Exception: pass`.

### C11.11. Ba CI guard tier 0 bổ sung

```bash
grep -rnE 'fields\.Char\([^)]*size\s*=' dms_blockchain/ && exit 1
grep -rnE 'compute=.*store=True.*default=|default=.*compute=.*store=True' dms_blockchain/ && exit 1
grep -rn 'blockchain\.chain\.profile' dms_blockchain/ docs/ && exit 1
```

cộng ba guard đã có ở §14 (list `_sql_constraints`, `child_of` trên
`parent_path`, tên field trùng kiểu Odoo), cộng regex uint256 sai
(`'^[0-9]{1,78}$'`), cộng hai gate registry/ACL ở §C10.1.

---

## C12. State machine — một bảng cho tất cả

Năm đối tượng phải chuyển trạng thái đồng bộ. Đây là ánh xạ, và nó thay năm
bảng `_ALLOWED` rời rạc hiện có.

| Pha | `blockchain.settlement` | `blockchain.metatx` | `blockchain.relay.job` (`chain_state` / `business_state`) | `blockchain.payment.request` | `payment.transaction` |
|---|---|---|---|---|---|
| Khởi tạo | `draft` | `draft` | — | `open` | `draft` |
| Đã duyệt | `authorized` | `simulated` → `signed` | — | `open` | `pending` |
| Đã đẩy ra outbox | `submitted` | `published` | `queued` / `pending` | `open` | `pending` |
| Relayer nhận | `submitted` | `claimed` | `nonce_leased` → `signed` / `pending` | `seen` | `pending` |
| Đã phát sóng | `broadcast` | `claimed` | `broadcast` / `pending` | `seen` | `pending` |
| Đã vào block | `pending_finality` | `mined` | `mined` / `pending` | `mined` | `pending` |
| **Final trên chain + nghiệp vụ OK** | **`final`** | `final` | `final` / **`success`** | `final` | **`done`** |
| Final trên chain, nghiệp vụ thất bại (swallow) | `failed` | `final` | `final` / **`failed`** | `open` | `error` |
| Revert (bubble) | `failed` | `failed` | `reverted` / `failed` | `open` | `error` |
| Hết hạn không ai nhận | `expired` | `expired` | `dead` / `pending` | `expired` | `cancel` |
| **Ký xong, nonce mồ côi** (relayer đổi nonce trước broadcast) | không đổi | `signed` | **`signed_orphan`** / `pending` | không đổi | không đổi |
| Reorg sau final | **`disputed`** | `final` | `orphaned` / `success` | `disputed` | **giữ `done`** |
| **Dispute: chain tái bao gồm** | `disputed` → **`final`** | `final` | `final` / `success` | `final` | `done` |
| **Dispute: đã ghi bút toán đảo** | `disputed` → **`compensated`** | `final` | `orphaned` / `success` | `refunded` | `done` + tx hoàn tiền riêng |
| Đã bù trừ (đường bình thường, không qua dispute) | **`final` → `compensated`** trên **bản gốc**, khi settlement bù trừ đạt `final` | — | — | `refunded` | tx hoàn tiền riêng |
| `transport = 'offset'` đạt cổng netting (§C9.4) | `pending_finality` → **`final`** | — | — | — | — |
| `transport = 'external'` đạt cổng fiat + anchor (§C9.4) | `pending_finality` → **`final`** | — | — | `final` | `done` |

**Quy tắc duy nhất, và nó là nguyên tắc `dms_vietqr` viết bằng code:**

> `payment.transaction._set_done()` yêu cầu **`_payment_gate()`** của §C10.9 —
> tổng các settlement `final` của request `>= amount_base` **AND** §C9.4 đúng
> cho từng cái. Với `transport = 'onchain'` điều đó bao gồm
> `chain_state == 'final'` **AND** `business_state == 'success'`; với `'offset'`
> nó đọc `netting_set_id.state`; với `'external'` nó đọc observation + anchor.
> `broadcast` không phải là thanh toán. `mined` cũng không.

**`disputed` có lối ra, và bản 1 không cho nó lối nào.** Vào bằng một reorg sau
`final`; ra bằng **`blockchain_resolve_dispute(resolution)`** (nhóm treasury +
auditor), và `resolution` chỉ nhận hai giá trị, mỗi cái hạ cánh trên một state
**có tên**:

| `resolution` | Điều kiện | State đích |
|---|---|---|
| `reincluded` | tx quay lại một block canonical, §C9.4 đúng lại | **`final`** |
| `compensated` | đã tạo settlement bù trừ và nó đạt `final` | **`compensated`** |

Không có nhánh thứ ba, và **không** có nhánh "để nguyên". Một settlement kẹt ở
`disputed` với `payment.transaction` vẫn `done` là tiền đã ghi nhận mà không ai
sở hữu quyết định — đúng thứ §C12 tồn tại để cấm. Không bút toán nào tự động bị
đảo **trên tín hiệu reorg**; việc đảo xảy ra khi một con người chọn
`resolution = 'compensated'`.

Xoá: 13-state machine của §06.2.6 (`epoch_expired` biến mất theo §C5; các state
còn lại gộp vào `chain_state`), state `reversed` của §10.4.8, `job_state` của
§15.2.4.

---

## C13. Odoo ↔ worker: transactional outbox, không có gì khác

Ba thiết kế đang cùng được trình bày như đã chốt. Chốt **§08.2b**:

1. Odoo ghi **một dòng `blockchain.relay.job`** trong **cùng transaction** với
   `settle_state = 'submitted'`. Không có gì khác xảy ra trong transaction đó.
2. Worker **poll Postgres** bằng `SELECT ... FOR UPDATE SKIP LOCKED`.
3. Worker báo ngược qua **`/json/2`** với một service JWT
   (`group_blockchain_relay_worker`).
4. `ir.cron` chỉ để **reconcile** (job `queued` quá lâu, job `broadcast` không
   có receipt), không phải để dispatch.
5. **Odoo không bao giờ mở socket ra ngoài trong một transaction nghiệp vụ.**

**Một quy tắc cho mỗi chiều — bản 1 có ba mô tả loại trừ nhau** (grant SQL trực
tiếp ở §C4, `/json/2` ở §C13.3, cron `sudo()` trong Odoo ở §C10.6/§C11.10), và
người xây P06/P11 phải biết một state transition là câu SQL hay lời gọi RPC vì
hai thứ có tính nguyên tử khác nhau:

| Chiều | Đường | Ai |
|---|---|---|
| **Đọc** hàng đợi, đọc metatx, đọc chain state | kết nối Postgres **trực tiếp**, `SELECT` | `bc_relay`, `bc_indexer`, `bc_hub` |
| **Claim** một job | cùng kết nối đó, `SELECT … FOR UPDATE SKIP LOCKED` — lock giữ trong transaction của worker, không ghi cột nào | `bc_relay` |
| **Mọi ghi**: đổi `chain_state`, đổi `business_state`, tạo `chain.event` / `chain.effect` / `zether.entry` / `block.header`, cập nhật `transaction` | **`/json/2`** với service JWT | `group_blockchain_relay_worker`, `group_blockchain_indexer` |

Hệ quả về hạ tầng: §C4 hạ ba DB role xuống **SELECT-only cộng row lock**, và các
grant INSERT/UPDATE **bị xoá**.

`sudo()` ở §C10.6/§C11.10 **không phải một đường thứ tư**: nó là điều xảy ra
**bên trong** Odoo sau khi lời gọi `/json/2` đã tới, và nó cần thiết vì
`bamboo_create_idempotent` chạy một ORM `search` đầy đủ nên nó chịu record rule.
Đường vào vẫn là RPC.

Lý do là tính nguyên tử, và nó là lý do duy nhất cần thiết: một `requests.post`
trong transaction cho ra hai lỗi không sửa được — tx đã broadcast mà Odoo
rollback (không có bản ghi nào), hoặc worker nhận rồi timeout và cron thử lại
(hai transaction trên một sổ cái không có UNDO).

**Xoá:** Redis Stream `bc:jobs:{caip2}` làm đường dispatch (§06.0.1) — Redis
được phép làm **một tín hiệu đánh thức thuần tuý**, không bao giờ là bản ghi;
`requests.post` từ cron (§10.4.11); HTTP callback `relay_report_batch` như một
đường riêng (nó trở thành một method RPC bình thường trên `/json/2`).

**Redis giữ đúng hai việc**, nơi nó thật sự cần: nonce lease (Lua script
nguyên tử, `appendfsync always`) và velocity bucket. Redis **không thể** là sự
thật về nonce: AOF everysec mất 1 s ghi, replica async roll back khi failover.
Chain là sự thật, Postgres là journal, Redis là cache — và phải có giao thức
cold start bắt buộc tái tạo `next` từ
`max(getTransactionCount(pending), max_signed_nonce_in_journal + 1)` cộng một
generation counter `gen` làm fencing thật.

---

## C14. Nhóm quyền, ACL, và bề mặt RPC

### C14.1. Mười nhóm — danh sách đóng

| XML id | Được gì | `implied_ids` |
|---|---|---|
| `group_blockchain_viewer` | đọc settlement/transaction/event của công ty mình; **không** thấy `signer_ref`, không thấy account `treasury`/`relay`/`admin` | |
| `group_blockchain_operator` | tạo settlement, retry job thất bại, đọc metatx | viewer |
| `group_blockchain_approver` | duyệt `blockchain.approval.request`. **Không** tạo settlement | viewer |
| `group_blockchain_treasury` | `blockchain_authorize_payout`, `withdraw` Zether, nạp quỹ relayer, `blockchain_resolve_dispute` | operator |
| `group_blockchain_relayer_admin` | CRUD `blockchain.relayer`, đổi `allowlist_state` | operator |
| `group_blockchain_compliance` | `freeze()`, `blockchain.travel.rule.message`, `blockchain.erasure.log` | viewer |
| `group_blockchain_manager` | CRUD chain, endpoint, deployment, token, custody config, cron | treasury + relayer_admin + approver |
| `group_blockchain_auditor` | đọc **tất cả** trong `env.companies` kể cả zether entry và proof; ghi **chỉ** `blockchain.audit.disclosure` | |
| `group_blockchain_indexer` | service account: `create` trên `chain.event` / `chain.effect` / `block.header`, `write` trên `transaction` | |
| `group_blockchain_relay_worker` | service account: `read`/`write` trên `blockchain.relay.job`, `read` trên `blockchain.metatx` | |

Ánh xạ tên cũ: `treasury_manager` → `treasury`; `blockchain_user` → `viewer`;
`key_admin` → `manager`; `group_relay_submitter` (§12.6) → `operator`;
`blockchain_operator`/`blockchain_manager` không prefix (§07, §11) → thêm prefix.

Hai điểm không được gộp lại: **`approver` không kế thừa `operator`** (nếu kế
thừa thì một người vừa tạo vừa duyệt và maker-checker thành trang trí);
**`indexer` và `relay_worker` là hai nhóm** vì chúng là hai process với hai bề
mặt ghi khác nhau, và §12 xếp chúng thành hai đối thủ riêng (A10, A11) — một
nhóm chung cho phép một indexer bị chiếm ghi được relay job.

`group_blockchain_manager` kế thừa `treasury`: đó là **một mặc định phải được
đọc và chọn**, không phải một tai nạn. Tổ chức có kiểm toán nội bộ bỏ `treasury`
khỏi `implied_ids`.

Con số **mười** ở tiêu đề có tải trọng: §C14.1 tuyên bố danh sách đóng, ACL CSV
được **sinh lại từ bảng C10.1**, và test allowlist bắt buộc của §12.6.2 viết đối
chiếu hai bảng này. Bản 1 viết "chín" và liệt kê mười — một generator hay một
reviewer tin con số thay vì đếm hàng sẽ **rơi mất một nhóm**, và hai nhóm dễ rơi
nhất đúng là hai service account mà canon nhấn phải tách riêng. Vì vậy con số
**không** được để ở dạng văn xuôi: **gate tier-0 #4 của §C10.1** khẳng định số
hàng bảng nhóm khớp số XML id `res.groups` được khai, và fail build khi lệch.

ACL CSV **sinh lại từ bảng C10.1**, không gõ tay: ~55 model **cụ thể** (ba
AbstractModel mang `ACL: n/a` và không sinh dòng nào), không phải ~20.
Một model không có dòng ACL là model không ai truy cập được trừ superuser, và
Odoo chỉ log warning — CI gate ở §C10.1 biến nó thành lỗi.

#### Bảng record rule — một hàng cho mỗi model có `company_id`

Một ma trận nhóm quyền không có bảng này là **một nửa mô hình bảo mật**: §C14.1
nói viewer thấy "settlement/transaction/event của công ty mình" và auditor đọc
"tất cả trong `env.companies`", mà một `ir.rule` cần một **domain**, và bản 1 để
`blockchain.transaction`, `blockchain.chain.event` và `blockchain.metatx` **không
có `company_id` và không có quan hệ nghịch tới settlement** — tức không có gì để
lọc. `blockchain.metatx` được chú "suy từ settlement", nhưng
`blockchain.settlement.metatx_id` là Many2one **không khai One2many nghịch đảo**,
nên ngay cả domain traversal `[('settlement_ids.company_id', 'in', ...)]` cũng
không viết được. Trên một deployment đa công ty, hệ quả là mọi user có nhóm
viewer đọc được tx hash, chain event đã decode và **phong bì EIP-1776 đã ký** của
mọi công ty — kể cả những cái nối tới `blockchain.zether.entry`, mà entry thì
canon **có** scope theo công ty. Hàng sổ cái bảo mật được bảo vệ, còn giao dịch
nó trỏ tới thì không.

Chốt: **thêm `company_id` vào cả ba** (§C10.1 đã sửa), thay vì đi đường
traversal. Ghi bởi Finality Gate / relay worker, lấy từ settlement sinh ra chúng.

| Model | XML id rule | Domain | Nhóm |
|---|---|---|---|
| `blockchain.settlement` | `rule_settlement_company` | `[('company_id','in',company_ids)]` | viewer, operator, approver, treasury, manager |
| **`blockchain.settlement.log`** | `rule_settlement_log_company` | `[('company_id','in',company_ids)]` | như trên — nó là audit trail **duy nhất** sau khi bỏ `mail.thread`, và timing `from_state`/`to_state` trên `disputed`/`compensated` hàm ý số tiền |
| `blockchain.transaction` | `rule_transaction_company` | `[('company_id','in',company_ids)]` | viewer + |
| `blockchain.chain.event` | `rule_chain_event_company` | `[('company_id','in',company_ids)]` | viewer + |
| `blockchain.metatx` | `rule_metatx_company` | `[('company_id','in',company_ids)]` | operator + |
| `blockchain.chain.effect` | `rule_chain_effect_company` | `[('company_id','in',company_ids)]` | viewer + |
| `blockchain.zether.entry` | `rule_zether_entry_company` | `[('company_id','in',company_ids)]` | treasury, auditor |
| `blockchain.relay.job` | `rule_relay_job_company` | `[('company_id','in',company_ids)]` | operator, relay_worker |
| `blockchain.account` | `rule_account_company` | `[('company_id','in',company_ids)]` | viewer + — **và rule của `blockchain.relayer.account` viết ở ĐÂY**, không trên con (§C10.3) |
| `blockchain.token` | `rule_token_company` | `[('company_ids','in',company_ids),('company_ids','=',False)]` (OR) | viewer + — **và rule của `blockchain.zether.token` viết ở ĐÂY** |
| mọi model còn lại có `company_id` = "có" ở §C10.1 | `rule_<model_short>_company` | `[('company_id','in',company_ids)]` | theo cột "Được gì" |

`group_blockchain_auditor` nhận một rule riêng `domain = [(1,'=',1)]` giới hạn
bởi chính `env.companies`, `perm_read` only.

### C14.2. Bề mặt RPC là một allowlist sinh ra

§10.6.1 trở thành **bảng đầy đủ**, một dòng cho mỗi method công khai, với cột:
model, method, `@api.readonly`, nhóm tối thiểu, shape request/response, và
**có nằm trên đường tiền hay không**. **Hai mươi mốt** method đang được định
nghĩa ở section khác mà bảng chưa có: `zether_account_bootstrap`,
`zether_view_accounts`, `zether_transfer_history`, `zether_history_page`,
`zether_submit_signed`, `metatx_build`, `metatx_quote`, `metatx_status`,
`relay_submit_intent`, `relay_job_status`, `relay_cancel_intent`,
`relay_report_batch`, `custody_probe`, `payment_request_open`, `chain_preflight`,
`chain_event_ingest`, `chain_effect_status`, `chain_finality_state`,
`blockchain_erase_subject`, `blockchain_check_abi_matches_chain`, và
**`blockchain_get_context`**.

`blockchain_get_context` là method mà test §14.11 gọi và **không section nào định
nghĩa** — bản 1 của canon bảo sửa route của nó mà không nói sửa thành gì. Chốt:
nó **tồn tại**, trên `res.users`, theo đúng khuôn §6 của CLAUDE.md (entry point
public mỏng + logic ở method private, **không nhận tham số**, mọi thứ suy từ user
đã xác thực):

```python
@api.model
@api.readonly
def blockchain_get_context(self):
    """POST /web/dataset/call_kw/res.users/blockchain_get_context
       POST /json/2/res.users/blockchain_get_context
    Tra ve: companies, chain enabled, token, money flow, nhom blockchain.* cua
    user. KHONG nhan allowed_company_ids do client gui."""
    return self.env.user._blockchain_build_context()
```

Test bắt buộc của §12.6.2 (liệt kê mọi method công khai và khẳng định nó nằm
trên allowlist đã review) được viết **đối chiếu bảng đó** và là một required check.

**Không có annexe controller HTTP.** Bản 1 mô tả controller `auth='public'` của
intent bus như một ngoại lệ có chủ ý, đồng thời §C4 đặt intent bus là service
standalone `intent-hub/` với process riêng, CI riêng, DB role riêng. Đó là hai
tiến trình trên hai ranh giới tin cậy khác nhau, và §12 xử lý hub như một **bề
mặt tấn công bên ngoài** trong khi một controller `auth='public'` nằm **bên
trong** process Odoo. Chốt: **hub là service standalone** (§C4), và
**relayer không bao giờ chạm HTTP của Odoo**. Endpoint nào của bus cần ghi một
model `blockchain.*` đi qua `/json/2` như mọi client khác, với service JWT.

### C14.3. Bảy màn hình phải thiết kế

UI được đặt tên khắp nơi mà chưa bao giờ được thiết kế, và §16 không có dòng ew
nào cho nó. Bảy màn hình **gate một workflow** (mọi thứ khác giữ list/form mặc
định, và điều đó phải được nói ra):

1. Settlement list + form (bộ lọc `pending_finality`, `disputed`, `gl_state='failed'`).
2. Approval inbox (`blockchain.approval.request`, hàng đợi của approver).
3. Dashboard đối soát — tiền đã cam kết mà chưa settle, **có cột "tuổi của mục
   cũ nhất"**, cộng hàng đợi `gl_state='failed'` (§15.4.3, §15.4.4).
4. Chain + endpoint health (`health_state`, `diverging`, độ trễ watermark).
5. Custody + key status (provider, `rotate_due_date`, ceremony).
6. Relayer statement (`blockchain.relayer.statement` và `.line`).
7. Một màn hình duy nhất hiện **cùng lúc** `blockchain.money.flow`,
   `blockchain.approval.policy` và `blockchain.custody.policy` cho một
   `flow_code` — §10.13(9) nói đúng: nếu không, không ai kiểm tra được cấu hình
   thật sự là gì.

Ngân sách: **15% effort backend**, tức **≈ +12 ew** phân bổ vào P04, P08, P09, P18.

---

## C15. Custody, lớp rủi ro, và khoá phiên

### C15.1. Hai trục, một chính sách, một khoá

Custody là **hai trục độc lập** (§07.2b), và đây là hiện thực hoá của locked #6:

- **`auth_custody`** — quyền chi tiêu (ECDSA/EdDSA). HSM làm được.
- **`conf_custody`** — giữ `x`, giải mã ElGamal, prove. HSM **không** làm được:
  không HSM thương mại nào có OID cho BN254 hay Baby Jubjub, và không cái nào
  expose `k + c·x mod r` trên scalar field tuỳ ý.

Kết luận trung tâm giữ nguyên: phần phụ thuộc `x` của một proof Zether **không
phải Bulletproofs** (range proof không dùng `x` làm witness) mà là **2 scalar
mul trên điểm công khai + 1 response `s = k + c·x mod r`**, nên TCB của enclave
thu về một trait `ZetherKeyOracle` dưới 300 dòng, và threshold hoá `x` là một
giao thức chuẩn chứ không phải nghiên cứu.

`blockchain.custody.policy` khoá theo **`flow_code` + `chain_id`** — cùng khoá
với `blockchain.money.flow` và `blockchain.approval.policy` (§C15.2). Ba
Selection riêng (12 giá trị `flow_code`, 3 giá trị `use_case`, 5 giá trị
`money_flow`) cho xấp xỉ cùng một tuple là ba nguồn sự thật, và không gì hiện
ngăn một deployment nơi money flow đi Zether trong khi custody policy của flow
đó có `conf_provider_id = False`.

```python
@api.constrains('active', 'flow_code', 'chain_id')
def _check_policies_exist(self):
    for rec in self.filtered('active'):
        if not rec._custody_policy() or not rec._approval_policy():
            raise ValidationError(_('Money flow khong the active khi thieu custody '
                                    'policy hoac approval policy khop (flow_code, chain).'))
```

`elgamal_decrypt` là một **decryption oracle trên `x`**: `decrypt(C, D)` với `D`
do kẻ tấn công chọn trả về log của `C · D^{-x}`, tức một ECDH oracle. Signer
**bắt buộc** từ chối mọi `(C, D)` không chứng minh được là trạng thái thật trên
chain (`ChainWitness`).

Signer là **một service, không phải một hàm**: MPC SaaS p50 300 ms–3 s sẽ cạn
worker pool của Odoo ở 6–20 request đồng thời. Mọi lời gọi đi qua hàng đợi
`blockchain.signing.request` với idempotency key — thiếu `idem` thì **mỗi retry
là một giao dịch trùng trên chain**.

**Backup mặc định là passkey PRF**, và §12.13 R4 phải thay bằng bảng của §07.10
thay vì một con số trung bình:

| Cơ chế backup | Tỷ lệ mất khoá/năm | 10,000 outlet × 500 k ₫, tích luỹ 5 năm |
|---|---|---|
| **passkey PRF đồng bộ (mặc định bắt buộc)** | 0.05 – 0.2% | 12 – 50 triệu ₫ |
| SLIP-39 tự chép | 0.5 – 2% | 125 – 500 triệu ₫ |
| device-bound không backup | 3 – 8% | 750 – 2,000 triệu ₫ |

**Device-bound không backup: không được phép cho luồng mang giá trị.** Chênh
lệch 10–40× ở cùng chi phí kỹ thuật chính là thứ quyết định thiết kế backup, và
một con số trung bình xoá mất quyết định đó.

**Omnibus custodial bị cấm cứng cho mọi luồng có Zether**: nó biến mọi giao dịch
thành "platform → platform" và phá huỷ đồ thị chuyển tiền on-chain, tức sập
toàn bộ lập luận tuân thủ.

**Guard lúc deploy: một tài khoản Zether không được gắn vào custody provider
thiếu `zk_mul_by_x`.** §C6.4 chứng minh phép kiểm duy nhất người nhận chạy được
mà không có `s` là `C_out · g^{-v} == D_out^{x_to}`, một scalar mul, và nó cần
`zk_mul_by_x`. Thiếu nó thì memo không giải được, BSGS bất khả thi ở dải B2B, và
fallback `(v, s)` là hành động của **người gửi** chứ không phải người nhận — tức
chủ tài khoản nhìn thấy số dư của chính mình **ít hơn auditor**. Đó không phải
"degrade", đó là không dùng được:

```python
@api.constrains('custody_key_id', 'token_id')
def _check_zether_custody_capable(self):
    for rec in self:
        if not rec.token_id.is_confidential:
            continue
        caps = rec.custody_key_id.provider_id.capability_ids.mapped('code')
        if 'zk_mul_by_x' not in caps:
            raise ValidationError(_(
                'Custody kind %s khong co zk_mul_by_x, nen tai khoan nay khong '
                'khoi phuc duoc so tien cua chinh no. Khong the gan mot token '
                'confidential vao no.') % rec.custody_key_id.provider_id.kind)
```

Ô tương ứng trong ma trận caps của §07 đổi từ *degrade* thành **blocking**.
Locked #6 (mọi custody model đều được hỗ trợ) giữ nguyên — guard này không loại
kind nào khỏi hệ thống, nó chỉ chặn một **tổ hợp** (kind thiếu `zk_mul_by_x` ×
token confidential) không lấy lại được tiền của chính nó.

Chú ý hợp đồng, không phải kỹ thuật: **chứng nhận FIPS 140-2 chuyển sang CMVP
Historical List ngày 2026-09-21.** Mọi câu "FIPS 140-2 Level 3" trong tài liệu
bán hàng, hồ sơ thầu và hợp đồng phải đổi thành "FIPS 140-3 Level 3, hoặc chứng
nhận CMVP đương thời tương đương".

### C15.2. R1–R4 — định nghĩa, và ai gán

Bốn lớp được dùng khắp nơi như thể đã định nghĩa (`blockchain.relay.job.risk_class`
mặc định `r2`, §06.4.4 throttle theo lớp, §12 nói tới duyệt R3/R4, §01.17.1 gate
deploy theo nó) mà chưa section nào định nghĩa.

| Lớp | Tiêu chí | Flow mặc định | Breaker | Duyệt | Finality |
|---|---|---|---|---|---|
| **R1** | không có giá trị chuyển; đọc hoặc neo | anchor, log, `rollOver`, `register`, `deposit` | chỉ trần toàn pool | không | soft |
| **R2** | giá trị ≤ `r2_max_fiat` (mặc định **5,000,000 ₫**), hiệu ứng nghiệp vụ đảo được | `LOYALTY_ACCRUE`, `LOYALTY_REDEEM`, `OUTLET_COLLECT` | velocity theo tenant | không | soft nếu dưới `soft_final_max_amount`, ngược lại hard |
| **R3** | vượt ngưỡng R2, hoặc bất kỳ dòng tiền ra nào của treasury/B2B | `B2B_PAYOUT`, `B2B_INVOICE_PAY`, `FIAT_OFFRAMP`, `withdraw` | velocity tenant + global | **maker-checker** | **hard** |
| **R4** | thay đổi quản trị, khoá, hoặc trạng thái contract | `pause`, `upgrade`, `freeze`, `setAuditorKey`, đổi validator set, đổi relayer allowlist, **gap-filler và replacement của một job R3 đã broadcast** | không bao giờ throttle **lối ra**; chỉ throttle lối vào | **quorum ≥ 2 approver, khác người yêu cầu** | **hard** |

Gán bởi `blockchain.money.flow.risk_class` (mặc định theo flow), **nâng lên
được cho từng settlement, không bao giờ hạ xuống, và không bao giờ do client
gửi**. Bảng ánh xạ đặt cạnh `blockchain.approval.policy` trong §10.

Quy tắc §06 giữ nguyên và bây giờ có chỗ đứng: breaker chặn đầu vào nhưng
**không được chặn lối thoát** — gap-filler và replacement của một job R3 đã
broadcast là **R4**, vì throttle chúng nghĩa là để nguyên một lỗ thủng nonce
hoặc để tiền treo giữa đường.

### C15.3. Khoá phiên (ephemeral session key): ngoài phạm vi

Note đặt agent giữ một session key giới hạn phạm vi (1–8 h, trần theo ngày) sau
một policy gate. §12.5.3 có quy tắc (`authEpoch` trong digest, trần tích luỹ
on-chain, revoke on-chain) nhưng **không model, không luồng cấp/gia hạn/thu hồi,
không bề mặt RPC, không dòng nào trong registry**.

Chốt: **agent dùng đúng đường custody như người dùng** (`blockchain.custody.key`
+ `blockchain.approval.policy` + lớp rủi ro R1–R4 ở trên). `blockchain.session.key`
**không được tạo trong 24 tháng đầu**, và ngôn ngữ session key được gỡ khỏi
phần agent của note. Lý do: một bề mặt cấp khoá thứ hai là một thứ thứ hai phải
audit, và §07.9 đã chỉ ra điều quyết định — **FIPS L3 chống TRÍCH XUẤT khoá,
không chống LẠM DỤNG khoá**; thứ thật sự giới hạn một agent là
`SigningPolicyService` nằm **cùng phía với signer** (to-allowlist, selector,
trần value, trần tích luỹ theo giờ), không phải thời hạn của một khoá. Xây
`SigningPolicyService`; không xây session key.

---

## C16. Compliance profile × use case

Cấu hình mặc định hiện tại làm **hai trong ba use case đã khoá không deploy
được**. Đây là cách giải mà không lật locked #3.

`compliance_profile` mặc định **`vn_conservative`** (giữ), và mỗi vertical được
gán một **hình thái** chạy được dưới profile đó:

| Vertical | **Chain** | Profile chạy được ngay | `token_legal_class` | `transfer_policy` | Archetype | Mode | Ghi chú |
|---|---|---|---|---|---|---|---|
| **P21 LOYALTY** | **Gnosis (public)** | `vn_conservative` | `loyalty_point` | `non_transferable` | **`ZTokenOpen`** — ngoại lệ freeze, xem dưới | M4, M12, M18-descoped | không quy đổi tiền mặt, không niêm yết tỷ giá, có hạn dùng, **phải thông báo NĐ 81/2018** |
| **P22 B2B** | **Besu private** (Zether), Gnosis cho anchor | `vn_conservative` | `tokenised_receivable` | `restricted` (allowlist đối tác) | `ZTokenPermissioned` | **M4 / M12 / M13** — token **ghi nhận** nghĩa vụ, chuyển khoản ngân hàng **chấm dứt** nghĩa vụ (BLDS 2015 Điều 378) | Zether có giá trị thật ở đây: brand không muốn distributor A thấy chiết khấu của B |
| **P23 ENDUSER_PAY** | **không có chain riêng** — record-only | `vn_conservative` | — | — | — | **M12 / M1 với fiat**: chain ghi nhận, VietQR/thẻ thu tiền | Zether end-user payment cần `offshore` + giấy phép |

**Cột chain là mới, và nó tồn tại vì bản 1 giao cho P21 hai chain loại trừ
nhau.** Bản 1 ép `ZTokenPermissioned` cho loyalty, mà §1.10
(`01-token-factory.md:644`) nói archetype đó *"**chỉ deploy được trên profile
private** (`profileMask` bit1)"* — trong khi toàn bộ lập luận loyalty của §C1.4
là một phép tính dung lượng **Gnosis** (33,000/ngày so với trần ~30,000/ngày của
mạng) và ngưỡng kiến trúc thứ tư ở §C1.2 chỉ tồn tại vì loyalty nằm trên Gnosis.
P21 là vertical ra mắt, và không ai biết nó ra mắt trên chain nào.

`Z-VND` dạng `PEG_RATIO` chấm dứt nghĩa vụ **vẫn là một thiết kế hợp lệ** — nó
chỉ bị **gate** sau `vn_pilot`/`offshore` cộng câu trả lời giấy phép của P19.
§13 phải ghi câu đó, để không ai đọc §13 như là huỷ §01.

**Sửa mâu thuẫn archetype (§13.6.3(4) vs §01.10).** Dưới `vn_conservative`,
`freeze(bytes32)` sau một multisig `COMPLIANCE_ROLE` 2-of-3 là **bắt buộc** cho
`tokenised_receivable`, `utility_internal`, `stablecoin_fx`, `cbdc`. `ZTokenOpen`
**theo archetype không có freeze**, và một khi đã mint dưới `ZTokenOpen` thì
không ai bật được nữa, kể cả admin, kể cả qua upgrade. Chốt:

> **Archetype là hàm của `compliance_profile` × chain**, và bảng §1.15 thêm cột
> đó. Dưới `vn_conservative`, mặc định là `ZTokenPermissioned`.
>
> **Loyalty là ngoại lệ tuân thủ có biện minh viết ra, không phải một tai nạn.**
> P21 ở lại Gnosis với `ZTokenOpen` (§1.15 giữ *"Profile khởi điểm: public
> (Gnosis)"*), tức **không có `freeze` cho `loyalty_point`**. Biện minh, ghi vào
> hồ sơ tuân thủ chứ không chỉ vào spec:
>
> 1. `transfer_policy = 'non_transferable'` — điểm thưởng không chuyển nhượng
>    được, nên thứ mà `freeze` sẽ chặn (dòng chảy tới bên thứ ba) **không tồn
>    tại**; biện pháp tương đương là ngừng `mint` và ngừng `redeem`, cả hai đều
>    là quyền của issuer và cả hai đều có trên `ZTokenOpen`.
> 2. `loyalty_point` không quy đổi tiền mặt, không niêm yết tỷ giá, có hạn dùng —
>    nó không phải phương tiện thanh toán, nên nghĩa vụ đóng băng theo yêu cầu cơ
>    quan không phát sinh theo cùng cách với `tokenised_receivable`.
> 3. Chuyển loyalty sang private chỉ để có `freeze` sẽ **xoá luôn** ngưỡng dung
>    lượng Gnosis của §C1.2 và phép tính hoà vốn của §C19, và bắt P21 — vertical
>    ra mắt, rẻ nhất, ít rủi ro pháp lý nhất — gánh toàn bộ chi phí vận hành
>    private stack.
>
> Nếu bộ phận pháp chế bác biện minh này thì loyalty chuyển sang Besu private với
> `ZTokenPermissioned`, và **cùng lúc đó** phải xoá hàng ngưỡng Gnosis ở §C1.2,
> xoá lập luận Gnosis ở §C1.4, và định giá lại P21 trên private stack. Đó là một
> quyết định của con người — **§C21 D10**.

**Câu trả lời về tịch thu, viết một lần** (§13.6.3(5) đang để mở, §1.10.3 đã trả
lời một nửa): trên Zether, `freeze` **chặn dòng ra nhưng không tịch thu được**;
`forceTransfer` chỉ tồn tại trên profile private với N validator chứng kiến;
**Zether trên public profile không thể đáp ứng một lệnh tịch thu**. Đó là một
hàng **ĐỎ** trong §13.8, không phải một câu hỏi mở.

**`MODE_OPEN` và thuế nhà thầu nước ngoài.** Không khấu trừ được ~10% FCT từ một
relayer ẩn danh trong mempool, và một khoản phí không hoá đơn thì không được
trừ. Chốt, và nó nằm trong bảng mặc định theo profile của §04.11 để một kỹ sư
relayer đọc §05 một mình cũng thấy:

> `compliance_profile = 'vn_conservative'` ⇒ mặc định
> `mode = MODE_RESTRICT_RELAYER | MODE_REQUIRE_SUCCESS`, relayer nằm trên
> allowlist đã ký hợp đồng.

Mục tiêu Phase 0 của §5.9 đổi từ "chạy MODE_OPEN từ ngày đầu" thành **"luyện
toàn bộ envelope và intent bus với một chữ ký restricted-relayer"** — lập luận
của §5.9 (đừng phát hiện giả định sai vào thời điểm tệ nhất) vẫn đúng, và nó
được thoả bằng việc chạy đủ đường đi, không bằng bit mode. Câu chống chế
"MODE_OPEN là về hình dạng chữ ký, không phải phạm vi mạng" **không cứu được**:
bit mode nằm **trong** digest, nên hình dạng chữ ký **chính là** phạm vi mạng.

Lưu ý là mặc định này **không** mua được gì trên đường Zether cho tới khi biến
thể `ZTX_V1_RELAYED` của §C6.6 tồn tại — `MODE_RESTRICT_RELAYER` chỉ hạn chế ai
gửi phong bì, mà phong bì không phải thứ chuyển tiền. Nó **vẫn** mua được đúng
thứ mục này cần (một relayer có hợp đồng, có hoá đơn, khấu trừ được FCT), và đó
là lý do nó ở lại làm mặc định.

**Ràng buộc pháp lý độc lập với mọi câu hỏi token:** một pháp nhân VN không có
đường hợp pháp để mua xDAI/CELO bằng VND với hoá đơn đầu vào hợp lệ, nên gas của
relayer không được trừ khi tính thuế TNDN. Đó là một lý do **thứ hai, độc lập**
cho locked #5 (private chain trước), và nó phải nằm trong tài liệu quyết định.

**Chân trời bảo mật, viết vào hợp đồng dịch vụ chứ không chỉ vào §03.** Với
`curve_profile = 'bn254'` trên public chain (mặc định hiện tại, §C6.1), phát
biểu chuẩn tắc là:

> **Phải giả định mọi số tiền confidential trên public chain đều có thể bị giải
> mã trong khoảng 2035–2045.** BN254 là ~100 bit sau exTNFS, ciphertext Zether là
> bất biến và vĩnh viễn, nên đây là harvest-now-decrypt-later — không phát hiện
> được, không có thời gian phản ứng.

Câu này phải xuất hiện trong: hợp đồng dịch vụ với distributor, hồ sơ DPIA, và
`blockchain.zether.token.confidentiality_horizon_years` (guard ở §C6.1 từ chối
> 10 năm cho tổ hợp bn254 × public). Nó **không** áp cho Zether trên Besu private,
nơi ciphertext không công khai — đó là lý do thứ ba, độc lập, cho locked #5.

---

## C17. Private chain: client, genesis, DR

### C17.1. Client — Besu + QBFT

§03.3.9 chọn go-quorum/geth-QBFT với lập luận "gnark-crypto là Go, ~150 dòng vào
`core/vm/contracts.go`; Besu là Java, cần JNI, gấp 5 lần công". §08.10 loại
GoQuorum vì nó ở chế độ maintenance. **Chốt Besu**, vì lập luận JNI đã cũ:
Besu chạy Java 21+ với Foreign Function & Memory API (GA từ JDK 22) gọi thư
viện Rust **không cần một dòng JNI** (~150 dòng Java, ngang 150 dòng Go), và
`besu-native` **đã có** binding tới gnark cho altbn128. Chạy một client ở chế độ
maintenance làm nền cho sổ cái bảo mật là một rủi ro vận hành lớn hơn nhiều lần
chênh lệch công sức đó.

Hệ quả phải áp: **xoá `smartcontracts/geth-precompile/` khỏi §3.9.1**, viết lại
lập luận client ở §3.3.9, và **chuyển mục tiêu audit B2 của §12.1.1 từ code Go
sang Java/FFM cộng thư viện Rust** (ngân sách $30–60 k giữ nguyên).

**Con số ~500 tx/s phải được ghi là có điều kiện.** Nó phụ thuộc native
precompile tồn tại. Cho tới khi S8 xong và precompile ship, con số §09, §11 và
§15 phải trích là **~13 tx/s** (Besu + Solidity verifier, §14.13(9)) — vẫn thừa
cho B2B ở khối lượng §C1, **không đủ** cho bán lẻ quốc gia.

### C17.2. Genesis — một file chuẩn tắc

`smartcontracts/devnet/besu/genesis.qbft.json`. Ba giá trị đang có ba câu trả lời:

| Tham số | **Chốt** | Vì sao |
|---|---|---|
| `gasLimit` | **50,000,000** (`0x2FAF080`) | Ở 1.94 M gas/tx đó là 25 confidential tx/block = **12.5 tx/s** ở block 2 s — cao hơn nhu cầu B2B Year 1 (§C1) ba bậc. Trần thật là **CPU validator** (9–28 ms/proof, §3.3.9), không phải gas: `gasLimit = 200 M` cho phép một block tiêu 1.3 giây CPU một lõi, tức đặt một quả bom liveness vào genesis. **Xoá 200 M (§01.16) và 100 M (§04.11, §06.4.5).** |
| Fork | **`cancunTime: 0`** | `foundry.toml` biên dịch `evm_version = "cancun"`, và §04.6.7 dựa vào `ReentrancyGuardTransient` (EIP-1153). Genesis hiện khai `shanghaiTime: 0` **không có** `cancunTime` ⇒ `TSTORE`/`MCOPY` là INVALID opcode **sau khi mọi test đã pass**. `devnet/check-genesis-fork.sh` là **required check**. |
| `contractSizeLimit` | **giữ 24,576** | Một codebase cho cả hai profile, và Gnosis cố định ở 24,576 dù sao — nới lỏng phía private cho phép ship một contract **không bao giờ lên public được**. §3.3.5 đã giải bài toán bằng SSTORE2: cấu hình 32/64 cần 8,192 B generator trong một **data contract riêng**, nên verifier còn chỗ. **S1 phải đo `forge build --sizes` cho `BulletproofsVerifier` với SSTORE2 đã áp**; nếu > 24,000 B thì gate §1.14.2 đổi thành allowlist per-contract kèm biện minh viết ra, và Zether trên public chain được xem xét lại. **Xoá `contractSizeLimit: 65536` khỏi §08.10, §16.1-S1 và §16.2.** |

Cộng: `zeroBaseFee: true`, `blockperiodseconds: 2`, ba lớp permissioning
(on-chain node + account allowlist), **4 validator tối thiểu ở ≥3 vùng lỗi độc
lập**, Bonsai cho validator cộng **một archive node riêng từ ngày đầu** (đổi
storage format sau đó là resync từ genesis).

`foundry.toml` chuẩn tắc là **§14.2**, không phải §01.14.1: `bytecode_hash = "ipfs"`
(giữ Sourcify full-match; metadata đã deterministic một khi solc/settings/submodule
đã ghim), `via_ir = false` (không cần cho `struct calldata`; bật nó tốn build
×6–13 và **chặn `forge coverage`**, tức biến gate coverage 90% của chính
§01.14.2 thành một gate chết), `[profile.coverage]` riêng. Yêu cầu **tính tái
lập** của §01 giữ nguyên nhưng được thoả bằng **determinism gate** (build hai
lần ở hai đường dẫn trong hai container, diff `keccak256(init_code)`).

### C17.3. DR — phần chưa ai sở hữu

Private chain giữ toàn bộ sổ cái bảo mật. Mất nó là mất **vĩnh viễn** mọi số dư
Zether: ERC-20 escrow nằm khoá và không ai chứng minh được số dư. §08.10 phủ
mất quorum (RTO 15 phút, hot standby) nhưng **không phủ mất dữ liệu**; anchor
HCS phát hiện giả mạo nhưng **không khôi phục gì**.

| Thành phần | RPO | RTO | Cơ chế |
|---|---|---|---|
| Private chain (Besu) | **0** (mọi block đã final) | 60 phút | Snapshot mỗi 6 h ra object storage ngoài vùng + **archive node riêng** giữ toàn bộ lịch sử; khôi phục = genesis + snapshot + replay |
| PostgreSQL (Odoo) | 5 phút | 30 phút | WAL archiving liên tục + base backup hằng ngày |
| Redis | **chấp nhận mất toàn bộ** | 10 phút | Cache; tái tạo bằng giao thức cold start (§C13). Phải **diễn tập** với transaction đã ký đang bay — kịch bản này chưa từng được costed hay test |
| Garage (proof, trace, receipt) | 15 phút | 4 giờ | Replication đa site |
| Signer (khoá) | — | 30 phút | Shamir share phục hồi; diễn tập là một trong hai drill mới của §12 |

Diễn tập bắt buộc, đưa vào bảng drill của §12.11: **khôi phục chain từ genesis +
snapshot mỗi quý, đo thời gian thật**, và trả lời bằng văn bản: điều gì hỏng khi
chain khôi phục **phân kỳ so với anchor HCS gần nhất**. Đưa vào §16 như một dòng
DoD của P18.

---

## C18. Phạm vi — cái gì KHÔNG làm trong 24 tháng đầu

Viết ra để không ai lập kế hoạch dựa vào nó.

| Ra khỏi phạm vi | Vì sao | Thay thế |
|---|---|---|
| M7 pull payment, M8 streaming, M9 escrow, M10 mandate | cần contract chưa ai scope; M9 cần một vòng audit riêng $25–40 k | M3, M4 |
| M18 voucher ký off-chain, M19 payment channel | cần contract bearer-claim; M19 được §09 gọi tên để bác bỏ | M11 |
| Ứng dụng ví người dùng cuối và mặt POS/merchant | không section nào sở hữu; +10–20 ew và một bộ kỹ năng mobile/POS không có trong ma trận §16.5.1 | `ENDUSER_PAY` = M12/M1: chain ghi nhận, VietQR/thẻ thu tiền (§C16) |
| `blockchain.session.key` | §C15.3 | cùng đường custody + `SigningPolicyService` |
| Basket / multi-leg peg | 3 leg × uptime 99.5% = 98.5% tổng, ~5.5 ngày/năm không mint được (§1.7.6) | `profileMask` của `BASKET_PEG` để `0x00` |
| Projection `vec` (vector hoá source/ABI/audit report) | không có consumer trong 24 tháng | — |
| Projection `ekg` (đồ thị tri thức on-chain) | Odoo đã có liên kết tương đương | `partner_id`, `origin_model`/`origin_id`, `counterparty_id` |
| `proc` Tool Gateway cho agent gọi contract | agent đi qua RPC surface bình thường (§C14.2) | — |
| `olap` ClickHouse | ngưỡng ở Year 3, không phải Year 1 (§C1.2) | BRIN + cron archival hằng tháng (**không** partition, §C1.2) |
| `eip681_uri` / `wc_uri` trên `blockchain.payment.request` | chỉ tồn tại cho ví on-chain của người dùng cuối, vốn đã descope ở hàng trên | — (§C10.9) |
| 5 hệ sinh thái ngoài EVM (HBAR/TON/SUI/Soroban/CosmWasm) | locked #4: **thiết kế trên giấy** | P17, 3 ew, tài liệu + ánh xạ interface, **không code** |

**Ánh xạ projection của note sang thực tại** (để người đọc note không giả định
chúng nằm trong phạm vi): `raw.blockchain_*_landing` → `blockchain.chain.event`
cộng `ir.attachment` trên Garage; `ods.chain_contract_events` →
`blockchain.chain.event`; `ods.chain_meta_tx_relay_ledger` →
`blockchain.metatx` + `blockchain.relay.job`; `ods.chain_zether_confidential_ledger`
→ `blockchain.zether.entry`; `sem` → đúng bộ metric của §11.11b, expose bằng SQL
view, không phải một plane mới. Chúng là **cùng những đối tượng dưới tên khác**,
không phải hạng mục công việc bổ sung.

---

## C19. Chi phí toàn chương trình (một trang, cho người duyệt)

Các mảnh chi phí đang nằm rải ở sáu section với sáu đơn vị và chưa bao giờ được
cộng lại hay đặt cạnh một lợi ích.

**Baseline đã trừ phần descope, và bản 1 thì chưa.** Con số 135–141 ew của bản 1
được tính **trước** §C18, rồi mang nguyên sang §C19 mà không trừ gì. Phần trừ:
ứng dụng ví người dùng cuối và mặt POS/merchant (**−10 đến −20 ew**, chính §C18
định giá thế), M7–M10 và M18–M19 (**−12 ew** ước lượng, chúng cần contract chưa
ai scope). Phần cộng: onboarding gasless `register` (**+6 ew**, §C21 D14 — nó
chặn giao dịch **đầu tiên** của cả hai use case và bản 1 chưa bao giờ định giá
nó). Ròng: **135–141 → 113–119 ew** ở phần kỹ thuật lõi, và tổng chương trình
tình cờ quay lại quanh 135–141 ew sau khi cộng UI, DR/services và onboarding.
Đó là một trùng hợp về con số, **không** phải lý do để giữ nguyên cách cộng cũ.

| Hạng mục | Year 1 | Year 3 (mỗi năm) |
|---|---|---|
| Kỹ thuật: **113–119 ew** sau descope + 12 ew UI (§C14.3) + ~4 ew DR/services (§C4, §C17.3) + **6 ew onboarding gasless** (§C21 D14) ≈ **135–141 ew** | ~2.7 engineer-year | bảo trì ~0.8 engineer-year |
| Audit (B → B2 → C → C2 → D → D2) | **$173 k – 345 k** | ~$15 k re-audit |
| Bug bounty float (ring-fenced, không phải chi phí) | $300 k | $300 k |
| Bootstrap relayer bên thứ ba (6 tháng) | $30 k | 0 |
| Hạ tầng (node, RPC, Postgres, Redis, Garage) | $480 – 830/tháng | $1,200 – 2,000/tháng |
| Custody — cấu hình C (KMS + on_device, đủ cho loyalty + end-user) | **$107/tháng** | |
| Custody — cấu hình A/B (HSM + enclave, bắt buộc khi bật B2B) | $2,900 – 9,750/tháng | |
| CI | $430/tháng (+$122/tháng mutation testing hằng đêm) | |
| Gas | ~$239/tháng ở 50 k tx | theo khối lượng |
| Pháp lý VN (P19) | 80 – 400 triệu ₫ | |

**Cấu hình khả thi tối thiểu** — loyalty only, custody C, private chain, không
deploy public: ~$620/tháng vận hành cộng phần kỹ thuật của M0 + P01 + P04 + P05
+ P14 + P21. Nó rẻ hơn cấu hình đầy đủ **hai bậc độ lớn**, và nó là điểm khởi
đầu được khuyến nghị.

**Điểm hoà vốn so với đường lui M2** (giao cho một acquirer có giấy phép, phí
0.5–1.0%): tự vận hành thắng trên khoảng **$300 k doanh số crypto/năm**. Ở khối
lượng §C1 Year 1 với `OUTLET_COLLECT` 1.25 M giao dịch × 2 triệu ₫ trung bình,
giá trị chạy qua hệ vượt xa ngưỡng đó — nhưng **chỉ khi luồng đó thật sự đi
on-chain**, mà §C16 nói nó không đi (M12: chain ghi nhận, fiat thu tiền). Với
hình thái record-only, **lợi ích không phải phí acquirer tiết kiệm được mà là
đối soát và bảo mật giá**, và đó là thứ phải được định giá trong quyết định
duyệt ngân sách — không phải một con số hoà vốn giả.

---

## C20. Danh sách sửa theo từng section

Mỗi section phải áp những mục dưới đây trước khi được coi là đồng bộ với canon.

| Section | Phải sửa |
|---|---|
| `01-token-factory.md` | Bỏ `RANGE_BITS = 64` đơn lẻ và `decimals = 2` (§C6.2); `maxSupply` viết theo `n_b`. Xoá `foundry.toml` ở §1.14.1, trỏ §14.2 (§C17.2). Genesis: `gasLimit` 50 M, `cancunTime: 0`, giữ 24,576 (§C17.2); tính lại 45 tx/s. Finality Gnosis 240 s, không 12.8 phút (§C9.2). §1.15 **giữ** archetype loyalty = `ZTokenOpen` trên Gnosis và thêm cột `compliance_profile` × chain; biện minh ngoại lệ freeze chép từ §C16. **Xoá luôn quy tắc dust của §1.8.1/§1.8.2** — chúng được dẫn từ `decimals = 2`, mà §C6.2 đã bỏ; dẫn lại theo `decimals = 0` + `scale_exponent` hoặc bỏ hẳn nếu dust không còn tồn tại ở 1 đơn vị ledger = 1 ₫. Đường `smartcontracts/` theo §C4. Regex uint256 (§C11.4). |
| `02-account-registry.md` | Curve-parametric, subgroup check khi cofactor ≠ 1, đổi tên enum `*_BN254`, **gỡ `BLS` khỏi enum scheme** và thêm `require` cấm mọi scheme công bố phần tử G2 trên tài khoản giữ số dư Zether (§C6.1). Seed `curve_profile = 'bn254'`, không `babyjubjub`. Xoá `blockchain.chain.profile`, `profile_id` → `chain_id` (§C9.1). Xoá `custody_model`/`secret_ref`, dùng `custody_key_id` (§C10.2). Giữ `C_audit` dạng shared-`s` và ghi rõ nó là bản chuẩn tắc (§C6.5). Thiết kế **trọn vẹn luồng onboarding gasless `register`** (ai mint và ký `RegistrationInvite`, relayer nào mang, vòng đời record, UI khi pending, xử lý khi fail) — hiện §2.1.6 và §3.11.1 U6 đá trách nhiệm cho nhau và nó chặn giao dịch **đầu tiên** của cả hai use case. Quyết định và ước lượng ở **§C21 D14** (+6 ew, pha P04, 10,000 outlet × ~95 k gas = ~0.95 G gas ≈ $1,900–5,700 trên Gnosis); §02 viết thiết kế, **không** tự chọn kiến trúc. |
| `03-zether-crypto.md` | Xoá biến thể auditor `s_a`/`D_aud` ở §3.4.8; thêm `C_aud` vào struct §3.2.5; sửa danh sách validation §3.1.6 (§C6.5). Sửa `_final_nonce_uniq` sang `models.UniqueIndex`, xoá `init()` và câu "Odoo 19 không có API cho partial unique index" (§C11.2). Gộp `blockchain.zether.transfer` vào `blockchain.zether.entry` (§C10.7). §3.9.4 dùng `_inherit`, bỏ `_name`. Finality Gnosis 240 s ở §3.9.5. Xoá `smartcontracts/geth-precompile/` ở §3.9.1 (§C17.1). Ghi §C5.4 là đường lui duy nhất. Thêm `validUntilBlock` vào thông điệp Schnorr của `rollOver` (§C5.1). Thêm biến thể `proofSystemId` **`ZTX_V1_RELAYED`** với `digest_hash` trong transcript (§C6.6). Sửa §3.3.9: lý do không Pippenger là **tỷ giá `ecAdd`/`ecMul`**, không phải thiếu precompile (§C7.1). Sửa §3.5.4: `rollOver` ghi **10 slot**, không 5 (§C7.3). Sửa §3.11.1 U4: Baby Jubjub là **~125 bit**, không ~100. |
| `04-eip1776-metatx.md` | Xoá sentinel `lane_slot`, dùng `models.UniqueIndex` (§C11.2). Thay `innerGasLimit`/`maxInnerGas`/`requiredOuterGas` bằng §C7.4. Thêm `TargetPolicy.requireSuccess` và ghi quy tắc §C8.3 làm bản chuẩn tắc. Đổi `metatx_digest` → `digest_hash` ở §04.12. Thêm bảng mặc định theo `compliance_profile` (§C16). |
| `05-open-relayer-network.md` | Xoá `zether.target_epoch` khỏi envelope, thêm `acc_seq`/`pending_seq` (§C5.3). Dựng lại §5.1.1 theo `expiry = 60 s`, **`W = 3 s`, poll 1 Hz** — đã chốt, không còn là câu hỏi (§C8.4). Dẫn lại sàn phí §5.3.3 với `p = 0` cho profile restricted (§C6.6). Xoá bảng chi phí 342 k–422 k (§C7.5). Xoá ba dòng cũ ở §5.12 (mask `0x0F`, `0x10` commit-reveal). Chuyển `_unique_statement_period` và `_check_fee_base` sang `blockchain.relayer.statement` và định nghĩa model đó (§C10.5). `net_display` → `digits=(38, 18)`; regex uint256 (§C11.4). Thay `init()` bằng `models.UniqueIndex`. Mục tiêu Phase 0 theo §C16. Thêm một dòng đầu section: §03 và §04 là thượng nguồn, §05 **không dẫn lại con số nào**. |
| `06-relay-pool-enterprise.md` | Xoá toàn bộ máy móc epoch (§C5.3). Xoá Redis Stream dispatch (§C13). Xoá `default='public'` và **xoá luôn khai báo lại field `chain_profile`** (§C9.1). Xoá bảng gas tự dẫn và mô hình ba range statement (§C7.5, §C6.3). `max_gas_per_tx` = 3,000,000 (§C7.4). Hai partial index sang `models.UniqueIndex`; §06.11 kiểm `pg_indexes` (§C10.8). Gộp `blockchain.relay.job` theo §C10.8, **đổi `origin_ref` → `origin_key`** và khoá thành `UNIQUE(company_id, origin_producer, origin_key)` (§C2.6). `chain_state` gồm `signed_orphan` (§C10.8). Xoá `size=`; xoá `default=` trên `runway_hours`. Đóng §06.12.3 theo §C8.3. |
| `07-custody-providers.md` | Viết lại §07.4b quanh memo AEAD; BSGS thành oracle; CI gate #19/#20 đo memo (§C6.4). Thêm `ecdh` vào `ICustodyProvider` nhóm B với đúng dòng caps-matrix của `zk_mul_by_x` (§C6.4). `endpoint_url` → `endpoint_ref`, bỏ `tracking=True` (§C11.7). Xoá `default=` trên `can_prove_zether`/`can_decrypt`. Kiểu trong `ZetherKeyOracle` thành curve-parametric (§C6.1). `blockchain.custody.policy` khoá theo `flow_code` + `chain_id`, và thêm guard `_check_zether_custody_capable` (§C15.1). Ô caps-matrix của các kind thiếu `zk_mul_by_x` đổi từ *degrade* sang **blocking** (§C6.4). Đường thay thế của người nhận là `C_out · g^{-v} == D_out^{x_to}`, **không** phải `(v, s)`. |
| `08-chain-adapters.md` | Xoá khối model `blockchain.chain`, trỏ §C9.1; giữ `finality_quorum` và `is_independent` bằng cách **thêm** chúng vào §10.4.2. Viết lại §08.4c theo §C8.3. Nhãn `fee_currency (Celo CIP-64)` cộng ba ràng buộc §C9.3. Xoá bảng gas 2.7 M (§C7.5). Genesis theo §C17.2. Đóng §08.11 Q2 (§C6.3). Thêm `fabric`/`corda` làm giá trị `chain_family` dự trữ và chuyển `gas_price()`/`estimate_gas()`/`mempool_peek()` sang mixin `EvmPublicAdapterExt` (§13.5.1). Mở rộng §08.10 bằng §C17.3. |
| `09-payment-modes.md` | Topology 4 addon, trỏ §C3; xoá `_acquirer` và `_mandate`. `is_production` → `is_testnet`; `fee_token_mode='free'` → `fee_mode='gasless'`; `confirm_depth` → `finality_soft/hard_blocks` (§C9.1). Xoá độ trễ dẫn từ epoch (§C5.3). Khai đầy đủ `blockchain.payment.request` / `.observation` / `.quote` và hợp đồng với settlement (§C10.9). Thêm `token_id` và `risk_class` vào `blockchain.money.flow` (§C15). Descope M7–M10, M18–M19 (§C18); **xoá `eip681_uri` và `wc_uri`** (§C10.9). Thêm `amount_settled_base` và quy tắc `_payment_gate()` theo tổng (§C10.9). Thêm `latency_budget`, `r2_max_fiat`, `is_payment_bound` vào `blockchain.money.flow` (§C9.1, §C9.4). |
| `10-odoo-addon-design.md` | `depends = ['base','mail','bamboo_idempotency']` (§C3). `_check_mode` theo §C8.2. `blockchain.settlement` theo §C10.4 (bỏ `mail.thread`, `compensated`+`disputed`, `authorized_*`, `gl_*`, `effect_id`, `notify_error`). `blockchain.zether.entry` theo §C10.7. Xoá `blockchain.outbox.job`, xoá `blockchain.event` (§C10.1). Sinh lại §10.3 từ §C10.1, §10.5.2 từ đó, §10.6.1 thành allowlist đầy đủ (§C14). Seed finality theo §C9.2. Nhãn CIP-64. Thêm chính sách migration (§C11.3). `blockchain.chain` cộng 7 field (§C9.1). Sửa comment `origin_model` từ `dms.trade.settlement.line` sang `dms.trade.settlement`. Thêm `create()` override ghi đè `origin_producer` (§C10.4) và guard `origin_model in self.env` cho `_compute_origin_ref` (§C10.4). Khai `blockchain.settlement.log` **6 cột kèm `company_id`** — §10.4.8 sở hữu nó (§C10.1). Khai `token_id` / `account_id` cho hai `_inherits` (§C10.3). Thêm `risk_class` và `finality_grade` vào settlement (§C10.4). Thêm `blockchain_get_context` trên `res.users` (§C14.2). Viết bảng record rule của §C14.1. |
| `11-indexer-finality.md` | `depends` trỏ §C3. Xoá `finality_source`/`reorg_window_blocks`, dùng tên §C9.1. **Xoá `memoAud`** (§C6.5). Xoá `blockchain.zether.transfer`, dùng `.entry` (§C10.7). `chain_event_ingest` thêm `check_access` + `has_group` và một dòng ACL create cho `group_blockchain_indexer` (§C10.6). §11.10 ghi rõ memo chỉ khả dụng với 3 loại custody và đường thay thế (§C6.4). Bỏ `size=` trên `position_key`. **§11.9 GIỮ NGUYÊN quyết định không partition** — canon bản 1 lật nó trên một tiền đề sai và đã được sửa; dùng BRIN trên `observed_datetime` + cron archival hằng tháng + `autovacuum_vacuum_scale_factor = 0.02` (§C1.2). Thêm `company_id` vào `blockchain.chain.event` (§C10.1). Caller của `bamboo_create_idempotent` phải rẽ nhánh trên `created is False` và sinh `blockchain.ref.collision` (§C10.6). Thêm `bamboo_uuid` cho `blockchain.zether.entry` (§C10.7). |
| `12-threat-model.md` | Thay dòng R4 của §12.13 bằng bảng ba dòng của §07.10 (§C15.1). Sửa runbook §12.10 (`blockchain.chain.profile` không tồn tại). `group_relay_submitter` → `group_blockchain_operator` (§C14.1). Chuyển mục tiêu audit B2 sang Java/FFM + Rust (§C17.1). Ghi `SigningPolicyService` là thay thế của session key (§C15.3). |
| `13-legal-vn.md` | Thêm bảng vertical × profile (§C16) và câu "§01 vẫn hợp lệ, chỉ bị gate". Ghi câu trả lời tịch thu thành một hàng ĐỎ (§C16). Đưa ràng buộc `MODE_RESTRICT_RELAYER` vào bảng mặc định profile của §04.11 (§C16). Ghi nợ CHECK địa chỉ đã trả ở §C10.2. Chép câu chân trời bảo mật 2035–2045 vào hợp đồng dịch vụ và DPIA (§C16). Xác nhận `deploy_state`, không `state`, trong `_check_legal_class_allowed`. |
| `14-contracts-repo-testing.md` | Sinh `EXPECTED` từ §C10.1 theo công thức tên §C2.4; xoá mọi tham chiếu `blockchain.chain.profile` (§C9.1). Genesis theo §C17.2 cộng `check-genesis-fork.sh` làm required check. Curve mặc định **`bn254`** cho public profile, ghi rõ giá trị cuối do gate G1 chốt và G1 phải so **ba** dòng gồm BLS12-381 (§C6.1). Thêm preflight `eth_call 0x0c` trên Gnosis và Celo làm required check. Thêm Foundry test cấm mâu thuẫn `MODE_APPEND_SENDER` × `TargetPolicy.appendsSender` (§C8.2) và test `METERED_FEE_NOT_CONFIDENTIAL` (§C8.3). Thêm job CI `odoo-bridge` (§C3). Viết lại I7 và I20 theo §C8.3 và thêm một Foundry test cho mỗi mode. Thêm cây bốn service và CI của chúng (§C4). Thêm invariant "`C_aud` dùng chung `s`" và vector âm tương ứng. |
| `15-settlement-layer.md` | Ghi outbox row thay vì tự định nghĩa `blockchain.relay.job`; hợp nhất theo §C10.8. Xoá `bamboo_uuid = fields.Uuid(...)` (§C11.10) và `size=`. Xoá `default=` trên 5 stored compute. Thay `init()` bằng `models.Index`. Sửa `_preflight`: `chain_id.token_ids` (đã thêm, §C9.1), `token_id.max_amount_base` (đã thêm, §C10.3), `payee_account_id.zether_registered` → `_zether_registered(chain)` (§C10.2). Thêm `effect_id` vào truy vấn hướng (A) (§C10.4). Chi phí batch cộng một `rollOver` **+70 k/tài khoản nhận khi batch, +186 k cho tài khoản lần đầu** (§C5.3, §C7.3). Đổi `origin_ref` của relay job → `origin_key` (§C2.6). Cổng `final` cho `transport = 'offset'` đọc `netting_set_id.state`, không đọc relay job (§C9.4). Thêm **luồng thứ tư `LOYALTY`** với cùng độ sâu như ba luồng kia: model nguồn, quy ước `origin_key`, chiến lược batch ở khối lượng §C1, ánh xạ `gl_policy`, `reward_tax_head`, ngữ nghĩa callback. |
| `16-decomposition-roadmap.md` | Sở hữu §C1 (sizing). DoD của P03 theo §C8.3. Ngưỡng S1 theo §C7.4, **đo trên `gasUsed` của toàn bộ giao dịch relay** (1.94 M nominal, đỉnh band 2.43 M, kill ở 2.5 M); xoá `contractSizeLimit: 65536` khỏi S1 và M0. Baseline ew trừ phần descope và cộng onboarding gasless (§C19). Đưa mười sáu quyết định của §C21 vào bảng gate của roadmap. Topology addon theo §C3. Thêm danh sách ngoài phạm vi §C18 và bảng chi phí §C19. Thêm ba dòng sub-project: **services engineering** (§C4, ~3 ew), **DR + drill** (§C17.3, đưa vào P18), **UI inventory** (§C14.3, +12 ew phân bổ). Chuyển review mật mã `rollOver` vào S0 như một hợp đồng trả tiền (§C5.4). Ghi P22/P23 chạy dưới hình thái record-only (§C16). |

---

## C21. Những gì canon KHÔNG quyết được

Mười sáu quyết định dưới đây cần một con người (D1, D2, D7, D12, D14, D17 nay
đã chốt — xem `_USER-DECISIONS.md` §15 và §19), vì chúng là ngân sách, pháp lý,
hoặc một đánh đổi nghiệp vụ mà không dữ liệu kỹ thuật nào giải được.

**Chúng được liệt kê Ở ĐÂY, không ở nơi khác.** Bản 1 nói chúng nằm "ở đầu ra có
cấu trúc của phiên làm việc này" — tức trong một artefact ngoài tài liệu. Canon
là xương sống bàn giao; một đội đọc nó sáng thứ Hai chỉ biết có mười sáu mục vô
danh chặn đường tới hạn và không tra được cái họ sắp bắt đầu có nằm trong đó
không. Chính quy tắc *"không ai được tạm chọn một trong số chúng trong code"*
cũng không thực thi được nếu không có danh sách.

| # | Quyết định | Ai quyết | Chặn gì | Khuyến nghị | Chỗ giữ chỗ (`state='draft'`) |
|---|---|---|---|---|---|
| ~~**D1**~~ **ĐÃ CHỐT: `bn254`** | **Gate G1 — curve cuối** | user, 2026-08-30 | — (gate đã mở) | Spike S7 **đã chạy** và bác bỏ tiền đề của khuyến nghị cũ: BLS12-381 **không** rẻ hơn 45–60%, ở k=277 nó **đắt hơn ~2%**. Lý do duy nhất còn lại (26 bit) chưa áp dụng vì Zether chạy **private** trước. Chốt `bn254`; mở lại D1 trước khi lên public. Bằng chứng: `_USER-DECISIONS.md` §17–19 | `curve_profile = 'bn254'`, **không còn `state='draft'` vì lý do này** |
| **D2** | **Gate G2 — đóng băng struct**: `C_aud` shared-`s` + biến thể `ZTX_V1_RELAYED` với `digest_hash` trong transcript | CTO, cùng lúc với D1 | **P10**, selector và struct không retrofit được | chốt cả hai cùng G1 | `proof_system_id` để rỗng, deploy bị chặn |
| **D3** | **Chân trời bảo mật B2B**: chấp nhận "giải mã được 2035–2045" trên public, hay bắt buộc private/BLS | Ban giám đốc + pháp chế | hình thái P22 trên public | ≤ 10 năm trên `bn254`×public, hoặc chuyển private (locked #5 đã ưu tiên private cho Zether) | `confidentiality_horizon_years = 5` |
| **D4** | **Ngân sách audit** $173 k – 345 k (B → B2 → C → C2 → D → D2) | duyệt ngân sách | **mọi luồng tiền thật** | duyệt tối thiểu B + B2 trước P10 | — |
| **D5** | **Bug bounty float** $300 k ring-fenced | tài chính | mainnet public | ring-fence trước khi mở public, không phải trước private | — |
| **D6** | **Giấy phép và pháp nhân VN** (P19, 80–400 triệu ₫) | pháp chế + ban giám đốc | **P22/P23 ở hình thái thanh toán** | khởi động P19 ở S0 — lead time pháp lý dài hơn lead time kỹ thuật | `compliance_profile = 'vn_conservative'` giữ nguyên |
| **D7** | **Cấu hình custody**: C ($107/tháng) hay A/B ($2,900–9,750/tháng) | CFO + CISO | **P07 và P11** | C cho loyalty-only; A/B **bắt buộc** khi bật B2B | `blockchain.custody.provider` `state='draft'` |
| **D8** | **Hợp đồng review mật mã `rollOver`** (2–3 tuần trả tiền, vào S0) | CTO | nếu bác ⇒ **năm section revert cùng nhau** (§C5.4, +6 ew) | ký ở S0, không để tới audit phase B | `epoch` **không** được cài lại tạm |
| **D9** | **Số dư điểm thưởng có cần bảo mật không?** | nghiệp vụ marketing | nếu "có" ⇒ loyalty rời Gnosis, `memoAud` và dòng Z-POINT quay lại | **không** — số dư điểm không phải bí mật thương mại (§C1.4) | `Z-POINT.is_confidential = False` |
| **D10** | **Chain và archetype của loyalty**: Gnosis + `ZTokenOpen` (ngoại lệ freeze) hay Besu private + `ZTokenPermissioned` | pháp chế duyệt biện minh ngoại lệ freeze | **P21**, và §C1.2 hàng bốn + §C1.4 + §C19 | Gnosis + `ZTokenOpen` với biện minh ba điểm của §C16 | `blockchain.token` của Z-POINT `deploy_state='draft'` |
| **D11** | **Bootstrap relayer bên thứ ba** $30 k / 6 tháng | ngân sách | P05, và mọi thứ dựa vào nhiều hơn một relayer | duyệt cùng D4 | `blockchain.relayer` chỉ có `kind='internal'` |
| **D12** | **Cấu hình khả thi tối thiểu**: loyalty-only ~$620/tháng làm điểm khởi đầu, hay đi thẳng cấu hình đầy đủ | ban giám đốc | thứ tự P21 vs P22 | **loyalty-only trước** — rẻ hơn hai bậc độ lớn (§C19) | — |
| **D13** | **Một bit rò rỉ khi chia nhỏ B2B**: chấp nhận "trên/dưới 4.29 tỷ ₫" lộ ra trên ~1% payout, hay trả 3.33 M gas cho đường một-transfer | chủ sở hữu nghiệp vụ B2B | không chặn gì, nhưng lật §C6.2 và toàn bộ §C7.4 nếu đổi | **chấp nhận một bit** — nhánh kia phá kill criterion S1 (§C6.2) | `n_v = 32` cho Z-VND B2B |
| **D14** | **Onboarding gasless `register`**: ai mint và ký `RegistrationInvite`, relayer pool nào mang, ai ghi `onchain_state` | CTO + chủ sở hữu P21 | **giao dịch ĐẦU TIÊN** của cả hai use case; 10,000 outlet × ~95 k gas | đăng ký counterfactual từ passkey; PoP do relay pool của issuer gửi; **một** state machine `blockchain.zether.account.chain.onchain_state` với người ghi có tên — §C10.2 `_zether_registered` đọc nó và **không ai đặt nó** | `onchain_state = 'unregistered'`; **+6 ew, pha P04** |
| **D15** | **Soft finality có được dùng cho luồng payment-bound không** | CFO (khẩu vị rủi ro) | ~38,000 tx/ngày khối lượng ra mắt | **không** — §C9.4 điều kiện (5) cấm, vì `_set_error` là no-op trên tx `done` (§C10.9) | `is_payment_bound = True` ⇒ hard |
| **D16** | **`group_blockchain_manager` có kế thừa `treasury` không** | kiểm toán nội bộ | không chặn, nhưng nó là maker-checker | tổ chức có kiểm toán nội bộ **bỏ** `treasury` khỏi `implied_ids` (§C14.1) | mặc định kế thừa, ghi ra để được chọn |

Chặn theo mục tiêu, để tra ngược: **P10** ← D1, D2. **P22/P23 hình thái thanh
toán** ← D6, D3. **Mọi luồng tiền thật** ← D4. **P07 và P11** ← D7. **P21** ←
D10, D14. **P05** ← D11.

Không ai được "tạm chọn" một trong số chúng trong code. Chỗ nào cần một giá trị
để chạy tiếp, đặt nó vào seed data với `state = 'draft'` và một constraint chặn
`enabled` — đó là khuôn mẫu §C9.2 đã dựng, và cột cuối bảng trên nói rõ giá trị
giữ chỗ cho từng dòng.
