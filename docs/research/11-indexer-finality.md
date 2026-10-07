> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 11. Indexer, Finality Gate, reorg va idempotency

Mục này trả lời một câu hỏi duy nhất: **làm sao đưa sự thật on-chain vào Odoo mà không bao giờ ghi sai sổ.** Nguyên tắc kế thừa từ `dms/models/orders/dms_vietqr.py` — *"Quét QR không phải là đã thu tiền"* — dịch sang đây thành: **broadcast không phải là thanh toán, và `included` cũng chưa phải.** `_set_done()` chỉ được gọi sau Finality Gate.

Có một mệnh đề thứ hai, mạnh hơn, mà bản nháp đầu chưa nói ra và §03.2.6 buộc phải nói: **indexer này không chỉ là đường đối soát, nó là hạ tầng recovery của ví Zether.** Nếu nó mất một event `ConfidentialTransfer`, một người dùng đổi điện thoại sẽ không dựng lại được số dư của mình, và §03.2.6 quy định ví phải **dừng, không cho tiêu** khi phát hiện thiếu event. Nghĩa là: mất một dòng log ở đây không phải là một lỗ hổng báo cáo, nó là một tài khoản bị khoá. Mọi quyết định retention ở §11.9 phải đọc dưới ràng buộc đó.

---

### 11.0. Ranh giới process: indexer chạy ở đâu

| Thành phần | Chạy ở đâu | Lý do |
|---|---|---|
| Cursor, event thô, effect nghiệp vụ, ABI registry, watchlist, chính sách finality, audit | Odoo 19 addon `dms_blockchain` | Cần ACL, record rule, multi-company, view, vết kiểm toán |
| Vòng quét block / decode / reorg detector | Ban đầu: `ir.cron` gọi một method model. Chỉ tách service khi SLA yêu cầu | Xem lập luận bên dưới |
| Kho lạnh (raw log > 90 ngày, **trừ Zether**) | ClickHouse / Parquet trên Garage | Projection `olap` của note |
| Proof blob, ABI JSON, XDR/BCS payload lớn | `ir.attachment` (Many2many) trên Garage | Không base64 trong DB, không JSON blob |

**Không tách service ngay.** Trên Gnosis, hard finality là ~160–240 s (xem §11.3 — con số trong note sai). Một `ir.cron` chạy mỗi 60 giây thêm tối đa 60 s vào một cửa sổ 200 s: **+30% ở trường hợp xấu nhất, ~+15% trung bình.** Đổi lại là không có process thứ hai, không có Redis thứ hai, không có deploy riêng. Với chain private (Zether đi trước) thì càng đúng: throughput do chính ta quyết định.

Ngưỡng thăng cấp lên service `chain-indexer` (asyncio, cạnh `relay-pool` của §06), **viết ra trước để không tranh cãi sau**:

- p95 latency từ `included` đến UI > 90 s **và** có người thật phàn nàn, hoặc
- > 2,000 log/phút trên một chain (cron 60 s bắt đầu chạy quá 30 s/lượt), hoặc
- cần WebSocket push cho UX < 5 s.

```
custom-addons/dms_blockchain/models/
    blockchain_index_cursor.py      blockchain_block_header.py
    blockchain_chain_event.py       blockchain_chain_effect.py
    blockchain_contract_abi.py      blockchain_watched_address.py
    blockchain_inbound_transfer.py  blockchain_reorg_event.py
    blockchain_decoder.py           # registry (address, topic0) -> handler, thuan Python
custom-addons/dms_blockchain/data/ir_cron.xml
```

Prefix `blockchain.*` (khớp §03/§04/§06/§10.3). Định danh chain dùng **CAIP-2** (`eip155:100`, `eip155:42220`, `sui:mainnet`, `stellar:pubnet`, `hedera:mainnet`, `ton:-239`). Trường `chain_id` là Many2one tới `blockchain.chain`; số nguyên EVM nằm ở `blockchain.chain.evm_chain_number` (đã định nghĩa ở §08.1).

> Ghi chú nhất quán: §05 viết `dms.blockchain.chain.chain_profile`, §03/§06/§10 viết `blockchain.*`. **Chốt `blockchain.*`** — prefix `dms.` sẽ ngụ ý phụ thuộc `dms`, đúng thứ mà quyết định khoá #7 cấm.

**Ba thứ về `ir.cron` phải biết trước khi viết dòng code đầu tiên**, vì cả ba đều im lặng:

1. **`ir.cron` không chạy chồng chính nó**, nhưng lý do là `SELECT … FOR UPDATE NOWAIT` trên dòng cron, không phải một lock nghiệp vụ. Nếu một method RPC (`chain_event_ingest`) cũng gọi cùng vòng quét, hai luồng **sẽ** chạy song song. Bắt buộc thêm advisory lock ở tầng nghiệp vụ:
   ```python
   def _try_scan_lock(self, caip2):
       self.env.cr.execute(
           "SELECT pg_try_advisory_xact_lock(hashtext(%s))", ('bc.scan:' + caip2,))
       return self.env.cr.fetchone()[0]
   ```
   `_xact_` (transaction-scoped) chứ không phải session-scoped: nó tự nhả khi transaction kết thúc, kể cả khi worker bị kill. Không có `try/finally` nào phải viết.

2. **Cron bị giết theo `limit_time_real_cron`** (mặc định lấy theo `limit_time_real`, thường 120 s). Một vòng quét backfill 2 triệu block sẽ bị `SIGXCPU` giữa chừng. Vì vậy vòng quét phải **tự giới hạn thời gian**, không giới hạn theo số block:
   ```python
   DEADLINE_SECONDS = 50          # < limit_time_real_cron / 2
   started = time.monotonic()
   while time.monotonic() - started < DEADLINE_SECONDS:
       processed = self._scan_one_chunk(chain)
       self.env.cr.commit()       # commit tung chunk: cron duoc phep commit
       if not processed:
           break
   ```
   `cr.commit()` trong cron là hợp lệ (Odoo tự commit giữa các job). Không commit từng chunk thì một backfill 200 chunk sẽ giữ một transaction 50 s, chặn vacuum và mất sạch khi bị giết.

3. **Cron không đảm bảo tần suất.** `interval_number = 1 minute` là *tối thiểu*, không phải *đúng*. Nếu cron worker bận, khoảng cách có thể là 10 phút. Mọi tính toán SLA phải dùng `scan_datetime` thật, không dùng cấu hình cron.

---

### 11.0b. Mười giả định bản nháp không nói ra

| # | Giả định ngầm | Đúng/Sai | Xử lý ở đâu |
|---|---|---|---|
| A1 | Mọi chain có "block number" là số nguyên vừa `int4` | **Sai** — TON `lt` ≈ 5×10^10, Hedera consensus timestamp nanos ≈ 1.7×10^18. `fields.Integer` của Odoo là `int4` (trần 2,147,483,647) | §11.2, `position_key` |
| A2 | RPC nói thật về `finalized` | **Sai** — một node tụt hậu trả `finalized` cũ; một node trên fork trả `finalized` của fork đó | §11.3b |
| A3 | Một `Transfer` log với `to = địa chỉ của ta` là tiền thật | **Sai và tốn tiền** — bất kỳ contract nào cũng phát được event bất kỳ, với giá ~$0.00006 trên Gnosis | §11.8b |
| A4 | Event decode được ngay khi có ABI | Đúng cho non-indexed; **sai cho `string`/`bytes`/array `indexed`** — topic chỉ chứa keccak, giá trị không khôi phục được | §11.6 |
| A5 | `block.timestamp` dùng được để xác định kỳ kế toán | **Sai** — timestamp do người tạo block đặt, dung sai ±15 s trên Ethereum, tuỳ ý trên chain private | §11.2b |
| A6 | Effect và bút toán kế toán ở cùng một transaction | Không nói ra, và **phải** như vậy, nếu không idempotency là giả | §11.5b |
| A7 | Đủ tiền để lưu raw log mãi mãi | Sai với chain public; **nhưng bắt buộc với Zether** vì §03.2.6 | §11.9 |
| A8 | Third-party indexer là một nguồn thay thế được | **Sai** — nó là nguồn *gợi ý*; mọi transition `final` phải tự verify | §11.1 |
| A9 | Amount của Zether chỉ lấy được qua BSGS hoặc người nhận | **Lỗi thời** — §03.2.5 đã thêm memo AEAD 32 B, giải mã 60 µs | §11.10 |
| A10 | `topic0` là khoá đủ cho decoder registry | **Sai** — `Transfer(address,address,uint256)` có cùng `topic0` trên mọi ERC-20 trên đời | §11.6 |

---

### 11.1. Ba đường nạp dữ liệu, và tại sao backfill luôn bắt buộc

| Đường | Dùng làm gì | Không được dùng làm gì |
|---|---|---|
| `eth_subscribe(logs/newHeads)` qua WebSocket | Gợi ý "có block mới, quét sớm đi" | **Nguồn sự thật.** WS rớt im lặng, mất log trong lúc reconnect, provider giới hạn số subscription, và `removed: true` chỉ đến nếu ta đang kết nối |
| `eth_getLogs(fromBlock, toBlock, address, topics)` theo watermark | **Nguồn sự thật duy nhất** | Không dùng cho native transfer (xem §11.8) |
| Indexer bên thứ ba (Ponder / Subsquid / Goldsky / Envio) | Backfill lịch sử sâu, analytics, chain lạ | Không đưa thẳng vào sổ kế toán khi chưa qua Finality Gate của chính ta |

Vòng lặp chính là **range scan theo cursor**, một code path duy nhất phục vụ cả tip-follow lẫn backfill. WS chỉ làm một việc: đánh thức vòng lặp sớm hơn `poll_interval`. Đây vừa là thiết kế đúng, vừa là thiết kế ít code nhất.

**Third-party indexer: hợp đồng tin cậy phải viết ra.** Bản nháp nói "không đưa thẳng vào sổ kế toán" nhưng không nói *cơ chế* nào ngăn. Cụ thể:

```python
TRUST = {
    'third_party': {'may_write': ['head'], 'may_set_final': False},
    'own_rpc':     {'may_write': ['head', 'final'], 'may_set_final': True},
}
```

Mọi transition sang `final` bắt buộc chạy lại **hai** call trực tiếp trên endpoint có `is_independent = True` (§08.1): `eth_getTransactionReceipt(tx_hash)` và `eth_getBlockByNumber(block_number)`, rồi so `receipt.blockHash == block.hash` và `block.hash` nằm trên nhánh đã xác thực. Chi phí: 2 RPC call cho mỗi tx sắp thành tiền — không đáng bàn ở 10k tx/ngày (20k call/ngày), và nó là ranh giới giữa "một nhà cung cấp SaaS bị hack có thể tạo tiền trong sổ của ta" và "không thể".

Backfill là bắt buộc, không phải tuỳ chọn, vì **sáu** lý do đều chắc chắn xảy ra:

1. Cold start / khôi phục DB từ backup.
2. Gap sau outage RPC hoặc sau khi Odoo down.
3. Thêm một contract hoặc một watched address mới → phải quét ngược.
4. Sửa bug decode hoặc đăng ký ABI mới → **re-decode** trên raw đã lưu (đây là lý do raw phải append-only và không bao giờ bị ghi đè).
5. Chain không có log stream: TON không có event, phải đi bộ transaction theo `lt`; Hedera phải hỏi mirror node REST.
6. **Recovery ví Zether** (§03.2.6): một người dùng cài lại app cần toàn bộ `ConfidentialTransfer` từ block đăng ký tài khoản. Đây là backfill *theo yêu cầu người dùng*, không phải theo lịch, và nó phải trả lời trong vài giây — nghĩa là dữ liệu phải nằm sẵn trong Postgres/archive của ta, không phải đi hỏi lại RPC.

**Ràng buộc lưu trữ theo chain — note bỏ sót hoàn toàn:**

| Chain | Cửa sổ dữ liệu của RPC thường | Hệ quả |
|---|---|---|
| Soroban RPC | `EVENT_LEDGER_RETENTION_WINDOW` mặc định **17,280 ledger ≈ 24 giờ**; trần giao thức 7 ngày | Backfill sâu hơn phải qua Horizon / Galexie / Hubble archive. Phải chốt nguồn archive **trước** khi go-live, không phải sau |
| Sui full node | Pruning bật mặc định trên node thường | Cần archival node hoặc checkpoint từ S3 bucket của Mysten |
| TON | Public RPC prune mạnh | Cần liteserver riêng hoặc TON Index |
| EVM public RPC | `eth_getLogs` giới hạn 2k–10k block hoặc 10k log/lần | Chunk thích ứng, chia đôi khi gặp lỗi "query returned more than N results" |
| **Celo sau migration L2 (03/2025)** | Node L2 **không** phục vụ block trước migration qua RPC chuẩn | Lịch sử pre-L2 cần endpoint archive riêng. Nếu chain #2 cần backfill quá mốc migration, đây là một endpoint thứ hai phải mua/chạy — **note và bản nháp đều bỏ sót** |
| Erigon/reth chạy `--prune.r` | Receipt và log **bị xoá** | Recovery Zether gãy hoàn toàn (§03.2.6). Cấu hình node bắt buộc: cấm prune receipt/log |

#### 11.1b. Ngân sách RPC: nó có vừa quota không

Bản nháp không có một con số nào về tải RPC. Đây là thứ quyết định "tự chạy node hay mua Alchemy", nên phải có.

Một chain EVM, cron 60 s, block 5 s (Gnosis) → 12 block/chu kỳ:

| Call | Số/chu kỳ | Số/ngày | Ghi chú |
|---|---|---|---|
| `eth_blockNumber` | 1 | 1,440 | head |
| `eth_getBlockByNumber("finalized")` | 1 | 1,440 | finality tag |
| `eth_getBlockByNumber(cursor)` header-only | 1 | 1,440 | reorg tầng 1 |
| `eth_getLogs` (1 range, mọi contract watched) | 1–3 | ~2,900 | chunk thích ứng |
| `eth_getBlockByNumber(n, true)` quét native | 12 | 17,280 | §11.8 |
| Xác minh `final` (2 call/tx) | — | 2 × tx/ngày | 20,000 ở 10k tx/ngày |
| **Tổng** | | **~44,500/ngày/chain** | |

Quy đổi compute unit (Alchemy, *ước tính*, giá CU thay đổi theo thời gian): `getBlockByNumber` ~24 CU, `getLogs` ~75 CU, `getTransactionReceipt` ~15 CU → ~44,500 × ~28 CU ≈ **1.25 M CU/ngày ≈ 37 M CU/tháng** cho một chain. Hai chain (Gnosis + Celo) ≈ 75 M CU/tháng. Gói free thường 300 M CU/tháng → **vừa, với biên 4×**. Kết luận: không cần tự chạy node vì lý do quota; cần tự chạy node vì lý do `is_independent` trong `finality_quorum` (§08.1) và vì lý do prune (bảng trên).

Con số đổi hoàn toàn nếu bật `debug_traceBlock` (§11.8, cách 1): trace một block Gnosis tốn ~10–30× một `getBlockByNumber` → +200 M CU/tháng, và phần lớn provider **không mở** `debug_*` ở tier thường. Đó là lý do §11.8 chọn cách 2.

---

### 11.2. Watermark, crash recovery, và thứ tự commit

Hai cursor cho mỗi (chain, stream), **không phải một**:

```python
class BlockchainIndexCursor(models.Model):
    _name = 'blockchain.index.cursor'
    _description = 'Per-chain, per-stream indexing watermark'

    chain_id       = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    stream_key     = fields.Char(required=True, index=True)   # 'logs', 'headers', 'native', 'sui:checkpoints'
    kind           = fields.Selection([('head', 'Head (optimistic)'),
                                       ('final', 'Final (gated)')], required=True)

    # Vi tri chuan: chuoi sap xep duoc theo thu tu tu dien. Xem ghi chu A1 ben duoi.
    position_key   = fields.Char(required=True, index=True, size=64)
    # Tien nghi hien thi / loc nhanh cho EVM. KHONG duoc dung lam khoa sap xep.
    last_block_number = fields.Integer(required=True, default=0)
    last_block_hash   = fields.Char(size=66, index=True)

    scan_datetime     = fields.Datetime(readonly=True)
    lag_blocks        = fields.Integer(readonly=True)
    lag_seconds       = fields.Integer(readonly=True)
    state          = fields.Selection([('running', 'Running'), ('paused', 'Paused'),
                                       ('rewinding', 'Rewinding'), ('halted', 'Halted')],
                                      required=True, default='paused', index=True)

    _unique_cursor = models.Constraint(
        'UNIQUE(chain_id, stream_key, kind)',
        'Moi (chain, stream, kind) chi co dung mot cursor.')
```

**A1 — sửa lỗi kiểu dữ liệu mà bản nháp mắc phải.** Bản nháp dùng `last_block_number = fields.Integer` làm khoá vị trí. `fields.Integer` của Odoo ánh xạ sang **`int4`**, trần 2,147,483,647. Điều đó hỏng ở hai chain trong sáu chain:

| Chain | Đơn vị vị trí | Độ lớn hiện tại | Vừa `int4`? |
|---|---|---|---|
| EVM (Gnosis) | block number | ~4.3 × 10^7 | Có |
| Sui | checkpoint seq | ~1 × 10^8 | Có |
| Soroban | ledger seq | ~5 × 10^7 | Có |
| **TON** | `lt` (logical time) | **~5 × 10^10** | **Không — tràn 23×** |
| **Hedera** | consensus timestamp (s.nanos) | **~1.7 × 10^18** | **Không — tràn 8×10^8 lần** |

Odoo 19 không có `fields.BigInteger`. Ba đường: (a) `fields.Char` chứa số thập phân **zero-pad**, so sánh từ điển = so sánh số; (b) `fields.Float` — sai, mất chính xác trên 2^53; (c) SQL thô — vỡ ORM. **Chọn (a)**, khớp với kết luận §10.4.1 ("uint256 không vừa vào bất kỳ field số nào của Odoo").

Định dạng `position_key`, cố định cho mọi chain, dài 64 ký tự, ASCII, so sánh từ điển ra đúng thứ tự thời gian:

```
EVM      :  "E" + block(018d) + ":" + tx_index(06d) + ":" + log_index(06d)
             E000000000043210987:000123:000007
Sui      :  "S" + checkpoint(018d) + ":" + event_seq(06d)
Soroban  :  "L" + ledger(018d) + ":" + op_index(06d)
TON      :  "T" + mc_seqno(018d) + ":" + lt(020d)
Hedera   :  "H" + consensus_seconds(012d) + "." + nanos(09d)
```

18 chữ số bao trọn `uint64` (1.8×10^19). Chi phí: 64 B/dòng thay vì 4 B, và một index B-tree text thay vì int. Ở 100 M dòng đó là ~6 GB text + ~4 GB index — đắt. Vì vậy: **`position_key` chỉ nằm trên cursor và trên `blockchain.chain.event`; các bảng phụ tham chiếu qua `event_id`.**

- **`head`** bám tip, có thể bị reorg kéo lùi. Cấp dữ liệu cho UI ở trạng thái `pending`.
- **`final`** chỉ tiến khi block đã qua Finality Gate. Chỉ cursor này được phép kích hiệu ứng kế toán.

Sáu quy tắc crash recovery, **theo đúng thứ tự này**:

1. **Ghi event và tiến cursor trong CÙNG một transaction Postgres.** Nếu tách, một crash ở giữa hoặc mất event (cursor tiến trước) hoặc lặp event (event ghi trước — vô hại nhờ idempotency). Vẫn ghi event trước rồi tiến cursor trong cùng transaction: nếu ai đó lỡ tách ra sau này, hướng lỗi rơi về phía an toàn.
2. **Khi khởi động, xác thực cursor.** Gọi `eth_getBlockByNumber(last_block_number)` và so `hash` với `last_block_hash`. Lệch → chuyển `state='rewinding'`, chạy §11.4. Đây là một RPC call, chạy mỗi lần start, không có lý do gì để bỏ.
3. **At-least-once là hợp đồng.** Không cố đạt exactly-once ở tầng vận chuyển — nó không tồn tại. Đạt exactly-once ở **hiệu ứng**, qua §11.5.
4. **Cron janitor** phát hiện cursor đứng im: `scan_datetime` cũ hơn `10 × poll_interval` → tạo `ops` alert. Không tự restart; một cursor đứng im thường là RPC nói dối chứ không phải process chết.
5. **Cursor không bao giờ lùi trừ khi qua `rewinding`.** Ràng buộc ở tầng code (`_write` chặn `position_key` giảm khi `state != 'rewinding'`), không ở tầng SQL — vì rewind là hợp lệ. Một cursor lùi "tự nhiên" nghĩa là hai process đang chạy song song, tức là advisory lock ở §11.0 đã hỏng.
6. **Backfill và tip-follow dùng cursor khác nhau.** `stream_key = 'logs'` cho tip, `stream_key = 'logs:backfill:<job_id>'` cho mỗi job backfill. Chúng gặp nhau ở bảng event, và §11.5 xử lý va chạm. Dùng chung một cursor cho cả hai là cách chắc chắn nhất để một backfill kéo tip lùi lại 2 triệu block.

Chunk thích ứng: bắt đầu `chunk = 2000` block, nhân đôi khi thành công 5 lần liên tiếp (trần `blockchain.rpc.endpoint.max_log_block_range`, §08.1), chia đôi khi provider từ chối (sàn 1). Không cần cấu hình — nó tự tìm giới hạn của provider. **Sàn phải là 1, không phải 0**, và khi chunk = 1 mà vẫn lỗi "too many results" thì đó là một block có > 10,000 log: chuyển sang lọc theo từng `address` trong watchlist thay vì lọc theo topic. Đã xảy ra thật trên các block airdrop.

#### 11.2b. Thời gian: `block.timestamp` không phải đồng hồ kế toán

Bản nháp không nhắc, và đây là một lỗi kế toán thật. `block.timestamp` do người tạo block đặt:

- Ethereum/Gnosis: consensus chấp nhận lệch tới ~±12 s so với slot; validator có thể đặt lệch mà không bị phạt.
- Chain private: operator đặt gì cũng được. Một node lệch NTP 3 tiếng sẽ tạo block "trong tương lai".
- Hedera: `consensus_timestamp` là aBFT và đáng tin hơn nhiều — trường hợp duy nhất trong sáu chain.

Hệ quả: một transfer trong block có `timestamp = 2026-12-31T23:59:50Z` nhưng đạt finality lúc `2027-01-01T00:03:00Z` sẽ vào kỳ nào? Quyết định, viết vào code chứ không để mặc:

```python
block_datetime      = fields.Datetime(readonly=True)   # tu chain, chi de tham chieu
observed_datetime   = fields.Datetime(readonly=True)   # khi indexer thay
final_datetime      = fields.Datetime(readonly=True)   # khi qua Finality Gate  <-- KY KE TOAN
clock_skew_seconds  = fields.Integer(readonly=True)    # observed - block, de canh bao
```

**Kỳ kế toán lấy theo `final_datetime`** (đồng hồ của Odoo, đồng hồ mà kiểm toán viên tin). `block_datetime` chỉ để đối chiếu và để đo skew. Cảnh báo khi `abs(clock_skew_seconds) > 300` — trên chain public đó là dấu hiệu RPC hỏng, trên chain private đó là dấu hiệu NTP hỏng ở một validator.

---

### 11.3. Finality: bảng trong note sai ở năm chỗ, ba chỗ quan trọng

Bảng §10.4 của note dùng được về hình dạng nhưng sai về số ở những chuỗi ta triển khai **đầu tiên**. Dưới đây là bản đã sửa, kèm cột `finality_source` — thứ note không có và là thứ quyết định implementation.

| Chain | Note viết | Thực tế | `finality_source` |
|---|---|---|---|
| Ethereum L1 | 2 epoch, ~12.8 phút | 12.8 phút là **cận dưới**. Tuỳ vị trí slot trong epoch, thực tế 12.8–19.2 phút, trung bình ~15–16 phút | `tag` — hỏi node `eth_getBlockByNumber("finalized")`, đừng đếm block |
| Arbitrum One | Soft 1 s / Hard 15 phút | Soft = **lời hứa của một sequencer tập trung**, không phải đồng thuận; đã từng reorder. Hard = batch được post lên L1 **và** block L1 đó finalized: điển hình 20–40 phút. Trường hợp xấu bị chặn bởi **force-inclusion window = 24 giờ** (`delaySeconds = 86400`), không phải "vài giờ" | `tag` (`finalized`) |
| Base / OP Stack | Gộp chung với Arbitrum | Khác cơ chế: `safe` = derive được từ batch trên L1 (vài phút, theo batcher interval), `finalized` = block L1 đó finalized (~15–20 phút). `unsafe` head reorg được | `tag` (`safe` cho soft, `finalized` cho hard) |
| **Polygon PoS** | Heimdall Checkpoint, ~25–30 phút | **Nhầm hai khái niệm.** *Milestone* (Heimdall, 2/3+ vote) mới là finality nội chain và là thứ tag `finalized` của Bor trả về; sau Bhilai/Rio (2025) thực tế **~5 s**. *Checkpoint* lên L1 mỗi ~30 phút chỉ cần cho bridge/withdraw. Note quá bảo thủ hàng trăm lần, **vì lý do sai**. Xác nhận lại con số tại thời điểm deploy | `tag` |
| **Gnosis xDAI** | 2 epoch, ~12.8 phút | **Sai.** Gnosis Beacon: slot 5 s, **16 slot/epoch** → epoch = 80 s. Finalize xảy ra 2 epoch sau epoch chứa block → **160–240 s (~3–4 phút)**, không phải 12.8 phút. Đây là chain #1 của ta và con số này sai theo hướng bất lợi | `tag` |
| **Celo** | IBFT 2.0, immediate finality, 1 block ~5 s | **Lỗi thời.** Celo đã migrate thành **L2 OP Stack trên Ethereum** (hardfork Cel2, 03/2025). Block time ~1 s, không còn IBFT instant finality; nay theo ngữ nghĩa `unsafe/safe/finalized` của OP Stack. Chain #2 của ta **phải được thiết kế lại như một rollup**, không như một BFT chain. Kèm hệ quả backfill ở §11.1 | `tag` — xác nhận lại tại thời điểm deploy |
| Hedera | 1 confirmation, 3–5 s | Đúng: aBFT, **không có reorg về mặt cấu trúc**. Nhưng thứ ta index là **mirror node**, và mirror node trễ 1–10 s, có thể stale hoặc thủng. Chế độ hỏng khác, cần gate khác | `attested` — cross-check 2 mirror node độc lập, cộng ràng buộc `now − consensus_timestamp ≥ 10 s` |
| TON | Masterchain inclusion, 5–10 s | Đúng về hình dạng. Đơn vị finality là **shard block được masterchain tham chiếu**, nên gate là `mc_seqno`, không phải "depth" | `reference` (mc_seqno) |
| SUI | Checkpoint cert, 400 ms – 2 s | 400 ms chỉ đúng cho **owned object fast-path**. Mọi contract có state dùng chung (token, Zether) đều là **shared object** → qua Mysticeti, 2–3 s. Note gợi ý một con số ta sẽ **không bao giờ** đạt | `checkpoint` |
| Soroban XLM | Ledger closed, ~5 s | Đúng, SCP không fork. Vấn đề thật là **retention của RPC** (§11.1), không phải finality | `ledger_close` |
| CosmWasm | 1 block, immediate, ~6 s | Đúng dưới giả định honest-supermajority. Nhưng CometBFT chain **bị rewind** bởi governance rollback hoặc halt-and-restart-from-snapshot; chuyện này đã xảy ra nhiều lần trên Cosmos | `depth=1` + **bắt buộc giữ hash check** |

**Điều "immediate finality" thật sự nghĩa là gì.** Trên chain BFT, nó nghĩa là *không có fork dưới giả định ≤1/3 byzantine* — **không** phải "không bao giờ bị kéo lùi". Bốn đường kéo lùi thật: (a) governance rollback, (b) halt rồi restart từ state export tại height H, (c) node phục vụ từ state đã prune hoặc từ một fork, (d) >1/3 equivocate (có thể quy trách nhiệm, nhưng thiệt hại đã xảy ra). Hệ quả implementation: **hash-verification không bao giờ được tắt trên bất kỳ chain nào.** Depth có thể bằng 1; hash check thì không.

**Chain private (profile đi trước cho Zether).** Finality tức thời về mặt đồng thuận, nhưng operator — chính chúng ta — rewind lúc nào cũng được. Ở đây "final" không phải một tính chất mật mã mà là một **cam kết vận hành**. Để nó có nghĩa: ký head hash mỗi N block bằng khoá HSM và neo (anchor) sang một chain công khai hoặc Hedera HCS (`TopicMessageSubmitTransaction`).

*Định lượng anchor (ước tính, cơ sở: bảng giá HCS ~$0.0001/message, chưa gồm biến động HBAR):*

| Chu kỳ neo | Message/ngày | Chi phí/ngày | Chi phí/năm | Cửa sổ có thể rewind mà không để lại vết |
|---|---|---|---|---|
| 15 s | 5,760 | $0.58 | $210 | ≤ 15 s |
| 60 s | 1,440 | $0.14 | $53 | ≤ 60 s |
| 5 phút | 288 | $0.03 | $11 | ≤ 5 phút |

Chọn **60 s** cho chain private: $53/năm để biến "tôi hứa không rewind" thành "rewind quá 60 s là chứng minh được". Neo mỗi 15 s không mua thêm gì đáng giá vì thời gian phát hiện của con người tính bằng phút.

Cấu hình trên `blockchain.chain` (bổ sung cho §08.1, không thay thế):

```python
finality_source  = fields.Selection([('tag', 'Node finalized/safe tag'), ('depth', 'Block depth'),
                                     ('checkpoint', 'Checkpoint / mc_seqno'),
                                     ('ledger_close', 'Ledger close'),
                                     ('attested', 'Attested by N sources')],
                                    required=True, default='depth')
finality_depth   = fields.Integer(required=True, default=1)
soft_depth       = fields.Integer(required=True, default=1)
finality_warn_seconds  = fields.Integer(required=True, default=1800)
finality_stuck_seconds = fields.Integer(required=True, default=3600)
reorg_window_blocks = fields.Integer(required=True, default=64,
                                     help='So header giu lai de do reorg. >= 2 * finality_depth, toi thieu 64.')
anchor_interval_seconds = fields.Integer(default=0, help='0 = khong neo. Chi co nghia khi chain_profile=private.')
```

Bản nháp có một ngưỡng (`finality_max_wait_seconds`); **cần hai**, vì hai ngưỡng trả lời hai câu hỏi khác nhau:

- `finality_warn_seconds` — "bất thường, nhìn xem": tạo activity, không chặn gì.
- `finality_stuck_seconds` — "coi như hỏng": chuyển effect sang `stuck`, page người thật, và **giữ tiền ở treo**.

Giá trị theo chain (`warn` / `stuck`):

| Chain | warn | stuck | Cơ sở |
|---|---|---|---|
| Gnosis | 600 s | 1,800 s | hard finality 240 s → 2.5× là bất thường, 7.5× là hỏng |
| Celo (L2) | 1,800 s | 5,400 s | `finalized` phụ thuộc L1 Ethereum |
| Arbitrum | 3,600 s | **93,600 s (26 h)** | force-inclusion window 24 h + biên. Một cảnh báo `stuck` ở 15 phút sẽ kêu mỗi ngày và bị tắt đi — tệ hơn không có |
| Private (QBFT) | 60 s | 300 s | block 2 s, depth 1 |

#### 11.3b. `finalized` tag nói dối như thế nào

Bản nháp chọn `finality_source = 'tag'` cho hầu hết chain nhưng không nói tag sai được. Ba cách:

1. **Node tụt hậu.** Một RPC đang sync trả `finalized` của 3 giờ trước. Hậu quả: ta chờ vô ích (an toàn) — nhưng nếu tag đó *tiến* nhanh hơn thực tế thì không an toàn.
2. **Node trên fork.** Trong một split nhẹ, `finalized` là finalized *của nhánh đó*.
3. **Node vừa restart từ checkpoint sync.** `finalized` có thể nhảy hoặc trả về 0 trong vài phút đầu.

Ba biện pháp, tất cả rẻ:

```python
def _finalized_head(self, chain):
    """Tra ve block da finalized, hoac raise. Khong bao gio tra ve mot con so doan."""
    blocks = [ep.rpc('eth_getBlockByNumber', 'finalized', False)
              for ep in chain.endpoint_ids.filtered(
                  lambda e: e.state == 'live' and e.is_independent)[:chain.finality_quorum]]
    if len(blocks) < chain.finality_quorum:
        raise NotEnoughEndpoints(chain.caip2)
    lowest = min(blocks, key=lambda b: int(b['number'], 16))
    # (1) quorum phai dong y ve HASH tai chieu cao thap nhat, khong chi ve so
    for b in blocks:
        h = self._hash_at(b, int(lowest['number'], 16))
        if h != lowest['hash']:
            raise FinalityDisagreement(chain.caip2, lowest['number'])
    # (2) finalized khong duoc phep lui
    if lowest_number < chain.last_finalized_number:
        raise FinalityRegressed(chain.caip2)
    # (3) tuoi hop ly: finalized qua moi la dau hieu node noi doi
    age = now - int(lowest['timestamp'], 16)
    if age < chain.hard_final_seconds * 0.5:
        raise FinalityTooFresh(chain.caip2, age)
    return lowest
```

Ba lỗi này đều dẫn tới **không tiến `final` cursor** chứ không dẫn tới rollback — hướng lỗi đúng. `finality_quorum` mặc định 2 và ít nhất một endpoint phải là node của chính ta (§08.1 `is_independent`); hai API key Alchemy khác nhau **không** phải hai nguồn.

---

### 11.4. Reorg: phát hiện, và bù trừ

**Phát hiện, hai tầng (rẻ trước, đắt sau):**

```
Tang 1 (moi lan poll, 1 RPC call):
    header = getBlockByNumber(head_cursor.last_block_number)
    if header.hash == head_cursor.last_block_hash: khong co reorg, quet tiep
Tang 2 (chi khi tang 1 lech):
    di nguoc blockchain.block_header theo parent_hash, tim common ancestor
    khong tim thay trong reorg_window_blocks -> HALT chain, goi nguoi that
```

Tầng 1 bắt gần như toàn bộ reorg thực tế với chi phí một call. Tầng 2 là đường tìm ngược trong bảng header cuộn (`reorg_window_blocks` dòng, ~150 B/dòng → 64 dòng = 10 KB, không đáng bàn).

**Sizing `reorg_window_blocks` bằng số liệu thật, không bằng cảm giác:**

| Chain | Độ sâu reorg điển hình | Sâu nhất đã ghi nhận | `reorg_window_blocks` đề xuất |
|---|---|---|---|
| Ethereum PoS | 1 | 7 (05/2022, beacon) | 64 |
| Gnosis | 1–2 | ~5 | 64 |
| Polygon PoS (trước milestone) | 3–30 | **157** (03/2022) | 512 nếu vì lý do nào đó không dùng tag `finalized` |
| OP Stack `unsafe` head | 1 | sequencer restart có thể xoá vài trăm block | 1,024 trên đường `unsafe`; không dùng đường `unsafe` cho tiền |
| Chain private QBFT | 0 | rewind thủ công không giới hạn | 1,024 + anchor (§11.3) |

64 là mặc định đúng cho Gnosis/Celo/Ethereum. Đừng để nó là mặc định cho Polygon.

**Model `blockchain.reorg.event` — bản nháp liệt kê file nhưng không định nghĩa:**

```python
class BlockchainReorgEvent(models.Model):
    _name = 'blockchain.reorg.event'
    _description = 'One detected chain reorganisation'
    _order = 'detected_datetime desc'

    chain_id            = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    detected_datetime   = fields.Datetime(required=True, readonly=True, index=True)
    depth               = fields.Integer(required=True, readonly=True)
    ancestor_block      = fields.Integer(required=True, readonly=True)
    orphaned_hash       = fields.Char(size=66, readonly=True)
    canonical_hash      = fields.Char(size=66, readonly=True)
    orphaned_event_count = fields.Integer(readonly=True)
    crossed_final_gate  = fields.Boolean(readonly=True, index=True,
                                         help='True = mot block da qua Finality Gate bi dao. Su co nghiem trong.')
    affected_effect_ids = fields.Many2many('blockchain.chain.effect')
    resolution_state    = fields.Selection([('auto_rescanned', 'Auto rescanned'),
                                            ('awaiting_human', 'Awaiting human'),
                                            ('reversed', 'Reversed by accountant'),
                                            ('confirmed_benign', 'Confirmed benign')],
                                           required=True, default='auto_rescanned', index=True)

    _unique_reorg = models.Constraint(
        'UNIQUE(chain_id, ancestor_block, orphaned_hash)',
        'Mot reorg tai cung mot diem chi ghi mot lan.')
```

Model này tồn tại vì một lý do cụ thể: **tần suất reorg là một chỉ số sức khoẻ chain, và nó phải đo được.** Nếu Gnosis đột nhiên reorg 20 lần/giờ, đó là tín hiệu tạm dừng luồng tiền *trước* khi có sự cố, không phải sau.

**Bù trừ theo trạng thái — đây là phần note hoàn toàn không nói:**

| Trạng thái khi bị reorg | Xử lý |
|---|---|
| `observed` / `included` (chưa qua gate) | Đánh dấu event `orphaned` (**không xoá**), lùi `head_cursor` về common ancestor, quét lại nhánh canonical. Effect chưa được áp → không có gì để hoàn |
| `final` bị reorg | **Sự cố nghiêm trọng.** Không tự động đảo. `blockchain.chain.state = 'halted'`, effect chuyển `finality_violation`, page người thật. Bút toán đảo (`account.move` reversal, **không bao giờ xoá**) chỉ tạo sau khi người duyệt. Lý do: tự động đảo một bút toán đã post, dựa trên một chain vừa chứng minh là không đáng tin, là chế độ hỏng tệ hơn một record bị treo |

Có một trường hợp thứ ba mà bản nháp bỏ sót: **reorg xảy ra *trong khi* backfill đang chạy trên cùng chain.** Backfill đọc một range cũ; tip-follower phát hiện reorg và lùi `head_cursor`. Nếu backfill đang ở range chồng lấn với vùng bị reorg, nó sẽ ghi event của nhánh chết. Xử lý: mọi job backfill mang một `branch_guard = head_cursor.last_block_hash tại lúc bắt đầu`; khi §11.4 phát hiện reorg, nó set `blockchain.index.cursor.state = 'rewinding'` cho **mọi** stream của chain đó, và backfill kiểm cờ này ở đầu mỗi chunk rồi tự dừng. Backfill dưới `ancestor_block` không bị ảnh hưởng và có thể chạy tiếp — nhưng "kiểm cờ rồi dừng" là 3 dòng code và đúng trong mọi trường hợp.

**Tại sao Finality Gate làm trường hợp thứ hai gần như không thể.** Trên Gnosis với `finality_source='tag'`, để một block `finalized` bị đảo cần ≥1/3 stake equivocate và bị slash — chi phí hàng trăm triệu USD, và nó chưa từng xảy ra trên bất kỳ chain Gasper nào. Đó chính là toàn bộ lý do tồn tại của Gate: **không phải để làm reorg-sau-done trở nên rẻ để xử lý, mà để làm nó trở nên đắt tới mức không xảy ra.** Ngược lại, trên chain private xác suất không do mật mã quyết định mà do chính sách vận hành — nên ở profile private, `finality_violation` là một rủi ro **quản trị**, và phải được viết vào runbook chứ không vào code.

Lưu ý cross-section: §09.7 cho phép `finality_mode = 'soft'` với `soft_final_max_amount` cho luồng `ENDUSER_PAY`. Điều đó **không mâu thuẫn** với mục này, nhưng phải nói rõ ranh giới: ở chế độ soft, `_set_done` chạy sớm và một reorg sau đó tạo `blockchain.payment.reversal` + activity, **không** rollback. Đó là một quyết định thương mại có giá trần (`soft_final_max_amount`), không phải một ngoại lệ kỹ thuật. Mọi luồng B2B settlement và loyalty mint phải là `hard`.

Một điểm kỹ thuật hay bị bỏ sót: **`log_index` không ổn định qua reorg.** Cùng một tx, được đóng lại vào block khác, gần như chắc chắn có `tx_index` và `log_index` khác. Mọi khoá dedup dựa trên `(tx_hash, log_index)` sẽ tạo bản ghi trùng sau reorg. Xem §11.5.

Thêm một điểm ít ai nghĩ tới: **`tx_hash` cũng không bất biến qua mọi chain.** Trên EVM nó là hash của signed tx và ổn định. Trên Hedera, một tx bị `DUPLICATE_TRANSACTION` phải sinh `validStart` mới → `TransactionId` mới (§08.2d). Trên Cosmos, thay `sequence` đổi hash. Vì vậy `tx_hash` là khoá tra cứu tốt, không phải khoá nghiệp vụ. Khoá nghiệp vụ là `ref` ở §11.5 tầng 1.

---

### 11.5. Exactly-once: ba tầng khoá, và `bamboo_idempotency`

Exactly-once *delivery* không tồn tại; exactly-once *effect* thì có. Ba tầng khoá, mỗi tầng giải một bài toán khác nhau:

**Tầng 1 — on-chain `bytes32 ref`.** Yêu cầu thiết kế contract, và là quyết định quan trọng nhất trong mục này: **mọi event nghiệp vụ phải mang một `bytes32 indexed ref` do người nộp chọn.** Với tx do `relay-pool` phát, `ref = job_uuid`. Khoá này miễn nhiễm với reorg, miễn nhiễm với `log_index` đổi, và nối thẳng về `origin_ref` của §06 lẫn `bamboo_uuid` phía Odoo. Không có nó, dedup chỉ là heuristic.

Ba ràng buộc kỹ thuật lên `ref` mà bản nháp không nêu:

1. **Phải `indexed`.** Không indexed thì không lọc được ở tầng node và mỗi lần tra một `ref` phải quét toàn bộ data. Với `bytes32` (kiểu tĩnh) `indexed` giữ nguyên giá trị trong topic — khác hẳn `string indexed` (§11.6).
2. **Là topic thứ mấy quyết định chi phí.** Solidity cho tối đa 3 topic indexed ngoài `topic0`. `ref` chiếm một; `from`/`to` chiếm hai. Không còn chỗ. Nếu muốn indexed thêm `token`, phải bỏ một cái khác. Chi phí mỗi topic: 375 gas (`LOG`) — không đáng, nhưng số ô thì hết thật.
3. **`ref` phải bao gồm `db_uuid`.** §09.6 đã chốt `ref32 = keccak256(b'odoo:' + db_uuid + b':' + reference)`. Hệ quả cho indexer: **một `ref` từ database staging không bao giờ khớp một `ref` của production**, kể cả khi hai bên dùng chung một chain testnet. Đó là hàng rào duy nhất chặn được kịch bản "copy DB staging, nó bắt đầu nhận event của production".

**Tầng 2 — tách *quan sát* khỏi *hiệu ứng*.**

```
blockchain.chain.event   (quan sat, append-only, khoa theo BLOCK HASH)
    bamboo_uuid = uuid5(NS_CHAIN_EVENT, f"{caip2}|{block_hash}|{tx_hash}|{log_index}")
        -> mot reorg sinh ra mot DONG KHAC, va do la dung: no la mot quan sat khac

blockchain.chain.effect  (hieu ung nghiep vu, ap dung DUNG MOT LAN, khoa theo REF)
    bamboo_uuid = uuid5(NS_CHAIN_EFFECT, f"{caip2}|{ref}")
        -> reorg khong tao effect moi; effect gan lai vao event canonical
```

`NS_CHAIN_EVENT` / `NS_CHAIN_EFFECT` là hằng UUID cố định trong code, không phải `ir.config_parameter` — đổi namespace là mất toàn bộ dedup lịch sử.

Một chi tiết dễ sai: khoá effect là `(caip2, ref)`, **không** gồm `token` hay `amount`. Nếu cùng một `ref` xuất hiện hai lần trên chain với số tiền khác nhau, đó không phải hai effect — đó là một **sự cố** (relayer nộp hai lần với cùng `ref`, hoặc contract cho phép reuse `ref`). Xử lý: effect thứ hai bị từ chối bởi UNIQUE, và indexer ghi một `blockchain.ref.collision` + activity. Nếu ta cho `amount` vào khoá thì sự cố này biến thành hai bút toán im lặng. **Khoá hẹp lại là an toàn hơn.**

**Tầng 3 — dùng `bamboo_idempotency` đúng cách.** Addon đã có sẵn (`/home/dockers/odoo19/addons/bamboo_idempotency/`) và cho mọi model một cột `bamboo_uuid` kiểu **`uuid` native của PostgreSQL** với **UNIQUE index từng phần** (`WHERE bamboo_uuid IS NOT NULL`, tên `<table>_bamboo_uuid_uniq`), cộng `bamboo_create_idempotent(vals, uuid)` trả `{'id': int, 'created': bool}`.

```python
res = self.env['blockchain.chain.effect'].bamboo_create_idempotent(vals, effect_uuid)
if not res['created']:
    continue          # backfill va tip-follower vua gap nhau. Khong lam gi. Dung.
```

Cuộc đua này **sẽ** xảy ra, không phải "có thể": backfill chạy song song tip-follower là trạng thái bình thường sau mỗi outage. `search` rồi `create` là một probe đội lốt bảo đảm; chính UNIQUE index mới phân xử, và bên thua đọc lại id của bên thắng qua `UniqueViolation` trong savepoint.

Năm cảnh báo vận hành (bản nháp có ba; hai cái sau đọc từ source của addon):

1. Cột là `uuid` native của Postgres → phải truyền **chuỗi UUID chuẩn**, không phải hex digest. Dùng `uuid.uuid5(ns, key)`, không dùng `hashlib.sha256(...).hexdigest()`. `fields.Uuid` của addon chuẩn hoá chữ hoa/thường và dấu gạch ở tầng Postgres, nên `A1B2…` và `a1b2…` không thể cùng tồn tại — đó chính là điều một cột `varchar` sẽ không làm được.
2. `_bamboo_uuid_enforced()` phải trả `True` cho model của ta. Nó là một truy vấn `pg_indexes` thật, không phải một cờ Python. **Kiểm bằng SQL, đừng tin code**: `SELECT indexname FROM pg_indexes WHERE indexname='blockchain_chain_effect_bamboo_uuid_uniq';` — nếu trống, `bamboo_create_idempotent` **raise `UserError`**, không âm thầm degrade. Đó là hành vi đúng, nhưng nghĩa là một cron sẽ chết chứ không chạy chậm; test phải bắt được điều này lúc install.
3. Default `uuidv7()` cần PostgreSQL 18. Ta **luôn** tự cấp uuid, nên default chỉ là tiện nghi; đừng để nó thành phụ thuộc.
4. **`bamboo_create_idempotent` chạy `search` trước.** Ở 100k event/ngày với một index B-tree trên cột `uuid` (16 B), mỗi `search` là ~0.1 ms — 10 s/ngày tổng cộng. Không đáng lo. Nhưng nó **là một ORM search đầy đủ**, nghĩa là nó chịu record rule. Nếu ai đó thêm một record rule trên `blockchain.chain.effect` mà indexer không thoả, `search` trả rỗng, `create` raise `UniqueViolation`, và fallback `search` cũng trả rỗng → addon raise. Vì vậy: **indexer chạy `sudo()`**, và điều đó phải viết ra chứ không để ngẫu nhiên.
5. **`UniqueViolation` có thể đến từ một constraint khác.** Source của addon đã xử lý: nếu sau `UniqueViolation` mà tìm không thấy `winner`, nó re-raise như một lỗi nghiệp vụ của caller. Nghĩa là `_unique_seq` ở §11.7 vi phạm sẽ **không** bị nuốt thành "duplicate". Đúng, nhưng caller phải bắt và phân loại, không được `except Exception: pass`.

**`dms_blockchain` phải `depends: ['base', 'bamboo_idempotency']`** — không `dms`.

#### 11.5b. Ranh giới transaction: effect và bút toán phải cùng một COMMIT

Đây là chỗ idempotency thường chết trong thực tế, và bản nháp không nhắc.

`bamboo_create_idempotent` bảo đảm rằng **dòng effect** chỉ được tạo một lần. Nó **không** bảo đảm rằng *hiệu ứng của effect* — `account.move` được post, `payment.transaction._set_done()`, `dms.trade.settlement` được đánh dấu đã trả — chỉ chạy một lần. Nếu code là:

```python
# SAI
res = Effect.bamboo_create_idempotent(vals, uuid)   # commit ngam? khong, nhung...
self.env.cr.commit()
self._apply_effect(res['id'])                        # crash o day => effect ton tai, tien khong bao gio duoc ghi
```

thì một crash ở giữa để lại một effect "đã tạo" mà không có bút toán, và lần chạy sau `created = False` → bỏ qua → **tiền biến mất khỏi sổ, im lặng.** Đây là chế độ hỏng tệ nhất trong toàn mục này vì nó không có cảnh báo nào.

Quy tắc, ba dòng:

```python
with self.env.cr.savepoint():
    res = Effect.bamboo_create_idempotent(vals, uuid)
    if res['created']:
        Effect.browse(res['id'])._apply()      # cung transaction, cung commit
# commit o day, hoac de cron commit theo chunk
```

Và một chốt chặn thứ hai vì `_apply()` có thể chạm hệ thống ngoài (webhook acquirer, `relay-pool`) không rollback được: `blockchain.chain.effect.applied_state` là một máy trạng thái riêng, và một cron reconciler quét `state='final' AND applied_state='pending' AND write_date < now() - 5 min` để hoặc áp lại (nếu `_apply` idempotent) hoặc báo người. **`_apply` phải idempotent theo chính nó**, không chỉ dựa vào việc được gọi một lần:

```python
def _apply(self):
    self.ensure_one()
    if self.applied_state == 'applied':
        return                                  # goi lai la vo hai
    # ... tao account.move / goi _set_done ...
    self.applied_state = 'applied'
```

`payment.transaction._set_done()` của Odoo 19 đi qua `_update_state(allowed_states, target, msg)`, vốn **bỏ qua** (và log) các transaction không nằm trong `allowed_states` — nên gọi lại trên một tx đã `done` không raise. Điều đó tốt, nhưng đừng dựa vào nó: `_post_process()` mới là chỗ tạo `account.payment`, và Odoo bảo vệ nó bằng `state == 'done'` chứ không bằng một cờ "đã post". Cờ `applied_state` của ta là lớp bảo vệ có kiểm soát.

**Dead-letter.** Effect mà `_apply()` raise 5 lần liên tiếp → `applied_state = 'failed'`, tạo `mail.activity` cho nhóm kế toán, và **thôi retry**. Một cron retry vô hạn trên một lỗi cấu hình sẽ tạo 1,440 activity/ngày và không ai đọc nữa. Backoff: 1 phút, 5, 15, 60, 240, rồi dừng.

---

### 11.6. Decode qua ABI, và versioning khi contract nâng cấp

Nhận định then chốt, làm cho "ABI versioning" phần lớn **không phải vấn đề**: `topic0 = keccak256("EventName(type1,type2,...)")`. Nếu chữ ký đổi, `topic0` đổi → log cũ vẫn decode đúng bằng decoder cũ.

Nhưng bản nháp rút ra kết luận **quá mạnh** từ đó: *"registry decoder khoá theo `topic0`, không khoá theo phiên bản contract"*. **Sai, và sai theo hướng nguy hiểm.** `topic0` của `Transfer(address,address,uint256)` là `0xddf252ad…` trên **mọi** ERC-20 từng được deploy. Khoá registry chỉ theo `topic0` nghĩa là một token giả cũng khớp decoder của USDC. Khoá đúng:

```
(chain_id, contract_address, topic0, block_range)   -> handler   # duong chinh
(topic0,)                                            -> handler   # chi cho ABI CHUAN, va chi de decode, khong de cap tien
```

Nói cách khác: `topic0` đủ để biết **cách đọc các byte**; nó không bao giờ đủ để biết **có nên tin các byte đó không**. Hai câu hỏi khác nhau, hai bảng khác nhau. Câu hỏi thứ hai thuộc về §11.8b.

Bốn chỗ ABI versioning *thật sự* là vấn đề:

1. **Tái sử dụng chữ ký với ngữ nghĩa khác.** Cấm tuyệt đối trong contract của ta. Nếu ngữ nghĩa đổi, đổi tên event hoặc thêm một tham số `uint8 version` indexed đầu tiên.
2. **Decode calldata**, không phải log. Selector `executeMetaTransaction(...)` giữ nguyên trong khi struct `MetaTransaction` (§04) tiến hoá → phải giải theo **block range**. Đây là chỗ duy nhất `active_from_block` thực sự bắt buộc.
3. **Proxy UUPS.** Log phát ra từ **địa chỉ proxy** nhưng theo ABI của implementation. Ràng buộc ABI là `(proxy address, block range) → implementation ABI`. Cơ chế cụ thể: index luôn event `Upgraded(address indexed implementation)` của ERC-1967 và **tự động đóng range cũ, mở range mới** tại block đó. Không có bước thủ công nào.
   - Mở rộng bắt buộc: **Beacon proxy** (ERC-1967 `BeaconUpgraded(address indexed beacon)`) — implementation đổi khi *beacon* đổi, không khi proxy đổi. Phải index cả `Upgraded` trên địa chỉ beacon và fan-out sang mọi proxy trỏ tới nó. Nếu §01/§02 dùng Factory + CREATE2 + beacon (rất có khả năng, vì "dùng chung code, khác data" là yêu cầu của note ở phần TOKEN), đây không phải trường hợp hiếm — nó là trường hợp mặc định.
   - **Diamond (EIP-2535)** thì tệ hơn: ABI là hợp của nhiều facet, đổi theo `DiamondCut`. **Khuyến nghị: cấm Diamond trong `smartcontracts/`.** Lợi ích không bù nổi chi phí indexer và audit.
4. **`indexed` trên kiểu động — bẫy im lặng nhất trong toàn bộ §11.** Với `event Foo(string indexed name, bytes indexed blob)`, topic chứa `keccak256(value)`, **không** chứa value. Không có ABI nào giải ngược được. Hệ quả cụ thể:
   - `ref` phải là `bytes32`, không phải `string`. §09.6 đã chọn đúng; ghi lại đây vì lý do khác.
   - Nếu một contract bên thứ ba ta phải index có `string indexed`, cách duy nhất là dựng **bảng tra ngược** `keccak256(candidate) -> candidate` từ tập giá trị ta đã biết. Với tập mở thì không giải được — phải lấy giá trị từ calldata thay vì từ log.
5. **Event `anonymous`.** `event X(...) anonymous` **không có `topic0`**; topic đầu tiên là tham số indexed đầu tiên. Registry khoá theo `topic0` sẽ không bao giờ khớp nó, im lặng. **Cấm `anonymous` trong contract của ta**, và với contract ngoài, phải khoá theo `(address, số topic, độ dài data)` — kém tin cậy, nên tránh.

```python
class BlockchainContractAbi(models.Model):
    _name = 'blockchain.contract.abi'
    _description = 'ABI binding valid over a block range'
    _order = 'chain_id, address, active_from_block'

    chain_id          = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    address           = fields.Char(required=True, index=True)
    impl_address      = fields.Char(help='Implementation phia sau proxy, neu co')
    beacon_address    = fields.Char(help='Beacon, neu la beacon proxy')
    proxy_kind        = fields.Selection([('none', 'Not a proxy'), ('uups', 'UUPS / ERC-1967'),
                                          ('transparent', 'Transparent'), ('beacon', 'Beacon')],
                                         required=True, default='none')
    abi_version       = fields.Char(required=True)          # '1.2.0'
    abi_sha256        = fields.Char(required=True, index=True)
    attachment_ids    = fields.Many2many('ir.attachment')   # ABI JSON tren Garage
    active_from_block = fields.Integer(required=True)
    active_to_block   = fields.Integer(default=0, help='0 = con hieu luc')
    source_kind       = fields.Selection([('evm_abi', 'EVM ABI JSON'), ('sui_bcs', 'Sui BCS type layout'),
                                          ('cw_schema', 'CosmWasm JSON schema'), ('soroban_spec', 'Soroban XDR spec'),
                                          ('ton_tlb', 'TON TL-B scheme')], required=True, default='evm_abi')
    is_verified_source = fields.Boolean(default=False,
                                        help='ABI lay tu block explorer da verify source, khong phai do nguoi dan vao')

    _unique_abi_range = models.Constraint(
        'UNIQUE(chain_id, address, active_from_block)',
        'Mot dia chi chi mo mot ABI range tai moi block.')
```

`abi_sha256` không phải trang trí: nó là thứ cho phép nói "ABI mà ta decode bằng, tại thời điểm ghi sổ, là đúng file này" khi kiểm toán viên hỏi ba năm sau. `ir.attachment` trên Garage có thể bị thay; hash trong DB thì không, vì effect tham chiếu nó.

**Log không decode được thì lưu thô, không vứt.** `state='undecoded'` + `topic0`. Khi đăng ký ABI mới, một cron re-decode đúng những dòng đó. Đây là lý do thứ tư khiến raw phải append-only. Đếm `undecoded` là một metric: nếu nó tăng, hoặc contract vừa upgrade mà ta chưa biết, hoặc watchlist đang bắt nhầm.

Ngoài EVM:

| Chain | Cơ chế decode | Độ khó |
|---|---|---|
| Sui | Event mang `type` đầy đủ `0xpkg::module::Event`, layout BCS lấy từ package (package **bất biến, có version**) | Dễ nhất — tự mô tả. `0xpkg` đã bao gồm định danh, nên không có bài toán "cùng chữ ký khác contract" |
| Soroban | Event là XDR `ScVal`, có kiểu | Dễ |
| CosmWasm | Event là **cặp key–value chuỗi, không schema**; `wasm-<action>` là quy ước, không phải chuẩn | Khó — phải ghim `code_id → JSON schema` thủ công, và `code_id` đổi khi `MigrateMsg` chạy → cũng cần block range |
| TON | Không có event. Phải parse body của outgoing message theo TL-B, phân biệt bằng 32 bit op-code đầu | Khó nhất; coi mỗi op-code như một `topic0`, nhưng op-code chỉ 32 bit → **va chạm giữa các contract là chuyện thường**, bắt buộc khoá theo `(contract address, op-code)` |
| Hedera HSCS | ABI EVM chuẩn qua mirror node | Dễ |

---

### 11.7. Bảo đảm về thứ tự

**Được bảo đảm:** thứ tự toàn phần trong một chain theo `position_key` (§11.2).
**Không được bảo đảm:** thứ tự giữa các chain, và thứ tự *đến nơi*. Backfill trả event cũ **sau** event mới là hành vi bình thường.

Một chi tiết nhỏ nhưng thật: **đừng tin thứ tự trong response của `eth_getLogs`.** Đặc tả không đảm bảo, và một số provider gộp kết quả từ nhiều node. Sort tường minh theo `(blockNumber, transactionIndex, logIndex)` sau mỗi lần nhận, chi phí bằng không so với hậu quả.

Quy tắc cho consumer, viết ra để không ai phải đoán:

1. Logic nghiệp vụ phải **giao hoán**, hoặc
2. được sắp bởi một **sequence on-chain**.

Với (2), các sequence có thật trên stack này — cập nhật theo §03 và §04, bản nháp mới nêu hai:

| Luồng | Sequence | Ai tăng | Ghi chú |
|---|---|---|---|
| Meta-tx (§04) | `meta_nonce(from, batchId)` | contract, mỗi lần execute | 2D nonce: **các `batchId` khác nhau song song, không so sánh được với nhau** |
| Zether outgoing (§03) | `zetherNonce(from)` | contract, mỗi `transferConfidential`/`withdraw` | Đơn điệu tăng, một luồng duy nhất mỗi account |
| Zether incoming (§03.5.4) | `pendingSeq(to)` | contract, mỗi lần có tiền vào `pending` | Đây là thứ quyết định thứ tự tiền **vào**, và bản nháp bỏ sót |
| Zether rollover (§03.5.4) | `accSeq(a)` | `rollOver(a)` — **[BẢN 5, 2026-09-03]** bất kỳ ai nếu `mode[a] == PUBLIC` (mặc định), chỉ chủ nếu `OWNER_ONLY` | Một `accSeq` mới nghĩa là mọi proof pin `accSeq` cũ đã hết hạn |

Khi (2) áp dụng, effect mang `seq_key` và `seq_number`:

```python
seq_key    = fields.Char(index=True)     # f"{caip2}|zether|{token}|{from_account}"
seq_number = fields.Integer()            # int4 du: nonce khong vuot 2.1e9 trong doi contract
```

Effect với `seq_number = n+2` khi mới áp tới `n` bị giữ ở `blocked`, không áp. Một cron drain lại hàng đợi `blocked` mỗi phút. Điều này biến một race thành một độ trễ — đổi đúng chiều.

```python
_unique_seq = models.Constraint(
    'UNIQUE(seq_key, seq_number)',
    'Mot sequence number chi duoc ap dung mot lan tren mot luong.')
```

**Head-of-line blocking là cái giá, và nó phải có trần.** Nếu effect `n+1` không bao giờ đến (event bị mất, ABI chưa đăng ký, handler crash), mọi effect từ `n+2` trở đi đứng vĩnh viễn. Bản nháp không nói gì về việc này. Trần cụ thể:

- Một effect ở `blocked` quá **900 s** → tạo activity với danh sách chính xác các `seq_number` còn thiếu, và một nút "quét lại range chứa nonce thiếu".
- Quá **3 giờ** → `blocked_expired`, chain chuyển `paused` cho luồng đó (không cho toàn chain), page người thật.
- **Không bao giờ tự động bỏ qua một lỗ hổng.** Bỏ qua `n+1` trong một sổ cái tiền là chọn sai dữ liệu thay vì chậm dữ liệu.

Đây cũng là lý do `meta_nonce` 2D của §04 tốt hơn nonce tuyến tính cho indexer, chứ không chỉ cho relayer: một `batchId` bị nghẽn không chặn các `batchId` khác. `seq_key` phải bao gồm `batchId`.

---

### 11.8. Tiền vào từ người chưa bao giờ dùng app

Đây là lý do phải index **theo địa chỉ**, không chỉ theo job của mình.

**ERC-20 vào:** `eth_getLogs` với `topics = [Transfer_topic0, null, watched_address_padded]` — chính xác, rẻ, lọc ngay ở node. Nhưng xem §11.8b trước khi tin bất kỳ kết quả nào của nó.

**Native coin (xDAI, CELO, ETH) vào: `getLogs` KHÔNG bắt được.** Chuyển native không phát log. Đây là một lỗ thật và note không nhắc. Ba lựa chọn:

| Cách | Chi phí | Bắt được | Đánh giá |
|---|---|---|---|
| `trace_block` / `debug_traceBlock` mỗi block | Nặng (~10–30× `getBlockByNumber` về CU), nhiều provider không mở ở tier thường | Tất cả, kể cả internal | Chỉ dùng nếu tự chạy node |
| Quét toàn bộ tx trong body mỗi block, lọc `to` | Gnosis 5 s/block, ~20–60 tx/block → 17,280 call/ngày (§11.1b). Ethereum 200+ tx/block → chấp nhận được | Chỉ **top-level** transfer | **Đủ dùng làm đường ghi nhận** |
| Diff `eth_getBalance` cho toàn bộ watchlist qua một multicall view mỗi block | 1 `eth_call`/block cho ~500 địa chỉ | Mọi thay đổi số dư, kể cả internal | Mất thông tin "ai gửi", nhưng là **detector không thể bỏ** |

**Chọn cách 2 làm đường ghi nhận, và cách 3 làm detector bắt buộc — không phải "dự phòng".** Bản nháp coi cách 3 là tuỳ chọn; đó là sai, vì cách 2 bỏ sót **bốn** loại tiền vào, cả bốn đều có thật:

1. **Internal transfer** — một contract gọi `CALL` với `value` tới địa chỉ ta. Không xuất hiện trong danh sách tx nào có `to = địa chỉ ta`. Ví dụ điển hình: rút từ một DEX router, hoặc một multisig giải ngân.
2. **`SELFDESTRUCT` beneficiary** (còn tồn tại ở dạng hạn chế sau EIP-6780) — chuyển số dư mà không có tx nào.
3. **Withdrawal của validator** (EIP-4895, có trên Gnosis) — nếu một địa chỉ treasury được đặt làm withdrawal address, tiền vào **không có tx, không có log, không có trace**. Chỉ số dư đổi.
4. **Phần thưởng khối / MEV tip** nếu ta chạy validator.

Cơ chế điều hoà: cron mỗi 15 phút chạy multicall `eth_getBalance` cho toàn watchlist, so với `Σ(inbound) − Σ(outbound)` mà ta đã ghi. Lệch → `blockchain.balance.drift` + activity. Không tự động hạch toán phần lệch (không biết nguồn) nhưng **biết là có** — đó là toàn bộ giá trị.

```python
class BlockchainWatchedAddress(models.Model):
    _name = 'blockchain.watched.address'
    address     = fields.Char(required=True, index=True)
    chain_id    = fields.Many2one('blockchain.chain', index=True)  # rong = MOI chain da cau hinh
    partner_id  = fields.Many2one('res.partner', index=True)       # res.partner o 'base' -> KHONG pha standalone
    purpose     = fields.Selection([('treasury', 'Treasury'), ('receive', 'Dedicated receive'),
                                    ('relayer', 'Relayer'), ('contract', 'Contract')], required=True)
    expected_ref = fields.Char(index=True, help='Neu dia chi duoc cap rieng cho mot khoan phai thu')
    watch_from_block = fields.Integer(default=0, help='Khong quet nguoc qua diem nay')
    balance_check_datetime = fields.Datetime(readonly=True)

    _unique_watch = models.Constraint(
        'UNIQUE(address, chain_id)',
        'Mot dia chi chi theo doi mot lan tren mot chain.')
```

`chain_id` để rỗng nghĩa là **theo dõi trên mọi chain đã cấu hình**, và đó phải là mặc định. Chế độ hỏng thực tế nguy hiểm nhất: cùng một địa chỉ EVM tồn tại trên Gnosis *và* Celo; người trả tiền gửi nhầm chain. Nếu chỉ watch một chain, tiền vào và **không ai biết**. (§09.7 gọi tình huống này là `unmatched_chain` và ghi rõ: nếu ta không kiểm soát khoá của địa chỉ đó trên chain kia thì **tiền mất thật** — nghĩa là `receiving_mode = 'derived'` phải deploy CREATE2 cùng salt trên **mọi** chain EVM ta chấp nhận.)

Khớp lệnh, theo thứ tự ưu tiên:

1. **`ref` khớp** trong calldata / memo (Stellar memo, Cosmos memo, TON comment) → khớp chắc chắn.
2. **Địa chỉ nhận riêng cho từng khoản phải thu** → khớp chắc chắn. Đây là tương đương crypto của một mã VietQR riêng cho mỗi hoá đơn, và là cơ chế tốt nhất. §09.6 đã định lượng: CREATE2 clone + sweep ≈ 100–120k gas ≈ **$0.00024/request** trên Gnosis ở 2 gwei; 1 triệu request/năm ≈ **$240**.
3. **Số tiền + cửa sổ thời gian** → *chỉ là gợi ý*, luôn cần người duyệt.

**Không bao giờ tự động hạch toán một inbound chưa khớp.** Nó đi vào tài khoản treo/clearing, hệt như `dms.bank.reconciliation`. Các trường hợp phải liệt kê trong runbook (§09.7 có bảng đầy đủ): trả thừa, trả thiếu, sai token, sai chain, trả từ một địa chỉ chưa KYC (khoá lại, không hoàn tự động — hoàn tự động về một địa chỉ chưa biết là một lỗ rửa tiền, và §09.7 chỉ rõ rằng `from` của một lần rút từ sàn là ví nóng của sàn, không phải ví khách).

#### 11.8b. Event giả: lỗ mất tiền rẻ nhất trong toàn bộ thiết kế

Bản nháp không nhắc, và đây là thứ sẽ bị khai thác đầu tiên.

`eth_getLogs(topics=[Transfer_topic0, null, our_address])` trả về log `Transfer` từ **mọi contract trên chain**, không chỉ từ USDC. Bất kỳ ai cũng deploy được:

```solidity
contract FakeUSDC {
    event Transfer(address indexed from, address indexed to, uint256 value);
    function mintFakeCredit(address to, uint256 v) external { emit Transfer(msg.sender, to, v); }
}
```

Chi phí một lần phát: `LOG3` ≈ 375 + 3×375 + 8×32 ≈ 1,750 gas, cộng base tx 21,000 ≈ **~23,000 gas**. Trên Gnosis ở 2 gwei: **0.000046 xDAI ≈ $0.000046**. Với $1, kẻ tấn công phát ~21,000 event giả. Nếu indexer credit loyalty point theo `value`, đó là một máy in tiền.

Bốn hàng rào, **tất cả bắt buộc**, không phải chọn một:

1. **Allowlist theo địa chỉ contract.** Log chỉ được xử lý nếu `log.address` nằm trong `blockchain.token` với `state = 'approved'`. Đây là hàng rào chính. Truy vấn `eth_getLogs` **phải** truyền `address = [danh sách token]`, không chỉ `topics` — lọc ở node rẻ hơn và loại bỏ 99.99% rác trước khi nó vào DB.
2. **Contract phải verify được.** `blockchain.contract.abi.is_verified_source = True` là điều kiện để một token vào allowlist. Một token không verify source thì không ai biết `transfer()` của nó làm gì.
3. **Đối chiếu số dư.** Với mọi token trong allowlist, cron 15 phút so `balanceOf(our_address)` với tổng đã ghi. Một token phát event mà không đổi số dư (event giả, hoặc fee-on-transfer, hoặc rebasing) lộ ra ở đây trong ≤ 15 phút.
4. **Loại token không tương thích, tường minh.** `blockchain.token.token_quirk` = `none | fee_on_transfer | rebasing | blacklistable | pausable`. Chỉ `none` được dùng cho luồng tiền tự động:
   - **fee-on-transfer**: `event.value` ≠ số nhận được. Ghi sổ theo event là ghi thừa.
   - **rebasing** (stETH-like): số dư đổi mà không có event nào. Đối chiếu số dư sẽ kêu mỗi ngày.
   - **blacklistable** (USDC/USDT thật đều có): tiền đã nhận có thể bị đóng băng sau đó. Không phải lỗi indexer, nhưng phải có trường `is_freezable` để kế toán biết khoản phải thu này có rủi ro khác 0.
   - **ERC-777** hooks: `tokensReceived` cho phép reentrancy vào contract nhận của ta. Cấm.

Cùng logic áp cho các chain khác: Sui event mang `0xpkg::module::Event` — `0xpkg` **là** allowlist, dễ hơn EVM. CosmWasm `wasm` event mang `_contract_address` — bắt buộc lọc theo nó. TON: op-code không đủ, phải khoá theo địa chỉ jetton wallet **và** kiểm rằng nó là jetton wallet hợp lệ của jetton master trong allowlist (một bước RPC thêm; bỏ qua bước này là lỗ tương đương).

---

### 11.9. Tăng trưởng lưu trữ và retention

Cơ sở ước tính: một dòng raw log = 4 topic × 32 B + data trung bình 128 B + `tx_hash`/`block_hash` 64 B + `position_key` 64 B ≈ **420 B payload**; cộng overhead dòng Postgres (23 B header + alignment) và 4 index ≈ **~950 B thực tế**. Dòng effect ≈ 400 B (khớp §3.9). Header ≈ 150 B.

| Kịch bản | Event/ngày | Postgres/năm | Object storage/năm |
|---|---|---|---|
| Chain private, Zether, 10k confidential transfer/ngày | 10,000 | 9.5 MB/ngày raw + 4 MB effect ≈ **4.9 GB** | proof 1,280 B (§3.3.3, cấu hình 32/64 nén) × 10k ≈ **4.7 GB** |
| Gnosis public, 50 contract + 5,000 địa chỉ theo dõi | 100,000 | **34.7 GB** | — |
| Header nếu lưu hết (Gnosis 5 s) | 6.31 M block | 0.95 GB | — |

*Đã sửa so với bản nháp:* proof blob là **1,280 B** (nén) cho cấu hình 32/64 mà §03.3.3 chốt, không phải 672–800 B — con số cũ là kích thước của **một** Bulletproof, trong khi một transfer cần **hai** (BP(v) n=32 và BP(b') n=64, không aggregate được vì khác `n`) cộng phần Sigma. Chênh 1.6×.

**Quyết định retention (thứ tự theo mức tiết kiệm):**

1. **Không lưu header vĩnh viễn.** Giữ `reorg_window_blocks` header cuộn, cộng một checkpoint mỗi 1,000 block để kiểm toán. Giảm ~600 lần và sẽ không ai đọc phần bị bỏ.
2. **Raw log của chain public: 90 ngày hot trong Postgres**, sau đó đẩy sang Parquet trên Garage / ClickHouse (projection `olap` của note) và xoá khỏi Postgres. Effect vẫn giữ con trỏ `archive_uri`.
3. **Raw log của Zether: KHÔNG BAO GIỜ XOÁ khỏi đường truy vấn nóng.** Bản nháp áp quy tắc 90 ngày cho tất cả — **sai, và nó phá recovery ví.** §03.2.6 quy định recovery của một ví là đọc lại **toàn bộ** `ConfidentialTransfer`/`Deposit`/`Withdraw` từ block đăng ký tài khoản, và ví phải **từ chối cho tiêu** nếu thiếu. Nghĩa là một người dùng cài lại app năm 2029 cần event của năm 2026. Ba con đường:

   | Đường | Chi phí | Độ trễ recovery 10k tx | Đánh giá |
   |---|---|---|---|
   | Giữ hết trong Postgres | 4.9 GB/năm ở 10k tx/ngày → 49 GB sau 10 năm | < 1 s | **Chọn cái này.** 49 GB là không đáng gì so với việc khoá một tài khoản |
   | Archive Parquet + query engine | rẻ hơn ~5× | 5–30 s | Thêm một phụ thuộc vận hành cho một lợi ích không có |
   | Đọc lại từ RPC | $0 | phút tới không bao giờ (prune) | Không. §03.2.6 cấm |

   Với chain private, quyết định càng dễ: ta kiểm soát khối lượng, và 10k tx/ngày là giả định trên. Điều kiện cần đi kèm: **một public method để client kéo lịch sử của chính nó** (§11.11), với phân trang theo `position_key` và ACL khoá cứng theo `schnorr_address` mà partner sở hữu.
4. **Effect: giữ vĩnh viễn.** Đó là chứng cứ kế toán. Ở 100k event/ngày, effect chiếm ~14.6 GB/năm — chấp nhận được.
5. **Proof blob: chỉ lưu khi chain là private.** Trên chain public, proof đã nằm trong calldata của một tx bất biến; lưu lại là nhân đôi 4.7 GB/năm để phòng một trường hợp (chain biến mất) không xảy ra. Trên chain private, chain **có thể** bị reset — lưu. Đây là chỗ bản nháp lưu cả hai mà không hỏi tại sao.
6. **ABI JSON: `ir.attachment` trên Garage**, giữ vĩnh viễn (vài MB tổng cộng), và `abi_sha256` trong DB là thứ neo nó.
7. Retention theo quy định lưu trữ chứng từ kế toán Việt Nam (10 năm cho chứng từ dùng trực tiếp để ghi sổ) — cần luật sư xác nhận phạm vi áp dụng cho artefact on-chain (§13).

**Về index — bản nháp khuyến nghị BRIN, và khuyến nghị đó sai.**

BRIN chỉ rẻ khi thứ tự **vật lý** của dòng tương quan với giá trị cột. Ba lý do nó không tương quan ở đây:

- Backfill chèn block cũ **sau** block mới → các block range xen kẽ nhau trong heap.
- `UPDATE` trạng thái (`undecoded → decoded`, `included → final`) tạo dòng mới ở cuối heap (HOT update không phải lúc nào cũng áp dụng khi có index trên cột đổi).
- `VACUUM FULL` / `pg_repack` sẽ khôi phục tương quan, nhưng không ai chạy nó hàng tuần trên bảng 80 GB.

Và tiết kiệm không đáng: một B-tree trên `(chain_id, block_number)` ở 100 M dòng ≈ **2.5–3 GB**, so với bảng ~95 GB. Đó là **~3%**. Đổi 3% dung lượng lấy một index không dùng được cho point lookup là một cuộc trao đổi tồi.

**Quyết định đã sửa:**

```sql
-- Duong tra cuu chinh: B-tree
CREATE INDEX bce_pos ON blockchain_chain_event (chain_id, position_key);
CREATE INDEX bce_tx  ON blockchain_chain_event (chain_id, tx_hash);
-- Loc trang thai: partial index, chi tren cai chua xong (vai nghin dong, khong phai 100 trieu)
CREATE INDEX bce_pending ON blockchain_chain_event (chain_id, id)
    WHERE state IN ('observed', 'included', 'undecoded');
-- BRIN CHI cho cron archival, quet theo thoi gian, khong point lookup
CREATE INDEX bce_arch ON blockchain_chain_event USING brin (observed_datetime) WITH (pages_per_range = 32);
```

Partial index trên `state` là chỗ tiết kiệm thật: 100 M dòng nhưng chỉ vài nghìn dòng chưa `final` tại một thời điểm → index ~200 KB thay vì 3 GB, và cron scan của §11.11 dùng đúng nó.

**Không partition trong Odoo.** ORM không hỗ trợ và ép nó vào sẽ tốn nhiều hơn được. Thay vào đó: một cron archival hàng tháng chuyển `observed_datetime < now() - 90 days AND chain_profile != 'private'` sang Parquet rồi `DELETE`. Kèm `autovacuum_vacuum_scale_factor = 0.02` đặt riêng cho bảng này — mặc định 0.2 nghĩa là vacuum chỉ chạy sau 20 M dòng chết, quá muộn.

---

### 11.10. Index sổ cái mã hoá: index được gì, và rò rỉ gì

**Công khai on-chain trong một `ConfidentialTransfer`** (theo struct §03.2.5, đã cập nhật so với note): `fromSchnorrAddress`, `toSchnorrAddress`, `zetherNonce`, `accSeq`, `fee` (uint256 **plaintext**), `feeRecipient` (tham số hàm, do relayer điền, **không** trong struct), `msg.sender` (relayer), `memoTo`/`memoFrom` (32 B ciphertext mỗi cái), gas used, block timestamp; và nếu bọc EIP-1776 thì cả `metaTx.from`, `batchId`, `batchNonce`, `rewardToken`, `rewardAmount`. **Không công khai:** `v` và số dư.

> Struct trong note gốc vừa có `uint256 fee` công khai vừa có `bytes32[2] C_fee`. Hai thứ này loại trừ nhau: nếu `fee` là public, contract tự dựng được ElGamal của nó (`(g^fee, 1)`) và trừ đồng hình — `C_fee` thừa. §3.4 đã kết luận cắt bớt pipeline phí; ở đây chỉ ghi nhận hệ quả cho indexer: **fee phải là public, vì Open Relayer không thể đánh giá lợi nhuận trên một con số mã hoá.** Đó cũng chính là điều §10.1 của note tự nói ("Public Relayer Fee").

Vậy indexer **index được**: đồ thị định danh, timing, tần suất, chuỗi nonce, phí, relayer, gas, và *số lượng* giao dịch. **Không index được từ dữ liệu công khai**: số tiền.

**Rò rỉ metadata — bốn thứ, xếp theo mức nghiêm trọng:**

1. **Phí theo tỉ lệ phần trăm phá vỡ toàn bộ bảo mật.** Nếu `fee = 0.3% × v` và `fee` công khai thì `v = fee / 0.003`. Một phép chia. **Quy tắc bắt buộc: phí phải là số phẳng lấy từ một thang rời rạc nhỏ** (ví dụ `{0.01, 0.05, 0.25, 1.00}` đơn vị), không bao giờ ad valorem. Đây là ràng buộc thiết kế contract, không phải tuỳ chọn vận hành. Định lượng độ rò của chính thang phí: với 4 bậc phí và một quy tắc "bậc theo khoảng giá trị", mỗi giao dịch lộ **2 bit** về `v`. Với 8 bậc là 3 bit. Nếu chọn thang thì **thang phải độc lập với `v`** (theo loại giao dịch, theo hợp đồng dịch vụ với relayer), không theo khoảng giá trị — nếu không, 4 bậc = 4 khoảng = biết `v` nằm trong khoảng nào.
2. **`deposit` và `withdraw` đều có số tiền plaintext.** Chỉ khúc *giữa* là bí mật. Nếu A nạp đúng 1,250,000, chuyển cho B, B rút đúng 1,250,000 — số tiền lộ bằng phép giao. Giảm thiểu: mệnh giá nạp tròn theo thang cố định, giữ tiền lại một thời gian (dwell time), gộp nhiều khoản. Định lượng: với thang 8 mệnh giá và < 5 tài khoản hoạt động mỗi cửa sổ thời gian, tính ẩn danh của số tiền sụp đổ gần như hoàn toàn — anonymity set thực tế là **số tài khoản có hoạt động trùng cửa sổ**, không phải số tài khoản đã đăng ký. Đây là con số phải theo dõi như một metric: `active_accounts_per_hour`. Dưới 20, cảnh báo cho người phụ trách privacy; dưới 5, bảo mật số tiền là danh nghĩa.
3. **Gas như kênh phụ.** Verify Bulletproof tốn gas theo số hạng aggregation, không theo giá trị → an toàn về `v`. Nhưng gas **có** rò rỉ hai thứ khác, đều đo được từ receipt: (a) bất kỳ nhánh rẽ nào (`if fee == 0`) làm gas khác nhau; (b) **tx đầu tiên tới một tài khoản đắt hơn ~45k gas** (4 slot zero→nonzero, §03.3.6) → từ receipt suy ra "đây là lần đầu B nhận tiền", tức là một sự kiện quan hệ kinh doanh mới. Quy tắc: **thực thi phải cùng hình dạng** cho mọi input hợp lệ, và với (b) — không sửa được rẻ, phải ghi vào tài liệu cho khách hàng doanh nghiệp.
4. **Lực lượng (cardinality).** Số transfer giữa mỗi cặp trong mỗi kỳ là công khai → lộ tần suất đặt hàng. Không có cách khắc phục rẻ; phải nói rõ với người dùng doanh nghiệp rằng đây là thứ họ đánh đổi để có anti-mixer compliance. Một biện pháp *có* rẻ và nên làm: **relayer không được là một địa chỉ riêng cho mỗi khách hàng.** Nếu brand A luôn dùng relayer R_A, thì `msg.sender` là một nhãn định danh miễn phí trên mọi giao dịch của A, kể cả khi `fromSchnorrAddress` được xoay. Dùng một pool relayer chung.

**Odoo lưu gì.** Odoo **không bao giờ** giữ `x` và **không bao giờ** prove. Số tiền chỉ vào Odoo qua một trong **năm** đường — bản nháp có bốn, và bỏ sót đường quan trọng nhất mà §03.2.5 vừa tạo ra:

```python
class BlockchainZetherTransfer(models.Model):
    _name = 'blockchain.zether.transfer'
    _description = 'One observed confidential transfer, with whatever we legitimately know about it'

    amount_units   = fields.Integer(help='Chi co gia tri khi amount_source != unknown. Don vi so cai, khong phai currency.')
    amount_source  = fields.Selection([
        ('self_originated',     'Odoo nay tao ra tx'),
        ('memo_decrypted',      'Giai ma memo AEAD bang khoa xem cua chinh minh'),
        ('recipient_decrypted', 'Client nguoi nhan giai ma va chung thuc'),
        ('disclosed',           'Doi tac cong bo kem bang chung'),
        ('unknown',             'Khong biet'),
    ], required=True, default='unknown', index=True)
    amount_verified = fields.Boolean(readonly=True,
        help='True khi da kiem C_out == g^v * y_to^s. Chi amount_source=disclosed moi co the False.')
    attestation_attachment_ids = fields.Many2many('ir.attachment')
    fee_public     = fields.Integer(readonly=True)
    zether_nonce   = fields.Integer(readonly=True, index=True)
    pending_seq    = fields.Integer(readonly=True)
    observed_datetime = fields.Datetime(readonly=True)
    memo_hex       = fields.Char(size=66, readonly=True, help='memoTo hoac memoFrom, luu tho de recovery')
```

**`memo_decrypted` là đường mới và nó đổi kiến trúc.** §03.2.5 gắn vào mỗi transfer hai memo AEAD 32 B: `memoTo` mã hoá `v` bằng khoá dẫn xuất từ `y_to^s`, `memoFrom` bằng `y_from^s`. Hệ quả cho indexer:

- Một Odoo **là chủ tài khoản** (treasury của brand) giải mã được `v` của **mọi** giao dịch vào/ra tài khoản đó, bằng một scalar mul + HKDF + ChaCha20 ≈ **60 µs** — không cần BSGS 0.1 s, không cần client hợp tác. Bản nháp nói "recipient_decrypted là đường quan trọng nhất"; **không còn đúng**: `memo_decrypted` nhanh hơn, không cần round-trip, và chạy được cả trên chiều gửi đi.
- Nhưng nó cần một **khoá**. Cụ thể là `x` — thứ nằm trong HSM và Odoo không được chạm (§07). Giải pháp: HSM expose một operation hẹp `ecdh(D_out) -> compress(D_out^x)` (chỉ một scalar mul, không ký được gì), Odoo nhận shared secret rồi tự HKDF + giải AEAD. Odoo không bao giờ thấy `x`. Chi phí: một round-trip HSM/MPC mỗi transfer — ở 10k/ngày là 10k operation, trong ngân sách của mọi HSM. **Đây là một yêu cầu mới lên §07 mà chưa section nào nêu.**
- `memo` là *tiện lợi*, ElGamal ciphertext mới là *nguồn sự thật* (§03.2.5 nói rõ contract không verify memo). Nên `amount_verified` phải được tính bằng cách kiểm `C_out == g^v · y_to^s` với `s` lấy từ đâu? Với memo ta chỉ có `v`, không có `s`. Kiểm chéo đúng là kiểm **tổng**: `g^{Σv} == C_acc · D_acc^{-x}` sau mỗi rollOver (§03.2.6). Vậy `amount_verified` trên từng dòng là `False` cho `memo_decrypted`, và ta có một cờ mức tài khoản `blockchain.zether.account.balance_reconciled_datetime`. **Nếu tổng lệch, dừng, không cho tiêu** — quy tắc của §03.2.6 áp thẳng vào Odoo, không chỉ vào ví.

`recipient_decrypted` vẫn giữ như đường dự phòng khi ta **không** là chủ tài khoản: client giải mã, gửi `(amount_units, s)` về Odoo của mình, Odoo **xác minh** `C_out == g^v · y_recv^s` — một phép kiểm tra rẻ (2 scalar mul), không cần khoá bí mật — rồi mới lưu, và ở đường này `amount_verified = True`.

**Viewing key cho kiểm toán viên: §03 chưa nhất quán, và phải chốt ở đây.** §03.1.6 liệt kê `C_aud, D_aud` trong danh sách điểm phải validate từ calldata, nhưng struct `ConfidentialTransferData` ở §03.2.5 **không có hai trường đó**. Một trong hai chỗ sai. Ba lựa chọn, và hệ quả:

| Lựa chọn | Chi phí | Ai đọc được `v` | Retrofit sau |
|---|---|---|---|
| Không có auditor key | 0 | Chỉ hai bên | **Đổi statement của proof ⇒ đổi verifier ⇒ migration mọi tài khoản.** Không làm được êm |
| `C_aud, D_aud` + sigma equality | +128 B calldata (uncompressed, §03.3.4) ≈ +2,048 gas; +1 sigma equality ≈ **+40–60k gas** (ước tính, cơ sở: ~8 `ecMul` × 6,000 + overhead) | Auditor, luôn luôn | — |
| Memo thứ ba `memoAud` mã hoá cho `y_auditor` | +32 B calldata ≈ +512 gas, **0 gas verify** | Auditor, **nếu sender trung thực** | Thêm được bất cứ lúc nào |

**Đề xuất: đường thứ ba cho v1, đường thứ hai chỉ khi có yêu cầu pháp lý ràng buộc.** Lý do: memo không có ZK constraint (§03.2.5 đã chọn không ép memo đúng), nên `memoAud` cùng mức bảo đảm với `memoTo` — mà `memoTo` đã đủ để hệ thống chạy. Nếu quy định yêu cầu auditor đọc được **kể cả khi sender gian dối**, thì phải trả 40–60k gas cho sigma equality, và **phải quyết trước khi verifier freeze**. Với chain private đi trước, gas không phải ràng buộc (quyết định khoá #5) — nên nếu đằng nào cũng cần, làm luôn ở private là rẻ nhất.

**Ba thứ Odoo tuyệt đối không lưu**, viết ra vì rất dễ vô tình lưu:

1. `x` (khoá bí mật Schnorr) — ở HSM/MPC, không ở `ir.config_parameter`, không ở record.
2. `s` (randomness của transfer) sau khi đã dùng xong xác minh — nó cho phép người khác kiểm `C_out` và suy ngược `v` nếu họ đoán được `v`. Với `v` trong không gian nhỏ (giá hoá đơn tròn), đoán là dễ. Xoá sau khi verify.
3. Khoá dẫn xuất `k_to`/`k_from` — tính lại từ HSM mỗi lần, không cache. Nếu phải cache vì hiệu năng, cache trong RAM của worker với TTL ≤ 60 s, **không** trong DB.

---

### 11.11. Bề mặt Odoo: gate, method RPC, cron

Máy trạng thái, dùng chung cho mọi money-flow (khớp §3.9 và §09.7):

```
draft -> proving -> broadcast -> included -> final
                        |            |
                        +-> expired  +-> reverted / orphaned / finality_violation / stuck
```

**Chỉ `final` được phép kích hiệu ứng tiền.** Ánh xạ sang các mode tích hợp thanh toán (quyết định khoá #8; danh sách đầy đủ 13 mode ở §09.2):

| Mode | `included` | `final` |
|---|---|---|
| (1) `payment.provider` in-house (M1) | `_set_pending()` | `_set_done()` rồi `_post_process()` |
| (2) Acquirer bên ngoài (M2) | `_set_pending()` | `_set_done()` sau khi khớp cả webhook acquirer **và** gate |
| (3) `account.payment` trực tiếp (M3) | Không tạo gì | Tạo `account.payment`, post |
| (4) Sub-ledger đối soát theo lô (M4) | Ghi effect | Đưa vào lô đối soát; `account.move` post ở bước lô |
| (5) Kết hợp theo từng dòng tiền (M5) | Theo cấu hình từng luồng | Theo cấu hình từng luồng |
| (13) Zether confidential (M13) | Ghi observation | Effect vào sub-ledger; **không bao giờ M1**, vì `payment.provider` cần một `amount` mà chain không có (§09.9) |

Ở **mọi** mode, `included` là `pending`. Không có ngoại lệ, kể cả khi ví người dùng đã hiện "thành công". Ngoại lệ duy nhất được cấu hình là `finality_mode = 'soft'` của §09.7, có trần giá trị `soft_final_max_amount`, và nó **không áp cho B2B settlement hay loyalty mint**.

**Bề mặt RPC công khai** (CLAUDE.md §6: cả `call_kw` lẫn `/json/2` dùng chung một method; không `_` đầu tên, không `@api.private`, không nhận `allowed_company_ids`):

```python
@api.model
def chain_event_ingest(self, caip2, events):
    """POST /web/dataset/call_kw/blockchain.chain.event/chain_event_ingest
       POST /json/2/blockchain.chain.event/chain_event_ingest
    Duong nap cho mot chain-indexer ben ngoai (khi da thang cap khoi ir.cron).
    Idempotent. Tra ve {'accepted': n, 'duplicate': n, 'rejected': [...], 'cursor_key': str}.
    Company suy ra tu blockchain.chain, KHONG nhan tu client.
    Moi event nap qua duong nay vao trang thai 'observed'; KHONG duoc phep dat 'final'.
    """
    return self._ingest(caip2, events)

@api.model
def chain_effect_status(self, ref):
    """Trang thai cua mot hieu ung theo business ref.
    'final' la trang thai DUY NHAT duoc coi la da thanh toan.
    Tra ve {'state', 'applied_state', 'tx_hash', 'block_number', 'final_datetime'}."""

@api.model
def chain_finality_state(self, caip2):
    """head_key, final_key, lag_blocks, lag_seconds, chain state, reorg_count_24h.
    Cho UI va healthcheck. Khong yeu cau quyen dac biet."""

@api.model
def zether_history_page(self, schnorr_address, after_position_key=None, limit=500):
    """Lich su ConfidentialTransfer/Deposit/Withdraw cua MOT tai khoan, de client recovery (§03.2.6).
    ACL: chi tra ve neu schnorr_address thuoc mot blockchain.zether.account co partner_id
    khop voi nguoi dung dang dang nhap. Server tu kiem, khong tin tham so.
    Phan trang theo position_key tang dan; limit tran cung 1000."""
```

Bốn method, không hơn. Mọi thứ khác là private. `zether_history_page` là method mà §03.2.6 ngầm yêu cầu và bản nháp chưa có.

**ACL và record rule** (bản nháp không nói, và nó quyết định ai in được tiền):

| Model | `blockchain_user` | `blockchain_operator` | `blockchain_manager` | Ghi chú |
|---|---|---|---|---|
| `blockchain.chain.event` | R | R | R | **Không ai có W/U/D.** Chỉ `sudo()` của indexer ghi |
| `blockchain.chain.effect` | R | R | R | Như trên. `applied_state` đổi qua method, không qua form |
| `blockchain.index.cursor` | — | R | RW (chỉ `state`) | Rewind thủ công là hành động của manager, có tracking |
| `blockchain.contract.abi` | R | R | RWC | Thêm ABI = thay đổi cách diễn giải tiền |
| `blockchain.watched.address` | R | RWC | RWCD | |
| `blockchain.reorg.event` | R | R | RW (`resolution_state`) | |

Record rule đa công ty: `blockchain.chain.event` là **quan sát**, không thuộc công ty nào → `company_id = False`, hiển thị cho mọi công ty. `blockchain.chain.effect` **có** `company_id`, suy ra từ `blockchain.money.flow` đã khớp (§09.4), không bao giờ từ client. Không dùng `child_of` trên bất kỳ cột `Char` nào.

```xml
<record id="cron_chain_index_scan" model="ir.cron">
    <field name="name">Blockchain: scan chains and advance finality gate</field>
    <field name="model_id" ref="model_blockchain_index_cursor"/>
    <field name="state">code</field>
    <field name="code">model._cron_index_scan()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">minutes</field>
</record>
```

Sáu cron, mỗi cái một dòng gọi method model:

| Cron | Chu kỳ | Method | Việc |
|---|---|---|---|
| `cron_chain_index_scan` | 1 phút | `model._cron_index_scan()` | Quét head + final, decode, tạo event/effect |
| `cron_effect_apply` | 1 phút | `model._cron_apply_effects()` | Drain `final AND applied_state != applied`, drain `blocked` (§11.7) |
| `cron_balance_reconcile` | 15 phút | `model._cron_reconcile_balances()` | Multicall `eth_getBalance`/`balanceOf` vs sổ (§11.8) |
| `cron_cursor_janitor` | 10 phút | `model._cron_check_cursors()` | Cursor đứng im, `warn`/`stuck` finality, drift |
| `cron_redecode_undecoded` | 1 giờ | `model._cron_redecode()` | Re-decode `state='undecoded'` sau khi có ABI mới |
| `cron_archive_events` | hàng tháng | `model._cron_archive()` | Parquet + DELETE cho chain public > 90 ngày |

Bẫy Odoo 19 áp dụng ở đây, đã kiểm:

- Toàn bộ constraint dùng `models.Constraint(...)`. **Kiểm bằng `pg_constraint`/`pg_indexes`, không tin code.**
- Tên field tránh trùng tên kiểu: `block_datetime`, `observed_datetime`, `final_datetime`, `scan_datetime`, `payload_hex`, `abi_version`, `position_key` — không `date`, `datetime`, `json`, `text`, `binary`.
- Cron chỉ gọi **một dòng** method của model; không `fields.` hay `relativedelta` trong eval context.
- `is_final` là compute **stored + required**: mọi nhánh phải gán giá trị, kể cả nhánh `chain chưa cấu hình` — nếu không, cột `NOT NULL` nhận `NULL` và INSERT chết. Stored compute **không** nhận `default`. Cụ thể ở đây: `_compute_is_final` phải có `else: rec.is_final = False` cho mọi `finality_source` chưa xử lý, kể cả một giá trị Selection mới thêm.
- Không `child_of` trên bất kỳ cột `Char` nào (`position_key` là Char và không bao giờ là vế trái của `child_of`).
- Không secret trong record: RPC key, mirror node token nằm ở `ir.config_parameter` hoặc ngoài DB; record chỉ giữ `secret_ref` (§08.1 đã bỏ hẳn field `url` vì URL *chính là* secret).
- `fields.Integer` là `int4`: không dùng cho `lt` của TON hay consensus timestamp nanos của Hedera (§11.2, A1).

#### 11.11b. Quan trắc: sáu metric, và ngưỡng

Không có mục này thì mọi thứ ở trên là lý thuyết. Sáu metric, tất cả tính được bằng một `SELECT`, đẩy sang `sem` (projection của note):

| Metric | Công thức | Cảnh báo | Nghiêm trọng |
|---|---|---|---|
| `index_lag_seconds` | `now() - scan_datetime` | > 10 × poll | > 30 × poll |
| `finality_lag_seconds` | `now() - final_datetime của block final mới nhất` | > `finality_warn_seconds` | > `finality_stuck_seconds` |
| `effects_pending` | count `state='final' AND applied_state='pending'` | > 50 | > 500 hoặc tuổi > 15 phút |
| `effects_blocked` | count `applied_state='blocked'` | > 0 quá 900 s | quá 3 giờ (§11.7) |
| `reorg_count_24h` | count `blockchain.reorg.event` | > 20 | bất kỳ `crossed_final_gate = True` |
| `balance_drift_units` | max abs(on-chain − sổ) trên watchlist | > 0 | > ngưỡng theo token |
| `undecoded_count` | count `state='undecoded'` | tăng liên tục 3 chu kỳ | > 1,000 |
| `active_accounts_per_hour` (Zether) | count distinct `fromSchnorrAddress` | < 20 | < 5 (§11.10) |

`crossed_final_gate = True` là metric duy nhất mà **một** sự kiện là nghiêm trọng. Mọi cái khác là ngưỡng.

#### 11.11c. Kiểm chứng bắt buộc trước khi go-live

Không phải "nên có". Nếu một trong sáu cái này chưa chạy, `dms_blockchain` chưa được bật cho tiền thật.

1. **Constraint có thật trong Postgres.** Không tin code (bẫy CLAUDE.md #2):
   ```sql
   SELECT conname, contype FROM pg_constraint
    WHERE conrelid IN ('blockchain_chain_event'::regclass,
                       'blockchain_chain_effect'::regclass,
                       'blockchain_index_cursor'::regclass);
   SELECT indexname FROM pg_indexes
    WHERE indexname LIKE 'blockchain%bamboo_uuid_uniq';
   ```
2. **Test reorg trên chain thật.** Chạy một devnet Besu/Anvil, ghi 10 event, reorg 5 block, xác nhận: event cũ `orphaned` không bị xoá, `head_cursor` lùi đúng ancestor, không effect nào bị áp hai lần, `blockchain.reorg.event` có một dòng với `depth = 5`.
3. **Test đua backfill × tip-follower.** Chạy hai worker cùng lúc trên cùng range, xác nhận `SELECT count(*) FROM blockchain_chain_effect` bằng đúng số event nghiệp vụ, và log có dòng "lost the insert race" của `bamboo_idempotency`.
4. **Test crash giữa create effect và apply.** Kill worker sau `bamboo_create_idempotent`, trước `_apply()`. Xác nhận cron reconciler nhặt lại trong ≤ 5 phút và bút toán được tạo đúng một lần.
5. **Test event giả.** Deploy `FakeUSDC`, phát `Transfer` tới địa chỉ watched. Xác nhận **không** có effect nào, và log có một dòng "log from non-allowlisted address" (§11.8b).
6. **Test recovery Zether.** Xoá state client, gọi `zether_history_page`, dựng lại số dư, xác nhận `g^{b_final} == C_acc · D_acc^{-x}` (§03.2.6). Đo thời gian: mục tiêu < 5 s cho 10,000 giao dịch.

---

### 11.12. Còn phải quyết

1. **`bytes32 indexed ref` trong mọi event nghiệp vụ** — quyết định contract, phải chốt trước khi §01–§04 freeze ABI. Không có nó, dedup chỉ là heuristic. Kèm ràng buộc: nó chiếm một trong ba ô topic indexed, nên phải quyết luôn hai ô còn lại là gì.
2. **Thang phí phẳng cho Zether** (giá trị cụ thể, đơn vị sổ cái). Ad valorem = mất bảo mật, không thương lượng được. Và thang phải **độc lập với `v`**, không theo khoảng giá trị (§11.10).
3. **Viewing key cho auditor**: `memoAud` (rẻ, tin sender) hay `C_aud + sigma equality` (+40–60k gas, không tin sender)? §03 hiện **mâu thuẫn với chính nó** — §03.1.6 nhắc `C_aud, D_aud`, struct §03.2.5 không có. Phải chốt trước khi verifier freeze.
4. **HSM phải expose `ecdh(point) -> shared_secret`** để Odoo giải memo AEAD mà không chạm `x` (§11.10). Yêu cầu mới lên §07; cần xác nhận nhà cung cấp custody đã chọn có operation này (Fireblocks/Fordefi/Turnkey đều có ở dạng nào đó, CloudHSM cần cấu hình mechanism).
5. **Celo sau khi thành L2**: xác nhận lại ngữ nghĩa finality, block time, **và endpoint archive cho lịch sử pre-migration** tại thời điểm deploy; toàn bộ giả định BFT trong note không còn đúng.
6. **Nguồn archive cho Soroban** (Horizon / Galexie / Hubble) — phải có trước go-live, không phải sau. Retention mặc định của Soroban RPC là ~24 giờ, không phải 7 ngày.
7. **Runbook `finality_violation`**: ai được duyệt bút toán đảo, trong bao lâu, và ngưỡng nào thì tạm dừng toàn bộ luồng tiền của chain đó.
8. **Ngưỡng chuyển từ `ir.cron` sang service** đã viết ở §11.0 — cần người xác nhận rằng p95 90 s là chấp nhận được cho UX thanh toán.
9. **Retention Zether = vĩnh viễn trong Postgres** (§11.9) — cần xác nhận từ phía vận hành rằng 49 GB sau 10 năm là chấp nhận được, và rằng backup/restore của DB đó vẫn trong SLA.
10. **`token_quirk` allowlist**: danh sách token cụ thể được phép cho luồng tự động trên Gnosis và Celo, và ai duyệt thêm.
11. **Chu kỳ anchor cho chain private**: đề xuất 60 s / $53 năm (§11.3). Cần xác nhận rằng cửa sổ rewind 60 s không để lại vết là chấp nhận được về mặt kiểm toán.

---

### 11.13. Chỗ mâu thuẫn cần đồng bộ giữa các section

| # | Mâu thuẫn | Đề xuất chốt |
|---|---|---|
| C1 | §05 dùng prefix `dms.blockchain.*`; §03/§04/§06/§10/§11 dùng `blockchain.*` | `blockchain.*` (§10.3 đã chốt) |
| C2 | §08.1 có `finality_depth` + `finality_mode`; §11.3 thêm `finality_source` + `finality_warn/stuck_seconds` | Hợp nhất trên một model `blockchain.chain`; `finality_mode` của §08 và `finality_source` của §11 là **cùng một khái niệm**, giữ tên `finality_source` và bỏ `finality_mode` |
| C3 | §09.7 cho `finality_mode = 'soft'` với reversal; §11.4 nói `final` bị reorg là sự cố phải halt | Không mâu thuẫn nhưng phải viết chung: `soft` là một profile riêng có `soft_final_max_amount`, và reorg sau `soft-done` tạo `blockchain.payment.reversal`, **không** halt chain |
| C4 | §03.1.6 nhắc `C_aud, D_aud`; §03.2.5 struct không có | Xem quyết định #3 ở §11.12 |
| C5 | Bản nháp §11 nói raw log 90 ngày; §03.2.6 nói recovery cần toàn bộ lịch sử | §11.9 mục 3: Zether không xoá; chain public 90 ngày |
| C6 | §08.1 `cursor_block` là một field trên `blockchain.chain`; §11.2 có model `blockchain.index.cursor` riêng | Model riêng thắng — một chain có nhiều stream (`logs`, `native`, `backfill:*`), một field không đủ. §08.1 nên bỏ `cursor_block` |
| C7 | §03.3.3 proof 1,280 B; bản nháp §11.9 dùng 672–800 B | 1,280 B (đã sửa trong §11.9) |
