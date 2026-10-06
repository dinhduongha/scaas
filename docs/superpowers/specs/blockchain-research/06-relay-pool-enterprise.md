## 06. Relay Pool nội bộ: nonce manager, gas circuit breaker, simulation gate

> **Trạng thái bản này:** bản nháp đầu bị rà soát lại theo hướng "hostile review". Những chỗ đã sửa được đánh dấu **[SỬA]**; những chỗ là bổ sung mới đánh dấu **[MỚI]**. Bảy cái sai kỹ thuật trong chính bản nháp đầu đã được gỡ, liệt kê tập trung ở §06.13.
>
> Quy ước đặt tên: prefix model `blockchain.*` (theo chốt của §10.3 — **không** phải `dms.blockchain.*` như §05 đang viết). `dms_blockchain` **không depend `dms`**.
>
> **Bản 2 — sau khi user chốt kiến trúc mesh.** `_USER-DECISIONS.md` §21.4 và §21.5 đổi hai thứ trong section này: relay pool nội bộ giờ là **một vai** (gateway / node có submit) trong một ma trận vai, không phải một loại hạ tầng riêng; và `KeyPool` mô tả ở đây **dùng chung** với node mesh do cá nhân chạy — cùng interface, khác nơi giữ khoá. Xem §06.5 và §06.6.

---

### 06.0. Phạm vi, ranh giới tiến trình, và ràng buộc standalone

> **[BẢN 3 — viết lại theo `_USER-DECISIONS.md` §23]** Bản 1 và bản 2 của §06.0/§06.1 xây trên một giả
> định chưa ai phát biểu: tầng daemon là **N tiến trình Python không trạng thái**. Từ đó suy ra Redis làm
> store nonce, Lua script cấp lease, fencing token, ownership lease, consistent-hash shard. `_USER-DECISIONS.md` §23.3 chốt
> **một binary Rust**, và bài toán đó biến mất cùng toàn bộ giải pháp của nó. **Không Redis. Không Lua.**

Relay Pool nội bộ là năng lực **ứng trước native gas** cho giao dịch của chính doanh nghiệp. Nó không
phải Open Relayer Network — Open Relayer là bên thứ ba tự quyết định lợi nhuận; relay pool nội bộ là hạ
tầng phải có SLA. Hai thứ chạy song song và **cạnh tranh cùng một intent**: nếu Open Relayer nhặt intent
trước, job nội bộ phải bị huỷ sạch chứ không phát sóng trùng.

Theo ma trận `_USER-DECISIONS.md` §21.4, "relay pool nội bộ" và "node mesh" **không phải hai phần mềm** — chúng là hai **cấu
hình** của cùng một binary: relay pool là một node có `ingest: http`, `pool: none`, `submit: true`, chạy
sau vành đai. Mọi cơ chế trong section này (nonce manager, breaker, simulation gate) **cũng cần cho một
node mesh có submit**; chúng không phải đặc quyền của hạ tầng doanh nghiệp.

Quyết định kiến trúc đầu tiên, và note gốc không nói rõ: **vòng lặp broadcast KHÔNG chạy trong `ir.cron`.**

| Thành phần | Chạy ở đâu | Lý do |
|---|---|---|
| Control plane: chain config, policy, relayer account, job record, audit, breaker state | Odoo 19 addon `dms_blockchain` | Cần ACL, record rule, view, multi-company, audit trail |
| Hot loop: cấp nonce, xin ký, broadcast, theo dõi receipt, replace | `scaas-node` vai `submit` (Rust) | Odoo worker là sync/blocking, `ir.cron` tối thiểu 1 phút và chạy trong transaction dài; một tx treo sẽ giữ lock hàng row |
| State nonce | **Bộ nhớ tiến trình** (một task sở hữu duy nhất) + **journal Postgres** | Không có state chia sẻ giữa các tiến trình ⇒ không cần store phân tán |
| Vật liệu khoá | **Không nằm ở đây.** Làn custody giữ (`_USER-DECISIONS.md` §23.2) | Làn relay parse byte của người lạ; khoá không được cùng address space |
| Cron Odoo | Chỉ reconcile + janitor, mỗi 1–5 phút | XML gọi đúng một dòng: `model._cron_relay_reconcile()` |

Ràng buộc standalone (khoá cứng): `dms_blockchain` **không depend `dms`**. Relay pool không biết gì về
`dms.trade.settlement` hay `dms.payment.collection`. Job mang con trỏ lỏng lẻo `origin_model` (Char) +
`origin_res_id` (Integer) + `origin_ref` (Char, idempotency key do consumer cấp). Không Many2one ngược về
consumer, không `ir.model.data` cross-addon.

Đường dẫn, sau khi gộp:

```
custom-addons/bamboo-dms/dms_blockchain/          # addon Odoo (control plane)
    models/blockchain_chain.py
    models/blockchain_rpc_endpoint.py
    models/blockchain_relayer_account.py
    models/blockchain_relay_job.py
    models/blockchain_gas_policy.py
    models/blockchain_breaker_event.py
    models/blockchain_target_policy.py
    data/ir_cron.xml

scaas-node/                                      # MOT binary Rust (`_USER-DECISIONS.md` §23.3)
    src/roles/{gateway,mesh,pool,submit,indexer}.rs
    src/roles/{custody,oracle}.rs                 # lan khac, xem `_USER-DECISIONS.md` §23.2
    src/chain/{evm,sui,soroban,cosmwasm,ton,hedera}.rs
    src/nonce/{actor.rs, journal.rs, coldstart.rs, gapfill.rs}
    src/keypool/pool.rs                           # `_USER-DECISIONS.md` §21.5
    src/sim/gate.rs   src/breaker/gas.rs
                                                  # KHONG co lua/  KHONG co shard/
smartcontracts/                                   # ngoai addon, theo quyet dinh da khoa
```

Định danh chain dùng **CAIP-2** ở mọi nơi (`eip155:100` = Gnosis, `eip155:42220` = Celo, `eip155:9000` =
chain private, `sui:mainnet`, `stellar:pubnet`, `cosmos:<chain-id>`, `hedera:mainnet`, `ton:-239`). Lý do:
một trường `Char` duy nhất chạy xuyên 7 hệ sinh thái, thay vì `Integer chain_id` chỉ dùng được cho EVM.
Tránh đặt tên field `chain_id` cho số nguyên EVM — `chain_id` là Many2one tới `blockchain.chain`; số EVM
lưu tại `blockchain.chain.evm_chain_number`.

#### 06.0.1. [BẢN 3] Giao diện Odoo ↔ node: outbox, không Redis Stream

Bản 1 nói "Redis Stream consumer group". §08.2b đã bác điều đó và chốt **transactional outbox**; `_USER-DECISIONS.md` §23 xoá
Redis khỏi kiến trúc hoàn toàn. Chốt lại đầy đủ:

| Hướng | Kênh | Payload | Ai là sự thật |
|---|---|---|---|
| Odoo → node (dispatch) | **Bảng `blockchain.relay.job` trong Postgres.** Node `SELECT ... FOR UPDATE SKIP LOCKED` | bản ghi job đầy đủ | Postgres. Job được ghi **cùng transaction** với thay đổi nghiệp vụ sinh ra nó |
| Đánh thức | `LISTEN/NOTIFY` trên channel `bc_job_{caip2}` | chỉ một tín hiệu, không dữ liệu | Không ai — mất NOTIFY thì poll bắt được |
| Node → Odoo (kết quả) | **Bảng `blockchain.relay.result`**, node ghi bằng DB role riêng | `{job_uuid, state, tx_hash, nonce, gas_used, cost_base_units, error_code, observed_at_ms}` | Odoo đọc bằng cron và áp vào job |
| Backstop | `ir.cron` 5 phút `model._cron_relay_reconcile()` | đọc chain + journal, sửa mọi job lệch | Bắt buộc, không tuỳ chọn |

Ba thay đổi so với bản 1, mỗi cái có lý do:

1. **Redis Stream → bảng Postgres.** Stream không tham gia được transaction của Odoo, nên luôn tồn tại
   cửa sổ "job đã ghi Stream, transaction rollback" hoặc ngược lại. Outbox không có cửa sổ đó. Đây là
   cùng lập luận §15.2.4 dùng cho settlement, và nó không có ngoại lệ nào cho relay.
2. **HTTP callback `relay_report_batch` → bảng kết quả.** Bản 1 cho node gọi HTTP vào Odoo. Bỏ: một
   round-trip HTTP có thể mất, có thể timeout sau khi Odoo đã commit, và nó bắt node biết URL + JWT của
   Odoo. Node ghi một dòng vào bảng nó có quyền ghi; Odoo đọc. Không ai phải bắt lỗi mạng.
   *Đánh đổi đã cân:* bản 1 lập luận "không ghi thẳng Postgres vì bỏ qua ORM là bỏ qua record rule và
   `@api.constrains`". Đúng — nên node **không** ghi vào `blockchain.relay.job`; nó ghi vào
   `blockchain.relay.result`, một bảng chỉ-thêm không có logic nghiệp vụ, và Odoo áp kết quả qua ORM.
   Invariant của ORM còn nguyên, cửa sổ mất mạng biến mất.
3. **`LISTEN/NOTIFY` thay cho poll 1 giây.** Độ trễ xuống dưới 10 ms mà không cần thêm hạ tầng. Mất
   NOTIFY là vô hại vì poll định kỳ vẫn chạy — NOTIFY là tối ưu latency, poll là bảo đảm.

#### 06.0.2. Trục `chain_profile`: private làm thay đổi nửa số cơ chế trong section này

Quyết định khoá #5 (private chain đi trước cho Zether) không chỉ đổi chi phí — nó đổi cả mô hình lỗi.

| Cơ chế | `chain_profile = 'public'` | `chain_profile = 'private'` (Clique / PoA) |
|---|---|---|
| Gas price | Biến động, phải có spike breaker | Cố định (`MinGasPrice = 0` trên chain 9000). **Tắt spike breaker** |
| Velocity limit | Đơn vị **USD** | Đơn vị **gas** (không có giá USD; runaway loop vẫn phải chặn) |
| Mempool eviction | Có, tx bị drop → cần re-broadcast | Không (txpool không bị ép giá). Trạng thái `dropped` gần như không xảy ra |
| Replacement | Speed-up bằng fee bump | Fee bump vô nghĩa. "Treo" = **signer đang kẹt** → alarm hạ tầng, không phải bump |
| Block gas limit | Cho trước (Gnosis ~17M) | **Ta đặt** — chain 9000 hiện 16,7M, ngang Gnosis, nâng được bằng signer vote không cần reset |
| Finality | Theo bảng §11 | **Clique một signer không có finality BFT.** Đừng chép `finality_depth = 1` từ một stack QBFT |
| RPC divergence check | Bật | **Vẫn bật**. Một validator bị chiếm là kịch bản dễ xảy ra hơn trên mạng nhỏ |
| Reorg | Có | Clique reorg ngắn được khi signer đổi lượt; không phải "không bao giờ" như BFT |
| MEV / front-run | Có | Không |

Hai hàng cuối đã sửa so với bản 1, vì bản 1 giả định một stack Besu QBFT không tồn tại. Chain private
thật là **Nethermind + Clique, một signer**. Clique không phải BFT: không instant finality, và reorg
ngắn được. Viết `finality = 1 block` cho nó là chép nhầm từ tài liệu khác.

Field: `blockchain.chain.chain_profile = fields.Selection([('public','Public'), ('private','Private/Permissioned')], required=True, default='public')`.
Mọi đoạn breaker/replacement dưới đây guard bằng profile. Không guard = build một đấu giá gas cho một
mạng một node của chính mình.

#### 06.0.3. Những giả định bản nháp đầu không nói ra

Liệt kê thẳng, vì mỗi cái là một cách hệ thống hỏng. **Hai giả định đầu của bản 1 đã chết cùng Redis** —
giữ lại số thứ tự và ghi rõ, để ai đọc bản cũ biết vì sao.

1. ~~**Redis được coi là sự thật về nonce.**~~ **Không còn Redis.** Sự thật là chain; journal là Postgres;
   cache là bộ nhớ của tiến trình sở hữu. Điều bản 1 lo — AOF `everysec` mất 1 giây ghi, replica async
   roll back khi failover — biến mất cùng thành phần gây ra nó.
2. ~~**Một worker sở hữu một relayer account "qua consistent hash".**~~ **Không còn worker thứ hai để
   tranh.** Xem §06.1.1: quyền sở hữu do **advisory lock của Postgres** cấp, một dòng, và nó tự nhả khi
   connection chết.
3. **`eth_estimateGas` cho ra chi phí.** Sai trên mọi L2 rollup: phí L1 data (blob/calldata) **không**
   nằm trong `gas` của L2. Bỏ sót nó làm ước tính thấp hơn thực tế 2–10 lần trên Base/Optimism/Celo-L2
   (§06.2.5).
4. **Tx đã ký luôn re-broadcast được.** Sai. Nếu base fee đã vượt `maxFeePerGas` của tx đã ký, node nhận
   nhưng không bao giờ đào. Đó là `underpriced`, chưa phải `dropped`, và cách chữa là **bump**.
5. **Sim là miễn phí.** `eth_call` một tx Zether 1,79M gas không miễn phí với nhà cung cấp RPC, và nhiều
   nhà cung cấp **cap gas của `eth_call`** ở 10M–50M (§06.3.5).
6. **Ký là một thao tác.** Với MPC SaaS, một vault thường **serialize** yêu cầu ký; song song hoá trong
   cùng vault không tăng throughput. 5–30 sign/s là cho cả vault, không phải mỗi connection.
7. **Job Postgres giữ được raw tx.** Ở 100 job/s, 6 KB/job là 52 GB/ngày. Phải có chính sách lưu trữ
   (§06.10.3).
8. **Giá USD luôn có.** Oracle giá native stale thì velocity limit tính sai. Phải fail-closed (§06.4.3).
9. **Tenant = company.** Chốt: `company_id` trên job; velocity bucket theo `company_id`; record rule theo
   `company_ids` của user.
10. **Consumer hiểu đúng "final".** Bảng ánh xạ state → nghĩa vụ tài chính ở §06.2.6.
11. **Một relayer account = một khoá.** Sai, và là ràng buộc cứng của EVM: nonce tuần tự nghĩa là một tx
    kẹt chặn toàn bộ hàng đợi phía sau. Một relayer cần **pool khoá** (`_USER-DECISIONS.md` §21.5); mọi thứ dưới đây hiểu
    "relayer" là một `relayer_id` có N khoá, không phải một địa chỉ.
12. **[BẢN 3] Node giữ khoá ký.** Không. Node xin làn custody ký (`_USER-DECISIONS.md` §23.2). Nonce manager quản **số**, không
    quản **khoá** — nó biết địa chỉ và nonce kế tiếp, không bao giờ thấy vật liệu khoá.

---

### 06.1. Nonce manager: vì sao `INCRBY` không đủ, và nó trông thế nào khi chỉ có một tiến trình

Note (§10.3 mục 2) viết: *"Duy trì bộ đếm tăng dần bất biến (`INCRBY`) cho từng địa chỉ Relayer trên từng
Chain ID"*. **Sai ở một chỗ mang tính quyết định**: `INCR` cấp phát, nhưng không ai trả lại. Đây là
**bài toán lỗ thủng nonce**:

```
t0  job A  cap -> nonce 41   -> ky -> broadcast OK
t1  job B  cap -> nonce 42   -> signer timeout -> job B chet
t2  job C  cap -> nonce 43   -> broadcast OK
```

Nonce 42 không bao giờ được phát sóng. Trên EVM, tx nonce 43 nằm vĩnh viễn trong mempool ở trạng thái
*queued* (không phải *pending*), không bao giờ được đào, và **mọi tx sau đó của ví này chết theo**. Một
lỗi signer timeout duy nhất đóng băng toàn bộ relayer account. Đúng y hệt trên Cosmos (account sequence),
Stellar (sequence number), TON (seqno).

Giải pháp: **nonce leasing** — cấp phát có thời hạn, có trả lại, có freelist.

**Và một giải pháp thứ hai ở tầng trên: nhiều khoá** (`_USER-DECISIONS.md` §21.5). Leasing chữa lỗ thủng *trong* một khoá; nó
không chữa việc một khoá chỉ chạy được ~1 tx/block. Hai cơ chế giải hai bài toán khác nhau, cần cả hai:

| Bài toán | Cơ chế | Mục |
|---|---|---|
| Nonce bị cấp rồi không dùng → khoá chết | Nonce leasing + freelist | §06.1 |
| Một khoá = 1 tx/block → trần thông lượng | Pool N khoá, chọn least-in-flight | §06.5.4, `_USER-DECISIONS.md` §21.5 |
| Một tx kẹt chặn hàng đợi phía sau | Replacement (§06.2) **cộng** chuyển job sang khoá khác | cả hai |

Hàng thứ ba là chỗ hai cơ chế gặp nhau: với một khoá, tx kẹt buộc phải chờ replacement thành công. Với
pool khoá, job mới đi sang khoá khác **ngay**, và gỡ khoá kẹt thành tác vụ nền chứ không phải sự cố chặn
dịch vụ. Đó là lý do thực dụng nhất để có pool, mạnh hơn cả lý do thông lượng.

#### 06.1.1. [BẢN 3] Một task sở hữu, không một store phân tán

Toàn bộ máy móc đồng bộ của bản 1 và bản 2 — Lua script, fencing token, `owner_fence`, ownership lease
TTL 10 s, consistent hash `% N_workers`, generation counter `gen` — tồn tại để giải **một** bài toán:
nhiều tiến trình tranh cùng một không gian nonce. Một tiến trình thì không có bài toán đó.

Hình dạng đúng trong Rust là **actor**: một task `tokio` sở hữu state của một `(caip2, key_addr)`, và mọi
yêu cầu đi qua một kênh `mpsc`. Không mutex, không lock, không race — **theo cấu trúc**, không theo kỷ
luật lập trình.

```rust
// Moi (caip2, key_addr) co dung MOT task nay. State la bien local cua no.
struct NonceActor {
    caip2: String,
    addr: Address,
    confirmed: u64,              // tu getTransactionCount('latest')
    next: u64,                   // nonce ke tiep chua tung cap
    leased: BTreeMap<u64, Lease>,       // nonce -> (job_uuid, expire_at)
    free: BinaryHeap<Reverse<u64>>,     // freelist, uu tien nonce nho nhat
    signed: BTreeMap<u64, TxHash>,      // nonce DA co raw tx da ky — KHONG BAO GIO ve free
    inflight: BTreeMap<u64, Instant>,
}

enum Msg {
    Acquire { job: Uuid, reply: oneshot::Sender<Result<u64>> },
    MarkSigned { nonce: u64, tx: TxHash },
    Release { nonce: u64, reason: ReleaseReason },
    Confirmed { upto: u64 },
    Reap,                        // het han lease
}
```

`Acquire` ưu tiên `free` trước, rồi mới `next += 1`. Backpressure nằm ngay trong `Acquire`: nếu
`leased.len() + inflight.len() >= max_inflight` thì trả `Err(Backpressure)` — **không** cấp một nonce chắc
chắn rơi vào hư vô. `max_inflight = 16` không phải con số tuỳ ý mà là `txpool.accountslots` mặc định của
node (`_USER-DECISIONS.md` §23.1).

**Quy tắc tài chính, giữ nguyên từ bản 1 và là quy tắc quan trọng nhất ở đây:** một nonce đã có raw tx
**đã ký** thì **không bao giờ** quay về `free`. Hai tx đã ký trên cùng nonce nghĩa là một hành động
nghiệp vụ đã huỷ vẫn có thể được đào. Đó là lỗi tiền thật, không phải lỗi vận hành. Vì thế `Release`
kiểm `signed` trước:

```rust
Msg::Release { nonce, reason } => {
    if self.signed.contains_key(&nonce) {
        // KHONG tra ve free. Duong duy nhat la replacement (§06.2) hoac gap-filler (§06.1.7).
        self.mark_stuck(nonce, reason);
    } else {
        self.free.push(Reverse(nonce));
        self.leased.remove(&nonce);
    }
}
```

**Chọn khoá trong pool** cũng nằm trong một actor riêng cho mỗi `(caip2, relayer_id)`, giữ một
`BTreeMap<Address, usize>` đếm inflight và trả về khoá ít việc nhất (least-in-flight, `_USER-DECISIONS.md` §21.5). Round-robin
**không** dùng được: nó vẫn gửi vào một khoá đang kẹt.

**Quyền sở hữu, khi ai đó vẫn chạy hai tiến trình.** Cấu hình đúng là một tiến trình có vai `submit` cho
một `(caip2, relayer_id)`. Cấu hình sai thì phải bị chặn, không phải bị phát hiện muộn — và Postgres đã
có sẵn công cụ:

```sql
SELECT pg_try_advisory_lock(hashtext('bc:submit:' || :caip2 || ':' || :relayer_id));
```

Một dòng. Lấy được thì chạy; không lấy được thì **từ chối khởi động vai `submit`** và log rõ ai đang
giữ. Lock tự nhả khi connection chết, nên không có lease TTL, không có fencing token, không có heartbeat.
Đây là toàn bộ §06.1.3 của bản 1, thay bằng một câu lệnh.

#### 06.1.2. Journal: cái gì phải bền, và ghi theo thứ tự nào

State trong bộ nhớ mất khi tiến trình chết. Cái không được mất là **quan hệ nonce ↔ tx đã ký**, vì đó là
thứ duy nhất phân biệt "nonce này an toàn để cấp lại" với "nonce này đã có một tx có thể được đào".

```python
class BlockchainNonceJournal(models.Model):
    _name = 'blockchain.nonce.journal'
    _description = 'Durable nonce ledger for one signing key'

    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True)
    key_address  = fields.Char(required=True, index=True)
    nonce        = fields.Char(required=True)          # uint64 dang chuoi, theo §10.4.1
    job_uuid     = fields.Uuid(index=True)
    journal_state = fields.Selection([
        ('leased', 'Leased'), ('signed', 'Signed'), ('broadcast', 'Broadcast'),
        ('confirmed', 'Confirmed'), ('released', 'Released'), ('stuck', 'Stuck')],
        required=True, default='leased', index=True)
    tx_hash      = fields.Char(index=True)
    leased_datetime = fields.Datetime(required=True)

    _unique_live_nonce = models.UniqueIndex(
        "(chain_id, key_address, nonce) WHERE journal_state != 'released'",
        'Mot nonce chi co mot ban ghi song cho mot khoa.')
```

**Thứ tự ghi bắt buộc (write-ahead), giữ nguyên từ bản 1:**

```
1. INSERT journal (leased)          -- COMMIT truoc khi lam gi tiep
2. xin lan custody ky               -- co the timeout
3. UPDATE journal -> signed + tx_hash   -- COMMIT truoc khi broadcast
4. broadcast
5. UPDATE journal -> broadcast
```

Đảo bước 3 và 4 là mở lại đúng cái lỗ mà cả mục này tồn tại để bịt: crash giữa broadcast và ghi journal
để lại một tx trên mạng mà ta không biết là của nonce nào.

Bước 1 và bước 2 **không nằm trong một transaction** — bước 2 là một lời gọi mạng, và §15.2.4 cấm gọi
mạng trong transaction. Đó là lý do `leased` là một trạng thái riêng chứ không phải một biến tạm.

#### 06.1.3. Cold start: giao thức khi tiến trình khởi động lại

Bản 1 gọi đây là "cold start khi Redis trống". Không còn Redis, nhưng bài toán còn nguyên: tiến trình
khởi động lại thì state trong bộ nhớ rỗng, và cấp nonce từ 0 cho một account đang ở nonce 4.128 làm mọi
tx bị `nonce too low` và quay vòng vô hạn.

```
Voi moi (caip2, key_addr) co vai submit:
  1. lay advisory lock (§06.1.1). Khong lay duoc -> khong khoi dong vai nay.
  2. chain_pending  = getTransactionCount(addr, 'pending')   qua >= 2 RPC doc lap, phai khop
  3. chain_latest   = getTransactionCount(addr, 'latest')
  4. journal_max    = SELECT max(nonce::bigint) FROM blockchain_nonce_journal
                      WHERE key_address = addr AND journal_state IN ('signed','broadcast')
  5. next      = max(chain_pending, journal_max + 1)
     confirmed = chain_latest
  6. nap lai `signed` tu journal cho moi nonce >= confirmed
  7. free = {} — KHONG suy ra freelist tu chenh lech.
     Lo thung giua confirmed va next do gap-filler xu ly (§06.1.7), khong do cold start doan.
```

Bước 2 hỏi **hai RPC độc lập và bắt chúng khớp**: một node tụt hậu trả `pending` thấp hơn thực tế, và
tin nó là cấp lại một nonce đã dùng. Đây là §06.7 áp vào đúng chỗ nguy hiểm nhất.

Bước 7 là chỗ dễ viết sai. Cám dỗ là "mọi nonce trong `[confirmed, next)` mà không có trong `signed` thì
cho vào freelist". **Không**: một tx đã broadcast nhưng journal chưa kịp ghi `signed` (crash giữa bước 3
và 4 ở §06.1.2) sẽ bị coi là free, và ta ký một tx thứ hai trên nonce đó. Cold start **không đoán**; nó
để lỗ thủng lại cho gap-filler, thứ có thời gian hỏi chain cẩn thận.

#### 06.1.8. Ngữ nghĩa sequence từng chuỗi — không đồng nhất

| Chuỗi | Đơn vị thứ tự | Tx revert có tiêu đơn vị? | Song song trong 1 tài khoản | Cách relay pool xử lý |
|---|---|---|---|---|
| EVM | `nonce` per EOA, tuần tự tuyệt đối | Có (revert vẫn đào, vẫn tiêu nonce) | Tối đa `txpool.accountslots` = **16** pending | Lease + freelist + `signed` set |
| Cosmos SDK | `account sequence` | Có, nếu tx vào block; **không** nếu bị CheckTx từ chối | Không | Giống EVM; CheckTx fail phải trả lease (đường 2). Lưu ý `sequence mismatch` là lỗi CheckTx phổ biến nhất |
| Stellar/Soroban | `sequence number` của source account | Có, nếu vào ledger | Không | Fee-bump không đổi sequence của inner tx. Gap-filler = `BumpSequence` |
| TON | `seqno` trong wallet contract | Có | Không, **trừ Highload Wallet V3** | **[SỬA]** Highload V3 dùng `query_id` **23 bit = 8.388.608 slot** trong một cửa sổ `timeout` (mặc định 128 s, tối đa 1300 s) — không phải "~8k slot" như bản nháp đầu viết, lệch 1000 lần. Highload V3 là lựa chọn bắt buộc cho throughput |
| SUI | **Không có nonce.** Thứ tự = version của gas coin và owned object | n/a | Có, nếu mỗi tx dùng **gas coin khác nhau** | Quản lý *pool gas coin* (§06.5) |
| Hedera | `TransactionId = payerAccount + validStart` (nanos) | n/a, duplicate bị từ chối | Có | Cấp phát `validStart` độc nhất. **`validStart` phải ở quá khứ và trong `transactionValidDuration`** (mặc định 120 s, max 180 s) — đồng hồ lệch > 10 s làm tx bị từ chối hàng loạt. Bắt buộc chronyd/NTP trên relay worker |
| EIP-1776 meta-tx | `meta_nonce(from, batchId)` — **không gian nonce THỨ HAI** | Có | Có, qua `batchId` khác nhau | Xem dưới |

Hàng SUI đáng chú ý vì nó là chuỗi duy nhất mà **pool gas coin thay thế hoàn toàn pool khoá**: song song đến từ việc có nhiều gas coin, không từ việc có nhiều địa chỉ. Cùng bài toán (một tài nguyên tuần tự là một nút thắt), khác hình dạng lời giải.

**Note gộp hai không gian nonce làm một.** `meta_nonce(from, batchId)` là nonce của *người dùng* trong contract; nonce EOA là của *relayer*. Chúng độc lập. Relay Pool phải quản lý cả hai:

- Nonce relayer EOA: actor sở hữu + journal như §06.1.1.
- `batchNonce`: **không** do relay pool cấp. Client/Agent cấp khi ký, vì chữ ký phủ lên nó. Relay pool chỉ **kiểm tra trước khi broadcast**: `meta_nonce(from, batchId) == metaTx.batchNonce`. Nếu lệch → job về `stale`, trả về consumer để ký lại. Không bao giờ sửa payload đã ký.
- Head-of-line blocking ở tầng meta-tx: nếu `batchNonce=5` fail vĩnh viễn, 6..n của cùng `batchId` treo. Chính sách: **mỗi intent độc lập dùng một `batchId` ngẫu nhiên 128-bit với `batchNonce=0`**; chỉ dùng chuỗi tuần tự khi nghiệp vụ thật sự có thứ tự (deposit → transfer → settle). Job trong một `batchId` tuần tự được đánh dấu `chain_group_key`; một job fail thì cả group về `blocked` chứ không retry lẻ tẻ.
- **[MỚI] Kiểm tra `meta_nonce` phải ghim block.** Đọc `meta_nonce` tại block N rồi broadcast ở N+3, một tx khác của cùng user có thể đã tiêu nó. Ghi `meta_nonce_block` vào job; nếu `head - meta_nonce_block > 3` thì đọc lại. Trên thực tế gọi `meta_nonce` **trong chính `eth_call` của sim gate** (một multicall) để không tốn thêm round-trip.

Lợi ích phụ của **chế độ mở** (`mode & MODE_RESTRICT_RELAYER == 0`, và `canon()` ép `relayer` về
`address(0)` trước khi băm — `_USER-DECISIONS.md` §24): chữ ký người dùng không ràng buộc `relayer`,
nên **bất kỳ EOA nào trong pool cũng nộp được**. Sharding K EOA cho ta K đường ống song song mà không động tới payload. Đây là lợi thế thật sự của EIP-1776 so với ERC-2771 (bị ràng vào một TrustedForwarder) trong bối cảnh relay pool.

Và nó là **điều kiện kỹ thuật để pool khoá tồn tại** (`_USER-DECISIONS.md` §21.5). Nếu intent nêu tên relayer trong digest, mỗi lần đổi khoá là một lần xin lại chữ ký của mọi người dùng — pool khoá sẽ không khả thi.

> **[BẢN 4]** Câu trước đây ở đây nói hai quyết định khớp nhau vì một cái "chống cross-mode replay".
> **Không có cross-mode replay để chống** — `mode` nằm trong digest nên hai chế độ vốn đã cho hai
> digest. Điều kiện thật cho pool khoá chỉ có một, và nó vẫn đứng: **`MODE_RESTRICT_RELAYER` phải là
> tuỳ chọn của người ký, và mặc định phải là tắt.** Ai bật nó thì tự bỏ khả năng dùng pool — đó là
> đánh đổi hợp lệ, không phải lỗi thiết kế.

---

### 06.2. Phát hiện và thay thế tx treo

#### 06.2.1. Ngưỡng "treo" phải tính bằng block, không bằng giây

Note nói 60 giây. Trên Gnosis (5s/block) đó là 12 block — hợp lý. Trên Ethereum L1 đó là 5 block — quá sớm, gây bão replacement lúc nghẽn mạng và **tự nó làm tăng chi phí**. Ngưỡng đúng:

| Chuỗi | `stuck_after_blocks` | Tương đương | `escalate_every_blocks` | Trần leo thang |
|---|---|---|---|---|
| Gnosis xDAI | 12 | 60s | 6 | 8x giá ban đầu |
| Celo (L2, 1s block) | 60 | ~60s | 20 | 4x |
| Ethereum L1 | 20 | ~4 phút | 10 | 10x |
| Polygon PoS | 30 | 60s | 10 | 8x |
| Base / Optimism (OP Stack) | 120 | ~4 phút | 60 | 3x |
| Arbitrum One (Nitro) | n/a — xem §06.2.2 | | | |
| **Chain private 9000 (Clique)** | 5 | ~25s | n/a | n/a — bump vô nghĩa (`MinGasPrice = 0`) |

Hàng cuối sửa so với bản 1, vốn ghi "chain riêng (PoA/IBFT) | 5 | ~10s". Chain thật là Clique period **5 s**, nên 5 block là ~25 s, không phải 10 s.

#### 06.2.2. [SỬA] Phân loại L2 đúng: ba nhóm, không phải một

Bản nháp đầu gộp "Arbitrum/Base" làm một và gán Celo vào nhóm L1 có mempool. Cả hai đều sai.

| Nhóm | Chain | Mempool | Replacement có chạy không? | Chế độ hỏng thật |
|---|---|---|---|---|
| **A. L1 có mempool công khai** | Ethereum, Gnosis, Polygon PoS, BSC | Công khai | Có, `txpool.pricebump` 10% | Tx treo vì underpriced |
| **B. OP Stack (sequencer + op-geth txpool riêng)** | Base, Optimism, **Celo (từ 03/2025)** | Riêng, không công khai | **Có** — op-geth giữ nguyên luật pricebump 10% | Sequencer downtime; tx treo hiếm |
| **C. Arbitrum Nitro** | Arbitrum One/Nova | Sequencer FIFO theo thứ tự đến | **Không đáng tin** — sequencer sắp thứ tự theo arrival, tx nonce tương lai bị giữ lại; replacement có thể được chấp nhận nhưng không được ưu tiên lại | Sequencer downtime; lối thoát là force-inclusion qua L1 delayed inbox (~24h) |

Hệ quả thiết kế:

- Nhóm B: giữ cơ chế replacement, nhưng `stuck_after_blocks` phải lớn (block 1–2s, 120 block = 2–4 phút) — bump sớm trên một chain có block 1s là đốt tiền.
- Nhóm C: **không cài replacement**. Cài **detector sequencer**: `head` không tăng > 60s → breaker `SEQUENCER_DOWN`, dừng nhận job mới, giữ inflight, không bump. Thêm một health probe riêng `arb_sequencer_feed` (WebSocket feed của sequencer) vì `eth_blockNumber` vẫn trả kết quả khi sequencer chỉ ngưng *nhận* tx.
- **Celo đã chuyển sang OP Stack tháng 3/2025, block time 1s** (đồng bộ với cái chính của §11). Bảng finality trong note (`Celo | 5s | IBFT 2.0 | 1 block`) đã lỗi thời cả ba cột.

#### 06.2.3. [SỬA] Luật bump trên EVM — con số 15% của note cần được nói rõ

Ba con số khác nhau hay bị lẫn:

| Con số | Là gì | Hệ quả |
|---|---|---|
| **10%** | `--txpool.pricebump` mặc định của go-ethereum (và op-geth). Tx thay thế phải có `maxFeePerGas` **và** `maxPriorityFeePerGas` mới >= cũ × 1,10 | Dưới ngưỡng này node **từ chối im lặng** (`replacement transaction underpriced`) |
| **12,5%** | `BASE_FEE_MAX_CHANGE_DENOMINATOR = 8` — mức base fee có thể tăng **mỗi block** | Bump 10% một lần có thể vẫn thua base fee sau 1 block |
| **15%** | Con số note đề xuất | Đủ để vượt cả hai — nhưng chỉ cho **lần bump đầu tiên** |

Sai lầm thực tế: bump 15% *một lần* rồi đợi. Lần bump thứ hai phải >= 1,10 lần **giá đã bump**, không phải giá gốc. Và nếu mạng đang tăng base fee 12,5%/block trong 10 block liên tiếp (×3,25), một bump 15% không bao giờ đuổi kịp.

**[SỬA] Bản nháp đầu còn hai bug số học trong hàm `bump()`:** (a) so sánh `tip` với `cap` của `max_fee` — nhầm hai đại lượng; (b) nhân float rồi truncate có thể rơi *dưới* ngưỡng `floor(old*110/100)` của geth. Bản đúng:

```python
def ceil_bump(x, pct=15):
    return (x * (100 + pct) + 99) // 100          # so nguyen, luon >= floor(x*1.10)

def bump(prev_max_fee, prev_tip, attempt, chain):
    base    = rpc.base_fee_next_block()
    tip     = max(ceil_bump(prev_tip), chain.min_tip_wei)
    tip     = min(tip, chain.max_tip_wei)                     # tran RIENG cho tip
    want    = base * 2 + tip * (115 ** attempt) // (100 ** attempt)
    max_fee = max(ceil_bump(prev_max_fee), want)
    max_fee = min(max_fee, chain.absolute_max_fee_wei)        # tran RIENG cho max_fee
    if max_fee < ceil_bump(prev_max_fee):                     # cham tran -> khong bump duoc nua
        raise BumpCeilingReached(prev_max_fee, max_fee)
    return max_fee, tip
```

`BumpCeilingReached` không được nuốt. Job về `stuck_at_ceiling`, breaker `GAS_CEILING`, thông báo — vì từ đây trở đi tx **sẽ treo cho đến khi mạng rẻ lại hoặc ta cancel**, và cancel cũng cần vượt ngưỡng bump nên cũng có thể không làm được. Đó là một trạng thái thật, phải có tên.

Với pool khoá, `stuck_at_ceiling` bớt nghiêm trọng một bậc: job **mới** đi sang khoá khác ngay, nên nó là một khoá bị kẹt chứ không phải dịch vụ bị kẹt. Nhưng khoá đó vẫn phải được gỡ, và cho tới lúc đó nó là một khoá chết mang theo số dư gas của nó. Cảnh báo phải nói rõ "1/50 khoá kẹt", không phải "hệ thống bình thường".

Bắt buộc: bump **cả hai** trường. Bump chỉ `maxFeePerGas` mà giữ `maxPriorityFeePerGas` là lỗi phổ biến nhất, node từ chối và tx cũ vẫn treo.

Type-2 tx là mặc định; trên Celo phải phát **CIP-64 (tx type `0x7b`)** để khai `feeCurrency` — ethers.js/web3.py chuẩn **không serialize được type này**, adapter Celo phải tự dựng và ký RLP. **[MỚI]** Hệ quả thứ hai ít ai nói: `eth_estimateGas` trên Celo **không** tính phí quy đổi `feeCurrency`; phải cộng thêm `intrinsicGasForFeeCurrency` (hiện ~50k gas cho token có adapter, đọc từ `FeeCurrencyDirectory`). Bỏ sót nó làm tx bị `out of gas` ngay ở khâu trừ phí.

**Chain private 9000 không có type-2.** Nó chạy trước London, nên tx phải là legacy (type 0) với `gasPrice`, không phải `maxFeePerGas`/`maxPriorityFeePerGas`. Một adapter mặc định type-2 sẽ bị chain từ chối mọi tx. Đây là hệ quả trực tiếp của `TRAPS.md` §"Private chain", và nó phải là một capability flag chứ không phải suy từ `chain_profile` — một chain private khác hoàn toàn có thể có London.

#### 06.2.4. Cancel-by-self-send

Không tồn tại "cancel" trên EVM. Cái gọi là cancel chỉ là một **replacement rẻ hơn**: tx tới chính mình, `value=0`, `data=0x`, `gas=21000`, cùng nonce, phí vượt ngưỡng bump. Dùng khi:

- Job đã bị consumer huỷ, hoặc
- `expiry` của meta-tx đã qua (contract sẽ revert, trả về tiền gas vô ích), hoặc
- Sim gate phát hiện target contract vừa bị đưa vào denylist, hoặc
- **[MỚI]** Job Zether quá `epoch_deadline_block` (§06.3.4), hoặc
- **[MỚI]** Job ở `signed_orphan` (§06.1.4 đường 3) cần được trung hoà.

Chi phí: 21.000 gas. Trên Gnosis ở 2 gwei = 0,000042 xDAI (~$0,00004). Trên Ethereum L1 ở 30 gwei = 0,00063 ETH. **Đừng cancel với một tx đã có khả năng đào thành công** — sẽ trả giá cả hai lần mà không được gì. Quy tắc: cancel chỉ cho tx *chắc chắn sẽ revert*; còn lại thì speed-up.

**[MỚI] Cancel có thể thất bại.** Nếu tx gốc đang ở giá rất cao, cancel phải vượt nó 10% — tức cancel *đắt hơn* tx gốc. Kiểm tra trước: `cancel_cost = 21000 * ceil_bump(prev_max_fee)`. Nếu `cancel_cost > value_at_risk` thì **không cancel**, để tx revert và chỉ mất gas của nó. Ghi quyết định này vào job (`cancel_declined_reason`).

#### 06.2.5. [MỚI] Chi phí L1 data trên rollup — thành phần bị bỏ sót hoàn toàn

`eth_estimateGas` trên một L2 trả về **gas thực thi L2**. Phí thật = `L2_execution_fee + L1_data_fee`. Với một tx Zether calldata ~2 KB, phần L1 thường **chiếm 60–90% tổng chi phí** trên OP Stack khi L1 đông.

| Chain | Cách lấy phí L1 | Ghi chú |
|---|---|---|
| OP Stack (Base, Optimism, Celo) | Predeploy `GasPriceOracle` tại `0x420000000000000000000000000000000000000F`, gọi `getL1Fee(bytes rawTx)` | Từ Ecotone là hàm của `l1BaseFee` + `blobBaseFee`. Phải gọi với **raw tx đã RLP**, không phải calldata |
| Arbitrum Nitro | `NodeInterface` tại `0x00000000000000000000000000000000000000C8`, `gasEstimateComponents(...)` trả `gasEstimateForL1` | Arbitrum gộp phí L1 vào `gas` nhưng phân bổ động; dùng `gasEstimateComponents` để tách |
| Gnosis, Polygon, BSC, chain private 9000 | Không áp dụng | L1 |

Chốt: `est_cost_usd` trong velocity limit (§06.4.3) và trong đánh giá lợi nhuận **phải** gọi lớp này. Adapter EVM có `async def estimate_total_fee(raw_tx) -> (l2_gas, l1_fee_wei)`; adapter cho chain L1 trả `l1_fee_wei = 0`.

Ước tính độ lớn (cơ sở: calldata 2 KB, ~95% byte khác 0):

- Trước EIP-4844: `2048 * 16 = 32.768` L1 gas. @ L1 20 gwei, ETH $3k → **$1,97/tx**.
- Với blob (Ecotone, blob base fee 1 wei — trường hợp thường): gần **$0,001–0,01/tx**.
- Khi blob market đông (blobBaseFee tăng 100–1000x): **$0,1–1/tx**.

Biên độ 1000 lần giữa hai chế độ là lý do breaker trên L2 phải theo dõi **blobBaseFee** như một đại lượng riêng, không chỉ `base_fee` của L2.

Với BLS12-381, calldata của proof gấp đôi (điểm 128 B thay vì 64 B — §01.1.12.1), nên toàn bộ cột chi phí L1 ở trên nhân đôi. Trên một rollup lúc blob đông, đó là chênh lệch $0,1 → $0,2/tx cho **cùng một mức bảo mật gas**. Đây là chi phí thật của việc chọn curve mà bảng gas MSM không hiện ra, và nó rơi vào đúng môi trường (rollup) mà L2 vốn được chọn vì rẻ.

#### 06.2.6. Trạng thái job và nghĩa vụ báo cho consumer
#### 06.2.6. Trạng thái job và nghĩa vụ báo cho consumer

```
draft -> simulated -> nonce_leased -> signed -> broadcast
                                        |         |-> mined -> final          (qua Finality Gate)
                                        |         |-> mined -> reorged        [MOI]
                                        |         |-> underpriced -> replaced [MOI]
                                        |         |-> dropped -> re_broadcast
                                        |         |-> replaced (n lan) -> mined / cancelled
                                        |-> signed_orphan -> replaced / mined  [MOI]
                                        |-> stuck_at_ceiling                   [MOI]
draft/simulated -> rejected (sim fail | breaker | policy | inflight_full)
broadcast/mined -> epoch_expired  (rieng Zether, §06.3.4)
* -> quarantined  (nonce lech, RPC noi doi, divergence lap lai, signed khong co job)
```

**[MỚI] Ánh xạ state → nghĩa vụ tài chính** (đây là chỗ consumer đọc, và là chỗ `_set_done()` được phép chạy):

| State | Consumer được kết luận gì | Được gọi `payment.transaction._set_*` không |
|---|---|---|
| `draft` … `signed` | Chưa có gì trên chain | Không |
| `broadcast` | Đã gửi. **KHÔNG phải đã thanh toán** | `_set_pending()` |
| `mined` | Đã vào một block. Vẫn có thể bị đảo ngược | `_set_pending()` — **vẫn là pending** |
| `final` | Qua Finality Gate | `_set_done()` — **trạng thái duy nhất** |
| `reorged` | Đã từng `mined`, bị đảo ngược | Giữ `_set_pending()`, retry hoặc `_set_error()` |
| `cancelled`, `rejected`, `epoch_expired` | Không xảy ra trên chain | `_set_canceled()` |
| `quarantined`, `stuck_at_ceiling` | **Không xác định** | Không gọi gì. Người phải vào xem |

`final` là trạng thái **duy nhất** được phép báo cho consumer là tiền đã chuyển. Đây là nguyên tắc `dms_vietqr` dịch sang on-chain: **broadcast không phải là đã thanh toán; mined cũng chưa phải**. Consumer nào gọi `_set_done()` tại `broadcast` là một bug tài chính. `quarantined` là trạng thái *không xác định* — bug nguy hiểm thứ hai là ánh xạ nó thành `_set_error()` rồi cho consumer retry, vì tx có thể vẫn đào sau đó.

Bảng này khớp với state machine hợp nhất của §05.8.1 nhưng **không** giống hệt: §05 mô tả vòng đời của một *intent* trên bus (có `published`, `claimed`, `queued`), §06 mô tả vòng đời của một *job broadcast* trong pool. Một intent có thể sinh ra nhiều job (retry, replacement); một job không bao giờ thuộc hai intent. Hai bảng, hai model (`blockchain.metatx` và `blockchain.relay.job`), và **đừng hợp nhất chúng** — chúng có vòng đời khác nhau và gộp lại sẽ tạo ra một state machine 20 trạng thái mà không ai đọc nổi.

---

### 06.3. Simulation gate bắt buộc

| Chuỗi | Lời gọi | Trả về gì dùng được | Buffer gas đề xuất |
|---|---|---|---|
| EVM | `eth_call` (pin `blockHash`, không pin `blockNumber`) → `eth_estimateGas` → `getL1Fee` (§06.2.5) → tuỳ chọn `debug_traceCall` | revert reason, gas, state diff, logs | **1,25x** bình thường; **1,6x** cho Zether; **2,0x** khi có `SLOAD` cold chưa rõ |
| SUI | `sui_devInspectTransactionBlock` (không tốn gas, không cần gas coin hợp lệ) và `sui_dryRunTransactionBlock` (cần gas coin thật) | effects, kết quả từng lệnh PTB | budget = `computationCost + storageCost − storageRebate`, ×1,3 |
| Soroban | `simulateTransaction` | CPU/mem instructions, **footprint bắt buộc**, resource fee, auth entries | Bắt buộc dùng kết quả sim; không thể đoán footprint. ×1,15 trên resource fee |
| Cosmos WASM | `POST /cosmos/tx/v1beta1/simulate` | `gas_used` | ×1,4 (mặc định cosmjs là 1,3; WASM biến thiên mạnh hơn) |
| TON | `ton-emulator` cục bộ trên state snapshot | cell tree, phí forward nanoTON | Cộng 0,05 TON dự phòng cho chain message |
| Hedera | SDK dry-run / `contractCallLocal` | gas, revert | ×1,2; phí neo USD nên ít biến động |

**[SỬA] Ghim bằng `blockHash`, không bằng `blockNumber`.** `eth_call` với `{"blockNumber": "0x..."}` vẫn có thể bị một provider trả lời trên một nhánh khác sau reorg. `{"blockHash": "0x..."}` là xác định. Mọi provider hiện đại đều hỗ trợ; provider nào không hỗ trợ thì không dùng cho sim.

#### 06.3.1. Sim phải bị ghim state

Kết quả sim chỉ đúng tại block N. Ghi `sim_block_hash` + `sim_block_height` vào job; nếu tại thời điểm broadcast `head − sim_block_height > max_sim_staleness` (EVM: 5 block; Sui: 10s; Soroban: 2 ledger) thì **sim lại**, không broadcast. Không làm việc này thì sim gate chỉ là trang trí.

**[MỚI] Sim lại không được miễn phí vô hạn.** Tối đa 3 lần sim cho một job; lần thứ 4 → `rejected(reason='sim_thrash')`. Một job phải sim lại 4 lần là một job đang chạy đua với state của chính nó; retry thêm chỉ đốt RPC quota.

#### 06.3.2. "Tỷ lệ revert 0%" là không đạt được

Sim đọc state tại N, tx thực thi tại N+k với state đã đổi. Note §14.2.8 yêu cầu "tỷ lệ revert bằng 0%" — đó là một mục tiêu không thể đạt, và nguy hiểm hơn là nó khiến người ta **bỏ qua việc đo lường**. Các nguồn divergence thật:

| Nguyên nhân | Ví dụ cụ thể | Xử lý |
|---|---|---|
| State drift | ERC-20 `allowance` bị tiêu bởi tx khác của cùng user | Sim lại + `expiry` ngắn (5 phút) |
| **Zether epoch rollover** | Proof dùng `simulateAccounts(addrs, e)`; tx đào ở epoch `e+1` → ciphertext lệch → revert | §06.3.4, nguồn divergence lớn nhất |
| `meta_nonce` bị tiêu | Tx khác của cùng user trên cùng `batchId` | Ghim `meta_nonce_block` (§06.1.8) |
| Sui shared object contention | Hai PTB cùng chạm shared object → một cái bị huỷ | Retry với backoff, không tính là divergence |
| Soroban footprint sai | State đổi làm footprint mở rộng → `ExceededLimit` | Bắt buộc re-simulate, không reuse |
| Gas underestimate | `estimateGas` chạy trên nhánh rẻ hơn (storage slot đang zero lúc sim, non-zero lúc thực thi: 20k vs 5k gas — chênh 15k/slot) | Buffer ở bảng trên |
| Cosmos gas multiplier thấp | Contract có vòng lặp phụ thuộc số item | ×1,4 |
| **[MỚI]** Access list thiếu | Tx type-1/2 có `accessList` sinh từ sim; state đổi làm slot ngoài list → cold access đắt hơn | Chỉ dùng `accessList` khi tiết kiệm > 10%; buffer 2,0x khi dùng |
| **[MỚI]** Block gas limit | Tx 1,79M gas trên chain giới hạn `eth_call` ở 10M vẫn pass sim nhưng bị từ chối khi vào block cùng block khác | Guard `gas * buffer < block_gas_limit * 0.4` |

Hàng cuối có một con số cụ thể đáng ghi: với chain private 9000 (`gasLimit` 16,7M), guard 40% cho phép **6,7M gas/tx** — thừa cho một Zether Bulletproofs 1,79M, nhưng **không** thừa nếu ai đó chọn ring size lớn (§05.3.2: ring 16 là ~7,2M). Guard này là thứ chặn một token cấu hình sai làm nghẽn cả block.

SLO thực tế đề xuất: **divergence rate < 0,5% trên tổng số broadcast, < 0,05% cho lớp R3/R4**. Vượt ngưỡng 20 divergence/giờ trên cùng một `target_address` → **auto-quarantine contract đó** (`blockchain.target.policy.state = 'quarantined'`), dừng nhận job mới tới nó, tạo `blockchain.breaker.event` và page on-call. Lý do quarantine theo contract chứ không theo chain: divergence tập trung một contract gần như luôn là bug contract hoặc bug ABI, không phải sự cố mạng.

Trên factory mở, quy tắc này còn cần hơn: pool sẽ gặp token của người lạ, và một token v-nào-đó cấu hình sai là chuyện bình thường chứ không phải sự cố. Quarantine theo `target_address` là cách cô lập nó mà không dừng cả chain.

**[MỚI] Quy trình khi sim và thực thi bất đồng** (brief hỏi thẳng câu này):

```
1. Bat receipt.status == 0 (hoac Cosmos code != 0, Sui effects.status.error, ...)
2. Lay lai revert reason THAT: debug_traceCall tren block DA DAO, voi
   stateOverrides = {} va blockHash = mined_block_hash.  (Khong dung Tenderly o buoc nay:
   ta can state cua chinh chain, khong phai fork.)
3. So sanh voi sim_trace da luu. Phan loai vao 9 nhom tren.
4. Ghi blockchain.sim.divergence(job_id, category, sim_gas, actual_gas,
                                sim_block_hash, mined_block_hash, revert_selector)
5. Quyet dinh:
   - category in (state_drift, meta_nonce, sui_contention) -> retry toi da 2 lan, sim lai
   - category in (footprint, gas_underestimate)            -> retry 1 lan voi buffer x2
   - category in (zether_epoch)                            -> KHONG retry, tra consumer (§06.3.4)
   - category == unknown                                    -> KHONG retry, quarantine target
6. Job den lan retry thu 3 -> 'rejected', tra consumer voi toan bo trace. Relay pool
   khong duoc phep retry vo han mot thu no khong hieu.
```

Điểm quan trọng: **`unknown` không bao giờ được retry.** Retry một thứ ta không phân loại được là cách đốt tiền nhanh nhất mà vẫn tin là mình đang "tự phục hồi".

#### 06.3.3. [MỚI] Policy gate: allowlist phải theo `(address, selector)`, không chỉ theo address

Note nói "Target Contract Allowlist". Chưa đủ: một contract có `transfer()` vô hại và `upgradeTo()` chết người. Model:

```python
class BlockchainTargetPolicy(models.Model):
    _name = 'blockchain.target.policy'
    _description = 'Allowlist entry: chain + contract + function selector + limits'

    chain_id        = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    target_address  = fields.Char(required=True, index=True, size=42)
    selector_hex    = fields.Char(required=True, size=10, help='0x + 8 hex. "0x*" = moi selector.')
    risk_class      = fields.Selection([('r1','R1'), ('r2','R2'), ('r3','R3'), ('r4','R4')],
                                       required=True, default='r2')
    max_value_base  = fields.Char(default='0', help='Gia tri native toi da, base units, chuoi thap phan.')
    max_gas         = fields.Integer(required=True, default=1_000_000)
    daily_call_cap  = fields.Integer(required=True, default=10_000)
    state           = fields.Selection([('draft','Draft'), ('active','Active'),
                                        ('quarantined','Quarantined'), ('denied','Denied')],
                                       required=True, default='draft', index=True)
    company_id      = fields.Many2one('res.company', index=True)

    _unique_target = models.Constraint(
        'UNIQUE(chain_id, target_address, selector_hex, company_id)',
        'Mot (chain, contract, selector, company) chi co mot chinh sach.')
    _check_selector = models.Constraint(
        "CHECK (selector_hex = '0x*' OR selector_hex ~ '^0x[0-9a-f]{8}$')",
        'Selector phai la 0x + 8 hex lowercase, hoac 0x*.')
```

Mặc định **deny**. Một job có `calldata_hex` mà 4 byte đầu không khớp entry `active` nào → `rejected(reason='selector_not_allowed')`. Entry `0x*` chỉ được tạo bởi `group_blockchain_manager` và bị ghi vào audit log — nó là một ngoại lệ, không phải một tiện ích.

`blockchain.target.policy` là **cùng một khái niệm** với acceptance policy của node mesh (`_USER-DECISIONS.md` §21.4), nhìn từ phía doanh nghiệp: cả hai đều là một bảng tra `(chain, contract, selector) → chấp nhận hay không`, đọc được trước khi simulate. Khác nhau ở mục đích — bên này là **kiểm soát rủi ro** (đừng ký thứ ta không hiểu), bên kia là **định tuyến kinh tế** (việc này có phải của tôi không). Cùng cấu trúc dữ liệu, hai cột chính sách. Đừng cài hai lần.

#### 06.3.4. Zether: sim gate phải có ràng buộc epoch — note bỏ trống hoàn toàn

`simulateAccounts(schnorrAddresses, epoch)` (§10.5.3) trả `(C, D)` sau khi gộp `pending_transfers` tại epoch mục tiêu. Proof được dựng *cho epoch đó*. Nhưng không có gì trong note đảm bảo tx đào đúng epoch đó. Với `Δ = 5 block` trên Gnosis = 25s, một tx bị trễ 25s là proof vô hiệu.

Chốt: job Zether mang thêm

- `zether_target_epoch` (Integer) — epoch proof được dựng cho,
- `zether_epoch_deadline_block` (Integer) = `(target_epoch + 1) * Δ - safety_margin`, với `safety_margin = 1` block.

Trước broadcast: `require head < epoch_deadline_block`. Sau broadcast, nếu chưa mined khi `head >= epoch_deadline_block` → **không speed-up mà cancel** (self-send) và trả job về consumer với `state='epoch_expired'` để dựng proof mới. Speed-up một tx Zether quá hạn epoch là đốt tiền vào một tx chắc chắn revert.

Hệ quả về chính sách phí: lớp Zether **luôn ưu tiên tip cao ngay từ lần đầu** (một lần đào đắt hơn hai lần revert). Cụ thể: `zether_initial_tip = p90(tip, 20 block)` thay vì `p50` của lớp khác. **[MỚI]** Và vì cửa sổ chỉ còn `Δ * block_time − sim_time − sign_time`, trên Gnosis là `25 − 0,3 − 0,8 ≈ 23,9s` (~4,8 block), **không còn chỗ cho một chu kỳ bump nào**. Nếu MPC ký mất 3s p99, cửa sổ còn ~4,4 block. Đó là lý do kỹ thuật trực tiếp để đưa Zether lên enclave signer (§06.6), không chỉ là lý do throughput.

Ràng buộc này là lý do độc lập thứ hai để **Zether không dùng soft-exclusivity** (§05.1.1 đã kết luận `W = 0` từ phía ngân sách latency của intent bus). Hai section, hai đường suy luận, cùng một kết luận — và khi hai đường độc lập gặp nhau ở cùng một chỗ thì đó là dấu hiệu kết luận đúng.

Trên chain private 9000, cửa sổ này rộng hơn nhiều vì `MinGasPrice = 0` nên không có ai cạnh tranh block space, và không có bump để mà lo. Đây là một trong những lý do cụ thể nhất khiến quyết định #5 (Zether chạy private trước) là đúng.

**[MỚI] Verify proof off-chain trước khi ký.** Một tx Zether 1,79M gas trên `eth_call` mất 200–600 ms CPU của provider và nhiều provider **cap gas của `eth_call`** (Alchemy/Infura thường 10M–50M, một số gói thấp hơn). Chéo: verify Bulletproof bằng thư viện Rust cục bộ mất **5–12 ms** (cơ sở: `dalek-cryptography/bulletproofs` verify n=64, m=1 ~1,5 ms trên x86 hiện đại; n=512 tổng bit ~8x → ~12 ms). Chốt pipeline Zether: `verify_offchain (10ms) → eth_call đầy đủ (300ms) → estimateGas`. Nếu verify off-chain fail thì không tốn một RPC call nào.

#### 06.3.5. [MỚI] Chi phí của chính sim gate

| Công cụ | Đơn giá | Ở 24.000 tx/ngày (720k/tháng) | Kết luận |
|---|---|---|---|
| `eth_call` + `eth_estimateGas` trên node tự vận hành | ~0 biến phí | ~$200/tháng (amortize node) | **Mặc định** |
| `eth_call` trên RPC managed (Alchemy/QuickNode) | tính theo compute unit; `eth_call` nặng gấp ~5–25x `eth_blockNumber` | Vượt gói growth, rơi vào bậc enterprise | Chỉ dùng làm fallback |
| Tenderly Simulation API | gọi theo đơn vị; free tier ~50k đơn vị/tháng | 720k đơn vị/tháng → **bậc trả phí cao** | **Không dùng trong hot path** |

Chốt: **Tenderly chỉ dùng cho hậu kiểm (post-mortem) một divergence**, không nằm trong đường broadcast. Bản nháp đầu và note đều để Tenderly ở hot path — ở quy mô 24k tx/ngày đó là một dòng chi phí không ai dự toán. Hot path dùng `eth_call` + `debug_traceCall` trên archive node của chính mình.

Với chain private 9000, cả bảng này biến mất: node là của ta, `eth_call` miễn phí, và không có provider nào để mà vượt quota. Chi phí sim gate là một chi phí của giai đoạn public.

---

### 06.4. Gas circuit breakers

#### 06.4.1. Spike breaker — "300% của trung bình 1h" cần sửa thống kê

Trung bình (mean) bị kéo bởi đúng một block spike; dùng mean thì breaker vừa nhạy lại vừa trễ. Dùng:

```
ref  = rolling_median(base_fee, window = 1h)      # Gnosis: 720 block; L1: 300 block
mad  = median(|base_fee_i - ref|)
trip     khi  base_fee_next > max(3.0 * ref, ref + 6 * mad)
reset    khi  base_fee_next < 1.5 * ref  lien tuc 20 block      # hysteresis
```

Hysteresis là bắt buộc. Không có nó, breaker flapping quanh ngưỡng 3,0x sẽ tạo ra chính xác cái kiểu tải bùng nhịp làm mạng tệ hơn.

**[MỚI] Cửa sổ 1h cần được mồi lúc khởi động.** Khi service vừa lên, chưa có 720 mẫu. Chính sách: dùng `fee_history` của RPC để nạp 1024 block gần nhất ngay ở bước khởi động (một lời gọi `eth_feeHistory(1024, 'latest', [10,50,75,90])`); trước khi có >= 200 mẫu, breaker ở chế độ **fail-closed cho R1/R2** (không chạy job deferrable) và fail-open cho R3/R4.

**[MỚI] Breaker phải có trạng thái `half_open`.** Khi reset điều kiện được thoả, không mở hoàn toàn ngay: cho qua 10% lưu lượng trong 5 phút, đo divergence và chi phí thực, rồi mới mở. `relay_breaker_state` là Gauge 0/1/2 đúng nghĩa closed/half/open.

Breaker phải đo **hai** đại lượng trên chain có native token biến động:

| Chain | Đại lượng theo dõi | Ghi chú |
|---|---|---|
| Gnosis xDAI | `base_fee` (xDAI) — một chiều là đủ | xDAI neo USD, chi phí USD = gas × price trực tiếp |
| Celo (L2) | `base_fee` theo `feeCurrency` (cUSD/USDC) **VÀ** `l1_blob_base_fee` | **[SỬA]** Sau khi thành OP Stack, phí L1 là một chiều độc lập (§06.2.5) |
| Base / Optimism | `base_fee` (ETH) **VÀ** `l1_blob_base_fee` **VÀ** `native_price_usd` | Ba chiều |
| Ethereum/Polygon/BSC | `base_fee` **VÀ** `native_price_usd` | Gas 30 gwei ở ETH $2k khác hẳn ở ETH $8k. Breaker phải trip theo **USD/tx** |
| **Chain private 9000** | **Không có `base_fee` để mà đo** | Chain chạy trước London: không EIP-1559, `MinGasPrice = 0`. Tắt spike breaker; vẫn cần velocity limit **tính bằng gas** |

Hàng cuối sửa so với bản 1 ("chain riêng PoA/IBFT — gas tĩnh"). Nó không chỉ tĩnh: **`eth_feeHistory` và `base_fee_next_block()` sẽ ném lỗi hoặc trả rác** trên chain đó, nên breaker không phải "tắt logic" mà là "không được gọi hàm đó". Guard theo capability (`chain.supports_eip1559`), không theo `chain_profile` — một chain private khác hoàn toàn có thể có EIP-1559.

Đây là lý do kỹ thuật cứng cho thứ tự chain đã khoá (Gnosis trước, Celo sau): trên Gnosis, breaker chỉ cần một chiều đo và ngưỡng tính bằng USD là con số thật, không phải ước lượng. **[SỬA]** Celo sau khi thành L2 **không** còn đơn giản như vậy — nó cần ba chiều đo; đó là một lý do bổ sung để Gnosis đi trước, không chỉ là thứ tự tuỳ ý.

#### 06.4.2. [MỚI] Giá native token: nguồn, độ trễ, và chính sách fail

Velocity limit tính bằng USD → phải có giá. Chưa ai nói lấy ở đâu.

| Chain | Nguồn giá | Độ trễ chấp nhận |
|---|---|---|
| Gnosis (xDAI) | Hằng số 1,00 USD, **có cảnh báo depeg**: đọc Chainlink DAI/USD trên Ethereum mỗi 15 phút; lệch > 2% → breaker `PEG_BROKEN` | 15 phút |
| Celo (cUSD) | Tương tự, `SortedOracles` on-chain của Celo | 15 phút |
| ETH/MATIC/BNB | Chainlink price feed on-chain trên chính chain đó (không dùng REST của sàn) | 5 phút |
| Chain private | Không áp dụng — velocity tính bằng gas | — |

Chính sách khi giá stale (`age > 2 * max_age`): **fail-closed với giá bảo thủ** — dùng `price_usd = last_known * 3` cho mọi tính toán chi phí. Không dùng `last_known` (đánh giá thấp rủi ro) và không chặn hết (dừng dịch vụ vì một oracle chết là phản ứng quá mức). Con số 3x là một lựa chọn, ghi vào `blockchain.chain.stale_price_multiplier`, chỉnh được.

#### 06.4.3. [BẢN 3] Velocity limit: nguyên tử, số nguyên, có refund — và không Lua

Bản nháp đầu dùng `INCRBYFLOAT` rồi kiểm tra riêng. Hai bug:

1. **TOCTOU**: đọc → so sánh → ghi không nguyên tử. Với 50 job/s song song, bucket vượt trần rồi mới bị
   phát hiện. Vượt bao nhiêu thì tuỳ may.
2. **Float**: `INCRBYFLOAT` trên hàng trăm nghìn thao tác tích luỹ sai số. Bucket tiền không được dùng float.

Bản 2 chữa hai bug đó bằng một Lua script trên Redis. **Bản 3 bỏ Redis (`_USER-DECISIONS.md` §23), nên chữa bằng thứ vốn đã
có transaction thật: Postgres.** Cùng ngữ nghĩa — đơn vị **micro-USD số nguyên**, reserve trước, settle
sau — nhưng nguyên tử là do `BEGIN ... COMMIT` chứ không do một script chạy đơn luồng.

```sql
CREATE TABLE blockchain_spend_bucket (
    scope       text   NOT NULL,          -- 'agent' | 'tenant' | 'global'
    scope_key   text   NOT NULL,          -- agent_id | company_id | ''
    window_key  text   NOT NULL,          -- 'YYYYMMDDHH'
    spent_uusd  bigint NOT NULL DEFAULT 0,-- micro-USD, SO NGUYEN
    PRIMARY KEY (scope, scope_key, window_key)
);

CREATE TABLE blockchain_spend_reservation (
    job_uuid      uuid   PRIMARY KEY,
    window_key    text   NOT NULL,
    reserved_uusd bigint NOT NULL,
    reserved_at   timestamptz NOT NULL DEFAULT now()
);
```

Reserve là **một** transaction, và `UPDATE ... RETURNING` với điều kiện trần làm việc kiểm tra và việc
ghi trở thành cùng một thao tác — đúng cái Lua script được thuê để làm:

```sql
BEGIN;
-- Ba dong, khoa theo thu tu co dinh (agent -> tenant -> global) de khong deadlock.
UPDATE blockchain_spend_bucket SET spent_uusd = spent_uusd + :cost
 WHERE scope='agent'  AND scope_key=:agent  AND window_key=:w
   AND spent_uusd + :cost <= :cap_agent   RETURNING spent_uusd;
-- khong co dong tra ve  ->  vuot tran  ->  ROLLBACK, tra ly do 'agent'
... lap lai cho tenant, global ...
INSERT INTO blockchain_spend_reservation(job_uuid, window_key, reserved_uusd)
VALUES (:job, :w, :cost);
COMMIT;
```

Ba điểm phải giữ đúng:

- **Thứ tự khoá cố định** `agent → tenant → global`. Hai job khoá ngược chiều nhau là deadlock, và
  Postgres sẽ giết một trong hai — đúng về an toàn, tệ về vận hành. Thứ tự cố định thì không bao giờ xảy ra.
- **`bigint`, không `numeric`, không `float`.** Micro-USD trong `bigint` cho trần 9.2e12 USD; đủ.
- **Row-level lock chỉ giữ trong một transaction ngắn.** Không có lời gọi mạng nào bên trong. Nếu ai đó
  đặt `eth_estimateGas` vào giữa `BEGIN` và `COMMIT`, hàng `global` thành một điểm serialize toàn hệ thống.

Kiểm tra **trước khi lease nonce** (không phải trước sim — sim gần như miễn phí trên node của mình, lease
thì không): `est_cost_uusd = (l2_gas * buffer * gas_price + l1_fee_wei) * native_price_usd * 1e6 / 1e18`.

Trên chain private 9000 (`MinGasPrice = 0`), `est_cost_uusd` luôn bằng 0 và velocity limit tính bằng USD
trở nên vô nghĩa. Nhưng **vẫn phải có velocity limit** — tính bằng **gas**, vì cái nó chặn không phải chi
phí mà là một vòng lặp chạy loạn làm ngập block. Hai đơn vị, cùng một cơ chế, chọn theo `chain_profile`.

- Khi job kết thúc (`final` hoặc `rejected`), **settle**: một `UPDATE` cộng phần chênh giữa reserved và
  thực tế (âm nếu rẻ hơn), rồi `DELETE` reservation. Cùng transaction.
- Janitor mỗi 5 phút quét `blockchain_spend_reservation` của cửa sổ *trước*; entry còn lại quá 2 giờ →
  refund và ghi `relay_spend_reservation_leaked_total`.
- Cửa sổ cũ hơn 2 giờ bị `DELETE` bởi cùng janitor. Đây là thứ thay cho `EXPIRE` của Redis, và nó là một
  dòng cron chứ không phải một tính năng của store.

Chi phí: một transaction Postgres ~0,3–0,8 ms trên cùng máy. Cùng bậc với round-trip Redis mà bản 2 tính
(~0,2 ms), và đổi lại là **một hệ thống lưu trữ ít hơn phải vận hành, backup, và giải thích khi nó mất
một giây ghi.**

#### 06.4.4. Thứ tự bị throttle — lớp ưu tiên

Note nói "R1/R2 bị đình chỉ, giữ R3". Bảng lớp đầy đủ, và có một điều note bỏ sót: **một số traffic bảo trì thật ra là R4**.

| Lớp | Nội dung | Hành vi khi breaker trip | Deferrable |
|---|---|---|---|
| **R1** | Anchoring hash audit, proof-of-action, batch merkle root | Dừng ngay, gom vào batch lớn hơn, phát lại khi reset | Vô hạn (gom 24h vẫn đúng) |
| **R2** | Loyalty point accrual, cập nhật metadata, index refresh | Dừng, hàng đợi giữ tới 6h | Hàng giờ |
| **R3** | B2B settlement, `withdraw` Zether, thanh toán end-user | Giảm throughput 50%, chỉ qua nếu `est_cost_usd < value * 0.5%` | Hàng phút |
| **R4** | Refill hot wallet, Zether `rollOver`, Soroban `extend_ttl`, unwind rủi ro thanh khoản, cancel tx độc, **gap-filler**, **replacement của job R3 đang inflight** | **Không bao giờ throttle** | Không |

`rollOver()` và `extend_ttl` bị xếp nhầm vào "bảo trì định kỳ" là một bẫy. Throttle `rollOver` làm đóng băng số dư khả dụng của **mọi** người dùng Zether; throttle `extend_ttl` trên Soroban làm **mất state contract** khi TTL hết. Chúng là R4.

Với `rollOver` có một sắc thái mà `_USER-DECISIONS.md` §13.3 làm rõ: trong code Zether thật, `rollOver` là `internal` và **được gọi ngầm** ở đầu mọi thao tác chạm tài khoản, nên nó không phải một job riêng để mà throttle. Cái cần xếp R4 là hàm **`rollOverPublic`/`rollOverBatch`** (§01) — thứ tồn tại để một tài khoản nhận tiền rồi im lặng vẫn được dọn pending. Nó hiếm, rẻ, và chặn nó là để tiền kẹt. **[BẢN 5, 2026-09-03]** `rollOverPublic` là **đường mặc định** của mọi tài khoản; tài khoản `OWNER_ONLY` (R3/R4, §C5 [BẢN 5]) đi qua `rollOverSigned` và job của nó mang một blob do custody ký — hai đường khác nhau về giá batch, cùng một lớp rủi ro.

**[MỚI]** Thêm hai mục vào R4 mà bản nháp đầu bỏ sót: gap-filler (throttle nó = để nguyên lỗ thủng = chặn toàn bộ account) và replacement của một job R3 **đã broadcast** (throttle nó = để tiền treo giữa đường). Quy tắc tổng quát: **không bao giờ throttle một hành động mà mục đích là gỡ kẹt một hành động trước đó.** Breaker chặn *đầu vào*, không chặn *lối thoát*.

Ngưỡng cảnh báo: 90% → thông báo (Odoo activity + webhook), 100% → chặn lớp <= R3. R4 vượt trần cần `blockchain.breaker.override` (record có `approver_uid`, `override_expiry`, `reason`, chỉ group `blockchain_treasury_manager` tạo được) — không có biến môi trường nào bypass được.

#### 06.4.5. [SỬA] Kích thước thật: Zether trên EVM công khai

Note viết ZKP verify "~180.000 – 250.000 gas". **Con số này có hình dạng của một verifier Groth16, không phải của Bulletproofs.** Groth16 trên alt_bn128 = 3 pairing + vài `ecMul`: `45.000 + 3*34.000 + ~10 * 6.000 ≈ 207.000 gas`. Khớp hoàn hảo với con số của note. Nhưng note **cũng** nói dùng Bulletproofs (§10.5.2 mục 3, và `zkpProof` trong `EncryptedTransfer`). Hai thứ không thể cùng đúng.

Số học cho Bulletproofs (cơ sở: EIP-1108 định giá lại `ecAdd` = 150, `ecMul` = 6.000 gas; **không** phải EIP-196 như bản nháp đầu ghi — EIP-196 gốc là 500/40.000, EIP-1108 mới hạ xuống):

```
Verify mot aggregated Bulletproof, m statement, n bit moi statement:
  kich thuoc MSM = 2*m*n + 2*log2(m*n) + ~7 diem
Voi precompile alt_bn128 khong co MSM san, chi phi ~ (so diem) * 6.000 gas
```

| Cấu hình | m×n bit | MSM (điểm) | Gas MSM | + Sigma + calldata + keccak | **Tổng ước tính** |
|---|---|---|---|---|---|
| ConsenSys gốc, n=32, m=2 | 64 | 141 | 0,85M | ~0,25M | **~1,1M** |
| Note đề xuất, n=128, m=2 (`v`, `b−v`) | 256 | 528 | 3,17M | ~0,3M | **~3,5M** |
| Note + fee, n=128, m=3→pad 4 | 512 | 1.049 | 6,29M | ~0,35M | **~6,6M** |
| **Đề xuất: n=64, m=3→pad 4** | 256 | 528 | 3,17M | ~0,3M | **~3,5M** |
| Groth16 thay Bulletproofs | — | — | — | — | **~0,21M** |

**Bản nháp đầu ước 2,0–2,5M — thấp hơn thực tế khi tính cả fee proof.** Cơ chế phí bảo mật của note (§10.5.3 mục 5: `fee >= 0`, `v >= 0`, `b−fee >= 0`, `b−fee−v >= 0`) cần **ba** range statement độc lập, aggregate phải pad lên bốn → 512 bit → ~6,6M gas.

Hệ quả trên Gnosis (block gas limit 17M):

| Chỉ số | n=128 + fee (~6,6M) | n=64 + fee (~3,5M) | Groth16 (~0,21M) |
|---|---|---|---|
| tx/block tối đa (17M) | 2 | 4 | 80 |
| tx/block thực tế (20% block space, 3,4M) | 0,5 | ~1 | 16 |
| **tx/ngày (block 5s)** | **~8.600** | **~17.000** | **~276.000** |
| Chi phí @ 2 gwei | 0,0132 xDAI ≈ $0,013 | 0,007 xDAI ≈ $0,007 | 0,0004 ≈ $0,0004 |
| Cùng tx trên Ethereum L1 @ 25 gwei, ETH $3k | **$495** | **$263** | **$16** |
| Thời gian prove (Rust, x86) | ~120 ms | ~60 ms | ~800 ms (Groth16 prove đắt) |
| Thời gian prove (WASM/mobile) | ~2–4 s | ~1–2 s | ~15–30 s |
| Trusted setup | Không | Không | **Có (per-circuit)** |

**Đề xuất cụ thể, cần người duyệt:** hạ range từ 128 xuống **64 bit** bằng cách cho Zether token dùng **6 decimals nội bộ** thay vì 18. `2^64 ≈ 1,8e19`; với 6 decimals đó là **18 nghìn tỷ đơn vị tiền** — thừa cho mọi giao dịch B2B tưởng tượng được. Note bác 32 bit vì `2^32` wei @ 18 decimals là $0,0000000043 — lập luận đó đúng, nhưng kết luận "vậy thì lên 128 bit" bỏ qua ràng buộc *scale*, không phải ràng buộc *bit*. Đổi lại: gas giảm ~47%, prove nhanh gấp đôi trên mobile (đây là yếu tố quyết định cho luồng "end-user payment tại quầy" của §07), và **dust dưới 10^-6 không thể chuyển bảo mật** — `deposit` phải từ chối số tiền không chia hết cho `10^12`, hoặc giữ phần dư ở số dư công khai. Đó là một điều khoản sản phẩm, phải chốt với người làm nghiệp vụ.

Đề xuất này **đã được §01.1.8 và §03 chốt theo một đường khác và mạnh hơn**: `decimals` là tham số per-token đặt trong `initialize()`, `SHIELD_SCALE` tách khỏi `decimals`, và ràng buộc thật là `maxSupply / SHIELD_SCALE <= MAX_DECRYPTABLE_SHIELDED` với mặc định `2^44`. Đọc §01.1.8 làm nguồn; mục này chỉ cần nhớ **hệ quả gas** của lựa chọn đó.

Một con số để đối chiếu quy mô DMS: 2.000 salesman × 30 visit/ngày = **60.000 sự kiện/ngày** — vượt trần Gnosis ở **mọi** cấu hình Bulletproofs. Kết luận bắt buộc: không bao giờ đưa từng sự kiện nghiệp vụ lên chain. R1 anchoring gộp Merkle root (1 tx/giờ/tenant), R2/R3 chỉ lên chain ở cấp chứng từ tiền tệ.

Và con số này xác nhận quyết định đã khoá của user (private chain trước cho Zether) là đúng về kỹ thuật, không chỉ về chi phí. **Nhưng với một điều chỉnh so với bản 1:** bản 1 đề nghị đặt block gas limit private ở **100M** cho ~14 tx Zether/block. Chain private thật hiện ở **16,7M** (§01.1.16), tức ngang Gnosis, tức **~4 tx Zether/block** ở cấu hình n=64. Nâng được bằng signer vote không cần reset chain — nhưng nó là một việc phải làm, không phải một điều kiện có sẵn. Và trần thật ở đó không phải gas mà là **CPU validator, ~45 confidential tx/s** (§01.1.12.2).

**Chốt con số cho policy** (cho đến khi có benchmark Foundry thật, §06.12 mục 4):
`blockchain.chain.max_gas_per_tx` = 8.000.000 trên chain private (sau khi nâng gasLimit), 3.500.000 trên Gnosis (tức **chỉ cho phép cấu hình n=64**). Nếu contract deploy với n=128, Gnosis bị tắt cho Zether transfer và chỉ còn `deposit`/`withdraw`.

Trên factory mở, `max_gas_per_tx` là một **chính sách của pool**, không phải một giới hạn của protocol: ai đó deploy một token ring-16 tốn 7,2M gas là quyền của họ, và pool của ta đơn giản từ chối relay nó trên Gnosis. Đó là cùng cơ chế `blockchain.target.policy` ở §06.3.3.

---

### 06.5. Hot wallet: số dư, refill, và gas coin

Mô hình 3 ngưỡng trên `blockchain.relayer.account`:

```
low_watermark    = expected_tx_per_hour * avg_gas * p90_gas_price * refill_lead_hours
target_balance   = low_watermark * 3
high_watermark   = low_watermark * 6        # vuot -> sweep ve treasury
```

`refill_lead_hours = 4` (đủ để một người trực tỉnh dậy xử lý manual nếu automation hỏng). Ví dụ Gnosis, 500 tx/h, 2,5M gas, 2 gwei: `500 * 2,5e6 * 2e-9 = 2,5 xDAI/h` → low = 10 xDAI, target = 30, high = 60. Số tiền nhỏ là cố ý: **ví hot không bao giờ giữ quá vài giờ runway**. Rủi ro mất khoá hot được giới hạn bằng số dư, không bằng độ mạnh của custody.

Đây chính là nguyên tắc mà `_USER-DECISIONS.md` §21.5 phát biểu ở dạng tổng quát: **khoá ký chỉ được phép làm đúng một việc — trả gas.** Với pool N khoá, công thức trên áp cho **từng khoá**, nên `low_watermark` mỗi khoá nhỏ hơn N lần và tổng vốn nằm chết không tăng. Điều tăng lên là số lần refill, và đó là lý do treasury phải nạp theo lô chứ không từng khoá một.

Refill: cron Odoo 5 phút gọi `model._cron_relayer_refill_scan()`, tạo `blockchain.refill.request` khi `balance < low`. Refill được ký bởi **treasury signer (HSM FIPS 140-2 L3, 2-of-3)** — đây mới là chỗ bắt buộc HSM, không phải ví relayer (xem §06.6). Tự động trả về `low → target` nếu `amount < auto_refill_cap_usd` (mặc định $500); vượt thì cần approve tay.

**[MỚI] Chống vòng lặp refill.** Nếu balance không tăng sau khi refill (tx refill bị treo, hoặc địa chỉ sai), scan tiếp sẽ tạo thêm request. Guard: tối đa **1 request `pending` mỗi account**, và `_unique_pending_refill` bằng partial unique index:

```python
_unique_pending_refill = models.Constraint(
    'UNIQUE (relayer_account_id) WHERE state IN (\'draft\',\'approved\',\'broadcast\')',
    'Moi relayer account chi co mot yeu cau refill dang xu ly.')
```

**[MỚI] `balance_native` không được là `Float`.** §10.4.1 đã chốt: `uint256` không vừa vào `fields.Float` (mất chính xác từ 2^53; 1 ETH = 1e18 wei). Bản nháp đầu viết `fields.Float(digits=(24,8))` — mâu thuẫn với §10 và mất chính xác ở wei. Sửa:

```python
balance_native_base = fields.Char(readonly=True, help='So du native, base units (wei), chuoi thap phan.')
balance_native_ui   = fields.Float(digits=(18, 6), readonly=True, help='Chi de hien thi/sort. Khong tinh toan tren truong nay.')
```

**[SỬA] `runway_hours` không nên `required=True`.** Bản nháp đầu dùng `store=True, required=True, default=0.0` rồi phải cảnh giác chuyện NULL. Giải pháp đơn giản hơn: **bỏ `required=True`**. Một chỉ số hiển thị không cần ràng buộc NOT NULL; `required` ở đây không bảo vệ gì mà chỉ tạo một cái bẫy. Nếu vẫn muốn giữ (để query không phải xử lý NULL), thì quy tắc "compute gán giá trị ở **mọi** nhánh" vẫn bắt buộc:

```python
runway_hours = fields.Float(compute='_compute_runway_hours', store=True, default=0.0)

@api.depends('balance_native_ui', 'burn_rate_native_per_hour')
def _compute_runway_hours(self):
    for rec in self:
        rate = rec.burn_rate_native_per_hour
        rec.runway_hours = 9999.0 if not rate else rec.balance_native_ui / rate
```

Đặc thù từng chuỗi:

| Chuỗi | Thứ phải "refill" không phải native balance | Cơ chế |
|---|---|---|
| **SUI** | **Pool gas coin.** Song song = số coin object rời, không phải nonce | Giữ `max_inflight` coin object, mỗi coin >= `gas_budget`. Job `_sui_split_gas_coins()` định kỳ `SplitCoins`. Dùng một coin cho hai tx song song = **equivocation**, object bị khoá hết epoch (~24h) |
| **Cosmos** | `x/feegrant` allowance còn hạn mức | Theo dõi `PeriodicAllowance.period_spend_limit`, gia hạn trước khi cạn |
| **Soroban** | TTL của contract instance/persistent entry | `extend_ttl` là R4, lịch theo `live_until_ledger − 100k ledger` |
| **Stellar** | Base reserve + số dư XLM cho fee-bump | Fee-bump lấy phí từ FeeSource, không từ inner source |
| **TON** | Số dư Highload Wallet V3 + cửa sổ `query_id` | `query_id` hết cửa sổ (mặc định 128 s) là một dạng "nonce exhaustion" riêng |
| **Celo** | Số dư `feeCurrency` (cUSD/USDC) chứ không phải CELO | Refill bằng stablecoin; vẫn giữ một ít CELO dự phòng. **[MỚI]** Sau khi thành L2, còn cần theo dõi số dư ETH trên L1 của batcher nếu ta tự chạy node |
| **Hedera** | Số dư HBAR của payer account | Phí neo USD → burn rate ổn định, dễ dự báo nhất trong 7 chuỗi |
| **Chain private 9000** | **Không refill gì cả** (`MinGasPrice = 0`) | Toàn bộ mục này là no-op ở đó. Đừng build refill automation cho nó |

Hàng SUI là chuỗi duy nhất mà **pool gas coin thay thế hoàn toàn pool khoá** (§06.1.8): song song đến từ số coin object, không từ số địa chỉ. Cùng bài toán, khác hình dạng lời giải — và cái bẫy equivocation ở đó nghiêm trọng hơn nonce gap trên EVM, vì object bị khoá cả epoch chứ không phải chờ một replacement.

#### 06.5.1. [MỚI] Xoay khoá và rút lui relayer account (draining)

Thiếu hoàn toàn trong bản nháp đầu. Một relayer EOA phải xoay được mà không làm kẹt nonce.

```
active -> draining : dung nhan job moi; giu nguyen quyen broadcast/replace cho inflight
draining -> retired: khi inflight rong VA signed rong VA balance da sweep ve treasury
```

Chính sách: xoay mỗi **30 ngày** cho relayer EOA (chứ không phải treasury). Trong lúc draining, một EOA mới đã được thêm vào pool từ trước (`state='paused'` → `active`) nên không có khoảng trống năng lực. Trước khi `retired`, bắt buộc một lần `cold_start()` của EOA mới và một lần `reconcile` của EOA cũ; `retired` account giữ nguyên record để audit, không được xoá (`ondelete='restrict'` từ job).

**Với pool khoá (`_USER-DECISIONS.md` §21.5), state machine này là cơ chế xoay vòng, không phải một thủ tục bảo trì hiếm.** Xoay 30 ngày trên một pool 50 khoá nghĩa là **một khoá rời pool mỗi ~14 giờ** — nó phải hoàn toàn tự động, không có bước người, và `draining → retired` phải là một cron chứ không phải một nút bấm. Ba yêu cầu kèm theo:

1. Pool phải luôn có `N + 2` khoá: N đang `active`, một đang `draining`, một `paused` chờ vào. Không có đệm thì mỗi lần xoay là một lần giảm năng lực.
2. `draining` không được đếm vào `bc:pool:{caip2}:{relayer_id}` (ZSET chọn khoá) nữa — nếu không, least-in-flight vẫn gửi job mới vào nó.
3. Chi phí sweep: mỗi lần retire là một tx chuyển số dư còn lại về treasury. Ở 50 khoá xoay 30 ngày, đó là ~50 tx/tháng — không đáng kể, nhưng phải nằm trong dự toán gas chứ không xuất hiện như một bất ngờ.

### 06.6. HSM/MPC: nút cổ chai thật sự

Con số (ước tính có cơ sở, **cần benchmark lại trên hạ tầng thực trước khi khoá kiến trúc**):

| Custody | Throughput ký | Latency p50 / p99 | Cơ sở ước tính |
|---|---|---|---|
| HSM tại chỗ (Thales/Utimaco, PKCS#11, ECDSA P-256) | 10^3 – 10^4 sign/s | 1–5 ms / 20 ms | Spec nhà sản xuất cho ECDSA. **secp256k1 phải xác nhận riêng** — nhiều HSM chỉ có P-256/P-384 |
| AWS CloudHSM (hsm2m.medium) | ~10^3 sign/s/HSM | 3–10 ms / 50 ms | Bậc độ lớn công bố cho ECDSA. secp256k1 có hỗ trợ trên hsm2m |
| AWS KMS asymmetric `Sign` (ECC_SECG_P256K1) | **~500 req/s** quota mặc định (**thay đổi theo region**, một số region 300) | 15–40 ms / 150 ms | Service quota, không phải giới hạn crypto. Xin nâng được |
| **MPC SaaS** (Fireblocks/Fordefi/Turnkey) | **5 – 30 sign/s cho một vault** | **300 ms – 3 s** / 10 s | Nhiều vòng MPC qua mạng + policy engine + API rate limit. **Song song trong cùng vault thường bị serialize** |
| Threshold Schnorr/FROST tự vận hành, cùng DC | 10^2 – 10^3 sign/s | 10–50 ms / 200 ms | 2 vòng, RTT nội bộ |
| Session key trong Nitro Enclave/SGX | 10^4+ sign/s | < 1 ms | Ký cục bộ, không ra mạng |

**MPC SaaS ở 5–30 sign/s là nút cổ chai nghiêm trọng hơn cả chain.** Nếu mỗi business action = 1 chữ ký, trần hệ thống là 5–30 action/s — thấp hơn cả Gnosis. Bốn cách thiết kế quanh nó, theo thứ tự hiệu quả:

**1. Batch executor: 1 chữ ký relayer cho N meta-tx.** Đòn bẩy lớn nhất, và nó rơi ra từ chính EIP-1776: chữ ký *người dùng* nằm trong `MetaTransaction.signature` (do session key ký, rẻ), còn HSM chỉ ký **vỏ ngoài** — tx của relayer EOA. Một contract `MetaTxBatcher.executeBatch(MetaTransaction[] calldata txs, bytes[] calldata sigs)` gộp N=50 meta-tx vào 1 tx on-chain → tải HSM giảm 50 lần. Với MPC 10 sign/s: 500 business action/s.

**[MỚI] Ba yêu cầu bắt buộc lên contract batcher mà bản nháp đầu chỉ nói một:**

```solidity
function executeBatch(MetaTransaction[] calldata txs, bytes[] calldata sigs) external {
    uint256 n = txs.length;
    require(n == sigs.length && n <= MAX_BATCH, "batch: len");
    for (uint256 i; i < n; ++i) {
        uint256 g = txs[i].gasLimit;
        // (a) EIP-150 63/64: callee chi nhan duoc toi da 63/64 gasleft.
        //     Khong guard -> ke tan cong dat gasLimit sat tran de item cuoi
        //     "het gas" mot cach co chu dich (insufficient-gas griefing).
        require(gasleft() >= g + g / 63 + 12_000, "batch: gas grief");
        (bool ok, bytes memory ret) = address(this).call{gas: g}(
            abi.encodeCall(this.executeOne, (txs[i], sigs[i])));
        if (!ok) emit BatchItemFailed(i, keccak256(ret));
        // (b) KHONG revert ca batch: mot meta-tx hong keo 49 cai kia chet, va sim gate
        //     phai mo phong xac suat tich hop cua 50 item -> khong lam duoc.
    }
}

function executeOne(MetaTransaction calldata t, bytes calldata sig) external {
    require(msg.sender == address(this), "self only");
    // (c) Phi PHAI duoc thu ke ca khi inner call revert. Neu khong, ke tan cong
    //     gui meta-tx chac chan revert -> relayer tra gas, khong duoc gi -> griefing
    //     mien phi. Thu phi truoc, tang meta_nonce truoc, roi moi call.
    _consumeNonce(t.from, t.batchId, t.batchNonce);
    _collectFee(t);                              // luon thu
    (bool ok, ) = t.to.call(t.data);
    if (!ok) emit MetaTxInnerFailed(t.from, t.batchId, t.batchNonce);
}
```

Điểm (c) là một **quyết định contract mà relay pool không thể an toàn nếu thiếu**, và nó kéo theo vấn đề grief ngược lại (một relayer độc đốt nonce của user) — xem §06.12 mục 3.

**[MỚI] Batch làm sim gate khó hơn, và đó là chi phí thật.** Sim một batch 50 item mất gas gấp ~50 lần; một `eth_call` 50 × 200k = 10M gas có thể vượt cap của provider. Chốt: **sim từng item riêng lẻ trên cùng một `blockHash`** (50 `eth_call` song song, mỗi cái nhỏ), rồi sim cả batch **một lần** để lấy gas tổng. Item nào sim fail thì loại khỏi batch trước khi ký — đó là lý do sim phải xảy ra **trước** batching, không phải sau.

**Kích thước batch tốt nhất không phải là lớn nhất.** Đánh đổi: batch lớn → ít chữ ký hơn, nhưng (i) một tx to hơn có xác suất treo cao hơn và replacement đắt hơn, (ii) latency chờ gom batch, (iii) một lần revert cấp batch mất hết. Đề xuất: `batch_size = min(50, ceil(arrival_rate * max_batch_wait_ms / 1000))`, `max_batch_wait_ms = 1500` cho R2, **0 (không batch)** cho R3/R4. Job R3 dùng batch là đặt một khoản tiền thật vào chung số phận với 49 job khác.

**2. Pool khoá — và bản 1 đánh giá thấp nó.** Bản 1 viết: *"sharding K relayer EOA song song hoá, nhưng không tăng throughput HSM (vẫn cùng một HSM/vault). Chỉ giải quyết head-of-line blocking."* Câu đó đúng về mặt chữ ký và **bỏ sót vế quan trọng hơn**: head-of-line blocking không phải một phiền toái, nó là **trần thông lượng cứng của EVM** (§06.1: `txpool.accountslots = 16`, và một tx kẹt chặn cả hàng). Với một khoá, throughput bị chặn ở ~1 tx/block bất kể HSM nhanh cỡ nào.

Nói cách khác: **batch giải nút cổ chai chữ ký, pool khoá giải nút cổ chai nonce.** Hai nút khác nhau, và hệ thống bị chặn ở cái thấp hơn. Cần cả hai.

**[MỚI]** Ngoại lệ về throughput ký: nếu MPC provider cho phép **nhiều vault**, mỗi vault một EOA thì throughput ký *có* nhân lên — nhưng chi phí license thường theo vault. Kiểm tra với nhà cung cấp trước khi đưa vào mô hình năng lực.

**3. Phân tầng custody theo lớp rủi ro** — đề xuất cần người duyệt: HSM FIPS L3 bắt buộc cho **treasury + refill signer + admin contract (upgrade/pause)**; relayer EOA hot dùng khoá sinh trong **Nitro Enclave/SGX**, không bao giờ ra plaintext ngoài enclave, trần chi tiêu bằng runway 4h, xoay vòng 30 ngày (§06.5.1). Nguyên tắc "cấm Agent lưu private key plaintext" vẫn được giữ tuyệt đối — enclave không phải plaintext-on-disk. Đổi lại throughput từ 10 lên 10^4 sign/s. Nếu compliance không chấp nhận, phải chấp nhận trần ~10–30 tx/s và thiết kế batch theo (1). Trùng khớp với bảng của §07.0.

Với mô hình mesh mở, tầng này có một biến thể thứ ba mà bản 1 không có: **một node mesh do cá nhân chạy giữ khoá trong một file.** Đó không phải cấu hình sai — nó là cấu hình đúng cho một khoá giữ $5 tiền gas và không có quyền gì khác (`_USER-DECISIONS.md` §21.5). `KeyPool` phải nhận cả ba: HSM, enclave, và file. Cùng interface `sign(tx) -> bytes`, khác backend, chọn bằng cấu hình. Đừng viết hai bản.

**Điểm quan trọng phải nói thẳng:** một khoá file chỉ chấp nhận được **vì** các ràng buộc ở `_USER-DECISIONS.md` §21.5 — float nhỏ, không phải `feeRecipient`, không role nào trên contract nào. Nếu ai đó bỏ một trong ba ràng buộc đó, khoá file trở thành một lỗ hổng. Ba ràng buộc và một backend rẻ đi cùng nhau; không tách được.

**4. Không pre-sign hàng loạt theo nonce.** Ký trước nonce n..n+50 rồi cất sẵn nghe hấp dẫn (amortize latency) nhưng tạo một kho tx đã ký có thể phát sóng bởi bất kỳ ai đọc được nơi cất, và không thể huỷ sau khi ký vì gas price đã chốt. **Cấm.** Ngoại lệ duy nhất được xem xét: pre-sign **một** tx cancel (self-send, 21000 gas, giá cao) cho mỗi nonce inflight, lưu trong enclave chứ không trong store thường — đó là một "dead man switch" có giá trị, nhưng vẫn là một tx đã ký nằm chờ, nên mặc định **tắt**.

Ngân sách latency một job (Gnosis, MPC SaaS, không batch):
Ngân sách latency một job (Gnosis, MPC SaaS, không batch):

```
policy + allowlist + selector                     2 ms
sim (eth_call + estimateGas + getL1Fee, 3 RPC)  120 ms
velocity reserve (1 transaction Postgres)         0.6 ms   [BAN 3] thay Lua
lease nonce (actor in-process, khong I/O)         0.01 ms  [BAN 3] thay Lua
journal (job -> leased), COMMIT                  15 ms   khong mien phi
sign (MPC, qua lan custody)                     800 ms   <-- 74% ngan sach
journal (job -> signed), COMMIT                  15 ms
serialize + broadcast fan-out                    80 ms
------------------------------------------------------
tong truoc khi len mempool                    ~1.031 ms
inclusion (1 block)                            5.000 ms
finality soft (1 block) / hard (2 epoch)        5 s / ~13 phut
```

**74% ngân sách nằm ở một lời gọi ký.** Đó là con số nói rõ nhất tại sao §06.6 mục 3 (enclave cho relayer hot) không phải một tối ưu hoá mà là một quyết định kiến trúc. Với enclave, dòng đó rớt từ 800 ms xuống < 1 ms và tổng trước mempool còn ~235 ms.

Và nó là lý do độc lập thứ ba để **Zether không đi qua MPC SaaS**: cửa sổ epoch chỉ còn ~4,8 block (§06.3.4), một chữ ký 800 ms p50 / 3 s p99 ăn mất 12–60% cửa sổ đó trước khi tx rời máy.

#### 06.6.1. [MỚI] Mô hình hàng đợi: bao nhiêu worker, bao nhiêu EOA

Little's law, mục tiêu **100 business action/s** (biên trên cho cả DMS + loyalty + payment):

```
Voi batch 50, R2:        2 on-chain tx/s
Voi R3 khong batch:      gia su 5 tx/s
Tong tx/s can:           ~7 tx/s

Moi EOA: gioi han boi (a) sign serial, (b) txpool.accountslots = 16
  (a) MPC 10 sign/s dung chung -> KHONG scale theo EOA
  (b) enclave 10^4 sign/s     -> gioi han la (16 inflight) / (5 s/block) = 3,2 tx/s/EOA

=> Voi enclave: K = ceil(7 / 3,2) = 3 EOA. Lay K = 6 (2x headroom + cach ly HOL).
=> Voi MPC:     tran he thong = 10 tx/s bat ke K. Phai batch.

[BAN 3] Khong con "worker process" nao de dem: MOT tien trinh scaas-node giu ca K khoa,
moi khoa mot task tokio. K=6 la sau task, khong phai sau tien trinh.
Postgres:  ~4 write/job. O 100 job/s va gom theo lo = ~2-5 commit/s. Khong dang ke.
Bo nho:    state nonce mot khoa < 4 KB. K=6 tren 3 chain = ~72 KB. Khong dang ke.
```

Kết luận đúng một câu: **với MPC SaaS, số EOA không quan trọng; với enclave, 6 EOA là đủ cho 100 action/s.** Bất cứ ai đề xuất 50 relayer EOA nên bị hỏi trước đó số này.

**Nhưng con số 6 là cho tải nội bộ có batch.** `_USER-DECISIONS.md` §21.5 đưa ra bảng 50 khoá cho 10 tx/s — không mâu thuẫn, mà là **một bài toán khác**: đó là một node mesh relay intent của người lạ, nơi **không batch được** (mỗi intent một chữ ký người dùng riêng, đến rời rạc, không có ai để gom) và mỗi tx là một `executeMetaTransaction` độc lập. Batch chỉ khả thi khi ta là người sinh ra cả N job cùng lúc.

Nói gọn: **batch được thì cần ít khoá; không batch được thì cần nhiều khoá.** Relay pool nội bộ ở vế đầu, node mesh ở vế sau, và cùng một `KeyPool` phục vụ cả hai với cấu hình khác nhau.

Thêm hai dòng cho chain private 9000: `block_time` là 5 s như Gnosis nên `(b)` không đổi, và MPC/HSM không nằm trên đường đó (chain nội bộ, khoá nội bộ), nên `(a)` cũng không. Trần thật ở đó là **CPU validator ~45 confidential tx/s** (§01.1.12.2), và nó cao hơn cả hai giới hạn trên — tức là ở giai đoạn private, không có nút cổ chai nào trong section này ràng buộc.

---

### 06.7. Multi-RPC: failover và phát hiện RPC nói dối / tụt hậu

Tối thiểu **3 provider độc lập** mỗi chain (1 node tự vận hành + 2 nhà cung cấp). `blockchain.rpc.endpoint` có `endpoint_ref` (Char, trỏ tới `ir.config_parameter` chứa URL + API key — **không** lưu key trên record), `weight`, `role` (`primary`/`fallback`/`witness`), `health_state`, `score`, `divergence_count`.

Trên chain private 9000 hiện chỉ có **một** node, nên "3 provider độc lập" không áp dụng. Điều đó không làm các lớp kiểm tra dưới đây vô nghĩa — lớp 1 (liveness) và lớp 4 (drop im lặng) vẫn chạy được với một endpoint; lớp 2 và 3 (đối chứng giữa các provider) thì không. Ghi rõ trong cấu hình chain rằng hai lớp đó **tắt vì thiếu quorum**, đừng để chúng báo "pass" một cách vô nghĩa.

#### 06.7.1. Bốn lớp kiểm tra

**Lớp 1 — sống (liveness), mỗi 5s:** `eth_blockNumber` + `eth_getBlockByNumber(head)`. Đo `head_lag_blocks` so với max của cả cụm, và `head_age = now − block.timestamp`. Trip khi `head_lag > 3` hoặc `head_age > 4 * block_time`. Đây là *lagging RPC*.

**Lớp 2 — trung thực (correctness), mỗi 30s:** hỏi **k-of-n** cùng một câu hỏi tại chiều sâu an toàn `H = head − witness_depth`:

```
blockhash(H)  tu tat ca endpoint  ->  phai bang nhau
```

**[SỬA] `witness_depth` phải theo chain, không phải hằng số 12.** Bản nháp đầu chốt 12 block cho mọi chain: trên Gnosis đó là 60s (chấp nhận được), trên Celo L2 block 1s đó là 12s (quá nông, reorg của sequencer restart có thể sâu hơn), trên Cosmos/Stellar (finality tức thời) 12 là thừa. Chốt `witness_depth = max(chain.finality_depth, 2)` cho chain BFT, `max(chain.finality_depth, 12)` cho chain probabilistic.

Clique (chain 9000) thuộc nhóm **probabilistic, không phải BFT** — nó không có instant finality (§01.1.16). Đừng xếp nó vào nhánh `max(finality_depth, 2)` chỉ vì nó là chain riêng.

**[SỬA] Một lần lệch không được eject ngay.** Hai provider có thể trả khác nhau *hợp pháp* trong vài giây ngay sau một reorg nông. Chốt: lệch lần đầu → `divergence_suspect`, hỏi lại sau 2 block **tại cùng chiều sâu mới**; vẫn lệch → **eject vĩnh viễn** (không auto-recover), `blockchain.breaker.event(kind='rpc_divergence')`, page P1. Nếu **quorum bị vỡ** (không có đa số) → dừng broadcast toàn chain, chuyển sang read-only.

**[MỚI] Lớp 3 — canary state:** blockhash bằng nhau không chứng minh `eth_call` trung thực. Một provider có thể phục vụ state cũ. Mỗi 60s, gọi cùng một `eth_call` tới một contract canary (một counter tăng đơn, hoặc đơn giản là `balanceOf(relayer)` của một ERC-20 quen thuộc) **pin theo `blockHash`** giống nhau trên mọi endpoint; kết quả phải byte-identical. Đây là kiểm tra duy nhất bắt được một archive node đang phục vụ state sai — kiểu lỗi đã từng xảy ra với nhà cung cấp thật.

**Lớp 4 — phát hiện drop im lặng:** lối hỏng nguy hiểm nhất là RPC trả về tx hash cho `eth_sendRawTransaction` rồi **không lan truyền** — job tưởng đã broadcast, thực tế không. Phát hiện: sau 2 block, xác nhận tx tồn tại qua **một provider KHÁC** (`eth_getTransactionByHash` != null hoặc `getTransactionCount(pending)` đã tăng). Không thấy → re-broadcast raw tx (giống hệt, cùng chữ ký) qua provider khác; sau 3 lần → eject provider.

Với một node duy nhất, lớp 4 lui về "xác nhận qua `txpool_content` của chính node đó" — yếu hơn hẳn, và phải được ghi nhận là một rủi ro tồn dư của cấu hình một node, không phải một kiểm tra tương đương.

#### 06.7.2. Ba quy tắc định tuyến bắt buộc

1. **Sticky provider cho đọc nonce-critical.** `getTransactionCount` phải luôn hỏi cùng một provider trong suốt vòng đời một relayer account (ghi `pinned_endpoint_id` trên account). Đọc `latest=41` từ node A rồi `latest=39` từ node B tụt hậu → nonce manager tự tạo gap. Đổi provider chỉ khi eject, và khi đổi thì **bắt buộc `cold_start()` toàn bộ** trước khi cấp lease tiếp (§06.1.2) — không phải chỉ "reconcile".
2. **Broadcast fan-out, đọc thì không.** Gửi raw tx tới **tất cả** provider khoẻ (tăng xác suất lan truyền, không có tác dụng phụ vì tx là idempotent theo hash). Ngược lại, đọc state thì chỉ từ primary + witness kiểm chứng.
3. **[MỚI] Fan-out phải trừ các endpoint có orderflow riêng.** Một số RPC (MEV-protect, private orderflow, builder-affiliated) **không** phát tán tx ra mempool công khai, và gửi tx tới đó là trao quyền ưu tiên cho một bên. Field `blockchain.rpc.endpoint.propagation = Selection([('public','Public mempool'), ('private','Private orderflow'), ('unknown','Unknown')])`. Fan-out chỉ tới `public`. Endpoint `private` chỉ dùng cho tx có `mev_sensitive=True` (ví dụ `withdraw` Zether, nơi §10.5.3 đã băm `recipient` vào challenge nhưng giá trị rút vẫn lộ ra), và khi đó **chỉ** gửi tới đó, không fan-out.

   Trường `propagation` này là cùng một khái niệm với `pool_visibility` của §05.8.2 nhìn từ tầng RPC: một nơi là "intent này có được gossip không", một nơi là "tx này có được phát tán không". Hai tầng, cùng một quyết định bảo mật, và chúng phải nhất quán — một intent `pool: private` mà cuối cùng được fan-out ra mempool công khai thì lớp bảo vệ đầu là vô ích.

Scoring để chọn primary: `score = 0.5*ewma(latency_p95) + 0.3*error_rate + 0.2*head_lag`, EWMA alpha=0,2, đánh giá lại mỗi 30s, đổi primary có hysteresis (chỉ đổi khi score tốt hơn primary hiện tại > 25% trong 3 lần liên tiếp).


---

### 06.8. Observability: chỉ số nào thật sự quan trọng

Prometheus, label chung `{caip2, relayer_addr, tenant, risk_class}`.

| Metric | Type | Ý nghĩa | Alert |
|---|---|---|---|
| `relay_nonce_gap_age_seconds` | Gauge | Tuổi của nonce bị thủng cũ nhất | > 120s → **page P1** (mọi tx sau đó đang chết) |
| `relay_nonce_lease_expired_total` | Counter | Lease hết hạn phải reclaim | > 5/phút → ticket (worker đang chết hoặc signer chậm) |
| `relay_nonce_desync_total` | Counter | `latest > next` (ai đó dùng chung ví) | >= 1 → **page P1**, quarantine account |
| `relay_signed_orphan_total` | Counter **[MỚI]** | Nonce có raw tx đã ký nhưng không có job | >= 1 → **page P1** (mất toàn vẹn WAL) |
| `relay_shard_ownership_lost_total` | Counter **[MỚI]** | Worker mất lease shard | > 2/giờ → ticket (worker flapping) |
| `relay_sim_exec_divergence_total` | Counter | Sim pass nhưng tx revert, label `{category}` | > 0,5% broadcast/15p → ticket; > 20/h cùng contract → auto-quarantine |
| `relay_sim_thrash_total` | Counter **[MỚI]** | Job phải sim lại >= 3 lần | Tăng = state drift cao, xem lại `expiry` |
| `relay_tx_stuck_seconds` | Histogram | broadcast → mined | p99 > 3× `block_time * stuck_after` → ticket |
| `relay_replacement_total` | Counter, label `{kind=speedup\|cancel\|gapfill}` | Speed-up + cancel + gap-filler | Tăng đột biến = breaker sắp trip hoặc fee model sai |
| `relay_bump_ceiling_total` | Counter **[MỚI]** | `BumpCeilingReached` | >= 1 → ticket ngay: tx đang kẹt và không gỡ được |
| `relay_hot_wallet_runway_hours` | Gauge | Số dư / burn rate | < 4h → ticket; **< 1h → page** |
| `relay_key_pool_available` | Gauge **[MỚI bản 2]** | Số khoá `active` không kẹt, không draining | < 2 → ticket; **0 → page** (mất hoàn toàn khả năng submit) |
| `relay_key_pool_stuck_total` | Counter **[MỚI bản 2]** | Khoá rơi vào `stuck_at_ceiling` | > 10% pool → ticket: đây là sự cố mạng, không phải một khoá xui |
| `relay_refill_pending_seconds` | Gauge **[MỚI]** | Tuổi refill request chưa xong | > 1800s → page (automation refill đang hỏng) |
| `relay_signer_latency_seconds` | Histogram | Đo tại HSM/MPC boundary | p99 > 3s → ticket; nút cổ chai, dashboard riêng |
| `relay_signer_throttled_total` | Counter | 429 từ KMS/MPC | > 0 → tăng batch size hoặc xin nâng quota |
| `relay_batch_size` | Histogram **[MỚI]** | Số item/batch thực tế | p50 << `batch_size` cấu hình = đang chờ vô ích, giảm `max_batch_wait_ms` |
| `relay_rpc_head_lag_blocks` | Gauge | Per endpoint | > 3 → demote |
| `relay_rpc_divergence_total` | Counter | Hash lệch tại `head − witness_depth`, sau xác nhận lần 2 | >= 1 → **page P1 bảo mật** |
| `relay_rpc_state_canary_mismatch_total` | Counter **[MỚI]** | `eth_call` canary lệch | >= 1 → **page P1 bảo mật** |
| `relay_breaker_state` | Gauge (0/1/2) | closed/half/open, per chain per class | Chuyển sang open → thông báo ngay |
| `relay_gas_spend_usd_total` | Counter | Per tenant, per risk_class | 90% quota → thông báo |
| `relay_spend_reservation_leaked_total` | Counter **[MỚI]** | Reservation phải refund bởi janitor | > 10/giờ → bug ở đường settle |
| `relay_l1_data_fee_ratio` | Gauge **[MỚI]** | `l1_fee / total_fee` trên rollup | > 0,9 → cảnh báo chi phí, xem xét nên batch to hơn |
| `relay_cost_per_business_action_usd` | Gauge | `gas_spend / batch_item_count` | Chỉ số ROI thật; theo dõi hàng ngày |
| `relay_zether_epoch_miss_total` | Counter | Tx Zether quá `epoch_deadline_block` | > 1% → tăng tip mặc định lớp Zether |
| `relay_finality_wait_seconds` | Histogram | mined → final | Đối chiếu bảng finality §11; lệch bền vững = cấu hình depth sai |
| `relay_admission_queue_depth` | Gauge **[MỚI]** | Job `draft` chờ lease | > 5 phút worth of throughput → hệ thống đang tích luỹ nợ |

**Năm alert page người lúc 3h sáng** (bản nháp đầu có bốn), còn lại là ticket: `nonce_gap_age`, `nonce_desync`, `signed_orphan`, `rpc_divergence` (bao gồm canary), `hot_wallet_runway < 1h`. Bốn cái đầu là mất toàn vẹn; cái cuối là mất dịch vụ hoàn toàn trong < 60 phút. Mọi thứ khác (gas đắt, sim fail, tx chậm) tự nó không làm hỏng dữ liệu.

**Bản 2 thêm một cái thứ sáu: `relay_key_pool_available == 0`.** Với pool khoá, mất hết khoá là mất dịch vụ y hệt mất số dư — và nó xảy ra âm thầm hơn, vì mỗi khoá kẹt riêng lẻ chỉ là một ticket. Cảnh báo phải nhìn vào *số khoá còn dùng được*, không vào *số khoá kẹt*.

SLO đề xuất: broadcast→`final` p95 <= `finality_hard + 60s`; tỷ lệ job đến `final` không cần can thiệp tay >= 99,5%/tháng; `nonce_gap_age` = 0 trong 99,9% thời gian; `relay_signed_orphan_total` = 0 tuyệt đối.

#### 06.8.1. [MỚI] Ba runbook phải viết trước khi lên production

| Sự cố | Triệu chứng | Các bước |
|---|---|---|
| **Tiến trình node chết / mất state bộ nhớ** | Khởi động lại, state nonce rỗng | 1. Lấy advisory lock (§06.1.1) — không lấy được thì dừng, có tiến trình khác đang giữ. 2. Với mỗi khoá: `cold_start()` (§06.1.3). 3. Đối chiếu `signed` nạp từ journal với `getTransactionCount(pending)`. 4. Nonce trong `[latest, pending)` không có job → gap-filler (§06.1.7). 5. **Không** suy freelist từ chênh lệch (§06.1.3 bước 7) |
| **`nonce_desync` (`latest > next`)** | Metric >= 1 | 1. Quarantine account **ngay** (tự động). 2. Không tự resume. 3. Người trực kiểm: có ai chạy script thủ công không? Khoá có bị export không? 4. Nếu nghi lộ khoá: `state='retired'`, sweep số dư về treasury bằng treasury signer, tạo EOA mới. 5. Chỉ resume khi giải thích được nguồn gốc |
| **Sequencer down (Arbitrum/OP)** | `head_age > 60s` trên mọi endpoint | 1. Breaker `SEQUENCER_DOWN`, dừng nhận job mới. 2. **Không** bump, **không** cancel (tx đang nằm trong hàng đợi của sequencer). 3. Nếu > 2h và có job R3 giá trị lớn: đánh giá force-inclusion qua L1 delayed inbox — đó là quyết định của người, không tự động. 4. Reset breaker khi head tăng liên tục 5 phút |

Runbook thứ hai đáng đọc kỹ với pool khoá: `nonce_desync` trên **một** khoá trong 50 không phải sự cố toàn hệ thống, và quarantine đúng một khoá là phản ứng đúng. Nhưng nếu nó xảy ra trên **nhiều** khoá cùng lúc, đó không phải nhiều sự cố — đó là một sự cố (khoá bị export hàng loạt, hoặc một worker ma đang chạy), và phản ứng phải là dừng cả pool. Ngưỡng: >= 2 khoá desync trong 1 giờ → quarantine toàn bộ `relayer_id`.

---

### 06.9. Bề mặt model Odoo (control plane)
Prefix `blockchain.*` (khớp với chốt của §10.3). Tất cả constraint dùng `models.Constraint`, không dùng list `_sql_constraints` — Odoo 19 **bỏ qua hoàn toàn** dạng list, constraint không bao giờ được tạo trong PostgreSQL. Kiểm chứng sau khi cài:

```sql
SELECT conname, contype FROM pg_constraint
WHERE conrelid = 'blockchain_relayer_account'::regclass;
```

Theo §10.4.3, `blockchain.relayer.account` là `_inherits` của `blockchain.account`, không phải một bảng song song:

```python
class BlockchainRelayerAccount(models.Model):
    _name = 'blockchain.relayer.account'
    _description = 'Relayer EOA in the internal relay pool'
    _inherits = {'blockchain.account': 'account_id'}

    account_id      = fields.Many2one('blockchain.account', required=True,
                                      ondelete='cascade', index=True)
    # chain_id, address, custody_mode, signer_ref, role, company_id -> tu blockchain.account

    # [MOI ban 2] Mot relayer_id co N khoa ky. Xem _USER-DECISIONS.md `_USER-DECISIONS.md` §21.5.
    relayer_id      = fields.Many2one('blockchain.relayer', index=True, ondelete='restrict',
                                      help='Danh tinh relayer. N account nay thuoc mot relayer_id.')

    pool_state      = fields.Selection([('paused','Paused'), ('active','Active'),
                                        ('draining','Draining'), ('quarantined','Quarantined'),
                                        ('retired','Retired')],
                                       required=True, default='paused', index=True)
    max_inflight    = fields.Integer(required=True, default=16,
                                     help='Mac dinh 16 = geth --txpool.accountslots. Vuot -> node im lang bo tx.')
    worker_shard    = fields.Char(readonly=True, help='worker_id dang giu ownership lease.')
    owner_fence     = fields.Integer(readonly=True)
    nonce_gen       = fields.Integer(readonly=True, help='Generation, tang moi lan cold start.')
    pinned_endpoint_id = fields.Many2one('blockchain.rpc.endpoint', ondelete='restrict')

    nonce_confirmed = fields.Integer(readonly=True)      # mirror tu journal, cho UI/audit
    nonce_allocated = fields.Integer(readonly=True)
    nonce_gap_count = fields.Integer(readonly=True)

    balance_native_base   = fields.Char(readonly=True, help='wei / base units, chuoi thap phan.')
    balance_native_ui     = fields.Float(digits=(18, 6), readonly=True, help='Chi de hien thi.')
    balance_sync_datetime = fields.Datetime(readonly=True)
    burn_rate_native_per_hour = fields.Float(digits=(18, 6), readonly=True)
    runway_hours    = fields.Float(compute='_compute_runway_hours', store=True, default=0.0)

    rotate_due_date = fields.Date(help='Xoay khoa moi 30 ngay cho relayer hot.')

    _unique_account = models.Constraint(
        'UNIQUE(account_id)', 'Mot on-chain account chi la mot relayer pool entry.')
    _check_inflight = models.Constraint(
        'CHECK (max_inflight > 0 AND max_inflight <= 64)',
        'max_inflight phai trong (0, 64]. Vuot 16 chi khi node duoc cau hinh accountslots cao hon.')
```

Trường `relayer_id` là bổ sung của bản 2 và nó không phải trang trí: **`registerSubmitter` của §05.6, cap per-relayer của §05.7, và đối soát gas của §05.8.3 đều cần biết N địa chỉ này là một người.** Thiếu nó, một relayer 50 khoá được đếm thành 50 relayer ở mọi chỗ có ngưỡng — và đó chính là sybil mà các ngưỡng đó tồn tại để chặn.

Tên field đã tránh trùng tên kiểu Odoo: `balance_sync_datetime` (không phải `datetime`), `lease_expiry` (không phải `date`), `payload_text` (không phải `text`), `calldata_hex` (không phải `binary`), `rotate_due_date` (không phải `date`).

`blockchain.relay.job` (rút gọn, chỉ các trường quyết định):

```python
class BlockchainRelayJob(models.Model):
    _name = 'blockchain.relay.job'
    _description = 'One relay attempt: intent -> signed tx -> finality'
    _order = 'create_date desc'

    job_uuid       = fields.Char(required=True, index=True, copy=False,
                                 default=lambda s: str(uuid.uuid4()))
    chain_id       = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    relayer_id     = fields.Many2one('blockchain.relayer.account', index=True, ondelete='restrict')
    company_id     = fields.Many2one('res.company', required=True, index=True,
                                     default=lambda s: s.env.company)
    risk_class     = fields.Selection([('r1','R1'), ('r2','R2'), ('r3','R3'), ('r4','R4')],
                                      required=True, default='r2', index=True)
    state          = fields.Selection([...], required=True, default='draft', index=True)

    target_address = fields.Char(required=True, size=42, index=True)
    selector_hex   = fields.Char(compute='_compute_selector', store=True, size=10, index=True)
    calldata_ref   = fields.Char(help='Khoa trong blockchain_relay_blob; ir.attachment cho R3/R4.')
    raw_tx_ref     = fields.Char(help='Khoa trong blockchain_relay_blob, TTL 24h. KHONG luu raw tx tren record.')

    nonce          = fields.Integer(index=True)
    nonce_gen      = fields.Integer()
    owner_fence    = fields.Integer()
    tx_hash        = fields.Char(size=66, index=True)
    replaces_job_id = fields.Many2one('blockchain.relay.job', ondelete='set null')

    sim_block_hash    = fields.Char(size=66)
    sim_block_height  = fields.Integer()
    sim_gas           = fields.Integer()
    meta_nonce_block  = fields.Integer()

    zether_target_epoch         = fields.Integer()
    zether_epoch_deadline_block = fields.Integer()

    est_cost_uusd  = fields.Integer(help='Micro-USD, so nguyen. Khong dung Float cho tien.')
    actual_cost_uusd = fields.Integer()
    l1_fee_base    = fields.Char(help='Phi L1 data tren rollup, base units.')

    origin_model   = fields.Char(index=True)   # seam long leo sang consumer
    origin_res_id  = fields.Integer(index=True)
    origin_ref     = fields.Char(required=True, index=True, help='Idempotency key do consumer cap.')

    _unique_origin = models.Constraint(
        'UNIQUE(company_id, origin_ref)',
        'origin_ref phai duy nhat trong mot company: day la khoa idempotency.')
    _unique_nonce_live = models.Constraint(
        "UNIQUE (relayer_id, nonce) WHERE state IN "
        "('nonce_leased','signed','signed_orphan','broadcast','mined')",
        'Chi mot job song tren mot nonce cua mot relayer.')
```
**[MỚI] `_unique_origin` là cơ chế idempotency thật sự.** Bản nháp đầu nói "idempotent theo `origin_ref`" mà không nói bằng gì. Với partial unique index này, `relay_submit_intent` gọi lại với cùng `origin_ref` sẽ đụng `INSERT` và trả về job cũ — không phải nhờ code kiểm tra trước (có race), mà nhờ database. `_unique_nonce_live` là partial index chặn trực tiếp lỗi nghiêm trọng nhất của §06.1.4.

Method public phục vụ cả `call_kw` lẫn `/json/2` (không `_`, không `@api.private`, không nhận `allowed_company_ids` từ client):

```python
@api.model
def relay_submit_intent(self, caip2, target_address, calldata_hex,
                        risk_class='r2', origin_model=None, origin_res_id=None,
                        origin_ref=None, meta_tx=None):
    """POST /web/dataset/call_kw/blockchain.relay.job/relay_submit_intent
       POST /json/2/blockchain.relay.job/relay_submit_intent
    Tra ve {'job_uuid': ..., 'state': 'draft'}. Idempotent theo (company, origin_ref):
    goi lai voi cung origin_ref tra ve job da co, khong tao job moi.
    Company suy ra tu self.env.company — KHONG nhan tu client."""
    return self._submit_intent(...)

@api.model
def relay_job_status(self, job_uuid):
    """Tra {'state', 'tx_hash', 'nonce', 'confirmations', 'final_datetime', 'error_code'}.
    'final' la trang thai DUY NHAT consumer duoc coi la da thanh toan. Xem bang §06.2.6."""

@api.model
def relay_cancel_intent(self, job_uuid, reason):
    """Yeu cau huy. Tra ve {'accepted': bool, 'reason': str}.
    accepted=False khi job da 'mined' — luc do khong con huy duoc, chi con doi hoac dao nguoc
    bang mot giao dich nghiep vu nguoc chieu."""

@api.model
def relay_report_batch(self, reports):
    """Worker -> Odoo. Chi service account co group_blockchain_relay_worker goi duoc.
    Toi da 200 ban ghi/lan."""
```

Cron XML (một dòng, không inline `fields.`/`relativedelta` — `ir.cron` eval context không có chúng):

```xml
<record id="cron_relay_reconcile" model="ir.cron">
    <field name="name">Blockchain: reconcile relayer nonce and balance</field>
    <field name="model_id" ref="model_blockchain_relayer_account"/>
    <field name="state">code</field>
    <field name="code">model._cron_relay_reconcile()</field>
    <field name="interval_number">5</field>
    <field name="interval_type">minutes</field>
</record>

<record id="cron_relay_janitor" model="ir.cron">
    <field name="name">Blockchain: reclaim leases, refund reservations, scan refill</field>
    <field name="model_id" ref="model_blockchain_relay_job"/>
    <field name="state">code</field>
    <field name="code">model._cron_relay_janitor()</field>
    <field name="interval_number">5</field>
    <field name="interval_type">minutes</field>
</record>
```

Nhóm quyền (khớp §10.5): `group_blockchain_viewer` (đọc), `group_blockchain_relay_worker` (chỉ `relay_report_batch`, không đọc được `blockchain.account.signer_ref`), `group_blockchain_relayer_admin` (CRUD relayer account, endpoint), `group_blockchain_treasury_manager` (refill approve, breaker override). **Người tạo `blockchain.breaker.override` không được đồng thời là người duyệt `blockchain.refill.request`** — đó là một đường rút tiền một người.

---

### 06.10. [MỚI] Năng lực, chi phí, và lưu trữ
#### 06.10.1. Ngân sách chi phí hạ tầng, một chain (Gnosis), 24.000 tx/ngày

| Mục | Cấu hình | USD/tháng (ước) |
|---|---|---|
| 3 relay worker | 2 vCPU / 4 GB | 120 |
| ~~Redis (nonce)~~ **bỏ** — state nằm trong tiến trình + journal Postgres | — | **0** |
| Node Gnosis tự vận hành (archive nhẹ, cho `eth_call`/`debug_traceCall`) | 8 vCPU / 2 TB NVMe | 200 |
| 2 RPC provider (fallback + witness) | gói growth | 100 – 400 |
| Prometheus + Grafana + Alertmanager | dùng chung hạ tầng | 0 – 50 |
| **Tổng hạ tầng** | | **480 – 830** |
| Gas thật (24k tx/ngày @ $0,007 tx Zether n=64) | | **~5.000** |
| Gas thật (24k tx/ngày @ $0,00005 tx thường 100k gas) | | **~36** |

Đọc bảng này theo một hướng: **chi phí gas của Zether công khai lớn gấp 6–10 lần toàn bộ chi phí hạ tầng.** Đó là lập luận kinh tế mạnh nhất cho private chain, mạnh hơn lập luận bảo mật.

Trên chain private 9000, dòng gas về **0** và bảng còn lại chỉ có hạ tầng — trong đó dòng "2 RPC provider" cũng biến mất (không có provider nào), nên tổng rơi về **~380/tháng**. Đây là con số nên dùng khi so sánh hai giai đoạn, không phải con số Gnosis.

Chi phí MPC SaaS **không** có trong bảng vì ở 24k tx/ngày (720k chữ ký/tháng nếu không batch) không nhà cung cấp MPC nào bán theo đơn giá mà còn hợp lý. Với batch 50: 14.400 chữ ký/tháng — nằm trong bậc thường. Đây là một ràng buộc thương mại, không chỉ kỹ thuật.

#### 06.10.2. Tăng trưởng bảng job

| Giả định | Số |
|---|---|
| Job/ngày | 24.000 |
| Byte/row (không kể raw tx / calldata) | ~800 B |
| Postgres/ngày | ~19 MB |
| Postgres/năm | **~7 GB** |
| Index (5 index) | +~60% → **~11 GB/năm** |

Chấp nhận được **chỉ khi** không lưu raw tx và calldata trên record.

#### 06.10.3. Chính sách lưu trữ raw tx và calldata

| Dữ liệu | Nơi lưu | TTL |
|---|---|---|
| `calldata_hex` (có thể 2–4 KB với Zether) | `blockchain_relay_blob`, janitor xoá | 24h |
| `raw_tx` đã ký | `blockchain_relay_blob`, janitor xoá | 24h (đủ cho mọi vòng replacement) |
| Cả hai, cho job R3/R4 | `ir.attachment` trên Garage (S3), Many2many như quy ước repo | 7 năm (nghĩa vụ kế toán) |
| Cả hai, cho job R1/R2 | Không giữ sau 24h | — |
| `sim_trace` của job có divergence | `ir.attachment` | 1 năm |

Lý do R1/R2 không giữ: một record `blockchain.relay.job` có `tx_hash` là đủ để tái tạo mọi thứ từ chain. Giữ raw tx của 8,7 triệu job/năm là giữ 35 GB để không bao giờ đọc.

Job `final` quá 90 ngày: chuyển sang bảng lịch sử bằng cron tháng (`_cron_relay_archive()`), giữ `job_uuid`, `tx_hash`, `origin_ref`, `actual_cost_uusd`, `state`. Không dùng `active=False` — một bảng 8 triệu row với `active` index vẫn làm mọi `search()` chậm.

---

### 06.11. [MỚI] Test: cái gì phải có trước khi chạm mainnet

Không phải một kế hoạch QA đầy đủ; chỉ là những thứ **không thể** kiểm chứng sau khi lên production.

| Hạng mục | Công cụ | Kịch bản bắt buộc |
|---|---|---|
| Nonce lease/freelist | test Rust trên actor + Postgres thật | Ký timeout giữa chừng; SIGKILL sau `signed` trước broadcast; **tiến trình thứ hai xin cùng khoá phải bị advisory lock từ chối** |
| Cold start | anvil + `anvil_setNonce` | Kill tiến trình khi có 5 job inflight; khởi động lại; kiểm tra không nonce nào bị cấp lại và freelist rỗng |
| **Pool khoá** | anvil | Một khoá kẹt ở `stuck_at_ceiling` → job mới **phải** đi sang khoá khác trong < 1 chu kỳ; bộ đếm least-in-flight không đếm khoá `draining` |
| Replacement / bump | anvil `--block-time 1` + `anvil_setNextBlockBaseFeePerGas` | Base fee tăng 12,5%/block × 15 block; xác nhận không bao giờ bị `replacement underpriced` |
| Reorg | anvil `evm_snapshot` / `evm_revert` | `latest` giảm 3 block sau khi job đã `mined`; job phải về `reorged`, không về `final` |
| RPC nói dối | 2 anvil khác nhau sau một proxy | Lớp 2 và lớp 3 phải eject đúng endpoint, và **không** eject khi chỉ là reorg nông 1 block |
| Velocity limit | Postgres thật, 200 task song song | Tổng chi tiêu **không được** vượt cap quá 1 job. Kiểm tra refund khi job fail, và **không deadlock** (thứ tự khoá cố định, §06.4.3) |
| Zether epoch | anvil + contract thật | Trì hoãn tx quá `epoch_deadline_block`; phải cancel, không được speed-up |
| Batch griefing | Foundry | Item có `gasLimit` sát trần → `batch: gas grief` revert, không phải item cuối im lặng fail |
| **Chain private 9000** | chain thật | Dò `pending_nonce_accurate` (§06.1.6); xác nhận adapter phát **legacy tx**, không phải type-2; xác nhận `base_fee_next_block()` không được gọi |
| Odoo constraint | Odoo test + SQL | `SELECT conname FROM pg_constraint WHERE conrelid LIKE 'blockchain_%'` phải có đủ các UNIQUE/CHECK đã khai |

Kiểm tra cuối cùng, bắt buộc, không thể bỏ: **chạy pool trên testnet Gnosis (Chiado) liên tục 72 giờ với fault injection ngẫu nhiên** (kill tiến trình node, chậm RPC, base fee spike giả lập, ngắt làn custody). Chỉ số nghiệm thu: `relay_signed_orphan_total == 0` và `nonce_gap_age` p99 < 120s.

---

### 06.12. Những chỗ note chưa chốt, và đề xuất

1. **Ai là chủ sở hữu nonce khi cả Open Relayer lẫn Relay Pool nội bộ đều nhìn thấy một intent?** Đề xuất: intent nội bộ mặc định điền `relayer = <địa chỉ pool>` trong `T_exclusive = 2 * block_time`; hết hạn thì consumer ký lại bản `relayer = address(0)` và thả ra mesh công khai (§05). Ký hai lần là chi phí CPU, rẻ hơn một tx trùng.

   **[MỚI]** Ký hai lần cũng có nghĩa là **hai chữ ký cho một hành động** — nhưng đó là chữ ký của *user*, không phải của HSM. Bản 1 tính nhầm nó vào ngân sách ký của relayer. Với session key của user thì nó gần như miễn phí; chỉ khi user ký bằng HSM (tài khoản treasury) thì mới phải tính vào §06.6.1.

   **[Bản 2]** Với pool khoá và wildcard relayer, phương án này có một biến thể rẻ hơn hẳn: ký **một** lần với `relayer = address(0)` và để pool nội bộ dùng **private pool** (`_USER-DECISIONS.md` §21.4) trong `T_exclusive`, rồi promote-to-open. Không phải ký lại lần nào, và nó dùng đúng cơ chế đã có.
2. **Không có định nghĩa "gap-filler" nào trong note.** Đã chốt ở §06.1.7 (self-send 21.000 gas, giá = `max(p75, ceil_bump(last_known))`, chi phí vào overhead của pool). Cần người duyệt dòng ngân sách này.
3. **`meta_nonce` tăng trước hay sau `call`?** Đây là **quyết định contract, nhưng relay pool không thể an toàn nếu chưa chốt.** Ba lựa chọn:
   - (a) Tăng **sau**, chỉ khi `call` thành công: user không bị đốt nonce, nhưng **relayer trả gas cho một tx revert và không được gì** → open relayer sẽ không bao giờ nhận intent của ta.
   - (b) Tăng **trước**, thu phí kể cả khi `call` fail (đề xuất ở §06.6 mục 1 (c)): relayer luôn được trả, nhưng một relayer độc có thể đốt nonce và **phí** của user bằng cách nộp tx chắc chắn revert.
   - (c) Tăng trước + thu phí + **`antiGriefBond`**: `msg.sender` phải stake một khoản; nếu `call` fail thì bond bị tịch thu về user. Đề xuất con số: `bond = 3 * fee`, hoàn lại ngay trong cùng tx nếu thành công (chi phí ~5.000 gas cho 2 SSTORE warm).

   **Đề xuất chọn (c)**, nhưng nó làm contract phức tạp hơn và cần một lần audit riêng. Nếu chọn (b) thì relay pool phải điền tên relayer cho mọi thứ có giá trị, tức bỏ phần lớn lợi ích của Open Relayer Network — **và mất luôn khả năng xoay khoá** (`_USER-DECISIONS.md` §21.5), vì tên relayer trong digest khoá cứng một địa chỉ ký.

   Điểm cuối là một lý lẽ mới mà bản 1 không có, và nó nghiêng cán cân về (c) rõ hơn hẳn.
4. **Chi phí Zether thật** cần benchmark trên Foundry trước khi khoá `max_gas_per_tx`. Con số 3,5M (n=64) và 6,6M (n=128) ở §06.4.5 là ước tính từ số điểm MSM × 6.000 gas — nó bỏ qua mọi tối ưu batching precompile và có thể sai 30% về một phía. **[MỚI]** Và câu hỏi lớn hơn nằm trước nó: **n=64 hay n=128?** Đó là một quyết định sản phẩm (dust 10^-6), không phải quyết định kỹ thuật. §01.1.8 đã trả lời theo một khung khác (`decimals` + `SHIELD_SCALE` + `MAX_DECRYPTABLE_SHIELDED`) — đọc ở đó.
5. **Phân tầng custody** (HSM cho treasury, enclave cho relayer hot) cần người duyệt về compliance — đây là đánh đổi throughput 3 bậc độ lớn. §07.0 đã đề xuất cùng hướng; cần một chữ ký. **[Bản 2]** Thêm một tầng thứ ba: khoá file cho node mesh cá nhân (§06.6 mục 3). Nó không cần compliance duyệt vì nó không phải khoá của ta — nhưng `KeyPool` phải hỗ trợ nó.
6. **[MỚI] Bulletproofs hay Groth16?** Note dùng cả hai ngôn ngữ (§10.5.2 nói Bulletproofs, con số gas lại là Groth16). Chênh lệch **~30 lần gas**. Bulletproofs: không trusted setup, prove nhanh, verify đắt. Groth16: trusted setup per-circuit (ceremony), prove chậm (bất lợi trên mobile), verify rẻ. Với private chain (gas không quan trọng) Bulletproofs thắng dễ dàng.

   **[Bản 2]** Trên factory mở, câu hỏi này **nhẹ đi rất nhiều**: hai verifier là hai entry catalogue, người tạo token chọn, và cả hai cùng tồn tại (§01.1.5). Không cần chốt một cái trước khi viết contract — cần chốt cái nào **ta audit và đứng sau trước**, và đó là câu hỏi ngân sách chứ không phải kiến trúc.
7. **[MỚI] Ai sở hữu ngân sách gas?** Velocity limit có ba tầng (agent, tenant, global) nhưng không ai nói tenant có *mua* hạn mức không, hay đó là chi phí của nền tảng. Nếu là chi phí nền tảng thì `relay_cost_per_business_action_usd` là một dòng lỗ/lãi thật và phải có người chịu trách nhiệm. Nếu tenant trả thì cần một mô hình tính phí và nó chạm vào §09 (payment modes).
8. **[MỚI] Chính sách khi một job R3 giá trị lớn rơi vào `quarantined`.** Hiện tại: "người phải vào xem". Chưa đủ cho một khoản B2B settlement. Cần một SLA: bao lâu thì phải có quyết định, ai quyết, và có đường trả tiền bằng kênh khác (bank transfer) không. Đó là quy trình nghiệp vụ, không phải code, nhưng thiếu nó thì `quarantined` là một hố đen.
9. **[MỚI] Đồng hồ.** Hedera (`validStart`), TON (`timeout` của Highload V3), và mọi `expiry`/`deadline` của meta-tx đều phụ thuộc đồng hồ của relay worker. Chưa ai nói ai bảo đảm NTP. Đề xuất: chronyd với >= 3 nguồn, alert khi `|offset| > 500 ms`, và relay worker **tự tắt** khi `|offset| > 5 s`.
10. **[MỚI] Private chain: ai là validator?** Quyết định khoá #5 đưa private chain lên trước, nhưng "private" chưa được định nghĩa. **[Bản 2] Câu hỏi này giờ đã có một phần đáp án, và đáp án đó không dễ chịu:** chain thật là Nethermind + Clique với **một signer** (§01.1.16). Nghĩa là ở hình thái hiện tại, "blockchain" đúng là một sổ cái có chữ ký của một bên — toàn bộ phần RPC divergence (§06.7) và Finality Gate mất phần lớn ý nghĩa. Chúng chỉ có giá trị khi có N signer của N đối tác. Đây vẫn là câu hỏi phải chốt, nhưng giờ nó là câu hỏi *"khi nào thêm signer thứ hai"*, không phải *"chọn client nào"*.

---
### 06.13. [MỚI] Tổng hợp những chỗ bản này đã sửa so với bản trước

| # | Chỗ | Bản trước | Bản này |
|---|---|---|---|
| 1 | `lease_nonce.lua` fence | `INCR` fence mỗi lần lease → kiểm tra fence vô tác dụng | `owner_fence` chỉ tăng khi đổi chủ; thêm `gen` cho cold start |
| 2 | Trả lease khi lease hết hạn | Luôn `ZADD free` nếu chưa lên chain | **Không bao giờ** trả freelist nếu đã `signed`; chỉ thoát bằng replacement |
| 3 | Cold start | Không có | Giao thức đầy đủ §06.1.2, dựa trên journal Postgres |
| 4 | Quyền sở hữu shard | Consistent hash | Ownership lease có TTL + fencing |
| 5 | `ttl_ms` L1 | 45s | 37s (số học đúng: `3*12000+1100`) |
| 6 | TON Highload V3 | "~8k slot query_id" | **8.388.608 slot (23 bit)**, cửa sổ 128s |
| 7 | Celo | L1 IBFT 2.0, 5s block | **OP Stack L2 từ 03/2025**, 1s block, có L1 data fee |
| 8 | Arbitrum + Base | Gộp làm một ("không có mempool") | Ba nhóm khác nhau (§06.2.2); OP Stack **có** replacement, Arbitrum thì không đáng tin |
| 9 | Hàm `bump()` | So sánh tip với cap của max_fee; nhân float | Trần riêng cho tip; số nguyên `ceil_bump`; `BumpCeilingReached` |
| 10 | Chi phí L1 data trên rollup | Không nhắc | §06.2.5, có địa chỉ predeploy và biên độ 1000x |
| 11 | Giả định dropped vs underpriced | Gộp làm một | Tách: `underpriced` phải bump, không phải re-broadcast |
| 12 | EIP-196 định giá `ecAdd`/`ecMul` | Gán cho EIP-196 | **EIP-1108** mới là cái hạ xuống 150/6.000; EIP-196 gốc là 500/40.000 |
| 13 | Gas Zether | 2,0–2,5M | 3,5M (n=64+fee) / **6,6M (n=128+fee)**; note bỏ sót ba range statement của cơ chế fee |
| 14 | Note "180–250k gas" | "chỉ đúng cho vài ecAdd/ecMul" | Chính xác hơn: **đó là con số của Groth16**, không phải Bulletproofs. Hai thứ trong note mâu thuẫn nhau |
| 15 | Velocity limit | `INCRBYFLOAT`, kiểm tra riêng | ~~Lua nguyên tử~~ → **[BẢN 3]** một transaction Postgres (§06.4.3); micro-USD số nguyên, reserve + settle + janitor refund |
| 16 | `balance_native` | `fields.Float(digits=(24,8))` | Mâu thuẫn §10.4.1 → `Char` base units + `Float` chỉ để hiển thị |
| 17 | `runway_hours` | `required=True` rồi phải cảnh giác NULL | Bỏ `required=True`; quy tắc "gán ở mọi nhánh" vẫn giữ |
| 18 | Idempotency `origin_ref` | Nói "idempotent" không nói bằng gì | Partial unique index `_unique_origin` |
| 19 | `witness_depth` | Hằng số 12 block | Theo chain; và lệch một lần không được eject ngay |
| 20 | Kiểm tra RPC | 3 lớp | 4 lớp, thêm **canary `eth_call`** — 3 lớp cũ không bắt được state sai |
| 21 | Batch executor | Chỉ nói `try/catch` | ~~EIP-150 63/64 guard, fee-on-failure~~ → **[BẢN 4] hết đối tượng**: không còn inner `CALL` (§24). Còn lại: cách sim một batch |
| 22 | Backpressure | Không có | `max_inflight = 16` (cơ sở: `txpool.accountslots`); **[BẢN 3]** `inflight_full` đếm trong actor, không phải Lua |
| 23 | Tenderly | Ở hot path | **Ra khỏi hot path** — chi phí 720k đơn vị/tháng; hot path dùng node của mình |
| 24 | Lưu trữ | Không nhắc | §06.10.3; raw tx không nằm trên record |
| 25 | Reorg | Không nhắc trong nonce manager | `latest < confirmed` → `reorged`, không lùi `next` |

### 06.14. [BẢN 2] Những chỗ sửa sau khi user chốt kiến trúc mesh và pool khoá

| # | Chỗ | Bản trước | Bản này |
|---|---|---|---|
| 26 | Vai của relay pool | Một loại hạ tầng riêng, song song với Open Relayer | **Một cấu hình** trong ma trận vai (`_USER-DECISIONS.md` §21.4): `ingest: http, pool: none, submit: true`. Mọi cơ chế ở đây cũng cần cho node mesh có submit |
| 27 | Pool khoá ký | Xem sharding K EOA là "chỉ giải head-of-line blocking" | Head-of-line blocking **là** trần thông lượng cứng của EVM. Batch giải nút chữ ký, pool khoá giải nút nonce — hai nút khác nhau, cần cả hai (§06.6 mục 2) |
| 28 | `blockchain.relayer.account` | Không có khái niệm "N khoá của một relayer" | Thêm `relayer_id`. Thiếu nó, cap per-relayer (§05.7), lottery (§05.4.4) và đối soát gas (§05.8.3) đều đếm một relayer thành N |
| 29 | Xoay khoá 30 ngày | Một thủ tục bảo trì | Với pool 50 khoá là **một khoá rời pool mỗi ~14 giờ** → phải tự động hoàn toàn, cần đệm `N+2` khoá, và `draining` phải rời ZSET chọn khoá |
| 30 | Custody | Hai tầng: HSM (treasury) / enclave (relayer hot) | Ba tầng — thêm **khoá file** cho node mesh cá nhân. Chấp nhận được **chỉ vì** ba ràng buộc của `_USER-DECISIONS.md` §21.5 (float nhỏ, không phải `feeRecipient`, không role nào) |
| 31 | Chain private | Giả định Besu QBFT, gasLimit 200M, block 2s, finality 1 block | **Nethermind + Clique, một signer, 16,7M gas, block 5s, chạy trước London** (§01.1.16). Không EIP-1559 → không type-2 tx, không `base_fee`, không spike breaker. Clique **không** có instant finality |
| 32 | `mode` bitmask | `MODE_RESTRICT_RELAYER`, `MODE_OPEN` | Bitmask bị loại (`_USER-DECISIONS.md` §5). Wildcard `relayer == address(0)`, và đó **là điều kiện để pool khoá tồn tại** (§06.1.8) |
| 36 | §06.12 mục 10 (ai là validator) | Câu hỏi mở hoàn toàn | Có một phần đáp án, và nó không dễ chịu: **một signer**. Câu hỏi đổi từ "chọn client nào" thành "khi nào thêm signer thứ hai" |

---

## 06.15. [BẢN 3] Chuẩn Tắc Nâng Cấp V3: Multi-Wallet KeyPool là Chuẩn Sản Xuất & Tùy Chọn Redis Fencing

*(Chi tiết đầy đủ xem `SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md` §2 và `ai-enterprise-blockchain-architecture.md` §5.3)*

### 06.15.1. Mô Hình Khuyến Nghị Chuẩn Sản Xuất: Mạng Lưới Ví Relayer Đa Điểm (Multi-Wallet KeyPool)
- **Kiến trúc cốt lõi:** Thay vì cố gắng chia sẻ một ví duy nhất cho nhiều worker dẫn đến tranh chấp lock Redis, Relayer duy trì một bể gồm $N$ ví hot độc lập (`relayer_1`, ..., `relayer_N`).
- **Phân bổ không khóa (Lock-Free):** Bộ điều phối phân bổ lệnh theo Round-Robin hoặc Least-in-flight. Do mỗi ví sở hữu một chuỗi EVM nonce độc lập trên chuỗi, **các worker song song không bao giờ dẫm chân lên nhau**.
- **Cơ chế Treasury Signer tự động nạp vốn (Auto-Refill):**
  * Mỗi ví hot chỉ lưu trữ lượng gas đủ chạy trong 4 giờ (`low_watermark`, $50 USD).
  * Khi số dư chạm ngưỡng, Treasury Signer (HSM FIPS 140-3 L3 / ví lạnh Multi-Sig 2-of-3) tự động ký lệnh nạp native gas với trần `auto_refill_cap_usd` ($500 USD) và guard `max_pending_refill = 1`.

### 06.15.2. Mô Hình Tùy Chọn Phụ Trợ: Redis Lease Kèm Generation Fencing
- Chỉ kích hoạt khi bị giới hạn hạ tầng hoặc đối tác chỉ cấp một địa chỉ ví relayer duy nhất.
- Sử dụng Redis Lease có thời hạn ngắn (TTL 5s) và Generation Fencing Token tăng đơn điệu để triệt tiêu nguy cơ Zombie Worker gửi trùng nonce làm hỏng chuỗi giao dịch.

### 06.15.3. Doanh Nghiệp Tự Vận Hành Inbound Relayer Đa Chuỗi & Gom Lô Giao Dịch (Enterprise Multi-Chain Inbound Batch Settlement)
- **Kiến trúc tiếp nhận trực tiếp:** Doanh nghiệp cung cấp API nội bộ `POST /api/v1/blockchain/inbound-meta-tx` (hoặc `/api/v1/blockchain/{chainId}/inbound-meta-tx`) tiếp nhận chữ ký EIP-712 trực tiếp từ khách hàng và đại lý, hỗ trợ tường minh tham số `chainId` và `tokenContract`.
- **Hàng Đợi Gom Lô Cách Ly Theo `(chainId, tokenContract)`:**
  * Do mỗi chuỗi EVM và mỗi hợp đồng token có state và bytecode riêng, hệ thống tuyệt đối không gom chung giao dịch khác chain hay khác token vào một batch.
  * Hàng đợi gom lô được phân vùng theo khóa: `inbound:queue:{chainId}:{tokenContract}` (Batch Window 3–5 giây, Max 50 items).
- **Điều Phối Ví Theo Chuỗi `KeyPool(chainId)`:**
  * Mỗi chuỗi EVM có cụm ví hot riêng chứa native gas của chuỗi đó (xDAI cho Gnosis, CELO cho Celo, ETH cho Base/Arbitrum, coin nội bộ cho Chain 9000).
  * Worker chuyên trách chuỗi rút ví khả dụng từ `KeyPool(chainId)` để phát lệnh `tokenContract.batchMtxPay(payments[])`.
  * Tiết kiệm 40%–60% gas tổng thể, loại trừ 100% rủi ro va chạm nonce giữa các worker. Sau Finality Gate, Odoo Projector tự động đối chiếu các `payId` và thực thi gạch nợ hóa đơn hàng loạt vào đúng Sổ nhật ký kế toán tương ứng.