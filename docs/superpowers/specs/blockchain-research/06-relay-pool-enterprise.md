## 06. Relay Pool noi bo: nonce manager, gas circuit breaker, simulation gate

> **Trang thai ban nay:** ban nhap dau bi ra soat lai theo huong "hostile review". Nhung cho da sua duoc danh dau **[SUA]**; nhung cho la bo sung moi danh dau **[MOI]**. Bay cai sai ky thuat trong chinh ban nhap dau da duoc go, liet ke tap trung o §06.13.
>
> Quy uoc dat ten: prefix model `blockchain.*` (theo chot cua §10.3 — **khong** phai `dms.blockchain.*` nhu §05 dang viet). `dms_blockchain` **khong depend `dms`**.

---

### 06.0. Pham vi, ranh gioi process, va rang buoc standalone

Relay Pool noi bo la cum may **ung truoc native gas** cho cac giao dich cua chinh doanh nghiep. No khong phai la Open Relayer Network (§10.1 muc 1 cua note) — Open Relayer la ben thu ba tu quyet dinh loi nhuan; Relay Pool noi bo la ha tang phai co SLA. Hai thu chay song song va **canh tranh cung mot intent**: neu Open Relayer nhat intent truoc, job noi bo phai bi huy sach chu khong phat song trung.

Quyet dinh kien truc dau tien, va note khong noi ro: **vong lap broadcast KHONG duoc chay trong `ir.cron`.**

| Thanh phan | Chay o dau | Ly do |
|---|---|---|
| Control plane: chain config, policy, relayer account, job record, audit, breaker state | Odoo 19 addon `dms_blockchain` | Can ACL, record rule, view, multi-company, audit trail |
| Hot loop: lease nonce, sign, broadcast, watch receipt, replace | Service Python asyncio doc lap `relay-pool` | Odoo worker la sync/blocking, `ir.cron` toi thieu 1 phut va chay trong transaction dai; mot tx bi treo se giu lock hang row |
| State chia se | Redis (nonce, lease, spend counter, breaker), PostgreSQL (job of record) | Redis cho hot path, Postgres cho su that cuoi cung |
| Cron Odoo | Chi reconcile + janitor, moi 1-5 phut | XML goi dung mot dong: `model._cron_relay_reconcile()` |

Rang buoc standalone (khoa cung): `dms_blockchain` **khong depend `dms`**. Relay Pool khong biet gi ve `dms.trade.settlement` hay `dms.payment.collection`. Job mang mot con tro long leo `origin_model` (Char) + `origin_res_id` (Integer) + `origin_ref` (Char, idempotency key do consumer cap). Khong co Many2one nguoc ve consumer, khong co `ir.model.data` cross-addon.

Duong dan:

```
/home/dockers/odoo19/custom-addons/dms_blockchain/       # addon Odoo (control plane)
    models/blockchain_chain.py
    models/blockchain_rpc_endpoint.py
    models/blockchain_relayer_account.py
    models/blockchain_relay_job.py
    models/blockchain_gas_policy.py
    models/blockchain_breaker_event.py
    models/blockchain_target_policy.py            # [MOI] allowlist theo (address, selector)
    data/ir_cron.xml
/home/dockers/odoo19/relay-pool/                          # service (hot loop), Python 3.12 + asyncio
    adapters/evm.py  adapters/sui.py  adapters/soroban.py  adapters/cosmwasm.py
    adapters/ton.py  adapters/hedera.py
    nonce/redis_lease.py   nonce/reconcile.py   nonce/coldstart.py     # [MOI]
    sim/gate.py            breaker/gas.py       signer/client.py
    wal/journal.py                                                      # [MOI]
    shard/ownership.py                                                  # [MOI]
    lua/lease_nonce.lua    lua/release_nonce.lua  lua/spend_reserve.lua  # [MOI]
/home/dockers/odoo19/smartcontracts/                      # ngoai addon, theo quyet dinh da khoa
```

Dinh danh chain dung **CAIP-2** o moi noi (`eip155:100` = Gnosis, `eip155:42220` = Celo, `sui:mainnet`, `stellar:pubnet`, `cosmos:<chain-id>`, `hedera:mainnet`, `ton:-239`). Ly do: bay tro thanh mot truong `Char` duy nhat chay xuyen 7 he sinh thai, thay vi mot `Integer chain_id` chi dung duoc cho EVM. Tranh dat ten field `chain_id` cho so nguyen EVM — `chain_id` la Many2one toi `blockchain.chain`; so EVM luu tai `blockchain.chain.evm_chain_number`.

#### 06.0.1. [MOI] Giao dien Odoo <-> relay worker: phai dinh nghia, khong duoc de mo

Ban nhap dau noi "Redis Stream consumer group" roi bo do. Do la mot cau chu, khong phai giao dien. Chot:

| Huong | Kenh | Payload | Ai la su that |
|---|---|---|---|
| Odoo -> worker (dispatch) | Redis Stream `bc:jobs:{caip2}`, consumer group `relay`, mot consumer moi shard | `{job_uuid, caip2, relayer_hint, risk_class, target, calldata_ref, meta_tx_ref, deadline_ms}` | Postgres (`blockchain.relay.job`) la ban goc; Stream chi la thong bao. Worker mat message van tim lai duoc qua reconcile |
| Worker -> Odoo (status) | HTTP `POST /json/2/blockchain.relay.job/relay_report_batch`, `auth='bearer'` (JWT `bamboo_token_auth`), service account rieng | Mang toi da 200 ban ghi `{job_uuid, state, tx_hash, nonce, gas_used, cost_base_units, error_code, observed_at_ms}` | Odoo la su that cuoi. Ghi bang mot `write()` da record |
| Worker -> Odoo (khan) | Cung endpoint, `flush=True` | Chi cho `quarantined`, `nonce_desync`, `rpc_divergence` | |
| Backstop | `ir.cron` 5 phut `model._cron_relay_reconcile()` | Doc Redis + RPC, sua moi job lech | Bat buoc, khong tuy chon |

Ly do worker **khong** ghi thang vao Postgres cua Odoo: bo qua ORM la bo qua record rule, `write_date`, mail thread, va moi `@api.constrains`. Chi phi cua duong HTTP: mot round-trip 5-15 ms cho 200 job, tuc **~0.05 ms/job**. Khong dang de doi lay viec pha vo invariant cua ORM.

Ly do co `_cron_relay_reconcile` du da co callback: callback co the mat (Odoo restart giua deploy, worker OOM). Reconcile la co che dam bao **eventual consistency**; callback chi la toi uu latency. Neu chi co callback, mot lan Odoo down 90 giay se de lai mot dam job "broadcast" vinh vien.

#### 06.0.2. [MOI] Truc `chain_profile`: private lam thay doi nua so co che trong section nay

Quyet dinh khoa #5 (private chain di truoc cho Zether) khong chi doi chi phi — no doi ca mo hinh loi.

| Co che | `chain_profile = 'public'` | `chain_profile = 'private'` (PoA / IBFT / QBFT) |
|---|---|---|
| Gas price | Bien dong, phai co spike breaker | Co dinh (thuong 0 hoac 1 wei). **Tat spike breaker** |
| Velocity limit | Don vi **USD** | Don vi **gas** (khong co gia USD; runaway loop van phai chan) |
| Mempool eviction | Co, tx bi drop → can re-broadcast | Khong (txpool khong bi ep gia). Trang thai `dropped` gan nhu khong xay ra |
| Replacement | Speed-up bang fee bump | Fee bump vo nghia. "Treo" = **validator set dang ket** → alarm ha tang, khong phai bump |
| Block gas limit | Cho truoc (Gnosis ~17M) | **Ta dat**. Day la thu lam Zether kha thi (§06.4) |
| Finality | Theo bang §11 | 1 block (BFT instant), nhung **van phai qua Finality Gate** — khong duoc bo qua |
| RPC divergence check | Bat | **Van bat**. Mot validator bi chiem la kich ban de xay ra hon tren mang nho |
| Reorg | Co | Khong (BFT khong fork), tru khi governance rollback thu cong |
| MEV / front-run | Co | Khong |

Field: `blockchain.chain.chain_profile = fields.Selection([('public','Public'), ('private','Private/Permissioned')], required=True, default='public')`. Moi doan breaker/replacement duoi day guard bang profile. Khong guard = build mot dau gia gas cho mot mang ba node cua chinh minh.

#### 06.0.3. [MOI] Nhung gia dinh ban nhap dau khong noi ra

Liet ke thang, vi moi cai deu la mot cach he thong hong:

1. **Redis duoc coi la su that ve nonce.** Sai. Redis AOF `appendfsync everysec` mat toi 1 giay ghi khi kernel panic; replica async co the roll back khi failover. Neu `next` tut lui, ta cap lai nonce da dung → moi tx sau deu bi `nonce too low`, hoac te hon, cap trung nonce voi mot tx da ky khac. **Chot: chain la su that, Postgres la journal, Redis la cache co the tai tao duoc.** Giao thuc cold start o §06.1.2.
2. **Mot worker so huu mot relayer account "qua consistent hash".** Consistent hash khong phai la quyen so huu. Khi `N_workers` doi (deploy, OOM, network partition), hai worker cung tuong minh so huu mot shard trong vai giay. Do la split-brain tren nonce. Can **ownership lease co fencing** (§06.1.3).
3. **`eth_estimateGas` cho ra chi phi.** Sai tren moi L2 rollup: phi L1 data (blob/calldata) **khong** nam trong `gas` cua L2. Bo sot no lam uoc tinh chi phi thap hon thuc te 2-10 lan tren Base/Optimism/Celo-L2 (§06.2.5).
4. **Tx da ky luon co the re-broadcast.** Sai. Neu base fee da vuot `maxFeePerGas` cua tx da ky, node nhan tx nhung khong bao gio dao no. Do la trang thai `underpriced`, chua thuoc `dropped`, va cach chua la **bump**, khong phai re-broadcast.
5. **Sim la mien phi.** Tenderly khong mien phi o quy mo nay (§06.3.5). `eth_call` mot tx Zether 6M gas khong mien phi voi nha cung cap RPC va nhieu nha cung cap **cap gas cua `eth_call`** o 10M-50M.
6. **Ky la mot thao tac.** Voi MPC SaaS, mot vault thuong **serialize** yeu cau ky; song song hoa trong cung mot vault khong tang throughput. Con so 5-30 sign/s la cho ca vault, khong phai cho moi connection.
7. **Job Postgres co the giu raw tx.** O 100 job/s, 6 KB/job la 52 GB/ngay. Phai co chinh sach luu tru (§06.10.3).
8. **Gia USD luon co.** Neu oracle gia native token stale, velocity limit tinh sai. Phai co chinh sach fail-closed (§06.4.3).
9. **Tenant = company.** Chua noi ra. Chot: `company_id` tren job; velocity bucket theo `company_id`; record rule theo `company_ids` cua user.
10. **Consumer hieu dung "final".** Chua co bang anh xa state → nghia vu tai chinh. Bo sung o §06.2.6.

---

### 06.1. Nonce manager: tai sao `INCRBY` khong du

Note (§10.3 muc 2) viet: *"Duy tri bo dem tang dan bat bien (`INCRBY`) cho tung dia chi Relayer tren tung Chain ID"*. **Sai o mot cho chi mang tinh chat quyet dinh**: `INCR` cap phat, nhung khong ai tra lai. Day la **gap problem**:

```
t0  job A  INCR -> nonce 41   -> sign -> broadcast OK
t1  job B  INCR -> nonce 42   -> HSM timeout -> job B chet
t2  job C  INCR -> nonce 43   -> broadcast OK
```

Nonce 42 khong bao gio duoc phat song. Tren EVM, tx nonce 43 nam vinh vien trong mempool o trang thai *queued* (khong phai *pending*), khong bao gio duoc dao, va **moi tx sau do cua vi nay deu chet theo**. Mot loi HSM timeout duy nhat lam dong bang toan bo relayer account. Dung tren Cosmos (account sequence), Stellar (sequence number), TON (seqno) voi cung co che.

Giai phap: **nonce leasing** — cap phat co thoi han, co tra lai, co freelist.

#### 06.1.1. Cau truc Redis

```
bc:n:{caip2}:{addr}:gen         STRING  int   generation, INCR moi lan reseed tu chain (cold start)
bc:n:{caip2}:{addr}:owner       STRING  "{worker_id}|{owner_fence}|{expire_ms}"   [SUA] quyen so huu shard
bc:n:{caip2}:{addr}:confirmed   STRING  int   nonce da confirm on-chain (tu getTransactionCount 'latest')
bc:n:{caip2}:{addr}:next        STRING  int   nonce ke tiep chua tung cap
bc:n:{caip2}:{addr}:lease       HASH    nonce -> "{job_uuid}|{expire_ms}|{gen}|{owner_fence}"
bc:n:{caip2}:{addr}:free        ZSET    nonce -> score = ready_at_ms   (freelist, uu tien nonce nho nhat)
bc:n:{caip2}:{addr}:inflight    ZSET    nonce -> broadcast_ms
bc:n:{caip2}:{addr}:signed      HASH    nonce -> "{job_uuid}|{tx_hash}"  [MOI] nonce DA co raw tx da ky
```

`bc:...:signed` la key quan trong nhat ma ban nhap dau khong co. Xem §06.1.4.

Cau hinh Redis bat buoc cho namespace `bc:n:*`: `appendonly yes`, `appendfsync always` cho instance nonce (chap nhan ~5-10k ops/s thay vi 100k — ta chi can ~1.5k ops/s o 100 job/s), **khong** bat auto-failover cua Sentinel cho instance nay. Neu Redis chet, relay pool **dung lai** va cold-start lai; do la hanh vi dung. Mot Redis "van chay nhung mat 1 giay ghi" nguy hiem hon mot Redis chet han.

#### 06.1.2. [MOI] Cold start: giao thuc bat buoc khi Redis trong

Day la lo hong lon nhat cua ban nhap dau. `INCR` tren key khong ton tai tra ve 1, tuc nonce 0. Voi mot account dang o nonce 4.128, moi tx sau do bi node tra `nonce too low` va relay pool quay vong vo han.

```python
async def cold_start(caip2, addr):
    # 1. Dat account ve 'draining' trong Odoo. Khong nhan job moi.
    await odoo.set_account_state(caip2, addr, 'draining')

    # 2. Doc chain tu ENDPOINT DA PIN (khong doc tu provider khac, xem 06.7 quy tac 1)
    latest  = await rpc.eth_getTransactionCount(addr, 'latest')
    pending = await rpc.eth_getTransactionCount(addr, 'pending')

    # 3. Doc journal Postgres: moi job cua account nay chua o trang thai cuoi
    open_jobs = await odoo.jobs_not_terminal(caip2, addr)   # signed | broadcast | replaced
    max_signed = max([j.nonce for j in open_jobs if j.raw_tx_ref], default=-1)

    # 4. next = max(pending, max_signed + 1). KHONG BAO GIO nho hon.
    nxt = max(pending, max_signed + 1)

    # 5. Dung lai signed-set tu journal; moi nonce trong [latest, nxt) khong co job
    #    -> la LO THUNG THAT (worker chet truoc khi ky). Dua vao freelist.
    for n in range(latest, nxt):
        if n in {j.nonce for j in open_jobs}:
            await redis.hset(k_signed, n, f"{job.uuid}|{job.tx_hash or ''}")
        else:
            await redis.zadd(k_free, {n: 0})

    await redis.mset({k_confirmed: latest, k_next: nxt})
    await redis.incr(k_gen)                 # moi lease cu deu vo hieu
    await odoo.set_account_state(caip2, addr, 'active')
```

Buoc 5 la ly do phai co journal Postgres: chain cho biet nonce cao nhat, no khong cho biet nonce nao *cua ta*. Neu bo journal, ta khong the phan biet "lo thung" voi "tx da ky chua lan truyen".

`gen` la fencing that su: moi lease mang `gen` luc cap; truoc `eth_sendRawTransaction`, worker doc lai `gen`, khac → huy broadcast.

#### 06.1.3. [SUA] Quyen so huu shard: ownership lease, khong phai consistent hash

Ban nhap dau: *"moi relayer account duoc gan cung cho dung mot worker qua consistent hash `hash(caip2+addr) % N_workers`"*. Chua du. Khi `N_workers` doi tu 3 sang 4, gan mot phan tu shard doi chu **ngay lap tuc va khong dong bo** — worker cu chua biet minh mat shard.

Chot: ownership lease trong Redis, TTL 10s, renew moi 3s.

```lua
-- lua/acquire_owner.lua  KEYS: owner, owner_fence   ARGV: worker_id, now_ms, ttl_ms
local cur = redis.call('GET', KEYS[1])
if cur then
  local w, f, exp = cur:match('([^|]+)|([^|]+)|([^|]+)')
  if w == ARGV[1] then                              -- renew
    redis.call('SET', KEYS[1], w..'|'..f..'|'..(tonumber(ARGV[2])+tonumber(ARGV[3])))
    return tonumber(f)
  end
  if tonumber(exp) > tonumber(ARGV[2]) then return -1 end   -- nguoi khac dang giu
end
local f = redis.call('INCR', KEYS[2])               -- doi chu -> fence moi
redis.call('SET', KEYS[1], ARGV[1]..'|'..f..'|'..(tonumber(ARGV[2])+tonumber(ARGV[3])))
return f
```

**`owner_fence` chi tang khi doi chu**, khong tang moi lan lease. Ban nhap dau lam nguoc (`local fence = redis.call('INCR', KEYS[4])` trong `lease_nonce.lua`) — voi hai job dong thoi, fence luon doi giua luc lease va luc broadcast, nen kiem tra fence hoac luon fail hoac bi bo qua. Do la mot bug, khong phai mot bao ve.

Giao thuc mat shard (worker cu): khi renew tra `-1`, worker **dung ngay**, khong broadcast job dang cam, `NACK` tat ca message trong Redis Stream. Job dang o `signed` **khong** duoc tra freelist (§06.1.4) — chu moi se tiep quan qua journal.

#### 06.1.4. [SUA] Lua cap lease va ba (bon) duong tra lease

```lua
-- lua/lease_nonce.lua
-- KEYS: next, lease, free, gen, owner, signed, confirmed
-- ARGV: job_uuid, ttl_ms, now_ms, worker_id, max_inflight
local cur = redis.call('GET', KEYS[5])
if not cur then return {-1, 'no_owner'} end
local w, ofence = cur:match('([^|]+)|([^|]+)|')
if w ~= ARGV[4] then return {-1, 'not_owner'} end

local confirmed = tonumber(redis.call('GET', KEYS[7]) or '0')
local nxt       = tonumber(redis.call('GET', KEYS[1]) or tostring(confirmed))
if nxt - confirmed >= tonumber(ARGV[5]) then return {-1, 'inflight_full'} end   -- backpressure

local nonce
local free = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', ARGV[3], 'LIMIT', 0, 1)
if #free > 0 then
  nonce = tonumber(free[1])
  if redis.call('HEXISTS', KEYS[6], free[1]) == 1 then return {-1, 'signed_conflict'} end
  redis.call('ZREM', KEYS[3], free[1])
else
  nonce = redis.call('INCR', KEYS[1]) - 1
end
if nonce < confirmed then return {-1, 'stale_nonce'} end                        -- guard cold start

local gen = redis.call('GET', KEYS[4]) or '0'
redis.call('HSET', KEYS[2], nonce,
  ARGV[1]..'|'..(tonumber(ARGV[3])+tonumber(ARGV[2]))..'|'..gen..'|'..ofence)
return {nonce, tonumber(gen), tonumber(ofence)}
```

Ba thu them so voi ban nhap dau, moi thu chan mot kieu hong that:
- `inflight_full` — backpressure. Geth mac dinh `--txpool.accountslots = 16`: qua 16 tx pending cho mot account, node **im lang bo** cac tx thua. Cap nonce 17 la cap mot nonce chac chan roi vao hu vo. `max_inflight` mac dinh **16**, khong phai mot con so tuy y.
- `signed_conflict` — khong bao gio cap lai mot nonce da co raw tx da ky.
- `stale_nonce` — chan hau qua cua Redis reseed sai.

`ttl_ms` mac dinh = `3 * block_time + sign_p99 + sim_p99`. **[SUA]** Gnosis: `3*5000 + 800 + 300 = 16.1s`. Ethereum L1: `3*12000 + 800 + 300 = 37.1s` (ban nhap dau ghi 45s — sai so hoc, doi thanh 37s, lam tron 40s).

Bon duong tra lease:

| # | Tinh huong | Job da ky chua? | Hanh dong |
|---|---|---|---|
| 1 | Broadcast thanh cong | Roi | `HDEL lease`, `ZADD inflight nonce now`, giu nguyen `signed` |
| 2 | That bai **truoc khi ky** (sim fail, breaker, policy, lease timeout truoc `sign`) | Chua | `ZADD free nonce 0`. Tai su dung ngay. **Day la duong `INCR` khong co** |
| 3 | That bai **sau khi ky, truoc broadcast** (HSM tra chu ky roi worker chet) | Roi | **KHONG tra freelist.** Ghi `signed[nonce]`, dua job ve `signed_orphan`. Chi thoat bang **replacement** o cung nonce, hoac cho no duoc dao |
| 4 | Lease het han (worker chet giua chung) | Kiem tra `signed` | Co trong `signed` → nhu (3). Khong co → truy van RPC (`getTransactionCount(pending)` + `eth_getTransactionByHash` neu co hash) → chua len chain thi `ZADD free nonce 0` |

**[SUA] Duong (3) la sua sai quan trong nhat cua section nay.** Ban nhap dau viet: *"Lease het han → neu chua len chain → `ZADD free nonce 0`"*. Neu raw tx da duoc ky va nam dau do (Redis, WAL, log, mot retry dang ngu), tra nonce ve freelist tao ra **hai tx da ky khac nhau tren cung mot nonce**. Cai nao vao block truoc thi thang. Neu cai thang la cai ta tuong da huy, ta vua thuc thi mot hanh dong nghiep vu da bi huy — chuyen tien khong ai duyet. Do la loi tai chinh, khong phai loi van hanh.

Quy tac tong quat: **mot nonce roi vao trang thai `signed` thi chi con mot duong ra la mot tx duoc dao tai nonce do.** Muon huy, phai *thay the* (§06.2.4), khong duoc *bo qua*.

#### 06.1.5. [MOI] Write-ahead: thu tu ghi bat buoc

Khong co thu tu nay thi khong the phuc hoi sau crash:

```
1. Postgres  : job -> 'simulated'                    (co sim_block_height)
2. Redis     : lease nonce                            (Lua tren)
3. Postgres  : job -> 'nonce_leased', luu nonce + gen + owner_fence
4. Signer    : ky
5. Redis     : HSET signed[nonce]                     <-- TRUOC khi ghi Postgres
6. Postgres  : job -> 'signed', luu tx_hash + raw_tx_ref
7. Redis     : GET gen, GET owner  -> kiem tra khop
8. RPC       : eth_sendRawTransaction (fan-out)
9. Redis     : HDEL lease, ZADD inflight
10. Postgres : job -> 'broadcast'
```

Buoc 5 truoc buoc 6 la co y: neu crash giua 5 va 6, reconcile thay `signed[nonce]` khong co job tuong ung → **quarantine account**, bat nguoi xu ly. That bai on ao tot hon that bai im lang. Nguoc lai (6 truoc 5) tao ra mot job "signed" ma nonce manager khong biet, va nonce do co the bi cap lai.

`raw_tx_ref` **khong** phai raw tx. No la key Redis `bc:raw:{job_uuid}` (TTL 24h) + `ir.attachment` tren Garage cho job R3/R4. Ly do o §06.10.3.

#### 06.1.6. Reconciliation voi chain

Moi `reconcile_interval` (mac dinh 5 block-time, toi thieu 10s):

```python
latest  = rpc.eth_getTransactionCount(addr, 'latest')    # da dao
pending = rpc.eth_getTransactionCount(addr, 'pending')   # geth: latest + so tx pending LIEN TUC
```

| Dieu kien | Ket luan | Hanh dong |
|---|---|---|
| `latest > confirmed` | tx da dao | Cap nhat `confirmed`, xoa `inflight` va `signed` < latest, dong job |
| **[MOI] `latest < confirmed`** | **reorg** — tx da dao bi dao nguoc | Khong panic. `confirmed = latest`; moi job da bao `mined` nhung chua `final` chuyen ve `reorged`; **khong** cap nhat nguoc `next`. Bao Finality Gate (§11) |
| `pending == latest` va `inflight` khong rong | mempool da drop tx cua ta | **[SUA]** Truoc khi re-broadcast: so `maxFeePerGas` cua raw tx voi `base_fee_next`. Neu `maxFee < base_fee` → **khong phai dropped, la `underpriced`** → phai bump (§06.2.3), re-broadcast se vo ich |
| `next > pending` va gap ton tai > `gap_timeout` (60s) | **nonce gap that su** | Phat *gap-filler* (§06.1.7) |
| `latest > next` | co ai khac dung vi nay | **Alarm P1**, `state=quarantined`, dong bo `next = latest`, **khong** tu dong resume |
| **[MOI]** `signed[n]` ton tai voi `n < latest` nhung khong co receipt cho `tx_hash` do | tx cua ta bi **thay the boi nguoi khac** o cung nonce | Alarm P1 bao mat: hoac khoa bi lo, hoac co worker ma. Quarantine |

`pending` cua geth chi dem chuoi lien tuc tu `latest`; mot nonce thung lam `pending` dung lai ngay do — chinh la tin hieu phat hien gap re nhat, khong can quet mempool. **Canh bao:** khong phai node nao cung the. Erigon va mot so RPC managed tra `pending` = `latest` luon. Adapter phai **do kha nang nay luc khoi dong** (`rpc.capabilities.pending_nonce_accurate`) bang cach gui mot tx test tren testnet hoac so sanh voi `txpool_content` neu co; khong do duoc thi lui ve quet `inflight` theo hash.

#### 06.1.7. [MOI] Gap-filler: dinh nghia day du

Ban nhap dau de mo. Chot:

```python
def gap_filler_tx(addr, nonce, chain, last_known_fee=None):
    base = rpc.base_fee_next_block()
    p75  = rpc.fee_history_percentile(75, blocks=20)
    tip  = max(p75.tip, chain.min_tip_wei)
    if last_known_fee:                      # lo thung do tx bi drop, khong phai chua tung ky
        tip = max(tip, ceil_bump(last_known_fee.tip))
    return {'to': addr, 'value': 0, 'data': b'', 'gas': 21000,
            'nonce': nonce, 'maxPriorityFeePerGas': tip,
            'maxFeePerGas': min(base * 2 + tip, chain.absolute_max_fee_wei)}
```

Chi phi: 21.000 gas. Gnosis @ 2 gwei = 0.000042 xDAI. Ai tra? **Overhead cua pool, khong tinh vao tenant** — tenant khong gay ra lo thung. Ghi vao `blockchain.breaker.event(kind='gap_filler')` de theo doi: `gap_filler` tang la trieu chung, khong phai giai phap.

Tren chain khong phai EVM: Cosmos khong the "fill" mot sequence — phai gui mot tx that (vd `MsgSend` 1 uatom cho chinh minh). Stellar: `BumpSequence` operation, dung chinh xac cho viec nay, chi phi 100 stroops. TON: gui external message rong toi wallet. Sui: **khong co gap** (khong co nonce). Hedera: khong co gap (`validStart`).

#### 06.1.8. Ngu nghia sequence tung chuoi — khong dong nhat

| Chuoi | Don vi thu tu | Tx revert co tieu don vi? | Song song trong 1 tai khoan | Cach relay pool xu ly |
|---|---|---|---|---|
| EVM | `nonce` per EOA, tuan tu tuyet doi | Co (revert van dao, van tieu nonce) | Toi da `txpool.accountslots` = **16** pending | Lease + freelist + `signed` set |
| Cosmos SDK | `account sequence` | Co, neu tx vao block; **khong** neu bi CheckTx tu choi | Khong | Giong EVM; CheckTx fail phai tra lease (duong 2). Luu y `sequence mismatch` la loi CheckTx pho bien nhat |
| Stellar/Soroban | `sequence number` cua source account | Co, neu vao ledger | Khong | Fee-bump khong doi sequence cua inner tx. Gap-filler = `BumpSequence` |
| TON | `seqno` trong wallet contract | Co | Khong, **tru Highload Wallet V3** | **[SUA]** Highload V3 dung `query_id` **23 bit = 8.388.608 slot** trong mot cua so `timeout` (mac dinh 128 s, toi da 1300 s) — khong phai "~8k slot" nhu ban nhap dau viet, lech 1000 lan. Highload V3 la lua chon bat buoc cho throughput |
| SUI | **Khong co nonce.** Thu tu = version cua gas coin va owned object | n/a | Co, neu moi tx dung **gas coin khac nhau** | Quan ly *pool gas coin* (§06.5) |
| Hedera | `TransactionId = payerAccount + validStart` (nanos) | n/a, duplicate bi tu choi | Co | Cap phat `validStart` doc nhat. **`validStart` phai o qua khu va trong `transactionValidDuration`** (mac dinh 120 s, max 180 s) — dong ho lech > 10 s lam tx bi tu choi hang loat. Bat buoc chronyd/NTP tren relay worker |
| EIP-1776 meta-tx | `meta_nonce(from, batchId)` — **khong gian nonce THU HAI** | Co | Co, qua `batchId` khac nhau | Xem duoi |

**Note gop hai khong gian nonce lam mot.** `meta_nonce(from, batchId)` la nonce cua *nguoi dung* trong contract; nonce EOA la cua *relayer*. Chung doc lap. Relay Pool phai quan ly ca hai:

- Nonce relayer EOA: Redis lease nhu tren.
- `batchNonce`: **khong** do relay pool cap. Client/Agent cap khi ky, vi chu ky phu len no. Relay pool chi **kiem tra truoc khi broadcast**: `meta_nonce(from, batchId) == metaTx.batchNonce`. Neu lech → job ve `stale`, tra ve consumer de ky lai. Khong bao gio sua payload da ky.
- Head-of-line blocking o tang meta-tx: neu `batchNonce=5` fail vinh vien, 6..n cua cung `batchId` treo. Chinh sach: **moi intent doc lap dung mot `batchId` ngau nhien 128-bit voi `batchNonce=0`**; chi dung chuoi tuan tu khi nghiep vu that su co thu tu (deposit → transfer → settle). Job trong mot `batchId` tuan tu duoc danh dau `chain_group_key`; mot job fail thi ca group ve `blocked` chu khong retry le te.
- **[MOI] Kiem tra `meta_nonce` phai ghim block.** Doc `meta_nonce` tai block N roi broadcast o N+3, mot tx khac cua cung user co the da tieu no. Ghi `meta_nonce_block` vao job; neu `head - meta_nonce_block > 3` thi doc lai. Tren thuc te goi `meta_nonce` **trong chinh `eth_call` cua sim gate** (mot multicall) de khong ton them round-trip.

Loi ich phu cua `MODE_OPEN (0x00)`: chu ky nguoi dung khong rang buoc `relayer`, nen **bat ky EOA nao trong pool cung nop duoc**. Sharding K EOA cho ta K duong ong song song ma khong dong toi payload. Day la loi the that su cua EIP-1776 so voi ERC-2771 (bi rang vao mot TrustedForwarder) trong boi canh relay pool.

---

### 06.2. Phat hien va thay the tx treo

#### 06.2.1. Nguong "treo" phai tinh bang block, khong bang giay

Note noi 60 giay. Tren Gnosis (5s/block) do la 12 block — hop ly. Tren Ethereum L1 do la 5 block — qua som, gay bao replacement luc nghen mang va **tu no lam tang chi phi**. Nguong dung:

| Chuoi | `stuck_after_blocks` | Tuong duong | `escalate_every_blocks` | Tran leo thang |
|---|---|---|---|---|
| Gnosis xDAI | 12 | 60s | 6 | 8x gia ban dau |
| Celo (L2, 1s block) | 60 | ~60s | 20 | 4x |
| Ethereum L1 | 20 | ~4 phut | 10 | 10x |
| Polygon PoS | 30 | 60s | 10 | 8x |
| Base / Optimism (OP Stack) | 120 | ~4 phut | 60 | 3x |
| Arbitrum One (Nitro) | n/a — xem §06.2.2 | | | |
| Chain rieng (PoA/IBFT) | 5 | ~10s | n/a | n/a — bump vo nghia |

#### 06.2.2. [SUA] Phan loai L2 dung: ba nhom, khong phai mot

Ban nhap dau gop "Arbitrum/Base" lam mot va gan Celo vao nhom L1 co mempool. Ca hai deu sai.

| Nhom | Chain | Mempool | Replacement co chay khong? | Che do hong that |
|---|---|---|---|---|
| **A. L1 co mempool cong khai** | Ethereum, Gnosis, Polygon PoS, BSC | Cong khai | Co, `txpool.pricebump` 10% | Tx treo vi underpriced |
| **B. OP Stack (sequencer + op-geth txpool rieng)** | Base, Optimism, **Celo (tu 03/2025)** | Rieng, khong cong khai | **Co** — op-geth giu nguyen luat pricebump 10% | Sequencer downtime; tx treo hiem |
| **C. Arbitrum Nitro** | Arbitrum One/Nova | Sequencer FIFO theo thu tu den | **Khong dang tin** — sequencer sap thu tu theo arrival, tx nonce tuong lai bi giu lai; replacement co the duoc chap nhan nhung khong duoc uu tien lai | Sequencer downtime; loi thoat la force-inclusion qua L1 delayed inbox (~24h) |

He qua thiet ke:
- Nhom B: giu co che replacement, nhung `stuck_after_blocks` phai lon (block 1-2s, 120 block = 2-4 phut) — bump som tren mot chain co block 1s la dot tien.
- Nhom C: **khong cai replacement**. Cai **detector sequencer**: `head` khong tang > 60s → breaker `SEQUENCER_DOWN`, dung nhan job moi, giu inflight, khong bump. Them mot health probe rieng `arb_sequencer_feed` (WebSocket feed cua sequencer) vi `eth_blockNumber` van tra ket qua khi sequencer chi ngung *nhan* tx.
- **Celo da chuyen sang OP Stack thang 3/2025, block time 1s** (dong bo voi cai chinh cua §11). Bang finality trong note (`Celo | 5s | IBFT 2.0 | 1 block`) da loi thoi ca ba cot.

#### 06.2.3. [SUA] Luat bump tren EVM — con so 15% cua note can duoc noi ro

Ba con so khac nhau hay bi lan:

| Con so | La gi | He qua |
|---|---|---|
| **10%** | `--txpool.pricebump` mac dinh cua go-ethereum (va op-geth). Tx thay the phai co `maxFeePerGas` **va** `maxPriorityFeePerGas` moi >= cu * 1.10 | Duoi nguong nay node **tu choi im lang** (`replacement transaction underpriced`) |
| **12.5%** | `BASE_FEE_MAX_CHANGE_DENOMINATOR = 8` — muc base fee co the tang **moi block** | Bump 10% mot lan co the van thua base fee sau 1 block |
| **15%** | Con so note de xuat | Du de vuot ca hai — nhung chi cho **lan bump dau tien** |

Sai lam thuc te: bump 15% *mot lan* roi doi. Lan bump thu hai phai >= 1.10 lan **gia da bump**, khong phai gia goc. Va neu mang dang tang base fee 12,5%/block trong 10 block lien tiep (x3,25), mot bump 15% khong bao gio duoi kip.

**[SUA] Ban nhap dau con hai bug so hoc trong ham `bump()`:** (a) so sanh `tip` voi `cap` cua `max_fee` — nham hai dai luong; (b) nhan float roi truncate co the roi *duoi* nguong `floor(old*110/100)` cua geth. Ban dung:

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

`BumpCeilingReached` khong duoc nuot. Job ve `stuck_at_ceiling`, breaker `GAS_CEILING`, thong bao — vi tu day tro di tx **se treo cho den khi mang re lai hoac ta cancel**, va cancel cung can vuot nguong bump nen cung co the khong lam duoc. Do la mot trang thai that, phai co ten.

Bat buoc: bump **ca hai** truong. Bump chi `maxFeePerGas` ma giu `maxPriorityFeePerGas` la loi pho bien nhat, node tu choi va tx cu van treo.

Type-2 tx la mac dinh; tren Celo phai phat **CIP-64 (tx type `0x7b`)** de khai `feeCurrency` — ethers.js/web3.py chuan **khong serialize duoc type nay**, adapter Celo phai tu dung va ky RLP. **[MOI]** He qua thu hai it ai noi: `eth_estimateGas` tren Celo **khong** tinh phi quy doi `feeCurrency`; phai cong them `intrinsicGasForFeeCurrency` (hien ~50k gas cho token co adapter, doc tu `FeeCurrencyDirectory`). Bo sot no lam tx bi `out of gas` ngay o khau tru phi.

#### 06.2.4. Cancel-by-self-send

Khong ton tai "cancel" tren EVM. Cai goi la cancel chi la mot **replacement re hon**: tx toi chinh minh, `value=0`, `data=0x`, `gas=21000`, cung nonce, phi vuot nguong bump. Dung khi:
- Job da bi consumer huy, hoac
- `expiry` cua meta-tx da qua (contract se revert, tra ve tien gas vo ich), hoac
- Sim gate phat hien target contract vua bi dua vao denylist, hoac
- **[MOI]** Job Zether qua `epoch_deadline_block` (§06.3.4), hoac
- **[MOI]** Job o `signed_orphan` (§06.1.4 duong 3) can duoc trung hoa.

Chi phi: 21.000 gas. Tren Gnosis o 2 gwei = 0,000042 xDAI (~$0,00004). Tren Ethereum L1 o 30 gwei = 0,00063 ETH. **Dung cancel voi mot tx da co kha nang dao thanh cong** — se tra gia ca hai lan ma khong duoc gi. Quy tac: cancel chi cho tx *chac chan se revert*; con lai thi speed-up.

**[MOI] Cancel co the that bai.** Neu tx goc dang o gia rat cao, cancel phai vuot no 10% — tuc cancel *dat hon* tx goc. Kiem tra truoc: `cancel_cost = 21000 * ceil_bump(prev_max_fee)`. Neu `cancel_cost > value_at_risk` thi **khong cancel**, de tx revert va chi mat gas cua no. Ghi quyet dinh nay vao job (`cancel_declined_reason`).

#### 06.2.5. [MOI] Chi phi L1 data tren rollup — thanh phan bi bo sot hoan toan

`eth_estimateGas` tren mot L2 tra ve **gas thuc thi L2**. Phi that = `L2_execution_fee + L1_data_fee`. Voi mot tx Zether calldata ~2 KB, phan L1 thuong **chiem 60-90% tong chi phi** tren OP Stack khi L1 dong.

| Chain | Cach lay phi L1 | Ghi chu |
|---|---|---|
| OP Stack (Base, Optimism, Celo) | Predeploy `GasPriceOracle` tai `0x420000000000000000000000000000000000000F`, goi `getL1Fee(bytes rawTx)` | Tu Ecotone la ham cua `l1BaseFee` + `blobBaseFee`. Phai goi voi **raw tx da RLP**, khong phai calldata |
| Arbitrum Nitro | `NodeInterface` tai `0x00000000000000000000000000000000000000C8`, `gasEstimateComponents(...)` tra `gasEstimateForL1` | Arbitrum gop phi L1 vao `gas` nhung phan bo dong; dung `gasEstimateComponents` de tach |
| Gnosis, Polygon, BSC, chain rieng | Khong ap dung | L1 |

Chot: `est_cost_usd` trong velocity limit (§06.4.3) va trong danh gia loi nhuan **phai** goi lop nay. Adapter EVM co `async def estimate_total_fee(raw_tx) -> (l2_gas, l1_fee_wei)`; adapter cho chain L1 tra `l1_fee_wei = 0`.

Uoc tinh do lon (co so: calldata 2 KB, ~95% byte khac 0):
- Truoc EIP-4844: `2048 * 16 = 32.768` L1 gas. @ L1 20 gwei, ETH $3k → **$1,97/tx**.
- Voi blob (Ecotone, blob base fee 1 wei — truong hop thuong): gan **$0,001-0,01/tx**.
- Khi blob market dong (blobBaseFee tang 100-1000x): **$0,1-1/tx**.

Bien do 1000 lan giua hai che do la ly do breaker tren L2 phai theo doi **blobBaseFee** nhu mot dai luong rieng, khong chi `base_fee` cua L2.

#### 06.2.6. Trang thai job va nghia vu bao cho consumer

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

**[MOI] Anh xa state → nghia vu tai chinh** (day la cho consumer doc, va la cho `_set_done()` duoc phep chay):

| State | Consumer duoc ket luan gi | Duoc goi `payment.transaction._set_*` khong |
|---|---|---|
| `draft` … `signed` | Chua co gi tren chain | Khong |
| `broadcast` | Da gui. **KHONG phai da thanh toan** | `_set_pending()` |
| `mined` | Da vao mot block. Van co the bi dao nguoc | `_set_pending()` — **van la pending** |
| `final` | Qua Finality Gate | `_set_done()` — **trang thai duy nhat** |
| `reorged` | Da tung `mined`, bi dao nguoc | Giu `_set_pending()`, retry hoac `_set_error()` |
| `cancelled`, `rejected`, `epoch_expired` | Khong xay ra tren chain | `_set_canceled()` |
| `quarantined`, `stuck_at_ceiling` | **Khong xac dinh** | Khong goi gi. Nguoi phai vao xem |

`final` la trang thai **duy nhat** duoc phep bao cho consumer la tien da chuyen. Day la nguyen tac `dms_vietqr` dich sang on-chain: **broadcast khong phai la da thanh toan; mined cung chua phai**. Consumer nao goi `_set_done()` tai `broadcast` la mot bug tai chinh. `quarantined` la trang thai *khong xac dinh* — bug nguy hiem thu hai la anh xa no thanh `_set_error()` roi cho consumer retry, vi tx co the van dao sau do.

---

### 06.3. Simulation gate bat buoc

| Chuoi | Loi goi | Tra ve gi dung duoc | Buffer gas de xuat |
|---|---|---|---|
| EVM | `eth_call` (pin `blockHash`, khong pin `blockNumber`) → `eth_estimateGas` → `getL1Fee` (§06.2.5) → tuy chon `debug_traceCall` | revert reason, gas, state diff, logs | **1.25x** binh thuong; **1.6x** cho Zether; **2.0x** khi co `SLOAD` cold chua ro |
| SUI | `sui_devInspectTransactionBlock` (khong ton gas, khong can gas coin hop le) va `sui_dryRunTransactionBlock` (can gas coin that) | effects, ket qua tung lenh PTB | budget = `computationCost + storageCost - storageRebate`, x1.3 |
| Soroban | `simulateTransaction` | CPU/mem instructions, **footprint bat buoc**, resource fee, auth entries | Bat buoc dung ket qua sim; khong the doan footprint. x1.15 tren resource fee |
| Cosmos WASM | `POST /cosmos/tx/v1beta1/simulate` | `gas_used` | x1.4 (mac dinh cosmjs la 1.3; WASM bien thien manh hon) |
| TON | `ton-emulator` cuc bo tren state snapshot | cell tree, phi forward nanoTON | Cong 0,05 TON du phong cho chain message |
| Hedera | SDK dry-run / `contractCallLocal` | gas, revert | x1.2; phi neo USD nen it bien dong |

**[SUA] Ghim bang `blockHash`, khong bang `blockNumber`.** `eth_call` voi `{"blockNumber": "0x..."}` van co the bi mot provider tra loi tren mot nhanh khac sau reorg. `{"blockHash": "0x..."}` la xac dinh. Moi provider hien dai deu ho tro; provider nao khong ho tro thi khong dung cho sim.

#### 06.3.1. Sim phai bi ghim state

Ket qua sim chi dung tai block N. Ghi `sim_block_hash` + `sim_block_height` vao job; neu tai thoi diem broadcast `head - sim_block_height > max_sim_staleness` (EVM: 5 block; Sui: 10s; Soroban: 2 ledger) thi **sim lai**, khong broadcast. Khong lam viec nay thi sim gate chi la trang tri.

**[MOI] Sim lai khong duoc mien phi vo han.** Toi da 3 lan sim cho mot job; lan thu 4 → `rejected(reason='sim_thrash')`. Mot job phai sim lai 4 lan la mot job dang chay dua voi state cua chinh no; retry them chi dot RPC quota.

#### 06.3.2. "Ty le revert 0%" la khong dat duoc

Sim doc state tai N, tx thuc thi tai N+k voi state da doi. Note §14.2.8 yeu cau "ty le revert bang 0%" — do la mot muc tieu khong the dat, va nguy hiem hon la no khien nguoi ta **bo qua viec do luong**. Cac nguon divergence that:

| Nguyen nhan | Vi du cu the | Xu ly |
|---|---|---|
| State drift | ERC-20 `allowance` bi tieu boi tx khac cua cung user | Sim lai + `expiry` ngan (5 phut) |
| **Zether epoch rollover** | Proof dung `simulateAccounts(addrs, e)`; tx dao o epoch `e+1` → ciphertext lech → revert | §06.3.4, nguon divergence lon nhat |
| `meta_nonce` bi tieu | Tx khac cua cung user tren cung `batchId` | Ghim `meta_nonce_block` (§06.1.8) |
| Sui shared object contention | Hai PTB cung cham shared object → mot cai bi huy | Retry voi backoff, khong tinh la divergence |
| Soroban footprint sai | State doi lam footprint mo rong → `ExceededLimit` | Bat buoc re-simulate, khong reuse |
| Gas underestimate | `estimateGas` chay tren nhanh re hon (storage slot dang zero luc sim, non-zero luc thuc thi: 20k vs 5k gas — chenh 15k/slot) | Buffer o bang tren |
| Cosmos gas multiplier thap | Contract co vong lap phu thuoc so item | x1.4 |
| **[MOI]** Access list thieu | Tx type-1/2 co `accessList` sinh tu sim; state doi lam slot ngoai list → cold access dat hon | Chi dung `accessList` khi tiet kiem > 10%; buffer 2.0x khi dung |
| **[MOI]** Block gas limit | Tx 6M gas tren chain gioi han `eth_call` o 10M van pass sim nhung bi tu choi khi vao block cung block khac | Guard `gas * buffer < block_gas_limit * 0.4` |

SLO thuc te de xuat: **divergence rate < 0,5% tren tong so broadcast, < 0,05% cho lop R3/R4**. Vuot nguong 20 divergence/gio tren cung mot `target_address` → **auto-quarantine contract do** (`blockchain.target.policy.state = 'quarantined'`), dung nhan job moi toi no, tao `blockchain.breaker.event` va page on-call. Ly do quarantine theo contract chu khong theo chain: divergence tap trung mot contract gan nhu luon la bug contract hoac bug ABI, khong phai su co mang.

**[MOI] Quy trinh khi sim va thuc thi bat dong** (brief hoi thang cau nay):

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

Diem quan trong: **`unknown` khong bao gio duoc retry.** Retry mot thu ta khong phan loai duoc la cach dot tien nhanh nhat ma van tin la minh dang "tu phuc hoi".

#### 06.3.3. [MOI] Policy gate: allowlist phai theo `(address, selector)`, khong chi theo address

Note noi "Target Contract Allowlist". Chua du: mot contract co `transfer()` vo hai va `upgradeTo()` chet nguoi. Model:

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

Mac dinh **deny**. Mot job co `calldata_hex` ma 4 byte dau khong khop entry `active` nao → `rejected(reason='selector_not_allowed')`. Entry `0x*` chi duoc tao boi `group_blockchain_manager` va bi ghi vao audit log — no la mot ngoai le, khong phai mot tien ich.

#### 06.3.4. Zether: sim gate phai co rang buoc epoch — note bo trong hoan toan

`simulateAccounts(schnorrAddresses, epoch)` (§10.5.3) tra `(C, D)` sau khi gop `pending_transfers` tai epoch muc tieu. Proof duoc dung *cho epoch do*. Nhung khong co gi trong note dam bao tx dao dung epoch do. Voi `Δ = 5 block` tren Gnosis = 25s, mot tx bi tre 25s la proof vo hieu.

Chot: job Zether mang them
- `zether_target_epoch` (Integer) — epoch proof duoc dung cho,
- `zether_epoch_deadline_block` (Integer) = `(target_epoch + 1) * Δ - safety_margin`, voi `safety_margin = 1` block.

Truoc broadcast: `require head < epoch_deadline_block`. Sau broadcast, neu chua mined khi `head >= epoch_deadline_block` → **khong speed-up ma cancel** (self-send) va tra job ve consumer voi `state='epoch_expired'` de dung proof moi. Speed-up mot tx Zether qua han epoch la dot tien vao mot tx chac chan revert.

He qua ve chinh sach phi: lop Zether **luon uu tien tip cao ngay tu lan dau** (mot lan dao dat hon hai lan revert). Cu the: `zether_initial_tip = p90(tip, 20 block)` thay vi `p50` cua lop khac. **[MOI]** Va vi cua so chi con `Δ * block_time - sim_time - sign_time`, tren Gnosis la `25 - 0,3 - 0,8 ≈ 23,9s` (~4,8 block), **khong con cho cho mot chu ky bump nao**. Neu MPC ky mat 3s p99, cua so con ~4,4 block. Do la ly do ky thuat truc tiep de dua Zether len enclave signer (§06.6), khong chi la ly do throughput.

**[MOI] Verify proof off-chain truoc khi ky.** Mot tx Zether 6M gas tren `eth_call` mat 200-600 ms CPU cua provider va nhieu provider **cap gas cua `eth_call`** (Alchemy/Infura thuong 10M-50M, mot so goi thap hon). Cheo: verify Bulletproof bang thu vien Rust cuc bo mat **5-12 ms** (co so: `dalek-cryptography/bulletproofs` verify n=64, m=1 ~1,5 ms tren x86 hien dai; n=512 tong bit ~8x → ~12 ms). Chot pipeline Zether: `verify_offchain (10ms) → eth_call day du (300ms) → estimateGas`. Neu verify off-chain fail thi khong ton mot RPC call nao.

#### 06.3.5. [MOI] Chi phi cua chinh sim gate

| Cong cu | Don gia | O 24.000 tx/ngay (720k/thang) | Ket luan |
|---|---|---|---|
| `eth_call` + `eth_estimateGas` tren node tu van hanh | ~0 bien phi | ~$200/thang (amortize node) | **Mac dinh** |
| `eth_call` tren RPC managed (Alchemy/QuickNode) | tinh theo compute unit; `eth_call` nang gap ~5-25x `eth_blockNumber` | Vuot goi growth, roi vao bac enterprise | Chi dung lam fallback |
| Tenderly Simulation API | goi theo don vi; free tier ~50k don vi/thang | 720k don vi/thang → **bac tra phi cao** | **Khong dung trong hot path** |

Chot: **Tenderly chi dung cho hau kiem (post-mortem) mot divergence**, khong nam trong duong broadcast. Ban nhap dau va note deu de Tenderly o hot path — o quy mo 24k tx/ngay do la mot dong chi phi khong ai du toan. Hot path dung `eth_call` + `debug_traceCall` tren archive node cua chinh minh.

---

### 06.4. Gas circuit breakers

#### 06.4.1. Spike breaker — "300% cua trung binh 1h" can sua thong ke

Trung binh (mean) bi keo boi dung mot block spike; dung mean thi breaker vua nhay lai vua tre. Dung:

```
ref  = rolling_median(base_fee, window = 1h)      # Gnosis: 720 block; L1: 300 block
mad  = median(|base_fee_i - ref|)
trip     khi  base_fee_next > max(3.0 * ref, ref + 6 * mad)
reset    khi  base_fee_next < 1.5 * ref  lien tuc 20 block      # hysteresis
```

Hysteresis la bat buoc. Khong co no, breaker flapping quanh nguong 3,0x se tao ra chinh xac cai kieu tai bung nhip lam mang te hon.

**[MOI] Cua so 1h can duoc mo rong luc khoi dong.** Khi service vua len, chua co 720 mau. Chinh sach: dung `fee_history` cua RPC de nap 1024 block gan nhat ngay o buoc khoi dong (mot loi goi `eth_feeHistory(1024, 'latest', [10,50,75,90])`); truoc khi co >= 200 mau, breaker o che do **fail-closed cho R1/R2** (khong chay job deferrable) va fail-open cho R3/R4.

**[MOI] Breaker phai co trang thai `half_open`.** Khi reset dieu kien duoc thoa, khong mo hoan toan ngay: cho qua 10% luu luong trong 5 phut, do divergence va chi phi thuc, roi moi mo. `relay_breaker_state` la Gauge 0/1/2 dung nghia closed/half/open.

Breaker phai do **hai** dai luong tren chain co native token bien dong:

| Chain | Dai luong theo doi | Ghi chu |
|---|---|---|
| Gnosis xDAI | `base_fee` (xDAI) — mot chieu la du | xDAI neo USD, chi phi USD = gas x price truc tiep |
| Celo (L2) | `base_fee` theo `feeCurrency` (cUSD/USDC) **VA** `l1_blob_base_fee` | **[SUA]** Sau khi thanh OP Stack, phi L1 la mot chieu doc lap (§06.2.5) |
| Base / Optimism | `base_fee` (ETH) **VA** `l1_blob_base_fee` **VA** `native_price_usd` | Ba chieu |
| Ethereum/Polygon/BSC | `base_fee` **VA** `native_price_usd` | Gas 30 gwei o ETH $2k khac han o ETH $8k. Breaker phai trip theo **USD/tx** |
| Chain rieng (PoA/IBFT) | Khong can spike breaker | Gas tinh; van can velocity limit **tinh bang gas** |

Day la ly do ky thuat cung cung cho thu tu chain da khoa (Gnosis truoc, Celo sau): tren Gnosis, breaker chi can mot chieu do va nguong tinh bang USD la con so that, khong phai uoc luong. **[SUA]** Celo sau khi thanh L2 **khong** con don gian nhu vay — no can ba chieu do; do la mot ly do bo sung de Gnosis di truoc, khong chi la thu tu tuy y.

#### 06.4.2. [MOI] Gia native token: nguon, do tre, va chinh sach fail

Velocity limit tinh bang USD → phai co gia. Chua ai noi lay o dau.

| Chain | Nguon gia | Do tre chap nhan |
|---|---|---|
| Gnosis (xDAI) | Hang so 1,00 USD, **co canh bao depeg**: doc Chainlink DAI/USD tren Ethereum moi 15 phut; lech > 2% → breaker `PEG_BROKEN` | 15 phut |
| Celo (cUSD) | Tuong tu, `SortedOracles` on-chain cua Celo | 15 phut |
| ETH/MATIC/BNB | Chainlink price feed on-chain tren chinh chain do (khong dung REST cua san) | 5 phut |
| Chain rieng | Khong ap dung — velocity tinh bang gas | — |

Chinh sach khi gia stale (`age > 2 * max_age`): **fail-closed voi gia bao thu** — dung `price_usd = last_known * 3` cho moi tinh toan chi phi. Khong dung `last_known` (danh gia thap rui ro) va khong chan het (dung dich vu vi mot oracle chet la phan ung qua muc). Con so 3x la mot lua chon, ghi vao `blockchain.chain.stale_price_multiplier`, chinh duoc.

#### 06.4.3. [SUA] Velocity limit: phai nguyen tu, phai la so nguyen, phai co refund

Ban nhap dau dung `INCRBYFLOAT` roi kiem tra rieng. Hai bug:
1. **TOCTOU**: doc → so sanh → ghi khong nguyen tu. Voi 50 job/s song song, bucket vuot tran roi moi bi phat hien. Vuot bao nhieu thi tuy may.
2. **Float**: `INCRBYFLOAT` tren hang tram nghin thao tac tich luy sai so. Bucket tien khong duoc dung float.

Ban dung: mot Lua script, don vi **micro-USD (so nguyen)**, reserve truoc — settle sau.

```lua
-- lua/spend_reserve.lua
-- KEYS: agent, tenant, global, resv
-- ARGV: cost_uusd, cap_agent, cap_tenant, cap_global, ttl_s, job_uuid
local c = tonumber(ARGV[1])
local a = tonumber(redis.call('GET', KEYS[1]) or '0')
local t = tonumber(redis.call('GET', KEYS[2]) or '0')
local g = tonumber(redis.call('GET', KEYS[3]) or '0')
if a + c > tonumber(ARGV[2]) then return {0, 'agent',  a, c} end
if t + c > tonumber(ARGV[3]) then return {0, 'tenant', t, c} end
if g + c > tonumber(ARGV[4]) then return {0, 'global', g, c} end
redis.call('INCRBY', KEYS[1], c); redis.call('EXPIRE', KEYS[1], ARGV[5])
redis.call('INCRBY', KEYS[2], c); redis.call('EXPIRE', KEYS[2], ARGV[5])
redis.call('INCRBY', KEYS[3], c); redis.call('EXPIRE', KEYS[3], ARGV[5])
redis.call('HSET', KEYS[4], ARGV[6], c)               -- reservation, de refund
return {1, 'ok', 0, c}
```

Key (TTL 7200s, giu 2 cua so de tinh truot):

```
bc:spend:agent:{agent_id}:{yyyymmddHH}     STRING  int micro-USD
bc:spend:tenant:{company_id}:{yyyymmddHH}  STRING  int micro-USD
bc:spend:global:{yyyymmddHH}               STRING  int micro-USD
bc:spend:resv:{yyyymmddHH}                 HASH    job_uuid -> reserved_uusd
```

Kiem tra **truoc khi lease nonce** (khong phai truoc sim — sim gan nhu mien phi tren node cua minh, lease thi khong): `est_cost_uusd = (l2_gas * buffer * gas_price + l1_fee_wei) * native_price_usd * 1e6 / 1e18`.

**Settle bat buoc** (day la thu ban nhap dau khong co, va thieu no thi bucket ro ri cho den khi TTL het):
- Job den `mined`: `delta = actual - reserved`; `INCRBY` cac bucket voi `delta` (co the am); `HDEL resv`.
- Job `rejected`/`cancelled` truoc broadcast: `INCRBY` voi `-reserved`; `HDEL resv`.
- Janitor moi 5 phut quet `bc:spend:resv:*` cua cua so *truoc*, moi entry con lai qua 2 gio → refund va ghi `relay_spend_reservation_leaked_total`.

Chi phi cua Lua: mot round-trip, ~0,2 ms. Khong dang tranh cai.

#### 06.4.4. Thu tu bi throttle — lop uu tien

Note noi "R1/R2 bi dinh chi, giu R3". Bang lop day du, va co mot dieu note bo sot: **mot so traffic bao tri that ra la R4**.

| Lop | Noi dung | Hanh vi khi breaker trip | Deferrable |
|---|---|---|---|
| **R1** | Anchoring hash audit, proof-of-action, batch merkle root | Dung ngay, gom vao batch lon hon, phat lai khi reset | Vo han (gom 24h van dung) |
| **R2** | Loyalty point accrual, cap nhat metadata, index refresh | Dung, hang doi giu toi 6h | Hang gio |
| **R3** | B2B settlement, `withdraw` Zether, thanh toan end-user | Giam throughput 50%, chi qua neu `est_cost_usd < value * 0.5%` | Hang phut |
| **R4** | Refill hot wallet, Zether `rollOver`, Soroban `extend_ttl`, unwind rui ro thanh khoan, cancel tx doc, **gap-filler**, **replacement cua job R3 dang inflight** | **Khong bao gio throttle** | Khong |

`rollOver()` va `extend_ttl` bi xep nham vao "bao tri dinh ky" la mot bay. Throttle `rollOver` lam dong bang so du kha dung cua **moi** nguoi dung Zether; throttle `extend_ttl` tren Soroban lam **mat state contract** khi TTL het. Chung la R4.

**[MOI]** Them hai muc vao R4 ma ban nhap dau bo sot: gap-filler (throttle no = de nguyen lo thung = chan toan bo account) va replacement cua mot job R3 **da broadcast** (throttle no = de tien treo giua duong). Quy tac tong quat: **khong bao giờ throttle mot hanh dong ma muc dich la go ket mot hanh dong truoc do.** Breaker chan *dau vao*, khong chan *loi thoat*.

Nguong canh bao: 90% → thong bao (Odoo activity + webhook), 100% → chan lop <= R3. R4 vuot tran can `blockchain.breaker.override` (record co `approver_uid`, `override_expiry`, `reason`, chi group `blockchain_treasury_manager` tao duoc) — khong co bien moi truong nao bypass duoc.

#### 06.4.5. [SUA] Kich thuoc that: Zether tren EVM cong khai

Note viet ZKP verify "~180.000 - 250.000 gas". **Con so nay co hinh dang cua mot verifier Groth16, khong phai cua Bulletproofs.** Groth16 tren alt_bn128 = 3 pairing + vai `ecMul`: `45.000 + 3*34.000 + ~10 * 6.000 ≈ 207.000 gas`. Khop hoan hao voi con so cua note. Nhung note **cung** noi dung Bulletproofs (§10.5.2 muc 3, va `zkpProof` trong `EncryptedTransfer`). Hai thu khong the cung dung.

So hoc cho Bulletproofs (co so: EIP-1108 dinh gia lai `ecAdd` = 150, `ecMul` = 6.000 gas; **khong** phai EIP-196 nhu ban nhap dau ghi — EIP-196 goc la 500/40.000, EIP-1108 moi ha xuong):

```
Verify mot aggregated Bulletproof, m statement, n bit moi statement:
  kich thuoc MSM = 2*m*n + 2*log2(m*n) + ~7 diem
Voi precompile alt_bn128 khong co MSM san, chi phi ~ (so diem) * 6.000 gas
```

| Cau hinh | m*n bit | MSM (diem) | Gas MSM | + Sigma + calldata + keccak | **Tong uoc tinh** |
|---|---|---|---|---|---|
| ConsenSys goc, n=32, m=2 | 64 | 141 | 0,85M | ~0,25M | **~1,1M** |
| Note de xuat, n=128, m=2 (`v`, `b-v`) | 256 | 528 | 3,17M | ~0,3M | **~3,5M** |
| Note + fee, n=128, m=3→pad 4 | 512 | 1.049 | 6,29M | ~0,35M | **~6,6M** |
| **De xuat: n=64, m=3→pad 4** | 256 | 528 | 3,17M | ~0,3M | **~3,5M** |
| Groth16 thay Bulletproofs | — | — | — | — | **~0,21M** |

**Ban nhap dau uoc 2,0-2,5M — thap hon thuc te khi tinh ca fee proof.** Co che phi bao mat cua note (§10.5.3 muc 5: `fee >= 0`, `v >= 0`, `b-fee >= 0`, `b-fee-v >= 0`) can **ba** range statement doc lap, aggregate phai pad len bon → 512 bit → ~6,6M gas.

He qua tren Gnosis (block gas limit 17M):

| Chi so | n=128 + fee (~6,6M) | n=64 + fee (~3,5M) | Groth16 (~0,21M) |
|---|---|---|---|
| tx/block toi da (17M) | 2 | 4 | 80 |
| tx/block thuc te (20% block space, 3,4M) | 0,5 | ~1 | 16 |
| **tx/ngay (block 5s)** | **~8.600** | **~17.000** | **~276.000** |
| Chi phi @ 2 gwei | 0,0132 xDAI ≈ $0,013 | 0,007 xDAI ≈ $0,007 | 0,0004 ≈ $0,0004 |
| Cung tx tren Ethereum L1 @ 25 gwei, ETH $3k | **$495** | **$263** | **$16** |
| Thoi gian prove (Rust, x86) | ~120 ms | ~60 ms | ~800 ms (Groth16 prove dat) |
| Thoi gian prove (WASM/mobile) | ~2-4 s | ~1-2 s | ~15-30 s |
| Trusted setup | Khong | Khong | **Co (per-circuit)** |

**De xuat cu the, can nguoi duyet:** ha range tu 128 xuong **64 bit** bang cach cho Zether token dung **6 decimals noi bo** thay vi 18. `2^64 ≈ 1,8e19`; voi 6 decimals do la **18 nghin ty don vi tien** — thua cho moi giao dich B2B tuong tuong duoc. Note bac 32 bit vi `2^32` wei @ 18 decimals la $0,0000000043 — lap luan do dung, nhung ket luan "vay thi len 128 bit" bo qua rang buoc *scale*, khong phai rang buoc *bit*. Doi lai: gas giam ~47%, prove nhanh gap doi tren mobile (day la yeu to quyet dinh cho luong "end-user payment tai quay" cua §07), va **dust duoi 10^-6 khong the chuyen bao mat** — `deposit` phai tu choi so tien khong chia het cho `10^12`, hoac giu phan du o so du cong khai. Do la mot dieu khoan san pham, phai chot voi nguoi lam nghiep vu.

Mot con so de doi chieu quy mo DMS: 2.000 salesman x 30 visit/ngay = **60.000 su kien/ngay** — vuot tran Gnosis o **moi** cau hinh Bulletproofs. Ket luan bat buoc: khong bao gio dua tung su kien nghiep vu len chain. R1 anchoring gom Merkle root (1 tx/gio/tenant), R2/R3 chi len chain o cap chung tu tien te. Va con so nay xac nhan quyet dinh da khoa cua user (private chain truoc cho Zether) la dung ve ky thuat, khong chi ve chi phi: tren chain rieng, block gas limit do ta dat (de nghi **100M**, cho ~14 tx Zether/block = 240.000 tx/ngay o block 5s) va 6,6M gas/tx khong con la rang buoc.

**Chot con so cho policy** (cho den khi co benchmark Foundry that, §06.12 muc 4):
`blockchain.chain.max_gas_per_tx` = 8.000.000 tren chain rieng, 3.500.000 tren Gnosis (tuc **chi cho phep cau hinh n=64**). Neu contract deploy voi n=128, Gnosis bi tat cho Zether transfer va chi con `deposit`/`withdraw`.

---

### 06.5. Hot wallet: so du, refill, va gas coin

Mo hinh 3 nguong tren `blockchain.relayer.account`:

```
low_watermark    = expected_tx_per_hour * avg_gas * p90_gas_price * refill_lead_hours
target_balance   = low_watermark * 3
high_watermark   = low_watermark * 6        # vuot -> sweep ve treasury
```

`refill_lead_hours = 4` (du de mot nguoi truc tinh day xu ly manual neu automation hong). Vi du Gnosis, 500 tx/h, 2,5M gas, 2 gwei: `500 * 2,5e6 * 2e-9 = 2,5 xDAI/h` → low = 10 xDAI, target = 30, high = 60. So tien nho la co y: **vi hot khong bao gio giu qua vai gio runway**. Rui ro mat khoa hot duoc gioi han bang so du, khong bang do manh cua custody.

Refill: cron Odoo 5 phut goi `model._cron_relayer_refill_scan()`, tao `blockchain.refill.request` khi `balance < low`. Refill duoc ky boi **treasury signer (HSM FIPS 140-2 L3, 2-of-3)** — day moi la cho bat buoc HSM, khong phai vi relayer (xem §06.6). Tu dong tra ve `low → target` neu `amount < auto_refill_cap_usd` (mac dinh $500); vuot thi can approve tay.

**[MOI] Chong vong lap refill.** Neu balance khong tang sau khi refill (tx refill bi treo, hoac dia chi sai), scan tiep se tao them request. Guard: toi da **1 request `pending` moi account**, va `_unique_pending_refill` bang partial unique index:

```python
_unique_pending_refill = models.Constraint(
    'UNIQUE (relayer_account_id) WHERE state IN (\'draft\',\'approved\',\'broadcast\')',
    'Moi relayer account chi co mot yeu cau refill dang xu ly.')
```

**[MOI] `balance_native` khong duoc la `Float`.** §10.4.1 da chot: `uint256` khong vua vao `fields.Float` (mat chinh xac tu 2^53; 1 ETH = 1e18 wei). Ban nhap dau viet `fields.Float(digits=(24,8))` — mau thuan voi §10 va mat chinh xac o wei. Sua:

```python
balance_native_base = fields.Char(readonly=True, help='So du native, base units (wei), chuoi thap phan.')
balance_native_ui   = fields.Float(digits=(18, 6), readonly=True, help='Chi de hien thi/sort. Khong tinh toan tren truong nay.')
```

**[SUA] `runway_hours` khong nen `required=True`.** Ban nhap dau dung `store=True, required=True, default=0.0` roi phai canh giac chuyen NULL. Giai phap don gian hon: **bo `required=True`**. Mot chi so hien thi khong can rang buoc NOT NULL; `required` o day khong bao ve gi ma chi tao mot cai bay. Neu van muon giu (de query khong phai xu ly NULL), thi quy tac "compute gan gia tri o **moi** nhanh" van bat buoc:

```python
runway_hours = fields.Float(compute='_compute_runway_hours', store=True, default=0.0)

@api.depends('balance_native_ui', 'burn_rate_native_per_hour')
def _compute_runway_hours(self):
    for rec in self:
        rate = rec.burn_rate_native_per_hour
        rec.runway_hours = 9999.0 if not rate else rec.balance_native_ui / rate
```

Dac thu tung chuoi:

| Chuoi | Thu phai "refill" khong phai native balance | Co che |
|---|---|---|
| **SUI** | **Pool gas coin.** Song song = so coin object roi, khong phai nonce | Giu `max_inflight` coin object, moi coin >= `gas_budget`. Job `_sui_split_gas_coins()` dinh ky `SplitCoins`. Dung mot coin cho hai tx song song = **equivocation**, object bi khoa het epoch (~24h) |
| **Cosmos** | `x/feegrant` allowance con han muc | Theo doi `PeriodicAllowance.period_spend_limit`, gia han truoc khi can |
| **Soroban** | TTL cua contract instance/persistent entry | `extend_ttl` la R4, lich theo `live_until_ledger - 100k ledger` |
| **Stellar** | Base reserve + so du XLM cho fee-bump | Fee-bump lay phi tu FeeSource, khong tu inner source |
| **TON** | So du Highload Wallet V3 + cua so `query_id` | `query_id` het cua so (mac dinh 128 s) la mot dang "nonce exhaustion" rieng |
| **Celo** | So du `feeCurrency` (cUSD/USDC) chu khong phai CELO | Refill bang stablecoin; van giu mot it CELO du phong. **[MOI]** Sau khi thanh L2, con can theo doi so du ETH tren L1 cua batcher neu ta tu chay node |
| **Hedera** | So du HBAR cua payer account | Phi neo USD → burn rate on dinh, de du bao nhat trong 7 chuoi |

#### 06.5.1. [MOI] Xoay khoa va rut lui relayer account (draining)

Thieu hoan toan trong ban nhap dau. Mot relayer EOA phai xoay duoc ma khong lam ket nonce.

```
active -> draining : dung nhan job moi; giu nguyen quyen broadcast/replace cho inflight
draining -> retired: khi inflight rong VA signed rong VA balance da sweep ve treasury
```

Chinh sach: xoay moi **30 ngay** cho relayer EOA (chu khong phai treasury). Trong luc draining, mot EOA moi da duoc them vao pool tu truoc (`state='paused'` → `active`) nen khong co khoang trong nang luc. Truoc khi `retired`, bat buoc mot lan `cold_start()` cua EOA moi va mot lan `reconcile` cua EOA cu; `retired` account giu nguyen record de audit, khong duoc xoa (`ondelete='restrict'` tu job).

---

### 06.6. HSM/MPC: nut co chai that su

Con so (uoc tinh co co so, **can benchmark lai tren ha tang thuc truoc khi khoa kien truc**):

| Custody | Throughput ky | Latency p50 / p99 | Co so uoc tinh |
|---|---|---|---|
| HSM tai cho (Thales/Utimaco, PKCS#11, ECDSA P-256) | 10^3 – 10^4 sign/s | 1-5 ms / 20 ms | Spec nha san xuat cho ECDSA. **secp256k1 phai xac nhan rieng** — nhieu HSM chi co P-256/P-384 |
| AWS CloudHSM (hsm2m.medium) | ~10^3 sign/s/HSM | 3-10 ms / 50 ms | Bac do lon cong bo cho ECDSA. secp256k1 co ho tro tren hsm2m |
| AWS KMS asymmetric `Sign` (ECC_SECG_P256K1) | **~500 req/s** quota mac dinh (**thay doi theo region**, mot so region 300) | 15-40 ms / 150 ms | Service quota, khong phai gioi han crypto. Xin nang duoc |
| **MPC SaaS** (Fireblocks/Fordefi/Turnkey) | **5 – 30 sign/s cho mot vault** | **300 ms – 3 s** / 10 s | Nhieu vong MPC qua mang + policy engine + API rate limit. **Song song trong cung vault thuong bi serialize** |
| Threshold Schnorr/FROST tu van hanh, cung DC | 10^2 – 10^3 sign/s | 10-50 ms / 200 ms | 2 vong, RTT noi bo |
| Session key trong Nitro Enclave/SGX | 10^4+ sign/s | < 1 ms | Ky cuc bo, khong ra mang |

**MPC SaaS o 5-30 sign/s la nut co chai nghiem trong hon ca chain.** Neu moi business action = 1 chu ky, tran he thong la 5-30 action/s — thap hon ca Gnosis. Bon cach thiet ke quanh no, theo thu tu hieu qua:

**1. Batch executor: 1 chu ky relayer cho N meta-tx.** Don bay lon nhat, va no roi ra tu chinh EIP-1776: chu ky *nguoi dung* nam trong `MetaTransaction.signature` (do session key ky, re), con HSM chi ky **vo ngoai** — tx cua relayer EOA. Mot contract `MetaTxBatcher.executeBatch(MetaTransaction[] calldata txs, bytes[] calldata sigs)` gom N=50 meta-tx vao 1 tx on-chain → tai HSM giam 50 lan. Voi MPC 10 sign/s: 500 business action/s.

**[MOI] Ba yeu cau bat buoc len contract batcher ma ban nhap dau chi noi mot:**

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

Diem (c) la mot **quyet dinh contract ma relay pool khong the an toan neu thieu**, va no keo theo van de grief nguoc lai (mot relayer doc dot nonce cua user) — xem §06.12 muc 3.

**[MOI] Batch lam sim gate kho hon, va do la chi phi that.** Sim mot batch 50 item mat gas gap ~50 lan; mot `eth_call` 50 x 200k = 10M gas co the vuot cap cua provider. Chot: **sim tung item rieng le tren cung mot `blockHash`** (50 `eth_call` song song, moi cai nho), roi sim ca batch **mot lan** de lay gas tong. Item nao sim fail thi loai khoi batch truoc khi ky — do la ly do sim phai xay ra **truoc** batching, khong phai sau.

**Kich thuoc batch tot nhat khong phai la lon nhat.** Danh doi: batch lon → it chu ky hon, nhung (i) mot tx to hon co xac suat treo cao hon va replacement dat hon, (ii) latency chờ gom batch, (iii) mot lan revert cap batch mat het. De xuat: `batch_size = min(50, ceil(arrival_rate * max_batch_wait_ms / 1000))`, `max_batch_wait_ms = 1500` cho R2, **0 (khong batch)** cho R3/R4. Job R3 dung batch la dat mot khoan tien that vao chung so phan voi 49 job khac.

**2. Sharding K relayer EOA.** Song song hoa, nhung *khong* tang throughput HSM (van cung mot HSM/vault). Chi giai quyet head-of-line blocking. **[MOI]** Ngoai le: neu MPC provider cho phep **nhieu vault**, moi vault mot EOA thi throughput *co* nhan len — nhung chi phi license thuong theo vault. Kiem tra voi nha cung cap truoc khi dua vao mo hinh nang luc.

**3. Phan tang custody theo lop rui ro** — de xuat can nguoi duyet: HSM FIPS L3 bat buoc cho **treasury + refill signer + admin contract (upgrade/pause)**; relayer EOA hot dung khoa sinh trong **Nitro Enclave/SGX**, khong bao gio ra plaintext ngoai enclave, tran chi tieu bang runway 4h, xoay vong 30 ngay (§06.5.1). Nguyen tac "cam Agent luu private key plaintext" van duoc giu tuyet doi — enclave khong phai plaintext-on-disk. Doi lai throughput tu 10 len 10^4 sign/s. Neu compliance khong chap nhan, phai chap nhan tran ~10-30 tx/s va thiet ke batch theo (1). Trung khop voi bang cua §07.0.

**4. Khong pre-sign hang loat theo nonce.** Ky truoc nonce n..n+50 roi cat trong Redis nghe hap dan (amortize latency) nhung tao mot kho tx da ky co the phat song boi bat ky ai doc duoc Redis, va khong the huy sau khi ky vi gas price da chot. **Cam.** Ngoai le duy nhat duoc xem xet: pre-sign **mot** tx cancel (self-send, 21000 gas, gia cao) cho moi nonce inflight, luu trong enclave chu khong trong Redis — do la mot "dead man switch" co gia tri, nhung van la mot tx da ky nam cho, nen mac dinh **tat**.

Ngan sach latency mot job (Gnosis, MPC SaaS, khong batch):

```
policy + allowlist + selector                     2 ms
sim (eth_call + estimateGas + getL1Fee, 3 RPC)  120 ms
velocity reserve (Redis Lua)                      0.2 ms
lease nonce (Redis Lua)                           0.2 ms
WAL Postgres (job -> nonce_leased)               15 ms   [MOI] khong mien phi
sign (MPC)                                      800 ms   <-- 74% ngan sach
WAL Postgres (job -> signed) + Redis signed      16 ms
fence re-check + serialize + broadcast fan-out   80 ms
------------------------------------------------------
tong truoc khi len mempool                    ~1.033 ms
inclusion (1 block)                            5.000 ms
finality soft (1 block) / hard (2 epoch)        5 s / ~13 phut
```

Voi batch 50: 800/50 = 16 ms/action cho phan ky; tong ~1.180 ms cho ca batch → **~24 ms/action**. Do la toan bo ly do batch executor la must-have chu khong phai toi uu.

#### 06.6.1. [MOI] Mo hinh hang doi: bao nhieu worker, bao nhieu EOA

Little's law, muc tieu **100 business action/s** (bien tren cho ca DMS + loyalty + payment):

```
Voi batch 50, R2:        2 on-chain tx/s
Voi R3 khong batch:      gia su 5 tx/s
Tong tx/s can:           ~7 tx/s

Moi EOA: gioi han boi (a) sign serial, (b) txpool.accountslots = 16
  (a) MPC 10 sign/s dung chung -> KHONG scale theo EOA
  (b) enclave 10^4 sign/s     -> gioi han la (16 inflight) / (5 s/block) = 3,2 tx/s/EOA

=> Voi enclave: K = ceil(7 / 3,2) = 3 EOA. Lay K = 6 (2x headroom + cach ly HOL).
=> Voi MPC:     tran he thong = 10 tx/s bat ke K. Phai batch.

Worker process: moi worker giu 1-3 shard. K=6 -> 3 worker (2 shard/worker) + 1 standby.
Redis ops:  ~14 ops/job * 100 job/s = 1.400 ops/s. Redis appendfsync=always lam ~5-10k ops/s. Du.
Postgres:   ~4 write/job (qua callback gom 200) = ~0,5 commit/s tu worker. Khong dang ke.
```

Ket luan dung mot cau: **voi MPC SaaS, so EOA khong quan trong; voi enclave, 6 EOA la du cho 100 action/s.** Bat cu ai de xuat 50 relayer EOA nen bi hoi truoc do so nay.

---

### 06.7. Multi-RPC: failover va phat hien RPC noi doi / tut hau

Toi thieu **3 provider doc lap** moi chain (1 node tu van hanh + 2 nha cung cap). `blockchain.rpc.endpoint` co `endpoint_ref` (Char, tro toi `ir.config_parameter` chua URL + API key — **khong** luu key tren record), `weight`, `role` (`primary`/`fallback`/`witness`), `health_state`, `score`, `divergence_count`.

#### 06.7.1. Bon lop kiem tra

**Lop 1 — song (liveness), moi 5s:** `eth_blockNumber` + `eth_getBlockByNumber(head)`. Do `head_lag_blocks` so voi max cua ca cum, va `head_age = now - block.timestamp`. Trip khi `head_lag > 3` hoac `head_age > 4 * block_time`. Day la *lagging RPC*.

**Lop 2 — trung thuc (correctness), moi 30s:** hoi **k-of-n** cung mot cau hoi tai chieu sau an toan `H = head - witness_depth`:

```
blockhash(H)  tu tat ca endpoint  ->  phai bang nhau
```

**[SUA] `witness_depth` phai theo chain, khong phai hang so 12.** Ban nhap dau chot 12 block cho moi chain: tren Gnosis do la 60s (chap nhan duoc), tren Celo L2 block 1s do la 12s (qua nong, reorg cua sequencer restart co the sau hon), tren Cosmos/Stellar (finality tuc thoi) 12 la thua. Chot `witness_depth = max(chain.finality_depth, 2)` cho chain BFT, `max(chain.finality_depth, 12)` cho chain probabilistic.

**[SUA] Mot lan lech khong duoc eject ngay.** Hai provider co the tra khac nhau *hop phap* trong vai giay ngay sau mot reorg nong. Chot: lech lan dau → `divergence_suspect`, hoi lai sau 2 block **tai cung chieu sau moi**; van lech → **eject vinh vien** (khong auto-recover), `blockchain.breaker.event(kind='rpc_divergence')`, page P1. Neu **quorum bi vo** (khong co da so) → dung broadcast toan chain, chuyen sang read-only.

**[MOI] Lop 3 — canary state:** blockhash bang nhau khong chung minh `eth_call` trung thuc. Mot provider co the phuc vu state cu. Moi 60s, goi cung mot `eth_call` toi mot contract canary (mot counter tang don, hoac don gian la `balanceOf(relayer)` cua mot ERC-20 quen thuoc) **pin theo `blockHash`** giong nhau tren moi endpoint; ket qua phai byte-identical. Day la kiem tra duy nhat bat duoc mot archive node dang phuc vu state sai — kieu loi da tung xay ra voi nha cung cap that.

**Lop 4 — phat hien drop im lang:** loi hong nguy hiem nhat la RPC tra ve tx hash cho `eth_sendRawTransaction` roi **khong lan truyen** — job tuong da broadcast, thuc te khong. Phat hien: sau 2 block, xac nhan tx ton tai qua **mot provider KHAC** (`eth_getTransactionByHash` != null hoac `getTransactionCount(pending)` da tang). Khong thay → re-broadcast raw tx (giong het, cung chu ky) qua provider khac; sau 3 lan → eject provider.

#### 06.7.2. Ba quy tac dinh tuyen bat buoc

1. **Sticky provider cho doc nonce-critical.** `getTransactionCount` phai luon hoi cung mot provider trong suot vong doi mot relayer account (ghi `pinned_endpoint_id` tren account). Doc `latest=41` tu node A roi `latest=39` tu node B tut hau → nonce manager tu tao gap. Doi provider chi khi eject, va khi doi thi **bat buoc `cold_start()` toan bo** truoc khi cap lease tiep (§06.1.2) — khong phai chi "reconcile".
2. **Broadcast fan-out, doc thi khong.** Gui raw tx toi **tat ca** provider khoe (tang xac suat lan truyen, khong co tac dung phu vi tx la idempotent theo hash). Nguoc lai, doc state thi chi tu primary + witness kiem chung.
3. **[MOI] Fan-out phai tru cac endpoint co orderflow rieng.** Mot so RPC (MEV-protect, private orderflow, builder-affiliated) **khong** phat tan tx ra mempool cong khai, va gui tx toi do la trao quyen uu tien cho mot ben. Field `blockchain.rpc.endpoint.propagation = Selection([('public','Public mempool'), ('private','Private orderflow'), ('unknown','Unknown')])`. Fan-out chi toi `public`. Endpoint `private` chi dung cho tx co `mev_sensitive=True` (vi du `withdraw` Zether, noi §10.5.3 da bam `recipient` vao challenge nhung gia tri rut van lo ra), va khi do **chi** gui toi do, khong fan-out.

Scoring de chon primary: `score = 0.5*ewma(latency_p95) + 0.3*error_rate + 0.2*head_lag`, EWMA alpha=0,2, danh gia lai moi 30s, doi primary co hysteresis (chi doi khi score tot hon primary hien tai > 25% trong 3 lan lien tiep).

**[MOI] Khong bao gio doi primary trong luc co job o `signed` chua broadcast.** Doi primary keo theo doi endpoint doc nonce (quy tac 1) keo theo cold start. Cho inflight rong, hoac hoan sang chu ky sau.

---

### 06.8. Observability: chi so nao that su quan trong

Prometheus, label chung `{caip2, relayer_addr, tenant, risk_class}`.

| Metric | Type | Y nghia | Alert |
|---|---|---|---|
| `relay_nonce_gap_age_seconds` | Gauge | Tuoi cua nonce bi thung cu nhat | > 120s → **page P1** (moi tx sau do dang chet) |
| `relay_nonce_lease_expired_total` | Counter | Lease het han phai reclaim | > 5/phut → ticket (worker dang chet hoac signer cham) |
| `relay_nonce_desync_total` | Counter | `latest > next` (ai do dung chung vi) | >= 1 → **page P1**, quarantine account |
| `relay_signed_orphan_total` | Counter **[MOI]** | Nonce co raw tx da ky nhung khong co job | >= 1 → **page P1** (mat toan ven WAL) |
| `relay_shard_ownership_lost_total` | Counter **[MOI]** | Worker mat lease shard | > 2/gio → ticket (worker flapping) |
| `relay_sim_exec_divergence_total` | Counter | Sim pass nhung tx revert, label `{category}` | > 0,5% broadcast/15p → ticket; > 20/h cung contract → auto-quarantine |
| `relay_sim_thrash_total` | Counter **[MOI]** | Job phai sim lai >= 3 lan | Tang = state drift cao, xem lai `expiry` |
| `relay_tx_stuck_seconds` | Histogram | broadcast → mined | p99 > 3x `block_time * stuck_after` → ticket |
| `relay_replacement_total` | Counter, label `{kind=speedup\|cancel\|gapfill}` | Speed-up + cancel + gap-filler | Tang dot bien = breaker sap trip hoac fee model sai |
| `relay_bump_ceiling_total` | Counter **[MOI]** | `BumpCeilingReached` | >= 1 → ticket ngay: tx dang ket va khong go duoc |
| `relay_hot_wallet_runway_hours` | Gauge | So du / burn rate | < 4h → ticket; **< 1h → page** |
| `relay_refill_pending_seconds` | Gauge **[MOI]** | Tuoi refill request chua xong | > 1800s → page (automation refill dang hong) |
| `relay_signer_latency_seconds` | Histogram | Do tai HSM/MPC boundary | p99 > 3s → ticket; nut co chai, dashboard rieng |
| `relay_signer_throttled_total` | Counter | 429 tu KMS/MPC | > 0 → tang batch size hoac xin nang quota |
| `relay_batch_size` | Histogram **[MOI]** | So item/batch thuc te | p50 << `batch_size` cau hinh = dang cho vo ich, giam `max_batch_wait_ms` |
| `relay_rpc_head_lag_blocks` | Gauge | Per endpoint | > 3 → demote |
| `relay_rpc_divergence_total` | Counter | Hash lech tai `head - witness_depth`, sau xac nhan lan 2 | >= 1 → **page P1 bao mat** |
| `relay_rpc_state_canary_mismatch_total` | Counter **[MOI]** | `eth_call` canary lech | >= 1 → **page P1 bao mat** |
| `relay_breaker_state` | Gauge (0/1/2) | closed/half/open, per chain per class | Chuyen sang open → thong bao ngay |
| `relay_gas_spend_usd_total` | Counter | Per tenant, per risk_class | 90% quota → thong bao |
| `relay_spend_reservation_leaked_total` | Counter **[MOI]** | Reservation phai refund boi janitor | > 10/gio → bug o duong settle |
| `relay_l1_data_fee_ratio` | Gauge **[MOI]** | `l1_fee / total_fee` tren rollup | > 0,9 → cannh bao chi phi, xem xet nen batch to hon |
| `relay_cost_per_business_action_usd` | Gauge | `gas_spend / batch_item_count` | Chi so ROI that; theo doi hang ngay |
| `relay_zether_epoch_miss_total` | Counter | Tx Zether qua `epoch_deadline_block` | > 1% → tang tip mac dinh lop Zether |
| `relay_finality_wait_seconds` | Histogram | mined → final | Doi chieu bang finality §11; lech ben vung = cau hinh depth sai |
| `relay_admission_queue_depth` | Gauge **[MOI]** | Job `draft` cho lease | > 5 phut worth of throughput → he thong dang tich luy no |

**Nam alert page nguoi luc 3h sang** (ban nhap dau co bon), con lai la ticket: `nonce_gap_age`, `nonce_desync`, `signed_orphan`, `rpc_divergence` (bao gom canary), `hot_wallet_runway < 1h`. Bon cai dau la mat toan ven; cai cuoi la mat dich vu hoan toan trong < 60 phut. Moi thu khac (gas dat, sim fail, tx cham) tu no khong lam hong du lieu.

SLO de xuat: broadcast→`final` p95 <= `finality_hard + 60s`; ty le job den `final` khong can can thiep tay >= 99,5%/thang; `nonce_gap_age` = 0 trong 99,9% thoi gian; `relay_signed_orphan_total` = 0 tuyet doi.

#### 06.8.1. [MOI] Ba runbook phai viet truoc khi len production

| Su co | Trieu chung | Cac buoc |
|---|---|---|
| **Redis bi xoa sach** | Moi key `bc:*` bien mat; worker bao `no_owner` | 1. Dung toan bo worker. 2. Voi moi account: `cold_start()` (§06.1.2). 3. Doi chieu `signed` tai tao tu journal voi `getTransactionCount(pending)`. 4. Neu co nonce trong `[latest, pending)` khong co job → gap-filler. 5. Khoi dong lai worker tung shard mot, cach nhau 30s |
| **`nonce_desync` (`latest > next`)** | Metric >= 1 | 1. Quarantine account **ngay** (tu dong). 2. Khong tu resume. 3. Nguoi truc kiem: co ai chay script thu cong khong? Khoa co bi export khong? 4. Neu nghi lo khoa: `state='retired'`, sweep so du ve treasury bang treasury signer, tao EOA moi. 5. Chi resume khi giai thich duoc nguon goc |
| **Sequencer down (Arbitrum/OP)** | `head_age > 60s` tren moi endpoint | 1. Breaker `SEQUENCER_DOWN`, dung nhan job moi. 2. **Khong** bump, **khong** cancel (tx dang nam trong hang doi cua sequencer). 3. Neu > 2h va co job R3 gia tri lon: danh gia force-inclusion qua L1 delayed inbox — do la quyet dinh cua nguoi, khong tu dong. 4. Reset breaker khi head tang lien tuc 5 phut |

---

### 06.9. Be mat model Odoo (control plane)

Prefix `blockchain.*` (khop voi chot cua §10.3). Tat ca constraint dung `models.Constraint`, khong dung list `_sql_constraints` — Odoo 19 **bo qua hoan toan** dang list, constraint khong bao gio duoc tao trong PostgreSQL. Kiem chung sau khi cai:

```sql
SELECT conname, contype FROM pg_constraint
WHERE conrelid = 'blockchain_relayer_account'::regclass;
```

Theo §10.4.3, `blockchain.relayer.account` la `_inherits` cua `blockchain.account`, khong phai mot bang song song:

```python
class BlockchainRelayerAccount(models.Model):
    _name = 'blockchain.relayer.account'
    _description = 'Relayer EOA in the internal relay pool'
    _inherits = {'blockchain.account': 'account_id'}

    account_id      = fields.Many2one('blockchain.account', required=True,
                                      ondelete='cascade', index=True)
    # chain_id, address, custody_mode, signer_ref, role, company_id -> tu blockchain.account

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

    nonce_confirmed = fields.Integer(readonly=True)      # mirror tu Redis, cho UI/audit
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

Ten field da tranh trung ten kieu Odoo: `balance_sync_datetime` (khong phai `datetime`), `lease_expiry` (khong phai `date`), `payload_text` (khong phai `text`), `calldata_hex` (khong phai `binary`), `rotate_due_date` (khong phai `date`).

`blockchain.relay.job` (rut gon, chi cac truong quyet dinh):

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
    calldata_ref   = fields.Char(help='Redis key bc:calldata:{uuid}; ir.attachment cho R3/R4.')
    raw_tx_ref     = fields.Char(help='Redis key bc:raw:{uuid}, TTL 24h. KHONG luu raw tx tren record.')

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

**[MOI] `_unique_origin` la co che idempotency that su.** Ban nhap dau noi "idempotent theo `origin_ref`" ma khong noi bang gi. Voi partial unique index nay, `relay_submit_intent` goi lai voi cung `origin_ref` se dung `INSERT` va tra ve job cu — khong phai nho code kiem tra truoc (co race), ma nho database. `_unique_nonce_live` la partial index chan truc tiep loi nghiem trong nhat cua §06.1.4.

Method public phuc vu ca `call_kw` lan `/json/2` (khong `_`, khong `@api.private`, khong nhan `allowed_company_ids` tu client):

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

Cron XML (mot dong, khong inline `fields.`/`relativedelta` — `ir.cron` eval context khong co chung):

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

Nhom quyen (khop §10.5): `group_blockchain_viewer` (doc), `group_blockchain_relay_worker` (chi `relay_report_batch`, khong doc duoc `blockchain.account.signer_ref`), `group_blockchain_relayer_admin` (CRUD relayer account, endpoint), `group_blockchain_treasury_manager` (refill approve, breaker override). **Nguoi tao `blockchain.breaker.override` khong duoc dong thoi la nguoi duyet `blockchain.refill.request`** — do la mot duong rut tien mot nguoi.

---

### 06.10. [MOI] Nang luc, chi phi, va luu tru

#### 06.10.1. Ngan sach chi phi ha tang, mot chain (Gnosis), 24.000 tx/ngay

| Muc | Cau hinh | USD/thang (uoc) |
|---|---|---|
| 3 relay worker | 2 vCPU / 4 GB | 120 |
| Redis (nonce), HA primary + replica, AOF always | 2 GB | 60 |
| Node Gnosis tu van hanh (archive nhe, cho `eth_call`/`debug_traceCall`) | 8 vCPU / 2 TB NVMe | 200 |
| 2 RPC provider (fallback + witness) | goi growth | 100 – 400 |
| Prometheus + Grafana + Alertmanager | dung chung ha tang | 0 – 50 |
| **Tong ha tang** | | **480 – 830** |
| Gas that (24k tx/ngay @ $0,007 tx Zether n=64) | | **~5.000** |
| Gas that (24k tx/ngay @ $0,00005 tx thuong 100k gas) | | **~36** |

Doc bang nay theo mot huong: **chi phi gas cua Zether cong khai lon gap 6-10 lan toan bo chi phi ha tang.** Do la lap luan kinh te manh nhat cho private chain, manh hon lap luan bao mat.

Chi phi MPC SaaS **khong** co trong bang vi o 24k tx/ngay (720k chu ky/thang neu khong batch) khong nha cung cap MPC nao ban theo don gia ma con hop ly. Voi batch 50: 14.400 chu ky/thang — nam trong bac thuong. Day la mot rang buoc thuong mai, khong chi ky thuat.

#### 06.10.2. Tang truong bang job

| Gia dinh | So |
|---|---|
| Job/ngay | 24.000 |
| Byte/row (khong ke raw tx / calldata) | ~800 B |
| Postgres/ngay | ~19 MB |
| Postgres/nam | **~7 GB** |
| Index (5 index) | +~60% → **~11 GB/nam** |

Chap nhan duoc **chi khi** khong luu raw tx va calldata tren record.

#### 06.10.3. Chinh sach luu tru raw tx va calldata

| Du lieu | Noi luu | TTL |
|---|---|---|
| `calldata_hex` (co the 2-4 KB voi Zether) | Redis `bc:calldata:{uuid}` | 24h |
| `raw_tx` da ky | Redis `bc:raw:{uuid}` | 24h (du cho moi vong replacement) |
| Ca hai, cho job R3/R4 | `ir.attachment` tren Garage (S3), Many2many nhu quy uoc repo | 7 nam (nghia vu ke toan) |
| Ca hai, cho job R1/R2 | Khong giu sau 24h | — |
| `sim_trace` cua job co divergence | `ir.attachment` | 1 nam |

Ly do R1/R2 khong giu: mot record `blockchain.relay.job` co `tx_hash` la du de tai tao moi thu tu chain. Giu raw tx cua 8,7 trieu job/nam la giu 35 GB de khong bao gio doc.

Job `final` qua 90 ngay: chuyen sang bang lich su bang cron thang (`_cron_relay_archive()`), giu `job_uuid`, `tx_hash`, `origin_ref`, `actual_cost_uusd`, `state`. Khong dung `active=False` — mot bang 8 trieu row voi `active` index van lam moi `search()` cham.

---

### 06.11. [MOI] Test: cai gi phai co truoc khi cham mainnet

Khong phai mot ke hoach QA day du; chi la nhung thu **khong the** kiem chung sau khi len production.

| Hang muc | Cong cu | Kich ban bat buoc |
|---|---|---|
| Nonce lease/freelist | `pytest` + `fakeredis` (Lua chay that qua `redis-server` trong container) | Ky HSM timeout giua chung; worker SIGKILL sau `signed` truoc broadcast; hai worker cung xin cung shard |
| Cold start | anvil + `anvil_setNonce` | Redis flushall khi co 5 job inflight; kiem tra khong nonce nao bi cap lai |
| Replacement / bump | anvil `--block-time 1` + `anvil_setNextBlockBaseFeePerGas` | Base fee tang 12,5%/block x 15 block; xac nhan khong bao gio bi `replacement underpriced` |
| Reorg | anvil `evm_snapshot` / `evm_revert` | `latest` giam 3 block sau khi job da `mined`; job phai ve `reorged`, khong ve `final` |
| RPC noi doi | 2 anvil khac nhau sau mot proxy | Lop 2 va lop 3 phai eject dung endpoint, va **khong** eject khi chi la reorg nong 1 block |
| Velocity limit | Redis that, 200 goroutine/task song song | Tong chi tieu **khong duoc** vuot cap qua 1 job. Kiem tra refund khi job fail |
| Zether epoch | anvil + contract that | Tri hoan tx qua `epoch_deadline_block`; phai cancel, khong duoc speed-up |
| Batch griefing | Foundry | Item co `gasLimit` sat tran → `batch: gas grief` revert, khong phai item cuoi im lang fail |
| Odoo constraint | Odoo test + SQL | `SELECT conname FROM pg_constraint WHERE conrelid LIKE 'blockchain_%'` phai co du cac UNIQUE/CHECK da khai |

Kiem tra cuoi cung, bat buoc, khong the bo: **chay pool tren testnet Gnosis (Chiado) lien tuc 72 gio voi fault injection ngau nhien** (kill worker, ngat Redis, cham RPC, base fee spike gia lap). Chi so nghiem thu: `relay_signed_orphan_total == 0` va `nonce_gap_age` p99 < 120s.

---

### 06.12. Nhung cho note chua chot, va de xuat

1. **Ai la chu so huu nonce khi ca Open Relayer lan Relay Pool noi bo deu nhin thay mot intent?** De xuat: intent noi bo mac dinh `MODE_RESTRICT_RELAYER (0x01)` gan vao pool noi bo trong `T_exclusive = 2 * block_time`; het han thi consumer ky lai ban `MODE_OPEN` va tha ra intent bus cong khai (§05). Ky hai lan la chi phi CPU, re hon mot tx trung. **[MOI]** Ky hai lan cung co nghia la **hai chu ky HSM cho mot hanh dong** — voi MPC 10 sign/s do la 10% ngan sach ky. Neu dung session key cua user (re) cho `MetaTransaction.signature` thi khong sao; neu la HSM thi phai tinh vao mo hinh nang luc §06.6.1.
2. **Khong co dinh nghia "gap-filler" nao trong note.** Da chot o §06.1.7 (self-send 21.000 gas, gia = `max(p75, ceil_bump(last_known))`, chi phi vao overhead cua pool). Can nguoi duyet dong ngan sach nay.
3. **`meta_nonce` tang truoc hay sau `call`?** Day la **quyet dinh contract, nhung relay pool khong the an toan neu chua chot.** Ba lua chon:
   - (a) Tang **sau**, chi khi `call` thanh cong: user khong bi dot nonce, nhung **relayer tra gas cho mot tx revert va khong duoc gi** → open relayer se khong bao gio nhan intent cua ta.
   - (b) Tang **truoc**, thu phi ke ca khi `call` fail (de xuat o §06.6 muc 1 (c)): relayer luon duoc tra, nhung mot relayer doc co the dot nonce va **phi** cua user bang cach nop tx chac chan revert.
   - (c) Tang truoc + thu phi + **`antiGriefBond`**: `msg.sender` phai stake mot khoan; neu `call` fail thi bond bi tich thu ve user. De xuat con so: `bond = 3 * fee`, hoan lai ngay trong cung tx neu thanh cong (chi phi ~5.000 gas cho 2 SSTORE warm).
   **De xuat chon (c)**, nhung no lam contract phuc tap hon va can mot lan audit rieng. Neu chon (b) thi relay pool phai giu `MODE_RESTRICT_RELAYER` cho moi thu co gia tri, tuc bo phan lon loi ich cua Open Relayer Network.
4. **Chi phi Zether that** can benchmark tren Foundry truoc khi khoa `max_gas_per_tx`. Con so 3,5M (n=64) va 6,6M (n=128) o §06.4.5 la uoc tinh tu so diem MSM x 6.000 gas — no bo qua moi toi uu batching precompile va co the sai 30% ve mot phia. **[MOI]** Va cau hoi lon hon nam truoc no: **n=64 hay n=128?** Do la mot quyet dinh san pham (dust 10^-6), khong phai quyet dinh ky thuat.
5. **Phan tang custody** (HSM cho treasury, enclave cho relayer hot) can nguoi duyet ve compliance — day la danh doi throughput 3 bac do lon. §07.0 da de xuat cung huong; can mot chu ky.
6. **[MOI] Bulletproofs hay Groth16?** Note dung ca hai ngon ngu (§10.5.2 noi Bulletproofs, con so gas lai la Groth16). Chenh lech **~30 lan gas**. Bulletproofs: khong trusted setup, prove nhanh, verify dat. Groth16: trusted setup per-circuit (ceremony), prove cham (bat loi tren mobile), verify re. Voi private chain (gas khong quan trong) Bulletproofs thang de dang. Voi public chain va luong "end-user payment tai quay", Groth16 co the la lua chon dung nhung keo theo mot ceremony phai to chuc. **Can chot truoc khi viet contract**, vi no doi ca client SDK.
7. **[MOI] Ai so huu ngan sach gas?** Velocity limit co ba tang (agent, tenant, global) nhung khong ai noi tenant co *mua* han muc khong, hay do la chi phi cua nen tang. Neu la chi phi nen tang thi `relay_cost_per_business_action_usd` la mot dong lo/lai that va phai co nguoi chiu trach nhiem. Neu tenant tra thi can mot mo hinh tinh phi va no cham vao §09 (payment modes).
8. **[MOI] Chinh sach khi mot job R3 gia tri lon roi vao `quarantined`.** Hien tai: "nguoi phai vao xem". Chua du cho mot khoan B2B settlement. Can mot SLA: bao lau thi phai co quyet dinh, ai quyet, va co duong tra tien bang kenh khac (bank transfer) khong. Do la quy trinh nghiep vu, khong phai code, nhung thieu no thi `quarantined` la mot ho den.
9. **[MOI] Dong ho.** Hedera (`validStart`), TON (`timeout` cua Highload V3), va moi `expiry`/`deadline` cua meta-tx deu phu thuoc dong ho cua relay worker. Chua ai noi ai bao dam NTP. De xuat: chronyd voi >= 3 nguon, alert khi `|offset| > 500 ms`, va relay worker **tu tat** khi `|offset| > 5 s`.
10. **[MOI] Private chain: ai la validator?** Quyet dinh khoa #5 dua private chain len truoc, nhung "private" chua duoc dinh nghia: mot node cua ta (khi do "blockchain" chi la mot database co chu ky), hay N node cua N doi tac B2B (khi do moi co y nghia). Toan bo phan RPC divergence (§06.7) va Finality Gate chi co gia tri o phuong an sau. Can chot truoc khi chon client (Besu QBFT / Quorum / go-ethereum Clique).

---

### 06.13. [MOI] Tong hop nhung cho ban nhap dau nay da sua so voi ban truoc

| # | Cho | Ban truoc | Ban nay |
|---|---|---|---|
| 1 | `lease_nonce.lua` fence | `INCR` fence moi lan lease → kiem tra fence vo tac dung | `owner_fence` chi tang khi doi chu; them `gen` cho cold start |
| 2 | Tra lease khi lease het han | Luon `ZADD free` neu chua len chain | **Khong bao gio** tra freelist neu da `signed`; chi thoat bang replacement |
| 3 | Cold start | Khong co | Giao thuc day du §06.1.2, dua tren journal Postgres |
| 4 | Quyen so huu shard | Consistent hash | Ownership lease co TTL + fencing |
| 5 | `ttl_ms` L1 | 45s | 37s (so hoc dung: `3*12000+1100`) |
| 6 | TON Highload V3 | "~8k slot query_id" | **8.388.608 slot (23 bit)**, cua so 128s |
| 7 | Celo | L1 IBFT 2.0, 5s block | **OP Stack L2 tu 03/2025**, 1s block, co L1 data fee |
| 8 | Arbitrum + Base | Gop lam mot ("khong co mempool") | Ba nhom khac nhau (§06.2.2); OP Stack **co** replacement, Arbitrum thi khong dang tin |
| 9 | Ham `bump()` | So sanh tip voi cap cua max_fee; nhan float | Tran rieng cho tip; so nguyen `ceil_bump`; `BumpCeilingReached` |
| 10 | Chi phi L1 data tren rollup | Khong nhac | §06.2.5, co dia chi predeploy va bien do 1000x |
| 11 | Gia dinh dropped vs underpriced | Gop lam mot | Tach: `underpriced` phai bump, khong phai re-broadcast |
| 12 | EIP-196 dinh gia `ecAdd`/`ecMul` | Gan cho EIP-196 | **EIP-1108** moi la cai ha xuong 150/6.000; EIP-196 goc la 500/40.000 |
| 13 | Gas Zether | 2,0–2,5M | 3,5M (n=64+fee) / **6,6M (n=128+fee)**; note bo sot ba range statement cua co che fee |
| 14 | Note "180-250k gas" | "chi dung cho vai ecAdd/ecMul" | Chinh xac hon: **do la con so cua Groth16**, khong phai Bulletproofs. Hai thu trong note mau thuan nhau |
| 15 | Velocity limit | `INCRBYFLOAT`, kiem tra rieng | Lua nguyen tu, micro-USD so nguyen, reserve + settle + janitor refund |
| 16 | `balance_native` | `fields.Float(digits=(24,8))` | Mau thuan §10.4.1 → `Char` base units + `Float` chi de hien thi |
| 17 | `runway_hours` | `required=True` roi phai canh giac NULL | Bo `required=True`; quy tac "gan o moi nhanh" van giu |
| 18 | Idempotency `origin_ref` | Noi "idempotent" khong noi bang gi | Partial unique index `_unique_origin` |
| 19 | `witness_depth` | Hang so 12 block | Theo chain; va lech mot lan khong duoc eject ngay |
| 20 | Kiem tra RPC | 3 lop | 4 lop, them **canary `eth_call`** — 3 lop cu khong bat duoc state sai |
| 21 | Batch executor | Chi noi `try/catch` | Them EIP-150 63/64 guard, fee-on-failure, va cach sim mot batch |
| 22 | Backpressure | Khong co | `max_inflight = 16` (co so: `txpool.accountslots`), `inflight_full` trong Lua |
| 23 | Tenderly | O hot path | **Ra khoi hot path** — chi phi 720k don vi/thang; hot path dung node cua minh |
| 24 | Luu tru | Khong nhac | §06.10.3; raw tx khong nam tren record |
| 25 | Reorg | Khong nhac trong nonce manager | `latest < confirmed` → `reorged`, khong lui `next` |
