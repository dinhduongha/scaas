# Thanh toán on-chain bằng meta-transaction — Thiết kế

**Ngày:** 2026-10-03 · **Trạng thái:** đã duyệt nội bộ, chờ review ngoài · **Rev 1.1 (2026-10-07):** Claude
review 1 folded (§15: rulings CR-PD-1…6, streams PAY-FIX1…7, superseded-rulings table §15.3); the private chain is
7622 (formerly 9000).
**Nguồn:** `ai-enterprise-blockchain-architecture.md` v3.3, `ai-enterprise-blockchain-integration.md` v2.5,
`smartcontracts/**`, `docs/superpowers/specs/blockchain-research/00-CANON.md`, `_USER-DECISIONS.md`.

> **Thứ bậc hiệu lực** (lấy nguyên từ SRS §0): (1) mã nguồn contract đã compile và test ghim
> (`MetaTxLib`, `ERC20MetaTx`, `FeePolicy`, `IOpenFactory`), (2) canon, (3) SRS kiến trúc,
> (4) SRS tích hợp. Spec này **xây trên** các quyết định đã khoá; chỗ nào lệch thì có một
> ruling ở §13, kèm lý do và cái giá nếu sai.

---

## 0. Mục tiêu

Một lát cắt dọc **chạy thật được**, từ contract tới màn hình portal:

1. **Contract** (Foundry, `smartcontracts/`): implementation `MetaToken` v1 (clone EIP-1167, tầng
   1 standalone + tầng 2 wrapper 1:1), `OpenFactory` hiện thực `IOpenFactory`, và `MetaTxDex` —
   sàn khớp lệnh nguyên tử P2P (SRS §3.3) không dùng allowance.
2. **Relayer** `scaas-node` (Rust, một binary — `_USER-DECISIONS` §23): mô-đun `submit`
   (outbox Odoo → simulate → ký vỏ tx → broadcast), `indexer` (log → finality gate + quorum RPC →
   Odoo), `gateway` (HTTP: nhận meta-tx đã ký từ bất kỳ ai, sổ lệnh DEX + matcher).
3. **Odoo** (ba addon tuỳ chọn): `dms_blockchain` (control plane), `dms_blockchain_payment`
   (provider `chain` trên framework `payment`), `dms_blockchain_bridge` (portal DMS).
4. **Người dùng portal trả đơn hàng on-chain, không cần gas**: ví ký EIP-712, công ty relay và
   trả gas, Odoo chỉ ghi nhận "đã trả" khi sự kiện `PaymentSettled` qua cổng finality.

Không mục tiêu nào ở trên đòi `bamboo_dms` biết blockchain tồn tại: `bamboo_dms` cài và chạy
y nguyên khi ba addon vắng mặt.

---

## 1. Tổng quan kiến trúc

```
 Trình duyệt portal (ví EIP-1193)                         Bất kỳ ai (ví, agent, đối tác)
   │ call_kw dms.portal.api.*  ▲ typed data                   │ POST /v1/metatx, /v1/dex/orders
   ▼                          │                               ▼
+-----------------------------------------------+     +--------------------------------------+
| Odoo 19                                       |     | scaas-node  (Rust, một binary)      |
|  dms_blockchain_bridge  (portal facade)       |     |  [gateway] HTTP: inbound meta-tx,    |
|  dms_blockchain_payment (provider 'chain')    |     |            sổ lệnh DEX + matcher     |
|  dms_blockchain (chain, token, metatx,        |     |  [submit]  poll job → simulate →     |
|     relay.job = OUTBOX, chain.event,          |◄────┤            ký → broadcast → báo cáo  |
|     payment.request)                          | json/2  [indexer] getLogs → finality gate |
|  Không giữ khoá. Không gọi RPC chain.          | API key  → quorum → chain_event_ingest   |
+-----------------------------------------------+     |  Signer: khoá vỏ tx (authKey)        |
                                                      +------------------┬-------------------+
                                                                         │ JSON-RPC (≥1 endpoint/chain)
                                                      +------------------▼-------------------+
                                                      | EVM: chain 7622 (formerly 9000)      |
                                                      |  OpenFactory · MetaToken clones ·    |
                                                      |  MetaTxDex                           |
                                                      +--------------------------------------+
```

Ba ranh giới, và mỗi cái có đúng một đường đi qua:

| Ranh giới | Đường duy nhất | Vì sao |
|---|---|---|
| Odoo → chain | **outbox** `blockchain.relay.job` (canon §C13) | Odoo không mở socket trong transaction nghiệp vụ |
| node → Odoo | **`/json/2`** + API key của service user | mọi ghi qua ORM: constraint, rule, compute đều chạy |
| chain → Odoo | **indexer** sau finality gate, qua `chain_event_ingest` | "broadcast không phải là thanh toán; mined cũng không" (canon §C12) |

---

## 2. Smart contracts

Cây `smartcontracts/` giữ nguyên bố cục đã chốt (`common/`, `metatx/`, `zether/`, `chains/`), thêm
`factory/` và `dex/`. Solidity 0.8.28, OpenZeppelin 5.2, profile `private9000` = `prague`.

### 2.1 `MetaToken` — implementation v1 của kind `META`

`contract MetaToken is ERC20MetaTx, IERC20Payment` — kế thừa **nguyên** mixin `ERC20MetaTx` đã đo
gas (bước 1–9 của §04.6.1). Một implementation duy nhất, hai tầng của SRS §3.1 chọn bằng
`underlying`:

| | Tầng 1 standalone (`underlying == 0`) | Tầng 2 wrapper (`underlying != 0`) |
|---|---|---|
| Cung | `initialSupply` mint cho `creator` lúc init; `mint(to, v)` chỉ `minter` (0 = cung cố định) | chỉ qua `wrap` |
| `decimals` | từ `initData` | đọc `IERC20Metadata(underlying).decimals()` lúc init |
| Nạp/rút | — | `wrap(amount)` (đo **delta số dư** thật nhận được, mint đúng delta) / `unwrap(amount, recipient)` |
| Bất biến | `Σ balance == totalSupply` | thêm `underlying.balanceOf(this) >= totalSupply` |

**`initData`** (ABI cố định cho v1): `abi.encode(string name, string symbol, uint8 decimals, uint256 initialSupply, address minter)`. Tầng 2 dùng `name`/`symbol`, bỏ qua `decimals` (đọc từ underlying) và **bắt buộc** `initialSupply == 0 && minter == 0` (`WrapperHasNoMint`).

**Clone-safe** (`01-token-factory.md` §1.3.5, §1.4.3):
- `constructor(address factory_)` của implementation đặt `FACTORY` và `_SELF` (immutable, đúng cho
  mọi clone) và khoá implementation (`_initialized = true` trên storage của chính nó).
- `initialize(creator, underlying, verifier, version, initData)` — `require(msg.sender == FACTORY)`,
  một lần, `verifier == 0` (kind META). Factory gọi nó **trong cùng hàm** với `CREATE2`.
- `name()`, `symbol()`, `decimals()` override để đọc storage của clone.
- **EIP-712 domain**: OZ `EIP712` giữ `name`/`version` dạng immutable, nên mọi clone của v1 có
  domain `name = "SCaaS MetaToken"`, `version = "1"`, `chainId`, `verifyingContract = clone`.
  Không có replay chéo token vì `verifyingContract` khác nhau. Client đọc domain qua
  `eip712Domain()` (ERC-5267); Odoo lưu `domain_name`/`domain_version` trên `blockchain.token`
  (SRS tích hợp §2.6). Ruling R5.
- Xuất xứ: `factory()`, `creator()`, `underlying()`, `verifier()` (= 0), `implementation()`
  (= `_SELF`), `version()`.

**Thao tác qua `executeMetaTransaction`** — `data` là **op có tag selector**, không thêm typehash
nào (ruling R2). `_checkOp` (bước 6) kiểm đủ; `_executeOp` (bước 8) không được fail:

| `data` | Kiểm ở bước 6 | Làm ở bước 8 |
|---|---|---|
| rỗng | — (số dư đã kiểm) | `transfer(from → to, value)` (giữ nguyên hành vi đã đo) |
| `pay(bytes32 entryRef)` — đúng 36 byte (`data.length < 4` ⇒ `MetaTxUnknownOp(0)`, không panic) | `to != 0` | transfer + `emit PaymentSettled(from, to, value, feeAmount, feeRecipient, entryRef)` |
| `trade(address counterToken, uint256 minCounterValue, address counterparty)` — đúng 100 byte | `mode & MODE_RESTRICT_RELAYER != 0` **và** `to == msg.sender` | transfer `from → msg.sender` (settlement contract) |
| khác | revert `MetaTxUnknownOp(bytes4)` (error mới, khai trong `MetaToken`; relayer giải mã từ ABI của `MetaToken`) | — |

Để event `PaymentSettled` mang phí thật, `ERC20MetaTx._executeOp` nhận thêm
`(feeAmount, feeRecipient)` — thay đổi chữ ký hàm internal, không đổi ABI, không đổi digest.

`payWithFee(...)` của `IERC20Payment` (đường gọi thẳng, `msg.sender` trả gas) cũng hiện thực,
dùng chung `FeePolicy`.

**Không có** `pause`, `blacklist`, `freeze`, owner, upgrade: token tự do (SRS §3.5.1). Token có
kiểm soát (`IRegulatedToken`) ngoài phạm vi.

### 2.2 `OpenFactory` — hiện thực `IOpenFactory`

- `constructor(address registrar)`. `registerImplementation` và `deprecate` chỉ `registrar`;
  catalogue **append-only** (`VersionAlreadyRegistered`), `deprecate` chỉ đánh dấu.
- Salt hiệu dụng `keccak256(abi.encode(creator, salt))` — creator là `msg.sender`, nên không ai
  chiếm được địa chỉ của người khác; `predictAddress(impl, creator, salt)` là hàm thuần.
- `createMetaToken` / `createZetherToken` / `createUnregistered`: `Clones.cloneDeterministic` rồi
  `IFactoryToken(token).initialize(...)` **cùng một hàm**. `createZetherToken` gọi
  `verifier.isSupportedOnThisChain()` (try/catch → `VerifierUnsupportedOnThisChain`).
  `createUnregistered` ghi `version == 0`, kiểm `implementation.code.length > 0`.
- Sổ tra: `isDeployedHere`, `creatorOf`, `versionOf`, `getWrapper(creator, underlying)` (cái đầu),
  `getWrapperCount/At`, `deployCountFor/deployedFor(underlying)`.
- `IFactoryToken` (mới, `src/factory/IFactoryToken.sol`): đúng một hàm `initialize(...)`. Đây là
  hợp đồng giữa factory và mọi implementation tương lai, kể cả Zether.

### 2.3 `MetaTxDex` — khớp lệnh nguyên tử, không allowance

SRS §3.3 mô tả `settleTrade(makerTx, takerTx, makerSig, takerSig)` với relayer nộp, zero lockup,
`minAmountReceive`, `validUntil`. Thiết kế giữ đúng hình đó **mà không cần `approve`**:

- Mỗi **lệnh** là một `MetaTransaction` trên token bán, `data = trade(counterToken,
  minCounterValue, counterparty)`, `to = relayer = MetaTxDex`, cờ `MODE_RESTRICT_RELAYER`. Chữ ký
  nói: *"chỉ `MetaTxDex` được thực thi lệnh chuyển này, và chỉ vào chính nó"*. Token tự ép điều đó
  ở bước 6 (§2.1), nên một lệnh bị lộ không thể bị ai thực thi lẻ.
- `settle(Leg a, Leg b)` với `Leg = {IERC20MetaTx token; MetaTransaction m; bytes sig}`:
  1. decode điều khoản hai chân; `a.token != b.token`, `a.m.from != b.m.from`;
  2. `termsA.counterToken == b.token`, `b.m.value >= termsA.minCounterValue` (và đối xứng);
     `counterparty` = 0 hoặc đúng `from` của chân kia;
  3. chân có phí (`feeMode != NONE`) phải có `feeRecipient != 0` và `!= this` — nếu không phí rơi
     vào DEX (do `ERC20MetaTx` mặc định `feeRecipient = msg.sender`) và kẹt vĩnh viễn;
  4. gọi `executeMetaTransaction` của **cả hai** token; đo **delta số dư** của DEX trên mỗi token
     phải đúng `m.value` (token lạ/phí-chuyển bị từ chối);
  5. trả `a.m.value` token A cho `b.m.from`, `b.m.value` token B cho `a.m.from` bằng `SafeERC20.safeTransfer`;
  6. `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`.
- Bất kỳ bước nào fail ⇒ cả tx revert ⇒ không chân nào thực thi, không nonce nào tiêu.
- `ReentrancyGuardTransient`. Không owner, không sweep, không upgrade. **Bất biến:** số dư của DEX
  trên mọi token **không đổi qua một `settle`** (ai gửi thẳng token vào DEX thì số đó kẹt vĩnh
  viễn — không có sweep là chủ ý, và bất biến phát biểu theo delta, không theo giá trị tuyệt đối).
- **Fill-or-kill**: `value` được ký chính xác, nên không có khớp một phần (ruling R3). Phần dư
  giá (`b.m.value > minCounterValue`) thuộc về người bán chân A — nó đã nằm trong chữ ký của B.
- Phí relayer: mỗi chân có thể trả phí bằng token của chính nó (`FIXED`/`PERCENT`, trần 1%) cho
  `feeRecipient` do relayer ngoài điền (không ràng buộc) hoặc người ký chỉ định.

### 2.4 Deploy

`script/Deploy.s.sol` (forge script, đọc `PRIVATE_KEY`, `REGISTRAR`): deploy `OpenFactory`,
`MetaToken` implementation (constructor nhận địa chỉ factory), `registerImplementation(META, 1)`,
`MetaTxDex`; tuỳ chọn tạo một token demo tầng 1. In địa chỉ ra JSON để seed Odoo và config node.
Chain 7622 (formerly 9000) dùng profile `private9000` (tên profile và `--chain-id` của test đổi cùng stream
migration của owner); test tích hợp dùng `anvil --chain-id 9000 --hardfork prague`.

---

## 3. Relayer `scaas-node`

Một crate Rust ở gốc repo (`scaas-node/`), cạnh `smartcontracts/`. `tokio`, `alloy` (provider,
`sol!`, EIP-712, signer), `axum`, `reqwest`, `serde`, `toml`. Một binary, mô-đun bật bằng config
(`_USER-DECISIONS` §23.3). **Không Redis, không Lua, không Postgres trực tiếp** (ruling R6).

### 3.1 Cấu hình (`node.toml`)

```toml
[odoo]
url = "http://odoo:8069"
database = "odoo19"
relay_api_key_env = "SCAAS_RELAY_API_KEY"     # user trong group_blockchain_relay_worker
indexer_api_key_env = "SCAAS_INDEXER_API_KEY" # user trong group_blockchain_indexer

[modules]
submit = true
indexer = true
gateway = true            # bind 127.0.0.1:8545x — đặt sau reverse proxy

[[chains]]
evm_chain_number = 7622                        # formerly 9000 (CR-PD-6)
rpc_urls = ["http://nethermind:8545"]          # >= finality.quorum endpoint độc lập; logs đọc từ đủ quorum (CR-PD-2)
signer_key_env = "SCAAS_RELAYER_KEY_7622"     # authKey vỏ tx — xem §6
finality = { mode = "depth", depth = 1, quorum = 1 }   # 'depth' | 'tag'
dex = "0x…"                                     # MetaTxDex, tuỳ chọn
poll_ms = 1000
stuck_after_secs = 60                           # thay thế cùng nonce, fee x1.25
max_gas_per_tx = 3000000                        # mạch ngắt SRS §6.8
max_fee_cap_gwei = 500                          # trần phí khi thay thế tx kẹt
```

Danh sách token **không** nằm trong config: node đọc nó từ Odoo (`node_config`) — một nguồn sự thật.

### 3.2 Mô-đun `submit` — tiêu thụ outbox

Một task cho mỗi chain, **sở hữu duy nhất** nonce vỏ của ví relayer (`_USER-DECISIONS` §23.1:
một tiến trình thì nonce là biến trong bộ nhớ).

```
loop mỗi poll_ms:
  jobs = odoo.relay_poll(chain, limit=10)              # chain_state='queued'
  for job: if odoo.relay_claim([job.id], node_id) trả lại job.id:   # CAS queued→nonce_leased
     sim = eth_call(token.executeMetaTransaction(m, sig), from=relayer, block=latest)
     revert  → odoo.relay_report(job, 'dead', error=decode(revert))  # MetaTxBadNonce, Expired…
     gas > max_gas_per_tx → 'dead'
     ok → ký EIP-1559 (nonce = next++) → tx_hash biết TRƯỚC khi gửi
          → odoo.relay_report(job, 'signed', tx_hash, nonce)        # ghi journal trước
          → eth_sendRawTransaction → odoo.relay_report(job, 'broadcast')
  theo dõi in-flight: receipt có  → status 0: 'reverted';  status 1: 'mined'
                      quá stuck_after_secs → thay thế cùng nonce, maxFee/priority ×1.25,
                      lặp không giới hạn tới trần max_fee_cap; KHÔNG BAO GIỜ bỏ rơi một nonce:
                      job phải bỏ (meta-tx hết hạn) ⇒ thay bằng tx 0-value tự chuyển cho chính
                      mình ở đúng nonce đó (gap-filler, SRS §6.8)
```

- Khởi động (cold start, `_USER-DECISIONS` §23.1): `next = max(getTransactionCount(pending),
  journal_max + 1)` với `journal_max` = `outer_nonce` lớn nhất Odoo đã ghi cho địa chỉ relayer
  trên chain này (`node_config`). Nonce nào trong `[getTransactionCount(pending), journal_max]`
  không còn tx trong mempool (`eth_getTransactionByHash` của job ghi nonce đó trả null) được lấp
  bằng gap-filler, và job của nó về `queued` (meta-tx nonce chặn thực thi đôi). Job
  `nonce_leased` không `tx_hash` → `queued`; job `signed`/`broadcast` có `tx_hash` → hỏi receipt /
  mempool rồi tiếp tục theo dõi — **không** ký lại (tránh nộp đôi một meta-tx, tốn gas vô ích).
- Simulation gate là bắt buộc (SRS §5.2, W3B-02 = 0%): không có `eth_call` xanh thì không ký.
- `final` của job **không** đến từ `submit`: nó đến từ `indexer` (§3.3) khi
  `MetaTransactionExecuted(digest)` qua cổng finality. Nhờ vậy job cũng final đúng khi meta-tx đã
  được người khác thực thi (MODE_OPEN, tự-relay của bên nhận).
- Hàng đợi riêng của gateway (§3.4) đi qua cùng task, cùng nonce, cùng simulation gate.
- **CR-PD-5 (Claude review M3):** `relay_report(signed)` là idempotent cho cùng `(tx_hash, outer_nonce)`; báo cáo
  lỗi (ví dụ timeout sau khi Odoo đã commit) ⇒ work giữ nguyên `(raw, hash, n)` đã ký và báo lại đúng giá trị đó
  trước khi gửi; nonce `n` không được giao cho job khác trong lúc chờ.
- **CR-PD-1 (Claude review H1):** job `call` chỉ được ký khi selector + đích khớp bảng của CR-PD-1 (§15.2), không
  bao giờ khi đích là token đã đăng ký; ngược lại `dead` với `CALL_TARGET_REFUSED`, trước simulation.

### 3.3 Mô-đun `indexer` — finality gate

```
cursor = odoo.node_config(chain).indexed_block
loop:
  head_final = mode=='tag'   ? eth_getBlockByNumber('finalized').number
             : latest.number - depth
  to = min(head_final, cursor + 1000);  nếu to <= cursor: ngủ
  hash_to = block(to).hash trên endpoint chính
  quorum: đếm endpoint trả cùng hash_to tại 'to'; < quorum → không tiến, cảnh báo
  logs = eth_getLogs(from=cursor+1, to, address=[tokens…, dex], topics=[MetaTransactionExecuted,
                      PaymentSettled, TradeSettled])
  odoo.chain_event_ingest(chain, cursor+1, to, hash_to, decoded(logs))   # nguyên tử phía Odoo
  cursor = to
```

- Odoo **từ chối** lô không liền mạch (`from_block != indexed_block + 1`), nên một indexer chạy
  lại hoặc chạy đôi không bao giờ tạo lỗ hổng hay ghi trùng; dedup thêm bằng
  `UNIQUE(chain_id, tx_hash, log_index)`.
- Chỉ log trong khoảng **đã final** được gửi đi; không có trạng thái "observed" bên Odoo ⇒ không có
  đường nào biến một log chưa final thành `_set_done` (canon §C10.9: flow gắn
  `payment.transaction` dùng ngưỡng hard).
- Seed từng chain: `finality_mode`/`finality_depth`/`finality_quorum` lấy từ `blockchain.chain`
  (Odoo là nguồn), node config chỉ là mặc định khi Odoo chưa khai. *(Superseded: NI R95/R96 — node store là
  nguồn cấu hình, §15.3.)*
- **CR-PD-2 (Claude review H2) — quorum trên event, không chỉ trên một block hash.** Pseudo-code trên chỉ so
  `hash_to` và đọc `finalized` + mọi log từ endpoint chính: một RPC gian dựng được `PaymentSettled` giả (nó thấy
  `entryRef` qua chính `eth_call` simulate của node). Từ rev 1.1: logs của mỗi vùng đọc từ ≥ `quorum` endpoint và
  phải là **cùng một tập** đã chuẩn hoá; `finalized`/`latest` lấy **min** trên quorum; lệch ⇒ không ingest, cảnh
  báo, `/readyz` đỏ. `quorum = 1` = tin một nhà cung cấp, node báo rõ (§15.2).

### 3.4 Mô-đun `gateway` — inbound công khai và DEX

HTTP (axum), không xác thực (relayer mở — SRS §4.9.4, §5), giới hạn body 64 KiB, giới hạn đồng
thời toàn cục (`tower` `ConcurrencyLimitLayer`, mặc định 32) vì mỗi request tốn một `eth_call`.
Với chân có phí mà `feeRecipient` **không** bị ràng buộc, gateway điền `feeRecipient = địa chỉ
relayer` trước khi simulate (nếu để 0, `ERC20MetaTx` trả phí cho `msg.sender` — khi simulate
`from = dex` thì "qua", tới `settle` lại bị `FeeWouldStick`). Chân `MODE_RESTRICT_FEE_RECIPIENT`
với `feeRecipient ∈ {0, dex}` bị từ chối ngay. Việc kẻ khác chép calldata `settle` và thay
`feeRecipient` (khi người ký không ràng buộc) là **theo thiết kế** của relayer mở: ai trả gas thì
nhận phí; người ký muốn chặn thì bật cờ ràng buộc.

| Route | Việc |
|---|---|
| `POST /v1/metatx` `{chain, token, m, signature}` | token phải nằm trong danh sách Odoo; parse chặt; `metaTxDigest` + simulate; ok → hàng đợi `submit`; trả `digest` |
| `POST /v1/dex/orders` `{chain, leg}` | leg phải là `trade(...)` với `relayer == to == dex`, chưa hết hạn; simulate **từng chân** bằng `eth_call` với `from = dex` (token chỉ cho DEX thực thi, và `eth_call` cho phép đặt `from` tuỳ ý mà không cần chữ ký) — bắt chữ ký sai, thiếu số dư, nonce đã tiêu ngay ở cửa; đưa vào sổ, chạy matcher |
| `GET /v1/dex/orders?chain&sell&buy` | đọc sổ |
| `GET /healthz` | sống; `GET /readyz` — RPC và Odoo trả lời |

**CR-PD-3 (Claude review M1):** Door A không phải vòi gas miễn phí — `value == 0` bị từ chối ở cửa, sàn
`min_fee` của cửa `~gateway` (TSS R189) áp dụng (policy tài trợ miễn sàn và giới hạn ngân sách), profile `public`
từ chối intent phí 0 không có policy tài trợ, giới hạn theo `from` (§15.2). **Claude review L5:** job của gateway
không có journal Odoo (`submit.rs` chỉ journal khi có `job_id`) — chấp nhận theo R16; SCaaS N2 "BUILT" chỉ đúng cho
job Odoo cho tới NI R105.

Matcher: với lệnh mới L (bán `L.value` A, đòi ≥ `minB` B), quét lệnh nghỉ R của cặp ngược theo FIFO,
điều kiện `R.value >= L.minB && L.value >= R.minA` và `counterparty` khớp; simulate
`settle(L, R)`; ok → đẩy vào `submit`. Lệnh hết hạn bị dọn. Sổ lệnh nằm trong bộ nhớ (ruling R16).

### 3.5 Hợp đồng RPC Odoo ↔ node (json/2)

`POST /json/2/<model>/<method>`, `Authorization: Bearer <api key>`, `X-Odoo-Database`.

| Method (model) | Nhóm | Vào | Ra / tác dụng |
|---|---|---|---|
| `node_config` (`blockchain.chain`) | relay_worker hoặc indexer | `evm_chain_number, relayer_address?` | chain params, finality, `indexed_block`, token `[{address, decimals}]`, `journal_max_nonce` và `inflight` (job `nonce_leased/signed/broadcast` của relayer, kèm payload) cho cold start |
| `relay_poll` (`blockchain.relay.job`) | relay_worker | `evm_chain_number, limit` | job `queued` kèm metatx đầy đủ (struct + signature + token) |
| `relay_claim` (`blockchain.relay.job`) | relay_worker | `job_ids, worker` | id claim được (CAS `UPDATE … WHERE chain_state='queued' RETURNING id`) |
| `relay_report` (`blockchain.relay.job`) | relay_worker | `job_id, chain_state, tx_hash?, outer_nonce?, error?` | chuyển trạng thái theo bảng cho phép §4.3 |
| `chain_event_ingest` (`blockchain.chain.event`) | indexer | `evm_chain_number, from_block, to_block, to_block_hash, events[]` | ghi event + áp tác dụng + tiến cursor, **một transaction** |

Mọi method kiểm nhóm tường minh (`has_group`), rồi `sudo()` bên trong. Không method nào nhận
`company_id` từ client.

---

## 4. Odoo addons

### 4.1 Ranh giới module

| Addon | `depends` | `auto_install` | Chứa |
|---|---|---|---|
| `dms_blockchain` | `base`, `mail` | `False` | chain, rpc endpoint, token, metatx, relay job (outbox), chain event, payment request; `lib/eip712.py` (keccak-256 + EIP-712 + ecrecover thuần Python); nhóm, ACL, rule, menu, cron |
| `dms_blockchain_payment` | `dms_blockchain`, `payment` | `False` | `payment.provider` `code='chain'`, `payment.method` `chain`, nối `payment.transaction` ↔ `blockchain.payment.request`, `_set_done` từ cổng thanh toán |
| `dms_blockchain_bridge` | `dms_blockchain_payment`, `dms_portal` | **`True`** | facade RPC trên `dms.portal.api`, nút + JS ký trên trang đơn portal |

- `bamboo_dms` không depends gì ở trên. `dms_portal` không depends gì ở trên. Bridge tự cài khi cả
  hai phía đã có (canon §C3: `auto_install: True` = `set(depends)`).
- **Không** depends `bamboo_idempotency` (ruling R7) và **không** có `dms_blockchain_account`
  (ruling R8): `account_payment` (Odoo chuẩn, tự cài khi có `account` + `payment`) đã tạo
  `account.payment` và gạch nợ khi `payment.transaction` sang `done`.
- Không thư viện Python ngoài: keccak-256 và secp256k1 viết thuần (ruling R13).

### 4.2 `dms_blockchain` — model

Quy ước canon §C2: prefix `blockchain.`, uint256 là `Char` + CHECK `'^(0|[1-9][0-9]{0,77})$'`
hậu tố `_base`, địa chỉ `Char` + CHECK `'^0x[0-9a-f]{40}$'` (lưu chữ thường), hash `_hash`, không
`size=`, `models.Constraint`/`models.UniqueIndex` (không `_sql_constraints`), không field trùng tên
kiểu dữ liệu.

**`blockchain.chain`** (`mail.thread`): `name`, `evm_chain_number` (Integer, unique),
`caip2` (compute stored `eip155:<n>`), `native_currency`, `state` (`draft`/`active`/`paused`),
`finality_mode` (`depth`/`tag`), `finality_depth`, `finality_quorum` (≥1), `indexed_block`
(Integer, chỉ indexer ghi), `public_rpc_url` (cho ví: `wallet_addEthereumChain`; không bao giờ là
URL có khoá). Seed: 7622 (formerly 9000) (`draft`, depth 1, quorum 1), Gnosis 100 (`draft`, tag, quorum 2), Celo
42220 (`draft`). Endpoint RPC **không** nằm trong Odoo (ruling R20): node giữ chúng, và node từ chối
khởi động khi `rpc_urls < quorum`.

**`blockchain.token`** (`mail.thread`): `chain_id`, `address`, `name`, `symbol`, `decimals`,
`domain_name` (mặc định `SCaaS MetaToken`), `domain_version` (`1`), `currency_id` (tiền pháp định
token neo 1:1 để quy đổi đơn hàng), `is_confidential` (luôn False ở đây), `active`.
`UNIQUE(chain_id, address)`.

**`blockchain.metatx`** — phong bì đã ký, bất biến sau khi ký (canon §C10.5): `company_id`,
`chain_id`, `token_id`, `from_address`, `to_address`, `value_base`, `data_hex`, `batch_hex`
(uint256 dạng hex 0x + 64), `nonce_base`, `valid_until_datetime`, `mode_flags` (Integer, CHECK
0..2^31-1, `@api.constrains` với `MODE_KNOWN_MASK` từ `lib/eip712.py`), `relayer_address`, `fee_base`,
`fee_recipient_address`, `digest_hash`, `signature_hex`, `signature_verified` (ecrecover khớp),
`metatx_state` (`signed`/`final`/`failed`/`expired`), `executed_tx_hash`.
`UNIQUE(chain_id, digest_hash)`. Ghi sau khi `signed` bị chặn ở `write` trừ các cột trạng thái.

**`blockchain.relay.job`** — outbox (canon §C10.8): `company_id`, `chain_id`, `metatx_id`,
`origin_producer`, `origin_key`, `chain_state` (`queued`, `nonce_leased`, `signed`, `broadcast`, `mined`,
`final`, `reverted`, `dead`, `consumed` — MESH R80; review L1), `business_state` (`pending`/`success`/`failed`),
`claimed_by`, `claimed_datetime`, `tx_hash`, `outer_nonce`, `attempt_count`, `last_error`; từ addendum §D thêm
`job_kind` (`metatx`/`call`/`signed_op`), `target_address`, `calldata_hex`, `call_valid_until_ts`,
`payment_request_id`, `signed_op_id`, `prerequisite_job_id`, `subject_account_id`.
`UNIQUE(company_id, origin_producer, origin_key)`. Không cột `state` trần (canon §C2.2).
**Bất biến sau `create` (CR-PD-1):** `company_id`, `chain_id`, `job_kind`, `metatx_id`, `signed_op_id`,
`target_address`, `calldata_hex`, `call_valid_until_ts`, `payment_request_id`, `subject_account_id`,
`origin_producer`, `origin_key` — `write` raise với mọi env, kể cả `sudo`; `prerequisite_job_id` chỉ được đặt một
lần từ rỗng khi job còn `queued` (`blockchain_subject_account.py:493`). Đổi lời gọi = job mới.

**`blockchain.chain.event`**: `chain_id`, `company_id` (từ request khớp, có thể rỗng),
`contract_address`, `event_name` (`MetaTransactionExecuted`/`PaymentSettled` — `TradeSettled` của DEX
không vào Odoo: không có nghiệp vụ ERP nào đọc nó),
`block_number`, `block_hash`, `tx_hash`, `log_index`, `from_address`, `to_address`, `value_base`,
`fee_base`, `entry_ref_hex`, `digest_hash`, `payment_request_id`.
`UNIQUE(chain_id, tx_hash, log_index)`.

**`blockchain.payment.request`** (canon §C10.9, thu gọn): `request_uuid`, `company_id`, `chain_id`,
`token_id`, `receiving_address`, `relayer_address`, `amount_base`, `amount_settled_base` (compute
stored từ event `PaymentSettled` khớp token + người nhận), `entry_ref_hex` (32 byte **ngẫu nhiên**,
ruling R9), `batch_hex` = `keccak256("scaas.pay.lane" ‖ entry_ref)` (nonce luôn 0),
`payer_address` (khoá cứng lúc `start` — lane là `(payer, batch)`), `issued_valid_until` (hạn của
typed data cuối cùng đã phát cho client; `submit` yêu cầu `valid_until` đúng bằng nó),
`expiry_datetime` (tạo + 1 ngày), `request_state` (`open`/`partial`/`final`/`expired`), `needs_attention` (tiền về khi tx đã huỷ, hoặc trả thừa),
`res_model`/`res_id` (nguồn), `metatx_ids`, `event_ids`. `UNIQUE(entry_ref_hex)`.
`amount_settled_base` = Σ `value_base` của event `PaymentSettled` có **cùng** `entry_ref_hex`,
`contract_address == token_id.address` **và** `to_address == receiving_address`.
`_payment_gate()`: bỏ qua nếu đã `final`; `int(amount_settled_base) >= int(amount_base)` ⇒
`request_state='final'`, `needs_attention` nếu thừa, rồi gọi hook `_on_paid()` (rỗng ở core,
payment override) **trong savepoint**: hook raise ⇒ rollback riêng hook, `needs_attention = True`
+ log, và lô ingest vẫn commit — một lỗi nghiệp vụ (kỳ kế toán đóng, credit) không bao giờ được
làm kẹt cursor của indexer.

### 4.3 Bảng chuyển trạng thái `relay.job.chain_state`

| Từ | Sang | Ai |
|---|---|---|
| (tạo) | `queued` | Odoo, cùng transaction với `payment.transaction → pending` |
| `queued` | `nonce_leased` | `relay_claim` (CAS) |
| `nonce_leased` | `queued` (node khởi động lại, chưa ký) / `signed` / `dead` / `consumed` | `relay_report` |
| `signed` | `broadcast` / `mined` / `reverted` (receipt đến trước báo `broadcast`, I3) / `queued` (gap-filled khi cold start) / `dead` (P3) / `consumed` | `relay_report` |
| `signed` | `signed` cùng `(tx_hash, outer_nonce, signer)` = no-op thành công; khác giá trị = lỗi (CR-PD-5) | `relay_report` |
| `broadcast` | `mined` / `reverted` / `broadcast` (thay thế, tx_hash mới) / `queued` (gap-filled) / `dead` / `consumed` | `relay_report` |
| `mined` | `reverted` | `relay_report` |
| `consumed` | `mined`/`reverted`/`consumed` = no-op muộn | `relay_report` (`LATE_NOOP`) |
| `queued`, `nonce_leased`, `signed`, `broadcast`, `mined`, `reverted`, `dead`, `consumed` | `final` + `success` | `chain_event_ingest` khi `MetaTransactionExecuted(digest)` |
| `queued`, `nonce_leased`, `consumed` | `dead` | cron hết hạn (`valid_until` + 10 phút, chưa final) |

Bảng khớp `TRANSITIONS`/`LATE_NOOP` trong `dms_blockchain/models/blockchain_relay_job.py:20-26` (Claude review L1).

`final` là trạng thái hút: không gì rời khỏi nó. `reverted`/`dead` vẫn có thể thành `final` vì
meta-tx có thể đã được thực thi bởi đường khác — indexer là sự thật. `business_state`: `dead` ⇒
`failed`; `final` ⇒ `success` (ghi đè `failed`); mọi trạng thái khác giữ `pending`.

### 4.4 `dms_blockchain_payment`

- `payment.provider`: `code` thêm `chain`; field `chain_token_id`, `chain_receiving_address`,
  `chain_relayer_address`, `chain_validity_seconds` (mặc định 300 — canon §C8.4 cho ERC-20 công
  khai). Seed một provider `chain` ở trạng thái `disabled` + `payment.method` `chain`.
- `payment.transaction.chain_request_id`. Private: `_chain_create_request()` (amount từ tx, quy
  đổi `amount × 10^decimals` bằng `Decimal`, yêu cầu `token.currency_id == tx.currency_id` — không
  FX, ruling R17), `_chain_typed_data(from_address)`, `_chain_submit(from_address, valid_until,
  signature)`.
- `blockchain.payment.request._on_paid()` override: tìm tx; `done` rồi ⇒ không làm gì; `tx._set_done()` (chỉ từ `pending`;
  nếu tx đã `cancel`/`error` thì ghi chú và để operator xử lý — không tự hoàn tiền).
- Cron hết hạn của core: (a) job `queued`/`nonce_leased` có `valid_until + 10 phút < now` ⇒ `dead`,
  metatx ⇒ `expired`; (b) request `open` quá `expiry_datetime`, **không** chữ ký nào có
  `valid_until + 1 giờ > now` (ân hạn cho finality: một meta-tx thực thi sát hạn vẫn cần vài phút
  để final) và không job nào `broadcast`/`mined` ⇒ `expired` ⇒ hook `_on_expired()` ⇒ tx
  `_set_canceled()`. Tiền về sau đó (không thể với chữ ký đã hết hạn, nhưng được phòng): request
  vẫn đi `expired → final` (canon §C10.9), `_set_done` trên tx đã huỷ không làm gì, và
  `needs_attention = True` cho operator.
- Provider cần `journal_id` (yêu cầu của `account_payment` khi tạo `account.payment`); khi tx
  `done`, `sale` xác nhận đơn và `account_payment` tạo/gạch payment theo luồng chuẩn.

### 4.5 `dms_blockchain_bridge` — portal

Facade công khai trên `dms.portal.api` (CLAUDE.md §6: entry mỏng + logic private, không nhận
`company_id`):

| Method | Việc |
|---|---|
| `dms_portal_chain_payment_start(order_id, from_address)` | entitlement (`dms_allowed_partner_ids`); đơn **đã xác nhận** (`state == 'sale'`, ruling R19); `provider.chain_token_id.currency_id == order.currency_id` (lỗi rõ ràng ngay, ruling R17); số phải trả: hoá đơn `posted` còn nợ của đơn ⇒ `invoice_ids` + Σ`amount_residual`, chưa có hoá đơn ⇒ `sale_order_ids` + `amount_total − amount_paid` (khoản ứng trước); **tái dùng** tx `chain` đang `draft/pending` của đơn khi `from` trùng `payer_address` (cùng lane ⇒ trả tối đa một lần); `from` **khác** ⇒ chỉ được khi `issued_valid_until + 60 s` đã qua (không còn typed data nào ký được), khi đó tx/request cũ bị huỷ và tạo request mới (entryRef mới, lane mới); phát `issued_valid_until = now + chain_validity_seconds`; trả `{reference, chain: {chainId, name, rpcUrl, nativeCurrency}, typed_data}` |
| `dms_portal_chain_payment_submit(reference, valid_until, signature)` | entitlement qua tx; `valid_until == issued_valid_until` (server chọn hạn, nên không có lệch đồng hồ và client không kéo dài được) và chưa qua; dựng lại digest từ request + `payer_address` + `valid_until`; chữ ký 65 byte khôi phục đúng `payer_address` ⇒ `signature_verified = True`; không khôi phục được (ví hợp đồng ERC-1271) ⇒ nhận với `signature_verified = False`, simulation của node là trọng tài (spam bị chặn bởi entitlement + một job sống cho mỗi request); tạo `metatx` + `relay.job` (outbox) cùng transaction; trả trạng thái |
| `dms_portal_chain_payment_status(reference)` | `{tx_state, request_state, job_state, tx_hash}` |

Trang `/my/dms/order/<id>`: kế thừa template `dms_portal.portal_order`, thêm nút "Pay on-chain"
khi provider `chain` đang bật; JS thuần (`web.assets_frontend`): `eth_requestAccounts` →
`wallet_switchEthereumChain` (fallback `wallet_addEthereumChain`) → `start` → `eth_signTypedData_v4`
→ `submit` → poll `status`. Không có logic nghiệp vụ trong JS.

### 4.6 Nhóm và quyền (tập con của canon §C14.1)

| XML id | Được |
|---|---|
| `group_blockchain_viewer` | đọc chain, token, event, request, job của công ty mình |
| `group_blockchain_operator` | + đọc metatx, đọc job (**không** ACL ghi trên `blockchain.relay.job`), đưa job `dead`/`reverted` về `queued` qua `action_requeue` (kiểm `has_group` tường minh rồi `sudo()` bên trong) — CR-PD-1 |
| `group_blockchain_manager` | CRUD chain, endpoint, token; implied operator |
| `group_blockchain_relay_worker` | service: `relay_poll/claim/report`, `node_config` |
| `group_blockchain_indexer` | service: `chain_event_ingest`, `node_config` |

`relay_worker` và `indexer` là **hai** nhóm, hai user, hai API key (canon §C14.1: chiếm indexer
không được ghi job). Record rule `company_id in company_ids` trên metatx, job, event, request.
Portal user **không** có ACL trên model `blockchain.*`; mọi thứ họ cần đi qua facade `sudo()` sau
kiểm entitlement.

---

## 5. Luồng end-to-end: portal trả đơn hàng

```
Ví (portal)        Odoo (bridge/payment/core)            scaas-node              Chain
 │ connect, addr ─►│ start(order, addr):                     │                        │
 │                 │  tx(chain, sale_order_ids) + request    │                        │
 │                 │  ref32 ngẫu nhiên, lane=keccak(ref32)    │                        │
 │◄─ typed data ───│  m = {from:addr, to:receiving, value,   │                        │
 │                 │       data:pay(ref32), batch:lane,      │                        │
 │                 │       nonce:0, validUntil:now+300,      │                        │
 │                 │       mode:RESTRICT_RELAYER, relayer,   │                        │
 │                 │       fee:0, feeRecipient:0}            │                        │
 │ signTypedData   │                                          │                        │
 │── signature ───►│ submit: digest, ecrecover (§4.5),       │                        │
 │                 │  metatx(signed) + relay.job(queued)      │                        │
 │                 │  tx → pending        [COMMIT]            │                        │
 │                 │◄── relay_poll / relay_claim (CAS) ──────│                        │
 │                 │                                          │── eth_call (simulate) ►│
 │                 │                                          │── sendRawTransaction ─►│ execute: pay op
 │                 │◄── relay_report(broadcast, tx_hash) ─────│                        │ emit PaymentSettled
 │                 │◄── relay_report(mined) ──────────────────│◄── receipt ────────────│ + MetaTxExecuted
 │                 │                                          │── getLogs (final) ────►│
 │                 │◄── chain_event_ingest([...]) ────────────│  sau finality+quorum   │
 │                 │  job final/success; request.amount_settled│                       │
 │                 │  gate ok ⇒ tx._set_done() ⇒ post-process:│                        │
 │                 │  SO xác nhận, account.payment, gạch nợ   │                        │
 │◄── status ──────│                                          │                        │
```

Đảm bảo, theo thứ tự quan trọng:
1. **Không ghi nhận trước finality**: `_set_done` chỉ từ `chain_event_ingest`, chỉ log trong vùng
   final, chỉ khi tổng `PaymentSettled` khớp (token, người nhận, `entryRef`) ≥ số phải trả. Log chỉ được tin khi
   đủ `quorum` endpoint độc lập trả **cùng tập log** cho vùng đó (CR-PD-2); `quorum = 1` nghĩa là tin một nhà cung
   cấp RPC, và Odoo luôn tin feed của node mình (SCaaS §3.5).
2. **Trả tối đa một lần cho mỗi request**: mọi chữ ký của một request dùng chung lane
   `(from, batch)` nonce 0, nên chain chỉ thực thi được một. Đổi ví (`from` khác) là lane khác —
   vì vậy `start` từ chối đổi `from` khi request đã có chữ ký chưa hết hạn. **Có điều kiện (CR-PD-4):** trên họ
   xoá lane đã dùng (TON, Aptos, Solana) đảm bảo chỉ đúng khi mọi chữ ký trên lane có
   `validUntil ≤ lần phát đầu + H` (H = 30 ngày, `LANE_HORIZON_S`) — quy tắc giao thức, không chỉ hằng số Odoo.
3. **Số tiền do server định**: `value` lấy từ tx (= đơn hàng); client không gửi số tiền nào.
4. **Relayer không chạm tiền**: nó chỉ thực thi đúng thứ đã ký; `to`, `value`, `data` nằm trong
   digest; phí 0.

---

## 6. Typed data và digest — một quy tắc, bốn nơi

`MetaTxLib.hashStruct` (Solidity) là chuẩn. Ba bản sao phải khớp từng byte: `lib/eip712.py`
(Odoo), `scaas-node` (alloy `sol!` struct), và typed data JSON gửi cho ví (ví tự băm). Quy tắc
canonical zeroing (`relayer`/`feeRecipient` = 0 khi cờ tắt) áp ở cả ba bản. Khoá chéo bằng một
**vector KAT** trong `smartcontracts/test/vectors/metatx_kat.json` sinh từ forge
(`vm.writeJson`): domain, struct, `structHash`, digest, và chữ ký của khoá `0xA11CE`. Test Python và
Rust đọc cùng file; đổi typehash là ba test đỏ.

---

## 7. Tin cậy và quản lý khoá

| Khoá / bí mật | Ở đâu | Ai thấy | Mất thì |
|---|---|---|---|
| Khoá ví người trả | ví của họ | chỉ họ | không liên quan hệ thống |
| `authKey` relayer (secp256k1, trả gas) | biến môi trường / file của node; trait `Signer` để thay bằng KMS/custody broker | node | mất số dư gas của ví relayer; xoay khoá + cập nhật `chain_relayer_address` |
| API key relay_worker / indexer | env của node; Odoo lưu hash (`res.users.apikeys`) | node | kẻ có key relay ép được trạng thái job (không tạo được tiền); có key indexer ép được `_set_done` ⇒ **hai key, hai user, phạm vi tối thiểu**, xoay định kỳ |
| `entry_ref` | Odoo | Odoo | công khai on-chain theo thiết kế; không mang thông tin gì |

- **Relayer không bao giờ giữ tiền người dùng**: token không có allowance cho relayer; meta-tx chỉ
  chuyển `from → to` đã ký; phí = 0 cho luồng portal. DEX không giữ số dư giữa các tx.
- **Replay**: domain gồm `chainId` + `verifyingContract`; nonce 2D tiêu khi thực thi; `validUntil`
  (300 s); `cancelMetaNonce(batch)` cho người ký rút lại.
- **Odoo không giữ khoá nào** (canon §C11.7) và không gọi chain. *(Superseded một phần: addendum §D/R50 — khoá
  custody `env:` chỉ-dev nằm trong tiến trình Odoo, §15.3.)*
- **Fee mode**: portal = `NONE` + `MODE_RESTRICT_RELAYER` (công ty trả gas; chỉ relayer của công ty
  nộp được). Gateway mở chấp nhận mọi mode hợp lệ; node có thể từ chối phí dưới ngưỡng (mặc định
  nhận phí 0 cho token trong danh sách — chính sách B2B `fee = 0`, SRS §5.2). **CR-PD-3:** phí 0 ở Door A chỉ
  mặc định trên profile `private`; profile `public` cần policy tài trợ; `value == 0` luôn bị từ chối.

---

## 8. Xử lý sự cố

| Tình huống | Hành vi |
|---|---|
| Node chết / Odoo chết | job nằm `queued`; chữ ký sống tới `validUntil`; hết hạn ⇒ cron `dead`, request `open` cho phép ký lại cùng lane |
| Node chết sau broadcast trước `relay_report` | khởi động lại: job `nonce_leased` của mình không `tx_hash` ⇒ về `queued` ⇒ simulate ⇒ nếu đã thực thi thì `MetaTxBadNonce` ⇒ `dead`; indexer vẫn đưa job về `final` từ event |
| Simulate revert (thiếu số dư, hết hạn, sai chữ ký) | job `dead` + `last_error` giải mã; tx vẫn `pending`; người dùng ký lại sau khi nạp tiền |
| Tx kẹt mempool | thay thế cùng nonce, phí ×1.25 mỗi `stuck_after_secs`, tới trần `max_fee_cap` (SRS tích hợp §5.4); không bao giờ bỏ nonce — job bỏ ⇒ gap-filler cùng nonce |
| Tx revert on-chain (đổi state giữa simulate và inclusion) | `reverted`; nonce meta-tx **không** tiêu (bubble, canon §C8.3); có thể claim lại |
| Reorg trước final | vô hình với Odoo: chỉ vùng final được gửi |
| Reorg sau final (hard) | ngoài mô hình (Gnosis `finalized`, Clique 1 signer); không tự đảo bút toán — ruling R12 |
| RPC lệch nhau | quorum không đủ ⇒ indexer đứng, `/readyz` đỏ |
| Trả thiếu / trả thừa | thiếu: `partial`, tx `pending`; thừa (chỉ có thể nếu nhiều lane): `final` + `needs_attention = True` cho operator hoàn tiền thủ công |
| Hook nghiệp vụ lỗi khi ingest | savepoint: event + cursor vẫn commit, `needs_attention = True` |
| DEX: một chân fail | cả `settle` revert, không chân nào thực thi |
| DEX: khớp một phần | không tồn tại (fill-or-kill, ruling R3) |
| Hoàn tiền | ngoài tự động: operator chuyển trả bằng ví công ty; tx hoàn tiền Odoo chuẩn |

---

## 9. Mô hình bảo mật và đe doạ

| # | Đe doạ | Chặn |
|---|---|---|
| T1 | Client tự định giá (gửi số tiền nhỏ) | `value` dựng từ tx phía server; client chỉ gửi chữ ký |
| T2 | IDOR: trả/đọc đơn của outlet khác | facade kiểm `dms_allowed_partner_ids` trước mọi `sudo()`; status theo `reference` cũng kiểm |
| T3 | Event giả `PaymentSettled` từ contract lạ | indexer chỉ lọc `address ∈ token đã đăng ký`; Odoo khớp thêm `token_id` + `receiving_address` |
| T4 | Kẻ thứ ba trả 1 wei với `entryRef` của người khác | tổng phải ≥ amount; thanh toán dư của người lạ chỉ là tiền vào công ty |
| T5 | Trả hai lần | một lane nonce 0 cho mỗi request (§5) |
| T6 | Relayer/ai đó front-run, đổi người nhận | `to/value/data` trong digest; `MODE_RESTRICT_RELAYER` |
| T7 | Replay chéo chain/token | domain `chainId` + `verifyingContract` |
| T8 | Chiếm API key indexer ⇒ ép `_set_done` | user riêng, nhóm riêng, chỉ một method; cursor liền mạch + UNIQUE; ghi chú vận hành: key ở secret store, xoay |
| T9 | Front-run `initialize()` của clone | init nguyên tử trong factory + `msg.sender == FACTORY` |
| T10 | Ai đó `initialize()` implementation | constructor khoá implementation |
| T11 | DEX: lệnh lộ bị thực thi lẻ | token ép `trade` chỉ khi `relayer == to == msg.sender` |
| T12 | DEX: token độc làm "giả chuyển" | đo delta số dư; người bán đã chọn `counterToken` trong chữ ký |
| T13 | DEX: phí rơi vào DEX | `settle` từ chối chân có phí mà `feeRecipient ∈ {0, dex}` |
| T14 | Grief relayer bằng meta-tx chắc chắn revert | simulation gate; gateway giới hạn body; node bỏ lệnh hết hạn |
| T15 | Parser node bị byte độc | serde chặt, giới hạn kích thước, không `unwrap` trên input; proptest/fuzz trên decoder |
| T16 | Signature malleability | OZ `ECDSA.tryRecover` (low-s) on-chain; Python từ chối `s > n/2` |
| T17 | Wrapper rút quá dự trữ | invariant `reserve >= totalSupply` (fuzz invariant) |
| T18 | Rò dữ liệu cá nhân on-chain | on-chain chỉ có địa chỉ ví, số tiền, `entryRef` ngẫu nhiên — không tên, không mã đơn |
| T19 | Một RPC gian dựng `PaymentSettled` giả (biết `entryRef` qua simulate của node) hoặc khai `finalized` sai | quorum trên **tập log** + min `finalized`/`latest` trên quorum (CR-PD-2) |
| T20 | Operator (hoặc phiên bị chiếm) sửa job `call` thành `token.transfer(attacker, …)` ký bởi lane | không ACL ghi cho operator, trường job bất biến, bảng selector/đích ở node (CR-PD-1) |
| T21 | Spam meta-tx phí 0, `value 0` từ khoá mới ⇒ đốt gas lane, kích cầu dao R55 | từ chối `value 0`, sàn `min_fee`/policy tài trợ, giới hạn theo `from` (CR-PD-3) |

---

## 10. Chiến lược kiểm thử

**Foundry** (`forge test`, profile default + `private9000`):
- `MetaToken.t.sol`: init một lần, chỉ factory, implementation bị khoá; tầng 1 mint/minter; tầng 2
  wrap/unwrap với token phí-chuyển; op `pay` phát `PaymentSettled` với phí thật; op lạ revert; op
  `trade` không restrict ⇒ revert; nonce/expiry/replay/cancel; ERC-1271.
- `OpenFactory.t.sol`: append-only, deprecate không chặn, predict == deployed, salt theo creator,
  `createUnregistered` version 0, verifier không hỗ trợ ⇒ revert.
- `MetaTxDex.t.sol`: khớp đúng, giá không đạt ⇒ revert, counterparty sai ⇒ revert, chân thứ hai
  fail ⇒ không chân nào thực thi, phí về `feeRecipient`, phí về DEX ⇒ revert, fuzz giá trị.
- **Invariant** (`StdInvariant`): `Σ balances == totalSupply`; wrapper `reserve >= supply`; DEX số dư
  0 sau mọi chuỗi handler call.
- `MetaTxGas.t.sol` hiện có vẫn xanh (đo lại không đổi); `test_metaTxTypehashIsPinned` không đụng.
- KAT: sinh `test/vectors/metatx_kat.json`.

**Rust** (`cargo test`): digest == KAT; decode/encode op; matcher (bảng ca); state machine finality
(mock RPC trait); config parse; client json/2 (mock server). Tích hợp (`--ignored`, cần `anvil` +
`forge`): deploy, ký, submit thật, indexer đọc lại event.

**Odoo** (`dms-test.sh` trên DB riêng `dms_test_chain`, cổng 8920):
- `dms_blockchain`: keccak/EIP-712/ecrecover == KAT; CHECK/UNIQUE có thật trong `pg_indexes`/
  `pg_constraint`; CAS claim; bảng chuyển trạng thái; ingest: liền mạch, idempotent, cursor; nhóm
  chặn method service; **`/json/2` với API key** cho `relay_poll` và `chain_event_ingest` (HttpCase).
- `dms_blockchain_payment`: quy đổi số tiền, typed data, submit sai chữ ký ⇒ lỗi, gate ⇒ `_set_done`;
  hook raise ⇒ ingest vẫn commit + `needs_attention`; ingest lần hai không gọi lại hook.
- `dms_blockchain_bridge`: **`call_kw` với session portal** và **`/json/2`** cho
  `dms_portal_chain_payment_start/submit/status` (CLAUDE.md §6); IDOR bị chặn; tái dùng lane; đơn
  được xác nhận và `account.payment` được tạo sau ingest.
- Ranh giới: `bamboo_dms` + `dms_portal` cài **không** có ba addon (gate hiện tại đã chứng minh).

---

## 11. Ngoài phạm vi (lần này)

Zether (verifier, prover, oracle, registry) · năm hệ sinh thái non-EVM · mesh libp2p (profile
private tắt mesh, SRS §5.1) · tầng 3 basket · token có kiểm soát/CBDC · sealed-bid · vesting ·
`batchMtxPay`/gom lô · khớp lệnh một phần, AMM · FX quote · hoàn tiền tự động · KMS/HSM/MPC thật
(chỉ có trait) · dispute sau reorg · tích hợp form thanh toán chuẩn của website checkout ·
`blockchain.settlement` và các model canon khác ngoài §4.2.

---

## 12. Kế hoạch triển khai

Bốn plan, theo thứ tự phụ thuộc: (1) contracts + DEX, (2) relayer, (3) Odoo core + payment,
(4) portal bridge. Mỗi plan: TDD, commit mỗi task, review diff + suite đầy đủ cuối plan.

---

## 13. Rulings

Định dạng: **Ruling: <cái gì> — <vì sao> — <giá nếu sai>.**

- **R1** *(Superseded → R30, R34, owner family taxonomy 2026-10-06; §15.3.)* Chỉ EVM, chỉ META token; Zether/non-EVM/mesh ngoài phạm vi — SRS §2 tự ghi verifier
  Bulletproofs "chưa viết mã", non-EVM "thiết kế trên giấy"; portal cần đúng một đường thanh toán
  công khai — nếu sai: các phần đó thành plan sau, không phải làm lại phần này (factory đã nhận
  kind ZETHER).
- **R2** *(Cost clause superseded → R138–R140: `mtxPay` built in v2, SCaaS §5.8; §15.3.)* Op thanh toán đi qua `executeMetaTransaction` với `data = pay(bytes32)`, không thêm
  `mtxPay` — struct ghim là nguồn #1, một typehash duy nhất, ví hiển thị một loại giao dịch; SRS
  `mtxPay` là tầng 3 — nếu sai: ~4k gas/tx so với fast-path và chưa có `batchMtxPay`; thêm sau
  không phá chữ ký đã phát hành.
- **R3** *(Superseded → R35 `OrderBookDex`: partial fills, IOC/FOK, persisted book; `MetaTxDex` legacy; §15.3.)* DEX = settle hai chân meta-tx đi qua DEX, fill-or-kill, không allowance, không AMM —
  giữ "không CALL lạ trong token, không allowance" (canon §C8.5) và SRS §3.3 — nếu sai: thiếu
  khớp một phần; cần sổ trạng thái lệnh on-chain để thêm.
- **R4** *(Superseded → R26, addendum A; §15.3.)* Không hiện thực EOA approve lockdown (SRS §3.2) — README `smartcontracts` (nguồn #1) đã
  bỏ `isEOA` vì không quyết định đúng được sau EIP-7702; DEX không cần allowance nên không mất gì —
  nếu sai: có thể thêm vào v2 implementation, không ảnh hưởng v1.
- **R5** Domain EIP-712 của clone = tên/version của implementation + `verifyingContract` = clone —
  OZ `EIP712` immutable; an toàn replay đến từ `verifyingContract`; Odoo lưu `domain_name/version` —
  nếu sai: ví hiển thị "SCaaS MetaToken" thay vì tên token.
- **R6** *(Superseded → NI R87/R97/R101: push job API, node never calls the ERP; pull is still the built path; §15.3.)* `scaas-node` nói với Odoo chỉ qua `/json/2` (đọc + ghi), claim = CAS qua RPC, không
  Postgres trực tiếp — canon §C13 claim bằng `FOR UPDATE SKIP LOCKED` rồi ghi qua `/json/2` trên
  **cùng dòng** là tự khoá (worker giữ row lock chờ HTTP, Odoo chờ row lock); `_USER-DECISIONS`
  §23 một tiến trình nên SKIP LOCKED không còn cần — nếu sai: tải poll lên Odoo (1 Hz/chain, chấp
  nhận được); thêm đường đọc Postgres sau là cục bộ trong node.
- **R7** Không depends `bamboo_idempotency`; dedup bằng UNIQUE trên khoá tự nhiên — addon tuỳ chọn
  phải cài độc lập; `bamboo_idempotency` thêm cột vào **mọi** bảng DB — nếu sai: thêm sau như một
  dependency, khoá tự nhiên vẫn đúng.
- **R8** Ba addon (`dms_blockchain`, `dms_blockchain_payment`, `dms_blockchain_bridge` cho
  portal), không `dms_blockchain_account`. `dms_blockchain_bridge` **tái định hướng** so với canon
  §C3 (canon: mixin settlement trên `dms.payment.collection`… với `depends ['dms_blockchain','dms']`;
  ở đây: facade portal với `depends ['dms_blockchain_payment','dms_portal']`); mixin backend chuyển
  sang pha B2B sau — `account_payment` chuẩn đã gạch nợ khi tx `done`;
  bridge canon (mixin trên `dms.payment.collection`…) chưa có người dùng — nếu sai: thêm addon
  account khi cần FX/đối soát lô.
- **R9** *(Amended → CR-PD-4: pay-once holds under the issuance horizon H on lane-pruning families.)* `entryRef` = 32 byte ngẫu nhiên; lane = `keccak256("scaas.pay.lane" ‖ entryRef)`, nonce 0 —
  ngẫu nhiên không liên kết được ngay từ cấu tạo (tốt hơn hash có salt); lane cố định cho request
  cho phép Odoo dựng typed data không cần đọc chain và bảo đảm trả tối đa một lần — nếu sai: lần
  dùng lane đầu tốn +17k gas (đo ở `MetaTxGas`), chấp nhận.
- **R10** *(Note, infra-service review M5: R10 trades payer self-submission for front-run safety; payee self-relay, SCaaS §5.9, stays available.)* Portal: phí `NONE` + `MODE_RESTRICT_RELAYER` về relayer công ty — canon §C8.3 mặc định
  restrict cho luồng tiền; SRS §5.2 B2B `fee = 0` — nếu sai: relayer công ty chết thì người dùng
  không tự nộp được; chữ ký hết hạn sau 300 s nên chỉ là chậm, không mất.
- **R11** *(Amended: NI R96 moves finality to the node store; CR-PD-2 — quorum over event sets.)* Finality do
  node quyết, Odoo chỉ nhận vùng final: `depth` (chain 7622 (formerly 9000): 1) hoặc `tag`
  (`finalized`) + quorum endpoint — canon §C10.9 flow gắn `payment.transaction` dùng ngưỡng hard —
  nếu sai: độ trễ ghi nhận = độ sâu final của chain (Gnosis ~3 phút).
- **R12** Không xử lý reorg sau hard finality — Gnosis `finalized` và Clique một signer không
  reorg trong mô hình; dispute canon cần `blockchain.settlement` — nếu sai: bút toán đã ghi cần
  đảo tay.
- **R13** *(Narrowed → R27 `wallet_kind`; §15.3.)* Odoo tự kiểm chữ ký (keccak-256 + secp256k1 ecrecover thuần Python, không thư viện
  ngoài) — phản hồi tức thì cho người dùng, và là bản thứ ba của digest được khoá bằng KAT;
  `pycryptodome` có trong container nhưng không phải dependency của Odoo — nếu sai: chữ ký
  ERC-1271 (ví hợp đồng) không khôi phục được ⇒ lưu `signature_verified = False` và để simulation
  của node quyết — trừ chữ ký dài đúng 65 byte, vốn phải khôi phục đúng ví (review I8): ví hợp đồng
  trả chữ ký 65 byte sẽ bị từ chối.
- **R14** Portal UI = nút + JS thuần gọi facade; không tích hợp form thanh toán chuẩn — CLAUDE.md §6
  (mọi logic ở method model); form chuẩn cần JS payment-form riêng — nếu sai: checkout website chưa
  có nút `chain`.
- **R15** Khoá vỏ tx trong node qua trait `Signer` với bản `LocalSigner` (env/file) — custody
  broker/KMS là một làn riêng chưa có (`_USER-DECISIONS` §23.5); trait giữ chỗ cắm — nếu sai: khoá
  nóng nằm trong tiến trình parse byte lạ; giảm bằng ví relayer chỉ nạp gas tối thiểu.
- **R16** *(Superseded → R35 book in Odoo, NI R105 store-backed; §15.3.)* Hàng đợi gateway và sổ lệnh DEX trong bộ nhớ — mất khi khởi động lại, người dùng gửi lại
  (chữ ký còn hạn) — nếu sai: thêm lưu bền khi có khối lượng.
- **R18** Không bỏ nonce vỏ: phí tăng tới trần, job bỏ ⇒ gap-filler; cold start theo
  `max(pending, journal + 1)` (§23.1) cộng lấp lỗ — review F3/F4: một nonce bị bỏ làm tắc mọi tx sau
  nó; journal không lấp lỗ thì để lại lỗ vĩnh viễn — nếu sai: vài tx 0-value tốn gas tối thiểu.
- **R19** Portal chỉ trả đơn **đã xác nhận** (`state == 'sale'`) — `sale._post_process` tự
  `action_confirm` báo giá `draft/sent` khi tx `done`, tức bỏ qua duyệt DMS và `dms_check_credit`
  (review F2); có hoá đơn thì gạch nợ, chưa có thì là khoản ứng trước — nếu sai: người mua không
  trả trước được báo giá; mở sau bằng một luồng duyệt riêng.
- **R20** *(Amended: NI R95 — RPC URLs stay toml-only; config authority otherwise the node store.)* Endpoint RPC chỉ ở config của node; bỏ `blockchain.rpc.endpoint` khỏi Odoo — Odoo không
  bao giờ gọi RPC, URL nhà cung cấp thường mang khoá, và hai nơi giữ cùng danh sách là hai sự thật —
  nếu sai: màn hình sức khoẻ endpoint (canon §C14.3 #4) phải đọc từ `/readyz` của node.
- **R17** Không FX: `token.currency_id` phải trùng tiền đơn hàng — quote tỷ giá (canon
  `blockchain.payment.quote`) cần nguồn giá — nếu sai: chỉ token neo đúng tiền đơn mới dùng được.

---

## 14. Review log

### Antigravity (agy), 2026-10-03 — 21 finding, đối chiếu từng cái với source

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| F1 | crit | **Đúng một phần.** `_set_done` chỉ đổi state (post-process chạy ở cron riêng — `sale/models/payment_transaction.py:_post_process`), nhưng hook nào raise vẫn rollback cả lô ingest và kẹt cursor | Nhận: hook trong savepoint, lỗi ⇒ `needs_attention` (§4.2) |
| F2 | crit | **Đúng.** `sale._post_process` `action_confirm` báo giá `draft/sent` ⇒ bỏ qua duyệt DMS + `dms_check_credit` (`bamboo_dms/models/extends/sale_order_extend.py:484`); không hoá đơn thì không có gì để gạch | Nhận: R19 (chỉ đơn `sale`), hoá đơn posted ⇒ `invoice_ids`, không thì ứng trước (§4.5) |
| F3 | high | Đúng là lệch `_USER-DECISIONS` §23.1 | Nhận + lấp lỗ (R18) |
| F4 | high | Đúng: bỏ nonce ⇒ tắc | Nhận: không giới hạn lần thay thế, gap-filler (R18) |
| F5 | high | Đúng: crash giữa send và report ⇒ ký lại ⇒ nộp đôi | Nhận: trạng thái `signed` ghi `tx_hash`+nonce **trước** khi gửi (§3.2, §4.3) |
| F6 | high | Đúng: thiếu cột | Nhận: `payer_address` |
| F7 | high | Đúng: hai ví = hai lane; gateway mở còn là đường nộp thứ hai | Nhận: khoá `payer_address`, đổi ví chỉ sau khi typed data cũ hết hạn ⇒ request mới (§4.5) |
| F8 | high | Đúng: §5 ghi `ecrecover == addr` mâu thuẫn R13 | Nhận: làm rõ quy tắc ở §4.5 |
| F9 | high | Đã có trong ý định, chưa viết ra | Nhận: ghi rõ `safeTransfer` |
| F10 | high | Ý 1 đúng (simulate qua, `settle` trượt) — ý 2 (MEV thay `feeRecipient`) là thiết kế của relayer mở | Nhận ý 1 (gateway điền `feeRecipient`); **bác** ý 2: người ký muốn chặn thì bật `MODE_RESTRICT_FEE_RECIPIENT` |
| F11 | high | Đúng | Nhận: gate idempotent, hook bỏ qua tx `done` |
| F12 | med | Đúng (ABI chỉ có trong plan) | Nhận: §2.1 |
| F13 | med | Đúng về cách phát biểu; test invariant của plan không có handler gửi thẳng nên vẫn đúng | Nhận: phát biểu theo delta |
| F14 | med | Đúng (câu thiếu `entryRef`) | Nhận |
| F15 | med | Đúng | Nhận: `dead ⇒ failed`, `final ⇒ success` |
| F16 | med | Đúng | Nhận: một tên `needs_attention` |
| F17 | med | Đúng về việc phải khai; khai trong `MetaToken` là đủ (interface `IERC20MetaTx` không đổi) | Nhận |
| F18 | med | Đúng | Nhận: R8 ghi rõ tái định hướng |
| F19 | low | Đúng | Nhận một phần: giới hạn đồng thời toàn cục; rate-limit theo IP để cho reverse proxy |
| F20 | low | Đúng hướng, sửa tốt hơn đề xuất | Nhận: `valid_until == issued_valid_until` (không cần dung sai) |
| F21 | low | Đúng | Nhận: kiểm ở `start` |

### Antigravity (agy) — review bốn PLAN, 2026-10-03 — 15 finding

| # | Sev | Kết luận (đã đối chiếu source) | Xử lý |
|---|---|---|---|
| P1 | crit | **Sai.** `sale.order.amount_paid` tồn tại trong Odoo 19 (`addons/sale/models/sale_order.py:274`, compute `_compute_amount_paid`) | Bác |
| P2 | crit | Đúng về plan odoo-core (phần `inflight` chỉ ghi ở plan relayer Task 4) | Đã có trong code (`_inflight`, commit c60a12f) |
| P3 | crit | Đúng: node báo `dead` từ `broadcast` khi job hết hạn lúc kẹt | Nhận: `signed/broadcast → dead`; `final` vẫn thắng (74521c9) |
| P4 | high | Đúng về test trong plan (USD 2 chữ số) | Code dùng 12.34 từ đầu (f4bbaf1) |
| P5 | high | Đúng một phần (thiếu `event_name`) | Nhận (74521c9) |
| P6 | high | Đúng — cũng bị test bắt khi chạy | Đã sửa (c60a12f) |
| P7 | high | Đúng: lỗi transport khi simulate bị coi là revert ⇒ job chết | Nhận: chỉ revert có data mới `dead`, còn lại `queued` |
| P8 | med | Đúng | Nhận: `JoinSet` |
| P9 | med | Đúng | Nhận (74521c9) |
| P10 | med | Đúng | Nhận: JS dừng ở trạng thái kết thúc |
| P11 | med | Đúng | Nhận: `invoice_policy = 'order'` trong fixture |
| P12 | med | Hợp lý (không chắc `copy()` giữ M2M) | Nhận: fixture gán method tường minh |
| P13 | low | Đúng về plan | Đã có ảnh (f4bbaf1) |
| P14 | low | Đúng | Nhận: handler có wrapper phí-chuyển (74521c9) |
| P15 | low | Đúng | Nhận: nạp danh sách token đồng bộ trước khi mở gateway |

### Antigravity (agy) — review IMPLEMENTATION (diff nhánh), 2026-10-03 — 13 finding

| # | Sev | Kết luận (đã đối chiếu code) | Xử lý |
|---|---|---|---|
| I1 | crit | **Đúng.** Đổi số phải trả huỷ tx/request cũ mà không chờ typed data cũ hết hạn; `_accept_signature` không kiểm `request_state` ⇒ tiền về tx đã huỷ | Nhận: request phải `open/partial`, tx phải `draft/pending` (8ace895) |
| I2 | high | Đúng: `feeRecipient` do client điền (DEX) lọt qua, settle revert, lệnh nghỉ bị đánh bật | Nhận: ghi đè vô điều kiện khi không ràng buộc (4e8b383) |
| I3 | high | Đúng: receipt có thể đến trước báo `broadcast` | Nhận: `signed → mined/reverted` |
| I4 | high | Đúng: thay thế bị từ chối vẫn đổi hash theo dõi | Nhận |
| I5 | high | Đúng: `report` nuốt lỗi nên vẫn gửi khi journal `signed` chưa ghi | Nhận: không journal thì không gửi, hàng đợi thử lại |
| I6 | high | Đúng: tx `done` chưa post-process thì `amount_residual` còn nguyên ⇒ mở được lần trả thứ hai | Nhận: chặn `start` và ẩn nút khi còn tx `done/authorized` chưa post-process |
| I7 | high | Đúng | Nhận: simulate cả `settle` trước khi lệnh rời sổ; fail ⇒ trả lệnh về |
| I8 | med | Đúng (chữ ký 65 byte rác lọt vào outbox) | Nhận: 65 byte phải khôi phục đúng ví; R13 hẹp lại tương ứng |
| I9 | med | Đúng | Nhận: `partial` cũng hết hạn, kèm `needs_attention` |
| I10 | med | Đúng | Nhận: ở trần phí thì chờ, không gửi lại |
| I11 | med | Đúng | Nhận: nút chỉ hiện khi còn phải trả |
| I12 | low | Đúng: fake Odoo nhận mọi chuyển trạng thái | Nhận: fake áp đúng bảng `TRANSITIONS` |
| I13 | low | Đúng | Nhận (cùng sửa với I7) |

Tự review (trước agy): sổ lệnh DEX không có trần ⇒ làm đầy bộ nhớ gần như miễn phí — trần
10.000 lệnh nghỉ (471e7a6). Bug do test bắt khi viết: verifier không có code thoát `try/catch`
(af06a69); SQL thô không flush làm CAS claim "thắng" hai lần (c60a12f); provider thiếu
`module_id` nên `account_payment` không tạo payment method (f799fd9); tx không có `operation`
nên `account_payment` không gạch nợ hoá đơn (751936b — cùng lỗi tiềm ẩn ở
`dms_portal.dms_portal_payment_start`, chưa sửa vì ngoài phạm vi).

### Grok
Lần 1 (2026-10-03): `free Grok Build usage limit` — không in giờ reset. Lần 2 (+~55 phút) và
lần 3 (+~1 giờ nữa): vẫn giới hạn. Lần 4 hẹn sau ~1 giờ, với prompt review implementation.

### Codex
Hết credit (theo owner) — không chạy.

---

## 15. Claude review 1 (2026-10-07) — disposition (rev 1.1)

Source: `docs/reviews/specs/2026-10-03-blockchain-payments-design-claude-review-1.md` (verdict FIX-THEN-GO).
Every finding was re-checked against the cited code on 2026-10-07 (`scaas` `main` 991d835; `bamboo-dms` `main`
b724c91). **Owner rule for this phase: docs only** — each code bug becomes a ruling with its fix and tests (§15.2)
and a code stream (§15.5); nothing is built in this revision. Ruling ids `CR-PD-n` are local to this spec so they
cannot collide with the global R-numbers other streams are allocating.

### 15.1 Claude review disposition

| # | Sev | Verified against code | Disposition |
|---|---|---|---|
| H1 | high | Confirmed. Operator ACL `1,1,0,0` (`dms_blockchain/security/ir.model.access.csv:7`); `write` filters only `SERVER_ONLY` (`blockchain_relay_job.py:79-86`); `_check_kind` checks presence only (`:88-97`); `_payload` ships target + calldata (`:169-172`); the node signs `job.call` as-is (`scaas-node/src/submit.rs:108-113`), no target/selector check in `submit.rs`/`adapter.rs`. Lanes hold value: unbound `feeRecipient` pays `msg.sender` (`ERC20MetaTx.sol:87`, `MetaTxCore.sol:90`, `OrderBookDex.sol:308`; node normalises to 0, `metatx.rs:124-131`); dev `PRIVATE_KEY` = registrar / `OrderBookDex` admin (`script/Deploy.s.sol:23-37`). NI rev 3.6 R103 grants `call` per namespace (`allow_call`) and `chain_contract` knows only `tender`/`sponsorship_pool` — no per-target rule exists anywhere. | **Accepted** → CR-PD-1; PAY-FIX1, PAY-FIX2; NI amendment §15.4 |
| H2 | high | Confirmed. `finalized` from the primary only (`chain.rs:168-176`, `indexer.rs:115`); quorum compares `block(to).hash` only (`indexer.rs:118-126`, `finality.rs:24-26`); both `get_logs` on the primary (`indexer.rs:131,142`); Odoo format-checks the hashes only (`blockchain_chain_event.py:79-103`). | **Accepted** → CR-PD-2; PAY-FIX3 (EVM/Hedera); other families: R3D CR-R3-2 |
| M1 | med | Confirmed. `post_metatx` checks token, expiry, simulation and digest only (`gateway.rs:152-174`). The `~gateway` `min_fee` floor (TSS R189, MESH §7) is SPECIFIED, not built. | **Accepted** → CR-PD-3; PAY-FIX4 |
| M2 | med | Confirmed. Lane state is pruned on TON (`ton/contracts/jetton.tact:291-321`), Aptos (`move/aptos/sources/meta.move:40,374`) and Solana (`solana/programs/scaas/src/account.rs:425-452`); TON's `validUntil ≤ now + LANE_TTL` (`jetton.tact:207`) is relative to execution, not lane creation; Odoo bounds issuance with `LANE_HORIZON_S` (`blockchain_payment_request.py:22-26,152-153`). Prune delays equal the 30-day horizon today, so Odoo-issued terms are safe. | **Accepted** → CR-PD-4 (R9, §5 guarantee 2 amended); tests in R3D stream R3-FIX12 |
| M3 | med | Confirmed. A failed `report('signed')` re-queues the work without consuming `n` (`submit.rs:311-316`); the next job is signed at the same `n`; `signed → signed` is not in `TRANSITIONS` (`blockchain_relay_job.py:20-25`). | **Accepted** → CR-PD-5; PAY-FIX5 |
| L1 | low | Confirmed (`blockchain_relay_job.py:20-26`). | **Accepted**: §4.2 state list and §4.3 table rewritten |
| L2 | low | Confirmed (`wallet/MandateWallet.sol:148-154`). | **Accepted** → addendum CR-ADW-1, stream ADW-FIX1 |
| L3 | low | Confirmed: `_validSig` uses uncapped `SignatureChecker.isValidERC1271SignatureNow` (`dex/OrderBookDex.sol:381-386`). | **Accepted**; ruling belongs to the DEX spec (recorded §15.4); stream PAY-FIX6 |
| L4 | low | Confirmed: per-fill fee `fill * feePpm / PPM` floors (`OrderBookDex.sol:216-217`). | **Accepted**; ruling belongs to the DEX spec (§15.4); stream PAY-FIX7 |
| L5 | low | Confirmed: journal only when `w.job_id` is set (`submit.rs:311-316`). | **Accepted** (doc): §3.4 note |
| L6 | low | Confirmed: §1, §2.4, §3.1, §4.2, R11 said 9000. | **Accepted** → CR-PD-6; text now says 7622 (formerly 9000) |
| Superseded table (15 rows) | — | Spot-checked: R28 (`dms_blockchain_payment/__manifest__.py:9`), R84 normalisation (`metatx.rs:124-131`), `mtxPay` built (`metatx/MetaTokenBase.sol:152`), platform company (`blockchain_receiving_wallet.py:9-10`). | **Accepted**: §15.3 + inline markers in §3.3, §7, §13 |

Rejected: none. Counts: 2 high, 3 medium, 6 low, 1 table — 12 accepted, 0 rejected.

### 15.2 Rulings

- **CR-PD-1** **Outbox `call` jobs are locked in Odoo and allowlisted by the node** (H1; addendum H1).
  (a) `group_blockchain_operator` loses write on `blockchain.relay.job` (ACL `1,0,0,0`); `action_requeue` checks
  `has_group('dms_blockchain.group_blockchain_operator')` explicitly, then keeps its `sudo()` write
  (`blockchain_relay_job.py:249-262`) — it is a public method, so the group check is what stops other readers.
  (b) The fields listed in §4.2 are immutable after `create`: `write` raises for every env, `sudo` included
  (pattern: `blockchain.metatx` `_MUTABLE`, `blockchain_metatx.py:10,65`); `prerequisite_job_id` may be set once,
  from empty, while the job is `queued`. No context-key switch (project rule). A different call is a new job.
  (c) The node executes a `call` job only if its 4-byte selector is in the table below **and** the target meets the
  row's rule; **never** when the target is a registered token of the chain (any kind), the token factory, or a
  contract in which a lane key holds a role; call jobs carry no native value. Refused ⇒ legacy pull: `dead` with
  `CALL_TARGET_REFUSED`, before simulation; NI push: `403 CALL_TARGET_REFUSED` at accept, next to step 4
  (`allow_call` stays necessary, no longer sufficient — NI amendment §15.4).

  | Selector | Target rule | Producer today |
  |---|---|---|
  | `SubjectAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | `blockchain_subject_account.py:178-196` |
  | `SubjectAccount.executeAsOwner(bytes,uint256,uint256,bytes)` | runtime code = EIP-1167 clone of that factory's `IMPLEMENTATION` (checked at lease, cached) | `blockchain_subject_account.py:422` |
  | `MandateWallet.payUnderMandate`, `revokeWithSig`, `executeAsOwner`; `HederaMandateWallet.executeAsOwnerRaw` | any address that is not a registered token (self-authenticating: the target checks the delegate/owner signature) | `blockchain_payment_request.py:240-255`, `dms_blockchain_payment/models/blockchain_autopay.py:101-113` |
  | `OrderBookDex.settle` / `cancel` / `invalidateNonces` | the chain's DEX | `dms_blockchain_dex/models/dex_trade.py:85-99` |
  | `UniversalAccountRegistry.register` | `chain.ua_registry`, `~gateway` only (NI R320) | node |

  Why: addendum §D made the node a blind signer for Odoo-built calldata; one operator session (or a stolen one)
  became an arbitrary transaction from a lane that holds fee income and, on dev deployments, admin roles. (a)+(b)
  close the Odoo path; (c) closes every client path, because NI R103 grants `call` per namespace, not per target.
  Selector matching suffices outside the token/role set: a lane's authority is only `msg.sender` of the direct
  call, never of calls the target makes. — Cost if wrong: a new call shape needs a table row (node release).
  Tests: Odoo — operator `write` on any job field ⇒ `AccessError`; `sudo().write` of each immutable field ⇒ error;
  `prerequisite_job_id` set once from empty passes, a second change fails; operator `action_requeue` still works,
  a viewer calling it over RPC fails. Node — call to a registered token, an unknown selector, a DEX selector on a
  non-DEX target, `executeAsOwner` on a non-clone ⇒ refused; calldata vectors exported by each Odoo producer test ⇒
  accepted.

- **CR-PD-2** **Finality authenticates the events, not one block hash** (H2). Per range the indexer reads the logs
  from ≥ `quorum` independent endpoints and requires the **same normalised set** (sorted
  `(block_number, block_hash, tx_hash, log_index, address, topics, data)`); `tag` mode takes `finalized` = minimum
  over the quorum, `depth` mode takes `latest` = minimum over the quorum; any disagreement ⇒ no ingest, `warn`,
  `/readyz` red (§8 "RPC lệch nhau"). `quorum = 1` is single-provider trust: allowed, reported at startup and as
  gauge `scaas_finality_quorum{chain}`. Receipt proofs (`eth_getBlockReceipts` against `receiptsRoot`) may replace
  the set comparison where providers serve them; not required. Residual trust: Odoo trusts its node's feed (SCaaS
  §3.5, NI T7). The same rule for every family is CR-R3-2 (R3D). — Why: the primary sees every pending payment
  through the node's own `eth_call`/`eth_estimateGas` and can fabricate `PaymentSettled` at a real token address.
  — Cost: `quorum ×` `eth_getLogs` per range. Tests: mock providers — the primary injects a fabricated log, drops a
  real one, or reports `finalized = latest` ⇒ nothing ingested / minimum used; honest providers ⇒ ingest identical
  to today.

- **CR-PD-3** **Door A is not a free gas faucet** (M1). At intake (`gateway.rs` `post_metatx`): (a) a
  `transfer`/`pay` op with `value == 0` ⇒ `422 ZERO_VALUE`; (b) the `~gateway` door applies its `min_fee` floor to
  the effective fee (TSS R189, MESH §7); a matching sponsor policy waives it and caps the spend with its budget;
  (c) defaults: `profile = private` keeps fee 0 (B2B, SRS §5.2, §7 here); `profile = public` refuses fee-0 Door A
  intents unless a sponsor policy matches; (d) a per-`from` token bucket (default 60 per hour, in memory) on top of
  the reverse-proxy per-IP limit (F19). The R55 hourly gas budget can then not be filled by unsponsored fee-0
  traffic on public chains. — Cost if wrong: public fee-0 payers need a sponsor policy row. Tests: zero value
  refused; fee 0 on a public chain refused without a policy, accepted and booked with one; the 61st intent from one
  `from` within an hour refused.

- **CR-PD-4** **Pay-once is conditional and is a protocol rule** (M2; amends R9 and §5 guarantee 2). "At most once
  per request" holds iff every signature issued on a pay lane has `validUntil ≤ t_first_issue + H`
  (`H = LANE_HORIZON = 30 d`) **and** every family that prunes lane state keeps an executed lane for ≥ H after the
  executed op's `validUntil` (TON two `LANE_TTL` generations, Aptos/Solana `PRUNE_DELAY_S`). Both hold in the code
  today. The issuer obligation moves from an Odoo constant to SCaaS §5.5 (amendment §15.4); a node chain on a
  pruning family must have `max_valid_for_secs ≤ H` (config check). Issuers that sign terms on a lane beyond H get
  no pay-once guarantee. — Cost: none for Odoo-issued terms. Tests: R3D stream R3-FIX12 (constants pinned equal,
  node config refusal).

- **CR-PD-5** **The `signed` journal report is idempotent** (M3). Odoo: `relay_report(job, 'signed', tx_hash, n)`
  on a job already `signed` with the same `(tx_hash, outer_nonce, signer_address)` succeeds with no change; other
  values ⇒ error. Node: when the report fails, the work keeps its signed `(raw, hash, n)`; the retry re-reports
  those values before anything else; success ⇒ consume `n`, broadcast; `n` is not given to another job while the
  retry is pending. — Why: a timeout after Odoo committed wedged the job until expiry and journaled two jobs at one
  nonce. Tests: fake Odoo commits, then times out ⇒ the retried report succeeds, one broadcast, the next job gets
  `n + 1`.

- **CR-PD-6** **The private reference chain is 7622 (formerly 9000)** (L6; owner 2026-10-07 — 9000 is also Evmos
  Testnet). Replay protection is only as good as the chain id; UA R330 adds `chain_uid`. Doc only; the migration
  (profile `private9000`, seeds, env var names, KAT) is the owner's pending stream.

### 15.3 Superseded rulings and statements

| PD text | Superseded by |
|---|---|
| R1 EVM-only, META-only; Zether/non-EVM out | R30 (round 3), R34 (Zether built, dev chains), owner family taxonomy 2026-10-06 |
| R2 "~4 k gas" cost of no `mtxPay` | R138–R140 (`mtxPay` built in v2; SCaaS §5.8) |
| R3 fill-or-kill, no partial fills; `/v1/dex/orders {chain, leg}` over `MetaTxDex` | R35 `OrderBookDex` (partial, IOC/FOK, persisted book); `MetaTxDex` is legacy |
| R4 no EOA approve lockdown | R26 (addendum A) |
| R6 node ↔ Odoo only over `/json/2`, Odoo-held outbox claimed by the node | NI R87/R97/R101 (push job API, node never calls the ERP) — pull is still the built path |
| §3.1/§3.3 "Odoo is the source" of token list and finality params; R11 seeding | NI R95/R96/R99 (node store is config authority) |
| R9 unconditional pay-once | CR-PD-4 (horizon rule) |
| R11 quorum on one block hash | CR-PD-2 (quorum over event sets) |
| R13 a 65-byte signature must recover / Odoo verifies | narrowed by R27 (`wallet_kind`) |
| R16 in-memory gateway queue and DEX book | R35 (book in Odoo), NI R105 (store-backed) |
| R20 RPC endpoints only in node config | kept, restated by NI R95 (toml-only list) |
| §3.4 gateway fills unbound `feeRecipient` with the relayer address | R84/R100: `chains.fee_recipient` or 0 (code follows R84, `metatx.rs:124-131`) |
| §4.1 `dms_blockchain_payment` depends `payment` | R28 (`account_payment`) |
| §4.2 address `CHECK '^0x…'` on every column | R61 (family-aware Python check) |
| §4.4 provider holds `chain_token_id`, `chain_receiving_address` | addendum §C (receiving wallets, four eyes, cooling-off) |
| §4.6 operator may write jobs (built ACL) | CR-PD-1 (read-only, requeue via sudo method) |
| §7 "Odoo giữ không khoá nào" | addendum §D / R50: dev-only `env:` custody keys live in the Odoo process |
| chain 9000 | 7622 (formerly 9000), owner 2026-10-07 (CR-PD-6) |

### 15.4 Amendments needed in other specs (recorded here; the owner syncs them)

| Spec | Amendment |
|---|---|
| NI rev 3.6 | R103 / §5.2 step 4: `allow_call` is necessary, not sufficient — add the CR-PD-1 call table and `403 CALL_TARGET_REFUSED` (also re-checked at lease); `chain_contract.kind` gains `account_factory` (and `dex` if it is not a chain field). §9 indexer and T7: event-set quorum, `scaas_finality_quorum` (CR-PD-2). §5.2 `~gateway`: `ZERO_VALUE`, per-`from` bucket, public-profile fee-0 rule (CR-PD-3). Pruning families: `max_valid_for_secs ≤ LANE_HORIZON` (CR-PD-4). |
| SCaaS.md | §3.5 "Node ↔ chain": finality gate = event-set quorum, single-provider trust stated; §5.5: pay-lane issuance horizon H as a protocol rule; §6 Door A intake rules; chain 7622 (formerly 9000) wherever 9000 remains. |
| integration.md | Odoo outbox: immutable job fields, operator read-only (CR-PD-1). |
| DEX spec | `OrderBookDex._validSig`: cap the ERC-1271 call like `MetaToken._erc1271Gas` (400 k for `SubjectAccount` clones by codehash, 50 k otherwise) — L3; the venue fee per fill rounds **up** (`Math.mulDiv(…, Math.Rounding.Ceil)`) when the market fee is on, and the node matcher mirrors it — L4. |
| TSS rev 1.3 | R189 door table: the `~gateway` default floor per profile (CR-PD-3). |

### 15.5 Code streams (new; for TODO)

| Stream | Scope | Ruling |
|---|---|---|
| **PAY-FIX1** | Odoo `dms_blockchain`: operator ACL read-only on `blockchain.relay.job`; `action_requeue` group check; immutable job fields (incl. `dms_blockchain_dex`, subject-account extensions); tests of CR-PD-1 (a)(b) | CR-PD-1 |
| **PAY-FIX2** | `scaas-node`: `call` selector/target table in `work_from_job` (legacy pull) and at NI accept; refusal code; tests with producer vectors | CR-PD-1 (c) |
| **PAY-FIX3** | `scaas-node` EVM/Hedera indexer: event-set quorum, min `finalized`/`latest`, quorum gauge; lying-provider tests | CR-PD-2 |
| **PAY-FIX4** | `scaas-node` gateway Door A: `ZERO_VALUE`, `min_fee`/sponsor floor, public fee-0 rule, per-`from` bucket; tests | CR-PD-3 |
| **PAY-FIX5** | Odoo `_apply_report` idempotent `signed`; node retry keeps `(raw, hash, n)`; timeout-after-commit test | CR-PD-5 |
| **PAY-FIX6** | `OrderBookDex` ERC-1271 gas cap (after the DEX spec ruling) | review L3 |
| **PAY-FIX7** | `OrderBookDex` fee rounds up per fill + node matcher (after the DEX spec ruling) | review L4 |

### 15.6 Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | Initial design; agy reviews of design, plans and implementation (§14) |
| 1.1 | 2026-10-07 | Claude review 1 folded: 12 findings accepted, 0 rejected; rulings CR-PD-1…6; streams PAY-FIX1…7; superseded-rulings table (§15.3); amendments for NI, SCaaS.md, integration.md, DEX, TSS recorded (§15.4); chain 7622 (formerly 9000) |
