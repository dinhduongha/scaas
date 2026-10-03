# Thanh toán on-chain bằng meta-transaction — Thiết kế

**Ngày:** 2026-10-03 · **Trạng thái:** đã duyệt nội bộ, chờ review ngoài
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
2. **Relayer** `bamboo-node` (Rust, một binary — `_USER-DECISIONS` §23): mô-đun `submit`
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
| Odoo 19                                       |     | bamboo-node  (Rust, một binary)      |
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
                                                      | EVM: chain 9000 (Nethermind, Prague) |
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

**Clone-safe** (`01-token-factory.md` §1.3.5, §1.4.3):
- `constructor(address factory_)` của implementation đặt `FACTORY` và `_SELF` (immutable, đúng cho
  mọi clone) và khoá implementation (`_initialized = true` trên storage của chính nó).
- `initialize(creator, underlying, verifier, version, initData)` — `require(msg.sender == FACTORY)`,
  một lần, `verifier == 0` (kind META). Factory gọi nó **trong cùng hàm** với `CREATE2`.
- `name()`, `symbol()`, `decimals()` override để đọc storage của clone.
- **EIP-712 domain**: OZ `EIP712` giữ `name`/`version` dạng immutable, nên mọi clone của v1 có
  domain `name = "Bamboo MetaToken"`, `version = "1"`, `chainId`, `verifyingContract = clone`.
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
| `pay(bytes32 entryRef)` — đúng 36 byte | `to != 0` | transfer + `emit PaymentSettled(from, to, value, feeAmount, feeRecipient, entryRef)` |
| `trade(address counterToken, uint256 minCounterValue, address counterparty)` — đúng 100 byte | `mode & MODE_RESTRICT_RELAYER != 0` **và** `to == msg.sender` | transfer `from → msg.sender` (settlement contract) |
| khác | revert `MetaTxUnknownOp` | — |

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
  5. trả `a.m.value` token A cho `b.m.from`, `b.m.value` token B cho `a.m.from`;
  6. `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`.
- Bất kỳ bước nào fail ⇒ cả tx revert ⇒ không chân nào thực thi, không nonce nào tiêu.
- `ReentrancyGuardTransient`. Không owner, không sweep, không upgrade. **Bất biến:** số dư của DEX
  trên mọi token không đổi qua một `settle`.
- **Fill-or-kill**: `value` được ký chính xác, nên không có khớp một phần (ruling R3). Phần dư
  giá (`b.m.value > minCounterValue`) thuộc về người bán chân A — nó đã nằm trong chữ ký của B.
- Phí relayer: mỗi chân có thể trả phí bằng token của chính nó (`FIXED`/`PERCENT`, trần 1%) cho
  `feeRecipient` do relayer ngoài điền (không ràng buộc) hoặc người ký chỉ định.

### 2.4 Deploy

`script/Deploy.s.sol` (forge script, đọc `PRIVATE_KEY`, `REGISTRAR`): deploy `OpenFactory`,
`MetaToken` implementation (constructor nhận địa chỉ factory), `registerImplementation(META, 1)`,
`MetaTxDex`; tuỳ chọn tạo một token demo tầng 1. In địa chỉ ra JSON để seed Odoo và config node.
Chain 9000 dùng profile `private9000`; test tích hợp dùng `anvil --chain-id 9000 --hardfork prague`.

---

## 3. Relayer `bamboo-node`

Một crate Rust ở gốc repo (`bamboo-node/`), cạnh `smartcontracts/`. `tokio`, `alloy` (provider,
`sol!`, EIP-712, signer), `axum`, `reqwest`, `serde`, `toml`. Một binary, mô-đun bật bằng config
(`_USER-DECISIONS` §23.3). **Không Redis, không Lua, không Postgres trực tiếp** (ruling R6).

### 3.1 Cấu hình (`node.toml`)

```toml
[odoo]
url = "http://odoo:8069"
database = "odoo19"
relay_api_key_env = "BAMBOO_RELAY_API_KEY"     # user trong group_blockchain_relay_worker
indexer_api_key_env = "BAMBOO_INDEXER_API_KEY" # user trong group_blockchain_indexer

[modules]
submit = true
indexer = true
gateway = true            # bind 127.0.0.1:8545x — đặt sau reverse proxy

[[chains]]
evm_chain_number = 9000
rpc_urls = ["http://nethermind:8545"]          # >= finality.quorum endpoint độc lập
signer_key_env = "BAMBOO_RELAYER_KEY_9000"     # authKey vỏ tx — xem §6
finality = { mode = "depth", depth = 1, quorum = 1 }   # 'depth' | 'tag'
dex = "0x…"                                     # MetaTxDex, tuỳ chọn
poll_ms = 1000
stuck_after_secs = 60                           # thay thế cùng nonce, fee x1.25
max_gas_per_tx = 3000000                        # mạch ngắt SRS §6.8
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
     ok → ký EIP-1559 (nonce = next++) → eth_sendRawTransaction
          → odoo.relay_report(job, 'broadcast', tx_hash, nonce)
  theo dõi in-flight: receipt có  → status 0: 'reverted';  status 1: 'mined'
                      quá stuck_after_secs → gửi lại cùng nonce, maxFee/priority ×1.25 (tối đa 3 lần)
```

- Khởi động: `next = eth_getTransactionCount(relayer, "pending")`; các job `nonce_leased` /
  `broadcast` do chính `node_id` claim mà chưa kết thúc được đối soát lại: có `tx_hash` → hỏi
  receipt; không có → về `queued` qua `relay_report(job, 'queued')`.
- Simulation gate là bắt buộc (SRS §5.2, W3B-02 = 0%): không có `eth_call` xanh thì không ký.
- `final` của job **không** đến từ `submit`: nó đến từ `indexer` (§3.3) khi
  `MetaTransactionExecuted(digest)` qua cổng finality. Nhờ vậy job cũng final đúng khi meta-tx đã
  được người khác thực thi (MODE_OPEN, tự-relay của bên nhận).
- Hàng đợi riêng của gateway (§3.4) đi qua cùng task, cùng nonce, cùng simulation gate.

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
  (Odoo là nguồn), node config chỉ là mặc định khi Odoo chưa khai.

### 3.4 Mô-đun `gateway` — inbound công khai và DEX

HTTP (axum), không xác thực (relayer mở — SRS §4.9.4, §5), giới hạn kích thước body 64 KiB:

| Route | Việc |
|---|---|
| `POST /v1/metatx` `{chain, token, m, signature}` | token phải nằm trong danh sách Odoo; parse chặt; `metaTxDigest` + simulate; ok → hàng đợi `submit`; trả `digest` |
| `POST /v1/dex/orders` `{chain, leg}` | leg phải là `trade(...)` với `relayer == to == dex`, chưa hết hạn; simulate **từng chân** bằng `eth_call` với `from = dex` (token chỉ cho DEX thực thi, và `eth_call` cho phép đặt `from` tuỳ ý mà không cần chữ ký) — bắt chữ ký sai, thiếu số dư, nonce đã tiêu ngay ở cửa; đưa vào sổ, chạy matcher |
| `GET /v1/dex/orders?chain&sell&buy` | đọc sổ |
| `GET /healthz` | sống; `GET /readyz` — RPC và Odoo trả lời |

Matcher: với lệnh mới L (bán `L.value` A, đòi ≥ `minB` B), quét lệnh nghỉ R của cặp ngược theo FIFO,
điều kiện `R.value >= L.minB && L.value >= R.minA` và `counterparty` khớp; simulate
`settle(L, R)`; ok → đẩy vào `submit`. Lệnh hết hạn bị dọn. Sổ lệnh nằm trong bộ nhớ (ruling R16).

### 3.5 Hợp đồng RPC Odoo ↔ node (json/2)

`POST /json/2/<model>/<method>`, `Authorization: Bearer <api key>`, `X-Odoo-Database`.

| Method (model) | Nhóm | Vào | Ra / tác dụng |
|---|---|---|---|
| `node_config` (`blockchain.chain`) | relay_worker hoặc indexer | `evm_chain_number` | chain params, finality, `indexed_block`, token `[{address, decimals}]` |
| `relay_poll` (`blockchain.relay.job`) | relay_worker | `evm_chain_number, limit` | job `queued` kèm metatx đầy đủ (struct + signature + token) |
| `relay_claim` (`blockchain.relay.job`) | relay_worker | `job_ids, worker` | id claim được (CAS `UPDATE … WHERE chain_state='queued' RETURNING id`) |
| `relay_report` (`blockchain.relay.job`) | relay_worker | `job_id, chain_state, tx_hash?, nonce?, error?` | chuyển trạng thái theo bảng cho phép §4.3 |
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
(Integer, chỉ indexer ghi), `public_rpc_url` (cho ví: `wallet_addEthereumChain`), `rpc_endpoint_ids`.
Seed: 9000 (`draft`, depth 1, quorum 1), Gnosis 100 (`draft`, tag, quorum 2), Celo 42220 (`draft`).
CHECK: chain chỉ `active` khi có ≥ `finality_quorum` endpoint.

**`blockchain.rpc.endpoint`**: `chain_id`, `url`, `sequence`, `active`. Chỉ manager đọc (URL có thể
mang khoá nhà cung cấp).

**`blockchain.token`** (`mail.thread`): `chain_id`, `address`, `name`, `symbol`, `decimals`,
`domain_name` (mặc định `Bamboo MetaToken`), `domain_version` (`1`), `currency_id` (tiền pháp định
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
`origin_producer`, `origin_key`, `chain_state` (`queued`, `nonce_leased`, `broadcast`, `mined`,
`final`, `reverted`, `dead`), `business_state` (`pending`/`success`/`failed`), `claimed_by`,
`claimed_datetime`, `tx_hash`, `outer_nonce`, `attempt_count`, `last_error`.
`UNIQUE(company_id, origin_producer, origin_key)`. Không cột `state` trần (canon §C2.2).

**`blockchain.chain.event`**: `chain_id`, `company_id` (từ request khớp, có thể rỗng),
`contract_address`, `event_name` (`MetaTransactionExecuted`/`PaymentSettled`/`TradeSettled`),
`block_number`, `block_hash`, `tx_hash`, `log_index`, `from_address`, `to_address`, `value_base`,
`fee_base`, `entry_ref_hex`, `digest_hash`, `payment_request_id`.
`UNIQUE(chain_id, tx_hash, log_index)`.

**`blockchain.payment.request`** (canon §C10.9, thu gọn): `request_uuid`, `company_id`, `chain_id`,
`token_id`, `receiving_address`, `relayer_address`, `amount_base`, `amount_settled_base` (compute
stored từ event `PaymentSettled` khớp token + người nhận), `entry_ref_hex` (32 byte **ngẫu nhiên**,
ruling R9), `batch_hex` = `keccak256("bamboo.pay.lane" ‖ entry_ref)` (nonce luôn 0),
`expiry_datetime` (tạo + 1 ngày), `request_state` (`open`/`partial`/`final`/`expired`), `needs_attention` (tiền về khi tx đã huỷ, hoặc trả thừa),
`res_model`/`res_id` (nguồn), `metatx_ids`, `event_ids`. `UNIQUE(entry_ref_hex)`.
`_payment_gate()`: `int(amount_settled_base) >= int(amount_base)`; true ⇒ `request_state='final'`
và gọi hook `_on_paid()` (rỗng ở core, bridge payment override).

### 4.3 Bảng chuyển trạng thái `relay.job.chain_state`

| Từ | Sang | Ai |
|---|---|---|
| (tạo) | `queued` | Odoo, cùng transaction với `payment.transaction → pending` |
| `queued` | `nonce_leased` | `relay_claim` (CAS) |
| `nonce_leased` | `queued` (node khởi động lại, chưa ký) / `broadcast` / `dead` | `relay_report` |
| `broadcast` | `mined` / `reverted` / `broadcast` (thay thế, tx_hash mới) | `relay_report` |
| `queued`, `nonce_leased`, `broadcast`, `mined`, `reverted`, `dead` | `final` + `success` | `chain_event_ingest` khi `MetaTransactionExecuted(digest)` |
| `queued`, `nonce_leased` | `dead` | cron hết hạn (`valid_until` + 10 phút, chưa final) |

`final` là trạng thái hút: không gì rời khỏi nó. `reverted`/`dead` vẫn có thể thành `final` vì
meta-tx có thể đã được thực thi bởi đường khác — indexer là sự thật.

### 4.4 `dms_blockchain_payment`

- `payment.provider`: `code` thêm `chain`; field `chain_token_id`, `chain_receiving_address`,
  `chain_relayer_address`, `chain_validity_seconds` (mặc định 300 — canon §C8.4 cho ERC-20 công
  khai). Seed một provider `chain` ở trạng thái `disabled` + `payment.method` `chain`.
- `payment.transaction.chain_request_id`. Private: `_chain_create_request()` (amount từ tx, quy
  đổi `amount × 10^decimals` bằng `Decimal`, yêu cầu `token.currency_id == tx.currency_id` — không
  FX, ruling R17), `_chain_typed_data(from_address)`, `_chain_submit(from_address, valid_until,
  signature)`.
- `blockchain.payment.request._on_paid()` override: tìm tx, `tx._set_done()` (chỉ từ `pending`;
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
| `dms_portal_chain_payment_start(order_id, from_address)` | entitlement (`dms_allowed_partner_ids`), đơn chưa huỷ và còn phải trả; **tái dùng** tx `chain` đang `draft/pending` của đơn (cùng request ⇒ cùng lane ⇒ trả tối đa một lần); trả `{reference, chain: {chainId, name, rpcUrl, nativeCurrency}, typed_data}` |
| `dms_portal_chain_payment_submit(reference, valid_until, signature)` | entitlement qua tx; `now < valid_until <= now + chain_validity_seconds + 60` (client không được kéo dài hạn); dựng lại digest từ request + `from` đã ghi + `valid_until`; ecrecover; tạo `metatx` + `relay.job` (outbox) cùng transaction; trả trạng thái |
| `dms_portal_chain_payment_status(reference)` | `{tx_state, request_state, job_state, tx_hash}` |

Trang `/my/dms/order/<id>`: kế thừa template `dms_portal.portal_order`, thêm nút "Pay on-chain"
khi provider `chain` đang bật; JS thuần (`web.assets_frontend`): `eth_requestAccounts` →
`wallet_switchEthereumChain` (fallback `wallet_addEthereumChain`) → `start` → `eth_signTypedData_v4`
→ `submit` → poll `status`. Không có logic nghiệp vụ trong JS.

### 4.6 Nhóm và quyền (tập con của canon §C14.1)

| XML id | Được |
|---|---|
| `group_blockchain_viewer` | đọc chain, token, event, request, job của công ty mình |
| `group_blockchain_operator` | + đọc metatx, đưa job `dead` về `queued` (`action_requeue`) |
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
Ví (portal)        Odoo (bridge/payment/core)            bamboo-node              Chain
 │ connect, addr ─►│ start(order, addr):                     │                        │
 │                 │  tx(chain, sale_order_ids) + request    │                        │
 │                 │  ref32 ngẫu nhiên, lane=keccak(ref32)    │                        │
 │◄─ typed data ───│  m = {from:addr, to:receiving, value,   │                        │
 │                 │       data:pay(ref32), batch:lane,      │                        │
 │                 │       nonce:0, validUntil:now+300,      │                        │
 │                 │       mode:RESTRICT_RELAYER, relayer,   │                        │
 │                 │       fee:0, feeRecipient:0}            │                        │
 │ signTypedData   │                                          │                        │
 │── signature ───►│ submit: digest, ecrecover==addr,        │                        │
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
   final, chỉ khi tổng `PaymentSettled` khớp (token, người nhận, `entryRef`) ≥ số phải trả.
2. **Trả tối đa một lần cho mỗi request**: mọi chữ ký của một request dùng chung lane
   `(from, batch)` nonce 0, nên chain chỉ thực thi được một. Đổi ví (`from` khác) là lane khác —
   vì vậy `start` từ chối đổi `from` khi request đã có chữ ký chưa hết hạn.
3. **Số tiền do server định**: `value` lấy từ tx (= đơn hàng); client không gửi số tiền nào.
4. **Relayer không chạm tiền**: nó chỉ thực thi đúng thứ đã ký; `to`, `value`, `data` nằm trong
   digest; phí 0.

---

## 6. Typed data và digest — một quy tắc, bốn nơi

`MetaTxLib.hashStruct` (Solidity) là chuẩn. Ba bản sao phải khớp từng byte: `lib/eip712.py`
(Odoo), `bamboo-node` (alloy `sol!` struct), và typed data JSON gửi cho ví (ví tự băm). Quy tắc
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
- **Odoo không giữ khoá nào** (canon §C11.7) và không gọi chain.
- **Fee mode**: portal = `NONE` + `MODE_RESTRICT_RELAYER` (công ty trả gas; chỉ relayer của công ty
  nộp được). Gateway mở chấp nhận mọi mode hợp lệ; node có thể từ chối phí dưới ngưỡng (mặc định
  nhận phí 0 cho token trong danh sách — chính sách B2B `fee = 0`, SRS §5.2).

---

## 8. Xử lý sự cố

| Tình huống | Hành vi |
|---|---|
| Node chết / Odoo chết | job nằm `queued`; chữ ký sống tới `validUntil`; hết hạn ⇒ cron `dead`, request `open` cho phép ký lại cùng lane |
| Node chết sau broadcast trước `relay_report` | khởi động lại: job `nonce_leased` của mình không `tx_hash` ⇒ về `queued` ⇒ simulate ⇒ nếu đã thực thi thì `MetaTxBadNonce` ⇒ `dead`; indexer vẫn đưa job về `final` từ event |
| Simulate revert (thiếu số dư, hết hạn, sai chữ ký) | job `dead` + `last_error` giải mã; tx vẫn `pending`; người dùng ký lại sau khi nạp tiền |
| Tx kẹt mempool | thay thế cùng nonce, phí ×1.25, tối đa 3 lần (SRS tích hợp §5.4) |
| Tx revert on-chain (đổi state giữa simulate và inclusion) | `reverted`; nonce meta-tx **không** tiêu (bubble, canon §C8.3); có thể claim lại |
| Reorg trước final | vô hình với Odoo: chỉ vùng final được gửi |
| Reorg sau final (hard) | ngoài mô hình (Gnosis `finalized`, Clique 1 signer); không tự đảo bút toán — ruling R12 |
| RPC lệch nhau | quorum không đủ ⇒ indexer đứng, `/readyz` đỏ |
| Trả thiếu / trả thừa | thiếu: `partial`, tx `pending`; thừa (chỉ có thể nếu nhiều lane): `final` + cờ `overpaid` cho operator hoàn tiền thủ công |
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
- `dms_blockchain_payment`: quy đổi số tiền, typed data, submit sai chữ ký ⇒ lỗi, gate ⇒ `_set_done`.
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

- **R1** Chỉ EVM, chỉ META token; Zether/non-EVM/mesh ngoài phạm vi — SRS §2 tự ghi verifier
  Bulletproofs "chưa viết mã", non-EVM "thiết kế trên giấy"; portal cần đúng một đường thanh toán
  công khai — nếu sai: các phần đó thành plan sau, không phải làm lại phần này (factory đã nhận
  kind ZETHER).
- **R2** Op thanh toán đi qua `executeMetaTransaction` với `data = pay(bytes32)`, không thêm
  `mtxPay` — struct ghim là nguồn #1, một typehash duy nhất, ví hiển thị một loại giao dịch; SRS
  `mtxPay` là tầng 3 — nếu sai: ~4k gas/tx so với fast-path và chưa có `batchMtxPay`; thêm sau
  không phá chữ ký đã phát hành.
- **R3** DEX = settle hai chân meta-tx đi qua DEX, fill-or-kill, không allowance, không AMM —
  giữ "không CALL lạ trong token, không allowance" (canon §C8.5) và SRS §3.3 — nếu sai: thiếu
  khớp một phần; cần sổ trạng thái lệnh on-chain để thêm.
- **R4** Không hiện thực EOA approve lockdown (SRS §3.2) — README `smartcontracts` (nguồn #1) đã
  bỏ `isEOA` vì không quyết định đúng được sau EIP-7702; DEX không cần allowance nên không mất gì —
  nếu sai: có thể thêm vào v2 implementation, không ảnh hưởng v1.
- **R5** Domain EIP-712 của clone = tên/version của implementation + `verifyingContract` = clone —
  OZ `EIP712` immutable; an toàn replay đến từ `verifyingContract`; Odoo lưu `domain_name/version` —
  nếu sai: ví hiển thị "Bamboo MetaToken" thay vì tên token.
- **R6** `bamboo-node` nói với Odoo chỉ qua `/json/2` (đọc + ghi), claim = CAS qua RPC, không
  Postgres trực tiếp — canon §C13 claim bằng `FOR UPDATE SKIP LOCKED` rồi ghi qua `/json/2` trên
  **cùng dòng** là tự khoá (worker giữ row lock chờ HTTP, Odoo chờ row lock); `_USER-DECISIONS`
  §23 một tiến trình nên SKIP LOCKED không còn cần — nếu sai: tải poll lên Odoo (1 Hz/chain, chấp
  nhận được); thêm đường đọc Postgres sau là cục bộ trong node.
- **R7** Không depends `bamboo_idempotency`; dedup bằng UNIQUE trên khoá tự nhiên — addon tuỳ chọn
  phải cài độc lập; `bamboo_idempotency` thêm cột vào **mọi** bảng DB — nếu sai: thêm sau như một
  dependency, khoá tự nhiên vẫn đúng.
- **R8** Ba addon (`dms_blockchain`, `dms_blockchain_payment`, `dms_blockchain_bridge` cho
  portal), không `dms_blockchain_account` — `account_payment` chuẩn đã gạch nợ khi tx `done`;
  bridge canon (mixin trên `dms.payment.collection`…) chưa có người dùng — nếu sai: thêm addon
  account khi cần FX/đối soát lô.
- **R9** `entryRef` = 32 byte ngẫu nhiên; lane = `keccak256("bamboo.pay.lane" ‖ entryRef)`, nonce 0 —
  ngẫu nhiên không liên kết được ngay từ cấu tạo (tốt hơn hash có salt); lane cố định cho request
  cho phép Odoo dựng typed data không cần đọc chain và bảo đảm trả tối đa một lần — nếu sai: lần
  dùng lane đầu tốn +17k gas (đo ở `MetaTxGas`), chấp nhận.
- **R10** Portal: phí `NONE` + `MODE_RESTRICT_RELAYER` về relayer công ty — canon §C8.3 mặc định
  restrict cho luồng tiền; SRS §5.2 B2B `fee = 0` — nếu sai: relayer công ty chết thì người dùng
  không tự nộp được; chữ ký hết hạn sau 300 s nên chỉ là chậm, không mất.
- **R11** Finality do node quyết, Odoo chỉ nhận vùng final: `depth` (chain 9000: 1) hoặc `tag`
  (`finalized`) + quorum endpoint — canon §C10.9 flow gắn `payment.transaction` dùng ngưỡng hard —
  nếu sai: độ trễ ghi nhận = độ sâu final của chain (Gnosis ~3 phút).
- **R12** Không xử lý reorg sau hard finality — Gnosis `finalized` và Clique một signer không
  reorg trong mô hình; dispute canon cần `blockchain.settlement` — nếu sai: bút toán đã ghi cần
  đảo tay.
- **R13** Odoo tự kiểm chữ ký (keccak-256 + secp256k1 ecrecover thuần Python, không thư viện
  ngoài) — phản hồi tức thì cho người dùng, và là bản thứ ba của digest được khoá bằng KAT;
  `pycryptodome` có trong container nhưng không phải dependency của Odoo — nếu sai: chữ ký
  ERC-1271 (ví hợp đồng) không khôi phục được ⇒ lưu `signature_verified = False` và để simulation
  của node quyết.
- **R14** Portal UI = nút + JS thuần gọi facade; không tích hợp form thanh toán chuẩn — CLAUDE.md §6
  (mọi logic ở method model); form chuẩn cần JS payment-form riêng — nếu sai: checkout website chưa
  có nút `chain`.
- **R15** Khoá vỏ tx trong node qua trait `Signer` với bản `LocalSigner` (env/file) — custody
  broker/KMS là một làn riêng chưa có (`_USER-DECISIONS` §23.5); trait giữ chỗ cắm — nếu sai: khoá
  nóng nằm trong tiến trình parse byte lạ; giảm bằng ví relayer chỉ nạp gas tối thiểu.
- **R16** Hàng đợi gateway và sổ lệnh DEX trong bộ nhớ — mất khi khởi động lại, người dùng gửi lại
  (chữ ký còn hạn) — nếu sai: thêm lưu bền khi có khối lượng.
- **R17** Không FX: `token.currency_id` phải trùng tiền đơn hàng — quote tỷ giá (canon
  `blockchain.payment.quote`) cần nguồn giá — nếu sai: chỉ token neo đúng tiền đơn mới dùng được.

---

## 14. Review log

(điền sau review ngoài)
