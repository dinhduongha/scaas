# bamboo-node

Tầng daemon của thanh toán on-chain — **một binary Rust** (`_USER-DECISIONS` §23), ba mô-đun
bật bằng config:

| Mô-đun | Việc | Nói với Odoo bằng |
|---|---|---|
| `submit` | rút outbox `blockchain.relay.job`, simulate, ký vỏ tx, broadcast, theo dõi receipt, thay thế tx kẹt, lấp nonce | API key nhóm *Blockchain Relay Worker (service)* |
| `indexer` | đọc log trong vùng **đã final** (depth/tag + quorum RPC), gửi `chain_event_ingest` | API key nhóm *Blockchain Indexer (service)* |
| `gateway` | HTTP mở: `POST /v1/metatx`, `POST/GET /v1/dex/orders`, `GET /healthz` | (qua `submit`) |

Thiết kế: `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` §3.
Không Redis, không Lua, không Postgres trực tiếp: mọi đọc/ghi Odoo đi qua `/json/2`.

## Build

```bash
cargo build --release          # rustc 1.90; alloy được ghim 1.6 qua resolver MSRV-aware (.cargo/config.toml)
cargo test                     # unit
cargo test --test e2e -- --ignored --nocapture   # cần anvil + forge trong PATH
```

## Cấu hình

Xem `node.example.toml`. File config **không** chứa bí mật — chỉ tên biến môi trường:

| Biến | Nội dung |
|---|---|
| `BAMBOO_RELAY_API_KEY` | API key của user service relay |
| `BAMBOO_INDEXER_API_KEY` | API key của user service indexer — **user khác**, nhóm khác |
| `BAMBOO_RELAYER_KEY_<chain>` | khoá vỏ tx (chỉ giữ gas, không bao giờ giữ tiền người dùng) |
| `BAMBOO_NODE_ID` | tên node ghi vào `claimed_by` |

Tạo hai user service trong Odoo: *Settings → Users*, thêm đúng một nhóm
(*Blockchain Relay Worker (service)* hoặc *Blockchain Indexer (service)*), rồi
*Account Security → New API Key*. Hai key, hai user: chiếm key indexer không ghi được job.

Danh sách token **không** nằm trong config: node đọc nó từ `blockchain.chain.node_config`.
Endpoint RPC **chỉ** nằm ở đây (ruling R20) và phải ≥ `finality.quorum`.

## Bất biến vận hành

- Không bao giờ bỏ một nonce vỏ: tx kẹt được thay thế (phí ×1.25 tới `max_fee_cap_gwei`); job
  hết hạn ⇒ nonce được lấp bằng tx 0-value tự chuyển.
- `signed` (tx_hash + nonce) được ghi vào Odoo **trước** khi gửi; khởi động lại không ký lại.
- Job chỉ `final` khi indexer thấy `MetaTransactionExecuted(digest)` trong vùng final.
- Hàng đợi gateway và sổ lệnh DEX nằm trong bộ nhớ (ruling R16): khởi động lại thì người ký
  gửi lại (chữ ký còn hạn).
