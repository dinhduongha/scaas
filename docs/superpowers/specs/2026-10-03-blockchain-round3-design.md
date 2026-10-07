# Round 3 — chặn production, passkey, sáu hệ sinh thái

**Ngày:** 2026-10-03 · **Bổ sung cho:** `2026-10-03-blockchain-payments-design.md` (spec gốc, R1–R20) và
`2026-10-03-blockchain-payments-addendum-wallets.md` (addendum ví, R21–R29). Ruling mới đánh số từ R30. **R30–R49 dành cho quyết định của owner** (owner tự đặt số); ruling kỹ thuật của
round này đánh số từ **R50** để không phải đánh số lại khi owner thêm quyết định.

**Rev 1.1 (2026-10-07):** Claude review 1 folded (§H: rulings CR-R3-1…10, streams R3-FIX1…14, superseded-rulings
table §H.4). **Rev 1.2 (2026-10-07): owner ruling CR-R3-11** — the Aptos, Sui and Solana programs are
**immutable at deploy** ("Bất biến ngay khi deploy", §H.3); this replaces open question Q1 of rev 1.1. "Sáu hệ sinh thái" is superseded by the owner's family taxonomy of 2026-10-06 (eight
families: EVM incl. Hedera, Aptos, Sui, Soroban, Cosmos, TON, Solana; §H.4).

**Nguồn yêu cầu (owner, qua coordinator, cùng ngày):** (1) relayer + contract + DEX cho Hedera, Sui, Soroban,
Cosmos, TON — **thay R1**; (2) cấu hình khoá relayer bằng khoá thô hoặc mnemonic 24 từ; (3) **sửa đổi**: meta-tx
cấp contract là đường mặc định, không dùng sequence tài khoản của chủ thể; (4) gap analysis
`/.superpowers/blockchain-gap-analysis.md` (gọi tắt **GA**): làm các blocker production trước; (5) SRS nguyên tắc 6
+ §1.1: blockchain là dịch vụ hạ tầng, **client ký**, passkey ký mọi thao tác ghi có giá trị.

**Thứ tự thực hiện (owner):** A. blocker production + khoảng trống SRS chọn lọc → B. abstraction adapter + khoá →
C. passkey (song song/ trước Hedera vì dùng chung verifier EVM) → D. Hedera → Sui → Soroban → Cosmos → TON.
Hợp nhất với nhánh territory: **không** làm ở nhánh này (coordinator làm), chỉ giữ seam sạch (§A.9).

---

## 0. Nguyên tắc xuyên suốt của round này

1. **Client ký, relayer trả phí** (SRS nguyên tắc 6, §1.1). Server không bao giờ giữ khoá để ký thay chủ thể;
   ngoại lệ duy nhất là ví custodial/mandate được uỷ thác rõ ràng, có hạn mức, bốn mắt (addendum D) — giữ nguyên.
2. **R30 — chống khoá chủ thể (owner):** *"lỗi khóa async của chủ thể trên nhiều contract — lỗi nặng của
   blockchain"*. Sequence tài khoản (Stellar sequence, Cosmos account sequence, TON wallet seqno, đường tx tài khoản
   Hedera) xếp hàng **mọi** thao tác của một chủ thể trên **mọi** contract: một tx kẹt khoá chủ thể ở khắp nơi.
   Vì vậy trên mọi mạng, đường chính là **meta-tx cấp contract**: chủ thể chỉ **ký** một payload có tách miền
   (mạng + contract + lane + nonce + hạn + hash thao tác), **mỗi contract tự giữ không gian lane/nonce của nó**
   (dùng lại R9: lane ngẫu nhiên theo `entryRef`, nonce 0), relayer gửi tx **từ tài khoản của chính nó**.
   Cơ chế tài trợ gốc của mạng (Sui sponsored, Soroban fee-bump, Cosmos feegrant, TON W5) chỉ dùng khi cần để
   **relayer** trả phí, **không bao giờ** để sequence của chủ thể làm khoá thứ tự.
3. **Relayer không thành khoá toàn cục mới:** mỗi mạng có nhiều **lane relayer** (tài khoản dẫn xuất từ mnemonic
   theo account index); mỗi lane có sequence riêng; job rải theo lane. §B.5 ghi từng adapter tránh head-of-line thế nào.
4. **Bất biến của owner giữ nguyên trên mọi mạng:** không tài khoản thường nào là spender (uỷ quyền/allowance chỉ
   cho contract/program), không replay, có hạn, hạn mức mandate theo lần/kỳ; bốn mắt và snapshot ví nhận ở Odoo.
5. **Code thắng SRS** khi đã có ruling (thứ tự ưu tiên của spec gốc). Mâu thuẫn được chốt ở
   `2026-10-03-srs-deltas.md`.
6. **Bất biến ngay khi deploy (owner, 2026-10-07 — CR-R3-11, Claude review H3):** gói Aptos, Sui và program Solana
   giữ số dư của mọi chủ thể nên **không nâng cấp được kể từ lúc deploy** (Aptos `upgrade_policy = "immutable"`, Sui
   `make_immutable` trên UpgradeCap, Solana upgrade authority = None), như contract EVM và SCaaS §1.2/§1.3. Sửa lỗi =
   deploy phiên bản mới + di chuyển. Hôm nay các deploy dev còn nâng cấp được bằng một khoá — stream R3-FIX15.

---

## A. Blocker production và khoảng trống SRS làm ngay (GA §2.1, §2.2 #4/#6/#7, §2.3 #12/#13/#14)

### A.1 Custody `env:` chỉ cho dev/test (GA 2.1#1) — R50

- Adapter `env:` **không còn tự đăng ký**. Chỉ đăng ký khi `ir.config_parameter`
  `dms_blockchain.allow_dev_custody` = `1`, **và** chỉ ký cho ví trên chain có `is_dev_chain = True`. Ví
  custodial/delegated trên chain không phải dev mà `signer_ref` dùng `env:` ⇒ từ chối lúc duyệt và lúc ký.
- **Constant-time:** ký ECDSA qua thư viện `cryptography` (OpenSSL; đã là phụ thuộc của Odoo — không thêm gì),
  không qua `secp256k1.py` thuần Python. `cryptography` sinh `k` ngẫu nhiên (không RFC 6979): chữ ký không tất
  định — chấp nhận; test so `ecrecover` thay vì so byte. Tính `v` bằng thử hai giá trị; chuẩn hoá low-s.
  `secp256k1.sign` thuần Python giữ lại **chỉ** cho vector test. Ghi giới hạn: code Python quanh OpenSSL vẫn chạy
  trong tiến trình Odoo — khoá nằm trong bộ nhớ tiến trình; production phải dùng adapter KMS/HSM (ngoài phạm vi).

### A.2 Khoá relayer — xem §B.3 (GA 2.1#2)

### A.3 Giám sát (GA 2.1#3, 2.3#12) — R51

- Node mở **cổng quản trị riêng** (`[modules] admin_bind`, mặc định `127.0.0.1:9108`), tách khỏi gateway công khai:
  - `GET /healthz` — tiến trình sống.
  - `GET /readyz` — trả ngay từ **trạng thái đệm** do một task nền cập nhật mỗi 10 s (review S19); 200 chỉ khi: mỗi chain có ≥ `finality.quorum` RPC trả lời trong 3 s; Odoo trả lời
    (`relay_stats`); độ trễ indexer `head_final − indexed ≤ max_index_lag` (cấu hình theo chain). Ngược lại 503 kèm
    JSON lý do. Không có gateway vẫn có `/readyz` (sửa GA 2.3#12). *(Claude review H2 → CR-R3-2: "quorum" là quorum
    trên tập event của vùng, không chỉ trên head; Cosmos/TON hôm nay không có quorum nào.)*
  - `GET /metrics` — văn bản Prometheus, viết tay (không thêm crate): `scaas_relay_jobs{chain,state}` (gồm
    `dead`), `scaas_payment_requests_attention{chain}`, `scaas_indexer_lag_blocks{chain}`,
    `scaas_relayer_balance{chain,lane}` (đơn vị nhỏ nhất của coin gas), `scaas_breaker_open{chain,breaker}`,
    `scaas_drift_alerts{chain}`.
- Số liệu Odoo đến từ method dịch vụ mới `blockchain.chain.relay_stats(chain_key)` (đọc, nhóm relay/indexer).

### A.4 CI (GA 2.1#4) — R52

`.github/workflows/blockchain-ci.yml`, chạy trên PR/push chạm `smartcontracts/**`, `scaas-node/**`,
`dms_blockchain*/**`: (a) forge (foundry-toolchain, `lib/` cài bằng `forge install` theo tag đã ghim:
OpenZeppelin `v5.2.0`, forge-std `v1.16.2` — vì `lib/` không commit), hai profile; (b) cargo test + clippy
`-D warnings` + e2e anvil; (c) Odoo `odoo:19` + postgres: cài `dms_blockchain, dms_blockchain_payment,
dms_portal, dms_blockchain_bridge` với `--test-tags`, rồi `-u` hai lần; (d) mỗi hệ sinh thái mới thêm job của nó
(move test, soroban, cosmwasm, tact) khi được thêm. Chrome tour cần Chrome trong image: dùng image `odoo:19` có
sẵn chromium? Không có ⇒ job Odoo cài `chromium` bằng apt **trong runner** (CI là hệ thống tạm, không phải máy
owner).

### A.5 Tạm dừng chỉ chặn gửi (GA 2.1#7) — R53

`blockchain.chain.state`: `draft | active | paused | halted`.
- `paused`: `relay_poll` trả rỗng, gateway từ chối, **indexer và `chain_event_ingest` tiếp tục**
  (`node_config` phục vụ cả `paused`). Khách đã trả tiền vẫn được ghi nhận.
- `halted`: dừng cả indexing (sự cố chain/reorg cần người); `draft`: chưa bật.

### A.6 Xác thực gateway + fuzz parser (GA 2.1#8) — R54

- `[modules] gateway_auth = "none" | "bearer" | "hmac"`; `gateway_secret_env`. `bearer`: `Authorization:
  Bearer <secret>` so sánh constant-time. `hmac`: `X-SCaaS-Timestamp` + `X-SCaaS-Signature =
  hex(HMAC-SHA256(secret, ts ‖ "." ‖ nonce ‖ "." ‖ METHOD ‖ " " ‖ path?query ‖ "\n" ‖ body))`, lệch giờ ≤ 300 s,
  `X-SCaaS-Nonce` (`[A-Za-z0-9_-]{1,64}`) nhớ tới khi chính timestamp hết hạn (ts + 300 s) ⇒ không phát lại (review S20); method + đường
  dẫn nằm trong chuỗi ký nên chữ ký một route không dùng được cho route khác. Mặc định `none` bị **từ chối** khi bind không
  phải loopback (lỗi cấu hình thì chết sớm).
- `proptest` (dev-dependency) cho mọi decoder đầu vào không tin cậy: `WireMetaTx::to_sol`, body gateway,
  payload job, decoder của từng adapter mới (BCS/XDR/protobuf/BOC). Bất biến: không panic, lỗi là `Err`.

### A.7 Cầu dao gas (GA 2.2#4) — R55

Theo chain, trong node (bộ nhớ, đặt lại khi khởi động):
- **Base-fee spike** (EVM): trung bình trượt 1 h của `baseFeePerGas`; nếu base fee hiện tại > `spike_ratio` (mặc
  định 3.0) × trung bình ⇒ tạm ngưng gửi job **mới** (job đã ký vẫn theo dõi/ thay thế); mở lại khi về dưới.
- **Ngân sách gas theo cửa sổ:** `gas_budget_per_hour` (đơn vị nhỏ nhất của coin gas, theo lane×chain); 90 % ⇒
  log cảnh báo + metric; 100 % ⇒ ngưng gửi job mới đến hết cửa sổ.
- **Sàn số dư relayer:** lane có số dư < `min_relayer_balance` ⇒ lane đó ngưng nhận job; < 20 % sàn cảnh báo.
- Cầu dao **không bao giờ** chặn indexing hay theo dõi tx đã gửi (SRS A§6.8). Mạng không phải EVM dùng ngân sách
  + sàn số dư (không có base fee kiểu EIP-1559).

### A.8 Một journal mỗi (chain, token) + kiểm drift (GA 2.2#6, #7) — R56

- `blockchain.token.journal_id` **company-dependent** (mỗi công ty chọn một journal ngân hàng cho mỗi token). Khi
  có, `payment.transaction` của provider `chain` hạch toán `account.payment` vào journal đó (dòng payment method
  của provider trên journal đó được tạo khi gán); không có ⇒ journal của provider như cũ.
- **Drift A (tiền vào không khớp):** indexer đọc thêm event `Transfer` (ERC-20) tới các **địa chỉ ví nhận**
  (node lấy danh sách từ `node_config`). Transfer không thuộc một tx đã có `PaymentSettled` ⇒ bản ghi
  `blockchain.chain.event` với `event_name = 'Transfer'` không khớp request ⇒ đánh dấu `unmatched_inbound`, hiện ở
  báo cáo drift và metric.
- **Drift C (số dư):** node định kỳ (mặc định 1 h) đọc `balanceOf(ví nhận)` tại khối đã final và báo
  `blockchain.chain.balance_report(chain_key, height, [{token, address, balance}])`. Odoo lưu
  `blockchain.balance.snapshot` và so **tổng** số dư mọi ví nhận đã duyệt của (công ty, token) với **số dư GL** của
  journal token của công ty đó (đổi về đơn vị cơ sở; review S16 — quét sang ví lạnh phải hạch toán thì hết lệch). Lệch
  ≠ 0 ⇒ `drift_state = 'mismatch'` + activity cho người duyệt ví. Không tự sửa sổ.
- Triển khai (S1): báo cáo chỉ được so khi `height` = cursor đã index (khác ⇒ `stale`, node đọc lại); sổ = các dòng
  posted của journal token trên tài khoản ngân hàng + mọi tài khoản outstanding mà payment của journal đã dùng;
  activity khi lệch kéo dài hai ảnh chụp liên tiếp (một lần lệch là độ trễ post-processing của `payment`).
  Họ không phải EVM: chưa có drift (adapter chưa có `balanceOf`/Transfer) — ghi ở HANDOFF.

### A.9 Seam cho nhánh territory + đổi tên "Host" (GA 2.3#13, #14, §2.4) — R57

- **Một** method công ty nhận: `dms.portal.api._dms_chain_receiving_company(order)`; mọi lookup provider, ví nhận,
  ghi chú nhân viên đi qua nó (sửa GA 2.3#13: `_dms_chain_offered`, `_dms_chain_start`, `sale_order`).
  `payment_transaction` giữ ràng buộc ví nhận cùng công ty với tx, thêm test khẳng định công ty giải được ==
  `order.company_id` (sẽ đỏ nếu một tier tương lai làm chúng khác).
- **Một** method quản trị ví: `res.users._blockchain_wallet_admin(company)` (đã có).
- "Host" (R23) ⇒ **"platform company"**: tham số `dms_blockchain.platform_company_id` (đọc cả tên cũ một lần khi
  nâng cấp), method `_blockchain_platform_company()`. Tránh trùng nghĩa "Host" của territory (bản ghi
  `company_id = False`).

### A.10 Ghi vào HANDOFF, không xây (GA 2.1#5/#6, 2.2 còn lại)

`docs/superpowers/HANDOFF-blockchain.md`: audit bên thứ ba, triển khai thật (7622 (formerly 9000)/Gnosis), bằng chứng finality 7
ngày, ≥2 RPC độc lập, và mọi mục GA 2.2 không làm ở round này (kèm tham chiếu SRS).

---

## B. Abstraction adapter, signer, khoá relayer

### B.1 `ChainAdapter` (scaas-node) — R58

```rust
pub enum Family { Evm, Hedera, Sui, Soroban, Cosmos, Ton }

#[async_trait]
pub trait ChainAdapter: Send + Sync {
    fn family(&self) -> Family;
    fn chain_key(&self) -> &str;                       // "evm:7622" (formerly 9000), "sui:localnet", "cosmos:wasmd-1"…
    // chain_key một mình không định danh chain (7622 không giả định là duy nhất): chain = (chain_key, chain_uid),
    // chain_uid = genesis hash do RPC báo (UA R330); adapter đối chiếu lúc khởi động.
    fn lanes(&self) -> &[Lane];                        // địa chỉ relayer theo lane
    async fn build(&self, job: &Job, lane: usize) -> Result<Built, SimError>;   // dựng + mô phỏng
    async fn sign(&self, built: Built, lane: usize, seq: u64) -> Result<Signed>; // qua Signer
    async fn submit(&self, signed: &Signed) -> Result<()>;
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus>;   // Pending | Mined{height} | Reverted{why} | Unknown
    async fn sequence(&self, lane: usize) -> Result<u64>;         // nonce / sequence / seqno (Sui: 0, không dùng)
    async fn final_head(&self) -> Result<Head>;                   // chiều cao + hash đã final (quorum)
    async fn events(&self, from: u64, to: u64) -> Result<Vec<Value>>; // event chuẩn hoá cho chain_event_ingest
}
```

*(Superseded/drift — Claude review L6: `Family` has eight members (owner taxonomy 2026-10-06); the built trait has
`events(from, to, contracts)`, `final_head -> Option<Head>`, `block_hash`, `lane_balance`, `tx_fee`,
`resend_journaled`, `op_consumed` (`scaas-node/src/adapter.rs`). The code is the reference. CR-R3-2: `final_head`
and `events` must agree across ≥ `quorum` endpoints on every family.)*

- **EVM** cài trait bằng `chain.rs` hiện có; vòng `submit.rs` (nonce pipelining, thay thế, gap-fill) **giữ
  nguyên hành vi** và test xanh. Indexer EVM giữ nguyên, chạy qua `final_head`/`events`.
- **Mạng khác** dùng runner chung `lane_runner`: mỗi lane một job đang bay (claim → build/simulate → sign → báo
  `signed` (journal) → submit → theo dõi tới `mined`/`reverted`/hết hạn). Không pipeline trong một lane; song song
  giữa lane. Hết hạn payload ký mà tx chưa vào ⇒ `dead` (chain từ chối payload hết hạn, không lặp).
- **Event chuẩn hoá** (mọi họ): `{event, contract, block_number, block_hash, tx_hash, log_index, from, to,
  amount, fee, fee_recipient, entry_ref}` với địa chỉ ở **dạng chuẩn của họ** (§D.0). `chain_event_ingest` nhận
  `chain_key`.

### B.2 `Signer` — R59

```rust
pub enum Curve { Secp256k1, Ed25519 }
pub trait Signer: Send + Sync {
    fn curve(&self) -> Curve;
    fn public_key(&self) -> Vec<u8>;               // compressed 33 B / 32 B
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>; // secp: prehash 32 B → 65 B r‖s‖v (low-s); ed25519: 64 B
}
```
`LocalSigner` (secp256k1 qua k256 của alloy, ed25519 qua `ed25519-dalek`). **Seam KMS/remote:** trait là chỗ
cắm; không cài adapter KMS ở round này (HANDOFF).

### B.3 Cấu hình khoá relayer — R60

```toml
[keys]
mnemonic = { env = "SCAAS_MNEMONIC" }          # hoặc { file = "/run/secrets/mnemonic" } (0600)
                                                # hoặc { keystore = "/etc/scaas/m.json", passphrase_env = "…" }
bip39_passphrase_env = "SCAAS_BIP39_PASSPHRASE" # tuỳ chọn
[[chains]]
family = "sui"; network = "localnet"
lanes = [0, 1, 2, 3]                            # account index theo BIP-44/SLIP-44
# hoặc: private_key = { env = "…" } | { file = "…" } | { keystore = "…", passphrase_env = "…" }  (một lane)
```

- BIP-39: **24 từ** (256 bit), kiểm checksum, từ điển tiếng Anh; seed = PBKDF2-HMAC-SHA512(2048).
- Đường dẫn theo coin type SLIP-44 (owner) — `i` = account index của lane:

| Họ | Coin | Đường cong | Đường dẫn | Ghi chú |
|---|---|---|---|---|
| EVM | 60 | secp256k1 BIP-32 | `m/44'/60'/0'/0/i` | như MetaMask |
| Hedera | 3030 | secp256k1 BIP-32 | `m/44'/3030'/0'/0/i` | JSON-RPC relay cần tài khoản ECDSA (alias EVM) |
| Sui | 784 | ed25519 SLIP-10 | `m/44'/784'/i'/0'/0'` | chuẩn Sui (mọi cấp hardened) |
| Stellar | 148 | ed25519 SLIP-10 | `m/44'/148'/i'` | SEP-0005 |
| Cosmos | 118 | secp256k1 BIP-32 | `m/44'/118'/0'/0/i` | |
| TON | 607 | ed25519 SLIP-10 | `m/44'/607'/i'` | **không** phải mnemonic gốc TON (PBKDF2 "TON default seed"); ví TON nhập được qua "BIP-39/Ledger path" — ghi rõ |

- Nguồn: file (từ chối nếu quyền không phải 0600/0400), biến môi trường, keystore mã hoá. Keystore: **Web3 Secret
  Storage v3** (scrypt + AES-128-CTR, MAC keccak) cho **cả hai** đường cong — bí mật 32 byte (khoá secp256k1 hoặc
  seed ed25519) hoặc mnemonic (UTF-8); thêm trường `"scaas": {"kind": "secp256k1"|"ed25519"|"mnemonic"}`.
  CLI: `scaas-node keystore new --kind … --out …` (đọc bí mật từ stdin, passphrase từ env).
- Không bao giờ log/ghi file cấu hình bí mật; khởi động in **chỉ địa chỉ** dẫn xuất của từng lane.
  `scaas-node addresses --config` in địa chỉ rồi thoát.
- Test: vector BIP-39 (Trezor, passphrase "TREZOR"), SLIP-10 ed25519 (test vector 1), SEP-0005, BIP-32/BIP-44
  secp256k1 (mnemonic "abandon…art" ⇒ địa chỉ MetaMask đã công bố).

### B.4 Odoo: họ mạng, địa chỉ, payload ký — R61

- `blockchain.chain`: `family` (`evm|hedera|sui|soroban|cosmos|ton`), `network_key` (EVM/Hedera: chain id;
  Sui: `mainnet|testnet|devnet|localnet`; Stellar: `pubnet|testnet|standalone`; Cosmos: chain-id;
  TON: `-239|-3|localnet`), `chain_key = family:network_key` (unique), `is_dev_chain`, `bech32_prefix` (Cosmos),
  `network_passphrase` (Stellar). `evm_chain_number` chỉ bắt buộc cho `evm|hedera`. `caip2`: `eip155:N`,
  `hedera:mainnet|testnet`, `sui:<net>`, `stellar:<pubnet|testnet>`, `cosmos:<chain-id>`, `ton:<-239|-3>`.
  API dịch vụ nhận `chain_key` (số nguyên cũ vẫn hiểu là `evm:N`).
- `lib/addresses.py` — `parse(family, value, chain) -> canonical`:
  - EVM: EIP-55 (đã có). Hedera: EIP-55 **hoặc** `0.0.N` (⇒ địa chỉ long-zero `0x000…N`), lưu dạng `0x`.
  - Sui: `0x` + tối đa 64 hex, chuẩn hoá đủ 64 chữ thường.
  - Stellar: strkey `G…` (account) / `C…` (contract): base32, version byte, CRC16-XModem; từ chối `M…`/`S…`.
  - Cosmos: bech32 (BIP-173), HRP = `bech32_prefix` của chain, dữ liệu 20 (tài khoản) hoặc 32 byte (contract).
  - TON: raw `wc:hex64` hoặc user-friendly base64/base64url 48 ký tự (tag, wc, hash, CRC16-XModem; cờ testnet
    phải khớp chain); lưu dạng raw `wc:hex64`.
- Ràng buộc địa chỉ DB (`CHECK ~ '^0x…'`) chuyển sang kiểm theo họ ở Python; cột vẫn Char. Ràng buộc cũ bị gỡ
  khi nâng cấp (kiểm bằng `pg_constraint` sau `-u` — review S25).
- **Payload ký theo họ** (`blockchain.signed.op`, cạnh `blockchain.metatx` EVM): `family, contract, from,
  payload` (bytes canonical của họ), `signature`, `pubkey`, `auth_kind` (`wallet|passkey`), `digest`. Odoo
  **dựng** payload từ request (không gọi RPC — R20) và chuyển cho ví ký; **kiểm** chữ ký ở mức cấu trúc (độ dài,
  định dạng) và, nếu là ed25519 của ví thường, kiểm thật bằng ed25519 thuần Python (RFC 8032, KAT). Phần còn lại
  do mô phỏng của node phân xử (như R27). Job `kind = 'signed_op'`.

### B.5 Tránh head-of-line theo adapter — R62

| Họ | Ai gửi tx | Thứ tự phía relayer | Vì sao một tx kẹt không khoá nơi khác |
|---|---|---|---|
| EVM (Hedera: `lane_runner`, net-hedera R6-1 — Claude review L2) | lane EOA | nonce per lane, pipeline + thay thế + gap-fill | chủ thể không có nonce tài khoản trong đường đi; lane khác chạy tiếp |
| Sui | lane address, gas coin riêng của lane | không nonce; mỗi lane một gas coin, một tx bay | object version per lane; shared object của chủ thể không có sequence |
| Soroban | lane account | sequence per lane, một tx bay | auth entry của chủ thể dùng nonce ngẫu nhiên (không tuần tự) |
| Cosmos | lane account | account sequence per lane, một tx bay | chủ thể không gửi tx |
| TON | lane wallet (W5) | seqno per lane, một tx bay | chủ thể không gửi tx; jetton wallet của chủ thể giữ lane/nonce riêng |

Test bắt buộc mỗi mạng (**anti-lock**): chủ thể ký thao tác X trên contract 1 và Y trên contract 2; giữ lại X
(không gửi / gửi kẹt); Y vẫn thành công; sau đó X thành công.

---

## C. Passkey (SRS nguyên tắc 6, §1.1 hệ quả 2–3) — R31

Cơ sở: `2026-10-03-blockchain-infrastructure-service.md` (blockchain là dịch vụ hạ tầng — client ký; bản trong repo
của SRS nguyên tắc 6 và §1.1). R31 và R32 thực hiện hệ quả 1–3 của tài liệu đó.

- **Định dạng:** WebAuthn assertion `{authenticatorData, clientDataJSON, r, s}` trên P-256. Challenge trong
  `clientDataJSON` = base64url(**digest thao tác**) (EIP-712 trên EVM; digest typed của từng mạng). Verifier kiểm:
  `type == "webauthn.get"`, challenge đúng, `rpIdHash` (32 byte đầu authenticatorData) = SHA-256(rpId) đã đăng
  ký, cờ **UP và UV**, **`origin`** trong `clientDataJSON` = origin đã đăng ký (review S17), `s ≤ n/2` (low-s), rồi
  P-256 trên `sha256(authenticatorData ‖ sha256(clientDataJSON))`. **CR-R3-1 (Claude review H1/M1):** một ngữ pháp
  `clientDataJSON` duy nhất cho mọi verifier (ngữ pháp chặt của EVM, `crossOrigin:true` bị từ chối, origin khớp
  **đúng**, không theo tiền tố) và một bộ vector chung; Cosmos hôm nay không kiểm rpIdHash, origin, UV (§H.2). WebAuthn trả chữ ký **DER** và authenticator
  **không** ép low-s: client giải DER thành `(r, s)` và chuẩn hoá `s := n − s` khi `s > n/2` (vẫn hợp lệ) trước
  khi gửi (review S5).
- **Gom lô:** challenge = gốc Merkle (keccak trên EVM, sha256 nơi khác) của các digest, lá băm kép
  `H(H(0x00 ‖ digest))` theo khuyến nghị OpenZeppelin để chặn second-preimage (review S26); chữ ký mỗi thao tác mang
  `(assertion, proof)`; verifier kiểm proof(digest → root) rồi assertion trên root. Một lần sinh trắc cho N dòng,
  mỗi dòng vẫn gắn với root đã ký.
- **EVM (và Hedera):** `SubjectAccount` (§C.3) — smart account ERC-1271 (đúng `AuthScheme.SMART_ACCOUNT_1271 = 7`):
  nhiều passkey `(qx, qy, rpIdHash)`; `isValidSignature(digest, sig)` theo trên; P-256 bằng `P256.verify` của
  OpenZeppelin 5.2 (gọi precompile RIP-7212 `0x100` nếu có, nếu không verifier Solidity). Probe precompile lúc
  cấu hình chain: `blockchain.chain.has_p256_precompile`. Vì verifier Solidity tốn ~200–330k gas, trần gas
  `staticcall` ERC-1271 trong `ERC20MetaTx` nâng từ 50k lên **400k** (contract chưa deploy thật — GA N9).
  *(Superseded: trần 400 k chỉ cho clone `SubjectAccount` nhận theo codehash, `MetaToken.sol:141-144`.)*
  **Triển khai account:** `SubjectAccountFactory` CREATE2, salt = hash(khoá đầu tiên) *(superseded →
  `keccak256(abi.encode(firstKey, guardian))`, `SubjectAccountFactory.sol:21-23`)* ⇒ địa chỉ biết trước; Odoo
  xếp job `call` `deploy` vào outbox **trước** job thanh toán đầu tiên của chủ thể (deploy không cần quyền:
  ai deploy cũng ra cùng account với cùng khoá) (review S3).
- **Vòng đời khoá:** `addKey`/`removeKey`/`setGuardian` chỉ qua `executeAsOwner` ký bởi một passkey hiện có
  (nonce riêng) hoặc `recover(newKey)` bởi guardian sau trễ `RECOVERY_DELAY` (mặc định 2 ngày, huỷ được bởi
  passkey). Không bao giờ còn 0 khoá.
- **Mạng khác:** Sui `ecdsa_r1::secp256r1_verify`; Soroban `env.crypto().secp256r1_verify` (CAP-51); Cosmos
  `secp256r1_verify` của cosmwasm-std 2.1+; Hedera = EVM (probe precompile, fallback Solidity); TON: TVM có
  `P256_CHKSIGNU/P256_CHKSIGNS` (nâng cấp TVM 2023/2024) — dùng qua `asm` trong Tact; reviewer cho rằng không có
  (review S6) — sẽ kiểm bằng biên dịch + sandbox; không có thì TON chỉ ed25519 và ghi khoảng trống.
  Mỗi mạng: account/contract của chủ thể lưu passkey; thao tác ký bằng passkey đi cùng đường meta-tx của mạng đó.
- **Portal:** nút "Dùng passkey" khi `window.PublicKeyCredential` có; `navigator.credentials.create` lúc đăng ký
  (nhân viên/khách tạo account), `get` lúc ký với `challenge = digest`; ví EIP-6963 vẫn là lựa chọn khác.
- **Test:** vector WebAuthn thật — sinh bằng authenticator phần mềm (khoá P-256 cố định, ký đúng định dạng
  WebAuthn) và một vector công khai (Daimo/OZ test suite) nếu lấy được.
- **Custody:** ví custodial/mandate vẫn là **chỗ duy nhất** server ký, được uỷ thác rõ ràng và có hạn mức (A.1).

### C.2 Ví seed words phía client — R32 (owner: *"Làm cả passkey, cả seed words"*)

- Ví HD không lưu ký từ mnemonic BIP-39 **24 từ**, sinh hoặc nhập **trên thiết bị**. Mnemonic và khoá **không bao
  giờ** rời thiết bị, không gửi Odoo hay relayer.
- **Dẫn xuất** *(superseded cho khoá account → UA R300 / S4F R269 role tree `m/7622'/0'/<account>'/<kind>'/<i>'`,
  SCaaS §9.4; addendum CR-ADW-3)* (cùng bảng §B.3, nhưng cho chủ thể): EVM `m/44'/60'/0'/0/i` (secp256k1); Cosmos `m/44'/118'/0'/0/i`;
  Hedera-ECDSA `m/44'/3030'/0'/0/i`; Hedera-ED25519 `m/44'/3030'/0'/0'/i'` (như HashPack); Sui `m/44'/784'/i'/0'/0'`;
  Stellar `m/44'/148'/i'`; TON `m/44'/607'/i'`.
- **Ký**: đúng digest typed của mạng như mọi signer khác (EIP-712 / payload `MetaOp` của họ).
- **Lưu trữ**: mã hoá AES-GCM (WebCrypto). Khoá bọc: **PRF** của passkey (`extensions.prf`) nếu có; nếu không,
  PIN/passphrase qua **scrypt** (N=2^15, r=8, p=1 — 32 MB, memory-hard; 2^17 làm treo trình duyệt di động —
  review S23; thư viện `@noble/hashes` vendored) *(superseded → S4F R259: `N = 2^17`, passphrase ≥ 8 ký tự,
  `clientkeys/src/vault.js:14,40-45`)*. Không lưu
  khoá bọc. Lưu ở IndexedDB/localStorage của origin (try/catch).
- **Sao lưu**: hiện mnemonic **một lần**, bắt buộc bước xác nhận (nhập lại 3 từ chọn ngẫu nhiên) trước khi dùng.
- **Nhập**: kiểm checksum BIP-39; sau khi dùng ghi đè buffer bí mật (`fill(0)`) trong giới hạn của JS (chuỗi
  không xoá được — ghi rõ).
- **Thư viện**: `@noble/hashes`, `@noble/curves` (secp256k1, ed25519), `@scure/bip39`, `@scure/bip32` — ghim
  phiên bản, vendored dạng ESM bundle trong `static/lib/`, **chỉ nạp khi chọn ví seed**.

### C.3 Account chủ thể nhiều khoá (R31 + R32)

- Một chủ thể có **một account** trên mỗi mạng (smart account EVM / object, contract ở mạng khác) *(không đúng
  trên Sui hôm nay: một `Account<T>` mỗi coin type, mỗi cái một bộ khoá — CR-R3-5)* giữ **nhiều
  khoá được uỷ quyền**: passkey (P-256 WebAuthn) và khoá dẫn xuất từ seed (secp256k1 / ed25519 tuỳ mạng).
  Thêm/xoay/xoá khoá cần chữ ký của một khoá hiện có, hoặc guardian sau trễ khôi phục. Seed là khoá khôi phục tự
  nhiên khi mất passkey, và ngược lại.
- EVM: `SubjectAccount` (ERC-1271) — khoá kiểu `P256_WEBAUTHN(qx,qy,rpIdHash)` hoặc `SECP256K1(address)`;
  chữ ký = `abi.encode(keyIndex, payload)` *(superseded → `abi.encode(keyIndex, bytes32[] proof, bytes sig)`,
  RS4-3)*; batch Merkle cho cả hai kiểu *(Claude review L1: gom lô Merkle chỉ có trên EVM và Soroban; các họ khác
  kiểm từng digest)*.
- Test e2e: thêm khoá thứ hai (seed khi đã có passkey) rồi ký bằng từng khoá.

### C.4 Khoá Zether (bảo mật số dư) từ cùng seed, đường dẫn riêng — R33 (owner: *"Seed word gen key riêng cho zether (key path khác)"*)

- SRS §8.1 tách `auth_custody` (khoá ký) và `conf_custody` (khoá ElGamal `x`): lộ khoá ký không lộ số dư; lộ `x`
  không uỷ quyền chuyển tiền. Nên `x` có **đường dẫn riêng**, không bao giờ trùng scalar khoá ký nào.
- BIP-32/SLIP-10 không có bn254 hay BLS12-381 ⇒ dẫn xuất **hardened-only kiểu EIP-2333** (HKDF-SHA256, `r` là bậc
  của nhóm, tách miền):
  - **BLS12-381:** đúng EIP-2333 (`derive_master_SK`, `derive_child_SK`, salt `"BLS-SIG-KEYGEN-SALT-"`), đường
    kiểu EIP-2334 `m/12381/<coin>/<account>/7` — `<use> = 7` dành riêng cho Zether-conf (EIP-2334 dùng 0 =
    withdrawal, 0/0 = signing; 7 không đụng). `<coin>` = SLIP-44 của mạng (EVM 60).
  - **bn254:** cùng cấu trúc EIP-2333 với `r` của bn254 và salt **`"SCAAS-ZETHER-BN254-v1"`**; HKDF-Expand ra
    **48 byte** (L = ceil(3·ceil(log2 r)/16) = 48) rồi `mod r`, lặp nếu 0 — như EIP-2333. Đường
    `m/254/<coin>/<account>/7` (gốc 254 để không bao giờ chạm cây 12381).
  - Khoá phụ thuộc (seed, đường cong, mạng/coin, account). **Không** theo token (một UA mỗi (đường cong, mạng,
    account) — đúng SRS "đăng ký theo cặp (account, chain)"); đổi đường cong của verifier ⇒ cây khác ⇒ không tái
    dùng scalar.
  - Khoá xem/tiết lộ cho kiểm toán (`ITransferDisclosure`): `<use> = 8`, cùng hai cây — chưa dùng (Zether chưa xây).
- `y = g^x` (G1 của đường cong), `UA = keccak256(encodedY)` (`ZetherTypes.toUA`: bn254 64 byte `x‖y`, BLS12-381
  128 byte theo EIP-2537). **PoP** (SRS §7.5): Schnorr bằng `x` trên `c = keccak256(registry ‖ encodedY ‖
  account)` với `account` = account chủ thể (khoá ký) ⇒ ràng PoP vào khoá ký/account. *(Superseded → UA
  R294–R297: PoP ràng chain, registry, UA, authRef; Claude review L3: challenge hiện tại không có chain id,
  `UniversalAccountRegistry.sol:95-96` — registry dev-only, thay bằng registry UA.)*
- Lưu như seed: chỉ phía client, mã hoá khi nghỉ, không gửi Odoo/relayer.
- **Phạm vi:** *(superseded → R34: Zether built on dev chains)* luồng Zether on-chain vẫn hoãn (R1/§11 cho Zether giữ nguyên); round này ship thư viện dẫn xuất,
  vector, PoP, lưu trữ client.
- **Test:** vector EIP-2333 công bố (BLS12-381); vector bn254 tự sinh và ghim; cùng seed khác đường ⇒ khoá độc lập;
  `x` ≠ mọi scalar khoá ký của cùng seed; `y`/UA round-trip; PoP verify.

---

## D. Sáu hệ sinh thái

### D.0 Mô hình chung (mọi họ không phải EVM)

**Claude review M7 → spec gốc CR-PD-4:** họ xoá state lane đã dùng (TON, Aptos, Solana) chỉ giữ "thực thi tối
đa một lần" cho chữ ký anh em khi mọi chữ ký trên lane có `validUntil ≤ lần phát đầu + H` (H = 30 ngày) và độ trễ xoá
≥ H — quy tắc giao thức (CR-R3-8).

Lane relayer trên mạng có sequence tài khoản (Cosmos, Stellar, TON): trước mỗi job runner **đọc sequence đã
commit** của lane; tx gửi đi mang timebound/`valid_until` = hạn payload, nên tx chưa vào hết hạn cùng payload và
sequence không bị "treo" (review S14).

Ba mảnh on-chain như EVM:
1. **Token (tương đương META):** số dư do contract của ta giữ, thao tác `pay(from,to,amount,payRef)` phát
   `PaymentSettled{from,to,amount,payRef}`; **meta-tx cấp contract** (`relay(op, auth)`): kiểm chữ ký chủ thể trên
   payload tách miền, lane/nonce riêng contract, `validUntil`, `relayer` (tuỳ chọn ràng buộc). Allowance (nếu
   mạng có khái niệm này) chỉ cho spender là contract.
2. **Mandate:** như `MandateWallet` (R25): tiền nằm trong contract, delegate ký, hạn mức lần/kỳ, payee, hạn,
   thu hồi, mỗi `payRef` một lần.
3. **DEX:** hai chân ký, fill-or-kill, không allowance cho tài khoản thường (đúng mô hình EVM) — trừ TON (§D.5).

**Payload chuẩn `MetaOp` v1** (mã hoá theo họ, mọi trường bắt buộc):
`domain="scaas.metaop.v1" ‖ network ‖ contract ‖ op(pay|trade|mandate_pay|revoke) ‖ from ‖ to ‖ amount(u128) ‖
payRef(32) ‖ lane(32) ‖ nonce(u64) ‖ validUntil(u64, giây) ‖ relayer(tuỳ chọn) ‖ extra(hash 32 của tham số riêng op)`.
Không phí trên các mạng mới (fee NONE như portal — R10); phí relayer chỉ trên EVM. Op `trade`: tham số riêng
(token đối ứng, số tối thiểu, đối tác) đi **nguyên văn** cạnh `MetaOp` và `extra = H(tham số)` (review S28).

### D.1 Hedera (HSCS) — R63

- **SRS:** HSCS chạy EVM; tài trợ bằng payer account. Theo R30, đường payer-sponsored (tx tài khoản Hedera của
  chủ thể) **không** làm: nó là đúng loại khoá chủ thể. *(Superseded → net-hedera R6-1/R6-2: không
  `SubjectAccount` trên Hedera (`HederaMetaToken.sol:22-24`), relayer chạy `lane_runner`, không pipeline EVM
  (`adapters/hedera.rs:4-6`) — Claude review L2.)* Dùng lại **toàn bộ** contract Solidity (MetaToken,
  MandateWallet, MetaTxDex, SubjectAccount) trên HSCS, relayer = adapter EVM trỏ vào **Hedera JSON-RPC Relay**
  (chain id 295/296/298), lane = tài khoản ECDSA (coin 3030).
- **Khoá ED25519 của Hedera:** `HederaMetaToken is MetaToken` ghi đè `_requireValidSignature`: nếu `from` là địa
  chỉ long-zero/tài khoản Hedera không có ECDSA alias, kiểm qua precompile **HIP-632** `isAuthorizedRaw` (0x16a)
  — cách chính thức để contract kiểm chữ ký ED25519/ECDSA của một tài khoản Hedera. Khoá secp256k1 có alias EVM
  đi đường ECDSA như EVM. *(Claude review, wallet-formats M3: chỉ chữ ký ED25519 **thô** trên digest EIP-712 được
  nhận; HashPack/WalletConnect `hedera_signMessage` thêm tiền tố HIP-820 nên không dùng được — chủ thể ED25519 cần
  signer thô (clientkeys); `MandateWallet` của chủ ED25519 trả qua `executeAsOwnerRaw`, addendum CR-ADW-2.)*
- **HTS:** token HTS (ví dụ USDC trên Hedera) dùng qua **wrapper tầng 2** của `MetaToken` (approve cho contract
  wrapper — hợp lệ theo R26); allowance HTS ở cấp giao thức không ép được "chỉ contract" ⇒ ghi rủi ro, không dùng
  allowance HTS ngoài wrapper.
- HCS (nhật ký kiểm toán agent) và scheduled tx: SRS không bắt buộc cho thanh toán ⇒ ngoài phạm vi (HANDOFF).
- **Test:** forge (precompile 0x16a giả bằng `vm.etch`); e2e trên `hedera-local-node` nếu chạy được (cần ~8 GB
  RAM, nhiều container), nếu không: e2e EVM trên anvil `--chain-id 298` + ghi khoảng trống. *(`hedera-local-node`
  bị deprecate từ 2024-09, thay bằng `solo` — e2e mới nhắm `solo`; wallet-formats review L2.)*

### D.2 Sui (Move) — R64

- **Token:** `scaas::meta::Account<T>` — **shared object một chủ thể** giữ `Balance<T>`, khoá công khai (ed25519 /
  secp256k1 / secp256r1-passkey), bảng lane→nonce. Tạo bằng `open<T>(pubkey, scheme)` (kiểm địa chỉ =
  blake2b256(flag‖pk)), nạp bằng `deposit` (ai cũng nạp được). Shared object per chủ thể ⇒ tranh chấp chỉ trong
  phạm vi một chủ thể. Coin owned **không** chi được bởi người khác trên Sui, nên số dư phải nằm trong object
  của contract.
- **Một account mỗi (chủ thể, coin type):** `Registry` shared ánh xạ `(address, TypeName) → ID`; `open` thứ hai bị
  từ chối ⇒ không ai tạo account trùng để nhốt tiền (review S15).
- **Ký:** ví ký `signPersonalMessage(BCS(MetaOp))`; Move dựng lại digest = blake2b256([3,0,0] ‖
  bcs(vector<u8>)) và kiểm `ed25519_verify` / `secp256k1_verify(hash=SHA256)`; passkey: `secp256r1_verify` theo
  §C. Miền: `network` = chuỗi lưu trong `Config` (đặt lúc publish) + `object::id(account)` (khác nhau giữa mạng).
  **Claude review M4 → CR-R3-5:** khoá nằm trong từng `Account<T>` (`meta.move:93-105`) — xoay khoá trên một coin
  type để khoá cũ sống trên coin khác, và `dex::cancel/invalidate_nonces` nhận bất kỳ `Account<X>` của maker; từ rev
  1.1 khoá thuộc một object `Keys` mỗi chủ thể. **Wallet-formats review H1 → CR-WSF-1:** BCS qua
  `signPersonalMessage` là blob mù — xem ghi chú định dạng ví.
- **Relayer:** lane address gửi tx gọi `meta::relay_pay<T>(account, …, clock)`; mỗi lane một gas coin. Sponsored
  tx (SRS) chỉ dùng cho tx do **chủ thể** tự gửi (nạp tiền) — seam, không bắt buộc.
- **Mandate:** `Mandate<T>` shared object (như R25). **DEX:** `dex::settle<A,B>(acct_a, acct_b, leg_a, leg_b)` —
  hai chân ký, đúng mô hình EVM (relayer gửi một tx, nguyên tử).
- **Test:** `sui move test`; e2e trên `sui start --with-faucet` (localnet, binary trong `~/.local/bin`).

### D.3 Stellar Soroban (Rust) — R65

- **Meta-tx = Soroban authorization gốc**: auth entry `SorobanAddressCredentials{nonce ngẫu nhiên, hạn ledger}`
  ký bởi chủ thể **đã là** verifier cấp contract với nonce **không tuần tự** (mỗi (địa chỉ, nonce) một lần) và
  preimage tách miền (network id + contract + hàm + đối số). Không viết verifier thứ hai; relayer là source của tx
  (lane account, sequence riêng) và trả phí; **fee-bump** (CAP-15) dùng để một tài khoản phí trả cho nhiều lane
  account (đúng SRS). Ví: Freighter `signAuthEntry`; passkey: smart wallet `__check_auth` với `secp256r1_verify`.
  Chủ thể `G…` phải tồn tại trên ledger (yêu cầu của host) — ghi.
- **Token:** SEP-41 + `pay(from,to,amount,pay_ref)` (`from.require_auth()`, `pay_ref` một lần, storage
  persistent + gia hạn TTL) *(Claude review M2 → CR-R3-3: một lần **theo `(from, pay_ref)`**, không toàn cục —
  khoá toàn cục cho phép front-run `pay(attacker, …, 0, pay_ref)` đốt `pay_ref` của người trả; `amount > 0`)*; `approve` chỉ cho địa chỉ contract (`C…`). **Mandate**, **DEX** `settle(a, b)` với
  hai `require_auth_for_args` — đúng mô hình EVM.
- **Test:** `cargo test` (soroban-sdk testutils); e2e trên `stellar/quickstart` local (docker) qua `stellar` CLI.

### D.4 Cosmos (CosmWasm) — R66

- **Token** `scaas-token` (CW20 + meta-tx): `Relay{op, pubkey, signature, scheme}`. Ký: Keplr/Leap
  `signArbitrary` (ADR-036) trên bytes JSON của `MetaOp`; contract dựng lại sign doc ADR-036, `sha256`,
  `secp256k1_verify`, địa chỉ = bech32(ripemd160(sha256(pk))) phải bằng `from`; passkey: `secp256r1_verify` với bộ giải
  WebAuthn riêng (không qua ADR-036). *(Claude review H1 → CR-R3-1: bộ giải hiện chỉ kiểm cờ UP, `type` và
  challenge bằng `contains` (`cosmos/metaop/src/lib.rs:130-148`) — không rpIdHash, origin, UV, low-s; địa chỉ
  passkey v2 ràng `(pk, rpIdHash, origin)`.)* Sign doc ADR-036 dựng bằng **khuôn byte cố định** (khoá đã sắp, không khoảng
  trắng) với `chain_id: ""` đúng ADR-036 (review S7, S24). Miền nằm **trong payload**: `MetaOp.network` phải bằng
  `env.block.chain_id`, `MetaOp.contract` bằng `env.contract.address`. `IncreaseAllowance` chỉ cho spender là contract
  (`query_wasm_contract_info` thành công), `TransferFrom` chỉ khi `info.sender` là contract.
- **Relayer:** lane account gửi `MsgExecuteContract` (sequence riêng lane). **feegrant** chỉ dùng cho tx chủ thể
  tự gửi (nạp native denom vào wrapper) — seam. **authz** không dùng: grantee là relayer (tài khoản thường) vi phạm
  bất biến owner; grantee là contract không cần vì tiền nằm trong contract.
- **Mandate** (nạp CW20 qua `Receive`), **DEX** hai chân ký đi qua token (chân giới hạn `relayer = to = DEX`).
- **Test:** `cw-multi-test`; e2e trên `wasmd` (docker `cosmwasm/wasmd`).

### D.5 TON (Tact) — R67

- **Ngôn ngữ: Tact** (npm, test bằng `@ton/sandbox`; FunC thấp hơn một bậc không đáng cho phạm vi này).
- **Token:** Jetton (TEP-74) với **jetton wallet tuỳ biến** giữ thêm `owner_pubkey` và bảng lane/nonce;
  `SignedTransfer{MetaOp, signature}` (relayer gửi internal message kèm TON cho gas) được jetton wallet kiểm bằng
  `checkSignature`. Gắn pubkey: `BindKey{walletStateInit}` *(superseded → lazy bind trong `SignedOp.stateInit`,
  `jetton.tact:209-212`)* — jetton wallet kiểm
  `contractAddress(stateInit) == owner` và đọc pubkey từ data của W5R1/V4R2 (không cần chủ thể gửi tx). Ký: TON
  Connect `signData` (kiểu `cell`) — verifier dựng lại **đúng phong bì** signData (prefix, domain, timestamp,
  địa chỉ) quanh cell `MetaOp` rồi mới kiểm (review S10) *(R10-3: domain chỉ kiểm off-chain; Claude review M6 →
  CR-R3-7: domain phải thuộc tập domain lưu on-chain của jetton wallet, vì ai cũng relay được `SignedOp`)*; `MetaOp` là **cây cell** (gốc + ref) vì một cell chỉ
  1023 bit (review S11). Miền: `network_id` (global id) lưu ở master + địa chỉ jetton wallet.
- **Relayer:** lane wallet W5 của relayer (seqno riêng lane) gửi internal message. W5 "gasless" của **chủ thể**
  không dùng (seqno chủ thể = khoá — R30).
- **DEX:** mô hình actor bất đồng bộ không có nguyên tử giữa contract ⇒ **escrow**: chân A (ký) đến DEX giữ chờ
  chân B khớp; hết hạn/không khớp ⇒ hoàn. `Refund(order)` **không cần quyền** sau hạn (relayer có cron, relayer
  khác cũng gửi được; gas trả từ TON đi kèm lệnh) (review S8). Fill-or-kill theo nghĩa: lệnh khớp đủ hoặc hoàn toàn bộ.
- **Test:** `@ton/sandbox` (jest). Node local TON (MyLocalTon) nặng ⇒ adapter test bằng vector BOC; ghi khoảng trống.

### D.6 Odoo và portal theo họ

- Ví nhận/ví trả theo (công ty, mạng, tài sản) cho mọi họ (§B.4 địa chỉ).
- Portal: connector theo họ, **chỉ nạp khi người trả chọn mạng đó**: EVM/Hedera — EIP-6963 (đã có); Sui — Wallet
  Standard (giao thức sự kiện `wallet-standard:*`, không thư viện); Cosmos — `window.keplr`/`window.leap`
  `signArbitrary` (không thư viện); Stellar — Freighter (`@stellar/freighter-api` bản ghim, vendored, nạp lười);
  TON — TON Connect (`@tonconnect/sdk` ghim, vendored, nạp lười); Hedera HashPack/WalletConnect — seam (R21).
  Passkey (§C) là lựa chọn ở mọi họ có account hỗ trợ passkey.
- Test tour với connector giả theo họ; thư viện vendored không chạy được trong CI không có ví thật ⇒ ghi.

---

## E. Rulings mới

- **R30** (owner) Meta-tx cấp contract là đường mặc định trên mọi mạng; sequence của chủ thể không bao giờ là khoá
  thứ tự; tài trợ gốc chỉ cho relayer; nhiều lane relayer. Thay R1.
- **R31** (owner) Passkey WebAuthn P-256 cho chủ thể portal/mobile; batch Merkle; vòng đời khoá qua account/registry.
  *(Amended → CR-R3-1 one WebAuthn grammar; CR-R3-6 lifecycle per family; salt, gas, signature encoding superseded, §H.4.)*
- **R33** *(PoP superseded → UA R294–R297; "on-chain hoãn" superseded → R34.)* (owner) Khoá Zether conf từ seed, đường riêng (EIP-2333 BLS12-381 `m/12381/<coin>/<acct>/7`, bn254 kiểu EIP-2333 salt riêng `m/254/<coin>/<acct>/7`), PoP ràng vào account; Zether on-chain vẫn hoãn.
- **R32** *(scrypt superseded → S4F R259; account key path → UA R300 / S4F R269.)* (owner) Ví seed words phía client (24 từ, không rời thiết bị, AES-GCM bọc bằng PRF/scrypt); account chủ thể nhiều khoá (passkey + seed).
- **R50** Custody `env:` chỉ dev (cờ + chain dev); ký qua `cryptography` (OpenSSL).
- **R51** `/readyz` + `/metrics` trên cổng quản trị riêng; số liệu Odoo qua `relay_stats`.
- **R52** CI blockchain riêng; `lib/` forge cài theo tag ghim.
- **R53** `paused` chỉ chặn gửi; `halted` chặn cả indexing.
- **R54** Gateway auth `bearer|hmac`; `none` chỉ trên loopback; proptest cho decoder.
- **R55** Cầu dao: spike base fee, ngân sách gas theo giờ, sàn số dư lane; không chặn indexing.
- **R56** Journal theo (công ty, token) company-dependent; drift A (Transfer không khớp) + drift C (số dư vs GL).
- **R57** Seam công ty nhận/quản trị ví duy nhất; "Host" ⇒ "platform company".
- **R58** `ChainAdapter`; EVM giữ runner riêng; mạng khác dùng `lane_runner` một-tx-mỗi-lane. *(Family enum superseded → eight families; trait drift L6.)*
- **R59** `Signer` secp256k1/ed25519 cục bộ; KMS là seam.
- **R60** Khoá: khoá thô hoặc mnemonic 24 từ; đường dẫn theo bảng §B.3; keystore Web3 v3 cho cả hai đường cong.
- **R61** Họ mạng trong Odoo; địa chỉ chuẩn theo họ; `blockchain.signed.op`; Odoo kiểm ed25519, còn lại node mô phỏng.
- **R62** Bảng tránh head-of-line §B.5 + test anti-lock mỗi mạng. *(Amended → MESH R77: Soroban excluded from mesh v1.)*
- **R63** Hedera = Solidity trên HSCS qua JSON-RPC relay + HIP-632 cho ED25519; không đường payer-sponsored. *(Amended → net-hedera R6-1/R6-2; ED25519 needs raw signing, CR-ADW-2.)*
- **R64** Sui = Account<T> shared per chủ thể + personal-message; DEX hai chân. *(Amended → CR-R3-5 `Keys` per subject; CR-WSF-1 readable message.)*
- **R65** Soroban = auth gốc làm meta-tx; fee-bump cho lane; DEX hai `require_auth`. *(Amended → CR-R3-3 `pay_ref` per `(from, pay_ref)`, amount > 0.)*
- **R66** Cosmos = CW20 + ADR-036; không authz; feegrant chỉ là seam. *(Amended → CR-R3-1 passkey v2; CR-R3-2 quorum; CR-R3-10 no `Sweep`.)*
- **R67** TON = Tact, jetton wallet tuỳ biến có pubkey + `BindKey`; DEX escrow. *(`BindKey` superseded → lazy bind; amended → CR-R3-7 domain set, CR-R3-9 bounced payouts.)*

---

## F. Quyết định owner thêm trong ngày (chi tiết ở tài liệu của từng luồng)

- **R34** (owner) **Zether đầy đủ** — thay phần loại trừ Zether của R1/§11. Contract (`ZetherToken` clone qua factory,
  verifier bn254 + BLS12-381, ElGamal `acc/pending`, hai chế độ `rollOver`, fund/transfer/burn, Bulletproofs đúng hai
  range statement n_v=32, n_b=64, DECRYPT_BOUND=2^40, ràng phong bì meta-tx §7.7, phí scalar công khai §7.4,
  `ITransferDisclosure`, `UniversalAccountRegistry` 8 kiểu + PoP §7.5), prover Rust → WASM, relayer, Odoo (yêu cầu
  thanh toán bảo mật, đối soát từ số tiền được tiết lộ, khoá xem kiểm toán theo công ty), portal chứng minh phía
  client. **Test bắt buộc** (owner sửa đổi). **UNAUDITED — NOT FOR PRODUCTION FUNDS**: cờ factory/deploy tắt mặc
  định trên chain không phải dev; thông báo trong NatSpec, HANDOFF, form chain/token Odoo. Mạng không phải EVM: chỉ
  ghi khả thi. Thiết kế chi tiết + đặc tả transcript: `2026-10-03-zether-design.md`.
- **R35** *(Book location settled: built in Odoo; NI R105 store-backed, SPECIFIED.)* (owner) **DEX hoàn chỉnh**: sổ lệnh off-chain **bền** (lưu ở Odoo hay SQLite — luồng DEX chọn và ghi),
  thị trường theo cặp, ưu tiên giá-thời gian, limit + IOC/FOK, khớp một phần, hạn ký, huỷ bằng chữ ký off-chain +
  vô hiệu nonce on-chain qua meta-tx, API đọc công khai; contract thanh toán kiểm **hai** lệnh ký EIP-712, giới hạn
  giá, `filled[orderHash]`, gom nhiều cặp một tx (nguyên tử từng cặp), DEX là spender duy nhất (R26), lane/nonce
  riêng (R30); hai phí độc lập: phí DEX bật/tắt theo thị trường (ppm maker/taker, trần 1 %, nằm trong lệnh ký) và
  phí relayer theo mode meta-tx hiện có; mọi hành động người dùng là meta-tx; Odoo: cấu hình thị trường, xem sổ, hạch
  toán phí. Thiết kế chi tiết: `2026-10-03-dex-design.md`.

## G. Review log

### Antigravity (agy) — review thiết kế round 3, 2026-10-03 — 28 finding

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| S1 | crit | **Sai**: nonce của `SorobanAddressCredentials` là i64 bất kỳ do người ký chọn; host ghi cặp (địa chỉ, nonce) đã dùng tới hạn chữ ký — không tuần tự | Từ chối; test anti-lock Soroban trên quickstart chứng minh |
| S2 | crit | Chưa chắc (HIP-632 `isAuthorizedRaw`) | Chờ kiểm trên hedera-local-node/testnet; không có thì tài khoản ED25519 dùng `SubjectAccount` với khoá seed ECDSA — ghi ở luồng Hedera |
| S3 | crit | Đúng | Nhận: `SubjectAccountFactory` CREATE2 + job deploy trước |
| S4 | crit | **Sai**: OZ 5.2 `P256.verify` gọi precompile rồi `verifySolidity` (`P256.sol:61,102`) | Từ chối |
| S5 | crit | Đúng | Nhận: client giải DER + chuẩn hoá low-s |
| S6 | crit | Mâu thuẫn với hiểu biết của ta (TVM có `P256_CHKSIGNU/S`) | Kiểm bằng biên dịch + sandbox |
| S7 | crit | Đúng về ADR-036 (`chain_id: ""`) | Nhận: miền nằm trong payload |
| S8 | crit | Đúng | Nhận: `Refund` không cần quyền |
| S9 | high | **Sai**: SLIP-0044 3030 = HBAR | Từ chối |
| S10, S11 | high | Đúng | Nhận |
| S12 | high | Đã có `validUntil` trong `MetaOp` + hạn ledger của auth entry | Ghi rõ |
| S13 | high | **Sai**: `v` tìm bằng `ecrecover` thuần Python trên dữ liệu công khai (đã làm, `custody.openssl_sign`) | Từ chối |
| S14 | high | Đúng một phần | Nhận: đọc sequence đã commit + timebound = hạn payload |
| S15, S16, S17 | high | Đúng | Nhận |
| S18 | high | **Sai**: pubkey trong tin nhắn không được ràng vào chủ — kẻ gian ký bằng khoá của mình | Từ chối; giữ `BindKey` (chứng minh bằng stateInit) |
| S19, S20 | med | Đúng | Nhận |
| S21 | med | **Sai**: Sui ký secp256k1 trên SHA-256 của digest blake2b ⇒ `secp256k1_verify(..., hash=SHA256)` trên digest blake2b là đúng | Từ chối; e2e localnet chứng minh |
| S22 | med | Đúng (tài khoản Hedera phải tồn tại) | Nhận: kiểm lúc khởi động + bước vận hành |
| S23, S24, S25, S26 | med/low | Đúng | Nhận |
| S27 | low | Job hết hạn là fail-safe (người trả ký lại) | Từ chối điều tiết thích ứng; trạng thái cầu dao lộ qua metric |
| S28 | low | Đúng | Nhận |

Grok: giới hạn quota (lần 8). Codex: không chạy (hết credit).

---

## H. Claude review 1 (2026-10-07) — disposition (rev 1.1)

Source: `docs/reviews/specs/2026-10-03-blockchain-round3-design-claude-review-1.md` (verdict FIX-THEN-GO). Each
finding re-checked against the cited code on 2026-10-07 (`scaas` 991d835, `bamboo-dms` b724c91). Owner rule: docs
only — a code bug becomes a ruling (fix + tests) here and a stream in §H.6; nothing is built. Ruling ids `CR-R3-n`
are local to this spec. Solana and Aptos details live in the net-* specs, which this revision does not edit: the
needed amendments are recorded in §H.5.

### H.1 Claude review disposition

| # | Sev | Verified against code | Disposition |
|---|---|---|---|
| H1 | high | Confirmed: Cosmos passkey checks only `ad[32] & 0x01`, and `type`/challenge by substring (`cosmos/metaop/src/lib.rs:130-148`); account = `sha256(tag ‖ pk)[..20]` (`:89-94`). Other families check rpIdHash + origin + UP + UV (`SubjectAccount.sol:270-303`, `move/aptos/sources/auth.move:89-108`, `move/sui/sources/auth.move`, `soroban/contracts/account/src/lib.rs`, `ton/contracts/common.tact:325-356`, `solana/programs/scaas/src/auth.rs:175-223`). | **Accepted** → CR-R3-1; R3-FIX1 |
| H2 | high | Confirmed: events from the primary only on EVM/Hedera (`indexer.rs:131,142`), Sui (`adapters/sui.rs` `rpc` = `rpcs[0]`), Solana (`adapters/solana.rs:710`), Soroban; quorum only on the head hash (`sui.rs:751`, `solana.rs:1014-1025`, `soroban.rs:400-411`); Cosmos `final_head` single endpoint (`adapters/cosmos.rs:522-531`), TON one `masterchainInfo` (`adapters/ton.rs:1217-1223`); `config.rs:505-506` still accepts `quorum > 1` for them. Aptos agrees per transaction across the quorum (`adapters/aptos.rs:555-572`). | **Accepted** → CR-R3-2; R3-FIX3, R3-FIX4 (EVM/Hedera: PAY-FIX3) |
| H3 | high | Confirmed: Aptos `upgrade_policy = "compatible"` (`move/aptos/Move.toml:4`), `deploy-object` (`move/aptos/scripts/devnet.sh:45`); Sui `sui client publish` keeps the UpgradeCap (`smartcontracts/scripts/deploy.sh:9`); Solana keeps `--upgrade-authority` (`solana/scripts/deploy.sh:10-11,31`). | **Accepted — owner ruling CR-R3-11** (immutable at deploy, §H.3; rev 1.2); R3-FIX15 |
| M1 | med | Confirmed: `crossOrigin` rejected on EVM (`SubjectAccount.sol:288-303`) and Aptos (`auth.move:99`) only; TON accepts anything after the stored origin prefix (`common.tact:349`); Sui, Soroban, Solana (`auth.rs:184-192`) do not look. | **Accepted** → CR-R3-1; R3-FIX2 |
| M2 | med | Confirmed: `Key::PayRef(pay_ref)` global (`soroban/contracts/token/src/lib.rs:198-216`); `check_amount` accepts 0 (`:113-117`); Cosmos avoided it on purpose (`cosmos/token/src/lib.rs:103-105`). | **Accepted** → CR-R3-3; R3-FIX5 |
| M3 | med | Confirmed: `initialize(network, admin)` stores any 32 bytes (`solana/programs/scaas/src/account.rs:28-34`). Mitigated for our node only: it compares RPC `getGenesisHash` with the configured network and `Config.network` (RS12-8, `adapters/solana.rs:724-740`); third-party relayers are not bound. | **Accepted** → CR-R3-4; R3-FIX6 |
| M4 | med | Confirmed: keys, origins, guardian per `Account<T>` (`move/sui/sources/meta.move:93-105`); `dex::cancel`/`invalidate_nonces` take any `Account<X>` of the maker (`dex.move:275-294`). | **Accepted** → CR-R3-5; R3-FIX7 |
| M5 | med | Confirmed: Cosmos passkey = one key, no rotation (`metaop/src/lib.rs:89-94`); Soroban guardian is a seam (`account/src/lib.rs:1-4`); TON: a passkey cannot rotate keys (`jetton.tact:219`), no guardian. | **Accepted** → CR-R3-6 (gaps stated per family); R3-FIX8…10 |
| M6 | med | Confirmed: `checkTonConnect` hashes the relayer-supplied domain and timestamp without checking them (`common.tact:264-272`); any sender may relay a `SignedOp` (`jetton.tact:202-206`). | **Accepted** → CR-R3-7; R3-FIX11 |
| M7 | med | Confirmed (same as spec gốc M2). | **Accepted** → spec gốc CR-PD-4; here CR-R3-8; R3-FIX12 |
| L1 | low | Confirmed (Merkle on `SubjectAccount.sol:257`, Soroban only). | **Accepted** (doc): §C.3 note; batching elsewhere is a feature, not a stream |
| L2 | low | Confirmed (`hedera/HederaMetaToken.sol:22-24`, `adapters/hedera.rs:4-6`). | **Accepted** (doc): §D.1 marker; §B.5 row "EVM/Hedera" reads "EVM" for the pipeline, Hedera = `lane_runner` |
| L3 | low | Confirmed (`registry/UniversalAccountRegistry.sol:95-96`). | **Accepted as superseded**: no fix — dev-only registry replaced by the UA registry (R294–R297) |
| L4 | low | Confirmed: `bounced(JettonTransfer)` → `addFee` (`ton/contracts/dex.tact:131-136`), withdrawn by `WithdrawFees` (`:43,158`). | **Accepted** → CR-R3-9; R3-FIX13 |
| L5 | low | Confirmed: admin `Sweep` (`cosmos/dex/src/lib.rs:137-143`). | **Accepted** → CR-R3-10; R3-FIX14 |
| L6 | low | Confirmed (`scaas-node/src/adapter.rs`). | **Accepted** (doc): §B.1 note |
| L7 | low | SCaaS §9.6: kind is an operator label, not stored. | **Accepted** (doc): §B.3 keystore `"scaas": {"kind"}` superseded (§H.4) |
| Superseded table (13 rows) | — | Spot-checked: scrypt `N = 2^17` (`clientkeys/src/vault.js:14`), salt (`SubjectAccountFactory.sol:21-23`), 400 k by codehash (`MetaToken.sol:141-144`), lazy bind (`jetton.tact:209-212`). | **Accepted**: §H.4 + inline markers |

Rejected: none. Counts: 3 high, 7 medium, 7 low, 1 table — 18 accepted (H3 by owner ruling CR-R3-11, rev 1.2),
0 rejected.

### H.2 Rulings

- **CR-R3-1** **One WebAuthn rule and one grammar for every family** (H1, M1; wallet-formats M2, L4; infra-service
  M1). Every passkey verifier checks, in order: `authenticatorData` ≥ 37 bytes; `rpIdHash` == the stored one; flags
  UP **and** UV; `clientDataJSON` matches exactly `{"type":"webauthn.get","challenge":"<b64url(digest)>","origin":"`
  + origin + `"` followed by either `}` (end of input) or `,"crossOrigin":false` followed by `}` (end) or `,`
  (EVM `_clientDataOk`, `SubjectAccount.sol:283-303`); the origin bytes equal a stored origin **exactly** (no prefix
  match — TON's `common.tact:349` accepts `https://a.example.evil`); `s ≤ n/2` (Cosmos adds the check before
  `secp256r1_verify`); P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))`. Shared vectors
  `smartcontracts/test/vectors/webauthn_kat.json` (accept cases from Safari L2 and Chrome/Firefox L3 shapes; reject
  cases: `crossOrigin:true`, `topOrigin`, a member before `crossOrigin`, whitespace, origin extended by a suffix,
  wrong rpIdHash, UV unset, high-s, challenge of another digest) run in every family's test suite.
  **Cosmos passkey v2:** the account is `sha256("scaas.passkey.v2" ‖ pk65 ‖ rpIdHash ‖ sha256(origin))[..20]`; the
  verifier reads rpIdHash from `authenticatorData` and the origin through the grammar, derives the account and
  requires it to equal `from`, so rpId and origin are bound without storage. One `(rpId, origin)` per Cosmos
  passkey account; v1 addresses (dev chains only) are no longer accepted. — Why: on Cosmos any page that can get
  an assertion for the rpId (sibling subdomain, related origin, delegated iframe) signs any `MetaOp`; elsewhere a
  cross-origin iframe yields assertions carrying the RP's origin. — Cost: Cosmos dev passkey addresses change.
- **CR-R3-2** **Cross-provider event verification on every family** (H2; infra-service H2). The universal rule:
  `final_head` = the minimum height reported by ≥ `quorum` endpoints, with the same block/ledger/checkpoint hash at
  that height; `events(from, to)` is evaluated against ≥ `quorum` endpoints and must return the **same normalised
  list** (the adapter's own output, so one comparison serves every family); disagreement ⇒ no ingest, warning,
  `/readyz` red. Per family: EVM/Hedera — `eth_getLogs` (spec gốc CR-PD-2); Aptos — built (per-tx agreement,
  `adapters/aptos.rs:555-572`; the Indexer-API hint may omit transactions, which only delays booking); Sui — event
  query per checkpoint range; Solana — per-signature transaction (`emit_cpi` inner data) agreement; Soroban —
  `getEvents` per ledger range; **Cosmos and TON honour the configured quorum** (no longer a single endpoint):
  Cosmos `status` + `block` at the min height and the tx events of that range, TON `masterchainInfo` + the jetton
  wallets' transactions of the range, each from ≥ `quorum` endpoints. `quorum = 1` is single-provider trust and is
  reported as such (gauge `scaas_finality_quorum{chain}`). — Why: one dishonest provider can book an unpaid order
  (it learns `pay_ref`/`to`/`amount` from our simulate calls). — Cost: `quorum ×` reads per range.
- **CR-R3-3** **Soroban `pay_ref` is one-shot per `(from, pay_ref)` and `pay` moves a positive amount** (M2):
  `Key::PayRef(from, pay_ref)`; `ref_used(from, pay_ref)`; `pay` with `amount ≤ 0` ⇒ `Error::ZeroAmount`; the mandate
  path keys by the mandate's address automatically. Odoo already sums settlements per `entry_ref` + receiver, so a
  stranger's payment with someone else's ref is only money in. — Tests: attacker `pay(attacker, receiver, 0 or 1,
  victim_ref)` then the victim's signed `pay` ⇒ succeeds; same `from` twice ⇒ `RefUsed`; amount 0 ⇒ `ZeroAmount`.
- **CR-R3-4** **The Solana signing network is read from the chain, not typed by an admin** (M3; wallet-formats M4;
  consistent with UA R330 `chain_uid`). The Solana runtime exposes no genesis hash (no syscall, no sysvar), so the
  program takes it at **build** time: `deploy.sh` reads `solana genesis-hash --url <cluster>` and builds the program
  with `SCAAS_NETWORK` = that hash next to `SCAAS_PROGRAM_ID`; `initialize` loses its `network` argument and stores
  the constant; `deploy.sh` records `(program id, genesis hash)` in the deployments file and refuses to deploy a
  program id already recorded for another genesis. The chain profile's `chain_uid` (UA R330) for Solana **is** the
  genesis hash as the RPC reports it; the node keeps RS12-8 (RPC genesis == `chain_uid` == `Config.network`, refuse
  to run otherwise). — Why: today a Config initialised with another cluster's hash makes that cluster's signatures
  valid here for the same PDA, for any relayer. — Cost: one build per cluster (already one per program id).
- **CR-R3-5** **Sui keys belong to the subject, not to a coin type** (M4). A shared `Keys` object per subject
  (owner, keys, origins, guardian, recovery, `key_nonce`, policy) is created by the first `open`; every
  `Account<T>` stores its `Keys` id; `verify_by`, `manage` and recovery take `&Keys`; `dex::cancel` and
  `invalidate_nonces` take the maker's `&Keys` (`order.maker == keys.owner`). A struct-layout change is not a
  `compatible` upgrade, so this is a fresh package publish on dev chains (no production deployment exists), and
  under CR-R3-11 every publish is a fresh, immutable one anyway. — Tests: rotate a key on `Keys` ⇒ the old key fails on `Account<USDC>` and `Account<SUI>`
  and cannot cancel orders on any market.
- **CR-R3-6** **Key lifecycle is stated per family; gaps are streams** (M5; infra-service M3). SCaaS §9.4
  "equivalents per family" reads:

  | Family | Rotation | Guardian / recovery | Gap |
  |---|---|---|---|
  | EVM | `SubjectAccount` add/remove/rotate via `executeAsOwner` | guardian + `RECOVERY_DELAY` | — |
  | Hedera | native account key update (no `SubjectAccount`, R6-2) | native | — (stated) |
  | Aptos | account keys + origins (`move/aptos/sources/meta.move`) | guardian + `RECOVERY_DELAY` (`meta.move:38,65`) | — |
  | Sui | per `Account<T>` today → per subject (CR-R3-5) | guardian per `Account<T>` (`meta.move:33,61`) | R3-FIX7 |
  | Soroban | account-authorised add/remove | **seam only** (R8-2) | R3-FIX8 |
  | Cosmos | **none** (passkey address = hash of key + rp + origin) | **none** | R3-FIX9 (passkey account contract: design + impl) |
  | TON | wallet key follows the owner's wallet; **a passkey cannot rotate** (`jetton.tact:219`) | **none** | R3-FIX10 (guardian + delayed passkey rotation) |
  | Solana | KeyOp add/remove/policy | `start_recovery`/`finish_recovery` (`account.rs:380-399`) | — |

- **CR-R3-7** **TON binds the signData `domain` on chain** (M6; wallet-formats M1). Each jetton wallet stores
  `domains` (set of `sha256(domain)`), initialised at lazy bind from the master's deploy-time `defaultDomains`
  (immutable data, no admin) and changed only by `SetDomains` sent **by the owner's own wallet** (`sender() ==
  owner`: a wallet transaction the user sees, not a signData). `AUTH_TONCONNECT` requires `sha256(domain) ∈
  domains` and `timestamp ≤ now() + 300`; an empty set refuses TON Connect auth (passkey still works). — Why: any
  sender may relay a `SignedOp`, so the off-chain domain check (R10-3) never runs when a phishing dApp relays its
  own. — Tests: sandbox — phishing domain ⇒ `E_AUTH`; listed domain ⇒ ok; `SetDomains` from a non-owner ⇒ refused.
- **CR-R3-8** **Lane pruning keeps pay-once only under the horizon rule** (M7) — ruled in spec gốc CR-PD-4. Stream
  R3-FIX12 pins the constants equal in tests (TON `LANE_TTL`, Aptos/Solana `PRUNE_DELAY_S`, node `LANE_TTL_S`, Odoo
  `LANE_HORIZON_S`) and makes the node refuse `max_valid_for_secs > LANE_HORIZON` on pruning families.
- **CR-R3-9** **TON DEX bounced payouts belong to the user, not to the fee pot** (L4). Every payout/refund carries
  a unique `queryId`; the DEX keeps `payoutOf[queryId] = (owner, master, amount)` until the bounce window passes
  (pruned after one day); `bounced(JettonTransfer)` credits `unclaimed[(owner, master)]`; `Claim{master}`
  (permissionless, gas paid by the caller, tokens to the owner) resends; `WithdrawFees` withdraws only fees. —
  Tests: sandbox — a bounced refund lands in `unclaimed`, `WithdrawFees` cannot take it, `Claim` pays the owner.
- **CR-R3-10** **The Cosmos DEX has no `Sweep`** (L5): the DEX never holds balances between transactions, as on
  EVM ("no owner, no sweep"); tokens sent to it directly are lost as on EVM. Admin keeps `SetMarket` only. —
  Tests: `Sweep` no longer in the message enum; settle/cancel tests unchanged.

### H.3 Owner ruling CR-R3-11 — the Aptos, Sui and Solana programs are immutable at deploy (review H3)

- **CR-R3-11** (owner, 2026-10-07: *"Bất biến ngay khi deploy"*) **Every program that holds subject value is
  immutable from the moment it is deployed**, as SCaaS §1.2/§1.3 state and as EVM already is (non-upgradeable
  clones). A bug fix = deploy a new version + voluntary migration (SCaaS §4.3), never an in-place upgrade.
  - **Aptos:** `Move.toml` `upgrade_policy = "immutable"`; the package registry at the package address reports
    policy immutable.
  - **Sui:** `0x2::package::make_immutable(UpgradeCap)` in the same deploy run, right after `sui client publish`;
    the UpgradeCap object no longer exists.
  - **Solana:** deploy with a temporary authority, run `initialize` (its `Initialize` accounts require the upgrade
    authority, `account.rs:16-26`; with CR-R3-4 it no longer takes `network`), then
    `solana program set-upgrade-authority <id> --final`; `solana program show <id>` reports `Authority: none`.
    Config cannot be re-created afterwards (PDA `init` + no authority).
  - **Cosmos** follows from SCaaS §1.3 ("no proxy upgrade on any contract that holds value"): instantiate with
    `--no-admin` when the instantiation tooling lands. TON and Soroban as built are already immutable.
  - **Deploy-script gate:** `smartcontracts/scripts/deploy.sh` (aptos, sui) and `solana/scripts/deploy.sh` end with a
    check that **fails the run (non-zero exit) if the deployed program is still upgradeable** — Aptos registry
    policy ≠ immutable, Sui UpgradeCap still present, Solana `Authority` ≠ none, Cosmos contract admin ≠ empty.
    Local test validators are not exempt (the gate is the same everywhere, so tests exercise it).
  - **Existing dev deployments** (upgradeable, single key) are abandoned and redeployed immutable; chain profiles in
    the node and Odoo get the new package/program ids (dev funds only).
  - Why: a held upgrade key lets one server-side key publish a `drain` entry over the stored `ExtendRef`/PDA seeds
    for every subject on that chain — the IaaS/BaaS failure mode SCaaS exists to remove. — Cost: no hotfix in place;
    a fix needs a new deployment and migration of balances by their owners.
  - Tests: each deploy script run against its local network ends green only when the gate passes; a negative test
    (skip the freeze step) makes the gate fail; Solana `initialize` after `--final` fails.
  - Stream: **R3-FIX15**.

History (rev 1.1, kept for the record — superseded by CR-R3-11): Q1 was left open with options (a) immutable after
audit, (b) multisig + timelock, (c) single key for dev with a production gate. Facts, verified: the Aptos package is
`upgrade_policy = "compatible"` (`move/aptos/Move.toml:4`) published with `deploy-object`, so the code object's
owner can publish an upgrade, and the package holds the `ExtendRef` of Root and of every subject `Account`; Sui is
published with `sui client publish` and the UpgradeCap stays with the publisher (`smartcontracts/scripts/deploy.sh:9`),
nothing calls `make_immutable`; Solana keeps an upgrade authority (`solana/scripts/deploy.sh:10-11,31`, "Production:
move the upgrade authority to a multisig"); Cosmos `--admin` (migrate) is undecided because instantiation tooling
is PLANNED. TON code and Soroban contracts as built are immutable; EVM tokens are non-upgradeable clones. Whoever
holds one of those keys can publish a compatible upgrade with a `drain` entry using the stored `ExtendRef`/PDA
seeds, which contradicts SCaaS §1.2 ("nobody without the subject's private key"), SCaaS §1.3 ("no proxy upgrade on
any contract that holds value"), §0 principle 4 here and the infra-service table, while the net-* specs (RS11-13)
ruled "upgrade compatible, multisig in production".

| Option | What it means | Consequence |
|---|---|---|
| **(a) Immutable after audit** | Aptos `upgrade_policy = "immutable"` (or freezing the code object), Sui `package::make_immutable(UpgradeCap)`, Solana `solana program set-upgrade-authority --final`, Cosmos instantiated without `--admin` | Matches SCaaS §1.2/§1.3 as written; a bug fix is a new package plus voluntary migration (SCaaS §4.3) |
| **(b) Upgrade authority = multisig + timelock** | Aptos code object owned by a multisig account behind a timelock; Sui UpgradeCap held by a timelocked multisig policy object restricted to compatible upgrades, emitting a public "upgrade scheduled" event; Solana upgrade authority = a multisig with a time lock; the delay (e.g. ≥ 7 days) is public | The key becomes an explicit trust root that SCaaS §1.2/§1.3 and the infra-service table must list; subjects get the delay to exit |
| **(c) Single key for dev only, production gate** | Keep today's single key on dev chains; the node refuses to activate a non-dev chain whose program authority is a single key (Aptos object owner, Sui UpgradeCap owner, Solana ProgramData authority are read at chain activation), and the deploy scripts refuse public clusters with one | Nothing changes for dev; production cannot start in the unsafe state |

Rev 1.1 recommended (b) until the audit, then (a). **The owner chose immutability at deploy (CR-R3-11)**, which
also makes the (c) production gate unnecessary: the deploy-script gate refuses an upgradeable result on every
network. Amended text: §0 principle 6 here; net-aptos/net-sui/net-solana RS11-13 and SCaaS §7.5 recorded in §H.5.

### H.4 Superseded rulings and statements

| R3D text | Superseded by |
|---|---|
| "Sáu hệ sinh thái"; R58 `Family {Evm, Hedera, Sui, Soroban, Cosmos, Ton}` | owner 2026-10-06 family taxonomy (+Aptos, Solana; Hedera ⊂ EVM) |
| R32 scrypt `N = 2^15`, PIN | S4F R259: `N = 2^17`, passphrase ≥ 8 chars (`clientkeys/src/vault.js:14,40-45`) |
| R31 factory salt = hash(first key) | `keccak256(abi.encode(firstKey, guardian))` (`SubjectAccountFactory.sol:21-23`) |
| R31 ERC-1271 gas 50 k → 400 k for all | 400 k only for `SubjectAccount` clones by codehash (`MetaToken.sol:141-144`) |
| R31/§C.3 signature `abi.encode(keyIndex, payload)` | `abi.encode(keyIndex, bytes32[] proof, bytes sig)` (RS4-3) |
| R33 "Zether on-chain vẫn hoãn" | R34 (Zether built on dev chains) |
| R33 PoP bound to the caller account | UA R294–R297 (PoP binds chain, registry, UA, authRef; relayable) |
| §C.2/§C.3 seed keys `m/44'/60'/0'/0/i` for accounts | UA R300 / S4F R269 role tree `m/7622'/…` (SPECIFIED; addendum CR-ADW-3) |
| R63 "reuse SubjectAccount/pipeline on Hedera" | net-hedera R6-1/R6-2 (`lane_runner`, no SubjectAccount) |
| R67 `BindKey{walletStateInit}` message | lazy bind inside `SignedOp.stateInit` (`jetton.tact:209-212`) |
| R67 verifier rebuilds signData domain | R10-3 (domain off-chain), now CR-R3-7 (domain set on chain) |
| R35 book "Odoo hay SQLite" | built in Odoo; NI R105 store-backed (SPECIFIED) |
| §B.5 "anti-lock test mỗi mạng"; Soroban on mesh | MESH R77: Soroban excluded from mesh v1 |
| §B.3 keystore `"scaas": {"kind": …}` | SCaaS §9.6: the kind is an operator label, not stored |
| §B.1 trait as written | built trait in `scaas-node/src/adapter.rs` (L6) |
| net-aptos/net-sui/net-solana RS11-13 "upgrade compatible, multisig in production"; Solana `deploy.sh` "Production: move the upgrade authority to a multisig" | CR-R3-11 (owner): immutable at deploy |
| §D.1 e2e on `hedera-local-node` | `solo` (deprecated tool, wallet-formats L2) |

### H.5 Amendments needed in other specs (recorded; owner syncs)

| Spec | Amendment |
|---|---|
| SCaaS.md | §1.2/§1.3 hold as written (CR-R3-11); §7.5/§7.7: "upgrade compatible" → immutable at deploy, fix = new version + migration, deploy gate; §6.6 / §3.5: what the finality gate checks per family (CR-R3-2); §9.3: one WebAuthn grammar + vectors (CR-R3-1); §9.4: lifecycle table (CR-R3-6); §7.3 Cosmos passkey v2, §7.4 Soroban `pay_ref` per `(from, pay_ref)`, §7.5 Sui `Keys`, §7.6 TON domain set and bounced payouts, §7.7 Solana build-time network. |
| net-cosmos | passkey v2 derivation + grammar; quorum on head and events; `Sweep` removed. |
| net-soroban | `pay_ref` per `(from, pay_ref)`, `amount > 0`; guardian (R3-FIX8); grammar. |
| net-sui | `Keys` object (CR-R3-5); grammar; event quorum; RS11-13 → `make_immutable` at deploy (CR-R3-11). |
| net-ton | domain set (CR-R3-7), exact origin, bounced payouts (CR-R3-9); quorum; guardian (R3-FIX10). |
| net-solana | build-time network = genesis hash, `initialize` without `network`, program-id reuse refusal (CR-R3-4); grammar (`crossOrigin`); event quorum; RS11-13 → upgrade authority None after `initialize` (CR-R3-11). |
| net-aptos | shared WebAuthn vectors; RS11-13 → `upgrade_policy = "immutable"` (CR-R3-11). |
| net-hedera | none beyond spec gốc CR-PD-2 (event quorum on the EVM path). |
| NI rev 3.6 | §9 indexer: event-set quorum for every family; Cosmos/TON honour `quorum`; `scaas_finality_quorum`; chain profiles carry the redeployed immutable package/program ids (CR-R3-11). |
| UA | R330 `chain_uid` for Solana = the genesis hash the program is built with (CR-R3-4). |

### H.6 Code streams (new; for TODO)

| Stream | Scope | Ruling |
|---|---|---|
| **R3-FIX1** | Cosmos `metaop`: passkey v2 (rpIdHash, strict grammar, UV, low-s, v2 derivation); tests + vectors | CR-R3-1 |
| **R3-FIX2** | `webauthn_kat.json` shared vectors; strict grammar + exact origin on Sui, Soroban, TON, Solana; EVM/Aptos/Cosmos run the vectors | CR-R3-1 |
| **R3-FIX3** | node Sui, Solana, Soroban adapters: `events` + `final_head` agreed across `quorum`; lying-provider tests | CR-R3-2 |
| **R3-FIX4** | node Cosmos, TON adapters: quorum on head and events (today single endpoint) | CR-R3-2 |
| **R3-FIX5** | Soroban token/mandate: `PayRef(from, pay_ref)`, `ZeroAmount`; tests | CR-R3-3 |
| **R3-FIX6** | Solana: build-time `SCAAS_NETWORK` from `solana genesis-hash`, `initialize` without `network`, deploy.sh id-reuse refusal, chain profile `chain_uid`; tests | CR-R3-4 |
| **R3-FIX7** | Sui `Keys` object per subject; `Account<T>`, recovery and DEX take `&Keys`; fresh dev publish; tests | CR-R3-5 |
| **R3-FIX8** | Soroban account guardian + delayed recovery (finish the R8-2 seam) | CR-R3-6 |
| **R3-FIX9** | Cosmos passkey account contract with rotation (design first) | CR-R3-6 |
| **R3-FIX10** | TON guardian + delayed passkey rotation | CR-R3-6 |
| **R3-FIX11** | TON `domains` set, `SetDomains` from owner wallet, timestamp bound; sandbox tests | CR-R3-7 |
| **R3-FIX12** | lane-horizon constants pinned equal in tests; node refuses `max_valid_for_secs > LANE_HORIZON` on pruning families | CR-R3-8 / CR-PD-4 |
| **R3-FIX13** | TON DEX `payoutOf`, `unclaimed`, `Claim`; `WithdrawFees` fees only; tests | CR-R3-9 |
| **R3-FIX14** | Cosmos DEX: remove `Sweep` | CR-R3-10 |
| **R3-FIX15** | Immutable at deploy: Aptos `upgrade_policy = "immutable"`; Sui `make_immutable` in `deploy.sh`; Solana `initialize` then `set-upgrade-authority --final`; Cosmos `--no-admin`; deploy-script gate failing on an upgradeable result (+ negative test); redeploy the existing dev deployments and update node/Odoo chain profiles | CR-R3-11 |

### H.7 Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | Round 3 design R30–R67; agy review S1–S28 (§G) |
| 1.1 | 2026-10-07 | Claude review 1 folded: 17 findings accepted, 0 rejected, H3 left as **open owner question Q1**; rulings CR-R3-1…10; streams R3-FIX1…14; superseded-rulings table (§H.4); net-*/SCaaS/NI/UA amendments recorded (§H.5) |
| 1.2 | 2026-10-07 | Owner ruling CR-R3-11: Aptos/Sui/Solana programs immutable at deploy (replaces Q1); deploy-script gate; stream R3-FIX15 (apply + redeploy dev deployments); RS11-13 superseded |
| 1.3 | 2026-10-07 | 2026-10-07 clean-up: private chain 7622 (formerly 9000) in §A.10 and the `chain_key` example; chain = `(chain_key, chain_uid)` per UA R330 (§B.1) |
