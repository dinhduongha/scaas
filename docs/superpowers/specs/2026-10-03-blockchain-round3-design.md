# Round 3 — chặn production, passkey, sáu hệ sinh thái

**Ngày:** 2026-10-03 · **Bổ sung cho:** `2026-10-03-blockchain-payments-design.md` (spec gốc, R1–R20) và
`2026-10-03-blockchain-payments-addendum-wallets.md` (addendum ví, R21–R29). Ruling mới đánh số từ R30. **R30–R49 dành cho quyết định của owner** (owner tự đặt số); ruling kỹ thuật của
round này đánh số từ **R50** để không phải đánh số lại khi owner thêm quyết định.

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
    JSON lý do. Không có gateway vẫn có `/readyz` (sửa GA 2.3#12).
  - `GET /metrics` — văn bản Prometheus, viết tay (không thêm crate): `bamboo_relay_jobs{chain,state}` (gồm
    `dead`), `bamboo_payment_requests_attention{chain}`, `bamboo_indexer_lag_blocks{chain}`,
    `bamboo_relayer_balance{chain,lane}` (đơn vị nhỏ nhất của coin gas), `bamboo_breaker_open{chain,breaker}`,
    `bamboo_drift_alerts{chain}`.
- Số liệu Odoo đến từ method dịch vụ mới `blockchain.chain.relay_stats(chain_key)` (đọc, nhóm relay/indexer).

### A.4 CI (GA 2.1#4) — R52

`.github/workflows/blockchain-ci.yml`, chạy trên PR/push chạm `smartcontracts/**`, `bamboo-node/**`,
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
  Bearer <secret>` so sánh constant-time. `hmac`: `X-Bamboo-Timestamp` + `X-Bamboo-Signature =
  hex(HMAC-SHA256(secret, ts ‖ "." ‖ body))`, lệch giờ ≤ 300 s, cộng `X-Bamboo-Nonce` (trong chuỗi ký) nhớ trong tập TTL 300 s ⇒ không phát lại (review S20). Mặc định `none` bị **từ chối** khi bind không
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

`docs/superpowers/HANDOFF-blockchain.md`: audit bên thứ ba, triển khai thật (9000/Gnosis), bằng chứng finality 7
ngày, ≥2 RPC độc lập, và mọi mục GA 2.2 không làm ở round này (kèm tham chiếu SRS).

---

## B. Abstraction adapter, signer, khoá relayer

### B.1 `ChainAdapter` (bamboo-node) — R58

```rust
pub enum Family { Evm, Hedera, Sui, Soroban, Cosmos, Ton }

#[async_trait]
pub trait ChainAdapter: Send + Sync {
    fn family(&self) -> Family;
    fn chain_key(&self) -> &str;                       // "evm:9000", "sui:localnet", "cosmos:wasmd-1"…
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
mnemonic = { env = "BAMBOO_MNEMONIC" }          # hoặc { file = "/run/secrets/mnemonic" } (0600)
                                                # hoặc { keystore = "/etc/bamboo/m.json", passphrase_env = "…" }
bip39_passphrase_env = "BAMBOO_BIP39_PASSPHRASE" # tuỳ chọn
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
  seed ed25519) hoặc mnemonic (UTF-8); thêm trường `"bamboo": {"kind": "secp256k1"|"ed25519"|"mnemonic"}`.
  CLI: `bamboo-node keystore new --kind … --out …` (đọc bí mật từ stdin, passphrase từ env).
- Không bao giờ log/ghi file cấu hình bí mật; khởi động in **chỉ địa chỉ** dẫn xuất của từng lane.
  `bamboo-node addresses --config` in địa chỉ rồi thoát.
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
| EVM/Hedera | lane EOA | nonce per lane, pipeline + thay thế + gap-fill | chủ thể không có nonce tài khoản trong đường đi; lane khác chạy tiếp |
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
  P-256 trên `sha256(authenticatorData ‖ sha256(clientDataJSON))`. WebAuthn trả chữ ký **DER** và authenticator
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
  **Triển khai account:** `SubjectAccountFactory` CREATE2, salt = hash(khoá đầu tiên) ⇒ địa chỉ biết trước; Odoo
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
- **Dẫn xuất** (cùng bảng §B.3, nhưng cho chủ thể): EVM `m/44'/60'/0'/0/i` (secp256k1); Cosmos `m/44'/118'/0'/0/i`;
  Hedera-ECDSA `m/44'/3030'/0'/0/i`; Hedera-ED25519 `m/44'/3030'/0'/0'/i'` (như HashPack); Sui `m/44'/784'/i'/0'/0'`;
  Stellar `m/44'/148'/i'`; TON `m/44'/607'/i'`.
- **Ký**: đúng digest typed của mạng như mọi signer khác (EIP-712 / payload `MetaOp` của họ).
- **Lưu trữ**: mã hoá AES-GCM (WebCrypto). Khoá bọc: **PRF** của passkey (`extensions.prf`) nếu có; nếu không,
  PIN/passphrase qua **scrypt** (N=2^15, r=8, p=1 — 32 MB, memory-hard; 2^17 làm treo trình duyệt di động —
  review S23; thư viện `@noble/hashes` vendored). Không lưu
  khoá bọc. Lưu ở IndexedDB/localStorage của origin (try/catch).
- **Sao lưu**: hiện mnemonic **một lần**, bắt buộc bước xác nhận (nhập lại 3 từ chọn ngẫu nhiên) trước khi dùng.
- **Nhập**: kiểm checksum BIP-39; sau khi dùng ghi đè buffer bí mật (`fill(0)`) trong giới hạn của JS (chuỗi
  không xoá được — ghi rõ).
- **Thư viện**: `@noble/hashes`, `@noble/curves` (secp256k1, ed25519), `@scure/bip39`, `@scure/bip32` — ghim
  phiên bản, vendored dạng ESM bundle trong `static/lib/`, **chỉ nạp khi chọn ví seed**.

### C.3 Account chủ thể nhiều khoá (R31 + R32)

- Một chủ thể có **một account** trên mỗi mạng (smart account EVM / object, contract ở mạng khác) giữ **nhiều
  khoá được uỷ quyền**: passkey (P-256 WebAuthn) và khoá dẫn xuất từ seed (secp256k1 / ed25519 tuỳ mạng).
  Thêm/xoay/xoá khoá cần chữ ký của một khoá hiện có, hoặc guardian sau trễ khôi phục. Seed là khoá khôi phục tự
  nhiên khi mất passkey, và ngược lại.
- EVM: `SubjectAccount` (ERC-1271) — khoá kiểu `P256_WEBAUTHN(qx,qy,rpIdHash)` hoặc `SECP256K1(address)`;
  chữ ký = `abi.encode(keyIndex, payload)`; batch Merkle cho cả hai kiểu.
- Test e2e: thêm khoá thứ hai (seed khi đã có passkey) rồi ký bằng từng khoá.

### C.4 Khoá Zether (bảo mật số dư) từ cùng seed, đường dẫn riêng — R33 (owner: *"Seed word gen key riêng cho zether (key path khác)"*)

- SRS §8.1 tách `auth_custody` (khoá ký) và `conf_custody` (khoá ElGamal `x`): lộ khoá ký không lộ số dư; lộ `x`
  không uỷ quyền chuyển tiền. Nên `x` có **đường dẫn riêng**, không bao giờ trùng scalar khoá ký nào.
- BIP-32/SLIP-10 không có bn254 hay BLS12-381 ⇒ dẫn xuất **hardened-only kiểu EIP-2333** (HKDF-SHA256, `r` là bậc
  của nhóm, tách miền):
  - **BLS12-381:** đúng EIP-2333 (`derive_master_SK`, `derive_child_SK`, salt `"BLS-SIG-KEYGEN-SALT-"`), đường
    kiểu EIP-2334 `m/12381/<coin>/<account>/7` — `<use> = 7` dành riêng cho Zether-conf (EIP-2334 dùng 0 =
    withdrawal, 0/0 = signing; 7 không đụng). `<coin>` = SLIP-44 của mạng (EVM 60).
  - **bn254:** cùng cấu trúc EIP-2333 với `r` của bn254 và salt **`"BAMBOO-ZETHER-BN254-v1"`**; HKDF-Expand ra
    **48 byte** (L = ceil(3·ceil(log2 r)/16) = 48) rồi `mod r`, lặp nếu 0 — như EIP-2333. Đường
    `m/254/<coin>/<account>/7` (gốc 254 để không bao giờ chạm cây 12381).
  - Khoá phụ thuộc (seed, đường cong, mạng/coin, account). **Không** theo token (một UA mỗi (đường cong, mạng,
    account) — đúng SRS "đăng ký theo cặp (account, chain)"); đổi đường cong của verifier ⇒ cây khác ⇒ không tái
    dùng scalar.
  - Khoá xem/tiết lộ cho kiểm toán (`ITransferDisclosure`): `<use> = 8`, cùng hai cây — chưa dùng (Zether chưa xây).
- `y = g^x` (G1 của đường cong), `UA = keccak256(encodedY)` (`ZetherTypes.toUA`: bn254 64 byte `x‖y`, BLS12-381
  128 byte theo EIP-2537). **PoP** (SRS §7.5): Schnorr bằng `x` trên `c = keccak256(registry ‖ encodedY ‖
  account)` với `account` = account chủ thể (khoá ký) ⇒ ràng PoP vào khoá ký/account.
- Lưu như seed: chỉ phía client, mã hoá khi nghỉ, không gửi Odoo/relayer.
- **Phạm vi:** luồng Zether on-chain vẫn hoãn (R1/§11 cho Zether giữ nguyên); round này ship thư viện dẫn xuất,
  vector, PoP, lưu trữ client.
- **Test:** vector EIP-2333 công bố (BLS12-381); vector bn254 tự sinh và ghim; cùng seed khác đường ⇒ khoá độc lập;
  `x` ≠ mọi scalar khoá ký của cùng seed; `y`/UA round-trip; PoP verify.

---

## D. Sáu hệ sinh thái

### D.0 Mô hình chung (mọi họ không phải EVM)

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
`domain="bamboo.metaop.v1" ‖ network ‖ contract ‖ op(pay|trade|mandate_pay|revoke) ‖ from ‖ to ‖ amount(u128) ‖
payRef(32) ‖ lane(32) ‖ nonce(u64) ‖ validUntil(u64, giây) ‖ relayer(tuỳ chọn) ‖ extra(hash 32 của tham số riêng op)`.
Không phí trên các mạng mới (fee NONE như portal — R10); phí relayer chỉ trên EVM. Op `trade`: tham số riêng
(token đối ứng, số tối thiểu, đối tác) đi **nguyên văn** cạnh `MetaOp` và `extra = H(tham số)` (review S28).

### D.1 Hedera (HSCS) — R63

- **SRS:** HSCS chạy EVM; tài trợ bằng payer account. Theo R30, đường payer-sponsored (tx tài khoản Hedera của
  chủ thể) **không** làm: nó là đúng loại khoá chủ thể. Dùng lại **toàn bộ** contract Solidity (MetaToken,
  MandateWallet, MetaTxDex, SubjectAccount) trên HSCS, relayer = adapter EVM trỏ vào **Hedera JSON-RPC Relay**
  (chain id 295/296/298), lane = tài khoản ECDSA (coin 3030).
- **Khoá ED25519 của Hedera:** `HederaMetaToken is MetaToken` ghi đè `_requireValidSignature`: nếu `from` là địa
  chỉ long-zero/tài khoản Hedera không có ECDSA alias, kiểm qua precompile **HIP-632** `isAuthorizedRaw` (0x16a)
  — cách chính thức để contract kiểm chữ ký ED25519/ECDSA của một tài khoản Hedera. Khoá secp256k1 có alias EVM
  đi đường ECDSA như EVM.
- **HTS:** token HTS (ví dụ USDC trên Hedera) dùng qua **wrapper tầng 2** của `MetaToken` (approve cho contract
  wrapper — hợp lệ theo R26); allowance HTS ở cấp giao thức không ép được "chỉ contract" ⇒ ghi rủi ro, không dùng
  allowance HTS ngoài wrapper.
- HCS (nhật ký kiểm toán agent) và scheduled tx: SRS không bắt buộc cho thanh toán ⇒ ngoài phạm vi (HANDOFF).
- **Test:** forge (precompile 0x16a giả bằng `vm.etch`); e2e trên `hedera-local-node` nếu chạy được (cần ~8 GB
  RAM, nhiều container), nếu không: e2e EVM trên anvil `--chain-id 298` + ghi khoảng trống.

### D.2 Sui (Move) — R64

- **Token:** `bamboo::meta::Account<T>` — **shared object một chủ thể** giữ `Balance<T>`, khoá công khai (ed25519 /
  secp256k1 / secp256r1-passkey), bảng lane→nonce. Tạo bằng `open<T>(pubkey, scheme)` (kiểm địa chỉ =
  blake2b256(flag‖pk)), nạp bằng `deposit` (ai cũng nạp được). Shared object per chủ thể ⇒ tranh chấp chỉ trong
  phạm vi một chủ thể. Coin owned **không** chi được bởi người khác trên Sui, nên số dư phải nằm trong object
  của contract.
- **Một account mỗi (chủ thể, coin type):** `Registry` shared ánh xạ `(address, TypeName) → ID`; `open` thứ hai bị
  từ chối ⇒ không ai tạo account trùng để nhốt tiền (review S15).
- **Ký:** ví ký `signPersonalMessage(BCS(MetaOp))`; Move dựng lại digest = blake2b256([3,0,0] ‖
  bcs(vector<u8>)) và kiểm `ed25519_verify` / `secp256k1_verify(hash=SHA256)`; passkey: `secp256r1_verify` theo
  §C. Miền: `network` = chuỗi lưu trong `Config` (đặt lúc publish) + `object::id(account)` (khác nhau giữa mạng).
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
  persistent + gia hạn TTL); `approve` chỉ cho địa chỉ contract (`C…`). **Mandate**, **DEX** `settle(a, b)` với
  hai `require_auth_for_args` — đúng mô hình EVM.
- **Test:** `cargo test` (soroban-sdk testutils); e2e trên `stellar/quickstart` local (docker) qua `stellar` CLI.

### D.4 Cosmos (CosmWasm) — R66

- **Token** `bamboo-token` (CW20 + meta-tx): `Relay{op, pubkey, signature, scheme}`. Ký: Keplr/Leap
  `signArbitrary` (ADR-036) trên bytes JSON của `MetaOp`; contract dựng lại sign doc ADR-036, `sha256`,
  `secp256k1_verify`, địa chỉ = bech32(ripemd160(sha256(pk))) phải bằng `from`; passkey: `secp256r1_verify` với bộ giải
  WebAuthn riêng (không qua ADR-036). Sign doc ADR-036 dựng bằng **khuôn byte cố định** (khoá đã sắp, không khoảng
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
  `checkSignature`. Gắn pubkey: `BindKey{walletStateInit}` — jetton wallet kiểm
  `contractAddress(stateInit) == owner` và đọc pubkey từ data của W5R1/V4R2 (không cần chủ thể gửi tx). Ký: TON
  Connect `signData` (kiểu `cell`) — verifier dựng lại **đúng phong bì** signData (prefix, domain, timestamp,
  địa chỉ) quanh cell `MetaOp` rồi mới kiểm (review S10); `MetaOp` là **cây cell** (gốc + ref) vì một cell chỉ
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
- **R33** (owner) Khoá Zether conf từ seed, đường riêng (EIP-2333 BLS12-381 `m/12381/<coin>/<acct>/7`, bn254 kiểu EIP-2333 salt riêng `m/254/<coin>/<acct>/7`), PoP ràng vào account; Zether on-chain vẫn hoãn.
- **R32** (owner) Ví seed words phía client (24 từ, không rời thiết bị, AES-GCM bọc bằng PRF/scrypt); account chủ thể nhiều khoá (passkey + seed).
- **R50** Custody `env:` chỉ dev (cờ + chain dev); ký qua `cryptography` (OpenSSL).
- **R51** `/readyz` + `/metrics` trên cổng quản trị riêng; số liệu Odoo qua `relay_stats`.
- **R52** CI blockchain riêng; `lib/` forge cài theo tag ghim.
- **R53** `paused` chỉ chặn gửi; `halted` chặn cả indexing.
- **R54** Gateway auth `bearer|hmac`; `none` chỉ trên loopback; proptest cho decoder.
- **R55** Cầu dao: spike base fee, ngân sách gas theo giờ, sàn số dư lane; không chặn indexing.
- **R56** Journal theo (công ty, token) company-dependent; drift A (Transfer không khớp) + drift C (số dư vs GL).
- **R57** Seam công ty nhận/quản trị ví duy nhất; "Host" ⇒ "platform company".
- **R58** `ChainAdapter`; EVM giữ runner riêng; mạng khác dùng `lane_runner` một-tx-mỗi-lane.
- **R59** `Signer` secp256k1/ed25519 cục bộ; KMS là seam.
- **R60** Khoá: khoá thô hoặc mnemonic 24 từ; đường dẫn theo bảng §B.3; keystore Web3 v3 cho cả hai đường cong.
- **R61** Họ mạng trong Odoo; địa chỉ chuẩn theo họ; `blockchain.signed.op`; Odoo kiểm ed25519, còn lại node mô phỏng.
- **R62** Bảng tránh head-of-line §B.5 + test anti-lock mỗi mạng.
- **R63** Hedera = Solidity trên HSCS qua JSON-RPC relay + HIP-632 cho ED25519; không đường payer-sponsored.
- **R64** Sui = Account<T> shared per chủ thể + personal-message; DEX hai chân.
- **R65** Soroban = auth gốc làm meta-tx; fee-bump cho lane; DEX hai `require_auth`.
- **R66** Cosmos = CW20 + ADR-036; không authz; feegrant chỉ là seam.
- **R67** TON = Tact, jetton wallet tuỳ biến có pubkey + `BindKey`; DEX escrow.

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
- **R35** (owner) **DEX hoàn chỉnh**: sổ lệnh off-chain **bền** (lưu ở Odoo hay SQLite — luồng DEX chọn và ghi),
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
