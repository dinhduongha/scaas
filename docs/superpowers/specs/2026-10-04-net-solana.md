# Solana (Rust/Anchor) — meta-tx cấp program, Account PDA, mandate, DEX, relayer (luồng S12)

**Ngày:** 2026-10-04 · **Luồng:** S12 (`r3-solana`) · **Đích trong repo:** `docs/superpowers/specs/2026-10-04-net-solana.md`
· **Bổ sung cho:** round-3 design §B, §C, §D.0, §D.6 (R30, R31, R32, R58–R62); DEX `2026-10-03-dex-design.md` (R35);
shared contract "Network streams" của `2026-10-03-r3-streams.md`. Mẫu gần nhất: S11 Aptos (`2026-10-04-net-aptos.md`),
S7 Sui (`2026-10-03-net-sui.md`). Ruling của luồng đánh số `RS12-n` (lead đánh lại khi merge).

Mã (dự kiến): program Anchor ở `chains/solana/` (program `bamboo`, workspace Cargo riêng), adapter
`bamboo-node/src/adapters/solana.rs`, e2e `bamboo-node/tests/e2e_solana.rs`, Odoo `dms_blockchain/lib/fam_solana.py` +
`models/blockchain_solana.py`, portal `dms_blockchain_bridge/static/src/js/connectors/solana.js`. DB `dms_test_chain_12`
/ 8932, devnet 32020–32049 (OQ4: Agave đòi dải cổng động ≥ 26).

Thứ tự mạng (owner): EVM → Cosmos → Hedera → Soroban → TON → Sui → Aptos → **Solana**. Sản phẩm trung lập thị
trường: không giả định tài sản, quốc gia hay luật nào; mọi mint SPL Token / Token-2022 mà Odoo đăng ký và qua chính
sách extension (§3.6) đều dùng được.

---

## 0. Bài học đã gặp ở mạng khác — thiết kế vào từ đầu

| # | Bài học (review mạng khác) | Ở Solana |
|---|---|---|
| L1 | Indexer lấy danh sách contract từ `node_config` dạng chuẩn của họ; danh sách rỗng ⇒ không tiến con trỏ (Cosmos H1/M1, Sui H1/H2, TON 1) | `events(from,to,contracts)` lọc theo `nc.tokens` (địa chỉ mint base58); không có danh sách tĩnh trong `params`; `index_step` chung đã giữ con trỏ; vùng chưa `finalized` không bao giờ được hỏi (§6.6) |
| L2 | e2e: Odoo giả trả token id thật, từ chối emitter chưa đăng ký (TON 1d, Hedera H2) | Odoo giả trả địa chỉ mint thật vừa tạo; ingest từ chối `contract ∉ tokens`; một bản deploy thứ hai của program (program id khác) phát event giống hệt ⇒ bị bỏ vì indexer chỉ đọc inner instruction của **đúng** program id + event authority PDA (§6.6, §9) |
| L3 | Số tiền do relayer chọn mà quyết định tiền có đến hay không phải nằm trong chữ ký người trả (TON 2 `forwardTon`) | `pay` không có tham số kiểu đó; fill DEX bị chặn bởi giá/lượng đã ký; compute unit và priority fee do relayer chọn chỉ ảnh hưởng relayer: hết CU ⇒ tx rollback toàn bộ (trừ phí + nonce lane), lane PDA của người trả còn nguyên ⇒ `Rejected` (§6.4) |
| L4 | Từ chối vĩnh viễn ở submit trả lane ngay (`adapter::Rejected`) (Cosmos L1, Hedera M2) | Bảng lỗi preflight/RPC ⇒ `Rejected`; lỗi hết CU đã vào sổ ⇒ `Rejected` (§6.4) |
| L5 | Lane an toàn khi crash: không equivocation, không dùng hai lần một sequence (Sui M3, merge TODO b) | Lane dùng **durable nonce account** riêng: mỗi giá trị nonce chỉ cho **một** tx vào sổ (kể cả tx lỗi vẫn advance nonce); `sequence(lane)` = giá trị nonce ⇒ `recover_lane` chung đúng nguyên văn, không cần journal đĩa (§6.1, §6.5) |
| L6 | Account nhiều khoá + origin + guardian, không bị "gạch" vì đổi origin (Sui M1) | `SubjectAccount` PDA ≤ 8 khoá (ed25519 / P-256 WebAuthn), ≤ 8 origin, guardian + trễ 2 ngày; thêm origin mới **cùng rpId** được chính passkey đó ký ⇒ đổi domain portal không gạch Account; chính sách "backup key required" (mặc định OFF) (§3.3) |
| L7 | Coin gửi thẳng tới địa chỉ object/contract phải kéo vào được (Sui M2, Cosmos L4, TON 2/9/14) | Số dư = **token account bất kỳ có owner = Account PDA** (ATA hay không) — không sổ nội bộ; lamports gửi nhầm vào PDA rút được bằng KeyOp; Market/Mandate có `sweep` (§3.2, §5) |
| L8 | Không object dùng chung tuần tự hoá mọi thị trường (Sui M4) | **Write-lock là khoá thật của Solana** (§2.4): đường nóng chỉ ghi account riêng của thao tác (lane PDA mới, fill PDA của lệnh, ATA của hai bên); `Config`, `Market`, `SubjectAccount` chỉ **đọc** (§3.5) |
| L9 | Odoo chỉ xác minh chữ ký bằng khoá nó chứng minh được (TON 12, Sui "signer == payer") | `verify` trả `True` chỉ khi pk ed25519 = địa chỉ người trả; passkey / khoá thêm sau ⇒ `None` — mô phỏng của node phân xử (§7) |
| L10 | Bảng lane/nonce lớn mãi ⇒ phí lưu trữ (TON 4) | Mỗi lane PDA/fill PDA/mref PDA giữ `valid_until` + `rent_payer`; `prune` không cần quyền sau hạn, **rent trả về đúng `rent_payer`** (lane relayer) (§3.4) |
| L11 | *(mới, đọc code main)* Odoo chuẩn hoá chuỗi bằng `.lower()` / `_hex32` | Base58 phân biệt hoa-thường; chữ ký tx Solana 64 byte. ⇒ `tx_id` = `0x` + 128 hex (an toàn với `.lower()` của `_apply_report`); ingest cần chấp nhận `tx_hash` 64 byte cho họ `solana` (cần từ lead, §12); địa chỉ không bao giờ đi qua `.lower()` |
| L12 | *(owner, round này)* R30 trên Solana: khoá thật là account write-lock, không phải sequence | Test bắt buộc thêm: tập account **writable** của hai thao tác khác contract của cùng chủ thể (trừ lane relayer + nonce lane) **rời nhau** (§9) |

---

## 1. Phạm vi

Sáu deliverable của shared contract: (1) thiết kế này; (2) program Anchor `chains/solana` — `auth` (introspection
precompile), `account` (SubjectAccount + pay), `mandate`, `dex`, test LiteSVM kể cả anti-lock và write-set; (3) adapter
Rust + e2e `solana-test-validator`; (4) `fam_solana` Odoo + vector chéo; (5) connector Wallet Standard
(`solana:signMessage` / `solana:signOffchainMessage`); (6) báo cáo.

**Trong phạm vi (khác Aptos):** passkey WebAuthn **có** trên đường program — Solana có precompile secp256r1 (§2.3).

**Ngoài phạm vi (seam, §11):** mint có transfer hook đang hoạt động / transfer fee khác 0 (§3.6); tự động `prune`
trong node; indexer Geyser cho mainnet tải cao (§6.6); thanh toán bảo mật (§10).

---

## 2. Vì sao meta-tx cấp program trên Solana (R30) — fee payer, blockhash, durable nonce, priority fee, write-lock

### 2.1 Năm cơ chế gốc (đã kiểm tài liệu 2026-10-04)

- **Fee payer.** Tx Solana do account đầu tiên ký trả phí; mọi signer khác chỉ uỷ quyền. Tài trợ gốc = chủ thể ký tx
  như authority, relayer ký làm fee payer. **Solana không có sequence tài khoản**: chống replay của tx là chữ ký +
  blockhash gần đây (status cache). Vì vậy fee payer **không** tự nó tạo khoá thứ tự kiểu Stellar/Cosmos.
- **Recent blockhash.** Tx tham chiếu một blockhash; quá ~150 block (~60–90 s, `lastValidBlockHeight`) chưa vào sổ ⇒
  hết hạn và bị bỏ. [solana.com/docs/core/transactions/durable-nonces]
- **Durable nonce.** Thay blockhash bằng giá trị lưu trong một nonce account; instruction đầu phải là
  `SystemProgram::AdvanceNonceAccount` (nonce account là account đầu, writable, phải **static** — SIMD-0242). Tx không
  hết hạn cho tới khi nonce bị advance. *"If a nonce transaction passes validation but execution fails …, the nonce is
  still advanced and fees are still collected."* Không advance hai lần trong một block. Tài liệu ghi *"Durable nonces
  may be deprecated in a future release"* (discussion SIMD #415). [cùng nguồn; SIMD-0242 Implemented]
- **Priority fee / compute budget.** Base fee 5 000 lamport **mỗi chữ ký — kể cả chữ ký mà precompile Ed25519 /
  Secp256k1 / Secp256r1 kiểm**. Priority fee: v0 = giá micro-lamport/CU qua instruction `ComputeBudget`; **v1 = tổng
  lamport ở header message**, `ComputeBudget` thành no-op, giới hạn CU/loaded-data **bắt buộc** (bỏ trống = 0 ⇒ tx
  không chạy). Phí ưu tiên là **local fee market**: tính theo account writable bị tranh chấp.
  [solana.com/docs/core/fees/fee-structure; solana.com/upgrades/larger-transaction-sizes; helius.dev/blog/solana-local-fee-markets]
- **Thực thi song song (Sealevel).** Tx khai báo trước mọi account đọc/ghi; scheduler không chạy song song hai tx ghi
  cùng account. Trần: 100M CU/block (SIMD-0286, mainnet 2026-07-29) nhưng **12M CU mỗi account writable mỗi block**
  không đổi. [solana.com/upgrades/100m-cu-blocks]

### 2.2 Áp vào R30

1. **Đường native (chủ thể ký tx, relayer làm fee payer) không đủ**, dù không có sequence:
   a. tx chủ thể ký sống ≤ ~90 s ⇒ không ký trước được job xếp hàng ở Odoo, lô, mandate, **lệnh DEX nằm trong sổ hàng
      giờ**;
   b. kéo dài bằng durable nonce **của chủ thể** ⇒ chính nonce account đó xếp hàng **mọi** thao tác của chủ thể trên
      **mọi** program (mỗi tx advance nó) — đúng "lỗi khoá async của chủ thể trên nhiều contract" (R30);
   c. chữ ký tx Solana chỉ là ed25519 ⇒ **passkey P-256 không ký tx được** — chỉ đi được qua kiểm tra trong program;
   d. tiền nằm trong ATA do khoá ví sở hữu ⇒ không có nhiều khoá / guardian / khôi phục (§C.3), không có mandate có trần.
2. **Kết luận (RS12-1):** đường chính = **meta-tx cấp program**: chủ thể ký một thông điệp tách miền; mỗi "contract"
   (SubjectAccount, Mandate, Market của ta) giữ không gian lane/nonce **dưới dạng PDA riêng mỗi lane**; relayer gửi tx
   **từ lane của chính nó** (fee payer = lane), tự trả base fee + priority fee + rent.
3. Fee payer gốc chỉ dùng cho **relayer** (lane trả phí cho tx của chính nó). Chủ thể chỉ gửi tx native cho việc một
   lần ngoài đường nóng (nạp tiền từ ví; guardian `start_recovery`).

### 2.3 Chữ ký program kiểm được (đã kiểm)

| Lược đồ | Cách kiểm trong program | Dùng? |
|---|---|---|
| ed25519 (Phantom/Solflare/Backpack, ví seed R32) | precompile `Ed25519SigVerify111111111111111111111111111` + introspection sysvar Instructions | **Có** |
| secp256r1 / WebAuthn | precompile `Secp256r1SigVerify1111111111111111111111111` (SIMD-0075, *Implemented*; Agave 2.2; báo cáo bật mainnet 06/2025): pk SEC1 nén 33 B, chữ ký 64 B `r‖s`, SHA-256 message bên trong, **ép low-S**, ≤ 8 chữ ký/instruction, chỉ số `0xFFFF` = "instruction hiện tại" | **Có** (passkey) |
| secp256k1 | precompile Keccak/secp256k1 (pk = địa chỉ ETH 20 B) | không (YAGNI) |

Nguồn: solana.com/docs/core/programs/precompiles; SIMD-0075 (`proposals/0075-precompile-for-secp256r1-sigverify.md`);
helius.dev/blog/solana-passkeys. Task 0 kiểm lại bằng `solana feature status` trên mainnet và trên validator cục bộ.

### 2.4 Write-lock — khoá thật của Solana (L8, L12) — RS12-2

- Write-lock chỉ tồn tại **trong lúc block thực thi** tx; tx đang chờ / bị giữ lại **không** giữ khoá. Vì vậy thuộc tính
  anti-lock (X giữ lại, Y vẫn qua) đạt được về cấu trúc khi X và Y không chung nonce — điều đường native 2.2b phá.
- Rủi ro thật là **account nóng**: mọi account bị nhiều tx ghi (bộ đếm toàn cục, một `Market` lưu sổ/`filled`, một
  vault phí chung, `Config` bị ghi trên đường nóng, `SubjectAccount` bị ghi mỗi thao tác) ⇒ các tx đó chạy tuần tự trong
  block, chạm trần 12M CU/account/block, đẩy priority fee cục bộ lên và bị rớt khi nghẽn. Tác động kiểu "khoá": hai thao
  tác **không liên quan** của cùng chủ thể giành nhau một account.
- **Quy tắc thiết kế:** trên đường nóng mỗi tx chỉ **ghi**: lane relayer + nonce account của lane; một PDA **mới** riêng
  thao tác (lane PDA / mref PDA / fill PDA); token account của đúng hai bên; Mandate PDA (chỉ thao tác mandate — trần kỳ
  vốn tuần tự); vault phí của **một** market (chỉ khi phí bật). Mọi thứ khác (`Config`, `Market`, `SubjectAccount`,
  mint, min-nonce PDA) là **readonly**. Bảng ghi/đọc đầy đủ ở §3.5; test write-set ở §9.

---

## 3. Account on-chain (`bamboo` program)

### 3.1 Bảng account

| Account | Địa chỉ (PDA của program `bamboo`) | Tạo bởi | Vai |
|---|---|---|---|
| program `bamboo` | program id cố định; upgrade authority (production: multisig) | deployer | một id cho lệnh gọi **và** event authority |
| `Config` | `["config"]` | `initialize` (chỉ upgrade authority — kiểm `ProgramData`) | `admin`, `network` = genesis hash của cluster. **Chỉ đọc** trên đường nóng |
| `SubjectAccount` | `["acct", owner32]` | lười ở `relay_pay` đầu (ed25519) hoặc `open` / `open_passkey` | khoá, origin, guardian, policy; **số dư = token account có owner = PDA này** |
| `LanePda` | `["lane", account, lane32]` | `relay_pay` / `mandate::open` / KeyOp (init) | `{next u64, valid_until i64, rent_payer}` |
| `Mandate` | `["mandate", account, seed32]` | `mandate_open` (ký bởi khoá Account) | như `MandateWallet` R25; số dư = token account có owner = PDA này |
| `MandateRef` | `["mref", mandate, pay_ref32]` | `mandate_pay` (init — chạy hai lần ⇒ lỗi) | `pay_ref` một lần, prunable |
| `Market` | `["mkt", base_mint, quote_mint]` | admin `list_market` | phí ppm, bật/tắt; vault phí = ATA(Market, mint) |
| `Fill` | `["fill", market, order_hash32]` | `settle` / `cancel_signed` (init_if_needed) | `filled` của **một** lệnh, `valid_until` = hạn lệnh |
| `MinNonce` | `["minnonce", market, account]` | `invalidate_nonces_signed` | `min_nonce` theo (maker, market) |
| `__event_authority` | `["__event_authority"]` (Anchor) | — | ký self-CPI của `emit_cpi!` |

PDA = `find_program_address(seeds, program_id)` (sha256(seeds ‖ bump ‖ program_id ‖ "ProgramDerivedAddress"), bump từ
255 xuống tới khi điểm **không** nằm trên ed25519) ⇒ Odoo, relayer, connector tính mọi địa chỉ **không RPC** (R20).
Vector chéo Rust program = Python = Rust adapter (§8).

### 3.2 Số dư nằm ở đâu — RS12-3

- **Không sổ số dư nội bộ.** Số dư của Account với mint X = các token account (SPL Token hoặc Token-2022) có `owner` =
  Account PDA và `mint` = X. Đường chuẩn là ATA(Account PDA, X, token_program) (ATA cho owner off-curve hợp lệ), nhưng
  program nhận **bất kỳ** token account nào có owner = PDA làm nguồn ⇒ tiền gửi vào token account lạ của PDA vẫn chi được
  (L7). Nạp tiền = chuyển SPL thường tới ATA đó (portal dựng tx `createIdempotent + transferChecked` cho ví, vì nhiều
  ví từ chối owner off-curve — tx native một lần, ngoài đường nóng).
- **Một Account cho mọi tài sản** (như Aptos): một bộ khoá, một lần xoay khoá; tài sản đi tường minh trong `MetaOp.asset`.
- Không SPL `Approve` nào cho tài khoản thường: authority của token account là PDA; chỉ program ký thay được
  (`invoke_signed` với seeds Account) — R26 "spender duy nhất là contract".
- Lamports gửi nhầm vào PDA (trên mức rent-exempt) rút bằng KeyOp `withdraw_lamports{to}` (L7).
- **Phương án bị loại:** để tiền trong ATA của ví và `Approve` cho PDA — một token account chỉ có **một** delegate
  (xung đột với dApp khác), cần tx native mỗi lần cấp lại, và không có nhiều khoá/khôi phục.

### 3.3 Khoá, origin, guardian, khôi phục, chính sách backup — RS12-4

```rust
#[account]
pub struct SubjectAccount {
    pub owner: [u8; 32],          // seed của PDA, không đổi
    pub bump: u8,
    pub keys: Vec<Key>,           // 1..=8
    pub origins: Vec<String>,     // 0..=8, mỗi origin ≤ 128 B; ≥ 1 khi còn khoá P-256
    pub guardian: Option<Pubkey>,
    pub recovery: Option<Recovery>, // { key: Key, ready_at: i64 }
    pub key_nonce: u64,
    pub policy: u8,               // bit0 = BACKUP_REQUIRED (mặc định 0)
}
pub struct Key { pub scheme: u8, pub pubkey: [u8; 33], pub rp_id_hash: [u8; 32] }
// scheme 0 = ed25519 (32 B + 1 byte 0), 2 = P-256 WebAuthn (33 B nén + rpIdHash)
```

- **`owner`**: ed25519 ⇒ chính pk 32 B (= địa chỉ ví Solana). Chủ thể passkey-first ⇒ `owner =
  sha256("bamboo.owner.p256" ‖ pk33)` (id, không phải ví). Account tạo `realloc` theo số khoá/origin (rent nhỏ lúc mở).
- **Mở:**
  - ed25519: lười trong `relay_pay` đầu tiên (chữ ký hợp lệ từ khoá = `owner`) hoặc `open(owner)` không cần quyền —
    khoá duy nhất là chính `owner` nên mở trước hộ người khác vô hại.
  - P-256: `open_passkey(pk33, assertion)` với challenge `sha256("bamboo.open.v1" ‖ program_id ‖ pk33)`;
    `rp_id_hash` = 32 byte đầu authenticatorData, `origin` đọc từ clientDataJSON **của chính assertion** (bài học
    RS7-2: không ai mở trước được Account với origin sai).
- **Quản trị:**
  1. `manage_signed(KeyOp, auth)` — `KeyOp{domain="bamboo.keyop.v1", network, account, action, key, origin, guardian,
     policy, to, nonce=key_nonce, valid_until}` ký bởi **một khoá hiện có**; `action` ∈ {add_key, remove_key,
     add_origin, remove_origin, set_guardian, cancel_recovery, set_policy, withdraw_lamports}; relayer gửi.
  2. guardian (tx native, ký bằng khoá Solana của guardian) `start_recovery(new_key)`; `finish_recovery` sau
     `RECOVERY_DELAY` = 2 ngày; khoá hiện có huỷ được. Như `SubjectAccount` EVM (round-3 §C).
- **Không gạch (L6):**
  - không bao giờ còn 0 khoá; còn khoá P-256 thì không còn 0 origin;
  - **origin mới cùng rpId:** assertion có `rpIdHash` khớp khoá nhưng `origin ∉ origins` **chỉ** được nhận cho đúng một
    việc: `KeyOp{action=add_origin, origin = chính origin trong assertion}`. Trình duyệt chỉ cho origin thuộc rpId (hoặc
    related origins do chủ rpId công bố) tạo assertion cho rpId đó ⇒ đổi domain trong cùng rpId không gạch Account, mà
    trang lừa đảo khác rpId vẫn bị chặn. Đổi rpId thì cần khoá seed hoặc guardian — lý do có chính sách backup.
- **Chính sách "backup key required" (owner xếp cho S4; ở đây mặc định OFF) — RS12-5:**
  - "Có backup" ⇔ (≥ 2 khoá) **hoặc** (1 khoá **và** có guardian).
  - Bật/tắt bằng `KeyOp set_policy` ký bởi khoá của **chính chủ** (admin không chạm Account). Bật khi chưa có backup ⇒
    từ chối (không tự khoá mình).
  - Khi bật: (a) `remove_key` / `set_guardian(None)` làm mất backup ⇒ từ chối; (b) thao tác giá trị (`relay_pay`,
    `mandate_open`, chân DEX của Account này) ⇒ abort `NoBackup` nếu vì lý do nào đó không còn backup (vd. guardian tự
    huỷ — không có đường đó, nhưng kiểm rẻ).
  - Odoo/portal: tham số công ty (S4 định nghĩa) bắt portal dẫn chủ thể thêm khoá seed/guardian rồi gửi `set_policy`.
    Odoo không đọc được trạng thái on-chain (R20) ⇒ thiếu backup bị mô phỏng phân xử (job `dead` với lý do rõ).
  - Ngữ nghĩa phải khớp S4 khi S4 chốt ⇒ OQ1.

### 3.4 Lane/nonce — RS12-6

- Một lane = một PDA `["lane", account, lane32]`, `init_if_needed`: `next == nonce` rồi tăng; `valid_until` = max của op đã
  dùng lane; `rent_payer` = lane relayer đã trả rent. Odoo phát nonce 0 trên lane ngẫu nhiên theo `entryRef` (R9) ⇒ thực
  tế mỗi request một PDA mới ⇒ **không** account dùng chung giữa hai thao tác.
- `prune(pdas)` **không cần quyền**: đóng LanePda / `MandateRef` khi `valid_until + PRUNE_DELAY_S < Clock.unix_timestamp`
  (`PRUNE_DELAY_S` = 30 ngày ≥ `LANE_HORIZON_S` của Odoo — review C1), `Fill` khi `valid_until < now` (hạn nằm trong
  hash lệnh); lamports về **`rent_payer` lưu trong PDA** (không về người gọi ⇒ không ai cướp rent). An toàn: `valid_until`
  chỉ là hạn của op ĐÃ CHẠY; Odoo phát lại điều khoản của một request trên CÙNG lane, nonce 0 (5318f20), mọi hạn trong
  30 ngày kể từ lúc tạo request ⇒ khi PDA bị xoá, mọi op khác đã ký cho request đã hết hạn (không trả hai lần).
- Chi phí (rent-exempt, refund khi prune): lane PDA ~0,0012 SOL; chưa prune thì tiền nằm đó (§11).

### 3.5 Bảng ghi/đọc trên đường nóng (L8, L12)

| Instruction | Writable (ngoài lane + nonce lane) | Readonly |
|---|---|---|
| `relay_pay` | LanePda (mới), token account nguồn của Account, ATA người nhận | Config, SubjectAccount (trừ lần mở lười), mint, sysvar Instructions |
| `mandate_pay` | Mandate (bộ đếm kỳ), MandateRef (mới), token account nguồn của Mandate, ATA người nhận | Config, mint |
| `settle` (mỗi cặp) | Fill×2, 4 token account của hai bên, vault phí của market (chỉ khi phí > 0) | Config, Market, SubjectAccount×2, MinNonce×2, mint×2 |
| `cancel_signed` | Fill của lệnh đó | Config, Market, SubjectAccount |

Hai chủ thể khác nhau ⇒ không chung account writable (trừ khi trả cùng một người nhận — ATA của người nhận là điểm ghi
chung không tránh được; 12M CU/block ≈ vài trăm thanh toán/block cho một người nhận, ghi ở §11). Cùng chủ thể, hai tài
sản ⇒ rời nhau; cùng tài sản ⇒ chung token account nguồn (chính là số dư — tuần tự trong block, không khoá giữa block).

### 3.6 SPL Token và Token-2022 — RS12-7

- Hỗ trợ **cả hai** program qua `anchor_spl::token_interface` (`InterfaceAccount<Mint>`, `transfer_checked`). Token
  program của mint đi theo account (`mint.owner`), ATA dẫn xuất theo đúng token program.
- **Chính sách extension, kiểm on-chain mỗi lần chuyển** (đọc TLV của mint): abort nếu
  - `NonTransferable`;
  - `TransferHook` có `program_id` khác null (hook chạy mã tuỳ ý, cần extra accounts — seam);
  - `TransferFeeConfig` mà phí của epoch hiện tại > 0 với `amount` này (người nhận nhận ít hơn số đã ký — phá L3; phí
    đổi được sau 2 epoch nên phải kiểm lúc chuyển, không lúc đăng ký).
- Chấp nhận nhưng là **rủi ro của issuer** (ghi cho vận hành, Odoo hiện cảnh báo khi đăng ký token theo khai báo):
  `PermanentDelegate` (issuer rút được khỏi token account của Account), freeze authority, `DefaultAccountState=Frozen`,
  `Pausable` (chuyển abort khi pause ⇒ `reverted`), `ScaledUiAmount`/`InterestBearing` (số base unit vẫn đúng, chỉ hiển
  thị khác). `MemoTransfer` trên ATA người nhận ⇒ chuyển abort ⇒ người nhận phải tắt (ví nhận do nền tảng quản lý).
- Quyết định này ảnh hưởng tài sản nào dùng được ⇒ owner xác nhận (OQ3).

---

## 4. Payload ký `MetaOp` v1 và phong bì chữ ký

### 4.1 Bytes (337 B, cố định, little-endian, không tiền tố độ dài — bảng cộng ra 337; bản nháp ghi nhầm 336)

| off | len | trường |
|---|---|---|
| 0 | 16 | `"bamboo.metaop.v1"` |
| 16 | 32 | `network` = genesis hash của cluster (đọc từ `Config.network`) |
| 48 | 32 | `contract` = SubjectAccount PDA (pay) / Mandate PDA (mandate_pay, revoke) |
| 80 | 32 | `asset` = mint |
| 112 | 1 | `op`: 0 pay · 1 trade (dành chỗ) · 2 mandate_pay · 3 revoke |
| 113 | 32 | `from` = owner |
| 145 | 32 | `to` = ví nhận (owner của ATA đích; revoke: 32 byte 0) |
| 177 | 16 | `amount` u128 (≤ u64::MAX — Odoo từ chối lớn hơn) |
| 193 | 32 | `pay_ref` (entryRef) |
| 225 | 32 | `lane` |
| 257 | 8 | `nonce` u64 |
| 265 | 8 | `valid_until` u64 giây unix, so với `Clock.unix_timestamp` |
| 273 | 32 | `relayer` (0 = lane nào cũng nộp; khác 0 = đúng fee payer) |
| 305 | 32 | `extra` = H(tham số riêng op) hoặc 0 |

- **`digest = sha256(bytes)`** (syscall `sol_sha256` rẻ; trùng hàm băm của WebAuthn) — khoá thao tác trong
  `MetaTransactionExecuted.digest`, Odoo chốt `blockchain.signed.op` theo nó.
- Program **dựng lại** bytes: `contract`, `from`, `asset`, `network` lấy từ account đã kiểm seeds (không từ instruction
  data); chỉ `to, amount, pay_ref, lane, nonce, valid_until, relayer, extra` đi trong data ⇒ relayer không đổi được
  trường nào mà chữ ký vẫn qua.
- **Tách miền — RS12-8:** program **không đọc được** genesis hash on-chain (không có sysvar) ⇒ `network` lưu trong
  `Config` lúc `initialize`; **adapter kiểm `getGenesisHash` = `Config.network` = `network` của chain trong Odoo lúc
  khởi động**, lệch ⇒ từ chối chạy. Thêm `contract` (PDA phụ thuộc program id) + `op` + `asset`. Cùng một keypair
  program deploy trên hai cluster vẫn khác `network`.
- Replay: lane PDA (pay), `MandateRef` (mandate), `Fill` (DEX). Hạn: `Clock.unix_timestamp <= valid_until`.

### 4.2 Văn bản được ký và phong bì — RS12-9

- Văn bản `T = "bamboo.metaop.v1:" ‖ hex(digest)` (81 byte ASCII, hex chữ thường). Lệnh DEX: `"bamboo.order.v1:"…`,
  huỷ: `"bamboo.cancel.v1:"…`, KeyOp: `"bamboo.keyop.v1:"…`, mandate: `"bamboo.mandate.v1:"…`.
- **ed25519 — hai phong bì, program nhận cả hai**, so khớp **nguyên văn** message trong precompile:
  - `kind 0` raw — `solana:signMessage(T)`: message = `T`. Không nhầm được với tx: byte đầu `'b'` = 0x62 sẽ là header
    legacy đòi 98 chữ ký (v0 bắt đầu 0x80, v1 0x81) — không bao giờ parse thành tx hợp lệ với 81 byte.
  - `kind 1` off-chain message (OCMS v1) — `solana:signOffchainMessage`: message = `"\xffsolana offchain"` ‖ version 1 ‖
    số signer = 1 ‖ pk32 ‖ `T` (bố cục byte chính xác ghim bằng vector từ `@solana/kit` ở Task 0). Đây là định dạng ví
    cứng (Ledger/Trezor) ký; tài liệu Solana khuyên dùng khi ví hỗ trợ, nếu không thì raw.
    [solana.com/docs/frontend/messages-and-auth]
- **passkey — `kind 2`**: challenge = base64url(digest) không padding; precompile secp256r1 nhận message =
  `authenticatorData ‖ sha256(clientDataJSON)`; program kiểm `clientDataJSON` chứa đúng một `"type":"webauthn.get"`,
  `"challenge":"<b64url(digest)>"`, `"origin":"<o>"` với `o ∈ origins` (ngoại lệ add_origin §3.3); `rpIdHash` = của khoá;
  cờ UP|UV (`flags & 0x05 == 0x05`); sha256(cdj) = 32 byte cuối message. Low-S do precompile ép; client chuẩn hoá
  `s := n − s` (round-3 §C).
- **Blob chữ ký** (connector → Odoo → job → relayer): `signature = hex(kind ‖ key_index ‖ sig64 ‖ [authData_len u16 ‖
  authData ‖ cdj])`, `public_key = hex(pk)` (32 hoặc 33 B). Relayer dựng instruction precompile từ blob.
- **Ví seed (R32)**: ký `kind 0` bằng `m/44'/501'/i'/0'` (§6.1).

### 4.3 Introspection precompile — cách program kiểm chữ ký (RS12-10)

Instruction của ta mang `Auth{kind, key_index, precompile_ix: u8, sig_index: u8, cdj?}`. Program:
1. `load_instruction_at_checked(precompile_ix, instructions_sysvar)` (Anchor ràng `address = sysvar::instructions::ID`
   — chặn lỗi giả sysvar kiểu Wormhole 2022); program id phải đúng Ed25519 (`kind 0/1`) hoặc Secp256r1 (`kind 2`);
   `precompile_ix < load_current_index_checked()`.
2. Parse header: `num_signatures`, offsets thứ `sig_index`; **cả ba** `*_instruction_index` phải = `u16::MAX` (dữ liệu
   nằm trong chính instruction precompile) và mọi offset nằm trong data.
3. pk trích ra = `account.keys[key_index].pubkey`; message trích ra = message kỳ vọng (`T`, `OCMS(pk,T)`, hoặc kiểm
   WebAuthn bên trên).
Precompile đã xác minh chữ ký ở tầng runtime (sai ⇒ cả tx thất bại). Hai instruction của ta trỏ cùng một chữ ký chỉ
kiểm lại cùng một op — lần hai chạm replay. Lỗi "absolute index" (secure-contracts.com, *Improper Instruction
Introspection*) không áp dụng vì ta so **nguyên văn** pk + message, không chỉ "có một ix ed25519".

### 4.4 Tái lập ở ba ngôn ngữ

| | Dựng bytes | digest | phong bì | kiểm |
|---|---|---|---|---|
| Program (Rust SBF) | ghép theo bảng §4.1 | `solana_program::hash::hashv` (sha256) | `auth::expected_message` | precompile + introspection |
| Python `fam_solana` | ghép byte (stdlib) | `hashlib.sha256` | cùng quy tắc | `cryptography` Ed25519 (kind 0/1) |
| Rust adapter | chỉ decode payload job (proptest) + vector | `sha2` (đã là dependency) | không dựng — dựng ix precompile từ blob | không (mô phỏng phân xử) |
| JS connector | dùng `terms.text` của Odoo | — | kiểm `signedMessage` trả về đúng `T`/OCMS trước khi gửi | — |

Vector chéo: `chains/solana/scripts/gen_vectors.py` sinh `programs/bamboo/tests/vectors.rs` (payload, digest, T, OCMS,
chữ ký thật từ khoá cố định, PDA Account/lane/mandate/fill, ATA) — Python test và adapter test ghim **cùng** hex.

---

## 5. Instruction của program

### 5.1 Account + pay

- `relay_pay(to, amount, pay_ref, lane, nonce, valid_until, relayer, extra, auth)` — accounts: lane signer (fee payer),
  Config, SubjectAccount (init lười), LanePda, nguồn, ATA đích (`create_idempotent` nếu thiếu — rent do lane trả, một lần
  mỗi (ví, mint)), mint, token program, Instructions sysvar, system/ATA program, event authority. Kiểm miền/hạn/relayer/
  lane/khoá/phong bì/policy; `amount > 0`; chính sách extension (§3.6); `transfer_checked`; `emit_cpi!`
  `MetaTransactionExecuted{contract: mint, account, from, digest, lane, nonce}` rồi `PaymentSettled{contract: mint,
  from, to, amount, pay_ref}`.
- `open`, `open_passkey`, `manage_signed`, `start_recovery` / `finish_recovery`, `prune` — §3.3, §3.4.
- `sweep` không cần: số dư là token account của PDA (§3.2).

### 5.2 Mandate (R25) — RS12-11

- `mandate_open(MandateInit, auth)`: khoá **Account** ký `MandateInit{domain="bamboo.mandate.v1", network, account,
  mandate, asset (mint duy nhất — review M2), delegate_key (ed25519|P-256), max_per_payment, max_per_period, period_s, expiry, payees ≤ 8, nonce=key_nonce,
  valid_until}` ⇒ không tx native của chủ (R30). Cấp vốn = một `pay` thường tới Mandate PDA (`to` = Mandate).
- `mandate_pay(...)`: delegate ký `MetaOp{op: mandate_pay, contract: mandate, asset = mint của mandate, nonce =
  generation}` (`generation` = `key_nonce` lúc mở; đóng rồi mở lại cùng seed ⇒ thế hệ mới, op/revoke cũ không chạy —
  review L4); `to` không được là token account/mint (review L5); hạn mandate, hạn chữ ký, payee, trần
  lần, trần kỳ (so bằng phép trừ — Sui L6), `MandateRef` init (một lần, prunable); event `PaymentSettled` +
  `PaidUnderMandate`.
- `mandate_revoke_signed` (delegate, `op: revoke` — kill switch platform) / `mandate_close_signed` (khoá Account): chuyển
  mọi token account của Mandate về ATA của Account, đóng PDA (rent về `rent_payer`). Rút được sau revoke/hết hạn.

### 5.3 DEX (R35) — RS12-12

- `Order` (bytes cố định): `domain="bamboo.order.v1", network, market, maker (owner), taker (0 = any), sell mint, buy
  mint, sell_amount u64, buy_amount u64, nonce u64, expiry, max_fee_ppm u32, flags u8 (bit0 FOK, bit1 IOC), relayer`;
  `order_hash = sha256(bytes)`, văn bản ký `"bamboo.order.v1:" ‖ hex(order_hash)`.
- `settle(a, b, hash_a, hash_b, fill_a, fill_b, auth_a, auth_b)` — MỘT cặp mỗi instruction (account kiểu Anchor,
  không `remaining_accounts` tự kiểm); batch = nhiều instruction `settle` trong một tx, nguyên tử theo tx (RS12-12a,
  đã thực thi). **Kiểm cả hai chữ ký trong chính tx** (như EVM), mỗi cặp: flags, hạn, `nonce >=
  MinNonce`, relayer, taker, khoá ∈ keys của maker/taker, cặp khớp chéo với market, hai bên khác nhau, market bật;
  `fill > 0`, `Fill.filled + fill <= sell_amount`, FOK; giá nhân chéo trên u128; phí ppm ≤ `max_fee_ppm`, trần 10 000 ppm
  kiểm ở `set_market`. Tiền đi token account Account→Account, phí vào vault của market. `fill` do relayer chọn nhưng bị
  chặn bởi giá và lượng đã ký (L3). Event `OrderFilled` ×2 + `Matched`. IOC: phần còn lại đóng (`filled = sell_amount`)
  trong chính `settle`.
- **Batch:** nhiều cặp mỗi tx, giới hạn bởi tx v1 (4 096 B, ≤ 64 account inline) và CU (1,4M) — thực tế 2–3 cặp; nguyên
  tử theo tx.
- Huỷ: `cancel_signed` (`Cancel{domain="bamboo.cancel.v1", network, market, order_hash}`) ⇒ `Fill.filled = sell_amount`
  (tạo Fill nếu chưa có — lệnh chưa từng khớp vẫn không bao giờ settle được); `invalidate_nonces_signed` ⇒ `MinNonce`
  tăng nghiêm ngặt. Chỉ chạm market đó.
- `sweep(market, mint)` không cần quyền: mọi thứ gửi nhầm vào token account của Market ngoài vault phí ⇒ `fee_recipient`.
- **Lệch so với EVM:** (1) vault phí theo market (account ghi chung của market — `ponytail:` tách N vault khi một market
  chạm trần 12M CU/block); (2) không phí relayer (§D.0); (3) ATA phía nhận được `create_idempotent`, rent do lane trả.

### 5.4 Admin

`Config.admin` (production: multisig). Chỉ admin: `list_market`, `set_market` (phí, bật/tắt). Admin **không** chạm
SubjectAccount/Mandate. `initialize` chỉ upgrade authority (chống front-run init).

### 5.5 Vì sao Anchor (không native/Pinocchio) — RS12-13

- Lớp lỗi lớn nhất của program Solana là **thiếu kiểm account** (owner, signer, seeds/bump, discriminator — "type
  cosplay", sysvar giả). Anchor sinh các kiểm đó từ ràng buộc khai báo; `token_interface` lo cả hai token program;
  `emit_cpi!` cho event không bị cắt (log có thể bị truncate). Native/Pinocchio rẻ CU hơn nhưng mọi kiểm viết tay — rủi ro
  kiểm toán cao hơn, mà ngân sách CU của ta dư (ước pay 40–80k CU, cặp settle ~150–250k, trần 1,4M).
- Ghim **Anchor 1.x** (bản ổn định đầu tiên, OtterSec + Solana Foundation bảo trì; `anchor test` 1.0 dùng Surfpool) —
  phiên bản chính xác chốt ở Task 0. Không cần `anchor` CLI: build bằng `cargo build-sbf`, test bằng LiteSVM trong
  `cargo test` (không validator ⇒ nhẹ RAM). Anchor v2 (alpha) không dùng.

---

## 6. Relayer (`adapters/solana.rs`)

### 6.1 Lane — RS12-14

- Khoá ed25519 SLIP-10 **`m/44'/501'/{i}'/0'`** (coin 501, mọi cấp hardened) — quy ước Phantom/Solflare và
  `solana-keygen … prompt://?full-path=m/44'/501'/0'/0'`; ví thứ hai của Phantom là `m/44'/501'/1'/0'`. (Ledger Live
  dùng `m/44'/501'/i'` ba cấp — không chọn.) Cần một dòng ở `keys.rs::lane_path` (lead) — §12.
- Địa chỉ lane = pk base58. Lane cần SOL. Khởi động in địa chỉ lane (R60).
- **Durable nonce mỗi lane:** nonce account = `create_with_seed(lane, "bamboo-nonce-v1", SystemProgram)` (địa chỉ tất
  định, không thêm keypair), authority = lane. Thiếu ⇒ adapter tự tạo (một tx setup do chính lane trả) ở lần
  `sequence(lane)` đầu. `ponytail:` side-effect trong `sequence`, đủ vì chỉ chạy một lần mỗi lane.
- **Vì sao durable nonce, không recent blockhash:** shared runner (`recover_lane` / `follow`) coi "sequence của lane đổi
  mà tx vẫn không thấy ⇒ tx không bao giờ vào nữa". Với nonce account đó là **đúng nguyên văn**: nonce đổi ⇔ có tx dùng
  nó đã vào sổ (thành công hay lỗi). Với blockhash thì "không bao giờ vào nữa" ⇔ `block_height > lastValidBlockHeight` —
  không biểu diễn được bằng phép so `!=` của runner nếu không đổi code chung. Thêm: mọi bản dựng lại của cùng job dùng
  **cùng** giá trị nonce ⇒ tối đa một tx vào sổ (như sequence EVM) ngay cả khi bytes cũ còn trôi đâu đó.
- **Phương án dự phòng nếu durable nonce bị deprecate** (discussion SIMD #415): recent blockhash + một hook mặc định
  trong trait `async fn sequence_moved(&self, lane, journaled) -> Result<bool>` (mặc định `sequence != journaled`;
  Solana: `finalized block_height > journaled` với `journaled = lastValidBlockHeight`). Chưa xây.

### 6.2 Dựng tx tại chỗ — RS12-15

- **Tx v1** (SIMD-0385 + SIMD-0296: 4 096 B, mainnet/devnet/testnet từ 2026-09-15, epoch 1035): byte 0 = `0x81`; giới
  hạn CU / loaded-accounts / priority fee nằm ở **header** (bắt buộc đặt); ≤ 64 địa chỉ inline, không ALT, không trùng
  địa chỉ; chữ ký ở **cuối**; `LifetimeSpecifier` = trường recent blockhash cũ ⇒ chứa giá trị durable nonce. Gửi bằng
  `encoding: "base64"` (base58 vẫn trần 1 232 B). Lý do v1: tx passkey (clientDataJSON của Chrome có thể kèm trường
  `other_keys_can_be_added_here` dài ~110 B) và `settle` hai chân vượt 1 232 B của v0/legacy.
- Viết tay (không crate `solana-sdk` — cây phụ thuộc lớn, rủi ro OOM khi build trên máy chung; như RS11-7): header,
  config, địa chỉ, lifetime, instruction (`AdvanceNonceAccount` đầu tiên, precompile, `bamboo::*` với discriminator
  Anchor `sha256("global:<name>")[..8]`), chữ ký lane. Crate đã có: `ed25519-dalek` (ký + kiểm off-curve cho PDA qua
  `VerifyingKey::from_bytes`), `sha2`, `bs58`, `base64` — **không thêm crate**.
- `tx_id` = `0x` + hex(chữ ký lane 64 B) — tính trước khi gửi để journal `signed`; đổi sang base58 khi gọi RPC.
- Vector: message v1 + chữ ký ghim từ `@solana/kit` ≥ 8.0 (`npm i` cục bộ trong `chains/solana/scripts/`, script
  `tx_vector.mjs`, không commit `node_modules`); e2e đối chiếu chữ ký RPC trả về.
- Tx của Odoo không bao giờ quá `valid_until`: program tự từ chối op hết hạn (Clock), nonce không có hạn riêng.

### 6.3 Mô phỏng, phí, số dư (R55)

- `simulateTransaction(tx, {sigVerify:false, replaceRecentBlockhash:false, commitment:"confirmed"})`: `err` do program
  `bamboo` (custom error) ⇒ `SimError::Revert` (job chết); lỗi HTTP/5xx/429 ⇒ `Transport`.
- `cu_limit = ceil(unitsConsumed × 1.2)`, trần `params.max_cu`; priority fee (tổng lamport, v1) = `cu_limit ×
  p75(getRecentPrioritizationFees(writable accounts))/10^6`, trần `params.max_priority_lamports`. Nhờ §2.4 các account
  writable của ta ít tranh chấp ⇒ phí cục bộ thấp.
- `lane_balance` = `getBalance(lane)`; `tx_fee` = `meta.fee` của `getTransaction`.
- `sequence(lane)` = 8 byte đầu của giá trị nonce (commitment `confirmed`) đọc LE, `& 0x7FFF_FFFF_FFFF_FFFF` (cột
  `outer_nonce` là `int8`). `sign` đọc lại nonce account và từ chối nếu không khớp `sequence` (lỗi thường, thử lại).

### 6.4 Gửi, trạng thái, `Rejected` — RS12-16

- `sendTransaction(base64, {skipPreflight:false, preflightCommitment:"confirmed", maxRetries: 0})`.
  - ⇒ `adapter::Rejected`: nonce không khớp / `BlockhashNotFound` (nonce đã advance), `InsufficientFundsForFee`,
    `InsufficientFundsForRent`, `SignatureFailure`, preflight `InstructionError` (dựng lại; mô phỏng ở lần dựng sau
    quyết định `dead`).
  - `AlreadyProcessed` ⇒ coi như đã gửi. 429/5xx/timeout ⇒ lỗi thường (gửi lại cùng bytes).
- **Tự rebroadcast:** RPC hay rớt tx khi nghẽn; adapter giữ bytes trong bộ nhớ theo `tx_id` và `tx_status` gửi lại cùng
  bytes (≤ 1 lần / 2 s) khi trạng thái còn `null` và nonce chưa đổi. `ponytail:` rebroadcast trong `tx_status`, tách
  task riêng khi cần nhiều RPC song song.
- `tx_status`: `getSignatureStatuses([sig], {searchTransactionHistory:true})`:
  - `null` ⇒ `Unknown`; chỉ `processed` ⇒ `Pending`; `confirmed`/`finalized` + `err=null` ⇒ `Mined{height: slot}`;
  - `InstructionError(i, Custom(_))` với `i` = instruction `bamboo` (kể cả lỗi token program trong CPI) ⇒
    `Reverted` (op sai/đã dùng/thiếu số dư);
  - `ComputationalBudgetExceeded` / `ProgramFailedToComplete` / `InsufficientFundsForRent` ⇒ `Err(Rejected)`: mọi thay
    đổi đã rollback trừ phí và nonce lane; lane PDA người trả còn nguyên ⇒ job về hàng đợi, dựng lại (L3/L4).
- Lane chuyển job tiếp khi `confirmed` (optimistic confirmation); finality cho Odoo đi qua indexer `finalized` (§6.6).

### 6.5 Crash-safe (L5) — RS12-17

- Một tx bay mỗi lane. Mọi tx của lane dùng nonce hiện tại ⇒ **một** tx tối đa vào sổ mỗi giá trị nonce; dựng lại job
  sau `Rejected` dùng lại cùng nonce ⇒ bytes cũ và mới loại trừ nhau.
- Sau restart (bytes mất): `recover_lane` chung — tx thấy ⇒ chốt; nonce đổi mà không thấy tx ⇒ `queued`; nonce không đổi
  ⇒ chờ tới `valid_until + 30 s` ⇒ `dead` (payer ký lại). Không journal đĩa (YAGNI, như RS11-12).
- Rủi ro còn lại: bytes cũ (không hết hạn) vào sổ **sau** khi job bị `dead` mà đồng hồ chain còn `< valid_until` (Clock
  Solana lệch được so với giờ thật). Không trả hai lần: request ký lại dùng **cùng lane** (R9, theo `entryRef`) ⇒ lane
  PDA chặn op thứ hai; ingest chốt request theo event. Ghi ở §11.

### 6.6 Finality, event, indexer — RS12-18

- **Finality:** commitment **`finalized`** (siêu đa số đã root; TowerBFT ~12,8 s). Alpenglow (SIMD-0326, ~150 ms) đã được
  bỏ phiếu 09/2025 nhưng **chưa** lên mainnet (mục tiêu H2 2026) — ngữ nghĩa commitment giữ nguyên, không đổi thiết kế.
- **Đơn vị con trỏ = slot.** `final_head` = `getSlot({commitment:"finalized"})` + hash của block đó; nhiều `rpc_urls`
  ⇒ lấy min slot của quorum và so hash như EVM. `block_hash(s)` = blockhash của block **được sản xuất cuối cùng ≤ s**
  (`getBlocks(s−512, s)` lấy phần tử cuối, rồi `getBlock(…, {transactionDetails:"none", rewards:false})`); slot bị bỏ
  qua là bình thường trên Solana; rỗng ⇒ `Err`.
- **Chọn nguồn (RS12-18):** **JSON-RPC chuẩn** — `getSignaturesForAddress(program_id, {commitment:"finalized", before,
  limit:1000})` phân trang lùi tới khi gặp slot `< from`, rồi `getTransaction(sig, {commitment:"finalized",
  maxSupportedTransactionVersion: 1, encoding:"json"})`. Chạy được trên `solana-test-validator`, trên RPC tự host và
  trên RPC hosted bất kỳ có lịch sử giao dịch — **không API độc quyền**. Loại: Geyser/Yellowstone (cần chạy node RPC
  riêng + plugin — nặng; là đường nâng cấp mainnet), webhook/"enhanced API" của nhà cung cấp (đẩy, khoá nhà cung cấp,
  tính đầy đủ không kiểm được).
- **Đầy đủ:** trang cuối mà slot nhỏ nhất vẫn `≥ from` và hết dữ liệu ⇒ kiểm `getFirstAvailableBlock() <= from`, không thì
  `Err` (RPC đã prune lịch sử). Mọi lỗi ⇒ `Err`, vùng không được chốt (Sui L5). Không bao giờ hỏi slot > `finalized`.
- **Lọc:** chỉ tx `meta.err = null`; chỉ **inner instruction** có program id = `params.program_id`, account đầu = event
  authority PDA, data bắt đầu bằng tag event-CPI của Anchor (`0xe445a52e51cb9a1d`) + discriminator event; event
  `MetaTransactionExecuted` / `PaymentSettled` / `PaidUnderMandate` có `contract ∈ contracts` (mint). Chỉ program của ta
  ký được bằng event authority của nó ⇒ program sao chép ở id khác bị bỏ (L2).
- **Chuẩn hoá:** `block_number` = slot, `block_hash` = `0x`+hex(blockhash), `tx_hash` = `0x`+hex(chữ ký 64 B) (cần lead,
  L11), `log_index` = thứ tự event trong tx, địa chỉ base58 chuẩn, `amount` thập phân chuỗi, `entry_ref` = `0x`+hex.
- **Con trỏ bắt đầu:** `blockchain.chain.solana_start_slot` (không đặt ⇒ slot finalized hiện tại).
- `ponytail:` mỗi bước phân trang từ đỉnh xuống `to` — rẻ trên localnet/tải thấp, O(chiều dài tụt hậu) khi bắt kịp trên
  mainnet. Đường nâng cấp: nhớ chữ ký biên trong bộ nhớ; tải cao ⇒ Geyser (OQ2).

### 6.7 Cấu hình node

```toml
[[chains]]
family = "solana"; network = "<genesis hash base58>"
rpc_urls = ["http://127.0.0.1:32020"]
lanes = [0, 1]
[chains.params]
program_id = "<base58>"
max_cu = 600000
max_priority_lamports = 2000000
```

### 6.8 Head-of-line (R62) — dòng cho bảng §B.5

| Họ | Ai gửi tx | Thứ tự phía relayer | Vì sao một tx kẹt không khoá nơi khác |
|---|---|---|---|
| Solana | lane fee payer (ed25519, coin 501) | durable nonce mỗi lane, một tx bay | chủ thể không gửi tx, không có nonce/sequence của chủ thể; lane/nonce là PDA riêng mỗi thao tác; write-set rời nhau ⇒ Sealevel chạy song song |

---

## 7. Odoo (`fam_solana.py`, `models/blockchain_solana.py`)

- `blockchain.chain`: `family='solana'`, `network_key` = genesis hash base58, `chain_key = solana:<genesis>`, `caip2 =
  solana:<32 ký tự đầu của genesis>` (CAIP-2 namespace solana); thêm `solana_program_id`, `solana_start_slot`;
  `solana_config` tính.
- `blockchain.token.address` = mint base58; thêm `solana_token_program` (`spl_token` | `token_2022`) để tính ATA nạp tiền.
- `addresses.canonical('solana')`: base58 giải ra đúng 32 byte, trả lại base58 chuẩn; **không lowercase** (lead, §12).
- `build_terms(request, valid_until)`: amount > u64::MAX ⇒ từ chối; `account = pda(["acct", owner])`;
  `MetaOp{pay, to, amount, pay_ref=entryRef, lane=lane_batch(entryRef), nonce=0, relayer=0, extra=0}` ⇒ `payload`,
  `digest`, `contract = account`, `terms = {text, digest, network, account, asset, ocms_ok: true}`, `extra = {asset,
  token_program}`.
- PDA trong Python: sha256 + kiểm "off-curve" bằng giải nén điểm ed25519 thuần Python (~20 dòng, RFC 8032 §5.1.3) — vector
  chéo với `Pubkey::find_program_address`.
- `verify(request, payload, signature, public_key)` (L9): tách blob; `kind 2` (passkey) ⇒ `None`; `kind 0/1`: message
  phải đúng `T`/OCMS ⇒ sai thì `False`; ed25519 sai ⇒ `False`; pk = địa chỉ người trả ⇒ `True`; pk khác (khoá thêm sau)
  ⇒ `None`. Không bao giờ `True` cho khoá không chứng minh được.

## 8. Portal (`connectors/solana.js`)

- Wallet Standard thuần (`wallet-standard:register-wallet` / `app-ready`, cùng cơ chế `sui.js`, không thư viện). Chọn
  ví có `standard:connect` + (`solana:signOffchainMessage` v1 **hoặc** `solana:signMessage`); `chains` của account phải
  chứa `solana:<genesis32>` tương ứng (mainnet/devnet/testnet; localnet bỏ qua).
- `connect()` ⇒ `{address, publicKey}` (32 B). `sign(terms)`: ưu tiên `signOffchainMessage` (kind 1), không có thì
  `signMessage(T)` (kind 0); kiểm `signedMessage` trả về đúng bytes kỳ vọng **trước khi** gửi; trả `{signature:
  hex(kind‖key_index‖sig64), publicKey}`. `key_index` = 0 cho khoá chủ; khoá thêm sau do UI S4 chọn.
- Passkey Solana dùng signer passkey chung của S4 (challenge = b64url(digest), blob `kind 2`).
- Ví seed (R32): `clientkeys` thêm `m/44'/501'/i'/0'` + ký `T` (S4 sở hữu ⇒ "needs from S4", §12).
- Test `node --test` với ví giả: có/không OCMS, ví trả message khác, chain sai, khoá không 32 B, từ chối.

---

## 9. Kiểm thử

**Program (LiteSVM trong `cargo test`, `.so` từ `cargo build-sbf`):**
- pay: vector thật, replay (lane), hạn, sai `network`/`contract`/`asset`/`op`, relayer ràng buộc, khoá ∉ keys,
  `kind 0` và `kind 1`, message lệch một byte, precompile trỏ `instruction_index` ≠ `u16::MAX` ⇒ từ chối, ix không phải
  precompile ⇒ từ chối, mở lười, nguồn là token account không-ATA của PDA.
- passkey: vector WebAuthn thật (authenticator phần mềm, khoá P-256 cố định), high-S bị precompile chặn, sai origin,
  thiếu UV, `open_passkey` chống origin giả, add_origin cùng rpId bằng chính passkey.
- khoá: thêm/xoá, không xoá khoá cuối, guardian + trễ, huỷ khôi phục; policy backup: bật khi thiếu ⇒ từ chối; bật rồi
  xoá khoá ⇒ từ chối.
- Token-2022: mint có transfer fee > 0 ⇒ abort; transfer hook có program ⇒ abort; NonTransferable ⇒ abort;
  PermanentDelegate ⇒ chuyển được.
- mandate: trần lần/kỳ, payee, `pay_ref` một lần, revoke, close về Account. DEX: giá, overfill, FOK/IOC, phí bật/tắt,
  `max_fee_ppm`, huỷ (kể cả lệnh chưa từng khớp), `MinNonce` theo market, hai market độc lập, batch 2 cặp.
- **Anti-lock (bắt buộc):** chủ thể ký X (`relay_pay` tài sản A) và Y (`mandate_pay` / DEX `cancel_signed`); giữ X;
  Y qua; rồi X qua. Thêm: cùng Account, hai tài sản, hai lane.
- **Write-set (L12):** dựng tx X và Y thật (qua code adapter hoặc builder test), assert tập account writable trừ lane +
  nonce lane **rời nhau**; và `Config`, `Market`, `SubjectAccount` readonly trong mọi tx đường nóng.
- **Anti-lock coin (L7):** SPL tới ATA Account (trước/sau khi Account tồn tại), tới token account phụ của PDA, tới Mandate;
  `sweep` market; lamports thừa ⇒ `withdraw_lamports`.
- `prune`: chỉ sau hạn, rent về `rent_payer`, op cũ không replay được.
- Nếu LiteSVM chưa có precompile secp256r1 (kiểm ở Task 0), test passkey chạy trên `solana-test-validator` trong e2e.

**Rust adapter:** proptest decoder payload job + blob chữ ký; vector message v1 + chữ ký (`@solana/kit`); PDA/ATA =
Python; phân loại `Rejected`/`Reverted`/hết CU trên JSON ghi lại; event của program khác / `contract ∉ contracts` bị bỏ;
trang `getSignaturesForAddress` thiếu lịch sử ⇒ `Err`.

**e2e `tests/e2e_solana.rs` (`#[ignore]`, `solana-test-validator`):** hai lane từ mnemonic 24 từ, airdrop, nonce account
tự tạo, program nạp sẵn ở genesis (`--upgradeable-program`), `initialize` với genesis hash thật, tạo mint SPL + một mint
Token-2022, Odoo giả trả mint thật + từ chối mint lạ, thanh toán qua `lane_step`, final qua `index_step`, anti-lock đồng
thời (X `signed` giữ lane 0, Y `mined` lane 1), restart giữa chừng (`recover_lane`), `Rejected` (nonce đã advance) trả
lane ngay, token rỗng ⇒ con trỏ đứng yên; chữ ký tự tính = chữ ký RPC.

**Odoo** (`dms_test_chain_12`/8932): vector chéo Python = program = adapter; `verify` ba nhánh; PDA/ATA; base58 không bị
lowercase qua `relay_report`; issue → accept → job `signed_op` với `extra.asset`.

**Devnet:** `solana-test-validator --reset --quiet --ledger $SP/solana-ledger --bind-address 127.0.0.1 --rpc-port 32020
--faucet-port 32022 --gossip-port 32023 --dynamic-port-range 32024-32050` (WebSocket tự lấy 32021; Agave 4.3 từ chối
dải < 26 cổng — OQ4 đã chốt ở §18). Validator cục bộ bật
mọi feature mặc định — Task 0 kiểm bằng `solana feature status -u http://127.0.0.1:32020` rằng secp256r1 và tx v1 đã bật.
**Chưa kiểm:** độ rộng tối thiểu của `--dynamic-port-range` (6 cổng có thể không đủ) ⇒ OQ4. Một validator mỗi lúc,
`free -g` trước; `cargo build-sbf` biên dịch Anchor + Solana crates (nặng RAM) — `CARGO_BUILD_JOBS=2`, không chạy song
song với build nặng của luồng khác (S11).

## 10. Thanh toán bảo mật — khả thi

Token-2022 có extension **ConfidentialTransfer** (ElGamal twisted trên Ristretto/curve25519 + range proof qua program ZK
ElGamal Proof). Program proof bị **tắt trên mainnet 2025-06-19** (epoch 805) sau lỗi cho phép dựng proof giả; có audit
Code4rena 08–09/2025, và tin 2026 cho biết confidential transfer đã quay lại mainnet — **chưa kiểm** chi tiết. Nếu bật, đây
là đường bảo mật số dư gốc của Solana (khác đường cong Zether EVM — bn254/BLS12-381, R33 ⇒ cây khoá riêng; proof sinh
phía client nặng). Không xây ở round này (R34 §5).

## 11. Rủi ro, seam

- Durable nonce có thể bị deprecate (SIMD discussion #415) ⇒ phương án §6.1.
- Rent bị khoá trong lane/mref/fill PDA tới khi `prune` (~0,0012 SOL mỗi thao tác); node chưa tự crank `prune` — seam
  (HANDOFF): script/cron gọi `prune` theo `rent_payer` = lane. Rent ATA người nhận tạo hộ không thu lại được.
- Người nhận nóng: mọi thanh toán tới cùng một ví ghi chung ATA đó (12M CU/block).
- Clock Solana lệch so với giờ thật (§6.5) — at-most-once do lane PDA giữ.
- Mint có transfer hook / transfer fee: không dùng được (OQ3). Issuer có permanent delegate / freeze / pause: rủi ro
  issuer.
- RPC hosted cắt lịch sử hoặc giới hạn `getSignaturesForAddress` ⇒ indexer báo lỗi, không chốt sai (OQ2).
- Front-run sao chép tx: chủ thể ký op chứ không ký tx; kẻ chép tx của lane phải là lane (fee payer ký) ⇒ không chép được
  nguyên tx; chép op sang tx riêng (nếu `relayer = 0`) chỉ làm thay việc của ta (op chạy đúng một lần), mất phí cho họ.
- v1 mới (09/2026): RPC/SDK cũ chưa nhận ⇒ adapter báo lỗi rõ; không fallback v0 (YAGNI — bật lại khi gặp RPC thật).

## 12. Cần từ chủ sở hữu file khác (không sửa trong luồng)

- **Lead (S1), commit tiên quyết:**
  - `adapter.rs`: `Family::Solana` + `parse("solana")`; **sửa test `families_parse`** (hiện assert `parse("solana") ==
    None`).
  - `keys.rs::lane_path`: `"solana" => (Ed25519, "m/44'/501'/{i}'/0'")` + vector (mnemonic `abandon…art`, đối chiếu
    `solana-keygen pubkey "prompt://?full-path=m/44'/501'/0'/0'"`).
  - `config.rs` (`uses_adapter`, `validate` nhận `network` = genesis base58); một arm ở `adapters/mod.rs` (luồng thêm).
  - Odoo: `FAMILIES` + `addresses.canonical('solana')` (base58 32 B, không lowercase); **ingest chấp nhận `tx_hash` =
    `0x`+128 hex cho họ `solana`** (hiện `_hex32`); field `solana_*` trên form chain/token; `node.example.toml` mẫu Solana;
    `chain_pay.js` nạp connector.
- **S4:** `clientkeys` đường dẫn 501 + ký `T`; định nghĩa chính sách "backup key required" ở Odoo/portal (OQ1);
  signer passkey dùng chung (challenge = b64url(digest)).
- **Coordinator:** cổng devnet (OQ4); lịch build nặng không chồng với S11.

## 13. Rulings

- **RS12-1** Đường chính = meta-tx cấp program; chủ thể không bao giờ gửi tx trên đường nóng; fee payer gốc chỉ cho lane.
- **RS12-2** Write-lock là khoá thật: đường nóng chỉ ghi PDA riêng thao tác + token account hai bên; Config/Market/
  SubjectAccount readonly; test write-set bắt buộc.
- **RS12-3** Một SubjectAccount PDA mỗi chủ thể cho mọi mint; số dư = token account có owner = PDA (không sổ nội bộ).
- **RS12-4** ≤ 8 khoá (ed25519 / P-256 WebAuthn), ≤ 8 origin, guardian + trễ 2 ngày; add_origin cùng rpId do chính passkey
  ký; `open_passkey` đòi assertion.
- **RS12-5** Policy `BACKUP_REQUIRED` (bit0, mặc định OFF), chủ tự bật/tắt; backup = ≥ 2 khoá hoặc 1 khoá + guardian.
- **RS12-6** Lane/nonce = PDA mỗi (account, lane), `prune` không cần quyền sau `valid_until + PRUNE_DELAY_S` (30 ngày,
  review C1), rent về `rent_payer`.
- **RS12-7** SPL Token + Token-2022 qua `token_interface`; abort NonTransferable, transfer hook có program, transfer fee > 0.
- **RS12-8** Miền = genesis hash lưu ở `Config` (adapter đối chiếu `getGenesisHash` lúc khởi động) + PDA + op + asset.
- **RS12-9** Văn bản ký `"<domain>:" ‖ hex(sha256)`; ed25519 nhận raw và OCMS v1; passkey challenge = b64url(digest).
- **RS12-10** Introspection: `load_instruction_at_checked`, đúng program precompile, mọi instruction index = `u16::MAX`,
  so nguyên văn pk + message.
- **RS12-11** Mandate mở bằng chữ ký khoá Account; `pay_ref` một lần bằng PDA `mref` prunable.
- **RS12-12** DEX: kiểm cả hai chữ ký trong `settle`; `Fill` PDA mỗi lệnh; vault phí theo market; huỷ tạo/đóng `Fill`.
- **RS12-13** Anchor 1.x, `cargo build-sbf` + LiteSVM; không Anchor v2 alpha, không native.
- **RS12-14** Lane = ed25519 `m/44'/501'/{i}'/0'`, durable nonce account `create_with_seed(lane,"bamboo-nonce-v1")`,
  `sequence` = nonce, một tx bay.
- **RS12-15** Tx v1 viết tay, không `solana-sdk`, không crate mới; vector từ `@solana/kit`.
- **RS12-16** Bảng `Rejected`; hết CU / thiếu rent đã vào sổ ⇒ `Rejected`; lỗi của `bamboo` ⇒ `Reverted`; tự rebroadcast.
- **RS12-17** Không journal đĩa; durable nonce + `recover_lane` chung đủ.
- **RS12-18** Finality `finalized`, cursor = slot; indexer JSON-RPC chuẩn (`getSignaturesForAddress` + `getTransaction`),
  event qua `emit_cpi!`, lọc program id + event authority + `nc.tokens`; thiếu lịch sử ⇒ lỗi.

## 14. Quyết định owner áp cho luồng này (đã có, 2026-10-04)

- Thứ tự mạng: Solana là mạng thứ tám, sau Aptos.
- Gasless: meta-tx cấp contract **ưu tiên** hơn fee payer gốc (§2) — lane/nonce theo contract, relayer nhiều lane.
- Lane relayer: ed25519 từ cùng mnemonic 24 từ, coin 501 (§6.1).
- Passkey: dùng precompile secp256r1 qua introspection; seed ed25519 qua Ed25519 program; Account nhiều khoá + origin +
  guardian, không gạch; toggle "backup key required" mặc định OFF (§3.3).
- Indexer: danh sách contract từ `node_config`; không tiến con trỏ khi rỗng hoặc vùng chưa final; finality = `finalized`.
- e2e trên validator cục bộ; DB `dms_test_chain_12` / 8932; cổng 32020–32049 (§18). Trung lập thị trường.

## 15. Câu hỏi mở

- **OQ1 (owner, cùng S4) — ngữ nghĩa "backup key required".** Đề xuất: backup = ≥ 2 khoá hoặc 1 khoá + guardian; bit
  on-chain do chủ bật; khi bật chặn xoá làm mất backup và chặn thao tác giá trị nếu thiếu. Thay thế: chỉ ép ở portal
  (không on-chain). Cần khớp định nghĩa S4.
- **OQ2 (owner/vận hành) — nguồn indexer mainnet.** Đề xuất: JSON-RPC chuẩn qua RPC hosted có lịch sử (như lựa chọn
  hosted của Aptos, nhưng API chuẩn, đổi nhà cung cấp được); Geyser/Yellowstone tự chạy khi tải cao.
- **OQ3 (owner) — chính sách Token-2022.** Đề xuất §3.6 (từ chối transfer hook đang hoạt động, transfer fee > 0,
  NonTransferable; nhận permanent delegate/freeze/pause như rủi ro issuer). Ảnh hưởng stablecoin nào dùng được.
- **OQ4 (coordinator) — cổng.** `solana-test-validator` cần dải `--dynamic-port-range`; nếu 32024–32029 (6 cổng) dưới mức
  tối thiểu thì cần cấp thêm dải.
- **Kiểm khi làm (không cần owner):** trạng thái feature secp256r1 + v1 (`solana feature status`); bố cục byte OCMS v1;
  LiteSVM có precompile secp256r1 không; phiên bản Anchor 1.x; durable nonce trong tx v1 trên validator cục bộ;
  confidential transfer đã bật lại chưa.

## 16. Nguồn

- Precompile: solana.com/docs/core/programs/precompiles; SIMD-0075 (github.com/solana-foundation/solana-improvement-documents
  `proposals/0075-precompile-for-secp256r1-sigverify.md`, *Implemented*); helius.dev/blog/solana-passkeys.
- Durable nonce: solana.com/docs/core/transactions/durable-nonces (deprecation note → discussion #415); SIMD-0242
  (static nonce account, *Implemented*); SIMD-0297 (relax invalid nonce, *Review*).
- Tx v1 / kích thước: solana.com/upgrades/larger-transaction-sizes (SIMD-0296, SIMD-0385; kích hoạt 2026-09-15 epoch 1035).
- Phí: solana.com/docs/core/fees/fee-structure; helius.dev/blog/solana-local-fee-markets; solana.com/upgrades/100m-cu-blocks
  (SIMD-0286; 12M CU/account writable).
- Finality/Alpenglow: solana.com/upgrades/alpenglow; SIMD-0326.
- Ký thông điệp: solana.com/docs/frontend/messages-and-auth (OCMS, `solana:signOffchainMessage`, `solana:signMessage`).
- Introspection: solana.com/docs/core/instructions/instruction-introspection; secure-contracts.com (Improper
  Instruction Introspection).
- Đường dẫn khoá: monadical.com/posts/export-phantom-wallet.html (`m/44'/501'/0'/0'`, `solana-keygen prompt://?full-path=`).
- Indexer: `getSignaturesForAddress` (helius.dev/docs/api-reference/rpc/http/getsignaturesforaddress — commitment
  `confirmed|finalized`, limit ≤ 1000, `before`/`until`).
- Anchor: anchor-lang.com/docs/updates/release-notes/1-0-0; solana.com/docs/programs/anchor-events (`emit_cpi!`);
  solana.com/docs/tools/litesvm.
- Token-2022: solana.com/docs/tokens/extensions. ZK ElGamal: solana.com/news/post-mortem-june-25-2025.

## 17. Review log

- Self-review: (1) đổi DEX từ "đăng lệnh on-chain trước" sang kiểm chữ ký inline sau khi xác nhận tx v1 4 096 B đã lên
  mainnet — một đường kiểm duy nhất, gần EVM; (2) thay bảng lane trong Account bằng PDA mỗi lane để Account readonly
  (write-lock); (3) phát hiện `_apply_report` lowercase `tx_hash` và `_hex32` của ingest ⇒ `tx_id` hex 64 B + yêu cầu lead
  (L11); (4) chọn durable nonce vì khớp nguyên văn `recover_lane`, ghi phương án dự phòng do cảnh báo deprecate.
- Self-review khi thực thi: (5) `open(owner)` không cần quyền cho phép bất kỳ ai mở trước id passkey-first
  `sha256("bamboo.owner.p256" ‖ pk)` bằng một khoá ed25519 ⇒ gạch Account passkey đó. Sửa: `open` đòi chính ví ký; mở hộ
  không cần vì `relay_pay` đầu tiên mở lười bằng chữ ký của chủ (test `open_needs_the_wallet_signature`). (6) `_lane_address`
  của Odoo cũng lowercase địa chỉ lane base58 — sửa cùng commit tiên quyết.
- agy (Gemini, chạy nền trên spec + `adapter.rs`, 2026-10-04 — sau đó hết quota 106 h, không chạy được review nhánh):

| # | Mức | Finding | Xử lý |
|---|---|---|---|
| 1 | critical | Restart: tx rơi + nonce không đổi ⇒ lane giữ tới `valid_until`; tx đã vào sổ mà RPC không còn status ⇒ requeue rồi `dead` | **Nhận phần 1**: `resend_journaled` của Solana advance nonce lane một lần lúc khởi động ⇒ bytes cũ không bao giờ vào sổ, `recover_lane` thấy nonce đổi ⇒ `queued` ngay (e2e: job `signed` chưa gửi ⇒ `queued` < 30 s). **Từ chối phần 2**: `getSignatureStatuses(searchTransactionHistory:true)`; RPC không lịch sử ⇒ job `dead` nhưng indexer vẫn chốt request theo event (`final` thắng `dead`), không trả hai lần |
| 2 | critical | `cancel_signed` không mang hạn lệnh ⇒ prune `Fill` sớm ⇒ lệnh đã huỷ sống lại | Đã tránh khi thực thi: `cancel_signed` nhận **lệnh đầy đủ**, kiểm hash, `Fill.valid_until` = hạn lệnh; prune chỉ sau hạn (test `cancel_even_before_any_fill`) |
| 3 | high | Mở lười buộc SubjectAccount writable mọi tx | Từ chối: account là `UncheckedAccount` không `mut`; adapter chỉ đánh writable khi Account chưa tồn tại (test write-set + `relay_pay_ix`) |
| 4 | high | Token-2022 `MemoTransfer` trên ATA người nhận ⇒ revert | Từ chối (đã nêu §3.6): ví nhận do nền tảng quản lý; mô phỏng bắt lỗi trước khi gửi ⇒ job `dead` với lý do rõ, không tốn phí |
| 5 | high | "Base fee không tính chữ ký precompile" | Từ chối — sai: LiteSVM và validator thật tính 10 000 lamport cho tx 1 chữ ký lane + 1 chữ ký precompile (test `python_signatures_pay…`, e2e) |
| 6 | high | Thiếu account program cho self-CPI; đích không kiểm ATA | Từ chối: `#[event_cpi]` thêm `event_authority` + `program`; chương trình ATA kiểm dẫn xuất trong `create_idempotent` (test `recipient_and_destination…`) |
| 7 | medium | Phân trang `getSignaturesForAddress` O(N²) khi bắt kịp; `getFirstAvailableBlock` > `from` | Nhận là rủi ro đã ghi (`ponytail` §6.6, OQ2 → Geyser); con trỏ bắt đầu ở `solana_start_slot` / slot finalized lúc bật nên `from` không bao giờ trước lịch sử của RPC |
| 8 | medium | Guardian bị lộ không gỡ được khi bật BACKUP_REQUIRED | Đã tránh: `set_guardian(khác)` (thay thế) luôn được; chỉ `set_guardian(None)` làm mất backup bị chặn (test `backup_policy…`) |
| 9 | medium | revoke vs close mâu thuẫn | Làm rõ khi thực thi: revoke (delegate) chỉ đặt cờ; close (khoá Account) chuyển các token account truyền vào rồi đóng PDA; token account sót vẫn thuộc PDA — mở lại cùng seed rồi close lần nữa |
| 10 | low | `getBlocks(s−512, s)` rỗng trên cluster rảnh | Nhận: cửa sổ 2 048 slot |
| 11 | low | `sequence` u64 không chứa đủ 32 byte nonce | Đã thiết kế: `sign` đọc lại nonce account (32 byte) và từ chối nếu 8 byte đầu ≠ `sequence` |

- grok: thử một lần (2026-10-04) — "free Grok Build usage limit" ⇒ không có kết quả.
- Reviewer độc lập: controller chạy sau báo cáo (theo brief, luồng không tự dispatch subagent).

## Quyết định của owner (2026-10-04) — thay thế OQ1–OQ4

- **OQ1 (backup key):** chính sách "bắt buộc khoá dự phòng" = ≥2 khoá HOẶC 1 khoá + guardian; là **bit tuỳ chọn, mặc định TẮT** (owner: "chỉ là option bật/tắt"); cùng ngữ nghĩa với follow-up S4.
- **OQ2 (indexer mainnet):** RPC do nhà cung cấp host qua JSON-RPC chuẩn (`getSignaturesForAddress` + `getTransaction`, `finalized`); Geyser là seam cho sau khi tải lớn.
- **OQ3 (Token-2022):** chặn on-chain mint có transfer hook đang bật, phí chuyển ≠ 0, hoặc NonTransferable; **chấp nhận permanent delegate** (rủi ro thuộc issuer, ghi rõ trong tài liệu và UI).
- **OQ4 (port validator):** coordinator — kiểm tra ở Task 0; nếu `--dynamic-port-range` 6 cổng không đủ thì dùng 32020–32039 và ghi lại.

## 18. Kết quả Task 0 và thực thi (2026-10-04)

**Phiên bản (user space, không sudo):** Agave **4.3.0** (`solana-release-x86_64-unknown-linux-gnu.tar.bz2`, sha256
`c97289a8…3611e8` khớp digest của GitHub release) trong `~/.local/share/solana/install/releases/4.3.0`; `cargo build-sbf`
4.3.0 + platform-tools **v1.57** (rustc 1.95 sbpf); **Anchor 1.2.0** (`anchor-lang`/`anchor-spl` crate, không CLI);
**LiteSVM 0.17.0** (`precompiles`) — kéo crate Agave 4.3 cần **rustc ≥ 1.97.1** cho test host ⇒ `rustup toolchain install
1.97.1` + `chains/solana/rust-toolchain.toml` (chỉ workspace này); `@solana/kit` **8.4.0** cục bộ ở `chains/solana/scripts/`.

**"Kiểm khi làm" đã giải:**

| Hạng mục | Kết quả |
|---|---|
| secp256r1 + tx v1 (`solana feature status`) | validator cục bộ: mọi feature bật từ epoch 0 (SIMD-0075, SIMD-0385, SIMD-0242). Mainnet: secp256r1 epoch 800, SIMD-0242 epoch 890, **tx v1 epoch 1035**; devnet: tx v1 epoch 1140. Alpenglow (SIMD-0326): **chưa** bật mainnet, đã bật devnet epoch 1167 |
| LiteSVM có precompile secp256r1? | **Có** (`agave-precompiles` 4.3, feature `enable_secp256r1_precompile` trong bộ mặc định) ⇒ test passkey (vector Python thật, high-S, origin, UV) chạy trong LiteSVM, không cần e2e |
| Bố cục OCMS v1 | `"\xffsolana offchain" ‖ version 1 ‖ n signer (u8) ‖ pk32×n (sắp tăng) ‖ text UTF-8` (`@solana/offchain-messages` 8.4.0, codec `preamble-v1`); Python = program = connector (vector `OCMS`) |
| Bố cục message/tx v1 | `0x81 ‖ header(3) ‖ config mask u32 ‖ lifetime 32 ‖ n_ix u8 ‖ n_keys u8 ‖ keys ‖ values (priority u64, CU u32, loaded bytes u32, heap u32 theo bit 0-1/2/3/4) ‖ ix headers (program u8, n_acc u8, len u16) ‖ payloads`; tx = message **rồi** chữ ký. Adapter khớp byte-for-byte với codec kit (`tx_vector.mjs`); thứ tự account là lựa chọn của adapter (kit sắp theo collation chuỗi; validator không đòi) |
| Durable nonce trong tx v1 trên validator | chạy (e2e): `AdvanceNonceAccount` đầu, lifetime = giá trị nonce |
| Phí precompile | base fee tính **cả** chữ ký precompile: tx `relay_pay` = 10 000 lamport (LiteSVM và validator thật); 51 580 CU |
| `--dynamic-port-range` tối thiểu (OQ4) | Agave 4.3 đòi **≥ 26 cổng** (gợi ý `32024-32050`); dải 32020–32039 của owner không đủ ⇒ khối S12 = **32020–32049** (RPC 32020, WS 32021, faucet 32022, gossip 32023, động [32024, 32050)). Cần coordinator ghi nhận |
| Confidential transfer bật lại? | Có: feature "Re-enables zk-elgamal-proof program" active mainnet epoch 982, devnet 1055 (§10 vẫn ngoài phạm vi) |
| Vector đường dẫn lane | `solana-keygen pubkey prompt://?full-path=m/44'/501'/{0,1}'/0'` với "abandon … art" = `3Cy3YNTF…aSnx`, `5frqxtii…hcTA` (test `keys::solana_path_matches_solana_keygen`) |

**Lệch so với spec khi thực thi (rulings bổ sung):**
- **RS12-4a** `open` đòi chữ ký của chính ví (§17 self-review 5).
- **RS12-11a** Delegate của Mandate chỉ ed25519 (khoá dịch vụ/HSM nền tảng; passkey không chạy trên server). `revoke`
  (delegate) chỉ đặt cờ; `close` (khoá Account, `"bamboo.mclose.v1" ‖ network ‖ account ‖ mandate ‖ key_nonce ‖
  valid_until`) chuyển các token account truyền vào về Account rồi đóng PDA.
- **RS12-12a** `settle` một cặp mỗi instruction; batch = nhiều instruction trong một tx. `cancel_signed` mang lệnh đầy
  đủ; `invalidate_nonces_signed` ký `"bamboo.minnonce.v1" ‖ network ‖ market ‖ account ‖ min_nonce`. Market một mức
  `fee_ppm` (không tách maker/taker); `sweep` không cần quyền chuyển mọi token account của Market (gồm vault) về
  `fee_recipient`.
- **RS12-9a** Blob passkey: `u16` độ dài authenticatorData là **little-endian**.
- **RS12-16a** Restart: `resend_journaled` của Solana advance nonce lane (agy #1). Lớp `Rejected`/`Reverted`: lỗi ở
  instruction precompile/`bamboo` (chỉ số ≥ 1) ⇒ `Reverted`, trừ hết CU; lỗi ở advance nonce/cấp tx ⇒ `Rejected`.
- **RS12-18a** `block_hash`/`final_head` = block sản xuất cuối ≤ slot trong cửa sổ 2 048 slot; Config đọc ở `confirmed`
  (bất biến sau `initialize`).

**Chưa kiểm (ghi rủi ro):** API chính xác của `solana:signOffchainMessage` trên ví thật (connector giả định
`{account, message, version: 1}` ⇒ `[{signedMessage, signature}]` và kiểm `signedMessage` = OCMS kỳ vọng, sai ⇒ từ chối
trước khi gửi); RPC hosted mainnet (lịch sử `getSignaturesForAddress`, `getTransaction` encoding json của tx v1).

