# Mạng Cosmos (CosmWasm) — thiết kế luồng S9 (R66)

**Ngày:** 2026-10-03 · **Thuộc:** round 3 §D.0, §D.4, §D.6, §B (R58–R62) · **Luồng:** S9 `r3-cosmos`.
Ruling của luồng đánh số `R9-n` (lead đánh số lại khi hợp nhất).

**Trạng thái (rev 1.1, 2026-10-07).** Contract + adapter node + Odoo BUILT. Review Claude 1 (§10) verdict FIX-THEN-GO,
0 Critical: mở luồng sửa code NET-COSMOS-FIX1…3 (§11). Quy tắc node chung: NI **R340–R349** (§11.1). Các mục dưới đây
**đã bị thay** — đọc spec sau trước:

| Ở đây | Bị thay bởi | Nội dung thay |
|---|---|---|
| §5 job lấy từ Odoo (`relay_poll`/`relay_claim`), token lọc theo `node_config.tokens`; §6 Odoo dựng terms và node chỉ trung gian | NI **R87/R95/R101** | Node độc lập; Odoo (và mọi client) đẩy job vào job API; store của node là nguồn cấu hình token. Code vẫn dùng `crate::odoo` (`adapter.rs:238, 377, 384, 450`) — chuyển theo luồng NI (P3–P9) |
| R9-1 địa chỉ passkey `sha256("scaas.passkey.v1"‖pk)[..20]` hiển thị `wasm1…` | UA rev 1.4 **R315** | Id UA 32 byte `webauthn-p256`, chỉ hiển thị dạng URN, ví từ chối gửi native tới đó — chờ luồng family của UA; code hiện vẫn R9-1 (`metaop/src/lib.rs:89-94`) |
| §5 `valid_until`/`contract` của job lấy từ JSON | NI **R344**, **R9-5** | Lấy từ payload đã ký |
| Đường dẫn `chains/cosmos/` | layout `smartcontracts/cosmos/` | Chỉ đổi đường dẫn |

## 1. Phạm vi

Ba contract CosmWasm trong `smartcontracts/cosmos/` (workspace Rust riêng, `cosmwasm-std` 3, test bằng
`cw-multi-test` 3): `scaas-token`, `scaas-mandate`, `scaas-dex`; crate `scaas-metaop` dùng chung (payload,
kiểm chữ ký). Adapter `scaas-node/src/adapters/cosmos.rs`, module Odoo `dms_blockchain/lib/fam_cosmos.py`,
connector portal `connectors/cosmos.js`. Devnet: `cosmwasm/wasmd:v0.61.15` (wasmvm 3), cổng 31990–31999.

## 2. Payload ký `MetaOp` v1 (R30, §D.0)

Bytes chủ thể ký là **JSON chính tắc** (khoá sắp xếp, không khoảng trắng, mọi trường bắt buộc):

```json
{"amount":"1000","contract":"wasm1…token","domain":"scaas.metaop.v1","extra":"","from":"wasm1…payer",
 "lane":"<64 hex>","network":"<chain-id>","nonce":0,"op":"pay","pay_ref":"<64 hex>","relayer":"",
 "to":"wasm1…payee","valid_until":1790000000}
```

- `amount` chuỗi thập phân u128; `lane`, `pay_ref` 32 byte hex chữ thường không `0x`; `nonce`, `valid_until`
  (giây unix) là số; `relayer` rỗng = relayer nào cũng được, khác rỗng = phải bằng `info.sender`;
  `extra` = hex `sha256(params)` của op `trade`, rỗng với op khác. *Thực tế (review Claude L3):* token bỏ qua `extra`
  với `pay`/`revoke` (`token/src/lib.rs:201-216`) ⇒ hai payload khác `extra` cùng cho phép một `pay` — **R9-8**.
- **Contract nhận nguyên bytes** (`Relay{payload: Binary, …}`), không dựng lại JSON: chữ ký phủ đúng bytes contract
  đọc nên không có lớp chính tắc hoá thứ hai để lệch. Parse chặt (`deny_unknown_fields`, serde từ chối khoá trùng).
- **Miền** nằm trong payload (review S7: ADR-036 có `chain_id: ""`): `network == env.block.chain_id`,
  `contract == env.contract.address`, `domain == "scaas.metaop.v1"`. Payload của contract/mạng khác bị từ chối.
  *Giả định (review Claude M1):* chain-id không duy nhất toàn cục (`testing`, `localwasm`, testnet khởi động lại, fork
  giữ chain-id) và địa chỉ contract wasmd cổ điển = `f(code_id, instance_id)` trùng giữa các chain cùng prefix ⇒ một
  `pay` ký trên chain này chạy được trên chain "sinh đôi" (`metaop/src/lib.rs:103-111`, mandate
  `mandate/src/lib.rs:131-136`). **R9-4** làm địa chỉ khác nhau và cấm chain-id trùng ở node.
- **Digest** = `sha256(payload)` — phát trong event `meta_tx_executed`, Odoo chốt `blockchain.signed.op` theo nó.
- **Lane/nonce riêng contract** (R9 + R30): `NONCES[(from, lane)]` bắt đầu 0, mỗi op đúng nonce hiện hành rồi
  tăng. Odoo dùng lane ngẫu nhiên theo request (`batch_hex`), nonce 0 ⇒ mỗi request một lane, chain thực thi tối
  đa một chữ ký. Không dính sequence tài khoản của chủ thể (chủ thể không gửi tx).
- `valid_until` kiểm với `env.block.time`; hết hạn ⇒ từ chối, không bao giờ treo.

## 3. Lược đồ chữ ký

| `scheme` | Ai | Thông điệp được ký | Kiểm on-chain | Ràng địa chỉ |
|---|---|---|---|---|
| `adr036` | Keplr/Leap `signArbitrary`; ví seed của ta (R32) | sign doc ADR-036 quanh `payload` | `sha256(doc)`, `secp256k1_verify` | `bech32(prefix, ripemd160(sha256(pk33))) == from` |
| `passkey` | WebAuthn P-256 (R31) | `authData ‖ sha256(clientDataJSON)`, `challenge = base64url(digest)` | `secp256r1_verify(sha256(...))` | `from == bech32(prefix, sha256("scaas.passkey.v1" ‖ pk)[..20])` — **bị thay bởi UA R315** (xem R9-1) |

Sign doc ADR-036 dựng bằng **khuôn byte cố định** (amino JSON đã sắp khoá, không khoảng trắng):

```
{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData",
 "value":{"data":"<base64(payload)>","signer":"<from>"}}],"sequence":"0"}
```

Ví seed (R32) ký đúng doc này bằng khoá `m/44'/118'/0'/0/i` ⇒ một đường kiểm duy nhất cho secp256k1.
Passkey: contract kiểm `clientDataJSON` chứa `"type":"webauthn.get"` và đúng chuỗi `"challenge":"<b64url>"`,
cờ UP của `authData`, chữ ký 64 byte low-s (client chuẩn hoá DER → r‖s, review S5). *Thiếu (review Claude L1):*
không kiểm `rpIdHash` (`authData[0..32]`), `origin`, cờ UV (`metaop/src/lib.rs:131-144`) — **R9-6**. Khoá passkey bắt buộc dạng
SEC1 không nén 65 byte (x‖y của khoá COSE) ⇒ một khoá đúng một địa chỉ.

**R9-1 — địa chỉ passkey dẫn xuất.** Cosmos không có tài khoản P-256 gốc. Số dư nằm trong contract token nên một
"địa chỉ" chỉ là khoá sổ cái: passkey sở hữu địa chỉ `bech32(prefix, sha256("scaas.passkey.v1"‖pk)[..20])`
(tiền tố miền ⇒ không trùng không gian `ripemd160(sha256(pk))` của secp256k1). Account nhiều khoá (C.3, xoay
khoá) là seam: cần contract account riêng, không làm ở round này.
**Rev 1.1: R9-1 bị thay bởi UA R315** (review Claude M3): id passkey là id UA 32 byte `webauthn-p256`, chỉ hiển thị
dạng URN. Dạng bech32 20 byte mời `MsgSend` bank / IBC tới một địa chỉ không ai có khoá (tiền mất). Tới khi luồng
family của UA vào, connector và Odoo **không bao giờ** hiển thị chủ passkey dạng `wasm1…` như địa chỉ nạp.

## 4. Contract

### 4.1 `scaas-token` (CW20 + meta-tx)

- CW20 tối thiểu: `Transfer`, `Send` (hook `Receive` — dùng nạp mandate), `Mint` (minter), query `Balance`,
  `TokenInfo`, `Allowance`, `Nonce{owner, lane}`.
- `Pay{to, amount, pay_ref}`: `info.sender` trả, phát `payment_settled`. **`pay_ref` không bị khoá toàn cục ở
  token** (giống `MetaToken` EVM): khoá "một lần" ở đây cho phép bất kỳ ai `Pay` 1 đơn vị với `pay_ref` của người
  trả (đọc từ mempool) để đốt nó và làm hỏng khoản thật. Chống replay là nonce lane; Odoo cộng theo `entry_ref`.
- `Relay{payload, pubkey, signature, scheme, authenticator_data?, client_data_json?}`: kiểm §2–3, rồi theo `op`:
  - `pay`: chuyển `from → to`, phát `payment_settled` + `meta_tx_executed`.
  - `trade`: như `pay` nhưng **bắt buộc** `relayer == to == info.sender` và `info.sender` là contract (chân DEX).
  - `revoke`: chỉ tiêu nonce (huỷ lệnh/thao tác đã ký trên lane đó), phát `meta_tx_executed`.
- `IncreaseAllowance`/`DecreaseAllowance`: spender phải là contract (`query_wasm_contract_info` thành công).
  `TransferFrom`: `info.sender` phải là contract **và** có allowance (R26).
- Event (`wasm-<type>`): `payment_settled{from,to,amount,pay_ref}`, `meta_tx_executed{from,digest,lane,nonce}`.

### 4.2 `scaas-mandate` (R25)

Một instance mỗi ví uỷ thác: `owner`, `token`, `delegate_pubkey` (secp256k1 33 byte), `max_per_payment`,
`max_per_period`, `period_secs`, `payees`, `expires_at`. Nạp: CW20 `Send` → `Receive` (chỉ đúng token).
`PayUnderMandate{to, amount, pay_ref, valid_until, signature}`: delegate ký `sha256` của JSON chính tắc
`{"amount","contract","domain":"scaas.mandate.v1","network","pay_ref","to","valid_until"}`; contract kiểm
chưa thu hồi, chưa hết hạn mandate/chữ ký, payee hợp lệ, hạn mức lần/kỳ (kỳ cố định theo `period_secs`), `pay_ref`
một lần, rồi gọi `token.Pay` ⇒ `payment_settled` mang đúng `pay_ref`. `Revoke`, `Withdraw` chỉ owner.

### 4.3 `scaas-dex` (R35, hai chân ký đi qua token)

- Lệnh = một `MetaOp` `op="trade"` trên token bán (`to = relayer = DEX`, `amount` = số bán, `extra =
  sha256(params)`) + `params` JSON nguyên văn: `{"buy_amount_min","buy_token","dex","max_fee_ppm"}`.
- `Settle{maker, taker}` (mỗi chân: payload, params, chữ ký): DEX parse cả hai, kiểm `extra`, cặp token khớp
  chéo, thị trường đã cấu hình, giới hạn giá (`nhận − phí ≥ buy_amount_min`), phí ppm maker/taker của thị trường
  (bật/tắt, trần 10 000 ppm = 1 %, ≤ `max_fee_ppm` đã ký), `FILLED[digest]` chưa có. Rồi phát nguyên tử:
  `tokenA.Relay(maker)`, `tokenB.Relay(taker)` (token kiểm chữ ký, nonce, hạn, `relayer == DEX`), chuyển chéo
  cho hai bên, phí về `fee_recipient`. Bất kỳ bước nào lỗi ⇒ cả tx revert.
- **Fill-or-kill**: chân là khoản chuyển cố định ⇒ khớp đủ hoặc không; `FILLED` + nonce token chặn khớp lại.
- **Huỷ**: chủ thể ký `revoke` trên lane/nonce của lệnh, gửi qua token ⇒ nonce tiêu ⇒ lệnh không bao giờ settle.
- **R9-2 — lệch khỏi R35:** không khớp một phần on-chain (FOK); batch nhiều cặp = nhiều `MsgExecuteContract`
  trong một tx (nguyên tử **toàn bộ**, không từng cặp) — sổ lệnh off-chain gửi cặp lẻ khi cần cô lập lỗi.

## 5. Relayer (adapter `cosmos`)

*Rev 1.1:* luồng job dưới đây (runner kéo job, báo trạng thái về Odoo, token từ `node_config`) mô tả code hiện tại;
đích là NI R87/R95/R101 (job API, store của node) — code chuyển theo luồng NI.

- Lane = tài khoản secp256k1 `m/44'/118'/0'/0/i`, địa chỉ `bech32(prefix, ripemd160(sha256(pk)))`.
- `build`: đọc `account_number` + sequence **đã commit** (REST `/cosmos/auth/v1beta1/accounts`), dựng
  `MsgExecuteContract{sender=lane, contract, msg=Relay{…}}` (`contract`, `valid_until` lấy **từ payload đã ký**, R9-5;
  hiện `relay_msg` đọc từ JSON của job, `cosmos.rs:177-198`), mô phỏng `/cosmos/tx/v1beta1/simulate`; gRPC Unknown(2)/InvalidArgument(3) (contract từ
  chối, tx hỏng) ⇒ `Revert` (job chết); sequence lệch, Unavailable/Deadline/ResourceExhausted, cổng lỗi ⇒ `Transport`
  (review L2). Gas = mô phỏng × 1.3; phí = gas × `gas_price` của lane.
- `sign`: protobuf `TxBody/AuthInfo/SignDoc` (SIGN_MODE_DIRECT), `sha256(SignDoc)`, chữ ký 64 byte low-s.
  Mã hoá protobuf viết tay (vài kiểu, không thêm `cosmrs`).
- `submit`: `broadcast` SYNC; 19 (đã trong mempool) ⇒ ok, 20 (mempool đầy) ⇒ gửi lại cùng bytes; mã CheckTx khác
  (32 sequence, 13 phí, 4 chữ ký, 5 số dư…) ⇒ `Rejected` ⇒ runner trả job `queued` để dựng lại, không giữ lane tới
  hạn (review L1). Khởi động từ chối `network` rỗng và `gas_price` ≤ 0 trừ `params.zero_fee = true` (devnet).
  Tx bị CometBFT đẩy khỏi mempool khi recheck: `tx_status` ra `Unknown`, `sent` là `Ok` ⇒ `follow` không gửi lại
  (`adapter.rs:313`) và lane nằm chờ tới `valid_until + grace` (review Claude L2) — **R9-7**.
- **Phân loại (NI R341):** CheckTx từ chối ⇒ `Rejected` (không vào khối, không bị thu phí) ⇒ `queued`; DeliverTx lỗi ⇒
  `Reverted` cuối (bị thu đủ `gas_limit × gas_price`). Đã khớp R341; thêm trần `max_attempts`.
- `tx_status`: REST `GetTx` (indexer tx: có thể tắt/trễ) — thấy là chắc; không thấy ⇒ quét `block` +
  `block_results` từ đỉnh lúc gửi tìm `sha256(tx bytes)` (review M2). e2e chạy devnet `indexer = "null"`.
- **Head-of-line (R62):** mỗi lane một tx bay; sequence đọc từ chain trước mỗi job; chủ thể không gửi tx nên không
  có sequence chủ thể nào để kẹt; nonce là `(contract, from, lane)` ⇒ thao tác kẹt trên contract 1 không chặn
  contract 2 (test anti-lock ở cả contract và e2e). Tx quá hạn bị contract từ chối ⇒ sequence lane không treo.
- **Phí:** relayer trả bằng native denom của lane. **Grief (review Claude H1):** chủ thể là tài khoản x/auth tự gửi
  tx được; giữa `simulate` và lúc vào khối nó `Transfer` hết số dư (`token/src/lib.rs:126-130`), hoặc tự `Relay` cùng
  payload / một `revoke` cùng `(from, lane)` (relayer rỗng = ai cũng gửi, `token/src/lib.rs:191`) ⇒ tx của lane lỗi ở
  DeliverTx và bị thu đủ phí; Odoo cấp lane mới mỗi request nên lặp vô hạn, không phí phía chủ thể (R10/R75), runner
  không đếm (`adapter.rs:280-291`). DEX: `Settle` không cần quyền và maker `revoke` được chân của mình sau mô phỏng
  (`dex/src/lib.rs:145`). **R9-3**. **feegrant** chỉ là seam cho tx chủ thể tự gửi (nạp). **authz
  không dùng** (R66): grantee tài khoản thường vi phạm R26.
- **Finality:** CometBFT final tức thì ⇒ `final_head` = khối mới nhất (`/status`).
  `events(from,to)`: `block_results` từng khối (lưu cùng lúc commit; **không** `tx_search` vì indexer tx chạy
  bất đồng bộ sau commit ⇒ khối mới nhất có thể chưa index, event lọt vĩnh viễn), `block` chỉ khi khối có event của
  ta (`tx_hash = sha256(tx bytes)`), lọc theo token đã đăng ký (token registry ở store của node, NI R95 — trước là
  `node_config.tokens` của Odoo; bech32 — review M1; danh sách rỗng ⇒
  `index_step` không tiến con trỏ), chuẩn hoá
  `{event, contract, block_number, block_hash, tx_hash, log_index, from, to, amount, entry_ref, digest}`;
  `log_index` = thứ tự event trong tx (`tx_hash` khác nhau giữa tx ⇒ khoá `(tx_hash, log_index)` duy nhất).
- Cấu hình: `rpc_urls = [CometBFT RPC]`, `params = {rest, prefix, denom, gas_price, zero_fee?}`.
- Thuộc tính event: CometBFT < 0.38 trả base64 ⇒ phát hiện qua `_contract_address` (wasmd luôn gắn) và giải mã
  (review L3).

## 6. Odoo và portal

- `fam_cosmos.build_terms`: dựng `payload` §2 từ request (không RPC — R20): contract = địa chỉ token, `network`
  = `chain.network_key` (chain-id), `lane = batch_hex`, `pay_ref = entry_ref_hex`, nonce 0, `relayer` rỗng.
  `terms` cho ví: `{chain_id, signer, data_b64}`.
- `verify`: chữ ký base64 64 byte + pubkey 33 byte; dựng doc ADR-036, khôi phục secp256k1 (thuần Python) so khoá
  công khai; ràng địa chỉ bằng `ripemd160` nếu `hashlib` có, không có thì `None` (node mô phỏng phân xử — R27).
  Passkey: `None` (node phân xử).
- Connector `cosmos.js`: `window.keplr || window.leap`, `enable(chainId)`, `getKey` ⇒ `{address, publicKey}`,
  `signArbitrary(chainId, signer, payloadString)` ⇒ `{signature, publicKey}`. Không thư viện.

## 7. Vector chéo

Một payload cố định + khoá secp256k1 test: Python (`test_fam_cosmos`), contract (`cw-multi-test`) và Rust
adapter cùng khẳng định `digest`, bytes doc ADR-036 và địa chỉ bech32.

## 8. Khả thi thanh toán bảo mật (R34 §5)

Zether cần pairing bn254 (hoặc BLS12-381) và nhiều phép nhân điểm: CosmWasm 2+ có `bls12_381_pairing_equality`
và phép toán G1/G2 BLS12-381 gốc nhưng không có bn254; verifier Bulletproofs viết bằng Rust → wasm chạy được nhưng
gas cao (phép nhân điểm thuần wasm). Khả thi kỹ thuật với biến thể BLS12-381 khi có prover tương ứng; **không
làm** ở round này (Zether EVM-first).

## 9. Rủi ro / khoảng trống

- Không quorum nhiều endpoint cho `final_head` (CometBFT BFT final; một RPC tin cậy) — ghi.
- Passkey dùng địa chỉ dẫn xuất, chưa xoay khoá (R9-1).
- Mandate qua Odoo (`_enqueue_mandate_payment`) hiện chỉ EVM: contract có, đường Odoo là seam.
- **Grief sau mô phỏng** (R9-3): chi phí còn lại bị chặn bởi NI R340–R342 (đếm phí tx lỗi, điểm grief theo `from`),
  không bằng không: mỗi `from` mới tốn cho lane tới 3 tx lỗi/24 h trước khi bị siết.
- **Mesh** (review Claude L4): `mesh/digest.rs:205-225` giải mã và kiểm miền/mạng/contract nhưng không kiểm chữ ký
  ADR-036/passkey ⇒ mỗi peer trả một `simulate` REST cho rác; mô phỏng là cổng duy nhất — NI R343.
- Hai chain trùng chain-id: an toàn nhờ R9-4 cho triển khai mới; triển khai cũ (`instantiate` cổ điển) dựa trên giả
  định "chain-id của các chain ta triển khai là duy nhất", node từ chối chain-id trùng.

## 10. Review log

**Tự review (2026-10-03):**

| # | Kết luận | Xử lý |
|---|---|---|
| C1 | Khoá `pay_ref` toàn cục ở token cho phép front-run đốt `pay_ref` (xem §4.1) | Bỏ; test `Pay` cùng `pay_ref` trước relay |
| C2 | `tx_search` có thể chưa index khối mới nhất ⇒ indexer bỏ sót event | Đọc `block_results` |
| C3 | Passkey nhận cả khoá nén lẫn không nén ⇒ hai địa chỉ cho một khoá | Chỉ 65 byte |
| C4 | Mô phỏng dùng thời gian khối cuối: payload hết hạn trong khoảng một khối vẫn qua mô phỏng rồi `reverted` khi vào khối | Chấp nhận (fail-safe, người trả ký lại); e2e dùng hạn đã qua rõ ràng |
| C5 | wasmvm 3 từ chối bulk-memory mà Rust ≥ 1.87 sinh ra | `build-wasm.sh` hạ tính năng bằng binaryen, kiểm MVP |

**agy:** lần 1 (thiết kế) hết quota (429, "Resets in 1h42m"); review nhánh chạy lại sau giờ reset — kết quả ở báo cáo luồng.
**Grok:** hết hạn mức miễn phí (một lần thử, ghi nhận).

### Claude review disposition — review 1 (2026-10-07, `docs/reviews/specs/2026-10-03-net-cosmos-claude-review-1.md`)

Verdict của review: FIX-THEN-GO, 0 Critical. Đối chiếu từng finding với code (file:line) trước khi nhận: **8 nhận,
0 từ chối** (2 nhận có chỉnh cách sửa).

| # | Sev | Kiểm với code | Kết luận | Xử lý |
|---|---|---|---|---|
| H1 | high | Chủ thể tự `Transfer` (`token/src/lib.rs:126-130`); relayer rỗng ⇒ ai cũng `Relay` (`:191`); revert ⇒ chỉ báo (`adapter.rs:280-291`); breaker chỉ phí `Mined` (`adapter.rs:270-276`); `Settle` mở (`dex/src/lib.rs:145`) | Đúng | R9-3, §5, §9; NI R340/R342; NET-COSMOS-FIX1 (DEX kiểm lại chân) |
| M1 | med | `verify` chỉ so chain-id chuỗi + địa chỉ contract (`metaop/src/lib.rs:103-111`); mandate cùng cách (`mandate/src/lib.rs:131-136`) | Đúng; chỉnh: không đổi payload (v1 giữ nguyên) — `instantiate2` với salt có genesis hash + node cấm chain-id trùng; `chain_uid` (UA R330) ghi ở node | R9-4, §2, §9; NET-COSMOS-FIX2 (deploy), NI R95/R330 |
| M2 | med | §5/§6 mô tả Odoo kéo job/`node_config`; code còn `crate::odoo` (`adapter.rs:238, 377, 384, 450`) | Đúng | Status block, §5, §1 đường dẫn |
| M3 | med | R9-1 còn là thiết kế; code `passkey_account` 20 byte (`metaop/src/lib.rs:89-94`) | Đúng | R9-1 đánh dấu bị thay (UA R315), cấm hiển thị `wasm1…` |
| M4 | med | `relay_msg` lấy `contract`/`valid_until` từ JSON (`cosmos.rs:177-198`); `op_consumed` hỏi `op["contract"]` (`cosmos.rs:414-426`); runner giữ lane tới `valid_until + grace` (`adapter.rs:307`); mesh lấy từ payload (`mesh/digest.rs:205-225`) | Đúng | R9-5, NI R344; NET-COSMOS-FIX1 |
| L1 | low | Passkey kiểm UP + `type`/`challenge` (`metaop/src/lib.rs:131-144`); không rpIdHash/origin/UV | Đúng; chọn sửa (không chỉ ghi quyết định) | R9-6, §3; NET-COSMOS-FIX2 |
| L2 | low | `follow` chỉ gửi lại khi `sent.is_err()` (`adapter.rs:313`); `Unknown` + `Ok` ⇒ chờ hạn | Đúng | R9-7, §5; NET-COSMOS-FIX1 |
| L3 | low | `pay`/`revoke` bỏ qua `extra` (`token/src/lib.rs:201-216`) | Đúng | R9-8, §2; NET-COSMOS-FIX2 |
| L4 | low | `mesh/digest.rs:205-225` không kiểm ADR-036/passkey | Đúng | §9, NI R343; NET-COSMOS-FIX3 |

## 11. Rulings rev 1.1 — review Claude 1 (2026-10-07)

- **R9-3** (H1) **Grief sau mô phỏng do chủ thể gây ra được đếm và siết, không loại trừ.** Node: phí DeliverTx lỗi vào
  breaker (NI R340), mỗi lỗi bị thu phí của tx ta tính cho `from` của payload (NI R342; `consumed` của job chưa
  publish cũng tính — đó chính là kiểu "tự gửi trước"). DEX: ngay trước khi ký `Settle`, đọc lại `Nonce{owner, lane}`
  của **cả hai** chân trên hai token; đã tiêu ⇒ bỏ cặp, không gửi. Tests: chủ thể chuyển hết số dư sau mô phỏng ⇒
  tx lỗi được tính vào `subject_grief`; lần thứ 3/24 h ⇒ chỉ 1 job sống; maker revoke trước settle ⇒ không gửi.
- **R9-4** (M1) **Địa chỉ contract khác nhau giữa các chain, chain-id trùng bị cấm.** Triển khai mới dùng
  `instantiate2` với salt `sha256("scaas.cosmos.salt.v1" ‖ chain_id ‖ genesis_hash)` (script deploy đọc genesis hash
  từ RPC) ⇒ `contract` trong payload là duy nhất theo chain kể cả khi chain-id trùng; node ghi `chain_uid` (UA R330)
  và từ chối hai chain Cosmos cùng chain-id trong store. Payload v1 không đổi. Tests: deploy script ra địa chỉ khác
  trên hai devnet cùng chain-id khác genesis; node từ chối cấu hình chain-id trùng.
- **R9-5** (M4) **`contract`, `valid_until` lấy từ payload đã ký** (NI R344): `relay_msg` parse payload; JSON của job
  khác ⇒ `422 BAD_PAYLOAD` ở cửa, `Revert` ở `build`; `op_consumed` dùng `payload.contract`. Tests: job có
  `valid_until` JSON > ký ⇒ từ chối; `contract` JSON khác ⇒ từ chối, không bao giờ `consumed` giả.
- **R9-6** (L1) **Passkey ràng RP và người dùng**: contract (bản code sau) lưu `rp_id_hashes` và `origins` lúc
  instantiate (bất biến), kiểm `authData[0..32] ∈ rp_id_hashes`, `"origin":"<o>"` với `o ∈ origins`, cờ UP **và** UV,
  `"crossOrigin":true` bị từ chối. Tests cw-multi-test: rpIdHash lạ, origin lạ, thiếu UV ⇒ từ chối.
- **R9-7** (L2) **Tx rơi khỏi mempool được gửi lại**: `Unknown` kéo dài quá `params.resubmit_after_blocks` (mặc định 5)
  khi `sent` là `Ok` ⇒ gửi lại đúng bytes (mã 19 ⇒ idempotent); không đổi bytes, không đổi sequence. Test: tx biến
  mất khỏi mempool giả ⇒ gửi lại, vào khối, `mined`.
- **R9-8** (L3) **`extra` rỗng ngoài `trade`**: token từ chối `pay`/`revoke` có `extra != ""` ⇒ digest là khoá duy nhất
  của một thao tác nghiệp vụ. Test: `pay` với `extra` khác rỗng ⇒ từ chối.

### 11.1 Quy tắc node chung (NI rev 3.7)

NI **R340** (breaker đếm phí DeliverTx lỗi), **R341** (CheckTx = không vào khối ⇒ `queued`; DeliverTx lỗi = cuối — đã
đúng, thêm `max_attempts`), **R342** (điểm grief theo `from`), **R343** (mesh kiểm ADR-036 secp256k1 / passkey cục bộ
trước `simulate`), **R344** (trường đã ký lấy từ payload — R9-5). R345/R346: Cosmos không có value out ngoài phí và
không có deposit do lane trả (mặc định 0).

### 11.2 Luồng code

Owner: không sửa code trong pha spec; làm sau §0 TODO.

| Luồng | Lớp | Nội dung | Ruling |
|---|---|---|---|
| **NET-COSMOS-FIX1** | Node `adapters/cosmos.rs`, `adapter.rs`, DEX venue (cùng NI NR1/NR2) | `relay_msg` từ payload; gửi lại khi `Unknown` quá N khối; DEX đọc lại nonce hai chân trước ký; tests | R9-3 (node), R9-5, R9-7 |
| **NET-COSMOS-FIX2** | Contract `metaop`, `token` + script deploy | Passkey rpIdHash/origin/UV/crossOrigin; `extra` rỗng ngoài `trade`; `instantiate2` + salt genesis; node cấm chain-id trùng; tests cw-multi-test; deploy mới | R9-4, R9-6, R9-8 |
| **NET-COSMOS-FIX3** | Node `mesh/digest.rs` (trong NI NR3) | Kiểm chữ ký `cosmos` trước `simulate` | NI R343 |

DEX: gắn relayer vào `OrderParams` + `info.sender == relayer` là **RS5-15 / DX-FIX4** (DEX spec) — không lặp ở đây.
Id passkey UA (R315) thuộc luồng family của UA.

## 12. Lịch sử bản

| Rev | Ngày | Thay đổi |
|---|---|---|
| 1.0 | 2026-10-03 | Bản đầu (S9): R9-1, R9-2; tự review C1–C5 |
| 1.1 | 2026-10-07 | Gộp review Claude 1: status block + bảng "bị thay" (NI R87/R95/R101, UA R315, NI R344, đường dẫn `smartcontracts/`); R9-3…8; sửa §1–§3, §5, §9; quy tắc node chung NI R340–R349; luồng NET-COSMOS-FIX1…3 |
