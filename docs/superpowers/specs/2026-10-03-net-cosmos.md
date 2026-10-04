# Mạng Cosmos (CosmWasm) — thiết kế luồng S9 (R66)

**Ngày:** 2026-10-03 · **Thuộc:** round 3 §D.0, §D.4, §D.6, §B (R58–R62) · **Luồng:** S9 `r3-cosmos`.
Ruling của luồng đánh số `R9-n` (lead đánh số lại khi hợp nhất).

## 1. Phạm vi

Ba contract CosmWasm trong `chains/cosmos/` (workspace Rust riêng, `cosmwasm-std` 3, test bằng
`cw-multi-test` 3): `bamboo-token`, `bamboo-mandate`, `bamboo-dex`; crate `bamboo-metaop` dùng chung (payload,
kiểm chữ ký). Adapter `bamboo-node/src/adapters/cosmos.rs`, module Odoo `dms_blockchain/lib/fam_cosmos.py`,
connector portal `connectors/cosmos.js`. Devnet: `cosmwasm/wasmd:v0.61.15` (wasmvm 3), cổng 31990–31999.

## 2. Payload ký `MetaOp` v1 (R30, §D.0)

Bytes chủ thể ký là **JSON chính tắc** (khoá sắp xếp, không khoảng trắng, mọi trường bắt buộc):

```json
{"amount":"1000","contract":"wasm1…token","domain":"bamboo.metaop.v1","extra":"","from":"wasm1…payer",
 "lane":"<64 hex>","network":"<chain-id>","nonce":0,"op":"pay","pay_ref":"<64 hex>","relayer":"",
 "to":"wasm1…payee","valid_until":1790000000}
```

- `amount` chuỗi thập phân u128; `lane`, `pay_ref` 32 byte hex chữ thường không `0x`; `nonce`, `valid_until`
  (giây unix) là số; `relayer` rỗng = relayer nào cũng được, khác rỗng = phải bằng `info.sender`;
  `extra` = hex `sha256(params)` của op `trade`, rỗng với op khác.
- **Contract nhận nguyên bytes** (`Relay{payload: Binary, …}`), không dựng lại JSON: chữ ký phủ đúng bytes contract
  đọc nên không có lớp chính tắc hoá thứ hai để lệch. Parse chặt (`deny_unknown_fields`, serde từ chối khoá trùng).
- **Miền** nằm trong payload (review S7: ADR-036 có `chain_id: ""`): `network == env.block.chain_id`,
  `contract == env.contract.address`, `domain == "bamboo.metaop.v1"`. Payload của contract/mạng khác bị từ chối.
- **Digest** = `sha256(payload)` — phát trong event `meta_tx_executed`, Odoo chốt `blockchain.signed.op` theo nó.
- **Lane/nonce riêng contract** (R9 + R30): `NONCES[(from, lane)]` bắt đầu 0, mỗi op đúng nonce hiện hành rồi
  tăng. Odoo dùng lane ngẫu nhiên theo request (`batch_hex`), nonce 0 ⇒ mỗi request một lane, chain thực thi tối
  đa một chữ ký. Không dính sequence tài khoản của chủ thể (chủ thể không gửi tx).
- `valid_until` kiểm với `env.block.time`; hết hạn ⇒ từ chối, không bao giờ treo.

## 3. Lược đồ chữ ký

| `scheme` | Ai | Thông điệp được ký | Kiểm on-chain | Ràng địa chỉ |
|---|---|---|---|---|
| `adr036` | Keplr/Leap `signArbitrary`; ví seed của ta (R32) | sign doc ADR-036 quanh `payload` | `sha256(doc)`, `secp256k1_verify` | `bech32(prefix, ripemd160(sha256(pk33))) == from` |
| `passkey` | WebAuthn P-256 (R31) | `authData ‖ sha256(clientDataJSON)`, `challenge = base64url(digest)` | `secp256r1_verify(sha256(...))` | `from == bech32(prefix, sha256("bamboo.passkey.v1" ‖ pk)[..20])` |

Sign doc ADR-036 dựng bằng **khuôn byte cố định** (amino JSON đã sắp khoá, không khoảng trắng):

```
{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData",
 "value":{"data":"<base64(payload)>","signer":"<from>"}}],"sequence":"0"}
```

Ví seed (R32) ký đúng doc này bằng khoá `m/44'/118'/0'/0/i` ⇒ một đường kiểm duy nhất cho secp256k1.
Passkey: contract kiểm `clientDataJSON` chứa `"type":"webauthn.get"` và đúng chuỗi `"challenge":"<b64url>"`,
cờ UP của `authData`, chữ ký 64 byte low-s (client chuẩn hoá DER → r‖s, review S5). Khoá passkey bắt buộc dạng
SEC1 không nén 65 byte (x‖y của khoá COSE) ⇒ một khoá đúng một địa chỉ.

**R9-1 — địa chỉ passkey dẫn xuất.** Cosmos không có tài khoản P-256 gốc. Số dư nằm trong contract token nên một
"địa chỉ" chỉ là khoá sổ cái: passkey sở hữu địa chỉ `bech32(prefix, sha256("bamboo.passkey.v1"‖pk)[..20])`
(tiền tố miền ⇒ không trùng không gian `ripemd160(sha256(pk))` của secp256k1). Account nhiều khoá (C.3, xoay
khoá) là seam: cần contract account riêng, không làm ở round này.

## 4. Contract

### 4.1 `bamboo-token` (CW20 + meta-tx)

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

### 4.2 `bamboo-mandate` (R25)

Một instance mỗi ví uỷ thác: `owner`, `token`, `delegate_pubkey` (secp256k1 33 byte), `max_per_payment`,
`max_per_period`, `period_secs`, `payees`, `expires_at`. Nạp: CW20 `Send` → `Receive` (chỉ đúng token).
`PayUnderMandate{to, amount, pay_ref, valid_until, signature}`: delegate ký `sha256` của JSON chính tắc
`{"amount","contract","domain":"bamboo.mandate.v1","network","pay_ref","to","valid_until"}`; contract kiểm
chưa thu hồi, chưa hết hạn mandate/chữ ký, payee hợp lệ, hạn mức lần/kỳ (kỳ cố định theo `period_secs`), `pay_ref`
một lần, rồi gọi `token.Pay` ⇒ `payment_settled` mang đúng `pay_ref`. `Revoke`, `Withdraw` chỉ owner.

### 4.3 `bamboo-dex` (R35, hai chân ký đi qua token)

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

- Lane = tài khoản secp256k1 `m/44'/118'/0'/0/i`, địa chỉ `bech32(prefix, ripemd160(sha256(pk)))`.
- `build`: đọc `account_number` + sequence **đã commit** (REST `/cosmos/auth/v1beta1/accounts`), dựng
  `MsgExecuteContract{sender=lane, contract, msg=Relay{…}}`, mô phỏng `/cosmos/tx/v1beta1/simulate`; gRPC Unknown(2)/InvalidArgument(3) (contract từ
  chối, tx hỏng) ⇒ `Revert` (job chết); sequence lệch, Unavailable/Deadline/ResourceExhausted, cổng lỗi ⇒ `Transport`
  (review L2). Gas = mô phỏng × 1.3; phí = gas × `gas_price` của lane.
- `sign`: protobuf `TxBody/AuthInfo/SignDoc` (SIGN_MODE_DIRECT), `sha256(SignDoc)`, chữ ký 64 byte low-s.
  Mã hoá protobuf viết tay (vài kiểu, không thêm `cosmrs`).
- `submit`: `broadcast` SYNC; 19 (đã trong mempool) ⇒ ok, 20 (mempool đầy) ⇒ gửi lại cùng bytes; mã CheckTx khác
  (32 sequence, 13 phí, 4 chữ ký, 5 số dư…) ⇒ `Rejected` ⇒ runner trả job `queued` để dựng lại, không giữ lane tới
  hạn (review L1). Khởi động từ chối `network` rỗng và `gas_price` ≤ 0 trừ `params.zero_fee = true` (devnet).
- `tx_status`: REST `GetTx` (indexer tx: có thể tắt/trễ) — thấy là chắc; không thấy ⇒ quét `block` +
  `block_results` từ đỉnh lúc gửi tìm `sha256(tx bytes)` (review M2). e2e chạy devnet `indexer = "null"`.
- **Head-of-line (R62):** mỗi lane một tx bay; sequence đọc từ chain trước mỗi job; chủ thể không gửi tx nên không
  có sequence chủ thể nào để kẹt; nonce là `(contract, from, lane)` ⇒ thao tác kẹt trên contract 1 không chặn
  contract 2 (test anti-lock ở cả contract và e2e). Tx quá hạn bị contract từ chối ⇒ sequence lane không treo.
- **Phí:** relayer trả bằng native denom của lane. **feegrant** chỉ là seam cho tx chủ thể tự gửi (nạp). **authz
  không dùng** (R66): grantee tài khoản thường vi phạm R26.
- **Finality:** CometBFT final tức thì ⇒ `final_head` = khối mới nhất (`/status`).
  `events(from,to)`: `block_results` từng khối (lưu cùng lúc commit; **không** `tx_search` vì indexer tx chạy
  bất đồng bộ sau commit ⇒ khối mới nhất có thể chưa index, event lọt vĩnh viễn), `block` chỉ khi khối có event của
  ta (`tx_hash = sha256(tx bytes)`), lọc theo token Odoo đăng ký (`node_config.tokens`, bech32 — review M1; danh sách rỗng ⇒
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
