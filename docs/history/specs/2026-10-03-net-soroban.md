# Luồng S8 — Stellar Soroban (R65)

**Ngày:** 2026-10-03 · **Thuộc:** round 3 (`2026-10-03-blockchain-round3-design.md` §D.0, §D.3, §D.6, §B, R30/R31/R32/R62/R65).
Ruling của luồng này đánh số `R8-n` (lead đánh số lại khi hợp nhất).

**Trạng thái (rev 1.1, 2026-10-07).** Contract + adapter + Odoo BUILT. Review Claude 1 (§10) mở ruling
**R8-9…R8-15** (§9) và luồng sửa code **NET-SOROBAN-FIX1…2** (+ phần DEX trong DX-FIX4 của spec DEX); phần chung
mọi họ mạng của node nằm ở NI **R340–R349** (§9 "Quy tắc node chung"). Các đoạn dưới đây **đã bị thay** — đọc spec
sau trước:

| Ở đây | Bị thay bởi | Nội dung thay |
|---|---|---|
| §4/§5 job đi qua Odoo (pull), token lấy từ `node_config` | NI **R87**, **R95**, **R101** (+ R324) | Odoo đẩy job vào job API của node; node không gọi Odoo; danh sách token = store của node |
| §3 đường dẫn `chains/soroban/` | layout `smartcontracts/<family>/` | `smartcontracts/soroban/contracts/{token,mandate,dex,account}/` |
| §4 R8-7 "`node_config.tokens` kiểu địa chỉ EVM, cần lead đổi" | đã làm | `TokenCfg.address` là chuỗi theo họ (`config.rs:302-306`); `params.contracts` không còn là nguồn |
| §1 (b) "`pay_ref` chỉ trả một lần" (toàn cục ở token) | **R8-9** | Khoá theo `(from, pay_ref)`; `amount > 0` |
| §3 DEX `require_auth_for_args((order,))` | DEX **RS5-15** + **R8-10** | Lệnh Soroban bắt buộc nêu `relayer`, `relayer.require_auth()` trong `settle` |

## 1. Meta-tx cấp contract = authorization gốc của Soroban (R30, R65)

Chủ thể **không** gửi tx và **không** dùng sequence tài khoản của mình. Chủ thể chỉ ký một
`HashIdPreimage::SorobanAuthorization` (XDR), relayer đặt chữ ký vào `SorobanAuthorizationEntry` của một tx
mà **lane account** của relayer là source (sequence riêng của lane, trả phí).

Payload chủ thể ký (bytes XDR chính xác, Odoo dựng không RPC — R20):

```
HashIdPreimage {
  type = ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9)
  network_id                = sha256(network_passphrase)          -- tách mạng
  nonce                     = i64(sha256("scaas.soroban.nonce" ‖ entryRef ‖ validUntil_be64)[0..8])
  signature_expiration_ledger = u32 (ước lượng trên, §1.2)
  invocation = { contract_fn: { contract_address = token (C…), function_name = "pay",
                                args = [Address from, Address to, I128 amount, BytesN<32> pay_ref, U64 valid_until] },
                 sub_invocations = [] }
}
ký: ed25519(sha256(payload))   (Freighter `signAuthEntry`, ví seed R32 cùng phép tính)
```

Ánh xạ `MetaOp` v1 (§D.0): network → `network_id`; contract → `contract_address`; op → `function_name`;
from/to/amount/payRef → args; lane+nonce → `nonce` (host ghi cặp (địa chỉ, nonce) đã dùng tới hạn chữ ký — **không
tuần tự**, review S1); validUntil → arg `valid_until` (contract kiểm `ledger.timestamp() ≤ valid_until`) **và**
`signature_expiration_ledger`; relayer → không ràng (mọi lane nộp được; host không ràng source tx); extra → không có
cho `pay`.

Chống replay: (a) host từ chối cặp (from, nonce) đã dùng; (b) ~~`pay_ref` chỉ trả một lần~~ *(rev 1.1, R8-9)*
mỗi **`(from, pay_ref)`** trả một lần (persistent, gia hạn TTL) — khoá toàn cục theo `pay_ref` cho phép bất kỳ ai
đốt `pay_ref` của người khác bằng một `pay` 0 đồng (review Claude H1); replay đã bị (a) + hạn chữ ký chặn;
(c) khác mạng ⇒ `network_id` khác ⇒ chữ ký sai; khác contract ⇒ `contract_address` khác ⇒ không khớp invocation.

### 1.1 Digest (khớp op ⇄ event)

Host không cho contract biết hash chữ ký, nên contract tự tính **digest thao tác** và phát trong
`MetaTransactionExecuted`:

```
digest = sha256( ScVal::Vec[ Symbol("scaas_metaop_v1"), BytesN<32>(network_id), Address(contract),
                             Symbol(function_name), Vec(args) ].to_xdr() )
```

Odoo, contract (test) và adapter Rust tính cùng một giá trị (vector chéo §6). Args chứa `pay_ref` và `valid_until`
⇒ mỗi lần phát (hạn khác) một digest khác; `UNIQUE(chain_id, digest_hash)` giữ nguyên nghĩa.

### 1.2 Hạn ledger không cần RPC (R8-1)

`signature_expiration_ledger` phải nằm trong `[ledger hiện tại, ledger hiện tại + max_entry_ttl − 1]`. Odoo không gọi
RPC, nên dùng **mốc** do indexer để lại: mỗi lần `chain_event_ingest` tiến cursor của chain `soroban`, Odoo ghi
`soroban_anchor_ts` (giờ server) cạnh `indexed_block` (ledger final). Ledger không đóng nhanh hơn 1/giây (SCP), nên

`exp = indexed_block + (valid_until − soroban_anchor_ts) + 17280`

là **cận trên**: không bao giờ hết hạn trước `valid_until` (hạn thật do contract kiểm theo giây); lề 17 280 ledger phủ
độ trễ indexer. Mốc chỉ được ghi khi lô ingest **ngắn hơn 1000 ledger** (= node đã bắt kịp đỉnh final; lô bắt kịp sau
sự cố dài không làm mốc cũ đi kèm giờ mới). Mốc cũ hơn 7 ngày (indexer ngừng) ⇒ từ chối phát (cận trên có thể vượt
`max_entry_ttl`). Chain chưa index lần nào ⇒ từ chối phát. Vượt cận trên chỉ kéo dài thời gian host giữ nonce.

## 2. Lược đồ chữ ký chủ thể

| Kiểu `from` | Ai ký | Chữ ký trong auth entry | Odoo kiểm |
|---|---|---|---|
| `G…` (ví Freighter, ví seed R32 `m/44'/148'/i'`) | khoá ed25519 của account (host kiểm ngưỡng/signer) | `Vec[Map{public_key: Bytes32, signature: Bytes64}]` (relayer dựng từ 64 byte) | ed25519 thật (`cryptography`) với khoá master trong strkey |
| `C…` = `scaas-account` (account chủ thể nhiều khoá — R31/R32) | passkey P-256 WebAuthn hoặc khoá ed25519 từ seed | ScVal `Signature` của account (XDR hex, relayer chèn nguyên văn) | không (`None`) — mô phỏng của node phân xử (R27) |

`scaas-account.__check_auth(signature_payload, Signature, contexts)`:
- `Ed25519{key_id, signature}`: `ed25519_verify(pk, signature_payload, sig)`.
- `WebAuthn{key_id, authenticator_data, client_data_json, signature(r‖s, low-s), proof}`: challenge =
  `signature_payload` nếu `proof` rỗng, ngược lại gốc Merkle sha256 của lá `sha256(sha256(0x00 ‖ payload))` với cặp
  sắp xếp (gom lô R31); `clientDataJSON` chứa `"type":"webauthn.get"`, `"challenge":"<base64url(challenge)>"`,
  `"origin":"<origin đã đăng ký>"`; `authenticator_data[0..32] = rp_id_hash`; cờ UP (0x01) và UV (0x04);
  `secp256r1_verify(pk65, sha256(authData ‖ sha256(clientDataJSON)), sig)` (host từ chối high-s — CAP-51).
- *(Rev 1.1, R8-13, review Claude L2)* `clientDataJSON` có `"crossOrigin":true` hoặc có trường `topOrigin` ⇒ từ
  chối (như Aptos); hiện `verify_webauthn` chỉ kiểm `type`/`challenge`/`origin` (`account/src/lib.rs:149-153`), nên
  một trang RP nhúng được trong iframe khác origin (Permissions-Policy `publickey-credentials-get`) cho ra assertion
  hợp lệ dưới trang của kẻ tấn công.
- Vòng đời khoá: `add_key`/`remove_key` cần chính account uỷ quyền (một khoá hiện có ký); không bao giờ còn 0 khoá.
  Guardian + trễ khôi phục: **seam** (R8-2) — chưa xây trên Soroban, ghi HANDOFF.
- R8-8: `__check_auth` không đọc `auth_contexts` — mọi khoá của account được làm mọi việc (kể cả `add_key`); phân
  quyền theo khoá (passkey chỉ trả ≤ X, seed mới đổi khoá…) là seam. *Rủi ro còn lại (review Claude L3):* bất kỳ
  một passkey nào cũng `add_key` được khoá của kẻ tấn công; giữ là seam tới khi có purpose theo khoá của UA (R298).
- Account phải tồn tại trên ledger trước khi trả (deploy không cần quyền: `__constructor(first_key)`). Chủ thể `G…`
  cũng phải tồn tại (yêu cầu của host).

## 3. Contract (`smartcontracts/soroban/contracts/`, soroban-sdk 25.3.0, Rust 1.90)

- **`scaas-token`** — SEP-41 (`balance`, `transfer`, `transfer_from`, `approve`, `allowance`, `burn`,
  `burn_from`, `decimals`, `name`, `symbol`) + `mint` (admin) + `pay(from, to, amount, pay_ref, valid_until)`:
  `from.require_auth()`, hạn, `pay_ref` một lần **theo `from`** và `amount > 0` (R8-9; hiện khoá toàn cục
  `token/src/lib.rs:203-209`, `check_amount` nhận 0 `:113-117`), phát `PaymentSettled{from,to | amount,pay_ref}` và
  `MetaTransactionExecuted{from | digest}`. **`approve` chỉ cho spender là contract** (`executable()` = Wasm hoặc
  StellarAsset) — R26. Không phí (R10 trên mạng mới). Storage: số dư/allowance/`pay_ref` persistent, gia hạn TTL.
- **`scaas-mandate`** (như `MandateWallet` R25): một owner; tiền nằm trong contract; theo token: delegate, hạn mức
  lần/kỳ, kỳ, hạn dùng, payee cho phép; `pay_under_mandate(token, payee, amount, pay_ref, valid_until)` —
  `delegate.require_auth()` rồi `token.pay(self, payee, …)` (cùng `PaymentSettled` ⇒ Odoo đối soát như thanh toán
  tay); `pay_ref` một lần; `revoke(token, by)` bởi owner **hoặc** delegate (kill switch); `withdraw` của owner.
  Owner gasless tự nhiên: auth gốc của owner qua relayer (không cần `executeAsOwner`).
- **`scaas-dex`** `settle(maker, taker, maker_fill)` (R35): `require_auth_for_args((order,))` cho **cả hai** lệnh;
  giới hạn giá của cả hai (giá maker; taker nhận ít nhất giá của mình); `filled[order_hash]` không overfill; phí ppm
  maker/taker theo thị trường (cặp token sắp xếp), bật/tắt, trần 1 % (10 000 ppm) và ≤ `max_fee_ppm` trong lệnh ký;
  token đi bằng `transfer_from` với DEX là spender (allowance chỉ cho contract — R26); `cancel(order)` do maker uỷ
  quyền đặt `filled = sell_amount` ⇒ lệnh huỷ không bao giờ settle. `order_hash = sha256(order.to_xdr())`.
  *(Rev 1.1, R8-10, review Claude H2.)* Host chỉ khớp `dex.settle(order)` (`dex/src/lib.rs:158-159`): đối ứng và
  `maker_fill` (`:153`) do người nộp chọn, nên ai thấy một `settle` đang chờ (tx được flood tới mọi peer trước khi
  ledger đóng) nộp lại hai auth entry với `maker_fill = 1` ⇒ cả hai nonce bị tiêu cho một khớp bụi, `settle` thật fail
  (relayer trả phí), hai maker phải ký lại. Sửa = gắn người settle theo DEX **RS5-15** (`relayer: Address` trong
  `Order` + `order.relayer.require_auth()` trong `settle`; luồng **DX-FIX4**) — chỉ lane của DEX operator tiêu được
  auth entry, nên khớp bụi của bên thứ ba bị loại; vai maker/taker và `maker_fill` do operator (đáng tin) chọn.
  **Trên Soroban không có dạng "mở"**: `Order.relayer` bắt buộc (không `Option`); lệnh mở vẫn bị khớp bụi. Không
  gắn `(order, fill)` vào chữ ký: lệnh nghỉ ký trước khi biết lượng khớp.
- *(Rev 1.1, R8-11, review Claude M1)* TTL: `pay_under_mandate` gia hạn `Key::Payee` mỗi lần dùng (hiện chỉ
  `set_payee` gia hạn, `mandate/src/lib.rs:131-140`; `:167` chỉ `has`), `scaas-account.__check_auth` gia hạn
  instance (hiện chỉ `save`, `account/src/lib.rs:75-78`; `__check_auth` `:215-229` không gia hạn) — không thì account
  dùng hằng ngày bị archive ~60 ngày sau lần đổi khoá cuối, payee 60 ngày sau khi được cho phép.
- **`scaas-account`** — §2.

### Lệch so với EVM (R8-3, R8-4)

- **R8-3 Một chữ ký = một lần settle.** Auth entry tiêu nonce khi dùng: lệnh khớp một phần cần maker ký lại phần còn
  lại; `filled[order_hash]` (hash không chứa nonce) chặn overfill giữa các bản ký lại của cùng lệnh.
- **R8-4 Không gom nhiều cặp một tx.** Tx Soroban = một lời gọi host; lỗi ở một cặp hoàn tác cả tx (không "nguyên tử
  từng cặp"). Matcher nộp mỗi cặp một tx, song song qua lane.
- **R8-5 DEX qua relayer cần job hai chữ ký.** Job `signed_op` hiện mang một chữ ký; `settle` cần hai auth entry.
  Adapter hỗ trợ `extra.auth = [{from, payload, signature, public_key}]` bổ sung (cùng quy tắc), nên matcher (S5)
  chỉ cần xếp job với hai chữ ký. Sổ lệnh/matcher Soroban: seam cho S5.

## 4. Relayer (adapter `scaas-node/src/adapters/soroban.rs`)

- Lane = account `G…` dẫn xuất `m/44'/148'/i'` (SEP-0005), mỗi lane một tx bay (`lane_runner`), sequence đọc **đã
  commit** (`getLedgerEntries` account) — tx dùng `seq+1`, `time_bounds.max_time = valid_until` (review S14): tx chưa
  vào hết hạn cùng payload, sequence lane không treo.
- `build`: giải `payload` (XDR) → kiểm `network_id` = sha256(passphrase cấu hình) (chặn cross-network trước khi tốn
  phí), contract của invocation = `op.contract`, `from` khớp; dựng `SorobanAuthorizationEntry` (credentials Address
  với nonce/hạn từ payload + chữ ký); `InvokeHostFunction` = đúng invocation; `simulateTransaction` (auth enforce) ⇒
  footprint + resource fee; lỗi mô phỏng ⇒ `Revert` (job chết); lỗi mạng ⇒ `Transport`.
  *(Rev 1.1, R8-15, review Claude L1; NI R344)* `valid_until` (⇒ `TimeBounds.max_time` và hạn của runner) và
  `contract` lấy từ invocation đã ký (arg `valid_until`, `contract_address`), không từ JSON job (hiện
  `op["valid_until"]`, `soroban.rs:313`); lệch ⇒ `422 BAD_PAYLOAD`.
- *(Rev 1.1, R8-11, review Claude M1)* `restorePreamble` trong kết quả mô phỏng (hiện ⇒ `Revert` ⇒ job `dead`,
  `soroban.rs:325-327`) ⇒ lane nộp `RestoreFootprintOp` với footprint/phí của preamble, rồi dựng lại job; phí thuê
  khôi phục là tiền đặt lane trả theo NI **R346** (≤ `chain.max_deposit_per_job`, tính vào R340/R342 của `from`).
  Test e2e: account archive ⇒ khôi phục ⇒ thanh toán `mined`.
- `sign`: `fee = base + min_resource_fee·1.15`, `seq = committed + 1`, ký ed25519 trên
  `sha256(TransactionSignaturePayload)`. `tx_id = 0x‖hex(hash)`.
- `submit`: `sendTransaction`; `tx_status`: `getTransaction` (SUCCESS/FAILED/NOT_FOUND).
  Lớp theo NI R341 (đã đúng trong code): `sendTransaction` `ERROR` = chưa vào ledger ⇒ requeue miễn phí
  (`soroban.rs:368-378`); `TRY_AGAIN_LATER`/lỗi mạng ⇒ gửi lại cùng bytes; `getTransaction` `FAILED` = đã vào, **đã
  thu** inclusion fee + resource fee không hoàn ⇒ `Reverted` cuối (`:380-387`). Không có vòng requeue sau khi bị thu.
- *(Rev 1.1, R8-14, review Claude M2; NI R340/R342)* Adapter không cài `tx_fee` lẫn `lane_balance` (mặc định `None`,
  `adapter.rs:112-118`) ⇒ cầu dao `gas_budget`/`min_relayer_balance` mù trên Soroban. Cài `tx_fee` = `feeCharged` (trong
  `resultXdr` của `getTransaction`) cho **cả** `SUCCESS` lẫn `FAILED`, `lane_balance` = số dư native của lane (và của `fee_bump_lane`).
  Chủ thể `G…` lật state sau mô phỏng (tự `transfer` hết, tự nộp auth entry để đốt nonce) là rủi ro còn lại, chặn theo
  `from` bằng `subject_grief` (R342; chưa có trong `scaas-node/src`).
- *(Rev 1.1, R8-12, review Claude M3; R80)* `op_consumed` cài cho Soroban (hiện mặc định `Ok(None)`): đọc
  `getLedgerEntries` của khoá nonce host (`ContractData{contract: from, key: LedgerKeyNonce{nonce}, Temporary}`) —
  có ⇒ `Some(true)`; với `pay` thêm `ref_used(from, pay_ref)` (R8-9). Auth entry bị người khác (H1/H2, hoặc chính chủ
  thể) tiêu thì job ra `consumed`, không `dead`/`reverted` ⇒ ERP không bắt người trả ký lại một thao tác đã chạy.
- **Fee-bump (CAP-15):** cấu hình `params.fee_bump_lane = i` ⇒ tx của mọi lane được bọc `FeeBumpTransaction` ký bởi
  account phí `m/44'/148'/i'`; lane account chỉ cần số dư tối thiểu. Không bao giờ dùng sequence của chủ thể.
- Head-of-line (R62): lane khác chạy tiếp; chủ thể không có sequence trong đường đi (nonce không tuần tự, dẫn xuất
  từ `entryRef ‖ validUntil` như §1 — `fam_soroban.auth_nonce`, `fam_soroban.py:88-90`; SCaaS §7.4 ghi "random" là sai lệch văn bản).
- Finality: SCP — ledger đã đóng là final. `final_head` = `getLatestLedger` (+ quorum: các endpoint khác trả cùng hash
  qua `getLedgers`); `block_hash` qua `getLedgers`.
- Event: `getEvents` (contract = token đã đăng ký, ≤ 5/lọc — R8-7 *đã xong*: `TokenCfg.address` là chuỗi theo họ,
  `config.rs:302-306`, `index_step` chuyển nguyên; nguồn token nay là store của node, NI R95), chuẩn hoá `{event, contract, block_number = ledger,
  block_hash, tx_hash, log_index, from, to, amount, entry_ref, digest}` (hash `0x`+64 hex, địa chỉ strkey).
  `log_index` = chỉ số event trong tx (Soroban: một op mỗi tx). `getEvents` chỉ phục vụ trong cửa sổ lưu của RPC
  (quickstart 120 960 ledger): chain mới tạo trong Odoo phải đặt `indexed_block` ≈ ledger hiện tại (vận hành).

## 5. Odoo (`dms_blockchain/lib/fam_soroban.py`, `models/blockchain_soroban.py`)

- `build_terms(request, valid_until)` ⇒ `payload` (XDR §1), `digest` (§1.1), `contract` = token, `terms` =
  `{network_passphrase, contract, function: "pay", from, preimage_b64, nonce, expiration_ledger}` cho connector.
- `verify`: `from` = `G…` ⇒ ed25519 thật trên `sha256(payload)` với khoá master trong strkey (chữ ký 64 byte hex),
  qua `cryptography` (đã là phụ thuộc của `lib/custody.py` — R50) thay vì ed25519 thuần Python (R8-6); account
  multisig/đổi signer ⇒ chữ ký master có thể không đủ ngưỡng: node mô phỏng phân xử. `C…` ⇒ chỉ kiểm hex/độ dài ⇒
  `None`.
- `blockchain.chain`: `soroban_anchor_ts` (§1.2) cập nhật trong `chain_event_ingest` (override nhỏ trong file mô
  hình của luồng).

## 6. Portal (`dms_blockchain_bridge/static/src/js/connectors/soroban.js`)

Freighter: `@stellar/freighter-api` bản ghim, vendored `static/lib/`, nạp lười khi người trả chọn Stellar.
`connect()` = `requestAccess` ⇒ `{address}`; `sign(terms)` = `signAuthEntry(preimage_b64, {networkPassphrase,
address})` ⇒ `{signature: hex 64 byte, publicKey: address}`. Passkey/seed: account C… — UI ký của S4.

## 7. Kiểm thử

- Contract (`cargo test`): token/mandate/dex/account; auth **thật** (`set_auths` + chữ ký ed25519/P-256 thật qua
  account), không chỉ `mock_all_auths`; **anti-lock**: chủ thể ký X trên token 1 và Y trên token 2; giữ X; Y thành
  công; rồi X thành công; nonce đã dùng thì replay bị từ chối.
- Vector chéo: cùng `payload`/`digest` từ Python, contract test và adapter Rust (hằng số ghim).
- Adapter: unit + proptest decoder; e2e `tests/e2e_soroban.rs` (`#[ignore]`) trên `stellar/quickstart` local
  (cổng 31980): hai lane từ mnemonic 24 từ, thanh toán qua `lane_step`, finality qua `index_step`, anti-lock end to end.
- Odoo: build/verify/accept trên `dms_test_chain_8`.

## 8. Thanh toán bảo mật (khả thi)

Zether là EVM-first (R34 §5). Soroban có host function BLS12-381 (CAP-59) và BN254 (CAP-74, protocol 25) + Poseidon
⇒ verifier Bulletproofs/ElGamal **khả thi về nguyên tắc**, nhưng ngân sách CPU một tx (~100 M instruction) có thể
không đủ cho Bulletproofs range proof n=64 ⇒ cần đo; ứng viên thực tế hơn là Groth16 (một pairing check) với mạch
Zether-like. Không xây ở round này.

## 9. Ruling rev 1.1 — review Claude 1 (2026-10-07)

- **R8-9** (H1) `Token::pay` khoá `Key::PayRef(from, pay_ref)` (không còn toàn cục) và từ chối `amount <= 0`
  (`Error::NonPositiveAmount`); `ref_used(from, pay_ref)`. Mandate giữ khoá `Key::Ref(pay_ref)` của nó (chỉ delegate
  tiêu được ref). Cùng hướng với Cosmos C1 (bỏ khoá toàn cục) và EVM `MetaToken` (không khoá `pay_ref`). Test: bên thứ
  ba `pay(self, x, 0, ref_nạn_nhân)` ⇒ `NonPositiveAmount`; `pay(self, x, 1, ref_nạn_nhân)` không chặn `pay` của nạn
  nhân; cùng `from` trả hai lần cùng `pay_ref` (hai chữ ký) ⇒ `RefUsed`; `pay_under_mandate` không bị đốt bởi bên thứ
  ba.
- **R8-10** (H2) DEX Soroban gắn người settle theo DEX RS5-15: `Order.relayer: Address` bắt buộc (không có dạng mở),
  `settle` gọi `maker.relayer.require_auth()` và đòi `maker.relayer == taker.relayer`. Test: bên thứ ba nộp lại hai
  auth entry với `maker_fill = 1` ⇒ fail; relayer đúng settle được. Thuộc **DX-FIX4**.
- **R8-11** (M1) TTL + khôi phục: `pay_under_mandate` gia hạn `Key::Payee`; `__check_auth` gia hạn instance của
  account; adapter nộp `RestoreFootprint` từ lane khi mô phỏng trả `restorePreamble` rồi thử lại (NI R346 cho phí
  thuê). Test contract: TTL sau `pay_under_mandate`/`__check_auth` được đẩy lên; e2e: archive ⇒ restore ⇒ `mined`.
- **R8-12** (M3) `op_consumed` đọc khoá nonce host (+ `ref_used(from, pay_ref)` cho `pay`). Test: auth entry đã bị
  nộp bởi người khác ⇒ job `consumed`.
- **R8-13** (L2) WebAuthn: từ chối `"crossOrigin":true` và mọi `topOrigin`. Test: assertion có `crossOrigin:true` ⇒
  `BadClientData`.
- **R8-14** (M2) Adapter cài `tx_fee` (SUCCESS và FAILED) và `lane_balance` (lane + `fee_bump_lane`) cho cầu dao (NI
  R340). Test: tx FAILED cộng `feeCharged` vào `spent`.
- **R8-15** (L1) `build` lấy `valid_until` và `contract` từ invocation đã ký; JSON khác ⇒ `BAD_PAYLOAD` (NI R344).
  Test: job JSON `valid_until` lớn hơn arg ký ⇒ từ chối.

### Quy tắc node chung (NI rev 3.7, R340–R349)

Soroban áp: **R340** (R8-14), **R341** (lớp §4: `ERROR` chưa vào ⇒ requeue; `FAILED` đã thu ⇒ `Reverted`), **R342**
(`subject_grief` theo `from` — rủi ro M2 còn lại), **R344** (R8-15), **R345** (`max_value_out` = 0), **R346** (phí
thuê `RestoreFootprint`, R8-11), **R349** (khoá ed25519 G… ký 32 byte thô như Hedera ED25519: một khoá mỗi họ).
**R343** chưa áp: Soroban không có trên mesh v1 (R77; `mesh/digest.rs:146` trả `FamilyNotSupported`) — khi vào mesh,
bộ giải mã kiểm ed25519 của `G…` cục bộ. **R347**/**R348** không áp (không journal riêng; quy tắc immutable chỉ cho
Sui/Aptos/Solana).

### Luồng code (owner: không sửa code trong pha spec)

| Luồng | Lớp | Nội dung | Ruling | Sau |
|---|---|---|---|---|
| **NET-SOROBAN-FIX1** | Contract `token`, `mandate`, `account` | Khoá `(from, pay_ref)` + `amount > 0`; gia hạn TTL payee/instance; WebAuthn `crossOrigin`/`topOrigin`; tests; deploy mới (Odoo đổi địa chỉ token/account mẫu) | R8-9, R8-11 (contract), R8-13 | — |
| **NET-SOROBAN-FIX2** | Node `adapters/soroban.rs` | `RestoreFootprint` + thử lại; `op_consumed`; `tx_fee`/`lane_balance`; `valid_until`/`contract` từ payload; tests | R8-11 (adapter), R8-12, R8-14, R8-15 | NI **NR1** (R340–R342), **NR2** (R344, R346); `ref_used(from, …)` sau FIX1 |
| DX-FIX4 (spec DEX) | Contract `dex` | `Order.relayer` bắt buộc + `require_auth` | R8-10 (= RS5-15) | — |

## 10. Review log

### Claude review disposition — review 1 (2026-10-07, `docs/reviews/specs/2026-10-03-net-soroban-claude-review-1.md`)

Verdict của review: FIX-THEN-GO, 0 Critical. Đối chiếu từng finding với code (file:line) trước khi nhận: 9 finding
(M4 tách 4 mục ⇒ 12 dòng), **12 nhận, 0 từ chối** (2 nhận có chỉnh).

| # | Sev | Kiểm với code | Kết luận | Xử lý |
|---|---|---|---|---|
| H1 | high | `token/src/lib.rs:203-209` khoá `PayRef(pay_ref)` toàn cục; `check_amount` `:113-117` nhận 0 (`move_funds` `:137-145` gọi nó); mandate đi qua `token.pay` `mandate/src/lib.rs:193` | Đúng | R8-9, §1, §3; NET-SOROBAN-FIX1 |
| H2 | high | `dex/src/lib.rs:153, 158-159` chỉ trói lệnh; `Order` không có relayer (`:35-47`) | Đúng; **chỉnh cách sửa:** gắn người settle (RS5-15) chứ không gắn `(order, fill)` (lệnh nghỉ không biết lượng khớp); Soroban không có dạng lệnh mở | R8-10, §3; DX-FIX4 |
| M1 | med | `soroban.rs:325-327` `restorePreamble` ⇒ `Revert`; `account/src/lib.rs:75-78` chỉ `save` gia hạn, `__check_auth` `:215-229` không; `mandate/src/lib.rs:131-140` chỉ `set_payee` gia hạn payee, `:167` chỉ `has` | Đúng | R8-11, §3, §4; NET-SOROBAN-FIX1/2 |
| M2 | med | Cầu dao chỉ nạp ở `Mined` (`adapter.rs:270-276`); không có `grief` trong `scaas-node/src` | Đúng; **chỉnh (nặng hơn):** Soroban không cài `tx_fee`/`lane_balance` (`adapter.rs:112-118` mặc định `None`) nên cả `Mined` cũng không vào ngân sách | R8-14, §4; NI R340/R342; NET-SOROBAN-FIX2 |
| M3 | med | `soroban.rs` không có `op_consumed` ⇒ `Ok(None)` (`adapter.rs:127-129`) | Đúng | R8-12, §4; NET-SOROBAN-FIX2 |
| M4a | med | `config.rs:302-306` `TokenCfg.address: String` | Đúng (R8-7 đã xong) | §4 sửa; bảng "bị thay" |
| M4b | med | `chains/soroban/` không còn; nay `smartcontracts/soroban/contracts/` | Đúng | §3 sửa |
| M4c | med | §4/§5 luồng pull Odoo, `node_config` | Đúng (NI R87/R95/R101) | Bảng "bị thay" |
| M4d | med | `fam_soroban.py:88-90` nonce = `sha256("scaas.soroban.nonce" ‖ entryRef ‖ validUntil)`; SCaaS §7.4 ghi "random `i64`" | Đúng (spec khớp code; SCaaS sai) | §4 sửa chữ "ngẫu nhiên"; SCaaS báo lead (không sửa ở đây) |
| L1 | low | `soroban.rs:313` `op["valid_until"]` ⇒ `TimeBounds.max_time` + hạn runner | Đúng | R8-15, §4; NI R344; NET-SOROBAN-FIX2 |
| L2 | low | `account/src/lib.rs:149-153` chỉ `type`/`challenge`/`origin` | Đúng | R8-13, §2; NET-SOROBAN-FIX1 |
| L3 | low | `__check_auth` bỏ `_contexts` (`account/src/lib.rs:215`) | Đúng (seam R8-8) | §2 rủi ro còn lại tới UA R298 |

## 11. Lịch sử bản

| Rev | Ngày | Thay đổi |
|---|---|---|
| 1.0 | 2026-10-03 | Bản đầu (S8): R8-1…R8-8 |
| 1.1 | 2026-10-07 | Gộp review Claude 1: bảng "bị thay" (NI R87/R95/R101, layout `smartcontracts/soroban/`, R8-7 xong); §1 (b) sửa; R8-9…R8-15; quy tắc node chung NI R340–R349; luồng code NET-SOROBAN-FIX1…2 (+ DX-FIX4) |
