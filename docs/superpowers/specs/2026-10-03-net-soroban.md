# Luồng S8 — Stellar Soroban (R65)

**Ngày:** 2026-10-03 · **Thuộc:** round 3 (`2026-10-03-blockchain-round3-design.md` §D.0, §D.3, §D.6, §B, R30/R31/R32/R62/R65).
Ruling của luồng này đánh số `R8-n` (lead đánh số lại khi hợp nhất).

## 1. Meta-tx cấp contract = authorization gốc của Soroban (R30, R65)

Chủ thể **không** gửi tx và **không** dùng sequence tài khoản của mình. Chủ thể chỉ ký một
`HashIdPreimage::SorobanAuthorization` (XDR), relayer đặt chữ ký vào `SorobanAuthorizationEntry` của một tx
mà **lane account** của relayer là source (sequence riêng của lane, trả phí).

Payload chủ thể ký (bytes XDR chính xác, Odoo dựng không RPC — R20):

```
HashIdPreimage {
  type = ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9)
  network_id                = sha256(network_passphrase)          -- tách mạng
  nonce                     = i64(sha256("bamboo.soroban.nonce" ‖ entryRef ‖ validUntil_be64)[0..8])
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

Chống replay: (a) host từ chối cặp (from, nonce) đã dùng; (b) `pay_ref` chỉ trả một lần (persistent, gia hạn TTL);
(c) khác mạng ⇒ `network_id` khác ⇒ chữ ký sai; khác contract ⇒ `contract_address` khác ⇒ không khớp invocation.

### 1.1 Digest (khớp op ⇄ event)

Host không cho contract biết hash chữ ký, nên contract tự tính **digest thao tác** và phát trong
`MetaTransactionExecuted`:

```
digest = sha256( ScVal::Vec[ Symbol("bamboo_metaop_v1"), BytesN<32>(network_id), Address(contract),
                             Symbol(function_name), Vec(args) ].to_xdr() )
```

Odoo, contract (test) và adapter Rust tính cùng một giá trị (vector chéo §6). Args chứa `pay_ref` và `valid_until`
⇒ mỗi lần phát (hạn khác) một digest khác; `UNIQUE(chain_id, digest_hash)` giữ nguyên nghĩa.

### 1.2 Hạn ledger không cần RPC (R8-1)

`signature_expiration_ledger` phải nằm trong `[ledger hiện tại, ledger hiện tại + max_entry_ttl − 1]`. Odoo không gọi
RPC, nên dùng **mốc** do indexer để lại: mỗi lần `chain_event_ingest` tiến cursor của chain `soroban`, Odoo ghi
`soroban_anchor_ts` (giờ server) cạnh `indexed_block` (ledger final). Ledger không đóng nhanh hơn 1/giây (SCP), nên

`exp = indexed_block + (valid_until − soroban_anchor_ts) + 16`

là **cận trên**: không bao giờ hết hạn trước `valid_until` (hạn thật do contract kiểm theo giây). Mốc cũ hơn 7 ngày
(indexer ngừng) ⇒ từ chối phát (cận trên có thể vượt `max_entry_ttl`). Chain chưa index lần nào ⇒ từ chối phát.

## 2. Lược đồ chữ ký chủ thể

| Kiểu `from` | Ai ký | Chữ ký trong auth entry | Odoo kiểm |
|---|---|---|---|
| `G…` (ví Freighter, ví seed R32 `m/44'/148'/i'`) | khoá ed25519 của account (host kiểm ngưỡng/signer) | `Vec[Map{public_key: Bytes32, signature: Bytes64}]` (relayer dựng từ 64 byte) | ed25519 thật (`cryptography`) với khoá master trong strkey |
| `C…` = `bamboo-account` (account chủ thể nhiều khoá — R31/R32) | passkey P-256 WebAuthn hoặc khoá ed25519 từ seed | ScVal `Signature` của account (XDR hex, relayer chèn nguyên văn) | không (`None`) — mô phỏng của node phân xử (R27) |

`bamboo-account.__check_auth(signature_payload, Signature, contexts)`:
- `Ed25519{key_id, signature}`: `ed25519_verify(pk, signature_payload, sig)`.
- `WebAuthn{key_id, authenticator_data, client_data_json, signature(r‖s, low-s), proof}`: challenge =
  `signature_payload` nếu `proof` rỗng, ngược lại gốc Merkle sha256 của lá `sha256(sha256(0x00 ‖ payload))` với cặp
  sắp xếp (gom lô R31); `clientDataJSON` chứa `"type":"webauthn.get"`, `"challenge":"<base64url(challenge)>"`,
  `"origin":"<origin đã đăng ký>"`; `authenticator_data[0..32] = rp_id_hash`; cờ UP (0x01) và UV (0x04);
  `secp256r1_verify(pk65, sha256(authData ‖ sha256(clientDataJSON)), sig)` (host từ chối high-s — CAP-51).
- Vòng đời khoá: `add_key`/`remove_key` cần chính account uỷ quyền (một khoá hiện có ký); không bao giờ còn 0 khoá.
  Guardian + trễ khôi phục: **seam** (R8-2) — chưa xây trên Soroban, ghi HANDOFF.
- Account phải tồn tại trên ledger trước khi trả (deploy không cần quyền: `__constructor(first_key)`). Chủ thể `G…`
  cũng phải tồn tại (yêu cầu của host).

## 3. Contract (`chains/soroban/`, soroban-sdk 25.3.0, Rust 1.90)

- **`bamboo-token`** — SEP-41 (`balance`, `transfer`, `transfer_from`, `approve`, `allowance`, `burn`,
  `burn_from`, `decimals`, `name`, `symbol`) + `mint` (admin) + `pay(from, to, amount, pay_ref, valid_until)`:
  `from.require_auth()`, hạn, `pay_ref` một lần, phát `PaymentSettled{from,to | amount,pay_ref}` và
  `MetaTransactionExecuted{from | digest}`. **`approve` chỉ cho spender là contract** (`executable()` = Wasm hoặc
  StellarAsset) — R26. Không phí (R10 trên mạng mới). Storage: số dư/allowance/`pay_ref` persistent, gia hạn TTL.
- **`bamboo-mandate`** (như `MandateWallet` R25): một owner; tiền nằm trong contract; theo token: delegate, hạn mức
  lần/kỳ, kỳ, hạn dùng, payee cho phép; `pay_under_mandate(token, payee, amount, pay_ref, valid_until)` —
  `delegate.require_auth()` rồi `token.pay(self, payee, …)` (cùng `PaymentSettled` ⇒ Odoo đối soát như thanh toán
  tay); `pay_ref` một lần; `revoke(token, by)` bởi owner **hoặc** delegate (kill switch); `withdraw` của owner.
  Owner gasless tự nhiên: auth gốc của owner qua relayer (không cần `executeAsOwner`).
- **`bamboo-dex`** `settle(maker, taker, maker_fill)` (R35): `require_auth_for_args((order,))` cho **cả hai** lệnh;
  giới hạn giá của cả hai (giá maker; taker nhận ít nhất giá của mình); `filled[order_hash]` không overfill; phí ppm
  maker/taker theo thị trường (cặp token sắp xếp), bật/tắt, trần 1 % (10 000 ppm) và ≤ `max_fee_ppm` trong lệnh ký;
  token đi bằng `transfer_from` với DEX là spender (allowance chỉ cho contract — R26); `cancel(order)` do maker uỷ
  quyền đặt `filled = sell_amount` ⇒ lệnh huỷ không bao giờ settle. `order_hash = sha256(order.to_xdr())`.
- **`bamboo-account`** — §2.

### Lệch so với EVM (R8-3, R8-4)

- **R8-3 Một chữ ký = một lần settle.** Auth entry tiêu nonce khi dùng: lệnh khớp một phần cần maker ký lại phần còn
  lại; `filled[order_hash]` (hash không chứa nonce) chặn overfill giữa các bản ký lại của cùng lệnh.
- **R8-4 Không gom nhiều cặp một tx.** Tx Soroban = một lời gọi host; lỗi ở một cặp hoàn tác cả tx (không "nguyên tử
  từng cặp"). Matcher nộp mỗi cặp một tx, song song qua lane.
- **R8-5 DEX qua relayer cần job hai chữ ký.** Job `signed_op` hiện mang một chữ ký; `settle` cần hai auth entry.
  Adapter hỗ trợ `extra.auth = [{from, payload, signature, public_key}]` bổ sung (cùng quy tắc), nên matcher (S5)
  chỉ cần xếp job với hai chữ ký. Sổ lệnh/matcher Soroban: seam cho S5.

## 4. Relayer (adapter `bamboo-node/src/adapters/soroban.rs`)

- Lane = account `G…` dẫn xuất `m/44'/148'/i'` (SEP-0005), mỗi lane một tx bay (`lane_runner`), sequence đọc **đã
  commit** (`getLedgerEntries` account) — tx dùng `seq+1`, `time_bounds.max_time = valid_until` (review S14): tx chưa
  vào hết hạn cùng payload, sequence lane không treo.
- `build`: giải `payload` (XDR) → kiểm `network_id` = sha256(passphrase cấu hình) (chặn cross-network trước khi tốn
  phí), contract của invocation = `op.contract`, `from` khớp; dựng `SorobanAuthorizationEntry` (credentials Address
  với nonce/hạn từ payload + chữ ký); `InvokeHostFunction` = đúng invocation; `simulateTransaction` (auth enforce) ⇒
  footprint + resource fee; lỗi mô phỏng ⇒ `Revert` (job chết); lỗi mạng ⇒ `Transport`.
- `sign`: `fee = base + min_resource_fee·1.15`, `seq = committed + 1`, ký ed25519 trên
  `sha256(TransactionSignaturePayload)`. `tx_id = 0x‖hex(hash)`.
- `submit`: `sendTransaction`; `tx_status`: `getTransaction` (SUCCESS/FAILED/NOT_FOUND).
- **Fee-bump (CAP-15):** cấu hình `params.fee_bump_lane = i` ⇒ tx của mọi lane được bọc `FeeBumpTransaction` ký bởi
  account phí `m/44'/148'/i'`; lane account chỉ cần số dư tối thiểu. Không bao giờ dùng sequence của chủ thể.
- Head-of-line (R62): lane khác chạy tiếp; chủ thể không có sequence trong đường đi (nonce ngẫu nhiên).
- Finality: SCP — ledger đã đóng là final. `final_head` = `getLatestLedger` (+ quorum: các endpoint khác trả cùng hash
  qua `getLedgers`); `block_hash` qua `getLedgers`.
- Event: `getEvents` (contract = `params.contracts`, ≤ 5/lọc), chuẩn hoá `{event, contract, block_number = ledger,
  block_hash, tx_hash, log_index, from, to, amount, entry_ref, digest}` (hash `0x`+64 hex, địa chỉ strkey).
  `log_index` = chỉ số event trong tx (Soroban: một op mỗi tx).

## 5. Odoo (`dms_blockchain/lib/fam_soroban.py`, `models/blockchain_soroban.py`)

- `build_terms(request, valid_until)` ⇒ `payload` (XDR §1), `digest` (§1.1), `contract` = token, `terms` =
  `{network_passphrase, contract, function: "pay", from, preimage_b64, nonce, expiration_ledger}` cho connector.
- `verify`: `from` = `G…` ⇒ ed25519 thật trên `sha256(payload)` với khoá trong strkey (chữ ký 64 byte hex/base64);
  `C…` ⇒ chữ ký phải là XDR hex hợp lệ về cấu trúc ⇒ `None`.
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
