# Mạng Hedera (HSCS) — thiết kế luồng S6 (chi tiết R63)

**Ngày:** 2026-10-03 · **Bổ sung cho:** `2026-10-03-blockchain-round3-design.md` §D.1 (R63), §D.0, §B, §D.6.
Ruling của luồng này đánh số `R6-n` (lead đánh số lại khi hợp nhất).

## 1. Tóm tắt quyết định

Hedera Smart Contract Service chạy EVM (Besu) nên **dùng lại nguyên** bộ contract Solidity: `MetaToken`
(meta-tx EIP-712 cấp contract), `MandateWallet`, `MetaTxDex`, `SubjectAccount` (luồng S4). Phần riêng của Hedera:

| Mảnh | Riêng Hedera | File |
|---|---|---|
| Token | `HederaMetaToken is MetaToken`: chữ ký **ED25519 của tài khoản Hedera** kiểm qua precompile HIP-632 `isAuthorizedRaw` (0x16a); `associateUnderlying()` cho wrapper tầng 2 trên token HTS | `smartcontracts/src/hedera/HederaMetaToken.sol` |
| Xác thực tài khoản | thư viện gọi `isAuthorizedRaw` bằng `CALL` (R6-6; gas chặn 100 000), revert/rác ⇒ `false` | `smartcontracts/src/hedera/HederaAccountAuth.sol` |
| Mandate | `HederaMandateWallet is MandateWallet`: thêm `executeAsOwnerRaw` cho owner là tài khoản ED25519 | `smartcontracts/src/hedera/HederaMandateWallet.sol` |
| DEX | không đổi — mỗi chân là meta-tx trên token, nên chân ký ED25519 tự đi qua `HederaMetaToken` | — |
| Relayer | `adapters/hedera.rs`: adapter EVM trỏ vào **Hedera JSON-RPC Relay**, chạy dưới `lane_runner` (một tx bay mỗi lane), phí `eth_gasPrice × 1.2`, priority 0 | `bamboo-node/src/adapters/hedera.rs` |
| Odoo | người trả `0.0.N` (địa chỉ long-zero) ⇒ đường khoá gốc ED25519: phát digest, nhận chữ ký 64 byte + khoá công khai, kiểm ed25519 | `dms_blockchain/lib/fam_hedera.py`, `models/blockchain_hedera.py` |
| Portal | connector ký digest bằng khoá ED25519 (seam cho ví seed / HashPack) | `dms_blockchain_bridge/static/src/js/connectors/hedera.js` |

Đường **payer-sponsored** (chủ thể tự gửi tx tài khoản Hedera, người khác trả phí) **không làm** (R30).
HCS (nhật ký kiểm toán) và scheduled transaction: ngoài phạm vi thanh toán (HANDOFF).

## 2. Payload ký (MetaOp v1 trên Hedera)

`MetaOp` v1 của §D.0 trên Hedera **chính là** `MetaTransaction` EIP-712 của `MetaToken` — không có định dạng thứ hai:

| MetaOp v1 | EIP-712 (`MetaToken`) |
|---|---|
| `domain="bamboo.metaop.v1"` | `EIP712Domain{name:"Bamboo MetaToken", version:"1"}` |
| `network` | `chainId` = 295 mainnet / 296 testnet / 297 previewnet / 298 localnet |
| `contract` | `verifyingContract` = clone token |
| `op` | `data` = `pay(bytes32)` ‖ payRef (op `trade` = `trade(address,uint256,address)`) |
| `from, to, amount` | `from, to, value` |
| `payRef(32)` | trong `data` |
| `lane(32)`, `nonce` | `batch = keccak(entryRef)` (R9), `nonce = 0` |
| `validUntil` | `validUntil` |
| `relayer` | `relayer` + cờ `MODE_RESTRICT_RELAYER` |
| `extra` | `data` (băm `keccak256(data)` trong struct) |

Chống replay chéo mạng: `chainId` trong domain (Hedera mainnet 295 ≠ mọi EVM khác). Chéo contract:
`verifyingContract`. Chéo lần: `(from, batch) → nonce` của chính token. Hết hạn: `validUntil` so với
`block.timestamp` (giây đồng thuận Hedera).

Digest = `keccak256(0x1901 ‖ domainSeparator ‖ structHash)` — Python (`lib/eip712.py`), Solidity (`metaTxDigest`)
và Rust (`metatx::digest`) tính cùng một số; vector chung `smartcontracts/test/vectors/hedera_kat.json`.

## 3. Lược đồ chữ ký

| Loại chủ thể | `from` | Chữ ký | Kiểm ở đâu |
|---|---|---|---|
| Tài khoản ECDSA có EVM alias (MetaMask qua EIP-6963, ví seed `m/44'/3030'/0'/0/i`) | alias `0x…` | 65 byte `r‖s‖v`, low-s | `ecrecover` (như EVM) |
| Tài khoản Hedera khoá **ED25519 đơn** (ví seed `m/44'/3030'/0'/0'/i'`) | long-zero `0x000…N` (= `0.0.N`) | **64 byte** ed25519 trên **đúng 32 byte digest** | HIP-632 `isAuthorizedRaw(from, digest, sig)` |
| Smart account (passkey, SubjectAccount S4; ví hợp đồng) | địa chỉ contract | blob của account | ERC-1271 |

**Quy tắc phân nhánh** trong `HederaMetaToken._requireValidSignature`: `from` có code ⇒ ERC-1271 (giữ nguyên);
`from` không code **và** chữ ký dài đúng 64 byte ⇒ HIP-632; còn lại ⇒ `ecrecover` của lớp cha.
Vì sao độ dài ở đây không mơ hồ: OZ 5.2 `ECDSA.tryRecover(bytes)` chỉ nhận 65 byte (không EIP-2098), nên 64 byte
chưa bao giờ là ECDSA trong hệ; và chính precompile phân loại theo độ dài (65–72 = EC, 64 = ED). Khoá ↔ tài khoản
được ràng **on-chain** bởi precompile (đọc khoá của tài khoản trong state Hedera), nên khoá công khai client gửi
không bao giờ là căn cứ cấp quyền.

Hành vi precompile (đọc mã `IsAuthorizedRawCall.java`, hiero-consensus-node, và thử trên testnet 2026-10-03):
- `isAuthorizedRaw(address,bytes,bytes) returns (bool)`, selector `0xb2a31da4`, phí gas = phí `ecrecover` (3 000).
- ED: tài khoản phải có khoá ED25519 **đơn** (không KeyList/Threshold), `messageHash` đúng 32 byte, chữ ký ed25519
  RFC 8032 trên chính 32 byte đó (không prefix, không băm lại).
- Tài khoản không tồn tại / khoá phức hợp / sai kiểu khoá ⇒ **revert** (không phải `false`). Thư viện của ta coi
  revert là "không được uỷ quyền".
- Testnet: `eth_call` tới 0x16a với tài khoản ED25519 có thật `0.0.6000019` + chữ ký rác ⇒ `false`; tài khoản không có
  ⇒ `execution reverted: INVALID_ACCOUNT_ID`. Vậy review S2 (HIP-632 có tồn tại không) đã trả lời: **có**, ở
  mainnet/testnet từ services v0.52. Đường dương (chữ ký đúng ⇒ `true`) chưa thử trên mạng thật vì không có tài
  khoản testnet được cấp tiền — ghi khoảng trống §9.
- **Phải gọi bằng CALL, không STATICCALL (R6-6).** `IsAuthorizedRawCall` không cài `allowsStaticFrame()` (mặc định
  `false`, `Call.java`), và `AbstractNativeSystemContract` HALT system contract trong frame tĩnh. Thử trên testnet
  (initcode qua `eth_call`, 2026-10-03): cùng tham số, STATICCALL ⇒ `ok = false` không dữ liệu; CALL ⇒ `ok = true` +
  `false`. Vì `ERC20MetaTx._requireValidSignature` là `view`, `HederaMetaToken` gọi qua con trỏ hàm ép kiểu `view`
  (`HederaAccountAuth.asView`) — an toàn vì chỗ gọi duy nhất là `executeMetaTransaction` (không view) và 0x16a không
  ghi state, không gọi ngược. Mock forge ghi storage nên cũng HALT khi bị STATICCALL (test chặn quay lại).
  Gas của lời gọi bị chặn 100 000: khi từ chối (tài khoản lạ, khoá phức hợp) system contract tính **toàn bộ** gas
  còn lại của frame (`reversionWith(rce, frame.getRemainingGas())`); trần giữ cho chữ ký xấu lọt mô phỏng không đốt
  hết gas tx của relayer (phí thật 3 000).
- Không phải tài khoản ECDSA long-zero: nhánh EC của precompile từ chối địa chỉ long-zero; tài khoản ECDSA luôn
  dùng alias `0x…` (đường `ecrecover`).

**Seam (R6-4):** HashPack/WalletConnect `hedera_signMessage` (HIP-820) ký `"\x19Hedera Signed Message:\n" + len + msg`
⇒ **không** tương thích `isAuthorizedRaw` (32 byte). Kiểm được bằng `isAuthorized(address, message, SignatureMap
protobuf)` (cũng hỗ trợ khoá ngưỡng/KeyList) — để sau: cần dựng `SignatureMap` trong Solidity và kiểm trên mạng
thật. Passkey trên Hedera đi qua `SubjectAccount` (ERC-1271, P-256 Solidity của OZ nếu không có precompile 0x100 —
probe `has_p256_precompile`).

## 4. Relayer, phí, khoá

- Lane = tài khoản **ECDSA** secp256k1 (`m/44'/3030'/0'/0/i`, R60) dùng qua **alias EVM**; JSON-RPC Relay chỉ nhận tx
  Ethereum ký ECDSA. Tài khoản lane phải **tồn tại** trên ledger (tạo bằng cách chuyển HBAR tới alias — auto-create
  HIP-583) — review S22: bước vận hành + adapter kiểm số dư lane trước mỗi job; lane số dư 0 (tài khoản chưa có hoặc
  hết HBAR) ⇒ job về hàng đợi với lỗi rõ ràng, không ký, không gửi.
- Relayer trả gas bằng HBAR từ lane của nó; chủ thể không cần HBAR, không gửi tx.
- Phí: Hedera có **giá gas cố định** theo biểu phí (testnet ghi được `eth_gasPrice = 0xca900a7c00` = 870 gwei-tương
  đương; `eth_maxPriorityFeePerGas = 0`; `eth_feeHistory` trả base fee hằng, reward 0). Adapter ký type-2 với
  `maxFee = gasPrice × 1.2`, `priority = 0`; Hedera chỉ thu theo giá biểu phí nên phần dư không mất. Precheck số
  dư của Relay tính `gasLimit × maxFee` ⇒ lane cần ≈ `gasLimit × 1.2 × gasPrice` HBAR mỗi tx (không phải gấp đôi như
  ước lượng `eth_feeHistory` của alloy — lý do adapter không dùng `Chain::fees`).
- Gas limit: ước lượng + 20 %. Hedera thu **tối thiểu 80 % gas limit** (HIP-185) ⇒ không đặt limit cao "cho chắc";
  trần `max_gas_per_tx` cấu hình (mạng giới hạn 15 M/tx).

## 5. Tránh head-of-line (R62) — R6-1

Hedera **không có mempool**: Relay chuyển tx tới một consensus node; tx vào đồng thuận trong vài giây hoặc bị từ chối
ở precheck. Hệ quả:
- Không có khái niệm "thay thế tx kẹt" (replacement) hay gap-fill: một nonce không bao giờ treo trong mempool.
- **Pipeline nhiều nonce trong một lane là nguy hiểm**: tx nonce N+1 có thể tới đồng thuận (qua node khác) trước tx
  N ⇒ `WRONG_NONCE`, relayer vẫn bị thu phí node. Vì vậy Hedera chạy **`lane_runner`** (một tx bay mỗi lane, đọc
  nonce đã commit trước mỗi job) chứ không chạy `submit.rs` (pipeline + thay thế). Song song giữa các lane.
- Chủ thể không có sequence trong đường đi: lane meta-tx là `batch = H(entryRef)` **trong từng contract**
  (R9/R30) — một thao tác bị giữ lại ở contract 1 không chặn thao tác của cùng chủ thể ở contract 2 (test
  anti-lock: forge + e2e).
- Định tuyến (review H1/M1, sửa ở file của lead trong commit riêng): `main.rs` chọn runner theo
  `ChainCfg::uses_adapter()` (= `family != "evm"`), nên Hedera đi `adapters::build` → `HederaAdapter` + `lane_runner`/
  `index_runner`. `is_evm()` giữ cho kiểm cấu hình (Hedera chỉ cần `evm_chain_number`, không cần `network`);
  `chain_key()` bỏ qua `network` với họ kiểu EVM ⇒ luôn `hedera:<chainId>` như Odoo. Gateway mở/DEX matcher HTTP hiện
  là EVM-only — Hedera dùng outbox Odoo cho tới khi gateway đi qua `ChainAdapter`.

## 6. Finality, event

- Hashgraph aBFT: tx đã vào record file là **final**; "block" của Relay = record file (~2 s), dữ liệu đọc từ mirror
  node (trễ vài giây). `final_head` = block mới nhất mirror trả (mode `instant`, độ sâu 0), quorum hash giữa các
  `rpc_urls` như EVM. Node nhận `finality.mode = "instant"` cho `hedera` (= độ sâu 0).
- Hash block: Relay cắt hash record file 48 byte còn 32 byte (`0x`+64 hex) — ổn định, khớp `block_hash(height)`.
- Event: `PaymentSettled`, `MetaTransactionExecuted` của token đã đăng ký, chuẩn hoá y hệt EVM (`indexer::encode_event`;
  địa chỉ `0x` chữ thường; tài khoản ED25519 không alias ở dạng long-zero; token/tài khoản ECDSA ở địa chỉ EVM thật
  — xem §8).
  `eth_getLogs` của Relay giới hạn 1 000 block/lần — trùng trần `index_step`.
- Receipt chưa có ở mirror ⇒ `TxStatus::Unknown` (runner chờ tới hạn payload). Receipt `status 0x0`: dữ liệu revert
  ABI hoặc `CONTRACT_REVERT_EXECUTED` ⇒ `Reverted{reason}` (vĩnh viễn); mã Hedera khác trong tập đã biết
  (`WRONG_NONCE`, `INSUFFICIENT_PAYER_BALANCE`, `DUPLICATE_TRANSACTION`, `BUSY`…) = meta-tx KHÔNG chạy ⇒
  `adapter::Rejected` ⇒ job về `queued`, dựng lại với nonce đã commit (review M2). Precheck của Relay từ chối
  `eth_sendRawTransaction` ⇒ cũng `Rejected`; "trùng" = chính tx đó đã vào ⇒ coi như đã gửi. Payload hết hạn ⇒ `dead`
  ngay ở `build`, trước bước kiểm số dư lane. Chỉ chuỗi trong tập mã đã biết mới được đọc là mã Hedera.
- Danh sách token để lọc event: token Odoo đăng ký, từ `node_config` mỗi vòng `index_step`; danh sách rỗng ⇒ con trỏ
  KHÔNG tiến (review H2, cùng hình dạng code với r3-cosmos). Không còn `params.tokens`.

## 7. Mandate, DEX, HTS

- **Mandate:** `MandateWallet` (R25) dùng nguyên: delegate = khoá custody secp256k1 của platform (ECDSA). Owner là
  tài khoản ED25519 thì `executeAsOwner` (ECDSA) không dùng được ⇒ `HederaMandateWallet.executeAsOwnerRaw` kiểm owner
  qua HIP-632, cùng `ownerNonce`, cùng digest `OwnerCall`. `isValidSignature` (ERC-1271 cho owner) giữ ECDSA — owner
  ED25519 trả tay bằng `executeAsOwnerRaw(execute(token, payWithFee…))`.
- **DEX:** `MetaTxDex` (và bản R35 của S5) không đổi; mỗi chân là `executeMetaTransaction` trên token ⇒ chân ký ED25519
  được `HederaMetaToken` kiểm. Phí DEX, `filled[orderHash]`, huỷ — theo S5.
- **HTS:** token HTS (ví dụ USDC Hedera) có mặt tiền ERC-20 tại địa chỉ long-zero của nó (HIP-218/376). Dùng qua
  wrapper tầng 2 `HederaMetaToken(underlying = token HTS)`. Contract phải **associate** token HTS trước khi nhận:
  `associateUnderlying()` không cần quyền, gọi HTS 0x167 `associateToken(this, underlying)`, chấp nhận `SUCCESS (22)`
  và `TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT (194)` (R6-5). Người dùng cấp allowance HTS **cho contract wrapper**
  (hợp lệ R26). Rủi ro ghi nhận: allowance HTS ở cấp giao thức không ép được "chỉ contract" — hệ không dùng allowance
  HTS ngoài wrapper.

## 8. Odoo và portal (§D.6) — R6-3

- Chain `family = hedera`, `evm_chain_number` 295–298 (đã có). Người trả địa chỉ alias `0x…` ⇒ đường EVM hiện có
  (EIP-712 + EIP-6963), không đổi.
- **Token và ví nhận nhập `0.0.N` (review H3):** `0.0.N` → long-zero chỉ đúng cho tài khoản ED25519 không alias. Clone
  CREATE2 có `address(this)` = địa chỉ EVM của nó (long-zero ⇒ sai `verifyingContract`, mọi thanh toán hỏng); tài
  khoản ECDSA nhận ở long-zero thì tiền kẹt (ecrecover ra alias; nhánh EC của HIP-632 từ chối long-zero). Nên với
  `blockchain.token` (`contracts`) và `blockchain.receiving.wallet` (`accounts`) trên chain Hedera, `0.0.N` được tra MỘT
  lần lúc nhập ở mirror node của chain (`blockchain.chain.hedera_mirror_url`, `/api/v1/{contracts|accounts}/0.0.N` →
  `evm_address`) và lưu dạng `0x`. Long-zero chỉ khi mirror báo khoá `ED25519` và không alias. Không có mirror, tra
  lỗi, hoặc tài khoản không-ED25519 không alias ⇒ từ chối, yêu cầu địa chỉ `0x`. Người trả giữ đường R6-3. Ngoại lệ
  với R20 (Odoo không RPC chain): chỉ một GET đọc công khai lúc nhập, không ở đường thanh toán.
- **Giả định cần kiểm trên testnet:** `msg.sender` (và địa chỉ nhận/ký) của tài khoản ECDSA có alias là alias `0x…`,
  không phải long-zero. Chưa thử trên mạng thật (không có tài khoản testnet được cấp tiền) — §9.
- Người trả `0.0.N` (lưu long-zero) ⇒ **đường khoá gốc**: `_issue` trả `{family:'hedera', digest, typed_data,
  valid_until, …}` cho connector `hedera`; `_accept_signature` nhận chữ ký **64 byte** + `public_key` (32 byte),
  kiểm ed25519 (thư viện `cryptography` đi kèm Odoo) trên digest — sai ⇒ từ chối ngay; đúng ⇒ tạo `blockchain.metatx`
  + job như EVM, `signature_verified = False` vì Odoo không biết khoá có thuộc `0.0.N` không (không RPC — R20); mô
  phỏng của node (HIP-632) phân xử (R27).
- Connector `connectors/hedera.js`: ký `digest` thô bằng một signer ED25519 do trang cung cấp
  (`window.dmsHederaSigner = {accountId, publicKey, signBytes(Uint8Array)}` — ví seed của S4 với đường
  `m/44'/3030'/0'/0'/i'`, hoặc cầu HashPack sau này). Không nạp thư viện nào.

## 9. Kiểm thử và devnet

- **Forge** (`smartcontracts/test/hedera/`): precompile 0x16a giả bằng `vm.etch` — forge 1.3.5 không có cheatcode
  ed25519, nên mock giả lập "khoá của tài khoản đã ký đúng 32 byte này" bằng chữ ký secp256k1 compact 64 byte; ed25519
  thật được Python + Rust kiểm trên vector KAT chung; ánh xạ tài khoản → khoá như state Hedera; revert cho tài khoản lạ (như mạng thật);
  HTS 0x167 giả. Test: ED25519 pay, chữ ký sai/khoá khác/tài khoản lạ, ECDSA vẫn chạy, ERC-1271 vẫn chạy, DEX chân
  ED25519, mandate owner ED25519, associate, **anti-lock** (X ở token 1 bị giữ, Y ở token 2 chạy, rồi X chạy), vector
  KAT chung.
- **Rust**: decoder receipt/log/block trên **vector ghi từ Relay testnet thật** (`bamboo-node/tests/vectors/
  hedera_testnet.json`), proptest decoder; e2e `tests/e2e_hedera.rs` (`#[ignore]`) trên anvil `--chain-id 298`: hai lane
  từ mnemonic 24 từ, thanh toán qua `lane_step`, finality qua `index_step`, anti-lock đầu-cuối.
- **Kết quả (2026-10-03):** forge 24 test Hedera + 157 toàn bộ xanh; Odoo `dms_blockchain` 118 test (4 Hedera) xanh trên
  `dms_test_chain_6`; Rust 9 test adapter (gồm proptest 2 × 2 000 ca) + e2e `e2e_hedera` xanh (anvil 298, cổng 31960);
  connector `node --test` 4 xanh — chữ ký ed25519 của node:crypto trùng byte với Python trên vector chung.
- **Smoke trên EVM Hedera thật, không cần tài khoản/HBAR** (`script/hedera/HederaSmoke.sol` +
  `testnet_smoke.py`): constructor chạy như initcode qua `eth_call` trên Relay testnet (mirror-node web3 chạy đúng
  thư viện EVM + system contract của services). Kết quả 2026-10-03: deploy `OpenFactory` + `HederaMetaToken` + clone
  chạy (TSTORE/MCOPY có), thanh toán meta-tx ECDSA ⇒ `ok`, shop nhận 100; chữ ký ED25519 sai cho tài khoản ED25519 có
  thật `0.0.6000019` qua 0x16a thật ⇒ `MetaTxBadSignature`; tài khoản không tồn tại ⇒ `MetaTxBadSignature`;
  `EXTCODESIZE` của EOA = 0 (phân nhánh `_isContract` đúng); 0x16a trả lời CALL, HALT với STATICCALL (R6-6).
- **Khoảng trống:** `hedera-local-node` (nay là `solo`, cần ≥ 8 GB RAM, nhiều container) không chạy trên máy dùng
  chung 10 luồng. Anvil khác Hedera ở: có mempool, không có precompile 0x16a/0x167 thật, không thu 80 % gas. Đường
  dương HIP-632 chưa thử trên mạng thật. Việc cần làm khi có tài khoản testnet: deploy `HederaMetaToken`, thanh toán
  một lần bằng tài khoản ED25519 và một lần bằng alias ECDSA; xác nhận `msg.sender` của tài khoản ECDSA có alias là
  alias (§8); xác nhận Relay trả mã Hedera (`WRONG_NONCE`…) trong `revertReason`/lỗi precheck như adapter đọc.

## 10. Thanh toán bảo mật (Zether) — khả thi

HSCS có precompile bn254 (0x06–0x08) nên verifier Zether bn254 của S2 chạy được như EVM; BLS12-381 (EIP-2537) chưa có
trên Hedera ⇒ chỉ biến thể bn254. Trần 15 M gas/tx đủ cho một lần verify Bulletproofs (ước lượng vài triệu gas) nhưng
Hedera thu ≥ 80 % gas limit theo giá cố định ⇒ chi phí mỗi chuyển bảo mật cao hơn đáng kể so với chuyển thường; cần đo
khi Zether contract có (R34). Không có trở ngại kiến trúc: account ED25519 chỉ ký phong bì meta-tx, phần chứng minh
không phụ thuộc khoá ký.

## 11. Ruling của luồng

- **R6-1** Hedera chạy `lane_runner` (một tx bay mỗi lane), không pipeline/thay thế/gap-fill (không mempool; nonce
  tương lai ⇒ `WRONG_NONCE`).
- **R6-2** `HederaMetaToken`: `from` không code + chữ ký 64 byte ⇒ HIP-632 `isAuthorizedRaw`; revert của precompile =
  không uỷ quyền; còn lại như `MetaToken`.
- **R6-3** Odoo: người trả long-zero `0.0.N` ⇒ đường khoá gốc ED25519 (digest thô, chữ ký 64 byte + khoá công khai,
  kiểm ed25519 ở Odoo, ràng khoá↔tài khoản on-chain).
- **R6-4** HashPack `signMessage`, khoá ngưỡng/KeyList (`isAuthorized` + `SignatureMap`) = seam.
- **R6-5** `associateUnderlying()` không cần quyền, idempotent (22/194).
- **R6-6** Gọi 0x16a bằng CALL (system contract HALT trong frame tĩnh); cần lead bỏ `view` khỏi
  `ERC20MetaTx._requireValidSignature` để bỏ phép ép kiểu `asView`.

## 12. Review log

### Grok — review thiết kế, 2026-10-03 — 10 finding, 0 nhận

| # | Sev | Nội dung | Kết luận |
|---|---|---|---|
| 1, 2, 9 | crit/high | revert của precompile phải thành `false`; nhánh 64 byte/không code; độ dài khác rơi về `ecrecover` | Đã là thiết kế (§3, R6-2); độ dài khác ⇒ `ecrecover` của lớp cha, fail closed. Từ chối |
| 3, 10 | high/med | `validUntil` phải được kiểm | Đã có: bước 2 của `ERC20MetaTx` + `lane_runner` (hết hạn ⇒ `dead`). Từ chối |
| 4 | high | Hedera phải chạy một tx/lane, trần gas | Đã là R6-1 + `max_gas_per_tx`. Từ chối |
| 5 | med | finality/event | Đã là §6. Từ chối |
| 6 | high | associate HTS với mã 22/194 | Đã là R6-5. Từ chối |
| 7 | high | ghi đè `executeAsOwner` | **Sai**: hàm không `virtual`; hàm riêng `executeAsOwnerRaw` dùng cùng digest + nonce. Từ chối |
| 8 | med | Odoo không ràng khoá ↔ tài khoản | Đã ghi (R6-3): `signature_verified = False`, mô phỏng HIP-632 phân xử; thêm cờ on-chain là trùng với `MetaTransactionExecuted`. Từ chối |

### Antigravity (agy)
Lần 1: hết quota ("Resets in 1h34m") — đã hẹn chạy lại.

### Opus (thay cho reviewer ngoài), 2026-10-04 — 3 High, 2 Medium, 5 Low — gộp hết
Chi tiết và kết luận: plan `2026-10-03-r3-hedera.md`, mục "Review opus (external substitute) — folded/rejected".
