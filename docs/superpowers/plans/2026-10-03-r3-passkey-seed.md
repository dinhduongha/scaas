# Round 3 — S4: passkey + ví seed + account chủ thể nhiều khoá (R31, R32, phía client R33)

Nhánh `r3-passkey-seed`. Thiết kế: `2026-10-03-blockchain-round3-design.md` §C.1–C.4 (+ review S3/S5/S17/S23/S26).
DB `dms_test_chain_4` / 8924, anvil 31940–31949.

**Mục tiêu:** chủ thể ký mọi thao tác ghi bằng passkey (WebAuthn P-256) hoặc khoá dẫn xuất từ seed 24 từ, qua một
`SubjectAccount` ERC-1271 nhiều khoá; Odoo chỉ giữ khoá công khai, xếp job deploy trước lần trả đầu.

## Quyết định thiết kế (ruling RS4-n)

- **RS4-1** `SubjectAccountFactory` deploy **clone EIP-1167** (`Clones.cloneDeterministic`) + `initialize` trong
  cùng tx; salt = `keccak256(abi.encode(firstKey, guardian))`. Guardian nằm trong salt: nếu salt chỉ là khoá đầu
  thì ai deploy trước được quyền chọn guardian (front-run lấy quyền recovery). Clone ⇒ deploy ~287k gas thay vì
  vài triệu (verifier P-256 nằm ở implementation). `deploy` lặp trả địa chỉ cũ, không revert.
- **RS4-2** Kiểm `clientDataJSON` theo **thuật toán kiểm giới hạn của WebAuthn L3 §5.8.1.2**: tiền tố cố định
  `{"type":"webauthn.get","challenge":"<b64url>","origin":"` rồi origin tới dấu `"` kế, keccak(origin) = `originHash`
  (lưu trong khoá), sau đó **chỉ** `}` (hết chuỗi) hoặc `,"crossOrigin":false` + `}`/`,`. Không cần
  `typeIndex/challengeIndex` do client gửi; trình duyệt xếp thứ tự khác thì fail-closed.
- **RS4-3** Chữ ký = `abi.encode(uint256 keyIndex, bytes32[] proof, bytes sig)`. `proof` rỗng ⇒ thông điệp = digest;
  khác rỗng ⇒ thông điệp = `MerkleProof.processProof(proof, leaf)`, `leaf = keccak256(keccak256(0x00 ‖ digest))`
  (cặp nút sắp xếp như OZ). Lô một dòng = ký thẳng digest. P-256: `sig = abi.encode(authenticatorData,
  clientDataJSON, r, s)`, challenge = base64url(thông điệp). secp256k1: `sig` 65 byte ECDSA (low-s) trên thông điệp thô.
- **RS4-4** `recover`: guardian `initiateRecovery(newKey)` → sau `RECOVERY_DELAY = 2 days` ai cũng gọi
  `completeRecovery(newKey)` ⇒ **thêm** khoá (không xoá khoá cũ: recovery dành cho MẤT khoá; khoá bị TRỘM đã tiêu
  được tiền bằng meta-tx, không cần đụng recovery). Khoá hiện có huỷ được qua `executeAsOwner(cancelRecovery)`;
  `setGuardian` huỷ recovery đang chờ. Guardian có thể là hợp đồng multisig.
- **RS4-5** `signCount` của authenticator không kiểm (passkey đồng bộ luôn trả 0).
- **RS4-6** Thứ tự deploy → trả: job `call` deploy và job thanh toán/owner-call đều nằm trong outbox; job sau mang
  `prerequisite_job_id`, `relay_poll` không trả nó khi job trước chưa `mined/final`; job trước `dead/reverted` ⇒
  job sau `dead` theo (override trong file của S4, không sửa file của S1).
- **RS4-7** Nonce `executeAsOwner` ở Odoo = số owner-call job của account đã `mined/final`; chỉ một owner-call sống
  mỗi lúc. `reverted` không tiêu nonce (receipt hỏng ⇒ không `mined`).
- **RS4-8** Vault seed: khoá dữ liệu ngẫu nhiên (DEK) mã hoá seed bằng AES-GCM (IV 12 byte mới mỗi lần); DEK bọc
  bằng PIN qua scrypt (salt 16 byte, N=2^15, r=8, p=1) **luôn có**, và thêm phong bì PRF khi passkey hỗ trợ.
- **RS4-9** Khoá Zether conf (R33) dẫn xuất **trong `clientkeys` bằng JS** (`@noble/curves` bn254 + BLS12-381,
  `@noble/hashes` HKDF), không cần wasm của S3 chỉ để đăng ký: EIP-2333 đúng cho BLS12-381
  (`m/12381/<coin>/<acct>/7`), biến thể bn254 salt `BAMBOO-ZETHER-BN254-v1` (`m/254/…`), `Y`, `UA`, PoP Schnorr
  ràng account chủ thể. Khớp từng byte với `zether-prover` (S3): vector `r33_keys.json`, `schnorr_*.json` chép
  nguyên văn vào `clientkeys/test/vectors/` + 4 vector EIP-2333 công bố. Nonce Schnorr hedged
  `sha512(x ‖ msg ‖ CSPRNG) mod r` (khác cách S3 nhưng chỉ cần verify chéo; với `k` cố định thì trùng byte).
  Entry lười riêng `zether-keys.js` để bundle seed không phình. `x` niêm phong bằng vault như seed.

## Task

1. Contract `src/account/{SubjectAccount,SubjectAccountFactory}.sol` + trần ERC-1271 400k; forge test (vector Base
   webauthn-sol công bố + vector authenticator phần mềm Node, các ca hỏng, batch, vòng đời khoá, recovery, MetaToken
   `pay` bằng passkey và seed key, đo gas precompile/Solidity).
2. `clientkeys/` (Node 26, `node --test`): BIP-39/32, SLIP-10, địa chỉ từng mạng, EIP-712, WebAuthn, vault
   (RS4-8), backup show-once; bundle esbuild ⇒ `dms_blockchain_bridge/static/lib/clientkeys/`.
3. Odoo: `blockchain.subject.account` (+ key), deploy job, payer = account, submit `contract`, add-key owner call.
4. Portal: chọn signer EIP-6963 | passkey | seed (nạp lười), tour authenticator giả + seed giả.
5. Khoá Zether conf R33 trong `clientkeys` (RS4-9), vector S3.
6. Review agy (plan + diff), full suites, báo cáo.

Trạng thái: 1–5 xong (commit e402f11, ec46749, 37eaaf6, 6371055, e186bbb).

## Review log

### agy — review plan, 2026-10-03 — 20 finding (SEC-01..20)

agy chạy `--mode plan` nhưng **đã ghi đè file plan này** (đã khôi phục); các lần review sau chạy trên bản sao.

| # | Kết luận | Xử lý |
|---|---|---|
| SEC-01 crossOrigin sau khoá khác/khoảng trắng | Đúng một phần | Nhận: sau origin chỉ nhận `}` hoặc `,"crossOrigin":false` + `}`/`,` |
| SEC-02 thứ tự khoá clientDataJSON | **Sai**: L3 §5.8.1.1 cố định thứ tự type, challenge, origin, crossOrigin cho client; vector Chrome + Safari công bố khớp | Từ chối; trình duyệt lệch ⇒ fail-closed (rủi ro mở) |
| SEC-03 originHash không được lưu | **Sai**: `originHash` nằm trong `SubjectKey` | Từ chối |
| SEC-04 lô một dòng | Không phải lỗi: lô một dòng ký thẳng digest | Từ chối, ghi rõ ở RS4-3 |
| SEC-05 lá không gắn account/chain | Digest của ta (MetaTransaction, OwnerCall) đã mang `from`/`verifyingContract`; gắn riêng lá không giải ERC-1271 replay cho digest đơn | Từ chối; ERC-7739 ghi rủi ro mở |
| SEC-06 khoá trộm huỷ recovery | Recovery cho mất khoá; khoá trộm đã tiêu được tiền | Từ chối |
| SEC-07 guardian bị chiếm | Trễ 2 ngày + huỷ bằng khoá là biện pháp; guardian có thể là multisig | Từ chối thay đổi; cần cảnh báo `RecoveryInitiated` (needs S1 indexer) |
| SEC-08 khoá xoá thành address(0) | **Sai**: slot xoá có `kind = NONE` ⇒ false; `tryRecover` lỗi ⇒ false | Từ chối (có test) |
| SEC-09 không có domain EIP-712 | **Sai**: `OwnerCall` dùng `_hashTypedDataV4` của account | Từ chối |
| SEC-10, SEC-11, SEC-12, SEC-18, SEC-20 | Đã có trong thiết kế | Không đổi |
| SEC-13, SEC-19 | Đúng | Nhận (RS4-6) |
| SEC-14 deploy làm hết hạn thanh toán | Một phần: điều kiện là `mined`, không `final` | Nhận như vậy |
| SEC-15 nonce đếm DB | `reverted` ≠ `mined` nên không lệch vì revert; lệch khi ai đó gọi ngoài Odoo ⇒ owner-call hỏng `BadNonce`, không mất tiền | Từ chối; ghi rủi ro |
| SEC-16, SEC-17 | Đúng | Nhận (RS4-8) |
