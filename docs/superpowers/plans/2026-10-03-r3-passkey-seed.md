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
  (`m/12381/<coin>/<acct>/7`), biến thể bn254 salt `SCAAS-ZETHER-BN254-v1` (`m/254/…`), `Y`, `UA`, PoP Schnorr
  ràng account chủ thể. Khớp từng byte với `zether-prover` (S3): vector `r33_keys.json`, `schnorr_*.json` chép
  nguyên văn vào `clientkeys/test/vectors/` + 4 vector EIP-2333 công bố. Nonce Schnorr hedged
  `sha512(x ‖ msg ‖ CSPRNG) mod r` (khác cách S3 nhưng chỉ cần verify chéo; với `k` cố định thì trùng byte).
  Entry lười riêng `zether-keys.js` để bundle seed không phình. `x` niêm phong bằng vault như seed.

- **RS4-10** (review S4-L1) `MetaToken` ghim implementation `SubjectAccount` của chain (tham số constructor,
  immutable); `ERC20MetaTx._erc1271Gas(from)` mặc định 50k, `MetaToken` cho 400k CHỈ khi `from.codehash` = mã clone
  EIP-1167 của implementation đó. Ví hợp đồng khác (Safe…) giữ 50k. `Deploy.s.sol` deploy `SubjectAccountFactory`
  trước token và ghi địa chỉ vào `deployments/<chainid>.json`. **Chạm file ngoài quyền S4** (`MetaToken.sol` của S5,
  `Deploy.s.sol` + `test/helpers/Fixtures.sol` của S1): commit riêng `e1a4a8b` để lead quyết khi merge.
- **RS4-11** (S4-H1) User handle WebAuthn **ngẫu nhiên 16 byte mỗi passkey** (không theo đối tác); `excludeCredentials`
  = passkey còn sống của account (server phục vụ, khoá `failed` không tính); thêm passkey trên máy mới thì mở và đối
  chiếu cụm từ phê duyệt TRƯỚC `navigator.credentials.create()`. `InvalidStateError` ⇒ "máy này đã có passkey".
- **RS4-12** (S4-M1) Khoá đầu tiên đăng ký hai bước: `..._register_start` trả challenge HMAC(`database.secret`;
  user, đối tác, chain, hạn) — không lưu gì, TTL 600 s; khoá mới ký `keccak256("scaas-subject-key-proof-v1" ‖
  challenge)` (tách miền: challenge do server chọn không bao giờ là digest của một thao tác). Passkey: assertion kiểm
  như `_clientDataOk` (bản Python), rpIdHash, UP|UV, chữ ký P-256; khoá seed: `ecrecover`. Origin/rpId lấy từ
  `dms_blockchain_bridge.passkey_origin`, mặc định `web.base.url` — **không** theo host của request. Ngữ nghĩa
  "user có entitlement hành động thay đối tác" giữ nguyên.
- **RS4-13** (S4-M2) Client **không ký typed data của server như nó là**: `checkPayment` dựng lại thao tác `pay`
  (op `pay(bytes32)`, `value` = số tiền đã hiển thị × 10^`tokenDecimals`, `from` = account, đúng chain, phí 0, hạn
  ≤ 1 ngày, đúng type) và `checkOwnerCall` (chỉ `addKey(khoá vừa tạo)` trên đúng account/chain, hạn ≤ 1 giờ); khác
  ⇒ từ chối. Owner call chỉ ký sau form hiển thị account, selector, value 0.
- **RS4-14** (S4-M3, thay tham số RS4-8) Passphrase mới ≥ 8 ký tự và không chỉ chữ số; scrypt **N=2^17**, r=8, p=1
  (Node 26: noble 501 ms, native 334 ms; N=2^15 là 131/86 ms). Vault cũ (2^15, PIN 6 số) vẫn mở được và được bọc
  lại khi mở (PIN yếu ⇒ chọn passphrase mới). Phong bì PRF **mặc định** khi một passkey của account cho PRF; phong
  bì passphrase vẫn luôn có (SEC-17).
- **RS4-15** (S4-L2) Vault theo chủ thể: `localStorage["dms_chain_seed_vault:<subject>"]` (`subject` = thẻ mờ
  theo đối tác từ server); khoá chung cũ đọc một lần rồi chuyển. Thay cụm từ đã lưu phải xác nhận.
- **RS4-16** (S4-L3) Job deploy chỉ cho account của CHÍNH đối tác của lần trả (`res_model/res_id` của request).

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

### Review DIFF nhánh + suite cuối (2026-10-04)

Suite trên `a667550`: `forge test` 180/180 (15 suite); `clientkeys` `node --test` 31/31; bundle esbuild dựng lại
khớp từng byte với `dms_blockchain_bridge/static/lib/clientkeys/`; Odoo `dms_blockchain,dms_blockchain_bridge,
dms_blockchain_payment` trên `dms_test_chain_4`/8924: 179 test, 0 failed, 0 error.

## Review agy — folded/rejected

**Chưa có review agy của DIFF** (review trên chỉ là PLAN). agy hết quota (`RESOURCE_EXHAUSTED`, "Resets in
120h9m" tính từ 2026-10-04); grok bị bộ phân loại quyền chặn trong phiên này. Prompt sẵn (chạy trên BẢN SAO plan):
`scratchpad/s4-review-prompt.md` (phiên a9570aaa). Thay thế tạm: Claude soát tay — `SubjectAccount` (nonce tăng
trước call, khoá xoá ⇒ `NONE` ⇒ false, không xoá được khoá cuối, `_clientDataOk` fail-closed, cờ UP+UV, rpIdHash,
low-s qua OZ `P256`), `derToRS` (DER chặt, chuẩn hoá s), vault (IV 12 byte mới mỗi lần seal, scrypt 2^15/8/1,
DEK ngẫu nhiên, AAD theo nhãn), Odoo (`_dms_chain_order` theo entitlement, rpId/origin do server quyết,
`_open` một account mỗi (partner, chain), add-key chỉ một owner-call sống, `prerequisite_job_id` + `_fail_dependents`).
**0 finding gộp.** Ghi nhận (không đổi): mọi user có entitlement trên partner đều đăng ký được khoá ĐẦU của account
partner đó — đúng mô hình "entitlement = hành động thay partner", cần guardian để thu hồi nếu chiếm sai. Rủi ro mở:
chưa có review ngoài của diff — chạy lại agy khi quota hồi.

## Review opus (external substitute) — folded/rejected (2026-10-04)

Review: `scratchpad/s4-opus-review.md` (Claude Opus, đọc diff, không chạy code): 0 critical, 1 high, 3 medium, 4 low.
Mỗi finding được kiểm lại trên code trước khi sửa; test viết trước.

- **H1 folded** `9552724` (RS4-11) — handle ngẫu nhiên mỗi passkey, `excludeCredentials`, phê duyệt trước `create()`.
  Test: node `creationOptions` (handle 16 byte khác nhau, exclude), Odoo `test_context_serves_exclusions_and_no_shared_user_handle`,
  tour kiểm options của `create`.
- **M1 folded** `9552724` (RS4-12) — đăng ký hai bước + kiểm origin/rpId/UV/chữ ký; origin theo cấu hình.
  Test: `test_register_needs_proof_of_the_key_and_its_origin` (sai scheme, sai cổng, sai rpId, thiếu UV, challenge lạ,
  dời hạn, khoá khác, seed ký sai), `test_register_passkey_uses_the_configured_rp_and_origin`, vector
  `key_proof_message` ghim chung với clientkeys; tour passkey: create, get (chứng minh), get (trả).
  Không làm: reset account bởi admin (gợi ý tuỳ chọn của review) — nguyên nhân "khoá đầu hỏng" đã bị chặn ở đăng ký.
- **M2 folded** `9552724` (RS4-13) — `checkPayment`/`checkOwnerCall` + form xác nhận owner call. Test node: 9 dạng
  OwnerCall và 11 dạng thanh toán bị từ chối (gồm OwnerCall đội lốt thanh toán, số tiền lớn hơn, op `trade`, phí).
- **M3 folded** `113adab` + `9552724` (RS4-14) — passphrase ≥ 8 ký tự không chỉ số, scrypt 2^17, bọc lại vault cũ,
  PRF mặc định. Không làm: khoá thiết bị WebCrypto không-xuất-được trong IndexedDB (phần "additionally" của review,
  ngoài ruling) — ghi là rủi ro mở.
- **L1 folded** `e1a4a8b` (RS4-10) — 400k chỉ cho clone SubjectAccount; forge `test_1271_gas_400k_only_for_subject_account_clones`
  (đỏ khi cho 400k mọi ví, xanh sau sửa). **Needs from S5/S1**: commit chạm `MetaToken.sol`, `Deploy.s.sol`,
  `test/helpers/Fixtures.sol` (ngoài quyền S4) — lead quyết khi merge.
- **L2 folded** `9552724` (RS4-15) — vault theo chủ thể, không ghi đè im lặng; tour kiểm khoá `dms_chain_seed_vault:<subject>`.
- **L3 folded** `9552724` (RS4-16) — `test_deploy_only_for_the_paying_partners_own_account`.
- **L4 folded** `91b8ee3` — `zether.js` theo đúng luật chỉ số của prover; kiểm chéo bằng `r33_inputs.json` của S3
  (`0e62494` trên `r3-zether-prover`), kèm seed passphrase NFKD.

Suite sau sửa (`9552724`): `forge test` 181/181 (15 suite); `clientkeys` `npm test` 38/38 (bundle dựng lại khớp từng
byte); Odoo `dms_blockchain,dms_blockchain_bridge,dms_blockchain_payment` trên `dms_test_chain_4`/8924: 184 test,
0 failed, 0 error (gồm hai tour passkey/seed).
