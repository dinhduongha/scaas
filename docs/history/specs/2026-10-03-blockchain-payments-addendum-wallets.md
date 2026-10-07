# Addendum — ví: chuẩn mở, ví nhận, ví trả và tự động thanh toán

**Ngày:** 2026-10-03 · **Bổ sung cho:** `2026-10-03-blockchain-payments-design.md` (gọi tắt "spec gốc")
**Nguồn yêu cầu:** owner, bốn yêu cầu trong cùng phiên (chuẩn ví mở; ví nhận theo công ty; ví trả +
auto-pay; quy tắc approve — hai lần đính chính). Mọi ruling mới đánh số tiếp từ R21.
**Rev 1.1 (2026-10-07):** Claude review 1 folded (§"Claude review 1": rulings CR-ADW-1…4, streams ADW-FIX1…4,
superseded-rulings table). The private chain is 7622 (formerly 9000).

---

## A. Quy tắc approve: chỉ hợp đồng được làm spender

**Phán quyết cuối của owner (đính chính 2, thay đính chính 1):** approve/allowance được phép, nhưng
**spender phải là hợp đồng**, và **chỉ hợp đồng được gọi `transferFrom`**. EOA không bao giờ là spender.
Cưỡng chế **trong code token**.

Nguồn: SRS kiến trúc §3.2 ("Chỉ Hợp Đồng Được Dùng Allowance: `approve` chỉ mở cho các Smart Contract
hợp lệ — Vault, Swap, Router — khi tương tác trong cùng giao dịch composable") và SRS tích hợp §4.1. Bản
SRS chặn *người gọi* là EOA; owner chốt dạng chặt hơn và đúng vào chỗ rủi ro: chặn *spender* là EOA, và
chặn EOA *tiêu* allowance. README `smartcontracts` bỏ `isEOA` vì `extcodesize` sai trong ba trường hợp —
quy tắc dưới đây xử lý cả ba một cách tường minh thay vì giả vờ chúng không tồn tại:

| Trường hợp | `code.length` | Ta coi là | Vì sao |
|---|---|---|---|
| EOA thường | 0 | EOA | — |
| EOA đã uỷ quyền EIP-7702 (Prague; chain 7622 (formerly 9000) có Prague) | 23, bắt đầu `0xef0100` | **EOA** | code chỉ là designator; khoá riêng của EOA vẫn ký được mọi thứ |
| Hợp đồng đang chạy constructor | 0 | **EOA** (từ chối) | không phân biệt được với EOA trong cùng lúc; hệ quả ghi rõ: một hợp đồng **không thể** được approve hay tiêu allowance từ constructor của chính nó |
| Hợp đồng đã deploy | > 0, không phải designator | hợp đồng | — |

Cài đặt: `ERC20MetaTx` (gốc của mọi token trong hệ) override `approve` (spender phải là hợp đồng) và
`transferFrom` (`msg.sender` phải là hợp đồng). Token không có `permit`/`increaseAllowance`, nên không
có cửa thứ hai. Lỗi: `SpenderNotContract(address)`, `CallerNotContract(address)`.
*(Stale — Claude review L1: từ R35 meta-op `approve(address,uint256)` (`MetaToken.sol:167-176`,
`MetaTokenBase.sol:316-323`) là cửa thứ hai; nó áp cùng kiểm tra "spender là hợp đồng", nên quy tắc vẫn đúng.)*

R4 của spec gốc ("không hiện thực EOA approve lockdown") **bị thay** bởi quy tắc này.

---

## B. Ví theo chuẩn mở (EIP-1193, EIP-6963, EIP-712, EIP-1271, WalletConnect)

1. **Khám phá ví (EIP-6963).** JS phát `eip6963:requestProvider`, nghe `eip6963:announceProvider` trong
   400 ms, khử trùng theo `rdns`, hiện bảng chọn (tên bằng `textContent`, biểu tượng chỉ khi là
   `data:image/{png,jpeg,gif,webp,svg+xml}` và chỉ qua `<img src>` — không bao giờ `innerHTML`). Nhớ
   `rdns` đã chọn trong `localStorage` (try/catch). Không ví nào lên tiếng ⇒ fallback `window.ethereum`
   (EIP-1193). Không thêm thư viện JS.
2. **Typed data** giữ nguyên chuẩn: domain có `chainId` + `verifyingContract`; mọi ví EIP-712 ký được.
3. **Sự kiện:** `chainChanged`/`accountsChanged` huỷ luồng đang chạy và báo người dùng (không poll để
   phát hiện); mã `4001` = người dùng từ chối ⇒ thông báo nhẹ, không phải lỗi.
4. **EIP-1271 (ví hợp đồng).** On-chain **đã có**: `ERC20MetaTx._requireValidSignature` gọi
   `isValidSignature` (magic `0x1626ba7e`) khi `from.code.length > 0` *(superseded → review W3: `_isContract(from)`,
   designator EIP-7702 là EOA; trần gas: 400 k chỉ cho clone `SubjectAccount` nhận theo codehash, 50 k cho mọi ví
   khác, `MetaToken.sol:141-144`; Hedera không có `SubjectAccount`, `HederaMetaToken.sol:22-24` — Claude review L2)*
   — không viết lại, chỉ thêm test
   (ví hợp lệ, sai, revert, trả rác). Phía Odoo không gọi RPC (R20), nên không tự biết `from` có code:
   trình duyệt hỏi `eth_getCode` qua chính provider của ví và gửi gợi ý `wallet_kind`. `eoa` ⇒ chữ ký
   phải khôi phục đúng ví như hiện nay; `contract` ⇒ nhận dạng chưa kiểm, simulation của node (gọi
   `isValidSignature` thật) là trọng tài. Gợi ý sai không mở đường nào tới tiền: một chữ ký không hợp lệ
   không thực thi được on-chain. (Thu hẹp R13.)
5. **WalletConnect v2 — ruling R21:** chỉ dựng **seam**: registry `providerFactories`; tuỳ chọn
   WalletConnect chỉ hiện khi `ir.config_parameter` `dms_blockchain.walletconnect_project_id` có giá trị
   **và** một asset tuỳ chọn đã đăng ký factory `walletconnect`. Không tải SDK từ CDN trong core — vì: SDK
   ~400 KB, phải ghim version + SRI, và không kiểm thử được trong CI không có mạng; một script bên thứ ba
   chạy trong portal thanh toán là bề mặt chuỗi cung ứng — giá nếu sai: ví di động cần một addon nhỏ
   đăng ký factory (pin `@walletconnect/ethereum-provider` + SRI) trước khi dùng được.

---

## C. Ví NHẬN theo công ty

**Model `blockchain.receiving.wallet`** (core, `mail.thread`, tracking mọi trường): `company_id`,
`chain_id`, `token_id` (tài sản), `address`, `label`, `approval_state` (mixin bốn mắt: `draft → pending_approval →
approved → archived`), `proposed_by_id`, `approved_by_id`, `approved_datetime`, `usable_from`,
`is_default`.

- **Địa chỉ:** nhận chữ thường/chữ hoa toàn bộ, hoặc chữ hoa-thường **đúng checksum EIP-55**; sai checksum
  ⇒ từ chối. Từ chối `0x0`, `0x…dEaD`, địa chỉ của **chính token** hoặc của bất kỳ token đã đăng ký trên
  chain đó (gửi tiền vào contract token = mất), và địa chỉ relayer của bất kỳ provider `chain` nào (ví
  nóng của platform không phải ví nhận của ai). Lưu chữ thường.
- **Bốn mắt:** đề xuất bởi người có quyền quản lý ví của công ty đó; phê duyệt bởi **một người khác** cũng
  có quyền đó. Quyền (seam `_blockchain_wallet_admin(company)`): nhóm mới `group_blockchain_treasury` và
  công ty nằm trong `user.company_ids`, hoặc `base.group_system`. Trên nhánh territory, seam này đọc thêm
  role assignment admin/accountant tại NPP.
- **Bất biến:** ví đã `approved` không sửa được (trừ cờ default và lưu trữ); muốn đổi ⇒ tạo ví mới, lưu
  trữ ví cũ.
- **Cooling-off — ruling R22:** ví mới được duyệt chỉ **dùng được** (nhận request mới, làm default) sau
  `usable_from = approved + N giờ` (`dms_blockchain.receiving_wallet_cooling_hours`, mặc định 24).
  Áp cho **mọi** việc dùng, không chỉ cờ default — vì đổi địa chỉ nhận tiền là vector gian lận số một và
  24 giờ là cửa sổ để bên thứ hai phát hiện — giá nếu sai: ví mới chậm một ngày.
- **Default:** tối đa một ví default mỗi công ty (`UniqueIndex` một phần).
- **Record rule:** công ty chỉ thấy/sửa ví của mình; `base.group_system` của Host thấy tất cả.
- **Host — ruling R23** *(superseded → R57 "platform company", `dms_blockchain.platform_company_id`;
  `host_company_id` chỉ còn đọc, `blockchain_receiving_wallet.py:9-10`)*: Host = `ir.config_parameter` `dms_blockchain.host_company_id`, mặc định
  `base.main_company`. Luồng portal phí `NONE` nên hôm nay không có chân phí; resolver
  `_blockchain_host_company()` là chỗ chân phí/hoa hồng tương lai lấy ví nhận.

**Công ty nhận tiền:** seam `_dms_chain_receiving_company(order)` = `order.company_id` (trên nhánh
territory: `res.company._dms_document_company()`).

**Snapshot:** `blockchain.payment.request` đã chụp `receiving_address`, `chain_id`, `token_id`,
`amount_base`, `payer_address`; thêm `receiving_wallet_id` (tham chiếu kiểm toán) và **chặn ghi** mọi
trường snapshot sau khi tạo. Sửa/thay/lưu trữ ví không bao giờ đổi hướng một request đang bay. Contract
không tra registry lúc thực thi: người nhận nằm trong typed data đã ký.

**Provider `chain`** không còn giữ token/địa chỉ nhận: chỉ giữ relayer, thời hạn chữ ký và journal. Token
và địa chỉ đến từ ví nhận người trả chọn.

**Portal:** `dms_portal_chain_payment_options(order_id)` liệt kê các cặp (chain, tài sản) **dùng được**
của công ty nhận mà tiền tệ token = tiền tệ đơn; `start(order_id, from_address, receiving_wallet_id=None)`
(mặc định: ví default nếu thuộc danh sách, hoặc phương án duy nhất). Không có phương án ⇒ không có nút;
**nhân viên** thấy cảnh báo trên form đơn hàng backend, khách không thấy gì.

**Đối soát:** đã khớp theo (chain, contract token, địa chỉ nhận, `entryRef`) — không theo số tiền.

---

## D. Ví TRẢ và tự động thanh toán

**Nền đã chốt (không mở lại):** custody cắm được, chọn lúc deploy (`_USER-DECISIONS` §0 "Custody");
Odoo chỉ giữ `signer_ref`, không bao giờ giữ vật liệu khoá (§23.2, canon §C11.7, CLAUDE.md §5.5);
"non-custodial là không giữ tiền của người khác, không có nghĩa là không có khoá nào ở server — ví
treasury của chính công ty là self-custody" (§23.11); smart account ERC-1271 với chính sách ngân sách là
đường uỷ quyền có giới hạn (07-custody §07.7, SRS §3.2 điểm 2); `SigningPolicyService` kiểm bốn lớp
trước khi ký: hợp đồng đích trong allowlist, đúng selector, hạn mức kỳ, `validUntil − now ≤ 300 s`
(SRS tích hợp §4.4).

**Model `blockchain.paying.wallet`** (core, `mail.thread`): `company_id` (công ty quản lý), `partner_id`
(người trả: partner của một công ty hoặc một outlet), `chain_id`, `token_id`, `address`, `mode`, 
`signer_ref`, `license_ref`, cùng vòng đời bốn mắt như ví nhận.

| `mode` | Ai ký | Địa chỉ `address` | Ràng buộc |
|---|---|---|---|
| `manual` (mặc định) | người dùng, mỗi lần | EOA/ví của họ | luồng hiện có |
| `custodial` | platform qua custody adapter (`signer_ref`) | EOA mà adapter điều khiển | `signer_ref` bắt buộc; ví của **partner không phải công ty** (khách/outlet) bắt buộc `license_ref` — nắm khoá tiền người khác là hoạt động custody (07-custody §07.5) — ruling R24 |
| `delegated` | khoá delegate của platform (qua adapter) **trong hạn mức on-chain** | địa chỉ `MandateWallet` của người trả | người trả giữ khoá chủ; hạn mức cưỡng chế on-chain |

**Custody adapter (socket):** `dms_blockchain/lib/custody.py` — registry theo scheme của `signer_ref`;
giao diện `address(ref)`, `sign_digest(ref, digest32) -> 65 byte`. Ship **`env:`** (dev/test: khoá ở
biến môi trường tiến trình, ký ECDSA RFC 6979 low-s thuần Python *(superseded → R50: OpenSSL qua `cryptography`,
cờ dev-only + chain dev, `lib/custody.py:9-13,64-75`)*). Adapter production (`broker:` gọi
custody broker qua mTLS, KMS, HSM) cắm vào cùng registry. **Không trường, không tham số, không attachment
nào chứa khoá** — có test duyệt `ir.model.fields` và `ir.config_parameter`.

**`MandateWallet` (delegated) — ruling R25.** Một smart account mỗi người trả, chủ là EOA của họ:
- giữ tiền (người trả nạp vào), hiện thực ERC-1271 cho chữ ký của chủ (nên chủ vẫn trả tay được từ ví này
  bằng meta-tx) — **trừ chủ Hedera khoá ED25519 (CR-ADW-2):** `isValidSignature` chỉ ECDSA và ERC-1271 được gọi bằng
  STATICCALL, nơi precompile HIP-632 không chạy; chủ đó trả tay qua `executeAsOwnerRaw` (`HederaMandateWallet.sol`),
  không qua meta-tx;
- chủ đặt mandate theo token: `delegate`, `maxPerPayment`, `maxPerPeriod`, `periodSeconds`, `expiry`, và
  danh sách payee được phép (chủ đặt — tức địa chỉ nhận đã duyệt của đối tác);
- `payUnderMandate(order, delegateSig)`: kiểm on-chain chưa revoke, chưa hết hạn, payee được phép, ≤
  hạn mức lần, ≤ hạn mức kỳ, order chưa dùng (chống replay), chữ ký EIP-712 của delegate; rồi gọi
  `IERC20Payment.payWithFee(to, amount, NONE, 0, 0, entryRef)` — **đường trả trực tiếp đã có trong
  `IERC20Payment`**, `msg.sender` là ví, không dùng allowance. `PaymentSettled` vẫn mang `entryRef` nên
  đối soát y hệt thanh toán tay;
- kill switch on-chain: `revoke(token)` bởi chủ, hoặc `revokeWithSig` bởi delegate (để platform revoke
  ngay qua relayer). **CR-ADW-1:** chữ ký revoke ràng vào `epoch` của mandate (tăng ở mỗi `setMandate`/revoke), nên
  một chữ ký revoke cũ không xoá được mandate chủ đặt lại sau đó.
Vì sao không approve cho một mandate contract chung (đính chính 2 cho phép): ví riêng giữ tiền nên một lỗi
ở một mandate chỉ chạm tiền đã nạp vào ví đó, và không cần một bước `approve` mà EOA phải tự trả gas —
giá nếu sai: người trả phải nạp tiền vào ví thay vì để trong EOA.

**Auto-pay — `blockchain.autopay.policy`** (`dms_blockchain_payment`, vì cần `account.move` và luồng
`payment.transaction`): người trả (`partner_id`), ví trả, trigger (`invoice_posted` | `invoice_due`),
hạn mức theo tiền tệ (`max_per_payment`, `max_per_day`, `max_per_month`), trạng thái bốn mắt
(`approval_state` của mixin + cờ `policy_killed`), `action_kill` (tắt tức thì off-chain; với `delegated` còn
xếp job `revokeWithSig` vào outbox).

**Chạy:** cron `_cron_autopay` (body trong method — CLAUDE.md §5.4) tìm hoá đơn khách hàng `posted`,
còn nợ, của người trả; mỗi (policy, hoá đơn, sự kiện) đúng **một** `blockchain.autopay.run`
(`UNIQUE`) ⇒ chạy lại cron hay retry không bao giờ trả hai lần. Kiểm hạn mức (lần/ngày/tháng trên các run
không thất bại); payee = ví nhận **dùng được** của công ty phát hành hoá đơn, đúng (chain, token) của ví
trả, chụp vào request. Rồi đi **đúng đường thanh toán tay**: `payment.transaction` (provider `chain`,
`invoice_ids`, `operation='offline'`) + request + outbox; `custodial` ký meta-tx qua adapter, `delegated`
ký `PayUnderMandate` và xếp job gọi `MandateWallet.payUnderMandate`. Ký đi qua kiểm tra kiểu
`SigningPolicyService` (token đích, op `pay`, hạn mức, `validUntil ≤ 300 s`). Thất bại ⇒ run `failed` +
**activity** trên policy — không bao giờ im lặng. Đối soát: tx `done` ⇒ `account_payment` gạch nợ như
thanh toán tay.

**Outbox tổng quát hoá:** `blockchain.relay.job` thêm `job_kind` (`metatx` | `call`), `target_address`,
`calldata_hex`, `payment_request_id`; `metatx_id` không còn bắt buộc. Node dùng `calldata` khi có. Job
`call` `final` khi `PaymentSettled` của request final. **Claude review H1 → spec gốc CR-PD-1:** các trường này bất
biến sau `create`, operator không có ACL ghi trên job, và node chỉ ký job `call` có selector + đích nằm trong bảng
cho phép (không bao giờ đích là token) — node không còn là "blind signer" cho calldata Odoo dựng.

**Ngoài phạm vi lần này:** đối soát phía người trả khi người trả cũng là một công ty trong cùng DB (hoá
đơn mua — bút toán liên công ty), cấu hình ví trả do chính khách tự phục vụ trên portal (nhân viên cấu hình
hộ; mandate on-chain do khách ký), adapter custody production.

## Rulings mới

- **R21** WalletConnect = seam + cờ cấu hình, không nạp SDK trong core (xem B.5).
- **R22** Cooling-off 24 h áp cho mọi việc dùng ví nhận mới duyệt.
- **R23** *(Superseded → R57 platform company.)* Host = tham số cấu hình, mặc định công ty chính.
- **R24** Ví trả `custodial` của partner không phải công ty bắt buộc `license_ref`.
- **R25** Delegated = `MandateWallet` riêng (ERC-1271 + mandate on-chain + `payWithFee`), không allowance.
  *(Amended → CR-ADW-1 revoke epoch; CR-ADW-2 Hedera ED25519 owners.)*
- **R26** *(Narrowed → R63: allowance HTS không ép được ⇒ chỉ dùng qua wrapper.)* Quy tắc approve: spender phải là hợp đồng, `transferFrom` chỉ do hợp đồng gọi; EOA uỷ quyền
  7702 là EOA; hợp đồng trong constructor bị coi là EOA. Thay R4.
- **R27** `wallet_kind` do trình duyệt báo (`eth_getCode` qua ví): `contract` ⇒ Odoo nhận chữ ký chưa kiểm,
  node simulate là trọng tài. Thu hẹp R13.
- **R28** `dms_blockchain_payment` phụ thuộc `account_payment` (trước đây `payment`) — auto-pay đọc hoá
  đơn và giao việc gạch nợ cho `account_payment` — provider `chain` không cài được trên DB không có kế toán.
- **R29** `MandateWallet` triển khai ngoài Odoo (`forge create … --constructor-args <owner>`), Odoo chỉ ghi
  địa chỉ — Odoo không gọi RPC và không giữ khoá deploy (R20); factory CREATE2 buộc Odoo tính initcode hash —
  onboarding ví delegated cần một bước vận hành.

## Review log

### Antigravity (agy) — review addendum + plan, 2026-10-03 — 23 finding

Lần 1 chạm quota (`Resets in 13m18s`), hẹn chạy lại nền sau 14 phút như owner yêu cầu.

| # | Sev | Kết luận (đã đối chiếu code) | Xử lý |
|---|---|---|---|
| W1 | crit | Đúng: job `revokeWithSig` không có event thanh toán để chốt | Nhận: job `call` không gắn request ⇒ `mined` = `success`; job trả tiền chốt theo request |
| W2 | crit | **Đúng**: `readonly=True` không chặn ORM/RPC ⇒ ghi `usable_from` là bỏ qua cooling-off | Nhận: `_FOUR_EYES_MANAGED` — chỉ action ghi được `usable_from`, `is_default` |
| W3 | high | Đúng: EOA 7702 đi nhánh 1271 trong `_requireValidSignature` | Nhận: dùng `_isContract(from)`; test EOA 7702 trả bằng ECDSA |
| W4 | high | Một phần: retry tạo request mới khi request cũ còn ký được thì trả hai lần | Thiết kế đã tránh: `action_retry` chỉ cho run `failed`, và run chỉ `failed` khi tx huỷ — tức request đã hết hạn sau `validUntil` + ân hạn, không còn job sống; cùng request thì lane nonce 0 / `refUsed` chặn on-chain |
| W5 | high | **Đúng**: `periodSeconds == 0` reset hạn mức kỳ mỗi lần | Nhận: `BadMandate` cho period 0, delegate 0, per-payment > per-period |
| W6 | high | Đúng (rủi ro) | Nhận: tiền tệ policy = tiền tệ token; cron chỉ lấy hoá đơn cùng tiền tệ |
| W7 | high | Một phần | Từ chối sửa: người gửi phải có entitlement trên đơn (không ẩn danh); chữ ký rác ⇒ simulation fail ⇒ job `dead` ⇒ lane mở lại; buộc ecrecover cho 65 byte phá ví 1271 trả 65 byte (yêu cầu #1) |
| W8 | high | Đúng | Nhận: payload phân nhánh `kind`; `Job` Rust với trường Option, test giải mã job `call` |
| W9 | high | Đúng là thiếu cơ chế deploy | Ruling R29 (deploy ngoài Odoo); không thêm factory |
| W10 | high | Đúng | Nhận: rule công ty cho ví trả, policy, run; Host admin thấy tất cả |
| W11 | high | Đúng | Nhận: `run_state` compute theo trạng thái tx — tx huỷ ⇒ `failed`, trả lại hạn mức |
| W12 | high | Đúng | Nhận: sự kiện ví chỉ huỷ trước khi submit |
| W13 | high | Đúng (ý đồ chưa ghi) | Nhận: `_FROZEN_AFTER_APPROVAL` cho ví trả và policy |
| W14 | med | Đúng (lỗi chữ trong plan) | Nhận: plan sửa thành `OwnerCall(bytes data,…)` |
| W15 | med | Đúng | Nhận: `PayFailed` khi `payWithFee` trả false |
| W16 | med | Không phải lỗi | Từ chối: owner chốt một default mỗi công ty; JS luôn cho chọn khi có nhiều phương án |
| W17 | med | Đúng | Nhận: `signer_ref` giống khoá bị từ chối trước khi ghi; `env:` chỉ nhận tên biến |
| W18 | med | Đúng một nửa (`tryRecover` đã chặn) | Nhận: constructor từ chối owner 0 |
| W19 | med | Đúng | Nhận: `_cron_expire` hiểu `call_valid_until_ts` |
| W20 | med | Đúng | Nhận: tour đăng ký factory, kiểm hiện/ẩn theo project id |
| W21 | low | Đúng | Nhận: thống nhất `approval_state` + `policy_killed` |
| W22 | low | Không khai thác được | Từ chối: `execute` chỉ owner; `payUnderMandate` theo CEI (`refUsed`, hạn mức ghi trước lời gọi ngoài) |
| W23 | low | Ngoài phạm vi | Từ chối: 1271 on-chain có forge test; node simulate calldata y nguyên; calldata/digest Python khoá bằng vector forge |

### Antigravity (agy) — review IMPLEMENTATION đợt 2 (diff 21487ef..), 2026-10-03 — 16 finding

| # | Sev | Kết luận (đã đối chiếu code) | Xử lý |
|---|---|---|---|
| X1 | crit | **Đúng**: guard bốn mắt mở bằng một khoá context — client RPC tự đặt context | Nhận: bỏ cờ context; `_four_eyes_set` đi vòng guard bằng `super()`; test thử ba khoá context |
| X2 | crit | Đúng: kill không chạm tới lần trả đã xếp hàng | Nhận: kill huỷ job `queued/nonce_leased`, hết hạn request, huỷ tx; job đã ký/broadcast thì ghi chatter (không thu hồi được) |
| X3 | crit | Đúng: indexer chốt request trước khi node báo receipt ⇒ job `call` kẹt `mined` | Nhận: báo `mined` khi request đã `final` ⇒ job `final/success`; test đúng thứ tự đó |
| X4 | high | Test khẳng định job còn `queued` sau khi settle — kịch bản không có thật | Nhận: test đi qua claim/signed/settle/mined |
| X5 | high | Đúng: `_chain_status` không thấy job `call` | Nhận: `req._jobs()` |
| X6 | high | Đúng (có từ đợt 1) | Nhận: `reverted` ⇒ `business_state = failed` cho mọi loại job |
| X7 | high | Đúng: request auto-pay hết hạn sau 24 h ⇒ hạn mức và retry treo cả ngày | Nhận: request auto-pay hết hạn sau 1 h |
| X8 | high | Không sai trong thực tế (`failure_note` luôn đi cùng `transaction_id = False`) | Viết lại điều kiện cho rõ |
| X9 | high | Đúng | Nhận: ví trả kiểm định dạng + địa chỉ đốt/token/relayer |
| X10 | high | **Sai**: Odoo 19 dịch đường many2one thành subquery `IN`, không INNER JOIN | Từ chối: `test_expired_call_job_dies_before_relay` chứng minh job `call` hết hạn được |
| X11 | high | Đúng: operator ghi `request_state` qua RPC | Nhận: `request_state`, `issued_valid_until`, `expiry_datetime` chỉ code server (sudo) ghi |
| X12 | med | Rủi ro hiệu năng, không crash (`create_date` luôn có sau create) | Nhận: tính hạn mức bằng search |
| X13 | med | Đúng theo seam territory | Nhận: provider của công ty nhận |
| X14 | med | Đúng (một số ví chỉ có `off`) | Nhận |
| X15 | med | Sai: `chain_relayer_address` đã bị constraint định dạng chặn khoảng trắng | Từ chối |
| X16 | low | Có cách khác: owner ký một lời gọi no-op (`setPayee` cùng giá trị) để đốt nonce | Từ chối |

### Grok
Lần 4 và 5 (prompt review implementation đợt 1): vẫn `free Grok Build usage limit`, không in giờ reset.
Đợt 2 (prompt implementation đợt 2): lần 1 và lần 2 (+1 giờ) vẫn giới hạn. Tổng cộng 7 lần trong ~9 giờ, không lần nào in giờ reset; review Grok chưa có — cần chạy lại khi tài khoản Grok còn quota.

### Codex
Không chạy — hết credit (owner).

---

## Claude review 1 (2026-10-07) — disposition (rev 1.1)

Source: `docs/reviews/specs/2026-10-03-blockchain-payments-addendum-wallets-claude-review-1.md` (verdict
FIX-THEN-GO). Each finding re-checked against the cited code on 2026-10-07 (`scaas` 991d835, `bamboo-dms` b724c91).
Owner rule: docs only — a code bug becomes a ruling (fix + tests) and a stream; nothing built here. Ruling ids
`CR-ADW-n` are local to this addendum.

### Disposition

| # | Sev | Verified against code | Disposition |
|---|---|---|---|
| H1 | high | Confirmed (same root cause as spec gốc H1): operator ACL `1,1,0,0` (`ir.model.access.csv:7`); no immutability of `job_kind/target_address/calldata_hex/call_valid_until_ts` (`blockchain_relay_job.py:79-97`); `work_from_job` signs `job.call` as-is (`submit.rs:108-113`); four producers (`blockchain_subject_account.py:178-196`, `blockchain_payment_request.py:240-255`, `blockchain_autopay.py:101-113`, `dex_trade.py:85-99`), none enforced. | **Accepted** → ruled once in spec gốc **CR-PD-1** (streams PAY-FIX1, PAY-FIX2) |
| M1 | med | Confirmed: `RevokeMandate(token, validUntil)` has no nonce/epoch (`wallet/MandateWallet.sol:148-154,164-166`); `_revoke` deletes the mandate and `setMandate` may recreate it with the same delegate. Other families checked: Solana binds `nonce = generation` (`mandate.rs:210-232`); Sui/Aptos/Cosmos mandates are one-shot (`revoked` is never cleared) — EVM only. | **Accepted** → CR-ADW-1; ADW-FIX1 |
| M2 | med | Confirmed: `MandateWallet.isValidSignature` is ECDSA-only (`MandateWallet.sol:173-176`); `HederaMetaToken._requireValidSignature` uses HIP-632 only when `from` is **not** a contract (`HederaMetaToken.sol:26-32`), so a wallet `from` goes ERC-1271 → ECDSA; HIP-632 needs CALL, ERC-1271 is STATICCALL (`HederaAccountAuth.sol:12-14`). `executeAsOwnerRaw` works for ED25519 owners. | **Accepted** (state the limitation; no token special case) → CR-ADW-2; ADW-FIX2 (test) |
| M3 | med | Confirmed: Odoo stores seed keys as the EOA `m/44'/60'/0'/0/i` (`blockchain_subject_account.py:330-331`); a `SECP256K1` key verifies a raw 32-byte digest (`SubjectAccount.sol:255-262`). Mainstream wallets no longer expose raw `eth_sign`, so the exposure is custom raw signers; still a built-vs-ruling gap against UA R300 / S4F R269 (SPECIFIED). | **Accepted** → CR-ADW-3; ADW-FIX3 |
| L1 | low | Confirmed (`MetaToken.sol:167-176`). | **Accepted** (doc): §A note |
| L2 | low | Confirmed (`MetaToken.sol:141-144`, `HederaMetaToken.sol:22-24`). | **Accepted** (doc): §B.4 note |
| L3 | low | Confirmed: `isValidSignature` accepts any digest signed by any registered key (`SubjectAccount.sol:111-113,253-265`). SCaaS digests bind `from`/`verifyingContract`, so none of ours replay. | **Accepted as documented limitation** (ERC-7739 class); wrapping 1271 digests is **rejected for now**: it changes the digest every 1271 consumer checks (KAT, clientkeys, Odoo) for a risk that only exists for third-party protocols with one key on two accounts |
| L4 | low | Confirmed: `checkPayment` takes `amount`, `decimals` from the caller and only checks the token `≠ account` (`clientkeys/src/evm.js:189-208`); the portal passes server data (`subject_signers.js:410-413`). | **Accepted** → CR-ADW-4; ADW-FIX4 |
| Superseded table (6 rows) | — | R57 (`blockchain_receiving_wallet.py:9-10`), R50 (`lib/custody.py`), W3 (`_isContract`) checked. | **Accepted**: table below + inline markers |

Rejected: L3's code fix only (documented instead). Counts: 1 high, 3 medium, 4 low, 1 table — 9 accepted (L3 as
documentation), 0 rejected outright.

### Rulings

- **CR-ADW-1** **Signed mandate revocation is bound to the mandate's epoch** (M1; also spec gốc L2). `MandateWallet`
  keeps `epoch[token]` (uint64), incremented by every `setMandate` and every revoke; `RevokeMandate` becomes
  `RevokeMandate(address token,uint64 epoch,uint256 validUntil)` and `revokeWithSig` requires `epoch == epoch[token]`.
  Typehash change: dev deployments only (no production wallet exists); Odoo `eip712.revoke_mandate_digest`,
  `blockchain_autopay._enqueue_revoke` and the forge KAT change together. — Why: a public revoke signature replayed
  until `validUntil` deletes a mandate the owner re-established. — Tests: forge — revoke, `setMandate` again, replay
  ⇒ `BadSignature`/`StaleEpoch`; current-epoch revoke works; Odoo digest == forge vector.
- **CR-ADW-2** **Hedera ED25519 owners pay from a `MandateWallet` only through `executeAsOwnerRaw`** (M2). ERC-1271
  runs under STATICCALL and HIP-632 `isAuthorizedRaw` halts there, so `isValidSignature` cannot cover ED25519; the
  token is not special-cased (one more Hedera-only path in the signature pipeline for a rare case). The §D sentence
  "chủ vẫn trả tay được bằng meta-tx" holds for ECDSA owners only. The owner's raw call is relayed as a `call` job
  (selector in the CR-PD-1 table) or submitted by the owner. — Tests: forge with `vm.etch` HAS mock — ED25519 owner
  pays a payee via `executeAsOwnerRaw` (`token.pay…` as `data`); the same owner's meta-tx with `from = wallet`
  fails ERC-1271.
- **CR-ADW-3** **New seed keys for subject accounts use the role path** (M3): new `SECP256K1` keys registered by
  Odoo/clientkeys are derived on the UA R300 / S4F R269 role path (`m/7622'/0'/<account>'/2'/<i>'`, SCaaS §9.4),
  never the subject's EOA key; existing dev keys stay until rotated. R32/§C.3 derivation for accounts is
  superseded. — Tests: clientkeys vector for the role path; Odoo refuses registering a key whose address equals the
  subject's EOA (`payer_address`) on the same account. If TODO already carries an S4F R269 stream, ADW-FIX3 merges
  into it.
- **CR-ADW-4** **`checkPayment` pins the token client-side** (L4): `checkPayment` takes `expectedToken` (and its
  `decimals`, `symbol`) from the signer's own chain profile (app/extension build-time or user-pinned registry), not
  from the server response, and refuses `verifyingContract ≠ expectedToken`. A portal page served by the same
  server that serves the typed data cannot be defended this way (it ships the signer code); that case is stated as
  out of scope. — Tests: clientkeys — server data with a different token but the expected symbol ⇒ refused.

### Superseded rulings and statements

| ADW text | Superseded by |
|---|---|
| R23 "Host" = `dms_blockchain.host_company_id` | R57 "platform company", `dms_blockchain.platform_company_id` |
| §D `env:` adapter "ký ECDSA RFC 6979 low-s thuần Python" | R50: OpenSSL (`cryptography`), dev-only flag + dev chain (`lib/custody.py:9-13,64-75`) |
| R26 "in the token code" for all tokens | R63: HTS allowances cannot be restricted (wrapper-only use) |
| §B.4 `from.code.length > 0` selects ERC-1271 | review W3: `_isContract(from)` (7702 designators are EOAs) — code follows W3 |
| §A "không có cửa thứ hai" | R35 meta-op `approve` (same contract-only check) |
| §C.3/§D seed keys on the EOA path | UA R300 / S4F R269 role path (CR-ADW-3) |
| §D outbox claimed by node over `/json/2` | NI R87/R101 push job API (SPECIFIED); call jobs restricted by CR-PD-1 |
| §D "chủ trả tay bằng meta-tx" (all owners) | CR-ADW-2 (ECDSA owners only on Hedera) |
| chain 9000 | 7622 (formerly 9000) |

### Amendments needed in other specs (recorded; owner syncs)

| Spec | Amendment |
|---|---|
| SCaaS.md | §9.4 / §4: `RevokeMandate` carries `epoch` (CR-ADW-1); §7.2 Hedera: ED25519 owners use `executeAsOwnerRaw` for wallet payments (CR-ADW-2); §9.3: 1271 digests are not account-wrapped — documented limitation (L3). |
| NI rev 3.6 | call table (spec gốc CR-PD-1) includes `executeAsOwnerRaw` and the epoch-bound `revokeWithSig`. |
| UA / S4F | none beyond the existing R300 / R269 (CR-ADW-3 implements them for subject accounts). |

### Code streams (new; for TODO)

| Stream | Scope | Ruling |
|---|---|---|
| (PAY-FIX1, PAY-FIX2) | outbox lock + node call table — shared with spec gốc | CR-PD-1 |
| **ADW-FIX1** | `MandateWallet` epoch + new `RevokeMandate` typehash; Odoo `eip712` + autopay; KAT; tests | CR-ADW-1 |
| **ADW-FIX2** | forge test: Hedera ED25519 owner pays via `executeAsOwnerRaw`; meta-tx from wallet fails | CR-ADW-2 |
| **ADW-FIX3** | Odoo `blockchain_subject_account` + clientkeys: register role-path seed keys; refuse EOA-equal key | CR-ADW-3 |
| **ADW-FIX4** | clientkeys `checkPayment(expectedToken…)`; callers pass their own chain profile; test | CR-ADW-4 |

### Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | Addendum R21–R29; agy reviews (design + plan, implementation round 2) |
| 1.1 | 2026-10-07 | Claude review 1 folded: 9 findings accepted (L3 as documentation, its code fix rejected); rulings CR-ADW-1…4; streams ADW-FIX1…4; superseded-rulings table; chain 7622 (formerly 9000) |
