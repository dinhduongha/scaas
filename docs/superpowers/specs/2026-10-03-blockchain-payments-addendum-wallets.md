# Addendum — ví: chuẩn mở, ví nhận, ví trả và tự động thanh toán

**Ngày:** 2026-10-03 · **Bổ sung cho:** `2026-10-03-blockchain-payments-design.md` (gọi tắt "spec gốc")
**Nguồn yêu cầu:** owner, bốn yêu cầu trong cùng phiên (chuẩn ví mở; ví nhận theo công ty; ví trả +
auto-pay; quy tắc approve — hai lần đính chính). Mọi ruling mới đánh số tiếp từ R21.

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
| EOA đã uỷ quyền EIP-7702 (Prague; chain 9000 có Prague) | 23, bắt đầu `0xef0100` | **EOA** | code chỉ là designator; khoá riêng của EOA vẫn ký được mọi thứ |
| Hợp đồng đang chạy constructor | 0 | **EOA** (từ chối) | không phân biệt được với EOA trong cùng lúc; hệ quả ghi rõ: một hợp đồng **không thể** được approve hay tiêu allowance từ constructor của chính nó |
| Hợp đồng đã deploy | > 0, không phải designator | hợp đồng | — |

Cài đặt: `ERC20MetaTx` (gốc của mọi token trong hệ) override `approve` (spender phải là hợp đồng) và
`transferFrom` (`msg.sender` phải là hợp đồng). Token không có `permit`/`increaseAllowance`, nên không
có cửa thứ hai. Lỗi: `SpenderNotContract(address)`, `CallerNotContract(address)`.

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
   `isValidSignature` (magic `0x1626ba7e`) khi `from.code.length > 0` — không viết lại, chỉ thêm test
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
- **Host — ruling R23:** Host = `ir.config_parameter` `dms_blockchain.host_company_id`, mặc định
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
biến môi trường tiến trình, ký ECDSA RFC 6979 low-s thuần Python). Adapter production (`broker:` gọi
custody broker qua mTLS, KMS, HSM) cắm vào cùng registry. **Không trường, không tham số, không attachment
nào chứa khoá** — có test duyệt `ir.model.fields` và `ir.config_parameter`.

**`MandateWallet` (delegated) — ruling R25.** Một smart account mỗi người trả, chủ là EOA của họ:
- giữ tiền (người trả nạp vào), hiện thực ERC-1271 cho chữ ký của chủ (nên chủ vẫn trả tay được từ ví này
  bằng meta-tx);
- chủ đặt mandate theo token: `delegate`, `maxPerPayment`, `maxPerPeriod`, `periodSeconds`, `expiry`, và
  danh sách payee được phép (chủ đặt — tức địa chỉ nhận đã duyệt của đối tác);
- `payUnderMandate(order, delegateSig)`: kiểm on-chain chưa revoke, chưa hết hạn, payee được phép, ≤
  hạn mức lần, ≤ hạn mức kỳ, order chưa dùng (chống replay), chữ ký EIP-712 của delegate; rồi gọi
  `IERC20Payment.payWithFee(to, amount, NONE, 0, 0, entryRef)` — **đường trả trực tiếp đã có trong
  `IERC20Payment`**, `msg.sender` là ví, không dùng allowance. `PaymentSettled` vẫn mang `entryRef` nên
  đối soát y hệt thanh toán tay;
- kill switch on-chain: `revoke(token)` bởi chủ, hoặc `revokeWithSig` bởi delegate (để platform revoke
  ngay qua relayer).
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
`call` `final` khi `PaymentSettled` của request final.

**Ngoài phạm vi lần này:** đối soát phía người trả khi người trả cũng là một công ty trong cùng DB (hoá
đơn mua — bút toán liên công ty), cấu hình ví trả do chính khách tự phục vụ trên portal (nhân viên cấu hình
hộ; mandate on-chain do khách ký), adapter custody production.

## Rulings mới

- **R21** WalletConnect = seam + cờ cấu hình, không nạp SDK trong core (xem B.5).
- **R22** Cooling-off 24 h áp cho mọi việc dùng ví nhận mới duyệt.
- **R23** Host = tham số cấu hình, mặc định công ty chính.
- **R24** Ví trả `custodial` của partner không phải công ty bắt buộc `license_ref`.
- **R25** Delegated = `MandateWallet` riêng (ERC-1271 + mandate on-chain + `payWithFee`), không allowance.
- **R26** Quy tắc approve: spender phải là hợp đồng, `transferFrom` chỉ do hợp đồng gọi; EOA uỷ quyền
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

### Grok
Lần 4 và 5 (prompt review implementation đợt 1): vẫn `free Grok Build usage limit`, không in giờ reset.

### Codex
Không chạy — hết credit (owner).
