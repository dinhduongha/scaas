# Ví: chuẩn mở, ví nhận, ví trả, auto-pay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Thanh toán on-chain làm việc với mọi ví theo chuẩn mở; mỗi công ty cấu hình ví nhận (bốn mắt, snapshot); người trả cấu hình ví trả và auto-pay có hạn mức; approve chỉ cho hợp đồng.

**Architecture:** Contract: quy tắc approve trong `ERC20MetaTx`, `MandateWallet` mới. Odoo core: mixin bốn mắt, `blockchain.receiving.wallet`, `blockchain.paying.wallet`, custody adapter, outbox job `call`. Payment: provider bỏ token/địa chỉ, auto-pay policy + run + cron. Bridge: options API, cảnh báo nhân viên, JS EIP-6963/1271/events. Node: job `call`.

**Tech Stack:** Solidity 0.8 + Foundry; Odoo 19; vanilla JS + Odoo tour; Rust (alloy 1.6).

**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-payments-addendum-wallets.md` + spec gốc.

## Global Constraints

- Không thư viện JS/Python mới; không gọi RPC chain từ Odoo (R20).
- Không trường/param nào giữ khoá (CLAUDE.md §5.5); `signer_ref` là handle.
- `models.Constraint`/`models.UniqueIndex`, không `_sql_constraints` (CLAUDE.md §5.2).
- Cron body trong method (CLAUDE.md §5.4).
- RPC public: không `_`, không `@api.private`; không nhận company từ client (CLAUDE.md §6).
- Test Odoo: `scripts/chain-odoo-test.sh` (DB `dms_test_chain`, port 8920), không chạy song song.
- Không tên field trùng kiểu dữ liệu (`date`, ...).

## Review Focus

1. Ví nhận bị sửa/thay sau khi request mở → request vẫn trả địa chỉ cũ (test T5).
2. Cùng một người vừa đề xuất vừa duyệt (kể cả admin) → từ chối (T4).
3. Cron auto-pay chạy hai lần / ngoại lệ giữa chừng → không trả hai lần (T8).
4. Ví 7702 (EOA có designator) được approve → revert (T1).
5. Trình duyệt không có ví EIP-6963 nào → fallback `window.ethereum`, không treo (T10).

---

## Part A — contracts

### Task 1: approve/transferFrom chỉ cho hợp đồng

**Files:** Modify `smartcontracts/src/metatx/ERC20MetaTx.sol`, `src/metatx/IERC20MetaTx.sol` (errors). Test: `smartcontracts/test/ContractOnlyAllowance.t.sol`.

- [ ] Test (fail trước): `approve(EOA)` revert `SpenderNotContract`; `approve(contract)` ok; EOA gọi `transferFrom` revert `CallerNotContract`; contract đã được approve gọi `transferFrom` ok; `vm.etch(eoa, 0xef0100‖impl)` ⇒ `approve(eoa)` revert và eoa gọi `transferFrom` revert; hợp đồng gọi `transferFrom` trong constructor revert; approve địa chỉ counterfactual revert; DEX + MetaToken suites vẫn xanh.
- [ ] Cài đặt:

```solidity
function approve(address spender, uint256 value) public virtual override returns (bool) {
    if (!_isContract(spender)) revert SpenderNotContract(spender);
    return super.approve(spender, value);
}
function transferFrom(address from, address to, uint256 value) public virtual override returns (bool) {
    if (!_isContract(msg.sender)) revert CallerNotContract(msg.sender);
    return super.transferFrom(from, to, value);
}
/// code rỗng (EOA, hoặc hợp đồng đang chạy constructor) hoặc đúng designator EIP-7702 ⇒ không phải hợp đồng
function _isContract(address a) internal view returns (bool) {
    uint256 len = a.code.length;
    if (len == 0) return false;
    if (len == 23) { bytes memory c = a.code; if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false; }
    return true;
}
```
- [ ] `forge test` (default + `FOUNDRY_PROFILE=private9000`), commit `feat(contracts): allowances only between contracts`.

### Task 2: test EIP-1271 cho meta-tx

**Files:** `smartcontracts/test/helpers/Mocks.sol` (Mock1271Wallet: mode valid/invalid/revert/garbage), `test/Erc1271.t.sol`.
- [ ] Ví hợp lệ ⇒ `pay` thành công, `PaymentSettled.from == wallet`; magic sai / revert / trả 4 byte ⇒ `MetaTxBadSignature`, nonce không đổi.
- [ ] Commit `test(contracts): ERC-1271 wallets pay through meta-tx`.

### Task 3: MandateWallet

**Files:** Create `smartcontracts/src/wallet/MandateWallet.sol`, `test/MandateWallet.t.sol`.

**Interfaces (Produces, dùng ở T7/T8/T11):**
- domain EIP-712 `("SCaaS MandateWallet","1",chainId,wallet)`
- `PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256 validUntil)`
- `RevokeMandate(address token,uint256 validUntil)`
- `payUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256 validUntil,bytes sig)` selector tính trong test Python.
- `revokeWithSig(address token,uint256 validUntil,bytes sig)`
- owner: `setMandate(token,delegate,maxPerPayment,maxPerPeriod,periodSeconds,expiry)`, `setPayee(token,payee,bool)`, `revoke(token)`, `execute(target,value,data)`; `executeAsOwner(bytes data,uint256 nonce,uint256 validUntil,bytes sig)` (owner ký `OwnerCall(bytes data,uint256 nonce,uint256 validUntil)` — `bytes` băm `keccak256(data)` theo EIP-712, gọi `address(this).call(data)`; hàm owner nhận `msg.sender == owner || msg.sender == address(this)`).
- `isValidSignature(hash,sig)` ⇒ magic khi ECDSA recover == owner.

- [ ] Test: trả trong hạn mức ⇒ `PaymentSettled(wallet→payee, entryRef)`; > maxPerPayment revert; tổng kỳ > maxPerPeriod revert, sang kỳ mới ok; payee không trong danh sách revert; hết `expiry` revert; sau `revoke`/`revokeWithSig` revert; `entryRef` dùng lại revert; chữ ký không phải delegate revert; `validUntil` qua revert; không gọi `approve`/`transferFrom` (đường trả = `payWithFee`); owner trả tay qua meta-tx (1271); `executeAsOwner` đặt mandate gasless.
- [ ] Commit `feat(contracts): MandateWallet — on-chain capped delegated payments`.

## Part B — Odoo core (`dms_blockchain`)

### Task 4: mixin bốn mắt + ví nhận

**Files:** Create `dms_blockchain/models/blockchain_four_eyes.py` (AbstractModel `blockchain.four.eyes.mixin`), `models/blockchain_receiving_wallet.py`; modify `lib/eip712.py` (`to_checksum`, `parse_address`), security XML/CSV (group `group_blockchain_treasury`, rules), views, `data/ir_config_parameter.xml` (cooling hours 24); test `tests/test_receiving_wallet.py`.

**Interfaces:**
- mixin: `approval_state` (`draft|pending_approval|approved|archived`), `proposed_by_id`, `approved_by_id`, `approved_datetime`, `action_submit()`, `action_approve()`, `action_reset_draft()`, `action_archive()`; hook `_four_eyes_company()`; `_FROZEN_AFTER_APPROVAL` (tên field không sửa được khi `approved`).
- `res.users._blockchain_wallet_admin(company) -> bool` (system, hoặc treasury + company ∈ company_ids).
- `eip712.parse_address(value) -> str` (chữ thường; mixed-case phải đúng EIP-55, ValueError khác).
- `blockchain.receiving.wallet._usable(company, token=None)` -> recordset approved, `usable_from <= now`.
- `_blockchain_forbidden_addresses(chain) -> set[str]` (hook; core: zero, dead, token của chain).

- [ ] Test: checksum đúng/sai/chữ thường; zero/dead/token address bị từ chối; người đề xuất tự duyệt bị từ chối (kể cả admin); user không có quyền công ty bị từ chối; ví approved không sửa được `address`; cooling: `usable_from = approved + 24h`, `_usable` rỗng trước hạn; default: chỉ khi usable, tối đa một mỗi công ty; công ty B không đọc ví công ty A; system đọc tất cả; mail tracking ghi đổi `address`.
- [ ] Commit `feat(blockchain): per-company receiving wallets with four-eyes approval`.

### Task 5: request snapshot + ví nhận

**Files:** `models/blockchain_payment_request.py` (field `receiving_wallet_id`, `_open_request(receiving_wallet=...)`, chặn ghi snapshot), test `tests/test_payment_request.py`.
- [ ] Test: tạo request từ ví W; lưu trữ W, tạo W2 default; request vẫn `receiving_address == W.address`, typed data `to == W.address`; `write({'receiving_address': ...})` raise; ví chưa usable ⇒ `_open_request` raise.
- [ ] Commit `feat(blockchain): payment requests snapshot the receiving wallet`.

### Task 6: custody adapter + ví trả

**Files:** Create `lib/custody.py` (registry, scheme `env:`), `lib/secp256k1.py` (+`sign` RFC 6979 low-s, `address_of`), `models/blockchain_paying_wallet.py`; tests `tests/test_custody.py`, `tests/test_paying_wallet.py`.

**Interfaces:** `custody.address(ref) -> str`, `custody.sign_digest(ref, digest32) -> bytes(65)`, `custody.register(scheme, adapter)`. `blockchain.paying.wallet`: `partner_id, company_id, chain_id, token_id, address, wallet_mode (manual|custodial|delegated), signer_ref, license_ref, delegate_address` + mixin.

- [ ] Test: khoá anvil #0 ⇒ địa chỉ `0xf39f…2266`, chữ ký ecrecover đúng, s ≤ n/2, tất định; ref sai scheme ⇒ ValueError; custodial: `address` phải = `custody.address(signer_ref)` khi duyệt; partner không phải công ty + custodial không `license_ref` ⇒ ValidationError; không field `ir.model.fields` blockchain.* nào chứa khoá hex sau khi ký; không `ir.config_parameter` nào chứa khoá.
- [ ] Commit `feat(blockchain): paying wallets and the custody adapter socket`.

### Task 7: outbox job `call`

**Files:** `models/blockchain_relay_job.py` (`job_kind`, `target_address`, `calldata_hex`, `call_valid_until_ts`, `payment_request_id`; `metatx_id` không bắt buộc), `lib/abi.py` (encode `payUnderMandate`, `revokeWithSig`), `lib/eip712.py` (`mandate_domain`, `pay_under_mandate_digest`, `revoke_digest`), request `_live_job` gồm job `call`; final ⇒ job `call` của request `final/success`; tests `tests/test_relay_job.py`, `tests/test_eip712.py` (selector + digest khớp forge).
- [ ] Commit `feat(blockchain): outbox carries plain contract calls`.

## Part C — payment (`dms_blockchain_payment`)

### Task 8: provider dùng ví nhận + auto-pay

**Files:** `models/payment_provider.py` (bỏ `chain_token_id`, `chain_receiving_address`; forbidden addresses hook = relayer), `models/payment_transaction.py` (`chain_receiving_wallet_id`, `_chain_start(payer, receiving_wallet)`), create `models/blockchain_autopay.py` (`blockchain.autopay.policy`, `blockchain.autopay.run`, `_cron_autopay`), data cron, views, ACL; tests `tests/test_chain_provider.py`, `tests/test_autopay.py`.

**Interfaces:** policy: `partner_id, paying_wallet_id, company_id, trigger (invoice_posted|invoice_due), max_per_payment, max_per_day, max_per_month, currency_id, policy_killed` + mixin, `action_kill()`. run: `policy_id, move_id, due_key, run_state (submitted|paid|failed), amount, transaction_id, failure_note`, UNIQUE(policy_id, move_id, due_key). `_cron_autopay(now=None)`.

- [ ] Test: custodial: hoá đơn posted ⇒ một tx `pending` + metatx đã ký từ ví trả, payee = ví nhận usable của công ty hoá đơn; chạy cron lần 2 ⇒ không có tx mới; vượt per-tx / per-day / per-month ⇒ run `failed` + activity, không tx; không ví nhận usable ⇒ failed + activity; policy chưa duyệt / bị kill ⇒ không chạy; delegated ⇒ job `call` tới ví mandate với calldata `payUnderMandate`, `action_kill` ⇒ job `revokeWithSig`; event `PaymentSettled` final ⇒ tx `done` (đối soát như tay); bốn mắt cho policy.
- [ ] Commit `feat(blockchain): auto-pay policies with caps, four-eyes and idempotent runs`.

## Part D — portal + node

### Task 9: options API + cảnh báo nhân viên

**Files:** `dms_blockchain_bridge/models/dms_portal_api.py` (`dms_portal_chain_payment_options`, start nhận `receiving_wallet_id`, `wallet_kind`), `models/sale_order.py` (`dms_chain_staff_note` compute), `views/sale_order_views.xml`, template; tests.
- [ ] Test: options liệt kê đúng cặp usable của công ty đơn (không lộ ví công ty khác, ví chưa usable); không có ⇒ `_dms_chain_offered` False và `dms_chain_staff_note` có nội dung; `wallet_kind='contract'` + chữ ký 65 byte sai ⇒ nhận chưa kiểm; `eoa` ⇒ từ chối.
- [ ] Commit `feat(dms-portal): pay-on-chain lists the receiving company's chain/asset options`.

### Task 10: JS EIP-6963 + events + tours

**Files:** `static/src/js/chain_pay.js`, `static/tests/tours/chain_pay_tour.js` (`web.assets_tests`), `tests/test_tour.py`.
- [ ] Tour 1 (fallback): không announce, `window.ethereum` giả ⇒ không hiện picker, gọi `eth_requestAccounts`, ký trả lỗi 4001 ⇒ "You cancelled". Tour 2 (picker): hai ví announce (một icon `data:` hợp lệ, một icon `javascript:`) ⇒ hai nút, icon thứ hai không render; chọn ví 2 ⇒ ví 2 nhận request; `localStorage` nhớ rdns.
- [ ] Commit `feat(dms-portal): EIP-6963 wallet picker, chain/account events, user rejection`.

### Task 11: node job `call`

**Files:** `scaas-node/src/odoo.rs` (`Job.metatx` Option, `Job.call` Option), `src/submit.rs` (`work_from_job`), unit test.
- [ ] Commit `feat(node): relay plain contract calls from the outbox`.

### Task 12: review + full suites
- [ ] forge (2 profile), cargo test + clippy, Odoo 3 addon + upgrade gate, agy review diff, sửa, ghi log.
