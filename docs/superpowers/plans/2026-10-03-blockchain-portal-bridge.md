# Portal On-Chain Payment (bridge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Portal users pay a confirmed DMS order on-chain with a gasless meta-transaction: `start` → wallet signs EIP-712 → `submit` (outbox) → relayer → finalized event → payment `done` → standard `account_payment` post-processing.

**Architecture:** `dms_blockchain_bridge` (auto-installs when `dms_blockchain_payment` and `dms_portal` are both present) adds three public methods on `dms.portal.api` — thin entry points that check entitlement, then delegate to private helpers on `payment.transaction` from `dms_blockchain_payment`. The order page gets one button and a vanilla JS file that only talks to those methods over `call_kw`.

**Tech Stack:** Odoo 19 (`dms_portal`, `payment`, `sale`, `account_payment`), vanilla ES2020 + EIP-1193 (`window.ethereum`).

**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` §4.5, §5, §9 (T1, T2, T5), rulings R14, R17, R19.

## Global Constraints

- Entry points: names without `_`, no `@api.private`, no `company_id`/amount parameters; entitlement (`self.env.user.dms_allowed_partner_ids()`) checked before any `sudo()` read (CLAUDE.md §6, dms_portal pattern).
- Only `state == 'sale'` orders (R19). Token currency must equal order currency (R17), checked first.
- Amount: posted, unpaid customer invoices of the order ⇒ `invoice_ids` and Σ `amount_residual`; none ⇒ `sale_order_ids` and `amount_total − amount_paid`.
- Wallet switch only when no live job and `issued_valid_until + 60 s` has passed; then the old tx is cancelled and its request expired.
- `call_kw` AND `/json/2` both tested for every new method.
- JS holds no business logic; amounts and terms come from the server.

## Review Focus

- Portal user B asks to `start` user A's order (IDOR by numeric id) — `AccessError` — pinned in Task 1.
- `status`/`submit` with another partner's transaction reference — `AccessError` — pinned in Task 1.
- A second `start` from the same wallet after a submitted signature must return the SAME lane, never a new request — pinned in Task 1.
- A quotation (`draft`) must be refused, not silently confirmed by `sale._post_process` — pinned in Task 1.
- After a finalized `PaymentSettled`, the transaction is `done` and post-processing creates the `account.payment` (reconciling an invoice when there is one) — pinned in Task 2.

## File Structure

| File | Responsibility |
|---|---|
| `dms_blockchain_bridge/__init__.py`, `__manifest__.py` | addon, auto_install |
| `dms_blockchain_bridge/models/dms_portal_api.py` | three public methods + private helpers |
| `dms_blockchain_bridge/views/portal_templates.xml` | button on `/my/dms/order/<id>` |
| `dms_blockchain_bridge/static/src/js/chain_pay.js` | connect → start → sign → submit → poll |
| `dms_blockchain_bridge/tests/test_portal_chain_payment.py` | logic + call_kw + json/2 + end-to-end ingest |

---

### Task 1: Portal API (`start` / `submit` / `status`)

**Files:**
- Create: `dms_blockchain_bridge/__init__.py`, `__manifest__.py`, `models/__init__.py`, `models/dms_portal_api.py`, `tests/__init__.py`, `tests/test_portal_chain_payment.py`

**Interfaces:**
- Consumes: `payment.transaction._chain_start/_chain_submit/_chain_status`, `blockchain.payment.request._live_job()`, `eip712.norm_address`.
- Produces: `dms.portal.api.dms_portal_chain_payment_start(order_id, from_address) -> {reference, amount, currency, chain{chainId, chainIdHex, name, rpcUrl, nativeCurrency, tokenSymbol}, typed_data}`; `dms_portal_chain_payment_submit(reference, valid_until, signature) -> status dict`; `dms_portal_chain_payment_status(reference) -> {reference, tx_state, request_state, job_state, tx_hash}`; private `_dms_chain_offered(order) -> bool` (used by the template).

- [ ] **Step 1: Failing tests** — `dms_blockchain_bridge/tests/test_portal_chain_payment.py`:

```python
import json

from odoo.exceptions import AccessError, UserError
from odoo.tests.common import HttpCase, tagged

from odoo.addons.dms_blockchain.lib import eip712
from odoo.addons.dms_blockchain.tests.test_payment_request import PK, _addr, _sign
from odoo.addons.dms_portal.tests.test_portal_catalog import PortalCatalogCase


class ChainPortalCase(PortalCatalogCase):

    def setUp(self):
        super().setUp()
        Account = self.env['account.account'].sudo()
        income = Account.create({'name': 'CP Income', 'code': 'CP4000', 'account_type': 'income',
                                 'company_ids': [(6, 0, [self.dist.id])]})
        receivable = Account.create({'name': 'CP Receivable', 'code': 'CP1310',
                                     'account_type': 'asset_receivable', 'reconcile': True,
                                     'company_ids': [(6, 0, [self.dist.id])]})
        bank_acc = Account.create({'name': 'CP Chain Bank', 'code': 'CP1120',
                                   'account_type': 'asset_cash', 'company_ids': [(6, 0, [self.dist.id])]})
        self.env['account.journal'].sudo().create({
            'name': 'CP Sales', 'code': 'CPSA', 'type': 'sale', 'company_id': self.dist.id,
            'default_account_id': income.id})
        self.chain_journal = self.env['account.journal'].sudo().create({
            'name': 'CP Chain', 'code': 'CPCH', 'type': 'bank', 'company_id': self.dist.id,
            'default_account_id': bank_acc.id})
        self.outlet_a.with_company(self.dist).property_account_receivable_id = receivable

        self.chain = self.env['blockchain.chain'].sudo().create({
            'name': 'Portal 9002', 'evm_chain_number': 9002, 'state': 'active',
            'public_rpc_url': 'http://localhost:8545'})
        self.token = self.env['blockchain.token'].sudo().create({
            'chain_id': self.chain.id, 'address': '0x' + 'cd' * 20, 'name': 'Bamboo Local',
            'symbol': 'bLOC', 'decimals': 6, 'currency_id': self.dist.currency_id.id})
        self.provider = self.env.ref('dms_blockchain_payment.payment_provider_chain').sudo().copy({
            'name': 'Chain (dist)', 'company_id': self.dist.id})
        self.provider.write({
            'state': 'test', 'journal_id': self.chain_journal.id,
            'chain_token_id': self.token.id, 'chain_receiving_address': '0x' + '5e' * 20,
            'chain_relayer_address': '0x' + '02' * 20})
        self.payer = _addr(PK)
        self.indexer = self.env['res.users'].sudo().create({
            'name': 'idx', 'login': 'idx-portal@chain.test',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id,
                                  self.env.ref('dms_blockchain.group_blockchain_indexer').id])]})

    def _api(self, user=None):
        return self.env['dms.portal.api'].with_user(user or self.buyer)

    def _confirmed_order(self):
        self._entitle()
        result = self._api().dms_portal_submit(
            self.outlet_a.id, [{'product_id': self.product_a.id, 'quantity': 2}])
        self.assertTrue(result['order_id'], result.get('errors'))
        order = self.env['sale.order'].sudo().browse(result['order_id'])
        order.write({'dms_approval_state': 'approved'})
        order.action_confirm()
        self.assertEqual(order.state, 'sale')
        return order

    def _sign_start(self, start):
        req = self.env['payment.transaction'].sudo().search(
            [('reference', '=', start['reference'])]).chain_request_id
        vu = int(start['typed_data']['message']['validUntil'])
        dg = eip712.digest(self.token._domain(), req._message(vu))
        return vu, '0x' + _sign(PK, dg).hex(), req

    def _settle(self, req, amount=None):
        block = self.chain.indexed_block + 1
        return self.env['blockchain.chain.event'].with_user(self.indexer).chain_event_ingest(
            9002, block, block, '0x' + '0b' * 32, [{
                'event': 'PaymentSettled', 'contract': self.token.address, 'block_number': block,
                'block_hash': '0x' + '0b' * 32, 'tx_hash': '0x' + f'{block:02x}' * 32, 'log_index': 0,
                'from': self.payer, 'to': req.receiving_address,
                'amount': amount or req.amount_base, 'fee': '0',
                'fee_recipient': '0x' + '02' * 20, 'entry_ref': req.entry_ref_hex}])


@tagged('post_install', '-at_install')
class TestPortalChainPayment(ChainPortalCase):

    def test_start_returns_typed_data_for_a_confirmed_order(self):
        order = self._confirmed_order()
        start = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        self.assertEqual(start['chain']['chainId'], 9002)
        self.assertEqual(start['typed_data']['message']['from'], self.payer)
        self.assertEqual(float(start['amount']), order.amount_total)
        self.assertEqual(int(start['typed_data']['message']['value']),
                         round(order.amount_total * 10 ** 6))

    def test_another_partners_order_is_refused(self):
        self._entitle()
        stray = self.env['sale.order'].sudo().create({'partner_id': self.outlet_b.id})
        with self.assertRaises(AccessError):
            self._api().dms_portal_chain_payment_start(stray.id, self.payer)

    def test_a_quotation_is_refused(self):
        self._entitle()
        result = self._api().dms_portal_submit(
            self.outlet_a.id, [{'product_id': self.product_a.id, 'quantity': 1}])
        with self.assertRaises(UserError):
            self._api().dms_portal_chain_payment_start(result['order_id'], self.payer)

    def test_currency_mismatch_is_refused_first(self):
        order = self._confirmed_order()
        self.token.currency_id = self.env.ref('base.EUR') if self.dist.currency_id != self.env.ref('base.EUR') \
            else self.env.ref('base.USD')
        with self.assertRaises(UserError):
            self._api().dms_portal_chain_payment_start(order.id, self.payer)

    def test_bad_address_is_a_user_error(self):
        order = self._confirmed_order()
        with self.assertRaises(UserError):
            self._api().dms_portal_chain_payment_start(order.id, '0x123')

    def test_restart_from_same_wallet_keeps_the_lane(self):
        order = self._confirmed_order()
        first = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        vu, sig, req = self._sign_start(first)
        self._api().dms_portal_chain_payment_submit(first['reference'], vu, sig)
        second = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        self.assertEqual(second['reference'], first['reference'])
        self.assertEqual(second['typed_data']['message']['batch'], first['typed_data']['message']['batch'])

    def test_another_wallet_waits_for_the_open_signature(self):
        order = self._confirmed_order()
        self._api().dms_portal_chain_payment_start(order.id, self.payer)
        with self.assertRaises(UserError):
            self._api().dms_portal_chain_payment_start(order.id, '0x' + '77' * 20)

    def test_submit_queues_outbox_and_status_reports_it(self):
        order = self._confirmed_order()
        start = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        vu, sig, _ = self._sign_start(start)
        status = self._api().dms_portal_chain_payment_submit(start['reference'], vu, sig)
        self.assertEqual(status['tx_state'], 'pending')
        self.assertEqual(status['job_state'], 'queued')
        self.assertEqual(self._api().dms_portal_chain_payment_status(start['reference'])['job_state'], 'queued')

    def test_status_of_another_partners_reference_is_refused(self):
        order = self._confirmed_order()
        start = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        other = self.env['res.users'].sudo().create({
            'name': 'Other Buyer', 'login': 'other-chain@dms.test',
            'group_ids': [(6, 0, [self.env.ref('base.group_portal').id])]})
        with self.assertRaises(AccessError):
            self._api(other).dms_portal_chain_payment_status(start['reference'])
        with self.assertRaises(AccessError):
            self._api(other).dms_portal_chain_payment_submit(start['reference'], 1, '0x00')

    def test_no_amount_parameter_anywhere(self):
        import inspect
        api = type(self.env['dms.portal.api'])
        for name in ('dms_portal_chain_payment_start', 'dms_portal_chain_payment_submit',
                     'dms_portal_chain_payment_status'):
            params = inspect.signature(getattr(api, name)).parameters
            self.assertNotIn('amount', params)
            self.assertNotIn('company_id', params)
            self.assertFalse(name.startswith('_'))
```

- [ ] **Step 2: Run to verify it fails**

Run: `source /home/dockers/odoo19/.env && scripts/chain-odoo-test.sh dms_blockchain,dms_blockchain_payment,dms_portal,dms_blockchain_bridge /dms_blockchain_bridge`
Expected: error — module `dms_blockchain_bridge` not found / methods missing.

- [ ] **Step 3: Implement**

`__manifest__.py`:

```python
{
    'name': 'Bamboo Blockchain - DMS Portal bridge',
    'version': '19.0.1.0.0',
    'license': 'LGPL-3',
    'category': 'Accounting/Payment Providers',
    'summary': 'Portal users pay confirmed DMS orders with a gasless on-chain meta-transaction',
    'author': 'dinhduongha@gmail.com',
    # auto_install True = install when BOTH sides are installed (canon §C3) — never pulls
    # blockchain into a DMS that did not ask for it.
    'depends': ['dms_blockchain_payment', 'dms_portal'],
    'data': ['views/portal_templates.xml'],
    'assets': {'web.assets_frontend': ['dms_blockchain_bridge/static/src/js/chain_pay.js']},
    'installable': True,
    'application': False,
    'auto_install': True,
}
```

`models/dms_portal_api.py`:

```python
import time

from odoo import api, models
from odoo.exceptions import AccessError, UserError

from odoo.addons.dms_blockchain.lib.eip712 import norm_address

_SWITCH_GRACE = 60


class DmsPortalApi(models.AbstractModel):
    """Thanh toán on-chain cho portal — ba entry point mỏng, logic ở `payment.transaction`
    (`dms_blockchain_payment`). Không tham số số tiền, không tham số công ty."""
    _inherit = 'dms.portal.api'

    # ------------------------------------------------------------------ public

    @api.model
    def dms_portal_chain_payment_start(self, order_id, from_address):
        """POST /web/dataset/call_kw/dms.portal.api/dms_portal_chain_payment_start
           POST /json/2/dms.portal.api/dms_portal_chain_payment_start"""
        return self._dms_chain_start(self._dms_chain_order(order_id), from_address)

    @api.model
    def dms_portal_chain_payment_submit(self, reference, valid_until, signature):
        """POST /web/dataset/call_kw/dms.portal.api/dms_portal_chain_payment_submit
           POST /json/2/dms.portal.api/dms_portal_chain_payment_submit"""
        tx = self._dms_chain_tx(reference)
        tx._chain_submit(int(valid_until), str(signature))
        return tx._chain_status()

    @api.model
    def dms_portal_chain_payment_status(self, reference):
        """POST /web/dataset/call_kw/dms.portal.api/dms_portal_chain_payment_status
           POST /json/2/dms.portal.api/dms_portal_chain_payment_status"""
        return self._dms_chain_tx(reference)._chain_status()

    # ------------------------------------------------------------------ private

    @api.model
    def _dms_chain_order(self, order_id):
        order = self.env['sale.order'].sudo().browse(int(order_id)).exists()
        if not order or order.partner_id.id not in self.env.user.dms_allowed_partner_ids():
            raise AccessError(self.env._('No approved entitlement for this order.'))
        return order

    @api.model
    def _dms_chain_tx(self, reference):
        tx = self.env['payment.transaction'].sudo().search(
            [('reference', '=', str(reference)), ('provider_code', '=', 'chain')], limit=1)
        if not tx or tx.partner_id.id not in self.env.user.dms_allowed_partner_ids():
            raise AccessError(self.env._('No approved entitlement for this payment.'))
        return tx

    @api.model
    def _dms_chain_provider(self, company):
        return self.env['payment.provider'].sudo().search([
            ('code', '=', 'chain'), ('state', 'in', ('enabled', 'test')),
            ('company_id', '=', company.id)], limit=1)

    @api.model
    def _dms_chain_offered(self, order):
        """Cho template: có nút hay không. Không raise."""
        return bool(order.state == 'sale' and self._dms_chain_provider(order.company_id))

    @api.model
    def _dms_chain_due(self, order):
        invoices = order.invoice_ids.filtered(
            lambda m: m.move_type == 'out_invoice' and m.state == 'posted'
            and m.payment_state not in ('paid', 'in_payment', 'reversed'))
        if invoices:
            return invoices, sum(invoices.mapped('amount_residual'))
        return invoices, order.amount_total - order.amount_paid

    @api.model
    def _dms_chain_start(self, order, from_address):
        if order.state != 'sale':
            # sale._post_process would action_confirm a quotation on `done`, past the DMS
            # approval and credit gates (ruling R19).
            raise UserError(self.env._('Only a confirmed order can be paid on-chain.'))
        provider = self._dms_chain_provider(order.company_id)
        if not provider:
            raise UserError(self.env._('On-chain payment is not offered for this order.'))
        token = provider.chain_token_id
        if token.currency_id != order.currency_id:
            raise UserError(self.env._('This order is in %(o)s; the on-chain token settles in %(t)s.',
                                       o=order.currency_id.name, t=token.currency_id.name))
        try:
            payer = norm_address(from_address)
        except ValueError as exc:
            raise UserError(self.env._('That is not a wallet address.')) from exc
        invoices, due = self._dms_chain_due(order)
        if order.currency_id.compare_amounts(due, 0) <= 0:
            raise UserError(self.env._('Nothing left to pay on this order.'))

        Tx = self.env['payment.transaction'].sudo()
        tx = Tx.search([('provider_id', '=', provider.id), ('sale_order_ids', 'in', order.ids),
                        ('state', 'in', ('draft', 'pending'))], order='id desc', limit=1)
        if tx and tx.chain_request_id and tx.chain_request_id.payer_address != payer:
            req = tx.chain_request_id
            if req._live_job() or req.issued_valid_until + _SWITCH_GRACE > int(time.time()):
                raise UserError(self.env._(
                    'A payment from another wallet is still open for this order. Try again in a few minutes.'))
            req.request_state = 'expired'
            tx._set_canceled(state_message='payer switched wallet')
            tx = Tx
        if tx and order.currency_id.compare_amounts(tx.amount, due) != 0 \
                and not (tx.chain_request_id and tx.chain_request_id._live_job()):
            # Hoá đơn mới được post giữa hai lần bấm: số phải trả đổi ⇒ request mới.
            if tx.chain_request_id:
                tx.chain_request_id.request_state = 'expired'
            tx._set_canceled(state_message='amount due changed')
            tx = Tx
        if not tx:
            vals = {
                'provider_id': provider.id,
                'payment_method_id': provider.payment_method_ids[:1].id,
                'partner_id': order.partner_id.id,
                'amount': due,
                'currency_id': order.currency_id.id,
                'sale_order_ids': [(6, 0, order.ids)],
                'reference': Tx._compute_reference(provider.code, prefix=order.name),
            }
            if invoices:
                vals['invoice_ids'] = [(6, 0, invoices.ids)]
            tx = Tx.create(vals)
        typed = tx._chain_start(payer)
        chain = token.chain_id
        return {
            'reference': tx.reference,
            'amount': tx.amount,
            'currency': order.currency_id.name,
            'chain': {
                'chainId': chain.evm_chain_number,
                'chainIdHex': hex(chain.evm_chain_number),
                'name': chain.name,
                'rpcUrl': chain.public_rpc_url or False,
                'nativeCurrency': chain.native_currency or 'ETH',
                'tokenSymbol': token.symbol,
            },
            'typed_data': typed,
        }
```

`__init__.py`: `from . import models`; `models/__init__.py`: `from . import dms_portal_api`; `tests/__init__.py`: `from . import test_portal_chain_payment`. Temporarily set manifest `data: []` and drop `assets` until Task 3.

- [ ] **Step 4: Run to verify it passes** (same command as Step 2) → `0 failed, 0 error(s)`.
- [ ] **Step 5: Commit** `git add dms_blockchain_bridge && git commit -m "feat(portal): on-chain payment start/submit/status for confirmed DMS orders"`

---

### Task 2: End-to-end in Odoo — finalized event ⇒ `done` ⇒ `account.payment`; call_kw and `/json/2`

**Files:** Modify `dms_blockchain_bridge/tests/test_portal_chain_payment.py`.

- [ ] **Step 1: Tests** — append:

```python
@tagged('post_install', '-at_install')
class TestPortalChainSettlement(ChainPortalCase):

    def _paid(self, order):
        start = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        vu, sig, req = self._sign_start(start)
        self._api().dms_portal_chain_payment_submit(start['reference'], vu, sig)
        self._settle(req)
        tx = self.env['payment.transaction'].sudo().search([('reference', '=', start['reference'])])
        return tx, req

    def test_finalized_payment_marks_the_transaction_done(self):
        order = self._confirmed_order()
        tx, req = self._paid(order)
        self.assertEqual(req.request_state, 'final')
        self.assertEqual(tx.state, 'done')

    def test_post_processing_creates_the_payment_as_an_advance(self):
        order = self._confirmed_order()
        tx, _ = self._paid(order)
        tx._post_process()
        self.assertTrue(tx.payment_id)
        self.assertEqual(tx.payment_id.journal_id, self.chain_journal)
        self.assertEqual(tx.payment_id.amount, order.amount_total)

    def test_invoice_is_reconciled_when_one_exists(self):
        order = self._confirmed_order()
        invoice = order._create_invoices()
        invoice.action_post()
        tx, _ = self._paid(order)
        self.assertEqual(tx.invoice_ids, invoice)
        tx._post_process()
        self.assertIn(invoice.payment_state, ('paid', 'in_payment'))

    def test_partial_settlement_leaves_the_transaction_pending(self):
        order = self._confirmed_order()
        start = self._api().dms_portal_chain_payment_start(order.id, self.payer)
        vu, sig, req = self._sign_start(start)
        self._api().dms_portal_chain_payment_submit(start['reference'], vu, sig)
        self._settle(req, amount=str(int(req.amount_base) // 2))
        tx = self.env['payment.transaction'].sudo().search([('reference', '=', start['reference'])])
        self.assertEqual(tx.state, 'pending')
        self.assertEqual(req.request_state, 'partial')


@tagged('post_install', '-at_install')
class TestPortalChainRpc(ChainPortalCase, HttpCase):
    """CLAUDE.md §6: cùng method, hai đường — call_kw (cookie) và /json/2 (bearer)."""

    def setUp(self):
        super().setUp()
        self.buyer.write({'password': 'buyer-chain-pw'})
        self.order = self._confirmed_order()
        self.env.flush_all()

    def test_start_over_call_kw_with_a_portal_session(self):
        self.authenticate('buyer-16a@dms.test', 'buyer-chain-pw')
        res = self.url_open('/web/dataset/call_kw/dms.portal.api/dms_portal_chain_payment_start',
                            data=json.dumps({'jsonrpc': '2.0', 'method': 'call', 'id': 1, 'params': {
                                'model': 'dms.portal.api', 'method': 'dms_portal_chain_payment_start',
                                'args': [self.order.id, self.payer], 'kwargs': {}}}),
                            headers={'Content-Type': 'application/json'})
        body = res.json()
        self.assertNotIn('error', body, body)
        self.assertEqual(body['result']['chain']['chainId'], 9002)

    def test_status_over_json2_with_a_portal_api_key(self):
        start = self._api().dms_portal_chain_payment_start(self.order.id, self.payer)
        key = self.env['res.users.apikeys'].with_user(self.buyer).sudo()._generate(None, 'portal', None)
        self.env.flush_all()
        res = self.url_open('/json/2/dms.portal.api/dms_portal_chain_payment_status',
                            data=json.dumps({'reference': start['reference']}),
                            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json',
                                     'X-Odoo-Database': self.env.cr.dbname})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['reference'], start['reference'])
```

- [ ] **Step 2: Run** (Task 1 command) → `0 failed, 0 error(s)`. If `_create_invoices` needs delivered quantities (invoice policy `delivery`), set `self.product_a.invoice_policy = 'order'` in `setUp`.
- [ ] **Step 3: Commit** `git commit -m "test(portal): finalized chain payment drives done, advance payment and invoice reconciliation"`

---

### Task 3: Order page button + JS

**Files:** Create `dms_blockchain_bridge/views/portal_templates.xml`, `static/src/js/chain_pay.js`; Modify `__manifest__.py` (`data`, `assets`), tests (render check).

- [ ] **Step 1: Test** — append to `TestPortalChainRpc`:

```python
    def test_order_page_shows_the_button_only_when_offered(self):
        self.authenticate('buyer-16a@dms.test', 'buyer-chain-pw')
        body = self.url_open(f'/my/dms/order/{self.order.id}').text
        self.assertIn('data-dms-chain-pay', body)
        self.provider.write({'state': 'disabled'})
        self.env.flush_all()
        body = self.url_open(f'/my/dms/order/{self.order.id}').text
        self.assertNotIn('data-dms-chain-pay', body)
```

- [ ] **Step 2: Run** → FAIL (no button).

- [ ] **Step 3: Implement** `views/portal_templates.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <template id="portal_order_chain_pay" inherit_id="dms_portal.portal_order"
              name="DMS Portal Order: pay on-chain">
        <xpath expr="//div[hasclass('table-responsive')]" position="after">
            <t t-if="request.env['dms.portal.api']._dms_chain_offered(order)">
                <div class="mt-3" t-att-data-dms-chain-pay="order.id">
                    <button type="button" class="btn btn-primary js_dms_chain_pay">Pay on-chain</button>
                    <p class="text-muted small mt-2 js_dms_chain_status">
                        Signing is free: your wallet signs, we submit and pay the network fee.
                        The order shows as paid only after the payment is final on chain.
                    </p>
                </div>
            </t>
        </xpath>
    </template>
</odoo>
```

`static/src/js/chain_pay.js`:

```javascript
/* Pay a DMS order on-chain. No business logic: terms come from the server, the wallet
 * only signs them, and "paid" is only ever what the server reports after finality. */
(function () {
    "use strict";

    async function rpc(method, args) {
        const res = await fetch(`/web/dataset/call_kw/dms.portal.api/${method}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", method: "call", id: Date.now(),
                params: { model: "dms.portal.api", method, args, kwargs: {} } }),
        });
        const body = await res.json();
        if (body.error) {
            throw new Error((body.error.data && body.error.data.message) || body.error.message);
        }
        return body.result;
    }

    async function ensureChain(eth, chain) {
        try {
            await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chain.chainIdHex }] });
        } catch (err) {
            if (err && err.code === 4902 && chain.rpcUrl) {
                await eth.request({ method: "wallet_addEthereumChain", params: [{
                    chainId: chain.chainIdHex, chainName: chain.name, rpcUrls: [chain.rpcUrl],
                    nativeCurrency: { name: chain.nativeCurrency, symbol: chain.nativeCurrency, decimals: 18 },
                }] });
            } else {
                throw err;
            }
        }
    }

    async function pay(box) {
        const status = box.querySelector(".js_dms_chain_status");
        const say = (text) => { status.textContent = text; };
        const eth = window.ethereum;
        if (!eth) {
            say("No browser wallet found. Install one that supports EIP-712 signing.");
            return;
        }
        const [from] = await eth.request({ method: "eth_requestAccounts" });
        const start = await rpc("dms_portal_chain_payment_start", [Number(box.dataset.dmsChainPay), from]);
        await ensureChain(eth, start.chain);
        say(`Sign ${start.amount} ${start.currency} in your wallet…`);
        const signature = await eth.request({
            method: "eth_signTypedData_v4", params: [from, JSON.stringify(start.typed_data)] });
        const validUntil = Number(start.typed_data.message.validUntil);
        let st = await rpc("dms_portal_chain_payment_submit", [start.reference, validUntil, signature]);
        for (let i = 0; i < 120 && st.tx_state !== "done"; i++) {
            say(`Submitted (${st.job_state || st.request_state}). Waiting for finality…`);
            await new Promise((r) => setTimeout(r, 5000));
            st = await rpc("dms_portal_chain_payment_status", [start.reference]);
        }
        say(st.tx_state === "done" ? "Paid. Thank you." : "Still waiting for the chain; you can leave this page.");
    }

    document.addEventListener("click", (ev) => {
        const btn = ev.target.closest(".js_dms_chain_pay");
        if (!btn) {
            return;
        }
        const box = btn.closest("[data-dms-chain-pay]");
        btn.disabled = true;
        pay(box).catch((err) => {
            box.querySelector(".js_dms_chain_status").textContent = String(err.message || err);
        }).finally(() => { btn.disabled = false; });
    });
})();
```

Manifest: `data: ['views/portal_templates.xml']`, `assets` as in Task 1's manifest.

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git commit -m "feat(portal): pay-on-chain button and wallet signing script on the order page"`

---

### Task 4: Boundary — core installs without the blockchain addons

**Files:** none new; a run, recorded in the progress log.

- [ ] **Step 1:** `source /home/dockers/odoo19/.env && CHAIN_TEST_DB=dms_test_chain_b scripts/chain-odoo-test.sh bamboo_dms,dms_portal /dms_portal:TestAddonBoundary` (if that class exists in `dms_portal/tests/test_addon_boundary.py`; otherwise `/dms_portal`). Then `SELECT name FROM ir_module_module WHERE name LIKE 'dms_blockchain%' AND state='installed'` on that DB returns 0 rows — bridge did NOT auto-install.
- [ ] **Step 2:** Full run of all four modules together and record counts.

---

## Self-review

| Spec item | Task |
|---|---|
| §4.5 start (state, currency, amount source, reuse lane, wallet switch) | 1 |
| §4.5 submit (issued valid_until, ecrecover, outbox) / status | 1 (via payment Task 7) |
| §4.5 UI (button, JS, no logic) | 3 |
| §5 guarantee 1 (done only after final ingest) | 2 |
| §5 guarantee 2 (same lane on restart) | 1 |
| §5 guarantee 3 (server amount) | 1 `test_no_amount_parameter_anywhere`, `test_start_returns…` |
| §9 T1, T2, T5 | 1 |
| §10 call_kw + /json/2 | 2 |
| R19 quotation refused | 1 |
| Boundary (core installs alone) | 4 |
