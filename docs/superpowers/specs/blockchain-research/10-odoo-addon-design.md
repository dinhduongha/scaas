## 10. Thiet ke addon dms_blockchain: model, ACL, RPC, cau hinh

> **Ban 2 — da qua review doi khang.** Ban 1 dung duoc ve cau truc nhung sai o sau cho ky thuat va
> giau bay gia dinh o muoi hai cho. Tat ca deu duoc sua o duoi va liet ke lai o §10.14.
>
> Section nay la **canonical** ve: ten module, ten model, ten field, ACL, be mat RPC, cron, cau hinh.
> Section nay **khong** canonical ve: kinh te relayer (§05), nonce lease (§06), custody backend (§07),
> adapter interface (§08), danh sach 13 payment mode (§09), indexer/reorg (§11), ke toan (§15).
> Khi mot section khac dinh nghia lai mot model da co o day, section do sai va §10.3 liet ke cho phai sua.
>
> **Moi khang dinh ve API Odoo 19 trong section nay da duoc kiem tren source that o
> `/usr/lib/python3/dist-packages/odoo` cua container `odoo19-server-1`**, khong lay tu tri nho. Cho nao
> la uoc tinh deu ghi ro "uoc tinh" va co so tinh.

---

### 10.0. Nhung gia dinh an cua ban nhap, noi ro ra

Mot ban thiet ke chi dung duoc khi nguoi doc biet no dang gia dinh gi. Ban 1 gia dinh am muoi hai dieu.
Bay gio chung la rang buoc co ten, va moi cai deu co the sai:

| # | Gia dinh an | Con neu no khong dung |
|---|---|---|
| A1 | Moi dia chi la dia chi EVM (`0x` + 40 hex) | `size=42` + CHECK regex lam **khong the** luu dia chi TON/Sui/Soroban/Cosmos/Hedera. Locked #4 noi 5 he sinh thai kia duoc thiet ke tren giay **ngay bay gio**. Xem §10.4.3. |
| A2 | `fields.Char(size=N)` chan do dai o DB | **Sai.** Odoo 19: `size` la `deprecated`, cot van la `VARCHAR` khong gioi han, va `convert_to_cache` **cat am tham** `value[:size]`. Xem §10.4.0. |
| A3 | Odoo goi relay worker bang `requests` ngay trong method | Mot HTTP call trong transaction: transaction rollback nhung tx da broadcast. Day la lo that thoat tien lon nhat cua ban 1. Xem §10.4.11 (outbox). |
| A4 | Mot lane `(batchId, batchNonce)` chi duoc ghi mot lan | Metatx het han **khong** tieu ton nonce on-chain. Lan thu hai phai dung lai dung lane do, va `UNIQUE` chan. Xem §10.4.5. |
| A5 | Consumer nao cung dat `origin_key` khong dung nhau | `UNIQUE(company_id, origin_key)` bien mot va cham vo tinh giua hai consumer thanh mot payout bi nuot. Xem §10.4.8. |
| A6 | `env.companies` khong doc gi tu client | **Sai.** `/json/2` nhan `context` tu client va `Environment.companies` doc `allowed_company_ids` tu context. No **an toan** vi co check, nhung ly do an toan khac han ly do ban 1 viet. Xem §10.6.2. |
| A7 | `field.groups` lam cot bien mat khoi `read()` | Odoo 19: `read()` **khong** truyen `fields` thi loc; truyen ten field bi cam thi **raise `AccessError`**. Khac hanh vi Odoo <= 16. Xem §10.5.4. |
| A8 | `UserError` luon la HTTP 200 | Chi dung tren `call_kw`. Tren `/json/2` la **HTTP 422**. Xem §10.6.3. |
| A9 | `blockchain.chain` la du de biet contract nao o dau | Khong co model nao luu dia chi contract da deploy. `verifying_contract` la `Char` tu do, khong co gi de doi chieu, va Policy Gate allowlist khong co cho de song. Xem §10.4.9. |
| A10 | Ai vao duoc `group_blockchain_treasury` thi duoc chi bat ky so tien nao | Khong co nguong, khong co maker-checker, khong co dual approval cho R3/R4 ma chinh note yeu cau. Xem §10.4.10. |
| A11 | `mail.thread` tren settlement la mien phi | 5 chuyen trang thai x 10k settlement/thang = 50k `mail_message`. Xem §10.4.12. |
| A12 | Cron chay bang quyen cua nguoi bam nut | `ir.cron` chi cho `base.group_system` (kiem: `base/security/ir.model.access.csv` dong 5). `_toggle_crons()` **phai** `sudo()`. Xem §10.7. |

---

### 10.1. Ten module `dms_blockchain` cho mot addon khong depend `dms`

Van de la that: mot nguoi cai Odoo khong co DMS se thay mot module ten `dms_blockchain` trong Apps va ket luan
sai rang no can DMS. Nhung cai gia cua viec doi ten **sau khi deploy lan dau** khong nho:

| Phuong an | Chi phi doi ten sau deploy | Danh gia |
|---|---|---|
| **A. Giu `dms_blockchain`** (khuyen nghi) | 0 | `dms` doc nhu vendor prefix, dung nhu module chinh ten la `dms` chu khong phai `bamboo_dms`. Sua nhan thuc bang `'name'` + `'category'` trong manifest, khong bang thu muc. |
| B. Doi thanh `bamboo_chain` / `chain_settlement` | Phai lam **truoc** khi cai lan dau. Sau do can migration script rewrite `ir_module_module.name`, `ir_module_module_dependency.name`, va cot `module` cua **moi** dong `ir_model_data`. Doi ten `_name` model con keo theo rename bang PostgreSQL. | Chi lam neu quyet ngay hom nay. |
| C. Giu `dms_blockchain` + them shim module rong ten trung tinh | 2 module de bao tri, 1 trong so do khong lam gi | Khong. |

**Dinh luong chi phi cua B** (uoc tinh, co so: dem model/ACL/rule/view du kien cua chinh section nay):
~24 model x (1 dong `ir_model` + trung binh 22 dong `ir_model_fields`) = ~550 dong `ir_model_data`;
~50 dong ACL; ~18 record rule; ~45 view/action/menu; ~8 cron; ~24 bang PostgreSQL phai `ALTER TABLE ... RENAME`.
Tong ~700 dong `ir_model_data` phai UPDATE cot `module` **va** cot `name` (XML id chua ten module o vai cho),
cong 24 rename bang + moi index/constraint/sequence gan voi chung. Do la mot migration script vai tram dong
va mot cua so downtime — khong phai mot `git mv`.

**Chot: A.** Manifest lam ro pham vi bang metadata, khong bang ten thu muc:

```python
# dms_blockchain/__manifest__.py
{
    'name': 'Blockchain Settlement & Confidential Payments',
    'summary': 'Multi-chain settlement plane, EIP-1776 meta-transactions, Zether confidential balances.',
    'description': """
Standalone. Does NOT require the DMS application, the Accounting app, or the Payment module.
Install it on a bare Odoo and it stays inert until an administrator enables a chain.
""",
    'category': 'Accounting/Blockchain',
    'version': '19.0.1.0.0',
    'license': 'LGPL-3',
    'author': 'Bamboo',
    'depends': ['base', 'mail'],          # KHONG 'dms', KHONG 'account', KHONG 'payment'
    'external_dependencies': {},          # xem ghi chu duoi
    'application': True,
    'installable': True,
    'auto_install': False,
    'data': [
        'security/blockchain_groups.xml',
        'security/ir.model.access.csv',
        'security/blockchain_security.xml',
        'data/ir_sequence.xml',
        'data/blockchain_chain_data.xml',
        'data/ir_cron.xml',
        'views/blockchain_chain_views.xml',
        'views/blockchain_account_views.xml',
        'views/blockchain_settlement_views.xml',
        'views/blockchain_metatx_views.xml',
        'views/blockchain_relayer_views.xml',
        'views/blockchain_zether_views.xml',
        'views/res_config_settings_views.xml',
        'views/menu.xml',
    ],
    'demo': [],
    'post_init_hook': None,
    'uninstall_hook': '_uninstall_guard',   # §10.10.7
}
```

**`external_dependencies` la `{}` — sua so voi ban 1.** Ban 1 khai `eth_utils`. Nhung addon nay khong bao gio
mo socket toi chain tu HTTP worker (moi I/O RPC nam trong relay worker, §06/§08), va hai thu duy nhat can
`eth_utils` la keccak (de tinh EIP-712 digest) va checksum EIP-55. Ca hai deu thuoc ve worker, khong thuoc ve
Odoo. Doi lai, mot module khong cai duoc vi thieu wheel tren **mot** node trong cum la mot su co van hanh that,
va no xay ra luc `-u`, tuc luc dang co nguoi dung. Validate dia chi trong Odoo bang regex lowercase (§10.4.3);
validate checksum EIP-55 o worker, noi da co Python 3 day du.

`requests` co san trong core Odoo nen khong phai dependency moi — nhung xem §10.4.11: **khong goi `requests`
truc tiep trong method nghiep vu.**

**`application: True`** khien module hien trong tab Apps chu khong chi Extensions. Do la co y: no la mot ung
dung doc lap. He qua: no can mot `ir.module.category` va mot menu goc — ca hai co o `data/` va `views/menu.xml`.

---

### 10.2. Topology: bon addon Odoo, mot service ngoai Odoo, mot cay contract

```
custom-addons/bamboo-dms/
├── dms_blockchain/            # CORE.   depends: base, mail                    auto_install: False
├── dms_blockchain_payment/    # BRIDGE. depends: dms_blockchain, payment       auto_install: False
├── dms_blockchain_account/    # BRIDGE. depends: dms_blockchain, account       auto_install: False
└── dms_blockchain_bridge/     # BRIDGE. depends: dms_blockchain, dms           auto_install: True

/home/dockers/odoo19/relay-pool/            # service rieng (§06, §08). KHONG phai addon.
/home/dockers/odoo19/confidential-signer/   # service rieng (§07). KHONG phai addon.
smartcontracts/                             # ngoai addon, goc repo (§01.14, §14)
```

| Module | Chua gi | Vi sao tach |
|---|---|---|
| `dms_blockchain` | Chain, endpoint, contract deployment, account, custody, token, metatx, relayer registry, transaction, event, **Zether**, **settlement layer**, outbox, approval policy, ACL, cron, config | Chay duoc mot minh, khong co `account` lan `payment` lan `dms` |
| `dms_blockchain_payment` | `payment.provider` `selection_add=[('chain', 'On-chain')]`, `payment.transaction` mapping, webhook acquirer | Chi can khi money-flow chon handler thuoc ho `payment.*` (§09) |
| `dms_blockchain_account` | Sinh `account.move` / `account.payment` tu `blockchain.settlement`, reconciliation run (§15.4-15.5) | Chi can khi money-flow chon handler co ke toan |
| `dms_blockchain_bridge` | `_inherit` mixin `blockchain.settlement.origin` len `dms.trade.settlement.line`, `dms.payment.collection`, `dms.trade.claim` | Cau duy nhat biet ten model `dms.*` |

**Zether nam trong core, khong tach module.** Ly do: `blockchain.settlement.zether_entry_id` la mot Many2one
tu core. Neu Zether o module rieng thi core phai dung `Reference` cho no, va toan bo bao cao doi soat phai
xu ly hai duong. Chi phi giu Zether trong core khi khong dung: 3 bang rong + 2 cron `active=False`. Re hon.

**`auto_install` cua bridge — kiem tren source.** `odoo/modules/module.py:445-458`:

```python
if isinstance(manifest['auto_install'], Iterable):
    manifest['auto_install'] = auto_install_set = set(manifest['auto_install'])
    non_dependencies = auto_install_set.difference(depends)
    assert not non_dependencies, "auto_install triggers must be dependencies, ..."
elif manifest['auto_install']:
    manifest['auto_install'] = set(depends)
```

Nghia la:

- `auto_install = True` → trigger set = **toan bo** `depends`. Module tu cai khi **ca hai** `dms_blockchain`
  va `dms` da `installed`. Day la dieu ta muon.
- `auto_install = ['dms']` → trigger set chi co `dms`. Cai `dms` mot minh se **keo `dms_blockchain` vao theo**
  nhu mot dependency. Day **khong** phai dieu ta muon, va la loi de mac.

```python
# dms_blockchain_bridge/__manifest__.py
{'name': 'DMS <-> Blockchain Bridge',
 'summary': 'Wires DMS trade settlement, collection and claim flows into the blockchain settlement layer.',
 'category': 'Accounting/Blockchain',
 'version': '19.0.1.0.0',
 'license': 'LGPL-3',
 'depends': ['dms_blockchain', 'dms'],
 'auto_install': True,            # = set(depends), KHONG viet ['dms']
 'installable': True,
 'data': ['security/ir.model.access.csv', 'views/dms_bridge_views.xml']}
```

He qua can biet truoc, khong phai bat ngo:

- Cai `dms` mot minh → bridge **khong** duoc cai. Dung.
- Cai `dms_blockchain` mot minh → bridge **khong** duoc cai. Dung.
- Cai ca hai → bridge tu cai **ngay trong cung transaction**, ke ca khi nguoi dung khong biet no ton tai.
- Muon chan tam thoi tren mot instance: `ir.module.module._button_immediate_install` doc
  `config.get('skip_auto_install')` (`base/models/ir_module.py:431`). Do la mot **config key cua server**,
  khong phai flag CLI chinh thuc — dat trong `odoo.conf` khi can mot cua so bao tri, khong dung lau dai.
- **Go `dms`** → Odoo go luon bridge (cascade). Core va toan bo du lieu settlement song sot. Day la ly do
  settlement layer phai o core chu khong o bridge.

`dms_blockchain_payment` va `dms_blockchain_account` **khong** `auto_install`: chung hien thuc hoa mot lua chon
chinh sach (§10.8/§09), khong phai mot su that ky thuat. Tu cai chung khi ai do tinh co cai `account` la sai.

**Cay thu muc core** (de ke hoach trien khai co cho de dat file):

```
dms_blockchain/
├── __init__.py  __manifest__.py
├── models/
│   ├── __init__.py
│   ├── blockchain_chain.py            blockchain_rpc_endpoint.py
│   ├── blockchain_contract.py         # deployment registry + ABI ref (§10.4.9)
│   ├── blockchain_account.py          blockchain_custody.py
│   ├── blockchain_token.py
│   ├── blockchain_metatx.py           blockchain_relayer.py
│   ├── blockchain_transaction.py      blockchain_event.py
│   ├── blockchain_zether.py
│   ├── blockchain_settlement.py       blockchain_settlement_origin.py
│   ├── blockchain_money_flow.py       blockchain_payment_handler.py   # §09 interface, impl rong
│   ├── blockchain_approval.py         blockchain_security_event.py
│   ├── blockchain_outbox.py
│   └── res_config_settings.py
├── security/  data/  views/  wizard/
├── tests/
│   ├── test_standalone_install.py     test_idempotency.py
│   ├── test_finality_gate.py          test_acl_matrix.py
│   └── test_sql_objects.py            # doc pg_constraint / pg_indexes, khong doc code
└── static/description/
```

---

### 10.3. Prefix model `blockchain.*` va so dang ky model canonical

`blockchain.*`, khong phai `dms.blockchain.*`. Ly do khong phai tham my: `dms.` la mot loi noi doi ve pham vi
tren mot module tu bo `depends dms`, va no se lam nguoi doc di tim model cha khong ton tai.

**So dang ky day du.** Moi model `blockchain.*` trong toan bo he thong, ai so huu dinh nghia, o dau:

| Model | Dinh nghia o | Module | company_id | Ghi chu |
|---|---|---|---|---|
| `blockchain.chain` | §10.4.2 | core | khong (`company_ids` M2M) | §08.1 phai doi theo bang nay |
| `blockchain.rpc.endpoint` | §10.4.2b | core | khong | |
| `blockchain.contract.deployment` | §10.4.9 | core | khong | **moi**, ban 1 thieu |
| `blockchain.contract.abi` | §11.6 | core | khong | |
| `blockchain.account` | §10.4.3 | core | **co** | |
| `blockchain.relayer.account` | §06.9 + §10.4.3 | core | qua `_inherits` | `_inherits` `blockchain.account` |
| `blockchain.custody.provider` | §07.12 | core | **co** | |
| `blockchain.custody.key` | §07.12 | core | related | |
| `blockchain.key.ceremony` | §07.8 | core | **co** | |
| `blockchain.token` | §01.13 | core | khong (`company_ids`) | |
| `blockchain.metatx` | §10.4.5 | core | khong (suy tu settlement) | |
| `blockchain.relayer` | §10.4.5 | core | **co** khi `kind='internal'` | |
| `blockchain.relayer.address` | §10.4.5 | core | khong | |
| `blockchain.transaction` | §10.4.6 | core | khong | |
| `blockchain.event` | §10.4.6 | core | khong | |
| `blockchain.index.cursor` | §11.2 | core | khong | |
| `blockchain.watched.address` | §11.8 | core | **co** | |
| `blockchain.zether.account` | §02.8.5 | core | **co** | |
| `blockchain.zether.account.chain` | §02.8.5 | core | qua parent | doi `profile_id` → `chain_id` |
| `blockchain.zether.entry` | §10.4.7 | core | **co** | |
| `blockchain.settlement` | §10.4.8 | core | **co** | canonical |
| `blockchain.settlement.batch` | §15.7 | core | **co** | |
| `blockchain.netting.set` | §15.6 | core | **co** | |
| `blockchain.settlement.origin` | §15.3 | core | AbstractModel | mixin, khong co bang |
| `blockchain.money.flow` | §09.4 | core | **co** (nullable = default) | |
| `blockchain.payment.handler` | §09.4 | core | AbstractModel | interface |
| `blockchain.payment.handler.none` | §09.4 | core | AbstractModel | impl rong, mac dinh |
| `blockchain.payment.request` | §09.6 | core | **co** | |
| `blockchain.approval.policy` | §10.4.10 | core | **co** | **moi** |
| `blockchain.approval.request` | §10.4.10 | core | **co** | **moi** |
| `blockchain.security.event` | §10.4.11 | core | **co** | **moi**, §07.13 da tham chieu |
| `blockchain.outbox.job` | §10.4.11 | core | **co** | **moi**, ban 1 thieu |
| `blockchain.reconciliation.run` / `.line` | §15.5 | `_account` | **co** | |
| `blockchain.audit.disclosure` | §13 | core | **co** | |
| `blockchain.travel.rule.message` | §13 | core | **co** | |
| `blockchain.upgrade.proposal` | §01 | core | khong | |

**Cho phai sua trong cac section da viet:**

| Nguon | Dang sai / lech | Chot |
|---|---|---|
| §02.8.5 | `blockchain.chain.profile` la mot model rieng, voi `evm_chain_id`, `is_private`, `finality_depth`… | **Xoa model do.** Cac field do la field tren `blockchain.chain` (§10.4.2). `blockchain.zether.account.chain.profile_id` → `chain_id = Many2one('blockchain.chain')`; constraint doi thanh `UNIQUE(account_id, chain_id)`. Ban 1 quy loi nay cho "01 §1.13" — **sai dia chi**, §01 da tro ve §10.4.2 tu dong 40. |
| §08.1 | `chain_family` dung, nhung `fee_token_mode`, `native_is_stable`, `finality_depth`, `state` gia tri `live/paused/retired` | Doi theo §10.4.2: `fee_mode` (5 gia tri), bo `native_is_stable` (da nam trong `fee_mode='native_stable'`), `state` gia tri `draft/enabled/degraded/halted/retired`. |
| §10 ban 1 | `chain_profile` co **ba** gia tri (`private`/`consortium`/`public`) | **Hai gia tri.** §05 va §08 viet `if chain.chain_profile == 'public'` o hang chuc cho. Them mot gia tri thu ba khien `consortium` roi vao nhanh `private` mot cach **im lang** — khong dong nao viet `!= 'private'`. Neu can phan biet consortium, dung mot field rieng `governance_model`, khong nhet vao truc nay. |
| §06.9 | `blockchain.relayer.account` la bang doc lap | Thanh `_inherits = {'blockchain.account': 'account_id'}` (§10.4.3). Giu nguyen ten cac field pool. |
| §05 ban 1 | prefix `dms.blockchain.*` | Da sua o ban 2 cua §05. Khong con no. |
| §02 §2.5.5 | ghi ket qua probe vao `blockchain.chain.profile.has_bls12381` | → `blockchain.chain.has_bls12381` |
| §02 §2.7 | `blockchain.chain.profile.compliance_freeze_enabled` | → `blockchain.chain.compliance_freeze_enabled` |

---

### 10.4. Data model

#### 10.4.0. Bon su that ve cot PostgreSQL cua Odoo 19, da kiem tren source

Bon dieu nay quyet dinh gan het cac lua chon kieu du lieu ben duoi. Ba trong so do trai voi truc giac.

**(1) `fields.Char(size=N)` la `deprecated` va cat chuoi trong im lang.**
`odoo/orm/fields_textual.py`: `size = None  # maximum size of values (deprecated)`, va

```python
def convert_to_cache(self, value, record, validate=True):
    ...
    value = s[:self.size]      # <-- CAT, khong raise
```

Cot sinh ra la `VARCHAR` **khong** co do dai (`column_type == ('varchar', 'VARCHAR')` — kiem bang
`fields.Char(size=42).column_type`). Vay `size=42` khong bao ve gi o DB va **pha du lieu** o Python:
ghi mot dia chi Sui 66 ky tu vao `Char(size=42)` cho ra 42 ky tu dau, khong loi, khong log.
**Quy uoc toan addon: khong dung `size=` o bat ky dau.** Do dai duoc ep bang `models.Constraint` CHECK.

**(2) `fields.Float(digits=(p, s))` sinh cot `numeric` nhung Python van la `float` C.**
`odoo/orm/fields_numeric.py:126-133`: `_column_type` tra `('numeric','numeric')` khi `_digits is not None`,
nguoc lai `('float8','double precision')`. Nhung `numeric` o day la `numeric` **khong tham so** — `(24, 8)`
chi dieu khien lam tron khi ghi (`float_round`) va hien thi. Gia tri trong Python la IEEE754 double →
mat chinh xac tu ~15-16 chu so co nghia. Mot so du 18 decimals co 20+ chu so. **Ket luan: khong bao gio
doi soat tren mot `Float`.** `Monetary` luon la `numeric` (`_column_type = ('numeric','numeric')`).

**(3) Odoo 19 co `models.Index` va `models.UniqueIndex`, khong chi `models.Constraint`.**
`odoo/orm/table_objects.py:125,185`. Dieu nay giai quyet dut diem van de partial unique index ma
`_sql_constraints` va `models.Constraint` khong lam duoc:

```python
_one_open_lane = models.UniqueIndex(
    "(chain_id, from_account_id, batch_id_hex, batch_nonce) "
    "WHERE metatx_state NOT IN ('expired', 'failed', 'final')",
    'Lane (batchId, batchNonce) dang co mot metatx chua ket thuc.')
```

Ten thuoc tinh **phai** bat dau bang `_` (assert trong `TableObject.__set_name__`), va ten SQL that se la
`{table}_{name}` — o vi du tren la `blockchain_metatx_one_open_lane`.

**(4) `models.Constraint` tu drop va tao lai khi definition doi**, so sanh bang
`sql.constraint_definition()`. Nghia la doi noi dung CHECK giua hai lan `-u` se chay `DROP CONSTRAINT` roi
`ADD CONSTRAINT` — va `ADD` **fail** neu du lieu cu vi pham. Do la hanh vi dung, nhung phai luong truoc:
moi lan siet CHECK deu can mot migration script don du lieu **truoc**.

Kiem chung bat buoc, khong tin code:

```sql
SELECT conname, contype, pg_get_constraintdef(oid)
FROM pg_constraint WHERE conrelid::regclass::text LIKE 'blockchain\_%';
SELECT indexname, indexdef FROM pg_indexes WHERE tablename LIKE 'blockchain\_%';
```

#### 10.4.1. uint256 khong vua vao bat ky field so nao cua Odoo

`fields.Integer` la `int4` (`_column_type = ('int4','int4')`). `fields.Float` la double (xem 10.4.0(2)).
Mot so du token 18 decimals vuot ca hai: `2^256 - 1 ≈ 1.16e77`, con `int4` het o 2.1e9 va double het chinh xac
o 9.0e15. Quy uoc **bat buoc** tren toan addon:

```python
# Gia tri chinh tac: chuoi thap phan base units. KHONG dau, KHONG 0x, KHONG dau phay.
amount_base = fields.Char(required=True, default='0', help='uint256 decimal string, base units.')

# Gia tri de doc/bao cao. CHI de hien thi va group by. KHONG duoc doi soat tren no.
amount_display = fields.Float(digits=(38, 18), compute='_compute_amount_display',
                              store=True, readonly=True)

_check_amount_base = models.Constraint(
    "CHECK (amount_base ~ '^(0|[1-9][0-9]{0,77})$')",
    'amount_base phai la chuoi thap phan uint256 khong co so 0 dan dau.')
```

Ba chi tiet co chu dich:

1. Regex chan **so 0 dan dau**. Neu khong, `'007'` va `'7'` la hai chuoi khac nhau cho cung mot so, va
   moi `UNIQUE`/`GROUP BY`/dedup tren field dan xuat deu sai. Chuan hoa o `create`/`write`, ep o DB.
2. `digits=(38, 18)` chu khong `(24, 8)`: 8 chu so thap phan lam **1 wei bien mat** tren token 18 decimals.
   `(38, 18)` khong cuu duoc gioi han double (muc 10.4.0(2)) nhung it nhat khong lam tron o tang lam tron.
3. `readonly=True` tren stored compute: chan mot dev tuong lai `write()` thang vao no.

**Stored computed field khong duoc nhan `default`, va moi nhanh phai gan gia tri.** Mau bat buoc:

```python
@api.depends('amount_base', 'token_id.token_decimals')
def _compute_amount_display(self):
    for rec in self:
        rec.amount_display = 0.0                       # DONG DAU TIEN. Truoc moi nhanh.
        if not rec.amount_base or not rec.token_id:
            continue
        rec.amount_display = int(rec.amount_base) / (10 ** (rec.token_id.token_decimals or 0))
```

Ap dung y het cho `fee_native_display` (§10.4.6), `reputation_score` (§10.4.5), `runway_hours` (§06.9),
`net_wei` (§05), `is_final` (§11), `divergent` (§02).

Hex thi luon `Char` **khong** `size`, luon `0x` prefix, luon lowercase, luon co index khi duoc tra cuu.
Do dai ep bang CHECK, khong bang `size`:

| Field | Do dai | CHECK |
|---|---|---|
| dia chi EVM | 42 | `~ '^0x[0-9a-f]{40}$'` |
| `tx_hash` EVM / `digest_hash` / `batch_id_hex` / `schnorr_address` | 66 | `~ '^0x[0-9a-f]{64}$'` |
| `signature_hex` (ECDSA) | 132 | `~ '^0x[0-9a-f]{130}$'` |
| `calldata_hex` | thay doi | `~ '^0x([0-9a-f]{2})*$'` |

#### 10.4.2. Chain va endpoint

```python
class BlockchainChain(models.Model):
    _name = 'blockchain.chain'
    _description = 'Blockchain network'
    _inherit = ['mail.thread']
    _order = 'sequence, id'

    sequence         = fields.Integer(default=10)      # BAT BUOC: _order tham chieu no (ban 1 thieu)
    name             = fields.Char(required=True)
    code             = fields.Char(required=True, index=True)   # 'gnosis', 'celo', 'besu-priv-01'
    caip2            = fields.Char(required=True, index=True)   # 'eip155:100'
    chain_family     = fields.Selection([('evm','EVM'), ('hedera','Hedera'), ('ton','TON'),
                                         ('sui','Sui'), ('soroban','Soroban'), ('cosmwasm','CosmWasm')],
                                        required=True, default='evm', index=True)
    chain_profile    = fields.Selection([('private','Private / Permissioned'), ('public','Public')],
                                        required=True, default='private', index=True, tracking=True)
    evm_chain_number = fields.Integer(help='EIP-155 chainId. 0 khi chain_family != evm.')
    is_testnet       = fields.Boolean(default=False)
    native_symbol    = fields.Char(required=True)
    native_decimals  = fields.Integer(required=True, default=18)
    fee_mode         = fields.Selection([('native','Native coin'),
                                         ('native_stable','Native coin la stablecoin (xDAI)'),
                                         ('fee_currency','ERC-20 fee currency (Celo CIP-52)'),
                                         ('sponsored','Sponsored / feegrant / fee-bump'),
                                         ('gasless','Gas price = 0 (private)')],
                                        required=True, default='native')
    block_time_ms        = fields.Integer(required=True, default=5000)
    finality_mode        = fields.Selection([('bft_instant','BFT instant'), ('depth','Block depth'),
                                             ('checkpoint','Checkpoint / epoch'),
                                             ('l1_batch','L2 with L1 batch')],
                                            required=True, default='depth')
    finality_soft_blocks   = fields.Integer(required=True, default=1)
    finality_soft_seconds  = fields.Integer(required=True, default=5)
    finality_hard_blocks   = fields.Integer(required=True, default=0)
    finality_hard_seconds  = fields.Integer(required=True, default=0)
    reorg_watch_blocks     = fields.Integer(required=True, default=0,
                                            help='So block van theo doi sau final de phat hien reorg (§11.4).')
    has_bls12381         = fields.Boolean(default=False, readonly=True,
                                          help='Ghi boi probe on-chain (§02.5.5). KHONG nhap tay.')
    compliance_freeze_enabled = fields.Boolean(default=False)   # §02.7, mac dinh tat tren public
    max_calldata_bytes   = fields.Integer(default=0, help='0 = khong gioi han rieng.')
    block_gas_limit      = fields.Integer()
    explorer_base_url    = fields.Char()
    relay_worker_ref     = fields.Char(required=True,
        help='Khoa ir.config_parameter chua base URL cua relay worker. KHONG phai URL.')
    capability_json  = fields.Json(help='Metadata nho do adapter bao cao. KHONG phai file, KHONG phai anh.')
    state            = fields.Selection([('draft','Draft'), ('enabled','Enabled'),
                                         ('degraded','Degraded'), ('halted','Halted'),
                                         ('retired','Retired')],
                                        required=True, default='draft', index=True, tracking=True)
    company_ids      = fields.Many2many('res.company', string='Available to companies')

    _unique_caip2 = models.Constraint('UNIQUE(caip2)', 'CAIP-2 phai duy nhat.')
    _unique_code  = models.Constraint('UNIQUE(code)',  'Chain code phai duy nhat.')
    _check_evm_number = models.Constraint(
        "CHECK (chain_family <> 'evm' OR evm_chain_number > 0)",
        'Chain EVM phai co evm_chain_number.')
    _check_finality = models.Constraint(
        'CHECK (finality_hard_blocks >= finality_soft_blocks)',
        'Nguong hard khong duoc thap hon soft.')
```

`blockchain.chain` la **ha tang dung chung, khong co `company_id`**. Kha dung theo cong ty dieu khien bang
`company_ids` (rong = moi cong ty). Cai gi giu tien moi co `company_id` (§10.9).

**Vi sao tach `soft` va `hard` thanh ca block lan giay.** Khong chuoi nao dien dat duoc bang mot chieu:
Ethereum finality la 2 epoch = 64 slot (**block**), Polygon PoS la Heimdall checkpoint (**thoi gian**, ~25-30
phut, khong co so block co dinh), Arbitrum soft la sequencer (1 giay) con hard la L1 batch (~15 phut).
Finality Gate lay `max()` cua hai dieu kien (§10.4.8 `_set_finality`).

**Bang chuan cho `data/blockchain_chain_data.xml`** (uoc tinh cho thang 08/2026; xac nhan lai khi deploy):

| code | caip2 | family | profile | fee_mode | block_time_ms | finality_mode | soft_blocks | hard_blocks | hard_seconds |
|---|---|---|---|---|---|---|---|---|---|
| `gnosis` | `eip155:100` | evm | public | `native_stable` | 5000 | `checkpoint` | 1 | 64 | 780 |
| `celo` | `eip155:42220` | evm | public | `fee_currency` | 1000 | `l1_batch` | 1 | 0 | **can xac nhan** |
| `besu-priv-01` | `eip155:1337001` | evm | private | `gasless` | 2000 | `bft_instant` | 1 | 1 | 0 |

**Celo: con so trong `blockchain.md` da loi thoi.** Note ghi "Istanbul BFT 2.0, 5 giay, immediate finality".
Celo da chuyen thanh **Ethereum L2 tren OP Stack (2025)**: block time ~1 giay, va finality khong con la BFT
tuc thoi cua validator set rieng ma phu thuoc L1. Nap `celo` voi `state='draft'` va **bat buoc do lai**
`finality_hard_seconds` tren mainnet truoc khi `enabled`. §11.12 da neu diem nay; §10 khong duoc chep lai
con so cu. Gnosis hard finality 780 giay = 2 epoch x 16 slot x 5 giay + bien (uoc tinh; Gnosis dung 16 slot/epoch,
5 giay/slot → 1 epoch = 80 giay, 2 epoch ~ 160 giay danh dau finalized, cong bien an toan cho reorg dai
→ chot 780 giay chi khi khong do duoc; **do that truoc khi enable**).

**`blockchain.rpc.endpoint`:**

```python
class BlockchainRpcEndpoint(models.Model):
    _name = 'blockchain.rpc.endpoint'
    _description = 'RPC endpoint for a chain'
    _order = 'chain_id, priority, id'

    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    name         = fields.Char(required=True)
    endpoint_ref = fields.Char(required=True,
        help='Khoa ir.config_parameter chua URL. KHONG BAO GIO la URL co API key.')
    kind         = fields.Selection([('http','HTTP JSON-RPC'), ('ws','WebSocket'),
                                     ('archive','Archive'), ('indexer','Indexer / mirror')],
                                    required=True, default='http')
    priority     = fields.Integer(required=True, default=10)
    latency_ms   = fields.Integer(readonly=True)
    health_state = fields.Selection([('unknown','Unknown'), ('ok','OK'),
                                     ('slow','Slow'), ('diverging','Diverging'), ('down','Down')],
                                    required=True, default='unknown', index=True)
    last_probe_datetime = fields.Datetime(readonly=True)      # KHONG dat ten 'datetime'
    divergence_count    = fields.Integer(default=0, readonly=True)
    head_block          = fields.Integer(readonly=True)

    _unique_ref = models.Constraint('UNIQUE(chain_id, endpoint_ref)', 'Endpoint bi khai bao hai lan.')
```

`diverging` la trang thai rieng, khong gop vao `down`: mot RPC **tra loi nhanh va sai** nguy hiem hon mot RPC
chet (§06.7). Endpoint `diverging` bi loai khoi vong quay ngay nhung **khong** duoc tu hoi phuc; can nguoi.

#### 10.4.2b. Vi sao khong co `blockchain.chain.company` ma la M2M

Mot ban ghi trung gian se can ACL rieng, view rieng, va mot vong doi rieng ma khong ai muon quan ly.
`company_ids` M2M rong nghia la "moi cong ty" — mot quy uoc, khong phai mot cot NULL nhap nhang. Ep trong
`_enabled_chains()`:

```python
def _enabled_chains(self, company=None):
    company = company or self.env.company
    return self.env['blockchain.chain'].search([
        ('state', '=', 'enabled'),
        '|', ('company_ids', '=', False), ('company_ids', 'in', company.id),
    ])
```

#### 10.4.3. Account / wallet va custody

Mot bang duy nhat cho moi vi. `blockchain.relayer.account` cua §06 tro thanh **delegation** cua no thay vi mot
bang song song (`_inherits` la co che san cua Odoo, mot dong, khong phai mot abstraction tu che):

```python
class BlockchainAccount(models.Model):
    _name = 'blockchain.account'
    _description = 'On-chain account (EOA, contract, smart account)'
    _rec_name = 'address'

    chain_id      = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    chain_family  = fields.Selection(related='chain_id.chain_family', store=True, index=True)
    address       = fields.Char(required=True, index=True)      # KHONG size=. Xem 10.4.0(1).
    address_label = fields.Char()
    account_kind  = fields.Selection([('eoa','EOA'), ('contract','Contract'),
                                      ('smart_account','Smart account / passkey'),
                                      ('multisig','Multisig')], required=True, default='eoa')
    role          = fields.Selection([('user','End user'), ('relay','Relayer'), ('treasury','Treasury'),
                                      ('issuer','Token issuer'), ('admin','Contract admin')],
                                     required=True, default='user', index=True)
    custody_key_id = fields.Many2one('blockchain.custody.key', index=True, ondelete='restrict')
    custody_mode  = fields.Selection(related='custody_key_id.provider_id.kind', store=True)
    signer_ref    = fields.Char(
        groups='dms_blockchain.group_blockchain_manager',
        help='Key handle / KMS ARN / MPC vault id. KHONG BAO GIO la khoa.')
    partner_id    = fields.Many2one('res.partner', index=True, ondelete='restrict')  # 'base', khong tao dep.
    user_id       = fields.Many2one('res.users', index=True, ondelete='set null')
    origin_model  = fields.Char(index=True)                     # seam sang dms.*, xem §15.3
    origin_id     = fields.Many2oneReference(model_field='origin_model', index=True)
    company_id    = fields.Many2one('res.company', required=True, index=True,
                                    default=lambda s: s.env.company)
    proof_of_control = fields.Selection([('none','Chua chung minh'), ('signature','Chu ky'),
                                         ('microtx','Micro-transaction'), ('deployed_by_us','Ta deploy')],
                                        required=True, default='none', index=True)
    bind_datetime = fields.Datetime(readonly=True)
    state         = fields.Selection([('draft','Draft'), ('active','Active'), ('frozen','Frozen'),
                                      ('retired','Retired')], required=True, default='draft', index=True)

    _unique_addr_per_chain = models.Constraint(
        'UNIQUE(chain_id, address)', 'Mot dia chi chi duoc khai bao mot lan tren mot chain.')
    _check_addr_shape = models.Constraint(
        "CHECK (address = lower(address) AND length(address) BETWEEN 20 AND 128)",
        'Address phai lowercase va co do dai hop le.')
    _check_evm_addr = models.Constraint(
        "CHECK (chain_family <> 'evm' OR address ~ '^0x[0-9a-f]{40}$')",
        'Dia chi EVM phai la 0x + 40 hex lowercase.')
```

**Sua so voi ban 1: `size=42` va CHECK `^0x[0-9a-f]{40}$` vo dieu kien deu sai.** Locked #4 dat 5 he sinh thai
non-EVM vao thiet ke ngay bay gio. Do dai va bang chu cai dia chi cua chung khac nhau hoan toan:

| Family | Dang dia chi | Do dai | Bang chu cai |
|---|---|---|---|
| EVM | `0x` + 40 hex | 42 | hex |
| Hedera | `0.0.<num>` (hoac EVM alias 42) | 7-20 | so + dau cham |
| TON | user-friendly base64url | 48 | base64url |
| Sui | `0x` + 64 hex | 66 | hex |
| Soroban / Stellar | `G…` / `C…` StrKey base32 | 56 | base32 |
| CosmWasm | bech32 `<hrp>1…` | 39-90 | bech32 |

`lower(address)` la sai voi Stellar StrKey (uppercase base32) va voi bech32 co checksum phan biet hoa thuong.
Ket luan trung thuc: **khong co mot CHECK nao dung cho ca sau ho.** Chot hai tang:

1. **DB**: mot CHECK tho dung cho moi ho (`length BETWEEN 20 AND 128`) + mot CHECK **co dieu kien theo
   `chain_family`** cho tung ho, them dan khi ho do duoc build. `chain_family` la related **stored** nen no
   la mot cot that va CHECK dung duoc.
2. **Python**: `@api.constrains('address', 'chain_id')` goi
   `self.env['blockchain.chain']._adapter(rec.chain_id).validate_address(rec.address)` — adapter la ho
   interface cua §08, khong phai code moi. Cai nay bat checksum EIP-55, bech32 checksum, StrKey CRC16.
   Adapter khong ton tai (ho chua build) → constrain bo qua, khong raise.

Bo `custody_mode` lam Selection tu do (ban 1) va lam `related` toi `blockchain.custody.key.provider_id.kind`
(§07.12): mot chuoi tu do o day va mot chuoi tu do o §07 la hai nguon su that cho cung mot su that.

**`signer_ref` bao ve bang `groups=` ngay trong dinh nghia field, khong bang record rule.** Record rule loc
**dong**, khong loc **cot**. Xem §10.5.4 cho hanh vi chinh xac.

**`blockchain.relayer.account` la delegation:**

```python
class BlockchainRelayerAccount(models.Model):
    _name = 'blockchain.relayer.account'
    _description = 'Relayer EOA in the internal relay pool'
    _inherits = {'blockchain.account': 'account_id'}

    account_id = fields.Many2one('blockchain.account', required=True,
                                 ondelete='cascade', index=True, auto_join=True)
    pool_state = fields.Selection([('active','Active'), ('draining','Draining'),
                                   ('paused','Paused'), ('quarantined','Quarantined')],
                                  required=True, default='paused', index=True)
    max_inflight       = fields.Integer(required=True, default=16)
    pinned_endpoint_id = fields.Many2one('blockchain.rpc.endpoint')
    nonce_confirmed    = fields.Integer(readonly=True)     # mirror tu Redis, cho UI/audit
    nonce_allocated    = fields.Integer(readonly=True)
    balance_native_base = fields.Char(readonly=True, default='0')   # uint256, khong Float
    balance_sync_datetime = fields.Datetime(readonly=True)
    burn_rate_native_per_hour = fields.Float(digits=(38, 18), readonly=True)
    runway_hours       = fields.Float(compute='_compute_runway_hours', store=True, readonly=True)
```

Ba he qua cua `_inherits` phai biet truoc, khong phai phat hien luc production:

1. `create()` tren child **tao ban ghi parent**; `unlink()` tren child **xoa parent** (`ondelete='cascade'`).
   Do la ly do `perm_unlink=0` tren ca hai (§10.5.3).
2. Field `state` cua parent bi field `pool_state` cua child **khong** dung ten — co y. Neu dat trung ten,
   child che parent va `blockchain.account.state` khong con truy cap duoc tu child.
3. **Field-level `groups` di theo qua delegation.** `odoo/orm/fields.py:777`:
   `_related_groups = property(attrgetter('groups'))` — field ke thua lay `groups` tu field goc khi khong
   khai bao rieng. Vay `signer_ref` van bi chan khi doc qua `blockchain.relayer.account`. **Van phai kiem**
   (§10.11 muc 9): day la lan duy nhat mot dac tinh bao mat phu thuoc mot dong trong ORM.
4. `runway_hours` la stored compute → **khong** `default`, va compute phai gan `0.0` o dong dau. Ban §06.9
   dang co `required=True, default=0.0` — sai ca hai (§10.14).

#### 10.4.4. Token

`blockchain.token` giu §01.13, them:

```python
is_confidential     = fields.Boolean(default=False)   # co Zether wrapper
registry_address    = fields.Char()                   # ZetherAccountRegistry ma token nay tro toi
underlying_token_id = fields.Many2one('blockchain.token')   # cho wrap/peg
peg_numerator       = fields.Char(default='1')        # uint256: 1 USDT -> 25000 Z-VND => 25000/1
peg_denominator     = fields.Char(default='1')
token_decimals      = fields.Integer(required=True, default=18)
company_ids         = fields.Many2many('res.company')
deploy_state        = fields.Selection([...])         # theo §01, khong dat ten 'state'
```

Khong them `company_id`: token la ha tang. `peg_*` la `Char` uint256 chu khong `Float` — mot ty le 1:25000
tinh bang `Float` tren so du 18 decimals lam tron ngay tu phep nhan dau tien.

#### 10.4.5. Meta-transaction va relayer registry

```python
class BlockchainMetatx(models.Model):
    _name = 'blockchain.metatx'
    _description = 'EIP-1776 meta-transaction request'
    _order = 'id desc'

    settlement_id      = fields.Many2one('blockchain.settlement', index=True, ondelete='cascade')
    chain_id           = fields.Many2one('blockchain.chain', required=True, index=True)
    deployment_id      = fields.Many2one('blockchain.contract.deployment', required=True, index=True,
                                         help='Hop dong verifying. Thay cho mot Char tu do.')
    verifying_contract = fields.Char(related='deployment_id.address', store=True, index=True)
    from_account_id    = fields.Many2one('blockchain.account', required=True, index=True)
    to_address         = fields.Char(required=True)
    token_id           = fields.Many2one('blockchain.token', index=True)
    amount_base        = fields.Char(required=True, default='0')
    calldata_hex       = fields.Char()                    # khong dat ten 'binary'
    calldata_sha256    = fields.Char(index=True)          # de dedup calldata dai
    batch_id_hex       = fields.Char(required=True, index=True)
    batch_nonce        = fields.Integer(required=True, default=0)
    attempt_seq        = fields.Integer(required=True, default=0,
        help='Lan thu may ky cho cung mot lane. Tang khi metatx truoc het han.')
    fee_base           = fields.Char(required=True, default='0')
    fee_token_id       = fields.Many2one('blockchain.token', index=True)
    expiry_datetime    = fields.Datetime(required=True, index=True)   # khong dat ten 'date'
    mode_flags         = fields.Integer(required=True, default=0)     # 0x00/0x01/0x02/0x03
    relayer_address    = fields.Char()
    fee_recipient      = fields.Char()
    domain_separator   = fields.Char(readonly=True, index=True)
    digest_hash        = fields.Char(index=True, readonly=True)
    signature_hex      = fields.Char(readonly=True)
    transaction_id     = fields.Many2one('blockchain.transaction', index=True)
    metatx_state       = fields.Selection([
        ('draft','Draft'), ('simulated','Simulated'), ('signed','Signed'),
        ('published','Published to bus'), ('claimed','Claimed by relayer'),
        ('mined','Mined'), ('final','Final'),
        ('expired','Expired'), ('failed','Failed')], required=True, default='draft', index=True)
    failure_code       = fields.Char(index=True)

    # UNIQUE tuyet doi tren lane la SAI: xem giai thich duoi.
    _one_open_lane = models.UniqueIndex(
        "(chain_id, from_account_id, batch_id_hex, batch_nonce) "
        "WHERE metatx_state NOT IN ('expired', 'failed')",
        'Lane (batchId, batchNonce) dang co mot metatx chua ket thuc.')
    _unique_attempt = models.Constraint(
        'UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce, attempt_seq)',
        'Mot lan thu tren mot lane chi duoc ghi mot lan.')
    _unique_digest = models.Constraint(
        'UNIQUE(chain_id, digest_hash)', 'Mot digest chi duoc ky mot lan tren mot chain.')
    _check_mode = models.Constraint('CHECK (mode_flags BETWEEN 0 AND 3)', 'mode_flags ngoai 0x00-0x03.')
```

**Sua loi cua ban 1: `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` tuyet doi lam he thong
ket cung.** Hop dong EIP-1776 chi tang `meta_nonce(from, batchId)` khi **thuc thi thanh cong**. Mot metatx
het han (`expiry` troi qua, khong relayer nao nhan) **khong** tieu lane. Lan thu hai bat buoc phai dung lai
dung `batchNonce` do — va `UNIQUE` chan `create()`, nen he thong khong the thu lai va tien treo o
`authorized` vinh vien. Partial `models.UniqueIndex` (§10.4.0(3)) sua dung van de: mot lane chi duoc co
**mot** metatx chua ket thuc, nhung so lan thu la khong gioi han va lich su duoc giu day du qua `attempt_seq`.

**`mode_flags` va nguy co dot nonce.** §06.10 muc 3 de mo mot cau hoi contract: `meta_nonce` tang truoc hay
sau `call`. Neu tang truoc, mot relayer doc co the dot nonce cua user bang mot tx chac chan revert. Tang
sau thi lai mo replay khi tx revert. **Day la quyet dinh contract, khong phai Odoo** — nhung Odoo phai
chuan bi cho ca hai: `attempt_seq` ton tai chinh vi kha nang `meta_nonce` **khong** tang, va
`failure_code = 'nonce_burned'` la nhanh xu ly khi no **co** tang. Model khong duoc gia dinh mot trong hai.

`blockchain.relayer` (registry cua ben thu ba, tach khoi `blockchain.relayer.account` la vi noi bo):

```python
class BlockchainRelayer(models.Model):
    _name = 'blockchain.relayer'
    _description = 'Third-party relayer registry entry'

    name          = fields.Char(required=True)
    kind          = fields.Selection([('internal','Internal pool'), ('partner','Alliance partner'),
                                      ('open_public','Open public')], required=True, index=True)
    operator_partner_id = fields.Many2one('res.partner', index=True)
    company_id    = fields.Many2one('res.company', index=True,
                                    default=lambda s: s.env.company)     # NULL khi kind='open_public'
    address_ids   = fields.One2many('blockchain.relayer.address', 'relayer_id')
    allowlist_state = fields.Selection([('unknown','Unknown'), ('probation','Probation'),
                                        ('allowed','Allowed'), ('blocked','Blocked')],
                                       required=True, default='unknown', index=True, tracking=True)
    stake_ref     = fields.Char(help='Tham chieu bond on-chain. KHONG luu so tien o day.')
    reputation_score  = fields.Float(digits=(6, 3), compute='_compute_reputation',
                                     store=True, readonly=True)
    success_count = fields.Integer(default=0, readonly=True)
    fail_count    = fields.Integer(default=0, readonly=True)
    median_latency_ms = fields.Integer(readonly=True)
    contact_url   = fields.Char()
    sla_attachment_ids = fields.Many2many('ir.attachment', string='SLA / contract')
    _inherit = ['mail.thread']
```

`sla_attachment_ids` la M2M `ir.attachment` (hop dong SLA la file, len Garage, khong base64 trong DB).
`reputation_score` la stored compute → gan `0.0` o dong dau moi nhanh.

#### 10.4.6. Transaction va receipt

```python
class BlockchainTransaction(models.Model):
    _name = 'blockchain.transaction'
    _description = 'Broadcast on-chain transaction'
    _order = 'block_number desc, id desc'

    chain_id        = fields.Many2one('blockchain.chain', required=True, index=True)
    chain_family    = fields.Selection(related='chain_id.chain_family', store=True)
    tx_hash         = fields.Char(required=True, index=True)      # KHONG size=. Xem bang duoi.
    sender_account_id = fields.Many2one('blockchain.account', index=True)
    relayer_id      = fields.Many2one('blockchain.relayer', index=True)
    to_address      = fields.Char()
    tx_nonce        = fields.Integer()
    gas_limit       = fields.Integer()
    gas_used        = fields.Integer()
    effective_gas_price_base = fields.Char()                      # uint256 wei
    fee_native_base = fields.Char(default='0')                    # uint256, gia tri chinh tac
    fee_native_display = fields.Float(digits=(38, 18), compute='_compute_fee_native_display',
                                      store=True, readonly=True)
    block_number    = fields.Integer(index=True)
    block_hash      = fields.Char(index=True)
    block_datetime  = fields.Datetime(index=True)
    confirmations   = fields.Integer(default=0)
    tx_state        = fields.Selection([
        ('signed','Signed'), ('broadcast','Broadcast'), ('mined','Mined'),
        ('soft_final','Soft final'), ('final','Final'),
        ('reverted','Reverted'), ('dropped','Dropped'), ('replaced','Replaced'),
        ('orphaned','Orphaned by reorg')],
        required=True, default='signed', index=True)
    replaced_by_id  = fields.Many2one('blockchain.transaction', ondelete='set null')
    revert_reason   = fields.Char()
    receipt_sha256  = fields.Char(index=True)
    receipt_attachment_ids = fields.Many2many('ir.attachment', string='Raw receipt / trace')
    settlement_ids  = fields.One2many('blockchain.settlement', 'transaction_id')   # can cho rule §10.9

    _unique_tx = models.Constraint('UNIQUE(chain_id, tx_hash)', 'tx_hash trung tren cung mot chain.')
    _check_evm_hash = models.Constraint(
        "CHECK (chain_family <> 'evm' OR tx_hash ~ '^0x[0-9a-f]{64}$')",
        'tx_hash EVM phai la 0x + 64 hex lowercase.')
```

**Sua so voi ban 1: `tx_hash size=66` chi dung cho EVM.** Dinh dang dinh danh giao dich theo ho:

| Family | Dinh dang tx id | Do dai |
|---|---|---|
| EVM | `0x` + 64 hex | 66 |
| Hedera | `0.0.<payer>@<sec>.<nanos>` | 20-30 |
| TON | base64 32 byte hash (hoac `lt:hash:workchain`) | 44+ |
| Sui | digest base58 | ~44 |
| Stellar / Soroban | 64 hex **khong** `0x` | 64 |
| CosmWasm | 64 hex **uppercase** | 64 |

Vay: khong `size`, CHECK theo `chain_family`, va **khong** ep lowercase toan cuc (Cosmos dung uppercase).

Raw receipt va execution trace di vao `ir.attachment` tren Garage, khong vao mot cot `Text`. Trong bang chi
giu `receipt_sha256` de doi chieu. Dinh luong (uoc tinh, co so: kich thuoc trace JSON EVM dien hinh
50-500 KB; mot `blockchain.event` ~300 B du lieu + ~200 B index):

| Khoi luong | `blockchain.transaction` | `blockchain.event` | Trace tren Garage |
|---|---|---|---|
| 10k tx/thang | ~6 MB/thang | 30k dong ~15 MB/thang | 0.5-5 GB/thang |
| 100k tx/thang | ~60 MB/thang | 300k dong ~150 MB/thang | 5-50 GB/thang |

Ket luan van hanh: **trace la thu dat nhat trong he thong**, va no phai co retention. `_cron_gc_traces()`
xoa attachment trace cua tx da `final` qua 90 ngay (giu `receipt_sha256` vinh vien). Giu trace cua tx
`reverted`/`orphaned` 400 ngay — do la thu se can khi co tranh chap.

```python
class BlockchainEvent(models.Model):
    _name = 'blockchain.event'
    _description = 'Decoded on-chain log'

    transaction_id   = fields.Many2one('blockchain.transaction', required=True,
                                       index=True, ondelete='cascade')
    log_index        = fields.Integer(required=True)
    contract_address = fields.Char(required=True, index=True)
    topic0           = fields.Char(required=True, index=True)
    event_name       = fields.Char(index=True)
    abi_id           = fields.Many2one('blockchain.contract.abi', index=True)   # §11.6 versioning
    decoded_args     = fields.Json()          # metadata nho, duoc phep; KHONG dat ten field la 'json'
    business_ref     = fields.Char(index=True, help='bytes32 ref nhung trong event (§11.12 muc 1).')
    processed        = fields.Boolean(default=False, index=True)

    _unique_log = models.Constraint('UNIQUE(transaction_id, log_index)', 'Log da ton tai.')
```

`decoded_args` la `fields.Json` — duoc phep vi la metadata nho co cau truc, **khong** phai anh/file.
Rang buoc bat buoc: khong bao gio > 8 KB; cai gi lon hon la attachment.

#### 10.4.7. Zether

`blockchain.zether.account` + `blockchain.zether.account.chain` giu §02.8.5, **voi mot sua**:
`profile_id` → `chain_id = fields.Many2one('blockchain.chain')`, constraint doi thanh
`UNIQUE(account_id, chain_id)` (§10.3).

Them so cai bao mat:

```python
class BlockchainZetherEntry(models.Model):
    _name = 'blockchain.zether.entry'
    _description = 'Confidential ledger entry'
    _order = 'epoch_number desc, id desc'

    company_id     = fields.Many2one('res.company', required=True, index=True,
                                     default=lambda s: s.env.company)
    token_id       = fields.Many2one('blockchain.token', required=True, index=True)
    account_id     = fields.Many2one('blockchain.zether.account', required=True, index=True)
    counterparty_id= fields.Many2one('blockchain.zether.account', index=True)
    direction      = fields.Selection([('deposit','Deposit'), ('withdraw','Withdraw'),
                                       ('transfer_in','Transfer in'), ('transfer_out','Transfer out'),
                                       ('fee','Relayer fee')], required=True, index=True)
    c_hex          = fields.Char(required=True)      # ElGamal C, 2 x 32 bytes hex
    d_hex          = fields.Char(required=True)      # ElGamal D
    zether_nonce   = fields.Integer(required=True)
    epoch_number   = fields.Integer(required=True, index=True)
    proof_attachment_id = fields.Many2one('ir.attachment', ondelete='restrict')  # blob tren Garage
    proof_sha256   = fields.Char(index=True)
    proof_bytes    = fields.Integer(readonly=True)
    transaction_id = fields.Many2one('blockchain.transaction', index=True)
    settlement_id  = fields.Many2one('blockchain.settlement', index=True)
    amount_clear_base = fields.Char(
        help='CHI dien khi cong ty nay giu khoa giai ma. Rong o phia doi tac.')
    clear_source   = fields.Selection([('none','Chua giai ma'), ('self_decrypt','Tu giai ma'),
                                       ('counterparty_disclosed','Doi tac cong bo'),
                                       ('audit_key','Audit view key')],
                                      required=True, default='none', index=True)

    _unique_zether_nonce = models.Constraint(
        'UNIQUE(token_id, account_id, zether_nonce, direction)',
        'Nonce Zether da duoc dung cho tai khoan/token nay.')
    _check_clear = models.Constraint(
        "CHECK (clear_source <> 'none' OR amount_clear_base IS NULL)",
        'amount_clear_base chi duoc dien khi co nguon giai ma.')
```

`amount_clear_base` rong khong phai loi — **mot so du bao mat ma Odoo doc duoc ro rang la mot lo hong thiet ke**.
Bao cao doi soat phai chiu duoc cot rong; §09.9 va §10.8 chi ra rang Zether pha vo cac mode co `amount` bat buoc.

**Dinh luong proof — sua so voi ban 1.** Ban 1 uoc 1.0-1.5 KB. Tinh lai cho **BN254 tren EVM**, noi mot diem
G1 trong calldata la **64 byte** (x, y moi cai 32 byte, khong nen):

| Thanh phan | Cong thuc | n=128, m=2 range | Byte |
|---|---|---|---|
| Bulletproof aggregate | `2*ceil(log2(m*n)) + 4` diem G1 | `2*8 + 4 = 20` diem | 20 x 64 = 1,280 |
| Scalar cua Bulletproof | 5 scalar | 5 | 5 x 32 = 160 |
| Sigma proof (Schnorr eq. + PoK) | ~4 diem + ~5 scalar | | 4x64 + 5x32 = 416 |
| Ciphertext C, D, C_debit, C_fee | 4 x 2 diem | | 8 x 64 = 512 |
| **Tong calldata** | | | **~2,370 B** |

Vay proof blob **~1.4-2.0 KB nen (compressed, 32 B/diem)** va **~2.3-2.5 KB tren calldata EVM**. Attachment,
khong `Char`. Voi 16 gas/byte calldata khac 0 → chi rieng calldata da ~38,000 gas.

**Gas Zether: con so trong `blockchain.md` sai mot bac do lon.** Note ghi "~180,000 - 250,000 gas" cho
xac thuc ZKP. Do la chi phi cua mot **pairing check Groth16** (`ecPairing` ~ 45,000 + 34,000/cap sau
EIP-1108), khong phai cua Bulletproof. Bulletproof **khong dung pairing**; no dung ~`2n + O(log n)` phep
nhan vo huong tren duong cong. Voi `ecMul` = 6,000 gas (EIP-1108) va n=128, m=2:

```
naive:        ~2*256 + 40  ≈ 550 ecMul  x 6,000 = 3.3M gas
Pippenger/    multi-exp gom ~40-60% => ~200-350 ecMul x 6,000 = 1.2M - 2.1M gas
inner-product cong ecAdd (150 gas) va calldata (38k)
```

→ **1.2M - 2.5M gas cho mot `transferConfidential`**, khop voi uoc tinh cua §06.4 va khong khop voi note.
He qua truc tiep: tren Ethereum L1 voi block gas limit 30M, mot block chua toi da ~12-25 giao dich Zether.
Do la ly do locked #5 (private chain truoc) khong phai mot su tri hoan ma la mot dieu kien kha thi.
Tren private Besu voi `gasPrice=0` va block gas limit tu cau hinh, con so nay khong ton tien — nhung no
van ton **thoi gian CPU cua validator**, nen `block_gas_limit` tren `blockchain.chain` phai duoc dat that.

#### 10.4.8. Settlement layer thong nhat — trung tam cua addon

Day la model **duy nhat** ma moi consumer (bridge DMS, payment, account, RPC ngoai) duoc phep dung. Moi thu
khac la noi that.

```python
class BlockchainSettlement(models.Model):
    _name = 'blockchain.settlement'
    _description = 'Unified on-chain settlement'
    _inherit = ['mail.thread']
    _order = 'id desc'

    name           = fields.Char(required=True, copy=False, default='/', readonly=True)
    company_id     = fields.Many2one('res.company', required=True, index=True,
                                     default=lambda s: s.env.company)
    # --- Idempotency & lien ket nguoc (§15.3) ---
    origin_producer = fields.Char(required=True, index=True, default='manual',
        help="Namespace cua consumer: 'dms', 'portal', 'erp-x'. Chan va cham origin_key giua hai consumer.")
    origin_key     = fields.Char(required=True, index=True,
        help='Khoa idempotency do consumer cung cap, duy nhat trong (company, producer).')
    origin_model   = fields.Char(index=True)                # 'dms.trade.settlement.line'
    origin_id      = fields.Many2oneReference(model_field='origin_model', index=True)
    origin_ref     = fields.Reference(selection='_selection_origin_ref', compute='_compute_origin_ref',
                                      inverse='_inverse_origin_ref', store=False)
    # --- Ban chat giao dich ---
    use_case       = fields.Selection([('loyalty','Loyalty / reward points'),
                                       ('b2b','B2B settlement'),
                                       ('payment','End-user payment')], required=True, index=True)
    direction      = fields.Selection([('out','Outbound / payout'), ('in','Inbound / collection')],
                                      required=True, index=True)
    transport      = fields.Selection([('onchain','On-chain transfer'),
                                       ('offset','Netting offset, khong co tx'),
                                       ('external','Fiat / ngoai chain, chain chi anchor')],
                                      required=True, default='onchain', index=True)
    chain_id       = fields.Many2one('blockchain.chain', index=True)   # NULL khi transport='offset'
    token_id       = fields.Many2one('blockchain.token', index=True)
    payer_account_id  = fields.Many2one('blockchain.account', index=True)
    payee_account_id  = fields.Many2one('blockchain.account', index=True)
    partner_id     = fields.Many2one('res.partner', index=True)
    amount_base    = fields.Char(required=True, default='0')
    currency_id    = fields.Many2one('res.currency', required=True,
                                     default=lambda s: s.env.company.currency_id)
    amount_fiat    = fields.Monetary(currency_field='currency_id')
    confidential   = fields.Boolean(default=False)
    # --- Lien ket ky thuat ---
    metatx_id      = fields.Many2one('blockchain.metatx', index=True)
    transaction_id = fields.Many2one('blockchain.transaction', index=True)
    zether_entry_id= fields.Many2one('blockchain.zether.entry', index=True)
    batch_id       = fields.Many2one('blockchain.settlement.batch', index=True)   # §15.7
    netting_set_id = fields.Many2one('blockchain.netting.set', index=True)        # §15.6
    money_flow_id  = fields.Many2one('blockchain.money.flow', index=True)         # §09.4
    reversal_of_id = fields.Many2one('blockchain.settlement', index=True, ondelete='restrict')
    # --- Vong doi ---
    settle_state   = fields.Selection([
        ('draft','Draft'), ('authorized','Authorized'), ('submitted','Submitted'),
        ('broadcast','Broadcast'), ('pending_finality','Pending finality'),
        ('final','Final'), ('failed','Failed'), ('expired','Expired'), ('reversed','Reversed')],
        required=True, default='draft', index=True, tracking=True)
    authorize_uid      = fields.Many2one('res.users', readonly=True)
    authorize_datetime = fields.Datetime(readonly=True)
    broadcast_datetime = fields.Datetime(readonly=True)
    finality_datetime  = fields.Datetime(readonly=True, index=True)
    failure_code       = fields.Char(index=True)
    failure_reason     = fields.Char()

    _unique_origin = models.Constraint(
        'UNIQUE(company_id, origin_producer, origin_key)',
        'origin_key phai duy nhat trong (company, producer).')
    _check_transport_chain = models.Constraint(
        "CHECK (transport <> 'onchain' OR chain_id IS NOT NULL)",
        'Settlement onchain phai co chain.')
    _check_reversal = models.Constraint(
        "CHECK (settle_state <> 'reversed' OR reversal_of_id IS NULL)",
        'Ban ghi bi dao khong tu tro ve chinh no.')
```

**Sua so voi ban 1: `UNIQUE(company_id, origin_key)` khong du.** Hai consumer doc lap (bridge DMS va mot
portal ngoai) hoan toan co the sinh cung mot chuoi `origin_key`. Khi do consumer thu hai nhan lai ban ghi
cua consumer thu nhat — mot payout **bien mat khong loi**. `origin_producer` la namespace bat buoc.
Quy uoc format: `origin_key = f"{model}:{id}:{purpose}"` (bridge DMS), hoac UUIDv4 (client ngoai).

**Ten ban ghi.** `name` `required=True default='/'` can mot `ir.sequence` — ban 1 thieu:

```xml
<record id="seq_blockchain_settlement" model="ir.sequence">
    <field name="name">Blockchain Settlement</field>
    <field name="code">blockchain.settlement</field>
    <field name="prefix">BCS/%(year)s/</field>
    <field name="padding">6</field>
    <field name="company_id" eval="False"/>
</record>
```

`company_id = False` tren sequence (dung chung moi cong ty) la mot lua chon: mot day so lien tuc de doi soat
hon. Neu ke toan yeu cau day so rieng theo phap nhan, tao mot sequence per company trong `post_init_hook`.

**May trang thai:**

```
draft ─authorize→ authorized ─submit→ submitted ─relayer claim→ broadcast
                                                       │
                                                       ├─ mined (VAN LA pending_finality)
                                                       ▼
                                            pending_finality ──Finality Gate──▶ final
                                                       │
                                       reverted/dropped/expiry ──▶ failed | expired
final ──(chi bang mot settlement nguoc chieu)──▶ reversed
```

Chuyen trang thai hop le, ep bang bang chu khong bang `if` rai rac:

```python
_ALLOWED = {
    'draft':            {'authorized', 'failed', 'expired'},
    'authorized':       {'submitted', 'failed', 'expired'},
    'submitted':        {'broadcast', 'failed', 'expired'},
    'broadcast':        {'pending_finality', 'failed'},
    'pending_finality': {'final', 'failed'},
    'final':            {'reversed'},
    'failed':           set(), 'expired': set(), 'reversed': set(),
}
```

**Nguyen tac ke thua tu `dms_vietqr` ("quet QR khong phai la da thu tien"): `final` la trang thai DUY NHAT
ma consumer duoc coi la tien da chuyen.** `broadcast` va ca `mined` deu khong. Ep bang code:

```python
_GATE = object()          # sentinel MODULE-LEVEL. Client chi gui duoc JSON nen khong the gia mao.
PAID_STATES = ('final',)

def blockchain_is_paid(self):
    self.ensure_one()
    return self.settle_state in PAID_STATES

def write(self, vals):
    new = vals.get('settle_state')
    if new and self.env.context.get('blockchain_gate') is not _GATE:
        for rec in self:
            if new not in _ALLOWED.get(rec.settle_state, ()):
                raise UserError(_("Chuyen %(a)s -> %(b)s khong hop le.", a=rec.settle_state, b=new))
            if new == 'final':
                raise UserError(_("settle_state='final' chi duoc dat boi Finality Gate."))
    return super().write(vals)

@api.model_create_multi
def create(self, vals_list):
    for vals in vals_list:
        if vals.get('settle_state') in ('final', 'reversed'):
            raise UserError(_("Khong the tao settlement o trang thai terminal."))
        if vals.get('name', '/') == '/':
            vals['name'] = self.env['ir.sequence'].next_by_code('blockchain.settlement') or '/'
    return super().create(vals_list)
```

**Vi sao sentinel object chu khong phai mot chuoi context.** `/json/2` nhan `context` tu client
(`Json2Dispatcher` → `Model.with_context(context)`), nen `context={'blockchain_gate': True}` se bi mot client
gui len duoc. Mot `object()` cap module khong ton tai trong JSON, khong the gia mao, va khong can them
mot tang phan quyen nao. Do la mot dong code.

`_set_finality` la method private duy nhat duoc phep ghi `final`:

```python
def _set_finality(self, transaction):
    """Chi goi tu _cron_finality_gate hoac tu chain_event_ingest (§11.11). Idempotent."""
    self.ensure_one()
    chain = self.chain_id
    if transaction.confirmations < chain.finality_hard_blocks:
        return False
    if chain.finality_hard_seconds and transaction.block_datetime and \
            (fields.Datetime.now() - transaction.block_datetime).total_seconds() \
            < chain.finality_hard_seconds:
        return False
    if self.settle_state == 'final':
        return True                                   # idempotent, khong raise
    self.with_context(blockchain_gate=_GATE).write({
        'settle_state': 'final',
        'finality_datetime': fields.Datetime.now(),
        'transaction_id': transaction.id,
    })
    self._notify_origin()                             # §15.3 mixin callback
    return True
```

Hai dieu kien la **VA**, khong phai HOAC — `max()` cua hai truc (§10.4.2). `reversed` khong bao gio la mot
`write` len ban ghi cu: no la mot settlement moi chieu nguoc voi `reversal_of_id`, vi so cai on-chain khong
co UNDO.

**`mail.thread` va chi phi cua no.** Chi `settle_state` co `tracking=True`. Uoc tinh (co so: `mail_message`
~400 B + `mail_tracking_value` ~120 B, 5 chuyen trang thai/settlement): 10k settlement/thang → 50k
`mail_message` ≈ 20 MB + 50k tracking ≈ 6 MB, moi thang. **Nguong: tren 100k settlement/thang, bo
`mail.thread`** va thay bang mot bang `blockchain.settlement.log` phang (chi 3 cot) — `mail.thread` cung
keo theo `message_follower_ids` va mot subquery trong moi `search` neu co filter theo follower.

#### 10.4.9. Contract deployment registry — model ban 1 thieu

Khong co model nay thi: `verifying_contract` la mot `Char` tu do khong doi chieu duoc; Policy Gate
"Target Contract Allowlist" ma chinh `blockchain.md` yeu cau khong co cho de song; va khong ai tra loi duoc
"Zether token Z-VND tren Gnosis dang o dia chi nao, phien ban implementation nao" — cau hoi se duoc hoi
trong tuan dau tien sau khi len production.

```python
class BlockchainContractDeployment(models.Model):
    _name = 'blockchain.contract.deployment'
    _description = 'A deployed contract instance on a chain'
    _inherit = ['mail.thread']
    _order = 'chain_id, purpose, id'

    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    purpose      = fields.Selection([
        ('metatx_forwarder','EIP-1776 forwarder'), ('token_factory','Token factory'),
        ('token_beacon','Beacon / implementation'), ('erc20','ERC-20 token'),
        ('zether_registry','Zether account registry'), ('zether_token','Zether token'),
        ('paymaster','Paymaster / gas station'), ('multisig','Multisig / timelock'),
        ('other','Other')], required=True, index=True)
    address      = fields.Char(required=True, index=True)
    token_id     = fields.Many2one('blockchain.token', index=True)
    abi_id       = fields.Many2one('blockchain.contract.abi', index=True)      # §11.6
    impl_address = fields.Char(help='Implementation phia sau proxy, khi la UUPS/Beacon.')
    impl_version = fields.Char()
    source_commit = fields.Char(help='Git commit cua smartcontracts/ da build ra bytecode nay.')
    bytecode_sha256 = fields.Char(index=True)
    deploy_tx_id = fields.Many2one('blockchain.transaction', index=True)
    audit_attachment_ids = fields.Many2many('ir.attachment', string='Audit reports')
    is_allowed_target = fields.Boolean(default=False, index=True, tracking=True,
        help='Policy Gate chi cho phep metatx tro toi deployment co co nay.')
    state        = fields.Selection([('draft','Draft'), ('deployed','Deployed'),
                                     ('verified','Verified on explorer'), ('active','Active'),
                                     ('deprecated','Deprecated'), ('killed','Killed')],
                                    required=True, default='draft', index=True, tracking=True)

    _unique_address = models.Constraint(
        'UNIQUE(chain_id, address)', 'Mot dia chi contract chi duoc dang ky mot lan tren mot chain.')
    _one_active_per_purpose = models.UniqueIndex(
        "(chain_id, purpose, COALESCE(token_id, 0)) WHERE state = 'active' AND purpose <> 'other'",
        'Chi mot deployment duoc active cho moi (chain, purpose, token).')
```

`is_allowed_target` la allowlist, va no la mot **field co `tracking`** chu khong phai mot dong trong
`ir.config_parameter`: bat mot contract vao allowlist la mot su kien phai co ai bat, luc nao, va co
chatter. Chi `group_blockchain_manager` duoc ghi (§10.5).

`_one_active_per_purpose` dung `models.UniqueIndex` voi `COALESCE(token_id, 0)` vi `UNIQUE` cua PostgreSQL
coi moi NULL la khac nhau — mot `UNIQUE(chain_id, purpose, token_id)` thuong se cho phep hai forwarder
`active` cung luc khi ca hai co `token_id IS NULL`. Day la loi kinh dien va no im lang.

#### 10.4.10. Approval policy — maker-checker cho tien ra

`blockchain.md` §10.4 yeu cau hanh dong R3/R4 phai co nguoi duyet (Scheduled Transactions tren Hedera,
Arbiter Agent…). Ban 1 chi co mot method `blockchain_authorize_payout` va mot nhom `treasury` — tuc la
**mot** nguoi trong nhom do ky duoc bat ky so tien nao. Do khong phai maker-checker.

```python
class BlockchainApprovalPolicy(models.Model):
    _name = 'blockchain.approval.policy'
    _description = 'How much may be authorized by whom, without a second pair of eyes'
    _order = 'company_id, sequence, id'

    sequence     = fields.Integer(default=10)
    company_id   = fields.Many2one('res.company', required=True, index=True,
                                   default=lambda s: s.env.company)
    use_case     = fields.Selection([('loyalty','Loyalty'), ('b2b','B2B'),
                                     ('payment','End-user payment'), ('any','Any')],
                                    required=True, default='any')
    chain_id     = fields.Many2one('blockchain.chain', index='btree_not_null')   # NULL = moi chain
    currency_id  = fields.Many2one('res.currency', required=True)
    amount_fiat_max_single = fields.Monetary(currency_field='currency_id', required=True,
        help='Tren nguong nay phai co nguoi thu hai. 0 = luon phai.')
    amount_fiat_max_daily  = fields.Monetary(currency_field='currency_id', required=True,
        help='Tong 24h cua ca company. Cham nguong -> khoa, khong canh bao.')
    quorum       = fields.Integer(required=True, default=2)
    approver_group_id = fields.Many2one('res.groups', required=True)
    active       = fields.Boolean(default=True)

    _check_quorum = models.Constraint('CHECK (quorum >= 1)', 'quorum toi thieu la 1.')


class BlockchainApprovalRequest(models.Model):
    _name = 'blockchain.approval.request'
    _description = 'Second pair of eyes on a settlement'

    settlement_id = fields.Many2one('blockchain.settlement', required=True,
                                    index=True, ondelete='cascade')
    policy_id     = fields.Many2one('blockchain.approval.policy', required=True)
    requested_uid = fields.Many2one('res.users', required=True, readonly=True)
    approver_ids  = fields.Many2many('res.users', readonly=True)
    quorum        = fields.Integer(required=True, readonly=True)
    approve_state = fields.Selection([('pending','Pending'), ('approved','Approved'),
                                      ('rejected','Rejected'), ('expired','Expired')],
                                     required=True, default='pending', index=True)
    expiry_datetime = fields.Datetime(required=True, index=True)

    _one_open_per_settlement = models.UniqueIndex(
        "(settlement_id) WHERE approve_state = 'pending'",
        'Settlement nay da co mot yeu cau duyet dang mo.')
```

Rang buoc bat buoc, ep trong `_authorize()`, khong bang UI: **nguoi tao settlement khong duoc la nguoi duyet**
(`self.env.uid != request.requested_uid`), va **cung mot user khong duoc dem hai lan** vao quorum. Ca hai
la mot dong `if`, va thieu chung thi ca model nay chi la trang tri.

Mac dinh khi khong co policy nao khop: `amount_fiat_max_single = 0`, tuc **luon** can nguoi thu hai.
Mac dinh phai la an toan; mot deployment muon noi long phai tu tao policy.

#### 10.4.11. Outbox va security event — cho hand-wave lon nhat cua ban 1

Ban 1 viet: *"Odoo goi worker qua `requests`"*. Do la mot cau mo ta mot bai toan kho ma khong noi lam the nao,
va cach hien nhien nhat de hien thuc no la sai:

```python
# SAI. Dung tuyet doi khong lam the nay.
def action_submit(self):
    requests.post(worker_url, json=payload, timeout=10)     # tx da broadcast
    self.write({'settle_state': 'submitted'})               # transaction co the rollback sau day
```

Neu transaction Odoo rollback sau khi `requests.post` tra ve (mot `@api.constrains` khac nem, mot deadlock,
mot `ConcurrencyError` khi ghi record khac trong cung request), thi **tren chain da co mot giao dich ma
trong Odoo khong co ban ghi nao**. Chieu nguoc lai cung te: worker timeout nhung da nhan payload → Odoo
rollback → cron thu lai → **hai tx**. Tren mot so cai khong co UNDO.

**Chot: transactional outbox.** Odoo chi **ghi** mot dong vao bang; mot cron (hoac worker poll) doc va goi.

```python
class BlockchainOutboxJob(models.Model):
    _name = 'blockchain.outbox.job'
    _description = 'Outbound call to the relay worker, committed with the business transaction'
    _order = 'id'

    company_id    = fields.Many2one('res.company', required=True, index=True,
                                    default=lambda s: s.env.company)
    chain_id      = fields.Many2one('blockchain.chain', required=True, index=True)
    job_kind      = fields.Selection([('submit_metatx','Submit meta-tx'),
                                      ('broadcast_tx','Broadcast raw tx'),
                                      ('zether_prove','Request Zether proof'),
                                      ('probe','Probe endpoint')], required=True, index=True)
    settlement_id = fields.Many2one('blockchain.settlement', index=True, ondelete='cascade')
    metatx_id     = fields.Many2one('blockchain.metatx', index=True, ondelete='cascade')
    payload_json  = fields.Json(required=True)          # <= 8 KB. Lon hon thi la attachment.
    idempotency_key = fields.Char(required=True, index=True)
    attempt_count = fields.Integer(default=0)
    next_attempt_datetime = fields.Datetime(index=True, default=fields.Datetime.now)
    last_error    = fields.Char()
    job_state     = fields.Selection([('queued','Queued'), ('sent','Sent'), ('acked','Acked'),
                                      ('failed','Failed'), ('dead','Dead letter')],
                                     required=True, default='queued', index=True)

    _unique_idem = models.Constraint(
        'UNIQUE(idempotency_key)', 'Job da duoc xep hang voi khoa idempotency nay.')
```

Ba tinh chat bat buoc:

1. `idempotency_key` di **theo request HTTP** toi worker (header `Idempotency-Key`). Worker chiu trach nhiem
   dedup — Odoo khong the tu bao dam exactly-once qua mang.
2. `job_state` chuyen `queued → sent` **truoc** khi goi, va cron commit ngay truoc do (`env.cr.commit()`).
   Neu Odoo chet giua chung, job o `sent` va **khong** duoc thu lai tu dong: no vao hang cho nguoi kiem
   (`_cron_outbox_reap` chuyen `sent` qua 10 phut thanh `dead`). At-most-once cho buoc gui, exactly-once
   dat duoc o worker bang `idempotency_key`. Day la danh doi co y thuc: tha treo mot payout con hon gui hai lan.
3. Backoff: `next_attempt_datetime = now + min(2 ** attempt_count, 3600) giay`. Sau 8 lan → `dead` +
   mot `blockchain.security.event`.

```python
class BlockchainSecurityEvent(models.Model):
    _name = 'blockchain.security.event'
    _description = 'Security-relevant event that a human must see'
    _order = 'id desc'

    company_id  = fields.Many2one('res.company', index=True)
    severity    = fields.Selection([('info','Info'), ('warn','Warning'),
                                    ('high','High'), ('critical','Critical')],
                                   required=True, default='warn', index=True)
    event_code  = fields.Char(required=True, index=True)   # 'tenant_cross_signer', 'rpc_divergence', …
    subject_model = fields.Char(index=True)
    subject_id    = fields.Many2oneReference(model_field='subject_model', index=True)
    user_id     = fields.Many2one('res.users', index=True)
    detail_json = fields.Json()
    ack_uid     = fields.Many2one('res.users', readonly=True)
    ack_datetime = fields.Datetime(readonly=True)
```

`perm_unlink = 0` cho **moi** nhom, ke ca manager. Mot log bao mat xoa duoc thi khong phai log bao mat.

#### 10.4.12. Dinh luong tang truong va nguong kien truc

Uoc tinh, co so: kich thuoc dong trung binh cua PostgreSQL cho cac model tren (24 byte header + cot),
cong index. Gia dinh 3 event/tx, 1.2 settlement/tx, 5 chuyen trang thai/settlement.

| Khoi luong | Tong DB/thang | Garage/thang | Nguong can doi kien truc |
|---|---|---|---|
| 1k settlement/thang | ~8 MB | ~0.5 GB | Khong. `ir.cron` du. |
| 10k/thang | ~55 MB | 0.5-5 GB | Bat retention trace. |
| 100k/thang | ~550 MB | 5-50 GB | **Bo `mail.thread`**, chuyen finality gate ra worker (§11.0). |
| 1M/thang | ~5.5 GB | 50-500 GB | Partition `blockchain_event` theo thang; chuyen `blockchain.event` sang ClickHouse va giu Odoo la control plane. |

Nguong doi tu `ir.cron` sang service (§11.0): cron toi thieu 1 phut, scheduler danh thuc moi ~60 giay →
p50 do tre phat hien finality ~30 giay, **p95 ~90 giay**. Tren Gnosis (hard finality ~13 phut) do la nhieu.
Tren mot private chain BFT (finality tuc thoi) do la **toan bo** do tre ma nguoi dung cam nhan — va no
khong chap nhan duoc cho UX thanh toan. Ket luan: **`ir.cron` du cho public chain, khong du cho private
chain.** Tren private chain, worker phai goi `chain_event_ingest` (§11.11) chu khong doi cron.

---

### 10.5. ACL: nhom quyen va record rule

#### 10.5.1. Nhom

| Nhom XML id | Ten | Duoc gi | `implied_ids` |
|---|---|---|---|
| `group_blockchain_viewer` | Blockchain / Viewer | Doc settlement, transaction, event cua cong ty minh. **Khong** thay `signer_ref`, khong thay account role `treasury`/`relay`/`admin`. | |
| `group_blockchain_operator` | Blockchain / Operator | Tao settlement, retry outbox job that bai, doc metatx | viewer |
| `group_blockchain_approver` | Blockchain / Approver | Duyet `blockchain.approval.request`. **Khong** duoc tao settlement. | viewer |
| `group_blockchain_treasury` | Blockchain / Treasury | `blockchain_authorize_payout`, `withdraw` Zether, nap quy relayer | operator |
| `group_blockchain_relayer_admin` | Blockchain / Relayer Admin | CRUD `blockchain.relayer`, doi `allowlist_state` | operator |
| `group_blockchain_manager` | Blockchain / Manager | CRUD chain, endpoint, deployment, token, custody config, allowlist, cron | treasury + relayer_admin + approver |
| `group_blockchain_auditor` | Blockchain / Auditor | Doc **tat ca** trong `env.companies`, ke ca zether entry va proof; ghi **chi** `blockchain.audit.disclosure` | |

Tach `treasury` khoi `relayer_admin` la co chu dich: nguoi duoc phep chi tien khong duoc dong thoi la nguoi
quyet dinh relayer nao hop le. Do la mot con duong rut tien mot nguoi.

**`approver` khong `implied_ids` `operator`, va do la diem quan trong nhat cua bang tren.** Neu approver ke
thua operator thi mot nguoi vua tao vua duyet duoc, va maker-checker (§10.4.10) tro thanh trang tri. Rang
buoc `self.env.uid != request.requested_uid` la lop thu hai; tach nhom la lop thu nhat.

**`group_blockchain_manager` ke thua ca ba nhanh** — nghia la manager cung la treasury. Neu mot to chuc muon
manager **khong** duoc chi tien, bo `treasury` khoi `implied_ids` va cap tay. Mac dinh gop lai vi phan lon
deployment nho chi co mot nguoi; nhung day la mot mac dinh phai duoc doc va chon, khong phai mot tai nan.

#### 10.5.2. Ma tran ACL day du

**Mot model khong co dong nao trong `ir.model.access.csv` la khong ai truy cap duoc tru superuser**, va
Odoo 19 chi log mot warning luc load (`odoo/modules/loading.py:257`: *"The models %s have no access rules in
module %s"*). Do la mot loi de sot vi no khong lam server chet. Bang duoi la day du; moi model trong §10.3
phai xuat hien.

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_chain_viewer,chain viewer,model_blockchain_chain,group_blockchain_viewer,1,0,0,0
access_chain_manager,chain manager,model_blockchain_chain,group_blockchain_manager,1,1,1,0
access_endpoint_manager,endpoint manager,model_blockchain_rpc_endpoint,group_blockchain_manager,1,1,1,1
access_endpoint_viewer,endpoint viewer,model_blockchain_rpc_endpoint,group_blockchain_operator,1,0,0,0
access_deploy_viewer,deployment viewer,model_blockchain_contract_deployment,group_blockchain_viewer,1,0,0,0
access_deploy_manager,deployment manager,model_blockchain_contract_deployment,group_blockchain_manager,1,1,1,0
access_token_viewer,token viewer,model_blockchain_token,group_blockchain_viewer,1,0,0,0
access_token_manager,token manager,model_blockchain_token,group_blockchain_manager,1,1,1,0
access_account_viewer,account viewer,model_blockchain_account,group_blockchain_viewer,1,0,0,0
access_account_operator,account operator,model_blockchain_account,group_blockchain_operator,1,1,1,0
access_account_manager,account manager,model_blockchain_account,group_blockchain_manager,1,1,1,0
access_account_auditor,account auditor,model_blockchain_account,group_blockchain_auditor,1,0,0,0
access_relayacct_manager,relayer account manager,model_blockchain_relayer_account,group_blockchain_manager,1,1,1,0
access_relayacct_operator,relayer account operator,model_blockchain_relayer_account,group_blockchain_operator,1,0,0,0
access_relayer_admin,relayer registry admin,model_blockchain_relayer,group_blockchain_relayer_admin,1,1,1,0
access_relayer_viewer,relayer registry viewer,model_blockchain_relayer,group_blockchain_viewer,1,0,0,0
access_metatx_operator,metatx operator,model_blockchain_metatx,group_blockchain_operator,1,1,1,0
access_metatx_viewer,metatx viewer,model_blockchain_metatx,group_blockchain_viewer,1,0,0,0
access_tx_viewer,transaction viewer,model_blockchain_transaction,group_blockchain_viewer,1,0,0,0
access_tx_manager,transaction manager,model_blockchain_transaction,group_blockchain_manager,1,1,1,0
access_event_viewer,event viewer,model_blockchain_event,group_blockchain_viewer,1,0,0,0
access_settlement_viewer,settlement viewer,model_blockchain_settlement,group_blockchain_viewer,1,0,0,0
access_settlement_operator,settlement operator,model_blockchain_settlement,group_blockchain_operator,1,1,1,0
access_settlement_auditor,settlement auditor,model_blockchain_settlement,group_blockchain_auditor,1,0,0,0
access_zether_acct_operator,zether account operator,model_blockchain_zether_account,group_blockchain_operator,1,1,1,0
access_zether_entry_viewer,zether entry viewer,model_blockchain_zether_entry,group_blockchain_viewer,1,0,0,0
access_zether_entry_operator,zether entry operator,model_blockchain_zether_entry,group_blockchain_operator,1,1,1,0
access_zether_entry_auditor,zether entry auditor,model_blockchain_zether_entry,group_blockchain_auditor,1,0,0,0
access_approval_policy_manager,approval policy manager,model_blockchain_approval_policy,group_blockchain_manager,1,1,1,0
access_approval_req_approver,approval request approver,model_blockchain_approval_request,group_blockchain_approver,1,1,0,0
access_approval_req_operator,approval request operator,model_blockchain_approval_request,group_blockchain_operator,1,0,1,0
access_outbox_operator,outbox operator,model_blockchain_outbox_job,group_blockchain_operator,1,1,0,0
access_outbox_manager,outbox manager,model_blockchain_outbox_job,group_blockchain_manager,1,1,1,0
access_secevent_viewer,security event viewer,model_blockchain_security_event,group_blockchain_manager,1,1,0,0
access_secevent_auditor,security event auditor,model_blockchain_security_event,group_blockchain_auditor,1,0,0,0
access_moneyflow_manager,money flow manager,model_blockchain_money_flow,group_blockchain_manager,1,1,1,1
access_custody_manager,custody manager,model_blockchain_custody_provider,group_blockchain_manager,1,1,1,0
access_custodykey_manager,custody key manager,model_blockchain_custody_key,group_blockchain_manager,1,1,1,0
```

**`perm_unlink = 0` gan nhu o moi noi — so cai khong xoa duoc.** Ba ngoai le: `blockchain.rpc.endpoint`
(cau hinh thuan tuy), `blockchain.money.flow` (cau hinh), `blockchain.relayer.address` (cascade). Con lai
dung `state = 'retired'`. Voi `blockchain.settlement`, them mot chan cung khong phu thuoc ACL:

```python
def unlink(self):
    if any(rec.settle_state != 'draft' for rec in self):
        raise UserError(_("Chi settlement o 'draft' moi xoa duoc."))
    return super().unlink()
```

#### 10.5.3. Record rule va dai so cua no

Ba quy tac cua Odoo phai thuoc truoc khi doc phan nay, vi hau het loi ACL deu tu hieu sai chung:

1. Rule **global** (`groups` rong) duoc **AND** vao moi truy van, cho moi user.
2. Rule cua **cung mot nhom** duoc **AND** voi nhau.
3. Rule cua **cac nhom khac nhau** duoc **OR** voi nhau, roi ket qua **AND** voi cac rule global.

Eval context cua `domain_force` trong Odoo 19 la **dung ba khoa** (`base/models/ir_rule.py:38-51`):
`user`, `company_ids`, `company_id`. **Khong co `time`, khong co `datetime`.** Mot rule viet
`('expiry_datetime', '>', time.strftime(...))` se raise luc validate domain.

```xml
<record id="rule_settlement_company" model="ir.rule">
    <field name="name">Settlement: multi-company</field>
    <field name="model_id" ref="model_blockchain_settlement"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    <field name="global" eval="True"/>
</record>

<record id="rule_account_company" model="ir.rule">
    <field name="name">Wallet: multi-company (global)</field>
    <field name="model_id" ref="model_blockchain_account"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    <field name="global" eval="True"/>
</record>

<record id="rule_account_own_wallet" model="ir.rule">
    <field name="name">Wallet: viewer chi thay vi cua chinh minh</field>
    <field name="model_id" ref="model_blockchain_account"/>
    <field name="groups" eval="[(4, ref('group_blockchain_viewer'))]"/>
    <field name="domain_force">
        ['|', ('user_id', '=', user.id), ('partner_id', '=', user.partner_id.id)]
    </field>
</record>

<record id="rule_account_operator_scope" model="ir.rule">
    <field name="name">Wallet: operator thay vi nghiep vu, khong thay treasury/relay/admin</field>
    <field name="model_id" ref="model_blockchain_account"/>
    <field name="groups" eval="[(4, ref('group_blockchain_operator'))]"/>
    <field name="domain_force">[('role', 'not in', ['treasury', 'relay', 'admin'])]</field>
</record>

<record id="rule_account_manager_all" model="ir.rule">
    <field name="name">Wallet: manager thay tat ca trong company</field>
    <field name="model_id" ref="model_blockchain_account"/>
    <field name="groups" eval="[(4, ref('group_blockchain_manager'))]"/>
    <field name="domain_force">[(1, '=', 1)]</field>
</record>

<record id="rule_account_auditor_all" model="ir.rule">
    <field name="name">Wallet: auditor doc tat ca</field>
    <field name="model_id" ref="model_blockchain_account"/>
    <field name="groups" eval="[(4, ref('group_blockchain_auditor'))]"/>
    <field name="domain_force">[(1, '=', 1)]</field>
    <field name="perm_write" eval="False"/>
    <field name="perm_create" eval="False"/>
    <field name="perm_unlink" eval="False"/>
</record>

<record id="rule_transaction_via_settlement" model="ir.rule">
    <field name="name">Transaction: thay qua settlement cua company minh</field>
    <field name="model_id" ref="model_blockchain_transaction"/>
    <field name="groups" eval="[(4, ref('group_blockchain_viewer'))]"/>
    <field name="domain_force">
        ['|', ('settlement_ids', '=', False),
              ('settlement_ids.company_id', 'in', company_ids)]
    </field>
</record>
```

**Sua mot loi cua ban 1.** Ban 1 chi co hai rule tren `blockchain.account`, ca hai deu chua
`('company_id','in',company_ids)` va **khong** co rule nao cho manager. Vi quy tac 3, mot user
`group_blockchain_manager` (ke thua treasury → operator → viewer) chi nhan OR cua hai rule kia →
**manager khong nhin thay vi treasury**, tuc khong nhin thay chinh cai vi minh phai quan ly. Ban 2 tach
dieu kien company ra rule **global** (khong lap lai trong tung rule nhom) va them
`rule_account_manager_all` + `rule_account_auditor_all`.

Luu y Odoo 19 doi `res.users.groups_id` → **`group_ids`**; code Python kiem tra quyen phai dung
`user.group_ids` (hoac `user.has_group('...')`), con `res.groups.implied_ids` giu nguyen ten.

#### 10.5.4. Bao ve cot: `field.groups`, va hanh vi chinh xac o Odoo 19

Record rule loc **dong**, khong loc **cot**. Bao ve `signer_ref` bang `groups=` **trong dinh nghia field**
(khong chi trong view):

```python
signer_ref = fields.Char(groups='dms_blockchain.group_blockchain_manager')
```

Hanh vi chinh xac, kiem tren `odoo/orm/models.py`:

| Cach goi | Ket qua khi khong du quyen |
|---|---|
| `record.read()` (khong truyen `fields`) | Cot bi **loai khoi ket qua**. `check_field_access_rights` tra ve danh sach field doc duoc (dong 3453-3459). |
| `record.read(['signer_ref'])` | **`AccessError`** (dong 3465 → `_check_field_access` → raise). |
| `search_read` co `signer_ref` trong `fields` | `AccessError` (qua `_field_to_sql` dong 2928). |
| `search([('signer_ref','=',x)])` | `AccessError` — domain cung di qua `_field_to_sql`. |
| `write({'signer_ref': ...})` | `AccessError` (dong 3553). |
| `env.su` / `sudo()` | **Bo qua hoan toan** (`if not field.groups or self.env.su: return True`). |
| Field `related`/`_inherits` tro toi no | Ke thua `groups` (`fields.py:777` `_related_groups`). |

Ban 1 viet "cot `signer_ref` khong xuat hien trong ket qua `read()`" — **dung mot nua**. Hanh vi im lang do
la cua Odoo <= 16; tu 17 tro di, goi ro ten field bi cam la `AccessError`. Client phai biet dieu do, neu
khong mot man hinh danh sach cua mobile app se vo 403 thay vi thieu mot cot.

Con mot muc manh hon: **`groups = '.'` (hang `NO_ACCESS` o `models.py:122`)** — khong nhom nao doc duoc, ke ca
`group_system`, tru `sudo()`. Dung cho field khong bao gio duoc lo ra RPC:

```python
signature_hex = fields.Char(groups='.', readonly=True)   # chi server-side doc
```

Va lop cuoi cung, khong phai ACL: **khong bao gio de khoa vao DB.** `signer_ref` la mot **handle**; ke lay
duoc no ma khong lay duoc HSM thi khong ky duoc gi.

---

### 10.6. Be mat RPC cong khai (CLAUDE.md §6)

#### 10.6.1. Bang method

Moi entry point: khong bat dau bang `_`, khong `@api.private`, phuc vu ca hai duong, **khong nhan tham so
`company_id`/`allowed_company_ids`** — pham vi cong ty suy ra tu `self.env.companies`.

| Model | Method | `@api.readonly` | Nhom toi thieu | Tra ve |
|---|---|---|---|---|
| `blockchain.chain` | `blockchain_capabilities()` | co | viewer | `{'enabled','chains','payment_mode','server_time'}` |
| `blockchain.chain` | `blockchain_finality_state(chain_code)` | co | viewer | `{'head_block','final_block','lag_blocks','state'}` |
| `blockchain.account` | `blockchain_my_accounts()` | co | viewer | vi cua chinh user |
| `blockchain.account` | `blockchain_bind_challenge(chain_code, address)` | **khong** | operator | nonce + message de ky |
| `blockchain.account` | `blockchain_bind_address(chain_code, address, signature_hex)` | khong | operator | binh chung so huu roi tao account |
| `blockchain.settlement` | `blockchain_submit_settlement(**kw)` | khong | operator | `{'name','settle_state','needs_approval'}` |
| `blockchain.settlement` | `blockchain_settlement_status(origin_producer, origin_key)` | co | viewer | `{'settle_state','tx_hash','confirmations','is_paid'}` |
| `blockchain.settlement` | `blockchain_authorize_payout(origin_producer, origin_key)` | khong | **treasury** | `draft → authorized` hoac tao approval request |
| `blockchain.approval.request` | `blockchain_approve(request_id, decision, note=None)` | khong | **approver** | quorum counter |
| `blockchain.metatx` | `blockchain_quote_metatx(**kw)` | co | operator | phi uoc tinh + `expiry_datetime` + `digest_hash` de vi ky |
| `blockchain.metatx` | `blockchain_attach_signature(digest_hash, signature_hex)` | khong | operator | vi ky ngoai, server khong giu khoa |
| `blockchain.relayer` | `blockchain_register_relayer(name, addresses, contact_url)` | khong | **relayer_admin** | vao `allowlist_state='probation'` |
| `blockchain.zether.account` | `zether_account_bootstrap(purpose)` (§02) | khong | operator | |
| `blockchain.event` | `chain_event_ingest(caip2, events)` (§11.11) | khong | worker service account | `{'accepted','duplicate','cursor_block'}` |

`@api.readonly` khong phai trang tri: `rpc/controllers/json2.py:53` dat `readonly=_web_json_2_rpc_readonly`,
ham nay do `method._readonly` de quyet dinh cap **cursor read-only** (co the tro toi replica). Mot method
doc ma quen `@api.readonly` van chay dung nhung an mot connection ghi. Mot method ghi ma **lo** danh
`@api.readonly` se raise luc `write()` — de phat hien, nhung tot nhat la co test.

#### 10.6.2. Company: quy tac dung, khac voi quy tac ban 1 viet

Ban 1 viet: *"khong doc `allowed_company_ids` tu payload RPC"*. Trong thuc te ta **khong the** khong doc:
`Json2Dispatcher` tao `Model = request.env[__model__].with_context(context)` voi `context` do client gui, va
`Environment.companies` doc `allowed_company_ids` tu context. Nhung no **an toan**, va ly do la day
(`odoo/orm/environments.py:266-272`):

```python
company_ids = self.context.get('allowed_company_ids', [])
user_company_ids = self.user._get_company_ids()
if company_ids:
    if not self.su:
        if set(company_ids) - set(user_company_ids):
            raise AccessError(self._("Access to unauthorized or invalid companies."))
    return self['res.company'].browse(company_ids)
```

Client **thu hep** duoc pham vi (hop le, huu ich), khong **mo rong** duoc. Vay quy tac dung khong phai
"bo qua context" ma la ba dieu nay:

1. **Khong bao gio nhan `company_id` lam tham so cua method.** Mot tham so nhu vay bo qua toan bo doan check
   tren. `self.env.company` va `self.env.companies` la nguon duy nhat.
2. **Khong bao gio `sudo()` mot method resolve company tu context.** Docstring cua `companies` noi thang:
   *"No sanity checks applied in sudo mode!"*. Neu can `sudo()` (vi du de ghi `ir.cron`), `sudo()` **dung
   mot thao tac do**, khong `sudo()` ca method.
3. **Ghi `company_id` no ra tren record khi tao**, khong de mac dinh chay theo context cua request sau.

Ban 1 con co mot verification item sai theo do (§10.11 muc 6 cu). Da sua.

#### 10.6.3. Hai duong, hai kieu loi. Client phai biet ca hai.

`rpc/controllers/json2.py` nhan **chi kwargs** (`ids`, `context`, va `**kwargs`) va goi
`signature.bind(records, **kwargs)`. He qua bat buoc cho moi method cong khai:

- **Moi tham so phai co ten va phai goi duoc bang keyword.** Khong dat `*args`. Khong dua vao thu tu.
- Method `@api.model` ma client gui kem `ids` khong rong → **HTTP 422** (`UnprocessableEntity`).
- Model khong ton tai / method private / `@api.private` → **404** hoac `AccessError`
  (`service/model.py:45-71`).

Bang loi day du (`odoo/exceptions.py` + `odoo/http.py:2674-2694`):

| Exception | `/web/dataset/call_kw` | `/json/2` |
|---|---|---|
| `UserError`, `ValidationError` | HTTP **200** + JSON-RPC `error` | HTTP **422** |
| `AccessError`, `AccessDenied` | 200 + `error` | **403** |
| `MissingError` | 200 + `error` | **404** |
| `LockError` | 200 + `error` | **409** |
| Exception khac | 200 + `error` | **500** |

**Sua so voi ban 1**, von khang dinh `UserError` cho HTTP 200 "khong phai traceback" — dung cho `call_kw`,
**sai cho `/json/2`** (422). Mobile client xu ly HTTP status phai coi 422 la "loi nghiep vu, doc `message`",
khong phai "server hong, retry".

`LockError` → 409 la dung ngu nghia cho race idempotency, va nen dung thay `UserError` o do.

#### 10.6.4. Mau chuan: entry point mong + logic private

```python
class BlockchainSettlement(models.Model):
    _inherit = 'blockchain.settlement'

    @api.model
    def blockchain_submit_settlement(self, origin_producer, origin_key, use_case, direction,
                                     chain_code, token_symbol, amount_base, payee,
                                     confidential=False, origin_model=None, origin_id=None,
                                     meta=None):
        """POST /web/dataset/call_kw/blockchain.settlement/blockchain_submit_settlement
           POST /json/2/blockchain.settlement/blockchain_submit_settlement

        Idempotent theo (env.company, origin_producer, origin_key). Goi lai KHONG tao ban ghi thu hai.
        KHONG nhan company_id: cong ty lay tu self.env.company (§10.6.2).
        Moi tham so goi duoc bang keyword: /json/2 chi truyen kwargs.
        """
        return self._submit(
            company=self.env.company, origin_producer=origin_producer, origin_key=origin_key,
            use_case=use_case, direction=direction, chain_code=chain_code,
            token_symbol=token_symbol, amount_base=amount_base, payee=payee,
            confidential=confidential, origin_model=origin_model, origin_id=origin_id,
            meta=meta or {})

    def _submit(self, company, origin_producer, origin_key, **kw):
        if not self.env['blockchain.chain']._enabled_chains(company):
            raise UserError(_('Blockchain settlement chua duoc cau hinh '
                              '(khong co chain nao o trang thai enabled).'))
        domain = [('company_id', '=', company.id),
                  ('origin_producer', '=', origin_producer),
                  ('origin_key', '=', origin_key)]
        existing = self.sudo().search(domain, limit=1)
        if existing:
            return existing._as_dict()          # idempotent
        try:
            rec = self.create(self._prepare_vals(company, origin_producer, origin_key, **kw))
        except psycopg2.errors.UniqueViolation as exc:
            raise LockError(_('Yeu cau nay dang duoc xu ly, thu lai sau it giay.')) from exc
        rec._enqueue_outbox()                   # KHONG goi HTTP o day. Xem §10.4.11.
        return rec._as_dict()
```

Ba diem khong duoc bo:

1. **`search` truoc `create` khong du.** Hai worker song song deu `search` thay rong roi cung `create`.
   `UNIQUE(company_id, origin_producer, origin_key)` la lop chan cuoi, va no nem `UniqueViolation` —
   phai bat va doi thanh `LockError` (409), khong de no thanh 500.
2. **`self.sudo().search`** cho buoc dedup: neu khong, mot user khong doc duoc ban ghi cu se tao ban thu hai.
   Nhung chi `sudo()` **dung cau search do**, va chi tra `_as_dict()` cua ban ghi cung company.
3. **`_enqueue_outbox()` chu khong `requests.post()`.** Xem §10.4.11.

`blockchain_authorize_payout` la **cong duy nhat** dua tien ra khoi he thong va no o mot method rieng, khong
phai mot tham so `auto_authorize=True` cua `blockchain_submit_settlement` — mot tham so boolean nhu vay se bi
client truyen `True` trong vong mot tuan.

#### 10.6.5. Versioning va tuong thich nguoc

Method cong khai la **hop dong voi mobile app da phat hanh**. Ba quy tac:

1. Chi **them** tham so co gia tri mac dinh. Doi ten hay doi thu tu la breaking (client cu goi bang
   positional qua `call_kw`).
2. Khoa moi trong dict tra ve la khong-breaking; **doi/xoa** khoa la breaking.
3. Khi that su phai doi: method moi ten `..._v2`, giu method cu goi vao `_v2` voi mac dinh, va dat
   `deprecated_since` trong docstring. Xoa sau 2 chu ky release, khong som hon.

---

### 10.7. `ir.cron`

Moi body nam trong method cua model; XML dung **mot** dong (eval context khong co `fields`, khong co
`relativedelta`).

| Cron | Chu ky | Goi | Model |
|---|---|---|---|
| Outbox dispatch | 1 phut | `model._cron_outbox_dispatch()` | `blockchain.outbox.job` |
| Outbox reap (`sent` treo) | 5 phut | `model._cron_outbox_reap()` | `blockchain.outbox.job` |
| Receipt poll | 1 phut | `model._cron_poll_receipts()` | `blockchain.transaction` |
| Finality gate | 1 phut | `model._cron_finality_gate()` | `blockchain.transaction` |
| Reorg watch | 2 phut | `model._cron_reorg_watch()` | `blockchain.transaction` |
| Metatx expiry sweep | 5 phut | `model._cron_expire_metatx()` | `blockchain.metatx` |
| Approval expiry | 10 phut | `model._cron_expire_approvals()` | `blockchain.approval.request` |
| Relayer nonce/balance reconcile | 5 phut | `model._cron_relay_reconcile()` (§06) | `blockchain.relayer.account` |
| Zether epoch rollOver | 1 phut | `model._cron_zether_rollover()` | `blockchain.zether.account` |
| RPC endpoint health probe | 2 phut | `model._cron_probe_endpoints()` | `blockchain.rpc.endpoint` |
| Custody probe + rotation due | 1 gio | `model._cron_custody_probe()` (§07) | `blockchain.custody.provider` |
| Registry reconcile | 1 gio | `model._cron_reconcile_registry()` (§02) | `blockchain.zether.account` |
| Attachment GC cho trace qua han | hang ngay | `model._cron_gc_traces()` | `blockchain.transaction` |

```xml
<record id="cron_finality_gate" model="ir.cron">
    <field name="name">Blockchain: finality gate</field>
    <field name="model_id" ref="model_blockchain_transaction"/>
    <field name="state">code</field>
    <field name="code">model._cron_finality_gate()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">minutes</field>
    <field name="active" eval="False"/>
</record>
```

`active=False` mac dinh cho **moi** cron. Cron duoc bat khi chain dau tien chuyen sang `state='enabled'`:

```python
def write(self, vals):
    res = super().write(vals)
    if 'state' in vals:
        self._toggle_crons()
    return res

def _toggle_crons(self):
    """ir.cron chi cho base.group_system (base/security/ir.model.access.csv dong 5) nen BAT BUOC sudo.
    Chi sudo dung thao tac nay, khong sudo ca method goi den no."""
    active = bool(self.env['blockchain.chain'].sudo().search_count([('state', '=', 'enabled')]))
    crons = self.env['ir.cron'].sudo().search([
        ('id', 'in', [self.env.ref(x).id for x in self._cron_xmlids() if self.env.ref(x, False)])])
    crons.filtered(lambda c: c.active != active).write({'active': active})
```

**Ba dieu ban 1 khong noi:**

1. **`sudo()` la bat buoc**, khong phai tuy chon (gia dinh an A12).
2. **Cron phai tu gioi han lo va tu commit.** `ir.cron` khong chay hai instance cua cung mot cron song song
   (co row lock), nhung mot lo qua lon giu lock qua ca chu ky sau va lam ton dong. Mau:

   ```python
   @api.model
   def _cron_finality_gate(self, limit=500):
       records = self.search([('tx_state', 'in', ('mined', 'soft_final'))], limit=limit)
       for rec in records:
           rec._advance_finality()
           self.env.cr.commit()        # tung ban ghi: mot loi khong keo do ca lo
       if len(records) == limit:
           self.env.ref('dms_blockchain.cron_finality_gate')._trigger()   # chay tiep ngay
   ```

   `_trigger()` la co che cua `ir.cron` de xep mot lan chay ngay lap tuc (bang `ir.cron.trigger`), thay vi
   doi het chu ky. Odoo 19 con co `ir.cron.progress` cho cron dai — dung khi mot lo vuot 60 giay.
3. **`env.cr.commit()` trong cron la hop le va can thiet**; trong mot request HTTP thi khong. Do la khac
   biet duy nhat dang ke giua code cron va code RPC trong addon nay.

---

### 10.8. Cau hinh, bi mat, va payment integration mode

#### 10.8.1. Bi mat

Khong co field nao chua bi mat. `ir.config_parameter` chua **tham chieu**, con bi mat nam ngoai DB
(KMS/HSM/vault/bien moi truong). Khoa dung:

| Key `ir.config_parameter` | Gia tri | Bi mat? |
|---|---|---|
| `blockchain.default_chain_code` | `gnosis` | khong |
| `blockchain.relay_worker.<chain_code>.base_url` | URL noi bo (mTLS) | khong |
| `blockchain.relay_worker.token_ref` | ten bien moi truong / vault path | khong (con tro) |
| `blockchain.rpc.<endpoint_ref>.url` | URL day du **co** API key | **CO** → xem duoi |
| `blockchain.signer.<signer_ref>.backend` | `awskms`/`fireblocks`/`turnkey`/`local_dev` | khong |
| `blockchain.finality.override.<chain_code>` | so block ghi de | khong |
| `blockchain.payment.ref_mode` | `hash` \| `plain` (§09) | khong |

**Mot canh bao ban 1 khong noi: `ir.config_parameter` KHONG phai noi de tien bi mat.** Bang
`ir_config_parameter` nam trong DB, nam trong moi ban backup, va doc duoc boi bat ky ai co `group_system`
(hoac bat ky SQL injection nao). Odoo chi bao ve no bang mot ACL. Vay:

- URL RPC **co API key** khong duoc nam trong `ir.config_parameter`. Dat `endpoint_ref = 'gnosis_primary'`
  va de URL that trong bien moi truong cua relay worker. Odoo khong can biet URL — Odoo chi goi worker.
- Neu mot deployment nho van muon de trong DB, do la mot **quyet dinh co y thuc** phai ghi vao runbook, va
  khoa do phai duoc lam ro trong bang tren. Khong de no thanh mot tai nan.

`res.config.settings` phoi cac khoa nay ra UI bang `config_parameter=`, bao ve bang
`group_blockchain_manager`. Bay: **gia tri `ir.config_parameter` luon la chuoi.** Mot
`fields.Integer(config_parameter=...)` doc lai `'0'` la truthy neu ai do `get_param()` truc tiep —
luon `int(... or 0)` khi doc.

#### 10.8.2. Payment integration mode

Ban 1 liet ke 5 mode. §09.2 liet ke 13. Ca hai deu dung o tang khac nhau, va §10 chot cach hoa giai:

- **5 mode cua brief la 5 *ho*** (`payment.provider` in-house / acquirer ngoai / `account.payment` truc tiep /
  sub-ledger / ket hop). Do la truc chinh sach.
- **13 mode cua §09.2 la 13 *handler cu the*** trong cac ho do. Do la truc hien thuc.
- **Noi luu la `blockchain.money.flow`** (§09.4), mot record cho mot `(company, flow_code, chain)`, voi
  `handler_code` la Selection mo rong bang `selection_add`. **Khong** phai mot khoa
  `blockchain.payment_integration_mode` toan he thong nhu ban 1 viet — mot deployment day du chay ba mode
  cung luc (locked #8: "hoac chon theo tung luong tien"), nen mot khoa don khong dien dat duoc.

| Ho | Co che | Module can | Khi nao dung |
|---|---|---|---|
| **1. `payment.provider` in-house** | `selection_add=[('chain','On-chain')]`; `_send_payment_request` tao settlement; `_set_pending` khi `broadcast`; **`_set_done` CHI trong Finality Gate**; `_set_error` khi `reverted` | `dms_blockchain_payment` | Thanh toan end-user co gio hang / portal |
| **2. Acquirer crypto ben ngoai** | Provider cua ben thu ba; chain chi la lop doi soat, so khop bang `origin_key` **va** webhook | `dms_blockchain_payment` | Khi can fiat off-ramp va KYC do acquirer lo |
| **3. `account.payment` truc tiep** | Bo qua module `payment`; settlement `final` sinh `account.payment` da reconcile | `dms_blockchain_account` | B2B, khong gio hang, ke toan can but toan tung giao dich |
| **4. Sub-ledger doi soat theo lo** (mac dinh) | `blockchain.settlement` la so cai doc lap; doi soat theo lo sang `account.move` cuoi ky (§15.4) | khong can gi | Loyalty points, va moi deployment chua co `account` |
| **5. Ket hop theo luong tien** | `blockchain.money.flow` mot record cho moi dong tien | ca hai bridge | Deployment day du |

Ho 4 la mac dinh vi no la ho duy nhat chay duoc voi `depends = ['base','mail']`.
`blockchain.payment.handler.none` la handler mac dinh, va no **khong lam gi** — mot settlement van chay
het vong doi va van `final`, chi khong co hieu ung ke toan nao.

**Doi mode la mot chieu.** Settlement da doi soat theo lo khong tu sinh nguoc ra `account.move` don le. Mot
`@api.constrains` tren `ir.config_parameter` khong chay, nen chan trong `set_values()` cua
`res.config.settings` **va** trong `write()` cua `blockchain.money.flow`:

```python
@api.constrains('handler_code')
def _check_handler_switch(self):
    for flow in self:
        if flow._origin.handler_code in (False, 'none'):
            continue
        n = self.env['blockchain.settlement'].search_count([
            ('money_flow_id', '=', flow.id), ('settle_state', '=', 'final')])
        if n:
            raise ValidationError(_(
                "Da co %(n)s settlement 'final' tren dong tien nay. Doi handler se lam "
                "lech doi soat. Tao mot money flow moi va tat cai cu.", n=n))
```

#### 10.8.3. Anh xa trang thai cho ho 1 — cho de sai nhat, va mot bay da kiem

| `settle_state` | `payment.transaction` |
|---|---|
| `draft`, `authorized`, `submitted` | `draft` |
| `broadcast`, `pending_finality` | `_set_pending()` |
| `final` | `_set_done()` roi `_post_process()` |
| `failed`, `expired` | `_set_error(state_message)` |
| `reversed` | settlement moi + refund tx, **khong** `_set_canceled()` tren tx cu |

Vi cua nguoi dung bao "success" ngay khi tx duoc mine. Do la thoi diem `_set_pending`, khong phai `_set_done`.
UI phai noi "dang cho xac nhan mang luoi (N/M block)" chu khong duoc noi "da thanh toan".

**Bay da kiem tren source `payment/models/payment_transaction.py`:**

- Chu ky la **keyword-only** cho ba ham: `_set_pending(*, state_message=None, extra_allowed_states=())`,
  `_set_authorized(*, ...)`, `_set_done(*, ...)`. Nhung `_set_error(state_message, extra_allowed_states=())`
  la **positional**. Goi sai kieu se `TypeError`, khong phai loi nghiep vu.
- `allowed_states` cua `_set_error` la `('draft','pending','authorized')`. **`done` KHONG nam trong do.**
  Va `_update_state` (dong 1035+) **khong raise** khi trang thai nguon sai — no chi log warning va bo qua.
  He qua truc tiep va nghiem trong: **sau mot reorg, goi `_set_error` tren mot tx da `done` khong lam gi ca,
  va khong ai biet.** Do la ly do Finality Gate phai dung nguong **hard**, khong phai soft; va la ly do
  `on_reorg` cua handler (§09.4) bat buoc phai hien thuc bang mot **giao dich hoan tien / but toan dao**,
  khong bang mot `write` trang thai.
- `_set_done` allowed tu `('draft','pending','authorized','error')` — nen goi `_set_done` hai lan la an toan
  (lan hai roi vao `txs_already_processed`, log INFO). Idempotency o day la mien phi; hay dua vao no.

---

### 10.9. Multi-company

- **Co `company_id`** (bat buoc, index, rule global `[('company_id','in',company_ids)]`):
  `blockchain.settlement`, `.batch`, `blockchain.netting.set`, `blockchain.account`, `blockchain.zether.account`,
  `blockchain.zether.entry`, `blockchain.custody.provider`, `blockchain.approval.*`, `blockchain.outbox.job`,
  `blockchain.security.event`, `blockchain.watched.address`, `blockchain.relayer` khi `kind='internal'`.
- **Khong co `company_id`** (ha tang dung chung, loc kha dung bang `company_ids` M2M): `blockchain.chain`,
  `blockchain.rpc.endpoint`, `blockchain.contract.deployment`, `blockchain.contract.abi`,
  `blockchain.token`, `blockchain.transaction`, `blockchain.event`, `blockchain.index.cursor`.
- `blockchain.transaction` khong company-scoped vi **mot tx co the phuc vu nhieu settlement cua nhieu cong ty**
  (batch, §15.7). Kha nang doc suy ra tu settlement lien ket, qua `settlement_ids` (§10.4.6) va rule
  `rule_transaction_via_settlement` (§10.5.3). Nhanh `('settlement_ids','=',False)` cho phep doc tx chua gan
  settlement — can thiet cho indexer va cho tx he thong (deploy, refill).
- **Mot `blockchain.account` thuoc dung mot cong ty.** Ban 1 viet o day mot cau lan lon
  ("hai ban ghi, cung `address`, khac `chain_id`?"). Noi lai cho ro: `UNIQUE(chain_id, address)` nghia la
  **mot dia chi tren mot chain chi co mot ban ghi, va ban ghi do thuoc dung mot company**. Neu hai phap nhan
  muon dung chung mot vi treasury, ho khong the — va do la co y: mot vi chung giua hai phap nhan la mot van de
  phap ly (ai so huu tai san khi mot ben pha san?) truoc khi la mot van de ky thuat. Neu that su can, cach
  dung la **hai vi khac nhau** tren cung chain, hoac mot multisig ma ca hai la signer, khai bao la
  `account_kind='multisig'` cho mot company va mot `blockchain.security.event` ghi lai thoa thuan.
- **Isolation cua custody theo tenant** (§07.11) la tang thu hai: `signer_ref` cua company B gui qua cert
  mTLS cua company A phai bi tu choi **o signer service**, khong chi o Odoo. Odoo khong phai bien tin cay.

---

### 10.10. Suy giam an toan

Ban 1 chi xet mot truong hop ("chua cau hinh chain nao"). Co bon truong hop, va ba trong so do xay ra tren
mot he thong **da** chay.

#### 10.10.1. Chua cau hinh chain nao (cai xong, chua bat gi)

1. **Khong co du lieu chain mac dinh o trang thai `enabled`.** `data/blockchain_chain_data.xml` nap Gnosis,
   Celo, va mot mau private voi `state='draft'`, `noupdate="1"`. Khong co RPC endpoint (khong URL nao dung duoc).
2. **Moi cron `active=False`** (§10.7). Khong cron nao chay dinh ky de roi log mot exception moi phut.
3. **Moi entry point RPC tra loi co cau truc.** `blockchain_capabilities()` tra
   `{'enabled': False, 'reason': 'no_chain_enabled', 'chains': []}` (**khong** raise — client dung no de an
   nut). `blockchain_submit_settlement` raise `UserError` co ma (→ 422 tren `/json/2`, 200+error tren `call_kw`).
4. **Menu an.** Menu goc `groups="group_blockchain_viewer"`, va khong nhom nao duoc gan cho ai luc cai
   (`res.groups.user_ids` rong trong `blockchain_groups.xml`). Admin phai chu dong cap.
5. **`dms_blockchain_payment` khong tao `payment.provider` o trang thai `enabled`.** Provider mac dinh
   `state='disabled'`, `is_published=False`.
6. **Bridge DMS la no-op.** `dms.trade.settlement.action_settle()` van chay nguyen nhu cu; bridge chi **them**
   mot buoc khi `_enabled_chains()` khong rong. Cai bridge len production dang chay phai la mot no-op cho toi
   khi ai do bat chain dau tien.

#### 10.10.2. Chain `enabled` nhung relay worker khong voi toi duoc

Day la truong hop hay xay ra nhat va ban 1 khong noi. Outbox (§10.4.11) lam no lanh tinh: settlement dung o
`submitted`, job o `queued` voi backoff, khong mat gi. Nhung **phai co mot cai gi do keu**:

```python
@api.model
def _cron_outbox_reap(self):
    stuck = self.search_count([('job_state', '=', 'queued'), ('attempt_count', '>=', 3)])
    if stuck >= 10:
        self.env['blockchain.chain'].sudo().search([('state', '=', 'enabled')]).write(
            {'state': 'degraded'})
        self.env['blockchain.security.event'].sudo().create({
            'severity': 'high', 'event_code': 'relay_worker_unreachable',
            'detail_json': {'stuck_jobs': stuck}})
```

`degraded` (khac `halted`) nghia la: khong nhan settlement moi qua RPC, nhung van tiep tuc theo doi va chot
finality cho nhung cai dang bay. Mot chain `halted` thi dung ca hai.

#### 10.10.3. Chain `enabled` nhung RPC noi doi hoac tut hau

`health_state='diverging'` tren endpoint (§10.4.2b) khong tu hoi phuc. Neu **moi** endpoint cua mot chain
`diverging` hoac `down`, chain tu chuyen `degraded` va Finality Gate **dung lai** — khong duoc chot `final`
tren du lieu tu mot RPC dang noi doi. Do la mot lua chon: tha treo con hon chot sai, vi `final` khong rut lai
duoc (§10.8.3).

#### 10.10.4. Go module

`uninstall_hook` bat buoc, va no **chan** thay vi don:

```python
def _uninstall_guard(env):
    n = env['blockchain.settlement'].sudo().search_count([('settle_state', '=', 'final')])
    if n and not env['ir.config_parameter'].sudo().get_param('blockchain.allow_destructive_uninstall'):
        raise UserError(_(
            "Co %(n)s settlement da 'final'. Go module se xoa vinh vien so cai doi chieu voi chain. "
            "Dat ir.config_parameter 'blockchain.allow_destructive_uninstall' = '1' neu that su muon.", n=n))
```

Ly do khong tu dong export: mot `uninstall_hook` sinh file la mot hanh vi bat ngo trong mot transaction
dang xoa bang. Chan, bat nguoi doc thong bao, va de ho export bang cong cu binh thuong truoc.

---

### 10.11. Kiem chung bat buoc

Moi muc duoi la mot lenh chay duoc hoac mot test file, khong phai mot y dinh.

1. **SQL object that su ton tai.** `_sql_constraints` dang list bi Odoo 19 bo qua hoan toan, nen khong tin code:
   ```sql
   SELECT conrelid::regclass AS tbl, conname, contype, pg_get_constraintdef(oid)
   FROM pg_constraint WHERE conrelid::regclass::text LIKE 'blockchain\_%' ORDER BY 1,2;
   SELECT tablename, indexname, indexdef FROM pg_indexes
   WHERE tablename LIKE 'blockchain\_%' AND indexdef ILIKE '%UNIQUE%';
   ```
   Doi chieu voi danh sach o §10.4. Test tu dong: `tests/test_sql_objects.py` doc `pg_constraint` va so voi
   mot danh sach hardcode; test fail khi ai do them constraint ma quen cap nhat danh sach.
2. **Standalone that.** Tren mot DB **khong co `dms`**: `odoo -d test_bare -i dms_blockchain --stop-after-init`
   → 0 ERROR, 0 CRITICAL. Them `grep -c "no access rules" log` phai bang 0.
3. **Khong con chuoi `dms` trong core.** `grep -rn "'dms\." dms_blockchain/ | grep -v dms_blockchain` → rong.
4. **Auto-install.** Cai `dms` → `SELECT name, state FROM ir_module_module WHERE name LIKE 'dms_blockchain%';`
   → `dms_blockchain_bridge` = `installed`.
5. **Go `dms`** → bridge bi go, `SELECT count(*) FROM blockchain_settlement;` khong doi.
6. **Idempotency.** Goi `/json/2/blockchain.settlement/blockchain_submit_settlement` **hai lan** cung
   `(origin_producer, origin_key)` → mot ban ghi. Chay hai lan **song song** (hai process) → mot ban ghi
   va mot HTTP 409.
7. **Company scope.** Goi cung method voi `context={'allowed_company_ids': [<id company khong thuoc user>]}`
   → **HTTP 403** (`AccessError` tu `Environment.companies`). Goi voi mot company hop le cua user →
   settlement thuoc dung company do. **(Ban 1 mong doi "tham so bi bo qua" — sai, xem §10.6.2.)**
8. **Field groups.** User chi co `group_blockchain_viewer`:
   - `read()` khong tham so → khong co khoa `signer_ref` trong dict.
   - `read(['signer_ref'])` → **`AccessError`** (khong phai dict thieu khoa).
   - `search([('signer_ref','!=',False)])` → `AccessError`.
9. **Groups di qua `_inherits`.** Cung user do doc `blockchain.relayer.account` → `signer_ref` van bi chan.
   Neu **khong** bi chan, `_inherits` la mot duong ro va phai bo, thay bang M2O tuong minh.
10. **Khong duong nao ghi `final` ngoai gate.** `write({'settle_state':'final'})` truc tiep → `UserError`.
    `write` voi `context={'blockchain_gate': True}` do client gui → **van** `UserError` (sentinel object).
11. **Chuyen trang thai.** Bang tham so hoa `_ALLOWED`: moi cap `(a, b)` khong nam trong bang phai raise.
12. **Cron.** Bat mot chain → `SELECT name, active FROM ir_cron WHERE name LIKE 'Blockchain:%';` tat ca
    `active = true`. Tat chain cuoi cung → tat ca `false`. Chay `_toggle_crons` bang mot user chi co
    `group_blockchain_manager` (khong `group_system`) → khong `AccessError`.
13. **Outbox.** Kill relay worker, goi submit → settlement `submitted`, job `queued`, khong exception.
    Bat lai worker → job `acked` trong 1 chu ky cron. Kill Odoo giua `sent` → job vao `dead`, khong gui lai.
14. **Non-EVM.** Tao `blockchain.account` voi `chain_family='cosmwasm'` va mot dia chi bech32 90 ky tu →
    luu **du 90 ky tu** (chung minh khong con `size=`). Doc lai va so sanh chuoi.
15. **uint256.** Ghi `amount_base = '115792089237316195423570985008687907853269984665640564039457584007913129639935'`
    (2^256-1) → luu nguyen; `amount_base = '007'` → `IntegrityError` tu CHECK.
16. **Approval.** Nguoi tao settlement tu bam duyet → `UserError`. Hai user khac nhau → quorum du, `authorized`.
17. **Payment ho 1.** Sau `_set_done`, goi `_set_error` → khong doi trang thai va **co** mot warning trong log;
    test phai khang dinh handler `on_reorg` da tao mot settlement bu, khong dua vao `_set_error`.

---

### 10.12. Chi phi va do phuc tap: nhung con so quyet dinh

Tap hop lai de ke hoach trien khai co the uoc luong. Tat ca la **uoc tinh**, co so ghi kem.

| Dai luong | Gia tri | Co so |
|---|---|---|
| Gas mot ERC-20 transfer thuong | 34k-51k | 21,000 base + SSTORE 20,000 (0→nonzero) hoac 2,900 (warm) + cold SLOAD 2,100 |
| Gas mot `executeMetaTransaction` (EIP-1776) chuyen token + tra fee | 95k-140k | base 21,000 + calldata ~500 B x 16 + ecrecover 3,000 + nonce SSTORE 5,000 + 2 ERC-20 transfer |
| Gas mot Zether `transferConfidential` | **1.2M-2.5M** | ~200-350 `ecMul` x 6,000 (EIP-1108) sau khi gom multi-exp + calldata ~2.4 KB x 16. **Note ghi 180k-250k la con so cua pairing Groth16, khong phai Bulletproof.** |
| Chi phi mot metatx tren Gnosis | ~$0.0003 | 130,000 gas x ~2 gwei x 1 xDAI ≈ 1 USD |
| Chi phi mot Zether tx tren Gnosis | ~$0.004 | 2M gas x 2 gwei |
| Chi phi mot Zether tx tren Ethereum L1 (10 gwei, ETH $3,000) | **~$60** | 2M x 10e-9 x 3,000. Day la ly do locked #5. |
| Kich thuoc proof Zether (calldata BN254) | ~2.4 KB | Bang o §10.4.7 |
| Kich thuoc proof nen (32 B/diem) | 1.4-2.0 KB | Cung bang, diem nen |
| Trace EVM day du | 50-500 KB | JSON trace dien hinh |
| Do tre finality gate qua `ir.cron` | p50 30 s, **p95 90 s** | Cron toi thieu 1 phut, scheduler ~60 s |
| DB tang truong o 10k settlement/thang | ~55 MB/thang | §10.4.12 |
| Chi phi doi ten module sau deploy | ~700 dong `ir_model_data` + 24 rename bang | §10.1 |

---

### 10.13. Cau hoi con phai nguoi quyet

Khong phai thieu nghien cuu — thieu mot quyet dinh cua nguoi.

1. **`meta_nonce` tang truoc hay sau `call` trong contract EIP-1776?** (§06.10 muc 3 de mo.) Quyet dinh nay
   thay doi `blockchain.metatx.attempt_seq` co can hay khong, va co can `antiGriefBond` hay khong. **Phai
   chot truoc khi freeze ABI**, tuc truoc M1.
2. **Manager co dong thoi la treasury khong?** §10.5.1 mac dinh co. Mot to chuc co kiem toan noi bo se muon
   khong. Cau tra loi doi mot dong `implied_ids`, nhung doi sau khi da cap quyen cho nguoi that thi phai
   ra soat lai toan bo user.
3. **Nguong `amount_fiat_max_single` mac dinh la bao nhieu?** §10.4.10 chot 0 (luon can hai nguoi). Do la an
   toan nhung se lam cham loyalty 5,000 diem. Co nen mac dinh khac theo `use_case`?
4. **Gnosis `finality_hard_seconds`: 780 giay hay it hon?** Con so trong bang la uoc tinh. Phai do that
   tren mainnet (thoi gian tu `latest` den `finalized`, p99 trong 7 ngay) truoc khi `enabled`.
5. **Celo sau khi thanh L2**: `finality_mode` la `l1_batch` hay `depth`? Va `finality_hard_seconds` bang bao
   nhieu? Toan bo gia dinh BFT trong `blockchain.md` khong con dung.
6. **`origin_producer` do ai cap?** Neu client tu khai, mot client co the gia mao namespace cua client khac
   va nuot mot settlement. De xuat: `origin_producer` suy ra tu **service account** dang goi
   (`self.env.user.login`), khong nhan tu tham so. Can xac nhan vi no doi chu ky method.
7. **Retention trace 90 ngay co du cho yeu cau kiem toan tai VN?** §13 phai tra loi; §10 chi dat mac dinh.
8. **Co bo `mail.thread` khoi `blockchain.settlement` ngay tu dau khong?** Neu khoi luong du kien > 100k/thang
   thi bo ngay re hon la go sau (§10.4.12).
9. **`blockchain.money.flow` va `blockchain.approval.policy` chong lan nhau o dau?** Ca hai deu la "chinh sach
   theo (company, luong tien)". Co nen gop? De xuat: khong gop — mot cai chon **duong di cua tien**, mot cai
   chon **ai duoc bam**. Nhung phai co mot man hinh duy nhat hien ca hai, neu khong khong ai kiem tra duoc.

---

### 10.14. Cho note goc / section khac / ban 1 sai hoac thieu

**Ve `blockchain.md`:**

1. **Khong noi gi ve tang Odoo.** Toan chuong 10 cua note la kien truc off-chain/on-chain; khong model, khong
   ACL, khong bien gioi module. Section nay la phan bu, va no la phan quyet dinh xem "standalone" co thuc su
   dung duoc hay khong.
2. **Gas Zether sai mot bac do lon.** Note: "~180,000 - 250,000 gas". Thuc te 1.2M-2.5M (§10.12). Con so cua
   note la chi phi mot pairing check Groth16, khong phai chi phi verify Bulletproof.
3. **Celo: "Istanbul BFT 2.0, 5 giay, immediate finality" da loi thoi.** Celo la Ethereum L2 tren OP Stack tu
   2025. Moi con so finality cua Celo trong note phai do lai.
4. **"Simulation gate voi ty le revert 0%"** la mot muc tieu khong dat duoc, khong phai mot rang buoc thiet ke.
   Trang thai chain doi giua simulate va mine. §06.3 da noi; §10 chi ghi lai de khong ai xay UI hua 0%.
5. **Note khong noi ai duoc phep bam nut chi tien.** §10.4.10 + §10.5.1 tra loi bang maker-checker va bang
   viec tach `treasury` khoi `relayer_admin` khoi `approver`.
6. **Note gia dinh Odoo se doc duoc so tien Zether de dua vao ERP.** Khong. Neu cong ty khong giu khoa giai ma
   thi `amount_clear_base` rong **vinh vien**, va moi bao cao doanh thu tren so bao mat phai duoc thiet ke voi
   cot rong la truong hop binh thuong, khong phai loi du lieu.
7. **Note khong noi so uint256 duoc luu the nao trong PostgreSQL qua Odoo ORM.** §10.4.1 chot Char + CHECK.
   Bo qua diem nay se dan den mot cot `Float` lam tron so du token 18 decimals va khong ai phat hien cho toi
   khi doi soat lech vai wei.

**Ve cac section khac:**

8. **§02.8.5 giu `blockchain.chain.profile` la model rieng** — phai xoa, gop vao `blockchain.chain` (§10.3).
   `blockchain.zether.account.chain.profile_id` → `chain_id`. *(Ban 1 quy loi nay cho "01 §1.13" — sai dia chi.)*
9. **§08.1 dinh nghia lai `blockchain.chain` voi bo field khac** (`fee_token_mode`, `native_is_stable`,
   `finality_depth`, `state='live'`) — doi theo §10.4.2.
10. **§06.9: `runway_hours = fields.Float(compute=..., store=True, required=True, default=0.0)`** — stored
    computed field **khong** duoc nhan `default`, va `required=True` bien mot nhanh khong gan gia tri thanh
    INSERT chet. Sua: bo `default`, bo `required`, gan `rec.runway_hours = 0.0` o dong dau compute.
    Ap dung y het cho `net_wei` (§05), `divergent` (§02), `is_final` (§11), va `amount_display`,
    `fee_native_display`, `reputation_score` (section nay).
11. **§06.9 `balance_native = fields.Float(digits=(24,8))`** — so du native la uint256 wei; `Float` mat chinh
    xac tu 2^53. Doi thanh `balance_native_base = fields.Char()`.

**Ve chinh ban 1 cua section nay** (moi cai da sua o tren):

12. `size=` tren moi field hex/address — deprecated, khong ep o DB, **cat chuoi im lang** (§10.4.0(1)).
13. CHECK `^0x[0-9a-f]{40}$` vo dieu kien tren `address`, va `tx_hash size=66` — chan het 5 ho non-EVM
    (§10.4.3, §10.4.6).
14. `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` tuyet doi — lam khong the thu lai mot
    metatx het han; phai la `models.UniqueIndex` partial (§10.4.5).
15. `UNIQUE(company_id, origin_key)` thieu namespace consumer (§10.4.8).
16. `_order = 'sequence, id'` tren `blockchain.chain` ma **khong khai bao field `sequence`** (§10.4.2).
17. `amount_display = fields.Float(digits=(24,8))` — 8 chu so thap phan lam 1 wei bien mat tren token 18
    decimals; va `Float` la double trong Python du cot la `numeric` (§10.4.0(2), §10.4.1).
18. `chain_profile` ba gia tri — pha vo moi guard `== 'public'` cua §05/§08 mot cach im lang (§10.3).
19. Khong co model cho contract da deploy, nen `verifying_contract` la `Char` tu do va allowlist khong co cho
    de song (§10.4.9).
20. Khong co maker-checker; mot nguoi trong `treasury` chi duoc bat ky so tien nao (§10.4.10).
21. "Odoo goi worker qua `requests`" — mot HTTP call trong transaction; phai la outbox (§10.4.11).
22. ACL thieu rule cho manager tren `blockchain.account` → **manager khong nhin thay vi treasury** (§10.5.3).
23. "cot `signer_ref` khong xuat hien trong `read()`" — chi dung khi khong truyen `fields`; truyen ten field
    la `AccessError` (§10.5.4).
24. "khong nhan `allowed_company_ids`" — khong the khong nhan; quy tac dung la khong nhan **tham so**
    `company_id` va khong `sudo()` (§10.6.2).
25. "`UserError` cho ra HTTP 200" — dung cho `call_kw`, **422** cho `/json/2` (§10.6.3).
26. `_toggle_crons()` thieu `sudo()`; `ir.cron` la `group_system` (§10.7).
27. Mot khoa `blockchain.payment_integration_mode` toan he thong — khong dien dat duoc locked #8 ("chon theo
    tung luong tien"); phai la `blockchain.money.flow` (§10.8.2).
28. `ir.config_parameter` duoc mo ta nhu noi an toan cho tham chieu, nhung khong canh bao rang no nam trong
    moi ban backup — URL RPC co API key khong duoc o do (§10.8.1).
29. Thieu `ir.sequence` cho `blockchain.settlement.name` (`required=True, default='/'` ma khong ai dien) (§10.4.8).
30. Thieu `settlement_ids` One2many tren `blockchain.transaction` ma chinh rule multi-company cua ban 1 lai
    tham chieu toi (§10.4.6, §10.9).
31. Suy giam an toan chi xet "chua co chain"; thieu ba truong hop xay ra tren he thong dang chay: worker chet,
    RPC noi doi, go module (§10.10.2-10.10.4).
