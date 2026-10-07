> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 10. Thiết kế addon dms_blockchain: model, ACL, RPC, cấu hình

> **Bản 2 — đã qua review đối kháng.** Bản 1 dùng được về cấu trúc nhưng sai ở sáu chỗ kỹ thuật và
> giấu bẫy giả định ở mười hai chỗ. Tất cả đều được sửa ở dưới và liệt kê lại ở §10.14.
>
> Section này là **canonical** về: tên module, tên model, tên field, ACL, bề mặt RPC, cron, cấu hình.
> Section này **không** canonical về: kinh tế relayer (§05), nonce lease (§06), custody backend (§07),
> adapter interface (§08), danh sách 13 payment mode (§09), indexer/reorg (§11), kế toán (§15).
> Khi một section khác định nghĩa lại một model đã có ở đây, section đó sai và §10.3 liệt kê chỗ phải sửa.
>
> **Mọi khẳng định về API Odoo 19 trong section này đã được kiểm trên source thật ở
> `/usr/lib/python3/dist-packages/odoo` của container `odoo19-server-1`**, không lấy từ trí nhớ. Chỗ nào
> là ước tính đều ghi rõ "ước tính" và cơ sở tính.
>
> **Bản 3 — sau khi user chốt factory mở.** `_USER-DECISIONS.md` §20 đổi vai của addon này: nó không
> còn là control plane của **token của ta**, mà là control plane của **một bản triển khai dùng
> protocol mở**. Hệ quả tập trung ở ba chỗ: `blockchain.token` phải mang xuất xứ (§10.4.9),
> `blockchain.relayer` phải tách danh tính khỏi khoá ký (§10.4.x, `_USER-DECISIONS.md` §21.5), và
> `blockchain.upgrade.proposal` **bị xoá** — không còn upgrade để mà đề xuất (§01.1.11.3).

---

### 10.0. Những giả định ẩn của bản nháp, nói rõ ra

Một bản thiết kế chỉ dùng được khi người đọc biết nó đang giả định gì. Bản 1 giả định ngầm mười hai điều.
Bây giờ chúng là ràng buộc có tên, và mỗi cái đều có thể sai:

| # | Giả định ẩn | Còn nếu nó không đúng |
|---|---|---|
| A1 | Mọi địa chỉ là địa chỉ EVM (`0x` + 40 hex) | `size=42` + CHECK regex làm **không thể** lưu địa chỉ TON/Sui/Soroban/Cosmos/Hedera. Locked #4 nói 5 hệ sinh thái kia được thiết kế trên giấy **ngay bây giờ**. Xem §10.4.3 |
| A2 | `fields.Char(size=N)` chặn độ dài ở DB | **Sai.** Odoo 19: `size` là `deprecated`, cột vẫn là `VARCHAR` không giới hạn, và `convert_to_cache` **cắt âm thầm** `value[:size]`. Xem §10.4.0 |
| A3 | Odoo gọi relay worker bằng `requests` ngay trong method | Một HTTP call trong transaction: transaction rollback nhưng tx đã broadcast. Đây là lỗ thất thoát tiền lớn nhất của bản 1. Xem §10.4.11 (outbox) |
| A4 | Một lane `(batchId, batchNonce)` chỉ được ghi một lần | Metatx hết hạn **không** tiêu tốn nonce on-chain. Lần thứ hai phải dùng lại đúng lane đó, và `UNIQUE` chặn. Xem §10.4.5 |
| A5 | Consumer nào cũng đặt `origin_key` không đụng nhau | `UNIQUE(company_id, origin_key)` biến một va chạm vô tình giữa hai consumer thành một payout bị nuốt. Xem §10.4.8 |
| A6 | `env.companies` không đọc gì từ client | **Sai.** `/json/2` nhận `context` từ client và `Environment.companies` đọc `allowed_company_ids` từ context. Nó **an toàn** vì có check, nhưng lý do an toàn khác hẳn lý do bản 1 viết. Xem §10.6.2 |
| A7 | `field.groups` làm cột biến mất khỏi `read()` | Odoo 19: `read()` **không** truyền `fields` thì lọc; truyền tên field bị cấm thì **raise `AccessError`**. Khác hành vi Odoo <= 16. Xem §10.5.4 |
| A8 | `UserError` luôn là HTTP 200 | Chỉ đúng trên `call_kw`. Trên `/json/2` là **HTTP 422**. Xem §10.6.3 |
| A9 | `blockchain.chain` là đủ để biết contract nào ở đâu | Không có model nào lưu địa chỉ contract đã deploy. `verifying_contract` là `Char` tự do, không có gì để đối chiếu, và Policy Gate allowlist không có chỗ để sống. Xem §10.4.9 |
| A10 | Ai vào được `group_blockchain_treasury` thì được chi bất kỳ số tiền nào | Không có ngưỡng, không có maker-checker, không có dual approval cho R3/R4 mà chính note yêu cầu. Xem §10.4.10 |
| A11 | `mail.thread` trên settlement là miễn phí | 5 chuyển trạng thái × 10k settlement/tháng = 50k `mail_message`. Xem §10.4.12 |
| A12 | Cron chạy bằng quyền của người bấm nút | `ir.cron` chỉ cho `base.group_system` (kiểm: `base/security/ir.model.access.csv` dòng 5). `_toggle_crons()` **phải** `sudo()`. Xem §10.7 |
| A13 | **[BẢN 3]** Token trong `blockchain.token` là token do ta deploy | Trên factory mở thì không. Một record có thể trỏ tới token của người lạ, và khi đó `deploy_state`, `salt_hex`, `predicted_address` đều vô nghĩa — cái có nghĩa là **xuất xứ đọc từ chain**. Xem §10.4.9 |
| A14 | **[BẢN 3]** Một relayer là một địa chỉ | Một relayer là một danh tính có **N khoá ký** (`_USER-DECISIONS.md` §21.5). Mọi ngưỡng tính theo địa chỉ sẽ đếm một relayer thành N |

---

### 10.1. Tên module `dms_blockchain` cho một addon không depend `dms`

Vấn đề là thật: một người cài Odoo không có DMS sẽ thấy một module tên `dms_blockchain` trong Apps và kết luận
sai rằng nó cần DMS. Nhưng cái giá của việc đổi tên **sau khi deploy lần đầu** không nhỏ:

| Phương án | Chi phí đổi tên sau deploy | Đánh giá |
|---|---|---|
| **A. Giữ `dms_blockchain`** (khuyến nghị) | 0 | `dms` đọc như vendor prefix, đúng như module chính tên là `dms` chứ không phải `bamboo_dms`. Sửa nhận thức bằng `'name'` + `'category'` trong manifest, không bằng thư mục |
| B. Đổi thành `scaas_chain` / `chain_settlement` | Phải làm **trước** khi cài lần đầu. Sau đó cần migration script rewrite `ir_module_module.name`, `ir_module_module_dependency.name`, và cột `module` của **mọi** dòng `ir_model_data`. Đổi tên `_name` model còn kéo theo rename bảng PostgreSQL | Chỉ làm nếu quyết ngay hôm nay |
| C. Giữ `dms_blockchain` + thêm shim module rỗng tên trung tính | 2 module để bảo trì, 1 trong số đó không làm gì | Không |

**Định lượng chi phí của B** (ước tính, cơ sở: đếm model/ACL/rule/view dự kiến của chính section này):
~24 model × (1 dòng `ir_model` + trung bình 22 dòng `ir_model_fields`) = ~550 dòng `ir_model_data`;
~50 dòng ACL; ~18 record rule; ~45 view/action/menu; ~8 cron; ~24 bảng PostgreSQL phải `ALTER TABLE … RENAME`.
Tổng ~700 dòng `ir_model_data` phải UPDATE cột `module` **và** cột `name` (XML id chứa tên module ở vài chỗ),
cộng 24 rename bảng + mọi index/constraint/sequence gắn với chúng. Đó là một migration script vài trăm dòng
và một cửa sổ downtime — không phải một `git mv`.

**Chốt: A.** Manifest làm rõ phạm vi bằng metadata, không bằng tên thư mục:

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
    'author': 'SCaaS',
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

**`external_dependencies` là `{}` — sửa so với bản 1.** Bản 1 khai `eth_utils`. Nhưng addon này không bao giờ
mở socket tới chain từ HTTP worker (mọi I/O RPC nằm trong relay worker, §06/§08), và hai thứ duy nhất cần
`eth_utils` là keccak (để tính EIP-712 digest) và checksum EIP-55. Cả hai đều thuộc về worker, không thuộc về
Odoo. Đổi lại, một module không cài được vì thiếu wheel trên **một** node trong cụm là một sự cố vận hành thật,
và nó xảy ra lúc `-u`, tức lúc đang có người dùng. Validate địa chỉ trong Odoo bằng regex lowercase (§10.4.3);
validate checksum EIP-55 ở worker, nơi đã có Python 3 đầy đủ.

`requests` có sẵn trong core Odoo nên không phải dependency mới — nhưng xem §10.4.11: **không gọi `requests`
trực tiếp trong method nghiệp vụ.**

**`application: True`** khiến module hiện trong tab Apps chứ không chỉ Extensions. Đó là cố ý: nó là một ứng
dụng độc lập. Hệ quả: nó cần một `ir.module.category` và một menu gốc — cả hai có ở `data/` và `views/menu.xml`.

---

### 10.2. Topology: bốn addon Odoo, một service ngoài Odoo, một cây contract

```
custom-addons/bamboo-dms/
├── dms_blockchain/            # CORE.   depends: base, mail                    auto_install: False
├── dms_blockchain_payment/    # BRIDGE. depends: dms_blockchain, payment       auto_install: False
├── dms_blockchain_account/    # BRIDGE. depends: dms_blockchain, account       auto_install: False
└── dms_blockchain_bridge/     # BRIDGE. depends: dms_blockchain, dms           auto_install: True

relay-pool/                    # service rieng (§06, §08). KHONG phai addon.
confidential-signer/           # service rieng (§07). KHONG phai addon.
smartcontracts/                # ngoai addon, goc repo (§01.14, §14)
```

| Module | Chứa gì | Vì sao tách |
|---|---|---|
| `dms_blockchain` | Chain, endpoint, contract deployment, account, custody, token, metatx, relayer registry, transaction, event, **Zether**, **settlement layer**, outbox, approval policy, ACL, cron, config | Chạy được một mình, không có `account` lẫn `payment` lẫn `dms` |
| `dms_blockchain_payment` | `payment.provider` `selection_add=[('chain', 'On-chain')]`, `payment.transaction` mapping, webhook acquirer | Chỉ cần khi money-flow chọn handler thuộc họ `payment.*` (§09) |
| `dms_blockchain_account` | Sinh `account.move` / `account.payment` từ `blockchain.settlement`, reconciliation run (§15.4–15.5) | Chỉ cần khi money-flow chọn handler có kế toán |
| `dms_blockchain_bridge` | `_inherit` mixin `blockchain.settlement.origin` lên `dms.trade.settlement.line`, `dms.payment.collection`, `dms.trade.claim` | Cầu duy nhất biết tên model `dms.*` |

**Zether nằm trong core, không tách module.** Lý do: `blockchain.settlement.zether_entry_id` là một Many2one
từ core. Nếu Zether ở module riêng thì core phải dùng `Reference` cho nó, và toàn bộ báo cáo đối soát phải
xử lý hai đường. Chi phí giữ Zether trong core khi không dùng: 3 bảng rỗng + 2 cron `active=False`. Rẻ hơn.

**`auto_install` của bridge — kiểm trên source.** `odoo/modules/module.py:445-458`:

```python
if isinstance(manifest['auto_install'], Iterable):
    manifest['auto_install'] = auto_install_set = set(manifest['auto_install'])
    non_dependencies = auto_install_set.difference(depends)
    assert not non_dependencies, "auto_install triggers must be dependencies, ..."
elif manifest['auto_install']:
    manifest['auto_install'] = set(depends)
```

Nghĩa là:

- `auto_install = True` → trigger set = **toàn bộ** `depends`. Module tự cài khi **cả hai** `dms_blockchain`
  và `dms` đã `installed`. Đây là điều ta muốn.
- `auto_install = ['dms']` → trigger set chỉ có `dms`. Cài `dms` một mình sẽ **kéo `dms_blockchain` vào theo**
  như một dependency. Đây **không** phải điều ta muốn, và là lỗi dễ mắc.

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

Hệ quả cần biết trước, không phải bất ngờ:

- Cài `dms` một mình → bridge **không** được cài. Đúng.
- Cài `dms_blockchain` một mình → bridge **không** được cài. Đúng.
- Cài cả hai → bridge tự cài **ngay trong cùng transaction**, kể cả khi người dùng không biết nó tồn tại.
- Muốn chặn tạm thời trên một instance: `ir.module.module._button_immediate_install` đọc
  `config.get('skip_auto_install')` (`base/models/ir_module.py:431`). Đó là một **config key của server**,
  không phải flag CLI chính thức — đặt trong `odoo.conf` khi cần một cửa sổ bảo trì, không dùng lâu dài.
- **Gỡ `dms`** → Odoo gỡ luôn bridge (cascade). Core và toàn bộ dữ liệu settlement sống sót. Đây là lý do
  settlement layer phải ở core chứ không ở bridge.

`dms_blockchain_payment` và `dms_blockchain_account` **không** `auto_install`: chúng hiện thực hoá một lựa chọn
chính sách (§10.8/§09), không phải một sự thật kỹ thuật. Tự cài chúng khi ai đó tình cờ cài `account` là sai.

**Cây thư mục core** (để kế hoạch triển khai có chỗ để đặt file):

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

### 10.3. Prefix model `blockchain.*` và sổ đăng ký model canonical

`blockchain.*`, không phải `dms.blockchain.*`. Lý do không phải thẩm mỹ: `dms.` là một lời nói dối về phạm vi
trên một module từ bỏ `depends dms`, và nó sẽ làm người đọc đi tìm model cha không tồn tại.

**Sổ đăng ký đầy đủ.** Mọi model `blockchain.*` trong toàn bộ hệ thống, ai sở hữu định nghĩa, ở đâu:

| Model | Định nghĩa ở | Module | company_id | Ghi chú |
|---|---|---|---|---|
| `blockchain.chain` | §10.4.2 | core | không (`company_ids` M2M) | §08.1 phải đổi theo bảng này |
| `blockchain.rpc.endpoint` | §10.4.2b | core | không | |
| `blockchain.contract.deployment` | §10.4.9 | core | không | **mới**, bản 1 thiếu |
| `blockchain.contract.abi` | §11.6 | core | không | |
| `blockchain.account` | §10.4.3 | core | **có** | |
| `blockchain.relayer.account` | §06.9 + §10.4.3 | core | qua `_inherits` | `_inherits` `blockchain.account` |
| `blockchain.relayer.submitter` | §06.9 | core | qua parent | **mới bản 3** — N khoá ký của một `relayer_id` (`_USER-DECISIONS.md` §21.5) |
| `blockchain.custody.provider` | §07.12 | core | **có** | |
| `blockchain.custody.key` | §07.12 | core | related | |
| `blockchain.key.ceremony` | §07.8 | core | **có** | |
| `blockchain.token` | §01.13 | core | không (`company_ids`) | **bản 3**: thêm cột xuất xứ, xem §10.4.9 |
| `blockchain.metatx` | §10.4.5 | core | không (suy từ settlement) | |
| `blockchain.relayer` | §10.4.5 | core | **có** khi `kind='internal'` | |
| `blockchain.relayer.address` | §10.4.5 | core | không | |
| `blockchain.transaction` | §10.4.6 | core | không | |
| `blockchain.event` | §10.4.6 | core | không | |
| `blockchain.index.cursor` | §11.2 | core | không | |
| `blockchain.watched.address` | §11.8 | core | **có** | |
| `blockchain.zether.account` | §02.8.5 | core | **có** | **bản 3**: thêm `curve` (§02.0) |
| `blockchain.zether.account.chain` | §02.8.5 | core | qua parent | đổi `profile_id` → `chain_id` |
| `blockchain.zether.entry` | §10.4.7 | core | **có** | |
| `blockchain.settlement` | §10.4.8 | core | **có** | canonical |
| `blockchain.settlement.batch` | §15.7 | core | **có** | |
| `blockchain.netting.set` | §15.6 | core | **có** | |
| `blockchain.settlement.origin` | §15.3 | core | AbstractModel | mixin, không có bảng |
| `blockchain.money.flow` | §09.4 | core | **có** (nullable = default) | **bản 3**: thêm `token_id` (§09.4) |
| `blockchain.payment.handler` | §09.4 | core | AbstractModel | interface |
| `blockchain.payment.handler.none` | §09.4 | core | AbstractModel | impl rỗng, mặc định |
| `blockchain.payment.request` | §09.6 | core | **có** | |
| `blockchain.payment.quote` | §09.7b | core | qua request | |
| `blockchain.credit.balance` | §09.7 | core | **có** | |
| `blockchain.approval.policy` | §10.4.10 | core | **có** | **mới** |
| `blockchain.approval.request` | §10.4.10 | core | **có** | **mới** |
| `blockchain.security.event` | §10.4.11 | core | **có** | **mới**, §07.13 đã tham chiếu |
| `blockchain.outbox.job` | §10.4.11 | core | **có** | **mới**, bản 1 thiếu |
| `blockchain.reconciliation.run` / `.line` | §15.5 | `_account` | **có** | |
| `blockchain.audit.disclosure` | §13 | core | **có** | |
| `blockchain.travel.rule.message` | §13 | core | **có** | |
| ~~`blockchain.upgrade.proposal`~~ | ~~§01~~ | — | — | **XOÁ ở bản 3.** Không còn upgrade để mà đề xuất (§01.1.11.3) |

**Chỗ phải sửa trong các section đã viết:**

| Nguồn | Đang sai / lệch | Chốt |
|---|---|---|
| §02.8.5 | `blockchain.chain.profile` là một model riêng, với `evm_chain_id`, `is_private`, `finality_depth`… | **Xoá model đó.** Các field đó là field trên `blockchain.chain` (§10.4.2). `blockchain.zether.account.chain.profile_id` → `chain_id = Many2one('blockchain.chain')`; constraint đổi thành `UNIQUE(account_id, chain_id)`. Bản 1 quy lỗi này cho "01 §1.13" — **sai địa chỉ**, §01 đã trỏ về §10.4.2 từ dòng 40 |
| §08.1 | `chain_family` đúng, nhưng `fee_token_mode`, `native_is_stable`, `finality_depth`, `state` giá trị `live/paused/retired` | Đổi theo §10.4.2: `fee_mode` (5 giá trị), bỏ `native_is_stable` (đã nằm trong `fee_mode='native_stable'`), `state` giá trị `draft/enabled/degraded/halted/retired` |
| §10 bản 1 | `chain_profile` có **ba** giá trị (`private`/`consortium`/`public`) | **Hai giá trị.** §05 và §08 viết `if chain.chain_profile == 'public'` ở hàng chục chỗ. Thêm một giá trị thứ ba khiến `consortium` rơi vào nhánh `private` một cách **im lặng** — không dòng nào viết `!= 'private'`. Nếu cần phân biệt consortium, dùng một field riêng `governance_model`, không nhét vào trục này |
| §06.9 | `blockchain.relayer.account` là bảng độc lập | Thành `_inherits = {'blockchain.account': 'account_id'}` (§10.4.3). Giữ nguyên tên các field pool |
| §05 bản 1 | prefix `dms.blockchain.*` | Đã sửa ở bản 2 của §05. Không còn nó |
| §02 §2.5.5 | ghi kết quả probe vào `blockchain.chain.profile.has_bls12381` | → `blockchain.chain.has_bls12381` |
| §02 §2.7 | `blockchain.chain.profile.compliance_freeze_enabled` | → `blockchain.chain.compliance_freeze_enabled` |
| **[BẢN 3] §01, §06** | `blockchain.upgrade.proposal` | **Xoá model.** `blockchain.token.upgradeable` cũng xoá, thay bằng `impl_version` + `impl_address` (§01.1.13.1) |
| **[BẢN 3] §05.8.2** | `blockchain.metatx.mode_flags` | Xoá cột — bitmask đã bị loại (`_USER-DECISIONS.md` §5). Thay bằng `fee_mode` + `pool_visibility` |

---

### 10.4. Data model

#### 10.4.0. Bốn sự thật về cột PostgreSQL của Odoo 19, đã kiểm trên source

Bốn điều này quyết định gần hết các lựa chọn kiểu dữ liệu bên dưới. Ba trong số đó trái với trực giác.

**(1) `fields.Char(size=N)` là `deprecated` và cắt chuỗi trong im lặng.**
`odoo/orm/fields_textual.py`: `size = None  # maximum size of values (deprecated)`, và

```python
def convert_to_cache(self, value, record, validate=True):
    ...
    value = s[:self.size]      # <-- CAT, khong raise
```

Cột sinh ra là `VARCHAR` **không** có độ dài (`column_type == ('varchar', 'VARCHAR')` — kiểm bằng
`fields.Char(size=42).column_type`). Vậy `size=42` không bảo vệ gì ở DB và **phá dữ liệu** ở Python:
ghi một địa chỉ Sui 66 ký tự vào `Char(size=42)` cho ra 42 ký tự đầu, không lỗi, không log.
**Quy ước toàn addon: không dùng `size=` ở bất kỳ đâu.** Độ dài được ép bằng `models.Constraint` CHECK.

**(2) `fields.Float(digits=(p, s))` sinh cột `numeric` nhưng Python vẫn là `float` C.**
`odoo/orm/fields_numeric.py:126-133`: `_column_type` trả `('numeric','numeric')` khi `_digits is not None`,
ngược lại `('float8','double precision')`. Nhưng `numeric` ở đây là `numeric` **không tham số** — `(24, 8)`
chỉ điều khiển làm tròn khi ghi (`float_round`) và hiển thị. Giá trị trong Python là IEEE754 double →
mất chính xác từ ~15–16 chữ số có nghĩa. Một số dư 18 decimals có 20+ chữ số. **Kết luận: không bao giờ
đối soát trên một `Float`.** `Monetary` luôn là `numeric` (`_column_type = ('numeric','numeric')`).

**(3) Odoo 19 có `models.Index` và `models.UniqueIndex`, không chỉ `models.Constraint`.**
`odoo/orm/table_objects.py:125,185`. Điều này giải quyết dứt điểm vấn đề partial unique index mà
`_sql_constraints` và `models.Constraint` không làm được:

```python
_one_open_lane = models.UniqueIndex(
    "(chain_id, from_account_id, batch_id_hex, batch_nonce) "
    "WHERE metatx_state NOT IN ('expired', 'failed', 'final')",
    'Lane (batchId, batchNonce) dang co mot metatx chua ket thuc.')
```

Tên thuộc tính **phải** bắt đầu bằng `_` (assert trong `TableObject.__set_name__`), và tên SQL thật sẽ là
`{table}_{name}` — ở ví dụ trên là `blockchain_metatx_one_open_lane`.

**(4) `models.Constraint` tự drop và tạo lại khi definition đổi**, so sánh bằng
`sql.constraint_definition()`. Nghĩa là đổi nội dung CHECK giữa hai lần `-u` sẽ chạy `DROP CONSTRAINT` rồi
`ADD CONSTRAINT` — và `ADD` **fail** nếu dữ liệu cũ vi phạm. Đó là hành vi đúng, nhưng phải lường trước:
mỗi lần siết CHECK đều cần một migration script dọn dữ liệu **trước**.

Kiểm chứng bắt buộc, không tin code:

```sql
SELECT conname, contype, pg_get_constraintdef(oid)
FROM pg_constraint WHERE conrelid::regclass::text LIKE 'blockchain\_%';
SELECT indexname, indexdef FROM pg_indexes WHERE tablename LIKE 'blockchain\_%';
```

#### 10.4.1. uint256 không vừa vào bất kỳ field số nào của Odoo

`fields.Integer` là `int4` (`_column_type = ('int4','int4')`). `fields.Float` là double (xem 10.4.0(2)).
Một số dư token 18 decimals vượt cả hai: `2^256 − 1 ≈ 1,16e77`, còn `int4` hết ở 2,1e9 và double hết chính xác
ở 9,0e15. Quy ước **bắt buộc** trên toàn addon:

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

Ba chi tiết có chủ đích:

1. Regex chặn **số 0 dẫn đầu**. Nếu không, `'007'` và `'7'` là hai chuỗi khác nhau cho cùng một số, và
   mọi `UNIQUE`/`GROUP BY`/dedup trên field dẫn xuất đều sai. Chuẩn hoá ở `create`/`write`, ép ở DB.
2. `digits=(38, 18)` chứ không `(24, 8)`: 8 chữ số thập phân làm **1 wei biến mất** trên token 18 decimals.
   `(38, 18)` không cứu được giới hạn double (mục 10.4.0(2)) nhưng ít nhất không làm tròn ở tầng làm tròn.
3. `readonly=True` trên stored compute: chặn một dev tương lai `write()` thẳng vào nó.

**Stored computed field không được nhận `default`, và mọi nhánh phải gán giá trị.** Mẫu bắt buộc:

```python
@api.depends('amount_base', 'token_id.token_decimals')
def _compute_amount_display(self):
    for rec in self:
        rec.amount_display = 0.0                       # DONG DAU TIEN. Truoc moi nhanh.
        if not rec.amount_base or not rec.token_id:
            continue
        rec.amount_display = int(rec.amount_base) / (10 ** (rec.token_id.token_decimals or 0))
```

Áp dụng y hệt cho `fee_native_display` (§10.4.6), `reputation_score` (§10.4.5), `runway_hours` (§06.9),
`net_wei` (§05), `is_final` (§11), `divergent` (§02).

Hex thì luôn `Char` **không** `size`, luôn `0x` prefix, luôn lowercase, luôn có index khi được tra cứu.
Độ dài ép bằng CHECK, không bằng `size`:

| Field | Độ dài | CHECK |
|---|---|---|
| địa chỉ EVM | 42 | `~ '^0x[0-9a-f]{40}$'` |
| `tx_hash` EVM / `digest_hash` / `batch_id_hex` / `schnorr_address` | 66 | `~ '^0x[0-9a-f]{64}$'` |
| `signature_hex` (ECDSA) | 132 | `~ '^0x[0-9a-f]{130}$'` |
| `calldata_hex` | thay đổi | `~ '^0x([0-9a-f]{2})*$'` |

#### 10.4.2. Chain và endpoint

```python
class BlockchainChain(models.Model):
    _name = 'blockchain.chain'
    _description = 'Blockchain network'
    _inherit = ['mail.thread']
    _order = 'sequence, id'

    sequence         = fields.Integer(default=10)      # BAT BUOC: _order tham chieu no (ban 1 thieu)
    name             = fields.Char(required=True)
    code             = fields.Char(required=True, index=True)   # 'gnosis', 'celo', 'priv-9000'
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
                                         ('fee_currency','ERC-20 fee currency (Celo CIP-64)'),
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
    supports_eip1559     = fields.Boolean(default=True, readonly=True,
                                          help='Ghi boi probe. Chain 9000 = False (§01.1.16).')
    supports_push0       = fields.Boolean(default=True, readonly=True,
                                          help='Shanghai. False => build voi evm_version thap hon.')
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

**[BẢN 3] Hai field capability mới, và chúng không phải trang trí.** `supports_eip1559` và
`supports_push0` là hệ quả trực tiếp của `TRAPS.md` §"Private chain": chain 9000 khai `londonBlock: 0`
trong genesis nhưng Nethermind bỏ qua key kiểu Geth **trong im lặng**, nên nó chạy trước London. Mọi
đoạn code gọi `base_fee_next_block()`, phát tx type-2, hay build với `evm_version = cancun` sẽ hỏng ở đó
— và hỏng theo kiểu không có triệu chứng cho tới lúc gửi tx thật.

Cả hai **phải** được ghi bởi probe, không nhập tay, và probe phải kiểm **hệ quả quan sát được** (có
`baseFeePerGas` trong header không; `eth_call` vào precompile trả gì) chứ không đọc file cấu hình chain.
`readonly=True` là để chặn ai đó "sửa cho đúng" trong UI.

`blockchain.chain` là **hạ tầng dùng chung, không có `company_id`**. Khả dụng theo công ty điều khiển bằng
`company_ids` (rỗng = mọi công ty). Cái gì giữ tiền mới có `company_id` (§10.9).

**Vì sao tách `soft` và `hard` thành cả block lẫn giây.** Không chuỗi nào diễn đạt được bằng một chiều:
Ethereum finality là 2 epoch = 64 slot (**block**), Polygon PoS là Heimdall checkpoint (**thời gian**, ~25–30
phút, không có số block cố định), Arbitrum soft là sequencer (1 giây) còn hard là L1 batch (~15 phút).
Finality Gate lấy `max()` của hai điều kiện (§10.4.8 `_set_finality`).

**Bảng chuẩn cho `data/blockchain_chain_data.xml`** (ước tính cho tháng 08/2026; xác nhận lại khi deploy):

| code | caip2 | family | profile | fee_mode | block_time_ms | finality_mode | soft_blocks | hard_blocks | hard_seconds |
|---|---|---|---|---|---|---|---|---|---|
| `gnosis` | `eip155:100` | evm | public | `native_stable` | 5000 | `checkpoint` | 1 | 32 | 160 |
| `celo` | `eip155:42220` | evm | public | `fee_currency` | 1000 | `l1_batch` | 1 | 0 | **cần xác nhận** |
| `priv-9000` | `eip155:9000` | evm | private | `gasless` | **5000** | **`depth`** | 1 | **cần đo** | 0 |

**[BẢN 3] Hai hàng đã sửa.** Gnosis hard: bản 1 ghi 64 block / 780 s, nhưng Gnosis có **16 slot/epoch**
và slot 5 s, nên 2 epoch = **32 slot ≈ 160 s** (§09.7 đã sửa cùng con số này). Và hàng chain private: bản 1
mô tả một Besu QBFT tưởng tượng (`bft_instant`, block 2000 ms). Chain thật là **Nethermind + Clique một
signer, block 5000 ms**, và Clique **không phải BFT** — nó không cho instant finality, nên `finality_mode`
là `depth` với một `finality_hard_blocks` bảo thủ phải đo, không phải `bft_instant` với `1`.

**Celo: con số trong `blockchain.md` đã lỗi thời.** Note ghi "Istanbul BFT 2.0, 5 giây, immediate finality".
Celo đã chuyển thành **Ethereum L2 trên OP Stack (2025)**: block time ~1 giây, và finality không còn là BFT
tức thời của validator set riêng mà phụ thuộc L1. Nạp `celo` với `state='draft'` và **bắt buộc đo lại**
`finality_hard_seconds` trên mainnet trước khi `enabled`. §11.12 đã nêu điểm này; §10 không được chép lại
con số cũ.

**Gnosis hard finality: 160 giây, không phải 780.** Bản 1 viết 780 giây rồi tự mâu thuẫn ngay trong cùng
đoạn (nó tính ra ~160 giây rồi vẫn chốt 780 "cho an toàn"). Gnosis dùng **16 slot/epoch, 5 giây/slot** →
1 epoch = 80 giây, 2 epoch = **160 giây** để đánh dấu finalized. Đó là con số, và nếu muốn biên an toàn thì
ghi biên đó ra riêng chứ đừng nhân vào rồi để người sau tưởng là số đo. §09.7 đã chốt 160 s; hai chỗ phải
khớp nhau.

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
    propagation  = fields.Selection([('public','Public mempool'), ('private','Private orderflow'),
                                     ('unknown','Unknown')], required=True, default='unknown')
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

`diverging` là trạng thái riêng, không gộp vào `down`: một RPC **trả lời nhanh và sai** nguy hiểm hơn một RPC
chết (§06.7). Endpoint `diverging` bị loại khỏi vòng quay ngay nhưng **không** được tự hồi phục; cần người.

`propagation` là field mới, lấy từ §06.7.2 quy tắc 3: fan-out broadcast chỉ tới endpoint `public`; endpoint
`private` (MEV-protect, builder-affiliated) chỉ dùng cho tx nhạy cảm và khi đó **chỉ** gửi tới đó. Nó phải
nhất quán với `pool_visibility` của intent (§05.8.2) — một intent private mà cuối cùng fan-out ra mempool
công khai thì lớp bảo vệ đầu vô ích.

#### 10.4.2b. Vì sao không có `blockchain.chain.company` mà là M2M

Một bảng trung gian sẽ cần ACL riêng, view riêng, và một vòng đời riêng mà không ai muốn quản lý.
`company_ids` M2M rỗng nghĩa là "mọi công ty" — một quy ước, không phải một cột NULL nhập nhằng. Ép trong
`_enabled_chains()`:

```python
def _enabled_chains(self, company=None):
    company = company or self.env.company
    return self.env['blockchain.chain'].search([
        ('state', '=', 'enabled'),
        '|', ('company_ids', '=', False), ('company_ids', 'in', company.id),
    ])
```

#### 10.4.3. Account / wallet và custody

Một bảng duy nhất cho mọi ví. `blockchain.relayer.account` của §06 trở thành **delegation** của nó thay vì một
bảng song song (`_inherits` là cơ chế sẵn của Odoo, một dòng, không phải một abstraction tự chế):

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

**Sửa so với bản 1: `size=42` và CHECK `^0x[0-9a-f]{40}$` vô điều kiện đều sai.** Locked #4 đặt 5 hệ sinh thái
non-EVM vào thiết kế ngay bây giờ. Độ dài và bảng chữ cái địa chỉ của chúng khác nhau hoàn toàn:

| Family | Dạng địa chỉ | Độ dài | Bảng chữ cái |
|---|---|---|---|
| EVM | `0x` + 40 hex | 42 | hex |
| Hedera | `0.0.<num>` (hoặc EVM alias 42) | 7–20 | số + dấu chấm |
| TON | user-friendly base64url | 48 | base64url |
| Sui | `0x` + 64 hex | 66 | hex |
| Soroban / Stellar | `G…` / `C…` StrKey base32 | 56 | base32 |
| CosmWasm | bech32 `<hrp>1…` | 39–90 | bech32 |

`lower(address)` là sai với Stellar StrKey (uppercase base32) và với bech32 có checksum phân biệt hoa thường.
Kết luận trung thực: **không có một CHECK nào đúng cho cả sáu họ.** Chốt hai tầng:

1. **DB**: một CHECK thô đúng cho mọi họ (`length BETWEEN 20 AND 128`) + một CHECK **có điều kiện theo
   `chain_family`** cho từng họ, thêm dần khi họ đó được build. `chain_family` là related **stored** nên nó
   là một cột thật và CHECK dùng được.
2. **Python**: `@api.constrains('address', 'chain_id')` gọi
   `self.env['blockchain.chain']._adapter(rec.chain_id).validate_address(rec.address)` — adapter là họ
   interface của §08, không phải code mới. Cái này bắt checksum EIP-55, bech32 checksum, StrKey CRC16.
   Adapter không tồn tại (họ chưa build) → constrain bỏ qua, không raise.

Bỏ `custody_mode` làm Selection tự do (bản 1) và làm `related` tới `blockchain.custody.key.provider_id.kind`
(§07.12): một chuỗi tự do ở đây và một chuỗi tự do ở §07 là hai nguồn sự thật cho cùng một sự thật.

**`signer_ref` bảo vệ bằng `groups=` ngay trong định nghĩa field, không bằng record rule.** Record rule lọc
**dòng**, không lọc **cột**. Xem §10.5.4 cho hành vi chính xác.

**`blockchain.relayer.account` là delegation:**

```python
class BlockchainRelayerAccount(models.Model):
    _name = 'blockchain.relayer.account'
    _description = 'Relayer EOA in the internal relay pool'
    _inherits = {'blockchain.account': 'account_id'}

    account_id = fields.Many2one('blockchain.account', required=True,
                                 ondelete='cascade', index=True, auto_join=True)
    relayer_id = fields.Many2one('blockchain.relayer', index=True, ondelete='restrict',
                                 help='Danh tinh relayer. N account nay thuoc mot relayer_id (§21.5).')
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

**[BẢN 3] `relayer_id` là field mới và nó chặn một lỗi đếm.** Một relayer chạy pool 50 khoá ký
(`_USER-DECISIONS.md` §21.5) có 50 record ở bảng này. Không có `relayer_id`, mọi ngưỡng tính theo địa chỉ —
cap per-relayer của sponsorship pool (§05.7), trọng số lottery (§05.4.4), đối soát gas (§05.8.3) — đều đếm
một người thành 50. Đó chính là sybil mà các ngưỡng đó tồn tại để chặn.

Ba hệ quả của `_inherits` phải biết trước, không phải phát hiện lúc production:

1. `create()` trên child **tạo bản ghi parent**; `unlink()` trên child **xoá parent** (`ondelete='cascade'`).
   Đó là lý do `perm_unlink=0` trên cả hai (§10.5.3).
2. Field `state` của parent bị field `pool_state` của child **không** đụng tên — cố ý. Nếu đặt trùng tên,
   child che parent và `blockchain.account.state` không còn truy cập được từ child.
3. **Field-level `groups` đi theo qua delegation.** `odoo/orm/fields.py:777`:
   `_related_groups = property(attrgetter('groups'))` — field kế thừa lấy `groups` từ field gốc khi không
   khai báo riêng. Vậy `signer_ref` vẫn bị chặn khi đọc qua `blockchain.relayer.account`. **Vẫn phải kiểm**
   (§10.11 mục 9): đây là lần duy nhất một đặc tính bảo mật phụ thuộc một dòng trong ORM.
4. `runway_hours` là stored compute → **không** `default`, và compute phải gán `0.0` ở dòng đầu. Bản §06.9
   đang có `required=True, default=0.0` — sai cả hai (§10.14).

#### 10.4.4. Token

`blockchain.token` giữ §01.13, thêm:

```python
is_confidential     = fields.Boolean(default=False)   # co Zether wrapper
registry_address    = fields.Char()                   # ZetherAccountRegistry ma token nay tro toi
underlying_token_id = fields.Many2one('blockchain.token')   # cho wrap/peg
peg_numerator       = fields.Char(default='1')        # uint256: 1 USDT -> 25000 Z-VND => 25000/1
peg_denominator     = fields.Char(default='1')
token_decimals      = fields.Integer(required=True, default=18)
company_ids         = fields.Many2many('res.company')
deploy_state        = fields.Selection([...])         # theo §01, khong dat ten 'state'

# [BAN 3] Xuat xu — bat buoc tren factory mo. Doc tu chain, khong nhap tay.
factory_address     = fields.Char(readonly=True, index=True)
creator_address     = fields.Char(readonly=True, index=True)
impl_address        = fields.Char(readonly=True)
impl_version        = fields.Integer(readonly=True, help='0 = ngoai catalogue (createUnregistered).')
verifier_address    = fields.Char(readonly=True, help='Chi voi token Zether.')
curve               = fields.Selection([('bn254','bn254'), ('bls12_381','BLS12-381')], readonly=True)
provenance_state    = fields.Selection([('unknown','Chua kiem'), ('verified','Da kiem'),
                                        ('rejected','Khong dat chinh sach')],
                                       required=True, default='unknown', index=True)
provenance_datetime = fields.Datetime(readonly=True)
```

Không thêm `company_id`: token là hạ tầng. `peg_*` là `Char` uint256 chứ không `Float` — một tỷ lệ 1:25000
tính bằng `Float` trên số dư 18 decimals làm tròn ngay từ phép nhân đầu tiên.

**[BẢN 3] Bảy field xuất xứ là hệ quả trực tiếp của factory mở** (`_USER-DECISIONS.md` §20). Trên một
factory mở, một record `blockchain.token` có thể trỏ tới token **của người lạ**, chạy một implementation ta
chưa đọc. Khi đó `deploy_state`, `salt_hex`, `predicted_address` — vốn mô tả *ta đã deploy nó thế nào* — đều
vô nghĩa; thứ có nghĩa là *nó là cái gì*, và câu đó chỉ trả lời được bằng bốn lời gọi `eth_call`.

`provenance_state` phải là điều kiện để dùng token: `blockchain.money.flow` (§09.4) và
`payment.provider.accepted_token_ids` (§09.5) đều từ chối token `unknown`. Và `impl_version = 0` **không**
phải lỗi — nó là token deploy qua `createUnregistered`, hợp lệ, chỉ là ta biết mình đang tin code người tạo
tự mang tới. Hiển thị nó, đừng giấu nó.

`curve` cần vì `schnorr_address` phụ thuộc curve (§02.0): cùng một người có hai định danh trên hai curve, và
gộp chúng lại là một lỗi dữ liệu không sửa được.

#### 10.4.5. Meta-transaction và relayer registry

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
    fee_mode           = fields.Selection([('none','None'), ('percent','Percent'), ('fixed','Fixed')],
                                          required=True, default='fixed')
    fee_base           = fields.Char(required=True, default='0')
    fee_token_id       = fields.Many2one('blockchain.token', index=True)
    expiry_datetime    = fields.Datetime(required=True, index=True)   # khong dat ten 'date'
    relayer_address    = fields.Char(help="address(0) = bat ky ai (wildcard).")
    fee_recipient      = fields.Char(help="address(0) = tra cho msg.sender.")
    pool_visibility    = fields.Selection([('open','Open'), ('private','Private')],
                                          required=True, default='open', index=True)
    never_public       = fields.Boolean(default=False)
    hop_count          = fields.Integer(default=0)
    domain_separator   = fields.Char(readonly=True, index=True)
    digest_hash        = fields.Char(index=True, readonly=True)
    signature_hex      = fields.Char(readonly=True)
    transaction_id     = fields.Many2one('blockchain.transaction', index=True)
    metatx_state       = fields.Selection([
        ('draft','Draft'), ('simulated','Simulated'), ('signed','Signed'),
        ('published','Published to bus'), ('queued','Queued'), ('claimed','Claimed by relayer'),
        ('broadcast','Broadcast'), ('mined','Mined'), ('final','Final'), ('done','Done'),
        ('reverted','Reverted'), ('expired','Expired'), ('superseded','Superseded'),
        ('failed','Failed')], required=True, default='draft', index=True)
    failure_code       = fields.Char(index=True)

    # UNIQUE tuyet doi tren lane la SAI: xem giai thich duoi.
    _one_open_lane = models.UniqueIndex(
        "(chain_id, from_account_id, batch_id_hex, batch_nonce) "
        "WHERE metatx_state NOT IN ('expired', 'failed', 'superseded')",
        'Lane (batchId, batchNonce) dang co mot metatx chua ket thuc.')
    _unique_attempt = models.Constraint(
        'UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce, attempt_seq)',
        'Mot lan thu tren mot lane chi duoc ghi mot lan.')
    _unique_digest = models.Constraint(
        'UNIQUE(chain_id, digest_hash)', 'Mot digest chi duoc ky mot lan tren mot chain.')
```

**[BẢN 3] `mode_flags` bị xoá.** Bitmask đã bị loại (`_USER-DECISIONS.md` §5): wildcard
`relayer == address(0)` thay cho `MODE_OPEN`, và hành vi bubble/swallow là thuộc tính của contract đích chứ
không phải một bit trong digest. `_check_mode` biến mất cùng nó. Thay vào đó là `fee_mode` (nằm **trong**
digest — nếu không, relayer đổi cách diễn giải `fee` từ tuyệt đối sang ppm) và ba field mesh
(`pool_visibility`, `never_public`, `hop_count` — §05.8.2).

`metatx_state` mở rộng theo state machine hợp nhất của §05.8.1: bản 1 thiếu `queued`, `broadcast`,
`superseded`, `done`, `reverted`.

**Sửa lỗi của bản 1: `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` tuyệt đối làm hệ thống
kẹt cứng.** Hợp đồng EIP-1776 chỉ tăng `meta_nonce(from, batchId)` khi **thực thi thành công**. Một metatx
hết hạn (`expiry` trôi qua, không relayer nào nhận) **không** tiêu lane. Lần thứ hai bắt buộc phải dùng lại
đúng `batchNonce` đó — và `UNIQUE` chặn `create()`, nên hệ thống không thể thử lại và tiền treo ở
`authorized` vĩnh viễn. Partial `models.UniqueIndex` (§10.4.0(3)) sửa đúng vấn đề: một lane chỉ được có
**một** metatx chưa kết thúc, nhưng số lần thử là không giới hạn và lịch sử được giữ đầy đủ qua `attempt_seq`.

**Nguy cơ đốt nonce.** §06.12 mục 3 để mở một câu hỏi contract: `meta_nonce` tăng trước hay sau `call`. Nếu
tăng trước, một relayer độc có thể đốt nonce của user bằng một tx chắc chắn revert. Tăng sau thì lại mở
replay khi tx revert. **Đây là quyết định contract, không phải Odoo** — nhưng Odoo phải chuẩn bị cho cả hai:
`attempt_seq` tồn tại chính vì khả năng `meta_nonce` **không** tăng, và `failure_code = 'nonce_burned'` là
nhánh xử lý khi nó **có** tăng. Model không được giả định một trong hai.

`blockchain.relayer` (registry của bên thứ ba, tách khỏi `blockchain.relayer.account` là ví nội bộ):

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
    submitter_ids = fields.One2many('blockchain.relayer.account', 'relayer_id')   # [BAN 3] pool khoa ky
    allowlist_state = fields.Selection([('unknown','Unknown'), ('probation','Probation'),
                                        ('allowed','Allowed'), ('blocked','Blocked')],
                                       required=True, default='unknown', index=True, tracking=True)
    stake_ref     = fields.Char(help='Tham chieu bond on-chain. KHONG luu so tien o day.')
    fee_recipient = fields.Char(help='[BAN 3] Dia chi lanh nhan phi. KHONG phai khoa ky (§21.5).')
    reputation_score  = fields.Float(digits=(6, 3), compute='_compute_reputation',
                                     store=True, readonly=True)
    forward_score = fields.Float(digits=(6, 3), compute='_compute_forward_score',
                                 store=True, readonly=True,
                                 help='[BAN 3] Cham theo forward CO ICH, khong theo luu luong (§05.4.4b).')
    success_count = fields.Integer(default=0, readonly=True)
    fail_count    = fields.Integer(default=0, readonly=True)
    median_latency_ms = fields.Integer(readonly=True)
    contact_url   = fields.Char()
    sla_attachment_ids = fields.Many2many('ir.attachment', string='SLA / contract')
    _inherit = ['mail.thread']
```

`sla_attachment_ids` là M2M `ir.attachment` (hợp đồng SLA là file, lên Garage, không base64 trong DB).
`reputation_score` là stored compute → gán `0.0` ở dòng đầu mọi nhánh.

**[BẢN 3] Ba field mới, cả ba đến từ `_USER-DECISIONS.md` §21.** `submitter_ids` là pool khoá ký của relayer
này — mọi ngưỡng phải tính theo `relayer_id`, không theo địa chỉ ký, nếu không một relayer 50 khoá được đếm
thành 50 người (§21.5). `fee_recipient` là ví **lạnh** nhận phí, tách hẳn khỏi khoá ký; đó là điều kiện để
xoay khoá mà không làm phí rơi rải rác trên N ví nóng. `forward_score` chấm một vai mới — pool thuần không
có khoá thì không bao giờ submit, nên `reputation_score` (dựa trên `fill_rate`) đánh giá nó là vô dụng; nó
phải được chấm theo **forward có ích**, tức intent nó chuyển tiếp mà sau đó thật sự lên chain.

`kind` giữ ba giá trị, nhưng đọc chúng khác đi trên mesh mở: `open_public` không còn là "một trường hợp
hiếm ta chưa gặp" mà là **vai mặc định của mạng** (§21.4). `company_id` để NULL cho nó là đúng — một relayer
người lạ không thuộc company nào của ta.

#### 10.4.6. Transaction và receipt

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

**Sửa so với bản 1: `tx_hash size=66` chỉ đúng cho EVM.** Định dạng định danh giao dịch theo họ:

| Family | Định dạng tx id | Độ dài |
| TON | base64 32 byte hash (hoặc `lt:hash:workchain`) | 44+ |
| Sui | digest base58 | ~44 |
| Stellar / Soroban | 64 hex **không** `0x` | 64 |
| CosmWasm | 64 hex **uppercase** | 64 |

Vậy: không `size`, CHECK theo `chain_family`, và **không** ép lowercase toàn cục (Cosmos dùng uppercase).

Raw receipt và execution trace đi vào `ir.attachment` trên Garage, không vào một cột `Text`. Trong bảng chỉ
giữ `receipt_sha256` để đối chiếu. Định lượng (ước tính, cơ sở: kích thước trace JSON EVM điển hình
50–500 KB; một `blockchain.event` ~300 B dữ liệu + ~200 B index):

| Khối lượng | `blockchain.transaction` | `blockchain.event` | Trace trên Garage |
|---|---|---|---|
| 10k tx/tháng | ~6 MB/tháng | 30k dòng ~15 MB/tháng | 0,5–5 GB/tháng |
| 100k tx/tháng | ~60 MB/tháng | 300k dòng ~150 MB/tháng | 5–50 GB/tháng |

Kết luận vận hành: **trace là thứ đắt nhất trong hệ thống**, và nó phải có retention. `_cron_gc_traces()`
xoá attachment trace của tx đã `final` quá 90 ngày (giữ `receipt_sha256` vĩnh viễn). Giữ trace của tx
`reverted`/`orphaned` 400 ngày — đó là thứ sẽ cần khi có tranh chấp.

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

`decoded_args` là `fields.Json` — được phép vì là metadata nhỏ có cấu trúc, **không** phải ảnh/file.
Ràng buộc bắt buộc: không bao giờ > 8 KB; cái gì lớn hơn là attachment.

**[BẢN 3] `abi_id` là bắt buộc chứ không phải tiện ích trên factory mở.** Một indexer sẽ gặp event của token
người lạ, và schema event của họ không nhất thiết giống của ta (§09.6). Một `topic0` không đủ để giải mã —
phải biết ABI nào. Và với token `provenance_state = 'unknown'`, cách đúng là **lưu log thô, không giải mã**,
chứ không phải đoán bằng một ABI gần giống.

#### 10.4.7. Zether

`blockchain.zether.account` + `blockchain.zether.account.chain` giữ §02.8.5, **với hai sửa**:
`profile_id` → `chain_id = fields.Many2one('blockchain.chain')`, constraint đổi thành
`UNIQUE(account_id, chain_id)` (§10.3); và thêm `curve` (§02.0) vì `schnorr_address` phụ thuộc curve.

Thêm sổ cái bảo mật:

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
    c_hex          = fields.Char(required=True)      # ElGamal C
    d_hex          = fields.Char(required=True)      # ElGamal D
    zether_nonce   = fields.Integer(required=True)
    send_counter   = fields.Integer(readonly=True,
        help='[BAN 3] Doc TU CHAIN. Client suy `s` bang PRF tu seed + counter nay (§13.2).')
    entry_ref      = fields.Char(index=True,
        help='[BAN 3] Khoa rang buoc giao dich, dung cho verifyTransferAmount (§12.3).')
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
                                       ('audit_key','Audit view key'),
                                       ('proof_verified','Da kiem bang verifyTransferAmount')],
                                      required=True, default='none', index=True)

    _unique_zether_nonce = models.Constraint(
        'UNIQUE(token_id, account_id, zether_nonce, direction)',
        'Nonce Zether da duoc dung cho tai khoan/token nay.')
    _check_clear = models.Constraint(
        "CHECK (clear_source <> 'none' OR amount_clear_base IS NULL)",
        'amount_clear_base chi duoc dien khi co nguon giai ma.')
```

`amount_clear_base` rỗng không phải lỗi — **một số dư bảo mật mà Odoo đọc được rõ ràng là một lỗ hổng thiết
kế**. Báo cáo đối soát phải chịu được cột rỗng; §09.9 và §10.8 chỉ ra rằng Zether phá vỡ các mode có `amount`
bắt buộc.

**[BẢN 3] Ba bổ sung, tất cả từ `_USER-DECISIONS.md` §12–13.** `entry_ref` là khoá ràng buộc một giao dịch
cụ thể, không có nó thì chỉ chứng minh được "có một giao dịch trị giá X" chứ không phải "giao dịch NÀY".
`send_counter` phải đọc **từ chain**, không phải một bộ đếm cục bộ — counter lặp ⇒ `s` lặp ⇒ tái dùng
randomness ElGamal ⇒ lộ số dư (§13.2, lỗi thảm hoạ, phải có test phủ định). Và `clear_source` có giá trị thứ
năm `proof_verified`: số tiền được xác lập bằng `verifyTransferAmount` (§12.3) — kiểm chứng được độc lập,
`view`, miễn phí qua `eth_call` — chứ không phải bằng lời khai của một bên.

**Định lượng proof — sửa so với bản 1.** Bản 1 ước 1,0–1,5 KB. Tính lại cho **BN254 trên EVM**, nơi một điểm
G1 trong calldata là **64 byte** (x, y mỗi cái 32 byte, không nén):

| Thành phần | Công thức | n=128, m=2 range | Byte |
|---|---|---|---|
| Bulletproof aggregate | `2*ceil(log2(m*n)) + 4` điểm G1 | `2*8 + 4 = 20` điểm | 20 × 64 = 1.280 |
| Scalar của Bulletproof | 5 scalar | 5 | 5 × 32 = 160 |
| Sigma proof (Schnorr eq. + PoK) | ~4 điểm + ~5 scalar | | 4×64 + 5×32 = 416 |
| Ciphertext C, D, C_debit, C_fee | 4 × 2 điểm | | 8 × 64 = 512 |
| **Tổng calldata** | | | **~2.370 B** |

Vậy proof blob **~1,4–2,0 KB nén (compressed, 32 B/điểm)** và **~2,3–2,5 KB trên calldata EVM**. Attachment,
không `Char`. Với 16 gas/byte calldata khác 0 → chỉ riêng calldata đã ~38.000 gas.

**Trên BLS12-381 mọi con số trong bảng nhân đôi**: một điểm G1 là **128 byte** (EIP-2537 pad mỗi Fp thành 64
byte — đã đo, §01.1.12.1), nên calldata ~4,7 KB và ~76.000 gas chỉ để mang proof. Đó là chi phí thật của việc
chọn curve mà bảng gas MSM không hiện ra, và nó nặng nhất đúng ở nơi L2 vốn được chọn vì rẻ (§06.2.5).

**Gas Zether: con số trong `blockchain.md` sai một bậc độ lớn.** Note ghi "~180.000 – 250.000 gas" cho
xác thực ZKP. Đó là chi phí của một **pairing check Groth16** (`ecPairing` ~ 45.000 + 34.000/cặp sau
EIP-1108), không phải của Bulletproof. Bulletproof **không dùng pairing**; nó dùng ~`2n + O(log n)` phép
nhân vô hướng trên đường cong. Với `ecMul` = 6.000 gas (EIP-1108) và n=128, m=2:

```
naive:        ~2*256 + 40  ≈ 550 ecMul  x 6,000 = 3.3M gas
Pippenger/    multi-exp gom ~40-60% => ~200-350 ecMul x 6,000 = 1.2M - 2.1M gas
inner-product cong ecAdd (150 gas) va calldata (38k)
```

→ **1,2M – 2,5M gas cho một `transferConfidential`**, khớp với ước tính của §06.4 và không khớp với note.
Hệ quả trực tiếp: trên Ethereum L1 với block gas limit 30M, một block chứa tối đa ~12–25 giao dịch Zether.
Đó là lý do locked #5 (private chain trước) không phải một sự trì hoãn mà là một điều kiện khả thi.

Trên chain private với `MinGasPrice = 0`, con số này không tốn tiền — nhưng nó vẫn tốn **thời gian CPU của
validator**, và §01.1.12.2 đã đo: trần là **~45 confidential tx/s**, không phải một con số vô hạn. Nên
`block_gas_limit` trên `blockchain.chain` phải được đặt thật, và trần thông lượng phải được ghi là CPU chứ
không phải gas.
#### 10.4.8. Settlement layer thống nhất — trung tâm của addon

Đây là model **duy nhất** mà mọi consumer (bridge DMS, payment, account, RPC ngoài) được phép dùng. Mọi thứ
khác là nội thất.

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

**Sửa so với bản 1: `UNIQUE(company_id, origin_key)` không đủ.** Hai consumer độc lập (bridge DMS và một
portal ngoài) hoàn toàn có thể sinh cùng một chuỗi `origin_key`. Khi đó consumer thứ hai nhận lại bản ghi
của consumer thứ nhất — một payout **biến mất không lỗi**. `origin_producer` là namespace bắt buộc.
Quy ước format: `origin_key = f"{model}:{id}:{purpose}"` (bridge DMS), hoặc UUIDv4 (client ngoài).

**Tên bản ghi.** `name` `required=True default='/'` cần một `ir.sequence` — bản 1 thiếu:

```xml
<record id="seq_blockchain_settlement" model="ir.sequence">
    <field name="name">Blockchain Settlement</field>
    <field name="code">blockchain.settlement</field>
    <field name="prefix">BCS/%(year)s/</field>
    <field name="padding">6</field>
    <field name="company_id" eval="False"/>
</record>
```

`company_id = False` trên sequence (dùng chung mọi công ty) là một lựa chọn: một dãy số liên tục dễ đối soát
hơn. Nếu kế toán yêu cầu dãy số riêng theo pháp nhân, tạo một sequence per company trong `post_init_hook`.

**Máy trạng thái:**

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

Chuyển trạng thái hợp lệ, ép bằng bảng chứ không bằng `if` rải rác:
Chuyển trạng thái hợp lệ, ép bằng bảng chứ không bằng `if` rải rác:

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

**Nguyên tắc kế thừa từ `dms_vietqr` ("quét QR không phải là đã thu tiền"): `final` là trạng thái DUY NHẤT
mà consumer được coi là tiền đã chuyển.** `broadcast` và cả `mined` đều không. Ép bằng code:

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

**Vì sao sentinel object chứ không phải một chuỗi context.** `/json/2` nhận `context` từ client
(`Json2Dispatcher` → `Model.with_context(context)`), nên `context={'blockchain_gate': True}` sẽ bị một client
gửi lên được. Một `object()` cấp module không tồn tại trong JSON, không thể giả mạo, và không cần thêm
một tầng phân quyền nào. Đó là một dòng code.

`_set_finality` là method private duy nhất được phép ghi `final`:

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

Hai điều kiện là **VÀ**, không phải HOẶC — `max()` của hai trục (§10.4.2). `reversed` không bao giờ là một
`write` lên bản ghi cũ: nó là một settlement mới chiều ngược với `reversal_of_id`, vì sổ cái on-chain không
có UNDO.

**`mail.thread` và chi phí của nó.** Chỉ `settle_state` có `tracking=True`. Ước tính (cơ sở: `mail_message`
~400 B + `mail_tracking_value` ~120 B, 5 chuyển trạng thái/settlement): 10k settlement/tháng → 50k
`mail_message` ≈ 20 MB + 50k tracking ≈ 6 MB, mỗi tháng. **Ngưỡng: trên 100k settlement/tháng, bỏ
`mail.thread`** và thay bằng một bảng `blockchain.settlement.log` phẳng (chỉ 3 cột) — `mail.thread` còn
kéo theo `message_follower_ids` và một subquery trong mọi `search` nếu có filter theo follower.

#### 10.4.9. Contract deployment registry — model bản 1 thiếu

Không có model này thì: `verifying_contract` là một `Char` tự do không đối chiếu được; Policy Gate
"Target Contract Allowlist" mà chính `blockchain.md` yêu cầu không có chỗ để sống; và không ai trả lời được
"Zether token Z-VND trên Gnosis đang ở địa chỉ nào, phiên bản implementation nào" — câu hỏi sẽ được hỏi
trong tuần đầu tiên sau khi lên production.

**[BẢN 3] Trên factory mở, model này còn quan trọng hơn một bậc.** Nó không chỉ trả lời "contract của ta ở
đâu" mà trở thành **sổ xuất xứ**: contract này do factory nào sinh, ai tạo, chạy implementation nào, đã
audit chưa. Đó là dữ liệu duy nhất đứng giữa "nhận tiền bằng một token" và "tin một implementation chưa ai
đọc" (§09.4, §10.4.4).

```python
class BlockchainContractDeployment(models.Model):
    _name = 'blockchain.contract.deployment'
    _description = 'A deployed contract instance on a chain'
    _inherit = ['mail.thread']
    _order = 'chain_id, purpose, id'

    chain_id     = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='restrict')
    purpose      = fields.Selection([
        ('metatx_forwarder','EIP-1776 forwarder'), ('open_factory','Open factory'),
        ('erc20','ERC-20 token'), ('zether_registry','Zether account registry'),
        ('zether_token','Zether token'), ('zether_verifier','ZK verifier'),
        ('migration_sink','Migration sink'), ('paymaster','Paymaster / gas station'),
        ('multisig','Multisig / timelock'), ('other','Other')], required=True, index=True)
    address      = fields.Char(required=True, index=True)
    token_id     = fields.Many2one('blockchain.token', index=True)
    abi_id       = fields.Many2one('blockchain.contract.abi', index=True)      # §11.6
    impl_address = fields.Char(help='Implementation phia sau clone EIP-1167. BAT BIEN.')
    impl_version = fields.Integer(help='Version trong catalogue. 0 = createUnregistered.')
    factory_address = fields.Char(index=True, help='[BAN 3] Factory da sinh ra contract nay.')
    creator_address = fields.Char(index=True, help='[BAN 3] Nguoi tao. Bat bien.')
    source_commit = fields.Char(help='Git commit cua smartcontracts/ da build ra bytecode nay.')
    bytecode_sha256 = fields.Char(index=True)
    impl_code_hash  = fields.Char(index=True, help='[BAN 3] EXTCODEHASH cua implementation.')
    deploy_tx_id = fields.Many2one('blockchain.transaction', index=True)
    audit_attachment_ids = fields.Many2many('ir.attachment', string='Audit reports')
    audit_covers_code_hash = fields.Boolean(default=False,
        help='[BAN 3] Ban audit dinh kem co dung impl_code_hash nay khong. False = coi nhu chua audit.')
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

`is_allowed_target` là allowlist, và nó là một **field có `tracking`** chứ không phải một dòng trong
`ir.config_parameter`: bật một contract vào allowlist là một sự kiện phải có ai bật, lúc nào, và có
chatter. Chỉ `group_blockchain_manager` được ghi (§10.5).

`_one_active_per_purpose` dùng `models.UniqueIndex` với `COALESCE(token_id, 0)` vì `UNIQUE` của PostgreSQL
coi mọi NULL là khác nhau — một `UNIQUE(chain_id, purpose, token_id)` thường sẽ cho phép hai forwarder
`active` cùng lúc khi cả hai có `token_id IS NULL`. Đây là lỗi kinh điển và nó im lặng.

**[BẢN 3] Bốn thay đổi.** `token_beacon` và `token_factory` trong `purpose` được thay bằng `open_factory`,
`zether_verifier` và `migration_sink` — beacon không còn tồn tại (§01.1.3), verifier là một artefact hạng
nhất vì token trỏ tới nó bằng địa chỉ, và `MigrationSink` lên hạng nhất vì nó là đường sửa lỗi duy nhất
(§01.1.17.2). `impl_version` đổi từ `Char` sang `Integer` cho khớp catalogue. `factory_address` /
`creator_address` / `impl_code_hash` là ba cột xuất xứ.

Và `audit_covers_code_hash` là một cột nhỏ chặn một lỗi lớn: một `audit_attachment_ids` không rỗng **không**
có nghĩa contract này đã được audit — nó có nghĩa *có một file PDF đính kèm*. Bản audit phải nói đúng
`impl_code_hash` đang chạy. Trên factory mở, nơi ta có thể trỏ tới implementation của người khác kèm bản
audit công khai của họ, phân biệt này là ranh giới giữa "đã kiểm" và "đã đọc tiêu đề".

#### 10.4.10. Approval policy — maker-checker cho tiền ra

`blockchain.md` §10.4 yêu cầu hành động R3/R4 phải có người duyệt (Scheduled Transactions trên Hedera,
Arbiter Agent…). Bản 1 chỉ có một method `blockchain_authorize_payout` và một nhóm `treasury` — tức là
**một** người trong nhóm đó ký được bất kỳ số tiền nào. Đó không phải maker-checker.

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

        "(settlement_id) WHERE approve_state = 'pending'",
        'Settlement nay da co mot yeu cau duyet dang mo.')
```

Ràng buộc bắt buộc, ép trong `_authorize()`, không bằng UI: **người tạo settlement không được là người duyệt**
(`self.env.uid != request.requested_uid`), và **cùng một user không được đếm hai lần** vào quorum. Cả hai
là một dòng `if`, và thiếu chúng thì cả model này chỉ là trang trí.

Mặc định khi không có policy nào khớp: `amount_fiat_max_single = 0`, tức **luôn** cần người thứ hai.
Mặc định phải là an toàn; một deployment muốn nới lỏng phải tự tạo policy.

#### 10.4.11. Outbox và security event — chỗ hand-wave lớn nhất của bản 1

Bản 1 viết: *"Odoo gọi worker qua `requests`"*. Đó là một câu mô tả một bài toán khó mà không nói làm thế nào,
và cách hiển nhiên nhất để hiện thực nó là sai:

```python
# SAI. Dung tuyet doi khong lam the nay.
def action_submit(self):
    requests.post(worker_url, json=payload, timeout=10)     # tx da broadcast
    self.write({'settle_state': 'submitted'})               # transaction co the rollback sau day
```

Nếu transaction Odoo rollback sau khi `requests.post` trả về (một `@api.constrains` khác ném, một deadlock,
một `ConcurrencyError` khi ghi record khác trong cùng request), thì **trên chain đã có một giao dịch mà
trong Odoo không có bản ghi nào**. Chiều ngược lại cũng tệ: worker timeout nhưng đã nhận payload → Odoo
rollback → cron thử lại → **hai tx**. Trên một sổ cái không có UNDO.

**Chốt: transactional outbox.** Odoo chỉ **ghi** một dòng vào bảng; một cron (hoặc worker poll) đọc và gọi.

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

Ba tính chất bắt buộc:

1. `idempotency_key` đi **theo request HTTP** tới worker (header `Idempotency-Key`). Worker chịu trách nhiệm
   dedup — Odoo không thể tự bảo đảm exactly-once qua mạng.
2. `job_state` chuyển `queued → sent` **trước** khi gọi, và cron commit ngay trước đó (`env.cr.commit()`).
   Nếu Odoo chết giữa chừng, job ở `sent` và **không** được thử lại tự động: nó vào hàng chờ người kiểm
   (`_cron_outbox_reap` chuyển `sent` quá 10 phút thành `dead`). At-most-once cho bước gửi, exactly-once
   đạt được ở worker bằng `idempotency_key`. Đây là đánh đổi có ý thức: thà treo một payout còn hơn gửi hai lần.
3. Backoff: `next_attempt_datetime = now + min(2 ** attempt_count, 3600) giây`. Sau 8 lần → `dead` +
   một `blockchain.security.event`.

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

`perm_unlink = 0` cho **mọi** nhóm, kể cả manager. Một log bảo mật xoá được thì không phải log bảo mật.

**[BẢN 3] Ba `event_code` mới, đến từ factory mở và pool khoá:**

| `event_code` | Khi nào | Severity |
|---|---|---|
| `token_provenance_failed` | Một token trong `money.flow` hoặc `accepted_token_ids` có `factory()`/`version()` không đạt chính sách (§09.4) | `high` |
| `key_pool_exhausted` | Số khoá `active` không kẹt của một `relayer_id` về 0 (§06.8) | `critical` |
| `multi_key_nonce_desync` | >= 2 khoá của cùng một `relayer_id` báo `nonce_desync` trong 1 giờ — không phải nhiều sự cố mà là một (§06.8.1) | `critical` |

#### 10.4.12. Định lượng tăng trưởng và ngưỡng kiến trúc

Ước tính, cơ sở: kích thước dòng trung bình của PostgreSQL cho các model trên (24 byte header + cột),
cộng index. Giả định 3 event/tx, 1,2 settlement/tx, 5 chuyển trạng thái/settlement.

| Khối lượng | Tổng DB/tháng | Garage/tháng | Ngưỡng cần đổi kiến trúc |
| 1k settlement/tháng | ~8 MB | ~0,5 GB | Không. `ir.cron` đủ |
| 10k/tháng | ~55 MB | 0,5–5 GB | Bật retention trace |
| 100k/tháng | ~550 MB | 5–50 GB | **Bỏ `mail.thread`**, chuyển finality gate ra worker (§11.0) |
| 1M/tháng | ~5,5 GB | 50–500 GB | Partition `blockchain_event` theo tháng; chuyển `blockchain.event` sang ClickHouse và giữ Odoo là control plane |

Ngưỡng đổi từ `ir.cron` sang service (§11.0): cron tối thiểu 1 phút, scheduler đánh thức mỗi ~60 giây →
p50 độ trễ phát hiện finality ~30 giây, **p95 ~90 giây**. Trên Gnosis (hard finality ~160 giây) đó đã là
hơn một nửa ngân sách. Trên một private chain đó là **toàn bộ** độ trễ mà người dùng cảm nhận — và nó
không chấp nhận được cho UX thanh toán.

**[BẢN 3] Câu kết luận của bản 1 phải sửa.** Bản 1 viết: *"`ir.cron` đủ cho public chain, không đủ cho
private chain"*, dựa trên giả định private chain có finality tức thời. Chain private thật là Clique
block 5 s, **không** instant-final (§01.1.16), nên độ trễ finality ở đó không phải ~0 mà là hàng chục giây.
Kết luận đúng hơn: **`ir.cron` không đủ ở bất kỳ đâu có ràng buộc UX tính bằng giây**, và điều đó đúng cho
`ENDUSER_PAY` trên cả hai loại chain. Worker phải gọi `chain_event_ingest` (§11.11) chứ không đợi cron —
không phải vì chain nào nhanh, mà vì cron chậm.

---

### 10.5. ACL: nhóm quyền và record rule

#### 10.5.1. Nhóm

| Nhóm XML id | Tên | Được gì | `implied_ids` |
|---|---|---|---|
| `group_blockchain_viewer` | Blockchain / Viewer | Đọc settlement, transaction, event của công ty mình. **Không** thấy `signer_ref`, không thấy account role `treasury`/`relay`/`admin` | |
| `group_blockchain_operator` | Blockchain / Operator | Tạo settlement, retry outbox job thất bại, đọc metatx | viewer |
| `group_blockchain_approver` | Blockchain / Approver | Duyệt `blockchain.approval.request`. **Không** được tạo settlement | viewer |
| `group_blockchain_treasury` | Blockchain / Treasury | `blockchain_authorize_payout`, `withdraw` Zether, nạp quỹ relayer | operator |
| `group_blockchain_relayer_admin` | Blockchain / Relayer Admin | CRUD `blockchain.relayer`, đổi `allowlist_state` | operator |
| `group_blockchain_manager` | Blockchain / Manager | CRUD chain, endpoint, deployment, token, custody config, allowlist, cron | treasury + relayer_admin + approver |
| `group_blockchain_auditor` | Blockchain / Auditor | Đọc **tất cả** trong `env.companies`, kể cả zether entry và proof; ghi **chỉ** `blockchain.audit.disclosure` | |

Tách `treasury` khỏi `relayer_admin` là có chủ đích: người được phép chi tiền không được đồng thời là người
quyết định relayer nào hợp lệ. Đó là một con đường rút tiền một người.

**`approver` không `implied_ids` `operator`, và đó là điểm quan trọng nhất của bảng trên.** Nếu approver kế
thừa operator thì một người vừa tạo vừa duyệt được, và maker-checker (§10.4.10) trở thành trang trí. Ràng
buộc `self.env.uid != request.requested_uid` là lớp thứ hai; tách nhóm là lớp thứ nhất.

**`group_blockchain_manager` kế thừa cả ba nhánh** — nghĩa là manager cũng là treasury. Nếu một tổ chức muốn
manager **không** được chi tiền, bỏ `treasury` khỏi `implied_ids` và cấp tay. Mặc định gộp lại vì phần lớn
deployment nhỏ chỉ có một người; nhưng đây là một mặc định phải được đọc và chọn, không phải một tai nạn.

Đây cũng chính là câu hỏi D16 của canon §C21 (*"`group_blockchain_manager` có kế thừa `treasury` không"*).
Khuyến nghị ở đó: tổ chức có kiểm toán nội bộ thì **bỏ** `treasury` khỏi `implied_ids`.

#### 10.5.2. Ma trận ACL đầy đủ

**Một model không có dòng nào trong `ir.model.access.csv` là không ai truy cập được trừ superuser**, và
Odoo 19 chỉ log một warning lúc load (`odoo/modules/loading.py:257`: *"The models %s have no access rules in
module %s"*). Đó là một lỗi dễ sót vì nó không làm server chết. Bảng dưới là đầy đủ; mọi model trong §10.3
phải xuất hiện.

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

**`perm_unlink = 0` gần như ở mọi nơi — sổ cái không xoá được.** Ba ngoại lệ: `blockchain.rpc.endpoint`
(cấu hình thuần tuý), `blockchain.money.flow` (cấu hình), `blockchain.relayer.address` (cascade). Còn lại
dùng `state = 'retired'`. Với `blockchain.settlement`, thêm một chặn cứng không phụ thuộc ACL:

```python
def unlink(self):
    if any(rec.settle_state != 'draft' for rec in self):
        raise UserError(_("Chi settlement o 'draft' moi xoa duoc."))
    return super().unlink()
```

#### 10.5.3. Record rule và đại số của nó

Ba quy tắc của Odoo phải thuộc trước khi đọc phần này, vì hầu hết lỗi ACL đều từ hiểu sai chúng:

1. Rule **global** (`groups` rỗng) được **AND** vào mọi truy vấn, cho mọi user.
2. Rule của **cùng một nhóm** được **AND** với nhau.
3. Rule của **các nhóm khác nhau** được **OR** với nhau, rồi kết quả **AND** với các rule global.

Eval context của `domain_force` trong Odoo 19 là **đúng ba khoá** (`base/models/ir_rule.py:38-51`):
`user`, `company_ids`, `company_id`. **Không có `time`, không có `datetime`.** Một rule viết
`('expiry_datetime', '>', time.strftime(...))` sẽ raise lúc validate domain.

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

**Sửa một lỗi của bản 1.** Bản 1 chỉ có hai rule trên `blockchain.account`, cả hai đều chứa
`('company_id','in',company_ids)` và **không** có rule nào cho manager. Vì quy tắc 3, một user
`group_blockchain_manager` (kế thừa treasury → operator → viewer) chỉ nhận OR của hai rule kia →
**manager không nhìn thấy ví treasury**, tức không nhìn thấy chính cái ví mình phải quản lý. Bản 2 tách
điều kiện company ra rule **global** (không lặp lại trong từng rule nhóm) và thêm
`rule_account_manager_all` + `rule_account_auditor_all`.

Lưu ý Odoo 19 đổi `res.users.groups_id` → **`group_ids`**; code Python kiểm tra quyền phải dùng
`user.group_ids` (hoặc `user.has_group('...')`), còn `res.groups.implied_ids` giữ nguyên tên.

#### 10.5.4. Bảo vệ cột: `field.groups`, và hành vi chính xác ở Odoo 19

Record rule lọc **dòng**, không lọc **cột**. Bảo vệ `signer_ref` bằng `groups=` **trong định nghĩa field**
(không chỉ trong view):

```python
signer_ref = fields.Char(groups='dms_blockchain.group_blockchain_manager')
```

Hành vi chính xác, kiểm trên `odoo/orm/models.py`:

| Cách gọi | Kết quả khi không đủ quyền |
|---|---|
| `record.read()` (không truyền `fields`) | Cột bị **loại khỏi kết quả**. `check_field_access_rights` trả về danh sách field đọc được (dòng 3453-3459) |
| `record.read(['signer_ref'])` | **`AccessError`** (dòng 3465 → `_check_field_access` → raise) |
| `search_read` có `signer_ref` trong `fields` | `AccessError` (qua `_field_to_sql` dòng 2928) |
| `search([('signer_ref','=',x)])` | `AccessError` — domain cũng đi qua `_field_to_sql` |
| `write({'signer_ref': ...})` | `AccessError` (dòng 3553) |
| `env.su` / `sudo()` | **Bỏ qua hoàn toàn** (`if not field.groups or self.env.su: return True`) |
| Field `related`/`_inherits` trỏ tới nó | Kế thừa `groups` (`fields.py:777` `_related_groups`) |

Bản 1 viết "cột `signer_ref` không xuất hiện trong kết quả `read()`" — **đúng một nửa**. Hành vi im lặng đó
là của Odoo <= 16; từ 17 trở đi, gọi rõ tên field bị cấm là `AccessError`. Client phải biết điều đó, nếu
không một màn hình danh sách của mobile app sẽ vỡ 403 thay vì thiếu một cột.

Còn một mức mạnh hơn: **`groups = '.'` (hằng `NO_ACCESS` ở `models.py:122`)** — không nhóm nào đọc được, kể cả
`group_system`, trừ `sudo()`. Dùng cho field không bao giờ được lộ ra RPC:

```python
signature_hex = fields.Char(groups='.', readonly=True)   # chi server-side doc
```

Và lớp cuối cùng, không phải ACL: **không bao giờ để khoá vào DB.** `signer_ref` là một **handle**; kẻ lấy
được nó mà không lấy được HSM thì không ký được gì.

---

### 10.6. Bề mặt RPC công khai (CLAUDE.md §6)

#### 10.6.1. Bảng method

Mọi entry point: không bắt đầu bằng `_`, không `@api.private`, phục vụ cả hai đường, **không nhận tham số
`company_id`/`allowed_company_ids`** — phạm vi công ty suy ra từ `self.env.companies`.

| Model | Method | `@api.readonly` | Nhóm tối thiểu | Trả về |
|---|---|---|---|---|
| `blockchain.chain` | `blockchain_capabilities()` | có | viewer | `{'enabled','chains','payment_mode','server_time'}` |
| `blockchain.chain` | `blockchain_finality_state(chain_code)` | có | viewer | `{'head_block','final_block','lag_blocks','state'}` |
| `blockchain.account` | `blockchain_my_accounts()` | có | viewer | ví của chính user |
| `blockchain.account` | `blockchain_bind_challenge(chain_code, address)` | **không** | operator | nonce + message để ký |
| `blockchain.account` | `blockchain_bind_address(chain_code, address, signature_hex)` | không | operator | bình chứng sở hữu rồi tạo account |
| `blockchain.settlement` | `blockchain_submit_settlement(**kw)` | không | operator | `{'name','settle_state','needs_approval'}` |
| `blockchain.settlement` | `blockchain_settlement_status(origin_producer, origin_key)` | có | viewer | `{'settle_state','tx_hash','confirmations','is_paid'}` |
| `blockchain.settlement` | `blockchain_authorize_payout(origin_producer, origin_key)` | không | **treasury** | `draft → authorized` hoặc tạo approval request |
| `blockchain.approval.request` | `blockchain_approve(request_id, decision, note=None)` | không | **approver** | quorum counter |
| `blockchain.metatx` | `blockchain_quote_metatx(**kw)` | có | operator | phí ước tính + `expiry_datetime` + `digest_hash` để ví ký |
| `blockchain.metatx` | `blockchain_attach_signature(digest_hash, signature_hex)` | không | operator | ví ký ngoài, server không giữ khoá |
| `blockchain.relayer` | `blockchain_register_relayer(name, addresses, contact_url)` | không | **relayer_admin** | vào `allowlist_state='probation'` |
| `blockchain.token` | `blockchain_verify_provenance(token_id)` | không | manager | **[BẢN 3]** đọc `factory()`/`version()`/`verifier()` từ chain, ghi `provenance_state` (§10.4.4) |
| `blockchain.zether.account` | `zether_account_bootstrap(purpose)` (§02) | không | operator | |
| `blockchain.event` | `chain_event_ingest(caip2, events)` (§11.11) | không | worker service account | `{'accepted','duplicate','cursor_block'}` |

`@api.readonly` không phải trang trí: `rpc/controllers/json2.py:53` đặt `readonly=_web_json_2_rpc_readonly`,
hàm này đọc `method._readonly` để quyết định cấp **cursor read-only** (có thể trỏ tới replica). Một method
đọc mà quên `@api.readonly` vẫn chạy đúng nhưng ăn một connection ghi. Một method ghi mà **lỡ** đánh
`@api.readonly` sẽ raise lúc `write()` — dễ phát hiện, nhưng tốt nhất là có test.

#### 10.6.2. Company: quy tắc đúng, khác với quy tắc bản 1 viết

Bản 1 viết: *"không đọc `allowed_company_ids` từ payload RPC"*. Trong thực tế ta **không thể** không đọc:
`Json2Dispatcher` tạo `Model = request.env[__model__].with_context(context)` với `context` do client gửi, và
`Environment.companies` đọc `allowed_company_ids` từ context. Nhưng nó **an toàn**, và lý do là đây
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

Client **thu hẹp** được phạm vi (hợp lệ, hữu ích), không **mở rộng** được. Vậy quy tắc đúng không phải
"bỏ qua context" mà là ba điều này:

1. **Không bao giờ nhận `company_id` làm tham số của method.** Một tham số như vậy bỏ qua toàn bộ đoạn check
   trên. `self.env.company` và `self.env.companies` là nguồn duy nhất.
2. **Không bao giờ `sudo()` một method resolve company từ context.** Docstring của `companies` nói thẳng:
   *"No sanity checks applied in sudo mode!"*. Nếu cần `sudo()` (ví dụ để ghi `ir.cron`), `sudo()` **đúng
   một thao tác đó**, không `sudo()` cả method.
3. **Ghi `company_id` nổ ra trên record khi tạo**, không để mặc định chạy theo context của request sau.

Bản 1 còn có một verification item sai theo đó (§10.11 mục 6 cũ). Đã sửa.

#### 10.6.3. Hai đường, hai kiểu lỗi. Client phải biết cả hai.
`rpc/controllers/json2.py` nhận **chỉ kwargs** (`ids`, `context`, và `**kwargs`) và gọi
`signature.bind(records, **kwargs)`. Hệ quả bắt buộc cho mọi method công khai:

- **Mọi tham số phải có tên và phải gọi được bằng keyword.** Không đặt `*args`. Không dựa vào thứ tự.
- Method `@api.model` mà client gửi kèm `ids` không rỗng → **HTTP 422** (`UnprocessableEntity`).
- Model không tồn tại / method private / `@api.private` → **404** hoặc `AccessError`
  (`service/model.py:45-71`).

Bảng lỗi đầy đủ (`odoo/exceptions.py` + `odoo/http.py:2674-2694`):

| Exception | `/web/dataset/call_kw` | `/json/2` |
|---|---|---|
| `UserError`, `ValidationError` | HTTP **200** + JSON-RPC `error` | HTTP **422** |
| `AccessError`, `AccessDenied` | 200 + `error` | **403** |
| `MissingError` | 200 + `error` | **404** |
| `LockError` | 200 + `error` | **409** |
| Exception khác | 200 + `error` | **500** |

**Sửa so với bản 1**, vốn khẳng định `UserError` cho HTTP 200 "không phải traceback" — đúng cho `call_kw`,
**sai cho `/json/2`** (422). Mobile client xử lý HTTP status phải coi 422 là "lỗi nghiệp vụ, đọc `message`",
không phải "server hỏng, retry".

`LockError` → 409 là đúng ngữ nghĩa cho race idempotency, và nên dùng thay `UserError` ở đó.

#### 10.6.4. Mẫu chuẩn: entry point mỏng + logic private

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

Ba điểm không được bỏ:

1. **`search` trước `create` không đủ.** Hai worker song song đều `search` thấy rỗng rồi cùng `create`.
   `UNIQUE(company_id, origin_producer, origin_key)` là lớp chặn cuối, và nó ném `UniqueViolation` —
   phải bắt và đổi thành `LockError` (409), không để nó thành 500.
2. **`self.sudo().search`** cho bước dedup: nếu không, một user không đọc được bản ghi cũ sẽ tạo bản thứ hai.
   Nhưng chỉ `sudo()` **đúng câu search đó**, và chỉ trả `_as_dict()` của bản ghi cùng company.
3. **`_enqueue_outbox()` chứ không `requests.post()`.** Xem §10.4.11.

`blockchain_authorize_payout` là **cổng duy nhất** đưa tiền ra khỏi hệ thống và nó ở một method riêng, không
phải một tham số `auto_authorize=True` của `blockchain_submit_settlement` — một tham số boolean như vậy sẽ bị
client truyền `True` trong vòng một tuần.

#### 10.6.5. Versioning và tương thích ngược

Method công khai là **hợp đồng với mobile app đã phát hành**. Ba quy tắc:

1. Chỉ **thêm** tham số có giá trị mặc định. Đổi tên hay đổi thứ tự là breaking (client cũ gọi bằng
   positional qua `call_kw`).
2. Khoá mới trong dict trả về là không-breaking; **đổi/xoá** khoá là breaking.
3. Khi thật sự phải đổi: method mới tên `..._v2`, giữ method cũ gọi vào `_v2` với mặc định, và đặt
   `deprecated_since` trong docstring. Xoá sau 2 chu kỳ release, không sớm hơn.

---

### 10.7. `ir.cron`

Mọi body nằm trong method của model; XML dùng **một** dòng (eval context không có `fields`, không có
`relativedelta`).
| Cron | Chu kỳ | Gọi | Model |
|---|---|---|---|
| Outbox dispatch | 1 phút | `model._cron_outbox_dispatch()` | `blockchain.outbox.job` |
| Outbox reap (`sent` treo) | 5 phút | `model._cron_outbox_reap()` | `blockchain.outbox.job` |
| Receipt poll | 1 phút | `model._cron_poll_receipts()` | `blockchain.transaction` |
| Finality gate | 1 phút | `model._cron_finality_gate()` | `blockchain.transaction` |
| Reorg watch | 2 phút | `model._cron_reorg_watch()` | `blockchain.transaction` |
| Metatx expiry sweep | 5 phút | `model._cron_expire_metatx()` | `blockchain.metatx` |
| Approval expiry | 10 phút | `model._cron_expire_approvals()` | `blockchain.approval.request` |
| Relayer nonce/balance reconcile | 5 phút | `model._cron_relay_reconcile()` (§06) | `blockchain.relayer.account` |
| Zether rollOver (`accSeq`, **không** epoch) | 1 phút | `model._cron_zether_rollover_request()` — chỉ **tạo** `blockchain.relay.job`; **[BẢN 5, 2026-09-03]** job cho tài khoản `PUBLIC` **không mang chữ ký** và batch được, chỉ `OWNER_ONLY` mới cần blob do custody ký | `blockchain.zether.account` |
| RPC endpoint health probe | 2 phút | `model._cron_probe_endpoints()` | `blockchain.rpc.endpoint` |
| Custody probe + rotation due | 1 giờ | `model._cron_custody_probe()` (§07) | `blockchain.custody.provider` |
| Registry reconcile | 1 giờ | `model._cron_reconcile_registry()` (§02) | `blockchain.zether.account` |
| Attachment GC cho trace quá hạn | hàng ngày | `model._cron_gc_traces()` | `blockchain.transaction` |

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

`active=False` mặc định cho **mọi** cron. Cron được bật khi chain đầu tiên chuyển sang `state='enabled'`:

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

**Ba điều bản 1 không nói:**

1. **`sudo()` là bắt buộc**, không phải tuỳ chọn (giả định ẩn A12).
2. **Cron phải tự giới hạn lô và tự commit.** `ir.cron` không chạy hai instance của cùng một cron song song
   (có row lock), nhưng một lô quá lớn giữ lock qua cả chu kỳ sau và làm tồn đọng. Mẫu:

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

   `_trigger()` là cơ chế của `ir.cron` để xếp một lần chạy ngay lập tức (bảng `ir.cron.trigger`), thay vì
   đợi hết chu kỳ. Odoo 19 còn có `ir.cron.progress` cho cron dài — dùng khi một lô vượt 60 giây.
3. **`env.cr.commit()` trong cron là hợp lệ và cần thiết**; trong một request HTTP thì không. Đó là khác
   biệt duy nhất đáng kể giữa code cron và code RPC trong addon này.

---

### 10.8. Cấu hình, bí mật, và payment integration mode

#### 10.8.1. Bí mật

Không có field nào chứa bí mật. `ir.config_parameter` chứa **tham chiếu**, còn bí mật nằm ngoài DB
(KMS/HSM/vault/biến môi trường). Khoá dùng:

| Key `ir.config_parameter` | Giá trị | Bí mật? |
|---|---|---|
| `blockchain.default_chain_code` | `gnosis` | không |
| `blockchain.relay_worker.<chain_code>.base_url` | URL nội bộ (mTLS) | không |
| `blockchain.relay_worker.token_ref` | tên biến môi trường / vault path | không (con trỏ) |
| `blockchain.rpc.<endpoint_ref>.url` | URL đầy đủ **có** API key | **CÓ** → xem dưới |
| `blockchain.signer.<signer_ref>.backend` | `awskms`/`fireblocks`/`turnkey`/`local_dev` | không |
| `blockchain.finality.override.<chain_code>` | số block ghi đè | không |
| `blockchain.payment.ref_mode` | `hash` \| `plain` (§09) | không |

**Một cảnh báo bản 1 không nói: `ir.config_parameter` KHÔNG phải nơi để tiền bí mật.** Bảng
`ir_config_parameter` nằm trong DB, nằm trong mọi bản backup, và đọc được bởi bất kỳ ai có `group_system`
(hoặc bất kỳ SQL injection nào). Odoo chỉ bảo vệ nó bằng một ACL. Vậy:

- URL RPC **có API key** không được nằm trong `ir.config_parameter`. Đặt `endpoint_ref = 'gnosis_primary'`
  và để URL thật trong biến môi trường của relay worker. Odoo không cần biết URL — Odoo chỉ gọi worker.
- Nếu một deployment nhỏ vẫn muốn để trong DB, đó là một **quyết định có ý thức** phải ghi vào runbook, và
  khoá đó phải được làm rõ trong bảng trên. Không để nó thành một tai nạn.

`res.config.settings` phơi các khoá này ra UI bằng `config_parameter=`, bảo vệ bằng
`group_blockchain_manager`. Bẫy: **giá trị `ir.config_parameter` luôn là chuỗi.** Một
`fields.Integer(config_parameter=...)` đọc lại `'0'` là truthy nếu ai đó `get_param()` trực tiếp —
luôn `int(... or 0)` khi đọc.

#### 10.8.2. Payment integration mode

Bản 1 liệt kê 5 mode. §09.2 liệt kê 13. Cả hai đều đúng ở tầng khác nhau, và §10 chốt cách hoà giải:

- **5 mode của brief là 5 *họ*** (`payment.provider` in-house / acquirer ngoài / `account.payment` trực tiếp /
  sub-ledger / kết hợp). Đó là trục chính sách.
- **13 mode của §09.2 là 13 *handler cụ thể*** trong các họ đó. Đó là trục hiện thực.
- **Nơi lưu là `blockchain.money.flow`** (§09.4), một record cho một `(company, flow_code, chain)`, với
  `handler_code` là Selection mở rộng bằng `selection_add`. **Không** phải một khoá
  `blockchain.payment_integration_mode` toàn hệ thống như bản 1 viết — một deployment đầy đủ chạy ba mode
  cùng lúc (locked #8: "hoặc chọn theo từng luồng tiền"), nên một khoá đơn không diễn đạt được.

| Họ | Cơ chế | Module cần | Khi nào dùng |
|---|---|---|---|
| **1. `payment.provider` in-house** | `selection_add=[('chain','On-chain')]`; `_send_payment_request` tạo settlement; `_set_pending` khi `broadcast`; **`_set_done` CHỈ trong Finality Gate**; `_set_error` khi `reverted` | `dms_blockchain_payment` | Thanh toán end-user có giỏ hàng / portal |
| **2. Acquirer crypto bên ngoài** | Provider của bên thứ ba; chain chỉ là lớp đối soát, so khớp bằng `origin_key` **và** webhook | `dms_blockchain_payment` | Khi cần fiat off-ramp và KYC do acquirer lo |
| **3. `account.payment` trực tiếp** | Bỏ qua module `payment`; settlement `final` sinh `account.payment` đã reconcile | `dms_blockchain_account` | B2B, không giỏ hàng, kế toán cần bút toán từng giao dịch |
| **4. Sub-ledger đối soát theo lô** (mặc định) | `blockchain.settlement` là sổ cái độc lập; đối soát theo lô sang `account.move` cuối kỳ (§15.4) | không cần gì | Loyalty points, và mọi deployment chưa có `account` |
| **5. Kết hợp theo luồng tiền** | `blockchain.money.flow` một record cho mỗi dòng tiền | cả hai bridge | Deployment đầy đủ |

Họ 4 là mặc định vì nó là họ duy nhất chạy được với `depends = ['base','mail']`.
`blockchain.payment.handler.none` là handler mặc định, và nó **không làm gì** — một settlement vẫn chạy
hết vòng đời và vẫn `final`, chỉ không có hiệu ứng kế toán nào.

**Đổi mode là một chiều.** Settlement đã đối soát theo lô không tự sinh ngược ra `account.move` đơn lẻ. Một
`@api.constrains` trên `ir.config_parameter` không chạy, nên chặn trong `set_values()` của
`res.config.settings` **và** trong `write()` của `blockchain.money.flow`:

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

#### 10.8.3. Ánh xạ trạng thái cho họ 1 — chỗ dễ sai nhất, và một bẫy đã kiểm

| `settle_state` | `payment.transaction` |
|---|---|
| `draft`, `authorized`, `submitted` | `draft` |
| `broadcast`, `pending_finality` | `_set_pending()` |
| `final` | `_set_done()` rồi `_post_process()` |
| `failed`, `expired` | `_set_error(state_message)` |
| `reversed` | settlement mới + refund tx, **không** `_set_canceled()` trên tx cũ |

Ví của người dùng báo "success" ngay khi tx được mine. Đó là thời điểm `_set_pending`, không phải `_set_done`.
UI phải nói "đang chờ xác nhận mạng lưới (N/M block)" chứ không được nói "đã thanh toán".

**Bẫy đã kiểm trên source `payment/models/payment_transaction.py`:**

- Chữ ký là **keyword-only** cho ba hàm: `_set_pending(*, state_message=None, extra_allowed_states=())`,
  `_set_authorized(*, ...)`, `_set_done(*, ...)`. Nhưng `_set_error(state_message, extra_allowed_states=())`
  là **positional**. Gọi sai kiểu sẽ `TypeError`, không phải lỗi nghiệp vụ.
- `allowed_states` của `_set_error` là `('draft','pending','authorized')`. **`done` KHÔNG nằm trong đó.**
  Và `_update_state` (dòng 1035+) **không raise** khi trạng thái nguồn sai — nó chỉ log warning và bỏ qua.
  Hệ quả trực tiếp và nghiêm trọng: **sau một reorg, gọi `_set_error` trên một tx đã `done` không làm gì cả,
  và không ai biết.** Đó là lý do Finality Gate phải dùng ngưỡng **hard**, không phải soft; và là lý do
  `on_reorg` của handler (§09.4) bắt buộc phải hiện thực bằng một **giao dịch hoàn tiền / bút toán đảo**,
  không bằng một `write` trạng thái.
- `_set_done` allowed từ `('draft','pending','authorized','error')` — nên gọi `_set_done` hai lần là an toàn
  (lần hai rơi vào `txs_already_processed`, log INFO). Idempotency ở đây là miễn phí; hãy dựa vào nó.

---

### 10.9. Multi-company

- **Có `company_id`** (bắt buộc, index, rule global `[('company_id','in',company_ids)]`):
  `blockchain.settlement`, `.batch`, `blockchain.netting.set`, `blockchain.account`, `blockchain.zether.account`,
  `blockchain.zether.entry`, `blockchain.custody.provider`, `blockchain.approval.*`, `blockchain.outbox.job`,
  `blockchain.security.event`, `blockchain.watched.address`, `blockchain.relayer` khi `kind='internal'`.
- **Không có `company_id`** (hạ tầng dùng chung, lọc khả dụng bằng `company_ids` M2M): `blockchain.chain`,
  `blockchain.rpc.endpoint`, `blockchain.contract.deployment`, `blockchain.contract.abi`,
  `blockchain.token`, `blockchain.transaction`, `blockchain.event`, `blockchain.index.cursor`.
- `blockchain.transaction` không company-scoped vì **một tx có thể phục vụ nhiều settlement của nhiều công ty**
  (batch, §15.7). Khả năng đọc suy ra từ settlement liên kết, qua `settlement_ids` (§10.4.6) và rule
  `rule_transaction_via_settlement` (§10.5.3). Nhánh `('settlement_ids','=',False)` cho phép đọc tx chưa gắn
  settlement — cần thiết cho indexer và cho tx hệ thống (deploy, refill).
- **Một `blockchain.account` thuộc đúng một công ty.** Bản 1 viết ở đây một câu lẫn lộn
  ("hai bản ghi, cùng `address`, khác `chain_id`?"). Nói lại cho rõ: `UNIQUE(chain_id, address)` nghĩa là
  **một địa chỉ trên một chain chỉ có một bản ghi, và bản ghi đó thuộc đúng một company**. Nếu hai pháp nhân
  muốn dùng chung một ví treasury, họ không thể — và đó là cố ý: một ví chung giữa hai pháp nhân là một vấn đề
  pháp lý (ai sở hữu tài sản khi một bên phá sản?) trước khi là một vấn đề kỹ thuật. Nếu thật sự cần, cách
  dùng là **hai ví khác nhau** trên cùng chain, hoặc một multisig mà cả hai là signer, khai báo là
  `account_kind='multisig'` cho một company và một `blockchain.security.event` ghi lại thoả thuận.
- **Isolation của custody theo tenant** (§07.11) là tầng thứ hai: `signer_ref` của company B gửi qua cert
  mTLS của company A phải bị từ chối **ở signer service**, không chỉ ở Odoo. Odoo không phải biên tin cậy.

---

### 10.10. Suy giảm an toàn

Bản 1 chỉ xét một trường hợp ("chưa cấu hình chain nào"). Có bốn trường hợp, và ba trong số đó xảy ra trên
một hệ thống **đã** chạy.

#### 10.10.1. Chưa cấu hình chain nào (cài xong, chưa bật gì)

1. **Không có dữ liệu chain mặc định ở trạng thái `enabled`.** `data/blockchain_chain_data.xml` nạp Gnosis,
   Celo, và một mẫu private với `state='draft'`, `noupdate="1"`. Không có RPC endpoint (không URL nào dùng được).
2. **Mọi cron `active=False`** (§10.7). Không cron nào chạy định kỳ để rồi log một exception mỗi phút.
3. **Mọi entry point RPC trả lời có cấu trúc.** `blockchain_capabilities()` trả
   `{'enabled': False, 'reason': 'no_chain_enabled', 'chains': []}` (**không** raise — client dùng nó để ẩn
   nút). `blockchain_submit_settlement` raise `UserError` có mã (→ 422 trên `/json/2`, 200+error trên `call_kw`).
4. **Menu ẩn.** Menu gốc `groups="group_blockchain_viewer"`, và không nhóm nào được gán cho ai lúc cài
   (`res.groups.user_ids` rỗng trong `blockchain_groups.xml`). Admin phải chủ động cấp.
5. **`dms_blockchain_payment` không tạo `payment.provider` ở trạng thái `enabled`.** Provider mặc định
   `state='disabled'`, `is_published=False`.
6. **Bridge DMS là no-op.** `dms.trade.settlement.action_settle()` vẫn chạy nguyên như cũ; bridge chỉ **thêm**
   một bước khi `_enabled_chains()` không rỗng. Cài bridge lên production đang chạy phải là một no-op cho tới
   khi ai đó bật chain đầu tiên.

#### 10.10.2. Chain `enabled` nhưng relay worker không với tới được

Đây là trường hợp hay xảy ra nhất và bản 1 không nói. Outbox (§10.4.11) làm nó lành tính: settlement dừng ở
`submitted`, job ở `queued` với backoff, không mất gì. Nhưng **phải có một cái gì đó kêu**:

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

`degraded` (khác `halted`) nghĩa là: không nhận settlement mới qua RPC, nhưng vẫn tiếp tục theo dõi và chốt
finality cho những cái đang bay. Một chain `halted` thì dừng cả hai.

#### 10.10.3. Chain `enabled` nhưng RPC nói dối hoặc tụt hậu

`health_state='diverging'` trên endpoint (§10.4.2b) không tự hồi phục. Nếu **mọi** endpoint của một chain
`diverging` hoặc `down`, chain tự chuyển `degraded` và Finality Gate **dừng lại** — không được chốt `final`
trên dữ liệu từ một RPC đang nói dối. Đó là một lựa chọn: thà treo còn hơn chốt sai, vì `final` không rút lại
được (§10.8.3).

#### 10.10.4. Gỡ module

`uninstall_hook` bắt buộc, và nó **chặn** thay vì dọn:

```python
def _uninstall_guard(env):
    n = env['blockchain.settlement'].sudo().search_count([('settle_state', '=', 'final')])
    if n and not env['ir.config_parameter'].sudo().get_param('blockchain.allow_destructive_uninstall'):
        raise UserError(_(
            "Co %(n)s settlement da 'final'. Go module se xoa vinh vien so cai doi chieu voi chain. "
            "Dat ir.config_parameter 'blockchain.allow_destructive_uninstall' = '1' neu that su muon.", n=n))
```

Lý do không tự động export: một `uninstall_hook` sinh file là một hành vi bất ngờ trong một transaction
đang xoá bảng. Chặn, bắt người đọc thông báo, và để họ export bằng công cụ bình thường trước.

---

### 10.11. Kiểm chứng bắt buộc

Mỗi mục dưới là một lệnh chạy được hoặc một test file, không phải một ý định.

1. **SQL object thật sự tồn tại.** `_sql_constraints` dạng list bị Odoo 19 bỏ qua hoàn toàn, nên không tin code:
   ```sql
   SELECT conrelid::regclass AS tbl, conname, contype, pg_get_constraintdef(oid)
   FROM pg_constraint WHERE conrelid::regclass::text LIKE 'blockchain\_%' ORDER BY 1,2;
   SELECT tablename, indexname, indexdef FROM pg_indexes
   WHERE tablename LIKE 'blockchain\_%' AND indexdef ILIKE '%UNIQUE%';
   ```
   Đối chiếu với danh sách ở §10.4. Test tự động: `tests/test_sql_objects.py` đọc `pg_constraint` và so với
   một danh sách hardcode; test fail khi ai đó thêm constraint mà quên cập nhật danh sách.
2. **Standalone thật.** Trên một DB **không có `dms`**: `odoo -d test_bare -i dms_blockchain --stop-after-init`
   → 0 ERROR, 0 CRITICAL. Thêm `grep -c "no access rules" log` phải bằng 0.
3. **Không còn chuỗi `dms` trong core.** `grep -rn "'dms\." dms_blockchain/ | grep -v dms_blockchain` → rỗng.
4. **Auto-install.** Cài `dms` → `SELECT name, state FROM ir_module_module WHERE name LIKE 'dms_blockchain%';`
   → `dms_blockchain_bridge` = `installed`.
5. **Gỡ `dms`** → bridge bị gỡ, `SELECT count(*) FROM blockchain_settlement;` không đổi.
6. **Idempotency.** Gọi `/json/2/blockchain.settlement/blockchain_submit_settlement` **hai lần** cùng
   `(origin_producer, origin_key)` → một bản ghi. Chạy hai lần **song song** (hai process) → một bản ghi
   và một HTTP 409.
7. **Company scope.** Gọi cùng method với `context={'allowed_company_ids': [<id company khong thuoc user>]}`
   → **HTTP 403** (`AccessError` từ `Environment.companies`). Gọi với một company hợp lệ của user →
   settlement thuộc đúng company đó. **(Bản 1 mong đợi "tham số bị bỏ qua" — sai, xem §10.6.2.)**
8. **Field groups.** User chỉ có `group_blockchain_viewer`:
   - `read()` không tham số → không có khoá `signer_ref` trong dict.
   - `read(['signer_ref'])` → **`AccessError`** (không phải dict thiếu khoá).
   - `search([('signer_ref','!=',False)])` → `AccessError`.
9. **Groups đi qua `_inherits`.** Cùng user đó đọc `blockchain.relayer.account` → `signer_ref` vẫn bị chặn.
   Nếu **không** bị chặn, `_inherits` là một đường rò và phải bỏ, thay bằng M2O tường minh.
10. **Không đường nào ghi `final` ngoài gate.** `write({'settle_state':'final'})` trực tiếp → `UserError`.
    `write` với `context={'blockchain_gate': True}` do client gửi → **vẫn** `UserError` (sentinel object).
11. **Chuyển trạng thái.** Bảng tham số hoá `_ALLOWED`: mọi cặp `(a, b)` không nằm trong bảng phải raise.
12. **Cron.** Bật một chain → `SELECT name, active FROM ir_cron WHERE name LIKE 'Blockchain:%';` tất cả
    `active = true`. Tắt chain cuối cùng → tất cả `false`. Chạy `_toggle_crons` bằng một user chỉ có
    `group_blockchain_manager` (không `group_system`) → không `AccessError`.
13. **Outbox.** Kill relay worker, gọi submit → settlement `submitted`, job `queued`, không exception.
    Bật lại worker → job `acked` trong 1 chu kỳ cron. Kill Odoo giữa `sent` → job vào `dead`, không gửi lại.
14. **Non-EVM.** Tạo `blockchain.account` với `chain_family='cosmwasm'` và một địa chỉ bech32 90 ký tự →
    lưu **đủ 90 ký tự** (chứng minh không còn `size=`). Đọc lại và so sánh chuỗi.
15. **uint256.** Ghi `amount_base = '115792089237316195423570985008687907853269984665640564039457584007913129639935'`
    (2^256-1) → lưu nguyên; `amount_base = '007'` → `IntegrityError` từ CHECK.
16. **Approval.** Người tạo settlement tự bấm duyệt → `UserError`. Hai user khác nhau → quorum đủ, `authorized`.
17. **Payment họ 1.** Sau `_set_done`, gọi `_set_error` → không đổi trạng thái và **có** một warning trong log;
    test phải khẳng định handler `on_reorg` đã tạo một settlement bù, không dựa vào `_set_error`.

---

### 10.12. Chi phí và độ phức tạp: những con số quyết định

Tập hợp lại để kế hoạch triển khai có thể ước lượng. Tất cả là **ước tính**, cơ sở ghi kèm.

| Đại lượng | Giá trị | Cơ sở |
|---|---|---|
| Gas một ERC-20 transfer thường | 34k-51k | 21,000 base + SSTORE 20,000 (0→nonzero) hoặc 2,900 (warm) + cold SLOAD 2,100 |
| Gas một `executeMetaTransaction` (EIP-1776) chuyển token + trả fee | 95k-140k | base 21,000 + calldata ~500 B x 16 + ecrecover 3,000 + nonce SSTORE 5,000 + 2 ERC-20 transfer |
| Gas một Zether `transferConfidential` | **1.2M-2.5M** | ~200-350 `ecMul` x 6,000 (EIP-1108) sau khi gom multi-exp + calldata ~2.4 KB x 16. **Note ghi 180k-250k là con số của pairing Groth16, không phải Bulletproof.** |
| Chi phí một metatx trên Gnosis | ~$0.0003 | 130,000 gas x ~2 gwei x 1 xDAI ≈ 1 USD |
| Chi phí một Zether tx trên Gnosis | ~$0.004 | 2M gas x 2 gwei |
| Chi phí một Zether tx trên Ethereum L1 (10 gwei, ETH $3,000) | **~$60** | 2M x 10e-9 x 3,000. Đây là lý do locked #5. |
| Kích thước proof Zether (calldata BN254) | ~2.4 KB | Bảng ở §10.4.7 |
| Kích thước proof nén (32 B/điểm) | 1.4-2.0 KB | Cùng bảng, điểm nén |
| Trace EVM đầy đủ | 50-500 KB | JSON trace điển hình |
| Độ trễ finality gate qua `ir.cron` | p50 30 s, **p95 90 s** | Cron tối thiểu 1 phút, scheduler ~60 s |
| DB tăng trưởng ở 10k settlement/tháng | ~55 MB/tháng | §10.4.12 |
| Chi phí đổi tên module sau deploy | ~700 dòng `ir_model_data` + 24 rename bảng | §10.1 |

---

### 10.13. Câu hỏi còn phải người quyết

Không phải thiếu nghiên cứu — thiếu một quyết định của người.

1. **`meta_nonce` tăng trước hay sau `call` trong contract EIP-1776?** (§06.10 mục 3 để mở.) Quyết định này
   thay đổi `blockchain.metatx.attempt_seq` có cần hay không, và có cần `antiGriefBond` hay không. **Phải
   chốt trước khi freeze ABI**, tức trước M1.
2. **Manager có đồng thời là treasury không?** §10.5.1 mặc định có. Một tổ chức có kiểm toán nội bộ sẽ muốn
   không. Câu trả lời đổi một dòng `implied_ids`, nhưng đổi sau khi đã cấp quyền cho người thật thì phải
   rà soát lại toàn bộ user.
3. **Ngưỡng `amount_fiat_max_single` mặc định là bao nhiêu?** §10.4.10 chốt 0 (luôn cần hai người). Đó là an
   toàn nhưng sẽ làm chậm loyalty 5,000 điểm. Có nên mặc định khác theo `use_case`?
4. **Gnosis `finality_hard_seconds`: 160 giây hay ít hơn?** Con số trong bảng là ước tính. Phải đo thật
   trên mainnet (thời gian từ `latest` đến `finalized`, p99 trong 7 ngày) trước khi `enabled`.
5. **Celo sau khi thành L2**: `finality_mode` là `l1_batch` hay `depth`? Và `finality_hard_seconds` bằng bao
   nhiêu? Toàn bộ giả định BFT trong `blockchain.md` không còn đúng.
6. **`origin_producer` do ai cấp?** Nếu client tự khai, một client có thể giả mạo namespace của client khác
   và nuốt một settlement. Đề xuất: `origin_producer` suy ra từ **service account** đang gọi
   (`self.env.user.login`), không nhận từ tham số. Cần xác nhận vì nó đổi chữ ký method.
7. **Retention trace 90 ngày có đủ cho yêu cầu kiểm toán tại VN?** §13 phải trả lời; §10 chỉ đặt mặc định.
8. **Có bỏ `mail.thread` khỏi `blockchain.settlement` ngay từ đầu không?** Nếu khối lượng dự kiến > 100k/tháng
   thì bỏ ngay rẻ hơn là gỡ sau (§10.4.12).
9. **`blockchain.money.flow` và `blockchain.approval.policy` chồng lấn nhau ở đâu?** Cả hai đều là "chính sách
   theo (company, luồng tiền)". Có nên gộp? Đề xuất: không gộp — một cái chọn **đường đi của tiền**, một cái
   chọn **ai được bấm**. Nhưng phải có một màn hình duy nhất hiện cả hai, nếu không không ai kiểm tra được.
10. **[BẢN 3] Ai chịu chi phí verify provenance cho token của người lạ?** Factory mở nghĩa là bất kỳ ai cũng
    tạo được một token tên `zDAI`. `blockchain_verify_provenance` (§10.6.1) đọc chain, nhưng **quyết định
    chấp nhận** là của người vận hành, không của code. Câu hỏi còn mở: một danh sách chấp nhận thủ công cho
    mỗi company, hay một điểm tin cậy suy ra từ `deploy_block` + khối lượng + tuổi? §01 §1.11 nghiêng về
    thủ công cho v1.

---

### 10.14. Chỗ note gốc / section khác / bản 1 sai hoặc thiếu

**Về `blockchain.md`:**

1. **Không nói gì về tầng Odoo.** Toàn chương 10 của note là kiến trúc off-chain/on-chain; không model, không
   ACL, không biên giới module. Section này là phần bù, và nó là phần quyết định xem "standalone" có thực sự
   dùng được hay không.
2. **Gas Zether sai một bậc độ lớn.** Note: "~180,000 - 250,000 gas". Thực tế 1.2M-2.5M (§10.12). Con số của
   note là chi phí một pairing check Groth16, không phải chi phí verify Bulletproof.
3. **Celo: "Istanbul BFT 2.0, 5 giây, immediate finality" đã lỗi thời.** Celo là Ethereum L2 trên OP Stack từ
   2025. Mọi con số finality của Celo trong note phải đo lại.
4. **"Simulation gate với tỷ lệ revert 0%"** là một mục tiêu không đạt được, không phải một ràng buộc thiết kế.
   Trạng thái chain đổi giữa simulate và mine. §06.3 đã nói; §10 chỉ ghi lại để không ai xây UI hứa 0%.
5. **Note không nói ai được phép bấm nút chi tiền.** §10.4.10 + §10.5.1 trả lời bằng maker-checker và bằng
   việc tách `treasury` khỏi `relayer_admin` khỏi `approver`.
6. **Note giả định Odoo sẽ đọc được số tiền Zether để đưa vào ERP.** Không. Nếu công ty không giữ khoá giải mã
   thì `amount_clear_base` rỗng **vĩnh viễn**, và mọi báo cáo doanh thu trên sổ bảo mật phải được thiết kế với
   cột rỗng là trường hợp bình thường, không phải lỗi dữ liệu.
7. **Note không nói số uint256 được lưu thế nào trong PostgreSQL qua Odoo ORM.** §10.4.1 chốt Char + CHECK.
   Bỏ qua điểm này sẽ dẫn đến một cột `Float` làm tròn số dư token 18 decimals và không ai phát hiện cho tới
   khi đối soát lệch vài wei.

**Về các section khác:**

8. **§02.8.5 giữ `blockchain.chain.profile` là model riêng** — phải xoá, gộp vào `blockchain.chain` (§10.3).
   `blockchain.zether.account.chain.profile_id` → `chain_id`. *(Bản 1 quy lỗi này cho "01 §1.13" — sai địa chỉ.)*
9. **§08.1 định nghĩa lại `blockchain.chain` với bộ field khác** (`fee_token_mode`, `native_is_stable`,
   `finality_depth`, `state='live'`) — đổi theo §10.4.2.
10. **§06.9: `runway_hours = fields.Float(compute=..., store=True, required=True, default=0.0)`** — stored
    computed field **không** được nhận `default`, và `required=True` biến một nhánh không gán giá trị thành
    INSERT chết. Sửa: bỏ `default`, bỏ `required`, gán `rec.runway_hours = 0.0` ở dòng đầu compute.
    Áp dụng y hệt cho `net_wei` (§05), `divergent` (§02), `is_final` (§11), và `amount_display`,
    `fee_native_display`, `reputation_score` (section này).
11. **§06.9 `balance_native = fields.Float(digits=(24,8))`** — số dư native là uint256 wei; `Float` mất chính
    xác từ 2^53. Đổi thành `balance_native_base = fields.Char()`.

**Về chính bản 1 của section này** (mọi cái đã sửa ở trên):

12. `size=` trên mọi field hex/address — deprecated, không ép ở DB, **cắt chuỗi im lặng** (§10.4.0(1)).
13. CHECK `^0x[0-9a-f]{40}$` vô điều kiện trên `address`, và `tx_hash size=66` — chặn hết 5 họ non-EVM
    (§10.4.3, §10.4.6).
14. `UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)` tuyệt đối — làm không thể thử lại một
    metatx hết hạn; phải là `models.UniqueIndex` partial (§10.4.5).
15. `UNIQUE(company_id, origin_key)` thiếu namespace consumer (§10.4.8).
16. `_order = 'sequence, id'` trên `blockchain.chain` mà **không khai báo field `sequence`** (§10.4.2).
17. `amount_display = fields.Float(digits=(24,8))` — 8 chữ số thập phân làm 1 wei biến mất trên token 18
    decimals; và `Float` là double trong Python dù cột là `numeric` (§10.4.0(2), §10.4.1).
18. `chain_profile` ba giá trị — phá vỡ mọi guard `== 'public'` của §05/§08 một cách im lặng (§10.3).
19. Không có model cho contract đã deploy, nên `verifying_contract` là `Char` tự do và allowlist không có chỗ
    để sống (§10.4.9).
20. Không có maker-checker; một người trong `treasury` chi được bất kỳ số tiền nào (§10.4.10).
21. "Odoo gọi worker qua `requests`" — một HTTP call trong transaction; phải là outbox (§10.4.11).
22. ACL thiếu rule cho manager trên `blockchain.account` → **manager không nhìn thấy ví treasury** (§10.5.3).
23. "cột `signer_ref` không xuất hiện trong `read()`" — chỉ đúng khi không truyền `fields`; truyền tên field
    là `AccessError` (§10.5.4).
24. "không nhận `allowed_company_ids`" — không thể không nhận; quy tắc đúng là không nhận **tham số**
    `company_id` và không `sudo()` (§10.6.2).
25. "`UserError` cho ra HTTP 200" — đúng cho `call_kw`, **422** cho `/json/2` (§10.6.3).
26. `_toggle_crons()` thiếu `sudo()`; `ir.cron` là `group_system` (§10.7).
27. Một khoá `blockchain.payment_integration_mode` toàn hệ thống — không diễn đạt được locked #8 ("chọn theo
    từng luồng tiền"); phải là `blockchain.money.flow` (§10.8.2).
28. `ir.config_parameter` được mô tả như nơi an toàn cho tham chiếu, nhưng không cảnh báo rằng nó nằm trong
    mọi bản backup — URL RPC có API key không được ở đó (§10.8.1).
29. Thiếu `ir.sequence` cho `blockchain.settlement.name` (`required=True, default='/'` mà không ai điền) (§10.4.8).
30. Thiếu `settlement_ids` One2many trên `blockchain.transaction` mà chính rule multi-company của bản 1 lại
    tham chiếu tới (§10.4.6, §10.9).
31. Suy giảm an toàn chỉ xét "chưa có chain"; thiếu ba trường hợp xảy ra trên hệ thống đang chạy: worker chết,
    RPC nói dối, gỡ module (§10.10.2-10.10.4).

**[BẢN 3] Về giả định "sẽ có upgrade":**

32. Bản 1 và bản 2 đều có model `blockchain.upgrade.proposal` và một luồng duyệt nâng cấp implementation.
    Quyết định §20.2 của `_USER-DECISIONS.md` xoá toàn bộ: token đã deploy **không bao giờ** nâng cấp được.
    Model bị gạch khỏi registry (§10.3), và chỗ nó chiếm được thay bằng bảy cột provenance trên
    `blockchain.token` (§10.4.4) — vì trong một factory mở, câu hỏi không còn là "phiên bản nào" mà là
    "contract này có thật sự do factory sinh ra không".