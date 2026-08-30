## 09. Payment API va 5+ che do tich hop, chon bang cau hinh

### 09.0. Nguyen tac va ranh gioi

Ke thua `dms/models/orders/dms_vietqr.py`: *"Quet QR khong phai la da thu tien"*.
Ban dich blockchain: **broadcast khong phai la da thanh toan; mined cung chua phai.**
`payment.transaction._set_done()` chi duoc goi tai trang thai `final` cua Finality Gate (§05.8,
§10.4 cua note). Moi trang thai truoc do la `_set_pending()`, ke ca khi vi cua nguoi tra da hien
"Success" va Metamask da bao "Confirmed".

Rang buoc #7 (standalone) khien section nay **khong the** la mot addon. `payment` keo theo
`onboarding` + `portal` (kiem chung: `odoo-src-19/addons/payment/__manifest__.py`, `depends:
['onboarding', 'portal']`); `account.payment` keo theo `account`. Neu core `dms_blockchain` depend
`payment`, thi mot deployment chi muon anchor hash cung phai cai ca payment engine. Vi vay che do
tich hop khong phai la mot `Selection` trong mot addon, ma la **mot truc addon**:

| Addon | `depends` | Chua gi | Che do mo khoa |
|---|---|---|---|
| `dms_blockchain` (core) | `base`, `web` | `blockchain.chain`, `blockchain.token`, `blockchain.payment.request`, `blockchain.payment.observation`, `blockchain.money.flow`, `blockchain.payment.quote`, watcher ingest, Finality Gate | M4, M12, M18 |
| `dms_blockchain_payment` | + `payment` | `payment.provider` `code='chain'`, `payment.transaction` overrides, `payment.method` data | M1, M6, M11 |
| `dms_blockchain_acquirer` | + `payment` | Adapter cho acquirer ben thu ba (Coinbase Commerce / Triple-A / BitPay-class) | M2 |
| `dms_blockchain_account` | + `account` | `account.payment`, batch reconcile vao `account.move`, FX/impairment journal | M3, M4 (nua ke toan), M15 |
| `dms_blockchain_mandate` | + `payment` | Allowance / ERC-2612 permit / session-key mandate, stream, escrow | M7, M8, M9, M10 |
| `dms_blockchain_dms` | + `dms`, `dms_blockchain` | Bridge toi `dms.payment.collection`, `dms.trade.settlement`, `dms.outlet.credit` | — |

Che do khong cai = code khong ton tai. Do la co che open/closed tang mot; tang hai o §09.4.

Duong dan: `/home/dockers/odoo19/custom-addons/dms_blockchain*/`, `smartcontracts/` o goc repo theo
quyet dinh #9.

> **[SUA] Bay `auto_install` ma ban nhap bo qua.** `account_payment/__manifest__.py` khai
> `'auto_install': ['account']`. Nghia la: tren bat ky database nao da cai `account`, viec cai
> `dms_blockchain_payment` (depend `payment`) se **tu dong** keo `account_payment` vao. Ta khong
> chon duoc "M1 khong ke toan" tren mot DB co Accounting. He qua bat buoc:
> `account_payment._post_process()` se chay, se goi `_create_payment()`, va se doc
> `self.provider_id.journal_id`. Neu journal chua cau hinh, moi giao dich `done` se nem exception
> **ben trong post-processing**, tuc la tien da ve chain, tx da `done`, va Odoo im lang fail o cron.
> Vi vay: `dms_blockchain_payment` phai co mot preflight check chan `state='enabled'` khi
> `journal_id` rong (§09.5).

> Bat nhat quan can chot: §05 dat ten model `dms.blockchain.intent`, §01/§02/§06 dat
> `blockchain.token` / `blockchain.relay.job`. Section nay dung tien to **`blockchain.`** (khong
> `dms.`), theo da so va theo §06.0 — vi addon standalone khong duoc mang ten mien `dms` trong
> model name khi `dms` co the khong ton tai.

> **[SUA] Dat ten so tien.** §15 da chot hau to `_base` cho so nguyen don vi co so luu dang `Char`
> (`total_base`, `delta_base`, `drift_base`). Section nay doi `amount_token_units` →
> **`amount_base`** de dong bo. Ly do ky thuat khong doi: `fields.Integer` cua Odoo la `int64`,
> `1e18 × 1000` = `1e21` da tran tu lau; `fields.Float` mat chinh xac tu `2^53`. Ap them mot
> constraint dinh dang, vi `Char` khong tu bao ve:
> ```python
> _amount_base_is_uint = models.Constraint(
>     "CHECK (amount_base ~ '^(0|[1-9][0-9]{0,77})$')",
>     'amount_base phai la so nguyen khong dau, toi da 78 chu so.')
> ```

---

### 09.0b. Nhung gia dinh ban nhap **khong noi ra** (va he qua neu sai)

| # | Gia dinh ngam | Vi sao no khong hien nhien | Xu ly o ban nay |
|---|---|---|---|
| A1 | Mot `payment.provider` phuc vu duoc nhieu chain × nhieu token | `account_payment` gan **mot** `journal_id` cho **mot** provider. Nhieu token duoi mot provider = tat ca tien vao mot journal, mat kha nang doi soat theo token | §09.5c: **mot provider cho moi (company, chain, settlement token)**, hoac override `_create_payment` |
| A2 | Tien te cua `payment.transaction` la tien te cua token | Khong. `amount` la **fiat** (`res.currency`), on-chain la base units. Giua hai cai co mot **ty gia** va mot **cua so hieu luc** | §09.7b: model `blockchain.payment.quote` |
| A3 | Watcher → cron → `_set_done` du nhanh cho `ENDUSER_PAY` | `ir.cron` co do phan giai **1 phut**; cron post-process cua Odoo mac dinh **10 phut**. Do tre yeu cau la **giay** | §09.5d: `cron._trigger()` + `_post_process()` goi truc tiep + bus notification |
| A4 | `_set_done` keo theo `_post_process` | Khong. `_post_process` chi chay tu `/payment/status/poll` (nguoi dung mo trinh duyet) hoac tu cron `payment.cron_post_process_payment_tx`. Nguoi tra khong bao gio mo app ⇒ **khong ai poll** | §09.5d |
| A5 | Handler interface public la an toan | Method public tren mot model Odoo **la RPC endpoint**. `on_final(request, observation)` public = bat ky user co ACL read cung ep duoc mot `_set_done` | §09.4: doi thanh `_on_final`, them facade public mong |
| A6 | Reference 40 bit la "gan du" | Sai so xac suat 3 bac. Voi 10^7 request, va cham gan nhu **chac chan** | §09.6: tinh lai, chot 64 bit |
| A7 | Mot ma QR EIP-681 quet duoc bang moi vi | Gan nhu khong vi nao ho tro goi ham tuy y qua EIP-681; chi `transfer` cua ERC-20 duoc ho tro mot phan | §09.6: R1 + WalletConnect, EIP-681 chi la tien ich |
| A8 | Zether transfer ~200k gas | Sai 15-20 lan; §03.3.7 da bat duoc. Con so that: **1.88 M** (32/64) | §09.9, §09.10 |
| A9 | Nguoi tra luon la mot `res.partner` ton tai | `payment.transaction.partner_id` **required**, `payment.token` cam partner public | §09.8b: chinh sach tao partner tu vi |
| A10 | Expiry + `_set_canceled` la du de dong mot request | Tien van co the ve sau do. Va neu tx da lien ket invoice, `account_payment._post_process` se `payment_id.action_cancel()` | §09.7 |
| A11 | Reorg la truong hop hiem | Voi `finality_mode='soft'` tren Gnosis (1 block) thi khong | §09.7, co cong thuc ton that ky vong |
| A12 | Mot cron loop la du ben | `for obs in ...: _process(); commit()` — mot observation loi lam chet ca vong lap ⇒ head-of-line blocking, hang doi dung yen | §09.5d: try/except/rollback tung dong |
| A13 | Tra thua/thieu la ngoai le | Voi thanh toan tu vi tu do, tra thieu do phi va lam tron la **binh thuong** | §09.7 bang tolerance |
| A14 | Chi phi xay = so person-week | Thieu chi phi van hanh: node/RPC, kiem toan hop dong, giam sat 24/7, quy du phong reorg | §09.10c |

---

### 09.1. Truc thu hai: money-flow. Che do duoc chon **theo tung dong tien**, khong theo he thong

Quyet dinh #8 noi "combination per money-flow". De lam duoc dieu do phai co danh sach dong tien
dong nhat, dat trong core:

| `flow_code` | Huong | Doi tuong Odoo dien hinh | Do tre chap nhan duoc | Che do kha thi |
|---|---|---|---|---|
| `LOYALTY_ACCRUE` | issuer → outlet/consumer | khong co (sub-ledger) | phut | M4, M12, M18 |
| `LOYALTY_REDEEM` | consumer → outlet | `sale.order` discount | giay | M4, M9, M18 |
| `B2B_PAYOUT` | brand → distributor | `dms.trade.settlement.payout_line_ids` | gio | M3, M4, M9, M17 |
| `B2B_INVOICE_PAY` | distributor → brand | `account.move` (`out_invoice`) | gio | M1, M6, M7, M15 |
| `OUTLET_COLLECT` | outlet → distributor | `dms.payment.collection` | phut | M0, M1, M6, M11 |
| `ENDUSER_PAY` | consumer → outlet | `pos.order` / `sale.order` | **giay** | M1, M11, M2, M14 |
| `RELAYER_FEE` | issuer → relayer | `account.move` (`in_invoice`), §05.8 | ngay | M4 |
| `REFUND` | nguoc lai bat ky flow nao | `payment.transaction` con | gio | M1 (co dieu kien), M3 |
| `ESCROW_MILESTONE` | brand → distributor theo moc | `dms.trade.claim` | ngay | M9 |
| `SUBSCRIPTION` | distributor → brand dinh ky | `sale.subscription` | ngay | M7, M8, M10 |
| `FIAT_ONRAMP` | consumer/distributor → treasury (VND → token) | `account.payment` + `blockchain.settlement` | gio | M16 |
| `FIAT_OFFRAMP` | treasury → ngan hang (token → VND) | `account.payment` | ngay | M16 |

`ENDUSER_PAY` la dong duy nhat co rang buoc do tre **giay**, va do la ly do ky thuat lon nhat de
Gnosis/Celo di truoc: soft finality 5s. Tren Ethereum L1, `ENDUSER_PAY` voi hard finality 12.8 phut
la khong the ban tai quay — phai chap nhan soft-final (§09.7) hoac dung M2.

#### Truc thu ba ma ban nhap bo sot: `chain_profile`

Quyet dinh #5 dat `public` vs `private` la mot truc kien truc. §08.1 da co
`blockchain.chain.chain_profile`. Truc do **phai** doi mac dinh cua lop payment, khong chi cua lop
adapter:

| Tham so | `chain_profile = 'public'` | `chain_profile = 'private'` | Ly do |
|---|---|---|---|
| `finality_mode` mac dinh | `hard` | `soft` (BFT instant = final ngay) | QBFT/IBFT khong reorg khi < 1/3 validator loi |
| `confirm_depth` mac dinh | theo `blockchain.chain.finality_depth` | `1` | — |
| `ref_mode` mac dinh | `hash` | `plain` | Khong co doi thu doc chain; debug de hon nhieu |
| `receiving_mode` mac dinh | `derived` (CREATE2) | `router` | Gas ~0, khong can tiet kiem; router cho log giau hon |
| Ke toan phi gas | co dong chi phi | **khong co** (gas price = 0) | §08.1 `fee_token_mode='free'` |
| Zether kha thi cho `ENDUSER_PAY` | khong (§09.9) | **co** | §09.9 |
| `soft_final_max_amount` | huu han, xem §09.7 | vo han | Khong co reorg |

Rang buoc bat buoc, viet duoi dang `@api.constrains`, khong phai duoi dang loi khuyen:
`payment.provider.state == 'enabled'` ⇒ moi `chain_id` trong `chain_ids` phai co
`is_production = True`. Thieu no, mot lan copy database staging sang production la du de nhan
tien that tren Chiado testnet (canh bao nay lay tu §08.1, ap dung vao lop payment).

---

### 09.2. Danh sach day du 20 che do

Danh so M0..M19. **Khong doi so M1..M13** de cac section khac con tham chieu duoc.

#### M0 — `payment_custom` (`code='custom'`, `custom_mode='wire_transfer'`), khong viet dong nao

Odoo 19 da co san addon `payment_custom`: nguoi tra chuyen tien ngoai he thong, Odoo dat
`_set_pending()`, ke toan xac nhan tay. Doc `payment_custom/models/payment_transaction.py`: no
`return None` trong `_extract_amount_data` (bo qua kiem tra so tien) va `_set_pending()` trong
`_apply_updates` — **dung y het cai ta can lam voi chain**, va da chay production tren hang chuc
nghin DB.
Cham: khong gi, chi cau hinh + mot dong text trong `pending_msg` chua dia chi vi.
Cost: **0.2 person-week** (chinh la cau hinh + mot `payment.method` icon).
Suits: `OUTLET_COLLECT`, `B2B_INVOICE_PAY` giai doan pilot.
Failure mode: khong co doi soat tu dong; khoi luong > ~50 giao dich/ngay la khong the lam tay.
**Day la duong lui bat buoc phai giu**: neu watcher chet 6 tieng, van thu duoc tien. Va no la
duong ngan nhat de chay pilot truoc khi M1 xong.

Con mot ly do thu hai de doc `payment_custom` truoc khi viet M1: method `_get_communication()`.
No la **hook san co** cua Odoo cho "chuoi ma nguoi tra phai ghi kem" (uu tien
`invoice_ids[0].payment_reference`, roi `sale_order_ids[0].reference`, roi `tx.reference`). Scheme
memo o §09.6 phai **mo rong** method nay chu khong dung mot ten khac.

#### M1 — In-house `payment.provider` voi `code='chain'`

Chain la lop reconciliation; Odoo la nguoi phat hanh payment request va nguoi quyet dinh khi nao
tien duoc coi la thu. Cham: `payment.provider`, `payment.transaction`, `payment.method`,
`account.payment` (qua `account_payment`, **bat buoc** neu DB co `account` — xem §09.0),
`sale.order`/`account.move` qua portal.
Cost: ~5-7 person-week (§09.10). Chi tiet o §09.5.
Failure mode: reorg sau `_set_done` (giai o §09.7); `_validate_amount` ha guc moi giao dich
Zether (§09.9); `partner_id` la `required` nen nguoi tra la khach vang lai phai co partner
placeholder (§09.8b); mot provider = mot journal (A1).

#### M2 — Acquirer crypto ben thu ba

Acquirer nhan crypto, chiu bien dong gia, tra fiat ve tai khoan ngan hang. Odoo chi thay mot
`payment.provider` HTTP binh thuong + webhook. Cham: `payment.provider`, `payment.transaction`,
khong cham chain.
Cost: ~2 person-week. Re nhat va la con duong dung cho `ENDUSER_PAY` giai doan dau.
Phi thuc te: **0.5-1.0%** tren doanh so (co so: bieu phi cong khai cua nhom Coinbase
Commerce/BitPay/Triple-A, uoc tinh 2026). So sanh: chi phi on-chain tu chay tren Gnosis la
~$0.0002/giao dich, tuc **duoi 0.01%** o gia tri don $5. Nguong hoa von: neu doanh so crypto
> ~$300k/nam thi 1% phi acquirer (= $3,000/nam) da vuot chi phi van hanh mot watcher + RPC
(uoc ~$1,500-3,000/nam, §09.10c). Duoi nguong do, M2 re hon that.
Failure mode: **khong con la blockchain project** — mat quyen kiem soat token, khong dung duoc
Zether, khong dung duoc EIP-1776, khong chay duoc tren private chain. Chi hop khi muc tieu la nhan
tien, khong phai xay ha tang.

#### M3 — `account.payment` truc tiep, bo qua module `payment`

Watcher thay transfer → tao thang `account.payment` (`payment_type='inbound'`,
`partner_type='customer'`) va `action_post()`, reconcile voi `account.move.line`.
Cham: `account.payment`, `account.journal` (mot journal rieng cho moi chain × token),
`account.payment.method.line`, `account.move`.
Cost: ~3 person-week.
Suits: `B2B_PAYOUT`, `REFUND`, `FIAT_OFFRAMP` — noi khong co checkout UI, khong co portal,
khong can token/redirect.
Failure mode: mat toan bo state machine cua `payment.transaction` (pending/error/expiry), phai tu
viet lai; khong co refund tree; khong co idempotency san — phai tu them constraint. Va: mot
`account.payment` da `posted` khong xoa duoc, chi `action_draft` + reverse — nen mot observation
bi reorg sau khi post la mot but toan dieu chinh, khong phai mot delete.

#### M4 — Sub-ledger doc lap, doi soat theo lo

`blockchain.payment.entry` la mot sub-ledger rieng (dong tien theo base units, khong theo
`res.currency`), chay doc lap, dinh ky sinh **mot** `account.move` tong hop theo (chain, token,
ngay) thay vi mot move moi transfer.
Cham: khong gi ca trong core; `dms_blockchain_account` sinh `account.move`; doi soat dung
`blockchain.reconciliation.run` cua §15.
Cost: ~4 person-week core + 2 cho bridge ke toan.
Suits: `LOYALTY_ACCRUE`/`LOYALTY_REDEEM` (khoi luong cao, gia tri don vi nho), `RELAYER_FEE`,
**va moi thu Zether** (§09.9).
Failure mode: doi soat lech thi phat hien cham (theo lo, khong theo giao dich); can mot
`blockchain.reconciliation.run` co trang thai `clean`/`drift` va mot nguong drift chan viec
posting move.
**[SUA] Dinh luong storage.** Ban nhap viet "400 B/dong ⇒ 330 MB/nam" — sai hai lan: (a) bo qua
index, (b) tinh nham thang thanh nam. Co so dung, lay tu §11.9 (dong effect ≈ 400 B payload,
**≈ 800 B thuc te** ke ca overhead dong Postgres va 3 index):

| Kich ban | Dong/thang | Postgres/thang | Postgres/nam |
|---|---|---|---|
| Sub-ledger M4, 200k outlet × 4 giao dich/thang | 800,000 | **640 MB** | **7.7 GB** |
| Neu sinh `account.move` 1-1 (move + 2 line + index ≈ 2.5 KB) | 800,000 move | **2.0 GB** | **24 GB** |
| M4 + mot move tong hop/ngay/token (2 token) | 60 move | ~0.2 MB | ~2 MB |

24 GB/nam `account.move` la khong chap nhan duoc — khong phai vi dung luong ma vi **moi bao cao
ke toan deu quet bang do**. Do la ly do M4 ton tai, va lap luan do bay gio co con so.

#### M5 — Ket hop theo tung dong tien

Khong phai mot che do; la **che do mac dinh cua he thong**. Bang o §09.1 chinh la cau hinh. Co che
ky thuat o §09.4.

#### M6 — "Pay by link" mang reference on-chain

Odoo gui link portal; trang portal hien dia chi nhan + `ref` + QR EIP-681 + nut WalletConnect.
Nguoi tra co the tra tu vi bat ky, ke ca khong mo link. Cham: `payment.transaction` (M1) +
`payment.link.wizard` (`wizards/payment_link_wizard.py`, da co san — chi can override
`_prepare_query_params`) + `portal` template.
Cost: +1 person-week tren M1.
Failure mode: nguoi dung copy dia chi ma bo `ref` → observation `unmatched` (§09.8). Ty le nay
thuc te khong nho; do la ly do R1 (dia chi rieng moi request) duoc uu tien hon memo (§09.6).

#### M7 — Pull payment qua `approve` / ERC-2612 `permit`

Nguoi tra ky `permit(owner, spender, value, deadline, v, r, s)` off-chain (khong ton gas), backend
goi `transferFrom` khi den han. Cham: `payment.token` (luu allowance nhu mot token),
`payment.transaction` voi `operation='offline'`, `_send_payment_request()`.
Cost: ~3 person-week tren M1.
Suits: `B2B_INVOICE_PAY`, `SUBSCRIPTION`.
Anh xa dep nhat trong ca section: **`approve`/`permit` = `_set_authorized()`, `transferFrom` =
capture, `_set_done()`**. Day la truong hop duy nhat manual capture co nghia tren chain.
Failure mode: USDT mainnet **khong** co `permit` (va con co quirk `approve` phai ve 0 truoc) → phai
fallback Permit2 hoac `approve` thuong. Allowance co the bi thu hoi bat ky luc nao va khong co
thong bao → truoc moi capture bat buoc doc `allowance()` va `balanceOf()`, khong tin state cu.
Them mot rang buoc Odoo ma ban nhap bo qua: `payment.token._check_partner_is_never_public` cam gan
token cho partner public ⇒ M7 khong dung duoc cho khach vang lai, chi cho doi tac da dinh danh.
Va `payment.token.provider_ref` la `required` — o day no la `keccak(owner ++ spender ++ token)`,
khong phai dia chi vi tran.

#### M8 — Streaming / subscription

Hop dong stream tuyen tinh (Sablier/Superfluid-class, hoac mot `LinearStream.sol` ~200 dong tu
viet). Cham: sub-ledger M4 + `sale.subscription`.
Cost: ~4 person-week ke ca contract.
Failure mode: khong khop mo hinh ky ke toan Odoo (doanh thu chay lien tuc, invoice chay theo
thang) → bat buoc phai co mot buoc "chot ky" doc `streamedAmount(t)` tai `t = ky ket thuc`. Neu
nguoi tra huy stream giua ky, so tien chot < invoice → phat sinh cong no, khong phai loi thanh toan.
Dinh luong: mot stream chi la 2 giao dich on-chain (`create`, `withdraw`) cho ca ky, so voi 1
giao dich/thang cua M7 — **stream chi re hon khi tan suat thu > 1 lan/thang**. Duoi do no chi la
do phuc tap khong tra tien.

#### M9 — Escrow giai ngan theo moc

Tien khoa trong hop dong, giai ngan khi arbiter/oracle xac nhan moc. Cham: `dms.trade.claim`
(qua bridge), `blockchain.escrow.deal` + `.milestone`.
Cost: ~5 person-week (contract + audit chiem phan lon).
Suits: `B2B_PAYOUT`, `ESCROW_MILESTONE`, `LOYALTY_REDEEM` co dieu kien.
Failure mode: arbiter la mot single point of trust — neu la mot khoa cua chinh doanh nghiep thi
escrow khong con y nghia trustless, chi con la mot cai khoa thoi gian. Noi thang dieu do trong
spec thay vi ban no nhu decentralization. Rui ro thu hai, nghiem trong hon: **tien nam trong hop
dong la tien mat neu hop dong co bug**. Escrow la che do duy nhat trong danh sach nay giu so du,
nen no la che do duy nhat **bat buoc** audit ben ngoai truoc khi bat.

#### M10 — Mandate uy quyen truoc (kieu direct debit)

Session key / smart account voi han muc va thoi han (§10.3 note: 1-8 gio; voi mandate B2B phai la
30-90 ngay + `daily_cap`). EIP-7702 hoac smart account cho phep uy quyen mot `spender` voi scope
hep. Cham: `payment.token` (mandate luu nhu token), `blockchain.mandate`.
Cost: ~4 person-week.
Failure mode: khac biet phap ly voi direct debit ngan hang — **khong co quyen doi lai tien
(chargeback)**. Neu ban mandate cho nguoi tieu dung ma khong noi ro dieu do, day la rui ro tuan thu,
khong phai rui ro ky thuat. Han che mandate cho `B2B_*`.

#### M11 — QR payment request mang URI EIP-681

QR chua `ethereum:<token>@<chainId>/transfer?address=<to>&uint256=<amount>`. Cham: portal/POS view.
Cost: ~0.5 person-week (EIP-681 la text thuan, khong CRC — khong tai su dung duoc `_emv` cua
VietQR ngoai phan render QR).
Suits: `ENDUSER_PAY`, `OUTLET_COLLECT`.
**[SUA] Failure mode nang hon ban nhap viet.** Ban nhap de xuat
`ethereum:<router>@100/pay?address=...&uint256=...&bytes32=<ref>`. Trong thuc te, **ho tro EIP-681
cho loi goi ham tuy y gan nhu bang khong**: cac vi di dong pho bien chi nhan dang duoc dang
`transfer` cua ERC-20 (va nhieu vi con bo qua ca `uint256`, chi lay dia chi). Mot QR goi
`pay(...)` voi tham so `bytes32` se khong quet duoc o hau het vi. He qua thiet ke: **QR chi duoc
tro toi dia chi R1 (derived) voi ham `transfer`** — do la dang duy nhat co co hoi hoat dong. Cho
nhung vi khong doc duoc URI, luon hien them dia chi + so tien dang text de nguoi dung tu nhap, va
mot nut **WalletConnect v2** (pairing URI) — day moi la duong dang tin cay cho vi di dong.
`chainId`: Gnosis = 100, Celo = 42220.
Va: quet QR khong phai la da thu tien.

#### M12 — Anchor-only (chain la bang chung, tien di duong fiat)

Khong co dong tien nao tren chain. Chi hash cua chung tu duoc neo (Hedera HCS hoac mot
`AnchorRegistry.sol`). Cham: `blockchain.anchor`.
Cost: ~1 person-week.
Suits: `LOYALTY_ACCRUE` giai doan dau, audit trail cho `dms.trade.settlement`.
Dang duoc goi ten vi day thuong la cau tra loi dung cho loyalty: diem thuong khong can la token
cho toi khi no can chuyen nhuong duoc giua cac chu the doc lap. Neu diem chi tieu trong he sinh
thai cua chinh issuer, mot token ERC-20 khong them gia tri gi ngoai chi phi.

#### M13 — Zether confidential settlement

Nhu M4 nhung so tien khong doc duoc tu chain. Xem §09.9. Day khong phai bien the cua M1.

#### M14 — Nhan token bat ky, tu quy doi ve token ngan quy (auto-convert at receipt)

Nguoi tra gui USDT, treasury muon USDC. Mot `PaymentRouter.payAndSwap(tokenIn, amountIn, minOut,
ref)` goi DEX (Curve/Balancer tren Gnosis) trong cung transaction.
Cham: `blockchain.token` (danh sach token chap nhan), router contract.
Cost: ~3 person-week + audit router.
Suits: `ENDUSER_PAY` tren public chain.
Failure mode: (a) **slippage lam so tien nhan duoc khac so tien tra** ⇒ `_validate_amount` se
`_set_error` neu ta so sanh `amountOut`; phai so sanh `amountIn` va ghi slippage nhu mot khoan chi
phi tai chinh. (b) MEV sandwich: `minOut` phai duoc dat, va tren mot public mempool no van bi
sandwich trong bien `minOut`. (c) Thanh khoan mong tren chain nho la rui ro that: mot swap $50k
tren mot pool $500k an ~1-2% slippage. Ket luan: M14 chi bat khi gia tri giao dich nho
(< ~$1,000/tx) hoac tren private chain co AMM noi bo.

#### M15 — Bu tru song phuong, chi thanh toan phan rong (netting)

Brand va distributor phat sinh cong no hai chieu (invoice ban hang vs. trade claim/rebate). Thay vi
N giao dich, tinh vi the rong theo ky va chi chuyen phan chenh lech.
Cham: `dms.trade.settlement`, `account.move` (bo tru cong no), `blockchain.settlement.batch` (§15).
Cost: ~3 person-week (logic netting) + 0 contract (chi la mot transfer).
Suits: `B2B_INVOICE_PAY` + `B2B_PAYOUT` **cung mot doi tac**.
Dinh luong: voi 500 distributor × 20 chung tu/thang moi chieu, netting theo thang giam tu
**20,000 giao dich** xuong **500 giao dich**/thang — giam 97.5% ca gas lan so dong sub-ledger. Day
la don bay lon nhat trong ca danh sach, va no khong can them mot dong Solidity nao.
Failure mode: netting la mot **thoa thuan phap ly**, khong phai mot tinh nang phan mem. Phai co
dieu khoan bu tru trong hop dong; neu khong, mot ben pha san thi phan bu tru co the bi toa lat
lai. Va no lam mo dau vet tung hoa don ⇒ bat buoc luu bang ke netting nhu chung tu.

#### M16 — Cau fiat on/off-ramp (VND ↔ stablecoin)

Outlet thu tien mat VND; treasury muon token. Hoac nguoc lai. Mot doi tac duoc cap phep thuc hien
quy doi; Odoo ghi nhan hai chan: chan fiat (`account.payment` / `dms.cash.handover`) va chan chain
(`blockchain.settlement`).
Cham: `dms.payment.collection`, `dms.bank.reconciliation`, `account.payment`, `blockchain.token`.
Cost: ~4 person-week + thoi gian phap ly (khong uoc luong duoc bang person-week).
Suits: `FIAT_ONRAMP`, `FIAT_OFFRAMP`, va **thuc te la dieu kien can** cho `OUTLET_COLLECT` tai
Viet Nam, noi tien mat van chiem phan lon.
Failure mode: day la cho toan bo kien truc cham vao quy dinh phap ly VN (§13). Khong co doi tac
hop phap = khong co off-ramp = token bi ket trong he sinh thai. **Day la rui ro nghiem trong nhat
cua ca du an, va no khong phai rui ro ky thuat.** Ghi vao roadmap nhu mot cong (gate), khong phai
mot task.

#### M17 — Giai ngan theo lo bang multicall (Disperse-style)

Mot transaction chuyen cho N nguoi nhan.
Cham: `blockchain.settlement.batch` (§15 da co `chunk_size = 150`), `dms.trade.settlement`.
Cost: ~1 person-week (contract ~60 dong) + audit nhe.
Suits: `B2B_PAYOUT`, `LOYALTY_ACCRUE`.
Dinh luong (co so: base tx 21,000 + ~30,000/`transfer` warm, EIP-1108/EIP-2929):

| N nguoi nhan | N tx rieng | 1 tx batch | Tiet kiem |
|---|---|---|---|
| 10 | 10 × 51,000 = 510,000 | 21,000 + 10 × 30,000 = 321,000 | 37% |
| 150 | 7,650,000 | 4,521,000 | 41% |

Tiet kiem gas chi ~40%, khong ngoan muc. Nhung tiet kiem **nonce management, so lan retry, va so
dong log** thi lon hon nhieu — do moi la ly do dung no. Failure mode: mot nguoi nhan la contract
revert lam hong ca lo ⇒ phai `try/catch` tung transfer trong contract va phat event that/bai theo
tung dong, hoac dung `atomicity='chunked'` cua §15.

#### M18 — Voucher ky off-chain (bearer claim)

Issuer ky mot phieu `(recipient, amount, nonce, expiry)` bang EIP-712; nguoi nhan tu `claim()` khi
muon. Khong ton gas cho issuer cho toi khi co nguoi claim, va phieu khong bao gio claim thi khong
ton gi.
Cham: `blockchain.voucher` (core, khong can `payment`), `AnchorRegistry`/`VoucherClaim.sol`.
Cost: ~2 person-week.
Suits: `LOYALTY_ACCRUE` (phat 200k phieu, thuc te ~5-15% duoc claim ⇒ tiet kiem 85-95% gas so voi
mint truoc), `LOYALTY_REDEEM`.
Failure mode: phieu la **bearer instrument** — ai co chu ky thi claim duoc neu contract khong rang
buoc `recipient`. Phai rang buoc. Va ke toan: mot phieu da phat nhung chua claim la mot **khoan
phai tra tiem tang**, phai trich truoc, khong duoc de ngoai so. Nguoc lai voi truc giac, che do "re
nhat ve gas" lai la che do **kho nhat ve ke toan**.

#### M19 — Payment channel / state channel

Duoc goi ten de **bac bo**. Hai ben mo kenh, giao dich off-chain khong gioi han, dong kenh mot lan.
Ly do bac bo: chi phi giao dich tren Gnosis da la $0.0002; kenh giai quyet mot van de (phi giao
dich cao) ma ta khong co, doi lay mot van de ta khong muon (watchtower, thoi han thach thuc, von
bi khoa). M15 (netting) dat duoc 97% loi ich voi 5% do phuc tap. **Khong xay.**

---

### 09.3. Bang so sanh nen

| | Chi phi xay | Do tre den `done` | Chargeback | Chay tren private chain | Ho tro Zether | Can contract moi |
|---|---|---|---|---|---|---|
| M0 | 0.2 pw | thu cong | khong | co | n/a | khong |
| M1 | 5-7 pw | finality gate | khong | co | khong (xem M13) | khong |
| M2 | 2 pw | acquirer quyet dinh | co (acquirer chiu) | khong | khong | khong |
| M3 | 3 pw | finality gate | khong | co | mot phan | khong |
| M4 | 4+2 pw | theo lo | khong | co | co | khong |
| M6 | +1 pw | nhu M1 | khong | co | khong | khong |
| M7 | +3 pw | finality gate | khong | co | khong | khong (Permit2 neu can) |
| M8 | 4 pw | chot ky | khong | co | khong | **co** |
| M9 | 5 pw | khi giai ngan | mot phan (arbiter) | co | phuc tap | **co, phai audit** |
| M10 | 4 pw | nhu M7 | khong | co | khong | **co** (smart account) |
| M11 | 0.5 pw | nhu M1 | khong | co | khong | khong |
| M12 | 1 pw | n/a | n/a | co | n/a | co (nhe) |
| M13 | 6 pw | epoch + finality | khong | **co, uu tien** | co | **co, phai audit** |
| M14 | 3 pw | nhu M1 | khong | co (neu co AMM) | khong | **co** |
| M15 | 3 pw | theo ky | khong | co | co | khong |
| M16 | 4 pw + phap ly | ngay (T+1) | theo doi tac | khong lien quan | khong lien quan | khong |
| M17 | 1 pw | finality gate | khong | co | khong | **co** (nhe) |
| M18 | 2 pw | khi claim | khong | co | khong | **co** |
| M19 | — | — | — | — | — | **khong xay** |

---

### 09.4. Co che cau hinh: `blockchain.money.flow` + handler registry

Note goc khong noi gi ve viec chon che do. Day la de xuat cu the.

**Mot record cho mot (company, flow_code, chain).** Fallback: `company_id = False` la mac dinh
toan he thong. Do phan giai: `(company, flow, chain)` → `(company, flow, False)` →
`(False, flow, False)` → `UserError`. Khong bao gio fallback im lang ve mot handler tuy y.

```python
class BlockchainMoneyFlow(models.Model):
    _name = 'blockchain.money.flow'
    _description = 'Money flow to payment-integration handler binding'
    _inherit = ['mail.thread']          # doi handler la mot su kien phai co vet

    company_id   = fields.Many2one('res.company', index=True)          # False = default
    flow_code    = fields.Selection(
        selection=[
            ('LOYALTY_ACCRUE', "Loyalty accrual"), ('LOYALTY_REDEEM', "Loyalty redemption"),
            ('B2B_PAYOUT', "B2B payout"), ('B2B_INVOICE_PAY', "B2B invoice payment"),
            ('OUTLET_COLLECT', "Outlet collection"), ('ENDUSER_PAY', "End-user payment"),
            ('RELAYER_FEE', "Relayer fee"), ('REFUND', "Refund"),
            ('ESCROW_MILESTONE', "Escrow milestone"), ('SUBSCRIPTION', "Subscription"),
            ('FIAT_ONRAMP', "Fiat on-ramp"), ('FIAT_OFFRAMP', "Fiat off-ramp"),
        ], required=True, index=True, tracking=True)
    chain_id     = fields.Many2one('blockchain.chain', index='btree_not_null')
    handler_code = fields.Selection(
        selection=[('none', "Not configured")], required=True, default='none', tracking=True,
        help="Extended by each bridge addon via selection_add.")
    handler_config_ref = fields.Many2oneReference(model_field='handler_config_model')
    handler_config_model = fields.Char()
    active       = fields.Boolean(default=True)

    _unique_binding = models.Constraint(
        'UNIQUE(company_id, flow_code, chain_id)',
        'Mot dong tien chi duoc gan mot handler tren mot chain trong mot company.')
```

**[SUA] `flow_code` phai la `Selection` dang list, khong phai `selection='_method'`.** Ban nhap
dung method-based selection; nhung `selection_add` (co che de bridge addon them flow rieng cua
`dms`) **chi hoat dong khi base la mot list**. Doi lai, va them `ondelete` o phia bridge:

```python
# trong dms_blockchain_dms
flow_code = fields.Selection(
    selection_add=[('DMS_OUTLET_CREDIT', "Outlet credit repayment")],
    ondelete={'DMS_OUTLET_CREDIT': 'set default'})
```

**[SUA] `provider_id` khong the nam trong core** (comodel `payment.provider` chua ton tai) — ban
nhap de xuat `fields.Reference`. Dung duoc, nhung §15 da chot idiom khac cho dung van de nay:
`fields.Many2oneReference(model_field='...')`. Dung theo §15 de ca bo tai lieu mot kieu. Khac biet
thuc te: `Reference` luu `'model,id'` trong mot `Char` va cho phep widget chon model; `Many2oneReference`
luu `Integer` + mot `Char` model rieng, index tot hon va khong can `selection`. O day ta biet model
tu `handler_code` nen khong can widget chon — `Many2oneReference` la lua chon dung.

#### 09.4a. Dispatch khong co `if` — va lo hong RPC cua ban nhap

```python
def _get_handler(self):
    self.ensure_one()
    model = 'blockchain.payment.handler.%s' % self.handler_code
    if model not in self.env:                      # module bi go sau khi da cau hinh
        raise UserError(_("Handler %s khong con duoc cai dat.", self.handler_code))
    return self.env[model].with_context(money_flow_id=self.id)
```

> **[SUA] `with_context(flow=self)` cua ban nhap la mot bug.** Context bi serialize (di qua
> `call_kw`, luu vao `ir.cron`, cho vao `queue_job`); mot recordset trong context khong serialize
> duoc va se hong ngay khi handler goi mot method chay o cursor khac. Truyen **id**, doc lai trong
> handler.

**Lo hong bao mat trong interface cua ban nhap.** Ban nhap dat ten method la `open_request`,
`on_observation`, `on_final`, `on_reorg`, `on_expire`. Theo CLAUDE.md §6, **moi method public tren
mot model Odoo la mot RPC endpoint**: bat ky user nao co ACL read tren model handler deu goi duoc
`POST /json/2/blockchain.payment.handler.chain_provider/on_final` va **ep mot `_set_done`**. Do la
duong ngan nhat toi viec ai do tu xac nhan da tra tien cho hoa don cua chinh ho. Interface phai
private:

```python
class BlockchainPaymentHandler(models.AbstractModel):
    _name = 'blockchain.payment.handler'
    _description = 'Payment integration handler interface (private, not RPC-reachable)'

    def _open_request(self, flow, amount_base, token, origin_model, origin_res_id,
                      origin_ref, partner_id=None, expiry_minutes=None):
        """Tao yeu cau thanh toan. Tra ve blockchain.payment.request.
           Idempotent theo (company_id, origin_model, origin_ref)."""
        raise NotImplementedError

    def _on_observation(self, request, observation):
        """Watcher thay mot transfer khop. observation.obs_state con la 'mined'."""
        raise NotImplementedError

    def _on_final(self, request, observation):
        """Da qua Finality Gate. Day la NOI DUY NHAT duoc phep bao 'da thu tien'."""
        raise NotImplementedError

    def _on_reorg(self, request, observation):
        """observation da final bi day nguoc. Bat buoc hien thuc, khong duoc pass."""
        raise NotImplementedError

    def _on_expire(self, request):
        raise NotImplementedError
```

Va **mot** entry point public duy nhat, mong, tren `blockchain.payment.request` — theo mau CLAUDE.md
§6 (public facade + private logic), phuc vu ca `call_kw` lan `/json/2`:

```python
@api.model
def payment_request_open(self, flow_code, amount_base, token_caip19,
                         origin_model, origin_ref, partner_id=None,
                         chain_caip2=None, expiry_minutes=None):
    """POST /web/dataset/call_kw/blockchain.payment.request/payment_request_open
       POST /json/2/blockchain.payment.request/payment_request_open

    KHONG nhan company_id, KHONG nhan allowed_company_ids tu client:
    company suy ra tu self.env.company (da duoc server giao voi assignment cua user).
    """
    self.check_access('create')
    flow = self.env['blockchain.money.flow']._resolve(self.env.company, flow_code, chain_caip2)
    return self._request_open_payload(
        flow._get_handler()._open_request(flow, amount_base, ..., origin_ref=origin_ref, ...))
```

`_request_open_payload` tra ve dict thuan (`request_uuid`, `receiving_address`, `ref_display`,
`amount_base`, `caip2`, `expiry_datetime`, `eip681_uri`, `wc_uri`) — khong tra recordset qua RPC.

**Nam dieu nay giu code open/closed:**

1. `handler_code` la `Selection` mo rong bang `selection_add` — dung y het `payment.provider.code`
   (`selection=[('none', ...)]`, xac nhan tai `payment/models/payment_provider.py:34`). Mot che do
   khong cai thi khong xuat hien trong dropdown, va neu khong con trong registry thi `_get_handler`
   raise ro rang thay vi chay nham nhanh khac.
2. Dispatch bang ten model, khong bang `if`. Them che do = them mot addon, khong sua file nao co san.
3. Core goi handler qua interface, khong bao gio import bridge.
4. `_on_reorg` bat buoc.
5. Entry point public duy nhat ⇒ be mat RPC bang **mot** method, kiem duoc bang mot dong grep.

**[SUA] "Fail luc cai dat" cua ban nhap khong tu xay ra.** `raise NotImplementedError` trong
AbstractModel fail luc **goi**, tuc la luc reorg — dung cai thoi diem khong duoc phep fail. Muon
fail luc cai dat thi phai co mot kiem tra registry that:

```python
def _register_hook(self):
    super()._register_hook()
    base = self.env.registry['blockchain.payment.handler']
    for name, Model in self.env.registry.items():
        if name.startswith('blockchain.payment.handler.') and name != '...handler.none':
            for m in ('_open_request', '_on_observation', '_on_final', '_on_reorg', '_on_expire'):
                if getattr(Model, m, None) is getattr(base, m):
                    raise ValueError("Handler %s chua hien thuc %s()" % (name, m))
```

Dat trong core, chay moi lan load registry. Mot handler thieu `_on_reorg` lam **server khong khoi
dong duoc**, do la dung muc do nghiem trong.

#### 09.4b. Bon tang cau hinh, va ai duoc sua tang nao

| Thu | Song o dau | Nhom duoc sua | Vi du |
|---|---|---|---|
| Handler cho tung dong tien | `blockchain.money.flow` (record, co ACL, co `mail.thread`) | `group_blockchain_treasury_manager` | `ENDUSER_PAY` → `chain_provider` |
| Tham so ky thuat toan he thong | `ir.config_parameter` | `base.group_system` | `blockchain.payment.ref_mode` = `hash`\|`plain` |
| Tham so cua mot provider | `payment.provider` (§09.5) | `payment.group_payment_manager` | `finality_mode`, `overpay_policy` |
| Bi mat (RPC key, HSM slot, acquirer secret) | **ngoai DB** — `ir.config_parameter` chi giu `secret_ref` | khong ai qua UI | CLAUDE.md §5 muc 5 |

Nhom moi khai bao trong `security/blockchain_security.xml`; nho Odoo 19 doi
`res.users.groups_id` → **`group_ids`** khi viet data cho user mau. Va them mot `ir.rule` tren
`blockchain.money.flow` theo `company_id` (`['|', ('company_id','=',False),
('company_id','in',company_ids)]`) — thieu no, mot company doc duoc cau hinh cua company khac.

---

### 09.5. `payment.provider` `code='chain'` — dac ta cu the

```python
class PaymentProvider(models.Model):
    _inherit = 'payment.provider'

    code = fields.Selection(selection_add=[('chain', "Blockchain")],
                            ondelete={'chain': 'set default'})

    chain_id             = fields.Many2one('blockchain.chain', required_if_provider='chain')
    settlement_token_id  = fields.Many2one('blockchain.token', required_if_provider='chain')
    accepted_token_ids   = fields.Many2many('blockchain.token', 'ppr_token_accept_rel')
    receiving_mode       = fields.Selection([
        ('derived', "Dia chi rieng moi request (HD/CREATE2)"),
        ('router',  "Dia chi chung + PaymentRouter.pay(ref)"),
        ('memo',    "Dia chi chung + memo native cua chain")], default='derived')
    router_address       = fields.Char()
    finality_mode        = fields.Selection([('soft', "Soft"), ('hard', "Hard")], default='hard')
    confirm_depth_override = fields.Integer(default=0)      # 0 = dung mac dinh cua chain
    request_expiry_minutes = fields.Integer(default=30)
    quote_validity_seconds = fields.Integer(default=900)    # §09.7b
    soft_final_max_amount  = fields.Monetary(currency_field='main_currency_id')
    tolerance_bps        = fields.Integer(default=10)
    overpay_policy       = fields.Selection([
        ('accept', "Nhan du, ghi thua vao credit"),
        ('accept_refund', "Nhan du, hoan phan thua"),
        ('hold', "Giu, cho nguoi xu ly")], default='accept')
    underpay_policy      = fields.Selection([
        ('partial', "Ghi nhan mot phan, giu request mo"),
        ('hold', "Giu, cho nguoi xu ly")], default='partial')
    refund_address_policy = fields.Selection([
        ('none', "Khong hoan on-chain"),
        ('observed_sender', "Chi hoan ve dia chi da gui, neu da xac minh")], default='none')
```

Ten field da tranh trung ten kieu Odoo: `request_expiry_minutes` (khong `date`),
`payload_text`, `ref_hash_hex` (khong `binary`/`json`).

`required_if_provider='chain'` la co che san co cua Odoo (`payment_provider._valid_field_parameter`
cho phep tham so nay, va `_check_required_if_provider()` chay trong `create`/`write`): field bo
trong ⇒ **khong enable duoc provider**. Dung no cho `chain_id`, `settlement_token_id`, va — quan
trong nhat — cho `journal_id` khi `account_payment` co mat.

#### 09.5a. `_get_supported_currencies` — cho kho nhat, va mot bug ngam

Mot ERC-20 stablecoin khong phai `res.currency`. Hai duong:

- (a) Tao `res.currency` cho tung token (USDC, Z-VND...). Sai: `res.currency` la don vi ke toan;
  hai token cung neo USD tren hai chain se thanh hai currency va moi bao cao consolidated se hong.
- (b) **Chon phuong an nay:** provider ho tro dung nhung `res.currency` co it nhat mot
  `blockchain.token` `active` map toi, qua model `blockchain.token` (`currency_id`, `decimals`,
  `caip19`, `contract_address`). So tien tren `payment.transaction` la **fiat**; so base units la
  `amount_base`.

```python
def _get_supported_currencies(self):
    currencies = super()._get_supported_currencies()
    if self.code == 'chain':
        currencies = currencies.filtered(
            lambda c: c.id in self.accepted_token_ids.mapped('currency_id').ids)
    return currencies

@api.depends('code', 'accepted_token_ids')          # <= dong nay la phan sua
def _compute_available_currency_ids(self):
    super()._compute_available_currency_ids()
```

> **[MOI] Bug ma ban nhap khong thay.** `available_currency_ids` la field **store=True** voi
> `@api.depends('code')` (`payment/models/payment_provider.py:195`). Chi `code` doi moi recompute.
> Admin them mot token vao `accepted_token_ids` ⇒ `_get_supported_currencies` doi, nhung
> `available_currency_ids` **khong recompute**, va `_get_compatible_providers` loc theo field
> stored do ⇒ provider bien mat khoi checkout ma khong co loi nao. Cach sua: override chinh method
> compute voi `@api.depends` moi (Odoo lay depends tu dinh nghia moi nhat cua method).

```python
def _compute_feature_support_fields(self):
    super()._compute_feature_support_fields()
    for p in self.filtered(lambda p: p.code == 'chain'):
        p.support_tokenization     = False   # True chi khi cai dms_blockchain_mandate
        p.support_express_checkout = False
        p.support_manual_capture   = False   # xem ghi chu SUA ben duoi
        p.support_refund = 'partial' if p.refund_address_policy != 'none' else 'none'

def _get_default_payment_method_codes(self):
    if self.code != 'chain':
        return super()._get_default_payment_method_codes()
    return {'chain_transfer'}
```

> **[SUA] `support_manual_capture = 'none'` cua ban nhap la gia tri khong hop le.** Selection cua
> **`payment.provider`** chi co `[('full_only', ...), ('partial', ...)]` — khong co `'none'`
> (`payment/models/payment_provider.py:163`). Base compute dat `None`. Ghi `'none'` vao se qua
> duoc write (Selection khong validate o tang ORM cho gia tri compute) nhung moi noi doc no se
> lech, va `_check_manual_capture_supported_by_payment_methods` so sanh voi `'none'` **tren
> `payment.method`** — noi `'none'` **la** hop le. Hai model, hai tap gia tri, cung ten field. Dung
> `False` cho provider, `'none'` cho method.

`data/payment_method_data.xml`: `<record model="payment.method">` voi `code = chain_transfer`,
`support_tokenization = False`, `support_manual_capture = none`, `support_refund = partial`,
`active = False` (Odoo tu bat khi provider duoc enable, qua `_activate_default_pms`).

`__init__.py` phai co `post_init_hook` theo dung mau cua `payment_demo`:

```python
from odoo.addons.payment import setup_provider, reset_payment_provider

def post_init_hook(env):
    setup_provider(env, 'chain')       # tao provider cho moi company + account.payment.method

def uninstall_hook(env):
    reset_payment_provider(env, 'chain')
```

Bo hook nay ⇒ khong co ban ghi `account.payment.method` voi `code='chain'` ⇒
`_ensure_payment_method_line()` **return im lang** ⇒ `journal_id` khong gan duoc ⇒
`_create_payment()` tao payment voi `payment_method_line_id = False` ⇒ loi o post-process, sau khi
tien da ve. Day la chuoi that, doc duoc tu `account_payment/models/payment_provider.py:23-32`.

#### 09.5b. Nguon notification khong phai webhook

Khong co controller. Watcher (§11) ghi `blockchain.payment.observation`, Finality Gate nang trang
thai, roi mot cron mot dong goi (CLAUDE.md bay #4: body cron nam trong method cua model):

```xml
<field name="state">code</field>
<field name="code">model._cron_process_final_observations()</field>
```

Biên giới tin cay o day khong phai chu ky webhook ma la **quorum RPC + finality depth**: mot
observation chi len `final` khi ≥ `blockchain.chain.finality_quorum` (mac dinh 2) RPC endpoint doc
lap tra ve cung receipt tai cung block hash (§08/§11). Mot RPC noi doi khong du de tao ra mot
`_set_done`.

#### 09.5c. Mot provider cho moi (company, chain, settlement token)

`account_payment._create_payment()` doc `self.provider_id.journal_id` — **mot** journal cho **mot**
provider. Neu mot provider nhan ca USDC lan Z-VND tren ca Gnosis lan Celo, toan bo tien vao mot
journal va khong the doi soat `balanceOf(treasury)` theo tung token (kiem tra (C) cua §15).

Quyet dinh: **mot `payment.provider` cho moi (company, chain, settlement token)**, moi cai tro toi
mot `account.journal` type `bank` rieng, currency = currency cua token, va mot outstanding account
rieng. `accepted_token_ids` van co the nhieu (nhan USDT, quy doi ve USDC bang M14) nhung
`settlement_token_id` la mot.

Chi phi cua quyet dinh nay: N provider hien trong danh sach checkout. Giam thieu bang
`is_published = False` cho cac provider chi dung backend, va bang `available_currency_ids` (da loc
theo token) — `_get_compatible_providers` se tu loai nhung provider khong khop currency cua don.

Phuong an thay the neu N qua lon (> ~6): giu mot provider va override:

```python
def _create_payment(self, **extra):
    if self.provider_code == 'chain':
        extra.setdefault('journal_id', self.blockchain_request_id.token_id.journal_id.id)
    return super()._create_payment(**extra)
```
Re hon ve UX, dat hon ve rui ro: `payment_method_line_id` van lay tu provider, nen phai override
ca no, va do la luc bat dau di lech khoi framework.

#### 09.5d. Do tre: vi sao mot cron 10 phut khong phuc vu duoc `ENDUSER_PAY`

Ba con so, tat ca deu doc duoc trong source:

| Nguon do tre | Gia tri | O dau |
|---|---|---|
| Do phan giai toi thieu cua `ir.cron` | **60 giay** | `interval_type` nho nhat la `minutes` |
| Cron post-process cua Odoo | **10 phut** (`interval_number=10`), va `active=False` cho toi khi co provider enabled | `payment/data/payment_cron.xml` |
| `_cron_post_process` chi lay tx co `last_state_change >= now - 4 ngay` | bo qua tx cu hon | `payment_transaction.py:1085` |

`ENDUSER_PAY` yeu cau **giay**. Ba viec phai lam:

1. **Watcher goi `_trigger()`**, khong doi lich cron. `ir.cron._trigger()` ton tai trong Odoo 19
   (`odoo/addons/base/models/ir_cron.py`) va danh thuc cron worker ngay lan wake ke tiep, do tre
   thuc te duoi mot giay khi `--max-cron-threads > 0`:
   ```python
   self.env.ref('dms_blockchain_payment.cron_process_final_observations')._trigger()
   ```
2. **Goi `_post_process()` truc tiep** ngay sau `_set_done()`. Nguoi tra khong mo trinh duyet ⇒
   khong ai goi `/payment/status/poll` ⇒ khong ai post-process. Doi cron 10 phut nghia la hoa don
   khong duoc xac nhan trong 10 phut sau khi tien da ve.
3. **Bus notification** cho man hinh thu ngan: `self.env['bus.bus']._sendone(channel, 'chain.paid',
   {...})`. POS khong duoc poll REST moi giay cho 50 quay.

Va vong lap cron phai chiu duoc mot dong hong — ban nhap khong chiu duoc:

```python
def _cron_process_final_observations(self, limit=200):
    Obs = self.env['blockchain.payment.observation']
    for obs in Obs.search([('obs_state', '=', 'final'), ('is_processed', '=', False)],
                          order='id', limit=limit):
        try:
            tx = self.env['payment.transaction']._process('chain', obs._payment_data())
            obs.is_processed = True
            if tx and tx.state == 'done' and not tx.is_post_processed:
                tx._post_process()
            self.env.cr.commit()
        except Exception:                      # noqa: BLE001 - mot dong hong khong duoc chan hang doi
            self.env.cr.rollback()
            obs.sudo().write({'error_text': traceback.format_exc()[-2000:],
                              'retry_count': obs.retry_count + 1})
            self.env.cr.commit()
        if obs.retry_count >= 5:
            obs.sudo().activity_schedule(...)   # dua cho nguoi, khong retry vo han
```

Throughput: `limit=200` moi lan chay. Voi `_trigger()` sau moi block (Gnosis 5s) ⇒ tran
**~144,000 observation/gio**, du xa. Voi lich cron 1 phut khong `_trigger` ⇒ 12,000/gio. Ghi con
so nay vao runbook de nguoi van hanh biet nguong.

#### 09.5e. Overrides tren `payment.transaction`

```python
def _extract_reference(self, provider_code, payment_data):
    if provider_code != 'chain':
        return super()._extract_reference(provider_code, payment_data)
    return payment_data.get('odoo_reference')      # giai ma tu ref_hash / dia chi, xem §09.6

def _extract_amount_data(self, payment_data):
    if self.provider_code != 'chain':
        return super()._extract_amount_data(payment_data)
    if payment_data.get('is_confidential'):
        return None            # Zether: opt out kiem tra so tien — xem §09.9
    return {'amount': payment_data['fiat_amount'],
            'currency_code': payment_data['currency_code'],
            'precision_digits': payment_data['currency_decimals']}

def _apply_updates(self, payment_data):
    if self.provider_code != 'chain':
        return super()._apply_updates(payment_data)
    self.provider_reference = '%s:%s:%s' % (payment_data['caip2'],
                                            payment_data['tx_hash'],
                                            payment_data['log_index'])
    state = payment_data['chain_state']
    if state in ('broadcast', 'mined'):
        self._set_pending(state_message=_("On-chain, cho du do sau chot khoi."))
    elif state == 'final':
        self._set_done()
    elif state == 'reverted':
        self._set_error(_("Giao dich revert tren chain."))
```

Ba ghi chu ky thuat, tat ca lay tu source:

- `_extract_amount_data` cua base tra **`{}`**, khong phai `None`. Neu quen override,
  `_validate_amount` chay `amount_data['amount']` ⇒ **`KeyError`**, khong phai mot loi sach. Vi vay
  nhanh `if self.provider_code != 'chain'` phai la dong dau tien, luon luon.
- `_process()` goi `_validate_amount()` **truoc** `_apply_updates()` va thoat som neu state chuyen
  sang `error`. Nghia la: neu so tien lech, `_apply_updates` **khong chay**, `provider_reference`
  **khong duoc ghi**, va ta mat con tro toi tx_hash. Phai ghi `provider_reference` o cho khac —
  cu the la tren `blockchain.payment.observation`, luon luon, truoc khi goi `_process`.
- `_set_done` khong tu goi `_post_process`. Xem §09.5d.

---

### 09.6. Reference/memo: noi on-chain transfer voi record Odoo

Truong hop kho: nguoi tra mo vi cua ho, chuyen USDC, khong bao gio cham app. Bon ky thuat, xep
theo do tin cay:

**R1 — Dia chi nhan rieng cho tung request (khuyen dung).** Khong can memo. EVM: `CREATE2`
counterfactual — dia chi tinh truoc bang `keccak256(0xff ++ factory ++ salt ++ initCodeHash)` voi
`salt = ref32`; contract chi duoc deploy khi quet tien ve. Chi phi: deploy EIP-1167 clone + sweep
≈ **100-120k gas**; tren Gnosis o 2 gwei = ~0.00022 xDAI ≈ $0.00022/request. Voi 1 trieu request
loyalty/nam: ~$220. Chap nhan duoc. Uu diem quyet dinh: **hoat dong voi moi vi, moi token, khong
can nguoi dung lam gi dung.**

Ba chi tiet trien khai ma ban nhap bo qua, va ca ba deu lam hong R1 neu sai:

1. **Factory phai o cung mot dia chi tren moi chain EVM.** Dia chi CREATE2 phu thuoc `factory`.
   Neu factory tren Gnosis va tren Celo khac dia chi, cung mot `salt` cho ra hai dia chi khac nhau
   ⇒ khi khach gui nham chain, tien roi vao mot dia chi **ta khong tinh duoc va khong so huu**.
   Cach lam: deploy factory qua deterministic deployment proxy
   `0x4e59b44847b379578588920cA78FbF26c0B4956C` (co san tren gan nhu moi chain EVM), voi cung
   `initCode` va cung `salt`. Kiem tra bang mot test CI so khop dia chi factory tren tat ca chain
   da cau hinh.
2. **`initCodeHash` phai giong nhau**, tuc implementation cua clone phai cung dia chi tren moi
   chain. Cung ly do, cung cach.
3. **SELFDESTRUCT khong con hoan gas.** EIP-3529 (London) da xoa refund cua SELFDESTRUCT; EIP-6780
   (Cancun) chi giu hanh vi xoa khi contract duoc tao trong **cung transaction** — dung voi
   deploy+sweep cua ta, nen storage van duoc don, nhung **khong co dong tien nao duoc hoan lai**.
   Dung tinh refund vao mo hinh chi phi.

**R2 — Dia chi chung + reference.** Tuy chain:

| Chain | Co cho de memo? | Cach dung |
|---|---|---|
| EVM (Gnosis, Celo, ...) | **Khong** tren `ERC20.transfer` | Phai goi `PaymentRouter.pay(token, amount, bytes32 ref)` phat `PaymentReceived(payer, token, amount, ref)` |
| Stellar / Soroban | Co | `MEMO_TEXT` 28 bytes hoac `MEMO_HASH` 32 bytes |
| Hedera | Co | transaction memo, 100 bytes |
| Cosmos / CosmWasm | Co | tx-level `memo`, mac dinh `max_memo_characters = 256` |
| TON | Co | text comment trong body cua message |
| SUI | **Khong** | PTB goi module phat event; hoac R1 |

Do dai `bytes32` la vua du cho EVM. Nhung khong dat plaintext reference len public chain: mot
`SO/2026/0413` cong voi dia chi doi tac lo ra khoi luong don hang cho doi thu. Vay:

```python
# ir.config_parameter blockchain.payment.ref_mode = 'hash' | 'plain'
def ref32(db_uuid, tx_reference):
    return keccak256(b'odoo:' + db_uuid.encode() + b':' + tx_reference.encode())   # bytes32
```

`ref32` la mot chieu → phai luu `ref_hash_hex` (Char(66), index unique) tren
`blockchain.payment.request` de tra nguoc. Tren `chain_profile = private` (quyet dinh #5), dat
`ref_mode = 'plain'`: khong co doi thu doc chain, va debug de hon nhieu.

**Thu tu tinh toan quan trong.** `ref32` bam tren `tx.reference`, ma `tx.reference` chi co gia tri
cuoi cung **sau khi** `_compute_reference()` da xu ly va cham (`payment_transaction.py:370` them
hau to `-1`, `-2`... khi trung). Vi vay: tao `payment.transaction` truoc → doc `tx.reference` →
tinh `ref32` → tinh dia chi CREATE2 → luu vao `blockchain.payment.request`. Tinh `ref32` truoc khi
tao tx la mot loi im lang: dia chi in tren hoa don se khong khop request.

**[SUA] Do dai reference doc duoc cho nguoi — tinh lai xac suat va cham.** Ban nhap viet: 40 bit,
khong gian 1.1e12, voi 10^7 request thi va cham theo birthday ≈ 4.5e-2. **Sai ba bac.** Cong thuc
xap xi `p ≈ n²/(2N)`:

| So bit | N | n = 10^6 | n = 10^7 |
|---|---|---|---|
| 40 | 1.10e12 | **0.45** | **≈ 1 (chac chan)** |
| 48 | 2.81e14 | 1.8e-3 | 0.18 |
| 64 | 1.84e19 | 2.7e-8 | **2.7e-6** |
| 80 | 1.21e24 | 4.1e-13 | 4.1e-11 |

Ket luan cua ban nhap (dung 64 bit) **dung**, nhung con so dan toi no thi sai va phai sua, vi ai do
se dung con so 4.5e-2 do de bien luan cho 40 bit o mot cho khac. Chot: **64 bit** = 13 ky tu
Crockford base32 + 1 ky tu checksum → `BC-XXXXXXXXXXXXX-C`. Crockford (bo I, L, O, U) de doc qua
dien thoai va chong nham `0/O`, `1/I`. Va van giu unique constraint tren `ref_hash_hex` lam chot
chan cuoi — xac suat khong phai la bao dam.

**R3 — Uniquify bang so le cua so tien.** Bac bo dut khoat. USDC 6 decimals: 3 chu so cuoi cho
1000 khoa; fee-on-transfer token va cac router se lam lech so tien; hai request cung gia se dam
nhau. Khong dung.

**R4 — Nguoi tra khai bao `tx_hash` tren portal.** Fallback thu cong, luon phai co, khong bao gio
la co che chinh. Phai verify: `tx.to == expected`, `tx.value/amount`, `tx_hash` chua duoc claim
(unique constraint), va chi accept khi da `final`. Them mot chi tiet chong lam dung: chi cho phep
khai bao `tx_hash` co `block_timestamp` **sau** thoi diem tao request — neu khong, ai do se khai
mot transfer cu cua chinh ho de dong mot hoa don moi.

Constraint idempotency bon tang:

```python
_unique_onchain_leg = models.Constraint(
    'UNIQUE(caip2, tx_hash, log_index)',
    'Mot log on-chain chi duoc ghi nhan mot lan.')                    # observation
_unique_ref_hash = models.Constraint(
    'UNIQUE(ref_hash_hex)', 'ref_hash phai duy nhat.')                # request
_unique_origin_ref = models.Constraint(
    'UNIQUE(company_id, origin_model, origin_ref)',
    'origin_ref cua consumer phai duy nhat.')                          # request
_unique_receiving_address = models.Constraint(
    'UNIQUE(caip2, receiving_address)',
    'Mot dia chi nhan chi phuc vu mot request.')                       # request, che do derived
```

Kiem chung bat buoc bang SQL, khong tin code (bay #2 CLAUDE.md):
`SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_payment_observation'::regclass;`
Ky vong: mot dong `u` cho `_unique_onchain_leg`. Khong co dong nao = constraint chua bao gio duoc
tao, va idempotency cua ca he thong la mot ao tuong.

---

### 09.7. State machine: broadcast → pending → finality → done

| Su kien on-chain | `blockchain.payment.request.request_state` | `payment.transaction.state` | Goi |
|---|---|---|---|
| Request tao ra | `open` | `draft` | — |
| Nguoi tra broadcast, thay trong mempool | `seen` | `pending` | `_set_pending()` |
| Co receipt, `status == 1` | `mined` | `pending` | `_set_pending()` (khong doi state, chi doi message) |
| Dat finality depth | `final` | `done` | `_set_done()` roi goi `_post_process()` |
| Receipt `status == 0` | `failed` | `error` | `_set_error()` |
| `mined` roi bi reorg day ra | `reorged` | tuy: xem duoi | `_on_reorg()` |
| Het han, chua co tien | `expired` | `cancel` | `_set_canceled()` |
| Het han, sau do tien ve | `late_paid` | — | activity, khong tu dong `done` |

Bang chuyen trang thai hop le cua Odoo 19 (doc tu `_set_*`, de biet cai gi **khong** lam duoc):

| Method | Source states cho phep |
|---|---|
| `_set_pending` | `draft` |
| `_set_authorized` | `draft`, `pending` |
| `_set_done` | `draft`, `pending`, `authorized`, `error` |
| `_set_canceled` | `draft`, `pending`, `authorized` |
| `_set_error` | `draft`, `pending`, `authorized` |

Doc bang nay ky: **khong co duong tu `done` di dau ca** (tru khi truyen `extra_allowed_states`, la
mot cua sau chu khong phai mot thiet ke). `_update_state` khong raise khi state khong hop le — no
**ghi mot `_logger.warning` va bo qua**. Nghia la mot chuyen trang thai sai se **khong** lam do
test, chi de lai mot dong log ma khong ai doc. Moi handler phai tu kiem tra `tx.state` sau khi goi
`_set_*` neu ket qua quan trong.

**Reorg sau `_set_done` la truong hop phai thiet ke, khong phai truong hop hiem.** Voi
`finality_mode = 'soft'` tren Gnosis (1 block, 5s) — che do bat buoc cho `ENDUSER_PAY` — reorg do
sau 1-2 block xay ra thuc te. Dao nguoc mot `done` da `_post_process` (da tao `account.payment`, da
xac nhan don) la sai. Quy tac:

- `finality_mode = 'hard'`: reorg sau `done` coi nhu khong xay ra.
- `finality_mode = 'soft'`: `_set_done` van chay, nhung `_on_reorg` **khong** dao nguoc — no tao mot
  `blockchain.payment.reversal` va mot activity cho ke toan, va bridge `dms_blockchain_account`
  sinh but toan dieu chinh. Tien da giao hang roi thi cai can la mot but toan, khong phai mot
  rollback.

**Dat `soft_final_max_amount` bang mot phep tinh, khong bang cam giac.** Ton that ky vong nam:

```
E[loss/nam] = P(reorg vuot depth) × so_tx/nam × gia_tri_tb_moi_tx
```

Vi du lam viec, cho `ENDUSER_PAY` tren Gnosis o soft finality (depth 1):
`P ≈ 1e-4/tx` (**uoc tinh** — Gnosis co reorg do sau 1 thinh thoang xay ra; con so that phai lay
tu histogram do sau reorg ma indexer §11 tu ghi trong 30 ngay, dung uoc tinh nay lam gia tri khoi
dong), 1,000,000 tx/nam, trung binh $5/tx ⇒ **E[loss] ≈ $500/nam**. So voi doanh so $5M, do la
1e-4 — re hon nhieu so voi chi phi mat khach vi bat khach doi 2.7 phut o quay.
Cung phep tinh cho mot khoan $50,000: E[loss] cho **mot** giao dich = $5. Van nho, nhung phuong sai
thi khong: mot lan mat $50,000 khong bu duoc bang 10,000 lan tiet kiem 2.7 phut. **Quy tac dat
nguong: `soft_final_max_amount` = so tien ma ban chiu duoc khi mat mot lan, khong phai so tien co
ton that ky vong thap.** De xuat mac dinh: **$200** cho `ENDUSER_PAY`, `False` (khong cho soft)
cho moi flow B2B. Va mot mach ngat tong: neu tong gia tri soft-final chua qua hard finality vuot
`soft_final_exposure_cap` (de xuat $5,000), moi request moi tu dong chuyen sang `hard`.

**Gia tri hard finality thuc te, da sua:**

| Chain | Soft | Hard | Ghi chu |
|---|---|---|---|
| Gnosis xDAI | 1 block ≈ 5s | 2 epoch = **2 × 16 slot × 5s ≈ 160s (~2.7 phut)** | **[SUA]** note ghi "12.8 phut" — do la con so cua Ethereum (32 slot × 12s × 2). Gnosis co **16 slot/epoch** va slot 5s |
| Ethereum L1 | 1 block ≈ 12s | 2 epoch ≈ **12.8 phut** | dung |
| Celo | ~1s (sequencer) | **den khi batch duoc finalize tren L1 ≈ 15-20 phut** | **[SUA]** note mo ta Celo la "IBFT 2.0, 1 block immediate finality". Celo da chuyen thanh **L2 OP-Stack tren Ethereum (2025)**; §03.3.8 cua bo tai lieu nay cung da coi Celo la L2 block 1s. Mot Celo adapter viet theo mo ta cu se coi soft la hard |
| Private QBFT/IBFT | instant | instant | khong reorg khi < 1/3 validator loi |

**Expiry khong duoc lam mat tien.** `_cron_expire_payment_requests` dat `expired` + `_set_canceled`,
nhung dia chi/ref **van duoc watch vinh vien**. Tien ve muon → observation `late_paid`, tao
activity, khong bao gio tu dong `_set_done` mot transaction da `cancel`. Xu ly: nguoi van hanh chon
"ap dung vao request moi" hoac "hoan tra". Luu y he qua ke toan: neu tx da lien ket invoice,
`account_payment._post_process()` se goi `tx.payment_id.action_cancel()` cho moi tx `cancel` — voi
mot request chua tung co tien thi khong sao (chua co payment), nhung dung cancel mot tx da tung
`done`.

**Overpay / underpay / sai token / sai chain:**

| Tinh huong | Hanh dong |
|---|---|
| Tra thua ≤ `tolerance_bps` (mac dinh 10 bps) | Coi la du, ghi chenh vao thu nhap khac |
| Tra thua > tolerance, `overpay_policy = accept` | `_set_done`, phan thua vao `blockchain.credit.balance` cua partner |
| Tra thieu, `underpay_policy = partial` | Request giu `open`, `amount_received_base` cong don; `_set_done` khi du. Nhieu transfer → nhieu observation cung mot request: dung |
| Tra thieu ≤ `tolerance_bps` | Coi la du. Day la truong hop **pho bien nhat** trong thuc te: vi tru phi, hoac nguoi dung go tron so |
| Sai token (USDT thay vi USDC) tren dung dia chi | `unmatched_token`, khong bao gio tu quy doi. Ty gia phai la mot quyet dinh cua nguoi, khong phai cua cron |
| Dung dia chi nhung sai chain (dia chi EVM giong nhau tren moi chain) | `unmatched_chain`. Day la loi nguoi dung pho bien nhat. Neu ta khong kiem soat khoa cua dia chi tren chain do → **tien mat that**. Vi vay `receiving_mode = 'derived'` phai deploy CREATE2 tren **moi** chain EVM ma ta chap nhan, cung factory, cung salt, cung initCodeHash (§09.6 R1) |
| Tien ve mot dia chi da `expired` | `late_paid`, xem tren |
| Gia tri sau khi sweep < `sweep_min_value` | Khong sweep ngay; gom. Tren Gnosis sweep ton ~$0.0002 nen nguong nay gan nhu bang 0; tren Ethereum L1 no la **$1-3** ⇒ moi khoan duoi $10 la khong dang sweep rieng |

`blockchain.credit.balance` (core, khong can `account`):

```python
class BlockchainCreditBalance(models.Model):
    _name = 'blockchain.credit.balance'
    _description = 'Overpayment credit held for a partner, per token'

    company_id = fields.Many2one('res.company', required=True, index=True)
    partner_id = fields.Many2one('res.partner', required=True, index=True)
    token_id   = fields.Many2one('blockchain.token', required=True, index=True)
    balance_base = fields.Char(required=True, default='0')
    _unique_credit = models.Constraint(
        'UNIQUE(company_id, partner_id, token_id)',
        'Mot partner chi co mot so du tin dung tren mot token.')
```
`balance_base` la plain field co `default`, **khong** phai stored computed — vi mot stored computed
khong nhan `default`, va neu compute co nhanh khong gan gi thi cot `required` nhan NULL va INSERT
chet (bay CLAUDE.md, §15 da bat duoc o ba cho).

**Refund la mot giao dich moi, khong phai dao nguoc.** `_create_child_transaction(amount,
is_refund=True)` cua Odoo 19 da lam dung phan Odoo (amount am, prefix `R-`). Phan chain:

```python
def _send_refund_request(self):
    if self.provider_code != 'chain':
        return super()._send_refund_request()
    src = self.source_transaction_id
    addr = src.blockchain_refund_address
    if not addr or not src.blockchain_refund_address_verified:
        raise ValidationError(_(
            "Khong co dia chi hoan tien da xac minh. Dia chi gui tien co the la vi nong cua "
            "san giao dich; hoan ve do la mat tien."))
    self.env['blockchain.relay.job'].relay_submit_intent(
        caip2=src.blockchain_caip2, target_address=src.blockchain_token_address,
        calldata_hex=encode_transfer(addr, self.blockchain_amount_base),
        origin_model='payment.transaction', origin_res_id=self.id,
        origin_ref='refund:%s' % self.reference)     # idempotency, khop _unique_origin cua §06
```

`blockchain_refund_address_verified` chi `True` khi: (a) dia chi da ky mot challenge trong portal
(EIP-191 `personal_sign` mot nonce co han, luu nonce de chong replay), hoac (b) dia chi khop mot
`blockchain.wallet` da KYC gan voi `partner_id`. `from` cua transfer **khong** du: rut tu Binance
thi `from` la vi nong cua Binance va tien hoan se khong bao gio ve tay khach. Do la ly do
`support_refund` mac dinh la `'none'`.

Va mot dieu ban nhap khong noi: **hoan tien mot phan tren chain khong ton tai nhu mot khai niem**.
`support_refund = 'partial'` chi co nghia la Odoo cho phep tao child tx voi so tien nho hon; on-chain
no van la mot transfer moi. Nghia la khong co gi rang buoc tong cac lan hoan ≤ so tien goc **o phia
chain** — chi Odoo rang buoc (`_update_source_transaction_state` cong don child). Neu ai do goi
`relay_submit_intent` truc tiep, rang buoc do bien mat. Do la ly do `relay_submit_intent` phai kiem
tra `origin_model='payment.transaction'` co child tuong ung o state `pending`.

---

### 09.7b. Ty gia va bao gia — cho ban nhap bo trong hoan toan

`payment.transaction.amount` la fiat (`res.currency`, thuong VND). On-chain la base units cua mot
token. Giua hai cai la mot ty gia. Ban nhap khong noi ai dat ty gia, dat luc nao, va ai chiu rui ro
khi no doi giua luc tao request va luc tien ve. Do la mot lo hong thuc thi, khong phai chi tiet.

Ba tinh huong, do rui ro khac han nhau:

| Cap | Bien dong trong 30 phut | Xu ly |
|---|---|---|
| USD invoice ↔ USDC | ~0 (stablecoin) | Ty gia 1:1, khong can quote |
| VND invoice ↔ USDC | ty gia USD/VND, bien dong ngay ~0.1-0.3% | Khoa ty gia luc tao request, han hieu luc |
| VND invoice ↔ token bien dong (khong khuyen nghi) | 2-10%/gio | Khong cho phep tren `B2B_*`; neu cho, quote 120 giay |

```python
class BlockchainPaymentQuote(models.Model):
    _name = 'blockchain.payment.quote'
    _description = 'Locked fiat-to-token rate for one payment request'

    request_id      = fields.Many2one('blockchain.payment.request', required=True,
                                      ondelete='cascade', index=True)
    currency_id     = fields.Many2one('res.currency', required=True)
    token_id        = fields.Many2one('blockchain.token', required=True)
    rate_numerator_base   = fields.Char(required=True)   # base units token
    rate_denominator_cent = fields.Char(required=True)   # don vi nho nhat cua fiat
    rate_source     = fields.Char(required=True)         # 'ecb', 'sbv', 'chainlink:...', 'fixed'
    locked_datetime = fields.Datetime(required=True)
    expiry_datetime = fields.Datetime(required=True, index=True)
    quote_state     = fields.Selection([('live', "Live"), ('used', "Used"),
                                        ('expired', "Expired")], default='live', required=True)
```

Ty gia luu duoi dang **phan so hai so nguyen**, khong phai float — vi mot `Float` VND/USDC voi 6
decimals lam tron sai o hang dong. `rate_source` la bat buoc va phai duoc luu: khi kiem toan hoi
"tai sao hoa don 25,000,000 ₫ lai la 1,000 USDC", cau tra loi phai la mot dong du lieu, khong phai
mot phep tinh lam lai bay gio.

Chinh sach khi quote het han truoc khi tien ve:
- Trong `tolerance_bps`: chap nhan, chenh lech vao tai khoan chenh lech ty gia (`account.account`
  loai `income`/`expense`, cau hinh tren `dms_blockchain_account`).
- Ngoai `tolerance_bps` va `quote_reprice_policy = 'reprice'`: request giu `open`, sinh quote moi,
  yeu cau tra bu phan thieu.
- Ngoai `tolerance_bps` va `quote_reprice_policy = 'accept'`: chap nhan, ghi lai/lo ty gia.

`quote_validity_seconds` mac dinh **900** (15 phut) cho cap fiat-stablecoin, **120** cho token bien
dong. `request_expiry_minutes` mac dinh 30 nen mot request co the phai reprice mot lan giua doi —
do la co y, va UI phai hien nguoc dong ho cua quote, khong phai cua request.

---

### 09.8. Nguoi tra khong bao gio mo app

```
Ke toan brand   ->  dms_blockchain_payment: tao payment.transaction (reference duoc chot)
                    -> blockchain.payment.request: ref32 = keccak(db_uuid, tx.reference)
                       receiving_mode='derived' -> dia chi D (CREATE2, chua deploy)
                    -> blockchain.payment.quote: khoa ty gia VND/USDC, han 15 phut
                ->  Gui email/portal link: "chuyen 5,000 USDC (Gnosis) toi D truoc <expiry>"
Distributor     ->  Mo Safe cua ho, transfer USDC -> D.   (Khong biet Odoo la gi)
Watcher (§11)   ->  Log Transfer(to=D) -> blockchain.payment.observation (obs_state=mined)
                    (ghi provider_reference vao observation NGAY, truoc moi buoc sau)
Finality Gate   ->  quorum RPC >= 2, depth du -> obs_state=final -> cron._trigger()
Cron            ->  payment.transaction._process('chain', obs._payment_data())
                    _search_by_reference: D -> request -> tx.reference     <- ANH XA O DAY
                    _validate_amount -> _apply_updates -> _set_done
                ->  tx._post_process()  (goi truc tiep, khong doi cron 10 phut)
                ->  bus._sendone(...) cho man hinh dang mo, neu co
Sweep job       ->  deploy clone tai D, transfer USDC -> treasury (gom lo neu duoi nguong)
```

Anh xa khong dua vao memo, khong dua vao `from`, khong dua vao so tien. Dia chi la reference.

Tien ve **truoc khi** co request (tra som, hoac chuyen nham) → observation `unmatched`. Quy tac
cung: **khong bao gio tu dong tao `payment.transaction` tu mot observation `unmatched`.** Mot
wizard cho nguoi van hanh gan no vao mot invoice. Tu dong o day la con duong ngan nhat toi viec ghi
nhan doanh thu cho mot khoan tien khong biet cua ai. (Cung ket luan voi §11.8, va cung mo hinh voi
`dms.bank.reconciliation`: tien chua khop vao tai khoan treo.)

#### 09.8b. `partner_id` la `required`, con nguoi tra thi vo danh

`payment.transaction.partner_id` la `required=True, ondelete='restrict'`. `payment.token` con chat
hon: `_check_partner_is_never_public` cam gan token cho partner public. Ba lua chon, phai chon mot
o muc deployment:

| Chinh sach | Cach lam | Hop voi |
|---|---|---|
| `anonymous_partner` | Mot `res.partner` ky thuat "Walk-in crypto payer" cho moi company. Moi tx vo danh tro vao no | `ENDUSER_PAY` khoi luong lon, gia tri nho |
| `partner_per_wallet` | Lan dau thay mot dia chi, tao `res.partner` + `blockchain.wallet` gan voi no; lan sau tai su dung | `B2B_*`, va bat buoc neu can Travel Rule |
| `require_known_partner` | Tu choi moi observation tu dia chi chua co trong `blockchain.wallet`. Tien vao tai khoan treo | Chain private, va moi truong tuan thu chat |

Mac dinh de xuat: `require_known_partner` cho `B2B_*` va `chain_profile='private'`;
`anonymous_partner` cho `ENDUSER_PAY`. `partner_per_wallet` nghe hay nhung tao rac: mot chien dich
loyalty co the sinh 200,000 `res.partner` trong mot thang, va `res.partner` la model nang nhat
trong Odoo. Neu chon no, phai co nguong (chi tao partner khi tong gia tri tu mot vi vuot mot muc).

Lien quan phap ly (§13): nguong Travel Rule cua FATF la **$1,000/EUR 1,000** cho giao dich VASP.
Neu deployment roi vao pham vi do, `require_known_partner` khong con la tuy chon.

---

### 09.9. Zether pha vo M1 — va vi sao M13 phai la M4, khong phai M1

`payment.transaction._validate_amount()` (Odoo 19, `payment/models/payment_transaction.py:794`)
so sanh so tien tu payment_data voi `tx.amount` va `_set_error` neu lech. Voi Zether, chain khong
he lo so tien: chi co `(C_transfer, D_transfer)` va mot `fee` cong khai. Khong co gi de so sanh.

May man la Odoo 19 da mo san cua: `_extract_amount_data` tra `None` → *"Skip validation for
transactions where the provider opts out of amount check"* (`payment_transaction.py:807`). Do la
duong hop phap duy nhat, va section nay dung no (§09.5e). Tien le: `payment_custom` lam **dung y
nhu vay** cho wire transfer.

Nhung ket qua la mot `payment.transaction` `done` ma **khong ai chung minh duoc so tien**. Chain
chi chung minh: mot khoan chuyen nao do, tu `fromSchnorrAddress` toi `toSchnorrAddress`, tai epoch
`e`, hop le ve range proof. So tien den tu **client cua nguoi nhan giai ma `(C, D)` bang khoa rieng
cua chinh ho**, roi Odoo **xac minh** `C_transfer == g^v · y_recv^s` (§11.10 — mot phep kiem tra re,
khong can khoa bi mat). Duong thu hai la mot receipt off-chain do nguoi tra ky bang viewing key.

Ket luan ky thuat: voi Zether, **nguon su that ve so tien la so du giai ma duoc cua nguoi nhan**,
khong phai mot su kien. Do la mo hinh sub-ledger, khong phai mo hinh payment gateway. Vi vay:

| | M1 + Zether | M4/M13 + Zether |
|---|---|---|
| So tien doi soat tu | receipt off-chain (tin nguoi tra) | delta so du giai ma cua chinh minh |
| Phat hien thieu tien | khong, cho toi khi ai do doi chieu | ngay o buoc reconcile lo |
| Reorg | phai dao nguoc mot `done` | chi lam lech mot lo, sua o lo sau |
| Khuyen nghi | **khong** | **co** |

Them mot rang buoc thuc te: Zether can `rollOver()` va `simulateAccounts()` (note §10.5.3) — so du
chi chinh thuc o epoch sau. Nghia la ngay ca soft finality cung khong du: `_on_final` cho Zether
phai doi **epoch boundary + finality depth**. Tren Gnosis voi epoch = 5 block × 5s = 25s, cong hard
finality 2 epoch beacon (~160s, da sua o §09.7) → **~3 phut**, khong phai 13 phut nhu ban nhap uoc.
Van la qua lau cho `ENDUSER_PAY`. Tren private chain (quyet dinh #5) voi block time 1s va instant
finality → **~5-10s: kha thi**. Do la mot ly do ky thuat doc lap ung ho quyet dinh #5, ngoai ly do
gas.

**Va rang buoc that su chan `ENDUSER_PAY` bang Zether tren public chain khong phai do tre, ma la
block space.** Theo §03.3.6/§03.3.8: mot confidential transfer cau hinh 32/64 ton **~1.88 M gas**;
Gnosis co block gas limit 17 M va block 5s ⇒ o muc chiem 20% block space cua ca mang, tran la
**~31,300 tx/ngay toan he thong**. Mot chuoi ban le 200,000 outlet khong nam vua trong con so do.
Private chain (QBFT, precompile native) cho ~500 tx/s. Khong co lua chon thu ba.

---

### 09.10. Dinh luong

#### 09.10a. Gas

Cong thuc dung cho ca bang: `chi_phi_USD = gas × gas_price_gwei × 1e-9 × gia_native_USD`.
Gia dinh: xDAI = $1.00, CELO = $0.50, Gnosis 2 gwei, Celo 5 gwei.
Celo cong **+50,000 gas intrinsic** cho giao dich khai `feeCurrency` (**uoc tinh**, co so:
overhead them cua tx type CIP-64 cho viec ghi no/co dong stablecoin o tang validator; phai do lai
tren mainnet Celo hien tai truoc khi dua vao SLA).

| Thao tac | Gas | Gnosis @2 gwei | Celo: gas+50k | Celo @5 gwei |
|---|---|---|---|---|
| `ERC20.transfer` (dich da warm) | 45,000 | $0.000090 | 95,000 | $0.000238 |
| `ERC20.transfer` (dich lan dau, ghi slot moi) | 65,000 | $0.000130 | 115,000 | $0.000288 |
| `PaymentRouter.pay(token, amount, ref)` + event | 85,000 | $0.000170 | 135,000 | $0.000338 |
| CREATE2 clone deploy + sweep | 110,000 | $0.000220 | 160,000 | $0.000400 |
| EIP-1776 envelope: ecrecover + EIP-712 + nonce | +9,000 … +24,000 | +$0.00002…0.00005 | — | — |
| EIP-1776 envelope + tra fee bang ERC-20 | +39,000 … +69,000 | +$0.00008…0.00014 | — | — |
| Zether `transferConfidential` 32/64 (§03.3.6) | **1,880,000** | **$0.00376** | 1,930,000 | **$0.00483** |
| Zether `transferConfidential` 128/128 | 3,870,000 | $0.00774 | 3,920,000 | $0.00980 |
| `permit` + `transferFrom` | 100,000 | $0.000200 | 150,000 | $0.000375 |
| Batch 150 nguoi nhan (M17) | 4,521,000 | $0.00904 | — | — |

**[SUA] Hai loi trong bang cua ban nhap:**

1. **Zether 180,000-250,000 gas: sai 15-20 lan.** §03.3.7 da truy ra nguon goc: `45,000 + 4 ×
   34,000 = 181,000` la chi phi verify mot **Groth16 SNARK tren alt_bn128** (4 pairing), khong phai
   Bulletproofs — Bulletproofs khong dung pairing. Con so dung la 1.88 M (32/64) den 3.87 M
   (128/128). Bang tren da sua theo §03 de ca bo tai lieu nhat quan.
2. **Cot Celo cua ban nhap khong khop chinh gia dinh cua no.** Voi CELO = $0.50 va +50k intrinsic,
   dong `65,000` phai ra $0.000288 chu khong phai $0.00033; dong `110,000` phai ra $0.000400 chu
   khong phai $0.00053. Da tinh lai toan bo bang bang mot cong thuc duy nhat, viet ro o tren.
3. **EIP-1776 "+32,000"** la mot con so khong chia nho duoc. Chia ra: `ecrecover` 3,000 +
   keccak/EIP-712 ~1,000 + SSTORE nonce 5,000 (slot warm nonzero→nonzero) hoac 20,000 (slot moi)
   = **9,000-24,000**. Neu fee tra bang mot `ERC20.transfer` rieng cho relayer thi cong them
   30,000-45,000 ⇒ **39,000-69,000**. Ban nhap gop nua chung.

#### 09.10b. Do tre va throughput

| Dai luong | Gia tri | Co so |
|---|---|---|
| Do tre `ENDUSER_PAY` tot nhat (Gnosis soft) | ~5-8s | 1 block 5s + quorum RPC + `_trigger` |
| Do tre `ENDUSER_PAY` neu quen `_trigger` | **den 10 phut** | cron post-process mac dinh |
| Do tre hard finality Gnosis | ~160s | 2 epoch × 16 slot × 5s |
| Do tre Zether tren Gnosis (epoch + hard) | ~185s | 25s epoch + 160s |
| Do tre Zether tren private chain | 5-10s | block 1s, instant finality |
| Tran xu ly observation (cron 1 phut, limit 200) | 12,000/gio | — |
| Tran xu ly observation (`_trigger` moi block) | ~144,000/gio | 720 lan chay/gio × 200 |
| Tran Zether toan mang Gnosis @20% block space | 31,300 tx/ngay | §03.3.8 |
| Tran Zether private chain | ~500 tx/s | §03.3.8 |

#### 09.10c. Cong suc va chi phi van hanh

Effort (person-week, mot dev senior, chua tinh audit contract):

| Goi | pw |
|---|---|
| M0 `payment_custom` cau hinh (chay duoc trong tuan dau) | 0.2 |
| Core: `blockchain.money.flow`, handler interface + registry check, request/observation/quote, Finality Gate binding | 5 |
| `dms_blockchain_payment` (M1 + M6 + M11) | 6 |
| `dms_blockchain_account` (M3 + M4 ke toan + M15 netting) | 6 |
| `dms_blockchain_mandate` (M7 + M10) | 4 |
| M8 stream, M9 escrow (ke ca contract, chua audit) | 8 |
| M14 auto-convert, M17 batch, M18 voucher (contract + Odoo) | 5 |
| M16 fiat ramp (phan phan mem; phan phap ly khong uoc luong duoc) | 4 |
| **Tong phan mem** | **~38 pw** |
| Audit contract ben ngoai cho router + escrow + voucher | ~$25-40k, 3-5 tuan lich |

Chi phi van hanh/nam (**uoc tinh**, co so: gia niem yet 2026 cua nhom nha cung cap pho bien):

| Muc | $/nam |
|---|---|
| 2 RPC endpoint doc lap (bat buoc cho quorum) tren Gnosis + Celo | $1,200-3,600 |
| Node tu chay (tuy chon, thay 1 endpoint) | ~$1,000 (VPS) + cong van hanh |
| Giam sat/alerting (watcher lag, reorg, so du gas relayer) | $300-1,200 |
| Gas cho 1M request loyalty R1 (deploy+sweep) tren Gnosis | ~$220 |
| Quy du phong ton that soft-final (theo §09.7) | dat bang E[loss], vi du $500 |

---

### 09.10d. Kiem chung: cai gi phai xanh truoc khi goi la xong

Khong phai test plan day du (§14 lo do), chi la nhung phep do ma **neu thieu thi khong biet la
minh sai**:

```
1. SQL, khong phai code:
   SELECT conname, contype FROM pg_constraint
   WHERE conrelid IN ('blockchain_payment_request'::regclass,
                      'blockchain_payment_observation'::regclass);
   -> phai co du 4 dong 'u' cua §09.6. Zero dong = idempotency khong ton tai.

2. Registry check cua §09.4a phai lam server KHONG khoi dong duoc khi mot handler
   thieu _on_reorg. Test bang cach tam xoa method va chay `odoo -u`.

3. available_currency_ids: them mot token vao accepted_token_ids, doc lai field.
   Neu no khong doi -> depends chua duoc override (§09.5a).

4. Reorg: chay anvil, tao mot payment, _set_done o soft, roi `anvil_reorg` 2 block.
   Ky vong: mot blockchain.payment.reversal + mot activity. KHONG phai tx.state doi.

5. Do tre end-to-end tren testnet Chiado: tu luc broadcast den luc invoice.state='paid'.
   Ky vong < 15s voi _trigger, < 10 phut neu quen no. Do ca hai de con so co y nghia.

6. forge test --gas-report tren PaymentRouter, CREATE2 factory, VoucherClaim,
   va Zether verifier. Snapshot gas vao CI: bang §09.10a la uoc tinh cho toi khi co snapshot.

7. Sai chain: gui USDC toi dia chi derived tren Celo trong khi request o Gnosis.
   Ky vong: unmatched_chain + van sweep duoc (cung factory, cung salt).
   Neu khong sweep duoc -> R1 chua trien khai dung (§09.6).
```

---

### 09.11. Cho note goc chua du, va quyet dinh da chon

| Cho thieu / rui ro trong `blockchain.md` | Quyet dinh o section nay |
|---|---|
| Note khong he noi den lop payment cua Odoo — chi noi "ERP/SoR" chung chung | Phan lop 6 addon (§09.0); mot deployment co the chi cai core |
| Note noi *"chi phat tin hieu xac nhan cho ERP khi dat Finality Depth"* nhung khong noi lam gi khi soft-final bi reorg **sau khi** da ghi so | `blockchain.payment.reversal` + but toan dieu chinh; khong dao nguoc `done`; `soft_final_max_amount` dat bang cong thuc ton that ky vong (§09.7) |
| Note gia dinh moi giao dich deu di qua Gateway cua ta. Truong hop nguoi tra dung vi rieng, khong cham app — chiem phan lon giao dich B2B thuc te — khong duoc nhac den | R1 dia chi CREATE2 rieng moi request, cung factory/salt/initCodeHash tren moi chain EVM (§09.6, §09.8) |
| Note khong co co che reference/memo nao. EVM `ERC20.transfer` khong co truong memo — day la lo hong thuc thi, khong phai chi tiet | Router contract `pay(token, amount, bytes32 ref)` cho EVM; memo native cho 5 chain con lai (bang §09.6); mo rong `_get_communication()` co san thay vi dat ten moi |
| Note khong noi ve refund | Refund la tx moi; `support_refund='none'` mac dinh; chi hoan ve dia chi da xac minh bang chu ky challenge, khong bao gio ve `from` (§09.7) |
| Zether + payment gateway khong tuong thich — note khong nhan ra | `_extract_amount_data` tra `None` (tien le `payment_custom`); khuyen nghi M4 thay vi M1 (§09.9) |
| Note khong dat gioi han tren so tien cho soft finality | `soft_final_max_amount` (de xuat $200) + `soft_final_exposure_cap` (de xuat $5,000) |
| **Note ghi Gnosis hard finality "12.8 phut"** | Sai: do la con so Ethereum. Gnosis 16 slot/epoch × 5s ⇒ 2 epoch ≈ **160s** (§09.7) |
| **Note mo ta Celo la "IBFT 2.0, 1 block immediate finality"** | Loi thoi: Celo da la **L2 OP-Stack** tu 2025 (§03.3.8 cung coi vay). Soft ~1s tu sequencer, hard = khi batch finalize tren L1 (~15-20 phut). Adapter viet theo mo ta cu se coi soft la hard |
| Note cite **CIP-52** cho fee currency | CIP-52 la thu muc fee currency; **CIP-64** moi la tx type mang truong `feeCurrency`. Adapter can dung so hieu tx type, khong phai so hieu CIP cua thu muc |
| **Note uoc Zether 180-250k gas** | Sai 15-20 lan; da sua theo §03.3.6/§03.3.7 (1.88 M / 3.87 M). He qua that: tran **31,300 tx/ngay** tren Gnosis, khong phai chi phi (§09.9, §09.10a) |
| Note khong noi gi ve ty gia fiat/token | `blockchain.payment.quote`, ty gia luu dang phan so nguyen, `rate_source` bat buoc (§09.7b) |
| Note khong noi ai la nguoi tra khi khach vang lai | Ba chinh sach partner, mac dinh theo flow, nguong Travel Rule $1,000 (§09.8b) |
| Note khong nhac fiat on/off-ramp — nhung outlet VN thu tien mat | M16, va no la **cong phap ly**, khong phai task ky thuat |
| §05 dung `dms.blockchain.*`, §01/02/06 dung `blockchain.*` | Chot `blockchain.*`; va `amount_base` (Char) theo §15, khong phai `amount_token_units` |

#### Lo trinh mac dinh (neu khong ai quyet dinh gi khac)

| Giai doan | Che do bat | Chain | Ly do dung o day |
|---|---|---|---|
| P0 (tuan 1-2) | **M0** | — | Thu duoc tien that truoc khi viet dong code nao. Va no la duong lui vinh vien |
| P1 (thang 1-3) | M1 + M6 + M11 + M4 | Gnosis, `chain_profile='public'`, `finality_mode='hard'` | Duong xuong nguon nong nhat, chua co Zether |
| P2 (thang 3-5) | + M17, M15, M12 | Gnosis | Giam 97% so giao dich B2B truoc khi toi uu gas |
| P3 (thang 5-8) | + M13/M4 Zether | **Private chain truoc** (quyet dinh #5) | Public chain khong cho du block space (§09.9) |
| P4 | + M7/M10, Celo adapter | Celo | Chi khi da co nhu cau that; Celo la L2, khong phai IBFT |
| Bat ky luc nao | M2 | — | Neu doanh so crypto < ~$300k/nam thi M2 re hon tu chay (§09.2 M2) |
| Khong bao gio | M19 | — | M15 dat 97% loi ich voi 5% do phuc tap |
