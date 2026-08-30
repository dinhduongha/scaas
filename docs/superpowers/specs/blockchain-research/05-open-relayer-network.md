## 05. Open Relayer Network: intent pool, kinh te hoc, chong front-run

> **Ban 2 — da qua review doi khang.** Ban 1 dung prefix model `dms.blockchain.*`; §10.3 da chot
> `blockchain.*` va yeu cau section nay doi. Da doi. Ban 1 cung dat `MODE_METERED_FEE = 0x04`, dung
> vao bit `MODE_REQUIRE_SUCCESS` ma §04.4 da cap. Da doi sang `0x08`. Chi tiet o §5.12.
>
> Rang buoc kien truc: `dms_blockchain` **khong depend `dms`**. Moi thu duoi day chi dung `base`,
> `web`, va (tuy chon) `bus`. Phan hach toan cham `account.move` nam trong bridge addon rieng
> `dms_blockchain_account`, khong nam trong core.
>
> **Rang buoc doc:** section nay khong dinh nghia lai struct `MetaTransaction` (§04), khong dinh
> nghia lai mat ma hoc Zether (§03), khong dinh nghia lai relay pool noi bo (§06), khong dinh nghia
> lai data model chung (§10). Noi nao con so cua section nay khac cac section do, section nay **sai**
> va da duoc sua theo. Xem §5.12 cho danh sach delta con lai phai dong bo nguoc.

---

### 5.0. Truc `chain_profile` quyet dinh phan nao cua section nay duoc bat

Quyet dinh khoa #5 (private chain di truoc cho Zether) lam cho gan **toan bo kinh te hoc relayer tro
thanh no-op** o profile private. Phai khai bao ro dieu do, neu khong se build mot thi truong dau gia
cho mot mang chi co ba node cua chinh minh.

| Co che | `chain_profile = private` | `chain_profile = public` |
|---|---|---|
| Intent bus | 1 hub noi bo, khong federation | Federated, nhieu hub peer voi nhau |
| Kenh mang | mTLS trong VPC, khong ra Internet | HTTPS cong khai + rate limit o edge |
| `mode` mac dinh | `MODE_RESTRICT_RELAYER (0x01)` | `MODE_OPEN (0x00)` |
| PoW chong sybil | Tat | Bat cho submitter khong co on-chain history va khong co JWT |
| Relayer stake | Tat (allowlist thay the) | Bat (weight cho lottery) |
| Soft-exclusivity lottery | Tat (round-robin tinh) | Bat |
| Danh gia loi nhuan | Tat (gas free / metered noi bo) | Bat |
| Sponsorship pool on-chain | Tuy chon (co the la budget counter thuan tuy) | Bat buoc |
| Finality Gate | Van bat (1 block BFT) | Bat |
| Ro ri du lieu qua intent | **Rui ro chinh** — xem §5.4.5 | Chain da cong khai roi |

Field: `blockchain.chain.chain_profile = fields.Selection([('private','Private/Permissioned'),
('public','Public')], required=True, default='private', index=True)`. Day la mot **field tren
`blockchain.chain`**, khong phai model rieng (§10.3 da bac bo `blockchain.chain.profile`). Moi doan
code kinh te hoc duoi day deu guard bang `if chain.chain_profile == 'public'`.

**Chi trien khai profile `public` khi da co it nhat 1 relayer ben thu ba that.** Truoc do, viet code
de no *co the* bat, dung bat.

**Dieu ban 1 khong noi thang, va can noi:** o profile `private`, section 05 rut gon thanh
**section 06 cong mot allowlist**. Khong co thi truong, khong co dau gia, khong co lottery, khong co
stake. Cai duy nhat con lai co gia tri kien truc la **dinh dang envelope va state machine** — vi do
la thu phai on dinh de sau nay bat public ma khong phai viet lai client. Neu ke hoach 12–18 thang dau
la private (§5.9 Phase 3 noi dung la vay), thi **deliverable that cua section nay o quy 1 la §5.2
(dinh dang) va §5.8 (state machine), khong phai §5.4 (front-run)**. Uu tien build theo thu tu do.

---

### 5.1. Cach intent duoc cong bo va kham pha: chon federated intent bus, khong xay p2p moi

Note goc (`blockchain.md` §10.1, muc `P2P_POOL`) noi "Open Relayer Gossip Mempool / Intent Pool ...
tu p2p gossip / mempool". Do la mot cau chu khong phai mot thiet ke, va no la lua chon dat nhat
trong ba lua chon.

| Phuong an | Latency them | Chi phi van hanh | Do kho cho relayer ben thu ba | Danh gia |
|---|---|---|---|---|
| **A. libp2p / gossipsub topic rieng** | 100–800 ms (mesh fanout) | Bootstrap nodes, NAT traversal, peer scoring, DHT | Cao: phai nhung go-libp2p / js-libp2p, hoc peer discovery | **Loai.** Xay lai mot mang p2p de van chuyen ~10 msg/s la over-engineering thuan tuy. ERC-4337 mat 3 nam moi co alt-mempool that su chay, va no van chu yeu la cac bundler goi HTTP truc tiep. |
| **B. Public mempool cua chinh chain** (nhung intent chua ky nhu tx thuong) | 0 | 0 | Thap | **Khong kha thi.** Intent EIP-1776 la mot payload can `msg.sender` la relayer — no khong phai mot tx hop le cho den khi relayer boc no lai. Khong the nhet vao mempool EVM. |
| **C. Federated intent bus (HTTP publish + poll/stream, nhieu hub peer voi nhau)** | 0–1000 ms (poll 1 Hz) | 1 controller + 1 bang Postgres | Rat thap: `curl` la du | **Chon.** |

**Khuyen nghi: C.** Ly do dinh luong: Gnosis block time 5 s. Poll 1 Hz them toi da 1 s = 20% mot
block. Doi lay dieu do, relayer ben thu ba chi can biet `GET`. Voi 50 relayer poll 1 Hz, hub nhan
50 req/s tren mot index `(chain_id, state, expiry_datetime)` — mot Odoo worker don xu ly duoc.

#### 5.1.1. Ngan sach latency, va cho ban 1 hua qua

Ban 1 noi "1 s la 20% mot block" roi dung o do. Do la mot cau dung cho intent thuong va **sai cho
Zether**. §04.5 chot `expiry` cua metaTx Zether la **≤ 20 giay** (1 epoch = 5 block × 5 s = 25 s,
tru 1 block an toan). §03.8 chot thoi gian prove: **0.2–0.5 s** (Android ARM64 native) den
**0.8–2.5 s** (WASM trong WebView). Ghep lai:

| Buoc | Intent thuong | Intent Zether |
|---|---|---|
| Client prove ZKP | 0 | **0.2–2.5 s** |
| Ky + `POST /publish` | 50–200 ms | 50–200 ms |
| Hub validate (tang 0–3) + persist | 5–20 ms | 5–20 ms |
| Relayer phat hien (poll 1 Hz) | **0–1000 ms** | **0–1000 ms** |
| Relayer `eth_call` simulate | 15–40 ms | **60–150 ms** (verify BP tren node) |
| Soft-exclusivity window `W` | **3000 ms** | **phai = 0** |
| Broadcast → inclusion (1 block) | 5000 ms | 5000 ms |
| **Tong xau nhat** | **~9.3 s** | **~8.9 s (khong ke prove)** |
| **Ngan sach `expiry`** | 900 s | **20 s** |
| **Bien con lai** | thoai mai | **~11 s, hoac ~8.5 s neu prove tren WASM** |

Ket luan bat buoc, ban 1 thieu:

1. **Intent Zether phai co `W = 0`** (khong soft-exclusivity). Mat 3 s cua ngan sach 20 s la
   15% ngan sach de doi lay mot bien phap chong lang phi $0.000024. Sai ty le.
2. **Intent Zether phai duoc day, khong duoc poll.** Them mot kenh long-poll:
   `GET /intents/v1/pending?wait=8&urgent=1` — server giu ket noi toi da 8 s, tra ngay khi co intent
   `is_zether` moi. Chi mo cho relayer **da dang ky** va co `median_latency_ms < 2000`.
3. **Long-poll khong duoc chay tren Odoo worker prefork** (xem canh bao duoi). Neu chua tach daemon,
   giai phap tam thoi dung duoc: relayer poll `?urgent=1` o **5 Hz** thay vi 1 Hz, chi lay summary
   (~200 B/intent). 5 Hz × 20 relayer = 100 req/s cho mot query index — chap nhan duoc, va no dua
   latency phat hien ve ≤ 200 ms ma khong can ha tang moi. **Chon cai nay cho v1.**

Khi nao nang cap len streaming that: khi latency 1 s an mat >5% co hoi (tuc khi so relayer canh
tranh cung mot intent > 3), hoac khi so relayer > 200. Luc do them SSE.

**Canh bao trien khai, da kiem chung tren stack Odoo:** khong lam SSE/WebSocket bang controller Odoo
trong che do prefork. Moi ket noi long-lived giu chet mot worker; voi `workers = 8` ban co toi da 7
stream dong thoi. (`bus.bus` cua Odoo giai quyet dieu nay bang gevent worker rieng — `--gevent-port`
— khong phai bang HTTP worker.) Neu can stream, tach mot daemon nho (aiohttp) doc `LISTEN/NOTIFY` tu
Postgres, dat ngoai addon tai `intent-hub/` o repo root (cung nguyen tac voi `smartcontracts/` o
quyet dinh khoa #9). Odoo giu phan request ngan.

#### 5.1.2. API cua hub

Tat ca la controller Odoo trong `dms_blockchain/controllers/intent_bus.py`. Chung khong phai model
method, vi day la API cho ben thu ba khong co Odoo session — day la ngoai le hop ly cua quy uoc
call_kw/json2 trong CLAUDE.md §6, va phai duoc ghi ro trong docstring.

**Chi tiet Odoo ban 1 bo qua:** dung `type='http'`, **khong** `type='json'`. `type='json'` cua Odoo
la JSON-RPC envelope (`{"jsonrpc":"2.0","params":{...}}`), khong phai REST JSON body — mot relayer
viet bang `curl` se khong doan ra. Mau dung:

```python
# dms_blockchain/controllers/intent_bus.py
import json
from odoo import http
from odoo.http import request

MAX_BODY = 32 * 1024          # Zether proof ~800 B -> hex ~1.6 KB; 32 KB la du rong

class IntentBus(http.Controller):

    @http.route('/intents/v1/publish', type='http', auth='public',
                methods=['POST'], csrf=False, save_session=False)
    def publish(self, **kw):
        """POST mot intent envelope (REST JSON, KHONG phai JSON-RPC).

        Khong dung type='json': ben thu ba goi bang curl/requests, khong co Odoo
        client library. csrf=False vi khong co session. save_session=False de khong
        sinh mot row ir.session moi cho moi request cua relayer.
        """
        raw = request.httprequest.get_data(cache=False)
        if len(raw) > MAX_BODY:
            return request.make_json_response({'error': 'BODY_TOO_LARGE'}, status=413)
        try:
            env = json.loads(raw)
        except ValueError:
            return request.make_json_response({'error': 'BAD_JSON'}, status=400)
        code, body = request.env['blockchain.intent.bus'].sudo().accept_envelope(env)
        return request.make_json_response(body, status=code)
```

`save_session=False` la bat buoc: khong co no, moi request cua moi relayer sinh mot session row va
mot cookie — 200 relayer × 5 Hz = 1000 session/s. Day la mot lo DoS tu gay.

| Route | Method | Muc dich | Auth |
|---|---|---|---|
| `/intents/v1/policy` | GET | fee floor theo (chain, token, mode), PoW bits, danh sach chain + profile, `spec` versions duoc chap nhan, khoa cong khai cua hub | public, `ETag` + `Cache-Control: max-age=60` |
| `/intents/v1/publish` | POST | Nhan mot intent envelope. Tra `409` neu `intent_id` da ton tai (idempotent). | public + tang 0–3 §5.5 |
| `/intents/v1/pending` | GET | `?chain_id=100&since=<cursor>&min_fee=…&token=0x…&target=0x…&fields=summary&urgent=1` | public |
| `/intents/v1/get` | GET | `?ids=0x..,0x..` — lay envelope day du cho toi da 50 id | public |
| `/intents/v1/claim` | POST | Dang ky y dinh relay (soft-exclusivity). **Bat buoc ky bang khoa relayer da dang ky.** Tra `409 CLAIMED_BY_OTHER` + `retry_after` | signed |
| `/intents/v1/receipt` | POST | Relayer bao `tx_hash`. Hub theo doi, re-publish neu qua han | signed |
| `/intents/v1/peers` | GET | Danh sach hub, moi entry ky boi hub owner | public |

**Ba lo hong cua ban 1 o day, deu phai va:**

1. **`/claim` khong co auth.** Bat ky ai cung claim duoc moi intent va khong bao gio relay → khoa
   toan bo lottery trong `W` giay, mien phi, lap lai vo han. Reputation chi phat *sau khi* co danh
   tinh; danh tinh vo danh thi mien phi. **Fix:** `claim` yeu cau header
   `X-Relayer-Sig: <secp256k1 sig>` tren `keccak256("bamboo-claim/1" ‖ intent_id ‖ hub_id ‖ ts)`,
   `|now - ts| <= 30 s`, va dia chi recover ra phai co trong `blockchain.relayer.address`
   voi `allowlist_state in ('probation','allowed')`. Relayer chua dang ky **van relay duoc** — chi la
   khong claim duoc, tuc phai doi het `W`. Do la mot dong co dang ky dung muc.
2. **`/pending` tra envelope day du la lang phi bang thong.** 50 relayer × 1 Hz × 50 intent × 1.5 KB
   = **3.75 MB/s = 30 Mbps** cho mot hang doi 50 intent. `fields=summary` tra
   `(intent_id, chain_id, to, token, fee, gas_limit, expiry, mode, is_zether, exclusive_until)`
   ≈ **200 B** → 0.5 MB/s. Relayer chi `GET /get?ids=` nhung cai no muon. **Giam 7×, mot dong code.**
   `fields=summary` la **mac dinh**; `fields=full` phai xin.
3. **Cursor `(write_date, id)` cua ban 1 bo sot row.** Hai ly do doc lap: (a) Odoo dat `write_date`
   bang `now()` **luc write trong Python**, khong phai luc COMMIT, va nhieu worker co the lech nhau;
   (b) ngay ca mot `bigserial` cung duoc cap **truoc** COMMIT, nen tx co seq nho hon co the hien ra
   sau tx co seq lon hon. Mot reader `WHERE seq > cursor ORDER BY seq` se **nhay qua** row do vinh
   vien. Day la mot bug that, khong phai ly thuyet — no bieu hien la "thinh thoang mot intent khong
   bao gio duoc relay".

   **Fix re nhat va dung:** cursor van la `bus_seq` (`bigserial`), nhung server chi phuc vu row co
   `published_at <= now() - interval '500 ms'` (lag window) **va** client luon xin lai tu
   `cursor - 200`, dedup bang `intent_id`. Dedup von da la co che chinh cua bus (`intent_id` la
   content address), nen chi phi cua overlap la 0 ve mat dung dan va ~200 row/lan poll ve mat bang
   thong. Ghi ro trong `/policy`: `"cursor_overlap": 200, "publish_lag_ms": 500`.

   `# ponytail: lag window 500 ms + overlap 200. Neu commit latency thuc te > 500 ms (dai giao dich`
   `# dai, vacuum), doi sang watermark tu pg_snapshot_xmin(pg_current_snapshot()).`

Federation: moi hub subscribe `/intents/v1/pending` cua peer va re-publish. Vong lap gossip vo hai
vi `intent_id` la **content address**, `publish` la idempotent. **Nhung ban 1 bo qua ba dieu:**

- **Khuech dai.** M hub full-mesh truyen moi intent M(M-1) lan. Voi M = 5 la 20 lan — khong sao.
  Voi M = 20 la 380 lan. Dat tran `max_peers = 8` va them `hops` (uint8) trong envelope, `hops <= 3`,
  hub tang `hops` khi re-publish va **tu choi `hops > 3`**. Khong phai chong tan cong; la chong ngu.
- **Hub doc hai.** Mot peer co the (a) re-publish intent da het han, (b) giu lai (kiem duyet),
  (c) sua `exclusive.*`. (a) chan bang kiem `expiry` truoc khi nhan. (c) chan bang `hub.sig` cua
  **hub goc** — xem §5.2. (b) khong chan duoc va khong can chan: relayer subscribe nhieu hub.
- **`/peers` la mot danh sach tin cay.** No khong nen tu do. `blockchain.intent.hub` la mot model
  co `allowlist_state`, admin duyet tay. Federation la mot lien minh, khong phai mot DHT.

---

### 5.2. Dinh dang thong diep va versioning

`intent_id` **la EIP-712 digest cua struct `MetaTransaction`**, khong phai hash cua JSON:

```
intent_id = keccak256(0x19 ‖ 0x01 ‖ domainSeparator(chainId, verifyingContract) ‖ hashStruct(MetaTransaction))
```

Day la **cung mot gia tri** voi `blockchain.metatx.digest_hash` cua §10.4.5 va `metatx_digest` cua
§04.4. Mot khai niem, mot cot, hai ten tren day. Trong Odoo dung `digest_hash`; tren day dung
`intent_id` vi do la ten ma relayer thay. Ghi ro trong docstring de nguoi doc khong di tim hai bang.

Ba tinh chat mien phi tu lua chon nay:

1. Moi hub tinh ra cung mot id ma khong can dong y ve canonical JSON (JSON canonicalisation la mot ho
   lay ban da roi vao — key order, so hoc float, unicode escape).
2. **Mien nhiem signature malleability.** ECDSA co hai chu ky hop le `(r, s)` va `(r, n-s)`. Vi digest
   khong chua chu ky, ke tan cong flip `s` khong tao ra intent_id moi — hub dedup dung. (Van phai
   reject high-s trong contract theo EIP-2 / `ECDSA.tryRecover`, nhung do la de chong replay on-chain,
   khong phai de dedup.)
3. O `MODE_OPEN`, `relayer` va `feeRecipient` **khong nam trong digest** (canonical zeroing cua
   §04.4) — nen intent_id on dinh bat ke ai relay. Dung cai muon.

**Envelope v1.1 (da bo sung 4 field ban 1 thieu):**

```json
{
  "spec": "bamboo-intent/1.1",
  "intent_id": "0x9f3c…",
  "chain_id": 100,
  "chain_profile": "public",
  "verifying_contract": "0xF17…",
  "meta_tx": {
    "from": "0xA1…", "to": "0xB2…", "tokenContract": "0xC3…",
    "amount": "0", "data": "0xa9059cbb…",
    "batchId": "7412…", "batchNonce": "0",
    "fee": "5000000000000000", "expiry": 1756500900,
    "innerGasLimit": 400000,
    "mode": 4, "relayer": "0x0…0", "feeRecipient": "0x0…0"
  },
  "signature": "0x…65 bytes… (r‖s‖v, low-s)",
  "sig_kind": "eoa",
  "sponsor": { "pool": "0xD4…", "policy_id": "0x0a…", "target_proof": ["0x…","0x…"] },
  "hints": {
    "gas_limit": 182000, "sim_block": 38102411,
    "fee_token_decimals": 18, "fee_value_native": "182000000000000",
    "revert_checked_at": 1756500012, "allowance_ok": true
  },
  "zether": { "from_schnorr": "0x7a…", "target_epoch": 1524096, "proof_bytes": 1376 },
  "beacon": { "block": 38102411, "hash": "0x5e…" },
  "exclusive": { "relayer_id": "0xE5…", "until": 1756500015 },
  "pow": { "algo": "keccak-hashcash", "bits": 20, "nonce": "0x1f8c…" },
  "hops": 0,
  "published_at": 1756500012,
  "bus_seq": 8814023,
  "hub": { "id": "hub.bamboo.vn", "sig": "0x…" }
}
```

Bon bo sung, va tai sao tung cai la bat buoc chu khong phai trang tri:

| Field | Vi sao khong the thieu |
|---|---|
| `meta_tx.innerGasLimit` | §04.6 dua no **vao struct duoc ky**. Khong co no trong envelope, relayer khong dung lai duoc digest → moi chu ky fail verify. Ban 1 thieu no la mot loi lam envelope **khong dung duoc**. |
| `sig_kind` (`eoa` / `erc1271`) | §04.4 chot dung `SignatureChecker.isValidSignatureNow` cho smart account. Relayer can biet truoc de (a) cong ~9 000 gas vao bao gia va (b) biet rang tinh hop le cua chu ky la **mutable** → phai re-simulate ngay truoc khi broadcast. |
| `zether.*` | Hub can `from_schnorr` de enforce single-flight (§5.4.3) va can `target_epoch` de tu het han intent khi epoch troi. Khong parse duoc tu `data` neu khong decode ABI — dung bat hub decode calldata tuy y. |
| `beacon.{block,hash}` | Chong grinding lottery. Xem §5.4.4(a). |

`hub.sig` — ban 1 co field nay nhung khong bao gio noi no ky cai gi. Chot:

```
hub_sig_payload = keccak256(
    "bamboo-hub/1" ‖ hub_id ‖ intent_id ‖ uint64(published_at)
                   ‖ uint64(beacon.block) ‖ beacon.hash
                   ‖ address(exclusive.relayer_id) ‖ uint64(exclusive.until))
```

Cong dung cu the, khong phai "de xac thuc": (1) relayer chung minh duoc no *duoc trao* exclusivity
khi tranh chap voi hub; (2) mot peer khong sua duoc `exclusive.*` khi re-publish; (3) khi hub cong
bo `beacon` sai (khong khop chain), bat ky ai cung chung minh duoc bang mot `eth_getBlockByNumber`.
Khoa cong khai cua hub nam trong `/policy` va trong `/peers`.

Quy tac versioning (ghi vao `/intents/v1/policy`):

| Loai thay doi | Hanh dong |
|---|---|
| Them field optional | Minor bump (`1.0` → `1.1`). Receiver **phai ignore field la** — khong reject. |
| Doi y nghia field, xoa field, doi cach tinh `intent_id` | Major bump (`bamboo-intent/2.0`) va **route moi** `/intents/v2/*`. Hai route chay song song >= 90 ngay. |
| Them chain / them `mode` bit | Khong bump. Chung la data, khong phai schema. `policy` liet ke gia tri hop le. |

Hub tu choi `spec` co major khong biet voi `400 UNSUPPORTED_SPEC` va tra ve danh sach major minh noi
duoc. Khong bao gio "co gang doan".

**Mot ngoai le phai ghi ro:** them mot `mode` bit **co** la thay doi schema doi voi *contract*, vi
§04.4 bat buoc `require(m.mode & ~MODE_KNOWN_MASK == 0)`. Mot intent mang bit moi se revert tren
contract cu. Nen quy tac day du la: them `mode` bit khong bump `spec`, nhung `/policy` **phai** cong
bo `mode_known_mask` **theo tung `verifying_contract`**, va relayer phai tu choi intent co
`mode & ~mask != 0` **truoc khi** simulate. Khong co dieu nay, mot dot nang cap contract khong deu se
bien thanh mot dot revert hang loat ma relayer chiu gas.

---

### 5.3. Relayer danh gia loi nhuan the nao — va con so that lam sap mo hinh

Cong thuc hien nhien:

```
cost_native  = (gas_intrinsic + innerGasLimit_charged) * effective_gas_price
revenue_nat  = metaTx.fee * FX(rewardToken -> native) + sponsor_quote
relay if:      revenue_nat >= cost_native * (1 + margin)     # margin mac dinh 0.30
```

Ban 1 viet `gas_limit_sim * effective_gas_price`. Do la **uoc luong sai phia an toan nguoc**: relayer
tra gas theo `gasUsed` thuc, khong theo `gas_limit`, **nhung** phai *co du* so du de dat `gas` =
`innerGasLimit + FLOOR_GAS` (§04.6). Hai con so khac nhau: cai thu nhat la chi phi, cai thu hai la
von luu dong. Mot relayer voi 5 xDAI khong the phat 200 tx song song moi tx dat `gas = 400_000` du
tong `gasUsed` chi la 30% — day la ly do thuc te khien relayer nho khong scale duoc, va no khong nam
o dau trong ban 1.

#### 5.3.1. Gas that su ton bao nhieu (uoc luong, co co so)

| Thao tac | Gas (uoc luong) | Co so |
|---|---|---|
| Intrinsic tx + calldata (~500 B non-zero) | ~29 000 | 21 000 + 16 gas/byte (EIP-2028) |
| `ECDSA.tryRecover` + EIP-712 hashing | ~4 500 | precompile `ecrecover` 3 000 + keccak |
| ...neu `sig_kind = erc1271` | +~9 000 | staticcall + logic vi (§04.4) |
| Ghi `meta_nonce` (SSTORE non-zero→non-zero, cold) | ~5 000 | 2 900 + 2 100 cold access (EIP-2929) |
| ERC-20 fee transfer toi `feeRecipient` | ~30 000–50 000 | tuy warm/cold cua slot dich |
| Inner call (ERC-20 transfer nghiep vu) | ~35 000–50 000 | |
| Guard / event / return cap | ~8 000 | §04.6 |
| **Tong meta-tx don gian** | **~112 000–146 000** | |
| **Zether `transferConfidential`, cau hinh 32/64 cua §03.9** | **~342 000–422 000** | §04.10, da cong envelope |

**Sua so voi ban 1:** ban 1 ghi Zether la "2 500 000–6 000 000 gas". Con so do la cua cau hinh
**128/128** ma §03.2 va §03.9 **da bac bo** (`MAX = 2^128 - 1` lam so du khong giai ma duoc). Cau
hinh da chot la `range_bits_value = 32`, `range_bits_balance = 64`, `scale_exponent = 2` — §03.3 cho
**~1.79 M gas** cho rieng phan verify+state, §04.10 cho **~342k–422k** cho toan bo loi goi ghep khi
verifier chay o cau hinh nay tren mot verifier duoc toi uu. Hai con so nay chenh nhau va **§03 la
nguon dung cho phan mat ma hoc**: neu verifier la `BulletproofsVerifier.sol` thuan Solidity thi
**~1.79 M**; con so 342k–422k cua §04.10 chi dat duoc voi **native precompile** (private chain) hoac
**Groth16/Baby Jubjub** (public chain). Ghi ca hai vao bang duoi va **dung cam ket mot con so cho ca
hai profile**.

Quy ra tien (gia dinh gia gas ghi ro, khong giau):

| Chain | Gas price gia dinh | Gia native | 130k gas | 1.79M gas (BP Solidity) | 400k gas (precompile / Groth16) |
|---|---|---|---|---|---|
| Gnosis xDAI | 1.5 gwei | $1.00 | **$0.000195** | **$0.00269** | **$0.00060** |
| Gnosis xDAI | 1.0 gwei (san toi thieu pho bien) | $1.00 | $0.000130 | $0.00179 | $0.00040 |
| Celo (fee currency cUSD) | ~5 gwei-equiv | $1.00 | ~$0.00065 | ~$0.0090 | ~$0.0020 |
| Ethereum L1 | 25 gwei | $3 000 | $9.75 | **$134** | $30 |

**Hai canh bao so lieu ban 1 khong co:**

1. **EIP-7623 (calldata floor).** Tren chain da bat Pectra, chi phi tx co san
   `21 000 + 40 × tokens` voi `tokens = zero_bytes + 4 × nonzero_bytes`. Voi mot Zether proof ~1.4 KB
   gan nhu toan non-zero: `tokens ≈ 5 600` → **san ≈ 245 000 gas**. Voi Zether (execution ≥ 400k) san
   khong rang buoc. Voi mot intent "re" mang calldata lon (vi du anchor mot merkle proof 2 KB roi
   khong lam gi), san **la** rang buoc va relayer se tra nhieu hon `gasUsed` mo phong. Relayer client
   phai tinh `max(gasUsed, floor)`; neu khong no se bao gia thap va lo dung o loai intent nay.
2. **Celo tinh phi bang fee currency co phu thu.** Tra gas bang cUSD di qua hook debit/credit cua
   validator, cong them **vai chuc nghin gas** moi tx so voi tra bang CELO, va tx phai la
   type `0x7b` (CIP-64) chu khong phai type 2. `blockchain.md` §10.2.1 goi chuan do la **CIP-52** —
   CIP-52 la ban de xuat cu; ban dang chay la **CIP-64** (them CIP-66 cho `maxFeeInFeeCurrency`).
   Phai kiem lai truoc khi code adapter Celo; sai o day nghia la relayer khong ky duoc tx nao.

#### 5.3.2. Sai so ky thuat trong note goc phai sua

`blockchain.md` §10.5.2 muc 3 viet ZKP verify ton "~180 000 – 250 000 gas". Con so do khong dung cho
Bulletproofs tren alt_bn128, o bat ky cau hinh bit nao.

- Sau EIP-1108, `ecMul` = 6 000 gas, `ecAdd` = 150 gas. Khong co precompile MSM cho BN254 (EIP-2537
  chi cho BLS12-381), nen **moi diem trong multi-exponentiation = 1 `ecMul` + 1 `ecAdd` + overhead
  staticcall ≈ 6 550 gas**. Khong co Pippenger, khong co windowing — precompile khong cho phep.
- §03.3 da lam bang day du: `32/32` → ~1.25 M; **`32/64` (cau hinh chot) → ~1.79 M**; `64/64` →
  ~2.10 M; `128/128` → ~3.79 M.
- 180k–250k chinh xac la chi phi cua **`ecPairing` 2–3 cap** (45 000 + 34 000 × k) cong vai `ecMul`
  to hop public input — tuc la **Groth16**, khong phai Bulletproofs. Dau vet nam ngay trong note: no
  vien dan `ecPairing` / EIP-197, ma **Bulletproofs khong dung pairing chut nao**.
- Ban 1 cua section nay noi "2.5M–6M" va suy ra tu `m*n = 512`. Do la cau hinh 128-bit da bi §03 bac
  bo. **Da sua.**

**He qua kien truc, khong phai chi tiet:** con so 180k–250k chi dat duoc bang **Groth16/PLONK** (co
trusted setup, mach co dinh, ElGamal tren Baby Jubjub). Neu giu Bulletproofs (khong trusted setup,
dung y dinh cua Zether), phai chap nhan ~1.79 M gas. §03.9 da chot: **Bulletproofs cho private
profile, Groth16 cho public profile**, `IZetherVerifier` pluggable. Section 05 chi can ket luan mot
dieu: **bao gia cua relayer phai doc `proofSystemId()` cua verifier**, vi cung mot intent Zether ton
1.79 M hay 400k gas tuy chain. Field `hints.gas_limit` **phai** phan anh dieu do, va hub phai tu choi
intent co `hints.gas_limit` lech > 25% so voi bao gia cua chinh no.

Tren Gnosis, 1.79 M gas = **$0.0018**. Hoan toan chap nhan duoc, va do chinh la ly do quyet dinh khoa
#4 (Gnosis truoc) va #5 (private truoc) la dung. Chi can dung viet 250k vao spec roi de contract
engineer phat hien o tuan thu 20.

#### 5.3.3. FX rate den tu dau, va dieu gi xay ra khi no chay

Ba nguon, xep theo do tin cay:

1. **`rewardToken` la stablecoin thanh khoan (USDC/USDT tren Gnosis) va native la xDAI.** FX ≈ 1.000
   ± 0.002. Do lech giua luc quote va luc inclusion (5 s) la **duoi 1 basis point**. Van de FX gan
   nhu bien mat. Day la ly do thuc su khien Gnosis/Celo la lua chon dung — khong phai vi re, ma vi
   **no xoa mot bien khoi bai toan cua relayer**.
2. **`rewardToken` la enterprise token khong co thi truong (Z-VND, loyalty point).** Khong co gia thi
   truong → khong duoc dung oracle. **Gia duoc dinh nghia boi cam ket mua lai cua issuer:**
   `SponsorshipPool.redemptionRate(token) -> wei native / token unit`, cong bo on-chain, co
   `validUntil` va chi doi duoc voi thong bao truoc N ngay. Day la mot *hop dong*, khong phai mot
   *gia*. Relayer doc no bang `eth_call` trong cung lan simulate — zero risk.
   **Ban 1 thieu mot vien gach:** `redemptionRate` chi co gia tri neu relayer **doi duoc** token ra
   native. Phai co `SponsorshipPool.redeem(token, amount)` tra xDAI theo dung `redemptionRate`, voi
   `dailyRedeemCap` va mot quy xDAI co so du kiem tra duoc on-chain. Khong co ham `redeem`, con so
   `redemptionRate` la mot loi hua, va mot relayer ly tri se chiet khau no ve 0. Bat buoc cong bo
   `redeemableBalance()` de relayer tu danh gia rui ro doi tac.
3. **Chainlink / DEX TWAP.** Chi dung khi (1) va (2) khong ap dung. Them do tre 1–2 block va rui ro
   oracle. Khuyen nghi: **khong ho tro trong v1.**

Bien dong giua quote va inclusion — cai that su chay **khong phai FX ma la gas price**:

- `metaTx.fee` da bi khoa trong digest tai thoi diem user ky. Khong ai bump duoc no ma khong xin chu
  ky moi.
- Neu base fee tang 3x giua luc ky va luc inclusion, intent don gian tro thanh khong sinh loi va
  **khong ai relay no**. No het han theo `expiry` va client ky lai voi fee cao hon. Do la thi truong
  hoat dong dung, khong phai loi.
- De client khong ky ra intent chet: hub cong bo fee floor theo chain trong `/intents/v1/policy`,
  cap nhat moi block. **Cong thuc cua ban 1 sai don vi:**
  `p90(gas_used_30d) * base_fee_now * 1.5` cho ra **wei native**, nhung `metaTx.fee` tinh bang
  **reward token**. Cong thuc dung:

```python
# dms_blockchain/lib/fee_floor.py — thuan Python, khong import odoo
def fee_floor_base(gas_p90: int, base_fee_wei: int, margin: float,
                   redemption_rate_wei_per_unit: int, mode_flags: int) -> int:
    """Tra ve so base-unit cua rewardToken. So nguyen, khong float."""
    risk = 1.5 if mode_flags & MODE_REQUIRE_SUCCESS else 1.0   # xem duoi
    native = int(gas_p90 * base_fee_wei * (1.0 + margin) * risk)
    return -(-native // redemption_rate_wei_per_unit)          # ceil div, khong lam tron xuong
```

Floor la mot bo ba `(chain_id, token, mode_flags)`, khong phai mot so cho moi chain. Ly do bat buoc,
ban 1 khong co: §04.6 chot `MODE_REQUIRE_SUCCESS (0x04)` = bubble revert = **relayer dot gas va
khong duoc gi khi inner call fail**. Mot intent bubble co rui ro cao hon han mot intent swallow, nen
**fee floor cua no phai cao hon**. Voi ty le inner-fail quan sat duoc `p`, bien loi nhuan yeu cau la
`margin' = (1 + margin)/(1 - p) - 1`. Voi `p = 5%`, `margin = 0.30` → `margin' = 0.37`. Voi `p = 20%`
→ `margin' = 0.63`. Hub phai do `p` theo `(to, selector)` va cong bo no; neu khong, relayer se tu do
va tu dat floor, va cac relayer se lech nhau.

**Bo sung `MODE_METERED_FEE (0x08)` — de nghi cu the, note goc khong co.**

> **Sua so voi ban 1:** ban 1 dat bit nay o `0x04`. `0x04` da la `MODE_REQUIRE_SUCCESS` trong §04.4.
> Va vi `mode` nam **trong** digest (§04.4), mot va cham bit khong gay loi bien dich — no gay ra
> **hai y nghia khac nhau cho cung mot chu ky**, tuc la mot lo hong xac thuc im lang. Doi sang `0x08`
> va nang `MODE_KNOWN_MASK` tu `0x07` len `0x0F`.

User ky `fee` nhu mot **tran**, contract chuyen `min(signedFee, gasUsed * conversionRate)` voi
`conversionRate` doc tu `SponsorshipPool`. Loi ich: user ky mot lan voi headroom 3x ma khong so bi
thu 3x; relayer van duoc bu du. Chi phi: +1 SLOAD cold (~2 100 gas) + mot phep nhan.

Ba chi tiet trien khai bat buoc, neu khong bit nay tu ban chan minh:

1. `gasUsed` khong doc duoc chinh xac tu ben trong tx. Phai do bang `gasleft()` truoc/sau va **cong
   mot hang so bu** cho phan chua do duoc (intrinsic + calldata + phan con lai cua frame):
   `charged = (gasStart - gasleft()) + GAS_OVERHEAD_CONST`, voi `GAS_OVERHEAD_CONST` do bang
   `forge test --gas-report` va cap nhat duoc qua governance. Sai so ±3 000 gas la chap nhan duoc;
   sai so khong bu la relayer luon lo ~30 000 gas.
2. `conversionRate` **phai** duoc doc **mot lan** va dua vao event, neu khong hai relayer doc hai gia
   tri khac nhau trong cung mot block la khong the chan duoc va se sinh khieu nai.
3. Bit nay **khong duoc** ket hop voi `bps_of_value` (§5.3.4) — hai co che dinh gia chong nhau.
   `require(!(mode & MODE_METERED_FEE != 0 && feeModel == BPS))`.

#### 5.3.4. Con so lam sap gia dinh "thi truong relayer tu duy tri"

Day la ket luan quan trong nhat cua section nay.

Tren Gnosis, chi phi gas cua mot meta-tx la **$0.00013–0.0002**. Mot bien loi nhuan 30% cho relayer
la **$0.00004–0.00006/tx**. Ngay ca khi fee dat gap 10 lan gas (relayer an ~$0.0018/tx):

| Muc tieu doanh thu relayer | So tx/thang can co | tx/phut lien tuc |
|---|---|---|
| $100/thang | 55 600 | 1.3 |
| $1 000/thang | 556 000 | 12.9 |
| $5 000/thang (1 ky su part-time) | 2 780 000 | 64 |

Va cot chi phi ma ban 1 khong ke: mot relayer that phai chay 1 VPS ($5–20/thang), 1 RPC archive/full
node hoac goi Alchemy ($0–50/thang), giu von xDAI (**~$50–200** de dat `gas` cho tx song song),
va **thoi gian nguoi** de xu ly khi no gay. Diem hoa von thuc te khong phai $0 — la **$30–70/thang**,
tuc **~17 000–39 000 tx/thang chi de khong lo**.

Khoi luong DMS thuc te (visit, settlement, claim) khong o gan cot phai. **Ket luan: tren chain co gas
re nhu Gnosis, phi bu gas khong the nuoi mot thi truong relayer doc lap.** Ai do se van relay, nhung
khong phai vi loi nhuan — ma vi ho co ly do khac (la distributor trong he thong, la issuer, la doi
tac).

Ba loi thoat, phai chon **truoc khi** viet contract vi no thay doi struct:

| `fee_model` | Cong thuc | Khi nao dung |
|---|---|---|
| `gas_reimburse` | `fee = gas * rate * (1+margin)` | Chain re + relayer la consortium member. Mac dinh. |
| `flat` | `fee = const` theo loai intent | Loyalty point redeem, UX de giai thich |
| `bps_of_value` | `fee = value * bps` (10 bps tren settlement $2 000 = **$2**) | **B2B settlement.** Day la cho duy nhat co bien loi nhuan that. |

`bps_of_value` yeu cau contract biet `value`. Voi Zether, `value` bi ma hoa → khong the tinh bps
on-chain. Giai phap ly thuyet: `fee` van la mot so cong khai do client tinh, va ZKP chung minh
`fee * 10000 - v * bps >= 0` bang mot range proof bo sung. Chi phi thuc: mot range proof 32-bit nua
trong cung transcript → theo bang §03.3, **+~80 diem MSM ≈ +525 000 gas** (khong phai "+25%" nhu ban
1 uoc). Tren Gnosis do la +$0.0005 — re — nhung no **cong ~0.1–0.3 s vao thoi gian prove tren
Android** (§03.8), va thoi gian prove la thu dang eo co cua Zether, khong phai gas.

**Khuyen nghi: `flat` cho Zether v1.** Va noi thang he qua thuong mai: neu mo hinh doanh thu cua
relayer la `bps_of_value`, thi **luong tien co bien loi nhuan lai chinh la luong tien phai bi ma
hoa**, va hai muc tieu do keo nguoc nhau. Do la mot cau hoi cho nguoi, khong phai cho kien truc —
xem `open_questions`.

---

### 5.4. Front-running: tai sao no khong sao, va cho nao thi no la van de

#### 5.4.1. Cho khong sao — va tai sao

O `MODE_OPEN`, payload da day du va tu uy quyen. Bat ky ai cung `msg.sender` duoc. Cai goi la
"front-run" o day la:

- `to`, `data`, `amount`, `fee`, `expiry`, `batchId`, `batchNonce`, `innerGasLimit`, `mode` **deu nam
  trong digest** → khong sua duoc mot byte.
- `relayer` va `feeRecipient` **khong nam trong digest** (canonical zeroing, §04.4) → ke "cuop" chi
  thay doi duoc *ai duoc tra tien*, va no dang tra cho chinh no bang cach chiu gas.
- Ket qua on-chain ma user nhan duoc la **byte-identical** bat ke ai submit.

Voi Zether `withdraw`, `recipient` da bi bam vao Fiat-Shamir challenge (note §10.5.3 muc 5, dung) →
khong doi duoc. Voi `transferConfidential`, `toSchnorrAddress` nam trong ciphertext → khong doi duoc.

**Vi vay: user hoan toan bang quan ve ket qua giao dich.** Moi co che o §5.4.4 ton tai *chi* de bao
ve bien loi nhuan cua relayer. **Nhung "bang quan ve ket qua" khong dong nghia voi "bang quan" —
xem §5.4.5, cai ban 1 bo sot hoan toan.**

#### 5.4.2. Cho la van de: N relayer dua nhau, 1 thang

Khi N relayer cung broadcast mot intent:

- 1 tx thanh cong, N-1 tx revert o buoc check dau tien. §04.5 chot thu tu check: **nonce truoc
  (SLOAD 2 100), roi expiry, roi mode, roi chu ky**. Do la mot quyet dinh kinh te co chu dich: no lam
  ke thua cuoc mat it nhat.
- Tx revert **van tra gas**: intrinsic 21 000 + calldata ~7 000 (calldata van duoc tinh du) + SLOAD
  nonce 2 100 ≈ **~24 000–30 000 gas** ≈ **$0.000024–0.000045** tren Gnosis (1–1.5 gwei).

Gas lang phi tuyet doi la khong dang ke. **Cai giet mo hinh la bien loi nhuan ky vong, khong phai
gas.**

Voi `fee_net = $0.0018` (fee tru gas cua ke thang), `revert_cost = $0.000024`, N relayer dong deu:

```
EV(N) = (1/N) * fee_net - ((N-1)/N) * revert_cost
```

| N | EV/tx | So voi N=1 |
|---|---|---|
| 1 | $0.001800 | 100% |
| 2 | $0.000888 | 49% |
| 3 | $0.000584 | 32% |
| 5 | $0.000341 | 19% |
| 10 | $0.000158 | **8.8%** |
| 20 | $0.000067 | 3.7% |
| **76** | **~$0.000000** | **0%** |

**Con so ban 1 bo sot, va la con so quan trong nhat cua muc nay:** diem can bang gia nhap tu do
(free entry, EV = 0) la

```
N* = 1 + fee_net / revert_cost = 1 + 0.0018 / 0.000024 ≈ 76
```

Tai `N*`, **toan bo phi cua user bi dot thanh gas lang phi**: `(N*-1) × revert_cost = fee_net`. Day
la ket qua co dien cua priority gas auction (rent dissipation) va no noi mot dieu manh hon bang tren:
mot cuoc dua khong dieu phoi khong chi lam relayer ngheo di, no **chuyen 100% phi cua user thanh rac
tren chuoi**. Ly do duy nhat thuc te N khong len den 76 la chi phi co dinh cua relayer (§5.3.4:
$30–70/thang) va variance — tuc la mang **tu on dinh o mot so it relayer lon**, chinh cai tap trung
hoa ma no dinh tranh.

Ket qua chuan cua mot cuoc dua khong dieu phoi: relayer nho rut lui, con lai 1–2 relayer lon.
Soft-exclusivity (§5.4.4a) khong phai mot tinh nang "hay co" — no la thu duy nhat giu duoc **> 2
relayer** trong mang.

#### 5.4.3. Van de nghiem trong hon: Zether nonce khong the dua

Note khong noi ra dieu nay. `zetherNonce(fromSchnorrAddress)` **duoc bam vao Fiat-Shamir challenge
cua ZKP**, va §04.10 con them `targetEpoch` vao ciphertext struct. Hai intent Zether dong thoi tu
cung mot `schnorrAddress`:

- Intent thu hai khong chi bi *reorder* — **proof cua no tro thanh vo hieu vinh vien**, phai sinh lai
  proof. Chi phi prover theo §03.8: **0.2–0.5 s** (Android ARM64 native) den **0.8–2.5 s** (WASM).
  Ban 1 ghi "200–800 ms" — thap hon thuc te tren nen tang ma nguoi dung DMS thuc su dung.
- `batchId` 2-D nonce cua EIP-1776 **khong cuu duoc**, vi diem serialize nam o tang Zether, khong
  phai tang envelope.

**Va day la con so ban 1 khong tinh:** ke thua trong mot cuoc dua Zether **khong** revert o 24 000
gas. Neu hai intent *khac nhau* cua cung mot schnorr address cung duoc broadcast, envelope nonce cua
chung **khac nhau** nen ca hai deu qua tang envelope; cai thu hai chay **het** verify Bulletproofs
roi moi fail o `zetherNonce`. Chi phi that: **~1.79 M gas ≈ $0.0018** — bang dung ca khoan fee.
**Va cham Zether dat gap 75 lan va cham thuong.** Do la ly do single-flight khong phai toi uu hoa
ma la bat buoc.

**Rang buoc bat buoc:** intent bus phai enforce **single-flight theo `from_schnorr_address` cho moi
intent Zether**.

**Sua ky thuat Odoo so voi ban 1.** Ban 1 dua ra hai lua chon nhu the ca hai deu viet duoc bang
`models.Constraint`. Khong phai:

- `models.Constraint(definition, message)` sinh ra `ALTER TABLE … ADD CONSTRAINT <name> <definition>`.
  Mot `EXCLUDE (…) WHERE (…)` **la** mot table constraint hop le → viet duoc, **nhung** can extension
  `btree_gist` (vi toan tu `=` tren `varchar` khong co trong GiST mac dinh), va `CREATE EXTENSION`
  can quyen superuser tren Postgres. Tren stack nay do la mot phu thuoc van hanh, khong phai mot dong
  code.
- Mot **partial unique index** khong phai table constraint. `UNIQUE (col) WHERE …` **khong** la SQL
  hop le trong `ADD CONSTRAINT`. Khong viet duoc bang `models.Constraint`.

Cach dung, khong can extension:

```python
class BlockchainMetatx(models.Model):
    _inherit = 'blockchain.metatx'

    def init(self):
        # Partial unique index: KHONG phai table constraint, nen KHONG dung models.Constraint.
        self.env.cr.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS blockchain_metatx_zether_inflight_uniq
            ON blockchain_metatx (from_schnorr_address)
            WHERE from_schnorr_address IS NOT NULL
              AND metatx_state IN ('published', 'claimed', 'broadcast', 'mined')
        """)
```

Kiem chung bang SQL, dung tin code (CLAUDE.md §5 muc 2):
```sql
SELECT indexname, indexdef FROM pg_indexes
 WHERE tablename = 'blockchain_metatx' AND indexname LIKE '%zether%';
```

Intent Zether tiep theo cua cung account nam o `state = 'queued'` cho den khi cai truoc `final` hoac
`expired`. Day la mot **head-of-line block co that** ma kien truc 2-D nonce khong xoa duoc — phai noi
ro trong tai lieu, khong duoc ban 2-D nonce nhu la "loai bo hoan toan head-of-line blocking" cho
luong Zether.

**Tran thong luong ma ban 1 khong tinh.** Single-flight + epoch 25 s (Δ = 5 block × 5 s tren Gnosis)
= **toi da 1 confidential tx / 25 s / schnorr address = 3 456 tx/ngay/address**. Mot vi treasury
tra 500 distributor mot lan/thang thi khong sao. Mot vi treasury tra 5 000 outlet moi ngay thi
**vuot tran**. Duong ra, chon truoc:

```
K_addresses = ceil(peak_tx_per_second * epoch_seconds * safety)
# vi du: 2 tx/s dinh diem, epoch 25 s, safety 1.5  ->  K = 75 schnorr address
```

Sharding vi treasury thanh K `schnorrAddress` la mien phi ve mat giao thuc (registry la singleton,
`register()` mot lan moi address) nhung **khong** mien phi ve mat ke toan: so du bi chia nho va
phai co mot job re-balance. Ghi vao `open_questions`. Mot cach tranh: gop nhieu nguoi nhan vao mot
`transferConfidential` **khong lam duoc** trong Zether nguyen ban (mot receiver moi tx) — nen sharding
la duong duy nhat.

#### 5.4.4. Cac bien phap, xep theo thu tu nen dung

**(a) Soft-exclusivity window — khuyen nghi lam mac dinh cho intent thuong, TAT cho Zether.**

Hub gan `exclusive.relayer_id` va `exclusive.until = published_at + W` (W mac dinh **3 s** tren
Gnosis ≈ 0.6 block; **W = 0 cho `is_zether`**, ly do o §5.1.1). Nguoi thang duoc chon **tat dinh**,
nen moi hub tinh ra cung ket qua ma **khong can round-trip nao**.

**Hai lo hong cryptoeconomic trong ban 1, ca hai deu lam co che nay vo dung:**

**Lo hong 1 — `sqrt(stake)` khong chong sybil, no *thuong* sybil.** Ban 1 viet
`weights = isqrt(stake) * reputation` voi ly do "mot ca voi 100x stake chi co 10x co hoi". Nhung voi
trong so can bac hai, tach stake `S` thanh `k` danh tinh cho ra tong trong so
`k · sqrt(S/k) = sqrt(k) · sqrt(S)` — tuc **nhan trong so len `sqrt(k)` lan, mien phi**. Voi `k = 100`
danh tinh, mot ca duoc **10x** trong so so voi khi trung thuc. Trong so can bac hai chi co y nghia
khi co mot registry danh tinh duy nhat (do la tien de cua quadratic funding); o day khong co.

**Fix:** trong so **tuyen tinh** (`k · S/k = S`, sybil-neutral) × reputation, cong mot **min bond**
`B` (chan so danh tinh o `S/B`) va mot **tran ty trong** ap thang vao dieu minh thuc su muon:

```python
# dms_blockchain/lib/lottery.py — thuan Python, khong import odoo, pytest duoc
CAP_SHARE = 0.20          # khong ai duoc qua 20% so lan boc
REP_FLOOR = 0.10          # relayer moi van co cua vao

def pick_exclusive(intent_id: bytes, beacon_hash: bytes, snapshot_root: bytes,
                   relayers) -> str:
    """relayers: [(relayer_id, stake_base:int, reputation:float)], da sap xep theo relayer_id.
    Tat dinh: moi hub tinh ra cung ket qua tu cung dau vao."""
    if not relayers:
        return ''
    raw = [s * max(r, REP_FLOOR) for _, s, r in relayers]
    total = sum(raw)
    if total <= 0:
        raw = [1] * len(relayers)          # khong im lang chon relayers[0]
        total = len(relayers)
    cap = int(total * CAP_SHARE)
    if len(relayers) > 1 / CAP_SHARE:      # tran chi co nghia khi du nguoi
        raw = [min(w, cap) for w in raw]
        total = sum(raw)
    draw = int.from_bytes(
        keccak256(intent_id + beacon_hash + snapshot_root), 'big') % total
    acc = 0
    for (rid, _, _), w in zip(relayers, raw):
        acc += w
        if draw < acc:
            return rid
    return relayers[-1][0]
```

**Lo hong 2 — nguon ngau nhien cua ban 1 bi nguoi ky *grind* duoc, mien phi.** Ban 1 boc bang
`keccak256(intent_id + snapshot_root)`. `intent_id` la EIP-712 digest, phu thuoc `batchId`, va
`batchId` la **256 bit do client tu chon tu do** (§04.3). Client thu mot `batchId` moi = **2 phep
keccak**, khong can ky. Voi 50 relayer, ky vong **~50 lan thu ≈ vai micro-giay** de dat exclusivity
vao dung relayer minh muon. Chu ky chi can ky **mot lan** o cuoi. Tuc la: mot relayer thong dong voi
user co the **luon** tu trao exclusivity cho minh, va lottery tro thanh trang tri.

**Fix:** dua vao mot **beacon khong doan duoc tai thoi diem ky**. Re nhat va du: block hash cua head
tai luc **hub nhan** intent.

```
draw_seed = keccak256(intent_id ‖ beacon.hash ‖ snapshot_root)
```

Rang buoc de peer kiem duoc: `beacon.block` phai nam trong **8 block gan nhat** so voi head cua hub
nhan, va `beacon.hash` phai khop `eth_getBlockByNumber` cua chinh peer do. Hub goc dien `beacon`, ky
no trong `hub.sig`, peer verify. Nguoi ky khong the grind vi `beacon.hash` chua ton tai luc no ky.
Chi phi: 0 gas, 1 RPC call ma hub von da co (no cache head).

`snapshot_root` cung nen bo phan "hub ky va cong bo moi gio" cua ban 1 va thay bang mot dinh nghia
tat dinh hon: **tap relayer active doc tu `RelayerRegistry` tai `beacon.block`**, sap theo dia chi,
`snapshot_root = keccak(abi.encode(sorted_addresses, stakes))`. Moi hub tu tinh ra cung mot gia tri
tu cung mot block — **khong con cua so chuyen giao 30 s va khong con hai hub chon hai nguoi thang**.
Ban 1 phai xu ly cua so do bang cach "chap nhan ca hai snapshot", ma chap nhan ca hai chinh la tao ra
N = 2 dung vao luc te nhat.

Cac tinh chat con lai giu nguyen tu ban 1:

- **Khong enforce on-chain.** Enforce on-chain nghia la `MODE_RESTRICT_RELAYER`, va nhu vay mat luon
  duong lui khi relayer duoc chon chet may. Enforce bang reputation.
- Sau `until`, intent tro thanh free-for-all that su. Tren Gnosis: `W = 3 s` chi hy sinh <1 block
  latency o truong hop xau nhat.

Hieu qua dinh luong: EV cua relayer tro ve ~85–95% muc N=1 (mat phan nho vi intent bi bo lo phai doi
qua W), thay vi 19% o N=5.

**(b) Reputation.** `blockchain.relayer.reputation_score` (§10.4.5 da khai bao, computed store=True,
**moi nhanh phai gan gia tri**), EWMA voi decay 0.98/ngay:

```
score = 0.6 * fill_rate + 0.3 * latency_score + 0.1 * uptime
fill_rate     = inclusions_confirmed / claims_granted     # nhan exclusivity roi khong lam -> tut
latency_score = clamp(1 - (median_latency_ms - 2000) / 8000, 0, 1)
```

**Sua so voi ban 1, quan trong ve mat cong bang:** `fill_rate` phai dem **`inclusions_confirmed`**
(tx co mat trong block, bat ke `innerSuccess`), **khong** dem thanh cong nghiep vu. O che do swallow
mac dinh (§04.6), `innerSuccess = false` van la mot tx thanh cong va relayer **da lam dung viec cua
no** — no ban blockspace, khong ban ket qua nghiep vu. Tru diem relayer vi mot inner call revert la
phat sai nguoi, va no se lam moi relayer tu choi intent cua nhung target hay revert. Ty le
inner-fail thuoc ve **`(to, selector)`**, khong thuoc ve relayer, va no la dau vao cua fee floor
(§5.3.3), khong phai cua reputation.

Relayer bo cuoc 3 lan lien tiep → `reputation_score` ve gan `REP_FLOOR` trong ~5 intent → hau nhu
khong duoc chon nua. Do la hinh phat du cho mot vu $0.005.

**(c) Commit-reveal — phan tich va loai bo cho v1.**

Commit-reveal (relayer commit `keccak(intent_id ‖ salt ‖ addr)`, reveal o block sau) them **it nhat
1 block (5 s) va 1 tx (~25k gas, gap 20% chi phi relay)**, va **khong ngan duoc hub operator ro ri
intent** — ma hub la ke duy nhat co the front-run som nhat. No giai quyet dung bai toan sai.

Gia tri that cua commit-reveal chi xuat hien khi **noi dung intent co MEV** (swap, liquidation).
EIP-1776 intent cho DMS (chuyen token, ghi nhan settlement, redeem point) khong co MEV **voi mot
ngoai le da xac dinh — xem §5.7: `dailyCap` cua sponsorship pool la mot tai nguyen tranh chap va do
la mot be mat MEV that.** Bien phap dung o do la per-relayer sub-cap, khong phai commit-reveal.

**Loai bo. Ghi vao spec la co the them sau bang `mode` bit `0x10`** (khong phai `0x08` nhu ban 1
viet — `0x08` da bi `MODE_METERED_FEE` lay o §5.3.3) **neu them intent type co MEV.**

**(d) Priority by stake ngoai lottery.** Khong can. Stake da vao lottery weight o (a). Them mot co
che uu tien thu hai la chong cheo.

#### 5.4.5. Cai ban 1 bo sot hoan toan: intent bus la mot kenh ro ri du lieu

`MODE_OPEN` nghia la **moi relayer, va moi nguoi goi duoc `/pending`, doc duoc toan bo calldata**
truoc khi no len chuoi. Ban 1 ket luan "user hoan toan bang quan" — dung ve *ket qua giao dich*, sai
ve *bao mat thuong mai*, va bao mat thuong mai la ly do ton tai cua ca chuong Zether.

| Luong tien | Cai gi ro ri qua bus | Muc do |
|---|---|---|
| Zether `transferConfidential` | `fromSchnorr`, `toSchnorr`, `metaTx.fee` cong khai. **So tien va so du: khong.** | Chap nhan duoc — dung thiet ke Zether |
| ERC-20 transfer thuong (B2B settlement) | **Toan bo**: nguoi tra, nguoi nhan, so tien, token, thoi diem | **Nghiem trong tren private profile** |
| Loyalty redeem | Dia chi outlet, so diem | Thap |
| Anchor hash | Chi hash | 0 |

**Diem chet nam o profile `private`.** Muc dich cua chain rieng la giu du lieu trong vanh dai. Mot
intent bus cong khai la **duong duy nhat du lieu do di ra ngoai**, va no di ra **truoc** khi len
chuoi. Ban 1 khong nhac den dieu nay o bat ky dau.

Quy tac chot, ghi thang vao §5.0:

1. `chain_profile = private` → bus **chi** nghe tren mang noi bo, mTLS bat buoc ca hai chieu,
   **khong federation**, `/pending` yeu cau client cert. Mot dong nginx, khong phai mot tinh nang.
2. `chain_profile = public` + luong tien co so tien nhay cam → **bat buoc Zether**, hoac bat buoc
   `MODE_RESTRICT_RELAYER` toi mot relayer da ky NDA. Khong duoc de mot B2B settlement $200 000 di
   qua `MODE_OPEN` tren public bus "vi dang nao no cung len chuoi" — no len chuoi **sau**, va truoc
   do no la thong tin giao dich chua thuc hien, tuc la co gia tri MEV/canh tranh.
3. Odoo phai enforce dieu 2, khong phai con nguoi:
   `blockchain.chain.max_public_intent_value_base` (Char uint256). Builder tu choi publish
   `MODE_OPEN` len public bus khi `amount > nguong` va `not confidential`. Mot `_check` don gian, va
   no la thu duy nhat dung giua mot ky su voi voi mot su co bao chi.

Mot he qua thu hai: `hints.fee_value_native` va `hints.gas_limit` **ro ri hinh dang cua intent** ngay
ca khi calldata bi cat. Tren private profile do khong quan trong; tren public profile no la ly do
`fields=summary` (§5.1.2) khong duoc chua `data`.

---

### 5.5. Sybil resistance va DoS

Chi phi tao mot intent gia = mot chu ky ECDSA ≈ 50 µs. Chi phi de hub xac minh no *that su* la tien:
mot `eth_call` simulate ton **15–40 ms** tren local node (**60–150 ms** neu la Zether, vi node phai
verify Bulletproofs). Ty le tan cong **~500:1**, len **~3 000:1** voi Zether. Day la lo hong DoS thuc
su, khong phai o tang mang.

Hang rao theo thu tu, re truoc:

| Tang | Co che | Chi phi cho attacker | Chi phi cho hub | Dat o dau |
|---|---|---|---|---|
| 0 | Rate limit theo IP (`60 req/min`), body cap 32 KB | Can botnet | ~0 | **nginx `limit_req`**, khong phai Odoo |
| 1 | Rate limit theo `meta_tx.from` (`10 intent/phut`, `100/gio`) | Can nhieu dia chi | 1 Redis INCR | Redis (khong phai bien module) |
| 2 | Sanity offline: `expiry` trong tuong lai va `<= max_expiry`, `fee >= fee_floor(chain, token, mode)`, `to` trong allowlist, `tokenContract` trong allowlist, `mode & ~mask == 0`, chu ky recover ra dung `from`, `innerGasLimit <= chain.max_inner_gas` | ~0 | ~1 ms | Python thuan |
| 3 | **Gate ai duoc simulate**: `from` phai (a) co `nonce > 0` on-chain, HOAC (b) co `sponsor.policy_id` hop le, HOAC (c) **JWT hop le tu `bamboo_token_auth`**, HOAC (d) kem PoW hashcash 20 bit | (d) ≈ 1M keccak ≈ **0.3–1 s CPU** | ~0.3 ms verify | Python + Redis |
| 4 | `eth_call` simulate; drop neu revert | — | 15–150 ms | RPC pool |
| 5 | Chia se ban list giua hub qua `/intents/v1/peers` (feed ky) | — | ~0 | cron |

**Bon sua so voi ban 1:**

1. **Tang 0 khong duoc lam trong Odoo.** Moi Odoo worker la mot process rieng; mot bo dem trong bien
   module dem sai theo he so `workers`. Rate limit theo IP thuoc ve **nginx** (`limit_req_zone
   $binary_remote_addr zone=intents:10m rate=60r/m;`). Rate limit theo `from` (tang 1) can trang thai
   chia se → **Redis**, cung cum ma §06 da dung cho nonce manager. Ghi ro de nguoi trien khai khong
   viet mot decorator vo dung.
2. **Them lua chon (c): JWT.** CLAUDE.md §6 chot rang client goi backend qua `bamboo_token_auth` JWT.
   Mot user DMS da dang nhap **da la** mot danh tinh — bat no lam PoW la vo nghia. PoW chi danh cho
   nguoi la hoan toan.
3. **PoW 20 bit qua nang cho mobile.** 1M keccak trong JS thuan tren Android tam trung ≈ **200k
   hash/s → 5 s**, va nguoi dung dang dung mot app ban hang. Neu buoc phai co PoW cho mobile: ha
   xuong **16 bit** (~65k keccak ≈ 0.3 s) va bu bang tang 1 chat hon. Nhung dung nhat la: mobile luon
   di duong (c), khong bao gio cham PoW.
4. **Storage DoS — loai ban 1 khong nhac.** Mot botnet 10 000 dia chi × 10 intent/phut = **1 667
   intent/s**. Chi phi ecrecover (`coincurve`) ≈ 50–100 µs → 0.17 s CPU/s: khong sao. Chi phi **ghi**
   moi la van de: 1 667 row/s × ~1.5 KB = **2.5 MB/s = 216 GB/ngay**. **Quy tac: khong persist gi
   truoc tang 3.** Intent chua qua tang 3 song trong Redis voi `TTL = expiry - now`, key
   `intent:pending:<intent_id>`. Chi khi qua tang 4 moi `create()` mot row `blockchain.metatx`.

**Nang luc thuc te:** mot hub worker Odoo (`auth='public'`, `save_session=False`, mot query index) ≈
**150–400 req/s**; simulate la nut co chai that: **~25–60 simulate/s/worker** (khong Zether),
**~7–16/s** (Zether). 4 worker ≈ 100–240 simulate/s. Mot flood 10 000/s **phai bi chan o tang 0–3**,
khong bao gio den tang 4. PoW 20 bit dua tran cua mot may tan cong don ve ~1–3 intent/s — du.

**Luu luong luu tru o che do binh thuong:** 1 000 intent/ngay (khoi luong DMS thuc te) × ~2 KB =
**2 MB/ngay ≈ 730 MB/nam**. Khong can partition. Chinh sach giu:

| Trang thai | Giu | Ly do |
|---|---|---|
| `final`, `reverted` | vinh vien | vet doi soat, la bang chung |
| `expired`, `superseded` | 30 ngay | chi de debug |
| chua qua tang 3 | khong bao gio ghi DB | Redis TTL |

PoW bits la config (`ir.config_parameter` `blockchain.intent.pow_bits`), tang tu dong khi hang doi
simulate > 500. **Tat hoan toan khi `chain_profile = private`.**

Mot loai DoS thu hai it ai nghi den: **intent hop le nhung co chu y khong sinh loi** (fee = 1 wei).
Chung khong ton simulate neu tang 2 kiem `fee >= fee_floor` truoc. Do la ly do tang 2 phai dung truoc
tang 4.

Va mot loai thu ba, re nhat cho ke tan cong, ban 1 khong co: **rut `approve` sau khi da publish.**
Fee duoc thu bang `safeTransferFrom(m.from, feeRcp, m.fee)` (§04.6) nen no can allowance cua `from`
cho forwarder. Ke tan cong publish 100 intent hop le, cho relayer simulate va broadcast, roi
`approve(forwarder, 0)` trong cung block. Moi tx broadcast revert; relayer mat gas; ke tan cong mat
**mot** tx. Ty le thiet hai 100:1. Bien phap:

- `hints.allowance_ok` do hub kiem o tang 4 (mot `eth_call allowance`) — chan truong hop vo tinh.
- **`blockchain.relayer` co `origin_grief_score` theo `meta_tx.from`**, khong phai theo relayer: 3 lan
  revert do allowance trong 24 h → `from` do bi day ve tang 3 lua chon (d) (PoW) va bi ha
  `max_inflight` xuong 1.
- Duong ban chat: uu tien `ERC-2612 permit` / Permit2 nhung noi target ho tro, khi do allowance nam
  **trong** chinh tx va khong rut duoc. Ghi vao `open_questions` vi no cham vao thiet ke token (§01).

---

### 5.6. Staking va slashing: lam it hon note goc de nghi

Cau hoi dung phai hoi truoc: **relayer thuc su co the lam gi sai?**

| Hanh vi | Co the khong | Thiet hai | Can slashing? |
|---|---|---|---|
| Sua noi dung intent | **Khong** — digest chan | 0 | Khong |
| An cap tien | **Khong** — `feeRecipient` la thu duy nhat no doi duoc, va no dang tra cho chinh no | 0 | Khong |
| Doi `recipient` cua Zether withdraw | **Khong** — bam vao Fiat-Shamir | 0 | Khong |
| Nhan exclusivity roi khong submit | Co | Tre `W` = 3 s | **Khong** — reputation la du |
| Kiem duyet (nhan intent, khong relay, khong bao) | Co | Tre den khi hub re-publish sau `W` | Khong — hub tu re-publish |
| Submit tx biet chac se revert de dot subsidy | Co | **Chi khi subsidy tra theo *lan thu*** | **Khong — sua thiet ke: subsidy chi tra khi inclusion thanh cong** |
| Claim subsidy cho intent minh khong relay | **Khong** — pool kiem `msg.sender == relayer` trong chinh tx | 0 | Khong |
| **Cap `gas` thap co y de inner call OOG roi van an fee** (swallow mode) | **Khong** — §04.6 co `require(gasleft() > innerGasLimit/63)` sau `call` | 0 | Khong — da chan on-chain |
| **Doc intent tren bus roi khong relay, chi de thu thap du lieu thuong mai** | **Co** | Ro ri thong tin (§5.4.5) | **Khong slashing** — chan bang quyen truy cap bus, khong bang tien |
| **Rut `dailyCap` cua sponsorship pool truoc doi thu** | Co | Doi thu mat gas mot tx | Khong — sua thiet ke: per-relayer sub-cap (§5.7) |

**Ket luan: v1 khong co slashing tu dong.** Xay mot he adjudication on-chain (challenge period, fraud
proof, arbiter) cho mot khieu nai tri gia $0.005 la vo ly ve mat kinh te — chi phi challenge tx da
lon hon thiet hai.

Cai `RelayerRegistry` **van can**, nhung voi mot cong viec khac: **stake la trong so cho lottery o
§5.4.4(a) va la hang rao sybil cho exclusivity**, khong phai bao chung hanh vi.

```solidity
interface IRelayerRegistry {
    function bond(uint256 amount) external;             // stake token issuer chi dinh
    function requestUnbond() external;                  // bat dau UNBOND_PERIOD = 7 days
    function withdrawBond() external;                   // sau 7 ngay
    function stakeOf(address relayer) external view returns (uint256);
    function isActive(address relayer) external view returns (bool);
    function activeSetAt(uint256 blockNumber)           // cho snapshot_root tat dinh (5.4.4a)
        external view returns (address[] memory, uint256[] memory);
    function MIN_BOND() external view returns (uint256);
    event Bonded(address indexed relayer, uint256 amount, uint256 total);
    event UnbondRequested(address indexed relayer, uint64 readyAt);
}
```

Bon quyet dinh tham so, ban 1 de trong:

| Tham so | Gia tri | Ly do dinh luong |
|---|---|---|
| `UNBOND_PERIOD` | **7 ngay** | De mot ke tan cong khong the bond → chiem lottery mot gio → rut ngay. |
| `MIN_BOND` | **tuong duong $500** | Chan so danh tinh o `stake/500`. Voi trong so tuyen tinh (§5.4.4a) sybil khong loi, nen `MIN_BOND` chi de chong spam registry, khong can cao. Cao hon la mot rao can gia nhap that su va no nguoc voi §5.9. |
| Token de bond | **native cua chain (xDAI)**, khong phai enterprise token | Bond bang chinh token cua issuer nghia la issuer co the in ra stake. Do la mot "stake" khong co y nghia kinh te. |
| Ai giu bond | Contract, khong ai rut duoc trong v1 | Khong co `slash()` → khong co ai co quyen tich thu → khong can governance. **Day la mot tinh nang.** |

Khong co ham `slash()` trong v1. Duong nang cap: them `slash(address, uint256, bytes proof)` chi khi
xuat hien mot hanh vi co thiet hai > $100/vu — chua ton tai. **`activeSetAt` la ham bat buoc phai co
tu dau** (khong phai nang cap sau), vi §5.4.4(a) can no de moi hub tinh ra cung mot `snapshot_root`;
neu registry khong luu lich su theo block thi phai them mot checkpoint array, va do la mot thay doi
storage layout — dat neu lam sau.

**Truong hop `chain_profile = private`: khong co registry, khong co bond.** Tap relayer la mot
allowlist trong `blockchain.relayer.allowlist_state` do admin duyet, va lottery la round-robin tinh
theo `intent_id % n`. Dung deploy `RelayerRegistry.sol` len private chain "de sau nay khoi doi" —
mot contract khong lam gi la mot be mat tan cong khong lam gi.

---

### 5.7. Sponsorship escrow pool va cach relayer doi tro cap

Note (§10.1 muc 1.b) mo ta "ky quy san mot be tai tro ... hoac tra phi dich vu off-chain/on-chain
dinh ky". **Ve "dinh ky/off-chain" la mot cai bay:** mot relayer ly tri se khong ung gas neu khoan bu
chi la loi hua se thanh toan cuoi thang. No phai **atomic voi lan thuc thi**.

Lai co mot rang buoc ky thuat cung: **contract khong doc duoc event log.** Moi thiet ke "relayer nop
batch receipt hang tuan, pool tu xac minh" deu **khong the trien khai** ma khong co attestor ky ngoai
chuoi (tuc la tap trung, tuc la mat diem cua ca mo hinh).

**Thiet ke duy nhat chay duoc: thanh toan inline trong chinh tx.**

```solidity
interface ISponsorshipPool {
    struct Policy {
        address rewardToken;      // token dung de tra relayer
        uint256 maxFeePerIntent;
        uint256 dailyCap;         // reset theo block.timestamp / 1 days
        uint256 dailySpent;
        uint256 perRelayerDailyCap;   // *** THEM SO VOI BAN 1 *** chong dua rut cap
        bytes32 targetsRoot;      // merkle root cua (to, selector) duoc tai tro
        uint64  validUntil;
        bool    requireRegistered;
    }

    /// @notice Relayer goi truoc bang eth_call de biet chac se duoc tra bao nhieu.
    ///         Dung view - no phai chay duoc trong cung lan simulate.
    function quote(bytes32 policyId, bytes32 intentId, address relayer, address to,
                   bytes4 selector, uint256 gasEstimate) external view returns (uint256 payout);

    /// @notice Chi executor cua EIP-1776 duoc goi, trong chinh tx thuc thi meta-tx.
    function settle(bytes32 policyId, bytes32 intentId, address relayer,
                    address to, bytes4 selector, bytes32[] calldata targetProof,
                    uint256 gasUsed) external returns (uint256 paid);

    /// @notice Doi rewardToken (enterprise token) ra native theo redemptionRate (5.3.3 muc 2).
    function redeem(address token, uint256 amount) external returns (uint256 nativeOut);
    function redemptionRate(address token) external view returns (uint256 weiPerUnit, uint64 validUntil);
    function redeemableBalance() external view returns (uint256);

    event Sponsored(bytes32 indexed policyId, bytes32 indexed intentId,
                    address indexed relayer, uint256 paid, uint256 dailyRemaining);
}
```

Luong: `executeMetaTransaction` thay `metaTx.fee == 0 && sponsor.policy_id != 0` → sau khi inner call
thanh cong, goi `pool.settle(...)`. Chi phi them: **~30 000–45 000 gas** (policy SLOAD + merkle proof
3–4 muc + ERC-20 transfer). Tren Gnosis: **+$0.00005**. Chap nhan duoc.

**Rui ro con lai va cach chan.** Ban 1 mo ta dung hien tuong nhung sai muc do: giua luc relayer
`quote` (block N) va luc inclusion (block N+1), mot relayer khac co the rut can `dailyCap`. Ban 1 goi
do la va cham ngau nhien va uoc "xac suat ~0 o muc 20 intent/ngay". **Sai lam la coi no la ngau
nhien.** `dailyCap` la mot tai nguyen chung, hien, co han — do **la** dinh nghia cua mot be mat MEV.
Mot relayer doi thu doc duoc `dailyRemaining` bang mot `eth_call` va co the chu dich dot no bang
chinh intent cua minh ngay truoc khi doi thu inclusion. Chi phi cho ke tan cong: bang khong (no van
duoc tra tien cho intent cua no). Thiet hai cho nan nhan: mot tx gas.

Bien phap, xep theo thu tu:

1. **`perRelayerDailyCap` (them moi).** Khong relayer nao rut duoc qua `dailyCap / expected_relayers`
   trong mot ngay. Dot cap cua nguoi khac tro nen bat kha thi vi ban khong tieu duoc phan cua ho.
   Chi phi: +1 SLOAD + 1 SSTORE ≈ 5 000 gas. **Day la bien phap chinh.**
2. **Soft reserve tren hub** (khong rang buoc, TTL = W) + canh bao van hanh khi
   `dailyRemaining < 20 * maxFeePerIntent`.
3. Neu `settle` tra 0, relayer mat gas va se ha reputation **cua policy do** — day la mot **policy
   reputation**, khong phai relayer reputation. Field: `blockchain.sponsorship.pool.miss_rate_7d`.
   Relayer client tu choi policy co `miss_rate_7d > 0.05`.
4. **Khong** dung on-chain reservation: `reserve()` la mot tx rieng → nhan doi gas → xoa sach loi
   nhuan. **Loai.**

**Ba dieu nua ban 1 khong noi:**

- **Ai nap pool, va het tien thi sao.** `Policy.validUntil` het han hoac quy can → **moi intent
  sponsor lap tuc thanh khong sinh loi va khong ai relay**, im lang. Bat buoc: cron
  `cron_check_sponsorship_runway()` canh bao khi `redeemableBalance / burn_rate_7d < 14 ngay`, va
  `/policy` cong bo `runway_days` de relayer tu tinh rui ro doi tac.
- **`targetsRoot` la merkle root cua `(to, selector)` — nhung ai cap nhat no?** Doi mot target la doi
  root, tuc mot tx governance. Voi mot he ERP them endpoint hang tuan, do la ma sat that. Khuyen
  nghi: `targetsRoot` tro toi mot danh sach **on dinh** (cac forwarder/token cot loi), va logic
  nghiep vu bien dong nam **sau** mot dispatcher co dia chi co dinh. Neu khong, moi lan release phai
  chay mot tx multisig.
- **Chong double-sponsor.** `settle` phai ghi `usedIntent[intentId] = true` (1 SSTORE, 20 000 gas
  lan dau) — neu khong, mot intent duoc relay hai lan (nonce chan lan thu hai, nhung `settle` co the
  bi goi tu mot executor khac) se rut pool hai lan. `require(msg.sender == trustedExecutor[chainId])`
  la dieu kien can, khong phai dieu kien du.

Truong hop `chain_profile = private`: pool co the la mot bo dem thuan tuy, khong can token chuyen
thuc, vi gas ben trong la ke toan noi bo. Khi do `settle` chi phat event va Odoo dem — **va khi do
`SponsorshipPool.sol` khong nen ton tai o profile private chut nao.** Mot bang trong Odoo la du.

---

### 5.8. Doi soat va hach toan giua relayer va issuer (phia Odoo)

Nguyen tac ke thua tu `dms_vietqr` ("quet QR khong phai la da thu tien"): **broadcast khong phai la
da tra tien.**

#### 5.8.1. State machine — va ba ban khac nhau dang ton tai trong tai lieu nay

Ban 1 cua §5.8, §04.10 va §10.4.5 dua ra **ba** state machine khac nhau cho cung mot doi tuong. Do la
mot loi tai lieu se tro thanh mot loi code. Ban hop nhat, de nghi lam chuan:

```
draft → simulated → signed → published ─┬→ queued ──→ claimed → broadcast → mined → final ─┬→ done
                                        │              │            │                       └→ reverted
                                        ├→ expired ←───┴────────────┘
                                        └→ superseded
```

| State | Nghia chinh xac | Ai chuyen |
|---|---|---|
| `simulated` | `eth_call` pass tai `sim_block` | builder |
| `signed` | co `signature_hex`, `digest_hash` co dinh | vi / HSM |
| `published` | da nam tren bus, dang cho relayer | bus |
| `queued` | hop le nhung bi chan boi single-flight Zether (§5.4.3) | bus |
| `claimed` | mot relayer da giu exclusivity, chua het `W` | bus |
| `broadcast` | co `tx_hash` tu `/receipt` | relayer (khong tin) |
| `mined` | co receipt, `receipt.status == 1`, **chua du Finality Depth** | indexer (§11) |
| `final` | da qua Finality Gate cua chain do | Finality Gate |
| `done` | `final` **va** `MetaTransactionExecuted.innerSuccess == true` | Finality Gate |
| `reverted` | `final` **va** `innerSuccess == false` (swallow), hoac `receipt.status == 0` | Finality Gate |
| `expired` | qua `expiry` truoc khi `mined`; nonce **khong** bi tieu | cron |
| `superseded` | nonce/lane bi tieu boi mot tx khac | indexer |

Bon quy tac cung:

- **`mined` khong phai `done`.** Khong ghi so, khong bao thanh cong cho consumer.
- **`final` khong phai `done`.** O che do swallow (§04.6 mac dinh), mot tx **thanh cong** tren chuoi
  van co the mang `innerSuccess = false`. Odoo tuyet doi khong duoc suy trang thai nghiep vu tu
  `receipt.status`. Chi `done` moi kich hoat callback nghiep vu; neu ai do map cai nay vao
  `payment.transaction`, `_set_done()` chi duoc goi o `done`, con `mined` va `final` deu la
  `_set_pending()`.
- **`reverted` sau `mined` la kha nang co that khi reorg** → phai co `action_reconcile_reorg()` chay
  tu Finality Gate (§11), khong phai tu relayer callback.
- **`/receipt` cua relayer khong bao gio duoc tin.** No chi la mot goi y de indexer nhin som. Hai
  relayer cung bao `tx_hash` khac nhau la binh thuong (mot ke thang, mot ke thua) — hub luu ca hai
  vao `blockchain.transaction` va **chi chain quyet dinh**. Ban 1 khong noi dieu nay va no la mot cho
  de viet sai thanh "intent chuyen sang broadcast khi relayer bao".

#### 5.8.2. Model

| Model | Vai tro | Ghi chu so voi ban 1 |
|---|---|---|
| `blockchain.metatx` | **Ban ghi intent. Da ton tai o §10.4.5 — khong tao model moi.** | Ban 1 de xuat `dms.blockchain.intent` song song. Do la mot bang thu hai cho cung mot thuc the. Bo. |
| `blockchain.relayer` | Registry ben thu ba. **Da ton tai o §10.4.5.** | Ban 1 de xuat `dms.blockchain.relayer` voi `stake_wei`/`is_active`. Anh xa: `stake_ref` + `allowlist_state`. |
| `blockchain.sponsorship.pool` | Mirror pool + lich su nap | them `miss_rate_7d`, `runway_days` |
| `blockchain.relayer.statement` | Bang ke ky (thang) theo relayer × chain | **Doi ten tu `…relayer.settlement`**: §10.4.8 da dung `blockchain.settlement` cho mot khai niem hoan toan khac (settlement nghiep vu). Hai ten gan giong nhau cho hai thu khac nhau la mot bay doc. |
| `blockchain.relayer.statement.line` | 1 dong / intent | |
| `blockchain.intent.hub` | Peer hub trong federation | **moi**, ban 1 thieu; `hub_id`, `base_url`, `pubkey`, `allowlist_state`, `last_seen_datetime` |

Field bo sung tren `blockchain.metatx` do section nay yeu cau:

```python
class BlockchainMetatx(models.Model):
    _inherit = 'blockchain.metatx'

    inner_gas_limit      = fields.Integer(required=True, default=200000)
    sig_kind             = fields.Selection([('eoa', 'EOA'), ('erc1271', 'Smart account')],
                                            required=True, default='eoa')
    from_schnorr_address = fields.Char(size=66, index=True)   # NULL neu khong phai Zether
    target_epoch         = fields.Integer()
    bus_seq              = fields.Integer(index=True, copy=False, readonly=True)
    published_datetime   = fields.Datetime(index=True, readonly=True)   # khong dat ten 'date'
    exclusive_relayer_id = fields.Many2one('blockchain.relayer', index=True)
    exclusive_until_datetime = fields.Datetime()
    beacon_block         = fields.Integer()
    beacon_hash          = fields.Char(size=66)
    hops                 = fields.Integer(default=0)
    origin_hub_id        = fields.Many2one('blockchain.intent.hub', index=True)
```

**Kieu du lieu tien — sua so voi ban 1.** Ban 1 dung `fee_wei`, `stake_wei`, `net_wei`,
`subsidy_paid_wei` nhu the chung la so. §10.4.1 chot: **uint256 khong vua vao bat ky field so nao cua
Odoo** (`Integer` la int4/int8; `Float` mat chinh xac tu 2^53). Mot stake 100 token 18 decimals =
`1e20` — **tran int8 (`9.22e18`) va hong am tham**. Quy uoc bat buoc:

```python
fee_base       = fields.Char(required=True, default='0')     # uint256 decimal string
subsidy_base   = fields.Char(required=True, default='0')
gas_spent_base = fields.Char(required=True, default='0')
net_base       = fields.Char(required=True, default='0', compute='_compute_net_base', store=True)
net_display    = fields.Float(digits=(24, 8), compute='_compute_net_base', store=True, default=0.0)

_check_fee_base = models.Constraint(
    "CHECK (fee_base ~ '^[0-9]{1,78}$')", 'fee_base phai la chuoi thap phan uint256.')
_unique_statement_period = models.Constraint(
    'UNIQUE(relayer_id, chain_id, period_start_date)',
    'Moi relayer chi co mot bang ke cho moi ky va moi chain.')
```

`_unique_intent_id` cua ban 1 khong can them: §10.4.5 da co `digest_hash` va §04.4 da chot
`models.Constraint('UNIQUE(metatx_digest)', …)`. Mot cot, mot constraint. Kiem chung:
`SELECT conname FROM pg_constraint WHERE conrelid = 'blockchain_metatx'::regclass;`

Bay da biet cua stack (CLAUDE.md §5 va brief): `net_base`/`net_display` la stored computed → **moi
nhanh cua `_compute_net_base` phai gan gia tri**, ke ca nhanh `not self.line_ids`, neu khong cot
`required` nhan NULL va INSERT chet. Viet `net = 0` truoc vong lap, khong viet trong `else`.

Cron: XML chi goi **mot** dong (khong co `fields`/`relativedelta` trong eval context):
```xml
<field name="state">code</field>
<field name="code">model.cron_close_relayer_statements()</field>
```

Bon cron cua section nay (tat ca `active=False` mac dinh, bat theo `chain_profile` — §10):

| Cron | Chu ky | Viec |
|---|---|---|
| `cron_expire_intents()` | 1 phut | `published`/`claimed`/`queued` qua `expiry` → `expired`; nha single-flight Zether |
| `cron_poll_peer_hubs()` | 5 giay | keo `/pending` cua peer, re-publish |
| `cron_refresh_relayer_reputation()` | 15 phut | EWMA, `activeSetAt` mirror |
| `cron_close_relayer_statements()` | ngay 1 hang thang | dong ky, tinh `net_base` |
| `cron_check_sponsorship_runway()` | 1 gio | canh bao het quy |

#### 5.8.3. Doi soat: cai gi doi voi cai gi

Ban 1 goi bang ke la "mot doi soat, khong phai mot lan tra tien" — dung, nhung khong noi **doi soat
cai gi voi cai gi**. Cu the:

| Cot | Nguon | Co doi soat duoc khong |
|---|---|---|
| `intent_count` | `blockchain.metatx` state `done`/`reverted` | Co — tu DB cua issuer |
| `fee_earned_base` | event `MetaTransactionExecuted(digest, relayer, feeRecipient, fee)` | **Co, on-chain** |
| `subsidy_paid_base` | event `Sponsored(policyId, intentId, relayer, paid)` | **Co, on-chain** |
| `gas_spent_base` | `receipt.gasUsed × effectiveGasPrice` cua tx do relayer gui | **Co, on-chain** — nhung chi khi biet tx nao la cua relayer nao |
| `net_base` | `fee + subsidy - gas` | Suy ra |

Diem mau chot: **`gas_spent_base` chi doi soat duoc neu ta biet `tx.from`**, va `tx.from` chinh la
`msg.sender`, chinh la relayer. Nen no doi soat duoc **hoan toan tu chain**, khong can relayer khai
bao gi. Suy ra mot nguyen tac van hanh: **khong bao gio chap nhan mot con so gas do relayer tu bao
cao.** `/receipt` chi cung cap `tx_hash`; moi con so tien deu doc lai tu receipt. Ban 1 khong noi
dieu nay va no la cho de mot relayer keu "toi ton nhieu gas hon" ma khong ai kiem.

**Doi soat da tien te.** Gas tra bang xDAI, fee nhan bang mot token, bao cao bang VND. Ba don vi.
Quy tac: `blockchain.relayer.statement` luu **ba cot base-unit rieng** (khong quy doi), cong mot cot
`amount_vnd` chi de bao cao, tinh bang ty gia cuoi ky (`res.currency.rate` ngay dong ky). Khong bao
gio tinh `net` bang cach cong ba don vi khac nhau roi luu mot so — do la cach tao ra mot bang ke
khong bao gio khop lai duoc.

**Kich thuoc thuc te lam thay doi quyet dinh.** Voi 1 000 intent/ngay va $0.0018/intent, doanh thu
relayer la **~$54/thang**, gas ~$4/thang. Chi phi phat hanh mot hoa don, doi chieu, chuyen khoan cho
mot khoan $50 tai VN (thoi gian ke toan + phi) la **> $10**. Ket luan van hanh: **khong bill tung
thang cho tung relayer.** `blockchain.relayer.statement` co `state = 'accrued'` va chi
`action_post()` khi `net_base` quy doi > mot nguong (`ir.config_parameter`
`blockchain.relayer.statement_min_vnd`, mac dinh **2 000 000 VND**). Duoi nguong thi cong don sang ky
sau. Day la mot dong logic va no tiet kiem nhieu hon toan bo phan toi uu gas cua section nay.

Anh xa sang cac mode thanh toan da khoa o quyet dinh #8:
- **Mode 4 (sub-ledger doi soat theo lo):** bang ke *chinh la* lo. Khong can `account` gi ca. Mac
  dinh cho `dms_blockchain` standalone.
- **Mode 1/3:** bridge addon `dms_blockchain_account` (depends `dms_blockchain`, `account`) them
  `action_post()` sinh **mot `account.move` kieu `in_invoice` moi relayer moi ky** cho phan
  `subsidy_paid_base`. Khong bao gio dat code nay trong core — do la cach duy nhat giu duoc rang buoc
  "standalone" cua quyet dinh #7.
- **Thue VN:** phi relayer la doanh thu dich vu cua mot phap nhan/ca nhan. Neu relayer la ca nhan cu
  tru, phat sinh nghia vu khau tru. Xem §13; khong giai o day, nhung **phai co `partner_id` tren
  `blockchain.relayer`** ngay tu v1 de sau nay khong phai migrate.

---

### 5.9. Bootstrapping: lam sao co relayer ben thu ba dau tien khi khong ai noi EIP-1776

Van de that khong phai "EIP-1776 chua la standard". Van de la **khong co phan mem nao chay san**. Ai
muon relay phai tu viet client. Do do:

**Phase 0 — chay MODE_OPEN tu ngay dau, du chi co mot relayer.**
Enterprise relayer la relayer duy nhat, nhung intent van duoc ky o `MODE_OPEN` va van di qua intent
bus. Khong co "che do noi bo" rieng. Ly do: neu doi den khi co ben thu ba moi bat MODE_OPEN, se phat
hien ra mot loat gia dinh sai vao dung luc khong the sua.

*Ngoai le bat buoc, tu §5.4.5:* o `chain_profile = private` voi luong tien co so tien cong khai,
`MODE_OPEN` **tren bus noi bo** thi duoc, tren bus cong khai thi khong. "MODE_OPEN tu ngay dau"
la ve **hinh dang chu ky**, khong phai ve **pham vi mang**.

**Phase 1 — ship client, dung ship spec.**
Deliverable: `smartcontracts/relayer-ref/` (ngoai addon, theo quyet dinh #9) — mot Docker image chay
bang:
```
docker run -e RPC_URL=… -e HUB_URL=https://hub.bamboo.vn \
           -e PRIVATE_KEY_FILE=/run/secrets/k -e MIN_MARGIN=0.30 bamboo/relayer:1
```

**Sua so voi ban 1:** ban 1 uoc "~300–500 dong TypeScript: poll, simulate, so sanh margin, claim, gui
tx, receipt. Do la toan bo cong viec." Do la mot **uoc luong ban duoc hang, khong phai mot uoc luong
ky thuat**, va no se lam mat uy tin dung luc mot ky su ben ngoai thu that. Danh sach that:

| Phan | Dong (uoc luong) | Ban 1 co ke? |
|---|---|---|
| Poll `/pending`, `/get`, dedup theo `intent_id` | 80 | Co |
| Validate envelope, dung lai digest, kiem chu ky | 120 | Khong |
| `eth_call` simulate + tinh `max(gasUsed, EIP-7623 floor)` | 120 | Mot phan |
| Doc `redemptionRate` / `pool.quote`, tinh margin | 100 | Mot phan |
| `claim` co ky + xu ly `409` + backoff | 80 | Co |
| **Nonce manager cua chinh EOA relayer** (§06 cho biet day la phan kho nhat) | **250** | **Khong** |
| **Gas price strategy + replacement khi treo** | **200** | **Khong** |
| **RPC failover, phat hien node tut hau** | **150** | **Khong** |
| **Khoi phuc sau crash** (tx da gui, chua biet ket qua) | **200** | **Khong** |
| Theo doi receipt, xu ly reorg, `POST /receipt` | 150 | Mot phan |
| Ke toan cuc bo + metrics | 120 | Khong |
| Cau hinh, log, health, Dockerfile, test | 250 | Khong |
| **Tong thuc te** | **~1 800–2 400** | |

**Do van la loi the canh tranh that su cua EIP-1776** — mot ERC-4337 bundler la ~10 000–15 000 dong
va can chay mot alt-mempool. **5x re hon, khong phai 30x.** Quang cao con so 5x va co the bao ve no
tot hon nhieu so voi quang cao con so 30x roi bi mot ky su ngoai chung minh nguoc trong mot buoi
chieu. **Va do moi la thu can duoc quang cao, khong phai 2-D nonce.**

Mot cach re hon nua de ha rao gia nhap, ban 1 khong co: **ship `relayer-ref` o hai muc**.
`--mode=simple` bo qua nonce manager va replacement (gui mot tx, cho, khong bump) — **~500 dong**,
dung duoc that tren Gnosis noi block time 5 s va gas price gan nhu tinh. `--mode=production` la ban
day du. Nguoi thu nghiem dung `simple`; nguoi van hanh that dung `production`. Con so "500 dong" cua
ban 1 dung — nhung chi cho `simple`, va phai noi ro.

**Phase 2 — bao dam bien loi nhuan cho N intent dau.**
`SponsorshipPool` voi policy `bootstrap`: tra `gas + X` cho moi inclusion thanh cong, 10 000
intent/relayer/thang dau tien.

Ban 1 chon `X = $0.01` → 10 relayer × 10 000 × $0.01 = **$1 000/thang**. **Con so do khong du va ban
1 khong kiem tra no tu phia relayer.** Doanh thu cua relayer: **$100/thang**. Tru VPS ($5–20), tru RPC
($0–50), con **$30–95/thang**. Do la duoi muc dang de mot ky su **chu y**, chu chua noi den van hanh.
Chi phi that khong phai server, la **su chu y cua nguoi**.

| `X` | Doanh thu/relayer/thang | Chi phi 10 relayer/thang | Danh gia |
|---|---|---|---|
| $0.01 | $100 | $1 000 | Duoi nguong chu y. Se khong ai chay qua thang thu 2. |
| **$0.05** | **$500** | **$5 000** | Ngang mot hop dong freelance nho. **Khuyen nghi.** |
| $0.10 | $1 000 | $10 000 | Thu hut ca nguoi khong nghiem tuc |

**De nghi: `X = $0.05`, tran 10 relayer, 6 thang = $30 000 tong ngan sach bootstrap**, giam dan
$0.05 → $0.02 → $0.01 theo quy. So sanh: mot ky su ha tang 6 thang tai VN dat hon nhieu. Nhung day
la **mot quyet dinh ngan sach cua nguoi**, khong phai cua kien truc — dua vao `open_questions`.

Va mot dieu kien khong duoc quen: policy `bootstrap` phai co `perRelayerDailyCap` (§5.7) va
`requireRegistered = true`, neu khong mot nguoi tao 10 danh tinh va lay het $5 000.

**Phase 3 — relayer dau tien la distributor, khong phai nguoi la.**
Day la duong bootstrap that su cho ngu canh nay va no nen duoc noi thang: mot distributor trong he
thong DMS **da co ly do kinh doanh** de giu duong settlement song, **da la doi tac KYC**, va **da
chay ha tang**. Voi ho, relay khong phai la kinh doanh — no la chi phi van hanh, giong nhu chay mot
may POS. Nhu vay:
- Sybil khong con la moi de doa (moi participant la mot phap nhan da dinh danh) → PoW va stake co
  the de o muc thap.
- `chain_profile` co the la `private` trong 12–18 thang dau ma khong mat gi.
- **Mang la consortium truoc, open sau.** `MODE_OPEN` giu cua mo ma khong doi thi truong mo phai ton
  tai vao ngay dau. Ban tai lieu nen goi dung ten no, dung goi la "decentralized" khi no dang la
  federated.
- **Va he qua ma ban 1 khong rut ra:** neu Phase 3 la duong that, thi §5.4 (lottery, beacon, chong
  grinding), §5.6 (stake) va phan lon §5.5 (PoW) **khong duoc build trong nam dau**. Chung phai duoc
  *thiet ke* (de envelope va contract khong phai doi) nhung khong duoc *trien khai*. Cai phai build
  ngay la §5.2, §5.8 va tang 0–2 cua §5.5.

**Phase 4 — cho ha tang san co lam relayer duoc (dung ky thuat, khong phai tranh luan standard).**

**Sua so voi ban 1 — mot trong hai adapter cua ban 1 khong chay duoc nhu mo ta.**
Ban 1 de nghi `EIP1776ForwarderAdapter` "implement `IERC2771Forwarder.execute`" de Gelato /
OpenZeppelin Defender / Biconomy relay intent EIP-1776 "ma khong sua phan mem cua ho". Dieu do khong
dung: mot ERC-2771 forwarder verify mot chu ky EIP-712 **tren domain va struct cua chinh no**
(`ForwardRequest`). Mot chu ky EIP-1776 khong bao gio verify duoc o do — hai `domainSeparator` khac
nhau, hai `hashStruct` khac nhau. Khong co adapter contract nao "dich" duoc mot chu ky.

Cai **thuc su chay duoc**, va no don gian hon:

| Duong | Cach lam | Chi phi them | Ai ky cai gi |
|---|---|---|---|
| **Gelato `callWithSyncFee` / Defender Relay** | Goi API "gui calldata nay den dia chi nay va tu tra gas". Calldata la `executeMetaTransaction(metaTx, sig)`. **Khong can adapter contract nao.** | 0 gas, phi dich vu cua ho | User ky lop 1776; **Gelato ky lop tx**. Hai lop doc lap, khong xung dot. |
| `EIP1776EntryPointAdapter` (ERC-4337 account) | Mot smart account 4337 co `callData = executeMetaTransaction(...)` | ~40 000–60 000 gas (validation + EntryPoint) | **Owner cua account la relayer, khong phai user.** Lop 4337 uy quyen cho *relayer*; lop 1776 uy quyen cho *user*. |

Diem dang noi ve duong thu hai, ban 1 khong rut ra: gia tri cua no **khong** phai "tuong thich
4337". Gia tri la **relayer duoc mot ERC-4337 Paymaster tra gas cho no bang ERC-20**, tuc la mot
relayer khong can giu xDAI chut nao. Voi mot distributor o VN khong muon mua crypto, do la mot rao
can bien mat. Do la ly do dung de build no — va no chi dang build khi rao can do la that.

Ca hai la **duong tuong tac mot chieu vao EIP-1776**, khong phai buoc lui. Chung ton tai de vao ngay
khong co relayer nao online, van co ha tang cong cong dam bao intent duoc dua len chuoi.

**Phase 5 — thu do duy nhat chung minh mang song, ban 1 khong co.** Mot `/intents/v1/stats` cong
khai va mot dashboard:

| Chi so | Nguong "mang song" |
|---|---|
| So relayer khac nhau co >= 1 inclusion trong 7 ngay | **>= 3** |
| Ty trong cua relayer lon nhat | **< 60%** |
| `p50` / `p95` thoi gian tu `published` den `mined` | < 8 s / < 30 s |
| Ty le intent `expired` khong ai relay | **< 2%** |
| Ty le tx revert do dua (waste ratio) | < 10% |

Neu sau 6 thang Phase 2 ma "so relayer >= 1 inclusion" van la 1, thi ket luan la **khong co thi
truong**, va quyet dinh dung la rut ve consortium va cat toan bo §5.4–§5.6 khoi roadmap. Dinh nghia
truoc tieu chi that bai la cach re nhat de khong tra tien cho mot thi truong khong ton tai trong ba
nam.

---

### 5.10. Nhung cho note goc chua du va cach giai quyet da chon

| Cho chua du trong `blockchain.md` | Giai quyet chon trong section nay |
|---|---|
| "p2p gossip / mempool" khong duoc dinh nghia | Federated HTTP intent bus + poll 1 Hz (5 Hz cho Zether); libp2p bi loai co ly do dinh luong (§5.1) |
| Khong co dinh dang thong diep, khong co versioning | `bamboo-intent/1.1`; `intent_id` = EIP-712 digest = `digest_hash`; quy tac major/minor + `mode_known_mask` theo contract (§5.2) |
| "Relayer quet mempool, chay estimateGas, khi loi nhuan duong thi nop" — bo qua nguon FX | 3 nguon FX xep hang; enterprise token dung `redemptionRate` **cong voi `redeem()` va `redeemableBalance()`** chu khong phai mot con so treo (§5.3.3) |
| Khong noi ai chiu rui ro khi gas price chay | Relayer chiu, cua so 5 s; hub cong bo fee floor **theo (chain, token, mode)** voi cong thuc dung don vi; de xuat `MODE_METERED_FEE (0x08)` (§5.3.3) |
| ZKP verify "180k–250k gas" | Sai 7–15 lan; do la con so Groth16. Bulletproofs 32/64 = ~1.79 M (§03.3). Bao gia relayer phai doc `proofSystemId()` (§5.3.2) |
| "Thi truong canh tranh mempool lanh manh" — khong co so | EV rot ve 19% o N=5; **diem gia nhap tu do N* ≈ 76, noi do 100% phi bi dot thanh gas** (§5.4.2) |
| Khong noi ve DoS bang intent gia | 6 tang hang rao; tang 0 o nginx khong o Odoo; PoW 20 bit (16 cho mobile, 0 khi co JWT); **khong persist truoc tang 3** (§5.5) |
| "Sponsorship Escrow Pool ... phi dich vu dinh ky" | Tra dinh ky khong kha thi (contract khong doc log) → `settle()` inline, +30–45k gas, **+ `perRelayerDailyCap` vi `dailyCap` la mot be mat MEV** (§5.7) |
| Khong noi ve staking/slashing | Stake = trong so lottery **tuyen tinh** + hang rao sybil; **khong slashing trong v1**; `MIN_BOND` ~$500, bond bang native (§5.6) |
| Khong co ke hoach bootstrap | 5 phase; phase 3 (distributor lam relayer) la duong that; **tieu chi that bai duoc dinh nghia truoc** (§5.9) |
| Khong noi intent bus la mot kenh ro ri | **Muc moi §5.4.5**: private profile phai mTLS, khong federation; nguong gia tri cho `MODE_OPEN` public |

---

### 5.11. Kiem chung: bon thu phai chay duoc truoc khi tin section nay

Khong co framework, khong co fixture. Bon file, chay bang `pytest` va `psql`.

```python
# dms_blockchain/tests/test_intent_envelope.py  — thuan Python, KHONG import odoo
def test_intent_id_matches_eip712_vector():
    """Digest phai khop vector chung voi Solidity va voi relayer-ref.
    Neu ba implementation Fiat-Shamir/EIP-712 khong co oracle chung thi mot trong ba
    se lech am tham (bai hoc cua §03.8 muc 3)."""
    v = json.load(open('smartcontracts/testvectors/intent_v1.json'))
    assert intent_id(v['meta_tx'], v['chain_id'], v['verifying_contract']) == v['intent_id']

def test_canonical_zeroing_open_mode():
    """MODE_OPEN: doi relayer/feeRecipient KHONG duoc doi intent_id (§04.4)."""
    a = dict(BASE, mode=0, relayer=ADDR_A, feeRecipient=ADDR_A)
    b = dict(BASE, mode=0, relayer=ADDR_B, feeRecipient=ADDR_B)
    assert intent_id_of(a) == intent_id_of(b)

def test_restrict_mode_binds():
    a = dict(BASE, mode=1, relayer=ADDR_A)
    b = dict(BASE, mode=1, relayer=ADDR_B)
    assert intent_id_of(a) != intent_id_of(b)

def test_mode_bits_do_not_collide():
    """Bat loi cua ban 1: METERED_FEE tung dung 0x04 cua REQUIRE_SUCCESS."""
    bits = [MODE_RESTRICT_RELAYER, MODE_RESTRICT_FEE_RECIPIENT,
            MODE_REQUIRE_SUCCESS, MODE_METERED_FEE]
    assert len(set(bits)) == len(bits)
    assert all(b & MODE_KNOWN_MASK == b for b in bits)

def test_lottery_is_sybil_neutral():
    """Tach stake thanh k phan KHONG duoc tang co hoi thang (loi sqrt cua ban 1)."""
    honest = [('A', 100_000, 1.0)] + [(f'X{i}', 10_000, 1.0) for i in range(9)]
    sybil  = [(f'A{i}', 10_000, 1.0) for i in range(10)] + \
             [(f'X{i}', 10_000, 1.0) for i in range(9)]
    wins_h = sum(pick_exclusive(seed(i), B, S, honest) == 'A' for i in range(20_000))
    wins_s = sum(pick_exclusive(seed(i), B, S, sybil).startswith('A') for i in range(20_000))
    assert abs(wins_h - wins_s) / wins_h < 0.05      # sqrt-weighting se lam cai nay fail nang

def test_free_entry_equilibrium():
    ev = lambda n, f, r: f / n - (n - 1) * r / n
    assert ev(1, 0.0018, 0.000024) > 0
    assert abs(ev(76, 0.0018, 0.000024)) < 1e-6      # N* = 1 + f/r
```

```sql
-- Kiem chung constraint that su ton tai (CLAUDE.md §5 muc 2: dung tin code)
SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
 WHERE conrelid = 'blockchain_metatx'::regclass AND contype IN ('u','c');
SELECT indexname FROM pg_indexes
 WHERE tablename = 'blockchain_metatx' AND indexname LIKE '%zether_inflight%';
```

Va mot bai kiem tra tich hop duy nhat dang chay bang tay truoc khi ship: **hai instance
`relayer-ref` cung tro vao mot hub, phat 200 intent, dem so tx revert.** Neu waste ratio > 10% thi
soft-exclusivity dang khong hoat dong va con so §5.4.2 la dung theo huong xau.

---

### 5.12. Delta phai dong bo nguoc sang cac section khac

Section nay da tu sua theo §03/§04/§10. Ba dieu di **nguoc lai**, phai sua o section kia:

| Section | Cho phai sua | Sua thanh |
|---|---|---|
| §04.4 | `MODE_KNOWN_MASK = 0x07` | `0x0F`, va them `MODE_METERED_FEE = 0x08` vao danh sach hang so (giu `0x10` trong cho commit-reveal) |
| §04.4 | Chi ba mode bit duoc mo ta | Them quy tac: `/policy` cong bo `mode_known_mask` **theo `verifying_contract`**; relayer tu choi bit la truoc khi simulate |
| §10.4.5 | `metatx_state` thieu `queued`, `broadcast`, `superseded`, `done`, `reverted` | Dung state machine hop nhat o §5.8.1 (11 trang thai) |
| §10.4.5 | `mode_flags` comment ghi `0x00/0x01/0x02/0x03` | `0x00`–`0x0F` |
| §10.4.5 | thieu `inner_gas_limit`, `sig_kind`, `from_schnorr_address`, `bus_seq`, `beacon_*` | Them (danh sach o §5.8.2) |
| §04.10 | Ngan sach gas Zether "342k–422k" mau thuan voi §03.3 "~1.79 M" | Ghi ro: 342k–422k **chi** voi native precompile hoac Groth16; 1.79 M voi `BulletproofsVerifier.sol` |
| §06 | Nonce manager mo ta cho relayer noi bo | Ghi ro no **khong** ap dung cho relayer ben thu ba — ho tu quan nonce cua ho; §5.9 Phase 1 tinh 250 dong cho viec do |
