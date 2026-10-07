> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 05. Open Relayer Network: intent pool, kinh tế học, chống front-run

> **Bản 2 — đã qua review đối kháng.** Bản 1 dùng prefix model `dms.blockchain.*`; §10.3 đã chốt
> `blockchain.*` và yêu cầu section này đổi. Đã đổi. Bản 1 cũng đặt `MODE_METERED_FEE = 0x04`, đụng
> vào bit `MODE_REQUIRE_SUCCESS` mà §04.4 đã cấp. Đã đổi sang `0x08`. Chi tiết ở §5.12.
>
> **Bản 3 — sau khi user chốt kiến trúc mesh.** `_USER-DECISIONS.md` §6 và §21 chọn **libp2p +
> gossipsub v1.1 theo mô hình 0x-mesh**, hai mode vận hành, hai bản cài đặt (Rust standalone và
> Odoo addon). Đó là một **quyết định ngược với khuyến nghị của §5.1 bản 2** (federated intent bus).
> §5.1 đã được viết lại: giữ nguyên phần phân tích so sánh vì nó vẫn đúng, đổi kết luận, và nói rõ
> lý lẽ nào của bản 2 còn đứng vững và lý lẽ nào bị quyết định của user vượt qua.
>
> Ràng buộc kiến trúc: `dms_blockchain` **không depend `dms`**. Mọi thứ dưới đây chỉ dùng `base`,
> `web`, và (tuỳ chọn) `bus`. Phần hạch toán chạm `account.move` nằm trong bridge addon riêng
> `dms_blockchain_account`, không nằm trong core.
>
> **Bản 4 — `mode` quay lại, `feeMode` biến mất vào trong nó.** `_USER-DECISIONS.md` §24 chốt struct
> cuối cùng (code chuẩn tắc: `smartcontracts/src/common/MetaTxLib.sol`). Ba hệ quả cho section này,
> áp dụng ở **mọi** chỗ bên dưới còn nói theo bản 2/bản 3:
>
> 1. **`mode: uint32` có mặt trong struct và trong digest**, với hai nửa byte hai bản chất: nửa đầu
>    là **cờ** (`0x01` ràng buộc `relayer`, `0x02` ràng buộc `feeRecipient`), nửa sau là **giá trị
>    liệt kê** cho cách tính phí (`0x00` NONE / `0x10` PERCENT / `0x20` FIXED). `MODE_KNOWN_MASK = 0xF3`.
> 2. **Không còn trường `feeMode` riêng.** Mọi chỗ dưới đây viết `"feeMode": 2` phải đọc là
>    `"mode": 32` (`0x20`). Lập luận "feeMode phải nằm trong digest" **vẫn đúng và vẫn được thoả** —
>    vì `mode` nằm trong digest.
> 3. **`/policy` công bố lại `mode_known_mask`** theo từng `verifying_contract`. Đoạn ở §5.6 tuyên bố
>    nghĩa vụ đó "chết cùng bitmask" là **sai từ bản 4 trở đi**; xem đính chính tại chỗ.
>
> Và một **đính chính thẳng**: mấy chỗ dưới đây nói bitmask gây *cross-mode replay*. **Sai.** Canonical
> zeroing với `mode` **bên trong** hash cho `(OPEN)` và `(RESTRICT, relayer=0)` hai digest **khác nhau**.
> Lý do thật để bỏ bitmask ở bản 2 là dư thừa và va chạm cấp bit giữa các section, không phải replay.
> Xem `04-eip1776-metatx.md` §04.4.
>
> **Ràng buộc đọc:** section này không định nghĩa lại struct `MetaTransaction` (§04), không định
> nghĩa lại mật mã học Zether (§03), không định nghĩa lại relay pool nội bộ (§06), không định nghĩa
> lại data model chung (§10). Nơi nào con số của section này khác các section đó, section này **sai**
> và đã được sửa theo. Xem §5.12 cho danh sách delta còn lại phải đồng bộ ngược.

---

### 5.0. Trục `chain_profile` quyết định phần nào của section này được bật

Quyết định khoá #5 (private chain đi trước cho Zether) làm cho gần **toàn bộ kinh tế học relayer trở
thành no-op** ở profile private. Phải khai báo rõ điều đó, nếu không sẽ build một thị trường đấu giá
cho một mạng chỉ có ba node của chính mình.

| Cơ chế | `chain_profile = private` | `chain_profile = public` |
|---|---|---|
| Intent bus | 1 hub nội bộ, không federation, không mesh | Mesh libp2p, gossipsub v1.1 |
| Kênh mạng | mTLS trong VPC, không ra Internet | libp2p công khai + rate limit ở edge |
| `mode` mặc định | `MODE_RESTRICT_RELAYER (0x01)` | wildcard `relayer == address(0)` |
| PoW chống sybil | Tắt | Bật cho submitter không có on-chain history và không có JWT |
| Relayer stake | Tắt (allowlist thay thế) | Bật (weight cho lottery) |
| Soft-exclusivity lottery | Tắt (round-robin tĩnh) | Bật |
| Đánh giá lợi nhuận | Tắt (gas free / metered nội bộ) | Bật |
| Sponsorship pool on-chain | Tuỳ chọn (có thể là budget counter thuần tuý) | Bắt buộc |
| Finality Gate | Vẫn bật | Bật |
| Rò rỉ dữ liệu qua intent | **Rủi ro chính** — xem §5.4.5 | Chain đã công khai rồi |

Field: `blockchain.chain.chain_profile = fields.Selection([('private','Private/Permissioned'),
('public','Public')], required=True, default='private', index=True)`. Đây là một **field trên
`blockchain.chain`**, không phải model riêng (§10.3 đã bác bỏ `blockchain.chain.profile`). Mọi đoạn
code kinh tế học dưới đây đều guard bằng `if chain.chain_profile == 'public'`.

Hai dòng của bảng đã đổi so với bản 2. **[BẢN 4]** `MODE_RESTRICT_RELAYER = 0x01` ở cột private
mang đúng nghĩa đen của nó: bit bật **và** `relayer` điền một địa chỉ cụ thể. Hai thứ đi cùng nhau —
bit bật mà `relayer == address(0)` là ràng buộc "chỉ địa chỉ 0 được relay", tức là khoá chết intent;
node phải bắt trường hợp đó ở tầng sanity (§5.9) chứ contract không bắt hộ.

**Chỉ triển khai profile `public` khi đã có ít nhất 1 relayer bên thứ ba thật.** Trước đó, viết code
để nó *có thể* bật, đừng bật.

**Điều bản 1 không nói thẳng, và cần nói:** ở profile `private`, section 05 rút gọn thành
**section 06 cộng một allowlist**. Không có thị trường, không có đấu giá, không có lottery, không có
stake. Cái duy nhất còn lại có giá trị kiến trúc là **định dạng envelope và state machine** — vì đó
là thứ phải ổn định để sau này bật public mà không phải viết lại client.

**Và có một lý do thứ hai, mạnh hơn, để chốt định dạng sớm:** user quyết định làm **hai bản cài đặt
song song** của cùng một giao thức — Rust standalone và Odoo addon (`_USER-DECISIONS.md` §21.2). Hai
bản cài đặt của một giao thức gossip là đúng chỗ mà lỗi bất đồng thuận sinh ra. Nên §5.2 không chỉ là
"deliverable quý 1", nó là **spec mà cả hai bản phải tuân theo**, kèm bộ vector tuân thủ dùng chung.
Viết bản Rust trước rồi coi nó là spec là cách chắc chắn nhất để hai bản lệch nhau sau vài tháng.

Thêm nữa: chain private 9000 có `MinGasPrice = 0` (§01.1.16), nên ở giai đoạn private **không cần
relayer nào cả** — người dùng tự gửi được vì gas miễn phí. Điều đó đẩy toàn bộ section này ra khỏi
đường tới hạn của giai đoạn 1, và củng cố thứ tự trên: chốt định dạng trên giấy, đừng build thị trường.

---

### 5.1. Cách intent được công bố và khám phá

> **Kết luận của mục này đã đổi ở bản 3.** Bản 2 khuyến nghị **federated intent bus** và bác bỏ p2p.
> User chốt **mesh libp2p kiểu 0x-mesh** (`_USER-DECISIONS.md` §6). Phần phân tích dưới đây giữ
> nguyên vì các con số vẫn đúng; điều đổi là trọng số giữa "rẻ và nhanh" và "mở thật".

Note gốc (`blockchain.md` §10.1, mục `P2P_POOL`) nói "Open Relayer Gossip Mempool / Intent Pool ...
tự p2p gossip / mempool". Bản 2 gọi đó là "một câu chữ không phải một thiết kế", và phần đó đúng —
nhưng kết luận rút ra thì không.

| Phương án | Latency thêm | Chi phí vận hành | Độ khó cho relayer bên thứ ba | Đánh giá |
| Phương án | Latency thêm | Chi phí vận hành | Độ khó cho relayer bên thứ ba | Đánh giá bản 2 | **Đánh giá bản 3** |
|---|---|---|---|---|---|
| **A. libp2p / gossipsub v1.1** | 100–800 ms (mesh fanout) | Bootstrap node, NAT traversal, peer scoring, DHT | Cao: phải nhúng go-libp2p / rust-libp2p, học peer discovery | *"Loại. Xây lại một mạng p2p để vận chuyển ~10 msg/s là over-engineering."* | **CHỌN.** Xem lý lẽ dưới |
| **B. Public mempool của chính chain** (nhúng intent chưa ký như tx thường) | 0 | 0 | Thấp | **Không khả thi.** Intent EIP-1776 là một payload cần `msg.sender` là relayer — nó không phải một tx hợp lệ cho đến khi relayer bọc nó lại. Không thể nhét vào mempool EVM | Không đổi — vẫn không khả thi |
| **C. Federated intent bus (HTTP publish + poll/stream, nhiều hub peer với nhau)** | 0–1000 ms (poll 1 Hz) | 1 controller + 1 bảng Postgres | Rất thấp: `curl` là đủ | *"Chọn."* | **Giữ, nhưng hạ xuống làm lớp bootstrap và làm gateway cho client nhẹ** |

**Lý lẽ định lượng của bản 2 vẫn đúng, và nó không phải thứ bị bác bỏ.** Gnosis block time 5 s; poll
1 Hz thêm tối đa 1 s = 20% một block; với 50 relayer poll 1 Hz, hub nhận 50 req/s trên một index —
một Odoo worker đơn xử lý được. Không con số nào ở đây sai.

**Cái bản 2 cân sai là trọng số, không phải con số.** Nó tối ưu cho "rẻ và nhanh để dựng", trong khi
ràng buộc thật là **mở**: nếu tham gia mạng relayer đòi kết nối tới một hub do ta vận hành, thì "open
relayer network" chỉ là tên gọi — ta là điểm kiểm duyệt, điểm hỏng, và điểm phải tin. Với một factory
mở cho toàn thế giới (§20 của `_USER-DECISIONS.md`), một mạng relayer có chủ là mâu thuẫn nội tại.

Ba lý lẽ cụ thể lật kết luận:

1. **Không tự viết giao thức.** Bản 2 phản đối "xây lại một mạng p2p", và điều đó đúng — nhưng
   libp2p + gossipsub v1.1 **không phải tự viết**, nó là lấy đúng bộ mà ERC-4337 đã chuẩn hoá
   (`eth-infinitism/bundler-spec/p2p-specs/p2p-interface.md`) và đang chạy thật trên Ethereum,
   Arbitrum, Optimism. Chi phí là tích hợp một thư viện, không phải thiết kế một giao thức.
2. **gossipsub v1.1 mang sẵn peer scoring**, tức là một primitive chống spam ở tầng mạng mà phương án
   C phải tự dựng lại bằng rate limit ở edge — và rate limit ở edge chỉ bảo vệ hub của ta, không bảo
   vệ mạng.
3. **Câu "ERC-4337 mất 3 năm mới có alt-mempool thật sự chạy" là một lý lẽ ủng hộ, không phải phản
   đối.** Nó nghĩa là bộ công cụ đã trưởng thành và các lỗi đã bị người khác trả giá.

**Cái bản 2 đúng và phải giữ:** phương án C không chết. Nó xuống hai vai trò cụ thể:

- **Bootstrap.** Mesh nào cũng cần điểm khởi đầu. Hub HTTP là bootstrap node đầu tiên, và là đường
  vào cho relayer chưa muốn chạy libp2p (§5.9 Phase 1–2).
- **Gateway cho client nhẹ.** Một ví trên điện thoại không nên chạy một node libp2p để gửi một
  intent. Nó `POST` lên một gateway, gateway gossip hộ. Đây chính là **mode 1** của
  `_USER-DECISIONS.md` §21.1 — relay thuần, không tham gia mạng.

Nên kiến trúc cuối là **cả hai**, và ranh giới rõ:

```
Client nhe (vi, web)  --HTTP-->  Gateway/Hub  --libp2p gossipsub-->  Mesh
                                     ^                                 |
Relayer mode 1 (relay thuan) --------+                                 |
Relayer mode 2 (node mang)  ------------------------------------------+
```

#### 5.1.0. Điểm thiết kế mà 0x-mesh không có: từ chối thì CHUYỂN TIẾP

`_USER-DECISIONS.md` §21.1: *"các tx không phù hợp với nó được đưa vào pool, relay đến các node
khác"*. Đây là chỗ thiết kế này hơn 0x-mesh, và nó đáng được nói rõ vì nó đổi cả kinh tế học băng
thông.

0x-mesh gossip mọi order tới mọi node và để từng node tự lọc — nên mỗi node trả chi phí băng thông
cho toàn bộ lưu lượng của mạng, kể cả phần nó không bao giờ nhận. Ở đây, acceptance policy (§5.3)
không chỉ là bộ lọc mà là **bộ định tuyến**: một node từ chối một intent vẫn chuyển tiếp nó.

Ba hệ quả:

- Intent phí 0 nhắm contract đối tác đi thẳng tới node đối tác, thay vì lang thang cho tới khi hết
  hạn. Đây là thứ làm `fee = 0` chạy được trên mạng mở (`_USER-DECISIONS.md` §3.4b).
- Một node chuyên một chain không phải mang lưu lượng của sáu chain kia.
- Mạng vẫn liên thông mà không cần mọi node biết mọi thứ.

**Và một bẫy phải thiết kế ngay chứ không vá sau: chuyển tiếp là định tuyến, nên nó có vòng lặp.**
Hai node có acceptance policy loại trừ nhau sẽ đẩy qua đẩy lại một intent cho tới khi nó hết hạn.
gossipsub lo phần chống lụt ở tầng mạng (message ID dedup, mesh degree), **không** lo phần vòng lặp ở
tầng ứng dụng. Bắt buộc:

| Cơ chế | Chi tiết |
|---|---|
| `hop_count` | Tăng mỗi lần chuyển tiếp có chủ đích. `MAX_HOPS = 4`. Vượt → drop, không gossip lại |
| Dedup theo `intent_id` | Mỗi node giữ một set `intent_id` đã thấy, TTL = `expiry` của intent. Thấy lại thì không xử lý lại, kể cả từ peer khác |
| `expiry` là trần cứng | Không bao giờ chuyển tiếp một intent đã hết hạn. Đây cũng là cơ chế prune (§5.2) |

`hop_count` **không** nằm trong digest EIP-712 — nó đổi theo đường đi, nên đưa vào digest là làm chữ
ký vô hiệu ngay hop đầu tiên. Nó nằm trong envelope, ngoài phần được ký. Hệ quả: `hop_count` không
được tin, và một node độc hại đặt nó về 0 mãi mãi. Đó là lý do dedup theo `intent_id` (thứ **có**
trong digest) mới là phòng tuyến thật, còn `hop_count` chỉ là cắt bớt lãng phí.

#### 5.1.1. Ngân sách latency, và chỗ bản 1 hứa quá

Bản 1 nói "1 s là 20% một block" rồi dừng ở đó. Đó là một câu đúng cho intent thường và **sai cho
Zether**. §04.5 chốt `expiry` của metaTx Zether là **≤ 20 giây** (1 epoch = 5 block × 5 s = 25 s,
trừ 1 block an toàn). §03.8 chốt thời gian prove: **0,2–0,5 s** (Android ARM64 native) đến
**0,8–2,5 s** (WASM trong WebView). Ghép lại:

| Bước | Intent thường | Intent Zether |
|---|---|---|
| Client prove ZKP | 0 | **0,2–2,5 s** |
| Ký + publish | 50–200 ms | 50–200 ms |
| Hub/node validate (tầng 0–3) + persist | 5–20 ms | 5–20 ms |
| Relayer phát hiện (poll 1 Hz **hoặc** gossip 100–800 ms) | **0–1000 ms** | **0–1000 ms** |
| Relayer `eth_call` simulate | 15–40 ms | **60–150 ms** (verify BP trên node) |
| Soft-exclusivity window `W` | **3000 ms** | **phải = 0** |
| Broadcast → inclusion (1 block) | 5000 ms | 5000 ms |
| **Tổng xấu nhất** | **~9,3 s** | **~8,9 s (không kể prove)** |
| **Ngân sách `expiry`** | 900 s | **20 s** |
| **Biên còn lại** | thoải mái | **~11 s, hoặc ~8,5 s nếu prove trên WASM** |

Kết luận bắt buộc, bản 1 thiếu:

1. **Intent Zether phải có `W = 0`** (không soft-exclusivity). Mất 3 s của ngân sách 20 s là
   15% ngân sách để đổi lấy một biện pháp chống lãng phí $0,000024. Sai tỷ lệ.
2. **Intent Zether phải được đẩy, không được poll.** Trên mesh thì điều này miễn phí — gossipsub
   vốn là push, latency 100–800 ms, và không cần một kênh long-poll riêng nào cả. **Đây là một lợi
   ích của kiến trúc mesh mà bản 2 không tính vào bảng so sánh**, và nó đúng ở chỗ nó đắt nhất: intent
   Zether, nơi ngân sách chỉ có 20 s.
3. **Cho client nhẹ đi qua gateway (mode 1), long-poll vẫn cần** — và nó **không được chạy trên Odoo
   worker prefork** (xem cảnh báo dưới). Nếu chưa tách daemon, giải pháp tạm thời dùng được: relayer
   poll `?urgent=1` ở **5 Hz** thay vì 1 Hz, chỉ lấy summary (~200 B/intent). 5 Hz × 20 relayer =
   100 req/s cho một query index — chấp nhận được, và nó đưa latency phát hiện về ≤ 200 ms mà không
   cần hạ tầng mới.

Thứ tự triển khai theo đó: **gateway HTTP + poll 5 Hz cho v1** (đủ cho giai đoạn private, nơi vốn
chưa cần relayer), **mesh libp2p khi chuẩn bị lên public**. Định dạng envelope (§5.2) phải giống nhau
ở cả hai, vì đó là thứ không đổi được sau khi có client ngoài.

**Cảnh báo triển khai, đã kiểm chứng trên stack Odoo:** không làm SSE/WebSocket bằng controller Odoo
trong chế độ prefork. Mọi kết nối long-lived giữ chết một worker; với `workers = 8` bạn có tối đa 7
stream đồng thời. (`bus.bus` của Odoo giải quyết điều này bằng gevent worker riêng — `--gevent-port`
— không phải bằng HTTP worker.) Nếu cần stream, tách một daemon nhỏ đọc `LISTEN/NOTIFY` từ Postgres,
đặt ngoài addon tại `intent-hub/` ở repo root (cùng nguyên tắc với `smartcontracts/` ở quyết định
khoá #9).

**Và đây chính là chỗ bản Rust standalone (`_USER-DECISIONS.md` §21.2 A) thuộc về.** Nó không phải
một bản song song thừa: một node libp2p giữ hàng trăm kết nối dài hạn là đúng thứ mà Odoo prefork
không làm được, và đúng thứ Rust làm tốt. Bản Odoo addon (§21.2 B) phục vụ mode 1 — nhận HTTP, ký,
đẩy lên chain — nơi mọi request đều ngắn. Ranh giới kỹ thuật trùng đúng ranh giới hai bản cài đặt, và
đó là lý do có hai bản chứ không phải sở thích ngôn ngữ.

#### 5.1.2. API của gateway

Tất cả là controller Odoo trong `dms_blockchain/controllers/intent_bus.py`. Chúng không phải model
method, vì đây là API cho bên thứ ba không có Odoo session — đây là ngoại lệ hợp lý của quy ước
call_kw/json2 trong CLAUDE.md §6, và phải được ghi rõ trong docstring.

**Chi tiết Odoo bản 1 bỏ qua:** dùng `type='http'`, **không** `type='json'`. `type='json'` của Odoo
là JSON-RPC envelope (`{"jsonrpc":"2.0","params":{...}}`), không phải REST JSON body — một relayer
viết bằng `curl` sẽ không đoán ra. Mẫu đúng:

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

`save_session=False` là bắt buộc: không có nó, mỗi request của mỗi relayer sinh một session row và
một cookie — 200 relayer × 5 Hz = 1000 session/s. Đây là một lỗ DoS tự gây.

| Route | Method | Mục đích | Auth |
|---|---|---|---|
| `/intents/v1/policy` | GET | fee floor theo `(chain, token)`, **`fee_recipient` của node này**, PoW bits, danh sách chain + profile, `spec` versions được chấp nhận, khoá công khai của gateway, **danh sách bootstrap multiaddr của mesh** | public, `ETag` + `Cache-Control: max-age=60` |
| `/intents/v1/publish` | POST | Nhận một intent envelope. Trả `409` nếu `intent_id` đã tồn tại (idempotent) | public + tầng 0–3 §5.5 |
| `/intents/v1/pending` | GET | `?chain_id=100&since=<cursor>&min_fee=…&token=0x…&target=0x…&fields=summary&urgent=1` | public |
| `/intents/v1/get` | GET | `?ids=0x..,0x..` — lấy envelope đầy đủ cho tối đa 50 id | public |
| `/intents/v1/claim` | POST | Đăng ký ý định relay (soft-exclusivity). **Bắt buộc ký bằng khoá relayer đã đăng ký.** Trả `409 CLAIMED_BY_OTHER` + `retry_after` | signed |
| `/intents/v1/receipt` | POST | Relayer báo `tx_hash`. Gateway theo dõi, re-publish nếu quá hạn | signed |
| `/intents/v1/peers` | GET | Danh sách gateway + bootstrap node của mesh, mỗi entry ký bởi owner | public |

Hai route cuối là cầu giữa hai lớp: `/policy` và `/peers` trả **bootstrap multiaddr**, nên một
relayer bắt đầu bằng HTTP có thể tự nâng cấp lên node mesh mà không cần cấu hình tay. Đó là đường
Phase 1 → Phase 2 của §5.9, và nó phải tồn tại từ ngày đầu vì thêm sau nghĩa là mọi relayer đã tích
hợp phải sửa.

**Ba lỗ hổng của bản 1 ở đây, đều phải vá:**

1. **`/claim` không có auth.** Bất kỳ ai cũng claim được mọi intent và không bao giờ relay → khoá
   toàn bộ lottery trong `W` giây, miễn phí, lặp lại vô hạn. Reputation chỉ phạt *sau khi* có danh
   tính; danh tính vô danh thì miễn phí. **Fix:** `claim` yêu cầu header
   `X-Relayer-Sig: <secp256k1 sig>` trên `keccak256("scaas-claim/1" ‖ intent_id ‖ hub_id ‖ ts)`,
   `|now - ts| <= 30 s`, và địa chỉ recover ra phải có trong `blockchain.relayer.address`
   với `allowlist_state in ('probation','allowed')`. Relayer chưa đăng ký **vẫn relay được** — chỉ là
   không claim được, tức phải đợi hết `W`. Đó là một động cơ đăng ký đúng mực.
2. **`/pending` trả envelope đầy đủ là lãng phí băng thông.** 50 relayer × 1 Hz × 50 intent × 1,5 KB
   = **3,75 MB/s = 30 Mbps** cho một hàng đợi 50 intent. `fields=summary` trả
   `(intent_id, chain_id, to, token, fee, gas_limit, expiry, is_zether, exclusive_until)`
   ≈ **200 B** → 0,5 MB/s. Relayer chỉ `GET /get?ids=` những cái nó muốn. **Giảm 7×, một dòng code.**
   `fields=summary` là **mặc định**; `fields=full` phải xin.

   Trên mesh, cùng vấn đề có cùng lời giải nhưng tên khác: gossip **summary** trên topic chính, và
   để node quan tâm kéo envelope đầy đủ qua một request trực tiếp tới peer. Đây là mô hình
   announce/fetch mà bittorrent và Ethereum devp2p đều dùng, và nó là lý do một node chuyên một chain
   không phải tải lưu lượng của sáu chain kia (§5.1.0).
3. **Cursor `(write_date, id)` của bản 1 bỏ sót row.** Hai lý do độc lập: (a) Odoo đặt `write_date`
   bằng `now()` **lúc write trong Python**, không phải lúc COMMIT, và nhiều worker có thể lệch nhau;
   (b) ngay cả một `bigserial` cũng được cấp **trước** COMMIT, nên tx có seq nhỏ hơn có thể hiện ra
   sau tx có seq lớn hơn. Một reader `WHERE seq > cursor ORDER BY seq` sẽ **nhảy qua** row đó vĩnh
   viễn. Đây là một bug thật, không phải lý thuyết — nó biểu hiện là "thỉnh thoảng một intent không
   bao giờ được relay".

   **Fix rẻ nhất và đúng:** cursor vẫn là `bus_seq` (`bigserial`), nhưng server chỉ phục vụ row có
   `published_at <= now() - interval '500 ms'` (lag window) **và** client luôn xin lại từ
   `cursor - 200`, dedup bằng `intent_id`. Dedup vốn đã là cơ chế chính của bus (`intent_id` là
   content address), nên chi phí của overlap là 0 về mặt đúng đắn và ~200 row/lần poll về mặt băng
   thông. Ghi rõ trong `/policy`: `"cursor_overlap": 200, "publish_lag_ms": 500`.

   `# ponytail: lag window 500 ms + overlap 200. Neu commit latency thuc te > 500 ms (giao dich`
   `# dai, vacuum), doi sang watermark tu pg_snapshot_xmin(pg_current_snapshot()).`

   Lỗi này **không tồn tại trên mesh** — gossipsub push chứ không cursor. Đó là một lý do kỹ thuật
   nữa ủng hộ mesh mà bảng so sánh ở §5.1 không tính: một lớp bug về thứ tự và con trỏ biến mất
   hoàn toàn. Nhưng gateway vẫn cần fix này, vì client nhẹ vẫn poll.

Liên thông giữa các gateway: mỗi gateway subscribe `/intents/v1/pending` của peer và re-publish. Vòng
lặp gossip vô hại vì `intent_id` là **content address**, `publish` là idempotent. **Nhưng bản 1 bỏ
qua ba điều:**

- **Khuếch đại.** M gateway full-mesh truyền mỗi intent M(M-1) lần. Với M = 5 là 20 lần — không sao.
  Với M = 20 là 380 lần. Đặt trần `max_peers = 8` và thêm `hop_count` (uint8) trong envelope,
  `hop_count <= MAX_HOPS`, gateway tăng khi re-publish và **từ chối khi vượt**. Không phải chống tấn
  công; là chống ngu. Đây là cùng một cơ chế với §5.1.0 — một trần hop, dùng cho cả gateway federation
  và mesh forwarding, không phải hai thứ khác nhau.
- **Gateway độc hại.** Một peer có thể (a) re-publish intent đã hết hạn, (b) giữ lại (kiểm duyệt),
  (c) sửa `exclusive.*`. (a) chặn bằng kiểm `expiry` trước khi nhận. (c) chặn bằng `hub.sig` của
  **gateway gốc** — xem §5.2. (b) không chặn được và không cần chặn: relayer subscribe nhiều gateway.

  Trên mesh, (b) yếu đi đáng kể: gossipsub phát tới toàn mesh nên một node giữ lại chỉ tự cô lập
  mình. Đó là một lợi ích an ninh thật của kiến trúc mesh, và nó thuộc loại không mua được bằng cách
  thêm gateway.
- **`/peers` là một danh sách tin cậy.** Nó không nên tự do. `blockchain.intent.hub` là một model
  có `allowlist_state`, admin duyệt tay. Federation gateway là một liên minh, không phải một DHT.

  **Mesh thì ngược lại, và đó là chủ ý**: bootstrap node là điểm khởi đầu chứ không phải cổng duyệt,
  và peer scoring của gossipsub v1.1 thay cho allowlist. Hai lớp, hai mô hình tin cậy, và không nên
  cố hợp nhất chúng.

---

### 5.2. Định dạng thông điệp và versioning

`intent_id` **là EIP-712 digest của struct `MetaTransaction`**, không phải hash của JSON:

```
intent_id = keccak256(0x19 ‖ 0x01 ‖ domainSeparator(chainId, verifyingContract) ‖ hashStruct(MetaTransaction))
```

Đây là **cùng một giá trị** với `blockchain.metatx.digest_hash` của §10.4.5 và `metatx_digest` của
§04.4. Một khái niệm, một cột, hai tên trên dây. Trong Odoo dùng `digest_hash`; trên dây dùng
`intent_id` vì đó là tên mà relayer thấy. Ghi rõ trong docstring để người đọc không đi tìm hai bảng.

Ba tính chất miễn phí từ lựa chọn này:

1. Mọi node tính ra cùng một id mà không cần đồng ý về canonical JSON (JSON canonicalisation là một
   hố lầy bẩn đã rơi vào — key order, số học float, unicode escape).
2. **Miễn nhiễm signature malleability.** ECDSA có hai chữ ký hợp lệ `(r, s)` và `(r, n-s)`. Vì digest
   không chứa chữ ký, kẻ tấn công flip `s` không tạo ra intent_id mới — node dedup đúng. (Vẫn phải
   reject high-s trong contract theo EIP-2 / `ECDSA.tryRecover`, nhưng đó là để chống replay on-chain,
   không phải để dedup.)
3. `relayer` và `feeRecipient` là **wildcard `address(0)`** ở chế độ mở, nên intent_id ổn định bất kể
   ai relay. Đúng cái muốn.

   **[BẢN 4]** Canonical zeroing của §04.4 **quay lại**: `hashStruct` gọi `canon()`, và `canon()`
   đặt `relayer = address(0)` khi cờ `MODE_RESTRICT_RELAYER` tắt, bất kể client điền gì. Kết quả cho
   `intent_id` **vẫn ổn định** — mạnh hơn wildcard thuần, vì một client điền rác vào `relayer` ở chế
   độ mở không còn tạo ra một digest thứ hai cho cùng một ý định. Câu của bản 3 nói zeroing "xoá nguy
   cơ cross-mode replay mà bitmask tạo ra" là **sai ở cả hai vế**: bitmask không tạo ra nguy cơ đó
   (digest của `OPEN` và của `RESTRICT, relayer=0` vốn đã khác nhau vì `mode` nằm trong hash), và
   zeroing không phải thứ để xoá nó.

**Điểm quan trọng nhất của mục này, và nó vừa nặng thêm:** định dạng ở đây là **spec cho hai bản cài
đặt** (`_USER-DECISIONS.md` §21.3), không phải mô tả một bản. Nên nó cần ba thứ mà bản 2 không có:

1. **Wire format bằng văn bản**: encoding, cách tính `intent_id`, digest EIP-712, tên topic
   gossipsub, và thứ tự byte. Một bảng, không phải một struct Rust.
2. **Bộ vector tuân thủ dùng chung**: N intent mẫu kèm `intent_id` và digest kỳ vọng, trong repo,
   chạy trong CI của **cả hai** bản. Đây là thứ rẻ nhất chặn được drift.
3. **Test liên thông A↔B**: một node Rust và một node Odoo trong cùng mesh, gossip qua lại được, cả
   hai relay được một intent thật.

Thiếu (2), hai bản sẽ lệch trong vài tháng mà không ai biết cho tới lúc có tiền thật.

**Envelope v1.1 (đã bổ sung 4 field bản 1 thiếu):**

```json
{
  "spec": "scaas-intent/1.1",
  "intent_id": "0x9f3c…",
  "chain_id": 100,
  "chain_profile": "public",
  "verifying_contract": "0xF17…",
  "meta_tx": {
    "from": "0xA1…", "to": "0xB2…", "tokenContract": "0xC3…",
    "value": "0", "data": "0xa9059cbb…",
    "batch": "7412…", "nonce": "0",
    "mode": 32, "fee": "5000000000000000", "feeRecipient": "0x0…0",
    "validUntil": 1756500900,
    "relayer": "0x0…0"
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
  "hop_count": 0,
  "published_at": 1756500012,
  "bus_seq": 8814023,
  "hub": { "id": "hub.scaas.vn", "sig": "0x…" }
}
```

**[BẢN 4]** `meta_tx` mang một trường `mode` (`uint32`) và **không** có trường `feeMode`. Cách tính
phí là **nửa byte sau** của `mode`: `0x00 = NONE`, `0x10 = PERCENT`, `0x20 = FIXED`. Ví dụ trên
`"mode": 32` nghĩa là FIXED, không ràng buộc relayer, không ràng buộc feeRecipient.

Lập luận của bản 3 vẫn nguyên giá trị và nay được thoả bằng chính `mode`: cách tính phí **phải nằm
trong digest** — nếu không, relayer đổi diễn giải `fee` từ tuyệt đối sang ppm và người ký trả sai số
tiền. Với intent Zether, phí bắt buộc là `NONE` hoặc `FIXED`; `PERCENT` bị contract từ chối
(`FeePolicy.requireConfidentialSafe`) vì số tiền là ciphertext, không nhân tỉ lệ được.

Bốn bổ sung, và tại sao từng cái là bắt buộc chứ không phải trang trí:

| Field | Vì sao không thể thiếu |
|---|---|
| `sig_kind` (`eoa` / `erc1271`) | §04.4 chốt dùng `SignatureChecker.isValidSignatureNow` cho smart account. Relayer cần biết trước để (a) cộng ~9.000 gas vào báo giá và (b) biết rằng tính hợp lệ của chữ ký là **mutable** → phải re-simulate ngay trước khi broadcast. |
| `zether.*` | Node cần `from_schnorr` để enforce single-flight (§5.4.3) và cần `target_epoch` để tự hết hạn intent khi epoch trôi. Không parse được từ `data` nếu không decode ABI — đừng bắt node decode calldata tuỳ ý. |
| `beacon.{block,hash}` | Chống grinding lottery. Xem §5.4.4(a). |

`hub.sig` — bản 1 có field này nhưng không bao giờ nói nó ký cái gì. Chốt:

```
hub_sig_payload = keccak256(
    "scaas-hub/1" ‖ hub_id ‖ intent_id ‖ uint64(published_at)
                   ‖ uint64(beacon.block) ‖ beacon.hash
                   ‖ address(exclusive.relayer_id) ‖ uint64(exclusive.until))
```

Công dụng cụ thể, không phải "để xác thực": (1) relayer chứng minh được nó *được trao* exclusivity
khi tranh chấp với gateway; (2) một peer không sửa được `exclusive.*` khi re-publish; (3) khi gateway
công bố `beacon` sai (không khớp chain), bất kỳ ai cũng chứng minh được bằng một
`eth_getBlockByNumber`. Khoá công khai của gateway nằm trong `/policy` và trong `/peers`.

Trên mesh, `hub.sig` **không biến mất mà đổi vai**: nó không còn là chữ ký của một cơ quan, mà là
chữ ký của node đã gán exclusivity. Một node khác không phải tin nó — nó chỉ dùng để phân xử khi có
tranh chấp, và một node bịa `exclusive.*` sẽ bị peer scoring hạ điểm khi bị phát hiện. Đây là điểm
khác biệt cơ bản giữa hai lớp: gateway federation dùng **allowlist**, mesh dùng **danh tiếng đo
được**.

Quy tắc versioning (ghi vào `/intents/v1/policy`):

| Loại thay đổi | Hành động |
|---|---|
| Thêm field optional | Minor bump (`1.0` → `1.1`). Receiver **phải ignore field lạ** — không reject. |
| Đổi ý nghĩa field, xoá field, đổi cách tính `intent_id` | Major bump (`scaas-intent/2.0`) và **route mới** `/intents/v2/*` + **topic gossipsub mới**. Hai phiên bản chạy song song >= 90 ngày. |
| Thêm chain | Không bump. Chúng là data, không phải schema. `policy` liệt kê giá trị hợp lệ. |

Node từ chối `spec` có major không biết với `400 UNSUPPORTED_SPEC` và trả về danh sách major mình nói
được. Không bao giờ "cố gắng đoán".

**Một ngoại lệ mà bản 3 tuyên bố đã chết, và bản 4 phục hồi:** thêm một `mode` bit là thay đổi
schema đối với *contract*, vì §04.4 bắt buộc `validateMode` từ chối bit lạ. Bản 3 viết rằng nghĩa vụ
công bố `mode_known_mask` "chết cùng bitmask". **`mode` đã quay lại (`_USER-DECISIONS.md` §24), nên
nghĩa vụ đó quay lại nguyên vẹn:** `/policy` **phải** công bố `mode_known_mask` theo từng
`verifying_contract`, hôm nay là `0xF3`.

Và nó không chỉ là bit lạ ở nửa đầu. Nửa sau là **giá trị**, nên một `mode = 0x30` lọt qua mọi phép
kiểm mask nhưng là giá trị phí không tồn tại — contract cũ revert, contract mới có thể không. `/policy`
vì thế công bố **hai** thứ: `mode_known_mask` cho nửa đầu, và `fee_modes_supported` cho nửa sau, theo từng
`verifying_contract`, vì một token Zether chỉ nhận `NONE`/`FIXED`. Relayer từ chối trước khi simulate.

---

### 5.3. Relayer đánh giá lợi nhuận thế nào — và con số thật làm sập mô hình

Công thức hiển nhiên:

```
cost_native  = gas_used_estimate * effective_gas_price
revenue_nat  = metaTx.fee * FX(rewardToken -> native) + sponsor_quote
relay if:      revenue_nat >= cost_native * (1 + margin)     # margin mac dinh 0.30
```

Bản 1 viết `gas_limit_sim * effective_gas_price`. Đó là **ước lượng sai phía an toàn ngược**: relayer
trả gas theo `gasUsed` thực, không theo `gas_limit`, **nhưng** phải *có đủ* số dư để đặt `gas` bằng
`gas_limit` mình chọn. Hai con số khác nhau: cái thứ nhất là chi phí, cái thứ hai là vốn lưu động.

> **[BẢN 3]** `innerGasLimit` không còn trong struct (`_USER-DECISIONS.md` §24) — không còn inner
> call nên không còn phong bì gas trong chữ ký. `gas_limit` bây giờ là **quyết định của relayer**,
> lấy từ **bảng gas tĩnh theo selector** (§04.10) cộng biên, chứ không phải một trường người dùng ký.
> Điều này *làm mạnh thêm* lập luận vốn lưu động dưới đây, không làm yếu: relayer bây giờ tự chịu
> trách nhiệm chọn đúng, và chọn thừa thì tự khoá vốn của chính mình. Một relayer với 5 xDAI không thể phát 200 tx song song mỗi tx đặt `gas = 400_000` dù
tổng `gasUsed` chỉ là 30% — đây là lý do thực tế khiến relayer nhỏ không scale được, và nó không nằm
ở đâu trong bản 1.

**Và đây là chỗ acceptance policy (§21.1) trở thành một khái niệm kinh tế chứ không phải cấu hình.**
Công thức trên giả định relayer nào cũng tối đa hoá lợi nhuận trên từng intent. Một relayer đối tác
thì không: nó nhận `fee = 0` cho contract nó có quan hệ, thu hồi ngoài chuỗi. Với nó, `relay if` không
phải một bất đẳng thức về `revenue_nat` mà là một vị từ về `to` và `tokenContract` — rẻ hơn nhiều, vì
nó quyết định được **trước khi simulate**. Xem §5.7.

#### 5.3.1. Gas thật sự tốn bao nhiêu (ước lượng, có cơ sở)

| Thao tác | Gas (ước lượng) | Cơ sở |
|---|---|---|
| Intrinsic tx + calldata (~500 B non-zero) | ~29.000 | 21.000 + 16 gas/byte (EIP-2028) |
| `ECDSA.tryRecover` + EIP-712 hashing | ~4.500 | precompile `ecrecover` 3.000 + keccak |
| …nếu `sig_kind = erc1271` | +~9.000 | staticcall + logic ví (§04.4) |
| Ghi `meta_nonce` (SSTORE non-zero→non-zero, cold) | ~5.000 | 2.900 + 2.100 cold access (EIP-2929) |
| ERC-20 fee transfer tới `feeRecipient` | ~30.000–50.000 | tuỳ warm/cold của slot đích |
| Inner call (ERC-20 transfer nghiệp vụ) | ~35.000–50.000 | |
| Guard / event / return cap | ~8.000 | §04.6 |
| **Tổng meta-tx đơn giản** | **~112.000–146.000** | |
| **Zether `transferConfidential`, cấu hình 32/64 của §03.9** | **~342.000–422.000** | §04.10, đã cộng envelope |

**Sửa so với bản 1:** bản 1 ghi Zether là "2.500.000–6.000.000 gas". Con số đó là của cấu hình
**128/128** mà §03.2 và §03.9 **đã bác bỏ** (`MAX = 2^128 - 1` làm số dư không giải mã được). Cấu
hình đã chốt là `range_bits_value = 32`, `range_bits_balance = 64`, `scale_exponent = 2` — §03.3 cho
**~1,79 M gas** cho riêng phần verify+state, §04.10 cho **~342k–422k** cho toàn bộ lời gọi ghép khi
verifier chạy ở cấu hình này trên một verifier được tối ưu. Hai con số này chênh nhau và **§03 là
nguồn đúng cho phần mật mã học**: nếu verifier là `BulletproofsVerifier.sol` thuần Solidity thì
**~1,79 M**; con số 342k–422k của §04.10 chỉ đạt được với **native precompile** (private chain) hoặc
**Groth16** (public chain). Ghi cả hai vào bảng dưới và **đừng cam kết một con số cho cả
hai profile**.

Quy ra tiền (giả định giá gas ghi rõ, không giấu):

| Chain | Gas price giả định | Giá native | 130k gas | 1,79M gas (BP Solidity) | 400k gas (precompile / Groth16) |
|---|---|---|---|---|---|
| Gnosis xDAI | 1,5 gwei | $1,00 | **$0,000195** | **$0,00269** | **$0,00060** |
| Gnosis xDAI | 1,0 gwei (sàn tối thiểu phổ biến) | $1,00 | $0,000130 | $0,00179 | $0,00040 |
| Celo (fee currency cUSD) | ~5 gwei-equiv | $1,00 | ~$0,00065 | ~$0,0090 | ~$0,0020 |
| **Chain private 9000** | **0** (`MinGasPrice = 0`) | — | **$0** | **$0** | **$0** |
| Ethereum L1 | 25 gwei | $3.000 | $9,75 | **$134** | $30 |

Dòng chain private là dòng quyết định thứ tự triển khai: ở đó **toàn bộ mục 5.3 là no-op**. Không có
định giá, không có biên lợi nhuận, không có FX. Đó là lý do relayer không nằm trên đường tới hạn của
giai đoạn 1 (§5.0).

**Hai cảnh báo số liệu bản 1 không có:**

1. **EIP-7623 (calldata floor).** Trên chain đã bật Pectra, chi phí tx có sàn
   `21.000 + 40 × tokens` với `tokens = zero_bytes + 4 × nonzero_bytes`. Với một Zether proof ~1,4 KB
   gần như toàn non-zero: `tokens ≈ 5.600` → **sàn ≈ 245.000 gas**. Với Zether (execution ≥ 400k) sàn
   không ràng buộc. Với một intent "rẻ" mang calldata lớn (ví dụ anchor một merkle proof 2 KB rồi
   không làm gì), sàn **là** ràng buộc và relayer sẽ trả nhiều hơn `gasUsed` mô phỏng. Relayer client
   phải tính `max(gasUsed, floor)`; nếu không nó sẽ báo giá thấp và lỗ đúng ở loại intent này.

   Lưu ý phạm vi: chain private 9000 **chưa có cả London**, nên nó cũng chưa có EIP-7623. Sàn này chỉ
   áp dụng trên Gnosis/Celo. Đây là một ví dụ của việc "một công thức gas không kèm tên chain là một
   công thức sai" (`TRAPS.md`).

   Với BLS12-381, proof lớn gấp đôi (điểm 128 B thay vì 64 B), nên `tokens ≈ 11.200` và sàn ≈
   469.000 gas. Ở cấu hình precompile 400k thì **sàn trở thành ràng buộc** và chi phí thật là sàn chứ
   không phải execution. Một lý do nữa để bảng gas phải gắn với curve.
2. **Celo tính phí bằng fee currency có phụ thu.** Trả gas bằng cUSD đi qua hook debit/credit của
   validator, cộng thêm **vài chục nghìn gas** mỗi tx so với trả bằng CELO, và tx phải là
   type `0x7b` (CIP-64) chứ không phải type 2. `blockchain.md` §10.2.1 gọi chuẩn đó là **CIP-52** —
   CIP-52 là bản đề xuất cũ; bản đang chạy là **CIP-64** (thêm CIP-66 cho `maxFeeInFeeCurrency`).
   Phải kiểm lại trước khi code adapter Celo; sai ở đây nghĩa là relayer không ký được tx nào.

#### 5.3.2. Sai số kỹ thuật trong note gốc phải sửa

`blockchain.md` §10.5.2 mục 3 viết ZKP verify tốn "~180.000 – 250.000 gas". Con số đó không đúng cho
Bulletproofs trên alt_bn128, ở bất kỳ cấu hình bit nào.

- Sau EIP-1108, `ecMul` = 6.000 gas, `ecAdd` = 150 gas. Không có precompile MSM cho BN254 (EIP-2537
  chỉ cho BLS12-381), nên **mỗi điểm trong multi-exponentiation = 1 `ecMul` + 1 `ecAdd` + overhead
  staticcall ≈ 6.550 gas**. Không có Pippenger, không có windowing — precompile không cho phép.
- §03.3 đã làm bảng đầy đủ: `32/32` → ~1,25 M; **`32/64` (cấu hình chốt) → ~1,79 M**; `64/64` →
  ~2,10 M; `128/128` → ~3,79 M.
- 180k–250k chính xác là chi phí của **`ecPairing` 2–3 cặp** (45.000 + 34.000 × k) cộng vài `ecMul`
  tổ hợp public input — tức là **Groth16**, không phải Bulletproofs. Dấu vết nằm ngay trong note: nó
  viện dẫn `ecPairing` / EIP-197, mà **Bulletproofs không dùng pairing chút nào**.
- Bản 1 của section này nói "2,5M–6M" và suy ra từ `m*n = 512`. Đó là cấu hình 128-bit đã bị §03 bác
  bỏ. **Đã sửa.**

**Câu "không có precompile MSM cho BN254" đúng, nhưng đừng suy ra rằng BLS12-381 sẽ rẻ hơn.** EIP-2537
có `G1MSM` một lệnh, và đo thật trên Gnosis cho thấy ở đúng quy mô này (k = 277) nó tốn 1.741.589 gas
so với 1.703.400 của 277 `ecMul` rời — **đắt hơn ~2%** (`_USER-DECISIONS.md` §17). Lợi thế của một
lệnh là ở calldata và số lần vào/ra precompile, không ở gas.

**Hệ quả kiến trúc, không phải chi tiết:** con số 180k–250k chỉ đạt được bằng **Groth16/PLONK** (có
trusted setup, mạch cố định). Nếu giữ Bulletproofs (không trusted setup, đúng ý định của Zether),
phải chấp nhận ~1,79 M gas. §03.9 đã chốt: **Bulletproofs cho private profile, Groth16 cho public
profile**, `IZetherVerifier` pluggable.

Trên factory mở, "chốt" đó nhẹ hơn: hai verifier là **hai entry catalogue**, và người tạo token chọn
(`_USER-DECISIONS.md` §20). Section 05 chỉ cần kết luận một điều: **báo giá của relayer phải đọc
`proofSystemId()` của verifier**, vì cùng một intent Zether tốn 1,79 M hay 400k gas tuỳ token — và
trên factory mở thì hai token trên **cùng một chain** có thể khác nhau. Field `hints.gas_limit`
**phải** phản ánh điều đó, và node phải từ chối intent có `hints.gas_limit` lệch > 25% so với báo giá
của chính nó.

Trên Gnosis, 1,79 M gas = **$0,0018**. Hoàn toàn chấp nhận được, và đó chính là lý do quyết định khoá
#4 (Gnosis trước) và #5 (private trước) là đúng. Chỉ cần đừng viết 250k vào spec rồi để contract
engineer phát hiện ở tuần thứ 20.

#### 5.3.3. FX rate đến từ đâu, và điều gì xảy ra khi nó chạy

Ba nguồn, xếp theo độ tin cậy:

1. **`rewardToken` là stablecoin thanh khoản (USDC/USDT trên Gnosis) và native là xDAI.** FX ≈ 1,000
   ± 0,002. Độ lệch giữa lúc quote và lúc inclusion (5 s) là **dưới 1 basis point**. Vấn đề FX gần
   như biến mất. Đây là lý do thực sự khiến Gnosis/Celo là lựa chọn đúng — không phải vì rẻ, mà vì
   **nó xoá một biến khỏi bài toán của relayer**.
2. **`rewardToken` là enterprise token không có thị trường (Z-VND, loyalty point).** Không có giá thị
   trường → không được dùng oracle. **Giá được định nghĩa bởi cam kết mua lại của issuer:**
   `SponsorshipPool.redemptionRate(token) -> wei native / token unit`, công bố on-chain, có
   `validUntil` và chỉ đổi được với thông báo trước N ngày. Đây là một *hợp đồng*, không phải một
   *giá*. Relayer đọc nó bằng `eth_call` trong cùng lần simulate — zero risk.

   **Bản 1 thiếu một viên gạch:** `redemptionRate` chỉ có giá trị nếu relayer **đổi được** token ra
   native. Phải có `SponsorshipPool.redeem(token, amount)` trả xDAI theo đúng `redemptionRate`, với
   `dailyRedeemCap` và một quỹ xDAI có số dư kiểm tra được on-chain. Không có hàm `redeem`, con số
   `redemptionRate` là một lời hứa, và một relayer lý trí sẽ chiết khấu nó về 0. Bắt buộc công bố
   `redeemableBalance()` để relayer tự đánh giá rủi ro đối tác.
3. **Chainlink / DEX TWAP.** Chỉ dùng khi (1) và (2) không áp dụng. Thêm độ trễ 1–2 block và rủi ro
   oracle. Khuyến nghị: **không hỗ trợ trong v1.**

Biến động giữa quote và inclusion — cái thật sự chạy **không phải FX mà là gas price**:

- `metaTx.fee` đã bị khoá trong digest tại thời điểm user ký. Không ai bump được nó mà không xin chữ
  ký mới.
- Nếu base fee tăng 3x giữa lúc ký và lúc inclusion, intent đơn giản trở thành không sinh lợi và
  **không ai relay nó**. Nó hết hạn theo `expiry` và client ký lại với fee cao hơn. Đó là thị trường
  hoạt động đúng, không phải lỗi.
- Để client không ký ra intent chết: node công bố fee floor theo chain trong `/intents/v1/policy`,
  cập nhật mỗi block. **Công thức của bản 1 sai đơn vị:**
  `p90(gas_used_30d) * base_fee_now * 1.5` cho ra **wei native**, nhưng `metaTx.fee` tính bằng
  **reward token**. Công thức đúng:

```python
# dms_blockchain/lib/fee_floor.py — thuan Python, khong import odoo
def fee_floor_base(gas_p90: int, base_fee_wei: int, margin: float,
                   redemption_rate_wei_per_unit: int, require_success: bool) -> int:
    """Tra ve so base-unit cua rewardToken. So nguyen, khong float."""
    risk = 1.5 if require_success else 1.0                     # xem duoi
    native = int(gas_p90 * base_fee_wei * (1.0 + margin) * risk)
    return -(-native // redemption_rate_wei_per_unit)          # ceil div, khong lam tron xuong
```

Floor là một bộ ba `(chain_id, token, require_success)`, không phải một số cho mỗi chain. Lý do bắt
buộc, bản 1 không có: §04.6 chốt hành vi **bubble revert** = **relayer đốt gas và không được gì khi
inner call fail**. Một intent bubble có rủi ro cao hơn hẳn một intent swallow, nên **fee floor của nó
phải cao hơn**. Với tỷ lệ inner-fail quan sát được `p`, biên lợi nhuận yêu cầu là
`margin' = (1 + margin)/(1 - p) - 1`. Với `p = 5%`, `margin = 0,30` → `margin' = 0,37`. Với `p = 20%`
→ `margin' = 0,63`. Node phải đo `p` theo `(to, selector)` và công bố nó; nếu không, relayer sẽ tự đo
và tự đặt floor, và các relayer sẽ lệch nhau.

> **[BẢN 4] — cả mục fee floor theo `require_success` ở trên đã hết đối tượng.** Không còn inner
> `CALL` (`_USER-DECISIONS.md` §24), nên không còn cặp bubble/swallow, không còn `p` = tỷ lệ
> inner-fail, và không còn `risk = 1.5`. Floor quay về bộ **đôi** `(chain_id, token)`. Phần toán
> `margin' = (1 + margin)/(1 - p) - 1` vẫn đúng như một công thức, chỉ là `p` bây giờ đo **tỷ lệ tx
> revert toàn phần** (nonce không tăng, relayer mất gas, không thu được gì) — nhỏ hơn hẳn, vì
> contract kiểm đủ **trước** khi thu phí thay vì kiểm sau khi gọi ra ngoài.
>
> **Bản 3:** bản 2 gọi hành vi này bằng bit `MODE_REQUIRE_SUCCESS (0x04)`. Bit đó **chết hẳn** (không
> phải "bitmask bị loại" — bitmask còn, xem [BẢN 4] ở đầu file; cái chết là *inner call*). Bubble hay
> swallow nay là một **thuộc tính của contract đích**: contract quyết định nó bubble hay swallow, và relayer đọc điều đó từ `/policy`
> theo `(verifying_contract, selector)`. Cùng một hệ quả kinh tế, không còn một trường trong digest
> để va chạm.
>
> Toàn bộ mục `MODE_METERED_FEE (0x08)` của bản 2 **bị xoá**. Nó là một bit thứ tư trong một bitmask
> không còn tồn tại. Ý tưởng đằng sau nó — user ký `fee` như một **trần**, contract thu
> `min(signedFee, gasUsed × rate)` — vẫn có giá trị, nhưng nó phải quay lại dưới dạng một
> **archetype contract riêng** trong catalogue (§01.1.5), không phải một cờ trên struct dùng chung.
> Ai cần nó thì chọn version có nó. Ba chi tiết triển khai của bản 2 vẫn đúng và được chuyển sang mô
> tả của archetype đó: `gasUsed` phải cộng `GAS_OVERHEAD_CONST` đo bằng `forge test --gas-report`
> (không bù thì relayer luôn lỗ ~30.000 gas); `conversionRate` phải đọc **một lần** và đưa vào event;
> và nó không được kết hợp với `bps_of_value`.

#### 5.3.4. Con số làm sập giả định "thị trường relayer tự duy trì"

Đây là kết luận quan trọng nhất của section này.

Trên Gnosis, chi phí gas của một meta-tx là **$0,00013–0,0002**. Một biên lợi nhuận 30% cho relayer
là **$0,00004–0,00006/tx**. Ngay cả khi fee đặt gấp 10 lần gas (relayer ăn ~$0,0018/tx):

| Mục tiêu doanh thu relayer | Số tx/tháng cần có | tx/phút liên tục |
|---|---|---|
| $100/tháng | 55.600 | 1,3 |
| $1.000/tháng | 556.000 | 12,9 |
| $5.000/tháng (1 kỹ sư part-time) | 2.780.000 | 64 |

Và cột chi phí mà bản 1 không kể: một relayer thật phải chạy 1 VPS ($5–20/tháng), 1 RPC archive/full
node hoặc gói Alchemy ($0–50/tháng), giữ vốn xDAI (**~$50–200** để đặt `gas` cho tx song song),
và **thời gian người** để xử lý khi nó gãy. Điểm hoà vốn thực tế không phải $0 — là **$30–70/tháng**,
tức **~17.000–39.000 tx/tháng chỉ để không lỗ**.

Con số đó còn tăng khi tính pool khoá (`_USER-DECISIONS.md` §21.5): 50 khoá × float mỗi khoá là vốn
lưu động thật, và nó nằm chết ở đó.

Khối lượng DMS thực tế (visit, settlement, claim) không ở gần cột phải. **Kết luận: trên chain có gas
rẻ như Gnosis, phí bù gas không thể nuôi một thị trường relayer độc lập.** Ai đó sẽ vẫn relay, nhưng
không phải vì lợi nhuận — mà vì họ có lý do khác (là distributor trong hệ thống, là issuer, là đối
tác).

**Kết luận này là nền của toàn bộ mô hình acceptance policy**, và nó nên được đọc cùng
`_USER-DECISIONS.md` §3.4b. Một mạng relayer mở **không phải một thị trường đấu giá** — nó là một tập
node có động cơ khác nhau, phần lớn không phải động cơ lợi nhuận trên từng intent. Đó là lý do
`fee = 0` hợp lệ, là lý do ma trận §21.4 có `priority: high` cho contract đối tác, và là lý do "pool
thuần không có key" là một vai chính đáng chứ không phải một node ăn bám.

Ba lối thoát, phải chọn **trước khi** viết contract vì nó thay đổi struct:

| `fee_model` | Công thức | Khi nào dùng |
|---|---|---|
| `gas_reimburse` | `fee = gas * rate * (1+margin)` | Chain rẻ + relayer là consortium member. Mặc định |
| `flat` | `fee = const` theo loại intent | Loyalty point redeem, UX dễ giải thích. **Bắt buộc cho Zether** (§3.2: phí theo % làm lộ `v`) |
| `bps_of_value` | `fee = value * bps` (10 bps trên settlement $2.000 = **$2**) | **B2B settlement công khai.** Đây là chỗ duy nhất có biên lợi nhuận thật |

Ba dòng này ánh xạ đúng vào `FeeMode` của `FeePolicy.sol`: `gas_reimburse` và `flat` là `FIXED`,
`bps_of_value` là `PERCENT`, và `NONE` là trường hợp đối tác tài trợ.

`bps_of_value` yêu cầu contract biết `value`. Với Zether, `value` bị mã hoá → **`PERCENT` bị cấm ở
tầng contract**, không phải chỉ khuyến nghị (`FeePolicy.requireConfidentialSafe`). Lý do dứt khoát:
`fee = v × p` với `fee` và `p` công khai cho `v = fee / p` — toàn bộ Zether trở nên vô nghĩa.

Bản 2 đề xuất một lối vòng: `fee` vẫn là một số công khai do client tính, và ZKP chứng minh
`fee * 10000 - v * bps >= 0` bằng một range proof bổ sung. **Lối vòng đó không cứu được gì** — nó
chứng minh phí *đủ lớn*, nhưng chính con số `fee` công khai vẫn tiết lộ một chặn dưới của `v`, và
qua nhiều giao dịch thì chặn dưới đó dựng lại được hồ sơ (§3.3, bẫy bậc thang). Chi phí kỹ thuật của
nó cũng không nhỏ: theo bảng §03.3, **+~80 điểm MSM ≈ +525.000 gas** (không phải "+25%" như bản 1
ước), cộng ~0,1–0,3 s vào thời gian prove trên
Android (§03.8), và thời gian prove là thứ đang eo cổ của Zether, không phải gas.

**Khuyến nghị: `flat` cho Zether v1**, và đó cũng là điều `_USER-DECISIONS.md` §3.2 chốt độc lập, ở
mức mạnh hơn: phí Zether **bắt buộc** là hằng số theo `(token, chain)`, không phần trăm, không bậc
thang, không trần phụ thuộc số tiền.

Và nói thẳng hệ quả thương mại: nếu mô hình doanh thu của relayer là `bps_of_value`, thì **luồng tiền
có biên lợi nhuận lại chính là luồng tiền phải bị mã hoá**, và hai mục tiêu đó kéo ngược nhau. Đó là
một câu hỏi cho người, không phải cho kiến trúc — xem `open_questions`.

Có một lối ra mà bản 2 không thấy, và nó đến từ mô hình mở: **relayer đối tác không cần biên lợi
nhuận trên từng intent.** Nếu bên hưởng lợi từ giao dịch tự chạy node (`_USER-DECISIONS.md` §3.4b),
thì `fee = 0` và câu hỏi "ai trả cho relayer" không còn là câu hỏi kinh tế mà là câu hỏi vận hành:
họ trả cho chính mình. Đó là mô hình khả thi nhất cho B2B settlement bảo mật, và nó không đòi hy sinh
tính bí mật.

---

### 5.4. Front-running: tại sao nó không sao, và chỗ nào thì nó là vấn đề

#### 5.4.1. Chỗ không sao — và tại sao

Với intent mở, payload đã đầy đủ và tự uỷ quyền. Bất kỳ ai cũng `msg.sender` được. Cái gọi là
"front-run" ở đây là:

- `to`, `value`, `data`, `fee`, `mode`, `validUntil`, `batch`, `nonce` **đều nằm trong digest** →
  không sửa được một byte. (`_USER-DECISIONS.md` §24: `feeToken` và `innerGasLimit` không còn tồn
  tại; cách tính phí nằm ở **nửa byte sau** của `mode`.)
- `relayer` và `feeRecipient` là **wildcard `address(0)`** → kẻ "cướp" chỉ thay đổi được *ai được trả
  tiền*, và nó đang trả cho chính nó bằng cách chịu gas.
- Kết quả on-chain mà user nhận được là **byte-identical** bất kể ai submit.

> **Sửa cách diễn đạt so với bản 2.** Bản 2 viết `relayer` và `feeRecipient` "**không nằm trong
> digest** (canonical zeroing, §04.4)". Điều đó **đã sai** sau khi bỏ bitmask: cả hai **nằm trong
> digest** như mọi trường khác, và giá trị `address(0)` là một **quy ước** có nghĩa "bất kỳ ai" /
> "trả cho `msg.sender`". Khác biệt không phải học thuật — loại một trường khỏi digest tuỳ theo mode
> chính là cross-mode replay mà `_USER-DECISIONS.md` §5 đã loại bỏ.

Với Zether `withdraw`, `recipient` đã bị băm vào Fiat-Shamir challenge (note §10.5.3 mục 5, đúng) →
không đổi được. Với `transferConfidential`, `toSchnorrAddress` nằm trong ciphertext → không đổi được.

**Vì vậy: user hoàn toàn bàng quan về kết quả giao dịch.** Mọi cơ chế ở §5.4.4 tồn tại *chỉ* để bảo
vệ biên lợi nhuận của relayer. **Nhưng "bàng quan về kết quả" không đồng nghĩa với "bàng quan" —
xem §5.4.5, cái bản 1 bỏ sót hoàn toàn.**

#### 5.4.2. Chỗ là vấn đề: N relayer đua nhau, 1 thắng

Khi N relayer cùng broadcast một intent:

- 1 tx thành công, N−1 tx revert ở bước check đầu tiên. §04.5 chốt thứ tự check: **nonce trước
  (SLOAD 2.100), rồi expiry, rồi chữ ký**. Đó là một quyết định kinh tế có chủ đích: nó làm kẻ thua
  cuộc mất ít nhất.
- Tx revert **vẫn trả gas**: intrinsic 21.000 + calldata ~7.000 (calldata vẫn được tính đủ) + SLOAD
  nonce 2.100 ≈ **~24.000–30.000 gas** ≈ **$0,000024–0,000045** trên Gnosis (1–1,5 gwei).

Gas lãng phí tuyệt đối là không đáng kể. **Cái giết mô hình là biên lợi nhuận kỳ vọng, không phải
gas.**

Với `fee_net = $0,0018` (fee trừ gas của kẻ thắng), `revert_cost = $0,000024`, N relayer đồng đều:

```
EV(N) = (1/N) * fee_net - ((N-1)/N) * revert_cost
```

| N | EV/tx | So với N=1 |
|---|---|---|
| 1 | $0,001800 | 100% |
| 2 | $0,000888 | 49% |
| 3 | $0,000584 | 32% |
| 5 | $0,000341 | 19% |
| 10 | $0,000158 | **8,8%** |
| 20 | $0,000067 | 3,7% |
| **76** | **~$0,000000** | **0%** |

**Con số bản 1 bỏ sót, và là con số quan trọng nhất của mục này:** điểm cân bằng gia nhập tự do
(free entry, EV = 0) là

```
N* = 1 + fee_net / revert_cost = 1 + 0.0018 / 0.000024 ≈ 76
```

Tại `N*`, **toàn bộ phí của user bị đốt thành gas lãng phí**: `(N*−1) × revert_cost = fee_net`. Đây
là kết quả cổ điển của priority gas auction (rent dissipation) và nó nói một điều mạnh hơn bảng trên:
một cuộc đua không điều phối không chỉ làm relayer nghèo đi, nó **chuyển 100% phí của user thành rác
trên chuỗi**. Lý do duy nhất thực tế N không lên đến 76 là chi phí cố định của relayer (§5.3.4:
$30–70/tháng) và variance — tức là mạng **tự ổn định ở một số ít relayer lớn**, chính cái tập trung
hoá mà nó định tránh.

Kết quả chuẩn của một cuộc đua không điều phối: relayer nhỏ rút lui, còn lại 1–2 relayer lớn.
Soft-exclusivity (§5.4.4a) không phải một tính năng "hay có" — nó là thứ duy nhất giữ được **> 2
relayer** trong mạng.

**Trên mesh, có một lời giải thứ hai mà bản 2 không có, và nó rẻ hơn:** một node **từ chối thì chuyển
tiếp** (§5.1.0) thay vì cùng đua. Nếu ma trận của node A không nhận intent này, A không đua — A đẩy
nó tới B. Cuộc đua chỉ xảy ra giữa những node **cùng** chấp nhận cùng một intent, và acceptance policy
làm tập đó nhỏ đi đáng kể một cách tự nhiên. `N` trong bảng trên không phải số node trong mạng; nó là
số node có chính sách trùng nhau.

#### 5.4.3. Vấn đề nghiêm trọng hơn: Zether nonce không thể đua

Note không nói ra điều này. `zetherNonce(fromSchnorrAddress)` **được băm vào Fiat-Shamir challenge
của ZKP**, và §04.10 còn thêm `targetEpoch` vào ciphertext struct. Hai intent Zether đồng thời từ
cùng một `schnorrAddress`:

- Intent thứ hai không chỉ bị *reorder* — **proof của nó trở thành vô hiệu vĩnh viễn**, phải sinh lại
  proof. Chi phí prover theo §03.8: **0,2–0,5 s** (Android ARM64 native) đến **0,8–2,5 s** (WASM).
  Bản 1 ghi "200–800 ms" — thấp hơn thực tế trên nền tảng mà người dùng DMS thực sự dùng.
- `batchId` 2-D nonce của EIP-1776 **không cứu được**, vì điểm serialize nằm ở tầng Zether, không
  phải tầng envelope.

**Và đây là con số bản 1 không tính:** kẻ thua trong một cuộc đua Zether **không** revert ở 24.000
gas. Nếu hai intent *khác nhau* của cùng một schnorr address cùng được broadcast, envelope nonce của
chúng **khác nhau** nên cả hai đều qua tầng envelope; cái thứ hai chạy **hết** verify Bulletproofs
rồi mới fail ở `zetherNonce`. Chi phí thật: **~1,79 M gas ≈ $0,0018** — bằng đúng cả khoản fee.
**Va chạm Zether đắt gấp 75 lần va chạm thường.** Đó là lý do single-flight không phải tối ưu hoá
mà là bắt buộc.

**Ràng buộc bắt buộc:** node phải enforce **single-flight theo `from_schnorr_address` cho mọi intent
Zether**.

Trên mesh, ràng buộc này **khó hơn** vì không có một điểm nào thấy hết. Hai node khác nhau có thể mỗi
node nhận một intent của cùng một `schnorr_address` và cả hai cùng submit. Ba cách xử lý, xếp theo
mức độ thực tế:

| Cách | Hiệu quả | Chi phí |
|---|---|---|
| Gossip một bản ghi `inflight(schnorr_address, until)` trên topic riêng | Tốt trong điều kiện bình thường, không đảm bảo dưới phân mảnh mạng | Rẻ, ~50 B/intent |
| Đưa intent Zether vào **private pool** (§21.4) thay vì mesh mở | Đảm bảo, vì chỉ một bên phục vụ | Mất tính mở cho đúng luồng cần nó nhất |
| Chấp nhận va chạm và để client ký lại | Đơn giản nhất | $0,0018 mỗi lần, cộng 0,2–2,5 s prove lại |

**Khuyến nghị: gossip `inflight` + chấp nhận va chạm còn sót.** Nó không đảm bảo, nhưng va chạm còn
sót là hiếm và giá của nó đã biết. Private pool dành cho luồng B2B giá trị cao, nơi $0,0018 không
phải vấn đề mà độ trễ mới là vấn đề.

**Sửa kỹ thuật Odoo so với bản 1.** Bản 1 đưa ra hai lựa chọn như thể cả hai đều viết được bằng
`models.Constraint`. Không phải:

- `models.Constraint(definition, message)` sinh ra `ALTER TABLE … ADD CONSTRAINT <name> <definition>`.
  Một `EXCLUDE (…) WHERE (…)` **là** một table constraint hợp lệ → viết được, **nhưng** cần extension
  `btree_gist` (vì toán tử `=` trên `varchar` không có trong GiST mặc định), và `CREATE EXTENSION`
  cần quyền superuser trên Postgres. Trên stack này đó là một phụ thuộc vận hành, không phải một dòng
  code.
- Một **partial unique index** không phải table constraint. `UNIQUE (col) WHERE …` **không** là SQL
  hợp lệ trong `ADD CONSTRAINT`. Không viết được bằng `models.Constraint`.

Cách đúng, không cần extension:

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

Kiểm chứng bằng SQL, đừng tin code (CLAUDE.md §5 mục 2):

```sql
SELECT indexname, indexdef FROM pg_indexes
 WHERE tablename = 'blockchain_metatx' AND indexname LIKE '%zether%';
```

Intent Zether tiếp theo của cùng account nằm ở `state = 'queued'` cho đến khi cái trước `final` hoặc
`expired`. Đây là một **head-of-line block có thật** mà kiến trúc 2-D nonce không xoá được — phải nói
rõ trong tài liệu, không được bán 2-D nonce như là "loại bỏ hoàn toàn head-of-line blocking" cho
luồng Zether.

**Trần thông lượng mà bản 1 không tính.** Single-flight + epoch 25 s (Δ = 5 block × 5 s trên Gnosis)
= **tối đa 1 confidential tx / 25 s / schnorr address = 3.456 tx/ngày/address**. Một ví treasury
trả 500 distributor một lần/tháng thì không sao. Một ví treasury trả 5.000 outlet mỗi ngày thì
**vượt trần**. Đường ra, chọn trước:

```
K_addresses = ceil(peak_tx_per_second * epoch_seconds * safety)
# vi du: 2 tx/s dinh diem, epoch 25 s, safety 1.5  ->  K = 75 schnorr address
```

Sharding ví treasury thành K `schnorrAddress` là miễn phí về mặt giao thức (registry là singleton,
`register()` một lần mỗi address) nhưng **không** miễn phí về mặt kế toán: số dư bị chia nhỏ và
phải có một job re-balance. Ghi vào `open_questions`. Một cách tránh: gộp nhiều người nhận vào một
`transferConfidential` **không làm được** trong Zether nguyên bản (một receiver mỗi tx) — nên sharding
là đường duy nhất.

Có một liên hệ đáng ghi với `_USER-DECISIONS.md` §21.5: sharding `schnorrAddress` ở tầng người gửi và
pool khoá ký ở tầng relayer là **cùng một bài toán** — một định danh tuần tự là một nút thắt, và lời
giải duy nhất là nhiều định danh. Hai chỗ, cùng hình dạng, và cả hai đều trả giá bằng vốn bị phân
mảnh.

#### 5.4.4. Các biện pháp, xếp theo thứ tự nên dùng

**(a) Soft-exclusivity window — khuyến nghị làm mặc định cho intent thường, TẮT cho Zether.**

Node gán `exclusive.relayer_id` và `exclusive.until = published_at + W` (W mặc định **3 s** trên
Gnosis ≈ 0,6 block; **W = 0 cho `is_zether`**, lý do ở §5.1.1). Người thắng được chọn **tất định**,
nên mọi node tính ra cùng kết quả mà **không cần round-trip nào**. Tính tất định là điều kiện để cơ
chế này chạy được trên mesh chứ không chỉ trên một hub — không có nó, hai node gán hai người thắng
khác nhau và cửa sổ độc quyền vô nghĩa.

**Hai lỗ hổng cryptoeconomic trong bản 1, cả hai đều làm cơ chế này vô dụng:**

**Lỗ hổng 1 — `sqrt(stake)` không chống sybil, nó *thưởng* sybil.** Bản 1 viết
`weights = isqrt(stake) * reputation` với lý do "một cá voi 100x stake chỉ có 10x cơ hội". Nhưng với
trọng số căn bậc hai, tách stake `S` thành `k` danh tính cho ra tổng trọng số
`k · sqrt(S/k) = sqrt(k) · sqrt(S)` — tức **nhân trọng số lên `sqrt(k)` lần, miễn phí**. Với `k = 100`
danh tính, một cá được **10x** trọng số so với khi trung thực. Trọng số căn bậc hai chỉ có ý nghĩa
khi có một registry danh tính duy nhất (đó là tiền đề của quadratic funding); ở đây không có.

**Fix:** trọng số **tuyến tính** (`k · S/k = S`, sybil-neutral) × reputation, cộng một **min bond**
`B` (chặn số danh tính ở `S/B`) và một **trần tỷ trọng** áp thẳng vào điều mình thực sự muốn:

```python
# dms_blockchain/lib/lottery.py — thuan Python, khong import odoo, pytest duoc
CAP_SHARE = 0.20          # khong ai duoc qua 20% so lan boc
REP_FLOOR = 0.10          # relayer moi van co cua vao

def pick_exclusive(intent_id: bytes, beacon_hash: bytes, snapshot_root: bytes,
                   relayers) -> str:
    """relayers: [(relayer_id, stake_base:int, reputation:float)], da sap xep theo relayer_id.
    Tat dinh: moi node tinh ra cung ket qua tu cung dau vao."""
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

**Lỗ hổng 2 — nguồn ngẫu nhiên của bản 1 bị người ký *grind* được, miễn phí.** Bản 1 bốc bằng
`keccak256(intent_id + snapshot_root)`. `intent_id` là EIP-712 digest, phụ thuộc `batchId`, và
`batchId` là **256 bit do client tự chọn tự do** (§04.3). Client thử một `batchId` mới = **2 phép
keccak**, không cần ký. Với 50 relayer, kỳ vọng **~50 lần thử ≈ vài micro-giây** để đặt exclusivity
vào đúng relayer mình muốn. Chữ ký chỉ cần ký **một lần** ở cuối. Tức là: một relayer thông đồng với
user có thể **luôn** tự trao exclusivity cho mình, và lottery trở thành trang trí.

**Fix:** dựa vào một **beacon không đoán được tại thời điểm ký**. Rẻ nhất và đủ: block hash của head
tại lúc **node nhận** intent.

```
draw_seed = keccak256(intent_id ‖ beacon.hash ‖ snapshot_root)
```

Ràng buộc để peer kiểm được: `beacon.block` phải nằm trong **8 block gần nhất** so với head của node
nhận, và `beacon.hash` phải khớp `eth_getBlockByNumber` của chính peer đó. Node gốc điền `beacon`, ký
nó trong `hub.sig`, peer verify. Người ký không thể grind vì `beacon.hash` chưa tồn tại lúc nó ký.
Chi phí: 0 gas, 1 RPC call mà node vốn đã có (nó cache head).

`snapshot_root` cũng nên bỏ phần "hub ký và công bố mỗi giờ" của bản 1 và thay bằng một định nghĩa
tất định hơn: **tập relayer active đọc từ `RelayerRegistry` tại `beacon.block`**, sắp theo địa chỉ,
`snapshot_root = keccak(abi.encode(sorted_addresses, stakes))`. Mọi node tự tính ra cùng một giá trị
từ cùng một block — **không còn cửa sổ chuyển giao 30 s và không còn hai node chọn hai người thắng**.
Bản 1 phải xử lý cửa sổ đó bằng cách "chấp nhận cả hai snapshot", mà chấp nhận cả hai chính là tạo ra
N = 2 đúng vào lúc tệ nhất.

Tính tất định này là **điều kiện để cơ chế sống được trên mesh**. Trên một hub duy nhất, "hub ký và
công bố" còn tạm chạy; trên một mesh không có trung tâm thì nó không có nghĩa gì. Suy ra mọi thứ từ
`beacon.block` là cách duy nhất để N node độc lập đồng ý mà không nói chuyện với nhau.

Các tính chất còn lại giữ nguyên từ bản 1:

- **Không enforce on-chain.** Enforce on-chain nghĩa là điền tên relayer vào `relayer` thay vì
  `address(0)`, và như vậy mất luôn đường lui khi relayer được chọn chết máy — **và mất luôn khả năng
  xoay khoá ký** (`_USER-DECISIONS.md` §21.5). Enforce bằng reputation.
- Sau `until`, intent trở thành free-for-all thật sự. Trên Gnosis: `W = 3 s` chỉ hy sinh <1 block
  latency ở trường hợp xấu nhất.

Hiệu quả định lượng: EV của relayer trở về ~85–95% mức N=1 (mất phần nhỏ vì intent bị bỏ lỡ phải đợi
qua W), thay vì 19% ở N=5.

**(b) Reputation.** `blockchain.relayer.reputation_score` (§10.4.5 đã khai báo, computed store=True,
**mọi nhánh phải gán giá trị**), EWMA với decay 0,98/ngày:

```
score = 0.6 * fill_rate + 0.3 * latency_score + 0.1 * uptime
fill_rate     = inclusions_confirmed / claims_granted     # nhan exclusivity roi khong lam -> tut
latency_score = clamp(1 - (median_latency_ms - 2000) / 8000, 0, 1)
```

**Sửa so với bản 1, quan trọng về mặt công bằng:** `fill_rate` phải đếm **`inclusions_confirmed`**
(tx có mặt trong block, bất kể `innerSuccess`), **không** đếm thành công nghiệp vụ. Ở chế độ swallow
mặc định (§04.6), `innerSuccess = false` vẫn là một tx thành công và relayer **đã làm đúng việc của
nó** — nó bán blockspace, không bán kết quả nghiệp vụ. Trừ điểm relayer vì một inner call revert là
phạt sai người, và nó sẽ làm mọi relayer từ chối intent của những target hay revert. Tỷ lệ
inner-fail thuộc về **`(to, selector)`**, không thuộc về relayer, và nó là đầu vào của fee floor
(§5.3.3), không phải của reputation.

Relayer bỏ cuộc 3 lần liên tiếp → `reputation_score` về gần `REP_FLOOR` trong ~5 intent → hầu như
không được chọn nữa. Đó là hình phạt đủ cho một vụ $0,005.

**Bổ sung cho mesh:** công thức trên chấm relayer theo hành vi *submit*. Một **pool thuần** không có
khoá thì không bao giờ submit, nên nó có `fill_rate` không xác định và bị đánh giá là vô dụng — sai.
`_USER-DECISIONS.md` §21.4 chốt chiều thứ hai: chấm theo **forward có ích**, tức intent mà node này
chuyển tiếp và sau đó thật sự lên chain. Hai điểm số, hai vai, và một node có thể có cả hai:

```
score_submit  = 0.6 * fill_rate + 0.3 * latency_score + 0.1 * uptime
score_forward = useful_forwards / total_forwards        # "useful" = intent do sau nay landed
```

Chấm forward theo **kết quả** chứ không theo **lưu lượng** là điểm mấu chốt: chấm theo lưu lượng thì
một node bơm rác được điểm cao. Điều kiện để đo được: node phải thấy receipt — nên `/receipt` (§5.2)
là đầu vào của hệ thống danh tiếng, không chỉ một tiện ích vận hành.

**(c) Commit-reveal — phân tích và loại bỏ cho v1.**

Commit-reveal (relayer commit `keccak(intent_id ‖ salt ‖ addr)`, reveal ở block sau) thêm **ít nhất
1 block (5 s) và 1 tx (~25k gas, gấp 20% chi phí relay)**, và **không ngăn được node operator rò rỉ
intent** — mà node là kẻ duy nhất có thể front-run sớm nhất. Nó giải quyết đúng bài toán sai.

Giá trị thật của commit-reveal chỉ xuất hiện khi **nội dung intent có MEV** (swap, liquidation).
EIP-1776 intent cho DMS (chuyển token, ghi nhận settlement, redeem point) không có MEV **với một
ngoại lệ đã xác định — xem §5.7: `dailyCap` của sponsorship pool là một tài nguyên tranh chấp và đó
là một bề mặt MEV thật.** Biện pháp đúng ở đó là per-relayer sub-cap, không phải commit-reveal.

Trên mesh có một lời giải đơn giản hơn nhiều cho cùng bài toán, và nó đã có sẵn: **private pool**
(`_USER-DECISIONS.md` §21.4). Intent nào có MEV thì đừng gossip nó — đưa vào private pool và để một
relayer được chỉ định lấy. Đó là mô hình private mempool, đã được chứng minh trên Ethereum, và nó
không tốn thêm một block nào.
**Loại bỏ.** Bản 2 ghi là "có thể thêm sau bằng `mode` bit `0x10`". **[BẢN 4] không còn chỗ đó**:
`0x10` nay là `MODE_FEE_PERCENT` ở nửa byte phí, và nửa byte cờ chỉ còn `0x04`/`0x08` trống. Nếu
sau này thật sự cần, nó lấy `0x04` — nhưng cấp bit là việc của §04.4, không phải của section này,
và bài toán MEV đã có private pool giải rồi nên đừng cấp.

**(d) Priority by stake ngoai lottery.** Khong can. Stake da vao lottery weight o (a). Them mot co
che uu tien thu hai la chong cheo.

#### 5.4.5. Cái bản 1 bỏ sót hoàn toàn: intent bus là một kênh rò rỉ dữ liệu

Intent mở nghĩa là **mọi relayer, và mọi người gọi được `/pending` hoặc nghe được topic gossip, đọc
được toàn bộ calldata** trước khi nó lên chuỗi. Bản 1 kết luận "user hoàn toàn bàng quan" — đúng về
*kết quả giao dịch*, sai về *bảo mật thương mại*, và bảo mật thương mại là lý do tồn tại của cả
chương Zether.

| Luồng tiền | Cái gì rò rỉ qua bus | Mức độ |
|---|---|---|
| Zether `transferConfidential` | `fromSchnorr`, `toSchnorr`, `metaTx.fee` công khai. **Số tiền và số dư: không.** | Chấp nhận được — đúng thiết kế Zether |
| ERC-20 transfer thường (B2B settlement) | **Toàn bộ**: người trả, người nhận, số tiền, token, thời điểm | **Nghiêm trọng trên private profile** |
| Loyalty redeem | Địa chỉ outlet, số điểm | Thấp |
| Anchor hash | Chỉ hash | 0 |

**Điểm chết nằm ở profile `private`.** Mục đích của chain riêng là giữ dữ liệu trong vành đai. Một
intent bus công khai là **đường duy nhất dữ liệu đó đi ra ngoài**, và nó đi ra **trước** khi lên
chuỗi. Bản 1 không nhắc đến điều này ở bất kỳ đâu.

**Và mesh làm vấn đề này nặng hơn hẳn một hub.** Một hub nội bộ chặn được bằng mTLS và một dòng
nginx; một mesh gossip thì **phát tán là hành vi mặc định của nó**. Đây là lý do `pool: private` của
`_USER-DECISIONS.md` §21.4 không phải một tuỳ chọn tiện ích mà là **yêu cầu bảo mật của chain riêng**.

Quy tắc chốt, ghi thẳng vào §5.0:

1. `chain_profile = private` → intent của chain đó **không bao giờ** gossip ra mesh công khai, kể cả
   dưới dạng summary. Node cấu hình `pool: private`, `peers_allowed` là danh sách rõ ràng, mTLS bắt
   buộc cả hai chiều. Đây phải là **mặc định suy ra từ `chain_profile`**, không phải một cờ ai đó nhớ
   bật — một node cấu hình sai ở đây làm rò rỉ toàn bộ luồng B2B mà không có triệu chứng nào.
2. `chain_profile = public` + luồng tiền có số tiền nhạy cảm → **bắt buộc Zether**, hoặc đưa vào
   private pool với một relayer đã ký NDA. Không được để một B2B settlement $200.000 đi qua mesh mở
   "vì đằng nào nó cũng lên chuỗi" — nó lên chuỗi **sau**, và trước đó nó là thông tin giao dịch chưa
   thực hiện, tức là có giá trị MEV/cạnh tranh.
3. Odoo phải enforce điều 2, không phải con người:
   `blockchain.chain.max_public_intent_value_base` (Char uint256). Builder từ chối publish lên mesh
   mở khi `amount > ngưỡng` và `not confidential`. Một `_check` đơn giản, và nó là thứ đứng giữa một
   kỹ sư vội với một sự cố báo chí.

Một hệ quả thứ hai: `hints.fee_value_native` và `hints.gas_limit` **rò rỉ hình dạng của intent** ngay
cả khi calldata bị cắt. Trên private profile đó không quan trọng; trên public profile nó là lý do
`fields=summary` (§5.1.2) không được chứa `data`.

Và một hệ quả thứ ba, đến từ mô hình chuyển tiếp (§5.1.0): **một node chuyển tiếp một intent nó không
nhận vẫn thấy toàn bộ nội dung của intent đó.** Chuyển tiếp không phải chuyển tiếp mù. Nên "node nào
được thấy gì" là một quyết định của `peers_allowed`, không phải một hệ quả tình cờ của topology.

---

### 5.5. Sybil resistance và DoS

Chi phí tạo một intent giả = một chữ ký ECDSA ≈ 50 µs. Chi phí để node xác minh nó *thật sự* là tiền:
một `eth_call` simulate tốn **15–40 ms** trên local node (**60–150 ms** nếu là Zether, vì node phải
verify Bulletproofs). Tỷ lệ tấn công **~500:1**, lên **~3.000:1** với Zether. Đây là lỗ hổng DoS thực
sự, không phải ở tầng mạng.

Hàng rào theo thứ tự, rẻ trước:

| Tầng | Cơ chế | Chi phí cho attacker | Chi phí cho node | Đặt ở đâu |
|---|---|---|---|---|
| 0 | Rate limit theo IP (`60 req/min`), body cap 32 KB | Cần botnet | ~0 | **nginx `limit_req`**, không phải Odoo |
| 1 | Rate limit theo `meta_tx.from` (`10 intent/phút`, `100/giờ`) | Cần nhiều địa chỉ | 1 Redis INCR | Redis (không phải biến module) |
| 2 | Sanity offline: `expiry` trong tương lai và `<= max_expiry`, `fee >= fee_floor(chain, token, fee_mode)`, `to` trong allowlist, chữ ký recover ra đúng `from`, `innerGasLimit <= chain.max_inner_gas` | ~0 | ~1 ms | Python thuần |
| 3 | **Gate ai được simulate**: `from` phải (a) có `nonce > 0` on-chain, HOẶC (b) có `sponsor.policy_id` hợp lệ, HOẶC (c) **JWT hợp lệ từ `bamboo_token_auth`**, HOẶC (d) kèm PoW hashcash 20 bit | (d) ≈ 1M keccak ≈ **0,3–1 s CPU** | ~0,3 ms verify | Python + Redis |
| 4 | `eth_call` simulate; drop nếu revert | — | 15–150 ms | RPC pool |
| 5 | Chia sẻ ban list giữa các node qua `/intents/v1/peers` (feed ký) | — | ~0 | cron |

Hàng "tầng 2" đã bỏ `mode & ~mask == 0` — không còn bitmask (`_USER-DECISIONS.md` §5). Thay vào đó
là kiểm ma trận §21.4, và nó **rẻ hơn** vì chỉ so khớp trên trường có sẵn.

**Trên mesh, gossipsub v1.1 thêm một tầng −1 mà bảng trên không có: peer scoring.** Nó chặn ở tầng
mạng trước cả nginx, và nó là thứ duy nhất trong danh sách này hoạt động khi kẻ tấn công **là một
peer** chứ không phải một client. Đó là lý do chính để không tự viết giao thức (§5.1).

**Bốn sửa so với bản 1:**

1. **Tầng 0 không được làm trong Odoo.** Mỗi Odoo worker là một process riêng; một bộ đếm trong biến
   module đếm sai theo hệ số `workers`. Rate limit theo IP thuộc về **nginx** (`limit_req_zone
   $binary_remote_addr zone=intents:10m rate=60r/m;`). Rate limit theo `from` (tầng 1) cần trạng thái
   chia sẻ → **Redis**, cùng cụm mà §06 đã dùng cho nonce manager. Ghi rõ để người triển khai không
   viết một decorator vô dụng.
2. **Thêm lựa chọn (c): JWT.** CLAUDE.md §6 chốt rằng client gọi backend qua `bamboo_token_auth` JWT.
   Một user DMS đã đăng nhập **đã là** một danh tính — bắt nó làm PoW là vô nghĩa. PoW chỉ dành cho
   người lạ hoàn toàn.
3. **PoW 20 bit quá nặng cho mobile.** 1M keccak trong JS thuần trên Android tầm trung ≈ **200k
   hash/s → 5 s**, và người dùng đang dùng một app bán hàng. Nếu buộc phải có PoW cho mobile: hạ
   xuống **16 bit** (~65k keccak ≈ 0,3 s) và bù bằng tầng 1 chặt hơn. Nhưng đúng nhất là: mobile luôn
   đi đường (c), không bao giờ chạm PoW.
4. **Storage DoS — loại bản 1 không nhắc.** Một botnet 10.000 địa chỉ × 10 intent/phút = **1.667
   intent/s**. Chi phí ecrecover (`coincurve`) ≈ 50–100 µs → 0,17 s CPU/s: không sao. Chi phí **ghi**
   mới là vấn đề: 1.667 row/s × ~1,5 KB = **2,5 MB/s = 216 GB/ngày**. **Quy tắc: không persist gì
   trước tầng 3.** Intent chưa qua tầng 3 sống trong Redis với `TTL = expiry - now`, key
   `intent:pending:<intent_id>`. Chỉ khi qua tầng 4 mới `create()` một row `blockchain.metatx`.

**Năng lực thực tế:** một gateway worker Odoo (`auth='public'`, `save_session=False`, một query index)
≈ **150–400 req/s**; simulate là nút cổ chai thật: **~25–60 simulate/s/worker** (không Zether),
**~7–16/s** (Zether). 4 worker ≈ 100–240 simulate/s. Một flood 10.000/s **phải bị chặn ở tầng 0–3**,
không bao giờ đến tầng 4. PoW 20 bit đưa trần của một máy tấn công đơn về ~1–3 intent/s — đủ.

**Lưu lượng lưu trữ ở chế độ bình thường:** 1.000 intent/ngày (khối lượng DMS thực tế) × ~2 KB =
**2 MB/ngày ≈ 730 MB/năm**. Không cần partition. Chính sách giữ:

| Trang thai | Giu | Ly do |
|---|---|---|
| `final`, `reverted` | vĩnh viễn | vết đối soát, là bằng chứng |
| `expired`, `superseded` | 30 ngày | chỉ để debug |
| chưa qua tầng 3 | không bao giờ ghi DB | Redis TTL |

PoW bits là config (`ir.config_parameter` `blockchain.intent.pow_bits`), tăng tự động khi hàng đợi
simulate > 500. **Tắt hoàn toàn khi `chain_profile = private`.**

Một loại DoS thứ hai ít ai nghĩ đến: **intent hợp lệ nhưng cố ý không sinh lợi** (fee = 1 wei).
Chúng không tốn simulate nếu tầng 2 kiểm `fee >= fee_floor` trước. Đó là lý do tầng 2 phải đứng trước
tầng 4.

**Nhưng quy tắc đó có một ngoại lệ bắt buộc, và bỏ sót nó là chặn nhầm luồng quan trọng nhất:**
`fee = 0` là **hợp lệ** khi có nhà tài trợ hoặc khi contract là đối tác của node
(`_USER-DECISIONS.md` §3.4b). Tầng 2 phải kiểm `fee >= fee_floor` **hoặc** intent khớp một mục
`min_fee: 0` trong ma trận §21.4 **hoặc** có `sponsor.policy_id` hợp lệ. Một node lọc thẳng `fee = 0`
sẽ vứt đúng luồng onboarding và đúng luồng đối tác.

Và một loại thứ ba, rẻ nhất cho kẻ tấn công, bản 1 không có: **rút `approve` sau khi đã publish.**
Fee được thu bằng `safeTransferFrom(m.from, feeRcp, m.fee)` (§04.6) nên nó cần allowance của `from`
cho forwarder. Kẻ tấn công publish 100 intent hợp lệ, chờ relayer simulate và broadcast, rồi
`approve(forwarder, 0)` trong cùng block. Mọi tx broadcast revert; relayer mất gas; kẻ tấn công mất
**một** tx. Tỷ lệ thiệt hại 100:1. Biện pháp:

- `hints.allowance_ok` do node kiểm ở tầng 4 (một `eth_call allowance`) — chặn trường hợp vô tình.
- **`blockchain.relayer` có `origin_grief_score` theo `meta_tx.from`**, không phải theo relayer: 3 lần
  revert do allowance trong 24 h → `from` đó bị đẩy về tầng 3 lựa chọn (d) (PoW) và bị hạ
  `max_inflight` xuống 1.
- Đường bản chất: ưu tiên `ERC-2612 permit` / Permit2 nơi target hỗ trợ, khi đó allowance nằm
  **trong** chính tx và không rút được. Ghi vào `open_questions` vì nó chạm vào thiết kế token (§01).

---

### 5.6. Staking và slashing: làm ít hơn note gốc đề nghị

Câu hỏi đúng phải hỏi trước: **relayer thực sự có thể làm gì sai?**

| Hành vi | Có thể không | Thiệt hại | Cần slashing? |
|---|---|---|---|
| Sửa nội dung intent | **Không** — digest chặn | 0 | Không |
| Ăn cắp tiền | **Không** — `feeRecipient` là thứ duy nhất nó đổi được, và nó đang trả cho chính nó | 0 | Không |
| Đổi `recipient` của Zether withdraw | **Không** — băm vào Fiat-Shamir | 0 | Không |
| Nhận exclusivity rồi không submit | Có | Trễ `W` = 3 s | **Không** — reputation là đủ |
| Kiểm duyệt (nhận intent, không relay, không báo) | Có | Trễ đến khi có node khác nhặt sau `W` | Không — mesh tự re-publish |
| Submit tx biết chắc sẽ revert để đốt subsidy | Có | **Chỉ khi subsidy trả theo *lần thử*** | **Không — sửa thiết kế: subsidy chỉ trả khi inclusion thành công** |
| Claim subsidy cho intent mình không relay | **Không** — pool kiểm `msg.sender == relayer` trong chính tx | 0 | Không |
| ~~**Cấp `gas` thấp cố ý để inner call OOG rồi vẫn ăn fee**~~ (swallow mode) | **Hết đối tượng** — [BẢN 3] không còn inner `CALL`, không còn 63/64 | 0 | Không — đã chặn on-chain |
| **Đọc intent trên bus rồi không relay, chỉ để thu thập dữ liệu thương mại** | **Có** | Rò rỉ thông tin (§5.4.5) | **Không slashing** — chặn bằng quyền truy cập (`peers_allowed`, private pool), không bằng tiền |
| **Rút `dailyCap` của sponsorship pool trước đối thủ** | Có | Đối thủ mất gas một tx | Không — sửa thiết kế: per-relayer sub-cap (§5.7) |
| **Chuyển tiếp rác để cày điểm forward** | Có | Băng thông của peer | Không — chấm theo **forward có ích** (§5.4.4b) làm nó vô giá trị |
| **Nhận intent vào private pool rồi không làm gì** | Có | Intent chết im lặng | Không slashing — **promote-to-open sau `T`** (§21.4) là biện pháp đúng |

**Kết luận: v1 không có slashing tự động.** Xây một hệ adjudication on-chain (challenge period, fraud
proof, arbiter) cho một khiếu nại trị giá $0,005 là vô lý về mặt kinh tế — chi phí challenge tx đã
lớn hơn thiệt hại.

Hai dòng cuối là bổ sung của bản 3, và cả hai củng cố cùng kết luận: các hành vi xấu mới mà mô hình
mesh mở ra đều có **biện pháp cấu trúc** rẻ hơn slashing. Đó là một tính chất tốt của thiết kế, không
phải may mắn — nó đến từ việc relayer không bao giờ giữ tiền của ai.

Cái `RelayerRegistry` **vẫn cần**, nhưng với một công việc khác: **stake là trọng số cho lottery ở
§5.4.4(a) và là hàng rào sybil cho exclusivity**, không phải bảo chứng hành vi.

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

**Một điều bản 2 không nói và mô hình mesh làm nó rõ:** stake ràng buộc một **địa chỉ**, còn một
relayer có **pool nhiều khoá ký** (`_USER-DECISIONS.md` §21.5). Hai thứ không cùng một danh tính.
Stake phải gắn với một `relayer_id` (địa chỉ danh tính, lạnh, không bao giờ ký tx), và pool khoá ký
được **khai báo** dưới `relayer_id` đó qua một `registerSubmitter(address)`. Không có bước này, một
relayer 50 khoá hoặc phải stake 50 lần, hoặc lottery không nhận ra 50 khoá đó là một người — và
trường hợp thứ hai là đúng cái sybil mà stake định chặn.

Bốn quyết định tham số, bản 1 để trống:

| Tham số | Giá trị | Lý do định lượng |
|---|---|---|
| `UNBOND_PERIOD` | **7 ngày** | Để một kẻ tấn công không thể bond → chiếm lottery một giờ → rút ngay |
| `MIN_BOND` | **tương đương $500** | Chặn số danh tính ở `stake/500`. Với trọng số tuyến tính (§5.4.4a) sybil không lợi, nên `MIN_BOND` chỉ để chống spam registry, không cần cao. Cao hơn là một rào cản gia nhập thật sự và nó ngược với §5.9 |
| Token để bond | **native của chain (xDAI)**, không phải enterprise token | Bond bằng chính token của issuer nghĩa là issuer có thể in ra stake. Đó là một "stake" không có ý nghĩa kinh tế |
| Ai giữ bond | Contract, không ai rút được trong v1 | Không có `slash()` → không có ai có quyền tịch thu → không cần governance. **Đây là một tính năng.** |

Không có hàm `slash()` trong v1. Đường nâng cấp: thêm `slash(address, uint256, bytes proof)` chỉ khi
xuất hiện một hành vi có thiệt hại > $100/vụ — chưa tồn tại. **`activeSetAt` là hàm bắt buộc phải có
từ đầu** (không phải nâng cấp sau), vì §5.4.4(a) cần nó để mọi node tính ra cùng một `snapshot_root`;
nếu registry không lưu lịch sử theo block thì phải thêm một checkpoint array, và đó là một thay đổi
storage layout — đắt nếu làm sau. Với contract bất biến (§01.1.3) thì "đắt" là nghĩa đen: không sửa
được, phải deploy registry mới.

**Trường hợp `chain_profile = private`: không có registry, không có bond.** Tập relayer là một
allowlist trong `blockchain.relayer.allowlist_state` do admin duyệt, và lottery là round-robin tĩnh
theo `intent_id % n`. Đừng deploy `RelayerRegistry.sol` lên private chain "để sau này khỏi đổi" —
một contract không làm gì là một bề mặt tấn công không làm gì.

**Và một vai mà bản 2 không có chỗ cho: pool thuần không stake được, và không nên phải stake.**
Một node không có khoá ký thì không bao giờ nhận exclusivity, nên nó không cần trọng số lottery, nên
`MIN_BOND` không áp dụng. Nó chỉ có `score_forward` (§5.4.4b) và peer scoring của gossipsub. Đây là
lý do rào vào của lớp đó bằng **không**, và đó là chủ ý — nó là lớp làm mạng thật sự mở.

---

### 5.7. Sponsorship escrow pool và cách relayer đòi trợ cấp

Note (§10.1 mục 1.b) mô tả "ký quỹ sẵn một bể tài trợ ... hoặc trả phí dịch vụ off-chain/on-chain
định kỳ". **Vế "định kỳ/off-chain" là một cái bẫy:** một relayer lý trí sẽ không ứng gas nếu khoản bù
chỉ là lời hứa sẽ thanh toán cuối tháng. Nó phải **atomic với lần thực thi**.

Lại có một ràng buộc kỹ thuật cứng: **contract không đọc được event log.** Mọi thiết kế "relayer nộp
batch receipt hàng tuần, pool tự xác minh" đều **không thể triển khai** mà không có attestor ký ngoài
chuỗi (tức là tập trung, tức là mất điểm của cả mô hình).

**Thiết kế duy nhất chạy được: thanh toán inline trong chính tx.**

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
Luồng: relayer gọi `quote` trong cùng lần simulate; executor của EIP-1776, sau khi meta-tx chạy
thành công, gọi `pool.settle(...)`. Chi phí thêm: **~30.000–45.000 gas** (policy SLOAD + merkle proof
3–4 mức + ERC-20 transfer). Trên Gnosis: **+$0,00005**. Chấp nhận được.

**Rủi ro còn lại và cách chặn.** Bản 1 mô tả đúng hiện tượng nhưng sai mức độ: giữa lúc relayer
`quote` (block N) và lúc inclusion (block N+1), một relayer khác có thể rút cạn `dailyCap`. Bản 1 gọi
đó là va chạm ngẫu nhiên và ước "xác suất ~0 ở mức 20 intent/ngày". **Sai lầm là coi nó là ngẫu
nhiên.** `dailyCap` là một tài nguyên chung, hiện, có hạn — đó **là** định nghĩa của một bề mặt MEV.
Một relayer đối thủ đọc được `dailyRemaining` bằng một `eth_call` và có thể chủ đích đốt nó bằng
chính intent của mình ngay trước khi đối thủ inclusion. Chi phí cho kẻ tấn công: bằng không (nó vẫn
được trả tiền cho intent của nó). Thiệt hại cho nạn nhân: một tx gas.

Biện pháp, xếp theo thứ tự:

1. **`perRelayerDailyCap` (thêm mới).** Không relayer nào rút được quá `dailyCap / expected_relayers`
   trong một ngày. Đốt cap của người khác trở nên bất khả thi vì bạn không tiêu được phần của họ.
   Chi phí: +1 SLOAD + 1 SSTORE ≈ 5.000 gas. **Đây là biện pháp chính.**

   Với pool khoá ký (`_USER-DECISIONS.md` §21.5) thì cap này phải tính theo **`relayer_id`**, không
   theo địa chỉ ký — nếu không, một relayer 50 khoá có 50 lần cap. Đây chính là lý do
   `registerSubmitter` ở §5.6 là bắt buộc chứ không phải tiện ích.
2. **Soft reserve trên node** (không ràng buộc, TTL = W) + cảnh báo vận hành khi
   `dailyRemaining < 20 * maxFeePerIntent`.
3. Nếu `settle` trả 0, relayer mất gas và sẽ hạ reputation **của policy đó** — đây là một **policy
   reputation**, không phải relayer reputation. Field: `blockchain.sponsorship.pool.miss_rate_7d`.
   Relayer client từ chối policy có `miss_rate_7d > 0,05`.
4. **Không** dùng on-chain reservation: `reserve()` là một tx riêng → nhân đôi gas → xoá sạch lợi
   nhuận. **Loại.**

**Ba điều nữa bản 1 không nói:**

- **Ai nạp pool, và hết tiền thì sao.** `Policy.validUntil` hết hạn hoặc quỹ cạn → **mọi intent
  sponsor lập tức thành không sinh lợi và không ai relay**, im lặng. Bắt buộc: cron
  `cron_check_sponsorship_runway()` cảnh báo khi `redeemableBalance / burn_rate_7d < 14 ngày`, và
  `/policy` công bố `runway_days` để relayer tự tính rủi ro đối tác.
- **`targetsRoot` là merkle root của `(to, selector)` — nhưng ai cập nhật nó?** Đổi một target là đổi
  root, tức một tx governance. Với một hệ ERP thêm endpoint hàng tuần, đó là ma sát thật. Khuyến
  nghị: `targetsRoot` trỏ tới một danh sách **ổn định** (các forwarder/token cốt lõi), và logic
  nghiệp vụ biến động nằm **sau** một dispatcher có địa chỉ cố định. Nếu không, mỗi lần release phải
  chạy một tx multisig.
- **Chống double-sponsor.** `settle` phải ghi `usedIntent[intentId] = true` (1 SSTORE, 20.000 gas
  lần đầu) — nếu không, một intent được relay hai lần (nonce chặn lần thứ hai, nhưng `settle` có thể
  bị gọi từ một executor khác) sẽ rút pool hai lần. `require(msg.sender == trustedExecutor[chainId])`
  là điều kiện cần, không phải điều kiện đủ.

Trường hợp `chain_profile = private`: pool có thể là một bộ đếm thuần tuý, không cần token chuyển
thực, vì gas bên trong là kế toán nội bộ. Khi đó `settle` chỉ phát event và Odoo đếm — **và khi đó
`SponsorshipPool.sol` không nên tồn tại ở profile private chút nào.** Một bảng trong Odoo là đủ.

---

### 5.8. Đối soát và hạch toán giữa relayer và issuer (phía Odoo)

Nguyên tắc kế thừa từ `dms_vietqr` ("quét QR không phải là đã thu tiền"): **broadcast không phải là
đã trả tiền.**

#### 5.8.1. State machine — và ba bản khác nhau đang tồn tại trong tài liệu này

Bản 1 của §5.8, §04.10 và §10.4.5 đưa ra **ba** state machine khác nhau cho cùng một đối tượng. Đó là
một lỗi tài liệu sẽ trở thành một lỗi code. Bản hợp nhất, đề nghị làm chuẩn:

```
draft → simulated → signed → published ─┬→ queued ──→ claimed → broadcast → mined → final ─┬→ done
                                        │              │            │                       └→ reverted
                                        ├→ expired ←───┴────────────┘
                                        └→ superseded
```

| State | Nghĩa chính xác | Ai chuyển |
|---|---|---|
| `simulated` | `eth_call` pass tại `sim_block` | builder |
| `signed` | có `signature_hex`, `digest_hash` cố định | ví / HSM |
| `published` | đã nằm trên bus/mesh, đang chờ relayer | bus |
| `queued` | hợp lệ nhưng bị chặn bởi single-flight Zether (§5.4.3) | bus |
| `claimed` | một relayer đã giữ exclusivity, chưa hết `W` | bus |
| `broadcast` | có `tx_hash` từ `/receipt` | relayer (không tin) |
| `mined` | có receipt, `receipt.status == 1`, **chưa đủ Finality Depth** | indexer (§11) |
| `final` | đã qua Finality Gate của chain đó | Finality Gate |
| `done` | `final` **và** `MetaTransactionExecuted.innerSuccess == true` | Finality Gate |
| `reverted` | `final` **và** `innerSuccess == false` (swallow), hoặc `receipt.status == 0` | Finality Gate |
| `expired` | quá `expiry` trước khi `mined`; nonce **không** bị tiêu | cron |
| `superseded` | nonce/lane bị tiêu bởi một tx khác | indexer |
Bốn quy tắc cứng:

- **`mined` không phải `done`.** Không ghi sổ, không báo thành công cho consumer.
- **`final` không phải `done`.** Ở chế độ swallow (§04.6 mặc định), một tx **thành công** trên chuỗi
  vẫn có thể mang `innerSuccess = false`. Odoo tuyệt đối không được suy trạng thái nghiệp vụ từ
  `receipt.status`. Chỉ `done` mới kích hoạt callback nghiệp vụ; nếu ai đó map cái này vào
  `payment.transaction`, `_set_done()` chỉ được gọi ở `done`, còn `mined` và `final` đều là
  `_set_pending()`.
- **`reverted` sau `mined` là khả năng có thật khi reorg** → phải có `action_reconcile_reorg()` chạy
  từ Finality Gate (§11), không phải từ relayer callback.
- **`/receipt` của relayer không bao giờ được tin.** Nó chỉ là một gợi ý để indexer nhìn sớm. Hai
  relayer cùng báo `tx_hash` khác nhau là bình thường (một kẻ thắng, một kẻ thua) — node lưu cả hai
  vào `blockchain.transaction` và **chỉ chain quyết định**. Bản 1 không nói điều này và nó là một chỗ
  dễ viết sai thành "intent chuyển sang broadcast khi relayer báo".

  Trên mesh, `/receipt` có thêm một vai thứ hai đã nói ở §5.4.4(b): nó là **đầu vào của
  `score_forward`**. Nhưng vai đó không làm nó đáng tin hơn — điểm forward phải được xác nhận bằng
  quan sát chain của chính node chấm điểm, không bằng lời khai của node được chấm.

#### 5.8.2. Model

| Model | Vai trò | Ghi chú so với bản 1 |
|---|---|---|
| `blockchain.metatx` | **Bản ghi intent. Đã tồn tại ở §10.4.5 — không tạo model mới.** | Bản 1 đề xuất `dms.blockchain.intent` song song. Đó là một bảng thứ hai cho cùng một thực thể. Bỏ |
| `blockchain.relayer` | Registry bên thứ ba. **Đã tồn tại ở §10.4.5.** | Bản 1 đề xuất `dms.blockchain.relayer` với `stake_wei`/`is_active`. Ánh xạ: `stake_ref` + `allowlist_state` |
| `blockchain.relayer.submitter` | **Mới ở bản 3.** Khoá ký thuộc một `relayer_id` (§21.5) | Không có nó, cap và lottery đếm một relayer nhiều khoá thành nhiều người |
| `blockchain.sponsorship.pool` | Mirror pool + lịch sử nạp | thêm `miss_rate_7d`, `runway_days` |
| `blockchain.relayer.statement` | Bảng kê ký (tháng) theo relayer × chain | **Đổi tên từ `…relayer.settlement`**: §10.4.8 đã dùng `blockchain.settlement` cho một khái niệm hoàn toàn khác (settlement nghiệp vụ). Hai tên gần giống nhau cho hai thứ khác nhau là một bẫy đọc |
| `blockchain.relayer.statement.line` | 1 dòng / intent | |
| `blockchain.intent.hub` | Peer gateway + bootstrap node của mesh | **mới**, bản 1 thiếu; `hub_id`, `base_url`, `multiaddr`, `pubkey`, `allowlist_state`, `last_seen_datetime` |

Field bổ sung trên `blockchain.metatx` do section này yêu cầu:

```python
class BlockchainMetatx(models.Model):
    _inherit = 'blockchain.metatx'

    inner_gas_limit      = fields.Integer(required=True, default=200000)
    fee_mode             = fields.Selection([('none', 'None'), ('percent', 'Percent'),
                                             ('fixed', 'Fixed')], required=True, default='fixed')
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
    hop_count            = fields.Integer(default=0)
    origin_hub_id        = fields.Many2one('blockchain.intent.hub', index=True)
    pool_visibility      = fields.Selection([('open', 'Open'), ('private', 'Private')],
                                            required=True, default='open', index=True)
    never_public         = fields.Boolean(default=False)      # chan promote-to-open (§21.4)
```

Ba field cuối là của bản 3: `hop_count` đổi tên từ `hops` cho khớp §5.1.0, và
`pool_visibility`/`never_public` hiện thực hoá private pool. `pool_visibility` phải có index vì nó
nằm trong mọi truy vấn phục vụ mesh, và mặc định của nó phải **suy ra từ `chain.chain_profile`** chứ
không phải để `open` cứng — xem cảnh báo ở §5.4.5.

**Kiểu dữ liệu tiền — sửa so với bản 1.** Bản 1 dùng `fee_wei`, `stake_wei`, `net_wei`,
`subsidy_paid_wei` như thể chúng là số. §10.4.1 chốt: **uint256 không vừa vào bất kỳ field số nào của
Odoo** (`Integer` là int4/int8; `Float` mất chính xác từ 2^53). Một stake 100 token 18 decimals =
`1e20` — **tràn int8 (`9,22e18`) và hỏng âm thầm**. Quy ước bắt buộc:

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

`_unique_intent_id` của bản 1 không cần thêm: §10.4.5 đã có `digest_hash` và §04.4 đã chốt
`models.Constraint('UNIQUE(metatx_digest)', …)`. Một cột, một constraint. Kiểm chứng:
`SELECT conname FROM pg_constraint WHERE conrelid = 'blockchain_metatx'::regclass;`

nhánh của `_compute_net_base` phải gán giá trị**, kể cả nhánh `not self.line_ids`, nếu không cột
`required` nhận NULL và INSERT chết. Viết `net = 0` trước vòng lặp, không viết trong `else`.

Cron: XML chỉ gọi **một** dòng (không có `fields`/`relativedelta` trong eval context):

```xml
<field name="state">code</field>
<field name="code">model.cron_close_relayer_statements()</field>
```

Năm cron của section này (tất cả `active=False` mặc định, bật theo `chain_profile` — §10):

| Cron | Chu kỳ | Việc |
|---|---|---|
| `cron_expire_intents()` | 1 phút | `published`/`claimed`/`queued` quá `expiry` → `expired`; nhả single-flight Zether |
| `cron_poll_peer_hubs()` | 5 giây | kéo `/pending` của peer, re-publish |
| `cron_promote_private_intents()` | 30 giây | intent `pool_visibility='private'` chưa ai claim quá `T` và `not never_public` → chuyển sang `open` (§21.4) |
| `cron_refresh_relayer_reputation()` | 15 phút | EWMA, `activeSetAt` mirror |
| `cron_close_relayer_statements()` | ngày 1 hàng tháng | đóng kỳ, tính `net_base` |
| `cron_check_sponsorship_runway()` | 1 giờ | cảnh báo hết quỹ |

`cron_promote_private_intents` là cron mới của bản 3, và nó là thứ ngăn private pool trở thành một
hố đen im lặng. Nó phải chạy ở tần suất cao hơn `cron_expire_intents` — promote sau khi đã hết hạn
thì vô nghĩa.

#### 5.8.3. Đối soát: cái gì đối với cái gì

Bản 1 gọi bảng kê là "một đối soát, không phải một lần trả tiền" — đúng, nhưng không nói **đối soát
cái gì với cái gì**. Cụ thể:

| Cột | Nguồn | Có đối soát được không |
|---|---|---|
| `intent_count` | `blockchain.metatx` state `done`/`reverted` | Có — từ DB của issuer |
| `fee_earned_base` | event `MetaTransactionExecuted(digest, relayer, feeRecipient, fee)` | **Có, on-chain** |
| `subsidy_paid_base` | event `Sponsored(policyId, intentId, relayer, paid)` | **Có, on-chain** |
| `gas_spent_base` | `receipt.gasUsed × effectiveGasPrice` của tx do relayer gửi | **Có, on-chain** — nhưng chỉ khi biết tx nào là của relayer nào |
| `net_base` | `fee + subsidy − gas` | Suy ra |

Điểm mấu chốt: **`gas_spent_base` chỉ đối soát được nếu ta biết `tx.from`**, và `tx.from` chính là
`msg.sender`, chính là relayer. Nên nó đối soát được **hoàn toàn từ chain**, không cần relayer khai
báo gì. Suy ra một nguyên tắc vận hành: **không bao giờ chấp nhận một con số gas do relayer tự báo
cáo.** `/receipt` chỉ cung cấp `tx_hash`; mọi con số tiền đều đọc lại từ receipt. Bản 1 không nói
điều này và nó là chỗ để một relayer kêu "tôi tốn nhiều gas hơn" mà không ai kiểm.

**Với pool khoá ký, "biết `tx.from`" cần thêm một bước** (§21.5): `tx.from` là một trong N khoá của
relayer, không phải `relayer_id`. Đối soát phải join qua `blockchain.relayer.submitter`. Không có
bảng đó thì gas của một relayer nằm rải trên N địa chỉ và không ai cộng lại được — đây là lý do thứ
hai (sau cap ở §5.7) khiến `registerSubmitter` là bắt buộc.

**Đối soát đa tiền tệ.** Gas trả bằng xDAI, fee nhận bằng một token, báo cáo bằng VND. Ba đơn vị.
Quy tắc: `blockchain.relayer.statement` lưu **ba cột base-unit riêng** (không quy đổi), cộng một cột
`amount_vnd` chỉ để báo cáo, tính bằng tỷ giá cuối kỳ (`res.currency.rate` ngày đóng kỳ). Không bao
giờ tính `net` bằng cách cộng ba đơn vị khác nhau rồi lưu một số — đó là cách tạo ra một bảng kê
không bao giờ khớp lại được.

**Kích thước thực tế làm thay đổi quyết định.** Với 1.000 intent/ngày và $0,0018/intent, doanh thu
relayer là **~$54/tháng**, gas ~$4/tháng. Chi phí phát hành một hoá đơn, đối chiếu, chuyển khoản cho
một khoản $50 tại VN (thời gian kế toán + phí) là **> $10**. Kết luận vận hành: **không bill từng
tháng cho từng relayer.** `blockchain.relayer.statement` có `state = 'accrued'` và chỉ
`action_post()` khi `net_base` quy đổi > một ngưỡng (`ir.config_parameter`
`blockchain.relayer.statement_min_vnd`, mặc định **2.000.000 VND**). Dưới ngưỡng thì cộng dồn sang kỳ
sau. Đây là một dòng logic và nó tiết kiệm nhiều hơn toàn bộ phần tối ưu gas của section này.

Ánh xạ sang các mode thanh toán đã khoá ở quyết định #8:

- **Mode 4 (sub-ledger đối soát theo lô):** bảng kê *chính là* lô. Không cần `account` gì cả. Mặc
  định cho `dms_blockchain` standalone.
- **Mode 1/3:** bridge addon `dms_blockchain_account` (depends `dms_blockchain`, `account`) thêm
  `action_post()` sinh **một `account.move` kiểu `in_invoice` mỗi relayer mỗi kỳ** cho phần
  `subsidy_paid_base`. Không bao giờ đặt code này trong core — đó là cách duy nhất giữ được ràng buộc
  "standalone" của quyết định #7.
- **Thuế VN:** phí relayer là doanh thu dịch vụ của một pháp nhân/cá nhân. Nếu relayer là cá nhân cư
  trú, phát sinh nghĩa vụ khấu trừ. Xem §13; không giải ở đây, nhưng **phải có `partner_id` trên
  `blockchain.relayer`** ngay từ v1 để sau này không phải migrate.

  Trên mạng mở thì phần lớn relayer **không có** `partner_id` và sẽ không bao giờ có — họ là người
  lạ. Trường này chỉ dùng cho relayer mà ta có quan hệ hợp đồng. Đừng để nó `required`.

---

### 5.9. Bootstrapping: làm sao có relayer bên thứ ba đầu tiên khi không ai nói EIP-1776

Vấn đề thật không phải "EIP-1776 chưa là standard". Vấn đề là **không có phần mềm nào chạy sẵn**. Ai
muốn relay phải tự viết client. Do đó:

**Phase 0 — chạy intent mở từ ngày đầu, dù chỉ có một relayer.**
Enterprise relayer là relayer duy nhất, nhưng intent vẫn được ký với `relayer = address(0)` và vẫn đi
qua intent bus. Không có "chế độ nội bộ" riêng. Lý do: nếu đợi đến khi có bên thứ ba mới bật chế độ
mở, sẽ phát hiện ra một loạt giả định sai vào đúng lúc không thể sửa.

*Ngoại lệ bắt buộc, từ §5.4.5:* ở `chain_profile = private` với luồng tiền có số tiền công khai,
intent mở **trên bus nội bộ** thì được, trên mesh công khai thì không. "Mở từ ngày đầu" là về **hình
dạng chữ ký**, không phải về **phạm vi mạng**.

**Phase 1 — ship client, đừng ship spec.**
Deliverable: `relayer-ref/` (ngoài addon, theo quyết định #9) — một Docker image chạy bằng:

```
docker run -e RPC_URL=… -e HUB_URL=https://hub.scaas.vn \
           -e PRIVATE_KEY_FILE=/run/secrets/k -e MIN_MARGIN=0.30 scaas/relayer:1
```

**Sửa so với bản 1:** bản 1 ước "~300–500 dòng TypeScript: poll, simulate, so sánh margin, claim, gửi
tx, receipt. Đó là toàn bộ công việc." Đó là một **ước lượng bán được hàng, không phải một ước lượng
kỹ thuật**, và nó sẽ làm mất uy tín đúng lúc một kỹ sư bên ngoài thử thật. Danh sách thật:

| Phần | Dòng (ước lượng) | Bản 1 có kể? |
|---|---|---|
| Poll `/pending`, `/get`, dedup theo `intent_id` | 80 | Có |
| Validate envelope, dựng lại digest, kiểm chữ ký | 120 | Không |
| `eth_call` simulate + tính `max(gasUsed, EIP-7623 floor)` | 120 | Một phần |
| Đọc `redemptionRate` / `pool.quote`, tính margin | 100 | Một phần |
| `claim` có ký + xử lý `409` + backoff | 80 | Có |
| **Nonce manager của chính EOA relayer** (§06 cho biết đây là phần khó nhất) | **250** | **Không** |
| **Pool khoá ký, least-in-flight, phát hiện kẹt** (§21.5) | **200** | **Không** |
| **Gas price strategy + replacement khi treo** | **200** | **Không** |
| **RPC failover, phát hiện node tụt hậu** | **150** | **Không** |
| **Khôi phục sau crash** (tx đã gửi, chưa biết kết quả) | **200** | **Không** |
| Theo dõi receipt, xử lý reorg, `POST /receipt` | 150 | Một phần |
| Kế toán cục bộ + metrics | 120 | Không |
| Cấu hình, log, health, Dockerfile, test | 250 | Không |
| **Tổng thực tế** | **~2.000–2.600** | |

Bảng này là cho một relayer **HTTP**. Một node **mesh** cộng thêm libp2p, gossipsub, peer scoring,
dedup theo `intent_id` với TTL, `hop_count`, và ma trận acceptance policy — khoảng **+1.500 dòng**
nữa. Đó chính là lý do bản Rust standalone tồn tại (`_USER-DECISIONS.md` §21.2): tổng ~4.000 dòng là
một dự án thật, không phải một script, và nó cần một ngôn ngữ có thư viện libp2p trưởng thành.

**Đó vẫn là lợi thế cạnh tranh thật sự của EIP-1776** — một ERC-4337 bundler là ~10.000–15.000 dòng
và cần chạy một alt-mempool. **5x rẻ hơn, không phải 30x.** Quảng cáo con số 5x và có thể bảo vệ nó
tốt hơn nhiều so với quảng cáo con số 30x rồi bị một kỹ sư ngoài chứng minh ngược trong một buổi
chiều. **Và đó mới là thứ cần được quảng cáo, không phải 2-D nonce.**

Một cách rẻ hơn nữa để hạ rào gia nhập, bản 1 không có: **ship `relayer-ref` ở nhiều mức**, và các
mức đó ánh xạ thẳng vào các vai ở §21.4:

| Mức | Tương ứng vai | Dòng (ước lượng) |
|---|---|---|
| `--mode=simple` | Gateway, một khoá, không bump gas | **~500** |
| `--mode=production` | Gateway đầy đủ, pool khoá, replacement | ~2.500 |
| `--mode=pool` | **Pool thuần** — chỉ gossip và forward, **không có khoá** | **~800** |
| `--mode=node` | Node đầy đủ: mesh + submit theo ma trận | ~4.000 |

`--mode=pool` là mức đáng chú ý nhất: nó không cần khoá, không cần gas, không cần RPC ghi — nên nó
**bỏ được toàn bộ nửa dưới của bảng dòng code** (nonce manager, gas strategy, crash recovery). ~800
dòng và không có tiền trong đó. Đây là rào vào thấp nhất mà mạng có thể có, và nó nên là mức được
quảng cáo cho người muốn thử.

Con số "500 dòng" của bản 1 đúng — nhưng chỉ cho `simple`, và phải nói rõ.

**Phase 2 — bảo đảm biên lợi nhuận cho N intent đầu.**
`SponsorshipPool` với policy `bootstrap`: trả `gas + X` cho mỗi inclusion thành công, 10.000
intent/relayer/tháng đầu tiên.

Bản 1 chọn `X = $0,01` → 10 relayer × 10.000 × $0,01 = **$1.000/tháng**. **Con số đó không đủ và bản
1 không kiểm tra nó từ phía relayer.** Doanh thu của relayer: **$100/tháng**. Trừ VPS ($5–20), trừ RPC
($0–50), còn **$30–95/tháng**. Đó là dưới mức đáng để một kỹ sư **chú ý**, chứ chưa nói đến vận hành.
Chi phí thật không phải server, là **sự chú ý của người**.

| `X` | Doanh thu/relayer/tháng | Chi phí 10 relayer/tháng | Đánh giá |
|---|---|---|---|
| $0,01 | $100 | $1.000 | Dưới ngưỡng chú ý. Sẽ không ai chạy qua tháng thứ 2 |
| **$0,05** | **$500** | **$5.000** | Ngang một hợp đồng freelance nhỏ. **Khuyến nghị** |
| $0,10 | $1.000 | $10.000 | Thu hút cả người không nghiêm túc |

**Đề nghị: `X = $0,05`, trần 10 relayer, 6 tháng = $30.000 tổng ngân sách bootstrap**, giảm dần
$0,05 → $0,02 → $0,01 theo quý. So sánh: một kỹ sư hạ tầng 6 tháng tại VN đắt hơn nhiều. Nhưng đây
là **một quyết định ngân sách của người**, không phải của kiến trúc — đưa vào `open_questions`.

Và một điều kiện không được quên: policy `bootstrap` phải có `perRelayerDailyCap` (§5.7) và
`requireRegistered = true`, nếu không một người tạo 10 danh tính và lấy hết $5.000.

**Phase 3 — relayer đầu tiên là distributor, không phải người lạ.**
Đây là đường bootstrap thật sự cho ngữ cảnh này và nó nên được nói thẳng: một distributor trong hệ
thống DMS **đã có lý do kinh doanh** để giữ đường settlement sống, **đã là đối tác KYC**, và **đã
chạy hạ tầng**. Với họ, relay không phải là kinh doanh — nó là chi phí vận hành, giống như chạy một
máy POS. Như vậy:

- Sybil không còn là mối đe doạ (mọi participant là một pháp nhân đã định danh) → PoW và stake có
  thể để ở mức thấp.
- `chain_profile` có thể là `private` trong 12–18 tháng đầu mà không mất gì.
- **Mạng là consortium trước, mở sau.** Ký với `relayer = address(0)` giữ cửa mở mà không đòi thị
  trường mở phải tồn tại vào ngày đầu. Bản tài liệu nên gọi đúng tên nó, đừng gọi là "decentralized"
  khi nó đang là federated.
- **Và hệ quả mà bản 1 không rút ra:** nếu Phase 3 là đường thật, thì §5.4 (lottery, beacon, chống
  grinding), §5.6 (stake) và phần lớn §5.5 (PoW) **không được build trong năm đầu**. Chúng phải được
  *thiết kế* (để envelope và contract không phải đổi) nhưng không được *triển khai*. Cái phải build
  ngay là §5.2, §5.8 và tầng 0–2 của §5.5.

  Bản 3 thêm một mục vào danh sách "thiết kế nhưng chưa build": **mesh libp2p**. Nó là đích đến
  (§5.1) nhưng nó không phải việc của năm đầu — gateway HTTP phục vụ được consortium, và định dạng
  envelope (§5.2) là thứ giữ cho việc chuyển đổi sau này không phải viết lại client.

**Phase 4 — cho hạ tầng sẵn có làm relayer được (đúng kỹ thuật, không phải tranh luận standard).**

**Sửa so với bản 1 — một trong hai adapter của bản 1 không chạy được như mô tả.**
Bản 1 đề nghị `EIP1776ForwarderAdapter` "implement `IERC2771Forwarder.execute`" để Gelato /
OpenZeppelin Defender / Biconomy relay intent EIP-1776 "mà không sửa phần mềm của họ". Điều đó không
đúng: một ERC-2771 forwarder verify một chữ ký EIP-712 **trên domain và struct của chính nó**
(`ForwardRequest`). Một chữ ký EIP-1776 không bao giờ verify được ở đó — hai `domainSeparator` khác
nhau, hai `hashStruct` khác nhau. Không có adapter contract nào "dịch" được một chữ ký.

Cái **thực sự chạy được**, và nó đơn giản hơn:

| Đường | Cách làm | Chi phí thêm | Ai ký cái gì |
|---|---|---|---|
| **Gelato `callWithSyncFee` / Defender Relay** | Gọi API "gửi calldata này đến địa chỉ này và tự trả gas". Calldata là `executeMetaTransaction(metaTx, sig)`. **Không cần adapter contract nào.** | 0 gas, phí dịch vụ của họ | User ký lớp 1776; **Gelato ký lớp tx**. Hai lớp độc lập, không xung đột |
| `EIP1776EntryPointAdapter` (ERC-4337 account) | Một smart account 4337 có `callData = executeMetaTransaction(...)` | ~40.000–60.000 gas (validation + EntryPoint) | **Owner của account là relayer, không phải user.** Lớp 4337 uỷ quyền cho *relayer*; lớp 1776 uỷ quyền cho *user* |

Điểm đáng nói về đường thứ hai, bản 1 không rút ra: giá trị của nó **không** phải "tương thích
4337". Giá trị là **relayer được một ERC-4337 Paymaster trả gas cho nó bằng ERC-20**, tức là một
relayer không cần giữ xDAI chút nào. Với một distributor ở VN không muốn mua crypto, đó là một rào
cản biến mất. Đó là lý do đúng để build nó — và nó chỉ đáng build khi rào cản đó là thật.

Cả hai là **đường tương tác một chiều vào EIP-1776**, không phải bước lùi. Chúng tồn tại để vào ngày
không có relayer nào online, vẫn có hạ tầng công cộng đảm bảo intent được đưa lên chuỗi.

Và cả hai ánh xạ đúng vào vai **gateway** ở §21.4: Gelato là một gateway do người khác vận hành. Nhìn
theo cách đó thì Phase 4 không phải một tính năng riêng mà là một hệ quả tự nhiên của việc tách
gateway khỏi node mesh.

**Phase 5 — thứ đo duy nhất chứng minh mạng sống, bản 1 không có.** Một `/intents/v1/stats` công
khai và một dashboard:

| Chỉ số | Ngưỡng "mạng sống" |
|---|---|
| Số relayer khác nhau có >= 1 inclusion trong 7 ngày | **>= 3** |
| Tỷ trọng của relayer lớn nhất | **< 60%** |
| `p50` / `p95` thời gian từ `published` đến `mined` | < 8 s / < 30 s |
| Tỷ lệ intent `expired` không ai relay | **< 2%** |
| Tỷ lệ tx revert do đua (waste ratio) | < 10% |

Nếu sau 6 tháng Phase 2 mà "số relayer >= 1 inclusion" vẫn là 1, thì kết luận là **không có thị
trường**, và quyết định đúng là rút về consortium và cắt toàn bộ §5.4–§5.6 khỏi roadmap. Định nghĩa
trước tiêu chí thất bại là cách rẻ nhất để không trả tiền cho một thị trường không tồn tại trong ba
năm.

---

### 5.10. Những chỗ note gốc chưa đủ và cách giải quyết đã chọn

| Chỗ chưa đủ trong `blockchain.md` | Giải quyết chọn trong section này |
|---|---|
| "p2p gossip / mempool" không được định nghĩa | **Mesh libp2p + gossipsub v1.1** (`_USER-DECISIONS.md` §6), với gateway HTTP làm lớp bootstrap và làm đường cho client nhẹ. Bản 2 loại p2p; bản 3 lật lại, xem §5.1 |
| Không có định dạng thông điệp, không có versioning | `scaas-intent/1.1`; `intent_id` = EIP-712 digest = `digest_hash`; quy tắc major/minor; **spec + conformance vectors dùng chung cho hai bản cài đặt** (§5.2) |
| "Relayer quét mempool, chạy estimateGas, khi lợi nhuận dương thì nộp" — bỏ qua nguồn FX | 3 nguồn FX xếp hạng; enterprise token dùng `redemptionRate` **cộng với `redeem()` và `redeemableBalance()`** chứ không phải một con số treo (§5.3.3) |
| Không nói ai chịu rủi ro khi gas price chạy | Relayer chịu, cửa sổ 5 s; node công bố fee floor **theo (chain, token, require_success)** với công thức đúng đơn vị (§5.3.3) |
| ZKP verify "180k–250k gas" | Sai 7–15 lần; đó là con số Groth16. Bulletproofs 32/64 = ~1,79 M (§03.3). Báo giá relayer phải đọc `proofSystemId()` (§5.3.2) |
| "Thị trường cạnh tranh mempool lành mạnh" — không có số | EV rớt về 19% ở N=5; **điểm gia nhập tự do N\* ≈ 76, nơi đó 100% phí bị đốt thành gas** (§5.4.2) |
| Không nói về DoS bằng intent giả | 6 tầng hàng rào + peer scoring của gossipsub; tầng 0 ở nginx không ở Odoo; PoW 20 bit (16 cho mobile, 0 khi có JWT); **không persist trước tầng 3** (§5.5) |
| "Sponsorship Escrow Pool ... phí dịch vụ định kỳ" | Trả định kỳ không khả thi (contract không đọc log) → `settle()` inline, +30–45k gas, **+ `perRelayerDailyCap` vì `dailyCap` là một bề mặt MEV** (§5.7) |
| Không nói về staking/slashing | Stake = trọng số lottery **tuyến tính** + hàng rào sybil; **không slashing trong v1**; `MIN_BOND` ~$500, bond bằng native (§5.6) |
| Không có kế hoạch bootstrap | 5 phase; phase 3 (distributor làm relayer) là đường thật; **tiêu chí thất bại được định nghĩa trước** (§5.9) |
| Không nói intent bus là một kênh rò rỉ | **Mục mới §5.4.5**: private profile không bao giờ gossip ra mesh mở; ngưỡng giá trị cho intent mở trên public |
| Không nói node có nhiều vai | **`_USER-DECISIONS.md` §21.4**: ba trục, sáu vai, ma trận cấu hình theo `(chain, contract)`; private pool + promote-to-open |
| Không nói một khoá ký là nút thắt | **`_USER-DECISIONS.md` §21.5**: pool khoá, least-in-flight, và phát hiện `feeRecipient` phải wildcard được |

---

### 5.11. Kiểm chứng: bốn thứ phải chạy được trước khi tin section này

Không có framework, không có fixture. Bốn file, chạy bằng `pytest` và `psql`.

```python
# dms_blockchain/tests/test_intent_envelope.py  — thuan Python, KHONG import odoo
def test_intent_id_matches_eip712_vector():
    """Digest phai khop vector chung voi Solidity va voi relayer-ref.
    Neu ba implementation Fiat-Shamir/EIP-712 khong co oracle chung thi mot trong ba
    se lech am tham (bai hoc cua §03.8 muc 3)."""
    v = json.load(open('smartcontracts/testvectors/intent_v1.json'))
    assert intent_id(v['meta_tx'], v['chain_id'], v['verifying_contract']) == v['intent_id']

def test_wildcard_relayer_does_not_change_digest():
    """relayer/feeRecipient = address(0) la MOT GIA TRI, khong phai mot ngoai le.
    Doi chung sang mot dia chi that PHAI doi intent_id."""
    a = dict(BASE, relayer=ZERO, feeRecipient=ZERO)
    b = dict(BASE, relayer=ADDR_A, feeRecipient=ADDR_A)
    assert intent_id_of(a) != intent_id_of(b)
    assert intent_id_of(a) == intent_id_of(dict(BASE, relayer=ZERO, feeRecipient=ZERO))

def test_fee_mode_is_in_digest():
    """Doi cach dien giai `fee` phai lam chu ky vo hieu (§5.2)."""
    assert intent_id_of(dict(BASE, feeMode=1)) != intent_id_of(dict(BASE, feeMode=2))

def test_percent_fee_rejected_for_zether():
    """FeePolicy.requireConfidentialSafe o tang client, truoc khi ky."""
    with pytest.raises(ValueError):
        build_intent(dict(BASE, feeMode=FEE_PERCENT), is_zether=True)

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

def test_forward_loop_terminates():
    """Hai node co policy loai tru nhau khong duoc day qua day lai mai (§5.1.0)."""
    a, b = Node(accepts=lambda i: False), Node(accepts=lambda i: False)
    hops = simulate_forward(a, b, INTENT, max_steps=100)
    assert hops <= MAX_HOPS
```

```sql
-- Kiem chung constraint that su ton tai (CLAUDE.md §5 muc 2: dung tin code)
SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
 WHERE conrelid = 'blockchain_metatx'::regclass AND contype IN ('u','c');
SELECT indexname FROM pg_indexes
 WHERE tablename = 'blockchain_metatx' AND indexname LIKE '%zether_inflight%';
```

Và một bài kiểm tra tích hợp duy nhất đáng chạy bằng tay trước khi ship: **hai instance
`relayer-ref` cùng trỏ vào một gateway, phát 200 intent, đếm số tx revert.** Nếu waste ratio > 10%
thì soft-exclusivity đang không hoạt động và con số §5.4.2 là đúng theo hướng xấu.

Khi có mesh, thêm một bài thứ hai: **một node Rust và một node Odoo trong cùng mesh** (§21.3), gossip
qua lại, cả hai relay được một intent thật. Đó là bài duy nhất bắt được drift giữa hai bản cài đặt
trước khi nó thành một vụ chia mạng.

---

### 5.12. Delta phải đồng bộ ngược sang các section khác
Section này đã tự sửa theo §03/§04/§10. Những điều đi **ngược lại**, phải sửa ở section kia:

| Section | Hiện tại | Phải sửa thành |
|---|---|---|
| ~~§04.4~~ **ĐÃ GIẢI QUYẾT** | `mode` bitmask | **Xoá toàn bộ bitmask.** `_USER-DECISIONS.md` §5 chốt wildcard `relayer == address(0)`; hành vi bubble/swallow là thuộc tính của contract đích, không phải một bit trong digest |
| §04.4 | `feeRecipient` chỉ nhận một địa chỉ cụ thể | Thêm quy ước **`address(0)` = trả cho `msg.sender`** như một tiện ích cho người gửi không biết ai sẽ relay. Không phải điều kiện sống còn: `feeRecipient` cố định là cấu hình tự nhiên của relayer có pool khoá, và relayer công bố nó ở `/policy` (`_USER-DECISIONS.md` §21.5) |
| ~~§04.4~~ **ĐÃ GIẢI QUYẾT** | Struct không có `feeMode` | Cách tính phí nay ở **nửa byte sau của `mode`** (§04.4), và `mode` vốn đã trong digest. Yêu cầu cấp một bit riêng ở §5.12 **rút lại**. Chi tiết cũ: relayer đổi diễn giải `fee` từ tuyệt đối sang ppm (§5.2) |
| §10.4.5 | `metatx_state` thiếu `queued`, `broadcast`, `superseded`, `done`, `reverted` | Dùng state machine hợp nhất ở §5.8.1 (11 trạng thái) |
| §10.4.5 | `mode_flags` | Xoá cột. Thay bằng `fee_mode` + `pool_visibility` (§5.8.2) |
| §10.4.5 | thiếu `sig_kind`, `from_schnorr_address`, `bus_seq`, `beacon_*`, `hop_count`, `pool_visibility`, `never_public` | Thêm (danh sách ở §5.8.2) |
| §10.4.5 | không có model cho khoá ký của relayer | Thêm `blockchain.relayer.submitter` (§21.5). Thiếu nó thì cap, lottery và đối soát gas đều đếm sai |
| §04.10 | Ngân sách gas Zether "342k–422k" mâu thuẫn với §03.3 "~1,79 M" | Ghi rõ: 342k–422k **chỉ** với native precompile hoặc Groth16; 1,79 M với `BulletproofsVerifier.sol` |
| §06 | Nonce manager mô tả cho relayer nội bộ | Ghi rõ nó **không** áp dụng cho relayer bên thứ ba — họ tự quản nonce của họ. Nhưng **`KeyPool` thì dùng chung** (§21.5): cùng interface, khác nơi giữ khoá |
| §01, §14 | Cây `smartcontracts/` không có chỗ cho relayer | Thêm `relayer-ref/` ở gốc repo (bốn mức: `simple`, `production`, `pool`, `node` — §5.9) |

**Ba delta của bản 3 nặng hơn bảy delta của bản 2**, vì chúng chạm vào struct được ký chứ không chỉ
vào model Odoo. Cụ thể: bỏ `mode`, thêm `feeMode`, và quy ước `feeRecipient == address(0)` đều đổi
`hashStruct`, tức đổi mọi `intent_id` đã tính. Không có chữ ký nào đang lưu hành nên chi phí bây giờ
bằng không — **nhưng sau khi có client bên ngoài thì nó là một major bump và 90 ngày chạy song song**
(§5.2). Đây là lý do §5.2 phải được chốt trước khi ship client, không phải sau.