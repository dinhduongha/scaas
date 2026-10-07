# DEX — sổ lệnh off-chain bền, thanh toán on-chain (R35)

**Ngày:** 2026-10-03 · **Luồng:** S5 (`r3-dex`) · **Bổ sung cho:** round-3 design §F R35, spec gốc §2.3/§3.4
(R3, R16 — **bị thay** ở đây), addendum R26, round-3 R30.

Ruling của luồng đánh số `RS5-n` (lead đánh lại số khi merge).

**Trạng thái (rev 1.2, 2026-10-07).** Code EVM + node BUILT; review Claude 1 (§8) mở 5 luồng sửa code DX-FIX1…5
(§7, cuối); rev 1.2 thêm RS5-21 (phí DEX làm tròn lên) và gộp PAY-FIX6/7 của spec thanh toán vào DX-FIX3/4. Các ruling dưới đây **đã bị thay** bởi spec sau — đọc spec sau trước:

| Ruling ở đây | Bị thay bởi | Nội dung thay |
|---|---|---|
| RS5-2 (sổ ở Odoo qua `/json/2`, vòng `dex_sync`/`restored`) — §2 | NI **R105** | Sổ ở store của node (`dex_market/order/trade`); Odoo chỉ là bản soi để hạch toán |
| §1.6 / D11 "ERC-1271 không trần gas" | UA §5.4 + **F10**; nay **RS5-14** | Trần 50k / 400k (clone `SubjectAccount`), returndata ≤ 32 B |
| RS5-9 "book chỉ nhận `relayer =` ví này" | mesh-gossip **R124** §11.6 | Mặc định theo thị trường (home-bound); thị trường `unbound` nhận `relayer = 0` (chỉ GTC nghỉ) — mở lại mặt MEV §3.4 cho maker chọn |
| RS5-11 (một lane) | NI **R102** | Job gắn relayer được ghim lane (`lane_hint`) |

---

## 0. Tóm tắt

| Lớp | Thứ được xây | Thay cái gì |
|---|---|---|
| Contract | `OrderBookDex` (`src/dex/OrderBookDex.sol`): kiểm hai lệnh EIP-712 (ECDSA/ERC-1271), giới hạn giá, `filled[orderHash]`, khớp một phần, batch nguyên tử từng cặp, `transferFrom` trực tiếp người→người (DEX không giữ tiền), phí DEX theo thị trường (bật/tắt, ppm maker/taker, trần 1 %), phí relayer theo `FeeMode` có sẵn, huỷ on-chain bằng chữ ký | `MetaTxDex` (R3: fill-or-kill, không allowance) **giữ nguyên làm legacy**, không còn route gateway |
| Token | `MetaToken`: op meta-tx `approve(address spender,uint256)` — spender phải là contract (R26) | — |
| Node | `scaas-node/src/dex.rs`: sổ lệnh theo thị trường, ưu tiên giá-thời gian, limit + IOC/FOK, khớp một phần; lưu bền **ở Odoo qua `/json/2`**; settle qua outbox `call` job; watcher event final riêng của DEX | sổ trong bộ nhớ (R16) |
| Gateway | `/v1/dex/*`: đặt lệnh, huỷ, huỷ-hết, markets, depth, trades, ticker, lệnh của một ví | `POST/GET /v1/dex/orders` kiểu chân meta-tx |
| Odoo | addon `dms_blockchain_dex`: cấu hình thị trường, sổ/khớp chỉ đọc, hạch toán phí DEX (thu) + phí relayer (chi) qua journal (công ty, token) | — |

---

## 1. Contract `OrderBookDex`

### 1.1 Lệnh ký (EIP-712)

Domain: `name = "SCaaS OrderBookDex"`, `version = "1"`, `chainId`, `verifyingContract = DEX`. Lệnh ký **trên DEX**,
không trên token: một chữ ký cho cả hai token của cặp, ví hiển thị một loại lệnh.

```
Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,
      uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,
      address feeToken,address feeRecipient)
CancelOrder(bytes32 orderHash)
InvalidateNonces(address maker,uint256 minNonce)
```

| Trường | Nghĩa |
|---|---|
| `maker` | người ký; EOA (ECDSA low-s) hoặc contract (ERC-1271, account passkey/seed của S4) — phân biệt bằng code như `ERC20MetaTx` (designator EIP-7702 = EOA) |
| `taker` | 0 = ai cũng được; khác 0 = chỉ đối ứng này (RFQ) |
| `sellAmount`, `buyAmount` | tổng bán / tổng tối thiểu nhận (gross, trước phí DEX). Giá giới hạn = `buyAmount/sellAmount` |
| `nonce` | duy nhất theo maker; lệnh hợp lệ khi `nonce >= minNonce[maker]` (huỷ hàng loạt). Client dùng `unix_ms·2^20 + random20` |
| `expiry` | hạn ký, giây epoch; `block.timestamp <= expiry` |
| `maxFeePpm` | phí DEX tối đa người ký chấp nhận (vai nào cũng vậy). Phí thị trường > `maxFeePpm` ⇒ cặp revert. Nâng phí **không** chạm lệnh đã ký |
| `flags` | bit0 `FOK`, bit1 `IOC`; bit lạ hoặc cả hai cùng bật ⇒ revert (như `validateMode`; review D17) |
| `relayer` | 0 = relayer nào cũng nộp được; khác 0 = chỉ `msg.sender` này (R10) |
| `feeMode`, `fee`, `feeToken`, `feeRecipient` | phí **relayer** (§1.5) |

Không có `lane/batch` của token ở đây: DEX tự giữ không gian nonce (`minNonce`, `filled`) — R30, §1.7.

### 1.2 `settle(Match[] ms) returns (bool[] ok)`

`Match = {bytes32 ref; Order maker; bytes makerSig; Order taker; bytes takerSig; uint256 makerFill; uint256 takerFill}`
— `makerFill` là lượng `maker.sellToken` maker giao, `takerFill` là lượng `taker.sellToken` taker giao. `ref` do
relayer đặt, chỉ được echo trong event (khoá trade ở Odoo).

Mỗi cặp chạy trong `try this.settleOne(m, msg.sender)` (external, chỉ `msg.sender == address(this)`): **nguyên tử
từng cặp** — cặp fail revert riêng phần của nó, emit `MatchFailed(ref, reason)`, các cặp khác vẫn chạy. **Không cặp
nào qua ⇒ cả tx revert `NothingSettled`**: simulate của relayer bắt được trước khi tốn gas (review D10). Sau vòng
lặp, mọi lệnh `IOC` vừa khớp được **đóng phần còn lại** (`filled = sellAmount`, emit `OrderCancelled`): IOC nghĩa là
"chỉ trong tx này", kể cả khi nó khớp nhiều maker trong cùng batch (review D3).
`settle` có `nonReentrant` (transient); `settleOne` không có guard nhưng chỉ chính DEX gọi được. Relayer thật được
truyền vào `settleOne` làm tham số: trong lời gọi tự thân `msg.sender == DEX`, và mặc định phí relayer về
`msg.sender` sẽ kẹt phí trong DEX — chính là `FeeWouldStick` (§1.5).

Kiểm (mỗi lệnh, rồi cả cặp), **trước** mọi chuyển tiền:

1. `flags` hợp lệ; `block.timestamp <= expiry`; `nonce >= minNonce[maker]`; `relayer ∈ {0, sender}`;
   `taker ∈ {0, đối ứng}`; chữ ký đúng (digest EIP-712 của DEX).
2. Cặp: `M.sellToken == T.buyToken`, `M.buyToken == T.sellToken`, `sellToken != buyToken`, `M.maker != T.maker`;
   thị trường của cặp (khoá không thứ tự) đã niêm yết.
3. Lượng: `makerFill > 0`, `takerFill > 0`; `filled[h] + fill <= sellAmount` (**không bao giờ overfill**);
   `FOK` ⇒ `filled[h] == 0 && fill == sellAmount`.
4. Giá (cả hai, nhân chéo, checked math — tràn thì revert, không bao giờ sai):
   `takerFill · M.sellAmount >= makerFill · M.buyAmount` và `makerFill · T.sellAmount >= takerFill · T.buyAmount`.
5. Phí DEX: `feeOn ⇒ makerPpm <= M.maxFeePpm && takerPpm <= T.maxFeePpm`.
6. Ghi `filled` (effects) rồi chuyển (interactions), mọi chuyển là `transferFrom(payer → payee)` trực tiếp:

| Từ | Đến | Lượng (token) |
|---|---|---|
| M | T | `makerFill − takerDexFee` (X) |
| M | feeRecipient thị trường | `takerDexFee = makerFill · takerPpm / 1e6` (X), chỉ khi > 0 |
| T | M | `takerFill − makerDexFee` (Y) |
| T | feeRecipient thị trường | `makerDexFee = takerFill · makerPpm / 1e6` (Y), chỉ khi > 0 |
| M / T | người nhận phí relayer | phí relayer của từng lệnh (§1.5), chỉ khi > 0 |

Phí DEX tính trên phần **nhận** của bên chịu phí (không cần thêm số dư), làm tròn xuống (lợi cho người dùng).
Tổng mỗi token bảo toàn chính xác: người trả mất đúng `fill` (+ phí relayer của chính lệnh đó, **cộng thêm** — §1.5,
review D1), phần còn lại chia cho người nhận + người thu phí; DEX không giữ gì ⇒ **không dust**. Thị trường tắt phí ⇒ ppm coi như 0 ⇒ không có lệnh chuyển phí nào (không phải "phí
0 được chuyển").

7. `emit OrderFilled(ref, hash, owner, Fill)` cho **mỗi** bên (`Fill` = struct: sellToken, sold, buyToken,
   received net, dexFee, dexFeeRecipient, relayerFeeToken, relayerFee, relayerFeeRecipient, filledTotal) — Odoo hạch
   toán theo góc nhìn từng ví; `emit Matched(ref, makerHash, takerHash)`.

Giá thực hiện do relayer chọn trong giới hạn của cả hai. Book của ta luôn khớp **giá của lệnh nghỉ (maker)**,
làm tròn có lợi cho maker (`takerFill = ceil(makerFill · M.buy / M.sell)`), và chỉ phát cặp qua đúng hàm kiểm
giới hạn giống contract (§3.3).

### 1.3 Huỷ on-chain (meta-tx — người dùng không cần gas)

- `cancel(CancelReq[] reqs)` với `CancelReq = {Order order; bytes sig}`: chữ ký `CancelOrder(hash(o))` của
  `o.maker` ⇒ `filled[h] = o.sellAmount` (đóng vĩnh viễn: lệnh đã huỷ **không bao giờ** settle được, kể cả bởi
  relayer khác đang giữ bản ký). Gom nhiều lệnh một tx (review D14); mục chữ ký sai hoặc đã đóng bị bỏ qua (không
  revert cả lô, không event). Phát lại là no-op.
- `invalidateNonces(maker, minNonce, sig)`: `minNonce` phải **tăng** và `<= 2^128 − 1` (`type(uint128).max`,
  `OrderBookDex.sol:89`; nonce là `uint256` nên phía trên vẫn còn chỗ) ⇒ phát lại bị từ chối, một chữ
  ký nhầm `2^256−1` không khoá vĩnh viễn địa chỉ (review D23); vô hiệu mọi lệnh `nonce < minNonce`.
- **RS5-10 — chữ ký huỷ không có hạn** (ngoại lệ có chủ ý của "mọi chữ ký có hạn"): huỷ chỉ đi một chiều có lợi cho
  người ký và phát lại là no-op; một `validUntil` chỉ tạo cửa sổ "đã gỡ khỏi sổ off-chain mà job huỷ on-chain hết
  hạn ⇒ lệnh vẫn settle được tới `expiry`" (review D4).

### 1.4 Thị trường, phí DEX, quyền admin — **RS5-1**

- `admin` **immutable**, đặt lúc deploy; production là một Safe/multisig (đổi người ký nằm trong Safe). Admin làm
  được đúng hai việc: `setMarket(base, quote, listed, feeOn, makerPpm, takerPpm, feeRecipient)` và không gì khác —
  không chạm tiền, không upgrade, không pause toàn cục (delist một thị trường = dừng cặp đó).
- Trần `FeePolicy.MAX_FEE_PPM` (1 %) kiểm trong `setMarket`; `feeOn` với ppm > 0 bắt buộc `feeRecipient ∉ {0, DEX}`.
- **Vì sao phí đổi được (không cố định theo clone):** yêu cầu "bật/tắt theo thị trường" nghĩa là phí *sẽ* đổi; cố
  định theo instance buộc mỗi lần đổi là một DEX mới, mọi người dùng ký lại `approve` cho spender mới (allowance gắn
  với spender), mọi lệnh nghỉ mất. An toàn của người dùng không đến từ việc phí đứng yên mà từ `maxFeePpm` **trong
  lệnh đã ký** + trần 1 % là hằng số: admin nâng phí thì cặp của lệnh cũ revert, không bao giờ thu vượt mức đã ký.
  Không timelock: không có gì để đợi — lệnh mới ký theo phí hiện hành, lệnh cũ được bảo vệ bởi chữ ký.

### 1.5 Phí relayer — tách hẳn khỏi phí DEX

Dùng đúng `FeeMode` (`NONE/PERCENT/FIXED`) và `FeePolicy` có sẵn; mỗi lệnh tự khai:

| `feeMode` | Token trả phí | Lượng mỗi lần khớp |
|---|---|---|
| `NONE` | — | 0 (B2B, R10/SRS §5.2) |
| `PERCENT` | `sellToken` (`feeToken ∈ {0, sellToken}`, khác ⇒ revert) | `FeePolicy.compute(PERCENT, fill, fee)` — trần 1 % |
| `FIXED` | `feeToken` (0 = `sellToken`) | `fee · fill / sellAmount` (pro-rata, làm tròn xuống ⇒ tổng ≤ `fee`); nếu trả bằng `sellToken` thì `fee <= 1 % · sellAmount` (`FeePolicy.compute(FIXED, sellAmount, fee)`) |

Người nhận: `feeRecipient` nếu khác 0, ngược lại relayer đã nộp tx (`sender`). `FeeWouldStick` giữ nguyên: người
nhận ∈ {0, DEX} ⇒ revert (không thể bằng 0 sau khi resolve, nhưng `feeRecipient = DEX` thì có).

Phí relayer **cộng thêm** vào phần giao (không trừ vào `fill`); intake đòi `fundable >= remaining + phí relayer còn
lại` khi trả bằng `sellToken`, và `feeFundable >= phí còn lại` khi trả bằng token phí riêng. Token phí riêng không có
trần 1 % (không so được hai token khác nhau mà không có oracle): người ký thấy và ký đúng con số tuyệt đối (review
D12, nhận một phần).

### 1.6 Hàm đọc cho intake

`checkOrder(Order o, bytes sig) view returns (bytes32 hash, uint8 status, uint256 remaining, uint256 fundable,
uint256 feeFundable)`: `status` ∈ `OK, BAD_FLAGS, EXPIRED, NONCE_INVALID, BAD_SIG, CLOSED, NOT_LISTED, BAD_FEE`
(0–7, `OrderBookDex.sol:93-100`; `BAD_FEE` = `feeMode` lạ, `feeRecipient = DEX`, hay vượt trần §1.5);
`fundable = min(balanceOf, allowance(DEX))` trên `sellToken`, `feeFundable` tương tự trên token phí relayer. Một
`eth_call` cho mọi kiểm ở cửa (chữ ký kể cả ERC-1271, số dư, allowance, đóng/huỷ, nonce).

~~ERC-1271 gọi qua `SignatureChecker` **không** trần gas~~ — **sai, thay bằng RS5-14** (review Claude H3; UA F10).
Code hiện tại (`OrderBookDex.sol:383-384`) vẫn là `SignatureChecker` không trần: một maker hợp đồng trả đúng dưới
`eth_call` nhưng đốt gas / trả returndata khổng lồ trong block thật làm sập cả lô `settle` (1/64 gas còn lại không đủ
cho các cặp sau) và **mọi** lô `cancel` (không có `try`). Đích: trần 50k, 400k cho clone `SubjectAccount` (theo
codehash, như `MetaToken._erc1271Gas`, `MetaToken.sol:141-143`), returndata chép tối đa 32 B — luồng DX-FIX3.

### 1.7 R26 và R30

- **R26:** DEX là spender duy nhất. Người dùng `approve` **không gas** qua op meta-tx mới của `MetaToken`:
  `data = approve(address spender,uint256 amount)` (68 byte, selector-tagged như `pay`/`trade`); bước 6 kiểm
  `m.value == 0`, `m.to == spender`, spender là contract (`_isContract`, 7702 = EOA ⇒ từ chối); bước 8
  `_approve(from, spender, amount)` thay vì transfer. Phí relayer của chính meta-tx approve luôn bằng 0: trần
  `FeePolicy` tính trên `value = 0` (`PERCENT` ra 0, `FIXED` > 0 revert `FeeExceedsCap`) — relayer tài trợ
  approve (một lần mỗi token); test `test_approveOpRelayerFeeIsCappedToZero`. `transferFrom` chỉ do contract gọi — DEX là contract.
- **R30:** DEX không đọc/ghi `metaNonce` của token. Lệnh dùng `filled`/`minNonce` của DEX; `approve` dùng lane
  ngẫu nhiên riêng (`keccak("scaas.dex.approve" ‖ rand)`, nonce 0). Hệ quả kiểm bằng test: lệnh DEX treo/huỷ
  không chặn một `pay`, `pay`/`cancelMetaNonce` không vô hiệu lệnh DEX.

### 1.8 Bất biến (test)

`filled[h] <= sellAmount` luôn; DEX không bao giờ có số dư sau `settle`; mỗi token Σ số dư không đổi; cặp vi phạm
giá/overfill/hết hạn/huỷ/nonce/chữ ký sai ⇒ chỉ cặp đó fail; phí tắt ⇒ đúng 0 chuyển phí; phí bật ⇒
`received + fee == fill` từng chân.

---

## 2. Lưu bền sổ lệnh — **RS5-2: Odoo qua `/json/2`**

Chọn Odoo, không SQLite:

- **Một nguồn sự thật** với outbox: khớp xong, cùng **một** transaction Odoo ghi lệnh (remaining mới), trade, và
  relay job `call` `settle(...)`. Không có cửa sổ "đã khớp trong sổ nhưng job chưa có" hay ngược lại.
- Settlement đi qua đúng đường relay đã kiểm (claim CAS, journal `signed` trước khi gửi, thay thế, lấp nonce —
  R18), không thêm kênh gửi thứ hai.
- Odoo có sẵn view chỉ đọc sổ/khớp và hạch toán phí mà không cần đồng bộ.
- Không thêm dependency C (rusqlite) vào node.

Đánh đổi: intake đặt lệnh phụ thuộc Odoo sống (submit vốn đã phụ thuộc). Odoo chết ⇒ đặt/huỷ lệnh trả 503, đọc
sổ vẫn chạy từ bộ nhớ.

**Người ghi duy nhất:** node (một tiến trình mỗi chain, sổ trong `tokio::Mutex`). Odoo không bao giờ tự sửa
`remaining`; Odoo chỉ đổi **trạng thái trade** (từ job/event) và đánh dấu lệnh hết hạn (tất định, node cũng bỏ).

Vòng đời trong node:

1. **Khởi động:** `dex_book_load(chain)` ⇒ mọi lệnh `open/partial` (đủ chữ ký + `remaining` + `seq`) ⇒ dựng sổ
   đúng thứ tự giá-thời gian (`seq` là thời gian).
2. **Đặt lệnh:** kiểm cửa (§3.4) ⇒ khớp trên **bản sao** sổ ⇒ simulate `settle` ⇒ cặp fail trong simulate:
   `checkOrder` hai bên, lệnh hỏng bị loại (persist `invalid`), thử lại (≤ 3 vòng) ⇒ `dex_book_commit` (lệnh +
   trade + job) ⇒ thành công mới thay sổ trong bộ nhớ. Commit lỗi (kể cả timeout: Odoo có thể ĐÃ commit) ⇒ **nạp
   lại toàn bộ sổ từ Odoo** rồi trả 503 — Odoo là sự thật, không đoán (review D20). `trade_ref` UNIQUE chặn ghi đôi.
3. **Trade fail** (job `dead/reverted`, hay event final `MatchFailed`): Odoo đặt trade `failed`. Vòng `dex_sync` của
   node (mỗi `poll`) lấy trade fail chưa xử lý ⇒ với từng lệnh: lệnh IOC/FOK **không bao giờ** trả về sổ (chúng
   không nghỉ; review D5); lệnh thường còn hợp lệ on-chain (`checkOrder`) thì được trả `fill` và **đi lại qua
   matcher** với `seq` cũ (giữ ưu tiên thời gian) — không chèn thẳng: nếu cả hai bên cùng khoẻ (job chết vì lý do
   của relayer), chèn thẳng để lại một sổ chéo (bid ≥ ask nằm yên); qua matcher thì chúng khớp lại thành một trade
   **mới** (tag có muối ngẫu nhiên mỗi tiến trình + bộ đếm, không trùng tag cũ mà Odoo coi là phát lại), simulate
   rồi commit cùng ack. Không thì loại ⇒ commit + ack.
   Lệnh bị huỷ on-chain (kể cả qua relayer khác) đến qua event final `OrderCancelled/NoncesInvalidated` (§3.6) ⇒ gỡ
   khỏi sổ (review D13).
4. **Final:** watcher DEX (§3.6) gửi `OrderFilled/Matched/MatchFailed` vùng final ⇒ trade `settled` ⇒ hạch toán.

---

## 3. Node (`scaas-node/src/dex.rs`)

### 3.1 Thị trường & phía

Thị trường `(base, quote)` lấy từ Odoo (`dex_markets`), đối chiếu với `markets(key)` on-chain lúc nạp và mỗi 30 s;
lệch (niêm yết/phí/người nhận) ⇒ thị trường đó **không** được phục vụ + log (drift Odoo ↔ chain).
*Thực tế (review Claude M2):* chỉ kiểm lúc `Venue::start` (`venue.rs:188-196`); vòng 30 s chưa có — RS5-17, DX-FIX5.
Lệnh bán `base` = **ask**, giá `buyAmount/sellAmount` (quote/base); lệnh bán `quote` = **bid**, giá
`sellAmount/buyAmount`. So giá bằng nhân chéo `U256` (lượng ở cửa `< 2^128` ⇒ không tràn).

### 3.2 Ưu tiên giá-thời gian

Mỗi phía một `Vec` sắp theo (giá tốt nhất, `seq` tăng). `seq` cấp đơn điệu lúc nhận, lưu ở Odoo, nạp lại giữ nguyên.

### 3.3 Khớp (thuần, không I/O)

Lệnh tới `O` đi qua phía đối diện theo thứ tự; với lệnh nghỉ `R` (maker) còn `R.rem`:
`x = min(R.rem, floor(O.rem · R.sell / R.buy))`, `y = ceil(x · R.buy / R.sell)`; `x = 0` ⇒ dừng; kiểm
`limits_ok(R, O, x, y)` **giống hệt** contract (§1.2 bước 3–4, kể cả FOK); không qua (làm tròn trần đẩy `y` vượt
giới hạn của O ở lượng rất nhỏ) ⇒ không bao giờ phát một cặp contract sẽ từ chối (review D2). Ai là phần lẻ quyết
định bước tiếp (**RS5-12**, review Claude H1): `x == R.rem` ⇒ **maker** là dust ⇒ bỏ qua R (`i += 1; continue`),
khớp tiếp lệnh sâu hơn; còn lại (`x < R.rem`) ⇒ **taker** là dust ⇒ dừng, phần lẻ của O nghỉ lại. Code hiện tại
`break` ở cả hai (`dex.rs:637-643`) ⇒ một maker dust ở đầu phía chặn mọi taker tới khi hết hạn (≤ 30 ngày) — DX-FIX1.
Lệnh nghỉ cùng maker bị **bỏ qua** (self-trade prevention, contract cũng từ chối; review D21).

- **GTC limit:** phần còn lại nghỉ trong sổ.
- **IOC:** khớp được bao nhiêu thì khớp, phần còn lại huỷ (không nghỉ). **RS5-3 (sửa rev 1.1, review Claude L4):**
  trên EVM, contract **có** đóng phần còn lại của IOC ở cuối tx `settle` (§1.2, D3; `OrderBookDex.sol:188-198`),
  kể cả khi khớp nhiều maker; `expiry` ngắn (≤ 60 s) là lớp thứ hai. Sui/Aptos/Solana đóng IOC ở lần khớp **đầu
  tiên** ⇒ matcher của các mạng đó chỉ cho IOC **một** maker (**RS5-18**, review Claude M3).
- **FOK — RS5-4:** cờ kiểm **on-chain**: lệnh FOK chỉ settle trong **một** cặp lấp đầy `sellAmount`. Book chỉ khớp
  FOK với một lệnh nghỉ đơn lẻ (đầu tiên theo giá-thời gian) đủ lấp trọn; không có ⇒ huỷ toàn bộ. Không gộp
  nhiều đối ứng cho FOK: "tất cả hoặc không" qua nhiều cặp trong batch nguyên tử-từng-cặp không chứng minh được
  on-chain. Khớp một phần là mặc định cho mọi loại khác (thay R3).
- Lệnh nghỉ không bao giờ là FOK/IOC (chúng không nghỉ).

### 3.4 Chặn spam ở cửa

Body ≤ 64 KiB (có sẵn); lượng `0 < amount < 2^128`; `expiry ∈ (now+5 s, now+30 ngày]`; tối thiểu theo thị trường
(`min_base_amount`: ask so `sellAmount`, bid so `buyAmount` — review D22); tối đa `MAX_OPEN_PER_MAKER = 50` lệnh mở
mỗi maker mỗi chain; trần toàn sổ `MAX_RESTING = 10 000`; hash trùng ⇒ từ chối; `checkOrder` phải `OK`.

- **Cam kết cộng dồn (review D6):** Σ `remaining` (+ phí relayer bằng `sellToken`) của mọi lệnh mở cùng
  (maker, sellToken) **cộng lệnh mới** phải `<= fundable`. Không thì một số dư 100 đặt được 50 lệnh 100.
  **RS5-16** (review Claude M1): cộng cả phần **đã khớp mà trade chưa `settled`/`failed`** (tiền chưa chuyển nhưng
  `remaining` đã trừ); hiện `Book::committed` chỉ cộng lệnh nghỉ (`dex.rs:449-462`) — DX-FIX5.
- **RS5-13 — token phí relayer bị giới hạn** (review Claude H2): `feeToken ∈ {0, sellToken, buyToken}` (hai token
  của thị trường đã niêm yết); khác ⇒ từ chối ở cửa. Không thì một maker đặt `feeToken` giả (`balanceOf`/`allowance`
  = 2^255, `transferFrom` luôn revert) qua `checkOrder` với `feeFundable` khổng lồ, và nhánh "maker khoẻ ⇒ lỗi ở lệnh
  mới" (`venue.rs:317-324`) từ chối mọi taker cắt qua nó — DX-FIX2.
- **RS5-9 — `relayer` phải là ví relayer này:** lệnh `relayer = 0` bị từ chối ở cửa. Lệnh công khai trong sổ mà ai
  cũng settle được thì kẻ quan sát mempool chèn được cặp của chính nó ở giá xấu nhất trong giới hạn người dùng (MEV),
  và relayer khác settle lại phần IOC/lệnh đã huỷ off-chain. Contract vẫn cho `relayer = 0` (relayer mở, SRS §4.9.4).
  *Rev 1.1:* nay là mặc định theo thị trường; thị trường `unbound` (mesh-gossip R124 §11.6) nhận `relayer = 0` cho
  GTC nghỉ — maker tự chấp nhận mặt MEV này.
- **Huỷ on-chain** (tốn gas relayer, review D14): chỉ cho lệnh đang có trong sổ; gom vào **một** `cancel(...)` mỗi
  vòng `poll` (≤ 50 lệnh); mỗi maker tối đa 20 huỷ on-chain mỗi giờ — vượt trần vẫn gỡ khỏi sổ ngay (relayer này
  là relayer duy nhất settle được nó, RS5-9) nhưng không tốn gas. Huỷ-hết chỉ khi maker còn ≥ 1 lệnh mở.

### 3.5 Gateway (`/v1/dex/*`)

| Route | Việc |
|---|---|
| `POST /v1/dex/orders` `{chain, order, signature}` | đặt lệnh ⇒ `{hash, status: resting/partial/filled/cancelled, fills[]}` |
| `POST /v1/dex/cancel` `{chain, orderHash, validUntil, signature}` | chữ ký `CancelOrder` ⇒ bỏ khỏi sổ **ngay** + job on-chain `cancel` |
| `POST /v1/dex/cancel-all` `{chain, maker, minNonce, validUntil, signature}` | `InvalidateNonces` ⇒ bỏ mọi lệnh `nonce < minNonce` + job on-chain |
| `GET /v1/dex/markets?chain` | thị trường + phí |
| `GET /v1/dex/depth?chain&market&levels` | mức giá gộp hai phía; giá là chuỗi thập phân đã quy đổi theo `decimals` hai token, không bao giờ chia nguyên thô (review D16) |
| `GET /v1/dex/trades?chain&market` | khớp gần nhất (vòng 200 trong bộ nhớ; lịch sử ở Odoo) |
| `GET /v1/dex/ticker?chain&market` | giá cuối, bid/ask tốt nhất, khối lượng trong vòng nhớ |
| `GET /v1/dex/orders?chain&maker` | lệnh mở của một ví |

`dex_routes()` trả một `Router` riêng; `gateway::router` `merge` nó — lớp auth của lead (§A.6, R54) bọc router
ngoài cùng, không cần biết route DEX. Không WebSocket (**RS5-5**): `axum` `ws` kéo `tokio-tungstenite`; client poll
`depth`/`trades` là đủ cho khối lượng hiện có.

### 3.6 Watcher DEX final

Một task riêng mỗi chain: cùng `finality::{safe_head, next_range, quorum_ok}`, **cursor riêng**
(`blockchain.chain.dex_indexed_block`), đọc log của địa chỉ DEX (`OrderFilled`, `Matched`, `MatchFailed`,
`OrderCancelled`, `NoncesInvalidated`), gửi `dex_fill_ingest` bằng **API key indexer**, rồi gỡ khỏi sổ mọi lệnh bị
đóng on-chain. `settled` là trạng thái cuối: một `MatchFailed` đến sau không lật nó.
Cursor riêng là R30 ở tầng vận hành: DEX ingest lỗi không bao giờ chặn chốt thanh toán và ngược lại; và không
sửa `indexer.rs` của lead.

---

## 4. Odoo `dms_blockchain_dex`

`depends: ['dms_blockchain', 'dms_blockchain_payment']`.

| Model | Trường chính |
|---|---|
| `blockchain.chain` (inherit) | `dex_address`, `dex_indexed_block` (chỉ watcher ghi) |
| `blockchain.dex.market` | `company_id` (công ty vận hành), `chain_id`, `base_token_id`, `quote_token_id`, `fee_on`, `maker_fee_ppm`, `taker_fee_ppm` (CHECK 0..10 000), `fee_recipient_address` (phải có ví nhận đã duyệt của công ty cho **cả hai** token), `min_base_amount`, `income_account_id`, `relayer_expense_account_id`, `journal_id` (dự phòng khi token chưa có journal), `active`; UNIQUE không thứ tự (chain, LEAST, GREATEST) — trùng khoá on-chain (review D19) |
| `blockchain.dex.order` | `market_id`, `order_hash` (UNIQUE theo chain), `maker_address`, `side` (bid/ask), lượng (Char uint, CHECK), `remaining_sell` (đơn vị `sellToken`, như `filled` on-chain — review D9), `nonce`, `expiry_ts`, `flags`, `max_fee_ppm`, phí relayer, `signature_hex`, `order_json`, `seq`, `order_state` (open/partial/filled/cancelled/expired/invalid) |
| `blockchain.dex.trade` | `trade_ref` (UNIQUE), `market_id`, `maker_order_id`, `taker_order_id`, `maker_fill_base`, `taker_fill_base`, phí dự kiến/thực tế, `relay_job_id`, `trade_state` (pending/settled/failed), `restored` (node đã xử lý fail), `tx_hash`, `block_number`, `move_ids` |

RPC (public, `check_service`): `dex_markets`, `dex_book_load`, `dex_book_commit`, `dex_sync` (relay_worker);
`dex_fill_ingest` (indexer). Không nhận company từ node: company suy từ market.

**Hạch toán (khi trade `settled`, tức event final):** seam `blockchain.token._dex_journal(company)` — trả
`journal_id` company-dependent của token nếu trường đó tồn tại (lead thêm, R56) và có giá trị, ngược lại
`market.journal_id`. Mỗi khoản phí hạch toán theo **token của chính nó** (phí maker bằng token maker nhận, phí taker
bằng token taker nhận, phí relayer bằng token phí của lệnh): journal, `decimals` và `currency_id` (neo 1:1, R17) của
token đó (review D7).
- **Phí DEX thu** (ví nhận phí là của công ty vận hành): Nợ TK mặc định journal token / Có `income_account_id`.
- **Phí relayer chi** (người trả là `blockchain.paying.wallet` đã duyệt của một công ty): Nợ
  `relayer_expense_account_id` / Có TK mặc định journal token của công ty đó.
Mỗi (trade, ví, loại phí) một bút toán, idempotent theo trade. Không có journal nào ⇒ không hạch toán, trade ghi
`accounting_note`, không chặn ingest (savepoint như F1 của spec gốc).

Job `dead/reverted` có trade ⇒ trade `failed` (override `_apply_report`). Cron hết hạn lệnh `open/partial`.

Bảo mật: viewer đọc market/order/trade (rule theo công ty của market); manager sửa market; service account không
có ACL, đi qua `check_service` + sudo (như `dms_blockchain`).

---

## 5. Non-EVM — mô hình các luồng mạng phải theo

Sổ, matcher, Odoo, gateway **dùng chung** (không phụ thuộc EVM ngoài địa chỉ/hash). Mỗi mạng cung cấp một
"settlement adapter" thoả cùng bất biến:

1. Lệnh ký có tách miền (mạng + contract DEX + toàn bộ trường §1.1), kiểm on-chain bằng khoá chủ thể (R30: không
   sequence tài khoản; nonce/`filled` do contract DEX giữ).
2. `filled[orderHash]` on-chain, không overfill, giá nhân chéo, `maxFeePpm` trong lệnh, trần 1 %.
3. Huỷ: đóng `filled` bằng chữ ký chủ; `minNonce` tăng.
4. Tiền đi thẳng người→người trong cùng giao dịch: Soroban hai `require_auth` (R65); Sui `Account<T>` hai chân
   (R64); Cosmos CW20 `TransferFrom` với allowance cho contract DEX (R66); TON escrow (R67 — ngoại lệ duy nhất có
   giữ tiền tạm, vì jetton không có `transferFrom`).
5. Event tương đương `OrderFilled/Matched/MatchFailed` để watcher + Odoo dùng nguyên.
6. **Settle gắn relayer** (**RS5-15**, review Claude H4): lệnh mang `relayer` (0 = mở; **không có dạng mở trên
   Soroban**, net-soroban R8-10) và contract kiểm người nộp.
   Sui (`dex.move:321`), Aptos (`dex.move:382`), Solana (`dex.rs:187`) đã có; **Cosmos** (`Settle` không kiểm
   `info.sender`, `OrderParams` không có relayer — `cosmos/dex/src/lib.rs:29-34, 145`), **Soroban**
   (`require_auth_for_args((order,))` chỉ trói lệnh, không trói đối ứng/`maker_fill`/người nộp — `lib.rs:158-159`) và
   **TON** (`receive(Match)` mở — `dex.tact:138-144`) chưa ⇒ kẻ xem mempool chép auth entry, chen cặp của mình và ăn
   phần cải thiện giá của taker. Sửa: Cosmos thêm `relayer` vào `OrderParams`, `info.sender == relayer` khi khác rỗng;
   Soroban thêm `relayer: Address` vào `Order` + `relayer.require_auth()`; TON thêm `relayer` tuỳ chọn vào
   `TradeParams`, so với `sender()` ở `Match` và đường gợi ý — DX-FIX4.
7. **`minNonce` có trần** (**RS5-19**, review Claude L1): như D23, `min_nonce < 2^(w−1)` với `w` = độ rộng nonce (Sui/
   Aptos `u128`, Solana `u64`); hiện ba mạng nhận `u128::MAX`/`u64::MAX` ⇒ một chữ ký nhầm khoá maker khỏi thị trường
   vĩnh viễn (`sui dex.move:295`, `aptos dex.move:299`, `solana dex.rs:340`) — DX-FIX4.

**Sai khác đã chấp nhận** (ruling của từng mạng; review Claude L2) — adapter, matcher và Odoo phải biết:

| Sai khác | Mạng | Nguồn |
|---|---|---|
| Không khớp một phần (lệnh FOK toàn phần) | Cosmos, TON | R9-2, R10-7 |
| Không có `minNonce` (huỷ hàng loạt) | Cosmos, Soroban, TON | adapter |
| IOC đóng ở lần khớp đầu (một maker) | Sui, Aptos, Solana | RS5-18 |
| Một người nhận phí cho cả DEX, không theo thị trường | Cosmos (`InstantiateMsg`), Soroban (`Key::FeeRecipient`) | adapter |
| Một `fee_ppm`, không tách maker/taker | Solana | `dex.rs:74-97` |
| Mức nhận tối thiểu tính **sau** phí DEX (EVM: `buyAmount` gross) | Cosmos, TON | adapter |
| Không kiểm self-trade on-chain (node vẫn bỏ qua, D21) | Cosmos, Soroban | adapter |

---

## 6. Test

| Lớp | Test |
|---|---|
| forge | không overfill (unit + fuzz + invariant), giới hạn giá hai bên, FOK, phí bật/tắt không dust, `maxFeePpm`, huỷ (chữ ký, phát lại, nonce), batch nguyên tử từng cặp, ERC-1271 maker, R26 (approve op: spender EOA/7702 bị từ chối, value≠0 bị từ chối), R30 (DEX ↔ pay độc lập), phí relayer 3 mode + `FeeWouldStick`, KAT EIP-712 → `test/vectors/dex_kat.json` |
| cargo | khớp giá-thời gian, một phần, IOC, FOK, giới hạn khớp == contract, snapshot/nạp lại (bền), chặn spam, KAT digest, decode event |
| e2e (anvil 31950–31959, gateway 18650–18659) | approve meta-tx → hai lệnh qua gateway → khớp một phần → job settle qua outbox → số dư; huỷ ⇒ settle không bao giờ chạy; khởi động lại venue ⇒ sổ còn nguyên |
| Odoo (`dms_test_chain_5`/8925) | commit/load khứ hồi, quyền service, trade fail khi job dead, ingest ⇒ settled + bút toán phí, phí tắt ⇒ không bút toán, seam journal |
| Thiếu — thêm ở DX-FIX1…5 (review Claude) | **forge:** maker 1271 đốt gas / bom returndata trong lô `settle` 3 cặp (2 cặp kia vẫn settle) và trong lô `cancel` (mục khác vẫn đóng); clone `SubjectAccount` passkey qua trần 400k; phát lại chữ ký lệnh/huỷ của DEX A trên DEX B (cùng chain) và trên chainId khác phải fail (hiện chỉ có KAT dương, `OrderBookDex.t.sol:667`); invariant §1.8 mở rộng: nhiều ask/bid, phí relayer bảo toàn, IOC đóng, nhiều maker (`OrderBookDexInvariant.t.sol` hiện một ask, không phí relayer, không IOC). **cargo:** maker dust đầu sổ + maker sâu hơn ⇒ taker khớp maker sâu (H1); maker `feeToken` độc + "maker khoẻ, cặp fail" không chặn taker khác lẫn khôi phục (H2); cặp OOG không được khôi phục (H3); quá cam kết khi trade đang chờ (M1); phí thị trường tăng on-chain ⇒ thị trường ngừng phục vụ trong một `poll` (M2); IOC một maker trên family Move/Solana (M3); `Matched` muộn sau khôi phục trừ lại sổ (L5). **Mạng:** bên thứ ba settle trên Cosmos/Soroban/TON phải fail (H4); `min_nonce` vượt trần bị từ chối (L1) |

---

## 7. Rulings

- **RS5-1** Admin immutable (Safe ở production) chỉ `setMarket`; phí đổi được nhưng bị chặn bởi `maxFeePpm` đã ký +
  trần 1 % hằng số; không timelock.
- **RS5-2** Sổ lệnh lưu ở Odoo qua `/json/2`, node là người ghi duy nhất; settle là outbox `call` job. Thay R16.
  *Bị thay bởi NI R105 (sổ ở store của node).*
- **RS5-3** ~~IOC chỉ off-chain~~ *(sửa rev 1.1)*: EVM đóng phần còn lại của IOC cuối tx `settle` (D3); `expiry`
  ngắn là lớp thứ hai. Family Move/Solana: RS5-18.
- **RS5-4** FOK kiểm on-chain = một cặp lấp trọn; book chỉ khớp FOK với một đối ứng. Khớp một phần là mặc định.
  Thay R3.
- **RS5-5** Không WebSocket; poll.
- **RS5-6** Phí DEX trên phần nhận, làm tròn xuống; phí relayer FIXED pro-rata làm tròn xuống.
  *Phí DEX: thay bởi RS5-21 (làm tròn lên mỗi fill); phí relayer giữ nguyên.*
- **RS5-7** `MetaTxDex` giữ làm legacy (không route); `OrderBookDex` là DEX của gateway.
- **RS5-8** Watcher DEX có cursor riêng và gửi bằng key indexer; không sửa `indexer.rs`.
- **RS5-9** Book chỉ nhận lệnh `relayer = ví relayer này` (chống MEV, chống settle lại phần đã huỷ off-chain).
  *Nay là mặc định theo thị trường; thị trường `unbound` theo mesh-gossip R124 §11.6.*
- **RS5-10** Chữ ký huỷ (`CancelOrder`, `InvalidateNonces`) không có hạn — một chiều, phát lại no-op.
- **RS5-11** Chain có `dex` chỉ chạy một lane relayer: lệnh khoá `relayer` = ví lane 0 (RS5-9) mà job outbox
  chưa ghim được lane (R62), nên lane khác claim job settle sẽ `WrongRelayer`. Node từ chối khởi động khi
  `lanes` > 1. Gỡ khi outbox có claim theo signer bắt buộc (cần S1). *Gỡ bởi NI R102 (ghim lane).*

### Rulings rev 1.1 — review Claude 1 (2026-10-07)

- **RS5-12** (H1) Phần lẻ do làm tròn: `x == R.rem` ⇒ maker dust ⇒ bỏ qua R và khớp tiếp; `x < R.rem` ⇒ taker
  dust ⇒ dừng. Maker có `R.rem · R.buy < R.sell` (không mua nổi 1 đơn vị ở giá của chính nó) bị **gỡ khỏi sổ**
  (trạng thái `filled`, ghi chú `dust`; on-chain phần còn lại vô giá trị). Test cargo: ask dust đầu sổ + ask sâu hơn
  ⇒ bid tới khớp ask sâu; dust bị gỡ ở lần chạm đầu.
- **RS5-13** (H2) `admit` đòi `feeToken ∈ {0, sellToken, buyToken}`. Quy lỗi cặp fail bằng chứng cứ, không đoán:
  `eth_call settleOne(m, relayer)` với `from = DEX` trả lý do revert — lỗi DEX mang `orderHash`, lỗi token
  (`SafeERC20FailedOperation(token)`) quy cho bên trả token đó trong cặp (M trả X, T trả Y, mỗi bên trả token phí
  của mình). Chỉ khi lý do chỉ vào lệnh mới thì 400; chỉ vào maker ⇒ loại maker (`invalid`) và thử lại. Maker fail
  trong 2 cặp với 2 taker khác nhau ⇒ gỡ. `sync_once` dùng cùng quy lỗi: chỉ bên bị quy lỗi không được trả về (thay
  `ponytail` "bỏ cả bên khoẻ", `venue.rs:500, 542`). Test: maker `feeToken` độc không chặn maker lành sâu hơn, không
  chặn khôi phục.
- **RS5-14** (H3; UA F10; thay §1.6 D11) `_validSig` nhánh hợp đồng: `staticcall` assembly với trần
  `_erc1271Gas(signer)` = 400k nếu `signer.codehash` = codehash clone `SubjectAccount` (immutable lúc deploy, như
  `MetaToken`), ngược lại 50k; chép tối đa 32 B returndata; trước lời gọi đòi `gasleft() ≥ cap · 64/63 + dự phòng`,
  không thì revert cả tx (EIP-150: relayer không được bỏ đói gas để biến chữ ký đúng thành sai). `cancel` không cần
  `try`: `_validSig` có trần chỉ trả `false` ⇒ mục bị bỏ qua. Node: cặp có lý do OOG (RS5-13) ⇒ lệnh 1271 đó không
  được khôi phục. Contract là bất biến ⇒ bản sửa là **deploy mới** (chain dev; người dùng `approve` lại spender mới).
  Test forge như §6 dòng "Thiếu".
- **RS5-15** (H4) Settle non-EVM gắn relayer (§5 mục 6). Test: bên thứ ba settle trên Cosmos/Soroban/TON fail.
  **Soroban không cho `relayer` = 0 (mở)** (net-soroban **R8-10**): `Order.relayer: Address` bắt buộc, vì với dạng
  mở ai thấy một `settle` đang chờ cũng nộp lại hai auth entry với `maker_fill = 1` ⇒ hai nonce bị tiêu cho một khớp
  bụi, `settle` thật fail (tấn công dust-fill). Test Soroban: lệnh không có `relayer` không dựng được / bị từ chối.
- **RS5-16** (M1) Cam kết cộng dồn gồm phần đã khớp chưa `settled`/`failed`, theo (maker, token), xoá khi trade
  xong. Test: số dư 100, ask #1 100 khớp và chờ ⇒ ask #2 100 bị từ chối.
- **RS5-17** (M2) Đối chiếu `markets(key)` on-chain mỗi vòng `poll` (≤ 30 s); lệch ⇒ ngừng phục vụ thị trường đó
  (không khớp, không nhận lệnh) tới khi khớp lại. Test: `setMarket` nâng ppm ⇒ thị trường ngừng phục vụ trong một vòng.
- **RS5-18** (M3) Matcher có cờ theo family `ioc_single_maker` (bật cho Sui/Aptos/Solana) như FOK: IOC chỉ khớp một
  maker. Bắt buộc trước khi N3 phục vụ sổ non-EVM. Test cargo.
- **RS5-19** (L1) `min_nonce < 2^(w−1)` trên Sui/Aptos (`w = 128`) và Solana (`w = 64`). Test mỗi mạng.
- **RS5-20** (L5) `dex_fill_ingest` lật `failed`+`restored` → `settled` (`dex_trade.py:195-198`) thì node trừ
  lượng đó khỏi sổ ở lần sync kế (trong R105: item `dex_trade` settled muộn ⇒ trừ `remaining` của lệnh đã khôi phục).
  Test: `Matched` muộn sau khôi phục ⇒ sổ không còn thanh khoản ma.

### Ruling rev 1.2 — từ review Claude 1 của spec thanh toán (L4, 2026-10-07)

- **RS5-21** (PD review L4; thay phần phí DEX của RS5-6) **Phí DEX mỗi fill làm tròn lên.** Hiện
  `fill * ppm / PPM` làm tròn xuống (`OrderBookDex.sol:216-217`; non-EVM cũng vậy: Sui `dex.move:250-251`, Aptos
  `dex.move:247-248`, Solana `dex.rs:208-210`, TON `dex.tact:208`) ⇒ chia lệnh thành fill `< PPM/ppm` đơn vị (ví dụ
  ≤ 333 đơn vị ở 0,3 %) thì phí thị trường = 0; trên chain riêng phí gas 0 nên chia nhỏ không tốn gì. Sửa: khi
  `feeOn` và `ppm > 0`, phí = `Math.mulDiv(fill, ppm, PPM, Math.Rounding.Ceil)` (non-EVM: `(fill·ppm + PPM − 1) / PPM`
  trên số rộng gấp đôi). `maxFeePpm` đã ký giới hạn **tỉ lệ**; làm tròn lên thêm dưới 1 đơn vị nhỏ nhất mỗi fill —
  đó là ngữ nghĩa mới của trần, ghi vào NatSpec. `ppm ≤ MAX_FEE_PPM` (1 %) < `PPM` ⇒ phí ≤ fill, `amount − fee` không
  tràn dưới; fill 1 đơn vị trả phí 1 (bên nhận nhận 0) là giá của lệnh bụi. Phí relayer giữ làm tròn xuống (RS5-6:
  tổng ≤ `fee` đã ký). **Node không đổi:** matcher không tính phí DEX (chỉ so `maxFeePpm` với phí thị trường,
  `dex.rs:565, 616-624`; phí DEX bị trừ trong chính lượng chuyển nên `fundable` không đổi), Odoo đọc `dexFee` từ event
  `OrderFilled`. Test forge: `ppm = 3_000`, fill 333 ⇒ phí 1 (trước: 0); fill 1 ⇒ phí 1, bên nhận 0; fill bội đúng ⇒
  phí như cũ; một fill 1 000 so với mười fill 100 ⇒ tổng phí mười fill ≥ phí một fill; fuzz `fill`, `ppm ≤ MAX_FEE_PPM`
  ⇒ `fee ≤ fill` và `fee · PPM ≥ fill · ppm`; `dexFee` trong event = lượng chuyển cho `feeRecipient`; `feeOn = false`
  ⇒ không có lệnh chuyển phí; sửa `test_feeOnSplitsReceivedAmountsWithoutDust` (`OrderBookDex.t.sol:439-454`, đang kỳ
  vọng làm tròn xuống) sang làm tròn lên. Mỗi mạng non-EVM một test tương đương (fill bụi trả phí 1).

**Luồng code** (owner: không sửa code trong pha spec; làm sau §0 TODO):

| Luồng | Lớp | Nội dung | Ruling |
|---|---|---|---|
| **DX-FIX1** | Node `dex.rs` | Maker dust: bỏ qua + gỡ; test | RS5-12 |
| **DX-FIX2** | Node `dex.rs`, `dex/venue.rs` | Giới hạn `feeToken`; quy lỗi cặp qua `eth_call settleOne`; gỡ maker sau 2 fail; không khôi phục cặp OOG; tests | RS5-13, RS5-14 (phần node) |
| **DX-FIX3** | Contract `OrderBookDex.sol` | 1271 có trần + returndata ≤ 32 B + chặn bỏ đói gas; phí DEX làm tròn lên mỗi fill; tests forge (1271 trong lô, phát lại chéo DEX/chain, invariant mở rộng, làm tròn phí); deploy mới. **Gộp PAY-FIX6** (spec thanh toán, review L3: cùng trần gas ERC-1271) **và phần EVM của PAY-FIX7** (review L4) | RS5-14, RS5-21 |
| **DX-FIX4** | Contract Cosmos/Soroban/TON + Sui/Aptos/Solana | Relayer gắn trong lệnh (3 mạng; Soroban bắt buộc, R8-10); trần `min_nonce` (3 mạng); phí DEX làm tròn lên (các mạng có phí ppm); tests. **Gộp phần non-EVM của PAY-FIX7** | RS5-15, RS5-19, RS5-21 |
| **DX-FIX5** | Node (+ `dms_blockchain_dex`) | Cam kết gồm trade chờ; đối chiếu thị trường mỗi `poll`; `ioc_single_maker`; trừ sổ khi `Matched` muộn; tests | RS5-16, 17, 18, 20 |

PAY-FIX6/7 không còn là luồng riêng (spec thanh toán §15.5 ghi gộp). PAY-FIX7 bỏ vế "node matcher": node không tính
phí DEX (RS5-21).

DX-FIX1/2/5 sửa đúng file mà NI **P7** (DEX lên store, R105) viết lại: làm trước P7 nếu P7 chưa bắt đầu, không thì
gộp vào P7 (ruling vẫn áp).

---

## 8. Review log

### Antigravity (agy) — review thiết kế, 2026-10-03 — 24 finding (đối chiếu từng cái)

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| D1 | crit | Đúng (mô tả mâu thuẫn): phí relayer cộng thêm, không trừ vào fill | Nhận: §1.2/§1.5 ghi rõ; intake đòi `fundable >= remaining + phí` |
| D2 | crit | Một phần: thiết kế đã kiểm `limits_ok` y hệt contract nên không gửi cặp bị revert; phần lẻ nghỉ lại | Nhận phần ghi rõ; từ chối "revert on-chain" |
| D3 | crit | Đúng (nếu relayer khác giữ lệnh) | Nhận: IOC đóng phần còn lại cuối tx; cộng RS5-9 |
| D4 | crit | Đúng: job huỷ hết hạn ⇒ lệnh đã gỡ vẫn settle được | Nhận: bỏ `validUntil` khỏi chữ ký huỷ (RS5-10) |
| D5 | crit | Đúng | Nhận: IOC/FOK không bao giờ trả về sổ |
| D6 | crit | Đúng | Nhận: cam kết cộng dồn theo (maker, sellToken) |
| D7 | crit | Đúng về cách viết (mỗi phí một token) | Nhận: §4 ghi rõ |
| D8 | crit | **Sai so với yêu cầu owner**: owner yêu cầu hạch toán *chi phí* phí relayer (công ty giao dịch bằng ví trả của mình); relayer thu phí là luồng khác | Từ chối; giữ "phí relayer chi" |
| D9 | crit | Đúng (tên/đơn vị) | Nhận: `remaining_sell` |
| D10 | high | Đúng | Nhận: `NothingSettled` |
| D11 | high | Đúng về `ERC20MetaTx`; DEX vốn không trần gas | Ghi rõ §1.6 |
| D12 | high | Một phần: token phí riêng là con số tuyệt đối đã ký; không thêm oracle | Ghi rõ §1.5; từ chối hạn chế |
| D13 | high | Đúng về watcher (contract đã có event) | Nhận: watcher ingest + gỡ khỏi sổ |
| D14 | high | Đúng | Nhận: gom huỷ một tx + trần mỗi maker |
| D15 | high | **Sai**: cặp đã khớp là giao dịch đã chốt lúc lệnh còn sống (như mọi sàn); huỷ chỉ áp phần còn lại. Nếu tx huỷ vào block trước, cặp đó `MatchFailed` và đối ứng được trả về sổ — kết quả an toàn | Từ chối |
| D16 | high | Đúng cho hiển thị (khớp lệnh vốn so bằng nhân chéo) | Nhận: giá hiển thị thập phân đã quy đổi |
| D17 | high | Đúng | Nhận: `flags == 3` bị từ chối |
| D18 | high | Một phần: relayer chọn vai, nhưng phí bị chặn bởi `maxFeePpm` từng bên đã ký; book gán vai theo thời gian; RS5-9 chỉ relayer này nộp được | Từ chối thay đổi contract |
| D19 | med | Đúng | Nhận: UNIQUE không thứ tự |
| D20 | med | Đúng | Nhận: lỗi commit ⇒ nạp lại từ Odoo |
| D21 | med | Đúng | Nhận: bỏ qua lệnh cùng maker |
| D22 | med | Đúng | Nhận |
| D23 | low | Đúng | Nhận: trần `2^128` |
| D24 | low | Đã có (`FeeModeInvalid`) | Không đổi |

Grok: giới hạn quota (`free Grok Build usage limit`) — lần 1 của luồng S5.

### Review implementation (diff `71f3ffb..HEAD`), 2026-10-03

agy: quota (429) lúc chạy, chạy lại sau reset. Grok: hết hạn mức free. Codex: hết credit. Reviewer Claude độc lập: 5 finding.

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| I1 | low | Đúng về spec: approve meta-tx `FIXED` > 0 revert vì trần tính trên `value = 0` (đã có test cố ý) | Sửa spec: phí relayer của approve luôn 0 |
| I2 | high | Đúng: lệnh `taker != 0` hoặc `maxFeePpm` < phí thị trường, hay thiếu phí relayer, nằm đầu sổ làm mọi cặp fail và lệnh lành bị từ chối | `admit` từ chối lệnh riêng tư + trần phí thấp; matcher bỏ qua maker có trần dưới phí (phí tăng sau); `funded` tính cả phí relayer |
| I3 | high | Đúng: sync kẹt mãi khi một bên hỏng / lệnh đã đóng ở Odoo; huỷ chờ mất khi commit lỗi | `dex_sync` gửi null cho lệnh đã đóng; khôi phục chỉ lệnh `funded`; cặp khớp lại fail ⇒ không trả về hai bên đó, vẫn ack (≤ `MAX_ROUNDS`); huỷ chờ trả lại hàng đợi khi commit lỗi |
| I4 | low | Đúng: huỷ off-chain nhận chữ ký high-s mà contract bỏ qua | `valid_sig` từ chối high-s |
| I5 | med | Đúng: `_cron_expire` của job ghi `dead` thẳng, bỏ qua hook | Hook chuyển sang `write` của relay job |
| I6 | high | Tự review lại fix I3: vòng khớp lại mới bỏ mất bước ghi `touched` ⇒ lệnh trả về sổ mà không khớp lại chỉ nằm trong bộ nhớ, Odoo vẫn `filled`, restart là mất | Ghi lại mọi lệnh `touched` vào commit; e2e bước 9 (một bên null) + restart; mutation đã kiểm test bắt được |
| I7 | low | Tự review fix I4: high-s trả `false` ngay nên ví hợp đồng (contract đi ERC-1271 theo code) ký 65 byte high-s bị node từ chối dù contract nhận | High-s chỉ bỏ qua khôi phục cục bộ, vẫn rơi xuống `isValidSignature`; e2e bước 6 gửi bản high-s ⇒ 400 |

### Claude review disposition — review 1 (2026-10-07, `docs/reviews/specs/2026-10-03-dex-design-claude-review-1.md`)

Verdict của review: FIX-THEN-GO, 0 Critical. Đối chiếu từng finding với code (file:line) trước khi nhận: **16 nhận,
0 từ chối** (2 nhận có chỉnh cách sửa).

| # | Sev | Kiểm với code | Kết luận | Xử lý |
|---|---|---|---|---|
| H1 | high | `dex.rs:634-643` `break` cả khi maker là dust; test `dex.rs:920` chỉ kiểm `limits_ok` | Đúng | RS5-12, §3.3; DX-FIX1 |
| H2 | high | `venue.rs:317-324` (maker khoẻ ⇒ 400), `funded` tin `feeFundable` (`venue.rs:786-790`), `admit` không giới hạn `feeToken` (`dex.rs:532-592`), phí là `safeTransferFrom` thật (`OrderBookDex.sol:283`); `sync_once` bỏ cả hai bên (`venue.rs:536-542`) | Đúng | RS5-13, §3.4; DX-FIX2 |
| H3 | high | `OrderBookDex.sol:383-384` `SignatureChecker` không trần, OZ chép toàn bộ returndata; `cancel` không `try` (`:317-325`); một job mỗi thị trường (`venue.rs:711-727`) | Đúng; chỉnh: không cần `try` từng mục trong `cancel` vì `_validSig` có trần chỉ trả `false`; thêm chặn bỏ đói gas (EIP-150) | RS5-14, §1.6; DX-FIX3 (+ phần node ở DX-FIX2) |
| H4 | high | Cosmos `lib.rs:29-34, 145` không kiểm sender; Soroban `lib.rs:158-159` chỉ trói lệnh; TON `dex.tact:138-144` mở; Sui/Aptos/Solana có kiểm | Đúng (tiềm ẩn tới N3, contract đã BUILT) | RS5-15, §5.6; DX-FIX4 |
| M1 | med | `Book::committed` chỉ cộng lệnh nghỉ (`dex.rs:449-462`), `fundable` từ chain (`venue.rs:290`) | Đúng | RS5-16; DX-FIX5 |
| M2 | med | `onchain_matches` chỉ ở `start` (`venue.rs:188-196`), `run_loops` không có (`:620-637`) | Đúng | RS5-17, §3.1; DX-FIX5 |
| M3 | med | IOC đóng ở lần khớp đầu: Sui `dex.move:334`, Aptos `:395`, Solana `dex.rs:204`; matcher không dừng IOC sau một maker | Đúng (tiềm ẩn tới N3) | RS5-18, §3.3; DX-FIX5 |
| M4 | med | NI R105/R102, UA §5.4 + F10, mesh-gossip R124 §11.6 có thật; `SCaaS.md:54` chỉ ghi RS5-* | Đúng | Bảng "bị thay" đầu spec; chú thích ở RS5-2/9/11, §1.6 |
| L1 | low | Sui `dex.move:294-296`, Aptos `:299-300`, Solana `dex.rs:340` không trần; EVM là `2^128 − 1` (`:89`) | Đúng | RS5-19, §1.3 sửa số; DX-FIX4 |
| L2 | low | Cosmos/TON FOK (R9-2/R10-7); không `min_nonce` ở Cosmos/Soroban/TON; người nhận phí một DEX (Cosmos `InstantiateMsg`, Soroban `Key::FeeRecipient`); Solana một `fee_ppm`; không kiểm self-trade ở Cosmos/Soroban | Đúng | Bảng sai khác §5 |
| L3 | low | `ST_BAD_FEE = 7` (`OrderBookDex.sol:100`, `351-362`) | Đúng | §1.6 |
| L4 | low | §3.3/RS5-3 mâu thuẫn §1.2/D3; code đóng IOC (`:188-198`) | Đúng | RS5-3 sửa, §3.3 |
| L5 | low | `dex_trade.py:195-198` lật `failed`→`settled` khi `Matched` muộn | Đúng (on-chain an toàn; sổ có thanh khoản ma, tốn gas) | RS5-20; DX-FIX5 |
| T1 | test | Phát lại chéo DEX/chain: chỉ KAT dương (`OrderBookDex.t.sol:667`) | Đúng | §6 "Thiếu"; DX-FIX3 |
| T2 | test | Invariant §1.8: `OrderBookDexInvariant.t.sol` một ask, không phí relayer, không IOC, không nhiều maker | Đúng | §6; DX-FIX3 |
| T3 | test | Test cho H1–H4, M1–M3 không có | Đúng | §6; theo từng luồng |

## 9. Lịch sử bản

| Rev | Ngày | Thay đổi |
|---|---|---|
| 1.0 | 2026-10-03 | Bản đầu (S5): RS5-1…11; review agy D1–D24, review implementation I1–I7 |
| 1.1 | 2026-10-07 | Gộp review Claude 1: bảng "bị thay" (R105, F10, R124, R102); RS5-3 sửa; RS5-12…20; bảng sai khác non-EVM §5; test thiếu §6; luồng code DX-FIX1…5 |
| 1.2 | 2026-10-07 | 2026-10-07 clean-up: RS5-15 ghi Soroban không có relayer mở (net-soroban R8-10); RS5-21 phí DEX làm tròn lên mỗi fill (PD review L4); PAY-FIX6 gộp vào DX-FIX3, PAY-FIX7 vào DX-FIX3/4 |
