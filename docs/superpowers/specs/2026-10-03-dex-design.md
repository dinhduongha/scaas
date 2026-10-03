# DEX — sổ lệnh off-chain bền, thanh toán on-chain (R35)

**Ngày:** 2026-10-03 · **Luồng:** S5 (`r3-dex`) · **Bổ sung cho:** round-3 design §F R35, spec gốc §2.3/§3.4
(R3, R16 — **bị thay** ở đây), addendum R26, round-3 R30.

Ruling của luồng đánh số `RS5-n` (lead đánh lại số khi merge).

---

## 0. Tóm tắt

| Lớp | Thứ được xây | Thay cái gì |
|---|---|---|
| Contract | `OrderBookDex` (`src/dex/OrderBookDex.sol`): kiểm hai lệnh EIP-712 (ECDSA/ERC-1271), giới hạn giá, `filled[orderHash]`, khớp một phần, batch nguyên tử từng cặp, `transferFrom` trực tiếp người→người (DEX không giữ tiền), phí DEX theo thị trường (bật/tắt, ppm maker/taker, trần 1 %), phí relayer theo `FeeMode` có sẵn, huỷ on-chain bằng chữ ký | `MetaTxDex` (R3: fill-or-kill, không allowance) **giữ nguyên làm legacy**, không còn route gateway |
| Token | `MetaToken`: op meta-tx `approve(address spender,uint256)` — spender phải là contract (R26) | — |
| Node | `bamboo-node/src/dex.rs`: sổ lệnh theo thị trường, ưu tiên giá-thời gian, limit + IOC/FOK, khớp một phần; lưu bền **ở Odoo qua `/json/2`**; settle qua outbox `call` job; watcher event final riêng của DEX | sổ trong bộ nhớ (R16) |
| Gateway | `/v1/dex/*`: đặt lệnh, huỷ, huỷ-hết, markets, depth, trades, ticker, lệnh của một ví | `POST/GET /v1/dex/orders` kiểu chân meta-tx |
| Odoo | addon `dms_blockchain_dex`: cấu hình thị trường, sổ/khớp chỉ đọc, hạch toán phí DEX (thu) + phí relayer (chi) qua journal (công ty, token) | — |

---

## 1. Contract `OrderBookDex`

### 1.1 Lệnh ký (EIP-712)

Domain: `name = "Bamboo OrderBookDex"`, `version = "1"`, `chainId`, `verifyingContract = DEX`. Lệnh ký **trên DEX**,
không trên token: một chữ ký cho cả hai token của cặp, ví hiển thị một loại lệnh.

```
Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,
      uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,
      address feeToken,address feeRecipient)
CancelOrder(bytes32 orderHash,uint256 validUntil)
InvalidateNonces(address maker,uint256 minNonce,uint256 validUntil)
```

| Trường | Nghĩa |
|---|---|
| `maker` | người ký; EOA (ECDSA low-s) hoặc contract (ERC-1271, account passkey/seed của S4) — phân biệt bằng code như `ERC20MetaTx` (designator EIP-7702 = EOA) |
| `taker` | 0 = ai cũng được; khác 0 = chỉ đối ứng này (RFQ) |
| `sellAmount`, `buyAmount` | tổng bán / tổng tối thiểu nhận (gross, trước phí DEX). Giá giới hạn = `buyAmount/sellAmount` |
| `nonce` | duy nhất theo maker; lệnh hợp lệ khi `nonce >= minNonce[maker]` (huỷ hàng loạt). Client dùng `unix_ms·2^20 + random20` |
| `expiry` | hạn ký, giây epoch; `block.timestamp <= expiry` |
| `maxFeePpm` | phí DEX tối đa người ký chấp nhận (vai nào cũng vậy). Phí thị trường > `maxFeePpm` ⇒ cặp revert. Nâng phí **không** chạm lệnh đã ký |
| `flags` | bit0 `FOK`, bit1 `IOC`; bit lạ ⇒ revert (như `validateMode`) |
| `relayer` | 0 = relayer nào cũng nộp được; khác 0 = chỉ `msg.sender` này (R10) |
| `feeMode`, `fee`, `feeToken`, `feeRecipient` | phí **relayer** (§1.5) |

Không có `lane/batch` của token ở đây: DEX tự giữ không gian nonce (`minNonce`, `filled`) — R30, §1.7.

### 1.2 `settle(Match[] ms) returns (bool[] ok)`

`Match = {bytes32 ref; Order maker; bytes makerSig; Order taker; bytes takerSig; uint256 makerFill; uint256 takerFill}`
— `makerFill` là lượng `maker.sellToken` maker giao, `takerFill` là lượng `taker.sellToken` taker giao. `ref` do
relayer đặt, chỉ được echo trong event (khoá trade ở Odoo).

Mỗi cặp chạy trong `try this.settleOne(m, msg.sender)` (external, chỉ `msg.sender == address(this)`): **nguyên tử
từng cặp** — cặp fail revert riêng phần của nó, emit `MatchFailed(ref, reason)`, các cặp khác vẫn chạy.
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
Tổng mỗi token bảo toàn chính xác: người trả mất đúng `fill`, phần còn lại chia cho người nhận + người thu phí; DEX
không giữ gì ⇒ **không dust**. Thị trường tắt phí ⇒ ppm coi như 0 ⇒ không có lệnh chuyển phí nào (không phải "phí
0 được chuyển").

7. `emit OrderFilled(ref, hash, owner, Fill)` cho **mỗi** bên (`Fill` = struct: sellToken, sold, buyToken,
   received net, dexFee, dexFeeRecipient, relayerFeeToken, relayerFee, relayerFeeRecipient, filledTotal) — Odoo hạch
   toán theo góc nhìn từng ví; `emit Matched(ref, makerHash, takerHash)`.

Giá thực hiện do relayer chọn trong giới hạn của cả hai. Book của ta luôn khớp **giá của lệnh nghỉ (maker)**,
làm tròn có lợi cho maker (`takerFill = ceil(makerFill · M.buy / M.sell)`), và chỉ phát cặp qua đúng hàm kiểm
giới hạn giống contract (§3.3).

### 1.3 Huỷ on-chain (meta-tx — người dùng không cần gas)

- `cancel(Order o, uint256 validUntil, bytes sig)`: chữ ký `CancelOrder(hash(o), validUntil)` của `o.maker` ⇒
  `filled[h] = o.sellAmount` (đóng vĩnh viễn: lệnh đã huỷ **không bao giờ** settle được, kể cả bởi relayer khác
  đang giữ bản ký). Phát lại vô hại (idempotent); có `validUntil` cho đồng bộ quy tắc "mọi chữ ký có hạn".
- `invalidateNonces(maker, minNonce, validUntil, sig)`: `minNonce` phải **tăng** ⇒ phát lại bị từ chối;
  vô hiệu mọi lệnh `nonce < minNonce` (huỷ tất cả).

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

### 1.6 Hàm đọc cho intake

`checkOrder(Order o, bytes sig) view returns (bytes32 hash, uint8 status, uint256 remaining, uint256 fundable,
uint256 feeFundable)`: `status` ∈ `OK, EXPIRED, NONCE_INVALID, BAD_SIG, CLOSED, BAD_FLAGS, NOT_LISTED`;
`fundable = min(balanceOf, allowance(DEX))` trên `sellToken`, `feeFundable` tương tự trên token phí relayer. Một
`eth_call` cho mọi kiểm ở cửa (chữ ký kể cả ERC-1271, số dư, allowance, đóng/huỷ, nonce).

### 1.7 R26 và R30

- **R26:** DEX là spender duy nhất. Người dùng `approve` **không gas** qua op meta-tx mới của `MetaToken`:
  `data = approve(address spender,uint256 amount)` (68 byte, selector-tagged như `pay`/`trade`); bước 6 kiểm
  `m.value == 0`, `m.to == spender`, spender là contract (`_isContract`, 7702 = EOA ⇒ từ chối); bước 8
  `_approve(from, spender, amount)` thay vì transfer. Phí relayer của chính meta-tx approve theo mode hiện có
  (`FIXED` bằng token đó; `PERCENT` trên `value = 0` ra 0). `transferFrom` chỉ do contract gọi — DEX là contract.
- **R30:** DEX không đọc/ghi `metaNonce` của token. Lệnh dùng `filled`/`minNonce` của DEX; `approve` dùng lane
  ngẫu nhiên riêng (`keccak("bamboo.dex.approve" ‖ rand)`, nonce 0). Hệ quả kiểm bằng test: lệnh DEX treo/huỷ
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
   trade + job) ⇒ thành công mới thay sổ trong bộ nhớ. Commit lỗi ⇒ sổ không đổi, trả 503.
3. **Trade fail** (job `dead/reverted`, hay event final `MatchFailed`): Odoo đặt trade `failed`. Vòng `dex_sync` của
   node (mỗi `poll`) lấy trade fail chưa xử lý ⇒ với từng lệnh: còn hợp lệ on-chain (`checkOrder`) thì
   `remaining += fill` (trả lại đúng chỗ theo `seq` cũ), không thì loại ⇒ commit + ack.
4. **Final:** watcher DEX (§3.6) gửi `OrderFilled/Matched/MatchFailed` vùng final ⇒ trade `settled` ⇒ hạch toán.

---

## 3. Node (`bamboo-node/src/dex.rs`)

### 3.1 Thị trường & phía

Thị trường `(base, quote)` lấy từ Odoo (`dex_markets`), đối chiếu với `markets(key)` on-chain lúc nạp và mỗi 30 s;
lệch (niêm yết/phí/người nhận) ⇒ thị trường đó **không** được phục vụ + log (drift Odoo ↔ chain).
Lệnh bán `base` = **ask**, giá `buyAmount/sellAmount` (quote/base); lệnh bán `quote` = **bid**, giá
`sellAmount/buyAmount`. So giá bằng nhân chéo `U256` (lượng ở cửa `< 2^128` ⇒ không tràn).

### 3.2 Ưu tiên giá-thời gian

Mỗi phía một `Vec` sắp theo (giá tốt nhất, `seq` tăng). `seq` cấp đơn điệu lúc nhận, lưu ở Odoo, nạp lại giữ nguyên.

### 3.3 Khớp (thuần, không I/O)

Lệnh tới `O` đi qua phía đối diện theo thứ tự; với lệnh nghỉ `R` (maker) còn `R.rem`:
`x = min(R.rem, floor(O.rem · R.sell / R.buy))`, `y = ceil(x · R.buy / R.sell)`; `x = 0` ⇒ dừng; kiểm
`limits_ok(R, O, x, y)` **giống hệt** contract (§1.2 bước 3–4, kể cả FOK); không qua ⇒ dừng ở R (dust).

- **GTC limit:** phần còn lại nghỉ trong sổ.
- **IOC:** khớp được bao nhiêu thì khớp, phần còn lại huỷ (không nghỉ). Cờ IOC **không** kiểm on-chain (contract
  không biết "ngay") — **RS5-3**: bảo vệ on-chain là `expiry` ngắn; client đặt `expiry` IOC ≤ 60 s.
- **FOK — RS5-4:** cờ kiểm **on-chain**: lệnh FOK chỉ settle trong **một** cặp lấp đầy `sellAmount`. Book chỉ khớp
  FOK với một lệnh nghỉ đơn lẻ (đầu tiên theo giá-thời gian) đủ lấp trọn; không có ⇒ huỷ toàn bộ. Không gộp
  nhiều đối ứng cho FOK: "tất cả hoặc không" qua nhiều cặp trong batch nguyên tử-từng-cặp không chứng minh được
  on-chain. Khớp một phần là mặc định cho mọi loại khác (thay R3).
- Lệnh nghỉ không bao giờ là FOK/IOC (chúng không nghỉ).

### 3.4 Chặn spam ở cửa

Body ≤ 64 KiB (có sẵn); lượng `0 < amount < 2^128`; `expiry ∈ (now+5 s, now+30 ngày]`; tối thiểu theo thị trường
(`min_base_amount` trên phía base); tối đa `MAX_OPEN_PER_MAKER = 50` lệnh mở mỗi maker mỗi chain; trần toàn sổ
`MAX_RESTING = 10 000`; hash trùng ⇒ từ chối; `relayer ∉ {0, ví relayer này}` ⇒ từ chối; `checkOrder` phải `OK` với
`fundable >= remaining` và đủ phí relayer. Huỷ on-chain (tốn gas relayer) chỉ cho lệnh đang có trong sổ; huỷ-hết
chỉ khi maker còn ≥ 1 lệnh mở — mỗi lần tốn gas phải đi kèm một lệnh đã qua kiểm tiền.

### 3.5 Gateway (`/v1/dex/*`)

| Route | Việc |
|---|---|
| `POST /v1/dex/orders` `{chain, order, signature}` | đặt lệnh ⇒ `{hash, status: resting/partial/filled/cancelled, fills[]}` |
| `POST /v1/dex/cancel` `{chain, orderHash, validUntil, signature}` | chữ ký `CancelOrder` ⇒ bỏ khỏi sổ **ngay** + job on-chain `cancel` |
| `POST /v1/dex/cancel-all` `{chain, maker, minNonce, validUntil, signature}` | `InvalidateNonces` ⇒ bỏ mọi lệnh `nonce < minNonce` + job on-chain |
| `GET /v1/dex/markets?chain` | thị trường + phí |
| `GET /v1/dex/depth?chain&market&levels` | mức giá gộp hai phía |
| `GET /v1/dex/trades?chain&market` | khớp gần nhất (vòng 200 trong bộ nhớ; lịch sử ở Odoo) |
| `GET /v1/dex/ticker?chain&market` | giá cuối, bid/ask tốt nhất, khối lượng trong vòng nhớ |
| `GET /v1/dex/orders?chain&maker` | lệnh mở của một ví |

`dex_routes()` trả một `Router` riêng; `gateway::router` `merge` nó — lớp auth của lead (§A.6, R54) bọc router
ngoài cùng, không cần biết route DEX. Không WebSocket (**RS5-5**): `axum` `ws` kéo `tokio-tungstenite`; client poll
`depth`/`trades` là đủ cho khối lượng hiện có.

### 3.6 Watcher DEX final

Một task riêng mỗi chain: cùng `finality::{safe_head, next_range, quorum_ok}`, **cursor riêng**
(`blockchain.chain.dex_indexed_block`), đọc log của địa chỉ DEX, gửi `dex_fill_ingest` bằng **API key indexer**.
Cursor riêng là R30 ở tầng vận hành: DEX ingest lỗi không bao giờ chặn chốt thanh toán và ngược lại; và không
sửa `indexer.rs` của lead.

---

## 4. Odoo `dms_blockchain_dex`

`depends: ['dms_blockchain', 'dms_blockchain_payment']`.

| Model | Trường chính |
|---|---|
| `blockchain.chain` (inherit) | `dex_address`, `dex_indexed_block` (chỉ watcher ghi) |
| `blockchain.dex.market` | `company_id` (công ty vận hành), `chain_id`, `base_token_id`, `quote_token_id`, `fee_on`, `maker_fee_ppm`, `taker_fee_ppm` (CHECK 0..10 000), `fee_wallet_id` (ví nhận đã duyệt của công ty), `min_base_amount`, `income_account_id`, `relayer_expense_account_id`, `journal_id` (dự phòng khi token chưa có journal), `active`; UNIQUE (chain, base, quote) |
| `blockchain.dex.order` | `market_id`, `order_hash` (UNIQUE theo chain), `maker_address`, `side` (bid/ask), lượng (Char uint, CHECK), `remaining_base`, `nonce`, `expiry_ts`, `flags`, `max_fee_ppm`, phí relayer, `signature_hex`, `order_json`, `seq`, `order_state` (open/partial/filled/cancelled/expired/invalid) |
| `blockchain.dex.trade` | `trade_ref` (UNIQUE), `market_id`, `maker_order_id`, `taker_order_id`, `maker_fill_base`, `taker_fill_base`, phí dự kiến/thực tế, `relay_job_id`, `trade_state` (pending/settled/failed), `restored` (node đã xử lý fail), `tx_hash`, `block_number`, `move_ids` |

RPC (public, `check_service`): `dex_markets`, `dex_book_load`, `dex_book_commit`, `dex_sync` (relay_worker);
`dex_fill_ingest` (indexer). Không nhận company từ node: company suy từ market.

**Hạch toán (khi trade `settled`, tức event final):** seam `blockchain.token._dex_journal(company)` — trả
`journal_id` company-dependent của token nếu trường đó tồn tại (lead thêm, R56) và có giá trị, ngược lại
`market.journal_id`. Số tiền = `base / 10**decimals` theo `currency_id` của token (neo 1:1, R17).
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

---

## 6. Test

| Lớp | Test |
|---|---|
| forge | không overfill (unit + fuzz + invariant), giới hạn giá hai bên, FOK, phí bật/tắt không dust, `maxFeePpm`, huỷ (chữ ký, phát lại, nonce), batch nguyên tử từng cặp, ERC-1271 maker, R26 (approve op: spender EOA/7702 bị từ chối, value≠0 bị từ chối), R30 (DEX ↔ pay độc lập), phí relayer 3 mode + `FeeWouldStick`, KAT EIP-712 → `test/vectors/dex_kat.json` |
| cargo | khớp giá-thời gian, một phần, IOC, FOK, giới hạn khớp == contract, snapshot/nạp lại (bền), chặn spam, KAT digest, decode event |
| e2e (anvil 31950–31959, gateway 18650–18659) | approve meta-tx → hai lệnh qua gateway → khớp một phần → job settle qua outbox → số dư; huỷ ⇒ settle không bao giờ chạy; khởi động lại venue ⇒ sổ còn nguyên |
| Odoo (`dms_test_chain_5`/8925) | commit/load khứ hồi, quyền service, trade fail khi job dead, ingest ⇒ settled + bút toán phí, phí tắt ⇒ không bút toán, seam journal |

---

## 7. Rulings

- **RS5-1** Admin immutable (Safe ở production) chỉ `setMarket`; phí đổi được nhưng bị chặn bởi `maxFeePpm` đã ký +
  trần 1 % hằng số; không timelock.
- **RS5-2** Sổ lệnh lưu ở Odoo qua `/json/2`, node là người ghi duy nhất; settle là outbox `call` job. Thay R16.
- **RS5-3** IOC chỉ off-chain; bảo vệ on-chain là `expiry` ngắn.
- **RS5-4** FOK kiểm on-chain = một cặp lấp trọn; book chỉ khớp FOK với một đối ứng. Khớp một phần là mặc định.
  Thay R3.
- **RS5-5** Không WebSocket; poll.
- **RS5-6** Phí DEX trên phần nhận, làm tròn xuống; phí relayer FIXED pro-rata làm tròn xuống.
- **RS5-7** `MetaTxDex` giữ làm legacy (không route); `OrderBookDex` là DEX của gateway.
- **RS5-8** Watcher DEX có cursor riêng và gửi bằng key indexer; không sửa `indexer.rs`.
