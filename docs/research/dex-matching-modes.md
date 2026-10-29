> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# DEX: bốn chế độ khớp lệnh — book, nguồn ngoài, hybrid, CoW / ring

Đánh giá 2026-10-29, chưa code. Câu hỏi của owner: DEX nhận `TradeOrder`; cần (1) một taker khớp nhiều maker,
(2) khớp thẳng với AMM, có thể nhiều path, thứ tự do bên ngoài quyết định, (3) hybrid: khớp maker trước, phần còn
lại đi AMM. Owner đồng ý (2026-10-29) thêm chế độ thứ tư, CoW / ring, và phân loại theo **nguồn thanh khoản**, không
theo hàm contract. Mục này ghi những gì đã làm, những gì chưa làm, cần cải tiến gì. Nguồn: `docs/contracts/dex.md`,
`docs/node/dex-venue.md`, `smartcontracts/evm/src/dex/SCaaSDex.sol`, `test/v2/DexExchange.t.sol`, các program DEX
non-EVM.

## 0. Tóm tắt

| # | Chế độ khớp | Nguồn thanh khoản | Hàm contract (EVM) | Contract | Node | Non-EVM |
|---|---|---|---|---|---|---|
| 1 | Book | maker trong book, một cặp | `mtxSettle` | **BUILT** (P2b-1, P2b-2, UA-5b) | **BUILT** (venue P5) | chỉ **1 × 1** |
| 2 | Nguồn ngoài | pool AMM, contract khác (RFQ, aggregator), executor (solver, flash swap) | `mtxExchange` (interactions) / `mtxExchangeVia` (executor) | **BUILT** (P2c) | **SPECIFIED** (TradeEngine), chưa build | không có |
| 3 | Hybrid | maker trước, phần dư ra nguồn ngoài | `mtxExchange` / `Via`, **một** plan | ghép được, chưa test | spec chia 2 giao dịch → sai với IOC / FOK | không có |
| 4 | CoW / ring | chính các lệnh với nhau, nhiều cặp, nhiều taker | `mtxExchange`, phần lệch ròng ra nguồn ngoài | ghép được; CoW 2 lệnh có test | chưa có planner | không có |

Kết luận ngắn:
- Contract **giữ 2 nhóm hàm**: `mtxSettle` và `mtxExchange` / `Via`. Bốn chế độ là việc của planner trên node
  (TradeEngine). `Via` không phải chế độ thứ 5, chỉ là cách thực thi của chế độ 2, 3 và 4.
- Chế độ 1 xong trên EVM. Non-EVM chỉ khớp từng cặp.
- Chế độ 2 xong phía contract. Thiếu toàn bộ phía node, thiếu executor thật và fork test Uniswap.
- Chế độ 3 và 4 không cần entry mới. Việc cần làm: test cho đúng các dạng plan, sửa NODE-DEX-17 thành một plan nguyên
  tử, build planner.
- **Khớp chính xác một cặp gần như không bao giờ xảy ra** (mục 5.2). Giải pháp: không đòi khớp chính xác. Một plan bù
  trừ nội bộ những gì trùng nhau, phần lệch ròng đi nguồn ngoài, phần làm tròn để contract chia cho người ký.

## 1. Hàm contract và chế độ khớp

`mtxExchange` / `mtxExchangeVia` là **hàm contract**: nhận các leg (mỗi leg một lệnh đã ký, `sellFill` và floor
`receiveFill` do submitter chọn), chạy interactions hoặc gọi executor. Sau đó contract kiểm tra floor ≥ giới hạn đã
ký, conservation từng token, rồi chia surplus cho người ký. Hàm này không biết maker / taker, không biết book, không
biết thứ tự ưu tiên. **Chế độ khớp** là chiến lược của node: lệnh gặp nguồn thanh khoản nào, theo thứ tự nào, với floor
nào. Chế độ 2, 3 và 4 đều là các plan `mtxExchange` có hình dạng khác nhau.

So sánh hai nhóm hàm:

| | `mtxSettle` | `mtxExchange` (a) / `mtxExchangeVia` (b) |
|---|---|---|
| Hình dạng | 1 taker × N maker, đúng một cặp A/B | N leg bất kỳ, token "known", nhiều cặp, cycle X→X, chiều bất kỳ |
| Giá | contract tính giá maker `⌈fill·receiveAmount/amount⌉`; taker nhận đúng tổng (`FillMismatch`), toàn bộ price improvement về taker | mỗi leg chỉ cần floor ≥ giới hạn; phần vượt floor (`excess_T`) chia theo tỷ lệ floor giữa các leg nhận T, leg cuối nhận phần dư làm tròn (CTR-DEX-21) |
| Market | phải listed (`MarketNotListed`) | chỉ cần cả hai token "known" |
| Nguồn ngoài | không | (a) `Interaction[]` do submitter sắp thứ tự; (b) executor trả lại ≥ Σ floor trong `exchangeCallback` |
| Cô lập lỗi | `Settlement[]`, mỗi settlement tự revert (`MatchFailed`) | một plan mỗi giao dịch, nguyên tử: một leg hỏng làm hỏng cả giao dịch |
| Event | `LegSettled` / `UALegSettled` | `ExchangeLegSettled` / `UAExchangeLegSettled` (có `surplus`, `limitReceive`) |
| Phí | `fee` đã ký, một lần mỗi lệnh mỗi settlement, trên tổng nhận | trên floor; surplus không chịu phí |
| Bảo vệ | conservation 2 token | snapshot + conservation mọi token; chặn DEX / puller / `mtxTrade` / `uaTrade` / `increaseAllowance` / Permit2 `approve`; reset `approve`; `LISTED_POOLS` / listed-only |
| Chi phí | rẻ nhất: không snapshot, không interaction | đắt hơn: snapshot, interactions, conservation trên nhiều token |

Hệ quả cho mọi chế độ dựa trên `mtxExchange`: giá maker và cách chia surplus **thực chất là chính sách của submitter**.
Submitter chọn floor (miễn ≥ giới hạn), còn quy tắc pro-rata chỉ áp cho phần vượt floor. Contract bảo đảm mỗi người ký
nhận ít nhất giới hạn của mình và DEX không giữ lại gì. Contract không bảo đảm surplus được chia "công bằng". Vì vậy
`relayer` của lệnh mặc định là node venue (CTR-DEX-17, NODE-DEX-18).

## 2. Chế độ 1 — Book: một taker × nhiều maker

**Đã làm (EVM).**
- `mtxSettle(Settlement[])`, `Settlement{ref, taker, makers[]}`; vai trò taker / maker do submitter chọn lúc settle,
  lệnh không mang vai trò (CTR-DEX-13).
- Maker bán ở đúng giá của nó, làm tròn có lợi cho maker. Phí của taker tính một lần trên tổng nhận (CTR-DEX-17).
  Lệnh SCaaS Path A / Path B, lệnh token ngoài qua `DexPuller`, lệnh UA (shape 1) dùng chung một book.
- Settlement hỏng chỉ ra `MatchFailed`. Riêng lỗi thiếu gas (`SigCheckGasStarved` / `UAVerifyGas`) revert cả giao dịch.
- Node venue (P5): book theo market, price-time, IOC / FOK / GTC, xử lý dust (NODE-DEX-05), committed balance, gossip,
  managed market.

**Giới hạn hiện có (đúng spec).**
- Minimum fill 50 % (CTR-DEX-14) áp cho **mỗi** lệnh trong một settlement: lệnh Path A khớp tối đa ở hai settlement,
  và maker chỉ khớp với taker lấy ít nhất một nửa lệnh của nó. **Owner 2026-10-29: bỏ sàn này** (mục 6.3).
- Một settlement một cặp token. Ring A→B→C→A là chế độ 4.
- Số maker mỗi giao dịch bị giới hạn bởi gas verify của từng loại chữ ký (bảng CTR-DEX-26: `mldsa65` 2 leg, classical
  > 90).

**Non-EVM: chưa có 1 × N.** Mọi program khác đều khớp từng cặp:

| Family | Entry | Ghi chú |
|---|---|---|
| Sui / Aptos | `settle<A, B>(…)` một cặp | IOC đóng ở lần khớp đầu (NODE-DEX-09) |
| Solana | `settle(a, b, …, fill_a, fill_b, …)` | như trên |
| Soroban | `settle(maker, taker, maker_fill)` | không có `minNonce` |
| Cosmos | `Settle { maker, taker }` | chỉ FOK |
| TON | `receive(Match)` | chỉ FOK, escrow |
| NEAR / Algorand (nhánh `near-algorand`) | `settle(order_a, op_a, auth_a, order_b, op_b, auth_b)` | một cặp; nhiều cặp = nhiều receipt / nhiều group |

Node có thể giả lập 1 × N bằng nhiều cặp trong một giao dịch (khi family cho phép batch). Nhưng mỗi cặp phải tự đứng
được: taker IOC chỉ khớp một maker, FOK không gom được nhiều maker.

## 3. Chế độ 2 — Nguồn ngoài: AMM, RFQ, solver

**Đã làm (EVM contract, P2c).**
- Cùng `TradeOrder`, không cần ký thêm.
- (a) `Interaction[]` do submitter sắp thứ tự: nhiều hop, split nhiều pool, cycle X→X (`receiveToken == sellToken`).
  Target bất kỳ (pool, router, aggregator, RFQ, `mtxWrap`) hoặc chỉ target đã list.
- (b) Executor: DEX chuyển phần bán cho executor, executor phải trả lại ít nhất Σ floor mỗi token nhận. Dùng cho
  callback pool, flash swap, solver / market maker có inventory riêng.
- Test: `test/v2/DexExchange.t.sol` (mock router, pair v2, executor, cycle, Path B, outside leg, surplus, target thù
  địch), `UADex.t.sol` / `UADexInvariant.t.sol` (leg UA).

**Chưa làm.**
1. **Node TradeEngine** (NODE-DEX-17, NODE-DEX-18) mới SPECIFIED. Node mới có ABI và guard cho `mtxExchange` /
   `mtxExchangeVia` (`scaas-node/src/abi.rs`, `guard.rs`). Chưa có: quoter, tìm route (`max_hops` 3, split), intake lệnh
   exchange-only, tính floor (`quote × (1 − buffer)`), simulate, job, `GET /v1/dex/exchanges/{ref}`, indexer
   `ExchangeLegSettled`.
2. **Executor thật**: chỉ có mock. Uniswap v3 callback, v4 `unlock` / PoolManager, flash swap đều cần một executor
   được list, có review riêng.
3. **Fork test bytecode Uniswap thật** trên anvil: spec yêu cầu, chưa build.
4. **Pool coin native**: interaction không mang `value` (DEX không giữ coin native); pool ETH đi qua WETH. Ghi vào docs
   node, không đổi contract.
5. **Router dùng Permit2** (Universal Router) bị chặn có chủ ý trên đường (a). Muốn dùng phải qua executor (b), hoặc
   router v2 / v3 với `approve` thường.
6. **Một plan mỗi giao dịch**: không có `ExchangePlan[]`, không có cô lập lỗi kiểu `MatchFailed`.
7. **Non-EVM**: không family nào có (dex.md §7 "EVM only").

## 4. Chế độ 3 — Hybrid: maker trước, phần dư ra nguồn ngoài

**Hiện trạng.** Không có entry riêng. NODE-DEX-17 mô tả mỗi tick: (1) khớp book bằng `mtxSettle`, (3) lệnh book còn dư
thì fill qua AMM. Tức là **hai giao dịch riêng**. Cách này hỏng ở ba chỗ:
- **IOC** đóng ngay ở lần pull đầu (`pulled = amount`, CTR-DEX-04). Sau `mtxSettle`, phần dư của taker IOC không thể
  đi AMM nữa.
- **FOK** (`minFill = amount`) không chia được cho hai giao dịch.
- **Minimum fill 50 %** (luật hiện tại, sẽ bỏ, mục 6.3): phần dư sau maker phải ≥ 50 % hoặc đúng là phần đóng lệnh.
  Thêm vào đó là hai lần gas, và giá AMM có thể chạy giữa hai giao dịch.

**Ghép trong một plan `mtxExchange`, không đổi ABI.** Ví dụ taker bán 100 A, maker M1 bán 30 B lấy 28 A, M2 bán 20 B
lấy 19 A:

```text
legs:          taker  sell A 100  floor B  = 30 + 20 + quote_AMM(53 A) · (1 − buffer)
               M1     sell B 30   floor A  = 28   (đúng giá M1)
               M2     sell B 20   floor A  = 19   (đúng giá M2)
interactions:  approve(router, 53 A); router.swap(53 A → B, recipient = DEX)   // một hoặc nhiều path
kết quả:       DEX nhận 100 A + 50 B; trả M1 28 A, M2 19 A; 53 A → AMM → B; taker nhận 50 B + đầu ra AMM
               excess_B (AMM ra nhiều hơn quote) → taker; excess_A = 0 khi route dùng đúng 53 A
```

Chạy được vì `_exchangeIn` nhận các leg có `from` khác nhau, chiều bất kỳ, miễn token "known". Floor cộng theo token
nhận, conservation tính từng token. Interactions chạy sau khi đã pull mọi leg.

**Khác với `mtxSettle` khi đưa maker vào plan exchange:**
- Giá maker không còn do contract tính. Floor do node đặt, contract chỉ kiểm tra floor ≥ giới hạn.
- Maker nhận thêm phần `excess` của token nó nhận, chia theo tỷ lệ floor. Với hybrid một taker, `excess_A` = 0 nếu
  route dùng đúng phần dư; nếu khác 0 thì phần thừa có lợi cho maker.
- Market không cần listed. Node vẫn chỉ lấy maker từ market listed.
- Một maker bị cancel hoặc hết số dư giữa chừng làm hỏng **cả** plan.
- Event của maker là `ExchangeLegSettled`. Venue và indexer phải ghi fill maker từ cả hai loại event.
- Phí maker vẫn là `fee` đã ký, trên floor. Node áp `maker_fee_ppm` cho maker như trong book.

## 5. Chế độ 4 — CoW / ring: các lệnh tự bù cho nhau

### 5.1 Định nghĩa và hiện trạng

Nhiều lệnh, có thể khác cặp, thanh toán **cho nhau** trong một plan: hai lệnh ngược chiều cùng cặp (A→B và B→A), hoặc
một vòng A→B, B→C, C→A. Không lệnh nào là maker đứng chờ trong book; thường là các lệnh exchange-only hoặc IOC đến
cùng một tick. Lợi ích: không trả phí pool, không có price impact, không MEV trên phần bù trừ.

- Contract: một plan `mtxExchange` với 0 interaction đã chạy được.
  `test_exchange_coincidenceOfWants_noInteractions_refundNotDistributed` thanh toán hai lệnh ngược chiều, Path B, phần
  vượt floor về người ký. Ring 3 token chưa có test, nhưng không cần gì mới: floor cộng theo token nhận, conservation
  từng token.
- Node: NODE-DEX-17 có nhắc "coincidences of wants among exchange-only orders", chưa có thuật toán, chưa build.

### 5.2 Khớp chính xác một cặp rất khó — giải quyết thế nào

Hai lệnh ngẫu nhiên gần như không bao giờ bù nhau **chính xác**: khối lượng khác nhau, giới hạn giá khác nhau, và phép
chia nguyên luôn để lại phần lẻ. Một planner đợi khớp chính xác thì hầu như không bao giờ chạy được chế độ 4. Lời giải
là **không đòi khớp chính xác**, theo bốn lớp:

1. **Bù trừ ròng, phần lệch đi nguồn ngoài, trong cùng một plan.** Planner cộng luồng theo từng token. Phần trùng
   nhau thanh toán nội bộ; chỉ **phần lệch ròng** đi qua interactions (AMM) hoặc executor. Ví dụ: X bán 100 A lấy B, Y
   bán 60 B lấy A, giá tham chiếu 1 A = 1 B. Bù nội bộ 60 A ↔ 60 B: Y nhận 60 A từ X, X nhận 60 B từ Y. 40 A còn lại
   của X swap qua AMM sang B. Mỗi lệnh vẫn
   chỉ là **một** leg với một `sellFill`. Contract không phân biệt đơn vị nhận đến từ đối tác nội bộ hay từ AMM, nên
   cả hai lệnh đều được fill đủ dù chỉ bù được một phần. Đây là cách CoW Protocol làm, và chế độ 4 lúc này hòa với chế
   độ 3: một plan = bù trừ nội bộ + maker trong book + phần lệch ra ngoài.
2. **Floor, không phải số tuyệt đối.** Contract không đòi khoản nhận bằng một con số chính xác. Nó đòi số dư cuối của
   mỗi token nhận ≥ Σ floor, rồi chia phần thừa (`excess_T`) cho người nhận, leg cuối nhận phần dư làm tròn
   (CTR-DEX-21). Phần lẻ do làm tròn ở token nhận vì vậy **không làm plan revert**, nó về người ký. Planner đặt floor
   theo giá tham chiếu (ví dụ giá biên AMM hoặc điểm giữa hai giới hạn), hơi thấp hơn một chút (buffer); phần thừa
   quay về người ký.
3. **Chỉ token trung gian mới phải chính xác.** Conservation đòi token chỉ-bán hoặc trung gian (không leg nào nhận)
   về đúng snapshot (`ConservationBroken`). Planner tránh lỗi này bằng swap **exact-input** dọc route (hop sau dùng
   đúng đầu ra hop trước), hoặc đặt bước cuối là executor để nó gánh phần lẻ. Một token mà có leg nhận thì không bao
   giờ cần chính xác (lớp 2).
4. **Tăng xác suất trùng nhau.** Gom lệnh theo cửa sổ (`trade_engine.tick`, vài block) thay vì xử lý từng lệnh ngay;
   tìm cả vòng (ring) qua nhiều cặp, không chỉ cặp ngược chiều; cho phép bù một phần (≥ `minFill` người ký đặt, sau
   khi bỏ sàn 50 %, mục 6.3). Phần nào không bù được và không có nguồn ngoài thì nằm lại book (GTC) hoặc bị hủy (IOC),
   như chế độ 1.

Không có nguồn ngoài cho cặp đó (không có pool) thì chỉ còn lớp 2 và 4. Chế độ 4 khi đó là "bù một phần, phần còn lại
nằm book". Với sàn 50 % hiện tại, một lệnh không thể chỉ bù 20 %; bỏ sàn (mục 6.3) gỡ giới hạn này, chỉ còn `minFill`
của người ký.

### 5.3 Giá và surplus trong CoW

Phần chênh giữa hai giới hạn giá là surplus của CoW. Contract chia phần vượt floor theo tỷ lệ floor **trong từng token
nhận**. Cách hai bên chia surplus vì vậy do planner quyết qua floor (mục 1). Đề xuất cho planner: một giá thanh toán
chung cho mọi leg cùng cặp trong plan (uniform clearing price), đặt ở giá biên AMM khi có pool, ở điểm giữa hai giới hạn
khi không có. Như vậy không ai nhận kém hơn đi thẳng AMM, và hai bên chia đều phần chênh.

## 6. Planner: thứ tự mỗi tick

Mỗi tick, với các lệnh đang chờ của một chain:

1. **Chế độ 4**: tìm bù trừ (cặp ngược chiều, ring) giữa các lệnh exchange-only / IOC trong cửa sổ.
2. **Chế độ 1**: lệnh crossed book và book khớp hết → `mtxSettle` (rẻ nhất, maker đúng giá do contract tính).
3. **Chế độ 3**: book còn dư và có route ngoài → một plan `mtxExchange`: maker legs + phần dư ra ngoài. Phần bù trừ của
   bước 1 dính đến cùng token thì gộp vào cùng plan này.
4. **Chế độ 2**: lệnh exchange-only còn lại → route ngoài.

Mỗi plan là **một giao dịch nguyên tử**. Không bao giờ chạy `mtxSettle` rồi AMM ở giao dịch sau cho cùng một lệnh.
Quy tắc owner nêu (maker trước, AMM phần còn lại) là mặc định của bước 3. Ghi chú: khi giá AMM tốt hơn maker sâu nhất,
gộp đường cong AMM vào book sẽ cho taker giá tốt hơn. Đây là việc của planner, contract không đổi.

### 6.1 Ba hướng cũ trong thiết kế mới

Với người ký không có gì đổi: vẫn một `TradeOrder`, không ký thêm, không đổi ABI. Cái mới là planner chọn chế độ và
gói mỗi lệnh vào **một giao dịch nguyên tử**.

| Tình huống của lệnh | Chế độ | Hàm |
|---|---|---|
| Market listed, book nuốt hết (theo luật minimum fill, mục 6.2) | 1 | `mtxSettle` |
| Market listed, book thiếu, có route ngoài | 3 | `mtxExchange` / `Via`, một plan |
| Market listed, book thiếu, không có route | 1, phần dư nằm book (GTC) / hủy (IOC) / không khớp (FOK) | `mtxSettle` |
| Exchange-only (không có market, cycle X→X), có lệnh đối ứng trong cửa sổ | 4, phần lệch ra ngoài | `mtxExchange`, có hoặc không interaction |
| Exchange-only, không có đối ứng | 2 | `mtxExchange` / `Via` |

**(1) 1 taker × N maker → giữ `mtxSettle`, khi book nuốt hết.** Taker bán 100 A lấy ≥ 95 B; book có M1 bán 60 B lấy
58 A, M2 bán 45 B lấy 42 A. 58 + 42 = 100 A ⇒ `mtxSettle(taker, [M1, M2])` như hiện nay. Contract tính giá maker,
taker nhận 105 B (toàn bộ phần tốt hơn giới hạn 95). Rẻ nhất: không snapshot, không interaction. Hai lệnh ngược chiều
cùng một market listed vẫn là chế độ 1, không phải 4. Non-EVM vẫn 1 × 1 cho đến mục 7.8.

**(2) AMM nhiều path → `mtxExchange` / `Via`, thêm bước bù trừ trước.** X bán 100 A lấy ≥ 95 C, không có market A/C:
route A→B→C qua hai pool, floor = quote × (1 − buffer), không dưới 95, interactions do planner sắp (có thể split; pool
có callback / v4 thì qua executor). Mới: nếu trong cửa sổ có Y (exchange-only) bán 40 C lấy A, planner bù nội bộ trước
(Y nhận A từ X, X nhận 40 C từ Y), chỉ phần lệch ròng đi AMM. Vẫn một plan, cả hai fill đủ.

**(3) Hybrid → một plan `mtxExchange`, không còn hai giao dịch.** Như (1) nhưng book chỉ có M1:

```text
legs:          taker  bán 100 A, floor B = 60 + quote_AMM(42 A) · (1 − buffer)
               M1     bán 60 B,  floor A = 58          (đúng giá M1, node đặt)
interactions:  swap 42 A → B qua AMM, người nhận = DEX
```

IOC và FOK của taker chạy được vì chỉ có một giao dịch. Đánh đổi so với (1) như mục 4.

### 6.2 Maker cuối chỉ khớp một phần

Bình thường, và có luật chung cho contract (CTR-DEX-14) và matcher của node (`scaas-node/src/dex.rs`, vòng chọn
maker). Book không ở on-chain: nó nằm trong store của node (NODE-DEX-14, `dex_order`). On-chain chỉ có
`pulled[orderHash]` và `minNonce[from][batch]`, mỗi lần khớp contract kiểm tra lại mọi giới hạn đã ký.

Ngưỡng mỗi lần khớp `m`:
- **Hiện tại:** `m = max(minFill, ⌈amount / 2⌉)`, tính trên `amount` của lệnh, không phải trên phần còn lại.
- **Sau khi bỏ sàn 50 % (owner 2026-10-29, mục 6.3):** `m = minFill` do người ký đặt.

| Trường hợp maker cuối | Kết quả |
|---|---|
| Phần taker cần `x ≥ m` | khớp một phần; phần còn lại **nằm nguyên chỗ cũ** trong book off-chain của node (NODE-DEX-14: chỉ giảm `remaining`, không xếp lại, giữ thứ tự price-time); on-chain chỉ ghi `pulled[h]`; lần khớp sau không verify chữ ký lại (`pulled[h] ≠ 0`, CTR-DEX-15 bước 4) |
| `x < m` | **bỏ qua maker này**, thử maker sâu hơn (giá kém hơn) xem có vừa không. Contract sẽ từ chối (`BelowMinFill`) nên node không bao giờ gửi. Sau khi bỏ sàn, chỉ xảy ra khi chính maker ký `minFill` lớn |
| Phần còn lại < `m` | chỉ khớp được **toàn bộ phần còn lại** (vế "đóng lệnh"), và chỉ khi các fill trước đã mined. Vế này giữ nguyên sau khi bỏ sàn: không có nó, phần dư nhỏ hơn `minFill` không bao giờ đóng được |
| Phần còn lại không mua nổi 1 đơn vị ở giá của nó | dust: bị gỡ khỏi book (NODE-DEX-05) |

Hệ quả:
- **Hiện tại:** lệnh Path A khớp tối đa ở hai settlement; maker chỉ khớp với taker lấy ít nhất một nửa lệnh của nó.
  **Sau khi bỏ sàn:** khớp bao nhiêu lần cũng được, mỗi lần ≥ `minFill`.
- Maker bị bỏ qua vì `x < m` vẫn giữ chỗ, nhưng taker có thể đi sâu hơn. Đây là ngoại lệ có chủ ý của price-time,
  ghi trong matcher; sau khi bỏ sàn chỉ áp cho maker tự chọn `minFill` lớn.
- "Book nuốt hết" ở mục 6.1 nghĩa là nuốt hết **trong luật này**. Phần taker không đặt được vào maker nào (vì `x < m`)
  là phần dư. Trong thiết kế mới, phần dư đó đi AMM trong cùng plan (chế độ 3), thay vì nằm book hoặc bị hủy.

### 6.3 Bỏ sàn minimum fill 50 % (owner 2026-10-29)

**Quyết định.** Owner 2026-10-29 bỏ sàn giao thức `MIN_FILL_PPM` (50 %) của CTR-DEX-14, luật owner đặt ngày
2026-10-08. Ngưỡng mỗi lần khớp chỉ còn `minFill` người ký đặt trong lệnh. Trạng thái: **spec xong 2026-10-29, chưa
code.** CTR-DEX-14 viết lại trong `contracts/dex.md` (SPECIFIED, code hiện tại ghi Transitional), entry trong
`decisions.md`, NODE-DEX-15 (`node/dex-venue.md`: minimum fill + khớp rác là chính sách venue), CLI-SGN-35, `settlement.md`.

**Vì sao bỏ.**
- Lý do gốc ("no order is matched as junk"; khớp lặt vặt bắt maker tạo lại lệnh, tăng việc on-chain) yếu:
  - khớp một phần không bắt maker tạo lại lệnh, phần còn lại vẫn nằm trong book;
  - lách phí bằng cách chia nhỏ đã bị chặn riêng (phí làm tròn lên, CTR-DEX-11);
  - gas do relayer trả, relayer là node venue (relayer-bound), node tự bỏ khớp không đáng gas;
  - chữ ký chỉ verify một lần mỗi lệnh (`pulled ≠ 0` thì bỏ qua), không phụ thuộc sàn.
- 50 % là con số tùy ý. 0x, 1inch limit order, CoW (`partiallyFillable`) để người ký tự chọn. Các family non-EVM của
  SCaaS không có sàn này (dex.md §11).
- Bị lợi dụng và gây hại:
  1. **Bức tường giả ở giá tốt nhất.** Lệnh rất lớn ở best bid / ask hiện trong `depth` / `ticker` nhưng chỉ taker lấy
     ≥ 50 % mới khớp được. Người đặt gần như không chịu rủi ro mà vẫn kéo được spread và giá hiển thị (spoofing rẻ).
  2. **Taker nhỏ bị đẩy sang giá kém hơn.** Matcher bỏ qua maker lớn, đi xuống maker sâu hơn. Price-time vô hiệu với
     lệnh lớn.
  3. **Làm ngược mục đích.** Muốn khớp nhỏ, người dùng chia lệnh to thành nhiều lệnh nhỏ: nhiều chữ ký, nhiều lần verify
     (PQ tới 5.95 M gas mỗi lần), tức càng nhiều việc on-chain.
  4. **Phần còn lại bị khóa cứng.** Sau một lần ≥ 50 %, phần còn lại chỉ khớp nguyên cục và sau khi lần trước mined;
     Path A khớp tối đa hai lần, phần dư hay thành mồ côi.
  5. **Chặn CoW một phần và hybrid** (mục 5.2): một lệnh không thể chỉ bù 20 %.

**Luật mới (đề xuất cho spec).**
- Sold side: `sellFill ≥ minFill` **hoặc** `sellFill == amount − pulled[h]` (đóng phần còn lại). `minFill ≤ amount`
  (`BadMinFill`) giữ nguyên; `minFill = 0` hợp lệ (khớp bất kỳ, > 0).
- Received side: bỏ dòng `receiveFill · 10⁶ ≥ receiveAmount · MIN_FILL_PPM`. Nó vốn suy ra từ sold side + giới hạn giá;
  giới hạn giá và `receiveFill > 0` vẫn kiểm tra như cũ.
- FOK giữ nguyên: `minFill = amount` với `pulled == 0`.
- Path B (`ESCROW`): DEX kiểm tra `sold ≥ minFill` hoặc `sold == amount`, bỏ vế nửa `receiveAmount`.
- Giữ: overfill, giới hạn giá, phí làm tròn lên, dust (NODE-DEX-05), vế "đóng lệnh chỉ khi các fill trước đã mined"
  ở matcher.

**Chống khớp rác bằng chính sách node, không phải luật contract.**
- Sàn tuyệt đối theo market (`min_base_amount` lúc intake, đã có) và một ngưỡng mỗi lần khớp: giá trị fill phải đáng
  tiền gas của relayer.
- Client đặt `minFill` mặc định theo kích thước tối thiểu của market. Người ký vẫn chọn được 50 % hay 100 % nếu muốn.
- Khớp lặt vặt on-chain bởi submitter khác (lệnh `relayer = 0`) không có lợi: submitter trả gas, maker vẫn nhận đúng
  giá, phí ≥ 1 đơn vị mỗi lần (CTR-DEX-11). Maker không muốn thì tự đặt `minFill`.
- Bức tường giả chỉ còn khi người ký **tự ký** `minFill` lớn. Lúc đó node thấy rõ: `depth` / `ticker` tách riêng
  thanh khoản có `minFill` > `min_base_amount` của market, không tính nó vào best bid / ask.

**Chỗ phải sửa khi làm.**
- Contract EVM: `TradeLib` (hằng số và check sold / received side), `SCaaSDex._calc` Path B (`SCaaSDex.sol:392-393`),
  NatSpec, test `Trade.t.sol` / `Dex.t.sol` / `UATrade.t.sol` (các case `BelowMinFill`), KAT nếu có vector phụ thuộc.
- Node: `min_fill` (`scaas-node/src/dex.rs:295`) và các test của nó; `depth` / `ticker` tách thanh khoản `minFill` lớn.
- `clientkeys`: hiển thị "effective minimum fill" (giờ = `minFill`), `minFill` mặc định theo market.
- Docs: CTR-DEX-14, CTR-DEX-05, các dòng "50 %" trong `dex.md` (§1, §3, §4), `dex-venue.md` (§2), decision mới thay
  CTR-DEX-14 trong `decisions.md`.
- Mọi chain hiện chỉ để test: không migration. Non-EVM không phải sửa (vốn không có sàn): đồng bộ với EVM.

### 6.4 Tính atomic

Atomic ở **mức từng lần khớp** (một settlement hoặc một plan), không phải cả vòng đời của một lệnh.

**Mỗi lần khớp (EVM): atomic.** Trong một settlement: pull mọi leg vào DEX, trả mọi bên, chia phí, hoàn Path B,
kiểm tra conservation (số dư DEX không đổi). Tất cả xảy ra hoặc không gì xảy ra; hỏng một bước thì cả settlement
revert, không ai mất tiền. `mtxSettle` chạy mỗi settlement trong một self-call: cái hỏng chỉ ra `MatchFailed`, các
cái khác vẫn chạy. Một plan `mtxExchange` atomic nguyên plan: mọi leg, mọi interaction, gồm cả hybrid và CoW (chế độ
3, 4), trong một giao dịch.

**Cả lệnh: tùy loại.**

| Loại lệnh | Atomic cả lệnh? |
|---|---|
| FOK (`minFill = amount`) | có: khớp đủ trong một settlement, hoặc không khớp gì |
| IOC | có: một settlement, phần không khớp bị đóng ngay ở lần pull (CTR-DEX-04) |
| Path B (`ESCROW`, ngầm định IOC) | có: pull cả `amount`, phần dư hoàn trong cùng giao dịch |
| GTC Path A | **không**: khớp dần qua nhiều settlement / giao dịch, mỗi lần atomic riêng |

Với GTC, giữa các lần khớp phần chưa khớp **vẫn nằm trong ví người ký**, không bị khóa hay escrow. On-chain chỉ ghi
`pulled[h]`. Người ký tiêu số dư đó thì lần khớp sau fail riêng (`MatchFailed`); node gỡ maker và khớp lại.

**Giữa book off-chain và chain.** Node khớp off-chain rồi mới gửi. Trong khoảng đó maker có thể hủy, hết số dư, hết
hạn: settlement fail riêng, không mất tiền, node quy lỗi theo bằng chứng (NODE-DEX-02) và khớp lại. Một lệnh có thể
"đã khớp trong book" mà chưa thanh toán, cho đến khi event cuối được xác nhận. Đây cũng là lý do chế độ 3 phải là một
plan, không phải `mtxSettle` rồi AMM ở giao dịch sau (mục 4).

**Non-EVM.**
- Sui, Aptos, Solana, Soroban, Cosmos, Algorand: mỗi lần settle một cặp là một giao dịch atomic (PTB / tx / atomic
  group).
- TON, NEAR: message / receipt bất đồng bộ, không atomic trong một giao dịch. Bảo đảm bằng escrow + hoàn tiền: TON
  escrow giữ tiền ngắn hạn (dex.md §11); NEAR DEX ghi mục `pending` theo `settle_id`, mỗi leg một receipt, leg hỏng
  thì refund. Kết quả cuối vẫn là "khớp đủ hoặc hoàn lại", nhưng có trạng thái trung gian nhìn thấy được. Đường
  exchange non-EVM (mục 7.9) trên hai family này phải tính đến điều đó.

## 7. Cần cải tiến (đề xuất, chưa code), theo thứ tự

**Contract (EVM).**
0. **Bỏ sàn minimum fill 50 %** (owner 2026-10-29, mục 6.3): spec trước, rồi contract + node + clientkeys. Làm trước
   các mục dưới, vì CoW một phần và hybrid dựa vào nó.
1. **Test cho chế độ 3 và 4**:
   - hybrid: taker + ≥ 2 maker ngược chiều + interactions mock v2 / v3; maker đúng giá; taker IOC và FOK; maker là lệnh
     UA và lệnh token ngoài; maker stale làm revert cả plan; `excess_A ≠ 0` chia cho maker;
   - CoW một phần: hai lệnh lệch khối lượng, phần lệch qua AMM, cả hai fill đủ;
   - ring 3 token không interaction; phần lẻ làm tròn về leg cuối; token trung gian dư → `ConservationBroken`.
   Đây là bằng chứng chế độ 3 và 4 đã có trên chain mà không đổi ABI.
2. **Batch plan có cô lập lỗi** (owner 2026-10-29: thêm ngay): `mtxExchangeBatch(ExchangePlan[] + interactions[])`,
   mỗi plan một self-call, lỗi thì `ExchangeFailed(ref, reason)`, re-raise lỗi thiếu gas như `mtxSettle`. Thêm entry,
   không sửa entry cũ.
2b. **Entry `mtxHybrid` / `mtxHybridVia`** (owner 2026-10-29: làm cả hai đường, plan `mtxExchange` **và** entry riêng).
   Phác thảo, chốt khi viết spec:
   ```solidity
   struct HybridPlan { bytes32 ref; Leg taker; Leg[] makers; uint256 outsideSell; uint256 outsideFloor; }
   function mtxHybrid(HybridPlan calldata p, Interaction[] calldata xs) external;          // (a) interactions
   function mtxHybridVia(HybridPlan calldata p, address executor, bytes calldata data) external; // (b) executor
   ```
   Khác plan `mtxExchange` ở chỗ contract tự giữ luật book: market phải listed; mỗi maker nhận đúng
   `⌈fill · receiveAmount / amount⌉` như `mtxSettle`, không nhận surplus; taker bán `Σ maker nhận + outsideSell`;
   phần `outsideSell` đi interactions / executor, phải về ít nhất `outsideFloor`; giới hạn giá của taker kiểm trên tổng
   `Σ maker bán + outsideFloor`; toàn bộ phần vượt `outsideFloor` về taker; conservation như cũ; event maker là
   `LegSettled`. Plan `mtxExchange` vẫn là đường cho CoW / ring và mọi hình dạng khác.
3. **Executor tham chiếu** (Uniswap v3 callback, v4 unlock, flash swap; gánh phần lẻ của token trung gian) và fork test
   bytecode Uniswap thật.
4. Giữ nguyên: không có `value` (dùng WETH), chặn Permit2 trên đường (a), không thêm entry `mtxCow` (CoW / ring đi plan
   `mtxExchange`).

**Node.**
5. **Sửa NODE-DEX-17** theo mục 6: bốn chế độ, mỗi plan một giao dịch nguyên tử.
6. **Build TradeEngine** theo thứ tự: quoter + route 1 hop → multi-hop / split (`max_hops` 3) → planner hybrid (chế độ
   3) → bù trừ ròng cặp ngược chiều (chế độ 4, lớp 1–3 của mục 5.2) → ring + cửa sổ gom lệnh (lớp 4) → simulate → job
   → indexer `ExchangeLegSettled` → `GET /v1/dex/exchanges/{ref}`.
7. **MEV**: trên chain public gửi qua private relay. Floor chặn mọi thiệt hại dưới giới hạn đã ký; sandwich chỉ lấy
   được surplus. Phần bù trừ nội bộ của chế độ 4 không lộ ra pool.

**Non-EVM.**
8. **1 × N** ở từng family: settle một taker với nhiều maker trong một lần gọi, phí taker một lần trên tổng nhận, như
   CTR-DEX-16. Mỗi family một program version.
9. **Đường exchange non-EVM** (chế độ 2–4: DeepBook / Cetus, Jupiter CPI, Ref, Tinyman, Osmosis, STON.fi / DeDust…):
   chưa có spec. Mỗi family khác hẳn nhau (CPI, PTB, inner group, async receipt), cần spec riêng trước khi làm.

## 8. Owner trả lời (2026-10-29)

1. **Hybrid / CoW: cả hai đường.** Plan `mtxExchange` hiện có (test hybrid, CoW một phần, ring; NODE-DEX-17 thành một
   plan nguyên tử) **và** entry riêng `mtxHybrid` / `mtxHybridVia` trong đó contract tự tính giá maker như `mtxSettle`
   và surplus chỉ về taker (mục 7.2b). Planner dùng `mtxHybrid` cho chế độ 3 trên market listed; plan `mtxExchange` cho
   chế độ 4 và các hình dạng khác.
2. **Giá CoW:** giá biên AMM khi có pool, điểm giữa hai giới hạn khi không có (mục 5.3).
3. **`mtxExchangeBatch`: thêm ngay**, cùng đợt contract với `mtxHybrid` và các test chế độ 3 / 4 (mục 7.2).
4. **Ưu tiên: song song** TradeEngine node EVM (mục 7.5–7.6) và 1 × N non-EVM (mục 7.8), trong giới hạn 3 agent /
   2 slot `capped`.

Thứ tự làm: sau khi merge near-algorand → code bỏ sàn minFill 50 % (mục 6.3) → spec rồi code contract EVM
(`mtxHybrid` / `Via`, `mtxExchangeBatch`, test chế độ 3 / 4, executor tham chiếu, fork test Uniswap) → song song:
TradeEngine node EVM và 1 × N non-EVM (mỗi phần spec trước). Đường exchange non-EVM (mục 7.9) chưa xếp lịch.
