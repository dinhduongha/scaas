> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 01. Token Factory, vòng đời Token và cơ chế Peg/Wrap

### 1.0. Kết luận trước, lý luận sau

Mười ba quyết định của section này, để một người đọc plan không phải đọc hết:

| # | Quyết định | Mục |
|---|---|---|
| 1 | Proxy pattern = **EIP-1167 clone, BẤT BIẾN**. Không Beacon, không UUPS, không Diamond. Token đã deploy thì không ai nâng cấp được, kể cả người tạo | 1.3 |
| 2 | Chuỗi xác định địa chỉ có **hai tầng**: deployer xác định → factory xác định → clone. Tầng beacon biến mất cùng với upgrade | 1.4 |
| 3 | `salt` cam kết cả `initData` bằng hash, còn `init_code` thì không. Nhờ vậy đổi tên token không đổi địa chỉ mà vẫn chống front-run `initialize()` | 1.4 |
| 4 | Thêm archetype hoặc version mới = 1 tx `registerImplementation`, **không** upgrade factory. Catalogue **append-only**: `(kind, version)` đã đăng ký không bao giờ trỏ lại chỗ khác | 1.5 |
| 5 | Invariant `WRAP_1_1` là **`<=`**, không phải `==`. Ai cũng có thể tặng thêm (donate) underlying vào vault | 1.6 |
| 6 | `PEG_RATIO` cho Z-VND: reserve **bằng VND**, không phải USDT. `FIXED_RATE` + spread hai chiều + hàng đợi redemption T+1 | 1.7 |
| 7 | Ràng buộc thật lên decimals không phải là decimals, mà là **`totalSupply` tính theo raw unit phải `<= 2^44`** — đó là trần chi phí giải mã Zether | 1.8 |
| 8 | Range proof width = **64 bit** (luỹ thừa của 2), tách hoàn toàn khỏi trần giải mã. `2^48` trong bản nháp trước là sai vì Bulletproofs cần `n*m` là luỹ thừa của 2 | 1.8 |
| 9 | Bất biến chống in tiền là **`confidentialLocked == balanceOf(address(this))`**, không phải một công thức trên "tổng số dư công khai" (không thể liệt kê on-chain) | 1.9 |
| 10 | `blacklist` mở: **từ chối trên public profile**. `pause` có trần 7 ngày, và lối thoát duy nhất khỏi trần đó là `WIND_DOWN` một chiều | 1.10 |
| 11 | Không còn quyền upgrade để mà quản trị. Quyền còn lại của người vận hành factory: xuất bản một version mới (không ai buộc phải chọn) và emit event deprecate (không chặn gì). Role bên trong token thuộc về **người tạo token** | 1.11 |
| 12 | `MigrationSink` là **đường duy nhất** để sửa bất cứ thứ gì, kể cả một lỗi logic tầm thường. Với token Zether đó là một chiến dịch 180 ngày, không phải một hàm | 1.17.2 |
| 13 | Con số quyết định kiến trúc: một Zether transfer 64-bit tốn **~1,9M gas**. Trên Gnosis (block limit ~17M, 5s) đây là ~0,4 tx/s bền vững. Trên Besu QBFT zero-gas, trần thật là CPU validator, ~20–45 tx/s | 1.12, 1.16 |

---

### 1.1. Phạm vi, giả định ẩn, và những chỗ `blockchain.md` còn bỏ ngỏ

Note gốc (dòng 3–11) nêu 6 yêu cầu, tất cả đều đúng ý định nhưng không đủ để code:

| Yêu cầu trong note | Trạng thái | Xử lý ở mục 1.2–1.11 |
|---|---|---|
| Tự mint (issuer token) | Rõ | archetype `ISSUER_NATIVE` |
| Wrap ERC-20 sẵn có (USDT → Z-USDT) | Thiếu xử lý fee-on-transfer, blacklist của underlying, decimals, donate, rebase | archetype `WRAP_1_1`, mục 1.6 |
| Mint/burn theo tỷ lệ (1 USDT → 25000 Z-VND) | **Thiếu hoàn toàn**: ai chịu FX risk, rate từ đâu, de-peg, redemption, spread, hàng đợi | archetype `PEG_RATIO`, mục 1.7 |
| "Mint/burn từ 1 hoặc 1 **group** ERC-20" | **Chưa ai thiết kế giỏ (basket)**: trọng số, rebalance, NAV, N oracle = N điểm gãy | mục 1.7.6 |
| "Dùng cơ chế delegate để chia sẻ code, khác data, support nhiều version" | Chưa chọn pattern; và note không hề nhắc đến kỷ luật storage layout — thứ duy nhất làm `delegatecall` nguy hiểm | mục 1.3. **Khuyến nghị đã lật: EIP-1167 clone bất biến**, xem 1.3.1 |
| "Factory Contract để tự do create2" | Chưa có công thức địa chỉ, chưa nói salt gồm gì, chưa nói ai deploy chính factory | mục 1.4 |
| "Có khả năng thêm nguyên mẫu Contract" | Chưa có registry | mục 1.5 |

Bốn thứ note **không** nhắc đến nhưng chặn mọi thiết kế: **decimals của VND**, **total-supply invariant khi một token vừa là ERC-20 công khai vừa giữ số dư Zether mã hoá**, **quyền upgrade thuộc về ai**, và **trần giải mã quyết định trần cung tiền**. Các mục 1.8, 1.9, 1.11.

Câu thứ ba trong bốn câu đó có một đáp án mà bản nháp không lường: **không ai cả, vì không có quyền upgrade.** Xem 1.11.

Trục **chain profile** (public/private, khoá quyết định #5) không phải là một trường config phụ: nó quyết định archetype nào được phép deploy, và trên private profile nó còn nối liền EIP-170 (xem 1.16). Model chính tắc là `blockchain.chain` với trường `chain_profile` (định nghĩa ở §08.1 và §10.4.2); section này không định nghĩa lại model đó.

#### 1.1.1. Mười ba giả định ẩn — nói ra để còn kiểm chứng được

Bản nháp đầu tiên im lặng về mười ba điều dưới đây. Mỗi dòng là một chỗ có thể làm hỏng hệ thống mà không ai thấy trước.

| # | Giả định ẩn | Nếu sai thì sao | Kiểm chứng ở đâu |
|---|---|---|---|
| A1 | ~~Có một khoá nào đó deploy được factory, và khoá đó không bao giờ mất~~ **ĐẢO CHIỀU.** Mất khoá registrar = catalogue đóng băng ở version cuối, **và mọi người vẫn deploy được qua `createUnregistered`** | Suy giảm, không chết. Hồ sơ rủi ro cũ xếp A1 ở mức thảm hoạ; mức đúng là vệ sinh vận hành | 1.5, 1.11 |
| A2 | `initialize()` không bị front-run giữa `CREATE2` và lần gọi đầu | Kẻ tấn công làm admin của token ta vừa deploy | 1.4 |
| A3 | `solc` build là deterministic | Cùng source, hai máy, hai `init_code`, hai địa chỉ. Mặc định solc **không** deterministic | 1.14 |
| A4 | Code chạm đất tại địa chỉ dự đoán chính là code ta muốn | Metamorphic contract / squatting | 1.2, 1.4 |
| A5 | Chain đã có Cancun (EIP-6780) | Implementation chưa `initialize` có thể bị chiếm và `SELFDESTRUCT` → brick mọi clone trỏ tới nó. **Giảm nhẹ chứ không mất khi bỏ upgrade**: không ai *thay* được implementation nữa, nhưng *phá* thì vẫn phá được | 1.3 |
| A6 | `underlying.balanceOf(vault)` chỉ đổi qua wrap/unwrap | Donate + rebase phá vỡ bất biến `==` | 1.6 |
| A7 | Reserve off-chain đối soát được tức thì | Mint on-chain nhanh hơn tiền về tài khoản. Cần `in_flight` buffer và mint cap | 1.7 |
| A8 | Một rate duy nhất dùng chung cho mint và redeem | Round-trip arbitrage quanh mỗi lần cập nhật oracle, miễn phí | 1.7.3 |
| A9 | `totalSupply` không liên quan gì đến khả năng giải mã số dư Zether | Sai. `totalSupply` raw chính là không gian tìm kiếm BSGS | 1.8 |
| A10 | Odoo là nguồn sự thật | Chain là nguồn sự thật; Odoo là bản chiếu. Hướng đối soát phải được phát biểu, không được suy diễn | 1.13 |
| A11 | Một token = một lần deploy | Cron chạy hai lần, hai broadcast, hai địa chỉ, một record | 1.13 |
| A13 | Một lỗi trong v1 có thể sửa được | **Sai, và đây là giả định đắt nhất.** Token bất biến: không có bản vá nào. Đường duy nhất là `MigrationSink`, và với số dư confidential đó là một chiến dịch 180 ngày | 1.17.2 |
| A12 | Block gas limit đủ cho một Zether tx | 128-bit range proof (~3,5M) chiếm 20% một block Gnosis. Trên một số L2 nó không vào nổi một block. Chain private 9000 có gasLimit 16,7M — **đã đo**, không phải 200M như bản nháp giả định | 1.12, 1.16 |

---

### 1.2. Nguyên tắc chủ đạo: "deploy không phải là đã có token"

Áp dụng nguyên tắc `dms_vietqr` ("quét QR không phải là đã thu tiền") vào vòng đời contract. Một `CREATE2` đã broadcast **không** là một token đang tồn tại. State machine của `blockchain.token`:

```
draft -> predicted -> broadcast -> pending_finality -> verified -> live
                          |              |               |          |
                          v              v               v          v
                       failed         failed          mismatch    paused -> wind_down -> retired
```

So với bản nháp, thêm một trạng thái: **`verified`**. Lý do là giả định A4. Giữa `pending_finality` và `live` phải có một bước **kiểm tra code thật sự nằm ở địa chỉ đó**, chứ không chỉ kiểm tra receipt `status == 1`:

```python
def _verify_deployed_code(self):
    """Chạy sau finality, trước khi set live. Ba phép kiểm, không phép nào bỏ được."""
    for tok in self:
        code_hash = tok._rpc_extcodehash(tok.contract_address)          # eth_getCode + keccak
        if code_hash != tok.prototype_id.expected_proxy_code_hash:
            tok.deploy_state = 'mismatch'; continue
        if tok._rpc_call('implementation()') != tok.prototype_id.implementation_address:
            tok.deploy_state = 'mismatch'; continue
        if tok._rpc_call('creator()') != tok.creator_address:
            tok.deploy_state = 'mismatch'; continue
        tok.deploy_state = 'live'
```

Phép kiểm thứ hai đổi so với bản trước: nó so `implementation()` chứ không so `beacon()`, vì không còn beacon. Phép kiểm thứ ba cũng đổi — bản cũ so `owner()` với `governance_safe` của chain, giả định mọi token đều thuộc về ta. Trên factory mở thì không: thứ phải khớp là **người tạo**, và với token bất biến thì `creator()` là một hằng số chứ không phải một vai trò có thể chuyển.

`live` chỉ được set bởi Finality Gate **cộng** ba phép kiểm trên. Ngưỡng finality đọc từ `blockchain.chain.finality_hard_blocks` / `finality_hard_seconds` (Gnosis: 2 epoch ~12,8 phút cho hard; 1 block ~5s cho soft — xem §08). Trước đó mọi RPC trả về địa chỉ đều phải kèm `deploy_state`, và client **không được phép** mint vào một token ở trạng thái `broadcast`.

Lý do không phải lý thuyết: reorg trên Gnosis trước finality checkpoint là có thật, và một `CREATE2` bị reorg để lại một địa chỉ đã được ghi vào Odoo nhưng không có code. Sau reorg, địa chỉ đó **vẫn dự đoán được bởi bất kỳ ai** — kẻ tấn công chỉ cần đọc `TokenDeployed` event đã bị reorg, tính lại salt, và deploy trước ta bằng chính Arachnid deployer.

Trên factory mở, cửa này **hẹp hơn bản cũ chứ không rộng hơn**: salt cam kết cả `keccak256(initData)` lẫn `address` người tạo (1.4.3), nên kẻ tấn công không tái tạo được salt của ta trừ khi họ dùng đúng địa chỉ của ta. Cái họ làm được là deploy một token khác ở một địa chỉ khác — tức là rác, không phải chiếm đoạt. Trạng thái `mismatch` vẫn là một incident, không phải một warning.

---

### 1.3. Proxy pattern: EIP-1167 vs UUPS vs Beacon vs Diamond

Yêu cầu của note là "chia sẻ code, khác data, support nhiều version". Bốn lựa chọn không tương đương nhau:

| Pattern | Deploy gas/token | Upgrade N token | Overhead call **lạnh** (lần đầu/tx) | Overhead call **ấm** | Địa chỉ dự đoán có ổn định qua các version? | Hiểm hoạ storage |
|---|---|---|---|---|---|---|
| EIP-1167 minimal proxy | ~45.000 | **Không thể** (impl hardcode trong 45 byte runtime) | ~2.700 | ~150 | **Không** — đổi impl là đổi `init_code` là đổi địa chỉ tương lai | Không có (không upgrade) |
| UUPS (ERC-1822) | ~200.000 – 240.000 | **N transaction** | ~4.800 (SLOAD lạnh 2.100 + DELEGATECALL lạnh 2.600) | ~200 | **Không** — cùng lý do | Impl quên kế thừa `UUPSUpgradeable` → brick vĩnh viễn |
| Beacon proxy | ~200.000 – 240.000 | **1 transaction cho cả N** | **~9.400** (SLOAD 2.100 + STATICCALL 2.600 + SLOAD trong beacon 2.100 + DELEGATECALL 2.600) | ~400 | **Có** — `init_code` chỉ chứa địa chỉ beacon | Blast radius = toàn bộ N token |
| Diamond (EIP-2535) | ~400.000+ | 1 `diamondCut`/proxy | ~4.900 (SLOAD selector map 2.100 + DELEGATECALL 2.600) | ~200 | Có (với `DiamondCutFacet` cố định) | Cao nhất: AppStorage/Diamond Storage phải kỷ luật tuyệt đối |

**Sửa số liệu so với bản nháp:** bản nháp ghi Beacon `~4.800` và Diamond `~4.800` — sai ở hai chỗ. Beacon có **một external call phụ** (STATICCALL sang beacon) mà Diamond không có, nên Beacon đắt hơn Diamond, không bằng nhau. Con số lạnh cho Beacon là **~9.400**, không phải 4.800. Con số này chỉ phát sinh **một lần cho mỗi transaction** (sau đó địa chỉ beacon và impl đã warm, cost về ~400). Với một `transfer` đơn lẻ đó là ~9.000 gas trên tổng ~46.000 — **20% overhead**, không phải 10%. Con số này là cơ sở cho quyết định ở 1.12.

**Khuyến nghị: EIP-1167 minimal proxy, BẤT BIẾN. Không Beacon, không UUPS, không Diamond.**

Bản nháp và bản thứ hai của mục này đều khuyến nghị **Beacon**, và cả hai đều dựa trên
một mệnh đề sai. Bảng trên giữ nguyên — số liệu vẫn đúng — nhưng kết luận lật.

#### 1.3.1. Mệnh đề sai đã đẩy cả section sang Beacon

Bản trước viết:

> *"EIP-1167 rẻ nhất và an toàn nhất nhưng mâu thuẫn trực tiếp với 'support nhiều
> version'."*

**Sai.** Nó giả định *"support nhiều version"* bắt buộc phải là **đi một token qua
nhiều version theo thời gian**. Có cách đọc thứ hai, và nó thoả đúng yêu cầu gốc:
**nhiều version cùng tồn tại trong một catalogue, người tạo chọn một lúc deploy, và nó
ghim vĩnh viễn.**

Yêu cầu gốc trong note là *"dùng cơ chế delegate để chia sẻ code, khác data, support
nhiều version"*. EIP-1167 thoả **cả ba**:

| Yêu cầu | Clone làm được không |
|---|---|
| chia sẻ code | có — mọi clone `delegatecall` tới cùng một implementation |
| khác data | có — mỗi clone có storage riêng |
| nhiều version | có — catalogue giữ v1, v2, v3 song song; token ghim một cái |

Giả định ẩn *"version = đường đi theo thời gian của một token"* chưa từng được viết ra
để kiểm, và chính nó là thứ đã loại EIP-1167 từ vòng đầu.

#### 1.3.2. Đọc lại bảng với tiền đề đúng

Với tiền đề mới, hai cột mà bảng xếp là **điểm trừ** của EIP-1167 trở thành **điểm
cộng**:

| Cột | Đọc cũ | Đọc đúng |
|---|---|---|
| "Upgrade N token" = *Không thể* | thiếu tính năng | **bất biến là tính năng chính** — không tồn tại nút bấm nào, của bất kỳ ai, đổi được contract đang giữ tiền của bạn |
| "Hiểm hoạ storage" = *Không có* | trung tính | **xoá hẳn một lớp rủi ro**: không ERC-7201, không `__gap`, không CI gate storage layout, không `validateUpgrade` |

Cộng với hai thứ bảng không đo được: deploy rẻ hơn **4–5 lần** (45.000 so với
200.000–240.000) và call rẻ hơn **3,5 lần lạnh** (2.700 so với 9.400 của Beacon).

Lý lẽ mạnh nhất của Beacon — *"40 token cần vá gấp, 1 tx thay vì 80 tx"* — chính là
thứ ta không được phép có trên factory mở. Xem 1.11.

#### 1.3.3. Cái giá, nói thẳng

Bỏ upgrade không miễn phí. Một lỗi trong v1 là **lỗi vĩnh viễn** của mọi token trên
v1 — không bản vá, không ngoại lệ khẩn cấp. Đường duy nhất là `MigrationSink`, và với
số dư confidential đó là một chiến dịch 180 ngày chứ không phải một hàm (1.17.2, giả
định A13).

Hệ quả ngân sách: **implementation Zether v1 phải được audit nặng hơn Meta Token v1**,
vì giá của một lỗi cao hơn hẳn.

#### 1.3.4. Diamond: vẫn không dùng, lý do không đổi

Không phải gas mà là audit surface và tooling. Blockscout của Gnosis và explorer của
Celo verify Diamond rất kém (mỗi facet phải verify riêng, giao diện "Read/Write
contract" không gộp lại), `diamondCut` mở rộng bề mặt tấn công bằng số facet, và
Diamond Storage sai một slot là mất tiền. Diamond chỉ giải quyết được **một** vấn đề
thật: giới hạn 24.576 byte (EIP-170).

**Về EIP-170, và tại sao nó không còn là lý do chọn Diamond:**

- Nếu `ZToken` + Zether + Bulletproofs verifier vượt 24KB trên **public profile**, giải
  pháp rẻ hơn là tách `BulletproofVerifier` thành một contract **stateless** gọi bằng
  `staticcall`, không phải facet: cùng chia sẻ code, không có Diamond Storage, và
  verifier có thể được audit độc lập và tái sử dụng cho mọi token.
  Đây cũng chính là hình dáng mà factory mở đòi hỏi: verifier là một địa chỉ **inject
  lúc `initialize()`**, nên một token chọn curve nào là chọn địa chỉ verifier nào.
- Chi phí của việc tách: một `staticcall` lạnh (2.600 gas) cộng chi phí copy calldata
  của proof (~1,3 KB → ~700 gas memory + copy). Tổng ~3.500 gas trên một giao dịch
  ~1,9M — **0,18%**.
- Trên **private profile** (§1.16), `contractSizeLimit` là tham số genesis và có thể
  đặt 64KB. Nhưng **không được dựa vào điều đó**: nếu source của public build và
  private build khác nhau, ta có hai codebase. Quy tắc: **mọi contract phải fit 24.000
  byte trên mọi profile**; CI enforce (1.14).

#### 1.3.5. Hai hiểm hoạ CÒN LẠI (ba cái kia chết cùng upgrade)

Ba mục của bản trước — ERC-1967 slot, ERC-7201 namespaced storage, và CI gate
`validateUpgrade` — **không còn ý nghĩa**. Kỷ luật storage layout chỉ cần khi hai
implementation khác nhau chạy trên **cùng** một state. Clone bất biến không bao giờ đổi
implementation, nên không bao giờ có implementation thứ hai để mà lệch layout.

Hai mục dưới đây **vẫn sống, và đều bắt buộc**:

1. **`constructor` không chạy trên clone.** Mọi giá trị `immutable` set trong
   constructor là giá trị của *implementation*, không phải của token. Bắt buộc:
   `initialize()` với modifier `initializer`, và constructor của implementation gọi
   `_disableInitializers()`.

   Bỏ qua bước này thì kẻ tấn công `initialize()` chính implementation. Với UUPS họ đi
   tiếp được tới `upgradeToAndCall` và `SELFDESTRUCT`; với clone thì đường đó đóng,
   nhưng `SELFDESTRUCT` chính implementation vẫn **brick mọi clone trỏ tới nó**. Rủi ro
   giảm, không mất. **EIP-6780 (Cancun) đã làm `SELFDESTRUCT` bớt nguy hiểm — nhưng chỉ
   trên chain đã có Cancun.** Gnosis đã fork Dencun; chain private 9000 thì **chưa có
   cả London** (xem `TRAPS.md`). Giả định A5 phải được kiểm chứng bằng một test
   on-chain thực tế trên mọi chain trước khi deploy, không bằng đọc changelog.

2. **`MAX_AMOUNT()` phải là `external view`, không được là `external pure`.** Note gốc
   (`blockchain.md`, interface `IZetherToken`) khai `pure`. Đây là một lỗi cụ thể,
   không phải một ý kiến.

   Lý lẽ cũ là *"mọi token dùng chung một beacon đều có cùng trần"*. Lý lẽ mới **mạnh
   hơn**: bỏ upgrade nghĩa là **mọi tham số per-token chỉ còn duy nhất một đường đến là
   `initialize()`** — không còn cách nào khác để phân biệt hai clone của cùng một
   implementation. `pure` khoá cứng giá trị vào bytecode dùng chung, nên nó làm mọi
   token của một version giống hệt nhau về trần, decimals, và `SHIELD_SCALE`.

   Cùng lớp lỗi này đã bắt được trong code thật: `ZSC.sol:21`
   `uint256 constant MAX = 4294967295;` — `constant` nên không thể per-token.

---
### 1.4. CREATE2 và dự đoán địa chỉ

```
address = keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))[12:32]
```

#### 1.4.1. Chuỗi xác định HAI tầng

Bản nháp nói một tầng, bản thứ hai nói ba. Với clone bất biến thì là **hai**:

```
Tầng 1: deployer   -> Arachnid 0x4e59b44847b379578588920cA78FbF26c0B4956C (hoặc EIP-2470 0xce0042B868300000d44A59004Da54A005ffdcf9f)
Tầng 2: factory    -> CREATE2 từ tầng 1, salt = keccak256("dms.blockchain.factory.v1")
Tầng 3: token      -> CREATE2 từ tầng 2, salt = xem 1.4.3, init_code = clone bytecode ++ implementation
```

Tầng beacon của bản trước biến mất cùng với upgrade. Nó tồn tại **chỉ để** giữ địa chỉ
ổn định khi implementation đổi — vì với Beacon thì `init_code` chứa địa chỉ beacon chứ
không chứa implementation. Không còn lần đổi nào thì không còn gì để mà giữ ổn định.

Đổi lại, `init_code` bây giờ chứa **chính địa chỉ implementation**. Nghĩa là:

- Hai token cùng `(kind, version)` trên hai chain có cùng địa chỉ **khi và chỉ khi**
  implementation của version đó nằm ở cùng địa chỉ trên cả hai chain. Mà implementation
  cũng deploy bằng CREATE2 từ tầng 2, nên điều đó đạt được bằng cách dùng cùng salt.
- `predictAddress` trở thành một **hàm thuần tuý**: không đọc storage nào, tính được
  hoàn toàn off-chain từ `(factory, implementation, salt)`. Bản trước phải lưu
  `initCodeHash` trong registry để client khỏi phải giữ bản sao bytecode của
  `BeaconProxy`; với clone thì bytecode là 45 byte cố định và client tự dựng được.

Gãy một tầng vẫn là gãy tất cả tầng dưới — nhưng giờ chỉ còn một tầng có thể gãy.

#### 1.4.2. Bẫy số 1 — `initData` trong `init_code`

Bẫy này **không còn** với EIP-1167: clone bytecode là 45 byte chỉ chứa địa chỉ
implementation, không có chỗ để nhét `initData` vào. Đổi tên token không bao giờ đổi
địa chỉ, miễn phí.

Nhưng điều đó có nghĩa contract sinh ra **chưa được initialize**, và đó là bẫy số 2 —
y hệt trường hợp `BeaconProxy` deploy với `data = ""`.

#### 1.4.3. Bẫy số 2 — front-run `initialize()` (giả định A2)

Contract sinh ra chưa được initialize. Nếu factory deploy ở tx 1 và initialize ở tx 2, bất kỳ ai cũng có thể chèn giữa và gọi `initialize()` trước, trở thành admin. Ba lớp chống, phải có **cả ba**:

1. **Atomic**: factory gọi `CREATE2` rồi `token.initialize(...)` **trong cùng một hàm**, một transaction. Không bao giờ để khoảng trống.
2. **Factory-only guard**: `initialize()` có `require(msg.sender == FACTORY)`. `FACTORY` là một `immutable` của *implementation* (constructor của implementation chạy bình thường, giá trị này đúng cho mọi clone trỏ tới nó). Kể cả khi ai đó đưa được một clone chưa init vào trạng thái lộ, họ không initialize được.
3. **Salt cam kết `initData`**: địa chỉ phải phụ thuộc vào nội dung khởi tạo, nhưng `init_code` thì không được. Giải bằng cách đưa hash của initData vào salt:

```solidity
bytes32 salt = keccak256(abi.encode(
    address(creator),         // NGƯỜI TẠO, không phải một id nội bộ — xem ghi chú dưới
    uint8(kind),              // TokenKind.META | TokenKind.ZETHER | TokenKind.MIGRATION
    uint64(version),          // 0 nếu deploy qua createUnregistered
    bytes8(assetCode),        // "ZVND", "ZUSDT"
    uint16(series),           // 0, 1, 2... cho phép re-deploy sau khi retire
    keccak256(initData)       // <-- cam kết nội dung khởi tạo MÀ KHÔNG nằm trong init_code
));
```

Kết quả: `predictAddress(salt)` vẫn trả lời được trước khi deploy (client tự tính `keccak256(initData)`), địa chỉ cam kết vào `name`/`symbol`/`decimals`/`maxSupply`, và `init_code` vẫn chỉ phụ thuộc `implementation`. Đây là thứ bản nháp thiếu.

**Trường đầu đổi so với bản trước, và đó không phải đổi tên.** Bản trước ghi
`uint64(issuerOrgId)` — "định danh tổ chức phát hành". Trên factory mở không có hệ
thống nào để định danh ai cả; trường đó phải là **`address` của người tạo**. Và nó
không chỉ là chỗ giữ chỗ: chính nó làm cho zDAI-A và zDAI-B của hai người khác nhau ra
hai địa chỉ khác nhau **kể cả khi mọi tham số còn lại giống hệt** — điều bắt buộc phải
đúng khi ai cũng wrap được cùng một underlying.

Không đưa `chainId` vào salt: ta *muốn* cùng địa chỉ trên nhiều chain. `chainId` đã nằm trong EIP-712 domain separator ở tầng meta-tx (§04), đó là chỗ đúng của nó.

#### 1.4.4. Bẫy số 3 — squatting và metamorphic

Nếu `deploy()` là **permissionless**, bất kỳ ai đọc được event đăng ký version cũng tính được địa chỉ tương lai của ta và deploy trước với initData của họ. Họ không chiếm được địa chỉ của ta (salt khác vì `keccak256(initData)` và `address(creator)` khác) nhưng họ **rác địa chỉ** và làm nhiễu indexer.

**Xử lý cũ, KHÔNG còn dùng được:** bản trước gắn `DEPLOYER_ROLE` cho `deploy()` và lập
luận *"deploy tự do không phải là một yêu cầu nghiệp vụ"*. Trên factory mở thì deploy
tự do **chính là** yêu cầu nghiệp vụ.

Xử lý đúng: `keccak256(initData)` và `address(creator)` đều nằm trong salt (1.4.3),
nên không ai chiếm được địa chỉ của ai — địa chỉ của ta phụ thuộc vào địa chỉ của ta.
Cái còn lại chỉ là **rác địa chỉ**, và đó là chi phí của permissionless, không phải lỗ
hổng. Indexer lọc bằng `isDeployedHere` cộng với các tín hiệu ở 1.2.

Nói cách khác: bẫy này không được *chặn*, nó được *chấp nhận* và đẩy sang tầng indexer.

**Metamorphic:** trước EIP-6780, một contract có thể `SELFDESTRUCT` rồi được `CREATE2` lại cùng địa chỉ với code khác. Trên chain chưa Cancun, điều này biến "địa chỉ = danh tính" thành sai — và chain private 9000 **chưa có cả London**, nên nó thuộc diện này. Xử lý: clone EIP-1167 không có `SELFDESTRUCT`; nhưng `expected_proxy_code_hash` trong Odoo (1.2) phải được **kiểm lại định kỳ**, không chỉ một lần lúc deploy. Một cron hàng ngày so `EXTCODEHASH` của mọi token `live` với giá trị đã lưu; lệch = incident.

#### 1.4.5. Deployer có sẵn không?

Arachnid deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C` được bootstrap bằng một **pre-EIP-155 signed transaction** (nonce 0 từ `0x3fab184622dc19b6109349b94811493bf2a45362`, gas price 100 gwei, gas limit 100.000 → cần 0,01 ETH-tương-đương trên chain đó). Chain không chấp nhận legacy tx thì không có sẵn.

Kiểm chứng bằng một lệnh, không bằng đọc docs:

```bash
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC
# khac "0x" = co san
```

- Gnosis: có sẵn.
- Celo: **phải kiểm lại.** Celo L1 dùng các transaction type riêng và từng hạn chế legacy tx; sau khi Celo chuyển sang L2 trên OP Stack (2025) thì hỗ trợ tx type chuẩn. Chạy lệnh trên trước khi chốt kiến trúc parity.
- Private (Nethermind 9000): ta tự bootstrap bằng chính presigned tx đó (funding 0,01 native cho `0x3fab18...` rồi broadcast raw tx). Nếu chain ở chế độ zero-gas thì bước funding bỏ qua.

#### 1.4.6. Khuyến nghị thực dụng về parity

Coi cross-chain address parity là *nice-to-have*, không phải ràng buộc. Client của ta **không bao giờ hardcode địa chỉ** — nó resolve từ `blockchain.token` qua RPC (`blockchain_list_tokens`). Nếu parity khó trên một chain, ghi nhận địa chỉ khác nhau và đi tiếp; đừng đính CI vào một ràng buộc không cần thiết.

Cái *phải* có, và khác hẳn parity, là **tính tái lập (reproducibility)**: cùng salt + cùng factory + cùng implementation phải luôn ra cùng địa chỉ, trên cùng một chain, từ bất kỳ máy nào. Cái đó là CI gate (1.14), và nó phụ thuộc `bytecode_hash = "none"`.

---

### 1.5. Catalogue implementation (thay cho Prototype Registry)

Yêu cầu "có khả năng thêm nguyên mẫu Contract" được thoả mãn bằng một catalogue on-chain, **không** bằng cách sửa factory. Đây là nơi version sống — và là nơi duy nhất, vì token đã deploy thì bất biến.

```solidity
enum TokenKind { META, ZETHER, MIGRATION }

struct Implementation {
    address implementation;  // clone trỏ thẳng tới đây, vĩnh viễn
    bytes32 implCodeHash;    // EXTCODEHASH kỳ vọng, để Odoo và ví đối chiếu
    bytes4  interfaceId;     // ERC-165: indexer phân loại contract không cần gọi catalogue
    uint8   profileHint;     // bit0 = public chain, bit1 = private chain. GỢI Ý, không chặn
    bool    deprecated;      // đánh dấu, KHÔNG chặn deploy
}
```

So với bản trước, ba trường **bỏ** và một trường **hạ cấp**:

| Trường cũ | Số phận |
|---|---|
| `beacon` | **bỏ** — không còn beacon |
| `archetype` + `majorVersion` | gộp thành khoá `(TokenKind kind, uint64 version)` của catalogue |
| `initCodeHash` | **bỏ** — với clone thì bytecode là 45 byte cố định, client tự dựng, không cần cache |
| `profileMask` → `profileHint` | **hạ cấp thành metadata.** Bản trước dùng nó để `require`: catalogue từ chối deploy archetype `permissioned` lên chain public. Đó là gác cổng **chính sách**, không phải chặn một cái brick — và người khác có thể có lý do chính đáng mà ta không biết. Giữ làm cảnh báo cho UI, bỏ `require` |

Ba trường **giữ**, và lý do vận hành không đổi:

- `implCodeHash`: bước verify ở 1.2 cần nó. Nếu chỉ lưu trong Odoo thì một Odoo bị xâm nhập tự sửa kỳ vọng của chính nó.
- `interfaceId` (ERC-165): trên factory mở điều này **cần hơn trước**. Indexer sẽ gặp token của người lạ mà nó chưa từng thấy; một `supportsInterface` rẻ hơn một vòng loop catalogue, và nó vẫn trả lời được khi catalogue không biết gì về token đó.
- `deprecated`: giữ, nhưng nghĩa đã đổi — xem dưới.

#### 1.5.1. Ba bất biến của catalogue

**1. Append-only.** `(kind, version)` đã đăng ký thì **không bao giờ trỏ lại chỗ khác**. Đây là bất biến quan trọng nhất, và nó phải có test riêng (§14).

Nếu `v1` trỏ lại được thì *"tôi muốn v1"* trở thành một mục tiêu di động: người tạo token đọc mã nguồn v1 hôm nay, deploy tuần sau, và nhận về một implementation khác. Cho phép sửa trỏ là dựng lại đúng cái quyền mà việc bỏ beacon vừa xoá đi — chỉ khác là nó tác động lên token tương lai thay vì token hiện tại.

**2. `deprecate()` đánh dấu, KHÔNG chặn.** Bản trước viết *"`deprecatePrototype` không xoá: token đã deploy vẫn chạy. Nó chỉ chặn `deploy` mới."* Nửa đầu vẫn đúng; nửa sau bỏ.

Chặn là thứ tự trấn an: `createUnregistered` bỏ qua catalogue hoàn toàn, nên bất kỳ rào nào cũng đi vòng được bằng một tham số. Một rào đi vòng được không mua thêm an toàn — nó chỉ mua cảm giác an toàn, và đổi lấy quyền chặn người khác deploy, thứ một factory mở không nên có.

Việc thật là **phát tín hiệu**: emit event kèm `reason`, để ví và UI hiện cảnh báo, để indexer đánh dấu mọi token đang chạy version đó. Lý do `reason` phải có vẫn như bản trước: khi ai đó deprecate lúc 3 giờ sáng, cái người trực cần là lý do, không phải một event trống.

Và câu cảnh báo cũ giờ mạnh hơn: **deprecate không cứu được một lỗ hổng đang bị khai thác trên các token đã sống** — cái đó là `pause` (1.10) rồi `MigrationSink` (1.17.2). Không còn `upgrade` trong danh sách.

**3. `createUnregistered` phải tồn tại.** Nếu chỉ version đã đăng ký mới deploy được thì người giữ quyền đăng ký quyết định được cả thế giới được tạo cái gì, và *"ai cũng tạo được"* thành khẩu hiệu.

Token sinh ra đường này mang `version() == 0`, và số 0 đó **cố ý nhìn thấy được**: ví phân biệt được "chạy v2 đã công bố, mã nguồn đọc được" với "chạy code người tạo tự mang tới". Cả hai đều hợp lệ; người sắp nạp tiền có quyền biết mình đang dùng cái nào.

Thêm archetype hoặc version mới = 1 tx `registerImplementation` + 1 record Odoo. **Factory không bao giờ phải upgrade** — câu này của bản trước vẫn đúng, và giờ nó là xương sống chứ không phải một tiện ích, vì factory cũng bất biến.

Interface đầy đủ ở `smartcontracts/src/common/IOpenFactory.sol`; section này không định nghĩa lại nó.

---

### 1.6. Ba nguồn gốc token

| Archetype | Contract | Collateral | Invariant kiểm tra được on-chain |
|---|---|---|---|
| `ISSUER_NATIVE` | `IssuerNativeToken` | Không | `totalSupply() <= maxSupply` |
| `WRAP_1_1` | `WrappedToken` + `ReserveVault` | 1:1 cùng asset | `totalSupply() <= reserveAccounted && reserveAccounted <= underlying.balanceOf(vault)` |
| `PEG_RATIO` | `PeggedToken` + `PegController` + `ReserveVault` | 1 hoặc giỏ ERC-20, hoặc reserve off-chain | `totalSupply() <= mulDiv(reserveValue(), rateNum, rateDen)` |
#### 1.6.1. `WRAP_1_1` — bẫy cụ thể

**Sửa so với bản nháp:** invariant không phải `totalSupply() == underlying.balanceOf(vault)`. Dạng `==` sai vì hai hướng:

- **Donate.** Bất kỳ ai cũng có thể `underlying.transfer(vault, x)`. Khi đó `balanceOf(vault) > totalSupply()` và một invariant test dạng `==` sẽ fail trên một hành vi vô hại. Tệ hơn: nếu code contract *tin* vào dạng `==` (ví dụ tính redeem theo `balanceOf`) thì donate trở thành một vector thao túng.
- **Rebase.** Nếu underlying là aToken, stETH, hay bất kỳ token rebasing nào, `balanceOf(vault)` thay đổi mà không có ai gọi hàm nào. Dạng `==` gãy ngay lập tức.

Thiết kế đúng: giữ một biến kế toán nội bộ.

```solidity
uint256 public reserveAccounted;   // chỉ thay đổi trong wrap/unwrap

function wrap(uint256 amountIn, address to) external nonReentrant {
    uint256 before = underlying.balanceOf(address(this));
    underlying.safeTransferFrom(msg.sender, address(this), amountIn);
    uint256 received = underlying.balanceOf(address(this)) - before;   // fee-on-transfer safe
    reserveAccounted += received;
    _mint(to, received);                                               // 1:1 raw unit
}

function sweepDonation(address to) external onlyRole(TREASURY_ROLE) {
    uint256 excess = underlying.balanceOf(address(this)) - reserveAccounted;
    require(excess > 0, "no excess");
    underlying.safeTransfer(to, excess);
    emit DonationSwept(to, excess);
}
```

Invariant `totalSupply() == reserveAccounted` (cái này đúng dạng `==`) **và** `reserveAccounted <= underlying.balanceOf(vault)`.

Với rebasing token: **từ chối wrap** ở tầng catalogue. `WRAP_1_1` không hỗ trợ rebasing underlying, chấm hết. Muốn hỗ trợ thì đó là một archetype khác (`WRAP_SHARES`, kiểu ERC-4626) — không làm trong v1.

Trên factory mở, "từ chối" ở đây là **từ chối trong code của archetype**, không phải một allowlist do ai đó duyệt: `WRAP_1_1` v1 đơn giản là không xử lý đúng rebasing, và ai wrap một rebasing token bằng nó thì tự chịu. Ai muốn làm đúng thì đăng ký một version khác.

Bẫy còn lại:

1. **Fee-on-transfer.** USDT trên Ethereum có `basisPointsRate` (hiện 0, nhưng code sống, và contract là upgradeable proxy nên "hiện 0" không phải là bảo đảm). USDT bridge sang Gnosis/Celo là contract khác với behaviour khác. **Không bao giờ tin tham số `amount`**: đo `balanceAfter - balanceBefore` như trên.
2. **USDT không tuân thủ ERC-20**: `transfer`/`approve` không return bool trên mainnet. Dùng `SafeERC20`. Và `approve` phải về 0 trước khi set giá trị mới.
3. **Underlying có thể freeze vault.** USDC/USDT có thể blacklist địa chỉ vault. Khi đó Z-USDT vẫn transfer được nhưng không redeem được — de facto de-peg trên một tài sản ta đã hứa là 1:1. Bắt buộc có state `REDEMPTION_HALTED` phát `event RedemptionHalted(bytes32 reason)`, **không được để `redeem` revert im lặng**. Một `revert` không có lý do là một sự cố hỗ trợ khách hàng; một event có lý do là một mục trong incident log.
4. **Underlying là một proxy và có thể đổi hành vi ngày mai.** USDT, USDC đều upgradeable. Ta không thể audit một mục tiêu di động. Xử lý tối thiểu: một cron đọc `EXTCODEHASH` của implementation của underlying hàng ngày; đổi = cảnh báo, không tự động halt (halt tự động trên một upgrade routine của Circle là một sự cố tự gây ra).

   Điểm này có một sự trớ trêu đáng ghi ra: **token của ta bất biến còn underlying của nó thì không.** Bỏ upgrade ở tầng của mình không mua được tính bất biến của thứ mình wrap. Người dùng zDAI-A tin hai thứ: code của zDAI-A (đọc được, cố định) và code của DAI (đọc được, có thể đổi). Tài liệu tích hợp phải nói rõ cả hai, đừng để tính bất biến của lớp ngoài che mất tính khả biến của lớp trong.
5. **Decimals**: **mirror y hệt underlying**, không "chuẩn hoá về 18". Đọc bằng `underlying.decimals()` **tại thời điểm initialize** và lưu vào storage; không hardcode trong Odoo. Wrap 1:1 theo raw unit thì rounding = 0, dust = 0, và invariant là một phép so sánh bằng. Bất kỳ phép scale nào cũng tạo ra một hướng làm tròn. Lưu ý phụ: `decimals()` **không** thuộc interface ERC-20 bắt buộc; một underlying khó tính có thể không có hàm đó. Nếu không có, từ chối wrap.

#### 1.6.2. `ISSUER_NATIVE`

Đơn giản nhất, nhưng `maxSupply` phải là `immutable`-tương-đương (set trong `initialize`, không có setter). Một `maxSupply` có thể tăng được thì không phải là trần, nó là một cái nút.

Hai thứ bản nháp thiếu:

- **`maxMintPerEpoch`.** `maxSupply` bảo vệ tổng; nó không bảo vệ tốc độ. Một khoá MINTER bị lộ có thể in hết `maxSupply` trong một block. Thêm `uint256 mintedThisEpoch` + `uint64 epochLength` (mặc định 1 ngày) + `require(mintedThisEpoch + amount <= maxMintPerEpoch)`. Đặt `maxMintPerEpoch` = 2% `maxSupply`: một kẻ tấn công cần 50 ngày, còn đội trực có 24 giờ để phát hiện.
- **`maxSupply` cũng là trần giải mã Zether.** Xem 1.8. `require(maxSupply <= MAX_DECRYPTABLE_RAW)` trong `initialize()` — một dòng, và nó chặn một lớp lỗi không thể sửa sau khi đã mint. Với token bất biến thì "không thể sửa sau" là nghĩa đen: không có bản vá, chỉ có `MigrationSink`.

---

### 1.7. `PEG_RATIO`: ai chịu FX risk, rate từ đâu, de-peg

Ví dụ trong note — `1 USDT -> 25000 Z-VND` — **không phải là một peg. Nó là một lời hứa hoàn trả, và nó là một vị thế short USD của issuer.**

Nếu tỷ giá thị trường về 27.000 VND/USD mà ta vẫn cam kết đổi 25.000 Z-VND lấy 1 USDT, mỗi 25.000 Z-VND redeem làm issuer mất 2.000 VND giá trị kinh tế. Định lượng: float 10 tỷ VND (= 400.000 USDT ở rate 25.000), VND mất giá 6%/năm (2024 VND mất khoảng 4,5–5% so với USD — ước tính, cơ sở là biến động tỷ giá trung tâm) → **~24.000 USDT P&L một năm**. Con số này phải là một dòng trong `account.move`, không phải một bất ngờ.

#### 1.7.1. Ba chế độ, và cái nào dùng cho cái gì

| Chế độ | Ai chịu FX | Redemption guarantee | Dùng khi nào |
|---|---|---|---|
| `FIXED_RATE` | **Issuer** | Luôn đúng tỷ lệ đã công bố | Loyalty/reward điểm, closed-loop. Tỷ lệ là *chính sách thương mại*, không phải tỷ giá |
| `ORACLE_RATE` | **Holder** | Theo rate tại thời điểm redeem | Khi Z-VND thật sự muốn là stablecoin VND |
| `RESERVE_FLOAT` | Chia sẻ qua bộ đệm over-collateral | Theo rate, halt khi CR thấp | B2B settlement có quỹ dự phòng |
**Khuyến nghị cho cả ba use case trong scope:** dùng `FIXED_RATE`, **nhưng đặt reserve bằng VND, không phải USDT**. Sai lầm cốt lõi là giữ tài sản USDT đối ứng một nghĩa vụ ghi bằng VND. Nếu token là Z-VND thì:

- reserve là số dư VND ở một tài khoản ngân hàng tách biệt (hoặc tài sản thanh toán bằng VND);
- chân USDT chỉ là **on-ramp một chiều**, quy đổi theo spot rate **tại thời điểm nạp**, đọc từ oracle **chỉ tại biên giới đó**;
- redemption guarantee phát biểu bằng VND: 25.000 Z-VND đổi 25.000 VND. Không bao giờ phát biểu bằng USDT.

Làm vậy thì FX mismatch biến mất hoàn toàn, và `1 USDT -> 25000 Z-VND` trở thành một tỷ giá tức thời chứ không phải một cam kết vĩnh viễn.

#### 1.7.2. Mint cap khi reserve nằm ngoài chain (giả định A7)

Bản nháp bỏ qua độ trễ thanh toán. On-chain mint là tức thì; tiền VND vào tài khoản là T+0 đến T+2. Nếu contract cho phép mint theo attestation gần nhất, ta mint trước khi tiền đến.

Công thức mint cap bắt buộc, đánh giá ở mỗi lần mint:

```
mintable = attested_reserve_minor
         - totalSupply_in_minor
         - in_flight_redemption_minor        // đã requestRedeem, chưa settle
         - safety_buffer_minor               // mặc định 2% attested_reserve
```

`attested_reserve_minor` có **staleness**. Quy tắc cụ thể:

| Tuổi attestation | Mint | Redeem | Ghi chú |
|---|---|---|---|
| <= 7 ngày | Bình thường | Bình thường | — |
| 8 – 35 ngày | Cho phép, nhưng `safety_buffer` tăng lên 10% | Bình thường | Cảnh báo |
| 36 – 60 ngày | **Chặn** | Bình thường | Incident |
| > 60 ngày | Chặn | Chặn mint, redeem pro-rata theo CR giả định = 100% | Chuyển `UNDERCOLLATERALIZED` |

Lý do không bao giờ chặn redeem theo staleness: staleness là lỗi của issuer, không phải của người giữ token.

#### 1.7.3. Spread — thứ bản nháp bỏ sót và nó là một lỗ hổng kinh tế

Nếu `mintRate == redeemRate` và không có phí, thì mỗi lần oracle cập nhật là một cơ hội arbitrage không rủi ro: kẻ tấn công mint ngay trước khi rate tăng và redeem ngay sau, ăn trọn delta, và tiền đó ra thẳng từ reserve. Với circuit breaker 2%/lần cập nhật (dưới đây) và 96 lần cập nhật/ngày, bề mặt mất mát tối đa là không giới hạn.

Bắt buộc có spread hai chiều:

```solidity
// spreadBps áp dụng đối xứng, luôn có lợi cho reserve
uint256 mintRate   = Math.mulDiv(oracleRate, 10_000 - spreadBps, 10_000);   // người mint nhận ít Z hơn
uint256 redeemRate = Math.mulDiv(oracleRate, 10_000 + spreadBps, 10_000);   // người redeem trả nhiều Z hơn
```

Chọn `spreadBps`: phải `>=` biến động tối đa giữa hai lần cập nhật. Với breaker 200 bps/lần cập nhật, `spreadBps >= 100` (1%) là ngưỡng tối thiểu lý thuyết. Thực dụng cho VND/USD (biến động ngày thường dưới 30 bps): **`spreadBps = 50`** (0,5%), cộng `redemptionDelaySeconds = 86400` cho mọi khoản redeem vượt 100 triệu VND. Độ trễ này là thứ biến arbitrage từ "không rủi ro" thành "có rủi ro qua đêm", và đó là đủ.

Với `FIXED_RATE` không dùng oracle, spread có thể = 0 — nhưng khi đó phải có `redemptionDelay` và `dailyRedemptionCap`, vì rủi ro không còn là arbitrage mà là bank run.

#### 1.7.4. Nguồn rate, xếp theo độ tin cậy

1. **AMM TWAP** — **loại bỏ cho VND**. Không có pool VND thanh khoản on-chain. Thao túng một pool sâu $50k trong một block tốn khoảng $1–2k với flashloan; kẻ tấn công mint theo rate giả. Chỉ chấp nhận nếu depth >= $5M và TWAP >= 30 phút, điều không tồn tại với VND.
2. **Oracle bên thứ ba** — Chainlink không có feed VND/USD trên Gnosis hay Celo (kiểm chứng tại `data.chain.link` trước khi chốt; tính đến thời điểm viết là không có). Thực tế là **ta phải tự vận hành feed**:

```solidity
struct SignedRate {
    bytes32 pair;            // keccak256("VND/USD")
    uint128 price;           // giá, theo priceDecimals
    uint8   priceDecimals;
    uint64  publishTime;
    uint64  roundId;         // tăng dần, chặn replay một round cũ
}
// 2-of-3 signer, EIP-712, domain có chainId + verifyingContract
require(block.timestamp - r.publishTime <= 900, "stale");
require(r.roundId > lastRoundId, "replay");
require(_absDeltaBps(r.price, lastPrice) <= 200, "breaker");   // 2% mỗi lần cập nhật
```

**Cái bản nháp chưa trả lời: khi oracle stale thì sao?** Nếu `require(stale)` làm `mint` revert, một sự cố oracle 20 phút làm dừng toàn bộ luồng nạp tiền — một DoS ta tự gây ra. Chính sách rõ ràng:

| Tình trạng oracle | `mint` | `redeem` | `CR` |
|---|---|---|---|
| Tuổi <= 15 phút | Rate hiện tại | Rate hiện tại | Tính bình thường |
| 15 phút – 6 giờ | **Chặn** | `lastGoodRate` + spread gấp đôi | Dùng `lastGoodRate` |
| > 6 giờ | Chặn | `lastGoodRate` + spread gấp đôi, cap 10 triệu VND/ngày/địa chỉ | Coi như stale, không tự động đổi state |
| Breaker này liên tục 3 lần | Chặn | Như trên | `GUARDIAN` được gọi dậy |

3. **Admin-set qua timelock** — lựa chọn trung thực cho loyalty closed-loop. `setRate` qua timelock 48h, và mint/burn dùng rate **đã có hiệu lực tại thời điểm tích luỹ** (lưu theo lô), không phải rate hiện tại. Người dùng tích điểm hôm qua không bị định giá lại sau một đêm.

   Lưu ý: timelock ở đây là của **người tạo token**, trên chính token của họ, và nó là một tham số `initialize()` chứ không phải một thiết chế toàn hệ thống. Nó không liên quan gì tới timelock upgrade đã bị xoá ở 1.11 — cái đó chết vì không còn upgrade; cái này sống vì `setRate` vẫn là một quyền thật trên tiền thật.

**Bổ sung bắt buộc cho lựa chọn 3:** "rate theo lô" nghĩa là contract phải lưu `mapping(uint64 batchId => uint256 rateNum)` và người redeem phải chỉ ra lô. Đó là một cấu trúc dữ liệu tăng không giới hạn. Thực dụng hơn: **rate không bao giờ giảm** cho loyalty (một chính sách thương mại, không phải một ràng buộc kỹ thuật), khi đó rate hiện tại luôn có lợi cho người giữ điểm và không cần lưu theo lô. Nếu bạn không thể cam kết điều đó, thì phải lưu theo lô và phải có `pruneBatches` sau 24 tháng.

#### 1.7.5. De-peg: state machine bắt buộc có từ ngày đầu

```
PEGGED  --CR < 100%-->  UNDERCOLLATERALIZED  --CR < 90%-->  REDEMPTION_HALTED
   ^                            |                                  |
   +----CR >= 102% trong 24h----+                                  v
                                                              WIND_DOWN
```

`CR = reserveValue() * rateDen / (totalSupply() * rateNum)`, tính lại ở mỗi mint/burn và mỗi lần cập nhật rate. Làm tròn: **floor trên tử số, ceil trên mẫu số** — CR luôn được báo cáo thấp hơn hoặc bằng sự thật.

Điểm quan trọng nhất, và là chỗ dễ sai nhất: **trong `UNDERCOLLATERALIZED`, redemption phải là pro-rata tại mức CR, không được first-come-first-served.** FCFS dưới tình trạng thiếu tài sản bảo đảm là **một cơ chế sinh ra bank run**: người rút đầu lấy 100%, người cuối lấy 0%, và ai cũng biết điều đó nên ai cũng rút ngay. Pro-rata (`payout = amount * CR`) là quy tắc công bằng duy nhất và **phải nằm trong contract từ đầu**, không thể thêm sau — thêm sau tức là đổi điều kiện hoàn trả giữa chừng.

Với token bất biến thì "không thể thêm sau" mạnh hơn một lời khuyên: nó là sự thật vật lý. Một `PEG_RATIO` v1 quên pro-rata sẽ chạy FCFS cho tới ngày nó chết, và cách duy nhất sửa là một token v2 cộng một chiến dịch di cư (1.17.2).

`WIND_DOWN`: mint tắt vĩnh viễn, redeem `min(1, CR)` pro-rata, cửa sổ claim 180 ngày, phần dư chuyển về `RecoveryVault`.

**`RecoveryVault` và `ReserveVault` phải là contract riêng, và lý do đã đổi.** Bản trước lập luận: nếu chúng nằm sau beacon dùng chung với token thì một lần `upgradeTo` sai (hoặc ác ý) điều khiển được số tiền dư của mọi vault cùng lúc. Vector đó **không còn** — không có beacon, không có `upgradeTo`.

Nhưng kết luận vẫn giữ, vì lý do thứ hai mạnh hơn: **tách vault khỏi token là tách bề mặt tấn công**, và với contract bất biến điều đó quan trọng hơn chứ không kém. Một lỗi trong logic token không được phép chạm tới tài sản bảo đảm, vì không có bản vá nào cả — bề mặt duy nhất giữa hai bên phải là một interface hẹp, kiểm được. Bản trước còn viết `ReserveVault` là "UUPS riêng với timelock 7 ngày, hoặc tốt hơn là bất biến hoàn toàn"; nhánh "tốt hơn" giờ là nhánh duy nhất.

#### 1.7.6. Giỏ (basket) — thứ note yêu cầu và chưa ai thiết kế

Note viết "mint/burn từ 1 hoặc 1 group ERC-20". Một giỏ không phải là một vault với nhiều token; nó là một bài toán NAV. Tối thiểu cần:

```solidity
struct BasketLeg {
    address token;
    uint16  targetBps;      // tổng 10.000
    uint16  bandBps;        // được lệch bao nhiêu trước khi bắt buộc rebalance
    bytes32 pricePair;      // khoá đọc từ SignedRateSource
    uint8   tokenDecimals;
}
function reserveValue() public view returns (uint256 minorUnits) {
    // sum over legs: balanceOf(vault) * price / 10^tokenDecimals, quy về minor unit của Z-token
    // MỌI leg cần một rate tươi. Một leg stale => toàn bộ reserveValue stale.
}
```

Ba hệ quả mà người quyết định phải nghe trước khi đồng ý:

1. **N leg = N oracle = N điểm gãy.** Với quy tắc staleness ở 1.7.2, xác suất "có ít nhất một leg stale" tăng gần tuyến tính theo N. Với 3 leg và uptime oracle 99,5% mỗi leg, uptime tổng = 98,5% — tức ~5,5 ngày/năm không mint được.
2. **Rebalance là một giao dịch giao ngay trên DEX**, tức là slippage, MEV, và một khoá có quyền chi tiêu reserve. Khoá đó là bề mặt tấn công lớn nhất trong toàn bộ hệ thống. Nếu rebalance thủ công qua Safe 4-of-7, nó không kịp với biến động; nếu tự động, ta vừa tạo một bot có quyền bán reserve.
3. **Giỏ làm kế toán Odoo phức tạp gấp N lần** vì mỗi leg là một `res.currency` khác nhau và một `account.account` khác nhau.

**Khuyến nghị dứt khoát: không làm basket trong v1.** Nếu cần đa tài sản, làm N token `WRAP_1_1` độc lập (Z-USDT, Z-USDC) và để việc trộn nằm ở tầng nghiệp vụ (Odoo), nơi mà bộ phận tài chính nhìn thấy và kiểm soát được. Thiết kế giỏ để ở đây dưới dạng giấy, và archetype `BASKET_PEG` **không được đăng ký vào catalogue** cho đến khi có quyết định ngược lại.

Lưu ý cách phát biểu đã đổi: bản trước nói `profileMask = 0x00` để "không deploy được ở đâu". Trên factory mở thì không có cách nào chặn ai đó tự viết một basket và deploy qua `createUnregistered`. Thứ ta kiểm soát là **cái gì có mặt trong catalogue của ta** — và đó là đủ, vì catalogue là thứ nói lên ta đứng sau cái gì.

#### 1.7.7. Reserve accounting và proof-of-reserve

| Loại reserve | Bằng chứng khả thi | Cadence |
|---|---|---|
| On-chain ERC-20 trong `ReserveVault` | `underlying.balanceOf(vault)` — là bằng chứng, không cần attest | mỗi block, indexer ghi vào `blockchain.reserve.snapshot` |
| Off-chain VND ở ngân hàng | **Không có PoR mật mã nào**. Chỉ có attestation | snapshot số dư hàng ngày, attestation ký hàng tháng |

Cho reserve off-chain:

```solidity
function attest(
    bytes32 statementHash,   // keccak256 của bản PDF lưu trên Garage
    uint256 amountMinor,     // số dư VND * 100
    uint64  asOf,
    bytes   calldata sig     // EIP-712, signer = khoá của đơn vị kiểm toán
) external;
```

Bản kê PDF lưu trên Garage dưới dạng `ir.attachment` (Many2many, không base64 trong DB, không JSON blob) và `keccak256` của nó ghi on-chain. Phía Odoo, `blockchain.reserve.attestation` đối soát với một `account.account` (tài khoản ngân hàng tách biệt) để con số trên GL và con số công bố on-chain là một.

**Gọi đúng tên: đây là "attested reserve", không phải "proof of reserve".** Cây Merkle kiểu sàn giao dịch chứng minh *nghĩa vụ* (tổng số dư người dùng), không chứng minh *tài sản*; nó không giải bài toán ở đây. Nói "proof of reserve" trong tài liệu marketing là một phát biểu sai sự thật mà bộ phận pháp chế sẽ phải gỡ lại sau.

Ba điều bản nháp chưa nói:

- **Nếu đơn vị kiểm toán ký sai số thì sao?** Attestation là một chữ ký trên một con số; contract không thể biết nó đúng. Biện pháp duy nhất có thật: `require(amountMinor <= lastAmountMinor * 3)` — một breaker chặn sai số kiểu thêm số 0, không chặn gian lận. Và **hai** signer độc lập cho mọi attestation vượt 50 tỷ VND.
- **Reserve không được là tài khoản vận hành.** Nếu tài khoản giữ reserve cũng là tài khoản trả lương, số dư dao động vì lý do không liên quan và CR nhảy lung tung. Phải là một tài khoản tách biệt, và số hiệu tài khoản đó phải nằm trong `blockchain.token.peg` để đối soát kiểm được.
- **Ai chịu chi phí attestation?** Một công ty kiểm toán lớn sẽ không ký hàng tháng cho một float nhỏ với giá hợp lý. Đó là một câu hỏi ngân sách, không phải kỹ thuật — đưa vào 1.19.

Invariant `attested_reserve_minor >= totalSupply() * unit` chain **không thể** tự kiểm tra (chain không biết số dư ngân hàng). Nó thuộc về một cron Odoo (`model._cron_reserve_check()`), và vi phạm thì mở incident, không phải ghi log.


---

### 1.8. Decimals, làm tròn, dust — và VND không có đơn vị phụ

VND có ISO 4217 exponent = 0. Decimals "đúng" cho Z-VND là 0. Nhưng `decimals = 0` khiến mọi phí phần trăm không biểu diễn được và mọi phép quy đổi từ USDT (6 decimals) sinh dust.

**Khuyến nghị: `decimals = 2` cho Z-VND** (đơn vị tối thiểu on-chain = 0,01 VND, không bao giờ hiển thị cho người dùng). Lý do định lượng: 1 raw unit USDT = 0,000001 USDT = 0,025 VND. Với `decimals = 0` thì mỗi phép mint bỏ mất tới 0,999 VND; với `decimals = 2` thì bỏ mất tới 0,009 VND — nhỏ hơn 100 lần, và đủ để biểu diễn phí 1,5% trên các giá trị nhỏ.

Hai ràng buộc bản nháp không đặt ra:

- **`decimals` là bất biến.** Vì không có setter, và vì ví và block explorer cache nó. Đổi decimals sau khi mint là đổi ý nghĩa của mọi số đã phát ra. Điều này làm việc chọn `decimals = 2` thành một quyết định nghiệp vụ cần chữ ký, không phải một config (1.19).

  Với token bất biến, "bất biến" ở đây không còn là một kỷ luật tự nguyện: nó là hệ quả của việc không có implementation thứ hai nào để mà đổi hành vi. Nhưng điều đó cắt cả hai chiều — chọn sai decimals ở v1 thì cách sửa duy nhất là một token v2 và một chiến dịch di cư 180 ngày (1.17.2).
- **`decimals()` không thuộc ERC-20 bắt buộc.** Một số tích hợp giả định 18. Ta không thể sửa thế giới; ta chỉ có thể **ghi decimals vào tên hiển thị trong metadata** và **không bao giờ phát hành Z-VND lên một DEX công khai mà không có cảnh báo**.

#### 1.8.1. Biên giới Odoo — một vấn đề kế toán, không phải một vấn đề contract

`res.currency` của VND trong Odoo có `rounding = 1.0`. Chain có granularity 0,01 VND. Hai hệ thống không thể khớp tuyệt đối.

> Quy tắc cứng: làm tròn **luôn có lợi cho bên giữ quỹ**: floor khi chi trả, ceil khi thu. Phần dư được hạch toán vào một tài khoản `Dust`, không bao giờ bị bỏ im lặng.

| Thao tác | Hướng làm tròn | Ai hưởng phần lẻ | Ghi sổ |
|---|---|---|---|
| mint (nạp underlying → Z) | floor `zOut` | reserve | `reserveDust` on-chain |
| redeem (Z → underlying) | floor payout | reserve | `reserveDust` on-chain |
| fee thu | ceil | fee recipient | doanh thu |
| refund / rebate trả | floor | reserve | `reserveDust` |
| CR | floor tử số / ceil mẫu số | bảo thủ | — |
| Post lên `account.move` | round half-up về 1 VND | GL | tài khoản `Dust` |

**Ràng buộc thực dụng để dust không sinh ra từ phía Odoo:** mọi lệnh mint/burn **khởi tạo từ Odoo** phải là bội số của `10^decimals` (tức số nguyên VND). Enforce ở tầng Odoo (`_check_amount_is_whole_major`), không ở tầng contract — contract vẫn phải chấp nhận đơn vị lẻ vì luồng on-chain (Zether transfer, phí relayer) sinh ra chúng. Nhờ vậy 100% các bút toán GL là số nguyên VND, và dust chỉ tồn tại ở các luồng on-chain thuần tuý.

#### 1.8.2. Công thức mint/burn không sinh dust

```solidity
uint256 zOut       = Math.mulDiv(amountIn, rateNum, rateDen);              // floor
uint256 consumedIn = Math.mulDiv(zOut, rateDen, rateNum, Math.Rounding.Ceil);
uint256 refund     = amountIn - consumedIn;
if (refund >= refundThreshold) underlying.safeTransfer(msg.sender, refund);
else reserveDust += refund;   // giữ lại => CR tăng, không bao giờ về tay admin
```

`Math.mulDiv` của OpenZeppelin dùng 512-bit trung gian nên không overflow.

**`refundThreshold` không được là hằng số** — bản nháp để nó là hằng số và điều đó sai trên chuỗi. Ngưỡng đúng là "giá trị refund > chi phí gas để trả nó". Một `safeTransfer` ~35.000 gas:

| Chain | Gas price | Native | Chi phí 1 transfer | `refundThreshold` hợp lý (USDT raw, 6 dec) |
|---|---|---|---|---|
| Gnosis | 1,5 gwei | xDAI = $1 | ~$0,00005 | 100 (= $0,0001) |
| Celo | ~5 gwei | CELO ~$0,4 | ~$0,00007 | 100 |
| Ethereum L1 | 10 gwei | ETH $3.000 | ~$1,05 | 2.000.000 (= $2) |
| Besu private (zero gas) | 0 | — | $0 | 1 |

Kết luận: `refundThreshold` là một biến storage set trong `initialize()`.

**Và ở đây bản trước có một câu không còn đúng:** nó viết `refundThreshold` "sửa được qua `TREASURY_ROLE` + timelock 48h". Với token bất biến thì một setter vẫn khả thi — bất biến nói về *code*, không phải về *state* — nhưng nó phải là một quyết định có ý thức của người tạo token, không phải mặc định. Hai nhánh, và người tạo chọn ở `initialize()`:

- **Có setter**: `refundThreshold` theo kịp giá gas, nhưng token có một khoá sống mãi mãi mà không ai thu hồi được, vì không có upgrade để gỡ nó ra sau này.
- **Không setter**: token không có khoá nào cả, nhưng nếu gas trên chain đó tăng 100 lần thì ngưỡng thành sai vĩnh viễn.

Trên chain private zero-gas thì nhánh hai là hiển nhiên. Trên public thì đây là một đánh đổi thật, và nó phải nằm trong mô tả archetype để người tạo đọc được trước khi chọn version.

#### 1.8.3. Ràng buộc bất ngờ từ Zether — và bản nháp trước cũng sai ở đây

Note (`blockchain.md`, mục 10.5.2 và 10.5.3) khẳng định nâng `MAX` từ `2^32 - 1` lên `2^128 - 1` là đủ. **Điều này sai ở một điểm quan trọng**: giới hạn `2^32` trong `anonymous-zether` của ConsenSys không (chỉ) là giới hạn range proof, nó là **giới hạn giải mã**. Chủ tài khoản phải khôi phục `b` từ `g^b` bằng baby-step giant-step; với không gian `2^128` thì BSGS cần `2^64` phép tính — bất khả thi. Nâng MAX lên `2^128` không làm số dư đọc được. (Chi tiết mật mã ở §03; ở đây chỉ lấy hệ quả lên token design.)

**Nhưng bản nháp trước của chính section này cũng sai khi đề xuất `MAX_CONFIDENTIAL = 2^48 - 1`.** Hai lý do:

1. **48 không phải luỹ thừa của 2.** Bulletproofs inner-product argument đòi `n * m` là luỹ thừa của 2. Với `n = 48`, prover phải pad lên 64, và **chi phí verify là chi phí của 64 bit**. Chọn 48 là trả tiền cho 64 mà nhận soundness của 48. Chọn **`n = 64`**.
2. **Range proof width và trần giải mã là hai thứ khác nhau và phải được tách ra.** Range proof bảo đảm *soundness* (không ai chuyển số âm, không ai tiêu quá số dư). Trần giải mã bảo đảm *usability* (chủ tài khoản đọc được số dư của mình). Gắn chúng vào một hằng số là lỗi thiết kế.

**Công thức đúng:** chi phí BSGS bị chặn bởi **`totalSupply` tính theo raw unit**, không phải bởi `2^n`. Lý do: tổng mọi số dư confidential = `confidentialLocked <= totalSupply`, nên mỗi số dư cá nhân cũng `<= totalSupply`. Do đó:

> **Quy tắc chốt: `maxSupply` tính theo raw unit phải `<= 2^44` (= 1,759e13). Enforce trong `initialize()`.**

Định lượng BSGS với không gian tìm kiếm `S`, bảng baby-step kích thước `B = sqrt(S)`:

| Token | decimals | Trần cung tiền | `S` (raw) | `log2 S` | `B = sqrt(S)` | Bộ nhớ bảng | Thời gian giải mã xấu nhất |
|---|---|---|---|---|---|---|---|
| Z-VND | **2** | 100 tỷ VND | 1,0e13 | 43,2 | 3,2e6 | ~130 MB | ~0,8 – 1,0 s |
| Z-VND | 0 | 100 tỷ VND | 1,0e11 | 36,5 | 3,2e5 | ~13 MB | ~0,08 s |
| Z-USDT | 6 | 10 triệu USDT | 1,0e13 | 43,2 | 3,2e6 | ~130 MB | ~0,8 – 1,0 s |
| (note đề xuất) | — | `2^128` | 3,4e38 | 128 | 1,8e19 | bất khả thi | bất khả thi |

Cơ sở: một phép cộng điểm affine trên `bn254` trong Rust tối ưu ~250–300 ns; vòng giant-step là (1 cộng điểm + 1 tra bảng hash) ~350–400 ns; `3,2e6 * 350ns ≈ 1,1 s` xấu nhất, ~0,55 s trung bình. Bộ nhớ: 3,2e6 entry × (32 byte toạ độ nén + 8 byte index) ≈ 128 MB, cộng overhead hash map ~1,5x nếu dùng `HashMap` chuẩn; dùng một open-addressing table thì sát 130 MB.

Con số này là của `bn254`. Trên BLS12-381, một điểm nén là 48 byte thay vì 32, nên **bảng baby-step lớn hơn ~1,4 lần** ở cùng `S` — 130 MB thành ~180 MB. Đó là một chi phí của việc chọn curve mà bảng gas không hiện ra, và nó rơi vào thiết bị của người dùng cuối chứ không vào hoá đơn gas. Với factory mở, curve là lựa chọn của người tạo token, nên con số này thuộc về tài liệu hướng dẫn chọn version chứ không phải một quyết định của ta.

**Đó là một ước tính, và nó thay đổi một quyết định:** `decimals = 2` đắt gấp 10 lần `decimals = 0` về thời gian khôi phục (1 s vs 0,08 s). Vẫn khuyến nghị `decimals = 2`, vì:

- đường hạnh phúc không dùng BSGS: mỗi giao dịch kèm một ciphertext phụ `encSelf = AEAD(kdf(x), value || randomness)` trong event log. Ví đọc số dư bằng cách giải AEAD, `O(1)`, không tới 1 ms. BSGS chỉ chạy khi **recovery** (mất cache cục bộ, đồng bộ máy mới).
- 1 giây cho một thao tác chạy vài lần trong đời một tài khoản là chấp nhận được; mất khả năng biểu diễn phí phần trăm thì không.

Chốt tham số cho v1:

```solidity
uint8   public immutable RANGE_BITS;            // 64 — luỹ thừa của 2, soundness
uint256 public immutable MAX_DECRYPTABLE_RAW;   // 1 << 44 = 1,759e13, usability
// initialize(): require(maxSupply_ <= MAX_DECRYPTABLE_RAW, "supply exceeds decryptable range");
// mint():       require(totalSupply() + amount <= maxSupply, "cap");
```

**Hai giá trị này là `immutable` chứ không `constant`, và đó là một sửa lỗi so với bản trước.** Bản trước khai `public constant`. Cùng lớp lỗi với `MAX_AMOUNT()` khai `pure` (1.3.5 mục 2) và với `ZSC.sol:21` `uint256 constant MAX = 4294967295;`: một hằng số biên dịch làm **mọi token dùng chung implementation đó có cùng trần**, và Z-VND với Z-USDT thì không thể cùng trần. Giá trị per-token chỉ có một đường đến duy nhất là `initialize()`.

Nếu một ngày nào đó cần vượt `2^44`, đường nâng cấp không phải là tăng `RANGE_BITS` — đó là **chia token thành nhiều series** (`series` đã có trong salt, 1.4.3), mỗi series có sổ cái riêng. Đó là một vấn đề kế toán, không phải mật mã. Và với token bất biến thì đó cũng là đường duy nhất, vì `RANGE_BITS` của một token đã deploy không đổi được kể cả khi muốn.

Định lượng gas của chính quyết định này ở mục 1.12.

---

### 1.9. Total-supply invariants
Viết dưới dạng property test (Foundry invariant), không phải comment:

```
inv_wrap_1  : totalSupply() == reserveAccounted
inv_wrap_2  : reserveAccounted <= underlying.balanceOf(vault)
inv_peg     : totalSupply() <= mulDiv(reserveValue(), rateNum, rateDen)
inv_native  : totalSupply() == mintedCumulative - burnedCumulative <= maxSupply
inv_cap     : maxSupply <= MAX_DECRYPTABLE_RAW
inv_conf    : confidentialLocked == balanceOf(address(this))
inv_conf_2  : confidentialLocked <= totalSupply()
inv_rate    : |rate_t - rate_{t-1}| * 10000 / rate_{t-1} <= 200   // stateful, qua nhiều lần cập nhật
inv_state   : pegState != PEGGED  =>  mint reverts
inv_impl    : implementation() không đổi qua MỌI chuỗi call            // xem §14, test bất biến
```

**Sửa so với bản nháp:** bản nháp viết `inv_conf : confidentialLocked == totalSupply() - sum(public ERC20 balances)`. Sai ở hai chỗ:

1. **`sum(public ERC20 balances)` không thể đánh giá được on-chain** — không có cách nào liệt kê holder của một ERC-20. Một bất biến không đánh giá được không phải là một bất biến; nó là một câu văn.
2. Công thức đúng đơn giản hơn nhiều: token contract giữ chính số token đã nạp vào vùng confidential, nên `balanceOf(address(this))` **là** số đó. Vậy `confidentialLocked == balanceOf(address(this))`, một phép so sánh một SLOAD với một mapping read. Đánh giá được trong `assert` cuối mỗi `deposit`/`withdraw`, không chỉ trong test.

`inv_impl` là dòng mới, và nó là bất biến rẻ nhất trong danh sách nhưng lại canh thứ đắt nhất: nếu nó gãy thì mọi bất biến còn lại đều vô nghĩa, vì code sinh ra chúng đã bị thay. Với EIP-1167 nó đúng theo cấu trúc (implementation nằm trong 45 byte runtime, không có storage slot nào để ghi đè) — nhưng đúng theo cấu trúc là lý do để test nó, không phải lý do để bỏ qua.

`inv_conf` là thứ note bỏ sót và nó là thứ dễ mất tiền nhất. Một Zether token vừa là ERC-20 công khai vừa giữ số dư mã hoá có **hai không gian số dư**. Phía mã hoá không thể cộng on-chain (đó là mục đích của nó). Bất biến duy nhất rẻ tiền là một biến đếm **công khai** `confidentialLocked`, tăng khi `deposit`, giảm khi `withdraw`, với `unchecked` bị cấm — một underflow ở đây chính là một lần in tiền.

Đánh đổi: `confidentialLocked` **lộ tổng float confidential** (không lộ từng tài khoản). Đây là một tiết lộ **có chủ ý và chấp nhận được** — nó là cái giá để có thể phát hiện một lỗ hổng mint vô hạn. Nếu không có nó, một bug trong Bulletproof verifier có thể in tiền mà không ai thấy cho đến khi vault cạn.

Với token bất biến, lập luận này mạnh thêm một bậc: **phát hiện sớm là biện pháp duy nhất còn lại.** Không có bản vá khẩn cấp, nên khoảng cách giữa "bug bắt đầu bị khai thác" và "có người nhìn thấy" là toàn bộ thiệt hại. Một bất biến rẻ, đánh giá được ở mọi giao dịch, đáng giá hơn hẳn so với khi còn có `upgradeTo` để chạy theo sau.

Cấu hình fuzz cụ thể (không phải "chạy invariant test"):

```toml
[invariant]
runs = 50_000
depth = 64
fail_on_revert = false
shrink_run_limit = 5_000
```

`depth = 64` vì các lỗi de-peg chỉ lộ ra sau một chuỗi mint/burn/rate-update đan xen; `depth = 15` mặc định của Foundry không bao giờ chạm tới `UNDERCOLLATERALIZED`. Handler phải có một `warp` ngẫu nhiên (0 – 30 ngày) để invariant staleness (1.7.2) được thử.

---

### 1.10. Pause / freeze / blacklist — cái nào chấp nhận được

Ba thứ này không giống nhau và phải được đối xử khác nhau:

| Cơ chế | Public chain profile | Private chain profile | Ràng buộc bắt buộc |
|---|---|---|---|
| `pause()` toàn cục | Chấp nhận | Chấp nhận | **`MAX_PAUSE = 7 ngày`**: sau mốc đó, `redeem`/`withdraw` tự động mở lại bất kể pause. Pause không giới hạn thời hạn là tịch thu tài sản có giấy tờ |
| `freeze(account)` | Chỉ cho `WRAP_1_1` của underlying vốn đã freeze được, và chỉ theo lệnh toà | Chấp nhận | Phát `AccountFrozen(account, bytes32 caseRef)`, role giữ bởi multisig, không bao giờ EOA |
| `blacklist` mở (admin tự thêm) | **Từ chối** | Thừa (transfer đã bị allowlist của registry chặn) | — |

Lý do từ chối blacklist trên public chain không phải ý thức hệ: một token có thể bị blacklist tuỳ ý **không dùng làm collateral ở bất cứ đâu khác**, và làm cho tuyên bố "wrapped 1:1" trở thành sai sự thật. Với `WRAP_1_1` của USDC thì ta **đã** thừa kế khả năng freeze của USDC rồi; giấu điều đó đi mới là không trung thực — công bố nó.

**Biến nó thành đặc tính của archetype, không phải cờ runtime:**

- `ZTokenOpen` — không `freeze`, không `blacklist`, `pause` giới hạn 7 ngày.
- `ZTokenPermissioned` — transfer gated bởi allowlist của registry.

Trên factory mở, hai cái này là **hai entry trong catalogue**, không phải hai nhánh của một cờ. Người tạo muốn token pause được thì chọn version có pause; muốn token không có admin nào thì chọn version không có. Đó chính là công dụng của catalogue, và nó làm cho lựa chọn hiện ra trong `version()` — thứ ví đọc được — thay vì nằm trong một biến storage mà không ai kiểm.

Bản trước viết `ZTokenPermissioned` "chỉ deploy được trên profile private (`profileMask` bit1)". Câu đó không còn thực thi được (1.5), và cũng không nên: nó là gác cổng chính sách. `profileHint` giữ lại làm cảnh báo trong UI.
Khi đã mint dưới `ZTokenOpen` thì **không ai bật được blacklist về sau**, kể cả admin, kể cả người tạo, kể cả người deploy factory.

**Lý do đảm bảo điều đó đã đổi, và bản mới mạnh hơn.** Bản trước viết: *"vì beacon của `ZTokenOpen` chỉ nhận implementation cùng archetype (registry kiểm tra `archetype` trong `validateUpgrade`)"* — tức lời hứa được thực thi bằng **logic registry**, và nó đúng chừng nào registry không có bug và không ai đổi được registry.

Bây giờ nó được thực thi bằng **vật lý**: không tồn tại đường nâng cấp nào cả. Lời hứa mạnh lên, còn cơ chế phải viết ra để bảo vệ nó thì biến mất. Đây là ví dụ rõ nhất trong cả section về việc bỏ upgrade mua được cái gì.

#### 1.10.1. Lối thoát khỏi trần pause 7 ngày

Bản nháp đặt `MAX_PAUSE = 7 ngày` nhưng không trả lời: **nếu chính `withdraw` là hàm có bug thì sao?** Tự động mở lại `withdraw` sau 7 ngày là mở lại lỗ hổng.

Lối thoát duy nhất, và nó phải là một chiều:

```
paused --(7 ngày hết hạn)--> auto-unpause redeem/withdraw
   |
   +--(GUARDIAN của token, KHÔNG timelock)--> WIND_DOWN  [một chiều, không quay lại]
```

`WIND_DOWN` không phải là "pause lâu hơn". Nó là: mint tắt vĩnh viễn, `RecoveryVault` được cấp vốn bằng toàn bộ reserve, và người giữ token đòi qua `RecoveryVault` (một contract khác, code khác, không chia sẻ bug với token). Nghĩa là bạn không được phép kéo dài pause; bạn chỉ được phép **từ bỏ token và trả tiền qua một đường khác**. Đó là một lựa chọn đắt, và nó đúng phải đắt — nó là thứ ngăn một pause "tạm thời" kéo dài 3 năm.

**Với token bất biến, `WIND_DOWN` không còn là phương án cuối cùng — nó là phương án duy nhất.** Bản trước ngầm giả định có một nhánh thứ ba: pause, vá bằng `upgradeTo`, mở lại. Nhánh đó không tồn tại. Nên chuỗi xử lý sự cố đầy đủ, viết ra để không ai đi tìm nhánh đã chết:

```
phát hiện bug -> pause (tối đa 7 ngày)
                   |
                   +-- bug không chạm tiền  -> hết 7 ngày, tự mở, sống chung với nó
                   +-- bug chạm tiền        -> WIND_DOWN -> token v2 + MigrationSink (1.17.2)
```

Hệ quả cho người tạo token: **`pause` chỉ mua được 7 ngày để quyết định, không mua được thời gian để sửa.** Ai deploy một token không có `pause` thì thậm chí không có 7 ngày đó — một lựa chọn hợp lệ, nhưng phải chọn có ý thức, và nó nằm ở việc chọn version.

#### 1.10.2. Pause và tính khả kết hợp

Một token bị pause đang nằm trong một pool DEX hoặc làm collateral ở một giao thức khác sẽ làm kẻ thứ ba không thanh lý được vị thế, và họ sẽ mất tiền vì quyết định của ta. Hai hệ quả thực tế:

- Với `ZTokenOpen` phát hành công khai, phải công bố `MAX_PAUSE` trong tài liệu tích hợp, và phát `Paused(uint64 autoUnpauseAt)` để bot của họ đọc được mốc tự động mở.
- Với `ZTokenPermissioned` trên private chain, không có bên thứ ba, vấn đề này không tồn tại. Đây là một lý do nữa để mọi luồng tiền có quy định nên ở private profile trước.

Trên factory mở có thêm một hệ quả thứ ba: **người tích hợp không biết trước token họ gặp có `pause` hay không.** Đó là lý do `version()` và `interfaceId` phải đọc được — chúng là cách duy nhất một bot trả lời được câu "token này có ai pause được không" mà không phải đọc bytecode.

#### 1.10.3. Freeze giao với Zether

Đóng băng một `schnorrAddress` (có trong registry, §02) chặn `rollOver` và `withdraw`, nhưng **không thể tịch thu** số dư mã hoá — contract không biết nó bằng bao nhiêu. Freeze ở tầng Zether nghĩa là "kẹt", không phải "thu hồi". Bộ phận pháp chế sẽ hỏi câu này; trả lời trước.

Hệ quả pháp lý mà bản nháp không kéo đến tận cùng: **nếu quy định đòi hỏi khả năng tịch thu (seizure) theo lệnh cơ quan, thì Zether trên public chain không đáp ứng được, chấm hết.** Chỉ có hai đường: (a) token không thể redeem ra tiền pháp định (loyalty thuần tuý) nên không thuộc phạm vi điều chỉnh đó, hoặc (b) chạy trên private chain nơi một lệnh toà được thực thi bằng một `forceTransfer` có sự chứng kiến của N validator.

Có một đường thứ ba mà bản trước không có, và nó không phải tịch thu: **chứng minh chọn lọc** (`transferWithProof`, `_USER-DECISIONS.md` §12). Phần lớn yêu cầu thật của cơ quan thuế và toà án là *xuất trình được*, không phải *tịch thu được* — và đó là thứ mở ciphertext trả lời được, trong khi tịch thu thì không. Ba đường này khác nhau và không thay thế nhau; §13 phải nói rõ cái nào đáp ứng yêu cầu nào.

---

### 1.11. Quản trị: của factory, và của token

Mục này trong bản trước tên là *"Quản trị upgrade"* và dài ~110 dòng: mười role, Safe 4-of-7, timelock 48h không đường tắt, `RECOVERY` 6-of-7 trễ 30 ngày, cron dò governance drift cross-chain, và một model `blockchain.upgrade.proposal` bắt buộc đính kèm báo cáo audit và storage diff.

**Toàn bộ bộ máy đó tồn tại để kiểm soát đúng một quyền: upgrade. Quyền đó không còn.**

Nhưng mục này không bị xoá — nó **tách làm đôi**, vì hai loại quản trị còn lại thuộc về hai chủ thể khác nhau và bị nhầm làm một trong bản trước.

#### 1.11.1. Quản trị factory — gần như trống

Quyền của người vận hành factory, liệt kê đầy đủ:

| Quyền | Hại tối đa gây được |
|---|---|
| `registerImplementation` | Xuất bản một version dở. Chỉ ảnh hưởng token deploy **sau** đó, và **chỉ khi có người chọn nó** |
| `deprecate` | Emit một event. Không chặn gì (1.5.1) |

Không quyền nào chạm được vào tiền của ai. Nên câu hỏi *"ai giữ khoá factory"* rớt từ **hạng mục rủi ro sống còn** xuống **vệ sinh vận hành**: một Safe 2-of-3 của đội kỹ thuật là đủ, và không cần timelock — timelock bảo vệ chống một hành động không đảo ngược được, còn `registerImplementation` thì không ai bị bắt phải dùng.

**Giả định A1 đảo chiều.** Bản trước: *"mất khoá = không deploy được token mới trên chain đó, và mất parity địa chỉ cross-chain vĩnh viễn"* — xếp ở mức thảm hoạ. Bây giờ: mất khoá ⇒ catalogue đóng băng ở version cuối, **và mọi người vẫn deploy được qua `createUnregistered`** (1.5.1). Suy giảm, không chết.

Một điều duy nhất còn đáng bảo vệ nghiêm túc ở tầng factory: **bất biến append-only** (1.5.1 mục 1). Nó không phải là một chính sách vận hành mà là một `require` trong code, và code thì bất biến — nên nó không cần khoá nào canh cả. Đó là hình dạng đúng: thay một quy trình bằng một dòng code không sửa được.

#### 1.11.2. Quản trị token — của NGƯỜI TẠO, không phải của ta

Các role bên trong một token không biến mất: `MINTER`, `BURNER`, `TREASURY_ROLE`, `RATE_SIGNER`, `ATTESTOR`, `GUARDIAN`, `pause`. Chúng thuộc về **người tạo token**, đặt lúc `initialize()`, và ta không có quyền gì trên chúng.

Nên bảng dưới đây đổi giọng: nó không còn là *"ta phải làm thế này"* mà là *"nếu token của bạn có role này, đây là các ngưỡng đã được cân nhắc và đây là lý do"*. Nó là tài liệu hướng dẫn kèm archetype, không phải một thiết chế.

| Role | Khuyến nghị | Ngưỡng | Độ trễ | Vì sao |
|---|---|---|---|---|
| `DEFAULT_ADMIN_ROLE` | Safe nhiều bên, có ít nhất một bên ngoài tổ chức | 4/7 | 7 ngày để đổi role | Bảy khoá của bảy nhân viên cùng một công ty là một chữ ký, không phải bảy |
| `MINTER` / `BURNER` | service account, khoá trong HSM | — | không trễ, nhưng `maxMintPerEpoch` on-chain (1.6.2) | Trần tổng không bảo vệ tốc độ |
| `TREASURY_ROLE` | Safe nhỏ hơn | 3/5 | 48h cho `sweepDonation`, `setRefundThreshold` | Chi tiêu reserve là hành động không đảo ngược |
| `RATE_SIGNER` | 2-of-3 | 2/3 | staleness 15 phút | 1.7.4 |
| `ATTESTOR` | khoá của đơn vị kiểm toán, **ngoài công ty** | 1, hoặc 2 khi > 50 tỷ | — | 1.7.7 |
| `GUARDIAN` | 1-of-5 kỹ sư trực | 1/5 | tức thì, **chỉ `pause`** | Guardian được phép **dừng**, không được phép **đổi** |
| `RECOVERY` | Safe rộng hơn | 6/7 | 30 ngày | Chỉ để thay toàn bộ signer set khi mất khoá |

Nguyên tắc cũ **vẫn đúng và giờ là tuyệt đối**: *guardian được phép dừng, chỉ timelock được phép đổi.* Trước đây nó là một kỷ luật; bây giờ nửa sau của nó được thực thi bởi việc không tồn tại hàm nào để mà đổi.

**Và một lựa chọn phải được ghi ra trước, vì trên factory mở nó là lựa chọn hợp lý nhất cho nhiều người: một archetype KHÔNG có role nào cả.** Không admin, không pause, không mint sau khi deploy. Một `WRAP_1_1` thuần tuý không cần bất kỳ khoá nào để hoạt động đúng — wrap và unwrap là hai hàm không cần ai cho phép. Token đó không có gì để mất khoá, không có gì để bị tấn công quản trị, và không có gì để người dùng phải tin. Nó nên là entry đầu tiên trong catalogue, không phải một trường hợp đặc biệt ở cuối danh sách.

#### 1.11.3. Ba thứ trong bản trước bị xoá hẳn

1. **Model `blockchain.upgrade.proposal`** cùng toàn bộ ràng buộc `audit_report_ids` / `storage_diff_ids` / `to_impl_codehash` / `proposal_state`. Không có upgrade để mà đề xuất.
2. **Cron dò governance drift cross-chain** (`getOwners()` + `getThreshold()` của mỗi Safe trên mỗi chain, so với danh sách kỳ vọng trong Odoo). Nó canh signer set của các Safe điều khiển upgrade. Với token của **ta** thì cron này vẫn hữu ích như một kiểm tra vận hành, nhưng nó là chuyện của `dms_blockchain`, không phải một yêu cầu của protocol — và nó không áp dụng cho token của người khác.
3. **`Ownable2Step` cho beacon owner.** Không có beacon.

Thứ **không** bị xoá và vẫn phải làm: câu *"không có đường từ một bản audit đến một lần execute"* của bản trước là một quan sát đúng, và nó chuyển thành một yêu cầu khác — **catalogue phải liên kết mỗi version với bản audit của nó**. Không phải bằng một model quy trình, mà bằng một sự thật đọc được: `implCodeHash` on-chain, cộng một bản audit công bố công khai với đúng hash đó. Người tạo token chọn v2 thì họ đọc được v2 đã audit hay chưa, và điều đó phải kiểm được mà không cần tin ai.

---

### 1.12. Định lượng gas, calldata và thông lượng

Cơ sở: chi phí opcode EVM sau EIP-1108 (`ecAdd` = 150, `ecMul` = 6.000, `ecPairing` = 45.000 + 34.000k) và EIP-2929 (cold account 2.600, cold SLOAD 2.100). Code deposit = 200 gas/byte (EIP-170 giới hạn 24.576 byte; EIP-3860 giới hạn initcode 49.152 byte + 2 gas/word). Gnosis: ~1,5 gwei, xDAI = 1 USD. Ethereum L1 đối chiếu: 10 gwei, ETH = 3.000 USD. **Tất cả là ước tính; đo lại bằng `forge test --gas-report` trước khi chốt ngân sách.**

| Thao tác | Gas | Gnosis | Ethereum L1 |
|---|---|---|---|
| Deploy implementation `ZTokenBase` (~13 KB runtime) | ~2.800.000 | $0,0042 | $84 |
| ~~Deploy `UpgradeableBeacon`~~ | — | — | không còn (1.3) |
| ~~Deploy BeaconProxy qua CREATE2 + `initialize`~~ | ~~230.000~~ | — | không còn (1.3) |
| **Deploy EIP-1167 clone + `initialize`** | **~70.000** | **$0,00011** | **$2,10** |
| `transfer`, người nhận đã có số dư (warm slot) | ~37.000 | $0,00006 | $1,11 |
| `transfer`, người nhận mới (slot 0 → non-0) | ~46.000 | $0,00007 | $1,38 |
| `mint` `PEG_RATIO` (đọc rate + vault transferFrom) | ~120.000 | $0,00018 | $3,60 |
| `attest()` | ~85.000 | $0,00013 | $2,55 |
| Zether `transferConfidential`, `RANGE_BITS = 32` | ~1.150.000 | $0,0017 | $34,50 |
| Zether `transferConfidential`, **`RANGE_BITS = 64` (chốt)** | **~1.900.000** | **$0,0029** | **$57** |
| Zether `transferConfidential`, `RANGE_BITS = 128` (note đề xuất) | ~3.500.000 | $0,0053 | $105 |

**Hai dòng đổi so với bản trước, và cả hai đều rẻ đi.** Deploy một token rớt từ ~230.000 xuống ~70.000 gas (45.000 cho clone + ~25.000 cho `initialize`) vì không còn `BeaconProxy`. Và `transfer` tới người nhận mới rớt từ ~54.000 xuống ~46.000 vì mất phần *"overhead beacon lạnh"* — STATICCALL sang beacon cộng SLOAD trong beacon, ~4.600 gas mỗi transaction đầu tiên. Với một token có 1 triệu transfer/năm trên Gnosis, riêng khoản đó là ~4,6e9 gas.

Đây là lợi ích không nằm trong lý lẽ chính của việc bỏ upgrade (1.3.2) nhưng nó có thật, và nó đi đúng chiều: thứ an toàn hơn cũng là thứ rẻ hơn.

#### 1.12.1. Phản bác con số Zether — và sửa lại chính bản nháp

Bản nháp kết luận "con số 180.000 – 250.000 gas trong note thấp hơn thực tế khoảng một bậc". **Kết luận đó đúng cho Bulletproofs nhưng sai ở chỗ nó không nói ra rằng con số của note là đạt được với một hệ chứng minh khác.** Phản bác đầy đủ:

Bulletproofs verify là một multi-scalar multiplication kích thước `2*n*m + 2*ceil(log2(n*m)) + ~7` điểm, và EVM không có precompile MSM cho `bn254` — mỗi điểm là một `ecMul` riêng:

| `n` (bit) | `m` (số giá trị) | Số điểm MSM | Gas MSM | Sigma-protocol | Cập nhật state | **Tổng** |
|---|---|---|---|---|---|---|
| 32 | 2 | 128 + 14 + 7 = 149 | ~916k | ~150k | ~50k | ~1,15M |
| **64** | **2** | 256 + 14 + 7 = 277 | ~1,70M | ~150k | ~50k | **~1,90M** |
| 128 | 2 | 512 + 16 + 7 = 535 | ~3,29M | ~150k | ~50k | ~3,50M |

**Câu "EVM không có precompile MSM" đúng cho `bn254` và SAI cho BLS12-381.** EIP-2537 có `G1MSM` ở `0x0c` — một lệnh duy nhất cho cả bó điểm. Đã đo thật trên Gnosis (`eth_estimateGas`, 2026-08-30), và kết quả lật ngược trực giác:

| k điểm | BLS12-381 `G1MSM` (1 lệnh) | alt_bn128 (k×`ecMul` + (k−1)×`ecAdd`) |
|---|---|---|
| 1 | 12.357 | 6.000 |
| 32 | 244.175 | 196.650 |
| 128 | 805.495 | 787.050 |
| **277** | **1.741.589** | **1.703.400** |

Ở đúng quy mô của bảng trên (k = 277), MSM một-lệnh của BLS **đắt hơn ~2%** so với 277 `ecMul` rời của bn254 — không rẻ hơn. Bảng discount của EIP-2537 định giá MSM gần như tuyến tính theo k, nên lợi thế "một lệnh" là lợi thế về calldata và về số lần vào-ra precompile, không phải về gas. Con số ~1,70M trong bảng đứng vững cho cả hai curve.

Hệ quả cho factory mở: **người tạo token chọn curve nào cũng trả gas xấp xỉ nhau**, nên curve là lựa chọn về biên an toàn và về chain khả dụng, không phải về chi phí (`_USER-DECISIONS.md` §17, §20.1).

Calldata của proof: `2*log2(n*m)` điểm cho inner-product + 4 điểm cam kết + 5 scalar. Với `n=64, m=2` trên bn254: 14 + 4 = 18 điểm × 64 byte + 5 × 32 byte = **1.312 byte**, ~21.000 gas calldata trên L1 (16 gas/byte khác 0). Trên BLS12-381 thì mỗi điểm là 128 byte, nên proof thành **2.464 byte** và calldata gần gấp đôi — đây là chỗ BLS thật sự đắt hơn, và nó không hiện trong bảng MSM.

Trên một L2 dùng calldata (không dùng blob), calldata là thành phần chi phí **lớn nhất**, không phải execution. Đó là một lý do nữa để Zether ở private chain hoặc ở Gnosis L1-như-L2, không ở một rollup.

Con số `~7,2M gas` mà `anonymous-zether` của ConsenSys báo cáo là cho **anonymity set 16**. Kiến trúc mặc định của ta không có anonymity set (người gửi/nhận công khai), nên phần `many-out-of-many` biến mất. Dùng con số 1,9M, không dùng 7,2M, khi làm ngân sách.

Trên factory mở có một sửa đổi cho câu trên: **ring size là thuộc tính của verifier, do người tạo token chọn** (`IZetherVerifier.ringSize()`). Ai muốn ẩn danh trong đám đông thì đăng ký một verifier ring lớn và trả 7,2M gas; ai muốn rẻ và lộ danh tính thì ring = 2. Cả hai đều là entry hợp lệ trong catalogue. **Mọi con số gas trong tài liệu vì thế phải gắn với một `m` cụ thể** — một con số gas không kèm ring size là một con số vô nghĩa.

**Con số 180k–250k của note đạt được bằng một hệ chứng minh pairing-based, không bằng Bulletproofs:**

| Hệ chứng minh | Gas verify | Kích thước proof | Prover time (client) | Trusted setup |
|---|---|---|---|---|
| Bulletproofs, n=64 | ~1,9M | ~1,3 KB | ~150 – 400 ms | Không |
| Groth16 (bn254) | **~230k – 280k** (1 `ecPairing` 4 cặp = 181k + ~8 `ecMul` input) | 128 byte | ~0,5 – 3 s | **Có, per-circuit ceremony** |
| PLONK / Halo2-KZG | ~350k – 500k | ~500 byte – 1 KB | ~1 – 5 s | Universal (có thể tái sử dụng) |

Đổi lại 1,9M → 250k gas (**giảm 87%**) là: một ceremony trusted setup (Groth16) hoặc một circuit phức tạp hơn (PLONK), cộng với việc circuit trở thành một artifact phải version và audit riêng. **Khuyến nghị v1: Bulletproofs**, vì private chain làm gas thành đơn vị kế toán nội bộ (khoá quyết định #5) và vì không có ceremony là một bớt gánh nặng vận hành thật.

Trên factory mở, câu này cũng nhẹ đi: đường nâng cấp sang Groth16 **không cần ai đồng ý** — nó là một `IZetherVerifier` khác, đăng ký thành `ZETHER v2`, và người tạo token nào muốn thì chọn. Không phải một cuộc di cư, chỉ là một entry mới trong catalogue. Xem §03.

#### 1.12.2. Thông lượng — con số bản nháp không có, và nó đổi kiến trúc

Gas per tx là một con số. Con số quyết định là **bao nhiêu giao dịch bảo mật một giây**.

| Chain | Block gas limit (ước, kiểm lại) | Block time | Zether tx/block nếu chiếm 100% block | Thực tế (giả định chiếm 25% block) |
|---|---|---|---|---|
| Ethereum L1 | ~36M | 12 s | 18 | 0,37 tx/s |
| Gnosis | ~17M | 5 s | 8 | **0,45 tx/s** |
| Celo (L2) | ~30M | ~1 s | 15 | 3,7 tx/s |
| Nethermind private 9000, gas limit 16,7M | 16,7M | 5 s | 8 | **xem dưới** |

**Dòng cuối đã đo, không còn là giả định.** Chain private ở `/home/dockers/mba-chain-nethermind` có `gasLimit = 0x1000000` = 16.777.216, Clique period 5s, một signer. Đó là con số thật, và nó **không** phải "200M gas limit, 2s" như bản nháp giả định cho một Besu QBFT tưởng tượng. Với 16,7M thì một block chứa tối đa 8 Zether tx, y hệt Gnosis.

Nâng gasLimit trên Clique làm được bằng signer vote, **không cần reset chain** — khác với đổi genesis (`TRAPS.md`). Nên con số này là một tham số vận hành, không phải một trần cứng.

Trên private chain, khi gas limit đã được nâng, ràng buộc thật là **CPU của validator**. 277 `ecMul` trên bn254; Nethermind dùng thư viện native cho alt_bn128 precompile, ~50–100 µs mỗi `ecMul`. `277 × 80µs ≈ 22 ms` để verify một proof. EVM chạy tuần tự trong một block, nên trần thật là:

```
5000 ms / 22 ms = ~225 proof/block  ->  ~45 confidential tx/s
```

Con số này, không phải gas limit, là thứ phải xuất hiện trong tài liệu năng lực. Và nó là một con số **đủ** cho mọi khối lượng B2B thực tế (45 tx/s = 3,9 triệu giao dịch/ngày), đồng thời là một con số **không đủ** cho thanh toán người dùng cuối bán lẻ ở quy mô quốc gia. Kết nối với 1.15.

#### 1.12.3. Con số củng cố khoá quyết định #5
#### 1.12.3. Con số củng cố khoá quyết định #5

Trên chain riêng, gas là giá trị kế toán nội bộ (zero-gas mode). Và nó định lượng lợi ích của việc chọn `RANGE_BITS = 64` thay vì 128: **giảm ~46% gas** và **~46% thời gian CPU validator** (225 → 122 proof/block nếu dùng 128 bit), đổi lấy một trần range 1,8e19 raw — thừa xa `MAX_DECRYPTABLE_RAW = 1,76e13` vốn là ràng buộc thật sự.

---

### 1.13. Phía Odoo — `dms_blockchain` độc lập

`__manifest__.py`: `'depends': ['base', 'mail']`. **Không có `dms`.** Model prefix là `blockchain.`, không phải `dms.` — dùng `dms.` khi DMS không được cài là một lời nói dối về phạm vi. (Prefix này được chốt ở §10.3; section này tuân theo.)

```
dms_blockchain/
├── __manifest__.py
├── models/
│   ├── chain.py                # blockchain.chain              (định nghĩa ở §08.1 / §10.4.2)
│   ├── token_archetype.py      # blockchain.token.archetype
│   ├── token_version.py        # blockchain.token.version      (mirror catalogue on-chain)
│   ├── token.py                # blockchain.token
│   ├── token_peg.py            # blockchain.token.peg          (rate_num, rate_den, cr, peg_state)
│   ├── reserve_snapshot.py     # blockchain.reserve.snapshot
│   └── reserve_attestation.py  # blockchain.reserve.attestation (M2M ir.attachment trên Garage)
├── data/ir_cron.xml
└── security/{ir.model.access.csv, blockchain_security.xml}
```

**Hai thay đổi so với bản trước.** `upgrade_proposal.py` (model `blockchain.upgrade.proposal`) **bị xoá** — không có upgrade để mà đề xuất (1.11.3). Và `token_prototype.py` đổi thành `token_version.py`, mirror catalogue `(kind, version)` thay vì registry prototype có beacon (1.5).

#### 1.13.1. `blockchain.token`

```python
class BlockchainToken(models.Model):
    _name = 'blockchain.token'
    _description = 'Deployed token contract'
    _inherit = ['mail.thread']
    _order = 'chain_id, symbol'

    name             = fields.Char(required=True)
    symbol           = fields.Char(required=True)
    active           = fields.Boolean(default=True)
    company_id       = fields.Many2one('res.company', required=True, index=True,
                                       default=lambda s: s.env.company)
    token_decimals   = fields.Integer(required=True, default=2)
    archetype        = fields.Selection([('issuer_native', 'Issuer Native'),
                                         ('wrap_1_1', 'Wrapped 1:1'),
                                         ('peg_ratio', 'Ratio Pegged')], required=True)
    chain_id         = fields.Many2one('blockchain.chain', required=True, index=True)

    # Version thay cho prototype_id + upgradeable. Ca hai deu BAT BIEN sau deploy.
    version_id       = fields.Many2one('blockchain.token.version')   # rong => createUnregistered
    impl_version     = fields.Integer(readonly=True, help='0 = ngoai catalogue')
    impl_address     = fields.Char(size=42, readonly=True)
    creator_address  = fields.Char(size=42, readonly=True)

    contract_address = fields.Char(size=42, index=True)   # LUON lowercase (xem _normalize)
    predicted_address= fields.Char(size=42)
    expected_codehash= fields.Char(size=66)
    salt_hex         = fields.Char(size=66)
    init_data_hex    = fields.Char()
    deploy_tx_hash   = fields.Char(size=66)
    deploy_date      = fields.Datetime(readonly=True)      # KHONG dat ten 'date'

    # uint256 luon la chuoi thap phan base unit (quy uoc §10.4.1). Integer/Float deu tran.
    max_supply_base  = fields.Char(help='uint256 decimal string, base units.')

    deploy_state     = fields.Selection([
        ('draft', 'Draft'), ('predicted', 'Predicted'), ('broadcast', 'Broadcast'),
        ('pending_finality', 'Pending Finality'), ('verified', 'Verified'), ('live', 'Live'),
        ('failed', 'Failed'), ('mismatch', 'Code Mismatch'),
        ('paused', 'Paused'), ('wind_down', 'Wind Down'), ('retired', 'Retired'),
    ], default='draft', required=True, tracking=True)

    _unique_addr = models.Constraint(
        'UNIQUE(chain_id, contract_address)',
        'Mot dia chi contract chi duoc dang ky mot lan tren mot chain.')
    _unique_salt = models.Constraint(
        'UNIQUE(chain_id, salt_hex)',
        'Mot salt chi sinh mot token tren mot chain — chan deploy trung.')
    _check_addr_lower = models.Constraint(
        r"CHECK (contract_address IS NULL OR contract_address ~ '^0x[0-9a-f]{40}$')",
        'contract_address phai la hex lowercase co 0x.')
    _check_maxsupply = models.Constraint(
        r"CHECK (max_supply_base IS NULL OR max_supply_base ~ '^[0-9]{1,78}$')",
        'max_supply_base phai la chuoi thap phan uint256.')

    @api.model
    def blockchain_predict_address(self, kind, version, salt_hex, chain_code):
        """POST /web/dataset/call_kw/blockchain.token/blockchain_predict_address
           POST /json/2/blockchain.token/blockchain_predict_address
        Khong nhan allowed_company_ids tu client; pham vi suy tu self.env.company."""
        return self._predict_address(kind, version, salt_hex, chain_code)

    @api.model
    def blockchain_list_tokens(self, chain_code=None):
        """Metadata cong khai cho client. Chi tra token deploy_state == 'live'."""
        dom = [('deploy_state', '=', 'live')]
        if chain_code:
            dom.append(('chain_id.code', '=', chain_code))
        return self.search_read(dom, ['symbol', 'token_decimals', 'contract_address',
                                      'archetype', 'chain_id', 'impl_version'])

    def _predict_address(self, kind, version, salt_hex, chain_code):
        ...
```

**`upgradeable = fields.Boolean(default=True)` bị xoá.** Nó luôn `False`, nên nó là một trường luôn nói dối hoặc luôn thừa. Thay bằng `impl_version` + `impl_address`, cả hai `readonly` và cả hai là sự thật đọc được từ chain.

`impl_version` lọt vào `blockchain_list_tokens` là có chủ ý: client cần phân biệt được token chạy version đã công bố với token chạy code người tạo tự mang tới (1.5.1 mục 3), và nó phải thấy điều đó **trước** khi nạp tiền, không phải sau.

#### 1.13.2. Sáu chi tiết Odoo bản nháp bỏ sót

1. **Địa chỉ phải được chuẩn hoá lowercase.** EIP-55 checksum nghĩa là `0xAbC...` và `0xabc...` là **cùng một địa chỉ** nhưng là hai chuỗi khác nhau. Một `UNIQUE(chain_id, contract_address)` trên chuỗi mixed-case không chặn được trùng. Lưu lowercase (`create`/`write` override, hoặc `_normalize`), hiển thị checksummed bằng một compute không lưu.
2. **`company_id` và record rule.** Cái gì giữ tiền thì có `company_id` (§10.9). Record rule chuẩn `[('company_id','in',company_ids)]`. Nếu một ngày nào đó cần hierarchy đơn vị, dùng `child_of` trên một **many2one**, không bao giờ trên `parent_path`.
3. **`res.users.group_ids`** (Odoo 19 đổi tên từ `groups_id`) — dùng tên mới trong mọi data XML và mọi đoạn Python của addon.
4. **Deploy phải idempotent (giả định A11).** Cron broadcast không được broadcast hai lần cho cùng một record. Khoá ở tầng DB, không ở tầng Python:

```python
def _cron_broadcast_pending_deploys(self):
    self.env.cr.execute("""
        SELECT id FROM blockchain_token
         WHERE deploy_state = 'predicted' AND active
         ORDER BY id
         FOR UPDATE SKIP LOCKED
         LIMIT 20
    """)
    ids = [r[0] for r in self.env.cr.fetchall()]
    for tok in self.browse(ids):
        tok._broadcast_deploy()     # set deploy_state='broadcast' + deploy_tx_hash truoc khi commit
```

`UNIQUE(chain_id, salt_hex)` là lớp chặn thứ hai: kể cả khi hai worker vượt qua khoá, lần insert thứ hai chết.

5. **Cron XML chỉ một dòng.** `<field name="code">model._cron_reserve_check()</field>` — eval context không có `fields` lẫn `relativedelta`. Ba cron của section này: `_cron_verify_deployed_code`, `_cron_broadcast_pending_deploys`, `_cron_reserve_check`.

   Bản trước liệt kê bốn, cái thứ tư là `_cron_governance_drift_check` — nó canh signer set của các Safe điều khiển upgrade, và không còn upgrade để canh (1.11.3). Nếu tổ chức muốn giữ nó như một kiểm tra vận hành trên token **của chính mình** thì được, nhưng nó không phải yêu cầu của protocol.
6. **`deploy_state` là Selection thường, không là stored computed field.** Một stored compute có nhánh không gán gì sẽ cho INSERT chết vì NULL trên cột required — bẫy đã biết của stack này.

Nhắc lại hai bẫy cũ, vì chúng sẽ quay lại:

- `_sql_constraints` dạng list bị Odoo 19 **bỏ qua hoàn toàn**; dùng `models.Constraint` như trên và **kiểm chứng bằng SQL, đừng tin code**:
  `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_token'::regclass;`
- Khoá deployer/HSM: `ir.config_parameter` giữ **`key_ref`** (tên của khoá trong HSM/KMS), không bao giờ giữ khoá. `password=True` không tồn tại ở Odoo 19 và chưa bao giờ chặn `read()`/RPC/export.

#### 1.13.3. Hướng đối soát — Odoo không phải nguồn sự thật (giả định A10)

Phải phát biểu rõ trong plan, vì nó quyết định cách viết mọi cron:

> **Chain là nguồn sự thật cho: `contract_address`, `implementation`, `totalSupply`, `reserveAccounted`, `CR`, `pegState`, danh sách role holder.
> Odoo là nguồn sự thật cho: ý định (`draft`/`predicted`), gắn kết nghiệp vụ, và lịch sử phê duyệt.**

Kết quả: mọi cron đồng bộ chạy theo hướng chain → Odoo và **ghi đè** giá trị trong Odoo. Nếu Odoo và chain lệch về một giá trị thuộc nhóm thứ nhất, chain thắng và Odoo mở một activity, không phải ngược lại. Một cron ghi chiều ngược lại ("sửa chain cho khớp Odoo") không được phép tồn tại.

Trên factory mở, nguyên tắc này còn có một hệ quả mà bản trước không cần đến: **`blockchain.token` có thể chứa token ta không tạo ra.** Một bản triển khai DMS hoàn toàn có thể muốn nhận thanh toán bằng zDAI-B của người khác. Với những record đó, Odoo không có cả "ý định" lẫn "lịch sử phê duyệt" — nó chỉ có bản chiếu của chain, cộng một quyết định nghiệp vụ là có chấp nhận token đó hay không. Trường `creator_address` tồn tại để phân biệt hai loại record này mà không cần đoán.

#### 1.13.4. Cầu (seam) nối sang `dms`

Một addon cầu `dms_blockchain_bridge` sau này sẽ map `dms.trade.settlement.line.payout_line_ids` và `dms.payment.collection` sang mint/burn, và `dms.incentive.rule.line` sang `ISSUER_NATIVE`. `dms_blockchain` không biết tên nào trong số đó, và không được `import` chúng. Cách kiểm chứng ràng buộc này không bị vi phạm theo thời gian: một CI grep

```bash
grep -rnE "\bdms\.[a-z_]+\b|from odoo.addons.dms\b" dms_blockchain/ && exit 1
```

và một test cài `dms_blockchain` trên một database **không có** `dms`.

### 1.14. Bố cục `smartcontracts/` (ngoài addon, ở gốc repo)

```
smartcontracts/
├── foundry.toml
├── src/
│   ├── common/{IOpenFactory.sol,MetaTxLib.sol,FeePolicy.sol,SigLib.sol}
│   ├── factory/{OpenFactory.sol}                      # CREATE2 + catalogue, BAT BIEN
│   ├── metatx/{IERC20MetaTx.sol,IERC20Payment.sol}
│   ├── token/{ZTokenBase.sol,ZTokenOpen.sol,ZTokenPermissioned.sol,
│   │          IssuerNativeToken.sol,WrappedToken.sol,PeggedToken.sol}
│   ├── peg/{ReserveVault.sol,SignedRateSource.sol,PegController.sol,
│   │        ReserveAttestation.sol,RecoveryVault.sol}
│   ├── migration/{MigrationSink.sol}                  # TokenKind.MIGRATION — xem 1.17.2
│   ├── zether/{IZetherToken.sol,IZetherVerifier.sol,ITransferDisclosure.sol,
│   │           ZetherAccountRegistry.sol,ZetherTypes.sol}
│   ├── verifier/{BulletproofVerifierBn254.sol,BulletproofVerifierBls12381.sol}
│   └── chains/{private7622,gnosis,celo}/              # cau hinh + script deploy theo chain
├── test/
│   ├── invariant/{WrapInvariant.t.sol,PegInvariant.t.sol,SupplyInvariant.t.sol,
│   │              ConfidentialInvariant.t.sol,ImmutabilityInvariant.t.sol}
│   ├── catalogue/{AppendOnly.t.sol,UnsupportedVerifier.t.sol}
│   └── fork/{UsdtGnosisFork.t.sol,UsdcCeloFork.t.sol}
└── script/{Deploy.s.sol,PredictAddress.s.sol,RegisterVersion.s.sol}
```

**Bốn thay đổi so với bản trước**, tất cả là hệ quả trực tiếp của 1.3 và 1.5:

| Cũ | Mới |
|---|---|
| `proxy/{DmsBeaconProxy,PinnedProxy,DmsUpgradeableBeacon}` | **xoá cả thư mục.** Clone EIP-1167 là 45 byte bytecode, không cần một file Solidity |
| `governance/{DmsTimelock,Guardian}` | **xoá `DmsTimelock`** — không có upgrade để trễ (1.11.1). `Guardian` chuyển vào `token/` vì `pause` là chuyện của từng token |
| `storage-layouts/v1/*.json` | **xoá.** Không có implementation thứ hai để mà lệch layout (1.3.5) |
| `factory/ContractPrototypeRegistry.sol` | gộp vào `factory/OpenFactory.sol` — catalogue và CREATE2 là một contract, và nó bất biến |

Và ba thứ **mới**, tương ứng ba quyết định mới:

- `verifier/` có **hai** verifier, một cho mỗi curve. Chúng không chia sẻ code (scalar field khác nhau), chỉ chia sẻ interface `IZetherVerifier`. Đây là chỗ chi phí audit tăng gấp đôi, và nó là chi phí đã biết của việc hỗ trợ cả hai curve.
- `migration/MigrationSink.sol` lên hạng nhất, không còn là phụ lục (1.17.2).
- `test/catalogue/` với hai test chặn hai bất biến mà cả hệ thống dựa vào: append-only, và từ chối verifier không chạy được trên chain hiện tại.

#### 1.14.1. `foundry.toml` — ba dòng quyết định tính tái lập

```toml
[profile.default]
solc_version   = "0.8.28"     # PIN. Doi minor version doi bytecode doi dia chi CREATE2.
bytecode_hash  = "none"       # BAT BUOC: mac dinh solc gan IPFS metadata hash vao cuoi bytecode
cbor_metadata  = false        # BAT BUOC: bo not phan metadata CBOR con lai
optimizer      = true
optimizer_runs = 200          # PIN. Doi con so nay doi bytecode doi dia chi.
via_ir         = true         # struct MetaTransaction nhieu truong => stack too deep neu khong bat
evm_version    = "cancun"     # doi chieu voi tung chain — xem profile rieng ben duoi

[profile.private7622]
evm_version    = "berlin"     # chain Nethermind private chay TRUOC London. Xem TRAPS.md
```

Không có `bytecode_hash = "none"`, cùng một source build trên hai máy CI cho hai `init_code` khác nhau, hai địa chỉ CREATE2 khác nhau, và toàn bộ mục 1.4 sụp đổ. Đây là giả định A3, và nó là một dòng config.

`evm_version` phải khớp chính xác với chain. Bản trước viết câu này như một cảnh báo giả định; **giờ nó là một sự thật đã đo được**: chain private 9000 chạy trước London — genesis khai `londonBlock: 0` nhưng Nethermind dùng chainspec riêng và bỏ qua key kiểu Geth **trong im lặng**. Build với `evm_version = "cancun"` sinh `PUSH0` (Shanghai) và chain không hiểu opcode đó. Đó là lý do có profile riêng, không phải một sự cẩn thận thừa.

#### 1.14.2. CI gate (fail build, không phải warning)

1. `forge test` + `forge coverage` >= 90% trên `src/token`, `src/peg`, `src/factory`;
2. `forge build --sizes` fail nếu bất kỳ contract nào > 24.000 byte (lề an toàn 576 byte dưới EIP-170); riêng `init_code` phải < 49.152 byte (EIP-3860);
3. `slither` — **bỏ `slither-check-upgradeability`**, không còn upgrade để kiểm;
4. **~~OZ `validateUpgrade` đối chiếu `storage-layouts/v<N-1>/`~~ — xoá.** Thay bằng **test bất biến**: sau deploy, không call nào từ bất kỳ địa chỉ nào (creator, factory owner, chính token) đổi được `implementation()`. Quét cả selector `upgradeTo` / `upgradeToAndCall` / `setImplementation`;
5. một job riêng chạy các invariant ở mục 1.9 với 50.000 run, `depth = 64`;
6. **fork test** trên Gnosis và Celo mainnet fork với **địa chỉ USDT/USDC thật**, không với mock. Một mock ERC-20 không có fee-on-transfer, không có blacklist, và không thiếu return value — tức là nó không thu được bất kỳ cái bẫy nào ở 1.6.1;
7. **determinism gate**: build hai lần trong hai container sạch, `diff` `keccak256(init_code)`. Khác nhau = fail. Đây là CI test duy nhất bảo vệ mục 1.4;
8. `PredictAddress.s.sol` chạy trên mọi chain trong `blockchain.chain` và so kết quả với `blockchain.token.predicted_address` đã lưu; lệch = fail.

Và **ba gate mới**, mỗi cái chặn một bất biến mà thiết kế mới dựa vào:

9. **Catalogue append-only**: `registerImplementation(kind, v, X)` rồi `registerImplementation(kind, v, Y)` phải revert (1.5.1 mục 1).
10. **`isSupportedOnThisChain()` bắt được chain thiếu precompile**: fork chain 9000 (hoặc `vm.etch` xoá `0x0b`), verifier BLS phải trả `false` và `createZetherToken` phải revert. **Đây là gate có giá trị nhất trong ba cái** — nó là cái bẫy im lặng duy nhất còn lại có thể làm mất tiền của người lạ, vì precompile vắng mặt không revert mà trả về thành công với output rỗng.
11. **Ma trận CI hai curve**: mọi test Zether chạy hai lần, bn254 và BLS12-381, và khẳng định `g1EncodedBytes()` là 64 với cái này, 128 với cái kia. Nhầm curve trong payload phải revert chứ không được verify sai.

---

### 1.15. Ba use case → archetype → profile — bảng quyết định

Khoá quyết định #3 đưa cả ba use case vào phạm vi. Bản nháp không ánh xạ chúng. Đây là bảng quyết định, và nó là thứ đội trực cần khi một yêu cầu nghiệp vụ mới đến:

| Use case | Archetype | Token class | Profile khởi điểm | Peg mode | Đổi ra tiền pháp định? | Pause/Freeze | Rủi ro pháp lý chính |
|---|---|---|---|---|---|---|---|
| **Loyalty / reward point** | `ISSUER_NATIVE` | `ZTokenOpen` | public (Gnosis) hoặc private | `FIXED_RATE`, rate không giảm | **Không.** Chỉ đổi hàng/chiết khấu | `pause` 7 ngày. Không `freeze` | Thấp. Không redeem tiền = khó bị coi là phương tiện thanh toán |
| **B2B settlement (brand → distributor)** | `PEG_RATIO` (Z-VND) hoặc `WRAP_1_1` (Z-USDT) | `ZTokenPermissioned` | **private trước** | `FIXED_RATE`, reserve VND | Có, hàng đợi T+1 | `pause` + `freeze` theo lệnh toà | Cao. §13 |
| **Thanh toán người dùng cuối** | `WRAP_1_1` của một token e-money đã có giấy phép, HOẶC `PEG_RATIO` Z-VND | tuỳ giấy phép | public sau khi có giấy phép | theo giấy phép | Có | theo giấy phép | Cao nhất |

Ba hệ quả điều hướng kế hoạch:

1. **Loyalty đi trước**, không phải vì nó dễ nhất kỹ thuật mà vì nó là use case duy nhất không phụ thuộc một kết luận pháp lý còn treo. `ISSUER_NATIVE` + `ZTokenOpen` có thể deploy và chạy thật trong wave 1.
2. **B2B settlement cần Zether và cần private chain**, và con số ở 1.12.2 nói rõ tại sao: 45 tx/s trên private chain là đủ cho B2B, 0,45 tx/s trên Gnosis thì không.
3. **Thanh toán người dùng cuối không thể chạy trên Zether ở quy mô** với Bulletproofs. Nếu use case đó thật sự được theo đuổi, nó bắt buộc kéo theo lựa chọn Groth16 ở 1.12.1 hoặc bỏ confidentiality ở luồng đó. Trên factory mở, "kéo theo" nhẹ hơn trước: đó là một `ZETHER v2` mới trong catalogue, không phải một cuộc cải tổ.

**Lưu ý về phạm vi của bảng này.** Nó mô tả các use case **của bản triển khai DMS**, không phải giới hạn của protocol. Factory mở nghĩa là ai cũng có thể tạo một token cho use case ta chưa nghĩ tới, và bảng này không nói gì về việc đó — nó là tài liệu nội bộ để chọn archetype, không phải một danh sách được phép.

---

### 1.16. Chain profile ở tầng token — private chain là chain nào

Bản trước viết mục này quanh một stack giả định: **Hyperledger Besu + QBFT**, 4 validator, gasLimit 200M, block 2s. **Chain private thật thì khác, và nó đã tồn tại, đang chạy** — `/home/dockers/mba-chain-nethermind`. Bảng dưới là tham số thật, không phải đề xuất:

| Tham số | Giá trị thật (đã đo) | Vì sao token design quan tâm |
|---|---|---|
| Client | **Nethermind**, không phải Besu | Chainspec khác cú pháp genesis Geth — xem cảnh báo dưới |
| Consensus | **Clique**, không phải QBFT | Clique **không** có instant finality như QBFT. Xem phần finality |
| chainId | 9000 (`0x2328`) | — |
| `period` | 5 s | Mẫu số của con số thông lượng ở 1.12.2 |
| `gaslimit` | `0x1000000` = **16.777.216** | 8 Zether tx/block, y hệt Gnosis. Nâng được bằng signer vote, **không cần reset chain** |
| Gas price | `MinGasPrice = 0` | Hiện thực hoá khoá quyết định #5 |
| Số signer | **1** | Xem câu treo ở cuối mục |
| EVM fork thực tế | **trước London** | Không EIP-1559, không EIP-2537. Build với `FOUNDRY_PROFILE=private7622` |
| `contractSizeLimit` | giữ 24576 | Không nới lỏng. Nới lỏng thì public build và private build phân nhánh, và ta có hai codebase để audit |

**Cảnh báo, và nó là loại bẫy im lặng tệ nhất:** genesis khai `londonBlock: 0`, `cancunBlock: 0`, `pragueBlock: 0`. **Không key nào có tác dụng.** Nethermind đọc chainspec riêng và bỏ qua key kiểu Geth mà không log gì. Cách duy nhất phát hiện là kiểm block header (`baseFeePerGas` vắng mặt) hoặc gọi thử precompile. Chi tiết ở `TRAPS.md` §"Private chain".

Hệ quả trực tiếp lên token design: **BLS12-381 không dùng được trên chain này**, nên một `createZetherToken` với verifier BLS phải bị chặn ở `isSupportedOnThisChain()` (1.14.2 gate 10) chứ không được deploy thành một cái brick.

**Finality: Clique không phải QBFT, và điều này đổi một kết luận.** Bản trước viết *"QBFT có instant finality (một block đã vote là final), nên `finality_hard_blocks = 1`"*. Clique thì không: nó là proof-of-authority theo lượt, và một chain Clique **một signer** không có finality theo nghĩa BFT nào cả — nó có đúng cái đảm bảo mà signer đó đưa ra. Đặt `finality_hard_blocks` theo một con số bảo thủ và ghi rõ cơ sở, đừng chép `= 1` từ một stack khác.

Nguyên tắc `dms_vietqr` vẫn áp dụng, chỉ là ngưỡng khác.

**Câu còn treo, và giờ nó gắt hơn:** bản trước hỏi *"ai chạy 4 validator đó?"* và cảnh báo rằng nếu cả 4 là của ta thì "permissioned blockchain" về mặt kỹ thuật là một database Postgres đắt tiền có chữ ký. Chain thật có **một** signer. Điều đó không sai — nó vẫn cho immutability, audit trail, và Zether — nhưng phải gọi đúng tên trong tài liệu bán hàng, và nó là một lý do độc lập để đường lên public tồn tại trong lộ trình. Xem 1.19.

### 1.17. Vòng đời đầy đủ: runbook deploy, migrate, retire

#### 1.17.1. Deploy (16 bước, tương ứng state machine ở 1.2)

| # | Bước | Actor | State sau bước |
|---|---|---|---|
| 1 | Tạo `blockchain.token`, chọn archetype + **version** + chain | Nghiệp vụ | `draft` |
| 2 | Kiểm `version.profileHint` so với `chain.chain_profile` — **cảnh báo, không chặn** (1.5) | Hệ thống | `draft` |
| 3 | Kiểm `max_supply_base <= 2^44` | Hệ thống | `draft` |
| 4 | Sinh `initData`, tính `keccak256(initData)`, dựng `salt` (1.4.3) | Hệ thống | `draft` |
| 5 | Gọi `factory.predictAddress()`, lưu `predicted_address` | Hệ thống | `predicted` |
| 6 | Phê duyệt (Safe 3-of-5 nếu `PEG_RATIO`, tự động nếu `ISSUER_NATIVE` loyalty) | Người | `predicted` |
| 7 | `_cron_broadcast_pending_deploys` khoá record (`FOR UPDATE SKIP LOCKED`) | Cron | `predicted` |
| 8 | Broadcast `factory.createZetherToken(version, ...)` hoặc `createMetaToken(...)` | HSM key | `broadcast` |
| 9 | Nhận tx hash, lưu `deploy_tx_hash`, commit **trước** khi làm gì khác | Hệ thống | `broadcast` |
| 10 | Receipt `status == 1` | Indexer | `pending_finality` |
| 11 | Đạt `finality_hard_blocks` của chain | Indexer | `pending_finality` |
| 12 | So `EXTCODEHASH` với `version.expected_proxy_code_hash` | Cron | `verified` hoặc `mismatch` |
| 13 | So `token.implementation()` với `version.impl_address` | Cron | `verified` hoặc `mismatch` |
| 14 | So `token.creator()` với `creator_address` kỳ vọng | Cron | `verified` hoặc `mismatch` |
| 15 | Verify source trên Blockscout/explorer (chain public) | CI | `verified` |
| 16 | Set `live`; từ đây `blockchain_list_tokens` mới trả về token này | Hệ thống | `live` |

Ba bước đổi so với bản trước: bước 2 hạ từ chặn xuống cảnh báo (1.5), bước 13 so `implementation()` thay vì `beacon()`, và bước 14 so `creator()` thay vì `owner()` — trên factory mở, thứ phải khớp là người tạo, và với token bất biến thì `creator()` là hằng số chứ không phải một vai trò chuyển được.

Bước 9 là bước dễ sai nhất: nếu broadcast xong mà chưa commit tx hash đã có exception, record về `predicted` và cron sẽ broadcast lần hai. `UNIQUE(chain_id, salt_hex)` không cứu được vì salt giống nhau và `CREATE2` lần hai revert — nhưng ta mất một lần gas và có một tx thất bại trong sổ sách. Commit ngay sau khi có tx hash.

#### 1.17.2. Migrate — ĐƯỜNG DUY NHẤT, không còn là phương án dự phòng

Bản trước đặt tên mục này là *"Migrate (khi upgrade không đủ)"* và liệt kê những gì upgrade không giải quyết được: đổi storage layout không tương thích, đổi decimals, đổi archetype, đổi chain.

**Bỏ upgrade thì danh sách đó thành: mọi thứ.** Một lỗi logic tầm thường — thứ trước đây vá bằng một `upgradeTo` — giờ cũng phải đi qua migration. `MigrationSink` không còn là phụ lục; nó là một entry catalogue hạng nhất (`TokenKind.MIGRATION`), phải có trong v1, và phải được audit cùng đợt với token.

```solidity
contract MigrationSink {
    IERC20Burnable public immutable oldToken;
    IERC20Mintable public immutable newToken;
    uint256 public immutable ratioNum;     // thuong 1:1
    uint256 public immutable ratioDen;
    uint64  public immutable deadline;     // sau moc nay, phan chua doi ve RecoveryVault

    function migrate(uint256 amount) external {
        oldToken.burnFrom(msg.sender, amount);
        newToken.mint(msg.sender, Math.mulDiv(amount, ratioNum, ratioDen));
    }
}
```

Trên factory mở, `MigrationSink` phải deploy được bởi **người tạo token**, cho token **của họ** — ta không deploy hộ ai, và ta cũng không có quyền gì trên cặp token của người khác.

Ba điều kiện bắt buộc đi kèm, không được bỏ:

- `oldToken` phải vào `WIND_DOWN` trước (mint tắt) — nếu không, tổng cung tiền của hai token cộng lại vượt `maxSupply`.
- `newToken.MINTER` cấp cho `MigrationSink` phải có `maxMintPerEpoch = oldToken.totalSupply()` và **hết hạn** sau `deadline`.
- Số dư **confidential** không migrate được bằng `burnFrom` (contract không biết nó bằng bao nhiêu). Người giữ phải `withdraw` về công khai trước. Đó là một chiến dịch truyền thông, không phải một hàm. **Cửa sổ `deadline` tối thiểu 180 ngày** vì lý do này.

**Điều kiện thứ ba là cái giá thật của việc bỏ upgrade với token Zether, và nó phải được nói thẳng ở chỗ dễ thấy:** vá một lỗi ở một Zether token nghĩa là mọi người giữ số dư bí mật phải **tự tay lộ số dư của mình ra công khai** rồi chuyển sang token mới. Không có đường nào khác — và ai không làm trong 180 ngày thì tiền của họ nằm lại ở token cũ.

Hai hệ quả điều hướng ngân sách, và chúng thuộc về mục này chứ không phải một phụ lục:

1. **Implementation Zether v1 phải được audit nặng hơn Meta Token v1.** Giá của một lỗi cao hơn hẳn, vì đường sửa đắt hơn hẳn.
2. **Mọi archetype Zether phải có một `withdraw` đơn giản, độc lập, và được audit riêng.** Nó là lối thoát duy nhất trong kịch bản xấu nhất; một `withdraw` chia sẻ bug với phần còn lại của token là một lối thoát không tồn tại.

#### 1.17.3. Retire

`retired` nghĩa là: không mint, không migrate, `RecoveryVault` đã đóng, và record Odoo giữ lại vĩnh viễn để đối soát lịch sử. Contract on-chain **không biến mất** và vẫn có thể có người cầm token. Odoo phải tiếp tục index nó (ở mức tối thiểu: log `Transfer`) trong 10 năm theo yêu cầu lưu trữ chứng từ kế toán. `active = False` trong Odoo **không** được dùng tắt indexer.

Với token bất biến, "retired" là một trạng thái **trong Odoo**, không phải trên chain. Chain không có khái niệm đó: contract vẫn ở đó, vẫn nhận call, vẫn chạy đúng như ngày đầu, mãi mãi. Đó là điều cần nói rõ với đội vận hành — họ không "tắt" được một token, họ chỉ ngừng dùng nó.

---

### 1.18. Những gì cố ý KHÔNG làm trong v1

Danh sách này tồn tại để một người đọc plan sau này không tưởng đây là thiếu sót:

| Không làm | Lý do | Thêm khi nào |
|---|---|---|
| Diamond (EIP-2535) | Tách `BulletproofVerifier` bằng `staticcall` giải quyết EIP-170 với 0,18% gas overhead | Không bao giờ, trừ khi có một yêu cầu mà facet là cách duy nhất |
| **Bất kỳ hình thức upgrade nào** | Xem 1.3. Đây là quyết định kiến trúc, không phải hoãn lại | **Không bao giờ** |
| Basket / giỏ nhiều ERC-20 | N oracle = N điểm gãy; rebalance cần một khoá có quyền bán reserve | Khi có một use case cụ thể và một người chịu trách nhiệm treasury |
| AMM TWAP oracle | Không có pool VND thanh khoản | Không bao giờ cho VND |
| Groth16 / PLONK verifier | Cần trusted setup ceremony; Bulletproofs đủ cho private chain | Khi Zether phải chạy trên public chain ở quy mô (1.12.1). Trên factory mở đây chỉ là một `ZETHER v2` mới trong catalogue |
| Anonymity set lớn trong Zether mặc định | Ring lớn làm gas ×4. **Nhưng đây là lựa chọn của người tạo token** (`ringSize()`), không phải một cấm đoán — ta chỉ không đăng ký nó vào catalogue v1 | Khi có người cần và chịu chi phí |
| CI gate cho cross-chain address parity | Parity là nice-to-have; client resolve địa chỉ qua RPC | Không |
| `WRAP_SHARES` (rebasing underlying, kiểu ERC-4626) | `WRAP_1_1` không xử lý đúng rebasing token | Khi có yêu cầu wrap stETH/aToken |
| Rate theo lô (`mapping(batchId => rate)`) | Thay bằng chính sách "rate không giảm" | Nếu chính sách đó không được chấp nhận (1.7.4) |
| Bridge private → public cho Z-VND | Một bridge là một hệ thống riêng với mô hình đe doạ riêng | §08, wave sau |

Một dòng của bản trước đã bị **sửa chứ không giữ**: *"Anonymity set trong Zether — không bao giờ (mâu thuẫn với AML)"*. Câu đó đúng khi ta là nhà phát hành và phải tuân thủ AML. Trên factory mở ta là người deploy protocol, và ring size là tham số của verifier do người tạo token chọn. Ta không đăng ký ring lớn vào catalogue v1 vì ta không cần nó — nhưng ta không cấm được, và giả vờ cấm được là mô tả sai hệ thống.

---

### 1.19. Câu hỏi còn lại cho người quyết định

Bản trước có tám câu. **Bốn câu đã rời khỏi danh sách của ta** — không phải vì có đáp án, mà vì mô hình factory mở chuyển chúng sang **người tạo token**. Chúng vẫn là câu hỏi thật, chỉ là không phải của ta, và chúng thuộc về tài liệu hướng dẫn kèm archetype (1.11.2).

Còn lại của ta:

1. **Ai chạy signer của private chain, và có thêm signer độc lập không?** Chain thật hiện có **một** signer (1.16). Nếu giữ nguyên, phải gọi đúng tên trong tài liệu: đó là một sổ cái có chữ ký, không phải một mạng phi tập trung. Đây là câu duy nhất của bản cũ còn nguyên vẹn là của ta.
2. **Ai giữ khoá registrar của catalogue, và ngưỡng bao nhiêu?** Đã hạ cấp mạnh (1.11.1): mất khoá không chặn ai deploy. Safe 2-of-3 kỹ thuật là đủ. Vẫn cần một câu trả lời để có người chịu trách nhiệm.
3. **Ngân sách audit, và phân bổ giữa Zether v1 và Meta Token v1.** Không phải một con số tổng: 1.17.2 lập luận Zether phải nặng hơn, và tỷ lệ đó cần một quyết định.
4. **`ZETHER v1` của catalogue dùng verifier nào — bn254, BLS12-381, hay cả hai?** Cả hai đều đăng ký được. Câu hỏi thật là ta audit và đứng sau cái nào trước, vì đó là thứ tốn tiền. Chain private chỉ chạy được bn254 (1.16).

Bốn câu **chuyển sang người tạo token**, giữ lại đây làm tham chiếu chéo:

| Câu | Thuộc về ai bây giờ |
|---|---|
| Z-VND có đổi ra tiền pháp định được không? | Người phát hành Z-VND. Với ta nó chỉ đổi archetype nào ta dùng, không đổi protocol |
| `decimals` của Z-VND: 2 hay 0? | Người tạo token đó, ở `initialize()`. Khuyến nghị 2 (1.8) |
| Trần cung tiền (`maxSupply`) là bao nhiêu? | Như trên. Ràng buộc kỹ thuật `<= 2^44` thì protocol enforce |
| Chấp nhận `MAX_PAUSE = 7 ngày`, lối thoát duy nhất là `WIND_DOWN`? | Người tạo token, và nó thể hiện ra bằng việc họ chọn version nào |

Hai câu **không đi đâu cả, chỉ đổi chủ thể**: ai ký reserve attestation và với ngân sách nào (1.7.7), và nếu quy định đòi tịch thu thì chọn đường nào (1.10.3). Cả hai là câu hỏi của bất kỳ ai phát hành một token có reserve — kể cả ta, nếu ta phát hành.

### 1.20. Kiểm chứng bắt buộc — không tin code, tin chain và `pg_constraint`

Chín lệnh, chạy trước khi bất kỳ ai nói "xong":

```bash
# 1. Constraint co that su ton tai trong Postgres khong (Odoo 19 bo qua _sql_constraints dang list)
psql -c "SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_token'::regclass;"

# 2. Deterministic deployer co tren chain khong
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url $RPC

# 3. Build hai lan trong hai container sach, init_code hash phai giong het
docker run --rm -v $PWD:/w -w /w/smartcontracts foundry forge build && \
  cast keccak $(jq -r '.bytecode.object' out/OpenFactory.sol/OpenFactory.json)

# 4. Dia chi du doan trong Odoo khop dia chi tinh tu chain
forge script script/PredictAddress.s.sol --rpc-url $RPC --sig "run(bytes32)" $SALT

# 5. Code that su nam o dia chi do (chan A4 va metamorphic)
cast keccak $(cast code $TOKEN --rpc-url $RPC)

# 6. Token BAT BIEN: implementation() la mot hang so, va khong co selector upgrade nao
cast call $TOKEN "implementation()(address)" --rpc-url $RPC
cast code $TOKEN --rpc-url $RPC | grep -qiE '3659cfe6|4f1ef286' && echo "FAIL: co selector upgradeTo"

# 7. Kich thuoc contract duoi 24,000 byte tren MOI contract
forge build --sizes | awk '$3 > 24000 {print; found=1} END {exit found}'

# 8. Chain co dung fork nhu genesis khai khong (Nethermind bo qua key kieu Geth trong im lang)
cast block latest --rpc-url $RPC --json | jq -e '.baseFeePerGas' || echo "PRE-LONDON"
cast call 0x000000000000000000000000000000000000000b $BLS_G1ADD_INPUT --rpc-url $RPC

# 9. Addon cai duoc tren database khong co dms
odoo -d test_no_dms -i dms_blockchain --stop-after-init --test-enable
```

**Lệnh 6 và 8 là hai lệnh mới, và cả hai kiểm một điều mà tài liệu không kiểm được.**

Lệnh 6 kiểm bất biến của token bằng cách quét bytecode tìm selector `upgradeTo(address)` = `0x3659cfe6` và `upgradeToAndCall(address,bytes)` = `0x4f1ef286`. Một clone EIP-1167 là 45 byte và không thể chứa chúng — nên lệnh này gần như luôn pass, và đó chính là lý do chạy nó: nó phát hiện ngày mà ai đó vô tình deploy một proxy khác dưới cùng một quy trình.

Lệnh 9 vẫn là lệnh quan trọng nhất trong section này: khoá quyết định #7 (`dms_blockchain` độc lập) là thứ dễ vi phạm nhất và dễ phát hiện nhất, và nó chỉ được đảm bảo bởi một lệnh chạy trong CI, không bởi một dòng trong tài liệu này.

---

## 1.17. Cập Nhật Chuẩn Tắc V3: Phân Loại Kiểm Soát Token & Open Asset Tokenization Suite

*(Chi tiết đầy đủ xem `SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md` §2 và `ai-enterprise-blockchain-architecture.md` §3.5–§3.7)*

### 1.17.1. Phân Loại Kiểm Soát Cấp Giao Thức (Token Control Classification)
Hợp đồng do Open Factory triển khai được phân thành 2 nhóm kiểm soát độc lập:
1. **Token Không Kiểm Soát (Uncontrolled / Permissionless Tokens):**
   - Mã nguồn bất biến hoàn toàn, không có backdoor, không chủ sở hữu có quyền đóng băng hay can thiệp số dư (ví dụ: utility token, wrapped native coins).
2. **Token Có Kiểm Soát Pháp Lý (Controlled / Regulated Tokens — `IRegulatedToken`):**
   - Dành cho Tiền kỹ thuật số Ngân hàng Trung ương (CBDC), Stablecoin pháp định tuân thủ, Cổ phiếu/Trái phiếu số hóa doanh nghiệp.
   - Hỗ trợ các hàm can thiệp tư pháp: `freezeAccount(address, bytes32 courtRulingId)`, `unfreezeAccount(address, bytes32 courtRulingId)`, `judicialForceTransfer(address from, address to, uint256 amount, bytes32 courtRulingId)`, `courtOrderBurn(address, uint256 amount, bytes32 courtRulingId)`.
   - **Chốt chặn an toàn:** Bắt buộc có tham số `bytes32 courtRulingId` trỏ về bản án của Tòa án và thực thi qua **Multi-Sig Quorum 3-of-5** (Pháp chế, CFO, Kiểm toán nội bộ, Cơ quan quản lý).

### 1.17.2. Bộ Công Cụ Token Hóa Mở (Open Asset Tokenization Suite)
Cung cấp Configurator Wizard trực tiếp trong Odoo 19 cho phép doanh nghiệp tự do phát hành các loại tài sản số, tài sản ảo và RWA trên nền tảng `IOpenFactory` dùng chung logic bytecode, đảm bảo phân lập dữ liệu tuyệt đối và tiết kiệm 95% chi phí triển khai.