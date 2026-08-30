# Quyết định của user + phát hiện từ code thật

Chốt trong phiên brainstorming 2026-08-30. **Đây là nguồn có thẩm quyền cao nhất**,
cao hơn `blockchain.md` và cao hơn mọi suy đoán của agent. Không tranh luận lại.


---

## 0. Cách đọc tham chiếu `§` — BẢNG TRA

Bộ tài liệu này trộn hai kiểu đánh số và trước đây không nói ra ở đâu cả. Bảng tra:

| Viết `§...` | Là file nào | Ví dụ |
|---|---|---|
| `§00`–`§16` | file spec cùng số: `00-CANON.md` … `16-decomposition-roadmap.md` | `§06.1` = mục 6.1 trong `06-relay-pool-enterprise.md` |
| `§1.x` … `§16.x` (một chữ số đầu) | vẫn là file spec đó | `§3.5.4` = `03-zether-crypto.md` mục 3.5.4 |
| **`§17`–`§23`** | **`_USER-DECISIONS.md`** (file này) — nó tiếp tục dãy số sau 16 | `§21.2` = mục 21.2 **trong file này** |
| `§C…` | `00-CANON.md`, phần đánh số canon | `§C5.1` = canon mục C5.1 |
| `D1`–`D17` | bảng quyết định cần người chốt, ở `00-CANON.md` cuối file | `D8` = dòng D8 của bảng đó |
| `locked #1`–`#9` | chín quyết định user khoá, ở `§1`–`§9` của file này | `locked #5` = §5 file này |
| `A1`–`A13` | bảng đối thủ ở `12-threat-model.md` §12.0.3 | `A5` = kẻ chiếm app server |
| `P01`–`P23`, `S0`–`S9`, `M0` | sub-project / spike / milestone ở `16-decomposition-roadmap.md` | `P10` = Zether core Rust |

**Chỗ dễ nhầm nhất, và là lý do bảng này tồn tại:** `§21`, `§22`, `§23` **không** phải file
`21-*.md` — không có file nào như thế. Chúng nằm trong `_USER-DECISIONS.md`, và chúng tiếp
dãy số sau `16-decomposition-roadmap.md` vì chúng là quyết định ra sau khi 16 section đã viết xong.

**Quy ước khi viết mới:** tham chiếu sang file khác thì **ghi tên file**, ví dụ
`_USER-DECISIONS.md §21.2` hoặc `06-relay-pool-enterprise.md §06.1`. Chỉ dùng `§` trần khi
tham chiếu trong cùng một file.

## 1. Phạm vi và định hướng

| | |
|---|---|
| Use case | Cả ba: loyalty/reward, B2B settlement (hãng↔NPP), end-user payment |
| Trọng tâm | MetaTransaction + Zether + stablecoin. *"Đi trước thời đại."* |
| EIP-1776 | **Dùng.** User: *"1776 chưa là standard vì đội ETH thiếu tầm nhìn. Chúng ta sử dụng."* Không đề xuất ERC-4337 thay thế. |
| Chain đầu tiên | Gnosis xDAI → Celo. 5 hệ sinh thái còn lại thiết kế trên giấy |
| Private chain | Trong scope, và **đi trước** cho Zether. Gas cho Zether do đó không phải ràng buộc chặn |
| Custody | **Pluggable, hỗ trợ tất cả**, chọn lúc deploy. User: *"Support tất cả. Việc này tùy thuộc vào khi deploy."* |
| `dms_blockchain` | **Độc lập hoàn toàn, KHÔNG depends vào `dms`.** User nhắc lại hai lần |
| Payment mode | **Option cấu hình**, chọn 1/4/5..., không hard-code |
| `smartcontracts/` | Cây riêng ở repo root, ngoài addon, chia theo chain và mục đích |
| Pháp lý | Để sau. Viết thành chương riêng, không chặn phần build được |

## 2. Token: decimals, scale, trần giải mã

**Quyết định: dynamic có default.**

Tách làm ba con số độc lập, đừng gộp:

| Tham số | Nghĩa | Chọn theo |
|---|---|---|
| `decimals` | mặt ERC-20 công khai | **khớp underlying** (18 cho Z-ETH, 6 cho Z-USDC/Z-VND) |
| `SHIELD_SCALE` | bao nhiêu raw unit = 1 đơn vị che giấu | sao cho `maxSupply / SHIELD_SCALE <= MAX_DECRYPTABLE_SHIELDED` |
| `MAX_DECRYPTABLE_SHIELDED` | trần BSGS khi khôi phục nguội | theo client yếu nhất phải khôi phục được ví |

Bất biến enforce trong `initialize()`, không có setter:

```
maxSupply / SHIELD_SCALE <= MAX_DECRYPTABLE_SHIELDED
```

Default: `decimals = 6`, `MAX_DECRYPTABLE_SHIELDED = 2^44`.

Ví dụ đã tính:

| Token | decimals | SHIELD_SCALE | 1 đơn vị che giấu | Trần cung |
|---|---|---|---|---|
| Z-ETH | 18 | 10^12 | 10^-6 ETH | 17,6 triệu ETH |
| Z-USDC | 6 | 1 | 10^-6 USDC | 17,6 triệu USDC |
| Z-VND | 6 | 10^6 | 1 VND | 17,6 nghìn tỷ VND |

**Vì sao trần giải mã tồn tại** (điểm tinh tế, tài liệu gốc nói sai):
ElGamal ở đây là dạng exponential/lifted — số dư mã hoá là `g^b`. Khoá bí mật `x`
chỉ bóc được lớp che: `C / D^x = g^b`. Đi từ `g^b` về `b` là **discrete log**, khoá
không giúp gì. BSGS tốn `O(sqrt(b))` theo raw unit.

`rollOver()` và `simulateAccounts()` **không** giải mã — cả hai trả về ciphertext
`(C, D)`. Contract không bao giờ có `x`.

Trần này chỉ cắn ở **khôi phục nguội**. Vận hành thường ngày client biết `b_cũ` nên
chỉ BSGS phần chênh lệch `g^{b_mới}/g^{b_cũ} = g^Δ`, rẻ bất kể decimals.

Đường cong đánh đổi (ước tính, 32 B/điểm, ~250 ns/bước, native):

| k | bảng | native | WASM (~4x) |
|---|---|---|---|
| 2^40 | 34 MB | 0,26 s | ~1 s |
| **2^44** | **134 MB** | **1,05 s** | **~4 s** |
| 2^48 | 537 MB | 4,2 s | ~17 s |
| 2^52 | 2,1 GB | 17 s | ~67 s |

`2^44` là bậc cuối bảng còn vừa thiết bị di động. Chặn `2^48` là **bộ nhớ**, không
phải thời gian. Pollard kangaroo gỡ được bức tường bộ nhớ với giá 2-4x thời gian.

Tăng `SHIELD_SCALE` **rẻ hơn** mua thêm bit, và chỉ trả bằng độ mịn.

## 3. Mô hình phí: LINH ĐỘNG cho public, BẮT BUỘC FIXED cho Zether

User chốt: *"Fee linh động, có thể = 0, có thể theo %, có thể fix. Riêng zether,
bản chất là số tiền ẩn, nên fee phải fix."*

### 3.1 Ba chế độ phí cho chuyển khoản CÔNG KHAI

```solidity
enum FeeMode { NONE, PERCENT, FIXED }
```

| Mode | Nghĩa | Ràng buộc |
|---|---|---|
| `NONE` | `feeAmount = 0`, `feeRecipient = address(0)` | miễn phí |
| `PERCENT` | `feeAmount = amount * feePpm / 1e6` | mẫu số **1e6 ppm**, trần **1% = 10000 ppm** |
| `FIXED` | `feeAmount` tuyệt đối theo đơn vị token | vẫn chịu trần 1% của `amount` |

`feeRecipient` do **người gửi** chỉ định trong cả ba mode — nhưng thường là điền theo giá trị mà
relayer công bố ở `/policy`, không phải người gửi tự nghĩ ra. Và `address(0)` là một giá trị hợp lệ
có nghĩa "trả cho `msg.sender`". Xem §21.5: `feeRecipient` cố định là cấu hình **tự nhiên** của một
relayer có pool khoá ký, không phải một vấn đề.

### 3.2 Zether: PHÍ BẮT BUỘC LÀ FIXED. Đây là ràng buộc bảo mật, không phải tuỳ chọn

Lý do, và nó dứt khoát:

Phí Zether **bắt buộc công khai** — `ZSC.sol` cộng `g^fee` dạng plaintext vào
pending của beneficiary, và nó phải công khai để Open Relayer thẩm định được lợi
nhuận trước khi nhận việc. Nếu phí cũng bị mã hoá thì relayer không biết có lãi
hay không, và mạng mở sụp (xem §6).

Nhưng số tiền chuyển `v` thì **bí mật**. Nếu phí tính theo phần trăm:

```
fee = v * p        →  v = fee / p
```

`fee` công khai, `p` công khai ⇒ **`v` lộ hoàn toàn**. Toàn bộ Zether trở nên vô
nghĩa: bỏ hàng triệu gas cho Bulletproofs để giấu một con số mà chính dòng phí bên
cạnh nó tiết lộ.

Nên với `transferConfidential`:

- **`FeeMode.PERCENT` bị CẤM ở tầng contract**, không phải chỉ khuyến nghị. Contract
  phải `require` mode là `NONE` hoặc `FIXED`.
- Phí lấy từ **bảng giá theo `(token, chain)`**, độc lập hoàn toàn với `v`.

### 3.3 Bẫy hạng hai: bảng phí phân bậc cũng rò rỉ

Một biểu phí "phân bậc" — giao dịch lớn phí cao hơn — **tái lập rò rỉ ở độ hạt thô
hơn**. Thấy `fee = 50.000 ₫` là biết `v` nằm trong bậc đó. Với ba bậc thì mỗi giao
dịch lộ ~1,6 bit về số tiền, và cộng dồn qua nhiều giao dịch thì đủ dựng lại hồ sơ.

Quy tắc: **phí Zether không được là hàm của `v` dưới bất kỳ dạng nào** — không phần
trăm, không bậc thang, không trần phụ thuộc số tiền. Chỉ một hằng số cho mỗi cặp
`(token, chain)`, đổi bằng governance, không đổi theo từng giao dịch.

Hệ quả kinh tế phải chấp nhận: phí cố định nghĩa là chuyển khoản nhỏ chịu tỉ lệ phí
cao. Đó là **cái giá của bảo mật**, và nó đúng — vì chi phí thật của relayer cũng
là cố định (gas cho một `transferConfidential` gần như không phụ thuộc `v`). Phí cố
định thực ra **khớp chi phí thật hơn** phí phần trăm.

### 3.4 Hai tầng phí, hai mode khác nhau

Nối với §10 (Zether là child của MetaTransaction):

| Tầng | Mode cho phép | Trả bằng | Người nhận |
|---|---|---|---|
| Ngoài (MetaTx) trên token công khai | `NONE` / `PERCENT` / `FIXED` | ERC-20 công khai | `address` |
| Ngoài (MetaTx) bọc `transferConfidential` | `NONE` / `FIXED` | ERC-20 công khai | `address` |
| Trong (Zether) | `NONE` / `FIXED` — **`PERCENT` bị cấm** | số dư ElGamal | `bytes32` UA |

Hàng giữa cũng cấm `PERCENT`: nếu phí tầng ngoài tính theo phần trăm của một
`amount` mà `amount = 0` (vì giá trị thật nằm trong payload bí mật) thì phí ra 0 —
vô nghĩa; còn nếu ai đó tính theo giá trị bí mật thì lại rò rỉ. Bọc Zether thì phí
tầng ngoài chỉ được là hằng số.

### 3.4b `fee = 0` hợp lệ, và mạng mở VẪN nhận — qua acceptance policy

User sửa lại: *"Relayer mở nhưng được cấu hình ưu tiên các contract đặc biệt của
đối tác, nên fee vẫn có thể bằng 0."*

Đúng, và đây là điểm tôi đã khoanh hẹp sai. **"Mở" nói về ai được tham gia, không
có nghĩa mọi node phải nhận mọi việc.** Mỗi relayer tự đặt **acceptance policy** của
mình, và một node hoàn toàn có thể nhận `fee = 0` cho những contract nó có quan hệ
đối tác — được trả tiền ngoài chuỗi, hoặc từ escrow của issuer, hoặc vì chính nó là
bên hưởng lợi từ giao dịch đó.

Nên **không lọc `fee = 0` khỏi mesh**. Intent phí 0 vẫn gossip bình thường; nó chỉ
đơn giản là không sinh lời cho relayer thị trường tự do, và sinh lời cho relayer
đối tác. Bốn đường đi được, không phải ba:

| Đường | Ai trả gas | Cơ chế |
|---|---|---|
| **Gọi trực tiếp** | user | user có native coin |
| **Relay pool nội bộ** | doanh nghiệp | HSM gas station, `MODE_RESTRICT_RELAYER` |
| **Issuer sponsorship** | bên phát hành | escrow on-chain |
| **Relayer đối tác trên mesh mở** | relayer, thu hồi ngoài chuỗi | **acceptance policy** ưu tiên contract đối tác |

### 3.5 Dọn tàn dư

Bỏ `txGas / baseGas / tokenGasPrice` trong `IERC20MetaTx` — mô hình đo gas kiểu GSN,
không dùng. Đổi `setTransferFeePerMille` (1e3) → `setTransferFeePpm` (1e6).

## 4. Chữ ký: EIP-712, không phải personal_sign

Thiết kế Grok dùng `wallet._signTypedData(domain, types, data)` = **EIP-712**.
Code đã commit dùng `toEthSignedMessageHash()` = `personal_sign`. **Bản thiết kế
đúng hơn bản code.** Lấy EIP-712 để ví hiển thị được nội dung thay vì 32 byte mù.

Bỏ `SignatureValidator.verifySignature2` — `ecrecover` thô, không chặn
malleability của `s`. Hiện chưa dùng nhưng là súng đã lên đạn.

## 5. Ràng buộc relayer: dùng wildcard, KHÔNG dùng mode bitmask

Code thật: `require(trade.relayer == address(0) || trade.relayer == msg.sender)`.

**An toàn hơn** mode bitmask của `blockchain.md`. Bitmask đòi đổi nội dung digest
theo mode (loại `relayer`/`feeRecipient` khỏi hash khi MODE_OPEN) — critic đã bắt
đó là rủi ro cross-mode replay và signature malleability. Wildcard giữ digest cố
định, `address(0)` nghĩa là "ai cũng được".

## 6. Mạng open relayer: ý tưởng 0x-mesh

User: *"0x-mesh là idea để làm mạng open relayers phi tập trung."* Lấy mô hình,
không chép triển khai (0x Mesh đã ngừng bảo trì).

Bốn thứ phải có:

1. **Validate trước khi gossip** — thứ hay nhất của 0x-mesh. Kiểm chữ ký,
   `meta_nonce`, `expiry`, số dư đủ trả `fee`, và `eth_estimateGas`. Không qua thì
   không forward. Spam phải tốn tiền thật.
2. **libp2p + gossipsub v1.1** — đừng tự viết giao thức. ERC-4337 bắt buộc đúng bộ
   này (`eth-infinitism/bundler-spec/p2p-specs/p2p-interface.md`) và Shared Mempool
   đang chạy thật trên Ethereum/Arbitrum/Optimism. `v1.1` có **peer scoring** =
   primitive chống spam ở tầng mạng.
3. **Expiry + prune** — 0x-mesh phình kho order. `expiry` đã có trong struct; node
   phải chủ động dọn và không rebroadcast cái quá hạn.
4. **Cuộc đua relayer là vấn đề kinh tế.** `MODE_OPEN` → N relayer cùng gửi, N-1
   mất gas, rồi bỏ mạng. So sánh: commit-reveal, cửa sổ độc quyền mềm, ưu tiên theo
   stake/reputation.

5. **Acceptance policy là một lớp thiết kế riêng, không phải chi tiết cấu hình.**
   Mỗi relayer công bố (hoặc giữ riêng) chính sách nhận việc: contract nào, token
   nào, phí tối thiểu, gas tối đa, giới hạn tần suất. Relayer lọc theo `to` /
   `tokenContract` **có sẵn trong intent** — rẻ, không cần mô phỏng. Đây là thứ làm
   cho `fee = 0` chạy được trên mạng mở (§3.4b), và cũng là thứ 0x-mesh thiếu.

6. **`fee = 0` cần cơ chế chống lạm dụng KHÁC, vì kinh tế học không còn bảo vệ.**
   Với intent có phí, spam tự giới hạn: kẻ spam phải trả phí thật. Với `fee = 0`
   được đối tác tài trợ thì cửa đó mở toang — kẻ tấn công bơm hàng loạt intent phí 0
   nhắm đúng contract đối tác, và người trả giá là nhà tài trợ.

   Nên **nhà tài trợ phải mang rủi ro DoS của chính mình**, on-chain:
   - Ngân sách có trần theo kỳ trên escrow của sponsor
   - Hạn mức theo từng `from` (mỗi tài khoản bao nhiêu giao dịch tài trợ mỗi ngày)
   - Điều kiện đủ tư cách kiểm được on-chain, không phải allowlist off-chain
   - Sponsor tự tắt được ngay lập tức

   Đây chính là mô hình deposit + reputation của paymaster trong ERC-4337, và lý do
   nó tồn tại giống hệt lý do ở đây.

Khác 4337 ở một điểm có lợi: bundler 4337 **phải** qua mev-boost vì bị front-run;
ở đây `MODE_OPEN` coi việc bị "cướp" là tính năng, nên chỉ còn nửa vấn đề (lãng phí
gas), không có nửa kia.

## 7. Phát hiện từ code thật của user

Nguồn: `custom-addons/zether-dev/packages/protocol/contracts`,
`/home/ha/work/blockchain/metatx`, `Grok3_Meta.txt`.
User đã nói: *"Interface có thể chưa đúng"* → được phép thiết kế lại.

**Chặn build:**

1. `address contract;` trong `MtxTradeOrderLib.MtxTradeOrder` — `contract` là từ
   khoá. Đã compile thử với solc 0.8.30:
   `Error (2314): Expected identifier but got 'contract'`. Đổi thành
   `verifyingContract`.
2. `ERC1776.sol` và `IERC1776.sol` **không tồn tại** nhưng `ERC1776Tradeable` và
   `Dex` đều import.

**Thiết kế:**

3. `IERC20MetaTx.MetaTx(...)` **không có tham số `signature`** — 12 tham số vị trí,
   không struct (đúng cái "stack too deep" mà `blockchain.md` §10.2.1 cảnh báo), và
   không chữ ký thì không verify được gì.
4. `ZSC.sol:21` — `uint256 constant MAX = 4294967295;` là `constant` nên **không
   thể per-token**. Cùng lỗi với `MAX_AMOUNT()` khai `pure` trong `blockchain.md`.
   Phải là biến set trong `initialize()`.
5. `ZetherVerifier.fee` là `public constant fee = 0` — phí nướng cứng lúc compile,
   ZSC đọc một lần trong constructor. Mâu thuẫn với
   `secureTransferWithFee(..., bytes32 beneficiary, ...)` vốn có người nhận phí
   theo từng giao dịch.
6. Code hiện tại là **anonymous-zether** (ring): `verifyTransfer` nhận mảng `y[]`,
   `secureTransfer` nhận `bytes32[] receivers`. Nhưng `blockchain.md` yêu cầu **lộ
   danh tính** để tuân thủ AML. Gas tỉ lệ theo ring size `m` — **mọi con số gas phải
   gắn với `m` cụ thể**. Lộ danh tính → ring = 2, rẻ hơn nhiều.

**Giữ lại, xây tiếp:**

7. `ZetherAccount.sol` **đã có sẵn multi-schema registry**: `accounts_schema`,
   `accSchemaIdx`, `_totalAccountsBySchema`, `links`/`link_eth`,
   `struct UniversalAccount`, `register(y, c, s, link)` với Schnorr PoP. Đúng cái
   "Registry mở rộng Multi-sign/Schnorr/BLS/FALCON" mà `blockchain.md` mô tả.
   **Xây trên nó, đừng phát minh lại.**
8. Epoch là **theo thời gian**, không theo block: `uint256 e = block.timestamp / epochLength;`
9. Phí trả cho beneficiary là **plaintext homomorphic**:
   `pending[beneficiaryHash][0].add(Utils.g().mul(fee))` — phí công khai, khớp yêu
   cầu "Public Relayer Fee" của `blockchain.md`.
10. `require(registered(beneficiaryHash))` với chú thích *"necessary so that
    receiving a fee can't backdoor you into registration"* — chi tiết bảo mật tốt,
    giữ nguyên.
11. `bytes32 account` = "Universal Account" = chính là `schnorrAddress`. Thuật ngữ
    phải thống nhất một tên trong toàn tài liệu.

## 8. Từ hội thoại Grok

- Có `mtxWrap` / `mtxUnwrap` — wrap/unwrap qua meta-transaction
- Có **Wrapper Factory**, còn bỏ ngỏ: ai được quyền tạo wrapper, có dùng proxy để
  tiết kiệm gas không → §01 đã chốt **Beacon proxy**, câu này có đáp án
- Bản copy **mất ruột code block**; văn xuôi và đoạn JS còn nguyên. Đủ lấy quyết
  định, không đủ lấy code. Không cần khôi phục — ta viết interface mới.

## 9. Môi trường

- Foundry đã cài (`~/.foundry/bin/forge`), solc 0.8.30 tải được → dùng cho §14
- Máy 23 GB RAM, `systemd-oomd` giết theo PSI với ngưỡng 50% user-slice trong 20s.
  Đã giết workflow hai lần. Fan-out phải giữ <= 3 agent song song

## 10. Phân tầng: Zether là CHILD của MetaTransaction

User: *"Zether riêng, là child của MetaTransaction."*

MetaTransaction là **tầng nền**; bảo mật là phần mở rộng chồng lên. Không phải hai
nhánh song song.

```
IERC20
 └── IERC20MetaTx            ← tầng nền: mọi token đều gasless được
      ├── IERC20Payment       ← token thanh toán công khai
      └── IZetherToken        ← token bảo mật, kế thừa TOÀN BỘ meta-tx
```

Sửa lại code hiện tại: `ISecureERC20 is IERC20` → phải là **`is IERC20MetaTx`**.

Hệ quả: **mọi Zether token tự động có meta-transaction**, và
`transferConfidential` gọi được cả hai đường như `blockchain.md` §10.5.3 mô tả —
trực tiếp bằng EOA có native gas, hoặc bọc trong MetaTransaction qua relayer.

### Hệ quả quan trọng: PHÍ CÓ HAI TẦNG, đừng nhầm làm một

| Tầng | Trả bằng | Người nhận | Kiểu |
|---|---|---|---|
| **Ngoài** (MetaTx) | số dư ERC-20 **công khai** | `address feeRecipient` (ví EOA relayer) | `uint256 feeAmount`, trần 1% |
| **Trong** (Zether) | số dư ElGamal **bí mật** | `bytes32 beneficiary` (Universal Account) | công khai giá trị, trừ trước khi trừ tiền chuyển |

Đây không phải trùng lặp. Hai tầng phục vụ hai tình huống khác nhau, và tình huống
thứ hai mới là lý do Zether cần phí riêng:

**Người dùng có toàn bộ tiền trong số dư bí mật không trả được phí tầng ngoài** —
họ không có đồng ERC-20 công khai nào. Nếu chỉ có phí tầng ngoài thì tài khoản
Zether thuần bị kẹt: không native gas, không token công khai, không cách nào trả
relayer. Phí tầng trong (`C_fee` trừ thẳng khỏi số dư mã hoá) là thứ duy nhất mở
được nút đó.

Ba tổ hợp cần thiết kế rõ, mỗi cái một luồng:

1. **Chỉ phí ngoài** — người dùng có token công khai, chuyển bí mật. Relayer nhận
   ERC-20 thường.
2. **Chỉ phí trong** — người dùng chỉ có số dư bí mật. Relayer nhận vào UA của
   mình, rồi tự `withdraw` khi cần. `feeAmount = 0` ở tầng ngoài.
3. **Cả hai bằng 0** — người dùng tự trả native gas, gọi thẳng, không qua relayer.

Ràng buộc ZKP của tầng trong vẫn như `blockchain.md` §10.5.3: trừ phí trước, trừ
tiền sau, chứng minh đồng thời `fee >= 0`, `v >= 0`, `b - fee >= 0`,
`(b - fee) - v >= 0`.

Và giá trị phí tầng trong **công khai** (plaintext `uint256`, cộng homomorphic
`g^fee` vào pending của beneficiary như `ZSC.sol` đang làm) — đúng yêu cầu
"Public Relayer Fee" để Open Relayer thẩm định được lợi nhuận trước khi nhận việc.
Nếu phí cũng bị mã hoá thì relayer không biết có lãi hay không, và mạng mở sụp.

## 11. Token factory: kiến trúc đã có trong `Grok3_Continued`

Nguồn: `_GROK-CODE.md` (49 code block, 5.965 dòng, trích từ
`~/Downloads/Grok3_Continued.html`). **Đây là bản HTML thật, code còn nguyên** —
khác `Grok3_Meta.txt` vốn mất ruột code block.

Cây kế thừa đã thiết kế:

```
WrappedERC20MetaTx is ERC20, Ownable          <- base, đã có meta-tx
 ├── SingleUnderlyingWrappedERC20MetaTx        <- wrap 1 ERC-20  (USDT -> Z-USDT)
 ├── MultiUnderlyingWrappedERC20MetaTx         <- wrap 1 rổ ERC-20 theo tỉ lệ
 ├── NoUnderlyingWrappedERC20MetaTx            <- issuer tự mint, không underlying
 └── PayableWrappedERC20MetaTx                 <- wrap native coin (ETH/xDAI)

WrappedERC20Factory                            <- createWrapper(...)
```

Khớp **chính xác** ba nguồn token mà `blockchain.md` §TOKEN liệt kê, cộng một cái
thứ tư mà tài liệu quên: **wrap native coin**. Trên Gnosis thì đó là wrap xDAI —
đáng chú ý vì xDAI native đã là stablecoin, nên `PayableWrappedERC20MetaTx` là
đường ngắn nhất tới một Z-token neo USD trên chain đầu tiên.

API đã có:

| Nhóm | Hàm |
|---|---|
| Wrap | `wrap`, `unwrap`, `wrapToken` |
| Meta-tx | `executeMetaTransaction`, `executeMetaTransactionWithFee` |
| Chuyển | `mtxTransfer`, `mtxTransferWithFee`, `mtxPay` |
| Factory | `createWrapper`, `createSingleUnderlyingWrapper`, `createNoUnderlyingWrapper`, `getWrapper`, `getAllWrappers`, `getWrapperCount` |
| Rổ | `addUnderlyingToken`, `removeUnderlyingToken`, `getSupportedTokens`, `addTokens` |
| Phí | `setFeeRecipient`, `setTransferFeePerMille` |
| Client JS | `signAndTransfer`, `signAndTransferWithFee`, `signAndExecuteWithFee`, `signAndPay` |

### struct MetaTransaction của Grok (bản đã hội tụ)

```solidity
struct MetaTransaction {
    address from;
    address to;
    uint256 value;
    bytes   data;
    uint256 nonce;        // 1D, KHÔNG có batchId/batchNonce
    uint256 validUntil;
    uint256 chainId;
    address wrapper;      // = verifyingContract
}
```

Phí **không nằm trong struct** — nó đi qua hàm riêng `mtxTransferWithFee` /
`executeMetaTransactionWithFee`.

### Ba biến thể struct phải hoà giải

| Nguồn | Nonce | Phí | Ràng buộc relayer |
|---|---|---|---|
| `Grok3_Continued` | 1D `nonce` | hàm riêng `...WithFee` | không có trong struct |
| `metatx/MtxTradeOrderLib` | 2D `batch` + `nonce` | `fee` ppm trong struct | `relayer` + wildcard `address(0)` |
| `blockchain.md` EIP-1776 | 2D `batchId` + `batchNonce` | `fee` tuyệt đối trong struct | `relayer` + `feeRecipient` + `mode` bitmask |

Khuyến nghị hợp nhất: **2D nonce** (yêu cầu của `blockchain.md`, và nó giải quyết
head-of-line blocking thật), **phí trong struct** (relayer phải đọc được phí từ
intent trên mesh mà không cần gọi thêm hàm), **wildcard `address(0)`** thay mode
bitmask (mục 5), và **bỏ `mode`** hoàn toàn.

### Mẫu số phần trăm: CHƯA thống nhất, phải chốt

Ba mẫu số đang cùng tồn tại:

| Nguồn | Mẫu số | 1% = |
|---|---|---|
| `setTransferFeePerMille` (Grok) | 1e3 phần nghìn | 10 |
| `MtxTradeOrderLib.fee` | 1e6 ppm | 10000 |
| `Dex.MIN_RECEIVE_PERCENTAGE` | 1e6 ppm | 10000 |

Khuyến nghị **1e6 (ppm)**: 1e3 không biểu diễn được 0,05%, và hai trên ba nơi đã
dùng ppm rồi. Đổi `setTransferFeePerMille` -> `setTransferFeePpm`.

## 12. `transferWithProof` — chứng minh số tiền đã gửi (selective disclosure)

User: *"Zether cần thêm tính năng transferWithProof => Kèm thêm thông tin để nếu
cần, có thể chứng minh: Tôi đã gửi đúng số tiền amount, và đây là bằng chứng. Có
thể dùng giải pháp hash (amount + random đi kèm) hoặc giải pháp nào đó hay hơn.
Dĩ nhiên đây là function thứ 2, khác function chuyển tiền ban đầu."*

### 12.1 Vì sao hash(amount ‖ random) là lựa chọn yếu

Cách đó công bố `H = keccak256(v ‖ r)` lúc chuyển, sau này lộ `(v, r)` để đối chiếu.
Hai khuyết điểm, cái thứ hai là chí mạng:

1. Tốn thêm 32 byte lưu/emit cho **mọi** giao dịch, kể cả những giao dịch không bao
   giờ cần chứng minh.
2. **Không ràng buộc vào giao dịch thật.** `H` là một cam kết độc lập, không có gì
   nối nó với ciphertext `(C, D)` đã thực sự di chuyển. Nó chứng minh *"tôi đã cam
   kết con số X"*, **không** chứng minh *"tôi đã chuyển X"*. Người gửi hoàn toàn có
   thể cam kết một số, chuyển một số khác. Muốn vá thì phải thêm một ZK proof rằng
   preimage của `H` bằng giá trị bên trong ciphertext — đắt, và thừa.

### 12.2 Giải pháp: mở chính ciphertext. Không cần thêm gì lúc chuyển

Ciphertext chuyển tiền vốn đã là một cam kết Pedersen-like vào `v`:

```
C_transfer = g^v · y_to^s
D_transfer = g^s
```

Nên **mở ciphertext chính là chứng minh số tiền**, và nó ràng buộc tuyệt đối vào
đúng giao dịch đó. Chi phí thêm lúc chuyển: **bằng không**.

Ba đường mở, ba chủ thể khác nhau, giữ cả ba:

| # | Ai chứng minh được | Cần biết | Verifier kiểm |
|---|---|---|---|
| **A** | **Người gửi** | `s` (randomness của giao dịch) | `C_transfer · g^{-v} == y_to^s` |
| **B** | **Người nhận** | `x_to` (khoá bí mật của mình) | `C_transfer · g^{-v} == D_transfer^{x_to}`, kèm Chaum-Pedersen chứng minh dùng đúng `x_to` ứng với `y_to` |
| **C** | **Auditor được chỉ định** | khoá auditor | mở `C_aud` (đã có trong canon §C6.5, dạng shared-`s`) |

Đường **A** rẻ nhất: hai scalar mult và một phép so sánh, không cần ZK. Đường **B**
quan trọng vì nó cho **người nhận** chứng minh mà **không cần người gửi hợp tác** —
tình huống tranh chấp thực tế thường là vậy. Canon đã có mầm của B ở bảng sửa §07:
`C_out · g^{-v} == D_out^{x_to}`.

### 12.3 Chứng minh KHÔNG được là giao dịch đổi trạng thái

Đây là điểm thiết kế dễ làm sai. Tách làm hai thứ:

```solidity
/// Verifier thuần, gọi FREE qua eth_call. Không tốn gas, không đổi state.
function verifyTransferAmount(
    bytes32 entryRef,      // ràng buộc vào đúng giao dịch: tx hash hoặc entry id
    uint256 v,             // số tiền được tuyên bố
    bytes calldata opening // đường A: s | đường B: (x_to proof) | đường C: auditor
) external view returns (bool);

/// Chỉ khi cần DẤU THỜI GIAN on-chain làm bằng chứng pháp lý.
/// Ghi một attestation bất biến. Tốn gas. Không bắt buộc.
function attestTransferAmount(
    bytes32 entryRef,
    uint256 v,
    bytes calldata opening
) external returns (bool);
```

Phần lớn nhu cầu — kiểm toán, đối soát ERP, trả lời cơ quan thuế — chỉ cần
`verifyTransferAmount` qua `eth_call`: **miễn phí, không giới hạn số lần, không để
lại vết on-chain**. Chỉ khi cần bằng chứng có dấu thời gian không chối được mới gọi
`attestTransferAmount`.

`entryRef` **bắt buộc** — thiếu nó thì chỉ chứng minh được *"có một giao dịch trị
giá X"*, không phải *"giao dịch NÀY trị giá X"*.

### 12.4 Ràng buộc bảo mật bắt buộc kèm theo

1. **`s` phải là random tươi cho mỗi giao dịch.** Nếu `s` sinh tất định (từ counter,
   từ khoá, từ nonce) thì lộ một `s` cho phép suy ra các `s` khác ⇒ mở được những
   giao dịch chưa từng định mở. Phải ghi rõ thành yêu cầu của client SDK và có test
   phủ định.
2. **Lộ `s` mở TOÀN BỘ ciphertext dùng chung `s` đó.** Thiết kế hiện dùng shared-`s`
   cho `C_transfer`, `C_debit`, `C_aud` (canon §C6.5). `C_debit` mã hoá cùng một `v`
   nên không lộ thêm gì; `C_fee` vốn đã công khai. Kết luận: an toàn — nhưng phải
   **ghi ra** là đã kiểm, vì nếu sau này có ai thêm một ciphertext thứ tư dùng chung
   `s` mang thông tin khác thì tính chất này gãy im lặng.
3. **Mở một giao dịch không lộ số dư.** Chỉ `v` của giao dịch đó bị lộ, `b` vẫn kín.
   Đây là tính chất tốt và phải có test khẳng định nó.
4. **Không có cách thu hồi.** Đã lộ `s` cho ai thì người đó chứng minh lại được với
   bất kỳ ai, mãi mãi. Selective disclosure là một chiều. UI phải nói rõ điều này
   trước khi người dùng bấm nút.

### 12.5 Vì sao đây là thứ pháp lý cần

Nối vào §13 (pháp lý): FATF Travel Rule và kiểm toán không đòi *mọi* giao dịch phải
công khai — chúng đòi **khi được yêu cầu hợp pháp thì phải xuất trình được**. Đó
chính xác là selective disclosure: mặc định kín, mở theo yêu cầu, và bằng chứng
kiểm chứng được độc lập bởi bên thứ ba mà không cần tin lời ai.

Nó cũng là câu trả lời cho câu hỏi tịch thu/cưỡng chế ở canon §C16 — không phải
"tịch thu được" nhưng là "chứng minh được", và đó là thứ toà án và cơ quan thuế
thực sự yêu cầu trong đa số tình huống.

### 12.6 Cần thêm vào section nào

| Section | Thêm gì |
|---|---|
| `03-zether-crypto` | Toàn bộ mục này: ba đường mở, Chaum-Pedersen cho đường B, yêu cầu `s` tươi, phân tích shared-`s` |
| `10-odoo-addon-design` | Model lưu opening đã phát hành: ai mở, cho ai, khi nào, `entryRef`. **Không lưu `s` trong DB** — nó là bí mật; lưu tham chiếu tới custody |
| `12-threat-model` | `s` tất định; lộ `s` mở nhầm ciphertext; ép buộc mở (coercion); mở rồi không thu hồi được |
| `13-legal-vn` | Selective disclosure là cách đáp ứng Travel Rule và yêu cầu xuất trình, không cần công khai mặc định |
| `14-contracts-repo-testing` | Test: mở đúng thì pass; đổi 1 bit của `v` thì fail; `entryRef` sai thì fail; mở giao dịch A không mở được giao dịch B; mở không lộ số dư |

## 12.7 Kịch bản tranh chấp: người nhận chối. Chứng minh có đứng vững không?

User: *"Người gửi bảo rằng tôi đã gửi x tiền, người nhận không chịu => Đưa ra pháp
lý, người gửi chứng minh được transaction zether này tôi đã gửi đúng số tiền này =>
Bên quan tòa chấp nhận người gửi đúng. Việc này tránh việc: người nhận nhận đủ
amount rồi, nhưng lại chối, hoặc cho rằng không đủ."*

Đây là phép thử nghiêm khắc nhất của §12, vì người nhận **không hợp tác** và có động
cơ nói dối. Phải chứng minh hai chiều: người gửi **không nói dối được**, và người
nhận **không chối được**.

### 12.7.1 Người gửi có mở gian được không? KHÔNG — chứng minh

Giả sử người gửi muốn tuyên bố một số khác `v' ≠ v`. Họ cần tìm `s'` sao cho:

```
C_transfer · g^{-v'} == y_to^{s'}
```

Thay `C_transfer = g^v · y_to^s` và `y_to = g^{x_to}`:

```
g^v · y_to^s · g^{-v'} == y_to^{s'}
g^{v - v'}              == y_to^{s' - s}
g^{v - v'}              == g^{x_to · (s' - s)}
v - v'                  == x_to · (s' - s)   (mod q)
```

Suy ra `s' = s + (v - v') / x_to`. Muốn tính được nó phải biết **`x_to` — khoá bí
mật của NGƯỜI NHẬN**. Người gửi không có, và lấy được nó tức là phá discrete log.

Đây chính là lập luận **binding của cam kết Pedersen**: `C = g^v · h^s` với
`h = y_to` mà người gửi không biết `log_g(h)` ⇒ **computationally binding**. Mở được
đúng một giá trị duy nhất.

**Điều kiện biên phải ghi ra**: tính binding chỉ đúng khi người gửi KHÔNG biết
`x_to`. Nếu hai bên thông đồng, hoặc người gửi tạo hộ ví cho người nhận, thì gãy.
Trong tranh chấp thật thì tiền đề này thoả — hai bên đối địch.

### 12.7.2 Người nhận có chối được không? KHÔNG — chuỗi bằng chứng

Ba mắt xích, không mắt nào cần người nhận hợp tác:

| # | Mắt xích | Nguồn | Bất biến |
|---|---|---|---|
| 1 | `y_to` ↔ danh tính pháp lý của người nhận | `ZetherAccount.register()` với Schnorr PoP, cộng `links`/`link_eth` | có, on-chain |
| 2 | Giao dịch tại block N chứa `C_transfer`, `D_transfer`, `from`, `to` | sổ cái | có, có dấu thời gian |
| 3 | `C_transfer · g^{-v} == y_to^s` | người gửi lộ `s` | kiểm được bởi bất kỳ ai |

Mắt xích 1 là thứ khiến "tôi không phải chủ ví đó" không đứng được: đăng ký đòi
**proof-of-possession Schnorr**, tức người nhận đã từng ký bằng chính `x_to`. Mắt
xích 2 nằm trên chuỗi, không ai sửa. Mắt xích 3 người gửi tự làm được.

Người nhận nói *"tôi không nhận"* hay *"nhận thiếu"* đều bị bác bởi ba mắt xích này
mà **không cần họ ký gì, không cần họ có mặt**.

### 12.7.3 Lỗ hổng thật: `rollOver` do chủ sở hữu ký

Đây là chỗ kịch bản của bạn va vào một quyết định của canon, và tôi phải nêu ra.

Canon §C5 chốt *"epoch đã chết, `accSeq` thắng"* với **`rollOver` do chủ tài khoản
ký**. Nghĩa là tiền chuyển tới nằm ở `pending` cho tới khi **người nhận tự ký** để
chuyển nó thành số dư khả dụng.

Người nhận thù địch khai thác được: *"Đúng, có ciphertext đó, nhưng tôi chưa bao giờ
rollOver nên tôi chưa nhận được gì."* Về mặt kỹ thuật tiền đã là của họ; về mặt tranh
tụng nó tạo ra một bề mặt chối cãi không cần thiết.

Hai cách bịt, tôi đề nghị cách một:

1. **`rollOver` KHÔNG cần chữ ký cho chiều cộng tiền.** Ai cũng gọi được để đẩy
   `pending → available` cho bất kỳ tài khoản nào. Cộng tiền cho ai thì không hại
   được họ, nên không cần uỷ quyền. Chữ ký chỉ cần cho việc tăng `accSeq` của chính
   người gửi khi chi tiêu. Cách này **đồng thời** sửa luôn vấn đề liveness tôi đã nêu
   trước đó (tiền kẹt vĩnh viễn ở pending nếu người nhận biến mất).
2. Giữ owner-signed, nhưng ghi vào hợp đồng dịch vụ và điều khoản pháp lý rằng
   **"giao hàng" = được ghi vào `pending`**, không phải = `rollOver`. Yếu hơn, vì nó
   dựa vào câu chữ hợp đồng thay vì tính chất kỹ thuật.

Đây là mâu thuẫn thật với canon §C5, phải đưa lên để quyết — thêm vào danh sách
D1–D16 của §C21 thành **D17**.

### 12.7.4 Yêu cầu vận hành: MẤT `s` LÀ MẤT QUYỀN CHỨNG MINH

Hệ quả nặng nhất và dễ bỏ sót nhất.

Người gửi chỉ chứng minh được nếu còn giữ `s` của giao dịch đó. `s` là random tươi
mỗi lần (§12.4), không tái tạo được từ khoá. **Mất `s` là mất vĩnh viễn khả năng
chứng minh** — dù tiền đã chuyển thật và ciphertext vẫn nằm trên chuỗi.

Nên client SDK **bắt buộc**:

- Lưu `s` cho **mọi** giao dịch gửi đi, mã hoá, cùng vòng đời với khoá ví
- Đưa `s` vào backup/khôi phục ví — không chỉ khoá, mà cả kho `s`
- Xuất được: một tệp bằng chứng độc lập `(entryRef, v, s, chainId, tokenAddress)`
  mà bên thứ ba kiểm được mà không cần app

Nếu bỏ qua điều này thì §12 chỉ đúng trên giấy: tính năng có, nhưng đúng lúc cần thì
dữ liệu đã mất. Đây là **yêu cầu bắt buộc của P12 (prover SDK)**, không phải
nice-to-have.

### 12.7.5 Công cụ cho toà: verifier độc lập

Toà và giám định viên **không được** buộc phải tin app của bất kỳ bên nào. Cần:

- **CLI verifier mã nguồn mở**, chạy độc lập, không phụ thuộc hạ tầng của doanh nghiệp
- Đọc trực tiếp từ archive node hoặc từ một chain export đã ký
- Nhận `(entryRef, v, s)`, in ra PASS/FAIL cùng toàn bộ số liệu trung gian
- **Tất định và tái lập được**: hai giám định viên chạy phải ra cùng kết quả

Về pháp lý Việt Nam: đây là vật liệu cho **giám định tư pháp** — bằng chứng kỹ thuật
số kiểm chứng được, không phải lời khai. Điểm mạnh là giám định viên tự chạy lại
được, không phải tin ai. Cần đưa vào §13 cùng câu hỏi bỏ ngỏ: toà Việt Nam đã có
tiền lệ chấp nhận bằng chứng mật mã dạng này chưa, và có cần chứng thực bởi tổ chức
giám định được chỉ định không.

### 12.7.6 Chiều ngược lại

Cùng bộ máy giải quyết luôn ba tranh chấp còn lại:

| Tranh chấp | Ai chứng minh | Bằng cách |
|---|---|---|
| Người nhận chối đã nhận | **người gửi** | đường A, lộ `s` |
| Người nhận nói nhận thiếu | **người gửi** | đường A — cùng một phép kiểm |
| Người gửi chối đã gửi | **người nhận** | đường B, dùng `x_to` + Chaum-Pedersen |
| Cả hai chối, bên thứ ba cần biết | **auditor** | đường C, mở `C_aud` |

Đây là lý do phải giữ **cả ba** đường mở của §12.2, không lược bớt đường nào.

## 13. Ba đính chính của user (thay thế phần tương ứng ở trên)

### 13.1 `fee = 0`: chống lạm dụng là việc của người vận hành relayer, off-chain

User: *"Đó là việc của người đang chạy open relayer, và thuộc về phạm trù offchain:
Quyết định chạy chain nào, quyết định chạy smartcontract nào, được tài trợ fee như
thế nào..."*

Chấp nhận. **Bỏ** yêu cầu ngân sách/hạn mức on-chain mà §6 mục 6 đã đặt ra — đó là
thiết kế thừa. Giao thức không được áp chính sách kinh doanh của relayer.

Phân định rạch ròi:

| Tầng | Ai lo | Gồm |
|---|---|---|
| **Giao thức** | contract + mesh | tính đúng đắn, chống replay, chống rò rỉ, phí công khai để thẩm định được |
| **Vận hành** | từng relayer, **off-chain** | chạy chain nào, nhận contract nào, ai tài trợ, hạn mức, chống spam của riêng mình |

Một ngoại lệ duy nhất giữ lại: **khi nhà tài trợ là một escrow ON-CHAIN**, thì
chính escrow đó phải có trần chi tiêu — không phải vì giao thức áp đặt, mà vì tiền
nằm trong contract thì contract phải tự bảo vệ. Sponsor off-chain thì không liên
quan tới giao thức.

### 13.2 Client KHÔNG lưu gì. Suy ra `s` từ seed — và điều này lật cảnh báo ở §12.4

User: *"Không, lưu hash(s) random trên chain. Hoặc cách nào đó. Tóm lại là sẽ có
cách để client không lưu thêm gì. Client chỉ cần có seed key."*

Đúng hướng, và có cách sạch hơn cả hai phương án bạn nêu: **suy ra `s` tất định từ
seed bằng một PRF**.

```
s = HKDF-SHA256(seed_zether,
                info = "ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter)
```

Client lưu **đúng một thứ: seed**. Muốn chứng minh giao dịch nào thì đọc
`sendCounter` của giao dịch đó **từ chuỗi**, suy lại `s`, xong. Khôi phục ví từ seed
trắng vẫn chứng minh được **mọi giao dịch trong quá khứ**.

**Đính chính §12.4 mục 1.** Tôi đã viết *"`s` phải là random tươi mỗi giao dịch;
sinh tất định thì lộ một `s` cho phép suy ra các `s` khác"*. **Sai** — điều đó chỉ
đúng với suy diễn *đoán được* (counter thô, timestamp, tuyến tính). Với **PRF** thì
không: HKDF cho các đầu ra độc lập, lộ `s_i` không tiết lộ gì về `seed` hay `s_j`.
Yêu cầu đúng phải là **"`s` không được đoán trước"**, chứ không phải "phải ngẫu
nhiên".

Vì sao suy diễn **thắng** lưu `hash(s)` on-chain:

| | Lưu `hash(s)` on-chain | Suy ra từ seed |
|---|---|---|
| Gas | +32 byte mọi giao dịch, mãi mãi | **0** |
| Client khôi phục được `s`? | **KHÔNG** — hash không đảo ngược được, vẫn phải lưu `s` | **CÓ** |
| Cần lưu gì | seed **và** kho `s` | **chỉ seed** |

`hash(s)` chỉ cho phép *kiểm* một `s` được xuất trình, không cho phép *lấy lại* nó.
Nó giải quyết nhầm bài toán.

**Ràng buộc bắt buộc**: `sendCounter` phải đọc từ **trạng thái on-chain**, không
phải bộ đếm cục bộ. Nếu counter lặp (giao dịch fail đã tăng counter cục bộ nhưng
chưa lên chuỗi) thì `s` lặp ⇒ **tái dùng randomness ElGamal** ⇒ lộ số dư. Đây là
lỗi thảm hoạ, phải có test phủ định.

Hệ quả: **xoá toàn bộ §12.7.4**. Không cần lưu `s`, không cần đưa `s` vào backup,
không cần kho `s`. Yêu cầu duy nhất còn lại của P12 là: SDK suy được `s` từ seed +
dữ liệu chuỗi, và xuất được tệp bằng chứng `(entryRef, v, s)` cho bên thứ ba.

### 13.3 `rollOver` mở cho mọi người — code hiện tại ĐÃ ĐÚNG, canon là hồi quy

User: *"Đồng ý rollOver open cho mọi người. Hoặc gửi tiền vào là rollOver. Hình như
code của tôi đã có hàm riêng cho việc đó."*

**Đã kiểm, đúng.** `SecureERC20.sol` / `ZSC.sol`:

```solidity
function rollOver(bytes32 yHash) internal {
    uint256 e = block.timestamp / epochLength;
    if (lastRollOver[yHash] < e) {
        // gộp pending vào acc
        delete pending[yHash];
        lastRollOver[yHash] = e;
    }
    if (lastGlobalUpdate < e) { lastGlobalUpdate = e; delete nonceSet; }
}
```

`internal` và **được gọi ngầm** ở đầu mọi thao tác chạm tài khoản: khi nạp tiền
(dòng 133), trước khi ghi có phí cho beneficiary (dòng 152), và trong vòng lặp người
tham gia chuyển khoản (dòng 158). **Không ai phải ký gì**, và không có hàm public
nào để gọi riêng — nó đơn giản là luôn xảy ra.

Nghĩa là **cả hai vấn đề đều không tồn tại trong bản cài đặt hiện tại**:

- Bề mặt chối cãi ở §12.7.3 — không có
- Tiền kẹt vĩnh viễn ở pending — không có

Chính đề xuất `accSeq` owner-signed của **canon §C5 mới tạo ra chúng**. Đó là một
**hồi quy so với code đang chạy**, không phải cải tiến.

**D17 (thay cho bản ở §12.7.3)**: canon §C5 phải chứng minh được lợi ích của
owner-signed `rollOver` lớn hơn hai hồi quy nó gây ra, nếu không thì **giữ nguyên
`rollOver` ngầm** như code hiện tại. Mặc định: **giữ code hiện tại**. Canon §C5.4 đã
tự ghi nhận đường lui và đã yêu cầu một hợp đồng review mật mã (§C21 D8) — đưa câu
hỏi này vào đúng phạm vi review đó.

Lưu ý kỹ thuật kèm theo: `delete nonceSet` khi epoch toàn cục tiến — đó là cơ chế
chống replay theo epoch mà canon định thay bằng `accSeq`. Hai thứ này gắn nhau, đổi
một phải đổi cả hai, và đó là lý do §C5.4 nói "năm section revert cùng nhau".

## 14. Preflight EIP-2537 — ĐÃ CHẠY THẬT, D1 có đáp án

Canon §C21 D1 đặt điều kiện: *"`bls12_381` **nếu** `0x0c` sống trên Gnosis và Celo
— nó rẻ hơn 45–60% **và** mạnh hơn 17–26 bit."* Điều kiện đó chưa ai kiểm.

Đã kiểm, 2026-08-30, bằng `eth_call` thật tới RPC công khai:

| Precompile | Địa chỉ | Gnosis | Celo |
|---|---|---|---|
| `BLS12_G1ADD` | `0x0b` | **sống** (128 B) | **sống** (128 B) |
| `BLS12_G1MSM` | `0x0c` | **sống** (128 B) | **sống** (128 B) |
| `BLS12_PAIRING_CHECK` | `0x0f` | **sống** (32 B) | **sống** (32 B) |
| `BLS12_MAP_FP_TO_G1` | `0x10` | **sống** (128 B) | **sống** (128 B) |

Phương pháp và đối chứng: input toàn số 0 hợp lệ theo EIP-2537 (G1ADD 256 B,
G1MSM 160 B, PAIRING 384 B, MAP_FP 64 B); đối chứng `alt_bn128 ecAdd` (`0x06`) trả
64 B trên cả hai. Precompile **không tồn tại** sẽ trả `0x` rỗng chứ không trả dữ
liệu — nên độ dài output khác 0 là bằng chứng nó đang thực thi.

Lần thử đầu `0x0c` báo lỗi vì tôi gửi 128 B thay vì 160 B. Bản thân thông báo lỗi
(`invalid input length` trên Celo, `PrecompileError` trên Gnosis) **đã chứng minh
precompile tồn tại và đang validate input** — nếu không có code thì không có lỗi,
chỉ có kết quả rỗng.

### Hệ quả

**D1 → `bls12_381`.** Đây không phải ý kiến của tôi, đó là quy tắc do chính canon
đặt ra, với tiền đề vừa được xác minh.

**D2 chốt cùng D1** theo đúng chỉ dẫn của canon.

**`0x0f` sống mở luôn đường nâng cấp Groth16** — con số ~181 k gas mà canon §C7
nói là cách duy nhất đưa Zether lên public chain ở quy mô. Trước đây nó là giả
định; giờ là năng lực có thật trên cả hai chain đầu tiên.

### Còn phải đo, chưa xong

Precompile **sống** không có nghĩa là **rẻ**. Con số "rẻ hơn 45–60%" của canon vẫn
là ước tính. Spike S7 phải đo gas thật của một `transferConfidential` đầy đủ trên
`bls12_381` so với `bn254`, trên testnet của cả hai chain, trước khi đóng băng
struct ở G2.

## 15. Quyết định D1/D2/D7/D12/D14/D17 — ĐÃ CHỐT

| # | Quyết định | Chốt |
|---|---|---|
| **D1** | curve | **`bls12_381`** — điều kiện canon đặt ra đã xác minh (§14) |
| **D2** | đóng băng struct | chốt cùng D1 |
| **D7** | custody | **A/B** ($2.900–9.750/tháng), HSM FIPS 140-2 L3 hoặc MPC thương mại |
| **D12** | phạm vi đợt đầu | **cấu hình đầy đủ** — cả ba use case cùng lúc |
| **D14** | onboarding `register` | **KHÔNG thuộc `dms_blockchain`** — xem dưới |
| **D17** | `rollOver` | **giữ code hiện tại** + thêm `rollOverPublic` / `rollOverBatch` |

D12 = đầy đủ nên D7 = A/B là bắt buộc, không phải lựa chọn — canon đã ghi A/B là
điều kiện cần khi bật B2B.

### D14: đăng ký key KHÔNG phải việc của addon

User: *"Tùy bên vận hành. Nhưng blockchain không liên quan dms. Nên việc đăng ký
key cho outlet là việc riêng. Không lẫn."*

Câu hỏi tôi đặt đã ngầm giả định sai — nó cho rằng `dms_blockchain` lo onboarding
outlet. **Không.** Addon không được biết "outlet" là gì; đó là khái niệm của `dms`,
và ràng buộc #7 cấm phụ thuộc đó.

Sửa lại phạm vi:

| Ai | Việc |
|---|---|
| `dms_blockchain` | quản lý `blockchain.account`: đăng ký khoá, PoP, vòng đời, liên kết tới `res.partner` **generic** |
| Bridge addon (`dms` ↔ chain) | ánh xạ outlet → account, nếu deployment nào cần |
| Bên vận hành | chính sách: ai được cấp khoá, khi nào, ai trả gas đăng ký |

Canon §C21 D14 phải viết lại theo hướng này — nó đang mô tả một luồng onboarding
mà addon không có thẩm quyền thực hiện.

## 16. Chain đích đầu tiên là PRIVATE, không phải Gnosis

`/home/dockers/mba-chain-nethermind` — Nethermind, hiện chưa chạy.

| | |
|---|---|
| chainId | `0x2328` = **9000** |
| Engine | **Clique** PoA, `period: 5` (block 5 giây), `epoch: 30000` |
| Fork | `pragueBlock: 0` ⇒ **EIP-2537 BLS12-381 có sẵn từ genesis** — tương thích D1 |
| gasLimit | `0x1000000` = **16.777.216** |
| MinGasPrice | **0** — gas miễn phí, khớp quyết định "gas không phải ràng buộc" |
| Signer | **một** account: `0xdE36845Cc887783397b2808c13f2Ed95DC2646BB` |
| RPC | 8545 / WS 8546, modules gồm `clique`, `trace` |
| Alloc | 6 tài khoản |

### Vấn đề 1: gasLimit quá thấp cho Zether

16,7 M gas/block chia cho ~1,9 M gas một `transferConfidential` = **~8 giao dịch
bảo mật mỗi block**. Với block 5 giây thì **~1,7 tx/s** — và đó là khi block chỉ
chứa Zether, không còn chỗ cho gì khác.

Canon §C17.2 đã khuyến nghị **50 M** cho chain private. Cần sửa `gasLimit` trong
genesis. Chain demo nên reset được, nên đây là thay đổi rẻ — nhưng phải làm **trước**
khi có state đáng giữ.

Ghi chú: Clique cho phép signer nâng dần gasLimit (`gasLimitBoundDivisor = 0x400`
⇒ ~0,1%/block), nhưng sửa genesis rồi reset nhanh hơn nhiều cho một chain demo.

### Vấn đề 2: một signer thì phải gọi đúng tên

Clique với **một** signer duy nhất không phải blockchain phi tập trung theo bất kỳ
nghĩa nào — nó là một cơ sở dữ liệu có hash và chữ ký. Hoàn toàn ổn cho demo và cả
cho vận hành nội bộ, nhưng:

- Tài liệu bán hàng **không được** gọi nó là "blockchain phi tập trung"
- Mô hình đe doạ (§12) phải ghi: signer đơn = một điểm kiểm duyệt và một điểm hỏng
- Nếu B2B thật chạy trên nó, đối tác phải biết ai kiểm soát signer

Canon §C21 D10 đã nêu đúng lo ngại này cho Besu; áp nguyên cho Nethermind.

### Hệ quả cho lộ trình

Canon giả định **Gnosis trước**. Thực tế: **private trước, Gnosis sau**. Điều đó
hợp với locked #5 (Zether chạy private trước vì gas không phải ràng buộc), nhưng
§16 roadmap phải đảo lại thứ tự, và §14 phải thêm chain 9000 vào ma trận CI.

Ưu điểm không nhỏ: `MinGasPrice = 0` và Prague sẵn có nghĩa là **spike S7 đo gas
BLS12-381 chạy được ngay trên chain này**, không cần faucet, không cần testnet.

## 17. Spike S7 — ĐÃ ĐO. Canon SAI về chi phí BLS12-381

Đo thật bằng `eth_estimateGas` trên Gnosis mainnet, 2026-08-30. Trừ base
(21.000 + 4 gas/byte-zero calldata). Sai số hệ thống ~350 gas, kiểm bằng đối chứng:
`bn128 ecMul` đo 6.345 so với spec 6.000; `G1MSM k=1` đo 12.357 so với spec 12.000.

### Kết quả: MSM ở quy mô Bulletproofs

| k điểm | BLS12-381 `G1MSM` (1 lệnh) | alt_bn128 (k×`ecMul` + (k−1)×`ecAdd`) | Chênh |
|---|---|---|---|
| 1 | 12.357 | 6.000 | **BLS đắt hơn 106%** |
| 8 | 70.852 | 49.050 | BLS đắt hơn 44% |
| 32 | 244.175 | 196.650 | BLS đắt hơn 24% |
| 64 | 447.538 | 393.450 | BLS đắt hơn 14% |
| 128 | 805.495 | 787.050 | BLS đắt hơn 2% |
| **277** | **1.741.589** | **1.703.400** | **BLS đắt hơn 2%** |

Kiểm chứng chéo với bảng discount của EIP-2537: `1.741.589 / (12.000 × 277) = 0,524`
— khớp mức đáy ~519–524/1000 của bảng. Phép đo nhất quán với spec, không phải nhiễu.

### Canon §C21 D1 nói sai

Canon: *"`bls12_381` **nếu** `0x0c` sống trên Gnosis và Celo — nó **rẻ hơn 45–60%**
và mạnh hơn 17–26 bit."*

Nửa đầu **sai**. Ở quy mô Bulletproofs thật (k≈277), BLS12-381 **không rẻ hơn** —
nó **đắt hơn ~2%**. Ở k nhỏ thì tệ hơn nhiều. Không có mức tiết kiệm 45–60% nào ở
bất kỳ k nào.

Nửa sau vẫn đúng: BLS12-381 ~126 bit an toàn so với BN254 ~100 bit (sau
Kim–Barbulescu).

### D1 phải mở lại

Tiền đề đã đổi, nên câu trả lời có thể đổi. Cân lại trung thực:

| | BLS12-381 | alt_bn128 (BN254) |
|---|---|---|
| Gas ở k=277 | 1,74 M | **1,70 M** |
| An toàn | **~126 bit** | ~100 bit |
| Code Zether hiện có của user | phải **viết lại verifier** | **đã chạy** (`ZetherVerifier.sol`, `InnerProductVerifier.sol`) |
| Thư viện Bulletproofs | ít trưởng thành hơn | arkworks/circom nhiều, hệ sinh thái sâu |
| Có trên chain private 9000 | **KHÔNG** (xem §16) | **có** |
| Đường Groth16 sau này | `0x0f` sống trên Gnosis/Celo | `0x08` sống ở mọi nơi |

Lý do duy nhất còn lại để chọn BLS là **biên an toàn 26 bit**, trả bằng: viết lại
verifier, hệ sinh thái mỏng hơn, và **không chạy được trên chain private hiện tại**.

Canon §C21 D3 hỏi đúng câu liên quan: *"chấp nhận giải mã được 2035–2045 trên
public, hay bắt buộc private/BLS"*. Với quyết định #5 (Zether chạy **private**
trước) thì đe doạ mà 26 bit kia phòng ngừa **chưa áp dụng cho giai đoạn đầu** —
chain private không công khai ciphertext cho kẻ tấn công thu thập.

**Khuyến nghị đảo lại: `bn254` cho giai đoạn private, xem lại BLS trước khi lên
public.** Nó giữ được code đang chạy, chạy được trên chain 9000, gas ngang nhau, và
đẩy đánh đổi an toàn sang đúng thời điểm nó thật sự quan trọng.

Cần user quyết lại D1.

## 18. Chain private 9000: genesis viết sai định dạng

`pragueBlock: 0` trong `params` **không kích hoạt Prague**. Nethermind dùng
chainspec riêng, không đọc key kiểu Geth. Bằng chứng đo được:

| Kiểm | Kết quả |
|---|---|
| `0x0b`/`0x0c`/`0x0f`/`0x10` (BLS12-381) | **rỗng — không tồn tại** |
| `0x06`/`0x07` (alt_bn128) | sống (đối chứng hợp lệ) |
| `baseFeePerGas` trong block header | **không có ⇒ London CHƯA bật** |
| `withdrawalsRoot` | không có ⇒ Shanghai chưa bật |
| `blobGasUsed` / `excessBlobGas` | không có ⇒ Cancun chưa bật |

Chain đang chạy ở mức **trước London**, dù genesis khai `londonBlock: 0`,
`cancunBlock: 0`, `pragueBlock: 0`. Tất cả bị bỏ qua **im lặng** — không log cảnh
báo nào.

Hệ quả:

- Không có EIP-1559 ⇒ không `baseFeePerGas`, mô hình phí khác hẳn public chain
- Không có EIP-2537 ⇒ **BLS12-381 không dùng được**, khoá chặt D1 về `bn254` nếu
  giữ chain này nguyên trạng
- Muốn bật thì phải viết lại `params` theo đúng key của Nethermind
  (`eip1559TransitionTimestamp`, `eip2537TransitionTimestamp`, ...) **và reset
  632 MB data** vì genesis hash đổi

Chưa làm gì. Đã backup `genesis.json`. Chain đang chạy nguyên trạng, block 7367+.

Đây là một cái bẫy đáng vào `TRAPS.md`: **chainspec Nethermind bỏ qua key kiểu Geth
mà không báo lỗi**, và cách duy nhất phát hiện là kiểm block header hoặc gọi thử
precompile.

## 19. D1 CHỐT LẠI: `bn254` cho giai đoạn private

Sau khi §17 đo được rằng tiền đề "BLS rẻ hơn 45–60%" là sai, user chốt tiếp
(*"tiếp tục"* trên khuyến nghị đảo lại). **`curve_profile = 'bn254'`.**

Đây là quyết định **cho giai đoạn private**, không phải vĩnh viễn. Nó đóng gate G1
đủ để P10 chạy được, và mở lại đúng một lần nữa trước khi lên public.

### Cái gì được mở khoá ngay

| | |
|---|---|
| `ZetherVerifier.sol` / `InnerProductVerifier.sol` của user | **giữ nguyên**, không viết lại |
| Chain 9000 | chạy được như hiện trạng, `0x06/0x07` sống — **không reset 632 MB** |
| Genesis Nethermind | **không sửa**. Chỉ sửa nếu sau này thật sự cần EIP-1559 hoặc EIP-2537 |
| G2 (D2 — đóng băng struct) | mở được, vì nó chờ G1 |
| Prover Rust | nhắm `bn254` (arkworks `ark-bn254`), hệ sinh thái sâu hơn |

### Điều kiện mở lại D1 — ghi ra để không quên

`bn254` ~100 bit sau Kim–Barbulescu. Con số đó chấp nhận được **vì chain private
không phát ciphertext ra cho kẻ tấn công thu thập**. Giả định đó chết ngay khi
bất kỳ điều nào sau đây xảy ra:

1. Zether được deploy lên **public chain** (Gnosis/Celo) — ciphertext thành công
   khai vĩnh viễn, harvest-now-decrypt-later áp dụng.
2. Chân trời bảo mật cần > 10 năm (đó chính là **D3**, vẫn đang mở).
3. Read RPC của chain private mở ra ngoài vành đai tin cậy.

Ở mỗi mốc đó, D1 phải được hỏi lại — không mặc định trôi theo.

### Ràng buộc kỹ thuật để việc mở lại không tốn cả hệ thống

Curve phải là **tham số deploy-time, không phải hằng số biên dịch rải khắp code**:

- `blockchain.zether.token.curve_profile` là Selection `bn254 | bls12_381`, và
  `proof_system_id` khoá cứng theo nó. Một token đã deploy **không đổi được**
  curve — migrate nghĩa là token mới + bridge, không phải setter.
- Contract verifier nằm sau một địa chỉ được inject lúc `initialize()`, không
  `import` trực tiếp vào `ZSC`. Đổi curve = deploy verifier khác, không sửa `ZSC`.
- Prover Rust trait-hoá theo curve từ đầu (`ark-ec::PairingEngine`), kể cả khi
  chỉ có một implementation chạy. Đây là chỗ **duy nhất** đáng trả giá trừu tượng
  hoá sớm, vì nó là chỗ duy nhất biết được là sẽ có nhánh thứ hai.

### Canon phải sửa

`00-CANON.md` §C21 hàng D1: bỏ mệnh đề *"rẻ hơn 45–60%"* (đo được là sai), đổi
khuyến nghị sang `bn254`, và trỏ tới §17 làm bằng chứng. §C7.2 nếu có bảng gas
BLS thì thay bằng số đo thật ở §17.

## 20. LẬT KIẾN TRÚC: factory mở cho toàn thế giới

User, 2026-08-30:

> *"Hệ thống factory, contract này sẽ open cho toàn thế giới. Ai cũng tạo được, ai
> cũng wrap token thành Meta Token được. Ai cũng wrap token thành Zether được. Thị
> trường sẽ quyết định dùng cái nào. Tôi chỉ deploy factory thôi."*
>
> *"Ví dụ wrap xDAI => zDAI, 10 người có thể wrap thành 10 contract khác nhau, kệ họ."*

Đây **không phải một yêu cầu tính năng**. Nó đổi vai của toàn bộ dự án: từ *nhà phát
hành token* sang *người deploy protocol*. Hầu hết các quyết định mở trong canon là
quyết định của nhà phát hành, và chúng không còn thuộc về ta nữa.

### 20.1 D1 tan biến. Hỗ trợ CẢ HAI curve

Không còn "curve của hệ thống". `curve_profile` không phải cấu hình toàn cục — nó là
thuộc tính của **từng token**, do người tạo token chọn qua địa chỉ verifier.

Thiết kế đã sẵn sàng cho việc này (verifier inject, không import cứng), nhưng có một
chỗ **phải sửa và đã sửa**: kiểu điểm.

| | bn254 | BLS12-381 |
|---|---|---|
| Fp | 254 bit, vừa một `uint256` | 381 bit; EIP-2537 pad thành **64 byte** |
| **G1 point on-chain** | **64 byte** | **128 byte** — đã đo `eth_call` 0x0b trên Gnosis |
| Scalar field `r` | 254 bit | 255 bit |
| Precompile | 0x06/0x07/0x08, có từ Byzantium 2017 | 0x0b…0x10, cần Prague |
| Gas ở k=277 (đo thật) | 1,70 M | 1,74 M |
| An toàn | ~100 bit | ~126 bit |

Nên `struct G1Point { uint256 x; uint256 y; }` **không dùng làm kiểu chung được** —
nó là kiểu của bn254. Interface chung nhận điểm dạng `bytes`, mã hoá theo
`proofSystemId()`. Điều này còn **rẻ hơn**: gói cả bó điểm vào một blob bỏ được toàn
bộ ABI offset của mảng động.

**Chi phí thật của việc hỗ trợ hai curve**, nói thẳng để đây là quyết định chứ không
phải mong muốn:

| Hạng mục | Chi phí |
|---|---|
| Verifier contract | **2×** — scalar field khác nhau nên không chia sẻ code được, chỉ chia sẻ cấu trúc. Đây là hạng mục audit đắt nhất |
| Prover Rust | ~1,3× — arkworks generic over `Pairing`; gadget Bulletproofs dùng chung, chỉ khác instantiation |
| Interface | 0 — đã curve-agnostic |
| Odoo addon | ~0 — `proof_system_id` vốn đã là một chuỗi |
| **Interop giữa hai curve** | **không có, và không thể có.** Z-token bn254 không chuyển bí mật sang Z-token BLS được. Cầu nối là unwrap → wrap. Đây là bản chất, không phải thiếu sót |

Và một cái bẫy phải ghi ra: **UA phụ thuộc curve.** Cùng một con người trên hai curve
có hai UA khác nhau — hai keypair trên hai nhóm khác nhau, không phải một danh tính
hai cách viết. Ví tuyệt đối không được gộp chúng thành một dòng số dư.

Spike S7 (§17) **không phí**. Nó chuyển từ *"quyết định của ta"* thành *"con số người
tạo token đọc để tự chọn"*, và nó là hướng dẫn thật:

> bn254 — gas ngang nhau, chạy trên **mọi** chain EVM, hệ sinh thái thư viện sâu, ~100 bit.
> BLS12-381 — đắt hơn ~2% ở quy mô Bulletproofs, chỉ chạy trên chain có Prague, ~126 bit.
> Chọn BLS khi và chỉ khi chân trời bảo mật vượt quá thời hạn an toàn của bn254.

Chain private 9000 chỉ chạy được bn254. Đó là dữ kiện triển khai, không còn là quyết
định kiến trúc.

### 20.2 KHÔNG CÓ UPGRADE. Version nằm ở factory, bất biến nằm ở token

User chốt:

> *"Và không có upgrade cho zDAI-A, zDAI-B. Factory sẽ đăng ký các version zether
> implement v1, v2, v3 … hoặc meta token v1, v2, v3. User create zether xDAI-A, xDAI-B
> tùy họ chọn implement version."*

Đây là mô hình sạch hơn hẳn bản tôi đề xuất trước đó (clone bất biến **hoặc** UUPS do
người tạo sở hữu). Bỏ luôn UUPS. **Chỉ còn EIP-1167 clone.** Người tạo cũng không nâng
cấp được token của chính mình.

Canon §01 mục 1 chốt **Beacon proxy** và tự ghi nhận *"blast radius = toàn bộ N token"*.
Trong hệ đóng nơi ta sở hữu cả N token đó là **ưu điểm** — vá 40 token bằng 1 giao
dịch. Với factory mở thì cùng cơ chế đó nghĩa là chủ beacon thay được implementation
của mọi token mà mọi người lạ từng tạo, im lặng, một giao dịch. Loại.

#### Chỗ tách đôi mà toàn bộ thiết kế xoay quanh

| | Ai đổi được | Ảnh hưởng tới |
|---|---|---|
| **Catalogue version** ở factory | thêm được v4 | **chỉ token deploy SAU đó** |
| **Token đã deploy** | **không ai** | — |

Đăng ký v4 không chạm được một byte nào của zDAI-A đang chạy v1. Đó là khác biệt
tuyệt đối so với beacon, nơi đổi implementation là đổi hành vi của mọi token đang lưu
hành, ngay lập tức.

Nên câu hỏi *"ai được đăng ký version"* **không** phải câu hỏi về quyền lực lên tiền
người khác. Kẻ đăng ký tệ nhất cũng chỉ xuất bản được một v4 dở mà người tạo token mới
có thể chọn hoặc không.

#### Ba bất biến của catalogue

1. **Append-only.** `(kind, version)` đã đăng ký thì **không bao giờ trỏ lại chỗ khác**.
   Nếu `v1` trỏ lại được thì *"tôi muốn v1"* thành mục tiêu di động: người tạo đọc mã
   nguồn v1 hôm nay, deploy tuần sau, nhận về implementation khác. Cho phép sửa trỏ là
   dựng lại đúng cái quyền mà việc bỏ beacon vừa xoá — chỉ khác là nó tác động lên
   token tương lai thay vì token hiện tại.
2. **`deprecate()` đánh dấu, KHÔNG chặn.** Chặn ở đây là trấn an: `createUnregistered`
   bỏ qua catalogue hoàn toàn, nên mọi rào đều đi vòng được bằng một tham số. Rào đi
   vòng được không mua thêm an toàn, chỉ mua cảm giác an toàn — và đổi lấy quyền chặn
   người khác deploy, thứ factory mở không nên có. Việc thật là phát tín hiệu: event,
   ví hiện cảnh báo, indexer đánh dấu token đang chạy version đó.
3. **`createUnregistered` phải tồn tại.** Nếu chỉ version đã đăng ký mới deploy được
   thì người giữ quyền đăng ký quyết định được cả thế giới được tạo cái gì, và
   *"ai cũng tạo được"* thành khẩu hiệu. Token sinh ra đường này có `version() == 0`, và
   số 0 đó **cố ý nhìn thấy được** — ví phân biệt được "chạy v2 đã công bố" với "chạy
   code người tạo tự mang tới". Cả hai hợp lệ; người sắp nạp tiền có quyền biết.

#### Cái giá, nói thẳng

**Một lỗi trong v1 là lỗi vĩnh viễn của mọi token trên v1.** Không có bản vá, không có
đường tắt, không có ngoại lệ khẩn cấp. Đường duy nhất: người tạo deploy token mới trên
v2, người dùng `unwrap` khỏi cái cũ và `wrap` vào cái mới — di cư tự nguyện, từng người
một, không ai bị ép.

Đó chính xác là thứ mua được bằng việc bỏ upgrade: **không tồn tại một nút bấm nào, của
bất kỳ ai, thay đổi được contract đang giữ tiền của bạn.** Không có nút thì không có ai
để phải tin, và không có gì để bị đánh cắp quyền.

Hệ quả kèm theo là dọn dẹp: `getWrapperCount(creator, underlying) > 1` giờ mang nghĩa
mới và hữu ích — "ông A có zDAI trên v1 và zDAI trên v2" là cách **duy nhất** còn tồn
tại của việc nâng cấp, và nó hiện ra như hai địa chỉ chứ không phải một trạng thái ẩn.

Và: chuỗi CREATE2 **ba tầng** của canon §1.4 mất lý do tồn tại. Nó có mặt chỉ để giữ
địa chỉ ổn định qua các lần nâng cấp. Không còn nâng cấp thì còn hai tầng, và với
EIP-1167 thì `init_code` chỉ phụ thuộc `implementation` nên `predictAddress` xác định
hoàn toàn và tính được off-chain.

### 20.3 Mỗi người tạo một wrapper. `getWrapper` GIỮ, đổi khoá

User đính chính (tôi đã đọc sai ở lần đầu):

> *"Không bỏ getWrapper. Và hiểu ý sai rồi. Ông A wrapper thì ra zDAI-A, Ông B wrap
> thì ra TokenContract zDAI-B .v.v. Thị trường sẽ tự quyết định dùng zDAI-a nhiều hay
> zDAI-b nhiều. Hai cái có 2 địa chỉ khác nhau."*

Tôi đã hiểu *"10 người wrap ra 10 contract, kệ họ"* thành **"không có tra cứu nào"**.
Sai. Ý đúng là **không có wrapper chính thức**, không phải không có tra cứu — mỗi
người tạo có wrapper của riêng mình, và nó tra được.

Khác biệt nằm ở **khoá**, không ở việc có hay không có hàm:

| Câu hỏi | Có đáp án? |
|---|---|
| `getWrapper(A, xDAI)` — *"wrapper xDAI của ông A là cái nào"* | **có, đúng một** |
| `getWrapper(xDAI)` — *"wrapper xDAI là cái nào"* | **không**, và một hàm trả một địa chỉ cho câu này sẽ nói dối |

Nên bản Grok không sai vì có `getWrapper`; nó sai vì khoá trên riêng `underlying`.
Đổi khoá thành `(creator, underlying)` là xong, và hàm trở nên đúng.

Ba mức tra cứu, ba câu hỏi khác nhau:

```solidity
// "wrapper xDAI của ông A"  -> một địa chỉ
getWrapper(creator, underlying) -> address

// "ông A có mấy wrapper xDAI"  -> A vẫn có thể có nhiều: một bn254, một BLS12-381,
// hoặc hai biểu phí. getWrapper trả cái đầu tiên, đây là danh sách đầy đủ.
getWrapperCount(creator, underlying) / getWrapperAt(creator, underlying, i)

// "có những zDAI nào trên đời, của ai"  -> để thị trường so sánh A với B
deployCountFor(underlying) / deployedFor(underlying, i)
```

**Không ràng buộc duy nhất trên riêng `underlying`.** Không duyệt tên, không duyệt
symbol. `zDAI-A` và `zDAI-B` cùng tồn tại là trạng thái bình thường, không phải xung
đột cần giải quyết.

**Tín hiệu xếp hạng không cần hàm mới.** `IERC20(xDAI).balanceOf(zDAI_A)` là lượng
tài sản thật đang bị khoá sau wrapper của A. Thị trường bỏ phiếu bằng tiền, và phiếu
đó đọc được on-chain miễn phí. Factory không xếp hạng hộ ai — đó đúng là phần
*"thị trường tự quyết định"*.

### 20.4 Bỏ gác cổng thì phải bù bằng xuất xứ kiểm được

"Kệ họ" không được biến thành "không ai kiểm được gì". Mười zDAI, chín cái có thể là
giả — đây đúng là bài toán token-list của ERC-20, và lời giải đã biết **không phải**
allowlist, mà là **provenance kiểm được on-chain**:

- Token trả lời bất biến: `factory()`, `creator()`, `underlying()`, `verifier()`
- Factory giữ `isDeployedHere(token)` để đối chiếu ngược — một contract tự khai
  `factory()` mà factory không xác nhận thì đó chỉ là một chuỗi tự khai

Điều này trả lời chính xác *"contract này có đúng là wrap xDAI bằng verifier X do địa
chỉ Y tạo không"*.

Nó **không** trả lời *"đây có phải cái zDAI tôi nên dùng không"*. Câu đó không có đáp
án on-chain, và giả vờ là có mới là chỗ nguy hiểm thật. Đó là câu hỏi của danh tiếng
và thanh khoản — của thị trường, đúng như thiết kế.

### 20.5 Những gì rơi khỏi đường tới hạn

Đây là quyết định của **nhà phát hành token**, không phải của protocol. Protocol cung
cấp nút bấm; ai tạo token thì người đó vặn và người đó chịu.

| Canon | Vì sao rơi |
|---|---|
| **D3** chân trời bảo mật | Người tạo token chọn curve theo chân trời của họ |
| **D6** giấy phép VN | Ta deploy protocol, không phát hành token. **User đã nói để sau — không nêu lại** |
| **D9** số dư điểm thưởng có cần bí mật không | Ai tạo token loyalty thì người đó chọn |
| **D10** chain và archetype của loyalty | Như trên |
| **D13** một bit rò rỉ khi chia nhỏ B2B | Thuộc về `ringSize()` và tham số token, do người tạo chọn |
| **`compliance_profile`** trên contract | Không có ở tầng contract. Nó là thuộc tính bên Odoo, mô tả token mà **bản triển khai này** chọn tương tác |
| **AML ⇒ ring = 2** | Ring size là thuộc tính verifier. Ring 2 lộ danh tính, ring lớn ẩn danh. Hai thị trường, hai lựa chọn |
| **`C_aud` auditor key** | **Tuỳ chọn theo token**, không bắt buộc. Người tạo muốn kiểm toán được thì bật |

### 20.6 Những gì NẶNG THÊM

Đổi lại, ba thứ nặng lên và phải nhận:

1. **Factory là artefact bảo mật quan trọng nhất, và nó bất biến.** Không có "vá sau".
   Sai một dòng trong factory là sai vĩnh viễn cho mọi token mọi người từng tạo. Ngân
   sách audit phải dồn về đây, không dàn đều.
2. **Không kiểm soát được ai dùng vào việc gì.** Đó là bản chất của permissionless và
   user đã chọn nó có chủ ý. Điều làm được: tài liệu rõ, verifier tham chiếu chất
   lượng cao, và **không tự nhận vai trò mình không giữ**.
3. **`isSupportedOnThisChain()` trở nên bắt buộc.** Một verifier BLS12-381 deploy
   **thành công** trên chain không có EIP-2537 rồi revert ở mọi proof mãi mãi —
   precompile vắng mặt không revert, nó trả về thành công với output rỗng. Không có
   triệu chứng nào cho tới khi đã có người nạp tiền. Trong hệ đóng ta biết chain của
   mình; trong factory mở thì không.

## 21. Open Relayer: hai mode, hai bản cài đặt

User chốt:

> *"App cho Open Relayer network có thể làm việc theo 2 mode: 1. Chỉ đơn thuần relay
> transactions đến blockchain. 2. Tham gia network, ngoài việc relay tx đến các
> blockchain, các tx không phù hợp với nó được đưa vào pool, relay đến các node khác."*
>
> *"A. Có thể chạy độc lập không liên quan đến odoo, addons... viết bằng Rust. Có API
> cho các node khác và RPC API cho client (web/desktop, wallet). B. Version thứ 2, song
> song, viết theo kiểu odoo addons."*

### 21.1 Hai mode

| Mode | Làm gì | Ai chạy |
|---|---|---|
| **1. Relay thuần** | Nhận intent qua RPC, ký, đẩy lên chain. Không gossip, không pool, không peer | Doanh nghiệp tự chạy gas station cho chính mình. Đây chính là *"relay pool nội bộ"* ở §3.4b — không cần mạng nào cả |
| **2. Node mạng** | Mode 1, cộng: intent **không hợp acceptance policy của mình** thì **không vứt đi mà đẩy vào pool và gossip sang node khác** | Ai muốn tham gia mesh mở |

**Điểm hay nhất nằm ở mệnh đề "tx không phù hợp với nó được đưa vào pool, relay đến
các node khác".** Nó biến acceptance policy (§6 mục 5) từ một bộ lọc thành một **bộ
định tuyến**, và đó là chỗ thiết kế này hơn 0x-mesh.

0x-mesh gossip mọi thứ tới mọi người và để từng node tự lọc — nên mỗi node trả chi phí
băng thông cho toàn bộ lưu lượng của mạng, kể cả phần nó không bao giờ nhận. Ở đây,
một node từ chối một việc vẫn **chuyển tiếp** nó, nên:

- Intent phí 0 nhắm contract đối tác đi thẳng tới node đối tác thay vì lang thang.
- Một node chuyên một chain không phải mang lưu lượng của sáu chain kia.
- Mạng vẫn liên thông mà không cần mọi node biết mọi thứ.

Ràng buộc kèm theo, phải thiết kế ngay chứ không vá sau: **chuyển tiếp phải có
TTL/hop-count và dedup theo `intent_id`**, nếu không hai node có policy loại trừ nhau
sẽ đẩy qua đẩy lại một intent cho tới khi nó hết hạn. Đây là bài toán định tuyến, và
nó có bẫy định tuyến — gossipsub v1.1 lo phần chống lụt, không lo phần vòng lặp ở tầng
ứng dụng.

### 21.2 Một bản cài đặt của ta, và một hợp đồng cho người ngoài

> **[SỬA §23.8]** Bản đầu của mục này chốt **hai** bản cài đặt song song — A Rust standalone và B Odoo
> addon. §23.3 gộp tầng daemon thành một binary Rust, và điều đó xoá lý do tồn tại của B. Viết lại.

| | **Node** — `bamboo-node` (Rust) | **Control plane** — addon Odoo |
|---|---|---|
| Là gì | tiến trình mạng: gateway, mesh, pool, submit, indexer | ERP quyết định chi tiền và đọc kết quả |
| Phụ thuộc | **không có Odoo, không có addon** | chạy trong Odoo |
| Đối tượng | ai cũng chạy được — mesh là mở, và phần lớn thế giới không dùng Odoo | bản triển khai DMS |
| Giao tiếp với nhau | outbox Postgres một chiều vào, bảng kết quả một chiều ra (§22.9) | như bên trái |
| Có gossip không | **có** | **không** |
| Có giữ pool không | **có** | **không** |
| Có ký vỏ tx không | có — xin làn custody ký bằng `authKey` | **không** |

Lý do bản đầu đưa ra cho B — *"một site DMS đã có Odoo, bắt họ vận hành thêm một tiến trình Rust là chi
phí không đổi lấy gì"* — đúng khi lựa chọn là "thêm bốn daemon hai ngôn ngữ". Sau §23.3 lựa chọn là
**một binary tĩnh**, và cái giá của việc giữ B thì không hề giảm: hai bản cài đặt của cùng một giao thức
gossip là đúng chỗ lỗi bất đồng thuận sinh ra (§21.3). Một site DMS chạy `bamboo-node` như chạy bất kỳ
daemon nào khác — nginx, redis, postgres đã có sẵn ở đó rồi.

Điều **không** đổi: mạng vẫn mở thật. Bất kỳ ai cũng chạy được node mà không cần Odoo — đó vẫn là điều
kiện để "mở cho toàn thế giới" không phải khẩu hiệu.

### 21.3 Hệ quả nặng nhất: giao thức phải có SPEC, không chỉ có code

> **[SỬA §23.8]** Kết luận của mục này giữ nguyên; **lý do đổi, và lý do mới mạnh hơn.**

Bản đầu lập luận: ta viết hai bản cài đặt, nên phải có spec để chúng không lệch nhau. Sau §23.8 ta chỉ
viết một bản — nhưng spec **vẫn bắt buộc**, vì lý do tốt hơn: **mạng là mở, nên người lạ sẽ viết bản của
họ.** Node A chấp nhận một intent mà node B từ chối, hoặc hai bên tính `intent_id` lệch nhau một byte, là
mạng chia đôi âm thầm — và ta không kiểm soát được node B là ai.

Một spec chỉ để ta đồng bộ với chính mình là thứ dễ bị bỏ khi gấp. Một spec là **hợp đồng với người
ngoài** thì không: bỏ nó nghĩa là mạng mở không mở được.

Nên thứ tự vẫn là: **spec trước, code sau** — không phải viết bản Rust rồi coi nó là spec. Ba thứ bắt buộc:

1. **Wire format cố định bằng văn bản**: encoding của intent, cách tính `intent_id`, digest EIP-712,
   topic name, và thứ tự byte. Một bảng, không phải một struct Rust.
2. **Bộ vector tuân thủ (conformance vectors)** công bố công khai: N intent mẫu kèm `intent_id` và digest
   kỳ vọng. Bản cài đặt của ta chạy nó trong CI; **bất kỳ ai viết node cũng chạy được nó** để tự kiểm
   trước khi vào mesh. Đây là thứ rẻ nhất chặn được drift.
3. **Test liên thông (interop)**: hai node trong cùng một mesh gossip qua lại được và cùng relay được một
   intent thật. Với một bản cài đặt, "hai node" là hai tiến trình cùng binary khác cấu hình — vẫn bắt
   được lỗi wire format, không bắt được lỗi hiểu spec. Lỗi loại sau chỉ lộ ra khi có bản cài đặt thứ hai
   thật, nên **bộ vector ở mục 2 là thứ duy nhất đứng thay được**, và vì thế nó phải đầy đủ chứ không
   phải tượng trưng.

Điểm này nối với `_REVIEW-01-UPGRADE.md`: relayer **không nằm trên đường tới hạn của giai đoạn private**
(chain 9000 có `MinGasPrice = 0`, gas miễn phí, không cần relayer nào). Nhưng spec giao thức thì nên chốt
sớm, vì nó rẻ khi còn trên giấy và đắt khi đã có node của người khác chạy lệch.

### 21.4 Node là MA TRẬN NĂNG LỰC, không phải hai mode

User bổ sung:

> *"Bộ định tuyến có thể linh động, làm nhiều vai. Chỉ là pool thuần, không có key để relay đến
> chain, chỉ relay sang node khác. Có thể tách riêng Open pool (relay đến node khác) và private pool
> (chờ private relayer khác lấy đẩy lên chain). Có thể vừa relay đến node khác, vừa đẩy tx lên chain,
> tùy vào network và smartcontract và có thuật toán tối ưu fee. Có thể phải có matrix config."*

**Hai mode ở §21.1 là cách nhìn sai, và phải thay.** "Mode 1 / mode 2" gợi ý một enum toàn cục, trong
khi thực tế có **ba trục độc lập**, và trục thứ ba còn **thay đổi theo từng đích đến**:

| Trục | Giá trị | Ghi chú |
|---|---|---|
| **Ingest** | nhận qua HTTP / nhận qua gossip / cả hai / không nhận | Node chỉ submit thì không cần ingest công khai |
| **Pool** | `open` (gossip ra mesh) / `private` (giữ, chỉ phục vụ peer được phép) / `none` | Đây là trục user vừa thêm |
| **Submit** | có key + có gas → đẩy lên chain / **không có key** → chỉ chuyển tiếp | **Theo từng `(chain, contract)`**, không toàn cục |

Trục thứ ba là chỗ "ma trận" đến từ: một node hoàn toàn có thể **submit trên Gnosis nhưng chỉ forward
cho chain 9000**, vì nó có gas trên chain này mà không có quyền trên chain kia. Một enum không diễn
đạt được điều đó.

#### Sáu vai, sinh ra từ ba trục

| Vai | Ingest | Pool | Submit | Vì sao tồn tại |
|---|---|---|---|---|
| **Pool thuần** | gossip | open | **không có key** | Chạy được bởi bất kỳ ai, không cần tiền, không cần tin tưởng. Đây là thứ làm mạng **thật sự mở** — rào vào thấp nhất có thể |
| **Gateway** | HTTP | none | có | Nhận từ ví/web, ký, đẩy. Không tham gia mesh. Đây là "mode 1" cũ |
| **Node đầy đủ** | cả hai | open | **theo ma trận** | Vai chính của mesh |
| **Private pool** | cả hai | **private** | không | Giữ intent không nên phát công khai, chờ relayer được phép lấy |
| **Private relayer** | kéo từ private pool | none | có | Đối tác của private pool. Cặp này là mô hình private mempool kiểu Flashbots |
| **Observer** | gossip | open | không | Chỉ index. Không có chính sách, không claim. Hữu ích cho explorer và cho đối soát |

#### Private pool: vì sao cần, và cái bẫy của nó

Ba lý do chính đáng để **không** gossip một intent ra mesh mở:

1. **Giá trị rò rỉ khi bị nhìn thấy** — front-run, sandwich. Đây là lý do private mempool tồn tại
   trên Ethereum.
2. **Intent của chain private** không nên xuất hiện trên mesh công khai chút nào, kể cả dưới dạng
   summary — nó lộ đối tác, tần suất, và quy mô (§5.4.5).
3. **Đối tác độc quyền**: sponsor trả tiền cho một relayer cụ thể, không muốn đấu giá.

**Bẫy, và nó nghiêm trọng:** một intent vào private pool mà relayer đối tác chết thì nó **chết im
lặng** — người gửi không biết, không có ai khác thấy nó, và nó chỉ biến mất khi hết hạn. Đó là một
chế độ hỏng tệ hơn hẳn "không ai nhận" trên mesh mở, vì trên mesh mở người gửi ít nhất thấy intent
của mình còn sống.

Bắt buộc kèm theo: **promote-to-open sau `T` giây chưa ai claim** (mặc định `T = expiry / 3`), trừ
khi người gửi đặt cờ `never_public`. Cờ đó phải là lựa chọn tường minh của người gửi, không phải mặc
định của node — và khi bật, người gửi chấp nhận rằng liveness phụ thuộc đúng một đối tác.

#### Ma trận cấu hình

Hình dạng cụ thể, và điều kiện quan trọng nhất nằm ở dòng cuối:

```yaml
defaults:            { ingest: gossip+http, pool: open, forward: true, submit: false }

chains:
  100:                                   # Gnosis
    submit: true
    max_gas_price_gwei: 5
    targets:
      "0xPARTNER...":  { min_fee: 0, priority: high }    # doi tac: nhan ca fee = 0
      "*":             { min_fee_native: "200000000000000" }

  9000:                                  # private chain
    pool: private                        # KHONG gossip ra mesh cong khai
    submit: false                        # cho private relayer lay
    peers_allowed: ["12D3Koo..."]
```

**Ma trận phải đánh giá được TRƯỚC khi simulate.** Nó chỉ được đọc các trường có sẵn trong intent —
`chain_id`, `to`, `tokenContract`, `fee`, `feeMode`, `innerGasLimit`. Đó là điều làm nó rẻ (một phép
so khớp, không một `eth_call` nào) và là lý do acceptance policy chạy được ở tốc độ gossip. Một luật
cần simulate mới quyết được thì không thuộc về ma trận này; nó thuộc về bước định giá ở §5.3.

#### Thuật toán submit-vs-forward, và một bẫy hợp tác

Quy tắc ngây thơ *"nếu có lãi thì submit, không thì forward"* **sai ở một chỗ**: nếu một node vừa
định submit vừa forward cùng lúc, nó tự tạo đối thủ cho chính mình và làm một node khác đốt gas vô
ích. Đó chính là cuộc đua relayer (§6 mục 4) mà mạng đang cố tránh.

Quy tắc đúng:

```
policy = matrix.match(intent)                      # re, khong simulate
if not policy.accept:            forward(intent); return      # khong phai viec cua minh
if not policy.submit:            forward(intent); return      # khong co key cho chain nay
if not profitable(intent):       forward(intent); return      # nguoi khac co the co cau truc chi phi khac
claim(intent)                                                  # danh dau exclusive, co han
forward(intent, exclusive_until=now+W)                         # van forward, NHUNG kem han doc quyen
submit(intent)
```

Điểm mấu chốt ở hai dòng cuối: **vẫn forward, nhưng kèm `exclusive_until`**. Mạng vẫn biết intent tồn
tại (nên nếu node này chết, node khác nhặt sau khi hết hạn độc quyền), mà không ai lãng phí gas trong
cửa sổ đó. Đây là soft-exclusivity của §5.4 áp dụng ở tầng mesh thay vì tầng hub.

Với intent Zether, `W = 0` (§5.1.1): ngân sách 20 giây không chịu nổi một cửa sổ độc quyền. Ở đó,
chấp nhận đua và chấp nhận lãng phí — hoặc dùng private pool.

#### Hệ quả: pool thuần không bị phạt được bằng kinh tế

Một node không có key thì **không tốn gì để chạy**, nên nó cũng không mất gì khi cư xử tệ. Kinh tế
học không bảo vệ được lớp này; peer scoring của gossipsub v1.1 phải làm.

Và điểm này quyết định cách chấm điểm: **chấm theo forward CÓ ÍCH, không theo lưu lượng.** Một
forward có ích = một intent mà node này chuyển tiếp và sau đó **thật sự lên chain**. Chấm theo lưu
lượng thì một node bơm rác được điểm cao; chấm theo kết quả thì nó không được gì. Điều kiện để làm
được: node phải quan sát chain (hoặc nhận receipt gossip) để biết intent nào đã landed — nên
`/receipt` của §5.2 không chỉ là tiện ích vận hành, nó là **đầu vào của hệ thống danh tiếng**.

### 21.5 Pool khoá ký: một khoá là một nút thắt cổ chai

User: *"Node Relayer thậm chí có khả năng quay vòng khoá dùng submit lên chain để không bị nghẽn ở 1
khoá duy nhất."*

Đúng, và nó **không phải tối ưu hoá — nó là ràng buộc cứng của EVM**. Nonce của một EOA là tuần tự
tuyệt đối: transaction nonce `n+1` không vào block được trước `n`. Hệ quả:

- Một tx bị kẹt (gas price dưới đáy mempool, hoặc nonce gap) **chặn toàn bộ hàng đợi phía sau nó**.
  Đây là head-of-line blocking, và với một khoá duy nhất thì một tx kẹt = relayer chết hoàn toàn cho
  tới khi ai đó can thiệp.
- Thông lượng trần của một khoá ≈ 1 tx/block trong thực tế vận hành an toàn. Trên Gnosis (5 s) đó là
  **0,2 tx/s**. Muốn 10 tx/s thì cần ~50 khoá, không phải một khoá nhanh hơn.

#### Vì sao xoay khoá MIỄN PHÍ ở thiết kế này

Vì `_USER-DECISIONS.md` §5 chốt **wildcard `relayer == address(0)`** thay cho mode bitmask có tên
relayer. Intent không nêu tên relayer nào, nên **đổi khoá ký không làm hỏng chữ ký nào cả**.

Nếu đã chọn `MODE_RESTRICT_RELAYER` với một địa chỉ cụ thể trong digest, thì mỗi lần xoay khoá là một
lần phải xin chữ ký lại từ mọi người dùng. Quyết định wildcard được đưa ra vì lý do khác (chống
cross-mode replay), và đây là một lợi ích kèm theo mà lúc đó chưa ai tính.

#### `feeRecipient` và khoá ký là hai thứ khác nhau — và đó là điều làm xoay khoá chạy được

*(Mục này thay cho một đoạn sai ở bản trước. Bản trước viết rằng `feeRecipient` do người gửi chỉ định
"làm thị trường mở không chạy được, vì không relayer lý trí nào nhận việc khi phí không về tay
mình". **Kết luận đó sai**, và nó sai vì lập luận bằng mô hình "relayer tối đa hoá lợi nhuận trên
từng intent" — đúng cái mô hình mà §3.4b và §5.3.4 đã bác bỏ.)*

**Vì sao kết luận cũ sai.** Relayer được trả bằng nhiều đường, và phần lớn không phải qua trường
`fee` của intent:

| Đường | `fee` trên intent | `feeRecipient` |
|---|---|---|
| Hợp đồng dịch vụ với issuer | thường **0** | không liên quan |
| Issuer tài trợ qua `SponsorshipPool.settle()` | 0 | pool trả thẳng cho `msg.sender` |
| Relayer **là** bên hưởng lợi (distributor giữ đường settlement của chính mình) | 0 | không liên quan |
| Đối tác, thu hồi ngoài chuỗi | 0 | không liên quan |
| Thị trường mở thuần tuý | > 0 | mới là chỗ nó quan trọng |

Bốn hàng đầu là **đa số các trường hợp thật** (§5.3.4: trên chain gas rẻ, phí bù gas không nuôi nổi
một thị trường relayer độc lập; ai relay là vì lý do khác). Với chúng, `feeRecipient` trỏ đi đâu
không đổi hành vi của ai.

**Và điểm quan trọng hơn, mà bản trước bỏ hẳn: `feeRecipient` cố định là thứ một relayer xoay khoá
CHỦ ĐỘNG MUỐN.** Hai trường trả lời hai câu hỏi khác nhau:

| Trường | Câu hỏi | Giá trị tự nhiên với pool khoá |
|---|---|---|
| `relayer` | **Ai được phép submit?** | `address(0)` — để xoay tự do quanh N khoá |
| `feeRecipient` | **Tiền về đâu?** | **một địa chỉ cố định** — ví lạnh thu phí |

Đó chính là cấu hình mà §21.5 mô tả ở phần bảo mật: khoá ký giữ float nhỏ và **không bao giờ là nơi
nhận phí**. Nếu `feeRecipient` bám theo khoá ký thì phí rơi rải rác trên N ví nóng — đúng thứ phải
tránh. Nên với một relayer có pool khoá, `feeRecipient` **phải** là một địa chỉ cố định, và
`relayer = address(0)` là thứ cho phép nó xoay khoá bên dưới.

User diễn đạt đúng luồng thật, và nó là luồng UI chứ không phải luồng giao thức:

> *"Có thể do UI của Node Relayer: Tôi muốn người nhận fee là người này, và hãy để địa chỉ relayer = 0
> để tôi còn roll quanh các ví gửi của tôi."*

Nghĩa là **relayer công bố `feeRecipient` của mình, người gửi điền vào**. Không cần wildcard nào cả.

#### Điều còn lại phải làm, nhỏ hơn nhiều

Hai thứ, và không thứ nào là sửa lỗ hổng:

1. **`/policy` phải công bố `fee_recipient` của node** (§5.2). Không có nó, người gửi không biết điền
   gì và phải hỏi ngoài băng. Một trường trong một endpoint đã tồn tại.
2. **`feeRecipient == address(0)` nghĩa là "trả cho `msg.sender`"** — giữ, nhưng đúng vai của nó: một
   **tiện ích cho trường hợp người gửi không biết và không quan tâm ai sẽ relay**, không phải điều
   kiện để thị trường tồn tại. Nó vẫn nằm **trong digest**; wildcard là một giá trị quy ước, không
   phải một trường bị loại khỏi chữ ký.

Và một luật cho ma trận §21.4, đọc được trước khi simulate: node chấp nhận intent khi
`feeRecipient ∈ {address(0), <ví thu phí của mình>}` **hoặc** khi ma trận nói nhận bất kể phí
(`min_fee: 0` cho contract đối tác). Vế thứ hai là vế quan trọng — thiếu nó, node đối tác tự loại
mình khỏi đúng luồng nó sinh ra để phục vụ.

#### Thiết kế pool khoá

```
KeyPool:
  keys[]: { address, nonce_local, in_flight, balance_native, stuck_since }
  hot_treasury: mot khoa RIENG, giu von, nap gas cho cac key
  fee_sink:     mot dia chi LANH, nhan phi. KHONG bao gio la khoa ky.
```

| Quyết định | Chọn | Lý do |
|---|---|---|
| Cách chọn khoá | **least-in-flight**, không round-robin | Round-robin vẫn gửi vào một khoá đang kẹt. Least-in-flight tự tránh nó |
| Nonce | Theo dõi **cục bộ**, không hỏi `eth_getTransactionCount` mỗi lần | RPC trả `pending` không nhất quán giữa các node. Đồng bộ lại từ chain chỉ khi khởi động và khi phát hiện gap |
| Phát hiện kẹt | `stuck_since > 3 block` | Không dùng thời gian tuyệt đối; block time khác nhau theo chain |
| Xử lý kẹt | Thay thế bằng self-send 0 giá trị **cùng nonce**, gas price ×1,25 | Đây là cách duy nhất giải phóng nonce. Huỷ không tồn tại trên EVM |
| Số dư mỗi khoá | Nhỏ, đủ ~50 tx. Treasury nạp lại khi dưới ngưỡng | Xem phần bảo mật dưới |
| Nơi nhận phí | **Không phải khoá ký** | Xem phần bảo mật dưới |

#### Bảo mật: N khoá là N thứ để mất

Đây là cái giá thật của pool khoá, và nó phải được thiết kế chứ không phải chấp nhận.

**Nguyên tắc: khoá ký chỉ được phép làm đúng một việc — trả gas.** Cụ thể:

- Khoá ký giữ số dư nhỏ (đủ ~50 tx). Mất một khoá = mất số tiền đó, không hơn.
- Khoá ký **không** là `feeRecipient`. Phí chảy về một địa chỉ lạnh, và địa chỉ đó không bao giờ ký gì.
- Khoá ký **không** có role nào trên bất kỳ contract nào. Không `MINTER`, không `TREASURY`, không gì
  cả. Một khoá relayer bị lộ phải là một sự cố tài chính nhỏ, không phải một sự cố an ninh.
- Treasury nạp gas là một khoá riêng, giữ nhiều tiền hơn, và **không bao giờ nằm trong đường nóng** —
  nó chỉ chạy theo lịch hoặc theo cảnh báo ngưỡng.

Điều này làm pool khoá trở thành thứ **an toàn hơn** một khoá duy nhất giữ nhiều tiền, không phải kém
an toàn hơn. Đó là lý lẽ chính, và nó ngược trực giác nên phải viết ra.

#### Bảng thông lượng để định cỡ

| Chain | Block time | tx/khoá/block (an toàn) | Khoá cần cho 1 tx/s | cho 10 tx/s |
|---|---|---|---|---|
| Gnosis | 5 s | 1 | 5 | 50 |
| Celo | ~1 s | 1 | 1 | 10 |
| Chain private 9000 | 5 s | 1 | 5 | 50 |

Nhưng trần thật trên chain private **không phải nonce mà là CPU validator** — ~45 confidential tx/s
(§01.1.12.2). Thêm khoá quá con số đó không mua được gì.

#### Còn phải làm

Mục này giao thẳng với §06 (relay pool nội bộ), vốn đã thiết kế một gas station có HSM. Hai chỗ phải
hợp nhất: **cùng một `KeyPool`, hai bối cảnh vận hành** — một cái khoá trong HSM cho doanh nghiệp,
một cái khoá trong file cho một node mesh do cá nhân chạy. Interface giống nhau; nơi giữ khoá khác
nhau, và đó là một tham số cấu hình chứ không phải hai bản cài đặt.

## 22. Vòng đời một meta-tx / Zether tx bên trong một node

> User, 2026-08-31 — tám câu hỏi, giữ nguyên văn vì chúng là mục lục của mục này:
>
> > Sẽ có nhiều câu hỏi xung quanh 1 meta tx và zether:
> > - Nhận từ đâu: Cổng RPC, queue nội bộ hay từ Node Relay khác.
> > - Có hợp lệ: Ví dụ nonce bé hơn nonce cuối cùng ⇒ không hợp lệ. (Chain → Contract → Address → Nonce …)
> > - Có hỗ trợ, hay bị lọc gì không?
> > - Sau đó thì làm gì? Submit to chain, đưa vào pool, relay to other node .v.v.
> > - Nếu submit pool thì làm gì: 2 câu hỏi ai được submit và tiền về đâu
> > - Để trong queue/mempool bao lâu.
> > - Có monitor network để nếu xử lý xong thì sao? Node khác xử lý thì sao?
> > - Có ném kết quả vào queue kết quả, hay callback-hook .v.v.

§21.4 mô tả node **có thể là ai** (ma trận vai). §21.5 mô tả node **ký bằng gì** (pool khoá). Mục này
mô tả cái ở giữa: một intent đi vào node rồi ra khỏi node bằng đường nào. Nó là **spec chung cho cả hai
bản cài đặt** (§21.3) — Rust standalone và Odoo addon phải cho cùng một kết quả trên cùng một intent,
và bộ vector kiểm chứng của §21.3 chính là bộ vector cho máy trạng thái này.

### 22.1 Một máy trạng thái, và ba cái cũ ánh xạ vào nó thế nào

Hiện có ba máy trạng thái rời rạc và chồng lấn: intent trên bus (§05.8.1), job broadcast trong pool
(§06.2.6), và các vai của §21.4. Chúng **không phải ba tầng của một thứ** — chúng là cùng một thứ nhìn
từ ba chỗ. Hợp nhất:

```
                    ┌─────────────────────────────────────────────┐
   ingest ─────────▶│ RECEIVED  (chưa tin gì, chưa tốn gì)        │
                    └──────┬──────────────────────────────────────┘
                           │ hàng rào L0–L2 (§22.3, chỉ CPU cục bộ)
                    ┌──────▼───────┐                  ┌──────────┐
                    │  SCREENED    │──── rớt ────────▶│ REJECTED │ (terminal, có mã)
                    └──────┬───────┘                  └──────────┘
                           │ tra bảng năng lực (§22.4)
              ┌────────────┼─────────────┬──────────────────┐
              ▼            ▼             ▼                  ▼
        ┌──────────┐ ┌──────────┐ ┌────────────┐    ┌──────────────┐
        │ POOLED   │ │ POOLED   │ │ FORWARDING │    │ SUBMITTABLE  │
        │ (open)   │ │ (private)│ │            │    └──────┬───────┘
        └────┬─────┘ └────┬─────┘ └─────┬──────┘           │ L3–L4 (tốn RPC)
             │            │             │                  ▼
             │  promote   │             │           ┌──────────────┐
             └───after T─▶│             │           │  SIMULATED   │
                          │             │           └──────┬───────┘
                          └─────────────┴──────────────────┤ chọn khoá (§21.5)
                                                           ▼
                                                    ┌──────────────┐
                                                    │  BROADCAST   │
                                                    └──────┬───────┘
                                                           │
        ┌──────────────┬───────────────┬───────────────────┼──────────────┐
        ▼              ▼               ▼                   ▼              ▼
   ┌─────────┐   ┌───────────┐   ┌───────────┐      ┌────────────┐  ┌──────────┐
   │ LANDED  │   │ LANDED_   │   │ DROPPED   │      │ SUPERSEDED │  │ EXPIRED  │
   │ (ta)    │   │ ELSEWHERE │   │ (replace) │      │ (nonce đi) │  │          │
   └─────────┘   └───────────┘   └───────────┘      └────────────┘  └──────────┘
```

Ánh xạ với ba máy cũ, để không ai phải đoán:

| Trạng thái ở đây | §05.8.1 (bus) | §06.2.6 (job pool) | Ai sở hữu |
|---|---|---|---|
| `RECEIVED` | `published` | — | tầng ingest |
| `SCREENED` | `validated` | — | tầng ingest |
| `POOLED(open)` | `open` | — | pool |
| `POOLED(private)` | — | `held` | pool |
| `FORWARDING` | `gossiped` | — | mesh |
| `SUBMITTABLE` / `SIMULATED` | `claimed` | `ready` / `simulated` | submit |
| `BROADCAST` | `broadcast` | `sent` | submit |
| `LANDED` | `included` | `mined` | watcher |
| `LANDED_ELSEWHERE` | — (§05 thiếu) | — (§06 thiếu) | watcher |
| `SUPERSEDED` | — | `nonce_consumed` | watcher |
| `EXPIRED` / `REJECTED` | `expired` / `rejected` | `expired` / `dead` | mọi tầng |

Hai trạng thái **mới, và chúng là lý do phải hợp nhất**: `LANDED_ELSEWHERE` (một node khác đã đưa
chính intent này lên chuỗi) và `SUPERSEDED` (một tx khác đã tiêu `meta_nonce` này, intent còn nằm đây
là rác). Cả hai section cũ đều thiếu, và thiếu chúng thì một node mở sẽ đốt gas broadcast những thứ
chắc chắn revert — xem §22.8.

### 22.2 Nhận từ đâu: ba cửa, ba mức tin cậy, không trộn

| Cửa | Đường | Xác thực | Mức tin cậy | Rate limit ở đâu |
|---|---|---|---|---|
| **A. RPC gateway** | `POST /v1/intents`, hoặc `call_kw`/`json/2` với bản Odoo | JWT (§CLAUDE.md §6) hoặc API key, hoặc **mở** nếu node muốn | Cao khi có JWT, thấp nhất khi mở | nginx `limit_req` theo IP, **không** trong process (§05.5 tầng 0) |
| **B. Queue nội bộ** | Bảng outbox trong cùng DB, hoặc Redis stream | Không cần — cùng biên tin cậy | Cao nhất; **bỏ qua L0–L1** | không cần |
| **C. Mesh** | gossipsub v1.1 topic `bamboo/intent/<caip2>/v1` | Chữ ký peer libp2p + peer score | Trung bình, và **giảm dần theo `hop_count`** | peer scoring của gossipsub, cộng trần intent/giây/peer |

Ba quy tắc cứng:

1. **`source` là một trường bất biến trên bản ghi intent**, không phải một biến tạm. Mọi quyết định về
   sau (có gossip không, có tính vào điểm forward không, có được ưu tiên không) đều tra vào nó.
2. **Cửa B không bao giờ được lộ ra ngoài process.** Nếu bản Odoo để `_enqueue_intent` thành một method
   public thì cửa B trở thành cửa A không xác thực. Method phải bắt đầu bằng `_`.
3. **Intent đến từ cửa C với `hop_count >= MAX_HOPS` (mặc định 4) bị bỏ ngay, không phản hồi.** Đây là
   biện pháp chống lặp duy nhất rẻ hơn dedup, vì nó không cần trạng thái.

### 22.3 Có hợp lệ không: thang hàng rào xếp theo giá, và chỗ `meta_nonce` thật sự nằm

Nguyên tắc: **kiểm cái miễn phí trước, và không bao giờ để một kiểm tra tốn RPC đứng trên đường gossip.**

| Tầng | Kiểm gì | Giá | Chạy khi nào |
|---|---|---|---|
| **L0** | Kích thước, độ dài trường, JSON/CBOR hợp lệ, `chainId` là chain node này biết | ~1 µs | mọi cửa |
| **L1** | `expiry > now + skew`; `hop_count`; `intent_id` chưa thấy (bloom filter + LRU) | ~1 µs | mọi cửa |
| **L2** | Digest EIP-712 tính lại và khớp; chữ ký `ecrecover` ra đúng `from`; `mode` nằm trong `MODE_KNOWN_MASK` | ~50 µs | mọi cửa trừ B |
| **L3** | `meta_nonce(from, batchId)` so với **cache trạng thái chuỗi** | ~0 (đọc cache) | trước khi gossip |
| **L4** | `meta_nonce` so với `eth_call` thật; số dư; allowance; `isRegistered` cho Zether | 1 RPC round-trip | **chỉ** trước khi submit |
| **L5** | `eth_estimateGas` / `debug_traceCall` đầy đủ | 1 RPC nặng | chỉ khi node định submit và giá trị vượt ngưỡng |

**Câu hỏi của user — "nonce bé hơn nonce cuối cùng ⇒ không hợp lệ" — thuộc L3/L4, và nó là
`meta_nonce(from, batchId)` chứ không phải nonce EOA.** Hai không gian nonce hoàn toàn khác nhau
(§06.1.8): nonce EOA là của **khoá ký của node** và §21.5 quản; `meta_nonce` là của **người ký intent**
và contract quản. Trộn hai cái là một lớp lỗi riêng.

Đường tra đúng, theo thứ tự user viết (Chain → Contract → Address → Nonce):

```
key   = (caip2, verifying_contract, from_address, batch_id)
known = nonce_cache.get(key)          # None nếu chưa từng thấy cặp này
```

**Đánh đổi mà §22 stub gọi là "chưa ai cân", cân ở đây:**

Kiểm `meta_nonce` bằng `eth_call` ngay lúc nhận thì đúng nhất nhưng không chạy được ở tốc độ gossip —
một node nhận 500 intent/giây sẽ tạo 500 RPC/giây chỉ để lọc rác. Bỏ hẳn thì node gossip rác cho cả
mạng. Chốt **ba tầng cache**, và tầng 2 là thứ làm cho nó chạy được:

1. **Cache dương** (`known`): giá trị `meta_nonce` đọc lần cuối cho `key`, kèm block đọc. TTL = 1 block.
   Reject ngay nếu `intent.nonce < known`. Đây là hàng rào bắt được đa số rác thật.
2. **Cache suy ra từ chuỗi (tầng quan trọng nhất).** Node đã theo dõi log của các contract nó hỗ trợ
   (§22.8 cần watcher đó rồi). Mỗi event `MetaTransactionExecuted(from, batchId, nonce)` **tăng cache
   mà không tốn một RPC nào**. Nghĩa là cache tự cập nhật theo thời gian thực cho mọi cặp đang hoạt
   động, và `eth_call` chỉ cần cho cặp **chưa từng thấy** — đúng một lần cho mỗi `(from, batchId)` mới.
3. **Tra lười:** `key` chưa có trong cache thì **không** gọi RPC ở đường gossip. Intent đi tiếp với cờ
   `nonce_unverified = True`; L4 sẽ tra thật nếu node định submit. Một intent `nonce_unverified` **được
   forward nhưng không được tính vào điểm forward hữu ích** (§21.4) cho đến khi biết kết quả.

Kết quả định lượng: với cặp `(from, batchId)` hoạt động thường xuyên — tức gần như toàn bộ lưu lượng
thật — chi phí kiểm nonce ở đường gossip là **một lần tra hash map**. RPC chỉ trả cho người lạ thật sự,
và một node bị dội bằng `(from, batchId)` ngẫu nhiên sẽ tự bảo vệ bằng chính cờ `nonce_unverified`:
những intent đó không bao giờ được ưu tiên và rơi ra khi hàng đợi đầy.

`meta_nonce` **lớn hơn** `known` là hợp lệ, không phải lỗi: 2D nonce cho phép nhiều lane, và một lane
mới bắt đầu ở 0 trong khi lane khác đã ở 40. Chỉ `<` mới là rác. Đây là chỗ dễ viết sai nhất trong cả
thang hàng rào.

### 22.4 Có hỗ trợ / bị lọc: MỘT bảng tra, không phải hai

§21.4 có ma trận `(chain, contract)` để quyết node làm gì; §06.3.3 có `blockchain.target.policy` để
quyết pool có nhận việc không. **Hai cái là một bảng tra với hai mục đích, và hiện thực hai lần là bảo
đảm chúng sẽ lệch nhau.** Hợp nhất thành một bảng, khoá `(caip2, contract_address, selector)` với
fallback `selector = '*'`:

| Cột | Nghĩa | Ai đọc |
|---|---|---|
| `support` | `none` \| `forward_only` \| `full` | §22.5 |
| `pool_visibility` | `open` \| `private` \| `none` | §22.5, §21.4 |
| `never_public` | chặn promote-to-open vĩnh viễn | §22.7 |
| `submit` | node này có khoá và chịu submit cho cặp này không | §22.5 |
| `max_inner_gas` | trần `innerGasLimit` chấp nhận | L2 |
| `min_fee` / `fee_recipient_allow` | sàn phí, và có nhận `feeRecipient` lạ không | §22.6 |
| `requires_simulation` | ép L5 kể cả khi giá trị nhỏ | §22.3 |
| `calldata_rules` | ràng buộc trên calldata (§04.9) | L2 |

Một dòng `support = 'none'` nghĩa là intent bị **REJECTED có mã**, không phải bị nuốt im lặng: người
gửi cần biết node này không làm được việc đó để đi tìm node khác. Đây là khác biệt giữa một mạng dùng
được và một mạng có những lỗ đen im lặng.

**Bảng phải evaluate được TRƯỚC khi simulate** (§21.4 đã đòi). Nghĩa là mọi cột trên đây phải là dữ
liệu tĩnh, không cột nào được là một hàm gọi ra ngoài.

### 22.5 Sau đó làm gì: submit / pool / forward

Không phải ba lựa chọn loại trừ. Một intent có thể vừa vào pool vừa được forward; cái duy nhất loại
trừ là submit.

```
policy = lookup(caip2, contract, selector)

if policy.support == 'none':                      → REJECTED('unsupported')
if policy.support == 'forward_only':              → FORWARDING (+ POOLED nếu pool_visibility != none)

# support == 'full'
can_submit = policy.submit
             and key_pool.has_capacity(caip2)
             and profitable(intent, policy)       # §22.6
             and not intent.nonce_unverified

if can_submit and not held_by_someone_else(intent):
    → SUBMITTABLE
else:
    → POOLED(policy.pool_visibility) + FORWARDING
```

**`held_by_someone_else` là chỗ §21.4 chốt forward-kèm-`exclusive_until` thay vì forward-rồi-đua.** Khi
một node forward một intent nó cũng định submit, nó gắn `exclusive_until = now + W` vào bản gossip. Node
nhận thấy `exclusive_until` còn hiệu lực thì **giữ trong pool, không submit** — nhưng vẫn forward tiếp.
Hết `W` mà chưa `LANDED` thì ai cũng được submit. `W = 3s` trên Gnosis, và **`W = 0` cho Zether**
(§05.4.4a): một va chạm Zether đốt ~1.79M gas trước khi revert, nên với Zether thì single-flight nghiêm
ngặt qua pool là bắt buộc chứ không phải soft-exclusivity.

`exclusive_until` **không phải một khoá phân tán** — không có ai cưỡng chế nó. Nó là một tín hiệu lịch
sự, và một node bỏ qua nó thì bị hạ điểm bởi chính cơ chế điểm của §21.4 (nó sẽ có nhiều
`BROADCAST → SUPERSEDED` — tức đốt gas mà không land). Đó là cách đúng: động cơ kinh tế, không phải
consensus.

### 22.6 Nếu vào pool: ai được submit, và tiền về đâu

Đây là hai câu hỏi user tách ra, và §21.5 đã trả lời chúng — nhắc lại ở đây vì đây là chỗ chúng được
dùng:

**Ai được submit** = trường `relayer` trong struct meta-tx.
- `relayer == address(0)`: bất kỳ ai. Đây là mặc định của một mạng mở, và là điều kiện để key pool của
  §21.5 chạy được — node xoay khoá ký tự do vì contract không ghim địa chỉ nào.
- `relayer == <địa chỉ cụ thể>`: chỉ khoá đó. Node khác thấy intent này thì **forward, không submit**,
  và nó vẫn được tính điểm forward hữu ích nếu intent sau đó land.

**Tiền về đâu** = trường `feeRecipient`, và nó **độc lập với `relayer`**.
- Một `feeRecipient` cố định + `relayer = address(0)` là **cấu hình đúng của một relayer xoay khoá**:
  phí về một ví duy nhất, còn khoá nào ký thì tuỳ node. §21.5 đòi ví thu phí không phải khoá ký, và
  đây là cách nó được diễn đạt trong struct.
- `feeRecipient` là địa chỉ của người khác, hoặc `fee = 0`: **hợp lệ và không hiếm.** Relayer có thể
  được trả bằng hợp đồng dịch vụ, bởi issuer tài trợ, hoặc chính nó là bên hưởng lợi từ giao dịch. Một
  node không nhận việc này chỉ vì `feeRecipient` khác nó là một node cấu hình hẹp, không phải một node
  lý trí.
- `policy.fee_recipient_allow` quyết định node này có nhận hay không, và `/policy` (§21.3) phải công bố
  nó để người gửi biết trước.

`profitable()` vì thế **không** phải `fee > gas_cost`. Nó là:

```
profitable(intent, policy) =
       intent.fee >= policy.min_fee                    # sàn của node, có thể là 0
   and (intent.fee_recipient in policy.fee_recipient_allow
        or policy.fee_recipient_allow == '*')
   and estimated_gas_cost <= policy.gas_budget_remaining()
```

Một node chạy vì được trả tiền ngoài chuỗi đặt `min_fee = 0` và `fee_recipient_allow = '*'`, và nó vẫn
là một node đúng.

### 22.7 Ở trong queue bao lâu

Bốn đồng hồ chạy song song. Cái nào hết trước thì thắng.

| Đồng hồ | Giá trị | Nguồn | Hết thì sao |
|---|---|---|---|
| `expiry` của chính intent | 60s Zether / 120s call đọc state / 300s ERC-20 / 900s anchor (§04.5) | trong chữ ký | `EXPIRED`, terminal. **Trần cứng, mọi cái dưới đây phải ngắn hơn** |
| `exclusive_until` | 3s Gnosis, 0 cho Zether | node forward đặt | mở khoá cho node khác submit |
| `promote_after` | mặc định 300s | `policy` | `POOLED(private) → POOLED(open)`, trừ khi `never_public` |
| TTL của hàng đợi | `min(expiry, queue_max_age)` | cấu hình node | rơi khỏi hàng đợi, ghi `EXPIRED('queue_pressure')` |

**Không có đồng hồ nào được dài hơn `expiry`.** Giữ một intent quá `expiry` là giữ rác, và nó chiếm chỗ
của intent thật. Một node giữ đầy intent hết hạn là một node có bug, không phải một node thận trọng.

`never_public` tồn tại cho private pool của một doanh nghiệp: calldata B2B không được đi ra mesh công
khai sau 300 giây chỉ vì không ai trong pool riêng nhặt được. Hết `expiry` thì nó chết, và đó là hành
vi đúng — §05.4.5 đã nói bus là một kênh rò rỉ thương mại.

### 22.8 Monitor network: xong rồi thì sao, node khác làm thì sao

Node **phải** có một watcher đọc log của các contract nó hỗ trợ. Watcher này không phải tính năng thêm —
nó là thứ nuôi cache nonce của §22.3, nên nó đã cần thiết từ trước.

| Sự kiện quan sát được | Intent trong node chuyển sang | Hệ quả |
|---|---|---|
| `MetaTransactionExecuted` với đúng `digest` của ta, tx của **ta** | `LANDED` | trả kết quả (§22.9); +1 điểm submit |
| Cùng `digest`, tx của **người khác** | `LANDED_ELSEWHERE` | trả kết quả; **+1 điểm forward hữu ích** nếu ta đã forward nó |
| `MetaTransactionExecuted` khác `digest` nhưng **cùng `(from, batchId, nonce)`** | `SUPERSEDED` | huỷ ngay, **không** broadcast; nếu đã broadcast thì tx của ta chắc chắn revert |
| Không thấy gì, quá `expiry` | `EXPIRED` | trả kết quả với lý do |
| Đã broadcast, tx biến mất khỏi mempool | `DROPPED` | thử lại **cùng lane** với khoá cùng pool, hoặc trả về pool |

Ba điểm dễ làm sai:

1. **`LANDED_ELSEWHERE` phải huỷ tx của ta nếu ta đã broadcast.** Không huỷ được trên chuỗi, nhưng phải
   dừng mọi thao tác bump/replace — bump một tx chắc chắn revert là đốt tiền hai lần.
2. **Dedup theo `digest`, không theo `intent_id`.** `intent_id` do người gửi đặt và hai node có thể thấy
   hai `intent_id` khác nhau cho cùng một chữ ký. `digest` là thứ contract nhìn thấy, nên nó là danh
   tính thật của một intent. `intent_id` chỉ dùng cho dedup ở tầng gossip (rẻ hơn, và ở đó sai một chút
   không sao).
3. **Điểm forward hữu ích tính ở đây, không ở lúc forward.** §21.4 chốt pool thuần được chấm bằng
   "intent sau đó land", và đây là chỗ duy nhất biết được điều đó. Không có watcher thì không có cách
   nào chấm điểm một pool không cầm khoá, và toàn bộ vai "pool thuần" của §21.4 mất động cơ.

### 22.9 Trả kết quả về đâu: queue là mặc định, callback là tuỳ chọn có rào

Hai mô hình, và chúng không thay thế nhau:

**(a) Queue kết quả — mặc định, luôn có.** Mọi intent có một bản ghi kết quả đọc được bằng
`GET /v1/intents/<digest>`, giữ tối thiểu 24 giờ sau khi terminal. Người gửi poll, hoặc mở
`GET /v1/intents/<digest>/stream` (SSE). Không có trạng thái nào ở phía node phụ thuộc vào việc người
gửi có đọc hay không — một người gửi biến mất không để lại gì phải dọn.

Với bản Odoo, queue này **là** một bảng: `blockchain.relay.result`, và bridge đọc nó bằng cron. Không
có HTTP nào trong transaction (§10.4.11, §15.2.4).

**(b) Callback/webhook — tuỳ chọn, và một URL trong intent thì KHÔNG.**

Đây là câu hỏi bảo mật mà stub đã nêu và nó có một câu trả lời dứt khoát: **node không bao giờ gọi một
URL lấy từ nội dung intent.** Lý do:

- **SSRF.** Một intent với `callback_url = http://169.254.169.254/latest/meta-data/` biến mọi node trong
  mạng thành một máy quét metadata cloud của chính nó. Trên một mạng mở, người gửi là người lạ.
- **Khuếch đại.** Một intent được gossip tới N node, N node cùng gọi một URL: mạng relayer trở thành
  một công cụ DDoS mà kẻ tấn công không phải trả gì ngoài một chữ ký.
- **Rò rỉ.** URL nằm trong intent là công khai trên mesh; đặt token vào nó là lộ token.

Chốt: callback **chỉ** cấu hình được ở phía node, cho những người gửi node đó biết:

```
[[callback]]
subject      = "did:key:z6Mk..."     # hoặc API key id, hoặc user Odoo
url          = "https://erp.example.com/hook/relay"
secret_ref   = "env:CALLBACK_HMAC_ERP"   # KHÔNG phải secret, là con trỏ (§10.8.1)
allow_hosts  = ["erp.example.com"]
max_rps      = 5
```

Và bốn rào bắt buộc: chỉ HTTPS; host phải nằm trong allowlist đã cấu hình; **giải DNS rồi từ chối mọi
IP private/link-local/loopback** (kiểm sau khi giải, không chỉ kiểm chuỗi — nếu không thì một tên miền
trỏ về 127.0.0.1 đi lọt); ký payload bằng HMAC với khoá lấy từ `secret_ref`, để bên nhận biết là node
gọi chứ không phải ai đó.

Callback là **at-least-once và không đáng tin**: nó là một tiện ích, còn queue (a) mới là nguồn sự thật.
Một node không gọi được callback vẫn phải ghi kết quả vào queue.

### 22.10 Còn phải quyết

1. **`MAX_HOPS` = 4 là con số đặt bừa.** Cần đo trên một mesh thật: đường kính mạng gossipsub với D=8
   thường là 3–4 hop cho vài trăm node, nhưng nếu mesh phân mảnh theo địa lý thì 4 là quá ngắn.
2. **`promote_after = 300s` mặc định có đúng cho luồng B2B không?** Với `expiry = 300s` của ERC-20, giá
   trị này nghĩa là private pool không bao giờ promote kịp. Hoặc hạ xuống ~120s, hoặc thừa nhận rằng
   promote-to-open chỉ có nghĩa cho intent có `expiry` dài.
3. **Điểm forward hữu ích chống được sybil đến đâu?** Một node có thể tự gửi intent của chính mình,
   forward chúng, rồi submit chúng để tự cộng điểm. Chi phí là gas thật, nên không miễn phí — nhưng
   chưa ai tính tỷ lệ. Cần một mô hình trước khi điểm forward được dùng để phân phối bất cứ thứ gì có
   giá trị.
4. **Ai giữ danh sách `subject` cho callback trên một node công cộng?** Nếu là thủ công thì callback chỉ
   dùng được cho private pool. Nếu tự động (ví dụ chứng minh sở hữu domain) thì đó là một hệ thống danh
   tính, và nó vượt ra ngoài phạm vi một relayer.

---

## 23. MỘT app Rust duy nhất cho tầng daemon. Không relay-pool Python, không Lua.

> User, 2026-08-31, sau khi đọc `AUDIT_SPEC_REPORT_20260831_021000.md`:
>
> > Phần DECOUPLED DAEMON SERVICES (Outside Odoo Container): Cần sửa lại trong spec: Chỉ chạy 1 app
> > viết bằng rust, làm nhiều chức năng của DECOUPLED DAEMON SERVICES. Tôi không hiểu vì sao lại có
> > relay-pool, và dính cả Lua ở đây? Và tôi cũng chưa rõ confidential-signer để làm gì?

Ba câu hỏi đều đúng chỗ. Trả lời trước, quyết định sau.

### 23.1 Vì sao có `relay-pool`, và vì sao nó biến mất

`relay-pool` không phải một quyết định kiến trúc — nó là **hệ quả của một giả định chưa ai phát biểu**:
rằng tầng daemon là **N tiến trình Python không trạng thái**, scale ngang.

Từ giả định đó mọi thứ trong §06 suy ra một cách logic:

| §06 xây cái gì | Vì sao | Còn cần không khi chỉ có 1 tiến trình |
|---|---|---|
| Nonce leasing qua Redis | N worker tranh cùng một không gian nonce EOA | **Không** — một tiến trình thì nonce là biến trong bộ nhớ |
| Lua script nguyên tử | `allocate` + `freelist` + tập `signed` phải nguyên tử **giữa các tiến trình** | **Không** — trong một tiến trình đó là một `Mutex`, hoặc tốt hơn là một task sở hữu duy nhất + kênh mpsc |
| Fencing token, `owner_fence` | phát hiện một worker mất quyền sở hữu shard | **Không** — không có shard, không có worker khác để mất quyền vào tay |
| Ownership lease TTL 10 s | worker chết thì shard phải chuyển chủ | **Không** — tiến trình chết thì khởi động lại và đọc lại journal |
| Consistent hash `% N_workers` | chia shard | **Không** |
| Generation counter `gen` | chống worker cũ hồi sinh ghi đè | **Không** |

Toàn bộ §06.1 (nonce manager phân tán) là **giải pháp cho một bài toán ta tự tạo ra**. Bỏ giả định
"N worker Python" thì bài toán biến mất cùng với giải pháp. Đây là khoảng một phần ba §06.

Cái **không** biến mất, vì nó không đến từ giả định đó:

- **Journal trên Postgres là bản ghi bền.** Redis chưa bao giờ được phép là sự thật (§06.1.2: AOF
  everysec mất 1 s ghi, replica async roll back khi failover). Chain là sự thật, Postgres là journal.
  Bỏ Redis không mất gì vì Redis vốn chỉ là cache.
- **Quy tắc "nonce đã có tx đã ký thì KHÔNG BAO GIỜ trả về freelist".** Đây là quy tắc tài chính, không
  phải quy tắc đồng bộ. Giữ nguyên.
- **Giao thức cold start**: dựng lại `next` từ `max(getTransactionCount(pending), max_signed_nonce_in_journal + 1)`.
  Vẫn cần — tiến trình vẫn khởi động lại. Nhưng nó là một hàm khởi động, không phải một giao thức phân tán.
- **`max_inflight = 16`** (`txpool.accountslots` của node). Là trần của mạng, không của kiến trúc ta.
- **Simulation gate.** Là logic, chạy ở đâu cũng được.

### 23.2 `confidential-signer` để làm gì — và vì sao câu hỏi này khó

Bản §23 đầu tiên trả lời câu này **nhập nhằng**, nên viết lại từ đầu.

Nguồn gốc nhập nhằng: cái tên `confidential-signer` đang gánh **hai thứ chẳng liên quan gì nhau**, và
§07.1 gộp cả hai vào một interface `ICustodyProvider`. Tách ra thì mọi thứ sáng ngay.

#### Có HAI loại khoá, và chúng không dính gì đến nhau

| | **`authKey`** — khoá ký EVM | **`encKey x`** — khoá Zether |
|---|---|---|
| Là gì | scalar secp256k1 | scalar trên bn254 (hoặc Baby Jubjub) |
| Ký/tính gì | chữ ký ECDSA trên một transaction Ethereum | `D^x` (giải mã ElGamal) và `s = k + c·x` (đáp sigma) |
| **Của ai** | của **node** — nó là người trả gas | của **chủ tài khoản Zether** — người/pháp nhân giữ tiền |
| Để làm gì | đẩy một tx lên chuỗi | đọc số dư của **chính mình**; dựng chứng minh chuyển tiền của **chính mình** |
| HSM/KMS giữ được | **có** — secp256k1 có trong mọi firmware | **không** — không HSM thương mại nào có bn254 (§07.2) |
| Cần khi nào | **luôn luôn**, kể cả cấu hình META-only | **chỉ khi có Zether** |
| Mất nó thì sao | mất số dư gas của node đó; xoay khoá là xong (§21.5) | mất tiền **và** lộ toàn bộ lịch sử số dư, không hồi tố được |
| Trong `ICustodyProvider` | NHÓM A (`sign_digest_secp256k1`, `sign_raw_tx`) | NHÓM B (`zk_mul_by_x`, `zk_response`, `elgamal_decrypt`) |

Trong §07.1 chúng nằm chung một Protocol. Đó là lý do sơ đồ §12.0.2 vẽ `relay-pool → confidential-signer`
và làm người đọc tưởng node relayer cần `x`. **Nó không cần.**

#### Node relayer KHÔNG BAO GIỜ cần `x` — và đó là toàn bộ mô hình bảo mật

Một relayer nhận một intent **đã ký, đã kèm chứng minh** từ người lạ và đẩy nó lên chuỗi. Nó:

- **không giải mã được** số tiền (không có `x` của ai cả),
- **không dựng được** chứng minh (chứng minh cần `x` của người gửi),
- **không sửa được** gì (mọi trường nằm trong digest EIP-712 đã ký).

Nếu relayer cần `x` thì Zether vô nghĩa: người relay sẽ đọc được mọi số tiền họ chuyển tiếp. Việc relayer
mù hoàn toàn về nội dung là **tính chất**, không phải hạn chế.

Nên với vai `submit` của `bamboo-node`, khoá duy nhất nó chạm là `authKey` — và cái đó KMS/HSM giữ được
bình thường. **Cấu hình META-only không có `x` nào tồn tại trong hệ thống.**

#### Vậy vì sao lại cần `x` ở phía server?

Đúng một lý do: **khi chính công ty là người gửi.**

Người dùng cuối giữ `x` của họ trên thiết bị của họ — điện thoại, passkey, ví. Không có gì phía server.
Nhưng khi brand trả 300 nhà phân phối từ **ví treasury Zether của chính brand**, không ai bấm điện thoại
300 lần. ERP quyết định chi, và **một thứ gì đó phía server phải giữ `x` của treasury** để dựng 300
chứng minh.

Đó là toàn bộ lý do `x` tồn tại ngoài thiết bị người dùng. Nó là bài toán **custody** (§07), không phải
bài toán **relay** (§06/§21). Hai luồng khác nhau:

```
Người dùng cuối gửi tiền Zether:
   thiết bị của họ giữ x  ->  dựng proof trên máy họ  ->  intent đã ký
   ->  bamboo-node [gateway/mesh]  ->  [submit] ký vỏ tx bằng authKey  ->  chain
   (không có x nào ở phía server)

Công ty gửi tiền Zether (treasury payout):
   Odoo quyet dinh chi  ->  outbox
   ->  custody: dung proof bang x cua treasury   <-- CHO NAY, va chi cho nay
   ->  intent đã ký  ->  bamboo-node [submit]  ->  chain
```

#### Vì sao `x` phải ở một tiến trình riêng, không nằm trong `bamboo-node`

Ba lý do, xếp theo sức nặng:

1. **Nó không thuộc về đó.** `x` của treasury là tài sản của pháp nhân, thuộc luồng custody do Odoo điều
   khiển. `bamboo-node` là hạ tầng mạng; một node relayer thuần (§21.4 vai "pool thuần") không có `x`
   nào cả và vẫn chạy đúng.
2. **`bamboo-node` parse byte của người lạ.** §14 bắt buộc ba cargo-fuzz target trên parser intent vì
   *một `panic!` là DoS toàn mạng bằng một gói tin 200 byte*. Một lỗi bộ nhớ trong parser mà cùng address
   space với `x` là mất sạch mọi tài khoản mà tiến trình đó phục vụ. Đây là khác biệt giữa "node bị
   crash" và "treasury bị rút cạn".
3. **Phần chạm `x` rất nhỏ nên tách rất rẻ.** §07.2b đã đo: chỉ 2 phép nhân vô hướng trên điểm công khai
   + 1 scalar response. `ZetherKeyOracle` **dưới 300 dòng**, enclave image **< 5.000 dòng kể cả crypto
   backend**, không I/O ngoài vsock, không parser. Đó là thứ audit được trong một tuần. Prover
   Bulletproofs (nặng, hàng trăm crate phụ thuộc) chạy **ngoài** enclave vì nó không giữ bí mật về khoá —
   nó chỉ giữ bí mật về *số tiền*, và đó là một biên khác.

#### Và vì sao nó cũng không nằm trong Odoo

`x` trong tiến trình Odoo nghĩa là A4 (`base.group_system`) đọc được nó. §12.6.1 đã chứng minh
`base.group_system` = RCE trong tiến trình Odoo: một `ir.actions.server` với `state='code'` chạy Python
tuỳ ý với mọi biến môi trường và mọi socket của tiến trình đó. Odoo giữ **`signer_ref`** — một handle —
và không bao giờ giữ vật liệu khoá. CI có grep gate cho việc này (§12.0.2 bất biến 1).

#### Tóm lại

`confidential-signer` = **dịch vụ custody**, không phải một phần của mạng relay. Nó phục vụ hai nhóm
thao tác rất khác nhau, và chúng nên được gọi bằng hai tên:

| Tên nên dùng | Nội dung | Chạy ở đâu | Ai gọi | Cần khi |
|---|---|---|---|---|
| **custody broker** | NHÓM A: `sign_digest_secp256k1`, `sign_raw_tx`, `attest`, vòng đời | tiến trình thường, proxy sang KMS/HSM/MPC | vai `submit` của node (ký vỏ tx) **và** Odoo (thao tác treasury) | luôn luôn |
| **key oracle** | NHÓM B: `zk_mul_by_x`, `zk_response`, `elgamal_decrypt` | **enclave**, < 300 dòng, chỉ vsock | custody broker, thay mặt Odoo | **chỉ khi Zether bật** |

Câu trả lời một dòng cho câu hỏi của user: **`confidential-signer` giữ khoá; nó không relay gì cả. Phần
liên quan Zether của nó chỉ tồn tại để công ty tự chi tiền từ ví bảo mật của chính công ty, và nếu chưa
có Zether thì phần đó không tồn tại.**

### 23.3 Quyết định: MỘT codebase, MỘT binary, vai chọn bằng config

```
bamboo-node --config node.toml                  # tang relay: gateway/mesh/pool/submit/indexer
bamboo-node --role=custody --config cust.toml   # tang custody: broker khoa. CUNG binary.
bamboo-node --role=oracle  --config orac.toml   # trong enclave, CHI khi Zether bat
```

Bốn "dịch vụ" cũ của tầng daemon trở thành **năm vai trong một binary**, nối vào đúng ba trục năng lực
của §21.4 chứ không phải một danh sách mới:

| Vai | Cũ là gì | Trục §21.4 | Chạm khoá nào |
|---|---|---|---|
| `gateway` | phần RPC của `relay-pool` | ingest | không |
| `mesh` | `intent-hub` | ingest + pool | không |
| `pool` | hàng đợi của `relay-pool` | pool `open` \| `private` \| `none` | không |
| `submit` | nonce manager + simulation gate | submit theo `(chain, contract)` | **`authKey`** — qua custody broker, không giữ trong tiến trình |
| `indexer` | `chain-indexer` | — (§22.8 cần nó) | không |

Và **hai vai ở một làn khác**, không thuộc mạng relay (§23.2):

| Vai | Cũ là gì | Ai gọi | Cần khi |
|---|---|---|---|
| `custody` | NHÓM A của `confidential-signer` | vai `submit`, **và** Odoo | luôn luôn |
| `oracle` | NHÓM B — `ZetherKeyOracle` | `custody`, thay mặt Odoo | **chỉ khi Zether bật** |

Một binary, không phải một tiến trình bắt buộc. Ba làn triển khai:

1. **Làn relay** — `bamboo-node`. Nói chuyện với chuỗi, parse byte của người lạ, **không giữ vật liệu
   khoá nào**. Muốn ký vỏ tx thì *hỏi* làn custody.
2. **Làn custody** — `bamboo-node --role=custody`. Giữ/môi giới khoá. NHÓM A đẩy xuống KMS/HSM/MPC.
   Với cấu hình META-only, làn này mỏng: một lớp bọc quanh KMS cộng cache idempotency.
3. **Làn oracle** — chỉ tồn tại khi Zether bật, chạy trong enclave, giao diện hai hàm qua vsock.

Một triển khai lớn vẫn chạy được nhiều bản sao của làn 1 với vai khác nhau (một chỉ `indexer`, một chỉ
`submit`) nếu muốn tách tải. Khác biệt với thiết kế cũ: **tách tiến trình là lựa chọn vận hành, không
phải ràng buộc kiến trúc**, và không tiến trình nào cần giao thức đồng bộ phân tán để nói chuyện với anh
em của nó — chúng nói chuyện qua Postgres, thứ đã có transaction thật.

Vì sao Rust cho tất cả, không phải Python cho phần dễ:

- Verifier và prover Zether **phải** là Rust (arkworks). `ZetherKeyOracle` cũng vậy. Đã có binary Rust rồi.
- Parser intent là bề mặt tấn công đòi fuzz; Python asyncio không cho gì ở đây mà lấy đi memory safety.
- Một binary tĩnh dễ pin hash, dễ attest, dễ chạy trong enclave. Bốn tiến trình hai ngôn ngữ thì không.
- §21.3 đòi conformance vector giữa các bản cài đặt. Một bản cài đặt của ta là một bộ vector ít hơn phải
  giữ đồng bộ.

**Lưu ý về §07:** §07.1 viết `ICustodyProvider` bằng Python (`confidential-signer/custody/base.py`). Sau
quyết định này nó là Rust, cùng binary, vai `custody`. Ngữ nghĩa của interface giữ nguyên từng hàm — kể
cả `idem` bắt buộc, `attest(h, nonce32)`, và ranh giới NHÓM A/B/B'. Chỉ ngôn ngữ và cách đóng gói đổi.

### 23.4 Nguy cơ thật của việc gộp: ranh giới TIN CẬY không được gộp theo

Đây là chỗ đơn giản hoá có thể phản tác dụng, và nó phải được nói ra.

§12.0.2 vẽ mô hình đe doạ **theo tiến trình**, và bốn bất biến của nó dựa vào ranh giới tiến trình:
Odoo không giữ khoá, Odoo không gọi signer, signer không tin `tenant_uuid` trong body, và **indexer
không có quyền ghi bảng nghiệp vụ nào**. Nếu gộp bốn tiến trình thành một mà không làm gì khác, bất biến
thứ tư mất: một binary chạy cả `indexer` lẫn `submit` có một connection Postgres duy nhất với đủ quyền
cho cả hai, và A11 (chiếm indexer) lập tức bằng A10 (chiếm relay worker).

Ranh giới phải được dựng lại bằng thứ khác, và có sẵn thứ tốt hơn tiến trình:

| Bất biến §12.0.2 | Trước: ranh giới tiến trình | Sau: ranh giới gì |
|---|---|---|
| Indexer chỉ ghi 3 bảng của nó | tiến trình riêng | **DB role riêng**. Vai `indexer` mở connection bằng `bamboo_indexer` với `GRANT` hẹp; vai `submit` dùng connection khác. Cùng binary, hai connection pool, hai role. Mạnh hơn ranh giới tiến trình cũ vì nó do Postgres cưỡng chế chứ không do sơ đồ. |
| Odoo không giữ vật liệu khoá | tiến trình riêng | không đổi — Odoo vẫn là tiến trình khác, và grep gate CI của §12.0.2 vẫn chạy |
| Signer không tin body | tiến trình riêng + mTLS | không đổi — signer **vẫn** là tiến trình riêng (§23.5) |
| Odoo không gọi thẳng chain | outbox trong Postgres | không đổi |

Quy tắc rút ra, và nó nên là một dòng test: **mỗi vai khai báo tập quyền DB của nó, và binary từ chối
khởi động nếu một vai được cấp quyền ngoài tập đó.** Gộp tiến trình được; gộp quyền thì không.

### 23.5 Hai ranh giới tiến trình còn lại, và vì sao chỉ còn hai

Gộp bốn daemon thành một binary **không** có nghĩa gộp mọi thứ vào một tiến trình. Còn đúng hai ranh
giới, và mỗi cái có một lý do không thể thay bằng cấu hình:

**(a) Làn relay ↔ làn custody.** Làn relay parse byte của người lạ; làn custody chạm khoá. Ranh giới này
tồn tại kể cả khi không có Zether, vì `authKey` của node cũng không nên nằm cùng address space với
parser. Giao tiếp qua mTLS (hoặc Unix socket nếu cùng máy), và custody **không tin `tenant_uuid` trong
body** — chỉ tin cái trong client cert (§07.11). Chi phí: một round-trip mỗi lần ký, đã nằm trong ngân
sách §06.6.

**(b) Làn custody ↔ làn oracle** — *chỉ khi Zether bật*. Đây là ranh giới enclave:

- Giao diện **hẹp và cố định**: `zk_mul_by_x(points, ctx)`, `zk_nonce_commit(bases, ctx)`,
  `zk_response(nonce_id, challenge)`. Không có `decrypt(C, D)` tuỳ ý — đó là một decryption oracle trên
  `x` (§07.4b): `decrypt(C, D)` với `D` do kẻ tấn công chọn trả về log của `C·D^{-x}`, tức một ECDH
  oracle. `elgamal_decrypt` **bắt buộc** nhận `ChainWitness` chứng minh `(C,D)` là trạng thái thật trên
  chuỗi.
- Oracle **tự giữ nonce của nó** và **chống replay theo digest** (§12.5.1 mục 2, 3).
- Triển khai enclave: Nitro Enclave / SEV-SNP, **chỉ vsock**, `x` unwrap bằng KMS có điều kiện trên PCR0.
  Triển khai tối thiểu (loyalty-only, §07 cấu hình C): cùng máy, Unix socket, `x` wrap bởi KMS — vẫn là
  tiến trình riêng, vẫn giao diện hẹp.
- **Không Zether ⇒ không chạy vai này.** Cấu hình META-only không có tiến trình oracle nào, và không có
  `x` nào tồn tại trong hệ thống.

Cái **không** còn là ranh giới tiến trình: `indexer` vs `submit`. Chúng ở chung làn relay, và bất biến
"indexer chỉ ghi ba bảng của nó" chuyển sang DB role (§23.4).

### 23.6 Sơ đồ sau khi sửa

```
+-------------------------------------------------------------------------+
|  Odoo 19  —  dms_blockchain (+ _bridge / _account / _payment)           |
|  Control plane. Giu signer_ref, KHONG giu vat lieu khoa.                |
|  Khong goi RPC ra chain trong transaction.                              |
+------------------+---------------------------------+--------------------+
                   | outbox (Postgres,               | mTLS
                   |  FOR UPDATE SKIP LOCKED)        | (thao tac treasury)
                   v                                 v
+----------------------------------------+  +----------------------------------+
|  LAN RELAY   bamboo-node               |  |  LAN CUSTODY                     |
|                                        |  |  bamboo-node --role=custody      |
|   [gateway]  RPC cho client            |  |                                  |
|   [mesh]     libp2p gossipsub          |  |  NHOM A: sign_digest_secp256k1,  |
|   [pool]     open / private            |  |          sign_raw_tx, attest     |
|   [submit]   key pool §21.5,           |--|-> ky vo tx bang authKey          |
|              nonce in-process          |mTLS|  -> KMS / HSM / MPC             |
|   [indexer]  multi-RPC, finality gate  |  |                                  |
|                                        |  |  Khong parse byte tu Internet.   |
|  Parse byte cua NGUOI LA. Fuzz target. |  +---------------+------------------+
|  KHONG giu vat lieu khoa nao.          |                  | vsock
|  Hai connection PG, hai DB role.       |                  | CHI KHI ZETHER BAT
|  Khong Redis. Khong Lua.               |                  v
+----------------------------------------+  +----------------------------------+
                                             |  LAN ORACLE (trong enclave)      |
                                             |  bamboo-node --role=oracle       |
                                             |  ZetherKeyOracle < 300 dong      |
                                             |  Giu x. Ba ham. Khong parser.    |
                                             +----------------------------------+
```

Đọc sơ đồ theo một câu: **byte của người lạ đi vào làn trái, khoá nằm ở làn phải, và giữa hai làn là một
giao diện đếm được bằng đầu ngón tay.**

### 23.7 Cái gì chết trong spec

Đánh dấu để không ai hiện thực lại:

| Chết | Ở đâu | Thay bằng |
|---|---|---|
| `relay-pool` như một dịch vụ Python | §06 toàn bộ tiêu đề, §08.2b, sơ đồ §12.0.2 | vai `submit` + `pool` trong `bamboo-node` |
| Redis làm store nonce | §06.1 | bộ nhớ tiến trình + journal Postgres |
| Lua script nguyên tử | §06.1.4, §06.4.3 (velocity limit) | task sở hữu duy nhất; velocity limit là một transaction Postgres |
| Fencing token, ownership lease, consistent hash shard, `gen` | §06.1.3–06.1.5 | — (bài toán không còn) |
| `intent-hub` như tiến trình riêng | §05.1, §12.0.2 | vai `mesh` |
| `chain-indexer` như tiến trình riêng | §11, §12.0.2 | vai `indexer`, **DB role riêng** |
| Python asyncio ở tầng daemon | §06, §11 | Rust |
| `ICustodyProvider` bằng Python | §07.1 | Rust, vai `custody`; **ngữ nghĩa từng hàm giữ nguyên** |
| Cái tên `confidential-signer` gánh hai việc | §07, §12.0.2 | tách tên: **custody broker** (NHÓM A) và **key oracle** (NHÓM B) — §23.2 |
| Sơ đồ `relay-pool → confidential-signer` gợi ý node cần `x` | §12.0.2 | node **không bao giờ** cần `x`; nó chỉ xin ký vỏ tx bằng `authKey` |
| "1 TypeScript Engineer" cho Pod D | §16 §9.2 (và báo cáo AGY chép lại) | Rust engineer |

Cái **giữ nguyên** dù sơ đồ đổi: outbox Postgres là biên duy nhất giữa Odoo và làn relay; Odoo không bao
giờ gọi HTTP trong transaction; `_set_done` chỉ đến từ Finality Gate; indexer không ghi bảng nghiệp vụ;
Odoo chỉ giữ `signer_ref`, không giữ vật liệu khoá.

### 23.8 §21.2 đảo: addon Odoo là control plane, không phải một node

**Đã chốt** (user, 2026-08-31: *"Sửa và viết lại đi"*).

§21.2 chốt hai bản cài đặt song song: A Rust standalone, B Odoo addon. Lý do của B là *"một site DMS đã
có Odoo, bắt họ vận hành thêm một tiến trình Rust là chi phí không đổi lấy gì"*.

Quyết định §23.3 làm lý do đó hết hiệu lực: trước là "thêm bốn daemon hai ngôn ngữ", giờ là **một binary
tĩnh**. Và cái giá của việc giữ B thì không đổi: hai bản cài đặt của cùng một giao thức gossip là đúng
chỗ §21.3 nói lỗi bất đồng thuận sinh ra — node A nhận một intent mà node B từ chối, hoặc hai bên tính
`intent_id` lệch một byte, là mạng chia đôi âm thầm. Trả cái giá đó cho một lợi ích đã teo lại là sai.

Chốt: **addon Odoo là control plane của node, không phải một bản cài đặt node.** Nó quyết định chi tiền,
ghi outbox, đọc kết quả, giữ ACL và `signer_ref`. Nó không gossip, không giữ pool, không ký vỏ tx.

Spec và conformance vector của §21.3 **vẫn bắt buộc**, nhưng lý do đổi và lý do mới mạnh hơn: không phải
vì ta viết hai bản, mà vì **mạng mở nên người lạ sẽ viết bản của họ**. Một spec chỉ để tự ta đồng bộ với
chính mình là thứ dễ bị bỏ; một spec là hợp đồng với người ngoài thì không.

§21.2 đã được viết lại theo quyết định này.

### 23.9 Nợ kỹ thuật để lại

1. ~~§06 cần một lần viết lại thật~~ — **đã làm**: §06.0 và §06.1 viết lại hoàn toàn, §06.4.3 đổi từ Lua
   sang transaction Postgres, §06.6.1 đổi theo pool khoá §21.5. Phần còn lại của §06 (bump rule, phân
   loại L2, chi phí L1 data, sim gate, breaker, multi-RPC, observability, chi phí) nói về **chuỗi**, không
   về topology tiến trình, nên giữ nguyên.
2. §12.0.2 phải vẽ lại theo **ranh giới quyền** chứ không theo ranh giới tiến trình, kèm bảng ở §23.4.
   Và sơ đồ của nó phải bỏ mũi tên `relay-pool → confidential-signer` (§23.2).
3. Bảng năng lực của §21.4 và bảng vai ở §23.3 phải hợp nhất — hiện là hai cách nói về cùng một cấu hình.
4. §07.1 phải đổi ngôn ngữ sang Rust và tách tên theo §23.2, giữ nguyên ngữ nghĩa từng hàm.

### 23.10 Zether Signer ghi vào đâu

Hai nghĩa, trả lời cả hai.

#### (a) Đặc tả của nó nằm ở file nào

| Thứ | File | Trạng thái |
|---|---|---|
| **Quyết định** (vì sao có, vì sao tiến trình riêng, ba làn) | `_USER-DECISIONS.md` §23.2, §23.5 | xong |
| **Đặc tả** (interface, backend, vòng đời khoá, attestation, mua sắm) | **`07-custody-providers.md`** — đây là section **sở hữu** | cần sửa: §07.1 viết bằng Python và gộp NHÓM A với NHÓM B dưới một tên (§23.9 mục 4) |
| Chính sách trước khi ký, chống lạm dụng | `12-threat-model.md` §12.5.1 | xong |
| Hạt nhân `ZetherKeyOracle` (< 300 dòng, cái gì vào enclave) | `07-custody-providers.md` §07.2b | xong |
| Cấu hình custody theo money flow | `07-custody-providers.md`, model `blockchain.custody.policy` | xong |
| Đường Odoo gọi tới nó | `10-odoo-addon-design.md` — chỉ giữ `signer_ref`, gọi qua mTLS | xong |
| Mã nguồn | `bamboo-node/src/roles/oracle.rs` (§23.3) | chưa viết |

Nói ngắn: **`07-custody-providers.md` là nhà của nó.** `_USER-DECISIONS.md` chỉ ghi quyết định, không
phải đặc tả — đừng đi tìm chi tiết interface ở đó.

#### (b) Nó ghi state vào đâu

Câu trả lời ngắn: **gần như không ghi gì cả**, và đó là cố ý.

| State | Ở đâu | Mất khi restart thì sao |
|---|---|---|
| `x` (khoá giải mã ElGamal) | **Không bao giờ ở dạng rõ.** Blob đã wrap nằm ở KMS/HSM, unwrap vào bộ nhớ enclave lúc khởi động, có điều kiện trên PCR0 | Unwrap lại. Ảnh khác PCR0 ⇒ KMS từ chối ⇒ enclave không chạy được. Đúng như thiết kế |
| Nonce của chính signer (chống hai chữ ký cùng nonce, §12.5.1 mục 2) | Bộ nhớ enclave | Đọc lại từ chain (`getTransactionCount`) khi khởi động |
| Cache chống replay `digest → đã thấy` | Bộ nhớ enclave, TTL 24 h | **Rỗng sau restart, và điều đó AN TOÀN** — xem dưới |
| `nonce_id` đang mở của `zk_nonce_commit` | Bộ nhớ enclave | **Rỗng sau restart, và fail-closed** — xem dưới |
| `sendCounter` cho PRF sinh `s` (§03) | **Không giữ.** Đọc từ chain (`IZetherToken.sendCounter`) | Không có gì để mất |
| Audit log ai xin ký cái gì | Ghi ra **ngoài** qua làn custody, vào `blockchain.security.event` của Odoo | Không mất — nó không nằm trong enclave |

**Vì sao mất cache replay khi restart là an toàn.** Với ECDSA sinh nonce theo RFC 6979 (tất định), ký
lại cùng một payload cho ra **đúng chữ ký cũ** — replay vô hại. Cache chỉ để tiết kiệm một lần ký, không
phải để bảo vệ.

**Vì sao mất `nonce_id` khi restart cũng an toàn, và nó là chỗ nguy hiểm nhất nếu làm sai.** Với sigma
protocol, `zk_nonce_commit` chọn `k`, `zk_response` trả `s = k + c·x`. Trả lời **hai lần cho cùng một
`k` với hai `c` khác nhau** là lộ `x` ngay lập tức: `x = (s₁ − s₂)/(c₁ − c₂)`. Đây là §12.3.1 và nó là
lỗ hổng nghiêm trọng nhất trong cả mô hình.

Nên quy tắc bắt buộc là **`nonce_id` không biết ⇒ TỪ CHỐI**, không phải "không biết ⇒ chấp nhận":

```
zk_response(nonce_id, c):
    k = open_nonces.remove(nonce_id)     # remove, khong phai get — dung mot lan
    if k is None: reject("unknown or already used nonce_id")
    return k + c * x mod r
```

`remove` chứ không `get` là toàn bộ cơ chế. Sau restart, mọi `nonce_id` cũ đều "không biết" ⇒ mọi yêu
cầu cũ bị từ chối ⇒ prover phải commit lại từ đầu. Bất tiện, và **đúng**. Một enclave persist bảng này
ra đĩa là một enclave có thể bị rollback về trạng thái cũ và trả lời lần thứ hai — nên **không persist
là một tính năng bảo mật, không phải một thiếu sót.**

Hệ quả vận hành phải ghi vào runbook: **restart làn oracle làm hỏng mọi chứng minh đang dựng dở.** Với
một batch payout 300 người, restart giữa chừng nghĩa là dựng lại các proof chưa xong. Chi phí là CPU
(30–50 ms/proof, §03), không phải tiền, và không có tx nào đã ký bị mất — vì tx chỉ được ký sau khi proof
xong.

### 23.11 "Non-custody thì bỏ được oracle lane?" — không hẳn, và đây là bảng quyết định

Câu hỏi gộp **ba trục khác nhau**. Tách ra thì trả lời được từng cái.

| Trục | Câu hỏi | Ảnh hưởng tới oracle lane |
|---|---|---|
| **1. Custody khoá của NGƯỜI DÙNG** | Platform có giữ `x` của người khác không? | Non-custodial ⇒ **không có `x` của user** ở server |
| **2. Tài khoản Zether của CHÍNH công ty** | Công ty có ví Zether riêng không? | Tự giữ khoá của mình **vẫn là giữ khoá**. Trục 1 không nói gì về trục này |
| **3. Có dùng Zether không** | Token là Meta công khai hay Zether? | Không Zether ⇒ **không có `x` nào tồn tại** |

Chỗ dễ nhầm là trục 2. **"Non-custodial" nghĩa là không giữ tiền của người khác — nó không có nghĩa là
không có khoá nào ở server.** Ví treasury của chính công ty là self-custody, và self-custody vẫn là một
khoá phải nằm ở đâu đó.

#### Trả lời theo từng dòng tiền

Bảng §07.0 đã chốt `conf_custody` cho từng dòng tiền, và đọc theo câu hỏi này thì ra thế này:

| Dòng tiền | `conf_custody` (§07.0) | Oracle lane có cần không |
|---|---|---|
| Loyalty / reward | `on_device` 1-of-1 | **KHÔNG.** Prover chạy trên máy người dùng; signer không nằm trên đường đi (§07 dòng 173) |
| End-user payment tại quầy | `on_device` 1-of-1 | **KHÔNG.** Cùng lý do |
| Treasury / mint / pause | không áp dụng — chỉ ECDSA | **KHÔNG.** Không có Zether ở đây |
| Relayer EOA nóng | không áp dụng | **KHÔNG** |
| Auditor `y_audit` | DKG 3-of-5 threshold ElGamal | **KHÔNG** — giải mã không cần proving |
| B2B settlement — **không Zether** (mặc định) | không áp dụng | **KHÔNG** |
| B2B settlement — **có Zether** (tuỳ chọn) | `x` chia Shamir 2-of-3 | **CÓ, nhưng chỉ giữ MỘT share** |

> **[user, 2026-08-31] Zether cho B2B là TUỲ CHỌN, không bắt buộc.** *"B2B dùng Zether thì là option,
> không bắt buộc. Tôi sẽ nghiên cứu lại sau."* Hệ quả trực tiếp: cấu hình mặc định của B2B **không có
> `x` nào**, nên **không dòng tiền nào trong locked #3 bắt buộc oracle lane**. Nó chỉ xuất hiện khi ai
> đó chủ động bật Zether cho B2B. `blockchain.custody.policy.conf_provider_id` để rỗng là hợp lệ và là
> mặc định; ràng buộc `min_threshold_n >= 3` chỉ áp khi trường đó có giá trị (§07.12.3, đã sửa).

Nên câu trả lời chính xác: **hai trong ba use case của locked #3 vốn đã không cần oracle lane.** Chỉ B2B
cần, và ngay cả ở đó platform giữ **một share 2-of-3**, không giữ `x` — platform một mình không chi tiêu
được. Đó đúng là hình dạng "non-custodial" mà một doanh nghiệp muốn, và nó **không** loại bỏ oracle lane,
nó chỉ làm cho oracle lane bất lực khi đứng một mình.

#### Vì sao B2B không bỏ được, kể cả khi chỉ NHẬN tiền

Cám dỗ: "công ty chỉ nhận thanh toán từ NPP, không gửi đi, nên không cần dựng proof, nên không cần `x`."
**Sai** — đọc số dư của chính mình cũng cần `x`:

- Số dư trên chuỗi là cặp `(C, D)`. Giá trị là `C · D^{-x}`.
- Đường nhanh là memo AEAD (§03.2.5), nhưng khoá memo dẫn xuất từ `D^x` — vẫn là `x`.
- §15.5.5 xếp "chủ tài khoản" là mức duy nhất **đối soát đầy đủ** được, và cơ chế của nó là HSM/enclave
  expose đúng một phép `ecdh(D) -> compress(D^x)`.

Nghĩa là: một treasury Zether **chỉ nhận** vẫn cần `x` để biết nó nhận được bao nhiêu. Bỏ oracle lane ở
đây không phải bỏ một tính năng — nó là **bỏ đối soát**, và §15.5.5 sẽ trả về `run_state = 'partial'`
vĩnh viễn thay vì `clean`. Báo "clean" khi chỉ kiểm được tính liên tục của nonce là một lối nói dối.

#### Cấu hình DUY NHẤT thật sự không có oracle lane

**Công ty không có tài khoản Zether nào cả.** Treasury là Meta Token công khai; Zether nếu có thì chỉ
chạy giữa các bên thứ ba với nhau. Đây chính là **META v1** (§20, §24) và là thứ đang ship trước.

Cái giá: công ty không nhận được thanh toán bảo mật. Với B2B thì đó là mất chính lý do dùng Zether — giá
gốc là bí mật sống còn (§07.0, §2.6). Với loyalty thì không mất gì, vì D9 đã chốt điểm thưởng **không**
cần bảo mật số dư.

#### Nếu vẫn muốn B2B mà tuyệt đối không có `x` phía server

Có một đường, và phải nói rõ giá của nó: **một người thật với một thiết bị.**

- Payout: 500 NPP × 12 tháng = 6.000 giao dịch/năm (§15.1.4). Zether **không batch proof được** (§15.7:
  300 `transferConfidential` = 564M gas, phải là 300 tx riêng), nên một đợt payout tháng là 500 proof.
  Ở 0,2–0,5 s/proof trên ARM64 là 100–250 giây tính toán — chạy được trên laptop, không chạy được trên
  điện thoại, và phải có người ngồi đó.
- **Đối soát thì không.** §15.5.5 đòi giải mã số dư sau mỗi lần rollOver, hằng ngày tối thiểu. Đó là
  automation, không phải một người bấm nút.

Nên kết luận thẳng: **thiết bị-người-thật xử được đường chi tiền, không xử được đường đối soát.** Ai chọn
đường này phải chấp nhận đối soát thủ công hoặc `run_state = 'partial'`.

#### Nợ: bảng §07.0 chưa nói CHIỀU

Hàng B2B của §07.0 ghi *"prover chạy phía distributor (họ vốn đã biết số tiền của chính họ)"*. Câu đó
đúng cho chiều **distributor → brand**. Chiều **brand → distributor** thì người gửi là brand, nên proof
phải dựng ở nơi có `x` của **brand** — và hàng "Treasury" ngay dưới lại ghi *"không có Zether ở đây"*.
Hai hàng nói ngược nhau về cùng một ví.

Phải sửa `07-custody-providers.md` §07.0: tách hàng B2B thành hai chiều, và nói rõ ví treasury của brand
**có** tài khoản Zether khi B2B bật.

---

## 24. Meta-tx trên token KHÔNG phải một forwarder. Bỏ `feeToken`, `innerGasLimit`, và cả `to`/`data`.

> User, 2026-08-31:
>
> > Bỏ feeToken đi. Cái đó nằm ngoài TokenContract, không đưa vào.
> > innerGasLimit có cần không? Ở đây đâu có dùng forwarder gì mà cần innerGasLimit?

Cả hai đúng, và câu thứ hai lộ ra một thứ lớn hơn hai trường bị bỏ.

### 24.1 Cái đã tìm thấy khi đi kiểm

Code thật (`smartcontracts/src/common/MetaTxLib.sol`) **vốn đã không có** `feeToken` lẫn
`innerGasLimit` — hai trường đó chỉ còn sống trong spec `04-eip1776-metatx.md` (44 lần),
`05-open-relayer-network.md` (6), `00-CANON.md` (15), `12-threat-model.md` (3).

Nhưng struct trong code lại mang `to` / `value` / `data`, và `executeMetaTransaction` trả về
`(bool success, bytes returnData)`. Đó là **hình dạng của một generic forwarder đặt bên trong một
token**. Nó kéo theo toàn bộ bề mặt tấn công của forwarder:

- allowance drain (§12.2 mục 3) — cần allowlist `to`, cấm `to == address(this)`, cấm fee token
- return-bomb (§12.2 mục 1) — cần `MAX_RETURN_BYTES`
- 63/64 griefing (§12.2 mục 2) — cần `innerGasLimit` **và** guard `gasleft() >= g + g/63 + FLOOR`
- swallow-vs-bubble (§04.6.2) — cần `MODE_REQUIRE_SUCCESS`

Trong khi **không token nào trong hệ phơi ra một lời gọi tuỳ ý**. Đọc lại interface thật:

| Contract | Thao tác phơi ra |
|---|---|
| `IERC20MetaTx` | `transfer`, `approve` (kế thừa `IERC20`) |
| `IERC20Payment` | `payWithFee(to, amount, feeMode, fee, feeRecipient, entryRef)` |
| `IZetherToken` | `fund`, `transferConfidential`, `burn`, `rollOverPublic`, `rollOverBatch` |

Tất cả là **thao tác có kiểu trên chính token đó**. Không cái nào cần gọi contract lạ. Vậy `to`/`data`
là một cơ chế không ai dùng, kéo theo bốn lớp phòng thủ cho một vector ta tự mở ra.

### 24.2 Quyết định

Struct mang **mã thao tác + tham số**, và bộ điều phối gọi một **internal function**, không phải opcode
`CALL`:

```solidity
struct MetaTransaction {
    address from;
    uint8   op;             // thao tac cua CHINH token nay
    bytes   args;           // tham so da ABI-encode cho op do
    uint256 batch;
    uint256 nonce;
    uint256 validUntil;
    address relayer;        // address(0) = wildcard
    FeeMode feeMode;
    uint256 fee;
    address feeRecipient;   // tra bang CHINH token nay
}
```

Bảng `op` là **append-only**: không bao giờ đổi số của một mã đã phát hành, vì nó nằm trong digest đã
ký. `verifyingContract` của EIP-712 domain quyết định token nào, nên hai token khác nhau dùng lại cùng
số là an toàn.

| `op` | Thao tác | `args` |
|---|---|---|
| 1 | `TRANSFER` | `(address to, uint256 amount)` |
| 2 | `APPROVE` | `(address spender, uint256 amount)` |
| 3 | `PAY_WITH_REF` | `(address to, uint256 amount, bytes32 entryRef)` |
| 10 | `FUND` | `(bytes encodedY, uint256 amount)` |
| 11 | `TRANSFER_CONF` | `(bytes payload, bytes proof)` |
| 12 | `BURN` | `(bytes payload, uint256 amount, bytes proof)` |
| 13 | `ROLLOVER` | `(bytes32 account, uint64 expectedPendingSeq, uint64 validUntilBlock)` |

### 24.3 Cái gì chết, và vì sao từng cái

| Chết | Vì sao |
|---|---|
| `feeToken` | Phí trả bằng **chính token này**. Một token khác nằm ngoài contract này, và contract này không cầm allowance của nó — đúng như user nói. Muốn trả phí bằng token khác thì đó là việc của một contract khác, không phải của token này. |
| `innerGasLimit` | Không có inner call thì không có gas nào để giới hạn. |
| Guard 63/64 (EIP-150) | Cùng lý do. Internal function không có ngữ nghĩa chuyển gas. |
| `MAX_RETURN_BYTES = 1024` | Không có returndata từ contract lạ để mà bomb. |
| `returnData` trong giá trị trả về | Op có kiểu ⇒ caller biết hình dạng kết quả. |
| `MODE_REQUIRE_SUCCESS` / swallow mode | Xem §24.4. |
| `to`, `value`, `data` | `to` là tham số của thao tác, không phải đích của một lời gọi ⇒ nằm trong `args`. `value` = 0 luôn: token không nhận native coin. |
| Allowlist target, `calldata_rules`, `targets[to].isFeeToken` | Không còn `to` tuỳ ý để mà allowlist. |
| ERC-2771 sender suffix, `appendsSender` | Không có contract đích để mà nối `from` vào cuối calldata. |
| `payable` trên `executeMetaTransaction` | Token không nhận native coin. Trả gas là việc của relayer ở tầng vỏ tx. |
| `success` trong event `MetaTransactionExecuted` | Xem §24.4 — không còn nhánh "thành công một nửa". |

### 24.4 Cái được thêm, và nó là lý do mạnh nhất cho thay đổi này

Một generic forwarder **không bao giờ biết trước** inner call sẽ fail vì gì. Nên nó buộc phải chọn một
trong hai cái tệ:

- **Thu phí trước, nuốt lỗi**: user trả tiền cho một việc không xảy ra.
- **Bubble revert**: relayer bỏ gas thật rồi không được gì.

§04.6.2 và §08.4c cãi nhau đúng chỗ này suốt bộ tài liệu (`_CRITIQUES.md` contradiction-2, chưa đóng).

Với thao tác **có kiểu**, contract biết chính xác cái gì có thể fail, nên nó kiểm hết **trước** khi thu
phí — và sau điểm đó thao tác không thể fail:

```
1. relayer      (0 gas)   — wildcard hoac khop msg.sender
2. validUntil   (0 gas)
3. op hop le    (0 gas)   — khong trong bang thi revert ngay
4. nonce        (1 sload)
5. chu ky       (~3k)
6. decode args, KIEM TRA DU dieu kien cua op
     TRANSFER      -> so du >= amount + fee
     TRANSFER_CONF -> da dang ky, nonce Zether khop, PROOF VERIFY PASS
     ROLLOVER      -> block.number <= validUntilBlock (§03.5.4)
7. thu phi
8. thuc thi op bang internal call
```

Bất biến trở thành **"phí đã thu ⟺ thao tác đã xảy ra"**, đạt được **không cần try/catch, không cần một
mode nào**. Đó là thứ mà mâu thuẫn contradiction-2 tranh cãi hai năm không giải được, và nó tự biến mất
khi bỏ tính tuỳ ý của `to`/`data`.

Op fail ⇒ toàn bộ tx revert ⇒ nonce không tiêu, phí không thu, **relayer mất gas**. Đó là chi phí còn
lại, và nó được xử ở tầng vận hành chứ không ở tầng contract: simulation gate bắt gần hết, phần còn lại
là kẻ cố tình và bị chấm `origin_grief_score` (§05.5). Với Zether, verify proof nằm ở bước 6 nên một
proof rác đốt ~1,79 M gas trước khi revert — đó là lý do thứ tự fail-fast của §12.1 (status → nonce →
on-curve → expiry → **rồi mới** MSM) là bắt buộc, không phải tối ưu.

Thêm một hàm nhỏ, và nó trả tiền cho chính nó:

```solidity
function supportsMetaOp(uint8 op) external view returns (bool);
```

Node mesh gọi một lần lúc onboard một contract để dựng bảng năng lực §22.4, thay vì đoán từ ABI.

### 24.5 Lợi ích phụ cho tầng mạng

Bảng tra của §22.4 khoá theo `(caip2, contract_address, selector)`. Với forwarder, "selector" là 4 byte
đầu của `data` — phải decode, và nó là selector của **contract khác**, nên bảng phải biết cả contract
đích lẫn hàm đích. Với op có kiểu:

- `contract_address` = `verifyingContract` trong EIP-712 domain, đọc thẳng
- `selector` = `m.op`, **một `uint8` nằm ngay trong struct**

Node lọc được ở tầng hàng rào L0/L1 của §22.3 (~1 µs, không decode gì), thay vì phải decode `bytes data`
ở L2. Và `event MetaTransactionExecuted` index được `op`, nên indexer lọc theo loại thao tác không cần
decode args.

### 24.6 Cái này KHÔNG đổi

- **Nonce 2D `(batch, nonce)`** — giải head-of-line blocking thật, giữ nguyên.
- **Wildcard `relayer == address(0)`** — giữ digest cố định, không cross-mode replay (§20, §21.5).
- **`fee` + `feeMode` trong struct** — relayer đọc phí từ intent trên mesh không cần gọi hàm.
- **`FeePolicy.requireConfidentialSafe()`** — `PERCENT` vẫn bị cấm trên token bảo mật; `fee = v × p` với
  cả hai vế công khai chính là số tiền (§12.3.7).
- **`keccak256(m.args)` trong structHash** — bỏ là lỗ hổng injectivity: `("ab","c")` và `("a","bc")` cho
  cùng digest. Fuzz không tìm ra, solver tìm ra trong vài giây.
- **`cancelMetaNonce`** — người ký phải rút lại được intent đã phát lên mesh.

### 24.7 Nợ để lại

`04-eip1776-metatx.md` là section sở hữu struct này và nó vẫn mô tả mô hình forwarder: 44 lần nhắc
`feeToken`/`innerGasLimit`, cộng §04.6 (allowlist target), §04.6.2 (`MODE_REQUIRE_SUCCESS`), §04.9
(griefing của forwarder), §04.6.7 (`ReentrancyGuardTransient` cho inner call). Phải viết lại.

Kéo theo: `00-CANON.md` §C21 và bảng sở hữu artefact; `12-threat-model.md` §12.2 (bốn lỗ hổng kinh điển
— ba trong bốn không còn đối tượng); `05-open-relayer-network.md` §5.3.1; `_CRITIQUES.md`
contradiction-2 và contradiction-3 (**cả hai tự đóng** theo §24.4 và theo việc bitmask `mode` đã chết ở
§20).
