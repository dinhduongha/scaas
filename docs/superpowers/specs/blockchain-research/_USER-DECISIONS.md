# Quyết định của user + phát hiện từ code thật

Chốt trong phiên brainstorming 2026-08-30. **Đây là nguồn có thẩm quyền cao nhất**,
cao hơn `blockchain.md` và cao hơn mọi suy đoán của agent. Không tranh luận lại.

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

`feeRecipient` do **người gửi** chỉ định trong cả ba mode.

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
