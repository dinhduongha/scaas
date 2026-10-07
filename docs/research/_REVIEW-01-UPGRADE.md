> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Review: `01-token-factory` và toàn bộ cơ chế upgrade

Sau quyết định §20.2 (`_USER-DECISIONS.md`): **không có upgrade cho token đã deploy;
version sống ở catalogue của factory.**

## Kết luận trước

1. **Chỉ `01` và `14` thật sự mang máy móc upgrade.** `02`, `04`, `12` đã tự kết luận
   **non-upgradeable** một cách độc lập, trước khi có quyết định này. Reframe **hoàn
   tất một sự hội tụ mà spec đang tự đi tới**, không đánh nhau với nó. Khối lượng sửa
   nhỏ hơn con số "41 chỗ nhắc beacon" gợi ra.
2. **`1.11 Quản trị upgrade` sụp gần hết** — và đó là phần thắng lớn nhất, không phải
   mất mát. Chi tiết §C.
3. **Một thứ NẶNG THÊM mà chưa ai nói ra**: `MigrationSink` (1.17.2) từ đường dự phòng
   trở thành **đường duy nhất**. Chi tiết §D.

---

## A. `01-token-factory`: cái gì chết, cái gì sống, cái gì MẠNH LÊN

### A.1 Chết hẳn

| Mục | Nội dung | Vì sao |
|---|---|---|
| 1.0 #1 | *"Proxy pattern = Beacon"* | Beacon = chủ beacon đổi được implementation của mọi token người lạ |
| 1.0 #2, 1.4 | Chuỗi CREATE2 **ba tầng** | Tầng beacon tồn tại chỉ để giữ địa chỉ ổn định qua nâng cấp. Còn hai tầng |
| 1.3 | `PinnedProxy` | Nó là *"biến thể để không ai upgrade được tôi"*. Giờ đó là mặc định và là duy nhất. Cả contract lẫn phần tính 4.600 gas đều bỏ |
| 1.3 (2) | ERC-7201 namespaced storage, cấm `__gap` | Kỷ luật storage layout chỉ cần khi có `delegatecall` qua nhiều version trên **cùng** state. Clone bất biến không bao giờ đổi implementation |
| 1.3 (5) | CI gate `storage-layouts/v<N>/*.json` + OZ `validateUpgrade` | Không còn version thứ hai chạy trên cùng storage |
| 1.5 | Trường `beacon` trong `struct Prototype` | — |
| 1.5 | `DEPLOYER_ROLE` gác `deploy()` | Ai cũng deploy được |
| 1.11 | Role `UPGRADE_ADMIN`, beacon owner, `Ownable2Step` cho beacon, timelock 48h cho upgrade | Không còn quyền upgrade để mà quản trị |
| 1.11.1 (3) | Model `blockchain.upgrade.proposal` (toàn bộ, kèm `storage_diff_ids`, `audit_report_ids`) | — |
| 1.13.1 | Trường `upgradeable = fields.Boolean(default=True)` | Luôn `False`. Thay bằng `version` + `implementation`, cả hai bất biến |
| 1.17.1 bước 13 | *"So `token.beacon()` với `prototype.beacon_address`"* | Thay bằng so `EXTCODEHASH` của clone và `implementation()` |
| A5 | Giả định *"chain đã có Cancun (EIP-6780)"* | Rủi ro là kẻ tấn công `initialize()` implementation rồi `SELFDESTRUCT` để **brick toàn bộ N proxy**. Với clone, brick implementation vẫn hại các clone trỏ tới nó — nên giả định **không chết hẳn**, xem A.3 |

### A.2 Sống nguyên, không sửa

`1.2` (deploy ≠ đã có token), `1.6` (ba nguồn gốc token), `1.7` (PEG_RATIO, FX risk,
de-peg, redemption), `1.8` (decimals, trần `2^44`, range proof 64-bit), `1.9`
(total-supply invariant), `1.12` (định lượng gas), `1.16` (chain profile), `1.17.3`
(retire), `1.18` (không làm trong v1), `1.20` (kiểm chứng thật).

Ba mục đáng chú ý vì **sống mà không cần biết gì về upgrade**: `1.7`, `1.8`, `1.9` là
phần dày nhất và giá trị nhất của section. Chúng không mất một dòng nào.

### A.3 Sống, nhưng đổi lý lẽ

**`1.3` — bảng so sánh bốn pattern GIỮ NGUYÊN, chỉ lật khuyến nghị.**

Và lý do lật đã nằm sẵn trong chính bảng đó: hàng EIP-1167 ghi *"Không thể upgrade /
Không có hiểm hoạ storage"* — hai cột mà giờ đọc là **ưu điểm**. Điều duy nhất bảng
tính là điểm trừ của EIP-1167:

> *"EIP-1167 rẻ nhất và an toàn nhất nhưng mâu thuẫn trực tiếp với 'support nhiều
> version'."*

**Mệnh đề này sai, và đó là bản lề của cả section.** Nó giả định *"support nhiều
version"* bắt buộc phải là **nâng cấp một token qua nhiều version**. Không phải. Có
cách thứ hai: **nhiều version cùng tồn tại, người tạo chọn một lúc deploy, và nó ghim
vĩnh viễn**. Yêu cầu gốc trong note là *"chia sẻ code, khác data, support nhiều
version"* — EIP-1167 thoả **cả ba**: clone chia sẻ code của implementation, mỗi clone
có state riêng, và catalogue giữ v1/v2/v3 cùng lúc.

Giả định ẩn "version = đường đi theo thời gian của một token" chưa từng được viết ra
để kiểm, và nó là thứ đã đẩy section này sang Beacon.

**`1.3` mục (3) `_disableInitializers()` — GIỮ, vẫn bắt buộc.** Clone cũng không chạy
constructor. Và giả định A5 chỉ **giảm nhẹ**, không mất: kẻ tấn công `initialize()`
implementation rồi `SELFDESTRUCT` nó vẫn brick mọi clone đang trỏ tới. Khác beacon ở
chỗ không ai *thay* được implementation, nhưng *phá* thì vẫn phá được. Giữ nguyên yêu
cầu test on-chain EIP-6780 trên mọi chain.

**`1.3` mục (4) `MAX_AMOUNT()` phải là `view` chứ không `pure` — GIỮ, và QUAN TRỌNG
HƠN TRƯỚC.** Lý lẽ cũ là "mọi token dùng chung một beacon sẽ cùng trần". Lý lẽ mới
mạnh hơn: **mọi tham số per-token giờ đều chỉ có thể đến từ `initialize()`**, vì không
còn đường nào khác để phân biệt hai clone của cùng một implementation. Cùng lỗi này
đã bắt được ở `ZSC.sol:21` (`uint256 constant MAX`).

**`1.5` Prototype Registry — sống, đổi tên và bỏ hai trường.** Cấu trúc gần khớp
`IOpenFactory` đã viết:

| Trường 1.5 | Số phận |
|---|---|
| `archetype`, `majorVersion` | → `(TokenKind kind, uint64 version)` |
| `beacon` | **bỏ** |
| `implementation` | giữ, giờ là đường duy nhất |
| `initCodeHash`, `implCodeHash` | giữ — `predictAddress` off-chain vẫn cần, và với clone thì `init_code` chỉ phụ thuộc `implementation` nên nó **xác định hoàn toàn** |
| `interfaceId` (ERC-165) | giữ — càng cần hơn: factory mở nghĩa là indexer gặp token của người lạ, không tra registry được |
| `deprecated` | giữ, nhưng **chỉ đánh dấu**, không chặn `deploy` (§20.2) |
| `profileMask` | **hạ cấp thành metadata.** Nó chặn deploy archetype `permissioned` lên chain public — đó là gác cổng chính sách, không phải chặn một cái brick. Ai đó có thể có lý do chính đáng. Giữ làm cảnh báo, bỏ `require` |

Câu *"Thêm archetype mới = 1 tx `registerPrototype`, factory không bao giờ phải
upgrade"* — **vẫn đúng, và giờ là xương sống chứ không phải một tiện ích.**

**`1.10` Pause/freeze/blacklist — archetype MẠNH LÊN.**

Bản cũ đảm bảo: *"Khi đã mint dưới `ZTokenOpen` thì không ai bật blacklist về sau, kể
cả admin, kể cả qua upgrade — vì beacon của `ZTokenOpen` chỉ nhận implementation cùng
archetype (registry kiểm tra `archetype` trong `validateUpgrade`)."*

Đó là một lời hứa **thực thi bằng logic registry** — tức là đúng chừng nào registry
không có bug và không ai đổi được registry. Giờ nó được thực thi bằng **vật lý**:
không tồn tại đường nâng cấp nào cả. Lời hứa mạnh lên, cơ chế bảo vệ nó bị xoá.

Và `ZTokenOpen` / `ZTokenPermissioned` ánh xạ tự nhiên thành **hai entry trong
catalogue**. Người tạo muốn token pause được thì chọn version có pause; muốn token
không có admin nào thì chọn version không có. Đó chính là công dụng của catalogue.

`1.10.1` `WIND_DOWN`, `1.10.2` khả kết hợp, `1.10.3` freeze giao Zether — giữ nguyên,
nhưng chuyển chủ thể: đó là cam kết của **người tạo token** với người giữ token của
họ, không phải của ta với thị trường.

---

## B. Quét upgrade toàn bộ — bảng kiểm

| File | Số chỗ | Trạng thái |
|---|---|---|
| `01-token-factory` | 41 beacon + 41 upgrade | **Sửa lớn** — §A |
| `14-contracts-repo-testing` | 22 upgrade, 10 storage-layout | **Sửa lớn** — §B.1 |
| `12-threat-model` | 15 upgrade, 4 storage-layout | Sửa vừa — bỏ vector "beacon nâng cấp cả họ proxy"; **đã tự ghi `ZetherAccountRegistry` không upgradeable và forwarder không upgradeable** |
| `02-account-registry` | 4 | **Không sửa.** Đã chốt *"registry KHÔNG upgradeable"* độc lập |
| `04-eip1776-metatx` | 6 | **Không sửa.** Đã chốt *"forwarder generic KHÔNG upgradeable"*, và bắt được mâu thuẫn A8 |
| `03`, `07`, `10`, `13`, `16` | rải rác | Sửa nhỏ, chỉ là câu chữ |
| `00-CANON` | 2 | Sửa hàng tương ứng ở §C20 |

**`02` và `04` đã đi tới cùng kết luận trước khi có quyết định này.** `04` thậm chí
ghi rõ *"A8 Forwarder UUPS upgradeable — Mâu thuẫn với §12.1"*. Token là mảnh cuối
cùng còn giữ upgrade, và giờ nó cũng bỏ.

### B.1 `14-contracts-repo-testing` phải đổi gì

**Bỏ:**
- Thư mục `proxy/{DmsBeaconProxy.sol, DmsUpgradeableBeacon.sol, PinnedProxy.sol}`
- Gate OZ `validateUpgrade` qua `openzeppelin-foundry-upgrades`
- `extra_output = ["storageLayout"]` và cây `storage-layouts/v<N>/`
- Rule semgrep `contract $C is UUPSUpgradeable { ... }`
- Submodule `openzeppelin-contracts-upgradeable`

**Thêm — bốn test mới, đều nhắm bất biến mà mô hình mới dựa vào:**

1. **Catalogue append-only**: `registerImplementation(kind, v, X)` rồi
   `registerImplementation(kind, v, Y)` phải revert. Đây là bất biến quan trọng nhất
   của factory; không có test thì nó chỉ là một lời hứa trong comment.
2. **Clone bất biến**: sau deploy, không call nào từ bất kỳ địa chỉ nào (creator,
   factory owner, chính token) đổi được `implementation()`. Test phủ định, quét cả
   selector `upgradeTo`/`upgradeToAndCall`/`setImplementation`.
3. **`isSupportedOnThisChain()` bắt được chain thiếu precompile**: fork chain 9000
   (hoặc `vm.etch` xoá 0x0b), verifier BLS phải trả `false` và `createZetherToken`
   phải revert. **Đây là test có giá trị nhất trong bốn cái** — nó là cái bẫy im lặng
   duy nhất còn lại có thể làm mất tiền của người lạ.
4. **Ma trận CI hai curve**: mọi test Zether chạy hai lần, bn254 và BLS12-381, và
   khẳng định `g1EncodedBytes()` là 64 với cái này, 128 với cái kia. Nhầm curve trong
   payload phải revert chứ không được verify sai.

---

## C. Phát hiện lớn nhất: quản trị sụp, và đó là thắng lợi

`1.11` là ~110 dòng: 10 role, Safe 4-of-7, timelock 48h không đường tắt, `RECOVERY`
6-of-7 trễ 30 ngày, cron dò governance drift cross-chain, model `blockchain.upgrade.proposal`
với ràng buộc phải đính kèm báo cáo audit và storage diff.

**Toàn bộ bộ máy đó tồn tại để kiểm soát đúng một quyền: upgrade.** Quyền đó không
còn.

Quyền còn lại của người vận hành factory, đầy đủ:

| Quyền | Hại tối đa gây được |
|---|---|
| `registerImplementation` | Xuất bản một v4 dở. Chỉ ảnh hưởng token deploy **sau** đó, và **chỉ khi có người chọn nó** |
| `deprecate` | Emit một event. Không chặn gì |

Không quyền nào chạm được vào tiền của ai. Nên câu hỏi *"ai giữ khoá factory"* rớt từ
**hạng mục rủi ro sống còn** xuống **vệ sinh vận hành**.

### C.1 Giả định A1 đảo chiều

Bản cũ:

> **A1** — *"Có một khoá nào đó deploy được `DmsTokenFactory`, và khoá đó không bao
> giờ mất. Mất khoá = không deploy được token mới trên chain đó, **và** mất parity địa
> chỉ cross-chain vĩnh viễn."*

Bây giờ: mất khoá ⇒ catalogue đóng băng ở version cuối, **và mọi người vẫn deploy
được qua `createUnregistered`**. Suy giảm, không chết. Đó là một cải thiện độ bền có
thật, đến miễn phí từ việc bỏ upgrade — và nó đáng được ghi ra vì hồ sơ rủi ro cũ
đang xếp A1 ở mức thảm hoạ.

### C.2 `1.11` không bị xoá, nó ĐỔI CHỦ THỂ

Các role **bên trong một token** — `MINTER`, `BURNER`, `TREASURY_ROLE`, `RATE_SIGNER`,
`ATTESTOR`, `GUARDIAN`, `pause` — không biến mất. Chúng thuộc về **người tạo token**,
đặt lúc `initialize()`.

Nên `1.11` viết lại thành hai phần khác hẳn nhau:

- **C.2.a Quản trị factory** — gần như trống. Một khoá registrar, và mất nó cũng không
  chặn được ai.
- **C.2.b Hướng dẫn cho người tạo token** — bảng role cũ giữ gần nguyên, nhưng đổi
  giọng từ *"ta phải làm thế này"* sang *"nếu token của bạn có `MINTER`, đây là các
  ngưỡng đã cân nhắc và đây là lý do"*. Cộng với: **archetype không có role nào cả**
  cũng là một lựa chọn hợp lệ, và trên factory mở nó nên là lựa chọn được ghi trước.

Câu `1.19` #4 (*"Ai là 7 người ký Safe?"*) và #7 (*"Chấp nhận `MAX_PAUSE = 7 ngày`?"*)
rời khỏi danh sách chặn của **ta**, thành câu hỏi của mỗi người tạo token. `1.19` #5
(*"Ai chạy 4 validator private chain?"*) vẫn là của ta.

---

## D. Thứ NẶNG THÊM: `MigrationSink` thành đường duy nhất

`1.17.2` mở đầu bằng *"Migrate (khi upgrade không đủ)"* và liệt kê những gì upgrade
không giải quyết được: đổi storage layout, đổi decimals, đổi archetype, đổi chain.

**Bỏ upgrade thì danh sách đó thành: mọi thứ.** Một lỗi logic tầm thường ở v1 — thứ
trước đây vá bằng một `upgradeTo` — giờ cũng phải đi qua migration.

`MigrationSink` do đó **không còn là phụ lục**. Nó là một entry catalogue hạng nhất,
phải có trong v1, phải được audit cùng đợt với token. Và ba ràng buộc `1.17.2` đã liệt
kê trở thành ràng buộc thiết kế đầu bảng chứ không phải chú thích:

1. `oldToken` phải vào `WIND_DOWN` trước, nếu không tổng cung hai token vượt `maxSupply`.
2. `MINTER` cấp cho `MigrationSink` phải có `maxMintPerEpoch = oldToken.totalSupply()`
   và **hết hạn** sau `deadline`.
3. **Số dư confidential không migrate được bằng `burnFrom`** — contract không biết nó
   bằng bao nhiêu. Người giữ phải `withdraw` về công khai trước. Đó là một chiến dịch
   truyền thông, không phải một hàm. **Cửa sổ tối thiểu 180 ngày.**

Điểm (3) là cái giá thật của việc bỏ upgrade với token Zether, và nó phải được nói
thẳng ở chỗ dễ thấy: **vá một lỗi ở một Zether token nghĩa là mọi người giữ số dư bí
mật phải tự tay lộ số dư ra công khai rồi chuyển sang token mới.** Không có đường nào
khác — và nếu có ai đó *không* làm trong 180 ngày thì tiền của họ nằm lại ở token cũ.

Hệ quả: **v1 của implementation Zether phải được audit nặng hơn v1 của Meta Token**,
vì cái giá của một lỗi cao hơn hẳn. Đây là chỗ ngân sách audit nên dồn về.

Và trên factory mở, `MigrationSink` phải deploy được bởi **người tạo token**, cho token
**của họ** — ta không deploy hộ ai. Thêm một `TokenKind.MIGRATION` vào catalogue.

---

## E. Việc phải làm với `01`

Không viết lại cả section. Sửa đúng bảy chỗ:

| # | Mục | Việc |
|---|---|---|
| 1 | `1.0` bảng 12 quyết định | Quyết định #1, #2, #11 viết lại; thêm một dòng về catalogue version |
| 2 | `1.1.1` | A1 viết lại (đảo chiều, §C.1); A5 giữ nhưng ghi rõ là "phá được, không thay được" |
| 3 | `1.3` | Giữ bảng, lật khuyến nghị, và **nói rõ mệnh đề "EIP-1167 mâu thuẫn với nhiều version" sai ở đâu** (§A.3). Bỏ mục (1), (2), (5); giữ (3), (4) |
| 4 | `1.4` | Ba tầng → hai tầng |
| 5 | `1.5` | Bỏ `beacon` và `DEPLOYER_ROLE`; `profileMask` hạ thành metadata; `deprecated` chỉ đánh dấu |
| 6 | `1.11` | Tách đôi theo §C.2. Xoá model `blockchain.upgrade.proposal` |
| 7 | `1.17.2` | Nâng `MigrationSink` lên hạng nhất, thêm `TokenKind.MIGRATION` (§D) |

`1.13` sửa hai dòng: bỏ `upgrade_proposal.py`, đổi `upgradeable` thành
`version` + `implementation_address`.
