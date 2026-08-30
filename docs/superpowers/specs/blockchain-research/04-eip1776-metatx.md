## 04. EIP-1776 Meta-Transaction: struct, 2D nonce, mode bitmask

Phần này đặc tả tầng envelope. Zether là *inner call*, không phải một tầng song song.
Mọi thứ dưới đây nằm trong `smartcontracts/evm/metatx/`, tách khỏi addon Odoo.

```
smartcontracts/evm/metatx/
├── src/MetaTxForwarder.sol          # verifyingContract cho hình thái generic, KHÔNG upgradeable
├── src/ERC1776Native.sol            # mixin nhúng thẳng vào ZetherToken / token nội bộ
├── src/lib/MetaTxLib.sol            # TYPEHASH, canonical hashing, mode, encode/decode
├── src/lib/ExcessivelySafeCall.sol  # call với out=0 + returndatacopy có cap
├── src/TargetPolicy.sol             # allowlist target + cờ appendsSender (04.6.5)
├── test/MetaTxForwarder.t.sol       # foundry, fuzz mode x nonce x gas
├── test/Griefing.t.sol              # return bomb, gas burn, 63/64
├── test/vectors/metatx_v1.json      # *** test vector chuẩn, xem 04.13 ***
└── foundry.toml
dms_blockchain/lib/eip1776.py        # signer thuần Python, KHÔNG import odoo
dms_blockchain/tests/test_eip1776_vectors.py   # đọc chính metatx_v1.json ở trên
dms_blockchain/models/blockchain_metatx.py
```

---

### 04.0. Những giả định bản nháp đã dùng mà không nói ra

Bản nháp trước của section này (và `blockchain.md` §10.2.1) đứng trên tám giả định không được
phát biểu. Sáu trong số đó sai hoặc chỉ đúng có điều kiện. Bảng này là hợp đồng: mọi thứ phía
sau chỉ đúng khi các dòng dưới đây được giữ.

| # | Giả định ẩn | Trạng thái | Xử lý ở đâu |
|---|---|---|---|
| A1 | `from` đã `approve` forwarder trước đó | **Sai** — user không có native gas thì không `approve` được. Bootstrap chicken-and-egg | 04.6.4 |
| A2 | Forwarder giữ allowance là an toàn | **Sai nghiêm trọng** — cho phép rút sạch mọi user đã approve | 04.6.3 |
| A3 | Target biết `from` là ai | **Sai** — target chỉ thấy `msg.sender == forwarder`. Không có ERC-2771 suffix trong struct của note | 04.6.5 |
| A4 | `amount` và `fee` cùng một token là chấp nhận được | **Chỉ đúng một phần** — loyalty point không trả được relayer | 04.1 |
| A5 | `uint8 mode` đủ chỗ | **Sai** — §05.3.3 đã xin `0x04` cho `MODE_METERED_FEE`, va chạm với `MODE_REQUIRE_SUCCESS` | 04.4 |
| A6 | Zether inner call tốn ~250k gas | **Sai một bậc độ lớn** — con số đúng là 2.0M–3.2M | 04.10 |
| A7 | Zether proof gắn với epoch nên expiry ≤ 1 epoch | **Không còn đúng** sau quyết định owner-exclusive rollover ở §03.5 | 04.5 |
| A8 | Forwarder UUPS upgradeable | **Mâu thuẫn với §12.1** — upgradeable + allowance = rug vector | 04.2 |

Ba giả định còn lại vẫn đứng và được giữ nguyên: EIP-712 digest là khoá idempotency duy nhất;
`mode` phải nằm trong hash; `innerGasLimit` phải nằm trong digest.

---

### 04.1. Struct: bản gốc trong note và bản đã vá

Struct trong `blockchain.md` §10.2.1 thiếu **ba** trường. Bản dùng để triển khai:

```solidity
struct MetaTransaction {
    address from;            // signer (EOA hoặc smart account EIP-1271)
    address to;              // target của inner call
    address tokenContract;   // ERC-20 dùng cho `amount` (envelope layer, công khai)
    address feeToken;        // *** THÊM MỚI *** token trả cho relayer; 0x0 = dùng tokenContract
    uint256 amount;          // principal chuyển thẳng from -> to; 0 nếu chỉ gọi logic
    bytes   data;            // calldata cho `to`, CHƯA có sender suffix (xem 04.6.5)
    uint256 batchId;         // lane của 2D nonce
    uint256 batchNonce;      // số thứ tự trong lane
    uint256 fee;             // thưởng token cho relayer (trần, nếu MODE_METERED_FEE)
    uint256 innerGasLimit;   // *** THÊM MỚI *** trần gas cấp cho inner call
    uint256 expiry;          // unix seconds, inclusive
    uint32  mode;            // *** MỞ RỘNG từ uint8 *** bitmask, xem 04.4
    address relayer;         // chỉ bind khi mode & 0x01
    address feeRecipient;    // chỉ bind khi mode & 0x02
}
```

**`innerGasLimit` phải nằm trong digest.** Nếu để relayer tự chọn, relayer cấp thiếu gas cho
inner call, inner call OOG, forwarder vẫn sống (quy tắc 63/64), fee vẫn trả, nonce vẫn tăng —
người dùng mất tiền, hành động nghiệp vụ không xảy ra. Đây là lỗ hổng kinh điển của GSN v1.

**`mode` là `uint32`, không phải `uint8`.** Tốn **0 gas thêm**: ABI encode padding cả hai về 32
byte trong calldata, và trong struct hash cả hai chiếm đúng một word. `uint8` chỉ còn 3 bit trống
sau khi §04.4 và §05.3.3 lấy 5 bit; hết bit giữa vòng đời của contract nghĩa là bump `version`
và vô hiệu hoá mọi chữ ký đang lưu hành. Đây là quyết định free-of-charge, làm ngay.

**`feeToken` tách khỏi `tokenContract`.** Note gộp hai vai trò vào một trường. Nó hỏng ở đúng
use case đã chốt số 1: loyalty/reward point. User giữ điểm thưởng; **không relayer mở nào chấp
nhận điểm thưởng làm phí** vì không có thị trường thứ cấp (§05.3.3 nguồn 2). Ba lối ra và lối
được chọn:

| Cách | Chi phí | Đánh giá |
|---|---|---|
| Giữ một token, luồng point phải để `fee = 0` và issuer trợ cấp off-envelope | 0 | Đẩy phức tạp sang §05.7, và relayer không đọc được cam kết trả tiền trong chính intent |
| Hai metaTx (một trả fee bằng USDC, một chuyển point) | +21,000 gas, +1 chữ ký, mất tính nguyên tử | Loại |
| **Thêm `feeToken`** | +32 byte calldata (~512 gas), +1 word struct hash (~30 gas) | **Chọn.** `feeToken == address(0)` giữ nghĩa cũ, tương thích ngược với mọi ví dụ trong note |

Quy ước bắt buộc: `feeToken` **luôn** nằm trong digest ở dạng như user ký (không canonical-zero
hoá — nó không phải trường do relayer điền).

Hai hình thái deploy, khác nhau ở `verifyingContract`:

| Hình thái | verifyingContract | Upgradeable | Bootstrap allowance | Dùng khi |
|---|---|---|---|---|
| `MetaTxForwarder` (generic) | 1 contract/chain | **KHÔNG** (§12.1) | cần `permit`/`transferWithAuthorization` mỗi tx | mọi `to` bất kỳ |
| `ERC1776Native` mixin | chính token contract | UUPS (theo note §10.2.1) | không cần (token tự trừ nội bộ) | Z-token, token nội bộ do issuer phát hành |

Với Zether, dùng **native mixin trên ZetherToken**: user chưa có native gas thì cũng chưa thể
`approve`, `permit` không tồn tại trên số dư ElGamal, và chỉ mixin mới enforce được điều cấm
hai-kênh-phí ở 04.10.

---

### 04.2. EIP-712 domain: từng trường đều chịu lực

```solidity
bytes32 constant DOMAIN_TYPEHASH = keccak256(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
// name = "BambooMetaTx", version = "1"
```

| Trường | Chặn được gì | Vì sao load-bearing **ở kiến trúc này cụ thể** |
|---|---|---|
| `chainId` | replay xuyên chuỗi | Note yêu cầu **Factory + CREATE2** (dòng 9). CREATE2 cho ra **cùng một address** trên Gnosis, Celo, mọi EVM khác nếu cùng `(deployer, salt, initcode)`. `verifyingContract` do đó **không** phân biệt được chain. `chainId` là thứ duy nhất còn lại. Bỏ nó = chữ ký testnet Chiado dùng được trên Gnosis mainnet. |
| `verifyingContract` | replay xuyên contract | Phân biệt Z-USDC với Z-VND khi cả hai đều dùng `ERC1776Native` mixin, cùng `TYPEHASH`, cùng chain. |
| `version` | revoke hàng loạt + upgrade | **Chỉ load-bearing trên hình thái native mixin.** Xem đoạn dưới. |
| `name` | domain collision | Cùng contract có thể ký cả `Permit` (EIP-2612) lẫn `MetaTransaction`. Nếu cùng `name` và một type string mới tình cờ có prefix trùng, hai TYPEHASH vẫn khác nhau — nhưng `name` là lớp phòng thủ rẻ nhất và là cách duy nhất tách hai product khác nhau deploy cùng bytecode. |

**Sửa so với bản nháp: forwarder generic KHÔNG upgradeable.** §12.1 chỉ đúng —
`approve(forwarder, max)` cộng với một forwarder UUPS nghĩa là chủ upgrade key rút được sạch mọi
user. Hệ quả dây chuyền:

- Nâng cấp = deploy `MetaTxForwarderV2` ở address mới ⇒ `verifyingContract` mới ⇒ mọi chữ ký v1
  tự động chết. Trường `version` trong domain **không còn tác dụng gì** ở hình thái này.
- Trên `ERC1776Native` mixin thì ngược lại: token là UUPS, address giữ nguyên qua upgrade, nên
  `version` là **cơ chế duy nhất** vô hiệu hoá chữ ký v1 khi v2 đổi nghĩa `mode` hay thêm trường.
  Bump `version` trong `_authorizeUpgrade`, không phải trong một hàm admin riêng — để không bao
  giờ quên.

Hệ quả bắt buộc trên code cho **cả hai** hình thái: **không hard-code `DOMAIN_SEPARATOR` vào
bytecode**. Hard fork đổi `chainid` được (Gnosis tách từ Ethereum Classic-style fork là tiền lệ
có thật), và UUPS proxy khiến constructor của implementation chạy ở storage context sai. Dùng
pattern lazy của OpenZeppelin `EIP712`/`EIP712Upgradeable`: so `block.chainid` với giá trị đã
cache, khác thì tính lại. Chi phí ở nhánh cache-hit: 1 `SLOAD` warm (~100 gas).

---

### 04.3. 2D nonce: lane, cấp phát, chi phí thật, và giới hạn thật

```solidity
mapping(address => mapping(uint256 => uint256)) private _metaNonce;
function meta_nonce(address from, uint256 batchId) external view returns (uint256);
```

Kiểm tra là `require(metaTx.batchNonce == _metaNonce[from][batchId])` — **bằng đúng**, không phải
`>=`. Nonce 1D truyền thống bị head-of-line blocking vì mọi giao dịch chung một bộ đếm: một tx kẹt
mempool ở nonce N làm mọi tx N+1.. treo. Với 2D, lane K kẹt chỉ chặn lane K.

**Giới hạn phải nói thẳng, đừng bán quá.** 2D nonce xoá head-of-line blocking **ở tầng envelope,
cho mỗi cặp `(from, batchId)`**. Nó **không** xoá được ba thứ:

1. **Serialize ở tầng Zether.** `zetherNonce(fromSchnorrAddress)` bị băm vào Fiat-Shamir challenge
   (§03.4). Hai intent Zether đồng thời từ cùng một `schnorrAddress` thì cái thứ hai có proof
   **vô hiệu vĩnh viễn**, phải sinh lại (~200–800 ms CPU). §05.4.3 enforce single-flight cho
   trường hợp này. `batchId` không cứu được vì điểm serialize nằm dưới envelope.
   Cách duy nhất song song hoá thật: **pool nhiều `schnorrAddress`**, một per settlement worker.
2. **Serialize ở tầng relayer.** Một relayer dùng một EOA thì nonce EOA của chính nó là 1D. Đây
   là vấn đề của §06 (relay pool), không phải của envelope.
3. **Thứ tự giữa các lane.** `batchNonce` chỉ bảo đảm thứ tự **trong một lane**. Escrow ở lane A
   và settle ở lane B có thể bị relayer đảo. Quy tắc cứng phía Odoo (khớp §12.2): mọi chuỗi phụ
   thuộc **phải** dùng cùng một `batchId`.

**Cấp phát batchId không đụng độ.** Hai chế độ, chọn theo bản chất tác vụ:

```python
# Song song, one-shot: dẫn xuất tất định từ bản ghi nghiệp vụ. Không cần registry tập trung,
# hai worker Odoo cùng dựng lại được một batchId giống nhau cho cùng một record.
LANE_DOMAIN = b'bamboo.metatx.lane.v1'
batch_id = int.from_bytes(keccak(
    encode(['bytes32', 'bytes32', 'string', 'uint64', 'uint32'],
           [keccak(LANE_DOMAIN), db_uuid, 'dms.trade.settlement', rec_id, lane_epoch])),
    'big')
# lane_epoch: bộ đếm tăng khi phải rời bỏ một lane chết (04.3 "gỡ lane kẹt"). Bắt đầu ở 0.

# Tuần tự (escrow -> deposit -> settle): cố định batch_id, batch_nonce 0 -> 1 -> 2.
```

Xác suất đụng độ của keccak 256-bit: sinh nhật ở 2^128 lane. Bỏ qua.

**Mâu thuẫn với §10.4.5 phải sửa ở §10, không ở đây.** §10.4.5 khai
`models.Constraint('UNIQUE(chain_id, from_account_id, batch_id_hex, batch_nonce)', ...)`. Ràng
buộc đó **chặn retry hợp lệ**: một metaTx hết hạn *không tiêu nonce* (04.5), nên bản ký lại phải
dùng đúng `(batch_id, batch_nonce)` cũ — và INSERT sẽ vi phạm UNIQUE. Phải là partial index:

```python
# dms_blockchain/models/blockchain_metatx.py
_unique_live_lane = models.Constraint(
    "UNIQUE NULLS NOT DISTINCT (chain_id, from_account_id, batch_id_hex, batch_nonce, lane_slot)",
    'Mot lane (batchId, batchNonce) chi duoc co mot ban ghi song.')
# lane_slot: Integer, NULL khi metatx_state in ('expired','failed','superseded'),
#            = 0 khi con song. Compute stored, MOI nhanh deu gan gia tri (bay Odoo 19).
```

Lý do dùng `lane_slot` nullable thay vì partial unique index: Odoo `models.Constraint` sinh
`ALTER TABLE ... ADD CONSTRAINT`, không sinh được `CREATE UNIQUE INDEX ... WHERE`. Muốn partial
index thật thì phải đặt trong `init()` — được, nhưng khi đó `pg_constraint` không có dòng nào và
bài test kiểm chứng ở §12 phải đọc `pg_indexes` thay vì `pg_constraint`. Ghi rõ để không ai đọc
`pg_constraint` rồi kết luận constraint bị Odoo 19 nuốt.

**Chi phí thật của lane mới** (EIP-2929 cold access 2,100 + EIP-2200 SSTORE):

| Thao tác | Gas | Gnosis @1.5 gwei | Ethereum L1 @25 gwei, ETH $3,000 |
|---|---|---|---|
| Lane mới (SSTORE 0→nonzero, cold) | 22,100 | $0.0000332 | $1.66 |
| Lane tái dùng (nonzero→nonzero, cold) | 5,000 | $0.0000075 | $0.375 |
| Chênh lệch | 17,100 | $0.0000257 | $1.28 |

Kết luận có số: trên Gnosis/Celo dùng batchId ngẫu nhiên mỗi tx thoải mái. Trên Ethereum L1
**không được** — 17,100 gas × 50,000 tx/tháng = 855M gas = **17.1 ETH/tháng ≈ $51,300/tháng ở 25
gwei**. Dùng pool cố định 64 lane/`from` (`batchId = laneBase + i`, round-robin). Đây là một lý
do kỹ thuật nữa cho thứ tự Gnosis → Celo trước.

**Chi phí state, thứ note và bản nháp đều bỏ qua.** Mỗi lane là một slot 32 byte **vĩnh viễn** —
không có cơ chế xoá, và EIP-3529 đã cắt refund SSTORE xuống còn tối đa 4,800 gas nên xoá cũng
không hoàn vốn. Ước lượng (cơ sở: một leaf trong Merkle-Patricia trie tốn ~150–200 byte kể cả
node trung gian và index của client):

| Chiến lược batchId | Slot mới/tháng @50k tx | State/năm |
|---|---|---|
| Ngẫu nhiên mỗi tx | 50,000 | ~90–120 MB |
| Pool 64 lane/`from`, 2,000 `from` | 128,000 một lần rồi 0 | ~25 MB tổng cộng, không tăng |

Trên chain private (profile đã chốt, §04.11) đây là chi phí của chính doanh nghiệp và nó tuyến
tính theo số tx — pool lane là mặc định đúng ở mọi profile trừ khi đo được ngược lại.

**Gỡ lane kẹt.** Note không nói cách này. Một metaTx hết hạn **không** tiêu nonce, nên nếu client
đã ký sẵn `batchNonce+1` thì lane chết vĩnh viễn. Ba biện pháp, dùng cả ba:

1. Quy tắc client: trong một lane, **không ký `batchNonce+1` trước khi `batchNonce` đạt Finality
   Gate**. Đây chính là nguyên tắc VietQR áp cho nonce: *broadcast chưa phải là đã xong*.
2. `function bumpBatchNonce(uint256 batchId, uint256 newNonce) external` — chỉ `msg.sender == from`,
   `require(newNonce > _metaNonce[from][batchId])`, để chủ tài khoản tự nhảy qua khe chết.
   `batchId = 0` reserve cho vận hành thủ công/admin.
3. `lane_epoch` trong công thức dẫn xuất ở trên: bỏ hẳn lane cũ, sang lane mới. Rẻ hơn
   `bumpBatchNonce` (không cần tx) nhưng tốn 22,100 gas cho slot mới. Trên Gnosis chọn (3), trên
   L1 chọn (2).

**Griefing của chính `bumpBatchNonce`** (bản nháp bỏ sót): user gọi `bumpBatchNonce` **sau khi**
relayer đã claim intent nhưng **trước khi** tx được include ⇒ tx của relayer revert ở check nonce,
relayer mất gas. Chi phí trên Gnosis là $0.00003 nên không đáng để chống bằng contract; chống
bằng reputation off-chain (§05.4.4b: `from` bị đánh dấu, hub hạ ưu tiên). Trên L1 thì đáng
$1.66 và phải chặn bằng `MODE_RESTRICT_RELAYER` + hợp đồng SLA.

---

### 04.4. Mode bitmask và bài toán digest

**Cấp phát bit — bảng này là nguồn sự thật duy nhất cho toàn bộ tài liệu.** §05.3.3 đề xuất
`MODE_METERED_FEE = 0x04`, va chạm với `MODE_REQUIRE_SUCCESS` của section này. Giải quyết ở đây
vì section này sở hữu bitmask:

```solidity
uint32 constant MODE_OPEN                   = 0x0000_0000;  // không phải một bit, là "không bit nào"
uint32 constant MODE_RESTRICT_RELAYER       = 0x0000_0001;
uint32 constant MODE_RESTRICT_FEE_RECIPIENT = 0x0000_0002;
uint32 constant MODE_REQUIRE_SUCCESS        = 0x0000_0004;  // 04.6
uint32 constant MODE_METERED_FEE            = 0x0000_0008;  // *** DỜI từ 0x04, xem §05.3.3 ***
uint32 constant MODE_APPEND_SENDER          = 0x0000_0010;  // 04.6.5 — chỉ dùng nếu chọn per-tx
// 0x20 reserve: commit-reveal MEV (§05.4.4c) nếu bao giờ cần
// 0x40 reserve: multi-call inner (danh sách call thay vì một call)
uint32 constant MODE_KNOWN_MASK             = 0x0000_001F;
```

`MODE_RESTRICT_BOTH = 0x03` của note giữ nguyên nghĩa (`0x01 | 0x02`) nhưng **không** nên là một
hằng riêng trong code — nó là một tổ hợp, không phải một chế độ. Giữ nó trong tài liệu, bỏ khỏi
`.sol`, để không ai viết `if (mode == MODE_RESTRICT_BOTH)` (so sánh bằng thay vì mask là bug chờ
xảy ra khi bit 0x04/0x08 được bật cùng lúc).

Note viết "chữ ký KHÔNG bao gồm `feeRecipient` và `relayer` trong digest hash (**hoặc** hash với
`address(0)`)". Chữ "hoặc" đó là chỗ hỏng. Hai cách cho ra hai digest khác nhau; nếu client chọn
cách A và verifier làm cách B thì mọi chữ ký fail. Phải chốt **một** cách, và phải là cách verifier
tự chuẩn hoá — không được hash calldata như nó đến.

Chọn **hash với `address(0)`**, không phải "bỏ trường ra khỏi struct". Lý do quyết định: EIP-712
`TYPEHASH` là hash của *type string*, và type string phải cố định. Nếu MODE_OPEN bỏ hai trường ra
khỏi struct thì nó là một **type khác**, cần một `TYPEHASH` thứ hai, và ví EIP-712 (MetaMask,
Rabby, mọi smart account) sẽ hiển thị hai type khác nhau cho cùng một hành động — người dùng
không đọc được. Một type string, hai giá trị canonical.

**Quy tắc canonical zeroing (bắt buộc, cả hai phía):**

```solidity
function _canon(MetaTransaction calldata m) internal pure returns (address r, address f) {
    r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
    f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
}
```

Verifier hash `(_canon(m).r, _canon(m).f)`, **không** hash `m.relayer`/`m.feeRecipient` thô. Nhờ vậy
trong MODE_OPEN relayer tự điền hai ô đó trong calldata mà digest không đổi; trong mode restrict,
ô đó đã nằm trong digest nên relayer sửa là chữ ký chết.

**Ba trường còn lại phải quyết cùng lúc, bản nháp bỏ sót:**

| Trường | MODE_OPEN | Restrict | Quy tắc |
|---|---|---|---|
| `relayer` | canonical → 0 | trong digest | như trên |
| `feeRecipient` | canonical → 0; contract dùng `msg.sender` khi runtime value là 0 | trong digest | như trên |
| `feeToken` | **luôn trong digest** | **luôn trong digest** | không phải trường của relayer |
| `fee` với `MODE_METERED_FEE` | **luôn trong digest** — nó là *trần*, không phải giá trị thực thu | như trên | contract chuyển `min(m.fee, gasUsed * rate)`; xem §05.3.3 |

Nghĩa là `MODE_METERED_FEE` **không** thay đổi quy tắc canonical, chỉ thay đổi số tiền thực
chuyển. Đó là lý do nó an toàn khi OR chung với 0x01/0x02.

**Vì sao không có cross-mode replay:** `mode` nằm *bên trong* struct được hash. Một chữ ký MODE_OPEN
mã hoá `(mode=0x00, relayer=0, feeRecipient=0)`; một chữ ký MODE_RESTRICT_RELAYER mã hoá
`(mode=0x01, relayer=R, feeRecipient=0)`. Word `mode` khác nhau ⇒ digest khác nhau ⇒ không thể lấy
chữ ký mode này dùng cho mode kia. Nếu bỏ `mode` ra khỏi struct (thiết kế mà một số bản 1776 dạo
quanh dùng) thì MODE_OPEN và MODE_RESTRICT_* với `relayer=0` sẽ trùng digest — sập ngay. **`mode`
bắt buộc ở trong hash.**

**Bắt buộc reject bit lạ và tổ hợp vô nghĩa:**

```solidity
require(m.mode & ~MODE_KNOWN_MASK == 0, "MODE_UNKNOWN");
if (m.mode & MODE_RESTRICT_RELAYER != 0)       require(m.relayer != address(0),      "MODE_ZERO_RELAYER");
if (m.mode & MODE_RESTRICT_FEE_RECIPIENT != 0) require(m.feeRecipient != address(0), "MODE_ZERO_FEE_RCP");
require(m.amount == 0 || (m.mode & MODE_REQUIRE_SUCCESS) != 0,  "AMOUNT_NEEDS_SUCCESS"); // 04.6
require(m.fee == 0   || m.feeToken != address(0) || m.tokenContract != address(0), "NO_FEE_TOKEN");
```

Dòng `AMOUNT_NEEDS_SUCCESS` là **bổ sung quan trọng nhất của lần review này ở tầng mode** và được
giải thích ở 04.6.2.

**Malleability còn lại, và hệ quả cho Odoo.** Digest bất biến, nhưng **calldata thì malleable**:
trong MODE_OPEN, hai calldata khác nhau (`feeRecipient = A` và `= B`) cùng verify với **một** chữ ký.
Bốn hệ quả cụ thể:

1. Off-chain **không** được dùng `keccak256(signature)` hay `keccak256(calldata)` làm khoá idempotency.
   Khoá duy nhất là **EIP-712 digest**. Trong Odoo: `digest_hash` char(66),
   `models.Constraint('UNIQUE(digest_hash)', 'Digest phai duy nhat.')`.
2. Event phải phát **cả** digest **và** relayer/feeRecipient **thực tế**, và "thực tế" nghĩa là
   `msg.sender` và biến `feeRcp` sau khi resolve — **không phải** `m.relayer`/`m.feeRecipient` đọc
   từ calldata. Trong MODE_OPEN, `m.relayer` có thể là rác tuỳ ý mà không ai check; nếu indexer đọc
   trường đó nó sẽ ghi vào `ods.chain_meta_tx_relay_ledger` một địa chỉ relayer sai.
3. ECDSA malleability cổ điển (`s` nửa trên, `v` lật) tạo ra chữ ký thứ hai cho cùng digest. Nonce
   chặn replay nên không mất tiền, nhưng nó phá mọi dedupe theo chữ ký. Dùng
   `ECDSA.tryRecover` của OpenZeppelin (reject `s > secp256k1n/2`, `v ∉ {27,28}`), không dùng
   `ecrecover` trần, và **bắt buộc** `require(recovered == m.from && m.from != address(0))` —
   `ecrecover` trả `address(0)` khi fail, nên một chữ ký rác với `from = address(0)` sẽ pass nếu
   thiếu vế thứ hai.
4. Độ dài `signature` không giới hạn là một vector calldata-DoS rẻ tiền với EIP-1271 (contract
   verifier có thể chấp nhận chữ ký dài tuỳ ý). `require(signature.length <= 2048, "SIG_TOO_LONG")`.

**Smart account / passkey.** Quyết định custody đã chốt là phải hỗ trợ smart-account/passkey, nên
`ecrecover` một mình không đủ: dùng `SignatureChecker.isValidSignatureNow(from, digest, sig)`
(fallback EIP-1271 staticcall). Chi phí: +~9,000 gas ước lượng (2,600 cold account access + ~3,000
staticcall overhead + verifier logic; một verifier P-256/passkey dùng precompile RIP-7212 tốn
3,450 gas, một verifier Solidity thuần tốn 150,000–330,000 gas — **con số này quyết định
`innerGasLimit` và phải hỏi trước, không đoán**). Đánh đổi phải nói rõ: **EIP-1271 khiến tính hợp
lệ của chữ ký trở nên *mutable*** — smart account có thể revoke giữa lúc simulate và lúc inclusion.
Đây là lý do thứ hai (sau serialize Zether) để giữ `expiry` ngắn.

---

### 04.5. Expiry

`require(block.timestamp <= m.expiry, "EXPIRED")`. Manipulation timestamp của validator ±12s là
không đáng kể ở mọi ngưỡng dưới đây. **Con số 15 phút trong note (§10.3) sai** — không phải vì lý
do bản nháp đưa ra, mà vì lý do kinh tế: một `expiry` dài là một **free option** cho relayer. Relayer
giữ intent, quan sát thị trường, broadcast lúc có lợi cho mình. 900 giây trên một luồng tiền là
900 giây user không kiểm soát được thời điểm.

**Sửa so với bản nháp: expiry của Zether KHÔNG còn bị epoch ràng buộc.** Bản nháp viết
"`expiry` ≤ 1 epoch = 20s" dựa trên mô hình epoch-based rollover. §03.5 đã chốt **owner-exclusive
rollover**: `acc[from]` chỉ đổi trong transaction do chính `from` khởi tạo, nên proof chỉ phụ
thuộc `zetherNonce`, không phụ thuộc epoch, và rủi ro revert do trôi epoch **bằng 0**. Ràng buộc
thật còn lại là §05.4.3 single-flight: chỉ một Zether intent bay cho mỗi `schnorrAddress`.

| Loại inner call | expiry đề xuất | Ràng buộc thật |
|---|---|---|
| Anchor hash, ghi log, redeem loyalty point | 900s | chỉ chống delayed-replay; không có state đọc |
| ERC-20 transfer công khai | 300s | free-option risk; giá token không đổi trong 5 phút thì bằng 0 |
| Gọi contract nghiệp vụ có state đọc | 120s | state đọc có thể đổi giữa simulate và inclusion |
| `transferConfidential` (Zether) | **60s** | **không phải epoch** — mà là: (a) mỗi giây expiry là một giây lane `schnorrAddress` bị khoá single-flight; (b) EIP-1271 revoke window; (c) proof đã tốn 200–800 ms CPU, ký lại không đắt |
| `withdraw` (Zether → ERC-20 công khai) | 60s | như trên, cộng anti-MEV: `recipient` đã băm vào challenge (§03.7) nên không có gì để front-run, nhưng cửa sổ ngắn giảm bề mặt |

Cơ sở của con số 60s cho Zether: Gnosis 5s/block. 60s = 12 block. Xác suất một relayer đã claim
intent không include được trong 12 block khi mạng không nghẽn là dưới 1% (cơ sở: p99 time-to-inclusion
trên Gnosis ở gas price mặc định thường dưới 3 block). Đặt 20s (4 block) như bản nháp làm tỷ lệ
expired tăng lên mức phải retry thường xuyên mà không đổi lại được gì — vì rủi ro epoch đã biến mất.
Trên Celo (đã migrate lên L2, ~1s/block từ 2025) 60s = 60 block, thoải mái hơn nữa.

Thứ tự check (quan trọng cho kinh tế relayer, xem 04.9):

```
1. mode validity (0 gas — pure bit ops, loại calldata rác trước khi đọc storage)
2. expiry        (0 gas)
3. nonce         (SLOAD cold 2,100 — loại nhanh kẻ thua cuộc đua)
4. signature     (~3,000 ecrecover / ~9,000+ EIP-1271)
5. effects       (nonce++)
6. interactions  (fee, principal, inner call)
```

**Sửa so với bản nháp**: bản nháp để `nonce` trước `expiry`. Sai thứ tự — `expiry` và `mode` tốn
**0 gas** (chỉ đọc calldata và so sánh), `nonce` tốn 2,100 gas cold SLOAD. Kiểm tra cái miễn phí
trước. Chênh lệch 2,100 gas × tỷ lệ intent hết hạn (ước 2–5% trên một open mempool) là nhỏ nhưng
miễn phí để lấy.

Expiry check nằm **trước** bước 5 là điều làm cho mô hình an toàn: relayer trễ hạn thì cả tx
revert, **nonce không bị tiêu và fee không bị trả**. Rủi ro thời điểm rơi vào đúng bên duy nhất
kiểm soát được thời điểm — relayer.

---

### 04.6. Return data, bubbling revert, và fee guarantee

Đây là quyết định kinh tế, không phải quyết định kỹ thuật.

| Chính sách | Nonce | Fee | Ai chịu rủi ro |
|---|---|---|---|
| Bubble revert (cả tx revert) | không tiêu | không trả | **Relayer** đốt gas, không được gì |
| Swallow revert (ghi `success=false`) | tiêu | trả | **User** trả fee cho một hành động không xảy ra |

Không có đáp án đúng chung. Vì vậy để **người ký chọn**, qua bit `MODE_REQUIRE_SUCCESS (0x04)`:

- Mặc định (bit tắt) = **swallow**. Đúng cho open relayer market: relayer bán blockspace, không bán
  kết quả nghiệp vụ. Không có nó thì không relayer mở nào dám nhận đơn từ người lạ.
- Bit bật = **bubble**. Đúng cho Zether và cho mọi luồng tiền: thà không có gì còn hơn mất fee mà
  tiền không chuyển. Relayer sẽ hét fee cao hơn hoặc từ chối — chấp nhận được, vì Simulation Gate
  đã lọc phần lớn.

**Cách bubble đúng.** Không phải `require(success)` — nó nuốt mất lý do revert và biến mọi lỗi
nghiệp vụ thành một chuỗi vô nghĩa. Bubble nguyên returndata, có cap:

```solidity
if (!success && (m.mode & MODE_REQUIRE_SUCCESS) != 0) {
    assembly { revert(add(ret, 0x20), mload(ret)) }   // ret đã bị cap ở MAX_RETURN_BYTES
}
```

Định lượng rủi ro của relayer khi bật bit: một Zether metaTx revert **sau khi đã verify proof**
đốt gần trọn `innerGasLimit`. Với con số đúng ở 04.10 (~2.5M gas, **không phải 250k như bản nháp
viết**):

| Chain | Gas price | Chi phí một lần revert |
|---|---|---|
| Gnosis xDAI | 1.5 gwei | **$0.00375** |
| Celo (cUSD fee currency) | ~5 gwei-equiv | ~$0.0125 |
| Ethereum L1 | 25 gwei, ETH $3,000 | **$187** |
| Private chain (gas = 0) | — | **$0** — chỉ tốn block space |

#### 04.6.1. Return-bomb

`returns (bytes memory)` không giới hạn là lỗ gas-griefing thật. Memory gas =
`3w + w²/512` với `w` = số word. Một target trả 1 MB (32,768 word) = 98,304 + 2,097,152 ≈ **2.2M gas**;
10 MB (327,680 word) = 983,040 + 209,715,200 ≈ **210M gas** — vượt block gas limit của mọi chain
trong scope, frame ngoài OOG. Bắt buộc cap:

```solidity
uint256 constant MAX_RETURN_BYTES = 1024;   // 32 word => 98 gas, đủ cho mọi revert string thật

assembly {
    success := call(innerGas, target, 0, add(cd, 0x20), mload(cd), 0, 0)  // out=0, KHÔNG copy
    n := returndatasize()
    if gt(n, MAX_RETURN_BYTES) { n := MAX_RETURN_BYTES }
    ret := mload(0x40)
    mstore(0x40, add(ret, add(n, 0x20)))
    mstore(ret, n)
    returndatacopy(add(ret, 0x20), 0, n)
}
```

Điểm chết người: `out = 0, outsize = 0` trong `call` là **bắt buộc**. Solidity high-level call tự
sinh `returndatacopy` toàn bộ trước khi bạn kịp check `returndatasize()` — dùng high-level call là
mất luôn biện pháp này. Cap áp cho **cả** nhánh thành công lẫn nhánh revert (revert reason cũng là
returndata). Event phát `keccak256(ret)` chứ không phát blob — log data 8 gas/byte, 1,024 byte =
8,192 gas mỗi tx là vô nghĩa.

Ghi chú vận hành: khi bubble một revert đã bị cắt ở 1,024 byte, kết quả có thể không decode được
thành `Error(string)` hợp lệ. Indexer phải xử lý được returndata cụt: thử decode, thất bại thì
lưu hex thô vào `blockchain.metatx.revert_data_hex`.

#### 04.6.2. `amount` và swallow mode — lỗ hổng bản nháp bỏ sót

Bản nháp đặt `safeTransferFrom(from, to, amount)` trước inner call và **không** ràng buộc gì với
mode. Hệ quả trong swallow mode: `amount` **đã chuyển** cho `to`, inner call revert, tx thành công,
nonce tiêu, fee trả. User mất principal cho một hành động không xảy ra, và `to` giữ tiền mà không
có nghĩa vụ gì on-chain. Với `amount` là một khoản settlement B2B thì đó là mất tiền thật.

Sửa bằng invariant on-chain, đã đưa vào 04.4:

```solidity
require(m.amount == 0 || (m.mode & MODE_REQUIRE_SUCCESS) != 0, "AMOUNT_NEEDS_SUCCESS");
```

Nói cách khác: **swallow mode chỉ hợp lệ cho metaTx thuần logic (`amount == 0`)**. Mọi luồng có
principal đều bắt buộc bubble. Đây là phiên bản on-chain của nguyên tắc VietQR: không có nửa vời
giữa "tiền đi rồi" và "việc chưa xảy ra".

#### 04.6.3. Quy tắc 63/64 (EIP-150) — sửa hai lỗi số học của bản nháp

`call` chỉ forward tối đa 63/64 gas còn lại; frame ngoài luôn giữ lại 1/64 và **sống sót qua OOG
của inner call**. Không có `innerGasLimit` đã ký thì relayer cố tình cấp thiếu gas là ăn fee mà
không thực thi.

```solidity
uint256 constant FLOOR_GAS = 60_000;   // đủ cho fee transfer + event + epilogue

// Pre-check: để child THỰC SỰ nhận đủ innerGasLimit, cần gasleft * 63/64 >= innerGasLimit
require(gasleft() >= (m.innerGasLimit * 64) / 63 + FLOOR_GAS, "GAS_TOO_LOW");
(success, ret) = _safeCall(m.to, cd, m.innerGasLimit);
if (!success) {
    require(gasleft() >= m.innerGasLimit / 63, "GAS_GRIEFED");
}
```

**Lỗi 1 đã sửa.** Bản nháp viết `require(gasleft() >= m.innerGasLimit + FLOOR_GAS)`. Thiếu hệ số
64/63. Ở `innerGasLimit = 2,600,000` (con số Zether đúng, 04.10), 64/63 là **+41,270 gas** — lớn
hơn cả phần lớn `FLOOR_GAS` mà người ta hay đặt. Với check sai, relayer đặt tx gas limit sát mép
làm child nhận 2,558,730 thay vì 2,600,000 và OOG, mà pre-check vẫn pass.

**Lỗi 2 đã sửa.** Bản nháp giải thích post-check là cần vì "pre-check có thể bị đánh lừa bởi
memory expansion phát sinh giữa hai điểm". **Sai** — memory expansion tốn gas, nên nó *giảm*
`gasleft()`, và pre-check đọc `gasleft()` ngay trước `call` đã tính hết. Lý do thật để giữ
post-check là khiêm tốn hơn và vẫn đủ để giữ: nó là một **assertion về tính đúng của
`FLOOR_GAS`**. Nếu ai đó sửa epilogue (thêm một event, thêm một SSTORE) mà quên tăng `FLOOR_GAS`,
post-check biến một lỗi im lặng thành một revert có tên. Chi phí 2 gas. Và post-check phải nằm
**trong nhánh `!success`** — bản nháp để nó vô điều kiện, sẽ revert nhầm khi inner call thành công
mà tiêu gần hết gas được cấp.

#### 04.6.4. Bootstrap allowance — bản nháp gọi nó là "câu hỏi mở", nó không phải

Vấn đề: user không có native gas ⇒ không gọi được `approve` ⇒ forwarder không
`transferFrom` được ⇒ không có metaTx đầu tiên. Bốn cơ chế, không phải một câu hỏi mở:

| Cơ chế | Token cần hỗ trợ gì | Chi phí | Đánh giá |
|---|---|---|---|
| EIP-2612 `permit` bundled | `permit(owner,spender,value,deadline,v,r,s)` | +~50,000 gas, +1 chữ ký EIP-712 thứ hai | **Chọn cho forwarder generic.** USDC, DAI, hầu hết stablecoin hiện đại đều có |
| EIP-3009 `transferWithAuthorization` | USDC/EURC có | +~40,000 gas | Tốt hơn permit (không để lại allowance) nhưng ít token hỗ trợ. Dùng khi có |
| `ERC1776Native` mixin | token là của mình | 0 | **Chọn cho Z-token và token nội bộ.** Không có allowance nào để rút |
| Approve thủ công một lần bằng ví có gas | không | 1 tx có gas | Chỉ dùng cho tài khoản doanh nghiệp đã có treasury EOA |

Entry point cụ thể cho lối 1, để `permit` và metaTx nguyên tử trong một tx:

```solidity
struct PermitData { uint256 value; uint256 deadline; uint8 v; bytes32 r; bytes32 s; }

function executeMetaTransactionWithPermit(
    MetaTransaction calldata metaTx,
    bytes calldata signature,
    PermitData calldata permitData          // value = metaTx.amount + fee ceiling, KHÔNG phải max
) external returns (bool innerSuccess, bytes memory returnData);
```

`permitData` **không** nằm trong digest của metaTx — nó là một chữ ký EIP-712 độc lập trên domain
của token, có `deadline` và nonce riêng của token. Forwarder gọi `try token.permit(...) {} catch {}`
rồi tiếp tục: nếu permit đã bị ai đó front-run (một vector có thật, permit là public), allowance
đã có sẵn và metaTx vẫn chạy. Không `try/catch` là tự tạo một DoS 0 chi phí cho kẻ tấn công.

Ràng buộc cứng, khớp §12.1: `permitData.value` phải là **số đúng** (`amount + fee`), có `deadline`
ngắn. **Cấm `type(uint256).max`.** Trần approve nếu phải dùng approve thủ công:
`fee_ceiling × 30 ngày`.

#### 04.6.5. Target không biết `from` là ai — lỗ hổng thiết kế trong struct của note

Note không có trường nào cho `_msgSender()`. Inner call là `to.call(m.data)`, nên tại `to`,
`msg.sender == address(forwarder)`. Một contract nghiệp vụ nhận metaTx từ 1,000 user khác nhau sẽ
thấy tất cả là cùng một caller. Với `transferConfidential` điều này vô hại (danh tính nằm trong
`fromSchnorrAddress`, và ZKP chứng minh sở hữu `x_from` — chính là lý do Zether ghép được với
forwarder generic mà không cần biết `msg.sender`). Với **mọi** contract nghiệp vụ khác thì đó là
một lỗ hổng phân quyền hoặc một chức năng không dùng được.

Giải pháp chuẩn là ERC-2771: append 20 byte `from` vào cuối calldata; target implement
`_msgSender()` đọc 20 byte cuối khi `msg.sender == trustedForwarder`.

**Ba quyết định phải chốt, note không nói câu nào:**

1. **Digest hash `data` CHƯA có suffix.** User ký ý định gọi `f(x)`; forwarder append `from`.
   Nếu hash sau khi append thì user phải tự append chính mình vào calldata mình ký — vô nghĩa và
   dễ sai. Ghi vào type string: `bytes data` là calldata **thuần**.
2. **Append là thuộc tính của target, không phải của user.** Một bit `MODE_APPEND_SENDER` để user
   chọn là sai chỗ: user không biết target có implement ERC-2771 hay không, và chọn sai thì hoặc
   là target hiểu nhầm 20 byte thừa, hoặc là mất `_msgSender()`. Đặt cờ trong `TargetPolicy`:

   ```solidity
   struct Target { bool allowed; bool appendsSender; bool isFeeToken; uint32 maxInnerGas; }
   mapping(address => Target) public targets;   // governance-managed
   ```

   Bit `0x10` vẫn reserve trong bitmask, chỉ dùng nếu sau này có target cần per-tx. Với target
   ngoài allowlist (nếu profile cho phép), mặc định `appendsSender = false` — an toàn hơn.
3. **20 byte thừa với target không phải ERC-2771 là gần như vô hại nhưng không hoàn toàn.**
   Solidity ABI decoder bỏ qua trailing bytes cho hàm có tham số tĩnh và cho hầu hết hàm có tham số
   động. Nó **không** vô hại với: hàm dùng `msg.data.length` để phân nhánh, fallback function,
   và contract viết bằng Yul/Huff tự parse calldata. Đây chính là lý do cờ phải nằm ở target policy
   chứ không phải mặc định bật.

#### 04.6.6. Forwarder giữ allowance = ai cũng rút được của ai — lỗ hổng nghiêm trọng nhất bản nháp bỏ sót

Hình thái generic: mọi user `approve(forwarder, X)`. Forwarder gọi `to.call(data)` với `to`, `data`
**hoàn toàn do người ký chọn**. Kẻ tấn công ký một metaTx của **chính mình**:

```
from  = attacker
to    = USDC                                     // chính token mà mọi người đã approve
data  = transferFrom(victim, attacker, X)        // msg.sender tại USDC = forwarder
mode  = MODE_OPEN, fee = 0, amount = 0
```

Chữ ký hợp lệ (attacker ký cho chính mình), nonce hợp lệ, expiry hợp lệ. Forwarder thực thi lệnh
gọi và USDC thấy caller là forwarder — **đúng cái địa chỉ mà victim đã approve**. Rút sạch. Đây là
lớp lỗ hổng đã giết nhiều generic forwarder/multicall contract trong thực tế; nó không cần bất kỳ
lỗi cài đặt nào, nó là hệ quả trực tiếp của "forwarder giữ allowance + `to`/`data` tự do".

Ba biện pháp, dùng **cả ba**, không chọn một:

```solidity
require(m.to != address(this),        "SELF_CALL");        // chặn re-entry qua đường vòng
require(!targets[m.to].isFeeToken,    "TARGET_IS_TOKEN");  // chặn mọi token forwarder có allowance
require(targets[m.to].allowed,        "TARGET_NOT_ALLOWED"); // allowlist (bật theo chain profile)
```

Và biện pháp gốc rễ: **đừng giữ allowance**. Với `permit`/`transferWithAuthorization` đúng số cho
đúng tx (04.6.4), allowance còn lại sau tx là 0 và toàn bộ lớp tấn công này biến mất kể cả khi ba
`require` trên bị bỏ sót. Đó là lý do thật để ưu tiên `ERC1776Native` mixin cho Z-token và
`permit` cho forwarder generic — không phải chỉ vì tiện.

`targets[m.to].maxInnerGas` cũng giải quyết mâu thuẫn với §12.2 (hub reject `innerGasLimit >
1,500,000`): trần là **per-target**, không phải một hằng toàn cục. `ZetherToken` được
`maxInnerGas = 3_200_000`; mọi target khác mặc định 1,500,000.

#### 04.6.7. Thứ tự fee vs inner call, và reentrancy

Checks-Effects-Interactions, guard, và **fee trước**:

```solidity
_metaNonce[m.from][m.batchId] = m.batchNonce + 1;                   // EFFECT trước mọi external call
address feeRcp = _resolveFeeRecipient(m);                            // MODE_OPEN: msg.sender nếu 0
uint256 feePaid = (m.mode & MODE_METERED_FEE) != 0
    ? _min(m.fee, _gasQuote(gasStart - gasleft()))                   // §05.3.3
    : m.fee;
if (feePaid > 0) IERC20(_feeToken(m)).safeTransferFrom(m.from, feeRcp, feePaid);
if (m.amount > 0) IERC20(m.tokenContract).safeTransferFrom(m.from, m.to, m.amount);
(success, ret) = _safeCall(m.to, _withSender(m), m.innerGasLimit);
```

Fee sau inner call sẽ hỏng khi inner call rút sạch số dư `feeToken` của `from` — fee transfer
fail, cả tx revert, relayer mất gas. Fee trước loại bỏ hoàn toàn lớp rủi ro này.

`if (feePaid > 0)` không phải mỹ phẩm: profile private chain và luồng sponsor đều có `fee = 0`, và
bỏ hẳn `safeTransferFrom` tiết kiệm **30,000–50,000 gas**, tức 25–35% tổng chi phí của một metaTx
đơn giản.

**Reentrancy giữa fee transfer và target call.** `safeTransferFrom` trên ERC-777/ERC-1363 trao
quyền điều khiển cho `from` hoặc `feeRecipient` **trước khi** inner call chạy — và trong MODE_OPEN,
`feeRecipient` là địa chỉ **do relayer chọn**, tức là do kẻ có thể là kẻ tấn công chọn. Ba lớp
chặn:

- (a) nonce đã tăng ở bước EFFECT nên chính metaTx này không replay được;
- (b) reentrancy guard chặn re-entry vào `executeMetaTransaction`;
- (c) `require(m.to != address(this))` ở 04.6.6 chặn đường vòng qua inner call.

Về (b), một sửa nhỏ có số: dùng **`ReentrancyGuardTransient`** (EIP-1153 transient storage) thay
vì `ReentrancyGuardUpgradeable`. Chi phí ~**200 gas** thay vì ~2,900 gas (2 SSTORE warm). Điều kiện:
chain phải có Cancun. Gnosis đã có; Celo sau khi migrate lên L2 (OP Stack) có; chain private
dựng bằng Besu/Nethermind bản mới có. **Phải kiểm tra per-chain trong `blockchain.chain` và có
fallback compile-time**, không giả định.

Về token fee-on-transfer (relayer bid `fee` nhưng nhận `fee*(1-tax)`): đo
`balanceAfter - balanceBefore` tốn thêm ~4,200 gas (2 SLOAD cold) và **vẫn không cứu được** khi
thiếu — không thể ép token trả thêm. Allowlist `feeToken` là câu trả lời đúng, và nó trùng với
allowlist đã cần cho 04.6.6.

#### 04.6.8. Batch — relayer sẽ hỏi, tốt hơn là thiết kế trước

21,000 gas intrinsic trên một metaTx đơn giản ~130,000 gas là **16%** chi phí. Relayer gộp 10
metaTx tiết kiệm 189,000 gas ≈ 15% tổng. Với `MODE_REQUIRE_SUCCESS`, một item hỏng **không được**
kéo cả batch xuống, nên phải isolate bằng external self-call:

```solidity
function executeBatch(MetaTransaction[] calldata txs, bytes[] calldata sigs)
    external returns (bool[] memory oks, bytes[] memory rets);

/// @dev chỉ address(this) gọi được; tồn tại để try/catch cô lập từng item
function executeOne(MetaTransaction calldata m, bytes calldata sig)
    external returns (bool, bytes memory);
```

Chi phí cô lập: mỗi item thêm một `CALL` (~2,600 warm) + copy calldata. Vẫn lời so với 21,000.
Ràng buộc: `executeOne` phải `require(msg.sender == address(this))`, và reentrancy guard phải cho
phép đường này (một lý do nữa để dùng transient guard với cờ riêng cho batch, không phải một
`nonReentrant` thô chặn mọi thứ). `txs.length <= 32` để không tự tạo return-bomb cho chính mình.

---

### 04.7. Reference interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;   // cần Cancun cho transient storage; hạ xuống ^0.8.20 nếu chain chưa có

interface IEIP1776 {
    struct MetaTransaction {
        address from; address to; address tokenContract; address feeToken;
        uint256 amount; bytes data;
        uint256 batchId; uint256 batchNonce;
        uint256 fee; uint256 innerGasLimit; uint256 expiry;
        uint32 mode; address relayer; address feeRecipient;
    }

    struct PermitData { uint256 value; uint256 deadline; uint8 v; bytes32 r; bytes32 s; }

    /// @dev relayer = msg.sender THỰC TẾ; feeRecipient = địa chỉ ĐÃ RESOLVE.
    ///      Không bao giờ phát m.relayer / m.feeRecipient thô: trong MODE_OPEN chúng là rác.
    event MetaTransactionExecuted(
        bytes32 indexed digest,
        address indexed from,
        address indexed to,
        uint256 batchId, uint256 batchNonce,
        address relayer, address feeRecipient, address feeToken,
        uint256 feePaid, bool innerSuccess, bytes32 returnDataHash);

    event BatchNonceBumped(address indexed from, uint256 indexed batchId, uint256 newNonce);

    /// @return innerSuccess kết quả inner call; false KHÔNG làm revert khi mode & 0x04 == 0
    /// @return returnData  returndata của inner call, cắt tại MAX_RETURN_BYTES (1024)
    function executeMetaTransaction(MetaTransaction calldata metaTx, bytes calldata signature)
        external returns (bool innerSuccess, bytes memory returnData);

    function executeMetaTransactionWithPermit(
        MetaTransaction calldata metaTx, bytes calldata signature, PermitData calldata permitData)
        external returns (bool innerSuccess, bytes memory returnData);

    function executeBatch(MetaTransaction[] calldata txs, bytes[] calldata sigs)
        external returns (bool[] memory oks, bytes[] memory rets);

    function meta_nonce(address from, uint256 batchId) external view returns (uint256);
    function bumpBatchNonce(uint256 batchId, uint256 newNonce) external;

    /// @notice Digest EIP-712 đã canonical-zero hoá theo mode. Client PHẢI đối chiếu ở CI.
    function hashMetaTransaction(MetaTransaction calldata metaTx) external view returns (bytes32);

    /// @notice Trả về gas tối thiểu relayer phải đặt cho tx bọc ngoài. Relayer đọc trước khi bid.
    function requiredOuterGas(MetaTransaction calldata metaTx) external view returns (uint256);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
```

`requiredOuterGas` là bổ sung của lần review này và nó tránh được cả một lớp bug vận hành. Công
thức, để relayer không phải tự đoán:

```
requiredOuterGas = innerGasLimit * 64 / 63
                 + 21_000                       // intrinsic
                 + 16 * nonzero_calldata_bytes  // ~40_000 với proof Zether 2.6 KB
                 + ENVELOPE_GAS                 // 32_000 (ecrecover + nonce + event + guard)
                 + (fee > 0 ? 50_000 : 0)       // fee transferFrom, giả định cold
                 + FLOOR_GAS (60_000)
```

**Cảnh báo EIP-7623 (Prague/Pectra).** Từ EIP-7623, một tx phải trả `max(execution_gas,
21000 + 10 * calldata_tokens)` với `token = 4` cho byte khác 0. Với một metaTx **đơn giản**
(~500 byte calldata, ~110,000 gas execution): floor = 21,000 + 10 × 2,000 = **41,000** — vẫn dưới
execution, không ảnh hưởng. Với một **batch 32 item** (~16 KB calldata, execution ~1.5M): floor =
21,000 + 10 × 64,000 = **661,000** — vẫn dưới. Với một metaTx **chỉ mang proof Zether mà không
verify** (không xảy ra ở đây) thì mới chạm floor. Kết luận: EIP-7623 không đổi thiết kế, nhưng
`requiredOuterGas` phải cộng floor để không bị reject ở mempool. Cần **kiểm chứng** Gnosis/Celo đã
kích hoạt Prague chưa trước khi chốt hằng số.

---

### 04.8. Thuật toán ký (pseudocode)

```python
# dms_blockchain/lib/eip1776.py  — thuần Python, không import odoo, test được bằng pytest
ZERO = '0x' + '00' * 20
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

TYPE_STRING = (
  "MetaTransaction(address from,address to,address tokenContract,address feeToken,"
  "uint256 amount,bytes data,uint256 batchId,uint256 batchNonce,uint256 fee,"
  "uint256 innerGasLimit,uint256 expiry,uint32 mode,address relayer,address feeRecipient)")
TYPEHASH = keccak(TYPE_STRING.encode())

MODE_KNOWN_MASK = 0x1F

def domain_separator(chain_id, verifying_contract):
    return keccak(abi_encode(
        ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
        [keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
         keccak(b"BambooMetaTx"), keccak(b"1"), chain_id, verifying_contract]))

def digest(m, chain_id, verifying_contract):
    # --- invariant, fail sớm ở client rẻ hơn revert on-chain ---
    assert m.mode & ~MODE_KNOWN_MASK == 0,                     "unknown mode bit"
    assert m.amount == 0 or (m.mode & 0x04),                   "amount requires MODE_REQUIRE_SUCCESS"
    assert not (m.mode & 0x01) or m.relayer      != ZERO,      "restrict relayer but zero"
    assert not (m.mode & 0x02) or m.fee_recipient != ZERO,     "restrict fee rcp but zero"
    assert m.expiry > now() + 5,                               "expiry already in the past"

    # --- canonical zeroing: ĐÚNG hai trường này, không hơn không kém ---
    relayer_c = m.relayer       if (m.mode & 0x01) else ZERO
    fee_rcp_c = m.fee_recipient if (m.mode & 0x02) else ZERO
    # feeToken KHÔNG canonical-zero hoá: nó là lựa chọn của user, không phải ô relayer điền.

    # EIP-712: `bytes data` được encode là keccak256(data), KHÔNG phải bytes thô.
    # Type string vẫn phải ghi `bytes data`. `data` ở đây CHƯA có ERC-2771 sender suffix.
    struct_hash = keccak(abi_encode(
        ['bytes32', 'address', 'address', 'address', 'address',
         'uint256', 'bytes32', 'uint256', 'uint256', 'uint256',
         'uint256', 'uint256', 'uint32', 'address', 'address'],
        [TYPEHASH, m.from_, m.to, m.token_contract, m.fee_token,
         m.amount, keccak(m.data), m.batch_id, m.batch_nonce, m.fee,
         m.inner_gas_limit, m.expiry, m.mode, relayer_c, fee_rcp_c]))
    return keccak(b'\x19\x01' + domain_separator(chain_id, verifying_contract) + struct_hash)

def sign(m, chain_id, verifying_contract, signer):
    d = digest(m, chain_id, verifying_contract)
    v, r, s = signer.sign_hash(d)          # signer = HSM / MPC / passkey / custodial adapter
    if s > SECP256K1_N // 2:               # low-s normalisation, KHÔNG phải assert
        s = SECP256K1_N - s                # đảo s và lật v: chữ ký vẫn hợp lệ cho cùng digest
        v = 27 + (28 - v)
    assert v in (27, 28)
    return d, encode_sig(v, r, s)
```

**Sửa so với bản nháp — hai chỗ.**

1. Bản nháp `assert s <= SECP256K1_N // 2`. Sai về vận hành: một HSM PKCS#11 hoặc một MPC provider
   **có thể** trả `s` nửa trên và bạn không sửa được firmware của nó. `s` nửa trên là chữ ký
   **hợp lệ**; chuẩn hoá nó ở client là một phép biến đổi thuần tuý (`s' = n - s`, lật `v`), không
   mất tính hợp lệ. Assert là biến một chuyện xử lý được thành một outage.
2. Bản nháp gọi `rpc.call(verifying_contract, 'hashMetaTransaction', m)` **trong mỗi lần ký**. Đó
   là một round-trip RPC (~50–200 ms) trên đường nóng của mọi giao dịch, và nó biến RPC endpoint
   thành single point of failure cho việc ký. Thay bằng:
   - **CI**: một test chạy `hashMetaTransaction` trên anvil fork cho toàn bộ `metatx_v1.json`
     (04.13). Fail = fail build.
   - **Runtime**: cross-check **một lần** lúc khởi tạo mỗi `blockchain.chain` (lưu kết quả vào
     `chain.digest_selftest_ok`), không phải mỗi chữ ký.
   - Trên chain private, `hashMetaTransaction` vẫn hữu ích để debug nhưng không nằm trên đường nóng.

`signer` là interface thay được: HSM (PKCS#11), MPC (Fireblocks/Turnkey REST), custodial keystore,
non-custodial (client ký, server chỉ nhận `signature`), smart-account (trả chữ ký EIP-1271, khi đó
bỏ qua toàn bộ nhánh low-s vì chữ ký không nhất thiết là ECDSA). Private key không bao giờ chạm DB
Odoo; `ir.config_parameter` chỉ giữ endpoint và key handle. Chi tiết custody ở §07.

---

### 04.9. Griefing: bảng tổng hợp

| Vector | Cơ chế | Biện pháp | Chi phí còn lại (Gnosis @1.5 gwei) |
|---|---|---|---|
| Target đốt sạch gas (vòng lặp vô hạn) | inner call ăn 63/64 | `innerGasLimit` đã ký + `targets[to].maxInnerGas` + Simulation Gate | relayer trả đúng `innerGasLimit`, đã biết trước khi bid |
| Return-bomb | returndata khổng lồ, memory bậc hai | `MAX_RETURN_BYTES = 1024`, `out=0` trong `call` low-level | 98 gas |
| OOG cố ý của relayer | 63/64 giữ frame ngoài sống | pre-check `gasleft() >= innerGasLimit*64/63 + FLOOR_GAS`; post-check trong nhánh `!success` | 0 |
| **Rút sạch qua allowance của forwarder** | `to = token`, `data = transferFrom(victim,...)` | `!targets[to].isFeeToken` + `to != address(this)` + không giữ allowance (permit đúng số) | 0 |
| **Self-call / re-entry đường vòng** | `to = address(this)` | `require(m.to != address(this))` | 0 |
| Đua nonce giữa 2 relayer | kẻ thua revert | check nonce sớm (sau 2 check 0-gas) | ~26,000 gas ≈ $0.00004 |
| User tự huỷ nonce để đốt gas relayer | tự submit tx khác cùng nonce, hoặc `bumpBatchNonce` | như trên + reputation off-chain (§05.4.4b) | như trên |
| User ký `innerGasLimit` khổng lồ để relayer phải dự trữ | 20M gas reserve | `targets[to].maxInnerGas` on-chain + hub reject (§12.2) | 0 |
| Relayer trễ hạn ăn fee | giữ intent như free option | `expiry` ngắn theo bảng 04.5, check **trước** nonce++ và fee | relayer mất gas, user mất 0 |
| Chữ ký EIP-1271 bị revoke sau simulation | smart account đổi owner | expiry ngắn + re-simulate ở block mục tiêu | relayer mất gas |
| Token fee-on-transfer | relayer nhận thiếu | allowlist `feeToken` | 0 |
| Reentrancy qua ERC-777 hook ở fee transfer | `feeRecipient` do relayer chọn, có control trước inner call | nonce++ trước + `ReentrancyGuardTransient` + allowlist token | ~200 gas |
| Front-run `permit` | permit là public, ai cũng gọi được | `try token.permit() {} catch {}` rồi tiếp tục | 0 |
| Bubble revert data cụt không decode được | cap 1,024 byte | indexer thử decode, thất bại thì lưu hex thô | 0 |
| Swallow mode ăn mất principal | `amount` đã chuyển, inner call revert | `require(amount == 0 \|\| mode & MODE_REQUIRE_SUCCESS)` | 0 |

---

### 04.10. Ghép với Zether `transferConfidential`

```python
inner = encode_with_selector(
    'transferConfidential(bytes32,bytes32,(bytes32[2],bytes32[2],bytes32[2],uint256,uint256,bytes32,bytes))',
    from_schnorr, to_schnorr, transfer_data)

m = MetaTransaction(
    from_=agent_eoa, to=zether_token,
    token_contract=ZERO, fee_token=WXDAI,   # amount = 0 => tokenContract không dùng
    amount=0, data=inner,
    batch_id=lane_for(settlement_id), batch_nonce=n,
    fee=quoted_fee_base, inner_gas_limit=3_000_000,   # *** không phải 400_000, xem bảng dưới ***
    expiry=now() + 60,                                 # *** không phải epoch_start + 20 ***
    mode=MODE_REQUIRE_SUCCESS,          # 0x04 — bắt buộc cho mọi luồng tiền
    relayer=ZERO, fee_recipient=ZERO)
```

Chú ý selector: struct `EncryptedTransfer` đã **bỏ `bytes32[2] C_fee`** theo quyết định §03.4 (phí
là public scalar, không cần ciphertext, không cần range proof cho phí). Note §10.5.3 vẫn còn
`C_fee` — nó phải bị xoá khỏi struct, và selector ở trên đã phản ánh việc xoá đó.

**Hai kênh fee, chỉ được chọn một.**

| Kịch bản | `metaTx.fee` (envelope, trả bằng ERC-20 công khai) | `transferData.fee` (Zether, public scalar trừ vào số dư mã hoá) | Lý do |
|---|---|---|---|
| Open relayer thị trường | `> 0` | `0`, `feeRecipient = bytes32(0)` | Relayer cần được trả bằng token nó tiêu được. Số dư Z-token không rút ngay được |
| Relayer doanh nghiệp có `schnorrAddress` và hợp đồng SLA | `0` | `> 0` | Relayer nhận thẳng vào số dư bảo mật; không cần allowance ERC-20 nào |
| Cả hai `> 0` | — | — | **Thu phí hai lần**, và §12.6 chỉ ra thêm: hai con số công khai cùng lúc cho quan sát viên một hệ phương trình về cơ cấu phí. **Cấm** |

**Sửa so với bản nháp**: bản nháp gọi `transferData.fee` là "bí mật". Không đúng sau §03.4 —
**cả hai kênh đều công khai**. Sự khác nhau là *đơn vị thanh toán* (ERC-20 công khai vs số dư
Z-token), không phải *mức độ lộ*. Điều đó **không** làm điều cấm trở nên bớt cần thiết, nhưng nó
đổi lý do: lý do không còn là bảo mật mà là kế toán (double charge) cộng với ràng buộc §12.6.1
(phí tuyệt đối **không được** là hàm của số tiền bí mật, nếu không `fee` công khai làm lộ `v`).

**Ai enforce được điều cấm.** `MetaTxForwarder` generic **không** parse được calldata tuỳ ý. Ba
chỗ enforce, dùng cả ba:

1. Builder trong Odoo: `_build_zether_metatx` raise khi cả hai khác 0. Rẻ nhất, nhưng bypass được.
2. `ERC1776Native` mixin **ngay trên ZetherToken** — nó thấy cả hai nên
   `require(!(envelopeFee > 0 && td.fee > 0))` là khả thi. **Đây là lý do kỹ thuật thứ hai để chọn
   native mixin cho Zether** (thứ nhất là bootstrap allowance, 04.6.4).
3. Nếu buộc phải dùng forwarder generic: một **calldata policy per selector** trong `TargetPolicy`.
   `transferData.fee` nằm ở offset cố định trong calldata của một selector đã biết, nên forwarder
   đọc được `uint256` tại offset đó mà không cần ABI decoder đầy đủ:

   ```solidity
   struct CalldataRule { bytes4 selector; uint16 wordOffset; bool mustBeZeroIfEnvelopeFee; }
   ```
   ~1,000 gas. Đây là câu trả lời cho "generic forwarder không enforce được" — nó enforce được,
   chỉ là bằng một cơ chế hẹp và phải khai báo per-selector. Vẫn kém mixin.

**Epoch: bản nháp đề xuất `targetEpoch`, §03.5 đã làm nó thừa.** Bản nháp viết "Bổ sung
`uint64 targetEpoch` vào struct và `require(currentEpoch() == td.targetEpoch)`". Với
**owner-exclusive rollover** (§03.5) thì `acc[from]` chỉ đổi trong tx của chính `from`, proof chỉ
phụ thuộc `zetherNonce`, và `targetEpoch` không có gì để bind. **Bỏ.** Nếu vì lý do audit mật mã
mà §03.5 bị bác và quay lại epoch-based rollover, thì `targetEpoch` quay lại **và** `expiry` của
Zether phải tụt về ≤ 1 epoch — hai thứ đi cùng nhau, ghi vào `open_questions`.

**Ngân sách gas của lời gọi ghép — con số bản nháp sai một bậc độ lớn.**

Bản nháp ghi "Verify Bulletproofs 128-bit + ElGamal ops: 200,000 – 280,000" và tổng ~342k–422k.
**Sai.** 180k–250k là chi phí của **một cặp `ecPairing`** — tức là của Groth16 — chứ không phải
Bulletproofs (§05.3.2 đã bắt lỗi này ở note gốc; bản nháp 04 lặp lại đúng lỗi đó). Bulletproofs
verify là một **multi-exponentiation tuyến tính theo số bit**, không có precompile multiexp trên
alt_bn128.

Tính lại với tham số đã chốt ở §03.4 (`n_v = 32` bit cho `v`, `n_b = 64` bit cho `b'`, aggregate
96 bit, anonymity set N = 2):

| Thành phần | Gas | Cơ sở |
|---|---|---|
| Intrinsic tx + calldata (~2.6 KB proof, 16 gas/nonzero byte) | 21,000 + ~40,000 | proof BP 96-bit ≈ 18 điểm + 5 scalar ≈ 1.3 KB; sigma ≈ 1.0 KB; ciphertext + scalar ≈ 0.3 KB |
| EIP-712 hash + `ECDSA.tryRecover` | ~5,500 | precompile 3,000 + keccak |
| SSTORE `meta_nonce` (lane tái dùng, cold) | 5,000 | 2,900 + 2,100 |
| `safeTransferFrom` fee | ~45,000 | 2 SSTORE, dest cold |
| **Bulletproof verify (96-bit aggregate)** | **1,300,000 – 2,200,000** | ~2×96 + 2×log2(128) + 8 ≈ **214 điểm**; `ecMul` = 6,000 (EIP-1108), `ecAdd` = 150 ⇒ naive 1.32M. Hiệu chỉnh lên theo đo thực của ConsenSys `anonymous-zether` (~1.7M ở 64 bit aggregate, N=2) |
| Sigma protocol (R1–R4, §03.4) | ~200,000 | ~30 `ecMul` + transcript keccak |
| Trừ phí public scalar khỏi số dư mã hoá | ~13,000 | 1 `ecMul` + 1 `ecAdd` (§03.4) |
| Cập nhật `(C,D)`: acc sender + pending receiver + feeRecipient | ~65,000 | 12 SSTORE nonzero→nonzero + 6 `ecAdd` |
| `zetherNonce++` + registry lookups | ~14,000 | 1 SSTORE + 2 staticcall + 2 SLOAD cold |
| Envelope overhead khác (`call`, guard transient, event) | ~10,000 | |
| **Tổng** | **~1,720,000 – 2,620,000** | |

Chốt `innerGasLimit = 3_000_000` (headroom ~15% trên cận trên), `targets[ZetherToken].maxInnerGas
= 3_200_000`, `requiredOuterGas ≈ 3,000,000 × 64/63 + 130,000 ≈ 3,178,000`.

**Quy ra tiền và ra thông lượng — đây mới là con số đổi quyết định:**

| Chain | Gas price | Chi phí/tx | 50,000 tx/tháng | Block gas limit | Tx tối đa/block | Trần thông lượng thực tế (giả định chiếm 15% block space) |
|---|---|---|---|---|---|---|
| Gnosis xDAI | 1.5 gwei | **$0.00477** | **$239/tháng** | ~17M | 5 | ~0.8 tx/block = **~13,800/ngày** |
| Celo (L2, cUSD fee) | ~5 gwei-eq | ~$0.016 | ~$800/tháng | ~30M+ | 9 | ~1.4 tx/block @1s = **~120,000/ngày** |
| Ethereum L1 | 25 gwei, ETH $3,000 | **$238** | **$11.9M/tháng** | 30–45M | 9–14 | không xét |
| **Private (Besu/Nethermind, gas subsidised)** | 0 | **$0** | **$0** | cấu hình được (đặt 100M) | 31 | @2s block = **~1.3M/ngày** |

Ba kết luận, mỗi cái đổi một quyết định:

1. **Bản nháp viết "~$19/tháng cho 50,000 confidential settlement". Con số đúng là ~$239/tháng
   trên Gnosis.** Vẫn rẻ, vẫn không phải ràng buộc — nhưng gấp 12,6 lần và đừng đưa số sai vào
   budget.
2. **Ràng buộc thật của Zether trên public chain không phải tiền, mà là block space.** ~13,800
   confidential tx/ngày trên Gnosis nếu chiếm 15% block, và đó là *toàn bộ* dung lượng dành cho
   Zether của cả hệ thống. Một brand thanh toán 500 distributor × 2 lần/ngày = 1,000 tx/ngày thì
   ổn; 50 brand thì không. Đây là lập luận định lượng cho **quyết định khoá số 5 (private chain
   trước cho Zether)** — mạnh hơn nhiều lập luận "gas cost không phải mối lo".
3. **`innerGasLimit = 400_000` của bản nháp sẽ làm mọi Zether metaTx OOG ngay tx đầu tiên.** Nếu
   con số đó lọt vào implementation plan, team mất một tuần debug ở tuần thứ 20 (§05.3.2 đã cảnh
   báo đúng điều này).

**Nếu 2.5M gas là không chấp nhận được trên public chain**, lối thoát không phải là tối ưu
Bulletproofs mà là **đổi hệ chứng minh sang Groth16/PLONK** (khi đó 180k–250k của note là đúng),
đánh đổi bằng trusted setup và mạch cố định. Đó là một quyết định kiến trúc thuộc §03, không phải
§04 — nhưng envelope phải chịu được cả hai: `innerGasLimit` là một trường đã ký, nên chuyển hệ
chứng minh **không** cần đổi struct, chỉ cần đổi hằng số. Đó là lợi ích cụ thể của việc đưa
`innerGasLimit` vào struct thay vì hard-code.

**Điểm cuối, đúng theo nguyên tắc VietQR.** Trong swallow mode, `innerSuccess = false` vẫn là một tx
**thành công** trên chuỗi. Odoo tuyệt đối không được suy ra trạng thái nghiệp vụ từ `receipt.status`.
Sự thật nghiệp vụ là `MetaTransactionExecuted.innerSuccess == true` **và** đã qua Finality Gate.
State machine của `blockchain.metatx`:

```
draft -> signed -> simulated -> published -> claimed -> broadcast -> mined -> finalized
                                                                                  ├─> done      (innerSuccess = true)
                                                                                  └─> reverted  (innerSuccess = false, chỉ có thể xảy ra khi mode & 0x04 == 0)
   └-> expired    (hết expiry trước khi mined; nonce KHÔNG tiêu; được ký lại cùng lane+nonce)
   └-> superseded (bumpBatchNonce hoặc lane_epoch++ đã bỏ lane này)
```

`done` là điểm duy nhất được phép gọi `_set_done()` phía payment/settlement consumer.
`mined` không phải là `done`. `reverted` **không thể** xảy ra với `amount > 0` (04.6.2) — nếu
indexer thấy một record như vậy thì đó là bug contract, phải raise, không được ghi sổ.

---

### 04.11. Chain profile: public vs private đổi mặc định gì

Trục `chain_profile` (quyết định khoá số 5) không phải một cờ cấu hình lẻ — nó đổi mặc định của
gần như mọi tham số trong section này. Bảng này là cấu hình khởi tạo của `blockchain.chain`:

| Tham số | `chain_profile = 'public'` | `chain_profile = 'private'` | Lý do |
|---|---|---|---|
| `mode` mặc định | `MODE_OPEN` (0x00) cho logic, `+0x04` cho luồng tiền | **`MODE_RESTRICT_RELAYER \| MODE_REQUIRE_SUCCESS` (0x05)** | Chain private không có thị trường relayer; relayer là pool nội bộ đã biết. MODE_OPEN trên chain private là bề mặt tấn công không đổi lại được gì |
| `fee` mặc định | theo `fee_model` §05.3.4 | **0** | Gas được trợ cấp; thu phí token chỉ tạo công việc kế toán |
| `feeToken` | bắt buộc trong allowlist | không dùng | |
| Target allowlist | bắt buộc | bắt buộc | Không nới ở đâu cả |
| `expiry` Zether | 60s | **300s** | Không có mempool công khai, không có free-option risk, không đua relayer |
| `innerGasLimit` Zether | 3,000,000 | 3,000,000 | Không đổi — cùng contract, cùng proof |
| Block gas limit | của chain | **đặt ≥ 100M** | Trực tiếp quyết định thông lượng Zether (04.10) |
| Reentrancy guard | transient nếu chain có Cancun | transient (tự chọn client được) | |
| Simulation Gate | bắt buộc | bắt buộc | Không nới |
| Intent bus (§05) | federated hub | **bỏ hẳn** — dispatch trực tiếp tới relay pool §06 | Không có bên thứ ba để gossip cho |
| `MODE_METERED_FEE` | có ý nghĩa | vô nghĩa (fee = 0) | |

Điểm phải nói thẳng: trên chain private, **toàn bộ giá trị của EIP-1776 rút xuống còn hai thứ**:
(a) người dùng cuối không cần giữ native coin, và (b) một định dạng envelope duy nhất dùng chung
với public chain, nên code path không rẽ đôi. Lý do (b) là lý do thật để vẫn dùng 1776 trên chain
private thay vì cho relay pool gọi thẳng — nhưng nó là lý do kỹ thuật phần mềm, không phải lý do
mật mã học. Đừng bán nó như một tính năng bảo mật.

---

### 04.12. Seam sang Odoo

Section §10 sở hữu data model. Ở đây chỉ chốt ba điểm giao mà envelope quy định:

```python
# dms_blockchain/models/blockchain_metatx.py — public, phục vụ cả /web/dataset/call_kw và /json/2
@api.model
def metatx_build(self, origin_model, origin_id, action_code, params=None):
    """Dựng metaTx draft từ một bản ghi nghiệp vụ. KHÔNG nhận chain_id, verifying_contract,
    from_address, mode, fee hay allowed_company_ids từ client — mọi thứ đó suy ra từ cấu hình
    và từ user đã xác thực."""
    return self._build_metatx(origin_model, origin_id, action_code, params or {})

@api.model
def metatx_quote(self, metatx_id):
    """Trả innerGasLimit, requiredOuterGas, fee đề xuất, expiry. Read-only, không ký."""

@api.model
def metatx_status(self, digest_hash):
    """Tra trạng thái theo digest. Digest là khoá idempotency duy nhất (04.4)."""
```

Ba invariant Odoo phải giữ, đối chiếu được bằng test:

1. `digest_hash` UNIQUE (`models.Constraint`, không phải `_sql_constraints` dạng list — bẫy Odoo 19
   số 2). Kiểm bằng SQL thật, không tin code.
2. `mode_flags` là `Integer` (Odoo không có unsigned; `uint32` max 4,294,967,295 vừa trong
   `Integer` 4-byte có dấu? **Không** — max của int4 là 2,147,483,647. Dùng `Integer` là đủ cho
   `MODE_KNOWN_MASK = 0x1F` và mọi bit tới 0x4000_0000, nhưng phải có
   `models.Constraint('CHECK (mode_flags >= 0 AND mode_flags <= 2147483647)', ...)` để không ai
   bao giờ set bit 31. Ghi vào spec: **bit 31 vĩnh viễn không dùng.**
3. `inner_gas_limit`, `fee_base`, `amount_base` là `Char` chứa số thập phân base units (§10.4.1) —
   `inner_gas_limit` là ngoại lệ duy nhất được dùng `Integer` vì nó luôn < 2^31.

Cron: không đặt logic trong XML (bẫy Odoo 19 số 4). Một dòng gọi method:

```xml
<field name="state">code</field>
<field name="code">model._cron_expire_metatx()</field>
```

`_cron_expire_metatx` chuyển `signed`/`published`/`claimed` quá `expiry_datetime` sang `expired`,
và **không** đụng tới `broadcast` (một tx đã broadcast có thể vẫn được mine sau `expiry` nếu đồng
hồ node lệch — để Finality Gate quyết, không để cron quyết).

---

### 04.13. Kiểm chứng bắt buộc trước khi gọi là xong

Không có mục nào trong danh sách này là tuỳ chọn. Mỗi mục là một lỗi đã được liệt kê ở trên,
biểu diễn dưới dạng một bài test chạy được.

| # | Kiểm chứng | Công cụ | Fail nghĩa là |
|---|---|---|---|
| 1 | `metatx_v1.json`: ≥ 24 vector (mỗi mode × có/không `feeToken` × `data` rỗng/dài × expiry biên) cho ra digest khớp giữa `eip1776.py` và `hashMetaTransaction` | pytest + `forge script` trên anvil | Client và contract không cùng một digest ⇒ 100% chữ ký fail |
| 2 | Fuzz: với mọi `mode & ~MODE_KNOWN_MASK != 0` ⇒ revert `MODE_UNKNOWN` | foundry fuzz 50k run | Bit lạ được chấp nhận ⇒ semantics tương lai bị khoá |
| 3 | Cross-mode: chữ ký MODE_OPEN không verify được khi submit với `mode = 0x01` và ngược lại | foundry | Cross-mode replay |
| 4 | Malleability: `(v, r, n-s)` bị reject | foundry | Dedupe theo chữ ký sai |
| 5 | Return-bomb: target trả 1 MB ⇒ tx dùng < 300k gas tổng | foundry, đo `gasleft()` | Gas griefing |
| 6 | Gas griefing: relayer đặt outer gas = `requiredOuterGas - 1` ⇒ revert `GAS_TOO_LOW`, **nonce không tăng** | foundry | Lỗ GSN v1 |
| 7 | Allowance drain: `to = feeToken`, `data = transferFrom(victim,...)` ⇒ revert `TARGET_IS_TOKEN` | foundry | Rút sạch mọi user |
| 8 | Self-call: `to = address(forwarder)` ⇒ revert `SELF_CALL` | foundry | Re-entry đường vòng |
| 9 | `amount > 0` với `mode & 0x04 == 0` ⇒ revert `AMOUNT_NEEDS_SUCCESS` | foundry | Mất principal trong swallow mode |
| 10 | Invariant Echidna: `_metaNonce[from][batchId]` đơn điệu không giảm qua mọi chuỗi lời gọi | echidna 50k | Replay |
| 11 | `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_metatx'::regclass` có UNIQUE trên `digest_hash` | test tích hợp Odoo | Bẫy Odoo 19 số 2 |
| 12 | Gas đo thật của một Zether metaTx trên fork Gnosis nằm trong `[1.7M, 2.7M]` | `forge test --gas-report` trên fork | Bảng 04.10 sai ⇒ `innerGasLimit` sai |
| 13 | Chain có Cancun (transient storage) hay không, ghi vào `blockchain.chain.has_transient_storage` | `eth_call` một probe contract | Guard chọn sai bản |

---

### 04.14. Còn phải quyết

Xem `open_questions` trong manifest. Ba điểm chặn thật, theo thứ tự phải trả lời:

1. **Hình thái deploy cho luồng không phải Zether** (generic forwarder vs mixin trên từng token).
   Nó quyết định `verifyingContract`, và `verifyingContract` nằm trong mọi digest, nên đổi sau khi
   đã có chữ ký lưu hành là một migration thật. Với Zether thì đã chốt: **native mixin** (hai lý do
   độc lập: bootstrap allowance 04.6.4 và enforce hai-kênh-phí 04.10).
2. **Chi phí verify chữ ký của smart account/passkey** (`SignatureChecker` → EIP-1271). Khoảng
   3,450 gas (precompile RIP-7212) đến 330,000 gas (verifier P-256 thuần Solidity) là chênh **hai
   bậc**, và nó cộng thẳng vào `requiredOuterGas` của **mọi** metaTx. Phải hỏi provider custody đã
   chọn, không đoán.
3. **§03.5 owner-exclusive rollover có được reviewer mật mã chấp nhận không.** Nếu không, `expiry`
   Zether tụt về ≤ 1 epoch, `targetEpoch` quay lại struct `EncryptedTransfer`, và tỷ lệ revert do
   trôi epoch trở thành một bài toán phải giải. Hai thứ này đi cùng nhau và cả hai đều nằm trong
   `expiry` — nên envelope không đổi struct, chỉ đổi hằng số. Đó là lý do không nên đưa
   `targetEpoch` vào `MetaTransaction`.
