## 04. Meta-Transaction trên token: struct, 2D nonce, thao tác có kiểu

> **[BẢN 3 — viết lại theo `_USER-DECISIONS.md` §24.]** Bản 1 và bản 2 của section này đặc tả một
> **generic forwarder**: `to` / `data` tuỳ ý, một opcode `CALL` tới contract lạ, và bốn lớp phòng thủ
> cho vector mà chính `CALL` đó mở ra. Không token nào trong hệ cần thứ đó. Struct bây giờ mang một
> **mã thao tác** của chính token, và bộ điều phối gọi một **internal function**.
>
> Cái chết theo — và cái được đổi lại — nằm ở §04.6. Tiêu đề cũ có chữ "mode bitmask"; `mode` đã chết
> ở `_USER-DECISIONS.md` §20, thay bằng wildcard `relayer == address(0)`.

Phần này đặc tả tầng envelope. Zether **không** phải một tầng song song: `IZetherToken` kế thừa
`IERC20MetaTx`, nên `transferConfidential` là một hàm của **chính contract đó** — không phải một lời
gọi ra ngoài.

```
smartcontracts/src/
├── common/MetaTxLib.sol        # struct, TYPEHASH, bang op, hashStruct
├── common/FeePolicy.sol        # FeeMode, tran phi, requireConfidentialSafe()
├── common/SigLib.sol           # EIP-712 + ERC-1271
├── metatx/IERC20MetaTx.sol     # tầng nền: mọi token đều gasless được
├── metatx/IERC20Payment.sol    # token thanh toan cong khai
├── zether/IZetherToken.sol     # ke thua IERC20MetaTx
└── test/
    ├── FeePolicy.t.sol         # pin TYPEHASH
    └── vectors/metatx_v1.json  # *** test vector chuan, xem 04.13 ***
dms_blockchain/lib/eip1776.py                  # signer thuan Python, KHONG import odoo
dms_blockchain/tests/test_eip1776_vectors.py   # doc chinh metatx_v1.json o tren
dms_blockchain/models/blockchain_metatx.py

# KHÔNG CÒN: MetaTxForwarder.sol, TargetPolicy.sol, ExcessivelySafeCall.sol, Griefing.t.sol
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
| A7 | Zether proof gắn với epoch nên expiry ≤ 1 epoch | **Không còn đúng** sau khi §03.5 bỏ epoch và thay bằng `accSeq`. **[BẢN 5, 2026-09-03]** ràng buộc thay thế **không** phải owner-exclusive mà là `expiry` ngắn + single-flight + pre-broadcast check `accSeq` | 04.5 |
| A8 | Forwarder UUPS upgradeable | **Mâu thuẫn với §12.1** — upgradeable + allowance = rug vector | 04.2 |

Ba giả định còn lại vẫn đứng và được giữ nguyên: EIP-712 digest là khoá idempotency duy nhất;
EIP-712 digest là khoá idempotency duy nhất. **[BẢN 3]** Hai giả định kia — *"`mode` phải nằm trong
hash"* và *"`innerGasLimit` phải nằm trong digest"* — đã hết đối tượng: `mode` bỏ ở §04.4,
`innerGasLimit` bỏ ở §04.1.

---

### 04.1. Struct

```solidity
struct MetaTransaction {
    address from;           // người ký, người chịu hiệu lực
    address to;             // đích của thao tác trên chính token này
    uint256 value;          // số lượng token cho thao tác (0 nếu chỉ gọi logic)
    bytes   data;           // payload của thao tác
    uint256 batch;          // nonce chiều 1 — luồng độc lập
    uint256 nonce;          // nonce chiều 2 — thứ tự trong luồng
    uint256 validUntil;     // hạn, giây epoch
    uint32  mode;           // hai nửa byte: cờ ràng buộc + cách tính phí. Xem §04.4
    address relayer;        // chỉ ràng buộc khi mode & MODE_RESTRICT_RELAYER
    uint256 fee;            // ppm nếu PERCENT, tuyệt đối nếu FIXED, bỏ qua nếu NONE
    address feeRecipient;   // chỉ ràng buộc khi mode & MODE_RESTRICT_FEE_RECIPIENT
}
```

**`verifyingContract` của EIP-712 domain LUÔN là chính token contract.** Không có forwarder trong hệ
này — xem §04.1b. Nên struct không mang `to` với nghĩa "contract nào để gọi"; `to` là **người nhận của
thao tác**, và thao tác thì nằm trong chính contract đang verify chữ ký.

Hai thứ struct này phục vụ, và chỉ hai:

| Việc | Trường dùng |
|---|---|
| Chuyển token công khai | `to`, `value` |
| Chuyển bảo mật Zether | `data` mang `(payload, proof)`; `value = 0` |

#### `feeMode` — bỏ khỏi struct, gộp vào `mode`

Nó là một cờ ba giá trị nói *"phí tính theo giá trị hay theo tỉ lệ"*. Một trường `uint8` riêng cho ba
giá trị là lãng phí một word trong struct hash, trong khi `mode` đã có sẵn 30 bit trống. Gộp vào **nửa
byte sau** của `mode` (bit 4–7). Đặc tả ở §04.4.

#### `feeToken` — bỏ

Bản 1 thêm `feeToken` để giải bài toán *"không relayer mở nào chấp nhận điểm thưởng làm phí"*.

Bài toán đó **không thuộc về contract này**. Một token khác nằm ngoài contract này, và contract này
**không cầm allowance của nó** — nên nó không chuyển token đó cho ai được. Bản 1 giải được là vì nó giả
định một forwarder chung cầm allowance trên nhiều token, và chính cái allowance đó là lỗ hổng nghiêm
trọng nhất bản 1 tự tìm ra (§04.6.0).

Ba đường thay thế, không đường nào cần một trường trong struct:

| Cần gì | Cách làm |
|---|---|
| Luồng loyalty không trả được phí bằng điểm | `MODE_FEE_NONE`, issuer trợ cấp relayer ngoài envelope (`_USER-DECISIONS.md` §21.5: `fee = 0` với `feeRecipient` lạ là **hợp lệ và không hiếm**) |
| Muốn trả phí bằng USDC cho thao tác trên Z-POINT | Hai giao dịch. Không phải việc của token |
| Relayer cần biết trước có được trả không | Nửa byte phí trong `mode` + `fee` đã trong struct, đọc được từ mesh |

#### `innerGasLimit` — bỏ, và đây là lý do đầy đủ

**Nó tồn tại để bảo vệ NGƯỜI DÙNG khỏi RELAYER, và chỉ trong sự có mặt của một opcode `CALL` CỘNG một
chế độ nuốt lỗi.** Cần cả hai; thiếu một cái là vector không tồn tại.

**Trực giác mặc định là đúng, và phải nói ra trước:** một transaction hết gas thì **rollback sạch** —
không nonce nào tăng, không phí nào thu, không ai mất gì ngoài relayer mất gas của chính nó. Nếu đó là
toàn bộ câu chuyện thì `innerGasLimit` vô nghĩa ngay cả với forwarder.

Nó **không** là toàn bộ câu chuyện vì hai lý do xếp chồng.

**Lý do 1 — `CALL` tạo một biên revert riêng.** Khi A gọi B mà B hết gas, **chỉ frame của B revert**. B
trả về 0, và **A chạy tiếp** với phần gas A giữ lại (quy tắc 63/64 của EIP-150: B nhận tối đa 63/64,
A giữ ≥ 1/64). State của A không bị đụng tới. Đây là chỗ trực giác "một transaction, một số phận" sai:
một `CALL` chia transaction thành nhiều số phận.

**Lý do 2 — forwarder BUỘC phải nuốt lỗi, và đó mới là mắt xích quyết định.** Nếu contract bubble revert
thì cả tx revert và **không ai mất gì** — trực giác đúng nguyên vẹn. Nhưng một forwarder generic không
sống được với bubble-luôn: khi lời gọi bên trong fail vì **lý do nghiệp vụ**, relayer đã bỏ gas thật và
bubble nghĩa là nó **không được trả gì**. Không relayer nào nhận việc với luật đó. Nên forwarder phải có
chế độ **thu phí kể cả khi lời gọi fail** — và chế độ đó là cái mở cửa.

Ghép hai lý do lại thì mới ra được vector:

```
1. Forwarder PHẢI nuốt lỗi để relayer được trả khi fail vì lý do nghiệp vụ
2. Nuốt lỗi  =>  frame ngoài commit: nonce++, thu phí, emit success=false
3. Relayer ÁC Ý "chế tạo" một failure bằng cách bóp gas
4. Contract KHÔNG PHÂN BIỆT ĐƯỢC: fail do nghiệp vụ và fail do đói gas nhìn giống hệt nhau
5. Người dùng mất phí + một nonce. Hành động không xảy ra. Relayer giữ phí.
```

`innerGasLimit` trong digest cho contract một cách phân biệt:
`require(gasleft() >= innerGasLimit*64/63 + FLOOR)` **trước** khi gọi. Chữ ký người dùng nói *"thao tác
này cần ít nhất N gas; từ chối chạy nếu ít hơn"*. Đó là lỗ hổng kinh điển của GSN v1, và
`innerGasLimit` là câu trả lời đúng — **cho một forwarder có nuốt lỗi**.

**Và tấn công này có một cửa sổ khả thi hẹp, đáng nói vì nó giải thích vì sao bản 1 lo đúng chỗ.** Frame
ngoài chỉ giữ lại `G/64` (G = gas còn lại tại điểm `CALL`). Muốn frame trong đói thì
`63G/64 < inner_need`; muốn frame ngoài sống thì `G/64 >= post_call_cost`. Ghép lại:

```
tấn công khả thi  <=>  post_call_cost  <~  inner_need / 63
```

Với một thao tác rẻ (chuyển token, ~100k) và bookkeeping ~50k: cần `50k <= 1,6k`. **Không khả thi** —
bóp gas làm chết luôn cả frame ngoài, tức rollback sạch.

Với Zether (`inner_need` ~1,79 M) và cùng bookkeeping ~50k: cần `50k <= 28k`. **Cùng bậc, khả thi.** Nên
với forwarder chạy Zether thì đây là mối lo thật — và đó chính là cấu hình bản 1 đặc tả.

**Không có forwarder thì cả chuỗi sụp ngay từ mắt xích 1.** Thao tác nằm trong chính contract đang verify
chữ ký, nên không có `CALL`, không có frame ngoài để sống sót, không có gì để nuốt. Hết gas ⇒ cả tx
revert ⇒ nonce không tiêu, phí không thu, người dùng mất 0.

Đó là khác biệt giữa "vector được giảm nhẹ" và "vector không tồn tại".

Bốn lý do khác người ta có thể viện ra, và vì sao không cái nào đứng được:

| Lý do viện ra | Vì sao không |
|---|---|
| "Relayer muốn giới hạn gas nó bỏ ra" | Relayer tự đặt `gasLimit` của **vỏ tx**. Không cần người dùng ký hộ một con số |
| "Người dùng muốn giới hạn **chi phí**" | Chi phí của người dùng là `fee`, đã cố định và đã ký. Gas là việc của relayer |
| "Zether verify tốn 1,79 M gas, biến động" | OOG revert sạch. Và relayer **muốn** nó thành công — nó chỉ được phí khi thành công |
| "Người dùng grief ngược relayer bằng thao tác đắt" | Chi phí bị chặn và biết trước: token này chỉ làm hai việc (§04.1), và Zether là cái đắt duy nhất. Relayer tra bảng tĩnh |

Và lập luận đóng đinh: **trong mọi trường hợp còn sót lại, kẻ tấn công LÀ người dùng** — nên một trường
do chính người dùng ký là vô dụng để chống lại họ.

Còn hai chỗ vẫn có lời gọi ra ngoài, và cách xử **không** phải `innerGasLimit`:

| Chỗ | Rủi ro | Xử bằng |
|---|---|---|
| `isValidSignature` của smart account (ERC-1271) | `from` là contract, code tuỳ ý | `staticcall{gas: 50_000}` — **hằng số trong contract**, không phải trường ký |
| `safeTransfer` underlying khi rút khỏi Zether | Người nhận là contract có hook | Reentrancy guard + CEI. Đốt hết gas thì cả tx revert, relayer mất gas, user không lợi gì |

Cả hai là **griefing thuần chống relayer**, xử ở tầng vận hành: simulation gate bắt gần hết, phần còn
lại vào `origin_grief_score` (§05.5).

#### `mode` — GIỮ

`mode` điều khiển **đúng hai trường**: `relayer` và `feeRecipient`. Đặc tả đầy đủ ở §04.4.

---
#### 04.1b. Không có forwarder, và sẽ không bao giờ có

Quyết định của user, 2026-08-31:

> *"Tôi không cần làm 'contract bạn không kiểm soát trở nên gasless', vì những contract mà không
> support gasless là sai triết lý. Nếu đã lỡ phát hành, thì cần wrap sang MetaTx."*

Một **generic meta-tx forwarder** là một contract đứng giữa, nhận chữ ký rồi `CALL` sang một contract
**thứ ba** với calldata tuỳ ý. Nó tồn tại để giải **đúng một** bài toán: làm cho một contract bạn
**không kiểm soát** trở nên gasless.

Bài toán đó không tồn tại ở đây, và không phải vì trùng hợp — vì **triết lý**: một token không hỗ trợ
gasless là một token thiết kế sai. Token trong hệ này tự hiện thực meta-transaction (native mixin), nên
`verifyingContract` **luôn là chính token contract**.

Token bên ngoài đã lỡ phát hành thì **wrap**: `MetaToken` bọc nó (archetype `WRAP_1_1`, §01), và wrapper
là contract của ta nên nó có sẵn mixin. Không cần lớp đệm.

**Vì sao spec từng có forwarder** — ba bước, mỗi bước hợp lý, kết quả thì không:

1. `blockchain.md` yêu cầu "meta-transaction theo EIP-1776" một cách chung chung.
2. Hình dạng chuẩn tắc của EIP-1776/GSN **là** forwarder, nên bản 1 đặc tả nó.
3. Bản 1 **cũng** nhận ra mixin tốt hơn và ghi *"với Zether dùng native mixin"* — rồi giữ cả hai song song.

Hệ quả: spec mang theo toàn bộ máy móc của forwarder cho một hình thái không ai dùng. **Tất cả đã bị gỡ:**

| Gỡ | Vì sao nó từng có |
|---|---|
| `MetaTxForwarder.sol` | Contract đứng giữa |
| `TargetPolicy.sol`, allowlist target | `to` tuỳ ý cần allowlist |
| `ExcessivelySafeCall.sol`, `MAX_RETURN_BYTES` | returndata từ contract lạ |
| `innerGasLimit`, guard 63/64 | Chống relayer bóp gas — §04.1 |
| `feeToken`, quản lý allowance, `permit` bootstrap | Forwarder cầm allowance nhiều token |
| ERC-2771 sender suffix, `MODE_APPEND_SENDER` | Target cần biết `from` là ai |
| `MODE_REQUIRE_SUCCESS`, swallow mode | Chọn bubble hay nuốt lỗi của inner call |

Và một chỗ bản 1 hiểu sai kiến trúc: nó viết *"Zether là inner call, không phải một tầng song song"* —
**đúng về ý** (Zether không phải tầng riêng), **sai về cơ chế**. `IZetherToken` **kế thừa**
`IERC20MetaTx`; `transferConfidential` không phải một `CALL` nào cả, nó là một hàm của chính contract đó.

---
### 04.2. EIP-712 domain: từng trường đều chịu lực

```solidity
bytes32 constant DOMAIN_TYPEHASH = keccak256(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
// name = "ScaasMetaTx", version = "1"
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
LANE_DOMAIN = b'scaas.metatx.lane.v1'
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
    'Một lane (batchId, batchNonce) chỉ được có một bản ghi sống.')
# lane_slot: Integer, NULL khi metatx_state in ('expired','failed','superseded'),
#            = 0 khi còn sống. Compute stored, MỌI nhánh đều gán giá trị (bẫy Odoo 19).
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

### 04.4. `mode`: điều khiển đúng hai trường, và bài toán digest

`mode` là bitmask `uint32`, và nó chỉ nói về **`relayer` và `feeRecipient`** — không gì khác.

```
bit:  7 6 5 4 | 3 2 1 0
      └──┬──┘   └──┬──┘
    cách tính    cờ ràng buộc
       phí       relayer / feeRecipient
```

```solidity
uint32 constant MODE_OPEN                   = 0x0000_0000;  // không phải một bit, là "không bit nào"

// --- nửa byte ĐẦU: cờ, bật được cùng lúc ---
uint32 constant MODE_RESTRICT_RELAYER       = 0x0000_0001;
uint32 constant MODE_RESTRICT_FEE_RECIPIENT = 0x0000_0002;
uint32 constant MODE_FLAGS_MASK             = 0x0000_000F;

// --- nửa byte SAU: giá trị liệt kê, loại trừ nhau ---
uint32 constant MODE_FEE_MASK               = 0x0000_00F0;
uint32 constant MODE_FEE_SHIFT              = 4;
uint32 constant MODE_FEE_NONE               = 0x0000_0000;
uint32 constant MODE_FEE_PERCENT            = 0x0000_0010;
uint32 constant MODE_FEE_FIXED              = 0x0000_0020;

uint32 constant MODE_KNOWN_MASK             = 0x0000_00F3;
```

**Hai nửa byte có bản chất khác nhau, và đó không phải chi tiết vụn.** Nửa đầu là **cờ** — độc lập, bật
được cùng lúc, đọc bằng `mode & FLAG`. Nửa sau là **giá trị liệt kê** — ba chế độ loại trừ nhau, đọc
bằng mask + shift. Viết `if (mode & MODE_FEE_PERCENT)` là một bug: `MODE_FEE_FIXED = 0x20` không chứa
bit `0x10`, nhưng một giá trị tương lai `0x30` thì có, và nó sẽ lọt.

```solidity
function feeModeOf(uint32 mode) internal pure returns (FeeMode) {
    uint32 v = (mode & MODE_FEE_MASK) >> MODE_FEE_SHIFT;
    if (v == 0) return FeeMode.NONE;
    if (v == 1) return FeeMode.PERCENT;
    if (v == 2) return FeeMode.FIXED;
    revert ModeFeeInvalid(mode);
}
```

`FeeMode` **vẫn là kiểu chuẩn tắc** của tầng phí (`FeePolicy.compute`, `requireConfidentialSafe` không
đổi một dòng). Cái bỏ đi là **một trường riêng trong struct**, không phải khái niệm.

`MODE_RESTRICT_BOTH = 0x03` giữ nguyên nghĩa (`0x01 | 0x02`) nhưng **không** nên là một hằng riêng trong
`.sol` — nó là một tổ hợp, không phải một chế độ. Để nó trong `.sol` là mời người ta viết
`if (mode == MODE_RESTRICT_BOTH)`, tức so sánh bằng thay vì mask, tức một bug chờ xảy ra nếu sau này có
thêm bit.

**Ba bit của bản 1 đã chết, và mỗi cái vì một lý do khác nhau:**

| Bit cũ | Số phận |
|---|---|
| `MODE_REQUIRE_SUCCESS = 0x04` | **Chết** cùng forwarder — không còn inner call để chọn bubble hay nuốt lỗi (§04.1b) |
| `MODE_METERED_FEE = 0x08` | **Chết** — cách tính phí giờ là nửa byte sau, ba giá trị rõ ràng thay cho một bit mơ hồ |
| `MODE_APPEND_SENDER = 0x10` | **Chết** cùng forwarder — ERC-2771 suffix chỉ có nghĩa khi gọi contract khác |

`uint32` giữ nguyên dù chỉ dùng 2 bit: tốn **0 gas** thêm (ABI pad cả `uint8` lẫn `uint32` về 32 byte
trong calldata, và trong struct hash cả hai chiếm đúng một word), và hết bit giữa vòng đời contract
nghĩa là bump `version` và vô hiệu hoá mọi chữ ký đang lưu hành.

#### Bài toán digest, và cách giải

Note viết *"chữ ký KHÔNG bao gồm `feeRecipient` và `relayer` trong digest hash (**hoặc** hash với
`address(0)`)"*. Chữ "hoặc" đó là chỗ hỏng: hai cách cho hai digest khác nhau; client chọn cách A,
verifier làm cách B, thì **mọi chữ ký fail**.

Chốt **hash với `address(0)`**, không phải "bỏ trường ra khỏi struct". Lý do quyết định: EIP-712
`TYPEHASH` là hash của *type string*, và type string phải cố định.

- Bỏ trường ra khi MODE_OPEN ⇒ đó là một **type khác** ⇒ cần `TYPEHASH` thứ hai ⇒ ví EIP-712 (MetaMask,
  Rabby, mọi smart account) hiển thị **hai loại giao dịch khác nhau cho cùng một hành động**. Người dùng
  không đọc được cái họ đang ký.
- Và encoding độ dài thay đổi **phá injectivity** — cùng lớp lỗi với việc quên `keccak256` trên `bytes`.

Một type string, hai giá trị canonical:

```solidity
function canon(MetaTransaction memory m) internal pure returns (address r, address f) {
    r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
    f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
}
```

Verifier băm `canon(m)`, **không** băm `m.relayer`/`m.feeRecipient` thô. Nhờ vậy trong MODE_OPEN relayer
tự điền hai ô đó trong calldata mà digest không đổi; trong mode restrict, ô đó đã nằm trong digest nên
relayer sửa là chữ ký chết.

#### Ba quy tắc bắt buộc đi kèm

1. **Quy tắc canonical phải giống hệt nhau ở BA nơi**: verifier Solidity, SDK client, builder Odoo. Lệch
   một chỗ thì mọi chữ ký fail — fail-closed nên không mất tiền, nhưng phải có test vector chung
   (§04.13 mục 1) chứ không dựa vào việc ba người nhớ đúng.
2. **Cấp phát bit là tài nguyên chung, và nó ĐÃ va chạm** — không giả định, có thật trong bộ tài liệu
   này: §05.3.3 xin `0x04` cho `MODE_METERED_FEE` trong khi §04 đã dùng `0x04` cho
   `MODE_REQUIRE_SUCCESS`; §5.12 lại xin mask `0x0F` trong khi §04 khai `0x1F`. Vì `mode` nằm **trong**
   digest, va chạm kiểu này **không gây lỗi biên dịch** — nó gây ra hai cách hiểu cho cùng một chữ ký.
   Bảng ở đầu mục này là **nguồn sự thật duy nhất**; section khác tham chiếu, không tự cấp phát.
3. **Bit lạ VÀ giá trị lạ đều phải bị từ chối** — hai kiểm tra khác nhau vì hai nửa byte khác bản chất:

   ```solidity
   function validateMode(uint32 mode) internal pure {
       if (mode & ~MODE_KNOWN_MASK != 0) revert ModeUnknownBits(mode);  // nua dau: bit la
       feeModeOf(mode);                                                 // nua sau: gia tri > 2
   }
   ```

   Nửa sau là chỗ dễ bỏ sót: `0x30` là **bit hợp lệ** (nằm trong `MODE_KNOWN_MASK`) nhưng **giá trị vô
   nghĩa**. Chỉ kiểm mask là để nó lọt, và khi ai đó muốn gán nghĩa cho `0x30` ở phiên bản sau thì đã có
   những chữ ký mang giá trị đó với ngữ nghĩa "không xác định" đang lưu hành. Gọi ở **bước 3** của
   §04.6.1, trước verify chữ ký — 0 gas cho rác.

#### Trạng thái mâu thuẫn: `RESTRICT_RELAYER` với `relayer = address(0)`

Hợp lệ về kiểu, và `canon` giữ `relayer = 0` trong hash. Contract kiểm `require(msg.sender == m.relayer)`
⇒ đòi `msg.sender == address(0)` ⇒ **revert vĩnh viễn**. Một intent trông hợp lệ, ký hợp lệ, không bao
giờ chạy được.

Chặn ở **builder**, không ở contract: `_build_metatx` raise khi `mode & MODE_RESTRICT_RELAYER` mà
`relayer == address(0)`. Đặt check này on-chain tốn gas cho mọi giao dịch để chặn một lỗi lập trình mà
người ký tự gây ra cho chính mình.

#### `relayer` và `feeRecipient` là hai câu hỏi khác nhau

`_USER-DECISIONS.md` §21.5: `MODE_RESTRICT_FEE_RECIPIENT` bật cộng `MODE_RESTRICT_RELAYER` **tắt** là
**cấu hình đúng của một relayer xoay khoá** — phí về một ví cố định, còn khoá nào ký thì tuỳ node. Đừng
gộp hai bit thành một "chế độ hạn chế": chúng trả lời hai câu hỏi độc lập.

Và `feeRecipient = address(0)` trong MODE_OPEN có nghĩa **"trả cho `msg.sender`"** — một tiện ích, không
phải một bảo đảm. Relayer nào muốn chắc chắn thì xin người ký bật bit và điền địa chỉ.

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

**[BẢN 5, 2026-09-03]** **Vế "rủi ro revert bằng 0" chỉ còn đúng cho tài khoản `OWNER_ONLY`.** Với mặc
định `PUBLIC` (§C5 [BẢN 5]), `accSeq` bump được bởi bên thứ ba — nhưng **chỉ sau một credit
thật** — nên proof đang bay vẫn chết được. Kết luận về `expiry` **không đổi** (nó không còn bị
epoch ràng buộc), nhưng lý do đổi: cái giữ tỷ lệ revert thấp bây giờ là **`expiry` ngắn (60 s) +
single-flight theo `schnorr_address` + pre-broadcast check `accSeq == provedAccSeq` tại block đã
ghim**, không phải quyền độc quyền của chủ tài khoản.

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

### 04.6. Thực thi: kiểm trước, thu phí sau

> **[BẢN 3]** Mục này trước có tám tiểu mục và ~280 dòng, gần như toàn bộ nói về hệ quả của một opcode
> `CALL` tới contract lạ. Không còn forwarder (§04.1b) nên phần lớn không còn đối tượng.

#### 04.6.0. Tám tiểu mục cũ, và số phận từng cái

| Tiểu mục cũ | Nội dung | Số phận |
|---|---|---|
| 04.6.1 Return-bomb | Target trả mảng bytes khổng lồ, `call` copy hết, memory bậc hai, OOG frame ngoài | **Chết.** Không có returndata từ contract lạ |
| 04.6.2 `amount` + swallow mode | Chuyển principal rồi inner call fail ⇒ mất tiền gốc; cần `MODE_REQUIRE_SUCCESS` | **Chết**, giải bằng cách tốt hơn — §04.6.2 mới |
| 04.6.3 Quy tắc 63/64 | `gasleft() >= innerGasLimit*64/63 + FLOOR` | **Chết.** Biện hộ đầy đủ ở §04.1 |
| 04.6.4 Bootstrap allowance | `permit` / EIP-3009 để forwarder có allowance | **Chết.** Token trừ số dư nội bộ, không cầm allowance của ai |
| 04.6.5 Sender suffix ERC-2771 | Nối `from` vào cuối calldata để target biết ai gọi | **Chết.** Không có target |
| 04.6.6 Forwarder giữ allowance | Lỗ hổng rút sạch mọi user đã approve | **Chết cùng nguyên nhân của nó** — xem dưới |
| 04.6.7 Thứ tự fee, reentrancy | CEI, guard | **Một nửa sống** — §04.6.3 mới |
| 04.6.8 Batch | `executeBatch` cho relayer | **Sống nguyên** — §04.6.4 mới |

Ghi chú về 04.6.6, vì nó là lỗ hổng nghiêm trọng nhất bản 1 tự tìm ra: một forwarder generic giữ
`approve(forwarder, max)` của nhiều user, cộng `to`/`data` tự do, cho phép bất kỳ ai ký một metaTx của
**chính mình** với `to = USDC, data = transferFrom(victim, attacker, X)`. Bản 1 vá bằng ba lớp. Bản 3
**không có allowance nào để mà rút**: token tự trừ số dư nội bộ, và `to` là người nhận chứ không phải
contract để gọi. Lỗ hổng biến mất cùng cơ chế sinh ra nó — đó là dạng vá tốt nhất.

#### 04.6.1. Thứ tự thực thi, và nó là hợp đồng

```
1. relayer      (0 gas)   — mode & RESTRICT_RELAYER == 0, hoặc m.relayer == msg.sender
2. validUntil   (0 gas)   — block.timestamp <= m.validUntil
3. mode hợp lệ  (0 gas)   — validateMode: bit lạ (nửa đầu) VÀ giá trị phí lạ (nửa sau)
4. nonce        (1 sload) — metaNonce[from][batch] == m.nonce
5. chữ ký       (~3k)     — trên digest đã canon (§04.4); ECDSA hoặc ERC-1271
                            staticcall{gas: 50_000}
6. KIỂM TRA ĐỦ điều kiện của thao tác — mọi thứ có thể fail đều fail ở đây
7. thu phí
8. thực thi thao tác
9. metaNonce[from][batch]++  và emit
```

Bước 1–3 tốn **0 gas** và chặn được toàn bộ spam rẻ tiền. Đặt `nonce` trước `validUntil` (như bản nháp
gốc của note) là trả 2.100 gas cho một thứ đáng lẽ miễn phí.

#### 04.6.2. Kiểm đủ trước khi thu phí — cái thay thế swallow mode

Đây là chỗ thiết kế không-forwarder trả tiền cho chính nó.

Một forwarder generic **không bao giờ biết trước** lời gọi bên trong sẽ fail vì gì, nên nó buộc phải chọn
một trong hai cái tệ, và cả bộ tài liệu cãi nhau đúng chỗ này (`_CRITIQUES.md` contradiction-2: §04.6.2
cũ nói bubble, §08.4c và §06.6 nói thu phí bất kể):

| Lựa chọn | Ai chịu |
|---|---|
| Thu phí trước, nuốt lỗi | **Người dùng** trả tiền cho một việc không xảy ra |
| Bubble revert | **Relayer** bỏ gas thật rồi không được gì |

Thao tác nằm trong **chính contract này**, nên contract biết chính xác cái gì fail được. Kiểm hết ở
**bước 6**, thu phí ở **bước 7**, và sau điểm đó thao tác **không thể** fail:

| Thao tác | Kiểm ở bước 6 |
|---|---|
| Chuyển token công khai | `balanceOf(from) >= value + feeAmount` |
| Chuyển bảo mật Zether | đã đăng ký; `zetherNonce` khớp; **proof verify PASS**; điểm on-curve + subgroup |

Bất biến trở thành **"phí đã thu ⟺ thao tác đã xảy ra"**, đạt được **không try/catch, không mode nào**.
contradiction-2 đóng vì hết đối tượng.

**Thao tác fail thì sao?** Toàn bộ tx revert: nonce không tiêu, phí không thu, relayer mất gas. Đó là chi
phí còn lại và nó nằm ở tầng vận hành — simulation gate bắt gần hết, phần còn lại là cố ý và vào
`origin_grief_score` (§05.5).

Với Zether có một sắc thái phải nói: verify proof nằm ở bước 6, nên một proof rác đốt ~1,79 M gas
**trước khi** revert. Đó là lý do thứ tự fail-fast của §12.1 — status → nonce → on-curve → expiry →
**rồi mới** MSM — là bắt buộc chứ không phải tối ưu. Reject sớm rẻ hơn reject muộn khoảng **1.000 lần**.

#### 04.6.3. Reentrancy — vẫn thật, nhưng vì lý do khác

Bản 1 cần guard vì `CALL` tới contract lạ. Không còn `CALL` đó, nhưng **đường rút khỏi Zether vẫn gọi ra
ngoài**: `underlying.safeTransfer(recipient, amount)`, và người nhận có thể là contract có hook
(ERC-777, hoặc underlying là contract).

Guard vẫn bắt buộc, quy tắc không đổi:

- **CEI nghiêm**: `zetherNonce++`, trừ `(C,D)`, tăng `metaNonce` — **tất cả trước** `safeTransfer`.
- **Một guard theo CONTRACT**, không theo hàm. Guard theo hàm không chặn cross-function reentrancy, và
  `burn` với `migrateAccount` dùng chung `(C,D)`.
- Test `ReentrancyCross.t.sol` gọi chéo **từng cặp** hàm đổi state.

**[CẬP NHẬT 2026-08-31] Chain 9000 đã nâng lên Nethermind 1.39.0 với Fusaka + BPO2, nên `TSTORE`/`TLOAD`
đã có** và `ReentrancyGuardTransient` dùng được. Profile `private7622` trong `foundry.toml` đổi từ
`berlin` sang `prague`.

Nhưng lý do bản trước phải hạ xuống `berlin` thì đáng giữ làm bài học: genesis khai `cancunBlock: 0`
kiểu Geth trong một file **format chainspec Nethermind**, và Nethermind bỏ qua im lặng mọi key ngoài
schema của nó. Không warning. Chain chạy pre-London trong khi file khai là Prague, và cách duy nhất
phát hiện là **đo** — `eth_call` một initcode chứa `PUSH0`, hoặc xem header có `baseFeePerGas` không.

#### 04.6.4. Batch — relayer sẽ hỏi, tốt hơn là thiết kế trước

`executeMetaTransactionBatch(MetaTransaction[] calldata ms, bytes[] calldata sigs)`.

Ba ràng buộc bắt buộc, giữ nguyên từ bản 1 vì chúng không đến từ mô hình forwarder:

1. **Một item fail KHÔNG được kéo cả batch chết.** Nhưng §04.6.2 vừa nói thao tác fail thì cả tx revert —
   cách giải: contract chạy bước 1–6 cho **toàn bộ** item trước, loại item nào không qua (emit
   `MetaTxSkipped(digest, reason)`), rồi mới chạy bước 7–9 cho phần còn lại. Không try/catch, vẫn
   thành-công-một-phần.
2. **Thu phí từng item trước khi thực thi item đó**, không gom cuối batch.
3. **Trần độ dài**: `require(ms.length <= MAX_BATCH)`. Không có trần là một vòng lặp do người dùng điều
   khiển.

Batch có ý nghĩa nhất khi **ta tự sinh cả N** (§06.6.1: một chữ ký HSM cho N item). Nó **không** giúp
một node mesh nhận việc của người lạ — chỗ đó cần pool khoá (`_USER-DECISIONS.md` §21.5). Hai cơ chế,
hai nút thắt khác nhau.

---
### 04.7. Reference interface

> Interface chuẩn tắc **là code**, không phải mục này: `smartcontracts/src/common/MetaTxLib.sol` và
> `smartcontracts/src/metatx/IERC20MetaTx.sol`. Chép ở đây để đọc liền mạch; khi hai bên lệch thì
> **code đúng**, và `test_metaTxTypehashIsPinned` là thứ ghim nó.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;   // chain 9000 nay da co Cancun/Prague, xem §04.6.3

library MetaTxLib {
    // bit 3..0 = cờ ràng buộc; bit 7..4 = cách tính phí. Xem §04.4
    uint32 constant MODE_OPEN                   = 0x0000_0000;
    uint32 constant MODE_RESTRICT_RELAYER       = 0x0000_0001;
    uint32 constant MODE_RESTRICT_FEE_RECIPIENT = 0x0000_0002;
    uint32 constant MODE_FLAGS_MASK             = 0x0000_000F;
    uint32 constant MODE_FEE_MASK               = 0x0000_00F0;
    uint32 constant MODE_FEE_SHIFT              = 4;
    uint32 constant MODE_FEE_NONE               = 0x0000_0000;
    uint32 constant MODE_FEE_PERCENT            = 0x0000_0010;
    uint32 constant MODE_FEE_FIXED              = 0x0000_0020;
    uint32 constant MODE_KNOWN_MASK             = 0x0000_00F3;

    struct MetaTransaction {
        address from;
        address to;             // người nhận của thao tác, KHÔNG phải contract để gọi
        uint256 value;
        bytes   data;
        uint256 batch;
        uint256 nonce;
        uint256 validUntil;
        uint32  mode;
        address relayer;
        uint256 fee;
        address feeRecipient;
    }

    // Cách tính phí nằm ở nửa byte sau của mode. FeeMode vẫn là kiểu của FeePolicy.
    function feeModeOf(uint32 mode) internal pure returns (FeeMode);
    // Từ chối bit lạ (nửa đầu) VÀ giá trị lạ (nửa sau). Gọi ở bước 3, §04.6.1.
    function validateMode(uint32 mode) internal pure;

    // Chuẩn hoá hai trường do relayer điền, TRƯỚC khi băm. Quy tắc này phải giống
    // hệt nhau ở verifier Solidity, SDK client và builder Odoo — §04.4.
    function canon(MetaTransaction memory m) internal pure returns (address r, address f) {
        r = (m.mode & MODE_RESTRICT_RELAYER)       != 0 ? m.relayer      : address(0);
        f = (m.mode & MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
    }

    bytes32 constant METATX_TYPEHASH = keccak256(
        "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,"
        "uint256 nonce,uint256 validUntil,uint32 mode,address relayer,"
        "uint256 fee,address feeRecipient)"
    );

    function hashStruct(MetaTransaction memory m) internal pure returns (bytes32) {
        (address r, address f) = canon(m);
        return keccak256(abi.encode(
            METATX_TYPEHASH, m.from, m.to, m.value,
            keccak256(m.data),                      // <-- keccak(data), BẮT BUỘC
            m.batch, m.nonce, m.validUntil, m.mode,
            r, m.fee, f
        ));
    }
}

interface IERC20MetaTx is IERC20 {
    // relayer/feeRecipient phát ra đây là giá trị ĐÃ RESOLVE tại runtime, không phải
    // m.relayer/m.feeRecipient thô — trong MODE_OPEN hai ô đó là rác do relayer điền.
    event MetaTransactionExecuted(
        address indexed from, address indexed relayer, uint256 indexed batch,
        uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee
    );
    event MetaTxSkipped(bytes32 digest, uint8 reason);   // chỉ trong batch, §04.6.4

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error ModeUnknownBits(uint32 mode);
    error ModeFeeInvalid(uint32 mode);
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);

    function metaNonce(address from, uint256 batch) external view returns (uint256);
    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function supportedModes() external view returns (uint32);

    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external returns (bool success);

    function executeMetaTransactionBatch(
        MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata sigs
    ) external returns (uint256 executed);

    function cancelMetaNonce(uint256 batch) external;
}
```

Bốn điểm đã đổi so với bản 1, mỗi cái nối về một mục:

| Đổi gì | Vì sao | Mục |
|---|---|---|
| Bỏ `feeToken`, `innerGasLimit`, `tokenContract` | Không forwarder; phí bằng chính token; `verifyingContract` đã là token | §04.1, §04.1b |
| `pragma ^0.8.24` → `^0.8.20` | Giữ sàn thấp cho khả năng chuyển chain. Transient storage nay **dùng được** trên 9000 (Fusaka) | §04.6.3 |
| `event` bỏ `success`, thêm `feeRecipient`/`fee` đã resolve | Không còn nhánh "thành công một nửa"; indexer cần biết phí thực trả về đâu | §04.6.2 |
| `mode` mask `0x1F` → `0xF3`, bỏ trường `feeMode` | Ba bit chết cùng forwarder; cách tính phí dời vào nửa byte sau | §04.4 |

`metaTxDigest` là `view` và **public có chủ đích**: mesh cần validate-before-gossip, SDK cần kiểm chéo
digest trước khi gửi. Nó không lộ gì — digest tính được từ dữ liệu công khai.

---

### 04.8. Thuật toán ký

Bên ký **không bao giờ** tự dựng `verifyingContract` hay `chainId` từ cấu hình cục bộ; đọc từ chain hoặc
từ `/policy` của node (`_USER-DECISIONS.md` §21.3). Một `chainId` sai làm chữ ký chết im lặng.

```python
# dms_blockchain/lib/eip1776.py  — thuần Python, KHÔNG import odoo
def build_and_sign(token_addr, chain_id, to, value, data, batch, nonce,
                   valid_until, mode, relayer, fee, fee_recipient, signer):
    # 1. Domain: verifyingContract LÀ CHÍNH TOKEN. Không có forwarder (§04.1b).
    domain = {'name': TOKEN_NAME, 'version': '1',
              'chainId': chain_id, 'verifyingContract': token_addr}

    # 2. Chặn trạng thái mâu thuẫn ở BUILDER, không ở contract (§04.4):
    #    RESTRICT_RELAYER với relayer = 0 là một intent revert vĩnh viễn.
    if (mode & MODE_RESTRICT_RELAYER) and relayer == ZERO:
        raise ValueError('RESTRICT_RELAYER cần một địa chỉ relayer thật')
    if (mode & ~MODE_KNOWN_MASK):
        raise ValueError('bit mode lạ: contract sẽ revert ModeUnknownBits')
    if ((mode & MODE_FEE_MASK) >> MODE_FEE_SHIFT) > 2:
        raise ValueError('nửa byte phí lạ: contract sẽ revert ModeFeeInvalid')

    # 3. FeeMode PERCENT bị CẤM trên token bảo mật: fee = v*p với cả hai vế công khai
    #    CHÍNH LÀ số tiền. §12.3.7. Kiểm ở client để lỗi hiện sớm, contract kiểm lại.
    if is_confidential(token_addr) and (mode & MODE_FEE_MASK) == MODE_FEE_PERCENT:
        raise ValueError('PERCENT fee làm lộ số tiền trên token bảo mật')

    m = MetaTransaction(from_=signer.address, to=to, value=value, data=data,
                        batch=batch, nonce=nonce, valid_until=valid_until,
                        mode=mode, relayer=relayer,
                        fee=fee, fee_recipient=fee_recipient)

    # 4. canon() TRƯỚC khi băm — cùng quy tắc với Solidity (§04.4).
    # 5. keccak(data) — KHÔNG encode thẳng. Bỏ là vỡ injectivity:
    #    ("ab","c") và ("a","bc") cho cùng một digest.
    digest = eip712_digest(domain, METATX_TYPE_STRING, canon(m))
    sig = signer.sign_digest(digest)
    return m, sig, digest
```

Bốn quy tắc bắt buộc cho mọi bản cài đặt bên ký:

1. **`nonce` đọc từ chain**, `metaNonce(from, batch)`, ngay trước khi ký. Cache là nguồn của intent chết.
2. **`batch` ngẫu nhiên 128-bit cho mọi intent độc lập**, `nonce = 0`. Chỉ dùng chuỗi tuần tự khi nghiệp
   vụ thật sự có thứ tự (§04.3, §15.2.3).
3. **`validUntil` theo bảng §04.5.**
4. **Test vector `metatx_v1.json` là hợp đồng liên ngôn ngữ.** Python signer, SDK client và Solidity
   verifier chạy chung một bộ — đặc biệt là quy tắc `canon`, thứ duy nhất phải khớp ở ba nơi. Đây cũng
   chính là bộ conformance vector mà `_USER-DECISIONS.md` §21.3 bắt buộc cho mạng mở.

---

### 04.9. Griefing: bảng tổng hợp

Bảng bản 1 có 15 dòng. **Chín dòng không còn đối tượng** sau khi bỏ forwarder; giữ lại tên chúng để
không ai tưởng bị bỏ sót.

| Vector | Còn không | Biện pháp / lý do chết |
|---|---|---|
| Target đốt sạch gas (vòng lặp vô hạn) | **chết** | Không có target |
| Return-bomb | **chết** | Không có returndata từ contract lạ |
| OOG cố ý của relayer (63/64) | **chết** | Không `CALL` ⇒ không frame ngoài sống sót. §04.1 |
| Rút sạch qua allowance của forwarder | **chết** | Không cầm allowance của ai |
| Self-call / re-entry đường vòng | **chết** | `to` là người nhận, không phải contract để gọi |
| Swallow mode ăn mất principal | **chết** | Không có swallow mode (§04.6.2) |
| Front-run `permit` | **chết** | Không dùng `permit` để bootstrap |
| Bubble revert data cụt | **chết** | Không bubble gì |
| User ký `innerGasLimit` khổng lồ | **chết** | Không có trường đó |
| Đua nonce giữa 2 relayer | **còn** | Check nonce sau 3 check 0-gas. Kẻ thua mất ~26.000 gas ≈ $0,00004 |
| User tự huỷ nonce để đốt gas relayer | **còn** | `cancelMetaNonce` là quyền chính đáng; chống bằng `origin_grief_score` (§05.5) |
| Relayer trễ hạn ăn fee | **còn** | `validUntil` ngắn (§04.5), check **trước** nonce++ và fee. Relayer mất gas, user mất 0 |
| Chữ ký EIP-1271 revoke sau simulation | **còn** | `validUntil` ngắn + re-simulate ở block mục tiêu. `staticcall{gas:50_000}` chặn 1271 đắt |
| Reentrancy qua hook của underlying | **còn** | CEI + guard theo **contract** (§04.6.3). Chỉ đường rút khỏi Zether |
| **[MỚI] Thao tác fail có chủ ý để đốt gas relayer** | **còn, và là vector chính còn lại** | Toàn bộ tx revert, relayer mất gas, user mất 0 và **không lợi gì**. Simulation gate + `origin_grief_score`. Với Zether tốn ~1,79 M gas trước revert ⇒ fail-fast của §12.1 bắt buộc |

Đọc bảng theo một câu: **bỏ forwarder xoá chín vector và không tạo ra vector nào mới.** Cái duy nhất mới
là dòng cuối, và nó không mới về bản chất — nó là dòng "đua nonce" nhìn từ góc khác, cùng cách xử ở tầng
vận hành.

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
phụ thuộc `zetherNonce`, và `targetEpoch` không có gì để bind. **Bỏ.** (**[BẢN 5, 2026-09-03]** `accSeq` thay
epoch ở cả hai chế độ `RollOverMode`, nên `targetEpoch` vẫn không có gì để bind — kết luận giữ
nguyên, chỉ lý do hẹp lại.) Nếu vì lý do audit mật mã
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
| Envelope overhead khác (dispatch nội bộ, guard, event) | ~10,000 | |
| **Tổng** | **~1,720,000 – 2,620,000** | |

**[BẢN 3]** Bản 1 chốt ở đây `innerGasLimit = 3_000_000`, `maxInnerGas = 3_200_000` và
`requiredOuterGas ≈ 3,178,000`. Cả ba **biến mất** cùng inner call (§04.1): không có `CALL` thì không có
63/64, không có trần để ký, không có "outer gas" tách khỏi "inner gas".

Cái thay thế chúng là **một bảng tĩnh phía relayer**, không phải một trường trong digest:

| Thao tác | Gas ước tính | Relayer đặt `tx.gasLimit` |
|---|---|---|
| Chuyển token công khai | **58.702 – 75.802 (ĐO)** — 67.4 k khi có phí; xem `00-CANON.md` §C7.6 | ~120.000 |
| Nạp vào Zether (`fund`) | ~120.000 | ~180.000 |
| **`transferConfidential`** | **1.720.000 – 2.620.000** | **3.200.000** |
| Rút khỏi Zether (`burn`) | ~1.900.000 | 3.200.000 |
| `rollOver` | ~31.000 | 60.000 |

Relayer tra bảng theo **selector 4 byte đầu của `data`** (hoặc `data` rỗng ⇒ chuyển token thường) —
đọc được ở hàng rào L0 (§22.3), **trước** cả khi verify chữ ký. Nó không cần người dùng ký hộ một con
số, và nó không bị nói dối được vì selector quyết định code chạy.

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
3. **Con số `400_000` của bản nháp gốc sai một bậc và sẽ làm mọi Zether metaTx OOG ngay tx đầu tiên.**
   Sau §04.1 nó không còn là một trường đã ký nữa, nhưng nó vẫn sống ở chỗ khác: **relayer đặt
   `tx.gasLimit`**. Đặt 400k ở đó thì tx revert vì OOG, relayer mất gas, và triệu chứng là "tx fail
   không rõ lý do" chứ không phải một lỗi có tên. Bảng gas ở trên là để không ai đoán con số đó.

**Nếu 2.5M gas là không chấp nhận được trên public chain**, lối thoát không phải là tối ưu
Bulletproofs mà là **đổi hệ chứng minh sang Groth16/PLONK** (khi đó 180k–250k của note là đúng),
đánh đổi bằng trusted setup và mạch cố định. Đó là một quyết định kiến trúc thuộc §03, không phải
§04 — nhưng envelope phải chịu được cả hai. **[BẢN 3]** Và nó chịu được **tốt hơn** sau khi bỏ
`innerGasLimit`: chuyển từ Bulletproofs sang Groth16 đổi chi phí của `transferConfidential` từ ~1,9 M xuống
~215 k, và thứ phải sửa là **một dòng trong bảng tra của relayer**, không phải struct, không phải
`TYPEHASH`, không phải chữ ký nào đang lưu hành. Với bản 1 thì `innerGasLimit` là trường đã ký, nên mọi
intent chưa land đều mang một con số lỗi thời.

**Điểm cuối, đúng theo nguyên tắc VietQR.** Trong swallow mode, `innerSuccess = false` vẫn là một tx
**thành công** trên chuỗi. Odoo tuyệt đối không được suy ra trạng thái nghiệp vụ từ `receipt.status`.
Sự thật nghiệp vụ là `MetaTransactionExecuted.innerSuccess == true` **và** đã qua Finality Gate.
State machine của `blockchain.metatx`:

```
draft -> signed -> simulated -> published -> claimed -> broadcast -> mined -> finalized -> done
   └-> expired    (hết expiry trước khi mined; nonce KHÔNG tiêu; được ký lại cùng lane+nonce)
   └-> superseded (bumpBatchNonce hoặc lane_epoch++ đã bỏ lane này)
```

**[BẢN 3] Nhánh `reverted` biến mất khỏi máy trạng thái.** Bản 1 có nó vì swallow mode: một tx
`mined` thành công mà thao tác bên trong fail (`innerSuccess = false`). Sau §04.6.2 trạng thái đó không
biểu diễn được — op fail thì cả tx revert, nên không có gì để `mine`. Một tx đã lên chuỗi nghĩa là thao
tác **đã xảy ra**.

`done` là điểm duy nhất được phép gọi `_set_done()` phía payment/settlement consumer, và `mined` **không
phải** `done` — khoảng giữa là Finality Gate (§11.3). Nếu indexer thấy một `MetaTransactionExecuted` mà
sổ không có settlement tương ứng, đó là `unattributed_chain` của §15.5.3, không phải một `reverted`.

---

### 04.11. Chain profile: public vs private đổi mặc định gì

Trục `chain_profile` (quyết định khoá số 5) không phải một cờ cấu hình lẻ — nó đổi mặc định của
gần như mọi tham số trong section này. Bảng này là cấu hình khởi tạo của `blockchain.chain`:

| Tham số | `chain_profile = 'public'` | `chain_profile = 'private'` | Lý do |
|---|---|---|---|
| `mode` mặc định | `MODE_OPEN` (0x00) cho logic, `+0x04` cho luồng tiền | **`MODE_RESTRICT_RELAYER \| MODE_REQUIRE_SUCCESS` (0x05)** | Chain private không có thị trường relayer; relayer là pool nội bộ đã biết. MODE_OPEN trên chain private là bề mặt tấn công không đổi lại được gì |
| `fee` mặc định | theo `fee_model` §05.3.4 | **0** | Gas được trợ cấp; thu phí token chỉ tạo công việc kế toán |
| ~~`feeToken`~~ | — | — | **Bỏ** (§04.1). Phí trả bằng chính token |
| ~~Target allowlist~~ | — | — | **Bỏ**. Không có `to` tuỳ ý để allowlist |
| `expiry` Zether | 60s | **300s** | Không có mempool công khai, không có free-option risk, không đua relayer |
| ~~`innerGasLimit` Zether~~ | — | — | **Bỏ** (§04.1). Relayer tra bảng gas tĩnh theo selector |
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
    """Trả gas ước tính theo selector (bảng §04.10), fee đề xuất, validUntil. Read-only, không ký.
    [BẢN 3] KHÔNG còn trả innerGasLimit/requiredOuterGas — hai thứ đó không còn tồn tại."""

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
| 1 | `metatx_v1.json`: ≥ 24 vector (mỗi tổ hợp cờ × ba giá trị nửa byte phí × `data` rỗng/dài × `relayer` wildcard/cụ thể × `validUntil` biên) cho ra digest khớp giữa `eip1776.py` và `hashStruct`, **và quy tắc `canon` khớp cả ba nơi** | pytest + `forge script` trên anvil | Client và contract không cùng một digest ⇒ 100% chữ ký fail |
| 2 | Fuzz `uint32 mode`: bit ngoài `MODE_KNOWN_MASK` ⇒ `ModeUnknownBits`; nửa byte phí > 2 ⇒ `ModeFeeInvalid`. Cả hai **ở bước 3, trước khi verify chữ ký** | foundry fuzz 50k run | Bit lạ hoặc giá trị lạ được chấp nhận ⇒ ngữ nghĩa tương lai bị khoá bởi chữ ký đã phát hành; verify chữ ký trước là 3k gas cho rác |
| 3 | Cross-mode: chữ ký MODE_OPEN không verify được khi submit với `mode = 0x01` và ngược lại | foundry | Cross-mode replay |
| 4 | Malleability: `(v, r, n-s)` bị reject | foundry | Dedupe theo chữ ký sai |
| 5 | Return-bomb: target trả 1 MB ⇒ tx dùng < 300k gas tổng | foundry, đo `gasleft()` | Gas griefing |
| 6 | Gas griefing: relayer đặt outer gas = `requiredOuterGas - 1` ⇒ revert `GAS_TOO_LOW`, **nonce không tăng** | foundry | Lỗ GSN v1 |
| 7 | **Injectivity:** hai `(op, args)` khác nhau **không bao giờ** cho cùng digest; đặc biệt `args` rỗng vs `args` toàn 0 | `halmos` `check_digest_injective` | Bỏ `keccak256(args)` là hai intent chung một chữ ký |
| 8 | **Phí ⟺ thao tác:** mọi đường làm thao tác fail đều làm `metaNonce` KHÔNG tăng và phí KHÔNG thu | foundry, một case cho chuyển công khai và một cho Zether | Bất biến trung tâm của §04.6.2 |
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
3. **§03.5 `accSeq` + nhánh `OWNER_ONLY` có được reviewer mật mã chấp nhận không.** (**[BẢN 5, 2026-09-03]** phạm vi câu hỏi đổi: mặc định đã là `PUBLIC`, gần paper FC 2020 hơn.) Nếu không, `expiry`
   Zether tụt về ≤ 1 epoch, `targetEpoch` quay lại struct `EncryptedTransfer`, và tỷ lệ revert do
   trôi epoch trở thành một bài toán phải giải. Hai thứ này đi cùng nhau và cả hai đều nằm trong
   `expiry` — nên envelope không đổi struct, chỉ đổi hằng số. Đó là lý do không nên đưa
   `targetEpoch` vào `MetaTransaction`.

---

## 04.15. Cập Nhật Chuẩn Tắc V3: Phân Hóa Hai Luồng MetaTx & Linh Hoạt Chi Trả Phí

*(Chi tiết đầy đủ xem `SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md` §2 và `ai-enterprise-blockchain-architecture.md` §4.8–§4.9)*

### 04.15.1. Hai Luồng Thực Thi Meta-Transaction Tối Ưu
1. **Luồng 1: Fast-Path Token Functions (`mtxPay`, `transferConfidential`, `fund`, `burn`):**
   - Nhận trực tiếp các tham số có kiểu rõ ràng (typed arguments), không bọc dynamic calldata.
   - Tiết kiệm ~4,200 gas do không tốn phí giải mã ABI decode động trong EVM.
   - Hàm `mtxPay` nhận `bytes32 payId` và phát sự kiện `Payment(sender, recipient, amount, feeAmount, feeRecipient, payId)` cho phép ERP Odoo tự động gạch nợ hóa đơn `account.move` tức thì (1-1 reconciliation).
2. **Luồng 2: Generic Calldata Execution (`executeMetaTransaction`):**
   - Nhận `bytes calldata data` cho các tương tác tùy ý composable (bỏ phiếu DAO, nộp cọc thầu kín sealed-bid, tương tác DEX). Tốn thêm 4.2k–8k gas decode calldata.

### 04.15.2. Tính Linh Hoạt Chi Trả Phí Relayer
1. **Bên Nhận Trả Phí (`feePaidByRecipient = true`):**
   - Người gửi chuyển chính xác $N$ token theo hợp đồng thương mại; Relayer thu phí $F$ token từ số tiền chuyển; Người nhận nhận thực tế $N - F$ token. Người gửi không phải tự tính cộng dồn phí vào lệnh chuyển.
2. **Chính Sách Trợ Cấp Phí Gas Inbound Của Doanh Nghiệp (Inbound BaaS Gas Subsidy):**
   - Doanh nghiệp vận hành Relayer tài trợ 100% gas (`fee = 0`) cho các giao dịch chuyển tiền B2B inbound vào ví của doanh nghiệp nếu giá trị giao dịch vượt ngưỡng tối thiểu (ví dụ: $\text{amount} \ge 10 \text{ USD}$).

### 04.15.3. Mô Hình Bên Nhận Tự Làm Relayer (Recipient Self-Relaying / P2P Direct Settlement)
- **Bản chất:** Trong giao dịch P2P giữa hai cá nhân hoặc hai đối tác (A chuyển token cho B), Bên gửi A ký EIP-712 offline với `feeAmount = 0` (hoặc `FEE_MODE_NONE`) và `relayer = address(0)` (wildcard relayer).
- **Thực thi:** Bản ký được gửi trực tiếp cho B (qua QR code, BLE, chat P2P). Bên nhận B dùng chính ví của mình nộp transaction lên chuỗi (`msg.sender == B`) gọi `mtxPay(...)` và tự trả native gas cho mạng lưới.
- **Kết quả:** B nhận trọn vẹn $N$ token, không mất phí token, không phụ thuộc vào bất kỳ hạ tầng Open Relayer nào của bên thứ ba, kháng kiểm duyệt và bảo mật tuyệt đối.

### 04.15.4. Chuẩn Hóa API Direct Inbound Đa Chuỗi & Đa Hợp Đồng (Enterprise Multi-Chain Inbound API)
- **Chuẩn hóa Endpoint Inbound:** Doanh nghiệp công khai API `POST /api/v1/blockchain/inbound-meta-tx` (hoặc `/api/v1/blockchain/{chainId}/inbound-meta-tx`) tiếp nhận payload ký EIP-712 trực tiếp, yêu cầu khai báo rõ `chainId` và `tokenContract`.
- **Ràng buộc EIP-712 Domain Separator:** Mỗi cặp `(chainId, tokenContract)` sở hữu một `DOMAIN_SEPARATOR` riêng biệt. Chữ ký ký trên một chuỗi EVM (ví dụ Gnosis `chainId: 100`) bị cấm tuyệt đối và không thể phát lại trên chuỗi EVM khác (ví dụ Celo `chainId: 42220` hoặc Chain 9000).
- **Hàng Đợi Gom Lô Phân Vùng:** Hàng đợi gom lô chia tách theo `(chainId, tokenContract)` để bảo đảm tính nguyên tử của phương thức `tokenContract.batchMtxPay(payments[])`. Worker rút ví hot từ `KeyPool(chainId)` để thanh toán native gas, tiết kiệm 40%–60% gas và tự động gạch nợ đa sổ kế toán ERP sau finality.

### 04.15.5. Chuẩn Hóa Endpoint URL & Adapters Cho Hệ Sinh Thái Non-EVM (SUI, TON, HBAR, Soroban, Cosmos)
- **Cấu trúc URL chuẩn:** `POST /api/v1/blockchain/{ecosystem}/{network_or_chain_id}/inbound-{tx_type}`
- **SUI Network:** `POST /api/v1/blockchain/sui/{network}/inbound-sponsored-tx` (Move PTB Base64 BCS `txBytes` + `userSignature`, pre-flight `sui_devInspectTransactionBlock`, nạp gas object từ `KeyPool(sui)`).
- **TON Network:** `POST /api/v1/blockchain/ton/{network}/inbound-boc` (Bag-of-Cells `boc`, parsing Cell tree, trích xuất `payId` 32-byte forward payload, nạp gas nanoTON từ `KeyPool(ton)` và nộp `sendBoc`).
- **Unified Smart Router:** `POST /api/v1/blockchain/inbound-tx` với headers `X-Ecosystem` và `X-Network`.

