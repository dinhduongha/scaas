> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 02. Singleton Account Registry và các sơ đồ chữ ký

### 2.0. Kết luận trước, lý luận sau

| Quyết định | Chọn | Lý do một dòng |
|---|---|---|
| Identity | `bytes32 schnorrAddress = keccak256(abi.encode(pkX, pkY))`, chỉ dẫn xuất từ **encryption key** | Chain-independent, không đổi khi xoay auth key |
| Truyền tham số | Truyền `(pkX, pkY)` trong calldata, **KHÔNG truyền `bytes32 addr`** — contract tự `keccak256` | Hash 36 gas rẻ hơn 32 bytes calldata 512 gas; bản nháp trước truyền cả hai là thừa |
| Registry | 1 Singleton **non-upgradeable** cho mỗi Zether Token trên một chain, có con trỏ `successor`, **tối đa 2 thế hệ** | Tránh proxy-governance trên component mà toàn hệ sinh thái phụ thuộc |
| Tách khoá | `encKey` (G1 của curve token, bất biến) **tách rời** `authKey` (pluggable scheme) | Zether math bắt buộc encKey là G1; mọi sơ đồ chữ ký khác chỉ là lớp uỷ quyền |
| **Token BẮT BUỘC gọi `assertAuthorized`** | Không phải tuỳ chọn | Nếu không, lớp authKey chỉ là trang trí: biết `x` là đủ chi tiêu. Xem §2.4.2 — đây là lỗ hổng lớn nhất của bản nháp trước |
| Multisig mặc định | k-of-n ECDSA qua `ecrecover` (3.000 gas/chữ ký + ~1.040 calldata) | Nhàm chán, rẻ, không crypto mới |
| Threshold Schnorr | **FROST** (t-of-n), **không phải MuSig2** (n-of-n) | Bản nháp trước lẫn hai khái niệm. MuSig2 chỉ dùng khi thật sự cần n-of-n |
| BLS | BLS12-381 (EIP-2537) biến thể **min-signature-size** (sig∈G1, pk∈G2), probe runtime | Hash-to-G1 rẻ hơn hash-to-G2 ~37k gas/verify. **[ĐO 2026-08-31 trên chain 9000]** pairing k=2 = **103.959** gas, verify min-sig đầy đủ ≈ **120k** — khớp ước tính ~118k ở §2.5.2. Và pairing BLS12-381 **rẻ hơn** pairing bn254 (114.091), nên `BLS_BN254` mất luôn lý do tồn tại trừ khi chain không có EIP-2537 |
| FALCON on-chain | **Không triển khai được hôm nay**, nhưng **không phải vì tiền** | Ước tính sửa lại: ~0,6M–2,5M gas (bản nháp trước nói 2M–10M, **quá cao**). Trên Gnosis đó là ~$0,003. Rào cản thật: không có verifier được audit + DoS surface, không phải chi phí |
| PQ thực dụng nếu bắt buộc on-chain | **SLH-DSA-SHA2-128s** (~0,4–0,8M gas, dùng precompile SHA-256 `0x02`) | Bản nháp trước bỏ qua hoàn toàn. Hash-only, không cần NTT, không cần SHAKE trong Solidity |
| PQ mặc định | Commitment on-chain + verify off-chain; native precompile trên **private chain** trước | Đúng quyết định khoá số 5 |
| Cross-chain | Đăng ký **per-chain** (rẻ, không trust), trạng thái freeze/revoke **attestation k-of-n ECDSA** | 32 bytes state monotonic không đáng đánh đổi một bridge |
| Custody của `encKey` | **Không thể nằm trong HSM FIPS 140-2 L3 tiêu chuẩn** — alt_bn128 không được hỗ trợ | Xem §2.4.4. Đây là mâu thuẫn trực tiếp với `blockchain.md` §10.3.1 và phải giải quyết ở cấp hợp đồng |
| Không xây | Bridge (CCIP/LayerZero), upgradeable registry, global admin freeze trên public chain, point compression | YAGNI + vector tập trung hoá |

**Ghi chú về curve, thêm sau khi chốt factory mở.** Bản trước viết `encKey` là "alt_bn128 G1" như một hằng số của hệ thống. Nó không còn là hằng số: một token chọn verifier nào thì `encKey` nằm trên curve của verifier đó (`_USER-DECISIONS.md` §20.1). Hệ quả cụ thể và phải nhớ: **một người có `encKey` riêng cho mỗi curve**, nên `schnorrAddress` của họ trên một token bn254 khác `schnorrAddress` trên một token BLS12-381. Đó là hai danh tính, không phải một danh tính hai cách viết, và ví không được gộp chúng. Registry vì thế là **per (chain, curve)**, không chỉ per-chain.

**Những gì bản nháp trước nói sai và đã sửa ở bản này** (chi tiết ở từng mục):

| # | Bản nháp trước | Sửa |
|---|---|---|
| 1 | Pack `status` vào 2 bit cao của `pkY` | **Chỉ còn 2 bit tự do** (`p` = 254 bit) nhưng có **5 trạng thái** → không vừa. Chuyển sang slot `meta` riêng (§2.1.4) |
| 2 | Truyền cả `addr` lẫn `(pkX, pkY)` | Thừa 512 gas/tham số. Chỉ truyền point, dẫn xuất addr on-chain (§2.1.3) |
| 3 | "Hash identity đắt hơn ~9.500 gas" | Quy sai nguyên nhân: phần lớn 9.500 gas đó là **chi phí tra cứu registry**, phải trả dù định danh là gì (§2.1.2) |
| 4 | `MUSIG2` cho MPC threshold | MuSig2 là n-of-n. MPC t-of-n là **FROST** (§2.4.3) |
| 5 | BLS12-381 verify ~150.000 gas với 1× `MAP_FP2_TO_G2` | hash_to_curve cần **2×** map + 1 add. Biến thể min-pubkey ~155k; biến thể **min-sig ~118k** — nên chọn biến thể min-sig (§2.5.2) |
| 6 | FALCON verify 2M–10M gas | Đếm lại thao tác: ~0,6M–2,5M. Kết luận không đổi nhưng **lý do đổi** (§2.6.3) |
| 7 | `REVOKED` chặn cả inflow | Mâu thuẫn với chính lý lẽ đã dùng để biện minh cho `FROZEN` cho inflow. **Mọi trạng thái đều cho inflow** (§2.7.3) |
| 8 | `cancelAuthRotation` bởi guardian | Guardian độc hại huỷ vĩnh viễn mọi lần xoay = DoS. Cần có đường ép buộc (§2.7.1) |
| 9 | "EIP-7623 không bao giờ bind" | Bind khi `execution_gas < 24 × non_zero_bytes`. Với chữ ký PQ 7.856 bytes ngưỡng là 188.544 gas — **bind thật** (§2.1.1, §2.6.4) |
| 10 | Không nói gì về non-EVM | TON là actor model bất đồng bộ → **không thể gọi registry đồng bộ**; toàn bộ mô hình `require(isRegistered)` sụp đổ (§2.9) |

---

### 2.1. Định danh `bytes32` bằng hash: được gì, mất gì

Note gốc (`blockchain.md` §10.5.3, Nguyên Tắc 1) khẳng định hash identity "tối ưu hoá calldata **và chi phí gas lưu trữ on-chain**". Về calldata thì đúng; về tổng gas thì **sai dấu**, và cần nói rõ vì nó đổi lại kiến trúc.

#### 2.1.1. Tính toán calldata (và khi nào EIP-7623 thật sự bind)

Post-EIP-2028: 16 gas/non-zero byte, 4 gas/zero byte. Truyền `(pkX, pkY)` trực tiếp = 64 bytes thay vì 32 bytes → chênh tối đa 32 × 16 = **512 gas/tham số**. Một `transferConfidential` có 2 tham số (`from`, `to`) → **~1.024 gas**.

Bản nháp trước nói "EIP-7623 không bao giờ bind". **Sai** — nó bind theo một công thức cụ thể, và công thức đó quan trọng ở §2.6. EIP-7623 (Pectra, 2025-05-07):

```
tokens        = zero_bytes × 1 + non_zero_bytes × 4
cost_standard = 21_000 + 4 × tokens + execution_gas
cost_floor    = 21_000 + 10 × tokens
tx_cost       = max(cost_standard, cost_floor)

=> floor BIND khi:  execution_gas < 6 × tokens = 24 × non_zero_bytes (bo qua zero byte)
```

| Payload | non-zero bytes | Ngưỡng `execution_gas` để floor bind |
|---|---|---|
| 2 G1 point bn254 (128 B) | 128 | 3.072 |
| 2 G1 point BLS12-381 (256 B) | 256 | 6.144 |
| `register()` calldata (~200 B) | 200 | 4.800 |
| Chữ ký FALCON-512 (666 B) | 666 | 15.984 |
| Chữ ký ML-DSA-65 (3.309 B) | 3.309 | 79.416 |
| Chữ ký SLH-DSA-128s (7.856 B) | 7.856 | **188.544** |

Với giao dịch Zether (~200k–250k gas execution) floor không bind → giữ 16 gas/byte. Với một giao dịch **chỉ neo commitment PQ** (execution ~30k) và chữ ký PQ lớn, floor **bind** và chi phí calldata thực tế là **40 gas/byte**, không phải 16. Ghi con số này vào bảng chi phí của §2.6.

Dòng thứ hai của bảng là dòng mới: điểm G1 của BLS12-381 là 128 byte chứ không phải 64 (EIP-2537 pad mỗi Fp thành 64 byte), nên một token chọn curve đó trả gấp đôi calldata cho cùng một định danh. Đó là một chi phí thật của việc chọn curve mà bảng gas của verifier không hiện ra.

#### 2.1.2. Tính toán chi phí đọc lại — và quy đúng nguyên nhân

Zether **bắt buộc** cần điểm `y` thật (không phải hash) để kiểm tra sigma protocol: ciphertext `(C, D) = (g^v · y^s, g^s)` chỉ verify được khi contract có `y` dưới dạng G1 point để đưa vào `ecMul`. Với hash identity thuần tuý (registry giữ point, token đọc về):

| Thao tác | Gas |
|---|---|
| `CALL` sang registry, lần đầu (cold account access, EIP-2929) | 2.600 |
| 2 × cold `SLOAD` cho `(pkX, pkY)` của `from` | 4.200 |
| 2 × cold `SLOAD` cho `(pkX, pkY)` của `to` | 4.200 |
| `CALL` thứ hai (warm account) nếu không gộp | 100 |
| Calldata/return/memory overhead của external call | ~600 |
| **Tổng** | **~11.700 gas** |
Bản nháp trước kết luận "hash identity đắt hơn ~9.500 gas/transfer". **Quy sai nguyên nhân.** Tách ra:

| Thành phần | Gas | Có tránh được không? |
|---|---|---|
| Tra cứu **trạng thái** tài khoản (registered? frozen?) | ~2.600 + 2 × 2.100 = 6.800 | **Không.** Bất kỳ registry nào cũng trả, dù định danh là hash hay là point. Note gốc bắt buộc `require(registry.isRegistered(from) && registry.isRegistered(to))` |
| Đọc **point** từ storage thay vì calldata | +4.200 | **Có** — bằng cách truyền point trong calldata |
| Tiết kiệm calldata do dùng hash | −1.024 | — |
| **Chi phí ròng thật sự của hash identity** | **+3.176** | Không phải 9.500 |

Nghĩa là: 6.800 gas trong con số 9.500 là **giá của mô hình Shared Registry**, không phải giá của hash identity. Nếu ai đó đọc bản nháp trước và kết luận "bỏ hash identity đi, tiết kiệm 9.500 gas" thì họ sẽ thất vọng: bỏ hash identity chỉ tiết kiệm 3.176 gas, và làm mất tính chain-independent (§2.1.6, điểm 4).


#### 2.1.3. Giải pháp: **không truyền `addr`**, dẫn xuất on-chain

Bản nháp trước đề xuất "caller truyền cả hai: `bytes32 addr` và `(pkX, pkY)`". Thừa. `keccak256(abi.encode(pkX, pkY))` tốn **30 + 6×2 = 42 gas** (KECCAK256 = 30 + 6/word); truyền thêm 32 bytes tốn **512 gas**. Chỉ truyền point:

```solidity
function transferConfidential(
    uint256 fromPkX, uint256 fromPkY,
    uint256 toPkX,   uint256 toPkY,
    EncryptedTransfer calldata data,
    bytes calldata authSig
) external returns (bool);
// addr duoc dan xuat: bytes32 from = keccak256(abi.encode(fromPkX, fromPkY));
```

Chi phí hot path sau khi sửa:

| Thao tác | Gas |
|---|---|
| Calldata 4 × 32 bytes cho 2 point | 2.048 |
| 2 × `keccak256` dẫn xuất addr | 84 |
| 1 × `CALL` gộp sang registry (`assertUsable(from, to)`) | 2.600 |
| 2 × cold `SLOAD` slot `meta` (1 slot/account) | 4.200 |
| Overhead call | ~400 |
| **Tổng** | **~9.300 gas** |

So với 11.700 của thiết kế đọc-point-từ-storage: tiết kiệm **~2.400 gas/transfer**. Trên Gnosis @2 gwei ≈ $0,0000048/tx — không đáng kể; trên Ethereum L1 @10 gwei/ETH $3.000 ≈ $0,072/tx — đáng kể ở quy mô 10^5 tx/tháng ($7.200/năm). **Ước tính, cơ sở: bảng giá EIP-2929 / EIP-2028 / EIP-1108.**

Lưu ý cho token dùng BLS12-381: dòng calldata đầu bảng thành **4.096 gas** thay vì 2.048, vì mỗi điểm là 128 byte. Khoản tiết kiệm của mục này không đổi, nhưng nền thì cao hơn.

**Hàm gộp `assertUsable` (một CALL cho cả hai tài khoản)** — bản nháp trước để hai lần gọi:

```solidity
/// @notice Kiem tra ca hai tai khoan trong MOT call. Revert voi ly do phan biet duoc.
/// @dev Khong revert khi tai khoan `to` o trang thai FROZEN/REVOKED: moi trang thai deu nhan duoc (§2.7.3).
function assertUsable(bytes32 from, bytes32 to) external view;
```

#### 2.1.4. Bố trí slot — **sửa một bug thật trong bản nháp trước**

Bản nháp trước đề xuất pack `status` vào 2 bit cao của `pkY` vì `p < 2^254`. Kiểm chứng:

```
p     = 21888242871839275222246405745257275088696311157297823662689037894645226208583
p.bit_length() = 254  =>  chi con 2 bit tu do (bit 254, 255)  =>  toi da 4 gia tri
```

Nhưng §2.7 của chính bản nháp trước định nghĩa **5 trạng thái** (`NONE, ACTIVE, FROZEN, REVOKED, MIGRATED`). **Không vừa.** Và ngay cả khi vừa, mỗi lần đọc status phải `AND` mask rồi shift, và mỗi lần ghi status phải đọc-sửa-ghi cả `pkY` — nguy hiểm.

Thủ thuật này còn hỏng theo một cách thứ hai mà bản trước không thấy: **nó phụ thuộc vào curve.** `p` của bn254 là 254 bit nên còn 2 bit; `p` của BLS12-381 là **381 bit**, không vừa một `uint256` nào cả, nên toạ độ phải nằm trên hai word và không có "bit cao tự do" theo nghĩa đó. Một thiết kế storage chỉ đúng cho một curve là thiết kế sai trên một factory hỗ trợ nhiều curve.

Bố trí đúng: gộp toàn bộ metadata **nóng** vào một slot riêng, để hot path chỉ chạm `pkX`/`pkY` khi thật sự cần (mà sau §2.1.3 thì không bao giờ cần):

```solidity
// 4 slot / account voi bn254. Hot path chi doc slot 2.
struct Account {
    uint256 pkX;          // slot 0 — encKey.x, BAT BIEN suot doi tai khoan
    uint256 pkY;          // slot 1 — encKey.y, BAT BIEN
    uint256 meta;         // slot 2 — packed, xem duoi. 240/256 bit dung.
    bytes32 authKeyHash;  // slot 3 — 0 neu authScheme == SELF_SCHNORR
}
// meta layout (little-end -> big-end):
//   [  0.. 7]  uint8   status        NONE|ACTIVE|FROZEN|REVOKED|MIGRATED   (con cho 251 gia tri)
//   [  8..15]  uint8   authScheme
//   [ 16..79]  uint64  authEpoch
//   [ 80..239] address verifier
//   [240..255] uint16  reserved       (khong dung; giu de mo rong khong doi layout)
mapping(bytes32 => Account) internal _accounts;
```

Kiểm chứng độ rộng: `8 + 8 + 64 + 160 = 240 ≤ 256`. Còn 16 bit dự trữ.

Với BLS12-381, `pkX`/`pkY` mỗi cái chiếm **hai** slot thay vì một, nên `Account` là 6 slot chứ không phải 4. Slot `meta` và `authKeyHash` không đổi — đó chính là lợi ích của việc tách metadata ra khỏi toạ độ: **layout của phần nóng độc lập với curve**, và chỉ phần lạnh thay đổi.

Hậu quả chi phí (bn254):

| Thao tác | Trước (pack vào pkY) | Sau (slot `meta`) |
|---|---|---|
| Đọc status | 1 cold SLOAD + mask/shift ≈ 2.110 | 1 cold SLOAD + mask ≈ 2.105 |
| Ghi status (freeze) | SLOAD 2.100 + SSTORE-dirty 2.900 = 5.000, **rủi ro hỏng `pkY`** | SLOAD 2.100 + SSTORE-dirty 2.900 = 5.000, không chạm `pkY` |
| `register()` SSTORE | 2 slot × 22.100 | 3 slot × 22.100 = 66.300 (`authKeyHash` = 0 không ghi) |

`register()` đắt hơn 22.100 gas so với bản nháp trước, và bảng gas của §2.2 được sửa theo. Với BLS12-381 thì `register()` là 5 slot × 22.100 = 110.500.

#### 2.1.5. Nên dùng point compression không? **Không** — và đây là con số

`p ≡ 3 (mod 4)` nên `sqrt(a) = a^((p+1)/4)`, tính được bằng precompile `MODEXP` (`0x05`). Truyền `pkX` + 1 bit parity thay vì `(pkX, pkY)`:

| | Gas |
|---|---|
| Tiet kiem calldata (32 bytes) | −512 |
| `MODEXP` 32/32/32 byte (EIP-2565) | +~1,360 |
| `mulmod` kiem tra + chon nhanh parity | +~50 |
| **Rong** | **+898 gas — dat hon** |

**Quyết định: không nên. Luôn truyền `(pkX, pkY)` không nén.** Ghi vào doc để không ai "tối ưu" lại.

#### 2.1.6. Cái thật sự mất khi bỏ (x, y) khỏi định danh

1. **Không thể gửi cho người chưa đăng ký.** Trên Ethereum bạn gửi được cho bất kỳ 20 bytes nào. Ở đây `transferConfidential(...)` phải `revert` nếu `to` chưa đăng ký, vì không có `y_to` để mã hoá. Hệ quả nghiệp vụ: **onboarding là bước bắt buộc trước khi nhận tiền** — brand không thể settle cho một distributor mới cho đến khi distributor đó `register()`. Phải có luồng "invite + gasless register" (§2.3d) và, quan trọng hơn, **giao diện Odoo phải chặn từ trước** chứ không để revert on-chain: một `dms.trade.settlement` chỉ được phép confirm khi mọi payee có `blockchain.zether.account` ở trạng thái `active` trên đúng chain. Tinh thần "quét QR không phải là đã thu tiền": chặn ở tầng gần người dùng, chain là lớp cuối.
2. **Không verify offline được.** Auditor cầm một event log không thể tự kiểm chứng minh nếu không có state của registry tại block đó. Bắt buộc: indexer lưu snapshot `(schnorrAddress → pkX, pkY, blockNumber)` và gắn hash snapshot vào `ir.attachment` trên S3/Garage. **Sau khi áp dụng §2.1.3, vấn đề này tự biến mất một phần**: `(pkX, pkY)` nằm ngay trong calldata của tx nên log + tx là đủ để tái lập; snapshot chỉ còn cần cho `status`/`authEpoch`.
3. **Không có checksum kiểu EIP-55.** Gõ nhầm 1 ký tự → một `bytes32` hợp lệ về cú pháp. Nhưng **registry lại là bộ lọc gõ nhầm**: 32 bytes ngẫu nhiên gần chắc chắn chưa đăng ký → `revert`. Đây là thuộc tính an toàn **tốt hơn** địa chỉ EOA, phải ghi vào tài liệu vận hành. (Xác suất trúng một tài khoản đã đăng ký với 10^6 tài khoản: 10^6 / 2^256 ≈ 10^-71.)
4. **Lợi ích miễn phí:** `keccak256` không phụ thuộc chain → cùng `(pkX, pkY)` cho **cùng một `schnorrAddress` trên mọi EVM chain**. Lớp identity đã giải quyết xong cho cross-chain; chỉ còn lớp *trạng thái* (§2.8).

   Một điều kiện của mệnh đề này phải nói rõ, vì factory mở làm nó dễ hiểu sai: nó đúng **trong phạm vi một curve**. Cùng `(pkX, pkY)` cho cùng `schnorrAddress` trên mọi chain — nhưng một keypair bn254 và một keypair BLS12-381 là hai keypair khác nhau, nên một người dùng cả hai loại token có hai `schnorrAddress`.
5. **Chi phí ẩn: xung đột không gian tên với EIP-1271 / smart account.** `bytes32` không phải `address`, nên không thể dùng trực tiếp làm `msg.sender` hay làm owner. Mọi liên kết `bytes32 ↔ address` đều phải đi qua `authKeyHash` (§2.4). Chấp nhận; nhưng nghĩa là **không thể tái sử dụng thư viện access-control của OpenZeppelin** — tất cả phải viết tay và đó là bề mặt bug.

#### 2.1.7. Ba lỗi cụ thể trong interface của note, phải sửa trước khi code

| Vấn đề | Sửa |
|---|---|
| `struct SchnorrPublicKey { bytes32 x; bytes32 y; }` — trong chính tài liệu này `x` là **private key** và `y` là **public key point**. Trường `y` ở đây lại là *toạ độ y*. Sẽ sinh bug. | Đổi tên `pkX`, `pkY`. Cấm dùng ký tự `x`/`y` đơn lẻ trong Solidity của dự án. Thêm một lint rule trong CI (`slither`/`solhint` custom) chặn biến tên `x`, `y`, `X`, `Y` ở phạm vi file. |
| `abi.encodePacked(x, y)` | Dùng `abi.encode(pkX, pkY)`. Với 2 `bytes32` kết quả giống nhau, nhưng `encodePacked` dễ sinh collision khi ai đó thêm tham số động sau này. |
| Kiểu `bytes32` cho toạ độ | Đổi sang `uint256`. Toạ độ là số trong `F_p`, mọi phép kiểm tra đều là số học; `bytes32` buộc cast liên tục và che đi việc thiếu range check. |
| Không có validation ranh giới trường | `require(pkX < P && pkY < P)` với `P = 21888242871839275222246405745257275088696311157297823662689037894645226208583`, và `require(mulmod(pkY,pkY,P) == addmod(mulmod(mulmod(pkX,pkX,P),pkX,P), 3, P))` (on-curve `y² = x³ + 3`). Từ chối `(0,0)`. alt_bn128 G1 có cofactor = 1 nên **không cần** subgroup check trên G1 (cần trên G2 — liên quan BLS, §2.5.3). |
| `getPublicKey()` trả về `(x, y)` cho token đọc | Giữ làm hàm view cho indexer/SDK, nhưng **token không được dùng** (§2.1.3). Đánh dấu `/// @dev Off-chain use only. Do NOT call from a token hot path.` |

Hàng thứ tư có một điều kiện gắn với curve: `P`, phương trình `y² = x³ + 3`, và mệnh đề "cofactor = 1 nên không cần subgroup check" đều là **của bn254**. BLS12-381 G1 có `y² = x³ + 4` và **cofactor khác 1**, nên subgroup check trên G1 là **bắt buộc** ở đó. Validation phải nằm trong verifier của curve tương ứng, không phải hằng số hoá trong registry.

**Quy tắc bất biến:** `schnorrAddress` dẫn xuất **chỉ từ encKey**, không bao giờ nhúng scheme tag hay authKey vào hash. Nếu nhúng vào, xoay auth key sẽ đổi địa chỉ → mất toàn bộ số dư. Ghi thành comment `@dev INVARIANT` trên hàm dẫn xuất **và** thành một Foundry invariant test (§2.10, mục 8).

---

### 2.2. Proof-of-Possession trên `register()`

Note có tham số `schnorrSignature` nhưng không định nghĩa challenge. Phải định nghĩa, vì PoP chặn 4 lớp tấn công khác nhau:

1. **Rogue-key (nghiêm trọng nhất, và là lý do thật sự).** Trong bất kỳ sơ đồ tổng hợp khoá nào (MuSig2, FROST, BLS), kẻ tấn công chọn `pk_rogue = pk_victim^{-1} · g^a`. Khoá tổng hợp `pk_agg = pk_victim · pk_rogue = g^a` — kẻ tấn công ký một mình cho cả nhóm. PoP buộc nó phải biết dlog của `pk_rogue`, triệt tiêu tấn công. Registry **không biết** khoá nào sẽ được dùng trong aggregation nào, nên PoP phải **bắt buộc cho mọi khoá, không ngoại lệ**.
2. **Điểm không hợp lệ / unknown-dlog.** Điểm không trên đường cong làm `ecMul` revert (DoS mềm), hoặc tạo ciphertext không bao giờ giải mã được — một tài khoản "đen" nhận tiền vào và không ai rút ra được, kể cả chính chủ.
3. **Đăng ký khoá người khác (griefing).** Xem xử lý dưới.
4. **Cross-registry / cross-chain replay của chính PoP.**

#### 2.2.1. Challenge cụ thể (Schnorr trên G1 của curve token)

```
n = 21888242871839275222246405745257275088548364400416034343698204186575808495617   // group order bn254
R = g^k                     (k random, tu HSM/MPC DRBG, KHONG bao gio tai su dung)
c = keccak256(abi.encode(
        "ZETHER_POP_V1",    // domain tag
        block.chainid,      // chan cross-chain replay
        address(this),      // chan cross-registry replay (ke ca giua registry v1 va v2)
        pkX, pkY,
        Rx, Ry
    )) mod n
s = k + c * sk  (mod n)
```

**Domain tag phải mang cả curve.** `"ZETHER_POP_V1"` là đủ khi hệ thống chỉ có một curve; với hai curve thì hai registry khác nhau có thể nhận cùng một PoP nếu ai đó vô ý dùng lại. Thêm curve vào tag (`"ZETHER_POP_V1/bn254"`) hoặc — tốt hơn — thêm `proofSystemId()` của verifier vào `abi.encode`. `address(this)` đã chặn phần lớn trường hợp vì hai registry là hai địa chỉ, nhưng một domain tag nói đúng phạm vi của nó thì không dựa vào may mắn đó.

On-chain verify: `g^s == R + pk·c` (ký hiệu cộng tính) → 2 × `ecMul` (6.000 mỗi cái, EIP-1108) + 1 × `ecAdd` (150) = **12.150 gas** thuần precompile. Cộng overhead thực: 3 × `staticcall` (warm precompile ~100 mỗi cái) + memory expansion + copy ≈ **+700** → **~12.900 gas** thực tế. Bản nháp trước bỏ qua overhead này; sai lệch 6% nhưng phải ghi đúng vì bảng ước tính sẽ được đối chiếu với đo đạc thật (§2.10, mục 7).

`c mod n` phải làm **sau** keccak và phải kiểm `c != 0`; `s < n` và `R != O` phải kiểm tường minh — một `s ≥ n` hoặc `R = O` là đường tầm thường để giả mạo trong nhiều bản hiện thực cẩu thả.

#### 2.2.2. Quyết định gây tranh cãi — **KHÔNG đưa `msg.sender` vào challenge**

| | Bind `msg.sender` | Không bind (**chọn**) |
|---|---|---|
| Front-running `register()` | Kẻ tấn công copy PoP từ mempool, submit trước, chiếm quyền owner → **DoS thật sự** | Kẻ tấn công submit trước → kết quả là **đúng một bản ghi giống hệt** (cùng `(pkX,pkY)`, cùng addr, cùng `meta` khởi tạo). Vô hại. Kẻ tấn công còn **trả gas hộ**. |
| Gasless register qua EIP-1776 | Phải thêm relayer allowlist hoặc EIP-712 wrapper | Chạy ngay, bất kỳ relayer nào |
| Gán owner EOA | Trong `register()` | Tách sang `setGuardians()` riêng, xác thực bằng PoP thứ hai |

Vì vậy: **`register()` là thao tác đăng ký khoá thuần tuý, không sinh bất kỳ state nào dẫn xuất từ `msg.sender`.** Đây là điều kiện để "user không có native gas" hoạt động ngay từ bước đầu tiên — nếu không, toàn bộ câu chuyện Open Relayer gãy ở bước 0. Note không đề cập điều này.

**Tính vô hại này là mong manh và phải có CI bảo vệ.** Ngay khi ai đó thêm một trường lấy từ `msg.sender` (ví dụ `registrar`, `sponsor`, `guardianInit`), front-running trở thành chiếm quyền. Foundry invariant test bắt buộc (§2.10, mục 2): gọi `register()` với cùng PoP từ hai `msg.sender` khác nhau → so sánh **toàn bộ storage diff** phải giống hệt, không chỉ so sánh `isRegistered`.

#### 2.2.3. Idempotency: `register()` trên addr đã tồn tại

Bản nháp trước không nói. Hai lựa chọn, phải chọn:

| | No-op trả `true` | **Revert `AlreadyRegistered()`** (chọn) |
|---|---|---|
| Hai relayer cùng nhặt một intent | Cả hai thành công → cả hai đòi `fee` → **issuer trả 2 lần** | Kẻ thứ hai revert; theo EIP-1776 `fee` chỉ chuyển khi thực thi thành công → không mất tiền |
| Relayer simulation | Không phát hiện được lãng phí | `eth_estimateGas` revert → relayer bỏ intent trước khi broadcast, không tốn gas |
| Trải nghiệm SDK | Mơ hồ | Rõ ràng, và SDK đọc `statusOf` trước |

Chọn revert. **Nhưng** kết hợp với §2.2.2 nó tạo một cánh cửa griefing nhỏ: kẻ tấn công front-run `register()` của nạn nhân bằng đúng PoP đó → nạn nhân revert và **relayer của nạn nhân mất gas** (relayer đã broadcast). Đánh giá: thiệt hại = 1 lần gas thất bại (~24k gas ≈ $0,00005 trên Gnosis), kẻ tấn công trả ~82k gas để gây ra. **Kinh tế ngược dấu, bỏ qua.** Ghi vào threat model chứ không xây biện pháp.

#### 2.2.4. Chống spam / bảo vệ bể tài trợ — **thiếu hoàn toàn trong bản nháp trước**

`register()` mở, gasless, và được issuer tài trợ (§2.3d). Đó là một vòi tiền công khai.

| Thông số | Giá trị |
|---|---|
| Gas một `register()` | ~105.000 (bảng §2.2.5) |
| Chi phí trên Gnosis @2 gwei, xDAI $1 | **$0,00021** |
| Bể tài trợ $1.000 → số lần đăng ký rác | **~4,76 triệu** |
| State thêm vào chain | 4,76M × 3 slot × 32 B = **457 MB** |

457 MB state rác trên Gnosis là một sự cố vận hành cho toàn mạng, không chỉ cho ta. Và $1.000 là một bể tài trợ nhỏ. **Bắt buộc có gate.** Chọn:

```solidity
// Invite-based sponsorship: issuer ky EIP-712 mot lan, registry theo doi nonce da dung.
struct RegistrationInvite {
    bytes32 inviteId;      // ngau nhien, 1 lan
    bytes32 boundTo;       // 0 = bat ky addr; khac 0 = chi addr nay
    uint64  expiry;
    uint32  maxUses;
}
mapping(bytes32 => uint32) public inviteUses;   // inviteId -> so lan da dung
```

Gate này **không** nằm trong `register()` (giữ `register()` thuần tuý theo §2.2.2) mà nằm trong **`IRegistrationPolicy`** (§2.3c) — `OpenRegistrationPolicy` là no-op cho public chain không tài trợ, `InviteRegistrationPolicy` cho luồng onboarding tài trợ, `AttestedRegistrationPolicy` cho private chain. Chi phí thêm: 1 × cold SLOAD + 1 × SSTORE-dirty + 1 × `ecrecover` ≈ 2.100 + 2.900 + 3.000 = **8.000 gas**.

Lớp bảo vệ thứ hai nằm ở relayer/gateway chứ không ở chain: **rate limit theo issuer-sponsored intent** (xem section 05/06, và `_USER-DECISIONS.md` §21 về acceptance policy). Một lớp on-chain + một lớp off-chain, vì lớp off-chain có thể bị vòng qua nếu ai đó tự trả gas — nhưng nếu họ tự trả gas thì họ tự chịu chi phí và không còn là vấn đề kinh tế của ta, chỉ còn là vấn đề state growth của chain.

#### 2.2.5. Ước tính gas `register()` (cơ sở: bảng giá EIP-1108 + EIP-2929 + EIP-2028)

| Mục | Gas |
|---|---|
| Base tx | 21.000 |
| Calldata ~200 non-zero bytes (2 point + 2 scalar + selector) | 3.200 |
| On-curve + range check (`mulmod` × 4, `addmod`) | ~250 |
| Schnorr PoP verify (12.150 precompile + ~700 overhead) | 12.850 |
| Policy check (`OpenRegistrationPolicy` = no-op) | ~250 |
| 3 × SSTORE (0 → non-zero): `pkX`, `pkY`, `meta` | 66.300 |
| Event `AccountRegistered` (3 topic + 64 B data) | ~1.900 |
| **Tổng** | **~105.750** |

Con số này là của **bn254**. Trên BLS12-381: calldata gấp đôi (+3.200), storage 5 slot thay vì 3 (+44.200), và PoP verify dùng `0x0b`/`0x0c` với giá khác. Tổng rơi vào khoảng **~160.000**. Không đổi kết luận nào ở dưới, nhưng phải ghi ra để bảng chi phí không bị dùng nhầm curve.

Chi phí thực:

| Chain | Giá gas | Native | USD/register |
|---|---|---|---|
| Gnosis xDAI | 2 gwei | xDAI ≈ $1 | **$0,00021** |
| Celo (L2 OP Stack, phí cUSD) | ~0,01 gwei L2 + L1 data | cUSD ≈ $1 | **~$0,0001** (ước tính; L1 data cost biến động) |
| Ethereum L1 | 10 gwei | ETH $3.000 | **$3,17** |
| Private chain 9000 (`MinGasPrice = 0`) | 0 | — | **$0** |

**Kết luận: đăng ký lại trên từng chain là rẻ đến mức không đáng thiết kế bridge** (§2.8). Với 5.000 tài khoản × 4 chain = 20.000 lần đăng ký = **$4,20** trên Gnosis. Con số này một mình nó đã quyết định xong §2.8.

#### 2.2.6. Interface `register()` đầy đủ

```solidity
/// @notice Dang ky mot encKey moi. Khong doc msg.sender. Idempotent-fail.
/// @param pkX,pkY  Toa do encKey tren G1 cua curve ma registry nay phuc vu.
/// @param popRx,popRy,popS  Chu ky Schnorr PoP theo challenge o §2.2.1.
/// @param policyAux  Du lieu cho IRegistrationPolicy (invite, attestation, hoac rong).
/// @return addr keccak256(abi.encode(pkX, pkY))
function register(
    uint256 pkX, uint256 pkY,
    uint256 popRx, uint256 popRy, uint256 popS,
    bytes calldata policyAux
) external returns (bytes32 addr);

error AlreadyRegistered(bytes32 addr);
error NotOnCurve();
error FieldOverflow();
error BadProofOfPossession();
error PolicyRejected(bytes reason);

event AccountRegistered(
    bytes32 indexed addr,
    uint256 pkX, uint256 pkY,       // KHONG indexed: indexer can gia tri, khong can filter
    uint8   indexed authScheme,
    uint64  registeredAtBlock
);
```

Chữ ký hàm này gắn với toạ độ một-word, nên nó là chữ ký của registry **bn254**. Registry BLS12-381 nhận `bytes calldata encodedPk` thay cho `(pkX, pkY)` — cùng lý do và cùng cách giải như ở `IZetherToken` (`_USER-DECISIONS.md` §20.1). Hai registry, hai ABI, cùng một mô hình.

---

### 2.3. Singleton vs ZSC nguyên khối của ConsenSys

Trong `anonymous-zether`, `ZSC.sol` gộp token + registry: `register(G1Point y, uint c, uint s)` nằm ngay trong contract token. N token → N lần đăng ký, N bản sao khoá. Singleton sửa đúng vấn đề. Nhưng nó **để lại 6 hậu quả mà note không xử lý**:

**(a) Single point of failure về governance.** Mọi token phụ thuộc một contract. Nếu registry là UUPS proxy (note §10.2.1 bắt buộc UUPS cho *mọi* contract), thì một admin key duy nhất có thể đổi `getPublicKey()` → đổi `y` của nạn nhân → mọi khoản tiền chuyển đến sau đó bị mã hoá dưới khoá kẻ tấn công, **và nạn nhân không thể phát hiện từ client của mình** vì họ vẫn thấy giao dịch thành công. Đây là vụ trộm hoàn hảo. **Quyết định: registry KHÔNG upgradeable.**

Bản trước gọi đây là "ngoại lệ duy nhất cho quy tắc UUPS của note". **Nó không còn là ngoại lệ** — §01.1.3 đã bỏ upgrade cho toàn bộ hệ, nên registry chỉ đang tuân theo quy tắc chung. Điều đáng giữ lại là lập luận: nó được kết luận **độc lập, từ mô hình đe doạ của chính nó**, trước khi có quyết định chung. Hai đường suy luận khác nhau đi tới cùng một chỗ là bằng chứng tốt hơn một đường.

Migration bằng con trỏ thế hệ:
```solidity
address public immutable predecessor;   // 0 neu la v1
address public successor;               // set 1 lan, boi governance timelock 30 ngay
uint8   public immutable generation;    // v1 = 1; require(generation <= 2)

function resolve(bytes32 addr) external view returns (Account memory);
// resolve() doc local truoc; neu status == NONE va predecessor != 0 -> doc predecessor.
```

**Giới hạn 2 thế hệ, cứng.** Bản nháp trước không đặt giới hạn. Chi phí mỗi hộp fallback = 2.600 (cold CALL) + 2.100 (cold SLOAD) + overhead ≈ **5.000 gas**. Với 4 thế hệ, hot path thêm 15.000 gas và trở thành không xác định (phụ thuộc tài khoản đăng ký đời nào). `require(generation <= 2)` trong constructor; trước khi deploy v3, phải chạy **migration sweep**: một hàm `bulkImport(bytes32[] addrs)` permissionless đọc từ predecessor và ghi vào local (chi phí ~25.000 gas/account, 5.000 account = 125M gas ≈ $0,25 trên Gnosis). Sau sweep, set `predecessor = 0` không được (immutable) — thay vào đó đặt cờ `sweepComplete` để `resolve()` bỏ qua fallback.

**(b) Linkability chéo token.** Một `schnorrAddress` dùng cho Z-USDC + Z-VND + Z-Loyalty → mọi hoạt động của pháp nhân đó liên kết được. Với triết lý "lộ danh tính, ẩn số tiền" thì đây là **chấp nhận được theo thiết kế**, nhưng phải có lối thoát: registry **không được** ép 1 khoá/pháp nhân. Một legal entity đăng ký N `schnorrAddress` cho N mục đích (treasury, payroll, loyalty, settlement với từng distributor). Mapping entity → tập địa chỉ nằm **off-chain trong Odoo**, không lên chain.

Con số để định liệu: nếu một brand có 200 distributor và muốn một địa chỉ settlement riêng cho từng distributor, đó là 200 lần `register()` = **$0,042** trên Gnosis. Chi phí không phải rào cản; **quản lý khoá là rào cản** — 200 encKey nghĩa là 200 lần backup Shamir (§2.7.5). Khuyến nghị thực tế: **1 địa chỉ/mục đích (4–6 địa chỉ/pháp nhân), không phải 1 địa chỉ/đối tác.** Linkability giữa các giao dịch cùng mục đích là chấp nhận được; số tiền vẫn ẩn.

**(c) Trục chain profile (locked #5) song hành với trục chain adapter.** `register()` trên public chain là mở; trên private/permissioned chain phải qua KYC attestor. Một interface, ba implementation — đây là trường hợp hiếm mà abstraction xứng đáng:

```
smartcontracts/src/registry/policy/IRegistrationPolicy.sol
    function check(bytes32 addr, uint256 pkX, uint256 pkY, bytes calldata aux) external;
    // KHONG phai `view`: InviteRegistrationPolicy ghi inviteUses.
smartcontracts/src/registry/policy/OpenRegistrationPolicy.sol      // no-op, public chain khong tai tro
smartcontracts/src/registry/policy/InviteRegistrationPolicy.sol    // §2.2.4, public chain co tai tro
smartcontracts/src/registry/policy/AttestedRegistrationPolicy.sol  // EIP-712 sig cua KYC attestor, private chain
```

`policy` là `immutable` trong registry — đổi policy = deploy registry mới. Không có setter. (Bản nháp trước để `check` là `view`; sai, invite policy phải ghi state.)

**(d) Gasless registration.** Vì `register()` không dùng `msg.sender` (§2.2.2), nó chạy tự nhiên qua EIP-1776: `metaTx.to = registry`, `metaTx.value = 0`, `metaTx.fee = phí token`, `metaTx.data = abi.encodeCall(register, ...)`. Nhưng bước đầu tiên người dùng **chưa có token** để trả `fee` → phải có sponsorship: issuer trả. Ghi rõ trong section relayer: **onboarding luôn là subsidized intent, không bao giờ là open-market intent.**

Hệ quả mà bản nháp trước không nói: một intent subsidized không có `fee` on-chain → **relayer thị trường tự do không có động cơ xử lý nó**. Chỉ relayer của issuer (hoặc relayer có hợp đồng rebate off-chain) mới nhặt.

**Câu này đã được sửa một lần và cần sửa nốt.** `_USER-DECISIONS.md` §3.4b: mạng mở **vẫn nhận** intent phí 0, qua **acceptance policy** — một relayer đối tác nhận việc phí 0 cho contract nó có quan hệ, thu hồi ngoài chuỗi. Và §21 đi xa hơn: một node **từ chối** một intent thì **chuyển tiếp** nó sang node khác thay vì vứt đi. Nên onboarding không nằm ngoài mesh; nó chỉ không sinh lời cho relayer thị trường tự do.

Điều đó **giảm** SPOF chứ không xoá. Nếu không có relayer đối tác nào online, luồng onboarding vẫn dừng dù mạng blockchain hoàn toàn khoẻ. SLO phải ghi riêng cho luồng này (đích: 99,5%, RTO 15 phút) — chi tiết ở section 06.

**(e) Registry là dependency cứng của mọi token → SLO của nó là SLO của toàn hệ thống.** Nếu registry deploy sai (ví dụ policy sai), không sửa được (non-upgradeable), và mọi token đã deploy trỏ tới địa chỉ đó. Bắt buộc: token lưu `registry` là `immutable` nhưng có hàm `registryOf()` đọc qua một **`RegistryPointer`** cực nhỏ, chỉ có một biến và một timelock 30 ngày? **Không** — đó là đưa proxy vào bằng cửa sau. Chọn thay thế: token lưu `registry` `immutable`, và **quy trình deploy bắt buộc**: registry lên testnet → chạy full test suite → deploy lên mainnet → **chờ 7 ngày và chạy một token thử nghiệm** → mới deploy token thật. Ghi vào runbook, không ghi vào code.

Trên factory mở, mục này có một hệ quả mà bản trước không cần đến: **địa chỉ registry là một tham số `initialize()` của token, do người tạo token chọn.** Ta không ép được ai dùng registry của ta. Cái ta làm được là công bố địa chỉ registry đã audit và để `IZetherToken.registry()` đọc được — người sắp nạp tiền kiểm được token đang trỏ tới registry nào, y như họ kiểm `verifier()` (§01.1.5).

**(f) Registry không được giữ tiền.** Kiểm tra: registry không có `receive()`, không có `payable`, không có `transfer` token nào. Nếu nó không bao giờ giữ giá trị, một bug trong nó không thể bị khai thác để rút tiền trực tiếp — chỉ để giả mạo trạng thái. Đó là một bậc giảm thiệt hại đáng kể và phải là một invariant test.

---

### 2.4. Tách `encKey` khỏi `authKey` — nền móng cho mọi sơ đồ chữ ký

Đây là điểm kiến trúc quan trọng nhất của section này, và note không có.

#### 2.4.1. Tại sao bắt buộc tách

**Zether bắt buộc `encKey` là điểm G1 của curve token, `y = g^x`.** Không thể thay bằng FALCON key, BLS key, hay ECDSA key: ElGamal mã hoá *tới* `y`, và sigma protocol chứng minh *biết* `x`. Mọi đề xuất "registry hỗ trợ FALCON" mà không tách hai khoá đều sẽ đâm vào tường này.

```solidity
// Xem bo tri slot o §2.1.4. Doc/ghi qua getter/setter, khong cham raw.
enum AuthScheme {
    SELF_SCHNORR,        // 0 — ZK proof cua Zether CHINH LA uy quyen
    ECDSA_MULTISIG,      // 1
    FROST_BN254,         // 2 — threshold Schnorr t-of-n (KHONG phai MuSig2)
    MUSIG2_BN254,        // 3 — n-of-n
    BLS_BN254,           // 4 — chi private chain
    BLS_12381,           // 5 — neu chain co EIP-2537
    PQ_COMMITMENT,       // 6 — verify off-chain
    SMART_ACCOUNT_1271   // 7
}
```

```solidity
interface ISignatureVerifier {
    /// @return magic 0x1626ba7e neu hop le (tuong thich EIP-1271)
    /// @dev PHAI la view. PHAI khong reentrancy. PHAI hoan tat trong GAS_CAP_VERIFY.
    function verify(bytes32 addr, bytes32 authKeyHash, bytes32 digest, bytes calldata sig)
        external view returns (bytes4 magic);
}
```

##### [BẢN 3] Tám giá trị, nhưng chỉ SÁU verifier — và MPC không cần cái nào

Đây là chỗ dễ thiết kế thừa nhất của cả mục, và bản trước không nói.

**FROST (2) và MUSIG2 (3) dùng CHUNG một đường xác minh.** Cả hai là giao thức **off-chain** để
nhiều bên cùng tạo ra **một chữ ký Schnorr duy nhất**. Chữ ký đó `(R, z)` verify bằng đúng phương
trình của chữ ký một người: `z·G == R + c·P`. Contract **không phân biệt được**, và không cần.
Viết hai `ISignatureVerifier` cho chúng là hiện thực hai lần cùng một phép toán.

Hai giá trị enum vẫn tách vì chúng khác nhau ở chỗ **khác**: registry ghi lại *cơ chế quản trị nào
đang bảo vệ tài khoản* — t-of-n hay n-of-n. Đó là thông tin kiểm toán và chính sách, không phải
thông tin xác minh.

Điều **duy nhất** MPC đòi ở tầng contract: khoá đăng ký phải là **khoá TỔNG HỢP** của nhóm, không
phải share của ai. Đó là ràng buộc lúc `register` (PoP §2.2), không phải lúc verify. Và §2.2 đã bắt
PoP cho **mọi** khoá không ngoại lệ, chính vì rogue-key — nên ràng buộc này đã có sẵn.

| `AuthScheme` | Verifier | Hiện thực |
|---|---|---|
| 0 `SELF_SCHNORR` | — | Không chữ ký nào để kiểm; ZK proof là uỷ quyền |
| 1 `ECDSA_MULTISIG` | N-of-M ECDSA | `MultiSig.sol` |
| 2 `FROST_BN254` | Schnorr bn254 | **cùng một** verifier |
| 3 `MUSIG2_BN254` | Schnorr bn254 | **cùng một** verifier |
| 4 `BLS_BN254` | pairing bn254 (0x08) | — |
| 5 `BLS_12381` | pairing BLS12-381 (0x0f) | `Bls12381.sol` + `HashToCurve.sol` |
| 6 `PQ_COMMITMENT` | off-chain | on-chain chỉ giữ cam kết |
| 7 `SMART_ACCOUNT_1271` | ERC-1271 | `SigLib.requireValid` |

##### [BẢN 3] BLS_12381: đã hiện thực và đã đo trên chain 9000

Chain 9000 đã bật EIP-2537 (2026-08-31). Số đo thật, `eth_estimateGas` trừ intrinsic + calldata:

| Thành phần | Gas |
|---|---:|
| `MAP_FP_TO_G1` (0x10) × 2 | 11.682 |
| `G1ADD` (0x0b) | ~1.100 |
| `expand_message_xmd` + 2× MODEXP rút gọn mod p | ~4.000 (ước) |
| `PAIRING_CHECK` (0x0f) k=2 | **103.959** |
| **Tổng verify min-sig** | **~120k** |

Khớp ước tính ~118k của §2.5.2. Và một kết quả ngược trực giác: **pairing BLS12-381 (103.959) rẻ
hơn pairing bn254 (114.091)** trên cùng chain đó — nên `BLS_BN254` (giá trị 4) mất lý do tồn tại
trừ khi chain không có EIP-2537. Đường cong 126-bit không đắt hơn đường cong 100-bit; nó rẻ hơn.

Điều này **không** mâu thuẫn spike S7: S7 đo **MSM ở quy mô Bulletproofs** (k=277), nơi BLS12-381
đắt hơn ~2%. Pairing và MSM là hai phép toán khác nhau, và cả hai đều đo được.

Ba chi tiết hiện thực mà sai một cái là hỏng im lặng:

1. **Địa chỉ precompile.** Bản cuối EIP-2537 **đánh số lại**: `G2ADD` là `0x0d` (không phải `0x0e`),
   `MAP_FP_TO_G1` là `0x10` (không phải `0x11`). Dùng số của draft là gọi trúng precompile khác, và
   với input toàn 0 nó **vẫn trả byte**.
2. **Bỏ `clear_cofactor` là ĐÚNG ở đây.** RFC 9380 làm `P = clear_cofactor(Q0 + Q1)`, nhưng
   `MAP_FP_TO_G1` của EIP-2537 đã clear cofactor rồi. Ta tính `h·Q0 + h·Q1` thay vì `h·(Q0+Q1)` —
   **bằng nhau**, vì nhân vô hướng là đồng cấu nhóm. Đã kiểm trên chain: `G1MSM(H(m), 1) == H(m)`,
   tức `H(m)` nằm trong subgroup bậc nguyên tố.
3. **`G1ADD`/`G2ADD` KHÔNG kiểm subgroup**, chỉ kiểm on-curve. `G1MSM`/`G2MSM`/`PAIRING_CHECK` thì
   có. Nên tổng hợp khoá bằng một chuỗi `G2ADD` rẻ tiền là **không** được bảo vệ — phải ép qua
   `G2MSM` k=1 một lần lúc đăng ký (§2.5.3 đã nói; `Bls12381.requireInG2Subgroup` là hiện thực).

#### 2.4.2. **Lỗ hổng lớn nhất của bản nháp trước: không ai bắt buộc gọi `assertAuthorized`**

Bản nháp trước viết "Token gọi `registry.assertAuthorized(addr, digest, sig)`" như một câu mô tả, rồi không bao giờ nói:

- Digest gồm những gì?
- Điều gì xảy ra nếu token **không** gọi?
- Tại sao lớp authKey không phải là trang trí, khi mà **biết `x` là đủ để tạo ZK proof và chi tiêu**?

Câu trả lời cho câu hỏi thứ ba là điểm then chốt của cả thiết kế, và phải được viết ra:

> **Bất biến an ninh #1.** `transferConfidential` và `withdraw` PHẢI xác thực **hai** thứ độc lập: (i) ZK proof chứng minh biết `x` (tính đúng đắn của số dư), và (ii) chữ ký theo `authScheme` trên một digest bao trùm toàn bộ giao dịch (quyền chi tiêu). Nếu bỏ (ii), thì compromise `encKey` = compromise toàn phần, và toàn bộ cột `authScheme` chỉ là trang trí.

Hệ quả trực tiếp, và là lý do thương mại mạnh nhất cho cả §2.4: **compromise `encKey` chỉ làm lộ số dư (read-only breach), không làm mất tiền**, miễn là `authScheme != SELF_SCHNORR`. Đó là sự khác biệt giữa "đối thủ đọc được bảng giá của ta" và "đối thủ rút sạch quỹ". Với custody model trong locked #6, đây cũng là thứ cho phép đặt `encKey` ở một ranh giới bảo mật yếu hơn `authKey` — xem §2.4.4, nơi mà điều đó trở thành bắt buộc chứ không phải tuỳ chọn.

**Trên factory mở, bất biến này là thứ không ép được bằng code của ta.** Registry cung cấp `assertAuthorized`; token của người khác gọi hay không là việc của họ. Nên nó phải là (i) một dòng trong mô tả archetype, (ii) một test trong bộ conformance của catalogue, và (iii) một thứ ví kiểm được — nếu `IZetherToken` không khai `registry()` thì người dùng biết token đó không có lớp uỷ quyền nào cả. Một archetype `SELF_SCHNORR` thuần tuý là hợp lệ, nhưng phải nhìn thấy được.

**Digest phải bao trùm tất cả:**

```solidity
bytes32 digest = keccak256(abi.encode(
    "ZETHER_AUTH_V1",
    block.chainid,
    address(this),          // token contract, khong phai registry
    from, to,               // ca hai schnorrAddress
    keccak256(abi.encode(data)),   // TOAN BO EncryptedTransfer, ke ca fee va feeRecipient
    authEpoch,              // doc tu registry -> xoay khoa vo hieu chu ky cu tuc thi
    deadline
));
```

Ba điểm mà nếu thiếu sẽ thành lỗ hổng:
- Thiếu `keccak256(data)` → relayer đổi `feeRecipient` hoặc `C_fee`.
- Thiếu `authEpoch` → chữ ký cũ còn hiệu lực sau khi xoay khoá; toàn bộ §2.7.1 vô nghĩa.
- Thiếu `address(this)` → chữ ký cho Z-USDC dùng được trên Z-VND.

**Tối ưu cho `SELF_SCHNORR`** (bản nháp trước tính 12.150 gas cho nó — thừa): khi `authScheme == SELF_SCHNORR`, `authKey ≡ encKey`, và ZK proof của Zether **đã** chứng minh biết `x`. Chữ ký Schnorr thứ hai là dư thừa. `assertAuthorized` trả về ngay:

```solidity
if (scheme == AuthScheme.SELF_SCHNORR) return;   // ZK proof la uy quyen. ~2,100 gas (chi doc meta).
```

Nhưng khi đó digest **phải** được nhúng vào Fiat-Shamir challenge của chính ZK proof, nếu không `feeRecipient` vẫn bị đổi. Note gốc đã làm đúng điều này cho `withdraw` (băm `recipient` vào challenge) nhưng **không làm cho `transferConfidential`** — đó là một lỗ hổng Anti-MEV thật trong note, phải sửa trong section 03.

Chi phí phụ trội của lớp auth, tính theo % của một giao dịch Zether (~200k–250k gas):

| Scheme | Gas auth | % thêm |
|---|---|---|
| `SELF_SCHNORR` | ~2.100 | +0,9% |
| `ECDSA_MULTISIG` 3-of-5 | 3 × 3.000 + 3 × 1.040 calldata + ~2.000 logic = ~14.120 | +6,3% |
| `MUSIG2_BN254` / `FROST_BN254` | ~12.900 | +5,7% |
| `BLS_12381` (min-sig) | ~118.000 | +52% — **không dùng cho hot path** |
| `PQ_COMMITMENT` | ~2.600 (chỉ đọc, verify off-chain) | +1,2% |
| `SMART_ACCOUNT_1271` | ~5.000 + chi phí của account (cap 100k) | +2,2% .. +45% |

Bảng này quyết định: **BLS không bao giờ là authScheme cho tài khoản giao dịch.** Nó chỉ hợp lý cho attestor quorum (§2.8), nơi tần suất là ~500 lần/năm chứ không phải mỗi transfer.

#### 2.4.3. MuSig2 vs FROST — **bản nháp trước lẫn hai khái niệm**

| | MuSig2 | FROST |
|---|---|---|
| Ngưỡng | **n-of-n** (mọi thành viên phải ký) | **t-of-n** |
| Khoá tổng hợp | `X = Σ H_agg(L, X_i) · X_i` | Khoá chia sẻ qua DKG (Feldman/Pedersen VSS) |
| On-chain | 1 G1 point + 1 Schnorr sig, gas **không đổi theo n** | Y hệt |
| Vòng giao tiếp | 2 (nonce round + sign round) | 2 (với FROST2/preprocessing có thể 1) |
| Hợp cho | Ban điều hành nhỏ bắt buộc đồng thuận tuyệt đối | **MPC custody, treasury t-of-n, mọi thứ còn lại** |

Bản nháp trước ánh xạ "MPC → `MUSIG2`". **Sai**: nhà cung cấp MPC (Fireblocks, Fordefi, Turnkey) làm threshold ECDSA hoặc FROST, không làm MuSig2. Và treasury 3-of-5 không thể dùng MuSig2 (nó đòi 5-of-5). Sửa ánh xạ custody (locked #6):

| Custody model | authScheme | Ghi chú |
|---|---|---|
| HSM (FIPS 140-2 L3) | `ECDSA_MULTISIG` | HSM làm secp256k1/P-256 tốt; không làm bn254 Schnorr (§2.4.4) |
| MPC | `SELF_SCHNORR` nếu provider hỗ trợ bn254 threshold, **ngược lại** `ECDSA_MULTISIG` | On-chain không phân biệt được; không quan trọng |
| MPC với threshold Schnorr bn254 | `FROST_BN254` | Chỉ khi provider thật sự hỗ trợ curve này — hỏi trước, đừng giả định |
| Custodial | `ECDSA_MULTISIG` | Custodian ký, khách hàng có 1 trong n |
| Non-custodial | `SELF_SCHNORR` | Người dùng tự giữ, tự chịu |
| Smart-account / passkey | `SMART_ACCOUNT_1271` | P-256 verify trong account (hoặc EIP-7212 nếu chain có) |
| Ban điều hành n-of-n | `MUSIG2_BN254` | Trường hợp hiếm; chỉ khi cần giấu cơ cấu nhóm |

**Registry không biết gì về custody model** — đúng như locked #6 yêu cầu. Cột `custody_model` chỉ tồn tại trong Odoo (`blockchain.zether.account.custody_model`) để vận hành, không lên chain.

**Bẫy chết người trong MuSig2/FROST: tái sử dụng nonce làm lộ khoá bí mật** (tấn công Wagner/ROS trên sơ đồ 2 vòng). Bắt buộc: nonce `(R1, R2)` sinh trong HSM/MPC với bộ đếm chống-lặp **cứng** (không phải biến trong RAM), và message được đưa vào hàm dẫn xuất nonce (`nonce = KDF(sk_share, msg, counter)`). Ghi thành `SECURITY:` comment trong SDK và thành một test negative: ký hai message khác nhau với cùng nonce phải bị SDK từ chối ở tầng API, không chỉ tầng docs.

Đây là cùng một lớp lỗi với ràng buộc `sendCounter` phải đọc từ chain ở `_USER-DECISIONS.md` §13.2 — tái dùng randomness làm lộ bí mật, và bộ đếm cục bộ là cách phổ biến nhất để vô tình tái dùng. Hai chỗ, một bài học, và cả hai đều cần test phủ định chứ không phải một dòng cảnh báo.

**MuSig2/FROST và rogue-key tại registry.** Hệ số `H_agg` đã chặn rogue-key ngay trong sơ đồ, nên PoP cho `X` không còn là yêu cầu mật mã — nhưng registry **không thể phân biệt** `X` là khoá đơn hay khoá tổng hợp, nên vẫn bắt buộc PoP; nhóm sản xuất PoP bằng chính một phiên MuSig2/FROST.

**Thay đổi thành viên nhóm.** Thêm/bớt một thành viên đổi `X_agg` → đổi `authKeyHash` → phải qua `requestAuthRotation` (§2.7.1) với chữ ký của `X_agg` **hiện tại**. Vì MuSig2 là n-of-n, một thành viên rời nhóm có thể chặn việc bị loại bỏ (họ không ký). Với FROST t-of-n thì t người còn lại làm được. **Đây là một lý do vận hành nữa để mặc định FROST chứ không MuSig2.**

#### 2.4.4. **`encKey` không nằm được trong HSM FIPS 140-2 L3 tiêu chuẩn** — mâu thuẫn trực tiếp với note

`blockchain.md` §10.3.1 và §14.2.8 tuyên bố: "Khoá cá nhân ... bắt buộc phải lưu trong ... FIPS 140-2 Level 3 HSM (AWS CloudHSM, Google Cloud KMS)". Áp dụng cho `encKey` thì **không làm được**, và đây là một rủi ro triển khai phải được báo cáo trước khi ký hợp đồng:

- AWS CloudHSM, GCP Cloud KMS, Azure Managed HSM hỗ trợ các đường cong NIST (P-256/384/521), secp256k1 (một số), Ed25519. **Không hỗ trợ alt_bn128 (BN254)** và không có API để nạp đường cong tuỳ ý. BLS12-381 cũng không, nên đổi curve không giải quyết được gì ở đây.
- Zether cần `ecMul` trên G1 với khoá bí mật `x`, và cần `x` trong **mạch tính Bulletproofs/sigma** — không chỉ một phép ký đơn lẻ. Ngay cả một HSM có bn254 cũng không đủ: prover cần hàng nghìn phép nhân vô hướng với `x` là một trong các input.

| Lựa chọn | Ranh giới bảo mật thật sự | Chi phí / thời gian | Đánh giá |
|---|---|---|---|
| (a) HSM giữ **seed**, host dẫn xuất `x` và prove trong RAM | `x` ở plaintext trong RAM của host khi prove | thấp | Vi phạm câu chữ của note. Chấp nhận được **chỉ khi** kết hợp bất biến #1 (§2.4.2) |
| (b) Prover chạy trong TEE (SGX / SEV-SNP / TDX) | `x` trong enclave; vẫn có side-channel | trung bình, 2–4 tuần tích hợp | **Khuyến nghị cho public chain** |
| (c) HSM lập trình được (Thales Luna Functionality Module, Utimaco CryptoServer CP5) | Đúng FIPS L3, `x` không bao giờ rời HSM | **cao**: firmware phải được ký, lead time 3–6 tháng, ~$30k–80k thiết bị + phát triển | Khả thi nhưng không cho MVP |
| (d) MPC provider hỗ trợ bn254 | Phân tán, không có điểm `x` đầy đủ | Phụ thuộc provider; **phải hỏi trước, phần lớn không hỗ trợ** | Kiểm tra sớm |
| (e) Không bảo vệ `encKey` bằng phần cứng; bảo vệ `authKey` bằng HSM | `encKey` compromise = lộ số dư; **không mất tiền** nhờ bất biến #1 | thấp | **Đây là lý do thật sự để tách hai khoá** |

**Quyết định đề xuất: (e) + (b).** `authKey` (quyền chi tiêu) nằm trong HSM FIPS L3 thật sự — điều này làm được vì `ECDSA_MULTISIG` dùng secp256k1/P-256. `encKey` (quyền giải mã) nằm trong TEE hoặc ở mức mềm hơn. Sửa câu chữ của note thành: *"Khoá có quyền chi tiêu bắt buộc HSM/MPC FIPS 140-2 L3; khoá giải mã ElGamal chạy trong TEE, và compromise của nó là read-only breach theo thiết kế."*

**Đây là một thay đổi cam kết với khách hàng, không phải một chi tiết kỹ thuật.** Phải đưa lên bảng câu hỏi mở (§2.12).

Trên factory mở, mục này đổi vai chứ không mất: đây là **hướng dẫn cho bất kỳ ai vận hành một tài khoản Zether**, kể cả ta. Ta không ép được ai dùng TEE. Cái ta làm được là để bất biến #1 khả thi ở tầng contract, và nói rõ trong tài liệu tại sao `authScheme = SELF_SCHNORR` trên một tài khoản treasury là một quyết định khác hẳn so với trên một ví cá nhân.

---

### 2.5. BLS: alt_bn128 vs BLS12-381 trên EVM

#### 2.5.1. Sự thật về bảo mật bn254

Sau exTNFS (Kim–Barbulescu 2016), độ khó DLP trong `F_p^12` của bn254 tụt xuống **~100 bit**. Điều này dẫn đến một bất đối xứng mà phải nói cho đúng, vì note bỏ qua:

- **ElGamal / Schnorr / Bulletproofs của Zether trên bn254 G1 vẫn an toàn ~127 bit** — chúng dựa vào ECDLP trên G1, không dựa vào pairing. exTNFS không chạm vào đây. **Zether trên bn254 là lựa chọn đúng.**
- **BLS trên bn254 KHÔNG an toàn 128 bit** — bảo mật của nó quy về co-CDH, bị chặn bởi DLP trong `F_p^12` → ~100 bit. **Không xây chữ ký BLS tuổi thọ dài trên bn254.**

100 bit nghĩa là gì về tiền: chi phí phá ~2^100 phép tính. Không ai phá được hôm nay. Nhưng một attestation quorum ký trạng thái freeze/revoke là thứ có **tuổi thọ pháp lý 7–10 năm** (thời hạn lưu hồ sơ kiểm toán). Đó là khoảng thời gian mà biên độ an toàn từ 128 xuống 100 bit trở nên đáng lo. Kết luận giữ nguyên.

Mục này là nguồn của điều kiện mở lại D1 ở `_USER-DECISIONS.md` §19, và hai chỗ phải đọc cùng nhau: **bất đối xứng ở đây (Zether an toàn, BLS không) là lý do bn254 dùng được cho giai đoạn private**, còn ~100 bit của pairing là lý do phải hỏi lại trước khi lên public.

#### 2.5.2. Precompile hiện có, và **biến thể BLS phải chọn**

| Curve | Precompile | Gia (gas) |
|---|---|---|
| alt_bn128 | `ecAdd` 0x06 / `ecMul` 0x07 / `ecPairing` 0x08 (EIP-196/197, dinh gia lai EIP-1108) | 150 / 6,000 / 45,000 + 34,000·k |
| alt_bn128 | hash-to-curve | **KHONG CO** — phai viet Solidity (try-and-increment: ~20k–60k gas) |
| Curve | Precompile | Giá (gas) |
|---|---|---|
| alt_bn128 | `ecAdd` `0x06` / `ecMul` `0x07` / `ecPairing` `0x08` (EIP-196/197, định giá lại EIP-1108) | 150 / 6.000 / 45.000 + 34.000·k |
| alt_bn128 | hash-to-curve | **KHÔNG CÓ** — phải viết Solidity (try-and-increment: ~20k–60k gas) |
| alt_bn128 | G2 arithmetic / G2 subgroup check | **KHÔNG CÓ** — xem §2.5.3 |
| BLS12-381 | EIP-2537, addr `0x0b`..`0x11`, vào mainnet cùng **Pectra (2025-05-07)** | G1ADD 375, G1MSM 12.000 (k=1), G2ADD 600, G2MSM 22.500 (k=1), PAIRING 32.600·k + 37.700, MAP_FP_TO_G1 5.500, MAP_FP2_TO_G2 23.800 |

**Bản nháp trước tính thiếu.** `hash_to_curve` theo RFC 9380 (`_XMD:SHA-256_SSWU_RO_`) cần **hai** field element → **hai** lần map → **một** lần add. Và có hai biến thể BLS mà bản nháp trước không phân biệt:

| Biến thể | pk | sig | hash-to | Kích thước |
|---|---|---|---|---|
| min-pubkey-size | G1 (48 B) | G2 (96 B) | G2 | pk nhỏ, sig to |
| **min-signature-size** (chọn) | G2 (96 B) | G1 (48 B) | **G1** | pk to, **sig nhỏ** |

Chi phí verify **một** chữ ký, tính lại đầy đủ:

| Bước | min-pubkey (sig∈G2) | **min-sig (sig∈G1)** |
|---|---|---|
| `expand_message_xmd` (SHA-256 precompile `0x02`, ~5 call) | ~500 | ~500 |
| map field → curve, 2× | 2 × 23.800 = 47.600 | 2 × 5.500 = 11.000 |
| clear cofactor / add, 1× | 600 (G2ADD) | 375 (G1ADD) |
| pairing check k=2 | 32.600×2 + 37.700 = 102.900 | 102.900 |
| calldata sig | 96 B = 1.536 | **48 B = 768** |
| **Tổng** | **~153.100** | **~115.500** |

**Chọn min-signature-size.** Tiết kiệm ~37.600 gas/verify và một nửa calldata. Đổi lại pk 96 B thay vì 48 B — nhưng pk lưu **một lần** khi đăng ký attestor, còn sig trả **mỗi lần**. Bản nháp trước chọn nhầm biến thể ngầm định.

bn254 BLS để đối chiếu: pairing k=2 (45.000 + 68.000 = 113.000) + hash-to-curve Solidity (~20k–60k) ≈ **150.000–180.000 gas**, ở mức bảo mật ~100 bit. **Đắt hơn và yếu hơn BLS12-381.** Chỉ dùng khi chain không có EIP-2537 và không còn lựa chọn nào khác.

Lưu ý phân biệt, vì hai chỗ trong tài liệu này nói về BLS12-381 với hai kết luận ngược nhau và điều đó không mâu thuẫn: **ở đây BLS12-381 thắng** (chữ ký attestor, `PAIRING` là phép chính, bn254 không có hash-to-curve và không có G2 arithmetic). **Ở §01.1.12 và `_USER-DECISIONS.md` §17 thì bn254 thắng** (Bulletproofs MSM, `G1MSM` của BLS đắt hơn ~2% ở k=277). Khác nhau vì hai bài toán dùng hai họ phép tính khác nhau. Một hệ có thể chạy Zether trên bn254 và attestation trên BLS12-381 cùng lúc — chúng không chia sẻ gì ngoài cái tên "curve".

#### 2.5.3. Subgroup check — cái bẫy mà bản nháp trước chỉ nhắc một dòng

Bản nháp trước viết "cần trên G2 — liên quan BLS". Đúng, nhưng hậu quả nặng hơn vẻ:

- **bn254 G2 có cofactor ≠ 1** và **EVM không có precompile nhân vô hướng trên G2**. Kiểm tra subgroup cho một pk∈G2 trên bn254 = nhân điểm với order `r` bằng số học `F_p^2` viết tay trong Solidity ≈ **500k–1,5M gas** (ước tính: ~254 lần double + add, mỗi lần ~4 mulmod trong Fp2 = ~12 mulmod, ~2.000–5.000 gas/bước). **Không làm được on-chain.** Đường duy nhất: kiểm tra off-chain khi đăng ký attestor, và coi tập attestor là permissioned. Chấp nhận được vì attestor set vốn là permissioned; nhưng phải ghi thành runbook, không được quên.
- **EIP-2537 có kiểm tra subgroup, nhưng không phải ở mọi precompile.** `G1MSM`/`G2MSM` và `PAIRING_CHECK` kiểm tra subgroup membership của input. `G1ADD`/`G2ADD` **chỉ** kiểm tra điểm nằm trên đường cong, **không** kiểm tra subgroup. Nghĩa là: nếu ta tổng hợp khoá attestor bằng một chuỗi `G2ADD` rẻ tiền, ta **không** được bảo vệ. Sửa: khi **đăng ký** một attestor pk, gọi một lần `G2MSM` với k=1 (22.500 gas) để ép kiểm tra subgroup; sau đó `G2ADD` để tổng hợp là an toàn (tổng của các phần tử trong subgroup vẫn trong subgroup).

#### 2.5.4. Điểm hoà vốn với ECDSA — và tại sao nó khác trên rollup

Giá trị thực của aggregate: n người ký **cùng một message** → 1 chữ ký, chi phí verify **không đổi**, cộng (n−1) `G2ADD` = 600 mỗi cái để gộp khoá (hoặc dùng bitmap + pre-aggregated key theo epoch).

Chi phí ECDSA: `ecrecover` 3.000 + calldata `(r,s,v)` đóng gói chặt 65 B = 1.040 + logic sort/dedupe ~500 ≈ **4.540 gas/signer**.

| Môi trường | BLS cố định | BLS/signer | ECDSA/signer | Hoà vốn n |
|---|---|---|---|---|
| L1 / Gnosis / chain độc lập | 115.500 | 600 | 4.540 | **n ≈ 29** |
| bn254 BLS (nếu buộc phải) | 165.000 | 150 | 4.540 | **n ≈ 38** |
| **Rollup (Celo L2, Base, Arbitrum)** — calldata trả tiền L1 | 115.500 + 48 B L1 | 600 + 0 | 4.540 + **65 B L1** | Xem dưới |

Trên rollup, byte calldata bị tính giá L1. Ở 10 gwei L1, một byte non-zero calldata có thể tốn **~160–240 gas-tương-đương** (16 gas × hệ số nén/scalar của rollup, tuỳ chính sách `l1FeeScalar`; ước tính, phải đo). Với ECDSA: 65 B/signer × ~200 = **13.000 gas-tương-đương/signer** thay vì 1.040. Hoà vốn tụt xuống:

```
115,500 + 600n  =  (3,000 + 13,000 + 500) n
n ≈ 115,500 / 15,900 ≈ 7.3
```

**Trên rollup, BLS thắng từ n ≈ 8.** Bản nháp trước nói "BLS chỉ thắng khi quorum > ~35" — đúng trên L1/Gnosis, **sai trên rollup**, và Celo (locked #4, chain thứ hai) **là một OP Stack rollup**. Đây là một kết luận đảo chiều.

**Quyết định cuối:**
- Quorum attestor 5-of-9 trên Gnosis / private chain → **ECDSA multisig** (5 × 4.540 ≈ 22.700 gas). Đúng.
- Cùng quorum trên Celo (rollup) → **BLS12-381 min-sig nếu chain có EIP-2537**, ngược lại ECDSA. Probe runtime.
- Kiến trúc §2.4 cho phép đổi verifier mà không migration, nên quyết định này **không khoá cứng**; đo gas thực tế sau 1 tháng vận hành rồi chốt.

Ba dòng trên nói về **verifier của authScheme**, thứ trỏ bằng địa chỉ trong slot `meta` và đổi được qua `requestAuthRotation`. Nó không mâu thuẫn với việc verifier ZK của token là bất biến (§01.1.3): hai thứ khác nhau, một cái là uỷ quyền chi tiêu, một cái là tính đúng đắn của số dư.

#### 2.5.5. Khả dụng theo chain — phải probe, không được giả định

Gnosis và Celo theo lịch fork riêng (Celo đã chuyển thành L2 OP Stack; OP Stack nhận EIP-2537 qua hard fork Isthmus). Deploy-time probe:

```solidity
// smartcontracts/src/registry/lib/CurveCapability.sol
function hasBls12381() internal view returns (bool ok) {
    // staticcall G1ADD (0x0b) voi vector (P + O = P) da biet, so sanh output.
    (bool s, bytes memory out) = address(0x0b).staticcall(_G1ADD_IDENTITY_VECTOR);
    ok = s && out.length == 128 && keccak256(out) == _EXPECTED_G1ADD_RESULT;
}
```

Chỉ `success == true` là **không đủ**: một chain không có precompile ở `0x0b` sẽ coi đó là một địa chỉ rỗng và `staticcall` trả `success = true` với `returndata` rỗng. Phải so sánh kết quả. Bản nháp trước chỉ kiểm `ok` — **bug**.

**Đây đúng là cái bẫy đã bắt được trên chain thật.** Chain private 9000 khai `pragueBlock: 0` trong genesis nhưng Nethermind bỏ qua key kiểu Geth trong im lặng, và `0x0b`/`0x0c`/`0x0f`/`0x10` không tồn tại (`TRAPS.md`). Một probe chỉ kiểm `success` sẽ báo "có BLS" trên chính chain đó. Cùng một hàm này là thứ `IZetherVerifier.isSupportedOnThisChain()` phải cài (§01.1.14 gate 10) — viết một lần, dùng cả hai chỗ.

Kết quả ghi vào Odoo record `blockchain.chain.profile.has_bls12381` lúc onboarding chain, không hardcode trong Python.

---

### 2.6. FALCON / post-quantum: nói thật

#### 2.6.1. Trạng thái chuẩn hoá (tính đến 2026-08)

NIST hoàn tất **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** và **FIPS 205 (SLH-DSA)** ngày 2024-08-13. **FIPS 206 (FN-DSA, tức FALCON) chưa ban hành chính thức.**

**Cảnh báo về độ tin cậy của chính câu trên:** trạng thái FIPS 206 có thể đã thay đổi giữa thời điểm viết và thời điểm đọc. Trước khi đưa "FALCON" vào bất kỳ hợp đồng, SOW, hay tài liệu tuân thủ nào, **phải kiểm tra lại trực tiếp tại `csrc.nist.gov/pubs/fips/206`** và ghi ngày kiểm tra vào tài liệu. Bất kỳ kế hoạch nào coi FALCON là "chuẩn NIST đã có" mà không kiểm tra đều là rủi ro pháp lý, không chỉ rủi ro kỹ thuật.

| Scheme | Public key | Signature | NIST level | Hàm băm |
|---|---|---|---|---|
| FALCON-512 | 897 B | ~666 B (max 752) | 1 | SHAKE256 |
| FALCON-1024 | 1.793 B | ~1.280 B (max 1.462) | 5 | SHAKE256 |
| ML-DSA-44 | 1.312 B | 2.420 B | 2 | SHAKE128/256 |
| ML-DSA-65 | 1.952 B | 3.309 B | 3 | SHAKE128/256 |
| ML-DSA-87 | 2.592 B | 4.627 B | 5 | SHAKE128/256 |
| SLH-DSA-SHA2-128s | 32 B | 7.856 B | 1 | **SHA-256** |
| SLH-DSA-SHA2-128f | 32 B | 17.088 B | 1 | **SHA-256** |
| (so sánh) Schnorr bn254 | 64 B | 64 B | ~127-bit classical | keccak256 |

#### 2.6.2. Verify FALCON on-chain: **bản nháp trước ước tính quá cao, và kết luận đúng vì lý do khác**

Đếm lại thao tác (ước tính, cơ sở: đếm opcode × bảng giá; **chưa có verifier FALCON Solidity nào được audit công khai** nên không có số đo thật để đối chiếu):

| Thành phần | Chi tiết | Gas ước tính |
|---|---|---|
| `HashToPoint` (SHAKE256) | ~1.180 B output cần ~10 lần keccak-f[1600]; **EVM không có precompile keccak-f thô**, `KECCAK256` opcode có padding SHA-3 khác SHAKE → phải hiện thực keccak-f trong Solidity: ~25k–60k gas/permutation | **250k–600k** |
| NTT-512 trên `Z_12289` | 9 tầng × 256 butterfly = 2.304 butterfly; mỗi butterfly ~1 `mulmod` + 2 `addmod` + memory ≈ 30–60 gas | **70k–140k / NTT** |
| Số NTT cần | `s1 = c − s2·h`: giữ `h` ở dạng NTT (nhưng `h` đến từ calldata → phải NTT), NTT(s2), và INTT kết quả | **3 NTT ≈ 210k–420k** |
| Giải nén chữ ký (Golomb-Rice) | 666 B bit-unpacking trong Solidity | **30k–80k** |
| Kiểm tra chuẩn `‖(s1,s2)‖² ≤ β²` | 1.024 `mulmod` + `addmod` | **~30k** |
| Calldata (pk 897 + sig 666 = 1.563 B) | 16 gas/byte | **~25k** |
| **Tổng** | | **~0,6M – 2,5M gas** |

Bản nháp trước nói **2M–10M**. Con số đó cao gấp 3–4 lần. Sửa lại, và kết luận **đổi lý do**:

| Chiều | Đánh giá |
|---|---|
| **Chi phí tiền** | Gnosis @2 gwei: 1,5M gas = **$0,003**. Celo tương đương. **Tiền KHÔNG phải rào cản.** Ethereum L1 @10 gwei/$3.000: **$45/verify** — ở đây tiền là rào cản |
| **Block gas limit** | Gnosis ~17–30M, Ethereum ~45M (2025). Một verify chiếm **5–15%** một block Gnosis. Chấp nhận được cho tần suất thấp, **không** cho hot path |
| **DoS surface** | Một hàm 2M gas ai cũng gọi được là một vector spam rẻ tiền trên chain có gas rẻ. Phải gate |
| **Kỹ thuật** | **Không tồn tại verifier FALCON Solidity được audit.** Tự viết = 3–6 tháng + audit $80k–150k, cho một thuật toán chưa có FIPS |
| **Phía ký** | FALCON cần Gaussian sampling với số học dấu phẩy động / fixed-point emulation — **rất ít HSM hỗ trợ firmware này**. Constant-time implementation là một bài toán khó đã từng có CVE |

**Kết luận sửa lại: không triển khai FALCON on-chain hôm nay — không phải vì gas, mà vì (a) không có verifier được audit, (b) FIPS 206 chưa ban hành, (c) phía ký không có hỗ trợ HSM.** Kết luận cuối cùng giống bản nháp trước, nhưng lý do khác hẳn, và điều đó đổi hướng dẫn: nếu mai có một verifier FALCON được audit, **quyết định này đảo chiều ngay trên Gnosis**, vì chi phí tiền đã chấp nhận được. Phải theo dõi.

Trên factory mở, "không triển khai" có nghĩa hẹp hơn trước: ta không đăng ký một verifier FALCON vào catalogue. Ai đó tự viết và tự deploy thì làm được, và `authScheme` là một trường của registry chứ không phải một danh sách ta duyệt. Cái ta kiểm soát là **cái ta đứng sau**.

#### 2.6.3. **Lựa chọn PQ on-chain thực dụng nhất lại là SLH-DSA-SHA2 — bản nháp trước bỏ qua hoàn toàn**

SLH-DSA (SPHINCS+) là **hash-based**: không NTT, không lattice, không số học dấu phẩy động, và biến thể `SHA2` dùng đúng hàm băm mà EVM **đã có precompile** (`SHA256` tại `0x02`, giá `60 + 12/word`).

Ước tính verify SLH-DSA-SHA2-128s (cơ sở: đếm số lần gọi hàm băm trong thuật toán verify):

| Thành phần | Số lần băm | Ghi chú |
|---|---|---|
| FORS: k=14 tree, a=12 | 14 × (1 + 12) = 182 | leaf + auth path |
| Hypertree: d=7 lớp, h/d=9 | 7 × 9 = 63 | auth path |
| WOTS+ chain: len=35, trung bình w/2≈7,5 bước | 7 × 35 × 7,5 ≈ 1.838 | chi phí trội nhất |
| Tweakable hash overhead, PRF, message compress | ~250 | |
| **Tổng** | **~2.330 lần băm** | |
| Gas: `staticcall` `0x02`, ~100 overhead + 60 + 12/word (input ~64–128 B) | 2.330 × ~200 | **~466.000** |
| Calldata sig 7.856 B | 16 × 7.856 = 125.700 **hoặc** floor EIP-7623 | xem dưới |
| **Tổng verify** | | **~0,6M gas** |

**EIP-7623 ở đây bind hay không?** Ngưỡng: floor bind khi `execution_gas < 24 × non_zero_bytes = 24 × 7.856 = 188.544`. Execution ~466k > 188,5k → **floor không bind**, calldata tính 16 gas/byte. Nhưng nếu ai đó chỉ **neo** một chữ ký SLH-DSA mà không verify (execution ~30k), floor **bind**: chi phí = `21.000 + 10 × 31.424 = 335.240` thay vì `21.000 + 125.700 + 30.000 = 176.700`. **Neo một chữ ký PQ đắt gần gấp đôi khi không verify nó.** Đó là một con số phản trực giác và phải nằm trong bảng chi phí của team.

So sánh cuối:

| Scheme PQ | Gas verify (ước tính) | Tồn tại verifier được audit? | FIPS |
|---|---|---|---|
| FALCON-512 | 0,6M–2,5M | **Không** | **Chưa** (FIPS 206) |
| ML-DSA-65 | 1,5M–4M (SHAKE trong Solidity + NTT-256 × nhiều) | Không | **Có** (FIPS 204) |
| **SLH-DSA-SHA2-128s** | **~0,6M** | Không, **nhưng đơn giản nhất để viết + audit** | **Có** (FIPS 205) |

**Khuyến nghị sửa đổi so với bản nháp trước:** nếu buộc phải có PQ verify **on-chain** trên EVM công khai, ứng viên là **SLH-DSA-SHA2-128s**, không phải FALCON và không phải ML-DSA. Lý do: dùng precompile sẵn có, không có số học lattice, bề mặt audit nhỏ nhất. Đổi lại chữ ký 7.856 B — chấp nhận được cho attestation/anchor tần suất thấp, không chấp nhận được cho mọi transfer. Giữ FALCON và ML-DSA như các giá trị `pqSchemeId` cho verify **off-chain** và cho native precompile trên private chain.

#### 2.6.4. Bẫy phải chặn ngay: "PQ trong SNARK"

"Verify FALCON bên trong một SNARK Groth16 trên bn254, chỉ tốn ~200–250k gas on-chain". Con số gas đúng, nhưng **bảo mật sai hoàn toàn**: soundness của Groth16/bn254 (và của Groth16/BLS12-381, và của mọi SNARK dựa trên pairing) dựa trên giả thiết pairing/discrete-log, thứ mà máy tính lượng tử phá được. Một kẻ tấn công lượng tử giả mạo SNARK trực tiếp, không cần phá FALCON. **PQ-trong-SNARK-pairing là an ninh trình diễn.**

Lưu ý rằng điều này **không** phụ thuộc việc chọn curve nào: đổi bn254 sang BLS12-381 không làm SNARK trở nên PQ-safe. Đây là một chỗ mà biên an toàn 26 bit của §2.5.1 hoàn toàn không liên quan — một máy tính lượng tử đủ lớn phá cả hai như nhau.

Đường PQ thật sự trên EVM chỉ có hai:

1. **STARK/FRI (chỉ dựa vào hash, PQ-safe)** — verifier trên EVM tốn ~1–5M gas (cơ sở: verifier SHARP của StarkWare trên mainnet ở thang đo này). Khả thi kỹ thuật, đắt, và cồng kềnh. Chú ý: nhiều hệ "STARK" trong sản xuất **bọc một lớp Groth16 cuối cùng** để rẻ gas — lớp bọc đó phá huỷ tính PQ. Phải đọc kỹ, không tin nhãn.
2. **Native precompile** — chỉ làm được khi ta sở hữu client. **Tức là private chain (locked #5).**

#### 2.6.5. Đường đi cụ thể (4 bước, không phải lộ trình mơ hồ)

| Giai đoạn | Public EVM (Gnosis, Celo) | Private chain |
|---|---|---|
| **Ngay bây giờ** | `authScheme = PQ_COMMITMENT`. Registry lưu **duy nhất** `authKeyHash = keccak256(pqSchemeId, pqPubKey)` (32 B, 1 SSTORE = 22.100 gas). Khoá đầy + chữ ký lưu `ir.attachment` trên S3/Garage, hash neo vào event. Verify FALCON/ML-DSA/SLH-DSA **off-chain** tại gateway và tại relayer. Cho **non-repudiation hồi tố** mà không tốn gas | Giống hệt, cộng thêm: bắt buộc dual-sign (classical on-chain + PQ off-chain) cho mọi giao dịch > ngưỡng |
| **Khi private chain lên phiên bản có plugin** | (không đổi) | Thêm precompile ML-DSA/SLH-DSA ở địa chỉ dự trữ (Nethermind/Besu plugin API), deploy `PqNativeVerifier`, `rotateAuthScheme()` sang verify on-chain thật. **Không động đến số dư, không migration** — nhờ tách encKey/authKey (§2.4) |
| **Khi có verifier SLH-DSA Solidity được audit** | Deploy `SlhDsaSha2Verifier`, rotate `verifier` cho các tài khoản giá trị cao. ~0,6M gas/verify = $0,0012 trên Gnosis — **chấp nhận được** | Hợp nhất |

Dòng "không động đến số dư, không migration" đáng được nhấn: với token bất biến (§01.1.3), đây là **một trong rất ít thứ còn nâng cấp được mà không phải deploy token mới**. Nó nâng cấp được chính vì nó nằm ở lớp uỷ quyền (trỏ bằng địa chỉ, xoay được qua §2.7.1) chứ không nằm trong code của token. Đó là lý do kiến trúc của §2.4 đáng giá hơn hẳn khi mọi thứ khác đã đóng băng.
| **Neu khong bao gio co** | Giu commitment + off-chain vinh vien. Chap nhan. Ghi vao hop dong khach hang | Da xong o buoc 2 |

#### 2.6.6. Van de PQ nghiem trong hon: **harvest-now-decrypt-later tren ciphertext**

Chu ky chi anh huong *tuong lai*, nhung **ciphertext ElGamal tren chain cong khai la vinh vien**. Mot may tinh luong tu du manh (CRQC) pha ECDLP tren bn254 G1 → **giai ma nguoc toan bo lich su so tien va so du Zether**. Day la harvest-now-decrypt-later ap dung thang vao bi mat thuong mai. Note hoan toan khong nhac.

Dinh lieu bang so:

| Yeu to | Gia tri |
|---|---|
| Muc tieu di chuyen PQ cua CNSA 2.0 (NSA) cho ha tang quoc gia | **2030–2033** |
| Uoc tinh phan tan cua gioi hoc thuat ve CRQC pha ECC-256 | 2030–2045, khong co dong thuan |
| Tuoi tho bi mat cua **gia ban thu cap FMCG / chiet khau trade** | 2–5 nam |
| Tuoi tho bi mat cua **gia von / dieu khoan hop dong B2B** | 5–15 nam |
| Tuoi tho bi mat cua **so du quy** | 1–3 nam |

Cong thuc Mosca: neu `tuoi_tho_bi_mat + thoi_gian_migrate > thoi_diem_CRQC` thi da tre. Voi B2B settlement gia von (15 nam) va CRQC bi quan (2035), ta **da tre tu bay gio**.

Ba lua chon, phai chon cong khai:

1. **Giu so cai bao mat tren private chain** (ciphertext khong cong khai) — dung voi locked #5, va day la **ly do ky thuat manh nhat cho quyet dinh do**, manh hon ly do gas ma user dua ra.
2. **Chap nhan chan troi bao mat** va ghi thanh so: "gia mua va so du bi lo neu CRQC xuat hien truoc nam X". Chap nhan duoc voi Z-Loyalty (tuoi tho bi mat ~1 nam) va thanh toan nguoi dung cuoi; **khong** chap nhan duoc voi B2B settlement gia von.
3. **Khong dua so tien len chain chut nao** cho luong nhay cam nhat: chain chi giu `keccak256(so_tien ‖ salt)`, so tien nam trong sub-ledger Odoo, doi soat theo lo. Day chinh la **payment mode (4)** trong locked #8, va no la mien nhiem PQ theo dinh nghia. Chi phi: mat tinh cong dong hinh, mat kha nang chung minh khong am on-chain. Doi lai: khong co gi de giai ma.
4. Migration sau nay sang scheme lattice-based confidential transfer — **chua ton tai o muc san xuat**. Khong lap ke hoach dua tren no.

**Khuyen nghi phan tang (dung theo locked #3):**

| Use case | Chain | Che do | Ly do |
|---|---|---|---|
| Loyalty / reward points | Gnosis, Celo (cong khai) | Zether day du | Tuoi tho bi mat ngan; gia tri thap |
| End-user payment | Gnosis, Celo (cong khai) | Zether day du | Nhu tren |
| **B2B settlement (gia von, chiet khau)** | **Private chain** | Zether day du, ciphertext khong cong khai | HNDL |
| B2B settlement — neo bang chung | Gnosis (cong khai) | Chi hash chung tu | Bat bien + kiem toan doc lap |

---

### 2.7. Xoay khoá, thu hồi, khôi phục

#### 2.7.1. Xoay `authKey` — rẻ, phải có timelock, **và phải chặn DoS của guardian**

```solidity
function requestAuthRotation(bytes32 addr, uint8 newScheme, bytes32 newAuthKeyHash,
                             address newVerifier, uint64 deadline, bytes calldata sigByCurrentAuth)
    external;   // digest: "ZETHER_ROTATE_V1", chainid, address(this), addr, authEpoch,
                //          newScheme, newAuthKeyHash, newVerifier, deadline
function executeAuthRotation(bytes32 addr) external;                  // sau ROTATION_DELAY
function vetoAuthRotation(bytes32 addr, bytes calldata sigByGuardians) external;
function forceAuthRotation(bytes32 addr) external;                    // sau FORCE_DELAY, khong the veto
```

`ROTATION_DELAY` mặc định **24 giờ**. Lý do: nếu khoá bị trộm, kẻ trộm sẽ lập tức xoay sang khoá của nó để khoá chủ thật ra ngoài. Timelock + event `AuthRotationRequested` + veto của guardian biến tấn công đó thành một cảnh báo có 24 giờ để xử lý. `authEpoch++` mỗi lần xoay → chữ ký cũ vĩnh viễn vô hiệu (nhờ §2.4.2 digest).

**Bản nháp trước để `cancelAuthRotation` cho guardian mà không giới hạn → guardian độc hại (hoặc guardian mất khoá) chặn vĩnh viễn mọi lần xoay.** Sửa:

| Cơ chế | Chi tiết |
|---|---|
| `vetoAuthRotation` | Cần `g-of-m` guardian. Hiệu lực: huỷ request **và** đặt `status = FROZEN` (không trả lại `ACTIVE` — nếu có tranh chấp thì tài khoản phải dừng, không phải chạy tiếp dưới khoá cũ có thể đã bị trộm) |
| Đếm veto | `vetoCount[addr]++`. Khi `vetoCount >= 2`, `ROTATION_DELAY` cho request tiếp theo đổi thành `FORCE_DELAY` |
| `FORCE_DELAY` | **14 ngày**, và guardian **không thể veto** trong chế độ này. Chủ tài khoản luôn có đường ra, chỉ là đường chậm |
| Reset | `vetoCount` reset về 0 sau một lần `executeAuthRotation` thành công |

Lý lẽ: 14 ngày đủ lâu để một vụ trộm bị phát hiện và xử lý qua đường pháp lý / freeze; và đủ ngắn để một guardian bỏ đi không khoá chết tài sản vĩnh viễn.

**Guardian set — bản nháp trước nhắc tên nhưng không định nghĩa.** Định nghĩa:

```solidity
// slot 4 cua Account (them vao §2.1.4)
bytes32 guardianSetHash;   // keccak256(abi.encode(threshold_g, sortedGuardianAddrs[]))
// Dat/doi qua chinh co che rotation (cung timelock, cung veto), ham rieng:
function requestGuardianChange(bytes32 addr, bytes32 newGuardianSetHash, uint64 deadline,
                               bytes calldata sigByCurrentAuth) external;
```

Guardian là `address` (EOA/multisig/smart account), **không** phải `schnorrAddress` — họ không cần tài khoản Zether. Xác thực bằng `ecrecover` trên digest, so sánh tập ký với `guardianSetHash` do caller cung cấp đầy đủ danh sách (calldata 20 B/guardian = 320 gas cho m=16; rẻ hơn lưu on-chain m slot).

`guardianSetHash = 0` (mặc định) → **không có guardian, không có veto, không có recovery.** Đó là mặc định đúng: đa số tài khoản loyalty không cần guardian, và một guardian mặc định do hệ thống đặt là một backdoor.

#### 2.7.2. Xoay `encKey` — **không làm tại chỗ được**

Số dư được mã hoá dưới `y`. Đường duy nhất: chuyển tài sản sang một `schnorrAddress` mới. Đừng `withdraw()` rồi `deposit()` (lộ số tiền ra công khai — không chấp nhận được), mà thêm một hàm trên **token** (không phải registry):

```solidity
/// @notice Chuyen toan bo so du bi mat sang schnorrAddress moi, khong lo so tien.
/// @dev proof: sigma proof chung minh ciphertext duoi y_old va y_new ma hoa CUNG mot gia tri v,
///      cong voi chung minh biet x_old. Chi phi: 4 ecMul + 2 ecAdd ~ 24,300 gas
///      (ban nhap truoc ghi 12,150 — thieu mot nua: equality proof Chaum-Pedersen can 2 cap).
function migrateAccount(bytes32 fromAddr, bytes32 toAddr, EncryptedTransfer calldata data,
                        bytes calldata authSigOld, bytes calldata authSigNew)
    external returns (bool);
```

**Cần chữ ký của cả hai** (`authSigOld` và `authSigNew`): chữ ký cũ chứng tỏ chủ thật đồng ý ra đi; chữ ký mới chứng tỏ địa chỉ đích là của chính họ chứ không phải địa chỉ kẻ tấn công bơm vào. Bản nháp trước chỉ có một bên.

Liên kết `old → new` **công khai** — đúng với triết lý "lộ danh tính". Registry đánh dấu `status(old) = MIGRATED` và lưu `successorAddr` (slot 5) để indexer nối chuỗi kiểm toán.

**Ranh giới trách nhiệm:** `migrateAccount` nằm trên token, nhưng `status(old) = MIGRATED` nằm trên registry → token phải được phép ghi vào registry. Đó là một quyền nguy hiểm. Giải pháp: registry giữ `mapping(address => bool) trustedTokens` **immutable qua constructor** (danh sách các token được deploy cùng lô), và bất kỳ token nào thêm sau phải qua registry thế hệ mới. **Hoặc** — đơn giản hơn và chọn cái này — `MIGRATED` do **chính chủ** đặt qua `selfMigrate(bytes32 old, bytes32 new, bytes sigByAuth)` trên registry, và token chỉ đọc. Không có token nào ghi vào registry. Bỏ `trustedTokens` hoàn toàn. **Registry chỉ-đọc-từ-token là một bất biến đáng giá.**

Trên factory mở, nhánh `trustedTokens` không chỉ phức tạp mà **không khả thi**: một danh sách immutable các token tin cậy không thể tồn tại khi ai cũng deploy token được, và một danh sách sửa được là đúng cái quyền tập trung mà §2.3(a) vừa loại bỏ. `selfMigrate` là đường duy nhất còn lại, và đó là may mắn — nó vốn là đường tốt hơn.

Hàm này cũng là chỗ mà `migrateAccount` gặp `MigrationSink` của §01.1.17.2 và hai thứ **không** thay thế nhau: `migrateAccount` đổi khoá trong cùng một token; `MigrationSink` đổi token. Một người dùng gặp cả hai tình huống sẽ phải làm hai việc khác nhau, và tài liệu vận hành phải gọi đúng tên từng cái.

#### 2.7.3. Thu hồi — 5 trạng thái, ngữ nghĩa phải đúng (**và sửa một mâu thuẫn nội tại**)

| status | Gửi đi | **Nhận vào** | `rollOver` | `withdraw` | Ai đặt được |
|---|---|---|---|---|---|
| `NONE (0)` | ✗ | ✗ | ✗ | ✗ | — |
| `ACTIVE (1)` | có | có | có | có | — |
| `FROZEN (2)` | **không** | **có** | có | **không** | Compliance role (private) / chỉ chính chủ (public) |
| `REVOKED (3)` | không | **có** ← *sửa* | có | không | Như trên, + timelock 7 ngày |
| `MIGRATED (4)` | không | **có** ← *sửa* | có | không | `selfMigrate` |

**Bản nháp trước mâu thuẫn với chính nó**: nó dùng lý lẽ "chặn inflow làm bên thứ ba vô can mất gas" để biện minh cho `FROZEN` nhận vào, rồi lại chặn inflow ở `REVOKED` và `MIGRATED` — cùng lý lẽ đó áp dụng y hệt. Sửa: **mọi trạng thái != NONE đều nhận được.** Chỉ outflow bị gate. Kết quả:

- Quy tắc trở nên một dòng, dễ kiểm chứng: `assertUsable(from, to)` chỉ kiểm `status(from) == ACTIVE` và `status(to) != NONE`.
- Tiền có thể bị đẩy vào một tài khoản REVOKED và kẹt ở đó. Đó là đúng: một tài khoản bị thu hồi vì lý do AML thì tiền vào nó **nên** bị đóng băng, không nên bị trả lại cho người gửi.
- Người gửi phải được cảnh báo trước ở tầng Odoo (`blockchain.zether.account.chain.onchain_state`), không phát hiện khi đã mất tiền. Lại là "quét QR không phải là đã thu tiền": UI chặn trước.

**Ai được đóng băng?** Trên public chain, một admin key có quyền đóng băng mọi tài khoản là vector tập trung hoá và là trách nhiệm pháp lý. **Mặc định public chain: chỉ `selfFreeze()` (chính chủ, không thể tự unfreeze dưới 72 giờ).** Quyền đóng băng của compliance chỉ bật trên chain profile `private`, qua `IRegistrationPolicy` mở rộng (`ICompliancePolicy`, cùng mô hình immutable). Nếu deployment nào đó cần freeze trên public chain, đó là lựa chọn có ý thức phải ký duyệt, không phải mặc định, và phải được ghi vào `blockchain.chain.profile.compliance_freeze_enabled` để hiển thị trong UI Odoo.

`selfFreeze()` có 72 giờ khoá ngược: chặn kịch bản kẻ trộm freeze để che dấu, rồi unfreeze để rút. 72 giờ là đủ để chủ thật liên lạc.

#### 2.7.4. **Không bao giờ cache trạng thái registry trong token**

Cám dỗ là ta muốn tiết kiệm 2.100 gas. Kết quả sẽ là: đóng băng một tài khoản trên registry nhưng Z-USDC vẫn cho nó rút tiền vì cache chưa hết hạn. Đọc trực tiếp, mỗi lần. Ghi thành một Foundry test: freeze trên registry ở block N, `transferConfidential` ở block N+1 phải revert không có bất kỳ độ trễ nào.

#### 2.7.5. Khôi phục — phân biệt rõ hai thứ

- **Khôi phục quyền uỷ quyền (`authKey`)**: guardian `g-of-m` + timelock 7 ngày + event công khai `RecoveryAnnounced` + khả năng chủ thật huỷ trong 7 ngày đó (bằng `authKey` cũ, nếu còn). Làm được. Interface = chính `requestAuthRotation` nhưng với `sigByGuardians` thay cho `sigByCurrentAuth`, và `RECOVERY_DELAY = 7 ngày` (dài hơn `ROTATION_DELAY = 24h` vì khôi phục là kênh yếu hơn).
- **Khôi phục khả năng giải mã (`encKey`, tức `x`)**: **KHÔNG THỂ.** Mất `x` = mất vĩnh viễn số dư bí mật. Không có admin key nào giải mã được — đó là thuộc tính của giao thức, không phải thiếu sót.

Có một sắc thái mà `_USER-DECISIONS.md` §13.2 thêm vào và nó thu hẹp thiệt hại: **client không cần lưu gì ngoài seed.** Randomness `s` của mỗi giao dịch suy ra bằng PRF từ seed cộng `sendCounter` đọc từ chain, nên khôi phục ví từ seed trắng vẫn chứng minh lại được mọi giao dịch quá khứ (§12 `transferWithProof`). Mất seed vẫn là mất tất cả; nhưng mất *máy* thì không mất gì.

Hai hệ quả bắt buộc, **và chúng là điều kiện mở tài khoản chứ không phải khuyến nghị**:

1. **Sao luu `x` la bat buoc luc cap phat.** Shamir 2-of-3 (share 1: HSM/TEE production; share 2: niem phong offline trong ket, hai nguoi mo; share 3: custodian phap ly hoac ngan hang) hoac co che recovery cua nha cung cap MPC. Quy trinh phai co **truoc khi mo tai khoan dau tien**, phai co dien tap khoi phuc dinh ky (de xuat: 6 thang/lan tren mot tai khoan thu nghiem), va ket qua dien tap phai duoc ghi nhan.
   Chi phi van hanh: voi 4–6 dia chi/phap nhan (§2.3b), mot brand co 1 nha phan phoi lon = ~10 bo Shamir. Voi 200 distributor moi ben 4 dia chi = 800 bo — **khong quan ly noi thu cong**. Do la mot ly do nua de khong cap 1 dia chi/doi tac.
2. Phai nam trong **hop dong voi khach hang**, khong chi trong tai lieu ky thuat. Cau chu de xuat: *"Việc mất khóa giải mã dẫn tới mất vĩnh viễn số dư bảo mật; nhà cung cấp không có và không thể có cơ chế khôi phục. Khách hàng chịu trách nhiệm vận hành quy trình sao lưu Shamir được mô tả tại Phụ lục X."*
1. **Sao lưu `x` là bắt buộc lúc cấp phát.** Shamir 2-of-3 (share 1: HSM/TEE production; share 2: niêm phong offline trong két, hai người mở; share 3: custodian pháp lý hoặc ngân hàng) hoặc cơ chế recovery của nhà cung cấp MPC. Quy trình phải có **trước khi mở tài khoản đầu tiên**, phải có diễn tập khôi phục định kỳ (đề xuất: 6 tháng/lần trên một tài khoản thử nghiệm), và kết quả diễn tập phải được ghi nhận.

   Chi phí vận hành: với 4–6 địa chỉ/pháp nhân (§2.3b), một brand có 1 nhà phân phối lớn = ~10 bộ Shamir. Với 200 distributor mỗi bên 4 địa chỉ = 800 bộ — **không quản lý nổi thủ công**. Đó là một lý do nữa để không cấp 1 địa chỉ/đối tác.

   Với PRF-từ-seed (§13.2 của `_USER-DECISIONS.md`), thứ phải sao lưu là **seed**, không phải từng `x`. Điều đó không giảm số bộ Shamir nếu mỗi địa chỉ có seed riêng — nhưng nó cho phép một seed duy nhất sinh ra cả cây địa chỉ theo kiểu BIP-32, và khi đó 800 bộ thành 1. Đó là thiết kế nên chọn, và nó phải được chốt **trước** khi cấp địa chỉ đầu tiên vì không đổi ngược được.
2. Phải nằm trong **hợp đồng với khách hàng**, không chỉ trong tài liệu kỹ thuật. Câu chữ đề xuất: *"Việc mất khoá giải mã dẫn tới mất vĩnh viễn số dư bảo mật; nhà cung cấp không có và không thể có cơ chế khôi phục. Khách hàng chịu trách nhiệm vận hành quy trình sao lưu Shamir được mô tả tại Phụ lục X."*

#### 2.7.6. Viewing key — một lỗ hổng tuân thủ trong note

Note tuyên bố "tuân thủ 100% AML/KYC và FATF Travel Rule" chỉ bằng cách lộ danh tính người gửi/nhận. **Điều này không đủ Travel Rule**: FATF Recommendation 16 yêu cầu thông tin originator/beneficiary **và số tiền** đi kèm giao dịch, và ở phía VASP thụ nhận phải có khả năng đối chiếu. Danh tính không kèm số tiền không thoả mãn. (Nghiêm ngặt hơn: Travel Rule ràng buộc **VASP**, không ràng buộc một hệ thống ERP nội bộ — nên mức độ áp dụng tuỳ thuộc việc deployment có được coi là VASP hay không. Đó là câu hỏi pháp lý, không phải kỹ thuật; xem section 13.)

Phương án kỹ thuật cụ thể:

```
Them mot ciphertext thu ba trong EncryptedTransfer:
    C_audit = g^v · y_audit^s        (dung chung randomness s voi C_transfer)
    (D dung chung: D = g^s, khong can them)
cong mot equality proof (Chaum-Pedersen) chung minh C_transfer va C_audit ma hoa CUNG v duoi cung s.
Chi phi: +64 bytes calldata (1,024 gas) + 4 ecMul + 2 ecAdd (24,300 gas) ~ 25,300 gas/transfer  (~+11%)
```

Bản nháp trước ghi 13.200 gas; thiếu một nửa vì đếm thiếu cặp thứ hai của equality proof. Sửa.

`y_audit` là khoá của auditor/cơ quan, đăng ký trong chính registry với một flag `isAuditor` (bit trong `meta.reserved`). Bật/tắt theo chain profile.

**Trên factory mở, "bật/tắt theo chain profile" đổi thành "tuỳ chọn theo token".** Người tạo token quyết định archetype của họ có `C_audit` hay không, và điều đó nhìn thấy được qua `interfaceId`. Một token không có `C_audit` là hợp lệ; nó chỉ không dùng được cho luồng nào cần xuất trình theo yêu cầu. Ta đăng ký cả hai biến thể vào catalogue và để người tạo chọn.

**Rủi ro tập trung hoá của chính viewing key — bản nháp trước không nói:** nếu `x_audit` bị lộ, **toàn bộ lịch sử** của mọi giao dịch có `C_audit` bị giải mã cùng một lúc. Đó là một mục tiêu giá trị cao hơn bất kỳ tài khoản đơn lẻ nào. Giảm thiểu:

- `y_audit` là khoá **threshold** k-of-n giữa n auditor (DKG Pedersen), giải mã cần k bên phối hợp. **Không tốn thêm gas on-chain** — on-chain vẫn chỉ là một điểm G1. Toàn bộ độ phức tạp nằm ở quy trình off-chain.
- Xoay `y_audit` theo kỳ (đề xuất 12 tháng). Ciphertext cũ vẫn dưới khoá cũ → phải lưu trữ khoá cũ theo lịch lưu hồ sơ, không huỷ.
- `y_audit` **riêng theo chain profile và theo pháp nhân phát hành**, không dùng chung một khoá toàn cầu.

**Lợi ích phụ, và nó lớn hơn vẻ ngoài:** nếu `x` của một bên bị mất, auditor vẫn tái dựng được **lịch sử số liệu** từ chuỗi `C_audit` — đây là cơ chế khôi phục *số liệu* duy nhất tồn tại, dù không khôi phục được *quyền chi tiêu*. Nghĩa là kế toán vẫn đóng được sổ; chỉ có tiền là khoá. Với một hệ thống ERP, đó là sự khác biệt giữa "một sự cố" và "một thảm hoạ".

Mục này giao với `transferWithProof` (`_USER-DECISIONS.md` §12) và hai thứ **bổ sung nhau chứ không thay thế**: `C_audit` là **mở thường trực cho một bên được chỉ định trước**; `transferWithProof` là **mở chọn lọc, sau sự việc, cho bất kỳ ai người gửi hoặc người nhận muốn thuyết phục**. Một token có thể có cả hai, một trong hai, hoặc không có cái nào. Ràng buộc kỹ thuật đã được kiểm ở §12.4 mục 2: `C_transfer`, `C_debit` và `C_aud` dùng chung `s`, nên lộ `s` mở cả ba — an toàn vì cả ba mã hoá cùng một `v`, nhưng tính chất đó gãy im lặng nếu ai đó thêm một ciphertext thứ tư mang thông tin khác dùng chung `s`.

---

### 2.8. Nhất quán cross-chain

`keccak256(pkX, pkY)` không phụ thuộc chain → `schnorrAddress` **đã giống nhau trên mọi EVM chain, miễn phí** (trong phạm vi một curve — xem §2.0). Vấn đề còn lại chỉ là *trạng thái*: đã đăng ký chưa, `authScheme`/`authKeyHash` hiện tại, và `status`.

| Mô hình | Trust | Chi phí | Rủi ro |
|---|---|---|---|
| **(A) Registry độc lập mỗi chain** | Không thêm giả định nào | ~105.750 gas/chain (~$0,00021 Gnosis) | Phân kỳ: freeze ở chain A, còn ACTIVE ở chain B |
| **(B) Canonical + attestation** | k-of-n attestor quorum | ~23.000 gas/attestation (ECDSA 5-of-9) | Độ trễ lan truyền; quorum bị chiếm |
| **(C) Bridge (CCIP/LayerZero/Hyperlane)** | Bên thứ ba + validator set của bridge | Cao nhất | Thêm một hệ thống có thể sập, cho 32 bytes state |

**Chọn (A) cho đăng ký + (B) cho trạng thái. Loại (C) thẳng.** Lý do loại (C) một dòng: không dẫn một bridge vào đường tin cậy để đồng bộ một số nguyên tăng dần.

#### 2.8.1. Cơ chế (B) cụ thể

Canonical registry đặt trên **private chain** (locked #5 — nó đã là nguồn sự thật cho KYC). Attestor quorum ký:

```
msg = abi.encode("ZETHER_REG_ATTEST_V1", canonicalChainId, targetChainId, schnorrAddress,
                 authScheme, authKeyHash, verifier, status, epoch)
```

`targetChainId` **phải có** — bản nháp trước thiếu. Không có nó, một attestation cho Gnosis dùng được trên Celo; thường thì vô hại (cùng nội dung) nhưng không phải luôn: nếu `verifier` là một địa chỉ contract, nó khác nhau trên mỗi chain, và áp dụng nhầm địa chỉ verifier = tài khoản không xác thực được nữa. Bug im lặng.

```solidity
function applyAttestation(Attestation calldata a, bytes[] calldata sigs, address[] calldata signers)
    external
{
    require(a.targetChainId == block.chainid, "wrong chain");
    require(a.epoch > _epochOf[a.addr], "stale");        // monotonic => replay-safe, khong can nonce
    require(_quorum.verify(_digest(a), sigs, signers), "quorum");
    _apply(a);                                            // ghi de status/authKey local
}
```

- **Permissionless relay**: bất kỳ ai submit được, không cần relayer allowlist. Attestation là dữ liệu tự-xác-thực.
- **Monotonic `epoch`** thay cho nonce → không có vấn đề sắp xếp, không có replay. `epoch` là một bộ đếm tăng dần **trên canonical**, không phải block number (block number của canonical không có ý nghĩa trên mirror).
- **Quorum**: 5-of-9 → **ECDSA multisig** (~23.000 gas) trên Gnosis; **BLS12-381 min-sig** trên Celo nếu chain có EIP-2537 (§2.5.4 đảo chiều kết luận trên rollup).
- Storage layout của `ZetherRegistryMirror` **giống hệt** `ZetherAccountRegistry` → một chain có thể chạy standalone (không nhận attestation) mà token không biết khác biệt.

#### 2.8.2. Vòng luẩn quẩn của tập attestor — **bản nháp trước không xử lý**

Mirror phải biết tập attestor. Nếu tập đó thay đổi, ai báo mirror? Câu trả lời ngây thơ: chính tập hiện tại ký một attestation loại `ATTESTOR_SET_CHANGE`. Nhưng đó là một chuỗi tin cậy không có điểm dừng, và nó có hai chế độ thất bại:

| Chế độ thất bại | Xử lý |
|---|---|
| Mirror bị tụt lại quá xa (offline dài ngày), tập attestor đã đổi nhiều thế hệ | `require(a.epoch <= _epochOf[a.addr] + MAX_EPOCH_GAP)` với `MAX_EPOCH_GAP = 64`. Vượt quá → mirror **tự dừng** và đợi governance re-anchor thủ công. Thà dừng còn hơn áp dụng nhầm |
| Quorum bị chiếm (k khoá bị trộm) | Mirror có một `pauseGuardian` **cục bộ** (multisig của chính deployment trên chain đó) chỉ có **một** quyền: `pauseAttestations()`. Không có quyền đổi state tài khoản. Một quyền, không thể làm điều gì khác |
| Attestor set change bị replay lên một mirror khác | `targetChainId` trong digest (§2.8.1) |
| Attestor mất khoá (không bị trộm) | Rotation bình thường, nhưng phải giữ `k` đủ: 5-of-9 chịu được 4 attestor chết. Nếu chết 5, phải re-anchor thủ công |

**Re-anchor thủ công** = một hàm `governanceSetAttestorSet(bytes32 newSetHash)` chỉ gọi được bởi `pauseGuardian` sau khi đã `pause`, với timelock 7 ngày và event công khai. Đó là đường thoát cuối cùng; nó là một quyền tập trung hoá và phải được ghi nhận là như vậy.

#### 2.8.3. Độ trễ = cửa sổ phơi nhiễm, và tần suất = chi phí

**Độ trễ.** Mục tiêu p95 < 60 giây từ lúc freeze trên canonical đến lúc mirror cập nhật. Phân rã:

| Chặng | Mục tiêu p95 |
|---|---|
| Ghi trên canonical (private chain, Clique period 5 s) | 5 s |
| Finality gate của canonical | 5 s |
| Attestor quan sát + ký (k=5 người ký, song song) | 10 s |
| Gom chữ ký + submit lên mirror | 5 s |
| Block time + finality soft của mirror (Gnosis 5 s soft) | 10 s |
| Đệm an toàn | 25 s |
| **Tổng** | **60 s** |

Chặng đầu sửa so với bản trước (2 s → 5 s): chain private thật là Clique period 5 s, không phải CometBFT/IBFT ~1 block như bản nháp giả định (§01.1.16).

Trong 60 giây đó, phòng tuyến thứ hai là **Odoo gateway từ chối dùng proof ngay lập tức** — đúng tinh thần "quét QR không phải là đã thu tiền": chặn ở tầng gần người dùng trước, chain là lớp cuối cùng chứ không phải lớp duy nhất. Cụ thể: khi `blockchain.zether.account.canonical_state` chuyển sang `frozen`, gateway từ chối ký/relay bất kỳ intent nào của tài khoản đó **trên mọi chain** ngay lập tức, không đợi mirror.

**Tần suất và chi phí** (ước tính cho một deployment có 5.000 tài khoản):

| Sự kiện | Tỷ lệ/năm | Số attestation/năm |
|---|---|---|
| Freeze/unfreeze | 0,5% tài khoản | 50 |
| Revoke | 0,1% | 5 |
| Auth rotation | 10% (chính sách xoay khoá 1 lần/10 năm + sự cố) | 500 |
| Migrate | 1% | 50 |
| Attestor set change | — | 4 |
| **Tổng/chain** | | **~609** |

609 × 23.000 gas = 14,0M gas/năm/chain ≈ **$0,028/năm trên Gnosis**. **Chi phí của cơ chế (B) là không đáng kể; toàn bộ rủi ro nằm ở độ trễ và ở quorum.** Đó là kết luận quan trọng: đừng tối ưu gas ở đây, hãy tối ưu độ tin cậy.
#### 2.8.4. Cây `smartcontracts/` (locked #9)

```
smartcontracts/
  src/
    registry/
      ZetherAccountRegistry.sol
      ZetherRegistryMirror.sol
      interfaces/IZetherAccountRegistry.sol
      interfaces/ISignatureVerifier.sol
      interfaces/IRegistrationPolicy.sol
      interfaces/ICompliancePolicy.sol
      verifiers/EcdsaMultisigVerifier.sol
      verifiers/SchnorrBn254Verifier.sol       # dung chung cho SELF_SCHNORR, FROST, MUSIG2
      verifiers/BlsBn254Verifier.sol
      verifiers/Bls12381Verifier.sol           # min-signature-size
      verifiers/PqCommitmentVerifier.sol
      verifiers/SmartAccount1271Verifier.sol
      policy/OpenRegistrationPolicy.sol
      policy/InviteRegistrationPolicy.sol
      policy/AttestedRegistrationPolicy.sol
      lib/Bn254.sol
      lib/CurveCapability.sol
  test/     # unit + invariant + fork
  script/   # deploy, probe, gas-report
  private/precompiles/slhdsa/                  # Rust plugin, giai doan 2
  hbar/ ton/ sui/ soroban/ cosmwasm/           # thiet ke tren giay (§2.9), xay sau
```

Bố cục này khớp cây ở §01.1.14 (một `foundry.toml` ở gốc `smartcontracts/`, không có tầng `evm/` riêng). `lib/CurveCapability.sol` là cùng một file mà §2.5.5 và `IZetherVerifier.isSupportedOnThisChain()` (§01) đều dùng — viết một lần.

#### 2.8.5. Phía Odoo (`dms_blockchain`, standalone — locked #7)

Không `depends` `dms`; `res.partner` nằm trong `base` nên liên kết đối tác không tạo phụ thuộc. `_name` tiền tố `blockchain.` để không đụng tên với bất kỳ addon nào.

```python
class BlockchainChainProfile(models.Model):
    _name = 'blockchain.chain.profile'
    _description = 'Blockchain Chain Profile'

    name = fields.Char(required=True)
    evm_chain_id = fields.Integer(required=True)          # KHONG dat ten 'chain_id' (de nham M2o)
    is_private = fields.Boolean(default=False)            # truc chain profile, locked #5
    registry_address = fields.Char()
    mirror_address = fields.Char()
    has_bls12381 = fields.Boolean(default=False)          # ghi boi probe, KHONG hardcode
    compliance_freeze_enabled = fields.Boolean(default=False)
    finality_depth = fields.Integer(default=1)
    company_id = fields.Many2one('res.company', default=lambda s: s.env.company)

    _unique_evm_chain = models.Constraint(
        'UNIQUE(evm_chain_id, company_id)', 'Moi chain chi co mot profile cho moi company.')


class BlockchainZetherAccount(models.Model):
    _name = 'blockchain.zether.account'
    _description = 'Zether Account Registry Entry'

    schnorr_address = fields.Char(required=True, index=True)   # 0x + 64 hex
    curve = fields.Selection([('bn254', 'bn254'), ('bls12_381', 'BLS12-381')],
                             default='bn254', required=True)   # xem §2.0: UA phu thuoc curve
    pk_x = fields.Char(required=True)
    pk_y = fields.Char(required=True)
    auth_scheme = fields.Selection([
        ('self_schnorr', 'Self Schnorr'), ('ecdsa_multisig', 'ECDSA Multisig'),
        ('frost_bn254', 'FROST bn254'), ('musig2_bn254', 'MuSig2 bn254'),
        ('bls_bn254', 'BLS bn254'), ('bls_12381', 'BLS12-381'),
        ('pq_commitment', 'PQ Commitment'), ('smart_account_1271', 'Smart Account (EIP-1271)'),
    ], default='self_schnorr', required=True)
    auth_key_hash = fields.Char()
    auth_epoch = fields.Integer(default=0)
    custody_model = fields.Selection([
        ('hsm', 'HSM'), ('mpc', 'MPC'), ('custodial', 'Custodial'),
        ('non_custodial', 'Non-custodial'), ('smart_account', 'Smart Account / Passkey'),
    ])                                                     # locked #6, KHONG len chain
    secret_ref = fields.Char()                             # tro sang HSM/MPC/KMS. KHONG chua khoa.
    partner_id = fields.Many2one('res.partner', index=True)    # base only
    owner_ref = fields.Reference(selection='_selection_owner_ref')  # seam cho dms.*, KHONG dependency
    register_date = fields.Datetime()                      # KHONG dat ten 'date'
    purpose = fields.Selection([
        ('treasury', 'Treasury'), ('loyalty', 'Loyalty'),
        ('settlement', 'B2B Settlement'), ('payroll', 'Payroll'), ('audit', 'Auditor Key'),
    ], required=True)
    canonical_state = fields.Selection([
        ('none', 'None'), ('active', 'Active'), ('frozen', 'Frozen'),
        ('revoked', 'Revoked'), ('migrated', 'Migrated'),
    ], default='none', required=True)
    successor_account_id = fields.Many2one('blockchain.zether.account')
    company_id = fields.Many2one('res.company', required=True,
                                 default=lambda s: s.env.company, index=True)
    chain_state_ids = fields.One2many('blockchain.zether.account.chain', 'account_id')
    divergent = fields.Boolean(compute='_compute_divergent', store=True, default=False)

    _unique_schnorr_address = models.Constraint(
        'UNIQUE(schnorr_address)', 'schnorrAddress phai duy nhat.')
```

Trường `curve` là bổ sung so với bản trước, và nó không phải trang trí: cùng một người có hai `schnorr_address` khác nhau trên hai curve (§2.0), nên nếu thiếu cột này thì UI sẽ hiển thị hai dòng trông như hai người, hoặc tệ hơn, ai đó sẽ "dọn trùng lặp" và gộp chúng lại.

**Bẫy Odoo 19 phải chú ý ở đây** (bẫy #6 trong danh sách dự án): `divergent` là stored computed. Nếu `_compute_divergent` có nhánh nào không gán giá trị, cột sẽ NULL. Với `Boolean` không `required` thì NULL đọc ra `False` nên không chết, **nhưng** nếu sau này ai đó thêm `required=True` thì INSERT sẽ chết im lặng ở một nhánh hiếm. Quy tắc: gán `rec.divergent = False` ở dòng đầu tiên của compute, rồi mới tính.

```python
class BlockchainZetherAccountChain(models.Model):
    _name = 'blockchain.zether.account.chain'
    _description = 'Zether Account State Per Chain'

    account_id = fields.Many2one('blockchain.zether.account', required=True,
                                 ondelete='cascade', index=True)
    profile_id = fields.Many2one('blockchain.chain.profile', required=True, index=True)
    onchain_state = fields.Selection([...], default='none', required=True)
    auth_epoch = fields.Integer(default=0)
    last_synced_block = fields.Integer(default=0)
    # Vong doi giao dich: "broadcast KHONG phai la da dang ky"
    tx_state = fields.Selection([
        ('draft', 'Draft'), ('submitted', 'Submitted to relayer'),
        ('broadcast', 'Broadcast'), ('mined', 'Mined (unconfirmed)'),
        ('final', 'Final'), ('failed', 'Failed'), ('reorged', 'Reorged'),
    ], default='draft', required=True)
    tx_hash = fields.Char(index=True)

    _unique_account_chain = models.Constraint(
        'UNIQUE(account_id, profile_id)', 'Moi tai khoan chi co mot ban ghi tren mot chain.')
```

**`tx_state` là chỗ mà nguyên tắc VietQR được áp dụng trực tiếp.** `onchain_state` chỉ được phép chuyển sang `active` khi `tx_state == 'final'` — tức là sau Finality Gate của chain đó (`profile_id.finality_depth`). Một `register()` đã `broadcast` và đã `mined` vẫn **chưa** là một tài khoản dùng được; UI phải hiện "Đang chờ xác nhận (N/M block)". Bản nháp trước có `canonical_state` nhưng không có vòng đời giao dịch, nên không thể diễn đạt trạng thái này.

Cron một dòng theo đúng bẫy #4 (`ir.cron` không có `fields`, không có `relativedelta` trong eval context):

```xml
<field name="state">code</field>
<field name="code">model._cron_reconcile_registry()</field>
```

Entry point RPC (phục vụ cả `call_kw` và `/json/2`), không nhận `allowed_company_ids`:

```python
@api.model
def zether_account_bootstrap(self, purpose):
    """POST /web/dataset/call_kw/blockchain.zether.account/zether_account_bootstrap
       POST /json/2/blockchain.zether.account/zether_account_bootstrap
    Khong nhan company/partner tu client: suy ra tu env.user."""
    return self._bootstrap(self.env.user, purpose)

def _bootstrap(self, user, purpose):   # private: khong lo qua RPC
    ...
```

Khoá bí mật `x`: **không bao giờ** nằm trong DB — `secret_ref` chỉ là một con trỏ, và giá trị thật nằm trong HSM/MPC/KMS; `ir.config_parameter` giữ endpoint và credential ref, không giữ khoá. Nhắc lại bẫy #5: `password=True` không tồn tại ở Odoo 19 và chưa bao giờ chặn `read()`/RPC/export.

**Bảo mật record-level:** `blockchain.zether.account` chứa `secret_ref` và liên kết pháp nhân → phải có record rule theo `company_id` và một group `blockchain_key_admin` riêng cho quyền đọc `secret_ref`. Vì Odoo không có field-level ACL trong Community, `secret_ref` nên tách sang một model riêng `blockchain.key.ref` với ACL riêng, hoặc để rỗng trong DB và tra cứu qua tên quy ước (`zether/{company}/{schnorr_address}`) trong KMS. **Chọn phương án tên quy ước: không lưu gì cả.** Một cột mà không ai được đọc thì tốt nhất là không tồn tại.

---

### 2.9. Registry trên các chuỗi không phải EVM (thiết kế trên giấy, locked #4)

Bản nháp trước không có mục này. Brief yêu cầu nhất quán cross-chain, và bốn trong năm chuỗi còn lại **phá vỡ một giả định nền tảng của thiết kế EVM**: rằng token có thể gọi registry **đồng bộ** trong cùng một giao dịch.

| Chuỗi | Registry ở đâu | Vấn đề riêng | Giải pháp đề xuất |
|---|---|---|---|
| **HBAR (HSCS)** | Contract EVM y hệt | Gas theo USD-peg; `ecPairing`/`ecMul` bn254 **có** trên HSCS nhưng giá khác. HCS dùng làm audit log cho event registry | Tái sử dụng nguyên code EVM. Neo `AccountRegistered` vào HCS topic để có consensus timestamp pháp lý |
| **TON** | **Vấn đề nghiêm trọng** | Actor model **bất đồng bộ**: một contract **không thể** gọi contract khác và nhận kết quả trong cùng transaction. `require(registry.isRegistered(to))` **không tồn tại** | **Đảo ngược mô hình**: registry phát một **certificate** (cell ký bởi registry key, chứa `addr, pkX, pkY, status, epoch, expiry`). Token verify chữ ký certificate **cục bộ**, không gọi ra ngoài. `expiry` ngắn (đề xuất 1 giờ) để giới hạn cửa sổ freeze. Đổi lại: freeze không tức thì trên TON, trễ tối đa 1 giờ — **phải ghi vào hợp đồng** |
| **SUI** | Object-centric | Một registry là **Shared Object** → mọi transfer chạm vào nó → **serialize toàn bộ throughput** qua consensus, mất lợi thế fast-path | Tách: `AccountCap` là **Immutable Object** cho `(pkX, pkY)` (bất biến, đọc song song, không consensus); chỉ `status` nằm trong một Shared Object nhỏ, và chỉ đọc khi cần. Hoặc dùng chính mô hình certificate như TON |
| **Soroban (Stellar)** | Persistent storage + **TTL** | **Entry registry hết hạn → tài khoản biến mất → số dư khoá vĩnh viễn.** Đây là một chế độ thất bại không tồn tại trên EVM | Registry entry phải ở `Persistent` (không `Temporary`), và **relayer/gateway phải có cron `extend_ttl` cho mọi tài khoản hoạt động**. Chi phí rent phải được mô hình hoá và tính vào giá dịch vụ. Nếu không ai trả rent trong X tháng, tài khoản phải được cảnh báo và di chuyển |
| **CosmWasm** | Contract riêng, `wasmd` | Gọi cross-contract đồng bộ **được** (`WasmQuery::Smart`) → mô hình EVM áp dụng được | Tái sử dụng logic EVM. `x/feegrant` lo gasless register |

**Kết luận kiến trúc phát sinh:** có **hai** mô hình registry, không phải một.

| Mô hình | Chuỗi | Freeze tức thì? | Gas/transfer |
|---|---|---|---|
| **Pull (query đồng bộ)** | EVM, HSCS, CosmWasm | Có | +~9.300 gas |
| **Push (certificate có hạn)** | TON, SUI (khuyến nghị), Soroban | Không — trễ tới `expiry` | Verify chữ ký cục bộ, rẻ hơn |

Mô hình Push là một **suy giảm an ninh có thể đo lường được**: cửa sổ mà một tài khoản đã bị freeze vẫn chi tiêu được = `expiry`. Đặt `expiry = 1 giờ` và ghi con số đó vào SLA tuân thủ. Với luồng B2B settlement giá trị cao, **không dùng mô hình Push** — dùng chuỗi Pull. Đó là một ràng buộc chọn chain theo use case, không phải một chi tiết triển khai.

---

### 2.10. Kiểm chứng bắt buộc (không tin code, tin `pg_constraint` và chain)

**Odoo:**

1. `SELECT conname, contype FROM pg_constraint WHERE conrelid='blockchain_zether_account'::regclass;` phải có dòng `u` (UNIQUE) — `_sql_constraints` dạng list bị Odoo 19 bỏ qua **hoàn toàn**, không warning.
2. Y hệt cho `blockchain_zether_account_chain` (UNIQUE `account_id, profile_id`) và `blockchain_chain_profile` (UNIQUE `evm_chain_id, company_id`).
3. `grep -rn "groups_id" dms_blockchain/` phải trả về rỗng (Odoo 19 đổi thành `group_ids`).
4. Cài `dms_blockchain` trên một DB **không có `dms`** → phải thành công. Đây là kiểm chứng trực tiếp của locked #7 và phải nằm trong CI, không phải làm thủ công.
5. Tạo một bản ghi với mọi `purpose` và mọi nhánh của `_compute_divergent` → `SELECT divergent FROM blockchain_zether_account WHERE divergent IS NULL;` phải trả 0 dòng.

**Foundry:**

6. `register()` với PoP hợp lệ từ **hai** `msg.sender` khác nhau phải cho **storage diff giống hệt** (không chỉ `isRegistered` giống nhau) — chứng minh front-running vô hại (§2.2.2).
7. `register()` với PoP từ chain khác (`chainid` khác trong challenge) phải revert `BadProofOfPossession`.
8. `register()` lần thứ hai trên cùng addr phải revert `AlreadyRegistered`, **không** được thành công im lặng (§2.2.3).
9. Fuzz: `(0,0)`, `pkX >= P`, `pkY >= P`, điểm không trên đường cong, `popS >= n`, `R = O` — tất cả phải revert.
10. **Invariant**: với mọi chuỗi thao tác hợp lệ, `keccak256(abi.encode(pkX, pkY)) == addr` luôn đúng, và `pkX`/`pkY` của một addr **không bao giờ** thay đổi sau `register()` (§2.1.7 bất biến).
11. **Invariant**: `address(registry).balance == 0` và registry không giữ số dư ERC-20 nào (§2.3f).
12. Sau `requestAuthRotation` + `executeAuthRotation`, chữ ký bằng authKey cũ bị từ chối **ở cùng block** (không có độ trễ) nhờ `authEpoch` trong digest (§2.4.2).
13. Freeze trên registry ở block N → `transferConfidential` ở block N+1 revert. Không cache (§2.7.4).
14. `to` ở trạng thái `FROZEN`/`REVOKED`/`MIGRATED` vẫn **nhận** được; chỉ `from` bị chặn (§2.7.3).
15. Guardian veto 2 lần → lần xoay thứ 3 dùng `FORCE_DELAY` và guardian không veto được (§2.7.1).
16. `applyAttestation` với `targetChainId` sai phải revert; với `epoch` cũ hoặc bằng phải revert; với `epoch` nhảy > `MAX_EPOCH_GAP` phải revert (§2.8.2).
17. Bit-packing `meta`: fuzz 5 status × 8 scheme × epoch 2^64−1 × verifier ngẫu nhiên → đọc lại phải bằng giá trị đã ghi (**đây là test chặn lại bug §2.1.4**).
18. **Hai curve**: cùng bộ test chạy trên registry bn254 và registry BLS12-381; `schnorrAddress` của cùng một người trên hai registry phải **khác nhau**, và một PoP của curve này phải revert trên registry của curve kia (§2.0, §2.2.1).

**Trên chain thật:**

19. Probe `CurveCapability.hasBls12381()` trên Gnosis và Celo mainnet, **so sánh returndata chứ không chỉ `success`** (§2.5.5), ghi kết quả vào `blockchain.chain.profile` — không hardcode. Chạy cùng probe đó trên chain private 9000 và khẳng định nó trả `false` — chain đó chạy trước London và `0x0b` không tồn tại (`TRAPS.md`).
20. Đo gas thực tế của `register()`, `assertUsable()`, `transferConfidential` trên Gnosis Chiado và Celo Alfajores; so với bảng ước tính §2.1.3 / §2.2.5 / §2.4.2. **Sai lệch > 25% thì bảng ước tính sai, sửa bảng, không sửa kỳ vọng.**
21. Đo gas thật của verify BLS12-381 min-sig trên một chain có EIP-2537 → xác nhận hay bác bỏ con số 115.500 và do đó bác bỏ hay xác nhận điểm hoà vốn n ≈ 8 trên rollup (§2.5.4).
22. Đo độ trễ thực tế end-to-end của cơ chế attestation (freeze trên canonical → mirror cập nhật) trên testnet, 100 mẫu, báo cáo p50/p95/p99. Mục tiêu p95 < 60 s (§2.8.3).

---

### 2.11. Bảng số tổng hợp (để tra cứu nhanh)

| Đại lượng | Giá trị | Cơ sở |
|---|---|---|
| `register()` (bn254) | ~105.750 gas | §2.2.5 |
| `register()` (BLS12-381) | ~160.000 gas | §2.2.5 |
| `register()` trên Gnosis @2 gwei | $0,00021 | xDAI = $1 |
| `register()` trên Ethereum L1 @10 gwei | $3,17 | ETH = $3.000 |
| Kiểm tra registry trong `transferConfidential` | ~9.300 gas | §2.1.3 |
| Chi phí ròng của hash identity (vs point identity) | +3.176 gas | §2.1.2 |
| Schnorr PoP verify | 12.850 gas | §2.2.1 |
| ECDSA multisig 3-of-5 | ~14.120 gas | §2.4.2 |
| BLS12-381 min-sig verify | ~115.500 gas | §2.5.2 |
| BLS12-381 min-pubkey verify | ~153.100 gas | §2.5.2 |
| BLS bn254 verify | 150.000–180.000 gas | §2.5.2 |
| Hoà vốn BLS vs ECDSA, L1/Gnosis | n ≈ 29 | §2.5.4 |
| Hoà vốn BLS vs ECDSA, rollup (Celo) | **n ≈ 8** | §2.5.4 |
| FALCON-512 verify on-chain | 0,6M–2,5M gas ($0,003 Gnosis) | §2.6.2 |
| SLH-DSA-SHA2-128s verify on-chain | ~0,6M gas | §2.6.3 |
| EIP-7623 floor bind khi | `execution_gas < 24 × non_zero_bytes` | §2.1.1 |
| G1 point on-chain: bn254 / BLS12-381 | 64 B / **128 B** | §2.1.1 |
| Storage/account: bn254 / BLS12-381 | 4–6 slot / 6–8 slot | §2.1.4 |
| Attestation 5-of-9 ECDSA | ~23.000 gas | §2.8.1 |
| Attestation/năm/chain (5.000 tài khoản) | ~609 | §2.8.3 |
| Tổng chi phí attestation/năm/chain | ~$0,028 | §2.8.3 |
| Độ trễ freeze canonical → mirror, p95 mục tiêu | 60 s | §2.8.3 |
| Cửa sổ phơi nhiễm mô hình Push (TON/SUI/Soroban) | = certificate `expiry`, đề xuất 1 giờ | §2.9 |
| `ROTATION_DELAY` / `FORCE_DELAY` / `RECOVERY_DELAY` | 24 h / 14 ngày / 7 ngày | §2.7 |
| `selfFreeze()` khoá ngược | 72 h | §2.7.3 |
| Chi phí 20.000 lần đăng ký (5.000 tài khoản × 4 chain) | $4,20 trên Gnosis | §2.2.5 |
| Bể tài trợ $1.000 không gate → số lần đăng ký rác | 4,76 triệu, 457 MB state | §2.2.4 |

---

### 2.12. Câu hỏi còn mở (cần quyết định của người, không phải của tài liệu)

1. **`encKey` và FIPS 140-2 L3 (§2.4.4).** Note cam kết HSM L3 cho mọi private key. Không làm được với alt_bn128, và cũng không làm được với BLS12-381 — đổi curve không cứu được. Chấp nhận TEE cho `encKey` và giữ HSM cho `authKey`, hay đầu tư HSM lập trình được ($30k–80k, 3–6 tháng)? **Đây là cam kết với khách hàng, phải trả lời trước khi ký.**
2. **FIPS 206 (§2.6.1).** Ai chịu trách nhiệm kiểm tra lại trạng thái FIPS 206 trước mỗi lần phát hành tài liệu bán hàng có chữ "FALCON"? Đề xuất: một mục trong checklist release.
3. **Chân trời HNDL cho B2B settlement.** Chấp nhận phương án 1 (private chain), 2 (chấp nhận rủi ro có ghi nhận), hay 3 (không đưa số tiền lên chain chút nào — payment mode 4)? Ba phương án này có chi phí triển khai rất khác nhau. Nối với điều kiện mở lại D1 ở `_USER-DECISIONS.md` §19.
4. **Travel Rule (§2.7.6).** Deployment này có được coi là VASP theo pháp luật Việt Nam không? Nếu có, `C_audit` là bắt buộc và `y_audit` phải là khoá của cơ quan nào? Nếu không, `C_audit` có thể là tuỳ chọn và tiết kiệm 25.300 gas/transfer. Câu hỏi pháp lý, chuyển sang section 13.
5. **Ngưỡng `MAX_EPOCH_GAP` và quy trình re-anchor (§2.8.2).** Ai giữ `pauseGuardian` của mỗi mirror? Đề xuất: multisig 3-of-5 gồm 2 kỹ thuật + 2 tài chính + 1 pháp chế. Cần xác nhận.
6. **Chính sách số lượng địa chỉ/pháp nhân (§2.3b, §2.7.5).** 4–6 địa chỉ/pháp nhân (khuyến nghị) hay 1 địa chỉ/đối tác (linkability tốt hơn nhưng 800 bộ Shamir)? Ảnh hưởng trực tiếp đến chi phí vận hành. Nếu chọn cây khoá kiểu BIP-32 từ một seed (§2.7.5) thì câu hỏi này gần như biến mất — nhưng phải chốt **trước** khi cấp địa chỉ đầu tiên.
7. **Chain nào cho use case nào (§2.9).** Bảng phân tầng đã đề xuất, nhưng nó khoá cứng việc B2B settlement không chạy trên public chain. Nếu khách hàng muốn B2B trên Gnosis vì lý do thương mại, phải có văn bản chấp nhận rủi ro HNDL.
8. **MuSig2 hay FROST cho tài khoản nhóm (§2.4.3).** Nếu nhà cung cấp MPC đang dùng không hỗ trợ FROST trên bn254, `ECDSA_MULTISIG` là phương án lùi — nhưng khi đó gas cao hơn và cơ cấu nhóm lộ ra on-chain. Cần hỏi provider trước khi chốt.
9. **Registry nào cho curve nào.** Factory mở hỗ trợ cả hai curve, nên về nguyên tắc cần **hai** registry trên mỗi chain. Ta deploy và đứng sau cả hai, hay chỉ bn254 và để ai cần BLS tự deploy? Câu hỏi ngân sách audit, cùng nhóm với §01.1.19 câu 4.