> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

## 03. Zether: mat ma hoc, 128-bit range proof, epoch va rollOver

> Phạm vi: lõi thanh toán bảo mật của `dms_blockchain`. Mọi thứ ở đây chạy được với **N = 2** (lộ sender + receiver) — tức là **Basic Zether** của paper FC 2020, **không phải** `anonymous-zether` của ConsenSys. Bỏ anonymity set là quyết định đúng và nó xoá luôn one-out-of-many proof (chi phí verify O(N)); phần còn lại của mục này giả định N = 2 xuyên suốt.
>
> Addon `dms_blockchain` là **standalone**: không `depends` vào `dms`. Không một dòng nào trong mục này được phép tham chiếu model của `dms`.

---

### 3.0. Những giả định ẩn — nói thẳng ra trước khi đi tiếp

Bản nháp trước ngầm định 14 thứ mà không viết ra. Một implementer đọc nó sẽ đoán sai ít nhất bốn trong số đó. Liệt kê đầy đủ, mỗi giả định kèm hệ quả nếu sai:

| # | Giả định ẩn | Nếu sai thì hỏng ở đâu | Xử lý ở mục |
|---|---|---|---|
| A1 | ElGamal ở đây là **exponential ElGamal** — plaintext nằm ở số mũ (`g^b`), nên giải mã = giải DL. Không phải ElGamal "textbook" nhân bản. | Toàn bộ lập luận về `MAX` vô nghĩa; người ta sẽ chọn `MAX = 2^128` và tưởng không sao | 3.2 |
| A2 | **Khoá Schnorr trong registry và khoá giải mã ElGamal là CÙNG một `x`.** | Nonce reuse khi ký Schnorr làm lộ `x` ⇒ lộ **toàn bộ lịch sử số dư**, hồi tố | 3.1.4 |
| A3 | Generators `g, h, {g_i}, {h_i}` của Bulletproof là **NUMS** (nothing-up-my-sleeve), không ai biết DL giữa chúng | Biết `α` với `h = g^α` ⇒ commitment không binding ⇒ **giả mạo range proof ⇒ in tiền** | 3.1.5 |
| A4 | Điểm nhận từ calldata luôn được kiểm **on-curve + prime-order subgroup + khác điểm vô cực** | BN254 cofactor = 1 nên on-curve là đủ; **BLS12-381 G1 cofactor ≠ 1** ⇒ bỏ check là lỗ hổng | 3.1.6 |
| A5 | `underlying` ERC-20 "cư xử tử tế": không fee-on-transfer, không rebase, không blacklist | USDT/USDC blacklist escrow ⇒ **đóng băng vĩnh viễn toàn bộ số dư mã hoá**, không có đường thoát | 3.7.4 |
| A6 | `scale_exponent` là hằng số toàn hệ thống (bản nháp ghi cứng `= 2`) | Z-VND không có đơn vị con ⇒ scale 2 lãng phí 6.6 bit dải và làm sai giới hạn giao dịch | 3.2.4 |
| A7 | Client giữ được sổ cục bộ nên không cần BSGS | Mất máy / cài lại app / đổi thiết bị là chuyện thường ngày ⇒ recovery phải là đường **first-class**, không phải fallback | 3.2.5 |
| A8 | Có thể đọc lại **toàn bộ** log `ConfidentialTransfer` từ block genesis | RPC công cộng cap `eth_getLogs` ở 10k log / 2k block; node non-archive prune log ⇒ recovery gãy | 3.2.6 |
| A9 | `fee` là public scalar và relayer nhận fee **ở dạng thanh khoản** | Nếu fee vào số dư mã hoá, relayer phải `withdraw` để tiêu ⇒ lộ số, tốn gas, phá kinh tế relayer | 3.4.3 |
| A10 | `feeRecipient` **không** nằm trong Fiat-Shamir challenge (để `MODE_OPEN` hoạt động) | Nếu nằm trong challenge, `MODE_OPEN` chết; nếu không nằm, mọi relayer copy được calldata ⇒ đua fee | 3.4.4 |
| A11 | Rollover đổi `acc` theo **cờ per-account** `RollOverMode` | **[BẢN 5, 2026-09-03]** Mâu thuẫn permissionless-vs-owner-exclusive đóng lại bằng một cờ: `PUBLIC` mặc định, `OWNER_ONLY` opt-in cho R3/R4. Xem 3.5.3 | 3.5.3 |
| A12 | Verifier Solidity chứa được toàn bộ vector generator trong bytecode | `2·n·m` điểm × 64 B; cấu hình 128/128 = **32,768 B > EIP-170 (24,576 B)** ⇒ không deploy được | 3.3.5 |
| A13 | Điểm trong calldata truyền **uncompressed** | Compressed rẻ hơn 32 B nhưng tốn 1,349 gas/điểm để decompress on-chain ⇒ đắt hơn 2.6× | 3.3.4 |
| A14 | Kiểm toán viên/cơ quan thuế chỉ cần thấy **đồ thị**, không cần thấy **số tiền** | Sai với kiểm toán BCTC và với thuế VN; Zether nguyên bản **không có** cơ chế nào cho việc này | 3.4.6 |

Bốn trong số này (A3, A11, A12, A13) là lỗi có thể làm dự án phải làm lại contract. A14 là lỗ hổng nghiệp vụ lớn nhất và nó nằm ngay trong khẩu hiệu "confidentiality with accountability" của note.

---

### 3.1. Nhóm, đường cong và mức an toàn thật sự

#### 3.1.1. Precompile và giá

ElGamal cộng đồng hình của Zether chỉ cần một nhóm cyclic mà DDH khó. Trên EVM lựa chọn mặc định là **G1 của alt_bn128 (BN254)** vì EIP-196 cho precompile sẵn:

| Precompile | Địa chỉ | Gas (sau EIP-1108) | Zether dùng để | Có ở đâu |
|---|---|---|---|---|
| `ALT_BN128_ADD` | `0x06` | 150 | cộng/trừ đồng hình `(C, D)`, MSM của Bulletproofs | mọi EVM chain từ Byzantium |
| `ALT_BN128_MUL` | `0x07` | 6,000 | mọi scalar mul trong verifier | như trên |
| `ALT_BN128_PAIRING` | `0x08` | 45,000 + 34,000·k | **Bulletproofs không dùng**; Groth16 profile dùng, k = 4 | như trên |
| `MODEXP` | `0x05` | ≥ 200, thực tế 1,349 cho một sqrt mod p | decompress điểm — **nên tránh**, xem 3.3.4 | như trên |
| `BLS12_G1ADD` (EIP-2537) | `0x0b` | 375 | profile BLS12-381 | Ethereum từ Prague/Pectra (2025); Gnosis theo sau; Celo qua op-geth Isthmus |
| `BLS12_G1MSM` (EIP-2537, k=1) | `0x0c` | 12,000 | profile BLS12-381 | như trên |

**Bẫy probe precompile mà bản nháp nói "probe lúc deploy" nhưng không nói probe thế nào.** Trên EVM, `staticcall` tới một địa chỉ **không có code và không phải precompile** trả về `success = true` với `returndatasize = 0`. Kiểm `success` là **sai**. Probe đúng:

```solidity
function _hasBls12G1Add() internal view returns (bool) {
    // vector: G1_generator + G1_generator = 2G, encoding EIP-2537 (2 x 128 byte in, 128 byte out)
    bytes memory input = _BLS_PROBE_INPUT;      // 256 byte hằng số
    bytes memory out = new bytes(128);
    bool ok;
    assembly {
        ok := staticcall(gas(), 0x0b, add(input, 32), 256, add(out, 32), 128)
        // phải kiểm CẢ returndatasize
        ok := and(ok, eq(returndatasize(), 128))
    }
    return ok && keccak256(out) == _BLS_PROBE_EXPECTED;
}
```

Kiểm cả `returndatasize()` **và** so hash kết quả với vector đã biết. Không có bước thứ hai thì một chain cài precompile sai/khác encoding vẫn pass.

#### 3.1.2. Về ~100 bit của BN254

Kim–Barbulescu (exTNFS, CRYPTO 2016) và các ước lượng cập nhật (Barbulescu–Duquesne 2019; Menezes–Sarkar–Singh 2016) hạ độ an toàn của BN254 từ 128 xuống khoảng **100–110 bit**. Số dùng cho kế hoạch: **100 bit** (chọn cận dưới, thận trọng). Cần tách bạch hai thứ mà note gộp làm một:

- DLP thuần trong G1 (order 254 bit) vẫn ≈ **127 bit** dưới Pollard rho.
- Nhưng BN254 có embedding degree 12, nên đối thủ **chuyển** bài toán G1-DLP sang $\mathbb{F}_{p^{12}}$ (≈ 3072 bit) qua pairing và giải ở đó với exTNFS. Cận trên hiệu dụng vì vậy là `min(127, ~100) ≈ 100 bit`. Việc Zether không gọi `ecPairing` **không** cứu được điều này — đối thủ gọi pairing, không phải hợp đồng.
- BLS12-381: $\mathbb{F}_{p^{12}}$ ≈ 4569 bit ⇒ **117–126 bit** sau exTNFS (dải, không phải một số). Đây là khác biệt thực chất, không phải marketing.

#### 3.1.3. "Money at rest" nghĩa là gì

Phải tách hai loại đổ vỡ, vì hệ quả hoàn toàn khác nhau:

| | Soundness break (giả mạo proof) | Hiding break (giải mã ciphertext cũ) |
|---|---|---|
| Hệ quả | rút trộm khỏi escrow pool | lộ toàn bộ giá, số dư, dòng tiền lịch sử |
| Trần thiệt hại | **có trần cứng** = số ERC-20 đang khoá trong pool | không trần |
| Phát hiện được không | **Có.** Invariant `IERC20(underlying).balanceOf(zetherToken) >= totalDepositedScaled - totalWithdrawnScaled` là công khai, kiểm mỗi block | **Không.** Hoàn toàn ngoại tuyến, không để lại dấu vết |
| Thời điểm rủi ro | chỉ khi đường cong đã gãy | **hồi tố** — ciphertext nằm bất biến trên sổ cái, "harvest now, decrypt later" |
| Thời gian phản ứng | phút (watcher gọi `pause()`) | bằng 0 — không có gì để phản ứng |

Kết luận cụ thể: rủi ro thực sự của BN254 **không** phải bị in tiền (invariant pool chặn được và có thể `Pausable` tự động), mà là **bí mật thương mại có hạn dùng**. Phát biểu trung thực để đưa vào hợp đồng dịch vụ: *trên public chain với BN254, phải giả định mọi số tiền confidential đều có thể bị giải mã bởi một đối thủ đủ nguồn lực trong khoảng 2035–2045.*

Con số cho phần lượng tử, để không phải tranh cãi bằng cảm tính: Shor trên ECDLP 254-bit cần **≈ 2,330 logical qubit và ≈ 1.3 × 10^11 Toffoli gate** (Roetteler–Naehrig–Svore–Lauter, ASIACRYPT 2017). Với overhead surface code ở error rate 10^-3, đó là **10^6–10^7 physical qubit**. Không ai có con số đó trước 2035 theo mọi lộ trình công bố. Nhưng ciphertext ghi hôm nay vẫn nằm đó năm 2040 — đó mới là vấn đề.

Đề xuất cụ thể: thêm trường cấu hình `confidentiality_horizon_years` trên `blockchain.zether.token`, và một deploy-time guard từ chối `curve_profile = 'bn254'` khi `chain_profile = 'public'` và horizon > 10.

Một điểm **mâu thuẫn trong chính note**: mục TOKEN nói registry mở rộng sang "FALCON kháng lượng tử". Chữ ký hậu lượng tử ở registry **không** làm số dư Zether kháng lượng tử — ElGamal và Bulletproofs đều dựa trên DL, Shor phá cả hai, và phá **hồi tố** mọi ciphertext đã ghi. Chân trời bảo mật của Zether bị chặn bởi CRQC, không phải bởi exTNFS. Không có đường nâng cấp PQ cho Zether; nếu cần thì phải đổi hẳn giao thức (lattice-based commitment + lattice range proof), không phải đổi chữ ký. FALCON ở registry chỉ bảo vệ **quyền điều khiển tài khoản trong tương lai**, không bảo vệ **bí mật của quá khứ**. Viết đúng như vậy vào tài liệu bán hàng, đừng để sales hiểu ngược.

#### 3.1.4. Tái dùng khoá giữa Schnorr và ElGamal — rủi ro vận hành số một

Trong Zether, `y = g^x` vừa là **khoá công khai ElGamal** vừa là **khoá xác thực Schnorr**. Đây là tái dùng khoá xuyên hai scheme. Về lý thuyết nó chứng minh được an toàn trong mô hình của paper (cả hai đều là DL trên cùng nhóm, và Schnorr PoK chính là relation R1 của transfer). Về vận hành nó tạo ra một chế độ hỏng rất tệ:

> **Ký Schnorr hai lần với cùng nonce `k` trên hai message khác nhau ⇒ lộ `x` ngay lập tức** (hai phương trình, hai ẩn: `s₁ = k + c₁x`, `s₂ = k + c₂x` ⇒ `x = (s₁-s₂)/(c₁-c₂)`). Và `x` là khoá **giải mã**. Lộ `x` không chỉ mất tiền — nó lộ **toàn bộ số dư và mọi khoản chuyển trong lịch sử**, hồi tố, không thể thu hồi.

Yêu cầu bắt buộc, không thương lượng:

1. Nonce Schnorr sinh theo **RFC 6979 deterministic** (HMAC-DRBG với `x`, message hash, và domain tag) **hoặc** hedged: `k = H(x ‖ msg ‖ 32 byte CSPRNG)`. Không bao giờ dùng RNG thuần trên thiết bị nhúng.
2. Nonce của **Sigma protocol** trong transfer (các giá trị `k_x, k_v, k_s, k_b`) chịu đúng quy tắc trên. Đây là chỗ dễ quên vì nó không "trông giống chữ ký".
3. **Một khoá Zether cho mỗi (chain, pháp nhân)**, không dùng chung một `x` xuyên chain. Dẫn xuất: `x_chain = KDF(seed, "ZETHER_V1" ‖ chainId ‖ entityId) mod q`, với reduction dùng RFC 9380 `hash_to_field` (bias < 2^-128), **không** dùng `keccak256(...) % q` (bias ~2^-2 ở bit cao, đủ để làm yếu bài toán nếu lặp).
4. Test bắt buộc: `Schnorr.nonceReuse.t.sol` + một fuzz test phía Rust ép cùng nonce và khẳng định key recovery thành công — để chứng minh rằng test đang thật sự kiểm cái nó nói.

#### 3.1.5. Generators phải là NUMS — và phải chứng minh được là NUMS

Bulletproof commit `V = g^v · h^γ`. Nếu ai đó biết `α` sao cho `h = g^α`, commitment mất tính binding và **mọi range proof đều giả mạo được** ⇒ in tiền không giới hạn. Điều này không phát hiện được bằng test chức năng: proof giả mạo vẫn verify pass.

Quy tắc, viết vào spec:

```
h      = hash_to_curve_G1("ZETHER/BN254/H/v1")
g_i    = hash_to_curve_G1("ZETHER/BN254/G/v1/" || uint16_be(i))   , i = 0..n_max-1
h_i    = hash_to_curve_G1("ZETHER/BN254/H/v1/" || uint16_be(i))   , i = 0..n_max-1
g      = generator chuẩn của BN254 G1 (1, 2)
```

- `hash_to_curve_G1` theo **RFC 9380** (SSWU cho BN254, hoặc try-and-increment nếu chấp nhận non-constant-time — ở đây input công khai nên timing không quan trọng).
- Giá trị tính **off-chain một lần**, hard-code vào contract dữ liệu (xem 3.3.5).
- Test `Generators.nums.t.sol` **tính lại toàn bộ vector trong test bằng một implementation độc lập** (Rust) và so từng byte. Không có test này thì không có gì ngăn một dev "tối ưu" bằng cách đặt `h = g·2`.
- Cross-implementation: cùng vector generator phải xuất hiện trong `testvectors/zether_generators_bn254_v1.json` và được cả prover Rust lẫn verifier Solidity nạp.

#### 3.1.6. Validation điểm đầu vào

Mọi điểm đọc từ calldata (`C_out, D_out, C_debit, C_aud, D_aud`, mọi điểm trong proof) phải qua:

| Kiểm | BN254 G1 | BLS12-381 G1 |
|---|---|---|
| Toạ độ < p | bắt buộc | bắt buộc (precompile tự reject, nhưng kiểm sớm để lỗi rõ ràng) |
| On-curve `y² = x³ + 3` | bắt buộc | bắt buộc |
| Prime-order subgroup | **miễn phí** — cofactor h = 1 | **bắt buộc** — cofactor `h = 0x396c8c005555e1568c00aaab0000aaab`; EIP-2537 precompile có tự kiểm, nhưng nếu tự viết arithmetic thì phải tự kiểm |
| Khác điểm vô cực | bắt buộc cho `D` (nếu `D = O` thì `s = 0` ⇒ `C = g^v` ⇒ **lộ v công khai**) | như trên |
| `y_from != y_to` | bắt buộc (`require(from != to)`) — self-transfer làm phép đồng hình cộng và trừ trên cùng slot, kết quả không xác định | như trên |

Chi phí: on-curve check = 3 `mulmod` + 1 so sánh ≈ 60 gas/điểm. Với 25 điểm ≈ 1.5k gas. Không có lý do gì để bỏ.

#### 3.1.7. Curve agility và cái bẫy migration

Đóng gói phép nhóm sau `IZetherCurve` với ba profile:

| profile | curve | ops | an toàn | ghi chú |
|---|---|---|---|---|
| `EVM_BN254` | alt_bn128 G1 | `0x06`/`0x07` | ~100 bit | rẻ nhất, có ở **mọi** EVM chain, cofactor 1 |
| `EVM_BLS12_381` | BLS12-381 G1 | `0x0b`/`0x0c` | 117–126 bit | **≈ 2.05× gas** (12,000/6,000 mul; 375/150 add), calldata **×2** (điểm G1 = 128 B thay vì 64), cofactor ≠ 1 |
| `NATIVE_RISTRETTO255` | ristretto255 | native | ~126 bit | Move / Rust WASM / Soroban; **không** có precompile EVM, chỉ dùng cho 5 hệ sinh thái ngoài EVM |

Cảnh báo mà không ai nghĩ tới cho đến khi muộn: **keypair Zether gắn chặt vào curve.** Đổi curve = register lại toàn bộ account **và** đẩy mọi số dư qua một vòng `withdraw` → `deposit` công khai. Tại đúng khoảnh khắc đó, **số dư của tất cả mọi người bị lộ công khai** — không phải rò rỉ dần, mà là một snapshot đầy đủ, vĩnh viễn, của toàn bộ treasury mọi đối tác, ghi trên public ledger.

Bản nháp dừng ở đó. Cần đi tiếp: **có cách giảm thiểu, và nó phải nằm trong plan ngay từ đầu.**

| Chiến lược migration | Rò rỉ | Chi phí | Khi nào dùng |
|---|---|---|---|
| Big-bang withdraw/deposit | **toàn bộ số dư mọi account, một block** | thấp | không bao giờ trên public chain |
| Staggered ngẫu nhiên 90 ngày, số tiền chia nhỏ ngẫu nhiên | lộ tổng, không lộ thời điểm/phân bổ | ×5–20 số tx | public chain, bắt buộc |
| Migrate trên private chain trước, chỉ public sau khi curve đã chốt | **bằng 0** | bằng 0 | **đúng thứ tự đã chốt của user** |
| Bridge contract giữ cả hai curve, proof of equal-value xuyên curve | bằng 0 | mạch ZK xuyên curve, 6–12 tháng R&D | không đáng ở giai đoạn này |

Đây là lý do kỹ thuật mạnh nhất ủng hộ thứ tự đã chốt (private chain trước): hãy chọn xong curve sẽ sống chung, trên một sổ cái chưa công khai, rồi mới lên public. Ghi vào roadmap như một **gate**, không phải một lời khuyên: *không deploy Z-token nào lên public chain trước khi `curve_profile` được đóng băng bằng một quyết định có chữ ký.*

---

### 3.2. Sai lầm nghiêm trọng nhất trong note: `MAX = 2^128 - 1` làm số dư không giải mã được

#### 3.2.1. `MAX` là cận giải mã, không phải tham số range proof

`MAX` trong Zether **không phải** tham số của range proof. Nó là **cận giải mã**. Số dư nằm dưới dạng `(C, D) = (g^b · y^r, g^r)`; chủ tài khoản tính `g^b = C · D^{-x}` rồi phải **giải discrete log** để lấy `b`. BSGS/Pollard kangaroo tốn `O(sqrt(MAX))` phép nhóm với bảng giant-step `sqrt(MAX)·32` byte.

| MAX | số bước BSGS | bảng (khoá 32 B) | Android tầm trung (~1.5 µs/point-add, Rust ARM64) | Desktop x86 (~0.35 µs) |
|---|---|---|---|---|
| 2^32 | 65,536 | 2 MB | ~0.10 s | ~0.02 s |
| 2^40 | 1.05 M | 34 MB | ~1.6 – 3 s | ~0.4 s |
| 2^48 | 16.8 M | 537 MB | ~30 – 60 s, **hết RAM trên máy tầm trung** | ~6 s |
| 2^64 | 4.3 G | 137 GB | không khả thi | không khả thi |
| **2^128** | **1.8 × 10^19** | — | **bất khả thi về mặt vật lý** | **bất khả thi** |

*(Bảng có thể rút gọn bằng Pollard kangaroo — bộ nhớ O(1) thay vì O(sqrt(MAX)) — nhưng số bước vẫn ~1.4·sqrt(MAX) và không song song hoá tốt trên điện thoại. Kangaroo giải quyết vấn đề RAM ở 2^48, không giải quyết vấn đề thời gian ở 2^64.)*

Nên: `uint256 public constant MAX = (1 << 128) - 1;` như note viết **làm hỏng giao thức** — không ai đọc được số dư của chính mình nữa. Đây là lỗi kỹ thuật, không phải quyết định thiết kế, và phải sửa.

#### 3.2.2. Tách ba hằng số, đừng gộp một

| Hằng số | Ai quan tâm | Giá trị đề xuất | Ràng buộc |
|---|---|---|---|
| `RANGE_BITS_VALUE` (n_v) | Bulletproof, verifier on-chain | 32 (hoặc 40 cho Z-VND) | quyết định gas; `n_v ≤ n_b` |
| `RANGE_BITS_BALANCE` (n_b) | Bulletproof, verifier on-chain | 64 | phải thoả `2^{n_b} > total_supply_scaled` với biên ≥ 2^10 |
| `DECRYPT_BOUND` | **chỉ client** | 2^40 cho mỗi khoản chuyển riêng lẻ | không xuất hiện trong contract |

Ba thứ này độc lập. Contract chỉ biết `n_v`, `n_b`. Client chỉ biết `DECRYPT_BOUND`. Không có hằng số nào tên `MAX`.

Ràng buộc số học phải kiểm ở deploy:

```
require(n_v <= n_b, "value range exceeds balance range");
require(n_b <= 64, "balance range beyond practical decryption/recovery");
require((1 << n_b) > totalSupplyScaled * 1024, "insufficient headroom");
```

Vì sao `n_b ≤ 64`: một số dư vượt `2^{n_b}` không "tràn" (nhóm là mod q ≈ 2^254) — nó chỉ trở thành **không chứng minh được**, tức là tài khoản **vĩnh viễn không tiêu được tiền**. Không có đường sửa: bạn không thể tạo range proof cho một giá trị ngoài range. Đây là chế độ hỏng câm lặng nguy hiểm nhất của thiết kế, và headroom 2^10 là để một attacker không đẩy được nạn nhân qua trần bằng cách gửi nhiều khoản nhỏ.

Định lượng griefing đó: với `n_v = 32`, `n_b = 64`, kẻ tấn công cần **2^32 ≈ 4.3 tỷ giao dịch max-size** để đẩy một tài khoản qua trần. Ở 31,000 tx/ngày (trần throughput Gnosis, xem 3.3.6) đó là **380,000 năm**. Không phải mối đe doạ. Nhưng với `n_v = 40, n_b = 48` (một cấu hình "tiết kiệm gas" mà ai đó sẽ đề xuất) con số là 256 giao dịch — **khả thi trong một buổi chiều**. Ghi công thức vào spec: `2^{n_b - n_v}` là số giao dịch tối đa mà tài khoản chịu được; yêu cầu `n_b - n_v >= 24`.

#### 3.2.3. Đổi đơn vị nội bộ, đừng lưu wei

Zether ledger dùng **đơn vị nội bộ riêng**, độc lập với `decimals` của ERC-20 gốc:

```solidity
uint8 public immutable scaleExponent;        // số chữ số thập phân mà ledger giữ lại
uint256 public immutable scaleDivisor;       // 10 ** (underlyingDecimals - scaleExponent)

function deposit(bytes32 acct, uint256 erc20Amount) external {
    require(erc20Amount % scaleDivisor == 0, "ZTH: dust not representable");
    uint256 scaled = erc20Amount / scaleDivisor;
    require(scaled > 0 && scaled < (1 << RANGE_BITS_VALUE), "ZTH: out of range");
    // ... đo delta thực tế, xem 3.7.4
}
```

Vấn đề "4.29e9 wei = 0.00000000429 token" mà note nêu **biến mất hoàn toàn** chỉ bằng việc đổi đơn vị, không cần đụng tới range proof. Với `scaleExponent = 2` trên một token 18 decimals: `2^32` đơn vị = **$42.9 M**.

Về dust: `require(... % scaleDivisor == 0)` là lựa chọn đúng (fail loud) so với làm tròn xuống (âm thầm ăn tiền người dùng) hoặc gom vào pool (phá invariant escrow). Client tự làm tròn trước khi gọi.

#### 3.2.4. `scale_exponent` phải theo từng token, không phải hằng số hệ thống

Bản nháp ghi cứng `scale_exponent = 2` cho cả hai profile. Sai với VND: **VND không có đơn vị con**. Giữ 2 chữ số thập phân cho VND là vứt đi 6.64 bit dải mà không mua được gì.

| Token | underlying decimals | `scale_exponent` | 1 đơn vị ledger | `n_v` | Trần một giao dịch | Đủ cho? |
|---|---|---|---|---|---|---|
| Z-USDT / Z-USDC | 6 | 2 | $0.01 | 32 | $42.9 M | thanh toán end-user + B2B |
| Z-VND | 0 hoặc 6 | 0 | 1 ₫ | 32 | 4.29 tỷ ₫ (~$163k) | **không đủ** cho settlement nhà phân phối |
| Z-VND (B2B) | 0 hoặc 6 | 0 | 1 ₫ | **40** | 1,100 tỷ ₫ (~$42 M) | đủ |
| Z-POINT (loyalty) | 0 | 0 | 1 điểm | 32 | 4.29 tỷ điểm | thừa |
| Z-DAI / Z-xDAI | 18 | 2 | $0.01 | 32 | $42.9 M | đủ |

Con số "settlement nhà phân phối vượt 4.29 tỷ ₫" không phải giả định: một nhà phân phối cấp 1 ngành FMCG ở VN doanh số tháng 20–80 tỷ ₫ là bình thường. `n_v = 32` với `scale 0` sẽ chặn đúng khách hàng lớn nhất. Đây là chỗ mà một hằng số ghi cứng trong tài liệu kiến trúc biến thành một cuộc gọi khẩn cấp sáu tháng sau.

Nhưng `n_v = 40` kéo theo `DECRYPT_BOUND = 2^40` ⇒ BSGS 1.6–3 s **cho mỗi khoản chuyển** khi recovery. 10,000 khoản ⇒ **4.4–8.3 giờ**. Không chấp nhận được. Đó là lý do phải có mục tiếp theo.

#### 3.2.5. Memo mã hoá số tiền — cơ chế bản nháp thiếu, và nó xoá bỏ BSGS

Bản nháp nói "client tự theo dõi số dư, BSGS chỉ là đường khôi phục". Với `n_v = 32` thì đường khôi phục đó chạy được (17 phút). Với `n_v = 40` thì không. Và giả định A7 — client luôn giữ được sổ — là giả định yếu nhất trong toàn bộ tài liệu: người dùng đổi điện thoại.

Giải pháp đúng, rẻ, và Zether nguyên bản không có: **gắn memo mã hoá đối xứng vào chính giao dịch.** Khoá dẫn xuất từ đúng shared secret đã có sẵn, không cần thêm một điểm nhóm nào.

```
Sender biết:   s (randomness), y_to, y_from, v
Shared secret to receiver:  S_to   = y_to^s     ( = D_out^{x_to},   receiver tính được )
Shared secret to self:      S_from = y_from^s   ( = D_out^{x_from}, sender  tính được )

k_to   = HKDF-SHA256( compress(S_to)   , info = "ZETHER/MEMO/v1" ‖ chainId ‖ token ‖ nonce )
k_from = HKDF-SHA256( compress(S_from) , info = "ZETHER/MEMO/v1" ‖ chainId ‖ token ‖ nonce )

memoTo   = ChaCha20-Poly1305( k_to,   nonce = 0, plaintext = uint64(v) ‖ uint64(memoTag) )
memoFrom = ChaCha20-Poly1305( k_from, nonce = 0, plaintext = uint64(v) ‖ uint64(memoTag) )
```

- Kích thước: 16 B plaintext + 16 B tag = **32 B mỗi memo**, hai memo = **64 B**. Calldata: 64 × 16 = **1,024 gas**. Event data thêm 64 B ≈ 512 gas. Tổng **< 1.6k gas**.
- Contract **không** verify memo — nó là dữ liệu mờ. Nếu sender ghi memo sai, người thiệt là sender/receiver, không phải hệ thống. Không cần ZK constraint nào. (Nếu muốn ép đúng thì cần chứng minh memo mã hoá đúng `v` — một mạch AEAD trong ZK, đắt gấp 50 lần lợi ích. **Không làm.** Ghi rõ: memo là *tiện lợi*, ElGamal ciphertext mới là *nguồn sự thật*.)
- Hệ quả: giải mã một khoản chuyển = 1 scalar mul + 1 HKDF + 1 ChaCha20 ≈ **60 µs**, thay vì 1.6–3 s BSGS. Nhanh hơn **25,000–50,000 lần**.
- Recovery 10,000 giao dịch: **0.6 giây** thay vì 8 giờ.
- BSGS vẫn giữ lại **chỉ như oracle kiểm tra chéo**: nếu tổng từ memo khác với `g^b` giải ra từ `acc`, có bất nhất ⇒ cảnh báo. Chạy BSGS một lần trên số dư (không phải trên từng khoản) khi `b < 2^40`, hoặc bỏ qua nếu vượt.

Bổ sung vào struct và event:

```solidity
struct ConfidentialTransferData {
    bytes32[2] C_out;      // g^v · y_to^s
    bytes32[2] D_out;      // g^s   (dùng chung cho debit — xem 3.4.2)
    bytes32[2] C_debit;    // g^v · y_from^s
    uint256    fee;        // PUBLIC scalar, đơn vị ledger
    uint256    zetherNonce;
    uint256    accSeq;     // xem 3.5.4
    bytes32    memoTo;     // 32 B AEAD
    bytes32    memoFrom;   // 32 B AEAD
    bytes      proof;      // Sigma ‖ BP(v) ‖ BP(b')
}
```

`feeRecipient` **không** nằm trong struct này — nó là tham số riêng của hàm, do relayer điền, và **không** vào Fiat-Shamir challenge (xem 3.4.4).

#### 3.2.6. Recovery là đường first-class, và nó phụ thuộc log retention

Với memo, recovery hoàn toàn xác định và không cần BSGS:

```
b_final = Σ deposits(public, từ event Deposit)
        − Σ withdrawals(public, từ event Withdraw)
        + Σ v_in   (giải memoTo từ mọi event ConfidentialTransfer có toSchnorrAddress = mình)
        − Σ v_out  (giải memoFrom từ mọi event có fromSchnorrAddress = mình)
        − Σ fee    (public, có trong event)
```

Kiểm chéo bắt buộc: `g^{b_final}` phải bằng `C_acc · D_acc^{-x}`. Nếu lệch ⇒ thiếu event ⇒ **dừng, không cho tiêu**, báo lỗi. Đừng để ví đoán.

**Ràng buộc hạ tầng mà bản nháp bỏ qua hoàn toàn (A8):** recovery cần đọc lại toàn bộ log từ block đăng ký tài khoản. Thực tế RPC:

| Nguồn | Giới hạn `eth_getLogs` | Hệ quả |
|---|---|---|
| Gnosis public RPC | ~10,000 log hoặc ~10,000 block/lần | phải phân trang, ~200 request cho 2 triệu block |
| Alchemy / QuickNode free tier | 2,000 block/lần, rate limit | ~1,000 request, vài phút |
| Node full (không archive) | log **được giữ** (log không bị prune như state) | OK, nhưng cần chạy node |
| Erigon / reth với `--prune.r` | log **bị prune** | recovery gãy hoàn toàn |

Quyết định: **`dms_blockchain` phải tự index và lưu event, không được coi RPC là nguồn recovery.** Model `blockchain.zether.transfer` giữ đủ trường để client dựng lại lịch sử (xem 3.9.3), và addon expose một public method để client kéo về. Đây là một trong ba nhiệm vụ của addon, và là nhiệm vụ mà bản nháp mô tả là "index event để đối soát" — thực ra nó còn là **hạ tầng recovery của ví**, quan trọng hơn nhiều. Cấu hình node bắt buộc: `--history.transactions=0` là được, nhưng **cấm prune receipt/log**.

---

### 3.3. Bulletproofs: kích thước nhỏ, nhưng verify tuyến tính theo n

#### 3.3.1. Kích thước và chi phí — công thức

Với `m` giá trị mỗi giá trị `n` bit (aggregated):

```
proof size   = 2·⌈log2(n·m)⌉ + 4  group elements  +  5 scalars
verify MSM   = 2·n·m + 2·⌈log2(n·m)⌉ + 8  điểm      ← TUYẾN TÍNH theo n
prover work  ≈ 4·n·m  scalar mul (hai vòng MSM lớn + IPA)
```

Note nói đúng rằng size tăng theo `log2(range)`, nhưng suy ra rằng 128-bit "chỉ thêm 2 vòng" là suy sai chỗ tốn tiền: 32 → 128 bit thêm **128 byte** proof nhưng **×4 công verify**. Kích thước là thứ rẻ; MSM là thứ đắt.

#### 3.3.2. Sửa lại bảng kích thước của bản nháp

Bản nháp ghi "672 + 704 B" cho cấu hình 32/64. **Sai.** Tính lại:

| Cấu hình | ⌈log2(nm)⌉ | group elems | scalars | size compressed (32 B/điểm) | size uncompressed (64 B/điểm) |
|---|---|---|---|---|---|
| n=32, m=1 | 5 | 14 | 5 | 448 + 160 = **608 B** | 896 + 160 = **1,056 B** |
| n=64, m=1 | 6 | 16 | 5 | 512 + 160 = **672 B** | 1,024 + 160 = **1,184 B** |
| n=32, m=2 (agg) | 6 | 16 | 5 | **672 B** | **1,184 B** |
| n=64, m=2 (agg) | 7 | 18 | 5 | **736 B** | **1,312 B** |
| n=128, m=2 (agg) | 8 | 20 | 5 | **800 B** | **1,440 B** |

Cấu hình 32/64 = hai proof riêng (không aggregate được vì khác `n`): `608 + 672 = 1,280 B` compressed. Bản nháp ghi 1,376 B. Đã sửa.

Vì sao không pad 32 lên 64 để aggregate: aggregate n=64 m=2 cho MSM **278 điểm**, hai proof riêng cho **82 + 148 = 230 điểm**. Riêng rẻ hơn **17%**. Aggregate chỉ thắng khi hai giá trị **cùng bit-length**.

#### 3.3.3. Gas trên EVM — không có MSM precompile cho BN254

Trên EVM không có MSM precompile cho BN254 (EIP-2537 chỉ cho BLS12-381), nên mỗi điểm trong MSM = 1 `ecMul` + 1 `ecAdd`:

```
6,000 (ecMul) + 150 (ecAdd) + ~400 (2 × staticcall overhead 100 + memory copy/expansion)
≈ 6,550 gas / điểm
```

Không có Pippenger, không có windowing, không có bucket method — precompile chỉ nhận một điểm một scalar mỗi lần gọi. Đây là ràng buộc kiến trúc của EVM, không phải thiếu tối ưu.

#### 3.3.4. Nén điểm trong calldata là phản tối ưu — con số

Bản nháp ngầm định (A13) không nói rõ. Quyết định phải viết ra:

| | Compressed 32 B | Uncompressed 64 B |
|---|---|---|
| Calldata mỗi điểm | 32 × 16 = **512 gas** | 64 × 16 = **1,024 gas** |
| Decompress on-chain | 1 modexp sqrt = **1,349 gas** (EIP-2565: `mult_complexity=16`, `iter_count=253`, `16·253/3`) | 0 |
| **Tổng mỗi điểm** | **1,861 gas** | **1,024 gas** |

**Uncompressed rẻ hơn 1.8×.** Quy tắc: **calldata dùng uncompressed; lưu trữ off-chain (`ir.attachment` trên Garage) dùng compressed.** Client SDK phải hỗ trợ cả hai encoding và `testvectors` phải có cả hai.

Hệ quả lên tổng calldata cho cấu hình 32/64:

```
Sigma:            8 điểm × 64 +  6 scalar × 32  =    704 B
BP(v),  n=32:    14 điểm × 64 +  5 scalar × 32  =  1,056 B
BP(b'), n=64:    16 điểm × 64 +  5 scalar × 32  =  1,184 B
Ciphertext C_out, D_out, C_debit: 3 × 64        =    192 B
memoTo, memoFrom, fee, nonce, accSeq, 2 addr    =    224 B
selector + offsets                              =    ~96 B
                                            TỔNG ≈  3,456 B  →  55.3k gas
```

Bản nháp ước 22k gas cho calldata. **Sai ~2.5×**, đã sửa. (EIP-7623 floor cost 10 gas/token không bind ở đây vì execution gas áp đảo.)

#### 3.3.5. Vector generator không nhét vừa bytecode — blocker EIP-170

Verifier cần `2·n·m` generator cho vector `g_i, h_i`. Bản nháp không nhắc (A12).

| Cấu hình | generator cần | × 64 B | vs EIP-170 (24,576 B) |
|---|---|---|---|
| n=32, m=1 | 64 | 4,096 B | OK |
| n=64, m=1 | 128 | 8,192 B | OK |
| **32/64 (dùng chung prefix)** | **128** | **8,192 B** | **OK — vừa một contract** |
| n=64, m=2 | 256 | 16,384 B | OK, sát |
| **n=128, m=2 (cấu hình của note)** | **512** | **32,768 B** | **VƯỢT — không deploy được** |

Cấu hình 128/128 mà note đề xuất **không deploy được trên EVM** nếu generator nằm trong bytecode. Ba đường:

1. **SSTORE2 / data contract** — deploy generator như payload của một contract không có logic, đọc bằng `extcodecopy`. Một contract chứa tối đa 24,576 B = 384 điểm ⇒ cấu hình 128/128 cần **2 contract**. Chi phí đọc: `2,600` (cold account) + `3` gas/word. 8,192 B = 256 word ⇒ **3,368 gas**; 32,768 B = 1,024 word ⇒ **5,672 gas** cho 2 contract. Rẻ. **Đây là lựa chọn.**
2. Lưu compressed trong bytecode (16,384 B cho 512 điểm, vừa) rồi decompress on-chain: 512 × 1,349 = **690k gas**. Không.
3. Tính `hash_to_curve` on-chain: hàng chục nghìn gas mỗi điểm. Không.

```solidity
contract ZetherGeneratorsBN254V1 {
    // constructor deploy 8,192 byte raw generator data làm runtime code
    // đọc: extcodecopy(address(this), dst, offset, len)
}
```

Test bắt buộc: `Generators.deploy.t.sol` khẳng định `address(gens).code.length == expected` và hash của toàn bộ blob khớp `testvectors/zether_generators_bn254_v1.json`.

#### 3.3.6. Bảng gas tổng, sửa lại

| n_v / n_b | MSM điểm | gas BP | Sigma | calldata | storage | fee ERC-20 | event + base + misc | **tổng ước tính** |
|---|---|---|---|---|---|---|---|---|
| 32 / 32 (agg m=2) | 148 | 0.970 M | 171 k | 50 k | 70 k | 30 k | 45 k | **~1.34 M** |
| **32 / 64 (hai proof, chung transcript)** | **230** | **1.507 M** | **171 k** | **55 k** | **70 k** | **30 k** | **45 k** | **~1.88 M** |
| 64 / 64 (agg m=2) | 278 | 1.821 M | 171 k | 57 k | 70 k | 30 k | 45 k | **~2.19 M** |
| 128 / 128 (agg m=2) | 536 | 3.511 M | 171 k | 41 k | 70 k | 30 k | 48 k | **~3.87 M** |

*Cơ sở ước tính (bottom-up, sai số ±25%):*
- `ecMul` 6,000 + `ecAdd` 150 (EIP-1108) + ~400 gas overhead `staticcall`/memory mỗi điểm MSM.
- Sigma: ~25 `ecMul` + ~20 `ecAdd` + validation điểm ≈ 150,000 + 3,000 + 18,000 = 171k.
- Storage: sender `acc` 4 slot (cold SSTORE nonzero→nonzero = 2,100 + 2,900) + receiver `pending` 4 slot + `zetherNonce` + `accSeq` ≈ 70k **cho người nhận đã có pending khác 0**. Người nhận lần đầu: 4 slot zero→nonzero = 4 × 22,100 = 88.4k ⇒ tổng **~115k**, tức tx đầu tiên tới một account đắt hơn ~45k. Ai trả? Người gửi. Chấp nhận được, nhưng phải hiện lên UI.
- `fee` trả bằng ERC-20 trực tiếp cho relayer (xem 3.4.3): ~30k (warm transfer).
- Generator `extcodecopy` ~3.4k, event ~4k, base tx 21k, validation điểm ~1.5k, registry SLOAD 2 × 8.4k.

Phải đo lại bằng `forge test --gas-report` trên verifier thật; số ở đây để **ra quyết định**, không để đưa vào SLA.

#### 3.3.7. Con số 180k–250k gas trong note: sai 15–20 lần, và sai một cách chẩn đoán được

`45,000 + 4 × 34,000 = 181,000` gas cho `ecPairing` với k = 4, cộng ~3 `ecMul` để tổ hợp public input ⇒ **~200k**. Đó **chính xác** là chi phí verify một **Groth16 SNARK trên alt_bn128** (phương trình `e(A,B)·e(−α,β)·e(−vk_x,γ)·e(−C,δ) = 1`, đúng 4 pairing). Dấu vết nằm ngay trong câu văn của note: nó viện dẫn `ecPairing` / EIP-197.

**Bulletproofs hoàn toàn không dùng pairing.** Con số đã bị mượn từ ngữ cảnh SNARK. Con số đúng cho Bulletproofs 128/128 là **~3.87 M**, sai lệch **19×**.

Điều đáng nói: con số 200k **đúng** nếu chọn Groth16 — nên đây không phải chỉ là lỗi số, nó là một **quyết định kiến trúc bị che giấu**. Note đã ngầm giả định một hệ chứng minh mà nó không nêu tên.

#### 3.3.8. Hệ quả throughput và chi phí — số quyết định

Chi phí tiền mặt trên Gnosis là **không đáng kể**; ràng buộc thật là **block space**.

| Chain | block gas limit | block time | gas/s toàn mạng | tx 1.88 M gas | ở 20% block space | tx 3.87 M gas | ở 20% block space |
|---|---|---|---|---|---|---|---|
| **Gnosis xDAI** | 17 M | 5 s | 3.40 M/s | 1.81 tx/s | **0.36 tx/s = 31,300/ngày** | 0.88 tx/s | **0.18 tx/s = 15,200/ngày** |
| **Celo (L2, OP-stack)** | ~30 M | 1 s | 30 M/s | 16 tx/s | 3.2 tx/s = 276k/ngày | 7.8 tx/s | 1.6 tx/s = 134k/ngày |
| Ethereum L1 | 36 M (max) | 12 s | 3.0 M/s | 1.6 tx/s | 0.32 tx/s | 0.78 tx/s | 0.16 tx/s |
| Private chain (QBFT, native precompile) | tuỳ chỉnh | 1 s | — | xem 3.3.9 | **~500 tx/s** | — | ~400 tx/s |

Chi phí bằng tiền:

| Chain | giá gas điển hình | tx 1.88 M gas | tx 3.87 M gas |
|---|---|---|---|
| Gnosis (xDAI = $1) | 1–3 gwei | **$0.002 – $0.006** | $0.004 – $0.012 |
| Celo (fee currency cUSD) | ~0.01–0.1 gwei tương đương | < $0.001 | < $0.002 |
| Ethereum L1 | 5 gwei, ETH $3,000 | **$28** | **$58** |

Kết luận đưa vào plan: **Ethereum L1 nằm ngoài phạm vi cho Zether.** Không phải "đắt", mà là sai công cụ. Gnosis đúng như thứ tự user đã chốt. Và trên Gnosis, con số ràng buộc không phải $0.006 mà là **31,300 tx/ngày toàn mạng ở cấu hình 32/64** — nếu DMS chạy 500 nhà phân phối × 20 outlet settlement/ngày = 10,000 tx/ngày, ta đang chiếm ~6.4% block space của cả Gnosis Chain. Đó là một con số cần biết trước khi ký hợp đồng, không phải sau.

#### 3.3.9. Verify rẻ gas không có nghĩa là verify nhanh — và đây là lý do có private chain

536 lần gọi precompile `bn256ScalarMult` trong geth ≈ **40–120 µs mỗi lần** (implementation Go, `gnark-crypto` từ geth 1.13) ⇒ **21–64 ms CPU đơn luồng mỗi transaction**, chạy **nối tiếp** trong block execution. Ở block time 1 s, trần là **~15–47 confidential tx/giây/chain** trước khi tính bất cứ thứ gì khác. Với cấu hình 32/64 (230 điểm): 9–28 ms ⇒ **35–110 tx/s**.

Trên chain mình tự vận hành, làm **native precompile**:

```
Địa chỉ: 0x...0100   ZETHER_VERIFY_TRANSFER_V1
Địa chỉ: 0x...0101   ZETHER_VERIFY_WITHDRAW_V1
Input:   abi.encode(statement, proof)
Output:  32 byte, 1 = valid
Gas:     giá cố định, ví dụ 60,000 (đo bằng benchmark, nhân hệ số an toàn 3×)
```

Implementation bằng `gnark-crypto` với Pippenger MSM: MSM 536 điểm ≈ **0.3–1 ms**, nhanh hơn **25–60×** đường precompile-per-point. Throughput trần khi đó bị chặn bởi state I/O chứ không phải crypto ⇒ **~500 tx/s** là con số hợp lý để lập kế hoạch.

Chi tiết triển khai phải nằm trong plan, không phải "để sau":

- **Client nào.** `go-quorum` hoặc một fork geth với **QBFT** — vì `gnark-crypto` là Go, precompile chỉ là ~150 dòng đăng ký vào `core/vm/contracts.go` (`PrecompiledContractsXxx` map). Besu (Java) cần JNI sang constantine/mcl — gấp 5 lần công và một bề mặt lỗi mới. **Chọn go-quorum/geth-QBFT.**
- **Đây là consensus change.** Mọi validator phải chạy đúng binary. Kích hoạt theo **block number hard-fork** trong genesis config, không phải theo flag. Một validator chạy binary cũ sẽ fork chain.
- **Bản Solidity giữ lại** làm reference implementation và làm oracle cho differential test. Contract chọn đường nào qua `IZetherVerifier` — cùng interface, hai implementation:

```solidity
interface IZetherVerifier {
    function verifyTransfer(bytes calldata statement, bytes calldata proof)
        external view returns (bool);
    function verifyWithdraw(bytes calldata statement, bytes calldata proof)
        external view returns (bool);
    function proofSystemId() external pure returns (bytes32); // "BP_BN254_V1" | "G16_BJJ_V1" | "NATIVE_BP_V1"
}
```

- **Private profile (ship trước):** `BulletproofsVerifier.sol` hoặc `NativePrecompileVerifier.sol`, `n_v = 32`, `n_b = 64`. Không cần trusted setup.
- **Public profile (ship sau):** `Groth16Verifier.sol` — **ElGamal đặt trên Baby Jubjub (EIP-2494)**, twisted Edwards curve có base field đúng bằng scalar field của BN254, nên scalar mul trong mạch chỉ ~2,000 constraint. Mạch tổng ~30–60k constraint. Verify **181k (pairing) + ~30k = ~215k gas**, proof **256 byte**. Phép cộng đồng hình trên Baby Jubjub làm bằng `mulmod` thuần Solidity trong extended coordinates (~9 `mulmod`, không cần nghịch đảo) ≈ 200–400 gas/phép, ngang `ecAdd`. Đánh đổi: cần trusted setup per-circuit (hoặc PLONK universal, verify ~290k) và thời gian prove client tệ hơn 10–20× (xem 3.8).

Lưu ý quan trọng về Groth16 profile: **đổi sang Baby Jubjub là đổi curve** ⇒ dính đúng cái bẫy migration ở 3.1.7. Nếu có ý định đi Groth16 trên public, hãy chọn Baby Jubjub **ngay từ private chain**, đừng đi BN254-G1 trước rồi đổi. Bulletproofs cũng chạy được trên Baby Jubjub (chỉ là verify Solidity đắt hơn vì không có precompile — mỗi scalar mul ~30k gas thuần Solidity thay vì 6k, ⇒ MSM 230 điểm ≈ 7 M gas, **không dùng được trên public, dùng được trên private với native precompile**). Đây là bảng quyết định thật:

| Nếu muốn | thì curve của ElGamal | verifier private | verifier public | migration về sau |
|---|---|---|---|---|
| Chỉ Bulletproofs mãi mãi | BN254 G1 | native precompile | Solidity BP (~1.9 M gas) | không |
| Bulletproofs trước, Groth16 sau | **Baby Jubjub** | native precompile BP | Groth16 (~215k gas) | **không** — cùng curve |
| Bulletproofs trước, Groth16 sau, mà chọn BN254 G1 | BN254 G1 | native | Groth16 phải chứng minh ECC BN254 trong mạch BN254 ⇒ **non-native field arithmetic, ~50× constraint** | **phải đổi curve, lộ toàn bộ số dư** |

**Khuyến nghị dứt khoát: đặt ElGamal trên Baby Jubjub ngay từ đầu.** Nó đắt hơn một chút ở private profile (không có precompile, nhưng ta có native precompile riêng nên không quan trọng) và nó là *điều kiện cần* để giữ được đường Groth16 mà không phải migrate. Đây là quyết định phải chốt **trước khi deploy contract đầu tiên**, vì sau đó không sửa được.

---

### 3.4. Quan hệ ZKP chính xác, Sigma protocol cụ thể, và pipeline phí

#### 3.4.1. Note tự mâu thuẫn về phí

Struct trong note khai `uint256 fee` (public trong calldata) nhưng comment gọi nó là "phí giao dịch bí mật", rồi lại thêm `bytes32[2] C_fee` (ciphertext của phí). Không thể vừa công khai vừa bí mật. Toàn bộ kinh tế học Open Relayer ở §10.1/§14.2.8 **bắt buộc** phí phải công khai để relayer thẩm định lợi nhuận trước khi bỏ gas ra. Vậy phí là **public scalar**. Xoá `C_fee`.

Một khi phí là public scalar thì **không cần ciphertext, không cần range proof, không cần equality proof cho phí**. Trừ phí khỏi số dư mã hoá chỉ là:

```
C_acc' = C_acc · g^(-fee)      // 1 ecMul + 1 ecAdd  ≈ 6,550 gas
D_acc' = D_acc                 // không đổi
```

Vì `fee` công khai, hợp đồng tự `require(fee < (1 << RANGE_BITS_VALUE))`. Tổng ≈ **7k gas**, và **xoá được 2 trong 4 quan hệ range proof mà note liệt kê**.

Ngoài ra note liệt kê `b − fee ≥ 0` như một ràng buộc độc lập — nó bị **suy ra** từ `(b − fee) − v ≥ 0` ∧ `v ≥ 0`. Còn lại đúng **hai** range statement.

#### 3.4.2. Quan hệ đầy đủ cho `transferConfidential`

```
Public statement S (mọi thứ trong đây PHẢI vào Fiat-Shamir transcript, theo đúng thứ tự này):
  chainId
  address(this)                      // token contract, KHÔNG phải registry
  "ZETHER_TRANSFER_V1"               // domain tag, 32 byte padded
  proofSystemId                      // "BP_BJJ_V1" ... chống nhầm hệ chứng minh
  y_from, y_to                       // registry tra từ schnorrAddress; điểm, không phải hash
  C_acc, D_acc                       // số dư khả dụng đã lưu của sender (SAU khi trừ nothing)
  C_out, D_out                       // credit cho receiver
  C_debit                            // D_debit == D_out, cùng randomness s
  fee                                // public scalar, đơn vị ledger
  zetherNonce
  accSeq                             // xem 3.5.4
  memoTo, memoFrom                   // 32 B mỗi cái; không ràng buộc ZK nhưng PHẢI vào transcript
                                     //   (nếu không, relayer đổi memo được -> grief recovery của receiver)

KHÔNG có trong S:  feeRecipient       // xem 3.4.4

Witness W: x_from, b, v, s, r_acc, gamma_v, gamma_b

R1  y_from   = g^{x_from}                                     Schnorr PoK of sk
R2  D_out    = g^s                                            randomness well-formed
R3  C_out    = g^v · y_to^s                                   credit well-formed, cùng s
R4  C_debit  = g^v · y_from^s                                 CÙNG v, CÙNG s  (equality across bases)
R5  b'       = b − fee − v, và b' là dlog cơ số g của
                 (C_acc · C_debit^{-1} · g^{-fee}) · ((D_acc · D_out^{-1})^{x_from})^{-1}
                                                              balance sau giao dịch, biết x_from
R6  v  ∈ [0, 2^{n_v})                                         Bulletproof #1
R7  b' ∈ [0, 2^{n_b})                                         Bulletproof #2
R8  V_v = g^v · h^{gamma_v}  và  V_b = g^{b'} · h^{gamma_b}   commitment của BP
    v trong V_v ≡ v trong C_out ;  b' trong V_b ≡ b' trong R5     ← SIGMA-BULLETS LINKAGE
```

`D_debit` **bị thiếu trong struct của note, và điều đó đúng** — debit và credit dùng chung randomness `s`, nên `D_debit == D_out`. Nhưng chỉ đúng **nếu R4 thực sự ràng buộc cùng `s`**; nếu bỏ R4, kẻ gian trừ của mình `v' < v` và cộng cho người nhận `v` ⇒ in tiền. Ghi rõ trong spec, đừng để implementer suy đoán.

#### 3.4.3. Phí trả cho relayer bằng ERC-20 công khai, không phải bằng số dư mã hoá

Bản nháp xoá `C_fee` nhưng vẫn để phí "cộng vào số dư bí mật của feeRecipient". Đi nốt một bước nữa: **phí phải rời khỏi hệ confidential ngay lập tức.**

Lý do vận hành, không phải thẩm mỹ:

- Relayer cần thanh khoản để mua native gas. Fee nằm trong số dư mã hoá ⇒ relayer phải `withdraw` để tiêu ⇒ mỗi lần withdraw lộ số tiền, tốn ~1 M gas (withdraw cũng cần range proof), và relayer phải chạy prover. **Relayer sẽ không tham gia mạng lưới với chi phí đó.**
- Relayer khi đó bắt buộc phải có tài khoản Zether đã register trên **từng** Z-token. Rào cản gia nhập cao ⇒ mâu thuẫn với "Open Relayer Network".

Thiết kế đúng:

```solidity
// bên trong transferConfidential, sau khi verify proof:
if (fee > 0) {
    totalDepositedScaled -= fee;                            // rời khỏi escrow, invariant vẫn đúng
    IERC20(underlying).safeTransfer(feeRecipient, fee * scaleDivisor);
}
```

- `feeRecipient` là **`address` EOA thường**, không phải `bytes32 schnorrAddress`. Relayer không cần tài khoản Zether. Không cần register. Không cần prover.
- Escrow invariant giữ nguyên: `balanceOf(this) >= totalDepositedScaled - totalWithdrawnScaled` với `totalDepositedScaled` đã trừ fee.
- Rò rỉ thêm: `fee` công khai (đã chấp nhận theo yêu cầu Open Relayer) và `feeRecipient` công khai. Không lộ gì về `v`.
- Gas: một `safeTransfer` warm ≈ 30k. Với `fee = 0` (trường hợp direct-call, người dùng tự trả gas) thì bỏ qua hoàn toàn.

Ràng buộc kinh tế cần ghi để §05/§06 dùng: `fee` tính bằng **đơn vị ledger của token**, relayer tự quy đổi sang native gas theo tỷ giá của mình. Với Z-USDT trên Gnosis: gas 1.88 M × 2 gwei = $0.0038 ⇒ `fee = 1` (1 cent) đã cho relayer biên **~160%**. Với Z-VND scale 0: `fee = 100` (100 ₫ ≈ $0.0038) là hoà vốn; đặt `fee = 300` cho biên an toàn. Đây là con số mà UI phải gợi ý mặc định, không để người dùng đoán.

#### 3.4.4. `feeRecipient` KHÔNG được vào Fiat-Shamir challenge — và hệ quả không dễ chịu

`MODE_OPEN (0x00)` của EIP-1776 nói rằng bất kỳ ai cũng làm relayer được và relayer tự chọn `feeRecipient`. Để điều đó hoạt động, `feeRecipient` **không được** nằm trong bất kỳ chữ ký hay challenge nào của người dùng — kể cả Fiat-Shamir challenge của Zether. Bản nháp không nói ra (A10).

Hệ quả phải chấp nhận, viết thẳng:

> Với `MODE_OPEN`, bất kỳ ai quan sát mempool đều có thể **copy nguyên calldata**, thay `feeRecipient` bằng địa chỉ của mình, và front-run relayer trung thực. Đó **đúng là** cơ chế đấu giá mở mà kiến trúc muốn. Nhưng relayer thua cuộc đua **vẫn tốn gas** — tx của họ revert ở `require(zetherNonce == ...)` và họ mất ~30–50k gas (base + validation trước khi revert).

Đây là một chi phí thật của mô hình Open Relayer, không phải một bug. Ba đường xử lý, phải chọn ở tầng deploy:

| Đường | Cơ chế | Ai chịu rủi ro | Khi nào |
|---|---|---|---|
| `MODE_OPEN` + public mempool | tự do | relayer chịu gas thua cuộc | thí nghiệm, giá trị nhỏ |
| `MODE_RESTRICT_RELAYER (0x01)` | user gắn cứng relayer vào chữ ký EIP-1776 | không ai | **mặc định cho mọi giao dịch B2B và mọi withdraw** |
| Private orderflow | user gửi thẳng payload cho một relayer qua HTTPS, không gossip | không ai | mặc định cho end-user payment |

Khuyến nghị: **`MODE_OPEN` chỉ dùng cho gossip pool công khai của các giao dịch nhỏ; mặc định của addon là `MODE_RESTRICT_RELAYER` + private orderflow.** Gnosis không có hạ tầng private mempool trưởng thành (không có Flashbots Protect tương đương), nên "private orderflow" ở đây nghĩa là HTTPS trực tiếp tới relayer đã chọn, không phải một mạng bảo vệ.

#### 3.4.5. Sigma protocol cụ thể — vì "decision-complete" nghĩa là viết ra được

Bản nháp nói "Sigma protocol ~25 ecMul" nhưng không đưa protocol. Đây là bản 3-move (đã Fiat-Shamir hoá), chứng minh R1–R5 + linkage R8 cùng lúc. Ký hiệu nhân tính, nhóm viết theo lối nhân.

**Prover, move 1 (commitments).** Sinh nonce ngẫu nhiên (hedged theo 3.1.4): `k_x, k_v, k_s, k_b, k_gv, k_gb ← Z_q`.

```
A_y      = g^{k_x}
A_D      = g^{k_s}
A_out    = g^{k_v} · y_to^{k_s}
A_debit  = g^{k_v} · y_from^{k_s}
A_bal    = g^{k_b} · (D_acc · D_out^{-1})^{k_x}      // ràng buộc R5 với cùng x_from
A_Vv     = g^{k_v} · h^{k_gv}                        // linkage tới commitment BP #1
A_Vb     = g^{k_b} · h^{k_gb}                        // linkage tới commitment BP #2
```

**Challenge.** `c = H_transcript(S ‖ V_v ‖ V_b ‖ A_y ‖ A_D ‖ A_out ‖ A_debit ‖ A_bal ‖ A_Vv ‖ A_Vb)`, với `H_transcript` là Merlin/STROBE hoặc SHA-512 → `hash_to_field` (RFC 9380) để về `Z_q` không bias. **Cùng một transcript này tiếp tục sinh mọi challenge của hai Bulletproof** (xem 3.4.7).

**Prover, move 3 (responses).**

```
z_x  = k_x  + c·x_from
z_v  = k_v  + c·v
z_s  = k_s  + c·s
z_b  = k_b  + c·b'
z_gv = k_gv + c·gamma_v
z_gb = k_gb + c·gamma_b
```

**Verifier** (tất cả trong nhóm; `T = C_acc · C_debit^{-1} · g^{-fee}`, `E = D_acc · D_out^{-1}`):

```
V1  g^{z_x}                        == A_y     · y_from^c
V2  g^{z_s}                        == A_D     · D_out^c
V3  g^{z_v} · y_to^{z_s}           == A_out   · C_out^c
V4  g^{z_v} · y_from^{z_s}         == A_debit · C_debit^c
V5  g^{z_b} · E^{z_x}              == A_bal   · T^c
V6  g^{z_v} · h^{z_gv}             == A_Vv    · V_v^c
V7  g^{z_b} · h^{z_gb}             == A_Vb    · V_b^c
```

Đếm chi phí verifier: V1 (1 mul + 1 mul), V2 (2), V3 (4), V4 (4), V5 (4), V6 (4), V7 (4) = **23 `ecMul` + 16 `ecAdd`** ⇒ `23×6,000 + 16×150 + 39×400` ≈ **156k gas** trên BN254 với precompile. Con số 171k ở bảng 3.3.6 đã gồm validation điểm. Khớp.

**Serialization của Sigma phần** (uncompressed):

```
offset  len  field
0       64   A_y
64      64   A_D
128     64   A_out
192     64   A_debit
256     64   A_bal
320     64   A_Vv
384     64   A_Vb
448     64   V_v
512     64   V_b
576     32   z_x
608     32   z_v
640     32   z_s
672     32   z_b
704     32   z_gv
736     32   z_gb
                 = 768 byte
```

(Nhiều hơn ước tính 704 B ở 3.3.4 — cập nhật calldata lên ~3,520 B, gas 56.3k. Sai số nằm trong ±25%.)

`c` **không** serialize — verifier tự tính lại từ transcript. Nếu ai đó đưa `c` vào proof, đó là lỗ hổng Frozen Heart cổ điển; thêm một test khẳng định proof format không có trường `c`.

#### 3.4.6. Cái bẫy chết người mà note không nhắc một chữ: Σ-Bullets

Ghép ngây thơ một Sigma protocol (R1–R5) với một Bulletproof (R6–R7) là **không an toàn**. Bulletproof mở commitment `V_v = g^v h^{gamma_v}`; Sigma protocol nói về `v` bên trong `C_out`. Nếu không có proof rằng **hai `v` đó là một**, kẻ gian chứng minh range cho một `v` vô hại rồi chuyển một `v` khác — **in tiền không giới hạn, không phát hiện được cho tới khi invariant escrow lệch**. Paper Zether gọi hẳn cấu trúc này là **Σ-Bullets** vì lý do đó.

Trong protocol ở 3.4.5, linkage chính là **V6 và V7** cộng với việc `z_v`, `z_b` **dùng chung** giữa V3/V4 và V6/V7. Đây là chỗ dễ bị "tối ưu" nhất: một dev thấy `A_Vv` thừa và xoá nó. Yêu cầu bắt buộc:

1. Test `SigmaBullets.linkage.t.sol`: dựng một proof với `v` trong `C_out` khác `v` trong `V_v`, khẳng định verify **fail**. Test này phải **fail nếu ai đó xoá V6**.
2. **Một transcript Fiat-Shamir duy nhất** cho Sigma + cả hai Bulletproof. Không phải ba transcript độc lập.
3. Code review bắt buộc bởi người thứ hai cho riêng file `Sigma.sol`.

Đây là chỗ dễ sai nhất của toàn bộ hệ thống. Bắt buộc có test đảo từng bit và một audit độc lập trước khi lên public chain.

#### 3.4.7. Fiat-Shamir phải "strong"

Transcript phải hấp thụ **toàn bộ statement S trước** message đầu tiên của prover, có domain separation. Hấp thụ chỉ commitment là đúng bug **Frozen Heart** (Trail of Bits, 2022 — đã dính Bulletproofs, PlonK, Girault trong thực tế production).

Note có domain separator ở tầng EIP-1776 (§10.3) nhưng **không có ở tầng ZKP** — đây là lỗ hổng thật:

- Không có `chainId` ⇒ proof sinh trên private chain verify được trên Gnosis mainnet.
- Không có `address(this)` ⇒ **một proof của Z-USDT verify được trên Z-VND** khi hai contract dùng chung generator và account có cùng `zetherNonce`. Với Shared Singleton Registry (cùng `y`, cùng account trên mọi token), điều kiện này **rất dễ xảy ra** — hai token mới deploy đều có `zetherNonce = 0`. Đây không phải rủi ro lý thuyết.
- Không có nhãn `"ZETHER_TRANSFER_V1"` vs `"ZETHER_WITHDRAW_V1"` ⇒ một transfer proof bị diễn giải lại thành withdraw proof.
- Không có `proofSystemId` ⇒ nâng cấp verifier từ BP sang Groth16 mở ra cross-protocol replay trong giai đoạn hai verifier cùng sống.

Thứ tự hấp thụ phải cố định và có prefix độ dài cho mọi trường độ dài thay đổi (chống ambiguity: `"AB" ‖ "C"` vs `"A" ‖ "BC"`). Dùng Merlin transcript (`append_message(label, bytes)`) hoặc tự viết với quy tắc `H(len(x) ‖ x)`. Test `Transcript.frozenheart.t.sol`: đảo **từng field** của S, khẳng định proof fail — 14 trường ⇒ 14 test case, sinh bằng vòng lặp.

#### 3.4.8. Kiểm toán viên không đọc được số tiền — lỗ hổng nghiệp vụ lớn nhất (A14)

Note bán "Confidentiality with Accountability" và kết luận rằng vì sender/receiver công khai nên "tuân thủ 100% AML/KYC và kiểm toán". **Đồ thị công khai không đủ.**

- Kiểm toán BCTC cần **số tiền** để đối chiếu công nợ, không phải chỉ biết "A có chuyển cho B".
- Cơ quan thuế VN cần trị giá giao dịch cho hoá đơn/VAT.
- FATF Travel Rule yêu cầu truyền **amount** kèm originator/beneficiary. Đồ thị không đáp ứng.

Zether nguyên bản **không có cơ chế nào** cho việc này. Ba lựa chọn, phải chọn ở tầng deploy:

| Lựa chọn | Cơ chế | Chi phí | Tính chống chối bỏ | Đánh giá |
|---|---|---|---|---|
| **(a) Off-chain disclosure** | client xuất `v` + `s` cho auditor, auditor tự kiểm `C_out == g^v · y_to^s` | 0 gas | **có** — auditor verify được với dữ liệu on-chain | rẻ, nhưng **client có thể từ chối xuất** ⇒ không cưỡng chế được |
| **(b) Auditor ciphertext bắt buộc** | thêm `C_aud = g^v · y_aud^{s_a}`, `D_aud = g^{s_a}` + equality proof `v` giữa `C_out` và `C_aud` | +2 điểm calldata (128 B), +3 `ecMul` +2 `ecAdd` trong Sigma, ≈ **+25k gas, +256 B proof** | **có, và cưỡng chế được on-chain** | **khuyến nghị cho private profile, bắt buộc cho B2B settlement** |
| **(c) Escrow khoá `x`** | HSM giữ bản sao `x` dưới dual control | 0 gas | có | **phá toàn bộ mô hình bảo mật** — ai kiểm soát HSM đọc được tất cả. Chỉ chấp nhận nếu chính doanh nghiệp là chủ sở hữu duy nhất |

Chọn **(b)**. Nó rẻ (+1.3% gas), nó cưỡng chế được (contract `require` có `C_aud` khi `auditorKey != 0`), và nó giữ nguyên tính chất bảo mật với mọi bên trừ auditor. Bổ sung relation:

```
R9  C_aud = g^v · y_aud^{s_a}  ∧  D_aud = g^{s_a}        (cùng v với R3)
    Sigma bổ sung:  A_aud = g^{k_v} · y_aud^{k_sa}
                    V8:  g^{z_v} · y_aud^{z_sa} == A_aud · C_aud^c
```

Cấu hình: `auditor_pubkey` là trường trên `blockchain.zether.token`; `bytes32(0)` = tắt. **Đổi auditor key phải là timelock 7 ngày + event công khai** — nếu không, chủ contract lặng lẽ thêm mình làm auditor và đọc mọi giao dịch tương lai. Ghi vào threat model (§12).

Giới hạn phải nói rõ với khách hàng: **(b) chỉ cho auditor thấy giao dịch *tương lai* kể từ khi bật.** Không có cách nào cho auditor thấy giao dịch quá khứ trừ khi chủ tài khoản tự nguyện xuất — tức là quay về (a). Vì vậy: **bật auditor key ngay từ block đầu tiên của mọi Z-token dùng cho B2B**, không bật sau.

---

### 3.5. Epoch, pending, rollOver: bài toán liveness thật nằm ở chỗ khác

#### 3.5.1. Note mô tả sai cơ chế, và vì thế tự tạo ra một bài toán không tồn tại

Note viết: *"Đầu Epoch e+1, người dùng gọi hàm `rollOver()`"*, ngụ ý người nhận phải tự gọi, và tiền kẹt nếu họ không gọi. Trong Zether/`anonymous-zether` thật, `rollOver` là **idempotent, permissionless, và được contract gọi nội bộ ở đầu mọi entry point** cho mọi account mà transaction chạm tới — kể cả người nhận. **Người nhận không bao giờ phải làm gì và không bao giờ phải trả gì.** Ai gửi transaction thì trả (~26k gas nếu pending khác 0, ~2k nếu bằng 0). Đó là trả lời trực tiếp cho câu hỏi "ai trả tiền rollOver" trong brief.

Note cũng nêu sai **lý do** có epoch: *"nhiều giao dịch chuyển tiền đến cùng một tài khoản trong cùng block thì `r` và `C, D` xung đột"*. Không xung đột — ElGamal cộng đồng hình cộng được vô hạn khoản đến, `(C₁·C₂, D₁·D₂)` là ciphertext hợp lệ của `v₁+v₂`. Lý do thật: **proof của người GỬI nói về một giá trị `acc` cụ thể; nếu một khoản đến kịp landing trước tx của họ và làm đổi `acc`, proof hết hiệu lực và revert.** Epoch đóng băng `acc` suốt một epoch để proof sống sót. Hiểu đúng chỗ này mới thấy `simulateAccounts` tồn tại để làm gì.

#### 3.5.2. Ràng buộc throughput mà note bỏ sót hoàn toàn

`anonymous-zether` gốc dùng epoch-nonce `u = g_epoch^{x}` để chống double-spend trong epoch, và hệ quả là **mỗi account chỉ được gửi đi 1 giao dịch mỗi epoch**. Với `EPOCH = 5 block × 5 s` trên Gnosis: **1 outgoing transfer / 25 s / account = 3,456/ngày**. Một brand thanh toán 500 distributor với 3 lần chuyển mỗi ngày mỗi bên là 1,500 tx/ngày — vừa đủ. Nhưng một tài khoản treasury trung tâm phải chi 5,000 lần/ngày thì **nghẽn cứng ở 3,456**, và không có cách tăng ngoài việc giảm epoch (làm tăng tỷ lệ revert).

**Ở đây note thực sự tốt hơn ConsenSys và cần được ghi nhận:** `zetherNonce(fromSchnorrAddress)` là một counter **đơn điệu**, không phải epoch-tag. Với counter đơn điệu, nhiều lần gửi trong một epoch là hợp lệ — vì debit đánh **thẳng vào `acc`** (chỉ credit mới vào `pending`), nên client biết chính xác `acc` sau mỗi lần gửi mà không cần chờ chain. Đánh đổi: proof phải dựng **nối tiếp** trên cùng một `schnorrAddress`, không song song hoá được.

Nếu cần đồng thời: dùng **pool nhiều `schnorrAddress`** (một per settlement worker / per fund) — đúng tinh thần `batchId` 2D-nonce của EIP-1776, nhưng ở tầng Zether. Định lượng: prove 0.3 s (server-side, xem 3.8) ⇒ một `schnorrAddress` cho **~3 tx/s nếu prove là nút cổ chai, hoặc 1 tx / block time nếu chain là nút cổ chai**. Trên Gnosis (5 s block): **1 tx / 5 s / account = 17,280/ngày**. Cần 5,000/ngày ⇒ một account là đủ. Cần 100,000/ngày ⇒ tối thiểu 6 account, đề xuất 16 để có biên. Đưa `settlement_account_pool_size` thành tham số cấu hình, mặc định 4.

#### 3.5.3. `rollOver`: permissionless vừa owner-exclusive — không trên cùng một tài khoản, nhưng có trên cùng một contract

> **[BẢN 5 — user chốt 2026-09-03.]** Kết luận cũ của mục này (*"hai câu loại trừ nhau,
> chọn owner-exclusive"*) **đúng khi và chỉ khi bất biến được phát biểu toàn cục**. Tính
> chất mà owner-exclusive mua là tính chất của **tập hợp mọi đường làm `accSeq` tiến**, nên
> hai hàm cùng bump một counter trên **cùng một tài khoản** thì cửa có khoá mua 0 an toàn.
> Phát biểu lại **per-account** thì cả hai cùng tồn tại được, và bất biến vẫn kiểm được:
>
> > `accSeq[a]` tiến được mà không cần `a` đồng ý **⟺** `mode[a] == PUBLIC`.
>
> **Mặc định `PUBLIC`** — nó giải nút *"tài khoản chỉ nhận rồi im lặng bị kẹt"* và trả lại
> đúng ngữ nghĩa idempotent/permissionless của `anonymous-zether` mô tả ở §3.5.2.
> **`OWNER_ONLY` là opt-in, gán theo lớp rủi ro R3/R4** (treasury, B2B payout, off-ramp).
>
> Con grief mà mục này mô tả (~30k gas, lặp vô hạn) **bị chặn bằng một quy tắc contract,
> không bằng chữ ký**: `rollOverPublic` **no-op khi `pendingSeq[a] == lastRolledPendingSeq[a]`**
> ⇒ kẻ tấn công phải **nạp một khoản tiền thật cho nạn nhân** trước mỗi lần thử. Đó chính là
> grief-bằng-1-xu ở đoạn kế tiếp — con **đã tồn tại sẵn bất kể ai gọi `rollOver`** — nên
> `PUBLIC` không thêm một lớp grief mới, nó gộp vào lớp có sẵn. Xem `00-CANON.md` §C5 [BẢN 5]
> để có đủ bốn ràng buộc bắt buộc.


Bản nháp đề xuất "owner-exclusive rollover" — `pending → acc` chỉ xảy ra trong transaction do chính chủ khởi tạo — rồi ở cuối lại viết *"`rollOver(bytes32[] calldata)` nhận mảng, permissionless"*. **Hai câu này loại trừ nhau**, và nếu implement theo câu thứ hai thì toàn bộ lợi ích của câu thứ nhất biến mất:

> Nếu `rollOver(victim)` là permissionless, kẻ tấn công gọi nó ngay trước khi tx của nạn nhân landing ⇒ `acc[victim]` đổi ⇒ proof của nạn nhân revert. Chi phí tấn công: ~30k gas ($0.00006 trên Gnosis). Chi phí cho nạn nhân: mất phí relayer và phải prove lại. **Đây là griefing gần như miễn phí, lặp vô hạn.**

Và còn một lỗ nữa mà bản nháp không thấy: kể cả khi rollOver chỉ chạy trong tx của chính chủ, **nội dung `pending` vẫn thay đổi giữa lúc simulate và lúc landing** (bất kỳ ai cũng gửi tiền cho bạn được). Nếu tx của chủ tự động gộp `pending` vào `acc` ở đầu, thì `acc` sau khi gộp khác với `acc` mà proof đã giả định ⇒ revert. Vấn đề race **không** biến mất, nó chỉ đổi chỗ.

#### 3.5.4. Thiết kế đúng: tách rời, không tự gộp, khoá bằng `accSeq`

Ba quy tắc, và chúng phải đi cùng nhau:

```
QT1.  `acc` và `pending` là hai slot tách biệt. transferConfidential và withdraw
      KHÔNG BAO GIỜ tự động gộp pending vào acc.
      Proof chỉ nói về `acc`.

QT2.  Mọi credit đến (transfer từ người khác, và cả deposit) chỉ cộng vào `pending`.
      pending[to] += C_out  (2 ecAdd). Đồng thời pendingSeq[to]++.

QT3.  `pending -> acc` chỉ xảy ra trong hàm rollOver().
      [BAN 5] Ai goi duoc no la tham so per-account:
        mode[a] == PUBLIC     -> bat ky ai (rollOverPublic / rollOverBatch),
                                 NO-OP khi pendingSeq[a] == lastRolledPendingSeq[a]
        mode[a] == OWNER_ONLY -> chi chu (Schnorr signature hoac controller EOA),
                                 thong diep BAT BUOC mang validUntilBlock
      rollOver khong co ZK proof, khong the fail vi ly do mat ma.
      No set accSeq[a] = pendingSeq[a].
```

Trạng thái mỗi tài khoản mỗi token:

| slot | kiểu | ai đổi được | dùng làm gì |
|---|---|---|---|
| `acc[a]` | `(C, D)` | chỉ tx được `a` uỷ quyền | nguồn của mọi proof |
| `pending[a]` | `(C, D)` | bất kỳ ai (credit) | nơi tiền đến nằm chờ |
| `accSeq[a]` | `uint64` | `rollOver(a)` — **[BẢN 5]** bất kỳ ai nếu `mode[a] == PUBLIC`, chỉ chủ nếu `OWNER_ONLY` | **được băm vào Fiat-Shamir**; contract `require(accSeq == provedAccSeq)` |
| `pendingSeq[a]` | `uint64` | mỗi credit | client dùng để biết có tiền mới |
| `zetherNonce[a]` | `uint64` | mỗi debit thành công | anti-replay của proof |

Vì `accSeq` chỉ đổi khi `rollOver` chạy, proof đang bay chỉ chết khi có người bump được `accSeq`. Với `mode == OWNER_ONLY` thì **không ai ngoài chủ làm được** — đây là điều mà "owner-exclusive rollover" muốn đạt được nhưng cơ chế của bản nháp không đạt. **[BẢN 5]** với `mode == PUBLIC` (mặc định) thì bất kỳ ai bump được, nhưng **chỉ sau khi nạp tiền thật cho nạn nhân** (quy tắc no-op), nên chi phí grief bằng đúng chi phí grief-bằng-1-xu vốn không xoá được.

Ba entry point. **[BẢN 5]** cờ `RollOverMode` quyết định cái nào chạy được cho một tài khoản; cờ đặt lúc register, **chỉ chủ đổi được**, và **phải có trong `v1`** vì token bất biến (thêm sau = deploy version mới + di cư người dùng):

```solidity
enum RollOverMode { PUBLIC, OWNER_ONLY }   // 1 bit, pack vao slot da co

// Duong MAC DINH: khong chu ky. Revert neu mode[acct] == OWNER_ONLY.
// NO-OP (khong revert, khong bump accSeq) khi pendingSeq[acct] == lastRolledPendingSeq[acct].
function rollOverPublic(bytes32 acct) external;                 // ~20k gas khi co viec, ~2k khi no-op
function rollOverBatch(bytes32[] calldata accts) external;      // bo qua phan tu OWNER_ONLY, khong revert ca lo

function setRollOverMode(bytes32 acct, RollOverMode m, bytes calldata sig) external;  // chi chu
```

Đường có chữ ký — **bắt buộc cho `OWNER_ONLY`**, và vẫn dùng được bởi chủ của tài khoản `PUBLIC`:

```solidity
// Biến thể A: Schnorr, không cần EOA, gasless được, tương thích custody MPC/HSM
function rollOver(
    bytes32 acct,
    uint64  expectedPendingSeq,   // chống rollOver trùng, và cho phép client biết nó gộp cái gì
    uint64  validUntilBlock,      // BẮT BUỘC — xem "tấn công giữ blob" ngay dưới
    bytes32[2] calldata R,        // Schnorr commitment
    bytes32 z                     // Schnorr response
) external;
//  require(block.number <= validUntilBlock);            // vài trăm gas
//  message = H(chainId, address(this), "ZETHER_ROLLOVER_V1",
//              acct, accSeq[acct], expectedPendingSeq, validUntilBlock)
//  cost: 2 ecMul + 1 ecAdd + keccak + 10 SSTORE + event  ≈ 13k + ~18k = ~31k gas

// Biến thể B: controller EOA gắn ở registry, rẻ hơn, kém linh hoạt hơn
function rollOverByController(bytes32 acct, uint64 expectedPendingSeq) external;
//  require(msg.sender == registry.controllerOf(acct) || _isMetaTxFrom(registry.controllerOf(acct)));
//  cost: ~2.1k SLOAD + ~18k SSTORE = ~20k gas
//  KHÔNG cần validUntilBlock: chữ ký không tồn tại, quyền đến từ msg.sender tại thời điểm gọi.
```

**`validUntilBlock` không phải trang trí — thiếu nó thì §3.5.3 nói sai về chính mình.** §3.5.3 kết luận
"vì `accSeq` chỉ đổi khi chính chủ rollOver, không ai grief được proof đang bay". Điều đó **chỉ đúng khi
chữ ký rollOver không sống lâu hơn ý định của người ký.** Kịch bản, gọi là **tấn công giữ blob**:

1. Chủ tài khoản ký một `rollOver` hợp lệ ở block `N` (ví dụ để gộp một khoản vừa nhận), và vì lý do
   nào đó nó không lên chuỗi — relayer bỏ, mạng nghẽn, hoặc chính chủ đổi ý.
2. Kẻ tấn công **giữ lại** blob đã ký đó. Nó hợp lệ vĩnh viễn: không có trường nào trong thông điệp
   ràng buộc thời gian, và `expectedPendingSeq` chỉ chống gọi trùng chứ không chống gọi **muộn**.
3. Ở block `N + 5000`, chủ tài khoản phát một `transferConfidential` chứng minh trên `accSeq = k`.
4. Kẻ tấn công phát blob cũ **ngay trước** đó. `rollOver` chạy, `accSeq` thành `k+1`, và
   `require(accSeq == provedAccSeq)` làm transfer revert — sau khi đã đốt gần hết gas verify
   (~1.79 M gas trên bn254, §3.3.6, vì `accSeq` được kiểm ở fail-fast **trước** MSM chỉ khi contract
   xếp đúng thứ tự; nếu xếp sai thì mất toàn bộ).

Chi phí tấn công: một tx ~31k gas. Thiệt hại: một lần prove lại cộng phí relayer, lặp lại được mỗi lần
nạn nhân thử. Đúng bằng griefing mà `accSeq` sinh ra để loại bỏ — chỉ khác là nó đi vòng qua chữ ký cũ
của chính nạn nhân thay vì qua một lời gọi permissionless.

`validUntilBlock` đóng nó lại với giá vài trăm gas. Quy tắc ví: đặt `validUntilBlock = block.number + W`
với `W` ngắn — đề xuất **`W = 50 block`** trên Gnosis (~4 phút, đủ cho một lần relay chậm, không đủ để
thành vũ khí). Client **không** được đặt `W` lớn "cho chắc": một `W = 100,000` là quay lại đúng lỗ hổng
trên.

Và một hệ quả cho §21/§22: một `rollOver` đã ký nằm trong pool của node relayer là một blob có hạn dùng,
nên `expiry` của intent bọc nó phải **không dài hơn** `validUntilBlock` quy ra thời gian. Node từ chối
intent nào vi phạm — đây là một dòng trong thang hàng rào L2 của §22.3, không phải một kiểm tra riêng.

**Trong hai biến thể có chữ ký, mặc định là A** — nó không đòi hỏi tài khoản Zether phải gắn với một EOA, điều bắt buộc nếu custody là MPC hoặc smart-account/passkey (quyết định đã chốt số 6). Biến thể B là tối ưu cho profile custodial. **[BẢN 5]** cả hai chỉ là đường của `OWNER_ONLY`; mặc định của hệ thống là `rollOverPublic`, và nó **không cần crypto stack riêng** vì không có chữ ký nào để verify.

`rollOver` **relay được**: nó là một lời gọi contract bình thường, bọc trong `metaTx.data` như mọi thứ khác, và **batch được**. **[BẢN 5]** hai hình batch, và chúng khác nhau về giá: `rollOverBatch(bytes32[] accts)` cho tài khoản `PUBLIC` — **không chữ ký nào**, nên một indexer quét ra danh sách tài khoản có `pending` cũ và dọn một lượt (+70 k gas/tài khoản, §C7.3); `rollOverBatch(bytes32[] accts, uint64[] seqs, Sig[] sigs)` cho tài khoản `OWNER_ONLY` — mỗi phần tử một chữ ký, nên chỉ hữu ích khi một pháp nhân sở hữu nhiều account (settlement pool ở 3.5.2). Trả lời trực tiếp cho brief: **"can it be batched or relayer-driven" — được cả hai, và permissionless là mặc định trừ tài khoản đăng ký `OWNER_ONLY`.**

#### 3.5.5. So sánh ba thiết kế

| | Zether gốc (epoch rollover) | "owner-exclusive" của bản nháp | **accSeq (thiết kế này)** |
|---|---|---|---|
| `acc[a]` bị đổi bởi | bất kỳ ai chạm vào `a` | tx của `a` — nhưng nội dung phụ thuộc `pending` của người khác | **chỉ `rollOver(a)` do `a` uỷ quyền** |
| Proof phụ thuộc epoch | **có** → phải pin `provedEpoch` | không, nhưng phụ thuộc `pending` | **không** — chỉ `zetherNonce` + `accSeq` |
| Grief bằng cách gửi 1 xu | **có** (đổi acc) | **có** (đổi kết quả gộp) | **không** |
| Grief bằng cách gọi rollOver | có | **có nếu permissionless** | **[BẢN 5]** `OWNER_ONLY`: **không** — cần chữ ký chủ. `PUBLIC`: chỉ sau khi kẻ tấn công **nạp tiền thật** (no-op khi `pending` rỗng), tức quy về đúng cột grief-bằng-1-xu |
| Xác suất revert do race | ~40% (tính ở dưới) | trung bình | **~0** |
| Tiền có kẹt được không | không | không | **không** |
| Số tx để tiêu tiền vừa nhận | 1 | 1 | **2** (rollOver + transfer) hoặc 1 nếu đã rollOver sẵn |
| `pending` phình to | 1 epoch | vô hạn thời gian | vô hạn thời gian, **vẫn đúng 2 điểm** — storage O(1) |
| Giải mã `pending` | BSGS | BSGS | **memo, O(1)** (3.2.5) |

Vì sao chuyện pin epoch là nghiêm trọng nếu **không** làm như trên: relayer mất 1–3 block giữa `eth_call` mô phỏng và inclusion. Trên Gnosis với `EPOCH = 5 block`, xác suất một tx đã simulate-pass bị lệch epoch ≈ `2/5 = 40%` nếu submit tại thời điểm ngẫu nhiên trong epoch. 40% revert là không dùng được. Cách vá thô là kéo `EPOCH_LENGTH ≥ 20 block` (100 s trên Gnosis) — nhưng khi đó tiền nhận được phải chờ tới 100 s mới tiêu được, và grief-bằng-1-xu vẫn còn. Thiết kế `accSeq` xoá cả ba vấn đề.

**Cái giá phải trả, nói thẳng: một transaction thừa.** Để tiêu tiền vừa nhận, ví phải `rollOver(self)` trước. Ba cách giảm ma sát:

1. **Rollover chủ động nền.** Ví/relayer theo dõi `pendingSeq` và tự gọi `rollOver` khi có tiền mới, gasless qua EIP-1776. Người dùng không thấy gì. Chi phí: ~28k gas ≈ $0.00006 trên Gnosis. Ở 10,000 credit/ngày = **$0.6/ngày cho toàn hệ thống**. Không đáng bàn.
2. **Gộp hai lời gọi trong một meta-tx** `[rollOver(self, seq), transferConfidential(...)]`. An toàn **chỉ khi** client pin `expectedPendingSeq` — nếu có credit mới chen vào, rollOver revert và cả batch revert. Đó là lựa chọn có ý thức: `strict_fold = true` (fail sạch) vs `false` (rollOver riêng, transfer dùng `acc` cũ, tiền mới chờ lần sau). **Mặc định `false`.**
3. **Không cần rollOver nếu `acc` đã đủ.** Ví kiểm `acc >= v + fee` trước; chỉ rollOver khi thiếu. Với tài khoản có float thường xuyên, rollOver hiếm khi nằm trên critical path.

#### 3.5.6. Trả lời dứt điểm các câu hỏi liveness của brief

| Câu hỏi | Trả lời |
|---|---|
| Người nhận không bao giờ gọi rollOver thì sao? | Tiền **không kẹt**: nó nằm trong `pending`, đọc được, giải mã được (memo), và trở thành khả dụng ngay khi họ rollOver, bất kể sau bao lâu. Không có hạn. |
| Tiền có "stuck pending" không? | Không. `pending` không hết hạn, không bị prune, không cần gas để duy trì (khác Soroban state rent). |
| Ai trả cho rollOver? | Bất kỳ ai submit tx — thường là relayer, được hoàn bằng `fee` của meta-tx. Chủ tài khoản chỉ phải **ký**, không phải trả. |
| Batch được không? | Được: `rollOverBatch`, nhưng mỗi account cần chữ ký riêng. Hữu ích cho settlement pool một pháp nhân. |
| Relayer-driven được không? | Được, và **nên** là mặc định (rollover chủ động nền, mục 3.5.5 điểm 1). |
| Có kịch bản nào tiền thật sự mất không? | Có **một**: mất `x`. Không có `x` thì không rollOver được, không tiêu được, không giải mã được. Xem 3.11. |

---

### 3.6. `simulateAccounts`: đúng ý tưởng, thiếu bốn thứ

Note nói đúng rằng dựng proof trên số dư tĩnh đọc từ chain sẽ revert. Nhưng chữ ký trong note có bốn lỗ:

1. **Trả về thiếu.** Client cần `acc`, `pending`, `zetherNonce`, `accSeq`, `pendingSeq` và `block.number` **cùng một block**. Hai lần `eth_call` riêng có thể vắt qua block boundary và cho một ảnh chụp không nhất quán — đúng loại bug xuất hiện một lần một tuần và không reproduce được. Gộp một struct, một lời gọi.
2. **`epoch` là tham số đầu vào nhưng không có gì ép transaction phải nằm trong epoch đó.** Nếu giữ mô hình epoch-based, phải thêm `provedEpoch` vào struct, băm nó vào challenge, và `require(provedEpoch == block.number / EPOCH_LENGTH)`. Không có nó thì `simulateAccounts` chỉ là hình thức. Với thiết kế `accSeq` ở 3.5.4, tham số `epoch` **biến mất hoàn toàn** và được thay bằng `accSeq` — một đại lượng không phụ thuộc thời gian, nên không có cửa sổ hết hạn.
3. **Không giới hạn độ dài mảng** — `eth_call` có gas cap ở tầng node (`--rpc.gascap`, mặc định geth 50 M; nhiều RPC công cộng đặt 10 M hoặc thấp hơn). Mỗi account đọc 10 slot cold ≈ 21k gas ⇒ ở 10 M cap, trần thực tế là ~470 account. Cap ở **256** để có biên và để phản hồi < 200 ms.
4. **Tên hàm nói dối.** Nó không "simulate" gì cả trong thiết kế `accSeq` — nó chỉ đọc state. Đặt tên `viewAccounts` để không ai tưởng nó chạy logic gộp.

```solidity
struct AccountView {
    bytes32[2] C_acc;    bytes32[2] D_acc;
    bytes32[2] C_pend;   bytes32[2] D_pend;
    uint64     zetherNonce;
    uint64     accSeq;
    uint64     pendingSeq;
    bool       registered;
}

/// @notice Ảnh chụp nguyên tử tại 1 block cho tối đa 256 tài khoản.
/// @dev Không có tham số epoch: acc chỉ đổi khi chính chủ rollOver (xem 3.5.4).
function viewAccounts(bytes32[] calldata schnorrAddresses)
    external view returns (AccountView[] memory views, uint256 atBlock, bytes32 atBlockHash);
```

Trả thêm `atBlockHash` để client phát hiện reorg giữa lúc đọc và lúc submit: nếu block đó không còn trên canonical chain, proof có thể đã dựng trên state chết. Kiểm rẻ: một `eth_getBlockByNumber` khi tx pending quá 3 block.

**Quy trình client đầy đủ**, viết ra để không ai bịa lại:

```
1. views, atBlock, atHash  = viewAccounts([self, counterparty])
2. require(views[1].registered)                     // người nhận đã register chưa
3. if acc(self) < v + fee:
       rollOver(self, views[0].pendingSeq)          // meta-tx riêng, chờ landing
       goto 1
4. b       = localLedger.balance(self)              // từ memo, không BSGS
   assert  g^b == C_acc · D_acc^{-x}                // kiểm chéo, fail loud
5. proof   = prove(statement(views[0].accSeq, views[0].zetherNonce, ...), witness)
6. metaTx  = wrap(transferConfidential(...), mode = MODE_RESTRICT_RELAYER)
7. relayer.simulate(metaTx) -> eth_call tại block hiện tại
8. relayer.broadcast(metaTx)
9. Finality Gate (3.9.5) -> _set_done
```

Bước 4 là thứ bản nháp không có và nó là ranh giới an toàn cuối cùng của client: nếu sổ cục bộ lệch với chain, **dừng**, đừng dựng proof, vì proof sẽ đúng về mặt mật mã nhưng sai về số tiền.

---

### 3.7. `withdraw`, anti-MEV, và ranh giới bảo mật thật

#### 3.7.1. Statement của withdraw

Note đúng: `recipient` phải bị **băm chặt vào Fiat-Shamir challenge**. Statement đầy đủ:

```
S_w = chainId ‖ address(this) ‖ "ZETHER_WITHDRAW_V1" ‖ proofSystemId
    ‖ schnorrAddress ‖ y_self
    ‖ recipient ‖ amount ‖ fee ‖ zetherNonce ‖ accSeq
    ‖ C_acc ‖ D_acc

Relations:
  W1  y_self = g^{x}
  W2  b' = b − amount − fee, và b' là dlog của
        (C_acc · g^{-(amount+fee)}) · (D_acc^{x})^{-1}
  W3  b' ∈ [0, 2^{n_b})                    Bulletproof (một proof, không phải hai)
  W4  linkage b' giữa W2 và V_b            Sigma-Bullets
```

`amount` và `fee` đều public ⇒ **không cần range proof cho chúng**, chỉ `require(amount + fee < 2^{n_v})` và kiểm tràn. Chỉ **một** Bulletproof (n_b = 64) ⇒ MSM 148 điểm ⇒ **~0.97 M + 0.30 M ≈ 1.27 M gas**. Withdraw rẻ hơn transfer ~32%.

#### 3.7.2. Anti-MEV chỉ chặn redirect, không chặn grief

Relayer độc hại không đổi được `recipient` (đổi 1 byte ⇒ challenge lệch ⇒ verify fail). Nhưng vẫn có thể:

- **Censor** — nhận payload rồi không broadcast. Không mất gì, người dùng chờ vô hạn.
- **Grief bằng nonce** — không áp dụng ở đây vì `zetherNonce` chỉ tăng khi tx thành công.
- **Front-run bằng chính giao dịch đó với `feeRecipient` khác** — hợp lệ theo `MODE_OPEN`, người dùng không thiệt, relayer trung thực thiệt gas.

Chính sách: với mọi `withdraw` giá trị lớn, dùng `MODE_RESTRICT_RELAYER (0x01)` **và** luôn giữ đường **direct-call fallback** bằng ví EOA có native gas. Timeout ở client: nếu không thấy tx trong 5 block, thử relayer khác; sau 3 relayer, chuyển sang direct-call. Đây là logic phải nằm trong SDK, không phải trong runbook.

#### 3.7.3. `amount` của withdraw là công khai — và đó là chỗ rò rỉ thật

Token rời escrow pool nên số tiền phải lộ. Nghĩa là **ranh giới bảo mật nằm ở `deposit`/`withdraw`, không phải ở `transferConfidential`.**

Định lượng rò rỉ — đây là phần bản nháp chỉ nói định tính. Với mọi tài khoản `a`, bất biến sau luôn đúng và **công khai một phần**:

```
Σ deposit(a) + Σ v_in(a) = Σ withdraw(a) + Σ v_out(a) + Σ fee(a) + balance(a)
   ^ public       ^ ẩn         ^ public        ^ ẩn        ^ public   ^ ẩn
```

Hệ quả có thể tính:

| Hình dạng tài khoản | Rò rỉ |
|---|---|
| Deposit X, một transfer đi, withdraw 0, drain hết (balance 0) | `v_out = X − fee`. **Lộ 100%.** |
| Deposit X, một transfer đi, giữ lại float | `v_out ≤ X − fee`. Lộ cận trên. |
| Deposit X, k transfer đi, drain hết | `Σ v_out = X − Σfee`. Lộ tổng, không lộ phân bổ (nếu k ≥ 2). |
| Không deposit, chỉ nhận rồi chuyển tiếp, không withdraw | lộ **0**. |
| Deposit đúng bằng số sắp chuyển, cùng block | lộ 100% và còn lộ cả ý định |

Đồ thị confidential là **công khai** (sender/receiver lộ theo thiết kế). Nếu đồ thị là một **cây** (mỗi node có đúng 1 cạnh vào hoặc 1 cạnh ra) và các lá đều có deposit/withdraw public, hệ phương trình tuyến tính trên **xác định duy nhất mọi `v`**. Đây không phải tấn công lý thuyết — mô hình B2B "brand nạp tiền → chuyển cho distributor → distributor rút" **chính là một cây hai tầng**.

Chính sách vận hành, phải đưa vào SDK dưới dạng cảnh báo cứng:

1. **Không bao giờ deposit một số bằng (hoặc gần bằng) số sắp chuyển.** SDK cảnh báo khi `|deposit − pendingTransfer| / deposit < 0.1`.
2. **Netting bên trong Zether.** Chuyển tiền giữa các đối tác nhiều lần trước khi ai đó rút.
3. **Rút thưa và rút số tròn.** Rút theo lịch cố định (ví dụ thứ Sáu hàng tuần) với số làm tròn tới bội của 10^6 đơn vị ledger, không rút đúng số dư.
4. **Giữ float khác 0 vĩnh viễn.** Một tài khoản drain về 0 tự khai báo toàn bộ dòng tiền của nó.
5. Với `n ≥ 3` counterparty và float ≠ 0, hệ phương trình **under-determined** và rò rỉ giảm về cận trên. Đó là ngưỡng cần đạt.

Ghi thẳng vào tài liệu bán hàng: **Zether bảo vệ số tiền khỏi người quan sát ngẫu nhiên, không bảo vệ khỏi một đối thủ chịu khó giải hệ phương trình trên đồ thị công khai.** Nói ngược lại là bán sai hàng.

#### 3.7.4. Escrow invariant, và ba loại ERC-20 sẽ phá nó (A5)

```solidity
// cuối mọi withdraw và mọi lần trả fee:
require(
    IERC20(underlying).balanceOf(address(this)) >= totalDepositedScaled * scaleDivisor
                                                  - totalWithdrawnScaled * scaleDivisor,
    "ZTH: escrow invariant violated"
);
```

Cộng một watcher off-chain gọi `pause()` khi lệch. Đây là cái lưới chặn dưới của soundness break ở 3.1.3, và là thứ biến "curve gãy = mất hết tiền" thành "curve gãy = mất tối đa số đang trong pool, phát hiện trong vòng 1 block".

Ba loại token phá nó, và note không nhắc loại nào:

| Loại | Vấn đề | Xử lý |
|---|---|---|
| **Fee-on-transfer** (USDT có công tắc phí, hiện = 0; nhiều token VN không) | `transferFrom(x)` chỉ về `x − φ` ⇒ invariant lệch ngay từ deposit đầu | `deposit` **đo delta thật**: `before = balanceOf(this); safeTransferFrom(...); received = balanceOf(this) − before;` rồi scale `received`. Bắt buộc, không tuỳ chọn. |
| **Rebasing** (aToken, stETH) | `balanceOf` đổi mà không có transfer ⇒ invariant lệch ngẫu nhiên cả hai chiều | **Cấm.** `deposit` không thể biết bao nhiêu là của ai khi số dư mã hoá. Allowlist token ở deploy, mặc định từ chối. |
| **Blacklist** (USDC, USDT) | Issuer blacklist địa chỉ escrow ⇒ **mọi withdraw revert vĩnh viễn, toàn bộ số dư mã hoá của mọi người đóng băng không có đường thoát** | **Không có mitigation kỹ thuật.** Không thể làm emergency-withdraw vì contract không biết ai có bao nhiêu. Xem dưới. |

Vấn đề blacklist đáng được nói thẳng vì nó là rủi ro tồn tại của cả hệ:

> Nếu Circle blacklist địa chỉ `ZetherToken(USDC)`, tiền của tất cả người dùng bị khoá vĩnh viễn. Contract không thể phân phối lại vì nó **không biết** số dư của ai — đó chính là mục đích của nó. Đây là chế độ hỏng duy nhất trong toàn bộ thiết kế mà **không có đường phục hồi kỹ thuật nào**.

Giảm thiểu, không phải giải quyết:

1. **Ưu tiên underlying không có blacklist**: xDAI (không có), DAI (không có), token do chính doanh nghiệp phát hành (kiểm soát được). **Tránh USDC/USDT làm underlying cho pool lớn.**
2. **Chia pool**: nhiều `ZetherToken` instance cho cùng một underlying, mỗi cái trần $500k. Blacklist một cái không chết cả hệ. Chi phí: thanh khoản phân mảnh, người dùng phải register nhiều account (Shared Registry giúp: register một lần, dùng mọi token).
3. **Đường thoát tự nguyện có thời hạn**: nếu contract `paused` quá 90 ngày, mở `emergencyRevealWithdraw(amount, proof)` — người dùng tự khai số dư và chứng minh, chấp nhận lộ số tiền để lấy tiền ra. Rò rỉ toàn bộ, nhưng tốt hơn mất trắng. **Phải có, và phải nói với khách hàng là nó tồn tại.**
4. Ghi vào §12 threat model và §13 legal như một rủi ro được chấp nhận có ý thức, có chữ ký.

#### 3.7.5. Reentrancy và thứ tự thao tác

`withdraw` chuyển ERC-20 ra ngoài ⇒ ERC-777 hook hoặc một `recipient` là contract có thể reenter. Áp Checks-Effects-Interactions **và** `ReentrancyGuardUpgradeable` (note đã yêu cầu ở §10.2.1, giữ nguyên):

```
1. checks:       registry, nonce, accSeq, range, invariant tiền-điều-kiện
2. verify proof  (view, không đổi state)
3. effects:      acc[a] = new; zetherNonce[a]++; totalWithdrawnScaled += amount
4. interactions: safeTransfer(recipient, ...); safeTransfer(feeRecipient, ...)
5. checks:       escrow invariant hậu-điều-kiện
```

Verify proof đặt **trước** effects nhưng **sau** checks rẻ tiền — để một tx sai nonce revert với 5k gas thay vì 1.3 M. Điều này quan trọng với relayer thua cuộc đua ở 3.4.4: chi phí thua giảm từ ~1.3 M xuống ~30k gas.

#### 3.7.6. Anti-replay hai tầng

Ngoài: `meta_nonce(from, batchId)` — `from` ở đây là **EOA/smart-account ký meta-tx**. Trong: `zetherNonce(fromSchnorrAddress)` — một **danh tính khác**, có thể không tương ứng 1-1 với EOA nào (trường hợp custody MPC).

Note không nói hai cái này có phải bind vào nhau không. Phân tích:

- Payload Zether nằm trong `metaTx.data`, đã được chữ ký EIP-712 phủ ⇒ relayer không sửa được nội dung.
- Ngược lại, ai đó **có thể** bóc payload Zether ra khỏi envelope này và nhét vào envelope khác (envelope của chính họ). Nhưng `zetherNonce` chặn nó chạy lần hai ⇒ hậu quả tối đa là **một relayer khác ăn `fee`**, đúng semantic `MODE_OPEN`.
- Chiều ngược lại quan trọng hơn: **có cần `zetherNonce` bind vào `meta_nonce` không? Không, và không nên.** Bind chúng sẽ làm một meta-tx thất bại khoá luôn nonce Zether, tạo head-of-line blocking đúng thứ mà 2D-nonce sinh ra để tránh.

**Không phải lỗ hổng, nhưng phải viết lý do ra spec** thay vì để ngầm định — vì reviewer tiếp theo sẽ hỏi đúng câu này và nếu không có câu trả lời sẵn, ai đó sẽ "sửa" bằng cách bind chúng lại.

Bảng đầy đủ các cơ chế anti-replay đang hoạt động đồng thời:

| Tầng | Cơ chế | Chống | Tiêu thụ khi nào |
|---|---|---|---|
| Meta-tx | `meta_nonce(from, batchId)` | replay envelope | tx thành công |
| Meta-tx | `expiry` (Unix ts) | delayed replay | — |
| Meta-tx | EIP-712 domain: `chainId` + `verifyingContract` | cross-chain, cross-contract | — |
| Zether | `zetherNonce[a]` trong FS challenge | replay proof/ciphertext | debit thành công |
| Zether | `accSeq[a]` trong FS challenge | proof dựng trên state cũ | rollOver |
| Zether | `chainId` + `address(this)` trong FS challenge | cross-chain, cross-token | — |
| Zether | domain tag `"ZETHER_TRANSFER_V1"` | cross-operation (transfer↔withdraw) | — |
| Zether | `proofSystemId` trong FS challenge | cross-verifier khi nâng cấp | — |

Bảy cơ chế. Sáu trong số đó không có trong note. Mỗi cái vắng mặt là một lớp CVE.

#### 3.7.7. Ai trả cho một validation thất bại

Cả hai nonce chỉ bị tiêu khi tx thành công (revert là revert toàn bộ), nên relayer đốt gas mà không thu được gì. EIP-1776 **không có** phase tách validation/execution như ERC-4337 — đây là một nhược điểm thật của chuẩn đã chốt, và cách bù là ở tầng vận hành chứ không phải tầng contract:

1. Relayer **`eth_call` đúng tx tại đúng block ngay trước khi broadcast** (Simulation Gate §10.4).
2. Với thiết kế `accSeq`, rủi ro tồn dư gần như bằng **0**: state của sender chỉ đổi khi chính sender gửi tx, mà sender không gửi hai tx cùng lúc trên cùng `schnorrAddress` (3.5.2).
3. Rủi ro còn lại duy nhất: **hai relayer cùng broadcast cùng một payload** (đua fee ở `MODE_OPEN`). Giải bằng `MODE_RESTRICT_RELAYER` (3.4.4).
4. Sắp xếp checks rẻ trước verify (3.7.5) để cái giá thua cuộc là 30k chứ không phải 1.3 M gas.

Với bốn biện pháp này, tỷ lệ tx hỏng của relayer nên < 0.1%, và chi phí thua ~$0.00006/lần trên Gnosis. Đó là con số cần cho mô hình kinh tế relayer ở §05/§06.

---

### 3.8. Thời gian prove phía client và hệ quả UX

#### 3.8.1. Cơ sở ước tính

Mốc gốc: `dalek-cryptography/bulletproofs` trên ristretto255, x86 AVX2 — một range proof 64-bit: **prove ~7–8 ms, verify ~1.2 ms** (bench công bố, single core, Skylake 3.5 GHz).

Hệ số quy đổi, mỗi cái nêu lý do:

| Hệ số | Giá trị | Lý do |
|---|---|---|
| BN254 vs ristretto255 | **×2.5** | Weierstrass 254-bit, không có complete Edwards addition law, cần Jacobian + nhiều nhánh; field 254 bit vs 255 bit không đáng kể, khác biệt nằm ở nhóm |
| Baby Jubjub vs ristretto255 | **×1.3** | cũng là twisted Edwards, nhưng field 254-bit của BN254 chậm hơn 2^255−19 (Montgomery reduction vs pseudo-Mersenne) |
| WASM vs native | **×3–4** | không có 64×64→128 mul intrinsic; `wasm-bindgen` overhead; SIMD128 bù lại một phần |
| ARM64 tầm trung vs x86 desktop | **×4–6** | Snapdragon 6xx/7xx ~2020: clock thấp hơn, cache nhỏ hơn, không AVX2 tương đương |
| JS thuần (noble-curves) vs Rust native | **×30–60** | BigInt của JS, không có carry-propagation nguyên thuỷ |

Khối lượng ở cấu hình đề xuất (`n_v = 32`, `n_b = 64`, hai BP chung transcript, cộng Sigma 23 exp) ≈ **1.5×** một proof 64-bit đơn: prover làm ~4·(32+64) = 384 scalar mul cho hai BP, cộng ~14 cho Sigma.

#### 3.8.2. Bảng thời gian, cấu hình 32/64 trên BN254

| Nền tảng | backend | prove | verify (client tự kiểm) | RAM đỉnh |
|---|---|---|---|---|
| Server x86, Rust native (arkworks/gnark bn254), 1 core | native | **~30–50 ms** | ~10–20 ms | ~8 MB |
| Desktop browser, Rust → WASM + SIMD | wasm | **~0.15–0.35 s** | ~50–100 ms | ~20 MB |
| Android tầm trung (Snapdragon 6xx/7xx ~2020), Rust qua JNI/UniFFI | ARM64 native | **~0.20–0.50 s** | ~70–150 ms | ~10 MB |
| Android tầm trung, WASM trong WebView | wasm | **~0.8–2.5 s** | ~0.3–0.8 s | ~30 MB |
| iPhone 12+ / Android flagship, native | ARM64 | ~0.08–0.15 s | ~30 ms | ~10 MB |
| React Native / browser, **JS thuần** (noble-curves) | JS | **~15–45 s** | ~5–15 s | ~80 MB |

Ở cấu hình 128/128 của note, nhân các số trên với **~2.5×** (prover MSM ≈ 2× số bit, cộng thêm một vòng IPA). Android tầm trung native: **0.5–1.25 s**. Vẫn dùng được, nhưng gas verify đã loại cấu hình đó rồi (3.3.8).

Trên Baby Jubjub (khuyến nghị ở 3.3.9), chia các số BN254 cho ~1.9: Android tầm trung native **~0.11–0.26 s**. Baby Jubjub prove **nhanh hơn** BN254 G1 — thêm một lý do chọn nó.

#### 3.8.3. Ngân sách UX theo use case

Con số quyết định không phải "prove mất bao lâu" mà là "người dùng chờ bao lâu từ lúc bấm nút tới lúc thấy kết quả". Chuỗi đầy đủ:

```
viewAccounts RPC      80 – 250 ms   (Gnosis RPC, p95)
prove                 xem bảng
ký meta-tx (HSM/MPC)  50 – 800 ms   (MPC 2-of-3 qua mạng: 300–800 ms; HSM local: 20–50 ms; passkey: 200–500 ms + UI sinh trắc)
relayer simulate      50 – 150 ms
broadcast → included  5 – 10 s      (1–2 block Gnosis)
Finality Gate         xem 3.9.5
```

| Use case | Ngân sách tới "pending" | Đạt được? | Ghi chú |
|---|---|---|---|
| **Loyalty points**, app Android tầm trung | < 2 s | **có** (0.25 + 0.3 + 0.15 ≈ 0.7 s tới broadcast) | hiển thị "đang ghi nhận", không chờ finality |
| **End-user payment tại quầy** | < 3 s tới "chấp nhận" | **có nếu** dùng Bulletproofs + native ARM64 | Groth16 **hỏng ở đây** (3–10 s prove) |
| **B2B settlement**, server-side | < 60 s | thừa sức | prove trên server, Groth16 chấp nhận được |
| **End-user payment trong browser**, WASM | < 3 s | **biên** (0.35 + 0.3 ≈ 0.65 s + RPC) | phải có SIMD; không có SIMD thì 1.5–3 s |
| Bất kỳ cái nào, **JS thuần** | — | **không** | 15–45 s |

#### 3.8.4. Ba kết luận cứng cho kế hoạch triển khai

1. **JS thuần không phải một lựa chọn.** Bắt buộc có một Rust core biên dịch ra `.so` ARM64 + x86_64 (Android, JNI hoặc UniFFI), `.xcframework` (iOS), và `.wasm` có SIMD (browser). Đây là yêu cầu **build-system** phải nằm trong plan ngay từ sprint đầu, không phải tối ưu về sau. Kích thước artifact ước tính: `.so` ~1.2 MB stripped, `.wasm` ~700 KB gzip. Với `.wasm`, phải có fallback không-SIMD cho Safari cũ và **phát hiện SIMD lúc chạy**, không lúc build.
2. **Prove không bao giờ chạy trên main thread.** Android: coroutine trên `Dispatchers.Default`; browser: Web Worker (và `SharedArrayBuffer` không cần thiết — proof là single-thread); React Native: native module trên background thread. Bất cứ thứ gì > 300 ms cần progress UI. Thêm: **prove là CPU-bound liên tục** ⇒ trên thiết bị đang ở chế độ tiết kiệm pin, clock bị hạ và thời gian có thể ×2–3. Test trên thiết bị bật battery saver, không chỉ trên bench.
3. **Cùng một Rust core làm cả prover và verifier**, và verifier Solidity phải được **differential-test** với nó qua một bộ test vector chung. Hai implementation độc lập của Fiat-Shamir mà không có oracle chung là công thức chuẩn để tạo ra một lỗ hổng im lặng.

```
smartcontracts/testvectors/zether_transfer_v1.json
{
  "curve": "bn254" | "babyjubjub",
  "generators_digest": "0x...",
  "cases": [
    { "name": "happy_32_64", "statement": {...}, "witness": {...},
      "proof_hex": "0x...", "expect": "valid" },
    { "name": "sigma_bullets_v_mismatch",  "expect": "invalid" },
    { "name": "frozen_heart_chainid_flip", "expect": "invalid" },
    { "name": "frozen_heart_token_flip",   "expect": "invalid" },
    { "name": "point_not_on_curve",        "expect": "invalid" },
    { "name": "D_out_is_identity",         "expect": "invalid" },
    { "name": "b_prime_out_of_range",      "expect": "invalid" },
    { "name": "accseq_stale",              "expect": "invalid" }
  ]
}
```

CI chạy bộ này trên **cả ba** implementation: Rust verifier, Solidity verifier, native precompile Go. Ba kết quả phải giống hệt nhau, bit-for-bit trên cả trường hợp invalid (cùng lý do fail, không chỉ cùng boolean).

#### 3.8.5. Nếu chọn Groth16 cho public profile

Prove **chậm hơn nhiều**: mạch 30–60k constraint ⇒ ~0.5–2 s desktop WASM, **~3–10 s Android tầm trung**, RAM đỉnh 150–400 MB (proving key phải nạp vào bộ nhớ; key cho 60k constraint ≈ **20–40 MB** phải tải về và cache). Verify on-chain rẻ hơn ~9× (215k vs 1.88 M gas).

| | Bulletproofs | Groth16 (Baby Jubjub) |
|---|---|---|
| prove (Android tầm trung) | 0.11–0.26 s | 3–10 s |
| RAM prove | ~10 MB | 150–400 MB |
| artifact phải tải | 1.2 MB code | 1.2 MB code + **20–40 MB proving key** |
| proof size | 1,280 B | 256 B |
| gas verify | ~1.88 M | ~215 k |
| trusted setup | **không** | có (per-circuit; hoặc PLONK universal, verify ~290k) |
| đổi `n_v`/`n_b` | đổi hằng số | **ceremony lại** |

Đánh đổi rõ ràng: Bulletproofs = prove nhanh / verify đắt; Groth16 = prove chậm / verify rẻ + cần trusted setup + không đổi tham số được. Với B2B settlement (batch, không tương tác, prove trên server) Groth16 thắng; với thanh toán end-user tại quầy (người mua đang đứng đợi) Bulletproofs thắng tuyệt đối. **Đây chính là lý do `IZetherVerifier` phải pluggable** chứ không phải vì tính "mở rộng" chung chung — và lý do phải chọn Baby Jubjub từ đầu để giữ được cả hai đường (3.3.9).

Một cảnh báo về trusted setup mà không ai thích nghe: một ceremony đúng chuẩn (Powers of Tau + phase 2, ≥ 20 người tham gia độc lập, có transcript công khai) mất **4–8 tuần lịch**. Nếu Groth16 nằm trong roadmap public, ceremony phải bắt đầu **trước** khi code xong, không phải sau.

---

### 3.9. Chốt tham số và bề mặt tích hợp Odoo

#### 3.9.1. Cây thư mục hợp đồng (ngoài addon, theo quyết định số 9)

```
smartcontracts/evm/zether/src/
    ZetherAccountRegistry.sol          # singleton, register once use everywhere
    ZetherToken.sol                    # per-asset, IERC20 + confidential
    verifier/
        IZetherVerifier.sol
        BulletproofsVerifier.sol       # reference, dùng precompile per-point
        NativePrecompileVerifier.sol   # gọi 0x...0100 trên private chain
        Groth16Verifier.sol            # public profile, sinh từ circom/snarkjs
    curve/
        IZetherCurve.sol
        CurveBN254.sol                 # 0x06/0x07
        CurveBabyJubjub.sol            # mulmod thuần, extended coords
        CurveBLS12381.sol              # 0x0b/0x0c, có subgroup check
    gens/
        ZetherGeneratorsBN254V1.sol    # SSTORE2 data contract, 8,192 B
        ZetherGeneratorsBJJV1.sol
    lib/
        Transcript.sol                 # strong Fiat-Shamir, domain-separated
        Sigma.sol                      # 3.4.5
        PointValidation.sol            # 3.1.6
smartcontracts/evm/zether/test/
    Transcript.frozenheart.t.sol       # đảo từng field của statement -> proof PHẢI fail (14 case)
    SigmaBullets.linkage.t.sol         # v trong C_out != v trong V_v -> PHẢI fail
    Generators.nums.t.sol              # tính lại toàn bộ vector, so từng byte
    Generators.deploy.t.sol            # kích thước bytecode + hash blob
    Escrow.invariant.t.sol             # invariant fuzz, gồm token fee-on-transfer giả lập
    RollOver.grief.t.sol               # bên thứ ba KHÔNG rollOver hộ được
    AccSeq.race.t.sol                  # credit chen vào KHÔNG làm revert transfer
    Schnorr.nonceReuse.t.sol           # chứng minh test đang kiểm đúng thứ nó nói
smartcontracts/circuits/zether_transfer/       # circom/noir, ElGamal trên Baby Jubjub
smartcontracts/crates/zether-core/             # Rust: prover + verifier tham chiếu
smartcontracts/crates/zether-{ffi,wasm}/       # Android .so / iOS xcframework / browser
smartcontracts/geth-precompile/                # patch go-quorum: core/vm/contracts.go
smartcontracts/testvectors/
    zether_transfer_v1.json
    zether_withdraw_v1.json
    zether_generators_bn254_v1.json
    zether_generators_bjj_v1.json
```

#### 3.9.2. Tham số deploy-time

Trên `blockchain.zether.token` — addon **standalone**, không phụ thuộc `dms`:

| trường | private profile | public profile | ghi chú |
|---|---|---|---|
| `curve_profile` | `babyjubjub` | `babyjubjub` | **khuyến nghị mới** — giữ được đường Groth16 mà không migrate (3.3.9). `bn254` chỉ nếu chắc chắn mãi mãi Bulletproofs |
| `verifier_kind` | `native_bp` | `bulletproofs` → `groth16_bjj` | pluggable qua `IZetherVerifier` |
| `range_bits_value` | 32 (40 cho Z-VND B2B) | như trái | `n_b − n_v ≥ 24` |
| `range_bits_balance` | 64 | 64 | `2^{n_b} > totalSupplyScaled × 1024` |
| `scale_exponent` | **theo token** (3.2.4) | như trái | 2 cho USD-stable, 0 cho VND/point |
| `rollover_policy` | `accseq_owner_signed` | như trái | biến thể A ở 3.5.4 |
| `strict_fold` | `false` | `false` | 3.5.5 điểm 2 |
| `epoch_blocks` | **không dùng** | không dùng | thay bằng `accSeq` |
| `auditor_pubkey` | **bắt buộc đặt** | tuỳ chính sách | 3.4.8; đổi phải timelock 7 ngày |
| `confidentiality_horizon_years` | — | ≤ 10 nếu `bn254`/`babyjubjub` | cả hai đều ~100 bit; guard từ chối > 10 trên public |
| `settlement_account_pool_size` | 4 | 4 | 3.5.2 |
| `default_relay_mode` | `MODE_RESTRICT_RELAYER` | như trái | 3.4.4 |
| `underlying_allowlist_policy` | `deny_rebasing`, `require_delta_measure` | như trái | 3.7.4 |

Ghi chú về `babyjubjub` và mức an toàn: Baby Jubjub có order ~251 bit trên field BN254, nên nó **thừa hưởng đúng ~100 bit** của BN254 (cùng lý do exTNFS). Nó **không** an toàn hơn BN254 G1 — nó chỉ **tương thích mạch** hơn. Đừng bán nó như một nâng cấp bảo mật. Nếu cần > 100 bit trên public chain thì phải là BLS12-381, và khi đó Groth16-in-circuit lại đắt trở lại. Đây là một đánh đổi chưa có lời giải đẹp; ghi vào câu hỏi mở.

#### 3.9.3. Model Odoo — cụ thể, và tuân thủ mọi bẫy Odoo 19 đã biết

Không model nào tham chiếu `dms`. Tên trường không trùng tên kiểu Odoo (`date`, `json`, ...).

```python
# dms_blockchain/models/blockchain_zether_token.py
class BlockchainZetherToken(models.Model):
    _name = 'blockchain.zether.token'
    _description = 'Zether confidential token deployment'

    name              = fields.Char(required=True)
    chain_id          = fields.Many2one('blockchain.chain', required=True, index=True)
    contract_address  = fields.Char(required=True, index=True)
    registry_address  = fields.Char(required=True)
    underlying_address= fields.Char(required=True)
    underlying_decimals = fields.Integer(required=True)
    scale_exponent    = fields.Integer(required=True, default=2)
    range_bits_value  = fields.Integer(required=True, default=32)
    range_bits_balance= fields.Integer(required=True, default=64)
    curve_profile     = fields.Selection(
        [('bn254', 'alt_bn128 G1'), ('babyjubjub', 'Baby Jubjub'),
         ('bls12_381', 'BLS12-381 G1')], required=True, default='babyjubjub')
    verifier_kind     = fields.Selection(
        [('bulletproofs', 'Bulletproofs'), ('native_bp', 'Native precompile'),
         ('groth16_bjj', 'Groth16 / Baby Jubjub')], required=True)
    chain_profile     = fields.Selection(
        [('private', 'Permissioned'), ('public', 'Public')], required=True)
    auditor_pubkey    = fields.Char()          # rong = tat
    deployed_block    = fields.Integer(required=True)   # diem bat dau index/recovery
    confidentiality_horizon_years = fields.Integer(default=10)

    _unique_token_per_chain = models.Constraint(
        'UNIQUE(chain_id, contract_address)',
        'Moi contract address chi khai bao mot lan tren mot chain.')

    @api.constrains('range_bits_value', 'range_bits_balance')
    def _check_range_bits(self):
        for rec in self:
            if rec.range_bits_value > rec.range_bits_balance:
                raise ValidationError(_("range_bits_value phai <= range_bits_balance."))
            if rec.range_bits_balance - rec.range_bits_value < 24:
                raise ValidationError(_("Can bien >= 24 bit de chong grief tran so du."))
            if rec.range_bits_balance > 64:
                raise ValidationError(_("range_bits_balance > 64 lam so du khong khoi phuc duoc."))
```

```python
# dms_blockchain/models/blockchain_zether_transfer.py
class BlockchainZetherTransfer(models.Model):
    _name = 'blockchain.zether.transfer'
    _description = 'Zether confidential transfer attempt'
    _order = 'create_date desc'

    token_id        = fields.Many2one('blockchain.zether.token', required=True,
                                      ondelete='restrict', index=True)
    from_account_id = fields.Many2one('blockchain.zether.account', required=True, index=True)
    to_account_id   = fields.Many2one('blockchain.zether.account', required=True, index=True)
    zether_nonce    = fields.Integer(required=True)
    acc_seq         = fields.Integer(required=True)
    attempt_no      = fields.Integer(required=True, default=1)
    fee_scaled      = fields.Integer(required=True, default=0)
    fee_recipient   = fields.Char()
    memo_to         = fields.Char()      # 32 B hex, AEAD
    memo_from       = fields.Char()
    c_out           = fields.Char(required=True)   # hex uncompressed
    d_out           = fields.Char(required=True)
    c_debit         = fields.Char(required=True)
    tx_hash         = fields.Char(index=True)
    block_number    = fields.Integer(index=True)
    broadcast_datetime = fields.Datetime()   # KHONG dat ten 'datetime'
    final_datetime     = fields.Datetime()
    confirmations   = fields.Integer(default=0)
    state = fields.Selection([
        ('draft', 'Draft'), ('proving', 'Proving'), ('broadcast', 'Broadcast'),
        ('included', 'Included'), ('final', 'Final'),
        ('reverted', 'Reverted'), ('expired', 'Expired'),
    ], required=True, default='draft', index=True)
    proof_attachment_ids = fields.Many2many('ir.attachment')   # proof blob -> Garage/S3
```

**Sửa một lỗi trong bản nháp.** Bản nháp đề xuất:

```python
_unique_zether_nonce = models.Constraint(
    'UNIQUE(token_id, from_account_id, zether_nonce)', '...')
```

Sai: một lần thử thất bại (`reverted`/`expired`) **dùng lại đúng nonce đó** khi retry ⇒ constraint chặn retry, tức là chặn đường phục hồi lỗi. Đúng phải là: nonce duy nhất **trong số các bản ghi đã final**, còn các lần thử thì đánh số. Odoo 19 không có API cho partial unique index, nên làm bằng `init()`:

```python
_unique_attempt = models.Constraint(
    'UNIQUE(token_id, from_account_id, zether_nonce, attempt_no)',
    'Moi lan thu phai co attempt_no rieng.')

def init(self):
    super().init()
    tools.create_index(
        self.env.cr,
        'blockchain_zether_transfer_final_nonce_uniq',
        self._table,
        ['token_id', 'from_account_id', 'zether_nonce'],
        unique=True,
        where="state = 'final'",
    )
```

Kiểm bằng SQL, đừng tin code (theo CLAUDE.md §5.2):

```sql
SELECT conname, contype FROM pg_constraint
 WHERE conrelid = 'blockchain_zether_transfer'::regclass;
SELECT indexname, indexdef FROM pg_indexes
 WHERE tablename = 'blockchain_zether_transfer';
```

**Bẫy stored-compute:** không đặt `compute` + `store=True` + `required=True` trên bất kỳ trường nào ở đây. `confirmations` là trường thường, do cron ghi. Nếu ai đó muốn `is_final` là computed stored, nhánh compute phải gán giá trị trên **mọi** đường đi — hoặc đơn giản hơn: đừng, dùng `state` là đủ.

#### 3.9.4. Bề mặt RPC — phục vụ cả `call_kw` và `/json/2`

Theo CLAUDE.md §6: method public mỏng, logic ở method private, không nhận `allowed_company_ids` từ client.

```python
class BlockchainZetherAccount(models.Model):
    _name = 'blockchain.zether.account'

    @api.model
    def zether_view_accounts(self, token_ref, schnorr_addresses):
        """POST /web/dataset/call_kw/blockchain.zether.account/zether_view_accounts
           POST /json/2/blockchain.zether.account/zether_view_accounts

        Proxy sang viewAccounts() on-chain, tra ve anh chup nguyen tu.
        Khong nhan company tu client: token_ref duoc resolve trong pham vi
        assignment cua user da xac thuc."""
        token = self._resolve_token(token_ref)        # private, kiem quyen
        return token._rpc_view_accounts(schnorr_addresses[:256])

    @api.model
    def zether_transfer_history(self, token_ref, schnorr_address, from_block=0, limit=1000):
        """Nguon recovery cua vi. Tra ve event da index, KHONG goi RPC ngoai."""
        return self._resolve_token(token_ref)._history(schnorr_address, from_block, limit)

    @api.model
    def zether_submit_signed(self, token_ref, payload):
        """Nhan meta-tx da ky tu client, day sang relayer.
        Odoo KHONG bao gio prove va KHONG bao gio giu x."""
        return self._resolve_token(token_ref)._submit(payload)
```

Ba method này không bắt đầu bằng `_`, không có `@api.private`, nên gọi được qua cả hai đường. Mọi thứ khác là private.

#### 3.9.5. Finality Gate — nguyên tắc `dms_vietqr` áp nguyên vẹn

**Odoo không bao giờ prove và không bao giờ giữ `x`.** Prover chạy client-side hoặc trong signer service cạnh HSM/MPC. Vai trò của addon trong mục này chỉ gồm bốn việc: (a) phục vụ `viewAccounts` cho client qua RPC, (b) index event `ConfidentialTransfer` để đối soát **và làm nguồn recovery của ví** (3.2.6), (c) **Finality Gate**, (d) giữ cấu hình token.

*"Quét QR không phải là đã thu tiền"* → **broadcast không phải là đã thu tiền.**

```
draft ──► proving ──► broadcast ──► included ──► final
             │            │             │
             │            └──► expired   └──► reverted
             └──► draft (prove fail, retry với attempt_no+1)
```

`included` (đã có receipt, đã vào block) **vẫn chưa phải payment** — reorg vẫn kéo ngược được. Chỉ trạng thái `final` mới được phép kích `payment.transaction._set_done()`. Mọi trạng thái trước đó là `_set_pending()`, kể cả khi ví người dùng đã hiện "thành công".

Ngưỡng finality (sửa một lỗi trong note §10.4):

| Chain | Ngưỡng `final` | Chờ trung bình | Ghi chú |
|---|---|---|---|
| Gnosis xDAI | 2 epoch finalized (Beacon) | ~12.8 phút | soft 1 block ~5 s — **chỉ dùng cho UI, không cho `_set_done`** |
| **Celo** | **L1 (Ethereum) finalization** | **~13–19 phút** | **Note sai:** Celo đã migrate thành **OP-stack L2 (tháng 3/2025)**. "IBFT 2.0, immediate finality, ~5 s" không còn đúng. Block 1 s, soft confirmation tức thì, hard finality bám Ethereum. |
| Private chain (QBFT) | 1 block | ~1 s | BFT finality tức thì, không reorg — điều kiện: ≥ 4 validator, không fork binary |

Cron theo đúng bẫy CLAUDE.md §5.4 — XML gọi **một** method của model, không có `fields`/`relativedelta` trong eval context:

```xml
<record id="cron_zether_finality_gate" model="ir.cron">
    <field name="name">Zether: Finality Gate</field>
    <field name="model_id" ref="model_blockchain_zether_transfer"/>
    <field name="state">code</field>
    <field name="code">model._cron_finality_gate()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">minutes</field>
</record>
```

```python
def _cron_finality_gate(self):
    """Toan bo logic o day. XML chi goi mot dong."""
    for token in self.env['blockchain.zether.token'].search([]):
        head = token._rpc_finalized_block()
        pending = self.search([('token_id', '=', token.id),
                               ('state', 'in', ('broadcast', 'included'))])
        for rec in pending:
            rec._refresh_receipt(head)     # -> included / reverted / final / expired
```

#### 3.9.6. Tăng trưởng lưu trữ

| Thành phần | Kích thước/bản ghi | 10,000 tx/ngày |
|---|---|---|
| `blockchain_zether_transfer` (Postgres) | ~420 B + index ~180 B | **2.2 GB/năm** |
| proof blob → `ir.attachment` trên Garage (compressed 1,280 B) | 1,280 B | **4.7 GB/năm** |
| state on-chain | 10 slot/account/token = 320 B | 100k account × 5 token = **160 MB** |
| log on-chain (event) | ~256 B | 0.94 GB/năm (do chain giữ, không phải mình) |

Không đáng lo. Nhưng: proof blob **có cần giữ không?** Nó đã nằm trong calldata on-chain vĩnh viễn. Giữ bản sao chỉ hữu ích khi (a) chain là private và có thể bị prune, hoặc (b) cần audit offline nhanh. **Quyết định: giữ trên private profile, không giữ trên public profile** (tiết kiệm 4.7 GB/năm và một bề mặt lưu trữ). Thêm trường `keep_proof_blob` trên token, mặc định theo `chain_profile`. Không base64 trong DB, không JSON blob — Many2many `ir.attachment` trên Garage như mọi thứ khác trong repo này.

---

### 3.10. Ba use case đã chốt, ba bộ tham số

Quyết định số 3 đưa cả ba use case vào phạm vi. Chúng **không** dùng chung một cấu hình Zether, và giả vờ rằng chúng dùng chung là cách nhanh nhất để cả ba đều tệ.

| | **Loyalty / reward points** | **B2B settlement (brand ↔ distributor)** | **End-user payment** |
|---|---|---|---|
| Token | Z-POINT (tự phát hành) | Z-VND hoặc Z-USDT | Z-VND |
| Giá trị mỗi giao dịch | 10 – 10^5 điểm | 10^6 – 10^11 ₫ | 10^4 – 10^7 ₫ |
| `scale_exponent` | 0 | 0 (VND) / 2 (USDT) | 0 |
| `range_bits_value` | **32** | **40** | **32** |
| `range_bits_balance` | 64 | 64 | 64 |
| Biên chống grief (`n_b − n_v`) | 32 ✓ | 24 ✓ (sát ngưỡng) | 32 ✓ |
| Prover chạy ở | điện thoại (ARM64 native) | **server** (signer service cạnh HSM) | điện thoại / POS |
| Hệ chứng minh | Bulletproofs | Bulletproofs (private) → Groth16 (public) | **Bulletproofs, không đàm phán** |
| Ngân sách prove | < 0.5 s | < 60 s | **< 0.5 s** |
| Custody | passkey / smart-account | HSM hoặc MPC | MPC hoặc custodial |
| `auditor_pubkey` | tuỳ (không phải tiền) | **bắt buộc** | **bắt buộc** (thuế/VAT) |
| Relay mode | `MODE_OPEN` (giá trị nhỏ) | `MODE_RESTRICT_RELAYER` | `MODE_RESTRICT_RELAYER` |
| Finality trước khi ghi nhận | soft 1 block đủ (điểm không phải tiền) | **hard finality bắt buộc** | hard finality cho settlement; soft cho UX "đã nhận" |
| Chain | private trước, Gnosis sau | **private trước** (khối lượng + bí mật giá) | Gnosis / Celo |
| Khối lượng ước tính | 10^5 – 10^6 /ngày | 10^3 – 10^4 /ngày | 10^4 – 10^5 /ngày |
| Có vượt trần Gnosis (31,300/ngày) không? | **có** → bắt buộc private chain hoặc Celo | không | **có** → Celo hoặc private |

Ba kết luận từ bảng này:

1. **Loyalty ở khối lượng thật không chạy được trên Gnosis.** 10^5–10^6 tx/ngày so với trần 31,300/ngày toàn mạng. Không phải vấn đề tiền (chi phí chỉ $190–1,900/ngày), mà là **không có chỗ trong block**. Loyalty phải ở private chain hoặc Celo, hoặc phải **không dùng Zether** (điểm thưởng có cần bảo mật số dư không? Đây là câu hỏi cần người quyết — xem 3.11).
2. **B2B settlement là use case duy nhất mà Zether rõ ràng đáng giá**: khối lượng thấp, giá trị cao, bí mật giá là yêu cầu thật, prover chạy trên server nên thời gian prove không quan trọng.
3. **`range_bits_value = 40` cho B2B kéo theo mọi hệ quả ở 3.2.4–3.2.5**: bắt buộc phải có memo mã hoá, nếu không recovery mất 8 giờ.

---

### 3.11. Những gì vẫn chưa giải quyết, và những gì cần người quyết

#### 3.11.1. Chưa có lời giải kỹ thuật

| # | Vấn đề | Trạng thái | Lựa chọn |
|---|---|---|---|
| U1 | **Mất `x` = mất tiền vĩnh viễn.** Không rollOver được, không tiêu được, không giải mã được. ERC-20 tương ứng khoá trong escrow mãi mãi ⇒ lỗ hổng kế toán. | **Không có giải pháp trong giao thức.** | (a) MPC custody (quyết định 6 đã cho phép) — shard `x`, khôi phục được; (b) private profile: issuer giữ một share recovery, có timelock 30 ngày + thông báo công khai; (c) public non-custodial: **chấp nhận mất**, ghi vào ToS. |
| U2 | **Blacklist underlying đóng băng toàn bộ pool** (3.7.4). | Không có mitigation kỹ thuật. | Tránh USDC/USDT làm underlying; chia pool; `emergencyRevealWithdraw` sau 90 ngày pause. |
| U3 | **[BẢN 5] phạm vi thu hẹp: nhánh mặc định `PUBLIC` gần paper FC 2020 hơn (permissionless, idempotent); cái cần review là nhánh `OWNER_ONLY`, việc ghim `accSeq` vào transcript, và đường lui "verifier chấp nhận `accSeq` cũ khi phần chênh chỉ gồm credit" (§C5.4).** Owner-signed rollOver chưa được kiểm chứng với chứng minh an toàn của paper FC 2020. Tôi tin nó đúng khi N = 2 và nonce đơn điệu (epoch-tag tồn tại để phục vụ anonymity set, thứ ta đã bỏ), nhưng đây là thay đổi ở tầng giao thức. | **Cần reviewer mật mã xác nhận**, không quyết bằng suy luận trong tài liệu này. | Thuê một audit mật mã 2–3 tuần cho riêng phần này, **trước** khi viết Solidity. |
| U4 | **Không có > 100 bit bảo mật với chi phí verify chấp nhận được trên EVM.** BN254/Baby Jubjub ~100 bit; BLS12-381 ~126 bit nhưng gas ×2 và Groth16-in-BLS đắt hơn nhiều. | Đánh đổi chưa có lời giải đẹp. | Private chain (native precompile ⇒ chọn curve nào cũng được) + hoãn quyết định cho public. |
| U5 | **Rò rỉ thống kê qua deposit/withdraw công khai** (3.7.3) trên đồ thị hình cây. | Giảm thiểu được, không xoá được. | Netting, float thường trực, rút theo lịch, ≥ 3 counterparty. |
| U6 | **Người nhận chưa register thì không nhận được tiền.** Rào cản lớn cho loyalty tới người tiêu dùng. | Có đường vòng, chưa chốt. | Counterfactual registration: dẫn xuất `schnorrAddress` từ passkey, ai cũng submit hộ PoP signature được, gasless, ở lần chạm đầu tiên. Cần thiết kế ở §02. |
| U7 | **Không có PQ path.** Shor phá hồi tố mọi ciphertext. | Không có. | Chấp nhận horizon ≤ 10 năm; đừng bán "kháng lượng tử". |

#### 3.11.2. Câu hỏi cần người quyết

1. **Loyalty points có thật sự cần bảo mật số dư không?** Nếu số điểm của khách hàng không phải bí mật thương mại, dùng ERC-20 công khai + EIP-1776 sẽ rẻ hơn ~40× gas, không cần prover trên điện thoại, không cần recovery, không cần memo. Zether cho loyalty có thể là over-engineering. Cần một câu trả lời trước khi viết dòng code nào.
2. **Chốt curve: `babyjubjub` hay `bn254` G1?** Đây là quyết định **không đảo ngược được** sau khi deploy contract đầu tiên (3.1.7). Khuyến nghị `babyjubjub` để giữ đường Groth16. Cần chữ ký.
3. **`auditor_pubkey` bật hay tắt, và ai giữ khoá?** Nếu bật, phải bật từ block đầu tiên. Nếu doanh nghiệp tự giữ, nó chỉ bảo vệ bí mật khỏi bên ngoài; nếu bên thứ ba (kiểm toán độc lập) giữ, cần thoả thuận pháp lý. Xem §13.
4. **Có xây native precompile trên private chain không?** Nó là consensus change và khoá ta vào một fork geth phải tự maintain. Lợi: 25–60× throughput. Cần quyết trước khi chọn chain client.
5. **Chấp nhận `n_v = 40` cho Z-VND B2B, hay chia nhỏ giao dịch lớn thành nhiều lần `n_v = 32`?** Chia nhỏ giữ được `DECRYPT_BOUND` thấp và biên grief 32 bit, nhưng nhân số tx (và số gas) lên 5–20 lần cho các khoản lớn nhất. Số liệu doanh số thật của nhà phân phối sẽ quyết định.
6. **Trần thị phần block space chấp nhận được trên Gnosis là bao nhiêu?** Tôi giả định 20% trong mọi tính toán throughput. Nếu con số thật là 5%, mọi trần ngày ở 3.3.8 chia 4 và câu hỏi 1 trở nên cấp bách.
7. **Có chạy trusted setup ceremony không, và bắt đầu khi nào?** 4–8 tuần lịch, phải bắt đầu trước khi code xong nếu Groth16 nằm trong roadmap public.

#### 3.11.3. Thứ tự thực hiện đề xuất

```
S1  Chốt curve (câu hỏi 2) + chốt Zether có dùng cho loyalty không (câu hỏi 1)
S2  Rust core: prover + verifier tham chiếu + testvectors     [không có Solidity nào ở bước này]
S3  Audit mật mã cho accSeq + nhánh OWNER_ONLY + drift chỉ-credit (U3) + Sigma-Bullets linkage
S4  Solidity: Registry, Token, BulletproofsVerifier, Generators (SSTORE2)
    + toàn bộ 8 file test ở 3.9.1
S5  Private chain QBFT + native precompile (nếu câu hỏi 4 = có)
S6  Addon dms_blockchain: index, viewAccounts proxy, Finality Gate
    [standalone, không depends dms]
S7  SDK: Android .so, iOS xcframework, WASM+SIMD; UX progress cho prove
S8  Đo lại toàn bộ số gas bằng forge --gas-report; cập nhật bảng 3.3.6
S9  Chỉ khi S1–S8 xanh: cân nhắc public chain (Gnosis), và audit lần hai
```

Không bước nào trong S1–S3 tạo ra Solidity. Đó là cố ý: mọi lỗi mật mã ở tầng này **rẻ gấp 100 lần** khi sửa trong Rust so với sau khi contract đã giữ tiền thật.
