# Zether — đặc tả giao thức byte-exact (round 3, luồng S2)

**UNAUDITED — NOT FOR PRODUCTION FUNDS.** Mọi contract trong `smartcontracts/src/zether/**` và
`src/registry/**` chỉ tạo được trên chain dev (§13). Không audit bên thứ ba thì không giữ tiền thật.

**Ngày:** 2026-10-03 · **Owner:** R34 (*"Làm cả zether luôn … phải full code"*, *"làm cả test zether"*).
**Nguồn:** SRS `ai-enterprise-blockchain-architecture.md` §7.1–7.7, §8.1, §9.3–9.5; research `03-zether-crypto.md`,
`02-account-registry.md`, `00-CANON.md` §C5–C6; round 3 §C.4 (R33), §F (R34). Code thắng SRS khi đã có ruling;
mọi chỗ lệch SRS có ruling `RS2-n` ở §16.

**Người đọc chính:** luồng S3 (prover Rust/WASM, nhánh `r3-zether-prover`). Tài liệu này là hợp đồng giữa prover
và verifier Solidity: **mọi byte** của statement, transcript, proof phải đúng như đây. Chỗ nào mơ hồ là bug của tài
liệu — báo lại, đừng đoán.

Ký hiệu: nhóm viết **cộng tính**. `[k]P` = nhân vô hướng, `O` = điểm vô cực, `G` = generator chuẩn của G1,
`r` = bậc nhóm (scalar field), `p` = trường cơ sở. `‖` = nối byte. `be32(x)` = 32 byte big-endian,
`be4(x)` = 4 byte big-endian, `u8(x)` = 1 byte. Chuỗi `"…"` là ASCII không có byte kết thúc.

---

## 1. Tham số

| Hằng số | Giá trị | Ở đâu |
|---|---|---|
| `n_v` (range_bits_value) | **32** | verifier — Bulletproof #1 |
| `n_b` (range_bits_balance) | **64** | verifier — Bulletproof #2 |
| `DECRYPT_BOUND` | **2^40** | chỉ client (BSGS); không có trong contract |
| `MAX_TOTAL_SHIELDED` | **2^54** | trần của `maxDecryptableShielded` lúc `initialize` (`2^n_b > total·1024`) |
| `MAX_CONFIDENTIAL_FEE` | `< 2^32` | `confidentialFee` phải `< 2^n_v` |
| Ring size | **2** | lộ danh tính người gửi/nhận (SRS §7.1); không có anonymity set |

`n_b − n_v = 32 ≥ 24` (SRS §7.3). Số dư của mọi tài khoản `≤ totalShielded ≤ maxDecryptableShielded ≤ 2^54 < 2^64`,
nên một số dư hợp lệ luôn chứng minh được.

**Đơn vị.** `shieldScale` = số raw unit của underlying cho **một** đơn vị che giấu (ruling RS2-3). Ví dụ USDT
(6 decimals, giữ 2 chữ số) `shieldScale = 10^4`; Z-VND (0 decimals) `shieldScale = 1`. `fund(amount)` nhận `amount`
**đơn vị che giấu** và kéo `amount · shieldScale` raw unit; `burn(amount)` trả `amount · shieldScale`.

## 2. Đường cong, mã hoá, kiểm tra điểm

| | bn254 (alt_bn128) | BLS12-381 G1 |
|---|---|---|
| `p` | `21888242871839275222246405745257275088696311157297823662689037894645226208583` | `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` |
| `r` | `21888242871839275222246405745257275088548364400416034343698204186575808495617` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| `G` | `(1, 2)` | x=`0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb` y=`0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1` |
| Điểm `P` bytes | **64** = `be32(x) ‖ be32(y)` (EIP-196) | **128** = `pad16 ‖ x48 ‖ pad16 ‖ y48` (EIP-2537; `pad16` = 16 byte 0) |
| `O` | 64 byte 0 | 128 byte 0 |
| Scalar | 32 byte BE, **phải `< r`** | 32 byte BE, **phải `< r`** |
| Precompile | `0x06` add, `0x07` mul (MSM = vòng mul+add) | `0x0b` G1ADD, `0x0c` G1MSM, `0x10` MAP_FP_TO_G1 |
| `proofSystemId` | `keccak256("bamboo/zether/sigma-bullets/bn254/n32-n64/v1")` | `keccak256("bamboo/zether/sigma-bullets/bls12-381/n32-n64/v1")` |

**Mã hoá chính tắc là duy nhất.** Toạ độ phải `< p` (precompile từ chối nếu không), BLS phải có `pad16` toàn 0.
Prover **không bao giờ** xuất điểm không chính tắc; `UA = keccak256(encodedY)` dựa vào điều đó.

**Kiểm tra điểm.**
- bn254: cofactor 1 — on-curve là đủ; precompile `0x06/0x07` revert với điểm sai.
- BLS12-381: G1ADD **chỉ** kiểm on-curve; G1MSM kiểm cả subgroup. Verifier đưa **mọi** điểm nhận từ ngoài vào ít
  nhất một G1MSM (mọi phương trình kiểm đều là MSM), nên subgroup check là ngầm định. Registry ép khoá `Y` qua
  G1MSM k=1 lúc đăng ký.
- `D_out ≠ O` (nếu `O` thì `C_out = [v]G` lộ `v`). `Y ≠ O` cho mọi khoá. `Y_from ≠ Y_to` (cấm tự chuyển).

## 3. Generator NUMS

Verifier **tự tính** generator trong constructor (không hard-code), ghi blob vào một data contract (SSTORE2,
`extcodecopy` lúc verify). Ai cũng tính lại được từ đặc tả này ⇒ NUMS kiểm chứng được.

Danh sách: `Hb` (blinding Pedersen, nhãn `"h"`), `U` (inner-product, nhãn `"U"`), `G_i` (nhãn `"G"`), `H_i`
(nhãn `"H"`), `i = 0..63`. Bulletproof `n=32` dùng **tiền tố** `G_0..G_31`, `H_0..H_31` của cùng vector.
`h` và `U` dùng `index = 0`. **Phân biệt hoa/thường:** `Hb` là `"h"` (0x68), `H_i` là `"H"` (0x48) —
dùng `"H"` cho `Hb` thì `Hb == H_0` và mọi proof hỏng.

**Blob** (thứ tự cố định): `Hb ‖ U ‖ G_0 … G_63 ‖ H_0 … H_63` = 130 điểm (bn254 8,320 B; BLS 16,640 B).

### 3.1 bn254 — try-and-increment

```
msg(label, index) = "BAMBOO-ZETHER-GEN-BN254-V1" ‖ u8(len(label)) ‖ label ‖ be4(index)
mapToG1(prefix):
  for ctr = 0, 1, 2, …:
    x   = uint256(keccak256(prefix ‖ be4(ctr))) mod p
    rhs = (x^3 + 3) mod p
    y   = rhs^((p+1)/4) mod p
    if y*y mod p == rhs:
        if y is odd: y = p - y          // chọn y chẵn
        return (x, y)
gen(label, index) = mapToG1(msg(label, index))
```

### 3.2 BLS12-381 — RFC 9380

`gen(label, index) = hash_to_curve(msg, DST)`, suite **`BLS12381G1_XMD:SHA-256_SSWU_RO_`**, với
`msg = u8(len(label)) ‖ label ‖ be4(index)` và
`DST = "BAMBOO-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_"`.
(Solidity: `HashToCurve.hashToG1` — `expand_message_xmd` + `MAP_FP_TO_G1` ×2 + G1ADD; arkworks:
`MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256,128>, WBMap<g1::Config>>`.)

Vector: `smartcontracts/test/vectors/zether/generators_{bn254,bls12381}.json` (§14).

## 4. Hash-to-scalar và transcript Fiat-Shamir

```
hashToScalar(seed: bytes32) = ( uint256(keccak256(seed ‖ 0x02)) · 2^256
                              + uint256(keccak256(seed ‖ 0x03)) ) mod r
```

Transcript (keccak, trạng thái một `bytes32 st`):

```
init():               st = keccak256("BAMBOO-ZETHER-TRANSCRIPT-V1")
absorb(label, data):  st = keccak256(st ‖ 0x00 ‖ u8(len(label)) ‖ label ‖ be4(len(data)) ‖ data)
challenge(label):     st = keccak256(st ‖ 0x01 ‖ u8(len(label)) ‖ label)
                      return hashToScalar(st)          // == 0 ⇒ proof bị từ chối
```

Một transcript **duy nhất** cho Σ và cả hai Bulletproof (chống Σ-Bullets tách rời, research §3.4.6). Statement
được hấp thụ **trước** mọi thông điệp của prover (strong Fiat-Shamir, chống Frozen Heart). Challenge không bao giờ
nằm trong proof — verifier tự tính lại.

Vector: `transcript.json` (§14).

## 5. Trạng thái ElGamal và vòng đời

Khoá: `x ∈ [1, r)`, `Y = [x]G`, `UA = keccak256(encodedY)`. Mã hoá lifted ElGamal: `(C, D) = ([b]G + [ρ]Y, [ρ]G)`.
Giải mã: `[b]G = C − [x]D`, rồi BSGS trong `DECRYPT_BOUND` (chỉ client).

Trạng thái mỗi `(UA, token)` (SRS §7.6, canon C5):

| Slot | Đổi bởi | Vai trò |
|---|---|---|
| `acc = (C, D)` | rollOver (cộng pending), debit (transfer/burn) | nguồn **duy nhất** của proof |
| `pending = (C, D)` | mọi credit: `fund`, transfer đến, phí tầng trong | nơi tiền đến nằm chờ |
| `accSeq` (uint64) | `+1` mỗi rollOver có việc | **trong statement**; contract `require(accSeq == provedAccSeq)` trước verify |
| `pendingSeq` (uint64) | `+1` mỗi credit | client biết có tiền mới |
| `lastRolledPendingSeq` | rollOver | quy tắc no-op |
| `sendCounter` (uint64) | `+1` mỗi debit thành công | **trong statement**; chống replay proof; PRF `s` phía client |
| `mode` | `setRollOverMode` (chữ ký chủ) | `PUBLIC` (mặc định) / `OWNER_ONLY` |

Tài khoản mới: `acc = pending = (O, O)`, mọi số đếm `0`, `mode = PUBLIC`. Không có epoch (canon C5).

**fund(Y, amount):** `pending.C += [amount]G` (D không đổi; số tiền công khai), `pendingSeq++`. Kéo
`amount·shieldScale` underlying từ `msg.sender` qua `transferFrom` — spender là **chính token contract** (R26).

**transfer:** sender chứng minh trên `acc`. Hiệu lực:
```
acc_f.C   = acc_f.C − C_deb − [fee]G         acc_f.D   = acc_f.D − D_out
pend_t.C += C_out                             pend_t.D += D_out           pendingSeq_t++
pend_ben.C += [fee]G   (nếu fee > 0)                                       pendingSeq_ben++
sendCounter_f++
```
**burn(amount, recipient):** `acc_f.C −= [amount + fee]G`, phí như trên, `sendCounter_f++`, trả underlying cho
`recipient`.

**rollOver:** `acc += pending; pending = (O,O); accSeq++; lastRolledPendingSeq = pendingSeq`. Chỉ chạy khi
`pendingSeq > lastRolledPendingSeq`; ngược lại **no-op im lặng** (SRS §7.6 — chặn DoS spam).
- `PUBLIC`: `rollOverPublic(UA)` / `rollOverBatch(UA[])` không chữ ký. `rollOverBatch` bỏ qua phần tử `OWNER_ONLY`
  và phần tử chưa đăng ký.
- `OWNER_ONLY`: `rollOverPublic` revert `RollOverOwnerOnly`. Chỉ `rollOverSigned(UA, expectedPendingSeq,
  validUntilBlock, sig)` — `block.number ≤ validUntilBlock`, `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq` (RS2-17, RS2-19), chữ ký theo
  `authScheme` (§11) trên
  `keccak256(abi.encode(keccak256("ZETHER_ROLLOVER_V1"), chainid, token, UA, accSeq, expectedPendingSeq, validUntilBlock))`.
- `rollOverSigned` cũng dùng được cho tài khoản `PUBLIC`.
- `setRollOverMode(UA, mode, validUntilBlock, sig)`: digest
  `keccak256(abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), chainid, token, UA, uint8(mode), modeNonce, validUntilBlock))`,
  `modeNonce++` sau mỗi lần đổi (chống phát lại chữ ký cũ).

**Race (SRS §7.6/§7.7, canon C5):** transfer/burn **không bao giờ** tự gộp pending. Credit đến trong lúc prove chỉ
đổi `pending` ⇒ proof vẫn sống. Chỉ rollOver đổi `accSeq`; proof dựng trên `accSeq` cũ bị từ chối **trước** verify
(`StaleAccSeq`, rẻ). Với `OWNER_ONLY` không ai ngoài chủ bump được `accSeq`, và credit chèn vào không giết được
`rollOverSigned` của chủ (RS2-17). Với `PUBLIC` grief **chỉ tốn gas**: một tài khoản đã đăng ký số dư 0 vẫn chứng
minh được transfer `v = 0` (proof hợp lệ, ẩn số tiền ⇒ không chặn được on-chain) rồi gọi `rollOverPublic` ⇒ ví nào
cần proof ổn định khi bị nhắm phải chuyển `OWNER_ONLY`. Quy tắc ví: không giữ rollOver đã ký khi còn transfer đang bay; `validUntilBlock` ngắn (≈50 block).

## 6. Statement (byte layout)

Token **tự dựng** statement từ storage + payload; prover dựng y hệt. `P` = byte của một điểm.

Header (384 byte, chung cho mọi op):

| Offset | Len | Trường |
|---|---|---|
| 0 | 32 | `opTag` — transfer: `keccak256("BAMBOO-ZETHER-OP-TRANSFER-V1")`, burn: `keccak256("BAMBOO-ZETHER-OP-BURN-V1")` |
| 32 | 32 | `proofSystemId` (§2) |
| 64 | 32 | `chainId` |
| 96 | 32 | địa chỉ token (12 byte 0 ‖ 20 byte) |
| 128 | 32 | `bindingTag` — `keccak256("ZTX_V1_DIRECT")` hoặc `keccak256("ZTX_V1_RELAYED")` |
| 160 | 32 | `envelopeBinding` — 0 nếu DIRECT; §10 nếu RELAYED |
| 192 | 32 | `sendCounter` |
| 224 | 32 | `accSeq` |
| 256 | 32 | `fee` (phí tầng trong, đơn vị che giấu) |
| 288 | 32 | `beneficiary` (UA nhận phí; 0 nếu không) |
| 320 | 32 | `amount` (burn; transfer = 0) |
| 352 | 32 | `recipient` (burn: 12 byte 0 ‖ address; transfer = 0) |

Phần điểm:
- **transfer:** `Y_f ‖ Y_t ‖ Y_a ‖ C_acc ‖ D_acc ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud` (9P). `Y_a` = khoá auditor của
  token, `O` nếu tắt; khi tắt `C_aud` **phải** là `O`.
- **burn:** `Y_f ‖ C_acc ‖ D_acc` (3P).

`fee = confidentialFee()` nếu `beneficiary ≠ 0`, ngược lại `0` (phí cố định theo token, không bao giờ là hàm của `v`).

## 7. Σ-protocol

### 7.1 Transfer

Witness: `x, v, s, b' = b − v − fee, γ_v, γ_b`. Commitment Bulletproof: `V_v = [v]G + [γ_v]Hb`,
`V_b = [b']G + [γ_b]Hb`. Prover dựng `C_out = [v]G + [s]Y_t`, `D_out = [s]G`, `C_deb = [v]G + [s]Y_f`,
`C_aud = [v]G + [s]Y_a` (shared-`s`, canon C6.5; `O` nếu auditor tắt).

Nonce `k_x, k_v, k_s, k_b, k_gv, k_gb` **hedged** (`k = H(x ‖ msg ‖ 32 byte CSPRNG)` rồi mod r) — lặp nonce là lộ `x`.

```
A_y   = [k_x]G
A_D   = [k_s]G
A_out = [k_v]G + [k_s]Y_t
A_deb = [k_v]G + [k_s]Y_f
A_bal = [k_b]G + [k_x](D_acc − D_out)
A_aud = [k_v]G + [k_s]Y_a          (O nếu auditor tắt)
A_Vv  = [k_v]G + [k_gv]Hb
A_Vb  = [k_b]G + [k_gb]Hb

T.init(); T.absorb("statement", statement)
T.absorb("sigma.commit", V_v ‖ V_b ‖ A_y ‖ A_D ‖ A_out ‖ A_deb ‖ A_bal ‖ A_aud ‖ A_Vv ‖ A_Vb)
c = T.challenge("sigma.c")
z_x = k_x + c·x   z_v = k_v + c·v   z_s = k_s + c·s
z_b = k_b + c·b'  z_gv = k_gv + c·γ_v  z_gb = k_gb + c·γ_b        (mod r)
```

Verifier — mỗi dòng là một MSM phải bằng `O`:

```
E1  [z_x]G − [c]Y_f − A_y
E2  [z_s]G − [c]D_out − A_D
E3  [z_v]G + [z_s]Y_t − [c]C_out − A_out
E4  [z_v]G + [z_s]Y_f − [c]C_deb − A_deb
E5  [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal
E6  [z_v]G + [z_s]Y_a − [c]C_aud − A_aud               (chỉ khi auditor bật; tắt ⇒ A_aud == O)
E7  [z_v]G + [z_gv]Hb − [c]V_v − A_Vv
E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
```

E5 là `T = C_acc − C_deb − [fee]G = [b']G + [x](D_acc − D_out)`. E7/E8 dùng chung `z_v`, `z_b` với E3/E4/E5 —
đó là liên kết Σ-Bullets; xoá E7 hoặc E8 là in tiền.

### 7.2 Burn

Witness `x, b' = b − amount − fee, γ_b`; `V_b = [b']G + [γ_b]Hb`.

```
A_y = [k_x]G      A_bal = [k_b]G + [k_x]D_acc      A_Vb = [k_b]G + [k_gb]Hb
T.init(); T.absorb("statement", statement)
T.absorb("sigma.commit", V_b ‖ A_y ‖ A_bal ‖ A_Vb)
c = T.challenge("sigma.c")
z_x = k_x + c·x   z_b = k_b + c·b'   z_gb = k_gb + c·γ_b

E1  [z_x]G − [c]Y_f − A_y
E5  [z_b + c·(amount + fee)]G + [z_x]D_acc − [c]C_acc − A_bal
E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
```

`recipient` và `amount` nằm trong statement ⇒ relayer không đổi được đích rút.

## 8. Bulletproofs — đúng hai mệnh đề dải

Transfer: `BP(n=32, V_v)` rồi `BP(n=64, V_b)`, **cùng transcript**, nối tiếp sau `c`. Burn: chỉ `BP(n=64, V_b)`.
`k = log2(n)` (5 hoặc 6). `y^n = (1, y, …, y^{n-1})`, `2^n = (1, 2, …, 2^{n-1})`.

### 8.1 Prover

```
a_L = bits of value (LSB first, a_L[i] = (value >> i) & 1);  a_R = a_L − 1^n
α, ρ, τ1, τ2, s_L[n], s_R[n] ← hedged random
A = [α]Hb + Σ[a_L[i]]G_i + Σ[a_R[i]]H_i
S = [ρ]Hb + Σ[s_L[i]]G_i + Σ[s_R[i]]H_i
T.absorb("bp.AS", be4(n) ‖ A ‖ S);  y = T.challenge("bp.y");  z = T.challenge("bp.z")
l0 = a_L − z·1^n          l1 = s_L
r0 = y^n ∘ (a_R + z·1^n) + z²·2^n      r1 = y^n ∘ s_R
t1 = <l0, r1> + <l1, r0>     t2 = <l1, r1>
T1 = [t1]G + [τ1]Hb      T2 = [t2]G + [τ2]Hb
T.absorb("bp.T", T1 ‖ T2);  x = T.challenge("bp.x")
l = l0 + x·l1;  r = r0 + x·r1;  t̂ = <l, r>
τ_x = τ2·x² + τ1·x + z²·γ;   μ = α + ρ·x
T.absorb("bp.t", be32(τ_x) ‖ be32(μ) ‖ be32(t̂));  w = T.challenge("bp.w")
IPA với a = l, b = r, generator G_i, H'_i = [y^{-i}]H_i, Q = [w]U:
  for j = 1..k (độ dài hiện tại m, nửa h = m/2; lo = [0,h), hi = [h,m)):
    L_j = Σ[a_lo]G_hi + Σ[b_hi]H'_lo + [<a_lo, b_hi>]Q
    R_j = Σ[a_hi]G_lo + Σ[b_lo]H'_hi + [<a_hi, b_lo>]Q
    T.absorb("ipa.LR", L_j ‖ R_j);  u_j = T.challenge("ipa.u")
    a  = a_lo·u_j + a_hi·u_j⁻¹          b  = b_lo·u_j⁻¹ + b_hi·u_j
    G  = [u_j⁻¹]G_lo + [u_j]G_hi        H' = [u_j]H'_lo + [u_j⁻¹]H'_hi
  final a, b (vô hướng)
```

### 8.2 Verifier

```
δ(y,z) = (z − z²)·Σ_{i<n} y^i − z³·(2^n − 1)
s_i = Π_{j=1..k} u_j^{ +1 nếu bit (k−j) của i là 1, ngược lại −1 }        (i ∈ [0,n))

BP-1  [t̂ − δ]G + [τ_x]Hb − [z²]V − [x]T1 − [x²]T2                                  == O
BP-2  A + [x]S + Σ[−z − a·s_i]G_i + Σ[z + y^{-i}·(z²·2^i − b·s_i⁻¹)]H_i
        − [μ]Hb + [w·(t̂ − a·b)]U + Σ[u_j²]L_j + Σ[u_j⁻²]R_j                        == O
```

Mọi challenge `y, z, x, w, u_j, c` phải `≠ 0`. Mọi scalar trong proof `< r`. Nghịch đảo bằng Fermat (`MODEXP 0x05`).

## 9. Định dạng proof (wire)

Điểm theo §2 (P byte), scalar 32 byte BE. Không có trường độ dài, không có challenge.

Trong `BP(n)` mọi điểm đứng trước mọi scalar; thứ tự hấp thụ của transcript (§8) **khác** thứ tự byte
(`τ_x ‖ μ ‖ t̂` được hấp thụ trước `L_1 ‖ R_1`) — verifier đọc theo offset, không đọc tuần tự.

```
BP(n) = A ‖ S ‖ T1 ‖ T2 ‖ L_1 ‖ R_1 ‖ … ‖ L_k ‖ R_k ‖ τ_x ‖ μ ‖ t̂ ‖ a ‖ b        ((4+2k)P + 160)

transfer = V_v ‖ V_b ‖ A_y ‖ A_D ‖ A_out ‖ A_deb ‖ A_bal ‖ A_aud ‖ A_Vv ‖ A_Vb
         ‖ z_x ‖ z_v ‖ z_s ‖ z_b ‖ z_gv ‖ z_gb
         ‖ BP(32) ‖ BP(64)                         = 40P + 512   (bn254 3,072 B; BLS 5,632 B)

burn     = V_b ‖ A_y ‖ A_bal ‖ A_Vb ‖ z_x ‖ z_b ‖ z_gb ‖ BP(64)
                                                   = 20P + 256   (bn254 1,536 B; BLS 2,816 B)
```

Payload (calldata cho token, cái statement lấy điểm từ đó):

```
transfer payload = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud   (64 + 6P)
burn payload     = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ Y_f                                       (64 + P)
```

## 10. Ràng phong bì meta-tx và chống replay (SRS §7.7)

Ba tầng:
1. **Phong bì:** 2D nonce `(from, batch) → nonce`, `validUntil`, chữ ký EIP-712 (`MetaTxLib.METATX_TYPEHASH`,
   domain `("Bamboo ZetherToken", "1", chainId, token)`), lane ngẫu nhiên theo `entryRef` (R9) do client chọn.
2. **Trạng thái:** `accSeq`, `sendCounter` trong statement; token so với storage **trước** verify.
3. **Ràng phong bì:** `bindingTag`/`envelopeBinding` trong statement.

```
envelopeBinding = keccak256(abi.encode(
    keccak256("BAMBOO-ZETHER-ENVELOPE-V1"), chainid, token,
    m.from, m.to, m.value, m.batch, m.nonce, m.validUntil, m.mode,
    canonRelayer, m.fee, canonFeeRecipient))        // canon* theo MetaTxLib.canon
```

`m.data` (chứa proof) **không** nằm trong binding — nếu có thì vòng tròn (proof phụ thuộc chính nó). Chữ ký EIP-712
phủ `m.data`; binding phủ danh tính phong bì `(from, batch, nonce, …)`. Hệ quả:
- Bóc proof khỏi phong bì rồi gọi thẳng ⇒ statement có `ZTX_V1_DIRECT`, binding 0 ⇒ transcript lệch ⇒ revert.
- Nhét proof vào phong bì khác (khác `from`/`batch`/`nonce`/hạn/phí) ⇒ binding lệch ⇒ revert.
- Khác token / khác chain ⇒ header lệch ⇒ revert.
- Phát lại sau khi chạy ⇒ `sendCounter`/`accSeq`/nonce phong bì đã tiến ⇒ revert.

**Lời gọi thẳng** (`msg.sender` tự trả gas, statement `ZTX_V1_DIRECT`, `envelopeBinding = 0`):

```
transferConfidential(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary) returns (bytes32 entryRef)
      selector 0x7c947e8e
burn(bytes payload, uint256 amount, address recipient, bytes32 beneficiary, bytes proof, bytes authSig)
      selector 0x8938052e
```

Lời gọi thẳng **không có phí ngoài** (RS2-14): người gọi tự trả gas; phí ngoài chỉ sống trong phong bì. (Bản 1 có
7 tham số `…, FeeMode, uint256, address` — bỏ vì không ai cần trả phí cho chính mình, và 7 tham số làm mọi
contract Solidity gọi vào bị *stack too deep* với legacy codegen.)

`authSig` có mặt ở **cả hai** đường: lời gọi thẳng không phải lối tắt quanh `auth_custody` (§11).
`burn`: `0 < amount ≤ maxDecryptableShielded` (≤ 2^54) kiểm **trước** khi dựng statement — cùng với `fee < 2^32`
nó bảo đảm `amount + fee < r`, không có bí danh mod `r`.

**Op trong phong bì** (`m.data = op ‖ abi.encode(...)`, `m.to = address(0)`, `m.value = 0`):
- `OP_ZTRANSFER = bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)"))`,
  args `(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`.
- `OP_ZBURN = bytes4(keccak256("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)"))`,
  args `(bytes payload, uint256 amount, address recipient, bytes32 beneficiary, bytes proof, bytes authSig)`.
- `m.data` rỗng ⇒ chuyển ERC-20 công khai `m.from → m.to` như mọi token.

**Phí (SRS §7.4).** Hai tầng:
- *Trong:* `fee` công khai trong statement, trừ đồng hình `C_acc − [fee]G`, cộng `[fee]G` vào `pending` của
  `beneficiary` (UA đã đăng ký). Cố định theo token (`confidentialFee`), không phụ thuộc `v`.
- *Ngoài:* trả bằng số dư ERC-20 **công khai** của token này (`wrap`/`unwrap` underlying 1:1). Op Zether chỉ nhận
  `FeeMode.NONE` hoặc `FIXED` — `PERCENT` bị `FeePolicy.requireConfidentialSafe` chặn; `FIXED` là tuyệt đối
  (không trần 1% vì số tiền ẩn — RS2-6). Chuyển ERC-20 thường (data rỗng) giữ nguyên `FeePolicy.compute`.
Thứ tự pipeline giữ §04.6.1, rẻ trước đắt sau: relayer → hạn → mode → nonce → chữ ký → **số dư công khai đủ trả
phí ngoài** → kiểm op rẻ (`accSeq`, `sendCounter`, đăng ký, độ dài) → **verify proof** → thu phí ngoài → thực thi →
nonce++. Phong bì không đủ phí revert trước mọi precompile.

`entryRef = keccak256(abi.encode(keccak256("BAMBOO-ZETHER-ENTRY-V1"), chainid, token, fromUA, sendCounter))`
(`sendCounter` trước khi tăng).

## 11. Uỷ quyền và registry (SRS §7.5, §8.3; bất biến an ninh #1 §02.4.2)

Transfer/burn xác thực **hai** thứ: proof (biết `x`) **và** chữ ký `authSig` theo `authScheme` của tài khoản gửi trên
`authDigest = keccak256("BAMBOO-ZETHER-AUTH-V1" ‖ keccak256(statement))`. Lộ `x` của tài khoản không phải
`SELF_SCHNORR`/`PQ_COMMITMENT` chỉ là read-only breach.

### 11.1 Schnorr (mọi curve)

```
sign(x, msg32):  k hedged;  R = [k]G;  e = hashToScalar(keccak256("BAMBOO-ZETHER-SCHNORR-V1" ‖ R ‖ Y ‖ msg32))
                 z = k + e·x mod r;   sig = R ‖ be32(z)                    (P + 32 byte)
verify:          z < r, R ≠ O, Y ≠ O, e ≠ 0, [z]G − R − [e]Y == O
```

### 11.2 Đăng ký và PoP

`register(encodedY, scheme, authData, popSignature, linkEVM)`: `|encodedY| ∈ {64, 128}` chọn curve; điểm hợp lệ,
`≠ O`, trong subgroup; `UA = keccak256(encodedY)` chưa tồn tại.

`c = keccak256(abi.encodePacked(registry, encodedY, msg.sender))` (SRS §7.5 nguyên văn; R33: `account` =
`msg.sender` = account chủ thể). Vì `c` trói `msg.sender`, `register` **không relay bởi bên thứ ba được**: chủ thể tự
gọi bằng EOA hoặc smart account của mình (relayer, nếu có, trả gas ở tầng account đó). Không có replay chéo chain:
phát lại cần chính `msg.sender` ấy và cho ra đúng bản ghi đó. `popSignature = abi.encode(bytes schnorrPop, bytes authPop)`:
- `schnorrPop` = Schnorr §11.1 bằng `x` trên `c` (chống rogue key cho khoá ElGamal).
- `authPop` = chứng minh nắm khoá uỷ quyền, cũng trên `c` (bảng dưới).

| # | Scheme | `authData` | `authSig` (transfer/burn/rollOverSigned) | `authPop` |
|---|---|---|---|---|
| 0 | SELF_SCHNORR | `0x` | rỗng khi có proof; ngoài ra `abi.encode(encodedY, schnorrSig)` | rỗng |
| 1 | ECDSA_MULTISIG | `abi.encode(address[] owners_sorted, uint256 threshold)` | `abi.encode(bytes[] sigs)` sắp theo signer tăng | như authSig, trên `c` |
| 2 | FROST_BN254 | `abi.encode(bytes groupKey64, uint256 threshold, uint256 total)` | Schnorr bn254 bằng groupKey | Schnorr bằng groupKey trên `c` |
| 3 | MUSIG2_BN254 | `abi.encode(bytes aggKey64, uint256 totalSigners)` | như 2 | như 2 |
| 4 | BLS_BN254 | `abi.encode(bytes g2PubKey128)` | sig G1 64 B; `e(sig,−G2)·e(H(m),pk)=1` | BLS trên `c`, nhãn POP |
| 5 | BLS_12381 | `abi.encode(bytes g2PubKey256)` | sig G1 128 B (min-sig) | BLS trên `c`, DST POP |
| 6 | PQ_COMMITMENT | `abi.encode(bytes32 pqCommitmentHash)` | như 0 (verify PQ off-chain, on-chain giữ cam kết) | rỗng |
| 7 | SMART_ACCOUNT_1271 | `abi.encode(address account)` | bytes cho `isValidSignature(digest, sig)` | `isValidSignature(c, authPop)` |

- ECDSA_MULTISIG: `0 < threshold ≤ len(owners)`, owners khác 0, tăng nghiêm ngặt — kiểm lúc `register`. Chữ ký
  ECDSA trên **digest thô** (không tiền tố EIP-191), low-s, sắp theo địa chỉ người ký tăng dần (`MultiSig.sol`).
- bn254 G2 (EIP-197): `x_im ‖ x_re ‖ y_im ‖ y_re`. `H(m)` cho BLS_BN254 = `mapToG1("BAMBOO-BLS-BN254-SIG-V1" ‖ m)`,
  PoP dùng `"BAMBOO-BLS-BN254-POP-V1"`.
- BLS_12381: `HashToCurve.hashToG1(m, DST)`, `DST_SIG = "BAMBOO-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"`,
  `DST_POP = "BAMBOO-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"`; pk qua `G2MSM` k=1 (subgroup).
- **BLS cùng curve với khoá ElGamal bị cấm** (canon C6.1: công bố `[x]G2` phá DDH): `BLS_BN254` với `Y` 64 byte và
  `BLS_12381` với `Y` 128 byte ⇒ `UnauthorizedScheme`.
- `linkEVM`: `links[msg.sender] = UA`, `link_eth[UA] = msg.sender`; `msg.sender` đã liên kết ⇒ `EVMAlreadyLinked`.
- Trùng UA ⇒ `AccountAlreadyRegistered`. Không có xoay khoá: đổi khoá = UA mới (RS2-9).

## 12. Tiết lộ (`ITransferDisclosure`, SRS §9.4)

Token lưu theo `entryRef`: `Y_t ‖ C_out ‖ D_out ‖ C_aud`. `opening` theo kind:

- `SENDER_S`: `abi.encode(uint256 s)` — kiểm `[s]G == D_out` và `[amount]G + [s]Y_t == C_out`.
- `RECEIVER_X`: `abi.encode(bytes A1, bytes A2, uint256 z)` — Chaum-Pedersen
  `log_G(Y_t) == log_{D_out}(C_out − [amount]G)`.
- `AUDITOR`: như `RECEIVER_X` với `Y_a`, `C_aud`.

```
e = hashToScalar(keccak256("BAMBOO-ZETHER-DISCLOSE-V1" ‖ be32(chainid) ‖ token(20) ‖ entryRef ‖ be32(amount)
                           ‖ u8(kind) ‖ A1 ‖ A2))
kiểm:  [z]G − A1 − [e]K == O    và    [z]D_out − A2 − [e](M − [amount]G) == O
       (K, M) = (Y_t, C_out) cho RECEIVER_X, (Y_a, C_aud) cho AUDITOR
```

Kiểm thêm: `amount < 2^n_v` (nếu không, `amount + r` cũng "đúng" vì `[amount]G` chỉ phụ thuộc `amount mod r`),
`z < r`, `e ≠ 0`; `A1`, `A2` vào cùng MSM (subgroup check trên BLS12-381).

`verifyTransferAmount` là view (miễn phí); `attestTransferAmount` emit `AmountAttested`. Auditor đọc được **đúng**
các `C_aud` (mỗi transfer một cái), không đọc được `acc`/`pending` của ai (mã hoá bằng khoá chủ). Khoá auditor đặt
lúc `initialize`, bất biến (RS2-8).

## 13. Cổng an toàn (owner, R34)

- `ZetherSafety.isDevChain()`: `chainid ∈ {31337 (anvil/hardhat), 1337 (geth --dev)}` — allowlist cứng (RS2-1).
- `OpenFactory.zetherEnabled` mặc định `false`; `setZetherEnabled(true)` (registrar) revert ngoài chain dev;
  `createZetherToken`/`createUnregistered(ZETHER)` revert khi cờ tắt **hoặc** chain không phải dev.
- `ZetherToken.initialize`, constructor của hai verifier và `UniversalAccountRegistry` cũng revert ngoài chain dev
  (deploy tay không vòng qua được).
- NatSpec mọi contract Zether và HANDOFF: **UNAUDITED — NOT FOR PRODUCTION FUNDS**.

## 14. Vector

Định dạng chung: JSON, số dạng chuỗi hex `0x…` (scalar 32 byte, điểm theo mã hoá §2), bytes là `0x…`.

**Do S2 (contracts) xuất** — `smartcontracts/test/vectors/zether/`:
- `generators_bn254.json`, `generators_bls12381.json`:
  `{ "curve", "proofSystemId", "h", "U", "G": [64], "H": [64], "blobKeccak" }`.
- `transcript.json`: `{ "cases": [ { "ops": [ {"absorb": label, "data": hex} | {"challenge": label, "curve": c} … ],
  "states": [st sau mỗi op], "challenges": [scalar] } ] }` + `hashToScalar` cases `{seed, bn254, bls12381}`.
- `schnorr_{bn254,bls12381}.json`: `{ "x", "Y", "msg", "k", "R", "e", "z", "sig" }`.

**Do S3 (prover) xuất** — `zether-prover/vectors/` (S2 chép vào `smartcontracts/test/vectors/zether/s3/`):
- `transfer_{bn254,bls12381}.json`:
  `{ "curve", "statement", "proof", "payload", "witness": {"x","v","s","b","bPrime","gammaV","gammaB"},
     "expect": true }` — statement theo §6 với chainId/token tuỳ ý (verifier không đọc chúng ngoài transcript).
- `burn_{bn254,bls12381}.json`: như trên, witness `{"x","b","amount","bPrime","gammaB"}`.
- `schnorr_{curve}.json` (đối chiếu chéo với của S2), `disclosure_{curve}.json`:
  `{ "entryRef","chainId","token","amount","kind","Yt","Cout","Dout","Ya","Caud","opening" }`.
S2 kiểm: vector đúng ⇒ `verifyTransfer/verifyBurn == true`; lật một bit bất kỳ của proof/statement ⇒ `false`
hoặc revert.

## 15. Gas (đo, forge 1.3.5, EVM Prague, chain 31337)

Đo bằng `gasleft()` quanh lời gọi trong test (`ZetherVerifier.t.sol`, `ZetherToken.t.sol`,
`UniversalAccountRegistry.t.sol`, chạy `forge test -vv`): **execution gas, chưa gồm 21,000 intrinsic và calldata**
(transfer bn254 ≈ 3.7 KB calldata ≈ +50k; BLS ≈ 6.6 KB ≈ +95k). Proof thật (prover test + vector S3).

| Thao tác | bn254 | BLS12-381 | Số SRS/canon (bn254 trừ khi ghi) | Lệch |
|---|---|---|---|---|
| `verifyTransfer` (verifier, auditor tắt) | 2,162,249 | 2,411,138 | BP 1,507k + Σ 171k = 1,678k (§3.3.6) | +29% |
| `verifyTransfer` (auditor bật) | 2,190,479 | 2,453,597 | +27.5k (C6.5) | khớp (+28k / +42k) |
| `verifyBurn` | 1,329,969 | 1,428,870 | ~1.27M (§3.7.1) | +5% |
| `transferConfidential` thẳng (auditor, phí trong) | 2,748,019 | 3,400,986 | **1,905,000** (C7.2); BLS ≈1,050,000 | +44%; BLS +224% |
| `transferConfidential` qua phong bì (+phí ngoài) | 2,818,905 | 3,457,852 | — | phong bì ≈ +71k |
| `burn` (gồm chuyển underlying) | 1,396,398 | 1,521,199 | ~1.27M | +10% |
| `fund` (credit đầu / ấm) | 191,360 / 28,591 | 247,307 / 36,832 | — | |
| `rollOverPublic` (có việc / no-op) | 115,234 / 2,305 | 166,414 / 2,295 | ~66k exec (C7.3) | +75% |
| `rollOverSigned` (Schnorr) | 133,370 | 197,316 | ~31k (§3.5.4) | ×4 |
| `register` SELF_SCHNORR | 102,645 | 83,437 | ~105,750 (§2.2.5); BLS ~160k | khớp; BLS rẻ hơn |

Vì sao lệch, để không ai "sửa" sai chỗ:
- **Verify bn254 +29%:** canon tính 6,550 gas/điểm MSM; thực tế mỗi điểm là `staticcall` 0x07 + 0x06 qua một
  vòng assembly + chép buffer, cộng ~10 MSM nhỏ của Σ (mỗi cái trả một lần overhead) và transcript keccak trên
  statement 960 B. Cận dưới không đổi được là 6,150 × 230 điểm ≈ 1.41M.
- **BLS đắt hơn bn254, không rẻ như canon dẫn:** EIP-2537 bản cuối định giá G1MSM 12,000/cặp × discount, discount
  sàn **519/1000** ở k ≥ 128 ⇒ ≈ 6,230 gas/điểm — ngang `ecMul` bn254 — trong khi canon giả định discount sâu hơn.
  Cộng điểm 128 B (gấp đôi bộ nhớ/calldata). Lợi thế của BLS12-381 là **bảo mật** (117–126 bit), không phải gas.
- **Token thêm ~560k (bn254) trên verify:** lưu bundle tiết lộ `Y_t‖C_out‖D_out‖C_aud` (256 B ≈ 9 slot mới ≈ 200k
  — cái giá của `transferCiphertext` bản SRS, RS2-15), cập nhật `acc`/`pending` dạng `bytes` trong storage, các
  lời gọi `g1Add/g1Sub/g1MulBase` sang verifier, `requireAuthorized` của registry.
- **rollOver:** 4 điểm `bytes` ghi lại + 2 phép cộng qua verifier; canon đếm 10 SSTORE ấm.
Kill criterion S1 của canon (2.5M) bị vượt ở transfer bn254 (2.75M thẳng): đây là v1 tham chiếu, chưa tối ưu
(gộp Σ thành một MSM ngẫu nhiên hoá, lưu điểm dạng `bytes32[2]`, bỏ bundle tiết lộ khỏi storage) — ghi ở rủi ro mở.

## 16. Rulings (S2)

- **RS2-1** Cổng dev: allowlist cứng `{31337, 1337}`; cờ factory mặc định tắt; kiểm thêm ở `initialize` và constructor
  verifier/registry. Chain 9000 **không** nằm trong allowlist (cần owner quyết).
- **RS2-2** Epoch bỏ (canon C5): `IZetherVerifier.verifyTransfer/verifyBurn` nhận `statement` đầy đủ thay cho
  `(payload, epoch)`; `simulateAccounts(encodedY, epoch)` thay bằng `accountState(UA)`.
- **RS2-3** `shieldScale` = raw unit / đơn vị che giấu (theo NatSpec code, không theo cột "2" của bảng SRS §7.3 —
  bảng đó là số chữ số giữ lại: `shieldScale = 10^(decimals − giữ)`).
- **RS2-4** Phí tầng trong vào `pending` của `beneficiary` UA (interface code + ZSC), không ra ERC-20 như research
  §3.4.3; phí ngoài là ERC-20 công khai của chính token (`wrap`/`unwrap`).
- **RS2-5** Ràng phong bì bằng `envelopeBinding` trên các trường phong bì **trừ** `data` (tránh vòng tròn); chữ ký
  EIP-712 phủ `data`.
- **RS2-6** Phí ngoài `FIXED` cho op Zether không chịu trần 1% (số tiền ẩn); `PERCENT` cấm.
- **RS2-7** Mixin meta-tx riêng (`ZetherMetaTx`), dùng `MetaTxLib` chỉ đọc; không sửa `ERC20MetaTx`/`MetaToken`.
- **RS2-8** Khoá auditor bất biến, đặt lúc `initialize` (không timelock vì không có setter).
- **RS2-9** Registry không xoay khoá; `EVMLinkUpdated` không dùng (không có hàm đổi link trong SRS).
- **RS2-10** `PQ_COMMITMENT` trên chuỗi = như `SELF_SCHNORR` (proof uỷ quyền; ngoài proof dùng Schnorr bằng `x`),
  cam kết PQ lưu để xoay khoá tương lai — đúng "verify off-chain" của SRS §7.5.
- **RS2-11** Underlying bắt buộc là ERC-20 (không native, không tự mint) ở v1.
- **RS2-12** `fund`/`rollOver*` là lời gọi thẳng; chỉ transfer/burn có op trong phong bì (rollOverSigned tự mang chữ
  ký nên ai cũng relay được).
- **RS2-13** Không memo AEAD (SRS §7 không có); client giải mã bằng BSGS trong `DECRYPT_BOUND`.
- **RS2-14** Lời gọi thẳng `transferConfidential(payload, proof, authSig, beneficiary)` — không có phí ngoài (chỉ
  phong bì có), khác chữ ký 6 tham số của SRS §9.3.
- **RS2-15** Bundle tiết lộ lưu trong storage để `transferCiphertext` trả được dữ liệu như SRS §9.4 (≈ +200k gas);
  token phí-chuyển bị từ chối (`UnsupportedUnderlying`) thay vì mint theo phần thực nhận.
- **RS2-16** Cổng gas của precompile: verifier chuyển `gas()` cho precompile (không ghim giá EIP-1108/2537) — một
  điểm sai làm tx tiêu hết gas; relayer phải mô phỏng trước (đã là quy tắc §3.7.7).

- **RS2-17** `rollOverSigned` kiểm `pendingSeq ≥ expectedPendingSeq` (không `==`): transfer `v = 0` miễn phí của
  kẻ grief không giết được rollOver của chủ `OWNER_ONLY`. Phát lại vẫn chặn vì digest ghim `accSeq` (review S2-R1).
- **RS2-19** `rollOverSigned` còn đòi `expectedPendingSeq > lastRolledPendingSeq`: chữ ký không nêu credit mới là
  no-op, không tăng `accSeq` ⇒ sau RS2-17 nó sống tới credit kế tiếp và ai cũng dùng nó ép rollOver, giết proof đang
  bay của chủ. Nay mọi chữ ký được chấp nhận đều làm rollOver thật ⇒ dùng một lần
  (`test_rollOverSignedWithoutNewCreditIsRejected`).
- **RS2-18** Registry từ chối khoá uỷ quyền BLS = điểm vô cực (BLS_12381 sau G2MSM, BLS_BN254 128 byte 0) và chữ ký
  BLS12-381 = vô cực — nếu không, pairing tầm thường cho "custody BLS" giả, `x` một mình tiêu được (review S2-R2).

## 17. Review log

### agy — review đặc tả bản 1 (2026-10-03), 10 finding

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| 1 | crit | **Sai một nửa**: reviewer đọc stub `IZetherToken` cũ. Thiết kế đã có `authSig` ở lời gọi thẳng | Ghi rõ ABI lời gọi thẳng (§10); giữ `ZTX_V1_DIRECT` |
| 2 | high | Đúng (thứ tự) | Kiểm số dư phí ngoài trước verify proof (§10) |
| 3 | high | Đúng là `register` không relay được; đó là hệ quả của SRS (c trói msg.sender) | Ghi rõ: chủ thể tự gọi (§11.2) |
| 4 | high | Đúng | Kiểm `threshold`/owners lúc đăng ký; ghi digest thô (§11.2) |
| 5 | high | Đúng | `0 < amount ≤ maxDecryptableShielded` trước statement (§10) |
| 6 | med | **Sai**: phát lại cần chính `msg.sender`, kết quả y hệt | Từ chối; giữ công thức SRS nguyên văn |
| 7 | med | Đúng phần `amount < 2^n_v` (bí danh mod r), `z < r` | Thêm (§12); subgroup đã ngầm qua MSM |
| 8 | med | Đã có (§6, E6) | Không đổi |
| 9 | low | Đúng (dễ đọc nhầm) | Ghi chú §9 |
| 10 | low | Đúng | Ghi chú §3 |

### Review nhánh (2026-10-03) — Claude reviewer độc lập (agy hết quota, grok rate-limit)

| # | Sev | Kết luận | Xử lý |
|---|---|---|---|
| S2-R1 | med | Đúng (PoC chạy): transfer `v = 0` từ tài khoản số dư 0 tăng `pendingSeq` nạn nhân ⇒ `rollOverSigned` `OWNER_ONLY` revert mãi; §5 nói sai "phải nạp tiền thật" | RS2-17 + sửa §5; test `test_rollOverSignedSurvivesFrontRunCredit` |
| S2-R2 | low | Đúng (PoC chạy): BLS_12381 đăng ký được với pk = vô cực, chữ ký 0 qua mọi digest | RS2-18; test trong `test_multisigBadAuthDataRejected`, `test_bls12381Auth` |
