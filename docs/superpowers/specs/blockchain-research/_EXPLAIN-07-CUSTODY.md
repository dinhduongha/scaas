# Giải thích cơ chế `07-custody-providers.md`

**Viết cho ai:** người cần hiểu §07 làm gì và vì sao, không cần đọc hết 18.400 từ.
**Ngày:** 2026-08-31. **Nguồn:** `07-custody-providers.md`, đối chiếu `_USER-DECISIONS.md` §23, §24.
**Đây là bản giải thích, không phải đặc tả.** Chi tiết chuẩn tắc nằm ở `07-custody-providers.md`.
Tham chiếu `§` đọc theo bảng tra ở `_USER-DECISIONS.md` §0.

---

## Bài toán gốc, phát biểu chính xác

**HSM là một signing oracle, không phải một máy tính đa dụng.** Nó nhận một digest, trả một chữ ký,
trên một đường cong nằm sẵn trong firmware đã được chứng nhận.

Zether cần chạy **hàng nghìn phép nhân vô hướng trên BN254 cộng một transcript keccak** với witness bí
mật. Đó không phải là ký — đó là chạy một chương trình.

Nên câu quen thuộc *"cứ để private key trong HSM FIPS 140-3 Level 3"* **không thực hiện được** cho khoá
Zether. §07 tồn tại để nói thẳng điều đó, rồi tìm đường vòng đủ tốt.

---

## Trụ cột 1 — HAI trục custody, không phải một

Đây là ý quan trọng nhất của cả file. Bản nháp cũ coi custody là **một** lựa chọn. Không phải:

| Trục | Giữ gì | Dùng để làm gì |
|---|---|---|
| **`auth_custody`** | `authKey` — secp256k1 / ed25519 | Ký transaction, ký EIP-712 |
| **`conf_custody`** | `encKey x` — scalar trên BN254 | Giải mã ElGamal, dựng ZKP |

Hai trục **chọn riêng biệt cho từng dòng tiền**. Ví dụ B2B có Zether: `auth_custody = hsm` cộng
`conf_custody = Shamir 2-of-3`. Chúng không liên quan gì nhau, và gộp chúng làm một là nguồn gốc của
gần như mọi nhầm lẫn downstream (xem `_USER-DECISIONS.md` §23.2).

---

## Trụ cột 2 — Ranh giới uỷ quyền có BA tầng, không phải hai

Bản nháp cũ nói "không uỷ quyền được". Quá thô. Phát biểu đúng:

> Không uỷ quyền được cho một **signing oracle**. Uỷ quyền được cho một **computing oracle** (enclave).
> Và phần thực sự phụ thuộc `x` bé đến mức uỷ quyền được cho một **threshold protocol qua mạng**.

| Thao tác | HSM / KMS / MPC SaaS | Enclave | Threshold qua mạng |
|---|---|---|---|
| `sign_digest_secp256k1` | ✔ | ✔ | ✔ |
| `sign_digest_ed25519` | ✔ | ✔ | ✔ |
| `sign_schnorr_bn254` | ✘ | ✔ | ✔ (FROST-BN254) |
| `zk_mul_by_x` | ✘ | ✔ | ✔ |
| `zk_response` | ✘ | ✔ | ✔ |
| `elgamal_decrypt` | ✘ | ✔ | ✔ |
| `zether_prove_transfer` | ✘ | ✔ | ✘ — đắt 10³–10⁵ lần |

### Ghi chú kỹ thuật sắc nhất của mục này

**`CKM_ECDH1_DERIVE` *chính là* phép nhân vô hướng.** PKCS#11 `C_DeriveKey` với KDF `CKD_NULL` trả về
toạ độ `x` của `x_priv · P`. Về lý thuyết đây đúng là nguyên thuỷ cần cho `zk_mul_by_x`. Bốn lý do vẫn
không dùng được:

1. HSM chỉ nhận `CKA_EC_PARAMS` là curve đã biết. **BN254 không có OID trong danh mục nào.** CloudHSM /
   Cloud HSM / Managed HSM đều không mở đường truyền tham số explicit.
2. Trả về **mất dấu `y`**. Khôi phục được bằng cách thử hai nghiệm — nhưng phải làm **ngoài** HSM, tức
   đã ra khỏi boundary. Với `zk_mul_by_x` còn tệ hơn: dấu sai làm proof invalid **im lặng**.
3. **`zk_response` không có nguyên thuỷ PKCS#11 nào tương ứng.** Không HSM thương mại nào cho tính
   `k + c·x` trong `F_r` của curve tuỳ ý. **Đây là rào cản cứng hơn rào cản curve**: kể cả một HSM *có*
   BN254 cũng không đủ — phải là HSM **lập trình được**.
4. Prover đầy đủ cần hàng nghìn round-trip PKCS#11 → vài giây tới vài chục giây/giao dịch. *Nhưng* với
   kiến trúc tách prover ở §07.2b, số round-trip tụt xuống **2–3**, và lý do (4) biến mất hoàn toàn.
   Chỉ còn (1)–(3).

---

## Trụ cột 3 — §07.2b: tách prover. Đóng góp chính của cả file

Quan sát mở đầu: **Bulletproofs range proof KHÔNG dùng `x`.** Witness của nó là các *giá trị*
(`v`, `b − v`) và blinding factor. Khoá bí mật không xuất hiện trong mạch.

| Thành phần proof | Khối lượng | Có `x`? |
|---|---|---|
| Range proof trên `v` (n_v = 32) | ~600–900 scalar mult + MSM | **Không** |
| Range proof trên `b − v` (n_b = 64) | ~1.200–1.800 scalar mult + MSM | **Không** |
| Chứng minh biết `x`: `y = g^x` | 1 mult + 1 response | **Có** |
| Chứng minh số dư đúng: `C_L · C_R^{-x} = g^b` | 1 mult + 1 response chung nonce | **Có** |
| Equality `v` dưới `y_sender` / `y_receiver` | 3–4 mult | **Không** (dùng `s`) |
| Fiat-Shamir transcript | keccak | Không |

**Tổng phần chạm `x`: 2 phép nhân vô hướng trên điểm CÔNG KHAI với cùng một nonce `k`, cộng 1 scalar
response `s_x = k + c·x mod r`.**

Từ đó rút ra `IZetherKeyOracle`, và **nó là thứ duy nhất cần bảo vệ bằng phần cứng**. Bốn hệ quả:

1. **TCB enclave co một bậc.** Thay vì nhét cả prover arkworks (vài chục nghìn dòng, hàng trăm crate phụ
   thuộc) vào enclave, chỉ nhét oracle: **< 300 dòng**, image **< 5.000 dòng** kể cả crypto backend,
   không I/O ngoài vsock, không parser. Audit được trong một tuần.
2. **Threshold hoá được.** 2 mult + 1 response là giao thức chuẩn, không phải đề tài nghiên cứu.
3. **HSM lập trình được (Functionality Module) từ "bất khả thi" thành "4–8 tuần".** Lý do từ chối bây giờ
   thuần **quy trình chứng nhận**, không còn là **kỹ thuật** — và điều đó đổi câu trả lời cho khách hàng
   regulated.
4. **Prover Bulletproofs chạy NGOÀI enclave.** Nó không giữ bí mật về *khoá*; nó chỉ giữ bí mật về *số
   tiền*, và đó là một biên khác.

---

## Trụ cột 4 — Cơ chế "pluggable" thực sự hoạt động thế nào

Ba lớp xếp chồng.

### (a) Interface `ICustodyProvider` — bốn nhóm thao tác

| Nhóm | Nội dung | Uỷ quyền được cho ai |
|---|---|---|
| **A** | `create_account`, `public_key`, `sign_digest_*`, `sign_raw_tx`, `attest`, `rotate_auth` | signer từ xa; khoá không bao giờ rời boundary |
| **B** | `zk_nonce_commit`, `zk_mul_by_x`, `zk_response`, `sign_schnorr_bn254`, `elgamal_decrypt` | **không** HSM/KMS/MPC SaaS; **có** enclave hoặc threshold shard |
| **B′** | `zether_prove_transfer` / `_withdraw` / `_migrate` | chỉ `enclave` / `on_device` / `custodial` |
| **C** | `wrap_export`, `import_wrapped`, `destroy` | thao tác đặc quyền, cần quorum ticket |

Bốn quy ước bắt buộc trên interface, mỗi cái vì một lỗi cụ thể:

- **`idem` bắt buộc trên mọi thao tác ký.** Không có nó: signer timeout ở giây thứ 3 → Odoo retry → HSM
  ký lần hai → hai raw tx cạnh tranh, hoặc tệ hơn, **hai giao dịch cùng được mine**. Quy tắc:
  `idem = H(tenant ‖ signer_ref ‖ digest32 ‖ purpose)`, signer cache 24 h và trả **đúng chữ ký cũ**.
- **`attest(h, nonce32)` nhận nonce**, do Odoo sinh. Không có nonce thì attestation replay được.
- **`PROTOCOL_VERSION`** — client từ chối nếu lệch.
- **`policy_bundle_id`** — hash của `SigningPolicy` đang hiệu lực, ký bởi governance.

### (b) `caps` — cổng chặn lúc CẤU HÌNH, không phải lúc chuyển tiền

```python
def call(provider, op, *a, **kw):
    if op not in provider.caps:
        raise CustodyUnsupported(f"{provider.kind} khong lam duoc {op}")
    return getattr(provider, op)(*a, **kw)
```

Nó chặn đúng một lỗi: một deployment cấu hình `conf_custody = 'kms'`, mọi thứ xanh cho tới lần bấm
"chuyển tiền bảo mật" **đầu tiên trên production**.

Ma trận `caps` theo `kind`:

| `kind` | A: `sign_*` | `zk_mul_by_x` / `zk_response` | `elgamal_decrypt` | `zether_prove_*` |
|---|---|---|---|---|
| `hsm` (PKCS#11) | ✔ | ✘ | ✘ | ✘ |
| `kms` | ✔ | ✘ | ✘ | ✘ |
| `mpc` (Fireblocks/Fordefi) | ✔ | ✘ | ✘ | ✘ |
| `tee_saas` (Turnkey) | ✔ | ✘ (trừ khi vendor mở custom code) | ✘ | ✘ |
| `enclave` (tự vận hành) | ✔ | ✔ | ✔ | ✔ |
| `custodial` | ✔ | ✔ | ✔ | ✔ |
| `on_device` | ✔ | ✔ | ✔ | ✔ |
| `smart_account` | ✔ (qua WebAuthn) | ✘ | ✘ | ✘ |

**Đọc bảng theo chiều dọc là đọc được cả §07.2:** cột `zether_prove_*` có **ba `kind` làm được, năm
không**. Cột `zk_mul_by_x` cũng ba `kind` đó — nhưng với TCB nhỏ hơn một bậc (§07.2b).

### (c) `blockchain.custody.policy` — hiện thực hoá "chọn lúc deploy"

Locked #6 nói "chọn lúc deploy". Bản nháp cũ mô hình hoá *các lựa chọn* nhưng không mô hình hoá *cái đã
chọn*. Không có model này thì "chọn lúc deploy" nằm **trong đầu người deploy**.

```
(company_id, money_flow, chain_profile)
      -> auth_provider_id            (bat buoc)
      -> conf_provider_id            (de rong neu luong nay khong dung Zether)
      -> requires_c_audit, min_threshold_n
```

Ràng buộc `@api.constrains` chặn hai lỗi: provider không prove Zether được mà bị gán vào
`conf_provider_id`; và B2B **có Zether** mà đặt `min_threshold_n < 3`.

---

## Custody có tắt được không

Hai trục, hai câu trả lời khác nhau (chi tiết: `07-custody-providers.md` §07.12.1b).

| Trục | Tắt được? |
|---|---|
| **`conf_custody`** (oracle lane, giữ `x`) | **CÓ, hoàn toàn.** Không Zether ⇒ để rỗng. Sau khi Zether cho B2B thành tuỳ chọn, đây là **mặc định** |
| **`auth_custody`** (ký vỏ tx) | **Không toàn cục — nhưng theo vai thì có** |

Ai đó phải ký transaction. Nhưng "ai đó" không nhất thiết là ta — ba cấu hình phía ta không cầm khoá nào:
node `submit: false` (pool thuần, §21.4); deployment chỉ nhận + index; mọi thứ user ký trên thiết bị và
bên thứ ba relay.

**Và điểm dễ hiểu sai nhất:** custody không phải một feature flag mà là **một slot cắm được, cái cắm vào
có thể rất nhỏ**. §07.1b nói *"signer là một sản phẩm riêng: deploy, HA, monitoring, on-call"* — đúng cho
`enclave`/`hsm`, **sai cho `kms`**, vốn chỉ là một lời gọi SDK trong chính tiến trình đang chạy.

Cấu hình tối thiểu chạy được cho META v1: **một provider `kind = 'kms'`, `conf_provider_id` rỗng** —
không enclave, không HSM, không tiến trình signer nào.

---

## Trụ cột 5 — Con đường giữ HSM có ý nghĩa thật

```
HSM FIPS 140-3 L3
  └── giu KEK (AES-256, non-extractable, CKM_AES_KEY_WRAP_KWP)   <-- bien FIPS o DAY
        └── wrap/unwrap blob chua x   (HSM khong "hieu" x, chi coi la 32 byte opaque)
              └── unwrap CHI trong enclave da attest
                    └── x song trong RAM enclave, hat nhan sigma chay tai do
```

Trên AWS đây **không phải sơ đồ trên giấy** — có cơ chế cưỡng chế cụ thể: `kms:Decrypt` với tham số
`Recipient` (attestation document COSE_Sign1 ký bởi Nitro PKI), key policy điều kiện trên
`kms:RecipientAttestation:PCR0`. Kết quả: **chỉ đúng một image enclave, đo bằng hash, mới unwrap được
`x`.** Một sysadmin có root trên EC2 host cũng không đọc được — KMS trả `CiphertextForRecipient`, mã hoá
dưới public key sinh **bên trong** enclave.

Trên GCP: Confidential Space + attribute condition trên `submods.container.image_digest`, **bắt buộc
kèm** `support_attributes` chứa `STABLE` — nếu không, một image debug cũng qua được.

### Câu phải viết vào hợp đồng khách hàng

**Ở mô hình này `x` KHÔNG nằm trong biên FIPS 140-3 Level 3 tại thời điểm sử dụng.** Nó nằm trong RAM
một enclave. Nitro Enclave, Intel TDX và AMD SEV-SNP **không** có chứng nhận FIPS 140-x Level 3 cho vai
trò này.

Nếu một cơ quan quản lý đòi FIPS L3 cho khoá mã hoá số dư, câu trả lời trung thực là: **yêu cầu đó hôm
nay không thoả mãn được với Zether.** Ba lựa chọn: (a) đổi câu chữ thành "khoá **chi tiêu** trong FIPS
L3; khoá **giải mã** trong confidential computing có attestation", (b) bỏ Zether, (c) đầu tư
Functionality Module.

---

## Trụ cột 6 — Đánh đổi trung tâm, một câu

> Khả năng khôi phục và tính non-custodial là **cùng một trục, ngược chiều nhau**. Không có cấu hình nào
> vừa "platform không thể chi tiêu tiền của bạn" vừa "platform khôi phục được tiền cho bạn".
> **Mọi lời chào hàng nói ngược lại là sai.**

Kèm số thật (§07.10): mất khoá **0,3–1,0%/năm** với tài khoản tự quản. 10.000 outlet ⇒ 30–100 tài khoản
mỗi năm khoá vĩnh viễn. Cấu hình backup quyết định con số này chênh **10–40 lần** ở cùng chi phí kỹ
thuật: passkey PRF đồng bộ ~0,05–0,2%/năm; seed phrase tự chép ~0,5–2%; device-bound ~3–8%.

---

## Bốn chi tiết Nitro là công việc thật, không phải footnote

| Chi tiết | Hệ quả |
|---|---|
| Enclave **không có network stack**, chỉ vsock | Phải viết `vsock-proxy` hai chiều. Nó là **toàn bộ I/O** của enclave ⇒ là thành phần bảo mật, nằm trong scope audit, phải whitelist đích |
| Enclave **không có RTC** | `expiry` không enforce được bằng đồng hồ enclave. Dùng **block number** làm đồng hồ |
| Attestation document ~5 KB | KMS chỉ nhận doc mới (~5 phút) ⇒ re-attest mỗi 60 s |
| Cold start 10–30 s | Không scale theo request ⇒ giữ pool enclave warm, N ≥ 2 |
| Bộ nhớ pre-allocate 2 GB/enclave | Bảng BSGS 2–4 MB + prover working set ~50 MB/luồng ⇒ đủ ~16 luồng |

---

## Chỗ §07 còn yếu (đã ghi vào nợ `_USER-DECISIONS.md` §23.9)

1. **§07.1 viết bằng Python.** `_USER-DECISIONS.md` §23.3 chốt Rust, vai `custody`. Ngữ nghĩa từng hàm
   giữ nguyên — chỉ ngôn ngữ và cách đóng gói đổi.
2. **Cái tên `confidential-signer` gánh hai việc.** Nó vừa là NHÓM A (ký tx, HSM/KMS làm được) vừa là
   NHÓM B (hạt nhân `x`, chỉ enclave). Đây là nguồn gốc của câu hỏi "signer để làm gì" khó trả lời.
   `_USER-DECISIONS.md` §23.2 đã tách tên: **custody broker** (NHÓM A) và **key oracle** (NHÓM B).
3. **Bảng §07.0 vừa được sửa** (2026-08-31): Zether cho B2B là **tuỳ chọn**, và hàng B2B đã tách theo
   chiều tiền chạy. Hệ quả: **không dòng tiền nào trong locked #3 bắt buộc oracle lane.**

---

## Đọc tiếp ở đâu

| Muốn biết | Đọc |
|---|---|
| Vì sao có ba làn (relay / custody / oracle) | `_USER-DECISIONS.md` §23.2, §23.5 |
| Oracle ghi state vào đâu, vì sao không persist | `_USER-DECISIONS.md` §23.10 |
| Non-custody có bỏ được oracle lane không | `_USER-DECISIONS.md` §23.11 |
| Chính sách trước khi ký, chống lạm dụng HSM | `12-threat-model.md` §12.5.1 |
| Odoo giữ gì (chỉ `signer_ref`) | `10-odoo-addon-design.md` §10.8.1 |
| Số thật của BSGS và vì sao bản nháp sai một bậc | `07-custody-providers.md` §07.4b |
