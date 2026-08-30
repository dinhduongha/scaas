## 07. Custody pluggable: HSM, MPC, custodial, non-custodial, smart account

### 07.0. Kết luận trước, lý luận sau

Bảy kết luận chi phối toàn bộ section này. Bốn trong số đó mâu thuẫn với câu chữ của `blockchain.md`; hai trong số đó mâu thuẫn với **bản nháp trước của chính section này**.

1. **Không có nhà cung cấp custody thương mại nào hôm nay giữ được toàn bộ khóa Zether.** Câu "khóa bí mật $x$ được lưu an toàn trong HSM/MPC FIPS 140-2 Level 3" (§10.5.2 mục 1 của note, lặp lại ở §10.3.1 và §14.2.8) **không thực hiện được như viết**. HSM ký; nó không sinh Bulletproof. Chi tiết ở §07.2 và §07.3.
2. Vì vậy custody phải tách làm **hai trục độc lập**, không phải một: `auth_custody` (ký EIP-712 / raw tx / Schnorr `authKey`) và `conf_custody` (giữ `x`, giải mã ElGamal, dựng ZKP). Nền móng đã có sẵn ở §2.4 — tách `encKey` khỏi `authKey`. Section này dùng lại nó và nói hệ quả vận hành.
3. **Bản nháp trước viết "`conf_custody` chỉ có ba hiện thực khả thi... Không có lựa chọn thứ tư." Câu đó sai và phải bỏ.** Có ít nhất năm, và cái thứ tư là cái tốt nhất: **tách prover**. Phần phụ thuộc `x` của một chứng minh Zether **không phải** là Bulletproofs — nó chỉ là 2–3 phép nhân vô hướng trên điểm công khai cộng 1–2 scalar response Schnorr. Đó là một oracle bé bằng 300 dòng code, **threshold hóa được**, **enclave hóa được với TCB tí hon**, và nó thay đổi gần như mọi kết luận downstream. Xem §07.2b — đây là đóng góp kỹ thuật quan trọng nhất của section.
4. **Hệ quả trực tiếp của (3): "mất `x` là mất vĩnh viễn" chỉ đúng cho cấu hình 1-of-1.** Nếu `x` được chia Shamir t-of-n **tại thời điểm tạo tài khoản**, thì mất một share không mất gì; và t bên còn lại khôi phục được *cả số liệu lẫn quyền chi tiêu* trên **mọi** chain, kể cả public, không cần `recoverAccount` phá tính bất biến. Cái giá là: t-of-n nghĩa là t bên **cùng có quyền chi tiêu**, tức là shared custody, tức là §07.5 (giấy phép) áp vào. Bản nháp trước bỏ sót toàn bộ nhánh này và tuyên bố "public chain: không có khôi phục. Chấm hết" — quá mạnh.
5. **"FIPS 140-2 Level 3" là ngôn ngữ đã hết hạn.** CMVP ngừng nhận hồ sơ FIPS 140-2 từ 2021, và **toàn bộ chứng nhận FIPS 140-2 chuyển sang Historical List ngày 2026-09-21** — tức **ba tuần nữa** tính từ hôm nay. Mọi câu trong `blockchain.md`, trong hợp đồng khách hàng và trong hồ sơ thầu viết "FIPS 140-2 Level 3" sẽ trỏ tới một danh mục lịch sử. Ngôn ngữ đúng: **"FIPS 140-3 Level 3, hoặc chứng nhận CMVP đương thời tương đương"**. Đây là một sửa đổi *văn bản hợp đồng*, phải làm trước khi ký, không phải một chi tiết kỹ thuật.
6. **Số của bản nháp trước về BSGS sai khoảng một bậc độ lớn**, và sai theo hướng nguy hiểm (lạc quan). Giải mã một *giao dịch* 32-bit không phải "vài ms" mà là **20–40 ms x86 native / 80–170 ms ARM64 native** khi có batch inversion, và **5–10× tệ hơn** khi không có. Giải mã một *số dư* 64-bit bằng BSGS **không phải "hàng giờ" mà là bất khả thi vì bộ nhớ** (bảng 2^32 điểm ≈ 86 GB); phải dùng Pollard kangaroo, ~57 phút một core x86. Xem §07.4b. Hệ quả: **running plaintext balance không phải "cache", nó là một phần trạng thái tài khoản**, và đường khôi phục nó là **replay delta từ indexer**, không phải brute force.
7. `C_audit` (§2.7.6) vẫn là cơ chế phục hồi *số liệu* duy nhất khi `x` mất hoàn toàn, và phải **bắt buộc** cho mọi tài khoản mang giá trị B2B settlement. Chi phí đúng là **~25,300 gas/transfer** (§2.7.6 đã sửa con số 13,200 của bản nháp cũ), ≈ $0.00005 trên Gnosis @2 gwei. Bản nháp trước của section 07 vẫn còn dùng con số 13,200 cũ — đã sửa ở đây.

Mặc định theo dòng tiền (locked #3), chọn lúc deploy:

| Dòng tiền | chain profile | `auth_custody` | `conf_custody` | Lý do |
|---|---|---|---|---|
| Loyalty / reward points | public (Gnosis) | `smart_account` (passkey) | `on_device` 1-of-1, PRF-wrapped | Giá trị nhỏ, UX là tất cả, không có nghĩa vụ custody |
| B2B settlement — **không Zether** (mặc định) | private hoặc public | `hsm` hoặc `ecdsa_multisig` 3-of-5 | **không áp dụng** | **[BẢN 3]** Zether cho B2B là **tuỳ chọn, không bắt buộc** (user, 2026-08-31). Không bật thì không có `x` nào, không có oracle lane, không có Shamir |
| B2B settlement — **có Zether** (tuỳ chọn) | **private** | `hsm` hoặc `ecdsa_multisig` 3-of-5 | **`x` chia Shamir 2-of-3** (thiết bị finance officer / enclave attested / két offline). Chiều distributor→brand prover chạy phía distributor; chiều brand→distributor prover chạy nơi có `x` của brand | Giá gốc là bí mật sống còn (§2.6 harvest-now-decrypt-later); mất khóa là thảm họa nên 1-of-1 bị cấm |
| End-user payment tại quầy | public (Gnosis/Celo) | `smart_account` | `on_device` 1-of-1 | Người mua đứng đợi → Bulletproofs, prove tại chỗ (§3.8) |
| Treasury / mint / upgrade / pause | mọi profile | **`hsm` FIPS 140-3 L3, bắt buộc, dual control** | không áp dụng | Không có Zether ở đây, chỉ ECDSA secp256k1 |
| Relayer EOA nóng | mọi profile | `enclave` (§06.6 mục 3), runway trần 4h | không áp dụng | Throughput 10 → 10^4 sign/s |
| Auditor `y_audit` | mọi profile | không áp dụng | **DKG 3-of-5, threshold ElGamal** | §07.4; giải mã không cần proving |

---

### 07.0b. Những giả định bản nháp trước không nói ra

Liệt kê đầy đủ, vì mỗi cái là một chỗ kế hoạch triển khai sẽ vấp:

| # | Giả định ngầm | Sự thật | Xử ở đâu |
|---|---|---|---|
| 1 | Có sẵn một service `confidential-signer` chạy được, ai đó vận hành nó | Nó là **một sản phẩm riêng**: deploy, HA, monitoring, cert lifecycle, on-call. Không phải một file `.py` | §07.1b |
| 2 | Gọi signer là đồng bộ và rẻ | MPC SaaS p50 **300 ms – 3 s** (§06.6). Gọi đồng bộ trong HTTP worker của Odoo = cạn worker pool ở 6–20 request đồng thời | §07.1b |
| 3 | `caps` do signer báo là đáng tin | Nó tự khai qua mTLS. Không có attestation ràng buộc thì một signer bị đánh tráo khai `kind='enclave'` và không ai biết | §07.1, §07.9 |
| 4 | Một provider cho một key là đủ mô hình hóa | Thiếu **binding money-flow → (auth provider, conf provider, policy)**. Locked #6 nói "chọn lúc deploy" — phải có model cho *cái được chọn*, không chỉ cho *các lựa chọn* | §07.12 `blockchain.custody.policy` |
| 5 | Nitro Enclave nói chuyện được với KMS và với chain | Nitro Enclave **không có network stack**. Chỉ vsock. Phải viết vsock proxy hai chiều, và nó là thành phần bảo mật (nó là toàn bộ I/O của enclave) | §07.2 |
| 6 | Attestation là một lần | Attestation document Nitro có hạn (nonce-bound, thực tế dùng trong vài phút; KMS chấp nhận doc không quá ~5 phút tuổi). Phải re-attest theo chu kỳ | §07.9 |
| 7 | Enclave có đồng hồ | Nitro enclave **không có RTC**. Thời gian phải lấy qua vsock từ host — tức **không tin được**. `deadline`/`expiry` không được enforce chỉ bằng đồng hồ enclave | §07.2 |
| 8 | `elgamal_decrypt` là thao tác vô hại | Nó là một **decryption oracle**. `decrypt(C, D)` với `D` do kẻ tấn công chọn trả về $\log_g(C \cdot D^{-x})$ — tức một ECDH oracle trên `x`. Phải chặn ciphertext không có thật trên chain | §07.1, §07.13 |
| 9 | `wrap_export` là một thao tác vòng đời bình thường | Nó là thao tác nguy hiểm nhất trong cả interface: nó **hợp pháp hóa việc lấy `x` ra khỏi boundary**. Phải quorum + dual control + rate limit + audit, giống hệt một ceremony | §07.1, §07.9 |
| 10 | `destroy(h)` an toàn | Destroy một key còn số dư Zether = đốt tiền không thu hồi được. Phải có tiền điều kiện "số dư chứng minh được bằng 0 hoặc đã `migrateAccount`" | §07.1 |
| 11 | `res.company` có định danh ổn định để làm key path | **Không có.** `res.company.id` là số nguyên tuần tự, trùng nhau giữa các database. Cần một `blockchain_tenant_uuid` bất biến | §07.11, §07.12 |
| 12 | Dump production restore sang staging là vô hại | Staging thừa hưởng nguyên `signer_ref`, `tenant_uuid`, `endpoint_url` → **staging ký được giao dịch production**. Đây là sự cố kinh điển | §07.11 `neutralize.sql` |
| 13 | Dữ liệu khóa được ở đâu cũng được | AWS/GCP **không có region tại Việt Nam**. Nitro/Confidential Space = dữ liệu ra khỏi VN → NĐ 13/2023 hồ sơ chuyển dữ liệu xuyên biên giới (§13.7.2) | §07.3, §07.14 |
| 14 | Odoo giữ được mTLS client key an toàn | `ir.config_parameter` đọc được bởi bất kỳ ai trong `base.group_system`. Private key của cert **không** thuộc về đó | §07.12 |
| 15 | Có thể chia Shamir cho `x` sau khi tài khoản đã chạy | Chỉ khi chủ **vẫn còn** `x`. Mất rồi thì không chia được nữa. Quyết định t-of-n là **quyết định lúc tạo tài khoản**, không sửa được sau | §07.10 |

---

### 07.1. `ICustodyProvider` — tập thao tác

Interface sống ở service `confidential-signer`, **không** trong addon. Addon Odoo chỉ giữ metadata và gọi qua mTLS. Thuần Python, không `import odoo`, test được ngoài Odoo.

```python
# /home/dockers/odoo19/confidential-signer/custody/base.py
from typing import Protocol

PROTOCOL_VERSION = "custody/1"   # bump khi doi chu ky bat ky ham nao; client tu choi neu lech

class ICustodyProvider(Protocol):
    kind: str            # hsm | kms | mpc | tee_saas | enclave | custodial | on_device | smart_account
    caps: frozenset[str] # tap thao tac thuc su lam duoc; gate moi dispatch
    policy_bundle_id: str    # hash cua SigningPolicy dang hieu luc, ky boi governance

    # --- NHOM A: uy quyen duoc cho signer tu xa (khoa khong bao gio roi boundary) ---
    def create_account(self, tenant: str, purpose: str, scheme: str) -> "AccountHandle": ...
    def public_key(self, h) -> bytes: ...
    def sign_digest_secp256k1(self, h, digest32: bytes, idem: str) -> tuple[int, bytes, bytes]: ...
    def sign_digest_ed25519(self, h, msg: bytes, idem: str) -> bytes: ...
    def sign_raw_tx(self, h, unsigned_payload: bytes, caip2: str, idem: str) -> bytes: ...
    def attest(self, h, nonce32: bytes) -> "Attestation": ...
    def rotate_auth(self, h, new_scheme: str, new_material_hash: bytes) -> "RotationTicket": ...

    # --- NHOM B: hat nhan phu thuoc x. KHONG uy quyen duoc cho HSM/KMS/MPC SaaS,
    #     NHUNG uy quyen duoc cho enclave hoac threshold shard (xem §07.2b) ---
    def zk_nonce_commit(self, h, bases: list[bytes], ctx32: bytes) -> "NonceCommitment": ...
    def zk_mul_by_x(self, h, points: list[bytes], ctx32: bytes) -> list[bytes]: ...
    def zk_response(self, h, nonce_id: str, challenge: bytes) -> bytes: ...
    def sign_schnorr_bn254(self, h, digest32: bytes) -> bytes: ...
    def elgamal_decrypt(self, h, C: bytes, D: bytes, onchain_witness: "ChainWitness") -> int: ...

    # --- NHOM B': prover day du. Chi enclave / on_device / custodial ---
    def zether_prove_transfer(self, h, stmt: "TransferStatement", wit: "TransferWitness") -> bytes: ...
    def zether_prove_withdraw(self, h, stmt, wit) -> bytes: ...
    def zether_prove_migrate(self, h, from_addr: bytes, to_pk: bytes, wit) -> bytes: ...

    # --- NHOM C: vong doi. Moi ham o day deu la thao tac dac quyen (xem duoi) ---
    def wrap_export(self, h, kek_ref: str, quorum: "QuorumTicket") -> bytes: ...
    def import_wrapped(self, tenant: str, blob: bytes, kek_ref: str) -> "AccountHandle": ...
    def destroy(self, h, reason: str, zero_balance_proof: bytes | None) -> None: ...
```

Bốn thay đổi so với bản nháp trước, mỗi cái vì một lý do cụ thể:

**(a) `idem` bắt buộc trên mọi thao tác ký.** Bản nháp trước không có, và hậu quả là một lỗi tiền thật: signer timeout ở giây thứ 3, Odoo retry, HSM ký lần thứ hai. Nếu digest giống hệt thì hai chữ ký ECDSA khác nhau (k ngẫu nhiên) nhưng cùng hợp lệ cho **cùng một nonce** → hai raw tx cạnh tranh; nếu digest khác nhau vì đã lease nonce mới (§06.1) thì hai giao dịch **cùng được mine**. Quy tắc: `idem = H(tenant || signer_ref || digest32 || purpose)`; signer giữ cache 24 h `idem → signature` và trả lại **đúng chữ ký cũ**, không ký lại. Đây là điều kiện để retry an toàn, và không có nó thì toàn bộ §06.2 (replace stuck tx) là một máy in giao dịch trùng.

**(b) `attest(h, nonce32)` nhận nonce.** Không có nonce thì attestation replay được: kẻ tấn công dựng một signer giả, phát lại một attestation document thật đã chụp trước đó. Nonce do **Odoo sinh** (`secrets.token_bytes(32)`), lưu vào record, và attestation trả về phải chứa đúng nonce đó trong `user_data`. Đây là chỗ giả định #3 ở §07.0b bị đóng lại.

**(c) `elgamal_decrypt` nhận `ChainWitness`.** Xem giả định #8. Signer **phải** từ chối giải mã một `(C, D)` không chứng minh được là trạng thái thật trên chain của chính `h`. `ChainWitness` cụ thể: `(chain_id, token_addr, block_number, storage_proof)` — một Merkle-Patricia proof của slot `balances[schnorrAddress]` tại `block_number`, verify bằng state root mà signer lấy từ *nhiều* RPC (§06.7 lớp 2). Rẻ hơn: signer tự đọc `getEncryptedBalance` / `getPendingBalance` từ 2 RPC độc lập và so khớp `(C, D)`; đủ tốt cho MVP, ghi rõ nó tin RPC. **Không có lớp này thì signer là một ECDH oracle trên `x`, cho bất kỳ ai gọi được nó.**

**(d) `wrap_export` nhận `QuorumTicket`.** Ticket là một object ký bởi ≥2 governance key, có `expiry ≤ 15 phút`, `signer_ref` cụ thể, `reason`, và một `ceremony_id`. Signer verify chữ ký **bằng public key đã nhúng trong policy bundle**, không bằng thứ gì Odoo gửi lên. Rate limit cứng: tối đa 1 export/signer_ref/90 ngày, vượt là từ chối cả khi ticket hợp lệ.

`caps` là hợp đồng thật, không phải trang trí. Dispatcher **fail-closed** ở cả hai đầu:

```python
class CustodyUnsupported(Exception): ...

def call(provider: ICustodyProvider, op: str, *a, **kw):
    if op not in provider.caps:
        raise CustodyUnsupported(f"{provider.kind} khong lam duoc {op}")
    return getattr(provider, op)(*a, **kw)
```

Điều này để tránh đúng một lỗi: một deployment cấu hình `conf_custody = 'kms'`, mọi thứ xanh cho tới khi ai đó bấm "chuyển tiền bảo mật" lần đầu trên production. `caps` khiến nó gãy **lúc validate cấu hình**, không phải lúc chuyển tiền. Phía Odoo cũng kiểm tra `caps_csv` trước khi cho `state = 'active'`, nhưng bản Odoo chỉ là cache — signer là nguồn thẩm quyền và kiểm lại lần nữa.

Ma trận `caps` tối thiểu theo `kind` (một deployment khai khác đi là một lỗi cấu hình, không phải một biến thể):

| `kind` | A: sign_* | `zk_mul_by_x` / `zk_response` | `elgamal_decrypt` | `zether_prove_*` | `wrap_export` |
|---|---|---|---|---|---|
| `hsm` (PKCS#11) | ✔ | ✘ | ✘ | ✘ | ✔ (chỉ KEK, không phải `x`) |
| `kms` | ✔ | ✘ | ✘ | ✘ | ✘ |
| `mpc` (Fireblocks/Fordefi) | ✔ | ✘ | ✘ | ✘ | ✔ (theo cơ chế nhà cung cấp) |
| `tee_saas` (Turnkey) | ✔ | ✘ (trừ khi vendor mở custom code) | ✘ | ✘ | ✔ (export bundle) |
| `enclave` (tự vận hành) | ✔ | ✔ | ✔ | ✔ | ✔ |
| `custodial` | ✔ | ✔ | ✔ | ✔ | ✔ |
| `on_device` | ✔ | ✔ | ✔ | ✔ | ✔ (chỉ về phía người dùng) |
| `smart_account` | ✔ (qua WebAuthn) | ✘ | ✘ | ✘ | ✘ |

Đọc bảng theo chiều dọc cột `zether_prove_*` là đọc được toàn bộ §07.2: **ba `kind` làm được, năm không.** Và đọc cột `zk_mul_by_x` là đọc được §07.2b: cùng ba `kind` đó, nhưng với TCB nhỏ hơn một bậc.

---

### 07.1b. Signer là một service, không phải một hàm: độ trễ, lỗi, và tại sao Odoo không được gọi đồng bộ

Bản nháp trước vẽ `endpoint_url` rồi đi tiếp. Đây là phần thiếu.

**Ngân sách độ trễ (Gnosis, MPC SaaS, không batch — lấy từ §06.6):**

```
policy + allowlist (trong signer)      2 ms
sim (2 RPC round-trip)               120 ms
lease nonce (Redis Lua)                1 ms
mTLS handshake (nếu không keep-alive) 40 ms   <-- phải keep-alive, nếu không cộng vào mọi call
sign (MPC SaaS)                      800 ms   <-- 76% ngân sách
serialize + broadcast                 80 ms
```

**Một HTTP worker Odoo bị chiếm 800 ms cho mỗi lần ký.** Với cấu hình mặc định 4–8 worker, 6–20 request đồng thời là cạn pool và **toàn bộ Odoo đứng** — kể cả các user không đụng gì tới blockchain. Đây không phải rủi ro lý thuyết, đây là chế độ hỏng mặc định.

Quy tắc bắt buộc:

> **Không có lời gọi signer nào được thực hiện trong ngữ cảnh HTTP request của Odoo.** Mọi thứ đi qua một hàng đợi: `blockchain.signing.request` (draft → queued → in_flight → signed / failed / expired), do một worker riêng (`ir.cron` mỗi phút, hoặc tốt hơn là một tiến trình `odoo shell` chuyên dụng đọc từ Redis) tiêu thụ. UI trả về ngay với trạng thái `queued`.

Ngoại lệ duy nhất được phép gọi đồng bộ: `attest()` và `/caps` (probe), vì chúng do admin bấm tay, có timeout 5 s, và không nằm trên đường tiền.

**Mô hình lỗi phải phân loại, vì mỗi loại xử khác nhau:**

| Loại lỗi | Ví dụ | Retry? | Hành động |
|---|---|---|---|
| `TRANSIENT` | timeout mạng, 503, MPC quorum tạm thiếu | Có, exponential backoff, **cùng `idem`** | Giữ `in_flight`, tối đa 5 lần / 10 phút |
| `POLICY_DENIED` | `to` ngoài allowlist, vượt trần giờ | **Không** | `failed`, tạo `blockchain.security.event` mức `warning`, thông báo ops |
| `FORBIDDEN` | `signer_ref` ngoài tenant | **Không** | `failed`, `security.event` mức **`critical`**, page ngay. Đây là dấu hiệu compromise, không phải bug cấu hình |
| `UNSUPPORTED` | `caps` không có op | Không | `failed`, và **đặt provider về `state='disabled'`** — cấu hình đã sai từ trước, đừng để nó thất bại tiếp 10.000 lần |
| `ATTESTATION_STALE` | PCR đổi, doc hết hạn | Không tự động | Chặn mọi thao tác nhóm B của provider đó cho tới khi re-probe thành công |
| `KEY_LOST` | HSM trả `CKR_OBJECT_HANDLE_INVALID` | Không | `blockchain.custody.key.state = 'lost'`, chạy runbook §07.10 |

**Signer down thì hệ thống làm gì?** Trả lời cụ thể, theo `key_role`:

- `relay`: hàng đợi dồn lại, `blockchain.relayer.account.runway_hours` tụt. Ở dưới 1 h thì §06.4 breaker chặn lớp ≤ R3. Chấp nhận được.
- `treasury` / `admin`: không có gì gấp, chờ.
- `zether_enc` cho `on_device`: **không ảnh hưởng** — prover chạy trên máy người dùng, signer không nằm trên đường đi. Đây là một lý do vận hành nữa để ưu tiên `on_device`.
- `zether_enc` cho `custodial` / `enclave`: **toàn bộ luồng confidential dừng**. Phải có N ≥ 2 enclave instance sau một load balancer, và mỗi instance có attestation riêng đã được KMS key policy chấp nhận (cùng PCR0 → cùng policy, không cần sửa gì).

**Xác thực hai chiều.** mTLS: Odoo trình client cert (một cert / một company / một môi trường), signer trình server cert. Odoo **phải** pin server cert hoặc CA riêng — không dùng CA hệ thống, vì mục tiêu là chống một signer giả trong cùng VPC. Cert xoay 90 ngày (§07.9).

---

### 07.2. Ranh giới không thể ủy quyền

Vấn đề gốc, phát biểu chính xác: **HSM là một signing oracle, không phải một máy tính đa dụng.** Nó nhận một digest, trả một chữ ký, trên một đường cong nằm trong firmware đã được chứng nhận. Zether cần chạy **hàng nghìn phép nhân vô hướng trên BN254 G1 cộng một transcript keccak** với các witness bí mật. Đó không phải là ký; đó là một chương trình.

Nhưng phát biểu "không ủy quyền được" của bản nháp trước quá thô. Phát biểu đúng có ba tầng:

> Không ủy quyền được **cho một signing oracle**. Ủy quyền được **cho một computing oracle** (enclave). Và phần thực sự phụ thuộc `x` bé đến mức ủy quyền được **cho một threshold protocol qua mạng**.

| Thao tác | Cần gì | Có phải "ký" không | Signing oracle (HSM/KMS/MPC SaaS) | Computing oracle (enclave) | Threshold qua mạng |
|---|---|---|---|---|---|
| `sign_digest_secp256k1` | ECDSA secp256k1 | có | **Được** | Được | Được (MPC) |
| `sign_raw_tx` (EVM/Cosmos/Stellar) | như trên, khác serialize | có | **Được** | Được | Được |
| `sign_digest_ed25519` (TON/SUI/Hedera) | EdDSA ed25519 | có | **Được** | Được | Được |
| `sign_schnorr_bn254` (`SELF_SCHNORR`) | 1 scalar mult G1 + nonce chống lặp | gần như | **Không** — không HSM nào có BN254 | Được | **Được** (FROST-BN254) |
| `zk_mul_by_x(P)` | 1 scalar mult G1 trên điểm **công khai** | không, nhưng cùng nguyên thủy | **Không** (xem ghi chú ECDH) | Được | **Được** (mỗi share trả $P^{x_i}$) |
| `zk_response(k, c)` | $s = k + c \cdot x \bmod r$ — **một phép cộng-nhân trong $\mathbb{F}_r$** | không | **Không** — không HSM nào expose phép này | Được | **Được** (Lagrange trong hàm mũ) |
| `elgamal_decrypt` | `C · D^{-x}` rồi BSGS | **không** | **Không** | Được | **Được** (threshold ElGamal, §07.4) |
| `zether_prove_transfer` | ~2,000–6,000 scalar mult, MSM, Fiat-Shamir | **không** | **Không, về nguyên tắc** | Được | Về lý thuyết được, chi phí 10^3–10^5× — **không** |

**Ghi chú kỹ thuật đáng lưu: `CKM_ECDH1_DERIVE` *là* phép nhân vô hướng.** PKCS#11 `C_DeriveKey` với `CKM_ECDH1_DERIVE` và KDF `CKD_NULL` trả về tọa độ $x$ của $x_{priv} \cdot P$. Về lý thuyết đây chính là nguyên thủy cần cho `zk_mul_by_x` và `elgamal_decrypt`. Bốn lý do nó vẫn không dùng được:

1. HSM chỉ chấp nhận `CKA_EC_PARAMS` là các đường cong đã biết (P-256/384/521, secp256k1, Ed25519, Brainpool). **BN254 không có OID nào trong danh mục nào.** Luna và Utimaco cho phép truyền `ECParameters` dạng explicit prime field, nhưng firmware vẫn từ chối tham số ngoài whitelist đã chứng nhận trên đa số model, và **AWS CloudHSM/GCP Cloud HSM/Azure Managed HSM đều không expose đường dẫn đó** — họ chỉ mở một tập curve cố định.
2. Trả về mất dấu $y$ (chỉ có tọa độ $x$). Khôi phục được bằng cách thử cả hai nghiệm, nhưng phải làm ngoài HSM — tức là đã ra ngoài boundary. Với `zk_mul_by_x` điều này còn tệ hơn: dấu sai làm proof invalid *im lặng*, không phải lỗi rõ ràng.
3. **`zk_response` không có nguyên thủy PKCS#11 nào tương ứng.** Không HSM thương mại nào cho bạn tính $k + c \cdot x$ trong $\mathbb{F}_r$ của một curve tùy ý và trả ra scalar. Đây là rào cản *cứng hơn* rào cản curve: kể cả một HSM có BN254 cũng không đủ, phải là HSM **lập trình được**.
4. Ngay cả khi (1)–(3) giải quyết xong, một `transferConfidential` với prover đầy đủ cần hàng nghìn lần derive → hàng nghìn round-trip PKCS#11. Ở 1 ms/op đó là **vài giây tới vài chục giây cho một giao dịch**, so với 30–50 ms native (§3.8). *Nhưng*: với kiến trúc tách prover ở §07.2b, số round-trip tụt xuống **2–3**, và lập luận (4) biến mất hoàn toàn. Chỉ còn (1)–(3).

**Con đường giữ HSM có ý nghĩa thật (khuyến nghị chốt):**

```
HSM FIPS 140-3 L3
  └── giu KEK (AES-256, non-extractable, CKM_AES_KEY_WRAP_KWP)   <-- FIPS boundary that
        └── wrap/unwrap blob chua x  (HSM khong bao gio "hieu" x, chi coi la 32 byte opaque)
              └── unwrap CHI trong enclave da attest
                    └── x song trong RAM enclave, hat nhan sigma chay tai do (§07.2b)
```

Trên AWS đây không phải sơ đồ trên giấy — nó có cơ chế cưỡng chế cụ thể: `kms:Decrypt` với tham số `Recipient` (Nitro Enclave attestation document, COSE_Sign1 ký bởi Nitro PKI), và key policy điều kiện trên `kms:RecipientAttestation:PCR0` / `kms:RecipientAttestation:ImageSha384`. Kết quả: **chỉ đúng một image enclave, đo bằng hash, mới unwrap được `x`.** Một sysadmin có quyền root trên EC2 host cũng không đọc được — KMS trả về `CiphertextForRecipient`, mã hóa dưới public key sinh **trong** enclave, host chỉ thấy blob. Trên GCP: Confidential Space + Workload Identity Pool với attribute condition trên `submods.container.image_digest`, và **bắt buộc kèm** `submods.confidential_space.support_attributes` chứa `STABLE` (nếu không, một image debug cũng qua được).

Bốn chi tiết vận hành Nitro mà bản nháp trước bỏ qua và chúng là công việc thật trong plan:

| Chi tiết | Con số | Hệ quả |
|---|---|---|
| Enclave **không có network stack**, chỉ vsock | — | Phải viết `vsock-proxy` hai chiều ở parent. Nó là **toàn bộ I/O của enclave** ⇒ nó là thành phần bảo mật, phải nằm trong scope audit, và phải whitelist đích (chỉ KMS endpoint + RPC endpoint) |
| Enclave **không có RTC** | — | `deadline`/`expiry` không được enforce chỉ bằng đồng hồ enclave. Dùng **block number** làm đồng hồ (lấy qua vsock, cross-check 2 RPC), hoặc nhúng thời gian vào chính attestation nonce do Odoo sinh |
| Attestation document | ~5 KB, verify ~1–3 ms | Nhưng KMS chỉ chấp nhận doc mới (thực tế ~5 phút). Re-attest mỗi 60 s là an toàn |
| Cold start | ~10–30 s (allocate memory + boot) | Không scale theo request. Giữ pool enclave warm, N ≥ 2 |
| Bộ nhớ phải pre-allocate | Đề xuất 2 GB/enclave | Bảng BSGS 2–4 MB (§07.4b) + prover working set ~50 MB/luồng ⇒ 2 GB đủ cho ~16 luồng song song |

**Nhưng phải nói thẳng, thành văn, trong hợp đồng khách hàng:** ở mô hình này **`x` không nằm trong biên FIPS 140-3 Level 3 tại thời điểm sử dụng.** Nó nằm trong RAM một enclave. Nitro Enclave, Intel TDX và AMD SEV-SNP **không** có chứng nhận FIPS 140-x Level 3 cho vai trò này (module crypto *bên trong* có thể dùng một thư viện đã validate, nhưng biên vật lý thì không). Nếu một hợp đồng hoặc một cơ quan quản lý yêu cầu FIPS L3 cho khóa mã hóa số dư, câu trả lời trung thực là: **yêu cầu đó hôm nay không thỏa mãn được với Zether**, và lựa chọn là (a) đổi câu chữ yêu cầu thành "khóa có quyền **chi tiêu** trong FIPS L3; khóa **giải mã** trong confidential computing có attestation", (b) bỏ Zether, hoặc (c) đầu tư Functionality Module (§07.3).

---

### 07.2b. Tách prover: hạt nhân phụ thuộc `x` chỉ bằng 300 dòng

Đây là phần bản nháp trước không có, và nó thay đổi mọi kết luận downstream. Lập luận bắt đầu từ một quan sát về chính giao thức Zether:

**Bulletproofs range proof không dùng `x`.** Witness của range proof là các *giá trị* ($v$, $b - v$) và các blinding factor. Khóa bí mật không xuất hiện trong mạch. Cái dùng `x` chỉ là phần **sigma protocol**:

| Thành phần proof | Witness | Khối lượng | Có `x`? |
|---|---|---|---|
| Range proof trên $v$ ($n_v = 32$) | $v$, blinding | ~600–900 scalar mult + MSM | **Không** |
| Range proof trên $b - v$ ($n_b = 64$) | $b$, $v$, blinding | ~1,200–1,800 scalar mult + MSM | **Không** |
| Chứng minh biết $x$: $y = g^x$ | $x$ | 1 mult (commit) + 1 response | **Có** |
| Chứng minh số dư đúng: $C_L \cdot C_R^{-x} = g^{b}$ | $x$, $b$ | 1 mult trên $C_R$ + 1 response chung nonce | **Có** |
| Equality $v$ dưới $y_{sender}$ và $y_{receiver}$ (và $y_{audit}$) | $v$, $s$ | 3–4 mult trên điểm công khai | **Không** (dùng $s$, không dùng $x$) |
| Fiat-Shamir transcript | — | keccak | Không |

Tổng phần có `x`: **2 phép nhân vô hướng trên điểm công khai ($g$ và $C_R$) với cùng một nonce $k$, và 1 scalar response $s_x = k + c \cdot x \bmod r$.** Cộng thêm nếu `authScheme = SELF_SCHNORR` thì digest §2.4.2 được nhúng vào challenge và không cần chữ ký thứ hai — vẫn cùng một $s_x$.

Từ đó rút ra một interface bé xíu, đặt tên `IZetherKeyOracle`, và **nó là thứ duy nhất cần được bảo vệ bằng phần cứng**:

```rust
// smartcontracts/crates/zether-core/src/key_oracle.rs
// Toan bo be mat phu thuoc x. Muc tieu: < 300 dong, khong I/O, khong allocation dong.
pub trait ZetherKeyOracle {
    /// Tra ve y = g^x. Goi mot lan luc dang ky.
    fn public_key(&self) -> G1Affine;

    /// Commit: sinh nonce k (deterministic, xem duoi), tra ve R_i = bases[i]^k.
    /// `ctx` rang buoc nonce voi mot statement cu the.
    fn nonce_commit(&self, bases: &[G1Affine], ctx: &[u8; 32]) -> (NonceId, Vec<G1Affine>);

    /// Nhan vo huong voi x tren diem CONG KHAI (ECDH-like). Dung cho C_R^x.
    fn mul_by_x(&self, points: &[G1Affine], ctx: &[u8; 32]) -> Vec<G1Affine>;

    /// s = k + c*x mod r. Tieu thu NonceId; goi lan hai voi cung NonceId PHAI panic.
    fn response(&self, id: NonceId, c: Fr) -> Fr;
}
```

**Hệ quả 1 — TCB của enclave co lại một bậc.** Thay vì đưa cả prover Bulletproofs (arkworks / một crate vài chục nghìn dòng, phụ thuộc transitively hàng trăm crate) vào enclave, chỉ đưa `ZetherKeyOracle` vào. Enclave image chứa: BN254 field/group arithmetic + HKDF + oracle. Ước tính **< 5,000 dòng kể cả crypto backend**, không I/O ngoài vsock, không parser. Đó là thứ audit được trong một tuần. Prover Bulletproofs chạy ở host / trên máy người dùng, nơi nó nhanh và nơi nó **không giữ bí mật nào về khóa** (nó giữ bí mật về *số tiền*, đó là một biên khác).

**Hệ quả 2 — hai biên bảo mật, không phải một.** Đây là điều bản nháp trước gộp làm một và vì thế kết luận sai:

| Biên | Bảo vệ cái gì | Compromise nghĩa là gì | Ai phải giữ |
|---|---|---|---|
| **Biên khóa** (`x`) | Quyền chi tiêu số dư bảo mật + quyền giải mã *mọi* số dư lịch sử | Mất tiền, mất toàn bộ bí mật quá khứ | `ZetherKeyOracle`: enclave / thiết bị / threshold shard |
| **Biên giá trị** ($v$, $b$, blinding) | Số tiền của **một** giao dịch đang dựng | Lộ đúng giao dịch đó | Prover: bất cứ đâu chủ tài khoản chấp nhận |

Với `on_device` hai biên trùng nhau (đều trên máy người dùng) — không mất gì. Với B2B, tách hai biên cho phép: **prover chạy trên máy chủ của distributor** (họ vốn đã biết số tiền của chính họ), còn **`x` chia 2-of-3 giữa thiết bị finance officer, enclave của platform, và một share offline**. Platform không bao giờ thấy `x` đầy đủ, không tự chi tiêu được, nhưng cùng với share offline thì khôi phục được. Đó chính xác là mô hình custody mà một doanh nghiệp muốn, và bản nháp trước tuyên bố nó không tồn tại.

**Hệ quả 3 — threshold hóa `x` là một giao thức chuẩn, không phải nghiên cứu.** Chia $x = \sum \lambda_i x_i$ (Shamir trên $\mathbb{F}_r$ của BN254, Lagrange trong hàm mũ):

```
Setup (mot lan, luc tao tai khoan):
    Pedersen DKG t-of-n tren BN254 G1  ->  y = g^x, share x_i, verification key y_i = g^{x_i}
    (khong ai tung thay x; hoac dealer-based roi dealer zeroize, don gian hon, rui ro cao hon)

mul_by_x(P):                       response(c):
    moi ben i: S_i = P^{x_i}           moi ben i: s_i = k_i + c*x_i
    + Chaum-Pedersen: log_g(y_i) = log_P(S_i)
    gop: P^x = prod S_i^{lambda_i}     gop: s = sum lambda_i * s_i
```

Chi phí: **2 vòng mạng, ~100 byte/vòng/bên, 2 scalar mult/bên (~100 µs)**. Với 3 bên trong cùng datacenter: **< 5 ms**. Với một bên là điện thoại của finance officer qua Internet: **~200–400 ms** — chấp nhận được cho B2B settlement (không ai đứng đợi ở quầy).

Ba cái bẫy phải viết vào code, không phải vào tài liệu:

1. **Tái sử dụng nonce $k$ với hai challenge khác nhau làm lộ `x` ngay lập tức**: $x = (s_1 - s_2)/(c_1 - c_2)$. Bắt buộc: $k_i = \text{HKDF}(x_i, \text{ctx}, \text{counter})$ với `counter` là **bộ đếm bền** (NVRAM của HSM, hoặc một record Postgres có `SELECT ... FOR UPDATE`), **không** phải biến RAM. Và `response(id, c)` phải tiêu thụ `NonceId`: gọi lần hai với cùng id → panic, không trả về. Test negative bắt buộc (§07.13).
2. **Lagrange coefficient tính trong $\mathbb{F}_r$** (scalar field, $r \approx 2^{254}$), không phải $\mathbb{F}_p$ (base field). Đây là lỗi kinh điển và nó tạo ra proof invalid im lặng, không phải crash.
3. **Chaum-Pedersen là bắt buộc trên mọi share**, không tùy chọn. Không có nó, một bên độc hại trả $S_i$ sai làm proof invalid mà không ai biết bên nào sai — và trong chế độ khôi phục (§07.10) nó làm bạn tin một số dư sai.

**Hệ quả 4 — một HSM lập trình được bây giờ đủ.** Trước đây phải nhét cả Bulletproofs vào FM (§07.3, không khả thi). Bây giờ FM chỉ cần hiện thực `ZetherKeyOracle`: BN254 scalar mult + một phép $k + cx$ trong $\mathbb{F}_r$. Đó là vài trăm dòng C, chạy 2–3 lần/giao dịch thay vì hàng nghìn. **Ước tính thời gian: 2–10 ms/giao dịch trên CPU nhúng của HSM**, so với 1–5 giây cho prover đầy đủ. Khuyến nghị vẫn là **không làm FM ở giai đoạn này** (lý do chứng nhận, §07.3), nhưng lý do bây giờ là *quy trình*, không còn là *kỹ thuật*. Nếu một khách hàng regulated trả tiền, con đường tồn tại và nó ngắn hơn nhiều so với đánh giá của bản nháp trước.

**Việc phải làm trong plan, cụ thể:**

```
smartcontracts/crates/zether-core/src/key_oracle.rs      # trait + impl in-process (on_device)
smartcontracts/crates/zether-oracle-enclave/             # impl vsock; image Nitro/TDX
smartcontracts/crates/zether-oracle-threshold/           # impl t-of-n, Chaum-Pedersen
smartcontracts/crates/zether-core/tests/oracle_equiv.rs  # ba impl PHAI cho cung proof
```

Test `oracle_equiv.rs` là điều kiện tiên quyết: ba hiện thực khác nhau của cùng một oracle mà không có differential test là công thức chuẩn tạo ra một lỗ hổng im lặng — cùng lý do §3.8 kết luận 3 bắt prover và verifier phải share test vector.

---

### 07.3. HSM FIPS 140-3 Level 3

**Sửa thuật ngữ trước.** Bản nháp trước và `blockchain.md` đều viết "FIPS 140-2 Level 3". Từ **2026-09-21**, toàn bộ chứng nhận FIPS 140-2 chuyển sang CMVP Historical List. Sản phẩm không biến mất, nhưng một điều khoản hợp đồng trỏ tới "FIPS 140-2 validated" sẽ trỏ tới danh mục lịch sử và một auditor có quyền bắt bẻ. Ngôn ngữ phải dùng: **"FIPS 140-3 Level 3, hoặc chứng nhận CMVP đương thời tương đương"**. Ước lượng độ tin cậy: cao về sự tồn tại của mốc chuyển đổi; cần một lần đối chiếu cuối với CMVP trước khi ký hợp đồng.

| Sản phẩm | Nền phần cứng | Đường cong ký | BN254 | Lập trình được bên trong | Chi phí |
|---|---|---|---|---|---|
| AWS CloudHSM `hsm2m.medium` | **Marvell LiquidSecurity**, không phải Luna (**bản nháp trước ghi sai**) | P-256/384/521, secp256k1, Ed25519 | không | **không** — AWS không mở FM | ~$1.45–1.81/hr/HSM. AWS khuyến nghị **3 HSM / 2 AZ** cho production ⇒ **~$3,200–4,000/tháng** (ước tính, us-east-1) |
| AWS KMS asymmetric (HSM protection) | Marvell | `ECC_NIST_P256/384/521`, `ECC_SECG_P256K1` | không | không | $1/key/tháng + **$0.15/10k request** cho ECC asymmetric (**bản nháp trước ghi $0.03/10k — đó là giá symmetric**). Quota `Sign` ~500 req/s/region |
| GCP Cloud KMS / Cloud HSM | Marvell | `EC_SIGN_P256`, `EC_SIGN_P384`, `EC_SIGN_SECP256K1` | không | không | ~$1–2.50/key/tháng + $0.03–0.15/10k op. Không expose raw point mult |
| Azure Managed HSM | Marvell | P-256, P-384, P-521, **P-256K (secp256k1)** | không | không | ~$3.20/hr/pool (pool = 3 HSM) ⇒ **~$2,300/tháng** |
| Thales Luna Network HSM + **Functionality Module** | Thales | tuỳ FM | **có thể** | **có** (C trong biên) | ~$25–40k/unit capex + support ~20%/năm. Xem dưới |
| Utimaco CryptoServer CP5 + **CryptoServer SDK** | Utimaco | tuỳ firmware tuỳ biến | **có thể** | **có** | Cùng bậc capex |
| Securosys Primus + **TSB / custom** | Securosys | tuỳ | **có thể** | **có** | Cùng bậc; đáng hỏi vì họ có sẵn nhiều primitive blockchain |

**Functionality Module: đánh giá lại sau §07.2b, nhưng kết luận không đổi ở giai đoạn này.**

Trước đây lý do từ chối là kỹ thuật (prover quá nặng cho CPU nhúng). Sau §07.2b lý do đó không còn — `ZetherKeyOracle` chạy 2–10 ms trong FM. Lý do từ chối bây giờ thuần quy trình, và nó vẫn đủ:

- (a) FM tự biên soạn **làm mất hiệu lực chứng nhận CMVP của firmware** cho tới khi tái chứng nhận (chu kỳ thường 12–24 tháng, chi phí sáu chữ số USD). Nghịch lý: bạn phá FIPS để đạt FIPS.
- (b) Phải tự viết và tự audit toàn bộ số học BN254 trong một môi trường gần như không debug được, không có sanitizer, không có fuzzing hạ tầng.
- (c) Lead time thiết bị 3–6 tháng (§2.4.4 đã ghi), không tương thích với bất kỳ mốc MVP nào.

**Khuyến nghị: không làm. Ghi vào danh mục "chỉ mở lại nếu một khách hàng regulated trả tiền cho việc tái chứng nhận", và ghi kèm ước tính mới: ~4–8 tuần phát triển cho `ZetherKeyOracle` trong FM, thay vì 6+ tháng cho prover đầy đủ.** Con số này thay đổi câu trả lời cho câu hỏi "bao lâu và bao nhiêu", nên nó phải nằm trong tài liệu.

**HSM vẫn bắt buộc, cho đúng bốn vai trò:**

1. Ký `authKey` cho `treasury`, `MINTER`/`BURNER` (§1.11), và admin nâng cấp/pause. ECDSA secp256k1 thuần — HSM làm hoàn hảo. **Kèm điều kiện của §12.5: HSM không biết nó đang ký cái gì.** Một `SigningPolicyService` parse RLP và enforce `to`-allowlist + trần `value` + trần tích lũy theo giờ phải nằm **cùng phía với signer**, không nằm trong Odoo. Không có lớp này thì HSM chỉ là một cách đặt tên khác cho "khóa nóng".
2. Giữ KEK bọc `x` (§07.2).
3. Giữ khóa gốc của Shamir escrow (§07.8).
4. Ký `QuorumTicket` cho `wrap_export` (§07.1 điểm d) và ký `policy_bundle` (§07.9).

**Chủ quyền dữ liệu: cloud HSM có thể bị loại ở Việt Nam, và đó là một quyết định phải làm sớm.**

AWS và GCP **không có region tại Việt Nam** (tính đến cutoff). Dùng CloudHSM/KMS/Nitro nghĩa là `x` (dạng wrapped) và mọi metadata giao dịch rời khỏi lãnh thổ, kích hoạt nghĩa vụ hồ sơ chuyển dữ liệu xuyên biên giới theo NĐ 13/2023/NĐ-CP (§13.7.2). So sánh cứng:

| Phương án | Capex | Opex/tháng | Dữ liệu ở đâu | Attestation | Thời gian triển khai |
|---|---|---|---|---|---|
| AWS CloudHSM (3 HSM) + Nitro Enclave | 0 | ~$3,200–4,000 + EC2 | Singapore/Tokyo | **Có sẵn, cưỡng chế bởi KMS** | 2–4 tuần |
| GCP Cloud HSM + Confidential Space | 0 | ~$2,000–3,000 | Singapore/Đài Loan | Có sẵn (WIP + attribute condition) | 3–5 tuần |
| **On-prem: 2× Thales/Utimaco/Securosys + host AMD SEV-SNP tự vận hành, DC tại VN** | **~$60–90k** (2 HSM + server) | ~$1,000 (colo, điện, support) | **Việt Nam** | **Phải tự xây**: SEV-SNP attestation report + một verifier service + chuỗi tin cậy tới AMD KDS | **3–6 tháng** (lead time thiết bị + tự xây attestation) |

Điểm hòa vốn thuần chi phí: **~24–30 tháng**. Nhưng quyết định không phải về chi phí — nó về việc một khách hàng regulated có chấp nhận `x` (wrapped) nằm ở Singapore hay không. **Phải hỏi trước khi viết `custody/enclave.py`**, vì hai đường có API attestation khác hẳn nhau và không dùng chung code được (§07.14 câu 6).

Nếu chọn tự vận hành, đề xuất **AMD SEV-SNP thay vì Intel TDX**: SEV-SNP có sẵn trên EPYC Milan/Genoa phổ thông tại các nhà cung cấp server ở VN, chuỗi attestation (VCEK từ AMD KDS) đơn giản hơn, và không cần một Provisioning Certification Service như SGX/TDX.

---

### 07.4. MPC và threshold

**Về `auth_custody`, MPC là lựa chọn tốt.** Fireblocks (MPC-CMP) và Fordefi ký được secp256k1 và ed25519 với policy engine, quorum người duyệt, audit log — đúng thứ treasury cần. Nút cổ chai đã định lượng ở §06.6: **5–30 sign/s, p50 300 ms – 3 s**. Với batch executor (§06.6 mục 1) điều đó chấp nhận được; không có batch thì không.

**Sửa một phân loại sai của bản nháp trước: Turnkey không phải MPC.** Turnkey là **TEE-based key management** — khóa sống trong enclave, policy enforce trong enclave, không phải threshold signing giữa nhiều bên. Điều này quan trọng vì hai lý do trái ngược nhau:

- Nó **loại** Turnkey khỏi các lập luận về "không có single point of trust" mà MPC được chọn vì nó.
- Nó **đưa** Turnkey (và Evervault, Anjuna, Fortanix Confidential Computing Manager) vào danh sách các nhà cung cấp *có thể* về nguyên tắc chạy `ZetherKeyOracle` của §07.2b, vì hạ tầng của họ vốn đã là confidential compute. Câu hỏi mua hàng cụ thể phải hỏi: **"chúng tôi có được deploy code Rust của mình vào enclave của các anh, với attestation ràng buộc image digest, không?"** Với Turnkey hôm nay câu trả lời là không (họ chỉ chạy signer của họ); với Fortanix CCM và Anjuna là có (họ chạy container tùy ý). Đưa vào bảng so sánh mua hàng, đừng loại từ đầu.

**Về `conf_custody` dạng "MPC SaaS giữ toàn bộ khóa Zether": không.** Catalogue đường cong của Fireblocks/Fordefi là secp256k1 / ed25519 / P-256. Không ai hỗ trợ BN254 G1, và kể cả nếu có, giao thức của họ là *threshold signing*, không phải *threshold proving*. Không tồn tại sản phẩm thương mại nào chạy một mạch Bulletproofs dưới MPC. (Về lý thuyết làm được — MPC-in-the-head, hoặc garbled circuit cho prover — nhưng chi phí là bậc độ lớn 10^3–10^5 lần so với prove tại chỗ. Không phải một lựa chọn kỹ thuật.)

**Nhưng threshold cho `conf_custody` thì có, và §07.2b đã chỉ ra tại sao: cái cần threshold hóa không phải prover, mà là oracle 300 dòng.** Ta tự chạy nó, không mua. Hai chỗ dùng, cùng một machinery:

#### 07.4a. Khóa auditor `y_audit` — threshold ElGamal

Nếu `y_audit` là một khóa đơn, thì một compliance officer đọc được **toàn bộ số dư và giá bán của mọi distributor**. Đó là một điểm tập trung tệ hơn cả vấn đề nó giải quyết (§2.7.6 đã nêu rủi ro; đây là hiện thực).

```
Setup: Pedersen DKG tren BN254 G1, t-of-n (de xuat 3-of-5:
       2 noi bo compliance, 1 internal audit, 1 external auditor, 1 niem phong offline)
       -> y_audit = g^x_audit, moi ben giu share x_i, cong bo verification key y_i = g^{x_i}
       -> KHONG ai tung thay x_audit

Giai ma mot C_audit = g^v · y_audit^s, D = g^s:
   moi ben i:  S_i = D^{x_i}                                   (1 scalar mult, ~50 us)
               + Chaum-Pedersen proof log_g(y_i) = log_D(S_i)  (2 scalar mult)
   gop:        D^{x_audit} = prod S_i^{lambda_i}               (Lagrange trong ham mu, mod r)
               g^v = C_audit / D^{x_audit}
               v   = BSGS(g^v)                                 <-- xem §07.4b cho con so that
```

Pedersen DKG cần ba thứ mà bản nháp trước không nói và chúng là công việc thật: (i) một **broadcast channel** tin cậy giữa n bên — thực dụng nhất là một Odoo record với chữ ký của từng bên, không phải một cuộc gọi Zoom; (ii) một **complaint round** để loại bên gửi share sai, nếu không một dealer độc hại làm hỏng DKG mà không ai biết; (iii) **Feldman VSS commitment** công bố để mỗi bên tự verify share nhận được. Bỏ (ii) hoặc (iii) là DKG chỉ trên danh nghĩa.

Chi phí một lần giải mã với 3 share: **~150 µs tính toán + 2 round-trip mạng** (thực tế 5–50 ms tùy vị trí các bên), cộng chi phí BSGS ở §07.4b. Chaum-Pedersen là bắt buộc — không có nó, một share sai lệch làm hỏng kết quả mà không ai phát hiện, và bạn sẽ tin một con số sai trong một báo cáo AML.

#### 07.4b. `elgamal_decrypt`: số thật của BSGS, và tại sao bản nháp trước sai một bậc

Đây là chỗ sửa quan trọng nhất về mặt số. Bản nháp trước viết: *"bảng 2^16 điểm = 65,536 × 32 B ≈ 2 MB, ~2^16 phép cộng điểm ⇒ vài ms"*. Con số cuối sai vì bỏ qua chi phí đắt nhất: **để tra một điểm trong hash table bạn phải chuẩn hóa nó về affine, và mỗi lần chuẩn hóa là một phép nghịch đảo modular** (~3–6 µs trên BN254 $\mathbb{F}_p$), đắt hơn phép cộng điểm cả bậc.

Tính lại, $N = 2^{32}$ (`range_bits_value = 32`, `scale_exponent = 2`), $m = \lceil\sqrt N\rceil = 2^{16}$:

| Hạng mục | x86-64 native | ARM64 tầm trung | WASM+SIMD (browser) |
|---|---|---|---|
| Bảng baby step, bộ nhớ (key 16 B truncated + u32, hashmap overhead ~1.6×) | **~2.1 MB** | như trên | như trên |
| Bảng, nếu key là full x-coord 32 B | ~3.8 MB | như trên | như trên |
| Dựng bảng (một lần / tiến trình): 2^16 add + batch inversion | **~40–60 ms** | ~200–350 ms | ~150–250 ms |
| Tìm, kỳ vọng 2^15 giant step, **có** batch inversion (chunk 256) | **~20 ms** | **~82 ms** | ~60–90 ms |
| Tìm, worst case 2^16 giant step | ~40 ms | ~165 ms | ~120–180 ms |
| Tìm, **không** batch inversion (hiện thực ngây thơ) | ~175 ms | ~700 ms – 1.2 s | ~500 ms – 1 s |

Ba hệ quả:

1. **Batch inversion (Montgomery trick) là bắt buộc, không phải tối ưu.** Nó là hệ số 5–10×. Ghi vào spec của `zether-core`, và ghi vào test hiệu năng.
2. **Giải mã vượt ngưỡng 300 ms của §3.8 mục 2 trên WASM và trên ARM khi worst case.** Nên `elgamal_decrypt` cũng phải chạy background thread + progress UI, y hệt prove. Bản nháp trước chỉ áp quy tắc đó cho prove.
3. **Kiểm chứng số 6 của bản nháp trước ("nếu > 50 ms thì bảng tham số §3.9 phải sửa") sẽ luôn fail trên ARM.** Nó là một ngưỡng đặt sai. Ngưỡng đúng: **p95 ≤ 200 ms trên ARM64 tầm trung với bảng đã warm**, và bảng phải được dựng một lần lúc khởi động app, không phải mỗi lần giải mã.

**Còn số dư 64-bit thì sao? Bản nháp trước nói "hàng giờ tới hàng ngày". Sai theo một cách khác: BSGS ở $2^{64}$ là bất khả thi vì bộ nhớ, không phải vì thời gian.** $m = 2^{32}$ entry × 20 B = **86 GB**. Không có bảng đó. Cái dùng được là **Pollard kangaroo** (lambda method), $O(1)$ bộ nhớ, ~$2\sqrt N = 2^{33}$ group op:

```
2^33 x ~0.4 us  =  ~57 phut  (1 core x86)
                =  ~8 phut   (8 core, kangaroo song song hoa gan tuyen tinh)
                =  ~6 gio    (1 core ARM64 tam trung)
```

**Nhưng đừng bao giờ chạy nó.** Có một đường nhanh hơn hàng trăm lần mà bản nháp trước không nêu:

> **Khôi phục số dư = replay delta từ indexer, không phải brute force số dư.**
>
> Mỗi `ConfidentialTransfer` mang $(C_{transfer}, D)$ mã hóa dưới $y$ của người nhận, và mỗi lần chi mang $(C_{debit}, D)$. Mỗi delta $< 2^{32}$ ⇒ giải mã được trong 20–170 ms. Với một tài khoản có 10.000 giao dịch trọn đời:
>
> ```
> 10.000 x 82 ms  = ~14 phut  (ARM64)
> 10.000 x 20 ms  = ~3,3 phut (x86)
> ```
>
> Và có thể song song hóa hoàn toàn (mỗi delta độc lập). Điều kiện: indexer (§11) giữ đủ event lịch sử của tài khoản — nó vốn phải giữ.

Từ đó, sửa một phát biểu của bản nháp trước từ "cache" thành "trạng thái":

> Ví **phải** giữ một `plaintext_balance` chạy song song, cập nhật sau mỗi transfer và mỗi `rollOver`. Nó **không phải cache** — nó là một phần trạng thái tài khoản, và mất nó là một sự cố cần 3–15 phút để phục hồi, không phải một lần miss cache. Nó phải nằm trong phạm vi backup của `ICustodyProvider` và trong phạm vi export dữ liệu của người dùng. **Mất `plaintext_balance` mà còn `x`: phục hồi được trong vài phút. Mất `x`: xem §07.10.**

Một điều nữa phải nói vì nó là ràng buộc thiết kế: `plaintext_balance` chỉ đúng nếu ví thấy **mọi** giao dịch đến. Zether cho phép bất kỳ ai chuyển tiền tới bạn mà không báo trước. Nên ví phải đối chiếu định kỳ: `BSGS(getEncryptedBalance)` không làm được (64-bit), nhưng **`plaintext_balance_expected` so với tổng delta từ indexer** thì làm được, và lệch thì replay lại từ đầu. Cron client-side, mỗi lần mở app.

---

### 07.5. Custodial — và hệ quả giấy phép

Custodial là mô hình **dễ nhất về kỹ thuật và đắt nhất về pháp lý**. Kỹ thuật: platform giữ `x` trong enclave, ký và prove thay người dùng; UX hoàn hảo, khôi phục được bằng reset mật khẩu; nó là mô hình duy nhất khiến payment mode M1 (`payment.provider` in-house) và M2 (crypto acquirer) của §09 chạy trơn tru, vì bạn kiểm soát cả hai đầu giao dịch.

**Hai biến thể, và chúng khác nhau về pháp lý nhiều hơn về kỹ thuật** (bản nháp trước không phân biệt; §12.5 có nhắc omnibus nhưng không đối chiếu):

| | Omnibus | Segregated |
|---|---|---|
| On-chain | **Một** `schnorrAddress` cho cả nghìn khách | Một `schnorrAddress`/khách |
| Sổ phụ | Postgres của Odoo **là nguồn sự thật duy nhất** về ai sở hữu bao nhiêu | Chain là nguồn sự thật |
| Chi phí | 1 lần `register()` (~105k gas), gộp transfer nội bộ = 0 gas | ~105k gas/khách + transfer thật |
| Rủi ro | Một lỗi ghi sổ = mất tiền của khách, không có bằng chứng on-chain đối chứng | Không có |
| `x` | 1 khóa. Mất = mất **tất cả** | n khóa. Mất 1 = mất 1 |
| Pháp lý | Rõ ràng là **nhận giữ tiền của người khác** | Vẫn là custody nếu platform giữ `x` |
| AML | Chain chỉ thấy platform ⇔ platform. **Phá đúng thứ Zether tồn tại để bảo toàn** (§10.5.1: lộ danh tính người gửi/nhận) | Giữ nguyên đồ thị |

**Kết luận: omnibus bị cấm cho mọi luồng có Zether.** Không phải vì pháp lý mà vì nó mâu thuẫn trực tiếp với triết lý anti-mixer của chính note: nếu mọi giao dịch đều là "platform → platform", đồ thị chuyển tiền on-chain trở nên vô nghĩa với auditor, và toàn bộ lập luận "tuân thủ 100% AML/KYC" ở §10.5.1 sụp. Omnibus chỉ được phép cho loyalty point closed-loop không dùng Zether.

Pháp lý: **nắm khóa của tiền người khác là hoạt động custody.** Bảng dưới là bản đồ rủi ro, **không phải tư vấn pháp lý — phải có luật sư xác nhận trước khi bật `custody_mode = 'custodial'` ở bất kỳ deployment nào.**

| Địa bàn | Điều kích hoạt nghĩa vụ | Hệ quả |
|---|---|---|
| Việt Nam | NĐ 52/2024/NĐ-CP (thanh toán không dùng tiền mặt): ví điện tử / trung gian thanh toán cần giấy phép NHNN, **vốn điều lệ tối thiểu 50 tỷ VND**, thời gian thực tế thường **> 12 tháng** (§13.4). Luật Công nghiệp công nghệ số (hiệu lực 2026-01-01) lần đầu định danh "tài sản mã hóa"; NQ 05/2025/NQ-CP mở thí điểm thị trường tài sản mã hóa | Khung còn đang hình thành. **Giữ khóa của tiền có thể quy đổi ra VND cho bên thứ ba là vùng rủi ro cao.** Đường nhanh hơn: hợp tác với đơn vị đã có giấy phép ⇒ payment mode M2 (§09) |
| EU | MiCA Art. 75 — "custody and administration of crypto-assets on behalf of clients" là dịch vụ CASP phải xin phép | Vốn tối thiểu, tách biệt tài sản khách, **trách nhiệm bồi thường khi mất khóa** |
| Singapore | PSA — digital payment token service | Giấy phép MAS |
| US | Money transmitter cấp bang + NYDFS BitLicense | Từng bang một |

Bài kiểm tra bốn câu của §13.4, áp thẳng vào cấu hình custody:

1. Token có neo mệnh giá VND không? 2. Có pre-fund 1:1 bằng tiền thật không? 3. Người giữ có quyền đòi lại tiền mặt không? 4. Bên thứ ba (không phải issuer) có chấp nhận nó không?

**Bốn "có" = tiền điện tử = cần giấy phép**, bất kể chain nào. Ba "có" trở xuống thì còn chỗ lập luận, và chỗ đó phải do luật sư lập luận.

**Đòn bẩy thiết kế quan trọng nhất, và nó thuộc về section này chứ không phải section token:** *loyalty point chỉ đổi được với chính issuer thường KHÔNG bị coi là e-money; thời điểm nó chuyển nhượng được sang bên thứ ba và quy đổi được ra tiền mặt, nó trở thành stored value.* Vì vậy:

```
blockchain.custody.provider.custodial_liability_class:
    'none'          -> khong giu khoa cua nguoi khac (on_device, smart_account)
    'closed_loop'   -> point chi doi hang cua issuer, khong transfer P2P, khong cash-out
                       => custodial cho phep, mac dinh
    'open_loop'     -> transfer P2P hoac cash-out duoc
                       => custodial BI CHAN CUNG o validate, tru khi
                          license_ref co gia tri tren blockchain.custody.provider
```

Chặn ở tầng cấu hình, không ở tầng review. Một record `license_ref` rỗng phải làm `write()` raise, không phải làm một dòng cảnh báo trong log.

**Ba nghĩa vụ vận hành đi kèm custodial mà bản nháp trước không liệt kê**, và chúng tốn tiền thật:

| Nghĩa vụ | Nội dung cụ thể | Chi phí ước tính |
|---|---|---|
| Tách biệt tài sản khách | Tài sản đảm bảo của `ZetherToken` phải nằm ở địa chỉ/tài khoản riêng, không trộn với treasury của platform. Đối soát hằng ngày `sum(so phu) == on-chain reserve` | Một cron + một báo cáo; rẻ về code, đắt về kỷ luật |
| Proof of reserves | Công bố định kỳ tổng dự trữ vs tổng nghĩa vụ. Với Zether, tổng nghĩa vụ **không cộng được từ chain** (số dư mã hóa) ⇒ phải công bố từ sổ phụ + `C_audit` do auditor xác nhận | Chi phí auditor bên ngoài, ~vài chục triệu VND/lần |
| Bảo hiểm / bồi thường | MiCA Art. 75 bắt bồi thường khi mất khóa. Bảo hiểm crypto custody có tồn tại nhưng phí cao và loại trừ nhiều | Chưa định lượng được; **một câu hỏi cho §07.14** |

---

### 07.6. Non-custodial on-device

Đây là mô hình mặc định cho loyalty và end-user payment, và là mô hình **duy nhất** không phát sinh nghĩa vụ custody.

Trở ngại cụ thể: **Secure Enclave (iOS) chỉ làm P-256; Android StrongBox làm RSA / EC P-256 / AES / HMAC (một số thiết bị KeyMint 2+ thêm Curve25519). Không cái nào biết BN254.** Nên `x` không thể *sống trong* secure element. Mẫu chuẩn, dùng secure element làm cổng chứ không làm kho:

```
seed (32 B, sinh boi CSPRNG cua HDH: SecRandomCopyBytes / java.security.SecureRandom)
  -> x = HKDF-SHA256(seed, salt = "", info = "zether/bn254/v1") mod r   (reject-sample)
  -> seed duoc boc: AES-GCM duoi khoa AES-256 trong StrongBox / Secure Enclave,
     khoa do dat setUserAuthenticationRequired(true) + setIsStrongBoxBacked(true)
     + setUnlockedDeviceRequired(true)
  -> ciphertext cua seed nam trong app storage; mo khoa can biometric
  -> x chi ton tai trong bo nho Rust core (§3.8), zeroize sau moi lan dung
```

**Sửa một chi tiết của bản nháp trước:** nó ghi `info="zether/bn254/v1/<schnorrAddress>"`. Đó là một vòng lặp: `schnorrAddress = keccak256(x_coord(y), y_coord(y))` mà `y = g^x`, nên `x` phụ thuộc `schnorrAddress` phụ thuộc `x`. Không tính được. Info phải là một chuỗi hằng cộng một chỉ số tài khoản: `info = "zether/bn254/v1/" || u32_be(account_index)`.

**Và một cảnh báo phải viết to: chuỗi `info` là bất biến vĩnh viễn của hệ thống.** Đổi nó ở version 2 nghĩa là mọi `x` dẫn ra khác, mọi `schnorrAddress` khác, và mọi số dư cũ nằm ở địa chỉ mà app mới không tìm ra. Nếu buộc phải đổi, app phải dẫn xuất **cả hai** và quét cả hai địa chỉ. Ghi vào `zether-core` như một hằng có comment `DO NOT CHANGE`.

Bốn yêu cầu kỹ thuật không được bỏ:

1. `x` và `seed` phải bị **zeroize** (`zeroize::Zeroizing`) sau mỗi thao tác. Rust core chịu trách nhiệm, không phải lớp Kotlin/Swift — vì `ByteArray` của JVM và `Data` của Swift đều bị GC/copy mà bạn không kiểm soát.
2. **Không bao giờ log `x`, `seed`, `k`, `r`, `s`, hay witness.** Một dòng `Log.d` trong build debug lọt vào release là toàn bộ bí mật thương mại của một distributor. Bổ sung ba bề mặt rò rỉ mà bản nháp trước không nêu: **screenshot** (đặt `FLAG_SECURE` trên màn hình có số dư), **accessibility service** (đọc được text trên màn hình), và **crash reporter** (Crashlytics/Sentry gửi thanh ghi và đôi khi cả stack memory — phải tắt native crash upload cho tiến trình có `x`, hoặc scrub).
3. Prove chạy trên background thread (§3.8 kết luận 2); UI phải có progress trên mọi thứ > 300 ms. Áp cả cho `elgamal_decrypt` (§07.4b).
4. **Backup là một luồng UX bắt buộc, không phải một mục trong Settings.** Người dùng không được nhận đồng token đầu tiên trước khi hoàn tất backup. Ba lựa chọn, xếp theo tỉ lệ mất khóa quan sát được:

| Cơ chế backup | Tỉ lệ mất ước tính/năm | Nghĩa vụ custody | Ghi chú |
|---|---|---|---|
| Passkey PRF đồng bộ iCloud/Google (§07.7) | **~0.05–0.2%** | Không | Mất khi mất cả tài khoản Apple/Google — hiếm, và có đường khôi phục của họ |
| SLIP-0039 / BIP-39 người dùng tự chép | ~0.5–2% | Không | Người dùng bán lẻ VN gần như chắc chắn không chép, hoặc chụp màn hình |
| Chỉ device-bound, không backup | **~3–8%** | Không | Mất máy = mất tiền. **Không được phép cho luồng có giá trị** |
| `x` chia Shamir 2-of-3, một share ở platform (§07.10) | ~0.01% | **Có** — platform là một bên có thể chi tiêu cùng bên thứ hai | Đây là đánh đổi trung tâm của §07.10 |

Cơ sở ước tính: quy tắc ngành cho ví tự quản; các ước lượng công khai về BTC mất vĩnh viễn (~20% tích lũy sau ~14 năm) nằm trong khoảng này nhưng phân bố lệch mạnh về những năm đầu và về ví device-bound không backup.

**Trách nhiệm phải nói với khách hàng bằng văn bản:** ở non-custodial 1-of-1, mất điện thoại và mất backup = mất tiền, và platform **không có** cách nào giúp. Đây là nội dung điều khoản hợp đồng, không phải mục FAQ. Câu chữ đề xuất đã có ở §2.7.5.

---

### 07.7. Smart account và passkey

Ánh xạ đã có: `authScheme = SMART_ACCOUNT_1271`, `verifier` trỏ tới một `ISignatureVerifier` (§2.4), và phía EIP-1776 dùng `SignatureChecker.isValidSignatureNow` chứ không `ecrecover` trần (§04.4).

**Chi phí verify WebAuthn P-256 on-chain — phải probe, không giả định** (đúng nguyên tắc §2.5):

| Đường | Gas | Khả dụng |
|---|---|---|
| RIP-7212 precompile `P256VERIFY` tại `0x100` | **3,450** | Polygon PoS (Napoli, 2024); OP Stack nhận qua Isthmus (2025) ⇒ **Celo (đã là OP Stack L2) rất có thể có**. **Gnosis: chưa — phải probe** |
| EIP-7951 (cùng precompile, đưa lên L1) | 3,450 | Dự kiến theo hard fork của Ethereum; nếu vào L1 thì Gnosis thường theo sau trong 1–2 quý. **Ước lượng, phải theo dõi** |
| Solidity `daimo-eth/p256-verifier` | ~**330,000** | Mọi EVM |
| `smoo.th` SCL / FreshCryptoLib (window + precompute) | ~**160,000–200,000** | Mọi EVM |

Trên Gnosis với gas 2 gwei (con số §06.4 dùng, không phải 1 gwei như bản nháp trước) và xDAI $1: 330k gas × 2 gwei = **0.00066 xDAI ≈ $0.00066/giao dịch** — không đáng kể so với 2.0–2.5M gas của chính giao dịch Zether (§06.4). **Passkey chiếm ~13–16% gas của một tx Zether với verifier Solidity, ~0.15% với precompile.** Đó là con số quyết định: dùng được ngay hôm nay bằng Solidity verifier, và probe RIP-7212 lúc onboarding chain, ghi vào `blockchain.chain.has_p256_precompile`, y hệt cách §2.5 xử lý `has_bls12381`.

**Cái bẫy thật của passkey, và nó là bẫy custody chứ không phải bẫy gas: khóa passkey không xuất được.** WebAuthn chỉ trả assertion. Nó **không thể** là `encKey` của Zether. Lời giải cụ thể là **WebAuthn PRF extension** (ánh xạ xuống CTAP2.1 `hmac-secret`):

```
prf_output = navigator.credentials.get({
    publicKey: { ..., extensions: { prf: { eval: { first: salt } } } }
}).getClientExtensionResults().prf.results.first     // 32 bytes
kek        = HKDF-SHA256(prf_output, info = "zether/kek/v1")
x          = AES-GCM-decrypt(kek, blob_x)     // blob_x luu tren server, server KHONG giai ma duoc
```

Sáu lưu ý bắt buộc (bản nháp trước có ba; ba cái sau là những cái làm hỏng ngày ra mắt):

- **Không dẫn `x` trực tiếp từ `prf_output`.** Dùng nó để *mở* một `blob_x` sinh ngẫu nhiên. Lý do: nếu về sau cần thêm một credential thứ hai (điện thoại mới, laptop), bạn chỉ cần bọc lại cùng một `blob_x` dưới `kek` thứ hai. Dẫn trực tiếp thì mỗi credential ra một `x` khác nhau, tức một `schnorrAddress` khác nhau, tức tiền nằm rải rác không gộp lại được.
- Hỗ trợ PRF không đồng đều: Chrome/Android và iOS 18+/macOS 15+ với passkey đồng bộ iCloud có; một số security key và WebView cũ **không** có. Client **phải** probe `PublicKeyCredential.getClientCapabilities()` và kết quả extension, rồi fallback sang §07.6, chứ không được giả định.
- **Ít nhất hai credential được đăng ký trước khi tài khoản nhận đồng token đầu tiên.** Một credential = một điểm hỏng duy nhất, và ở đây điểm hỏng đó là không thể sửa.
- **PRF thường KHÔNG trả kết quả trong `create()`**, chỉ trong `get()`. Trên nhiều platform authenticator, `create({extensions:{prf:{}}})` chỉ *bật* PRF; muốn lấy `prf_output` phải gọi `get()` ngay sau đó. Luồng đăng ký vì thế là **create → get → derive kek → sinh `blob_x` → upload**, ba bước có thể fail độc lập. Phải là một state machine có resume, không phải một `await` thẳng.
- **PRF output gắn chặt với RP ID (domain).** Đổi domain, hay chuyển từ `app.example.vn` sang `example.vn`, là **mất toàn bộ `kek`**. Chốt RP ID **trước khi** phát hành credential đầu tiên và ghi nó vào tài liệu vận hành như một hằng bất biến, ngang hàng với chuỗi `info` của §07.6.
- **Passkey đồng bộ = bảo mật của `x` bằng bảo mật tài khoản Apple/Google của người dùng.** Đó là một đánh đổi hoàn toàn hợp lý cho loyalty, và **không chấp nhận được** cho B2B settlement. Với B2B, passkey phải là device-bound (security key vật lý, `authenticatorAttachment: "cross-platform"`, `residentKey: "required"`), và khi đó tỉ lệ mất tăng trở lại ⇒ bắt buộc Shamir (§07.10).

Một lựa chọn thay thế đáng biết: **WebAuthn `largeBlob` extension** cho phép lưu ~1 KB **trong chính authenticator**, tức `blob_x` không cần server. Hỗ trợ còn hẹp hơn PRF, và nó không đồng bộ giữa các thiết bị. Không chọn làm đường chính, nhưng là đường hay cho một security key vật lý dùng làm share thứ ba trong Shamir.

Social recovery chỉ áp cho `authKey`: guardian n-of-m + timelock 7 ngày (`RECOVERY_DELAY`, §2.7.5) + event công khai. **Nó không khôi phục `x`.** Trộn lẫn hai thứ này trong tài liệu bán hàng là cách chắc chắn nhất để hứa một điều không tồn tại.

---

### 07.8. Key ceremony

Áp dụng cho: KEK trong HSM, khóa treasury/minter/admin, share DKG của `y_audit`, và **share Shamir của `x` cho tài khoản B2B**. **Không** áp dụng cho `x` 1-of-1 của người dùng cuối (sinh trên máy họ).

| Bước | Nội dung | Bằng chứng lưu lại |
|---|---|---|
| 1 | Máy air-gapped, boot từ image có hash đã công bố trước | Hash image, ảnh chụp màn hình boot |
| 2 | Dual control: hai người thao tác, không ai một mình chạm bàn phím | Danh sách ký tên |
| 3 | Chứng kiến: internal audit + một bên độc lập | Biên bản có chữ ký |
| 4 | Sinh khóa **trong** HSM (`CKA_EXTRACTABLE = false`, `CKA_SENSITIVE = true`) hoặc DKG cho `y_audit` / Shamir cho `x` | `CKA_ID`, public key, ảnh chụp |
| 5 | Chia share: **SLIP-0039** (Shamir có checksum + passphrase) 2-of-3 theo §2.7.5 | Vị trí từng share |
| 6 | Share vào túi niêm phong chống giả mạo, ba két ở ba địa điểm; một share do đại lý escrow giữ theo văn bản pháp lý | Số seri túi niêm phong |
| 7 | Quay video toàn phiên, không cắt | Hash file video |
| 8 | Hash toàn bộ hồ sơ phiên, **neo on-chain** | `KeyCeremonyAnchor(bytes32 ceremonyHash, uint64 ts)` hoặc Hedera HCS |
| 9 | Diễn tập khôi phục **trong vòng 30 ngày**, trên khóa test, trước khi khóa production nhận đồng đầu tiên | Biên bản diễn tập, có bấm giờ |

Bước 9 là bước hay bị bỏ nhất và là bước duy nhất chứng minh tám bước kia có tác dụng. Một backup chưa từng được restore không phải là một backup.

**Một ceremony thứ hai mà bản nháp trước hoàn toàn bỏ qua: ceremony của enclave image.**

Toàn bộ §07.2 dựa trên "chỉ đúng một image, đo bằng PCR0, unwrap được `x`". Điều đó chỉ có nghĩa nếu **PCR0 được sinh ra một cách tái lập được và được công bố trước khi nó được đưa vào key policy**. Nếu không, "attestation" chỉ chứng minh rằng *một image nào đó mà ops build hôm qua* đang chạy — không chứng minh gì về nội dung của nó.

| Bước | Nội dung | Sản phẩm |
|---|---|---|
| E1 | Build **tái lập được** (reproducible): Docker image pin theo digest, `cargo --locked`, `SOURCE_DATE_EPOCH`, không network trong build | `Dockerfile` + `Cargo.lock` commit |
| E2 | Hai người build độc lập trên hai máy, so PCR0 | Hai giá trị PCR0 phải trùng từng bit |
| E3 | Công bố PCR0 + commit hash + hash của `.eif` trong một record `blockchain.enclave.image` và **neo on-chain** cùng cơ chế bước 8 | `image_pcr0`, `git_commit`, `anchor_tx_hash` |
| E4 | Cập nhật KMS key policy / WIP attribute condition sang PCR0 mới, **giữ PCR0 cũ song song** trong thời gian chuyển | Diff của key policy, có approve |
| E5 | Sau khi mọi instance đã chạy image mới, **gỡ PCR0 cũ** khỏi policy | Diff thứ hai |

Bước E5 hay bị bỏ, và bỏ nó nghĩa là mọi image cũ (kể cả cái có lỗ hổng vừa được vá) vẫn unwrap được `x` mãi mãi. Nó là một cron nhắc, không phải một ý định tốt.

**Vấn đề quy mô mà §2.7.5 đã nêu và §07 phải trả lời: 200 distributor × 4–6 địa chỉ = ~800–1.200 bộ Shamir. Không quản lý thủ công được.**

Câu trả lời cụ thể, ba tầng:

| Tầng | Ai | Ceremony | Số lượng |
|---|---|---|---|
| Tầng 0: KEK, treasury, `y_audit` | Platform | **Ceremony đầy đủ 9 bước, có người, có video** | ~5–10 lần/năm |
| Tầng 1: `x` của pháp nhân B2B (brand, distributor lớn) | Khách hàng, platform hỗ trợ | Ceremony rút gọn: bước 2, 4, 5, 9. Không video, có biên bản | ~50/năm |
| Tầng 2: `x` của outlet / người dùng cuối | Tự động, trên thiết bị | **Không ceremony.** Backup = passkey PRF hoặc SLIP-0039 hiển thị trong app, có bước xác nhận nhập lại 2 từ ngẫu nhiên | ~10.000 |

Ceremony thủ công **chỉ** ở tầng 0 và 1. Nếu một thiết kế đòi ceremony ở tầng 2, thiết kế đó sai.

---

### 07.9. Xoay khóa

| Khóa | Xoay tại chỗ được? | Cơ chế | Chi phí |
|---|---|---|---|
| `authKey` (mọi scheme) | **có** | `requestAuthRotation` → `ROTATION_DELAY` 24h → `executeAuthRotation`, `authEpoch++` (§2.7.1) | ~50k gas |
| Relayer EOA | có | Tạo EOA mới, `state = 'draining'` trên cái cũ, đợi inflight rỗng, chuyển native balance | 1 tx |
| KEK trong HSM | có | Sinh KEK mới, unwrap-in-enclave rồi rewrap toàn bộ blob, giữ KEK cũ 90 ngày rồi destroy | O(số tài khoản) |
| Passkey credential | có | Đăng ký credential mới, bọc lại `blob_x` dưới `kek` mới, thu hồi credential cũ | 0 gas |
| **`encKey` / `x`** | **KHÔNG** | Bắt buộc `migrateAccount(fromAddr, toAddr, ...)` với sigma proof đẳng thức dưới $y_{old}$ và $y_{new}$, **cần chữ ký của cả hai** (§2.7.2). Liên kết old → new **công khai** | **~24,300 gas** (§2.7.2 đã sửa con số 12,150 của bản nháp cũ) |
| Share DKG của `y_audit` | có, không đổi `y_audit` | Proactive secret sharing: các bên tái chia sẻ share mà khóa tổng không đổi. Không cần đụng chain | 0 gas |
| **Share Shamir của `x`** | **có, không đổi `x`** | Cùng cơ chế proactive resharing. Đây là lý do kỹ thuật để chọn Shamir chứ không phải "3 bản copy": copy không thu hồi được, share thì có | 0 gas |
| **mTLS client cert của Odoo** | có | Cert mới cấp trước 14 ngày, signer chấp nhận cả hai trong cửa sổ chuyển, gỡ cert cũ sau | 0 |
| **`policy_bundle`** | có | Bundle mới ký bởi ≥2 governance key, có `version` tăng đơn điệu. Signer **từ chối** bundle có version thấp hơn bundle đang chạy (chống rollback) | 0 |
| **Enclave image (PCR0)** | có | Ceremony E1–E5 ở §07.8 | 0 |

Lịch đề xuất: `authKey` treasury 12 tháng hoặc **ngay khi có người rời tổ chức**; relayer EOA hàng giờ nếu là session key trong enclave (§06.6); KEK 12 tháng; mTLS cert 90 ngày; policy bundle theo nhu cầu; enclave image theo mỗi bản vá bảo mật. `y_audit` **không xoay**, chỉ proactive-resharing 6 tháng — vì xoay `y_audit` làm mọi `C_audit` cũ **không giải mã được nữa**, tức là phá đúng cơ chế phục hồi mà nó tồn tại để cung cấp. (§2.7.6 đề xuất xoay 12 tháng và giữ khóa cũ theo lịch lưu hồ sơ; hai cách đều được, nhưng phải chọn một và ghi vào runbook — **giữ khóa cũ mãi mãi** thì rủi ro tập trung không giảm, còn **hủy khóa cũ** thì mất khả năng audit lịch sử. Đề xuất chốt: proactive resharing 6 tháng, **không** xoay khóa; xoay chỉ khi nghi ngờ compromise, và khi đó khóa cũ được lưu ở tầng 0 ceremony.)

**Một thứ tự nguy hiểm phải viết thành runbook**, vì làm ngược là mất quyền truy cập vào toàn bộ `x`:

```
SAI:  cap nhat KMS key policy sang PCR0 moi  ->  deploy enclave image moi
      (giua hai buoc, enclave dang chay KHONG unwrap duoc nua -> toan bo luong confidential chet)

DUNG: 1. Them PCR0 moi vao key policy, GIU ca PCR0 cu
      2. Deploy image moi song song, verify no unwrap duoc
      3. Chuyen traffic
      4. Drain + tat instance cu
      5. Go PCR0 cu khoi key policy      <-- buoc E5, khong duoc quen
```

**Runbook compromise, theo `key_role`** — bản nháp trước không có, và 15 phút đầu là 15 phút quyết định:

| Key bị lộ | Phút 0–5 | Phút 5–60 | Sau đó |
|---|---|---|---|
| Relayer EOA | Đặt `state='draining'`, dừng lease nonce mới (§06.1), sweep số dư về treasury | Tạo EOA mới, kiểm log xem có tx lạ nào không | Điều tra đường lộ; xoay enclave image nếu nghi TCB |
| `authKey` treasury / admin | **`pause()` contract** (§12.10) | `requestAuthRotation` + báo guardian; nếu kẻ tấn công đã xoay trước, dùng `forceAuthRotation` (14 ngày, không veto được) | Ceremony mới, tầng 0 |
| `x` của một tài khoản (nghi lộ) | Không có `pause` cho một tài khoản Zether. `selfFreeze()` chặn outflow (§2.7.3) | `migrateAccount` sang `x` mới **ngay** — mỗi phút chậm là số dư còn ở khóa cũ | Giả định toàn bộ lịch sử số dư của tài khoản đó đã lộ. Không hoàn tác được |
| `x_audit` (một share) | Loại share đó khỏi quorum | Proactive resharing với n−1 bên | Nếu ≥ t share lộ: **toàn bộ lịch sử `C_audit` coi như public**. Thông báo mọi tenant |
| KEK | Không có gì lộ ngay (blob vẫn AES-KWP) | Sinh KEK mới, rewrap toàn bộ | Điều tra HSM audit log |
| mTLS client key của Odoo | Thu hồi cert ở signer | Kiểm `blockchain.security.event` xem có request lạ | Cấp cert mới; nếu Odoo bị compromise thì đây là vấn đề nhỏ nhất |

---

### 07.10. Mất khóa: số dư Zether không giải mã được nữa

Đây là phần khó nhất và cũng là phần `blockchain.md` hoàn toàn không nhắc tới.

**Sự thật kỹ thuật:** số dư nằm dưới dạng $(C, D) = (g^b \cdot y^r, g^r)$. Không có `x`, không tồn tại thuật toán nào lấy lại $b$ hay chi tiêu nó. Không admin key nào cứu được. Đó là thuộc tính của giao thức, không phải khiếm khuyết của hiện thực.

**Nhưng bản nháp trước rút ra kết luận quá mạnh từ sự thật đó.** "Public chain: không có khôi phục. Chấm hết" chỉ đúng khi `x` là 1-of-1. Bảng đầy đủ, và cột quyết định là **cấu hình chọn lúc tạo tài khoản**:

| Cấu hình `x` | Mất 1 thành phần | Mất `plaintext_balance` | Khôi phục *số liệu* | Khôi phục *quyền chi tiêu* | Nghĩa vụ custody |
|---|---|---|---|---|---|
| 1-of-1 on-device, không backup | **Mất hết** | Replay delta, 3–15 phút | Chỉ qua `C_audit` (§07.4a) | **Không bao giờ** | Không |
| 1-of-1 + SLIP-0039 2-of-3 do người dùng giữ cả 3 | Khôi phục nếu còn 2 | như trên | Có | Có | Không |
| 1-of-1 + PRF passkey đồng bộ | Khôi phục qua tài khoản Apple/Google | như trên | Có | Có | Không |
| **Shamir/DKG 2-of-3, platform giữ 1 share** | Mất 1 share = không mất gì | như trên | Có | **Có, trên mọi chain, không cần `recoverAccount`** | **CÓ** — platform + escrow chi tiêu được |
| **DKG 3-of-5** (B2B) | Mất 2 share vẫn ổn | như trên | Có | Có | Có, nếu platform là 1 trong 5 |

**Đây là đánh đổi trung tâm của cả section, và nó phải được nói bằng một câu:** khả năng khôi phục và tính non-custodial là **cùng một trục, ngược chiều nhau**. Không có cấu hình nào vừa "platform không thể chi tiêu tiền của bạn" vừa "platform khôi phục được tiền cho bạn". Mọi lời chào hàng nói ngược lại là sai.

Và một ràng buộc thời điểm không hiển nhiên: **quyết định t-of-n phải làm lúc tạo tài khoản.** Sau đó, chia share chỉ làm được nếu chủ **vẫn còn** `x` (họ phải chạy DKG resharing với các bên mới). Mất rồi thì không chia được nữa. Nên UI tạo tài khoản phải hỏi, và mặc định phải đúng theo money flow (bảng §07.0).

**Hệ quả kế toán, và nó nghiêm trọng hơn hệ quả với người mất khóa:** `ZetherToken` là wrapper giữ N token ERC-20 làm tài sản đảm bảo. Khi một tài khoản mất khóa, tổng các số dư *giải mã được* tụt xuống dưới N. Khoản chênh lệch là **dust không thể thu hồi, tăng đơn điệu theo thời gian**, và invariant total-supply ở §1.9 vẫn *đúng về sổ sách* trong khi *sai về kinh tế*. Phải có một dòng trong sổ cho nó.

Định lượng (ước tính, cơ sở ghi rõ):

```
Co so: ti le mat khoa tu quan cua nguoi dung cuoi, theo bang §07.6:
       passkey dong bo   0.05 - 0.2 %/nam
       SLIP-39 tu chep   0.5  - 2   %/nam
       device-bound      3    - 8   %/nam

10.000 outlet, non-custodial, so du loyalty trung binh 500.000 VND
  passkey dong bo:  5 - 20 tai khoan/nam  ->  2,5 -  10 trieu VND/nam
  SLIP-39 tu chep: 50 - 200 tai khoan/nam -> 25   - 100 trieu VND/nam
  device-bound:   300 - 800 tai khoan/nam -> 150  - 400 trieu VND/nam

Sau 5 nam, tich luy:
  passkey:      12  -   50 trieu VND
  SLIP-39:     125  -  500 trieu VND
  device-bound: 750 - 2.000 trieu VND      <-- khong chap nhan duoc
```

**Con số này một mình đủ để quyết định cơ chế backup mặc định: passkey PRF, không phải seed phrase.** Chênh lệch 10–40× dust tích lũy giữa hai lựa chọn, ở cùng một chi phí kỹ thuật. Bản nháp trước gộp cả ba vào một khoảng "0.3–1.0%/năm" và vì thế không thấy được quyết định này.

Với loyalty, dust ở mức passkey là chi phí vận hành chấp nhận được. Với B2B settlement — nơi số dư một distributor có thể là hàng tỉ đồng — **1-of-1 bị cấm**, không phải "không khuyến khích". Đó là lý do kỹ thuật thứ hai (sau §2.6) để B2B chạy trên private chain, và lý do thứ nhất để B2B dùng Shamir.

**Bốn đường xử lý, chọn theo cấu hình và chain profile:**

| Cấu hình | Cơ chế | Điều kiện |
|---|---|---|
| 1-of-1, public | **Không có khôi phục quyền chi tiêu.** Chấm hết | Phải nằm trong hợp đồng và trong onboarding UI, không chỉ trong tài liệu kỹ thuật |
| 1-of-1, public, dữ liệu | Auditor quorum giải mã chuỗi `C_audit` (§07.4a) để **biết** số dư đúng — vẫn không chi tiêu được | Cần `C_audit` bật ở mọi giao dịch của tài khoản đó |
| **t-of-n, mọi profile** | t bên còn lại chạy threshold `mul_by_x` + `response` (§07.2b) để **`migrateAccount` sang `x` mới**. Không cần hàm đặc quyền nào, không phá bất biến | Quyết định lúc tạo tài khoản. Quorum khôi phục phải **khác** quorum vận hành hằng ngày |
| **private, không có t-of-n** | `recoverAccount` có governance | Xem quy trình dưới đây |

Lưu ý đường thứ ba: nó **tốt hơn hẳn** `recoverAccount` vì nó không cần một hàm đặc quyền trong contract, chạy trên public chain, và không có ai "cấp lại tiền" — chỉ là chính chủ (theo nghĩa t-of-n) tự di chuyển tài sản. Nếu chọn được nó thì `recoverAccount` không cần tồn tại.

**`recoverAccount` trên private chain — quy trình cụ thể, không phải ý tưởng:**

```
1. Chu tai khoan nop yeu cau + bang chung danh tinh off-chain.
2. Quorum auditor t-of-n giai ma C_audit tich luy -> so du dung b*,
   kem Chaum-Pedersen proof giai ma dung cua tung share (§07.4a).
3. Governance multisig goi:
      recoverAccount(bytes32 lostAddr, bytes32 newAddr, uint256 bStar, bytes auditProof)
   Hop dong: verify auditProof voi y_audit da dang ky trong registry,
             dat status(lostAddr) = REVOKED, so du ma hoa cu bi bo di,
             mint (C, D) moi ma hoa b* duoi y_new,
             phat RecoveryExecuted(lostAddr, newAddr, ceremonyHash).
4. Timelock 30 ngay giua buoc 3 va hieu luc; event cong khai de chu that phan doi.
```

Ba ràng buộc bổ sung mà bản nháp trước bỏ:

- **`b*` phải khớp invariant.** Sau `recoverAccount`, tổng nghĩa vụ không được vượt tài sản đảm bảo. Contract phải kiểm `recoveredTotal + b* <= reserve - sum(other known)`; vì không cộng được số dư mã hóa, thực dụng là giữ một `recoveryBudget` on-chain do governance nạp, và trừ dần. Không có nó, một `b*` sai (hoặc gian lận) tạo ra token không có đảm bảo.
- **`status(lostAddr) = REVOKED` vẫn nhận được inflow** theo §2.7.3 đã sửa. Nghĩa là tiền vẫn có thể chảy vào một địa chỉ đã recover và kẹt ở đó. Phải có cảnh báo phía Odoo (`onchain_state`) trước khi gửi — lại là "quét QR không phải là đã thu tiền": UI chặn trước, không phát hiện sau.
- **Quorum governance của `recoverAccount` phải khác biệt hoàn toàn với quorum vận hành**, và ít nhất một thành viên phải ở ngoài tổ chức vận hành. Nếu không, "khôi phục" là một backdoor tự phục vụ với 30 ngày timelock.

Điều này **cố ý** phá tính bất biến để đổi lấy khả năng thu hồi, nên nó **chỉ tồn tại trên private chain**. Trên public chain, hàm này không được deploy — không phải bị vô hiệu hóa bằng cờ, mà là **không có trong bytecode**, dùng hai profile build riêng trong `smartcontracts/evm/zether/`. Một cờ runtime có thể bị bật; một hàm không tồn tại thì không.

**Hệ quả bắt buộc lên §2.7.6:** `C_audit` chuyển từ "tuỳ chọn trên loyalty" thành **bắt buộc trên mọi tài khoản có `recovery_class != 'none'`**. Chi phí đúng: **+25,300 gas/transfer** (~+11% của một tx Zether) ≈ **$0.00005 trên Gnosis @2 gwei**. Đó là giá của cơ chế khôi phục số liệu duy nhất tồn tại cho cấu hình 1-of-1. Rẻ đến mức tranh luận về nó là lãng phí thời gian — nhưng phải chốt **trước khi deploy**, vì nó thay đổi calldata và struct của contract.

---

### 07.11. Cô lập theo tenant trong Odoo multi-company

Nguyên tắc chi phối, và nó là điều dễ làm sai nhất trong cả section:

> **Odoo không bao giờ được là nguồn thẩm quyền quyết định khóa nào thuộc tenant nào.** Một lỗi record rule, một domain viết sai, một chỗ `sudo()` thừa, hay một SQL injection sẽ trở thành "ký được bằng khóa của công ty khác". Ràng buộc phải nằm **ở phía provider**, và signer service phải **tự dẫn xuất lại** đường dẫn khóa từ tenant đã xác thực bằng mTLS, rồi **từ chối** mọi `signer_ref` không nằm dưới đường dẫn đó.

```python
# confidential-signer/authz.py
import re
_REF = re.compile(r'^blockchain/[0-9a-f-]{36}/[a-z0-9_]+/[A-Za-z0-9_-]{1,64}$')

def resolve(tenant_uuid: str, signer_ref: str) -> str:
    prefix = f"blockchain/{tenant_uuid}/"
    if not _REF.match(signer_ref) or not signer_ref.startswith(prefix):
        raise CustodyForbidden("signer_ref ngoai pham vi tenant")   # audit + alert, khong chi tu choi
    return signer_ref
```

`tenant_uuid` lấy từ **client cert mTLS** (`subject.CN` hoặc một SAN URI `urn:tenant:<uuid>`), không lấy từ body request. Đây là điểm khác biệt sống còn: Odoo *nói* nó là công ty nào không quan trọng; cert *chứng minh* nó là công ty nào.

**Nhưng `tenant_uuid` phải tồn tại đã, và Odoo không có nó.** `res.company.id` là số nguyên tuần tự — company id 3 trên production và company id 3 trên một database khác là hai pháp nhân khác nhau. Cần:

```python
# models/res_company.py  (day la mo rong duy nhat ra ngoai prefix blockchain.* ,
#  va no bat buoc: khong co dinh danh on dinh thi khong co co lap tenant)
class ResCompany(models.Model):
    _inherit = 'res.company'

    blockchain_tenant_uuid = fields.Char(
        readonly=True, copy=False, index=True,
        default=lambda s: str(uuid.uuid4()),
        help='Bat bien. Duoc nhung vao signer_ref, KMS encryption context va key path. '
             'Doi no = mat quyen truy cap moi khoa cua company nay.')

    _unique_tenant_uuid = models.Constraint(
        'UNIQUE(blockchain_tenant_uuid)', 'tenant uuid phai duy nhat.')

    @api.constrains('blockchain_tenant_uuid')
    def _check_tenant_uuid_immutable(self):
        # readonly chan UI, khong chan write() qua RPC. Chan that o day.
        for rec in self:
            if not rec.blockchain_tenant_uuid:
                raise ValidationError(_("tenant uuid khong duoc rong."))
```

Bất biến là bắt buộc vì `tenant_uuid` được nhúng vào **KMS encryption context**, và encryption context là thứ *thực sự* cưỡng chế cô lập:

```python
# custody/awskms.py
kms.encrypt(
    KeyId=key_arn,
    Plaintext=x_bytes,
    EncryptionContext={
        'tenant':     tenant_uuid,     # doi -> Decrypt fail, khong phai fail-open
        'signer_ref': signer_ref,
        'role':       key_role,
    },
)
```

Encryption context được AES-GCM bind vào ciphertext. Một blob của tenant A **không giải mã được** dưới context của tenant B, kể cả khi kẻ tấn công có đủ quyền IAM gọi `Decrypt`. Đây là hàng phòng thủ mạnh hơn `resolve()` nhiều, vì nó không phụ thuộc code của ta. Dùng **cả hai**.

**Sự cố kinh điển mà bản nháp trước không nhắc: restore dump production sang staging.**

Staging thừa hưởng nguyên `blockchain_tenant_uuid`, `signer_ref`, `endpoint_url`. Một developer bấm "test ký" trên staging và ký một giao dịch **production**. Ba lớp chặn, phải có cả ba:

1. **mTLS cert khác nhau theo môi trường.** Staging có cert riêng, signer map cert → tenant → **và cả environment**. Signer từ chối cert staging trên key path production. Đây là lớp duy nhất không bypass được từ phía Odoo.
2. **`data/neutralize.sql`** — Odoo hỗ trợ neutralize database từ v16; module ship file này và nó chạy tự động khi `odoo-bin neutralize` hoặc khi restore qua công cụ có hỗ trợ:
   ```sql
   -- dms_blockchain/data/neutralize.sql
   UPDATE blockchain_custody_provider SET state = 'disabled', endpoint_url = '';
   UPDATE blockchain_custody_key      SET state = 'retired';
   UPDATE ir_cron SET active = false
    WHERE id IN (SELECT res_id FROM ir_model_data
                  WHERE module = 'dms_blockchain' AND model = 'ir.cron');
   ```
3. **Một `ir.config_parameter` `blockchain.environment`** (`prod` / `staging` / `dev`) được **gửi kèm mọi request** và signer so khớp với environment gắn vào cert. Lệch = `FORBIDDEN` + `security.event` mức critical. Lớp này bắt được cả trường hợp ai đó copy cert.

Lưu ý: neutralize là **best effort** — nó chạy khi có người gọi nó. Lớp 1 là lớp duy nhất đúng trong mọi trường hợp. Đừng đảo thứ tự ưu tiên.

| Cơ chế cô lập | Chi phí | Sức mạnh | Khi nào |
|---|---|---|---|
| AWS KMS: một key/company + key policy điều kiện `kms:EncryptionContext:tenant = <tenant_uuid>` | ~$1/key/tháng + **$0.15/10k req** (ECC asymmetric; $0.03/10k nếu chỉ dùng symmetric wrap) | Cao — cưỡng chế bởi IAM + AES-GCM AAD, không bởi code của ta | **Mặc định** |
| HashiCorp Vault Transit: path `/transit/keys/blockchain/{tenant_uuid}/*` + policy theo path | Đã có sẵn nếu đã dùng Vault | Cao | Nếu stack đã có Vault |
| Luna/Utimaco: một **partition** PKCS#11 cho mỗi tenant | Thường 10–100 partition/HSM tùy model và license | Rất cao — biên phần cứng, mỗi partition có PIN riêng | Khách hàng regulated |
| Một cluster CloudHSM riêng cho mỗi tenant | ~$3,200–4,000/tháng/tenant | Tối đa | Chỉ khi khách hàng trả tiền cho nó |
| MPC SaaS: một vault/workspace cho mỗi tenant | Theo hợp đồng nhà cung cấp | Cao | Nếu đã dùng MPC |
| Enclave: một instance enclave cho mỗi tenant | Chi phí EC2 (~$50–150/tháng/instance) | Trung bình-cao | Cô lập theo tiến trình |
| **Chỉ dựa vào record rule Odoo** | 0 | **Không đủ. Cấm dùng một mình** | — |

Phía Odoo vẫn cần record rule đúng, chỉ là nó không phải hàng phòng thủ duy nhất. Lưu ý Odoo 19: `res.users.group_ids`, **không** phải `groups_id`.

```xml
<record id="rule_custody_key_company" model="ir.rule">
    <field name="name">Custody key: company scoped</field>
    <field name="model_id" ref="model_blockchain_custody_key"/>
    <field name="domain_force">[('company_id','in',company_ids)]</field>
    <field name="global" eval="True"/>
</record>
```

Bốn cấm cứng:

1. **Không share `blockchain.custody.key` giữa các company** kể cả khi cùng một khóa vật lý. Nếu hai company dùng chung một relayer EOA, tạo hai record trỏ cùng `signer_ref`, và ghi rõ trong `shared_note` — để việc chia sẻ là một quyết định hiển thị trong UI, không phải một `company_id = False` nằm im.
2. **Chi phí gas không được gộp giữa tenant.** Velocity limit (§06.4) và runway (§06.5) tính theo `company_id`, nếu không một tenant đốt hết ngân sách của tenant khác.
3. **`x` của tenant A không bao giờ được unwrap trong cùng một tiến trình enclave đang giữ `x` của tenant B**, trừ khi enclave đó đã được audit về memory isolation. Mặc định: một enclave một tenant, hoặc drain + zeroize giữa hai request khác tenant. Chi phí của lựa chọn "một enclave một tenant": ~$50–150/tháng/tenant — với 5 tenant là $250–750/tháng, rẻ hơn nhiều so với một sự cố cross-tenant.
4. **Không có `sudo()` nào trong đường gọi signer.** Nếu một method cần vượt quyền để đọc cấu hình, tách nó ra khỏi method gọi signer. Grep `sudo()` trong `dms_blockchain/` phải là một mục trong checklist review, không phải một thói quen.

---

### 07.12. Bề mặt model Odoo

Standalone tuyệt đối: `depends = ['base', 'mail']` (khớp §10), **không** `dms`, **không** `account`, **không** `payment`. Không Many2one nào trỏ ra ngoài addon, ngoại lệ duy nhất là `res.company` và `res.partner` (cả hai thuộc `base`). Prefix `blockchain.*` khớp §03/§04/§06.

#### 07.12.1. `blockchain.custody.provider`

```python
# /home/dockers/odoo19/custom-addons/dms_blockchain/models/blockchain_custody_provider.py
from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError

class BlockchainCustodyProvider(models.Model):
    _name = 'blockchain.custody.provider'
    _description = 'Custody backend configured at deploy time'
    _inherit = ['mail.thread']          # audit trail cho moi thay doi cau hinh
    _order = 'company_id, name'

    name         = fields.Char(required=True, tracking=True)
    company_id   = fields.Many2one('res.company', required=True, index=True,
                                   default=lambda s: s.env.company)
    kind         = fields.Selection([
        ('hsm', 'HSM FIPS 140-3 L3 (PKCS#11)'), ('kms', 'Cloud KMS'),
        ('mpc', 'MPC SaaS (threshold signing)'),
        ('tee_saas', 'TEE SaaS (Turnkey / Fortanix / Anjuna)'),
        ('enclave', 'Confidential enclave (tu van hanh)'),
        ('custodial', 'Custodial'), ('on_device', 'Non-custodial on-device'),
        ('smart_account', 'Smart account / passkey'),
        ('local_dev', 'Khoa trong bien moi truong — CHI dev/CI'),   # [BAN 3]
    ], required=True, tracking=True)
    # [BAN 3] KHONG con required tuyet doi. Chi cac kind that su la SERVICE NGOAI moi
    # can endpoint. `kms` la mot loi goi SDK; `on_device`/`smart_account` khong co gi
    # phia server; `local_dev` doc bien moi truong. Bat endpoint_url cho chung la ep
    # deployment bia ra mot URL gia. Xem §07.12.1b.
    endpoint_url = fields.Char(tracking=True)                  # signer service, mTLS
    client_cert_path = fields.Char(
        required=True,
        help='Duong dan file tren dia (chmod 0600, owner odoo). KHONG luu private key '
             'trong DB va KHONG trong ir.config_parameter: config_parameter doc duoc boi '
             'moi user thuoc base.group_system.')
    caps_csv     = fields.Char(required=True, readonly=True, default='',
                               help='Do signer service bao cao qua /caps. Khong nhap tay. Chi la cache.')
    protocol_version = fields.Char(readonly=True, default='')
    can_prove_zether = fields.Boolean(compute='_compute_caps_flags', store=True,
                                      required=True, default=False)
    can_decrypt      = fields.Boolean(compute='_compute_caps_flags', store=True,
                                      required=True, default=False)
    attestation_kind = fields.Selection([
        ('none', 'Khong co'), ('nitro', 'AWS Nitro'), ('tdx', 'Intel TDX'),
        ('snp', 'AMD SEV-SNP'), ('gcp_cs', 'GCP Confidential Space'),
        ('pkcs11', 'HSM audit log only')], required=True, default='none')
    expected_measurement = fields.Char(
        help='PCR0 / MRENCLAVE / image_digest mong doi. Probe lech gia tri nay => tu choi.')
    fips_boundary_note = fields.Text(
        help='Ghi ro thao tac nao THUC SU nam trong bien FIPS. Bat buoc khi kind=hsm.')
    custodial_liability_class = fields.Selection(
        [('none', 'Khong giu khoa cua nguoi khac'),
         ('closed_loop', 'Closed-loop: chi doi hang cua issuer'),
         ('open_loop', 'Open-loop: transfer P2P / cash-out duoc')],
        required=True, default='none', tracking=True)
    license_ref  = fields.Char(help='So giay phep custody/e-money. Bat buoc khi open_loop.')
    last_probe_datetime = fields.Datetime(readonly=True)   # khong dat ten 'datetime'
    last_probe_nonce    = fields.Char(readonly=True)
    state        = fields.Selection([('draft','Draft'), ('probed','Probed'),
                                     ('active','Active'), ('disabled','Disabled')],
                                    required=True, default='draft', index=True, tracking=True)

    _unique_name_company = models.Constraint(
        'UNIQUE(company_id, name)', 'Ten custody provider phai duy nhat trong mot company.')

    # BAY ODOO 19: stored computed KHONG duoc nhan `default`. Neu mot nhanh cua
    # compute khong gan gi va cot la required, INSERT chet vi NULL.
    # Gan gia tri o MOI nhanh, khong dung `continue`.
    @api.depends('caps_csv')
    def _compute_caps_flags(self):
        for rec in self:
            caps = set((rec.caps_csv or '').split(','))
            rec.can_prove_zether = 'zether_prove_transfer' in caps
            rec.can_decrypt = 'elgamal_decrypt' in caps

    @api.constrains('custodial_liability_class', 'license_ref')
    def _check_license(self):
        for rec in self:
            if rec.custodial_liability_class == 'open_loop' and not rec.license_ref:
                raise ValidationError(_("Open-loop custodial can license_ref."))

    @api.constrains('kind', 'fips_boundary_note')
    def _check_fips_note(self):
        for rec in self:
            if rec.kind == 'hsm' and not (rec.fips_boundary_note or '').strip():
                raise ValidationError(_("kind=hsm phai ghi ro bien FIPS thuc te."))

    @api.constrains('state')
    def _check_activate(self):
        for rec in self:
            if rec.state == 'active' and not rec.last_probe_datetime:
                raise ValidationError(_("Phai probe truoc khi active."))
            if rec.state == 'disabled' and rec.key_ids.filtered(
                    lambda k: k.state in ('provisioning', 'active', 'rotating')):
                raise ValidationError(_("Con key dang hoat dong; retire chung truoc."))

    @api.model
    def custody_probe(self, provider_id):
        """POST /web/dataset/call_kw/blockchain.custody.provider/custody_probe
           POST /json/2/blockchain.custody.provider/custody_probe

        Goi /caps + /attest cua signer service, ghi caps_csv va so khop
        expected_measurement. Khong nhan allowed_company_ids tu client:
        company suy ra tu record, va quyen suy ra tu env.user."""
        rec = self.browse(provider_id)
        rec.check_access('write')       # Odoo 19: API hop nhat; browse() mot minh KHONG kiem quyen
        return rec._probe()
```

Ba điểm về `custody_probe` mà bản nháp trước bỏ:

- `@api.model` + nhận `provider_id` là một RPC nhận id tùy ý. `self.browse(id)` **không** kiểm quyền cho tới khi đọc field. Phải gọi `check_access('write')` tường minh (Odoo 19 hợp nhất `check_access_rights`/`check_access_rule` thành `check_access(operation)`; nó mang `@api.private` nên không tự lộ ra RPC, gọi nội bộ được).
- `_probe()` là private → không lộ RPC. Đúng mẫu §6 của CLAUDE.md.
- Probe **phải** so `expected_measurement`; nếu lệch thì đặt `state='disabled'` và tạo `security.event` mức critical, chứ không phải ghi đè giá trị mới. Ghi đè là tự tay vô hiệu hóa attestation.


#### 07.12.1b. [BẢN 3] Custody có tắt được không — và vì sao `endpoint_url` không còn `required`

Câu hỏi (user, 2026-08-31): *"Custody Provider này cũng là option bật tắt?"* Trả lời phải tách theo trục,
vì hai trục có hai câu trả lời khác nhau.

| Trục | Tắt được không | Điều kiện |
|---|---|---|
| **`conf_custody`** (oracle lane, giữ `x`) | **CÓ, tắt hoàn toàn** | Không dùng Zether ⇒ `conf_provider_id` để rỗng. Sau khi Zether cho B2B thành tuỳ chọn (§07.0), đây là **mặc định** |
| **`auth_custody`** (ký vỏ tx) | **Không tắt được toàn cục — nhưng tắt được theo vai** | Xem dưới |

**Vì sao `auth_custody` không tắt toàn cục được:** ai đó phải ký transaction gửi lên chuỗi. Kể cả chain
private với `MinGasPrice = 0` — gas miễn phí không có nghĩa tx không cần chữ ký.

**Nhưng "ai đó" không nhất thiết là ta.** Ba cấu hình hợp lệ, phía ta không có `auth_custody` nào:

1. **Node `submit: false`** — pool thuần / forwarder / observer (`_USER-DECISIONS.md` §21.4). Nhận intent,
   chuyển tiếp, **không cầm khoá nào**. Đây là một vai chính thức trong ma trận, không phải một cấu hình
   thiếu sót.
2. **Deployment chỉ nhận và index** — theo dõi địa chỉ, đối soát, sinh `account.move`. Không phát tx nào
   ⇒ không cần khoá nào. Đây là §09 mode M0/M4.
3. **Mọi thứ do user ký trên thiết bị** (`smart_account` passkey), và relay do bên thứ ba làm. Ta không
   ký gì.

Ngược lại, `auth_custody` **chắc chắn tồn tại** ngay khi ta: chạy relayer, refill hot wallet, deploy
contract, hoặc chi từ treasury.

**Điểm quan trọng nhất, và là chỗ §07.1b nói quá:** custody **không phải một feature flag mà là một slot
cắm được, và cái cắm vào có thể rất nhỏ.**

§07.1b viết *"`confidential-signer` là một sản phẩm riêng: deploy, HA, monitoring, cert lifecycle,
on-call. Không phải một file `.py`."* Câu đó **đúng cho `enclave` và `hsm`**, và **sai cho `kms`**:
`kind = 'kms'` là một lời gọi AWS SDK từ chính tiến trình đang chạy — không có dịch vụ nào để vận hành,
không có cert nào để xoay, không có ai phải on-call.

| `kind` | Có phải service ngoài không | `endpoint_url` |
|---|---|---|
| `hsm`, `enclave`, `tee_saas`, `mpc` | **có** — tiến trình riêng, mTLS | **bắt buộc** |
| `kms` | không — SDK call trong tiến trình | không có |
| `on_device`, `smart_account` | không — không có gì phía server | không có |
| `custodial` | có, nếu tách; không, nếu nhúng | tuỳ |
| `local_dev` | không — biến môi trường | không có |

Vì thế `endpoint_url` **bỏ `required=True`**, và thay bằng ràng buộc có điều kiện:

```python
@api.constrains('kind', 'endpoint_url', 'client_cert_path')
def _check_endpoint_required(self):
    """Chi cac kind that su la service ngoai moi can endpoint + cert. Bat moi kind
    khai endpoint la ep deployment bia ra mot URL gia, va mot URL gia trong cau hinh
    bao mat te hon mot o trong."""
    REMOTE = {'hsm', 'enclave', 'tee_saas', 'mpc'}
    for rec in self:
        if rec.kind in REMOTE and not (rec.endpoint_url and rec.client_cert_path):
            raise ValidationError(_(
                "kind=%s la mot service ngoai: bat buoc co endpoint_url va client_cert_path.",
                rec.kind))
        if rec.kind not in REMOTE and rec.endpoint_url:
            raise ValidationError(_(
                "kind=%s khong phai service ngoai; de endpoint_url trong.", rec.kind))
```

Và thêm `kind = 'local_dev'` (khoá trong biến môi trường) — nó vốn đã tồn tại trong bảng cấu hình của
`10-odoo-addon-design.md` §10.8.1 (`blockchain.signer.<ref>.backend` nhận `local_dev`) nhưng thiếu trong
Selection này. Hai chỗ nói khác nhau về cùng một tập giá trị là một lỗi sẽ nổ lúc validate cấu hình.

**Guard bắt buộc đi kèm `local_dev`:** `@api.constrains` chặn `state = 'active'` khi
`kind == 'local_dev'` và `blockchain.environment != 'dev'`. Một khoá trong biến môi trường trên
production là đúng cái §07.11 dựng ba lớp để chặn.

**Cấu hình tối thiểu chạy được (META v1, §24):** một provider `kind = 'kms'`, `conf_provider_id` rỗng,
không enclave, không HSM, không tiến trình signer nào. Chi phí ~$107/tháng theo §07.12b cấu hình C.
Đó là mức khởi điểm, và §07 nên đọc từ đó lên chứ không phải từ HSM xuống.

#### 07.12.2. `blockchain.custody.key`

```python
class BlockchainCustodyKey(models.Model):
    _name = 'blockchain.custody.key'
    _description = 'Key handle. NEVER key material.'
    _inherit = ['mail.thread']

    provider_id  = fields.Many2one('blockchain.custody.provider', required=True,
                                   index=True, ondelete='restrict')
    company_id   = fields.Many2one(related='provider_id.company_id', store=True, index=True)
    signer_ref   = fields.Char(required=True, tracking=True,
                               help='blockchain/<tenant_uuid>/<role>/<name>. KHONG BAO GIO la khoa.')
    key_role     = fields.Selection([('treasury','Treasury'), ('minter','Minter'),
                                     ('admin','Contract admin'), ('relay','Relayer EOA'),
                                     ('zether_enc','Zether encKey'),
                                     ('zether_share','Zether encKey share (t-of-n)'),
                                     ('audit_share','Auditor DKG share'),
                                     ('kek','Key encryption key')],
                                    required=True, index=True)
    curve        = fields.Selection([('secp256k1','secp256k1'), ('ed25519','ed25519'),
                                     ('p256','NIST P-256'), ('bn254_g1','BN254 G1'),
                                     ('aes256','AES-256 (KEK)')], required=True)
    public_key_hex = fields.Char(index=True)   # KHONG required: KEK khong co public key
    threshold_t  = fields.Integer(default=0, help='0 = 1-of-1. >0 = t trong t-of-n.')
    threshold_n  = fields.Integer(default=0)
    backup_scheme = fields.Selection([('none','None'), ('slip39_2of3','SLIP-0039 2-of-3'),
                                      ('mpc_vendor','Vendor recovery'), ('prf_wrapped','WebAuthn PRF'),
                                      ('dkg_share','DKG share, khong co backup rieng')],
                                     required=True, default='none')
    recovery_class = fields.Selection([('none','Khong khoi phuc duoc'),
                                       ('audit_data_only','Chi khoi phuc so lieu qua C_audit'),
                                       ('threshold','t-of-n: t ben con lai migrate duoc'),
                                       ('governance','Governance recoverAccount, private chain')],
                                      required=True, default='none', tracking=True)
    ceremony_id  = fields.Many2one('blockchain.key.ceremony', ondelete='restrict')
    rotate_due_date = fields.Date()                     # khong dat ten 'date'
    last_export_date = fields.Date(readonly=True)       # rate limit wrap_export 90 ngay
    shared_note  = fields.Text(help='Neu signer_ref nay dung chung voi company khac, ghi ro o day.')
    state        = fields.Selection([('provisioning','Provisioning'), ('active','Active'),
                                     ('rotating','Rotating'), ('retired','Retired'),
                                     ('lost','Lost'), ('compromised','Compromised')],
                                    required=True, default='provisioning', index=True, tracking=True)

    _unique_signer_ref = models.Constraint(
        'UNIQUE(provider_id, signer_ref)', 'Mot signer_ref chi khai bao mot lan.')
    _threshold_sane = models.Constraint(
        'CHECK (threshold_n = 0 OR (threshold_t >= 1 AND threshold_t <= threshold_n))',
        'Nguong t-of-n khong hop le.')

    @api.constrains('key_role', 'recovery_class', 'threshold_n')
    def _check_recovery_policy(self):
        for rec in self:
            if rec.key_role == 'zether_enc' and rec.recovery_class == 'threshold' \
               and rec.threshold_n < 2:
                raise ValidationError(_("recovery_class=threshold can threshold_n >= 2."))
```

`public_key_hex` **không** `required` — bản nháp trước để `required=True`, nhưng một KEK AES-256 không có public key, nên record KEK không tạo được. Sửa. Kèm một cron đối chiếu: `public_key_hex` của key `zether_enc` phải khớp `getPublicKey(schnorrAddress)` trên registry, lệch là `security.event`.

#### 07.12.3. `blockchain.custody.policy` — cái bản nháp trước thiếu hẳn

Locked #6 nói "chọn lúc deploy". Bản nháp trước mô hình hóa *các lựa chọn* nhưng không mô hình hóa *cái đã chọn*. Không có model này thì "chọn lúc deploy" nằm trong đầu người deploy.

```python
class BlockchainCustodyPolicy(models.Model):
    _name = 'blockchain.custody.policy'
    _description = 'Binding: money flow + chain profile -> custody providers'
    _inherit = ['mail.thread']

    company_id   = fields.Many2one('res.company', required=True, index=True,
                                   default=lambda s: s.env.company)
    money_flow   = fields.Selection([('loyalty','Loyalty / reward points'),
                                     ('b2b_settlement','B2B settlement'),
                                     ('enduser_payment','End-user payment'),
                                     ('treasury','Treasury / mint / admin'),
                                     ('relay','Relayer gas')], required=True, index=True)
    chain_profile = fields.Selection([('public','Public'), ('private','Private')],
                                     required=True, index=True)
    auth_provider_id = fields.Many2one('blockchain.custody.provider', required=True,
                                       ondelete='restrict')
    conf_provider_id = fields.Many2one('blockchain.custody.provider', ondelete='restrict',
                                       help='Bo trong neu luong nay khong dung Zether.')
    requires_c_audit = fields.Boolean(required=True, default=True)
    min_threshold_n  = fields.Integer(required=True, default=1,
                                      help='1 = cho phep 1-of-1. B2B phai >= 3.')
    active       = fields.Boolean(default=True)

    _unique_flow = models.Constraint(
        'UNIQUE(company_id, money_flow, chain_profile)',
        'Moi (company, money_flow, chain_profile) chi co mot policy.')

    @api.constrains('conf_provider_id', 'money_flow')
    def _check_conf_caps(self):
        """Chan dung loi ma §07.1 mo ta: cau hinh xanh cho toi lan chuyen tien dau tien."""
        for rec in self:
            if rec.conf_provider_id and not rec.conf_provider_id.can_prove_zether:
                raise ValidationError(_(
                    "Provider '%s' (kind=%s) khong prove Zether duoc. "
                    "Chon enclave / on_device / custodial.",
                    rec.conf_provider_id.name, rec.conf_provider_id.kind))

    @api.constrains('money_flow', 'min_threshold_n', 'conf_provider_id')
    def _check_b2b_threshold(self):
        """[BAN 3] Chi ap khi B2B THUC SU dung Zether. Zether cho B2B la tuy chon;
        conf_provider_id rong nghia la khong co `x` nao de mat, nen nguong vo nghia."""
        for rec in self:
            if (rec.money_flow == 'b2b_settlement'
                    and rec.conf_provider_id            # <-- dieu kien moi
                    and rec.min_threshold_n < 3):
                raise ValidationError(_(
                    "B2B settlement co Zether cam 1-of-1: dust do mat khoa "
                    "khong chap nhan duoc (§07.10)."))
```

#### 07.12.4. Còn lại

`blockchain.key.ceremony` giữ hồ sơ §07.8: `ceremony_hash` (Char), `anchor_tx_hash`, `witness_ids` (Many2many `res.partner`), `ceremony_date` (Date, không đặt tên `date`), `drill_date` (ngày diễn tập bước 9), và biên bản/video là **Many2many `ir.attachment` trên Garage** — không base64 trong DB, không JSON blob.

`blockchain.enclave.image` giữ §07.8 E1–E5: `image_pcr0`, `git_commit`, `eif_sha384`, `anchor_tx_hash`, `policy_added_date`, `policy_removed_date`. Cron cảnh báo khi một image có `policy_added_date` mà chưa có `policy_removed_date` sau khi image kế tiếp đã active 30 ngày (đó là bước E5 bị quên).

`blockchain.security.event` (được §07.13 và §12 tham chiếu, bản nháp trước dùng mà không định nghĩa): `severity` (`info`/`warning`/`critical`), `event_kind`, `company_id`, `signer_ref`, `detail`, `occurred_datetime`, `acknowledged_uid`. Mức `critical` tạo `mail.activity` cho group `blockchain_treasury_manager` **và** bắn webhook — không chỉ ghi log.

`blockchain.signing.request` (§07.1b): `policy_id`, `key_id`, `op`, `idem_key` (Char, unique), `payload_hash`, `state`, `attempt_count`, `last_error_kind`, `result_ref`. Constraint:

```python
_unique_idem = models.Constraint(
    'UNIQUE(idem_key)', 'Idempotency key phai duy nhat: chong ky hai lan khi retry.')
```

ACL tối thiểu (`security/ir.model.access.csv`) — ba group: `blockchain_user` (đọc), `blockchain_operator` (ghi `signing.request`), `blockchain_treasury_manager` (ghi provider/key/policy/ceremony):

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_custody_provider_mgr,custody.provider.mgr,model_blockchain_custody_provider,group_blockchain_treasury_manager,1,1,1,0
access_custody_provider_user,custody.provider.user,model_blockchain_custody_provider,group_blockchain_user,1,0,0,0
access_custody_key_mgr,custody.key.mgr,model_blockchain_custody_key,group_blockchain_treasury_manager,1,1,1,0
access_custody_key_user,custody.key.user,model_blockchain_custody_key,group_blockchain_user,1,0,0,0
access_custody_policy_mgr,custody.policy.mgr,model_blockchain_custody_policy,group_blockchain_treasury_manager,1,1,1,0
access_key_ceremony_mgr,key.ceremony.mgr,model_blockchain_key_ceremony,group_blockchain_treasury_manager,1,1,1,0
access_security_event_user,security.event.user,model_blockchain_security_event,group_blockchain_user,1,0,0,0
access_security_event_mgr,security.event.mgr,model_blockchain_security_event,group_blockchain_treasury_manager,1,1,1,0
```

`perm_unlink = 0` **ở khắp nơi**: một custody key hay một security event bị xóa là một dấu vết bị xóa. Retire, không delete.

Cron một dòng, không `fields.` inline (bẫy §5.4 của CLAUDE.md). Lưu ý Odoo 17+ đã **bỏ** `numbercall` và `doall` — một XML cũ mang hai field đó sẽ fail lúc cài:

```xml
<record id="cron_custody_probe" model="ir.cron">
    <field name="name">Blockchain: probe custody providers and key rotation due</field>
    <field name="model_id" ref="model_blockchain_custody_provider"/>
    <field name="user_id" ref="base.user_root"/>
    <field name="state">code</field>
    <field name="code">model._cron_custody_probe()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">hours</field>
    <field name="active" eval="True"/>
</record>
```

Layout service:

```
/home/dockers/odoo19/confidential-signer/          # tien trinh rieng, mTLS, KHONG trong Odoo worker
    custody/base.py            # ICustodyProvider (§07.1)
    custody/pkcs11.py  custody/awskms.py  custody/mpc_fireblocks.py
    custody/tee_turnkey.py     custody/enclave.py   custody/custodial.py
    authz.py                   # resolve() §07.11
    policy.py                  # SigningPolicy: to-allowlist, selector, tran value, tran gio
    idem.py                    # cache (tenant, signer_ref, digest) -> signature, TTL 24h
    chainwitness.py            # verify (C, D) that su la trang thai on-chain (§07.1 diem c)
    enclave/                   # image chay trong Nitro/TDX/SNP
    enclave/vsock_proxy.py     # I/O DUY NHAT cua enclave -> trong scope audit
    threshold/dkg.py  threshold/decrypt.py  threshold/oracle.py   # §07.2b, §07.4a
```

Và trong `smartcontracts/` (ngoài addon, locked #9):

```
smartcontracts/crates/zether-core/src/key_oracle.rs
smartcontracts/crates/zether-oracle-enclave/
smartcontracts/crates/zether-oracle-threshold/
smartcontracts/crates/zether-core/tests/oracle_equiv.rs
smartcontracts/crates/zether-core/benches/bsgs.rs          # §07.4b, chay trong CI
```

---

### 07.12b. Tổng chi phí custody: một bảng để so, không phải một cảm giác

Giả định: 3 tenant, 50.000 giao dịch ký/tháng, 5.000 tài khoản Zether, Gnosis + một private chain.

| Hạng mục | Cấu hình A: cloud (AWS) | Cấu hình B: on-prem VN | Cấu hình C: tối thiểu (loyalty only) |
|---|---|---|---|
| HSM | CloudHSM 3× hsm2m ~$3,600/th | 2× Thales/Utimaco, amortize 5 năm ~$1,300/th + support ~$600/th | KMS asymmetric, 6 key ~$6/th |
| KMS request (50k sign) | ~$0.75/th | 0 | ~$0.75/th |
| Enclave | 3× c6a.xlarge Nitro ~$450/th | 2× server SEV-SNP amortize ~$400/th + colo ~$500/th | 0 (on_device) |
| MPC SaaS (nếu dùng cho treasury) | ~$1,500–5,000/th theo hợp đồng | như trên | 0 |
| Signer service (compute + LB) | ~$200/th | ~$100/th | ~$100/th |
| Tổng hạ tầng | **~$4,250–9,750/th** | **~$2,900/th** (+ $60–90k capex) | **~$107/th** |
| Chi phí xây attestation | 0 (dùng KMS Recipient) | **~4–8 tuần kỹ sư** | 0 |
| Nghĩa vụ dữ liệu xuyên biên giới | **Có** (NĐ 13/2023) | Không | Không |
| Thời gian tới production | 2–4 tuần | 3–6 tháng | 1 tuần |

Đọc bảng: **cấu hình C đủ cho loyalty và end-user payment**, và đó là 2 trong 3 use case của locked #3. Chỉ B2B settlement mới cần A hoặc B. Kế hoạch triển khai nên bắt đầu từ C, không phải từ A — và điều đó khớp với locked #4 (Gnosis trước) và locked #5 (private chain trước cho Zether, nhưng private chain của giai đoạn đầu có thể chạy enclave tự vận hành ở quy mô nhỏ).

---

### 07.13. Kiểm chứng bắt buộc

Nhóm theo cái nó bảo vệ, vì một checklist phẳng thì không ai chạy hết.

**A. Odoo / dữ liệu**

1. `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_custody_key'::regclass;` phải có dòng UNIQUE — `_sql_constraints` dạng list bị Odoo 19 **bỏ qua hoàn toàn**. Lặp lại cho `blockchain_custody_provider`, `blockchain_custody_policy`, `blockchain_signing_request`, `res_company` (tenant uuid).
2. Tạo một `blockchain.custody.provider` với `caps_csv = ''` → INSERT phải thành công và `can_prove_zether` phải là `False`, **không** NULL. Đây là test cho bẫy stored-computed-required.
3. `custody_probe` gọi qua `/json/2/blockchain.custody.provider/custody_probe` bởi một user không thuộc `blockchain_treasury_manager` phải raise `AccessError`, không phải trả dữ liệu.
4. `unlink()` một `blockchain.custody.key` phải fail (ACL `perm_unlink = 0`), kể cả bởi admin qua RPC.
5. `_check_b2b_threshold`: tạo policy `money_flow='b2b_settlement'`, `min_threshold_n=1` → phải raise.
6. `grep -rn "sudo()" dms_blockchain/models/` — mỗi kết quả phải có comment giải thích, hoặc bị xóa.
7. `grep -rn "depends.*'dms'" dms_blockchain/__manifest__.py` → phải rỗng (locked #7).

**B. Cô lập tenant**

8. `signer_ref` của company B gửi qua cert mTLS của company A phải bị từ chối **và** sinh một `blockchain.security.event` mức `critical`, không chỉ trả 403.
9. KMS: `Decrypt` một blob của tenant A với `EncryptionContext` của tenant B phải fail. Nếu nó thành công, encryption context không được truyền và §07.11 vô nghĩa.
10. Restore một dump production vào một database staging, chạy `odoo-bin neutralize`, rồi thử `custody_probe` → phải fail vì `endpoint_url` rỗng. Sau đó **bỏ neutralize** và thử lại với cert staging → phải fail ở signer vì environment lệch. **Cả hai lớp phải chặn độc lập.**

**C. Attestation và enclave**

11. Thực nghiệm trên KMS thật: `kms:Decrypt` với `Recipient` từ một enclave có PCR0 **sai** phải fail. Nếu nó thành công, key policy viết sai và toàn bộ §07.2 vô nghĩa.
12. `attest(h, nonce)` với một nonce đã dùng trước đó phải bị Odoo từ chối (chống replay attestation). Test bằng cách gửi lại đúng response cũ.
13. Probe một provider mà `expected_measurement` lệch → provider phải chuyển `state='disabled'`, **không** phải ghi đè measurement mới.
14. Thứ tự xoay image (§07.9): mô phỏng bỏ bước "thêm PCR0 mới trước" và xác nhận luồng confidential chết — để runbook có bằng chứng, không phải niềm tin.

**D. Crypto**

15. `zk_response(id, c)` gọi lần thứ hai với cùng `NonceId` phải panic / raise, không trả về. Test negative bắt buộc: nonce reuse làm lộ `x`.
16. `oracle_equiv.rs`: ba hiện thực `ZetherKeyOracle` (in-process, enclave, threshold) trên cùng witness phải cho **cùng một proof byte-for-byte** (hoặc cùng verify pass với transcript xác định).
17. Threshold decrypt với **một share cố tình sai** → Chaum-Pedersen phải bắt được và chỉ đúng share nào sai. Không có test này thì §07.4a chỉ là hình vẽ.
18. `elgamal_decrypt` với một `(C, D)` bịa (không có trên chain) phải bị từ chối bởi `chainwitness.py`. Đây là test chống decryption oracle (§07.0b giả định #8).
19. Benchmark BSGS trong CI (`benches/bsgs.rs`) trên x86 và trên một runner ARM64: p95 ≤ **200 ms** với bảng warm ở `range_bits_value = 32`. Nếu > 200 ms, sửa **hiện thực** (batch inversion) trước, chỉ sửa tham số §3.9 khi hiện thực đã tối ưu. Thất bại của bench là fail build, không phải cảnh báo.
20. Đo thời gian replay khôi phục `plaintext_balance` từ 10.000 delta; phải < 20 phút trên ARM64.

**E. Vòng đời và tiền**

21. Diễn tập khôi phục SLIP-0039 2-of-3 trên khóa test, **có bấm giờ**, trước khi khóa production nhận đồng đầu tiên (§07.8 bước 9).
22. `wrap_export` không có `QuorumTicket` hợp lệ phải fail. `wrap_export` lần thứ hai trong 90 ngày phải fail kể cả với ticket hợp lệ.
23. `destroy()` một key `zether_enc` còn số dư khác 0 phải fail (thiếu `zero_balance_proof`).
24. Retry một `sign_raw_tx` với cùng `idem` phải trả về **đúng chữ ký cũ**, không ký lại. Kiểm bằng cách so bytes.
25. Signer down 5 phút giữa lúc có 100 job queued → sau khi lên lại, đúng 100 giao dịch on-chain, không phải 100 + số lần retry.

**F. Chain**

26. Probe `P256VERIFY` (0x100) trên Gnosis và Celo mainnet, ghi vào `blockchain.chain.has_p256_precompile`. **Không hardcode.**
27. Foundry: build profile `public` của `ZetherToken` phải **không chứa** selector của `recoverAccount`. Kiểm bằng cách grep bytecode, không bằng cách đọc source.
28. `migrateAccount` với chỉ `authSigOld` (thiếu `authSigNew`) phải revert (§2.7.2).

---

### 07.14. Còn phải quyết (cần người quyết, không phải cần thêm nghiên cứu)

1. **Chấp nhận rằng `x` không nằm trong biên FIPS Level 3 lúc sử dụng?** Nếu không chấp nhận thì phải bỏ Zether hoặc trả tiền cho Functionality Module — mà sau §07.2b, FM chỉ còn là ~4–8 tuần phát triển cộng chu kỳ tái chứng nhận, chứ không phải 6 tháng. Đây là quyết định hợp đồng, không phải quyết định kỹ thuật. **Kèm theo: sửa mọi câu "FIPS 140-2 Level 3" trong `blockchain.md`, hồ sơ thầu và hợp đồng thành "FIPS 140-3 Level 3 hoặc chứng nhận CMVP đương thời" trước 2026-09-21.**
2. **`C_audit` bắt buộc ở đâu?** Đề xuất: bắt buộc mọi nơi trừ loyalty closed-loop có `recovery_class = 'threshold'` (khi đã có t-of-n thì `C_audit` là dư thừa cho mục đích khôi phục, nhưng vẫn cần cho Travel Rule — nên câu trả lời có thể vẫn là "mọi nơi"). Chi phí $0.00005/tx. Cần chốt vì nó thay đổi calldata của contract, tức chốt **trước** khi deploy.
3. **Cấu hình `x` mặc định cho mỗi money flow: 1-of-1 hay t-of-n?** Đây là câu hỏi lớn nhất của section, vì nó **là** đánh đổi giữa "khôi phục được" và "không phải custodian". Đề xuất: loyalty và end-user payment 1-of-1 + passkey PRF (dust ~12–50 triệu VND/5 năm, chấp nhận được, không có nghĩa vụ custody); B2B settlement 2-of-3 hoặc 3-of-5 với platform giữ một share (**chấp nhận nghĩa vụ custody cho luồng này, và chỉ luồng này**). Cần luật sư xác nhận rằng giữ một share 1-of-3 của một khóa B2B, khi không thể chi tiêu một mình, có cấu thành custody theo NĐ 52/2024 hay không — đây là câu hỏi pháp lý chưa có tiền lệ ở VN.
4. **Ai giữ share DKG thứ 4 và thứ 5 của `y_audit`?** Đề xuất 3-of-5 với một share do kiểm toán độc lập và một share niêm phong offline. Cần tên người và văn bản uỷ quyền, không cần thêm thiết kế.
5. **Dust do mất khóa hạch toán thế nào?** Nợ tiềm tàng, hay thu nhập khác sau N năm không hoạt động? Có luật escheatment/tài sản vô chủ áp dụng không? Cần kế toán trưởng và luật sư. Con số để họ làm việc: bảng §07.10.
6. **Bật `custody_mode = 'custodial'` ở Việt Nam trước khi khung pháp lý rõ?** Đề xuất mặc định **không**, và chặn cứng ở `_check_license` (§07.5) cho tới khi có `license_ref`. Kèm: **omnibus bị cấm cho mọi luồng có Zether** — cần xác nhận rằng không có yêu cầu kinh doanh nào đòi omnibus, vì nếu có thì phải bỏ Zether ở luồng đó.
7. **Enclave dùng nền nào, và dữ liệu ở đâu?** AWS Nitro (cưỡng chế bằng KMS attestation, có sẵn cơ chế, dữ liệu ở Singapore) hay AMD SEV-SNP tự vận hành tại VN (chủ quyền dữ liệu, nhưng phải tự xây chuỗi attestation, +4–8 tuần, +$60–90k capex). Ràng buộc NĐ 13/2023 về chuyển dữ liệu xuyên biên giới có thể loại bỏ lựa chọn đầu. **Phải xác nhận trước khi viết `custody/enclave.py`** — hai đường không dùng chung code attestation.
8. **Ngưỡng giá trị nào bắt buộc `auth_custody = 'hsm'` thay vì `enclave` cho relayer?** §06.6 mục 3 nói cần người duyệt về compliance. Đề xuất: mọi khóa có thể mint, pause, hoặc nâng cấp contract dùng HSM không có ngoại lệ; relayer EOA dùng enclave với runway trần 4 giờ (§06.5).
9. **Bảo hiểm custody: có mua không, và ở đâu?** Nếu bật custodial hoặc t-of-n có platform, MiCA (nếu bán sang EU) bắt bồi thường khi mất khóa. Thị trường bảo hiểm crypto custody tồn tại nhưng phí cao và loại trừ nhiều. Cần một báo giá thật trước khi định giá dịch vụ, không phải sau.
10. **Ai vận hành `confidential-signer` on-call 24/7?** Nó là một hệ thống trên đường tiền với SLA khác hẳn Odoo. Nếu câu trả lời là "cùng đội vận hành Odoo", thì phải chấp nhận `on_device` làm mặc định cho mọi thứ có thể, để signer down không dừng luồng nào của người dùng cuối.

---

### 07.15. Tóm tắt những chỗ section này sửa

| Nguồn | Điều được sửa | Sửa thành |
|---|---|---|
| `blockchain.md` §10.3.1, §10.5.2, §14.2.8 | "Khóa bí mật $x$ lưu trong HSM/MPC FIPS 140-2 L3" | Không thực hiện được. Tách `authKey` (HSM được) khỏi `encKey` (enclave / t-of-n). §07.2 |
| `blockchain.md` (khắp nơi) | "FIPS 140-2 Level 3" | "FIPS 140-3 Level 3 hoặc CMVP đương thời". Chứng nhận 140-2 vào Historical List **2026-09-21** |
| `blockchain.md` §10.5.2 | Không nhắc gì tới mất khóa | §07.10: dust tích lũy, ba đường khôi phục, đánh đổi custody |
| Bản nháp 07 §07.0 mục 3 | "`conf_custody` chỉ có ba hiện thực, không có lựa chọn thứ tư" | Sai. Có ít nhất năm; tách prover (§07.2b) là cái tốt nhất |
| Bản nháp 07 §07.3 | "AWS CloudHSM (Luna-based)" | **Marvell LiquidSecurity**, và AWS không mở Functionality Module |
| Bản nháp 07 §07.3 | CloudHSM "tối thiểu 2 cho HA ⇒ $2,100–2,700/tháng" | AWS khuyến nghị 3 HSM / 2 AZ ⇒ **$3,200–4,000/tháng** |
| Bản nháp 07 §07.4 | Turnkey xếp cùng nhóm MPC | Turnkey là **TEE-based**, không phải MPC. Điều đó đưa nó vào danh sách ứng viên cho `ZetherKeyOracle` |
| Bản nháp 07 §07.4 | BSGS 2^32: "vài ms" | **20–40 ms x86 / 80–170 ms ARM64** có batch inversion; 5–10× tệ hơn nếu không |
| Bản nháp 07 §07.4 | Số dư 2^64: "hàng giờ tới hàng ngày" | BSGS **bất khả thi vì bộ nhớ** (86 GB). Kangaroo ~57 phút. Nhưng đường đúng là **replay delta**, 3–15 phút |
| Bản nháp 07 §07.4 | `plaintext_balance` là "cache" | Là **trạng thái tài khoản**, có đường khôi phục xác định |
| Bản nháp 07 §07.6 | `info = "zether/bn254/v1/<schnorrAddress>"` | Vòng lặp không tính được. Phải là hằng + `account_index` |
| Bản nháp 07 §07.7 | Gnosis @1 gwei | §06.4 dùng 2 gwei. Passkey Solidity verifier = **13–16% gas của một tx Zether** |
| Bản nháp 07 §07.9, §07.10 | `migrateAccount` "+12,150 gas", `C_audit` "+13,200 gas" | **24,300** và **25,300** (§2.7.2, §2.7.6 đã sửa) |
| Bản nháp 07 §07.10 | "public chain: không có khôi phục. Chấm hết" | Đúng cho 1-of-1. t-of-n khôi phục được trên mọi chain, đổi lại nghĩa vụ custody |
| Bản nháp 07 §07.12 | `public_key_hex` `required=True` | Record KEK không tạo được. Bỏ `required` |
| Bản nháp 07 §07.12 | `custody_probe` chỉ `browse(id)` | Thiếu `check_access('write')` → RPC đọc/ghi provider của company khác |
| Bản nháp 07 (toàn bộ) | Không có model cho "cái đã chọn lúc deploy" | `blockchain.custody.policy` (§07.12.3) |
| Bản nháp 07 (toàn bộ) | Signer coi như một hàm | Là một service: hàng đợi, idempotency, phân loại lỗi, chế độ hỏng (§07.1b) |
