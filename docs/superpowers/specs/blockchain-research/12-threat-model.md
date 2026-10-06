## 12. Mô hình đe doạ và bảo mật

### 12.0. Biên tin cậy, đối thủ, và nguyên tắc chủ đạo

Nguyên tắc VietQR áp dụng ở đây ở dạng mạnh nhất: **broadcast không phải là thanh toán, và `receipt.status == 1` cũng không phải**. Một tx thành công trên chuỗi với `innerSuccess = false` vẫn là tx thành công. Vì vậy mọi biện pháp trong section này đều quy về một câu hỏi duy nhất: *điều gì có thể làm cho `blockchain.metatx.state` chuyển sang `done` trong khi tiền không thực sự di chuyển, hoặc làm cho tiền di chuyển mà không có bản ghi nào trong Odoo?*

#### 12.0.1. Mười giả định ẩn của bản nháp trước — nói ra để còn kiểm chứng được

Bản nháp trước dùng cả mười giả định này mà không phát biểu cái nào. Một mô hình đe doạ không liệt kê giả định của nó thì không kiểm chứng được, và mọi giả định sai ở đây đều là một lỗ hổng không ai tìm.

| # | Giả định ẩn | Có đúng không | Hậu quả nếu sai | Xử lý |
|---|---|---|---|---|
| G1 | Chỉ có một tenant / một pháp nhân | **Sai** — §10.9 là multi-company | Operator công ty A ký được bằng khoá công ty B | Thêm A9; §07.11 `resolve(tenant_uuid, signer_ref)` là biên thật |
| G2 | `dms_blockchain` là một process | **Sai** — có ít nhất 4 process: Odoo, `relay-pool`, `confidential-signer`, indexer | Mỗi ranh giới process là một ranh giới tin cậy không được mô tả | Bảng 12.0.2 |
| G3 | Indexer chỉ đọc | **Sai** — indexer là thứ **ghi** `finalized`/`done` | Chiếm indexer = tạo tiền trong sổ kế toán mà không chạm chuỗi | Thêm A11 |
| G4 | `chain_profile = private` giảm rủi ro | **Chỉ đổi rủi ro** | Validator set là chính ta ⇒ rewind được, precompile là code Go chưa audit | 12.1.1, A12 |
| G5 | Prover client là tin cậy và RNG của nó tốt | **Chưa kiểm chứng** | Lặp `s` hoặc `k` một lần = **lộ `x`** = mất sạch tài khoản | 12.3.1 — đây là lỗ hổng nghiêm trọng nhất mà bản nháp bỏ sót hoàn toàn |
| G6 | `base.group_system` yếu hơn RCE | **Sai trên Odoo** | `ir.actions.server` `state='code'` chạy Python tuỳ ý trong process Odoo ⇒ **A4 = A5** | 12.6.1 |
| G7 | Đồng hồ Odoo và đồng hồ chuỗi khớp nhau | Không bảo đảm | `expiry` tính sai ⇒ intent chết lúc sinh, hoặc sống quá lâu | 12.7.4 |
| G8 | Audit tìm ra lỗi ⇒ deploy an toàn | Không suy ra được | Bytecode deploy khác bytecode audit | 12.7.3, và `to_impl_codehash` của §1.11.1 |
| G9 | Supply chain chỉ là toolchain contract | **Thiếu một nửa** | Client SDK (npm/pypi) cầm `x` — backdoor ở đó lấy khoá trực tiếp | Thêm A13 |
| G10 | Bulletproofs an toàn vì đã có bài báo | Bài báo an toàn, **triển khai thì không** | Fiat-Shamir yếu = proof giả | 12.3.2 |

#### 12.0.2. Ranh giới TIN CẬY — vẽ theo QUYỀN, không theo tiến trình

> **[BẢN 3 — `_USER-DECISIONS.md` §23.]** Bản trước vẽ mô hình đe doạ **theo tiến trình**, và ba
> trong bốn bất biến của nó dựa vào việc `relay-pool`, `chain-indexer` và `intent-hub` là ba tiến
> trình khác nhau. §23.3 gộp chúng thành **một binary Rust**, nên nếu chỉ đổi sơ đồ mà không đổi
> cách cưỡng chế thì A11 (chiếm indexer) lập tức bằng A10 (chiếm relay worker).
>
> Cái thay thế **mạnh hơn** cái nó thay: ranh giới do **Postgres** cưỡng chế, không do sơ đồ.

```
[ Browser / Mobile ]                       tin cay: 0
        | JWT bamboo_token_auth, call_kw + /json/2
        v
[ Odoo worker ]           <-- A4/A6 song o day. KHONG BAO GIO giu vat lieu khoa.
        | bang outbox trong Postgres, KHONG phai HTTP (§08.2b, §06.0.1)
        v
+--------------------------------------------------------------+
| LAN RELAY   scaas-node   (MOT binary, nhieu vai)             |
|                                                               |
|   [gateway] [mesh] [pool]     <-- A2/A3. Parse byte NGUOI LA. |
|   [submit]                    <-- A10. Nonce actor + journal. |
|   [indexer]                   <-- A11. Ghi `finalized`.       |
|                                                               |
|   HAI connection Postgres, HAI DB role. Xem bang duoi.        |
|   KHONG giu vat lieu khoa nao.                                |
+-----------------------------+--------------------------------+
                              | mTLS + tenant_uuid trong client cert
                              v
+--------------------------------------------------------------+
| LAN CUSTODY  scaas-node --role=custody                       |
|   NHOM A: sign_digest_secp256k1 / sign_raw_tx / attest        |
|   <-- A5 muon toi day. Enforce policy TRUOC khi ky.           |
+-----------------------------+--------------------------------+
                              | vsock.  CHI TON TAI KHI ZETHER BAT.
                              v
+--------------------------------------------------------------+
| LAN ORACLE (trong enclave)   scaas-node --role=oracle        |
|   ZetherKeyOracle < 300 dong. Giu `x`. Khong parser.          |
|   <-- bien khoa. A5 khong lay duoc `x`, nhung CO THE lam dung.|
+--------------------------------------------------------------+

        ^ 3 RPC provider doc lap (§06.7)   <-- A7
```

##### Bất biến, và cái gì cưỡng chế từng cái

| # | Bất biến | Trước: cưỡng chế bởi | **Bây giờ: cưỡng chế bởi** |
|---|---|---|---|
| 1 | Odoo không giữ vật liệu khoá | quy ước + grep gate CI | **không đổi** — grep gate: không file nào trong `dms_blockchain/` chứa `eth_keys`, `eth_account`, `coincurve`, `PKCS11`, `boto3.client('kms')` |
| 2 | Odoo không gọi thẳng signer | chỉ `relay-pool` có cert mTLS | **không đổi** — chỉ làn relay có cert. Odoo ghi outbox |
| 3 | Signer không tin `tenant_uuid` trong body | tiến trình riêng + mTLS | **không đổi** — làn custody **vẫn** là tiến trình riêng (§23.5) |
| 4 | **Indexer chỉ ghi ba bảng của nó** | **ranh giới tiến trình** | **DB role.** Vai `indexer` mở connection bằng role `scaas_indexer` với `GRANT INSERT/UPDATE` chỉ trên `blockchain_chain_event`, `blockchain_chain_effect`, `blockchain_transaction`. Vai `submit` dùng role khác |

Bất biến 4 là cái duy nhất thật sự đổi, và nó **mạnh lên**. Trước: một sơ đồ nói rằng indexer chạy
riêng, và không có gì chặn ai đó gọi thẳng. Bây giờ: Postgres từ chối `INSERT` vào
`blockchain_settlement` từ connection của indexer, bất kể code làm gì.

**Quy tắc rút ra, và nó nên là một dòng test:** mỗi vai khai báo tập quyền DB của nó, và binary
**từ chối khởi động** nếu một vai được cấp quyền ngoài tập đó. Gộp tiến trình được; gộp quyền thì
không.

##### Ba mũi tên đã bị xoá khỏi sơ đồ cũ

| Mũi tên cũ | Vì sao sai |
|---|---|
| `relay-pool → confidential-signer` để lấy `x` | **Node relayer không bao giờ cần `x`** (§23.2). Nó chỉ xin ký **vỏ tx** bằng `authKey`. Sơ đồ cũ làm người đọc tưởng ngược lại, và đó là nguồn gốc của câu hỏi "signer để làm gì" khó trả lời |
| `Redis` giữ nonce lease | Không còn Redis (§23.1). Nonce là biến trong một task `tokio` sở hữu duy nhất, journal ở Postgres |
| `intent-hub` là một tiến trình | Là vai `mesh` trong cùng binary |

#### 12.0.3. Bảng đối thủ (mở rộng từ 8 lên 13)

| # | Đối thủ | Năng lực giả định | Không có | Biện pháp chính |
|---|---|---|---|---|
| A1 | Người ngoài trên public chain | Đọc toàn bộ state + mempool, submit tx bất kỳ, trả gas không giới hạn hợp lý | Khoá của ai | Contract |
| A2 | Open relayer ác ý | Như A1 + nhận intent trước khi lên chuỗi, trì hoãn / bỏ qua / đảo thứ tự | Sửa được digest | 12.2, 12.4 |
| A3 | Hub operator | Như A2 + thấy toàn bộ intent flow, chọn người thắng exclusivity | Khoá của user | 12.4, đường thoát Enterprise Pool |
| A4 | Nhân viên nội bộ có `base.group_system` | **Bằng A5** — xem 12.6.1 | Khoá trong HSM/enclave | 12.6 |
| A5 | Kẻ chiếm được app server Odoo | Gọi tuỳ ý vào signer API bằng credential của service | Khoá raw | Policy phía signer (12.5) |
| A6 | Kẻ chiếm được admin key của contract | Upgrade, pause, đổi tham số | Khoá của user | Timelock 48h, guardian chỉ pause |
| A7 | Kẻ chiếm được RPC provider (hoặc chính provider nói dối) | Trả state giả, nuốt tx, giả lập receipt | Ghi lên chuỗi | 4 lớp của §06.7 |
| A8 | Supply chain toolchain contract (solc, foundry, npm, cargo) | Chèn bytecode khác với source | — | 12.7.3 |
| **A9** | **Insider của tenant khác** (Odoo multi-company) | Đọc/ghi record của mình, gọi mọi RPC method public | `signer_ref` của tenant khác | Rule `company_id` + `resolve()` phía signer |
| **A10** | **Kẻ chiếm `relay-pool` worker** | Nonce lease, chọn tx nào broadcast, đọc calldata trước khi lên chuỗi | Khoá; policy của signer | Signer policy là lớp cuối, không phải relay-pool |
| **A11** | **Kẻ chiếm indexer (hoặc chỉ ghi được bảng của nó)** | Đặt `finalized` cho một tx không tồn tại ⇒ Odoo `_set_done` ⇒ giao hàng | Ghi lên chuỗi | DB role hẹp + xác nhận 2 provider + hash check |
| **A12** | **Validator set của private chain** (chính ta, hoặc một nhà thầu) | Rewind, kiểm duyệt, đổi genesis, đổi precompile | Khoá của user | Anchor head hash sang HCS (§11.3), 4-eyes trên binary |
| **A13** | **Supply chain client SDK** (npm `@scaas/zether-sdk`, pypi) | Đọc `x` trong RAM của client, đổi `recipient` trước khi ký | — | 12.3.6 |

#### 12.0.4. Tài sản, xếp theo thiệt hại giảm dần, kèm giá trị quy ước

| Hạng | Tài sản | Thiệt hại nếu mất | Giá trị quy ước (giả định pilot) |
|---|---|---|---|
| 1 | `encKey x` của Zether + vault ERC-20 phía sau Z-token | Rút sạch vault; lộ toàn bộ lịch sử số tiền | = TVL. Pilot B2B giả định **$2M** |
| 2 | Admin/upgrade key (`DEFAULT_ADMIN_ROLE`, beacon owner) | Mint vô hạn, backdoor | = TVL + giá trị thương hiệu |
| 3 | Khoá auditor `x_audit` | Giải mã **toàn bộ lịch sử** mọi tài khoản, không hồi tố được | Bí mật giá cả của cả mạng lưới phân phối |
| 4 | Treasury EOA | Mất số dư treasury | Theo số dư, thường < $200k |
| 5 | Toàn vẹn của `blockchain.metatx.state = done` | Giao hàng mà không nhận tiền | = giá trị hàng chưa thu tiền trong 1 chu kỳ đối soát |
| 6 | Tính bí mật của số tiền | Đối thủ biết bảng giá | Không định giá được; là lý do tồn tại của Zether |
| 7 | Hot wallet gas | Mất runway 4h gas | < $2,000 |

#### 12.0.5. Sổ rủi ro ưu tiên (đọc bảng này trước, phần còn lại là chi tiết)

Xếp theo `likelihood × impact`, và cột cuối là thứ quyết định ngân sách.

| Hạng | Rủi ro | Khả năng | Thiệt hại | Biện pháp có tỷ lệ lợi ích/chi phí cao nhất |
|---|---|---|---|---|
| 1 | Fiat-Shamir yếu trong Bulletproof verifier tự viết | **Cao** (lớp bug phổ biến nhất của BP triển khai tay) | Mint vô hạn = 100% TVL | Audit mật mã Phase B + bộ negative test từng public input (12.3.2) |
| 2 | **Lặp nonce/randomness trong prover ⇒ lộ `x`** | Trung bình | 100% số dư của tài khoản đó | Nonce tất định RFC-6979-style + test known-answer (12.3.1) |
| 3 | `withdraw` proof không bind `chainId`/`address(this)` | **Đã xác nhận trong note** | Replay cross-chain, mất tiền thật | Sửa challenge (12.3.3) |
| 4 | A4/A5 lạm dụng HSM (không trích xuất khoá) | Trung bình | Treasury + upgrade | `SigningPolicyService` cùng phía signer (12.5.1) |
| 5 | RPC nói dối / indexer bị chiếm ⇒ `_set_done` sai | Trung bình | Hàng giao không thu tiền | 2 provider + hash + canary (12.7.1) |
| 6 | Rút sạch chậm qua một bug chưa biết | Trung bình | Toàn bộ TVL | **`WithdrawLimiter` on-chain** (12.11) — biến "mất tất cả" thành "mất 0.5%" |
| 7 | Upgrade key compromise | Thấp | 100% TVL | Timelock 48h + monitor `Upgraded` realtime |
| 8 | Toolchain/bytecode drift | Thấp | 100% TVL | `EXTCODEHASH` đối chiếu trước execute (12.7.3) |
| 9 | Precompile Go tự viết trên private chain sai | Trung bình | Chain halt hoặc accept proof giả | Audit riêng cho Go, differential test (12.1.1) |
| 10 | Rò rỉ đồ thị brand-distributor trên public chain | **Chắc chắn** (là thiết kế) | Tình báo cạnh tranh | Quyết định kinh doanh: ép B2B về private (12.12) |
---

### 12.1. Smart contract

| Vector | Kịch bản cụ thể trên thiết kế này | Biện pháp chốt |
|---|---|---|
| Reentrancy | `withdraw()` chuyển ERC-20 cho `recipient`; token có hook (ERC-777, hoặc underlying là contract) gọi ngược vào `transferConfidential` khi `zetherNonce` chưa tăng | CEI nghiêm: `zetherNonce++` và trừ `(C,D)` **trước** `safeTransfer`; `ReentrancyGuardTransient` trên mọi hàm đổi state tài chính; `MetaTxForwarder` tăng `batchNonce` trước inner call (§04.5, bước 5 trước 6) |
| Reentrancy **cross-function** | `withdraw` và `migrateAccount` dùng chung `(C,D)` nhưng khác guard | Một guard duy nhất theo **contract**, không theo hàm; test `ReentrancyCross.t.sol` gọi chéo từng cặp hàm đổi state |
| Upgrade key compromise (A6) | Đổi implementation của `ZTokenBase` sang bản có backdoor `mint()` | **[BẢN 3] Không còn áp dụng cho token đã deploy** — token do factory sinh ra là immutable (§20.2). Rủi ro chuyển sang factory: kẻ chiếm được `registerImplementation` đăng ký một implementation có backdoor và chờ người lạ chọn nó. Biện pháp: `registerImplementation` chỉ append, đi qua `TimelockController` 48h, và `deprecate` là cờ một chiều không xoá được bản đã đăng ký. `ZetherAccountRegistry` không upgradeable (§02.3) |
| Registry key swap | Nếu registry là UUPS, admin đổi `getPublicKey(addr)` sang khoá của mình; mọi khoản chuyển đến sau đó bị mã hoá dưới khoá attacker, nạn nhân không đọc được và không biết | Đã chặn bởi quyết định registry immutable + `successorAddr` set một lần qua `selfMigrate`. Đây là lý do kỹ thuật quan trọng nhất để **không** áp UUPS lên mọi contract như note yêu cầu |
| Storage collision trên proxy | **[BẢN 3] Không còn tồn tại.** Không có proxy, không có beacon, không có storage layout phải giữ tương thích giữa hai phiên bản. Một `ZETHER v2` là một contract mới, deploy cho token mới; token v1 đã tồn tại không bao giờ trỏ sang nó | CI gate `validateUpgrade` bị xoá cùng với cơ chế. Thứ thay thế: `implementation_codehash` ghi trong registry của factory phải khớp `EXTCODEHASH` đọc từ chuỗi (12.7.3) |
| Initialisation front-running | Factory `create2` rồi gọi `initialize()` ở tx thứ hai; A1 xen vào giữa, chiếm owner | Deploy + init **nguyên tử trong một call** của factory; `_disableInitializers()` trong constructor của implementation; salt = `keccak256(msg.sender, userSalt)` để không ai squat được địa chỉ đã predict (§1.4.3) |
| Unchecked delegatecall | Note (§TOKEN) yêu cầu "dùng cơ chế delegate để dùng chung code". Một `delegatecall(target, data)` với `target` do caller cung cấp = xoá slot 0, đổi owner | `delegatecall` **chỉ** tới địa chỉ lấy từ catalogue implementation của factory có `approved = true`; không `delegatecall` trong vòng lặp; CI grep chặn `delegatecall` ngoài 2 file được allowlist |
| `selfdestruct` làm brick proxy | **Sửa so với bản nháp**: sau EIP-6780 (Cancun), `SELFDESTRUCT` chỉ xoá code khi nằm trong **cùng tx với lần tạo**. Gnosis đã kích hoạt Dencun (2024), Celo là OP-stack post-Cancun ⇒ vector "brick implementation bằng selfdestruct" **đã chết trên cả hai chain mục tiêu** | Vẫn cấm `selfdestruct` trong implementation (chi phí bằng 0), nhưng đừng đưa nó vào hồ sơ rủi ro như một mối đe doạ sống. Rủi ro thật còn lại của delegatecall là **ghi đè storage + đổi owner** |
| ERC-20 approve race (nghĩa gốc) | Nạn nhân `approve(spender, 100)` rồi đổi ý `approve(spender, 50)`; spender front-run tx thứ hai, tiêu 100, rồi tiêu tiếp 50 = **150** | Không bao giờ dùng `approve` để đặt lại giá trị khác 0. Chỉ `approve(0)` rồi `approve(n)`, hoặc dùng `permit` (EIP-2612) có `deadline` và `nonce` |
| Approve race (dạng nguy hiểm hơn ở thiết kế này) | Hình thái `MetaTxForwarder` generic cần `approve`. `approve(forwarder, type(uint256).max)` + forwarder bị upgrade = rút sạch mọi người | Ưu tiên `ERC1776Native` mixin (không cần approve, §04.6.4). Nếu buộc dùng forwarder: EIP-2612 `permit` đúng số, có `deadline`; trần approve = `fee_ceiling × 30 ngày`; **forwarder không upgradeable**; `require(m.to != address(this))` và `!targets[to].isFeeToken` (§04.9) |
| `transferFrom` không trả `bool` | USDT trên nhiều chain không trả giá trị; `require(token.transferFrom(...))` revert nhầm hoặc bỏ qua thất bại | `SafeERC20` ở **mọi** chỗ, không ngoại lệ. CI grep chặn `.transfer(` / `.transferFrom(` thô trên kiểu `IERC20` |
| `ecrecover` trả `address(0)` | Chữ ký rác ⇒ `ecrecover` trả 0; nếu `from` chưa khởi tạo cũng là 0 thì so sánh bằng cho **pass** | `ECDSA.tryRecover` của OZ (đã reject `v` sai và `s` cao) + `require(signer != address(0) && signer == m.from)` |
| Fee-on-transfer | `WrappedToken.deposit(amount)` mint `amount` nhưng vault chỉ nhận `amount - fee`. FoT 1% trên vault $1M = lỗ hổng $10,000 và nó lớn dần | Đo delta thực: `received = after - before`, mint theo `received`; allowlist underlying kèm test `assertEq(received, amount)` khi onboarding |
| Rebasing token | `balanceOf(vault)` của stETH/aToken tự tăng giảm ⇒ invariant `totalSupply == balanceOf(vault)` sai mỗi ngày, không còn phân biệt được bug với rebase | **Cấm tuyệt đối** rebasing token cho archetype `WRAP_1_1`. Muốn hỗ trợ thì wrap bản share-based (wstETH) chứ không wrap bản rebasing |
| `decimals` khác nhau | Underlying 6 decimals (USDC) vs Z-token 18; `peg_ratio` nhân sai luỹ thừa ⇒ sai 10^12 lần | `decimals` đọc một lần từ underlying lúc `initialize` và **lưu immutable**; không đọc lại runtime (một token có thể nói dối hoặc đổi qua upgrade) |
| Precision / rounding drain | `peg_ratio` 1 DAI → 25,000 Z-VND, Zether dùng đơn vị cent (§03.2). Lặp deposit/withdraw dust để mỗi vòng ăn 1 cent | Làm tròn **luôn có lợi cho pool**: mint floor, burn ceil; `require(erc20Amount % 10**(decimals-2) == 0)` (§03.2); `MIN_WRAP = 100 cent`; invariant test `SupplyInvariant.t.sol` 50,000 run kiểm `vaultBalance >= totalSupply` sau mọi chuỗi thao tác ngẫu nhiên |
| Share-inflation / first-depositor | **Không áp dụng** — vault là 1:1, không phát hành share, không có `totalAssets/totalSupply`. Ghi ra đây để reviewer không phải hỏi | Nếu bao giờ đổi sang mô hình share (yield-bearing reserve) thì vector này quay lại và phải thêm dead-share |
| Gas-limit DoS của verifier | Nếu giữ Bulletproofs 128/128, verify **~3.87M gas** (§03.3.6) = **22.8% block limit Gnosis (17M)**. Đối thủ spam vài tx/block làm nghẽn chuỗi | Đã chốt: `n_v = 32`, `n_b = 64` ⇒ **~1.88M gas** contract-level, **1.72–2.62M** cả envelope (§04.10). Public profile đi Groth16/Baby Jubjub **~215k gas** (181k pairing + ~30k), **không phải 250–350k** — sửa so với bản nháp |
| Verifier tiêu gas rồi mới revert | Attacker gửi proof rác; contract chạy 1.5M gas MSM rồi revert ⇒ relayer mất tiền | **Thứ tự fail-fast bắt buộc**: (1) `status(from)==ACTIVE && status(to)!=NONE` (2 SLOAD ≈ 4.2k), (2) `zetherNonce` (2.1k), (3) on-curve + subgroup + reject identity (~1.5k), (4) `expiry`, (5) **rồi mới** MSM. Tỷ lệ: reject sớm **~1,000× rẻ hơn** reject muộn. Ghi thành test `VerifierFailFast.t.sol` đo gas của từng nhánh revert |
| Event thiếu ⇒ indexer phải đọc state | Reorg làm state-read sai, event thì không | Mọi thay đổi tài chính **phải** phát event mang đủ dữ liệu để dựng lại state, gồm `bytes32 ref` (§11.5 tầng 1). Test: chạy indexer chỉ từ log, không `eth_call` nào, phải đúng số dư |
| **[BẢN 3] Implementation giả mạo trong catalogue** | Factory mở: một người lạ đọc `implementations(ZETHER, 3)` và tin rằng nó là bản đã audit. Nếu kẻ tấn công đăng ký được một entry, mọi token deploy sau đó bằng version ấy đều có backdoor — và chúng **immutable**, không sửa được | `registerImplementation` sau timelock; mỗi entry ghi `audit_report_uri` + `audit_covers_code_hash`; §10.4.4 bắt Odoo so `EXTCODEHASH` on-chain với `audit_covers_code_hash` trước khi cho một token vào `accepted_token_ids`. Không có đường vá: một token đã mint bằng implementation xấu chỉ có thể bị **bỏ dùng**, và đó là lý do `MigrationSink` là artefact v1 chứ không phải v2 |

#### 12.1.1. Private chain: precompile Go là một bề mặt tấn công mới (bản nháp bỏ trống)

§03.3.9 chốt **native precompile trong go-quorum/geth-QBFT** để đạt ~500 tx/s. Đó là lựa chọn đúng, nhưng nó đổi bản chất rủi ro và không chỗ nào trong bản nháp nói điều đó:

| Rủi ro mới | Vì sao nó khác contract | Biện pháp |
|---|---|---|
| **Bug trong precompile = consensus bug** | Một revert sai ở Solidity chỉ hỏng một tx. Một kết quả khác nhau giữa hai validator làm **fork chain** | Mọi validator chạy **cùng một binary, cùng một hash**. Kích hoạt theo block number trong genesis, không theo flag. Đo hash binary vào monitoring |
| **Precompile trả `true` cho proof giả** | Không có lớp nào bên trên bắt được: contract tin nó tuyệt đối | **Differential test bắt buộc**: cùng `testvectors/zether_transfer_v1.json` chạy qua cả `BulletproofsVerifier.sol` và precompile Go, 100% khớp, gồm cả **negative vector**. Đây là lý do §03.3.9 giữ bản Solidity làm oracle |
| **Giá gas cố định sai** | Đặt 60,000 cho một phép tính 1 ms ⇒ một attacker mua được 1 giây CPU với giá 60k gas ⇒ DoS rẻ | Benchmark thực, nhân hệ số an toàn 3×, **và** đặt `blockGasLimit` sao cho worst-case block không vượt 500 ms CPU |
| **A12: validator là chính ta** | `block.timestamp`, thứ tự tx, và cả lịch sử đều do ta quyết | Anchor `head_hash` mỗi 15 s sang Hedera HCS (~$0.6/ngày, §11.3). Đó là thứ biến "tôi hứa" thành "có bằng chứng thời điểm" |
| Nâng cấp precompile | Đổi logic verify = đổi consensus = phải coordinate downtime | Hard-fork có lịch, `proofSystemId` đổi theo, contract chọn verifier qua `IZetherVerifier` chứ không hard-code địa chỉ |

**Lưu ý về chain 9000 thật:** chain private hiện có **không** phải go-quorum/QBFT mà là **Nethermind 1.39.0 + Clique, một signer, block 5 s, gasLimit 16,7M**. **[CẬP NHẬT 2026-08-31]** Nó **đã** được nâng lên Fusaka + BPO2 — EIP-2537, PUSH0, TSTORE/MCOPY, CLZ và precompile secp256r1 đều sống; base fee dính 0 nên gas vẫn miễn phí. Trước đó nó chạy pre-London vì genesis khai fork kiểu Geth mà Nethermind bỏ qua im lặng (xem `TRAPS.md` và `README-chainspec.md` của chain). Ba hệ quả: (1) precompile Go nói ở trên phải viết lại thành plugin Nethermind (C#) hoặc đổi client; (2) Clique **không có instant finality** và reorg được, nên A12 mạnh hơn bảng trên mô tả; (3) một signer duy nhất nghĩa là `finality_quorum = 2` không thoả mãn được — §09 đã ghi.

**Ngân sách audit riêng**: code precompile này **không** nằm trong phạm vi audit Solidity. Ước **$30k–60k** cho một review chuyên về implementation crypto + consensus integration (cơ sở: giá thị trường cho review 2,000–5,000 dòng code crypto, 2 tuần, 2 người). Bản nháp không phân bổ đồng nào cho nó.

---

### 12.2. Meta-transaction (EIP-1776)

> **[BẢN 3 — `_USER-DECISIONS.md` §24.]** Token tự hiện thực meta-transaction (native mixin);
> **không có forwarder**, không `to`/`data` tuỳ ý tới contract lạ, không `innerGasLimit`, không
> `feeToken`, không swallow mode. Ba lỗ hổng kinh điển của meta-transaction — return-bomb,
> 63/64 griefing, allowance drain — **mất đối tượng**; bảng đầy đủ ở `04-eip1776-metatx.md` §04.9
> (15 dòng xuống 6). Giữ tên chúng lại: một lỗ hổng biến mất vì cơ chế sinh ra nó biến mất là
> thông tin, không phải chỗ trống.
>
> Đồng thời `mode` **vẫn còn** (§04.4) — nó điều khiển `relayer` và `feeRecipient`, cộng nửa byte
> sau cho cách tính phí. Bản trước của mục này có chỗ nói `mode` đã chết; sai.


- **Replay cross-chain / cross-contract / cross-mode.** EIP-712 domain `{name, version, chainId, verifyingContract}` chặn hai cái đầu. Cái thứ ba chặn bằng việc `mode` nằm **trong** struct được hash (§04.4); bỏ `mode` ra là MODE_OPEN và MODE_RESTRICT_* với `relayer = 0` trùng digest. Domain separator phải tính lại khi `block.chainid` đổi (hard fork): dùng `EIP712` của OpenZeppelin (nó cache theo `address(this)` + `chainid` và tự tính lại), **không** hard-code separator vào `immutable`.
- **Digest injectivity — chỗ bản nháp chỉ nói một nửa.** Chặn replay chưa đủ; còn phải chặn **hai struct khác nhau cho ra cùng digest**. Lỗi kinh điển: `bytes data` không được `keccak256` trước khi đưa vào `abi.encode` của struct hash, khiến `("ab","c")` và `("a","bc")` trùng digest. Không fuzz nào tìm ra (xác suất 0), solver tìm ra trong vài giây. Bắt buộc property `check_digest_injective` bằng `halmos` (§14.9) — đây là property đáng giá nhất trong cả bộ formal.
- **Canonical zeroing.** Chữ "hoặc" trong note ("không bao gồm, **hoặc** hash với `address(0)`") là lỗi spec: hai cách cho hai digest. Chốt `_canon()` (§04.4), verifier tự chuẩn hoá, không bao giờ hash `m.relayer` thô. Một type string, hai giá trị canonical — không được tạo `TYPEHASH` thứ hai cho MODE_OPEN.
- **Malleability.** `ECDSA.tryRecover` (reject `s > n/2`, `v ∉ {27,28}`, reject `signer == address(0)`). Khoá idempotency phía Odoo là **EIP-712 digest**, không phải `keccak256(signature)` và không phải `keccak256(calldata)`: trong MODE_OPEN hai calldata khác nhau cùng verify với một chữ ký.
- **EIP-1271 là stateful, và đó là một cửa sổ tấn công.** Với smart account, `isValidSignature` có thể trả `true` lúc simulate và `false` lúc inclusion (đổi owner, revoke session key). Relayer mất gas, user mất 0 — đúng phía chịu, nhưng phải (a) `expiry` ngắn, (b) re-simulate tại block mục tiêu, (c) hub không trả bounty cho relayer trong trường hợp này. Ngược lại: một account có thể trả `true` **sau** khi đã revoke nếu implementation cache — không phải lỗi của ta, nhưng phải có trong danh sách kiểm tra khi allowlist một loại smart account.
- **EIP-7702 phá vỡ một giả định cũ.** Sau Pectra, một EOA **có thể có code**. Mọi kiểm tra dạng `require(from.code.length == 0)` hoặc `msg.sender == tx.origin` đều không còn nghĩa. Nếu contract nào trong `smartcontracts/` dùng một trong hai mẫu này thì phải bỏ. Grep gate CI.
- **Expiry bypass.** Validator lệch timestamp ±12s không đáng kể. Rủi ro thật là `expiry` quá dài: một metaTx ký với expiry 15 phút (con số trong note §10.3) cho relayer quyền giữ nó như một **free option**, broadcast khi có lợi cho relayer. Chốt theo §04.5: **60s cho Zether** (không phải 20s — epoch đã bị loại bởi owner-exclusive rollover), 120s cho call có đọc state, 300s cho ERC-20 transfer thường, 900s cho anchor/log. Check `expiry` phải nằm **trước** `nonce++` và trước thu fee: relayer trễ hạn thì revert, nonce không tiêu, fee không trả.
- **Thứ tự check là một quyết định kinh tế, không phải phong cách.** `relayer`, `validUntil` và `mode` tốn **0 gas**; `nonce` tốn 2.100 (cold SLOAD); chữ ký ~3.000. Kiểm cái miễn phí trước. Bản nháp đặt `nonce` trước `expiry` — sai thứ tự. Thứ tự chốt ở §04.6.1, và bước 3 (`validateMode`) phải kiểm **cả** bit lạ ở nửa byte đầu **và** giá trị phí lạ ở nửa byte sau.
- ~~**Relayer griefing** qua `innerGasLimit` / return-bomb / 63-64.~~ **Cả ba mất đối tượng.** Chúng chặn hệ quả của một opcode `CALL` tới contract lạ; không có `CALL` thì không có frame ngoài sống sót sau khi frame trong OOG, không có returndata của người lạ để bomb, và không có gas nào để giới hạn. Lý do đầy đủ ở §04.1. Bảng còn lại ở §04.9: 15 dòng xuống 6.
- **User griefing ngược lại relayer — CÒN, và là vector chính còn lại.** Không còn qua `innerGasLimit` (không có trường đó), mà qua việc **cố ý làm thao tác fail**. Hệ quả: cả tx revert, relayer mất gas, user mất 0 và **không lợi gì**. Chặn ở tầng vận hành: simulation gate bắt gần hết, phần còn lại vào `origin_grief_score` (§05.5). Với Zether nó đắt — proof rác đốt ~1,79 M gas **trước** revert — nên thứ tự fail-fast của §12.1 là bắt buộc chứ không phải tối ưu.
- ~~**Rút `approve` sau khi publish.**~~ **Mất đối tượng**: token trừ số dư nội bộ, không cầm allowance của ai. Nhưng **hình dạng** của tấn công còn — đổi thành *rút số dư sau khi publish*: attacker publish 100 intent hợp lệ rồi chuyển sạch số dư trong cùng block. Tỷ lệ thiệt hại vẫn 100:1, và biện pháp vẫn nguyên: `origin_grief_score` theo `m.from` (3 lần revert/24h ⇒ ép PoW + `max_inflight = 1`). Cái mất đi là *đường bản chất* — `permit`/Permit2 không cứu được, vì vấn đề không còn là allowance.
- **Cross-lane reordering.** `batchNonce` chỉ bảo đảm thứ tự **trong một lane**. Nếu Odoo đặt `escrow` và `settle` ở hai `batchId` khác nhau, relayer được phép đảo thứ tự. Quy tắc cứng phía Odoo (§15.2.1): mọi chuỗi phụ thuộc phải dùng **cùng một** `batchId` được dẫn xuất tất định từ `origin_key`; `_build_metatx` raise khi phát hiện một `origin_ref` sinh ra hai lane.
- **Lane exhaustion.** `batchId` là `uint256` ngẫu nhiên ⇒ không hết. Nhưng một lane **kẹt** (nonce đã cấp, tx không bao giờ lên chuỗi) khoá vĩnh viễn mọi giao dịch phụ thuộc. Phải có `lane_epoch++` (§04.3) và `bumpBatchNonce` on-chain; thiếu nó thì một tx treo làm chết cả chuỗi settlement và không ai gỡ được.
### 12.3. Zether

#### 12.3.1. Randomness — lỗ hổng nghiêm trọng nhất mà bản nháp không nhắc một chữ

Toàn bộ bảo mật của Zether nằm trên giả định rằng `r`, `s`, và nonce Schnorr `k` là **ngẫu nhiên và không bao giờ lặp**. Ba hệ quả nếu sai, tất cả đều là mất sạch tài khoản chứ không phải rò rỉ nhỏ:

| Lỗi | Toán học | Hậu quả |
|---|---|---|
| Lặp `k` giữa hai chữ ký Schnorr | `k = (z1 - z2)/(c1 - c2) mod q`, rồi `x = (z1 - c1·k)/1` | **Lộ `x` hoàn toàn.** Đây là lỗi đã giết Sony PS3 và nhiều ví Android |
| Lặp `s` giữa hai transfer cho **cùng** người nhận | `C1/C2 = g^(v1-v2)` ⇒ hiệu hai số tiền lộ ra; với một số tiền đã biết thì cả hai lộ | Lộ số tiền, phá bí mật |
| RNG yếu (seed theo `time()`, `Math.random()`, `/dev/urandom` trong container mới khởi động chưa có entropy) | Không gian tìm kiếm nhỏ | Brute-force ra `x` |

**Chốt, bắt buộc, và phải có test:**

1. **Nonce tất định kiểu RFC 6979 / synthetic nonce** cho mọi chữ ký Schnorr và mọi randomness của sigma proof:
   `k = HMAC-SHA512(key = x, msg = domain_sep || chainId || address(this) || zetherNonce || H(statement) || 32_byte_random)`, rồi reduce mod `q`. Kết hợp **tất định + entropy** (synthetic): tất định chặn lặp khi RNG chết, entropy chặn phân tích sai lệch theo fault injection.
2. **`s` của ElGamal không được tất định theo (v, y_recv)** — nếu tất định thuần thì hai lần chuyển cùng số tiền cho cùng người cho ra **cùng ciphertext**, lộ ngay. Phải thêm `zetherNonce` vào input HMAC. Đó là một khác biệt tinh tế giữa chữ ký và mã hoá mà nhiều implementation làm sai.
3. **Test bắt buộc** `test_no_nonce_reuse`: chạy 10,000 proof với RNG bị ép trả hằng số, assert rằng tất cả `k` và `s` vẫn khác nhau (vì đã có `zetherNonce` trong transcript). Và `test_extract_x_fails`: hai proof cho cùng `zetherNonce` phải **không thể** tạo ra (contract đã tăng nonce), và nếu ép tạo thì bộ test phải chứng minh không giải được `x`.
4. **Cấm dùng RNG của ngôn ngữ.** `Math.random`, `random.random()`, `rand()` bị CI grep chặn trong `smartcontracts/` và trong client SDK. Chỉ `getrandom(2)` / `crypto.getRandomValues` / `OsRng`.

#### 12.3.2. Proof forgery — rủi ro số 1, và nó là lỗi transcript chứ không phải lỗi toán học

Lớp bug phổ biến nhất của Bulletproofs triển khai tay là Fiat-Shamir yếu ("Frozen Heart"): thiếu một public input trong transcript là proof giả được. Transcript **bắt buộc** hấp thụ, đúng thứ tự, **đúng độ dài cố định, có domain separation và length-prefix**:

```
absorb("ZETHER_BP_V1")                 // domain, 12 byte co dinh
absorb_u64(chainId)
absorb_addr(address(verifier))
absorb_b32(proofSystemId)              // "BP_BN254_V1" | "G16_BJJ_V1" | "NATIVE_BP_V1"
absorb_b32(fromAddr); absorb_b32(toAddr)
absorb_u64(zetherNonce); absorb_u64(authEpoch)
absorb_point(C_transfer); absorb_point(D_transfer)
absorb_point(C_debit);    absorb_point(C_audit)
absorb_u256(fee); absorb_b32(feeRecipient)
absorb_b32(keccak(generators_blob))    // tap generator, KHONG hap thu tung diem
absorb_u64(deadline)
```

Ba quy tắc mà nếu thiếu thì transcript vẫn "trông như đúng":

- **Length-prefix mọi trường độ dài biến.** Nếu hấp thụ `bytes` thô, `("ab","c")` và `("a","bc")` cho cùng challenge. Đây là cùng một lớp lỗi với digest injectivity ở §12.2.
- **Hấp thụ `generators_blob` hash, không hấp thụ từng generator.** Vừa rẻ vừa chặn được "đổi generator" — một vector thật nếu generator đọc từ SSTORE2 (§03.3.5).
- **`proofSystemId` phải nằm trong transcript**, không chỉ trong interface. Ngược lại, một proof Groth16 có thể được trình cho verifier Bulletproof và ngược lại trong tương lai đa-verifier.

**[BẢN 3] Và với hai đường cong song song, `curveName()` phải nằm cùng chỗ.** Quyết định §20.1 cho phép cả bn254 lẫn BLS12-381 tồn tại trong cùng một factory. Hai verifier khác đường cong sinh hai không gian điểm khác nhau, nhưng một transcript chỉ hấp thụ `proofSystemId` mà không hấp thụ tên đường cong sẽ để hai hệ nói cùng một ngôn ngữ challenge. `IZetherVerifier.curveName()` và `g1EncodedBytes()` (64 với bn254, **128** với BLS12-381) phải đi vào transcript như hai trường riêng — không suy ra từ `proofSystemId`, vì `proofSystemId` do người đăng ký implementation đặt tên và không ai kiểm được.

Kiểm chứng: một file `smartcontracts/testvectors/zether_transfer_v1.json` dùng chung cho prover Rust, verifier Solidity **và** precompile native, cộng một bộ **negative test** đổi từng byte của từng public input và assert revert. Bộ negative test phải có **ít nhất một case cho mỗi trường** trong transcript ở trên (13 trường ⇒ >= 13 negative vector). **Không có bộ negative test này thì không được deploy.**

#### 12.3.3. Lỗi thật trong note: `withdraw` không bind chain

Note băm `recipient, amount, zetherNonce` vào challenge — đúng, chặn được relayer đổi `recipient`. Nhưng `schnorrAddress = keccak256(pkX, pkY)` **giống hệt nhau trên mọi EVM chain** (§02.8). Nếu cùng một tài khoản tồn tại trên Gnosis và Celo và `zetherNonce` tình cờ bằng nhau, một proof withdraw hợp lệ trên chain A replay được trên chain B. Phải thêm `block.chainid`, `address(this)` và `authEpoch` vào challenge. Đây là lỗ hổng mất tiền thật, không phải góp ý phong cách.

Hệ quả tương tự, và bản nháp cũng bỏ sót: **thiếu `address(this)` thì chữ ký/proof cho Z-USDC dùng được trên Z-VND** (§02.4.2 đã nêu cho `assertAuthorized`, nhưng điều đó phải áp cho cả Fiat-Shamir challenge của `transferConfidential`, không chỉ cho `withdraw`). Và note gốc băm `recipient` vào challenge cho `withdraw` nhưng **không** băm `feeRecipient` vào challenge cho `transferConfidential` — đó là một lỗ hổng anti-MEV thật: relayer đổi `feeRecipient` sang ví của nó.

**[BẢN 3] Trong factory mở, `address(this)` còn quan trọng hơn.** Có mười contract cùng tên `zDAI` do mười người tạo (§20.3). Một proof không bind `address(this)` là một proof dùng được trên cả mười — và chín trong số đó không phải tiền của người ký.

#### 12.3.4. Malformed ciphertext và điểm xấu

- alt_bn128 G1 có **cofactor 1** nên chỉ cần on-curve check; nhưng nếu chuyển sang **Baby Jubjub** (public profile, và §03.3.9 khuyến nghị dùng ngay từ đầu) cofactor là **8** ⇒ **bắt buộc subgroup check** (`[q]P == O`), không có ngoại lệ. Bỏ qua nó = small-subgroup attack, rò rỉ từng bit của `x`.
- **[BẢN 3] BLS12-381 G1 có cofactor khác 1** (`h = 0x396c8c005555e1568c00aaab0000aaab`), nên nhánh BLS **luôn** phải subgroup-check, không được sao chép logic của nhánh bn254. Precompile EIP-2537 tự làm subgroup check cho input của nó, nhưng điểm do client gửi lên và được lưu vào storage phải được check trước khi lưu — không phải trước khi tính.
- **Điểm identity phải bị reject mọi nơi**: `y = O` làm `C = g^v` (lộ thẳng số tiền), `D = O` làm giải mã tầm thường. Registry PoP (§02.2) đã chặn `y = O` lúc đăng ký; contract vẫn phải reject identity trong ciphertext — không được giả định input đến từ registry.
- **Invalid-curve**: điểm không nằm trên đường cong nhưng precompile vẫn tính (bn254 precompile của EVM tự reject, nhưng một implementation native tự viết thì **không** nếu quên). Test vector âm phải có cả điểm off-curve và điểm trong subgroup nhỏ.
- **`C_audit` phải được validate như mọi điểm khác.** Nó là đường lọt dễ nhất vì nó "chỉ để kiểm toán".

#### 12.3.5. Epoch race, và cái giá của quyết định owner-exclusive

Với thiết kế epoch gốc, xác suất lệch epoch giữa simulate và inclusion là đáng kể trên Gnosis (block 5s, epoch 5 block = 25s: một tx nằm ở 20% cuối epoch và chậm 1 block là lệch). Quyết định **owner-exclusive rollover** (§03.5) xoá hẳn vector này: `acc[from]` chỉ đổi trong tx của chính `from`.

Nhưng phải nói thẳng hai điều bản nháp không nói:

1. **Đó là một thay đổi tầng giao thức so với bài báo Zether.** Nó **không** được quyết bằng suy luận trong tài liệu này. Nó là mục trung tâm của audit Phase B. Nếu reviewer bác, thì `uint64 targetEpoch` quay lại struct **và** `expiry` của Zether tụt về <= 1 epoch — hai thứ đi cùng nhau (§04.10).
2. **Nếu deployment nào giữ thiết kế gốc**: thiếu `require(currentEpoch() == targetEpoch)` thì proof của epoch `e` mined ở `e+1` có thể **pass trên state cũ** nếu `rollOver` chưa chạy, và đó là **mất tiền** chứ không phải revert. Đây là khác biệt giữa "khó chịu" và "mất quỹ".

#### 12.3.6. Recipient DoS bằng pending flooding — kinh tế thực tế, sửa lại con số của bản nháp

Storage là O(1) nhờ tính đồng hình, nên chuỗi không sao. Nạn nhân là **client**: ví phải giải mã để giữ số cục bộ.

Bản nháp tính: `10,000 dust transfer × 60k gas ≈ 600M gas ≈ $0.60`, tỷ lệ thiệt hại 1,700:1, kết luận "kinh tế không chặn được". **Cả ba con số đều sai:**
| | Bản nháp | Đúng |
|---|---|---|
| Gas một Zether transfer | 60,000 | **1.72M–2.62M** (§04.10) |
| Tổng gas cho 10,000 tx | 600M | **~20 Ggas** |
| Chi phí tiền mặt (Gnosis @1.5 gwei, xDAI=$1) | $0.60 | **~$30** (và base fee sẽ tăng khi chiếm block) |
| Thời gian để land 10,000 tx | không tính | 20 Ggas ÷ 3.4 Mgas/s = **~98 phút ở 100% block space của cả Gnosis** |
| Thiệt hại phía nạn nhân | 17 phút BSGS | 17 phút, **hoặc ~0 nếu có memo (§03.2.5)** |

Kết luận đối chiếu: tỷ lệ thiệt hại không phải 1,700:1 mà vào khoảng **1:1 đến 10:1**, và tấn công bị chặn bởi chính block space chứ không bởi ví tiền. **Không** còn là "kinh tế không chặn được". Vẫn phải chặn, nhưng bằng thiết kế client chứ không bằng hoảng loạn:

- (a) Ví đọc `getPendingBalance` và BSGS **một lần trên tổng** khi số event chưa xử lý > 200, thay vì cộng dồn từng khoản. Với tính đồng hình đây là một phép giải mã, không phải N.
- (b) **Memo mã hoá số tiền** (§03.2.5) xoá bỏ BSGS hoàn toàn cho đường thông thường. Đó là biện pháp thực sự, (a) chỉ là dự phòng.
- (c) Indexer phía Odoo tính `pending_event_count` và cảnh báo (bảng 12.11 dòng 13).
- (d) **Không** thêm allowlist người gửi ở tầng contract — nó phá tính nhận tiền không cần xin phép và không giải quyết được gốc.

**Con số quan trọng hơn, và bản nháp không có nó:** nếu 10,000 tx rác chiếm 98 phút block space của Gnosis thì **chính hệ thống của ta bị DoS**, không phải một client. Xem 12.7.5.

#### 12.3.7. Rò rỉ metadata

Bốn đường, ba trong số đó phải chặn bằng quy tắc:

1. **Phí tuyệt đối không được là hàm của số tiền bí mật.** Nếu báo giá relayer theo phần trăm giá trị giao dịch (một quy tắc nghiệp vụ rất tự nhiên), `metaTx.fee` công khai **lộ chính xác số tiền**: `v = fee / 0.003`, một phép chia, phá huỷ toàn bộ Zether. Chốt: **phí phẳng lấy từ một thang rời rạc nhỏ** (ví dụ `{0.01, 0.05, 0.25, 1.00}` đơn vị), hoặc bậc thang theo `innerGasLimit`. Đây là ràng buộc **thiết kế contract**, không phải tuỳ chọn vận hành. Ghi vào `_build_zether_metatx` một assert **và** ghi vào `TargetPolicy` một `CalldataRule` (§04.10 mục 3). Trong `smartcontracts/src/common/FeePolicy.sol`, `requireConfidentialSafe()` revert thẳng trên `FeeMode.PERCENT` — quy tắc này đã là code, không còn là lời khuyên.
2. **Cấm cả hai kênh phí cùng > 0** (§04.10): thu phí hai lần, và hai con số công khai cùng lúc cho quan sát viên một hệ phương trình về cơ cấu phí. Enforce ở cả ba chỗ: builder Odoo, `ERC1776Native` mixin, `CalldataRule` của forwarder.
3. **`deposit`/`withdraw` công khai số tiền.** Một công ty nạp $250k rồi 3 transfer rồi rút $0 đã lộ tổng lượng. **Định lượng:** với thang 8 mệnh giá và < 5 tài khoản hoạt động mỗi epoch, tính ẩn danh của số tiền **sụp đổ gần như hoàn toàn** (§11.10). Giảm thiểu: giữ float làm việc, nạp theo lịch cố định và số tròn (bước $50k), không nạp "vừa đủ" ngay trước một lần thanh toán, và **dwell time tối thiểu** giữa deposit và transfer.
4. **Gas như kênh phụ.** Proof size cố định nên verify không lộ gì. Nhưng bất kỳ nhánh rẽ nào (`if (fee == 0)`, `if (feeRecipient == 0)`) làm gas khác nhau và rò rỉ một bit. Quy tắc: **thực thi phải cùng hình dạng** cho mọi input hợp lệ; test `GasUniformity.t.sol` đo gas của 3 nhóm input và assert lệch < 2,000 gas.
5. **`simulateAccounts` là một oracle** (bản nháp không nhắc). Nó là `view`, không tốn gas, không xác thực, và cho phép bất kỳ ai **liệt kê** tập tài khoản đã đăng ký và quan sát `pending` đổi theo thời gian thực. Đó không phải số tiền, nhưng nó là đồ thị + timing với độ phân giải cao hơn cả event. Không thể bỏ (client cần nó), nên: (a) chấp nhận trên public profile, (b) trên private profile đặt node RPC sau mTLS, (c) rate-limit ở RPC gateway.

#### 12.3.8. Danh tính công khai là thiết kế, nhưng hệ quả thì phải nói thẳng

Đối thủ đọc chuỗi biết **toàn bộ danh sách distributor** của một brand, biết khi nào một distributor bị cắt, biết tần suất thanh toán, và biết **lực lượng** (số transfer mỗi cặp mỗi kỳ). Đó là tình báo cạnh tranh, không phải số tiền. Trên public chain không có cách nào giấu đồ thị mà không quay lại mixer (đã bị loại theo yêu cầu AML). Nếu đồ thị là bí mật ⇒ B2B settlement **phải** chạy trên `chain_profile = private`. Đây là một quyết định kinh doanh, đưa vào mục 12.12.

Thêm một hệ quả pháp lý mà §02.7.6 đã chỉ ra và bản nháp 12 không nhắc: **lộ danh tính không làm thoả mãn FATF Travel Rule.** Rec.16 đòi thông tin originator/beneficiary **và số tiền**. Danh tính không kèm số tiền không đủ. Đó là lý do `C_audit` tồn tại và là lý do nó phải **bắt buộc** trên B2B, không phải tuỳ chọn.

#### 12.3.9. Khoá auditor `x_audit`

Nó giải mã được mọi giao dịch có `C_audit`, **cả lịch sử**, và một lần lộ là lộ vĩnh viễn (không có forward secrecy). Nó là mục tiêu giá trị cao hơn bất kỳ tài khoản đơn lẻ nào. Bắt buộc, theo §02.7.6:

- `y_audit` là khoá **threshold k-of-n** giữa n auditor (DKG Pedersen). Không tốn thêm gas on-chain (vẫn là một điểm G1); toàn bộ độ phức tạp nằm ở quy trình off-chain.
- Riêng theo **chain profile và theo pháp nhân phát hành**, không dùng chung một khoá toàn cầu.
- Lưu offline/HSM, tách hoàn toàn khỏi hạ tầng vận hành; không bao giờ nằm trong cùng tài khoản cloud với production.
- Xoay theo kỳ (đề xuất 12 tháng), **xoay không làm mất hiệu lực lịch sử** — ciphertext cũ vẫn dưới khoá cũ ⇒ phải lưu trữ khoá cũ theo lịch lưu hồ sơ, không huỷ.
- Giá thực: `C_audit` + equality proof Chaum-Pedersen = **~25,300 gas/transfer (~+11%)**, không phải 13,200 như một bản nháp trước ghi (§02.7.6 đã sửa).

**[BẢN 3] Trong factory mở, `C_audit` là tuỳ chọn của người tạo token, không phải của ta.** §20.5 đã ghi: `compliance_profile` rời khỏi đường tới hạn. Một người lạ wrap xDAI thành zDAI-B mà không bật `C_audit` thì token đó không dùng được cho B2B của ta — và đó là toàn bộ hệ quả. Không có cơ chế nào ép được, và cũng không nên có: factory chỉ deploy, thị trường chọn.

#### 12.3.10. Client SDK (A13) — vector mà bản nháp bỏ hoàn toàn

`x` sống trong RAM của client. Kẻ chèn được một dòng vào `@scaas/zether-sdk` hoặc vào một dependency của nó lấy được `x` của **mọi** người dùng, không cần chạm chain, không chạm Odoo, không chạm HSM. Đó là đường rẻ nhất trong cả mô hình này.

| Biện pháp | Cụ thể |
|---|---|
| Pin và lock | `package-lock.json` commit, `npm ci --ignore-scripts`, cấm `postinstall` |
| Tối thiểu hoá dependency | Prover Rust biên dịch sang WASM, chỉ lộ một mặt cắt API. Mục tiêu: **< 10 dependency trực tiếp** cho đường chạm `x` |
| Subresource Integrity | Web client tải SDK bằng `<script integrity="sha384-...">`, không bao giờ từ CDN không pin |
| Reproducible build + ký | Artifact WASM có hash công bố; client kiểm hash trước khi nạp. Ký bằng khoá release riêng, không phải khoá CI |
| Tách `x` khỏi UI | Prover chạy trong Web Worker / enclave, UI không bao giờ đọc được `x`. Không xoá được XSS nhưng nâng chi phí khai thác |
| `recipient` phải hiển thị từ **dữ liệu đã ký** | Client render `to` từ chính struct sắp ký, không từ biến state khác. Chặn "UI hiện A, ký B" |

---

### 12.4. Mạng lưới relayer

| Vector | Đánh giá | Biện pháp |
|---|---|---|
| Sybil | Chi phí tạo intent giả ~50 µs (một ECDSA) vs 15–40 ms simulate (**60–150 ms** nếu Zether) ⇒ tỷ lệ **500:1**, lên **~3,000:1** với Zether | 6 tầng của §5.5. **Sửa so với bản nháp:** tầng 0 (IP) phải ở **nginx `limit_req`**, không trong Odoo (mỗi worker là một process, bộ đếm trong biến module đếm sai theo hệ số `workers`); tầng 1 (`from`) ở Redis |
| PoW | Bản nháp ghi "PoW 20 bit ở tầng 3" | **Sửa:** 20 bit ≈ 1M keccak ≈ **5 s trên Android tầm trung** — không chấp nhận được cho app bán hàng. Mobile luôn đi đường **JWT `bamboo_token_auth`** (§5.5 lựa chọn c). PoW chỉ cho người lạ hoàn toàn, và khi buộc phải có trên mobile thì **16 bit** (~0.3 s). `blockchain.intent.pow_bits` là config, tăng tự động khi hàng đợi simulate > 500, **tắt hoàn toàn khi private profile** |
| Storage DoS | Botnet 10,000 địa chỉ × 10 intent/phút = 1,667 intent/s × 1.5 KB = **216 GB/ngày** nếu persist | **Không persist gì trước tầng 3.** Intent sống trong Redis `TTL = expiry - now`. Chỉ qua tầng 4 mới `create()` row `blockchain.metatx` |
| Intent theft | **Không thể** — digest chặn sửa nội dung; `feeRecipient` là thứ duy nhất đổi được và nó đang trả cho chính nó | Không cần thêm |
| Fee front-run giữa N relayer | Kẻ thua revert, EV giảm về ~18% khi N=5 | Soft-exclusivity **W = 3s trên Gnosis, và W = 0 cho `is_zether`** (§5.4.4a — bản nháp bỏ mất vế thứ hai) + lottery |
| **Lottery weighting** | Bản nháp ghi `sqrt(stake) × reputation`. **Sai, và sai theo hướng nguy hiểm** | §5.4.4a đã bác: với trọng số căn bậc hai, tách stake `S` thành `k` danh tính cho tổng `sqrt(k)·sqrt(S)` — **thưởng sybil `sqrt(k)` lần miễn phí** (k=100 ⇒ 10×). Trọng số căn bậc hai chỉ có nghĩa khi có registry danh tính duy nhất; ở đây không có. **Chốt: trọng số tuyến tính × reputation, `MIN_BOND` ~$500, `CAP_SHARE = 0.20`, `REP_FLOOR = 0.10`** |
| Kiểm duyệt của một relayer | Hub re-publish sau `W` | Reputation EWMA |
| **Kiểm duyệt của toàn bộ hub** (A3) | Note không xử lý | Đường thoát bắt buộc: `blockchain.relay.job` chuyển sang **Enterprise Relay Pool** nội bộ bằng một cờ switch; **drill blackout hub hàng tháng**, đo thời gian chuyển mạch. Đường thoát không được kiểm thử là đường thoát không tồn tại |
| Rò rỉ dữ liệu qua intent bus | §5.4.5: `MODE_OPEN` = mọi người đọc được calldata **trước** khi lên chuỗi. Với ERC-20 B2B đó là **toàn bộ** giao dịch | Private profile: bus chỉ nghe nội bộ, **mTLS hai chiều, không federation**. Public profile: `blockchain.chain.max_public_intent_value_base` — builder từ chối publish `MODE_OPEN` khi `amount > ngưỡng` và không confidential |
| MEV sandwich quanh deposit/withdraw | Với `WRAP_1_1` không có giá ⇒ không sandwich được. Với `PeggedToken` **có**: front-run một lần cập nhật rate | `minAmountOut` trên mọi phép quy đổi peg; `SignedRateSource` k-of-n publisher, `maxRateAge = 3600s`, `maxDeviationBps = 200`/lần cập nhật, **halt mint (không halt burn)** khi lệch > 500 bps |
| MEV trên `withdraw` Zether | `recipient` đã băm vào Fiat-Shamir ⇒ không đổi được. Nhưng **`amount` của withdraw là plaintext**, nên một withdraw lớn vẫn là tín hiệu giao dịch cho kẻ khác | `blockchain.rpc.endpoint.propagation`: tx có `mev_sensitive=True` chỉ gửi tới endpoint `private orderflow`, **không fan-out** (§06.7.2 quy tắc 3). Bản nháp bỏ mất quy tắc này |
| Slashing | v1 **không có**. Xây adjudication on-chain cho khiếu nại $0.005 là vô lý (§5.6) | `UNBOND_PERIOD = 7 days` để chặn bond-chiếm-lottery-rút. Bond bằng **native của chain (xDAI)**, không bằng enterprise token — bond bằng token mình in ra không phải là stake |
| Relayer đọc bus để thu thập tình báo thương mại | **Có thể**, và không slashing nào chặn được | Chặn bằng **quyền truy cập bus** (mTLS, NDA cho `MODE_RESTRICT_RELAYER`), không bằng tiền |
| **[BẢN 3] Node trong mesh mở nhận vai trò nó không nên có** | §21.4: một node cấu hình sai có thể vừa là pool công khai vừa cầm khoá submit, và forward intent của người khác trong khi tự race chúng lên chuỗi | Ma trận năng lực phải **evaluate được trước khi simulate**, và thuật toán submit-vs-forward là forward **kèm `exclusive_until`**, không phải forward-rồi-đua. Pool thuần chấm điểm bằng **forward hữu ích** (intent sau đó lên chuỗi), không bằng lưu lượng — nếu không, spam forward là chiến lược tối ưu |
| **[BẢN 3] Key pool bị dùng để né rate limit hoặc né reputation** | §21.5 cho một node xoay nhiều khoá ký để không nghẽn ở nonce tuần tự. Cùng cơ chế đó cho phép một node xấu xuất hiện như N relayer | Khoá trong pool **không phải danh tính**: `feeRecipient` cố định và tách khỏi khoá ký, reputation chấm theo `relayer_id` chứ không theo địa chỉ gửi. Khoá chỉ trả gas, giữ float nhỏ, không giữ vai trò nào trong contract — nên N khoá **an toàn hơn** một khoá, và đồng thời không mua được N phiếu |

---

### 12.5. Custody

#### 12.5.1. HSM không biết nó đang ký cái gì

Đây là hiểu lầm nguy hiểm nhất quanh yêu cầu "FIPS 140-2 L3". Một HSM PKCS#11 ký bất kỳ 32 byte nào bạn đưa vào. A5 chiếm được app server thì ký được một tx rút sạch treasury **mà không cần trích xuất khoá**. **FIPS L3 chống trích xuất khoá, không chống lạm dụng khoá.**

Biện pháp: **policy phải nằm cùng phía với signer**, không nằm trong Odoo. Bản nháp đúng ở kết luận nhưng hand-wave ở cơ chế. Cụ thể:

```python
# confidential-signer/policy.py  — chay TRONG enclave, truoc moi lan ky
def authorize(tenant_uuid: str, signer_ref: str, payload: bytes) -> None:
    tx = parse_typed_tx(payload)          # BAT BUOC ho tro type 0x00,0x01,0x02,0x03,0x04
    assert signer_ref.startswith(f"blockchain/{tenant_uuid}/")   # §07.11
    assert tx.chain_id in ALLOWED_CHAINS[tenant_uuid]
    assert tx.to in ALLOWLIST[tenant_uuid][tx.chain_id]
    assert tx.selector in ALLOWED_SELECTORS[tx.to]
    assert tx.value <= VALUE_CAP[signer_ref]
    assert hourly_spend(signer_ref) + tx.value <= HOURLY_CAP[signer_ref]
    assert tx.nonce == expected_nonce(signer_ref)   # signer giu nonce, KHONG tin caller
    assert digest_not_seen(sha256(payload))         # chong replay VAO signer
```

Sáu điểm mà nếu thiếu thì lớp này chỉ là trang trí:

1. **Parse được mọi tx type, kể cả `0x04` (EIP-7702 SetCode).** Một payload type 4 ký được sẽ gắn code vào EOA của treasury. Nếu parser không biết type 4, mặc định phải là **từ chối**, không phải bỏ qua.
2. **Signer tự giữ nonce.** Nếu nó tin `tx.nonce` do relay-pool gửi thì A10 ký được hai tx cùng nonce (một cho ta, một cho nó) và thay thế trong mempool.
3. **Chống replay vào chính signer.** Cùng một payload gửi hai lần phải bị từ chối; nếu không, A10 tua lại một lệnh rút hợp lệ.
4. **Enclave image được pin.** Trên AWS: `kms:Decrypt` với tham số `Recipient` (attestation document COSE_Sign1 ký bởi Nitro PKI) và key policy điều kiện trên `kms:RecipientAttestation:PCR0` / `ImageSha384`. Kết quả: **chỉ đúng một image, đo bằng hash, mới unwrap được `x`**. Root trên EC2 host cũng không đọc được. Trên GCP: Confidential Space + attribute condition trên `submods.container.image_digest`.
5. **Đổi image là một sự kiện governance, không phải một lần deploy.** Pin PCR0 nghĩa là mọi bản vá đều phải được thêm vào key policy — đó là cố ý. Phải có runbook, 2 người duyệt, và monitoring trên thay đổi key policy.
6. **Rollback protection.** Nếu key policy còn cho phép PCR0 cũ, một attacker chạy lại image cũ có bug. Chính sách: giữ **tối đa 2 PCR0** (hiện tại + bản trước, để rollback khẩn), xoá cái thứ ba.

Và một câu phải viết vào hợp đồng khách hàng: **ở mô hình này `x` không nằm trong biên FIPS 140-2 Level 3 tại thời điểm sử dụng.** Nitro Enclave / Intel TDX không có chứng nhận FIPS L3 cho vai trò này. Nếu một cơ quan quản lý đòi FIPS L3 cho khoá mã hoá số dư, câu trả lời trung thực là yêu cầu đó **hôm nay không thoả mãn được với Zether** (§07.2).

#### 12.5.2. Hai lớp khoá, và chỗ note sai

Note yêu cầu mọi private key nằm trong HSM/MPC. **Một HSM PKCS#11 không tính được Bulletproof/ElGamal**: `encKey x` phải ở trong process prover, được dùng liên tục. (Chi tiết kỹ thuật: `CKM_ECDH1_DERIVE` *là* phép nhân vô hướng, nhưng không HSM nào có OID cho BN254/Baby Jubjub, và hàng nghìn round-trip PKCS#11 cho một transfer là vài giây — §07.2.)

| Lớp khoá | Dùng để | Nơi sống | Ai duyệt | Throughput |
|---|---|---|---|---|
| `authKey` treasury / contract admin | Đăng ký implementation, pause, refill, mint | HSM FIPS L3 hoặc MPC, **dual control** | Governance Safe | 10^3/s (không cần) |
| `authKey` relayer hot | Ký vỏ tx của relayer EOA | Nitro Enclave / SGX, **xoay 30 ngày** (không phải mỗi giờ — sửa so với bản nháp, §06.5.1), runway 4h | Ops | 10^4/s |
| Session key của Agent | Ký `MetaTransaction` | Enclave hoặc secure element của thiết bị | Policy on-chain | — |
| **`encKey x` (Zether)** | Giải mã số dư, dựng proof | Enclave; hoặc MPC threshold ElGamal (chi phí ký cao); tối thiểu là DEK wrap bởi KMS, giải trong RAM, **không bao giờ persist** | Bắt buộc backup Shamir 2-of-3 **trước khi mở tài khoản đầu tiên** | 1 proof/200–800 ms |

**Nút cổ chai phải biết trước:** MPC SaaS cho **5–30 sign/s và p50 300 ms – 3 s** cho một vault (§06.6). Nếu mỗi business action = 1 chữ ký thì trần hệ thống là 5–30 action/s — thấp hơn cả chuỗi. Đường ra là `MetaTxBatcher.executeBatch` (1 chữ ký HSM cho N=50 meta-tx) chứ không phải thêm EOA. Nhưng batcher **mở ra một vector mới**: một item hỏng kéo cả batch chết, và một relayer có thể đốt nonce của user. Ba ràng buộc bắt buộc lên batcher (§06.6): `require(gasleft() >= g + g/63 + 12_000)` trước mỗi item; **không** revert cả batch khi một item fail; thu fee **trước** inner call.

**[BẢN 3] Batching và key pool giải hai nút thắt khác nhau, và cần cả hai.** Batching gộp N công việc vào một chữ ký — chỉ làm được khi **ta tự sinh cả N** (§06.6.1: 6 EOA là đủ). Key pool (§21.5) giải nút thắt **nonce tuần tự của EVM**: một khoá ký được khoảng một tx mỗi block dù ký nhanh đến đâu. Một node relayer mở nhận việc của người lạ không batch được, nên nó cần 50 khoá. Hai con số không mâu thuẫn nhau; chúng trả lời hai câu hỏi.

#### 12.5.3. Session-key over-scoping

Một session key với `to = MetaTxForwarder` và calldata tự do là **toàn quyền**. Scope phải là `(chainId, target, selector, tokenContract, cumulative_value_cap, expiry, batchId range)` và phải được enforce **on-chain** bởi smart account, không chỉ trong Odoo — vì A5 và A10 đi vòng qua Odoo được.

Bốn quy tắc thêm:

- **`authEpoch` phải nằm trong digest** (§02.4.2). Thiếu nó thì xoay khoá không vô hiệu hoá chữ ký cũ, và toàn bộ cơ chế thu hồi là trang trí.
- **Cumulative cap phải on-chain**, không phải per-tx cap. Một trần $1,000/tx với 500 tx là $500,000.
- **Thời hạn 1–8 giờ**, và revoke phải là một lệnh **on-chain** (`authEpoch++`), không phải một cờ trong Odoo.
- **Không pre-sign hàng loạt theo nonce** (§06.6.4): một kho tx đã ký trong Redis là một kho tiền ai đọc được Redis cũng phát sóng được, và không huỷ được. Ngoại lệ duy nhất được xem xét là **một** tx cancel (self-send, 21,000 gas) cho mỗi nonce inflight, lưu trong enclave chứ không trong Redis, và mặc định **tắt**.

#### 12.5.4. Custodial mode và rủi ro nội bộ

**Custodial mode**: omnibus `schnorrAddress` chung ⇒ operator thấy mọi số tiền của mọi khách, và sổ phụ Odoo trở thành nguồn sự thật duy nhất. Về mặt pháp lý đó là **nhận giữ tiền của người khác** (§13.4). Ghi rõ trong tài liệu deploy; không bật mặc định.

**Insider risk, cụ thể chứ không chung chung:**

| Kịch bản | Chặn bằng |
|---|---|
| Một kỹ sư có cả quyền deploy và quyền duyệt | Tách `DEPLOYER_ROLE` (service account) khỏi `PROTOTYPE_ADMIN` (Safe 3-of-5) — §1.11. Người không được ở cả hai |
| Người giữ treasury cũng là người duyệt relayer | `group_blockchain_treasury` và `group_blockchain_relayer_admin` **không bao giờ** cùng một user; test ACL assert giao rỗng (§10.5) |
| Nhân viên nghỉ việc vẫn còn quyền | Offboarding checklist có: xoá khỏi Safe (on-chain tx!), xoay `authEpoch`, thu hồi client cert mTLS, xoay credential RPC. Cron đối chiếu `getOwners()` của mọi Safe với `blockchain.governance.signer` **hàng ngày** (§1.11.1 mục 2) |
| Break-glass bị lạm dụng | Mỗi lần dùng khoá break-glass phát event on-chain + page toàn đội + post-mortem bắt buộc, kể cả khi hợp lệ |

---

### 12.6. Tầng Odoo
```python
@api.model
def relay_submit_intent(self, caip2, target_address, calldata_hex, ...):
    # 1. KHONG sudo() o day. sudo() trong entry point RPC = bat ky user noi bo nao
    #    cung dieu khien duoc quy gas cua doanh nghiep.
    self.check_access('create')          # check_access mang @api.private => khong goi duoc qua RPC
    if not self.env.user.has_group('dms_blockchain.group_relay_submitter'):
        raise AccessError(_('Khong co quyen gui intent.'))
    # 2. Allowlist target o server, khong tin client.
    self._assert_target_allowed(caip2, target_address, calldata_hex[:10])
    # 3. Velocity theo user, khong theo IP (IP la nginx lo).
    self._assert_velocity(self.env.user.id)
    # 4. Cong ty lay tu env, KHONG bao gio tu payload.
    return self._submit_intent(self.env.company, ...)   # logic private
```

#### 12.6.1. `base.group_system` = RCE trong process Odoo (sửa một sai lầm của bản nháp)

Bản nháp tách A4 (`base.group_system`) và A5 (chiếm app server) thành hai mức độ khác nhau. **Trên Odoo đó là một.** Một user `base.group_system` có thể tạo `ir.actions.server` với `state = 'code'` và chạy Python tuỳ ý **trong chính process Odoo**, với mọi biến môi trường, mọi socket, mọi credential mà process đó có. Cũng như vậy với `base.automation`, với `ir.cron` (`state='code'`), và với cài đặt một module tuỳ ý.

Hệ quả, phải viết ra chứ không được để người đọc tự suy:

1. **Mọi biện pháp dựa trên "chỉ group_system mới đọc được" đều bằng không.** `ir.config_parameter` chỉ là một ví dụ; kể cả `fields.Char(groups=...)` cũng không chặn được A4 vì A4 chạy code, không gọi `read()`.
2. **Do đó policy signer phải ở ngoài Odoo** (12.5.1). Đó không phải "defense in depth", đó là **duy nhất** lớp còn lại khi A4 xuất hiện.
3. **Danh sách người có `base.group_system` phải ngắn và phải được review định kỳ** như danh sách signer của Safe. Trong Odoo 19, kiểm bằng `group_ids` (không còn `groups_id`).
4. **Monitoring bắt buộc**: bất kỳ `create`/`write` trên `ir.actions.server`, `base.automation`, `ir.cron`, `ir.model`, `ir.model.fields` đều là sự kiện bảo mật, không phải sự kiện cấu hình (bảng 12.11 dòng 12).
5. Câu hỏi còn lại cho người quyết: `base.group_system` có nằm trong biên tin cậy không. Hiện tại **có** — và đó là một lựa chọn, không phải một sự thật.

#### 12.6.2. Bảng vector tầng Odoo

| Vector | Cụ thể | Biện pháp |
|---|---|---|
| Record-rule bypass | Rule dùng `('organization_id', 'child_of', ...)` trên một Char `parent_path` ⇒ `ValueError`, và ở Odoo 19 một rule lỗi làm **mọi** search raise (bẫy §2 CLAUDE.md). `dms_blockchain` không có `organization_id`; dùng `company_id` many2one + `('company_id', 'in', company_ids)` | Guard CI đã có; thêm test đọc/ghi chéo company cho **từng** model `blockchain.*` (A9) |
| Rò rỉ qua `read_group` / `search_read` | Rule lọc **dòng**, và `read_group` vẫn bị rule chặn — nhưng một `read_group` trên `amount_base` của model không company-scoped (`blockchain.transaction`, §10.9) lộ tổng hợp cho tenant khác | `blockchain.transaction` phải có rule gián tiếp `['|', ('settlement_ids','=',False), ('settlement_ids.company_id','in',company_ids)]`. Test: user công ty A `read_group` không thấy tổng của B |
| Rò rỉ cột, không phải dòng | Rule không lọc cột. `signer_ref`, `endpoint_ref`, `pow` của account | `fields.Char(groups='dms_blockchain.group_blockchain_manager')` — **Odoo thực sự chặn ở `read()`**, khác hẳn `password=True` vốn không tồn tại ở Odoo 19 và chưa bao giờ chặn `read()`/RPC/export |
| RPC lộ method nguy hiểm | Bất kỳ method không `_` và không `@api.private` đều gọi được qua `call_kw` **và** `/json/2` | Quy tắc cứng: **không method public nào được gây ra một chữ ký HSM đồng bộ**. Ký chỉ xảy ra trong cron/worker, trên record đã ở state được rule cho phép. Test liệt kê mọi method public của `blockchain.*` và assert nó nằm trong allowlist đã review (§10.6) |
| Nhận `allowed_company_ids` từ client | Một method public nhận `company_id` là một lỗ hổng leo thang phạm vi | `self.env.companies` do session/JWT quyết định, và `Environment.companies` raise `AccessError` với company ngoài `_get_company_ids()` — client thu hẹp được, không mở rộng được (§10.6.2). Grep gate: không signature nào của method public chứa `company_id` hay `allowed_company_ids` |
| `ir.config_parameter` đọc được bởi `base.group_system` | `get_param` gọi được qua RPC; **và** dump DB chứa nó nguyên vẹn | Chỉ lưu **handle** (`signer_ref`, `url_ref`, `key_ref`). Bí mật thật nằm trong biến môi trường / file đọc lúc khởi động (`odoo.tools.config`) hoặc secret manager. §06.7 đề nghị lưu URL RPC **kèm API key** trong `ir.config_parameter` — **đó là rò rỉ credential tới mọi Settings admin và tới mọi bản backup**, phải sửa |
| Backup DB và filestore | Một bản dump `.sql` là một bản sao của mọi `ir.config_parameter`, mọi `res.users.password` hash, mọi attachment metadata | Backup mã hoá at-rest, khoá nằm ngoài Odoo; **không bao giờ** restore production dump lên staging mà không chạy script scrub (`ir.config_parameter` `blockchain.*`, `ir.mail_server`, `fetchmail.server`) |
| Rò rỉ qua log | Traceback của `requests` in cả URL kèm query string; một API key trong URL vào thẳng `ir.logging` và vào Sentry | Credential không bao giờ ở query string; `logging` filter cho `Authorization`; `ir.logging` retention 30 ngày |
| SQL injection | Indexer xử lý reorg thường viết raw SQL có tên bảng động | Dùng `odoo.tools.SQL` (Odoo 17+ có object này và `cr.execute` nhận trực tiếp) hoặc `cr.execute(query, params)` với `%s`; tên bảng động dùng `SQL.identifier(...)`; **cấm f-string trong `execute` bằng một grep gate trong CI** |
| Privilege escalation qua `sudo()` | `sudo()` để ghi audit row rồi vô tình dùng `self` đã sudo cho cả nhánh nghiệp vụ | `sudo()` chỉ trên một recordset **mới lấy lại** (`self.env['x'].sudo().create(...)`), không bao giờ trên `self`; mọi `sudo()` phải có comment một dòng lý do; CI đếm số lần `sudo()` và fail khi tăng mà không có review |
| `ir.attachment` của audit report / proof blob | Attachment `public=True` hoặc lộ `access_token` ⇒ báo cáo kiểm toán reserve đọc được bởi bất kỳ ai. Chúng nằm trên Garage (S3) | `public=False`, `res_model`/`res_id` trỏ đúng record, không sinh `access_token`; bucket Garage **không** public-read; presigned URL TTL <= 15 phút |
| Consumer suy sai trạng thái | `payment.transaction._set_done()` gọi từ `mined` | `_set_done()` **chỉ** khi `blockchain.metatx.state == 'done'` (finalized **và** `innerSuccess = true`), rồi `_post_process()`. `_set_pending()` cho mọi trạng thái trước đó. Với hoàn tiền: settlement mới + refund tx, **không** `_set_canceled()` trên tx cũ (§10.8) |
| **Đường ghi `done` không được kiểm soát** (bản nháp thiếu) | Ngoài Finality Gate còn: sửa tay trên UI, `sudo()` trong bridge, script migration, A4 | Guard trong `write()`: chuyển sang `done` chỉ hợp lệ khi context mang **sentinel object** của module (không phải một khoá boolean client gửi được) và caller là cron; mọi chuyển trạng thái ghi một dòng vào `blockchain.settlement.transition` (append-only, không `unlink`); monitoring dòng 12 cảnh báo khi có `done` không kèm transition row |
| Trap Odoo 19 | `_sql_constraints` dạng list bị bỏ qua hoàn toàn ⇒ tưởng có UNIQUE mà không có ⇒ double-spend theo digest | `models.Constraint('UNIQUE(metatx_digest)', ...)` + test tích hợp `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_metatx'::regclass;` |
| Trap Odoo 19 (2) | Stored computed field không được nhận `default`; một nhánh compute không gán gì ⇒ cột `required` bị NULL ⇒ INSERT chết | Áp dụng cho `lane_slot` (§04.3) và mọi compute stored của `blockchain.*`: **mọi nhánh phải gán giá trị** |
| Bridge làm rò rỉ ngược | `dms_blockchain_bridge` depend `dms`; một rule của `dms` bị lỗi làm hỏng cả `blockchain.*` | Core `dms_blockchain` **không** depend `dms` (locked #7). Test: cài đặt core trên một DB không có `dms` và chạy full test suite |

---

### 12.7. Vận hành

#### 12.7.1. RPC nói dối (A7) và indexer bị chiếm (A11) — đường mất tiền lớn nhất ngoài smart contract

Một provider bị chiếm trả về một receipt cho tx chưa bao giờ tồn tại ⇒ Finality Gate confirm ⇒ Odoo `_set_done` ⇒ hàng được giao. Biện pháp, **bốn lớp** (bản nháp ghi "3 lớp", §06.7 có bốn):

| Lớp | Kiểm gì | Chu kỳ | Hành động khi lệch |
|---|---|---|---|
| 1 | Liveness: `eth_blockNumber` + `head_age` | 5s | `head_lag > 3` hoặc `head_age > 4×block_time` ⇒ demote |
| 2 | `blockhash(head - witness_depth)` k-of-n | 30s | Lệch lần đầu ⇒ `divergence_suspect`, hỏi lại sau 2 block **ở chiều sâu mới**; vẫn lệch ⇒ **eject vĩnh viễn** (không auto-recover) + P1 |
| 3 | **Canary state**: cùng một `eth_call` pin theo `blockHash`, byte-identical trên mọi endpoint | 60s | Lệch ⇒ P1. **Đây là lớp duy nhất bắt được archive node phục vụ state sai** — blockhash khớp không chứng minh `eth_call` trung thực |
| 4 | Drop im lặng: sau 2 block, xác nhận tx tồn tại qua **provider khác** | per-tx | Không thấy ⇒ re-broadcast qua provider khác; 3 lần ⇒ eject |

**`witness_depth` không phải hằng số 12.** `max(finality_depth, 2)` cho chain BFT, `max(finality_depth, 12)` cho chain probabilistic (§06.7.1).

**Xác nhận finality không đếm block trên Gnosis.** §11.3 chốt `finality_source = 'tag'`: hỏi node `eth_getBlockByNumber("finalized")`. Và sửa một con số quan trọng của note: **Gnosis 2 epoch ≈ 160 giây** (16 slot/epoch × 5s = 80s/epoch), **không phải 12.8 phút**. Con số sai theo hướng bất lợi cho UX và cho SLA.

Yêu cầu cứng cho Finality Gate: **hai provider độc lập khớp nhau cả `receipt` và `blockhash(receipt.blockNumber)`**, cộng `tag=finalized` bao trùm block đó; log/topic đọc từ chính log, không tin field đã decode của provider; sticky provider cho `getTransactionCount` (§06.7.2 quy tắc 1).

**[BẢN 3] Trên chain private 9000 lớp này phải viết khác.** Clique một signer: không có `finalized` tag có nghĩa, không có k-of-n provider (chỉ một node), và reorg là khả năng thật. §09 đã ghi `finality_quorum = 2` không thoả mãn được ở đó. Lớp thay thế duy nhất còn hiệu lực là anchor head hash ra ngoài (§11.3) — nếu không anchor thì trên chain đó "finality" chỉ là lời hứa của người vận hành node.

**A11 (indexer) cần một lớp riêng mà bản nháp không có:** indexer là thứ **ghi** `finalized`. Nếu chiếm được nó thì không cần nói dối RPC nữa. Ba biện pháp:
- DB role riêng, `GRANT INSERT/UPDATE` chỉ trên 3 bảng của indexer, không có quyền trên `blockchain.settlement`.
- Chuyển trạng thái `finalized → done` do **Odoo cron** thực hiện sau khi **đọc lại** receipt từ một provider (không tin bảng của indexer).
- Đối soát định kỳ (§15.5): tổng trên chuỗi vs tổng trong sổ kế toán; lệch ≠ 0 là P1.

#### 12.7.2. Oracle cho peg

Rate từ TWAP một pool DEX mỏng là manipulable: với $50k thanh khoản, một swap $10k đẩy giá ~20% ⇒ attacker mint thêm 20%. Dùng `SignedRateSource` k-of-n publisher ký EIP-712, lấy **median** (không phải trung bình — trung bình bị kéo bởi một outlier), `maxRateAge = 3600s`, `maxDeviationBps = 200`/lần cập nhật, và **halt mint (không halt burn)** khi lệch > 500 bps. Halt burn là giam giữ tiền người khác; halt mint chỉ là ngừng bán.

Reserve ratio kiểm mỗi 5 phút, `< 100%` là P1. Và một điều bản nháp không nói: **publisher key là một khoá nóng với quyền in tiền gián tiếp.** Nó phải ở enclave, xoay theo lịch, và k-of-n phải có `k >= 2` kể cả trong pilot.

#### 12.7.3. Supply chain toolchain (A8)

- `forge install` theo tag là **mutable**; pin bằng commit SHA trong `foundry.lock` và commit file đó.
- Pin `solc_version` **chính xác** (không `^`), kiểm checksum binary, build trong container hermetic có digest cố định.
- Sau deploy, **đối chiếu bytecode on-chain với bytecode build lại cục bộ** (`cast code <addr>` vs `forge inspect <C> deployedBytecode`) và verify trên Sourcify. Một bước, chặn được cả "compiler nói dối" lẫn "deploy nhầm branch".
- **[BẢN 3] `implementation_codehash` trong catalogue của factory phải khớp `EXTCODEHASH` đọc lại từ chain trước khi một token được chấp nhận** (§10.4.4). Đây là thứ thay thế cho `to_impl_codehash` của luồng upgrade cũ: không còn nâng cấp để mà đối chiếu, nhưng vẫn phải chứng minh rằng bản đã audit và bản đang chạy là một.
- Phía Python: `requirements.txt` hash-pinned (`--require-hashes`), không `--extra-index-url` (chặn dependency confusion).
- Phía client SDK: xem 12.3.10 — đó là một chuỗi cung ứng **khác**, không được gộp chung.
- CI runner có quyền deploy là một mục tiêu: khoá deploy không bao giờ nằm trong CI secret. CI **đề xuất** tx; người ký.

#### 12.7.4. Thời gian (G7)

`expiry` được tính ở Odoo, kiểm ở chain. Odoo lệch đồng hồ 90 giây ⇒ mọi Zether intent (expiry 60s) chết lúc sinh, hoặc sống 150s mà ta tưởng 60s. Biện pháp: NTP bắt buộc, và **`_build_metatx` lấy mốc thời gian từ `block.timestamp` của head đã đọc gần nhất**, không từ `fields.Datetime.now()`. Monitoring: `abs(chain_head_timestamp - odoo_now)` > 30s là ticket.

Trên private chain, `block.timestamp` do chính validator của ta đặt ⇒ `expiry` không còn là một bảo đảm mật mã, chỉ là một bảo đảm vận hành (A12).

#### 12.7.5. DoS chuỗi nền (bản nháp không có mục này)

Con số quyết định: **17M gas/block × 17,280 block/ngày = ~294 Ggas/ngày** trên Gnosis. Ở 1.5 gwei và xDAI = $1, mua **100% block space của cả Gnosis một ngày tốn ~$441** (ước tính, chưa tính EIP-1559 base fee tăng khi block đầy). Thực tế base fee tăng ~12.5%/block khi block đầy, nên một giờ phong toả tốn vào khoảng **$200–500** (ước tính, cần đo lại).

Nghĩa là: một đối thủ có động cơ cạnh tranh có thể **đẩy chi phí và độ trễ giao dịch của ta lên bất cứ lúc nào với ngân sách vài trăm đô la một giờ**, và Zether của ta tiêu 1.88M gas/tx nên ta là nạn nhân tự nhiên. Hai biện pháp:

1. **Lớp ưu tiên gas (§06.4.4)**: R3/R4 không bao giờ bị throttle, chấp nhận trả tip cao. R1/R2 dừng.
2. **Đường lui sang private profile** cho B2B — đây là một lý do định lượng nữa cho quyết định khoá #5, ngoài block space (§04.10).

---

### 12.8. Kế hoạch kiểm toán

| Phase | Phạm vi | Ai làm | Thời lượng | Ước tính chi phí | Gate |
|---|---|---|---|---|---|
| A | Slither, Halmos trên `MetaTxLib`/`Bn254`/`Bls12381`/`PegController`, Echidna + `forge` invariant 50k run | Nội bộ | CI, mỗi PR | 0 | Fail = fail build |
| B | **Mật mã học**: transcript, Bulletproof verifier, sigma protocol, **sinh nonce/randomness (12.3.1)**, biến thể *`accSeq` + nhánh `OWNER_ONLY`* và đường lui *verifier chấp nhận `accSeq` cũ khi phần chênh chỉ gồm credit* (**[BẢN 5, 2026-09-03]**; đây là thay đổi tầng giao thức, **không** được quyết bằng suy luận trong tài liệu) | Hãng chuyên ZK (ZKSecurity / Least Authority / Veridise / ABDK) | 3–4 tuần | **$60k–120k** | Không deploy có giá trị thật nếu chưa đóng |
| **B2** | **Precompile native + consensus integration** cho private chain (12.1.1) | Hãng có năng lực Go/C# + crypto | 2 tuần | **$30k–60k** | Chỉ bắt buộc khi bật private profile |
| C | Factory, token, peg, registry, forwarder, batcher, `WithdrawLimiter` | Hãng audit EVM tuyến 1–2 | 2–3 tuần | **$40k–80k** | Như trên |
| C2 | Certora trên `MetaTxForwarder` + `WrappedToken` (§14.9) | Certora / nội bộ có license | 1–2 tuần | $15k–30k | Trước mainnet có tiền thật |
| D | Hub relayer, Odoo control plane, RPC gateway, custody + **enclave attestation chain** | Pentest | 2 tuần | $20k–40k | Trước go-live |
| D2 | **Client SDK + supply chain** (12.3.10) | Cùng đơn vị D | 3–5 ngày | $8k–15k | Trước khi phát hành SDK |
| E | Re-audit | Bất kỳ thay đổi nào chạm vào: verifier, transcript, ngữ nghĩa `mode`, sinh nonce, hoặc thêm chain adapter | Cùng hãng phase B/C | 3–5 ngày/lần | Bắt buộc |

**Tổng ngân sách chương trình: $173k–345k** cho lần đầu (không kể bounty float), cộng ~$15k/năm cho re-audit định kỳ. Bản nháp ghi $120k–240k vì thiếu B2, C2, D2.

**[BẢN 3] Và hai đường cong nghĩa là phase C chạy hai lần.** §20.1 đã ghi: verifier bn254 và verifier BLS12-381 là hai bộ code khác nhau, không dùng chung phần lớn logic, nên chi phí audit **gấp đôi** cho hạng mục verifier. Đó là cái giá đã biết trước của việc để thị trường chọn đường cong, không phải một khoản phát sinh.

Bốn quy tắc quy trình mà bản nháp không có, và thiếu chúng thì con số trên là tiền vứt:

1. **B trước C.** Một lỗi tầng giao thức làm vô hiệu kết quả audit contract.
2. **Scope freeze.** Commit SHA được audit phải được đóng băng. Mọi commit sau đó vào phạm vi audit đi vào **danh sách delta** và phải được reviewer xác nhận lại bằng văn bản. Không có "sửa nhỏ sau audit".
3. **"Đóng" nghĩa là** mọi finding Critical/High đã fix **và** được chính reviewer xác nhận lại bằng văn bản. Remediation retest phải nằm trong hợp đồng, không phải mua thêm.
4. **Ai sở hữu fix nào, SLA bao lâu**: Critical 48h, High 5 ngày, Medium 30 ngày, Low vào backlog có ngày. Một finding quá hạn là một mục trong risk register, không phải một dòng Slack.

Và một điều cần nói thẳng: **audit không thay thế được `WithdrawLimiter`.** Mọi hệ thống bị hack đều đã từng được audit. Ngân sách $250k cho audit mà không có trần rút on-chain là phân bổ sai. **[BẢN 3]** Điều này nặng hơn nữa khi token không nâng cấp được: một bug đã deploy chỉ có thể chặn bằng thứ đã có sẵn trong contract lúc deploy.

### 12.9. Bug bounty

**Không mở bounty trước khi Phase B + C đóng** — mở sớm là thuê người ngoài làm việc mà audit sẽ làm, chất lượng thấp hơn và lộ sớm hơn. Bắt đầu trên testnet (cả public lẫn private profile) với state giống production, 3 tháng trước go-live.

| Mức | Ví dụ | Thưởng |
|---|---|---|
| Critical | Proof forgery, mint trái phép, rút khỏi vault không có proof, **trích được `x` từ prover/SDK**, bypass Finality Gate làm `_set_done` sai, chiếm quyền `registerImplementation` của factory | 10% số tiền có thể mất, **trần $250,000**, sàn $25,000 |
| High | Khoá vĩnh viễn tiền người khác, ăn cắp phí relayer ở quy mô, đổi `recipient`/`feeRecipient`, bypass `WithdrawLimiter` | $10,000 |
| Medium | Griefing làm relayer lỗ, DoS verifier, rò rỉ số tiền bí mật, rò rỉ cross-tenant trong Odoo | $2,500 |
| Low / Info | Thiếu event, sai NatSpec | $250 / ghi nhận |

Vị trí cụ thể (bản nháp chỉ có một dòng "safe harbour"):

- **Nền tảng**: Immunefi cho contract (nó là nơi người săn contract ở), **self-hosted** cho Odoo/hub (không muốn lộ topology nội bộ lên một marketplace công khai).
- **Primacy of impact**: trả theo tác động chứng minh được, không theo nhãn của ta về mức độ.
- **PoC bắt buộc** trên fork hoặc testnet của ta. **Cấm tuyệt đối test trên mainnet có giá trị thật**; vi phạm = mất quyền nhận thưởng và có thể bị truy cứu.
- **Safe harbour** viết rõ: không kiện, không báo công an, miễn trừ CFAA/luật tương đương, với điều kiện tuân thủ scope và không exfiltrate dữ liệu người dùng.
- **Triage 72h**, phản hồi trạng thái mỗi 7 ngày, thanh toán trong 30 ngày sau khi xác nhận.
- **KYC cho payout > $10,000** và sàng lọc danh sách cấm vận.
- **Duplicate**: báo cáo đầu tiên có PoC hợp lệ được trả. Không trả cho vấn đề đã nằm trong báo cáo audit **đã công bố**.
- **Loại trừ**: hub availability, giá token, lỗi của chain nền, social engineering nhân viên, DoS thuần tuý không có lỗ hổng logic.
- **Ngân sách float**: giữ sẵn **$300,000** thanh khoản (trần $250k + dự phòng). Một bounty không trả được là một bounty trả bằng danh tiếng.

### 12.10. Ứng phó sự cố và đường pause on-chain

```
GUARDIAN (1-of-5 ky su truc, KHONG timelock)  -> pause()   : dung deposit, transferConfidential, mint
   |  tu het hieu luc sau 7 ngay (MAX_PAUSE), redeem/withdraw tu mo lai
   |
   +-- Safe 4-of-7 (GUARDIAN + board), KHONG timelock -> WIND_DOWN  [MOT CHIEU]
           : mint tat vinh vien, reserve chuyen sang RecoveryVault (code khac)

TimelockController 48h (proposer Safe 4-of-7) -> registerImplementation() / unpause()
```

**Sửa so với bản nháp:** bản nháp ghi "Guardian 2-of-3" và "Governance 3-of-5"; §1.11 chốt **GUARDIAN 1-of-5** (tức thì, chỉ `pause` và `deprecate`, tự hết hiệu lực 7 ngày), **DEFAULT_ADMIN Safe 4-of-7**, **PROTOTYPE_ADMIN 3-of-5**, **RECOVERY 6-of-7 timelock 30 ngày**. Hai bản số không khớp nhau là một bug tài liệu; **lấy §1.11 làm nguồn sự thật** và sửa ở đây.

**[BẢN 3] Và pause chỉ áp được lên contract của chính ta.** Trong factory mở, `GUARDIAN` không có vai trò nào trong zDAI-B do người lạ tạo — token ấy có guardian riêng, hoặc không có guardian nào. Runbook dưới đây áp cho hạ tầng và cho token ta phát hành; với token của người khác, hành động duy nhất là gỡ nó khỏi `accepted_token_ids` và ngừng nhận.

`pause()` **không được chặn `withdraw`**. Nếu pause khoá luôn đường rút, thì chính cái pause là vụ tấn công: ai chiếm được guardian sẽ đóng băng tiền của khách. Thay vào đó `withdraw` vẫn mở nhưng đi qua `WithdrawLimiter` (trần theo tài khoản/giờ và trần toàn cục/giờ). Chỉ `WIND_DOWN` — 4-of-7, một chiều, phát event kèm lý do — mới được dừng hẳn đường mint, và nó không dừng `withdraw` mà **chuyển** nó sang `RecoveryVault`.

Và một câu trả lời bản nháp không có: **nếu chính `withdraw` là hàm có bug thì sao?** Tự động mở lại sau 7 ngày là mở lại lỗ hổng. Lối thoát duy nhất là `WIND_DOWN` (§1.10.1): bạn không được kéo dài pause; bạn chỉ được **từ bỏ token và trả tiền qua một đường khác**. Đó là một lựa chọn đắt, và nó đúng phải đắt. **[BẢN 3]** Với token immutable, đây không còn là lựa chọn cuối cùng mà là lựa chọn *duy nhất* — không có bản vá nào để chờ. `MigrationSink` vì thế phải tồn tại từ v1, không phải v2.

Runbook (đồng hồ bắt đầu từ alert đầu tiên):

| T | Hành động | Ai |
|---|---|---|
| T+0 | Alert P1 (12.11) | Tự động |
| T+1' | **Bảo toàn chứng cứ trước khi chạm vào gì**: snapshot `head`, dump mempool, snapshot DB (`pg_dump` vào bucket write-once), giữ nguyên log. Không restart service | Tự động (script `ir-preserve.sh`) |
| T+2' | Xác nhận bằng nguồn thứ hai (provider khác + explorer) | On-call |
| T+5' | `GUARDIAN.pause()` trên contract liên quan; đặt `blockchain.chain.state = 'halted'` ⇒ mọi cron dừng, mọi `blockchain.relay.job` treo ở `held` | On-call |
| T+10' | Đóng băng custody: `authEpoch++` (revoke session key), rút hot wallet về treasury, xoay credential RPC, thu hồi client cert mTLS của worker nghi ngờ | Ops + Security |
| T+15' | **Ai được tuyên bố sự cố**: on-call có quyền pause không cần hỏi. Chỉ CEO/CTO được tuyên bố "breach" ra bên ngoài | Lead |
| T+15' | Thông báo nội bộ + đối tác đang có giao dịch treo (mẫu thư soạn sẵn, không viết lúc 3h sáng) | Lead |
| T+30' | Đánh giá pháp lý: có dữ liệu cá nhân liên quan không ⇒ nghĩa vụ thông báo | Legal |
| T+60' | Root cause sơ bộ, quyết định `WIND_DOWN` hay không | Lead + Sec |
| T+2h | Nếu private chain: quyết định **có rewind không**. Đây là quyết định của người, phải có biên bản, và phải thông báo đối tác — một rewind im lặng là một sự cố thứ hai | Lead + Legal |
| T+24h | Post-mortem viết, không quy lỗi cá nhân, kèm test hồi quy đã merge | Team |

Bốn lưu ý bắt buộc, tất cả đều là bẫy:

1. **Job đang `held` không được auto-cancel.** Một tx đã broadcast vẫn có thể lên chuỗi sau khi ta pause. Consumer phải giữ `pending`, không `_set_canceled`, cho đến khi reconcile.
2. **`encKey` bị lộ thì không thể khắc phục ngược.** Không có forward secrecy: attacker giải mã được **toàn bộ lịch sử** đã ghi trên chuỗi. Hành động duy nhất là `migrateAccount()` ngay lập tức sang khoá mới (giảm thiệt hại tương lai) và thông báo phạm vi lộ cho đối tác. **Phải có trong hợp đồng, không chỉ trong runbook.**
3. **`x_audit` bị lộ là một sự cố lớn hơn `encKey` của một tài khoản.** Nó lộ toàn bộ lịch sử của **mọi** tài khoản. Runbook riêng: dừng ngay `C_audit` mới (đổi `y_audit`), thông báo **mọi** đối tác, và chấp nhận rằng lịch sử cũ không cứu được.
4. **Pause trên public chain làm kẻ thứ ba mất tiền.** `ZTokenOpen` có thể đang làm collateral ở chỗ khác; phát `Paused(uint64 autoUnpauseAt)` để bot của họ đọc được mốc tự động mở, và công bố `MAX_PAUSE` trong tài liệu tích hợp (§1.10.2).

### 12.11. Giám sát: phát hiện trong vài phút, không phải vài ngày

Nguyên tắc chọn chỉ số: **ưu tiên invariant có thể kiểm bằng một câu hỏi RPC, và ưu tiên cái chặn được thiệt hại chứ không chỉ báo cáo nó.**

| # | Invariant / tín hiệu | Tần suất | Ngưỡng báo | MTTD kỳ vọng |
|---|---|---|---|---|
| 1 | `WrappedToken.totalSupply() == underlying.balanceOf(vault)` | mỗi block | lệch ≠ 0 | <= 10s |
| 2 | `zether.depositTotal - zether.withdrawTotal == underlying.balanceOf(zether)` | mỗi block | lệch ≠ 0 | <= 10s |
| 3 | **Withdraw velocity** tổng theo giờ vs baseline | mỗi block | > 3σ hoặc > `2% TVL/giờ` ⇒ **auto-pause**, không chỉ alert | <= 30s |
| 4 | **[BẢN 3]** `ImplementationRegistered` / `ImplementationDeprecated` trên factory | realtime | bất kỳ, nếu không khớp một đề xuất timelock đã duyệt | <= 15s |
| 5 | Tx bất kỳ từ admin/timelock/guardian address | realtime | bất kỳ | <= 15s |
| 6 | `AuthRotationRequested`, `successorAddr` set, `RecoveryAnnounced` | realtime | bất kỳ | <= 15s |
| 7 | Tỷ lệ revert của verifier | 1' | > 1% (baseline) | <= 2' |
| 8 | RPC divergence lớp 2 (`blockhash`) **và lớp 3 (canary state)** | 30s / 60s | bất kỳ lệch (sau xác nhận lần 2) ⇒ eject vĩnh viễn + P1 | <= 60s |
| 9 | `nonce_allocated - nonce_confirmed` mỗi relayer; `nonce_desync` (`latest > next`) | 30s | > 20; hoặc desync >= 1 ⇒ P1 + quarantine | <= 1' |
| 10 | Fee spread relayer âm | 1' | âm liên tục > 10' | <= 10' |
| 11 | Peg: lệch rate vs median publisher; reserve ratio | 5' | > 200 bps; < 100% | <= 5' |
| 12 | Odoo: `relay_submit_intent` theo user; user ngoài group; ghi `ir.config_parameter` key `blockchain.*`; **ghi `ir.actions.server` / `base.automation` / `ir.cron`**; `done` không kèm transition row | realtime | vượt baseline 5×; hoặc bất kỳ với nhóm `ir.*` | <= 1' |
| 13 | `pending_event_count` của một `schnorrAddress` | 5' | > 500 (dấu hiệu flooding 12.3.6) | <= 5' |
| 14 | **Dead man's switch**: indexer đã xử lý block trong N phút qua chưa? worker relay-pool còn heartbeat? | 60s | không có tiến độ > 5 phút ⇒ P1 | <= 5' |
| 15 | **Đối chiếu Safe**: `getOwners()`/`getThreshold()` mỗi chain vs `blockchain.governance.signer` | hàng ngày | lệch ⇒ incident | <= 24h |
| 16 | **Hash binary validator** (private chain) và **PCR0 của enclave đang chạy** | 5' | khác giá trị đã duyệt ⇒ P1 | <= 5' |
| 17 | Lệch đồng hồ `abs(chain_head_ts - odoo_now)` | 1' | > 30s ⇒ ticket | <= 1' |
| 18 | **[BẢN 3]** `EXTCODEHASH` của mọi token trong `accepted_token_ids` vs `audit_covers_code_hash` | hàng ngày | lệch ⇒ gỡ token khỏi danh sách chấp nhận + P1 | <= 24h |

Ba điều về **cách** giám sát, không phải giám sát cái gì, mà bản nháp không nói:

- **Giám sát không được chạy trên hạ tầng nó đang giám sát.** Nếu Prometheus + alertmanager sống cùng cụm Odoo thì một kẻ chiếm cụm đó tắt luôn cảnh báo. Tối thiểu: alerting ở một tài khoản cloud/khu vực khác, và một heartbeat ra ngoài (dead man's switch #14 phải được một dịch vụ **bên ngoài** kiểm).
- **Alert phải có chủ.** Năm alert page người lúc 3h sáng (§06.8): `nonce_gap_age`, `nonce_desync`, `signed_orphan`, `rpc_divergence` (gồm canary), `hot_wallet_runway < 1h`. Cộng từ section này: #3 (auto-pause, page sau khi đã pause), #4, #5, #14, #16. Còn lại là ticket.
- **Vắng tín hiệu là một tín hiệu.** Cách hỏng tồn tại nhiều ngày nhất không phải một alert bị bỏ qua, mà là một pipeline chết im lặng. Đó là lý do #14 tồn tại và là lý do nó phải được test bằng cách **thật sự tắt indexer** trong drill.

**Dòng quan trọng nhất của bảng này là #3.** Proof forgery, mint trái phép, bug rounding — **tất cả đều chỉ biến thành tiền khi ai đó `withdraw`**. Công thức để đặt tham số:

```
thiet_hai_toi_da = cap_rate_per_hour × thoi_gian_phan_ung
Muc tieu: thiet_hai_toi_da <= 0.5% TVL, voi thoi_gian_phan_ung = 15 phut (SLA P1 den luc pause)
=> cap_rate_per_hour <= 0.5% / 0.25h = 2% TVL/gio          <-- chot 2%/gio
Kiem tra nguoc: neu phan ung mat 1 gio (dem, on-call ngu quen) => mat toi da 2% TVL.
Voi TVL pilot $2M: tran 40,000 USD/gio, thiet hai xau nhat 40,000 USD thay vi 2,000,000 USD.
Tran theo tai khoan: max(5,000 USD, 20% cua tran toan cuc) — de mot tai khoan bi chiem
khong tieu het han muc cua ca he thong.
```

Đó là biện pháp có tỷ lệ lợi ích/chi phí cao nhất trong cả section này (một contract ~80 dòng, ~5,000 gas/withdraw), và nó phải được triển khai **on-chain** (`WithdrawLimiter`), không phải trong Odoo — vì Odoo không nằm trên đường đi của một tx trực tiếp. **[BẢN 3]** Với token immutable, nó còn phải nằm trong implementation *ngay từ v1*: không thêm được sau.

**Năm drill định kỳ có biên bản** (bản nháp có ba):

| Drill | Chu kỳ | Đo cái gì |
|---|---|---|
| Blackout toàn bộ hub | hàng tháng | Thời gian chuyển sang Enterprise Relay Pool |
| `GUARDIAN.pause()` trên staging | hàng quý | T+5' có đạt không; ai bấm nút khi on-call chính nghỉ |
| Giả lập một RPC nói dối | hàng quý | Lớp 2 và lớp 3 eject đúng endpoint |
| **Tắt indexer không báo trước** | hàng quý | Dead man's switch #14 có kêu không, sau bao lâu |
| **Khôi phục Shamir của `x`** trên tài khoản thử nghiệm | 6 tháng | Quy trình có chạy được không, ai giữ share nào, share có còn đọc được không (§02.7.5) |

### 12.12. Còn phải quyết

Mười điểm còn cần người quyết (bản nháp có bảy):

1. **Đồ thị brand-distributor lộ trên public chain** — chấp nhận hay ép B2B settlement về `chain_profile = private`. Ảnh hưởng: kiến trúc, chi phí vận hành chain riêng, và §13.
2. **Ai giữ `y_audit`**, theo cơ sở nào, k-of-n bằng bao nhiêu, xoay thế nào, và ai chịu trách nhiệm khi lộ.
3. **Quyền freeze trên private chain thuộc vai trò nào**, có đường lệnh toà án không (`forceTransfer` có sự chứng kiến của N validator, §1.10.3).
4. **`WITHDRAW_CAP_PER_HOUR`** — đề xuất 2% TVL/giờ với cơ sở ở 12.11; cần người chấp nhận rằng thiệt hại xấu nhất là 2% TVL.
5. **Compliance có chấp nhận relayer hot key trong enclave** (thay vì HSM L3) để đổi từ 10–30 lên 10^4 sign/s không. Nếu không, trần hệ thống là ~10–30 tx/s và **batch executor trở thành bắt buộc**, không phải tối ưu.
6. **Ngân sách $173k–345k** cho toàn bộ chương trình audit (gồm B2 precompile, C2 Certora, D2 SDK, và **hai lần** hạng mục verifier vì hai đường cong) có được duyệt trước go-live không, hay ship thiết kế epoch gốc trước để tránh audit Phase B cho biến thể.
7. **`base.group_system` có nằm trong biên tin cậy không** — hiện tại **có**, và 12.6.1 chỉ ra rằng đó đồng nghĩa với RCE. Nếu không chấp nhận được thì phải giảm số người có group này xuống còn 1–2 và thêm break-glass.
8. **Bounty float $300,000** có được phong toả không, và ai là bên trả (issuer hay platform).
9. **Đường cong của ElGamal.** §20.1 chốt hỗ trợ **cả hai** (bn254 và BLS12-381) và để thị trường chọn — nhưng đó là quyết định ở tầng factory. Ở tầng một token cụ thể, người tạo chọn một lần và **không sửa được sau khi deploy** (§20.2), vì đổi đường cong = migrate = lộ toàn bộ số dư. Điều còn phải quyết là **ta** phát hành token của mình trên đường cong nào; §19 chốt bn254 cho giai đoạn private, với ba điều kiện mở lại.
10. **Chính sách rewind trên private chain**: ta có quyền kỹ thuật để rewind. Có được phép không, ai duyệt, và có phải thông báo đối tác không. Nếu không trả lời trước, câu trả lời sẽ được đưa ra lúc 3h sáng bởi một người đang hoảng.

### 12.13. Rủi ro tồn dư — cái không có biện pháp, và phải ký nhận

Một mô hình đe doạ trung thực phải có mục này. Bảy rủi ro dưới đây **không** có biện pháp trong phạm vi dự án; chúng phải được ghi vào hồ sơ rủi ro và có người ký chấp nhận.

| # | Rủi ro tồn dư | Vì sao không chặn được | Nếu xảy ra |
|---|---|---|---|
| R1 | >1/3 stake Gnosis equivocate | Ngoài tầm kiểm soát | Finality bị đảo ⇒ `finality_violation`, halt chain, đảo bút toán thủ công (§11.4) |
| R2 | BN254 chỉ còn **~100 bit** an toàn sau các tấn công TNFS | Là thuộc tính của đường cong | Chấp nhận cho "money in motion"; với "money at rest" dài hạn thì phải có kế hoạch đổi curve (§03.1.2). BLS12-381 giữ ~126 bit và §20.1 để cửa đó mở, nhưng phép đo S7 cho thấy nó **không** rẻ hơn về gas — lý do đổi là biên an toàn, không phải chi phí |
| R3 | **Harvest-now-decrypt-later** trên ciphertext ElGamal | Ciphertext đã trên chuỗi vĩnh viễn; PQ không cứu được cái đã ghi | Số tiền của hôm nay bị giải mã khi có CRQC. Đó là lý do B2B nên ở private chain, nơi chuỗi không công khai (§02.6.6) |
| R4 | Mất `x` = mất vĩnh viễn quyền chi tiêu | Thuộc tính giao thức | Ước **0.3–1.0%/năm** tài khoản tự quản; 10,000 outlet ⇒ 30–100 tài khoản/năm, 15–50 triệu VND/năm khoá vĩnh viễn (§07.10). Chấp nhận được với loyalty, **không** với B2B |
| R5 | Không tịch thu được (seizure) trên public chain | Contract không biết số dư bằng bao nhiêu | Nếu quy định đòi seizure thì Zether public **không đáp ứng được, chấm hết** (§1.10.3) |
| R6 | Lực lượng (cardinality) của đồ thị thanh toán là công khai | Là thiết kế anti-mixer | Đối thủ biết tần suất đặt hàng. Phải nói với khách hàng, không được giấu |
| R7 | Mất 4 trong 7 khoá Safe | `RECOVERY` 6-of-7 cũng không cứu được | Hệ thống chết vĩnh viễn. Phải ở hồ sơ rủi ro, không được lờ đi (§1.11.1 mục 4) |
| **R8** | **[BẢN 3] Một token do người lạ tạo bằng implementation đã deprecate vẫn chạy vĩnh viễn** | Factory mở + không upgrade: `deprecate` chỉ là một cờ, nó không dừng được contract đã tồn tại | Người dùng zDAI-B vẫn giao dịch với một bản có lỗi đã biết. Ta chỉ gỡ được nó khỏi `accepted_token_ids` của mình. Đây là cái giá đã chọn của §20.2 và §20.4: provenance thay cho gatekeeping |

### 12.14. Ma trận truy vết: biện pháp -> nơi enforce -> test chứng minh

Một biện pháp không có test là một ý định. Bảng này là thứ mà team dùng để biết **đã xong hay chưa**; mỗi dòng phải có một file test thật.

| Biện pháp | Enforce ở đâu | Test chứng minh nó sống |
|---|---|---|
| Transcript đầy đủ (12.3.2) | `BulletproofsVerifier.sol` + prover Rust + precompile | `testvectors/zether_transfer_v1.json` + >= 13 negative vector; differential 3 chiều |
| Nonce không lặp (12.3.1) | Prover (Rust/WASM) | `test_no_nonce_reuse` với RNG bị ép hằng số |
| `withdraw` bind chain (12.3.3) | Fiat-Shamir challenge | `ReplayCrossChain.t.sol`: proof hợp lệ trên chainId A phải revert trên B |
| Fail-fast verifier (12.1) | Thứ tự check trong `transferConfidential` | `VerifierFailFast.t.sol` đo gas từng nhánh revert, assert < 20k |
| Gas uniformity (12.3.7 mục 4) | Verifier | `GasUniformity.t.sol`, lệch < 2,000 gas |
| Digest injectivity (12.2) | `MetaTxLib` | `halmos` `check_digest_injective` |
| MODE_OPEN bỏ qua relayer (12.2) | `_canon()` | `halmos` `check_mode_open_ignores_relayer` |
| Phí phần trăm không dùng được với token bí mật (12.3.7) | `FeePolicy.requireConfidentialSafe()` | `FeePolicy.t.sol` — đã có, revert trên `FeeMode.PERCENT` |
| Không `delegatecall` tự do (12.1) | CI grep + catalogue implementation của factory | `grep_gate.sh` + `PrototypeOnly.t.sol` |
| **[BẢN 3]** Implementation đã đăng ký khớp bản đã audit | `implementation_codehash` trong factory + §10.4.4 | `test_provenance_codehash_mismatch_rejects` |
| `WithdrawLimiter` 2%/giờ (12.11) | `WithdrawLimiter.sol` | `LimiterInvariant.t.sol`: 50k run, tổng rút/giờ không bao giờ > cap |
| Registry không cache trong token (12.1) | `ZTokenBase` đọc trực tiếp | Freeze ở block N, `transferConfidential` ở N+1 phải revert |
| Signer policy (12.5.1) | `confidential-signer/policy.py` (enclave) | `test_policy_rejects_type4`, `test_policy_rejects_replay`, `test_policy_owns_nonce` |
| PCR0 pin (12.5.1) | KMS key policy | Drill: chạy image khác ⇒ `kms:Decrypt` phải fail |
| Không method public gây chữ ký (12.6) | Quy ước + test | `test_public_methods_allowlist` liệt kê mọi method của `blockchain.*` |
| Cross-tenant (A9) | Rule `company_id` + `resolve()` | `test_cross_company_read`, `test_signer_rejects_foreign_ref` |
| `done` chỉ từ Finality Gate (12.6) | Guard trong `write()` + `settlement.transition` | `test_cannot_set_done_from_ui`, `test_done_requires_transition_row` |
| `models.Constraint` thật sự tồn tại | Postgres | `SELECT conname FROM pg_constraint WHERE conrelid='blockchain_metatx'::regclass;` |
| RPC canary (12.7.1) | `relay-pool` lớp 3 | Drill quý: fake một endpoint trả state cũ |
| Dead man's switch (12.11 #14) | Dịch vụ ngoài | Drill quý: tắt indexer, đo thời gian đến alert |
| Bytecode khớp audit (12.7.3) | Runbook deploy | `cast code` vs `forge inspect` trong script deploy, fail = abort |