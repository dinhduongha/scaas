# TỔNG HỢP VÀ NÂNG CẤP KIẾN TRÚC BLOCKCHAIN DOANH NGHIỆP V3.0 (SYNTHESIS V3)
*Tài liệu chuẩn hóa kiến trúc sản xuất từ nghiên cứu và các quyết định mở rộng*
**Ngày phát hành:** 2026-09-05  
**Trạng thái:** Chuẩn tắc sản xuất (Production Specification & Canon Addendum)  
**Tài liệu gốc đồng bộ:** `ai/ai-enterprise-blockchain-architecture.md` (v3.3) · `ai/ai-enterprise-blockchain-integration.md` (v2.3) · `ai/ai-enterprise-dimensions-expansion.md` (v2.9)

---

## 1. TỔNG QUAN VÀ BỐI CẢNH NÂNG CẤP

Trong quá trình đánh giá và đối soát giữa tập 24 tài liệu nghiên cứu chuyên sâu (`00-CANON.md` đến `16-decomposition-roadmap.md`, `_USER-DECISIONS.md`) tại thư mục `blockchain-research/` và hệ thống kiến trúc AI Doanh nghiệp cấp cao (`ai-enterprise-*.md`), hệ thống đã xác định 9 cơ chế nghiệp vụ - kỹ thuật mang tính đột phá cần được chuẩn hóa đồng bộ hai chiều.

Tài liệu này đóng vai trò là văn bản chuẩn tắc hợp nhất (Synthesis Document), tích hợp toàn bộ các phát hiện mới, giải quyết triệt để các khoảng cách giữa nghiên cứu lý thuyết và thực tiễn triển khai ERP (Odoo 19).

---

## 2. CỬU ĐẠI CƠ CHẾ NÂNG CẤP CỐT LÕI (9 ADVANCED MECHANISMS)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   9 CƠ CHẾ NÂNG CẤP KIẾN TRÚC BLOCKCHAIN V3                      │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ 1. Multi-Wallet Pool     │ Bể ví Hot Relayer Round-Robin; không dẫm chân nonce;  │
│    vs. Redis Lease       │ Treasury Signer (HSM/MultiSig) tự động nạp vốn an toàn│
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 2. MetaTx 2 Luồng        │ Generic Calldata (đa năng) vs Fast-Path Token Function│
│    (Generic vs Fast-Path)│ (mtxPay tiết kiệm ~4.2k gas, phát Payment kèm payId)  │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 3. Ứng dụng Token Mới    │ Quỹ rút định kỳ Vesting Vault (IVestingVault) và      │
│                          │ Cổ phiếu/Trái phiếu giao dịch sàn Nhà nước giám sát   │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 4. Phân loại Kiểm soát   │ Token không kiểm soát (Uncontrolled) vs Token pháp    │
│    (Uncontrolled vs Reg) │ định (Controlled IRegulatedToken, courtRulingId, 3/5) │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 5. Bên nhận trả phí      │ feePaidByRecipient: Người gửi chuyển đúng N token;    │
│                          │ Người nhận nhận N - fee; Relayer thu fee trực tiếp     │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 6. Phí như dịch vụ BaaS  │ Doanh nghiệp tài trợ 100% gas (fee = 0) cho giao dịch │
│                          │ chuyển tiền B2B inbound giá trị > $10                 │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 7. Open Asset Suite      │ Configurator Wizard cho doanh nghiệp tự do phát hành  │
│                          │ tài sản số, RWA trên nền Open Factory dùng chung logic│
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 8. Đấu thầu Sealed-Bid   │ Giao thức thầu phong bao kín 2 pha (commit-reveal);   │
│    (ISealedBidTender)    │ Tự động giải ngân người trúng; hoàn cọc 100% trượt thầu│
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ 9. Recipient Self-Relay  │ Cá nhân B tự làm msg.sender trả native gas, fee = 0;   │
│    & Direct Inbound API  │ Doanh nghiệp chuẩn hóa Inbound API gom lô 40-60% gas  │
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

---

### Cơ Chế 1: Quản Trị Nonce Ngoài Của Relayer — Multi-Wallet Pool (Chính) vs. Redis Lease (Phụ)

#### A. Vấn đề của thiết kế cũ
Thiết kế cũ coi Redis Lease có Fencing Token là cơ chế duy nhất để phân bổ nonce ngoài của ví Relayer. Tuy nhiên, khi toàn bộ worker dùng chung 1 ví duy nhất, việc tranh chấp lock Redis trở thành điểm nghẽn cổ chai (bottleneck) và tăng độ trễ gửi lệnh khi số lượng worker phân tán mở rộng.

#### B. Thiết kế sản xuất chuẩn tắc: Mạng Lưới Ví Relayer Đa Điểm (Multi-Wallet KeyPool)
- **Cơ chế:** Relayer duy trì một bể gồm $N$ ví hot độc lập (`relayer_1`, `relayer_2`, ..., `relayer_N`).
- **Phân bổ không khóa (Lock-free Allocation):** Dispatcher gán lệnh cho các worker theo thuật toán Round-Robin hoặc Least-in-flight.
- **Triệt tiêu va chạm nonce:** Do mỗi ví sở hữu một chuỗi EVM nonce hoàn toàn riêng biệt trên blockchain, các worker song song **tuyệt đối không bao giờ dẫm chân lên nhau**.
- **Cơ chế Treasury Signer tự động nạp vốn (Auto-Refill):**
  * Mỗi ví hot chỉ lưu trữ một lượng gas tối thiểu đủ vận hành trong 4 giờ (`low_watermark`, ví dụ: $50 USD).
  * Khi số dư chạm ngưỡng, dịch vụ Treasury Signer (bảo mật bằng HSM FIPS 140-3 L3 hoặc ví lạnh Multi-Sig 2-of-3) tự động ký lệnh nạp thêm native gas với trần giới hạn cứng (`auto_refill_cap_usd`, ví dụ: $500 USD/lần) và chốt chặn tối đa 1 lệnh nạp đang chờ xử lý (`max_pending_refill = 1`).

#### C. Lựa chọn phụ trợ: Redis Lease kèm Generation Fencing
- Chỉ kích hoạt khi bị giới hạn hạ tầng hoặc đối tác bắt buộc chỉ cấp 1 địa chỉ ví relayer duy nhất.
- Sử dụng fencing token đơn điệu chống zombie worker ghi đè nonce sau khi bị network timeout/chậm trễ.

---

### Cơ Chế 2: Phân Hóa Hai Luồng Meta-Transaction — Generic Calldata vs. Fast-Path Token Functions

#### A. Luồng 1: Fast-Path Token Functions (`mtxPay`, `transferConfidential`, `fund`, `burn`)
- **Mục đích:** Luồng thanh toán siêu tốc, tối ưu hóa gas và đối soát ERP khép kín.
- **Đặc tính kỹ thuật:** Nhận trực tiếp các tham số có kiểu dữ liệu tường minh (typed arguments).
- **Lợi ích gas:** Tiết kiệm ~4,200 gas so với việc bọc dynamic calldata do bỏ qua bước ABI decode phức tạp trong EVM.
- **Đối soát khép kín ERP:** Hàm `mtxPay` nhận trực tiếp `bytes32 payId = keccak256(ODOO || company_id || journal_code || move_name || date)` và phát ra sự kiện `Payment(sender, recipient, amount, feeAmount, feeRecipient, payId)`. Projector bắt sự kiện này để gạch nợ tự động trong Odoo `account.move`.

#### B. Luồng 2: Generic Calldata Execution (`executeMetaTransaction`)
- **Mục đích:** Hỗ trợ mọi lời gọi hàm tùy ý vào smart contract (Composable).
- **Đặc tính kỹ thuật:** Nhận `(address sender, address to, bytes calldata data, FeePolicy fee, uint256 validUntil, uint256 nonceKey, bytes signature)`.
- **Ứng dụng:** Biểu quyết quản trị DAO, nộp hồ sơ đấu thầu sealed-bid, hoán đổi token đa chặng trên DEX. Tốn thêm ~4.2k–8k gas để decode calldata nhưng đạt độ linh hoạt tối đa.

---

### Cơ Chế 3: Ứng Dụng Token Nâng Cao — Quỹ Dòng Tiền Rút Định Kỳ & Cổ Phiếu/Trái Phiếu Trên DEX Nhà Nước Giám Sát

#### A. Quỹ Dòng Tiền Rút Định Kỳ (Vesting Streaming Vaults — `IVestingVault`)
- Ký quỹ token doanh nghiệp và tự động giải ngân theo dòng thời gian thực (block-by-block streaming hoặc các mốc cliff).
- Người thụ hưởng (Nhân viên, Nhà thầu, Nhà cung ứng) có thể rút bất kỳ lúc nào phần token đã mở khóa qua Meta-Tx hoàn toàn gasless.
- Doanh nghiệp có quyền cấu hình tính năng thu hồi (Revoke) theo hợp đồng lao động; phần token chưa mở khóa lập tức hoàn về kho bạc công ty.

#### B. Cổ Phiếu & Trái Phiếu Doanh Nghiệp Trên Sàn Giao Dịch Nhà Nước Giám Sát (`ISecurityToken`)
- Số hóa vốn cổ phần, trái phiếu chuyển đổi và cổ tức điện tử.
- Hàm kiểm định tuân thủ tư pháp bắt buộc: `checkTransferCompliant(from, to, amount)` kiểm tra trạng thái KYC/AML, giới hạn sở hữu nước ngoài (room ngoại) và điều kiện pháp lý trước khi cho phép khớp lệnh.
- Giao dịch trên sàn phi tập trung nội bộ (State-Supervised DEX) có node kiểm toán chuyên dụng của Ủy ban Chứng khoán Nhà nước.

---

### Cơ Chế 4: Phân Loại Kiểm Soát Token Cấp Giao Thức — Uncontrolled vs. Controlled / Regulated Token

#### A. Token Không Kiểm Soát (Uncontrolled / Permissionless Tokens)
- Hợp đồng bất biến (Immutable), không có backdoor, không có vai trò Admin/Owner nào có quyền can thiệp số dư.
- Bảo đảm tính phi tập trung tuyệt đối cho các tài sản như mwETH, mwDAI, token tiện ích công khai.

#### B. Token Có Kiểm Soát Pháp Lý (Controlled / Regulated Tokens — `IRegulatedToken`)
- Áp dụng bắt buộc cho: Tiền kỹ thuật số Ngân hàng Trung ương (CBDC), Stablecoin pháp định tuân thủ, và Cổ phiếu số hóa (Security Tokens).
- Cung cấp các giao diện can thiệp tư pháp:
  * `freezeAccount(address account, bytes32 courtRulingId)`
  * `unfreezeAccount(address account, bytes32 courtRulingId)`
  * `judicialForceTransfer(address from, address to, uint256 amount, bytes32 courtRulingId)`
  * `courtOrderBurn(address account, uint256 amount, bytes32 courtRulingId)`
- **Chốt chặn an toàn bắt buộc:**
  * Bắt buộc có tham số `courtRulingId` (mã băm trỏ về văn bản phán quyết của Tòa án lưu tại kho kiểm toán).
  * Kích hoạt độc quyền thông qua **Multi-Sig Quorum 3-of-5** (Pháp chế, CFO, Ban Kiểm soát, và Đại diện Cơ quan Quản lý).

---

### Cơ Chế 5 & 6: Tính Linh Hoạt Của Phí Relayer — Bên Nhận Trả Phí & Trợ Cấp Phí Gas B2B Inbound

#### A. Bên Nhận Trả Phí (`feePaidByRecipient = true`)
- Trong các hợp đồng kinh tế B2B, Bên gửi (Công ty A) ký lệnh chuyển đúng $N$ token theo hợp đồng.
- Khi cờ `feePaidByRecipient` được bật: Tài khoản Bên gửi bị trừ chính xác $N$ token; Relayer thu phí $F$ token từ giá trị chuyển dịch; Bên nhận (Công ty B) nhận được $N - F$ token.
- Giúp Bên gửi không phải tính toán cộng dồn phí phức tạp vào lệnh chuyển tiền.

#### B. Phí Như Một Dịch Vụ Doanh Nghiệp (Inbound Gas Subsidy Policy)
- Doanh nghiệp vận hành Relayer có thể thiết lập chính sách trợ cấp toàn bộ phí gas (`fee = 0`) đối với mọi giao dịch chuyển tiền vào ví của công ty nếu giá trị giao dịch vượt ngưỡng tối thiểu (ví dụ: $\text{amount} \ge 10 \text{ USD}$).
- Biến chi phí gas thành chi phí vận hành dịch vụ khách hàng (Customer Acquisition & Frictionless B2B Onboarding).

---

### Cơ Chế 7: Bộ Công Cụ Token Hóa Mở (Open Asset Tokenization Suite)

- **Kiến trúc Open Factory:** Dựa trên giao diện `IOpenFactory`, chia sẻ chung mã bytecode logic đã kiểm toán an ninh, tách biệt hoàn toàn không gian lưu trữ dữ liệu giữa các loại token.
- **Configurator Wizard trong ERP Odoo:** Cho phép doanh nghiệp tự do cấu hình:
  * Loại token (NoUnderlying, SingleUnderlying, MultiUnderlying).
  * Tỷ lệ quy đổi số nguyên (`conversionNumerator / conversionDenominator`).
  * Chế độ kiểm soát: Uncontrolled hay Controlled (`IRegulatedToken`).
  * Danh mục whitelist chuyển nhượng và chính sách phí relayer.

---

### Cơ Chế 8: Giao Thức Đấu Thầu Phong Bao Kín (Sealed-Bid Tender Protocol — `ISealedBidTender`)

Để hiện đại hóa quy trình Mua sắm Doanh nghiệp (Procure-to-Pay), loại bỏ hoàn toàn tình trạng thông đồng giá thầu (Collusion) và rủi ro giam tiền cọc:

1. **Pha 1: Cam Kết Băm Kín (Commit Phase):**
   - Nhà thầu nộp tiền ký quỹ vào hợp đồng Escrow (`deposit >= minDeposit`).
   - Nộp cam kết giá thầu dưới dạng mã băm mật mã:
     $$\text{bidCommitment} = \text{keccak256}(\text{abi.encodePacked}(\text{price}, \text{salt}, \text{msg.sender}))$$
   - Toàn bộ giá thầu được giữ bí mật tuyệt đối trên blockchain trong suốt thời gian nhận hồ sơ.

2. **Pha 2: Mở Thầu Công Khai (Reveal Phase):**
   - Sau thời hạn chót, nhà thầu nộp giá trị gốc `(price, salt)`. Smart contract tự động kiểm tra lại tính hợp lệ của mã băm.

3. **Pha 3: Phân Định & Quyết Toán Hoàn Cọc 100%:**
   - Hợp đồng tự động xác định nhà thầu thắng thầu (Giá tối ưu nhất).
   - **Hoàn cọc tự động 100%:** Toàn bộ các bên trượt thầu được hợp đồng mở quyền rút lại 100% tiền ký quỹ (`withdrawDeposit()`), không cần phê duyệt thủ công từ doanh nghiệp mời thầu.
   - **Xử lý vi phạm (Slashing):** Nhà thầu nào đã nộp cọc nhưng cố tình không mở thầu trong thời hạn quy định sẽ bị tịch thu tiền cọc sung vào quỹ thầu.

---

### Cơ Chế 9: Mô Hình Bên Nhận Tự Làm Relayer & Chuẩn Hóa API Direct Inbound Doanh Nghiệp (Recipient Self-Relaying & Enterprise Inbound Direct-Relay API)

#### A. Bên Nhận Tự Làm Relayer (Recipient Self-Relaying / P2P Direct Settlement)
- **Bối cảnh & Vấn đề:** Trong các giao dịch ngang hàng P2P (Cá nhân A chuyển mxDAI cho Cá nhân B), Bên gửi A không sở hữu native coin, Bên nhận B có sẵn native coin (xDAI, CELO, ETH) và muốn nhận thanh toán lập tức mà không muốn phụ thuộc vào bất kỳ hạ tầng Open Relayer của bên thứ ba nào.
- **Giải pháp kỹ thuật:**
  * Cá nhân A ký thông điệp EIP-712 offline với cấu hình `feeAmount = 0` (hoặc `FEE_MODE_NONE`) và `relayer = address(0)` (wildcard relayer).
  * Bản ký payload được chuyển giao cho Cá nhân B qua kênh liên lạc ngoài chuỗi (mã QR, chat P2P, Bluetooth BLE, hoặc API chia sẻ).
  * **Bản thân Bên nhận B đóng vai trò Relayer:** B trực tiếp tạo transaction on-chain gọi `mtxPay(...)` với `msg.sender == B`. B tự bỏ native gas ra trả cho validator của mạng lưới.
  * Smart contract xác thực chữ ký của A, trừ $N$ token của A và cộng đủ $N$ token vào tài khoản của B, thu 0 token phí và phát sự kiện `Payment(A, B, amount, 0, address(0), payId)`.
  * **Lợi ích:** Độc lập tự chủ 100%, bảo mật thông tin, kháng kiểm duyệt (censorship-resistant), loại bỏ hoàn toàn nguy cơ bị relayer trung gian front-run hay từ chối phục vụ.

#### B. Chuẩn Hóa API Direct Inbound Đa Chuỗi (`chainId`) & Đa Hợp Đồng (`tokenContract`) Cho Doanh Nghiệp (Enterprise Multi-Chain Inbound API & Batch Settlement)
- **Bối cảnh doanh nghiệp:** Các tổ chức, nhà bán lẻ, sàn thương mại điện tử, nhà phân phối B2B khi thu tiền từ khách lẻ hoặc đại lý đối tác trên nhiều hệ sinh thái EVM khác nhau (nhiều `chainId`: 9000, 100, 42220, 42161, 8453) và nhiều hợp đồng token khác nhau (mwUSDC, mwDAI, mwEUR, Loyalty, CBDC) có thể tự đóng vai trò Relayer tiếp nhận và nộp giao dịch mà không cần thông qua đơn vị trung gian nào.
- **Chuẩn Hóa Endpoint & Request Payload:**
  * Doanh nghiệp công khai endpoint: `POST /api/v1/blockchain/inbound-meta-tx` (hoặc URI theo chuỗi: `/api/v1/blockchain/{chainId}/inbound-meta-tx`, hoặc Header `X-Chain-Id: {chainId}`).
  * Khách hàng / Đại lý gửi JSON payload chứa tường minh:
    `{ chainId, tokenContract, tokenSymbol, sender, recipient, amount, feePolicy, validUntil, nonceKey, payId, signature }`.
- **Xác Thực Đa Chuỗi & Tái Lập Dynamic Domain Separator:**
  * Odoo Controller kiểm tra `chainId` có nằm trong danh sách chuỗi kích hoạt (`enabled == True`) và `tokenContract` đăng ký trong `blockchain.token` trên chuỗi đó.
  * Tái lập EIP-712 Domain Separator động: $\text{domainSeparator} = \text{keccak256}(\text{abi.encode}(\dots, \text{chainId}, \text{tokenContract}))$.
  * Mô phỏng `eth_call` trên đúng RPC node của chuỗi đó: kiểm tra chữ ký `ecrecover`, số dư người gửi và nonce.
- **Kiến trúc Gom Lô Tách Biệt Theo Phân Đoạn `(chainId, tokenContract)` (Segregated Batch Queues):**
  * *Bất biến giao thức:* Lời gọi `batchMtxPay` là phương thức của một hợp đồng cụ thể trên một chuỗi cụ thể, **tuyệt đối không gom lẫn lộn các giao dịch khác chuỗi hoặc khác hợp đồng vào cùng một batch**.
  * Hàng đợi được phân đoạn theo composite key: `inbound:queue:{chainId}:{tokenContract}`.
  * Cụm ví Hot Relayer được chia tách theo chuỗi `KeyPool(chainId)` nạp sẵn native gas tương ứng (xDAI, CELO, ETH, native coin).
  * Worker chuyên trách của chuỗi gom $M = 10 \dots 50$ giao dịch trong cửa sổ gom $T_{\text{batch}} = 3\text{s}$ và phát lệnh `tokenContract.batchMtxPay(payments[])`, tiết kiệm **40% – 60% tổng chi phí gas**.
- **Đối Soát Đa Sổ Nhật Ký Kế Toán ERP Tự Động:** Khi batch giao dịch vượt qua Finality Gate, Odoo Projector đối chiếu danh sách `payId` với hóa đơn `account.move` và tự động hạch toán thanh toán vào đúng Sổ nhật ký ngân hàng `account.journal` tương ứng với hợp đồng token trên chuỗi đó.

#### C. Chuẩn Hóa Endpoint URL & Kiến Trúc Adapter Cho Các Hệ Sinh Thái Non-EVM (SUI, TON, HBAR, Soroban, Cosmos)
- **Cấu trúc URL chuẩn:** `POST /api/v1/blockchain/{ecosystem}/{network_or_chain_id}/inbound-{tx_type}`
  * **EVM:** `POST /api/v1/blockchain/evm/{chainId}/inbound-meta-tx`
  * **SUI:** `POST /api/v1/blockchain/sui/{network}/inbound-sponsored-tx` (Move PTB Dual-Signer, `txBytes` + `userSignature`, pre-flight `sui_devInspectTransactionBlock`, sponsor gas coin từ `KeyPool(sui)`).
  * **TON:** `POST /api/v1/blockchain/ton/{network}/inbound-boc` (Bag-of-Cells `boc`, parsing qua `ton-core`, trích xuất 32-byte `payId` trong forward payload cell, nộp toncenter RPC `sendBoc` với nanoTON gas từ `KeyPool(ton)`).
  * **Hedera / Stellar Soroban / Cosmos:** Lần lượt qua Payer Account, Fee-Bump CAP-0015, và `x/feegrant`.
- **Cổng hợp nhất:** `POST /api/v1/blockchain/inbound-tx` kèm headers `X-Ecosystem` và `X-Network`.

---

## 3. BẢNG ĐỐI CHIẾU THAY ĐỔI GIỮA BẢN NGHIÊN CỨU VÀ BẢN CHUẨN TẮC V3

| Khía cạnh | Bản Nghiên cứu Cũ (Research Drafts) | Bản Chuẩn Tắc Sản Xuất V3 (Canon & Architecture) |
|---|---|---|
| **Cấp phát Nonce Relayer** | Chỉ dựa vào Redis Lease + Fencing Token đơn lẻ | **Ưu tiên Multi-Wallet Relayer Pool Round-Robin** + Treasury Auto-Refill; Redis Lease là tùy chọn |
| **Bản tin MetaTx** | Độc quyền cấu trúc EIP-1776 tổng quát | **Phân định 2 luồng:** Fast-Path `mtxPay` (tiết kiệm 4.2k gas) vs Generic Calldata `executeMetaTransaction` |
| **Phí Relayer** | Cố định người gửi trả phí qua token | **Linh hoạt:** Bên nhận trả phí (`feePaidByRecipient`), Trợ cấp Inbound B2B > $10, và **Bên nhận tự làm Relayer** |
| **Hạ tầng Inbound Doanh nghiệp** | Bắt buộc nộp qua Open Relayer công cộng | **Chuẩn hóa API Inbound Direct-Relay Đa Chuỗi / Đa Hợp Đồng** (`POST /api/v1/blockchain/inbound-meta-tx`) gom lô cách ly (`batchMtxPay`) tiết kiệm 40–60% gas |
| **Kiểm soát Tư pháp** | Chỉ có khái niệm Freeze chung chung | **Chuẩn hóa `IRegulatedToken`:** Bắt buộc `courtRulingId` và MultiSig Quorum 3-of-5 |
| **Ứng dụng Token** | Chỉ gồm chuyển tiền cơ bản và Zether | **Mở rộng:** Vesting Streaming Vaults, Security Tokens DEX, Sealed-Bid Tender Protocol |
| **Quy trình Mua sắm ERP** | Đàm phán trực tiếp đơn giản | **Tích hợp Đấu thầu Kín Sealed-Bid 2 pha:** Cam kết băm và hoàn cọc 100% tự động |
| **Khởi tạo Token** | Cấu hình thủ công | **Open Asset Tokenization Suite Wizard** trên Open Factory Pattern chia sẻ bytecode |

---

## 4. HƯỚNG DẪN ĐỒNG BỘ CHO ĐỘI NGŨ PHÁT TRIỂN

1. **Bộ Hợp Đồng Thông Minh (`smartcontracts/`):**
   - Giữ nguyên các hợp đồng compiled hiện hành: `WrappedERC20MetaTx`, `MetaTxLib`, `UA`.
   - Bổ sung interface chuẩn vào thư viện giao thức: `IRegulatedToken.sol`, `ISealedBidTender.sol`, `IVestingVault.sol`, `ISecurityToken.sol`.
2. **Addon Odoo 19 (`custom-addons/bamboo-dms/`):**
   - Cập nhật model `blockchain.relay.job` và dịch vụ Relayer Pool hỗ trợ đa ví (`relayer_ids`, Round-Robin selection) phân vùng theo `chain_id`.
   - Mở rộng model `blockchain.chain` và `blockchain.token` (gắn `account.journal`) quản lý danh mục đa chuỗi và đa hợp đồng.
   - Mở rộng Controller Odoo tiếp nhận API Inbound Direct-Relay (`POST /api/v1/blockchain/inbound-meta-tx`) hỗ trợ tham số `chainId` & `tokenContract`, tích hợp hàng đợi gom lô phân vùng `inbound:queue:{chainId}:{tokenContract}` gọi `batchMtxPay` tối ưu 40-60% gas và tự động gạch nợ đa sổ kế toán.
   - Tích hợp trường `court_ruling_id` và luồng ký duyệt Multi-Sig 3-of-5 trong `blockchain.account`.
   - Cập nhật module `bamboo_dms_tender` kết nối trực tiếp với smart contract `ISealedBidTender`.
3. **Bộ Quy Chuẩn Tuân Thủ:**
   - Mọi bản án, quyết định cưỡng chế tài sản số phải có số hiệu văn bản pháp lý lưu tại hệ thống quản lý văn bản nội bộ trước khi tạo transaction trên chuỗi.
