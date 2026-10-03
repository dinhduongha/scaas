# Blockchain là Dịch vụ Hạ tầng Cơ sở

> Nguồn: SRS `ai-enterprise-blockchain-architecture.md` — nguyên tắc 6 và §1.1 (quyết định của chủ dự án, 2026-10-03). Tham chiếu "nguyên tắc 2/3", "§3.2", "§4.4", "§4.9", "§5.2", "§7" là các mục trong SRS đó.

**Blockchain là Dịch vụ Hạ tầng Cơ sở (Blockchain as Foundational Infrastructure Service):**
- Blockchain được định vị ngang hàng với các dịch vụ hạ tầng cơ sở khác (compute, database, storage, identity) — **không phải một tính năng ứng dụng** gắn thêm vào ERP. Mọi ứng dụng (ERP, DMS, Portal, Mobile, AI Agent) dùng chung lớp hạ tầng này như dùng chung database hay object storage.
- Khác biệt cốt lõi với các dịch vụ hạ tầng truyền thống nằm ở **gốc thẩm quyền ghi (write authority)**: ở dịch vụ truyền thống, **server ký** (JWT/session) và server được tin là đã kiểm tra quyền; ở dịch vụ blockchain, **client ký** từng thao tác ghi bằng khóa của chính chủ thể, và mọi bên đều kiểm chứng được chữ ký đó mà không cần tin server.
- Xem so sánh chi tiết ở mục [So sánh Mô hình Thẩm quyền](#so-sánh-mô-hình-thẩm-quyền-iaas-ec2--compute-engine-vs-baas-supabase-vs-dịch-vụ-blockchain) bên dưới.

## So sánh Mô hình Thẩm quyền: IaaS (EC2 / Compute Engine) vs BaaS (Supabase) vs Dịch vụ Blockchain

| Tiêu chí | **IaaS — AWS EC2 / Google Compute Engine** (ứng dụng tự cấp JWT, server ký) | **BaaS — Supabase** (Supabase Auth cấp JWT, server ký; Postgres RLS) | **Dịch vụ Blockchain** (client ký; passkey ký trên mọi thao tác create/update) |
|---|---|---|---|
| **Ai ký thao tác ghi** | Server ứng dụng. Client chỉ cầm JWT do server ký (HS256/RS256); mọi create/update được thực hiện *nhân danh* user bởi server. | Server Supabase Auth ký JWT; PostgREST/Postgres thực thi ghi, RLS đọc `auth.uid()` từ JWT. | **Chính chủ thể**: thiết bị của user ký từng thao tác bằng passkey (WebAuthn, P-256) hoặc ví. Relayer chỉ trả phí gas, **không có khóa của user**. |
| **Gốc tin cậy (trust root)** | Nhà vận hành ứng dụng + nhà cung cấp cloud (IAM, hypervisor) + bất kỳ ai giữ khóa ký JWT. | Supabase (nhà vận hành) + chủ project giữ JWT secret / `service_role` key. | Secure enclave/authenticator trên thiết bị của user + đồng thuận (consensus) của mạng + mã contract bất biến (nguyên tắc 3). |
| **Ai có thể giả mạo thao tác của user** | Bất kỳ ai giữ khóa ký JWT, có quyền ghi DB trực tiếp, hoặc chiếm được server/IAM — có thể ghi *thay* user mà không để lại dấu vết phân biệt được. | Bất kỳ ai giữ JWT secret (tự cấp token cho uid bất kỳ) hoặc `service_role` key (bỏ qua RLS), hoặc có quyền DB của nhà vận hành. | **Không ai** nếu không có khóa riêng của user. Relayer/nhà vận hành chỉ có thể **từ chối hoặc trì hoãn** (censorship/liveness), không thể giả mạo; chống bằng nhiều relayer hoặc user tự gửi giao dịch. |
| **Chống chối bỏ (non-repudiation)** | Không có: log do server ghi, server có thể tạo ra bất kỳ dòng nào. | Không có (cùng lý do). | **Có cho từng thao tác**: chữ ký của user gắn với payload (domain-separated, có nonce + hạn dùng), kiểm chứng công khai mãi mãi. |
| **Nhật ký kiểm toán** | Log ứng dụng/CloudTrail — do bên vận hành giữ, sửa/xóa được. | Log Postgres/Supabase — do nhà vận hành giữ. | Sổ cái phân tán, chỉ-ghi-thêm, ai cũng đối soát được; ERP chỉ là bản sao đọc vào (Land) từ sổ cái. |
| **Thực thi phân quyền** | Code ứng dụng (dễ sót một endpoint). | RLS trong Postgres — tập trung hơn, nhưng `service_role` và lỗi policy vẫn bỏ qua được. | Mã contract bất biến kiểm chữ ký + nonce + hạn mức trên **mọi** lời gọi; không có khóa admin vượt quyền (nguyên tắc 3, §3.2). |
| **Thu hồi / đổi khóa** | Dễ: TTL ngắn, deny-list, xoay khóa server. | Dễ: xoay JWT secret, revoke refresh token. | Khó hơn: xoay khóa on-chain (smart account / Account Registry), cần nhiều passkey hoặc guardian để khôi phục khi mất thiết bị. |
| **Độ trễ & chi phí ghi** | Mili-giây; chi phí compute/DB. | Mili-giây; theo gói dịch vụ. | Theo thời gian finality của mạng (giây); mỗi thao tác ghi tốn gas — do relayer tài trợ (§4.9, §5.2). |
| **Đọc dữ liệu** | Server phục vụ. | PostgREST + RLS. | **Không ký**: đọc qua indexer/ERP như dịch vụ thường (JWT/session vẫn dùng cho đọc và workflow ERP). Chỉ thao tác **ghi có giá trị** đi qua chữ ký client. |
| **Riêng tư** | Dữ liệu nằm trong hạ tầng của bên vận hành. | Như trên. | Sổ cái công khai: danh tính hai đầu công khai theo thiết kế (nguyên tắc 2), số tiền/số dư che bằng Zether (§7). |
| **Hỏng hóc điển hình** | Lộ khóa ký JWT / IAM = giả mạo toàn bộ người dùng. | Lộ JWT secret / `service_role` = giả mạo toàn bộ người dùng, bỏ qua RLS. | Lộ khóa **một** user = chỉ user đó bị ảnh hưởng, giới hạn bởi hạn mức mandate; mất relayer = chậm, không mất tiền. |

**Hệ quả thiết kế:**

1. **Phạm vi chữ ký client:** mọi thao tác create/update có giá trị (chuyển tiền, thanh toán, khớp lệnh DEX, cấp/đổi quyền, đăng ký khóa) phải mang chữ ký của chủ thể. Server **không bao giờ** giữ khóa để ký thay user. Ngoại lệ duy nhất là ví custodial do chính user/tổ chức chủ động ủy thác, có hạn mức và nhật ký phê duyệt.
2. **Passkey (WebAuthn, P-256/secp256r1):** passkey không ký trực tiếp digest mà ký `authenticatorData ‖ SHA-256(clientDataJSON)`; challenge trong `clientDataJSON` phải là digest typed-data của thao tác (EIP-712 hoặc tương đương trên mạng không phải EVM). Contract (hoặc smart account qua EIP-1271, `AuthScheme 7`) phải kiểm cả định dạng WebAuthn lẫn challenge, cờ user-presence/user-verification, và chống malleability (`s` thấp). Trên EVM dùng precompile P-256 khi mạng hỗ trợ (RIP-7212 / EIP-7951), nếu không thì dùng verifier thuần Solidity. Trên các mạng khác dùng cơ chế verify P-256/passkey gốc của mạng nếu có; nếu không có thì verify trong contract.
3. **UX:** ký passkey trên mọi thao tác ghi = một lần xác thực sinh trắc/PIN cho mỗi thao tác. Nhiều thao tác liên quan được gom vào **một** chữ ký trên gốc Merkle hoặc danh sách thao tác (batch), vẫn đảm bảo từng thao tác được chủ thể phê duyệt.
4. **Không khóa chủ thể (anti-lock):** chữ ký client đi qua meta-transaction với nonce/lane **riêng từng contract**, không dùng sequence của tài khoản user làm thứ tự. Nhờ vậy thao tác của một chủ thể trên nhiều contract không chặn lẫn nhau khi một giao dịch bị treo (§4.4).
5. **Kết hợp:** đọc, báo cáo và workflow ERP vẫn dùng JWT/session như IaaS/BaaS. Blockchain là lớp hạ tầng cho **thẩm quyền ghi và giá trị**, không thay thế database ứng dụng.

---
