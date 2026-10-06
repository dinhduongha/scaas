# Blockchain là Dịch vụ Hạ tầng Cơ sở

> Nguồn: SRS `ai-enterprise-blockchain-architecture.md` — nguyên tắc 6 và §1.1 (quyết định của chủ dự án, 2026-10-03). Tham chiếu "nguyên tắc 2/3", "§3.2", "§4.4", "§4.9", "§5.2", "§7" là các mục trong SRS đó.
>
> **Rev 1.1 (2026-10-07):** Claude review 1 folded (section "Claude review 1" at the end). Định vị được sửa theo
> `docs/SCaaS.md` §1.1 (chuẩn tắc, thắng tài liệu này khi lệch). **Câu hỏi mở của owner Q1** (khả năng nâng cấp gói
> Aptos/Sui/Solana) chưa quyết — các hàng bảng chạm tới nó được đánh dấu "(Q1)".

**Blockchain là Dịch vụ Hạ tầng Cơ sở (Blockchain as Foundational Infrastructure Service):**
- **Smart contract chính là dịch vụ API** chạy nghiệp vụ (SCaaS §1.1, owner): thanh toán, mandate, token và wrapper, DEX, đấu thầu, vesting, phân phối, chuyển khoản bảo mật là các hàm contract — mã theo họ mạng, deploy thành clone EIP-1167 từ factory mở trên EVM và module/program tương đương ở họ khác — kiểm chữ ký, nonce, hạn và hạn mức của chủ thể trên mọi lời gọi. ERP, DMS, portal, mobile, AI agent gọi chúng như gọi một API. **Contract là sản phẩm**, không phải một tính năng gắn vào ERP; SCaaS không phụ thuộc ERP nào (Odoo là một client, R87).
- **`scaas-node` là hạ tầng, không phải sản phẩm: ai cũng chạy được.** Nó kiêm relayer (nộp intent đã ký, trả gas, journal, index, chờ finality, trả lại sự kiện đã final). Mỗi nhà vận hành **độc lập** và tự đặt chính sách nhận, phí, tài trợ, denylist, gossip, peer và SLO; bảo đảm của giao thức (luật contract, chữ ký, nonce) không phụ thuộc nhà vận hành nào. **Bên nhận tự relay** là đường hạng nhất (SCaaS §5.9). *(Bản trước gọi blockchain là "lớp hạ tầng dùng chung ngang compute/DB" và relayer là của nhà vận hành — sửa theo Claude review M5.)*
- Khác biệt cốt lõi với các dịch vụ hạ tầng truyền thống nằm ở **gốc thẩm quyền ghi (write authority)**: ở dịch vụ truyền thống, **server ký** (JWT/session) và server được tin là đã kiểm tra quyền; ở dịch vụ blockchain, **client ký** từng thao tác ghi bằng khóa của chính chủ thể, và mọi bên đều kiểm chứng được chữ ký đó mà không cần tin server.
- Xem so sánh chi tiết ở mục [So sánh Mô hình Thẩm quyền](#so-sánh-mô-hình-thẩm-quyền-iaas-ec2--compute-engine-vs-baas-supabase-vs-dịch-vụ-blockchain) bên dưới.

## So sánh Mô hình Thẩm quyền: IaaS (EC2 / Compute Engine) vs BaaS (Supabase) vs Dịch vụ Blockchain

| Tiêu chí | **IaaS — AWS EC2 / Google Compute Engine** (ứng dụng tự cấp JWT, server ký) | **BaaS — Supabase** (Supabase Auth cấp JWT, server ký; Postgres RLS) | **Dịch vụ Blockchain** (client ký; passkey ký trên mọi thao tác create/update) |
|---|---|---|---|
| **Ai ký thao tác ghi** | Server ứng dụng. Client chỉ cầm JWT do server ký (HS256/RS256); mọi create/update được thực hiện *nhân danh* user bởi server. | Server Supabase Auth ký JWT; PostgREST/Postgres thực thi ghi, RLS đọc `auth.uid()` từ JWT. | **Chính chủ thể**: thiết bị của user ký từng thao tác bằng passkey (WebAuthn, P-256) hoặc ví. Relayer chỉ trả phí gas, **không có khóa của user**. |
| **Gốc tin cậy (trust root)** | Nhà vận hành ứng dụng + nhà cung cấp cloud (IAM, hypervisor) + bất kỳ ai giữ khóa ký JWT. | Supabase (nhà vận hành) + chủ project giữ JWT secret / `service_role` key. | Secure enclave/authenticator trên thiết bị của user + đồng thuận (consensus) của mạng + mã contract bất biến (nguyên tắc 3). **(Q1)** Hôm nay gói Aptos, Sui và program Solana nâng cấp được bằng một khoá — nếu owner giữ khả năng nâng cấp, khoá nâng cấp (multisig + timelock) là một gốc tin cậy tường minh của họ đó. |
| **Ai có thể giả mạo thao tác của user** | Bất kỳ ai giữ khóa ký JWT, có quyền ghi DB trực tiếp, hoặc chiếm được server/IAM — có thể ghi *thay* user mà không để lại dấu vết phân biệt được. | Bất kỳ ai giữ JWT secret (tự cấp token cho uid bất kỳ) hoặc `service_role` key (bỏ qua RLS), hoặc có quyền DB của nhà vận hành. | **Không ai** nếu không có khóa riêng của user **(Q1: ngoại trừ người giữ khoá nâng cấp gói Aptos/Sui/Solana chừng nào nó còn)**. Relayer/nhà vận hành chỉ có thể **từ chối hoặc trì hoãn** (censorship/liveness), không thể giả mạo; chống bằng relayer khác, hoặc chủ thể / **bên nhận** tự gửi (SCaaS §5.9). Luồng portal mặc định ràng relayer của công ty (`MODE_RESTRICT_RELAYER`, R10): đổi quyền người trả tự gửi lấy an toàn front-run; bên nhận vẫn tự relay được. |
| **Chống chối bỏ (non-repudiation)** | Không có: log do server ghi, server có thể tạo ra bất kỳ dòng nào. | Không có (cùng lý do). | **Có cho từng thao tác**: chữ ký của user gắn với payload (domain-separated, có nonce + hạn dùng), kiểm chứng công khai mãi mãi. |
| **Nhật ký kiểm toán** | Log ứng dụng/CloudTrail — do bên vận hành giữ, sửa/xóa được. | Log Postgres/Supabase — do nhà vận hành giữ. | Sổ cái phân tán, chỉ-ghi-thêm, ai cũng đối soát được; ERP là bản sao đọc vào (Land) từ sổ cái **qua node của nó** — xem hàng "Land". |
| **Thực thi phân quyền** | Code ứng dụng (dễ sót một endpoint). | RLS trong Postgres — tập trung hơn, nhưng `service_role` và lỗi policy vẫn bỏ qua được. | Mã contract kiểm chữ ký + nonce + hạn mức trên **mọi** lời gọi. **Không admin nào chuyển được tiền của chủ thể, ngoại trừ** các quyền có giới hạn hoặc chốt lúc tạo sau: TW2 `rateAdmin`/`guardian` (R142, `SingleUnderlyingToken.sol:261-331`, `MultiUnderlyingToken.sol:86-98`); `OrderBookDex.admin` `setMarket` (phí ≤ 1 %, `OrderBookDex.sol:143-151`); admin token Soroban mint không giới hạn (`soroban/contracts/token/src/lib.rs:188-194`); admin DEX TON `WithdrawFees` (sẽ không còn nhận hoàn tiền bị bounce, R3D CR-R3-9); `Sweep` của DEX Cosmos (bỏ, R3D CR-R3-10); và **(Q1)** khoá nâng cấp gói Aptos/Sui/Solana. SCaaS §4.5 liệt kê TW2 theo cùng cách. |
| **Thu hồi / đổi khóa** | Dễ: TTL ngắn, deny-list, xoay khóa server. | Dễ: xoay JWT secret, revoke refresh token. | Khó hơn: xoay khóa on-chain (smart account / Account Registry); chính sách khôi phục là công tắc backup (S4F R250–R254). **Theo họ** (R3D CR-R3-6): EVM, Aptos, Solana có xoay + guardian; Sui xoay theo từng coin type tới khi có `Keys` (CR-R3-5); Soroban guardian mới là seam; passkey Cosmos và TON chưa xoay được; EOA thường không bao giờ xoay được. |
| **Độ trễ & chi phí ghi** | Mili-giây; chi phí compute/DB. | Mili-giây; theo gói dịch vụ. | Theo thời gian finality của mạng (giây); mỗi thao tác ghi tốn gas — do relayer tài trợ (§4.9, §5.2). |
| **Đọc dữ liệu** | Server phục vụ. | PostgREST + RLS. | **Không ký**: đọc qua feed của node (`/v1/jobs`, `/v1/events`, NI R93/R94 — SPECIFIED; hôm nay Odoo nhận push `chain_event_ingest`), indexer hoặc ERP như dịch vụ thường (JWT/session vẫn dùng cho đọc và workflow ERP). Chỉ thao tác **ghi có giá trị** đi qua chữ ký client. |
| **Land (ghi nhận vào ERP)** | — | — | ERP tin **node của mình** và, qua node, **quorum RPC**: một sự kiện chỉ được ghi nhận khi ≥ `quorum` nhà cung cấp độc lập trả **cùng tập sự kiện** cho vùng đã final (spec gốc CR-PD-2, R3D CR-R3-2); `quorum = 1` = tin một nhà cung cấp; node bị chiếm có thể nói dối trên `/v1/events` (SCaaS §3.5, NI T7). "Ai cũng kiểm chứng được không cần tin server" đúng cho **chữ ký**, không tự động đúng cho bút toán ERP. |
| **Riêng tư** | Dữ liệu nằm trong hạ tầng của bên vận hành. | Như trên. | Sổ cái công khai: danh tính hai đầu công khai theo thiết kế (nguyên tắc 2), số tiền/số dư che bằng Zether (§7). |
| **Hỏng hóc điển hình** | Lộ khóa ký JWT / IAM = giả mạo toàn bộ người dùng. | Lộ JWT secret / `service_role` = giả mạo toàn bộ người dùng, bỏ qua RLS. | Lộ khóa **một** user = chỉ user đó bị ảnh hưởng, giới hạn bởi hạn mức mandate; mất relayer = chậm, không mất tiền. **(Q1)** Lộ khoá nâng cấp gói Aptos/Sui/Solana = mọi chủ thể trên mạng đó — chính kiểu hỏng của IaaS/BaaS, nên Q1 phải được quyết trước production. |

**Hệ quả thiết kế:**

1. **Phạm vi chữ ký client:** mọi thao tác create/update có giá trị (chuyển tiền, thanh toán, khớp lệnh DEX, cấp/đổi quyền, đăng ký khóa) phải mang chữ ký của chủ thể. Server **không bao giờ** giữ khóa để ký thay user. Ngoại lệ duy nhất là ví custodial do chính user/tổ chức chủ động ủy thác, có hạn mức và nhật ký phê duyệt. *(Ghi rõ — Claude review L3: khoá custody `env:` chỉ-dev nằm trong tiến trình Odoo (R50); node ký job `call` do ERP dựng — chỉ khi selector + đích thuộc bảng cho phép, spec gốc CR-PD-1.)*
2. **Passkey (WebAuthn, P-256/secp256r1):** passkey không ký trực tiếp digest mà ký `authenticatorData ‖ SHA-256(clientDataJSON)`; challenge trong `clientDataJSON` phải là digest typed-data của thao tác (EIP-712 hoặc tương đương trên mạng không phải EVM). Contract (hoặc smart account qua EIP-1271, `AuthScheme 7`) phải kiểm cả định dạng WebAuthn lẫn challenge, cờ user-presence/user-verification, và chống malleability (`s` thấp). Trên EVM dùng precompile P-256 khi mạng hỗ trợ (RIP-7212 / EIP-7951), nếu không thì dùng verifier thuần Solidity. Trên các mạng khác dùng cơ chế verify P-256/passkey gốc của mạng nếu có; nếu không có thì verify trong contract. *(Claude review M1 — chưa đạt trên mọi mạng: Cosmos không kiểm rpIdHash, origin, UV (`cosmos/metaop/src/lib.rs:130-148`); Sui, Soroban, TON, Solana không từ chối `crossOrigin: true`. Quy tắc và ngữ pháp chung: R3D CR-R3-1, stream R3-FIX1/R3-FIX2. P-256 precompile RIP-7212/EIP-7951 ở `0x100`, OZ 5.2 `P256.verify` dò rồi fallback (SCaaS §7.1) — đúng; chain riêng là 7622 (formerly 9000).)*
3. **UX:** ký passkey trên mọi thao tác ghi = một lần xác thực sinh trắc/PIN cho mỗi thao tác. Nhiều thao tác liên quan được gom vào **một** chữ ký trên gốc Merkle hoặc danh sách thao tác (batch), vẫn đảm bảo từng thao tác được chủ thể phê duyệt. *(Claude review M2: gom lô Merkle hôm nay chỉ có trên EVM (`SubjectAccount.sol:257`) và Soroban (`soroban/contracts/account/src/lib.rs:136`); Sui, Aptos, Cosmos, TON, Solana kiểm từng digest.)*
4. **Không khóa chủ thể (anti-lock):** chữ ký client đi qua meta-transaction với nonce/lane **riêng từng contract**, không dùng sequence của tài khoản user làm thứ tự. Nhờ vậy thao tác của một chủ thể trên nhiều contract không chặn lẫn nhau khi một giao dịch bị treo (§4.4). *(Đúng, với hai lưu ý — Claude review L2: `cancelMetaNonce` trên EVM là một tx trực tiếp, chủ thể tự trả gas (`ERC20MetaTx.sol:58-60`); trên họ xoá lane (TON, Aptos, Solana) "thực thi tối đa một lần" phụ thuộc horizon `validUntil`, spec gốc CR-PD-4.)*
5. **Kết hợp:** đọc, báo cáo và workflow ERP vẫn dùng JWT/session như IaaS/BaaS. Blockchain là lớp hạ tầng cho **thẩm quyền ghi và giá trị**, không thay thế database ứng dụng.

---

---

## Câu hỏi mở của owner Q1 — khả năng nâng cấp gói Aptos, Sui, Solana

**Chưa quyết trong revision này.** Bằng chứng, phương án và khuyến nghị đầy đủ: round-3 design §H.3. Tóm tắt:
gói Aptos (`upgrade_policy = "compatible"`, `deploy-object`), Sui (UpgradeCap giữ lại) và program Solana (upgrade
authority giữ lại) giữ số dư của mọi chủ thể và nâng cấp được bằng **một** khoá hôm nay; TON và Soroban bất biến;
token EVM là clone không nâng cấp.

| Phương án | Nội dung |
|---|---|
| (a) Bất biến sau audit | Aptos `immutable`, Sui `make_immutable`, Solana `--final`, Cosmos không `--admin`; sửa lỗi = gói mới + di chuyển tự nguyện |
| (b) Multisig + timelock | Khoá nâng cấp là multisig có trễ công khai; liệt kê tường minh là gốc tin cậy trong bảng trên và SCaaS §1.2/§1.3 |
| (c) Một khoá chỉ cho dev, có cổng production | Node/script deploy từ chối mạng không phải dev khi authority là một khoá |

**Khuyến nghị: (b) cho tới khi audit, sau đó (a)**; cổng (c) áp ở cả hai giai đoạn.

## Claude review 1 (2026-10-07) — disposition (rev 1.1)

Source: `docs/reviews/specs/2026-10-03-blockchain-infrastructure-service-claude-review-1.md` (verdict FIX-THEN-GO).
Re-checked against `docs/SCaaS.md` §1 and the code on 2026-10-07 (`scaas` 991d835, `bamboo-dms` b724c91). This is a
positioning text: no ruling ids of its own; code consequences are ruled where the code is specified (spec gốc, R3D,
addendum). Docs only.

| # | Sev | Verified | Disposition |
|---|---|---|---|
| H1 | high | Confirmed: `move/aptos/Move.toml:4`, `smartcontracts/scripts/deploy.sh:9`, `solana/scripts/deploy.sh:10-11,31`; contradicts SCaaS §1.2/§1.3 and this table. | **Not decided — OPEN OWNER QUESTION Q1** (above; R3D §H.3); table rows marked "(Q1)" |
| H2 | high | Confirmed: event push trusts the node's primary RPC for logs (`scaas-node/src/indexer.rs:115-142`); Cosmos/TON no quorum (`adapters/cosmos.rs:522`, `adapters/ton.rs:1217`); SCaaS §3.5 states the node trust, this spec did not. | **Accepted**: new "Land" row; event-set quorum ruled in spec gốc CR-PD-2 / R3D CR-R3-2 |
| M1 | med | Confirmed (`cosmos/metaop/src/lib.rs:130-148`; `crossOrigin` not rejected on Sui/Soroban/TON/Solana). | **Accepted**: consequence 2 note; ruled R3D CR-R3-1 |
| M2 | med | Confirmed (`SubjectAccount.sol:257`, `soroban/contracts/account/src/lib.rs:136`). | **Accepted**: consequence 3 note (no stream: a feature, not a bug) |
| M3 | med | Confirmed (Cosmos `metaop/src/lib.rs:89-94`; Soroban seam `account/src/lib.rs:1-4`; TON `jetton.tact:219`; Sui per coin type `meta.move:93-105`). | **Accepted**: "Thu hồi / đổi khóa" row per family; ruled R3D CR-R3-6 |
| M4 | med | Confirmed (`SingleUnderlyingToken.sol:261-331`, `MultiUnderlyingToken.sol:86-98`, `OrderBookDex.sol:143-151`, `soroban/contracts/token/src/lib.rs:188-194`, `cosmos/dex/src/lib.rs:137-143`, `ton/contracts/dex.tact:131-136`). | **Accepted**: "Thực thi phân quyền" row lists the exceptions |
| M5 | med | Confirmed against SCaaS §1.1 (contracts are the product; node is infrastructure anyone runs; operators independent; payee self-relay §5.9) and R10 (`blockchain_payment_request.py:135-142`). | **Accepted**: intro rewritten; "Ai có thể giả mạo" row states the R10 trade-off |
| L1 | low | NI R93/R94 SPECIFIED; Odoo push today. | **Accepted**: "Đọc dữ liệu" row |
| L2 | low | Confirmed (`ERC20MetaTx.sol:58-60`; pruning, spec gốc CR-PD-4). | **Accepted**: consequence 4 note |
| L3 | low | Confirmed (R50; call jobs, spec gốc H1). | **Accepted**: consequence 1 note |
| L4 | low | Confirmed (SCaaS §7.1). | **Accepted**: consequence 2 note; chain 7622 (formerly 9000) |
| Superseded list | — | SCaaS §1 (positioning), NI R87 (ERP is one client), RS11-13 (upgradeable packages, now Q1), TW2 R142 (creation-time admin roles), S4F R250–R254 (backup switch). | **Accepted**: table below |

Rejected: none. Counts: 2 high (H1 left open), 5 medium, 4 low, 1 list — 11 accepted, 1 open question, 0 rejected.

### Superseded statements

| This spec said | Superseded by |
|---|---|
| Blockchain = shared infrastructure next to compute/DB; relayer belongs to the operator | SCaaS §1.1: the contracts are the product/API; `scaas-node` is infrastructure anyone runs; operators independent; payee self-relay first-class (§5.9) |
| ERP reads in from the ledger (implicitly trustless) | NI R87 (ERP is one client of its node), SCaaS §3.5 / NI T7 (node trusted for its feed), CR-PD-2 / CR-R3-2 (event-set quorum) |
| "Mã contract bất biến … không có khóa admin vượt quyền" on every family | RS11-13 (upgradeable Move/Solana packages) — now open question Q1; TW2 R142 and the admin list in the table |
| "Cần nhiều passkey hoặc guardian" as the recovery policy | S4F R250–R254 backup switch; per-family capability R3D CR-R3-6 |

### Amendments needed in other specs (recorded; owner syncs)

| Spec | Amendment |
|---|---|
| SCaaS.md | §1.2 table: "Land" row and the "(Q1)" qualifiers until Q1 is decided; "no admin key above it" → "no admin can move a subject's funds, except: …" (the list above); §1.3 "An upgradeable platform" row per Q1. |

### Code streams

None new: every code consequence is a stream of the spec that rules it (PAY-FIX1…3, R3-FIX1…4, R3-FIX7…10,
R3-FIX13…14).

### Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | Positioning text from SRS principle 6 / §1.1 |
| 1.1 | 2026-10-07 | Claude review 1 folded: positioning corrected per SCaaS §1.1; "Land" row; admin-power exceptions; per-family rotation; 11 findings accepted, 0 rejected; H1 recorded as **open owner question Q1** |
