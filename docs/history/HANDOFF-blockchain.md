# HANDOFF — blockchain (việc của owner/vận hành, và việc đã lên lịch nhưng chưa xây)

Nguồn: gap analysis `/.superpowers/blockchain-gap-analysis.md` (GA), spec round 3 §A.10.

## 1. Bước của owner / vận hành (không làm trong code)

| # | Việc | Tham chiếu |
|---|---|---|
| O1 | Audit bên thứ ba cho mọi contract (Solidity, Move, Soroban, CosmWasm, Tact) trước khi giữ tiền thật | GA 2.1#5, I§7.3 #4 |
| O2 | `registrar` của OpenFactory là một EOA (mặc định deployer) ⇒ chuyển sang multisig trước mainnet | GA 2.1#5, B12 |
| O3 | Triển khai thật (chain 7622 — formerly 9000, Gnosis; sau đó các mạng round 3) và ghi `deployments/<chain>.json` | GA 2.1#6, N9 |
| O4 | Bằng chứng finality 7 ngày + ≥2 RPC độc lập trước khi chuyển chain sang `active` | GA 2.1#6, I§5.1 |
| O5 | Rate limit theo IP ở reverse proxy trước gateway mở | GA 2.1#9 |
| O6 | Adapter custody production (KMS/HSM/broker) cho ví custodial/delegated; `env:` chỉ dev (R50) | GA 2.1#1, R50 |
| O7 | Signer KMS/HSM cho khoá relayer (seam `Signer`, R59) trên chain công khai | GA 2.1#2 |
| O8 | Nạp và theo dõi số dư lane relayer từ treasury (metric `scaas_relayer_balance`) | GA H6, N4 |
| O9 | Quyết định DPIA / CI gate cho Land vào ERP | SRS deltas #11 |
| O10 | `MandateWallet`/account chủ thể: quy trình onboarding (deploy ngoài Odoo, R29) | R29 |
| O11 | Mỗi NPP thu on-chain cần provider `chain` + journal + ví nhận đã duyệt (sau khi hợp nhất territory) | GA 2.4#4 |

## 2. Đã lên lịch, chưa xây (GA §2.2 trừ #4/#6/#7 đã làm ở round 3)

| GA 2.2 | Việc | SRS |
|---|---|---|
| #1 | `burn` tầng 1 và wrap theo tỷ lệ tầng 2 — cần implementation v2 (v1 bất biến) | A§3.1, BM |
| #2 | Universal Account Registry (PoP, liên kết) + chiếu danh tính đối tác | A§7.5, A§9.5, I§4.6 |
| #3 | KeyPool + tự nạp từ treasury (lane relayer đã có ở round 3; tự nạp chưa) | A§4.9.4 #4 |
| #5 | Schema inbound doanh nghiệp đầy đủ + `batchMtxPay` gom lô | A§4.9.4 |
| #8 | Người nhận trả phí, chính sách trợ giá gas theo USD, hạch toán OPEX | A§4.9.1–2, I§2.5 |
| #9 | Chi trả ra ngoài (treasury → nhà cung cấp/NPP) | I§3.1 |
| #10 | Telemetry W3B-01…06, trace OTel, FinOps chi phí gas/chứng từ | I§6 |
| #11 | Neo bằng chứng (Merkle batching, HCS) | BM §6.21, I§1.3.4 |
| #12 | Quy trình xoá dữ liệu cá nhân `payer_address ↔ partner` (trung lập thị trường) | I§1.3 |
| #13 | Zether (verifier, registry, `rollOverSigned`), mesh libp2p, regulated token, tender, vesting, Celo CIP-64 / `l1_batch` | A§7–§10 |
| #14 | `cancelMetaNonce` cho người dùng, QR tự relay/e-cheque, QR EIP-681 | canon M11 |
| #15 | Drift A/C cho họ không phải EVM (adapter cần `balanceOf` + event chuyển khoản tới ví nhận); CI cho suite bridge cần repo `bamboo_idempotency` (biến `BAMBOO_IDEMPOTENCY_REPO`) | R56, R52 |

## 3. Hợp nhất với `feat/territory-document-tier` (coordinator làm)

Seam: `dms.portal.api._dms_chain_receiving_company(order)` (mọi lookup đi qua) và
`res.users._blockchain_wallet_admin(company)`. Chi tiết: GA §2.4.

## 4. Zether (round 3, luồng S2) — **UNAUDITED — NOT FOR PRODUCTION FUNDS**

Contract `smartcontracts/evm/src/zether/**` (`ZetherToken`, `ZetherMetaTx`, `ZetherVerifierBn254`,
`ZetherVerifierBls12381`, `ZetherCurves`, `ZetherTranscript`, `ZetherSafety`) và `src/registry/**`
(`UniversalAccountRegistry`) là hiện thực tham chiếu **chưa audit**. Đặc tả: `specs/2026-10-03-zether-design.md`.

| # | Việc của owner / vận hành | Ghi chú |
|---|---|---|
| Z1 | Audit mật mã độc lập (Σ-Bullets, transcript, IPA, registry PoP) **trước khi** bỏ cổng dev | canon C5.4 / §3.4.6 |
| Z2 | Cổng: `OpenFactory.zetherEnabled` mặc định tắt; chỉ bật được trên chain id 31337/1337 (`ZetherSafety`). Token, verifier, registry cũng từ chối deploy/khởi tạo ngoài allowlist. Thêm chain = sửa `ZetherSafety` + deploy version mới, sau Z1 | RS2-1 |
| Z3 | Quyết định chain 7622 (formerly 9000) có phải "dev" không (hiện **không**) | needs owner |
| Z4 | Chốt curve (gate G1): BLS12-381 an toàn hơn nhưng **không** rẻ hơn bn254 (đo §15 đặc tả) | canon C6.1 |
| Z5 | Tối ưu gas trước public chain: transfer bn254 2.75M > kill criterion 2.5M | đặc tả §15 |
| Z6 | Form chain/token Odoo hiển thị cảnh báo UNAUDITED (luồng tích hợp Odoo) | R34 |
