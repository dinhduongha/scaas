> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Research library

Background research behind the SCaaS design, kept unchanged except for the one-line banner at the top of each
file. Nothing here is normative: the current rules are the component docs under `docs/`, and every ruling's
rationale is restated, self-contained, in `docs/decisions.md`. Current docs link here only from `decisions.md`
"Source." lines.

Moved from `docs/superpowers/specs/blockchain-research/` on 2026-10-07. The wallet signing formats note that used
to live here is normative and is now `docs/history/specs/round3-wallet-signing-formats.md`.

Market-specific material (`13-legal-vn.md`) never enters the product docs; it and `_GROK-CODE.md` (raw tool
output) are kept while the repository is private and are dropped before a public release (owner, 2026-10-07).

| File | Title |
|---|---|
| [00-CANON.md](00-CANON.md) | 00. CANON — the settled spine |
| [01-token-factory.md](01-token-factory.md) | 01. Token Factory, vòng đời Token và cơ chế Peg/Wrap |
| [02-account-registry.md](02-account-registry.md) | 02. Singleton Account Registry và các sơ đồ chữ ký |
| [03-zether-crypto.md](03-zether-crypto.md) | 03. Zether: mat ma hoc, 128-bit range proof, epoch va rollOver |
| [04-eip1776-metatx.md](04-eip1776-metatx.md) | 04. Meta-Transaction trên token: struct, 2D nonce, thao tác có kiểu |
| [05-open-relayer-network.md](05-open-relayer-network.md) | 05. Open Relayer Network: intent pool, kinh tế học, chống front-run |
| [06-relay-pool-enterprise.md](06-relay-pool-enterprise.md) | 06. Relay Pool nội bộ: nonce manager, gas circuit breaker, simulation gate |
| [07-custody-providers.md](07-custody-providers.md) | 07. Custody pluggable: HSM, MPC, custodial, non-custodial, smart account |
| [08-chain-adapters.md](08-chain-adapters.md) | 08. Chain adapter va chain profile: 6 he sinh thai + private chain |
| [09-payment-modes.md](09-payment-modes.md) | 09. Payment API và 5+ chế độ tích hợp, chọn bằng cấu hình |
| [10-odoo-addon-design.md](10-odoo-addon-design.md) | 10. Thiết kế addon dms_blockchain: model, ACL, RPC, cấu hình |
| [11-indexer-finality.md](11-indexer-finality.md) | 11. Indexer, Finality Gate, reorg va idempotency |
| [12-threat-model.md](12-threat-model.md) | 12. Mô hình đe doạ và bảo mật |
| [13-legal-vn.md](13-legal-vn.md) | 13. Phap ly Viet Nam, CBDC, AML/KYC va Travel Rule |
| [14-contracts-repo-testing.md](14-contracts-repo-testing.md) | 14. Cay smartcontracts/, toolchain va chien luoc kiem thu |
| [15-settlement-layer.md](15-settlement-layer.md) | 15. Lớp settlement thống nhất và đối soát với kế toán |
| [16-decomposition-roadmap.md](16-decomposition-roadmap.md) | 16. Chia nho thanh sub-project va thu tu thuc hien |
| [AUDIT_SPEC_REPORT_20260831_021000.md](AUDIT_SPEC_REPORT_20260831_021000.md) | BÁO CÁO TOÀN DIỆN VỀ ĐẶC TẢ KIẾN TRÚC BLOCKCHAIN |
| [SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md](SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md) | TỔNG HỢP VÀ NÂNG CẤP KIẾN TRÚC BLOCKCHAIN DOANH NGHIỆP V3.0 (SYNTHESIS V3) |
| [_CRITIQUES.md](_CRITIQUES.md) | Cross-section critique — 93 issues from 4 adversarial lenses |
| [_EXPLAIN-07-CUSTODY.md](_EXPLAIN-07-CUSTODY.md) | Giải thích cơ chế `07-custody-providers.md` |
| [_GROK-CODE.md](_GROK-CODE.md) | Grok3_Continued — code blocks |
| [_MANIFESTS.md](_MANIFESTS.md) | Per-section manifests: key findings, open questions, corrections to blockchain.md |
| [_REVIEW-01-UPGRADE.md](_REVIEW-01-UPGRADE.md) | Review: `01-token-factory` và toàn bộ cơ chế upgrade |
| [_USER-DECISIONS.md](_USER-DECISIONS.md) | Quyết định của user + phát hiện từ code thật |
| [eip7702-eip8141-vs-metatx.md](eip7702-eip8141-vs-metatx.md) | EIP-7702 and EIP-8141 compared with the SCaaS meta-transaction (2026-10-11) |
| [pq-eips-vs-scaas.md](pq-eips-vs-scaas.md) | Post-quantum EIP drafts and SCaaS (2026-10-11) |
