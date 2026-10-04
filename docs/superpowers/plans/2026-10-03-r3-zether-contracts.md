# Kế hoạch luồng S2 — Zether contracts (round 3)

**Mục tiêu:** hiện thực đầy đủ tầng số dư bí mật Zether theo SRS §7 + đặc tả
`specs/2026-10-03-zether-design.md`, có test bắt buộc, sau cổng dev (UNAUDITED — NOT FOR PRODUCTION FUNDS).
**Kiến trúc:** một `ZetherToken` (clone EIP-1167) cho mọi đường cong; mọi phép nhóm và proof qua `IZetherVerifier`
bất biến (bn254 / BLS12-381); `UniversalAccountRegistry` singleton cho khoá + uỷ quyền; mixin meta-tx riêng.
**Stack:** Solidity 0.8.28, OZ 5.2, forge 1.3.5 (EVM Prague có EIP-2537), py_ecc 8 cho KAT độc lập.

| # | Task | Test viết trước | Commit |
|---|---|---|---|
| 1 | Đặc tả byte-exact cho S3 + review agy | — | `646751d`, `d143390` |
| 2 | Curve libs, transcript, generator NUMS, verifier skeleton | `ZetherKat.t.sol` (vector `kat.py`) | `62d439b` |
| 3 | Σ + Bulletproofs verify, prover chỉ-test | `ZetherVerifier.t.sol` | `6e16eb6` |
| 4 | Registry 8 scheme + PoP | `UniversalAccountRegistry.t.sol` | `19e27a5` |
| 5 | Token + mixin meta-tx + cổng factory | `ZetherToken.t.sol`, `ZetherGate.t.sol`, `ZetherRevertPaths.t.sol` | `eab460a` |
| 6 | Vector S3 (Rust) trên verifier Solidity | `ZetherS3Vectors.t.sol` | `6442513` |
| 7 | Gas, coverage từng chỗ revert, HANDOFF, review nhánh | `ZetherRevertPaths.t.sol` (bảng), `ZetherKat.t.sol` | `7b04a13`, `2466e71`, `0d7183f`, `011d655`, `90d0f9d`, `9d3fc37` |

Chạy: `forge test --match-path 'test/zether/*'` (hoặc `FOUNDRY_PROFILE=zether …`). Sinh lại KAT:
`python3 test/vectors/zether/kat.py` (cần `py_ecc>=8`).

## Review agy — folded/rejected

Review nhánh bằng agy (2026-10-04): 0 finding — không có gì gộp/từ chối. Chi tiết + review Claude trước đó
(S2-R1..R3) ở §17 của `specs/2026-10-03-zether-design.md`. Suite cuối: `forge test` 270/270 (zether 138/138).
