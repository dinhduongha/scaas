# S3 — Zether prover Rust/WASM: kế hoạch

**Nhánh:** `r3-zether-prover` · **Sở hữu:** `zether-prover/**` · **Thiết kế:** round 3 §C.4 (R33), §F (R34);
giao thức byte-exact do S2 viết ở `2026-10-03-zether-design.md` (nhánh `r3-zether-contracts`).
**UNAUDITED — NOT FOR PRODUCTION FUNDS.**

**Mục tiêu:** crate Rust `zether-prover/` (arkworks 0.5, bn254 + BLS12-381 G1) cung cấp: khoá conf từ seed (R33),
ElGamal lifted + BSGS (cận 2^40), PoP, Σ-protocol + hai Bulletproof (n_v=32, n_b=64) cho fund/transfer/burn,
phong bì meta-tx, verifier gương bản địa, CLI, vector JSON cho S2, bản WASM + smoke test Node.

## Task

1. **Khung crate + đường cong + ElGamal + R33.** `curve.rs` (trait `ZCurve` trên `SWCurveConfig`, mã hoá
   EIP-196/EIP-2537, giải mã chặt: canonical, on-curve, subgroup), `elgamal.rs` (mã hoá, cộng/trừ đồng hình,
   trừ phí công khai, BSGS 2^20×2^20, lỗi `DecryptBound`), `keys.rs` (EIP-2333 đúng, bn254 salt riêng, đường
   `m/<root>/<coin>/<account>/<use>`, BIP-39 24 từ). Test: vector EIP-2333 công bố, round-trip, cận 2^40.
2. **R33 test liên đường + vector bn254 ghim + PoP** (theo §PoP của S2). Độc lập giữa đường/đường cong/coin/account;
   `x` ≠ scalar secp256k1 BIP-32 `m/44'/60'/0'/0/0`, ≠ ed25519 SLIP-10, ≠ khoá ký/rút EIP-2334 cùng cây.
3. **Transcript + generator** đúng tài liệu S2; vector byte-for-byte.
4. **Bulletproofs** (range n=32, n=64, IPA) + test âm (ngoài dải, sửa phần tử, sai statement).
5. **Σ-protocol + statement fund/transfer/burn** + test âm (sai khoá, sai số dư, đổi người nhận, linkage V6/V7).
6. **Phong bì meta-tx** (payload/digest theo S2), **CLI**, **vector JSON** `zether-prover/vectors/*.json`.
7. **WASM** (`wasm32-unknown-unknown`, wasm-bindgen) + smoke test Node headless: dẫn khoá → chứng minh transfer →
   verify bằng hàm verify Rust biên dịch sang wasm.
8. Toàn bộ suite, review agy, sửa, báo cáo.
