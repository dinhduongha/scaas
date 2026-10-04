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

## Trạng thái task 8 (2026-10-04)

Suite cuối trên `e5781c7`: `cargo test --release` 40/40 (8 binary), `cargo clippy --release --all-targets -D warnings`
sạch (commit `e5781c7` thêm 2 `allow` lint), `./wasm-smoke.sh` 16/16 check (proveTransfer wasm: bn254 196 ms,
BLS12-381 482 ms).

## Review agy — folded/rejected

**Chưa có review ngoài của diff nhánh.** agy hết quota (`RESOURCE_EXHAUSTED`, "Resets in 120h9m" tính từ
2026-10-04); grok bị bộ phân loại quyền chặn trong phiên này. Prompt sẵn sàng chạy lại:
`scratchpad/s3-review-prompt.md` (phiên a9570aaa). Thay thế tạm: Claude soát tay phần nhạy cảm — nonce hedged
(`nonce.rs`: SHA-512 của tag ‖ len ‖ witness ‖ statement ‖ CSPRNG, mỗi proof một seed), EIP-2333 (`HKDF_mod_r`
đúng v4: băm salt đầu vòng, `L = 48`, lamport 255 chunk, 4 vector công bố qua), codec điểm (độ dài, on-curve,
subgroup, chỉ toàn-0 = vô cực), scalar chặt `< r`, BSGS (va chạm khoá 64 bit chỉ gây "not found", có kiểm bằng),
biên JSON/wasm (lỗi trả `Err`, không panic; u32 đã chặn ở `3ce225f`). **0 finding.** Rủi ro mở: chưa có review
ngoài — chạy lại agy khi quota hồi.

## Review opus (external substitute) — folded/rejected (2026-10-04)

Review: `scratchpad/s3-opus-review.md` (Claude Opus, đọc diff `71f3ffb..b86f990`, không chạy code). 0 critical,
0 high, 1 medium, 4 low. Mỗi finding được kiểm lại bằng test đỏ trước khi sửa.

- **M1 folded** `cf46bed` — passphrase BIP-39 không NFKD. Ghi chú: review nói feature `std` thiếu
  `unicode-normalization`; thực tế `std → alloc → unicode-normalization` đã bật, lỗi nằm ở việc gọi
  `parse_normalized`/`to_seed_normalized`. Sửa: `parse` + `to_seed`, feature ghi rõ. Vector: 24 từ
  `abandon…art` + `"mật khẩu"` (NFC và NFD) = seed của @scure/bip39 và Python `pbkdf2_hmac` trên NFKD.
- **L1 folded** `cf46bed` — `passphrase` không phải string → lỗi (null/thiếu → `""`).
- **L2 folded** `1bb9e9f` — bảng BSGS: mảng `(key, j)` sắp xếp, 2^20 × 16 B = 16 MiB (test khẳng định đúng cỡ),
  dựng theo khối 4096 điểm, cache theo đường cong (`ZCurve::bsgs`, `OnceLock`); va chạm khoá thử hết. Cận 2^40 giữ nguyên.
- **L3 folded** `fa13d47` — nonce mở Chaum-Pedersen hedge thêm chainId, token, amount, kind (= tiền ảnh challenge
  trừ A1/A2). Test RNG chết + receiver = auditor: trước sửa A1 trùng (đỏ), sau sửa khác. Vector disclosure tái sinh
  (chỉ opening đổi; harness forge S2 không đọc file disclosure).
- **L4 folded** `9d9e075` — zeroize: `ZetherKey` (Zeroize thay dead store), seed BIP-39/seed hex (`Zeroizing`),
  SK trung gian `derive_path`, `TransferWitness`/`BurnWitness` (Drop), buffer đầu vào nonce. Giới hạn: `Fr` là
  `Copy`, bản sao trên stack không xoá được (ghi `ponytail:` ở `zether.rs`).
- **Chỉ số đường dẫn JS (L4 của S4)** sửa ở nhánh S4 (`clientkeys/src/zether.js`), cùng luật với `api.rs num32`.

Suite sau sửa (`9d9e075`): `cargo test --release` 41/41, `cargo clippy --release --all-targets -D warnings` sạch,
`./wasm-smoke.sh` 16/16 (proveTransfer wasm: bn254 198 ms, BLS12-381 487 ms).
