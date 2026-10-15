# pqz-core/stmt — `pqz-stmt`, the one PQZ statement codec

`no_std` + `alloc` Rust, no dependencies, no `unsafe`, no floats (P6e plan R2, D15, R6). It parses and builds every
statement form of both proof systems (PQZL and PQZH read the same statement bytes; the `proofSystemId` word picks
the verifier), the `pk` / ciphertext objects, the disclosure bundle and opening, and the precompile input
`u8(op) ‖ be32(len) ‖ stmt ‖ proof`. Every decoder accepts exactly one encoding, and `encode(parse(x)) == x` for every
accepted input. Spec: `docs/contracts/pq-zether.md` §5, §7.2, §7.7, §7.9, §9.1; the independent Python codec is
`smartcontracts/vectors/pqz/pqz_kat.py` (same rules, same rejection reasons).

| op | form | statement bytes | decoder |
|---|---|---|---|
| 1 | `R_TX` / `R_TX0` (by length, `auditorOn` must match) | 83,072 / 66,560 | `parse`, `decode_input` |
| 2 | `R_BURN` (BURN, REFRESH by opTag) | 50,048 | `parse`, `decode_input` |
| 3 | `R_REG` | 16,480 | `parse`, `decode_input` |
| 4, 5 | `R_DS`, `R_DR` (RECEIVER, AUDITOR by opTag) | 33,184 | `parse`, `decode_input` |
| 6 | SELFTEST (empty) | 0 | `parse`, `decode_input` |
| 7 | `R_TXM`, M legs (P6-ANON) | `50,048 + 16,640·M + 16,384·G` (auditor on) / `33,664 + 16,512·M + 16,384·G` (off), `G = ⌈M/4⌉` | `parse_multi` |

## Op 7 — the multi-recipient transfer `R_TXM` (P6-ANON plan §4, D6; task S2)

- `opTag = keccak256("SCAAS-PQZ-OP-TRANSFER-MULTI-V1")` = `6f6a773a…26b90`; the §7.7 header with word 192 =
  `recipientsHash = keccak256(word(UA_0) ‖ … ‖ word(UA_{M−1}))` (32-byte UA words in leg order), word 320 = `M`,
  `amount` = 0; `G = ⌈M/4⌉` with or without the auditor (80 hints, β 446, owner-accepted CTR-PQZ-03 exception); body `pk_f ‖ pk_0…pk_{M−1} ‖ [pk_a]
  ‖ T ‖ u_0…u_{G−1} ‖ v_0…v_{M−1} ‖ v_f ‖ [v_{a,0}…v_{a,M−1}]`. At M = 1 the body is op 1's byte for byte.
- **Built leg counts per id**, either auditor mode (`built_legs`, owner ruling D20): PQZL {1, 2, 4, 8}, PQZH {1, 2,
  4}. The decoder enforces them per id (it already knows the id), so no unbuilt shape reaches either verifier;
  feature `oversize` (bench only) adds M = 8, 16 for both ids, and pqz-ffi refuses to compile with it
  (`pqz_stmt::OVERSIZE`). `fee` may be 0 (owner 2026-10-14). PQZH `(4, on)`: 5 + 132,992 + `MAX_PROOF` > `MAX_INPUT`
  by 1,925 B (honest proofs fit; H2 measures the exact bound).
- **Rule order** (`parse_multi`, the same in `pqz_kat.py`): opTag; id; header present (`< 640` B ⇒ `Length`);
  `auditorOn` ∈ {0, 1} (`AuditorOn`); the `M` word in the id's built set (`Reject::Legs`); length =
  `multi_len(M, auditorOn)` (`Length`); `fee`,
  `amount` < 2^64; salt word = 16 zero bytes ‖ salt; `amount` = 0 (`MustBeZero("amount")`); every coefficient < q.
  The words pick the shape, because the length alone does not: `(M = 1, auditor on)` and `(M = 2, off)` are both
  83,072 B (equal object counts). A wrong `M` or `auditorOn` word on a valid body therefore fails as `Length`.
  `Multi::encode` refuses a header whose `M` / `auditorOn` word disagrees with the objects (`Legs` / `AuditorOn`).
- `parse` and `decode_input` still refuse op 7 (`Reject::Op`): `Stmt` / `Form` are matched exhaustively in pqz-ffi and
  Ligero, which S3 / H1 extend together with the precompile dispatch. `MAX_INPUT` and `MAX_PROOF` are unchanged (D8).

## Tests and cross-check

`xcheck.sh <label>` (one job under `scripts/capped`) builds the C core, dumps its six statements, writes the
`pqz_kat.py` inputs (`xcheck.py`: random statements of every form, every built op 7 shape of both ids with fee 0 on
every other, and the D15 / R6 / op 7 mutations with `pqz_kat.py`'s reason), runs `cargo test` (release and debug),
the cross-check `tests/xcheck.rs` (same fields, same bytes, same rejection reason) and the wasm32 build; outputs in
`runs/<label>-*.txt`. `cargo test --features oversize` covers the bench-only shapes.
