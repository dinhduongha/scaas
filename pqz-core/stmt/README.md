# pqz-core/stmt — `pqz-stmt`, the one PQZ statement codec

`pqz-stmt` is the Rust library that reads and writes every byte layout PQZ puts on chain: the statements of every
operation, public keys and ciphertexts, disclosure bundles and openings, and the precompile input. Both proof systems
(PQZL and PQZH) read the same statement bytes, so this one codec serves both. The precompile library
[`pqz-ffi`](../ffi/README.md) uses it to decode every input before any verifier runs; wallets use it to build
statements. For the terms (statement, op, form, `proofSystemId`) see the glossary in the
[pqz-core README](../README.md).

**Properties** (P6e plan R2, D15, R6): `no_std` + `alloc` Rust, no dependencies, no `unsafe`, no floating point;
it builds for wasm32.

**Canonical encoding.** Every decoder accepts exactly one encoding of each value, and `encode(parse(x)) == x` for every
accepted input. So the same transfer can never be submitted in two different byte forms.

**Specification and second implementation.** The byte layouts are in `docs/contracts/pq-zero-knowledge.md` §5, §7.2,
§7.7, §7.9 and §9.1. An independent Python codec, `smartcontracts/vectors/pqz/pqz_kat.py`, applies the same rules and
gives the same rejection reasons; the tests below compare the two.

## Statement forms

The precompile input is `u8(op) ‖ be32(len) ‖ stmt ‖ proof`: one op byte, the statement length as a 4-byte big-endian
number, the statement, then the proof. The op byte selects the form:

| op | form | statement bytes | decoder |
|---|---|---|---|
| 1 | `R_TX` / `R_TX0` (chosen by the length; the `auditorOn` word must match) | 83,072 / 66,560 | `parse`, `decode_input` |
| 2 | `R_BURN` (BURN or REFRESH, chosen by the opTag) | 50,048 | `parse`, `decode_input` |
| 3 | `R_REG` | 16,480 | `parse`, `decode_input` |
| 4, 5 | `R_DS`, `R_DR` (RECEIVER or AUDITOR, chosen by the opTag) | 33,184 | `parse`, `decode_input` |
| 6 | SELFTEST (empty statement) | 0 | `parse`, `decode_input` |
| 7 | `R_TXM`, M legs (P6-ANON) | `50,048 + 16,640·M + 16,384·G` (auditor on) / `33,664 + 16,512·M + 16,384·G` (auditor off), where `G = ⌈M/4⌉` | `parse_multi`; `parse` and `decode_input` hand op 7 to it |

## Op 7 — the multi-recipient transfer `R_TXM` (P6-ANON plan §4, D6; task S2)

The multi-recipient transfer (`R_TXM`, op 7) is one transfer with one proof and M legs (recipients); some legs can be
decoys that receive an encryption of 0. It has its own decoder, `parse_multi`, and builder, `Multi::encode`.

**Layout.**

- `opTag = keccak256("SCAAS-PQZ-OP-TRANSFER-MULTI-V1")` = `6f6a773a…26b90`.
- The header is the §7.7 header, with three words set for op 7:
  - word 192 = `recipientsHash = keccak256(word(UA_0) ‖ … ‖ word(UA_{M−1}))`: the recipients' accounts as 32-byte
    words, in leg order;
  - word 320 = `M`;
  - `amount` = 0.
- Legs are encrypted in groups of up to 4 that share one random value: `G = ⌈M/4⌉` groups, with or without the auditor
  (80 hints, β 446; an owner-accepted exception to CTR-PQZ-03).
- The body is `pk_f ‖ pk_0…pk_{M−1} ‖ [pk_a] ‖ T ‖ u_0…u_{G−1} ‖ v_0…v_{M−1} ‖ v_f ‖ [v_{a,0}…v_{a,M−1}]`; the parts in
  brackets are present only with the auditor. At M = 1 the body is byte for byte the body of op 1.

**Built leg counts.** Each proof system supports only some values of M, in both auditor modes (`built_legs`, owner
ruling D20): PQZL {1, 2, 4, 8}, PQZH {1, 2, 4}.

- The decoder enforces these per `proofSystemId` (it has already read the id), so no unbuilt shape reaches either
  verifier.
- The feature `oversize` (benchmarks only) adds M = 8 and 16 for both ids. `pqz-ffi` refuses to compile with it
  (`pqz_stmt::OVERSIZE`).
- `fee` may be 0 (owner 2026-10-14).
- PQZH with M = 4 and the auditor on: 5 + 132,992 + `MAX_PROOF` is larger than `MAX_INPUT` by 1,925 B. Honest proofs
  still fit: the H2 measurement found the exact largest proof, 236,196 B, so the largest input is 369,193 B (see
  [pqz-core README §4](../README.md#4-statement-forms-ids-limits)).

**Rule order.** `parse_multi` checks the rules in this order, the same order as `pqz_kat.py`, so both report the same
reason:

1. opTag;
2. `proofSystemId`;
3. the header is present (shorter than 640 B ⇒ `Length`);
4. `auditorOn` ∈ {0, 1} (`AuditorOn`);
5. the `M` word is in the id's built set (`Reject::Legs`);
6. the length equals `multi_len(M, auditorOn)` (`Length`);
7. `fee` and `amount` < 2^64;
8. the salt word = 16 zero bytes ‖ salt;
9. `amount` = 0 (`MustBeZero("amount")`);
10. every coefficient < q.

The header words, not the length, pick the shape, because the length alone is ambiguous: (M = 1, auditor on) and
(M = 2, auditor off) are both 83,072 B (they have the same number of objects). A wrong `M` or `auditorOn` word on an
otherwise valid body therefore fails as `Length`. In the other direction, `Multi::encode` refuses a header whose `M` or
`auditorOn` word disagrees with the objects it is given (`Legs` / `AuditorOn`).

**Through `parse` and `decode_input`.** Since P6-ANON S3, `parse(7, …)` and `decode_input` call `parse_multi` and
return the result as `Stmt::Multi`, which is how `pqz-ffi` and Ligero receive op 7. `Stmt::Multi` has no `Form` (op 7
has one length per (M, auditorOn), not one per op), so `Stmt::form()` returns `None` for it. `MAX_INPUT` and
`MAX_PROOF` did not change for op 7 (D8).

## Tests and cross-check

One command runs everything, from the repository root:

```sh
scripts/capped pqz-core/stmt/xcheck.sh <label>     # outputs in pqz-core/stmt/runs/<label>-*.txt
```

`xcheck.sh` runs as one job under `scripts/capped`, the repository's machine lock. It:

1. builds the C core and dumps its six statements;
2. writes the inputs for `pqz_kat.py` (`xcheck.py`): random statements of every form; every built multi-recipient
   shape of both ids, with fee 0 on every other one; and the mutations for the D15 / R6 rules and the multi-recipient
   rules, each with the reason `pqz_kat.py` gives;
3. runs `cargo test` (release and debug) and `cargo test --features oversize`, which covers the benchmark-only
   shapes;
4. runs the cross-check `tests/xcheck.rs`: Rust, C and Python must agree on the same fields, the same bytes and the
   same rejection reason;
5. builds for wasm32.
