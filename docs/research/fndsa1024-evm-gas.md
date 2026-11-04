> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Falcon-1024 on the EVM: verification gas, measured (2026-11-04)

The measurement behind [spec 2026-11-04-fndsa1024](../superpowers/specs/2026-11-04-fndsa1024.md) (owner 2026-11-04: after
ML-DSA-87, measure Falcon-1024 and write its spec for review; no production build). All figures are `UNAUDITED` research
code, forge, not a chain.

## Method

- **Code.** `smartcontracts/evm/runs/2026-11-04-fndsa1024-probe/Falcon1024.sol` is a copy of the built `Falcon512` library
  (`src/ua/FnDsa.sol`, as on branch `mldsa87` at `78a4a86e`) with the Falcon-1024 parameters of the round-3 specification
  v1.2 (Table 3.3) and the reference code (`common.c` `l2bound[10]`): n 1,024, q 12,289, pk `0x0A ‖ h` (1,793 B), padded
  signature `0x3A ‖ salt (40) ‖ compressed s2 (1,239 B)` zero-padded to 1,280 B (`falcon.h` `FALCON_SIG_PADDED_SIZE(10)`),
  accept iff `‖s1‖² + ‖s2‖² ≤ 70,265,242`, and a zeta table `1945^brv10(k) mod q` (1945 = 11^6, a primitive 2,048-th root of
  unity). Everything else is the built code: the same SHAKE256 hash-to-point (16-bit draws, keep `< 5q`), `PqNtt`, the
  reference `comp_decode` (`|v| ≤ 2047`, no "−0", zero tail) and the norm loop. One addition, `verifyNtt`: the same check on
  `ĥ = NTT(h)` (1,024 × u16), the key form a cache would store. `Fndsa1024Probe` mirrors `UAFndsaVerifier`'s
  `verify(keyData, bytes32 ua_msg, sig)`.
- **Vectors.** The NIST round-3 Falcon submission package, `Falcon-Round3.zip` from
  `https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Falcon-Round3.zip`
  (SHA-256 `fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44`), member `KAT/falcon1024-KAT.rsp`
  (SHA-256 `036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d`; 100 rows). `extract.py` (run with
  `python3 -I`, both SHA-256 checked before parsing, the zip read with `zipfile` without extracting) rebuilds each NIST
  `sm` (`u16 len ‖ nonce ‖ msg ‖ 0x2A ‖ compressed`) as a padded signature and keeps the first 10 rows (count 0–9,
  messages 33–330 B) in `kat1024.json`, as `pq_external.json` keeps 10 Falcon-512 rows. The compressed s2 of the 100 rows
  is 1,224–1,240 B: **row 82 (1,240 B) has no 1,280-byte padded form** (a padded signer retries; the NIST KAT signer did
  not pad). `noble1024.mjs` re-checks the 10 rows with `@noble/post-quantum` 0.7.1 in both forms (the original NIST `sm`
  through `falcon1024.attached.open`, the padded rebuild through `falcon1024padded.verify`: all agree) and makes one
  UA-shaped row `ua1024.json`: a key from the SEP-0005 test mnemonic by `clientkeys`' PQ derivation (HKDF, 48-byte seed)
  under the proposed tag `scaas.ua.fndsa1024.v1`, Falcon over the 32-byte `ua_msg` as `fndsa512` signs, the fixed signing
  randomness of `pq-vectors.mjs`, and six mutations (header, salt, middle, padding, pk, message), all refused by noble.
- **Gas.** `Fndsa1024Probe.t.sol` with the probe's own `foundry.toml` (extends the project's, adds read access to the probe
  directory): Foundry 1.8.5, solc 0.8.37, Amsterdam, `isolate = true`. Verify gas is the `staticcall`'s gas, as
  `test/ua/PqGas.t.sol` measures `fndsa512`; the least working gas is a binary search on the call's gas (± 1,000). The built
  `UAFndsaVerifier` runs in the same test on the `fndsa512` row of `pq_kat.json` for comparison.

Reproduce: `cd smartcontracts/evm && FOUNDRY_SPARSE_MODE=true FOUNDRY_CONFIG=runs/2026-11-04-fndsa1024-probe/foundry.toml
scripts/capped forge test -vv` (the `capped` path from the repo root). Evidence lines: `runs/2026-11-04-fndsa1024-probe/summary.txt`.

## Results

Every kept KAT verifies on both key forms; in every KAT case a set padding bit, the NIST header `0x2A`, the Falcon-512 header
`0x39`, a 1,281-byte signature, a pk header `0x09` and a flipped message are refused; the UA row verifies on both forms and its
six mutations are refused; the decoder accepts `|s2_0| = 2047` and refuses 2048 over 1,024 coefficients.

| Path (valid UA row, message 32 B) | `fndsa512` (built, same run) | **`fndsa1024`** |
|---|---|---|
| verify on the round-3 key | 2,266,899 | **4,728,382** |
| least working gas, round-3 key (± 1,000) | — | **4,725,205** |
| verify on the NTT key `ĥ` (calldata) | — | **3,967,725** |
| least working gas, NTT key (± 1,000) | — | **3,964,333** |
| deployed cap without a precompile | 2,500,000 (P6c) | — (proposal 5,250,000, spec §4) |
| 66 % of 12,000,000 / of 10,500,000 | 7,920,000 / 6,930,000 | **passes both** (39 % / 45 % of the budget) |

**The message length matters a little.** The hash-to-point absorbs `salt ‖ msg` (one Keccak permutation, ~70 k gas, per 136 B)
and squeezes about 17 blocks for 1,024 coefficients; the decoder's work follows the coefficients. Over the 10 KATs
(messages 33–330 B) the round-3 key costs 4,787,553–4,932,967 and the NTT key 4,026,918–4,172,332, at most 4.3 % above the UA
row. The UA kind always hashes a 40-byte salt and the 32-byte `ua_msg`.

**Ratio to Falcon-512.** 2.09 × the built `fndsa512` (4.73 M / 2.27 M): the NTTs grow as n log n (1,024 · 10 against 512 · 9,
2.2 ×), the hash-to-point and the decoder as n.

**Cached form.** A key in the NTT domain removes one of the three NTTs: −0.76 M (−16 %). Stored once per key per chain as an
SSTORE2 blob of 2,048 B: 150,424 regular + 3,318,570 EIP-8037 state gas (measured, the write alone). The round-3 key already
passes the 66 % rule, so the cache is not needed for the kind to be enabled (spec, open point Q4). FIPS 206's provisional public
key encoding is the NTT form (below), so a FIPS 206 kind would read `ĥ` directly.

**One table for both sizes.** The first 512 entries of the Falcon-1024 zeta table are exactly `FnDsa.sol`'s Falcon-512 table
(`brv10(k) = 2 · brv9(k)` for `k < 512`, and `1945² = 10302`; checked byte for byte): a built verifier keeps one 2,048-byte
constant for both sizes.

## What it means against the budget

- `UA_VERIFY_BUDGET` 12,000,000 (EIP-7825 chains) / 10,500,000 (Hedera); a PQ kind is enabled on a chain only if its measured
  cap is **≤ 66 %** of the budget: 7,920,000 / 6,930,000 (CTR-UA-23).
- **Round-3 key:** 4.73 M on the UA row, 4.93 M at the largest KAT: **passes on both budgets without a precompile**, with
  2.99 M / 2.00 M of headroom to the bound. A cap of 5,250,000 (the KAT maximum + 6.4 %, the margin `fndsa512`'s 2.5 M cap
  has over its 2.35 M) would be 43.75 % / 50 % of the budget; T-GAS at build measures the worst case and sets it.
- **Without a precompile, pure Solidity is the path**, as for `fndsa512`. No EIP defines a Falcon-1024 precompile (below).
- **An `msig`** of `fndsa1024` members holds two signatures on a 12 M budget (bound 10,669,484 at the 5.25 M cap) and one on
  Hedera (5,374,484); spec §6.

## Standards status (read 2026-11-04)

- **EIP-8052** (<https://eips.ethereum.org/EIPS/eip-8052>, "Precompile for Falcon support", **Draft**, created 2025-10-17,
  requires EIP-7932; last change in `ethereum/EIPs` 2026-02-17, `87b06609`): Falcon-512 only ("Falcon-512 is chosen"); three
  precompiles `FALCON_HASH_TO_POINT_SHAKE256`, `FALCON_HASH_TO_POINT_KECCAKPRNG`, `FALCON_CORE`, addresses "TBD by ACD"; 666-byte
  padded signature, 896-byte key, 32-byte message; assets `kat_FALCONCORE_512.rsp`, `kat_HASHTOPOINT_512.rsp`,
  `kat_ethfalcon512.rsp` (no 1024 file). **No Falcon-1024 address and no 1024 encoding exist to probe.** EIP-7885 (Draft, an
  NTT precompile) quotes Falcon-1024 gas estimates but defines no Falcon verify.
- **FIPS 206 (FN-DSA): no draft is published.** The NIST CSRC FIPS list (<https://csrc.nist.gov/publications/fips>, read
  2026-11-04) shows FIPS 203, 204 and 205 (final, 2024-08-13) and no FIPS 206, final or draft; NIST's "drafts open for comment"
  (<https://csrc.nist.gov/publications/drafts-open-for-comment>) lists no FIPS. NIST's last public statement found is Ray Perlner,
  "FIPS 206 Status Update", Sixth PQC Standardization Conference, 2025-09-25
  (<https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon>): "We expect to release an Initial Public Draft soon … It's
  basically written, awaiting approval". The slides mark as **provisional** changes that touch a verifier or its encodings:
  the public key in **NTT form** `ĥ`; **little-endian** encodings; separate **pure / pre-hash** versions and the **BUFF
  transform** (the message hash binds the public key); **only randomized** signing; verification restricts the **infinity norm**
  of the signature as well as the L2 norm; pseudorandom seeds uniformly 40 bytes. Each one makes a FIPS 206 signature fail
  under a round-3 verifier or the reverse, so a FIPS 206 Falcon-1024 is a new kind version, as accounts.md already rules for
  `fndsa512`.
- **Other chains.** Algorand's `falcon_verify` (AVM v12+) verifies a *deterministic* Falcon-1024 only (fixed salt, header MSB
  set) and refuses a randomized round-3 signature, so it cannot verify this kind
  ([pq-signatures-per-family.md](pq-signatures-per-family.md)). Third-party claims (BNB Chain BEP-575 proposing Falcon-512 with
  "optional Falcon-1024") are proposals, not deployments.

## Not measured here

Timing of a native verify (no calibration run: the owner's rule), a precompile path (none exists), the worst case over
adversarial inputs (T-GAS at build: hash-to-point squeezes, the longest decodable s2), the registry's own `register` and
`requireAuthorized` at the new kind (not built; the spec estimates them from `fndsa512`'s measured rows), and any family other
than EVM.
