# Zether: one transfer to many recipients, three disclosure modes

**Status:** ACCEPTED by the owner 2026-10-08 and folded into the component docs; frozen here as the design record. Ids: Z1/Z2/Z3/Z7/Z8 → CTR-ZTH-37, Z4 → CTR-ZTH-38, Z9 → CTR-ZTH-39, Z10 → CTR-ZTH-40, Z11 → CTR-ZTH-41, Z12 → CTR-ZTH-42, Z13 → CTR-ZTH-43; Z5/Z6 need no rule (spike merged; CTR-ZTH-30 unchanged).
**Date:** 2026-10-08. **Scope:** classical Zether on EVM (`ZetherToken`, `ZetherDisclosure`, `ZetherVerifier` bn254 + BLS12-381,
`clients/zether-prover`). PQZ: notes only (§6). Builds on [contracts/zether.md](../../contracts/zether.md); the
statement header stays the BUILT 384-byte layout (the `chainUid` word is stream MT-6).

## 1. Why

A `transferConfidential` has one recipient (`zether.md` payload, `ZetherToken.sol:341`); the research said several
recipients in one proof were impossible "in original Zether" (`research/05-open-relayer-network.md:931`) — it missed
that the relation extends directly. The owner wants one transfer to many recipients so that a sender can add
**randomly chosen decoy recipients** receiving 0 and hide the real one (no ring anonymity of the sender is wanted), and
three disclosure-storage modes instead of one.

## 2. Owner decisions (2026-10-08)

| # | Decision |
|---|---|
| Z1 | One transfer, `M ≥ 1` recipients, one proof; decoys receive an encryption of 0 |
| Z2 | Sender anonymity (ring) is not wanted; the sender stays public |
| Z3 | **One shared `s`** for every recipient: handing `s` to a checker opens every leg of that transfer, decoys included — accepted |
| Z4 | Three functions by disclosure storage: **hash only (default)**, full bundle, no bundle |
| Z5 | The measuring spike is real code and is merged |
| Z7 | The multi-recipient transfer **is** `transferConfidential` (default, HASH) |
| Z8 | The single-recipient format is **kept, renamed `transferConfidentialSingle`** — same payload, statement, proof, proof system id and full-bundle storage as today; only the name changes |
| Z6 | `s` of one transfer opens only that transfer (HKDF over `sendCounter`, [CTR-ZTH-30](../../contracts/zether.md#CTR-ZTH-30)); the sender rebuilds `s` from its seed and reads the bundle from calldata when nothing is stored |
| Z9 | **`attestTransferAmount` and `AmountAttested` are removed.** `verifyTransferAmount` (view, callable by any contract, third-party ones included) and `transferCiphertext` stay |
| Z10 | New opening **`SENDER_CP`**: the sender proves leg `j` with a Chaum-Pedersen proof instead of handing over `s`, so only `v_j` opens (§5.1). The disclosure challenge binds the leg index `j` for every kind |
| Z11 | The auditor key **should be a k-of-n threshold key** (e.g. company, audit firm, regulator): `Y_a` stays one public key, `x_a` is split off chain by a DKG; decrypting or an `AUDITOR` opening needs k parties. No contract change; prover/CLI protocol follows with [CTR-ZTH-29](../../contracts/zether.md#CTR-ZTH-29) |
| Z12 | **The sender may leave the auditor out of a transfer** on a token whose auditor is on (both formats): every `C_aud_j = O`; the token then builds the statement with `Y_a = O`. Owner-accepted consequence: on such a transfer the auditor reads nothing, and the opt-out is publicly visible (`C_aud = O`) |
| Z13 | **Disclosure lives in a separate stateless `ZetherDisclosure`** (no state, no admin, no upgrade; one instance for every Zether token on every curve); the token exposes the raw entry (`transferEntry`) and `disclosure()` |

## 3. Relation and proof

Witness: `x, s, v_1..v_M, b' = b − Σv_j − fee, γ_vj, γ_b`. Ciphertexts (shared `s`, shared `D_out = [s]G`):

```text
C_out_j = [v_j]G + [s]Y_tj        C_aud_j = [v_j]G + [s]Y_a  (O when the auditor is off)
C_deb   = [V]G + [s]Y_f   with V = Σ v_j            V_vj = [v_j]G + [γ_vj]Hb      V_b = [b']G + [γ_b]Hb
```

Σ commitments (hedged nonces as today): `A_y = [k_x]G`, `A_D = [k_s]G`, `A_deb = [Σk_vj]G + [k_s]Y_f`,
`A_bal = [k_b]G + [k_x](D_acc − D_out)`, `A_Vb = [k_b]G + [k_gb]Hb`; per `j`: `A_out_j = [k_vj]G + [k_s]Y_tj`,
`A_aud_j = [k_vj]G + [k_s]Y_a`, `A_Vvj = [k_vj]G + [k_gvj]Hb`. Responses `z_x, z_s, z_b, z_gb`, per `j`: `z_vj, z_gvj`.
Transcript: `T.absorb("statement", statement)`; `T.absorb("sigma.commit", V_b ‖ A_y ‖ A_D ‖ A_deb ‖ A_bal ‖ A_Vb ‖
(V_vj ‖ A_out_j ‖ A_aud_j ‖ A_Vvj)_{j=1..M})`; `c = T.challenge("sigma.c")`; then the range proofs in the order
`v_1 … v_M, b'` with the existing per-proof transcript use.

```text
E1    [z_x]G − [c]Y_f − A_y
E2    [z_s]G − [c]D_out − A_D
E3_j  [z_vj]G + [z_s]Y_tj − [c]C_out_j − A_out_j
E4    [Σ z_vj]G + [z_s]Y_f − [c]C_deb − A_deb
E5    [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal
E6_j  [z_vj]G + [z_s]Y_a − [c]C_aud_j − A_aud_j            (auditor on for this transfer; off ⇒ every C_aud_j, A_aud_j = O)
E7_j  [z_vj]G + [z_gvj]Hb − [c]V_vj − A_Vvj
E8    [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
```

Range proofs: one Bulletproof per `v_j` and one for `b'`, all `n = 64`, the existing single-value proof (no
aggregation in this spike). Soundness as [CTR-ZTH-18](../../contracts/zether.md#CTR-ZTH-18): the only sum of proven
values is `a = b' + Σv_j + fee < (M + 2)·2^64 ≪ r`, so `Σv_j + fee ≤ a` as integers.

## 4. Encoding

```text
payload   = be32(provedAccSeq) ‖ be32(provedSendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_{j=1..M}
statement = header(opTag) ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_{j=1..M}
opTag     = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/" ‖ mode)     mode ∈ {"HASH", "BUNDLE", "NONE"}
proof     = sigma commitments ‖ sigma responses ‖ BP(v_1) … BP(v_M) ‖ BP(b')
```

The mode is in `opTag`, so a relayer cannot switch the mode of a signed proof. `1 ≤ M ≤ MAX_RECIPIENTS = 16`
(`BadRecipientCount`); recipients pairwise distinct, none equal to the sender, all registered (`DuplicateRecipient`,
`SelfTransfer`, `NotRegistered`). The multi-recipient format has its own proof system id, so a single-recipient proof never matches it.

## 5. Token

```solidity
function transferConfidential(bytes calldata payload, bytes calldata proof, bytes calldata authSig, UA beneficiary)
    external returns (bytes32 entryRef);                 // mode HASH (default)
function transferConfidentialBundle(…) external returns (bytes32);       // mode BUNDLE
function transferConfidentialNoBundle(…) external returns (bytes32);     // mode NONE
```

Checks and order as `transferConfidentialSingle` (cheap first, `accSeq`/`sendCounter`, registry `requireAuthorized` over the
statement digest, verify). Effects: `acc_f −= (C_deb + [fee]G, D_out)`; per `j` `pending_tj += (C_out_j, D_out)`,
`pendingSeq_tj++`; fee to the beneficiary as today; `sendCounter_f++` once. `entryRef` as today (one per transfer);
recipient `j` is addressed as `(entryRef, j)`. Bundle `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`:

| Mode | Stored | Event | Disclosure |
|---|---|---|---|
| HASH | `keccak256(B_1 ‖ … ‖ B_M)` (one slot) | `ConfidentialTransferMulti(from, recipients, beneficiary, fee, sendCounter, entryRef, mode)` + the bundles in a `TransferBundles(entryRef, bundles)` event | on chain: the caller supplies all bundles, `ZetherDisclosure` checks the hash, then the opening checks on `B_j` |
| BUNDLE | `B_1 ‖ … ‖ B_M` | the summary event | on chain, nothing supplied |
| NONE | nothing | the summary event | off chain only (calldata) |

**Disclosure contract (Z13).** Disclosure is not in the token: `ZetherDisclosure` (stateless, no admin, no upgrade, one
instance for every token and curve) reads `transferEntry(entryRef)`, `verifier()` and `auditorKey()` from the token.
`transferEntry` returns the raw record: `B_1 ‖ … ‖ B_M` (single format, BUNDLE), the 32-byte hash (HASH), empty (NONE,
unknown ref). `disclosure()` is an immutable of the token implementation (set in its constructor, shared by every
clone), so a third party finds the canonical contract from the token:
`token.disclosure().verifyTransferAmount(token, entryRef, j, amount, kind, opening, bundles)` serves both formats (a
single entry has `j = 0`; `bundles` ignored when the record is stored, checked against the hash in HASH mode,
`UnknownEntry` in NONE mode). `transferCiphertext(token, entryRef, j, bundles)` exports the raw leg for an independent
verifier. No attestation (Z9): a contract that needs an on-chain trace records the result itself. The caller picks the
token it trusts (a fake "token" can answer anything); the challenge binds the token address, not the disclosure
contract's.
Relaying through the meta-tx envelope follows stream MT-6 (direct calls only here).

**Auditor per transfer (Z12).** Token auditor off: every `C_aud_j` must be `O` (as today). Token auditor on: either
every `C_aud_j ≠ O` (statement `Y_a` = the token key) or every `C_aud_j = O` (statement `Y_a = O`, E6 skipped); a mix
reverts (`AuditorLegsMixed`). `Y_a` is in the statement and the transcript, so a proof made for one choice never
verifies under the other. The single format follows the same rule with its one `C_aud`.

### 5.1 Openings

| Kind | Who | Secret | Opening | Checks (leg `j`, `M_j = C_out_j − [v]G`) | Opens |
|---|---|---|---|---|---|
| `SENDER_S` (0) | sender | `s` | `s` (32 B) | `[s]G == D_out`, `M_j == [s]Y_tj` | every leg of the transfer |
| `RECEIVER_X` (1) | recipient `j` | `x_tj` | `(A1, A2, z)` | DLEQ `log_G Y_tj == log_{D_out} M_j` | leg `j` |
| `AUDITOR` (2) | auditor | `x_a` | `(A1, A2, z)` | DLEQ `log_G Y_a == log_{D_out}(C_aud_j − [v]G)`; false when `C_aud_j = O` | leg `j` |
| `SENDER_CP` (3) | sender | `s` | `(A1, A2, z)` | DLEQ `log_G D_out == log_{Y_tj} M_j` | leg `j` |

DLEQ `log_G K == log_B N` (`ZetherDisclosure._chaumPedersen`): `[z]G − A1 − [e]K == O` and `[z]B − A2 − [e]N == O` over the pairs above.
Challenge `e = H(DISCLOSE_TAG ‖ chainid ‖ token ‖ entryRef ‖ j ‖ amount ‖ kind ‖ A1 ‖ A2)` — `j` is new for every kind
(vectors change). Nonce `k` hedged (`H(secret ‖ statement ‖ rng)`): a repeated `k` over two openings reveals the secret.
The prover's `verify_opening` mirrors `ZetherDisclosure` (`open_sender_cp` builds `SENDER_CP`); off-chain checking needs no storage mode.

## 6. PQZ (note)

The PQZ encryption is already multi-recipient with shared randomness ([CTR-PQZ-04](../../contracts/pq-zether.md#CTR-PQZ-04)):
one `u` (16,384 B) for all recipients and one `v_j` (128 B, plus 128 B when the auditor is on) per recipient, so an
extra recipient adds little calldata at send time; the LNP22 proof growth with `M` is unknown until `pqz-core` exists.
The real per-recipient cost comes later: each credit — decoys included — enters the receiver's rollover as a full
`u ‖ v_j` ciphertext (≈ 16.5 KB, ≈ 0.52 M gas, [CTR-PQZ-11](../../contracts/pq-zether.md#CTR-PQZ-11)). Not measurable
now: no PQZ code exists (engine spikes E-S0… not started). Not in this spike.

## 7. Measurement (gate of the spike)

forge, real proofs from the prover, bn254 and BLS12-381: execution gas of `transferConfidential*` for
`M ∈ {1, 2, 4, 8}` × the three modes, next to `transferConfidentialSingle` (baseline: the measured table of `contracts/zether.md`); calldata bytes per case. Prover time per `M`.
Results go into the gas table of `contracts/zether.md` on fold.

**Measured 2026-10-08, rev 6** (Z9/Z10/Z12/Z13 in the code). `test/zether/ZetherMulti.t.sol` `test_gas*`, forge 1.3.5,
Prague, `gasleft()` around the call — execution gas without the 21,000 intrinsic and calldata, each cell from a fresh
state (every recipient and the beneficiary get their first credit), inner fee to a beneficiary, one real recipient
and `M − 1` decoys at 0, real proofs (test prover `ZetherProver.sol`). **on** = auditor on; **out** = the same
auditor-on token, the sender leaves the auditor out (Z12, every `C_aud = O`, statement `Y_a = O`). Calldata = the
ABI-encoded call in bytes (same for on and out).

| Curve | Entry | Aud. | M = 1 | M = 2 | M = 4 | M = 8 | Calldata (M = 1 / 2 / 4 / 8) |
|---|---|---|---|---|---|---|---|
| bn254 | `transferConfidentialSingle` | on | 3,287,303 | — | — | — | 3,876 |
| bn254 | `transferConfidentialSingle` | out | 3,218,528 | — | — | — | 3,876 |
| bn254 | HASH (default) | on | 3,146,110 | 4,652,247 | 7,675,864 | 13,769,380 | 3,908 / 5,604 / 8,996 / 15,780 |
| bn254 | HASH (default) | out | 3,117,996 | 4,596,256 | 7,563,572 | 13,542,293 | same |
| bn254 | BUNDLE | on | 3,297,417 | 4,978,914 | 8,353,251 | 15,147,864 | same |
| bn254 | BUNDLE | out | 3,229,503 | 4,843,323 | 8,081,759 | 14,602,377 | same |
| bn254 | NONE | on | 3,094,881 | 4,597,525 | 7,614,084 | 13,692,433 | same |
| bn254 | NONE | out | 3,066,767 | 4,541,534 | 7,501,792 | 13,465,346 | same |
| BLS12-381 | `transferConfidentialSingle` | on | 3,902,468 | — | — | — | 6,948 |
| BLS12-381 | `transferConfidentialSingle` | out | 3,779,228 | — | — | — | 6,948 |
| BLS12-381 | HASH (default) | on | 3,585,859 | 5,311,984 | 8,825,406 | 16,099,191 | 6,980 / 10,148 / 16,484 / 29,156 |
| BLS12-381 | HASH (default) | out | 3,543,316 | 5,226,325 | 8,650,604 | 15,734,441 | same |
| BLS12-381 | BUNDLE | on | 3,912,526 | 5,989,371 | 10,204,233 | **18,879,876** | same |
| BLS12-381 | BUNDLE | out | 3,790,383 | 5,744,512 | 9,711,031 | **17,878,326** | same |
| BLS12-381 | NONE | on | 3,532,486 | 5,252,950 | 8,754,906 | 16,003,409 | same |
| BLS12-381 | NONE | out | 3,489,943 | 5,167,291 | 8,580,104 | 15,638,659 | same |

- **Rev 6 vs rev 4 (auditor on):** multi cells +1.5 k (M = 1) to +9 k (M = 8) — the `C_aud` scan that picks `Y_a`
  (Z12), ≈ 1 k per leg; the slopes below are unchanged. Single is now measured by the same harness as the multi cells
  (rev 4 took it from `contracts/zether.md`).
- **Per extra recipient** (slope M = 1 → 8, auditor on): bn254 HASH ≈ 1.52 M, BUNDLE ≈ 1.69 M, NONE ≈ 1.51 M;
  BLS12-381 HASH ≈ 1.79 M, BUNDLE ≈ 2.14 M, NONE ≈ 1.78 M — against ≈ 3.29 M / 3.90 M for another separate transfer.
- **Leaving the auditor out (Z12)** saves E6 per leg (bn254 ≈ 28 k, BLS12-381 ≈ 43–46 k) and, where the bundle is
  stored, the zero `C_aud` words: Single −69 k / −123 k, BUNDLE M = 8 −545 k / −1.0 M (bn254 / BLS12-381).
- **EIP-7825 cap (16,777,216 per transaction, intrinsic + calldata included):** every bn254 cell fits; on BLS12-381
  M = 8 BUNDLE does not, auditor on or out; M = 8 HASH on ≈ 16.6 M and NONE on ≈ 16.5 M fit with ≈ 1–2 % headroom,
  out ≈ 16.2 M / 16.1 M.
- **Prover** (rev 4, unchanged code path; release `zether-cli proveTransferMulti`, one process per call; median of 3
  on the chain-7622 host, AMD Ryzen 5 7235HS): bn254 single 74 ms, M = 1/2/4/8 = 75 / 114 / 181 / 322 ms; BLS12-381
  single 162 ms, M = 1/2/4/8 = 159 / 231 / 361 / 660 ms.

**Disclosure** (`ZetherDisclosure.verifyTransferAmount`, `test_gasDisclose*`): an on-chain call from a contract
(`Escrow3P.measure`: `token.disclosure()`, then `gasleft()` around the call), every opening true, on the real leg
`j = M − 1`. Token, `ZetherDisclosure` and verifier cooled with `vm.cool` before each call (cold accounts and slots as
in a new transaction; the token account itself is warm, the caller just read `disclosure()`). HASH: the bundles are
passed in calldata — their size in the last column; their transaction calldata cost (≤ 16 gas/B) is not included.

| Curve | Entry | `SENDER_S` | `RECEIVER_X` | `AUDITOR` | `SENDER_CP` | Bundles in calldata |
|---|---|---|---|---|---|---|
| bn254 | Single (stored) | 74,935 | 97,975 | 106,783 | 98,024 | — |
| bn254 | BUNDLE M = 1 | 74,935 | 97,975 | 106,783 | 98,024 | — |
| bn254 | BUNDLE M = 8 | 196,953 | 220,014 | 228,826 | 220,063 | — |
| bn254 | HASH M = 1 | 60,248 | 83,287 | 92,094 | 83,336 | 256 B |
| bn254 | HASH M = 8 | 61,459 | 84,510 | 93,320 | 84,559 | 2,048 B |
| BLS12-381 | Single (stored) | 118,091 | 148,712 | 161,917 | 148,761 | — |
| BLS12-381 | BUNDLE M = 1 | 118,091 | 148,712 | 161,917 | 148,761 | — |
| BLS12-381 | BUNDLE M = 8 | 362,294 | 392,974 | 406,193 | 393,023 | — |
| BLS12-381 | HASH M = 1 | 86,150 | 116,767 | 129,971 | 116,816 | 512 B |
| BLS12-381 | HASH M = 8 | 88,617 | 119,270 | 132,481 | 119,319 | 4,096 B |

- `SENDER_CP` costs as `RECEIVER_X` (+49 gas: the bases swap); `AUDITOR` adds the cold `auditorKey()` read (≈ 9 k /
  13 k). A stored entry is read whole: BUNDLE M = 8 pays ≈ 65 / 129 cold slots for 2 / 4 KiB, which is why HASH (one
  slot + calldata) is the cheaper on-chain check at large `M`. Off chain (`eth_call`) every kind is free.

**Sizes** (`forge build --sizes`, runtime bytes, optimizer 200 runs; EIP-170 limit 24,576 B):

| Contract | Before (`main` `c137dca`) | After (rev 6) |
|---|---|---|
| `ZetherToken` | 31,911 (+7,335 over) | 28,939 (+4,363 over) |
| `ZetherDisclosure` | — | 4,916 |
| `ZetherVerifierBn254` | 15,955 | 15,955 |
| `ZetherVerifierBls12381` | 16,312 | 16,312 |

The split (Z13) takes 2,972 B off the token; it is **still over EIP-170** by 4,363 B. The next candidates are the prover-only views (`transferStatement*`, `burnStatement`) and the meta-tx relay
path; not done here.

## 8. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat decisions Z1–Z6 |
| 2 | 2026-10-08 | Z7: the multi-recipient transfer is `transferConfidential`; names without "Many" |
| 3 | 2026-10-08 | Z8: the single-recipient format stays as `transferConfidentialSingle` |
| 4 | 2026-10-08 | Spike merged (`93eddd2` on main as cherry-pick): names aligned with the code (`…-MULTI-V1/…` opTag, `ConfidentialTransferMulti`); measurements in §7 |
| 5 | 2026-10-08 | Z9 attestation removed, Z10 `SENDER_CP` + `j` in the disclosure challenge, Z11 threshold auditor key (off chain), Z12 per-transfer auditor opt-out; measurements to redo (§7) |
| 6 | 2026-10-08 | Z9, Z10, Z12 implemented; Z13: disclosure split into the stateless `ZetherDisclosure`, the token keeps `transferEntry` + `disclosure()`; §7 re-measured (transfer with auditor on / left out, disclosure per kind, sizes) |
