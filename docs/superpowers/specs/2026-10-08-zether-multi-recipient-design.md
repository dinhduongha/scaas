# Zether: one transfer to many recipients, three disclosure modes

**Status:** DRAFT; owner decisions recorded (Z1–Z6); a measuring spike implements it and stays in the code (owner:
"merge it so it can be reused"). Provisional ids `ZM-n`; real ids are allocated in `docs/decisions.md` on acceptance.
**Date:** 2026-10-08. **Scope:** classical Zether on EVM (`ZetherToken`, `ZetherVerifier` bn254 + BLS12-381,
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
E6_j  [z_vj]G + [z_s]Y_a − [c]C_aud_j − A_aud_j            (auditor on; off ⇒ every C_aud_j, A_aud_j = O)
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
opTag     = keccak256("SCAAS-ZETHER-OP-TRANSFER-MANY-V1/" ‖ mode)     mode ∈ {"HASH", "BUNDLE", "NONE"}
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
| HASH | `keccak256(B_1 ‖ … ‖ B_M)` (one slot) | `ConfidentialTransferMany(from, beneficiary, fee, sendCounter, entryRef, M, mode)` + the bundles in a `TransferBundles(entryRef, bundles)` event | on chain: the caller supplies all bundles, the token checks the hash, then the existing opening checks on `B_j` |
| BUNDLE | `B_1 ‖ … ‖ B_M` | the summary event | on chain, nothing supplied |
| NONE | nothing | the summary event | off chain only (calldata) |

`verifyTransferAmount(entryRef, j, amount, kind, opening, bundles)` / `attestTransferAmount(…)` serve both formats
(the token knows each entry's mode; a single entry has `j = 0` and its stored bundle), as the single-recipient disclosure (`bundles` ignored in BUNDLE mode, refused in NONE mode). Relaying through the meta-tx
envelope follows stream MT-6 (direct calls only here).

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

**Measured 2026-10-08** (owner Z7/Z8 names: the multi-recipient entry points are `transferConfidential` (HASH),
`transferConfidentialBundle`, `transferConfidentialNoBundle`; the single format is `transferConfidentialSingle`).
`test/zether/ZetherMulti.t.sol` `test_gas*`, forge 1.3.5, Prague, `gasleft()` around the call — execution gas
without the 21,000 intrinsic and calldata, each cell from a fresh state (every recipient and the beneficiary get their
first credit, as in the single-recipient figure), auditor on, inner fee to a beneficiary, one real recipient and
`M − 1` decoys at 0. Calldata = the ABI-encoded call in bytes.

| Curve | Entry | M = 1 | M = 2 | M = 4 | M = 8 | Calldata (M = 1 / 2 / 4 / 8) |
|---|---|---|---|---|---|---|
| bn254 | `transferConfidentialSingle` | 3,286,811 | — | — | — | 3,876 (derived: payload 32 B shorter, same proof) |
| bn254 | HASH (default) | 3,144,613 | 4,649,839 | 7,671,625 | 13,761,419 | 3,908 / 5,604 / 8,996 / 15,780 |
| bn254 | BUNDLE | 3,295,898 | 4,976,484 | 8,348,990 | 15,139,891 | same |
| bn254 | NONE | 3,093,384 | 4,595,117 | 7,609,845 | 13,684,495 | same |
| BLS12-381 | `transferConfidentialSingle` | 3,920,276 | — | — | — | 6,948 (derived) |
| BLS12-381 | HASH (default) | 3,584,305 | 5,309,455 | 8,820,900 | 16,090,549 | 6,980 / 10,148 / 16,484 / 29,156 |
| BLS12-381 | BUNDLE | 3,910,950 | 5,986,820 | 10,199,705 | **18,871,249** | same |
| BLS12-381 | NONE | 3,530,932 | 5,250,421 | 8,750,400 | 15,994,832 | same |

- **Per extra recipient** (slope M = 1 → 8): bn254 HASH ≈ 1.52 M, BUNDLE ≈ 1.69 M, NONE ≈ 1.51 M; BLS12-381 HASH
  ≈ 1.79 M, BUNDLE ≈ 2.14 M, NONE ≈ 1.78 M — against ≈ 3.29 M / 3.92 M for another separate transfer. The slope is
  one 64-bit range proof (≈ 1.2–1.4 M), E3/E6/E7, the recipient's `pending` write and its share of the bundle.
- **M = 1 vs the single format** (bn254): BUNDLE stores the same 256 B and costs +9 k (the `proofSystemIdMulti` call,
  the count word, the recipient loop); HASH saves 142 k, NONE 193 k. BLS12-381: HASH −336 k, NONE −389 k.
- **EIP-7825 cap (16,777,216 per transaction, intrinsic + calldata included):** every bn254 cell fits; on BLS12-381
  M = 8 BUNDLE does not (18.9 M execution), M = 8 HASH ≈ 16.6 M and NONE ≈ 16.5 M fit with < 2 % headroom.
- **Prover** (release `zether-cli proveTransferMulti`, one process per call — includes process start and generator
  setup; median of 3 on the chain-7622 host, AMD Ryzen 5 7235HS): bn254 single 74 ms, M = 1/2/4/8 = 75 / 114 / 181 /
  322 ms; BLS12-381 single 162 ms, M = 1/2/4/8 = 159 / 231 / 361 / 660 ms.
- **Sizes:** `ZetherToken` runtime 31,911 B (27,353 B before this change — already over the EIP-170 limit of 24,576 B
  on `main`); verifiers 15,955 B (bn254) / 16,312 B (BLS12-381). Optimizer runs = 1 does not bring the token under the
  limit (31,548 B); see the implementation notes.

## 8. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat decisions Z1–Z6 |
| 2 | 2026-10-08 | Z7: the multi-recipient transfer is `transferConfidential`; names without "Many" |
| 3 | 2026-10-08 | Z8: the single-recipient format stays as `transferConfidentialSingle` |
