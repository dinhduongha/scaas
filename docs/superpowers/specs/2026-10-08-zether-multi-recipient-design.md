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
`SelfTransfer`, `NotRegistered`). The proof system id gains the variant (`…/many/v1`) so a single-recipient proof never
matches.

## 5. Token

```solidity
function transferConfidentialMany(bytes calldata payload, bytes calldata proof, bytes calldata authSig, UA beneficiary)
    external returns (bytes32 entryRef);                 // mode HASH (default)
function transferConfidentialManyBundle(…) external returns (bytes32);   // mode BUNDLE
function transferConfidentialManyNoBundle(…) external returns (bytes32); // mode NONE
```

Checks and order as `transferConfidential` (cheap first, `accSeq`/`sendCounter`, registry `requireAuthorized` over the
statement digest, verify). Effects: `acc_f −= (C_deb + [fee]G, D_out)`; per `j` `pending_tj += (C_out_j, D_out)`,
`pendingSeq_tj++`; fee to the beneficiary as today; `sendCounter_f++` once. `entryRef` as today (one per transfer);
recipient `j` is addressed as `(entryRef, j)`. Bundle `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`:

| Mode | Stored | Event | Disclosure |
|---|---|---|---|
| HASH | `keccak256(B_1 ‖ … ‖ B_M)` (one slot) | `ConfidentialTransferMany(from, beneficiary, fee, sendCounter, entryRef, M, mode)` + the bundles in a `TransferBundles(entryRef, bundles)` event | on chain: the caller supplies all bundles, the token checks the hash, then the existing opening checks on `B_j` |
| BUNDLE | `B_1 ‖ … ‖ B_M` | the summary event | on chain, nothing supplied |
| NONE | nothing | the summary event | off chain only (calldata) |

`verifyTransferAmountMany(entryRef, j, amount, kind, opening, bundles)` / `attestTransferAmountMany(…)` mirror the
single-recipient disclosure (`bundles` ignored in BUNDLE mode, refused in NONE mode). Relaying through the meta-tx
envelope follows stream MT-6 (direct calls only here).

## 6. PQZ (note)

The PQZ encryption is already multi-recipient with shared randomness ([CTR-PQZ-04](../../contracts/pq-zether.md#CTR-PQZ-04)):
one `u` (16,384 B) for all recipients and one `v_j` (128 B, plus 128 B when the auditor is on) per recipient, so an
extra recipient adds little calldata at send time; the LNP22 proof growth with `M` is unknown until `pqz-core` exists.
The real per-recipient cost comes later: each credit — decoys included — enters the receiver's rollover as a full
`u ‖ v_j` ciphertext (≈ 16.5 KB, ≈ 0.52 M gas, [CTR-PQZ-11](../../contracts/pq-zether.md#CTR-PQZ-11)). Not measurable
now: no PQZ code exists (engine spikes E-S0… not started). Not in this spike.

## 7. Measurement (gate of the spike)

forge, real proofs from the prover, bn254 and BLS12-381: execution gas of `transferConfidentialMany*` for
`M ∈ {1, 2, 4, 8}` × the three modes, next to `transferConfidential`; calldata bytes per case. Prover time per `M`.
Results go into the gas table of `contracts/zether.md` on fold.

## 8. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat decisions Z1–Z6 |
