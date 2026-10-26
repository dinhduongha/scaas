# C0 — Contract-layer cryptographic design review

Reviewed checkout: `64549aa4f95f52618edbb6d55ac9c90dc6abf5fb`.

**Findings: one P0, one P1 and one P2.** Conclusions are from static inspection. No files were changed; no builds, tests, benchmarks or timing runs were performed.

## C0-1 — P0 — Classical Zether auditor copies expose differences between confidential amounts

**Locations:** [ZetherVerifier.sol:538](smartcontracts/evm/src/zether/ZetherVerifier.sol:538), lines 538–566; [zether.md:547](docs/contracts/zether.md:547), lines 547–568.

**Claim:** An audited multi-recipient transfer reuses the same mask under the same auditor key for every leg. Anyone can remove that mask by subtraction. This leaks amount differences and equality, undermines decoys, and lets knowledge of one leg expose amount commitments for every other leg.

**Evidence:** The specification defines:

```text
C_aud_j = [v_j]G + [s]Y_a
```

The verifier enforces exactly this construction. `_sigmaLegs` sets:

```solidity
l.ya = _sp(x, 1);
l.zs = z[1];
```

Every `_sigmaLeg` then checks E6 using the same `l.ya` and `l.zs`:

```solidity
_z4([l.g, l.ya, _lp(x, j, 2), _pf(x, 8 + 4 * j)],
    [zv, l.zs, l.nc, r1])
```

Consequently:

```text
C_aud_j − C_aud_k = [v_j − v_k]G
```

No auditor secret, signature forgery or invalid proof is required.

Concrete consequences:

- Zero-value decoys have identical auditor ciphertexts. In the common one-real-recipient transfer with several zero decoys, the repeated auditor ciphertext identifies the decoy cluster.
- Small amount differences can be recovered by enumeration; larger bounded differences permit the same discrete-log techniques used for legitimate Zether decryption.
- A recipient who knows its own amount, or a verifier given one legitimate `AUDITOR` disclosure, obtains `[s]Y_a = C_aud_k − [v_k]G`. It can then compute `[v_j]G` for **every** leg and recover amounts within its search bound. The claimed one-leg auditor disclosure therefore leaks information about other legs.

This is the classical counterpart of the separately reviewed PQZ R0-1 issue. PQZ now uses distinct auditor coefficient windows; the classical construction still repeats its mask. The specified older on-chain findings do not list this classical issue as fixed.

**Suggested fix:** Give each auditor copy independent encryption randomness and its corresponding public randomness commitment. Update the relation, transcript, wire format, disclosure and clients together, with a new proof-system identifier. Until that change is available, reject audited multi-recipient transfers with more than one leg. Independent proof nonces alone do not fix encryption-mask reuse.

## C0-2 — P1 — PQZH proposal A omits authorization size when deciding which holders can spend

**Locations:** [pqzh-calldata-cap.md:117](docs/research/pqzh-calldata-cap.md:117), lines 117–175 and 230–239; [UARegistry.sol:386](smartcontracts/evm/src/ua/UARegistry.sol:386), lines 386–416, 464–503 and 562–586; [PqzStateLib.sol:23](smartcontracts/evm/src/pqz/PqzStateLib.sol:23), lines 23–50.

**Claim:** Classifying PQZH support by parameter set, transfer shape and relay path is insufficient. Accepted PQ-dominant multisig holders can require substantially larger authorization calldata than the measured signer, including at n2048—the set proposal A retains for debits.

**Evidence:** The note reports n2048 burn/refresh calldata of:

```text
mtxExecute: 255,780 bytes
uaExecute:  259,140 bytes
```

The respective remaining calldata margins are only 6,129 and 2,769 bytes.

The registry permits up to 16 multisig members. PQ eligibility requires only:

```solidity
return classical < threshold;
```

Its registration feasibility check bounds verification execution gas, not the complete PQZH debit calldata. `_msig` requires individual member signatures; it provides no aggregation.

For example, consider an accepted **8-of-8 ML-DSA-65** holder on a precompile-enabled registry with sufficient verification budget. ML-DSA-65 signatures are 3,309 bytes, as fixed by `MlDsa.params65()`. Relative to the measured single-signature authorization, signatures alone add:

```text
(8 − 1) × 3,309 = 23,163 bytes
```

The multisig structure and ABI encoding add further bytes. This exceeds both margins. Removing the small address envelope also cannot recover that space. The note states that its vector proofs save only approximately 3–4 KB, which does not close this gap.

Such a holder can register using the smaller PQZL registration path and receive into a PQZH token: holder eligibility checks its immutable PQZ key, not whether its authorization fits that token’s debit transaction.

The already documented n2304/n2560 problem also remains relevant: `PqzStateLib.init` accepts the set’s PQZH identifier through `requirePqz`, without a debit-feasibility restriction. Proposal A’s release prohibition is therefore an essential protection, not an optional optimization.

**Impact:** Proposal A does not establish spendability for every holder the contracts accept. Normal valid PQZH debits can exceed the transaction cap even for its retained n2048 forms. This review establishes that capability gap; it does not claim a proof-size-independent impossibility theorem for every conceivable proof.

**Suggested fix:** Make feasibility depend on the **complete supported authorization profile**, including holder quorum, fee-payer authorization, proof bound, payload and relay overhead. Before accepting confidential value, ensure the holder has a supported exit path. Make the prohibition on PQZH token releases without feasible debits mandatory. Apply the same eligibility rule across chain kinds.

Proposal A otherwise preserves the existing statements, ciphertext storage and rollover algebra; this authorization-size omission prevents accepting its blanket “fits” conclusion.

## C0-3 — P2 — Classical COMPACT/NONE retain the history dependency forbidden by the stated storage rule

**Locations:** [ZetherLib.sol:278](smartcontracts/evm/src/zether/ZetherLib.sol:278), lines 278–287 and 699–716; [ZetherDisclosure.sol:103](smartcontracts/evm/src/zether/ZetherDisclosure.sol:103), lines 103–118; [zether.md:958](docs/contracts/zether.md:958), lines 958–963.

**Claim:** Under the task’s rule that ciphertexts stay in contract state and are never only hashed, classical Zether retains a conflicting exception.

**Evidence:** HASH stores:

```solidity
s.entryHashes[entryRef] = keccak256(r);
s.memos[entryRef] = payload[legsEnd:];
emit IZetherToken.TransferBundles(entryRef, r);
```

NONE skips `_storeRecord` entirely:

```solidity
if (mode != ZetherTypes.TransferMode.NONE)
    _storeRecord(s, p, entryRef, payload, pp, mode);
```

`ZetherDisclosure._leg` consequently requires caller-supplied bundles matching the stored hash. The documentation explicitly says receivers and auditors need `TransferBundles` or calldata under commit-reveal.

Concrete sequence: execute a COMPACT transfer, aggregate subsequent credits and rollovers, then lose access to its transaction/log history. Contract state retains the aggregate account ciphertexts, transfer hash and encrypted sender memo, but not the original recipient and auditor ciphertexts. An auditor cannot reconstruct the transfer from state alone; the sender memo requires the sender’s secret.

**Impact:** Historical receiver/auditor disclosure depends on retained history or sender cooperation. Aggregate balances remain spendable; this finding does not establish loss of funds.

**Suggested fix:** Persist the transfer ciphertext bundle in every classical mode, preferably once with references. Retire NONE or give it the same ciphertext persistence. Update the classical storage specification to match the owner rule.

## Checked and sound

These are scoped conclusions; the exceptions above remain open.

| Invariant | Evidence |
|---|---|
| **PQZ statement binding** | `PqzCore._header`, `_transferBuffer`, `_multiBuffer` and `_burnBuffer` bind the token, chain, registry, identifier, sender counter, cut, expiry, fees, recipients, stored keys, reconstructed `T` and outputs. |
| **Mode and relay binding / D15** | `_bindMode` folds transfer mode into direct and relayed statements; PQZ `_envUnwrap` additionally folds the leg and `minOut`. Restricted relayer/fee-recipient fields follow the envelope flags. |
| **Precompile result handling** | `PqzCore.verdict` accepts only successful calls returning exactly 32 bytes equal to one; authorization precedes settlement. |
| **PQZ debit races and pending window** | `_total` reconstructs `acc ± pending[window]`; rollover retains the subtraction window and enforces age/cap checks. Interleavings either preserve `T` or reject. Old backlog beyond the retained window and same-block TRIVIAL merges remain documented retry cases. |
| **Balance conservation, including fees** | `_debit` changes `totalShielded` by `shieldIn − fee − amount`; layer pool movements mirror it. Both multi-transfer implementations pay the decoy fee uniformly to every leg. Ordinary ERC-20/UA moves reject `SHIELD_POOL`. |
| **PQZ ciphertext persistence** | Debit blobs contain outputs; pending entries and fresh accumulators reference them, while rollover materializes the accumulator. HASH still retains the blob. Classical persistence has C0-3. |
| **Privacy and decoy semantics** | PQZ exposes sender, candidate recipients, counts, timing, public shields/burns and fees. Ordered prefix consumption avoids selective skipping. Decoy selection/collusion remain wallet assumptions; classical audited legs have C0-1. |
| **Selective disclosure** | PQZ loads the leg/key from state, binds amount/domain/kind and auditor window, and supplies only the proof as opening. Classical Chaum–Pedersen challenges bind entry, index, amount and kind; C0-1 defeats auditor isolation. Classical `SENDER_S` intentionally opens all legs. |
| **Signature/proof domain separation** | UA kind/purpose tags, PoP registry/chain binding, native `UAAuth` domains and predecessor routing match the design. Protocol consumers supply token/chain-separated digests; counters prevent repeated spends. |
| **BLS12-381 Zether protocol** | Statement and Sigma commitments precede the challenge; range commitments are linked through Sigma equations. Scalars/challenges are checked, MSM validates subgroups, and `accSeq`/`sendCounter` replace epochs. PUBLIC rollover grief is documented; OWNER_ONLY provides the specified mitigation. |
| **PQ signature choices and message encoding** | ML-DSA-44/65 use their distinct parameter tables and pure empty-context formatted `pq_msg`; SLH-DSA uses SHA2-128s with the same formatting. `fndsa512` explicitly implements Falcon-512 v1.2 padded encoding over `ua_msg`, rather than claiming a final FIPS-206 format. |
| **Relayability and zero fees** | Confidential writes, rollover and prepare-acc have allowlisted relay paths. Absolute fee classes allow NONE/FIXED, including zero; no positive fee floor is imposed. |
| **PQZH proposal A** | Its exclusions address the documented calldata excess without changing cryptography or storage. Full support remains unestablished because of C0-2. |

The earlier W-A mode-binding fix, removal of W-E’s hash/base mechanism, and CHAIN-01 zero-`u` refusal are present in the inspected PQZ paths; they are not re-reported.

## Not covered

- Native PQZ precompile/proof-system implementations, cryptographic parameter derivations and consensus code.
- Full arithmetic/hash-round audits of `MlDsa.sol`, `FnDsa.sol`, `SlhDsa.sol`, `Shake.sol`, `PqNtt.sol`, and classical signature helpers; signature review here covered design, parameters and encoding boundaries.
- Full wrapper reserve/admin logic, deployment scripts, client implementations, decoy-selection enforcement and live deployments.
- Exhaustive reading of historical/alternative research constructions and superseded parameter-sizing sections.
- Dynamic reproduction, gas measurements or independently regenerated builds for the other parameter sets; cited gas figures are existing repository evidence.

No execution checks were performed. The confirmed classical auditor-mask leak remains a risk to amount privacy.