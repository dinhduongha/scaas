# The verifier fee: an `OFFCHAIN` PQZ token pays its verifier UA from each debit's fee word (round 3t) — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-11 for the owner's ruling of the same day (§1), on branch
`ua-mtx-3t` at `7ec69f67` (spec 3r final, mid-build; spec 3s final). It uses 3r's names throughout (`admin`, `adminGeneration`,
`NotAdmin`; spec `2026-11-10-admin-not-owner.md` §4.1); the build comes after 3s. PQZ kinds 4, 5, 12, 13 in `OFFCHAIN` mode only;
`PRECOMPILE` tokens and every Zether kind keep today's behaviour (Zether ≠ PQZ). Recorded in `decisions.md` as
[CTR-PQZ-36](../../decisions.md#CTR-PQZ-36) (owner: yes) with Change lines on the rules it moves (§14). The component docs move
with the build (T11). **Controller calls 2026-11-11** on `727eec7a`, under the owner's leave of 2026-11-10: the three open
questions take their defaults and the `MetaTxLib.sol` comment leaves 3t; each is applied below, tagged (controller call 1 …), and
listed in §18.

## 1. The ruling (owner, 2026-11-11, in chat)

The owner's words, on the controller's proposal of the same day: **"OK, vậy đi"** (OK, go with it). The proposal, as approved:

- **R1. Config.** A new `verifierFee` (`uint64`) and an immutable cap `verifierFeeMax` in `IFactoryToken.ConfidentialConfig`. Only
  `OFFCHAIN` tokens of kinds 4, 5, 12, 13 may set them; a `PRECOMPILE` token refuses a non-zero value, the same class as
  `PqzVerifyConfigInvalid`. `verifierFee = 0` is off; no flag. Init: `verifierFee ≤ verifierFeeMax`, and the range rules extend to
  `confidentialFee + verifierFee + 8·minDecoyFee < 2^64` and `< maxShielded`.
- **R2. Payment.** Every proof-carrying op adds `verifierFee` to the statement's public `fee` word, `txFee + verifierFee + M·d`:
  the four `mtxConfidentialTransfer…` variants, `mtxUnshield` (burn and refresh) and `mtxUnshieldUnwrap`, direct and envelope
  forms. The relation and `proofSystemId` do not change. The op pays `verifierFee` from `SHIELD_POOL` to the current verifier UA's
  public UA-ledger balance, as `txFee` reaches the beneficiary. `verifyTransferAmount` charges nothing. `confidentialFee` is
  unchanged.
- **R3. Changing it.** The admin changes it within `[0, verifierFeeMax]` by `setVerifierFee(uint64)` and the router op
  `mtxSetVerifierFee` (typed, relayable at fee 0, one entry point). A decrease, to 0 included, applies at once. An increase, from 0
  included, takes the factory's `noticePeriod` stored at init: the first call proposes, the same call by the same proposer in the
  same admin generation within `[eta, eta + noticePeriod]` confirms, as `pqzSetVerifier` (CTR-PQZ-28). Events
  `VerifierFeeProposed(current, next, eta)`, `VerifierFeeSet(previous, next)`. A fee change makes already-built proofs fail, so a
  relayer simulates first.
- **R4. Off chain.** The statement builders and prover (`pqz-core`, `clients/clientkeys`, `ua-rs`), `scaas-pqz-verifier` (checks
  the fee word against the token's current `verifierFee`), the node (job fields, simulation, a pre-check of `fee`), wallets (the
  fee, the cap, a pending increase), the vectors from their generators, the matrix.
- **R5.** The Vietnamese comment on `MODE_OPEN` in `smartcontracts/evm/src/common/MetaTxLib.sol:44` becomes English. **Moved out of
  3t** (controller call 4): Vietnamese comments sit in hundreds of lines across `smartcontracts/evm/src` and `scaas-node/src`, so
  the controller makes them one separate cleanup item in TODO; 3t changes no comment, no task and no pin for it.

**The controller's additions** (2026-11-11, after the owner asked whether `SHIELD_POOL` can be drained by continuous confidential
transfers): **A1** state that `verifierFee` is part of the `fee` the relation subtracts from the sender's hidden balance (the new
balance `≥ 0` is proved), so the pool pays out only what a hidden balance lost; **A2** state that `totalShielded` decreases by
exactly `fee` (plus a burn's `amount`) and that `balanceOf(SHIELD_POOL) == totalShielded · shieldScale` holds after every op; **A3**
an invariant / fuzz test over a long sequence of fee-paying transfers, unshields and shields with `shieldIn` top-ups, and a threat
sentence: a lying `OFFCHAIN` verifier is the only path to a drain, bounded by the existing maximum loss, and `verifierFee` does not
widen it. Applied in §6.2, §9 (T28) and §15 (8), (9).

**Rules applied, not reopened:** CTR-PQZ-06 (fees out of `SHIELD_POOL` to public UA-ledger balances; `txFee = confidentialFee`
with a beneficiary), CTR-PQZ-12 (`PqzAuth` authorizes every spend), CTR-PQZ-17, CTR-PQZ-27 (trust model, maximum loss),
CTR-PQZ-28 (the verifier UA and its notice machinery), CTR-PQZ-29 (the verdict), CTR-AS-25 (every fee leg checks its recipient
before effects), CTR-TOK-29 (`noticePeriod`, at most 30 days), CTR-TOK-30 (body modules and the split rule), ARCH-POS-13, explicit
parameters, every state-changing `mtx*` relayable at fee 0, one rule on every chain, all chains test-only (no alias, no migration).

## 2. What is there today (at `7ec69f67`)

| Item | Where | Today |
|---|---|---|
| Config | `src/factory/IFactoryToken.sol:82-106` | `ConfidentialConfig {auditorKey, shieldScale, maxShielded, confidentialFee, disclosureMode, auditorMode, minDecoyFee, pqzVerifyMode, pqzVerifierUA, pqzVerifierFixed, proofStore}`; the two fees `uint256` |
| Init | `src/pqz/PqzStateLib.sol:45-97` | `confidentialFee < 2^64`, `< maxShielded`; `minDecoyFee < 2^64`; `confidentialFee + 8·minDecoyFee < 2^64` and `< maxShielded`, all `BadInit()`; a verifier field against the mode `PqzVerifyConfigInvalid()`; `OFFCHAIN` stores `noticePeriod()` |
| Other kinds | `MetaTokenBase.sol:162-174` (plain), `ZetherLib.sol:248-253` (Zether) | any set PQZ field `ConfigFieldForOtherKind(4)` |
| Fee word | `PqzCore.sol:878-893` `_common`, `:467-482` `prepareMulti` | `fee = beneficiaryUA ≠ 0 ? confidentialFee : 0`; op 7 adds `M·d` and refuses `fee ≥ 2^64` (`AmountOutOfRange`); header word 256 (`_header`, `:1230`) |
| Debit | `PqzCore.sol:1126-1135` `_debit` | `totalShielded = totalShielded + shieldIn − fee − amount`, checked |
| Payout | `PqzCore.sol:161-171` `Paid {shieldIn, ben, fee, decoyFee, legs}`; `PqzLayer.sol:374-401`, `:464-474` | `_fromPool(ben, fee)` (op 1, burn), `_fromPool(ben, fee − M·d)` then `d` to every leg (op 7); `_fromPool` (`:537`) = `_poolMove(SHIELD_POOL, to, units·shieldScale)`, unhooked |
| Beneficiary rule | `PqzCore.sol:886-891`; `RegulatedBase.sol:257-259`, `:275-278` | any registered UA (`kindOf ≠ 0`), no PQZ key (C0-7); on 12, 13 `_regName` → `_feeRecipient` (frozen, `R`; after 3s also `L`) before effects |
| Verifier transfer | `PqzStateLib.sol:110-138`, `_live` `:195-198` | propose / confirm by the same proposer in the same `adminGeneration` within `[eta, eta + noticePeriod]`; `NotProposer` before `NotAdmin`; notice 0 applies at once |
| Storage | `PqzCore.sol:64-96`; pin `test/v2/layout/namespaces.json` `pqz` | slots 0–19 used: 13 `pqzVerifierUA`, 14 shape, 15 `{epoch, fixed, noticePeriod, eta}`, 16–18 the pending verifier, 19 `debitRec`; slot 0 bytes 22, 23 the two mode bytes |
| View | `IPqzToken.sol:105-113`; `PqzStateLib.sol:175-180` | `pqzVerifyConfig()` → `PqzVerifyConfig {pqzVerifyMode, verifier, fixed_, pqzVerifierEpoch, pending, eta, noticePeriod}` |
| `PqzAuth` | `PqzCore.sol:186-188` | the 20 header words verbatim, `fee` among them: the holder's signature binds the fee word |
| Interface id | `test/merge/PqzPairs.t.sol:476` | `type(IPqzToken).interfaceId == 0x3fef18ca` |

## 3. Config

### 3.1 Fields

Appended to `IFactoryToken.ConfidentialConfig` after `proofStore` (the 3h precedent):

```solidity
/// `*_PQZ` kinds in `OFFCHAIN` mode only (round 3t, CTR-PQZ-36; every other kind and `PRECOMPILE` require both 0): the verifier
/// fee each proof-carrying debit pays to the current verifier UA, in the fee word's unit, and its immutable cap.
uint64 verifierFee;
uint64 verifierFeeMax;
```

**Unit.** The fee word's unit, the shielded unit of `confidentialFee` and `decoyFee`: R2 adds `verifierFee` to the word itself.
The payout is `verifierFee · shieldScale` public units, as `_fromPool` pays `txFee`; at `shieldScale = 1` the two numbers are equal
(controller call 1: this restates the ruling's "public units" precisely and does not change it: the fee is counted in shielded
units, like `confidentialFee` and the fee word, and paid as `verifierFee · shieldScale` public units).

### 3.2 The encoding and who reads it

The `ConfidentialConfig` tuple gains two static words at the end of its head, so `abi.encode(TokenConfig)` moves for **every**
kind (`conf` is in every `TokenConfig`, empty or not); all chains are test-only, so no alias.

| Reader | Change |
|---|---|
| `OpenFactory`, `GovernanceRouter.mtxCreateToken` | none in code: `initArgs` is opaque (the router signs `keccak256(initArgs)`); a given configuration's bytes and `initHash` move |
| `PqzStateLib.init` | the rows of §3.3 |
| `MetaTokenBase._requireUnused` (kinds 0, 1, 8, 9), `ZetherLib.init` (2, 3, 10, 11) | the two fields join the `ConfigFieldForOtherKind(4)` checks (`ZetherLib` on the 3f line, as `proofStore` did) |
| Node | `scaas-node/tests/e2e.rs:1557` (`sol!` struct), the e2e configs; `src/` decodes no `TokenConfig` (creations are no node rows) |
| Scripts | `script/pqz/e2e.py` (`CFG`, its self-test against the source turns red until updated, the T25 precedent), `script/onchain/pq.py` (`create_cfg`), `script/onchain/{Tokens,Dex,Gov,WrapLimits}.s.sol`, `script/ZetherE2E.s.sol` |
| Tests | 19 positional `IFactoryToken.ConfidentialConfig(…)` constructions in 15 files: 10 under `test/` (`test/pqz/helpers/PqzFixture.sol:96`, the five Zether files, `GovProofBit`, `NamedEntry`, `ZetherPairs`, `DiffZether`) and the five scripts above |
| Clients | none: no `TokenConfig` encoder in `clientkeys`, `ua-rs` or a `ua-*` at `7ec69f67` (grep); the wizard's encoder, when built, takes the fields |
| Vectors | none encodes a `TokenConfig`; `factory/create3_kat.json` does not depend on it |

### 3.3 Init rows (`PqzStateLib.init`, beside the 3f rows)

| Check | Error |
|---|---|
| `PRECOMPILE` and (`verifierFee ≠ 0` or `verifierFeeMax ≠ 0`) | `PqzVerifyConfigInvalid()` (a field set against the mode, CTR-PQZ-27) |
| `verifierFee > verifierFeeMax` | `VerifierFeeAboveMax(uint64 fee, uint64 max)` (new; also the setter's) |
| `confidentialFee + verifierFeeMax + 8·minDecoyFee ≥ 2^64` or `≥ maxShielded` (today's row, extended) | `BadInit()` (today's error for today's row) |
| written | `s.verifierFee`, `s.verifierFeeMax` (§4) |

**The cap in the range row** (controller call 2). The ruling writes the row with `verifierFee`. Checking it with
`verifierFeeMax` makes the ruled row hold for every value `setVerifierFee` can write (each is `≤ verifierFeeMax`), so the setter
needs no range check of its own and op 1 and the burn keep `fee < 2^64` with no runtime check (op 7 keeps its own). The ruled row
at init follows from it, since `verifierFee ≤ verifierFeeMax` is checked first.

## 4. Storage and layout pins

`scaas.pqz`, appended after `debitRec` (slot 19); no existing label, slot or offset moves:

```solidity
// round 3t (CTR-PQZ-36), read on the `OFFCHAIN` branch only: the fee, its immutable cap, a pending increase and its `eta` in one
// slot; the increase's proposer and its admin generation (the pending verifier's pattern, slots 16-18)
uint64 verifierFee;
uint64 verifierFeeMax;
uint64 verifierFeePending;
uint64 verifierFeeEta;
bytes32 verifierFeeProposer;
uint32 verifierFeeProposerGeneration;
```

| Label (`namespaces.json` `pqz`) | Slot | Inner | Byte | Width | Encoding | Written by |
|---|---:|---:|---:|---:|---|---|
| `verifierFee` | 20 | 0 | 0 | 8 | inplace | `init`, `setVerifierFee` |
| `verifierFeeMax` | 20 | 0 | 8 | 8 | inplace | `init` only (immutable, I-V1) |
| `verifierFeePending` | 20 | 0 | 16 | 8 | inplace | `setVerifierFee` |
| `verifierFeeEta` | 20 | 0 | 24 | 8 | inplace | `setVerifierFee` |
| `verifierFeeProposer` | 21 | 0 | 0 | 32 | inplace | `setVerifierFee` |
| `verifierFeeProposerGeneration` | 22 | 0 | 0 | 4 | inplace | `setVerifierFee` |

`Layout.t.sol` (`:79-98`, `:303-316`) writes distinct values to the six fields and asserts them with `_more(f, F(…))`;
`smartcontracts/vectors/pqz/state.json` and `n2304-kmax4096/state.json` copy the pin (`layout`) and are regenerated
(`STATE_VECTORS=1`). A `PRECOMPILE` debit reads no new slot (slot 0's mode byte is read first; I-V2, test (2)).

## 5. The fee word

### 5.1 Per op

`vf = (pqzVerifyMode == OFFCHAIN) ? verifierFee : 0`, read once in `_common` (shared by `prepareTransfer`, `prepareMulti`,
`prepareBurn`, hence by every statement view), after the beneficiary's `txFee`:

```solidity
if (s.pqzVerifyMode == OFFCHAIN) {   // slot 0, already read; slot 20 on this branch only
    o.verifierFee = s.verifierFee;
    o.fee += o.verifierFee;
}
```

| Op (entries, direct and `UAEnvelope` forms) | Header word 256 `fee` | Other words |
|---|---|---|
| op 1: `mtxConfidentialTransferSingle`, `…SingleCompact` (a stale version's migration to itself included) | `txFee + vf` | unchanged |
| op 7: `mtxConfidentialTransfer`, `…Compact` | `txFee + vf + M·d`; `≥ 2^64` ⇒ `AmountOutOfRange` (today's check) | unchanged; `vf` once per op, never per leg |
| op 2 burn: `mtxUnshield`, `amount > 0` | `txFee + vf` | `amount`, `recipient` unchanged |
| op 2 refresh: `mtxUnshield`, `amount = 0` | `txFee + vf` | unchanged |
| op 2 unwrap: `mtxUnshieldUnwrap` (kinds 5, 13) | `txFee + vf` | the unwrap binding unchanged |
| disclosure: `disclosureStatement`, `verifyTransferAmount` (both forms) | no fee word (`STMT_DISCLOSE`) | nothing charged: a view |

`txFee = confidentialFee` when `beneficiaryUA ≠ 0`, else 0 (unchanged). A debit with no beneficiary pays `vf (+ M·d)`. The args
structs, their typehashes (`UAPqzTransfer`, `UAPqzUnshield`, …) and `PqzAuth`'s typehash do not move: the fee word is computed by
the token, never a parameter. `ConfidentialTransfer` / `ConfidentialTransferMulti` keep emitting the whole word as `fee`; the split
is in the pool moves of the same transaction (`UATransfer` / `Transfer` from `SHIELD_POOL`).

### 5.2 The relation and `proofSystemId` do not change (checked)

- **Layout.** §7.7 of `pq-zero-knowledge.md`: word 256 is `fee`, a public header word; serialization v1 row 8: "`fee` `< 2^64`
  (read by every debit relation)". No word is added, moved or reinterpreted.
- **PQZL** (`pqz-core/pqzl/rust/src/rel.rs:454`, `:574`, `:768`; `sv.rs:1024`, `:1182`): `parse_debit` reads `fee` with `word64`
  and row 7 takes `digit(t.fee, i)` as a public right-hand side; no witness or transcript element depends on its value.
- **PQZH** (`pqz-core/pqzh/ligero/src/cs.rs:572`, `:842-858`): row 7's right-hand side adds the public `fee` digit `k`.
- **Relations** (`pq-zero-knowledge.md` §7.4, §7.5, CTR-PQZ-26): `R_TX` row 7 `M_i + c_{i−1} = d'_i + d_i + f_i + 16·c_i`,
  `f = digits(fee)`; `R_BURN` = rows 1, 2, 4, 6, 7; `R_TXM` row 7 likewise with every leg. `fee` is a public input of every debit
  relation, any value `< 2^64`.
- **Parser** (`pqz-core/stmt`): `fee ≥ 2^64` refused (`Reject::Fee`), else accepted; the bound is kept by §3.3 and op 7's check.

Result: the relations, both proof systems, the transcripts and `proofSystemId` are unchanged; no new vectors in the statement or
proof files and no full gate. What changes off chain is the witness: `d' = digits(b − v − fee)` with the larger `fee` (§12).

### 5.3 What a fee change does to a built op

Every debit's statement, hence its proof, its `PqzAuth` digest and its verdict, binds the fee word. After any `VerifierFeeSet`, an
op built at the old fee refuses on chain, first **`AuthRejected()`** (`_auth` runs before the proof and hashes the header with the
new word), and with a re-signed `pqzAuth` `PqzVerdictMismatch(3)` (`statementHash`); off chain the verifier answers
`FEE_WORD_MISMATCH` (§11) and the node `PQZ_FEE_MISMATCH` (§10). **A relayer simulates every PQZ debit before sending** (NODE-JOB-22
already does); a wallet re-reads the statement view and re-proves. The holder never pays a fee it did not sign: an increase makes
the op fail, never charges more.

## 6. Payment

### 6.1 Order inside each op

`Paid` gains two fields, `uint256 verifierFee` and `bytes32 verifier`; `_paid` sets `verifier = verifierFee == 0 ? 0 :
s.pqzVerifierUA` after `_check` passed, so it is the UA whose verdict was accepted (its epoch matched) and never 0 when a fee is
paid. The token pays (D19: the library decides, the token pays):

| Step | op 1 (`_single`) | op 7 (`_multi`) | burn, refresh (`_mtxUnshieldBody` → `_burn`) | unwrap (`_mtxUnshieldUnwrapBody` → `_burn`) |
|---|---|---|---|---|
| 1. checks, no effect | `_regSender(from)`, `_regPayer()` if `shieldIn`, `_regName(ben)`, **`_regName(verifierPayee())`** | the same | `_regReceiver(recipient)` if `amount ≠ 0`, the receiver rule, then as op 1 in `_burn` | `quoteTo` (before the proof), then as burn |
| 2. `_pullShieldIn` | `shieldIn·s` signer → pool | the same | the same | the same |
| 3. library | statement (`fee = txFee + vf`), `_check`, `_debit`: `totalShielded += shieldIn − fee` | `fee = txFee + vf + M·d`; `totalShielded += shieldIn − fee` | `totalShielded += shieldIn − fee − amount` | the same |
| 4. pay `txFee` | `_fromPool(ben, fee − vf)` | `_fromPool(ben, fee − vf − M·d)` | `_fromPool(ben, fee − vf)` | the same |
| 5. **pay `vf`** | **`_fromPool(verifier, vf)`** | the same | the same | the same |
| 6. the rest | — | `_fromPool(leg_j, d)` for every leg | `_fromPool(recipient, amount)` (burn; none on a refresh) | `_poolMove(SHIELD_POOL, 0, amount·s)` (a burn of the token), `payOutTo` the underlying |

`s` = `shieldScale`. `_fromPool` with 0 units moves nothing, so `vf = 0` and `ben = 0` cost no move. `verifierPayee()` (new,
`PqzCore`, internal) is `s.pqzVerifierUA` when `OFFCHAIN` and `verifierFee ≠ 0`, else 0; every slot it reads is read later in the
same op anyway, so it adds no cold access. The relayer's outer fee (the envelope's, step 6 of the base) is unchanged and apart.

### 6.2 Conservation (controller A1, A2)

- **A1. The pool pays out only what a hidden balance lost.** `vf` is part of the `fee` word, and every debit relation proves
  `Σ M_i·16^i = b' + v + fee` exactly (op 7: `b' + Σ a_j + fee`; burn: `b' + amount + fee`) with `b' ≥ 0` a digit property and `T`
  built by the token from state plus `Trivial(shieldIn)` (`pq-zero-knowledge.md` §7.4, row 7; §5.2 here). So `v + fee ≤ T`: the verifier fee comes out of the
  sender's hidden balance (and the same call's `shieldIn`) exactly as `txFee` does; a sender whose `T` is below `v + fee` (or
  `amount + fee`) has no valid proof (§15 (9)).
- **A2. `totalShielded` moves by exactly what the pool moves.** `_debit` writes `totalShielded + shieldIn − fee − amount`
  (checked: an underflow reverts), and steps 2–6 move exactly `shieldIn·s` into the pool and `(txFee + vf + M·d + amount)·s =
  (fee + amount)·s` out of it (op 1's and op 7's credits `v`, `a_j` stay in the pool, hidden). Hence `balanceOf(SHIELD_POOL) ==
  totalShielded · shieldScale` after every op, and the sum of every payout of a token's life is at most the sum of its shields and
  `shieldIn`s.
- **`totalSupply`** moves only with wraps, mints and unwraps: every payout is an ERC-20 move from `SHIELD_POOL` (to an address, or
  to `UA_POOL` with the ledger credit), never a mint or burn; `mtxUnshieldUnwrap` burns `amount·s` from the pool as today, never
  `vf`. `balanceOf(UA_POOL) == Σ` UA-ledger balances holds (`_poolMove` credits both). The escrow `underlying.balanceOf(this) ≥
  totalSupply()` on 5, 13 is untouched.
- **`decoyFee`, `shieldIn`**: unchanged rules; `vf` sits beside `txFee` in the word, `M·d` after it; a holder whose hidden balance
  is short of the fee may pay it from `shieldIn` in the same call.

### 6.3 The payee (the beneficiary rule, applied to the verifier)

The payee is the current verifier UA (`pqzVerifierUA` at the op; during a pending verifier transfer, the current one until the
confirm). As for the beneficiary (C0-7), it needs no PQZ key and is a public credit:

- **Native verifier** (`0x0001`, a padded address): its ERC-20 balance, spendable at once.
- **Derived verifier** (`secp256k1`, `p256`, `webauthn-p256`, `mldsa44`, `mldsa65`, or an `msig` of those): registered by
  construction (`verifierShape` strict at every assignment refuses `kindOf = 0`, `PqzVerifierUnregistered`), so a registered
  UA-ledger receiver. **A derived verifier without a ledger balance** simply has `balanceOfUA = 0`: the first payout creates the
  balance (one new slot, about 98 k state gas, paid by that op's submitter once); nothing is refused and no PQZ key is needed. Every
  admitted kind is a signing kind, so the verifier spends the balance with its own UA signature (an `msig` by its quorum) through
  the UA-ledger entries. A PQZ token always has a registry (`validateEnv`), so the ledger is never off.
- **No verifier** (revoked, `pqzVerifierUA = 0`): every proof-carrying op refuses `PqzVerifierRevoked()` in `_check`, before any
  payout; `Paid.verifier` is never 0 with `vf ≠ 0` (I-V3, mutant M19).

### 6.4 The regulated kinds (12, 13)

The verifier fee is a fee leg, so CTR-AS-25 applies: `_regName(verifierPayee())` checks it as a fee recipient (`_feeRecipient`:
frozen ⇒ `FeeRecipientFrozen`, `R` under `KYC`, and 3s's `L` under the lists) before effects, only while `vf ≠ 0` (`_regName(0)`
checks nothing). On 4, 5 `_regName` is the empty hook ("+0" holds for the plain kinds; the PQZ debit paths are not in
`plus_zero_gas.json`). Relief when a check stops every debit: the admin sets the fee to 0, at once (T31).

## 7. Changing the fee

### 7.1 `setVerifierFee(uint64 next)` (kinds 4, 5, 12, 13; `governed`, `nonReentrant`)

The module stub calls `PqzStateLib.setVerifierFee(next, _govSubject())`, the `pqzSetVerifier` pattern line by line:

```solidity
function setVerifierFee(uint64 next, bytes32 caller) public {
    PqzCore.PqzStorage storage s = PqzCore.$();
    GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
    bool live = _feeLive(s, g);
    bool confirm = live && next == s.verifierFeePending;
    if (confirm && caller != s.verifierFeeProposer) {
        revert IGovernance.NotProposer(0, bytes32(uint256(next)), s.verifierFeeProposer);   // before the admin check, as 3f
    }
    _admin(caller, g);                                                                        // NotAdmin(caller)
    if (s.pqzVerifyMode != PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyConfigInvalid();
    uint64 cur = s.verifierFee;
    if (confirm) {
        if (block.timestamp < s.verifierFeeEta) revert IPqzToken.VerifierFeeNotReady(s.verifierFeeEta);
        _setFee(s, cur, next);
        return;
    }
    if (next > s.verifierFeeMax) revert IPqzToken.VerifierFeeAboveMax(next, s.verifierFeeMax);
    if (next == cur) revert IPqzToken.VerifierFeeSame();
    if (next < cur) {                         // a decrease, to 0 included: at once; a live pending increase is dropped
        _setFee(s, cur, next);
        return;
    }
    if (live) revert IPqzToken.VerifierFeePending(s.verifierFeePending);
    uint64 eta = uint64(block.timestamp) + s.noticePeriod;
    emit IPqzToken.VerifierFeeProposed(cur, next, eta);
    if (s.noticePeriod == 0) {
        _setFee(s, cur, next);
        return;
    }
    (s.verifierFeePending, s.verifierFeeEta, s.verifierFeeProposer, s.verifierFeeProposerGeneration) =
        (next, eta, caller, g.adminGeneration);
}

/// @dev A pending increase still confirmable: proposed in this admin generation, `[eta, eta + noticePeriod]` not passed. An
///      increase is `> verifierFee ≥ 0`, so `verifierFeePending ≠ 0` marks one.
function _feeLive(PqzCore.PqzStorage storage s, GovernanceLib.GovernanceStorage storage g) private view returns (bool) {
    return s.verifierFeePending != 0 && s.verifierFeeProposerGeneration == g.adminGeneration
        && block.timestamp <= uint256(s.verifierFeeEta) + s.noticePeriod;
}

/// @dev Writes the fee, drops any pending increase, `VerifierFeeSet(previous, next)`.
function _setFee(PqzCore.PqzStorage storage s, uint64 previous, uint64 next) private {
    s.verifierFee = next;
    (s.verifierFeePending, s.verifierFeeEta, s.verifierFeeProposer, s.verifierFeeProposerGeneration) = (0, 0, 0, 0);
    emit IPqzToken.VerifierFeeSet(previous, next);
}
```

- **Reused, not copied:** `_admin` (`PqzStateLib.sol:184`), the stored `noticePeriod` (slot 15), `adminGeneration`, `NotProposer`,
  `NotAdmin`, `PqzVerifyConfigInvalid`. Own state (§4), because a verifier transfer and a fee increase may be pending at once.
- **An admin change or a passed window** leaves the pending dead (`_feeLive` false); the next increase proposes afresh.
- **No cancel entry** (one entry point, R3): a pending increase dies unconfirmed, or by a decrease. **A decrease during a pending
  increase cancels it** (controller call 3): the `VerifierFeeProposed` is superseded, `_setFee` deletes the pending and emits
  `VerifierFeeSet(previous, next)`; no event of its own, and a later increase gives a new notice.
- **A fixed verifier** (`pqzVerifierFixed`) fixes the verifier, not its fee: the admin changes the fee on both (R3 names no
  exception). **Admin 0** (no administration): the fee stays at its init value for ever (disclosed at creation, §12).
- **Order of refusals:** `NotProposer` (a live pending, the same `next`, another caller), `NotAdmin`, `PqzVerifyConfigInvalid`
  (`PRECOMPILE`), then `VerifierFeeNotReady` (a confirm), `VerifierFeeAboveMax`, `VerifierFeeSame`, `VerifierFeePending`.

### 7.2 Router op

`mtxSetVerifierFee(UAEnvelope e, address target, uint64 next, UASig auth)` over `UASetVerifierFee(bytes32 from,address target,uint64
next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)`, beside
`mtxPqzSetVerifier` (`GovernanceRouter.sol:130`): `_ua(T.UA_SET_VERIFIER_FEE, e, target, IPqzToken.setVerifierFee.selector,
abi.encode(next), auth)`; fee mode `NONE`, relayable at fee 0, any submitter. The token's `mtxSelectors()` and `_uaAllowed` do not
change (a direct governance entry, never on the generic allow-list). `next` is the new fee; the envelope's `fee` is the relay fee.

### 7.3 The view

`pqzVerifyConfig()` (selector unchanged) returns `PqzVerifyConfig` with four fields appended: `uint64 verifierFee`, `uint64
verifierFeeMax`, `uint64 verifierFeePending`, `uint64 verifierFeeEta` (a dead pending reads as 0, 0, as the verifier's).
`PRECOMPILE` tokens answer 0 for the four. Existing readers access by name or read the first words (`pq.py`, `e2e.py`), so they keep
working; the node's and the verifier service's `sol!` structs gain the fields (§10, §11). No new view entry.

## 8. ABI (selectors with `cast sig`, topics and typehash with `cast keccak`, Foundry 1.8.5, 2026-11-11)

**Positive controls**, computed the same way in the same run: `mtxPqzSetVerifier` `0x065bf7fd` (= `scaas-node/src/guard.rs:1929`),
`mtxSetProofStore` `0xa63e5886` (= `guard.rs:1936`), `pqzSetVerifier(bytes32)` `0x45fbee36` and `pqzVerifyConfig()` `0xdc59c66e`
(= `script/modules/entries.json`), `UAPqzSetVerifier` `0xc7b836ae…` (= `test/governance/GovRouterTypehash.t.sol:206`),
`UASetProofStore` `0xcd4ab715…` (= `:225` and `vectors/typed/typed_ops.json`), `PqzVerifyConfigInvalid()` `0xbb2bf818` and
`NotAdmin(bytes32)` `0xba963c12` (found among the 208 errors of `script/modules/face_abi.json`; `NotAdmin` = 3r's table).
**Collisions:** the two new function selectors are not among the 168 signatures of `test/vectors/selector_audit.json` (all 168
computed; `mtxPqzSetVerifier`, `mtxSetProofStore`, `pqzSetVerifier` and `setProofStore(uint8)` `0x26f21b98` found among them); the four new error selectors are not among `face_abi.json`'s 208 errors.

| Signature | Selector / topic0 | Where |
|---|---|---|
| `setVerifierFee(uint64)` | `0xe790fb8f` | kinds 4, 5, 12, 13 (`IPqzToken`): module Q on 4, 12; S on 5, 13 |
| `mtxSetVerifierFee((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),address,uint64,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))` | `0xf0d8cbbf` | router |
| `pqzVerifyConfig()` | `0xdc59c66e` (unchanged) | the struct gains four fields (§7.3) |
| `VerifierFeeAboveMax(uint64,uint64)` | `0xd6a6babf` | `IPqzToken` (init, setter) |
| `VerifierFeePending(uint64)` | `0x42b748e0` | `IPqzToken` |
| `VerifierFeeSame()` | `0xd24bcb0e` | `IPqzToken` |
| `VerifierFeeNotReady(uint64)` | `0x7c735c30` | `IPqzToken` |
| `VerifierFeeProposed(uint64,uint64,uint64)` | `0xd82df1fee25629c20173f2b882fd47151bf638b7f8aaf9fbf4a43f965e7d11a7` | `IPqzToken` (`current`, `next`, `eta`; none indexed, as `PqzVerifierProposed`) |
| `VerifierFeeSet(uint64,uint64)` | `0x782a7205089b449dd89f2c2ed79ae1ab0cf1efbf1b5b58e4258b88052ed86131` | `IPqzToken` (`previous`, `next`) |
| reused | `PqzVerifyConfigInvalid()` `0xbb2bf818`, `NotAdmin(bytes32)` `0xba963c12`, `NotProposer(uint8,bytes32,bytes32)` `0xe0facde2`, `BadInit()` `0xc673943d`, `ConfigFieldForOtherKind(uint8)` `0xcabd65e1`, `AmountOutOfRange(uint256,uint256)` `0x4cc4d546` | |

| Typehash | Value |
|---|---|
| `UASetVerifierFee(bytes32 from,address target,uint64 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)` | `0xffa3baec15773742773872cec5ac6e8000b668a4576324f215b5e663818dd14d` |

`T.UA_SET_VERIFIER_FEE` gets a `*TypehashIsPinned` row in `GovRouterTypehash.t.sol`. **`type(IPqzToken).interfaceId` moves**
`0x3fef18ca` → `0xd87fe345` (that value XOR `0xe790fb8f`, the one new function; `pqzVerifyConfig()`'s return does not enter the id),
recomputed after 3r and 3s merge; the pin in `PqzPairs.t.sol:476` moves old → new. Unchanged selectors whose behaviour moves: the
twelve proof-carrying entries (the fee word, the payout) and the debit statement views `transferStatement`,
`transferSingleStatement`, `burnStatement`, `unshieldUnwrapStatement` (the fee word).

## 9. Trust model and threats

**Trust model** (CTR-PQZ-27, extended; shown at creation, in wallets and before a shield into an `OFFCHAIN` token): besides the
soundness it already places in the verifier UA, an `OFFCHAIN` token charges every debit up to `verifierFeeMax` units for its
verifier; the current value and any pending increase are public; an increase waits the factory's notice period stored at init
(possibly 0 on a test chain); a decrease is at once. The holder signs the fee word of each op (`PqzAuth`).

Rows for `pq-zero-knowledge.md` §12 (next free id T28):

| # | Abuse | Outcome (3t) |
|---|---|---|
| T28 | **Drain of `SHIELD_POOL`** by continuous confidential transfers (controller A3) | An honest proof cannot pay out more than a hidden balance lost (§6.2 A1): `vf` is inside the proved `fee`, and `totalShielded` moves with the pool (A2), its subtraction checked. **A lying `OFFCHAIN` verifier is the only path to a drain** (on a `PRECOMPILE` token only a broken proof system, T2), bounded by CTR-PQZ-27's maximum loss `min(totalShielded, maxShielded) · shieldScale` public units; `verifierFee` does not widen it: every payout of a debit, the verifier's included, leaves the pool only as `totalShielded` falls, and the verifier's own fees count inside that bound, not beside it. `PRECOMPILE` tokens: `vf = 0`, unchanged |
| T29 | **Admin raises the fee as a hostage** | Bounded per op by the immutable `verifierFeeMax` and in time by the notice: `VerifierFeeProposed` (an indexer alert, §10) gives every holder `noticePeriod` to leave at the old fee (one debit each); a confirm comes no earlier than `eta` and dies after `eta + noticePeriod` or at an admin change. With `noticePeriod = 0` there is no notice (disclosed). A transferable verifier lets the admin name itself the payee (with the verifier's own notice), still within the cap. A creator that wants no fee power sets `verifierFeeMax = 0` |
| T30 | **Dust below the fee** | A hidden balance below `txFee + vf` (with `M·d` on op 7) cannot be debited at all, unshield, refresh and a stale version's migration included, unless the same call tops it up with `shieldIn` from the holder's public balance of the same token, or the admin lowers the fee (at once). The largest unshield is `T − fee`. With admin 0 the fee never moves: such dust stays until topped up. Wallets warn (§12) |
| T31 | **The verifier as a payee fails a regulated check** (12, 13) | A frozen, ineligible (`KYC`) or listed-out (3s) verifier stops every proof-carrying op while `vf ≠ 0` (CTR-AS-25 refuses the leg); relief: the admin sets the fee to 0 at once, or lifts the cause; with `vf = 0` nothing is checked. A verifier nobody can sign for (a pool address as a native id) passes no op, so no fee reaches it |
| T32 | **A fee change strands built ops** | Every op proved and signed at the old fee refuses (§5.3); funds are not at risk, the holder re-proves. Relayers simulate first; a queued job is `PQZ_FEE_MISMATCH`, back in the queue, never `dead` (§10). A wallet that sees a pending increase with `eta` before its op's deadline warns or waits |
| T33 | **Forced refreshes** | A full `acc` needs a debit (CTR-PQZ-06), which now costs `vf`. A griefer forces one refresh per `K_MAX − 2` credits into the victim, paying it at least `K_MAX − 2` units (shields) or `(K_MAX − 2)·minDecoyFee` (decoy legs) for each; the victim loses net only when `vf` exceeds that. Disclosed; the wizard shows the ratio for the chosen set |

## 10. Node and gateway rows (both directions)

| File | Change |
|---|---|
| `scaas-node/src/typed.rs` | one `GR` row after `UASetProofStore` (`:240`): `("UASetVerifierFee", "mtxSetVerifierFee", GR, "bytes32 from,address target,uint64 next,E", "")`; the counts (`:1631`, `:1637`) +1 on top of 3r's and 3s's, old → new in the commit; the twelve PQZ debit rows take the named job field `pqz_fee` (below), never in the call data |
| `scaas-node/src/guard.rs` | the router's `CALL_TABLE` gains the row (type string, ABI signature, selector `0xf0d8cbbf`), the router count +1; `args.pqz_fee` decoded as a `uint64` decimal string, refused `BAD_PAYLOAD` when absent on a proof-carrying entry or `≥ 2^64`, hex `HEX_ARGS_REFUSED`; the allow-lists equal `selector_audit.json` both ways |
| `scaas-node/src/pqz.rs` (`fill`, `:88`) | **the fee pre-check**, before the verdict fetch, at intake and again before every send: `expected = (beneficiaryUA ≠ 0 ? confidentialFee() : 0) + pqzVerifyConfig().verifierFee + M·decoyFee` (`M`, `d` from op 7's args, 0 otherwise); on `OFFCHAIN` it also equals the rebuilt statement's word 256. `pqz_fee ≠ expected` ⇒ `PQZ_FEE_MISMATCH: proved {p}, the token's fee word is {e} (txFee {a}, verifierFee {b}, M·d {c})`, zero sends: a 422 at intake; in the lane back in the queue until the deadline (a decrease may restore the word), never `dead` while it may land |
| `scaas-node/src/submit.rs` | a PQZ debit's simulation reverting `AuthRejected()` or `PqzVerdictMismatch(3)` after an indexed `VerifierFeeSet` of its token since intake ⇒ `PQZ_FEE_MISMATCH`, back in the queue (the `PQZ_KEY_ROTATED` pattern, T55); a fee change is the reason to simulate first (§5.3) |
| `scaas-node/src/abi.rs` | `IPqzToken`: `setVerifierFee`, `PqzVerifyConfig` (`:410`) with the four fields, the four errors, the two events; the PQZ refusal lists (`:680`): `VerifierFeeNotReady(eta)` and `VerifierFeePending(pending)` liftable (as `PqzVerifierNotReady` / `PqzVerifierPending`), `VerifierFeeAboveMax`, `VerifierFeeSame` final |
| `scaas-node/src/indexer.rs` | `VerifierFeeProposed(current, next, eta)` a row with `alert: true` (the hostage notice, T29); `VerifierFeeSet(previous, next)` a row without; the per-token health stamp gains `pqz_verifier_fee` |
| Gateway / job API | `args.pqz_fee` required on the twelve proof-carrying entries (both modes: one rule; a `PRECOMPILE` token's word is `txFee + M·d`); the token view (SPECIFIED, `indexer-feeds.md#pqz-verifier-rows`) gains `verifier_fee: {fee, max, pending, eta}`. **Operator note:** a job shape change: a consumer on the old shape gets `BAD_PAYLOAD: no pqz_fee` |
| Docs | `job-api.md` NODE-JOB-22 (`pqz_fee`, the pre-check, the refusal; the error table at `:961`), `submit-lanes.md` (the liftable names), `indexer-feeds.md:186-197`, `ops.md:827` (the verifier's payout and the operator note) |

## 11. The PQZ verifier (off-chain), `scaas-pqz-verifier`

| File | Change |
|---|---|
| `src/abi.rs` | `PqzVerifyConfig` with the four fields |
| `src/lib.rs` `verdict()` (`:376`) | after the config read, before the view call: the request's statement word 256 must equal `(beneficiaryUA ≠ 0 ? confidentialFee() : 0) + cfg.verifierFee + M·d` from `op.args`, else `FEE_WORD_MISMATCH` naming the three terms; then today's byte compare (`STATEMENT_MISMATCH`), pqz-ffi (`VERDICT_ZERO`) and key checks. It signs nothing it did not verify; the fee is the token's, not the service's policy |
| `tests/service.rs` | a statement at a stale fee refused by name; the positive control at the current fee signed; an overspend proof (§15 (9)) `VERDICT_ZERO` |
| Docs | `ops.md#pqz-verifier`: the verifier is paid on the token (its address's balance, or its UA's ledger balance), spends with its own key; an operator's price floor is not specified |

## 12. Clients, wallets and vectors (generators only)

| Item | Change |
|---|---|
| `pqz-core` | no change to `pqzl`, `pqzh`, `stmt`, `ffi/src` or a set (§5.2): no full gate. A new test `pqz-core/ffi/tests/fee_word.rs` (§15 (9)), outside `ffi/src` |
| Witness builders | the reference builders take the fee from the statement view's word 256, never from their own sum: `script/pqz/e2e.py:1782`, `:1865` (`fee` gains `vf`), `smartcontracts/vectors/pqz/pqz_kat.py` where it rebuilds a debit's `d'` |
| `clients/clientkeys` | `src/evm.js`: the `UASetVerifierFee` router type (beside `:407`), `pqzFeeWord({confidentialFee, beneficiaryUA, verifierFee, legs, decoyFee})` (display and the node / verifier parity; a wallet's witness uses word 256), the `PqzVerifyConfig` decode with the four fields; `test/pqz-verifier-fee.test.js` reads `verifier_fee.json`; `test/typed-ops.test.js` the new row |
| `clients/ua-rs` | `src/pqzfee.rs` (the pattern of `src/wraplimit.rs`): the `UASetVerifierFee` struct hash and digest (ua-rs signs every kind), `pqz_fee_word`; `tests/pqzfee.rs` against `typed_ops.json` and `verifier_fee.json`; the `ua-*` wrappers sign through it (none lists router types today) |
| `clients/zether-prover/tests/typed_ops.rs` | `NOT_ZETHER` gains `UASetVerifierFee` |
| Wallets (`docs/clients/app.md#pqz-verifier-display`) | show `verifierFee`, `verifierFeeMax`, a pending increase with its value and `eta`, and before signing the op's whole fee word split `txFee` / `verifierFee` / `M·d`; the wizard shows the cap, the stored notice period and T33's ratio; before a shield into an `OFFCHAIN` token, the fee and the cap with the trust model; warn on T30's dust and on a pending increase whose `eta` precedes the op's deadline |
| `smartcontracts/vectors/pqz/verifier_fee.json` (new) | writer `test/pqz/PqzVerifierFeeVectors.t.sol` (`WRITE_VERIFIER_FEE=1`): per form (op 1 BUNDLE / HASH, op 7 `M` ∈ {1, 2, 4, 8}, burn, refresh, unwrap) × beneficiary (0 / set) × `vf` (0, 1, the cap): `confidentialFee`, `verifierFee`, `M`, `d`, the fee word, each payout in public units at `shieldScale` 1 and `10^12`, Δ`totalShielded`, Δ pool; read by clientkeys, ua-rs, the node and the verifier service |
| `smartcontracts/vectors/typed/typed_ops.json` | `clients/clientkeys/scripts/typed-ops-vectors.mjs`: `UASetVerifierFee`, plus one row with a non-zero unbound `relayer` and `feeRecipient` (the canonical zeroing) |
| `smartcontracts/evm/test/vectors/selector_audit.json` (by hand, never regenerated) | kinds 4, 5, 12, 13: `setVerifierFee(uint64)` `ADMIN`, error `NotAdmin(bytes32)`; the router: `mtxSetVerifierFee` `SIGNED`; `SelectorAudit.t.sol` and the node's both-directions test |
| Unchanged | `statement_*.json`, `proof_*.json`, `negative.json`, `fee0.json`, `verdict.json`, `governance_bits.json` (no bit: a fee change is an admin act, as the verifier's, C4) |

## 13. Matrix

`script/onchain/pq.py`, group `pqoff` (§10 of the run, `:346`): an `OFFCHAIN` token of kind 4 and one of kind 13 created with
`verifierFee = f`, `verifierFeeMax = F`; a debit of each form pays `f·s` to the verifier (its balance read before and after), the
pool and `totalShielded` agree after each step; a decrease applies at once; an increase proposes (`VerifierFeeProposed`), confirms
after the local notice (at once when it is 0); an op built at the old fee refuses (`AuthRejected`); `setVerifierFee` on a
`PRECOMPILE` token refuses `PqzVerifyConfigInvalid`; the router op at fee 0 by a stranger relayer. `coverage.py gen`; local run
only; the SCaaS testnet run follows the round's merge.

## 14. Docs to change

- **`decisions.md`** (this commit): [CTR-PQZ-36](../../decisions.md#CTR-PQZ-36), owner: yes, status SPECIFIED, the owner's quote on
  its Source line; Change lines on CTR-PQZ-06 (a third fee), CTR-PQZ-17 (the range row), CTR-PQZ-27 (two config fields, the trust
  model), CTR-PQZ-29 (a fee change invalidates built statements), CTR-TOK-25 (the `TokenConfig` encoding moves for every kind),
  CTR-GOV-15 (the router's closed table gains `mtxSetVerifierFee`), CTR-AS-25 (the verifier fee leg on 12, 13), NODE-JOB-22
  (`pqz_fee`, `PQZ_FEE_MISMATCH`).
- **`contracts/pq-zero-knowledge.md`** (T11): §9.5 (the CTR-PQZ-27 table gains the two fields; the trust model; the rule
  **CTR-PQZ-36** written after CTR-PQZ-30 as the normative text, `decisions.md` keeping the ruling), CTR-PQZ-06's fee bullet ("two
  fees" → `txFee`, `verifierFee` on `OFFCHAIN`, `decoyFee`), CTR-PQZ-17 (the range row), §7.1's token globals, §7.4 and §7.5's
  effects (the verifier's payout), §7.8 (`fee` = `txFee + verifierFee + M·decoyFee`), CTR-PQZ-29 (§5.3's sentence), §9.4 (the
  setter, the view's fields), §12 (T28–T33), §14 (the tests).
- **`integration.md`** (T11): `#pqz-offchain-checks` (the fee, the cap, a pending increase; re-prove after a change), the error
  table (`PQZ_FEE_MISMATCH`), the confidential-money row's fields.
- `clients/app.md#pqz-verifier-display`, `clients/signers-clientkeys.md#pqz-verdict-clients` (the helper, the router type; the
  "builds the creation fields" sentence checked against the code, which has no `TokenConfig` encoder), the node docs of §10, the
  verifier's of §11, `contracts/token-wrappers.md` (the module table's Q and S rows gain `setVerifierFee`).

## 15. Tests (red first) and mutants

Red first, each before its code; every negative with its positive control (the same call at the current fee, with the fee 0, or
by the admin, passes):

1. **Init** (`test/pqz/PqzVerifierFee.t.sol`, the OFFCHAIN fixture `PqzOffchainBase`): `PRECOMPILE` with either field set
   `PqzVerifyConfigInvalid`; `verifierFee > verifierFeeMax` `VerifierFeeAboveMax`; the range row with the cap, each term alone at
   the boundary `BadInit` and one below it passing; kinds 0, 1, 8, 9 and 2, 3, 10, 11 with either field `ConfigFieldForOtherKind(4)`.
2. **The fee word**: every form of §5.1's table, the statement view's word 256 is `txFee + vf (+ M·d)`, `vf` once on op 7; with
   `beneficiaryUA = 0` it is `vf (+ M·d)`; the `PRECOMPILE` statement bytes equal today's vectors; a `PRECOMPILE` debit reads no slot
   20 (`vm.record` accesses).
3. **Payment**: per form, the verifier's balance `+vf·s` (a native verifier's ERC-20 balance; a derived one's ledger balance, its
   first payout from 0; an `msig`), the beneficiary `+txFee·s`, each leg `+d·s`, the recipient `+amount·s`, the pool `−(fee +
   amount)·s + shieldIn·s`, `totalShielded` likewise in units, `totalSupply` unchanged (unwrap: `−amount·s`); the payee is the
   current verifier while a verifier transfer is pending; `vf = 0` moves nothing to the verifier.
4. **Setter**: a decrease at once (`VerifierFeeSet`), to 0; an increase proposes (`VerifierFeeProposed`, `eta`); a confirm before
   `eta` `VerifierFeeNotReady`, inside the window applies, after `eta + noticePeriod` is a new proposal; after an admin change the
   pending is dead; another caller's confirm `NotProposer`; `> verifierFeeMax` `VerifierFeeAboveMax`; the current value
   `VerifierFeeSame`; another increase while one is live `VerifierFeePending`; a decrease while one is live cancels it and emits only `VerifierFeeSet`,
   the old `eta` no longer confirms; notice 0 applies
   at once with both events; a fixed verifier's fee changes; `PRECOMPILE` `PqzVerifyConfigInvalid`; a stranger `NotAdmin`; through
   the router at fee 0 by a stranger relayer; `verifierFeeMax` never moves (I-V1); the view's four fields, a dead pending as 0.
5. **A built op after a change**: refuses `AuthRejected`, and with a re-signed `pqzAuth` `PqzVerdictMismatch(3)`; the same op at
   the unchanged fee passes.
6. **Disclosure**: `verifyTransferAmount` (both forms) moves no balance.
7. **Regulated** (12, 13): a frozen verifier `FeeRecipientFrozen`, a `KYC`-ineligible one `NotEligible`, a denied one (3s)
   `Denied`, each only while `vf ≠ 0` (positive control: the same token at fee 0 passes); the check runs before `_pullShieldIn`.
8. **Invariants (controller A3)**: `test/pqz/invariant/PqzFeeInvariants.t.sol` over `PqzFeeHandler.t.sol`, on a `PRECOMPILE` and an
   `OFFCHAIN` kind 4 token and an `OFFCHAIN` kind 5 token, three holders: shields of any amount into any holder, op 1 and op 7 (with
   and without a beneficiary, `d ≥ minDecoyFee`), burns, refreshes and unwraps, each with a random `shieldIn` top-up, and fee
   changes (decrease, propose, warp, confirm); amounts drawn across the sender's ghost hidden balance. Proofs are mocked under an
   honest model: the precompile mock (`PRECOMPILE`) and the handler's verifier key (`OFFCHAIN`) accept a debit only when the ghost
   `T ≥ v + fee` (or `amount + fee`). **F1** `balanceOf(SHIELD_POOL) == totalShielded · shieldScale` after every call; **F2**
   `totalShielded == Σ` ghost hidden balances; **F3** `Σ` public payouts (beneficiaries, verifier, legs, recipients, unwrap burns)
   `== Σ (fee + amount) · s`, and `Σ shields + Σ shieldIn − Σ (fee + amount) == totalShielded`; **F4** `totalSupply` moves only by
   wraps, mints and unwraps; **F5** no debit landed with ghost `T < v + fee` and every such attempt reverted; **F6** each landed
   debit's fee word equals `txFee + vf_now (+ M·d)`; and the contract's own: **I-V1** `verifierFeeMax` never moves, **I-V2** a
   `PRECOMPILE` debit reads no slot 20 and its `verifierFee` stays 0, **I-V3** no payout of `vf ≠ 0` to the zero id. A long run: 64 runs × depth 128 at the default set, the four sets through
   `at-set.sh` in the gates.
9. **Real proofs** (`pqz-core/ffi/tests/fee_word.rs`, PQZL, and PQZH where the set builds it): op 1, op 7 `M = 2`, burn, refresh
   proved at `fee = txFee + vf` verify `01`; the same proofs at `fee ± 1` verify `00` (a fee change kills a built proof); an
   overspend witness (balance `< v + fee`, `d'` wrapped) verifies `00`: a sender out of hidden balance cannot transact, in
   `PRECOMPILE` mode by the proof, in `OFFCHAIN` mode by the honest verifier (`VERDICT_ZERO`, §11).
10. **Node**: `pqz_fee` required and decoded, the pre-check with every term, `PQZ_FEE_MISMATCH` at intake and in the lane,
    `AuthRejected` after an indexed `VerifierFeeSet` mapped and queued, the router row both ways, the indexer rows and the alert;
    e2e `pqz_offchain_transfer_on_anvil` with a fee (the verifier's balance after).
11. **Verifier service**: `FEE_WORD_MISMATCH` with its control; `VERDICT_ZERO` on the overspend proof.
12. **Pins**: layout (§4), `UASetVerifierFee` typehash, the interface id, `selector_audit.json`, the router's binding matrix
    (`next`), digests reproduced by clientkeys and ua-rs.

| # | Mutant | Caught by |
|---|---|---|
| M1 | `_common` leaves `vf` out of the word | (2), F6, `verifier_fee.json` |
| M2 | `vf` read on `PRECOMPILE` (slot 20 unconditionally) | (2)'s access test |
| M3 | op 7 adds `vf` per leg | (2) op 7 rows |
| M4 | the beneficiary gets `fee − M·d` (the verifier's share too) | (3), F3 |
| M5 | the verifier is paid twice, or not at all | F1, F3, (3) |
| M6 | the payee is the beneficiary, or the pending verifier | (3) |
| M7 | the range row checks `verifierFee`, not the cap | (1) (a fee below and a cap above the boundary) |
| M8 | init accepts `verifierFee > verifierFeeMax` | (1) |
| M9 | `PRECOMPILE` init or setter accepts a non-zero fee | (1), (4) |
| M10 | a Zether or plain kind accepts a field | (1) |
| M11 | a decrease waits, or an increase applies at once with a notice | (4) |
| M12 | the confirm skips the proposer, the generation or the window | (4) |
| M13 | a decrease leaves the live pending | (4) |
| M14 | the setter skips `VerifierFeeAboveMax` | (4) |
| M15 | the setter refuses a fixed verifier's token | (4) |
| M16 | `verifyTransferAmount` pays | (6) |
| M17 | 12, 13 skip the verifier's check, or check it at `vf = 0` | (7) |
| M18 | `verifierFeeMax` written by the setter | (4), I-V1 |
| M19 | `Paid.verifier` 0 with `vf ≠ 0` (a burn of `vf·s` to address 0) | F4, (3) |
| M20 | `pqzVerifyConfig` shows a dead pending | (4) |
| M21 | refresh or migration exempt from `vf` | (2), (3) |
| M22 | `_regName(verifier)` after `_pullShieldIn` or after the library | (7) (the order test) |
| B1 | `next` dropped from `UASetVerifierFee` | the binding matrix |
| N1–N3 | the node skips the pre-check, leaves `vf` out of `expected`, or reports `AuthRejected` after a fee change `dead` | (10) |
| V1 | the verifier service skips `FEE_WORD_MISMATCH` (only `STATEMENT_MISMATCH` left) | (11), by name |

Gates: every `forge` directory and the node e2e (shared change: the `TokenConfig` encoding of every kind),
`script/pqz/at-set.sh <set> test` at the four sets, the size gate, layout, ABI, gas pins (old → new in the commit), `cargo test` +
`clippy -D warnings` for the node and the verifier service, clientkeys, ua-rs and zether-prover tests, `pqz-core/ffi` tests (not
the full gate), the local matrix run.

## 16. Gas and size [estimates; measured in T9]

**Gas.** Anchors [measured, T50, `n2304-kmax4096`]: an `OFFCHAIN` op 1 with the auditor 22,993,020, an unshield 22,410,810.

| Op | Today | 3t |
|---|---|---|
| `OFFCHAIN` debit, `vf ≠ 0`, the verifier's balance exists | as above | + ≈ 2.1 k (slot 20 cold) + ≈ 10–15 k (one pool move with its events) ≈ +0.07 % |
| `OFFCHAIN` debit, the first payout to a verifier | — | + ≈ 98 k state gas once (a new balance slot, ERC-20 or ledger; the Zether leg payout measured 116,698 in all under Amsterdam, F185) |
| `OFFCHAIN` debit, `vf = 0` | — | + ≈ 2.2 k (slot 20 read), no move |
| `PRECOMPILE` debit | — | + ≈ 0.1–0.3 k (warm mode reads, two `Paid` words, zero-unit no-ops); every PQZ gas pin moves old → new |
| 12, 13 with `vf ≠ 0` | — | + the verifier's `_feeRecipient`: ≈ 2.1 k (freeze slot) + one registry call (≈ 8 k) under `KYC` + ≈ 2.3 k under a list (3s) |
| `setVerifierFee`, a decrease | — | ≈ 30–40 k direct; + the router's verification relayed (ECDSA ≈ +30 k, `mldsa65` more) |
| `setVerifierFee`, a proposal | — | ≈ 0.1–0.2 M (the proposer slot new: ≈ 98 k state; slot 20 rewritten); a confirm ≈ 30–40 k plus refunds |

`MtxSplitOverhead.t.sol`'s bounds (PQZL 99,000, PQZH 335,000) and `PQZ_DEBIT_MIN_GAS` keep their margin (two `Paid` words are tens
of gas); the plus-zero rows do not move (public paths only).

**Size.** Q of kind 12 (`NormalPqzRegulatedTokenQ`) measures 32,423 B [measured, `size-baseline.json`] against the module notice
line 33,780 B (57 M) and the stop line 35,570 B (60 M): 1,357 B before 3s; 3s estimates ≈ 32.8 KB after it, ≈ 0.9 KB left
[estimate, spec 3s §14]. 3t adds to Q on 4 and 12: the entry `setVerifierFee` (≈ 0.2–0.25 KB: dispatch, the `uint64` decode, the
guard, the library call), `pqzVerifyConfig`'s four words (≈ 0.1 KB), the payout (`Paid`'s two words, three `_fromPool` sites, three
subtractions, `verifierPayee` and its three calls ≈ 0.25–0.35 KB): **≈ +0.5–0.8 KB** [estimate], so **Q(12) ≈ 33.3–33.6 KB, ≈ 0.2–0.5
KB under the notice line**; Q(4) 30,641 → ≈ 31.2–31.5 KB. On 5 and 13 the entry and the view go to S (18,216 / 19,038 B, +≈ 0.3 KB)
and Q gets the payout only (28,405 / 29,490 B, +≈ 0.3 KB). `PqzStateLib` +≈ 0.6–0.9 KB (the rows, the setter, the view), each of
`PqzTransferLib` (24,456 B), `PqzBurnLib` (15,404 B), `PqzViewLib` +≈ 0.1–0.2 KB (`_common`, `Paid`), `GovernanceRouter` +≈ 0.1 KB
(3f's three router ops measured +304 B), every kind's A +≈ 40–80 B (the `TokenConfig` decoder, `_requireUnused`), `ZetherLib` +≈ 30
B; the libraries' lines are 33,903 / 35,694 B. Code-hash pins move only for the contracts 3t changes: every token kind (its
`TokenConfig` decoder), the PQZ libraries and the router, old → new in T9; with the `MetaTxLib.sol` comment out of 3t (controller
call 4) no other artifact's metadata hash moves.

**Lever.** None of `docs/research/evm-size-levers.md`'s levers is needed [estimate]: they answer the old 64 KiB token limit, and
Q(12) stays under its notice line. If T9's measurement after 3s passes 33,780 B at any set, the ruled split applies
(CTR-TOK-30, owner 2026-11-09: Q into Q and S on 4 and 12, as built on 5 and 13), not a new lever; a baseline row moves only with
its reason.

## 17. Tasks (after 3s merges)

| Task | Content | Estimate |
|---|---|---|
| T0 | The round's gate script (per-step logs, resume, progress lines), mutant harness, summary header | 0.25 d |
| T1 | Red tests §15 (1)–(7), the typehash pin, the layout rows, `PqzFeeHandler` skeleton | 0.75 d |
| T2 | Contracts: `IFactoryToken` fields; `PqzStateLib` (init rows, `setVerifierFee`, `_feeLive`, `_setFee`, the view); `PqzCore` (storage, `Op.verifierFee`, `_common`, `Paid`, `_paid`, `verifierPayee`); `PqzLayer` (`_single`, `_multi`, `_burn`); `MetaTokenBase`, `ZetherLib`; `IPqzToken` (entry, struct, errors, events); the module stubs (`entries.json`, `gen_faces.py`, Q on 4, 12, S on 5, 13); the router op | 1.5 d |
| T3 | §15 (1)–(7) green, the router's binding matrix, B1 | 0.75 d |
| T4 | §15 (8) invariants F1–F6, §15 (9) `pqz-core/ffi/tests/fee_word.rs` | 1 d |
| T5 | Vectors and clients: `verifier_fee.json` and its writer, `typed_ops.json`, `selector_audit.json` by hand, the two `state.json`; clientkeys, ua-rs (`pqzfee.rs`), zether-prover; `e2e.py`, `pqz_kat.py`; the 19 `ConfidentialConfig` sites and the scripts; generated and pinned files (`face_abi.json`, `test/v2/module-opcodes.json`, `test/modules/Groups.t.sol`, `Modules.t.sol`, the link-closure rows) | 1 d |
| T6 | Node: `typed.rs`, `guard.rs` (row, count, `pqz_fee`), `pqz.rs` (pre-check), `submit.rs` (the mapping), `abi.rs`, `indexer.rs`; e2e; `cargo test`, `clippy` | 1.25 d |
| T7 | `scaas-pqz-verifier`: the struct, `FEE_WORD_MISMATCH`, tests | 0.5 d |
| T8 | Matrix: `pq.py` group `pqoff` (§13), `coverage.py gen`, local run | 0.75 d |
| T9 | Gates and pins: every forge dir, the four PQZ sets, size (the lever decision of §16), layout, ABI, gas old → new, the interface id, node and verifier e2e | 0.75 d |
| T10 | Mutants M1–M22, B1, N1–N3, V1, log | 0.5 d |
| T11 | Docs: `pq-zero-knowledge.md` (CTR-PQZ-36's text, §9.5, the fee bullet, CTR-PQZ-17, §7, §12, §14), `integration.md`, `clients/*.md`, the node docs, `token-wrappers.md`'s module table; `docs_check` | 0.5 d |
|  | **Total** | **≈ 9.5 d** |

## 18. Controller calls (2026-11-11, on `727eec7a`, under the owner's leave of 2026-11-10)

No open question is left. The controller decided the three the spec raised, and one scope change; each is applied where named.

| # | Call | Applied in |
|---|---|---|
| 1 | **Unit.** `verifierFee` and `verifierFeeMax` are in shielded units, like `confidentialFee` and the fee word; the payout is `verifierFee · shieldScale` public units. This restates the ruling's "public units" precisely and does not change it | §3.1, `decisions.md` |
| 2 | **Init range.** `confidentialFee + verifierFeeMax + 8·minDecoyFee < 2^64` and `< maxShielded`, with the cap, so the setter checks only `next ≤ verifierFeeMax` | §3.3, test (1), M7 |
| 3 | **A decrease during a pending increase** cancels the pending: `VerifierFeeProposed` is superseded, `VerifierFeeSet(previous, next)` is emitted | §7.1, test (4), M13 |
| 4 | **The `MetaTxLib.sol` comment fix leaves 3t**: a separate one-pass cleanup of the Vietnamese comments in `smartcontracts/evm/src` and `scaas-node/src`, put in TODO by the controller | §1 R5, §15, §16, §17 |

Kept as written (controller, the same day): `AuthRejected` comes before `PqzVerdictMismatch(3)` on a built op after a fee change,
mapped to the node's `PQZ_FEE_MISMATCH` and the verifier service's `FEE_WORD_MISMATCH` (§5.3, §10, §11); a fixed verifier's fee
can still change, and admin 0 freezes the fee (§7.1).
