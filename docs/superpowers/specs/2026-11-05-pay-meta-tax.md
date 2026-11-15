# Payment metadata, free pay lanes and tax on the regulated kinds (group 3e) — design

**Status:** **approved by the owner 2026-11-06.** **BUILT** on branch `ua-mtx-merge`, T37–T43 (UNAUDITED; `payNo` as
`bytes32`, `save` and the pay records by plan T83). PT-1 is CTR-MTX-31, PT-4 CTR-AS-18, PT-5 CTR-AS-19, PT-6 CTR-GOV-21, PT-7
ARCH-POS-17 (the proposed ARCH-POS-13 is taken), PT-2 / PT-3 Changes of CTR-MTX-26 / -27 (T19). The section tags below are the
design's. Revised after the Codex and Fable reviews of the first draft
([Codex](../../research/paytax-codex-review.md): 4 medium, 3 low, 1 info; [Fable](../../research/paytax-fable-review.md): 0 P0,
3 P1, 14 P2, 12 P3, addendum A-1, B-1…B-6) and the owner's rulings O8–O18 of 2026-11-05 and 2026-11-06; every finding's outcome is in §17.
Work-order group **3e** of branch `ua-mtx-merge`: tasks **T37–T43** after T36 (regulated kinds) and before 3c (`PqChat` and the
registry generation), so the round's docs (T19), review (T22) and PR (T23) cover it and the EVM freeze and audit include it.
`payNo` is confirmed (O15); P-1 and P-2 were accepted (O13) and P-3 rejected (O12); every question is answered (O16, O17, §11).

**Rules this spec applies, not reopens:** [CTR-MTX-30](../../contracts/metatx.md#CTR-MTX-30) (one signed entry per operation, `UASig`
last, the merged `mtx*` names), [CTR-MTX-29](../../decisions.md#ctr-mtx-29--every-parameter-is-explicit) (explicit
parameters), [CTR-MTX-23](../../contracts/metatx.md#CTR-MTX-23) (the typed path `UAMetaTransfer`),
[CTR-MTX-13](../../contracts/metatx.md#CTR-MTX-13) (fee modes, ppm, 1 % cap), [CTR-MTX-08](../../contracts/metatx.md#CTR-MTX-08)
(the fee never goes to the payee), [CTR-MTX-05](../../contracts/metatx.md#CTR-MTX-05) / [-06](../../contracts/metatx.md#CTR-MTX-06)
(receiver-pays), [CTR-MTX-27](../../contracts/metatx.md#CTR-MTX-27) (relay fee); the regulated-kinds spec
[2026-11-05-regulated-kinds.md](2026-11-05-regulated-kinds.md) (RK-1 … RK-11, the roles `issuer` and `compliance`, the hooks of
§2.2, the fee-leg rule RK-6, the size method of §6.2); [CTR-GOV-10](../../decisions.md#ctr-gov-10--bit-bands-0-127-one-meaning-128-255-per-application-none-refused)
(bit bands), [CTR-GOV-14](../../decisions.md#ctr-gov-14--bits-13-and-14-stay-unallocated-a-party-fixed-at-creation-holds-no-bit-no-tender-rescue)
(bits 13 and 14 never reused), [CTR-GOV-03](../../decisions.md#ctr-gov-03--a-plain-transfer-stays-0-one-regulated-implementation-per-kind-never-per-feature)
("+0" on a plain transfer). Where a ruling changes one of these, the change is listed in §10 for a `decisions.md` Change line in
T19; nothing is resolved silently.

## 0. Owner rulings, controller calls, proposals (2026-11-05)

### 0.1 Owner rulings

Written as given; not reopened. O8–O18 replace what O6 and O7 said where they differ (kinds, holder, classes, empty metadata, money flow).

| # | Ruling | Where |
|---|---|---|
| O1 | Pay functions are special: they connect to external sales and ERP systems. `entryRef` plus the metadata is the reconciliation key. | §1, PT-1 |
| O2 | Metadata is a parameter, the **last** one, on every pay entry: `mtxPay`, `mtxPayReceiverFee`, `payWithFee`, `payWithFeeToUA` and the new `mtxPayWithTax`. One entry per operation: `mtxPayMeta` / `uaPayMeta` go to `legacy/` (backup, not delete). The signed entries take `UAMetaTransfer t` as a struct (the legacy ABI decoder, `via_ir` off, has too few argument slots for the flat form): `mtxPay(UAMetaTransfer t, UASig auth, PayMeta meta)`. | §2, §3 |
| O3 | A `payId` may be paid many times (partial payments); whether an invoice is fully paid is decided off chain. `payLane(payId)` with nonce 0 is dropped for pay: pay uses free `batch` / `nonce` exactly like transfer. A client may still choose a lane; the contract does not care. | §2.2 |
| O4 | `mtxRelayFee` / `MtxRelayFee.relay`: free `batch` / `nonce` too (`UARelayFee` gains `batch`, `nonce`, a new typehash). The payer may dedicate a lane to relay fees (for example lane 2). The contract does not stop paying twice for the same call: that is the payer's decision. `ref` stays the payment reference. | §4 |
| O5 | Invoice numbers on chain: **not recommended, a warning only, not a ban.** They may go in the metadata. `docs/architecture.md` §10 item 1 and the four-condition test change from "never" to a recommendation (§9). Wallets warn when a clear metadata is signed; schema 4 is recommended for private data. Factual point: the transaction carries `from` / `to`. | §3.3, §9 |
| O6 | Tax on regulated kinds (kinds: O8). Separate entry `mtxPayWithTax(UAMetaTransfer t, uint8 taxMode, uint256 tax, UASig auth, PayMeta meta)`. Modes PERCENT and AMOUNT. AMOUNT: `tax` is the total of the invoice's taxes, computed by the ERP, signed by the payer, accepted as signed. PERCENT: `tax == rate × amount` (rounding rule defined here) else `TaxMismatch`; the notice period on an increase, immediate on a decrease, **only** for the PERCENT rate. Money flow: payer → payee `amount`, then payee → `taxRecipient` `tax` (replaced by O13's direct split); the payee nets `amount − tax`; `tax ≤ amount`; the payer's fee as in `mtxPay`. `taxRecipient` is a UA (`bytes32`) configured in the token (issuer via governance), credited through the UA ledger, pools and the token refused, RK-6 on the tax leg. A governance feature bit `TAX` in the SCaaS band; the existing roles, no new role. The tax logic in a library; size impact estimated. | §5, §6 |
| O7 | (1) A payee with a tax class still receives through `mtxPay`, transfers, `payWithFee` and receiver-fee: no entry is blocked. (2) The payer does **not** sign `taxRecipient`: it is configured in the token as a UA `bytes32` and the contract reads it there; the signed struct is `UAPayWithTax(UAMetaTransfer payment, uint8 taxMode, uint256 tax)`; wallets read the recipient from the token for display. (3) `payNo` in `PayMeta` in place of schema 2's `invoiceNo` (§3.1; confirmed by O15). | §3.1, §5 |
| O8 | Tax applies to **every regulated kind 8–13**, Zether and PQZ included. Tax concerns public balances, not hidden amounts: on 10–13 `mtxPayWithTax` moves public balances, and confidential (proof) transfers carry no tax leg. `requireConfidentialSafe` does not apply to a PERCENT tax on a public pay (Fable B-3). The hook seats are the existing `_uaExecuteTransfer` / `_uaMove` (B-2). Node rows cover each contract class × the six kinds (B-4). Kind 13 is measured first in T40, with the stop rule and the levers (B-1). | §5.1, §6.4, §7.1 |
| O9 | Bit 23 `TAX` may be held by an **EOA, an `msig` or a contract**; it is not in `_contractOnlyBits()`. With an EOA holder beside a contract issuer, a `grantRole` after creation is needed (Fable A-1). | §6.1 |
| O10 | **No tax classes.** PERCENT uses **one token-wide rate**: an increase waits the notice period, a decrease is immediate. `taxClass`, `setTaxClass`, `TaxClassSet` and the per-class rate are removed. | §6.2 |
| O11 | **No empty `PayMeta`.** Every pay entry always carries `PayMeta` with a non-zero `salt`; `payNo` may be empty and `body` may be empty. `entryRef` is always required and always equals the commitment of the given `PayMeta`; the "empty metadata accepts any `entryRef`" branch is gone. `PaymentMeta` is always emitted, so a relayer cannot strip the metadata from a pay entry. Private data uses schema 4 (encrypted body). No `META_PUBLISH` bit. | §3 |
| O12 | **P-3 rejected.** The generic transfer paths `mtxExecuteTransfer` and `mtxBatchTransfer` keep accepting `entryRef ≠ 0`; they are not blocked, because reconciliation can still be done off chain. Consequence: a payment signed for a pay entry can still land through the generic path without `PaymentMeta`; the ERP then reconciles off chain from `entryRef` and the preimage it keeps. The node still sends pay jobs through the pay entries (F-10). | §2.3, §7.1 |
| O13 | **P-1 and P-2 accepted.** P-1: the tax is split directly by the payer: payer → payee `amount − tax` and payer → `taxRecipient` `tax`. P-2: a direct `payWithTax` (no meta-tx) for contract payers such as `MandateWallet`, symmetric with `payWithFee`. | §5.3, §5.6 |
| O14 | (2026-11-06) **Router open mode for the relay fee stays as it is on the regulated kinds 8–13 too** (CTR-MTX-27 unchanged); the first revision's call that refused open mode there, and its extra hook, are withdrawn (the calls below are renumbered). | §4.1 |
| O15 | (2026-11-06) **`payNo` confirmed as written:** `PayMeta { salt, payNo, schema, body }`, `payNo` optional, schema 2 without `invoiceNo`; the bound is **256 bytes** (owner correction 2026-11-06, superseding the 64 bytes first written). | §3.1 |
| O16 | (2026-11-06) **Q3, Q4, Q5, Q7, Q8, Q9 and Q10 decided as recommended** (§11): floor rounding; recipient change immediate; bit 23 not delay-relaxed; `PayMeta.body` stays `bytes` on chain; no pay on the mesh in this group; the factory's `noticePeriod()`; the legacy copy of `paymeta.json` with the non-EVM consumers repointed. | §11 |
| O17 | (2026-11-06) **Q-M deferred:** a taxed mandate payment (`MandateWallet` calling `payWithTax`) is a later wallet item, not this group. | §5.6, §11 |
| O18 | (2026-11-06) **A kind that crosses 65,536 B is reduced, never admitted above the line:** the `_above64KiB` row is not an accepted fallback for kind 13 or any regulated kind. T37 and T40 measure kind 13 first; at or above the stop line the task applies the ordered levers of §6.4 until the kind fits, re-measuring after each, and goes back to the controller only when every lever is exhausted. | §6.4 |

### 0.2 Controller calls (2026-11-05, owner may override)

| # | Call | Where |
|---|---|---|
| C1 | The commitment tag is versioned: `"scaas.pay.meta.v2"` (Codex #8, Fable F-12); the consumer count is corrected | §3.1, Q10 |
| C2 | The node's signer and digest for `UAPayWithTax`: the payer signs; the outer digest is the job identity and the execution match (Codex #1) | §7.1, T42 |
| C3 | Dropping invoice pay-once does not drop the nonce-lifetime safeguards of the pruning families (Codex #3) | §2.2, §8 |
| C4 | The privacy wording states three separate properties (Codex #6) | §3.3 |
| C5 | `MandateWallet` and `HederaMandateWallet` are callers of the direct pay entries: wallet, tests, KAT, CREATE2 address and node rows in T37 and the operator note (Fable F-01) | §2.4 |
| C6 | The reconciliation formula for taxed payments and the indexer join (F-02); `PaymentTaxed` carries `from` (F-05); the entry the node sends is named (F-10) | §5.4, §7.1 |
| C7 | An in-flight PERCENT payment fails `TaxMismatch` when the rate changes; ERPs use AMOUNT; an ops note and a test (F-04, F-06) | §5.5 |
| C8 | Sizes and estimates updated (F-13, F-14) | §6.4, §15 |

### 0.3 Proposals of the revision (answered by the owner, kept for the record)

| # | Proposal | Where |
|---|---|---|
| P-1 | **Accepted (O13).** **Direct split from the payer:** payer → payee `amount − tax` and payer → `taxRecipient` `tax`, not through the payee (Fable F-07). The payee still nets `amount − tax`; the ledger shows the payer as the withholding agent; a frozen payee does not block the tax leg; no `_poolMove` is needed. | §5.3 |
| P-2 | **Accepted (O13).** A direct `payWithTax` (no meta-tx) for contract payers such as `MandateWallet`, symmetric with `payWithFee` (F-11). | §5.6 |
| P-3 | ~~The generic transfer paths refuse `entryRef ≠ 0`~~ — **rejected by the owner (O12)**; kept here for the record. | §2.3 |

## 1. Scope and non-goals — SPECIFIED

**In scope (EVM; Hedera with the EVM code on kinds 0–9, so tax on 8 and 9 only there, B-6):**

| Item | Rule |
|---|---|
| `PayMeta` on the five pay entries, every token kind 0–13, and on the mandate wallets' pay entries | §2, §3; one pay entry per operation; `mtxPayMeta` and the flat `mtxPay` to legacy |
| Free `batch` / `nonce` on every pay entry and on the relay fee | §2.2, §4 |
| The commitment `metaPayId` with `payNo` (O15) under the tag `scaas.pay.meta.v2` | §3.1; `paymeta.json` regenerated |
| `mtxPayWithTax` and the direct `payWithTax` on kinds 8–13 (public balances, O13) | §5 |
| Bit 23 `TAX`, two powers and two router ops | §6 |
| Vectors, `clientkeys`, `ua-rs` and wrappers, `zether-prover`'s relay-fee builder, node rows, jobs, indexer, gateway | §7 |
| Doc changes, including `architecture.md` §10 and the four-condition test | §9 (written in T19) |

**Non-goals.** No change to `UAMetaTransfer`, `UAReceiverFee`, `relayRef` or any Zether or PQZ statement, transcript, binding tag
or `proofSystemId`. No tax leg on a confidential (proof) transfer, shield or unshield (O8): no site in `ZetherLayer`,
`PqzLayer` or their libraries changes (Zether ≠ PQZ stays untouched). No on-chain check of an AMOUNT-mode tax. No on-chain
notion of "invoice fully paid" (O3). No blocking of any entry to any payee (O7(1)). No non-EVM contract change here (§8). No
migration: every chain is test-only; the SCaaS testnet takes this at reset 2 with the rest of the branch.

**PT-1 (O1).** The pay entries are the interface to external sales and ERP systems. A payment is found by the key `(token,
payer, payee, entryRef)` ([CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10)); every pay through a pay entry carries its `PayMeta` on chain (O11); one landed through the generic path is
reconciled off chain from `entryRef` and the kept preimage (O12).
Amounts of one key add up (gross for untaxed rows, §5.4 for taxed rows); the ERP decides when a document is settled. A refund
is a new payment payee → payer with the same `entryRef` and `PayMeta`; the key includes the direction, so it never adds to the
original sum (Fable "missing" 14). `payNo` is compared byte for byte: there is no normalisation on chain.

## 2. The pay entries — SPECIFIED

### 2.1 One entry per operation

| Entry (after) | Signed struct | Gate | Replaces (to `legacy/ua-mtx-merge/`) |
|---|---|---|---|
| `mtxPay(MetaTxLib.UAMetaTransfer t, IUARegistry.UASig auth, PayMeta meta)` | `UAMetaTransfer` (unchanged typehash) | `PAYABLE` | flat `mtxPay(bytes32 from, …, bytes32 payId, …)`, `mtxPayMeta`, `_uaPayMeta`, `_uaPay` |
| `mtxPayReceiverFee(UAMetaTransfer t, UASig payerAuth, uint256 fee, address feeRecipient, uint256 rfValidUntil, UASig payeeAuth, PayMeta meta)` | payer `UAMetaTransfer`, payee `UAReceiverFee` (both unchanged) | `PAYABLE`; shape of §2.5 | today's body (lane / nonce shape) |
| `payWithFee(address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef, PayMeta meta)` | none (direct, the caller's own transaction) | `PAYABLE` | today's six-argument form |
| `payWithFeeToUA(bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef, PayMeta meta)` | none (direct) | `PAYABLE` | today's six-argument form |
| `mtxPayWithTax(UAMetaTransfer t, uint8 taxMode, uint256 tax, UASig auth, PayMeta meta)` (kinds 8–13) | `UAPayWithTax` (new, §5.2) | `PAYABLE`, `TAX` | — (new) |

- `PayMeta` is the **last** parameter on each (O2) and is never empty (O11). Each entry calls `_payMeta(entryRef, meta)` (§3.2)
  right after its gates, before any signature check; `PaymentMeta` is emitted before the payment's events.
- Argument slots with `via_ir` off: `mtxPay` 3, `mtxPayWithTax` 5, `mtxPayReceiverFee` 7, `payWithFee*` 7. These are paper
  counts: T37 measures each and, if the legacy decoder runs out of stack, the entry takes its non-signed tail as one named struct
  (the `RelayPay` fallback of §4; F-23).
- `mtxTransfer`, `mtxTransferWithFee` are not pay entries and do not change.
- `payLane(bytes32)` **stays** as a pure view: a client may still use the old lane as its own convention (O3), and an API is not
  dropped because nothing calls it. Its NatSpec says "a client convention, not enforced".
- Interfaces: `IMetaTokenV2` (pay entries, `metaPayId`, `PaymentMeta`), `IERC20Payment` (`payWithFee`) and `IERC20MetaTx`
  (`mtxRelayFee`) change, so their ERC-165 ids move; `supportsInterface` answers the new ids.
- Gas pins: `MetaTxGasV2`'s `mtxPay` and `mtxPayMeta` rows (CTR-MTX-11's figures) move old → new in T37's commit (F-26).

### 2.2 Free lanes (O3)

Every pay entry consumes `(t.from, t.batch, t.nonce)` exactly as `mtxExecuteTransfer`: the nonce space of
[CTR-UA-26](../../contracts/accounts.md#CTR-UA-26), one lane per `(from, batch)`. Nothing ties `batch` or `nonce` to `entryRef`.

- One `entryRef` may be settled by several payments, on any lanes; each carries the same `PayMeta` (its commitment is the
  `entryRef`), so each emits `PaymentMeta` and every receipt is self-describing (F-16; one log per payment).
- The contract no longer gives "each request payable at most once". A client that wants it signs on `payLane(entryRef)` with
  nonce 0 (the old convention, now off chain).
- A payment signed twice is paid twice if both are submitted: two signatures, the payer's own choice. One signature never lands
  twice (the nonce).
- **Nonce lifetime is not invoice pay-once (C3, Codex #3).** On EVM the nonce map is persistent. On a family that prunes lane
  state (Sui, Aptos, Solana, TON), forgetting a lane forgets which nonce slots were consumed: two alternative signatures on one
  `(lane, nonce)` with different expiries become sequential after a prune. Dropping invoice pay-once therefore does **not** drop
  the signing horizon and retention rules of [CTR-MTX-04](../../contracts/metatx.md#CTR-MTX-04)'s table for those families
  (NET-ALL-01, NET-APT-24, NET-SOL-22, NET-SOL-25, NET-SUI-12, NODE-STO-01): they stay, keyed on every lane, until the family's
  own round specifies persistent generations, tombstones or another complete replay answer (§8).

### 2.3 The generic transfer path (O12)

`mtxExecuteTransfer(t, auth)` and `mtxBatchTransfer(ts, auths)` stay as they are: any `entryRef`, no metadata, never gated
([CTR-MTX-23](../../contracts/metatx.md#CTR-MTX-23), [CTR-MTX-24](../../contracts/metatx.md#CTR-MTX-24)); Tender's deposit
shape and the node's batches keep them. **Consequence, stated plainly (O12):** the `UAMetaTransfer` a payer signs for `mtxPay`
is the same struct, so anyone holding it can land it through the generic path, without `PaymentMeta` and without the `PAYABLE`
gate; the nonce is consumed and the log cannot be added later. The payment is still found by its key `(token, payer, payee,
entryRef)`, and the ERP reconciles it off chain from `entryRef` and the `PayMeta` preimage it keeps (it built the commitment).
A payer that needs the log on chain submits through a node that keeps the rule of §7.1 (a pay job is sent only as its pay
entry). `mtxPayWithTax` and `mtxPayReceiverFee` sign their own outer structs, so their payments cannot take the generic path.
Codex #7 and Fable F-03 are closed by owner ruling for this path (O11 closes them for the pay entries).

### 2.4 Callers of the direct pay entries: the mandate wallets (C5, Fable F-01)

`MandateWallet` calls `payWithFee(addr, amount, FeeMode.NONE, 0, address(0), entryRef)` and `payWithFeeToUA(payee, …, entryRef)`;
`HederaMandateWallet` inherits it. With O11 the token requires `entryRef == metaPayId(meta)`, so:

- the wallet's pay entries (`payUnderMandate` and the named `mtxPayUnderMandate(UAEnvelope, …, UASig)`) gain `PayMeta meta` as
  their **last** parameter, unsigned and bound by the signed `entryRef` (the delegate's `UAPayUnderMandate` typehash does not
  change), and pass it to the token;
- the wallet's own `refUsed[entryRef]` (one mandate payment per `entryRef` per wallet) is the wallet's rule and is untouched by
  O3: it is not the token's pay-once;
- T37 moves the wallet, `HederaMandateWallet`, their tests (`MandateWallet.t.sol`, `MandateWalletMerged.t.sol`), the mandate
  KAT, their bytecode and CREATE2 addresses; T42 the node's wallet rows; the operator note says so.

### 2.5 Receiver-pays shape after O3

`mtxPayReceiverFee`'s shape loses `t.batch == payLane(t.entryRef)` and `t.nonce == 0`. It keeps `t.entryRef ≠ 0` (now through
`_payMeta`), payer fee mode `NONE` and `t.fee == 0`, `MODE_RESTRICT_RELAYER` set, `feeRecipient ≠ 0`, `0 < fee ≤ t.value`,
`feeRecipient ≠ t.to`, the token and the pools refused. RP2 (a co-signature takes effect at most once) still holds:
`UAReceiverFee` nests the whole `UAMetaTransfer`, `batch` and `nonce` included, and the payer's nonce is consumed once. The
regulated rule stays (owner 2026-11-05): a frozen payee cannot pay a receiver fee.

## 3. `PayMeta` — SPECIFIED

### 3.1 Shape and commitment

```solidity
struct PayMeta {
    bytes32 salt;    // 32 bytes from a CSPRNG; never 0 (O11)
    string  payNo;   // optional business document number (invoice, order, contract); "" = none; <= 256 bytes
    uint16  schema;  // 0 = no body; 1 note, 2 structured reference, 3 bound call, 4 encrypted (CTR-MTX-26)
    bytes   body;    // the schema's encoding; empty iff schema == 0
}
```

**`payNo` (O15).** The number of the business document the payment settles (an invoice, an order, a
contract), so one document may have several payments (O3), each with the same `payNo`. Typed, optional, bounded at **256 bytes**
of UTF-8 (`PayNoTooLong(uint256 length)`; owner 2026-11-06): room for a composite reference (a series or prefix, a document
number, a line or instalment suffix) and for scripts whose characters take 3–4 bytes in UTF-8; ISO 20022's 35-character
document number (`Max35Text`) fits many times over and is context only. The bound keeps the per-payment cost bounded: at most
256 B of calldata (≈ 4.1 k gas at 16 gas per byte, or the EIP-7976 floor rate) plus 256 B of log data (≈ 2 k gas) and one more
hashed word group per pay entry; wallets wrap a long `payNo` rather than truncate it. A longer text belongs in a schema 1 note or
schema 4. The contract does not check UTF-8; wallets and `clientkeys`
refuse a `payNo` with invalid UTF-8, control characters or bidirectional overrides (display spoofing).

**Commitment** (old → new; C1 versions the tag):

```text
old: payId = keccak256("scaas.pay.meta"    ‖ salt ‖ keccak256(abi.encode(uint16 schema, bytes body)))
new: payId = keccak256("scaas.pay.meta.v2" ‖ salt ‖ keccak256(abi.encode(string payNo, uint16 schema, bytes body)))
     metaPayId(PayMeta m) = keccak256(abi.encodePacked("scaas.pay.meta.v2", m.salt, keccak256(abi.encode(m.payNo, m.schema, m.body))))
```

The new tag makes the two formats disjoint: an old raw `meta` chosen equal to `abi.encode(payNo, schema, body)` no longer gives
the same `payId` (Codex #8), and a client on the wrong formula fails `PayMetaMismatch` by name on every family (F-12). The view
becomes `metaPayId(PayMeta calldata meta) returns (bytes32)`; `metaPayId(bytes32, bytes)` goes to legacy.
`smartcontracts/vectors/metatx/paymeta.json` is **regenerated** by its generator (§7.3).

**Schemas** ([CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26), family-neutral):

| Schema | Body | Change |
|---|---|---|
| 0 | empty: **the value for "no body"** (O11); a `PayMeta` may be a salt alone, or a salt and a `payNo` | new |
| 1 | the raw UTF-8 bytes of a note, non-empty | non-empty required (F-18) |
| 2 | `abi.encode(string creditorRef, uint64 dueDate)`, `dueDate` in Unix seconds | **`invoiceNo` dropped**: `payNo` replaces it (O15) |
| 3 | `abi.encode(uint256 chainId, bytes32 target, bytes32 callHash)` | none |
| 4 | any of these encrypted to the payee (KEM wrap to the payee's `UARegistry` KEM key ‖ AES-256-GCM; inner layout a later client item) | the way for private data (O11, O5) |

`body` stays `bytes` on chain: it is the preimage of a commitment the contract never parses, and schema 4 is a ciphertext. The
node job and every client carry it as **named fields per schema** and build the bytes (§7.1). Q7 records the tension with
CTR-MTX-29.

### 3.2 The check, `_payMeta(bytes32 entryRef, PayMeta calldata m)`

One internal function in `MetaTokenBase`, called by every pay entry after its gates:

| Check, in order | Error |
|---|---|
| `m.salt ≠ 0` | `PayMetaShape()` |
| `(m.schema == 0) == (m.body.length == 0)` | `PayMetaShape()` |
| `bytes(m.payNo).length ≤ 256` | `PayNoTooLong(length)` |
| `entryRef == metaPayId(m)` (so `entryRef ≠ 0` always) | `PayMetaMismatch(bytes32 entryRef, bytes32 payId)` |
| then emit `PaymentMeta(bytes32 indexed payId, string payNo, uint16 schema, bytes body)` | — |

A zero salt is refused because a `payId` over a known `payNo` and no salt can be brute-forced from document numbers
([CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03)'s reason); non-zero does not prove entropy: the CSPRNG stays the signer's
duty. The event names its fields; the old `PaymentMeta(bytes32 indexed payId, bytes meta)` goes to legacy. Unknown schema values
are not refused (the contract does not parse; clients treat an undecodable body as opaque data, never as verified facts). No
contract cap on `body`; the node's `max_pay_meta_bytes` (default 2,048) counts `payNo` and `body`, and is checked before the node
allocates the schema encoding.

**Publication (O11).** On a pay entry the metadata cannot be stripped: `entryRef` is signed and equals the commitment, so the only
`PayMeta` the call accepts is the one the payer committed to, and `PaymentMeta` is always emitted. Through the generic path a
payment can still land without the log (O12, §2.3); the ERP keeps the preimage.

### 3.3 Privacy: a warning, not a ban (O5, C4)

Three separate properties (Codex #6):

1. **An unpublished random-salted preimage resists document-number guessing.** A `payId` whose salt has never been published
   cannot be found from a document number. Since every pay entry publishes its `PayMeta` in calldata and in `PaymentMeta` (O11), this
   holds only for a reference not yet paid through a pay entry.
2. **A clear `payNo` or a clear body (schemas 1–3) is publicly searchable, forever.** Anyone can search the chain for it. A schema
   4 body is searchable only by those who can decrypt it; a payment with `payNo` empty and schema 0 or 4 publishes nothing
   searchable but its salt.
3. **Repeated `entryRef` values are linkable whatever the salt.** Partial payments and refunds under one `entryRef` are linked by
   design.

The factual point of O5, scoped: the transaction carries `from` and `to` in clear. A holder of the document who also learns
something that identifies the payment (a clear `payNo`, the amount and date, the payer's or payee's address) can find it and
link the payer's address to the payer; a schema 4 body with an empty `payNo` gives no such handle by itself.

- A clear `payNo` or a schema 1 or 2 body is **not recommended**; it is never refused.
- Wallets (`clientkeys`, every `ua-*` signer, the app) warn before signing a payment whose `PayMeta` has a non-empty `payNo` or a
  schema 1 or 2 body: **once per payee per session**, and the decoded fields are always shown beside the typed data, with the
  recommendation of schema 4 (F-24; CTR-MTX-26's display rule).
- `TaxRecipientSet` and the rate are public governance state; they say nothing about a payee.

## 4. Relay fee with free lanes (O4) — SPECIFIED

```text
old: UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 validUntil,address relayer)
new: UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)
```

- Token: `mtxRelayFee(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value, uint256 batch, uint256
  nonce, uint256 validUntil, IUARegistry.UASig auth)`; it builds `UAMetaTransfer{from, to: payee, value, entryRef: ref, batch,
  nonce, validUntil, mode: MODE_RESTRICT_RELAYER, relayer: msg.sender, fee: 0, feeRecipient: 0}` and passes the new
  `UARelayFee` hash as `signed` to `_uaExecuteTransfer` (as today). `ref = relayRef(target, callDataHash)` unchanged
  (`relayref.json` unchanged). Not `PAYABLE`-gated. No `PayMeta`: the relay fee is not a pay entry of O2 (its reference is the
  call), and it is reached only through `_uaExecuteTransfer`, never through `mtxExecuteTransfer`.
- Router: `MtxRelayFee.relay(address target, bytes callData, address token, bytes32 from, bytes32 payee, uint256 value, uint256
  batch, uint256 nonce, uint256 validUntil, IUARegistry.UASig auth)`. If the legacy decoder runs out of stack (on the router or
  on the token's ten-argument `mtxRelayFee`, F-23), the six payment fields travel as one named struct `RelayPay { bytes32 from;
  bytes32 payee; uint256 value; uint256 batch; uint256 nonce; uint256 validUntil; }` (explicit fields; measured in T38). The
  bytecode moves, so the CREATE2 addresses of `MtxRelayFee` and its executor move (test-only chains).
- **Pay-once of a relay fee is gone (O4), pay-once of a signature is not** (F-29): one `UARelayFee` signature runs at most once
  (its nonce). Paying twice for one call needs two signatures and a target that accepts the call twice; a target with its own
  nonce or guard reverts the second `relay`, which pays nothing. CTR-MTX-27's conformance line "a second `relay` with the same
  `ref` fails (pay lane)" becomes "a second signature for the same call pays only if the target call runs again".
- The payer may dedicate a lane (for example `batch = 2`) to relay fees; the node's "payer held" rule (job-api review I2) is
  unchanged.

### 4.1 Regulated kinds: open mode unchanged (O14)

Router open mode stays on kinds 8–13 as on every kind (CTR-MTX-27 unchanged). Accepted limitation: in open mode a frozen relayer
can still collect a relay fee forwarded by the router, because RK-6 checks the router (the signed payee), not the final relayer.

## 5. Tax on the regulated kinds (O6–O10) — SPECIFIED

### 5.1 Where (O8, B-2, B-3)

Every regulated kind 8–13 (Hedera: 8, 9). Bit 23 `TAX` is in their `_validBits()`; the plain kinds 0–5 refuse it like every
regulated bit (`FeatureInvalidForKind(23)`), so CTR-GOV-03's "+0" is untouched. Tax concerns public balances: on 10–13
`mtxPayWithTax` moves public balances (the UA ledger and the ERC-20 core, the same public path as `mtxPay` on every kind), and no
confidential site (shield, transfer, unshield, roll-over) gets a tax leg, so no `ZetherLayer`, `PqzLayer` or library file
changes. `FeePolicy.requireConfidentialSafe` (`PercentFeeForbiddenOnConfidential`) does **not** apply: the amount of a public pay
is public calldata and is emitted in `UAPaymentSettled`, so a PERCENT tax reveals nothing the payment did not (B-3). The hook
seats are the existing ones of `_uaExecuteTransfer` and `_uaMove` (`_regPre`, `_regFeeTo`, `_regMove`); no new seat is added for
tax (B-2). No entry other than `mtxPayWithTax` and `payWithTax` reads tax state (O7(1)).

### 5.2 The signed struct (O7(2))

```solidity
bytes32 constant UA_PAY_WITH_TAX_TYPEHASH = keccak256(
    "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)"
    "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,"
    "uint32 mode,address relayer,uint256 fee,address feeRecipient)");
// hashStruct = keccak256(abi.encode(UA_PAY_WITH_TAX_TYPEHASH, _structHash(t), taxMode, tax)): the nested STRUCT hash, with
// relayer and feeRecipient zeroed when unbound, as MtxPipelineLib._structHash does
```

Signed in the token's domain by the payer (`t.from`); consumes `(t.from, t.batch, t.nonce)` like every pay entry; a plain
`UAMetaTransfer` signature cannot authorize a tax leg and a tax signature cannot pass as a plain transfer. `taxRecipient` is not
signed: wallets read `taxConfig()` and show it. `taxMode`: `1` PERCENT, `2` AMOUNT (the numbers of the public fee modes
`FeeMode.PERCENT` and `FeeMode.FIXED`); anything else `TaxModeInvalid(uint8)`.

### 5.3 `mtxPayWithTax(UAMetaTransfer t, uint8 taxMode, uint256 tax, UASig auth, PayMeta meta)`

Order, all or nothing, cheap first, under the token's one `nonReentrant` guard for the whole call:

1. `requireFeature(PAYABLE)`, `requireFeature(TAX)`.
2. `_payMeta(t.entryRef, meta)` (§3.2).
3. `taxMode` valid; `tax ≤ t.value` (`TaxExceedsAmount(tax, amount)`); PERCENT: `tax == Math.mulDiv(t.value, rate, 10^6)` with
   `rate = effectiveRate()` (§6.2), else `TaxMismatch(uint256 expected, uint256 got)`. AMOUNT: `tax` as signed.
4. `r = taxRecipient` (from `scaas.regulated`); `r ≠ t.to` (`TaxRecipientIsPayee`); `tax ≠ 0` ⇒ `_regFeeTo(r, tax)` (RK-6: `F(r)`
   ⇒ `FeeRecipientFrozen`, `!R(r)` ⇒ `NotEligible`), before effects.
5. **One split execution (O13).** `_uaExecuteTransfer` gains two internal arguments, `uint256 withheld, bytes32 withheldTo`
   (every other caller passes `0, 0`); here `d = _uaExecuteTransfer(t, hashStruct(UAPayWithTax), tax, r, auth)`: the seats
   `_regPre`, signature, nonce and `_regFeeTo` as today; the balance check `value + fee` as today (tax is inside `value`); the
   payer's fee on top, basis `t.value` (CTR-MTX-13, CTR-MTX-08); then `_uaMove(t.from, t.to, t.value − tax)` and, when `tax ≠ 0`,
   `_uaMove(t.from, r, tax)`, both hooked by `_regMove` (`P`, `F(payer)`, `R(to)`); then `UAPaymentSettled(from, to, value, fee,
   feeTo, entryRef)` (gross, the signed `value`) and `UAMetaTransactionExecuted(…, d, …)`. A frozen payee does not block the tax
   leg (its `from` is the payer, and credits are never refused for a freeze, CTR-AS-05); no `_poolMove` is used, so the regulated
   spec's list of `_poolMove` callers does not change (F-17 moot).
6. Emit `PaymentTaxed(bytes32 indexed entryRef, bytes32 indexed payee, bytes32 indexed taxRecipient, bytes32 from, uint8
   taxMode, uint256 tax, bytes32 digest)`, also when `tax == 0` (C6, F-05). Under the B-1 levers the emit may live in
   `RegulatedLib` (a library event under `DELEGATECALL` carries the token's address).

**Books (O13).** Payer `−(t.value + fee)`; payee `+(t.value − tax)`; `taxRecipient` `+tax`; fee recipient `+fee`. Where roles
coincide (payer = `taxRecipient`, `taxRecipient` = fee recipient) the deltas add. The ledger shows the payer as the withholding
agent. Events in order: `PaymentMeta`, the transfer logs, `UAPaymentSettled` (gross), `UAMetaTransactionExecuted`,
`PaymentTaxed`. Wallet display: `amount` (tax included), `tax`, mode, the configured `taxRecipient`, the fee.

**Not in a batch:** `mtxBatchTransfer` carries no tax. **No receiver fee with tax:** a payee that pays the relayer and a tax uses
the payer's fee on `mtxPayWithTax`, or two calls.

### 5.4 Reconciliation of a taxed payment (C6, F-02, F-07)

The gross-sum rule of CTR-MTX-03's chain → client procedure (`Σ amount ≥ amount_base` ⇒ final) applies **only to rows without
`PaymentTaxed`**. For a payment row joined with a `PaymentTaxed` (join: same transaction, same token, same `entryRef` and `from`,
`PaymentTaxed.digest == UAMetaTransactionExecuted.digest`, the `PaymentTaxed` after the `UAPaymentSettled`):

```text
net = value − tax                         # booked as the receivable's settlement
tax                                       # booked as tax withheld by the payer, remitted to taxRecipient
request final  ⇔  Σ net ≥ amount_base − expected_tax   and   Σ tax == expected_tax
otherwise      ⇒  reconciliation exception (an over- or under-declared tax is never closed silently)
```

The node feed row carries `tax`, `tax_mode`, `tax_recipient`, `net` and `withheld_by = from`; the ERP presents "the payer paid
gross `value`, withheld `tax` to `taxRecipient`, the payee received `net`" from `PaymentTaxed`, not from the transfer log.

### 5.5 Mode guidance and the in-flight rule (C7, F-04, F-06)

- **ERPs use AMOUNT.** They compute the tax anyway; real invoices carry several taxes with their own bases and round at currency
  precision, which a floor at token precision does not match. AMOUNT is also immune to a rate change in flight. PERCENT serves
  wallets and simple single-rate regimes.
- One `taxRecipient`, one leg: several taxes to several authorities are split off chain by the recipient's holder (a collection
  UA).
- **In flight:** a PERCENT payment signed at rate `r0` and landing after any rate change (a decrease, or an increase whose `eta`
  passed) reverts `TaxMismatch(expected, got)`. The node re-simulates, returns `TAX_MISMATCH` with `expected`, and the client
  re-signs; the job is refused by name, never `dead`. The ops note says: announce rate changes, drain PERCENT queues across
  `eta`, prefer AMOUNT.

### 5.6 Direct `payWithTax` (O13)

`payWithTax(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef, PayMeta meta)` on kinds 8–13 (Hedera 8,
9), `PAYABLE` and `TAX` gated, `nonReentrant`, symmetric with `payWithFee` / `payWithFeeToUA`: the payer is the caller,
`pad(_msgSender())` (a native id: a contract treasury, `MandateWallet`, a Safe, or an EOA paying its own gas); `to` a native or a
registered SIGNING derived id (`_checkTo`). Steps 1–4 and 6 of §5.3 (with `amount` for `t.value` and `to` for `t.to`), then the
split without a signature, nonce or fee: `_uaMove(payer, to, amount − tax)` and, when `tax ≠ 0`, `_uaMove(payer, r, tax)`, both
hooked by `_regMove`; then `UAPaymentSettled(payer, to, amount, 0, address(0), entryRef)` and `PaymentTaxed(…, from: payer, …,
digest: 0)` (no digest: no signed struct). It is not allowlisted for the generic self-call (a direct entry, as `payWithFee`), so
the relayed form is `mtxPayWithTax`. Size: +0.4–0.6 KB on each of the six kinds [est.], counted in §6.4. The mandate wallets do
not call it in this group (O17).

## 6. Bit 23 `TAX`, policy and storage — SPECIFIED

### 6.1 The bit (O9)

Bit **23** (`0x800000`), the first free bit of the SCaaS band after `OPERATOR_TRANSFER` 22 (bits 13 and 14 are never reused,
CTR-GOV-14). Type: power, not scalar, no scope. Valid on kinds 8–13. **Any holder** (O9): an EOA, a single-key UA, an `msig` or
a contract; bit 23 is in `_roleBits()` of 8–13 and in `GovernanceBits.ISSUER_BITS` (so `init` grants it to `roles.issuer` when it
is set, F-19), and **not** in `_contractOnlyBits()` nor `REGULATED_ROLES` (the `msig` clause of RK-1 is moot for it). Init must
not refuse an issuer that holds only bit 23 (`RoleWithoutFeature` checked against the issuer's actual bits, F-19).

**The issuer seat (A-1).** `init` grants one `roles.issuer` id every set issuer bit; bits 5–7 require a contract or an `msig`.
A token that wants a contract for `FREEZE` / `PAUSE` and an EOA for `TAX` cannot say so in `TokenConfig`: it is created with the
contract issuer and then `grantRole(23, eoa)` (two calls under `grantDelay`, CTR-GOV-04), and may revoke the contract's bit 23.
The disclosure says so. A `LIMITED` grant does not bound `setTaxRecipient` (no scalar), so a single key redirects tax revenue at
once (Q4).

**Relaxation (Q5).** Recommendation: bit 23 **not** in `_delayedRelaxBits()`. Fable F-08 argues for delaying `disableFeature` and
`revokeRole` of 23 (losing collection harms the authority). Weighed against O9: the delay mask covers **every** relaxation of the
bit, including the owner's `revokeRole` of a compromised holder; with a single-key holder allowed, a stolen key could redirect the
recipient (immediate) while its revocation waits `grantDelay` (≤ 30 days). The authority's concern is met without the delay:
`FeatureDisabled(23)`, `RoleRevoked(23, …)` and `TaxRecipientSet` are node alerts; another root sets the recipient back at once;
the disclosure states that the owner can stop tax collection at once. Runbook row for the regulated spec §3.6: "compromised `TAX`
holder: at once another root `setTaxRecipient` back and the owner `revokeRole(23)`; nothing waits".

### 6.2 Powers, storage, the rate (O10)

Direct entries on kinds 8–13, `nonReentrant`, gated by `GovernanceUse.use(TAX, _govSubject(), 0)`, bodies in `RegulatedLib`
(§6.4); relayed through the `GovernanceRouter` (no `mtx` twin on the token, G19) as `mtx<Op>(UAEnvelope e, address target, …,
UASig auth)` over `UA<Op>`, fee mode `NONE`, relayable at fee 0:

| Op | Direct entry | Router entry, struct `UA<Op>` params | Event |
|---|---|---|---|
| Rate | `setTaxRate(uint32 ratePpm)` | `mtxSetTaxRate`: `uint32 ratePpm` | `TaxRateSet(uint32 ratePpm, uint64 effectiveAt)` |
| Recipient | `setTaxRecipient(bytes32 taxRecipient)` | `mtxSetTaxRecipient`: `bytes32 taxRecipient` | `TaxRecipientSet(bytes32 indexed taxRecipient)` |

Storage appended to `erc7201:scaas.regulated` (the namespace is new in this branch; the layout pin gains the rows, old → new):

| Slot | Content |
|---|---|
| +5 | `taxRecipient bytes32` |
| +6 | `TaxRate { uint32 ratePpm; uint32 pendingPpm; uint64 eta; }` (one slot, token-wide) |

- **Rate (PT-5).** `ratePpm ≤ 1,000,000` (`TaxRateInvalid`). `effectiveRate() = (eta ≠ 0 && now ≥ eta) ? pendingPpm : ratePpm`.
  On `setTaxRate` a matured pending is folded into `ratePpm` first; then a value **≤ the effective rate** applies at once (pending
  cleared); a value **above** it is written as `pendingPpm` with `eta = now + noticePeriod`, the effective rate unchanged until
  then (a later decrease cancels it). The token reads `IOpenFactory(FACTORY).noticePeriod()` (an immutable of the factory) and
  passes it to `RegulatedLib`, which cannot see the token's immutables under `DELEGATECALL` (F-20). The period is what the
  factory was deployed with: `OpenFactory` enforces only the 30-day upper bound; the 3-day floor on public mainnets is a check of
  the deploy script, and test chains and dev chains may run lower, or 0 (no notice at all). The disclosure and wallets show the
  actual period, never a promised floor (Codex #5).
- **Rounding (PT-6).** `tax = Math.mulDiv(amount, rate, 10^6)`, floor, the rule of `FeePolicy.compute` (Q3). With `rate ≤ 10^6`
  it cannot overflow; `paytax.json` pins `amount = 2^255` and a row where half-up and floor differ (F-27, F-06).
- **Recipient.** `taxRecipient ≠ 0`, not `pad(UA_POOL)`, `pad(SHIELD_POOL)` or `pad(this)` (`TaxRecipientInvalid(bytes32)`). A
  native id (an authority's address or contract, zero-padded) is valid; a derived id must be registered SIGNING
  (`MtxPipelineLib._checkTo`), checked at set time (a record never changes kind, CTR-UA-15) (F-21). At set time also `!F(r)` and
  `R(r)` (two reads), so an unattested or frozen recipient never turns every taxed payment into a refusal; the pay-time check of
  step 4 stays (F-15). Immediate (Q4).
- **Creation.** `RegulatedParams` gains `bytes32 taxRecipient` (≠ 0 iff bit 23; else `RegulatedConfigInvalid()`), validated as
  above in `init` (`RegulatedLib.init`, reached by `ZetherWrappedLib.init` and `PqzWrappedLib.init` too, B-5); the rate starts at
  0. `TokenConfig`'s encoding moves again (the ripple list of the regulated spec §2.4).
- **Views:** `taxConfig() returns (TaxConfig { bytes32 taxRecipient; bool enabled; uint32 ratePpm; uint32 pendingPpm; uint64 eta;
  uint32 effectivePpm; uint64 noticePeriod; })`: one struct view (B-1). A wallet and the node read it to build and check a
  payment.

Codex #4 and #5's class half, and Fable F-09 and F-28, fall away with O10 (no class 0 policy, no class reassignment, no published
classification, no untaxable class).

### 6.3 Disclosure

Bit 23's sentences in `governance_bits.json`: "any holder (an EOA too) sets the tax recipient and the one PERCENT rate; a rate
increase waits the factory's notice period (shown; it may be 0 on a test chain), a decrease is immediate and makes PERCENT
payments in flight fail; a recipient change is immediate and is not signed by the payer; an AMOUNT tax is the payer's signed
figure, unchecked by the contract; the owner can stop tax collection at once".

### 6.4 Library and size (C8, B-1, F-13)

The bodies (`setTaxRate`, `setTaxRecipient`, the init check, the PERCENT check, the `PaymentTaxed` emit under B-1) live in
**`RegulatedLib`** (already linked on 8–13: no new link, no new `Env.libs` / `libCodeHashes` row; the release codehash pins move
with the new bytecode). The token keeps `mtxPayWithTax` (it moves balances, which the library cannot reach; no library split of
the move), two thin stubs that only `DELEGATECALL`, and the one struct view.

| Release | Δ runtime [est.] | Basis |
|---|---|---|
| every kind 0–13 (pay entries, `PayMeta`, relay fee) | **+1.0 to +2.0 KB** | four entries each gain a calldata validator for a struct with a `string` and a `bytes` (~250–450 B each), `_payMeta` with `abi.encode(string, uint16, bytes)` and an event with two dynamic fields, `mtxPay`'s struct decoder; minus `mtxPayMeta`, `_uaPayMeta`, `_uaPay` (~0.5 KB) |
| kinds 8–13 (tax) | +0.9 to +1.4 KB on top | `mtxPayWithTax` 0.6–0.9 (struct decode, typehash, the split's two arguments), two stubs and one view 0.3–0.5 |
| kinds 8–13 (`payWithTax`, O13) | +0.4 to +0.6 KB on top | the direct twin |
| `RegulatedLib` | +1.0 to +2.0 KB | two bodies, the rate fold, the checks, the event |
| `GovernanceRouter` | +0.4 to +0.6 KB | two router ops; its CREATE2 address moves again |
| `MandateWallet`, `HederaMandateWallet` | +0.3 to +0.6 KB | the `PayMeta` tail on the pay entries; new CREATE2 addresses |

Against the ceilings (the regulated spec's §6.2 estimates, still unmeasured: T27):

- **`WrappedPqzRegulatedToken` (kind 13), the tight one:** `WrappedPqzToken` 56,507 B today, regulated estimate 59.5–61.2 K,
  plus this group 2.3–4.0 K (with `payWithTax`) ⇒ **61.8–65.2 K**: the 65,536 B jump-width cliff is inside the range. Kinds 11 and 12 keep 6–9 KB below it.
- `NormalRegulatedToken`: 35.1–36.6 K ⇒ about 37–40.6 K; asked gas at ≈ 1,680 gas per runtime byte about 62–68 M: it misses
  60 M (it was at the edge) and fits 70 M only at the low end. `WrappedRegulatedToken` and 10–13 already miss 70 M (accepted
  gap, regulated Q7); each asks 3–6 M more. Everything fits the SCaaS testnet (131,072 B, 200 M block).

**How it is measured.** `forge build src --sizes --json` and `size_gate.py`; the asked gas by `DEPLOY_GAS` on the regulated
spec's §6.2 method; `size-baseline.json` rows old → new with the reason in `_comment`.

**Stop rule (O18).** The stop line is **64,512 B** of runtime: 1,024 B under the 65,536 B jump-width cliff, the 64.5 KB line
the typed-signing build used (`evm-size-levers.md` §9), so the review's fix wave (T22) still has room. **T37 measures kind 13
first** (one pay entry converted, then the rest) and **T40 measures kind 13 first** (the tax entry, then the stubs, then
`payWithTax`); then every other kind of 0–13. A kind at or above the stop line is **reduced**: the task applies the levers below
in order, one at a time, re-measures after each (size, then the whole `forge test`), and stops as soon as the kind is under the
line. It goes back to the controller only when every lever is applied and the kind is still at or above it. The `_above64KiB`
row is not a fallback (O18). A deploy-gas figure that runs more than 50 % over this section's estimate is reported to the
controller, without stopping the task.

**Levers, in order** (estimates on kind 13 [est.]; levers 2 of the size note, the shared `nonReentrant` body, and 1, the raw
`initArgs` into `PqzWrappedLib` / `ZetherWrappedLib`, are already built and give nothing more; each lever below is a library
split and passes the split checklist: DELEGATECALL storage is the token's own namespace, `address(this)` is the token,
`msg.sender` is the direct caller (the router or the relayer, never the subject: `_govSubject()` and every immutable such as
`FACTORY`, `_REGISTRY` or `IS_HEDERA` are read in the token and passed as arguments), the return data is fixed and checked, the
token's one `nonReentrant` guard wraps the whole entry and the library takes none, and the release's `LinkClosure` pins and
library codehashes move old → new):

| # | Lever | Saving [est.] | Constraints beyond the checklist |
|---|---|---|---|
| 1 | One internal split `_taxSplit(payer, to, value, tax, r)` shared by `mtxPayWithTax` (through `_uaExecuteTransfer`'s two arguments) and `payWithTax`, with one shared PERCENT check | 0.2–0.4 KB | no library; gas ±20 per call |
| 2 | The two tax powers as thin stubs: the token forwards its calldata words and `_govSubject()` to `RegulatedLib` with no local decoding or event | 0.2–0.4 KB | `setTaxRate` passes `IOpenFactory(FACTORY).noticePeriod()`; gas of the powers +100–300 (cold paths, no pin) |
| 3 | The `PaymentTaxed` emit and the PERCENT / `tax ≤ value` / recipient checks in one `RegulatedLib.checkTax(…)` call returning `r` | 0.3–0.5 KB | a library event under DELEGATECALL carries the token's address (indexer unchanged); `_regFeeTo` stays in the token (it is a hook); gas of a taxed payment +700–1,200, pins old → new |
| 4 | One struct view: `taxConfig()` merged into the regulated spec's `regulatedConfig()` (one selector, one encoder) | 0.15–0.3 KB | an `eth_call` shape change for wallets and the node (T41, T42); no on-chain gas |
| 5 | `_payMeta` (the shape checks, `metaPayId`, the `PaymentMeta` emit) in `MtxPipelineLib`, already linked on every kind | 0.4–0.8 KB, on every kind | the `PayMeta` calldata struct is re-encoded into the library call: +1–2 k gas per pay (more with a large body), the `mtxPay` pins old → new on every kind; `MtxPipelineLib`'s rule "no state, one nonce slot" holds (it writes nothing) |
| 6 | The `UAPayWithTax` struct hash in `MtxPipelineLib` (as `receiverFeeDigest`) | 0.1–0.2 KB | gas +~300 per taxed payment |
| 7 | Error consolidation: `PayMetaInvalid(uint8 reason)` for the three `PayMeta` errors and `TaxInvalid(uint8 reason, uint256 expected, uint256 got)` for the tax errors | 0.1–0.3 KB | still named errors with a reason code: the node's and clients' decode tables move (T41, T42); tests assert the reason |
| 8 | `payWithTax`'s body in `RegulatedLib` except the two moves, which stay in the token behind one internal call | 0.2–0.4 KB | the moves need token internals (`_uaMove`), so the library returns and the token moves; gas +~800 per direct taxed payment |

**Not levers without the owner's word:** a views-behind-`fallback` module or the base bodies in a library (the size note's lever 3
and T9's L / D, deprecated by the owner 2026-11-05); `optimizer_runs` or `via_ir` (they move every kind's gas and re-verify the
whole tree); dropping or narrowing an entry or a ruling (`payWithTax` on 12, 13, the `PayMeta` fields).

## 7. Vectors, clients, node — SPECIFIED

### 7.1 Node (`scaas-node`)

| Area | Change |
|---|---|
| Job shape (EVM, `ua_metatx`) | a pay is a named entry: `{op: {entry: "mtxPay" \| "mtxPayReceiverFee" \| "mtxPayWithTax", token, args: {t: WireUAMetaTransfer, taxMode?, tax?, fee?, feeRecipient?, rfValidUntil?, payeeAuth?, meta}, auth}}`; `args.t` maps to the signed `payment` member; `meta` (required, O11) = `{salt, payNo, schema, body}` with `body` **named per schema** (0 absent, 1 `{note}`, 2 `{creditorRef, dueDate}`, 3 `{chainId, target, callHash}`, 4 `{ciphertext}` hex, the one crypto object); the node builds `body` and `PayMeta`. The old `salt` + hex `meta` form is refused `HEX_ARGS_REFUSED`; `mtxPayMeta` by name (`ENTRY_RETIRED`) |
| The entry sent (F-10) | a pay job (`entryRef ≠ 0`) is sent only as its pay entry (`mtxPay`, `mtxPayReceiverFee`, `mtxPayWithTax`) with its `PayMeta`, never downgraded to `mtxExecuteTransfer` or a batch, on any retry; so the `PAYABLE` gate applies to every pay job (operator note). A `struct: "transfer"` job (no `meta`) is relayed through `mtxExecuteTransfer` as today, whatever its `entryRef` (O12) |
| Signer and digest of `UAPayWithTax` (C2, Codex #1) | the signer is `payment.from` (never the receiver-fee fallback to `payment.to`); the payer's nested lane `(from, batch, nonce)`; the **outer** `UAPayWithTax` digest is the job identity, the idempotency key and the execution match against `UAMetaTransactionExecuted.digest`. The receiver-fee behaviour (signer `payment.to`, inner digest) stays as it is, specific to `UAReceiverFee` |
| Pre-checks, before simulation | `meta` shape as §3.2; `entryRef == metaPayId(meta)` (`PAY_META_MISMATCH`); `payNo` ≤ 256 B (`PAY_NO_TOO_LONG`, at ingress, before any encoding); `payNo + body ≤ max_pay_meta_bytes` (default 2,048, unchanged: the 256-byte `payNo` fits inside it) (`PAY_META_TOO_LONG`), checked before encoding; **the `batch == payLane(entryRef)`, `nonce == 0` checks go** (O3); `tax ≤ value`; PERCENT: `tax == floor(value × taxConfig().effectivePpm / 10^6)` (`TAX_MISMATCH` with `expected`) |
| Relay fee | `args` gain `batch`, `nonce`; the lane is the payer's, not `payLane(ref)` |
| Pricing (F-25) | the quote counts the calldata of `payNo + body` (and the EIP-7976 floor); a small payment with a large body is refused `RELAY_FEE_REFUSED` / below the operator's price, or relayed only on the restricted scope |
| `typed.rs` `TYPED`, `guard.rs` | the pay entries' rows move to the struct form; `UAPayWithTax` in **each contract class** (`token`, `zether`, `pqz`) on the kinds 8–13 (B-4); `mtxPay` becomes a row (`NOT_ROWS` loses it); two `gov_router` rows (`UASetTaxRate`, `UASetTaxRecipient`); the mandate wallets' rows with `PayMeta`; equality both directions with `mtxSelectors()`, `_uaAllowed`, `selector_audit.json` per kind, checked against the target's actual `kind()` |
| Errors | named decode of `PayMetaShape`, `PayNoTooLong`, `PayMetaMismatch`, `TaxModeInvalid`, `TaxMismatch`, `TaxExceedsAmount`, `TaxRecipientIsPayee`, `TaxRateInvalid`, `TaxRecipientInvalid`: refusals, never `dead` while a transaction may land; a re-simulation after `TaxRateSet` refuses a queued PERCENT job by name |
| Landed elsewhere | a pay or tax job whose nonce was consumed is matched by its outer digest in `UAMetaTransactionExecuted`; a match is `landed`, never `superseded` (Codex #1) |
| Indexer, feeds | `PaymentMeta` (new topic, named fields) enriches the `UAPaymentSettled` of the same transaction and `(from, entryRef)`; `PaymentTaxed` joins as §5.4 and adds `tax`, `tax_mode`, `tax_recipient`, `net`, `withheld_by`; alerts on `TaxRateSet` (with `effectiveAt`), `TaxRecipientSet` (with `canReceive(r)`, the class of `OrderRecorded`), `FeatureDisabled(23)`, `RoleRevoked(23, …)` |
| Gateway | `/v1/op` takes the three pay entries as named entries; `/v1/ua-metatx` keeps refusing `salt` / `meta` (T15 call) |
| Mesh | a pay is not a mesh body in this group (it always carries `PayMeta` now): refused by name (Q8); a plain transfer (`entryRef = 0`) travels as today |
| Non-EVM adapters | the eight adapters (`algorand`, `aptos`, `cosmos`, `near`, `solana`, `soroban`, `sui`, `ton`) keep the old commitment and empty-meta behaviour until their family round (§8, Q10) |
| Operator note | the pay job shape (required named meta, no lane check, never downgraded, the `PAYABLE` gate), the relay-fee lane, the new `MtxRelayFee`, router and mandate-wallet addresses, the tax rows, the in-flight `TaxMismatch` rule; old shapes refused by name |

### 7.2 Clients

| Client | Change |
|---|---|
| `clientkeys` | `buildPay`, `buildPayReceiverFee`, `buildPayWithTax` (struct form, `PayMeta` last, never empty), `metaPayId(PayMeta)` under `scaas.pay.meta.v2`, `payNo` refused above 256 bytes before signing, `encodeMetaBody(schema, fields)` / `decodeMetaBody`, `buildRelayFee` with `batch` / `nonce`; the warning (§3.3) and the `payNo` text checks; each digest tested with a non-zero unbound `relayer` / `feeRecipient` |
| `ua-rs` (the one signer, 3d) and its wrappers `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb` | sign `UAPayWithTax` and the new `UARelayFee`; `metaPayId` v2; `tests/metatx.rs` reads the regenerated `paymeta.json`; `ua-qt`'s `tst_ua.qml` row moves |
| `zether-prover` | its `typed.rs` relay-fee builder takes the new `UARelayFee` (no proof, statement or tag moves) |
| native `ua-py`, `ua-go`, `ua-cs`, `ua-dart` | only where one reproduces a pay or relay-fee digest (checked by grep in T41); none expected |
| App, wallets | display `amount` (tax included), `tax`, mode, the token's configured `taxRecipient`, the decoded `PayMeta`; refuse on a commitment mismatch (as CTR-MTX-26) |

### 7.3 Vectors

| File | Change |
|---|---|
| `smartcontracts/vectors/metatx/paymeta.json` | **regenerated** under `scaas.pay.meta.v2`: rows `{name, salt, payNo, schema, body, payId}`; schema 2 without `invoiceNo`; rows: salt only (schema 0, `payNo` empty), `payNo` only, `payNo` of exactly 256 bytes (accepted) and a refused-row of 257 bytes, multi-byte UTF-8 `payNo` ending at the bound, each schema; a row whose old-tag hash over the same bytes differs (C1); `payLane` column dropped. The old file is copied first to `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/paymeta.json` (MD-4) |
| new `smartcontracts/vectors/metatx/paytax.json` | PERCENT rows (rates 0, 1 ppm, 100,000, 1,000,000; amounts 0, 1, 999,999, `2^255`; floor edges; a half-up ≠ floor row), AMOUNT rows (`tax == amount`, `tax == 0`), refused rows (`tax > amount`, mismatch), `UAPayWithTax` digests (non-zero unbound `relayer` / `feeRecipient` in the input); written by a forge test, read by `clientkeys`, `ua-rs`, the node |
| `smartcontracts/vectors/typed/typed_ops.json` | `UARelayFee` type string moves; `UAPayWithTax` per contract class; two router rows; by `typed-ops-vectors.mjs` |
| `smartcontracts/vectors/governance/governance_bits.json` | bit 23 `TAX` with its sentences (§6.3) |
| `smartcontracts/evm/test/vectors/selector_audit.json` | the two direct `TAX` powers in the class of the existing powers; `mtxPayWithTax` and `payWithTax` on six kinds; the pay entries' selectors; the mandate wallets' entries |
| the mandate KAT | regenerated (new wallet bytecode and entry forms; typehashes unchanged) |
| Unchanged | `relayref.json`, `metatransfer_kat.json`, `hedera_kat.json` (no `mtxPay` row), `plus_zero_slots.json` (kinds 0–5), `ua/metatx3.json` (`UAMetaTransfer`, `UAReceiverFee` unchanged) |

## 8. Family impact — SPECIFIED (each in its own round, one rule)

The rule is family-neutral: a required `PayMeta { salt, payNo, schema, body }` as the last argument of the family's pay entries,
the `scaas.pay.meta.v2` commitment, free lanes for pay and relay fee, no invoice pay-once. Tax follows a family only with its
regulated kinds (none exists outside EVM today). Until a family's round, its contracts, its node adapter and its tests keep the
old formula and the legacy copy of `paymeta.json` (Q10).

| Family | Pay metadata | Free lanes | Nonce-lifetime safeguard (C3) | Relay fee |
|---|---|---|---|---|
| EVM, Hedera | this group | this group | persistent nonce map: none needed | this group |
| Soroban | `pay` / `ua_pay` take `meta` last; `pay_meta` / `ua_pay_meta` to legacy | the once-set `(from, pay_ref)` goes; lane nonce as transfer | persistent storage with TTL extension: the round states it | `relay-fee` router: lane and nonce |
| Solana | the meta argument on the pay instruction | the per-pay lane PDA becomes the payer's lane | **kept:** `MAX_TTL_S`, the prune delay and the signing horizon (NET-SOL-22, NET-SOL-25) on every lane until persistent generations or tombstones are specified | `relay_fee_<entry>` wrappers, generic router |
| Cosmos | the meta field on `Pay` | lane nonce as transfer | persistent: none needed | `relayfee`: lane and nonce |
| Sui | the meta argument on `pay` | as transfer | **kept:** NET-SUI-12's horizon and `prune` delay on every lane | `scaas::relayfee`: lane and nonce |
| Aptos | the meta argument on `pay` | as transfer | **kept:** NET-APT-24's horizon and `PRUNE_DELAY_S` on every lane (the different-expiry attack, `aptos.md`) | `scaas::relayfee`: lane and nonce |
| TON | `OP_PAY` `params` carries `payNo` too | the once-set lanes keep working as nonces | **kept:** two `LANE_TTL` generations and the signing horizon | the escrow key `(payer, ref)` gains the nonce |
| NEAR | `mtx_pay_meta` merges into `mtx_pay` | as transfer | persistent: none needed | `relay_fee_<entry>`, escrow router |
| Algorand | `mtx_pay_meta` merges into `mtx_pay`; the 507 B cap counts `payNo` and `body` (a 256 B `payNo` leaves 251 B of body) | as transfer | box storage persistent: none needed | `relayfee` app |

NEAR ≠ Algorand: separate rounds, separate caps. NODE-STO-01 (`max_valid_for_secs ≤ LANE_HORIZON` on a pruning family) stays.

## 9. Doc changes (written in T19, BUILT only with code and tests)

| Doc | Change |
|---|---|
| `docs/architecture.md` "Three properties" item 2 and **the four-condition test** item 1 | from "no … tax ids or party names" as a prohibition to: "**Recommended:** commitments only; a business document number, tax id or party name in clear is not recommended and never refused by the contracts; the payment metadata may carry it (`payNo`, schema 1 or 2) at the payer's choice, with the wallet's warning; schema 4 for private data"; the three properties of §3.3 |
| `docs/architecture.md` §10 item 1 | from "never names, document numbers, tax ids, order numbers or free text" to "not recommended … a warning, not a ban"; the scoped factual point (§3.3); the PLANNED CI guard on calldata types lists `PayMeta.payNo` and `PayMeta.body` as declared fields |
| `docs/decisions.md` | Change lines (§10), the entries of §12; ARCH-POS-04's "no personal data on chain" gets the recommendation wording |
| `docs/contracts/metatx.md` | CTR-MTX-01, -03, -04, -06, -09, -10, -11, -23, -24, -26, -27 rewritten (§10); the equivalence table; §6 lane table (pay row: a client convention); §12 payers; the privacy bullets of CTR-MTX-26 (§3.3) |
| `docs/contracts/accounts.md` | the pay rows to the merged struct forms with `PayMeta` |
| `docs/contracts/mandates.md` | the wallets' pay entries with `PayMeta`; `refUsed` is the wallet's rule (§2.4) |
| `docs/contracts/asset-suite.md` | §2: tax (CTR-AS-18, -19), bit 23, the accepted open-mode limitation (§4.1) |
| regulated spec (`2026-11-05-regulated-kinds.md`) | the §3.6 runbook row for bit 23; the open-mode limitation beside RK-6 (§4.1) |
| `docs/integration.md` | payment references: partial payments and refunds on one `entryRef` (O3, PT-1), the UNIQUE constraint on the request stays, the settled sum is the ERP's; the taxed reconciliation formula (§5.4); `payNo`; mode guidance (§5.5); data protection as architecture §10 |
| `docs/node/job-api.md`, `gateway.md`, `mesh.md`, `indexer-feeds.md`, `submit-lanes.md` (NODE-LANE-11), `ops.md` | §7.1 rows; the operator note; the in-flight `TaxMismatch` ops note |
| `docs/clients/signers-clientkeys.md`, `ua-libraries.md`, `app.md` | builders, the warning, the display |
| `docs/networks/*.md` | only the EVM, Hedera and README rows that cite the EVM pay forms; each family's own section in its round |

## 10. Existing rules the rulings, calls and proposals change (for Change lines, not resolved here)

| Source | Rule and what it says today | Change needed |
|---|---|---|
| O3 | [CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03): "`entryRef` is 32 random bytes"; a fixed lane per request with nonce 0 "makes each request payable at most once"; "issue one request per instalment" | lane = a client convention; one `entryRef` takes several payments; with O11 the pay `entryRef` is always a `PayMeta` commitment, never a bare random value |
| O3, C3 | [CTR-MTX-04](../../contracts/metatx.md#CTR-MTX-04): pay-once is a protocol rule, with obligations on issuers, signing clients, contracts and the node | invoice pay-once leaves the protocol; the nonce-lifetime obligations of the pruning families stay (§8) |
| O3 | [CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10): "the lane is derived on chain … at most once through `mtxPay`" | no derivation; the key sums amounts (§5.4 for taxed rows) |
| O3 | [CTR-MTX-06](../../contracts/metatx.md#CTR-MTX-06): receiver-fee shape `batch = payLane(entryRef)`, `nonce = 0` | the two terms go (§2.5) |
| O2, O11, O7(3), C1 | [CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26): two entries `mtxPayMeta` / `uaPayMeta`; "Off chain: plain `mtxPay` with `payId = metaPayId(salt, meta)` … nothing is published"; `meta = abi.encode(uint16 schema, bytes body)`; schema 2 with `invoiceNo`; the tag `scaas.pay.meta`; "`payId` stays unlinkable" | one required `PayMeta` last on every pay entry; the off-chain path is gone (O11); the v2 formula with `payNo` (O15); schema 2 without `invoiceNo`; the three privacy properties (§3.3) |
| O2 | [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09), [CTR-MTX-30](../../contracts/metatx.md#CTR-MTX-30) rows R1 and R27 | `mtxPay` takes `UAMetaTransfer t` as a struct; `mtxPayMeta` to legacy |
| O4 | [CTR-MTX-27](../../contracts/metatx.md#CTR-MTX-27): "lane `payLane(ref)`, nonce 0"; "Atomic and pay-once"; conformance "a second `relay` with the same `ref` fails"; the `UARelayFee` typehash (TS-D19); T20's wallet-display row | new typehash; §4's wording; T20 signs the new row if it has not run yet |
| O6, O7(2) | [CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11): "one type per intent means one wallet display" | `UAPayWithTax` is a second payment type signed by the payer (precedent: `UARelayFee`, TS-D19) |
| O8 | regulated spec §2.1, §7: "No user-facing entry is added or changes form" on 8–13; "kinds 8–13 take their base kind's token rows unchanged" | `mtxPayWithTax` and `payWithTax` (O13) are added on 8–13; the node rows of 8–13 gain them |
| O11 | `payWithFee` / `payWithFeeToUA` accept any `entryRef`, 0 included ([CTR-MTX-08](../../contracts/metatx.md#CTR-MTX-08)'s entry; [CTR-UA-28](../../contracts/accounts.md#CTR-UA-28)) | always a `PayMeta` commitment |
| O11, C5 | [CTR-ACC-12](../../contracts/mandates.md#CTR-ACC-12) / mandates.md: the wallets' pay entries and their KAT | the `PayMeta` tail; new addresses |
| O5 | `architecture.md` §10 item 1, the four-condition test item 1, [ARCH-POS-04](../../decisions.md#ARCH-POS-04)'s "no personal data on chain" | a recommendation (§9) |
| O7(3) | [CTR-MTX-29](../../decisions.md#ctr-mtx-29--every-parameter-is-explicit): "no packed `bytes` holding several fields" | `PayMeta.body` of schemas 2 and 3 (Q7) |
| O7(3), Q10 | AGENTS "Clients and vectors": byte formats change everywhere at once | non-EVM families keep the old commitment until their rounds; the versioned tag keeps the two apart (precedent CTR-MTX-30 R31) |
| O13 | O6's money flow (payer → payee `amount`, payee → recipient `tax`) | a direct split from the payer (the owner's own ruling replaces it) |
| O12 | [CTR-MTX-01](../../contracts/metatx.md#CTR-MTX-01), [CTR-MTX-23](../../contracts/metatx.md#CTR-MTX-23), [CTR-MTX-24](../../contracts/metatx.md#CTR-MTX-24), NODE-LANE-11, [CTR-TND-01](../../contracts/tender.md#CTR-TND-01) | unchanged (P-3 rejected); CTR-MTX-26's Change states that the generic path lands a payment without `PaymentMeta` and that reconciliation is then off chain |

## 11. Questions answered by the owner

No question is open. Answered on 2026-11-05: Q1 (kinds: O8), the holder half of Q5 (O9), the first draft's class questions
(O10), the blocking question (O7(1)), empty metadata (O11), `taxRecipient` signing (O7(2)), the generic path (P-3 rejected, O12),
the money flow and the direct entry (P-1, P-2 accepted, O13); on 2026-11-06: open mode (O14), `payNo` (O15), the rows below (O16,
O17), each as recommended.

| # | Question | Answer (owner 2026-11-06, as recommended) |
|---|---|---|
| Q3 | Rounding of PERCENT | **Floor** (`Math.mulDiv`), the rule of `FeePolicy.compute`; ERPs use AMOUNT anyway (§5.5) (O16) |
| Q4 | `taxRecipient` is not signed (O7(2)) and its change is immediate (O6), by any holder, an EOA too (O9) | **Immediate**, with the set-time `R` / `F` checks, the node alert of `OrderRecorded`'s class and the disclosure (O16) |
| Q5 | Bit 23 in `_delayedRelaxBits()` (F-08)? | **No** (§6.1): with single-key holders the owner's revoke must be immediate; alerts and an immediate set-back cover the authority's concern (O16) |
| Q7 | `PayMeta.body` holds several fields in `bytes` for schemas 2 and 3 (CTR-MTX-29) | **`bytes` on chain** (a commitment preimage never parsed, the class of the "kind-specific signature encodings" exception); named fields in node JSON and every client (O16) |
| Q8 | Pays on the mesh | **Not in this group:** refused by name; a later mesh version may add a body (O16) |
| Q9 | Which notice period | **The factory's `noticePeriod()`**, read in the token and passed to the library; the actual value is shown, 0 possible on a test chain (O16) |
| Q10 | The shared `paymeta.json` changes formula while its non-EVM consumers keep the old one until their rounds | **The old file copied to `metatx/legacy/ua-mtx-merge/paymeta.json` and its ~35 non-EVM consumers repointed in T41** (8 node adapters, 7 contract families' tests and generators, `clientkeys`' `near` and `algorand` tests, `ua-qt`'s `tst_ua.qml`, `famvec.py`, `.github/ci_changes.py`, two older gate runners); the v2 tag keeps the formulas apart (O16) |
| Q-M | A taxed mandate payment calling `payWithTax` in this group? | **Deferred** to a later wallet item (new delegate-signed struct, gross or net caps) (O17) |
| Q11 | `payNo`, its bound, schema 2 without `invoiceNo` | **Confirmed** as §3.1 (O15), with the bound 256 bytes (owner correction 2026-11-06) |

## 12. Rules this group adds — SPECIFIED

Each lands in `docs/decisions.md` in T19 with its commit; local labels PT-n map to the ids below (the ids are proposals for T19's register entries).

| Label | Proposed id | Rule (one line) | Section |
|---|---|---|---|
| PT-1 | CTR-MTX-31 | Pay entries are the ERP interface: `(token, payer, payee, entryRef)` is the key; amounts add up (net and tax for taxed rows); a refund is a reverse payment on the same key; a `payId` may be paid many times; pay lanes are free; nonce-lifetime safeguards stay on pruning families | §1, §2.2, §5.4 |
| PT-2 | CTR-MTX-26 Change | `PayMeta { salt, payNo, schema, body }` is the required last parameter of every pay entry; non-zero salt; schema 0 iff empty body; `payNo ≤ 256 B`; `entryRef == metaPayId(meta)` under `scaas.pay.meta.v2`; `PaymentMeta` always emitted | §3 |
| PT-3 | CTR-MTX-27 Change | `UARelayFee` carries `batch` and `nonce`; a relay fee is not pay-once, a signature is; open mode unchanged on every kind (O14) | §4 |
| PT-4 | CTR-AS-18 | `mtxPayWithTax` on the regulated kinds 8–13, public balances only: `UAPayWithTax(payment, taxMode, tax)` signed by the payer, PERCENT checked, AMOUNT as signed, `tax ≤ amount`, split by the payer (payer → payee `amount − tax`, payer → recipient `tax`), the direct twin `payWithTax` for contract payers, the recipient from the token, RK-6 on the tax leg, `PaymentTaxed` with `from` even at 0; no other entry blocked; no tax leg on a confidential op | §5 |
| PT-5 | CTR-AS-19 | One token-wide PERCENT rate: an increase after the factory's notice period, a decrease at once; floor rounding | §6.2 |
| PT-6 | CTR-GOV-21 | Bit 23 `TAX`: power, kinds 8–13, any holder (EOA, `msig`, contract), granted with the issuer seat, not delay-relaxed | §6.1 |
| PT-7 | ARCH-POS-13 | Business identifiers in clear on chain: not recommended, never refused; wallets warn; the three privacy properties | §3.3, §9 |

## 13. Invariants — SPECIFIED

| # | Invariant | Test |
|---|---|---|
| J1 | every pay entry lands only with a well-formed `PayMeta` whose commitment is `entryRef`, and `PaymentMeta` precedes the payment's events (the generic path is outside J1, O12) | `PayMeta.t.sol` |
| J2 | every pay entry consumes exactly `(t.from, t.batch, t.nonce)`; one signature never lands twice across `mtxPay`, `mtxExecuteTransfer`, `mtxPayWithTax`, `mtxPayReceiverFee` | `PayLanes.t.sol` |
| J3 | `mtxPayWithTax`: payer `−(value + fee)`, payee `+(value − tax)`, recipient `+tax`, fee recipient `+fee`; `payWithTax`: caller `−amount`, payee `+(amount − tax)`, recipient `+tax`; deltas added where roles coincide (Codex); both tax moves have the payer as `from`, the payee never sends (O13); `Σ balances == totalSupply` | invariant suite |
| J4 | PERCENT: `tax == floor(value × effectiveRate() / 10^6)`; the effective rate never rises before `eta` | `Tax.t.sol`, fuzz |
| J5 | the tax leg's recipient is the configured `taxRecipient` at execution, never 0, a pool, the token or the payee; the tax leg never moves more than `tax ≤ t.value` of the same call | invariant suite |
| J6 | "+0": kinds 0–5 `transfer`, `mtxTransfer`, `transferToUA`, `mtxExecuteTransfer` read the same slots; gas moves only old → new | `PlusZero.t.sol` |
| J7 | no transfer, pay (other than the tax entries), wrap or confidential entry reads `scaas.regulated` +5, +6 (F-22) | `vm.accesses` per entry, a shielded transfer and an unshield on each of 10–13 with `TAX` set |
| J8 | a relay fee pays only after its exact call ran, on the lane the payer signed | `MtxRelayFee.t.sol` |

## 14. Test plan — SPECIFIED

Red first, positive control first (the same call with a well-formed `PayMeta`, a matching commitment, AMOUNT 0), one change at a
time. Negatives (each must be able to fail): salt 0; schema 0 with a body; schema 1 with an empty body; `payNo` of 257 bytes (256
passes); commitment over another `payNo`; an old-tag `payId` over the same bytes (`PayMetaMismatch`); `payWithFee` with
`entryRef = 0`; `mtxPayMeta`'s selector absent; a pay on `payLane(entryRef)` nonce 0 and on lane 7 nonce 3 both work; two pays of
one `entryRef` both land and both emit `PaymentMeta`; the limitation of O12 pinned: a `UAMetaTransfer` signed for `mtxPay` lands
through `mtxExecuteTransfer` with no `PaymentMeta` and its nonce then refuses `mtxPay`; receiver fee on a free lane, and its co-signature dead after the payer's nonce was used elsewhere;
`MandateWallet` and `HederaMandateWallet` pay with `PayMeta`, and with a mismatched one refused; the relay fee with a stale
nonce, with an old-typehash signature, twice for a replayable mock target (two signatures, pays twice) and for a nonce-guarded
target (second reverts); on 8–13 a relay fee to a frozen bound payee refused and open mode works (the O14 limitation pinned: a frozen submitter is paid through the router);
`mtxPayWithTax` with mode 0 and 3, `tax > amount`, PERCENT off by one unit either way, with `TAX` off, on a plain kind
(`FeatureInvalidForKind(23)` at init), on each of 10–13 by name (a public pay with tax works), recipient frozen and not attested
(`FeeRecipientFrozen`, `NotEligible`), payee == recipient, a frozen payee paid with tax (passes: the tax leg is from the payer); **signed at `r0`, rate
lowered, lands: `TaxMismatch`; signed at `r0`, increase matured at `eta`, lands: `TaxMismatch`** (F-04); a rate increase not
effective at `eta − 1`, effective at `eta`; a decrease at once and cancelling a pending increase; `noticePeriod = 0` applies an
increase at once; `payWithTax`: by a frozen caller refused (`Frozen`), to a frozen payee passes, without `PAYABLE` or `TAX` refused, with a mismatched `PayMeta`, PERCENT off by one, `tax > amount`, payee == recipient each refused, a `MandateWallet`-like contract caller and an EOA caller pass with the books of J3, its selector absent from `mtxSelectors()`; `setTaxRecipient` to a pool, the token, an unregistered UA, a frozen or unattested id refused, a padded native
address accepted; an EOA holder of bit 23 granted after creation beside a contract issuer; init with only bit 23 and an EOA
issuer passes; kind 11 and 13 creation with bit 23 and `taxRecipient = 0` refused (B-5); a shielded transfer and an unshield on
10–13 with `TAX` set emit no `PaymentTaxed` (J7); the `UAPayWithTax` digest in `clientkeys` and `ua-rs` with a non-zero unbound
`relayer` and `feeRecipient`; node: distinct payer and payee sign-check, a landed-elsewhere tax job is `landed`, a meta job never
downgraded on retry, a queued PERCENT job after `TaxRateSet` refused by name.

**Mutants** (one at a time, clean tree, logged `mutant | test that went red | rc`; a survivor is a finding):

| Area | Mutants |
|---|---|
| Meta | `payNo` left out of the hash; the old tag; the salt-0 refusal dropped; the schema/body rule dropped; `_payMeta` after the transfer; the 256-byte bound off by one (255 or 257); `PaymentMeta` skipped |
| Lanes, generic path | `payLane` still enforced in `mtxPayReceiverFee`; `batch` / `nonce` not in `UARelayFee`'s hash; the node still checking `payLane`; the node downgrading a meta job |
| Tax | PERCENT rounding up; `tax ≤ amount` dropped; the tax leg from the payee instead of the payer; the payee credited `amount` instead of `amount − tax`; `payWithTax` without `_regFeeTo(r)`; `payWithTax` taking the payer from an argument instead of the caller; the recipient taken from calldata; `_regFeeTo` skipped on the tax leg; `PaymentTaxed` skipped at 0 or without `from`; the pending rate effective before `eta`; a decrease delayed; `taxRecipient` hashed into the struct (wallet vectors red); the confidential fee rule applied to PERCENT tax on 10–13 |
| Governance | bit 23 accepted on a plain kind; bit 23 put in `_contractOnlyBits()` (an EOA grant goes red); not in `ISSUER_BITS` (init grant red) |
| "+0" | a tax slot read in the base `_uaMove` (J6, J7) |
| Node, clients | `PAY_META_MISMATCH` decoded as `dead`; the tax signer taken as `payment.to`; the inner digest used as the tax job id; schema 2 encoded with `invoiceNo`; `UARelayFee` field order swapped |

## 15. Tasks — SPECIFIED

Written into the merge plan as **T37–T43**, after T36 and before 3c; T19 (docs), T21 (gates), T22 (review) and T23 (PR) cover the
group. Contracts T37 → T38 → T39 → T40 sequential in this worktree (shared `MetaTokenBase`, `ERC20MetaTx`, `RegulatedLib`,
`size-baseline.json`); T41 (`clients/`, `smartcontracts/vectors/`) after T40 fixes the ABI; T42 (node) after T41; T43 beside
T41–T42. Every contracts task ends with the whole `forge test` green at the default set and the size gate; T37 and T40 also run
`script/pqz/at-set.sh <set> test --match-path 'test/{ua,pqz,as/confidential}/*'` at the four sets (one run per work tree,
`PqzSet.sol` restored). Legacy copies (MD-4) are the first commit of each task that replaces a body.

| Task | Content | Depends on | Estimate (agent-days) |
|---|---|---|---|
| T37 | Pay entries: `PayMeta`, `_payMeta`, `metaPayId` v2, `PaymentMeta` with fields; `mtxPay` struct form; `mtxPayReceiverFee`, `payWithFee`, `payWithFeeToUA` with `PayMeta` last; free lanes; `MandateWallet` and `HederaMandateWallet` (entries, tests, KAT, addresses); legacy moves; interfaces and ERC-165 ids; `paymeta.json` regenerated (old copy to legacy); `PayMeta.t.sol`; gas pins old → new; **kind 13 measured first**, stop rule; the four sets | T36 | 3 |
| T38 | Relay fee: `UARelayFee` with `batch`, `nonce` (typehash pin old → new), token `mtxRelayFee`, `MtxRelayFee.relay` (the `RelayPay` struct only if the stack needs it), CREATE2 addresses, `DeployBase` | T37 | 1 |
| T39 | Bit 23 `TAX`: `GovernanceBits` (`ISSUER_BITS`), masks of 8–13, `init` grant and the issuer check; `RegulatedParams.taxRecipient` and the `TokenConfig` ripple; `RegulatedLib` tax bodies and storage +5, +6 (layout pin); two stubs, the struct view, events; two router ops (`UASetTaxRate`, `UASetTaxRecipient`, typehash pins); `selector_audit.json`; `governance_bits.json` bit 23 | T38 | 1.5 |
| T40 | `mtxPayWithTax` on 8–13 (O13's split in `_uaExecuteTransfer`), `PaymentTaxed`; the direct `payWithTax`; `paytax.json` writer; **kind 13 first**, then 8–12, the router and `RegulatedLib`: sizes and deploy gas against §6.4 with the stop rule and the levers; the four sets | T39 | 2.5 |
| T41 | Vectors and clients: `typed_ops.json`, `paytax.json` readers, `clientkeys` builders, the warning and `payNo` checks, `ua-rs` and wrappers, `zether-prover`'s relay-fee builder; the ~35 non-EVM consumers repointed to the legacy `paymeta.json` (Q10); generators re-run, `git diff --exit-code` | T40 | 2 |
| T42 | Node: job shapes with required named meta, pre-checks, the entry sent and never downgraded, the lane checks removed, relay-fee lanes, `UAPayWithTax` signer and outer digest with the distinct-payer/payee and landed-elsewhere cases (C2), rows in three contract classes × six kinds, the mandate rows, error table, pricing of meta bytes, indexer join and feeds, alerts, gateway, mesh refusal, operator-note draft; `CAPPED_MEM=6G` whole suite alone, clippy, e2e on anvil | T41 | 3 |
| T43 | Invariants J1–J8 (handlers over every pay entry, the relay fee, the tax powers, the confidential entries of 10–13) and the mutant harness of §14 | T40; beside T41–T42 | 1.5 |
| T19 (adds) | §9's doc changes, the Change lines of §10, the entries of §12 | T37–T43 | +0.5 |

**Total: 15 agent-days** (14.5 for T37–T43, 0.5 added to T19); the first draft's 12 grew by the mandate wallets, six kinds, kind
13 first, the node's tax signer and join, and the ~35 vector consumers (F-14).

## 16. Risks — SPECIFIED

| # | Risk | Mitigation |
|---|---|---|
| 1 | Clients that relied on on-chain pay-once double-pay a request | O3 stated in docs and the operator note; `payLane` helper kept for the convention; ERPs reconcile by key and sum; refunds are reverse payments on the key |
| 2 | An AMOUNT tax is wrong or over-declared (up to `amount`) | accepted by O6 (checked off chain); `tax ≤ amount`; wallets show `tax` beside `amount`; §5.4's formula makes it an exception, never a closed invoice |
| 3 | A recipient change, by a single key under O9, redirects in-flight taxes (Q4, O16) | set-time checks, node alert, disclosure |
| 4 | Clear `payNo` and bodies leak business data | O5 warning in every wallet; schema 4; §3.3's three properties |
| 5 | Kind 13 crosses 65,536 B; `NormalRegulatedToken` misses 60 M | kind 13 measured first in T37 and T40; reduced by the ordered levers under the 64,512 B stop line (O18); the deploy-gas gap recorded in TODO |
| 6 | The commitment change splits EVM from the other families until their rounds | the v2 tag; Q10; the node computes the formula per family; the legacy vector file keeps their tests green |
| 7 | A second payer-signed payment type confuses wallet display | `UAPayWithTax` nests the whole payment (as `UAReceiverFee`); a display check of one row if T20 has not run |
| 8 | A rate change kills PERCENT payments in flight | §5.5: AMOUNT for ERPs, a named node refusal and re-sign, the ops note |
| 9 | A relayer lands a payment through the generic path without `PaymentMeta` (O12) | accepted by the owner: the ERP reconciles off chain from `entryRef` and its preimage; the node never downgrades a pay job |

## 17. Review disposition

Every item of the two reviews ([Codex](../../research/paytax-codex-review.md), [Fable](../../research/paytax-fable-review.md)):
**adopted** (where), **rejected** (reason) or **closed by owner ruling**.

| Item | Severity | Outcome |
|---|---|---|
| Codex #1 node signer and digest of `UAPayWithTax` | medium | adopted: C2, §7.1, T42 |
| Codex #2 open-mode relay fee bypasses RK-6 | medium | closed by owner ruling O14 (open mode unchanged; the limitation stated in §4.1) |
| Codex #3 pruning families' nonce lifetime | medium | adopted: C3, §2.2, §8 |
| Codex #4 class zero writable | medium | closed by owner ruling O10 (no classes) |
| Codex #5 notice disclosure overstated | low | class half closed by O10; the factory-floor half adopted: §6.2, §6.3 |
| Codex #6 privacy claims | low | adopted: C4, §3.3 |
| Codex #7 metadata publication not signed | low | closed by owner rulings: O11 for the pay entries (§3.2), O12 for the generic path (§2.3: reconciliation off chain); the node's never-downgrade rule kept (§7.1) |
| Codex #8 unversioned tag | info | adopted: C1, `scaas.pay.meta.v2` |
| Codex, J3 with coinciding roles | note | adopted: J3 |
| Codex, transparent kinds restriction | note | closed by owner ruling O8 (8–13, public balances) |
| F-01 `MandateWallet` callers | P1 | adopted: C5, §2.4, T37, operator note |
| F-02 taxed reconciliation | P1 | adopted: C6, §5.4 |
| F-03 relayer strips metadata | P1 | closed by owner rulings: O11 for the pay entries, O12 for the generic path; the node rule, its test and mutant adopted (§7.1, §14) |
| F-04 in-flight `TaxMismatch` | P2 | adopted: C7, §5.5, §14; the suggestion to delay decreases rejected: O10 rules a decrease immediate |
| F-05 `from` in `PaymentTaxed` | P2 | adopted: §5.3 step 6, §5.4 |
| F-06 mode guidance | P2 | adopted: §5.5; the per-class part closed by O10 |
| F-07 withholding agent in the ledger | P2 | closed by owner ruling O13 (P-1, direct split); presentation rule adopted in §5.4 |
| F-08 bit 23 delayed relaxation | P2 | rejected (§6.1, Q5): with any holder (O9) the owner's revoke of a compromised key must be immediate; alerts, immediate set-back and the disclosure cover the authority |
| F-09 tax class published | P2 | closed by owner ruling O10 |
| F-10 entry the node sends | P2 | adopted: §7.1 "The entry sent" (O12 keeps it) |
| F-11 direct `payWithTax` | P2 | closed by owner ruling O13 (P-2): §5.6 |
| F-12 one tag, two formulas; consumer count | P2 | adopted: C1, Q10's corrected list, T41 |
| F-13 size row optimistic; kind 13 stop rule | P2 | adopted, with the owner's O18 (reduce, never `_above64KiB`): §6.4, T37 and T40 |
| F-14 estimates low | P2 | adopted: 15 agent-days |
| F-15 recipient `R` / `F` at set time | P2 | adopted: §6.2 |
| F-16 `payNo` on later partials | P2 | adopted, and settled by O11: every partial carries its `PayMeta` (§2.2) |
| F-17 `_poolMove` caller | P2 | moot: O13's split uses no `_poolMove` (§5.3) |
| F-18 schema ≠ 0 with empty body | P3 | adopted: refused (§3.2) |
| F-19 `ISSUER_BITS`, `_roleBits`, init check | P3 | adopted: §6.1, T39; `_contractOnlyBits()` excluded by O9 |
| F-20 notice period read in the token; 0 on dev chains | P3 | adopted: §6.2, §6.3 |
| F-21 padded native `taxRecipient` | P3 | adopted: valid (§6.2) |
| F-22 J7 wording | P3 | adopted: J7 |
| F-23 slot counts on paper | P3 | adopted: §2.1, §4 |
| F-24 "warn once" undefined | P3 | adopted: once per payee per session, decoded fields always shown (§3.3) |
| F-25 relay pricing of meta bytes | P3 | adopted: §7.1 Pricing |
| F-26 `mtxPay` gas pins | P3 | adopted: §2.1 |
| F-27 rounding note | P3 | adopted: §6.2 |
| F-28 AMOUNT on an untaxable payee | P3 | closed by owner ruling O10 (no classes, no untaxable class) |
| F-29 relay-fee wording | P3 | adopted: §4 |
| Fable Q1 verdict | — | closed by owner ruling O8 |
| Fable Q5 verdict (half) | — | holder half closed by O9; delay half: see F-08 |
| Fable Q6 verdict (keep the generic path) | — | closed by owner ruling O12 (kept, as Fable recommended) |
| Fable Q2 verdict | — | closed by owner ruling O13 (the tax leg is from the payer; no `_poolMove`) |
| Fable Q3, Q4, Q7, Q8, Q9, Q10, Q11 verdicts | — | agreed; answered by the owner as recommended (O15, O16) with F-15, F-20, F-12 folded in |
| Fable §10 missing rows (CTR-ACC, INT-ERP, NODE job-api, regulated §2.2, CTR-GOV-09) | — | adopted in §10, except the CTR-GOV-09 row (bit 23 not delayed, F-08) |
| Fable "missing" 14 refunds | — | adopted: PT-1 |
| A-1 issuer seat, EOA holder | P2 | adopted: §6.1 (with O9) |
| B-1 sizes of 10–13, kind 13 first | P1 | adopted (and ruled by O8): §6.4, T40 |
| B-2 no new hook seat on 10–13 | — | adopted (and ruled by O8): §5.1 |
| B-3 `requireConfidentialSafe` not applicable | — | adopted (and ruled by O8): §5.1 |
| B-4 node rows per contract class | P2 | adopted (and ruled by O8): §7.1, T42 |
| B-5 creation of 11, 13 with bit 23 | P3 | adopted: §14 |
| B-6 Hedera 8, 9 only | P3 | adopted: §1, §5.1 |
