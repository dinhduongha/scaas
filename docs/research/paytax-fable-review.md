> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Requested by the owner (2026-11-05); it reviewed the first draft of [the pay-meta-tax spec](../superpowers/specs/2026-11-05-pay-meta-tax.md). Copied verbatim below.

# Counter-review: `docs/superpowers/specs/2026-11-05-pay-meta-tax.md` (design)

Reviewer: Fable 5.1, read-only, 2026-11-05. Worktree `ua-mtx-merge` at `ee181f0e` + the uncommitted spec. Checked against
`smartcontracts/evm/src/`, `docs/contracts/metatx.md`, `docs/superpowers/specs/2026-11-05-regulated-kinds.md`,
`docs/decisions.md`, `docs/integration.md`, `docs/architecture.md`, `scaas-node/src/`, `clients/`, `smartcontracts/vectors/`.
Owner rulings O1–O7 are not reopened; where one leaves a hole the hole is named. The Codex security pass runs in parallel; this
report is design, economics, integration, node/client impact, size, plan.

Counts: 0 P0, 3 P1, 14 P2, 12 P3.

## Findings

### P1

**F-01 (P1, §2.1, §7, §15 T37) — `MandateWallet` calls the six-argument `payWithFee` / `payWithFeeToUA`; the spec moves both
to seven arguments and the six-argument forms to legacy, and never names the wallet.**
`smartcontracts/evm/src/wallet/MandateWallet.sol:152-153` calls `IERC20Payment(token).payWithFee(addr, amount, FeeMode.NONE, 0,
address(0), entryRef)` and `IMetaTokenV2(token).payWithFeeToUA(payee, amount, FeeMode.NONE, 0, address(0), entryRef)`. §2.1
rows 3–4 change `IERC20Payment` / `IMetaTokenV2` to the `PayMeta`-last forms (row "Replaces: today's six-argument form"). The
wallet then calls a selector no token has: every mandate payment reverts. `HederaMandateWallet` inherits it. Nothing in §2.1,
§7, §9, §15 (T37 files) or the `TokenConfig`-style ripple list names the wallet, its tests (`test/wallet/MandateWallet.t.sol`,
`MandateWalletMerged.t.sol`), its bytecode and CREATE2 address, `mandate_kat.json`, or the node's wallet rows
(`scaas-node/src/typed.rs:127`, `guard.rs:873-924`).
*Fix:* add to §2.1 a row "callers of the direct pay entries: `MandateWallet` (+ Hedera) passes an empty `PayMeta`"; add the wallet,
its tests and address move to T37 and to the operator note (§7.1 last row); state in §2.2 that the wallet's own
`refUsed[entryRef]` (`MandateWallet.sol:48,141,150`) is the wallet's rule and is untouched by O3 (one mandate payment per
`entryRef` per wallet stays; it is not the token's pay-once). Decide and write whether a mandate payment may ever carry
metadata (today it cannot: the wallet has no `meta` argument; O2 "every pay entry" is then satisfied at the token, not at the
wallet, and the doc must say so).

**F-02 (P1, §1 PT-1, §5.3 Books, §9 `integration.md`, §16 risk 2) — The ERP reconciliation rule marks a taxed invoice "final"
on the gross amount while the payee may have received nothing.**
`docs/integration.md:430-435` (and `metatx.md:555-560`, CTR-MTX-03's chain → client rule): `amount_settled = Σ amount` of
`PaymentSettled` matching `(token, payer, payee, entryRef)`; `≥ amount_base` ⇒ final. §5.3 keeps `UAPaymentSettled(from, to,
value, …)` **gross** (tax included) and, in AMOUNT mode, accepts any `tax ≤ value` as signed (O6). A payer that signs
`tax = value` produces a `UAPaymentSettled` for the full invoice amount; the ERP's rule sums it and closes the invoice; the
payee netted 0 and the tax authority holds the money. §16 risk 2 says "the ERP flags a mismatch as a reconciliation exception",
but no rule in §1, §5 or §9 changes the reconciliation formula, and the indexer row today carries only `amount`
(`scaas-node/src/indexer.rs:115-125`: the ERP "reads the new fields only as fields").
*Fix:* write the rule as PT-1's second sentence and in §9's `integration.md` row: for a `PaymentSettled` joined with
`PaymentTaxed`, the ERP books `net = value − tax` as the receivable settlement and `tax` as tax withheld, and closes the request
only when `Σ net ≥ amount_base − expected_tax` **and** `tax == expected_tax` (else exception). State that the gross-sum rule
applies only to rows without `PaymentTaxed`. The node feed row must carry `tax`, `tax_mode`, `tax_recipient`, `net` (§7.1 says
so) **and the join must be defined** (same tx, same token, same `entry_ref`, the `PaymentTaxed` after the `UAPaymentSettled`;
see F-05 on the missing `from`).

**F-03 (P1, §3, §7.1 Mesh, §16) — The on-chain emission of `PayMeta` is at the submitter's discretion: a relayer can strip it.**
`PayMeta` is not signed (O2 keeps the commitment, no typehash); only `entryRef == metaPayId(meta)` is checked (§3.2). Any
relayer holding the signed `UAMetaTransfer` can submit `mtxPay(t, auth, empty)` or `mtxExecuteTransfer(t, auth)` (Q6 keeps it
ungated) and the payment lands with no `PaymentMeta` log: the payer intended a public record (an audit trail for the payee's
accountant, the "sales system" of O1) and gets none; the nonce is consumed, so the record can never be added. "A relayer can
refuse or delay, never forge or alter" (AGENTS) is broken for the metadata half of a payment. The reverse (a relayer adding
metadata the payer kept off chain) needs the preimage, which only a job that carries it has; Q8 keeps such jobs off the mesh.
*Fix:* state the limitation in §3.3 and the docs (CTR-MTX-26 Change): the on-chain log of the metadata is the submitter's act;
a payer who needs it on chain submits through its own node / gateway (`bus.scope = restricted`, INT-ERP-15) or checks the
`PaymentMeta` log on the finalized range and re-issues the metadata by a 0-value… no: by a second payment is impossible on the
same nonce, so the only remedy is **choosing the relayer**. Add a node rule in §7.1: a job whose `meta` is non-empty is sent
only as `mtxPay` with that meta (never downgraded), and a `PaymentMeta`-less landing of such a job is reported to the client
as `meta_dropped` (the node is open; the guarantee belongs in the node spec). Add the test "node never sends empty meta for a
meta job" and the mutant "meta dropped on retry".

### P2

**F-04 (P2, §5.3 step 3, §6.2 Rate, §14) — An immediate rate decrease, a class change, or a matured increase kills every
in-flight PERCENT payment with `TaxMismatch`.**
The payer signs `tax` at rate `r0` (O6: "computed once on `amount`"); the contract checks `tax == floor(value × effectiveRate)`
at execution. `setTaxRate` with a lower value "applies at once", `setTaxClass` is immediate, and a pending increase matures at
`eta`. A payment signed before and landing after any of these reverts `TaxMismatch` (the node's pre-check passed at submit).
With INT-ERP-06's 300 s validity the window is small, but an issuer rate change at a month boundary hits every payment in the
queue, and a wallet-signed payment with a longer `validUntil` is dead. Nothing in §5, §6, §14 names this; the §14 negatives
test the rate at `eta − 1` / `eta` but not a signed-before / landed-after payment.
*Fix:* keep the strict equality (ruled) and (a) write the operational rule in §5.3: the node returns `TAX_MISMATCH` with
`expected` from the revert, the client re-signs; (b) add the negative "signed at `r0`, rate lowered, lands: `TaxMismatch`" and
the node test "re-simulation after `TaxRateSet` refuses the queued job by name, never `dead`"; (c) recommend AMOUNT to ERPs in
§5.3 (they compute the tax anyway and AMOUNT is immune to the race). Consider asking the owner whether a **decrease** should also
wait the notice period for this reason alone (it harms no payer to wait; it kills in-flight payments not to).

**F-05 (P2, §5.3 step 7) — `PaymentTaxed` lacks the payer; the ERP key is `(token, payer, payee, entryRef)`.**
`PaymentTaxed(entryRef, payee, taxRecipient, taxMode, tax, digest)` has no `from`. The indexer's join rule for `PaymentMeta`
requires `from` when the event names it (`indexer.rs:120-121`); for the tax row the join must go through `digest` ↔
`UAMetaTransactionExecuted.digest` or "same tx, same entryRef, preceding `UAPaymentSettled`", none of which the spec writes.
*Fix:* add `bytes32 from` (not indexed; three indexed slots are taken) or drop `digest` for `from`, and write the join rule in
§7.1 Indexer.

**F-06 (P2, §5.3, §6.2 Class, §6.3) — PERCENT by payee class does not match withholding practice; AMOUNT carries it, and the
spec should say which mode is for whom.**
Real withholding is a function of the payer (the withholding agent), the service category and the payee's status, with two or
more taxes per invoice (a contractor's VAT and income tax, both withheld; an individual's PIT), each with its own base (gross
including or excluding VAT) and its own rounding at currency precision. PERCENT here is one rate per payee class, computed on
`t.value`, floored at token precision (Q3). An ERP rounding at currency precision (2 decimals, or integer VND) on a 6- or
18-decimal token will produce a `tax` that differs from the on-chain floor in the last units ⇒ `TaxMismatch` on most invoices.
So in practice: **ERPs use AMOUNT; PERCENT serves wallets and simple single-rate regimes.** Several taxes to several
authorities cannot be split on chain: one `taxRecipient`, one leg.
*Fix:* say so in §5 ("mode guidance") and §6.3 disclosure: AMOUNT for invoices with several taxes or currency-precision
rounding; PERCENT for a single rate; the `taxRecipient` is a collection UA whose holder splits off chain. Add a `paytax.json`
row that shows the currency-rounding mismatch (an amount whose half-up tax differs from floor) so client authors see it.

**F-07 (P2, §5, Books) — The money flow books the *payee* as the one who paid the tax; the withholding agent is the payer.**
O6 (ruled): payer → payee `value`; payee → `taxRecipient` `tax`. On the ERC-20 / UA ledger the `Transfer` / `UATransfer` of the
tax leg is from the payee. An auditor reading the token's transfer log sees the payee remitting, while in a withholding regime
the payer remits on the payee's behalf and the payee receives net plus a withholding certificate. Not reopened; the consequence
is a reporting rule: the indexer row and the ERP must present "payer paid gross `value`, withheld `tax` to `taxRecipient`, payee
received `net`", derived from `PaymentTaxed`, not from the transfer log.
*Fix:* write the presentation rule in §7.1 Indexer and §9 `integration.md`; add `net` and a `withheld_by = from` field to the
feed row. (This is also why F-05's `from` matters.)

**F-08 (P2, Q5 / §6.1) — `TAX` not in `_delayedRelaxBits()` is the wrong direction for a compliance control.**
The regulated spec delays relaxations of 5–7 (CTR-GOV-09, §3.6) because *losing* a control is the harm a regulator cares about.
Disabling `TAX`, revoking bit 23, or `setTaxRecipient` to the issuer's own UA (Q4) stops or redirects collection at once. The
spec's reason ("harms no holder") takes the token holder's view, not the authority's. `revokeRole(23)` is not delayed either.
*Fix:* put 23 in `_delayedRelaxBits()` (the `disableFeature` / `revokeRole` of bit 23 wait `grantDelay`, as 5–7), and add a
runbook row in the regulated spec's §3.6 table: "compromised `TAX` holder: at once another root `setTaxRecipient` back / owner
`revokeRole` after `grantDelay`". If the owner keeps it immediate, say in §6.3 that an owner can stop tax collection at once.

**F-09 (P2, §6.2 Class, §6.3, §9) — `TaxClassSet(account, class)` publishes a party classification in clear, forever.**
A class is "individual / foreign contractor / exempt" in every real policy. This is a stronger data-protection point than a
`payNo` (architecture §10 item 1, ARCH-POS-04): it is set by the issuer, not chosen by the payer, and the payer is not warned.
*Fix:* rule that class numbers are opaque (their meaning lives in the issuer's off-chain policy; `governance_bits.json` sentence
for bit 23 says "the class is a number with no on-chain meaning"); wallets show the number and the resulting rate only.

**F-10 (P2, Q6, §7.1 Job shape) — Which entry the node sends for a plain pay with empty meta is not stated, and the gate
differs.**
Today `guard.rs:1038` lists `mtxPay` as *not* a job row; a pay relays as `mtxExecuteTransfer` (ungated) or `mtxPayMeta`
(`PAYABLE`-gated) (`submit.rs:290-291`, `job-api.md:151-153`). §7.1 says a pay job is `{entry: "mtxPay", …, meta?}`. If the
node now sends `mtxPay` for every pay, a payment to a token without `PAYABLE` (bit 0 off at creation, `GovernanceBits.sol:34`
`ALWAYS_LOCKED`) fails where it works today.
*Fix:* one line in §7.1: empty meta ⇒ `mtxExecuteTransfer` as today; non-empty ⇒ `mtxPay`; `mtxPayWithTax` always. Or: always
`mtxPay` and say the gate now applies to every relayed pay (operator note).

**F-11 (P2, §5.3, §1 non-goals) — No direct `payWithTax`: a contract payer (treasury contract, `MandateWallet`, a Safe) cannot
pay tax on chain.**
`payWithFee` / `payWithFeeToUA` are the direct twins of `mtxPay`; tax exists only on the relayed `mtxPayWithTax`. A corporate
payer that pays from a contract wallet (the common case for the "withholding agent") has no tax path. "Every `mtx*` is
relayable" is met; the direct side is simply absent.
*Fix:* either add `payWithTax(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef, PayMeta meta)` on
kinds 8, 9 (same body, `msg.sender` payer; +0.4–0.6 KB on two kinds) or write it as a non-goal with the reason and the
workaround (a contract signs `UAPayWithTax` by ERC-1271 and a relayer submits).

**F-12 (P2, §3.1, Q10) — The same derivation string `"scaas.pay.meta"` now names two formulas across families.**
§3.1: "the derivation string is unchanged". EVM, the node's EVM path, `clientkeys` and `ua-rs` compute
`keccak("scaas.pay.meta" ‖ salt ‖ keccak(abi.encode(payNo, schema, body)))`; eight node adapters
(`scaas-node/src/adapters/{algorand,aptos,cosmos,near,solana,soroban,sui,ton}.rs`), seven contract families' tests and
generators, `clients/clientkeys/test/{near,algorand}.test.js:15-16` and `clients/ua-qt/tests/tst_ua.qml:424` keep
`keccak("scaas.pay.meta" ‖ salt ‖ keccak(abi.encode(schema, body)))`. A mixed-family client has no way to tell which
formula a `payId` was built with except by family; the AGENTS trap "editing one reproducer alone is a defect" is exactly this.
Also the spec's count is wrong: "three node adapters" is eight; `clientkeys` has two non-EVM tests of the file; `ua-qt` reads it.
*Fix:* version the label (`"scaas.pay.meta.2"` or `"scaas.pay.meta" ‖ 0x02`): a wrong-formula client fails by name
(`PayMetaMismatch`) on every family, and the vectors say which formula they are. Correct the consumer list in Q10 / T41 (35
files incl. `.github/ci_changes.py`) and the T41 estimate.

**F-13 (P2, §6.4) — The all-kinds size row (−0.2 to +0.6 KB) is optimistic; kind 13 has no stop rule.**
Four entries gain a calldata struct with two dynamic members (`string payNo`, `bytes body`): the legacy codegen emits a
calldata validator per entry (~250–450 B each), plus `abi.encode(string, uint16, bytes)` and an event with a `string` and a
`bytes` in `_payMeta`, plus `mtxPay`'s `UAMetaTransfer` calldata decoder. The removed bodies (`mtxPayMeta`, `_uaPayMeta`,
`_uaPay`, `MetaTokenBase.sol:224-261`) are ~0.5 KB. Net on every kind is more likely +1.0 to +2.0 KB. The regulated spec's own
note: "the governance record ran 2–5 × over earlier estimates". `WrappedPqzRegulatedToken`'s margin under 65,536 B is 3.8–5.5
KB *before* this group (regulated §6.2); the regulated hooks are not measured yet (T27 pending). The "stop if > 50 % over"
rule in §6.4 covers T40 (kinds 8, 9) only.
*Fix:* give T37 the same stop rule for kind 13 (`_above64KiB` row with the reason, as regulated §6.2 says), and measure the
all-kinds delta on kind 13 first (one entry converted, then the rest).

**F-14 (P2, §15) — Estimates are low by about a third.**
T37 (2 d): the `mtxPay` struct form touches 25 forge test files (`grep payLane`: 45 lines; `mtxPay(`/`metaPayId`/`payWithFee`
callers in `test/` and `script/`), the Hedera tests (`HederaV2.t.sol`, `HederaKat.t.sol`), the wallet (F-01), two interfaces'
ERC-165 ids, `PayMeta.t.sol`'s writer, and the four PQZ set runs (one run per work tree, serial; ~hours). T42 (2 d): a new job
shape with four named body schemas, 37 `payLane` / `pay_lane` test lines in `scaas-node/src`, mesh refusal, gateway, indexer
join (F-02, F-05), feeds, alerts, errors, operator note, the whole suite at 6 GB alone plus e2e. T41 (1.5 d): 35 consumers
(F-12). Realistic: T37 3, T41 2, T42 3, T43 1.5 ⇒ 14.5–15 agent-days, not 12.

**F-15 (P2, Q4, §6.2 Recipient) — `setTaxRecipient` checks `_checkTo` only; under `ALLOWLIST` an unattested recipient
blocks every taxed payment.**
§5.3 step 4: `_regFeeTo(r, tax)` ⇒ `!R(r)` ⇒ `NotEligible` at every payment. §6.2 "checked at set time only (a record never
changes kind)" checks registration, not `R`. An issuer that sets a recipient not yet attested (or whose attester is disabled,
regulated §5) turns every `mtxPayWithTax` into a refusal until fixed; the node sees `NotEligible` on the *recipient*, which the
error names, but wallets show the payee.
*Fix:* `setTaxRecipient` also requires `R(r)` and `!F(r)` at set time (two cheap reads); the node's alert on
`TaxRecipientSet` includes `canReceive(r)`; the error at pay time stays.

**F-16 (P2, §2.2, §3.2, §7.1) — Partial payments and metadata: the second partial's feed row has no `payNo`.**
§2.2: the first partial carries `PayMeta` (emitted once), later ones an empty `PayMeta` "no second log, same key". The indexer
gives `meta` to the first later `PaymentSettled` in the same tx (`indexer.rs:120`), so the ERP sees `pay_no` on row 1 only and
must map `entry_ref → payNo` itself. That is fine, but the spec presents "empty on later partials" as the rule; the contract
accepts a non-empty `PayMeta` on every partial (same commitment, one log each) and some sales systems want each receipt
self-describing.
*Fix:* write both as allowed ("the client chooses; each non-empty `PayMeta` costs one log") and tell the ERP to key by
`entry_ref` (§9 `integration.md` row).

**F-17 (P2, §5.3 step 6, Q2, regulated spec §2.2 / §9) — The tax leg on `_poolMove` is a third caller of the hook-free move;
the regulated spec's mutant table treats a `_poolMove` caller as a bypass.**
Regulated §2.2: `_poolMove` carries no hook because it carries decoy fees and forced transfers; risk 4 and mutant "MODERATE
moved on `_poolMove`" guard against new callers. Q2's answer (no `F(payee)` on the tax leg, `_regFeeTo(r, tax)` at step 4)
is right for the economics (the payee just received `value ≥ tax`; a frozen payee still receives, CTR-AS-05), but the
regulated spec must list the tax leg among `_poolMove`'s sanctioned callers and I3 must be read as a per-call delta (the frozen
payee's balance rises by `value − tax`).
*Fix:* a Change line for the regulated spec §2.2 ("`_poolMove` callers: decoy fees, `forceTransfer`, the tax leg of
`mtxPayWithTax` whose recipient passed `_regFeeTo`") and the J5 invariant "the tax leg's `from` is `t.to` of the same call and
`tax ≤ t.value`" (the spec's mutant "tax leg from the payer" covers half of it).

### P3

**F-18 (P3, §3.2)** — `schema ≠ 0` with an empty `body` (schema 1 with no note, schema 4 with no ciphertext) is not refused;
only `schema == 0 ∧ body ≠ empty` is. Harmless (never parsed) but asymmetric. Refuse `schema ≠ 0 ∧ body == empty` or state it
is allowed.

**F-19 (P3, §6.1, §15 T39)** — `init` grants the issuer by `features & GovernanceBits.ISSUER_BITS`
(`GovernanceLib.sol:120`), not `REGULATED_ROLES`. §6.1 names only `REGULATED_ROLES` gaining 23; `ISSUER_BITS`, `_roleBits()`
and `_contractOnlyBits()` of kinds 8, 9 must gain 23 too (and `RoleWithoutFeature(FREEZE)` fires today when the issuer holds
only bit 23: `GovernanceLib.sol:121`). List them in T39.

**F-20 (P3, Q9, §6.2 Rate)** — `noticePeriod` is an immutable of `OpenFactory` (`OpenFactory.sol:40`, ≤ 30 d,
`MAX_NOTICE_PERIOD`); the token's `FACTORY` is an immutable (`MetaTokenBase.sol:38`) invisible inside `RegulatedLib`'s
`DELEGATECALL` (regulated F-05). The token must read `IOpenFactory(FACTORY).noticePeriod()` and pass it to the library; say so.
A dev chain with `noticePeriod = 0` gets no rate notice; say so in the disclosure.

**F-21 (P3, §6.2 Recipient)** — "a UA (`bytes32`)" and "a derived id registered SIGNING (`_checkTo`)": `_checkTo`
(`MtxPipelineLib.sol:260-270`) accepts a zero-padded native address too. State whether a tax authority's contract address
(padded) is a valid `taxRecipient`; it is the likely real case.

**F-22 (P3, §13 J7)** — "no entry other than `mtxPayWithTax` reads `scaas.regulated` +5…+7" is false by construction: the three
setters, `taxConfig()`, `taxRateOf()`, `taxClassOf()` read them. Word J7 as "no transfer, pay, wrap or confidential entry
reads +5…+7".

**F-23 (P3, §2.1)** — The slot count for `mtxPayReceiverFee` (7) and the token's `mtxRelayFee` (9 + `auth`) is asserted on
paper; only the router gets "measured in T38". `_uaPay` already takes nine arguments (`MetaTokenBase.sol:247-250`); the
widened `mtxRelayFee` builds the struct from nine plus `msg.sender`. Give both the router's caveat (a `RelayPay` struct if the
stack needs it).

**F-24 (P3, §3.3)** — "Wallets warn **once**" is undefined (per install? per payee? per schema?). A one-time warning protects
nobody after the first click. Recommend "once per payee per session, and the decoded fields always shown beside the typed
data" (CTR-MTX-26's existing wallet rule).

**F-25 (P3, §7.1, §16)** — Relay pricing of metadata bytes is not mentioned: a 2,048 B body costs the relayer ~33 k calldata
gas plus the EIP-7976 floor, against a fee capped at 1 % of `value` (CTR-MTX-13). Small payments with large bodies are
unprofitable to relay; the node's price model must count `payNo + body` bytes (NODE pricing row) or the operator note says
meta jobs are restricted-scope only.

**F-26 (P3, §5.3 Books, §13 J6)** — `MetaTxGasV2`'s `mtxPay` / `mtxPayMeta` rows (`metatx.md:819-820`: 53,868 / 57,344) move
with the struct form and the `PayMeta` decode on every call; the spec pins only the plain kinds' transfers (J6). Say "gas pins of
`mtxPay` move old → new in T37's commit".

**F-27 (P3, Q3)** — Floor is right for one rule in the codebase (`FeePolicy.compute`, `FeePolicy.sol:45`). Note in §6.2 that
`Math.mulDiv(amount, rate, 1e6)` with `rate ≤ 1e6` cannot overflow and that `amount = 2^255` rows in `paytax.json` are the
edge; and (F-06) that ERPs rounding at currency precision will not match PERCENT.

**F-28 (P3, §5.3, O7(1), §16 risk 2)** — AMOUNT lets a payer tax an untaxable payee (class 0) by any `tax ≤ value`; the payee
cannot refuse (no co-signature) and learns after landing. A cheap guard inside the rulings: for `tax ≠ 0` require
`taxClassOf(t.to) ≠ 0` (a registered taxable payee); O7(1) says the class "serves only the PERCENT rate lookup", so this needs
the owner's word. Raise it as Q12 rather than leave the payee unprotected.

**F-29 (P3, §4)** — "In practice the target call has its own nonce or guard, so the second `relay` reverts at the target": the
payer's second payment needs a second `UARelayFee` signature (new nonce), so the only double-pay path is the payer signing twice;
the sentence reads as if one signature could run twice. Reword: pay-once of the *signature* holds by the nonce; pay-twice needs
two signatures and a target that accepts the call twice.

## Verdicts on Q1–Q11

| Q | Verdict | Reason |
|---|---|---|
| Q1 kinds 8, 9 only | **Agree** | `mtxPay` exists on every kind (`NormalZetherToken is NormalToken, ZetherLayer`, both over `MetaTokenBase`), so a public pay on 10, 11 is taxable later without a rule change; O6's reason (amount hidden) applies to Zether as to PQZ; Zether ≠ PQZ is kept by naming 10–13 as "refuse bit 23" each. Add the four kinds to the `FeatureInvalidForKind(23)` test by name. |
| Q2 tax leg on `_poolMove`, no `F(payee)` | **Agree**, with F-17 | Credits are never refused for a freeze (CTR-AS-05); the leg moves part of the same call's credit. The regulated spec must list the caller and the J5/I3 wording must follow. |
| Q3 floor | **Agree** | One rule (`FeePolicy.compute`); F-06/F-27: say that ERPs will use AMOUNT. |
| Q4 recipient change immediate | **Agree as ruled, with F-08 and F-15** | The payer is not harmed (same `tax`); the authority is. The runbook row and the delayed `disableFeature` / `revokeRole` of bit 23 are the mitigation that costs nothing. |
| Q5 contract-only + `msig`, not delay-relaxed | **Half** | Contract-only with the `msig` rule: agree (RK-1). Not in `_delayedRelaxBits()`: **disagree** (F-08): disabling tax at once is the relaxation a regulator cares about. |
| Q6 keep `mtxExecuteTransfer` for payments | **Agree, with F-10** | Tender's deposit and the node's batches use it; the node must say which entry it sends for an empty-meta pay. |
| Q7 `bytes body` on chain | **Agree** | The contract never parses it; schema 4 is a ciphertext; a decoder per schema in every kind is the wrong trade. The CTR-MTX-29 Change line is needed (owner rule); write the exception as "the hash preimage of a commitment the contract never parses", which is the same class as the existing "kind-specific signature encodings" exception. |
| Q8 no meta / tax on the mesh | **Agree** | A mesh body for meta would carry up to 2 KB per job and the stripping problem (F-03) gets worse with unknown relayers. |
| Q9 factory `noticePeriod` | **Agree, with F-20** | No new config; the mechanics (read in the token, pass to the library; 0 on dev chains) must be written. |
| Q10 legacy copy, repoint non-EVM consumers | **Agree on the mechanism, with F-12** | Fix the count (8 adapters, 2 `clientkeys` tests, `ua-qt`, 7 families, `ci_changes.py`) and version the label so the two formulas cannot be confused. |
| Q11 `payNo`, 64 B, schema 2 without `invoiceNo` | **Agree** | ISO 20022 `Max35Text` fits; 64 B is 16 CJK characters, enough for a document number; the text checks (UTF-8, bidi) belong in clients as written. One addition: say `payNo` is compared byte-wise by the ERP (no normalisation on chain). |

## §10 conflict list

Agree with every row. Missing rows:

- **CTR-ACC (MandateWallet)**: `payWithFee` / `payWithFeeToUA` callers (F-01); the wallet's `refUsed` pay-once is the wallet's
  rule, unchanged.
- **INT-ERP chain → client rule** (`integration.md` §7, `metatx.md` CTR-MTX-03's "Σ amount ⇒ final"): the taxed-payment
  reconciliation formula (F-02).
- **NODE job-api "Pay-meta and relay-fee jobs"** (`job-api.md:148-158`): the `batch == payLane`, `nonce == 0` checks go, the job
  shape changes, `mtxPay` becomes a row (`guard.rs:1038` `NOT_ROWS`).
- **Regulated spec §2.2 `_poolMove` callers and §9 mutants** (F-17).
- **CTR-GOV-09 / regulated §3.6** if bit 23 joins `_delayedRelaxBits()` (F-08).

## Missing from the spec

1. `MandateWallet` / `HederaMandateWallet` as callers of the direct pay entries (F-01).
2. The ERP's reconciliation formula for a taxed payment: gross vs net, `tax == expected` (F-02).
3. The relayer's power to strip metadata; the node rule that a meta job is never downgraded (F-03).
4. In-flight `TaxMismatch` after a rate / class change: ops rule, node error flow, negative test (F-04).
5. `from` in `PaymentTaxed` and the indexer join for the tax row (F-05, F-07).
6. Mode guidance (AMOUNT for ERPs and multi-tax invoices; PERCENT for single-rate wallets); one recipient, off-chain split
   (F-06).
7. A direct `payWithTax` or its explicit non-goal (F-11).
8. Tax class as public classification: opaque numbers, disclosure (F-09).
9. Runbook row for a compromised `TAX` holder; delayed relaxation of bit 23 (F-08).
10. `ISSUER_BITS`, `_roleBits`, `_contractOnlyBits` for bit 23; `noticePeriod` read in the token (F-19, F-20).
11. Native (padded) address as `taxRecipient`; `R(r)` at set time (F-15, F-21).
12. Relay pricing of metadata bytes (F-25); `mtxPay` gas pins moving (F-26).
13. A versioned derivation label and the full consumer list of `paymeta.json` (F-12).
14. Refund / credit note after an over-declared tax or an overpayment: `integration.md:1056` says "manual refund"; with pay-once
    gone, overpayment by retry becomes the common case (§16 risk 1) and a compensating payment from payee to payer carries the
    key with roles swapped. One sentence in PT-1: a refund is a new payment payee → payer with the same `entryRef`; the ERP's
    key includes direction.
15. The AMOUNT-mode guard for untaxable payees as an owner question (F-28).

## Checked and found sound

- The commitment `keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(abi.encode(payNo, schema, body))))` is
  unambiguous (`abi.encode` of dynamic types is length-prefixed); the zero-salt refusal keeps CTR-MTX-03's brute-force
  argument; `entryRef` stays unlinkable with a random salt.
- Free lanes are safe against replay: every pay entry consumes `(from, batch, nonce)` in `MtxPipelineLib.preTransferUA`
  (`ERC20MetaTx.sol:250-259`); `UAReceiverFee` nests the whole `UAMetaTransfer` so RP2 (co-signature once) still holds
  (`MtxPipelineLib.sol:152-157`); `UAPayWithTax` nesting `payment` with `_structHash(t)` and canonical zeros follows the same
  pattern, so the unbound-`relayer` / `feeRecipient` vectors rule applies and the spec says to test it.
- The receiver-fee shape after O3 (§2.3) keeps every term of CTR-MTX-06 except the two lane terms; the frozen-payee rule of the
  regulated spec (owner call 2) stays.
- The `UARelayFee` change: `relayRef` (`MetaTokenBase.sol:312-314`, `MtxRelayFee.sol:76-78`) is untouched, so `relayref.json`
  is indeed unchanged; the router's `relayer = msg.sender` binding (`_relayHash`, line 320) still makes a non-router caller fail
  the signature; the new typehash moves `clients/zether-prover/src/typed.rs:41`, `scaas-node/src/typed.rs:151`,
  `clients/clientkeys/src/evm.js:153` as §7.2 lists.
- Tax ordering: `_regFeeTo(r, tax)` before `_uaExecuteTransfer` costs no signature check on a refused recipient (regulated
  F-09); `r ≠ t.to` before effects mirrors `FeeRecipientIsPayee`; the payer's fee basis `t.value` is CTR-MTX-13's basis; the
  fee never goes to the payee (CTR-MTX-08) and the tax never goes to the payee (`TaxRecipientIsPayee`).
- Bit 23 is the first free SCaaS-band bit after 22 (`GovernanceBits.sol:25`); 13 and 14 stay unused (CTR-GOV-14); plain kinds
  refuse it by `_validBits()` (CTR-GOV-10 Change), so "+0" (CTR-GOV-11) holds by construction with no hook change (O7(1)).
- `erc7201:scaas.regulated` +5…+7 appended after the regulated spec's +0…+4: layout pin moves old → new as required.
- Hedera: `hedera_kat.json` has no `mtxPay` row (checked), so "unchanged" holds; HIP-632 signs a digest, so the nested struct
  needs no Hedera change.
- `RegulatedLib` is already in `Env.libs` for kinds 8–13 (regulated §6.1), so no `LinkClosure` change: correct.
- The router's CREATE2 address moving again is consistent with regulated §6.1 (M-07) and reset 2.
- The node's `max_pay_meta_bytes` (2,048, `adapter.rs:686`, `submit.rs:2134`) counting `payNo + body` is consistent with
  Algorand's 507 B and NEAR's 2,048 B caps (CTR-MTX-26), each family keeping its own.
- The task order (T37 → T40 serial on shared files; T41/T42 after the ABI; T43 beside) is right; MD-4 legacy copies first is
  consistent with "backup, do not delete".

## Addendum: the two owner rulings of 2026-11-05 (received during this review)

**R-A: bit 23 `TAX` may be held by an EOA, an `msig` or a contract** (Q5's contract-only half overruled).
**R-B: tax on every regulated kind 8–13; `mtxPayWithTax` moves public balances on the confidential kinds too; confidential
transfers carry no tax leg** (Q1 overruled).

What they change, judged against the code:

**A-1 (P2, §6.1, T39) — Holder rule.** Bit 23 goes to `_roleBits()` of 8–13 and **not** to `_contractOnlyBits()` or
`GovernanceBits.REGULATED_ROLES` (`GovernanceBits.sol:34-35`); the `msig` clause of RK-1 is moot for it (any holder). Keep
`init`'s grant to `roles.issuer` (`ISSUER_BITS` gains 23, F-19) but note the consequence: `GovernanceLib.init` grants the one
`roles.issuer` id every issuer bit set (`GovernanceLib.sol:119-122`), and 5–7 require a contract or `msig`; a token that wants
a contract for FREEZE/PAUSE and an EOA for TAX cannot express it in `TokenConfig` and must `grantRole(23, eoa)` after creation
(two calls under `grantDelay`, CTR-GOV-04). Write that in §6.1 and the disclosure. An EOA holder makes F-08 (immediate
`setTaxRecipient`, no delayed relaxation) sharper: a single key redirects tax revenue at once; `LIMITED` grants do not bound
`setTaxRecipient` (no scalar). Recommend at least `TaxRecipientSet` as a node alert of the same class as `OrderRecorded`.

**B-1 (P1, §6.4, §15 T40) — Sizes of 10–13.** The per-kind tax row (+1.0 to +1.6 KB: `mtxPayWithTax`, three stubs, views)
now lands on six releases, not two. Kind 13: `WrappedPqzToken` 56,507 B today (`size-baseline.json`), regulated estimate
59.5–61.2 K (regulated §6.2, unmeasured: T27 pending), plus this group's all-kinds row (spec +0.6 KB, F-13 says +1.0–2.0 KB)
plus the tax row ⇒ **61.1–64.8 K**: the 65,536 B jump-width cliff is inside the estimate's range for the first time. Kinds 11
and 12 (51.4 K / 47.0 K today) stay under it with 6–9 KB to spare. `NormalPqzRegulatedToken` and the Zether regulated kinds
already miss 60/70 M (accepted); the asked gas grows ~2–4 M more each. *Fix:* T40 measures kind 13 **first** (as T27 does for
the regulated hooks), with the stop rule; the levers inside the rulings, in order: one struct view `taxConfig()` returning
`{taxRecipient, enabled}` and `taxRateOf` returning the struct (fewer selectors, M-07's pattern); the three stubs as thin
`DELEGATECALL`s with no local decoding; the `PaymentTaxed` emit inside `RegulatedLib` (events emitted from a library carry
the token's address under `DELEGATECALL`); and, if still over, the `_above64KiB` row for kind 13 with the reason (CTR-GOV-19
allows it on the SCaaS testnet). Do not plan a library split of the move (`_uaExecuteTransfer` is internal to the token).

**B-2 (sound) — The confidential kinds' public pay path exists and is checked.** `NormalZetherToken is NormalToken,
ZetherLayer` and the PQZ kinds inherit `MetaTokenBase`, so `mtxPay`, `mtxExecuteTransfer` and the UA ledger are the same
public path on 2–5 and 10–13 (`ERC20MetaTx.sol:222-259`). On a regulated confidential kind a public pay runs `_regPre(from, 0,
mode)` (the confidential pre row reads nothing when not fee-bearing, regulated §3.2) and then `_regMove` on `_uaMove` with `P`,
`F(from)`, `R(to)` (the "transfer … pay" ledger row applies to every kind 8–13). So `mtxPayWithTax` on 10–13 needs **no new
hook seat**: the payer leg is the hooked `_uaExecuteTransfer`, the tax leg is `_poolMove` guarded by `_regFeeTo` (step 4,
F-17), exactly as on 8, 9. "Confidential transfers carry no tax leg" means no site in `ZetherLayer`, `PqzLayer` or the
libraries: Zether ≠ PQZ stays untouched, no statement, transcript or binding tag moves (§1 non-goals hold). Write B-2 into §5.1
in place of "kinds 8, 9" and add to §14 a test per confidential kind: a shielded transfer and an unshield on a token with `TAX`
set emit no `PaymentTaxed` and read none of +5…+7 (`vm.accesses`, J7).

**B-3 (sound; answer: no) — `FeePolicy.requireConfidentialSafe` / `PercentFeeForbiddenOnConfidential` must not apply to a
PERCENT tax on a public pay.** The rule exists because `fee = v × p` with public `fee`, `p` reveals a hidden `v`
(`FeePolicy.sol:62-75`). On `mtxPayWithTax` the amount `t.value` is public calldata and is emitted in `UAPaymentSettled`; a
PERCENT tax reveals nothing the payment did not. The code agrees: `requireConfidentialSafe` has no caller in `src/` (checked);
the confidential rule is enforced by the `ABSOLUTE` fee class of the confidential selectors in `MtxPipelineLib._checkCall`
(CTR-MTX-20), and a public `UAMetaTransfer` on a Zether kind already takes a PERCENT **fee** through `_checkTransfer`
(`MtxPipelineLib.sol:238-245`). Keep PERCENT and AMOUNT on every regulated kind; state in §5.2 that the tax modes are the
public fee modes' numbers and the confidential fee rule is out of scope because no confidential op carries a tax leg.

**B-4 (P2, §7.1, T42) — Node rows per contract class.** The node's typed table keys rows by contract class (`typed.rs:1591`:
`("UARelayFee", "token" | "pqz" | "zether")`), so `UAPayWithTax` needs a row in each of the three classes and the per-kind
equality tests (kinds 8–13 both directions) cover six kinds, not two; `selector_audit.json` gains `mtxPayWithTax` on six
kinds. T42's estimate grows accordingly (F-14).

**B-5 (P3, §6.2 Creation) — `RegulatedParams.taxRecipient` on the confidential kinds** flows through `ZetherWrappedLib.init`
and `PqzWrappedLib.init` (regulated §2.4: they decode `TokenConfig` and call `RegulatedLib.init(cfg.reg, …)`), so the field
reaches them with no extra encoder; the `TokenConfig` ripple list of the spec already names both. Sound, but T39's test list
should include a kind-11 and a kind-13 creation with bit 23 set and `taxRecipient` 0 ⇒ `RegulatedConfigInvalid()`.

**B-6 (P3, §8 Family impact)** — "Tax follows a family only with its regulated kinds (none exists outside EVM today)" is
unchanged by R-B. Hedera: 10–13 are not on Hedera (regulated §6.1), so Hedera takes tax on 8, 9 only; say so in §1.

Net effect on the verdicts: Q1 and the holder half of Q5 are closed by the owner; F-08 (delayed relaxation of bit 23), F-13 /
B-1 (kind 13 size) and F-15 (recipient `R` at set time) gain weight; nothing else in the findings changes.
