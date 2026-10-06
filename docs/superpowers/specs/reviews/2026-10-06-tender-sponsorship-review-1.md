# Review 1: component spec B (tender, sponsorship, receiver-pays, shredding), rev 1.1

Reviewer: Claude subagent, adversarial design review. Read-only, no builds.
Read: the spec (all 999 lines); `MetaTxCore.sol`, `MetaTokenBase.sol`, `MetaTxLib.sol`, `FeePolicy.sol`,
`ERC20MetaTx.sol` / `MetaToken.sol` (v1), `IOpenFactory*.sol`, `OpenFactoryV2.sol`, `HederaTokensV2.sol`,
`SubjectAccount.sol`, `IMetaTokenV2.sol`; NI rev 3.3 §4, §5.2, R100–R103, R111; MESH R84, R86; TW2 R132, R138–R140, §10.
Owner rulings were not re-litigated (commit-reveal + deposit, disqualification with reason, node + later pool
sponsorship, receiver-pays v2-only, client-held salts).

## Verdict: **FIX-THEN-GO**

The tender's main money path is sound. I checked it against the code:

- **Nobody can land the deposit outside `commitBid`.** In both the v1 path (`ERC20MetaTx.sol:67`) and the v2 path
  (`MetaTxCore._execute` step 1), the relayer check runs before anything else. Every v2 entry point (`mtxPay`,
  `mtxBatch`, `executeMetaTransaction*`) goes through `_execute` with `msg.sender` set to the caller, so
  `relayer = tender` cannot be satisfied anywhere except a call made by the tender.
- **The intent cannot be replayed into another tender, another tenderId or another chain.** `depositRef` binds it.
- **Fee mode NONE always computes a fee of 0** (`FeePolicy.compute`).
- **META tokens have no fee-on-transfer**, so the balance-delta check is redundant but harmless.
- **R186 provenance means something.** `registerImplementation`/`deprecate` are `onlyRegistrar`, and unregistered
  clones have version 0, which yields `implementationOf == 0`.

Four findings must be fixed before implementation:

- Receiver-pays reverts on every node that has a `chains.fee_recipient` set (H2).
- Receiver-pays quietly needs a hot key that controls the whole payee account (H3).
- Shredding claims that backups are erased when they are not (H4).
- Reveal and commit liveness depends on the buyer, who keeps the forfeits (H1).

The other findings are medium or low. Several of them make the spec smaller.

---

## High

### H1. Reveal and commit liveness depends on the party that receives the forfeits (§A.5.2–A.5.3, R182, R183, §A.7.1)

**Problem.** A.5.3 says "bidders hold no native coin". The buyer sponsors `commitBid`/`revealBid`, and A.5.2 steps 3–4
route the commit and the reveal hand-over through the buyer's portal. R183 sends non-reveal forfeits to the buyer
organisation's `slashSink`. R183 argues that forfeits "do not change the buyer's incentives", but that only holds if
the buyer cannot affect whether a bidder reveals. Here it can.

**Attack.**

1. During the reveal window, the buyer pauses its sponsor policy or lets its portal sit on the handed-over
   `(price, salt)`. `PUT …/state paused` is an operator action, audited but legal.
2. A gasless bidder's fallback is "submit elsewhere (permissionless, any relayer or a direct transaction)". Nothing
   pays for that: `revealBid` carries no fee field, R75 has no mesh reward, and `call` jobs need `allow_call` in some
   namespace.
3. The bidder's deposit forfeits to the buyer. The buyer can do this selectively, to a strong competitor, which also
   removes that competitor's price from the tender.

The same works at commit: the portal can hold a competitor's signed deposit intent (`validUntil ≤ 1 h`) until it
expires or until `commitDeadline` passes.

**Fix (spec text, no contract change).**

- Drop "bidders hold no native coin" as a safety assumption.
- A.5.2 must require an **independent reveal path** that the buyer does not control: the bidder's own node namespace
  with its own sponsor policy or gas, or a `~gateway` policy run by a neutral operator.
- The bidder ERP/app refuses to sign a deposit intent unless such a path is configured for that chain.
- Add a row to A.7.1: "buyer withholds sponsorship or a handed-over reveal ⇒ forfeit to buyer".
- Correct R183's rationale: forfeits to the buyer are acceptable only because the bidder has an independent path.

### H2. R100 normalization makes every `mtxPayReceiverFee` revert (§B2.2 step 1, §B2.5; NI R100, MESH R84)

**Problem.** B2.2 step 1 requires `m.feeRecipient == 0`, otherwise `ReceiverFeeShape`. NI R100 applies R84
normalization to **every origin, including job-API jobs**: when `MODE_RESTRICT_FEE_RECIPIENT` is off,
`feeRecipient := chains.fee_recipient or 0`.

The payer intent here has fee NONE and an unbound recipient, so a node with `chains.fee_recipient` set rewrites it to
non-zero at accept (NI §5.2 step 7). The digest is unchanged (`canon` zeroes the field), but the raw struct reaches
the shape check. Simulation fails, so every receiver-fee job on such a node ends `dead`.

B2.5's claim that "normalization does not touch it" is true only for the payee's `feeRecipient`, not the payer's.

**Fix.** Delete the `m.feeRecipient == 0` clause. `canon` already zeroes the field and `FeePolicy.validateRecipient(NONE,
·)` already ignores it on purpose (FeePolicy.sol comment). Keep `m.fee == 0` and fee mode NONE. Do not make the
contract depend on node behaviour. Add a test with a non-zero unbound `m.feeRecipient`.

### H3. The payee co-sign key is a full-control key on a `SubjectAccount` (§B2.5)

**Problem.** B2.5 proposes "a `SubjectAccount` receiving wallet with an ERC-1271 co-sign key under
`SigningPolicyService` limits". `SubjectAccount` keys are not scoped:

- `_isValid` (`SubjectAccount.sol:253`) accepts any digest.
- The same keys authorise `executeAsOwner` (`:119`), so a key can add keys, change the guardian and call
  `execute`.

"`SigningPolicyService` limits" exist only in the server that holds the key.

**Attack.** Whoever compromises the ERP co-sign key can:

- sign `MetaTransaction`s that drain the receiving wallet;
- add a persistent key;
- sign `ReceiverFee` with `fee = m.value` to themselves for every incoming pay intent they can see. On an unbound
  payer relayer that means front-running from the mempool.

Receiver-pays turns every co-signing payee wallet into a hot wallet. The spec presents it as a limited-scope key.

**Fix.**

- State plainly that a co-signing receiving wallet is a **hot collection wallet**: a dedicated EOA or SubjectAccount
  holding only incoming receiver-pays funds, with an automated sweep (mandate or periodic transfer) to a cold
  treasury.
- Remove the "under limits" wording.
- A scoped key kind for SubjectAccount, one that verifies only `ReceiverFee` preimages with a fee cap carried in the
  signature, would be a separate SubjectAccount v2 change. Note it as an open item, not part of RP1.

### H4. Tier A "erasure immediate everywhere, backups included" is false (§C.3, §C.4, R197)

**Problem.** The DEK encrypts **salts only** (C.3: "salts encrypted with the subject's DEK"). The plaintext payload
(the personal data itself) and the address ↔ party mapping are deleted from the live database in steps 2–3, but they
stay in plaintext in every backup in **both** tiers.

Destroying the DEK in KMS makes only the on-chain commitments unopenable. The erasure duty is about the personal
data, and that is still in the backups. R197's reasoning ("backups … hold only ciphertext") is wrong for payloads and
mappings.

**Fix.** Choose one:

- (a) Encrypt the personal payload fields and the mapping rows under the subject DEK as well (envelope encryption,
  AAD = model/record id). Then Tier A really is immediate, and Tier B depends on DEK backup expiry as stated.
- (b) Restate the claim: Tier A erases the *chain linkage* at once, and personal data in backups is erased at backup
  expiry in both tiers. The restore replay applies in both.

(a) is the one that matches the stated goal.

---

## Medium

### M1. `bidderList`, `MAX_BIDS` and the O(n) disqualification scan are unnecessary and add a DoS (§A.2.1, §A.2.2, §A.4, §A.8)

**Problem.** `maxDisqualifications ≤ 2`, each disqualification removes the current leader, and every reveal happens
before the award window opens. So the only bids that can ever lead are the top `maxDisqualifications + 1` (at most
3) valid bids. The 256 cap exists only to bound the scan.

**Attack on open tenders (`eligibilityRoot = 0`).**

1. A sybil with 256 × `minDeposit` of capital fills `bidderList`. Real bidders then get `TooManyBids`.
2. The sybil reveals every bid validly, at `maxPrice` for LOWEST_PRICE, or at `minPrice` for HIGHEST_PRICE. All
   deposits are refunded (I1).
3. The cost is gas and the time value of the capital.

If no honest bid exists, the sybil "wins" and is refunded under RETURN_ON_AWARD. Cancelling and re-running does not
help, because the attack repeats.

**Fix.** At reveal, track the top `k = maxDisqualifications + 1` valid bids by (rule, seq) in a sorted array of at
most 3 entries. `disqualifyWinner` then pops the head, which is O(1). This deletes `bidderList`, `MAX_BIDS`,
`TooManyBids`, the ~700 k scan gas and three tests, and removes the fill DoS. ERPs enumerate bidders from the
`BidCommitted` events, as A.5.1 step 6 already does.

### M2. Sponsorship counts and caps unverified jobs (§B1.3, §B1.7)

**Problem.**

- Accept does no signature check (NI §5.2: "no RPC"). `admit` increments the hour, payer-hour and day `tx_count` at
  accept. A job that dies at lease simulation releases its reservation but **keeps its count**.
- Per-payer caps are keyed on the unsigned `m.from`, and `value_of(job)` is the unsigned `m.value`.
- `call` jobs have `digest = NULL`, so `job_live_digest` (G2) never deduplicates them.

**Attack.**

1. Through `~gateway`/`~mesh`, an attacker sends well-formed jobs with garbage signatures, a random `from` each time
   and `value ≥ min_value`. This costs nothing.
2. `max_tx_per_hour` fills up and the per-payer cap is useless. With `on_exhausted = reject` the subsidy is shut off
   for honest users.
3. Separately, two identical `revealBid`/`withdrawDeposit` jobs (portal retry, or a malicious submitter through the
   portal) both pass simulation and both broadcast. The second reverts on chain, and its measured cost is booked
   against the budget. This is the "simulation-passes-then-reverts" row of B1.7, here with no attacker cost at all.

**Fix.**

- For sponsored metatx/signed_op jobs, verify EOA, Ed25519 and secp256k1 signatures locally at accept (this needs no
  RPC). ERC-1271 payers on public doors go unsponsored, or are checked at lease.
- Increment rate counters at lease, after simulation succeeds (or decrement them when the job goes `dead` before
  broadcast).
- Deduplicate live `call` jobs on `(chain_key, target, keccak(calldata))`.
- Define the payer for `call` jobs: for `commitBid` the node can decode `m.from`; for `revealBid`/`withdrawDeposit`,
  the `bidder` argument. Otherwise the per-payer cap is `n/a` for calls, and it must be documented that way.
- On public doors, require `min_value > 0` or a set `receiver`: a `contract = '*'`/`min_value = 0` policy on
  `~gateway` is a budget drain by construction.

### M3. Reservation bookkeeping leaks and can overshoot (§B1.2, §B1.3, R190)

**Problems.**

- (a) The job stores only `sponsor_policy_id`. A `PATCH` of `max_cost_per_tx`, or the restart recompute ("from live
  jobs"), uses the *current* value, not the one reserved, so `cost_reserved` drifts or goes negative.
- (b) A job reserved on UTC day D and mined on D+1 releases from, and books to, a bucket the spec does not define.
- (c) The lease check uses `gas_estimate × max_fee_cap`, but the transaction is sent with a gas limit above the
  estimate, plus any fee bumps on stuck transactions. The measured cost can then exceed `max_cost_per_tx`, so R190's
  "overshoots by at most the reserved headroom" does not hold.
- (d) Costs are `TEXT` and the arithmetic happens in code. Under MySQL REPEATABLE READ (R111 backend), a plain read
  followed by a write loses updates when two accepts touch the same bucket concurrently. PostgreSQL raises a
  serialization error, and SQLite is single-writer.

**Fix.**

- Add job columns `sponsor_reserved` and `sponsor_day`. Release and book exactly those values, and recompute at
  startup from them.
- Check `gas_limit × max_fee_cap ≤ max_cost_per_tx`, and cap fee bumps at that figure.
- Specify `INSERT … ON CONFLICT DO NOTHING` followed by `SELECT … FOR UPDATE` on the day, hour and payer-hour bucket
  rows inside the step-8 transaction.
- Add tests: day rollover, PATCH while jobs are live, concurrent accept on MySQL.

### M4. `feeRecipient = 0 ⇒ msg.sender` in `ReceiverFee` breaks TW2 convention and allows front-run fee theft (§B2.1, §B2.4, §B2.5 e-cheque)

**Problem.**

- TW2's named fee functions require a bound, non-zero fee recipient (`_requireFeeShape`, `MetaTokenBase.sol`, "turn
  3293").
- In the e-cheque flow the payer intent is signed offline and its relayer may be unbound.

**Attack.**

1. A mempool watcher copies the pending `mtxPayReceiverFee` calldata and front-runs it, becoming `msg.sender`, so it
   takes the fee.
2. Alternatively, it lands the payer intent alone through `executeMetaTransaction`. The payee then pays no fee, and
   the honest relayer reverts and pays gas.

B2.4 notes this risk as "bind the payer's relayer", but nothing enforces it.

**Fix.** Require `feeRecipient ≠ 0` in `ReceiverFee`. The payee names the node's `chains.fee_recipient`, which it must
know anyway because B2.5 builds the intent with `relayer = its lane`. Also recommend, or require,
`MODE_RESTRICT_RELAYER` on the payer intent for this function. Both changes are one line each and match TW2.

### M5. Neutrality of the chain and of transaction ordering is assumed, not stated (§A.7.1 "Censorship", "Timestamp skew", R184 tie-break)

**Problem.** The roadmap includes private and PoA chains (`chains/private9000`, the queued post-quantum Zether work on
private/PoA chains). On such a chain the buyer organisation may run the validators. It can then:

- censor competitors' reveals, which forfeits them to its own sink and picks the winner;
- censor commits;
- set timestamps within the consensus drift rules.

Separately, the earliest-`seq` tie-break is decided by the order in which commits are submitted. The buyer's portal,
which relays commits (A.5.2 step 3), or a builder can order a favoured bidder first. Ties are realistic with round
price grids.

**Fix.**

- A.7.2: "the tender is fair only on a chain whose transaction inclusion the buyer does not control". The ERP refuses
  to create a tender on a chain the buyer organisation validates alone, or shows a warning.
- Add the portal-ordering caveat to the tie-break rationale. A bidder that cares about ties submits its commit
  through its own path (see H1).

### M6. Erasure log location and `log_key` are unspecified (§C.4, R197)

**Problem.**

- "Restore replays every erasure ticket newer than the backup" works only if the log lives **outside** the database
  being restored. Otherwise an old backup brings back an old log that lacks the newer tickets.
- If `log_key` sits in the database, or in `ir.config_parameter`, then `HMAC(log_key, partner_id)` over sequential
  ids can be reversed by anyone who holds the backup.
- `subject_ref` (C.3) is also an HMAC, with an unnamed key.

**Fix.**

- Keep the erasure log in a separate append-only store, with retention ≥ the maximum backup age.
- Keep `log_key` with the KEK, outside the database, and never in `ir.config_parameter`. Name the key used for
  `subject_ref`, and keep it separate from `log_key` unless linking the two is intended.
- Add a test: restore an old backup, then replay from the external log.

---

## Low

- **L1. Invariants (§A.2.4).**
  - I3, "before `revealDeadline` no price is derivable", is false: reveals happen inside `(commitDeadline,
    revealDeadline]`. It should read "before the bidder's own reveal, and in particular before `commitDeadline`".
  - I6 is false as written: anyone can `transfer`, or `pay` without a relayer binding, to the tender (R187 calls these
    stray tokens). It should read "no bid deposit".
  - The invariants are numbered I1, I2, I3, I4, I7, I5, I6. Renumber them.
- **L2. Residual discretion is understated (§A.7.1, §A.7.2).**
  - With `validReveals ≤ maxDisqualifications`, the buyer can disqualify every candidate after seeing the prices,
    which makes the tender `FAILED`. That is a price-informed abort, and the abuse-table row "Buyer aborts after
    seeing prices" says it cannot happen.
  - `claimBond` (HOLD) is discretionary, needing only a `reasonRef`. With forfeit classes declared, the buyer can
    therefore seize up to three deposits (two disqualified bids plus the winner's bond).
  - Fix: state both, or forbid disqualifying the last remaining candidate.
- **L3. R186 and the factory kinds.** Factory v2 can also deploy v1 `META` (and `ZETHER`) kinds
  (`IOpenFactoryV2.TokenDeployed`: "only for v1 kinds"). Say whether a v2-factory `META` token is accepted. Note
  that `IOpenFactory.TokenKind` and `IOpenFactoryV2.TokenKind` are different types: decode `versionOf` per factory.
- **L4. Bytecode size.** `mtxPayReceiverFee` and the `ReceiverFee` hashing land in `MetaTokenBase`, so they are added
  to every tier and both Hedera children. No v2 artifacts exist in `out/`, so I could not measure. TW2 §10 already
  has a 24,576-byte CI gate and a library fallback, but only for Multi. RP1 should name its own fallback in case
  Single or Multi goes over the limit.
- **L5. Gas estimate.** The `commitBid` estimate (145–175 k) leaves out an ERC-1271 bidder. A SubjectAccount gets a
  400 k cap; with WebAuthn, P-256 costs ≈ 100–300 k. A buyer that sizes `max_cost_per_tx` from §A.8 kills its own
  SubjectAccount bidders with `SPONSOR_TX_CAP`. Add a row to the table and a sizing note.
- **L6. R139.** `mtxPayReceiverFee` takes a generic `m`, so once-per-`(payer, entryRef)` does not hold. The payee
  builds the typed data anyway, so require `batch = payLane(entryRef)` and `nonce = 0` (as `mtxPay` does), or state
  that the property is absent.
- **L7. Merkle formats.** Eligibility uses OZ double-hash leaves. Anchoring (C.2) uses `0x00`/`0x01`-prefixed hashes,
  which have "OZ-compatible ordering" but cannot be checked with OZ `MerkleProof`. State that the anchoring verifier
  is custom, or align the two formats.
- **L8. Multi-subject records under per-subject DEKs are undefined (§C.3).** For a record about two parties, say which
  DEK wraps its salt (and, after H4, its payload) and what erasing one of the subjects does.
- **L9. Tests to add.**
  - **Tender, I6 front-running:** a third party submits the deposit intent through `mtxPay`, `mtxBatch` or
    `executeMetaTransaction` and gets `MetaTxUnauthorizedRelayer`, on v1 and v2. The intent is replayed into another
    `tenderId` and into another tender contract.
  - **Tender, timing:** a commit and a cancel in the same block at `now == commitDeadline`.
  - **KATs:** for `depositRef`, the deposit `pay` data and the `ReplaceBid` digest. Today only `commitmentOf` has
    one.
  - **Hedera:** a 64-byte ED25519 deposit intent.
  - **Receiver-pays:** a test with a non-zero unbound `m.feeRecipient` (H2).
  - **Sponsorship:** day rollover, policy PATCH while jobs are live, `dead` before broadcast does not consume the
    rate cap, and duplicate `call` jobs (M2, M3).
  - **Shredding:** the Tier A backup claim (H4) and restoring with the external log (M6).

---

## Over-engineering (cut or defer)

- **O1. Top-k tracking instead of `bidderList` + scan + `MAX_BIDS`.** See M1. This is the largest simplification.
- **O2. `replaceBid` (defer).** It is the tender's only signature check. Removing it deletes:
  - the EIP-712 domain, `SigLib`, `replaceNonce` and seq reassignment;
  - the KAT;
  - most of the reason for a Hedera child, so TB2 becomes deploying the same bytecode plus an HSCS end-to-end test.

  A bidder who wants to change its price has none of this in v1. The owner decides. It is not covered by a ruling.
- **O3. B3 SponsorshipPool is fully specified while still PLANNED-later.** Cut it to R194's paragraph. Write down one
  caveat for PL1: the "refund, not profit" argument fails where the relayer is the block producer and receives the
  base fee or priority fee, as on PoA/private chains and some L2/Celo fee handlers. Self-farming is then pure profit.
- **O4. Field-level salts, `FIELD_TAG` commitments and `verify-field` have no consumer in this spec.** Defer them until
  the anchoring stream needs selective disclosure.
- **O5. The `HOLD_UNTIL_RELEASE` bond inside the tender** adds three entry points, a time parameter and a discretionary
  seizure (L2). If SCaaS §10.2 allows it, consider a separate bond step after the award. Optional.

---

## Summary table

| # | Sev | Section | One line |
|---|---|---|---|
| H1 | High | A.5.2–3, R183 | Buyer controls gasless bidders' reveal/commit path and receives the forfeits; require an independent path |
| H2 | High | B2.2, NI R100 | R100 rewrites payer `feeRecipient` ⇒ `m.feeRecipient == 0` check reverts every receiver-fee job; drop the check |
| H3 | High | B2.5 | SubjectAccount co-sign key is unscoped (full control); receiver-pays wallet must be declared a hot, swept wallet |
| H4 | High | C.3–C.4, R197 | DEK covers salts only; payloads/mappings stay plaintext in backups; encrypt them under the DEK or restate the claim |
| M1 | Med | A.2, A.4 | Track top-(maxDq+1) bids; delete bidderList/MAX_BIDS/scan; removes 256-slot sybil fill DoS |
| M2 | Med | B1.3 | Unverified jobs consume rate caps; per-payer cap keyed on unsigned `from`; no dedupe for `call` jobs |
| M3 | Med | B1.2–3 | Store reserved amount + day on the job; cap by gas_limit and fee bumps; lock bucket rows (MySQL lost update) |
| M4 | Med | B2.1 | Require `feeRecipient ≠ 0` (TW2 convention) and payer relayer binding; prevents front-run fee theft |
| M5 | Med | A.7 | Tender fairness needs a chain the buyer does not validate; portal decides the seq tie-break |
| M6 | Med | C.4 | Erasure log must live outside the restored DB; `log_key` outside the DB |
| L1–L9 | Low | various | Invariant wording (I3, I6), understated discretion, factory kinds, code size, ERC-1271 gas, R139, Merkle formats, multi-subject records, missing tests |
| O1–O5 | — | — | Top-k, defer replaceBid, trim Pool, defer field salts, optional HOLD bond |
