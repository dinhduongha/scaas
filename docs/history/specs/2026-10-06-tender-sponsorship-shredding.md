# Sealed-bid tender, gas sponsorship and receiver-pays, crypto-shredding (component spec B)

Status: draft rev 1.4, 2026-10-07. Rev 1.1 folds in the owner's answers to the two rev-1 open questions
(post-reveal disqualification, R185; receiver-pays stays v2-only, R193); rev 1.2 folds in independent review 1
(FIX-THEN-GO; disposition in §10); rev 1.3 folds in the Codex review (FIX-THEN-GO; H1–H2, M1–M2, L1; disposition in
§11) and aligns with NI rev 3.5 (R320, R325) and UA rev 1.4. Code verified at `scaas` `main` 9e27d35. Rev 1.4 (2026-10-07 clean-up): NI amends row and §B1.2 SQL gain
`job.sponsor_fallback` (NI rev 3.6).
**Nothing in this spec is built.**
Rulings: **R180–R199** (§2). R150–R172 belong to the app spec, R200–R216 to the asset-suite spec (AS). Owner rulings of 2026-10-06 folded in:
(1) sealed-bid tender = commit–reveal + deposit, gasless bidders, procurement integration, EVM + Hedera first;
(2) gas sponsorship **and** receiver-pays: node policy first, receiver co-signed fee, an on-chain `SponsorshipPool` as a
later stream; (3) crypto-shredding with client-held salts and keys.

Amends:

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §5.9 (receiver pays, sponsorship), §6 consequences 1 and 4, §10 (tender), §11.2 (shredding), §13.2 (budgets), §14.7, §15.1 row 23: status → SPECIFIED, link here. §10 and §14.7 are superseded where this spec differs (R182, R185 and §A.3) |
| INT | `docs/integration.md` | §8 (sponsorship, receiver pays), §9 (tender): status → SPECIFIED, link here |
| NI | `2026-10-06-node-independence-design.md` rev 3.5 | additions only: tables `sponsor_policy`, `sponsor_usage`, `chain_contract`; job columns `sponsor_policy_id`, `sponsor_reserved`, `sponsor_day`, `call_hash`, `gas_used`, `gas_price`, `cost_native`; live-call dedupe index (per namespace, R325); local signature check for sponsored public-door jobs; admin routes §B1.5; job payload field `receiver_fee` (§B2.5). **Rev 1.3 additions for NI to fold** (all in NI §4/§5.2/§7.3, nothing removed): job columns `sponsor_hour`, `sponsor_fallback` (NI rev 3.6 added both); policy column `min_valid_secs`; `sponsor_usage.tx_count` counted at accept and released on a pre-broadcast end, so `SPONSOR_RATE` becomes an accept `429` and leaves the lease `dead` reasons (NI §4 state table); new accept `429 SPONSOR_TOO_SHORT` and admin `422 POLICY_INVALID` (`fallback_to_namespace`); `409 DUPLICATE_CALL` carries the live job's `uid`; a `~gateway` `call` policy is valid for the R320 UA registration target only (NI §7.3 sentence on TSS §B1.5); feed field `sponsor_fallback` |
| TW2 | `2026-10-06-token-wrappers-v2.md` | one named function added to `MetaTokenBase` (`mtxPayReceiverFee`, R192), shipped as a new implementation version per tier; `_execute` returns the digest (no behaviour change) |
| MESH | `2026-10-05-relayer-mesh-design.md` | R75 **not amended**; its scope is clarified by R194 |

Sources: SCaaS §2.2, §5.7–§5.9, §6, §10, §11, §14.7; INT §5, §8, §9; TW2 §3, §7; NI §4, §5, §7; MESH R75, R84, R86,
§7; PD R2, R9, T18; research 09, 15 §15.12.1; SRS architecture §4.9, §10, integration §2.5–§2.6, §3.5, §4.2; code
`smartcontracts/evm/src/{common,metatx,wallet,zether,factory,account}`.

Market-neutral: no country's law is cited. "GDPR-class regime" means any data-protection regime with lawful basis,
minimization, erasure, retention and processor duties.

---

## 1. Scope and non-goals

### 1.1 In scope

| Part | What |
|---|---|
| A | `SealedBidTender` contract (EVM; same bytecode on Hedera), bidder and buyer flows, node/ERP/app touchpoints |
| B1 | Node sponsorship policy: matching, fee-floor waiver, budgets, rate caps, accounting, metrics, admin API |
| B2 | Receiver-pays: payee co-signature, new named function `mtxPayReceiverFee` on v2 tokens, node job field |
| B3 | `SponsorshipPool`: rule R194 and constraints only; design is stream PL1 (PLANNED-later) |
| C | Crypto-shredding: commitment formats, salt and key handling on the client, erasure and retention procedure, audit |

### 1.2 Non-goals

- Multi-criteria scoring, multi-lot tenders, other auction types (pre-qualification = the eligibility allowlist);
  confidential bids, Zether deposits, anonymous bidders (a fresh `SubjectAccount` per tender is possible, SCaaS §10.6).
- A fee market or any in-protocol mesh reward (R75 stays); fiat valuation in the node (R189).
- Receiver-pays on v1 tokens, non-EVM families (no fee fields, R3D §D.0) and Zether tokens (hidden amounts).
- Hiding the address graph (SCaaS §1.3): shredding removes the link to a person, not between addresses.
- Anchoring contracts and batch scheduling (SCaaS §2.2): only the commitment and leaf formats are fixed here.

---

## 2. Rulings

Format: **ruling — why — cost if wrong.**

### 2.1 Sealed-bid tender

- **R180** **Deposit and commitment are one signature: the deposit token's own `pay` meta-tx** (unchanged typehash,
  v1 or v2 token): `to = tender`, `value = minDeposit`, `data = pay(depositRef)`, fee `NONE`, `MODE_RESTRICT_RELAYER`
  with `relayer = tender`, `depositRef = keccak256(abi.encode(DEPOSIT_TAG, block.chainid, tender, tenderId,
  commitment))`. Anyone submits `commitBid(tenderId, commitment, proof, m, sig)`; the tender recomputes `depositRef`,
  checks the shape, calls `token.executeMetaTransaction(m, sig)` and records the bid. — The payId binds the deposit to
  this commitment: no tender-level signature, no allowance (R26), and nobody lands the deposit outside `commitBid`
  (v1 and every v2 entry point check the relayer first). Bidders reconcile it as a payment (`entryRef =
  depositRef`). — If wrong: wallets show "pay 1000 to <tender>" rather than "bid".
- **R181** **Commitment** `= keccak256(abi.encode(BID_TAG, block.chainid, address(this), tenderId, bidder, price,
  salt))`, `BID_TAG = keccak256("scaas.tender.bid.v1")`, `DEPOSIT_TAG = keccak256("scaas.tender.deposit.v1")`,
  `price` `uint128` in base units of the price unit named in the tender documents, `salt` 32 bytes from a CSPRNG or
  derived per §A.5.4. `abi.encode`, never `encodePacked` (research §15.12.1 used packed encoding). — Binding chain,
  contract, tender and bidder stops copying a commitment into another tender or onto another chain. — If wrong: a
  format change is a new `BID_TAG`.
- **R182** **Reveal and withdraw are permissionless; no replacement in v1.** `revealBid(tenderId, bidder, price, salt)`
  and `withdrawDeposit(tenderId, bidder)` take no signature: the commitment binds the bidder, and payouts go only to
  the destination the rules fix (§A.2.3). A commitment cannot be replaced (deferred on merit, review O2, §10). — The
  tender contract verifies no signature at all, every bidder action needs at most the one deposit signature,
  and any node or keeper can run reveals and refunds. Amends SCaaS §10.3 (bidder-signed reveal/withdraw, replacement).
  — If wrong: a tender v2 adds `replaceBid`; v1 bidders who must change a price abandon the bid (forfeit).
- **R183** **Forfeited deposits go to `slashSink`**, fixed at creation, immutable, `∉ {0, tender}`, never a bidder.
  ERP default: the buyer organization's tender-security account; not burned, not redistributed. — The buyer is the
  party harmed by a non-reveal; burning only destroys value; redistribution breaks I1. Acceptable **only because
  every bidder has a commit and reveal path the buyer does not control** (§A.5.2, review H1); otherwise a sponsoring
  or relaying buyer could withhold a competitor's reveal and keep its deposit. — If wrong: name a neutral sink.
- **R184** **Public reserve only.** `[minPrice, maxPrice]` (inclusive, `maxPrice = 0` ⇒ unbounded) is published; a
  reveal outside it is **invalid** and forfeits. No sealed reserve in v1 (it would be a price-informed abort);
  forfeiting out-of-range reveals closes the "reveal garbage to exit" escape. **Tie-break = earliest commit `seq`**
  (per-tender counter at commit): deterministic, not manipulable after reveals; commit order is decided by submitters
  and block producers, so a bidder that cares commits through its own path (§A.5.2, review M5).
- **R185** **Cancel until `commitDeadline` only**, by the buyer, with a `reasonRef` (salted commitment, §C.2); every
  deposit then refunds 100 %; prices are still hidden, so a cancel cannot be price-informed (amends SCaaS §10.3).
  `minBidders ≥ 1` valid reveals (disqualified ones included) else `FAILED`: valid revealers refunded, others forfeit.
  **Award window and disqualification** (owner, rev 1.1; top-k per review O1). During reveals the contract keeps the
  **top `k = maxDisqualifications + 1` (≤ 3) valid bids** sorted by price (`rule`), then `seq`; the head leads. For
  `dqWindow` seconds after `revealDeadline` (fixed at creation, `≤ 7 d`, ERP default 72 h, `0` = off) the buyer may
  `disqualifyWinner` **the current leader only**, with a non-zero `reasonRef` (salted commitment of the document,
  R198), a violation class, and **only while a next valid bid exists** (review L2: never a price-informed abort);
  the next bid leads. Only the top `k` can ever lead, so nothing else is stored. The disqualified deposit refunds in
  full unless the class is one of the `forfeitClasses` declared at creation (bitmask of ≤ 8 classes defined in the
  tender documents, e.g. forged bid documents) — then it goes to `slashSink`. At most `maxDisqualifications ≤ 2`;
  each emits `BidDisqualified`. **Settlement:** the buyer may settle any time after `revealDeadline` (closing the
  window), anyone after the window; `withdrawDeposit` settles lazily; no `awardDeadline`. — Procurement must pass over
  a winner failing due diligence; leader-only, short window, public reason, cap and last-candidate rule bound the
  discretion (§A.7.2). — If wrong: a tender wanting no discretion sets `dqWindow = 0`.
- **R186** **Deposit token** = a token deployed by the configured factory v1 (`META`) or factory v2 (`META`,
  `META_NONE`, `META_SINGLE`, `META_MULTI`; factory v2 also deploys the v1 `META` kind, accepted when registered)
  through a **registered, non-deprecated** implementation (unregistered clones have version 0 ⇒
  `implementationOf == 0` ⇒ refused; Zether kinds refused), checked at `createTender`. `versionOf` is decoded with
  each factory's own `TokenKind` type (`IOpenFactory` and `IOpenFactoryV2` enums differ). The tender also checks the
  balance delta equals `minDeposit` (redundant for META tokens, kept as defence). — Bidders sign an intent on this
  token; an attacker-chosen "token" could fake `executeMetaTransaction`. — If wrong: other tokens wrap first.
- **R187** **Windows and bonds.** `revealDeadline − commitDeadline ∈ [1 h, 30 d]` (ERP default 24 h);
  `commitDeadline ≤ createdAt + 365 d`; bond policies `RETURN_ON_AWARD` | `HOLD_UNTIL_RELEASE` kept (SCaaS §10.2):
  under HOLD the winner's deposit is the bond, released by the buyer or by anyone after `bondReleaseTime`
  (`≤ revealDeadline + 730 d`), or claimed by the buyer to `slashSink` before then with a `reasonRef` (kept on merit,
  review O5, §10). — If wrong: constants change only with a new deployment.
  **No admin.** One immutable contract per chain, no owner, pause, upgrade or sweep; stray tokens sent directly are
  unrecoverable. `bidder ≠ buyer`. — Every refund path must hold without anyone's consent (I1).
- **R188** **Families: EVM and Hedera first** (the same bytecode on HSCS: the tender verifies no signature, so no
  Hedera child is needed; HIP-632 bidders are handled by the deposit token). Cosmos, Soroban, Sui, Aptos, TON,
  Solana are PLANNED with the native designs of §A.10.
  **Prerequisite: EIP-1153 (`TLOAD`/`TSTORE`)** for the tender's and PL1's reentrancy guard (rev 1.3, Codex M2). It
  is not a new requirement: every deposit token already needs it (`MetaTxCore.nonReentrant`, `MetaTxCore.sol:38-44`,
  inherited by the v2 tiers and the Hedera children; `ERC20MetaTx.sol:35-41` for v1), so a chain without it cannot
  hold an eligible deposit token. The deploy script probes `TSTORE` and refuses the chain; no storage-guard fallback
  (it would be dead code on every chain that passes R186).

### 2.2 Gas sponsorship (node)

- **R189** **A sponsorship policy is a node store row that matches jobs and (a) waives the fee floor of the door the
  job came through, (b) books its gas to a sponsor account, (c) enforces that account's budget and rate caps.** It
  never changes a signed field and never adds a fee. Matching uses only job data (no RPC at accept, NI §5.2).
  Doors: client namespaces (no fee floor today: the policy books and limits), `~gateway` and `~mesh` (the MESH §7
  `min_fee` floor is waived for matching jobs). — Owner: node-level sponsorship first; one mechanism serves inbound
  subsidies ("to wallet W, value ≥ X ⇒ fee 0, gas to account Y", SCaaS §6) and tenant cost control. — If wrong:
  policies are data; nothing on chain depends on them.
  **Client namespaces: `unsponsored` means "booked to the namespace"** (rev 1.3, Codex H1). The node pays gas for every
  client job and books unmatched jobs to the namespace (`sponsor_policy_id NULL`, NI `usage_day.sponsor_policy = ''`),
  which is the tenant's own billed spend; a fallback is that and nothing more, and is marked (`sponsor_fallback`,
  §B1.4; metric `result="unsponsored"`), never booked to the sponsor account. A policy is therefore a cap on the
  **sponsor account** in every case, and a cap on a **tenant's** spend only with `on_exhausted = reject` on a policy
  that covers the tenant's jobs (e.g. `contract = '*'`, `selector = '*'`). The admin API refuses `unsponsored` on a
  client-namespace policy unless the request sets `fallback_to_namespace: true` (stored in the audit row), so the
  fallback is a recorded decision. — The finding's "silently spends lane gas" is the namespace's default for any
  unmatched job; what was missing is the statement and the mark. — If wrong: a tenant cap becomes a namespace column
  (NI), not a policy flag.
  **Value thresholds are token base units per (chain, token).** Conversion from a reporting currency is the
  client's business (it pushes new rows when its rates change). — The node holds no prices and no oracle. — If
  wrong: a stale threshold sponsors slightly more or less.
- **R190** **Budget unit = the family's smallest native unit** (wei, tinybar, lamports, uatom-equivalent, MIST,
  octa, nanoton, stroops), measured from receipts (`gas_used × effective price`, or the family's fee field). Budget
  per UTC day; rate caps per hour per policy and per payer. Admission reserves `max_cost_per_tx` per sponsored job
  and stores the reserved amount and day on the job; the reservation is replaced by the measured cost, booked to that
  same day, at `mined`/`reverted`. A sponsored transaction is built so that its maximum chargeable fee (`gas_limit ×
  max_fee_cap` on EVM, fee bumps included) is `≤ max_cost_per_tx`, so measured ≤ reserved and a day's spend never
  exceeds its budget. **Rate counters are taken at accept with the reservation** (rev 1.3, Codex H2; was "at lease"
  per review M2): the job stores `sponsor_hour`, the hour and payer-hour `tx_count` are checked and incremented in the
  same transaction as the day reservation, and a job that ends before broadcast releases all three. Otherwise one
  payer could reserve a whole day's budget with jobs that never reach lease. Review M2's concern (unverified jobs
  burn caps) is met by the local signature check on public doors, and by the release: a garbage job holds a count only
  until it dies at lease. A sponsored job needs `valid_until ≥ now + p.min_valid_secs` (default 120) at accept, or it
  is not sponsored (`on_exhausted` decides), so near-expiry jobs cannot cycle reservations. `on_exhausted ∈ {reject,
  unsponsored}`. — Arithmetic at accept, measurement at the end; no oracle. — If wrong: a too-low cap leaves some
  sponsored jobs `dead` (`SPONSOR_TX_CAP`); the client re-pushes them unsponsored.
- **R191** **Admin routes and audit** (§B1.5): create/patch/delete `admin`, state `operator`, read `viewer`; every
  mutation audited (R110), hot reload ≤ 2 s (R95). Metrics `scaas_sponsor_*` (§B1.6).

### 2.3 Receiver-pays

- **R192** **New named function `mtxPayReceiverFee(m, payerSig, fee, feeRecipient, rfValidUntil, payeeSig)` in v2
  `MetaTokenBase`**, with the payee's EIP-712 co-signature `ReceiverFee(bytes32 paymentDigest, uint256 fee, address
  feeRecipient, uint256 validUntil)` in the token's own domain, where `paymentDigest` is the **full EIP-712 digest**
  of the payer's intent. The payer's `MetaTransaction` and typehash are unchanged; the payer runs the nine-step
  pipeline untouched; then `fee` moves from the payee to the resolved fee recipient in the same transaction. —
  `paymentDigest` is consumed once by the payer's nonce, so the co-signature is single-use with no new storage, and
  it is bound to one token, chain, payer, amount and `entryRef`. R140 ("no second typehash") concerns the
  **payment intent**; `ReceiverFee` is a different message signed by a different party (as `MandateWallet` has its
  own types), so payer wallets still show one transaction type. — If wrong: payees sign one more typed message.
- **R193** **Shape:** payer op is `pay(entryRef)` (36 bytes) with fee mode `NONE` (one fee per intent),
  `MODE_RESTRICT_RELAYER` set, `batch = payLane(entryRef)`, `nonce = 0` (as `mtxPay`, so R139 "once per
  `(payer, entryRef)`" holds); `fee` is an absolute amount, `0 < fee ≤ m.value`; the co-signed `feeRecipient` is
  non-zero (TW2 named-fee convention) and `≠ m.to` (R132). The payer's `feeRecipient` field is **not** checked
  (`canon` zeroes it, and NI R100 may rewrite it on the node; review H2). No 1 % cap: the
  payee signs the exact amount it gives up, and the payee can never lose more than it receives in this call. Events:
  `PaymentSettled(…, N, entryRef)` unchanged (gross), plus `ReceiverFeePaid(paymentDigest, payee, feeRecipient,
  fee)`. — The payer's books do not change; the payee books receipt N and expense F (SRS integration §2.5: net
  N − F).
  **Availability:** v2 tokens of the next implementation version of each tier (EVM and Hedera children);
  older v2 clones and v1 lack it (clones are immutable). Not in `mtxBatch`. Node jobs carrying `receiver_fee` are
  `bus.scope = restricted` (the mesh envelope has no slot for the co-signature). A co-signing receiving wallet is a
  **hot collection wallet** (§B2.5, review H3). — Smallest change that is atomic
  and allowance-free; production registration (O3) has not happened, so the version bump costs nothing. **Decided
  (owner, rev 1.1): v2-only, no v1 router.** — If wrong: v1 issuers migrate to v2 to offer receiver-pays.

### 2.4 SponsorshipPool and R75

- **R194** **`SponsorshipPool` is an opt-in application contract, not a mesh reward. R75 is not amended.** R75
  governs what the mesh protocol pays (only the intent's own `fee`/`feeRecipient`); a pool is a `call` target any
  relayer may use, like the tender. In v1 the mesh does not gossip pool-bound intents (an envelope slot would be a
  mesh change). Status **PLANNED-later**. — Owner asked to reconcile; keeping the mesh protocol fee-only preserves
  every MESH admission and exclusivity rule. — If wrong: a later mesh revision adds a `via_pool` envelope field.
  **Pool reward = native-gas refund**, `min((gasMeasured + overheadGas) × min(tx.gasprice, block.basefee +
  maxPriorityFee), maxRewardPerIntent, balance)`, paid to `msg.sender` after the intent executes inside `settle`.
  Sponsor withdrawals wait `withdrawDelay ≥ 3600 s + finality` (≥ NI `max_valid_for_secs`). — A refund, not a profit,
  removes the incentive to farm the pool with self-made intents; the delay stops a sponsor from pulling funds from
  under an in-flight relayer. Caveat for PL1 (review O3): where the relayer can be the block producer and receives
  base or priority fees (PoA/private chains, some L2 or fee-currency handlers), a refund is profit and self-farming
  pays; PL1 restricts programs to chains where lanes do not produce blocks, or pays a fixed capped reward. — If
  wrong: token-denominated rewards are a second mode later.

### 2.5 Crypto-shredding

- **R195** **The client holds every salt and key; the chain holds only commitments; the node holds neither salts nor
  personal data.** Node payloads are addresses, amounts, digests, commitments (retained ≤ `job_retention_secs`,
  SCaaS §11.1). — Owner. The erasure duty then lands entirely in the system of record, where it can be met.
- **R196** **Commitment formats** (§C.2): record `keccak256(abi.encode(REC_TAG, salt, payloadHash))` with
  `payloadHash = SHA-256(JCS(payload))`; Merkle leaf `keccak256(0x00 ‖ commitment)`, node `keccak256(0x01 ‖ min ‖
  max)` (a custom verifier, not OZ `MerkleProof`). Field-level salts are deferred until anchoring needs selective
  disclosure (review O4). — Domain tags and the
  leaf/node prefix stop cross-format and second-preimage confusion; JCS reuses NI R91's canonical form. Supersedes
  the `keccak256(salt ‖ canonical(payload))` sketch of SCaaS §11.2 (same idea, fixed encoding).
- **R197** **Salts and anchored payloads are encrypted under a per-subject data key (DEK); erasure destroys the
  DEK** (rev 1.2, review H4). Tier A (DEK in a KMS/secret store with key destruction): salts and anchored payloads
  become unreadable in every copy, backups included, at once (commitments unlinkable at once). Tier B (wrapped DEK
  in the ERP database): the same when the last backup holding the DEK expires. **Address ↔ party mappings and ERP
  master data are not encrypted** (that would turn relational, searchable wallet and accounting fields into
  ciphertext with blind indexes — unreasonable for v1): deleted live at once, gone from backups at backup expiry, both
  tiers. Restores replay an erasure log kept **outside** the restored database (random ticket + `HMAC(log_key,
  subject_id)` + itemized tombstones keyed by `HMAC(log_key, model ‖ id)`, rev 1.3; `log_key` with the KEK):
  tombstones first, then the current retention logic (§C.4). — Deleting rows alone leaves them in backups; a plain hash of a sequential
  id is reversible. Refines SCaaS §11.2.
- **R198** **References carry no personal data and are not derived from business identifiers**: `entryRef`/`payId`
  random (R9); `documentRef`, `reasonRef`, bond/claim references are salted commitments (R196); `depositRef` is
  derived only from public tender data (R180); revealed tender prices are public by design and personal data only
  through the address ↔ party mapping, which is erasable off chain.
- **R199** **Disclosure = opening.** An auditor verifies a commitment from `(salt, payload)`, a batch member from the
  Merkle path; Zether amounts via `ITransferDisclosure.verifyTransferAmount` (view, no trace). `attestTransferAmount`
  writes `AmountAttested(entryRef, amount, …)` forever: never for amounts that are personal data unless the
  retention basis outlives the chain, and the data subject is told that given openings cannot be revoked.

---

## A. Sealed-bid tender

### A.1 Roles and lifecycle

Buyer: `msg.sender` of `createTender` (in practice a `SubjectAccount`, `MandateWallet` owner call or a multisig,
submitted as a `call` job). Bidder: `m.from` of the deposit intent. Keeper: anyone (node, buyer, bidder) running
permissionless steps.

```
createTender ─► OPEN ──commitDeadline──► (REVEAL) ──revealDeadline──► (AWARDABLE) ─settle─► SETTLED | FAILED
                │ commitBid               │ revealBid                     │ disqualifyWinner    │ withdrawDeposit
                │                                                         │ (buyer, ≤ dqWindow) │ releaseBond / claimBond
                └ cancelTender (buyer, now ≤ commitDeadline) ─► CANCELLED ─ withdrawDeposit
```

Stored states: `OPEN`, `SETTLED`, `FAILED`, `CANCELLED`; `REVEAL` and `AWARDABLE` (the award window
`(revealDeadline, revealDeadline + dqWindow]`, then until someone settles) are derived from `block.timestamp`.

### A.2 Rules

#### A.2.1 Commit (`now ≤ commitDeadline`)

1. Tender exists and stored state `OPEN`; `bidder = m.from`; `bidder ∉ {buyer, slashSink}`; eligibility proof
   valid when `eligibilityRoot ≠ 0` (OpenZeppelin `MerkleProof`, leaf `keccak256(bytes.concat(keccak256(abi.encode(
   bidder))))`); bidder has no bid.
2. Intent shape (`BadDepositIntent(code)`): `m.to == address(this)`, `m.value == minDeposit`,
   `m.data == abi.encodePacked(bytes4(keccak256("pay(bytes32)")), depositRef(tenderId, commitment))`,
   `feeModeOf(m.mode) == NONE`, `m.mode & MODE_RESTRICT_RELAYER != 0`, `m.relayer == address(this)`.
3. Effects: bid `{commitment, seq = nextSeq++, status = COMMITTED}`, `commits++`.
4. Interaction: `b0 = balanceOf(this)`; `IERC20MetaTx(token).executeMetaTransaction(m, sig)` (reverts propagate);
   `balanceOf(this) − b0 == minDeposit` else `DepositNotReceived`.
5. Emit `BidCommitted(tenderId, bidder, commitment, seq)`.

The batch/nonce of `m` is the bidder's choice; clients SHOULD use `payLane(depositRef)`, nonce 0 (R9 convention).
A commit and a cancel in the same block at `now == commitDeadline` are both valid; their order decides (a cancel
after the commit refunds it).

#### A.2.2 Reveal, disqualify, settle

- `revealBid(tenderId, bidder, price, salt)`: `commitDeadline < now ≤ revealDeadline`, bid `COMMITTED`, recomputed
  commitment equals the stored one else `CommitmentMismatch`. `valid = minPrice ≤ price ∧ (maxPrice == 0 ∨ price ≤
  maxPrice)`. Stores `price`, status `REVEALED`, `valid`; if valid: `validReveals++` and insert into the sorted
  `top` list (≤ `k = maxDisqualifications + 1` entries; `LOWEST_PRICE`: lower first, `HIGHEST_PRICE`: higher first;
  equal ⇒ lower `seq`), dropping the entry beyond `k`. Emits `BidRevealed(tenderId, bidder, price, valid)`.
- `disqualifyWinner(tenderId, reasonRef, violationClass)`: buyer only; state `OPEN`; `revealDeadline < now ≤
  revealDeadline + dqWindow` else `DisqualifyClosed`; `dqCount < maxDisqualifications` else `DisqualifyCapReached`;
  `topLen ≥ 2` (a next valid bid exists) else `NoNextBid`; `reasonRef ≠ 0`; `violationClass == 0` (no violation) or
  `1 ≤ violationClass ≤ 8` with bit `violationClass − 1` set in `forfeitClasses`, else
  `ViolationClassNotDeclared`. Effects: head's bid status `DISQUALIFIED`, `forfeit = (violationClass ≠ 0)`,
  `dqCount++`, pop the head of `top` (O(1), ≤ 3 entries). Emits `BidDisqualified(tenderId, bidder, reasonRef,
  violationClass, forfeit, newLeader)`.
- `settleTender(tenderId)`: state `OPEN`; caller is the buyer and `now > revealDeadline`, or anyone and `now >
  revealDeadline + dqWindow`. `validReveals ≥ minBidders ∧ topLen ≥ 1` ⇒ `SETTLED` with `winner = top[0]`, else
  `FAILED`; emits `TenderSettled(tenderId, winner, price, validReveals, commits)` (`winner = 0` when `FAILED`;
  `validReveals` includes disqualified bids). A second call reverts `WrongPhase`.

#### A.2.3 Payout routing (`withdrawDeposit(tenderId, bidder)`, permissionless, once per bid)

Settles first if `now > revealDeadline + dqWindow` and still `OPEN`; otherwise requires `SETTLED`, `FAILED` or
`CANCELLED` — except a `DISQUALIFIED` bid, which pays out at once (it can never lead again).

| Tender state | Bid | Destination | Event |
|---|---|---|---|
| `CANCELLED` | any | bidder | `DepositRefunded` |
| `SETTLED`/`FAILED` | revealed, valid, not winner | bidder | `DepositRefunded` |
| `SETTLED` | winner, `RETURN_ON_AWARD` | bidder | `DepositRefunded` |
| `SETTLED` | winner, `HOLD_UNTIL_RELEASE` | revert `BondHeld` (use `releaseBond`/`claimBond`) | — |
| `SETTLED`/`FAILED` | not revealed, or revealed invalid | `slashSink` | `DepositSlashed` |
| any (after disqualification) | `DISQUALIFIED`, `forfeit = false` | bidder | `DepositRefunded` |
| any (after disqualification) | `DISQUALIFIED`, `forfeit = true` (declared class) | `slashSink` | `DepositSlashed` |

Bid status becomes `DONE` before the token transfer (CEI). `releaseBond(tenderId)`: buyer at any time after settle,
anyone after `bondReleaseTime` ⇒ winner (`BondReleased`). `claimBond(tenderId, reasonRef)`: buyer, `HOLD`, `now <
bondReleaseTime` ⇒ `slashSink` (`BondClaimed`). Payouts use the token's plain `transfer` (the tender is the holder).

#### A.2.4 Invariants

- **I1** Every bidder of a cancelled tender, every valid non-winning revealer and every bidder disqualified without
  a declared violation class receives exactly `minDeposit`, through a permissionless call, with no expiry.
- **I2** For every token: `balanceOf(tender) ≥ Σ minDeposit over bids with status ≠ DONE`.
- **I3** No bid's price is derivable from chain data before that bidder's own reveal, in particular before
  `commitDeadline` (salt secret and uniformly random).
- **I4** Winner = the best valid, non-disqualified bid by (rule, seq); the buyer's only influence is removing the
  current leader inside the award window, at most `maxDisqualifications` times, never the last candidate, each with a
  public `reasonRef`.
- **I5** `settle` happens once; a bid pays out once (status `DONE`).
- **I6** No **bid deposit** enters the tender except through `commitBid` (relayer bound to the tender, R180); plain
  transfers to the tender are possible and unrecoverable (R187).
- **I7** A deposit is forfeited only for non-reveal, invalid reveal, a declared violation class, or a HOLD bond
  claim — never for an undeclared reason.

### A.3 Interface (supersedes SCaaS §14.7)

```solidity
interface ISealedBidTender {
    enum State { NONE, OPEN, REVEAL, AWARDABLE, SETTLED, FAILED, CANCELLED }   // REVEAL/AWARDABLE derived
    enum Rule { LOWEST_PRICE, HIGHEST_PRICE }
    enum BondPolicy { RETURN_ON_AWARD, HOLD_UNTIL_RELEASE }
    enum BidStatus { NONE, COMMITTED, REVEALED, DISQUALIFIED, DONE }

    struct TenderConfig {
        address depositToken; uint128 minDeposit;
        uint64 commitDeadline; uint64 revealDeadline;
        Rule rule; uint128 minPrice; uint128 maxPrice;      // inclusive; maxPrice 0 = unbounded (R184)
        uint32 minBidders;                                  // >= 1 (R185)
        BondPolicy bondPolicy; uint64 bondReleaseTime;      // HOLD only; else 0
        uint32 dqWindow;                                    // award window after revealDeadline, <= 7 d; 0 = off (R185)
        uint8 maxDisqualifications;                         // <= MAX_DISQUALIFICATIONS = 2
        uint8 forfeitClasses;                               // bitmask of declared violation classes 1..8
        address slashSink;                                  // R183
        bytes32 eligibilityRoot;                            // 0 = open
        bytes32 documentRef;                                // salted commitment of the tender documents (R198)
    }
    struct Bid { bytes32 commitment; uint128 price; uint64 seq; BidStatus status; bool valid; bool forfeit; }

    event TenderCreated(uint256 indexed tenderId, address indexed buyer, bytes32 documentRef, TenderConfig config);
    event TenderCancelled(uint256 indexed tenderId, bytes32 reasonRef);
    event BidCommitted(uint256 indexed tenderId, address indexed bidder, bytes32 commitment, uint64 seq);
    event BidRevealed(uint256 indexed tenderId, address indexed bidder, uint256 price, bool valid);
    event BidDisqualified(uint256 indexed tenderId, address indexed bidder, bytes32 reasonRef, uint8 violationClass,
                          bool forfeit, address newLeader);
    event TenderSettled(uint256 indexed tenderId, address indexed winner, uint256 price, uint32 validReveals,
                        uint32 commits);
    event DepositRefunded(uint256 indexed tenderId, address indexed bidder, uint256 amount);
    event DepositSlashed(uint256 indexed tenderId, address indexed bidder, address sink, uint256 amount);
    event BondReleased(uint256 indexed tenderId, address indexed winner, uint256 amount);
    event BondClaimed(uint256 indexed tenderId, bytes32 reasonRef, uint256 amount);

    error BadConfig(uint8 code);   // 1 token, 2 deposit, 3 windows, 4 bounds, 5 minBidders, 6 bond, 7 sink, 8 disqualification
    error WrongPhase(State state); error NotBuyer(); error NotEligible(address bidder); error BidExists(); error NoBid();
    error BidderExcluded(address bidder);   // buyer or slashSink
    error BadDepositIntent(uint8 code);     // 1 to, 2 value, 3 data, 4 fee mode, 5 relayer binding
    error DepositNotReceived(uint256 expected, uint256 got); error CommitmentMismatch();
    error DisqualifyClosed(); error DisqualifyCapReached(); error NoNextBid();
    error ViolationClassNotDeclared(uint8 violationClass); error BondHeld(); error BondNotHeld();

    function createTender(TenderConfig calldata c) external returns (uint256 tenderId);
    function cancelTender(uint256 tenderId, bytes32 reasonRef) external;                  // buyer, R185
    function commitBid(uint256 tenderId, bytes32 commitment, bytes32[] calldata eligibilityProof,
                       MetaTxLib.MetaTransaction calldata m, bytes calldata depositSig) external;   // anyone, R180
    function revealBid(uint256 tenderId, address bidder, uint128 price, bytes32 salt) external;   // anyone, R182
    function disqualifyWinner(uint256 tenderId, bytes32 reasonRef, uint8 violationClass) external;  // buyer, R185
    function settleTender(uint256 tenderId) external;                 // buyer after reveals; anyone after the window
    function withdrawDeposit(uint256 tenderId, address bidder) external;                  // anyone, §A.2.3
    function releaseBond(uint256 tenderId) external;
    function claimBond(uint256 tenderId, bytes32 reasonRef) external;                     // buyer, HOLD

    function commitmentOf(uint256 tenderId, address bidder, uint128 price, bytes32 salt) external view
        returns (bytes32);
    function depositRef(uint256 tenderId, bytes32 commitment) external view returns (bytes32);
    function state(uint256 tenderId) external view returns (State);
    function bidOf(uint256 tenderId, address bidder) external view returns (Bid memory);
    function leaders(uint256 tenderId) external view returns (address[] memory);          // current top list
    function configOf(uint256 tenderId) external view returns (TenderConfig memory, address buyer);
}
// constructor(address factoryV1, address factoryV2) — immutable (R186); either may be 0 on a chain without it.
```

Differences from SCaaS §14.7: R180 deposit, `commitBid`, signature-free reveal/withdraw and no replacement (R182),
disqualification window instead of `awardDeadline` (R185), `minBidders`/`FAILED`, per-bid routing, `uint128` prices.

### A.4 Storage

```
mapping(uint256 => Tender) tenders;     // Tender = TenderConfig (≈ 7 slots packed) + buyer, State, commits/validReveals
                                        //          uint32, nextSeq uint64, createdAt uint64, dqCount, topLen uint8,
                                        //          address[3] top (sorted, head = leader)   (≈ 12 slots)
mapping(uint256 => mapping(address => Bid)) bids;   // 2 slots: commitment | price, seq, status, valid, forfeit
uint256 nextTenderId;                   // starts at 1
// transient reentrancy guard keccak256("scaas.tender.reentrancy.v1") on every state-changing function (EIP-1153, R188)
```

No bidder list: ERPs enumerate bids from `BidCommitted` events. `createTender` checks (`BadConfig`): R186 token
acceptance (`isDeployedHere`, `versionOf` per factory type, `implementationOf ≠ 0`, `!isDeprecated`, kind in the META
set); `minDeposit > 0`; `now < commitDeadline ≤ now + 365 d`; reveal window in `[1 h, 30 d]`; `maxPrice == 0 ∨
minPrice ≤ maxPrice`; `minBidders ≥ 1`; HOLD ⇒ `revealDeadline < bondReleaseTime ≤ revealDeadline + 730 d`, RETURN ⇒
`bondReleaseTime == 0`; `slashSink ∉ {0, this}`; `dqWindow ≤ 7 d`, `maxDisqualifications ≤ 2`, `dqWindow == 0 ⇒
maxDisqualifications == 0 ∧ forfeitClasses == 0`.

### A.5 Flows

#### A.5.1 Buyer (ERP)

| # | ERP | Chain |
|---|---|---|
| 1 | Tender record linked to the RFQ; documents canonicalized (JCS), `documentRef` = salted commitment (§C.2); deposit token, `minDeposit`, deadlines, reserve, `minBidders`, bond policy, `slashSink`, allowlist root, `dqWindow`, `maxDisqualifications`, `forfeitClasses` (each class defined in the documents) | — |
| 2 | Chain check (§A.7.2): refuses, or warns with a recorded reason, on a chain whose validators the buyer organization controls alone; then a `call` job `createTender(config)` from the buyer account (namespace `allow_call`, R103) | `TenderCreated` (`tenderId` from the event) |
| 3 | Publishes tender id, deadlines, deposit terms, eligibility proofs; may offer a sponsored portal path (§B1), never as the bidders' only path | — |
| 4 | Watches commits (count only); may cancel until `commitDeadline` | `BidCommitted`, `TenderCancelled` |
| 5 | Inside the award window: due diligence on the leader; if it fails, `disqualifyWinner(reasonRef, class)` with the reason document committed (§C.2) and retained for audit and dispute | `BidDisqualified` |
| 5b | Then `settleTender` (buyer early, or any keeper after the window) | `TenderSettled` |
| 6 | On the **finalized** `TenderSettled`: PO to the winner; non-revealers = committed set − revealed set; keeper jobs `withdrawDeposit` for every bid (refunds and forfeits) | `DepositRefunded`, `DepositSlashed` |
| 7 | Bond: `releaseBond` on contract signature/delivery, or `claimBond(reasonRef)` | `BondReleased`/`BondClaimed` |
| 8 | Supplier invoice paid with `mtxPay` and a **fresh random `entryRef`** (R9); the link tender ↔ PO ↔ invoice ↔ `entryRef` stays off chain | `PaymentSettled` |

The payment `entryRef` is never derived from `tenderId` (R198, INT §5.1).

#### A.5.2 Bidder (ERP, portal or app)

0. **Independent path (normative, review H1).** Before signing a deposit intent, the bidder's ERP/app checks that it
   can submit `commitBid` and `revealBid` on that chain **without the buyer**: its own node namespace (own gas or
   own sponsor policy), a door run by a neutral operator, or a direct transaction from a wallet holding native coin.
   If none is configured it refuses to sign. The buyer's portal may be used as a convenience, never as the only path.
1. Generate `salt` (§A.5.4), compute `commitment = commitmentOf(…)` locally, store `(tenderId, price, salt)` in the
   bidder's secret store **before** signing.
2. Build and sign the deposit intent (R180): `to = tender`, `value = minDeposit`, `data = pay(depositRef)`,
   `batch = payLane(depositRef)`, `nonce = 0`, `mode = MODE_RESTRICT_RELAYER`, `relayer = tender`, `fee = 0`,
   `feeRecipient = 0`, `validUntil ≤ now + 3600`.
3. Submit `commitBid` as a `call` job (own path, or the portal). Verify `BidCommitted` is final; if missing before
   `validUntil`/`commitDeadline − margin`, submit the same signed intent through the independent path (any submitter
   works: the intent binds the tender, not a lane).
4. After `commitDeadline`: submit `revealBid` (no signature) through the independent path, or hand `(price, salt)` to
   the portal **and** verify `BidRevealed` before `revealDeadline − margin`, falling back to the independent path.
   The independent path is a namespace other than the portal's (a node door or own wallet): live-call dedupe is per
   namespace (NI R325), so a portal's queued, paused or under-capped copy of the same reveal never blocks it (Codex
   M1). On its own namespace a `409 DUPLICATE_CALL {uid}` names the bidder's own live job: follow it, or cancel it
   (never published) and re-push.
5. After settlement: refund arrives through any keeper's `withdrawDeposit`; the bidder's ERP books it from
   `DepositRefunded` (the outgoing deposit was booked from its own `PaymentSettled(entryRef = depositRef)`).

#### A.5.3 Gas

Bidder steps are relayed `call` jobs, so a bidder needs no native coin **if** its independent path pays gas (its own
node, or a neutral sponsor). A buyer may additionally sponsor its tender's `commitBid`/`revealBid`/`withdrawDeposit`/
`settleTender` selectors (§B1, `job_kind = call`). Size `max_cost_per_tx` for ERC-1271 bidders (§A.8).

#### A.5.4 Salt generation and backup (bidder)

A lost salt means a forfeited deposit. Either: (a) 32 CSPRNG bytes, encrypted backup with the bid record; or (b)
derived from a high-entropy secret the bidder already backs up: `salt = HKDF-SHA256(ikm = secret, info =
"scaas.tender.salt.v1" ‖ u256(chainId) ‖ tender ‖ u256(tenderId))`, where `secret` is a seed-vault key or passkey PRF
output (deterministic). Never an ECDSA/WebAuthn signature as entropy unless the signer is proven deterministic
(passkeys are not). The salt is never sent to anyone before `commitDeadline`.

### A.6 Node, Odoo, app touchpoints

| Where | Change |
|---|---|
| Node store | `chain_contract (chain_key, address, kind CHECK (kind IN ('tender', 'sponsorship_pool')), PRIMARY KEY (chain_key, address))`; admin `GET/POST/DELETE /v1/admin/chains/{key}/contracts` (viewer / admin / admin, audited) |
| Node indexer | indexes events of `chain_contract` rows like token events; `range` items carry them; a namespace receives them when the contract is in its token subset (`PUT /v1/tokens/{chain}` accepts registered contracts) |
| Node submit | `call` jobs to a registered tender: simulation as usual; no batching; live duplicates in the same namespace refused with the live `uid` (§B1.3, NI R325); `commitBid` jobs pass R86 because the inner token is registered |
| Odoo (`dms_blockchain*`, example) | model `blockchain.tender` (config, state, `tender_id`, `chain_id`, links to RFQ/PO), `blockchain.tender.bid` (own bids: commitment, encrypted `(price, salt)`, status) with `SERVER_ONLY` secret fields (NI R101); producers `blockchain.tender` / `blockchain.tender.bid` on outbox jobs; handlers for the ten events; PO creation only from the finalized `TenderSettled`; the H1 path check before signing |
| App | bidder view: compute commitment and salt in the client (`clientkeys`), sign the deposit intent, reveal reminder at `commitDeadline` |

### A.7 Security analysis

#### A.7.1 Abuse table

| Threat | Defence |
|---|---|
| Copying a commitment to another tender/chain, or pairing a deposit with another commitment | R181 binding; `depositRef` inside the signed `pay` data (R180) |
| Landing the deposit outside `commitBid` (stranded funds) | relayer bound to the tender (I6) |
| Fake token implementing a no-op `executeMetaTransaction` | R186 provenance + balance delta |
| Fee taken from the deposit intent to the tender (`feeRecipient` unbound ⇒ `msg.sender` = tender) | fee mode `NONE` required |
| Last-revealer exit after seeing others | possible at the cost of `minDeposit` (forfeit); out-of-range reveal is also forfeit (R184) |
| Selective reveal by a multi-identity bidder | each unrevealed identity forfeits `minDeposit`; buyer sizes `minDeposit` ≥ expected surplus at risk; allowlist |
| Buyer reads prices early | impossible from chain data (I3); the bidder never sends `(price, salt)` before `commitDeadline` |
| Buyer withholds sponsorship, a handed-over commit or reveal ⇒ forfeit to the buyer's sink | independent path required before signing (§A.5.2 step 0), verify-and-fallback in steps 3–4 (R183) |
| Buyer aborts after seeing prices | no cancel after `commitDeadline`; the last candidate cannot be disqualified (R185); remaining: a buyer sybil winning or refusing the PO off chain (§A.7.2) |
| Buyer never settles / withholds refunds | settle and withdraw are permissionless after the window (R185, R182) |
| Buyer cherry-picks the winner by disqualifying | leader only, inside `dqWindow`, cap ≤ 2, public `reasonRef` and event; residual risk §A.7.2 |
| Buyer seizes deposits with false violation claims | only classes declared at creation; reason committed and openable in a dispute; residual risk §A.7.2 |
| Sybil fills the tender to lock out real bidders | no bid cap; each bid costs `minDeposit` and is refunded only to the bidder |
| Deposits locked by extreme windows | R187 caps |
| Reentrancy via token | registered META code + transient guard + CEI |
| Censorship near deadlines on a public chain | bidders commit early; reveal window ≥ 1 h floor (24 h default) |
| Buyer controls inclusion or timestamps (own PoA/private chain) | not defended on chain; ERP refuses or warns (§A.5.1 step 2, §A.7.2) |

#### A.7.2 Known limits (stated to users)

- **Chain neutrality (review M5).** The tender is fair only on a chain whose transaction inclusion the buyer does not
  control. On a private/PoA chain validated by the buyer organization alone, it can censor competitors' reveals
  (forfeiting them to its own sink), censor commits and move timestamps within consensus rules. Commit ordering (the
  tie-break) is decided by submitters and block producers.
- A buyer can commit and reveal through a sybil identity; if the sybil wins, the tender ends without a real award
  (the sybil's deposit is refunded as winner) — equivalent to refusing the PO, which no contract can prevent. The
  award on chain is evidence of a fair procedure, not an enforcement of the purchase.
- **Residual buyer discretion.** Within the award window the buyer can pass over the best `maxDisqualifications`
  (≤ 2) valid bids, so in effect choose among the top three, but never end the tender without a winner. With declared
  violation classes it forfeits those deposits to `slashSink`, and under `HOLD_UNTIL_RELEASE` it may also claim the
  winner's bond: up to three deposits per tender — an incentive to allege violations when the sink is the buyer's own
  organization. The contract cannot judge whether a reason is true: it makes every use public, bounded and bound to
  a committed document the bidder can contest off chain. Tenders that want no discretion set `dqWindow = 0` and
  `RETURN_ON_AWARD`; bidders that distrust the buyer can demand a neutral `slashSink` or `forfeitClasses = 0`.
- Bidder identities are public at commit (addresses), prices at reveal, forever (R198).

### A.8 Gas (estimates, to be measured in TB1)

| Call | Estimate | Notes |
|---|---|---|
| `createTender` | 240–280 k | ~12 new slots + event with config |
| `commitBid` (EOA bidder) | 120–150 k | token meta-tx with first-use lane (~52 k) + 2 bid slots (44 k) + checks, Merkle proof ~1.5 k/level |
| `commitBid` (ERC-1271 bidder) | + up to 400 k | `SubjectAccount` cap; WebAuthn P-256 ≈ 100–300 k. Sponsors size `max_cost_per_tx` for this row, or ERC-1271 bidders die with `SPONSOR_TX_CAP` |
| `revealBid` | 25–50 k | keccak + 1 slot update + sorted insert into `top` (≤ 3) |
| `disqualifyWinner` | 15–30 k | status write + pop head |
| `settleTender` | 8–15 k | state write + event |
| `withdrawDeposit` | 30–45 k | status write + token transfer (cold recipient adds ~20 k) |

### A.9 Tests (TB1)

Unit: every `BadConfig` code; commit with each `BadDepositIntent` code; v1 and v2 tokens; factory-v2 `META` kind
accepted when registered; unregistered and deprecated token refused; Zether refused; eligibility proof valid/invalid;
buyer and sink cannot bid; ERC-1271 bidder (`SubjectAccount`); reveal mismatch, out-of-range reveal, reveal outside
the window; ties broken by `seq`; both rules; `minBidders` ⇒ `FAILED`; cancel before/after `commitDeadline`, and
commit + cancel in the same block at `now == commitDeadline`; every routing row of §A.2.3 and double withdraw; bond
release by buyer, by anyone after `bondReleaseTime`, claim before it. **I6 front-running:** a third party submits the
deposit intent through `mtxPay`, `mtxBatch`, `executeMetaTransaction` (v2) and `executeMetaTransaction` (v1) ⇒
`MetaTxUnauthorizedRelayer`; the intent replayed into another `tenderId` and another tender contract ⇒
`BadDepositIntent(3)`. Disqualification: outside the window (before `revealDeadline`, after `revealDeadline +
dqWindow`), non-buyer, `dqWindow = 0`, cap reached, `NoNextBid` on the last candidate, zero `reasonRef`, undeclared
class, class 0 ⇒ refund, declared class ⇒ forfeit; next leader correct for both rules with ties, invalid bids never
in `top`, `top` truncation at `k`; settle by buyer inside the window closes it; disqualified bid withdrawable before
settle. Invariant fuzz (random bidders, prices, reveals, disqualifications, timing): I1–I7. KATs (`tests/kat/
tender.json`, Python and TypeScript builders): `commitmentOf`, `depositRef`, the deposit `pay` data. Hedera (TB2):
same bytecode on HSCS with a 64-byte ED25519 deposit intent (HIP-632 on the token). Gas snapshot including an
ERC-1271 bidder. Deploy script: `TSTORE` probe refuses a chain without EIP-1153 (R188).

### A.10 Families

| Family | Status | Design notes |
|---|---|---|
| EVM | **SPECIFIED** (TB1) | this section |
| Hedera | **SPECIFIED** (TB2) | same bytecode on HSCS (no child: the tender checks no signature); deposit token = Hedera v2 meta token; gas limit tight (HSCS charges ≥ 80 % of the limit); EIP-1153 as for the Hedera token children (R188) |
| Cosmos (CosmWasm) | PLANNED | contract holds the deposit; commit = the meta token's signed `Relay` op with a `pay` memo = `depositRef`, executed by the tender via submessage; commitment over `(chain_id, contract, tender, bidder, price, salt)` with SHA-256 |
| Soroban | PLANNED | `require_auth` entries of the bidder for `commit_bid` (deposit = SAC/token `transfer` sub-invocation in the same auth tree); reveal/withdraw permissionless |
| Sui / Aptos | PLANNED | tender object / resource; deposit coin moved by the relayer-submitted PTB / entry function under the bidder's signed op; time from `Clock` / `timestamp` |
| TON | PLANNED | async: deposit arrives as a jetton `transfer_notification` with `forward_payload = (tenderId, commitment)`; reveal/withdraw are internal messages; bounce handling on refunds |
| Solana | PLANNED | program + PDA vault per tender; deposit via the token program CPI under the bidder's Ed25519-precompile-verified op (RS12) |

---

## B1. Gas sponsorship policy (node)

### B1.1 Model

The node already pays gas for every job it lands. A policy decides **which account that gas is booked to, how much
of it is allowed, and whether a fee floor is waived** (R189). Matching and the budget reservation happen at accept
on job data only (plus a local signature check on public doors), with the rate counts (rev 1.3); the fee cap at
lease; booking at the end. The result is stored on the job (`sponsor_policy_id`, `sponsor_reserved`, `sponsor_day`,
`sponsor_hour`). The client keeps booking from finalized events plus the new
cost fields on the jobs feed.

### B1.2 Store (additions to NI §4)

```sql
CREATE TABLE sponsor_policy (
  id              BIGINT PRIMARY KEY,                 -- from counter row 'sponsor_policy'
  name            TEXT NOT NULL UNIQUE,               -- [a-z0-9._-]{3,64}
  state           TEXT NOT NULL CHECK (state IN ('active', 'paused')),
  priority        INTEGER NOT NULL DEFAULT 100,       -- lower first; ties by id
  namespace       TEXT NOT NULL,                      -- a namespace, '~gateway', '~mesh', or '*'
  chain_key       TEXT NOT NULL,
  job_kind        TEXT NOT NULL CHECK (job_kind IN ('metatx', 'signed_op', 'call', '*')),
  contract        TEXT NOT NULL,                      -- token (metatx/signed_op: token_of, MESH R86) or call target; canonical, or '*'
  selector        TEXT NOT NULL,                      -- EVM '0x'+8 hex | '0x' (transfer) | '*'; non-EVM 'pay' | '*'
  receiver        TEXT,                               -- canonical m.to / op payee; NULL = any (metatx/signed_op only)
  min_value       TEXT NOT NULL DEFAULT '0',          -- uint256 decimal, token base units (R189); must be '0' when contract = '*'
  account         TEXT NOT NULL,                      -- opaque booking label (cost centre / sponsor contract id); no personal data
  max_cost_per_tx TEXT NOT NULL,                      -- smallest native unit; reservation and per-tx cap
  budget_per_day  TEXT NOT NULL,                      -- smallest native unit, UTC day
  max_tx_per_hour INTEGER NOT NULL, max_tx_per_payer_hour INTEGER NOT NULL,   -- payer per §B1.3; 0 = no per-payer cap
  on_exhausted    TEXT NOT NULL CHECK (on_exhausted IN ('reject', 'unsponsored')),
  min_valid_secs  INTEGER NOT NULL DEFAULT 120,       -- rev 1.3: sponsored only if valid_until ≥ now + this (R190)
  valid_from BIGINT, valid_to BIGINT, created_by TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX sponsor_policy_match ON sponsor_policy (chain_key, state, priority, id);

CREATE TABLE sponsor_usage (                          -- buckets: day (cost), hour (tx), payer-hour (tx)
  policy_id BIGINT NOT NULL, bucket TEXT NOT NULL,    -- 'd:2026-10-06' | 'h:2026-10-06T14' | 'p:<payer>:2026-10-06T14'
  tx_count BIGINT NOT NULL DEFAULT 0,                 -- jobs admitted in the hour (rev 1.3: at accept; −1 on a pre-broadcast end)
  cost_spent TEXT NOT NULL DEFAULT '0',               -- measured (decimal, arbitrary precision in code)
  cost_reserved TEXT NOT NULL DEFAULT '0',            -- Σ job.sponsor_reserved of live jobs of this day
  PRIMARY KEY (policy_id, bucket));                   -- hour/payer buckets pruned after 48 h, day buckets after 400 d

-- job additions
ALTER TABLE job ADD COLUMN sponsor_policy_id BIGINT;  -- NULL = booked to the namespace
ALTER TABLE job ADD COLUMN sponsor_reserved TEXT;     -- amount reserved at accept (released/booked exactly)
ALTER TABLE job ADD COLUMN sponsor_day TEXT;          -- 'd:YYYY-MM-DD' of the reservation; cost books to this day
ALTER TABLE job ADD COLUMN sponsor_hour TEXT;         -- rev 1.3: 'YYYY-MM-DDTHH' of the reservation; its counts are released here
ALTER TABLE job ADD COLUMN sponsor_fallback TEXT;     -- policy name when matched but exhausted with on_exhausted = unsponsored (NI rev 3.6)
ALTER TABLE job ADD COLUMN call_hash BLOB;            -- kind = call: keccak256(target ‖ calldata); else NULL
CREATE UNIQUE INDEX job_live_call ON job (namespace, chain_key, call_hash)   -- per namespace (NI R325)
  WHERE call_hash IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');   -- ⇒ 409 DUPLICATE_CALL {uid}
ALTER TABLE job ADD COLUMN gas_used BIGINT;           -- or the family's resource figure
ALTER TABLE job ADD COLUMN gas_price TEXT;            -- effective price, smallest native unit per gas (EVM/Hedera)
ALTER TABLE job ADD COLUMN cost_native TEXT;          -- total fee paid by the lane, smallest native unit
```

Hedera reports cost in tinybar from the record (gas price conversion is the network's); Cosmos the `fee` coin of the
outer tx; Sui `gasUsed` total; Aptos `gas_used × gas_unit_price`; TON total fees of the outer message chain charged
to the lane; Solana `meta.fee` (+ priority fee); Soroban `fee_charged` (stroops).

### B1.3 Evaluation (accept, lease, end)

```
match(job) -> Option<policy>:                                  -- accept, after NI §5.2 step 7
  candidates = active policies of job.chain_key, now within [valid_from, valid_to], ordered (priority, id)
  first p where  p.namespace ∈ {job.namespace, '*'}          -- '*' never matches '~mesh'/'~gateway' (explicit only)
             ∧ p.job_kind ∈ {job.kind, '*'}
             ∧ p.contract ∈ {contract_of(job), '*'}         -- metatx/signed_op: token_of; call: target
             ∧ p.selector ∈ {selector_of(job), '*'}
             ∧ (p.receiver IS NULL ∨ p.receiver == receiver_of(job))   -- call jobs: receiver must be NULL
             ∧ value_of(job) ≥ p.min_value                   -- call jobs: min_value must be '0'
admit(job, p):                                                 -- accept, inside the step-8 transaction
  public door (~gateway, ~mesh) ∧ metatx/signed_op ⇒ verify the payer signature locally (ECDSA secp256k1, Ed25519,
      P-256: no RPC); contract (ERC-1271) payers are not sponsored on public doors; bad signature ⇒ 422 BAD_SIGNATURE
  job.valid_until < now + p.min_valid_secs ⇒ ¬ok (TOO_SHORT)                       -- rev 1.3, Codex H2
  lock bucket rows: INSERT … ON CONFLICT DO NOTHING, then SELECT … FOR UPDATE (day, hour, payer-hour; SQLite: the
      single writer suffices)
  ok = day.cost_spent + day.cost_reserved + p.max_cost_per_tx ≤ p.budget_per_day        (BUDGET)
     ∧ hour.tx_count < p.max_tx_per_hour ∧ (p.max_tx_per_payer_hour = 0 ∨ payer-hour.tx_count < it)   (RATE)
  ok         ⇒ job.sponsor_policy_id = p.id, sponsor_reserved = p.max_cost_per_tx, sponsor_day = today,
               sponsor_hour = this hour; day.cost_reserved += sponsor_reserved;
               day/hour/payer-hour tx_count += 1                      (rev 1.3: counts taken here, Codex H2)
  ¬ok, reject      ⇒ 429 SPONSOR_BUDGET | SPONSOR_RATE | SPONSOR_TOO_SHORT {policy: p.name}
  ¬ok, unsponsored ⇒ no sponsor, sponsor_fallback = p.name; the door's normal fee floor applies
                     (client namespace: booked to the namespace, R189)
no match ⇒ no sponsor; the door's normal fee floor applies
lease (after simulation succeeds):
  max chargeable fee of the tx as built (EVM: gas_limit × max_fee_cap) > job.sponsor_reserved ⇒ dead SPONSOR_TX_CAP
  fee bumps of a stuck tx stop at gas_limit × price = sponsor_reserved
end (mined/reverted): day(sponsor_day).cost_reserved −= sponsor_reserved; cost_spent += cost_native
end (dead/consumed-before-broadcast/cancelled): release the reservation and the three tx_count (buckets of
     sponsor_day/sponsor_hour, payer_of(job)), in the terminal transaction; lost races after broadcast book their
     measured cost and keep their counts
startup: cost_reserved recomputed as Σ sponsor_reserved of live jobs per sponsor_day (tx_count is transactional)
```

Payer (`payer_of`) for per-payer caps: `m.from` / op signer for metatx/signed_op; for `call` jobs to a registered
tender, `m.from` decoded from `commitBid` and the `bidder` argument of `revealBid`/`withdrawDeposit`; any other `call`
has no payer and its policy must set `max_tx_per_payer_hour = 0`. Live `call` jobs of one namespace with the same
target and calldata are refused (`job_live_call`, per namespace, NI R325), so a retried reveal or refund cannot be
broadcast twice from one tenant; the `409 DUPLICATE_CALL` body carries the live job's `uid` (same namespace, so it
leaks nothing) and the client follows that job, or cancels it before publication and re-pushes. Two namespaces may
each hold the same tender call; the tender refuses the second (the bid is no longer `COMMITTED`, or already `DONE`):
simulation makes it `dead`, a lost race after broadcast books as `reverted`. Dedupe stays on live states rather than
signed ones (Codex M1 alternative): two queued copies in one namespace would otherwise both broadcast.

Fee floor per door: client namespaces — none (jobs are accepted as today); `~gateway` and `~mesh` — the MESH §7
`min_fee` of the matching mesh policy row, compared with the effective fee (R86). A sponsored job's floor is 0. A
policy never makes a job acceptable that NI §5.2 or MESH §7.2 would refuse for any other reason (unregistered token,
`support = none`, expiry, `allow_call`).

### B1.4 Jobs feed and client booking

Job feed items in states `mined`, `reverted` (and the final snapshot) add `gas_used`, `gas_price`, `cost_native`,
`sponsor: {policy, account} | null`, and `sponsor_fallback: <policy name> | null` (a policy matched but was exhausted
and `on_exhausted = unsponsored`, R189). Clients book `cost_native` (converted at transaction time to the reporting
currency) to the business document of the job (SCaaS §13.2 FinOps) and, when `sponsor` is set, to the sponsor
account named by `account` (e.g. "inbound subsidy, customer programme Y"). The node never receives fiat values.

### B1.5 Admin API (NI §7.3 additions)

| Route | Role | Hot |
|---|---|---|
| `GET /v1/admin/sponsorship/policies[/{id}]` | viewer | — |
| `POST /v1/admin/sponsorship/policies`, `PATCH …/{id}`, `DELETE …/{id}` (delete refused while live jobs reference it ⇒ `409 POLICY_BUSY`; pause instead) | admin | hot |
| `PUT /v1/admin/sponsorship/policies/{id}/state` (`active`/`paused`) | operator | hot |
| `GET /v1/admin/sponsorship/usage?policy=&since=&bucket=day|hour` | viewer | — |
| `GET/POST/DELETE /v1/admin/chains/{key}/contracts` (§A.6) | viewer / admin / admin | hot |

Write validation: canonical addresses (`addresses.canonical`), lowercase selectors, `contract = '*'` ⇒
`min_value = '0'`, `job_kind = call` ⇒ `receiver IS NULL ∧ min_value = '0'` (and `max_tx_per_payer_hour = 0` unless
the target is a registered tender), policies on `~gateway`/`~mesh` need a concrete `contract` and (`min_value > 0` or
a `receiver`) — except the one `~gateway` `call` shape NI R320 creates: `contract = chain.ua_registry`, `selector` =
`register`, `max_tx_per_payer_hour = 0` (UA S6 sponsored registration; budget and hourly cap bound it), every uint256
field parses, `namespace` exists or is reserved/`*`, `30 ≤ min_valid_secs ≤ chain.max_valid_for_secs`, and
`on_exhausted = unsponsored` on a client namespace (or `*`) only with `fallback_to_namespace: true` in the request
(R189; recorded in the audit row) ⇒ else `422 POLICY_INVALID`. A `PATCH` never changes the
reservation of live jobs (they keep `sponsor_reserved`). Every mutation is an `audit_log` row with before/after (R110). Bootstrap from
`node.toml` `[[sponsorship.policies]]` follows R95 (import if absent, never overwrite).

### B1.6 Metrics

`scaas_sponsor_jobs_total{policy,chain,result="admitted|rejected_budget|rejected_rate|rejected_too_short|unsponsored|tx_cap|bad_sig"}`,
`scaas_sponsor_cost_spent{policy,chain}` (gauge, current UTC day, native smallest unit as float),
`scaas_sponsor_budget_remaining_ratio{policy}`, `scaas_sponsor_reserved{policy}`. No payer labels (cardinality,
and payers are pseudonymous personal data, SCaaS §11.1).

### B1.7 Security

| Threat | Defence |
|---|---|
| Gas drain through a public door with fee 0 | `~gateway`/`~mesh` need an explicit, concrete policy (`*` namespace does not match them; `min_value > 0` or `receiver`); budget, hourly and per-payer caps |
| Garbage-signature jobs burn rate caps or forge per-payer keys | local signature check before sponsoring on public doors; a job that dies before broadcast releases its counts (rev 1.3) |
| Reservation starvation: one payer reserves the day budget with jobs that never reach lease (Codex H2) | hour and payer-hour counts taken at accept with the reservation; `min_valid_secs` refuses near-expiry jobs |
| Exhausted client-namespace policy with `unsponsored` spends gas unseen (Codex H1) | booked to the namespace, marked `sponsor_fallback`; `unsponsored` on a client namespace needs an explicit, audited `fallback_to_namespace`; tenant caps use `reject` (R189) |
| Another namespace's queued copy of a reveal blocks the bidder (Codex M1) | dedupe per namespace (NI R325); `DUPLICATE_CALL` names the own live `uid` |
| Duplicate `call` jobs (retried reveal/refund) both broadcast and the loser's revert is booked | `job_live_call` unique index (per namespace) |
| Concurrent accepts lose bucket updates (MySQL REPEATABLE READ) | bucket rows locked `FOR UPDATE` in the step-8 transaction |
| Farming an inbound subsidy ("≥ X to wallet W") | the farmer pays ≥ X to W per sponsored tx; per-payer cap |
| Simulation-passes-then-reverts griefing | measured cost counts against the budget; MESH `origin_grief_score` applies to `~mesh` |
| Expensive calldata (huge batch, heavy ERC-1271) | maximum chargeable fee ≤ `sponsor_reserved` at lease, bumps capped |
| Policy edit by a low role | create/patch/delete `admin` only, audited |
| Over-reservation starving a policy | released on every terminal state from the job's own `sponsor_reserved`/`sponsor_day`; recomputed at startup |

Tests (SP1): matching precedence and every wildcard rule; `'*'` vs reserved namespaces; budget boundary (exactly
equal admits); hour and payer-hour caps; `reject` vs `unsponsored`; reservation release on each terminal state;
restart recomputes reservations; lease-time `SPONSOR_TX_CAP`; day rollover (reserved D, mined D+1 books to D) and hour
rollover (counts released to `sponsor_hour`); `PATCH` of `max_cost_per_tx` while jobs are live; a job `dead` before
broadcast releases its counts; **one payer cannot reserve beyond `max_tx_per_payer_hour × max_cost_per_tx`** and
queued jobs count toward `max_tx_per_hour` (Codex H2); `valid_until < now + min_valid_secs` ⇒ `SPONSOR_TOO_SHORT` /
unsponsored; **an exhausted client-namespace policy with `unsponsored` books to the namespace, sets
`sponsor_fallback`, never touches the sponsor account; the write without `fallback_to_namespace` ⇒ `422`** (Codex
H1); the `~gateway` UA-registration policy accepted, any other `~gateway` `call` policy refused; bad-signature and
ERC-1271 jobs on public doors; duplicate `call` jobs in one namespace ⇒ `DUPLICATE_CALL {uid}`, the same call in two
namespaces accepted in both (Codex M1); concurrent accepts on
PostgreSQL and MySQL; feed fields per family (EVM, Hedera, one non-EVM); admin route roles and audit rows; toml import
precedence.

### B1.8 Families

Every family (node-level): §B1.2 cost fields; `signed_op` matches on the decoded op. Non-EVM: book and limit only.

---

## B2. Receiver-pays

### B2.1 Messages

Payer (unchanged type): `MetaTransaction{from: payer, to: payee, value: N, data: pay(entryRef), batch:
payLane(entryRef), nonce: 0, validUntil, mode (fee NONE | MODE_RESTRICT_RELAYER), relayer: the submitting lane, fee:
0, feeRecipient: any (not checked)}` in domain `("SCaaS MetaToken", "2", chainId, token)`. `paymentDigest = _hashTypedDataV4(hashStruct(m))`.

Payee (new, same domain):

```solidity
bytes32 constant RECEIVER_FEE_TYPEHASH =
    keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");
```

`feeRecipient` must be non-zero (review M4: with "0 ⇒ `msg.sender`" a mempool copier could front-run and take the fee);
the payee names the relayer's fee address (the node's `chains.fee_recipient`). No nonce: `paymentDigest` executes at most once (payer nonce), and only through this function does the
co-signature have any effect.

### B2.2 Function (TW2 §7 style, `MetaTokenBase`)

```solidity
event ReceiverFeePaid(bytes32 indexed paymentDigest, address indexed payee, address indexed feeRecipient, uint256 fee);
error ReceiverFeeShape();   // not pay op; payer fee mode != NONE or fee != 0; relayer unbound; lane/nonce not payLane/0; feeRecipient 0
error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
error ReceiverFeeAmount(uint256 fee, uint256 value);        // fee == 0 or fee > value

function mtxPayReceiverFee(MetaTxLib.MetaTransaction calldata m, bytes calldata payerSig,
                           uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig)
    external nonReentrant returns (bool);
function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
    external view returns (bytes32);
```

Order:

1. Shape (`ReceiverFeeShape`): `m.data` is `pay(p)` (36 bytes), `feeModeOf(m.mode) == NONE`, `m.fee == 0`,
   `m.mode & MODE_RESTRICT_RELAYER ≠ 0`, `m.batch == payLane(p)`, `m.nonce == 0`, `feeRecipient ≠ 0`; `m.feeRecipient`
   is deliberately not checked (`canon` zeroes it; NI R100 may set it). Then `block.timestamp ≤ rfValidUntil`;
   `0 < fee ≤ m.value`.
2. `feeRecipient == m.to` ⇒ `FeeRecipientIsPayee` (R132).
3. `bytes32 d = _execute(m, payerSig)` — the unchanged nine steps (payer → payee `N`, `PaymentSettled`,
   `MetaTransactionExecuted`); `_execute` now returns its digest (internal change only).
4. `_requireValidSignature(m.to, receiverFeeDigest(d, fee, feeRecipient, rfValidUntil), payeeSig)` (EOA, ERC-1271 with
   `_erc1271Gas(m.to)`, HIP-632 on Hedera children).
5. `_transfer(m.to, feeRecipient, fee)` (cannot fail: the payee just received `N ≥ fee`); emit `ReceiverFeePaid(d,
   m.to, feeRecipient, fee)`.

Equivalence: the payer side is exactly `mtxPay`/`executeMetaTransaction` with the same struct — same digest, events
and nonce. A payer signature landed through any other path makes the co-signature dead (no fee is taken).

### B2.3 Invariants

- **RP1** The payee's net change from the call is `N − fee ≥ 0`; the payer's is `−N`; the fee recipient's `+fee`.
- **RP2** A co-signature takes effect at most once and only together with the exact payer intent it names.
- **RP3** No signed field can be changed by the relayer. **RP4** Fee collected ⇔ payment completed (one transaction).

### B2.4 Abuse

| Threat | Defence |
|---|---|
| Relayer raises the fee or redirects it | `fee`, `feeRecipient` signed by the payee |
| Payee signature replayed on another payment | bound to `paymentDigest` (domain = token + chain) |
| Payer forces a fee on the payee | needs `payeeSig` |
| Race: someone lands the payer intent alone, or copies the call to take the fee | payer relayer bound (required) and `feeRecipient` non-zero (required) |
| Co-sign key compromised | it controls the receiving wallet: use a hot collection wallet with an automated sweep (§B2.5) |
| Fee leaves the payee negative | `fee ≤ m.value` (RP1) |
| Malicious ERC-1271 payee wallet | `staticcall` with the token's gas cap; failure reverts the whole call (payer intent stays valid elsewhere) |

### B2.5 Node, Odoo, app touchpoints

- **Job payload** (`kind = metatx`, NI §5.2): optional `receiver_fee: {fee, feeRecipient, validUntil, signature}`.
  Digest = the payer digest (G2 unchanged). Accept adds: shape of §B2.2 step 1–2 without RPC; `valid_until =
  min(m.validUntil, receiver_fee.validUntil)`; `bus.scope` forced `restricted` (R193); never batched. R100 may rewrite
  the payer's unbound `feeRecipient`; the contract ignores it. The co-signed `feeRecipient` is signed and untouched. Submit calls `mtxPayReceiverFee`.
  Token capability: admin flag `token.features` contains `receiver_fee` (set at registration; simulation is the final
  check) ⇒ else `422 FEATURE_UNSUPPORTED`.
- **Indexer:** decodes `ReceiverFeePaid` into `range` items.
- **Payee ERP (Odoo example):** payment request field `fee_paid_by_receiver` and `receiver_fee_amount` (base units)
  on the request the payee issues; after the payer's address is known (portal: wallet connected) the server builds
  the payer's typed data with fee `NONE` and relayer = its lane, computes `paymentDigest` and signs `ReceiverFee` with
  the receiving wallet's key. **That key controls the wallet** (a `SubjectAccount` key validates any digest and
  authorizes `executeAsOwner`; there is no scoped key kind): the receiving wallet for this mode is a dedicated **hot
  collection wallet** (EOA or `SubjectAccount`) holding only incoming receiver-pays funds, swept automatically
  (mandate or periodic transfer) to a cold treasury. A cold receiving wallet cannot co-sign and must not offer this
  mode. A scoped `ReceiverFee`-only key kind is a separate SubjectAccount v2 change (§9). Booking: receipt `N` from `PaymentSettled`, fee expense `F` from `ReceiverFeePaid` matched by digest.
- **Payer ERP:** unchanged (pays `N`, books `N`).
- **E-cheque flow:** the payee's request names the relayer lane; the payer signs offline with that relayer bound and
  hands the intent to the payee, which co-signs over the digest and pushes it to that relayer's node.
- **Bytecode size (review L4):** RP1 extends the TW2 24,576-byte CI gate to every tier and both Hedera children; if
  one exceeds it, the `ReceiverFee` hashing and check move to an external library (`ReceiverFeeLib`, public
  functions), as TW2 §10's fallback.

### B2.6 Gas and tests

Gas: `mtxPay` + payee signature (~4 k EOA, ERC-1271 up to its cap) + `ReceiverFee` hashing (~1 k) + one transfer
(~7 k warm, ~25 k new recipient) + event (~2 k): **+14 to +32 k** over `mtxPay`. Measured in RP-stream gas tests.

Tests (RP1): each shape error (unbound payer relayer, wrong lane or nonce, zero `feeRecipient`); a payer intent with
a non-zero unbound `m.feeRecipient` succeeds (H2); fee 0, fee = value, fee > value; recipient = payee;
co-signature over another digest; expired co-signature; replay after the payer intent landed through
`executeMetaTransaction` (bad nonce); ERC-1271 payee (`SubjectAccount`) and Hedera HIP-632 payee; RP1/RP4 under
fuzz; event fields; node accept rules and the forced `restricted` scope.

### B2.7 Families

EVM and Hedera v2 (next implementation version per tier). v1, Zether and non-EVM families: not available (R193,
non-goals); there the options are payee self-relay and sponsorship.

---

## B3. SponsorshipPool (PLANNED-later stream PL1)

Rev 1.2 keeps only the rule (R194) and the constraints PL1 must meet (review O3): an immutable contract; programs
funded by a sponsor in native coin, scoped to one registered token (R186 provenance), optional receiver, selector and
minimum value; `settle(program, m, sig)` executes the intent (fee `NONE`) and pays `msg.sender` the R194 refund;
per-payer daily cap; withdrawals after `withdrawDelay`; events for funding, withdrawal and each sponsored intent;
transient reentrancy guard (EIP-1153 prerequisite as R188). Open design points for PL1: the Hedera formula (HSCS charges ≥ 80 % of the gas limit), the
block-producer caveat of R194, and node routing (a `call` job to `settle` on a registered `sponsorship_pool`
contract, §A.6; not carried by the mesh).

---

## C. Crypto-shredding

### C.1 Data placement

| Item | Chain | Node | Client (system of record) |
|---|---|---|---|
| Party identity, documents, contact data | never | never | yes (erasable) |
| Address ↔ party mapping | never | never | yes (erasable) |
| Salts, per-subject DEKs | never | never | yes (secret store) |
| Commitments, Merkle roots, `entryRef`, `depositRef`, digests | yes (permanent) | job payloads ≤ 30 d | yes |
| Addresses and transparent amounts | yes (permanent, value transfers) | job payloads ≤ 30 d, feeds 7 d | yes |
| Zether ciphertexts, auditor ciphertexts | yes (permanent) | job payloads ≤ 30 d | openings only when produced |
| Revealed tender prices | yes (permanent) | feeds 7 d | yes |

### C.2 Commitment formats (R196)

```
salt          = CSPRNG(32 bytes), one per record, never reused, never derived from the payload
payloadHash   = SHA-256(JCS(payload))                         # RFC 8785, same canonical form as NI R91
commitment    = keccak256(abi.encode(REC_TAG, salt, payloadHash))   REC_TAG = keccak256("scaas.commit.v1")
merkle leaf   = keccak256(0x00 ‖ commitment)                  # one leaf per record
merkle node   = keccak256(0x01 ‖ min(a, b) ‖ max(a, b))       # sorted pairs; custom verifier (not OZ MerkleProof,
                                                              # whose leaves are double-hashed as in §A.2.1)
```

Uses: `documentRef` (tender documents), `reasonRef` (cancel, bond claim), anchored records (SCaaS §2.2) and batch
roots. The payload is never on chain; `payloadHash` alone is not published (a hash of low-entropy data is
brute-forceable, the salt is what hides it).

### C.3 Salt and key storage (client; Odoo example)

- **Hierarchy:** KEK (KMS/HSM/Vault transit, or a key file/env secret outside the database) → per-subject DEK
  (AES-256-GCM key, wrapped) → **salt and anchored payload** of each record encrypted with the DEK (AES-256-GCM, AAD =
  model + record id). `log_key` (erasure log) and `subject_key` (for `subject_ref`) are two distinct keys held with
  the KEK, never in the database; they are separate so the log cannot be joined to key rows unless intended.
- **Tier A (KMS/secret store):** DEK destroyed in the KMS ⇒ salts and payloads unreadable everywhere, backups
  included, at once.
- **Tier B (no KMS):** wrapped DEK in the ERP database; erasure deletes it; complete when the last backup holding it
  expires (deployment's backup retention, stated in its records of processing).
- **Not covered by the DEK (both tiers):** address ↔ party mappings (wallet approvals, payment requests) and ERP
  master data. They are deleted from the live database at once and leave backups at backup expiry (R197).
- **Multi-subject records (review L8):** the record's salt and payload are encrypted under a record key wrapped by
  each subject's DEK. Erasing one subject is refused (`legal_basis = other_subject`) while another subject's basis or
  retention needs the record; otherwise the whole record is erased. Where per-subject erasure matters, commit one
  record per subject.
- **Odoo example (`dms_blockchain`, not built):** model `blockchain.shred.key` (`subject_ref = HMAC(subject_key,
  res.partner id)`, `wrapped_dek`, `state`), model `blockchain.shred.record` (`model`, `res_id`, `key_ids`,
  `ciphertext` of `(salt, payload)`, `retain_until`, `legal_basis`); both without ACL rows for non-system groups and
  with `SERVER_ONLY` fields (NI R101); access only through server methods (`_shred_commit(record, payload)`,
  `_shred_open(record)`); KEK, `log_key` and `subject_key` from the environment or a secret file, **never**
  `ir.config_parameter` (it lives in the database and its backups). Salts never appear in outbox payloads, logs, or
  the node.
- **Never:** salts in the node store, on chain, in logs, in analytics exports (SCaaS §11.4), or derived from the
  payload or from a business id.

### C.4 Erasure and retention procedure

```
erase_subject(party_id, reason) -> {ticket, erased: […], refused: [{model, id, legal_basis, retain_until}]}
  requires role compliance_officer (client side)
  1. ticket = random 16 bytes; append {ticket, HMAC(log_key, party_id), reason_code, at} to the erasure log
     (separate append-only store outside the ERP database, retention ≥ the longest backup age)
  2. for each record of the subject:
       retain_until > now ⇒ refuse (legal basis returned), schedule erasure at retain_until
       else              ⇒ delete its shred record (encrypted salt + payload) and any plaintext copy
  3. delete the off-chain mapping (approved wallet records ↔ party) unless refused in 2
  4. no record left under retention ⇒ destroy the subject's DEK (Tier A) / delete it (Tier B)
  5. append the ticket's tombstones (rev 1.3, Codex L1), in the transaction's commit order:
       {ticket, deleted: [{model, item, fields?}]         -- shred records, mapping rows, plaintext fields deleted
        refused: [{model, item, legal_basis, retain_until}], dek: destroyed | deleted | kept, scheduled_at?}
     item = HMAC(log_key, model ‖ id), never the id itself (the log must not link a ticket to a record id);
     model and field names only, never values
  6. nothing to send to the node or chain (R195); node payloads age out within job_retention_secs (30 d)
  scheduled erasures at retain_until run steps 2–5 for that record and append their own tombstones to the ticket
restore(backup):
  before reopening, for every ticket newer than the backup (both tiers): (a) apply its tombstones exactly — find each
  item by recomputing HMAC(log_key, model ‖ id) over the restored rows of that model, delete the listed rows and
  fields, restore the refusal schedule; (b) then re-run steps 2–4 with the restored retention data, so
  a record that became erasable since is erased and one deleted live never comes back with an old retain_until
```

Retention conflicts (accounting, anti-money-laundering, contract duties) refuse until `retain_until`; surplus
personal data is still deleted; on-chain pseudonyms are handled by deleting the mapping (SCaaS §11.2).

### C.5 What remains on chain, and what an auditor can still verify

After shredding: commitments and roots (random-looking 32-byte values), addresses and transparent amounts of value
transfers, `entryRef`s, revealed tender prices, Zether ciphertexts, any `AmountAttested` event already written,
block times.

| Auditor question | Still verifiable after shredding of record X? |
|---|---|
| Retained record Y existed at time T | yes: `(salt_Y, payload_Y)` opens Y's commitment; Merkle path from leaf to the anchored root |
| Integrity of the remaining batch | yes: leaves are hashes of commitments, not personal data; the client keeps the leaf list after shredding X |
| What X contained / who X was about | no (by design) |
| Payment N from address A to B with `entryRef` E | yes from chain data; who A or B is: only while the mapping is retained |
| Zether amount of transfer E | yes with an opening (`ITransferDisclosure`: `SENDER_S`, `RECEIVER_X`, `AUDITOR`) via `verifyTransferAmount` (view, leaves no trace); identity only while the mapping is retained |
| Tender procedure fairness | yes: all events and reveals are public; `documentRef` opens only while its salt is retained |

Disclosure flow: the client hands the auditor `(salt, payload)` for the specific record, never the DEK; for Zether
the opening of SCaaS §8.9. The independent verifier CLI (SCaaS §11.3, PLANNED) gains `verify-commitment` and
`verify-merkle`.

### C.6 `entryRef`, `payId` and other references (R198)

- `entryRef`/`payId`: 32 random bytes per payment request (R9); never a hash of invoice numbers or parties; no salt
  needed; erasure = delete the request ↔ party link.
- `depositRef` (R180) is derived from `(chainId, tender, tenderId, commitment)`: public data only.
- `documentRef`, `reasonRef`: salted commitments (§C.2), so the documents and reasons they name are shreddable.
- `origin.key` and `client_ref` sent to the node (NI R91): opaque (`entryRef`, record ids), never names.

### C.7 Tests and checks (CS streams)

KATs for every format of §C.2 (Python, TypeScript, Solidity view helper) in `tests/kat/commitments.json`; JCS
edge cases (Unicode, numbers); erasure procedure: retained vs erasable records, multi-subject refusal, DEK
destruction makes a Tier A backup's salts and payloads unreadable, log contains no derivable id and no values,
restoring an old database backup then replaying the external log re-erases — including a partial erasure (surplus
plaintext deleted around a retained record) where the backup holds an older `retain_until`/`legal_basis` (Codex L1); CI calldata-type guard of SCaaS §11.1 (allow `address`, `bool`, `uint*`,
`int*`, `bytes32`, `bytes32[]`; deny `string`/`bytes` except declared proof/signature/meta-tx fields) applied to the
tender, `mtxPayReceiverFee` and the pool.

### C.8 Families

Chain-agnostic (32-byte commitments; transport is the anchoring stream). keccak256 on EVM/Hedera; SHA-256-native
families use the same structure with SHA-256 and tag `scaas.commit.sha256.v1`.

---

## 8. Streams

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| TB1 | Tender EVM | `SealedBidTender` + tests (§A.9), KAT, gas snapshot | TW2 T1–T6 (built) | **SPECIFIED** |
| TB2 | Tender Hedera | same bytecode on HSCS, e2e incl. a 64-byte ED25519 deposit intent | TB1 | **SPECIFIED** |
| TB3 | Tender node + ERP | `chain_contract`, indexer events, admin contracts route, Odoo `blockchain.tender*`, portal bidder flow | TB1, NI P2–P5 | **SPECIFIED** |
| TB4 | Tender other families | §A.10 designs | TB1, family contracts | PLANNED |
| SP1 | Sponsorship policy | tables, accept/lease/mined hooks, feed cost fields, admin routes, metrics, tests (§B1.7) | NI P3 (submit from store), P2b (admin routes) | **SPECIFIED** |
| SP2 | Sponsorship booking (Odoo) | cost fields → gas expense per business document and sponsor account | SP1, NI P5 | **SPECIFIED** |
| RP1 | Receiver-pays contract | `mtxPayReceiverFee`, `_execute` returns digest, new implementation version per tier (EVM + Hedera children), tests, gas | TW2 (built), before O3 production registration | **SPECIFIED** |
| RP2 | Receiver-pays node + Odoo | `receiver_fee` job field, `token.features`, indexer event, payee co-sign service, booking | RP1, NI P3–P5; `SigningPolicyService` for production keys | **SPECIFIED** |
| PL1 | SponsorshipPool | design to §B3 constraints, Hedera formula, node `call` routing | SP1, TB3 (`chain_contract`) | **PLANNED-later** |
| CS1 | Shredding client | commitment library (Python/TS) + KATs, Odoo `blockchain.shred.*`, erasure API, external log, restore replay | — | **SPECIFIED** |
| CS2 | Calldata guard | CI guard of §C.7 | — | **SPECIFIED** |
| CS3 | Verifier CLI | `verify-commitment`, `verify-merkle` + Zether openings (SCaaS §11.3) | CS1 | PLANNED |

Order: RP1 first (no production v2 registration yet), TB1 ∥ CS1/CS2, SP1 after NI P3, then TB3/RP2/SP2, PL1 last.

## 9. Open questions and follow-ups

No owner question is open. Decided: post-reveal disqualification (owner, rev 1.1: R185, §A.2.2, §A.7.2);
receiver-pays v2-only, no v1 router (owner, rev 1.1: R193); `replaceBid` deferred (R182) and the HOLD bond kept
(R187) on review merit (rev 1.2). Follow-up outside these streams: a scoped SubjectAccount key kind that validates
only `ReceiverFee` preimages with a fee cap (SubjectAccount v2), so a payee's co-sign key need not control its wallet.

## 10. Review 1 disposition (rev 1.2)

All findings applied, none found wrong; H4 partly as allowed (payloads under the DEK, mappings not; claim restated, R197).

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Buyer controls gasless bidders' commit/reveal path and keeps forfeits | Applied: independent path required before signing, verify-and-fallback, R183 rationale corrected, abuse row | R183, §A.5.2–A.5.3, §A.7.1 |
| H2 | R100 rewrites payer `feeRecipient` ⇒ shape check reverts | Applied: check removed, test added | R193, §B2.2, §B2.5–B2.6 |
| H3 | Co-sign key is a full-control `SubjectAccount` key | Applied: hot collection wallet + sweep; scoped key kind as follow-up | R193, §B2.4–B2.5, §9 |
| H4 | DEK covered salts only; backup claim false | Applied (a) for salts + anchored payloads; mappings and master data stated as backup-expiry | R197, §C.3–C.4 |
| M1 | `bidderList`/scan/`MAX_BIDS` + sybil fill DoS | Applied as O1: top-k (≤ 3) tracking | R185, §A.2–A.4, §A.8 |
| M2 | Unverified jobs consume caps; unsigned payer key; no `call` dedupe | Applied: local signature check on public doors, counts at lease, `job_live_call`, payer of `call` jobs, public-door policy rule | R190, §B1.2–B1.7 |
| M3 | Reservation drift, day rollover, gas-limit/bump overshoot, MySQL lost update | Applied: `sponsor_reserved`/`sponsor_day`, max chargeable fee ≤ reservation, bump cap, row locks, tests | R190, §B1.2–B1.3, §B1.7 |
| M4 | `feeRecipient = 0 ⇒ msg.sender` allows front-run fee theft | Applied: `feeRecipient ≠ 0`, payer relayer binding required | R193, §B2.1–B2.5 |
| M5 | Chain/ordering neutrality assumed | Applied: known limit, ERP chain check, tie-break caveat | R184, §A.5.1, §A.7 |
| M6 | Erasure log location and keys unspecified | Applied: external append-only log, `log_key`/`subject_key` with the KEK | R197, §C.3–C.4 |
| L1 | I3/I6 wording, numbering | Applied | §A.2.4 |
| L2 | Discretion understated (abort via disqualification, bond claim) | Applied: last candidate cannot be disqualified; up to three deposits stated | R185, §A.7.2 |
| L3 | Factory v2 `META` kind; enum types differ | Applied | R186, §A.9 |
| L4 | Bytecode size of `mtxPayReceiverFee` | Applied: CI gate on every tier, library fallback | §B2.5 |
| L5 | ERC-1271 bidder gas | Applied: gas row + sizing note | §A.5.3, §A.8 |
| L6 | R139 not held by generic `m` | Applied: `payLane(entryRef)`, nonce 0 required | R193, §B2.2 |
| L7 | Merkle formats differ | Applied: anchoring verifier stated custom | R196, §C.2 |
| L8 | Multi-subject records | Applied: record key wrapped per subject, refusal rule | §C.3 |
| L9 | Missing tests | Applied | §A.9, §B1.7, §B2.6, §C.7 |
| O1 | Top-k instead of scan | Accepted | as M1 |
| O2 | Defer `replaceBid` | **Accepted on merit**: it was the only signature check (domain, nonce, KAT, Hedera child) for a small benefit | R182, R188 |
| O3 | Trim the Pool | Accepted; block-producer caveat added | R194, §B3 |
| O4 | Defer field-level salts | Accepted | R196, §C.2, §C.5 |
| O5 | Separate the HOLD bond | **Rejected on merit**: a standard procurement instrument; separating it needs a second winner deposit and a missing escrow; its discretion is declared at creation and stated | R187, §A.7.2 |

## 11. Codex review disposition (rev 1.3)

Review `docs/reviews/specs/2026-10-06-tender-sponsorship-codex-review-1.md`, verdict FIX-THEN-GO, 0 critical, 2 high,
2 medium, 1 low. Each finding checked against this spec, NI rev 3.5 and the code it cites. Owner rulings unchanged
(commit–reveal + deposit, buyer disqualification with reason and evidence inside the window, node-level sponsorship
first and the pool later, receiver-pays v2-only, client-held salts). 3 applied as proposed, 2 applied with a variant
where part of the finding did not hold; none rejected outright.

| # | Finding | Verified | Disposition | Where |
|---|---|---|---|---|
| H1 | `on_exhausted = unsponsored` bypasses the budget on client namespaces | **partly**: the sponsor account's budget is never exceeded, and an unmatched client job is already booked to the namespace (NI `usage_day`, `sponsor_policy = ''`), so nothing escapes accounting; true that the policy was presented as a tenant cost control it cannot be with `unsponsored`, and that the fallback was unmarked | **Applied with variant**: `unsponsored` on a client namespace = booked to the namespace, marked `sponsor_fallback`, allowed only with an explicit audited `fallback_to_namespace`; tenant caps need `reject`; test added. No namespace gas-budget column (that would be NI; noted as the if-wrong path) | R189, §B1.3–B1.7 |
| H2 | Rate caps at lease let one payer reserve the whole day budget | yes: admission reserved without counting, counts at lease, pre-broadcast ends released only the reservation | **Applied**: hour/payer-hour/day counts taken at accept with the reservation (`sponsor_hour` on the job), released on a pre-broadcast end; `min_valid_secs` (default 120) for sponsored jobs; `SPONSOR_RATE` moves from lease `dead` to accept `429`. Review-1 M2's concern stays met by the public-door signature check and the release | R190, §B1.1–B1.3, §B1.6–B1.7, Amends NI |
| M1 | `job_live_call` turns tender calls into a liveness lock | **partly**: since NI rev 3.5 (R325) dedupe is per namespace, so a portal's or operator's copy never blocks the bidder's independent path; within one namespace the duplicate is the tenant's own job | **Applied with variant**: index and text per namespace; `409 DUPLICATE_CALL` returns the live `uid` to follow or cancel; bidder step 4 requires the independent path to be another namespace. "Dedupe only signed calls" rejected: two queued copies in one namespace would both broadcast and the loser's revert would be booked | §A.5.2, §A.6, §B1.2–B1.3, §B1.7 |
| M2 | Transient guard assumes EIP-1153; Hedera "same bytecode" | **partly**: correct that the spec did not say so, but every eligible deposit token already needs it (`MetaTxCore.sol:38-44` for v2 and the Hedera children, `ERC20MetaTx.sol:35-41` for v1), so the tender adds no new chain requirement | **Applied**: EIP-1153 stated as a prerequisite for TB1/TB2/PL1, deploy-time `TSTORE` probe. Storage-guard fallback rejected: no chain that passes R186 lacks EIP-1153 | R188, §A.4, §A.9, §A.10, §B3 |
| L1 | Erasure log replay cannot reproduce partial erasure | yes: the log held only ticket + subject HMAC | **Applied**: itemized tombstones (deleted rows/fields, refusals with `retain_until`, DEK state, schedule), items keyed by `HMAC(log_key, model ‖ id)` so the log links no ticket to a record id; replay tombstones first, then current retention; test added | R197, §C.4, §C.7 |

Consistency fixes found while verifying (not in the review): `~gateway` `call` policies were impossible under §B1.5
(`call` ⇒ `min_value = 0` and no `receiver`) although NI R320 and UA S6 rely on TSS budgets for sponsored UA
registration — one allowed shape added (§B1.5, NI §7.3 to follow); NI reference moved from rev 3.3 to rev 3.5.
