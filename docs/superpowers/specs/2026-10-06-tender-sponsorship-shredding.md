# Sealed-bid tender, gas sponsorship and receiver-pays, crypto-shredding (component spec B)

Status: draft rev 1.1, 2026-10-06. Rev 1.1 folds in the owner's answers to the two rev-1 open questions
(post-reveal disqualification, R185; receiver-pays stays v2-only, R193). Code at `scaas` `main` 97ba59e.
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
| NI | `2026-10-06-node-independence-design.md` rev 3.3 | additions only: tables `sponsor_policy`, `sponsor_usage`, `chain_contract`; job columns `sponsor_policy_id`, `gas_used`, `gas_price`, `cost_native`; admin routes §B1.5; job payload field `receiver_fee` (§B2.5) |
| TW2 | `2026-10-06-token-wrappers-v2.md` | one named function added to `MetaTokenBase` (`mtxPayReceiverFee`, R192), shipped as a new implementation version per tier; `_execute` returns the digest (no behaviour change) |
| MESH | `2026-10-05-relayer-mesh-design.md` | R75 **not amended**; its scope is clarified by R194 |

Sources (read for facts): SCaaS §2.2, §5.7–§5.9, §6, §10, §11, §14.7; INT §5, §8, §9; TW2 §3, §7 (R132, R138–R140);
NI §4, §5, §7 (R90–R92, R95, R102, R103, R107, R110); MESH R75, R84, R86, §7; payments design R2, R9, T18; research
`09-payment-modes.md`, `15-settlement-layer.md` §15.12.1; SRS architecture §4.9, §10 and integration §2.5–§2.6,
§3.5, §4.2; code `smartcontracts/evm/src/{common/MetaTxLib.sol, metatx/MetaTxCore.sol, metatx/MetaTokenBase.sol,
wallet/MandateWallet.sol, zether/ITransferDisclosure.sol, factory/OpenFactoryV2.sol, common/SigLib.sol,
hedera/HederaAccountAuth.sol}`.

Market-neutral: no country's law is cited. "GDPR-class regime" means any data-protection regime with lawful basis,
minimization, erasure, retention and processor duties.

---

## 1. Scope and non-goals

### 1.1 In scope

| Part | What |
|---|---|
| A | `SealedBidTender` contract (EVM, Hedera child), bidder and buyer flows, node/ERP/app touchpoints |
| B1 | Node sponsorship policy: matching, fee-floor waiver, budgets, rate caps, accounting, metrics, admin API |
| B2 | Receiver-pays: payee co-signature, new named function `mtxPayReceiverFee` on v2 tokens, node job field |
| B3 | `SponsorshipPool` contract: **specified now, stream PLANNED-later** |
| C | Crypto-shredding: commitment formats, salt and key handling on the client, erasure and retention procedure, audit |

### 1.2 Non-goals

- Multi-criteria tender scoring (price + quality), multi-lot tenders, Dutch/English/Vickrey auctions. Technical
  pre-qualification happens before the tender and is expressed as the eligibility allowlist.
- Confidential bids (encrypted prices, Zether deposits) and anonymous bidders. Identity is public at commit (address)
  and price at reveal; a bidder may use a fresh `SubjectAccount` per tender (SCaaS §10.6).
- A fee market or any in-protocol mesh reward (R75 stays).
- Receiver-pays on v1 tokens, on non-EVM families (no fee fields, R3D §D.0) and on Zether tokens (hidden amounts).
- Fiat valuation inside the node: thresholds are token base units (R189).
- Hiding the transaction graph of addresses (SCaaS §1.3: not a mixer). Shredding removes the link to a person, not
  the link between addresses.
- Anchoring contracts and Merkle batch scheduling (SCaaS §2.2, HANDOFF GA 2.2 #11): this spec fixes only the
  commitment and leaf formats they must use.

---

## 2. Rulings

Format: **ruling — why — cost if wrong.**

### 2.1 Sealed-bid tender

- **R180** **Deposit and commitment are one signature: the deposit token's own `pay` meta-tx.** The bidder signs a
  standard `MetaTransaction` (unchanged typehash, v1 or v2 token) with `to = tender`, `value = minDeposit`,
  `data = pay(depositRef)`, fee mode `NONE`, `MODE_RESTRICT_RELAYER` with `relayer = tender`, where
  `depositRef = keccak256(abi.encode(DEPOSIT_TAG, block.chainid, tender, tenderId, commitment))`. Anyone submits
  `commitBid(tenderId, commitment, proof, m, sig)`; the tender recomputes `depositRef`, checks the intent's shape,
  calls `token.executeMetaTransaction(m, sig)` and records the bid. — The payId binds the deposit to exactly this
  commitment, so no second (tender-level) signature, no allowance (R26 untouched, as `MandateWallet`), and the
  relayer binding means nobody can land the deposit outside `commitBid` (which would strand funds). Bidders' ERPs
  reconcile the deposit like any payment (`PaymentSettled.entryRef = depositRef`). — If wrong: wallets show "pay
  1000 to <tender>" rather than "bid"; the price could not be displayed anyway.
- **R181** **Commitment** `= keccak256(abi.encode(BID_TAG, block.chainid, address(this), tenderId, bidder, price,
  salt))`, `BID_TAG = keccak256("scaas.tender.bid.v1")`, `DEPOSIT_TAG = keccak256("scaas.tender.deposit.v1")`,
  `price` `uint128` in base units of the price unit named in the tender documents, `salt` 32 bytes from a CSPRNG or
  derived per §A.5.4. `abi.encode`, never `encodePacked` (research §15.12.1 used packed encoding). — Binding chain,
  contract, tender and bidder stops copying a commitment into another tender or onto another chain (SCaaS I3). —
  If wrong: a format change is a new `BID_TAG`.
- **R182** **Reveal and withdraw are permissionless; replacement is signed.** `revealBid(tenderId, bidder, price,
  salt)` and `withdrawDeposit(tenderId, bidder)` take no signature: the commitment binds the bidder, and payouts go
  only to the destination the rules fix (§A.2.3). Replacing a commitment before `commitDeadline` needs the bidder's
  EIP-712 `ReplaceBid` signature in the tender's domain, with a per-bid `replaceNonce`. — Every bidder action is
  gasless with at most one signature, any node or keeper can run reveals and refunds, and a bidder can hand
  `(price, salt)` to an agent after the deadline. Amends SCaaS §10.3 (bidder-signed reveal/withdraw). — If wrong:
  none found; a third party that learns `(price, salt)` can only do what the bidder committed to.
- **R183** **Forfeited deposits go to `slashSink`**, fixed at creation, immutable, `≠ 0`, `≠ tender`, and never equal
  to a bidder (checked at commit). ERP default: the buyer organization's tender-security account (a treasury address
  distinct from the address that creates tenders). Not burned, not redistributed. — The party harmed by a
  non-reveal (distorted or failed tender, re-run cost) is the buyer; the deterrent is the bidder's loss and is the
  same wherever the money goes, so burning only destroys value; redistribution to honest bidders breaks I1 (refunds
  of exactly `minDeposit`) and rewards hoping for others' failure. Forfeits to the buyer organization do not change
  the buyer's incentives: in a first-price sealed bid a buyer's own sybil bids cannot move another bidder's price
  (§A.7.2). — If wrong: a deployment sets `slashSink` to a charity or burn address; the contract accepts any
  non-bidder address.
- **R184** **Public reserve only.** `[minPrice, maxPrice]` (inclusive, `maxPrice = 0` ⇒ no upper bound) is the
  reserve, published in the config. A reveal outside it is recorded as **invalid** and forfeits like a non-reveal.
  No sealed reserve in v1. — A sealed reserve gives the buyer a price-informed abort (not revealing it after seeing
  bids); forfeiting out-of-range reveals closes the "reveal garbage to exit" escape. — If wrong: a later version adds
  a buyer-bonded sealed reserve.
  **Tie-break = earliest commit sequence** (`seq`, a per-tender counter assigned at commit; a replacement
  takes a new `seq`). `seq` is unique, so no second key is needed. — Deterministic, not manipulable after the fact
  (salt-derived randomness can be biased by the last revealer at the cost of a deposit). — If wrong: rewards early
  commits, which honest bidders control.
- **R185** **Cancel until `commitDeadline` only**, by the buyer, with a `reasonRef` (salted commitment, §C.2); every
  deposit then refunds 100 %. After `commitDeadline` there is no cancel. `minBidders ≥ 1`: fewer valid reveals ⇒
  state `FAILED` (no winner), valid revealers refunded, non-revealers forfeit. — Before the deadline prices are
  hidden, so a cancel cannot be price-informed; the buyer may legitimately react to the commit count. Amends SCaaS
  §10.3 ("only before the first commitment"). — If wrong: bidders lose gas only (sponsored, §B1).
  **Award window and disqualification** (owner, rev 1.1). The leader (best valid bid: price by `rule`, then `seq`)
  is tracked during reveals. After `revealDeadline` an award window of `dqWindow` seconds opens (fixed at creation,
  `≤ 7 d`, ERP default 72 h, `0` = no disqualification). Inside it the buyer may `disqualifyWinner` **the current
  leader only**, with a non-zero `reasonRef` (salted commitment of the disqualification document, R198) and a
  violation class; the next valid, non-disqualified bid by the same ordering becomes leader. The disqualified
  deposit refunds in full, unless the class is one of the `forfeitClasses` the tender declared at creation (bitmask
  of up to 8 classes defined in the tender documents, e.g. "forged bid documents") — then it goes to `slashSink`.
  At most `maxDisqualifications ≤ 2` per tender. Every disqualification emits `BidDisqualified` (bidder, reason,
  class, forfeit, new leader). `minBidders` counts valid reveals **including** disqualified ones (it measures
  competition); no candidate left ⇒ `FAILED`. **Settlement:** the buyer may `settleTender` any time after
  `revealDeadline` (it closes the window); anyone may after `revealDeadline + dqWindow`; `withdrawDeposit` settles
  lazily. No `awardDeadline`. — Procurement must be able to pass over a winner that fails due diligence; the
  leader-only rule, the short window, the public reason and the cap bound the buyer's discretion to the top
  `maxDisqualifications + 1` valid bids (§A.7.2). Removes SCaaS §10.5 row "buyer never settles". — If wrong: a
  tender that wants no discretion sets `dqWindow = 0` (settlement then permissionless right after the reveals).
- **R186** **Deposit token** = a token deployed by the configured factory v1 (`META`) or factory v2 (`META_NONE`,
  `META_SINGLE`, `META_MULTI`) through a **registered, non-deprecated** implementation (unregistered clones and Zether
  kinds refused), checked at `createTender`. The tender also checks the balance delta equals `minDeposit`. — Bidders
  sign an intent on this token; an attacker-chosen "token" could fake `executeMetaTransaction`. — If wrong: other
  tokens wrap first (MetaTxLib header).
- **R187** **Windows and bonds.** `revealDeadline − commitDeadline ∈ [1 h, 30 d]` (ERP default 24 h);
  `commitDeadline ≤ createdAt + 365 d`; bond policies `RETURN_ON_AWARD` | `HOLD_UNTIL_RELEASE` kept (SCaaS §10.2):
  under HOLD the winner's deposit is the bond, released by the buyer or by anyone after `bondReleaseTime`
  (`≤ revealDeadline + 730 d`), or claimed by the buyer to `slashSink` before then with a `reasonRef`. — Caps stop a
  config from locking deposits indefinitely; bidders see every value before they commit. — If wrong: constants
  change only with a new deployment.
  **No admin.** One immutable contract per chain, no owner, pause, upgrade or sweep; stray tokens sent
  directly are unrecoverable. `bidder ≠ buyer`. — Every refund path must hold without anyone's consent (I1). — If
  wrong: a stuck-funds bug needs a redeploy; deposits of open tenders remain claimable on the old one.
- **R188** **Families: EVM and Hedera first** (same Solidity; Hedera child verifies `ReplaceBid` through HIP-632,
  `HederaAccountAuth`). Cosmos, Soroban, Sui, Aptos, TON, Solana are PLANNED with the native designs of §A.10.

### 2.2 Gas sponsorship (node)

- **R189** **A sponsorship policy is a node store row that matches jobs and (a) waives the fee floor of the door the
  job came through, (b) books its gas to a sponsor account, (c) enforces that account's budget and rate caps.** It
  never changes a signed field and never adds a fee. Matching uses only job data (no RPC at accept, NI §5.2).
  Doors: client namespaces (no fee floor today: the policy books and limits), `~gateway` and `~mesh` (the MESH §7
  `min_fee` floor is waived for matching jobs). — Owner: node-level sponsorship first; one mechanism serves inbound
  subsidies ("to wallet W, value ≥ X ⇒ fee 0, gas to account Y", SCaaS §6) and tenant cost control. — If wrong:
  policies are data; nothing on chain depends on them.
  **Value thresholds are token base units per (chain, token).** Conversion from a reporting currency is the
  client's business (it pushes new rows when its rates change). — The node holds no prices and no oracle. — If
  wrong: a stale threshold sponsors slightly more or less.
- **R190** **Budget unit = the family's smallest native unit** (wei, tinybar, lamports, uatom-equivalent, MIST,
  octa, nanoton, stroops), measured from receipts (`gas_used × effective price`, or the family's fee field). Budget
  per UTC day; rate caps per hour per policy and per payer. Admission reserves `max_cost_per_tx` per live sponsored
  job; the reservation is replaced by the measured cost at `mined`/`reverted`. `on_exhausted ∈ {reject,
  unsponsored}`. — Arithmetic at accept, measurement at the end; no oracle. — If wrong: one day's budget overshoots
  by at most the reserved headroom.
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
- **R193** **Shape:** payer op is `pay(entryRef)` (36 bytes) with fee mode `NONE` (one fee per intent); `fee` is an
  absolute amount, `0 < fee ≤ m.value`; resolved recipient (`0` ⇒ `msg.sender`) `≠ m.to` (R132). No 1 % cap: the
  payee signs the exact amount it gives up, and the payee can never lose more than it receives in this call. Events:
  `PaymentSettled(…, N, entryRef)` unchanged (gross), plus `ReceiverFeePaid(paymentDigest, payee, feeRecipient,
  fee)`. — The payer's books do not change; the payee books receipt N and expense F (SRS integration §2.5: net
  N − F).
  **Availability:** v2 tokens of the next implementation version of each tier (EVM and Hedera children);
  older v2 clones and v1 lack it (clones are immutable). Not in `mtxBatch`. Node jobs carrying `receiver_fee` are
  `bus.scope = restricted` (the mesh envelope has no slot for the co-signature). — Smallest change that is atomic
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
  under an in-flight relayer. — If wrong: token-denominated rewards are a second mode later.

### 2.5 Crypto-shredding

- **R195** **The client holds every salt and key; the chain holds only commitments; the node holds neither salts nor
  personal data.** Node payloads are addresses, amounts, digests, commitments (retained ≤ `job_retention_secs`,
  SCaaS §11.1). — Owner. The erasure duty then lands entirely in the system of record, where it can be met.
- **R196** **Commitment formats** (§C.2): record `keccak256(abi.encode(REC_TAG, salt, payloadHash))` with
  `payloadHash = SHA-256(JCS(payload))`; Merkle leaf `keccak256(0x00 ‖ commitment)`, node `keccak256(0x01 ‖ min ‖
  max)`; field-level salts `HMAC-SHA256(recordSalt, "scaas.field.v1" ‖ 0x00 ‖ fieldName)`. — Domain tags and the
  leaf/node prefix stop cross-format and second-preimage confusion; JCS reuses NI R91's canonical form. Supersedes
  the `keccak256(salt ‖ canonical(payload))` sketch of SCaaS §11.2 (same idea, fixed encoding).
- **R197** **Salts at rest are encrypted under a per-subject data key (DEK); erasure = destroy the DEK.** Tier A: DEK
  in a KMS/secret store with key destruction (immediate, also for backups, which hold only ciphertext). Tier B
  (no KMS): DEK row in the ERP database, KEK outside the database; erasure is effective when the last backup holding
  the DEK expires, and every restore replays the erasure log before reopening. The erasure log holds a random ticket
  id and `HMAC(log_key, subject_id)`, never a plain hash of a (guessable) subject id. — Deleting salt rows alone
  leaves them in every backup; hashing a sequential partner id is reversible. Refines SCaaS §11.2.
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
                │ commitBid / replaceBid   │ revealBid                    │ disqualifyWinner   │ withdrawDeposit
                │                                                         │ (buyer, ≤ dqWindow) │ releaseBond / claimBond
                └ cancelTender (buyer, now ≤ commitDeadline) ─► CANCELLED ─ withdrawDeposit
```

Stored states: `OPEN`, `SETTLED`, `FAILED`, `CANCELLED`; `REVEAL` and `AWARDABLE` (the award window
`(revealDeadline, revealDeadline + dqWindow]`, then until someone settles) are derived from `block.timestamp`.

### A.2 Rules

#### A.2.1 Commit (`now ≤ commitDeadline`)

1. Tender exists and stored state `OPEN`; `bidder = m.from`; `bidder ∉ {buyer, slashSink}`; eligibility proof
   valid when `eligibilityRoot ≠ 0` (OpenZeppelin `MerkleProof`, leaf `keccak256(bytes.concat(keccak256(abi.encode(
   bidder))))`); bidder has no bid; `bidderList.length < MAX_BIDS` (256) else `TooManyBids`.
2. Intent shape (`BadDepositIntent(code)`): `m.to == address(this)`, `m.value == minDeposit`,
   `m.data == abi.encodePacked(bytes4(keccak256("pay(bytes32)")), depositRef(tenderId, commitment))`,
   `feeModeOf(m.mode) == NONE`, `m.mode & MODE_RESTRICT_RELAYER != 0`, `m.relayer == address(this)`.
3. Effects: bid `{commitment, seq = nextSeq++, status = COMMITTED}`, `commits++`, `bidderList.push(bidder)`.
4. Interaction: `b0 = balanceOf(this)`; `IERC20MetaTx(token).executeMetaTransaction(m, sig)` (reverts propagate);
   `balanceOf(this) − b0 == minDeposit` else `DepositNotReceived`.
5. Emit `BidCommitted(tenderId, bidder, commitment, seq)`.

The batch/nonce of `m` is the bidder's choice; clients SHOULD use `payLane(depositRef)`, nonce 0 (R9 convention).

#### A.2.2 Replace, reveal, disqualify, settle

- `replaceBid(tenderId, bidder, newCommitment, validUntil, sig)`: `now ≤ commitDeadline`, `now ≤ validUntil`, bid
  `COMMITTED`; sig over `ReplaceBid(uint256 tenderId,address bidder,bytes32 newCommitment,uint32 replaceNonce,uint256
  validUntil)` in domain `("SCaaS SealedBidTender", "1", chainId, tender)` (EOA or ERC-1271 via `SigLib`;
  HIP-632 on Hedera); sets commitment, `replaceNonce++`, `seq = nextSeq++`; emits `BidReplaced`. The deposit is
  untouched (its `depositRef` keeps naming the first commitment; it is only a payment reference).
- `revealBid(tenderId, bidder, price, salt)`: `commitDeadline < now ≤ revealDeadline`, bid `COMMITTED`, recomputed
  commitment equals the stored one else `CommitmentMismatch`. `valid = minPrice ≤ price ∧ (maxPrice == 0 ∨ price ≤
  maxPrice)`. Stores `price`, status `REVEALED`, `valid`; if valid: `validReveals++` and compare with the best
  (`LOWEST_PRICE`: lower wins; `HIGHEST_PRICE`: higher wins; equal ⇒ lower `seq`). Emits `BidRevealed(tenderId,
  bidder, price, valid)`.
- `disqualifyWinner(tenderId, reasonRef, violationClass)`: buyer only; state `OPEN`; `revealDeadline < now ≤
  revealDeadline + dqWindow` else `DisqualifyClosed`; `dqCount < maxDisqualifications` else `DisqualifyCapReached`;
  a leader exists else `NoBid`; `reasonRef ≠ 0`; `violationClass == 0` (no violation) or `1 ≤ violationClass ≤ 8`
  with bit `violationClass − 1` set in `forfeitClasses`, else `ViolationClassNotDeclared`. Effects: leader's bid
  status `DISQUALIFIED`, `forfeit = (violationClass ≠ 0)`, `dqCount++`; new leader = best bid over `bidderList`
  with status `REVEALED ∧ valid` (same ordering as reveals: price by `rule`, then lower `seq`), or none. Emits
  `BidDisqualified(tenderId, bidder, reasonRef, violationClass, forfeit, newLeader)`. The scan is O(bids ≤ 256).
- `settleTender(tenderId)`: state `OPEN`; caller is the buyer and `now > revealDeadline`, or anyone and `now >
  revealDeadline + dqWindow`. `validReveals ≥ minBidders ∧ leader exists` ⇒ `SETTLED` with `winner = leader`,
  else `FAILED`; emits `TenderSettled(tenderId, winner, price, validReveals, commits)` (`winner = 0` when `FAILED`;
  `validReveals` includes disqualified bids). Idempotence: a second call reverts `WrongPhase`.

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
- **I3** Before `revealDeadline` no price is derivable from chain data (salt secret and uniformly random).
- **I4** Winner = the best valid, non-disqualified bid by (rule, seq); the buyer's only influence is removing the
  current leader inside the award window, at most `maxDisqualifications` times, each with a public `reasonRef`.
- **I7** A deposit is forfeited only for non-reveal, invalid reveal, a declared violation class, or a HOLD bond
  claim — never by an undeclared reason.
- **I5** `settle` happens once; a bid pays out once (status `DONE`).
- **I6** No deposit enters the tender except through `commitBid` (relayer bound to the tender, R180).

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
    struct Bid { bytes32 commitment; uint128 price; uint64 seq; uint32 replaceNonce; BidStatus status; bool valid;
                 bool forfeit; }

    event TenderCreated(uint256 indexed tenderId, address indexed buyer, bytes32 documentRef, TenderConfig config);
    event TenderCancelled(uint256 indexed tenderId, bytes32 reasonRef);
    event BidCommitted(uint256 indexed tenderId, address indexed bidder, bytes32 commitment, uint64 seq);
    event BidReplaced(uint256 indexed tenderId, address indexed bidder, bytes32 commitment, uint64 seq);
    event BidRevealed(uint256 indexed tenderId, address indexed bidder, uint256 price, bool valid);
    event BidDisqualified(uint256 indexed tenderId, address indexed bidder, bytes32 reasonRef, uint8 violationClass,
                          bool forfeit, address newLeader);
    event TenderSettled(uint256 indexed tenderId, address indexed winner, uint256 price, uint32 validReveals,
                        uint32 commits);
    event DepositRefunded(uint256 indexed tenderId, address indexed bidder, uint256 amount);
    event DepositSlashed(uint256 indexed tenderId, address indexed bidder, address sink, uint256 amount);
    event BondReleased(uint256 indexed tenderId, address indexed winner, uint256 amount);
    event BondClaimed(uint256 indexed tenderId, bytes32 reasonRef, uint256 amount);

    error BadConfig(uint8 code);            // 1 token, 2 deposit, 3 windows, 4 bounds, 5 minBidders, 6 bond, 7 sink,
                                            // 8 disqualification params
    error WrongPhase(State state);
    error NotBuyer();
    error NotEligible(address bidder);
    error BidderExcluded(address bidder);   // buyer or slashSink
    error BidExists();
    error NoBid();
    error BadDepositIntent(uint8 code);     // 1 to, 2 value, 3 data, 4 fee mode, 5 relayer binding
    error DepositNotReceived(uint256 expected, uint256 got);
    error CommitmentMismatch();
    error TooManyBids();
    error DisqualifyClosed();
    error DisqualifyCapReached();
    error ViolationClassNotDeclared(uint8 violationClass);
    error BondHeld();
    error BondNotHeld();
    error SignatureExpired();
    error BadSignature();

    function createTender(TenderConfig calldata c) external returns (uint256 tenderId);
    function cancelTender(uint256 tenderId, bytes32 reasonRef) external;                  // buyer, R185
    function commitBid(uint256 tenderId, bytes32 commitment, bytes32[] calldata eligibilityProof,
                       MetaTxLib.MetaTransaction calldata m, bytes calldata depositSig) external;   // anyone, R180
    function replaceBid(uint256 tenderId, address bidder, bytes32 newCommitment, uint256 validUntil,
                        bytes calldata sig) external;                                     // anyone, bidder-signed
    function revealBid(uint256 tenderId, address bidder, uint128 price, bytes32 salt) external;   // anyone, R182
    function disqualifyWinner(uint256 tenderId, bytes32 reasonRef, uint8 violationClass) external;  // buyer, R185
    function settleTender(uint256 tenderId) external;                 // buyer after reveals; anyone after the window
    function withdrawDeposit(uint256 tenderId, address bidder) external;                  // anyone, §A.2.3
    function releaseBond(uint256 tenderId) external;
    function claimBond(uint256 tenderId, bytes32 reasonRef) external;                     // buyer, HOLD

    function commitmentOf(uint256 tenderId, address bidder, uint128 price, bytes32 salt) external view
        returns (bytes32);
    function depositRef(uint256 tenderId, bytes32 commitment) external view returns (bytes32);
    function replaceDigest(uint256 tenderId, address bidder, bytes32 newCommitment, uint256 validUntil)
        external view returns (bytes32);
    function state(uint256 tenderId) external view returns (State);
    function bidOf(uint256 tenderId, address bidder) external view returns (Bid memory);
    function configOf(uint256 tenderId) external view returns (TenderConfig memory, address buyer);
}
// constructor(address factoryV1, address factoryV2) — immutable (R186); either may be 0 on a chain without it.
```

Differences from SCaaS §14.7: deposit via the token's pay intent (R180), `commitBid` instead of
`submitBidCommitment`, reveal/withdraw take `bidder` and no signature (R182), no `awardDeadline` but a buyer
disqualification window (R185), `minBidders` and `FAILED` (R185), `replaceBid`, per-bid `withdrawDeposit` routing to
bidder or sink, `uint128` prices, at most 256 bids per tender.

### A.4 Storage

```
mapping(uint256 => Tender) tenders;     // Tender = TenderConfig (7 slots packed) + buyer, State, best (address),
                                        //          bestPrice uint128, bestSeq uint64, commits/validReveals uint32,
                                        //          nextSeq uint64, createdAt uint64, dqCount uint8   (≈ 11 slots)
mapping(uint256 => mapping(address => Bid)) bids;   // 2 slots: commitment | price, seq, replaceNonce, status, valid, forfeit
mapping(uint256 => address[]) bidderList;           // commit order; ≤ MAX_BIDS = 256 (disqualification scan)
uint256 nextTenderId;                   // starts at 1
// transient reentrancy guard keccak256("scaas.tender.reentrancy.v1") on every state-changing function
```

`createTender` checks (`BadConfig`): R186 token acceptance (`isDeployedHere`, `versionOf`, `implementationOf ≠ 0`,
`!isDeprecated`, kind in the META set); `minDeposit > 0`; `now < commitDeadline ≤ now + 365 d`; reveal window in
`[1 h, 30 d]`; `maxPrice == 0 ∨ minPrice ≤ maxPrice`; `minBidders ≥ 1`; HOLD ⇒ `revealDeadline < bondReleaseTime ≤
revealDeadline + 730 d`, RETURN ⇒ `bondReleaseTime == 0`; `slashSink ∉ {0, this}`; `dqWindow ≤ 7 d`,
`maxDisqualifications ≤ 2`, `dqWindow == 0 ⇒ maxDisqualifications == 0 ∧ forfeitClasses == 0`.

### A.5 Flows

#### A.5.1 Buyer (ERP)

| # | ERP | Chain |
|---|---|---|
| 1 | Tender record linked to the RFQ; documents canonicalized (JCS), `documentRef` = salted commitment (§C.2); deposit token, `minDeposit`, deadlines, reserve, `minBidders`, bond policy, `slashSink`, allowlist root, `dqWindow`, `maxDisqualifications`, `forfeitClasses` (each class defined in the documents) | — |
| 2 | `call` job: `createTender(config)` from the buyer account (namespace `allow_call`, R103) | `TenderCreated` (`tenderId` from the event) |
| 3 | Publishes tender id, deadlines, deposit terms, eligibility proofs to invited bidders; sponsorship policy for its tender contract (§B1) | — |
| 4 | Watches commits (count only); may cancel until `commitDeadline` | `BidCommitted`, `TenderCancelled` |
| 5 | Inside the award window: due diligence on the leader; if it fails, `disqualifyWinner(reasonRef, class)` with the reason document committed (§C.2) and retained for audit and dispute | `BidDisqualified` |
| 5b | Then `settleTender` (buyer early, or any keeper after the window) | `TenderSettled` |
| 6 | On the **finalized** `TenderSettled`: PO to the winner; non-revealers = committed set − revealed set; keeper jobs `withdrawDeposit` for every bid (refunds and forfeits) | `DepositRefunded`, `DepositSlashed` |
| 7 | Bond: `releaseBond` on contract signature/delivery, or `claimBond(reasonRef)` | `BondReleased`/`BondClaimed` |
| 8 | Supplier invoice paid with `mtxPay` and a **fresh random `entryRef`** (R9); the link tender ↔ PO ↔ invoice ↔ `entryRef` stays off chain | `PaymentSettled` |

The payment `entryRef` is never derived from `tenderId` (R198, INT §5.1).

#### A.5.2 Bidder (ERP, portal or app)

1. Generate `salt` (§A.5.4), compute `commitment = commitmentOf(…)` locally, store `(tenderId, price, salt)` in the
   bidder's secret store **before** signing.
2. Build and sign the deposit intent (R180): `to = tender`, `value = minDeposit`, `data = pay(depositRef)`,
   `batch = payLane(depositRef)`, `nonce = 0`, `mode = MODE_RESTRICT_RELAYER`, `relayer = tender`, `fee = 0`,
   `feeRecipient = 0`, `validUntil ≤ now + 3600`.
3. Submit `commitBid` as a `call` job: through its own node, or through the buyer's portal (the buyer's ERP pushes
   it in its namespace; the buyer learns only the commitment). Verify `BidCommitted` is final.
4. After `commitDeadline`: submit `revealBid` (no signature) through its own node, or hand `(price, salt)` to the
   buyer's portal **and** verify `BidRevealed` before `revealDeadline − margin`; if missing, submit it elsewhere
   (permissionless, any relayer or a direct transaction).
5. After settlement: refund arrives through any keeper's `withdrawDeposit`; the bidder's ERP books it from
   `DepositRefunded` (the outgoing deposit was booked from its own `PaymentSettled(entryRef = depositRef)`).

#### A.5.3 Gas

All bidder steps are relayed `call` jobs; bidders hold no native coin. The buyer typically sponsors its tender
contract's `commitBid`/`revealBid`/`withdrawDeposit`/`settleTender` selectors (§B1, policy `kind = call`).

#### A.5.4 Salt generation and backup (bidder)

A lost salt means a forfeited deposit. Either: (a) 32 CSPRNG bytes, encrypted backup with the bid record; or (b)
derived from a high-entropy secret the bidder already backs up: `salt = HKDF-SHA256(ikm = secret, info =
"scaas.tender.salt.v1" ‖ u256(chainId) ‖ tender ‖ u256(tenderId) ‖ u32(replaceNonce))`, where `secret` is a seed-vault
key or passkey PRF output (deterministic). Never an ECDSA/WebAuthn signature as entropy unless the signer is proven
deterministic (passkeys are not). The salt is never sent to anyone before `commitDeadline`.

### A.6 Node, Odoo, app touchpoints

| Where | Change |
|---|---|
| Node store | `chain_contract (chain_key, address, kind CHECK (kind IN ('tender', 'sponsorship_pool')), PRIMARY KEY (chain_key, address))`; admin `GET/POST/DELETE /v1/admin/chains/{key}/contracts` (viewer / admin / admin, audited) |
| Node indexer | indexes events of `chain_contract` rows like token events; `range` items carry them; a namespace receives them when the contract is in its token subset (`PUT /v1/tokens/{chain}` accepts registered contracts) |
| Node submit | `call` jobs to a registered tender: simulation as usual; no batching; `commitBid` jobs pass R86 because the inner token is registered |
| Odoo (`dms_blockchain*`, example) | model `blockchain.tender` (config, state, `tender_id`, `chain_id`, links to RFQ/PO), `blockchain.tender.bid` (own bids: commitment, encrypted `(price, salt)`, status) with `SERVER_ONLY` secret fields (NI R101); producers `blockchain.tender` / `blockchain.tender.bid` on outbox jobs; event handlers for the ten events; PO creation only from the finalized `TenderSettled` |
| App | bidder view: compute commitment and salt in the client (`clientkeys`), sign the deposit intent, reveal reminder at `commitDeadline` |

### A.7 Security analysis

#### A.7.1 Abuse table

| Threat | Defence |
|---|---|
| Copying a commitment to another tender/chain | R181 binds chain, contract, tender, bidder |
| Pairing someone's deposit with another commitment | `depositRef` inside the signed `pay` data (R180) |
| Landing the deposit outside `commitBid` (stranded funds) | relayer bound to the tender (I6) |
| Fake token implementing a no-op `executeMetaTransaction` | R186 provenance + balance delta |
| Fee taken from the deposit intent to the tender (`feeRecipient` unbound ⇒ `msg.sender` = tender) | fee mode `NONE` required |
| Last-revealer exit after seeing others | possible at the cost of `minDeposit` (forfeit); out-of-range reveal is also forfeit (R184) |
| Selective reveal by a multi-identity bidder (commit k prices, reveal the most profitable) | each unrevealed identity forfeits `minDeposit`; buyer sizes `minDeposit` ≥ expected surplus at risk and uses the allowlist to bound identities |
| Buyer reads prices early | impossible from chain data (I3); a portal that receives `(price, salt)` early is a client bug — the bidder never sends it before `commitDeadline` |
| Buyer's portal withholds a handed-over reveal | bidder verifies `BidRevealed`, re-submits elsewhere (R182) |
| Buyer aborts after seeing prices | no cancel after `commitDeadline` (R185); remaining abort = a buyer sybil winning (A.7.2) or refusing the PO off chain |
| Buyer never settles / withholds refunds | settle and withdraw are permissionless after the window (R185, R182) |
| Buyer cherry-picks the winner by disqualifying | leader only, inside `dqWindow`, cap `maxDisqualifications ≤ 2`, each with a public `reasonRef` and event; residual risk §A.7.2 |
| Buyer seizes deposits with false violation claims | only classes declared at creation forfeit; reason committed on chain and openable in a dispute; at most 2 deposits; residual risk §A.7.2 |
| Disqualification turns a tender `FAILED` | only by exhausting candidates (`minBidders` counts disqualified reveals) |
| Unbounded scan gas | `MAX_BIDS = 256` per tender |
| Deposits locked by extreme windows | R187 caps |
| Commit spam | each commit costs `minDeposit` (refunded only if revealed validly) + allowlist |
| Replacement replay (A→B→A flip) | `replaceNonce` in the signed struct |
| Reentrancy via token | registered META code + transient guard + CEI |
| Censorship near `commitDeadline` | public chain risk; bidders commit early; reveal window ≥ 1 h floor (24 h default) |
| Timestamp skew | seconds against windows of hours |

#### A.7.2 Known limits (stated to users)

- A buyer can commit and reveal through a sybil identity; if the sybil wins, the tender ends without a real award
  (the sybil's deposit is refunded as winner). This is equivalent to the buyer refusing to sign the PO, which no
  contract can prevent. The award on chain is evidence of a fair procedure, not an enforcement of the purchase.
- **Residual buyer discretion (disqualification).** Within the award window the buyer can pass over the best
  `maxDisqualifications` (≤ 2) valid bids, so in effect choose among the top three. With a declared violation class
  it also forfeits those deposits to `slashSink` — an incentive to allege violations when the sink is the buyer's
  own organization. The contract cannot judge whether a reason is true: it only makes every use public, bounded and
  bound to a committed document that the bidder can contest off chain. Tenders that want no discretion set
  `dqWindow = 0`; bidders that distrust the buyer can demand a neutral `slashSink` or `forfeitClasses = 0`.
- Bidder identities are public at commit (addresses), prices at reveal, forever (R198).

### A.8 Gas (estimates, to be measured in TB1)

| Call | Estimate | Notes |
|---|---|---|
| `createTender` | 230–260 k | ~10 new slots + event with config |
| `commitBid` | 145–175 k | token meta-tx with first-use lane (~52 k) + 2 bid slots (44 k) + `bidderList` push (~25 k) + checks, Merkle proof ~1.5 k/level |
| `replaceBid` | 15–25 k | 1 slot update + signature |
| `revealBid` | 20–35 k | keccak + 1 slot update + best update |
| `disqualifyWinner` | 30 k + ~2.6 k per bid | status write + scan of `bidderList` (cold reads); ≤ ~700 k at 256 bids |
| `settleTender` | 8–15 k | state write + event |
| `withdrawDeposit` | 30–45 k | status write + token transfer (cold recipient adds ~20 k) |

### A.9 Tests (TB1)

Unit: every `BadConfig` code; commit with each `BadDepositIntent` code; v1 and v2 tokens; unregistered and
deprecated token refused; Zether refused; eligibility proof valid/invalid; buyer and sink cannot bid; replace with
stale nonce and expired signature; ERC-1271 bidder (`SubjectAccount`); reveal mismatch, out-of-range reveal,
reveal outside the window; ties broken by `seq` (including after replacement); both rules; `minBidders` ⇒
`FAILED`; cancel before/after `commitDeadline`; every routing row of §A.2.3 and double withdraw; bond release by
buyer, by anyone after `bondReleaseTime`, claim before it. Disqualification: outside the window (before
`revealDeadline`, after `revealDeadline + dqWindow`), non-buyer, `dqWindow = 0`, cap reached, zero `reasonRef`,
undeclared class, class 0 ⇒ refund, declared class ⇒ forfeit; next leader correct for both rules, with ties
(lower `seq`), skipping invalid and disqualified bids; disqualifying the last candidate ⇒ `FAILED`; `minBidders`
counted with disqualified bids; settle by buyer inside the window closes it (later disqualify reverts); disqualified
bid withdrawable before settle; `TooManyBids` at 257; scan gas at 256 bids. Invariant fuzz (handler with random
bidders, prices, reveals, disqualifications, timing): I1, I2, I4, I5, I6, I7. Differential: `commitmentOf` vs the Python and TypeScript client builders
(KAT file `tests/kat/tender.json`). Hedera child: HIP-632 `ReplaceBid` for an ED25519 account. Gas snapshot.

### A.10 Families

| Family | Status | Design notes |
|---|---|---|
| EVM | **SPECIFIED** (TB1) | this section |
| Hedera | **SPECIFIED** (TB2) | same contract on HSCS; `HederaSealedBidTender` overrides the `ReplaceBid` check with `HederaAccountAuth.isAuthorizedRaw`; deposit token = Hedera v2 meta token; gas limit tight (HSCS charges ≥ 80 % of the limit) |
| Cosmos (CosmWasm) | PLANNED | contract holds the deposit; commit = the meta token's signed `Relay` op with a `pay` memo = `depositRef`, executed by the tender via submessage; commitment over `(chain_id, contract, tender, bidder, price, salt)` with SHA-256 |
| Soroban | PLANNED | `require_auth` entries of the bidder for `commit_bid` (deposit = SAC/token `transfer` sub-invocation in the same auth tree); reveal/withdraw permissionless |
| Sui / Aptos | PLANNED | tender object / resource; deposit coin moved by the relayer-submitted PTB / entry function under the bidder's signed op; time from `Clock` / `timestamp` |
| TON | PLANNED | async: deposit arrives as a jetton `transfer_notification` with `forward_payload = (tenderId, commitment)`; reveal/withdraw are internal messages; bounce handling on refunds |
| Solana | PLANNED | program + PDA vault per tender; deposit via the token program CPI under the bidder's Ed25519-precompile-verified op (RS12) |

---

## B1. Gas sponsorship policy (node)

### B1.1 Model

The node already pays gas for every job it lands. A policy decides **which account that gas is booked to, how much
of it is allowed, and whether a fee floor is waived** (R189). Evaluation happens once, at accept, on job data only;
the result is stored on the job (`sponsor_policy_id`). The client keeps booking from finalized events plus the new
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
  max_tx_per_hour INTEGER NOT NULL,
  max_tx_per_payer_hour INTEGER NOT NULL,             -- payer = m.from / op signer; 0 = no per-payer cap
  on_exhausted    TEXT NOT NULL CHECK (on_exhausted IN ('reject', 'unsponsored')),
  valid_from BIGINT, valid_to BIGINT,                 -- optional window (unix s)
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX sponsor_policy_match ON sponsor_policy (chain_key, state, priority, id);

CREATE TABLE sponsor_usage (                          -- buckets: day (cost), hour (tx), payer-hour (tx)
  policy_id BIGINT NOT NULL, bucket TEXT NOT NULL,    -- 'd:2026-10-06' | 'h:2026-10-06T14' | 'p:<payer>:2026-10-06T14'
  tx_count BIGINT NOT NULL DEFAULT 0,
  cost_spent TEXT NOT NULL DEFAULT '0',               -- measured (decimal, arbitrary precision in code)
  cost_reserved TEXT NOT NULL DEFAULT '0',            -- live sponsored jobs × max_cost_per_tx
  PRIMARY KEY (policy_id, bucket));                   -- hour/payer buckets pruned after 48 h, day buckets after 400 d

-- job additions
ALTER TABLE job ADD COLUMN sponsor_policy_id BIGINT;  -- NULL = booked to the namespace
ALTER TABLE job ADD COLUMN gas_used BIGINT;           -- or the family's resource figure
ALTER TABLE job ADD COLUMN gas_price TEXT;            -- effective price, smallest native unit per gas (EVM/Hedera)
ALTER TABLE job ADD COLUMN cost_native TEXT;          -- total fee paid by the lane, smallest native unit
```

Hedera reports cost in tinybar from the record (gas price conversion is the network's); Cosmos the `fee` coin of the
outer tx; Sui `gasUsed` total; Aptos `gas_used × gas_unit_price`; TON total fees of the outer message chain charged
to the lane; Solana `meta.fee` (+ priority fee); Soroban `fee_charged` (stroops).

### B1.3 Evaluation at accept (after NI §5.2 step 7, inside the step 8 transaction)

```
match(job) -> Option<policy>:
  candidates = active policies of job.chain_key, now within [valid_from, valid_to], ordered (priority, id)
  first p where  p.namespace ∈ {job.namespace, '*'}          -- '*' never matches '~mesh'/'~gateway' (explicit only)
             ∧ p.job_kind ∈ {job.kind, '*'}
             ∧ p.contract ∈ {contract_of(job), '*'}         -- metatx/signed_op: token_of; call: target
             ∧ p.selector ∈ {selector_of(job), '*'}
             ∧ (p.receiver IS NULL ∨ p.receiver == receiver_of(job))   -- call jobs: receiver must be NULL
             ∧ value_of(job) ≥ p.min_value                   -- call jobs: min_value must be '0'
admit(job, p):
  day, hour, payer-hour buckets of p
  ok = day.cost_spent + day.cost_reserved + p.max_cost_per_tx ≤ p.budget_per_day
       ∧ hour.tx_count < p.max_tx_per_hour ∧ (p.max_tx_per_payer_hour = 0 ∨ payerhour.tx_count < cap)
  ok         ⇒ job.sponsor_policy_id = p.id; reserve p.max_cost_per_tx; tx_count += 1 (hour, payer-hour, day)
  ¬ok, reject      ⇒ 429 SPONSOR_BUDGET {policy: p.name}
  ¬ok, unsponsored ⇒ no sponsor; the door's normal fee floor applies
no match ⇒ no sponsor; the door's normal fee floor applies
```

Fee floor per door: client namespaces — none (jobs are accepted as today); `~gateway` and `~mesh` — the MESH §7
`min_fee` of the matching mesh policy row, compared with the effective fee (R86). A sponsored job's floor is 0. A
policy never makes a job acceptable that NI §5.2 or MESH §7.2 would refuse for any other reason (unregistered token,
`support = none`, expiry, `allow_call`).

At lease time (simulation): estimated cost `= gas_estimate × max_fee_cap` > `max_cost_per_tx` ⇒ job `dead`,
`error = SPONSOR_TX_CAP` (terminal, the client may re-push unsponsored). At `mined`/`reverted`: release the
reservation, add `cost_native` to `cost_spent`. A `dead`/`consumed`/`cancelled` job releases its reservation with
no cost. Lost races (`consumed`) after broadcast are booked with their measured cost.

### B1.4 Jobs feed and client booking

Job feed items in states `mined`, `reverted` (and the final snapshot) add `gas_used`, `gas_price`, `cost_native`,
`sponsor: {policy, account} | null`. Clients book `cost_native` (converted at transaction time to the reporting
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
`min_value = '0'`, `job_kind = call` ⇒ `receiver IS NULL ∧ min_value = '0'`, every uint256 field parses, `namespace`
exists or is reserved/`*`. Every mutation is an `audit_log` row with before/after (R110). Bootstrap from
`node.toml` `[[sponsorship.policies]]` follows R95 (import if absent, never overwrite).

### B1.6 Metrics

`scaas_sponsor_jobs_total{policy,chain,result="admitted|rejected_budget|rejected_rate|unsponsored|tx_cap"}`,
`scaas_sponsor_cost_spent{policy,chain}` (gauge, current UTC day, native smallest unit as float),
`scaas_sponsor_budget_remaining_ratio{policy}`, `scaas_sponsor_reserved{policy}`. No payer labels (cardinality,
and payers are pseudonymous personal data, SCaaS §11.1).

### B1.7 Security

| Threat | Defence |
|---|---|
| Gas drain through a public door with fee 0 | `~gateway`/`~mesh` need an explicit policy (`*` namespace does not match them); budget, hourly and per-payer caps |
| Farming an inbound subsidy ("≥ X to wallet W") | the farmer pays ≥ X to W per sponsored tx; per-payer cap |
| Simulation-passes-then-reverts griefing | measured cost counts against the budget; MESH `origin_grief_score` applies to `~mesh` |
| Expensive calldata (huge batch, heavy ERC-1271) | `max_cost_per_tx` checked at lease from the estimate |
| Policy edit by a low role | create/patch/delete `admin` only, audited |
| Over-reservation starving a policy | reservations are released on every terminal state; `cost_reserved` recomputed from live jobs at startup |

Tests (SP1): matching precedence and every wildcard rule; `'*'` vs reserved namespaces; budget boundary (exactly
equal admits); hour and payer-hour caps; `reject` vs `unsponsored`; reservation release on each terminal state;
restart recomputes reservations; lease-time `SPONSOR_TX_CAP`; feed fields per family (EVM, Hedera, one non-EVM);
admin route roles and audit rows; toml import precedence.

### B1.8 Families

Node-level, so every family: the cost fields of §B1.2 per family; matching uses the decoded op (`token_of`,
payee, value) for `signed_op`. Non-EVM intents carry no fee, so for them a policy only books and limits.

---

## B2. Receiver-pays

### B2.1 Messages

Payer (unchanged): `MetaTransaction{from: payer, to: payee, value: N, data: pay(entryRef), batch, nonce, validUntil,
mode (fee NONE; relayer optionally bound), relayer, fee: 0, feeRecipient: 0}` in domain `("SCaaS MetaToken", "2",
chainId, token)`. `paymentDigest = _hashTypedDataV4(hashStruct(m))`.

Payee (new, same domain):

```solidity
bytes32 constant RECEIVER_FEE_TYPEHASH =
    keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");
```

`feeRecipient = 0` means "whoever submits" (`msg.sender`), as in the payer pipeline; a payee that wants one relayer
names it. No nonce: `paymentDigest` executes at most once (payer nonce), and only through this function does the
co-signature have any effect.

### B2.2 Function (TW2 §7 style, `MetaTokenBase`)

```solidity
event ReceiverFeePaid(bytes32 indexed paymentDigest, address indexed payee, address indexed feeRecipient, uint256 fee);
error ReceiverFeeShape();                                   // not pay op, or payer fee mode != NONE, or fee field != 0
error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
error ReceiverFeeAmount(uint256 fee, uint256 value);        // fee == 0 or fee > value

function mtxPayReceiverFee(MetaTxLib.MetaTransaction calldata m, bytes calldata payerSig,
                           uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig)
    external nonReentrant returns (bool);
function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
    external view returns (bytes32);
```

Order:

1. Shape: `m.data` is `pay(bytes32)` (36 bytes), `feeModeOf(m.mode) == NONE`, `m.fee == 0`, `m.feeRecipient == 0`
   else `ReceiverFeeShape`; `block.timestamp ≤ rfValidUntil`; `0 < fee ≤ m.value`.
2. `fr = feeRecipient == 0 ? msg.sender : feeRecipient`; `fr == m.to` ⇒ `FeeRecipientIsPayee` (R132).
3. `bytes32 d = _execute(m, payerSig)` — the unchanged nine steps (payer → payee `N`, `PaymentSettled`,
   `MetaTransactionExecuted`); `_execute` now returns its digest (internal change only).
4. `_requireValidSignature(m.to, receiverFeeDigest(d, fee, feeRecipient, rfValidUntil), payeeSig)` (EOA, ERC-1271 with
   `_erc1271Gas(m.to)`, HIP-632 on Hedera children).
5. `_transfer(m.to, fr, fee)` (cannot fail: the payee just received `N ≥ fee`); emit `ReceiverFeePaid(d, m.to, fr,
   fee)`.

Equivalence: the payer side is exactly `mtxPay`/`executeMetaTransaction` with the same struct — same digest, events
and nonce. A payer signature landed through any other path makes the co-signature dead (no fee is taken).

### B2.3 Invariants

- **RP1** The payee's net change from the call is `N − fee ≥ 0`; the payer's is `−N`; the fee recipient's `+fee`.
- **RP2** A co-signature takes effect at most once and only together with the exact payer intent it names.
- **RP3** No field signed by either party can be changed by the relayer.
- **RP4** Fee collected ⇔ payment completed (one transaction, reverts together).

### B2.4 Abuse

| Threat | Defence |
|---|---|
| Relayer raises the fee or redirects it | `fee`, `feeRecipient` signed by the payee |
| Payee signature replayed on another payment | bound to `paymentDigest` (domain = token + chain) |
| Payer forces a fee on the payee | needs `payeeSig` |
| Race: someone lands the payer intent alone | payee pays nothing; the co-signing relayer loses the race (bind the payer's relayer to it) |
| Fee leaves the payee negative | `fee ≤ m.value` (RP1) |
| Malicious ERC-1271 payee wallet | `staticcall` with the token's gas cap; failure reverts the whole call (payer intent stays valid elsewhere) |

### B2.5 Node, Odoo, app touchpoints

- **Job payload** (`kind = metatx`, NI §5.2): optional `receiver_fee: {fee, feeRecipient, validUntil, signature}`.
  Digest = the payer digest (G2 unchanged). Accept adds: shape of §B2.2 step 1–2 without RPC; `valid_until =
  min(m.validUntil, receiver_fee.validUntil)`; `bus.scope` forced `restricted` (R193); never batched. The
  co-signed `feeRecipient` is signed, so R84/R100 normalization does not touch it. Submit calls `mtxPayReceiverFee`.
  Token capability: admin flag `token.features` contains `receiver_fee` (set at registration; simulation is the final
  check) ⇒ else `422 FEATURE_UNSUPPORTED`.
- **Indexer:** decodes `ReceiverFeePaid` into `range` items.
- **Payee ERP (Odoo example):** payment request field `fee_paid_by_receiver` and `receiver_fee_amount` (base units)
  on the request the payee issues; after the payer's address is known (portal: wallet connected) the server builds
  the payer's typed data with fee `NONE` and relayer = its lane, computes `paymentDigest` and signs `ReceiverFee` with
  the receiving wallet's signer (a `SubjectAccount` receiving wallet with an ERC-1271 co-sign key under
  `SigningPolicyService` limits, or a dev `env:` key; a cold receiving wallet cannot co-sign and must not offer this
  mode). Booking: receipt `N` from `PaymentSettled`, fee expense `F` from `ReceiverFeePaid` matched by digest.
- **Payer ERP:** unchanged (pays `N`, books `N`).
- **E-cheque flow:** the payer signs offline and hands the intent to the payee, which co-signs over the digest and
  submits through any relayer that accepts the fee.

### B2.6 Gas and tests

Gas: `mtxPay` + payee signature (~4 k EOA, ERC-1271 up to its cap) + `ReceiverFee` hashing (~1 k) + one transfer
(~7 k warm, ~25 k new recipient) + event (~2 k): **+14 to +32 k** over `mtxPay`. Measured in RP-stream gas tests.

Tests (RP1): each shape error; fee 0, fee = value, fee > value; recipient = payee (bound and defaulted);
co-signature over another digest; expired co-signature; replay after the payer intent landed through
`executeMetaTransaction` (bad nonce); ERC-1271 payee (`SubjectAccount`) and Hedera HIP-632 payee; RP1/RP4 under
fuzz; event fields; node accept rules and the forced `restricted` scope.

### B2.7 Families

EVM and Hedera v2 (next implementation version per tier). v1, Zether and non-EVM families: not available (R193,
non-goals); there the options are payee self-relay and sponsorship.

---

## B3. SponsorshipPool (PLANNED-later stream PL1)

### B3.1 Interface

```solidity
interface ISponsorshipPool {
    struct Program {
        address sponsor; address token; address receiver;       // receiver 0 = any
        bytes4 selector;                                        // OP_PAY or bytes4(0) = plain transfer
        uint256 minValue;
        uint64 start; uint64 end;
        uint32 overheadGas; uint64 maxPriorityFee; uint128 maxRewardPerIntent;
        uint32 maxIntentsPerPayerPerDay;                        // 0 = no cap
        uint64 withdrawDelay;                                   // >= MIN_WITHDRAW_DELAY (R194)
    }
    event ProgramCreated(uint256 indexed id, address indexed sponsor, Program p);
    event ProgramFunded(uint256 indexed id, uint256 amount);
    event WithdrawRequested(uint256 indexed id, uint64 unlockAt);
    event Withdrawn(uint256 indexed id, uint256 amount);
    event Sponsored(uint256 indexed id, bytes32 indexed digest, address indexed relayer, uint256 gasCharged,
                    uint256 reward);
    error ProgramInactive(); error IntentNotEligible(uint8 code); error PayerCapReached(); error WithdrawLocked();
    error NotSponsor();

    function createProgram(Program calldata p) external payable returns (uint256 id);
    function fund(uint256 id) external payable;
    function requestWithdraw(uint256 id) external;              // sponsor; also stops new settles at unlockAt
    function withdraw(uint256 id, uint256 amount) external;     // sponsor, after unlockAt
    function settle(uint256 id, MetaTxLib.MetaTransaction calldata m, bytes calldata sig)
        external returns (uint256 reward);                      // token = p.token
}
```

### B3.2 `settle`

1. Program active (`start ≤ now ≤ end`, not past `unlockAt`), `m.to == p.receiver` (if set),
   selector match, `m.value ≥ minValue`, fee mode `NONE` (one reward per intent), relayer bound to the pool **or**
   unbound (bound is recommended: the payer opts into the program), payer daily cap.
2. `g0 = gasleft()`; `IERC20MetaTx(p.token).executeMetaTransaction(m, sig)`; `used = g0 − gasleft() + overheadGas`.
3. `price = min(tx.gasprice, block.basefee + maxPriorityFee)`; `reward = min(used × price, maxRewardPerIntent,
   balance)`; balance −= reward (before the call); `msg.sender.call{value: reward}("")` (failure reverts all).
4. Emit `Sponsored(id, digest, msg.sender, used, reward)` (`digest` from `token.metaTxDigest(m)`).

Guards: transient reentrancy guard; `token` must pass the R186 provenance check at `createProgram`.

### B3.3 Abuse and limits

Self-farming yields at most a gas refund (no margin beyond `overheadGas`); priority-fee kickback bounded by
`maxPriorityFee`; sponsor rug-pull bounded by `withdrawDelay`; relayers re-simulate before broadcast. Hedera: HSCS
charges ≥ 80 % of the gas limit, so measured gas under-refunds; Hedera support needs a limit-based formula (decided
in PL1). Node: a job whose payer intent binds `relayer = pool` is accepted as a `call` job to `settle` on a registered
`sponsorship_pool` contract (§A.6), sent by any of the chain's lanes (R102 pinning does not apply: the intent binds
the pool, not a lane); the mesh does not carry it (R194). Other families: none
planned.

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
field salt    = HMAC-SHA256(recordSalt, "scaas.field.v1" ‖ 0x00 ‖ utf8(fieldName))   # selective disclosure
field commit  = keccak256(abi.encode(FIELD_TAG, fieldSalt, SHA-256(JCS(value))))    FIELD_TAG = keccak256("scaas.field.v1")
merkle leaf   = keccak256(0x00 ‖ commitment)                  # one leaf per record
merkle node   = keccak256(0x01 ‖ min(a, b) ‖ max(a, b))       # sorted pairs, OZ-compatible ordering
```

Uses: `documentRef` (tender documents), `reasonRef` (cancel, bond claim), anchored records (SCaaS §2.2) and batch
roots. The payload is never on chain; `payloadHash` alone is not published (a hash of low-entropy data is
brute-forceable, the salt is what hides it).

### C.3 Salt and key storage (client; Odoo example)

- **Hierarchy:** KEK (KMS/HSM/Vault transit, or a key file/env secret outside the database) → per-subject DEK
  (AES-256-GCM key, wrapped) → salts encrypted with the subject's DEK (AES-256-GCM, AAD = record id).
- **Tier A (KMS/secret store):** DEK stored and destroyed in the KMS; erasure is immediate everywhere, backups
  included.
- **Tier B (no KMS):** wrapped DEK in the ERP database. Erasure deletes the DEK row; old backups still hold it, so
  erasure becomes complete when the last such backup expires (deployment's backup retention, stated in its records
  of processing), and every restore replays the erasure log before the system reopens.
- **Odoo example (`dms_blockchain`, not built):** model `blockchain.shred.key` (`subject_ref` = HMAC of
  `res.partner` id, `wrapped_dek`, `state`), model `blockchain.shred.salt` (`model`, `res_id`, `subject_key_id`,
  `ciphertext`, `retain_until`, `legal_basis`); both without ACL rows for non-system groups and with `SERVER_ONLY`
  fields (NI R101); access only through server methods (`_shred_commit(record, payload)`,
  `_shred_open(record)`); KEK from the environment or a secret file, **never** `ir.config_parameter` (it lives in
  the database and its backups). Salts never appear in outbox payloads, logs, or the node.
- **Never:** salts in the node store, on chain, in logs, in analytics exports (SCaaS §11.4), or derived from the
  payload or from a business id.

### C.4 Erasure and retention procedure

```
erase_subject(party_id, reason) -> {ticket, erased: […], refused: [{model, id, legal_basis, retain_until}]}
  requires role compliance_officer (client side)
  1. ticket = random 16 bytes; log row {ticket, HMAC(log_key, party_id), reason_code, at}   # no plain id hash
  2. for each record of the subject:
       retain_until > now ⇒ refuse (legal basis returned), schedule erasure at retain_until
       else              ⇒ delete plaintext payload and its salt row
  3. delete the off-chain mapping (approved wallet records ↔ party) unless refused in 2
  4. no record left under retention ⇒ destroy the subject's DEK (Tier A) / delete it (Tier B)
  5. nothing to send to the node or chain (R195); node payloads age out within job_retention_secs (30 d)
restore(backup):
  replay every erasure ticket newer than the backup before reopening (Tier B completeness)
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

Disclosure flow: the client hands the auditor `(salt, payload)` or a field opening for the specific record, never
the DEK; for Zether the opening of §8.9 SCaaS. The independent verifier CLI (SCaaS §11.3, PLANNED) gains three
commands: `verify-commitment`, `verify-merkle`, `verify-field`.

### C.6 `entryRef`, `payId` and other references (R198)

- `entryRef`/`payId`: 32 random bytes per payment request (R9); never a hash of invoice numbers or parties; no salt
  needed; erasure = delete the request ↔ party link.
- `depositRef` (R180) is derived from `(chainId, tender, tenderId, commitment)`: public data only.
- `documentRef`, `reasonRef`: salted commitments (§C.2), so the documents and reasons they name are shreddable.
- `origin.key` and `client_ref` sent to the node (NI R91): opaque (`entryRef`, record ids), never names.

### C.7 Tests and checks (CS streams)

KATs for every format of §C.2 (Python, TypeScript, Solidity view helper) in `tests/kat/commitments.json`; JCS
edge cases (Unicode, numbers); erasure procedure: retained vs erasable records, DEK destruction, log contains no
derivable id, restore replays tickets; CI calldata-type guard of SCaaS §11.1 (allow `address`, `bool`, `uint*`,
`int*`, `bytes32`, `bytes32[]`; deny `string`/`bytes` except declared proof/signature/meta-tx fields) applied to the
tender, `mtxPayReceiverFee` and the pool.

### C.8 Families

Chain-agnostic: a commitment is 32 bytes on every family (anchoring transport per family is the anchoring
stream). Hash function on chain stays keccak256 for EVM/Hedera; families that anchor with SHA-256 natively use the
same structure with SHA-256 and a distinct tag (`scaas.commit.sha256.v1`).

---

## 8. Streams

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| TB1 | Tender EVM | `SealedBidTender` + tests (§A.9), KAT, gas snapshot | TW2 T1–T6 (built) | **SPECIFIED** |
| TB2 | Tender Hedera | `HederaSealedBidTender` (HIP-632 replace), HSCS e2e | TB1 | **SPECIFIED** |
| TB3 | Tender node + ERP | `chain_contract`, indexer events, admin contracts route, Odoo `blockchain.tender*`, portal bidder flow | TB1, NI P2–P5 | **SPECIFIED** |
| TB4 | Tender other families | §A.10 designs | TB1, family contracts | PLANNED |
| SP1 | Sponsorship policy | tables, accept/lease/mined hooks, feed cost fields, admin routes, metrics, tests (§B1.7) | NI P3 (submit from store), P2b (admin routes) | **SPECIFIED** |
| SP2 | Sponsorship booking (Odoo) | cost fields → gas expense per business document and sponsor account | SP1, NI P5 | **SPECIFIED** |
| RP1 | Receiver-pays contract | `mtxPayReceiverFee`, `_execute` returns digest, new implementation version per tier (EVM + Hedera children), tests, gas | TW2 (built), before O3 production registration | **SPECIFIED** |
| RP2 | Receiver-pays node + Odoo | `receiver_fee` job field, `token.features`, indexer event, payee co-sign service, booking | RP1, NI P3–P5; `SigningPolicyService` for production keys | **SPECIFIED** |
| PL1 | SponsorshipPool | §B3, Hedera formula, node `call` routing | SP1, TB3 (`chain_contract`) | **PLANNED-later** |
| CS1 | Shredding client | commitment library (Python/TS) + KATs, Odoo `blockchain.shred.*`, erasure API, restore replay | — | **SPECIFIED** |
| CS2 | Calldata guard | CI guard of §C.7 | — | **SPECIFIED** |
| CS3 | Verifier CLI | `verify-commitment`, `verify-merkle`, `verify-field` + Zether openings (SCaaS §11.3) | CS1 | PLANNED |

Order: RP1 first (cheapest while no production v2 registration exists), TB1 and CS1/CS2 in parallel, then SP1 when
NI P3 lands, then TB3/RP2/SP2, PL1 last.

## 9. Open questions

None open. Decided by the owner in rev 1.1:

1. **Post-reveal disqualification:** yes — leader only, inside a short award window fixed at creation, with an
   on-chain `reasonRef`; refund in full unless a violation class declared at creation applies (then forfeit to
   `slashSink`); at most two per tender; residual discretion stated (R185, §A.2.2, §A.7.2).
2. **Receiver-pays on v1 tokens:** no; v2-only, no v1 router (R193).
