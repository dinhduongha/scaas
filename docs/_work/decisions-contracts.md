# Decisions — contracts (Phase 1 register, merged into docs/decisions.md in Phase 2)

Entries for every `CTR-` id: current, open and superseded. Format per the reorg plan §3.3. Rationale is
self-contained; the old ids live only in the `old:` field.

## General

### CTR-GEN-01 — Separate blockchain CI; forge libs pinned by tag
- old: R52 · status: current · owner: no · date: 2026-10-03 · normative: contracts/README.md#CTR-GEN-01 · superseded-by: —

**Why.** Contracts break in ways the node tests do not see; pinning the forge libraries by tag makes a CI run reproducible because `lib/` is not committed.
**Cost if wrong.** An unpinned dependency changes bytecode between two runs and a deployed address no longer matches its audited source.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:525`

### CTR-GEN-02 — Value-holding programs immutable from deploy
- old: CR-R3-11, UD:§20.2, owner:2026-10-07:immutable · status: current · owner: yes · date: 2026-10-07 · normative: contracts/README.md#CTR-GEN-02 · superseded-by: —

**Why.** Users can verify once what a program does and rely on it forever; an upgrade key is an admin key over every balance. Rejected alternatives: UUPS/ERC-1822 proxies "for all contracts", `ReentrancyGuardUpgradeable` + an admin `Pausable` on every function, and "delegate to share code, support many versions": versions are new implementations behind immutable clones, and a registry must never be upgradeable.
**Cost if wrong.** A bug is permanent for that deployment; the remedy is a new deployment plus voluntary migration, so audits and the deploy gate must precede real funds.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:714`, `research/_USER-DECISIONS.md:1140`, `history/SCaaS-2026-10-07.md:40`. Owner wording for the Aptos, Sui and Solana programs: "Bất biến ngay khi deploy" (immutable as soon as deployed).

### CTR-GEN-03 — Contracts in their own tree per family
- old: UD:§1:smartcontracts-tree · status: current · owner: yes · date: 2026-08-30 · normative: contracts/README.md#CTR-GEN-03 · superseded-by: —

**Why.** Each family has its own toolchain; one tree per family keeps builds and audits separable.
**Cost if wrong.** Mixed trees force every family build to know every other toolchain.
**Source.** `research/_USER-DECISIONS.md:46`

### CTR-GEN-04 — Issuer choices are not protocol decisions
- old: UD:§20.5 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/README.md#CTR-GEN-04 · superseded-by: —

**Why.** SCaaS ships a protocol, not a token catalogue; names, symbols, rates and roles belong to the issuer who answers for them.
**Cost if wrong.** If SCaaS made issuer choices it would carry issuer liability and become a gatekeeper.
**Source.** `research/_USER-DECISIONS.md:1272`

## Meta-transactions

### CTR-MTX-01 — Pay op is pay(bytes32) via executeMetaTransaction
- old: R2(op) · status: current · owner: no · date: 2026-10-03 · normative: contracts/metatx.md#CTR-MTX-01 · superseded-by: —

**Why.** A payment is one signed `pay(bytes32 entryRef)` op through the standard envelope, so wallets, relayers and indexers handle payments with no extra entry point.
**Cost if wrong.** A separate payment entry point would duplicate the nine-step pipeline and its audit surface.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:664`

### CTR-MTX-02 — Clone domain: implementation name, clone verifyingContract
- old: R5 · status: current · owner: no · date: 2026-10-03 · normative: contracts/metatx.md#CTR-MTX-02 · superseded-by: —

**Why.** Clones share the implementation name and version but each clone is its own `verifyingContract`, so a signature for one token never replays on another.
**Cost if wrong.** A shared domain would let a signature move between clones of the same implementation.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:674`

### CTR-MTX-03 — Random entryRef; pay lane derived from it
- old: R9(lane) · status: current · owner: no · date: 2026-10-03 · normative: contracts/metatx.md#CTR-MTX-03 · superseded-by: —

**Why.** A random `entryRef` cannot be guessed or front-run, and deriving the pay lane from it lets the contract enforce pay-once without a request registry.
**Cost if wrong.** Sequential references leak volumes and allow pre-emptive lane exhaustion.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:692`

### CTR-MTX-04 — Pay-once holds under lane horizon H
- old: CR-PD-4(issuer) · status: current · owner: no · date: 2026-10-07 · normative: contracts/metatx.md#CTR-MTX-04 · superseded-by: —

**Why.** Pay-once is a protocol rule only within the lane horizon; stating the horizon makes the guarantee checkable instead of implied.
**Cost if wrong.** Clients that assume unconditional pay-once could double-pay after the horizon.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:901`

### CTR-MTX-05 — Receiver-pays via payee co-signed ReceiverFee
- old: R192 · status: current · owner: no · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-05 · superseded-by: —

**Why.** Receiver-pays needs the payee to consent to the fee; a co-signed `ReceiverFee` keeps both parties bound to the same numbers.
**Cost if wrong.** Without the payee signature a relayer could charge the payee arbitrarily.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:172`

### CTR-MTX-06 — Receiver-pays op shape, v2-only availability
- old: R193(shape) · status: current · owner: yes · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-06 · superseded-by: —

**Why.** Receiver-pays is a v2-only op of fixed shape, so v1 clones keep their audited surface.
**Cost if wrong.** Back-porting would change audited v1 bytecode.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:181`

### CTR-MTX-07 — MetaTxCore v2: same struct, domain version 2
- old: R131 · status: current · owner: no · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-07 · superseded-by: —

**Why.** v2 keeps the v1 struct and typehash with domain version 2: existing signing code works and v1/v2 signatures cannot be confused.
**Cost if wrong.** A new struct would split every client and indexer.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:72`

### CTR-MTX-08 — Fee never goes to the payee
- old: R132 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-08 · superseded-by: —

**Why.** A fee that goes to the payee lets a payee inflate its own receipts; refusing it keeps the fee a relayer payment.
**Cost if wrong.** Payees could disguise discounts or extract hidden charges through the fee field.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:78`

### CTR-MTX-09 — Named meta-tx functions are thin entry points
- old: R138 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-09 · superseded-by: —

**Why.** Named functions are readable in wallets and explorers, but they only route into the one pipeline, so there is no second security model.
**Cost if wrong.** Logic in the named functions would drift from the envelope path.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:119`

### CTR-MTX-10 — mtxPay payId is entryRef, lane on chain
- old: R139 · status: current · owner: no · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-10 · superseded-by: —

**Why.** `payId` is the payment reference and the lane is derived on chain, so a client cannot mislabel the lane.
**Cost if wrong.** Client-chosen lanes would break pay-once.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:124`

### CTR-MTX-11 — No second typehash; mtxBatch atomic
- old: R140 · status: current · owner: no · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-11 · superseded-by: —

**Why.** One typehash per struct keeps every signer and verifier on one digest rule; `mtxBatch` is atomic so a partial batch cannot strand fees.
**Cost if wrong.** A second hash of the same struct invites cross-path replay; a non-atomic batch leaves half-paid states.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:131`

### CTR-MTX-12 — Gasless unwrap op with minOut
- old: R148(contract) · status: current · owner: yes · date: 2026-10-06 · normative: contracts/metatx.md#CTR-MTX-12 · superseded-by: —

**Why.** A gasless unwrap lets holders exit without native gas; `minOut` protects them against rate moves between signing and execution.
**Cost if wrong.** Without `minOut` a relayer could time execution against the holder.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:172`

### CTR-MTX-13 — Public fee modes NONE, PERCENT, FIXED
- old: UD:§3.1, UD:§11:fee-denominator · status: current · owner: yes · date: 2026-08-30 · normative: contracts/metatx.md#CTR-MTX-13 · superseded-by: —

**Why.** Three fee modes cover the business cases (none, percentage, fixed) with a 1 % cap on percentages: the denominator is 1e6 ppm, so the cap is 10000 ppm.
**Cost if wrong.** More modes multiply audit cases; an uncapped percentage would let a signer be overcharged by a misreading.
**Source.** `research/_USER-DECISIONS.md:107`, `research/_USER-DECISIONS.md:450`

### CTR-MTX-14 — EIP-712 typed data, not personal_sign
- old: UD:§4 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/metatx.md#CTR-MTX-14 · superseded-by: —

**Why.** EIP-712 typed data is what wallets display; `personal_sign` of a hash shows the user nothing they can check. The first committed code hashed with `toEthSignedMessageHash()` (`personal_sign`) while the design sketch signed with `wallet._signTypedData(domain, types, data)` (EIP-712); the design was right and the code was changed.
**Cost if wrong.** Users would sign blind hashes, the precondition for drain attacks.
**Source.** `research/_USER-DECISIONS.md:206`

### CTR-MTX-15 — No forwarder; drop feeToken, innerGasLimit; keep mode
- old: UD:§24, UD:§24.1 · status: current · owner: yes · date: 2026-08-31 · normative: contracts/metatx.md#CTR-MTX-15 · superseded-by: —

**Why.** Meta-tx logic lives in the token, so there is no trusted forwarder; `feeToken` and `innerGasLimit` were dropped (another token is outside this contract; the gas limit only matters to a forwarder that swallows failures) and `mode` was kept, split into two nibbles: the low nibble holds flags (`RESTRICT_RELAYER` 0x01, `RESTRICT_FEE_RECIPIENT` 0x02), the high nibble an enum of the fee mode (`NONE` 0x00, `PERCENT` 0x10, `FIXED` 0x20). The halves differ in kind: `if (mode & MODE_FEE_PERCENT)` is a bug, because `MODE_FEE_FIXED = 0x20` lacks bit 0x10 but a future 0x30 would have it; validation checks unknown flag bits and enum values above 2. Rejected: the early `IEIP1776` sketch (`tokenContract`, `batchNonce`, `expiry`, `meta_nonce(from, batchId)`) — corrected to `MetaTxLib.MetaTransaction` with `metaNonce`, `validUntil` and the split mode nibble.
**Cost if wrong.** A forwarder becomes a shared trust root for every token; keeping the sketch shape would add fields no contract can enforce.
**Source.** `research/_USER-DECISIONS.md:2504`, `research/_USER-DECISIONS.md:2534`

### CTR-MTX-16 — No generic forwarder; wrap legacy tokens
- old: UD:§24.2, UD:§24.3 · status: current · owner: yes · date: 2026-08-31 · normative: contracts/metatx.md#CTR-MTX-16 · superseded-by: —

**Why.** No generic forwarder means each token owns its replay protection; legacy tokens are wrapped instead of trusted. A generic forwarder cannot know why the inner call will fail, so it must either take the fee and swallow the error (the user pays for nothing) or bubble the revert (the relayer pays gas for nothing); a token that executes its own meta-transaction knows its failure cases before it charges.
**Cost if wrong.** A generic forwarder would let one bug affect every legacy token at once.
**Source.** `research/_USER-DECISIONS.md:2570`, `research/_USER-DECISIONS.md:2586`

### CTR-MTX-80 — No named mtxPay; accepted gas cost
- old: R2(cost) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-MTX-09, CTR-MTX-10, CTR-MTX-11

**What it said.** An earlier design had no named `mtxPay` and accepted the generic path's gas cost.

### CTR-MTX-81 — Unconditional pay-once per request
- old: R9(pay-once) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-MTX-04, NET-ALL-01, NODE-STO-01

**What it said.** An earlier design promised unconditional pay-once per payment request.

### CTR-MTX-82 — Drop GSN gas fields and per-mille setter
- old: UD:§3.5 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early proposal dropped the GSN gas fields and a per-mille fee setter.

### CTR-MTX-83 — Relayer wildcard instead of mode bitmask
- old: UD:§5 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early proposal replaced the mode bitmask with a relayer wildcard.

### CTR-MTX-84 — Reconcile three struct variants
- old: UD:§11:struct-variants · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early note reconciled three different meta-tx struct variants.

## Token wrappers and factory

### CTR-TOK-01 — Spender and transferFrom caller must be contracts
- old: R26 · status: current · owner: yes · date: 2026-10-03 · normative: contracts/token-wrappers.md#CTR-TOK-01 · superseded-by: —

**Why.** An allowance held by an EOA is the classic drain vector; restricting spenders (and `transferFrom` callers) to contracts keeps allowances for DEX and escrow code that enforces its own rules.
**Cost if wrong.** EOA phishing approvals drain balances; legitimate EOA-spender flows must move to contracts or meta-tx.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:198`. Owner wording: "spender là hợp đồng" (the spender is a contract).

### CTR-TOK-02 — Three tiers, one implementation per tier
- old: R129 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-02 · superseded-by: —

**Why.** Three tiers (no underlying, single, multi) with one implementation each keep the audit surface small and the behaviour predictable per tier.
**Cost if wrong.** Per-token variants would multiply audits.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:61`

### CTR-TOK-03 — Factory v2 new deployment, appended token kinds
- old: R130 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-03 · superseded-by: —

**Why.** Factory v2 is a new deployment with appended kinds, so v1 kind numbers and clones never change meaning.
**Cost if wrong.** Renumbering kinds would break indexers and existing addresses.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:66`

### CTR-TOK-04 — Conversion rate num/den, rounding favours contract
- old: R133 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-04 · superseded-by: —

**Why.** Rates as `(num, den)` with rounding in favour of the contract keep reserves solvent under every rounding path.
**Cost if wrong.** Rounding in favour of users leaks value per operation and can drain reserves.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:84`

### CTR-TOK-05 — Internal reserve accounting and solvency invariant
- old: R134 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-05 · superseded-by: —

**Why.** Internal reserve accounting ignores donations and forced sends, so the solvency invariant is checkable from the contract's own state.
**Cost if wrong.** Balance-based accounting lets an attacker skew rates with a donation.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:91`

### CTR-TOK-06 — Fixed or timelocked adjustable rate at creation
- old: R135 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-06 · superseded-by: —

**Why.** The issuer chooses at creation between a fixed rate and a timelocked adjustable one; holders see the choice before they wrap.
**Cost if wrong.** A silently adjustable rate is an admin key over holders' value.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:98`

### CTR-TOK-07 — Multi-underlying any-of with disable-only guardian
- old: R136 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-07 · superseded-by: —

**Why.** Multi-underlying is any-of with a disable-only guardian: holders can always exit through any enabled leg and nobody can add a leg. Rejected: a weighted basket that mints from a group of tokens at fixed proportions — it needs price oracles and rebalancing, which the immutable design forbids.
**Cost if wrong.** A basket would introduce oracle and rebalancing risk into every wrap and unwrap.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:108`

### CTR-TOK-08 — Decimals are display only
- old: R137 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-08 · superseded-by: —

**Why.** Decimals are display only; arithmetic uses raw units, so a decimals mismatch can never misprice a wrap.
**Cost if wrong.** Scaling by decimals inside the contract adds rounding paths and errors.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:115`

### CTR-TOK-09 — NoUnderlyingToken holder burn, renounceable minter
- old: R141 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-09 · superseded-by: —

**Why.** A `NoUnderlyingToken` lets holders burn and its minter renounce, which matches self-issued tokens.
**Cost if wrong.** A non-renounceable minter is a permanent admin key.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:135`

### CTR-TOK-10 — Only creation-time visible admin exceptions
- old: R142 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-10 · superseded-by: —

**Why.** Only creation-time, publicly visible admin exceptions exist, so a holder can read every power over a token before acquiring it.
**Cost if wrong.** Hidden or later-added powers would make provenance meaningless.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:138`

### CTR-TOK-11 — Fee-on-transfer-out and rebasing underlyings unsupported
- old: R143 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-11 · superseded-by: —

**Why.** Fee-on-transfer-out and rebasing underlyings break 1:1 accounting; they are refused rather than half-supported.
**Cost if wrong.** Supporting them silently would make reserves drift from supply.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:144`

### CTR-TOK-12 — Voluntary v2 migration; domain read per token
- old: R146 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-12 · superseded-by: —

**Why.** Moving from v1 to v2 is voluntary; each token reads its own domain, so both generations keep working side by side.
**Cost if wrong.** Forced migration would require an admin key; a shared domain would confuse signatures.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:156`

### CTR-TOK-13 — Multi rates adjustable per leg, default off
- old: R147 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-13 · superseded-by: —

**Why.** Per-leg adjustable multi rates are an issuer option, off by default.
**Cost if wrong.** Default-on adjustability would surprise holders of plain wrappers.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:160`

### CTR-TOK-14 — Gasless wrap through permit is planned only
- old: R149 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-14 · superseded-by: —

**Why.** Gasless wrap through permit depends on the underlying supporting it; until then it is planned only.
**Cost if wrong.** Promising it would mislead integrators about tokens without permit.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:184`

### CTR-TOK-15 — Open factory: anyone creates tokens
- old: UD:§20 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-15 · superseded-by: —

**Why.** An open factory means anyone can create tokens or wrap any token; SCaaS is not a gatekeeper.
**Cost if wrong.** Spam tokens exist; provenance getters (CTR-TOK-17) let clients filter them.
**Source.** `research/_USER-DECISIONS.md:1079`

### CTR-TOK-16 — getWrapper keyed by creator and underlying
- old: UD:§20.3 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-16 · superseded-by: —

**Why.** Wrappers are looked up by `(creator, underlying)`, so two creators never collide and no global "official" wrapper exists. Three lookups answer three questions: getWrapper(creator, underlying) is A's xDAI wrapper; getWrapperCount / getWrapperAt list all of A's xDAI wrappers (one per curve or fee schedule); deployCountFor / deployedFor list every zDAI wrapper of every creator so the market can compare A with B. There is no uniqueness on `underlying` alone and no name or symbol review: `zDAI-A` and `zDAI-B` coexist normally.
**Cost if wrong.** A global wrapper slot invites squatting.
**Source.** `research/_USER-DECISIONS.md:1210`

### CTR-TOK-17 — Provenance getters instead of gatekeeping
- old: UD:§20.4 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-17 · superseded-by: —

**Why.** Every token answers immutably who created it and from which implementation; clients decide trust instead of the factory.
**Cost if wrong.** Clients that ignore provenance can be shown look-alike tokens.
**Source.** `research/_USER-DECISIONS.md:1255`

### CTR-TOK-18 — Factory is the critical immutable artifact
- old: UD:§20.6 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-18 · superseded-by: —

**Why.** The factory is the most critical immutable artifact: every clone inherits its code choices.
**Cost if wrong.** A factory bug is inherited by every token created through it until a new factory ships.
**Source.** `research/_USER-DECISIONS.md:1288`

### CTR-TOK-80 — No EOA approve lockdown
- old: R4 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-TOK-01

**What it said.** An earlier design did not lock EOA approvals.

## Accounts and mandates

### CTR-ACC-01 — SubjectAccount clones; salt binds key and guardian
- old: RS4-1 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts-mandates.md#CTR-ACC-01 · superseded-by: —

**Why.** Counterfactual clones with a salt binding the first key and the guardian give a predictable address that nobody else can claim.
**Cost if wrong.** A salt of the key alone would let anyone deploy the account with a hostile guardian.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:11`

### CTR-ACC-02 — Signature is keyIndex, Merkle proof, sig
- old: RS4-3 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts-mandates.md#CTR-ACC-02 · superseded-by: —

**Why.** One signature encoding `(keyIndex, proof, sig)` covers single operations and Merkle batches for both key types.
**Cost if wrong.** Two encodings would double the parsing and test surface.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:19`

### CTR-ACC-03 — Guardian recovery adds a key after two days
- old: RS4-4 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts-mandates.md#CTR-ACC-03 · superseded-by: —

**Why.** Guardian recovery adds a key after a two-day delay that any existing key can cancel, so a lost device is recoverable and a rogue guardian is visible.
**Cost if wrong.** An instant recovery would let a compromised guardian take the account.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:23`

### CTR-ACC-04 — Authenticator signCount is not checked
- old: RS4-5 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts-mandates.md#CTR-ACC-04 · superseded-by: —

**Why.** Synced passkeys report a zero or non-monotonic signCount; checking it would lock out legitimate users.
**Cost if wrong.** A cloned authenticator is not detected by the counter; the account relies on device security instead.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:27`

### CTR-ACC-05 — 400k ERC-1271 cap only for SubjectAccount clones
- old: RS4-10 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts-mandates.md#CTR-ACC-05 · superseded-by: —

**Why.** Only `SubjectAccount` clones, identified by codehash, get the 400 k ERC-1271 cap that the Solidity P-256 path needs; everything else keeps 50 k.
**Cost if wrong.** A global 400 k cap lets any contract wallet grief relayers with expensive validation.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:43`

### CTR-ACC-06 — Delegated payment uses MandateWallet, no allowance
- old: R25 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts-mandates.md#CTR-ACC-06 · superseded-by: —

**Why.** Delegated payment through a dedicated `MandateWallet` with per-token limits never exposes the payer's main balance to an allowance.
**Cost if wrong.** An allowance-based mandate would be an unlimited spender on the payer's tokens.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:196`

### CTR-ACC-07 — Signed mandate revocation bound to epoch
- old: CR-ADW-1 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts-mandates.md#CTR-ACC-07 · superseded-by: —

**Why.** A signed revocation bound to an epoch revokes every outstanding mandate signature at once and works gaslessly.
**Cost if wrong.** Without the epoch a revoked delegate could replay an older mandate.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:296`

### CTR-ACC-08 — Passkey subjects, Merkle batch, account key lifecycle
- old: R31(account) · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts-mandates.md#CTR-ACC-08 · superseded-by: —

**Why.** Retail subjects use passkeys they already have; Merkle batching gives one biometric prompt for many lines; one grammar and check order apply in every family.
**Cost if wrong.** Per-family WebAuthn checks drift, and one lax family (suffix origin, crossOrigin) becomes the phishing target.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:519`

### CTR-ACC-09 — SubjectAccount kept as optional option (b)
- old: R307 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts-mandates.md#CTR-ACC-09 · superseded-by: —

**Why.** `SubjectAccount` stays available as option (b) for users who want a stable address across key rotation.
**Cost if wrong.** Removing it would force every rotation to move funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:238`

## DEX

### CTR-DEX-01 — Settlement contract checks two signed orders
- old: R35(contract) · status: current · owner: yes · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-01 · superseded-by: —

**Why.** An off-chain persistent book with on-chain settlement of two signed orders gives exchange UX without custody; settlement checks price limits and fills itself.
**Cost if wrong.** Trusting the book for prices would let the operator fill against users.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:554`

### CTR-DEX-02 — Cancel signatures never expire
- old: RS5-10 · status: current · owner: no · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-02 · superseded-by: —

**Why.** Cancel signatures never expire, so a cancellation cannot lapse before the order does.
**Cost if wrong.** An expiring cancel could resurrect an order the maker withdrew.
**Source.** `history/specs/2026-10-03-dex-design.md:119`

### CTR-DEX-03 — Immutable admin sets markets; fee capped
- old: RS5-1 · status: current · owner: no · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-03 · superseded-by: —

**Why.** An immutable admin sets markets and a capped fee; it cannot touch user funds.
**Cost if wrong.** An uncapped or upgradeable admin is custody by another name.
**Source.** `history/specs/2026-10-03-dex-design.md:398`

### CTR-DEX-04 — EVM closes IOC remainder at settle
- old: RS5-3 · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-04 · superseded-by: —

**Why.** On EVM an IOC remainder is closed at settle, so it cannot fill later.
**Cost if wrong.** A dangling IOC remainder could fill at a stale price.
**Source.** `history/specs/2026-10-03-dex-design.md:402`

### CTR-DEX-05 — FOK checked on chain as one full pair
- old: RS5-4 · status: current · owner: no · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-05 · superseded-by: —

**Why.** FOK is checked on chain as one full pair, so a partial fill can never settle.
**Cost if wrong.** Trusting the book for FOK lets a buggy matcher partially fill.
**Source.** `history/specs/2026-10-03-dex-design.md:404`

### CTR-DEX-06 — Relayer FIXED fee pro-rata, rounds down
- old: RS5-6(relayer-fee) · status: current · owner: no · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-06 · superseded-by: —

**Why.** The relayer FIXED fee is charged pro-rata per fill and rounds down in the user's favour.
**Cost if wrong.** Charging the full fee per partial fill overcharges makers.
**Source.** `history/specs/2026-10-03-dex-design.md:407`

### CTR-DEX-07 — MetaTxDex kept as unrouted legacy
- old: RS5-7 · status: current · owner: no · date: 2026-10-03 · normative: contracts/dex.md#CTR-DEX-07 · superseded-by: —

**Why.** `MetaTxDex` stays deployed as legacy but is not routed by the gateway.
**Cost if wrong.** Routing two settlement contracts doubles the support surface.
**Source.** `history/specs/2026-10-03-dex-design.md:409`

### CTR-DEX-08 — OrderBookDex caps ERC-1271 gas by codehash
- old: RS5-14(contract) · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-08 · superseded-by: —

**Why.** OrderBookDex caps ERC-1271 gas by codehash (400 k for `SubjectAccount` clones, else 50 k) and refuses to run with too little gas left.
**Cost if wrong.** Uncapped 1271 lets a maker grief the settler; a 63/64 starvation could fake a failed check.
**Source.** `history/specs/2026-10-03-dex-design.md:431`

### CTR-DEX-09 — Non-EVM settlement bound to the relayer
- old: RS5-15(non-evm) · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-09 · superseded-by: —

**Why.** Non-EVM settlement is bound to the relayer, so a third party cannot front-run a matched pair.
**Cost if wrong.** Unbound settlement lets copycats steal relayer fees.
**Source.** `history/specs/2026-10-03-dex-design.md:438`

### CTR-DEX-10 — min_nonce capped by family word width
- old: RS5-19 · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-10 · superseded-by: —

**Why.** `min_nonce` is capped by each family's word width so a maker cannot brick its own nonce space by overflow.
**Cost if wrong.** An uncapped value could wrap or exhaust the nonce space.
**Source.** `history/specs/2026-10-03-dex-design.md:448`

### CTR-DEX-11 — DEX fee per fill rounds up
- old: RS5-21 · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-11 · superseded-by: —

**Why.** The DEX fee per fill rounds up, so many small fills cannot evade the fee by rounding.
**Cost if wrong.** Round-down lets dust fills trade fee-free.
**Source.** `history/specs/2026-10-03-dex-design.md:455`

### CTR-DEX-12 — Managed market venue contract and arbiter
- old: R214(contract) · status: current · owner: yes · date: 2026-10-06 · normative: contracts/dex.md#CTR-DEX-12 · superseded-by: —

**Why.** A managed market is a venue contract with an arbiter for regulated assets; ordinary markets stay permissionless.
**Cost if wrong.** Mixing managed rules into the open DEX would gate everyone.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:176`

### CTR-DEX-80 — Fill-or-kill two-leg MetaTxDex settlement
- old: R3 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-01, NODE-DEX-01, INT-ERP-12

**What it said.** The first design settled two `MetaTxDex` legs fill-or-kill.

### CTR-DEX-81 — DEX fee on received side rounds down
- old: RS5-6(dex-fee) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-11

**What it said.** An earlier rule rounded the DEX fee on the received side down.

## Sealed-bid tender

### CTR-TND-01 — Deposit and commitment are one pay signature
- old: R180 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-01 · superseded-by: —

**Why.** The deposit and the bid commitment are one pay signature, so a bidder cannot commit without paying the deposit.
**Cost if wrong.** Separate steps let a bidder commit and never deposit.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:62`

### CTR-TND-02 — Commitment hash binds chain, tender and bidder
- old: R181 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-02 · superseded-by: —

**Why.** The commitment hash binds chain, tender and bidder, so it cannot be copied to another tender or bidder.
**Cost if wrong.** An unbound commitment could be replayed by another bidder.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:70`

### CTR-TND-03 — Permissionless reveal and withdraw; no bid replacement
- old: R182 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-03 · superseded-by: —

**Why.** Reveal and withdraw are permissionless and bids cannot be replaced, so nobody depends on the organizer to finish.
**Cost if wrong.** Organizer-only reveal lets the organizer suppress bids.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:76`

### CTR-TND-04 — Forfeited deposits go to immutable slashSink
- old: R183 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-04 · superseded-by: —

**Why.** Forfeited deposits go to an immutable `slashSink`, so the organizer cannot profit from disqualifying bidders.
**Cost if wrong.** A mutable sink rewards fake disqualification.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:82`

### CTR-TND-05 — Public price range; earliest commit wins ties
- old: R184 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-05 · superseded-by: —

**Why.** A public price range and earliest-commit tie-break make the winner deterministic from on-chain data.
**Cost if wrong.** Hidden ranges or discretionary ties invite manipulation.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:87`

### CTR-TND-06 — Early cancel only; bounded leader disqualification
- old: R185 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-06 · superseded-by: —

**Why.** The organizer may cancel only early and disqualify the leader only within bounds, so a tender cannot be steered after reveal.
**Cost if wrong.** Unbounded disqualification is a veto over the result.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:92`

### CTR-TND-07 — Deposit token from a registered factory implementation
- old: R186 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-07 · superseded-by: —

**Why.** The deposit token must come from a registered factory implementation, so its transfer semantics are known.
**Cost if wrong.** An arbitrary token could block refunds or fake deposits.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:107`

### CTR-TND-08 — Fixed windows, bond policies, no admin
- old: R187 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-08 · superseded-by: —

**Why.** Fixed windows and bond policies with no admin make the timeline enforceable by anyone.
**Cost if wrong.** An admin-adjustable window can be bent for a favoured bidder.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:114`

## Asset suite

### CTR-AS-01 — Regulated module as separate implementations, kinds 5-7
- old: R200 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-01 · superseded-by: —

**Why.** Regulated behaviour ships as separate implementations (kinds 5–7), so plain tokens never carry compliance powers.
**Cost if wrong.** Optional compliance flags inside plain tokens would make every token potentially regulated.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:69`

### CTR-AS-02 — Regulated module is a third creation-time exception
- old: R201 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-02 · superseded-by: —

**Why.** The regulated module is a third creation-time exception, visible before anyone acquires the token.
**Cost if wrong.** Adding it later would break the provenance promise.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:80`

### CTR-AS-03 — Issuer and compliance roles; renouncing relaxes
- old: R202 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-03 · superseded-by: —

**Why.** Issuer and compliance roles are separate; renouncing a role only relaxes control.
**Cost if wrong.** One combined role would concentrate every power in one key.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:87`

### CTR-AS-04 — Forced transfer only against a recorded order
- old: R203 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-04 · superseded-by: —

**Why.** A forced transfer requires a recorded order, so it leaves an auditable reason on chain.
**Cost if wrong.** Unrecorded forced transfers are indistinguishable from theft.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:94`

### CTR-AS-05 — Freeze semantics and bounded freeze duration
- old: R204 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-05 · superseded-by: —

**Why.** Freezes have defined semantics and a bounded duration, so a freeze is not a silent confiscation.
**Cost if wrong.** Unbounded freezes are de facto seizures.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:102`

### CTR-AS-06 — Global pause up to 7 days with cooldown
- old: R205 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-06 · superseded-by: —

**Why.** A global pause lasts at most 7 days with a cooldown, so it cannot become a permanent lock.
**Cost if wrong.** Unbounded pauses trap holders indefinitely.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:111`

### CTR-AS-07 — Allowlist through ComplianceRegistry, receivers only
- old: R206 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-07 · superseded-by: —

**Why.** Allowlisting runs through the address-keyed `ComplianceRegistry` and checks receivers only, so holders can always exit to an allowed address.
**Cost if wrong.** Checking senders too could trap holders who lost status.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:118`

### CTR-AS-08 — Regulated checks at step 6 and in _update
- old: R207 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-08 · superseded-by: —

**Why.** Regulated checks sit at pipeline step 6 and in `_update`, so every path (direct and meta-tx) is covered.
**Cost if wrong.** A check in one path only is bypassed through the other.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:126`

### CTR-AS-09 — No regulated power touches reserves, rates or legs
- old: R208 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-09 · superseded-by: —

**Why.** No regulated power touches reserves, rates or legs, so compliance cannot be used to move backing value.
**Cost if wrong.** Compliance roles over reserves would be custody.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:138`

### CTR-AS-10 — One counterfactual VestingGrant clone per grant
- old: R209 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-10 · superseded-by: —

**Why.** One counterfactual `VestingGrant` clone per grant isolates grants and gives each a predictable address.
**Cost if wrong.** A shared vesting pool mixes beneficiaries' risks.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:145`

### CTR-AS-11 — Merkle distributions from a node-indexed snapshot
- old: R210 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-11 · superseded-by: —

**Why.** Distributions are Merkle claims from a node-indexed snapshot, so gas scales with claimants, not holders.
**Cost if wrong.** On-chain iteration over holders does not scale and can be griefed.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:155`

### CTR-AS-12 — Splits are migrations through ExchangeOffer
- old: R211 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-12 · superseded-by: —

**Why.** Splits are migrations through `ExchangeOffer`, so no token ever rebases.
**Cost if wrong.** Rebasing breaks integrations and 1:1 reserves.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:162`

### CTR-AS-13 — ExchangeOffer exact multiples and protected obligations
- old: R212 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-13 · superseded-by: —

**Why.** `ExchangeOffer` uses exact multiples and protects outstanding obligations, so a migration never strands value.
**Cost if wrong.** Inexact ratios leave dust and disputes.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:167`

### CTR-AS-14 — Asset templates are off-chain presets
- old: R213 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-14 · superseded-by: —

**Why.** Asset templates are off-chain presets over the same implementations, so adding a template needs no contract change.
**Cost if wrong.** On-chain templates would need upgradeable code or new audits per template.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:173`

### CTR-AS-15 — Action contracts have no owner or upgrade
- old: R216 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-15 · superseded-by: —

**Why.** Action contracts have no owner and no upgrade.
**Cost if wrong.** An owner on an action contract is a backdoor over the assets it holds.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:187`

### CTR-AS-16 — ELIGIBLE_CONTRACT only on pass-through contracts
- old: R217 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-16 · superseded-by: —

**Why.** `ELIGIBLE_CONTRACT` is granted only to pass-through contracts, so allowlisting a contract cannot launder transfers to ineligible holders.
**Cost if wrong.** Eligible contracts that hold and release value would bypass the receiver check.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:193`

## Zether (classical)

### CTR-ZTH-01 — Full classical Zether, unaudited, dev-chain gated
- old: R34(scope), UD:§12, UD:§12.2, UD:§12.3, UD:§12.4, UD:§12.7.6, UD:§15:D2, UD:§19:curve-param, UD:§20.1, UD:§25, UD:§25:flipped, UD:§25:ruling, canon:D1, canon:D2, canon:D17 · status: current · owner: yes · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-01 · superseded-by: —

**Why.** The owner wants full classical Zether now (identity visible, amounts hidden), built, unaudited and gated to dev chains, with bn254 and BLS12-381 verifiers. The curve is a property of each token (chosen by its verifier address), not a system setting: bn254 uses the Byzantium (2017) precompiles 0x06/0x07/0x08 with 64-byte G1 points; BLS12-381 needs the Prague precompiles 0x0b to 0x10 and 128-byte G1 points (measured with `eth_call` to 0x0b on Gnosis). rollOver is `PUBLIC` by default and `OWNER_ONLY` by opt-in, per `(account, token)`: owner signing protects only if it covers every path that advances the account sequence, so per account `accSeq[a]` advances without the owner's consent exactly when `mode[a] == PUBLIC`. The `PUBLIC` branch is safe because rollOver is a no-op when `pendingSeq[a] == lastRolledPendingSeq[a]`, so a griefer must fund the victim before each attempt.
**Cost if wrong.** Unaudited cryptography on a public chain could mint; the gate (CTR-ZTH-02) is what prevents that.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:546`, `research/_USER-DECISIONS.md:463`, `research/_USER-DECISIONS.md:483`, `research/_USER-DECISIONS.md:508`, `research/_USER-DECISIONS.md:537`, `research/_USER-DECISIONS.md:691`, `research/_USER-DECISIONS.md:860`, `research/_USER-DECISIONS.md:1060`, `research/_USER-DECISIONS.md:1093`, `research/_USER-DECISIONS.md:2630`, `research/_USER-DECISIONS.md:2638`, `research/_USER-DECISIONS.md:2653`, `research/_USER-DECISIONS.md:859`, `research/_USER-DECISIONS.md:864`

### CTR-ZTH-02 — Classical Zether gated to dev chains 31337/1337
- old: RS2-1 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-02 · superseded-by: —

**Why.** A hard-coded dev-chain allowlist in every constructor keeps unaudited Zether off real networks even with a manual deploy.
**Cost if wrong.** A configurable gate is one transaction away from production use.
**Source.** `history/specs/2026-10-03-zether-design.md:583`

### CTR-ZTH-03 — No epochs; verifier takes the full statement
- old: RS2-2 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-03 · superseded-by: —

**Why.** Proofs take the full statement and there are no epochs, removing epoch-boundary races. Rejected: the early `IZetherToken` sketch with epoch-based `simulateAccounts`, `getPendingBalance` per epoch and an epoch `rollOver()`.
**Cost if wrong.** Epochs force retries at boundaries and couple liveness to block timing.
**Source.** `history/specs/2026-10-03-zether-design.md:586`

### CTR-ZTH-04 — shieldScale is raw units per shielded unit
- old: RS2-3, UD:§2 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-04 · superseded-by: —

**Why.** `shieldScale` is raw underlying units per shielded unit, a single integer that keeps the 2^54 bound meaningful for any decimals. The bound exists because the amount is exponential ElGamal: the key only strips the mask (`C / D^x = g^b`), and getting `b` back from `g^b` is a discrete log that BSGS solves in `O(sqrt(b))` steps; the contract only ever returns ciphertext and never holds `x`. The bound bites only in cold recovery: in daily use the client knows the previous balance and solves only the difference. 2^44 is the last BSGS table size that fits a phone; `2^48` is blocked by memory, not time (Pollard kangaroo removes the memory wall at 2 to 4 times the time). Raising `shieldScale` is cheaper than buying bits and costs only granularity.
**Cost if wrong.** Scaling by decimals inside the circuit would add rounding paths.
**Source.** `history/specs/2026-10-03-zether-design.md:588`, `research/_USER-DECISIONS.md:49`

### CTR-ZTH-05 — Inner fee to beneficiary pending; outer fee public
- old: RS2-4, UD:§10:fee-layers · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-05 · superseded-by: —

**Why.** Two fee layers: an inner confidential fee to a beneficiary's pending balance and an outer public fee for the relayer. A holder whose money is all confidential has no public token to pay an outer fee; the inner fee (`C_fee`, debited from the encrypted balance) is the only way such an account can pay a relayer. Fee first, amount second: the proof shows `fee >= 0`, `v >= 0`, `b - fee >= 0` and `(b - fee) - v >= 0` together.
**Cost if wrong.** One fee layer would either leak the amount or leave relayers unpaid.
**Source.** `history/specs/2026-10-03-zether-design.md:590`, `research/_USER-DECISIONS.md:351`

### CTR-ZTH-06 — Envelope binding covers envelope fields except data
- old: RS2-5 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-06 · superseded-by: —

**Why.** The envelope binding covers every envelope field except `data`, so a proof cannot be stripped or re-wrapped.
**Cost if wrong.** An unbound proof can be lifted into another envelope with another fee recipient.
**Source.** `history/specs/2026-10-03-zether-design.md:592`

### CTR-ZTH-07 — Outer FIXED fee uncapped; PERCENT forbidden
- old: RS2-6, UD:§3, UD:§3.2, UD:§3.4 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-07 · superseded-by: —

**Why.** Confidential ops take only an absolute FIXED outer fee; PERCENT would reveal the amount through the fee.
**Cost if wrong.** A percentage fee on a hidden amount is an amount oracle.
**Source.** `history/specs/2026-10-03-zether-design.md:594`, `research/_USER-DECISIONS.md:102`, `research/_USER-DECISIONS.md:124`, `research/_USER-DECISIONS.md:164`

### CTR-ZTH-08 — Separate ZetherMetaTx mixin; v1 sources untouched
- old: RS2-7, UD:§10 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-08 · superseded-by: —

**Why.** A separate `ZetherMetaTx` mixin reuses `MetaTxLib` read-only, so v1 token sources stay untouched. Zether is a child of the meta-transaction layer, so every confidential token is gasless too; an early code draft declared `ISecureERC20 is IERC20`, which would have left confidential tokens without meta-transactions. Rejected: the early `IZetherToken` interface sketch (`schnorrAddress`, `zetherNonce`, `EncryptedBalance` structs, `transferConfidential` with a `metaTx.amount = 0` wrapper) — replaced by the built `IZetherToken` and the envelope ops.
**Cost if wrong.** Editing the v1 sources would invalidate their tests and audits.
**Source.** `history/specs/2026-10-03-zether-design.md:595`, `research/_USER-DECISIONS.md:331`

### CTR-ZTH-09 — Auditor key immutable, set at initialize
- old: RS2-8 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-09 · superseded-by: —

**Why.** The auditor key is immutable and set at `initialize`; there is no setter.
**Cost if wrong.** A settable auditor key would let an admin start reading every future transfer.
**Source.** `history/specs/2026-10-03-zether-design.md:596`

### CTR-ZTH-10 — Underlying must be an ERC-20 in v1
- old: RS2-11 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-10 · superseded-by: —

**Why.** The underlying must be an ERC-20 in v1; native coins and self-minted supply add paths the proofs do not cover.
**Cost if wrong.** Native-coin handling would add reentrancy and accounting paths.
**Source.** `history/specs/2026-10-03-zether-design.md:600`

### CTR-ZTH-11 — fund and rollOver direct; transfer/burn enveloped
- old: RS2-12 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-11 · superseded-by: —

**Why.** `fund` and `rollOver*` are direct calls; only transfer and burn travel in envelopes.
**Cost if wrong.** Enveloping public ops adds cost with no privacy gain.
**Source.** `history/specs/2026-10-03-zether-design.md:601`

### CTR-ZTH-12 — No AEAD memo; client decrypts by BSGS
- old: RS2-13 · status: current · owner: no · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-12 · superseded-by: —

**Why.** No AEAD memo: the client decrypts balances itself with BSGS, so no extra ciphertext format needs securing.
**Cost if wrong.** A memo would be a second encryption to audit and key-manage.
**Source.** `history/specs/2026-10-03-zether-design.md:603`

### CTR-ZTH-13 — Direct transferConfidential carries no outer fee
- old: RS2-14 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-13 · superseded-by: —

**Why.** A direct confidential transfer carries no outer fee; the caller pays its own gas.
**Cost if wrong.** An outer fee on direct calls would need an unbound recipient.
**Source.** `history/specs/2026-10-03-zether-design.md:605`

### CTR-ZTH-14 — Disclosure bundle stored; fee-on-transfer underlyings refused
- old: RS2-15, ZL:D6 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-14 · superseded-by: —

**Why.** The disclosure bundle is stored per transfer so the parties can prove amounts later; fee-on-transfer underlyings are refused.
**Cost if wrong.** Without the bundle disclosures depend on off-chain archives; FoT underlyings break the escrow invariant.
**Source.** `history/specs/2026-10-03-zether-design.md:607`, `history/specs/2026-10-05-zether-limits.md:18`

### CTR-ZTH-15 — Verifier forwards gas to precompiles; simulate first
- old: RS2-16 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-15 · superseded-by: —

**Why.** The verifier forwards `gas()` to the precompiles and clients simulate first, so a precompile repricing does not silently fail proofs.
**Cost if wrong.** Pinned gas stipends break when precompile prices change.
**Source.** `history/specs/2026-10-03-zether-design.md:609`

### CTR-ZTH-16 — rollOverSigned accepts pendingSeq at least expected
- old: RS2-17 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-16 · superseded-by: —

**Why.** `rollOverSigned` accepts `pendingSeq` at least the expected value, so a free public rollover in between does not invalidate a signed one.
**Cost if wrong.** An equality check lets anyone grief signed rollovers.
**Source.** `history/specs/2026-10-03-zether-design.md:612`

### CTR-ZTH-17 — rollOverSigned requires a new credit
- old: RS2-19 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-17 · superseded-by: —

**Why.** `rollOverSigned` requires a new credit, so it cannot be replayed to no effect.
**Cost if wrong.** Replays would burn the owner's relayer fees.
**Source.** `history/specs/2026-10-03-zether-design.md:614`

### CTR-ZTH-18 — Range bits n_v = n_b = 64, sound
- old: RS-NV64-1, ZL:D1, ZL:D2 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-18 · superseded-by: —

**Why.** Range bits `n_v = n_b = 64` are sound with the 2^54 cap; every honest value fits and no wrap-around is provable.
**Cost if wrong.** Fewer bits would reject honest balances; an unsound pair would allow minting.
**Source.** `history/specs/2026-10-03-zether-design.md:623`, `history/specs/2026-10-05-zether-limits.md:13`, `history/specs/2026-10-05-zether-limits.md:14`

### CTR-ZTH-19 — Configurable client BSGS plus device balance cache
- old: RS-NV64-2, ZL:D4, ZL:D5 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-19 · superseded-by: —

**Why.** Client BSGS is configurable and a device balance cache avoids repeated discrete logs.
**Cost if wrong.** A fixed BSGS table either wastes memory or fails on large balances.
**Source.** `history/specs/2026-10-03-zether-design.md:644`, `history/specs/2026-10-05-zether-limits.md:16`, `history/specs/2026-10-05-zether-limits.md:17`

### CTR-ZTH-20 — Clients and gateway pin canonical verifier and registry
- old: RS2-20 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-20 · superseded-by: —

**Why.** Clients and the gateway pin the verifier and registry addresses per chain profile.
**Cost if wrong.** A spoofed verifier address would accept forged proofs in the client's view.
**Source.** `history/specs/2026-10-03-zether-design.md:661`

### CTR-ZTH-21 — ZetherMetaTx ERC-1271 gas cap by codehash
- old: RS2-21 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-21 · superseded-by: —

**Why.** `ZetherMetaTx` applies the same codehash-based ERC-1271 cap as `MetaToken`.
**Cost if wrong.** An uncapped check lets contract wallets grief relayers.
**Source.** `history/specs/2026-10-03-zether-design.md:664`

### CTR-ZTH-22 — Mandatory invariant, subgroup and D_out tests
- old: RS2-23 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-22 · superseded-by: —

**Why.** Invariant, subgroup and `D_out` tests are mandatory before any gate is lifted.
**Cost if wrong.** Missing subgroup tests have broken real Zether-like systems.
**Source.** `history/specs/2026-10-03-zether-design.md:670`

### CTR-ZTH-23 — Outer fee recipient equal to token reverts
- old: RS2-24 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-23 · superseded-by: —

**Why.** An outer fee recipient equal to the token reverts, so fees cannot be locked in the token.
**Cost if wrong.** Fees sent to the token are stuck forever.
**Source.** `history/specs/2026-10-03-zether-design.md:675`

### CTR-ZTH-24 — Client balance-cache key includes the chain
- old: RS2-25 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-24 · superseded-by: —

**Why.** The client balance-cache key includes the chain, so two chains with the same token address do not mix balances.
**Cost if wrong.** A shared cache shows wrong balances after a chain switch.
**Source.** `history/specs/2026-10-03-zether-design.md:676`

### CTR-ZTH-25 — Public schnorrSign export takes no nonce k
- old: RS2-26 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-25 · superseded-by: —

**Why.** The public `schnorrSign` export takes no nonce `k`, so callers cannot reuse nonces.
**Cost if wrong.** A caller-supplied nonce reused twice leaks the key.
**Source.** `history/specs/2026-10-03-zether-design.md:678`

### CTR-ZTH-26 — MAX_TOTAL_SHIELDED stays 2^54
- old: ZL:D3 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-26 · superseded-by: —

**Why.** `MAX_TOTAL_SHIELDED` stays 2^54: it is the BSGS decryption bound, not a per-transfer maximum.
**Cost if wrong.** Raising it makes client decryption impractical.
**Source.** `history/specs/2026-10-05-zether-limits.md:15`

### CTR-ZTH-27 — Zether runs on the private chain first
- old: UD:§1:private-chain · status: open · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-27 · superseded-by: —

**Why.** Open owner decision: whether classical Zether runs on the private chain first.
**Cost if wrong.** Deciding without the audit and gas data could put unaudited cryptography on a shared chain.
**Source.** `research/_USER-DECISIONS.md:42`

### CTR-ZTH-28 — Tiered Zether fees leak the amount
- old: UD:§3.3 · status: open · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-28 · superseded-by: —

**Why.** Open owner decision: a tiered Zether fee leaks the amount band; only flat fees are safe today.
**Cost if wrong.** A tiered fee turns the fee into an amount oracle.
**Source.** `research/_USER-DECISIONS.md:149`

### CTR-ZTH-29 — Independent open-source disclosure verifier CLI
- old: UD:§12.7.5 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-29 · superseded-by: —

**Why.** An independent open-source disclosure verifier lets any counterparty check a disclosure without trusting SCaaS. It reads from an archive node or a signed chain export, takes `(entryRef, v, s)` and prints PASS or FAIL with every intermediate value; it is deterministic, so two examiners get the same result.
**Cost if wrong.** Disclosure checked only by SCaaS tools is trust in SCaaS.
**Source.** `research/_USER-DECISIONS.md:676`

### CTR-ZTH-30 — Derive s from seed via PRF
- old: UD:§13.2 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-30 · superseded-by: —

**Why.** The sender randomness `s` is derived from the seed by a PRF, so nothing per transfer needs storing. The research sketch was s = HKDF-SHA256(seed_zether, info = "ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter) with the `sendCounter` read from the chain, so a wallet restored from its seed alone can still prove every past transfer.
**Cost if wrong.** Stored randomness is one more secret to lose or leak.
**Source.** `research/_USER-DECISIONS.md:727`

### CTR-ZTH-31 — Fallback: accept stale accSeq for credits only
- old: UD:§25:fallback · status: open · owner: yes · date: 2026-09-03 · normative: contracts/zether.md#CTR-ZTH-31 · superseded-by: —

**Why.** Open owner contingency: if rollover griefing spreads, accept a stale `accSeq` for credits only (a credit only raises the balance, so the range statement does not weaken); that is a protocol change and needs the cryptography review. The immediate escape hatch for one account is `setRollOverMode(OWNER_ONLY)`, one transaction; epochs are not the fallback.
**Cost if wrong.** Without a fallback a griefer could keep a busy account from spending.
**Source.** `research/_USER-DECISIONS.md:2688`

### CTR-ZTH-32 — Production curve for classical Zether tokens
- old: reorg:Q5(curve) · status: open · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-32 · superseded-by: —

**Why.** Open owner decision: the production curve for classical Zether (bn254 or BLS12-381); BLS12-381 is more secure and not cheaper.
**Cost if wrong.** Choosing bn254 for money at rest accepts ~100-bit security.
**Source.** `superpowers/plans/2026-10-07-docs-reorg.md:1219`

### CTR-ZTH-33 — Chain 7622 is not a classical-Zether dev chain
- old: reorg:Q5(dev-chain) · status: open · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-33 · superseded-by: —

**Why.** Open owner decision: chain 7622 is not a classical-Zether dev chain until the owner decides.
**Cost if wrong.** Treating it as dev would put unaudited classical Zether on the shared private chain.
**Source.** `superpowers/plans/2026-10-07-docs-reorg.md:1219`

### CTR-ZTH-80 — Range bits 32 and DECRYPT_BOUND 2^40
- old: R34(params) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-ZTH-18, CTR-ZTH-19

**What it said.** An earlier ruling used range bits 32 and a decryption bound of 2^40.

### CTR-ZTH-81 — Zether registry with eight auth schemes and PoP
- old: R34(registry) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-02, CTR-UA-16, CTR-UA-22

**What it said.** The built Zether-only registry with eight auth schemes and a PoP bound to `msg.sender` (Transitional, BUILT on dev chains; replaced by the UA registry).

### CTR-ZTH-82 — PQ_COMMITMENT verified like SELF_SCHNORR
- old: RS2-10 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-23, CTR-UA-16

**What it said.** An earlier rule verified `PQ_COMMITMENT` exactly like `SELF_SCHNORR`.

### CTR-ZTH-83 — Built registry PoP does not bind authority
- old: RS2-22 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: CTR-UA-07

**What it said.** A note that the built registry PoP does not bind an authority.

### CTR-ZTH-84 — Permissionless rollOver proposed as D17
- old: UD:§12.7.3 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A proposal for permissionless rollOver as a separate decision.

### CTR-ZTH-85 — SDK must store every s
- old: UD:§12.7.4 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-30

**What it said.** A proposal that the SDK store every sender randomness `s`.

### CTR-ZTH-86 — Implicit rollOver open to everyone
- old: UD:§13.3 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A proposal for implicit rollOver open to everyone.

### CTR-ZTH-87 — Curve D1 = BLS12-381 after preflight
- old: UD:§14 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to BLS12-381 after a preflight.

### CTR-ZTH-88 — D1 and D2 settled on BLS12-381
- old: UD:§14:consequences · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling settling two curve decisions on BLS12-381.

### CTR-ZTH-89 — Curve D1 = bls12_381
- old: UD:§15:D1 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to bls12_381.

### CTR-ZTH-90 — Keep implicit rollOver plus public entry points
- old: UD:§15:D17 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling keeping implicit rollOver plus public entry points.

### CTR-ZTH-91 — Curve D1 = bn254 for the private phase
- old: UD:§19 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to bn254 for the private phase.

### CTR-ZTH-92 — Keep bn254 verifiers and chain 9000 as is
- old: UD:§19:unlocked · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01, NET-EVM-02

**What it said.** A ruling keeping the bn254 verifiers and the private chain unchanged.

### CTR-ZTH-93 — When to reopen the curve decision
- old: UD:§19:reopen-conditions · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** Conditions under which the curve decision would reopen.

## Universal Account

### CTR-UA-01 — Refuse BLS keys and signatures at infinity
- old: RS2-18 · status: current · owner: no · date: 2026-10-03 · normative: contracts/universal-account.md#CTR-UA-01 · superseded-by: —

**Why.** BLS keys and signatures at infinity make the pairing trivial; refusing them prevents a fake BLS custody that lets `x` alone spend.
**Cost if wrong.** Accepting infinity lets anyone pass a BLS check.
**Source.** `history/specs/2026-10-03-zether-design.md:618`

### CTR-UA-02 — UA is a key-derived identifier, not a contract
- old: R290 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-02 · superseded-by: —

**Why.** A UA is an identifier derived from key data, like an EOA for every scheme: free, deterministic, the same on every chain, with nothing to deploy.
**Cost if wrong.** A contract per account costs a deploy per user per chain and is upgradeable state.
**Source.** `history/specs/2026-10-06-universal-account-design.md:93`

### CTR-UA-03 — 32-byte kind-tagged ids in canonical form
- old: R291 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-03 · superseded-by: —

**Why.** 32-byte kind-tagged ids never collide with 20-byte native ids; a 20-byte truncation would allow a 2^80 grind between an EOA and a multisig policy.
**Cost if wrong.** 12 more calldata bytes per id (192 gas).
**Source.** `history/specs/2026-10-06-universal-account-design.md:100`

### CTR-UA-04 — keccak256 for ids in every family
- old: R292 · status: current · owner: no · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-04 · superseded-by: —

**Why.** One hash (keccak256) with native support in every family gives the same id on every chain.
**Cost if wrong.** Different hashes per family would give different ids for one key.
**Source.** `history/specs/2026-10-06-universal-account-design.md:113`

### CTR-UA-05 — Fixed kind table per registry generation
- old: R293 · status: current · owner: no · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-05 · superseded-by: —

**Why.** The kind table is fixed per registry generation; a mutable table would be an admin key over every account.
**Cost if wrong.** New schemes wait for a new generation and new token implementations.
**Source.** `history/specs/2026-10-06-universal-account-design.md:117`

### CTR-UA-06 — Native kinds unregistered; derived kinds register first
- old: R294 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-06 · superseded-by: —

**Why.** Native kinds need no registration; derived kinds register once per chain, which is where PoP and one-key-one-purpose are enforced and typos revert.
**Cost if wrong.** One registration per chain (~75 k gas on bn254).
**Source.** `history/specs/2026-10-06-universal-account-design.md:125`

### CTR-UA-07 — PoP binds chain, registry, UA and authRef
- old: R295, UA:Q10 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-07 · superseded-by: —

**Why.** Every record field follows from signed data (PoP over chain, registry, UA and `authRef`; the authority co-signs), so registration is relayable and front-running yields the same record or a revert.
**Cost if wrong.** A field taken from `msg.sender` or left unsigned would turn front-running into capture.
**Source.** `history/specs/2026-10-06-universal-account-design.md:133`, `history/specs/2026-10-06-universal-account-design.md:1407`

### CTR-UA-08 — Rogue-key defence chosen per aggregate kind
- old: R296, UA:Q3 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-08 · superseded-by: —

**Why.** Each aggregate kind uses its native rogue-key defence, checked on chain: per-member PoP for `msig`, KeyAgg for MuSig2, DKG PoKs for FROST.
**Cost if wrong.** Off-chain facts (share distribution, distinct parties) stay attestation-only and must be shown as such.
**Source.** `history/specs/2026-10-06-universal-account-design.md:148`, `history/specs/2026-10-06-universal-account-design.md:1391`

### CTR-UA-09 — Structures commit to members; one nesting level
- old: R297 · status: current · owner: no · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-09 · superseded-by: —

**Why.** Structures commit to sorted members and nest one level, which bounds gas and avoids cycles.
**Cost if wrong.** Two-level governance uses `SubjectAccount` or Safe as a member.
**Source.** `history/specs/2026-10-06-universal-account-design.md:159`

### CTR-UA-10 — One key one purpose: registry, tags, EOAs
- old: R298(2-3-4) · status: current · owner: yes · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-10 · superseded-by: —

**Why.** One key = one purpose in four layers (derivation, registry `keyOwner`, tagged messages, EOA rules) prevents cross-scheme nonce leaks and signing oracles.
**Cost if wrong.** A foreign wallet reusing an EOA key for `bip340` remains undetectable on chain.
**Source.** `history/specs/2026-10-06-universal-account-design.md:166`

### CTR-UA-11 — keyHash per curve group, not per kind
- old: R299 · status: current · owner: no · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-11 · superseded-by: —

**Why.** `keyHash` per curve group makes all kinds over one group share a namespace, so the same key cannot register under two kinds.
**Cost if wrong.** A per-kind keyHash allows the same key under two kinds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:173`

### CTR-UA-12 — Tagged message for every derived-UA signature
- old: R301 · status: current · owner: no · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-12 · superseded-by: —

**Why.** Every derived-UA signature is over a tagged message with kind and purpose, so cross-kind and cross-purpose replay die at the hash; native signers sign EIP-712 `UAAuth`, never a raw hash.
**Cost if wrong.** One extra keccak (~60 gas).
**Source.** `history/specs/2026-10-06-universal-account-design.md:188`

### CTR-UA-13 — No key rotation inside a UA
- old: R302, RS2-9, UA:Q1 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-13 · superseded-by: —

**Why.** A UA is immutable: new key data is a new UA; rotation moves funds. A rotatable policy kind was rejected for v1 because it brings back an admin-like mutable record.
**Cost if wrong.** Membership changes of a corporate `msig` require moving funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:202`, `history/specs/2026-10-03-zether-design.md:597`, `history/specs/2026-10-06-universal-account-design.md:1385`

### CTR-UA-14 — Each function accepts only the kinds it needs
- old: R303, UA:Q4, UA:Q5, UA:Q7 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-14 · superseded-by: —

**Why.** Each function accepts exactly the kinds it needs; native-address functions keep their ABIs and Zether UAs can neither receive on v3 nor sign through `requireAuthorized`.
**Cost if wrong.** UA holders need v3 tokens; deployed v1/v2 clones stay native-only.
**Source.** `history/specs/2026-10-06-universal-account-design.md:207`, `history/specs/2026-10-06-universal-account-design.md:1394`, `history/specs/2026-10-06-universal-account-design.md:1396`, `history/specs/2026-10-06-universal-account-design.md:1400`

### CTR-UA-15 — Registry is monotonic and admin-free
- old: R304 · status: current · owner: no · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-15 · superseded-by: —

**Why.** A monotonic, admin-free registry lets tokens rely on a record forever and nobody can repoint a key. Rejected: the early shared-registry sketch (`SchnorrPublicKey {x, y}`, `register(x, y, sig)`, `schnorrAddress = keccak256(abi.encodePacked(x, y))`) — corrected to kind-tagged ids, a PoP with domain tag, chain and registry, on-curve and subgroup checks, and no upgrade path.
**Cost if wrong.** A compromised derived key is handled like a compromised EOA: move funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:215`

### CTR-UA-16 — Zether kinds bind encryption key; immutable authRef
- old: R305, UA:Q2 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-16 · superseded-by: —

**Why.** Zether kinds bind only the encryption key; authorization is an immutable `authRef` (self, native or SIGNING UA), so spend authority stays separate from decryption.
**Cost if wrong.** `authRef` cannot rotate; a timelocked rotation was rejected.
**Source.** `history/specs/2026-10-06-universal-account-design.md:219`, `history/specs/2026-10-06-universal-account-design.md:1389`

### CTR-UA-17 — Verify through registry; large keys stored once
- old: R306 · status: current · owner: no · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-17 · superseded-by: —

**Why.** The registry does lookup and check in one call; small keys travel in calldata, large keys (PQ, MuSig2/FROST group keys) are stored once.
**Cost if wrong.** No token-side cache in v1: one cold call (~2.6 k) per check.
**Source.** `history/specs/2026-10-06-universal-account-design.md:229`

### CTR-UA-18 — Derived-UA balances in a separate bytes32 ledger
- old: R308 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-18 · superseded-by: —

**Why.** Derived-UA balances live in a separate `bytes32` ledger shown to ERC-20 tools as the `UA_POOL` sub-ledger, keeping `Transfer` replay equal to `balanceOf`.
**Cost if wrong.** Naive indexers see one large `UA_POOL` holder.
**Source.** `history/specs/2026-10-06-universal-account-design.md:243`

### CTR-UA-19 — UAMetaTransaction has its own typehash
- old: R309, UA:Q11 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-19 · superseded-by: —

**Why.** `UAMetaTransaction` has its own struct and typehash because `from` is `bytes32`; this is not a second hash of the same struct.
**Cost if wrong.** Clients build two struct shapes.
**Source.** `history/specs/2026-10-06-universal-account-design.md:255`, `history/specs/2026-10-06-universal-account-design.md:1410`

### CTR-UA-20 — Optional VC layer; on-chain anchor deferred
- old: R310 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-20 · superseded-by: —

**Why.** The credential layer is optional; contracts consume only `ComplianceRegistry` flags. The on-chain anchor is deferred because nothing reads it and it would leak metadata.
**Cost if wrong.** No public holder/issuer co-statement in v1; the evidence bundle carries it privately.
**Source.** `history/specs/2026-10-06-universal-account-design.md:264`

### CTR-UA-21 — Holder binding by account-signed presentation
- old: R311, UA:Q14 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-21 · superseded-by: —

**Why.** Holder binding is a presentation signed by the account under purpose `vp` (SD-JWT VC + KB-JWT `alg: scaas-ua`), ideally by a dedicated identity UA.
**Cost if wrong.** External SD-JWT verifiers accept these presentations only if they implement `scaas-ua`.
**Source.** `history/specs/2026-10-06-universal-account-design.md:271`, `history/specs/2026-10-06-universal-account-design.md:1415`

### CTR-UA-22 — Breaking dev-only migration from Zether registry
- old: R312 · status: current · owner: no · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-22 · superseded-by: —

**Why.** Migration from the built Zether registry is breaking and dev-only: the old registry and `AuthScheme` are deleted, Zether accounts re-register.
**Cost if wrong.** Dev balances are recreated by scripts; no production data exists.
**Source.** `history/specs/2026-10-06-universal-account-design.md:278`

### CTR-UA-23 — PQ and ed25519 kinds on every EVM chain
- old: R313, UA:Q9 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-23 · superseded-by: —

**Why.** PQ signing kinds and ed25519 are enabled on every EVM chain (owner), verified by precompile where probed or pure Solidity, each within a measured per-chain cap; an over-budget kind is disabled, never registrable-but-unusable.
**Cost if wrong.** PQ checks cost real money on public L1s (≈ $36–240 per ML-DSA-65 check at 10 gwei).
**Source.** `history/specs/2026-10-06-universal-account-design.md:281`, `history/specs/2026-10-06-universal-account-design.md:1404`

### CTR-UA-24 — EIP-7702 EOAs are native; classify by code
- old: R331 · status: current · owner: no · date: 2026-10-07 · normative: contracts/universal-account.md#CTR-UA-24 · superseded-by: —

**Why.** An EIP-7702 delegated EOA keeps its base key as root, so ECDSA is accepted and ERC-1271 through the delegate is a fallback; classification is by code at verify time.
**Cost if wrong.** If a future EIP lets 7702 accounts disable the base key, a new registry generation must follow it.
**Source.** `history/specs/2026-10-06-universal-account-design.md:355`

### CTR-UA-25 — No on-chain registration gate in v1
- old: UA:Q8 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/universal-account.md#CTR-UA-25 · superseded-by: —

**Why.** No on-chain registration gate in v1: node sponsorship limits bound spam; self-paid spam pays its own gas.
**Cost if wrong.** An immutable `IRegistrationPolicy` per generation is the fallback if spam becomes a problem.
**Source.** `history/specs/2026-10-06-universal-account-design.md:1402`

## Post-quantum Zether

### CTR-PQZ-01 — Separate PQZ class gated to private chains
- old: R270 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-01 · superseded-by: —

**Why.** PQZ is a separate token class gated by a hard-coded allowlist, a constructor precompile self-test and the registry `chain_uid`, with licence and audit release gates.
**Cost if wrong.** Without the self-test a chain with the same id but another client would accept PQZ deployments.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:208`

### CTR-PQZ-02 — Additive-only MLWE with BFV-style encoding
- old: R271 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-02 · superseded-by: —

**Why.** Additive-only MLWE with BFV-style encoding gives exactly Enc/Add/Dec with a provable decryption relation; full FHE stacks bring relinearization keys and failure probabilities.
**Cost if wrong.** A failure-prone scheme gives an attacker a key-recovery oracle.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:225`

### CTR-PQZ-03 — Lattice parameters at or above Kyber-512
- old: R272 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-03 · superseded-by: —

**Why.** Parameters at or above Kyber-512 under classical and quantum core-SVP (β ≈ 476) with worst-case noise bounds, so an accepted state never fails to decrypt.
**Cost if wrong.** Any change needs a new `proofSystemId` and a recomputed noise budget.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:230`

### CTR-PQZ-04 — Shared encryption randomness with split fallback
- old: R273 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-04 · superseded-by: —

**Why.** One shared `(r, e1)` per transfer saves two 16 KB `u` vectors; security against malicious recipients is a stated hint-leakage assumption with a split-randomness fallback.
**Cost if wrong.** If the assumption fails, a colluding receiver and auditor could open the sender's new balance.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:239`

### CTR-PQZ-05 — Every debit re-encrypts the remaining balance
- old: R274 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-05 · superseded-by: —

**Why.** Every debit re-encrypts the remaining balance fresh, resetting noise and digit growth.
**Cost if wrong.** Homomorphic subtraction would accumulate noise until decryption fails.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:250`

### CTR-PQZ-06 — Credit cap and public plainPending amounts
- old: R275 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-06 · superseded-by: —

**Why.** Public amounts go to `plainPending` and only proven credits take slots under `K_MAX = 1024`, so dust cannot lock an account.
**Cost if wrong.** Counting dust as slots let `fund(victim, 1)` × 4096 lock a victim.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:254`

### CTR-PQZ-07 — Ciphertexts in calldata, hashes in storage
- old: R276 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-07 · superseded-by: —

**Why.** Ciphertexts live in calldata and events with hashes in storage; storage of a 16 KB ciphertext would cost 2.6–8.8 M gas per write.
**Cost if wrong.** Indexers must rebuild state from events; clients check hashes.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:265`

### CTR-PQZ-08 — Public rollover with race-free debits
- old: R277 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-08 · superseded-by: —

**Why.** Public rollover cannot disturb a debit because the contract rebuilds the same `T` either way; at most 16 inline credits.
**Cost if wrong.** A griefer with > 16 proven credits can force one re-prove.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:269`

### CTR-PQZ-09 — LNP22 proofs through rewritten LaZer fork
- old: R278 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-09 · superseded-by: —

**Why.** LNP22 via a LaZer fork with six rewritten layers runs portably and deterministically in the node, the prover and WASM; one implementation, no Solidity verifier; kill criterion on size and verify time.
**Cost if wrong.** We own a C fork; upstream fixes are merged by hand.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:277`

### CTR-PQZ-10 — Native never-crash precompile on chain 7622
- old: R279 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-10 · superseded-by: —

**Why.** A native never-crash precompile on chain 7622 verifies at ≈ 0.12 M gas per ms; a Solidity verifier would exceed the per-transaction cap.
**Cost if wrong.** Every node of chain 7622 must run the PQZ client build; a crash would halt the single-signer chain.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:290`

### CTR-PQZ-11 — Deterministic precompile pricing and chain limits
- old: R280 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-11 · superseded-by: —

**Why.** Precompile prices are deterministic, calibrated on p99 adversarial verify time against `ecMul`; the block gas target rises to 80 M within the EIP-7934 byte limit.
**Cost if wrong.** Mispriced verification makes block capacity a DoS surface.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:308`

### CTR-PQZ-12 — Authorization always by a separate PQ signing UA
- old: R281 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-12 · superseded-by: —

**Why.** PQZ authorization is always a separate PQ signing UA (or a PQ-dominant `msig`), so no classical-only key can move confidential value.
**Cost if wrong.** Users need an ML-DSA key in addition to the PQZ key.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:318`

### CTR-PQZ-13 — PQZ UA kind 0x0142 pqz-mlwe
- old: R282 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-13 · superseded-by: —

**Why.** PQZ adds one UA kind (`0x0142` `pqz-mlwe`) under the UA rules instead of its own identity scheme.
**Cost if wrong.** The UA kind table, keyHash groups and vectors gain one row each.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:325`

### CTR-PQZ-14 — Disclosure only by zero-knowledge proof
- old: R283 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-14 · superseded-by: —

**Why.** Disclosure is by zero-knowledge proof only; revealing `r` would open the sender's balance and noise must not leak.
**Cost if wrong.** Each disclosure costs a proof (≈ 15–25 KB, estimate).
**Source.** `history/specs/2026-10-06-pq-zether-design.md:333`

### CTR-PQZ-15 — PqzToken is ERC-20 plus IERC20MetaTx
- old: R284, owner:2026-10-07:pqz-metatx · status: current · owner: yes · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-15 · superseded-by: —

**Why.** The owner ruled that `PqzToken` follows `IERC20MetaTx` exactly like `ZetherToken`: v1 and v3 envelope paths over one pipeline, wrap/unwrap as direct calls on both tokens, and the envelope `burn` as the gasless exit; authority is split between the PQ `authSig` and the envelope signer.
**Cost if wrong.** A broken v1 envelope key can spend that signer's public float and burn its nonces; it can never move confidential value.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:337`, `history/SCaaS-2026-10-07.md:39`. Owner wording (2026-10-07): "PqzToken => Cái này cũng phải theo MetaTransaction IERC20MetaTx chứ." (PqzToken must also follow IERC20MetaTx).

### CTR-PQZ-16 — Direct decryption without BSGS
- old: R285 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-16 · superseded-by: —

**Why.** Decryption is rounding of 16 coefficients: exact and microseconds, no BSGS.
**Cost if wrong.** None found; a balance cache stays a UX convenience.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:361`

### CTR-PQZ-17 — PQZ shielded supply and amount limits
- old: R286 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-17 · superseded-by: —

**Why.** `MAX_TOTAL_SHIELDED = 2^62` and amounts `< 2^64` keep `b' + v + fee < 2^64` for honest states.
**Cost if wrong.** The classical 2^54 rationale (BSGS) does not apply; raising further would break the digit argument.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:364`

### CTR-PQZ-18 — Native and WASM prover platforms early
- old: R287 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-18 · superseded-by: —

**Why.** Retail provers come early (owner): native x86-64/aarch64, then the WASM prover in the app's Zether worker with a user-run native fallback.
**Cost if wrong.** WASM emulates 64×64→128 multiplication, which may miss phone budgets.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:367`

### CTR-PQZ-19 — Message-bound derived encryption randomness
- old: R288 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zether.md#CTR-PQZ-19 · superseded-by: —

**Why.** Encryption randomness is derived from a message-bound seed, so the sender can re-derive it for disclosure and a re-proof never reuses `r`.
**Cost if wrong.** Reusing `r` across two messages leaks `Δ·(m − m')` up to noise.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:376`

### CTR-PQZ-20 — Classical to PQZ migration by burn then fund
- old: R289 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zether.md#CTR-PQZ-20 · superseded-by: —

**Why.** Migration is `ZetherToken.burn` then `PqzToken.fund`; the amount is public once, which is acceptable because classical Zether holds no production funds.
**Cost if wrong.** No cross-system equality proof in v1.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:382`
