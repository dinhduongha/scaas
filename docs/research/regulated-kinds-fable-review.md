> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Fable counter-review of the regulated-kinds spec draft, 2026-11-05 (kept verbatim).

# Counter-review: regulated kinds 8–13 spec (`docs/superpowers/specs/2026-11-05-regulated-kinds.md`)

Reviewer: Fable (Claude), 2026-11-05, read-only, branch `ua-mtx-merge` at `00bade4e`. Scope: the spec with Q1–Q8 answered as
recommended. Rules cited by the spec are settled and not reopened; findings name where the spec contradicts them, misses a
case, or creates a risk. Code references are to `smartcontracts/evm/src/` at the commit above. Everything here is
UNAUDITED work reviewed by an AI model, not an audit.

Severity: P0 wrong / unsafe · P1 must fix before build · P2 should · P3 nice.

**Counts (distinct findings):** P0 0 · P1 5 (F-01, F-02, F-03, F-04, F-27) · P2 14 (F-05, F-06, F-09, F-10, F-11, F-14,
F-15, F-16, F-19, F-20, F-23, F-28, F-33, M-08) · P3 18 (F-07, F-08, F-12, F-13, F-17, F-18, F-21, F-22, F-24, F-25, F-26,
F-29, F-30, F-31, F-32, F-34, F-35, M-10) + 4 short P3 notes at the end of §M. §M lists the ten "missing entirely"; M-01
to M-07 and M-09 point at the F item that carries them.

---

## L6 — Authorization and call flow

**F-01 · P1 · §2.1, §3.1 — contract-only bits 5–7, 10, 21 refuse a derived `msig` issuer; two owner rulings disagree.**
The spec: "a derived UA cannot hold these bits (contract-only)". CTR-AS-03 (Change 2026-11-04): "a holder is a native id
whose address has code". CTR-GOV-01 Change (owner 2026-11-04, same day): "a PQ or `msig` issuer holds a power under its own
id, with no per-issuer contract". Code: `GovernanceLib._check` refuses any derived id on a contract-only bit
(`GovernanceLib.sol:429-432`). A regulated token whose issuer is a PQ threshold account (the product's own identity story,
and the family-neutral one for L13) is impossible under the spec. Fix: raise it to the owner as a one-line question rather
than pick silently. Recommendation: "contract" for bits 5–7, 10, 21 means a native id with code **or** a derived UA whose
registry kind is a threshold (`msig`) record; `_check` reads `IUARegistry.kindOf` for a derived id. Until answered, the
spec must say which ruling it follows and why.

**F-02 · P1 · §3.3, §3.6 — FORCE's "live RECORD" test reads roots only; `disableFeature(RECORD)` leaves FORCE live and
orders unrevokable.** Spec: `forceTransfer` needs "a live root of bit 10 (`counts[10].roots ≠ 0`)". `disableFeature(10)`
clears the feature bit but not `counts[10].roots` (`GovernanceLib.disableFeature`, `:313-320`, touches only `features`);
`revokeOrder` runs under `GovernanceUse.use(10, …)` which reverts `FeatureNotSet` once bit 10 is off
(`GovernanceBase.sol:16`). Result after `disableFeature(RECORD)`: every live record stays live forever, nobody can revoke,
and `forceTransfer` keeps passing. Bit 10 is not in `_delayedRelaxBits`, so this is one undelayed owner call. Fix: define
"record live" as `!revoked && features & RECORD ≠ 0`, and FORCE's RECORD test as `features & RECORD ≠ 0 && counts[10].roots
≠ 0`; state that `disableFeature(RECORD)` ends every record-backed freeze (as `revokeOrder` of all would) and stops FORCE.
Add the mutant "RECORD disabled, forceTransfer still passes".

**F-03 · P1 · §3.6 (Q4) — "no new mechanism" is not true: the relaxing entries have no pending plumbing, and the pending
key collides.** `revokeRole` (`GovernanceLib.sol:151-162`) bars the account and deletes `pending[bit][account]` **before**
`_clear`, with no `_due` call; `renounceRole` (`:165-170`) deletes the pending; `disableFeature` (`:313`) has no account to
key a pending on; `setGrant`'s "pure narrowing applies at once" (`_narrowing`, `:197-208`) accepts a `validUntil` reduction
at once, which CTR-GOV-09's Change says must take the delay on a masked bit. `_due` uses `termsHash = 0` for a whole grant
(`:221`), so an owner's proposed *revoke* of `(bit, X)` with hash 0 would *confirm* a live pending *grant* of `(bit, X)`.
Fix (spec text, before T24): (a) a relaxation proposal is keyed `pending[bit][account]` with a sentinel `termsHash`
(e.g. `keccak256("relax")`), `disableFeature` under `account = bytes32(uint256(bit))` or a dedicated key; (b) a live
pending with another hash is `GrantTermsMismatch`, so grant and revoke proposals on one `(bit, account)` exclude each
other; (c) `barred`, the pending deletion and `_clear` happen at confirm, not at propose; (d) `_narrowing` returns false
for a masked bit when the edit ends the power before `now + grantDelay`; (e) a `renounceRole` proposal's proposer is the
holder and dies on an owner change (`_live` reads `ownerGeneration`, `:237-239`) — state it; (f) emit `GrantProposed` (or
a new `RelaxProposed`) so wallets see "freezes end at eta". Re-estimate T24.

**F-04 · P1 · §3.3 — freeze state transitions are underspecified and one path silently unfreezes.** Spec row
`freeze(subject, ref, recordId)`: "`until = freezeUntil`". A record with `maxAmount > 0, freezeUntil = 0` (allowed by
`recordOrder`) called on an account under a live issuer-only freeze sets `until = 0`: the account is unfrozen by a call
named `freeze`. Likewise `freeze(a, ref, 0)` on an account under a record-backed freeze: "not frozen ⇒ …" is skipped, so
`until = min(now + 30 d, episodeStart + 60 d)` with a stale or zero `episodeStart` shortens or ends the record-backed
freeze. Fix: state the transition table: `until` never decreases except by `unfreeze` and `revokeOrder`; a record-backed
call requires `freezeUntil > now` (`FreezeTooLong`-class error, or `OrderInactive`) and sets `until = max(until,
freezeUntil)`; an issuer-only call on a record-frozen account is refused (`AlreadyRecordFrozen`) or a no-op; `unfreeze`
and a new issuer-only episode clear `FreezeState.recordId`, and `revokeOrder` ends a freeze only when `recordId` matches.
Add tests for each cell.

**F-05 · P2 · §3.1 — the eight control stubs: `nonReentrant`, and `_govSubject()` evaluated in the token.** The spec says
each stub `DELEGATECALL`s `RegulatedLib`; it does not say the stubs are `nonReentrant` (every entry of a token is, and the
`governed` modifier of `GovernanceBase` is the same guard, `MetaTokenBase.sol:129-130`). It must also say `_govSubject()`
(reads the `GOV_ROUTER` immutable, `GovernanceBase.sol:53-56`) runs in the token and is passed into the library as a word:
a DELEGATECALLed library cannot read immutables, and `msg.sender` inside it is the router, not the subject.

**F-06 · P2 · §3.1, §3.6 — the emergency path is not written down.** Revoking or disabling bits 5–7 takes `grantDelay`
(≤ 30 d). A compromised FORCE holder is stopped at once only by `revokeOrder` (bit 10, undelayed) or by the owner's
`revokeRole(10)` of every compliance root (undelayed, kills FORCE per CTR-AS-03). A compromised issuer can pause ≤ 7 d and
freeze ≤ 30 d per account. Write the "what to do first" table into §3.6 and the operator note; the node's `OrderRecorded`
alert is the trigger.

**F-07 · P3 · §3.1 — `_check` does not refuse `pad(address(this))` as a holder or owner.** `GovernanceLib._check`
(`:424-425`) refuses 0 and the two pools. A role on the token's own id is reachable only through a self-call, and the
control selectors are on no allow-list, so it is inert today; refuse it anyway, as the pools are (B-19's reason).

**F-08 · P3 · §3.4 — `moderatedTransfer` with `to == from` and `forceTransfer` with `amount == 0`.** Neither is refused:
the first is a no-op that emits an event and debits a grant's `maxUses`; the second emits `ForcedTransfer(…, 0)` on a
freeze-only record (`maxAmount = 0`, `executed + 0 ≤ 0` passes). Refuse both.

## L7 — State, reentrancy, external calls

**F-09 · P2 · §2.2 — `_regShape` "after steps 1–4" is after the signature and the nonce, not CTR-AS-08's shape step.**
In the built pipeline authorization is step 2 and the nonce step 4, inside `MtxPipelineLib.pre*` (`UAMetaTxBase.sol:137-144`,
`ERC20MetaTx.sol:250-258`). Placing the regulated check after them means a frozen `from`'s relayed op costs the relayer
the signature check first: for a derived PQ UA that is a registry verify (ML-DSA / Falcon), not a "cheap prefix". It also
contradicts the spec's own claim that the check sits at the shape step (CTR-AS-08, L15). Fix: split the hook: `P` and
`F(from)` need only `e.from`, so call them in the token **before** `MtxPipelineLib.pre*`; `F(feeTo)` / `R(feeTo)` after,
once `o.feeTo` / `o.fee` exist. State the gas bound per signer class (ECDSA, ERC-1271, HIP-632, PQ) in I10.

**F-10 · P2 · §2.2 — hook arguments computed in the plain kind are not "+0 by construction".** An empty `internal view
virtual` body is free, but an argument such as `uaOf(t.yFrom)` (`ZetherLib.sol:614`: `keccak256(abi.encode(y))` over 64
calldata bytes) or `_ticketSubject()` is evaluated in the plain kind unless the optimizer proves it dead; with `via_ir`
off (`MetaTokenBase.sol:231-234` notes the legacy pipeline) that is not reliable. CTR-GOV-11 forbids a new *read* only, so
this is gas and bytecode drift, which the pins will show. Fix: hooks take raw inputs (`G1 calldata yFrom`, `address from`)
and the regulated override computes the id; I0 keeps the slot pin **and** a gas pin with old → new per kind.

**F-11 · P2 · §5 — `hasFlags` STATICCALL is unbounded in gas and the registry's code is not pinned.** A registry is "a plain
contract, deployed by anyone", checked for code only. A proxy or self-destructing registry turns "pinned at creation" into
"pinned address, mutable policy", which the disclosure promises otherwise. Fix: `DeployBase` publishes the canonical
`ComplianceRegistry` runtime hash; `initialize` refuses a registry whose `extcodehash` differs (one `EXTCODEHASH`, init
only); wallets show the hash. Separately, cap the STATICCALL gas (e.g. `gas: 50_000`) so a transfer's cost on a regulated
token is bounded and the node's estimate holds (L9).

**F-12 · P3 · §2.2 — `_regMove` from `_update` runs for `_poolMove`'s `ERC20._update`? No, and say so.** `_poolMove` calls
`ERC20._update` qualified (`ERC20MetaTx.sol:297`), which skips the override; the spec's "never `_poolMove`" holds by that
qualified call. Add the mutant "`_poolMove` calls `_update` unqualified" (it would then check decoy fees: I9 catches it).

**F-13 · P3 · §2.2 — `RegulatedBase` declared "over `ERC20MetaTx`" cannot override `_validBits` and friends.** Those are
`GovernanceBase` / `MetaTokenBase` members (`GovernanceBase.sol:60-68`, `MetaTokenBase.sol:135-138`), and `_regShape` must be
declared in `UAMetaTxBase` (where `_uaSettle` is `private`, `:171`), which the router inherits too. State the inheritance
order and that the router gets the empty hooks (+0 there as well).

## L8 — Economics and manipulation

**F-14 · P2 · §3.3 — `recordOrder` is public and names the subject before any freeze.** `OrderRecorded(subject, …)` lands
one transaction before `freeze(subject, ref, recordId)`; the subject (or a bot on the node's own `OrderRecorded` alert)
moves first. Asset-suite A4 names private submission for the freeze; the spec needs the ordering: issuer-only `freeze`
first (no record needed, ≤ 30 d), record second, record-backed freeze third; the node's alert is for wallets, not a
mitigation. Also: `mtxFreeze` relayed through an open node is visible to every relayer; a contract issuer should call the
direct entry from its own transaction where front-running matters.

**F-15 · P2 · §3.2 — `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`, `mtxRelayFee`, `mtxWrapOrder` fee legs are not
in the path table.** `payWithFee` moves the fee by `_transfer(payer, feeRecipient, …)` (`MetaTokenBase.sol:342`): the
`_update` hook gives `R(feeRecipient)` but **not** `F(feeRecipient) ⇒ FeeRecipientFrozen`, which CTR-AS-05 ("cannot
receive a relayer fee") and CTR-AS-08 ("also on `payWithFee`") require and asset-suite §2.4 lists. `mtxWrapOrder` mints
`fee` to `msg.sender` (`WrappedToken.sol:197`): `R` by the mint row, no `F`. `mtxPayReceiverFee`'s fee leg
(`MetaTokenBase.sol:292`) makes the payee the `from`: a frozen payee cannot *receive* a receiver-fee payment, against
"credits are never refused" — decide and state it. Fix: add the five rows; `payWithFee*` check `F(feeRecipient)` in the
entry (the base body is copied, as CTR-AS-08 says).

**F-16 · P2 · §3.4 — PAUSE and DEX markets.** A paused regulated leg stalls every market on it for ≤ 7 d (every
`mtxTrade` and every DEX payout hits `P`), and the venue's committed-balance model (NODE-DEX-07) keeps those orders
resting. State: the venue halts the market on `Paused`, re-opens on `Unpaused` or expiry, and does not grief-score
settlement reverts with `TokenPaused` (asset-suite §2.7's exemption covers only issuer-touched accounts).

**F-17 · P3 · §3.3 — `revokeOrder` does not start the issuer cooldown.** Asset-suite §2.5 says "(issuer cooldown starts as
above)"; the spec's row does not. Without it: open-ended record freeze → revoke → immediate 60-day issuer-only episode →
new record, with compliance's cooperation, which the model accepts anyway (A3). Align the text either way.

**F-18 · P3 · §3.2 — `mtxCancelNonce` with a fee under FREEZE/PAUSE.** It charges its fee by `_uaChargeFee` outside
`_uaSettle` (`UAMetaTxBase.sol:93-105`), so `_regShape` never runs: a frozen `from` at fee 0 cancels (fine, nothing moves;
CTR-AS-05's "any meta-tx op" is read narrowly), and at fee ≠ 0 the refusal is `Frozen(from)` from `_regMove`, not
`FeeRecipientFrozen` for a frozen recipient. State both.

## L9 — Gas, DoS, chain limits

**F-19 · P2 · §6.2 — the size estimate rests on a stand-in that measured 2 of ~15 sites.** T0's +995 B is "six direct
stubs and a two-read hook"; the design adds five hooks at ≥ 12 sites, eight stubs with a DELEGATECALL each, two struct
views, the init path, `RoleConflict` and the delayed-relax paths in `GovernanceLib`, and `controls` mirroring in a
`disableFeature` override. The spec's own record says estimates ran 2–5× over. `WrappedPqzRegulatedToken` has 4.3–6.0 KB
to the 65,536 B cliff; at 3× the stand-in it crosses. The decision is already taken (CTR-GOV-19, Q7), so the fix is
process: T26 measures kind 9 and 13 **first** (a two-kind skeleton) before T27–T30 fill the bodies, and the task order
puts the `_above64KiB` row and the deploy-gas gate in T26, not T31.

**F-20 · P2 · §7, §2.4 — `TokenConfig.reg` changes the init ABI of every kind and every encoder.** `ZetherWrappedLib.init`
and `PqzWrappedLib.init` `abi.decode` the raw `TokenConfig` (`ZetherWrappedLib.sol:35-36`, `PqzWrappedLib.sol:26-27`),
`WrappedLib.initToken` takes it, `DeployBase`, `script/pqz/e2e.py`, `Factory.t.sol`, the node's config builders and
`clientkeys` encode it. None is in T24's list. Add them to T24 and to the blast radius; `ConfigFieldForOtherKind(6)` also
needs the NatSpec enum at `IFactoryToken.sol:101` extended.

**F-21 · P3 · §6.1 — `ComplianceRegistry` and the ELIGIBLE_CONTRACT attestations are not in the deploy plan.** Something
must deploy a registry on the SCaaS testnet and attest `SCaaSDex` and `DexPuller` as `ELIGIBLE_CONTRACT` before any
ALLOWLIST token trades; `deploy.sh`'s `DEPLOY_REGULATED=1` and `e2e.py` need the steps and the JSON keys
(`compliance_registry`), and the node a config row.

**F-22 · P3 · §8 I10 — "< 200 k" is not a bound a PQ-signed envelope meets.** The refusal of a relayed confidential op
runs inside the self-call, after `preNamedUA` verified the envelope's signature through the registry; for an ML-DSA-87
or Falcon-1024 UA that alone can exceed the figure. Bound per signer class, or move `P`/`F(from)` before `pre*` (F-09).

## L11 — Privacy and metadata

**F-23 · P2 · §4 — a refresh (`mtxUnshield` with `amount = 0, recipient = 0`) under FREEZE and PAUSE is undecided.**
`PqzLayer.mtxUnshield` is also the refresh (`PqzLayer.sol:320-329`): it moves nothing out, like a roll-over. The spec's §4.2
row applies `F(b.fromUA)` and `P` to every `_burn`, so a frozen account cannot refresh its `acc`, and `_regReceiver(0)`
would be asked. Decide (recommend: a refresh is open, as roll-over is, U1/U2's reason) and skip `R` when `amount == 0`.

**F-24 · P3 · §5, §2.8 — the registry and the freeze events are a public per-UA status list.** `Attested(bytes32 indexed
account, flags…)` publishes `KYC_DONE`, `ACCREDITED`, `SANCTIONS_CLEAR` per id; `AccountFrozen(account)` and
`OrderRecorded(subject)` name ids on confidential kinds too. "No personal data" is true of the bytes, not of the
inference. The disclosure sentence of bits 8/9 and 5 should say that attestation status and freezes are public per id.

**F-25 · P3 · §4.3 — what a refusal reveals.** A relayer's simulation of a Zether/PQZ transfer that reverts `Frozen(ua)`
names the sender; the sender is already public (`yFrom` / `fromUA` are explicit fields, `IZetherToken.sol:37,61,74`), so no
new leak. State it, so a later reviewer does not reopen it.

## L13 — One rule on every family

**F-26 · P3 · §1, §7 — the portable parts are the KAT, and two EVM-isms need a family-neutral statement.** `recordId =
keccak256(abi.encode(orderId, subject, beneficiary))` is three 32-byte words (portable); `hasFlags` and the freeze
arithmetic are in `regulated_kat.json` (good). "Holder has code" (F-01) and the `GovernanceRouter` are EVM-shaped; the
spec should say each family authenticates the holder its own way and that a threshold record counts as a contract on every
family. Soroban's `require_auth` needs no router; say so in §1 so the Soroban round does not build one.

## L15 — Spec ↔ rules

**F-27 · P1 · §3.2, §8 I4 — Q6's answer is not folded into the tables.** Q6 opens a fee-0 `mtxBurn` during a pause on
kinds 8, 9; §3.2's shape row still reads "`P` unless the op is an unwrap op", and I4 reads "only the open rows of §3.2".
`burn` is on `_uaAllowed` of `NormalToken` (`NormalToken.sol:81-83`) so the generic path reaches it too. Add `burn` to the
fee-0 exception (shape row, I4, the mutant "burn paused").

**F-28 · P2 · §3.2 — `mtxWrapOrder` / C10 is in the governance spec's Wrap row and not in this one.** Governance spec
§4.3: "`wrap`, `wrapToUA`, `mtxWrapOrder`, `uaWrapOrder`: the payer (`o.from` on an order) when the destination is another
id". The spec's §3.2 names "wrap whose payer is not the destination" and §2.2 "a wrap payer when the destination is
another id" without `mtxWrapOrder`; its body (`WrappedToken.sol:188-199`) has no `_wrap` call, so the `_regSender` site
would be missed. List it, with `o.from` as the payer.

**F-29 · P3 · §2.1 — bit 21 made contract-only is an addition to CTR-GOV-08.** CTR-GOV-08 does not say the MODERATE
holder must have code; CTR-AS-03 covers 5–7 and 10. Either cite the reason or drop 21 from `_contractOnlyBits()`
(AGENTS: follow the stated rule, no added assumptions).

**F-30 · P3 · §2.2 — "the hook never reads `scaas.governance`" is false by the spec's own `F`/`P`.** `F(a)` and `P` read
`counts[bit].roots`, which is `scaas.governance` (+6). The sentence means `features`; say that.

**F-31 · P3 · §7 — `selector_audit.json` class "power, router only" is wrong for a direct entry.** A contract holder calls
`freeze` directly (`_govSubject()` = its padded address); "router only" describes a derived holder's path. Use the class
the 19 existing powers carry (`mint`, `disableWrap`, …).

**F-32 · P3 · §3.1 — `mtxCancelNonce` of a frozen `from` on a public kind.** CTR-AS-05: a frozen account "cannot be the
`from` of any meta-tx op"; the spec's `_regShape` does not cover `mtxCancelNonce` (F-18). Record the exception.

## L16 — Test plan

**F-33 · P2 · §9 — add the negatives that the findings above need, each with its positive control:**
record-backed `freeze` with `freezeUntil ≤ now` on an issuer-frozen account (F-04); issuer-only `freeze` on a
record-frozen account (F-04); `disableFeature(RECORD)` then `forceTransfer` and `revokeOrder` (F-02); a pending grant and a
proposed revoke on one `(bit, account)` (F-03); `acceptOwnership` kills a pending relaxation (F-03); `payWithFee` with a
frozen fee recipient (F-15); `mtxWrapOrder` with a frozen submitter and with a frozen `o.from` and another destination
(F-15, F-28); `mtxPayReceiverFee` to a frozen payee (F-15); a refresh under FREEZE (F-23); `forceTransfer(…, 0)` and
`moderatedTransfer(a, a, …)` (F-08); `hasFlags` at `validUntil == now` (the spec says `≥`); a reverting and a gas-burning
registry: transfers fail, burn and unwrap succeed, mint fails; a derived `msig` as issuer (F-01, whichever way the owner
rules); `freeze(0)`, `freeze(pad(UA_POOL))`, `freeze(pad(this))` refused (not in the spec: add the refusal).

**F-34 · P3 · §9 — mutants to add.** `_poolMove` unqualified `_update` (F-12); `F(from)` moved after `pre*` (F-09);
`controls` mirror not cleared by `disableFeature` on the wrapped kind's override (`WrappedToken.sol:265-268` is the one to
compose with); `counts[10].roots` read without `features & RECORD` (F-02); `recordId` not cleared on `unfreeze` (F-04);
`ELIGIBLE_CONTRACT` checked against `extcodehash` of a proxy registry (F-11, if adopted).

**F-35 · P3 · §8 I0 — the pin should be slots and gas.** `PlusZero.t.sol` pins read slots by `vm.record` /
`vm.accesses` (`test/governance/PlusZero.t.sol:104-108`); add the gas figure with old → new in the commit, so F-10's
argument-evaluation drift is visible.

## L5 — Architecture and what is missing (§M)

**M-01 · P1 · (= F-01)** which identity may hold the regulated bits: contract address vs threshold UA.
**M-02 · P1 · (= F-03)** the delayed-relaxation state machine: keys, collisions, when `barred` applies, events.
**M-03 · P1 · (= F-04)** the freeze transition table (issuer-only ↔ record-backed, `recordId` clearing).
**M-04 · P1 · (= F-02)** RECORD disabled: records, FORCE, `revokeOrder`.
**M-05 · P2 · (= F-15, F-28)** the fee legs and `mtxWrapOrder` in the path table.
**M-06 · P2 · (= F-06)** the emergency runbook: who stops what at once, who after `grantDelay`.
**M-07 · P2 · (= F-20, F-21)** the `TokenConfig.reg` ripple and the registry / ELIGIBLE_CONTRACT deploy steps; the
`GovernanceRouter` bytecode change moves its CREATE2 address, `Env.govRouter` of every release, `deployments/*.json` and
the node's `governance_routers` (reset 2 covers it, the spec should say so in §6.1).
**M-08 · P2 · §3.1 events** — a freeze ended by `revokeOrder` emits no `AccountUnfrozen`; `disableFeature(FREEZE)` ends
every freeze with one `FeatureDisabled`; a proposed relaxation has no event. Wallets and the indexer need all three
(`AccountUnfrozen(subject, reasonRef)` on revoke; the indexer derives the rest from `FeatureDisabled` / `RoleRevoked`,
documented in §7).
**M-09 · P2 · (= F-23)** refresh under FREEZE / PAUSE, and `mtxUnshield` with `amount == 0` skipping `R(recipient)`.
**M-10 · P3 · §7** — mandate wallets and `IRegulatedToken` in `supportsInterface`: a `MandateWallet` holding a regulated
token is a native id with code (not moderatable, force-able, must not be frozen to pay; asset-suite §2.7); say it in §7's
node/wallet rows. Add `type(IRegulatedToken).interfaceId` to `supportsInterface` (`MetaTokenBase.sol:141-147`) on kinds
8–13 only, so a wallet detects a regulated kind without reading `kind()`.

Further P3 items noted and not expanded: owner = 0 with regulated bits needs those bits locked or `init` refuses
`OwnerHasHolders` (`GovernanceLib.sol:117-119`) — state it in §2.4; `regulatedConfig().controls` must equal `features() &
0x3E0` (an invariant test); a disabled attester voids every attestation it made, so a registry admin's `setAttester(false)`
is a mass receive-DoS for legitimately attested accounts (operational note for the registry's disclosure); the "five wrap
entries" of §2.2 should be named (`mtxWrap`, `mtxWrapLeg`, `mtxWrapToUA`, `mtxAddReserve`, `mtxWrapShield`).

---

## What holds

- The hook seats match the code: `_update` after the `UA_POOL` → `_ticketSubject()` resolution (`ERC20MetaTx.sol:199-203`),
  `_uaMove` before `_poolMove` (`:281-287`), nothing on `_poolMove` / `_fromPool`; the Zether and PQZ sites in the spec's
  §4 tables agree with `ZetherLayer.sol:150-155, 168-184, 214-220`, `PqzLayer.sol:195-198, 274-295, 348-354` and the two
  wrapped kinds' `mtxWrapShield` / `mtxUnshieldUnwrap`.
- Zether's sender is an explicit field (`yFrom`), so "the check reads the proof's sender" is implementable without touching
  the ring; `uaOf` is pure (`ZetherLib.sol:614`).
- `forceTransfer` on `_poolMove` with the pools and `this` refused by `recordOrder` keeps `SHIELD_POOL`'s backing and the
  `UA_POOL` sum intact (never lose ciphertext; CTR-UA-18).
- CTR-GOV-05's leg refusal is already built (`WrappedLib.sol:135-137`) and the spec cites it correctly.
- `_checkTo` for a derived beneficiary (`MtxPipelineLib.sol:260-266`) is the right receiver rule to reuse.
- Every control op is relayable at fee 0 through the router at mode `NONE` (CTR-GOV-15 Change), the token keeps no twin.
