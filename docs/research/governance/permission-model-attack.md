> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**
>
> **Superseded by the built model:** [contracts/README.md §8](../../contracts/README.md#governance) and CTR-GOV-01 to -19 in [decisions.md](../../decisions.md#ctr-gov-01--governancebase-on-every-token-kind-and-the-dex); this note is the record of an earlier round, not rewritten.

# Attack round on `permission-model.md` (2026-11-02): judgment

Scope: the draft [permission-model.md](permission-model.md) (line numbers below are its, main checkout), judged against
the EVM source at `typed-signing` `ca2d7b41` (read with `git show`, nothing run, nothing measured) and the normative
docs it cites. Inputs: one escalation report with three refuter votes per finding (cut off after its 7th finding), two
gap reports (generality; `MODERATE` reach, cut off after its 2nd finding), the critic's gap list, and the generality
answer. Tags as in the draft: **[V]** read in code or spec, **[I]** inferred, **[est.]** not measured.

## 1. Verdict

**Sound with changes.** The model (existence bit → compiled shape → flat holding → envelope outside the token, one
rule everywhere, chain not ranks, rescue with a fixed destination) survives every attack. What does not survive is
four things the draft states as settled: (1) the grant-delay mechanism as written (anyone executes, no expiry, no
tie to the owner that queued it) falsifies its own disclosure sentence "owner 0 means nothing above can change"; (2)
§4 step 5 believes a holder's self-report; (3) "force never possible on a confidential kind" and "`features()` is the
worst case" are true of the token's ABI and false of a wrapped unit's value, because a leg's issuer (SCaaS `MODERATE`
/ `FORCE` once built, or any outside token today) can move the wrapper's leg balance; (4) the vocabulary generalises
to non-token contracts, the holder clone does not, and the owner's question needs that answer stated. Nothing in the
model has to be reworked; the §8 list changes in form (item 1), gains two owner questions, and loses the carve-out.

## 2. Findings that stand

Severity: P0 funds or binding rule broken by the design as written; P1 must be fixed before the freeze or before the
owner answers the §9 questions; P2 doc correction. "Found by": E = escalation lens, G = generality gap report, M =
`MODERATE` gap report, C = critic's gap list, J = this judgment.

| Id | Sev | Section | Attack (verified) | Fix | By |
|---|---|---|---|---|---|
| A1 | P1 | §8 item 1, §4 step 3, §2 row "after renounce" | Pending grant then `renounceOwnership`: nobody can cancel (`revokeRole` needs `_onlyOwner`, AdminLib.sol:104–110, :186–189), `renounceOwnership` clears only `owner`/`pendingOwner` (:146–151), anyone executes after the delay (:292–293). `owner() == 0` is read as "nothing above can change, ever" (:205) and CTR-TOK-22's recipe "revoke every role, then renounce" (token-wrappers.md:539) no longer gives an unchangeable token. Same with `transferOwnership`: the new owner inherits a pending it has no list of. Not stronger than today (today: grant then renounce, X keeps the role, AdminLib.sol:145), but the draft's new `holderCount` reads 0 while the minter is pending, so the new completeness check lies. Votes P2/P2/P1. | Drop "executed by anyone" and the `executeGrant` stub: the **owner calls `grantRole` a second time** after `eta`, within `[eta, eta + grantDelay]` (A2); outside the window the pending is dead. Owner 0 can never confirm; a new owner confirms explicitly or not at all. Logic in `AdminLib` only; the token gains a config field and one view, no new entry. | E |
| A2 | P1 | §8 item 1, §2 :148, §4 | No expiry and no reader: a key held for one hour queues `grantRole(MINTABLE, burner)`; months later anyone finalises and mints in one block. §4 (:199–214) has no pending step; `holderCount` excludes pendings; the mapping is keyed `(bit, account)` so a wallet reads only what it already knows. The repo's own timelock has a window (`eta + 7 days`, token-wrappers.md:341–343; WrappedLib.sol:407) and an owner-only executor (:401–402); the grant path as drafted has neither. Votes P1 ×3. | Window `[eta, eta + grantDelay]` (no new config); the pending word stores `eta` and the proposing owner; a `pendingGrant(bit, account)` view and `lastGrantProposedAt`; §4 gains a step "if `lastGrantProposedAt` is within `2 × grantDelay`, warn and read `RoleProposed` events". With A1 the owner-confirm already kills rotation and renounce. | E |
| A3 | P1 | §4 step 5, §3 disclosure row, Q4 | A contract returning `supportsInterface(IRoleEnvelope) = true`, `envelope() = {total 1000}`, `spent() = 0` while forwarding unbounded `mint` is shown as "a minter can mint up to 1000" (:212–213, :279). `_grant` checks nothing about the holder (AdminLib.sol:176–184); `mint` checks only `requireRole` (NormalToken.sol:39–41). Holders see a harmless envelope during the delay and do not exit; with `renounceOwnership` the wallet shows a permanently capped supply. The repo's rule for tokens (IOpenFactory.sol:139 "trust `isRegisteredToken` only"; token-wrappers.md CTR-TOK-17) is not carried to holders. Votes P1 ×3. | Step 5 trusts only a holder that a pinned catalogue confirms (registered, `version != 0`, not deprecated) and whose `envelope().token == t` and `.bit` = the bit under review; anything else is "whole shape". The catalogue cannot be a `TokenKind` (closed enum, IOpenFactory.sol:11–21, A14), so: a separate immutable envelope catalogue wallets pin per chain (no pre-freeze bytecode), or a new domain on `OpenFactory` before the freeze (owner question Q4'). | E |
| A4 | P1 | §5 :225, §1.3 :105, §10.2 :394, §8 item 2 | Leg P (`NORMAL`, `MINTABLE\|MODERATE`) under a `WRAPPED_PQZ` / `WRAPPED_ZETHER` wrapper: `_addLeg` checks only code and `decimals()` (WrappedLib.sol:105–131); the wizard rule on flags 5–8 is off chain (asset-suite.md:162–165, :390) and bit 9 is outside it. P's moderator calls `moderatedTransfer(from = wrapper, …)`: `_update` refuses only `UA_POOL`/`SHIELD_POOL` as `from` (ERC20MetaTx.sol:307–318). `reserve` stays, `collateralValue()` reads `reserve` (:442–449), `_quote` passes (:278–287), `payOut` reverts on the mismatch (:293–306): every unshield-unwrap of every confidential holder reverts; one unit moved makes `_requireCollateral` (:422–438) and the draft's §10 post-check revert too. Ciphertexts intact, value gone, no record, no proof. The same holds today for any outside leg whose issuer can seize (USDC), which CTR-TOK-11 and asset-suite.md:390 already accept. Report said P0; judged P1: nothing is built (`MODERATE`, flags 5–8 refused `FeatureNotBuilt`), the hole pre-exists for outside legs, and the design adds an in-system form plus two false sentences. | (1) `_addLeg`, every wrapped kind, one rule: a leg that is a SCaaS token (`factory.isToken`) whose `features()` carries `FORCE` or `MODERATE` is refused (features only lose bits, so an init check stays sound). `WrappedLib` body, 0 token bytes. This hardens the wizard rule of asset-suite.md:162 into bytecode: owner question. Outside legs cannot be checked: say so. (2) Reword :225 and :394: "never on this token's ABI; a wrapped unit's value is as good as each leg's issuer" (A5). (3) `moderatedTransfer` refusing a contract `from` is a product trade-off (Safe-held balances become unreachable), not the fix. | M |
| A5 | P2 | §1.1 :66–68, §4 :199–214, §7 :282 | "`features()` states the worst case before reading any holder" is false for every wrapped kind today: a minter on leg A mints, wraps A, unwraps B and empties B's reserve (`_quote` checks one leg); an outside leg's issuer can blacklist the wrapper. §4 never reads `underlyings()`. | Reword the attenuation rule to "the worst case of this contract's own powers"; add a §4 step: per `underlyings()`, recurse on `isRegisteredToken` legs, show "unknown issuer powers" for the rest. | M |
| A6 | P2 | §2 :144–151, §6 :253, §8 :297 | The owner row says "after `grantDelay`" but the first block is not delayed: `transferOwnership` + `acceptOwnership` have no timestamp (AdminLib.sol:130–143), `revokeRole`, `disableFeature`, `renounceOwnership` and cancel are immediate, and in config A (:269, :276) the owner **is** the minter, so it mints at once (INIT grants bypass `grantRole`, :88). ":297 replaces `AccessControlDefaultAdminRules`" is false: ADAR delays the admin transfer, not grants; ruling C1 (2026-10-10 plan :77–81) already chose two-step without delay, so the draft removes nothing. Intermediate and leaf rows hold (2 × `perWindow` at a boundary is the window's meaning, MandateWallet.sol:117–118). Votes P2 ×3. | Split the owner row into "at once" / "after delay"; state that an owner that is also a holder has no delay; correct :297 and cite C1; add Q2' "delay `acceptOwnership` by the same integer?" as an owner question (contradicts C1, gives a stalemate with a shared key, not recovery). Do not forbid owner == holder: that is token A. | E |
| A7 | P2 | §2 :148, §3 :181, §4 :206, §5 :228, §7 :269, Q3 :328 | A derived msig id is 32 bytes outside native space; `owner`, `roles` and `Envelope.operator` are `address`; `_msgSender()` is `UA_POOL` for every derived subject (MetaTxBase.sol:296–300); `grantRole` is on no UA allowlist. So "msig UA" as a direct owner, holder or operator cannot exist, and :228 "holding is an address; CTR-UA-37 decides whether that address can sign" is vacuous for it. Escalation ("grant `MODERATE` to `UA_POOL`, every UA moves anyone's balance") refuted: with Q3 every balance-touching holder is a contract and `UA_POOL` has no code (`SigCheck.isContract`); today a grant to `UA_POOL` is inert because no role-gated entry is UA-allowlisted. Votes P2 ×3. | A UA acts through a `UAMetaTxBase` holder contract with `operator: bytes32` compared to `_subject()`; remove the direct msig UA from the six places; :226 "cannot administer gaslessly" → "cannot administer at all". | E, G |
| A8 | P2 | §8 :295–296 | The carve-out "confidential kinds may take `grantDelay = 0` (RATE/WRAP roles are already contract-only)" is wrong twice: kinds 2 and 4 carry `MINTABLE` (AdminLib.sol:198) with an address minter, and only `RATE_ADJUSTABLE` is contract-only (:180; guardian "may be an EOA", token-wrappers.md:255). Only `WrappedPqzToken` is tight. The trigger "if C6 needs the bytes" is stale (C6 is built; the 1,077 B is after it). Votes P2 ×3. | Delete the carve-out. With A1 there is no `executeGrant` stub, so item 1 costs a config field and a view. If `WrappedPqzToken` still measures over the stop line, except that one kind only, with the reason "no `MINTABLE`, rate has its own timelock, guardian is inflow-only". Do not make the guardian contract-only (no time bound, contradicts :261). | E |
| A9 | P2 | §1.2 :84, §8 :293, Q2 :323 | "`revokeRole` stays immediate (reduce-only)": once flags 5–8 exist, revoking the last `issuer` ends every freeze and pause at once (CTR-AS-03, asset-suite.md:99–100), so one owner key releases what a 3-of-5 issuer guards, in the same block as the subject's transfer. Narrower than reported: the issuer can `unfreeze` without renouncing anyway, and I6 (controls only lose bits) means re-grant does not restore, so the "asymmetry" is not the point. The §2 owner row omits this at-once effect. Not built. | Mark reduce-only as "reduces power over holders"; note in §2 and §8 that revoke/`disableFeature` on `FREEZE`/`FORCE`/`PAUSE` is value-moving for a beneficiary; whether their relaxation takes `grantDelay` changes CTR-AS-03 wording: owner question for the asset-suite stream, not the freeze. | E |
| A10 | P1 | §1.2 :90, §1.3 :116–118, §3, Q4 | The owner's three examples do not run on the holder clone: `Envelope{token, bit}` names a token bit; a `MetaTxBase` child has no `features()`, `roles` or `AdminLib`; a holder in front of a family tree is only another `_msgSender()`; a generic holder must decode each target (then it is per-application) or forward `bytes` (CTR-MTX-16, metatx.md:51 "a generic forwarder is never added"; explicit parameters; NET-ALL-27 has no call-by-name on Move/Solana). The vocabulary carries over, the contract does not, and the draft's own non-token rows (:107–110) already live in those contracts' fields. | New section answering the owner (§4 below): a grant lives in the contract that owns the power; tokens are the exception and use a holder because they cannot grow. Reword Q4 as "for token powers". Nothing before the freeze changes. | G, C |
| A11 | P2 | §1.2 :74, :90 | No floor: `[1 M, 100 M]` is not expressible with `perCall`; `activeUntil` (:87) is used by :107/:117 but missing from "nine words". Splitting (3 × 100 M to one borrower) and "value ≠ effect" (`approve(loanId)` has no amount word; the loan contract pays its stored principal) show the check binds only where it reads the value that takes effect. | `perCall` → `[min, max]`; correct the count; rule: amount limits bind in the contract that holds the record. Per-counterparty exposure and asset binding are compiled there. | G |
| A12 | P2 | §1.1 :62, §1.2 :78, §3 :187 | The set forms are address predicates; "my subtree" (a `u64` person id, NM-4) fits none, and `RECORD` has no read interface, so it means "ask the target". The sketched struct has one `setRef` and no mask: `REGISTRY(G, mask)`, `REGISTRY + FIXED`, and the draft's own `FIXED{buyer, seller}` (:109) cannot be encoded; CTR-AS-07 keys by `bytes32`, so address-typed sets miss derived UA members. | Say the five forms cover address parties of token moves only; scope on application data is a compiled check over a typed field beside the grant; for the token holder either `fromSet, toSet, fromRef, toRef, fromMask, toMask` as `bytes32`, or one set form per holder. Bound a subtree walk by a shape constant. | G |
| A13 | P2 | §1.1 :66, §2 :151, §5 :231 | A `REGISTRY(G, mask)` scope widens after the grant: the registry admin adds Mallory with no delay and no pending state (inherited power, survey P21); :231 "changing one = revoke + grant" is false for the part that matters. | §4 step 5 names who controls the set and prints "X can change this group at once"; `FIXED` for promises that must not move; a membership delay belongs to the group contract, never to the token. | G |
| A14 | P2 | §3 :195, §4 :201, §8 :308 | "A new factory kind" cannot be added: `TokenKind` is a closed enum (IOpenFactory.sol:11–21, "an out-of-range kind fails ABI decoding"), `_create` reads token views, `OpenFactory` is immutable. So `isRegisteredToken` never confirms a holder, and §4 step 1 has no provenance for it (A3). | Write "a separate catalogue contract, later" and add it as §4's application path, or add a domain to `OpenFactory` before the freeze: the one place the non-token answer touches pre-freeze bytecode (Q4'). | G |
| A15 | P2 | §10.1 DEX row, §10.2, §8 item 4 | §10.2 requires an immutable destination ("a changeable destination is a power with a holder again"), but the DEX and `DexPuller` rescue to `treasury`, which the admin rewrites at will through `setFeeSplit` (SCaaSDex.sol:180–200). That is the Aptos `admin_sweep` form §10 says to avoid. | `DexConfig.rescueTo`, immutable, beside `treasury`; 0 = no rescue. Add to §8 item 4. | C, J |
| A16 | P2 | §10.1 WRAPPED row, §10.3 | The post-check "after any rescue every leg has `balanceOf_i ≥ reserve_i`" makes every rescue, foreign strays included, revert while one leg is short (A4 grief: one unit moved off a leg). | Foreign asset: every leg's balance **unchanged** across the call (defeats the alias of §10.3 without trapping); a leg asset: that leg's `balanceOf ≥ reserve` after. Same ≤ 8 reads. | J |
| A17 | P1 | Q5 :331–333 | Q5 recommends "+2,100 gas on a plain transfer once flags 5–8 are built", against the binding rule "a plain transfer's gas should not rise". The draft presents a rule breach as a recommended yes. | Present it as the breach it is. Zero-SLOAD forms: (i) separate regulated implementations (CTR-AS-17 rejected them; the rule-compliant path); (ii) clone-with-immutable-args in `OpenFactory` (a "regulated" word read by `CODECOPY`, est. 20–30 gas instead of 2,100, only regulated instances take the SLOAD) [I, est.]: factory bytecode before the freeze. Owner rules; the draft recommends neither until measured. | C, J |
| A18 | P2 | §5 :233–240 | "One rule on every chain family" is mapped for four families; Algorand (`admin` mint, token.py:137–139), TON jetton (`admin` `Mint`, jetton.tact:44–45), CosmWasm CW20 `minter`, Sui `AdminCap`, Aptos `Root.admin` + `admin_sweep` (contracts/README §3) are omitted. None has a lock; each admin can be a contract (app account, jetton contract, CW20 contract, capability holder), so the rule is expressible, unmapped. §8 (`grantDelay`, `holderCount`, `rescueTo`, `MODERATE`) has no non-EVM mapping; `renounce_admin` on a live Soroban/NEAR token is a new deployment, not an upgrade. NEAR and Algorand stay separate rows. | Add the five rows; state per family which §8 item has an equivalent and which is "EVM only, same rule, no lock"; Hedera's "—" holds for the token, but an HTS leg's native keys are an inherited power (A5). | C |
| A19 | P2 | §3 :178–191, Q1 | The holder chain is unspecified: the sketch has views only, no acting entry, no sub-grant, and "a grantee's envelope is at most its grantor's" (:67) is enforced nowhere; `MandateWallet` is not a factory clone, so its accounting is reused by intent only; the struct :179–188 packs into more than 3 slots. | Specify the one level that is needed (masterMinter): `GrantLib.narrows(child, parent)` at sub-grant, epoch kill (MandateWallet `StaleEpoch`) instead of a walk, accounting consumed only when the token call succeeds, `uint128` units are token units (a rate change does not change units). | C, J |
| A20 | P2 | §4 step 4, §8 item 3 | `issuer`/`compliance` are single INIT fields (AdminLib.sol:44–45) and `ROLE_BITS` excludes 5–8 (:36), so today `grantRole(FREEZE, …)` reverts `NoSuchRole`; CTR-AS-03 says the owner grants them later. `holderCount` must count INIT grants and idempotent re-grants once. | Count in `_grant` (the one path, INIT included; `if (s.roles…) return` keeps it idempotent) and decrement in revoke/renounce; the asset-suite stream adds bits 5–8 to `ROLE_BITS`. State that pendings are not counted. | C, J |
| A21 | P2 | §8, §10.4 | The sum: items 1, 3, 6 on `WrappedPqzToken` est. 500–600 B of 1,077 B before any `TokenConfig` field is costed through init, the factory and the client ABIs, and the levers note treats a margin under 1 KB as none. `WrappedZetherToken` has 2,331 B, not 2.5 KB (:416). | Order of drops on that kind: rescue (6) first, then `holderCount` (3); item 1 in the A1 form is a field and a view. Measure before the owner answers Q2/Q7. | C |

## 3. Refuted, or refuted in part

- A1 "looks stronger than today, where no hidden path exists": today's grant-then-renounce leaves an unbounded minter
  visible only in events (AdminLib.sol:145). "Shows as fixed supply": :205's "nothing above" covers steps 1–2; the
  `MINTABLE` sentence stays, fixed supply is "no flag" (token-wrappers.md:122). What is new is only the false
  `holderCount` completeness and the indefinite sleep.
- A6 "wrong at every level": the intermediate row holds (no "form (c)" exists; `validUntil` ends it), the leaf row
  holds (`total` caps the boundary double), "no renounce" reads an interface-only sketch, "weaker than its spec
  candidate" is C1's ruling, not the draft's.
- A7 escalation to theft by every UA: refuted (contract-only holders; `UA_POOL` has no code; no role-gated entry on a
  UA allowlist). "A truncated id bricks the owner": nothing truncates; the option is unbuildable, not silently bricked.
- A8 "holders can least see the dilution": mint goes to a public balance, the shield pool counts in `totalSupply`;
  "one rule on every chain family" is about families, not kinds; "one transaction" needs a contract owner.
- A3 `createTokenUnregistered` aside: it makes plain tokens at version 0 (OpenFactory.sol:156–162); the attack needs
  no factory.
- A9 issuer limb (the issuer can `unfreeze` anyway) and the 2-day "asymmetry" (I6: controls only lose bits).
- A4 as P0: the leg-side seizure exists today for outside legs and is documented (asset-suite.md:390); nothing is built.
- G "form (c) lets an intermediate rewrite every leaf": (c) is the rejected hook, not a holder form.
- "The holder cannot exist" is too wide: it exists for typed token powers (compiled `mint(to, amount)`-style
  entries, no bytes forwarded, CTR-MTX-16 untouched); it does not exist as a generic one.

## 4. What held

The envelope never touches the hot path; confidential kinds keep `MODERATE` and flags 5–8 refused on their ABI; chain
beats ranks and needs no rank table in any kind; `MODERATE` as its own bit distinct from `FORCE`, with every
balance-touching holder a contract (which also makes `UA_POOL` and a fake EOA holder impossible); (c) rejected on a
token, with the boundary "pinned at INIT, immutable code, one view, inherited power disclosed" to be stated; reduce-only
as a marker; rescue as "anyone, fixed destination, never the accounted asset" (asset suite, with A15/A16 corrections);
the bit's worst-case sentence for the token's **own** powers; "erase never exists" at the storage level (README:1095),
only the remove op is missing; §8's before-freeze list does not depend on the non-token answer; nested token holders
enforce each level's own limits at call time, so no subset proof is needed on tokens.

## 5. Generality: the owner's question

**Answer: yes for the vocabulary, no for the contract.** The scalar words (`[min, max]`, `total`, `perWindow/window`,
`validUntil`, `maxUses`) generalise; `fromSet`/`toSet` are the token's scope words; the holder clone is token-shaped.
The general form, as the generality answer put it and this round confirms:

```
Right  = (contract, selector)                 one typed entry per power, the id wallets already map (mtxSelectors)
Limits = {min, max, total, perWindow, window, validUntil, maxUses}      generic, GrantLib
Scope  = bytes32 whose meaning and partial order the application defines
Precond = application state, never in the grant
Grant  = (grantee, Right, Limits, Scope, grantor, epoch); use = app checks Precond, picks the scalar, GrantLib.check, its own scope predicate
Narrowing = GrantLib.narrows(child, parent) ∧ app.scopeNarrows(child, parent); revoke of a grantor bumps its epoch
```

Placement: each application checks its own rule with a shared `GrantLib` (internal library: `Limits`, `Spent`,
`check`, `narrows`, the `MandateWallet` window grid reused, est. 0.6–1 KB) and implements `IGrant` (ERC-165:
`grantOf`, `scopeNarrows`, `Granted`/`Revoked`/`Used`). A generic envelope over decoded arguments is rejected
(packed policy language, fixed word offsets only, impossible narrowing proofs, two-layer wallet display). The draft's
§3 (d) is this placement applied to tokens: the holder clone is the one application a token needs, implementing
`IGrant` with `scope = bytes32(bit)`; `IRoleEnvelope` becomes that instance, not a second standard. Non-generic by
nature: scope predicates and their order, state preconditions, which number the limit binds, per-key limits, co-signature
(an msig UA or an app rule), labels, custody vs user balances. Subjects on a `UAMetaTxBase` child are `bytes32`.

The three examples:

- **Family tree:** `FamilyTree` (immutable clone, `UAMetaTxBase`); rights `addMember` / `removeMember` (remove =
  tombstone with `ref`, reduce-only, history never erased); `Limits = {validUntil, maxUses}`; `scope = root person id`;
  `isDescendant(scope, parent)` at use; `scopeNarrows = isDescendant(parent, child)`; a `MAX_DEPTH` shape constant
  bounds the walk. Nothing from any token.
- **Circulation within a group:** either (i) custody, `GroupLedger` holds a plain `NORMAL` token and keeps member
  balances, right `moveWithin`, `scope = groupId`, both ends `isMember`, the token sees one holder; or (ii) balances in
  wallets, `NORMAL` + `ALLOWLIST` with the group's own contract as the registry pinned at INIT (receiver side,
  CTR-AS-07; the group admin's power disclosed, A13). (ii) is a token property, not a grant, and the only form that
  touches `_update`, on that token only.
- **Loan approval in [1 M, 100 M]:** `LoanBook`, right `approveLoan(loanId, amount)`, scalar = the named `amount`
  that the contract also pays, `Limits = {min 1 M, max 100 M, total = portfolio cap, validUntil}`, `scope = branchId`;
  preconditions `status == PENDING`, `borrower ≠ approver`; a committee grants `[1 M, 100 M]`, a manager sub-grants
  `[1 M, 20 M]` (`narrows`); two approvers above 50 M = msig UA (CTR-UA-37) or an app rule.

## 6. The seven owner questions, revised

1. **Ranks or chain:** chain, unchanged; add that the chain is enforced by `GrantLib.narrows` at sub-grant and an
   epoch kill at revoke, never by a walk (A19).
2. **Grant delay:** yes, in the A1/A2 form: `grantDelay` at INIT, owner calls `grantRole` twice (propose; confirm in
   `[eta, eta + grantDelay]`), no `executeGrant`, pending view + §4 step, pendings not in `holderCount`; carve-out
   deleted (A8); `WrappedPqzToken` excepted only if measured over the stop line. Revoke immediate, with the A9 caveat
   routed to the asset-suite stream. **Q2' (new):** delay `acceptOwnership` by the same integer? Contradicts C1; a
   stalemate, not recovery; recommend no unless the owner wants a visible handover.
3. **`MODERATE` + contract holders:** yes to both; add **`_addLeg` refuses a SCaaS leg carrying `FORCE` or
   `MODERATE`, every wrapped kind** (A4), recommended yes; `moderatedTransfer` on a contract `from` is a product
   decision, recommend allowed and disclosed.
4. **Envelopes in a holder, never in the token:** yes **for token powers**; application powers use `GrantLib` +
   `IGrant` in their own contract (A10). Step 5 trusts only a catalogued holder (A3). **Q4' (new):** catalogue as a
   separate immutable contract later (recommended: no pre-freeze bytecode) or a new `OpenFactory` domain before the
   freeze (A14).
5. **One `features` SLOAD on a plain transfer:** change the recommendation. As drafted it breaks the stated rule.
   Recommend: measure clone-with-immutable-args (A17, est. 20–30 gas, factory change before the freeze) against
   separate regulated implementations; the owner rules on the trade-off with numbers, not on "yes".
6. **DEX two-step + renounce:** yes; plus immutable `DexConfig.rescueTo` instead of `treasury` as the rescue
   destination (A15).
7. **Rescue:** yes, with the A16 post-check (foreign: legs unchanged; leg: that leg covered) and the DEX destination of
   Q6; `WrappedPqzToken` v1 without it if it measures over the line, dropped before `holderCount` (A21).

## 7. Before the EVM audit freeze, revised

Token or `AdminLib` / `WrappedLib` / factory bytecode, so it must land before the freeze:

1. `grantDelay` in the two-call form (A1, A2): `TokenConfig` field, pending word `(eta, proposer)`, window, view; no
   new entry.
2. Reserve bit 9 `MODERATE`, 0 B (unchanged).
3. `holderCount(bit)` counted in `_grant` / decremented on revoke and renounce; pendings excluded (A20).
4. DEX: two-step admin transfer + renounce + immutable `rescueTo` (A15).
5. Selector-audit test of the §4 sentence (no bytecode).
6. `rescueTo` + `rescue(asset)` with the A16 check; `WrappedPqzToken` only if it measures under the stop line.
7. **New, owner question:** `_addLeg` refusal of `FORCE`/`MODERATE` SCaaS legs on every wrapped kind (A4), library
   body, 0 token bytes.
8. **New, owner questions:** `acceptOwnership` delay (Q2'); `OpenFactory` catalogue domain (Q4'); clone-with-immutable-
   args for Q5 (A17). Each is factory or `AdminLib` bytecode if answered yes.

Measure `WrappedPqzToken` after 1, 3, 6 (A21) before the owner answers. Nothing for `GrantLib`, `IGrant`, application
contracts, `moderatedTransfer`, or the envelope catalogue is needed before the freeze.

## 8. Not covered

Nothing was run or measured: every byte and gas figure, including the CODECOPY estimate of A17, is [est.]. The
escalation report was truncated after its 7th finding and the `MODERATE` report after its 2nd; the parts not seen were
not judged. §10 rescue was attacked by reading only; the tender `owed` and relay-router rows were not re-derived. The
non-EVM mapping of §8 was checked for existence of admin powers (README §3, source greps), not designed per family.
Zodiac Roles and ERC-7710 remain unverified names. Consent and personal-data law for a family tree, and the templates
(`templates.md` does not exist), were out of scope. The owner's wording "cây gia phả của mình" (my instance vs my
subtree) and the "custom contract" parenthesis (token rule, delegate, or app custody) were tested by reading both
meanings, not resolved.
