> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**
>
> **Superseded by the built model:** [contracts/README.md §8](../../contracts/README.md#governance) and CTR-GOV-01 to -19 in [decisions.md](../../decisions.md#ctr-gov-01--governancebase-on-every-token-kind-and-the-dex); this note is the record of an earlier round, not rewritten.

# A general permission model for SCaaS contracts (2026-11-02)

**Version 1, kept for the record; superseded by [permission-model.md](permission-model.md).** Rebuilt from the agent's transcript, since version 2 overwrote the file before it was committed: three late edits could not be re-applied, so a few lines near the owner questions may differ.

Owner request (2026-11-02, translated): *"You are fixating on mint. That was only my example. There are many other
things related to granting authority. Is there a right or not? If right X is granted, which parameters are accepted,
what limits are there? Having a right is not the same as its parameters."* And: under the contract owner, should there
be owner – admin – moderators, or individual grants as today? This note derives the answer from the model; it builds
nothing.

Sources read: [README](README.md), [gov-inventory](gov-inventory.md) (2026-10-20, checked against `typed-signing`
below), [gov-survey](gov-survey.md), [gov-survey-2 §15](gov-survey-2.md), TODO "Governance matrix" and its 2026-10-21
inputs, [contracts/README §3](../../contracts/README.md#admin-powers-complete-list), CTR-TOK-22, CTR-AS-02…08/17,
CTR-DEX-03/23/24, CTR-UA-37 (typed-signing), tender I4, `AdminLib.sol`, `ITokenAdmin.sol`, `MetaTokenBase.sol`,
`NormalToken.sol`, `ERC20MetaTx._update`, `OpenFactory.sol`, `IFactoryToken.TokenConfig`, `size-baseline.json`,
[evm-size-levers](../evm-size-levers.md), the Soroban `token`, NEAR `token` and Solana `scaas` sources.
Tags: **[V]** verified by reading code or spec this session; **[I]** inferred; **[est.]** a byte or gas estimate, not
measured.

**Inventory check (2026-10-20 → typed-signing, 2026-11-02).** `AdminLib` is unchanged in substance (one rename commit
`d4550552`): two feature words, `owner` with a two-step transfer and no delay, `renounceOwnership` keeps role holders,
flat `roles[bit][account]`, role bits 1/3/4 only, flags 5–8 refused `FeatureNotBuilt`, `issuer`/`compliance` must be 0
[V]. `mint` still has no cap or rate limit ("lives in the minter contract") [V]. New since the inventory and relevant
here: named `mtx*`/`ua*` entries (TS-D14) and their byte cost; CTR-UA-37 (an msig authorises nothing until accepted
weight reaches its threshold, roles included); no EIP-7702 (an admin that is a designator is refused); `WrappedLib`
signatures take `(u, …, caller)`. The 2026-10-21 inputs (mint allowance, moderator transfer, hybrid underlying) are in
TODO only, nothing built [V]. Sizes today (`size-baseline.json`, typed-signing): `NormalToken` 37,228 B, `WrappedToken`
48,015 B, `NormalZetherToken` 52,741 B, `WrappedZetherToken` 62,169 B, `NormalPqzToken` 52,891 B, `WrappedPqzToken`
63,423 B (1,077 B to the 64,500 B stop line), `AdminLib` 3,272 B, `SCaaSDex` 27,957 B [V]. Marginal cost of one named
entry on a wrapped kind: +256 B `mtx`, +260 B `ua`, +341 B for the first entry of a new argument shape; with lever 2
+218 B / +135 B [V, levers §2].

## 1. The model

### 1.1 A power as an object

A **power** is an operation on an instance that somebody other than the balance owner may perform, or that changes the
instance's own rules. Every power has six attributes, and the owner's point is that the first three are distinct:

| Attribute | Question | Where it is answered today (tokens) |
|---|---|---|
| **existence** | does this instance have power X at all? | a bit of `features` [V] |
| **shape** | what can X do at most, whoever holds it (the hard bounds)? | compiled in the implementation: `MAX_FEE_PPM`, rate `RATE_WINDOW`, the specified 30 d / 7 d / record-gating of 5–8 [V] |
| **holding** | who may use X? | `roles[bit][account]`, several holders, no per-holder data [V] |
| **envelope** | which arguments does *this* holder's use accept, within what limits? | none; "a cap lives in the minter contract" [V] |
| **administration** | who changes holding or envelope, with what delay? | the `owner`, immediately [V] |
| **lock** | can any of the above be frozen forever? | `lockedFeatures` (existence can never be removed), `disableFeature` (existence removed forever), `renounceOwnership` (administration removed forever) [V] |

So the object, written as a record:

```
Power {
  id          : uint8  bit                         // MINT, FORCE, FREEZE, PAUSE, RATE, WRAP_DISABLE, GRANT, …
  exists      : bool   per instance (INIT), removable one-way unless locked
  shape       : constants of the implementation (never per instance)
  holders     : (holder → Envelope)*
  admin       : who may change holders/envelopes (today: owner), grantDelay
  lock        : existence-forever | existence-removed | administration-removed
}
Envelope {    // what one holder may do, always a subset of the shape
  perCall, total, perWindow+window, validUntil, maxUses,
  fromSet, toSet  ∈ {ANY, SELF, FIXED(addr), REGISTRY(addr, mask), RECORD}
}
```

**Attenuation rule** (the one rule the rest follows from): *the bit states the worst case; a holder's envelope only
narrows it, never widens it; a grantee's envelope is at most its grantor's.* A reader who knows `features()` knows the
worst that can happen to a balance before reading any holder. [I]

### 1.2 The constraint vocabulary, tested

| Constraint | Kind | Covers | Keep? |
|---|---|---|---|
| per call (`perCall`) | amount | mandate `maxPerPayment` [V, MandateWallet], moderator transfer, mint | keep |
| cumulative (`total`) | amount | USDC `minterAllowance` [V, survey 1.1], CTR-AS-04 `maxAmount` [V] | keep |
| per window (`perWindow`, `window`) | amount | mandate `maxPerPeriod` / `periodSeconds` [V], TODO 10-21 mint allowance [V] | keep |
| expiry (`validUntil`) | time | mandate `expiry` [V], ENS fuse expiry [survey P1] | keep |
| source / destination set | set | CTR-AS-04 record = one (subject, beneficiary) pair; CTR-AS-07 registry + mask [V]; escrow arbiter = two fixed parties | keep, but only the five forms above: no on-chain lists |
| self-only | set | mint to self, burn own | drop as a word: it is `toSet = SELF` |
| ratio (`maxStepBps`) | parameter | rate change only [V] | drop from the general envelope; stays the rate power's own field |
| delay | time | rate `rateDelay` [V]; grants (missing) | keep, as a field of **administration**, not of the envelope |
| co-signature | holder | FORCE = compliance record + issuer act [V] | drop as a constraint: two holders on one act is either `fromSet = RECORD` (the record is written by another role) or the holder being an msig (CTR-UA-37). Nothing in the token |
| one-shot (`maxUses`) | count | GateSeal [survey P4], tender `maxDisqualifications` [V], vesting revoke | keep, as a count beside `total` |
| reduce-only | property of the operation | `disableWrap`, `disableFeature`, `revokeRole`, `cancelRate`, tender disqualify, Pendle fee-down [survey P6] | keep, as a **marker on the power**, not a field |
| fuse | lock | `lockedFeatures`, `disableFeature`, `renounceOwnership` [V] | keep, as the lock attribute |
| **missing:** max duration + cooldown | time | freeze ≤ 30/60 d, cooldown 30 d; pause ≤ 7 d, cooldown 7 d [V, CTR-AS-05/06] | add, as **shape** constants, not envelope fields |
| **missing:** active window of the power itself | time | tender `dqWindow` [V], Balancer pause window [survey P2] | add to existence: `activeUntil` where a template needs it; 0 elsewhere |
| **missing:** instance cap | invariant | `maxSupply` of the hybrid underlying (TODO), `maxShielded` [V] | not a grant constraint: an instance invariant, set at INIT |

Result: nine words suffice — `perCall`, `total`, `perWindow/window`, `validUntil`, `maxUses`, `fromSet`, `toSet`,
`delay` (administration), `maxDuration/cooldown` (shape) — plus two markers, *reduce-only* and *lock*. [I]

### 1.3 The vocabulary against the powers the owner named

| Power | exists | shape (compiled) | holder | envelope that matters | reduce-only | change path |
|---|---|---|---|---|---|---|
| transfer by a third party ("moderator", TODO 10-21) | new bit `MODERATE`, `NORMAL`/`WRAPPED` only | public balances; own event; relayable | contract | `perCall`, `perWindow`, `total`, `validUntil`, `fromSet`/`toSet` ANY or FIXED | no | owner grants/revokes |
| forced transfer (CTR-AS-04) | bit `FORCE` | from a **frozen recorded subject** to the **recorded beneficiary**, ≤ `maxAmount` | `issuer` contract; record by `compliance` | `fromSet = toSet = RECORD` (the record is the envelope) | no | as flags |
| freeze (CTR-AS-05) | bit `FREEZE` | ≤ 30 d, extend ≤ 60 d, cooldown 30 d; open-ended only with a record | `issuer` | none beyond the shape; a `fromSet` would be a blacklist | no (unfreeze is) | as flags |
| blacklist | not a SCaaS power: freeze is the per-account form; `ALLOWLIST` is receiver-side through a registry [V] | — | — | `REGISTRY(addr, mask)` pinned at INIT | — | registry's own admin (inherited power, survey P21) |
| pause (CTR-AS-06) | bit `PAUSE` | ≤ 7 d, cooldown 7 d, unwrap never paused | `issuer` | none | no (unpause is) | as flags |
| rate change (CTR-TOK-06) | bit `RATE_ADJUSTABLE` | `rateDelay` 2–30 d, step ≤ 10 %, 7 d window, one pending | `rateAdmin` contract | none | no | `disableFeature` |
| fee change | none on tokens (every fee is signed per intent, ≤ 1 %) [V]; DEX `setFeeSplit` changes who receives, never the amount [V] | ppm ≤ 10^6 | DEX admin | none | no | none (no delay, no lock) |
| wrap disable | bit `WRAP_DISABLEABLE` | per leg, one-way | `guardian` | none | **yes** | `disableFeature` |
| reserve moves | **no outbound reserve power exists anywhere** [V, inventory row 100, CTR-AS-02]; `addReserve` is inbound, anyone | — | — | — | — | keep it absent: not a bit |
| DEX venue settings | always (an admin exists iff set at INIT) | `setMarket`, `setExchangeTarget`, `setListedOnly` | admin | none | listing both ways | **none**: no transfer, no renounce [V] |
| tender award | per instance (`dqWindow`, `maxDisqualifications`) | remove the leader only, never the last candidate, public `reasonRef` (I4) | buyer | `maxUses`, `activeUntil` | **yes** | fixed at creation |
| asset-suite issuer action (`VestingGrant.revoke`, `Distribution` funding, `ExchangeOffer` close) | `revocable` per grant | once | grantor | `maxUses = 1` | yes | fixed |
| a template's arbiter (escrow, README use case; `templates.md` does not exist, CTR-AS-14 keeps templates off chain) | per instance | release to one of two fixed parties, ≤ escrow balance | arbiter | `toSet = FIXED{buyer, seller}`, `maxUses = 1`, `validUntil` then a default path | no | fixed |
| record correction (family-tree / provenance registries, not specified) | per registry | **append** a correction that references the old record; erase never exists | author or corrector role | `fromSet = SELF` (own records) | n/a | registry owner |
| role grants (`grantRole`) | always while an owner exists | bit must be set (attenuation), some bits contract-only | owner | none | revoke is | **no delay** today [V]; renounce = fuse |
| rescue of stray assets and surplus (§10) | `rescueTo ≠ 0` at INIT | any asset the contract does not owe; never the accounted asset below what is owed | **nobody**: anyone triggers | `toSet = FIXED(rescueTo)`, `fromSet` = the unowed set, computed | n/a | none: destination immutable |
| rescue of stray assets and surplus (§10) | `rescueTo ≠ 0` at INIT | any asset the contract does not owe; never the accounted asset below what is owed | **nobody**: anyone triggers | `toSet = FIXED(rescueTo)`, `fromSet` = the unowed set, computed | n/a | none: destination immutable |

Two things fall out. First, the balance-touching powers differ from each other in **shape** and **set form**, not in
new vocabulary: FORCE is "third-party transfer with `fromSet = toSet = RECORD`", MODERATE is the same move with
`fromSet = toSet = ANY` and a per-holder amount envelope. Second, most non-token powers (tender, vesting, DEX) need no
amount envelope at all: they are reduce-only or count-bounded, and the vocabulary covers them with `maxUses` and
`activeUntil`. [I]

### 1.4 Is the general model too heavy for a token?

The full `Envelope` (3–4 storage slots per holder, a decoder and a checker per power) in every token kind: est. 1.5–3 KB
runtime per kind if inlined, est. 0.4–1 KB of stubs if the logic sits in `AdminLib` (external library, DELEGATECALL) —
and `WrappedPqzToken` has 1,077 B [V]. It is too heavy for the confidential kinds, and they must not have it anyway:
flags 5–8 (and `MODERATE`) are refused on `*_ZETHER` / `*_PQZ` [V, CTR-AS-17], so no entry of theirs changes. What
survives for every kind is what exists today: **existence bits, lock bits, flat holding.** The envelope lives outside
the token, in the holder (§3). Shape constants stay compiled. The vocabulary is then a **disclosure and holder-contract
standard**, not token code. [I]

## 2. Delegation

**Attenuation as the rule.** A grantor may only pass on a subset of its own envelope; a grant beyond the bit's
existence is impossible already (`RoleWithoutFeature`) [V]. The data today is two levels: an `owner` that administers
but only acts by granting itself a role, and leaf holders with the whole shape each [V, CTR-TOK-22 "the owner only
administers"]. There is no third level in storage and no per-holder data to attenuate.

**Three ranks or a chain?** Owner – admin – moderator as fixed ranks in the token means: a rank-2 table with its own
sub-grants, a second grant path, a second revoke path, on every kind, and an audit of two authorisation routes. A chain
of narrowing grants needs none of that in the token: the "admin" of the owner's question is a **holder contract** that
holds one bit and keeps its own sub-grants with envelopes — exactly USDC's `masterMinter → minter(allowance)` [V,
survey 1.1], and exactly what CTR-AS-03 already demands (`issuer` and `compliance` are contracts) [V]. The token sees
`owner` and leaf holders; depth is unbounded outside it. **The data supports the chain, not the ranks.** [I]

**A compromised key, per level** (what it can do at once, today → with the model):

| Level | Today | With grant delay + envelopes |
|---|---|---|
| owner key | grants itself every set bit immediately: the full worst case of `features` (mint unbounded, and once 5–8 exist freeze/force/pause within shape) [V] | the same worst case, but after `grantDelay` with a visible pending grant; holders can exit; an msig owner needs accepted members (CTR-UA-37) |
| "admin" (holder contract's admin) | n/a | bounded by that contract's envelope `total` / `perWindow`; cannot widen |
| leaf (moderator / minter) | the whole shape (unbounded mint) [V] | its envelope only; expiry ends it without any revoke |
| after `renounceOwnership` | existing holders keep the whole shape forever [V] | existing holders keep their **envelopes**: a surviving minter with `total` is a bounded residue, which is the right meaning of "renounce" |

## 3. Where it lives

Four placements, scored. Hot path = a plain `mtxTransfer` ≈ 41.8 k execution gas on the v2 path [V, metatx.md:763];
`_update` reads no `AdminLib` slot today [V].

| | (a) per-instance table in the token (INIT) | (b) compiled per implementation | (c) external policy consulted by a hook | (d) hybrid: bits in token, shape compiled, envelope in the holder |
|---|---|---|---|---|
| bytes, `NormalToken` / `WrappedToken` | est. +0.4–1 KB stubs + `AdminLib` growth; fits (28 / 17 KB headroom) | 0 per instance; one implementation per combination explodes the catalogue (the reason CTR-AS-17 chose flags) | est. +0.3–0.6 KB (one `STATICCALL` + decode per privileged entry) | **0** (holding and bits exist) |
| bytes, `WrappedPqzToken` (1,077 B) | does not fit if any entry is added; not needed (5–8 refused) | 0 | 0 if no hook on confidential kinds | 0 |
| hot path of a plain transfer | 0 for amount envelopes (read only on the privileged call); FREEZE/PAUSE/ALLOWLIST need one `features` SLOAD in `_update` (+2,100 gas cold) once built, on the two plain kinds only | same SLOAD | the same SLOAD **plus** an external call per transfer if the policy hooks `_update` | same SLOAD, envelope never on the path |
| audit surface | every kind's `AdminLib` path + the table coder | one code path | the hook, the policy contract and the trust in it | `AdminLib` unchanged + one small holder implementation audited once |
| disclosure | best: everything on the token | best worst-case, no per-holder limit | worst: a wallet must read another contract's code | bits on the token (worst case), `envelope()` on the holder (actual); a non-conforming holder = "worst case" |
| upgrade hatch? | no | no | **yes**: whoever can change the policy address, or the policy's own admin, changes the token's rules after deploy, against CTR-GEN-02 | no: the holder is an immutable clone; replacing it = revoke + grant, visible, same as rotating a key today |
| storage per grant | 3–4 slots in the token (est. 60–80 k gas) | 0 | per policy | 1 slot in the token (today) + an envelope clone (est. 3 slots + clone, ≈ 100–130 k gas) |

**(c) is rejected** as a policy consulted by the token: an external policy address in the token is an upgrade hatch
unless immutable and content-fixed, and then it is just (d) with an extra call. **(a)** is affordable on the two plain
kinds but duplicates on every kind what one holder implementation gives once. **(d)** is the recommendation: it is what
the code already does by intent ("a cap lives in the minter contract" [V]) made into a published, readable standard.
[I]

The holder implementation, sketched (interface only; it is a `MetaTxBase` child so its operator signs gaslessly, like
`MandateWallet`, and the window accounting of `MandateWallet` / the NEAR `Mandate` terms is reused, not rewritten):

```solidity
interface IRoleEnvelope {                 // one holder of one bit on one token; an immutable factory clone
    struct Envelope {
        address token; uint8 bit;         // which power it narrows
        address operator;                 // who may use it (EOA, Safe, msig UA)
        uint128 total;                    // cumulative amount left; type(uint128).max = unbounded
        uint128 perCall;
        uint128 perWindow; uint32 window;
        uint64  validUntil;               // 0 = none
        uint32  maxUses;                  // 0 = unbounded
        uint8   fromSet; uint8 toSet; address setRef;   // ANY | SELF | FIXED | REGISTRY | RECORD
    }
    function envelope() external view returns (Envelope memory);   // written once at creation
    function spent() external view returns (uint128 total, uint128 inWindow, uint32 windowStart, uint32 uses);
}
```

Size est. 10–15 KB (`MandateWallet`, which does the same accounting with an arbitrary `execute`, is 16,305 B [V]).
It is a new factory kind, published, versioned and immutable like a token; the token is untouched.

## 4. Disclosure: reading from chain what can be done to a balance

The reading order a wallet follows before accepting a token, all `view` and today's ABI unless marked:

1. `factory.isRegisteredToken(t)`, `versionOf(t)`: published code or `version() == 0` (unvetted) [V].
2. `kind()`, `features()`, `lockedFeatures()`: the **worst case**, one sentence per set bit, in the form of asset-suite
   §2.8 extended to `MINTABLE` and `MODERATE` (e.g. *"a moderator can move tokens out of any account"*). A bit absent
   from `features` can never appear [V]. `lockedFeatures` says which sentences are permanent.
3. `owner()`: 0 means nothing above can change, ever; otherwise *"the owner can grant any set bit"* (after `grantDelay`
   once it exists). If the owner is an msig UA, `memberAccepted` must reach the threshold or it can do nothing
   [V, CTR-UA-37].
4. Per set bit with a role: the holders. **Gap:** `hasRole(bit, acct)` is a point query; holders are enumerable only
   through `RoleGranted` / `RoleRevoked` events, which live in history [V]. Smallest fix: `holderCount(bit)` (one slot
   per bit, est. +100 B) so a wallet can check that its indexed list is complete; a full `EnumerableSet` is est. +1–2 KB
   on every kind and not worth it.
5. Per holder: if `supportsInterface(IRoleEnvelope)` then `envelope()` and `spent()` are the **actual** limits;
   otherwise the holder has the bit's whole shape and the wallet says so.
6. Regulated bits: `termsHash`, the pinned registry, `requiredFlags` (spec, CTR-AS-02/07).

The public "admin powers complete list" stays true per instance iff one sentence holds and is tested: **no entry point
moves, freezes or pauses a balance its caller does not own unless gated by a feature bit, and no feature bit exists
outside the list.** Today that is true [V: every privileged entry calls `requireRole` / `requireFeature` / `_onlyOwner`].
The selector audit of the freeze can pin it (every non-`mtx*` external that writes state, classified).

## 5. Rules that bind, and how the model keeps them

| Rule | In the model |
|---|---|
| confidential kinds: force never possible | `MODERATE`, `FORCE`, `FREEZE`, `PAUSE`, `ALLOWLIST` invalid for kinds 2–5 in `_validFor` [V]; the envelope standard is irrelevant to them; a minter never mints shielded value [V] |
| every state-changing `mtx*` relayable | the token gains no new `mtx*` for envelopes (nothing to relay); `MODERATE` ships as `moderatedTransfer` + its `mtx`/`ua` named entries (fee may be 0); the holder contract is a `MetaTxBase` child, so its operator relays too. **Gap today:** owner ops (`grantRole`, …) are direct-call only (not on `mtxSelectors`) [V, NormalToken]; a UA owner cannot administer gaslessly. Not an `mtx*` by name, so not a rule breach; note it |
| explicit named parameters | `Envelope` is a typed struct written once; `moderatedTransfer(from, to, amount, ref)` named; no packed bytes |
| an msig holder counts only with accepted members | unchanged: holding is an address; CTR-UA-37 decides whether that address can sign [V] |
| one rule on every chain family | "the bit states the worst case, a holder contract narrows" is expressible wherever a contract can be an authority: see below |
| no assumption about gas price or block limit | nothing time- or gas-dependent beyond `block.timestamp` windows already used by rates and mandates |
| contracts immutable | envelopes are immutable clones; changing one = revoke + grant on the token; no policy pointer anywhere |

Chain families (what each holds today, and what it cannot express):

| Family | Today [V] | Model mapping | Cannot express |
|---|---|---|---|
| Soroban `scaas-token` | `admin` set in the constructor; `mint` is admin-only; no `set_admin`, no freeze, no clawback | existence = MINT only, always; holder = `admin`; envelope = make `admin` a contract whose `__check_auth` enforces it | lock (no renounce entry), disable; would need a `renounce_admin` entry |
| NEAR `token` | `admin` set in `new`; `mint` admin-only; `admin()` view; no transfer | the same: `admin` = a contract account enforcing the envelope (predecessor check) | lock; same remedy |
| Solana | no SCaaS token program; any SPL / Token-2022 mint passing NET-SOL-09; `Config.admin` lists markets only | the mint's own authorities are the powers: mint authority (unbounded MINT, reassignable, `None` = fuse), freeze authority (FREEZE with **no duration bound**); a PDA of a policy program is the holder contract | duration/cooldown on freeze; record-gated force. **Gap [I]:** NET-SOL-09 refuses `NonTransferable`, hooks and transfer fees but not `PermanentDelegate`, which is an unbounded FORCE over every holder; the disclosure must read it, or the policy must refuse it |
| EVM, Hedera | as §1 | as §1 | — |

## 6. Today's powers on the model

| Power | exists | holder | envelope | admin / delay | lock | Fits? |
|---|---|---|---|---|---|---|
| `mint`, `mintToUA` | bit 1 | `minter`* | none (unbounded) | owner, none | disable / locked | fits; envelope missing |
| holder `burn` | bit 2 | the holder (`fromSet = SELF`) | own balance | — | always locked | fits |
| `proposeRate` / `executeRate` / `cancelRate` | bit 3 | `rateAdmin` (contract) | shape: delay, step, window | owner, none | disable | fits |
| `disableWrap` | bit 4 | `guardian`* | reduce-only | owner, none | disable | fits |
| `disableFeature` | owner exists | owner | reduce-only, not on locked | — | renounce | fits |
| `grantRole` / `revokeRole` | owner exists | owner | bit ∈ features; some contract-only | **no delay** | renounce | gap: no delay |
| `renounceRole` | — | holder | reduce-only | — | — | fits |
| `transferOwnership` 2-step | owner exists | owner | — | **no delay** (CTR-TOK-22 names a delayed form, not built) | — | gap |
| `renounceOwnership` | owner exists | owner | fuse of administration; **holders survive** | — | — | fits once holders have envelopes; today a surviving unbounded minter |
| `addReserve` | wrapped kinds | anyone | inbound only | — | — | fits (not a power) |
| flags 5–8 | refused `FeatureNotBuilt` | `issuer`, `compliance` (spec) | shape per CTR-AS-04/05/06/07 | owner | disable / locked | fits; the spec already has the shape |
| DEX `setMarket`, `setFeeSplit`, `setExchangeTarget`, `setListedOnly` | admin ≠ 0 at INIT | admin | ppm ≤ 10^6, never the amount | **none: no transfer, no renounce** | none | gap: no change path at all (a lost key = a frozen venue config forever) |
| Tender `disqualifyWinner` | per instance | buyer | `maxUses`, `activeUntil`, never the last | fixed | — | fits |
| `MandateWallet` mandate | per token | delegate | `perCall`, `perWindow`, `validUntil`, payee allowlist | owner, immediate; epoch kill switch | — | **is** the envelope, for a user's own power |
| Zether rollover mode | per account | the account | — | self | — | not a power over others |
| Factory `deployImplementation`, `deprecate`, `setKindEnabled` | always | registrar | `noticePeriod` on a release; none on the others | **registrar cannot rotate** | — | fits; registrar rotation is a known absence (inventory) |
| Soroban / NEAR `mint` | always | `admin` | none | none | none | fits; no lock |
| rescue / sweep | tokens, DEX, puller, factory: **absent** [V, inventory §12]; asset suite: `rescue(token)` / `sweepExcess()`, anyone, fixed destination (spec) [V]; Aptos `admin_sweep` [V, README §3]; Cosmos `Sweep` removed [V]; wallets: the owner's `execute` [V] | anyone (spec) / admin (Aptos) | `toSet = FIXED` | — | — | fits as the §10 power; the Aptos form (admin chooses) is the one to avoid |

\* several holders allowed, each with the whole shape [V].

## 7. Tokens A, B, C as configurations

Common: kind `NORMAL`, `decimals 0`, `owner` = the issuer's Safe (or msig UA with accepted members), `MINTABLE` set.
`PAYABLE` as the issuer wishes; not a permission.

| | A: only Admin mints/burns, nobody's tokens may be moved | B: a moderator mints/burns within limits | C: a moderator moves from anyone to anyone |
|---|---|---|---|
| `features` | `MINTABLE \| BURNABLE` | `MINTABLE \| BURNABLE` | `MINTABLE \| BURNABLE \| MODERATE` |
| `lockedFeatures` | `MINTABLE` if the right must exist forever, else 0 | 0 | `MODERATE` if the issuer promises it stays (rare); usually 0 so it can be fused off later |
| `roles.minter` | the Admin Safe itself | an `IRoleEnvelope` clone: `{operator: moderator, total, perWindow, window, validUntil}` | as B, or the Admin |
| `MODERATE` holder | **absent and impossible**: the bit is not in `features`, so no owner can ever grant it | absent | unrestricted: the moderator's Safe directly; limited: an envelope clone `{fromSet ANY, toSet ANY, perCall, perWindow}` |
| "burn" | the holder's own `burn` (bit 2); the Admin burning *others'* tokens would be a third-party move, which A forbids | the moderator burns its own balance; burning a user's points is a `MODERATE` move to a burn sink, which B does not have | `MODERATE` with `toSet = FIXED(burn sink)` if wanted |
| disclosure sentences | "the owner can mint without limit" | "a minter can mint up to N per window until T" | + "a moderator can move tokens out of any account [up to N per window]" |
| what a stolen moderator key does | nothing (no moderator) | mints up to the envelope | moves up to the envelope; unrestricted variant: everything, which is why Q7 makes that holder a contract |

Note the owner's A: "no moderator needed" is not a role left empty but a **bit left out**, which is the stronger
guarantee and already expressible today. B needs only the envelope holder. C needs the one new token power.

## 8. The smallest first step that closes no door

Tokens are clones of published implementations: anything that changes token bytecode or storage must be in the
implementation before the EVM audit freeze; anything that is a new contract can ship later.

**Before the freeze** (token or DEX bytecode):

1. **`grantDelay`** (uint32, `TokenConfig`, INIT, immutable; 0 allowed): `grantRole` becomes a pending grant executed by
   anyone after the delay; `revokeRole` stays immediate (reduce-only); a pending grant is cancelled by revoke. In
   `AdminLib` (+1 mapping, +1 field); token est. +250–450 B for `executeGrant` and the view; `WrappedPqzToken` est.
   +250 B — inside its 1,077 B but close; if C6 needs the bytes, confidential kinds may take `grantDelay = 0` only and
   skip the entry (`RATE`/`WRAP` roles are already contract-only). Replaces the specified
   `AccessControlDefaultAdminRules` (est. 2–3 KB) with one integer.
2. **Reserve bit 9 `MODERATE`** in `AdminLib`'s constants and `_validFor` (plain kinds only), refused `FeatureNotBuilt`:
   0 B of logic, so a later release never renumbers and wallets can hard-code the sentence.
3. **`holderCount(bit)`** (est. +100 B per kind) for the disclosure read of §4.
4. **DEX admin two-step transfer + renounce** on `SCaaSDex` (27,957 B; est. +500 B), the same shape as tokens.
5. The one-sentence invariant of §4 as a selector-audit test (no bytecode).
6. **`rescueTo` + `rescue(asset)`** (§10) on the kinds where the stub fits: `NORMAL`, `WRAPPED`, both Zether kinds,
   `NormalPqzToken`, `SCaaSDex`; `WrappedPqzToken` only if it measures under the stop line.
6. **`rescueTo` + `rescue(asset)`** (§10) on the kinds where the stub fits: `NORMAL`, `WRAPPED`, both Zether kinds,
   `NormalPqzToken`, `SCaaSDex`; `WrappedPqzToken` only if it measures under the stop line.

**Later releases** (new contracts, or a new implementation version):

- `IRoleEnvelope` and its factory kind (B is possible the day it ships; A is possible today).
- `moderatedTransfer(from, to, amount, ref)` + `mtxModeratedTransfer` / `uaModeratedTransfer` on `NORMAL` and
  `WRAPPED` (est. 1.2–1.5 KB: three entries + body + event); with flags 5–8 in the asset-suite stream, which already
  carries the `_update` SLOAD.
- `renounce_admin` on Soroban / NEAR tokens; the `PermanentDelegate` rule on Solana.

**Cut:** a per-instance policy table in tokens; three ranks in token code; generic co-signature; ratio outside the rate
power; on-chain source/destination lists; an `EnumerableSet` of holders; any policy address inside a token; OZ
`AccessControlDefaultAdminRules`.

## 9. Questions for the owner (each with the recommended answer)

1. **Ranks or chain?** Recommend the chain: the token knows `owner` and leaf holders; an "admin" is a holder contract
   with its own sub-grants. No rank table in any kind.
2. **Grant delay per instance at INIT (`grantDelay`, 0 allowed, immutable)?** Recommend yes; wizard default 2 days,
   dev chains 0. Revoke stays immediate.
3. **`MODERATE` as its own bit (free third-party move, bounded only by the holder), distinct from `FORCE`
   (record-gated), and every holder of a balance-touching bit (`MODERATE`, `FORCE`, `FREEZE`, `PAUSE`) a contract, as
   `rateAdmin`, `issuer` and `compliance` already are?** Recommend yes to both: a reader of `features()` must see the
   difference without reading a holder, and the "unrestricted moderator" of token C is then at least a Safe or an
   accepted msig; envelope clones satisfy it by construction.
4. **Envelopes in a published holder contract (`IRoleEnvelope`), never in the token?** Recommend yes; the token keeps
   flat holding. A holder that is not an `IRoleEnvelope` is disclosed as "whole shape".
5. **Accept one `features` SLOAD (≈ 2,100 gas cold) on a plain transfer of `NORMAL` / `WRAPPED` once FREEZE / PAUSE /
   ALLOWLIST are built?** Recommend yes; the only zero-cost alternative is separate regulated implementations, which
   CTR-AS-17 rejected. `MODERATE` and every amount envelope cost the hot path nothing.
6. **DEX admin: add two-step transfer + renounce before the freeze?** Recommend yes; today a lost admin key fixes the
   venue's listings and fee split forever.
7. **Rescue (§10): an immutable `rescueTo` at creation, anyone may trigger, never a role, and `WrappedPqzToken` v1
   ships without it if the stub does not fit under the stop line?** Recommend yes; the wizard defaults `rescueTo` to the
   issuer treasury (0 for a token that wants to promise "nothing ever leaves except by holders").

## 10. Rescue: assets a contract holds but does not account for

Owner addition (2026-11-02): contracts can hold assets they do not account for: tokens that strayed in, and surplus
left by operations. A rescuer is needed. Is it governance?

**It is a power** (it moves assets out of a contract) and the model places it in one line: existence per instance
(`rescueTo ≠ 0` at creation), **no holder** (anyone triggers), envelope `toSet = FIXED(rescueTo)` and `fromSet` = the
set of what the contract does not owe, computed in the call. Because the destination is fixed, who calls is
irrelevant, so there is no role, no grant, no delay and nothing to lock except existence (an immutable `rescueTo`).
A *rescuer role* that chooses the destination per call is the form to avoid: it is a balance-adjacent power with an
envelope, needs a holder, a delay and a disclosure sentence, and it is what Aptos `admin_sweep` does today [V]. The
asset suite already specifies the right form: `rescue(token)` / `sweepExcess()`, anyone, to a fixed `grantor` /
`sweepTo`, any token except the accounted one [V, asset-suite.md:558–559, 705]. [I]

### 10.1 Three classes of asset, and the invariant per kind

| Class | Example | Rescuable? |
|---|---|---|
| **stray foreign asset** | an ERC-20 sent to a token, the DEX, the puller, the factory; native coin forced in by `SELFDESTRUCT` or as a coinbase | yes, whole balance: the contract owes none of it |
| **surplus of an accounted asset** | a wrapped leg's `balanceOf − reserve` (sent without `wrap`, a positive rebase); a tender's `balance − Σ owed`; a vesting grant's `balance − (obligation − released)` [V, asset-suite.md:592] | yes, **only where the contract tracks what it owes exactly**; the surplus is `balance − owed`, never less than 0 |
| **the accounted asset itself** | a leg's `reserve`; the token's own units (`UA_POOL`, `SHIELD_POOL` are rows of its own ledger, not foreign assets); user funds inside a DEX settle | **never** |

The invariant that must hold and be proven per kind: **after any rescue, every obligation the contract tracks is still
covered.**

| Kind | What it owes | Rescuable set | Proof obligation |
|---|---|---|---|
| `NORMAL*` token | nothing in foreign assets; its own units are never a foreign asset (`_update` refuses `to == this` [V], so `balanceOf(this) == 0`) | every ERC-20 ≠ `this`; all native coin (no `receive()`, so only forced coin [V]) | `rescue(this)` refused; nothing else to prove |
| `WRAPPED*` token | `reserve_i` per leg; `Σ⌊reserve_i·q_i⌋ ≥ totalSupply()`; `reserve` changes only through wrap / `addReserve` / unwrap [V, WrappedLib header]; `_pull` measures the received delta, so a fee-on-transfer leg is accounted correctly [V] | per leg: `balanceOf_i − reserve_i` (native: `balance − reserve_native`); any non-leg ERC-20 whole | **after the transfer, every leg still has `balanceOf_i ≥ reserve_i`** (≤ 8 reads, the same `ReserveShortfall` check `_pull` makes [V]). This one check also defeats the alias attack of §10.3 |
| `*_ZETHER`, `*_PQZ` | as the plain kind of their tier; the shielded total is their own units at `SHIELD_POOL` | as the plain kind | the same; the rescue never names `this`, so no pool row can move |
| `SCaaSDex` | nothing at rest: "between calls the DEX holds no user funds" [V, CTR-DEX-23]; in-call surplus is already paid to the signers [V, CTR-DEX-21] | everything at rest | `nonReentrant` (a rescue cannot run inside a settle); destination = the existing `treasury` (0 ⇒ no rescue, stays as today) |
| `DexPuller` | nothing (transit only, `pull(token, from, amount)` [V]) | everything | to the DEX's `treasury` |
| relay router (`MtxRelayFee`) | nothing [I: the fee moves inside the token from `from` to `payee`] | everything | if it holds nothing by construction, a rescue is still cheap insurance; low priority |
| `MandateWallet`, `SmartKeyAccount` | the owner's own funds | n/a: the owner's `execute(target, value, data)` [V] is the rescue | nothing |
| `OpenFactory` | nothing; not payable [V] | ERC-20 strays only | skip: not a value-holding contract; a stray to the factory is the sender's loss |
| `SealedBidTender` | `Σ minDeposit` over bids not `DONE` + live bonds (I2) [V] | `balance − owed` of the deposit token; other tokens whole | I6 says plain transfers are "unrecoverable" today [V]; with exact `owed` the surplus is rescuable, else leave I6 |
| `VestingGrant`, `Distribution`, `ExchangeOffer` | `obligation − released` / unclaimed | as specified: `sweepExcess`, `rescue` [V] | already in the spec |

Where `owed` is not tracked exactly on chain, **no surplus rescue**: only foreign assets. That is the rule, not a
heuristic.

### 10.2 Who decides what; refunds

- **Existence and destination:** the creator, at creation, in `TokenConfig.rescueTo` (`DexConfig.treasury` already
  exists for the DEX). Immutable: a changeable destination is a power with a holder again. `0` = no rescue ever, which
  is the stronger promise and what every token has today.
- **Trigger:** anyone, any time, no delay (the destination cannot be worse than the day before). A relayer may call it
  directly; it needs no signature, so it is not an `mtx*` and the relayable rule does not bind it.
- **Refund of a stray's owner:** the contract cannot know who sent a stray (an ERC-20 `transfer` leaves only a
  `Transfer` log, in history). An on-chain claim would need the sender to prove a pruned event. So: **not on chain.**
  The destination (the issuer's treasury) refunds on proof of the transfer, off chain, as its own policy; the
  disclosure says so. A destination that is an `IRoleEnvelope`-style contract could pay back automatically, but that is
  the destination's business, not the token's.
- **How a holder sees it:** `rescueTo()` view and one sentence: *"Assets sent to this token by mistake, and any
  underlying above the reserve, can be moved by anyone to X; the reserve and your balance never."* In the admin powers
  list it is a row with holder "anyone".

### 10.3 A malicious `asset` argument

`rescue(address asset)` with `asset` chosen by the caller is the whole attack surface:

| Threat | Answer |
|---|---|
| reentrancy from the asset's `transfer` (hook token) | `nonReentrant`, as every entry [V]; the surplus is computed before the call and the post-check runs after |
| griefing: an asset that reverts, burns gas, returns false | only the attacker's own call fails; `safeTransfer`; no gas cap needed (nothing waits on it), unlike the DEX's W-O calls where a third party's settle would fail |
| `asset == this` | refused explicitly |
| **an accounted asset behind another address** (a double-entry token: a second contract exposing the same balances and `transfer`) | `reserveOf(alias) == 0`, so the computed surplus would be the whole reserve. The address-based rule cannot catch it; the **balance-based post-check can**: after the transfer, every leg's `balanceOf_i ≥ reserve_i` or revert. This is why the proof obligation is stated on balances, not addresses |
| rebasing leg | a negative rebase gives `balance < reserve`: shortfall, nothing rescuable, wrap and top-up already refuse [V]; a positive rebase is surplus, but it is the holders' gain: the wizard refuses rebasing legs (asset-suite says v2 legs have neither fee nor rebase [V]) |
| fee-on-transfer leg | `reserve` is the measured delta [V], so surplus is exact |
| native coin | `rescue(address(0))`: `balance − reserve_native` (0 if no native leg); no `receive()` on tokens, so only forced coin arrives |

### 10.4 Bytes and the freeze

One direct entry, body in the external library (`WrappedLib.rescue` for the wrapped kinds, `AdminLib` for the rest), the
token paying a stub of the existing one-`address` shape (`transferOwnership(address)`): est. +150–250 B per kind, +~400
B of library. `NormalToken` (37,228 B) and `WrappedToken` (48,015 B) take it without question; the Zether kinds and
`NormalPqzToken` have 2.5–12 KB. **`WrappedPqzToken` has 1,077 B** [V], and the levers note says to treat a margin
under 1 KB as none [V, levers §2]: measure; if it ends over the 64,500 B stop line, **v1 of that kind ships without
rescue** (strays stay stuck, as every token today) and the next implementation version adds it. No other lever is
worth pulling for it. `SCaaSDex` (27,957 B): est. +300 B, `treasury` as the destination.

**Before the freeze:** yes for the kinds that take the stub, because the destination and the entry are token
bytecode and a clone cannot gain them later. The library body is audited once. The asset-suite contracts carry theirs
in their own stream.
