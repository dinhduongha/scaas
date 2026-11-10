# Wrap and unwrap limits on the wrapped kinds — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-10 from the owner's rulings of 2026-11-10 (below), on
branch `ua-mtx-merge`, read against the code at `39c3c6f1`. Revised the same day twice: R9–R11 (a separate `redeemer` role,
Sybil accepted, the decay of the net-wrapped entitlement, §2.1), then **approved by the owner 2026-11-10 with every question
ruled** (R12–R25; §12 maps each question to its ruling): the limits apply to **hybrid tokens only** (R12), everything else as
recommended. Plan: group 3l of [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md); the build runs later in its
own worktree. No gas or size figure here was measured: **[estimate]** is arithmetic over
measured inputs, **[measured]** is quoted from a run already committed. Rules read: [token-wrappers.md](../../contracts/token-wrappers.md)
(CTR-TOK-04, -05, -07, -20, -22, -24, -26), [decisions.md](../../decisions.md) (CTR-GOV-09 to -12, -17 to -19, CTR-TOK-30), the
governance spec [2026-11-02-governance.md](2026-11-02-governance.md) §1.6, the T66b spec
[2026-11-09-t66b-library-organisation.md](2026-11-09-t66b-library-organisation.md) §3.4, §4.2, §4.6, §11, the pay-meta-tax spec
[2026-11-05-pay-meta-tax.md](2026-11-05-pay-meta-tax.md) Q9 (which notice period), and the sources `WrappedLib`,
`WrappedTokenCore`, `WrappedZetherTokenCore`, `WrappedPqzTokenCore`, `RegulatedBase`, `GovernanceLib`, `GovernanceBits`,
`GovernanceRouter`.

**Owner rulings applied, not reopened (2026-11-10):**

| # | Ruling |
|---|---|
| R1 | Two independent limits per direction (wrap, unwrap), each `(amount, period)`: a short one (for example 1k or 2k per day, `period = 86,400` s) and a long one (for example 7, 30 or 60 days; the period configurable). Each is off when its amount is 0. A wrap must fit both wrap limits, an unwrap both unwrap limits. |
| R2 | Fixed windows, not sliding: a window starts at the first use after the previous window ended and lasts `period`. A sliding window would need about one bucket per day per user, too much state gas. |
| R3 | Per user, plus an optional token-wide cap per limit. |
| R4 | "Unwrap ≤ own net wrapped", a separate option, default off: a user may unwrap at most the underlying they wrapped, net of their earlier unwraps. It is not the long window. |
| R5 | A wrapper list and an unwrapper list, each optional, default open to everyone, managed by a role. |
| R6 | The token owner sets them, through `GovernanceRouter`. Tightening takes effect at once (a lower amount, a list turned on, the net option turned on); relaxing waits the notice period (a higher amount, a list turned off, the option turned off), after the `_delayedRelaxBits` pattern. |
| R7 | One slot per user, packing both windows' starts and used amounts and the net-wrapped amount. |
| R8 | The wrap and unwrap bodies live in body module W (T66b). |
| R9 | (Q2) A separate **`redeemer` role** is exempt from the net-wrapped rule: merchants who receive payments. |
| R10 | (Q5) Sybil: accepted as is. Per-user caps stay; no anti-Sybil measure. |
| R11 | **The net-wrapped entitlement decays over time**, configurable and turned on and off separately from the net rule. Purpose: foreigners wrap a foreign stablecoin (for example USDC) to get the domestic token and spend it; if they do business they can unwrap their own money back; if they leave it unused, the foreign currency stays in the economy as liquidity for others to unwrap. The owner's example: after a year without unwrapping, half of what was wrapped is unwrappable; after two years, nothing. |
| R12 | (Q12) **Hybrid tokens only.** A hybrid token both mints and wraps: the issuer mints a supply (`maxSupply ≠ 0`), and users wrap and unwrap the underlying. The owner's example: the state issues a kVND CBDC on a public chain, 100 billion minted; citizens may wrap and unwrap to create kVND. The limits apply to hybrid tokens of the wrapped kinds 1, 3, 5, 9, 11, 13. A pure-wrap token (`maxSupply = 0`) does not get them: creating one with bit 25 or 26 is refused with a named error (bit 27 likewise, §2). Issuer mints never count and never add to anyone's net. |
| R13 | (Q1) **Holder protection on unwrap.** Tightening the unwrap side waits the notice period, so holders can exit first; relaxing it applies at once. The wrap side stays as R6 rules: tightening at once, relaxing waits. The decay follows the unwrap rule (on or a shorter `H` waits, off or a longer `H` at once). Membership changes and a redeemer's revoke stay at once. |
| R14 | (Q3) **Whose quota: the subject**, never `msg.sender` of a relay: the direct caller, the signer of a relayed op, the signer of a DEX wrap order (`o.from`), the proof's sender of an unshield-unwrap. The net credit goes to the id that receives the units (`to`, `toUA`, the order's destination). Service pulls move no reserve; a future liquidity module wraps through `mtxWrapOrder`. A contract that wraps for itself is its own subject, under the per-user parts like any id, with no exemption list; it may hold the redeemer role. |
| R15 | (Q4) **Per leg**, in that leg's own units and decimals: each leg its own four limits, token-wide caps, `unit`, decay and net; one slot per id and leg. |
| R16 | (Q6) **The fixed-window burst is accepted**: up to 2× a cap within one `period` across a window boundary; documented. |
| R17 | (Q7) **Amounts are the underlying moved**: a wrap's measured `received` (for a fee-on-transfer leg what arrived), an unwrap's `out`. |
| R18 | (Q8) **No new stop.** 0 means no limit; the stops are the existing powers (`disableWrap`, `PAUSE`, `FREEZE`); an unwrap near-stop is an unwrap tightening and waits the notice (R13). |
| R19 | (Q9) **Views, events, pre-checks as specified**: the remaining quota per user and token-wide with the next window's start, the entitlement and the day it reaches 0, events on every setting and membership change, the node's named refusal before any submission. |
| R20 | (Q10) **Defaults**: every limit, list, the net rule and the decay off until set; the bits chosen at creation, off by default; nothing ever on tokens of earlier releases. |
| R21 | (Q11) **The delay is the factory's `noticePeriod()`**, with the two-call shape of `_delayedRelaxBits`. |
| R22 | (Q13) **Quanta, one slot** per id and leg, the unit fixed by the first configuration, windows in minutes. |
| R23 | (Q14) **The decay's shape: (a), linear to zero over one horizon `H`.** |
| R24 | (Q15) **The decay's clock: the weighted-average start**, against dust wraps. |
| R25 | (Q16) The round trip's rejuvenation is accepted and disclosed (under "everything else as recommended"). |

**Confirmed by the owner 2026-11-10, at the build's start:** R25 as written (an unwrap, then a wrap again, refreshes the weighted
start; accepted and disclosed), and bit 27 under R12 (`REDEEMER` is refused on a pure-wrap token at `initToken` with
`WrapControlNeedsHybrid`, like bits 25 and 26).

**Contents**

1. [Scope: kinds and paths](#1-scope-kinds-and-paths--specified)
2. [The model](#2-the-model--specified)
3. [Mint, burn and the other paths that do not count](#3-mint-burn-and-the-other-paths-that-do-not-count--specified)
4. [Order of checks](#4-order-of-checks--specified)
5. [Storage and its bounds](#5-storage-and-its-bounds--specified)
6. [Setting the limits](#6-setting-the-limits--specified)
7. [Errors, events, views](#7-errors-events-views--specified)
8. [Placement and size](#8-placement-and-size--specified)
9. [Node, clients, vectors, families](#9-node-clients-vectors-families--specified)
10. [Gas](#10-gas--specified-estimates)
11. [Tests, mutants, pins, on-chain rows](#11-tests-mutants-pins-on-chain-rows--specified)
12. [Owner questions](#12-owner-questions)
13. [Tasks and estimates](#13-tasks-and-estimates--specified)

## 1. Scope: kinds and paths — SPECIFIED

**Kinds and tokens (R12).** **Hybrid tokens** of the six kinds that hold a reserve: `WRAPPED` (1), `WRAPPED_ZETHER` (3),
`WRAPPED_PQZ` (5), `WRAPPED_REGULATED` (9), `WRAPPED_ZETHER_REGULATED` (11), `WRAPPED_PQZ_REGULATED` (13). A hybrid both mints and
wraps: its issuer mints a supply under `maxSupply ≠ 0` (with `MINTABLE`, CTR-GOV-12) and users wrap and unwrap the underlying (the
owner's example: a kVND CBDC on a public chain, 100 billion minted, citizens wrapping and unwrapping). A pure-wrap token
(`maxSupply = 0`) never gets the limits: its creation with bit 25, 26 or 27 is refused (`WrapControlNeedsHybrid`, §2), so it reads
nothing new. Within a hybrid every leg count is covered, one leg or up to eight (CTR-TOK-07), the native-coin leg included
(CTR-TOK-26). The normal kinds 0, 2, 4, 8, 10, 12 have no reserve and are untouched; kind 8's W module holds only the
regulated powers and does not change.

**Paths.** Every entry that moves underlying into or out of the reserve against wrapped units counts, direct or relayed. A
relayed form runs the same body under the signer (the self-call of `_named` / `_namedUA`, `MetaTxBase._selfCall`), so one check
inside the body covers the direct entry, its named `mtx*` form, `mtxExecute` with that calldata and each item of `mtxBatch`.

| Path | Entries (kinds) | Module | Counts as | Quota and lists of | Net credited to / debited from |
|---|---|---|---|---|---|
| wrap | `wrap(uint256)`, `wrap(address,uint256)`; `mtxWrap`, `mtxWrapLeg`; `mtxExecute` / `mtxBatch` items (1, 3, 5, 9, 11, 13) | W (`mtx*` forms in W, `mtxExecute` / `mtxBatch` in P; both self-call into W) | wrap, the received underlying | the subject: the direct caller, or the signer | the same id |
| wrap into a UA | `wrapToUA`, `mtxWrapToUA` (all six) | W | wrap | the payer (the subject) | `to`, the UA credited (R14) |
| wrap-shield | `mtxWrapShield`, direct and relayed (3, 5, 11, 13) | Z (3, 11), Q (5, 13) | wrap | the payer (the subject) | `toUA`, the shielded receiver |
| the DEX's wrap order | `mtxWrapOrder(address, UAWrapOrder, UASig)` (CTR-TOK-20; all six) | T | wrap, `o.amount` (= received) | `o.from`, the order's signer; never `msg.sender`, the submitter | `o.destination`, or `o.from` when 0 |
| unwrap | `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)`, `unwrap(address,uint256,address,uint256)`; `mtxUnwrap`, `mtxUnwrapLeg`; `mtxExecute` / `mtxBatch` items, a derived UA's included | W | unwrap, the underlying paid out (`out`) | the subject: the caller, or the signer's id (a derived UA, never `UA_POOL`) | the same id |
| unwrap into a UA | `unwrapToUA`, `mtxUnwrapToUA` (all six) | W | unwrap | the subject | the same id |
| unshield-unwrap | `mtxUnshieldUnwrap`, direct and relayed (3, 5, 11, 13) | Z, Q | unwrap | the proof's sender: Zether `ZetherLib.uaOf(b.yFrom)`, PQZ `b.fromUA`; never the envelope's `from` or the submitter, since anyone may submit another account's proof | the same id |

**Why each.** A limit bounds the reserve's inflow and outflow, so every entry that changes `reserve` against units counts, and
nothing else (§3). The relayed forms must count: otherwise a signature would bypass a limit the direct call obeys, against
"every state-changing `mtx*` is relayable" holding the same rule. `wrapToUA` and the wrap-shield count on the payer, who brings the
underlying in; their net credit goes to the id that receives the units, so a holder who wraps into its own UA or its own shielded
balance can unwrap it later (R14). The wrap order counts on `o.from` because the order's signer is the depositor; the submitter
only relays and takes `fee` in units minted to it, with no net credit. The unshield-unwrap counts on the proof's sender, as
FREEZE already reads it on the regulated confidential kinds (CTR-GOV-17); both ids are public on that path today (a Zether burn
names its account, a PQZ burn its `fromUA`), so the limits leak nothing new. The DEX's `mtxExchange` (CTR-DEX-20) and every trade of
wrapped units against the underlying on a market move no reserve and are not unwraps.

## 2. The model — SPECIFIED

**Per leg, in the leg's own units (R15, R17).** A token of `n` legs has, per leg `i`, four limits — `wrapShort`, `wrapLong`,
`unwrapShort`, `unwrapLong` — each a `WrapLimit { uint24 perUser; uint64 tokenWide; uint32 period; }`, and a decay horizon
`decayDays` (§2.1). Amounts are in **quanta** of the leg's `unit = 10^unitExp` raw units of that underlying (§5 gives why: R7's
one slot). The amount that counts is the underlying that moved: on a wrap the measured `received` (a fee-on-transfer leg counts
what arrived; a wrap order's `received == o.amount`; a native leg's `msg.value`); on an unwrap the `out` the reserve pays
(`UnderlyingTransferMismatch` makes the reserve's drop exactly `out`; a fee-on-transfer recipient may get less, `out` still
counts). Counting in the leg's underlying, not in wrapped units, keeps a limit stable across a rate change (CTR-TOK-04) and makes
R4 literal: "the underlying they wrapped".

**A limit's two parts.** `perUser` bounds one id per window, `tokenWide` all ids together per window; each part is off at 0
(R1). When either part is on, `period` is required: a whole number of minutes, `60 ≤ period ≤ (2^23 − 1) · 60` s (≈ 15.9
years); with both parts off it must be 0. Short and long are labels: nothing requires `wrapShort.period < wrapLong.period`.

**A use.** For an amount `x` (raw) on leg `i`, `q = ⌈x / unit⌉` quanta. For each limit of the direction whose part is on, with
the stored window `(start, used)` of that part (the user's for `perUser`, the token's for `tokenWide`), in minutes:

```
nowMin = uint24(block.timestamp / 60)
active = used != 0 && uint24(nowMin - start) <= period / 60     // modular in 2^24 minutes, §5
base   = active ? used : 0
if base + q > cap:  revert (WrapLimitExceeded | WrapCapExceeded)(…, remaining = (cap - min(base, cap)) * unit)
start  = active ? start : nowMin;  used = base + q              // a new window starts at this use (R2)
```

A window so lasts from its first use for more than `period` and at most `period + 60` s: the minute's rounding can only
refuse, never allow (the price of R7's one slot once the decay state is in it, §5). A wrap must fit both wrap limits and their
token-wide parts; an unwrap both unwrap limits and theirs (R1). All writes of a use happen or none (one revert). A part that is
off is neither read nor written. A limit lowered below a window's `used` leaves `remaining = 0` until the window ends; a part
turned on later may meet a stale window of an earlier time it was on, which can only refuse more, never less.

**Net wrapped (R4).** Per id and leg, a **base** `b` in quanta and its **start day** `s`. Once the token holds bit 25 and the
owner has written the first configuration (§6), every wrap credits the credited id and every unwrap debits the holder, **whether
the rules are on or off**, so turning a rule on later counts every wrap since the first configuration. Without the decay, `b` is
the plain net: `Σ ⌊received / unit⌋ − Σ ⌈out / unit⌉`, saturating at `2^32 − 1` and at 0. Rounding goes against the user both
ways: less than one `unit` per wrap is never redeemable under a rule, and that is disclosed. `b` is an upper bound per id, not a
balance: transfers, payments, FORCE and OPERATOR_TRANSFER move units and never move `b`; a user who wrapped, paid the units away
and bought them back keeps its `b`.

**The entitlement and its rule.** The amount an id may unwrap under a rule is its entitlement `E` (§2.1: `E = b` without the
decay, the decayed value with it). Two independent switches decide whether it is checked:

| `netUnwrap` | `decayDays` | An unwrap of `q` quanta needs |
|---|---|---|
| off | 0 | nothing |
| on | 0 | `q ≤ b` (R4) |
| off or on | `H ≠ 0` | `q ≤ E(now)`, the decayed entitlement (R11) |

**Redeemers (R9).** Bit 27 `REDEEMER`, a role: its holders skip the entitlement check, net and decay alike, and nothing else
(the lists, the per-user parts and the token-wide caps still bind them). A merchant paid in wrapped units never wrapped them;
the role lets it redeem. The owner grants and revokes it with the existing governance ops (`grantRole`, `setGrant`, `revokeRole`
through `GovernanceRouter`; a grant is a widening and waits `grantDelay` as every grant does, a revoke applies at once). The
role is read only when an unwrap would otherwise be refused, so a normal unwrap pays nothing for it. A redeemer's `b` is still
updated, so it carries its record if the role is revoked.

**Lists (R5).** Per token, not per leg: `wrapList` (only ids with `canWrap` may wrap) and `unwrapList` (only ids with
`canUnwrap` may unwrap). The wrapper is the payer of §1, the unwrapper the holder of §1. Membership is a byte per id written by
the holders of bit 26 at once both ways; the lists' on and off are the owner's (§6). Lists are valid on the confidential kinds
too: the payer of a wrap-shield and the sender of an unshield-unwrap are public, unlike the decoy receivers that rule
`ALLOWLIST` out on those kinds (CTR-GOV-17).

**Feature bits (R20).** Three new SCaaS bits (band 0–127, CTR-GOV-10), the next free numbers at this commit; the build takes the
next free ones if another spec takes these first:

| Bit | Name | Type | Kinds | Holder | Meaning |
|---|---|---|---|---|---|
| 25 | `WRAP_LIMIT` | capability | hybrids of 1, 3, 5, 9, 11, 13 | none (the owner sets) | the owner may set the four limits per leg, their token-wide caps, the net rule and the decay |
| 26 | `WRAP_LIST` | power | hybrids of 1, 3, 5, 9, 11, 13 | any holder (EOA, `msig`, contract), never contract-only, not delay-relaxed | the owner may turn the two lists on and off; a holder writes members (`canWrap`, `canUnwrap`) |
| 27 | `REDEEMER` | power | hybrids of 1, 3, 5, 9, 11, 13 | any holder (EOA, UA, `msig`, contract), never contract-only, not delay-relaxed | a holder may unwrap beyond its entitlement (R9) |

All three join `WRAPPED_BITS`; 26 and 27 join `WRAPPED_ROLES`; the normal kinds refuse them (`FeatureInvalidForKind`). **Only a
hybrid takes them (R12):** `WrappedLib.initToken`, beside today's `MaxSupplyInvalid` check, refuses any of the three when
`maxSupply == 0` with `WrapControlNeedsHybrid(uint8 bit)`; bit 27 goes with them because it exempts from a rule only bit 25 sets. Features
only lose bits after creation, so a token created without 25 and 26 can never limit anyone, which a holder reads at a glance (the
reasoning of CTR-GOV-18). Bits 26 and 27 stay out of `_delayedRelaxBits`: a compromised lister is revoked at once (the reason bit
23 is not delayed, pay-meta-tax Q5), and a revoked redeemer loses its exemption at once. Disabling 25, 26 or 27 is refused while
a control under it is on or, for 27, while it has holders (`WrapControlActive`), so a relaxation cannot skip §6's delay through
`disableFeature`, and an unwrap tightening for every redeemer at once needs the revokes, each visible.

**Sybil (R10).** Per-user caps can be split across many UAs; accepted, no anti-Sybil measure (owner 2026-11-10).

**Fixed-window burst (R16).** Using a whole window at its end and the next at its start moves up to `2 × perUser` (and
`2 × tokenWide`) within one `period` across the boundary. Accepted (R2); a long limit bounds the repetition; disclosed.

### 2.1 The decay of the entitlement (R11)

**Shape (R23): linear to zero over a horizon `H`** = `decayDays`, one parameter per leg, 0 = off, `1 ≤ H ≤ 65,535` days. With
the age `g = today − s` in whole UTC days (`today = ⌊block.timestamp / 86,400⌋`):

```
E(now) = ⌊ b · (H − min(g, H)) / H ⌋
```

The owner's example is `H = 730`: a wrap of `a` gives `E = a` on its day, `a/2` after 365 days, 0 after 730. The entitlement
steps once a day.

**The start: a weighted average (R24).** "Counted from the last wrap", read literally, is gameable: a 1-wei wrap would reset the
clock for the whole balance. A wrap instead moves the start by the weight of what it adds against what is there, and rescales the
base so the value at that moment is exact. A wrap of `received`, `a = ⌊received / unit⌋` quanta, at age `g` (clamped `g_c = min(g, H)`):

```
if a == 0:   nothing changes                               // dust below one unit moves neither the base nor the clock
decay off:   g' = b == 0 ? 0 : ⌈ b · g / (b + a) ⌉;   b' = min(b + a, 2^32 − 1)
decay on:    E  = ⌊ b · (H − g_c) / H ⌋
             g' = ⌈ E · g_c / (E + a) ⌉                    // the age, weighted by value; rounded older
             b' = min( ⌊ (E + a) · H / (H − g') ⌋,  b + a,  2^32 − 1 )
s' = today − g'
```

The clock is kept while the decay is off, so turning it on later counts each id's real age. An unwrap of `q ≤ E` quanta keeps
`s` and lowers the line so that the entitlement drops by exactly `q`:

```
decay off:   b' = b − q
decay on:    b' = ⌊ b · (E − q) / E ⌋                      // = b − q·H/(H − g): the decayed share of q goes with it
q > E (a redeemer, or no rule on):  b' = the same formulas saturating at 0
```

Reducing `b` by `q` alone under the decay would be wrong: the entitlement would drop by less than `q`, and repeated unwraps
would sum to `b`, the undecayed amount (a mutant, §11).

**Bounds.**

- **No division by zero.** If `E = 0` (fully decayed, or `b = 0`), `g' = 0` and `H − g' = H ≥ 1`. If `E > 0` then `g_c < H`,
  and with `a ≥ 1`, `g' ≤ g_c < H`.
- **The base never grows past what was added.** With the exact age `g* = E·g/(E + a)` and the exact `E = b(H − g)/H`,
  `H − g* = (E(H − g) + aH)/(E + a)`, so `b'* = (E + a)²·H / (E(H − g) + aH) = (E + a)² / (E²/b + a) ≤ b + a` (the Cauchy–Schwarz
  form `(x₁ + x₂)² / (x₁²/y₁ + x₂²/y₂) ≤ y₁ + y₂`). Rounding `g'` up only makes the line older; the `min(…, b + a)` clamp keeps the
  bound under rounding. An unwrap gives `b' ≤ b − q` because `E ≤ b`. So at every moment **`E ≤ b ≤` the plain net**: the decay
  never allows more than R4 would, and turning the decay off never gives more than the plain net (it gives back the decayed share
  of what was not yet used; every use under the decay settles the decay up to that use).
- **Dust.** A wrap of `a` quanta moves the age by `g_c · a / (E + a)`: a one-quantum wrap against `E = 10^6` moves it by a
  millionth of `g` (and by nothing after the round-up); halving the age takes a wrap as large as the whole current entitlement,
  which is new money brought in.
- **Products.** `b · H ≤ 2^32 · 2^16`, `(E + a) · H ≤ 2^33 · 2^16`, `b · g` with the decay off `≤ 2^64`: all in `uint256` with
  room; `s` is an absolute day in `uint32`, which cannot overflow before the year 11,000,000, and `today − g' ≥ 0` since
  `g' ≤ g`.
- **A round trip rejuvenates (R25).** Wrapping fresh money and unwrapping the same amount leaves `E` but a younger start: the
  rejuvenation is proportional to the money cycled (halving the age cycles as much as `E`). One start cannot tell which money
  left first. It is bounded by the per-user wrap and unwrap windows and the token-wide caps, and it is disclosed.

**Governance (§6).** Turning the decay on or shortening `H` is a tightening of the unwrap side; turning it off or lengthening `H`
relaxes it. It follows the unwrap-protection rule (R13): a tightening waits the notice period, so holders can exit first; a
relaxation applies at once.

## 3. Mint, burn and the other paths that do not count — SPECIFIED

- **The hybrid's issuer mint** (`mint`, `mintToUA`, bit 1, CTR-GOV-12): **does not count and credits no `net`.** No underlying
  enters; the mint is bounded by `maxSupply` and by the minter's grant (`GovernanceUse.use(MINTABLE, …, amount)`: budget and
  window). A minted unit is exactly what R4 keeps from redeeming against the depositors' reserve. Ruled (R12).
- **Burn by roles:** none exists on the wrapped kinds (`BURNABLE` is not in `WRAPPED_BITS`). `FORCE` and `OPERATOR_TRANSFER`
  (9, 11, 13) move public units and never the reserve: not counted, `net` unmoved.
- **`addReserve` / `mtxAddReserve`:** underlying in, no units out: not a wrap, not counted.
- **`rescue`:** the surplus over the reserve: not counted.
- **Transfers, pay, `mtxRelayFee`, service pulls** (the service-pull spec: "the underlying is never touched"), **trades**,
  **shield / unshield** between public and shielded balances, **roll-over**: no reserve moves, not counted.
- **A future liquidity module** (none exists today): a module that wraps for a signer goes through `mtxWrapOrder`, so the signer
  counts; a module that wraps for itself is its own subject (R14).

## 4. Order of checks — SPECIFIED

The new checks sit inside `WrappedLib` (§8), where each path already computes the amount. Every regulated check that runs before
the body comes first; the ledger hooks of the mint come after the wrap checks, those of the burn before the unwrap count. A
refusal is atomic either way: the order fixes only which named error a caller sees, and the tests pin it.

| Step | Wrap (W, Z/Q wrap-shield, T wrap order) | Unwrap (W) | Unshield-unwrap (Z, Q) |
|---|---|---|---|
| 1 | relayed: envelope, `_regPre` (9, 11, 13: P unless pause-open, F(from)), signature, allowlist, nonce | the same; unwraps are in the pause-open set (CTR-AS-06) | relayed: the same |
| 2 | `_regPayer` (wrapToUA, wrap-shield) / `_regSender(o.from)` (wrap order to another id) | — | `_regZetherSender` (Zether), `_regName`, the payee check |
| 3 | leg: `NativeNotGasless` (order), `WrapDisabledFor`, `WrapPausedForRateChange`, `WrapOrderInvalid` | `quoteUnwrap`: recipient, `out`, `UnwrapTooSmall`, `UnwrapBelowMin`, `InsufficientReserve`, `burned` | `quoteTo` (the same quote) |
| 4 | **wrapper list** (before the pull) | **unwrapper list, the four parts, the entitlement (a would-be refusal reads the redeemer role): checked, not written** | **the same check, before the proof**: a refusal costs the relayer the cheap prefix |
| 5 | native value / `ReserveShortfall`, the measured pull (order: the quote and the fee) | the burn: `_regMove` F(from) | the proof, the pool burn, the fee |
| 6 | `WrapTooSmall`, the hybrid cap | **the count, in `payOut` / `payOutToUA`**: the same checks again (warm), then the writes, before `reserve -= out` and the one outside call (CEI) | **the count**, in `payOutTo` → `payOut` / `payOutToUA` |
| 7 | **the four parts, then the net credit and the weighted start** (order: before `mtxTrade`, at `o.amount`) | the transfer, `UnderlyingTransferMismatch` | the same |
| 8 | the mint: `_regMove` P, R(to) | — | — |

The unwrap counts once: `payOutTo` calls `quoteTo` again, and that call only checks; the write is in `payOut` / `payOutToUA`, which
every unwrap path reaches exactly once.

## 5. Storage and its bounds — SPECIFIED

**A new ERC-7201 namespace `scaas.wraplimit`**, its root `keccak256(abi.encode(uint256(keccak256("scaas.wraplimit")) - 1)) &
~bytes32(uint256(0xff))`, computed and pinned at the build. Storage structs are flat: in Solidity a struct-typed member starts a
new slot, so the calldata type `WrapLimit` is never nested in storage; periods are stored in minutes.

```solidity
/// @custom:storage-location erc7201:scaas.wraplimit
struct WrapLimitStorage {
    mapping(uint256 leg => LegConfig) config;                       // +0: two slots per leg
    mapping(uint256 leg => TokenWindows) total;                     // +1: two slots per leg
    mapping(bytes32 account => mapping(uint256 leg => Quota)) quota; // +2: ONE slot per id and leg (R7)
    mapping(bytes32 account => uint8) member;                       // +3: bit 0 canWrap, 1 canUnwrap
    bytes32 pendingCommit;                                          // +4: §6
    uint64 pendingEta;                                              // +5
    uint32 pendingGeneration;                                       //    the owner generation at the proposal
}
struct LegConfig {   // slot 0: the wrap side (248 bits); slot 1: the unwrap side (248 bits)
    uint24 wrapShortPerUser;   uint64 wrapShortTokenWide;   uint24 wrapShortPeriodMin;
    uint24 wrapLongPerUser;    uint64 wrapLongTokenWide;    uint24 wrapLongPeriodMin;    uint8 unitExp;     uint16 decayDays;
    uint24 unwrapShortPerUser; uint64 unwrapShortTokenWide; uint24 unwrapShortPeriodMin;
    uint24 unwrapLongPerUser;  uint64 unwrapLongTokenWide;  uint24 unwrapLongPeriodMin;  uint8 unitExpCopy; uint16 decayDaysCopy;
}
struct TokenWindows { // slot 0: wrap (176 bits); slot 1: unwrap (176 bits); starts in minutes
    uint24 wrapShortStart;   uint64 wrapShortUsed;   uint24 wrapLongStart;   uint64 wrapLongUsed;
    uint24 unwrapShortStart; uint64 unwrapShortUsed; uint24 unwrapLongStart; uint64 unwrapLongUsed;
}
```

**The user's slot, `Quota`** (one word; solc packs in declaration order, low byte first):

| Bytes | Bits | Field | Type | Meaning |
|---|---|---|---|---|
| 0–2 | 0–23 | `wrapShortStart` | `uint24` | `⌊block.timestamp / 60⌋ mod 2^24` at the window's first use |
| 3–5 | 24–47 | `wrapLongStart` | `uint24` | |
| 6–8 | 48–71 | `unwrapShortStart` | `uint24` | |
| 9–11 | 72–95 | `unwrapLongStart` | `uint24` | |
| 12–14 | 96–119 | `wrapShortUsed` | `uint24` | quanta in the window |
| 15–17 | 120–143 | `wrapLongUsed` | `uint24` | |
| 18–20 | 144–167 | `unwrapShortUsed` | `uint24` | |
| 21–23 | 168–191 | `unwrapLongUsed` | `uint24` | |
| 24–27 | 192–223 | `base` | `uint32` | `b` of §2, quanta, saturating |
| 28–31 | 224–255 | `startDay` | `uint32` | `s` of §2.1, the weighted start, an absolute UTC day |

**It fits one slot** with the decay: the window starts moved from seconds to minutes (24 bits each) to make room for `startDay`.

**Bounds and why nothing overflows.**

- **Used ≤ cap.** A use is refused when `base + q > cap`, computed in `uint256` before narrowing, and `perUser ≤ 2^24 − 1`,
  `tokenWide ≤ 2^64 − 1` by type, so a stored `used` never exceeds its field. Per id, leg and window at most 16,777,215 quanta;
  token-wide at most `2^64 − 1`.
- **`base` saturates** at `2^32 − 1` quanta on credit and at 0 on debit: a saturated `base` only refuses more (fail closed). The
  decay's own bounds are in §2.1.
- **`unitExp ≤ 36`** (`WrapUnitInvalid`), so `quanta × unit` stays below `2^64 · 10^36 < 2^256` in every view and error. Examples
  [estimate]: USDC (6 decimals) at `unitExp = 4` (a cent): a window up to 167,772 USDC per id, `base` up to 42.9 M USDC; an
  18-decimal leg at `unitExp = 16` (a hundredth of a token): 167,772 tokens per window; a 0-decimal low-value leg at `unitExp = 3`:
  16.7 G units per window. The wizard proposes `unitExp = max(0, decimals − 2)` and raises it when a limit would not fit 24 bits.
- **Window time, modular minutes.** Starts are `uint24(⌊now / 60⌋)`; the elapsed minutes `uint24(nowMin − start)` are exact
  while the true idle time is below `2^24` minutes (31.9 years). A window idle longer can alias to "active": it then refuses for
  at most one `period`, never allows more. `period / 60 ≤ 2^23 − 1` leaves half the circle as "ended". A window counts as active
  only while `used ≠ 0`, so a start of 0 needs no sentinel.
- **Decay time, absolute days.** `startDay` is a `uint32` UTC day, no modular arithmetic: it cannot wrap, so a decayed entitlement
  can never revive.
- **`ctl`, the hot-path copy.** `WrappedLib.Leg` slot a (token 0–19, decimals 20, `wrapEnabled` 21, `adjustable` 22, `capped` 23)
  gains `uint8 ctl` at byte 24: `TRACK` 1 (bit 25 held and the first configuration written), `NET` 2, `WLIST` 4, `ULIST` 8,
  written on every leg by each applied configuration and cleared with the bits. Every wrap and unwrap already reads slot a in the
  same transaction (an unwrap in `payOut`; the quote's earlier read makes that one warm), so a token without the bits, or with
  them but never configured, adds **no storage read** (the copies pattern of `capped` and `adjustable`). `unitExpCopy` (write-once)
  and `decayDaysCopy` are written with their originals by the one setter, so a wrap reads only the wrap side and an unwrap only the
  unwrap side.

**Why quanta (R22).** Four windows, `base` and `startDay` in raw units and seconds need about 5 × 80 bits beside the starts; R7's
one slot leaves 128 bits. Quanta give 24 and 32 bits each, and the unit is chosen per leg. The other reading, two slots per id and
leg (raw amounts, windows in seconds), would cost a second new slot (≈ 98 k state gas) on an id's first unwrap; not taken.

## 6. Setting the limits — SPECIFIED

**The owner's op (R6).** One governed token entry, reached through `GovernanceRouter` (or called directly by an owner contract):

```solidity
struct WrapLimit     { uint24 perUser; uint64 tokenWide; uint32 period; }        // period in seconds, a whole number of minutes
struct WrapLegLimits { address underlying; uint8 unitExp; uint16 decayDays;
                       WrapLimit wrapShort; WrapLimit wrapLong; WrapLimit unwrapShort; WrapLimit unwrapLong; }

function setWrapLimits(WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList) external;   // governed
function setWrapMember(bytes32 account, bool canWrap, bool canUnwrap) external;                                  // governed, bit 26
```

`legs` has exactly `legCount` entries in the leg order, each naming its underlying (`WrapLegMismatch(i, u)` otherwise), so a
signer sees which leg each figure is for. Checks: the owner (`NotOwner`); amounts, `unitExp ≠ 0`, `decayDays ≠ 0` and `netUnwrap`
need bit 25, `wrapList` / `unwrapList` need bit 26 (`FeatureNotSet(bit)`); each limit's `period` rule of §2 (`WrapLimitInvalid(u,
limit)`); `unitExp ≤ 36`, and once the first configuration on a bit-25 token is written, `unitExp` never changes
(`WrapUnitInvalid(u, unitExp)`). The first such configuration fixes every leg's unit and sets `TRACK` on every leg; tracking of
`b` and `s` starts then (§2). `setWrapMember` is `GovernanceUse.use(WRAP_LIST, subject, 0)`: a power, no scalar, no scope; at once
both ways. The redeemer role has no entry of its own: it is bit 27's `grantRole` / `setGrant` / `revokeRole`.

**Tighter, looser.** Field by field against the configuration in force, with `eff(a) = a == 0 ? ∞ : a`:

| Field | Tighter (or equal) | Looser |
|---|---|---|
| `perUser`, `tokenWide` | `eff(new) ≤ eff(old)` (turning a part on from 0 is tighter) | `eff(new) > eff(old)` (raising, or 0 = off) |
| `period` (the limit on before and after) | `new ≥ old` | `new < old` |
| `decayDays` (unwrap side) | `eff(new) ≤ eff(old)` (turning the decay on, a shorter horizon) | a longer horizon, or 0 = off |
| `netUnwrap`, `wrapList`, `unwrapList` | off → on | on → off |
| `unitExp` | equal (any change refused) | — |

**When a call applies.**

| Change | Applies (R6 for the wrap side, R13 for the unwrap side) |
|---|---|
| wrap side tighter | at once |
| wrap side looser | waits the delay |
| unwrap side tighter (an unwrap part, `unwrapList` on, `netUnwrap` on, the decay on or a shorter `H`) | **waits the delay** |
| unwrap side looser | **at once** |
| membership (`setWrapMember`), a redeemer's grant (`grantDelay`, as every grant) or revoke | at once |

A call applies at once only when every field it changes applies at once; otherwise it takes **two calls**, the pattern of
`_delayedRelaxBits` (`GovernanceLib._due`, governance spec §1.6): the first call stores `pendingCommit = keccak256(abi.encode(legs,
netUnwrap, wrapList, unwrapList))`, `pendingEta = now + delay` and the owner generation, emits `WrapLimitsProposed`, and changes
nothing; the same call again, by the owner, in `[eta, eta + delay]` and under the same owner generation, applies it and clears the
pending. Before `eta` it reverts `GrantNotReady(25, 0, eta)` (the pattern's error). One pending at a time: a new call that needs
the delay replaces it (new commit, new eta: holders see the new proposal); a call that applies at once also clears it, so the
owner cancels by re-sending the configuration in force. With `delay = 0` (a test chain) every call applies at once. **The delay
is the factory's `noticePeriod()`** (the owner's word "notice period", which pay-meta-tax Q9 defined for the tax rate; R21); the token reads it from `FACTORY` as `setTaxRate` does.

**Holder protection on unwrap (R13).** Applied at once, an unwrap tightening would let the owner stop redemptions instantly (a
token-wide unwrap cap of one quantum, the unwrapper list on with no members, the net rule on, a one-day decay): a pause of unwrap,
which the repository refuses elsewhere (unwrap from a disabled leg stays open, CTR-TOK-07; on the regulated kinds "unwrap is never
paused", CTR-GOV-17). Hence the asymmetry: tightening the unwrap side waits the notice, so holders can exit first; relaxing it
applies at once; the wrap side stays as R6 rules, since a wrap stop traps nobody. The disclosure states it. A call that both
tightens the unwrap side and relaxes the wrap side waits once, for both.

**Defaults (R20).** Bits 25, 26 and 27 off unless chosen at the creation of a hybrid (the wizard proposes them off; the hybrid wizard offers them);
with the bits on, every limit off, both lists off, the net rule and the decay off, nothing tracked until the first configuration.
Tokens of earlier releases never get limits: nothing deployed is upgraded, and every chain is test-only (no migration).

**Hard stop vs limit (R18).** An amount of 0 means no limit, so a stop is the existing powers': wrap — `disableWrap(u)` (bit 4, the
guardian, one-way per leg, CTR-TOK-07) and, on 9, 11, 13, `PAUSE` (bit 7: the mint's P stops every wrap and wrap-shield); unwrap —
no stop on the public kinds by design, `FREEZE` (bit 5) stops one account's burn and so its unwrap, `PAUSE` stops the
unshield-unwrap on 11 and 13 (CTR-GOV-17). The nearest thing to an unwrap stop the limits give is one quantum or a one-day decay,
an unwrap tightening that waits the notice (R13). No new stop is added.

## 7. Errors, events, views — SPECIFIED

**Errors** (`IWrappedToken`; amounts in the leg's raw units; `limit`: 0 `wrapShort`, 1 `wrapLong`, 2 `unwrapShort`, 3 `unwrapLong`):

| Error | When |
|---|---|
| `WrapLimitExceeded(address underlying, uint8 limit, bytes32 account, uint256 amount, uint256 remaining)` | a per-user part |
| `WrapCapExceeded(address underlying, uint8 limit, uint256 amount, uint256 remaining)` | a token-wide part |
| `UnwrapAboveNetWrapped(address underlying, bytes32 account, uint256 amount, uint256 entitlement)` | the entitlement rule, plain or decayed |
| `WrapperNotListed(bytes32 account)`, `UnwrapperNotListed(bytes32 account)` | the lists |
| `WrapLimitInvalid(address underlying, uint8 limit)`, `WrapLegMismatch(uint256 index, address underlying)`, `WrapUnitInvalid(address underlying, uint8 unitExp)` | `setWrapLimits` |
| `WrapControlNeedsHybrid(uint8 bit)` | the creation of a pure-wrap token (`maxSupply = 0`) with bit 25, 26 or 27 (R12) |
| `WrapControlActive(uint8 bit)` | `disableFeature` of bit 25, 26 or 27 while a control under it is on (27: while it has holders) |
| reused: `FeatureNotSet(bit)`, `NotOwner(caller)`, `MissingRole(26, caller)`, `GrantNotReady(25, 0, eta)` | |

**Events.** `WrapLimitsSet(bytes32 indexed by, WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList)` when a
configuration applies; `WrapLimitsProposed(bytes32 indexed by, uint64 eta, WrapLegLimits[] legs, bool netUnwrap, bool wrapList,
bool unwrapList)` when one waits; `WrapMemberSet(bytes32 indexed account, bytes32 indexed by, bool canWrap, bool canUnwrap)`; a
redeemer's grant and revoke are governance's own `RoleGranted` / `RoleRevoked`. No event per use: `Wrapped`, `UAWrapped`,
`Unwrapped`, `UnwrappedToUA` already carry the amounts, and the state is in the views.

**Views (R19).**

```solidity
struct WindowView { uint256 left; uint64 resetAt; }   // left: raw units; type(uint256).max when the part is off
struct WrapQuota  { WindowView wrapShort; WindowView wrapLong; WindowView unwrapShort; WindowView unwrapLong;
                    uint256 netWrapped;       // b, undecayed, raw units
                    uint256 entitlement;      // E(now), raw units; type(uint256).max when no rule applies or a redeemer
                    uint64 entitlementZeroAt; // the first time E reaches 0 (start day + H, as a timestamp); 0 without the decay
                    bool canWrap; bool canUnwrap; bool redeemer; }
function wrapQuotaOf(bytes32 account, address underlying) external view returns (WrapQuota memory);      // per user
function wrapQuotaTotal(address underlying) external view returns (WindowView[4] memory);                // token-wide, by limit id
function wrapLimits() external view returns (WrapLegLimits[] memory legs, bool netUnwrap, bool wrapList, bool unwrapList,
    bytes32 pendingCommit, uint64 pendingEta, bool pendingLive);
```

`resetAt` is the end of the active window, the earliest time the next one can start (0 when none is active); `canWrap` is
`!wrapList || member.canWrap`, `canUnwrap` likewise. A wallet's "at most now": wrap `min` of the two user `left` and the two total
`left` (0 unless `canWrap`), in the leg's underlying; unwrap the same over the unwrap side and `entitlement`, converted to wrapped
units with `previewUnwrap`. A wrap of exactly `left` fits (`⌈left / unit⌉` quanta).

## 8. Placement and size — SPECIFIED

**In `WrappedLib`, not in each module.** Every path of §1 already calls `WrappedLib` — `wrap` (W's `_wrap`, Z's and Q's
wrap-shield), `wrapBySigUA` (T's wrap order), `quoteUnwrap` / `quoteUnwrapToUA` / `quoteTo` and `payOut` / `payOutToUA` / `payOutTo`
(W's unwraps, Z's and Q's unshield-unwrap) — and each reads the leg's slot a, where `ctl` sits. The check therefore lives once, in
the one library all six kinds share, reached by the `DELEGATECALL` each path makes today: no new call, no new cold account. The
changed signatures: `wrap(…, bytes32 receiver)`, the quotes `(…, bytes32 holder)`, the payouts `(…, bytes32 holder)`;
`wrapBySigUA` takes its ids from the order. New library functions: `setWrapLimits`, `setWrapMember`, `checkControlsOff(bit)` and
the three views; the redeemer read is `GovernanceLib`'s role read (internal, no new library). The token's new entries
(`setWrapLimits`, `setWrapMember`, `wrapLimits`, `wrapQuotaOf`, `wrapQuotaTotal`) go to module W, beside `disableWrap` and the rate
entries (T66b §4.2; `script/t66b/entries.json`, faces regenerated); the `disableFeature` refusal goes where `_disableFeatureBody`
already is (A on 1, 3, 5; W on 9, 11, 13).

**Growth [estimate]; lines from CTR-GOV-19's Change: module 33,780 B (57 M) / 35,570 B (60 M), release 33,594 / 35,386 B, library
33,903 / 35,694 B.** Sizes now [measured, T66b build]:

| Contract | Now (B) | Adds | After [estimate] | Margin to the 57 M line |
|---|---:|---|---:|---:|
| `WrappedLib` | 17,095 | the counter, the checks, the decay and its weighted start, setter with the tighter / looser table, member setter, views | 21.1–22.9 KB | ≥ 11.0 KB |
| W, kind 13 (largest) | 29,202 | five entries (ABI decode of the leg array, struct returns), the receiver / holder words | 30.2–31.0 KB | ≥ 2.8 KB |
| W, kinds 11 / 9 | 29,011 / 28,021 | the same | 30.0–30.8 / 29.0–29.8 KB | ≥ 2.9 KB |
| W, kinds 1 / 3 / 5 | 21,873 / 21,697 / 21,903 | the same | 22.7–23.7 KB | ≥ 10 KB |
| Z (3, 11), Q (5, 13) | 27,996 / 28,865; 28,283 / 29,465 | one word to each changed call | +0.05–0.15 KB | ≥ 4.1 KB |
| T, all six (largest 17,045) | | the same | +0.05 KB | ≥ 16 KB |
| A (1, 3, 5) | | the `disableFeature` refusal | +0.1 KB | — |
| the token (largest release `WrappedPqzRegulatedToken`) | 27,713 | five stubs and dispatcher rows | 28.0–28.2 KB | ≥ 5.3 KB |
| `GovernanceRouter` | 15,572 | two typed ops (the leg array's struct hash) | 16.3–16.8 KB | ≥ 16 KB |

**No W needs a split**: the largest, kind 13, stays at most about 31.0 KB, below the 57 M line by 2.8 KB and below T66b §3.4's
watch mark (31.7 KB); the decay's arithmetic sits in the library, not in W. The deploy gas of W grows by about 1.6–3.0 M per kind
at ≈ 1,606 gas per byte [estimate]. `GovernanceLib` does not change: the pending of §6 is the namespace's own, and bit 27 uses
the existing role machinery.

## 9. Node, clients, vectors, families — SPECIFIED

- **Router ops** (fee mode `NONE`, as every governance op): `mtxSetWrapLimits(UAEnvelope e, address target, WrapLegLimits[]
  legs, bool netUnwrap, bool wrapList, bool unwrapList, UASig auth)` over `UASetWrapLimits(bytes32 from,address
  target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,uint256 batch,uint256 nonce,uint256 validUntil,uint32
  mode,address relayer,uint256 fee,address feeRecipient)WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit
  wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)WrapLimit(uint24 perUser,uint64 tokenWide,uint32
  period)`, the router hashing the struct words itself (`_uaCall` with `words ≠ data`); `mtxSetWrapMember(UAEnvelope e, address
  target, bytes32 account, bool canWrap, bool canUnwrap, UASig auth)` over `UASetWrapMember(bytes32 from,address target,bytes32
  account,bool canWrap,bool canUnwrap,…)`. Both typehashes pinned (`*TypehashIsPinned`). The redeemer role needs no op: the
  router's existing grant and revoke ops take bit 27.
- **Node.** `typed.rs` gains the two router rows (with the referenced struct types); the router's `CALL_TABLE` rows in `guard.rs`
  equal the router's table, both directions. The tokens' `mtxSelectors()` and `_uaAllowed` do not change (governance is not on
  the generic allow-list), so no token row moves. A simulation revert with `WrapLimitExceeded`, `WrapCapExceeded`,
  `UnwrapAboveNetWrapped`, `WrapperNotListed` or `UnwrapperNotListed` is a named refusal of the class of NODE-LANE-09: the job
  stays `queued` with `error = WRAP_LIMIT_REFUSED: <named error>`, never `dead` while the payload may still land (a window ends, a
  member is added, a redeemer is granted, a later wrap raises the entitlement); expiry or the attempt cap ends it (NODE-LANE-14);
  no grief score. The node runs the simulation before any submission, so the client sees the name before a transaction exists;
  it may skip re-simulating until the smallest `resetAt` of `wrapQuotaOf` / `wrapQuotaTotal`. A note for operators: a wrapped
  token's job can now wait for a window.
- **Clients and vectors.** `clientkeys` `evm.js` rows for both ops and the decoder entries of the new errors; `typed_ops.json`
  regenerated by its generator; `ua-rs`, the one signer, builds and signs both ops; every `ua-*` reads the same rows.
  `governance_bits.json` gains bits 25, 26 and 27 (name, type, kinds, holder) and their sentences: the limits and the notice, the
  lists, the net rule and its rounding, the decay (the horizon, the weighted start, the round trip), the redeemer, the Sybil line,
  the burst. A vector `wraplimits.json` (generated, then checked by forge and `clientkeys`) holds rows of the decay arithmetic
  (`b`, `s`, `H`, a sequence of wraps and unwraps by day → `E`, `b'`, `s'`), so a wallet that previews the entitlement between
  reads matches the contract. `test/vectors/selector_audit.json` classifies the new entries. Wallets read the three views (§7).
- **Families.** One rule on every chain: the same limits, decay, errors and order on every family with wrapped kinds, built in
  each family's own round (PLANNED; Hedera with its round). EVM first.

## 10. Gas — SPECIFIED (estimates)

All **[estimate]**, from Amsterdam's prices as measured in this repository (a new slot ≈ 97,920 state gas under EIP-8037, as the
`acceptMembership` rows of `decisions.md` measured); the build measures each with `--isolate` and moves every pin old → new.

| Case | Extra per wrap or unwrap |
|---|---|
| a pure-wrap token, or a hybrid without bits 25 / 26 or never configured | no new read (`ctl` is in slot a, already read); the extra argument words, ≈ +30 to +150 gas |
| lists only (bit 26) | the member byte: ≈ 2.1 k |
| tracked (bit 25), the user's slot exists | the leg's config side 2.1 k + the user's slot 2.1 k read + 2.9 k write ≈ **7 k**; the decay's arithmetic ≈ +0.2–0.4 k; an unwrap the same |
| tracked, the id's first use on that leg | one new slot: ≈ **98 k state gas** + ≈ 5 k regular |
| a token-wide part on | its window slot ≈ 5 k (the first use of that leg and side: ≈ 98 k state gas, once per token) |
| payer ≠ credited id (`wrapToUA`, wrap-shield, an order to another id) | the credited id's slot: ≈ 5 k, or ≈ 98 k when new |
| an unwrap above the entitlement | the redeemer role read ≈ 2.1–4.2 k (only on this path) |
| unshield-unwrap | the check twice (before the proof, warm in the payout) ≈ +0.3 k over an unwrap |
| `setWrapLimits` | ≈ 30–60 k per leg written, plus `ctl` on every leg (≤ 8 slot writes) |

A plain `transfer` and `mtxTransfer` gain no read on any kind (CTR-GOV-11; `PlusZero.t.sol` unchanged). The wrap and unwrap pins of
every wrapped kind move by the argument words even when off; the commit carries old → new.

## 11. Tests, mutants, pins, on-chain rows — SPECIFIED

**Red tests and mutants, one per check.** Each test has its positive control (the same call one quantum lower, or the id listed,
passes) and changes one thing at a time; each mutant must turn the test red.

| # | Check | Red test | Mutant |
|---|---|---|---|
| 1 | wrapper list | an unlisted payer: `WrapperNotListed`, nothing pulled | the list reads the receiver; the check after the pull |
| 2 | unwrapper list | an unlisted holder: `UnwrapperNotListed` | reads the recipient; reads `UA_POOL` for a derived UA |
| 3 | per-user short / long, wrap | at `perUser` passes, one quantum more refused; short and long independent | `>` → `>=`; `⌈⌉` → `⌊⌋`; one window updates the other |
| 4 | per-user short / long, unwrap | the same on `out` | counts `burned` (wrapped units) instead of `out` |
| 5 | token-wide caps | two ids together over `tokenWide`: `WrapCapExceeded` | the total not written |
| 6 | fixed window in minutes | refused until `period` has passed and up to 60 s more, passes after; a period not a whole number of minutes refused | `<=` → `<` (ends up to a minute early); the start reset on every use |
| 7 | modular minutes | warp past `2^24` minutes: windows behave; an aliased stale window refuses, never allows | signed or unmasked subtraction |
| 8 | plain net rule | received-by-transfer units refused; own wraps pass | credit to the payer on `wrapToUA`; debit `⌊⌋`; the rule on while off |
| 9 | tracked while off | wrap, turn the net rule on, unwrap within `b` passes; wrap, turn the decay on, `E` counts the real age | tracking only while on; the clock not kept while the decay is off |
| 10 | relayed paths | `mtxWrap`, `mtxExecute(wrap)`, `mtxBatch` (second item refused), a derived UA's `mtxUnwrap` | `_msgSender()` as the id (every derived UA on `UA_POOL`'s quota) |
| 11 | wrap order | `o.from` counted, the submitter not | `msg.sender` counted |
| 12 | wrap-shield / unshield-unwrap (3, 5, 11, 13) | payer counted, `toUA` credited; the proof's sender counted; the refusal before the proof (gas below the verifier's) | the envelope's `from` counted; the count in the pre-proof `quoteTo` too (counted twice) |
| 13 | mint not counted | a hybrid mint leaves windows and `b` | the mint credits `b` |
| 14 | wrap side tighter at once | each tighter wrap field applies in one call | `eff(0)` read as the tightest |
| 15 | wrap side looser waits | `GrantNotReady` before `eta`, applies in `[eta, eta + delay]`, dead after, dead after an owner change; a mixed call waits; a new proposal replaces the old | the window unchecked; the generation unchecked; the period's direction inverted |
| 16 | unwrap side (R13) | an unwrap tightening (a part, the list, the net rule, the decay on, a shorter `H`) waits; an unwrap relaxing applies at once; a call tightening the unwrap side and relaxing the wrap side waits once | the unwrap side classified as the wrap side; `decayDays` classified on the wrap side |
| 17 | unit write-once | a changed `unitExp` after the first configuration: `WrapUnitInvalid` | `unitExpCopy` not written |
| 18 | disable refused while on | `disableFeature(25)` with a limit on, `(27)` with a holder: `WrapControlActive` | the check missing for bit 26 or 27 |
| 19 | bits and kinds | 25, 26, 27 refused on 0, 2, 4, 8, 10, 12; the setter without the bit: `FeatureNotSet` | 25 in a normal kind's mask |
| 20 | per leg | a limit on leg A leaves leg B; `b` per leg (wrap USDC, unwrap DAI refused under the rule) | one `Quota` per id across legs |
| 21 | copies | after every setter every leg's `ctl`, `unitExpCopy` and `decayDaysCopy` equal the configuration | one leg or one copy not written |
| 22 | +0 when off | `vm.accesses`: no new slot read on wrap and unwrap of a token without the bits | `ctl` in a new slot |
| 23 | views | `left` passes exactly, `left` + one quantum refused; `resetAt` equals the refusal's lift; `entitlement` equals what passes | `left` from the wrong window |
| 24 | order (§4) | on 9: a frozen relayed sender gets `Frozen` before any limit; a direct frozen unwrapper `Frozen` at the burn | the list after the pull |
| 25 | node | `WRAP_LIMIT_REFUSED` keeps the job `queued`, never `dead` | classified `reverted` |
| 26 | decay at 0, H/2, H | `H = 730`: `E = a` on day 0, `⌊a/2⌋` on day 365, 0 on day 730 and after; one quantum above `E` refused at each | `E` rounded up; `min(g, H)` missing (negative factor) |
| 27 | weighted start vs dust | a wrap below one unit changes nothing; a one-quantum wrap against a large `E` leaves `s`; a wrap equal to `E` halves the age | the start set to today on every wrap (the literal reading); `g'` rounded down |
| 28 | the line after a wrap | right after a wrap, `E = E_before + a` (or one quantum less); `b' ≤ b + a` | the `b + a` clamp missing; `b'` not rescaled |
| 29 | unwrap under the decay | an unwrap of `q` lowers `E` by exactly `q`; repeated unwraps never sum past `E` | `b' = b − q` (the sum reaches `b`) |
| 30 | redeemer | a redeemer unwraps past `E`, net and decay; still bound by the lists and windows; revoked, refused at once | the role skips the windows too; the role read on every unwrap (gas pin) |
| 31 | decay on and off | on (tighter), off (`E` back to `b`, never above the plain net), on again (the kept clock) | off restores a value above the plain net |
| 32 | overflow and saturation | `b` at `2^32 − 1` saturates and refuses more; `H = 65,535`; the largest products; a fuzz invariant `E ≤ b ≤ plain net` over random wraps, unwraps and days | `unchecked` narrowing of `b'` |
| 33 | round trip (R25) | the rejuvenation of a wrap-then-unwrap equals §2.1's bound, pinned, so a change is seen | — (documents the accepted limit) |
| 34 | hybrid only (R12) | creating a pure-wrap token of each of 1, 3, 5, 9, 11, 13 with bit 25, 26 or 27: `WrapControlNeedsHybrid(bit)`; the same hybrid passes | the check missing for one bit; the check reading `features` after `init` cleared nothing (order) |

Run at the four PQZ sets for kinds 5 and 13 (`script/pqz/at-set.sh <set> test`, one run per work tree, `PqzSet.sol` restored).

**Pins.** `test/v2/layout/namespaces.json`: a `wrapLimit` entry (root, every field of `WrapLimitStorage` at the probe keys, the
`Quota` byte offsets of §5) and the `underlying` entry's new `legs[1].ctl` (slot 0, inner 0, byte 24), both through
`Layout.t.sol` `test_namespaceRootsAndOffsetsArePinned`. Typehash pins for the two router structs. `size-baseline.json` rows old →
new with the reason. Gas pins old → new.

**On-chain matrix rows** (`script/onchain/`, `coverage.json` gains the five token entries per wrapped kind and the two router
ops). The factory's `noticePeriod()` of the chain decides the two-call rows: the run uses a chain with a non-zero notice for them,
or records them as one call where it is 0. Rows that need time to pass (a window's end, the decay at H/2 and H) run on the local
target, which advances its own clock (`evm_increaseTime`); on the SCaaS testnet the decay is checked at day 0 by the views.

| Group | Rows |
|---|---|
| gov | `mtxSetWrapLimits` tightening (applies); relaxing (proposed, then confirmed after the notice); `mtxSetWrapMember`; bit 27 granted and revoked through the router's grant ops; `disableFeature(25)` refused while on |
| tokens (hybrids of 1, 9) | `createToken` of a pure-wrap token with bit 25: expected revert `WrapControlNeedsHybrid`; a wrap within the limits; a wrap over: expected revert `WrapLimitExceeded`; a token-wide `WrapCapExceeded`; an unwrap of transferred units under the net rule: `UnwrapAboveNetWrapped`; a redeemer passes; the decay at day 0, H/2, H (local); `wrapToUA` credits `to`; a relayed `mtxUnwrap` of a derived UA counted on the UA; `mtxWrapOrder` counted on `o.from`; the three views |
| zether (hybrids of 3, 11), pq (hybrids of 5, 13) | `mtxWrapShield` within and over; `mtxUnshieldUnwrap` refused before the proof; the views |
| views | `wrapLimits`, `wrapQuotaOf`, `wrapQuotaTotal` on a hybrid of every wrapped kind |

## 12. Owner questions — ruled 2026-11-10

Every question is ruled; the ruling's full text is in the table at the top. Q1–Q10 were the controller's review points, Q11–Q16
came from this design.

| # | Question | Ruling |
|---|---|---|
| Q1 | Holder protection on unwrap | R13: unwrap tightening waits the notice, relaxing at once; wrap as R6 |
| Q2 | The net rule and received units | R9: a separate `redeemer` role, bit 27 |
| Q3 | Whose quota | R14: the subject; the net credit to the id credited; no exemption list |
| Q4 | Multi-leg tokens | R15: per leg, in the leg's own units |
| Q5 | Sybil | R10: accepted as is, no measure |
| Q6 | Fixed-window burst | R16: accepted, documented |
| Q7 | Amount units | R17: the underlying moved |
| Q8 | Hard stop vs limit | R18: no new stop |
| Q9 | Views, events, pre-checks | R19: as §7 and §9 |
| Q10 | Defaults | R20: all off; bits at creation, off by default |
| Q11 | Which notice period | R21: the factory's `noticePeriod()` |
| Q12 | "Hybrid" kinds | R12: hybrid tokens (`maxSupply ≠ 0`) of 1, 3, 5, 9, 11, 13 only; a pure-wrap token refused the bits |
| Q13 | Quanta vs raw | R22: quanta, one slot |
| Q14 | The decay's shape | R23: linear to zero over `H` |
| Q15 | The decay's clock | R24: the weighted-average start |
| Q16 | The round trip | R25: accepted and disclosed |

## 13. Tasks and estimates — SPECIFIED

Group 3l of the plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md), tasks T97–T104 (the plan block cuts
WL1–WL8 into tasks with their red tests, gates and mutants; the total is the same), in the pre-freeze work order of branch
`ua-mtx-merge` (contracts are immutable: before the EVM freeze); built later in its own worktree.

| # | Task | Agent-days |
|---|---|---:|
| WL1 | Contracts: `scaas.wraplimit` and `ctl` in `WrappedLib` (counter in minutes, checks, the decay and its weighted start, setter with the tighter / looser table and the pending, member setter, views); bits 25–27 in `GovernanceBits` and the kind masks, `WrapControlNeedsHybrid` in `initToken`; the receiver / holder words through W, Z, Q, T; `entries.json` and the regenerated faces; the `disableFeature` refusal; `IWrappedToken` errors, events, views; legacy copy of the touched bodies first | 3–3.5 |
| WL2 | `GovernanceRouter`: the two typed ops, typehashes and pins, its selector table | 0.5 |
| WL3 | Tests and mutants of §11 (33 rows, the decay fuzz included), at the four PQZ sets for 5 and 13 | 2.5–3 |
| WL4 | Gates: forge, size gate rows old → new, gas pins old → new (`--isolate`), layout and typehash pins, deploy gas of W against 60 M | 1 |
| WL5 | Node: `typed.rs` rows, `CALL_TABLE`, the `WRAP_LIMIT_REFUSED` class and its tests, an operator note | 1–1.5 |
| WL6 | Clients and vectors: `governance_bits.json` 25–27 and sentences, `typed_ops.json`, the `wraplimits.json` decay rows and their generator, `clientkeys` rows and decoder, `ua-rs` builder and tests, the `ua-*` vector readers, `selector_audit.json` | 2–2.5 |
| WL7 | On-chain matrix rows of §11 and `coverage.json` | 1 |
| WL8 | Docs: the rule in `token-wrappers.md` (next free CTR-TOK id) and its `decisions.md` entry with the owner's answers (R9–R11 included), bits 25–27 in the governance docs, the node row in `job-api.md` and `submit-lanes.md`, the disclosure text | 0.5–1 |
| | **Total** | **11.5–14** |
