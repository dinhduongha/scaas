# Wrap and unwrap limits on the wrapped kinds — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-10 from the owner's rulings of 2026-11-10 (below), on
branch `ua-mtx-merge`, read against the code at `39c3c6f1`. The controller's ten review points of the same day are open owner
questions (§12, Q1–Q10), each with a recommendation; three more come from this design (Q11–Q13). Where the body depends on an
open question it says which one, and it follows the recommendation, except Q1, where the body keeps the ruling and §6 shows both
readings. No gas or size figure here was measured: **[estimate]** is arithmetic over measured inputs, **[measured]** is quoted
from a run already committed. Rules read: [token-wrappers.md](../../contracts/token-wrappers.md) (CTR-TOK-04, -05, -07, -20,
-22, -24, -26), [decisions.md](../../decisions.md) (CTR-GOV-09 to -12, -17 to -19, CTR-TOK-30), the governance spec
[2026-11-02-governance.md](2026-11-02-governance.md) §1.6, the T66b spec
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

**Kinds.** The six kinds that hold a reserve: `WRAPPED` (1), `WRAPPED_ZETHER` (3), `WRAPPED_PQZ` (5), `WRAPPED_REGULATED` (9),
`WRAPPED_ZETHER_REGULATED` (11), `WRAPPED_PQZ_REGULATED` (13). Every token of them is covered, whatever its legs: one leg or up to
eight (CTR-TOK-07), the native-coin leg included (CTR-TOK-26), a hybrid (`maxSupply ≠ 0` with `MINTABLE`, CTR-GOV-12) or a fully
backed wrapper. In this repository "hybrid" names the wrapped token its issuer may also mint under `maxSupply`; it is the owner's
motivating case (a CBDC whose foreign depositors bring USDC), but the limits do not read `maxSupply`, so they hold on every
wrapped token (Q12). The normal kinds 0, 2, 4, 8, 10, 12 have no reserve and are untouched; kind 8's W module holds only the
regulated powers and does not change.

**Paths.** Every entry that moves underlying into or out of the reserve against wrapped units counts, direct or relayed. A
relayed form runs the same body under the signer (the self-call of `_named` / `_namedUA`, `MetaTxBase._selfCall`), so one check
inside the body covers the direct entry, its named `mtx*` form, `mtxExecute` with that calldata and each item of `mtxBatch`.

| Path | Entries (kinds) | Module | Counts as | Quota and lists of | Net credited to / debited from |
|---|---|---|---|---|---|
| wrap | `wrap(uint256)`, `wrap(address,uint256)`; `mtxWrap`, `mtxWrapLeg`; `mtxExecute` / `mtxBatch` items (1, 3, 5, 9, 11, 13) | W (`mtx*` forms in W, `mtxExecute` / `mtxBatch` in P; both self-call into W) | wrap, the received underlying | the subject: the direct caller, or the signer | the same id |
| wrap into a UA | `wrapToUA`, `mtxWrapToUA` (all six) | W | wrap | the payer (the subject) | `to`, the UA credited (Q3) |
| wrap-shield | `mtxWrapShield`, direct and relayed (3, 5, 11, 13) | Z (3, 11), Q (5, 13) | wrap | the payer (the subject) | `toUA`, the shielded receiver |
| the DEX's wrap order | `mtxWrapOrder(address, UAWrapOrder, UASig)` (CTR-TOK-20; all six) | T | wrap, `o.amount` (= received) | `o.from`, the order's signer; never `msg.sender`, the submitter | `o.destination`, or `o.from` when 0 |
| unwrap | `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)`, `unwrap(address,uint256,address,uint256)`; `mtxUnwrap`, `mtxUnwrapLeg`; `mtxExecute` / `mtxBatch` items, a derived UA's included | W | unwrap, the underlying paid out (`out`) | the subject: the caller, or the signer's id (a derived UA, never `UA_POOL`) | the same id |
| unwrap into a UA | `unwrapToUA`, `mtxUnwrapToUA` (all six) | W | unwrap | the subject | the same id |
| unshield-unwrap | `mtxUnshieldUnwrap`, direct and relayed (3, 5, 11, 13) | Z, Q | unwrap | the proof's sender: Zether `ZetherLib.uaOf(b.yFrom)`, PQZ `b.fromUA`; never the envelope's `from` or the submitter, since anyone may submit another account's proof | the same id |

**Why each.** A limit bounds the reserve's inflow and outflow, so every entry that changes `reserve` against units counts, and
nothing else (§3). The relayed forms must count: otherwise a signature would bypass a limit the direct call obeys, against
"every state-changing `mtx*` is relayable" holding the same rule. `wrapToUA` and the wrap-shield count on the payer, who brings the
underlying in; their net credit goes to the id that receives the units, so a holder who wraps into its own UA or its own shielded
balance can unwrap it later (Q3). The wrap order counts on `o.from` because the order's signer is the depositor; the submitter
only relays and takes `fee` in units minted to it, with no net credit. The unshield-unwrap counts on the proof's sender, as
FREEZE already reads it on the regulated confidential kinds (CTR-GOV-17); both ids are public on that path today (a Zether burn
names its account, a PQZ burn its `fromUA`), so the limits leak nothing new. The DEX's `mtxExchange` (CTR-DEX-20) and every trade of
wrapped units against the underlying on a market move no reserve and are not unwraps.

## 2. The model — SPECIFIED

**Per leg, in the leg's own units (Q4, Q7).** A token of `n` legs has, per leg `i`, four limits — `wrapShort`, `wrapLong`,
`unwrapShort`, `unwrapLong` — each a `WrapLimit { uint24 perUser; uint64 tokenWide; uint32 period; }`. Amounts are in **quanta** of
the leg's `unit = 10^unitExp` raw units of that underlying (§5 gives why: R7's one slot). The amount that counts is the underlying
that moved: on a wrap the measured `received` (a fee-on-transfer leg counts what arrived; a wrap order's `received == o.amount`;
a native leg's `msg.value`); on an unwrap the `out` the reserve pays (`UnderlyingTransferMismatch` makes the reserve's drop exactly
`out`; a fee-on-transfer recipient may get less, `out` still counts). Counting in the leg's underlying, not in wrapped units,
keeps a limit stable across a rate change (CTR-TOK-04) and makes R4 literal: "the underlying they wrapped".

**A limit's two parts.** `perUser` bounds one id per window, `tokenWide` all ids together per window; each part is off at 0
(R1); `period` is required (`≠ 0`) when either part is on and must be 0 when both are off. Short and long are labels: nothing
requires `wrapShort.period < wrapLong.period`.

**A use.** For an amount `x` (raw) on leg `i`, `q = ⌈x / unit⌉` quanta. For each limit of the direction whose part is on, with
the stored window `(start, used)` of that part (the user's for `perUser`, the token's for `tokenWide`):

```
now32  = uint32(block.timestamp)
active = used != 0 && uint32(now32 - start) < period    // modular, §5
base   = active ? used : 0
if base + q > cap:  revert (WrapLimitExceeded | WrapCapExceeded)(…, remaining = (cap - min(base, cap)) * unit)
start  = active ? start : now32;  used = base + q        // a new window starts at this use (R2)
```

A wrap must fit both wrap limits and their token-wide parts; an unwrap both unwrap limits and theirs (R1). All four writes of a
use happen or none (one revert). A part that is off is neither read nor written. A limit lowered below a window's `used` leaves
`remaining = 0` until the window ends; a part turned on later may meet a stale window of an earlier time it was on, which can
only refuse more, never less.

**Net wrapped (R4).** Per id and leg, `net` in quanta. Once the token holds bit 25 and the owner has written the first
configuration (§6), every wrap credits the credited id `⌊received / unit⌋` (saturating at `2^32 − 1`), and every unwrap debits
`q = ⌈out / unit⌉` (saturating at 0), **whether the option is on or off**, so turning it on later counts every wrap since the
first configuration. With the option on, an unwrap with `q > net` reverts `UnwrapAboveNetWrapped`. Rounding goes against the
user both ways: less than one `unit` per wrap is never redeemable under the option, and that is disclosed. `net` is an upper bound
per id, not a balance: transfers, payments, FORCE and OPERATOR_TRANSFER move units and never move `net`; a user who wrapped,
paid the units away and bought them back keeps its `net`.

**Exempt ids (Q2, Q3).** A member flag `exempt`, set by the holders of bit 26, frees an id from the per-user parts and from the
net rule. It does not free it from the lists or from the token-wide caps. It serves a merchant paid in wrapped units (it never
wrapped them) and a contract the issuer trusts that wraps for many users (a pool, an escrow).

**Lists (R5).** Per token, not per leg: `wrapList` (only ids with `canWrap` may wrap) and `unwrapList` (only ids with
`canUnwrap` may unwrap). The wrapper is the payer of §1, the unwrapper the holder of §1. Membership is a byte per id written by
the holders of bit 26 at once both ways; the lists' on and off are the owner's (§6). Lists are valid on the confidential kinds
too: the payer of a wrap-shield and the sender of an unshield-unwrap are public, unlike the decoy receivers that rule
`ALLOWLIST` out on those kinds (CTR-GOV-17).

**Feature bits (Q10).** Two new SCaaS bits (band 0–127, CTR-GOV-10), the next free numbers at this commit; the build takes the next
free ones if another spec takes these first:

| Bit | Name | Type | Kinds | Holder | Meaning |
|---|---|---|---|---|---|
| 25 | `WRAP_LIMIT` | capability | 1, 3, 5, 9, 11, 13 | none (the owner sets) | the owner may set the four limits per leg, their token-wide caps and the net option |
| 26 | `WRAP_LIST` | power | 1, 3, 5, 9, 11, 13 | any holder (EOA, `msig`, contract), never contract-only, not delay-relaxed | the owner may turn the two lists on and off; a holder writes members (`canWrap`, `canUnwrap`, `exempt`) |

Both join `WRAPPED_BITS`; 26 joins `WRAPPED_ROLES`; the normal kinds refuse both (`FeatureInvalidForKind`). Features only lose bits
after creation, so a token created without 25 and 26 can never limit anyone, which a holder reads at a glance (the reasoning of
CTR-GOV-18). Bit 26 stays out of `_delayedRelaxBits`: a compromised lister is revoked at once (the reason bit 23 is not delayed,
pay-meta-tax Q5). Disabling 25 or 26 is refused while a control under it is on (`WrapControlActive`), so a relaxation cannot
skip §6's delay through `disableFeature`; after the owner has turned everything under the bit off, disabling it loses nothing.

**Sybil (Q5).** A per-user part binds one id, and ids are cheap: anyone can split a wrap across many UAs. The token-wide cap is the
real bound on the reserve's flow; a per-user part means something only with the matching list on, where the issuer admits each id.
The disclosure says so.

**Fixed-window burst (Q6).** Using a whole window at its end and the next at its start moves up to `2 × perUser` (and
`2 × tokenWide`) within one `period` across the boundary. Accepted (R2); a long limit bounds the repetition; disclosed.

## 3. Mint, burn and the other paths that do not count — SPECIFIED

- **The hybrid's issuer mint** (`mint`, `mintToUA`, bit 1, CTR-GOV-12): **does not count and credits no `net`.** No underlying
  enters; the mint is bounded by `maxSupply` and by the minter's grant (`GovernanceUse.use(MINTABLE, …, amount)`: budget and
  window). A minted unit is exactly what R4 keeps from redeeming against the depositors' reserve (the owner's e-VND example).
  Recommendation, the controller may override.
- **Burn by roles:** none exists on the wrapped kinds (`BURNABLE` is not in `WRAPPED_BITS`). `FORCE` and `OPERATOR_TRANSFER`
  (9, 11, 13) move public units and never the reserve: not counted, `net` unmoved.
- **`addReserve` / `mtxAddReserve`:** underlying in, no units out: not a wrap, not counted.
- **`rescue`:** the surplus over the reserve: not counted.
- **Transfers, pay, `mtxRelayFee`, service pulls** (the service-pull spec: "the underlying is never touched"), **trades**,
  **shield / unshield** between public and shielded balances, **roll-over**: no reserve moves, not counted.
- **A future liquidity module** (none exists today): a module that wraps for a signer goes through `mtxWrapOrder`, so the signer
  counts; a module that wraps for itself is its own subject (Q3).

## 4. Order of checks — SPECIFIED

The new checks sit inside `WrappedLib` (§8), where each path already computes the amount. Every regulated check that runs before
the body comes first; the ledger hooks of the mint come after the wrap checks, those of the burn before the unwrap count. A
refusal is atomic either way: the order fixes only which named error a caller sees, and the tests pin it.

| Step | Wrap (W, Z/Q wrap-shield, T wrap order) | Unwrap (W) | Unshield-unwrap (Z, Q) |
|---|---|---|---|
| 1 | relayed: envelope, `_regPre` (9, 11, 13: P unless pause-open, F(from)), signature, allowlist, nonce | the same; unwraps are in the pause-open set (CTR-AS-06) | relayed: the same |
| 2 | `_regPayer` (wrapToUA, wrap-shield) / `_regSender(o.from)` (wrap order to another id) | — | `_regZetherSender` (Zether), `_regName`, the payee check |
| 3 | leg: `NativeNotGasless` (order), `WrapDisabledFor`, `WrapPausedForRateChange`, `WrapOrderInvalid` | `quoteUnwrap`: recipient, `out`, `UnwrapTooSmall`, `UnwrapBelowMin`, `InsufficientReserve`, `burned` | `quoteTo` (the same quote) |
| 4 | **wrapper list** (before the pull) | **unwrapper list, the four parts, the net rule: checked, not written** | **the same check, before the proof**: a refusal costs the relayer the cheap prefix |
| 5 | native value / `ReserveShortfall`, the measured pull (order: the quote and the fee) | the burn: `_regMove` F(from) | the proof, the pool burn, the fee |
| 6 | `WrapTooSmall`, the hybrid cap | **the count, in `payOut` / `payOutToUA`**: the same checks again (warm), then the writes, before `reserve -= out` and the one outside call (CEI) | **the count**, in `payOutTo` → `payOut` / `payOutToUA` |
| 7 | **the four parts, then the net credit** (order: before `mtxTrade`, at `o.amount`) | the transfer, `UnderlyingTransferMismatch` | the same |
| 8 | the mint: `_regMove` P, R(to) | — | — |

The unwrap counts once: `payOutTo` calls `quoteTo` again, and that call only checks; the write is in `payOut` / `payOutToUA`, which
every unwrap path reaches exactly once.

## 5. Storage and its bounds — SPECIFIED

**A new ERC-7201 namespace `scaas.wraplimit`**, its root `keccak256(abi.encode(uint256(keccak256("scaas.wraplimit")) - 1)) &
~bytes32(uint256(0xff))`, computed and pinned at the build. Storage structs are flat: in Solidity a struct-typed member starts a
new slot, so the calldata type `WrapLimit` is never nested in storage.

```solidity
/// @custom:storage-location erc7201:scaas.wraplimit
struct WrapLimitStorage {
    mapping(uint256 leg => LegConfig) config;                       // +0: two slots per leg
    mapping(uint256 leg => TokenWindows) total;                     // +1: two slots per leg
    mapping(bytes32 account => mapping(uint256 leg => Quota)) quota; // +2: ONE slot per id and leg (R7)
    mapping(bytes32 account => uint8) member;                       // +3: bit 0 canWrap, 1 canUnwrap, 2 exempt
    bytes32 pendingCommit;                                          // +4: §6
    uint64 pendingEta;                                              // +5
    uint32 pendingGeneration;                                       //    the owner generation at the proposal
}
struct LegConfig {   // slot 0: the wrap side (248 bits); slot 1: the unwrap side (248 bits)
    uint24 wrapShortPerUser;   uint64 wrapShortTokenWide;   uint32 wrapShortPeriod;
    uint24 wrapLongPerUser;    uint64 wrapLongTokenWide;    uint32 wrapLongPeriod;    uint8 unitExp;
    uint24 unwrapShortPerUser; uint64 unwrapShortTokenWide; uint32 unwrapShortPeriod;
    uint24 unwrapLongPerUser;  uint64 unwrapLongTokenWide;  uint32 unwrapLongPeriod;  uint8 unitExpCopy;
}
struct TokenWindows { // slot 0: wrap (192 bits); slot 1: unwrap (192 bits)
    uint32 wrapShortStart;   uint64 wrapShortUsed;   uint32 wrapLongStart;   uint64 wrapLongUsed;
    uint32 unwrapShortStart; uint64 unwrapShortUsed; uint32 unwrapLongStart; uint64 unwrapLongUsed;
}
```

**The user's slot, `Quota`** (one word; solc packs in declaration order, low byte first):

| Bytes | Bits | Field | Type | Meaning |
|---|---|---|---|---|
| 0–3 | 0–31 | `wrapShortStart` | `uint32` | `uint32(block.timestamp)` at the window's first use |
| 4–7 | 32–63 | `wrapLongStart` | `uint32` | |
| 8–11 | 64–95 | `unwrapShortStart` | `uint32` | |
| 12–15 | 96–127 | `unwrapLongStart` | `uint32` | |
| 16–18 | 128–151 | `wrapShortUsed` | `uint24` | quanta in the window |
| 19–21 | 152–175 | `wrapLongUsed` | `uint24` | |
| 22–24 | 176–199 | `unwrapShortUsed` | `uint24` | |
| 25–27 | 200–223 | `unwrapLongUsed` | `uint24` | |
| 28–31 | 224–255 | `net` | `uint32` | quanta, saturating |

**Bounds and why nothing overflows.**

- **Used ≤ cap.** A use is refused when `base + q > cap`, computed in `uint256` before narrowing, and `perUser ≤ 2^24 − 1`,
  `tokenWide ≤ 2^64 − 1` by type, so a stored `used` never exceeds its field. Per id, leg and window at most 16,777,215 quanta;
  token-wide at most `2^64 − 1`.
- **`net` saturates** at `2^32 − 1` quanta on credit and at 0 on debit: a saturated `net` only refuses more (fail closed).
- **`unitExp ≤ 36`** (`WrapUnitInvalid`), so `quanta × unit` stays below `2^64 · 10^36 < 2^256` in every view and error. Examples
  [estimate]: USDC (6 decimals) at `unitExp = 4` (a cent): a window up to 167,772 USDC per id, `net` up to 42.9 M USDC; an 18-decimal
  leg at `unitExp = 16` (a hundredth of a token): 167,772 tokens per window; a 0-decimal low-value leg at `unitExp = 3`: 16.7 G units per window. The
  wizard proposes `unitExp = max(0, decimals − 2)` and raises it when a limit would not fit 24 bits.
- **Time, modular.** Starts are `uint32(block.timestamp)`; the elapsed time is `uint32(now32 − start)`, exact while the true
  elapsed time is below `2^32` s (136 years) and correct past 2106 without a cliff. A window idle for more than 136 years can alias
  to "active": it then refuses for at most one `period`, never allows more. `period ≤ 2^32 − 1` s by type. A window counts as
  active only while `used ≠ 0`, so a start of 0 needs no sentinel.
- **`ctl`, the hot-path copy.** `WrappedLib.Leg` slot a (token 0–19, decimals 20, `wrapEnabled` 21, `adjustable` 22, `capped` 23)
  gains `uint8 ctl` at byte 24: `TRACK` 1 (bit 25 held and the first configuration written), `NET` 2, `WLIST` 4, `ULIST` 8,
  written on every leg by each applied configuration and cleared with the bits. Every wrap and unwrap already reads slot a in the same transaction (an unwrap in `payOut`; the quote's earlier read
  makes that one warm), so a
  token without the bits, or with them but never configured, adds **no storage read** (the copies pattern of `capped` and
  `adjustable`). `unitExpCopy` is written with `unitExp`, once (write-once, §6), so an unwrap reads only its side.

**Why quanta (Q13).** Four windows and `net` in raw units need about 5 × 80 bits beside the four starts; R7's one slot leaves 128
bits for five amounts. Quanta give 24 and 32 bits each, and the unit is chosen per leg. The other reading, two slots per id and leg
with raw amounts, costs a second new slot (≈ 98 k state gas) on an id's first unwrap; Q13 asks.

## 6. Setting the limits — SPECIFIED

**The owner's op (R6).** One governed token entry, reached through `GovernanceRouter` (or called directly by an owner contract):

```solidity
struct WrapLimit     { uint24 perUser; uint64 tokenWide; uint32 period; }
struct WrapLegLimits { address underlying; uint8 unitExp;
                       WrapLimit wrapShort; WrapLimit wrapLong; WrapLimit unwrapShort; WrapLimit unwrapLong; }

function setWrapLimits(WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList) external;   // governed
function setWrapMember(bytes32 account, bool canWrap, bool canUnwrap, bool exempt) external;                     // governed, bit 26
```

`legs` has exactly `legCount` entries in the leg order, each naming its underlying (`WrapLegMismatch(i, u)` otherwise), so a
signer sees which leg each figure is for. Checks: the owner (`NotOwner`); amounts, `unitExp ≠ 0` and `netUnwrap` need bit 25,
`wrapList` / `unwrapList` need bit 26 (`FeatureNotSet(bit)`); each limit's `period` rule of §2 (`WrapLimitInvalid(u, limit)`);
`unitExp ≤ 36`, and once the first configuration on a bit-25 token is written, `unitExp` never changes (`WrapUnitInvalid(u,
unitExp)`). The first such configuration fixes every leg's unit and sets `TRACK` on every leg; net tracking starts then (§2).
`setWrapMember` is `GovernanceUse.use(WRAP_LIST, subject, 0)`: a power, no scalar, no scope; at once both ways.

**Tighter, looser.** Field by field against the configuration in force, with `eff(a) = a == 0 ? ∞ : a`:

| Field | Tighter (or equal) | Looser |
|---|---|---|
| `perUser`, `tokenWide` | `eff(new) ≤ eff(old)` (turning a part on from 0 is tighter) | `eff(new) > eff(old)` (raising, or 0 = off) |
| `period` (the limit on before and after) | `new ≥ old` | `new < old` |
| `netUnwrap`, `wrapList`, `unwrapList` | off → on | on → off |
| `unitExp` | equal (any change refused) | — |

**When a call applies.**

| Change | As ruled (R6, the body) | Q1's recommendation |
|---|---|---|
| wrap side tighter | at once | at once |
| wrap side looser | waits the delay | waits the delay |
| unwrap side tighter (an unwrap part, `unwrapList` on, `netUnwrap` on) | at once | **waits the delay** |
| unwrap side looser | waits the delay | **at once** |
| membership (`setWrapMember`) | at once both ways | at once both ways |

A call applies at once only when every field it changes applies at once; otherwise it takes **two calls**, the pattern of
`_delayedRelaxBits` (`GovernanceLib._due`, governance spec §1.6): the first call stores `pendingCommit = keccak256(abi.encode(legs,
netUnwrap, wrapList, unwrapList))`, `pendingEta = now + delay` and the owner generation, emits `WrapLimitsProposed`, and changes
nothing; the same call again, by the owner, in `[eta, eta + delay]` and under the same owner generation, applies it and clears the
pending. Before `eta` it reverts `GrantNotReady(25, 0, eta)` (the pattern's error). One pending at a time: a new call that needs
the delay replaces it (new commit, new eta: holders see the new proposal); a call that applies at once also clears it, so the
owner cancels by re-sending the configuration in force. With `delay = 0` (a test chain) every call applies at once. **The delay
is the factory's `noticePeriod()`** (the owner's word "notice period", which pay-meta-tax Q9 defined for the tax rate; Q11 asks
whether `grantDelay` is meant instead); the token reads it from `FACTORY` as `setTaxRate` does.

**Holder protection on unwrap (Q1).** As ruled, an owner can stop redemptions at once: a token-wide unwrap cap of one quantum, the
unwrapper list on with no members, or the net rule on. That is a pause of unwrap, which the repository refuses elsewhere: unwrap
from a disabled leg stays open (CTR-TOK-07), and on the regulated kinds "unwrap is never paused" (CTR-GOV-17). Q1 recommends the
asymmetry above: tightening the unwrap side waits the notice, so holders can exit first; relaxing it applies at once; the wrap side
stays as ruled, since a wrap stop traps nobody.

**Defaults (Q10).** Bits 25 and 26 off unless chosen at creation (the wizard proposes them off; the hybrid wizard offers them);
with the bits on, every limit off, both lists off, the net option off and nothing tracked until the first configuration. Tokens of
earlier releases never get limits: nothing deployed is upgraded, and every chain is test-only (no migration).

**Hard stop vs limit (Q8).** An amount of 0 means no limit, so a stop is the existing powers': wrap — `disableWrap(u)` (bit 4, the
guardian, one-way per leg, CTR-TOK-07) and, on 9, 11, 13, `PAUSE` (bit 7: the mint's P stops every wrap and wrap-shield); unwrap —
no stop on the public kinds by design, `FREEZE` (bit 5) stops one account's burn and so its unwrap, `PAUSE` stops the
unshield-unwrap on 11 and 13 (CTR-GOV-17). The nearest thing to an unwrap stop the limits give is one quantum, which is Q1's case.
No new stop is added.

## 7. Errors, events, views — SPECIFIED

**Errors** (`IWrappedToken`; amounts in the leg's raw units; `limit`: 0 `wrapShort`, 1 `wrapLong`, 2 `unwrapShort`, 3 `unwrapLong`):

| Error | When |
|---|---|
| `WrapLimitExceeded(address underlying, uint8 limit, bytes32 account, uint256 amount, uint256 remaining)` | a per-user part |
| `WrapCapExceeded(address underlying, uint8 limit, uint256 amount, uint256 remaining)` | a token-wide part |
| `UnwrapAboveNetWrapped(address underlying, bytes32 account, uint256 amount, uint256 netWrapped)` | the net rule |
| `WrapperNotListed(bytes32 account)`, `UnwrapperNotListed(bytes32 account)` | the lists |
| `WrapLimitInvalid(address underlying, uint8 limit)`, `WrapLegMismatch(uint256 index, address underlying)`, `WrapUnitInvalid(address underlying, uint8 unitExp)` | `setWrapLimits` |
| `WrapControlActive(uint8 bit)` | `disableFeature` of bit 25 or 26 while a control under it is on |
| reused: `FeatureNotSet(bit)`, `NotOwner(caller)`, `MissingRole(26, caller)`, `GrantNotReady(25, 0, eta)` | |

**Events.** `WrapLimitsSet(bytes32 indexed by, WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList)` when a
configuration applies; `WrapLimitsProposed(bytes32 indexed by, uint64 eta, WrapLegLimits[] legs, bool netUnwrap, bool wrapList,
bool unwrapList)` when one waits; `WrapMemberSet(bytes32 indexed account, bytes32 indexed by, bool canWrap, bool canUnwrap, bool
exempt)`. No event per use: `Wrapped`, `UAWrapped`, `Unwrapped`, `UnwrappedToUA` already carry the amounts, and the state is in the
views.

**Views (Q9).**

```solidity
struct WindowView { uint256 left; uint64 resetAt; }   // left: raw units; type(uint256).max when the part is off (or exempt)
struct WrapQuota  { WindowView wrapShort; WindowView wrapLong; WindowView unwrapShort; WindowView unwrapLong;
                    uint256 netWrapped; bool canWrap; bool canUnwrap; bool exempt; }
function wrapQuotaOf(bytes32 account, address underlying) external view returns (WrapQuota memory);      // per user
function wrapQuotaTotal(address underlying) external view returns (WindowView[4] memory);                // token-wide, by limit id
function wrapLimits() external view returns (WrapLegLimits[] memory legs, bool netUnwrap, bool wrapList, bool unwrapList,
    bytes32 pendingCommit, uint64 pendingEta, bool pendingLive);
```

`resetAt` is the end of the active window, the earliest time the next one can start (0 when none is active); `canWrap` is
`!wrapList || member.canWrap`, `canUnwrap` likewise. A wallet's "at most now": wrap `min` of the two user `left` and the two total
`left` (0 unless `canWrap`), in the leg's underlying; unwrap the same over the unwrap side and, when `netUnwrap` and not `exempt`,
`netWrapped`, converted to wrapped units with `previewUnwrap`. A wrap of exactly `left` fits (`⌈left / unit⌉` quanta).

## 8. Placement and size — SPECIFIED

**In `WrappedLib`, not in each module.** Every path of §1 already calls `WrappedLib` — `wrap` (W's `_wrap`, Z's and Q's
wrap-shield), `wrapBySigUA` (T's wrap order), `quoteUnwrap` / `quoteUnwrapToUA` / `quoteTo` and `payOut` / `payOutToUA` / `payOutTo`
(W's unwraps, Z's and Q's unshield-unwrap) — and each reads the leg's slot a, where `ctl` sits. The check therefore lives once, in
the one library all six kinds share, reached by the `DELEGATECALL` each path makes today: no new call, no new cold account. The
changed signatures: `wrap(…, bytes32 receiver)`, the quotes `(…, bytes32 holder)`, the payouts `(…, bytes32 holder)`;
`wrapBySigUA` takes its ids from the order. New library functions: `setWrapLimits`, `setWrapMember`, `checkControlsOff(bit)` and
the three views. The token's new entries (`setWrapLimits`, `setWrapMember`, `wrapLimits`, `wrapQuotaOf`, `wrapQuotaTotal`) go to
module W, beside `disableWrap` and the rate entries (T66b §4.2; `script/t66b/entries.json`, faces regenerated); the
`disableFeature` refusal goes where `_disableFeatureBody` already is (A on 1, 3, 5; W on 9, 11, 13).

**Growth [estimate]; lines from CTR-GOV-19's Change: module 33,780 B (57 M) / 35,570 B (60 M), release 33,594 / 35,386 B, library
33,903 / 35,694 B.** Sizes now [measured, T66b build]:

| Contract | Now (B) | Adds | After [estimate] | Margin to the 57 M line |
|---|---:|---|---:|---:|
| `WrappedLib` | 17,095 | the counter, the checks, setter with the tighter / looser table, member setter, views | 20.6–22.1 KB | ≥ 11.8 KB |
| W, kind 13 (largest) | 29,202 | five entries (ABI decode of the leg array, struct returns), the receiver / holder words | 30.2–31.0 KB | ≥ 2.8 KB |
| W, kinds 11 / 9 | 29,011 / 28,021 | the same | 30.0–30.8 / 29.0–29.8 KB | ≥ 2.9 KB |
| W, kinds 1 / 3 / 5 | 21,873 / 21,697 / 21,903 | the same | 22.7–23.7 KB | ≥ 10 KB |
| Z (3, 11), Q (5, 13) | 27,996 / 28,865; 28,283 / 29,465 | one word to each changed call | +0.05–0.15 KB | ≥ 4.1 KB |
| T, all six (largest 17,045) | | the same | +0.05 KB | ≥ 16 KB |
| A (1, 3, 5) | | the `disableFeature` refusal | +0.1 KB | — |
| the token (largest release `WrappedPqzRegulatedToken`) | 27,713 | five stubs and dispatcher rows | 28.0–28.2 KB | ≥ 5.3 KB |
| `GovernanceRouter` | 15,572 | two typed ops (the leg array's struct hash) | 16.3–16.8 KB | ≥ 16 KB |

**No W needs a split**: the largest, kind 13, stays at most about 31.0 KB, below the 57 M line by 2.8 KB and below T66b §3.4's
watch mark (31.7 KB). The deploy gas of W grows by about 1.6–3.0 M per kind at ≈ 1,606 gas per byte [estimate]. `GovernanceLib` does not
change: the pending of §6 is the namespace's own, keyed nowhere in governance storage.

## 9. Node, clients, vectors, families — SPECIFIED

- **Router ops** (fee mode `NONE`, as every governance op): `mtxSetWrapLimits(UAEnvelope e, address target, WrapLegLimits[]
  legs, bool netUnwrap, bool wrapList, bool unwrapList, UASig auth)` over `UASetWrapLimits(bytes32 from,address
  target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,uint256 batch,uint256 nonce,uint256 validUntil,uint32
  mode,address relayer,uint256 fee,address feeRecipient)WrapLegLimits(address underlying,uint8 unitExp,WrapLimit
  wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)WrapLimit(uint24 perUser,uint64 tokenWide,uint32
  period)`, the router hashing the struct words itself (`_uaCall` with `words ≠ data`); `mtxSetWrapMember(UAEnvelope e, address
  target, bytes32 account, bool canWrap, bool canUnwrap, bool exempt, UASig auth)` over `UASetWrapMember(bytes32 from,address
  target,bytes32 account,bool canWrap,bool canUnwrap,bool exempt,…)`. Both typehashes pinned (`*TypehashIsPinned`).
- **Node.** `typed.rs` gains the two router rows (with the referenced struct types); the router's `CALL_TABLE` rows in `guard.rs`
  equal the router's table, both directions. The tokens' `mtxSelectors()` and `_uaAllowed` do not change (governance is not on
  the generic allow-list), so no token row moves. A simulation revert with `WrapLimitExceeded`, `WrapCapExceeded`,
  `UnwrapAboveNetWrapped`, `WrapperNotListed` or `UnwrapperNotListed` is a named refusal of the class of NODE-LANE-09: the job
  stays `queued` with `error = WRAP_LIMIT_REFUSED: <named error>`, never `dead` while the payload may still land (a window ends, a
  member is added, a later wrap raises `net`); expiry or the attempt cap ends it (NODE-LANE-14); no grief score. The node runs the
  simulation before any submission, so the client sees the name before a transaction exists; it may skip re-simulating until the
  smallest `resetAt` of `wrapQuotaOf` / `wrapQuotaTotal`. A note for operators: a wrapped token's job can now wait for a window.
- **Clients and vectors.** `clientkeys` `evm.js` rows for both ops and the decoder entries of the new errors; `typed_ops.json`
  regenerated by its generator; `ua-rs`, the one signer, builds and signs both ops; every `ua-*` reads the same rows.
  `governance_bits.json` gains bits 25 and 26 (name, type, kinds, holder) and their sentences: the limits and the notice, the
  lists, the net rule and its rounding, the exemption, the Sybil note, the burst. `test/vectors/selector_audit.json` classifies the
  new entries. Wallets read the three views (§7); no client computes a window itself.
- **Families.** One rule on every chain: the same limits, errors and order on every family with wrapped kinds, built in each
  family's own round (PLANNED; Hedera with its round). EVM first.

## 10. Gas — SPECIFIED (estimates)

All **[estimate]**, from Amsterdam's prices as measured in this repository (a new slot ≈ 97,920 state gas under EIP-8037, as the
`acceptMembership` rows of `decisions.md` measured); the build measures each with `--isolate` and moves every pin old → new.

| Case | Extra per wrap or unwrap |
|---|---|
| token without bits 25 / 26, or never configured | no new read (`ctl` is in slot a, already read); the extra argument words, ≈ +30 to +150 gas |
| lists only (bit 26) | the member byte: ≈ 2.1 k |
| tracked (bit 25), the user's slot exists | the leg's config side 2.1 k + the user's slot 2.1 k read + 2.9 k write ≈ **7 k**; an unwrap reads the same |
| tracked, the id's first use on that leg | one new slot: ≈ **98 k state gas** + ≈ 5 k regular |
| a token-wide part on | its window slot ≈ 5 k (the first use of that leg and side: ≈ 98 k state gas, once per token) |
| payer ≠ credited id (`wrapToUA`, wrap-shield, an order to another id) | the credited id's slot: ≈ 5 k, or ≈ 98 k when new |
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
| 6 | fixed window | refused at `start + period − 1`, passes at `start + period`; the start moves only on a new window | `<` → `<=`; the start reset on every use |
| 7 | modular time | warp past `2^32`: windows behave; an aliased stale window refuses, never allows | signed or unmasked subtraction |
| 8 | net rule | received-by-transfer units refused; own wraps pass; an exempt id passes | credit to the payer on `wrapToUA`; debit `⌊⌋`; the rule on while the option is off |
| 9 | net tracked while off | wrap, turn the option on, unwrap within `net` passes | tracking only while on |
| 10 | relayed paths | `mtxWrap`, `mtxExecute(wrap)`, `mtxBatch` (second item refused), a derived UA's `mtxUnwrap` | `_msgSender()` as the id (every derived UA on `UA_POOL`'s quota) |
| 11 | wrap order | `o.from` counted, the submitter not | `msg.sender` counted |
| 12 | wrap-shield / unshield-unwrap (3, 5, 11, 13) | payer counted, `toUA` credited; the proof's sender counted; the refusal before the proof (gas below the verifier's) | the envelope's `from` counted; the count in the pre-proof `quoteTo` too (counted twice) |
| 13 | mint not counted | a hybrid mint leaves windows and `net` | the mint credits `net` |
| 14 | tighter at once | each tighter field applies in one call | `eff(0)` read as the tightest |
| 15 | looser waits | `GrantNotReady` before `eta`, applies in `[eta, eta + delay]`, dead after, dead after an owner change; a mixed call waits; a new proposal replaces the old | the window unchecked; the generation unchecked; the period's direction inverted |
| 16 | Q1 reading (if adopted) | an unwrap tightening waits, an unwrap relaxing applies at once | the unwrap side classified as the wrap side |
| 17 | unit write-once | a changed `unitExp` after the first configuration: `WrapUnitInvalid` | `unitExpCopy` not written |
| 18 | disable refused while on | `disableFeature(25)` with a limit on: `WrapControlActive` | the check missing for bit 26 |
| 19 | bits and kinds | 25 / 26 refused on 0, 2, 4, 8, 10, 12; the setter without the bit: `FeatureNotSet` | 25 in a normal kind's mask |
| 20 | per leg | a limit on leg A leaves leg B; `net` per leg (wrap USDC, unwrap DAI refused under the option) | one `Quota` per id across legs |
| 21 | `ctl` copies | after every setter every leg's `ctl` equals the configuration | one leg not written |
| 22 | +0 when off | `vm.accesses`: no new slot read on wrap and unwrap of a token without the bits | `ctl` in a new slot |
| 23 | views | `left` passes exactly, `left` + one quantum refused; `resetAt` equals the refusal's lift | `left` from the wrong window |
| 24 | order (§4) | on 9: a frozen relayed sender gets `Frozen` before any limit; a direct frozen unwrapper `Frozen` at the burn | the list after the pull |
| 25 | node | `WRAP_LIMIT_REFUSED` keeps the job `queued`, never `dead` | classified `reverted` |

Run at the four PQZ sets for kinds 5 and 13 (`script/pqz/at-set.sh <set> test`, one run per work tree, `PqzSet.sol` restored).

**Pins.** `test/v2/layout/namespaces.json`: a `wrapLimit` entry (root, every field of `WrapLimitStorage` at the probe keys, the
`Quota` byte offsets of §5) and the `underlying` entry's new `legs[1].ctl` (slot 0, inner 0, byte 24), both through
`Layout.t.sol` `test_namespaceRootsAndOffsetsArePinned`. Typehash pins for the two router structs. `size-baseline.json` rows old →
new with the reason. Gas pins old → new.

**On-chain matrix rows** (`script/onchain/`, `coverage.json` gains the five token entries per wrapped kind and the two router
ops). A token with a short `grantDelay` is not needed: the factory's `noticePeriod()` of the local chain decides; the run uses a
chain with a non-zero notice for the two-call rows, or records them as one call where it is 0.

| Group | Rows |
|---|---|
| gov | `mtxSetWrapLimits` tightening (applies); relaxing (proposed, then confirmed after the notice); `mtxSetWrapMember`; `disableFeature(25)` refused while on |
| tokens (1, 9) | a wrap within the limits; a wrap over: expected revert `WrapLimitExceeded`; a token-wide `WrapCapExceeded`; an unwrap of transferred units under the net option: `UnwrapAboveNetWrapped`; an exempt id passes; `wrapToUA` credits `to`; a relayed `mtxUnwrap` of a derived UA counted on the UA; `mtxWrapOrder` counted on `o.from`; the three views |
| zether (3, 11), pq (5, 13) | `mtxWrapShield` within and over; `mtxUnshieldUnwrap` refused before the proof; the views |
| views | `wrapLimits`, `wrapQuotaOf`, `wrapQuotaTotal` on every wrapped kind |

## 12. Owner questions

Q1–Q10 are the controller's review points of 2026-11-10, open; Q11–Q13 come from this design. Each has a recommendation.

| # | Question | Recommendation |
|---|---|---|
| Q1 | **Holder protection on unwrap.** As ruled, tightening the unwrap side at once lets the owner stop redemptions instantly (§6), against CTR-TOK-07 and CTR-GOV-17's "unwrap is never paused". | **Unwrap: tightening waits the notice period, so holders can exit first; relaxing applies at once. Wrap: as ruled (tighter at once, looser waits).** The asymmetry is stated in the disclosure; §6's table has both columns; test 16. Membership changes stay at once (a lister can stop one id's unwrap when the list is on, as FREEZE does on 9, 11, 13). |
| Q2 | **The net rule and received units.** A merchant paid in wrapped units never wrapped them, so it could never unwrap under the rule. | **An exemption by a separate member flag `exempt`**, set by the holders of bit 26, freeing an id from the net rule (and from the per-user parts, Q3). Not "every unwrapper-list member": with the list on, every unwrapper is a member, and the rule would bind nobody. |
| Q3 | **Whose quota.** | **The subject**, never `msg.sender` of a relay: the direct caller, the signer of a relayed op, the signer of a DEX wrap order (`o.from`), the proof's sender of an unshield-unwrap; service pulls move no reserve; a future liquidity module wraps through `mtxWrapOrder` (its signer counts). **`net` is credited to the id that receives the units** (`to`, `toUA`, the order's destination). A contract that wraps for itself (a pool, an escrow) is its own subject; the issuer marks a trusted one `exempt` (Q2's flag), no second list. |
| Q4 | **Multi-leg tokens.** | **Per leg, in that leg's own units and decimals**: each leg its own four limits, token-wide caps, `unit` and `net` (§2, §5); one slot per id and leg, one per id on a one-leg token. A per-leg token-wide unwrap cap also slows the drain of the good legs in a depeg (CTR-TOK-07). |
| Q5 | **Sybil.** | **Say it plainly**: per-user parts can be split across many UAs; the token-wide cap is the real outflow guard; per-user parts mean something only with the matching list on. In the disclosure and §2. |
| Q6 | **Fixed-window burst.** | **Accept and document**: up to 2× a cap within one `period` across a window boundary (R2's trade-off); the long limit bounds repeats. |
| Q7 | **Amount units.** | **The underlying moved**: a wrap's measured `received` (for a fee-on-transfer leg what arrived), an unwrap's `out` (the reserve's exact drop). |
| Q8 | **Hard stop vs limit.** | **No new stop.** 0 means no limit; the stops are `disableWrap` (bit 4) and, on 9, 11, 13, `PAUSE` for wraps; for unwrap none on the public kinds by design, `FREEZE` per account, `PAUSE` on the unshield-unwrap of 11, 13. A one-quantum unwrap limit is a near-stop and falls under Q1. |
| Q9 | **Views, events, pre-checks.** | **As §7 and §9**: the remaining quota per user and token-wide with `resetAt` (the next window's earliest start), events on every applied and proposed setting and membership change, and the node's named refusal `WRAP_LIMIT_REFUSED` before any submission. |
| Q10 | **Defaults.** | **Every limit off on new tokens until set; no limit ever on tokens of earlier releases.** The two bits are chosen at creation and off by default (features only lose bits, so a holder sees whether a token can ever limit). |
| Q11 | **Which delay is "the notice period".** The `_delayedRelaxBits` pattern waits the token's `grantDelay`; the tax rate waits the factory's `noticePeriod()` (pay-meta-tax Q9). | **The factory's `noticePeriod()`**, with the two-call shape of `_delayedRelaxBits`: the owner's word, the tax precedent, and an issuer cannot set it to 0 on a chain that has a notice (`grantDelay` may be 0 per token). No bypass through `disableFeature` (§2: refused while on). |
| Q12 | **"Hybrid" kinds.** The ruling says "the wrapped (hybrid) kinds". | **Every token of the six wrapped kinds**, hybrid or not: the check sits in `WrappedLib`, which all share; limiting only `maxSupply ≠ 0` would add a branch and protect nothing. |
| Q13 | **Quanta vs raw.** R7's one slot holds four windows and `net` only in quanta of a per-leg `unit`. | **Quanta, one slot per id and leg** (§5), the unit fixed by the first configuration. The other reading, two slots per id and leg in raw units, costs ≈ 98 k state gas more on an id's first unwrap. |

## 13. Tasks and estimates — SPECIFIED

Placed by the controller in the pre-freeze work order of branch `ua-mtx-merge` (contracts are immutable: before the EVM freeze),
after the owner answers §12. Estimates assume the recommendations.

| # | Task | Agent-days |
|---|---|---:|
| WL1 | Contracts: `scaas.wraplimit` and `ctl` in `WrappedLib` (counter, checks, setter with the tighter / looser table and the pending, member setter, views); bits 25 / 26 in `GovernanceBits` and the kind masks; the receiver / holder words through W, Z, Q, T; `entries.json` and the regenerated faces; the `disableFeature` refusal; `IWrappedToken` errors, events, views; legacy copy of the touched bodies first | 2.5–3 |
| WL2 | `GovernanceRouter`: the two typed ops, typehashes and pins, its selector table | 0.5 |
| WL3 | Tests and mutants of §11 (25 rows), at the four PQZ sets for 5 and 13 | 2–2.5 |
| WL4 | Gates: forge, size gate rows old → new, gas pins old → new (`--isolate`), layout and typehash pins, deploy gas of W against 60 M | 1 |
| WL5 | Node: `typed.rs` rows, `CALL_TABLE`, the `WRAP_LIMIT_REFUSED` class and its tests, an operator note | 1–1.5 |
| WL6 | Clients and vectors: `governance_bits.json` 25 / 26 and sentences, `typed_ops.json`, `clientkeys` rows and decoder, `ua-rs` builder and tests, the `ua-*` vector readers, `selector_audit.json` | 1.5–2 |
| WL7 | On-chain matrix rows of §11 and `coverage.json` | 1 |
| WL8 | Docs: the rule in `token-wrappers.md` (next free CTR-TOK id) and its `decisions.md` entry with the owner's answers, bits 25 / 26 in the governance docs, the node row in `job-api.md` and `submit-lanes.md`, the disclosure text | 0.5–1 |
| | **Total** | **10–12.5** |
