# Role `BURNER` (3zb) and wrapped supply caps (3zc) — design

**Status:** BUILT on branch `burner-wrap-caps` (2026-11-15; EVM, node, clients; the other families follow in their rounds), **UNAUDITED**. Was: SPECIFIED, nothing built. Written 2026-11-13 from TODO items 3zb and 3zc (owner rulings of
2026-11-13, quoted there verbatim, applied here and not reopened). Read against `ua-mtx-merge` at `cf6f785a`. Order (owner):
this round runs **after the PQZ three-key round (3za) and before reset 4**, on a branch cut from the merged three-key
result. The three-key round splits the PQZ regulated ops module and changes the registry, so this spec names modules **by
role** ("the admin module", "the wrap module", "the PQZ ops module"), not by today's letters. No gas or size figure here
was measured: **[estimate]** is arithmetic over the committed baseline, **[baseline]** is `size-baseline.json` at
`cf6f785a` (stale once the three-key round lands: step 0 re-measures every row). Revised 2026-11-13 after the
independent Fable review `20261113-18-fable-fable5.2-high-spec-burner-wrap-caps.md` (S-1 to S-17, each checked against
the code; §10 maps them).

Sources read: `GovernanceBits`, `GovernanceLib`, `GovernanceBase`, `IGovernance`, `GovernanceRouter(Base)`,
`NormalTokenCore`, `WrappedTokenCore`, `WrappedLib`, `IWrappedToken`, `PqzLayer`, `NormalPqzTokenCore`,
`WrappedPqzTokenCore`, `WrappedZetherTokenCore`, `ZetherLayer`, the regulated cores, `IFactoryToken.TokenConfig`,
`governance_bits.json`, `scripts/size_gate.py`, `decisions.md` (CTR-GOV-10, -12, -27, -28), the wrap-limits spec
`2026-11-10-wrap-limits.md`, the node's `typed.rs` / `guard.rs` / `abi.rs`.

## 0. Rulings applied (summary; the TODO text is the authority)

| # | Ruling |
|---|---|
| B1 | Burn has three creation-time modes on the Normal kinds (0, 2, 4, 8, 10, 12): off; `BURNABLE` (bit 2, any holder, own balance, no limit); `BURNER` (a role with a scalar, like `MINTABLE`). `BURNABLE` and `BURNER` are exclusive. |
| B2 | A `BURNER` holder burns only its **own** balance, within its grant (min / max / total / perWindow+window / maxUses / validUntil / delegable narrower). Never another account's (that is `FORCE`). |
| B3 | Covers `burn`, `mtxBurn` and the generic `mtxExecute` burn. The confidential `R_BURN` / `ZetherBurn` unshield is not gated (ruling O1 below, §2.3). |
| B4 | Wrapped kinds: no burn, unchanged. |
| B5 | The admin may disable `BURNER` later, one-way, all burns stop, like `MINTABLE`. Switching between `BURNABLE` and `BURNER` stays refused. |
| C1 | A hybrid's `maxSupply` is changeable by the admin through one governed path, both directions, delayed, with the chain word and an event. Floors: `>= totalSupply()`, `!= 0`, `>= maxWrapSupply` when that is non-zero. No free undelayed decrease. |
| C2 | `maxSupply` stays the TOTAL cap (wrap and mint both count). |
| C3 | `reserveValue()` = Σ ⌊reserve_i · q_i⌋, on every wrapped kind. |
| C4 | `maxWrapSupply` (cap) and `totalWrapped` (counter) on every wrapped kind, pure wraps and hybrids. A wrap of `x` passes only if `totalWrapped + x <= maxWrapSupply`; 0 = no wrap cap. `maxWrapSupply <= maxSupply` when both non-zero. Changeable through the same delayed path; a new non-zero value is `>= totalWrapped()` and `<= maxSupply` (non-zero). Unwrap subtracts what it burns, saturating at 0. The minter's mint is bound by `maxSupply` only. Error `MaxWrapSupplyExceeded`, not `WrapCapExceeded`. |
| C5 | Feature bit `SUPPLY_CAP_ADJUSTABLE`, chosen at creation: set = both caps changeable; unset, or disabled later (one-way) = both fixed for good. |
| C6 | The delay of a cap change is the token's `grantDelay`. No new parameter. |
| C7 | Convention: an uncapped hybrid uses `maxSupply = 2^256 - 1`. |
| — | Accepted, not re-raised: a minter may mint unbacked units and unwrap them against the reserve; a user can send units to an unspendable address (not a burn). |

### 0.1 Owner rulings on this spec (2026-11-13, relayed by the controller)

| # | Ruling (verbatim) | Content | Status |
|---|---|---|---|
| O1 | "1, 2 theo đề xuất." (question 1) | `BURNER` gates only the public `burn` / `mtxBurn` and the generic `mtxExecute` burn. The confidential `R_BURN` / `ZetherBurn` unshield is **not** gated: a shielded holder unshields, then burns under the role check. | SPECIFIED, §2.3; nothing built |
| O2 | "1, 2 theo đề xuất." (question 2) | No zero-recipient guard is added to `_poolMove` (every caller already refuses 0). | closed, nothing to build |
| O3 | "OK, giữ chainUid_" | The direct setters stay `setMaxSupply(uint256, bytes32 chainUid_)` and `setMaxWrapSupply(uint256, bytes32 chainUid_)`; the router ops carry the word as a signed field. | SPECIFIED, §3.5, §3.7; nothing built |
| O4 | "OQ1, OQ2 theo đề xuất" (OQ1, review S-1) | No: a pending lower cap does **not** bind new wraps or mints before its apply. The blocking behaviour stays as documented, with the listed remedies. | SPECIFIED, §3.5; nothing built |
| O5 | "OQ1, OQ2 theo đề xuất" (OQ2, review S-12) | Yes: `setWrapLimits` and `mtxSetWrapLimits` gain the chain word in this round (direct entry: trailing `chainUid_`, `NotAdmin` then `ChainUidMismatch` before any write; router op: a signed field). `setWrapMember` stays without. | SPECIFIED, §3.8; nothing built |
| O6 | "(2), gộp vào round 3zb + 3zc." | CTR-GOV-28 widens from admin entries to **every direct entry a role holder calls**, in this round: `setWrapMember` (this replaces O5's "stays without") and every power entry of the 12 token kinds and the DEX. Pattern: trailing `bytes32 chainUid_`, one shared helper, the caller's check first, then the word, before any write; the router ops sign the word. | SPECIFIED, §3.9; nothing built |
| O7 | "OQ3 theo đề xuất" | `burn(amount)` in `BURNER` mode and the unwrap entries that draw on `REDEEMER` stay **without** the chain word: they are every user's own-balance entries. The ERC-20 `burn(uint256)` selector, the `UABurn` / `UAUnwrap*` typehashes and the tokens' allow-lists are unchanged. | SPECIFIED, §3.9; nothing built |
| O8 | "Đồng ý, chuyển sang module trong round 3zb + 3zc" | `SCaaSDex`'s four power entries (`setMarket`, `setExchangeTarget`, `setListedOnly`, `setFeeSplit`, with `_power` and their chain word) move from the main contract into `SCaaSDexGovernanceModule` in this round, deliberately, not waiting for the T-1 line. | SPECIFIED, §3.10; nothing built |

## 1. Governance bits — SPECIFIED

Bits 13, 14 are "never reused", 15, 16 are reserved names, 18-20 are the catalogue's. The free band starts at 30.

| Bit | Name | Type | Valid on kinds | Holder | Scalar |
|---|---|---|---|---|---|
| 30 | `BURNER` | power (role) | 0, 2, 4, 8, 10, 12 | any (EOA, single-key UA, `msig`, contract) | yes: the amount burnt, raw units |
| 31 | `SUPPLY_CAP_ADJUSTABLE` | capability (no holder) | 1, 3, 5, 9, 11, 13 | — | — |

If the three-key round takes 30 or 31, use the next two free numbers; fix them in build step 1, before any vector.

`GovernanceBits` edits (every kind's mask composes from these, so no core restates a mask):

| Constant | Change |
|---|---|
| `NORMAL_BITS` | `|= 1 << BURNER` |
| `NORMAL_ROLES` | `|= 1 << BURNER` |
| `TOKEN_SCALAR` | `|= 1 << BURNER` (inert on the wrapped kinds: bit 30 is not in their role mask, a grant there is `NoSuchRole`) |
| `WRAPPED_BITS` | `|= 1 << SUPPLY_CAP_ADJUSTABLE` |
| `ALWAYS_LOCKED` | unchanged: neither bit. `BURNABLE` stays always locked. Each new bit is lockable by the creator through `lockedFeatures`, as `MINTABLE`. |
| `ENABLEABLE` | unchanged: neither bit is ever switched on after creation (`FeatureNotEnableable`). |
| `NOT_DISABLEABLE` | unchanged: both are disabled one-way by the admin with `disableFeature(bit, chainUid_)` unless locked. |
| contract-only, scope, `ISSUER_BITS`, `_delayedRelaxBits` | unchanged: neither bit. A revoke of a burner, and the disable of either bit, apply at once (as `MINTABLE`). |

Exclusivity at init, in `GovernanceLib.init` (one place for the six Normal kinds):
`features` holding both bit 2 and bit 30 reverts `IGovernance.FeatureConflict(uint8 bit, uint8 other)` = `(30, 2)` (new
error). Bit 30 on a wrapped kind and bit 31 on a Normal kind are `FeatureInvalidForKind` by the masks.

Initial holder: `GovernanceLib.Roles` gains a last field `bytes32 burner` (`init`: `if (roles.burner != 0) _grant(BURNER,
…)`, a `WHOLE` root, `RoleWithoutFeature(30)` without the bit), the twin of `minter`. Reason: without a seat a `BURNER`
token with `admin == 0` could never burn. With `admin == 0` the seat needs bit 30 in `lockedFeatures`: `init` runs
`_noLiveHolder`, and a set, unlocked role bit with a root reverts `AdminHasHolders(30)` (as the minter seat today).
`roles.burner` on a wrapped kind is `NoSuchRole(30)` (`_check`: the bit is not in the kind's role mask). Limits come
after, by `setGrant`. `TokenConfig` changes anyway (§3.2). `SCaaSDex.initialize` passes an empty `Roles` to
`GovernanceLib.init`, so the sixth word moves the DEX's bytecode too (§7).

Switching modes later is impossible by construction: bit 2 is always locked and never enableable, bit 30 is never
enableable. Disabling 30 leaves the token in mode off for good.

## 2. Burn (3zb) — SPECIFIED

### 2.1 The entry

One body serves all six Normal kinds, `NormalTokenCore._burnBody(amount)`; `mtxBurn` and the generic `mtxExecute` reach it
by the self-call, so there is one check for every path:

```
f = features
if (f has BURNER)  GovernanceUse.use(BURNER, _subject(), amount);   // FeatureNotSet / MissingRole / GrantExpired / GrantExhausted(field)
else               GovernanceLib.requireFeature(BURNABLE);          // off, or BURNER disabled: FeatureNotSet(2), as today
_burn(_msgSender(), amount);
```

- **Who is checked:** `_subject()`, the id whose balance `_burn(_msgSender(), …)` debits: the ticket's subject under a
  signed call (a derived UA burns its UA-ledger balance through `UA_POOL`), else the padded direct caller. Never
  `_govSubject()`: a router call would check one id and burn another. Own balance only, by construction (B2).
- **Scalar = `amount`**, raw units. A `WHOLE` holder (the seat, or `grantRole`) has no limit; a `LIMITED` holder is
  debited by `useLimited` (`GrantUsed(30, holder, amount)`); a leaf debits its parent too (generic).
- `BURNABLE` and off modes: byte-for-byte today's behaviour and errors. A `BURNER` token whose bit 30 was disabled
  answers `FeatureNotSet(2)` though it never had bit 2: a client must not key its burn button on bit 2 alone; it reads
  bit 2, else bit 30 and `hasRole(30, id)` (`docs/clients/`).
- Regulated Normal kinds (8, 10, 12): the regulated hooks are unchanged (`F(from)`, `L(from)` on the burn row; burn is not
  paused). A frozen or denied burner cannot burn.
- Order of refusals on `mtxBurn`: the pipeline's (envelope, signature, allow-list, nonce) first, then the body's role
  check inside the self-call; a refused burn reverts the whole call, nonce unused.

### 2.2 Router, allow-lists

No router op for burn: the router acts for a subject but the balance burnt is the caller's, so a `mtxBurn` op on the
router could only burn the router's own balance. A UA holder signs the token's own `mtxBurn` (`UABurn`, unchanged
typehash, relayable at fee 0). `mtxSelectors`, `_uaAllowed`, `_mtxRule`: unchanged. Granting, limiting and revoking a
burner use the existing `mtxGrantRole`, `mtxSetGrant`, `mtxRevokeRole`, `mtxDisableFeature` with `bit = 30`.

### 2.3 The confidential kinds (2, 4, 10, 12)

Code fact at `cf6f785a`: on a Normal confidential kind the `R_BURN` / `ZetherBurn` path (`mtxUnshield`) **moves** public
units from `SHIELD_POOL` to a recipient (`_fromPool`); `totalSupply()` does not change, and the path does not read
`BURNABLE` today (mode off still unshields). The only path that lowers `totalSupply()` on these kinds is the public
`burn` / `mtxBurn` of §2.1.

Ruled (O1): `mtxUnshield` (and the refresh, amount 0) is **not** gated by `BURNER`; a shielded holder that wants to
destroy units unshields to itself and burns, and that burn is role-checked on the subject. Supply only falls by a role
holder's burn, and every user can still leave the shielded pool.

## 3. Wrapped supply caps (3zc) — SPECIFIED

### 3.1 Storage

No new namespace: three fields appended to `WrappedLib.WrappedStorage` (`erc7201:scaas.underlying`); nothing deployed is
upgraded and reset 4 follows, so an append is safe.

```
uint256 maxSupply;            // +4, existing; the "immutable" comment goes: changeable under bit 31
uint256 maxWrapSupply;        // +5, 0 = no wrap cap
uint256 totalWrapped;         // +6
CapChange pendingMaxSupply;       // +7, +8
CapChange pendingMaxWrapSupply;   // +9, +10
struct CapChange { uint256 value; uint64 eta; uint32 generation; }   // eta 0 = none
```

`Leg.capped` (the copy of `maxSupply != 0`) stays valid: a hybrid stays a hybrid. Pins: `test/v2/layout/*.json` and
`namespaces.json` regenerated, old → new offsets in the commit.

### 3.2 Creation

`TokenConfig` gains `uint256 maxWrapSupply` right after `maxSupply` (WRAPPED* only; a Normal kind refuses a non-zero value
with `ConfigFieldForOtherKind(5)`, field 5 now "maxSupply / maxWrapSupply"). The Normal kinds refuse `maxSupply` at
**two** sites, and `maxWrapSupply` is refused at both: `MetaTokenBase._requireUnused` (kinds 0, 4, 8, 12) and
`ZetherLib.initNormal` (kinds 2, 10, whose init never reaches `_requireUnused`). `WrappedLib.initToken`, the one init of
all six wrapped kinds (`WrappedTokenCore`, `ZetherWrappedLib.init`, `PqzWrappedLib.init` call it), checks
`maxSupply != 0 && maxWrapSupply > maxSupply` → `MaxWrapSupplyInvalid()` and stores it; `totalWrapped` starts 0. Bit 31 is
valid on a pure wrap (its `maxWrapSupply` is adjustable; its `maxSupply` is 0 and stays 0).

### 3.3 The counter, on every path

All paths already pass two mint-side and two burn-side functions of `WrappedLib`; the counter lives there, not in the
cores. On the mint side a path cannot forget it (`minted` is computed in the library). On the burn side the library
cannot check the number: each of the four core call sites passes `burned`, so each has its own test and mutant (§6).

| Path (entries) | Core call site | Lib choke point | Counter |
|---|---|---|---|
| `wrap(amount)`, `wrap(u, amount)`, `mtxWrap`, `mtxWrapLeg`, generic `mtxExecute` | `WrappedTokenCore._wrap` | `WrappedLib.wrap` | `+ minted` |
| `wrapToUA`, `mtxWrapToUA` | `_wrap` (`to != 0`) | `WrappedLib.wrap` | `+ minted` |
| `mtxWrapOrder` (signature wrap) | `_mtxWrapOrderBody` | `WrappedLib.wrapBySigUA` | `+ minted` (the submitter's fee part included) |
| Zether `mtxWrapShield` (direct and signed) | `WrappedZetherTokenCore._mtxWrapShieldBody` | `WrappedLib.wrap` | `+ minted` |
| PQZ `mtxWrapShield` (direct and signed) | `WrappedPqzTokenCore._mtxWrapShieldBody` | `WrappedLib.wrap` | `+ minted` |
| `unwrap` ×3, `mtxUnwrap`, `mtxUnwrapLeg`, generic | `_unwrap` | `WrappedLib.payOut` | `− burned` (`⌈out·q⌉`) |
| `unwrapToUA`, `mtxUnwrapToUA` | `_unwrapToUABody` | `WrappedLib.payOutToUA` | `− burned` |
| Zether `mtxUnshieldUnwrap` (direct and signed) | `WrappedZetherTokenCore` | `WrappedLib.payOutTo` | `− wrapped` (all of `amount·shieldScale`, burnt from `SHIELD_POOL`) |
| PQZ `mtxUnshieldUnwrap` (direct and signed) | `WrappedPqzTokenCore` | `WrappedLib.payOutTo` | `− wrapped` |

- `payOut`, `payOutToUA` take a new `uint256 burned` parameter (`payOutTo` passes `wrapped`); the subtraction is
  `totalWrapped = totalWrapped > burned ? totalWrapped - burned : 0`, written in the one helper both already share
  (`_unwrapCount`'s caller position, before `reserve -= out`).
- Paths that do **not** move it: `mint`, `mintToUA` (minter), `mtxShield` / `mtxUnshield` (public ↔ pool moves),
  `addReserve`, transfers, fees, `rescue`, a rate change. The three-key round's new entries: any that mints by a wrap or
  burns by an unwrap must go through the same lib functions (checked in build step 0).
- Invariants (tests): `totalWrapped() <= totalSupply()` always; on a pure wrap `totalWrapped() == totalSupply()` exactly
  (every unit is born by a wrap and dies by an unwrap), which is the positive control for every path.

### 3.4 The wrap check

In `WrappedLib.wrap` and `wrapBySigUA`, after `minted` is known and after the existing `_cap` (order of refusals:
`WrapDisabledFor` → `WrapPausedForRateChange` → wrapper list → pull → `WrapTooSmall` → `MaxSupplyExceeded` →
`MaxWrapSupplyExceeded` → the wrap-limit windows):

```
next = totalWrapped + minted            // cannot overflow: totalWrapped <= totalSupply
if (maxWrapSupply != 0 && next > maxWrapSupply) revert MaxWrapSupplyExceeded(next, maxWrapSupply);
totalWrapped = next;
```

`MaxWrapSupplyExceeded(uint256 totalWrapped, uint256 maxWrapSupply)`: the first word is the value the wrap would reach,
as `MaxSupplyExceeded` names the supply it would reach. Both this cap and the wrap-limit windows bind a wrap.

Where the write goes: in `wrap` right there (pull → counter → the token's mint, no outside call in between). In
`wrapBySigUA` the **check** runs in `_sigQuote` (it stays `view`), before the leg's `mtxTrade`, and the **write**
(`totalWrapped = next`) after `_sigReceived`, so a reader called from inside the leg never sees `totalWrapped` ahead of
`totalSupply()`; the token's guard excludes a second wrap in between. The unwraps are burn → counter → pay.

### 3.5 The two setters

```solidity
function setMaxSupply(uint256 newMaxSupply, bytes32 chainUid_) external;          // hybrids only
function setMaxWrapSupply(uint256 newMaxWrapSupply, bytes32 chainUid_) external;  // every wrapped kind
```

Both `governed`, in the wrap module beside `mint` and `setWrapLimits`; the core body is
`WrappedLib.setMax…(value, _adminOnChain(chainUid_), totalSupply())`, so the order is CTR-GOV-28's: `NotAdmin`, then
`ChainUidMismatch`, before any write. Why the direct setters carry `chainUid_` (O3): a native admin's transaction
signature binds only the chain id and the contract sees only calldata, so on a sibling chain with the same chain id, an
aligned nonce and the same token address the transaction would replay unless the token's own chain word is a parameter it
checks; the router ops carry the same word as a signed field. Then, in the library:

1. `FeatureNotSet(31)` unless bit 31 is set (unset at creation, or disabled: both caps fixed for good; a pending dies
   with it, nothing to clean).
2. Shape, at both calls: `setMaxSupply` needs the current `maxSupply != 0` and `newMaxSupply != 0`, else the existing
   `MaxSupplyInvalid()`. `setMaxWrapSupply` takes any value, 0 included (0 removes the wrap cap).
3. Delay = the token's `grantDelay`, in the two-call shape `setWrapLimits` already uses (`WrappedLib._due`), one pending
   per cap, both directions alike:
   - `grantDelay == 0`: applies at once.
   - no live pending with this value: **propose**: write `(value, eta = now + grantDelay, adminGeneration)`, emit
     `…Proposed`, return. A proposal with another value replaces the pending and restarts the clock.
   - a live pending with this value: before `eta` `GrantNotReady(31, 0, eta)`; in `[eta, eta + grantDelay]` under the same
     admin generation: delete it and **apply**. Past the window, or after a change of admin, the pending is dead and the
     call proposes again.
   - No cancel entry: an unwanted pending is left to die or replaced. The idiom: propose the current value; it
     replaces the pending, and confirming it changes nothing.
   - A call sent after the window does not revert: it proposes again. A landed setter transaction is therefore a
     proposal or an apply; the event tells which (`…Proposed` / `…Set`), and the node and the docs say so.
   - A proposal writes `lastProposedAt` (the governance layer's "something is pending" signal; the delay is its
     `grantDelay`). `setWrapLimits` does not, and that part of it is left as it is.
   - No event when a pending is replaced (the new `…Proposed` shows it) or dies (an indexer infers it from
     `AdminTransferred`, `FeatureDisabled(31)` or the clock).
4. Floors, at **apply** only, against the state then (the state moves during the delay, and a joint raise of both caps
   can then be proposed together and applied `maxSupply` first):
   - `setMaxSupply`: `newMaxSupply >= totalSupply()` else `MaxSupplyBelowSupply(newMaxSupply, totalSupply)`;
     `maxWrapSupply == 0 || newMaxSupply >= maxWrapSupply` else `MaxSupplyBelowWrapCap(newMaxSupply, maxWrapSupply)`.
   - `setMaxWrapSupply`, for a non-zero value: `>= totalWrapped` else
     `MaxWrapSupplyBelowWrapped(newMaxWrapSupply, totalWrapped)`; `maxSupply == 0 || <= maxSupply` else
     `MaxWrapSupplyAboveMaxSupply(newMaxWrapSupply, maxSupply)`.
5. Write, emit `…Set`.

To lower `maxSupply` under the current `maxWrapSupply`, lower `maxWrapSupply` first (both may be pending together).

**Consequence of the apply-time floor (review S-1), stated as behaviour:** a lower cap applies only if supply is still
under it at the apply. The proposal is public for `grantDelay`; anyone who wraps above the pending value before `eta`
and holds through `[eta, eta + grantDelay]` makes the apply revert (`MaxSupplyBelowSupply` /
`MaxWrapSupplyBelowWrapped`), at the cost of locked capital only; the minter's mint does the same to `maxSupply`. The
admin's remedies with existing tools, before or during a decrease (`ops.md`): on a hybrid with bit 25, a token-wide
wrap limit (tightening the wrap side applies at once); with bit 26, the wrapper list (turning it on applies at once);
revoke or narrow the minter (at once), or `disableFeature(MINTABLE)`; on any wrapped kind with `WRAP_DISABLEABLE`, the
guardian's `disableWrap` of a leg, which is one-way. A pure wrap has no bit 25 / 26 (hybrids only), so there only
`disableWrap` answers. Ruled (O4): this is not closed on chain; a pending lower value binds nothing before its apply.

### 3.6 Events, errors, views (all in `IWrappedToken`)

```solidity
event MaxSupplyProposed(bytes32 indexed by, uint256 maxSupply, uint64 eta);
event MaxSupplySet(bytes32 indexed by, uint256 oldMaxSupply, uint256 newMaxSupply);
event MaxWrapSupplyProposed(bytes32 indexed by, uint256 maxWrapSupply, uint64 eta);
event MaxWrapSupplySet(bytes32 indexed by, uint256 oldMaxWrapSupply, uint256 newMaxWrapSupply);

error MaxWrapSupplyExceeded(uint256 totalWrapped, uint256 maxWrapSupply);
error MaxWrapSupplyInvalid();                                    // creation: above a non-zero maxSupply
error MaxSupplyBelowSupply(uint256 maxSupply, uint256 totalSupply);
error MaxSupplyBelowWrapCap(uint256 maxSupply, uint256 maxWrapSupply);
error MaxWrapSupplyBelowWrapped(uint256 maxWrapSupply, uint256 totalWrapped);
error MaxWrapSupplyAboveMaxSupply(uint256 maxWrapSupply, uint256 maxSupply);

function maxWrapSupply() external view returns (uint256);
function totalWrapped() external view returns (uint256);
function reserveValue() external view returns (uint256);
function pendingSupplyCaps() external view returns (
    uint256 pendingMaxSupply, uint64 maxSupplyEta, bool maxSupplyLive,
    uint256 pendingMaxWrapSupply, uint64 maxWrapSupplyEta, bool maxWrapSupplyLive);
```

None collides with `WrapCapExceeded` / `WrapLimitExceeded` (wrap limits) or `MaxSupplyExceeded` / `MaxSupplyInvalid`
(existing, kept). `…Live` in `pendingSupplyCaps()` is false whenever bit 31 is not set (a disabled token keeps the
pending's storage but shows no live proposal), as well as past the window or after an admin change.
`GrantNotReady(31, 0, eta)` is the same for both setters and `MaxSupplyInvalid()` serves creation and the setter's
shape: a client tells them apart by the entry it called. `reserveValue()` is the owner's name for the sum `collateralValue()` already returns on every wrapped
kind (`Σ⌊reserve_i·num_i/den_i⌋`, saturating): it calls the same library function; `collateralValue()` stays (no API is
dropped). Compare `reserveValue()` with `totalSupply()`; on a hybrid it may be lower by design.

### 3.7 Router ops and typed data (CTR-GOV-28)

Two rows in `GovernanceRouter`, fee mode `NONE`, relayable at fee 0, the word last among the op's fields and forwarded as
the entry's trailing argument:

```
mtxSetMaxSupply(UAEnvelope e, address target, uint256 maxSupply, bytes32 chainUid, UASig auth)
mtxSetMaxWrapSupply(UAEnvelope e, address target, uint256 maxWrapSupply, bytes32 chainUid, UASig auth)

UASetMaxSupply(bytes32 from,address target,uint256 maxSupply,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)
UASetMaxWrapSupply(bytes32 from,address target,uint256 maxWrapSupply,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)
```

Body: `_ua(T.UA_SET_MAX_SUPPLY, e, target, IWrappedToken.setMaxSupply.selector, abi.encode(maxSupply, chainUid), auth)`
and its twin. The propose and the apply are the same signed op sent twice (two nonces). Typehash pins in
`GovRouterTypehash.t.sol`. Disabling bit 31: the existing `mtxDisableFeature`.

### 3.8 `setWrapLimits` gains the chain word (O5)

The same sibling-replay class as the two cap setters: admin-only in code, delayed, in the same module.

```solidity
function setWrapLimits(WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList, bytes32 chainUid_) external;

mtxSetWrapLimits(UAEnvelope e, address target, WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList, bytes32 chainUid, UASig auth)

UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)WrapLegLimits(…)WrapLimit(…)
```

- Direct entry: the core body becomes `WrappedLib.setWrapLimits(legs, …, _adminOnChain(chainUid_), FACTORY)`: `NotAdmin`,
  then `ChainUidMismatch`, before any write and before the library's own checks (leg count, bits). The library's
  `_adminAndBits` admin check stays (a second guard, now unreachable by a stranger).
- The word is **not** part of the pending's commitment (`keccak256(abi.encode(legs, netUnwrap, wrapList, unwrapList))`
  unchanged): it is a constant of the token, and the propose and the confirm both pass it.
- Router: the word is the last op field (after `unwrapList`, before `uint256 batch`), signed and forwarded as the
  entry's trailing argument. The nested `WrapLegLimits` / `WrapLimit` type strings are unchanged.
- `setWrapMember` / `mtxSetWrapMember` (bit 26's holder) gain the word too, by O6 (§3.9). The wrap-limit views, events
  and errors: unchanged.
- What moves, old → new in the commit: the selectors of `setWrapLimits` and `mtxSetWrapLimits`, the `UA_SET_WRAP_LIMITS`
  typehash, `IWrappedToken`'s ERC-165 id, `entries.json` and the generated faces / wrap modules of the six wrapped
  kinds; the superseded forms go to `legacy/`.

### 3.9 Every role holder's direct entry carries the chain word (O6)

Why: a native holder's direct transaction is the same replay class as a native admin's (§3.5): the signature binds
only the chain id, so on a sibling with the same chain id, an aligned nonce and the same contract address it lands
again unless the contract checks its own word from calldata.

**Helper**, one, in `GovernanceBaseCore`, the shape `_renounceRoleBody` already has:

```solidity
/// The subject; if it holds `bit`, its word before any write. A caller without the bit is refused by the body, by the
/// name it has today (MissingRole, NotGuardian, NotRateAdmin, FeatureNotSet…): no existing refusal changes.
function _holderOnChain(uint8 bit, bytes32 chainUid_) internal view returns (bytes32 c) {
    c = _govSubject();
    if (GovernanceLib.$().roles[bit][c] != 0) _govChainWord(chainUid_);
}
```

Each body becomes `X(args…, _holderOnChain(BIT, chainUid_))` where it passed `_govSubject()`. Order: a stranger gets the
body's own refusal first (caller check), a holder gets `ChainUidMismatch(expected, got)` before the library runs, so
before any write and before a `LIMITED` grant is debited. On the DEX the four entries and `_power` move into the
governance module (O8, §3.10), where `_power(bit, chainUid_)` is `GovernanceUse.use(bit, _holderOnChain(bit, chainUid_), 0)`. Cost per call: one role-slot read that `GovernanceUse.use` then reads
warm, and 32 bytes of calldata.

**Inventory** (found by grepping `GovernanceUse.use`, `hasRole`, `MissingRole`, `NotGuardian`, `NotRateAdmin`,
`_onlyRateAdmin`, `_power`, `NotAdmin`, `onlyAdmin`, `NotKycProvider` over `src/` at `cf6f785a`; step 0 repeats the grep
on the new base). "Before" is the tree at `cf6f785a` with CTR-GOV-28 as built.

Entries that gain the word by O6 (24), each with its router op (24), the word last among the op's fields:

| # | Contract | Entry, after | Who may call | Word before → after | Router op (signs `chainUid`) |
|---|---|---|---|---|---|
| 1 | 12 token kinds | `mint(to, amount, chainUid_)` | bit 1 `MINTABLE` holder | no → yes | `mtxMint` |
| 2 | 12 token kinds | `mintToUA(to, amount, chainUid_)` | bit 1 holder | no → yes | `mtxMintToUA` |
| 3 | wrapped kinds 1, 3, 5, 9, 11, 13 | `disableWrap(u, reason, chainUid_)` | bit 4 holder (guardian) | no → yes | `mtxDisableWrap` |
| 4 | wrapped kinds | `proposeRate(u, num, den, chainUid_)` | bit 3 holder (a contract) | no → yes | `mtxProposeRate` |
| 5 | wrapped kinds | `cancelRate(chainUid_)` | bit 3 holder | no → yes | `mtxCancelRate` |
| 6 | wrapped kinds | `executeRate(chainUid_)` | bit 3 holder | no → yes | `mtxExecuteRate` |
| 7 | wrapped kinds | `setWrapMember(account, canWrap, canUnwrap, chainUid_)` | bit 26 holder | no → yes | `mtxSetWrapMember` |
| 8 | regulated kinds 8-13 | `setAllowed(accounts, on, chainUid_)` | bit 8 holder | no → yes | `mtxSetAllowed` |
| 9 | regulated kinds | `setDenied(accounts, on, chainUid_)` | bit 9 holder | no → yes | `mtxSetDenied` |
| 10 | regulated kinds | `freeze(account, ref, recordId, chainUid_)` | bit 5 holder | no → yes | `mtxFreeze` |
| 11 | regulated kinds | `unfreeze(account, ref, chainUid_)` | bit 5 holder | no → yes | `mtxUnfreeze` |
| 12 | regulated kinds | `forceTransfer(recordId, amount, chainUid_)` | bit 6 holder | no → yes | `mtxForceTransfer` |
| 13 | regulated kinds | `pause(ref, until, chainUid_)` | bit 7 holder | no → yes | `mtxPause` |
| 14 | regulated kinds | `unpause(ref, chainUid_)` | bit 7 holder | no → yes | `mtxUnpause` |
| 15 | regulated kinds | `recordOrder(orderId, documentHash, subject, beneficiary, maxAmount, freezeUntil, chainUid_)` | bit 10 holder | no → yes | `mtxRecordOrder` |
| 16 | regulated kinds | `revokeOrder(recordId, reasonRef, chainUid_)` | bit 10 holder | no → yes | `mtxRevokeOrder` |
| 17 | regulated kinds | `operatorTransfer(from, to, amount, ref, chainUid_)` | bit 22 holder | no → yes | `mtxOperatorTransfer` |
| 18 | regulated kinds | `setTaxRate(ratePpm, chainUid_)` | bit 23 holder | no → yes | `mtxSetTaxRate` |
| 19 | regulated kinds | `setTaxRecipient(taxRecipient, chainUid_)` | bit 23 holder | no → yes | `mtxSetTaxRecipient` |
| 20 | PQZ kinds 4, 5, 12, 13 | `setProofStore(next, chainUid_)` | bit 24 holder | no → yes | `mtxSetProofStore` |
| 21 | `SCaaSDex` | `setMarket(base, quote, listed, chainUid_)` | bit 11 holder | no → yes | `mtxSetMarket` |
| 22 | `SCaaSDex` | `setExchangeTarget(target, listed, chainUid_)` | bit 11 holder | no → yes | `mtxSetExchangeTarget` |
| 23 | `SCaaSDex` | `setListedOnly(on, chainUid_)` | bit 11 holder | no → yes | `mtxSetListedOnly` |
| 24 | `SCaaSDex` | `setFeeSplit(relayerSharePpm, treasury, chainUid_)` | bit 12 holder | no → yes | `mtxSetFeeSplit` |

Entries of this round that carry the word by earlier rulings (3): `setMaxSupply`, `setMaxWrapSupply` (new, O3),
`setWrapLimits` (no → yes, O5). With O6 the round moves or adds **27 direct entries and 27 router ops** (24 + 3; two
of the ops are new).

Already with the word, unchanged: `grantRole`, `setGrant` (the admin, or a delegable holder's leaf), `cancelGrant`
(admin or proposer), `revokeRole` (admin or a leaf's grantor), `renounceRole` (a holder), `disableFeature`,
`enableFeature` (8-13), `transferAdmin`, `renounceAdmin`, `pqzSetVerifier` / `setVerifierFee` (proposer or admin),
`pqzCancelVerifier`, `pqzRevokeVerifier`, `ComplianceRegistry.setKycProvider` (admin) and `setCompliance` (a KYC
provider), the `OpenFactory` admin entries as CTR-GOV-27 / -28 list them (not re-audited here). `acceptAdmin()` stays without (CTR-GOV-28's reading: only a pending admin
written by a word-checked transfer).

Not role-holder entries of the governance layer, unchanged (step 0 confirms each): bit 21 `MODERATE` has no entry;
bits 18-20 are the factory's admin entries; `RescueVault` (`withdraw`, `setRescuer`, `rotateAdmin`: its own signed
domain and sequence), `SmartKeyAccount`'s guardian, `PqChat`'s admins (authors of signed messages), `UARegistry` (no
governance bit); views.

Two entries read a power inside an entry every user calls; they are **not** given the word (ruled, O7): `burn(amount)` in `BURNER` mode (bit 30) and the unwraps when the caller's excess over its
entitlement is debited from bit 27 `REDEEMER`.

**What moves, old → new in the commit:** the selectors of the 24 entries on every kind that has them and of the 24
router ops; 24 typehashes (each struct gains `bytes32 chainUid` after its own fields, before `uint256 batch`, for
example `UAMint(bytes32 from,address target,address to,uint256 amount,bytes32 chainUid,…E)`); the ERC-165 ids of
`IWrappedToken`, `IRegulatedToken`, `IPqzToken`, `ISCaaSDex` and whichever interface declares `mint`; `entries.json` and
the generated faces and modules; link-closure and release pins of all 12 kinds and the DEX. `mtxSelectors`,
`_uaAllowed` and `_mtxRule` do not move: none of these entries is on a token's allow-list. The superseded forms go to
`legacy/`. A contract that holds a power (an issuer's minter contract, a rate-admin timelock, a guardian) must pass the
token's `chainUid()`: an integration note in `docs/integration.md`.

### 3.10 The DEX's four power entries move into `SCaaSDexGovernanceModule` (O8)

Today (`cf6f785a`): `setMarket`, `setExchangeTarget`, `setListedOnly`, `setFeeSplit` and the private `_power` are bodies
in `SCaaSDex`, each `governed`; the nine admin / grant entries are already one-line stubs (`_forward()`) into
`SCaaSDexGovernanceModule` (`SCaaSDexAdmin.sol`), which inherits `SCaaSDexGovernance` only and has no access to
`scaas.dex`.

After:

- **Module.** `SCaaSDexGovernanceModule is SCaaSDexGovernance, SCaaSDexCore`: `SCaaSDexCore` gives `DexStorage` and
  `_s()` (the `scaas.dex` ERC-7201 accessor) and `_scaas`. The three helpers the bodies use, private in `SCaaSDex`
  today, become `internal` in `SCaaSDexCore`, one definition for both sides: `_pair` (the main contract keeps using
  it), `_setFeeSplit` (`initialize` keeps using it in the main contract) and `_classify` (only `setMarket` uses it, so
  it leaves the main contract's code). The module's four entries are `external onlyDelegated`, with the trailing
  `chainUid_` of §3.9, bodies moved verbatim; its header count goes from 22 to 26 entries.
- **Dispatch.** No fallback: the main contract keeps one explicit stub per entry with the full ABI,
  `function setMarket(address, address, bool, bytes32) external { _forward(); }` and its three twins, as the nine
  governance stubs today. `_forward()` is unchanged: `_guardIn`, DELEGATECALL of `msg.data` to the module immutable,
  the revert data verbatim, `_guardOut`, the return data verbatim. The DEX's stubs are hand-written in `SCaaSDex.sol`
  (`gen_faces.py` only knows the module's group id; step 0 confirms there is no generated DEX face and no
  `entries.json` row to add).
- **The split checks (AGENTS.md):**
  - *DELEGATECALL storage:* the module writes `scaas.dex` and `scaas.governance` through the same constant slots in
    the DEX's storage; it declares no state (M6). Its two immutables (`_SELF`, `_FACTORY`) are in its own code.
  - *`this`:* `_setFeeSplit` refuses `treasury == address(this)`; under DELEGATECALL that is the DEX, as before. No
    body calls back into `this`. `_classify` / `_scaas` read the factory: step 0 checks which factory value they read
    in the module (the module's `_FACTORY` equals the DEX's, checked by the DEX's constructor).
  - *`msg.sender` / `_govSubject`:* preserved by DELEGATECALL; `_caller()` (the EIP-7702 designator refusal) and
    `_govSubject()` (the router's `subject()`) are `SCaaSDexGovernance`'s, the one definition both sides already
    share; `ChainEnvCode` reads the clone's code at `address(this)`, the DEX, as for the admin entries.
  - *Return data:* the four entries return nothing; a revert's data passes verbatim (`BadMarket`, `FeeSplitInvalid`,
    `MissingRole`, `FeatureNotSet`, `ChainUidMismatch`, `GrantExhausted`).
  - *Reentrancy guard, both sides:* the stub's `_forward` runs `_guardIn` (the transient guard's check: refused inside
    a running settlement) exactly as the `governed` modifier did; the module has no guard of its own (M3) and
    `onlyDelegated` refuses a direct call. The transient slot is the DEX's on both sides.
  - *Library closure and pins:* the module already links `GovernanceLib` (`GovernanceUse.use` → `useLimited` by
    DELEGATECALL for a `LIMITED` holder); `test/v2/module-opcodes.json`'s row for the module (DELEGATECALL count) and
    the `LinkClosure` release pins of the DEX and the module move, old → new in the commit. No new library.
- **Events** `MarketSet`, `ExchangeTargetSet`, `ListedOnlySet`, `FeeSplitSet` are emitted by the module's code under
  DELEGATECALL, so their emitter stays the DEX's address and their topics are unchanged; the module names them through
  `ISCaaSDex`. `initialize`'s `FeeSplitSet` still comes from the main contract's code.
- **ABI.** The DEX's external ABI is what §3.9 already gives (the four entries with `chainUid_`); the move adds no
  further change. The router ops `mtxSetMarket`, `mtxSetExchangeTarget`, `mtxSetListedOnly`, `mtxSetFeeSplit` call the
  same selectors on the DEX's address: no change beyond §3.9's signed word. The node, the clients and the vectors see
  nothing of the move. Views (`marketListed`, `listedOnly`, …) stay in the main contract.
- **Deploy.** `DeployBase` / `KindModules` already deploy the module and pass it in `implArgs`; a DEX release is a new
  release with a new module, as any change (nothing deployed is upgraded). The superseded `SCaaSDex.sol` /
  `SCaaSDexAdmin.sol` go to `legacy/`.

## 4. Node, clients, vectors — SPECIFIED

All byte formats move together, by the generators, never by hand; the superseded vectors go to `legacy/`.

| Area | Change |
|---|---|
| `vectors/governance/governance_bits.json` (generated by `GovBitsVector.t.sol`, `WRITE_BITS=true`) | rows 30, 31 (name, type, kinds, holder `any` on 30, sentences below); note "Bits 32-127 are free"; row 1's hybrid sentence gains a bracket printed while bit 31 is set |
| `vectors/typed/typed_ops.json` | `UASetWrapLimits` regenerated with `chainUid` (§3.8; old row to `legacy/`); `UASetMaxSupply`, `UASetMaxWrapSupply` rows (a non-zero unbound `relayer` / `feeRecipient` case included, per the canon rule) |
| `vectors/factory/create_config.json` | `TokenConfig` with `maxWrapSupply`, `TokenRoles` with `burner`; a `BURNER` Normal config, a bit-31 hybrid and a bit-31 pure wrap |
| node `typed.rs` | the `UASetWrapLimits` row gains `bytes32 chainUid` before `E` (§3.8); the two router rows; the `TokenConfig` / `TokenRoles` type strings; row-count pins old → new |
| node `guard.rs` | `mtxSetWrapLimits`' row (type string, ABI signature, selector pin `0x6178483c` → new) and the governed `setWrapLimits` selector on the six wrapped kinds (§3.8); an old-shape `mtxSetWrapLimits` job is refused by name, with the operator note in `ops.md`; the two router rows in the closed table; `setMaxSupply` / `setMaxWrapSupply` governed (`ADMIN`) on the six wrapped kinds, never on a token's allow-list; allow-lists stay equal to `mtxSelectors` / `_uaAllowed` both directions (unchanged for burn); count pins old → new |
| node `abi.rs`, `guard::revert_verdict` | the verdict table below; the new errors decoded by name |
| node docs | `job-api.md`, `submit-lanes.md` (the liftable list, the two ops), `ops.md`: operator note that a `create` job's named config now requires `maxWrapSupply` and `roles.burner` (no silent default; an old-shape job is refused by name) |
| `clientkeys` | `UASetWrapLimits` / `setWrapLimits` with `chainUid` in `evm.js`, the typed-ops scripts and `test/wrap-limits.test.js` (§3.8); `evm.js` (bit names 30, 31; the two typed ops; new errors / views in the ABI), `factory.js` (`ROLES` + `burner`, `TokenConfig` + `maxWrapSupply`), `scripts/typed-ops-vectors.mjs` / `typed-ops-expected.mjs`, tests `governance-bits`, `typed-ops` |
| `ua-rs` (the only signer) | the two admin ops signed; `wraplimit.rs` and `tests/wraplimit.rs`: `chainUid` in `UASetWrapLimits` (§3.8); bit table; vectors tests |
| `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb` | bit tables / sentences read from the same `governance_bits.json` rows; their vectors tests |
| `zether-prover` | `tests/typed_ops.rs`: the regenerated rows **and** its hard-coded list of router op names gains `UASetMaxSupply`, `UASetMaxWrapSupply` |
| every other `TokenConfig` / `Roles` encoder (hand-written copies) | `scaas-pqz-verifier/tests/anvil.rs` (its own `sol!` `Roles` / `TokenConfig`), `scaas-node/tests/e2e.rs` (the named JSON config and a `sol!` copy), `smartcontracts/evm/script/pqz/e2e.py` (`CFG` and its self-test), `script/onchain/pq.py` and every matrix script that reuses e2e's `create`, every Solidity test helper and `script/` contract that builds a `TokenConfig` (forge compiles the whole tree, so these move in the same commit as the struct, step 2), the `scaas-testnet` profile build. Step 0 lists them once by grep (`rateAdmin`, `maxSupply`, `TokenConfig`); the list is reused, because the three-key round moves `TokenConfig` too |
| other families | nothing: no family contract carries the governance bit table (grep at `cf6f785a`; TON's jetton file matched on a name only and was not read) |

O6 (§3.9) across this section: `typed_ops.json` regenerates the 24 structs (old rows to `legacy/`, a non-zero unbound
`relayer` / `feeRecipient` case kept per op); node `typed.rs` 24 rows gain `bytes32 chainUid` before `E`, `guard.rs`
24 router rows (type string, ABI signature, selector pin each old → new) and the governed selectors of the 24 direct
entries per kind, an old-shape job refused by name with the operator note in `ops.md` and `job-api.md` (named field
`chainUid`); `ChainUidMismatch` on any of these ops is `dead` by name (a wrong word never lands). `ua-rs` (`admin.rs`,
`regulated.rs`, `wraplimit.rs` and wherever `UAMint` and the DEX ops are built) and the same ops on `ua-rs-sign`;
`clientkeys` `evm.js`, the typed-ops scripts and their tests; every `ua-*` that builds one of the 24 ops (step 0 lists
them by the struct names); `zether-prover`'s name list is unchanged for these. Scripts and harnesses that call an
entry directly move in the same commit as the entry: `script/onchain/{Gov,Tokens,Dex,WrapLimits,Misc}.s.sol`,
`script/pqz/e2e.py`, `script/onchain/pq.py`, `scaas-node/tests/e2e.rs`, and **every forge test or helper that calls
`mint(to, amount)`** (the largest mechanical change of the round; one helper where the tests allow it).

Node verdicts (after the consumption check, as the other named classes; expiry or the attempt cap ends a queued job):

| Revert | On | Verdict |
|---|---|---|
| `MaxWrapSupplyExceeded`, `MaxSupplyExceeded` | any wrap job; `MaxSupplyExceeded` also the minter's `mtxMint` / `mtxMintToUA` (dead today) | `queued`, `SUPPLY_CAP_REFUSED: <error>`: an unwrap or a cap change lets it land. A wrap larger than a cap that cannot move waits until its deadline; accepted, no extra read |
| `GrantNotReady(31, …)` | `mtxSetMaxSupply`, `mtxSetMaxWrapSupply` | `queued`, same code: lifts at `eta` |
| `MaxSupplyBelowSupply`, `MaxWrapSupplyBelowWrapped`, `MaxSupplyBelowWrapCap`, `MaxWrapSupplyAboveMaxSupply` | the two setter ops | `queued`, same code: lift by supply or by the other setter |
| `FeatureNotSet(31)`, `MaxSupplyInvalid`, `MaxWrapSupplyInvalid` | setters, creation | `dead`, by name |
| `MissingRole(30, from)`, `FeatureNotSet(2)` / `(30)`, `GrantExpired`, `GrantExhausted` fields 0, 1, 2, 5, 7 | `mtxBurn` | `dead`, by name (the job's own subject lacks the power, as an own-list refusal) |
| `GrantExhausted(3)` (the window) | `mtxBurn`; the same error on `mtxMint` | `queued`: the next window lifts it. Step 0 checks whether `revert_verdict` already has a grant class and uses it; if a mint's window refusal is `dead` today, this row is a node rule change recorded in `submit-lanes.md` |

Sentences (final wording at build, in the generator):

- 30: "Only a holder of this power destroys units, and only its own, within its grant; nobody else can burn. The admin
  can switch it off for good, after which nobody burns." (`locked`: "…; it can never be switched off.")
- 31: "The admin can raise or lower maxSupply() (when not 0) and maxWrapSupply() after grantDelay {grantDelay} (0: at
  once), never below totalSupply() / totalWrapped(); the admin can give this up for good. Without this bit both caps
  are fixed."
- 31 gains the S-1 clause: "A lower cap applies only if supply is still under it when the admin applies it."
- 1 hybrid, new bracket: "[The cap {maxSupply} can be changed by the admin: see bit 31.]"
- **Selected by `maxWrapSupply() != 0`, not by a bit** (top-level `sentences.wrapCap` with `wrapCapWhen`, as `hybrid` is
  selected by `maxSupply() != 0`), on pure wraps and hybrids: "Deposits stop when {maxWrapSupply} units are outstanding
  through wraps; {maxWrapSupply − totalWrapped} can still be wrapped now. [This limit is fixed.] [The admin can change
  it: see bit 31.]" (first bracket without bit 31, second with it). Without it a pure wrap with a fixed cap would print
  nothing about a cap that stops wraps, and a hybrid's row 1 would name only `maxSupply` while deposits stop earlier.
  This is selection logic, not only regenerated rows: every client that selects sentences today (found in step 0 by its
  `hybrid` selection) reads `maxWrapSupply()` and `totalWrapped()` and gets a vector case for it.

## 5. Docs and decisions — SPECIFIED

- `decisions.md`: two new entries, the next free CTR-GOV ids (29, 30 at `cf6f785a`; the three-key round may take some):
  **BURNER** (rule B1-B5, Source = the 3zb quotes) and **Wrapped supply caps** (C1-C7, Source = the 3zc quotes, each
  ruling written out in full with status and commit). Changes on CTR-GOV-10 (bits 30, 31 allocated), CTR-GOV-12
  (`maxSupply` changeable under bit 31; `maxWrapSupply`), CTR-GOV-28 (two more admin entries and two router ops carry
  the word, by O5 `setWrapLimits` / `mtxSetWrapLimits`, and by O6 every role holder's entry). **The CTR-GOV-28
  Change text:**

  > Change (owner 2026-11-13, "(2), gộp vào round 3zb + 3zc."; status: SPECIFIED, round 3zb + 3zc). The rule widens
  > from "every direct admin entry" to **every direct entry an admin or a role holder calls**. The table's row "the
  > powers, the lists, the tax entries, `setMarket`, `setExchangeTarget`, `setFeeSplit`, `setListedOnly`,
  > `setWrapLimits`, `setWrapMember`, `setProofStore`: no → no (role entries)" is replaced by the 24 rows of the
  > spec's §3.9 (word no → yes) and by `setWrapLimits`, `setMaxSupply`, `setMaxWrapSupply` (admin, then word). Order
  > for a holder's entry: the caller's check first (a stranger keeps today's refusal by name), then the holder's word,
  > before any write and before a grant is debited (`GovernanceBaseCore._holderOnChain`; the DEX's `_power`). The
  > router ops that sign the target's word go from thirteen to forty (the 24, `mtxSetWrapLimits`, `mtxSetMaxSupply`,
  > `mtxSetMaxWrapSupply`), each with `bytes32 chainUid` as the last op field before `uint256 batch`, typehashes and
  > selectors old → new listed in the commit. Why: a native holder's direct transaction replays on a sibling with the
  > same chain id, an aligned nonce and the same contract address exactly as a native admin's does. Cost: every
  > holder's call names the word (a script or a holder contract reads `chainUid()` first); 24 selectors per kind, 24
  > typehashes, the interface ids. `acceptAdmin()` stays without.

  A Change on CTR-DEX's module rule (the entry that records the governance module, CTR-TOK-30's DEX part; the id is
  fixed in step 1) quotes O8 in full: "Đồng ý, chuyển sang module trong round 3zb + 3zc": the four power entries of
  `SCaaSDex` run in `SCaaSDexGovernanceModule` from this round, by the owner's word and not by the size gate (the
  "ask before a module split" rule is met by this ruling); sizes old → new; what did not move (the views,
  `initialize`, `rescue`); status SPECIFIED, then BUILT with the commit. `docs/contracts/dex.md` gets the entry list of
  the module.

  CTR-TOK-31 (wrap limits), CTR-GOV-20, -21, -22, -24 (operator transfer, tax, proof store, the lists) and the
  component docs that print these signatures (`token-wrappers.md`, `asset-suite.md`, `dex.md`,
  `pq-zero-knowledge.md`, `metatx.md`, `docs/node/job-api.md`, `docs/integration.md`) get the new signatures. Both entries
  record that the other families' tokens have no burn mode or supply cap today and follow in each family's next round,
  so the rule is not read as EVM-only.
- `docs/contracts/token-wrappers.md`: CTR-TOK-22's flag table (rows 30, 31), the `NORMAL` burn rows, CTR-TOK-05 (the
  reserve view; its invariant row gains `totalWrapped ≤ totalSupply`, `totalWrapped ≤ maxWrapSupply` when non-zero
  at every wrap, `==` on a pure wrap), the wrapped section (caps, counter, setters, the `2^256 - 1` convention), the tests table;
  `zether.md` / `pq-zero-knowledge.md`: the flags-valid sentences and §2.3's statement that unshield is not a burn;
  `metatx.md`: `burn`'s allow-list row (role-gated under bit 30). Status tags SPECIFIED in step 1, BUILT only with code
  and tests.
- `docs/integration.md` / `docs/clients/`: the wallet sentences (the `wrapCap` selection), the two ops, the burn
  button rule of §2.1.
- Also mention `BURNABLE` or `maxSupply` today and are re-read: `docs/contracts/asset-suite.md`,
  `docs/contracts/README.md`, `docs/architecture.md`, `docs/guides/item-economies.md`.
- This spec moves to `docs/superpowers/specs/2026-11-13-burner-wrap-caps.md` in step 1 (code comments will cite its
  sections; the scratchpad is git-ignored). Committed only on the owner's word, like every design note.

## 6. Tests and mutants — SPECIFIED

A negative test must be able to fail: each list below has its positive control, and each mutant is one change.

**3zb** (new `test/governance/GovBurner.t.sol`, run over the six Normal kinds):
- init: 2+30 → `FeatureConflict(30, 2)`; 30 on a wrapped kind and 31 on a Normal kind → `FeatureInvalidForKind`;
  `roles.burner` without bit 30 → `RoleWithoutFeature(30)`, on a wrapped kind → `NoSuchRole(30)`; `admin == 0` with a
  seat: bit 30 unlocked → `AdminHasHolders(30)`, locked → created and the seat burns; 2 never disableable.
- never set after init, on kinds 8, 10, 12 (the only ones with `enableFeature`; on 0, 2, 4 the test would be vacuous):
  `enableFeature(30)` → `FeatureNotEnableable(30)` on an off token **and** on a `BURNABLE` token; `grantRole(30)` and
  `setGrant(30)` on a non-`BURNER` token of every Normal kind → `RoleWithoutFeature(30)`.
- `maxWrapSupply = 1` on each of the six Normal kinds → `ConfigFieldForOtherKind(5)` (one mutant per refusal site:
  `_requireUnused`, `ZetherLib.initNormal`).
- positive control: the seat burns its own balance by `burn`, by `mtxBurn` (native and derived UA), by generic
  `mtxExecute`; `totalSupply()` falls by `amount`.
- negatives: a non-holder with a balance → `MissingRole(30, id)` on each of the three paths; a `LIMITED` holder beyond
  each word (min, max, total, perWindow, maxUses, validUntil); a leaf debits its parent; after `revokeRole` and after
  `disableFeature(30)` nobody burns; `BURNABLE` and off tokens behave exactly as before (existing tests unchanged).
- own balance only: a holder's `mtxBurn` signed by A never lowers B's balance (derived and native).
- confidential kinds: `mtxUnshield` works for a non-holder in `BURNER` mode and leaves `totalSupply()` unchanged; the
  burn after it is role-checked.
- regulated: a frozen / denied burner is refused by the regulated hook; burn is not paused.
- mutants: drop the `use` call; check `_govSubject()` instead of `_subject()` (killed only by the derived-UA `mtxBurn`
  positive, its named control: for a native signer both ids are equal); pass scalar 0; invert the mode branch;
  drop the exclusivity check; add 30 to `ENABLEABLE`; add 30 to `ALWAYS_LOCKED`; drop 30 from `TOKEN_SCALAR` (a limited
  grant must then be refused by `GrantWordRefused`).

**3zc** (new `test/wrap/SupplyCaps.t.sol` + the kinds file pattern of `WrapLimitsKinds.t.sol`, over the six wrapped
kinds, pure and hybrid):
- the counter: every test on a leg with `num != den` and an amount that does not divide (on a 1:1 leg `out == burned`
  and the mutant "pass `out`" is equivalent). One test per row of §3.3's table asserting the exact delta, plus `mint` / `mtxShield` / `mtxUnshield` /
  `addReserve` asserting no move; saturation (a hybrid unwraps minter-minted units below 0 → 0); the two invariants as
  fuzz / invariant tests.
- the cap: at the cap exactly passes, one unit over → `MaxWrapSupplyExceeded(next, cap)` on each wrap path,
  `mtxWrapShield` on kinds 3, 5, 11, 13 included; inside the leg's `mtxTrade` of a signature wrap a reader sees
  `totalWrapped() <= totalSupply()` (S-5); 0 = no cap;
  the wrap-limit window and the cap both bind (each alone refuses); the minter's mint ignores `maxWrapSupply`.
- setters: `NotAdmin` then `ChainUidMismatch` before any write (extend `AdminChainWord.t.sol`); `FeatureNotSet(31)`
  unset and after disable; propose / `GrantNotReady` / apply in window / dead after the window / dead after an admin
  change / replaced by another value; `grantDelay == 0` at once; each floor at apply, with the state moved during the
  delay (supply raised past a pending lower cap → the apply reverts); raise and lower both delayed; joint raise applied
  in order; `setMaxSupply` on a pure wrap and to 0 → `MaxSupplyInvalid`; creation `MaxWrapSupplyInvalid`.
- views: `reserveValue() == collateralValue()`; `pendingSupplyCaps()` live flags, false after `disableFeature(31)`;
  `lastProposedAt()` moves at a proposal.
- router: both ops by UA signature, a sibling's word refused, typehash pins.
- `setWrapLimits` word (§3.8): in `AdminChainWord.t.sol`, on the six wrapped kinds, a stranger → `NotAdmin` (with a
  wrong word too: the admin check is first); the admin with a sibling's word → `ChainUidMismatch`, nothing written and
  no pending created; the right word proposes and, at the confirm, applies (positive control); `mtxSetWrapLimits` signed
  over a sibling's word refused by the target; the `UA_SET_WRAP_LIMITS` typehash pin and both selectors old → new; every
  existing wrap-limit test, script (`WrapLimits.s.sol`, `wraplimits.sh`) and vector passes the word. Mutants: replace
  `_adminOnChain(chainUid_)` by `_govSubject()` in the `setWrapLimits` body; drop `chainUid` from the router's signed
  words (forward it unsigned).
- mutants: skip `+ minted` in `wrap`; skip it in `wrapBySigUA`; skip `− burned` in each of `payOut`, `payOutToUA`; pass
  `out` instead of `burned`; pass `0` from each of the four core call sites (`_unwrap`, `_unwrapToUABody`, Zether and PQZ
  `mtxUnshieldUnwrap`); `>` → `>=` in the cap; drop the cap check in `wrapBySigUA`; non-saturating subtraction; drop
  each of the four floors; check floors at propose instead of apply; drop the feature check; drop the delay (apply at
  propose); ignore `generation`; drop `_adminOnChain`'s word; replace `_adminOnChain(chainUid_)` by `_govSubject()` in
  each setter (the library does not re-check the admin: without the core's check anyone sets the caps); drop the cap
  check in `wrap`; write the counter before the leg call in `wrapBySigUA`.

**O6 (§3.9)**, in `AdminChainWord.t.sol` (or a twin `HolderChainWord.t.sol`), table-driven over the 24 entries and
every kind that has each:
- a stranger → the entry's refusal of today, by name, with a right word and with a wrong word (the caller check is
  first; no existing refusal changes);
- a `WHOLE` holder with a sibling's word → `ChainUidMismatch`, state unchanged; a `LIMITED` holder with a sibling's
  word → `ChainUidMismatch` and `grantOf` shows nothing spent (the word is before the debit);
- the right word → the entry acts (positive control, one per entry);
- each of the 24 router ops signed over a sibling's word → refused by the target; signed over the right word but
  forwarded with another → signature refused; typehash and selector pins old → new;
- the DEX's four entries the same, through the module's `_power`.
- the move (§3.10): each of the four entries called on the DEX's address acts and emits its event **from the DEX's
  address** with the state changed in the DEX (positive controls, by a `WHOLE` and a `LIMITED` holder and through the
  router); the same call made directly on the module's address → `NotDelegated`, the module's own storage untouched;
  a call from inside a running settlement (an interaction target calling `setMarket`) → `ReentrancyGuardReentrantCall`;
  an EIP-7702 designator holder refused; `setFeeSplit` with `treasury` = the DEX refused and with `treasury` = the
  module's address accepted (it is not `this`); `initialize` still emits `FeeSplitSet`; the existing DEX suites
  (`test/v2/Dex*.t.sol`, `test/ua/UADexAdmin.t.sol`) pass unchanged but for the word. Mutants: a stub that calls
  `_forwardRaw` (no guard); `onlyDelegated` dropped from each module entry; a stub forwarding to the liquidity module.
- mutants: `_holderOnChain` without the word check; with the word check after the library call (the `LIMITED` debit
  test kills it); with the role read of another bit; per entry, `_govSubject()` passed instead of
  `_holderOnChain(…)` (24, generated from the table); in the router, per op, the word forwarded but not signed.

Existing suites that must move knowingly (old → new in the commit, never edited just to pass): layout pins, selector
audit, `mtxSelectors` tables (unchanged), typehash pins, `CreateConfigKat`, `GovBitsVector`, link-closure release pins
(`GovernanceLib` and `WrappedLib` bytecode change on every kind and on the DEX; every `TokenConfig` decoder grows by two
words: `ZetherLib` (two decodes), `RegulatedLib.init`, `ZetherWrappedLib`, `PqzWrappedLib`, the module that holds
`initialize`; `SCaaSDex`'s release, code hash and link pins), ERC-165 ids that include `IWrappedToken`, gas pins,
`test/modules` (the pre-split side follows the precedent of the 3l / 3s additions; check it in step 0).

## 7. Sizes and gas — SPECIFIED (estimates)

Lines (`size_gate.py`): module T-2 33,780 / T-1 35,570; library 33,903 / 35,694; release 33,594 / 35,386.

| Contract | [baseline] | Change [estimate] | Note |
|---|---|---|---|
| `GovernanceLib` | 15,631 | +150 to +250 B | exclusivity, the burner seat |
| `WrappedLib` | 28,083 | +1.0 to +1.6 KB | counter, cap, two setters, pending, view |
| the Normal kinds' admin module (holds `burn`) | 24.8 to 28.8 K | +150 to +300 B | the inlined `GovernanceUse.use` |
| the wrapped kinds' wrap module | 26.0 to 28.6 K | +400 to +700 B | two setters, four views, forwards |
| the wrapped faces | up to 30,607 (`WrappedPqzRegulatedToken`) | 6 stubs (2 setters, 4 views), about +1.0 KB each | about 165 B per stub today; to about 31.6 K against T-2 33,594, before the three-key round's own entries; generated by `gen_faces.py` from `entries.json` |
| `SCaaSDex` | 35,031 | a few tens of B | passes a `Roles` to `GovernanceLib.init`: a sixth word. Lands after the move of §3.10 (the O8 row below), which makes the room for it |
| the `TokenConfig` decoders (`ZetherLib` 27,219, `RegulatedLib`, `ZetherWrappedLib`, `PqzWrappedLib`, the init module) | — | two words each | measured in step 7 |
| `OpenFactory` | 35,061 | 0 B | `initArgs` is opaque to it; not moved by this spec |
| **O8**, `SCaaSDex` (main) | 35,031 (355 B under T-1 35,386, over T-2 33,594) | −0.8 to −1.3 KB, then + a few tens of B (`Roles` word) → about 33.8 to 34.3 K | loses the four bodies, `_power`, the inlined `GovernanceUse.use`, `_classify`; keeps `_setFeeSplit` (`initialize` uses it); gains four one-line `_forward()` stubs. Likely still over the T-2 notice line, at least 1 KB under T-1 |
| **O8**, `SCaaSDexGovernanceModule` | about 7.1 K (a local artifact, not a baseline row; re-measured in step 0) | +1.3 to +1.8 KB → about 8.5 to 9 K | the four bodies with the word, `_power`, `_holderOnChain`, `_setFeeSplit`, `_classify`, `_pair`, the storage accessor; against T-1 35,570 |
| O6, the regulated module (12 entries) of kinds 8-13 | 27.5 to 28.6 K (W / R today) | +400 to +600 B | the helper once, about 30 B per entry |
| O6, the wrap module (5 entries, plus §3.5 / §3.8) | 26.0 to 28.6 K | +200 to +300 B more | |
| O6, the module that holds `mint` / `mintToUA` | 24.8 to 28.8 K | +120 to +180 B | |
| O6, the module that holds `setProofStore` | `NormalPqzRegulatedTokenQ` 33,633; `NormalPqzTokenQ` 31,698; S on the wrapped PQZ kinds | +120 to +160 B | puts `NormalPqzRegulatedTokenQ` at or over its notice line (33,780) before the three-key split; split allowed for it by the owner's ruling |
| O6, `GovernanceRouter` | 26,001 | +0.7 to +1.1 KB (24 ops, one word each) | to about 27.5 K against T-2 33,516 |
| O6, faces | — | 0 B | stubs forward calldata; the count of entries does not change |
| `GovernanceRouter` | 26,001 | +250 to +400 B | two rows |
| the PQZ ops module of kind 12 (`NormalPqzRegulatedTokenQ`, 33,633; split by the three-key round) | — | 0 B | it does not hold `burn`, and the unshield is not gated (O1) |

`SCaaSDex`: the move of §3.10 is done first (step 2a), before the `Roles` word and the chain word land on it, and it is
measured there and again after step 5a. One stop stays: if the main contract is still over 35,386 B **after** the move,
the build stops with the figures (no further lever without the owner).

Rule: `NormalPqzRegulatedTokenQ` (or its successors) may be split automatically if it crosses its line (owner
2026-11-13); **any other** contract that would cross its T-1 line, or `WrappedPqzToken` its stop line, stops the build
with the measured sizes for the owner, no split and no lever applied. `size-baseline.json` moves only with the reason.

Gas [estimate], measured in the build by the existing pinned tests, old → new in the commit:
- every wrap, all six wrapped kinds: + one cold SLOAD (`maxWrapSupply`) + one SLOAD/SSTORE (`totalWrapped`) ≈ +7 k, the
  first wrap of a token ≈ +24 k (a new slot; under EIP-8037 it is state gas and counts toward inclusion);
- every unwrap: ≈ +5 k;
- **measured in the build (`test/wrap/WrapLimitsGas.t.sol`, regular gas, EIP-8037 state gas apart, Amsterdam prices),
  superseding the three estimates above:** a wrap +14,531 to +14,547 (a cold read-modify-write of `totalWrapped` and a
  cold read of `maxWrapSupply`), an unwrap +12,497 to +12,513 (the read-modify-write of `totalWrapped`); the first wrap
  of a token adds the new slot's state gas on top. Packing the two caps into one slot was refused (controller
  2026-11-14): both are `uint256` by this spec (the uncapped-hybrid convention `2^256 - 1`).
- `burn` in `BURNER` mode: `WHOLE` holder ≈ +2.2 k (one role slot); `LIMITED` as a limited `mint` (one DELEGATECALL,
  up to three slot writes); `BURNABLE` mode ≈ unchanged.
These assume classic slot prices; the build runs Amsterdam with EIP-8037, where a new slot is state gas at another
price: no figure goes into a doc until the pinned tests give it. No timing or calibration run is needed.

## 8. Build plan and gates — SPECIFIED

Branch `burner-wrap-caps` in its own worktree, cut from the merged three-key result. Commit locally per step; no merge,
no push without the owner's word. Heavy commands through `scripts/capped`, foreground; the one exception by name is
`at-set.sh others modules`, which runs **without** an outer `capped` (its build and forge take their own slots).

Stacking on the three-key round (no bit, rule id or wrap / unwrap entry conflict found at `954126d1`): both rounds move
`TokenConfig` (three-key: `ConfidentialConfig.pqzOwnKey`, `pqzOpening`), so `create_config.json`, the node's type
strings and every encoder of §4 move twice, with two `legacy/` moves; step 0 makes the encoder list once. `ua-rs`:
branch `ua-rs-sign` (unmerged, restructures the signer) must receive the two new ops in its op table as well, or its
merge drops or conflicts them.

| # | Step | Gate (state what ran and its result) |
|---|---|---|
| 0 | Repeat §3.9's grep on the new base (any role entry the three-key round adds joins the table); re-read on the new base: module names after the three-key split, any new wrap / unwrap / burn entry, free bit numbers and rule ids, how `test/modules` took the 3l / 3s additions; the `TokenConfig` / `Roles` encoder list (§4); **re-measure every [baseline] row of §7**, the wrapped PQZ faces and `SCaaSDex` first; the clients that select sentences; the node's verdict for a grant refusal | none (notes in the plan) |
| 1 | Docs: rules SPECIFIED, the two decisions entries and the three Changes | `python3 scripts/docs_check.py check`; `python3 scripts/test_docs_check.py` |
| 2 | Shared bases: `GovernanceBits`, `GovernanceLib.init` (+ `Roles.burner`), `IGovernance.FeatureConflict`, `TokenConfig.maxWrapSupply` with both Normal refusal sites; the same commit carries every Solidity test helper and script that builds a `TokenConfig` or a `Roles` | `forge build` of the whole tree; targeted governance tests |
| 2a | The DEX move (§3.10, O8), alone, before any other change reaches the DEX: helpers to `SCaaSDexCore`, bodies to the module, stubs, pins | `forge test` of `test/v2/Dex*.t.sol`, `test/ua/UADex*.t.sol`, `LinkClosure`; sizes of `SCaaSDex` and the module old → new; the stop of §7 |
| 3 | 3zb: `_burnBody`; `GovBurner.t.sol`; mutants | targeted tests; mutants all killed |
| 4 | 3zc library and cores: storage, counter, cap, setters, views; `setWrapLimits(…, chainUid_)` (§3.8); `entries.json` → `gen_faces.py` (`--check`); layout pins | targeted tests; mutants all killed |
| 5 | Router: two ops, `mtxSetWrapLimits` with the word (§3.8), typehash pins, `AdminChainWord`, `SelectorAudit` | targeted tests |
| 5a | O6 (§3.9): `_holderOnChain`, the 24 entries and their router ops, `entries.json` → `gen_faces.py`, every caller in tests, helpers and scripts in the same commit; `HolderChainWord` tests and mutants | `forge build` of the whole tree; targeted tests; mutants all killed; `SCaaSDex` size checked before going on |
| 6 | Vectors by their generators (`governance_bits.json`, `typed_ops.json`, `create_config.json`); old ones to `legacy/` | the vector tests in forge |
| 7 | Sizes and gas pins | `forge build src --sizes --json` → `scripts/size_gate.py … size-baseline.json`; stop rule of §7 |
| 8 | **Contract gate** (shared bases changed: every directory): `forge test` at the default set, all of `test/`; `forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'`; then `script/pqz/at-set.sh others sensitive` (under `capped`) and `script/pqz/at-set.sh others modules` (**no** outer `capped`) (one run per work tree, `PqzSet.sol` restored after); `FOUNDRY_PROFILE=scaas-testnet forge build`; the `e2e.py` self-test. No full `pqz-core/gate.sh`: no core, statement or set parameter changes | per-step summary `step | commit | rc | counts` |
| 9 | Node: `typed.rs`, `guard.rs`, `abi.rs`, `tests/e2e.rs`' config copies, docs; `scaas-pqz-verifier/tests/anvil.rs` | `cargo test && cargo clippy --all-targets -- -D warnings`; `cargo test --test e2e -- --ignored` (alone, 6 GB); `scripts/capped cargo test` in `scaas-pqz-verifier` (in no CI job today) |
| 10 | Clients: `clientkeys`, `ua-rs` (and the same two ops on `ua-rs-sign`), every `ua-*`, `zether-prover` | each client's own test command (CI header); `dotnet build-server shutdown` after the C# run |
| 11 | Docs to BUILT, with the runs summary | `docs_check.py check` |
| 12 | On-chain matrix, local target | `matrix.sh` local; `coverage.json` lists every new entry |

On-chain matrix additions (step 12, and again by the controller after reset 4, with Blockscout verification of every
contract):
- `tokens`: a `BURNER` token of kinds 0 and 8: the seat's `burn`, a UA holder's `mtxBurn`, a limited grant, a
  non-holder refused, `disableFeature(30)`.
- `zether`, `pq`: kinds 2, 10 and 4, 12 in `BURNER` mode: unshield by a non-holder, burn by the holder.
- `gov`: `mtxSetMaxSupply`, `mtxSetMaxWrapSupply` by UA signature on a `grantDelay = 0` hybrid (apply at once) and on a
  delayed one (propose, `GrantNotReady`); a sibling word refused; `mtxDisableFeature(31)` then `FeatureNotSet(31)`.
- `wraplimits` (kinds 1, 5, 13, as today) or a new `supplycaps` group: `totalWrapped()` after each path of §3.3,
  `MaxWrapSupplyExceeded` at the cap, a pure wrap's `totalWrapped() == totalSupply()`.
- `views`: `reserveValue()`, `totalWrapped()`, `maxWrapSupply()`, `pendingSupplyCaps()` on the six wrapped kinds.

## 9. Open questions

None. Every question raised is ruled (§0.1): O1, O2, O4, O5, O6 and O7 (OQ3: `burn` in `BURNER` mode and the
`REDEEMER` unwraps stay without the chain word).

Decided here without a ruling of their own, because the stated rules imply them (listed so the owner can object): the
`burner` seat in `Roles` and `maxWrapSupply` in `TokenConfig` (§1, §3.2); one pending per setter and floors checked at
apply (§3.5); no cancel entry; a cap proposal writes `lastProposedAt`; `reserveValue()` beside the identical
`collateralValue()` (§3.6); the node's verdict table (§4), where `MaxSupplyExceeded` becomes liftable for wraps and
for the minter's mint.

## 10. Fable review 2026-11-13 — findings and where they landed

Basis per finding (the last column): **code** = checked in the code at `cf6f785a` before it was applied (S-2 to S-4,
S-7, S-8(b), S-10 to S-12, S-14 to S-16); **review** = applied from the review's reasoning and the earlier reading of the
same code, not re-checked, to verify in build step 0 (S-5, S-6, S-8 but (b), S-9, S-13, S-17); S-1 is a consequence of
this spec's own logic, not a code fact.

| Finding | Landed | Basis |
|---|---|---|
| S-1 pending decrease blocked by raised supply | §3.5 consequence and remedies, bit 31's sentence (§4), test kept (§6); ruled O4 | spec logic |
| S-2 two Normal refusal sites | §3.2 names both; §6 test over six kinds, one mutant per site; `roles.burner` on a wrapped kind | code |
| S-3 disclosure with `maxWrapSupply != 0` | §4 `sentences.wrapCap`, selected by config, client logic and vector case | code |
| S-4 encoders and gates | §4 encoder row; §8 steps 0, 2, 8, 9 | code |
| S-5 counter before the leg call | §3.4 check before, write after `_sigReceived`; §6 test and mutant | review, step 0 |
| S-6 burn side passes `burned` | §3.3 reworded; §6 legs with `num != den` | review, step 0 |
| S-7 size ripple | §7 rows (`SCaaSDex`, decoders, faces, six stubs); §6 pins | code |
| S-8 setter behaviour | §3.5 (idiom, re-propose, `lastProposedAt`, events), §3.6 (live flag, shared errors) | (b) code; the rest review, step 0 |
| S-9 node verdicts | §4 verdict table | review, step 0 |
| S-10 seat with `admin == 0` | §1, §6 | code |
| S-11 vacuous tests, missing mutants | §6 | code |
| S-12 `setWrapLimits` and CTR-GOV-28 | §3.8, §4, §5, §6; ruled O5 | code |
| S-13 three-key stacking | header, §8 opening and step 0, step 10 | review, step 0 |
| S-14 `others modules` outside `capped` | §8 opening and step 8 | code |
| S-15 docs | §5 (more files, CTR-TOK-05 row, the spec's place, the other families) | code |
| S-16 gas prices, hard-coded op list | §7, §4 | code |
| S-17 error after disable | §2.1, §5 | review, step 0 |
