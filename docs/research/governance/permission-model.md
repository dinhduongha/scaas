> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# A general permission model for SCaaS contracts — version 2 (2026-11-02)

**Status against the build (2026-11-04).** The owner accepted this model on 2026-11-02 and decided D1–D9 as CTR-GOV-01
to CTR-GOV-09, with later rulings CTR-GOV-10 to CTR-GOV-19 and their Changes. **BUILT on branch `governance`, EVM,
UNAUDITED:** `GovernanceBase` / `GovernanceLib` / `GovernanceUse` / `IGovernance` in `scaas.governance` on the six token
kinds and `SCaaSDex` (CTR-GOV-01), the whole `Grant` record on every kind (CTR-GOV-02), the plain half of "+0" and the real
enum members 8–13 (CTR-GOV-03, -11, -16), the two-call `grantDelay` with `cancelGrant` (CTR-GOV-04), the leg refusal
(CTR-GOV-05), rescue to an immutable `rescueTo` (CTR-GOV-06), the bands 0–127 / 128–255 and `governance_bits.json`
(CTR-GOV-10), bits 13 and 14 unused (CTR-GOV-14), the hybrid under `maxSupply` (CTR-GOV-12), identity by UA `bytes32` with
`_govSubject()` (CTR-GOV-01 Change) and one `GovernanceRouter` per chain in place of per-operator holder clones (CTR-GOV-15
Change). **SPECIFIED, not built:** the regulated implementations with flags 5–9 (CTR-GOV-03, -17, -18), `MODERATE` at bit
21 (CTR-GOV-08, -13), `_delayedRelaxBits()` and `RECORD` (CTR-GOV-09). **PLANNED:** every non-EVM family (CTR-GOV-07). The
normative text now lives in `docs/decisions.md` (CTR-GOV-01 to -19), the summary in
[contracts/README.md §8](../../contracts/README.md#governance), and the design field by field in
`docs/superpowers/specs/2026-11-02-governance.md` with its UA identity Change spec
(`docs/superpowers/specs/2026-11-04-governance-ua-identity.md`). Below, the reasoning of 2026-11-02 is kept; a statement
the build made false carries **superseded:** with the built rule and its CTR-GOV id or is corrected in place, and `[V]` line numbers read
at `b3cf5718` are re-pointed to the current file or dropped.

Version 1 (same day, superseded by this file) derived the model from the owner's question *"is there a right, and
within what?"* and placed every per-holder limit outside the token. The attack round
([permission-model-attack.md](permission-model-attack.md), A1–A21, plus the parts of the escalation report after its
7th finding and of the `MODERATE` report after its 2nd, read this session from the workflow journal) and three owner
decisions of 2026-11-02 change the placement, not the model:

- **A. `GovernanceBase` accepted.** One layer — owner, features, roles, lock, delay — in its own storage namespace,
  inheritable by any contract: tokens, `SCaaSDex`, tender, `LoanBook`, third-party applications. Not in `MetaTxBase`
  or `UAMetaTxBase`, which are authentication and relay.
- **B. Bit bands, decided** (CTR-GOV-10's Change, owner 2026-11-04): bits 0–127 are SCaaS's, **one global table, each bit allocated once, never
  renumbered, the same meaning on every SCaaS contract** (`PAUSE` is the same bit on a token and on the DEX; a contract
  without the power leaves the bit off); 128–255 are per-contract, declared by the application with a label (bit →
  function) so a wallet can show them; no band is refused. Existing bits 0–9 and `MODERATE` (bit 21) stay in the SCaaS band.
- **C.** The owner's three examples must run: loan approval in [1 M, 100 M] VND as a constraint on a named argument of
  the application's function (not `perCall`); add or remove members only in one's own family subtree; circulation only
  within a group.

Sources read this session: the governance folder, `AdminLib.sol`, `ITokenAdmin.sol`, `MetaTokenBase.sol` (:28–143),
`ERC20MetaTx.sol` (:296–320, :385–407), `NormalToken.sol` (:38–52), `WrappedLib.sol` (:346, :359), `MetaTxBase.sol`
(:296–299), `UAMetaTxBase.sol` (:134), `WalletExecute.sol`, `MandateWallet.sol` (:27–50), `SCaaSDex.sol` (:66–80,
:146–225), `IOpenFactory.sol` (:1–80), `OpenFactory.sol` (:95–114, :160–300), `test/v2/Layout.t.sol`,
`test/v2/layout/NormalToken.json`, `test/v2/Features.t.sol` (test names), `test/metatx/TokenKat.t.sol` (:28–70),
`size-baseline.json`, the storage-namespace grep, the inheritance grep — all on `typed-signing` `b3cf5718`. Non-EVM
sources were **not** re-read: §4 rests on the families report's citations. Tags: **[V]** verified by reading this
session; **[I]** inferred; **[est.]** a byte or gas figure, not measured; **[F]** fetched from a primary source this
session. Since the build, `AdminLib.sol` and `ITokenAdmin.sol` are kept in `smartcontracts/evm/legacy/governance/` with
the same line numbers; the other files changed, so their line numbers in this list are those of `b3cf5718`.

## 1. The model, restated

### 1.1 One sentence

*A bit says whether a right exists on this contract; a holder entry says who has it; an optional grant record says
within what; the owner, after a delay, changes holders and grants; a lock makes a bit permanent.* Every SCaaS contract
that has rights at all inherits `GovernanceBase`, so these five words are read the same way at every address.
(Superseded in part: a contract whose parties are fixed at creation holds no bit and does not take the base, CTR-GOV-14;
the tender, vesting, distribution and offer contracts are such.)

### 1.2 `GovernanceBase`, `GovernanceLib`, `GovernanceBits`

Three pieces, because tokens cannot afford inlined logic (`WrappedPqzToken` had 1,077 B to the 64,500 B stop line at
`b3cf5718`; superseded: it is 72,160 B now, the one contract in `size-baseline.json` `_above64KiB`, under a ceiling of
131,072 B runtime on the SCaaS testnet, and size is decided later, CTR-GOV-19) and `AdminLib` is already an external
library for that reason (CTR-TOK-24 [V, `legacy/governance/AdminLib.sol`:8]):

| Piece | What it is | Holds |
|---|---|---|
| `GovernanceBits` | a constants file (library of `uint8` constants) | the global table of bits 0–127 (§1.4) and the per-kind masks |
| `GovernanceLib` | `AdminLib` renamed and extended; external library, DELEGATECALL, one body audited once | storage namespace `erc7201:scaas.governance`; `init`, `initHolder`, `grantRole`, `setGrant`, `cancelGrant`, `revokeRole`, `renounceRole`, `disableFeature`, the ownership entries, `useLimited`, the `NORMAL*` rescue |
| `GovernanceUse` (built, not in the first proposal) | internal library in `GovernanceBase.sol`: `use`, the whole-shape fast path inline and one DELEGATECALL to `GovernanceLib.useLimited` (spec §1.3, B-26) | nothing |
| `GovernanceBase` | abstract contract, one-line wrappers over the library, the `IGovernance` ABI, five `pure virtual` masks, `_govSubject()`, the immutable `GOV_ROUTER` | nothing of its own |

A contract declares its masks (compile-time constants, read by `init`, `_grant` and `setGrant`, never storage). As
built (`smartcontracts/evm/src/governance/GovernanceBase.sol`; the first proposal had three masks and a `pure`
`bitLabel`):

```solidity
abstract contract GovernanceBase is IGovernance {
    address public immutable GOV_ROUTER;                                     // this chain's router, from Env.govRouter; 0 = none
    function _govSubject() internal view returns (bytes32);                  // router's subject, else the caller's native id
    function _validBits()        internal pure virtual returns (uint256);  // bits this contract implements (both bands)
    function _roleBits()         internal pure virtual returns (uint256);  // subset with a holder (PAYABLE, BURNABLE, RESCUABLE have none)
    function _contractOnlyBits() internal pure virtual returns (uint256);  // subset whose holder must have code
    function _scalarBits()       internal pure virtual returns (uint256);  // subset whose power passes the number it acts on (B-09)
    function _scopeBits()        internal pure virtual returns (uint256);  // subset whose power reads use's scope (B-10)
    function _scopeNarrows(uint8 bit, bytes32 parent, bytes32 child) internal view virtual returns (bool) { return parent == child; }
    function bitLabel(uint8 bit) external view virtual returns (BitType, bytes4, string memory); // 128–255 only
}
// in IGovernance:
enum BitType { CAPABILITY, POWER }   // §1.4: the type is `_roleBits()`, never a second declaration
```

`_validFor(kind)` of `AdminLib` [V, `legacy/governance/AdminLib.sol`:193–201] becomes each token kind's `_validBits()`;
`ROLE_BITS` [V, :36] becomes `_roleBits()`; the `RATE_ADJUSTABLE` contract-only check [V, :180] becomes
`_contractOnlyBits()`. The library
refuses, in this order (no band is refused, CTR-GOV-10's Change, owner 2026-11-04: the word is `uint256` and a bit `uint8`, so the mask is the only
band check); a bit outside `_validBits()` (`FeatureInvalidForKind`, today's error, kept); a regulated bit not yet built
(`FeatureNotBuilt`, kept until the asset suite lands); a role on a bit outside `_roleBits()` (`NoSuchRole`); a holder
without code on a `_contractOnlyBits()` bit (`RoleNotContract`; built: a native id whose address has code, so a derived
UA cannot hold such a bit); `UA_POOL` and `SHIELD_POOL` as a holder (the `MODERATE` report's F5; built as the new `RoleAccountPool`, and as owner
`OwnerAccountPool`, B-19; 0 as a holder is `RoleAccountZero`). So "`AdminLib`
accepts only known bits" stays true per contract: the SCaaS band is known from the global table, the application band
from the contract's own mask.

### 1.3 The grant record (what "within what" means)

Holding stays flat: `roles[bit][account]` is one slot, as in `AdminLib` [V, `legacy/governance/AdminLib.sol`:61], but
its value becomes `uint8`: `0` none, `1` whole shape (`WHOLE`), `2` limited (`LIMITED`). A holder at `2` has a `Grant`
record at `grants[bit][account]`. As built (`IGovernance.sol`; the first proposal had a four-slot record with an
`address grantor` and `use(uint8, address, uint128)`), the owner or a delegable holder passes `GrantTerms`, and the
record adds what has been spent; every identity is a UA id `bytes32` (CTR-GOV-01 Change):

```solidity
struct GrantTerms {                     // what a grantor chooses
    uint128 min; uint128 max; uint128 total; uint128 perWindow; uint32 window;
    uint64 validUntil; uint32 maxUses; bool delegable; bytes32 scope;
}
struct Grant {                          // six slots; a whole-shape holder's record is unused
    uint128 min;  uint128 max;          // bounds on the scalar the contract names (0 / type(uint128).max = none)
    uint128 total; uint128 spentTotal;  // cumulative
    uint128 perWindow; uint128 spentInWindow;
    uint32 window; uint32 windowStart; uint64 validUntil; uint32 maxUses; uint32 uses;   // MandateWallet's grid
    uint32 grantorEpoch; bool delegable; bool barred;   // barred: set by the owner's revoke, only the owner re-admits (B-05)
    bytes32 scope;                      // opaque to the base; the contract's predicate reads it
    bytes32 grantor;                    // the UA that granted a leaf; 0 on a root
}
// GovernanceUse, inlined into every power's entry; the subject is _govSubject()
function use(uint8 bit, bytes32 account, uint256 scalar) internal returns (bytes32 scope);   // the one check
```

The rule that makes the owner's loan example run and closes A11: **the scalar a contract passes to `use` is the
number it then acts on** (the principal it pays, the amount it mints, the units it moves), never a number the caller
chose for the check alone. A contract without a scalar passes 0 (`min`/`max` unused; `total`, `maxUses`, `validUntil`
still bind). The base never interprets `scope`: `use` returns it and the contract applies its own predicate (§1.6).
`use` on a whole-shape holder costs the same one SLOAD as `requireRole` today (the value `1` is in the same slot the
`bool` was) [I]; only a limited holder pays the record's reads and one write. (Superseded: `requireRole` is removed,
B-31; `use` reads `features` and `roles[bit][account]` and returns 0 inline for a whole-shape holder, and a limited
holder pays one DELEGATECALL to `useLimited`, which debits its record and, for a leaf, its parent's; spec §1.3, §1.5,
CTR-GOV-02.)

**Two levels, enforced where used, no proof.** The owner grants; a holder whose grant is `delegable` may grant a leaf
on the same bit; a leaf cannot delegate. (Built with three rules the first proposal lacked: only the owner can make a
grant `delegable`; a `delegable` grant needs a finite budget, `total` on a scalar bit or `maxUses` on another,
`GrantBudgetRequired`, B-02; a word the contract does not bind, outside `_scalarBits()` or `_scopeBits()`, is refused,
`GrantWordRefused`, B-09, B-10. Spec §1.5.) At a leaf grant the library checks `narrows(child, parent)` on every scalar
field (child ⊆ parent: `min ≥`, `max ≤`, `total ≤ parent.total − parent.spentTotal`, `perWindow ≤`, `validUntil ≤`,
`maxUses ≤`) and asks the contract `_scopeNarrows(bit, parent.scope, child.scope)`. At use, a leaf also debits its
parent's `total` / window (so a manager's [1 M, 20 M] officers cannot together exceed the manager's 100 M) and checks
`parent.epoch == leaf.grantorEpoch` — one extra SLOAD per hop, depth at most 2, revoke of the parent kills every leaf
without a walk (A19, escalation F3). Deeper trees are a holder that is itself a `GovernanceBase` child: each hop
enforces its own limits at call time, which the attack round confirmed needs no subset proof. This is MetaMask's
"caveats accumulate along the chain" and USDC's `masterMinter → minter`, with exactly one table.

**Replacing a grant never refreshes a budget** (escalation F13): `setGrant` on an existing holder keeps `spentTotal`,
`spentInWindow`, `uses` — `MandateWallet`'s rule "an edit never grants a fresh period budget" [V, MandateWallet.sol
header], now in the base. One grant per `(bit, holder)`; a second clone for the same operator cannot exist because
there are no clones.

### 1.4 The global bit table (bits 0–127)

> **Changed after this note** (governance build, 2026-11-04): the table below is the **built** allocation, `GovernanceBits.sol`
> and `smartcontracts/vectors/governance/governance_bits.json` (plan T14), which are the authority. Against this note's first
> proposal: bit 9 is `DENYLIST` ([CTR-GOV-18](../../decisions.md#ctr-gov-18--receiver-check-two-feature-bits-allowlist-and-denylist-off-by-default)),
> `MODERATE` moved from 9 to 21 ([CTR-GOV-08](../../decisions.md#ctr-gov-08--moderate-later-with-flags-5-8)); 13 `DISQUALIFY`
> and 14 `REVOKE_GRANT` were never allocated and stay unused for ever; 15 `ARBITRATE` and 16 `CORRECT` are reserved names with
> no spec; the SCaaS band is 0–127 and 128–255 the application's (CTR-GOV-10's Change). Where the rest of this note says
> "bit 9" for `MODERATE` or "flags 5–8", read bit 21 and flags 5–9.

Decided: one table, allocated once, never reused or renumbered, the same meaning everywhere. Pinned in code as
`GovernanceBits.sol` and in docs as the table below moved to `docs/contracts/README.md §3` when normative (built: the
table is the spec's §1.2, summarised in `docs/contracts/README.md` §8); a vector
file `smartcontracts/vectors/governance/governance_bits.json` (`bit → name → type → disclosure sentence`) is written by a forge test from the
constants and read by every client, so a wallet names bits 0–127 **without reading the contract**; bits 128–255 come
from the contract's `bitLabel(bit)`. A bit's name is general (what the holder may do to others or to the instance),
never a contract's function name.

**Every bit has a type, and the type is part of the table** (owner question, 2026-11-02): a **capability** is a
behaviour of the instance with no holder — it is open to every user (`PAYABLE`: anyone may pay through the pay entries;
`BURNABLE`: any holder of units may destroy its own units; `RESCUABLE`: anyone may trigger the rescue) or binds every
user (`ALLOWLIST`: every receiver is gated). Nobody "acts under" a capability as a person; the instance behaves that
way. A **power** is a right tied to persons: it has holders, and only a holder (whole-shape or limited by a `Grant`)
acts under it; `MINTABLE` with its `minter` is the pattern. In code the type **is** `_roleBits()`: a bit in
`_validBits() & ~_roleBits()` is a capability, a bit in `_roleBits()` is a power — one declaration, not two.
`grantRole` on a capability bit reverts `NoSuchRole(bit)`, exactly as `AdminLib`'s `ROLE_BITS` check did for `PAYABLE` and
`BURNABLE` [V, `legacy/governance/AdminLib.sol`:36, :178]; `holderCount` of a capability is always 0; `setGrant` refuses it the same way.
A capability can be locked (`PAYABLE`, `BURNABLE`, `RESCUABLE` always are: `GovernanceBits.ALWAYS_LOCKED`) or disabled one-way like any
bit; `ALLOWLIST` is the one capability with a parameter (the pinned registry), set at INIT (superseded: `DENYLIST`, bit 9,
reads `deniedFlags` on the same registry, CTR-GOV-18, and `RESCUABLE` takes `rescueTo`, CTR-GOV-06). `BURNABLE` is therefore
**not** "an admin burns": burning another account's units is a third-party move and needs `MODERATE` with a burn-sink
scope, never `BURNABLE`. For the application band, `bitLabel(bit)` returns the type beside the selector and the name,
derived from the same mask, so a wallet prints "anyone may `<name>`" for a capability and "holders of `<name>`: X, Y
(limits …)" for a power without a second table; `governance_bits.json` carries the type for 0–127.

| Bit | Name | Meaning (same on every contract) | Type | Reduce-only | Contract-only | Built state (branch `governance`) |
|---|---|---|---|---|---|---|
| 0 | `PAYABLE` | anyone may pay through the pay entries | capability (always locked) | — | — | every token kind |
| 1 | `MINTABLE` | a holder creates units | power | no | no | `NORMAL*`; `WRAPPED*` as a hybrid under `maxSupply` |
| 2 | `BURNABLE` | any holder of units destroys its own | capability (always locked) | — | — | every token kind |
| 3 | `RATE_ADJUSTABLE` | a holder changes a conversion rate under the rate timelock | power | no | yes | `WRAPPED*` |
| 4 | `WRAP_DISABLEABLE` | a holder closes an inflow, one-way | power | yes | no | `WRAPPED*` |
| 5 | `FREEZE` | a holder stops one account's outflow, bounded in time | power | no | yes | regulated implementations, SPECIFIED; refused on the plain ones |
| 6 | `FORCE` | a holder moves units out of a frozen account to a recorded beneficiary; public balances only | power | no | yes | same |
| 7 | `PAUSE` | a holder stops every outflow, bounded in time | power | no | yes | same |
| 8 | `ALLOWLIST` | a receiver must hold `requiredFlags` in a `ComplianceRegistry` pinned at INIT | capability (parameters) | — | — | same; not the confidential kinds |
| 9 | `DENYLIST` | a receiver must hold none of `deniedFlags` in that registry | capability (parameters) | — | — | same |
| 10 | `RECORD` | a holder writes a compliance record that another power relies on | power | no | yes | name taken, no contract implements it yet |
| 11 | `LISTING` | a holder decides what this instance trades or accepts (DEX `setMarket`, `setExchangeTarget`, `setListedOnly`) | power | no | no | `SCaaSDex` |
| 12 | `FEE_ROUTING` | a holder decides who receives this instance's fees, never how much (DEX `setFeeSplit`) | power | no | no | `SCaaSDex` |
| 13 | — | unused, never allocated, never reused | unused | — | — | — |
| 14 | — | unused, never allocated, never reused | unused | — | — | — |
| 15 | `ARBITRATE` | reserved name, no spec behind it | reserved | — | — | — |
| 16 | `CORRECT` | reserved name, no spec behind it | reserved | — | — | — |
| 17 | `RESCUABLE` | anyone may move what this instance does not owe to `rescueTo` | capability (always locked; parameter `rescueTo`) | — | — | every token kind; the DEX through `DexPuller.rescue` |
| 18 | `PUBLISH` | a holder adds a release to a catalogue | power | no | no | name taken; the deployed factory is immutable: later |
| 19 | `DEPRECATE` | a holder marks a release unusable for new instances, never undone | power | yes | no | same |
| 20 | `ENABLE_KIND` | a holder turns a catalogue kind on or off | power | no | no | same |
| 21 | `MODERATE` | a holder moves public units out of any account, no record ([CTR-GOV-08](../../decisions.md#ctr-gov-08--moderate-later-with-flags-5-8), [CTR-GOV-13](../../decisions.md#ctr-gov-13--moderate-only-on-public-balances)) | power | no | yes | regulated implementations, later; SPECIFIED |
| 22–127 | free (SCaaS band) | | | | | |
| 128–255 | application band, labelled by `bitLabel(bit)` | | | | | |

Twenty bits named (13 and 14 left unused) after two years of design, most of them in one afternoon from the inventory's ≈ 110 rows
collapsing to general names; 106 free (CTR-GOV-10's Change, owner 2026-11-04). **It suffices** [I]: every named power in gov-inventory, tender, asset-suite and
the DEX maps to one of the above or to the application band; the SCaaS band is 0–127 (CTR-GOV-10's Change, owner 2026-11-04),
so exhaustion has an answer other than renumbering. What the table must never do: give a bit a second meaning on one contract (a DEX
`PAUSE` stops settlement, a token `PAUSE` stops outflow — both "stops every outflow of this instance", one sentence).

### 1.5 Attenuation, restated after A5 and the families F3

*The bits of this contract state the worst case of **this contract's own code**; a holder's grant only narrows; a leaf
is at most its grantor.* Inherited powers — a leg's issuer (SCaaS `MODERATE` / `FORCE`, USDC's blacklist, HTS `WIPE`
/ `FREEZE` / `KYC` / `PAUSE` / `FEE_SCHEDULE` / `ADMIN` keys, Token-2022 `PermanentDelegate`, Aptos `TransferRef`) —
are read separately, per leg, and disclosed as "unknown issuer powers" where they cannot be read (Aptos). The §2
disclosure order of v1 gains that step; nothing in code changes for it.

### 1.6 The three examples, run on the base

> **Changed after this note:** the forms that pass the built rules are the spec's §1.9, run by
> `smartcontracts/evm/test/governance/GovExamples.t.sol` (CTR-GOV-10). Against the text below: a `delegable` grant needs a
> finite budget (B-02), so the family-tree head's `{scope = headId, delegable}` reverts `GrantBudgetRequired` and takes
> `maxUses = N`; the subject is `_govSubject()`, a UA id; form (ii) of the group example needs kind 8 `NORMAL_REGULATED`,
> SPECIFIED, not built (CTR-GOV-03, -18).

- **Loan approval in [1 M, 100 M] VND.** `LoanBook is GovernanceBase`; `_validBits()` includes 128 `APPROVE_LOAN`,
  `bitLabel(128) = (approveLoan.selector, "approve a loan")`. Entry: `approveLoan(uint256 loanId)` reads
  `loans[loanId].principal` (the number the contract pays), requires `status == PENDING` and `borrower != sender`
  (preconditions are application state, never grant fields), then `bytes32 branch = use(128, sender, principal)` and
  `require(loans[loanId].branch == branch)`. Grants: the committee is `owner`; `setGrant(128, manager, {min 1e6, max 1e8,
  total = portfolio cap, validUntil, scope = branchId, delegable})`; the manager issues `setGrant(128, officer, {min 1e6,
  max 2e7, …, scope = branchId})`, accepted because it narrows. Two approvers above 50 M: the holder is an msig
  `SmartKeyAccount` or an application rule — not a grant word. `perCall` does not appear: the band is `min`/`max` on
  the principal.
- **Add or remove members only in one's own subtree.** `FamilyTree is GovernanceBase`; 128 `ADD_MEMBER`
  (`addMember(uint64 parent, …)`), 129 `REMOVE_MEMBER` (`removeMember(uint64 id, bytes32 ref)`: a tombstone that
  references the record, reduce-only; erase never exists). `use(128, sender, 0)` returns `scope = bytes32(rootId)`; the
  contract checks `isDescendant(rootId, parent)` with a `MAX_DEPTH` shape constant bounding the walk. The clan's
  `owner` grants the head `{scope = headId, delegable}`; the head grants a son `{scope = sonId}` and the base asks
  `_scopeNarrows(128, headId, sonId) = isDescendant(headId, sonId)`. "Self" is not a set word: the subtree is the scope.
- **Circulation only within a group.** Two honest forms, and the owner picks by where balances live. (i) Custody:
  `GroupLedger is GovernanceBase` holds a plain `NORMAL` token and keeps member balances; 128 `MOVE_WITHIN`
  (`moveWithin(uint64 from, uint64 to, uint256 amount)`), `use` returns `scope = groupId`, both ends `isMember(groupId,
  ·)`; the token sees one holder. (ii) Wallet balances: a `NORMAL` token with bit 8 `ALLOWLIST` and the group's own
  contract pinned as the registry at INIT (receiver side, CTR-AS-07); that is a **token property, not a grant**, it is
  the only form that touches `_update` and the registry's controller is disclosed ("X can change this group at once",
  A13). Nothing here needs `MODERATE`.

### 1.7 Reconciled with the attack report's `GrantLib` / `IGrant`

| Attack-report piece | v2 |
|---|---|
| `Right = (contract, selector)` | **replaced** by `(contract, bit)`; the selector is the public label of an application bit, read through `bitLabel`, never the key. A right that exists without any function (`PAYABLE`, `RESCUABLE`) could not be a selector |
| `Limits = {min, max, total, perWindow, window, validUntil, maxUses}` | **kept** as the `Grant` fields, one record per `(bit, holder)` in the base |
| `Scope = bytes32`, app-defined order | **kept**: `scope` + `_scopeNarrows` |
| `Precond` in the app | **kept**, stated as a rule |
| `GrantLib` as an internal library per app, est. 0.6–1 KB each | **replaced** by `GovernanceLib`'s external body, paid once per chain, stubs per contract |
| `IGrant` (`grantOf`, `scopeNarrows`, events) | **folded** into `IGovernance`: `grantOf(bit, holder)`, `Granted` / `Revoked` / `Used`, plus `bitLabel`, `validBits` (built events: `RoleGranted`, `RoleRevoked`, `GrantSet`, `GrantUsed`, `GrantProposed`, `GrantCancelled`, every identity `bytes32 indexed`) |
| `IRoleEnvelope` holder clone + its catalogue (A3, A14) | **dropped**: a token's bounded minter is a limited holder in the token; nothing self-reports; `OpenFactory` needs no new domain |
| `narrows` at sub-grant, epoch kill at revoke | **kept**, bounded to two levels |
| a contract that does not inherit the base (a Safe, a third-party app, `MandateWallet`, `SmartKeyAccount`) | it can still **hold** a bit on a base contract (built: under its native id, `bytes32`); its own rules are not readable by this model, so the disclosure says "whole shape, mutable by its own rules" (escalation F15). It may adopt the model by inheriting; there is no second way, and none is needed. A derived UA (PQ key, `msig`) holds a bit under its own id and acts through the `GovernanceRouter` (CTR-GOV-01, -15 Changes) |

## 2. What moves

### 2.1 Storage

At `b3cf5718` `AdminLib.TokenStorage` (`erc7201:scaas.token`) held `features`, `lockedFeatures`, `owner`, `pendingOwner`,
`creator`, `version`, `kind`, `decimals`, `initialized`, `name`, `symbol`, `roles` [V, `legacy/governance/AdminLib.sol`:48–62]. v2 splits
it:

| Namespace | Keeps | Why |
|---|---|---|
| `erc7201:scaas.token` | `creator`, `version`, `kind`, `decimals`, `initialized`, `name`, `symbol` | identity and metadata of a token; the DEX has its own (`scaas.dex`, `SCaaSDex.sol`) |
| `erc7201:scaas.governance` (new) | `features`, `lockedFeatures`, `owner`, `pendingOwner`, `grantDelay`, `roles` (`uint8`), `holderCount[bit]`, `pending[bit][account] = (eta, proposer)`, `lastProposedAt`, `grants[bit][holder]`, `epoch[bit][holder]` | one slot formula for "features" at every address that inherits the base |

Superseded in detail, CTR-GOV-01 and its Change: the built `GovernanceStorage` (`GovernanceLib.sol`, spec §1.4) is
`features`, `lockedFeatures`, `owner` and `pendingOwner` as `bytes32` UA ids in a slot each, one packed slot
`grantDelay` / `ownerGeneration` / `lastProposedAt`, then `roles`, `counts[bit] = {holders, roots}` (in place of
`holderCount[bit]`: `holderCount` reads `holders`, the renounce rule `roots`), `grants`, `epoch`,
`pending[bit][account] = {eta, generation, proposer, termsHash}`, and `rescueTo` (an `address`, a payout destination);
every mapping is keyed by `bytes32`.

**Yes, the tokens' fields split from `scaas.token`.** The cost is nil: no chain is production (all test-only, 7622
may be reset [memory]), so no migration; a wallet or indexer that read `features` by raw slot (`scaas.token` slot 0)
now reads `scaas.governance` slot 0 — same formula, new seed. `WrappedLib`'s `reserve` (`scaas.underlying`, the slot
the indexer and storage proofs read [V, `test/v2/Layout.t.sol`]) does not move.

**Layout pins.** `test/v2/layout/<Kind>.json` pins the **linear** layout only (slots 0–4: `_balances` …
`_symbol`; the test asserts slot 5 is zero) [V, `test/v2/Layout.t.sol`; `NormalToken.json`]. ERC-7201 roots are not in
the pin, so the files are unchanged by the split — which is exactly the gap: add the namespace roots (`scaas.token`,
`scaas.governance`, `scaas.underlying`, `scaas.ua.ledger`, `scaas.metatx`) as labelled rows to each pin file in the
same commit, so a later move is deliberate. `test/v2/Features.t.sol::test_adminWritesDoNotTouchOtherNamespaces`
changes with it. (Built otherwise: the roots are pinned once, in `test/v2/layout/namespaces.json`, CTR-GOV-01.)

### 2.2 ABI

`ITokenAdmin` [V] becomes `IGovernance`, every existing name kept (`features`, `lockedFeatures`, `owner`,
`pendingOwner`, `hasRole`, `grantRole`, `revokeRole`, `renounceRole`, `disableFeature`, `transferOwnership`,
`acceptOwnership`, `renounceOwnership`, the five events, the twelve errors), plus: `grantDelay()`, `pendingGrant(bit,
account) → (eta, proposer)`, `lastProposedAt()`, `holderCount(bit)`, `grantOf(bit, holder) → Grant`, `setGrant(bit,
holder, Grant)` (owner, or a `delegable` holder of that bit), `validBits()`, `bitLabel(bit)`, `supportsInterface(
IGovernance)`; errors `FeatureReserved(bit)`, `GrantNotNarrower(field)`, `GrantExhausted(field)`, `GrantExpired`,
`RoleAccountPool`. `grantRole` keeps its signature and means "whole shape" (`roles = 1`); the second call within the
window confirms (§3 A1). The DEX: `admin()` → `owner()`, `DexConfig.admin` → `owner`, `setMarket` /
`setExchangeTarget` / `setListedOnly` under `LISTING`, `setFeeSplit` under `FEE_ROUTING`; `DexCreated`'s last field
is read from `owner()`. `createTokenUnregistered` unchanged. Nothing on any `mtx*` / `ua*` struct changes, so no
typed-signing digest moves.

Built (`IGovernance.sol`, CTR-GOV-01 Change, CTR-GOV-04): every account, owner, holder and proposer is `bytes32`
(`grantRole(uint8, bytes32)`, `transferOwnership(bytes32)`, `owner() → bytes32`, …); `pendingGrant(bit, account) → (eta,
proposer, termsHash, live)`; `setGrant(bit, holder, GrantTerms)`; `cancelGrant(bit, account)` is new; errors as listed
above plus `GrantWordRefused`, `GrantBudgetRequired`, `OwnerAccountPool`, `GrantBarred`, `GrantWindowInUse`,
`OwnerHasHolders`, `GrantDelayTooLong`, `GrantNotReady`, `GrantTermsMismatch`; `FeatureReserved` is declared but no path
raises it since the bands of CTR-GOV-10's Change. The governed contracts' own `mtx*` / `ua*` structs did not change
(`metatx_kat.json`, `metatransfer_kat.json` unchanged); `dex_order_kat.json` was regenerated with the UA identity Change
(its spec §6), and the `GovernanceRouter` adds typed structs of its own (19 ops, 38 entries, pinned by
`test/governance/GovRouterTypehash.t.sol`, vectors `smartcontracts/vectors/typed/typed_ops.json`; spec §3.2). No
governance operation is on a governed contract's `mtx*` / `ua*` allow-list (`test/vectors/selector_audit.json`).

### 2.3 Factory, kinds, catalogue, CREATE2, KAT

- **Kind enum:** unchanged by the base. It changes only if the owner takes A17 option (i) (§2.5): two values
  `NORMAL_REGULATED = 8`, `WRAPPED_REGULATED = 9` (6 and 7 are never reused). Reserving
  the two ids now is a comment, 0 B. (Superseded: real enum members, CTR-GOV-16: `TokenKind` 0–13 in
  `src/factory/IOpenFactory.sol`, `RETIRED_6` and `RETIRED_7` refused by `deployImplementation`, 8–13 the regulated
  ids of the two plain and four confidential kinds, off until an implementation is published.)
- **Catalogue:** `GovernanceLib` replaces `AdminLib` in every kind's and the DEX's `Env.libs` / `libCodeHashes` pin
  [V, OpenFactory.sol `_deploy`], so each domain publishes one new env version. No holder kind, no envelope catalogue,
  no new domain. (Built: `Env.govRouter` names the chain's `GovernanceRouter`, read into each release's `GOV_ROUTER`;
  the router is not a release and `OpenFactory` does not know it, spec §3.1.)
- **CREATE2:** an implementation's address is `CREATE2(initcode ‖ abi.encode(v, env, implArgs), salt =
  keccak(kind, version))` [V, `src/factory/OpenFactory.sol` `deployImplementation`, `_deploy`]; new bytecode is a new version by rule, and every clone's
  address is `predictDeterministicAddress(implementation, salt(creator, salt))` [V, `predictAddress`]. So every token created from
  v2 has a different address from any prediction made against v1 — a non-event on test-only chains; no deployed token
  moves.
- **KAT:** `metatx_kat.json` / `metatransfer_kat.json` derive the domain separator from the test's own clone address
  (`new NormalToken(...)` + `Clones.clone`) [V, `test/metatx/TokenKat.t.sol`], not from factory CREATE2, and no signed struct
  changes: the vectors stay byte-identical. `smart_key_account_create2.json` is the account factory's, untouched.
  `hedera_kat.json`, `trade_kat.json`, `dex_order_kat.json` do not touch admin fields. Only a new vector file is
  added: `governance_bits.json` (§1.4). (Built otherwise in part: `dex_order_kat.json` was regenerated with the UA
  identity Change; new vector files are `smartcontracts/vectors/governance/governance_bits.json`,
  `smartcontracts/vectors/typed/typed_ops.json`, `test/vectors/selector_audit.json` and
  `test/vectors/plus_zero_slots.json`.)

### 2.4 Bytes and gas per kind [est., nothing measured]

> **Superseded by measurement and by the owner** (CTR-GOV-02, CTR-GOV-19): the prototype measured D1 and D2
> (`prototype/RESULTS.md`): as designed the record did not fit `WrappedPqzToken` (65,520 B). The owner chose to reduce
> size rather than cut the record, then (2026-11-03) to build the whole record on every kind and decide size later. No
> drop order below was taken: no kind is flat-only, and rescue is on every token kind. Built sizes in
> `smartcontracts/evm/size-baseline.json` at `dd674581`: `NormalToken` 40,853, `WrappedToken` 52,297,
> `NormalZetherToken` 50,547, `WrappedZetherToken` 62,472, `NormalPqzToken` 56,191, `WrappedPqzToken` 72,160,
> `GovernanceLib` 13,181, `SCaaSDex` 33,725 B. The size gate's ceiling is 131,072 B runtime and 262,144 B init on the
> SCaaS testnet, which leaves EIP-7954 out; `_above64KiB` lists the contracts above 65,536 B, today `WrappedPqzToken`
> alone, not deployable on a public chain until the owner decides. The "+0" of a plain transfer means no new storage
> read, not an equal gas figure (CTR-GOV-11), pinned by `test/governance/PlusZero.t.sol` on every kind. The text below
> is the estimate of 2026-11-02.

Baseline [V, `size-baseline.json` at `b3cf5718`]: `NormalToken` 37,228, `WrappedToken` 48,015, `NormalZetherToken` 52,741,
`WrappedZetherToken` 62,169, `NormalPqzToken` 52,891, `WrappedPqzToken` 63,423 (1,077 B to the stop line),
`AdminLib` 3,272, `SCaaSDex` 27,957. Levers §2 figures for a stub: ≈ 100–150 B per one-`address` external entry, ≈ 256
B per `mtx` named entry [V, v1 header].

| Item | `GovernanceLib` | each token kind | `WrappedPqzToken` note | `SCaaSDex` |
|---|---|---|---|---|
| move of today's admin ABI into `GovernanceBase` | 0 (rename) | ≈ 0 (the same twelve stubs, moved) | 0 | +1.2–1.6 KB (gains the whole admin surface it lacks today) |
| band refusal (`>= 128`; removed by CTR-GOV-10's Change, owner 2026-11-04), masks as arguments | +60–120 B | 0 | 0 | 0 |
| two-call `grantDelay` + `pendingGrant` view + `lastProposedAt` | +350–500 B | +150–250 B (config field through `init` decode, one view) | +150–250 B | same |
| `holderCount` | +80–120 B | +60–100 B | +60–100 B | same |
| `Grant` record, `use`, `setGrant`, `grantOf`, `narrows`, epoch | +1.0–1.5 KB | +300–450 B (`setGrant` + `grantOf` stubs; `mint` / `mintToUA` on `use` +≈ 50 B) | **drop first**: flat holding only on this kind (its roles are `RATE_ADJUSTABLE` / `WRAP_DISABLEABLE`, contracts, no scalar); the disclosure says "no grant records on this kind" | same +≈ 0.4 KB |
| `RESCUABLE` + `rescueTo` + `rescue(asset)` (§3 A15/A16) | +≈ 400 B (or `WrappedLib`) | +150–250 B | **second drop** if over the line | +≈ 300 B, only if CTR-DEX-20 does not already pay strays out (§3 A15) |
| sum | ≈ 5.5–6.5 KB (from 3,272) | +0.7–1.1 KB | +0.2–0.6 KB after drops, against 1,077 B | +2.0–2.8 KB → ≈ 30–31 KB |

Gas [est. except where marked]: a **plain transfer rises by 0**: `_update` reads no governance slot today [V,
`src/metatx/ERC20MetaTx.sol` `_update`] and v2 adds nothing to `_update` or `_uaMove` (§2.5 is the only exception and it is the
owner's call). `mint` on a whole-shape holder: unchanged (same slot, `uint8` instead of `bool`). `mint` on a limited
holder: +4 cold SLOAD + 1–2 SSTORE ≈ +10–15 k. `setGrant`: 4 slots ≈ 90–110 k cold. `init`: +1 SSTORE for
`grantDelay` (packed with `owner` if the struct is ordered for it: 0 extra) [I]. `grantRole` ×2: the propose write +
the confirm write ≈ 2 × 22–44 k.

**What must be measured and how** (owner: ask before timing runs; since built: sizes are held by the size gate,
"+0" by `PlusZero.t.sol`, governance gas by `test/governance/GovGas.t.sol`; the prototype's figures are in
`prototype/RESULTS.md`): (1) `scripts/size_gate.py` against
`size-baseline.json` after each of §6's steps 1–3, `WrappedPqzToken` first, and the drop order above applied only on
a measured breach; (2) `test/v2/MetaTxGasV2.t.sol` for `mtxTransfer` / `mtxPay` before and after (the plain-transfer
rule is a test assertion, not a promise: `assertEq(gasAfter, gasBefore)` on the transfer row); (3) `DexGas.t.sol` for
a settle; (4) the `init` delta in `Factory.t.sol`.

### 2.5 The hot path, re-examined (A17)

The rule is binding: a plain transfer's gas must not rise. The base itself keeps it (nothing on `_update`). The breach
is older than the base: once `FREEZE` / `PAUSE` / `ALLOWLIST` are built on the two plain kinds, `_update` **and**
`_uaMove` (which bypasses `_update` [V, `src/metatx/ERC20MetaTx.sol` `_uaMove`, `_poolMove`]; the `MODERATE` report's lead) must learn whether this
instance is regulated. Honest accounting of the forms, in gas on a plain `transfer` / `mtxTransfer`:

| Form | Plain-kind transfer | Regulated-instance transfer | Cost elsewhere | Verdict |
|---|---|---|---|---|
| (0) read `features` in `_update` | **+2,100 cold** (+100 if the word is already warm in the tx: the pay entries read `PAYABLE` from it [V, `src/metatx/MetaTokenBase.sol`, `requireFeature(PAYABLE)`], so `mtxPay*` pays +100, `transfer` / `mtxTransfer` pay +2,100 [V by EIP-2929, I on the path]) | same | 0 | breaks the rule on the entry that matters most |
| (i) two implementations, `NORMAL_REGULATED` / `WRAPPED_REGULATED` (kinds 8, 9), same source, the `_update` hook compiled in by one constant | **0** by construction, verifiable by reading | +2,100 (its holders accepted a regulated token) | +2 catalogue rows, +2 artifacts in the size gate and audit; CTR-AS-17's "flags, not kinds" is kept for the *ABI* (the regulated bits are still bits; the plain kind refuses them, the regulated kind requires at least one) | **recommended** |
| (ii) clone-with-immutable-args (the regulated word appended to the proxy's DELEGATECALL calldata, read by `calldataload(calldatasize − 32)`) | +≈ 10–30 [est.] | same | `OpenFactory` switches from OZ `Clones` to an immutable-args clone library: every `predictAddress` formula and clone bytecode changes, `createTokenUnregistered` too; a second clone shape to audit; factory bytecode before the freeze | zero-SLOAD but not zero, and the widest change |
| (iii) pack the regulated word into a slot `_update` already reads (`_totalSupply` high bits) | 0 | 0 | a hack through OZ `ERC20` storage; rejected |

Recommendation: (i). It is the one form that meets the rule by construction rather than by a measurement, and its
cost is two catalogue rows. It contradicts CTR-AS-17's placement, not its ABI, and the owner rules (§6 D3). Until
then nothing is built, and `features` keeps carrying the regulated bits on both forms.

Decided (CTR-GOV-03, owner 2026-11-02): (i), one regulated implementation per kind, never per feature, the confidential
kinds included (ids 10–13, CTR-GOV-16, -17); "+0" means no new read (CTR-GOV-11). Built: the plain half only. `NORMAL`
and `WRAPPED` refuse flags 5–9 with `FeatureNotBuilt`, the confidential kinds with `FeatureInvalidForKind`; the regulated
implementations are SPECIFIED, and the Change to CTR-AS-17 (spec §12.1) still waits for the owner.

## 3. The attack findings, A1–A21, in v2

The "How" column is the answer of 2026-11-02; where the build differs, the cell ends with **Built:** or **Superseded:**
and the rule's id. The spec's §8 disposes of every later finding (B-01 to B-34, R-01 to R-19).

| Id | v2 | How |
|---|---|---|
| A1 pending grant survives renounce / transfer | **fixed** | no `executeGrant`, nobody else executes: the **owner calls `grantRole` twice**; `pending[bit][account] = (eta, proposer)`; the confirm requires `caller == owner && caller == proposer`, so a renounced owner (0) and a new owner cannot confirm; a new owner re-proposes. `renounceOwnership` reverts while any `pending` is live? No: a dead pending is harmless once nobody can confirm; the view shows it. **Built** (CTR-GOV-04 and its Change): "same proposer" is an equal `ownerGeneration`, which `acceptOwnership` and `renounceOwnership` bump; the pending binds a `termsHash`; `setGrant` that adds a holder or widens takes the same two calls; `cancelGrant` deletes a pending |
| A2 no expiry, no reader | **fixed** | window `[eta, eta + grantDelay]`, dead after; `pendingGrant` view, `lastProposedAt`; the disclosure warns within `2 × grantDelay`; `holderCount` excludes pendings. **Built** (CTR-GOV-04): `grantDelay ≤ 30 days` (`GrantDelayTooLong`); `pendingGrant` returns `live` |
| A3 a holder self-reports a limit | **fixed, dissolved** | limits live in the granting contract's own `grants[bit][holder]`; a wallet never reads a holder's claims. A holder that is itself a base child is a second contract to read, by the same rule, from its own storage |
| A4 a `MODERATE` / `FORCE` SCaaS leg drains a wrapper | **fixed, owner decision D5** | `_addLeg` of every wrapped kind refuses a `factory.isToken` leg whose `features()` has bit 6 or 9 (features only lose bits, so an init check holds) — `WrappedLib` body, 0 token bytes; outside legs cannot be checked and the wording of §1.5 says so. **Built** (CTR-GOV-05): `isRegisteredToken`, not `isToken`; bit 6 `FORCE` or bit 21 `MODERATE` (`UnderlyingInvalid`) |
| A5 `features()` ≠ worst case on wrapped kinds | **fixed by wording** | §1.5: "this contract's own code"; the disclosure recurses on `underlyings()`, registered legs by the same read, others "unknown issuer powers" |
| A6 the owner's first block is not delayed | **fixed by wording** | an owner that is also a holder acts at once (token A is that by design); `revokeRole`, `disableFeature`, `renounceOwnership` are at once; ADAR sentence removed; C1's two-step without delay stands; `acceptOwnership` delay recommended **no** (a stalemate, not recovery) |
| A7 an msig UA cannot be owner / holder | **fixed by statement** | owner, holders and `grantor` are addresses; a derived UA acts through a contract (`SmartKeyAccount`, a Safe, a base child); `UA_POOL` / `SHIELD_POOL` refused as holders in `_grant`; "cannot administer gaslessly" → "cannot administer at all except through a contract". **Superseded:** every identity is a UA id `bytes32`, so an `msig` or PQ UA is owner or holder under its own id and acts through the chain's `GovernanceRouter` (`ua<Op>`, fee 0); the governed contract reads the subject by `_govSubject()` (CTR-GOV-01 Change, CTR-GOV-15 Change); pools and 0 stay refused (`RoleAccountPool`, `OwnerAccountPool`, `RoleAccountZero`) |
| A8 `grantDelay = 0` carve-out for confidential kinds | **fixed** | deleted; `WrappedPqzToken` is excepted only if measured over the stop line, and then per the drop order of §2.4, never by kind. **Superseded:** no exception at all; the whole record and the delay on every kind, size decided later (CTR-GOV-02, -19) |
| A9 revoking the last issuer releases every freeze at once | **not fixed here, routed** | `GovernanceLib` carries one more mask, `_delayedRelaxBits()`, under which `revokeRole` and `disableFeature` take `grantDelay`; the asset-suite stream decides whether 5–7 are in it (it rewrites CTR-AS-03). Default mask 0 = today's behaviour, 0 B until used. Reduce-only is re-labelled "reduces power over holders". **Decided, SPECIFIED** (CTR-GOV-09 and Changes): the mask also covers `renounceRole`, an edit that ends the power before `now + grantDelay`, and a parent's revoke killing leaves; it counts live roots; not in the code, it arrives with the regulated implementations |
| A10 the three examples do not run on the holder clone | **fixed** | §1.6: the grant lives in the contract that owns the power, for tokens and applications alike |
| A11 no floor; value ≠ effect | **fixed** | `min` / `max`; the scalar passed to `use` is the number the contract acts on |
| A12 set forms are address predicates; one `setRef`, no mask | **fixed** | one `bytes32 scope`, the contract's predicate; token `MODERATE` scope = `0` (any) or a registry address; `FIXED{a, b}` is a two-member registry; the five set words are gone. **Superseded in part** (spec §1.5, B-10): on a bit in `_scopeBits()` a scope of 0 is refused (`GrantWordRefused`), so "any" for `MODERATE` is a non-zero constant named when it is built |
| A13 a registry scope widens after the grant | **fixed by wording** | the disclosure names the registry's controller ("X can change this group at once"); a promise that must not move pins an immutable registry; no membership delay in the token |
| A14 "a new factory kind" cannot exist | **fixed, dissolved** | no holder kind; `TokenKind` changes only for §2.5 (i). **Built:** `TokenKind` 0–13 with the six regulated ids (CTR-GOV-16) |
| A15 DEX rescues to the admin-rewritable `treasury` | **fixed** | `DexConfig.rescueTo`, immutable, `RESCUABLE` set iff non-zero; but first check CTR-DEX-20 (the rescue report says strays at rest already go to any submitter [I, not re-read]): if so the DEX needs no `rescue` entry and only `DexPuller` keeps `rescueTo`. **Built** (CTR-GOV-06): CTR-DEX-20's sweep stands, so the DEX has no `rescue`; `DexConfig.rescueTo` goes to `DexPuller`'s immutable `rescueTo`, and `DexPuller.rescue(token)` is open to anyone; `SCaaSDex.initialize` refuses a pool, the DEX or the puller as `rescueTo` |
| A16 the all-leg post-check traps unrelated rescues | **fixed** | foreign asset: every leg's balance unchanged across the call; a leg asset: that leg `balanceOf ≥ reserve` after; ≤ 8 reads; a short leg no longer blocks a foreign rescue. **Built** (CTR-GOV-06) on the six token kinds, plus: a leg's rescue requires every other leg's balance unchanged (`RescueTouchedLeg`) |
| A17 +2,100 on a plain transfer | **re-examined, owner decision D3** | §2.5: (i) recommended; the base adds 0. **Decided** (i), CTR-GOV-03; "+0" = no new read, CTR-GOV-11, pinned on every kind |
| A18 families unmapped | **fixed** | §4, nine rows, NEAR and Algorand separate |
| A19 the holder chain is unspecified | **fixed** | §1.3: two levels, `narrows` + `_scopeNarrows` at grant, parent debit + epoch at use, `uint128` in the contract's own units |
| A20 `holderCount` must count INIT grants and pendings not | **fixed** | counted in `_grant` (the one path, INIT included, idempotent re-grant skipped), decremented in revoke / renounce; pendings excluded. **Built:** `Counts {holders, roots}` per bit, one transition table (spec §1.7); `holderCount` reads `holders` |
| A21 `WrappedPqzToken` bytes | **open, measurement** | §2.4 drop order: grant record first (flat-only kind), rescue second, `holderCount` last; measure after §6 steps 1–3. **Superseded:** measured, and the owner kept the whole record; `WrappedPqzToken` is 72,160 B on the SCaaS testnet's 131,072 B ceiling, size decided later (CTR-GOV-02, -19) |

The findings the judgment did not see, from the journal:

| Source | v2 |
|---|---|
| escalation F6: `issuer` and `compliance` on one bit, one holder writes the order and executes it | **fixed**: bit 10 `RECORD` is the compliance right; `FORCE` (6) acts on a record written under 10; a contract may hold both only if the asset-suite spec says so (recommend: refused in `_grant` when `hasRole(10)`, 0 B lib). **Decided, SPECIFIED** (CTR-GOV-09): one holder is refused both; bit 10 is a number only, and `init` refuses `roles.compliance ≠ 0` (`RoleWithoutFeature(10)`) |
| escalation F8 (= A3) | dissolved |
| escalation F9 (= A9) | routed |
| escalation F10 (= A10, confused deputy through a generic holder) | fixed: no generic `execute` anywhere in the model; a base child exposes typed entries only |
| escalation F11: `MODERATE` against `FREEZE` / `FORCE` / `ALLOWLIST`; reaches contract-held balances | **D8**: `moderatedTransfer` passes every regulated check of the instance (frozen `from` refused, `ALLOWLIST` on `to`); refuses a `from` with code (so tender pools, vesting clones, wrapper reserves, AMM pools are unreachable; Safe-held balances too — the product trade-off, stated) |
| escalation F12: renounce with an unbounded surviving holder | **fixed, one rule**: `renounceOwnership` reverts while a holder exists on a bit that is **not locked**; a locked bit's holders survive (the issuer promised the power is permanent, and a wallet reads `lockedFeatures` as exactly that). CTR-TOK-22's "revoke every role, then renounce" becomes enforced for unlocked bits. A surviving limited holder on a locked bit keeps its `Grant`, which the owner can no longer widen. **Built** (CTR-GOV-02 and its Change): the rule counts live roots (`Counts.roots`), not dead leaves (`OwnerHasHolders`); `init` with owner 0 runs the same check |
| escalation F13: budgets add across clones, refresh on rotation | fixed (§1.3, one record per holder, spent carried) |
| escalation F14: non-EVM holder replaced silently or never revoked | §4 |
| escalation F15: contract-only ≠ a Safe; a mutable holder is a replacement without a grant | fixed by wording: contract-only stops a raw EOA; the disclosure says "mutable by its own rules" unless the holder is a base child with `owner() == 0`, whose rules are then readable |
| `MODERATE` F3: `fromSet ANY` reaches tender deposits and clones | D8 (no `from` with code) |
| `MODERATE` F4: derived UAs unreachable; the `bytes32` repair's traps | D8: `moderatedTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref)` on `_uaMove`, refusing 0, `pad(UA_POOL)`, `pad(SHIELD_POOL)`, `pad(this)`, an unregistered or non-SIGNING derived `to`, a native `from` with code; tested: no moderated move changes `balanceOf(UA_POOL) − Σ` |
| `MODERATE` F5: `mtx` / `ua` twins of `moderatedTransfer` are meaningless | D8: one direct entry; the holder is a contract that relays on its own (`MetaTxBase` child or `SmartKeyAccount`), which keeps the "every mtx* write relayable" rule because there is no `mtx*`. **Superseded in part:** a holder is any UA, and a relayed power reaches the governed contract through a `GovernanceRouter`; `moderatedTransfer` is not in the built router's closed table, so it would take another child of `GovernanceRouterBase` (spec §3.2 "Another router", CTR-GOV-15 Change; `MODERATE` itself SPECIFIED, CTR-GOV-08) |
| `MODERATE` F6: bit 9 outside every regulated rule; CTR-TOK-10, README §3, `architecture.md` become false | D8 lists the amendments: 9 joins CTR-AS-02 disclosure + `termsHash`, contract-only holder, the wizard's underlying refusal (now D5 in bytecode) |
| rescue F2–F4, F6 (alias legs, buffers, rebases, the all-leg check) | A16's per-asset check; the wizard refuses rebasing legs; a leg's surplus is rescuable only where `owed` is exact on chain (unchanged rule) |
| rescue F5: CTR-DEX-20 already sweeps strays | A15 |
| rescue F7, F8: tender `owed`, relay router | tender: rescue only when I2's `owed` is on chain, else foreign assets only; relay router: no rescue (holds nothing by construction, CTR-MTX-27 forbids the entry [I, report]) |
| families F1–F11 | §4 |

## 4. Non-EVM: what `GovernanceBase` becomes

The rule is one everywhere: *a bits word, flat holders, an optional grant, an owner with a two-step transfer and a
renounce, a delay, a lock.* What differs is the container and what the family cannot express. NEAR and Algorand are
separate rows and must stay so. All non-EVM cells rest on the families report's citations [I], not on sources re-read
this session.

> **Status, 2026-11-04:** nothing below is built; every family is PLANNED (CTR-GOV-07, Part D7 first for Soroban, the
> others in their own rounds; spec §6.3). Superseded for every row: the stored owner, holder and grantor are the same UA
> id `bytes32` on every family, and each family maps its own caller to it, or to its router's subject (CTR-GOV-01 Change,
> UA identity Change spec §5); "owner is an `AccountId`" and holder keys by native address below read as that. Bits are
> 0–255 everywhere (CTR-GOV-10). CTR-GOV-07's Change adds TON, Solana, Cosmos and Aptos to the two entries, and gives Sui
> a two-step and a burn, not `store`.

| Family | `GovernanceBase` becomes | Owner / holder / grant | Delay, lock | Cannot express |
|---|---|---|---|---|
| **Soroban** | a `governance` Rust module shared by `scaas-token` and the DEX: instance storage `features: u128`, `owner: Option<Address>`, `pending_owner`, roles map `(bit, Address) → u8`, grants map; `require_auth` on the owner | a contract can be any holder (its `__check_auth`); grants as on EVM; sync, atomic | ledger timestamp; lock = the same word. **Gap today:** admin is write-once (families F1), and the Soroban freeze is the same freeze as EVM's (`TODO.md`) — `set_admin` two-step + `renounce_admin` must land **before it** (§6 D7) | no `isContract`; a holder's code authority is not readable from the token (the contract is immutable as built, so a holder's mutability is the holder's own concern) |
| **Solana** | no SCaaS token; the `scaas` program gets a `Governance` PDA per instance (`features: [u128; 2]`, bits 0–255, CTR-GOV-10's Change, owner 2026-11-04, owner, pending, roles as PDAs seeded `(instance, bit, holder)`, grants as PDAs). For SPL / Token-2022 mints the model is **display only**: mint authority → `MINTABLE`, freeze authority → `FREEZE`, `PermanentDelegate` → `FORCE` (NET-SOL-09: accepted as issuer risk, owner decision, not a gap) | a policy program's PDA as holder only if its upgrade authority is `None` (escalation F14, families F10); otherwise "whole shape, mutable" | delay: slot or unix timestamp; lock on SPL = authority `None`, one-way | a duration bound on freeze; a record-gated force; `grantDelay` on `SetAuthority` |
| **NEAR** | a `Governance` struct in the contract state (`LookupMap` roles / grants), `predecessor_account_id` as the caller; owner is an `AccountId`; derived UA ids as `Vec<u8>` keys | a contract account as holder; **async**: `use` reserves the budget, the callback settles or releases it, and the view shows `reserved` (families F9) | block timestamp; lock = word. Write-once admin today (F1): `set_admin` / `renounce_admin` in the NEAR UA round, before its add-on audit | a synchronous read of another contract's `features` (a wrapper cannot check a leg at init); a holder account's full-access keys are an inherited power the token cannot see |
| **Algorand** | global state: **four `uint64` words** (bits 0–255, CTR-GOV-10's Change, owner 2026-11-04: Algorand's global uint is 64-bit), owner, pending; roles and grants in boxes keyed `bit ‖ addr`; the holder funds the box MBR by an inner payment in the same group | an app account as holder (`Txn.sender` of an inner call); **atomic**: a failed use fails the group, no reserve state (not NEAR) | round timestamp; lock = word. Write-once admin today (F5): the same two entries in the Algorand UA round | a rekey of the owner or a holder account (silent replacement, F5); `isContract` |
| **Aptos** | a `Governance` resource under the instance object; bits `u256` (0–255, CTR-GOV-10's Change, owner 2026-11-04); roles as a table | the real powers are `MintRef` / `TransferRef` / `BurnRef` values; a resource that holds a Ref **is** the holder, bits are its display. A Ref stored elsewhere is unreadable (families F8) | timestamp; lock = word; object-level rotation is native [I] | the worst case of an FA: **unknowable**; the disclosure says so. `admin_sweep` stays the admin-chosen form to avoid → `rescue_to` fixed at creation |
| **Sui** | a shared `Governance<T>` object with bits; `TreasuryCap<T>` wrapped inside = the `MINTABLE` holder; roles as a `Table` | **`AdminCap` has `key` without `store` and no transfer entry (families F7)**: give it `store` or a two-step transfer + burn **before `make_immutable`**, or the DEX config is frozen at the first lost key | `Clock`; lock = word; `DenyCap` and global pause are inherited powers of a regulated coin | an envelope on an `AdminCap` holder is impossible until F7 is fixed; a multisig address rotates by deriving a new address |
| **TON** | fields in the jetton master and the DEX; bits `u128`; roles as a dict; `mintable` derived from `MINTABLE`, not the constant (families F2) | a contract as holder; **async**: a use is counted before the message; a bounce must report back or the disclosure states "spent is an upper bound" (F9) | `now()`; lock = word | a synchronous balance read, so no accounted-asset surplus rescue, foreign only; `MODERATE` cannot be added later without changing every wallet address (F6); `WithdrawFees` with a free `to` reaches bounced user proceeds (F4) → `FEE_ROUTING` with a fixed `rescue_to` |
| **Cosmos (CW20 + DEX)** | a `governance` state item (bits, owner, pending, roles map, grants map); `info.sender` as caller; `minter: Option` becomes a `MINTABLE` holder | a contract as holder; atomic | block time; lock = word. **Code authority:** a wasm `admin` can migrate the code (families F10): `--no-admin` is a rule, SPECIFIED not built | the built DEX `Sweep{token, recipient, amount}` (F4) is the admin-chosen form: replace by `RESCUABLE` + `rescue_to` |
| **Hedera** | the EVM code, unchanged | as EVM | as EVM | an HTS leg's native keys (`ADMIN`, `WIPE`, `FREEZE`, `KYC`, `PAUSE`, `FEE_SCHEDULE`) are inherited `FORCE` / `FREEZE` over the whole reserve, not refused on chain (NET-HED-07, SPECIFIED): the disclosure step reads `getTokenKey` per leg (families F3); whether a clone inherits a contract `adminKey` is unverified |

What no family can express and the model does not pretend: the "fixed supply by leaving `MINTABLE` out" of token A
exists today on EVM and Cosmos only; Soroban, NEAR, Algorand and TON tokens mint after creation, so a fixed supply
there is "initial mint, then renounce" — which needs the renounce entry of D7 (families F5).

## 5. Prior art, fetched and compared

**Fetched [F]:** Zodiac Roles Modifier v3 — `packages/evm/contracts/types/Operator.sol`, `Allowance.sol`,
`Permission.sol`, `Condition.sol` (raw, main), `packages/evm/README.md`, the docs introduction
(`docs.roles.gnosisguild.org`; its concept pages returned 404). ERC-7710 — the EIP text at eips.ethereum.org.
MetaMask Delegation Framework — `README.md`, `src/utils/Types.sol`, `documents/DelegationManager.md`,
`documents/CaveatEnforcers.md`, `documents/Security.md`, the `src/enforcers` listing. **Not fetched:** any audit or
incident record for either; "known failures" below are those the projects' own documents state.

### 5.1 Scope models

| | Zodiac Roles v3 [F] | ERC-7710 / MetaMask DF [F] | v2 |
|---|---|---|---|
| unit of a right | `Role { members, clearance[target] ∈ {None, Target, Function}, scopeConfig[key] }`: a role key, a target, a function, an `ExecutionOptions ∈ {None, Send, DelegateCall, Both}` | `Delegation { delegate, delegator, authority, caveats[], salt, signature }`; `Caveat { enforcer, terms, args }`; open delegate `0xa11` | a bit on a contract; a holder; a `Grant` |
| where it is checked | a **caller-side** module in front of an avatar (a Safe), over the **calldata** it forwards | a **manager** between redeemer and delegator, enforcers before / after the execution, over calldata and (balance enforcers) state deltas | the **target itself**, over the number it acts on |
| conditions | a flattened tree (`ConditionFlat { parent, paramType, operator, compValue }`, BFS index) with operators `Pass, And, Or, Empty, Matches, ArraySome, ArrayEvery, ArrayTailMatches, ZipSome, ZipEvery, Slice, Pluck, EqualToAvatar, EqualTo, GreaterThan, LessThan, SignedInt…, Bitmask, Custom, WithinRatio, WithinAllowance, CallWithinAllowance` | 38 enforcers (`AllowedTargets`, `AllowedMethods`, `AllowedCalldata`, `ERC20TransferAmount`, `ERC20PeriodTransfer`, `ERC20Streaming`, `*BalanceChange`, `LimitedCalls`, `Timestamp`, `BlockNumber`, `Redeemer`, `Nonce`, `Id`, `ExactCalldata`, `LogicalOrWrapper`, …) | `min`/`max`/`total`/`perWindow`/`validUntil`/`maxUses` + one `scope` word + the contract's predicate |
| allowance | `Allowance { refill, maxRefill, period, balance, timestamp }` (2 slots), keyed by `bytes32`, shared by any condition that names the key, consumed by "allowance tracing" | `ERC20PeriodTransfer`, `*Streaming`, keyed `(manager, delegationHash)` | `perWindow` / `window` / `total` per `(bit, holder)` |
| narrowing | none between roles (a role is set by the owner) | "caveats accumulate along the chain": each hop adds its own; validity only at execution; revocation on chain (`disableDelegation`) | two levels, `narrows` at grant, each hop enforces its own at use |
| known failures stated by the project | the README's allowance tracing is the one described mechanism; no failure list found | `Security.md`: unchecked calldata lengths in the assembly `decodeBatch` let `Execution[0]` read `Execution[1]`'s data; `CaveatEnforcers.md`: **enforcer order matters** (a payment enforcer drains before a balance enforcer checks), execution output is not validated, a passing `beforeHook` guarantees nothing — use `afterHook`; a signature can turn invalid when the delegator's signer config changes; simulate before submitting | — |

### 5.2 Taken and rejected

| Idea | Verdict | Reason |
|---|---|---|
| Zodiac `Allowance` as two storage words with `balance` and `timestamp` sharing one | **taken** (the `Grant` packs `spentInWindow`, `window`, `windowStart` in one word) | the one write on `use` touches one slot. **Superseded:** the built six-slot `Grant` keeps `spentInWindow` beside `perWindow` and `windowStart` beside the small words, so a limited `use` writes up to three slots [I, from the struct order] |
| Zodiac: an allowance keyed independently of the member, shared by several | **rejected for now** | one grant per `(bit, holder)` is readable; a shared budget per bit ("the token mints at most N per window, whoever mints") is an instance invariant, settable at INIT if ever wanted, not a grant |
| Zodiac condition trees over calldata (`Matches`, `Pluck`, `Slice`, `Bitmask`) | **rejected** | a packed policy language over word offsets: the attack report's reason, plus the explicit-parameters rule; and calldata is not effect (A11): the loan the contract pays is in storage, not in the argument |
| Zodiac `Custom` operator (an external condition contract) | **taken in spirit** | that is the contract's own predicate over `scope`; ours lives in the target, not in a side contract |
| Zodiac `ExecutionOptions` (`Send`, `DelegateCall`) | **rejected** | no generic execute exists in the model (CTR-MTX-16) |
| MetaMask `authority = hash(parent)`, root authority | **taken as `grantor` + `grantorEpoch`** | the same link, on chain, revocable by bumping the parent |
| MetaMask "each hop checks its own caveats; a chain is read leaf to root" | **taken** | our "no subset proof: each level enforces at use"; the base adds `narrows` at grant only because a wallet must be able to print a leaf's limits without re-deriving the chain |
| MetaMask off-chain signed delegations, redeemed through a manager | **rejected** | no on-chain holder list (no `holderCount`, no disclosure), revocation costs gas anyway (their own note), validity "only at execution" (their own note); SCaaS already has the relay path for gasless *use*; the *grant* must be on chain |
| MetaMask `bytes terms` / `bytes args` per enforcer | **rejected** | opaque blobs, against explicit parameters; `args` is redeemer-supplied and ignored in the hash by design |
| MetaMask balance-change enforcers (`afterHook` compares a cached balance) | **taken as the rule, not the mechanism** | "the scalar passed to `use` is what the contract acts on" is the same insight — bind the effect — without before/after hooks and their ordering surface |
| MetaMask open delegate `0xa11` | **rejected** | a right with no holder is a bit without a role (`PAYABLE`, `RESCUABLE`); an "anyone under caveats" grant is what `RESCUABLE` is, and it has no caveats |
| ERC-7710 `redeemDelegations(bytes[] permissionContexts, bytes32[] modes, bytes[] executionCallData)` | **rejected** | opaque contexts, ERC-7579 execution over arbitrary targets, and the standard's own "needs discussion" security section; nothing in it that a typed entry on the target does not do better for a factory-made, immutable contract |
| ERC-7710 "simulate before you act" | **taken as a wallet rule** | a wallet shows `grantOf` and the window; it still simulates, because a grant can be revoked between read and send |

## 6. Decisions for the owner (nine), and the order of work

Sorted: what must land before the EVM audit freeze first (token, `GovernanceLib`, `WrappedLib`, factory, DEX
bytecode), then Soroban's freeze, then later releases. Band decisions A, B and the global table are **not** here: they
are decided.

> **Decided 2026-11-02, as recommended, each with the owner's Changes since** (the table below is the question as it was
> put; the rule is the register's):
>
> | # | Rule | Where the answer differs from the recommendation | Built state |
> |---|---|---|---|
> | D1 | CTR-GOV-01 | identities are UA ids `bytes32`, `_govSubject()`, one `GovernanceRouter` per chain (Change 2026-11-04) | BUILT (T3, T10b, T11) |
> | D2 | CTR-GOV-02 | no kind is flat-only: the whole record on every kind, size later (CTR-GOV-19); the renounce rule counts live roots | BUILT (T5–T7) |
> | D3 | CTR-GOV-03, -11, -16 | ids 8–13 are real enum members, not a comment; regulated means flags 5–9 with `DENYLIST` | plain half BUILT; regulated kinds SPECIFIED |
> | D4 | CTR-GOV-04 | `setGrant` widenings take the two calls with a `termsHash`; `cancelGrant`; `grantDelay ≤ 30 days`; `grantDelay = 0` is one call | BUILT (T7) |
> | D5 | CTR-GOV-05 | `isRegisteredToken`; bits 6 or 21 | BUILT (T8) |
> | D6 | CTR-GOV-06 | CTR-DEX-20 stands: `DexPuller` alone on the DEX side; `RescueTouchedLeg` | BUILT on the six token kinds and `DexPuller` (T10) |
> | D7 | CTR-GOV-07 | every family takes the two entries; Sui a two-step and a burn | PLANNED |
> | D8 | CTR-GOV-08, -13 | bit 21, not 9; `moderatedTransfer` is subject to `FREEZE`, `PAUSE` and the receiver check; public balances only | SPECIFIED, number only |
> | D9 | CTR-GOV-09 | the mask also covers `renounceRole`, an edit ending the power early, a parent's revoke; counts live roots | SPECIFIED; bit 10 a number only |
>
> The order of work below was replaced by the build plan's tasks T1–T19 on branch `governance`; the selector audit of
> step (7) is `test/vectors/selector_audit.json` (T13).

| # | Decision | Recommended answer | Cost |
|---|---|---|---|
| **D1** (freeze) | Split `scaas.token` into `scaas.token` (identity) + `scaas.governance`; `AdminLib` → `GovernanceLib`; the admin ABI into `GovernanceBase` on every kind and on `SCaaSDex` (`admin` → `owner`, `LISTING`, `FEE_ROUTING`); namespace roots added to the layout pins; `IGovernance` replaces `ITokenAdmin` with every name kept | **yes** | tokens ≈ 0 B for the move; DEX +1.2–1.6 KB; one new env version per domain; `Features.t`, `Factory.t`, `Dex.t` admin tests edited; clients rename `admin` → `owner` on the DEX |
| **D2** (freeze) | The `Grant` record in the base: `use(bit, holder, scalar) → scope`, `setGrant`, `grantOf`, two levels, spent carried on edit, `renounceOwnership` refused while an unlocked bit has holders (escalation F12) | **yes** | lib +1.0–1.5 KB, each kind +300–450 B, `WrappedPqzToken` flat-only if it measures over the line; the F12 rule changes CTR-TOK-22's recipe from advice to a revert |
| **D3** (freeze) | A17: how a regulated instance is known on the hot path: (i) `NORMAL_REGULATED` / `WRAPPED_REGULATED` kinds 8 / 9, (ii) immutable-args clones, (0) accept +2,100 | **(i)**; reserve ids 8 / 9 in the enum comment now (0 B), build with flags 5–8 | +2 catalogue rows and artifacts; CTR-AS-17 reworded ("flags on the ABI, two implementations behind them"); (ii) would change every clone address formula and the factory before the freeze |
| **D4** (freeze) | `grantDelay` (`TokenConfig` / `DexConfig`, immutable, 0 allowed) in the two-call form; `pendingGrant`, `lastProposedAt`, `holderCount`; `acceptOwnership` **not** delayed (C1 stands) | **yes**; wizard default 2 days, dev chains 0 | lib +0.4–0.6 KB, each kind +0.2–0.35 KB; `grantRole` tests doubled |
| **D5** (freeze) | `_addLeg` of every wrapped kind refuses a SCaaS leg with bit 6 or 9 (A4); the wizard refuses a `MODERATE` token as a tender / vesting / offer deposit asset | **yes** | `WrappedLib` +≈ 100 B, 0 token bytes; one `isToken` + `features()` STATICCALL per leg at init |
| **D6** (freeze) | `RESCUABLE` (bit 17) + immutable `rescueTo` + `rescue(asset)` with the per-asset check (A16) on the kinds that fit; DEX only if CTR-DEX-20 does not already pay strays out, else `DexPuller` alone; `WrappedPqzToken` last | **yes** | each kind +150–250 B, `WrappedLib` / lib +≈ 400 B; the CTR-DEX-20 check is one read of `dex.md` before building |
| **D7** (Soroban freeze) | `set_admin` (two-step) + `renounce_admin` on the Soroban token and DEX before their freeze; NEAR and Algorand the same two entries in their UA rounds; Sui `AdminCap` gets `store` or a two-step transfer before `make_immutable` | **yes** | small per family; without it every Soroban token is write-once forever (families F1/F2), and the EVM-only delay is the only delay there is |
| **D8** (later, with flags 5–8) | `MODERATE` shape: one direct entry `moderatedTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref)` on `_uaMove` with the §3 refusals; **refuses a native `from` with code**; passes `FREEZE` / `ALLOWLIST`; scope = any or a registry; bit 9 joins CTR-AS-02 disclosure + `termsHash`; CTR-TOK-10, README §3, `architecture.md` amended | **yes**, including the contract-`from` refusal (Safe-held balances become unreachable by a moderator: the lesser hole) | ≈ 0.6–0.9 KB on `NORMAL` / `WRAPPED` later; three normative sentences rewritten; 0 B now |
| **D9** (later, asset suite) | `_delayedRelaxBits()`: revoke / `disableFeature` on `FREEZE` / `FORCE` / `PAUSE` take `grantDelay` (A9); `RECORD` (bit 10) as the compliance right distinct from `FORCE` (escalation F6), a holder refused both | **yes** to both | rewrites CTR-AS-03's "losing a role relaxes at once"; the mask costs 0 B until the asset suite sets it |

**Before the freeze, in order:** (1) D1 — the move and the split, measured on `WrappedPqzToken` first; (2) D4 — the
delayed grant, `holderCount`; (3) D2 — the grant record, with the drop decision on `WrappedPqzToken` taken from the
measurement; (4) D3 — the enum reservation only (the regulated kinds are built with flags 5–8); (5) D5 — the leg
refusal; (6) D6 — rescue, after the CTR-DEX-20 read; (7) the selector-audit test of v1 §4 (every non-`mtx*` external
that writes state is gated by a bit, the owner, or is a holder's own balance); (8) D7 — Soroban's two entries, in the
same freeze window. Measure after (1)–(3) and again after (6) (A21). D8 and D9 need nothing before the freeze beyond
the bit numbers, which are allocated now and cost 0 B.

## 7. Attack on this result: the three weakest points

1. **The `Grant` record is the heaviest piece and the least measured.** It is justified by decision B and the three
   examples, and its bytes on `WrappedPqzToken` may force a flat-only kind — two disclosure shapes on one chain. If the
   measurement says so, the honest fallback is "grants on `NORMAL*` and the DEX only", stated, not a lever hunt.
   Everything in §2.4 is [est.]. (Resolved by the owner: the measurement said it did not fit, and the whole record was
   built on every kind anyway, one disclosure shape; `WrappedPqzToken` runs only on a chain with the higher ceiling
   until size is decided, CTR-GOV-02, -19.)
2. **`_scopeNarrows` is application code.** Scalars narrow in the base; scope narrows wherever the application says
   it does. A wrong predicate (an `isDescendant` that returns true for a sibling) widens a leaf silently, and the base
   cannot tell. The mitigation is only that it is one `view`, named, auditable, and that a leaf still debits its
   parent's budget whatever the scope says.
3. **The global table's "same meaning everywhere" is carried by names.** `PAUSE` on a token and on a DEX are the same
   sentence; `LISTING`, `DISQUALIFY`, `REVOKE_GRANT` are allocated from specs not re-read this session (tender.md,
   asset-suite.md) [I], and D3's recommendation (i) contradicts CTR-AS-17's placement — the owner may keep flags-only
   and take the +2,100, which the model survives but the rule does not. (Since: `DISQUALIFY` and `REVOKE_GRANT` were
   never allocated, bits 13 and 14 stay unused, CTR-GOV-14; the owner took (i), CTR-GOV-03, and the Change to CTR-AS-17
   still waits.)

Verified by reading [V], at `b3cf5718`: everything cited with a file and line in §1.2, §2.1–2.5 and the "today" column of §1.4; the
EVM facts behind A1–A21 as the attack report verified them. Inferred [I]: every byte and gas figure, the bit
allocation of 10–20, the non-EVM table, the CTR-DEX-20 sweep claim, the A17 estimate for immutable-args clones.
Fetched [F]: §5 only.
