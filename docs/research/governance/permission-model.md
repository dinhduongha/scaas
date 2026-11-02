> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# A general permission model for SCaaS contracts — version 2 (2026-11-02)

Version 1 (same day, superseded by this file) derived the model from the owner's question *"is there a right, and
within what?"* and placed every per-holder limit outside the token. The attack round
([permission-model-attack.md](permission-model-attack.md), A1–A21, plus the parts of the escalation report after its
7th finding and of the `MODERATE` report after its 2nd, read this session from the workflow journal) and three owner
decisions of 2026-11-02 change the placement, not the model:

- **A. `GovernanceBase` accepted.** One layer — owner, features, roles, lock, delay — in its own storage namespace,
  inheritable by any contract: tokens, `SCaaSDex`, tender, `LoanBook`, third-party applications. Not in `MetaTxBase`
  or `UAMetaTxBase`, which are authentication and relay.
- **B. Bit bands, decided:** bits 0–63 are SCaaS's, **one global table, each bit allocated once, never renumbered,
  the same meaning on every SCaaS contract** (`PAUSE` is the same bit on a token and on the DEX; a contract without the
  power leaves the bit off); 64–127 are per-contract, declared by the application with a label (bit → function) so a
  wallet can show them; 128 and above are reserved and refused today. Existing bits 0–8 and `MODERATE` at 9 stay in
  the SCaaS band.
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
session.

## 1. The model, restated

### 1.1 One sentence

*A bit says whether a right exists on this contract; a holder entry says who has it; an optional grant record says
within what; the owner, after a delay, changes holders and grants; a lock makes a bit permanent.* Every SCaaS contract
that has rights at all inherits `GovernanceBase`, so these five words are read the same way at every address.

### 1.2 `GovernanceBase`, `GovernanceLib`, `GovernanceBits`

Three pieces, because tokens cannot afford inlined logic (`WrappedPqzToken` has 1,077 B to the 64,500 B stop line [V,
`size-baseline.json`]) and `AdminLib` is already an external library for that reason (CTR-TOK-24 [V, AdminLib.sol:8]):

| Piece | What it is | Holds |
|---|---|---|
| `GovernanceBits` | a constants file (library of `uint8` constants) | the global table of bits 0–63 (§1.4), nothing else |
| `GovernanceLib` | `AdminLib` renamed and extended; external library, DELEGATECALL, one body audited once | storage namespace `erc7201:scaas.governance`; `init`, grant / revoke / renounce, two-call delayed grant, `disableFeature`, owner two-step and renounce, `holderCount`, the grant record and `use` |
| `GovernanceBase` | abstract contract, one-line wrappers over the library, the `IGovernance` ABI, three `pure virtual` masks | nothing of its own |

A contract declares three masks (compile-time constants, read by `init` and `_grant`, never storage):

```solidity
abstract contract GovernanceBase is IGovernance {
    function _validBits()        internal pure virtual returns (uint256);  // bits this contract implements (both bands)
    function _roleBits()         internal pure virtual returns (uint256);  // subset with a holder (PAYABLE, BURNABLE, RESCUABLE have none)
    function _contractOnlyBits() internal pure virtual returns (uint256);  // subset whose holder must have code
    function _scopeNarrows(uint8 bit, bytes32 parent, bytes32 child) internal view virtual returns (bool) { return parent == child; }
    function bitLabel(uint8 bit) external pure virtual returns (BitType t, bytes4 selector, string memory name); // 64–127 only
}
enum BitType { CAPABILITY, POWER }   // §1.4: the type is `_roleBits()`, never a second declaration
```

`_validFor(kind)` of today [V, AdminLib.sol:193–201] becomes each token kind's `_validBits()`; `ROLE_BITS` [V, :36]
becomes `_roleBits()`; the `RATE_ADJUSTABLE` contract-only check [V, :180] becomes `_contractOnlyBits()`. The library
refuses, in this order: a bit ≥ 128 (`FeatureReserved(bit)`, on `features`, `lockedFeatures` and in `_grant`:
`features >> 128 != 0` reverts, `bit >= 128` reverts — the word stays `uint256` so the ABI does not move when 128+
opens); a bit outside `_validBits()` (`FeatureInvalidForKind`, today's error, kept); a regulated bit not yet built
(`FeatureNotBuilt`, kept until the asset suite lands); a role on a bit outside `_roleBits()` (`NoSuchRole`); a holder
without code on a `_contractOnlyBits()` bit (`RoleNotContract`); `UA_POOL` and `SHIELD_POOL` as a holder
(`RoleAccountZero` reused or a new `RoleAccountPool`; the `MODERATE` report's F5, 0 token bytes). So "`AdminLib`
accepts only known bits" stays true per contract: the SCaaS band is known from the global table, the application band
from the contract's own mask, and 128+ is refused everywhere.

### 1.3 The grant record (what "within what" means)

Holding stays flat: `roles[bit][account]` is one slot, as today [V, AdminLib.sol:61], but its value becomes `uint8`:
`0` none, `1` whole shape, `2` limited. A holder at `2` has a `Grant` record at `grants[bit][account]`:

```solidity
struct Grant {                          // 4 slots; absent for a whole-shape holder (today's holders)
    uint128 min;  uint128 max;          // bounds on the scalar the contract names (0 / type(uint128).max = none)
    uint128 total; uint128 spentTotal;  // cumulative
    uint128 perWindow; uint128 spentInWindow; uint32 window; uint32 windowStart;   // MandateWallet's grid [V, :27–35]
    uint64 validUntil; uint32 maxUses; uint32 uses;
    bytes32 scope;                      // opaque to the base; the contract's predicate reads it
    address grantor; uint32 grantorEpoch; bool delegable;
}
function use(uint8 bit, address holder, uint128 scalar) internal returns (bytes32 scope);   // the one check
```

The rule that makes the owner's loan example run and closes A11: **the scalar a contract passes to `use` is the
number it then acts on** (the principal it pays, the amount it mints, the units it moves), never a number the caller
chose for the check alone. A contract without a scalar passes 0 (`min`/`max` unused; `total`, `maxUses`, `validUntil`
still bind). The base never interprets `scope`: `use` returns it and the contract applies its own predicate (§1.6).
`use` on a whole-shape holder costs the same one SLOAD as `requireRole` today (the value `1` is in the same slot the
`bool` was) [I]; only a limited holder pays the record's reads and one write.

**Two levels, enforced where used, no proof.** The owner grants; a holder whose grant is `delegable` may grant a leaf
on the same bit; a leaf cannot delegate. At a leaf grant the library checks `narrows(child, parent)` on every scalar
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

### 1.4 The global bit table (bits 0–63), proposed allocation

Decided: one table, allocated once, never reused or renumbered, the same meaning everywhere. Pinned in code as
`GovernanceBits.sol` and in docs as the table below moved to `docs/contracts/README.md §3` when normative; a vector
file `test/vectors/governance_bits.json` (`bit → name → one disclosure sentence`) is written by a forge test from the
constants and read by every client, so a wallet names bits 0–63 **without reading the contract**; bits 64–127 come
from the contract's `bitLabel(bit)`. A bit's name is general (what the holder may do to others or to the instance),
never a contract's function name.

**Every bit has a type, and the type is part of the table** (owner question, 2026-11-02): a **capability** is a
behaviour of the instance with no holder — it is open to every user (`PAYABLE`: anyone may pay through the pay entries;
`BURNABLE`: any holder of units may destroy its own units; `RESCUABLE`: anyone may trigger the rescue) or binds every
user (`ALLOWLIST`: every receiver is gated). Nobody "acts under" a capability as a person; the instance behaves that
way. A **power** is a right tied to persons: it has holders, and only a holder (whole-shape or limited by a `Grant`)
acts under it; `MINTABLE` with its `minter` is the pattern. In code the type **is** `_roleBits()`: a bit in
`_validBits() & ~_roleBits()` is a capability, a bit in `_roleBits()` is a power — one declaration, not two.
`grantRole` on a capability bit reverts `NoSuchRole(bit)`, exactly as today's `ROLE_BITS` check does for `PAYABLE` and
`BURNABLE` [V, AdminLib.sol:36, :178]; `holderCount` of a capability is always 0; `setGrant` refuses it the same way.
A capability can be locked (`PAYABLE`, `BURNABLE`, `RESCUABLE` always are [V, :37]) or disabled one-way like any
bit; `ALLOWLIST` is the one capability with a parameter (the pinned registry), set at INIT. `BURNABLE` is therefore
**not** "an admin burns": burning another account's units is a third-party move and needs `MODERATE` with a burn-sink
scope, never `BURNABLE`. For the application band, `bitLabel(bit)` returns the type beside the selector and the name,
derived from the same mask, so a wallet prints "anyone may `<name>`" for a capability and "holders of `<name>`: X, Y
(limits …)" for a power without a second table; `governance_bits.json` carries the type for 0–63.

| Bit | Name | Meaning (same on every contract) | Type | Reduce-only | Contract-only | Today |
|---|---|---|---|---|---|---|
| 0 | `PAYABLE` | anyone may pay through the pay entries | capability (always locked) | — | — | [V] |
| 1 | `MINTABLE` | a holder creates units | power | no | no | [V] |
| 2 | `BURNABLE` | any holder of units destroys its own | capability (always locked) | — | — | [V] |
| 3 | `RATE_ADJUSTABLE` | a holder changes a conversion rate under the rate timelock | power | no | yes | [V] |
| 4 | `WRAP_DISABLEABLE` | a holder closes an inflow, one-way | power | yes | no | [V] |
| 5 | `FREEZE` | a holder stops one account's outflow, bounded in time | power | no | yes | spec, refused |
| 6 | `FORCE` | a holder moves units out of a frozen account to a recorded beneficiary | power | no | yes | spec, refused |
| 7 | `PAUSE` | a holder stops every outflow, bounded in time | power | no | yes | spec, refused |
| 8 | `ALLOWLIST` | every receiver is gated by a registry pinned at INIT | capability (parameter: the registry) | — | — | spec, refused |
| 9 | `MODERATE` | a holder moves units out of any account, no record (§6 D8) | power | no | yes | proposed, reserve now |
| 10 | `RECORD` | a holder writes a compliance record that another power relies on (the `compliance` side of `FORCE`; escalation F6: two rights, two bits) | power | no | yes | proposed |
| 11 | `LISTING` | a holder decides what this instance trades or accepts (DEX `setMarket`, `setExchangeTarget`, `setListedOnly`) | power | no | no | DEX `admin` [V] |
| 12 | `FEE_ROUTING` | a holder decides who receives this instance's fees, never how much (DEX `setFeeSplit`) | power | no | no | DEX `admin` [V] |
| 13 | `DISQUALIFY` | a holder removes a counterparty from a selection, never the last one, with a public reason (tender I4) | power | yes | no | spec |
| 14 | `REVOKE_GRANT` | a holder ends a counterparty's future entitlement early (vesting revoke, offer close) | power | yes | no | spec |
| 15 | `ARBITRATE` | a holder releases held value to one of the parties fixed at creation | power | no | no | templates |
| 16 | `CORRECT` | a holder appends a correction to a record; erase never exists | power | no | no | registries |
| 17 | `RESCUABLE` | anyone may move what this instance does not owe to `rescueTo` (§3 A15/A16) | capability (always locked; parameter: `rescueTo`) | — | — | proposed |
| 18 | `PUBLISH` | a holder adds a release to a catalogue (factory `deployImplementation`) | power | no | no | factory registrar [V]; the factory is deployed and immutable: later |
| 19 | `DEPRECATE` | a holder marks a release unusable for new instances, never undone | power | yes | no | same |
| 20 | `ENABLE_KIND` | a holder turns a catalogue kind on or off | power | no | no | same |
| 21–63 | free | | | | | |

Twenty-two bits allocated after two years of design, twelve of them in one afternoon from the inventory's ≈ 110 rows
collapsing to general names; 42 free. **It suffices** [I]: every named power in gov-inventory, tender, asset-suite and
the DEX maps to one of the above or to the application band, and 128+ is held back precisely so that exhaustion has an
answer other than renumbering. What the table must never do: give a bit a second meaning on one contract (a DEX
`PAUSE` stops settlement, a token `PAUSE` stops outflow — both "stops every outflow of this instance", one sentence).

### 1.5 Attenuation, restated after A5 and the families F3

*The bits of this contract state the worst case of **this contract's own code**; a holder's grant only narrows; a leaf
is at most its grantor.* Inherited powers — a leg's issuer (SCaaS `MODERATE` / `FORCE`, USDC's blacklist, HTS `WIPE`
/ `FREEZE` / `KYC` / `PAUSE` / `FEE_SCHEDULE` / `ADMIN` keys, Token-2022 `PermanentDelegate`, Aptos `TransferRef`) —
are read separately, per leg, and disclosed as "unknown issuer powers" where they cannot be read (Aptos). The §2
disclosure order of v1 gains that step; nothing in code changes for it.

### 1.6 The three examples, run on the base

- **Loan approval in [1 M, 100 M] VND.** `LoanBook is GovernanceBase`; `_validBits()` includes 64 `APPROVE_LOAN`,
  `bitLabel(64) = (approveLoan.selector, "approve a loan")`. Entry: `approveLoan(uint256 loanId)` reads
  `loans[loanId].principal` (the number the contract pays), requires `status == PENDING` and `borrower != sender`
  (preconditions are application state, never grant fields), then `bytes32 branch = use(64, sender, principal)` and
  `require(loans[loanId].branch == branch)`. Grants: the committee is `owner`; `setGrant(64, manager, {min 1e6, max 1e8,
  total = portfolio cap, validUntil, scope = branchId, delegable})`; the manager issues `setGrant(64, officer, {min 1e6,
  max 2e7, …, scope = branchId})`, accepted because it narrows. Two approvers above 50 M: the holder is an msig
  `SmartKeyAccount` or an application rule — not a grant word. `perCall` does not appear: the band is `min`/`max` on
  the principal.
- **Add or remove members only in one's own subtree.** `FamilyTree is GovernanceBase`; 64 `ADD_MEMBER`
  (`addMember(uint64 parent, …)`), 65 `REMOVE_MEMBER` (`removeMember(uint64 id, bytes32 ref)`: a tombstone that
  references the record, reduce-only; erase never exists). `use(64, sender, 0)` returns `scope = bytes32(rootId)`; the
  contract checks `isDescendant(rootId, parent)` with a `MAX_DEPTH` shape constant bounding the walk. The clan's
  `owner` grants the head `{scope = headId, delegable}`; the head grants a son `{scope = sonId}` and the base asks
  `_scopeNarrows(64, headId, sonId) = isDescendant(headId, sonId)`. "Self" is not a set word: the subtree is the scope.
- **Circulation only within a group.** Two honest forms, and the owner picks by where balances live. (i) Custody:
  `GroupLedger is GovernanceBase` holds a plain `NORMAL` token and keeps member balances; 64 `MOVE_WITHIN`
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
| `IGrant` (`grantOf`, `scopeNarrows`, events) | **folded** into `IGovernance`: `grantOf(bit, holder)`, `Granted` / `Revoked` / `Used`, plus `bitLabel`, `validBits` |
| `IRoleEnvelope` holder clone + its catalogue (A3, A14) | **dropped**: a token's bounded minter is a limited holder in the token; nothing self-reports; `OpenFactory` needs no new domain |
| `narrows` at sub-grant, epoch kill at revoke | **kept**, bounded to two levels |
| a contract that does not inherit the base (a Safe, a third-party app, `MandateWallet`, `SmartKeyAccount`) | it can still **hold** a bit on a base contract; its own rules are not readable by this model, so the disclosure says "whole shape, mutable by its own rules" (escalation F15). It may adopt the model by inheriting; there is no second way, and none is needed |

## 2. What moves

### 2.1 Storage

Today `AdminLib.TokenStorage` (`erc7201:scaas.token`) holds `features`, `lockedFeatures`, `owner`, `pendingOwner`,
`creator`, `version`, `kind`, `decimals`, `initialized`, `name`, `symbol`, `roles` [V, AdminLib.sol:48–62]. v2 splits
it:

| Namespace | Keeps | Why |
|---|---|---|
| `erc7201:scaas.token` | `creator`, `version`, `kind`, `decimals`, `initialized`, `name`, `symbol` | identity and metadata of a token; the DEX has its own (`scaas.dex` [V, SCaaSDex.sol:69]) |
| `erc7201:scaas.governance` (new) | `features`, `lockedFeatures`, `owner`, `pendingOwner`, `grantDelay`, `roles` (`uint8`), `holderCount[bit]`, `pending[bit][account] = (eta, proposer)`, `lastProposedAt`, `grants[bit][holder]`, `epoch[bit][holder]` | one slot formula for "features" at every address that inherits the base |

**Yes, the tokens' fields split from `scaas.token`.** The cost is nil: no chain is production (all test-only, 7622
may be reset [memory]), so no migration; a wallet or indexer that read `features` by raw slot (`scaas.token` slot 0)
now reads `scaas.governance` slot 0 — same formula, new seed. `WrappedLib`'s `reserve` (`scaas.underlying`, the slot
the indexer and storage proofs read [V, Layout.t.sol:9]) does not move.

**Layout pins.** `test/v2/layout/<Kind>.json` pins the **linear** layout only (slots 0–4: `_balances` …
`_symbol`; the test asserts slot 5 is zero) [V, Layout.t.sol:17, :54; NormalToken.json]. ERC-7201 roots are not in
the pin, so the files are unchanged by the split — which is exactly the gap: add the namespace roots (`scaas.token`,
`scaas.governance`, `scaas.underlying`, `scaas.ua.ledger`, `scaas.metatx`) as labelled rows to each pin file in the
same commit, so a later move is deliberate. `Features.t.sol::test_adminWritesDoNotTouchOtherNamespaces` [V, :223]
changes with it.

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

### 2.3 Factory, kinds, catalogue, CREATE2, KAT

- **Kind enum:** unchanged by the base. It changes only if the owner takes A17 option (i) (§2.5): two values
  `NORMAL_REGULATED = 8`, `WRAPPED_REGULATED = 9` (6 and 7 are never reused [V, IOpenFactory.sol:12–14]). Reserving
  the two ids now is a comment, 0 B.
- **Catalogue:** `GovernanceLib` replaces `AdminLib` in every kind's and the DEX's `Env.libs` / `libCodeHashes` pin
  [V, OpenFactory.sol `_deploy`], so each domain publishes one new env version. No holder kind, no envelope catalogue,
  no new domain.
- **CREATE2:** an implementation's address is `CREATE2(initcode ‖ abi.encode(v, env, implArgs), salt =
  keccak(kind, version))` [V, OpenFactory.sol:106, :281–294]; new bytecode is a new version by rule, and every clone's
  address is `predictDeterministicAddress(implementation, salt(creator, salt))` [V, :165]. So every token created from
  v2 has a different address from any prediction made against v1 — a non-event on test-only chains; no deployed token
  moves.
- **KAT:** `metatx_kat.json` / `metatransfer_kat.json` derive the domain separator from the test's own clone address
  (`new NormalToken(...)` + `Clones.clone`) [V, TokenKat.t.sol:33–41], not from factory CREATE2, and no signed struct
  changes: the vectors stay byte-identical. `smart_key_account_create2.json` is the account factory's, untouched.
  `hedera_kat.json`, `trade_kat.json`, `dex_order_kat.json` do not touch admin fields. Only a new vector file is
  added: `governance_bits.json` (§1.4).

### 2.4 Bytes and gas per kind [est., nothing measured]

Baseline [V, `size-baseline.json`]: `NormalToken` 37,228, `WrappedToken` 48,015, `NormalZetherToken` 52,741,
`WrappedZetherToken` 62,169, `NormalPqzToken` 52,891, `WrappedPqzToken` 63,423 (1,077 B to the stop line),
`AdminLib` 3,272, `SCaaSDex` 27,957. Levers §2 figures for a stub: ≈ 100–150 B per one-`address` external entry, ≈ 256
B per `mtx` named entry [V, v1 header].

| Item | `GovernanceLib` | each token kind | `WrappedPqzToken` note | `SCaaSDex` |
|---|---|---|---|---|
| move of today's admin ABI into `GovernanceBase` | 0 (rename) | ≈ 0 (the same twelve stubs, moved) | 0 | +1.2–1.6 KB (gains the whole admin surface it lacks today) |
| band refusal (`>= 128`), masks as arguments | +60–120 B | 0 | 0 | 0 |
| two-call `grantDelay` + `pendingGrant` view + `lastProposedAt` | +350–500 B | +150–250 B (config field through `init` decode, one view) | +150–250 B | same |
| `holderCount` | +80–120 B | +60–100 B | +60–100 B | same |
| `Grant` record, `use`, `setGrant`, `grantOf`, `narrows`, epoch | +1.0–1.5 KB | +300–450 B (`setGrant` + `grantOf` stubs; `mint` / `mintToUA` on `use` +≈ 50 B) | **drop first**: flat holding only on this kind (its roles are `RATE_ADJUSTABLE` / `WRAP_DISABLEABLE`, contracts, no scalar); the disclosure says "no grant records on this kind" | same +≈ 0.4 KB |
| `RESCUABLE` + `rescueTo` + `rescue(asset)` (§3 A15/A16) | +≈ 400 B (or `WrappedLib`) | +150–250 B | **second drop** if over the line | +≈ 300 B, only if CTR-DEX-20 does not already pay strays out (§3 A15) |
| sum | ≈ 5.5–6.5 KB (from 3,272) | +0.7–1.1 KB | +0.2–0.6 KB after drops, against 1,077 B | +2.0–2.8 KB → ≈ 30–31 KB |

Gas [est. except where marked]: a **plain transfer rises by 0**: `_update` reads no governance slot today [V,
ERC20MetaTx.sol:307–318] and v2 adds nothing to `_update` or `_uaMove` (§2.5 is the only exception and it is the
owner's call). `mint` on a whole-shape holder: unchanged (same slot, `uint8` instead of `bool`). `mint` on a limited
holder: +4 cold SLOAD + 1–2 SSTORE ≈ +10–15 k. `setGrant`: 4 slots ≈ 90–110 k cold. `init`: +1 SSTORE for
`grantDelay` (packed with `owner` if the struct is ordered for it: 0 extra) [I]. `grantRole` ×2: the propose write +
the confirm write ≈ 2 × 22–44 k.

**What must be measured and how** (owner: ask before timing runs): (1) `scripts/size_gate.py` against
`size-baseline.json` after each of §6's steps 1–3, `WrappedPqzToken` first, and the drop order above applied only on
a measured breach; (2) `test/v2/MetaTxGasV2.t.sol` for `mtxTransfer` / `mtxPay` before and after (the plain-transfer
rule is a test assertion, not a promise: `assertEq(gasAfter, gasBefore)` on the transfer row); (3) `DexGas.t.sol` for
a settle; (4) the `init` delta in `Factory.t.sol`.

### 2.5 The hot path, re-examined (A17)

The rule is binding: a plain transfer's gas must not rise. The base itself keeps it (nothing on `_update`). The breach
is older than the base: once `FREEZE` / `PAUSE` / `ALLOWLIST` are built on the two plain kinds, `_update` **and**
`_uaMove` (which bypasses `_update` [V, ERC20MetaTx.sol:390–407]; the `MODERATE` report's lead) must learn whether this
instance is regulated. Honest accounting of the forms, in gas on a plain `transfer` / `mtxTransfer`:

| Form | Plain-kind transfer | Regulated-instance transfer | Cost elsewhere | Verdict |
|---|---|---|---|---|
| (0) read `features` in `_update` | **+2,100 cold** (+100 if the word is already warm in the tx: the pay entries read `PAYABLE` from it [V, MetaTokenBase.sol:202 ff.], so `mtxPay*` pays +100, `transfer` / `mtxTransfer` pay +2,100 [V by EIP-2929, I on the path]) | same | 0 | breaks the rule on the entry that matters most |
| (i) two implementations, `NORMAL_REGULATED` / `WRAPPED_REGULATED` (kinds 8, 9), same source, the `_update` hook compiled in by one constant | **0** by construction, verifiable by reading | +2,100 (its holders accepted a regulated token) | +2 catalogue rows, +2 artifacts in the size gate and audit; CTR-AS-17's "flags, not kinds" is kept for the *ABI* (the regulated bits are still bits; the plain kind refuses them, the regulated kind requires at least one) | **recommended** |
| (ii) clone-with-immutable-args (the regulated word appended to the proxy's DELEGATECALL calldata, read by `calldataload(calldatasize − 32)`) | +≈ 10–30 [est.] | same | `OpenFactory` switches from OZ `Clones` to an immutable-args clone library: every `predictAddress` formula and clone bytecode changes, `createTokenUnregistered` too; a second clone shape to audit; factory bytecode before the freeze | zero-SLOAD but not zero, and the widest change |
| (iii) pack the regulated word into a slot `_update` already reads (`_totalSupply` high bits) | 0 | 0 | a hack through OZ `ERC20` storage; rejected |

Recommendation: (i). It is the one form that meets the rule by construction rather than by a measurement, and its
cost is two catalogue rows. It contradicts CTR-AS-17's placement, not its ABI, and the owner rules (§6 D3). Until
then nothing is built, and `features` keeps carrying the regulated bits on both forms.

## 3. The attack findings, A1–A21, in v2

| Id | v2 | How |
|---|---|---|
| A1 pending grant survives renounce / transfer | **fixed** | no `executeGrant`, nobody else executes: the **owner calls `grantRole` twice**; `pending[bit][account] = (eta, proposer)`; the confirm requires `caller == owner && caller == proposer`, so a renounced owner (0) and a new owner cannot confirm; a new owner re-proposes. `renounceOwnership` reverts while any `pending` is live? No: a dead pending is harmless once nobody can confirm; the view shows it |
| A2 no expiry, no reader | **fixed** | window `[eta, eta + grantDelay]`, dead after; `pendingGrant` view, `lastProposedAt`; the disclosure warns within `2 × grantDelay`; `holderCount` excludes pendings |
| A3 a holder self-reports a limit | **fixed, dissolved** | limits live in the granting contract's own `grants[bit][holder]`; a wallet never reads a holder's claims. A holder that is itself a base child is a second contract to read, by the same rule, from its own storage |
| A4 a `MODERATE` / `FORCE` SCaaS leg drains a wrapper | **fixed, owner decision D5** | `_addLeg` of every wrapped kind refuses a `factory.isToken` leg whose `features()` has bit 6 or 9 (features only lose bits, so an init check holds) — `WrappedLib` body, 0 token bytes; outside legs cannot be checked and the wording of §1.5 says so |
| A5 `features()` ≠ worst case on wrapped kinds | **fixed by wording** | §1.5: "this contract's own code"; the disclosure recurses on `underlyings()`, registered legs by the same read, others "unknown issuer powers" |
| A6 the owner's first block is not delayed | **fixed by wording** | an owner that is also a holder acts at once (token A is that by design); `revokeRole`, `disableFeature`, `renounceOwnership` are at once; ADAR sentence removed; C1's two-step without delay stands; `acceptOwnership` delay recommended **no** (a stalemate, not recovery) |
| A7 an msig UA cannot be owner / holder | **fixed by statement** | owner, holders and `grantor` are addresses; a derived UA acts through a contract (`SmartKeyAccount`, a Safe, a base child); `UA_POOL` / `SHIELD_POOL` refused as holders in `_grant`; "cannot administer gaslessly" → "cannot administer at all except through a contract" |
| A8 `grantDelay = 0` carve-out for confidential kinds | **fixed** | deleted; `WrappedPqzToken` is excepted only if measured over the stop line, and then per the drop order of §2.4, never by kind |
| A9 revoking the last issuer releases every freeze at once | **not fixed here, routed** | `GovernanceLib` carries one more mask, `_delayedRelaxBits()`, under which `revokeRole` and `disableFeature` take `grantDelay`; the asset-suite stream decides whether 5–7 are in it (it rewrites CTR-AS-03). Default mask 0 = today's behaviour, 0 B until used. Reduce-only is re-labelled "reduces power over holders" |
| A10 the three examples do not run on the holder clone | **fixed** | §1.6: the grant lives in the contract that owns the power, for tokens and applications alike |
| A11 no floor; value ≠ effect | **fixed** | `min` / `max`; the scalar passed to `use` is the number the contract acts on |
| A12 set forms are address predicates; one `setRef`, no mask | **fixed** | one `bytes32 scope`, the contract's predicate; token `MODERATE` scope = `0` (any) or a registry address; `FIXED{a, b}` is a two-member registry; the five set words are gone |
| A13 a registry scope widens after the grant | **fixed by wording** | the disclosure names the registry's controller ("X can change this group at once"); a promise that must not move pins an immutable registry; no membership delay in the token |
| A14 "a new factory kind" cannot exist | **fixed, dissolved** | no holder kind; `TokenKind` changes only for §2.5 (i) |
| A15 DEX rescues to the admin-rewritable `treasury` | **fixed** | `DexConfig.rescueTo`, immutable, `RESCUABLE` set iff non-zero; but first check CTR-DEX-20 (the rescue report says strays at rest already go to any submitter [I, not re-read]): if so the DEX needs no `rescue` entry and only `DexPuller` keeps `rescueTo` |
| A16 the all-leg post-check traps unrelated rescues | **fixed** | foreign asset: every leg's balance unchanged across the call; a leg asset: that leg `balanceOf ≥ reserve` after; ≤ 8 reads; a short leg no longer blocks a foreign rescue |
| A17 +2,100 on a plain transfer | **re-examined, owner decision D3** | §2.5: (i) recommended; the base adds 0 |
| A18 families unmapped | **fixed** | §4, nine rows, NEAR and Algorand separate |
| A19 the holder chain is unspecified | **fixed** | §1.3: two levels, `narrows` + `_scopeNarrows` at grant, parent debit + epoch at use, `uint128` in the contract's own units |
| A20 `holderCount` must count INIT grants and pendings not | **fixed** | counted in `_grant` (the one path, INIT included, idempotent re-grant skipped), decremented in revoke / renounce; pendings excluded |
| A21 `WrappedPqzToken` bytes | **open, measurement** | §2.4 drop order: grant record first (flat-only kind), rescue second, `holderCount` last; measure after §6 steps 1–3 |

The findings the judgment did not see, from the journal:

| Source | v2 |
|---|---|
| escalation F6: `issuer` and `compliance` on one bit, one holder writes the order and executes it | **fixed**: bit 10 `RECORD` is the compliance right; `FORCE` (6) acts on a record written under 10; a contract may hold both only if the asset-suite spec says so (recommend: refused in `_grant` when `hasRole(10)`, 0 B lib) |
| escalation F8 (= A3) | dissolved |
| escalation F9 (= A9) | routed |
| escalation F10 (= A10, confused deputy through a generic holder) | fixed: no generic `execute` anywhere in the model; a base child exposes typed entries only |
| escalation F11: `MODERATE` against `FREEZE` / `FORCE` / `ALLOWLIST`; reaches contract-held balances | **D8**: `moderatedTransfer` passes every regulated check of the instance (frozen `from` refused, `ALLOWLIST` on `to`); refuses a `from` with code (so tender pools, vesting clones, wrapper reserves, AMM pools are unreachable; Safe-held balances too — the product trade-off, stated) |
| escalation F12: renounce with an unbounded surviving holder | **fixed, one rule**: `renounceOwnership` reverts while a holder exists on a bit that is **not locked**; a locked bit's holders survive (the issuer promised the power is permanent, and a wallet reads `lockedFeatures` as exactly that). CTR-TOK-22's "revoke every role, then renounce" becomes enforced for unlocked bits. A surviving limited holder on a locked bit keeps its `Grant`, which the owner can no longer widen |
| escalation F13: budgets add across clones, refresh on rotation | fixed (§1.3, one record per holder, spent carried) |
| escalation F14: non-EVM holder replaced silently or never revoked | §4 |
| escalation F15: contract-only ≠ a Safe; a mutable holder is a replacement without a grant | fixed by wording: contract-only stops a raw EOA; the disclosure says "mutable by its own rules" unless the holder is a base child with `owner() == 0`, whose rules are then readable |
| `MODERATE` F3: `fromSet ANY` reaches tender deposits and clones | D8 (no `from` with code) |
| `MODERATE` F4: derived UAs unreachable; the `bytes32` repair's traps | D8: `moderatedTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref)` on `_uaMove`, refusing 0, `pad(UA_POOL)`, `pad(SHIELD_POOL)`, `pad(this)`, an unregistered or non-SIGNING derived `to`, a native `from` with code; tested: no moderated move changes `balanceOf(UA_POOL) − Σ` |
| `MODERATE` F5: `mtx` / `ua` twins of `moderatedTransfer` are meaningless | D8: one direct entry; the holder is a contract that relays on its own (`MetaTxBase` child or `SmartKeyAccount`), which keeps the "every mtx* write relayable" rule because there is no `mtx*` |
| `MODERATE` F6: bit 9 outside every regulated rule; CTR-TOK-10, README §3, architecture.md:858 become false | D8 lists the amendments: 9 joins CTR-AS-02 disclosure + `termsHash`, contract-only holder, the wizard's underlying refusal (now D5 in bytecode) |
| rescue F2–F4, F6 (alias legs, buffers, rebases, the all-leg check) | A16's per-asset check; the wizard refuses rebasing legs; a leg's surplus is rescuable only where `owed` is exact on chain (unchanged rule) |
| rescue F5: CTR-DEX-20 already sweeps strays | A15 |
| rescue F7, F8: tender `owed`, relay router | tender: rescue only when I2's `owed` is on chain, else foreign assets only; relay router: no rescue (holds nothing by construction, CTR-MTX-27 forbids the entry [I, report]) |
| families F1–F11 | §4 |

## 4. Non-EVM: what `GovernanceBase` becomes

The rule is one everywhere: *a bits word, flat holders, an optional grant, an owner with a two-step transfer and a
renounce, a delay, a lock.* What differs is the container and what the family cannot express. NEAR and Algorand are
separate rows and must stay so. All non-EVM cells rest on the families report's citations [I], not on sources re-read
this session.

| Family | `GovernanceBase` becomes | Owner / holder / grant | Delay, lock | Cannot express |
|---|---|---|---|---|
| **Soroban** | a `governance` Rust module shared by `scaas-token` and the DEX: instance storage `features: u128`, `owner: Option<Address>`, `pending_owner`, roles map `(bit, Address) → u8`, grants map; `require_auth` on the owner | a contract can be any holder (its `__check_auth`); grants as on EVM; sync, atomic | ledger timestamp; lock = the same word. **Gap today:** admin is write-once (families F1), and the Soroban freeze is the same freeze as EVM's (TODO:229) — `set_admin` two-step + `renounce_admin` must land **before it** (§6 D7) | no `isContract`; a holder's code authority is not readable from the token (the contract is immutable as built, so a holder's mutability is the holder's own concern) |
| **Solana** | no SCaaS token; the `scaas` program gets a `Governance` PDA per instance (`features: u128`, owner, pending, roles as PDAs seeded `(instance, bit, holder)`, grants as PDAs). For SPL / Token-2022 mints the model is **display only**: mint authority → `MINTABLE`, freeze authority → `FREEZE`, `PermanentDelegate` → `FORCE` (NET-SOL-09: accepted as issuer risk, owner decision, not a gap) | a policy program's PDA as holder only if its upgrade authority is `None` (escalation F14, families F10); otherwise "whole shape, mutable" | delay: slot or unix timestamp; lock on SPL = authority `None`, one-way | a duration bound on freeze; a record-gated force; `grantDelay` on `SetAuthority` |
| **NEAR** | a `Governance` struct in the contract state (`LookupMap` roles / grants), `predecessor_account_id` as the caller; owner is an `AccountId`; derived UA ids as `Vec<u8>` keys | a contract account as holder; **async**: `use` reserves the budget, the callback settles or releases it, and the view shows `reserved` (families F9) | block timestamp; lock = word. Write-once admin today (F1): `set_admin` / `renounce_admin` in the NEAR UA round, before its add-on audit | a synchronous read of another contract's `features` (a wrapper cannot check a leg at init); a holder account's full-access keys are an inherited power the token cannot see |
| **Algorand** | global state: **two `uint64` words** (`features_lo` bits 0–63, `features_hi` 64–127: Algorand's global uint is 64-bit), owner, pending; roles and grants in boxes keyed `bit ‖ addr`; the holder funds the box MBR by an inner payment in the same group | an app account as holder (`Txn.sender` of an inner call); **atomic**: a failed use fails the group, no reserve state (not NEAR) | round timestamp; lock = word. Write-once admin today (F5): the same two entries in the Algorand UA round | a rekey of the owner or a holder account (silent replacement, F5); `isContract` |
| **Aptos** | a `Governance` resource under the instance object; bits `u128`; roles as a table | the real powers are `MintRef` / `TransferRef` / `BurnRef` values; a resource that holds a Ref **is** the holder, bits are its display. A Ref stored elsewhere is unreadable (families F8) | timestamp; lock = word; object-level rotation is native [I] | the worst case of an FA: **unknowable**; the disclosure says so. `admin_sweep` stays the admin-chosen form to avoid → `rescue_to` fixed at creation |
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
| Zodiac `Allowance` as two storage words with `balance` and `timestamp` sharing one | **taken** (the `Grant` packs `spentInWindow`, `window`, `windowStart` in one word) | the one write on `use` touches one slot |
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

| # | Decision | Recommended answer | Cost |
|---|---|---|---|
| **D1** (freeze) | Split `scaas.token` into `scaas.token` (identity) + `scaas.governance`; `AdminLib` → `GovernanceLib`; the admin ABI into `GovernanceBase` on every kind and on `SCaaSDex` (`admin` → `owner`, `LISTING`, `FEE_ROUTING`); namespace roots added to the layout pins; `IGovernance` replaces `ITokenAdmin` with every name kept | **yes** | tokens ≈ 0 B for the move; DEX +1.2–1.6 KB; one new env version per domain; `Features.t`, `Factory.t`, `Dex.t` admin tests edited; clients rename `admin` → `owner` on the DEX |
| **D2** (freeze) | The `Grant` record in the base: `use(bit, holder, scalar) → scope`, `setGrant`, `grantOf`, two levels, spent carried on edit, `renounceOwnership` refused while an unlocked bit has holders (escalation F12) | **yes** | lib +1.0–1.5 KB, each kind +300–450 B, `WrappedPqzToken` flat-only if it measures over the line; the F12 rule changes CTR-TOK-22's recipe from advice to a revert |
| **D3** (freeze) | A17: how a regulated instance is known on the hot path: (i) `NORMAL_REGULATED` / `WRAPPED_REGULATED` kinds 8 / 9, (ii) immutable-args clones, (0) accept +2,100 | **(i)**; reserve ids 8 / 9 in the enum comment now (0 B), build with flags 5–8 | +2 catalogue rows and artifacts; CTR-AS-17 reworded ("flags on the ABI, two implementations behind them"); (ii) would change every clone address formula and the factory before the freeze |
| **D4** (freeze) | `grantDelay` (`TokenConfig` / `DexConfig`, immutable, 0 allowed) in the two-call form; `pendingGrant`, `lastProposedAt`, `holderCount`; `acceptOwnership` **not** delayed (C1 stands) | **yes**; wizard default 2 days, dev chains 0 | lib +0.4–0.6 KB, each kind +0.2–0.35 KB; `grantRole` tests doubled |
| **D5** (freeze) | `_addLeg` of every wrapped kind refuses a SCaaS leg with bit 6 or 9 (A4); the wizard refuses a `MODERATE` token as a tender / vesting / offer deposit asset | **yes** | `WrappedLib` +≈ 100 B, 0 token bytes; one `isToken` + `features()` STATICCALL per leg at init |
| **D6** (freeze) | `RESCUABLE` (bit 17) + immutable `rescueTo` + `rescue(asset)` with the per-asset check (A16) on the kinds that fit; DEX only if CTR-DEX-20 does not already pay strays out, else `DexPuller` alone; `WrappedPqzToken` last | **yes** | each kind +150–250 B, `WrappedLib` / lib +≈ 400 B; the CTR-DEX-20 check is one read of `dex.md` before building |
| **D7** (Soroban freeze) | `set_admin` (two-step) + `renounce_admin` on the Soroban token and DEX before their freeze; NEAR and Algorand the same two entries in their UA rounds; Sui `AdminCap` gets `store` or a two-step transfer before `make_immutable` | **yes** | small per family; without it every Soroban token is write-once forever (families F1/F2), and the EVM-only delay is the only delay there is |
| **D8** (later, with flags 5–8) | `MODERATE` shape: one direct entry `moderatedTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref)` on `_uaMove` with the §3 refusals; **refuses a native `from` with code**; passes `FREEZE` / `ALLOWLIST`; scope = any or a registry; bit 9 joins CTR-AS-02 disclosure + `termsHash`; CTR-TOK-10, README §3, architecture.md:858 amended | **yes**, including the contract-`from` refusal (Safe-held balances become unreachable by a moderator: the lesser hole) | ≈ 0.6–0.9 KB on `NORMAL` / `WRAPPED` later; three normative sentences rewritten; 0 B now |
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
   Everything in §2.4 is [est.].
2. **`_scopeNarrows` is application code.** Scalars narrow in the base; scope narrows wherever the application says
   it does. A wrong predicate (an `isDescendant` that returns true for a sibling) widens a leaf silently, and the base
   cannot tell. The mitigation is only that it is one `view`, named, auditable, and that a leaf still debits its
   parent's budget whatever the scope says.
3. **The global table's "same meaning everywhere" is carried by names.** `PAUSE` on a token and on a DEX are the same
   sentence; `LISTING`, `DISQUALIFY`, `REVOKE_GRANT` are allocated from specs not re-read this session (tender.md,
   asset-suite.md) [I], and D3's recommendation (i) contradicts CTR-AS-17's placement — the owner may keep flags-only
   and take the +2,100, which the model survives but the rule does not.

Verified by reading [V]: everything cited with a file and line in §1.2, §2.1–2.5 and the "today" column of §1.4; the
EVM facts behind A1–A21 as the attack report verified them. Inferred [I]: every byte and gas figure, the bit
allocation of 10–20, the non-EVM table, the CTR-DEX-20 sweep claim, the A17 estimate for immutable-args clones.
Fetched [F]: §5 only.
