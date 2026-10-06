# Open Asset Suite: regulated module, vesting, asset templates, distributions, corporate actions, managed markets

Status: draft rev 1, 2026-10-06. Component spec **A** of the asset roadmap. Code: none yet (contracts under
`smartcontracts/evm/src` at `scaas` `main` 9737ef3 are the base). Short name **AS**.
Rulings: **R200–R216** (§2). R150–R172 belong to the app spec and R180–R199 to spec B. Owner rulings of 2026-10-06 (six items) are
folded in and marked `(owner)`; everything else is a decision of this spec that amends PLANNED text in `SCaaS.md`.

Amends:

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §4.1, §4.5, §4.6, §4.8, §4.9, §14.6, §14.8, §15.1 row 23: status PLANNED → SPECIFIED with a link (done with this spec). Text updates at stream AS9 (§13): §4.5 rules 3–5 and `courtOrderBurn` (R203–R205), §4.6 vault shape (R209), §4.8 `CouponPayer` (R210), §14.5 `attributes(UA)` proposal withdrawn (R206), §14.6 and §14.8 replaced by §3.3 and §4.2 here, §15.2 q8 answered (R200) |
| TW2 | `2026-10-06-token-wrappers-v2.md` | R142 gets a third creation-time exception (R201); `IOpenFactoryV2.TokenKind` appends three kinds (R200); `MetaTokenBase._checkOp`, `MetaTokenBase.payWithFee` and `SingleUnderlyingToken._checkRecipient` become `internal`/`virtual` overridable (R207; keyword change only, no behaviour change) |
| A2 | `2026-10-06-mesh-gossip-amendment.md` | R124/R128: a `managed` market is home-bound only, not gossiped by default, admin-trusted homes only (R214) |
| DEX | `2026-10-03-dex-design.md` | none in the contract; node intake gains the managed-market checks (§8) |

Inputs: `SCaaS.md` §4 (tokens; §10 tender is separate and untouched), TW2 (R129–R149, storage §10.1, factory §9),
DEX design (RS5-*), A2 R124/R128, research `01-token-factory.md` §1.10–1.11, `02-account-registry.md`,
`09-payment-modes.md` M8/M9/M17/M18, the SRS drafts (architecture §3.5–3.7, §9.6; integration §4.7–4.8; reference
only, never edited), and the code: `metatx/MetaTxCore.sol`, `metatx/MetaTokenBase.sol`, the three tiers,
`factory/OpenFactoryV2.sol`, `registry/UniversalAccountRegistry.sol`, `dex/OrderBookDex.sol`, `dex/MetaTxDex.sol`.

---

## 1. Scope

### 1.1 What this spec adds

```
EVM / Hedera (Solidity), all clones of never-upgraded implementations:

MetaTokenBase v2 tiers (TW2, BUILT)            + RegulatedControls (abstract, ERC-7201 storage, §3)
 ├── NoUnderlyingToken      META_NONE            → RegulatedNoUnderlyingToken      META_NONE_REG   (5)
 ├── SingleUnderlyingToken  META_SINGLE          → RegulatedSingleUnderlyingToken  META_SINGLE_REG (6)
 └── MultiUnderlyingToken   META_MULTI           → RegulatedMultiUnderlyingToken   META_MULTI_REG  (7)
     (+ Hedera children of each regulated tier: HederaRegulated*)

ComplianceRegistry          address-keyed attestations (flags, validUntil); no personal data      (§3.7)
AssetFactory                CREATE2 clones of the three action contracts, counterfactual funding   (§4–§6)
 ├── VestingGrant           one per grant: linear + cliff + interval, or tranches/milestones
 ├── Distribution           one per dividend/coupon: Merkle root over a node-indexed snapshot
 └── ExchangeOffer          one per offer: redemption at maturity, buyback, split/reverse-split exchange
Templates                   equity, bond, loyalty, voucher: off-chain presets over the above        (§7)
Managed markets             OrderBookDex unchanged; node intake + gossip rules                     (§8)
```

### 1.2 Non-goals

- Confidential (Zether) regulated tokens. `SCaaS` §4.5 rule 6 stays as written; no Zether code changes.
- Non-fungible assets (ERC-721/1155); `SCaaS` §4.9 row stays PLANNED.
- Rebasing, scaled balances or balance checkpoints in any token (TW2: balances never rebase; R210, R211).
- On-chain coupon schedules, interest accrual or oracles. Coupons are funded distributions (§5).
- Escrow with an arbiter (research M9) and the sealed-bid tender (`SCaaS` §10): separate specs.
- Gasless wrap (TW2 R149 stays PLANNED).
- Any country-specific rule. Eligibility is expressed as attestation flags whose meaning the issuer defines.
- A new DEX contract. Managed markets are node policy over `OrderBookDex` plus token-level enforcement (R214).

---

## 2. Rulings

Format: **ruling — reason — cost if wrong.**

- **R200** (owner: optional module at creation on any tier) The regulated module is **separate implementations**,
  one per tier, each a child of its TW2 tier plus an abstract `RegulatedControls`; factory kinds are **appended**:
  `META_NONE_REG = 5`, `META_SINGLE_REG = 6`, `META_MULTI_REG = 7` (same underlying-count rules as their base tier).
  Unregulated implementations carry no control code and no runtime flag. The enum change is made to
  `IOpenFactoryV2`/`OpenFactoryV2` **before their first production deployment** (operator step O3; every dev/test
  contract is redeployed anyway, `TODO.md` §0); if a production factory v2 exists by then, the kinds ship in a new
  factory deployment (v2.1), never as an edit of a deployed one. Answers `SCaaS` §15.2 q8 ("factory kind") —
  research §1.10 (the choice must be visible in `versionOf()`, not in a storage flag), and a runtime flag would put
  seizure selectors and one SLOAD per transfer into every permissionless token — if wrong: one more catalogue line
  per tier; wallets read `kind` either way.
- **R201** (owner) **Third exception to R142.** "Nobody alters a deployed token" now has three creation-time,
  visible exceptions: the R135 rate admin, the R136 guardian, and the **regulated module** of a `*_REG` token.
  The module's powers are exactly the bits set in `controls()` (`FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`), fixed at
  creation; `termsHash` (non-zero) commits to the issuer's disclosure document. Disclosure is **mandatory**: the
  wizard refuses to create, and wallets show a blocking notice before a first receive, listing each enabled power,
  both role addresses and the registry. No regulated power can mint, change a rate, touch a reserve or add a power —
  if wrong: holders would have to read code to learn a token can be seized.
- **R202** (owner: issuer + compliance roles) Two roles, set at creation, each **a contract** (`_isContract`, R26
  rule; a multisig with an external seat is recommended, default 3-of-5 as `SCaaS` §4.5 rule 2, which the contract
  cannot prove): `issuer` executes (freeze, unfreeze, forced transfer, pause, unpause); `compliance` records and
  revokes orders. Neither role is transferable (membership changes happen inside the multisig); each can
  `renounce` one-way. `issuer == compliance` is allowed and reported by `rolesSeparated() == false` — if wrong: a
  single compromised multisig could both record and execute (§3.10 A3).
- **R203** (owner: forced transfer only against a recorded order) `compliance` records an **order record**
  `{orderId, documentHash, subject, beneficiary, maxAmount}` (`orderId` = keccak256 of the authority's canonical
  order identifier; `documentHash` = hash of the order document, kept off chain). `issuer` may force-transfer only
  (a) against a live record, (b) **from the recorded subject while it is frozen**, (c) **to the recorded
  beneficiary**, (d) cumulatively ≤ `maxAmount`. There is **no `courtOrderBurn`** (`SCaaS` §4.5/§14.6 amended): a
  burn is a forced transfer to a beneficiary that burns (tier 1) or unwraps (wrapper tiers) itself — if wrong: one
  extra power, one extra audit path, no extra capability.
- **R204** Freeze semantics: a frozen account cannot send (transfer, `transferFrom`, burn, unwrap), cannot be the
  `from` of any meta-tx op, cannot receive a relayer fee (owner), and cannot be the recipient of an unwrap (the
  underlying is liquid value outside the freeze). It **can** receive this token (credits are never refused because
  of a freeze, so payers and distributions never lose funds through it). Every freeze/unfreeze carries a non-zero
  `ref`; there is no time limit (an order may be open-ended) — if wrong: blocking credits is one comparison more and
  bounces payments to frozen merchants.
- **R205** (owner: global pause, bounded) `pause(ref, until)`: `until ≤ now + 7 days`, no extension while paused,
  and a **cooldown of 7 days** after any pause ends before the next may start (at most half of any period paused).
  Paused: transfers, `transferFrom`, mints, wraps and every meta-tx op except unwrap revert. **Never paused:**
  unwrap (direct and R148 op), holder burn, forced transfer. Replaces `SCaaS` §4.5 rule 5's "reopen redeem
  automatically" with "exits never close" — if wrong: back-to-back pauses would be an indefinite freeze of everyone.
- **R206** Allowlist through a new **`ComplianceRegistry`** (address → `{uint64 flags, uint64 validUntil}`; an
  immutable `admin` contract manages attesters; attesters set flags; no personal data). The UA registry is **not**
  extended: it is a Zether key registry with no admin by design and dev-chain only (RS2-1); the `SCaaS` §14.5
  `attributes(UA)` proposal is withdrawn and its flag bits are reused (§3.7). A regulated token pins one registry and
  one `requiredFlags` mask at creation. **Only receivers are checked** (`to` of a transfer or mint, fee recipient,
  unwrap recipient): a holder whose attestation lapsed can still exit to an eligible party — if wrong: a
  sender-side check would trap holders when an attester is slow.
- **R207** (owner: interaction with meta-tx) Checks run at **step 6** through an override of `_checkOp` (TW2 §3.2;
  `MetaTokenBase._checkOp` gains `virtual`), so a failing intent costs the relayer only the cheap prefix; the same
  rules are enforced again in an `_update` override for every direct path. A frozen `from` reverts every op,
  including `approve`; a frozen or ineligible resolved fee recipient reverts (also on `payWithFee`, which gains
  `virtual`). R26 (EOA approve lockdown) is unchanged and orthogonal: the regulated check binds the parties, not
  the spender. Regulated templates default to `MODE_FEE_NONE` (sponsored), because a fee-earning relayer would
  itself need an attestation — if wrong: failures surface at step 7/8 at full gas.
- **R208** (owner: Multi reserves/unwrap) No regulated power touches `reserve_i`, rates or legs; forced transfer
  moves wrapped units only, so `collateralValue() ≥ totalSupply()` is untouched. A frozen holder **cannot unwrap**
  (it would convert frozen units into unfrozen underlying); the beneficiary of a forced transfer can. Unwrap is
  open during a pause (R205). Guardian and rate admin keep exactly their TW2 powers — if wrong: a seizure could
  drain a leg other holders rely on.
- **R209** (owner: vesting) **One EIP-1167 clone per grant** (`VestingGrant`), not a vault. Funding is
  **counterfactual**: the clone address is `CREATE2(keccak256(abi.encode(params)))`, the grantor funds it with an
  ordinary (gasless) transfer or `pay` op, then anyone deploys it; init reverts unless the balance covers `total`.
  Schedules: linear with cliff and optional step `interval`, or ≤ 16 tranches, optionally gated per tranche by an
  `approver` (milestones). Revocable option (grantor reclaims the unvested part, pull-style). Claim is a
  permissionless `release()` that pays only the beneficiary: gasless through any relayer, no signature, no nonce.
  Supersedes the `SCaaS` §4.6 `VestingVault` shape — per-grant isolation makes freeze and forced transfer of a
  regulated grant address-exact (a vault would hold everyone's grants at one address), needs no allowance, and costs
  ≈ 45 k gas more per grant once (§4.7) — if wrong: payroll-scale streams cost ~25 % more to create.
- **R210** (owner: distributions) **Merkle distribution off a node-indexed snapshot**, no balance checkpoints in
  tokens. One clone per distribution (`Distribution`), counterfactual funding as R209, a review window before
  `claimStart` in which `admin` may cancel, permissionless claims that pay only the leaf's account, and `sweep()` of
  the remainder to `sweepTo` after `expiry` (or never). The snapshot is deterministic (§5.4) and recomputable by
  anyone from finalized `Transfer` events. Supersedes the `SCaaS` §4.8 `CouponPayer` — checkpoints would add ≈ 2
  SSTOREs to every transfer of every holder for an event that happens a few times a year — if wrong: a wrong root
  can be published; the review window, independent recomputation and `cancel` bound it.
- **R211** (owner: corporate actions; TW2 "balances never rebase") Split and reverse split are a **migration to a
  new token** through an `ExchangeOffer` (old in, new out at `num/den`). A scaled view is rejected: every
  integrator (DEX limits, vesting totals, Merkle leaves, allowances, ERP books) holds raw amounts, and a view would
  make the same raw number mean two quantities. Bond redemption at maturity and buybacks are `ExchangeOffer`s too
  (§6); a buyback at market is a DEX bid — if wrong: a split needs every holder to act once (gasless); dust stays in
  the old token, buyable by a cash offer.
- **R212** `ExchangeOffer` is gasless through a `trade` op leg exactly as `MetaTxDex` (relayer = to = the offer,
  restricted; measured delta), plus a direct `transferFrom` path for holders who pay gas. Exact multiples only
  (`in·num % den == 0`, else `NotExactMultiple`), so no holder silently loses dust — if wrong: rounding dust goes to
  the issuer instead of being refused.
- **R213** (owner: templates) Templates are **off-chain presets** (versioned JSON in the SDK and wizard) that map to
  one `createTiered` call plus optional action contracts; there is no on-chain preset factory. Defaults in §7 — if
  wrong: a preset contract would freeze defaults that issuers must be able to change.
- **R214** (owner: managed markets, R124/R128) A **managed market** is a market on an `OrderBookDex` instance whose
  `admin` is the licensed venue operator's multisig and whose node policy has `managed = 1`: **home-bound only**
  (relayer-unbound orders are refused at intake and never signed by our wallets), node intake checks eligibility of
  both parties on every regulated leg, the book is **not gossiped by default**, and when gossip is enabled only
  admin pre-trusted homes are listed (R128 automatic trust is disabled for managed markets). On chain the regulated
  token is the arbiter (its receiver checks run inside `transferFrom`), so a pair with an ineligible party fails
  (`MatchFailed`) whoever settles it — if wrong: unbound orders would let unlicensed parties execute regulated
  trades, which the venue cannot be accountable for.
- **R215** Families: **EVM and Hedera** in this spec (same Solidity; Hedera children add HIP-632 only). Cosmos,
  Soroban, Move, TON and Solana are PLANNED per family spec after their v2 wrapper work (TW2 R145), mapping the same
  rulings onto native mechanisms (§10) — if wrong: nothing to undo; those families keep tier-1 tokens.
- **R216** Order of exits and powers, stated once for every action contract: grants, distributions and offers have
  **no owner and no upgrade**; their only privileged calls are `revoke`/`renounceRevocation` (grantor, if chosen),
  `approveMilestone` (approver, if chosen), `cancel` before `claimStart` (distribution admin), `close` (offer admin,
  only if `closable`). Remainders always go to a creation-time `sweepTo`/grantor, never to the caller — if wrong:
  a permissionless sweep could redirect funds.

---

## 3. Regulated module

### 3.1 Shape

- `abstract contract RegulatedControls` holds the controls, roles, order records, frozen set and pause state in an
  ERC-7201 namespace (`keccak256(abi.encode(uint256(keccak256("scaas.regulated.v1")) - 1)) & ~0xff`), so the TW2
  slot pins (slots 0–15) of every tier stay valid. It has no base contract; it declares the hooks it needs
  (`_forceMove(from, to, amount)`, `_isContract(a)`) and the tier child implements them.
- `RegulatedNoUnderlyingToken is NoUnderlyingToken, RegulatedControls` (and the Single/Multi equivalents) contain
  only glue: `tokenKind()`, `_init` (tier init + `RegulatedConfig`), and overrides of `_update`, `_checkOp`,
  `payWithFee`, `_checkRecipient`. `_forceMove` calls `ERC20._update` directly (bypassing the overrides).
- Hedera: `HederaRegulated*` add the 4-line `_requireValidSignature` override through `HederaV2Lib` (TW2 I3) and
  inherit the fail-closed HTS checks (R144).
- Size: `forge build --sizes` ≤ 24 576 for each of the six; if a Multi child exceeds it, the external control
  functions move into a linked library (clone → implementation → library `DELEGATECALL` keeps clone storage, TW2
  §10.3).

Keyword changes to built TW2 code (R207; no behaviour change, gas table and layout pins must stay identical — a
test): `MetaTokenBase._checkOp` `internal view override` → `internal view virtual override`; `MetaTokenBase.payWithFee`
gains `virtual`; `SingleUnderlyingToken._checkRecipient` `private` → `internal view virtual` (the one choke point of
direct unwrap, Multi unwrap and the R148 op).

### 3.2 Configuration and init

`initData = abi.encode(<the tier's TW2 fields…>, RegulatedConfig cfg)`: the tier fields decode as today (ABI
decoding ignores the extra trailing head word; a test pins this), the child decodes the full tuple.

```solidity
struct RegulatedConfig {
    address issuer;        // enforcement role (contract)
    address compliance;    // order role (contract)
    address registry;      // IComplianceRegistry; ≠ 0 iff CTRL_ALLOWLIST
    uint64  requiredFlags; // receivers must hold all of these; ≠ 0 iff CTRL_ALLOWLIST
    uint8   controls;      // CTRL_FREEZE 1 | CTRL_FORCE 2 | CTRL_PAUSE 4 | CTRL_ALLOWLIST 8; ≠ 0; FORCE ⇒ FREEZE
    bytes32 termsHash;     // hash of the issuer's terms/disclosure document; ≠ 0
}
```

| Init check | Error |
|---|---|
| `controls ≠ 0`, no unknown bit, `FORCE ⇒ FREEZE` (R203 needs a frozen subject) | `RegulatedConfigInvalid()` |
| `issuer`, `compliance` have code (`_isContract`; 7702 designators are EOAs) | `RoleNotContract(a)` |
| `ALLOWLIST` ⇔ `registry ≠ 0 && requiredFlags ≠ 0`; registry has code | `RegulatedConfigInvalid()` |
| `termsHash ≠ 0` | `RegulatedConfigInvalid()` |
| tier-1 `initialSupply` recipient (`creator`) passes the receiver check | `NotEligible(creator, reason)` |

Storage (namespace): **hot slot** `registry (20) ‖ controls u8 ‖ pausedUntil u64` (29 bytes, read on every transfer);
cold slot `requiredFlags u64 ‖ cooldownUntil u64`; `issuer`; `compliance`; `termsHash`; `mapping(address ⇒ bool)
frozen`; `mapping(bytes32 ⇒ OrderRecord) orders`.

### 3.3 Interface (replaces the `SCaaS` §14.6 proposal)

```solidity
interface IRegulatedToken {
    struct OrderRecord {
        bytes32 orderId; bytes32 documentHash; address subject; address beneficiary;
        uint256 maxAmount; uint256 executed; uint64 recordedAt; bool revoked;
    }
    // recordId = keccak256(abi.encode(orderId, subject, beneficiary))
    event OrderRecorded(bytes32 indexed recordId, bytes32 indexed orderId, address indexed subject,
                        address beneficiary, uint256 maxAmount, bytes32 documentHash);
    event OrderRevoked(bytes32 indexed recordId, bytes32 reasonRef);
    event AccountFrozen(address indexed account, bytes32 indexed ref, address indexed issuer);
    event AccountUnfrozen(address indexed account, bytes32 indexed ref, address indexed issuer);
    event ForcedTransfer(bytes32 indexed recordId, address indexed from, address indexed to, uint256 amount);
    event Paused(bytes32 indexed ref, uint64 until);
    event Unpaused(bytes32 indexed ref);
    event RoleRenounced(uint8 role);                              // 1 issuer, 2 compliance

    error Frozen(address account);
    error TokenPaused(uint64 until);
    error NotEligible(address account, uint8 reason);             // 1 no attestation/flags, 2 expired
    error FeeRecipientFrozen(address account);
    error NotIssuer(); error NotCompliance(); error ControlDisabled(uint8 control);
    error RefRequired(); error RoleNotContract(address a); error RegulatedConfigInvalid();
    error OrderExists(bytes32 recordId); error OrderUnknown(bytes32 recordId); error OrderInactive(bytes32 recordId);
    error SubjectNotFrozen(address subject); error OrderExceeded(uint256 remaining);
    error PauseTooLong(uint64 until); error PauseCooldown(uint64 until); error AlreadyPaused(uint64 until);
    error AlreadyFrozen(address a); error NotFrozen(address a);

    // views (free, for wallets, venues and indexers)
    function controls() external view returns (uint8);
    function issuer() external view returns (address);
    function compliance() external view returns (address);
    function rolesSeparated() external view returns (bool);
    function registry() external view returns (address);
    function requiredFlags() external view returns (uint64);
    function termsHash() external view returns (bytes32);
    function isFrozen(address account) external view returns (bool);
    function pausedUntil() external view returns (uint64);       // 0 or ≤ now ⇒ not paused
    function pauseCooldownUntil() external view returns (uint64);
    function canReceive(address account) external view returns (bool ok, uint8 reason);
    function checkTransfer(address from, address to, uint256 amount) external view returns (bool ok, uint8 reason);
    function order(bytes32 recordId) external view returns (OrderRecord memory);

    // compliance role
    function recordOrder(bytes32 orderId, bytes32 documentHash, address subject, address beneficiary,
                         uint256 maxAmount) external returns (bytes32 recordId);
    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;
    // issuer role
    function freeze(address account, bytes32 ref) external;
    function unfreeze(address account, bytes32 ref) external;
    function forceTransfer(bytes32 recordId, uint256 amount) external;
    function pause(bytes32 ref, uint64 until) external;
    function unpause(bytes32 ref) external;
    // either role, for itself, one-way
    function renounceRole() external;
}
```

`checkTransfer` reason codes (one table for node, venue and wallet): `0` ok, `1` receiver not attested,
`2` receiver attestation expired, `3` sender frozen, `4` paused, `5` balance too low. Reason `3`/`4` revert with
`Frozen`/`TokenPaused` in state-changing paths, `1`/`2` with `NotEligible`.

### 3.4 Semantics per path

`R` = receiver check (`canReceive`: `ALLOWLIST` off ⇒ true; else `registry.hasFlags(a, requiredFlags)` or the
`ELIGIBLE_CONTRACT` flag, §3.7). `F(a)` = `a` frozen. `P` = paused.

| Path | Reverts when |
|---|---|
| `transfer`, `transferFrom` (incl. DEX settle), meta-tx transfer / `pay` / `trade` | `P`; `F(from)`; `!R(to)` |
| meta-tx `approve` op | `P`; `F(from)` (direct `approve` is unrestricted: a frozen account's allowance cannot be spent, `transferFrom` checks `F(from)`) |
| relayer fee (meta-tx step 7, `payWithFee`) | `F(feeRecipient)` ⇒ `FeeRecipientFrozen`; `!R(feeRecipient)` |
| mint (tier-1 `minter`, wrap) | `P`; `!R(to)` |
| holder `burn` (tier 1) | `F(from)` (not `P`) |
| unwrap (direct, Multi, R148 op) | `F(from)`; `F(recipient)`; `!R(recipient)` (not `P`) |
| `forceTransfer` | §3.5 only (not `P`, not `F(from)`) |
| `addReserve` (wrapper tiers) | unchanged (no mint, no regulated check) |

Step-6 placement (R207): the `_checkOp` override computes the resolved fee recipient and fee amount exactly as step 6
does (`m.feeRecipient == 0 ? msg.sender : m.feeRecipient`, `FeePolicy.compute`), applies the table above for the op
in `m.data`, then calls `super._checkOp(m)`. The `_update` override re-applies the transfer/mint/burn rows for direct
paths; on the meta-tx path its reads are warm.

### 3.5 Order records and forced transfer

```
compliance: recordOrder(orderId, docHash, subject, beneficiary, maxAmount)     // OrderRecorded
            orderId ≠ 0, docHash ≠ 0, subject ≠ beneficiary, both ≠ 0, maxAmount > 0, recordId unused
issuer:     freeze(subject, ref)                                               // AccountFrozen (may precede the record)
issuer:     forceTransfer(recordId, amount)
              CTRL_FORCE; record exists (OrderUnknown), not revoked (OrderInactive)
              F(subject) (SubjectNotFrozen); executed + amount ≤ maxAmount (OrderExceeded)
              !F(beneficiary), R(beneficiary); amount ≤ balanceOf(subject)
              executed += amount; _forceMove(subject, beneficiary, amount)    // ForcedTransfer + Transfer
issuer:     unfreeze(subject, ref)                                             // separately, when the order says so
compliance: revokeOrder(recordId, reasonRef)                                   // stops further execution
```

- An amended order is a new `orderId` (new record); a record is never edited.
- One order against several accounts = several records. `maxAmount = type(uint256).max` means "everything",
  stated in the event.
- Seizing a wrapper's backing means: force-transfer wrapped units to a beneficiary, which unwraps (R208). Seizing to
  destroy means a beneficiary that burns (tier 1) or unwraps and destroys off chain (R203).
- Contract holders are subjects like any other: a `VestingGrant`, `Distribution` or `ExchangeOffer` clone can be
  frozen and force-transferred from exactly (R209).

### 3.6 Pause

```
pause(ref, until)   issuer; CTRL_PAUSE; ref ≠ 0; now < until ≤ now + 7 days (PauseTooLong);
                    not paused (AlreadyPaused); now ≥ cooldownUntil (PauseCooldown)
                    pausedUntil = until; cooldownUntil = until + 7 days; Paused(ref, until)
unpause(ref)        issuer; paused; pausedUntil = now; cooldownUntil = now + 7 days; Unpaused(ref)
```

Expiry is passive (`pausedUntil ≤ now` ⇒ not paused; no transaction needed). Integrators read `pausedUntil()` (the
research §1.10.2 requirement for DEX/collateral bots).

### 3.7 `ComplianceRegistry`

```solidity
interface IComplianceRegistry {
    event AttesterSet(address indexed attester, bool enabled);
    event Attested(address indexed account, uint64 flags, uint64 validUntil, address indexed attester);
    error NotAdmin(); error NotAttester(); error AdminNotContract(address a); error LengthMismatch();

    function admin() external view returns (address);             // immutable, a contract
    function isAttester(address a) external view returns (bool);
    function setAttester(address attester, bool enabled) external; // admin
    function attest(address[] calldata accounts, uint64[] calldata flags, uint64[] calldata validUntil) external;
                                                                    // attester or admin; flags 0 = revoke
    function attestationOf(address account) external view returns (uint64 flags, uint64 validUntil); // one slot
    function hasFlags(address account, uint64 required) external view returns (bool);
        // (flags & required) == required && validUntil ≥ now, or (flags & ELIGIBLE_CONTRACT) != 0 && validUntil ≥ now
}
```

Flag bits (reused from the withdrawn `SCaaS` §14.5 proposal; meaning set by the issuer's policy, market-neutral):
`KYC_DONE = 1`, `ACCREDITED = 2`, `SANCTIONS_CLEAR = 4`, `ELIGIBLE_CONTRACT = 8` (a contract that holds on behalf of
eligible parties: grants, distributions, offers, escrow Safes, venue fee recipients); bits 16–63 issuer-defined
(investor classes, holding categories). One registry may serve many tokens; anyone may deploy one (plain deployment,
no factory). The registry holds no personal data: the ERP is the system of record for identity evidence and pushes
only flags (§9.2).

### 3.8 Interactions

| With | Rule |
|---|---|
| Meta-tx pipeline | §3.4 at step 6; step order, digest, typehash, nonces, named functions and `mtxBatch` unchanged; a batch item that fails a regulated check reverts the batch (TW2 R140), so the node never batches regulated items whose parties it has not re-checked |
| Node simulation and grief score | a post-simulation revert with `Frozen`, `TokenPaused`, `NotEligible` or `FeeRecipientFrozen` caused by an authority or attester transaction landing first is **exempt** from the origin's grief score (A2 / TW2 §7.6 class "not signer-caused"); the node refuses at intake intents whose `validUntil` exceeds the receiver's attestation `validUntil` |
| R26 lockdown | unchanged: spenders are contracts; `transferFrom` callers are contracts; the regulated check binds `from`/`to`, so an allowance to any contract cannot move tokens to an ineligible party |
| Single/Multi wrappers | R208; `wrap` is a mint (paused ⇒ refused; receiver check on `msg.sender`); the guardian's `disableWrap` and the rate timelock are unchanged; a pending rate change and a pause can overlap; unwrap stays open in both |
| `OrderBookDex` | settle's `transferFrom` runs the regulated check per leg; a failing leg fails only its pair (`MatchFailed`, RS5); `checkOrder` does not see freezes or eligibility, so the venue adds `checkTransfer` (§8.2); market fee recipients on a regulated leg need `R` |
| `MandateWallet` | it calls `payWithFee`; the wallet address is the `from` and must not be frozen; payees need `R` |
| Vesting / distribution / offer clones | holders like any other; attest them `ELIGIBLE_CONTRACT` before funding (the address is known in advance, R209) |
| Zether | none (non-goal) |

### 3.9 Disclosure (mandatory, R201)

The wizard, the app and wallets show, before creation or a first receive: kind (`*_REG`), each enabled control in
plain words, `issuer`, `compliance`, `rolesSeparated()`, the registry and `requiredFlags`, `termsHash` with a link to
the document, and the standing statements: *"The issuer can freeze any account. With a recorded order it can move
tokens out of a frozen account to the beneficiary named in the order. It can pause transfers for up to 7 days at a
time, never redemptions. It cannot mint outside the minter rules, change rates beyond the rate rules, or touch the
reserve."* Wallets mark accounts with a pending `OrderRecorded` naming them.

### 3.10 Security analysis

Invariants (each an invariant test, §3.12):

- I1 `Σ balances == totalSupply` (forced transfer is a move); wrapper tiers keep TW2's `collateralValue() ≥
  totalSupply()` and per-leg conservation across every regulated call.
- I2 Every `ForcedTransfer` has a live record, a subject frozen at execution, `to == beneficiary`, and cumulative
  `executed ≤ maxAmount`.
- I3 No balance of a frozen account decreases except by `ForcedTransfer`.
- I4 While paused, no transfer, mint or meta-tx op other than unwrap succeeds; unwrap and burn always do (absent
  freeze and TW2 limits); no two pauses are closer than 7 days; no pause exceeds 7 days.
- I5 Every receiver of a balance increase (except forced-transfer beneficiaries, which are checked too) passed `R`
  at that block, when `ALLOWLIST` is on.
- I6 No regulated call changes `reserve_i`, `num_i/den_i`, `wrapEnabled_i`, `minter` or `controls()`.

| # | Abuse | Outcome |
|---|---|---|
| A1 | Compromised `issuer` alone | freezes anyone, pauses ≤ 7 of every 14 days; **cannot move funds** without a compliance record. Visible: every call emits |
| A2 | Compromised `compliance` alone | records fake orders; cannot execute. Node/ERP alert on every `OrderRecorded` |
| A3 | Both compromised, or `issuer == compliance` | full seizure of frozen accounts up to recorded amounts: the nature of a regulated token. Mitigation: separate multisigs with an external seat, alerts, `rolesSeparated()` disclosed |
| A4 | Subject front-runs a freeze | moves funds first. Mitigation: issuer submits freezes privately (as the TW2 guardian, §8.4); on private chains moot |
| A5 | Replay / over-execution of an order | cumulative `executed ≤ maxAmount`; records are immutable; revocation stops it |
| A6 | Wrong beneficiary | impossible without a new record by `compliance` |
| A7 | Registry admin compromised | attests anyone: allowlist bypass, no fund movement. Disclosed; registry pinned at creation |
| A8 | Attestation lapse | receivers fail; holders still exit to eligible parties (R206); the node refuses intents that outlive the receiver's attestation |
| A9 | Fee griefing with a frozen/ineligible fee recipient | fails at step 6 (cheap) |
| A10 | Unwrap to a frozen accomplice | `F(recipient)` refused (R204) |
| A11 | Rolling pauses | bounded by the cooldown; exits stay open for wrappers; tier-1 regulated tokens are disclosed as pausable 50 % |
| A12 | Frozen holder escapes via DEX | `transferFrom` checks `F(from)`; the pair fails; the venue drops the maker's orders on `AccountFrozen` |
| A13 | Forced transfer from a protocol clone (grant/distribution/offer) | address-exact; affects only that clone (R209), disclosed |

### 3.11 Gas (estimates; measured numbers replace them in `test/as/RegulatedGas.t.sol`)

Per transfer on top of the TW2 row: hot-slot SLOAD (2 100 cold) + `frozen[from]` (2 100 cold) ≈ **+4.3 k** without
allowlist; with allowlist + registry call (cold account 2 600 + cold slot 2 100 + call overhead ≈ 5.5 k) per checked
receiver ≈ **+10 k**; a meta-tx with a fee checks two receivers ≈ +15 k. On the meta-tx path the `_update` re-check
is warm (≈ +0.5 k). Unregulated kinds: **0** (R200). Control functions are rare: `recordOrder` ≈ 140 k (5 new slots),
`forceTransfer` ≈ 60 k, `freeze` ≈ 27 k.

### 3.12 Tests (`test/as/`)

| Area | Tests |
|---|---|
| Init | every refusal of §3.2; EOA and 7702 roles refused; `FORCE` without `FREEZE`; tier fields decode unchanged with the trailing config; `termsHash = 0` |
| Paths | each row of §3.4 on all three tiers, direct and meta-tx (generic, named, `mtxBatch`), at step 6 (gas of a refused intent < 40 k) |
| Orders | record/revoke/execute; `SubjectNotFrozen`; `OrderExceeded` at the exact edge; beneficiary frozen/ineligible; record immutability; same `orderId` with two subjects |
| Pause | 7-day bound, no extension, cooldown from actual end (unpause early), passive expiry, unwrap and burn during pause, forced transfer during pause |
| Wrappers | frozen holder unwrap refused (direct, Multi, R148 op); unwrap to frozen recipient refused; reserves untouched by every regulated call; guardian/rate flows unchanged |
| DEX | `OrderBookDex.settle` with a frozen maker, an ineligible taker, an ineligible market fee recipient: only that pair fails |
| Keywords | TW2 v2 gas table and layout pins identical after the `virtual` changes |
| Registry | admin contract only; attester add/remove; batch attest; revoke by flags 0; expiry; `ELIGIBLE_CONTRACT` |
| Hedera | each `HederaRegulated*` signs via HIP-632; HTS fail-closed checks unchanged |
| Invariant | handlers: transfers, meta-tx with fees, wraps/unwraps, freezes, records, forced transfers, pauses with `warp`, attestation expiry; invariants I1–I6 |

---

## 4. Vesting and streaming (R209)

### 4.1 Roles and flow

`grantor` (funds, may revoke if `revocable`), `beneficiary` (receives; should be a `SubjectAccount` so a lost key is
recoverable, `SCaaS` §9.4), `approver` (optional, milestones only), relayer (submits anything; earns nothing on
chain).

```
1. client builds GrantParams p; grant = AssetFactory.predictGrant(p)
2. grantor signs a gasless transfer (or pay op with entryRef = grant id) of p.total to `grant`; relayer submits
   (regulated token: attest `grant` ELIGIBLE_CONTRACT first)
3. anyone: AssetFactory.createGrant(p) → clone at `grant`, initialize(p): Underfunded unless balanceOf ≥ total
4. over time: anyone calls release() → pays releasable() to beneficiary
5. milestones: approver calls approveMilestone(i, ref), or anyone submits approveMilestoneWithSig(i, ref, sig)
6. optional: grantor revoke() → unvested part to grantor; vested part stays releasable
```

### 4.2 Interface (replaces the `SCaaS` §14.8 proposal)

```solidity
interface IVestingGrant {
    struct Tranche { uint64 at; uint192 amount; }
    struct GrantParams {
        address token; address grantor; address beneficiary; uint256 total;
        uint64 start; uint64 cliff; uint64 end; uint32 interval;   // linear; all zero when tranches are used
        Tranche[] tranches;                                         // ≤ 16, strictly increasing `at`, Σ amount == total
        address approver;                                           // tranches only; 0 ⇒ time-only tranches
        bool revocable;
        bytes32 ref;                                                // grant id in the ERP (salt and reconciliation)
    }
    event Released(uint256 amount, uint256 releasedTotal);
    event Revoked(uint256 vestedAtRevoke, uint256 returned);
    event RevocationRenounced();
    event MilestoneApproved(uint8 indexed index, bytes32 ref, address indexed approver);
    event ExcessSwept(uint256 amount);
    error Underfunded(uint256 balance, uint256 total); error ScheduleInvalid(); error NotGrantor();
    error NotRevocable(); error AlreadyRevoked(); error NotApprover(); error BadApproval(); error NothingToRelease();

    function release() external returns (uint256 amount);                              // anyone
    function revoke() external;                                                         // grantor, if revocable
    function renounceRevocation() external;                                             // grantor, one-way
    function approveMilestone(uint8 index, bytes32 ref) external;                       // approver
    function approveMilestoneWithSig(uint8 index, bytes32 ref, bytes calldata sig) external; // anyone submits
    function sweepExcess() external returns (uint256);                                  // anyone; pays grantor
    function vestedAmount(uint64 at) external view returns (uint256);
    function releasable() external view returns (uint256);
    function params() external view returns (GrantParams memory);
    function released() external view returns (uint256);
}
```

### 4.3 Schedule math

Linear (`tranches` empty): `start ≤ cliff ≤ end`, `start < end`, `interval ≤ end − start`.

```
vested(t) = 0                                   if t < cliff
          = total                               if t ≥ end
          = mulDiv(total, e, end − start)       otherwise, e = interval == 0 ? t − start
                                                                   : ⌊(t − start)/interval⌋ · interval
```

Tranches: `vested(t) = Σ amount_i` over tranches with `at_i ≤ t` and (no approver or approved_i). "Fixed periods"
are tranches without an approver, "milestones" tranches with one (`at` = earliest date, may be 0). After `revoke()`,
`vested(t) = vestedAtRevoke` for all `t`. `releasable() = vested(now) − released`.

### 4.4 Revocation, approval, excess

- `revoke()`: `cap = vested(now)`; returns `total − cap` to `grantor`; the vested remainder stays releasable
  (pull-style, so a frozen or contract beneficiary cannot block a revocation). Unapproved milestones are unvested.
- `renounceRevocation()`: one-way; turns a revocable grant into an irrevocable one (e.g. after a change of control).
- `approveMilestone`: approver only, one-way, idempotent error on repeat (`BadApproval`). `approveMilestoneWithSig`:
  EIP-712 domain `("SCaaS VestingGrant", "1", chainId, grant)`, type `ApproveMilestone(uint8 index,bytes32 ref)`,
  ECDSA low-s or ERC-1271 (code check as `MetaTxCore._isContract`). No nonce and no expiry: the act is one-way and a
  replay is a no-op (as RS5-10 cancels). This is the gasless path for an approving agent's key.
- `sweepExcess()`: pays the grantor `balance − (cap_or_total − released)`; recovers over-funding and stray transfers.
  Never touches the obligation.

### 4.5 Meta-tx, node, ERP, app

- No new typehash on tokens. Funding uses existing gasless transfer/`pay` (an `entryRef` = `p.ref` lets the ERP
  reconcile the funding as a normal payment, R9). `release()`, `createGrant`, `approveMilestoneWithSig` are
  unsigned-by-subject `call` jobs (NI job API) sponsored by the relayer.
- Node: normaliser events `GrantCreated`, `Released`, `Revoked`, `RevocationRenounced`, `MilestoneApproved`,
  `ExcessSwept`; optional policy "release every N days" is an ERP-pushed `call` job, not node logic.
- ERP: grant register (beneficiary, schedule, vested/released mirrors), funding as a payment, revocation as a
  journal reversal of the unvested part.
- App: beneficiary page (schedule chart, releasable, release button that posts a sponsored job), grantor page.

### 4.6 Security

Invariants: `released ≤ vested(now) ≤ total` (or `≤ vestedAtRevoke`); `token.balanceOf(grant) ≥ obligation − released`
for a well-behaved token; only the beneficiary receives `release`; only the grantor receives `revoke`/`sweepExcess`;
`vested` is monotone in `t`.

| Abuse | Outcome |
|---|---|
| Someone deploys a different grant at the funded address | impossible: the address commits to every parameter (CREATE2 salt = hash of `p`; init code is the fixed clone) |
| Funds sent, never deployed | anyone can deploy; funds cannot go anywhere else |
| Partial funding | deploy reverts `Underfunded` until topped up |
| Third party calls `release()` early | pays the beneficiary what is vested; nothing else |
| Approver compromised | approves milestones whose date has passed; cannot redirect funds |
| Grantor revokes before the cliff | the revocable bargain; disclosed in the wizard and the beneficiary page |
| Token with transfer fee / rebasing | unsupported (v2 tokens have neither); the wizard refuses non-v2 tokens without an override flag |

### 4.7 Gas (estimates)

| Operation | Grant clone (chosen) | Vault (rejected) |
|---|---|---|
| create | clone ≈ 41 k + init ≈ 5 slots × 22.1 k ≈ 110 k (+22 k per tranche) ⇒ ≈ 155 k | ≈ 110 k + `transferFrom` ≈ 30 k ⇒ ≈ 140 k, plus an allowance first |
| fund | one transfer (≈ 35–60 k as meta-tx) | inside create |
| release | ≈ 45–60 k (token transfer + 1 SSTORE) | similar |

Streaming payroll per short pay period is cheaper as `mtxBatch` of `pay` ops (TW2 §7.4); grants suit periods of a
quarter or more and incentive vesting.

### 4.8 Tests

Unit: schedule edges (`t = cliff − 1, cliff, end`), interval steps, tranche ordering and Σ checks, approver gating,
signature approval (EOA, ERC-1271, 7702 = EOA, replay no-op), revoke before/after cliff and after full vesting,
`renounceRevocation`, `sweepExcess`, counterfactual funding then deploy, `Underfunded`, regulated token (grant frozen
⇒ release reverts; beneficiary frozen ⇒ release credits, R204). Fuzz: `vested` monotone and ≤ total;
`Σ released + returned + swept ≤ funded`. Invariant: handlers release/revoke/approve/warp/stray transfers.

---

## 5. Dividend and coupon distribution (R210)

### 5.1 Flow

```
1. issuer picks recordToken, recordBlock (final), payout pool and policy (exclusions, protocol-clone mapping)
2. node builds the snapshot (§5.4) → root, total, leafCount, leaves; anyone can recompute
3. client builds DistParams p; dist = AssetFactory.predictDistribution(p); issuer funds `dist` (gasless transfer)
4. anyone: AssetFactory.createDistribution(p) → Underfunded unless balanceOf ≥ total; claimStart ≥ now
5. review window [create, claimStart): admin may cancel() → all funds to sweepTo
6. claims from claimStart: anyone submits claim(index, account, amount, proof) → pays `account`
7. after expiry (if any): anyone sweep() → remainder to sweepTo
```

### 5.2 Interface

```solidity
interface IDistribution {
    struct DistParams {
        address payoutToken; bytes32 root; uint256 total; uint32 leafCount;
        address admin; address sweepTo; uint64 claimStart; uint64 expiry;    // expiry 0 ⇒ never
        address recordToken; uint64 recordBlock; bytes32 policyHash;          // provenance (events, salt)
        bytes32 ref;                                                          // ERP declaration id
    }
    struct Claim { uint256 index; address account; uint256 amount; bytes32[] proof; }
    event Claimed(uint256 indexed index, address indexed account, uint256 amount);
    event Cancelled(uint256 returned);
    event Swept(uint256 amount);
    error NotStarted(uint64 claimStart); error ClaimsClosed(uint64 expiry); error AlreadyClaimed(uint256 index);
    error BadProof(); error NotAdmin(); error ReviewOver(); error NotExpired(); error IndexOutOfRange();

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external;
    function claimMany(Claim[] calldata cs) external;  // skips already-claimed items, reverts on a bad proof
    function cancel() external;                          // admin, now < claimStart
    function sweep() external;                           // anyone, expiry ≠ 0 && now > expiry
    function isClaimed(uint256 index) external view returns (bool);
    function claimedTotal() external view returns (uint256);
}
// leaf = keccak256(bytes.concat(keccak256(abi.encode(index, account, amount))))   (OZ MerkleProof, sorted pairs)
```

Init checks: `root ≠ 0`, `total > 0`, `leafCount > 0`, `claimStart ≥ now`, `expiry == 0 || expiry ≥ claimStart +
30 days`, `sweepTo ≠ 0`, balance ≥ total. Claimed bitmap `mapping(uint256 ⇒ uint256)`. `claimedTotal ≤ total`
checked on every claim (a root whose leaves exceed `total` fails at the claim that crosses it, never overpays).

### 5.3 Coupons and dividends

- Dividend: pool `D` over eligible balance `S`: `amount_i = ⌊D·b_i/S⌋`; dust stays and is swept.
- Coupon: per-unit amount `c` (`num/den` in payout raw units per bond raw unit): `amount_i = ⌊b_i·num/den⌋`;
  `total = Σ amount_i`.
- One distribution per payment date; the ERP schedules them from the bond terms. Funding remains the issuer's
  obligation: the contracts make payment automatic **once funded**, they do not remove credit risk (corrects the
  SRS §3.6 wording).

### 5.4 Snapshot (node, deterministic)

Input: `(chain_key, recordToken, recordBlock, policy)` with `recordBlock` final under the chain's finality gate.
Balances = replay of every finalized `Transfer` of `recordToken` from its creation block (node indexer watch list,
NI P4) to the end of `recordBlock`; must equal `balanceOf(a)` at `recordBlock` for a sampled set (archive RPC
quorum) or the build fails. Policy (canonical JSON, `policyHash = keccak256` of its RFC 8785 bytes): excluded
addresses (issuer treasury, DEX, offers), and attribution of protocol clones (`VestingGrant` balances to their
beneficiary, to the grantor, or excluded — issuer's choice). Leaves sorted by `account` ascending, `index` = position,
zero amounts dropped. Frozen holders stay in (entitlement is not seized by a freeze; payment credits them, R204).
Output: root, total, leafCount, leaves file (CSV + JSON), proofs. Vectors: `test/vectors/merkle_dist_vectors.json`
(Solidity, Rust node, Python ERP).

Node API (NI job-API conventions, namespace-scoped): `POST /v1/snapshots {chain, token, block, policy}` → `{id}`;
`GET /v1/snapshots/{id}` → `{state, root, total, leaf_count, policy_hash}`; `GET /v1/snapshots/{id}/leaves`;
`GET /v1/snapshots/{id}/proof?account=` (public data, cacheable). CLI `scaas-node snapshot verify <file>`
recomputes a root from chain without trusting the store. The node is not trusted for the root (NI T7): the review
window and independent recomputation are the control.

### 5.5 Meta-tx, ERP, app

Claims and `claimMany` are sponsored `call` jobs (the relayer batches ≤ 100 claims per tx); no signature is needed
because a claim pays only the leaf's account. ERP: a declared distribution is a payable; `Claimed` reduces it;
`Cancelled`/`Swept` reverse the remainder. App: holder page lists claimable distributions with a claim button.

### 5.6 Security

Invariants: each index paid once; `claimedTotal ≤ total ≤ funded`; nothing leaves except to a leaf account
(claims) or `sweepTo` (cancel before `claimStart`, sweep after `expiry`).

| Abuse | Outcome |
|---|---|
| Wrong root (issuer or node error, lying node) | review window + independent recompute + `cancel`; after `claimStart` the `total` cap bounds the loss to the pool |
| Second-preimage of an inner node as a leaf | double-hashed leaves |
| Admin cancels after claims start | `ReviewOver` |
| Early sweep | `NotExpired`; with `expiry = 0` never |
| Griefing claims | pay the rightful account only |
| Snapshot double counting via clones | policy attribution, committed in `policyHash` |

### 5.7 Gas and tests

Claim ≈ 30 k + 0.4 k × ⌈log₂ leafCount⌉ + the payout transfer (≈ 30–55 k): ≈ 65–95 k for 10⁵ holders;
`claimMany` saves the 21 k intrinsic per item. Create ≈ clone 41 k + 6 slots ≈ 175 k. Tests: proof vectors,
duplicate index, bad proof, `claimMany` skip semantics, time edges (`claimStart`, `expiry`), cancel window, sweep,
over-`total` root, regulated payout token (frozen account credited, ineligible account refused — the policy must
exclude or the issuer attest), fuzz over random trees (≤ 2¹⁰ leaves), invariant handlers claim/cancel/sweep/warp.

---

## 6. Corporate actions: `ExchangeOffer` (R211, R212)

### 6.1 One contract, four uses

| Use | `tokenIn` | `tokenOut` | `num/den` | Window | `closable` | `sink` |
|---|---|---|---|---|---|---|
| Bond redemption at maturity | bond (tier-1 REG) | payout stablecoin | face value per unit | `opensAt = maturity`, `closesAt = 0` or maturity + claim period | no | 0 (burn) |
| Buyback (tender at a fixed price) | equity | stablecoin | price | issuer's choice, `capIn` | yes | issuer treasury or 0 |
| Split `1 : k` | old equity | new equity (pre-minted `k × supply` to the offer) | `k/1` | long | no | 0 (burn) |
| Reverse split `k : 1` | old equity | new equity | `1/k` | long | no | 0 (burn) |

A buyback at market is a bid on a managed market (§8), not an offer. Wrapper tokens are not split (their unit is
defined by the rate; an adjustable-rate token re-pegs through TW2 §6).

### 6.2 Interface

```solidity
interface IExchangeOffer {
    struct OfferParams {
        address tokenIn; address tokenOut; uint96 num; uint96 den;  // out = in·num/den, exact (R212)
        uint256 capIn;                                               // 0 ⇒ no cap
        uint64 opensAt; uint64 closesAt;                             // closesAt 0 ⇒ never
        address admin; bool closable; address sweepTo; address sink; // sink 0 ⇒ burn (tier-1 tokenIn only)
        bytes32 termsHash; bytes32 ref;
    }
    event Exchanged(address indexed holder, uint256 amountIn, uint256 amountOut);
    event Closed(uint64 at);
    event Swept(uint256 amountOut);
    error NotOpen(); error ClosedOffer(); error CapExceeded(uint256 remaining); error NotExactMultiple();
    error InsufficientOut(uint256 have, uint256 need); error NotATradeLeg(); error LegNotRoutedHere();
    error CounterTokenMismatch(); error PriceNotMet(uint256 out, uint256 min); error FeeWouldStick();
    error DeltaMismatch(uint256 got, uint256 expected); error NotAdmin(); error NotClosable(); error SinkRequired();

    function exchange(MetaTxLib.MetaTransaction calldata leg, bytes calldata sig) external returns (uint256 out);
    function exchangeDirect(uint256 amountIn, uint256 minOut) external returns (uint256 out);
    function close() external;   // admin, only if closable
    function sweep() external;   // anyone, after close or closesAt: tokenOut remainder → sweepTo
    function quote(uint256 amountIn) external view returns (uint256 out);
    function filledIn() external view returns (uint256);
}
```

`exchange` (gasless): `leg` is a `trade` op on `tokenIn` signed by the holder with `data = trade(tokenOut,
minCounterValue, counterparty ∈ {0, this})`, `to = relayer = this`, `MODE_RESTRICT_RELAYER`, fee `NONE` or a bound
`feeRecipient ∉ {0, this}` — the `MetaTxDex._terms`/`_checkRouting`/`_pull` checks verbatim (shared library
extracted from `MetaTxDex`, no behaviour change there). The offer calls `tokenIn.executeMetaTransaction(leg, sig)`,
requires the measured delta `== leg.value`, computes `out`, requires `out ≥ minCounterValue`, `filledIn + in ≤ capIn`,
the window open and `tokenOut.balanceOf(this) ≥ out`, burns (`NoUnderlyingToken.burn`) or forwards to `sink`, then
pays `out` to `leg.from`. `exchangeDirect`: same checks with `transferFrom(msg.sender)` (the holder approved this
contract, R26). Init: `sink == 0` requires `tokenIn.tokenKind() ∈ {META_NONE, META_NONE_REG}` (`SinkRequired`).

Offers need not be fully funded at creation (a redemption offer is created at issuance and funded at maturity);
an exchange that cannot be paid reverts `InsufficientOut`. The offer address is known at issuance and goes into the
bond's `termsHash` document.

### 6.3 Splits in practice

1. Issuer creates the new token with the same template (same regulated config; new `termsHash` referencing the
   action) and `initialSupply = ⌈S_old·num/den⌉` to itself, then transfers it to the offer (or funds the counterfactual
   address).
2. Holders exchange (gasless) multiples of `den/gcd(num, den)`; the wallet computes the amount and shows the dust.
3. Dust stays in the old token; a buyback offer (cash in lieu) can absorb it.
4. The old token remains a valid token; the issuer may pause it once (R205) to concentrate the migration, never
   block exchange (the exchange is a transfer *to* the offer: during a pause it is refused, so issuers schedule pauses
   outside the exchange window). The new-token remainder after the window is swept to the issuer, who burns it.
5. DEX: the venue delists the old market and lists the new one; resting orders on the old token expire or are
   cancelled.

### 6.4 Security, gas, tests

Invariants: `filledIn ≤ capIn`; every `Exchanged` paid exactly `in·num/den`; no `tokenOut` leaves except to a holder
(exchange) or `sweepTo` (after close/`closesAt`); `tokenIn` is burned or at `sink`. Abuse: a leg replayed (token
nonce), a leg routed to another offer (`LegNotRoutedHere`), a fake token delta (measured), reentrancy via hooks
(transient guard), early close of a non-closable redemption (`NotClosable`), rate typo (bounded by the funded
balance; the wizard shows the human rate). Gas: ≈ MetaTxDex leg (≈ 60 k) + burn (≈ 8 k) + payout (≈ 30–55 k) ≈
110–130 k. Tests: both paths, exact-multiple edges, cap edge, window edges, sink vs burn, `SinkRequired` for wrapper
`tokenIn`, regulated `tokenIn` (offer needs `ELIGIBLE_CONTRACT`; frozen holder refused at step 6) and regulated
`tokenOut` (ineligible holder refused), fuzz `num/den` ∈ [1, 2⁹⁶) with the TW2 rate vectors' edge set.

---

## 7. Asset templates (R213)

Presets live in `sdk/asset_templates.json` (versioned; the wizard, the app and the ERP read the same file) with a
vector per preset (`initData` bytes for given inputs). Each preset names its kind, `initData` builder, required
inputs, defaults, follow-up actions and disclosure text.

| Template | Kind | Defaults | Follow-ups |
|---|---|---|---|
| **Equity** (shares, units of a fund) | `META_NONE_REG` | `decimals 0`; `initialSupply` to the issuer treasury Safe; `minter` = issuance multisig or 0 (fixed); `controls = FREEZE|FORCE|PAUSE|ALLOWLIST`; `requiredFlags = KYC_DONE|SANCTIONS_CLEAR` (+ `ACCREDITED` for restricted offerings); fee `NONE` | dividends (§5), splits/buybacks (§6), managed market (§8), vesting of employee grants (§4) |
| **Bond** | `META_NONE_REG` | `decimals 0` (1 unit = 1 denomination); supply minted at issuance, minter renounced after; controls as equity; `termsHash` covers face, coupon dates and rate, maturity, redemption offer address | one `Distribution` per coupon date; one `ExchangeOffer` (redemption, burn, `opensAt = maturity`) created at issuance |
| **Loyalty points** | `META_NONE` | `decimals 0`; `minter` = the issuer's mint contract (rate limits live there, TW2 §4); fee `NONE`; no regulated module. Prepaid points: `META_SINGLE` with a rate (TW2 §6.4 example, 1 USDC → 100 points) | campaigns as `Distribution` of points; redemption = `pay` to the merchant |
| **Voucher** (gift card, coupon) | `META_NONE` (or `META_SINGLE` for prepaid value) | `decimals 0`, 1 unit = 1 voucher of the stated face value; issuer minter; validity = the redemption offer's window | issuance by mint or `Distribution` (campaign); merchants accept by `pay`; issuer redeems merchants' vouchers by an `ExchangeOffer` (voucher → payout, burn) whose `closesAt` is the expiry |

Points and vouchers do not expire on chain (balances never change, TW2); expiry is the end of the issuer's
redemption offer, disclosed as such. A loyalty or voucher issuer who needs freeze or allowlist picks the `*_REG`
kind of the same tier; the wizard then applies §3.9.

---

## 8. Managed DEX markets (R214)

### 8.1 Venue

- The licensed operator deploys its own `OrderBookDex` instance (`admin` immutable = its multisig, RS5-1) and lists
  only managed pairs; its listing power covers only its venue. Contract unchanged.
- Node config per market: `dex_market.managed = 1`, `unbound = 0` (forced), `gossip = 0` (default),
  `eligibility_tokens` (the regulated legs; read from `versionOf(token).kind`), optional venue-level
  `registry`/`required_flags` for pairs of two unregulated tokens (enforced at intake only; documented as off-chain).
- Wallets show managed markets with the venue name, the regulated legs' disclosures (§3.9) and the eligibility
  result for the user before signing.

### 8.2 Intake and matching (node, DEX §3.4 additions)

| Point | Check | Refusal |
|---|---|---|
| Order intake | `relayer == our lane` (RS5-9, mandatory for managed); for each regulated leg: maker not frozen (`isFrozen`), `canReceive(maker)` for the token the maker buys, token not paused | `NOT_ELIGIBLE {reason}`, `UNBOUND_FORBIDDEN`, `PAUSED` |
| Expiry | `expiry ≤ min(now + 30 d, receiver attestation validUntil)` | `ATTESTATION_SHORTER` |
| Before each settle simulation | `checkTransfer(maker, taker, x)` and the reverse on each regulated leg; market fee recipient `canReceive` | pair dropped, both orders re-checked |
| Events | `AccountFrozen` (maker ⇒ drop the maker's orders from the book), `Paused` (stop matching the market until `pausedUntil`), `Attested` with flags 0 (drop) | — |

On chain the token is the arbiter regardless (§3.8): a pair that slipped through fails alone (`MatchFailed`).

### 8.3 Gossip (A2 §11 amendments)

- Managed markets are **not gossiped** by default: wallets post to the venue's gateway; `route_order` for a managed
  market is refused (`MANAGED_LOCAL`).
- If the operator enables gossip (`gossip = 1`): home-bound replicas only (R124 bound mode), listed only for homes
  with `gossip_trusted.dex = 1` (admin pre-trust); R128 automatic trust is not computed for managed markets (a
  settle history is not a licence); depth is indicative as today; `unbound` stays 0.
- Private-profile chains: managed markets follow A2 §12 (never on gossip).

### 8.4 Security

| Abuse | Outcome |
|---|---|
| Third party settles two eligible makers' signed unbound orders | our wallets never sign `relayer = 0` for managed markets and intake refuses them; a maker who signs one elsewhere accepts it (A2 §11.6 item 6); the token still enforces eligibility |
| KYC revoked between intake and settle | pre-settle re-check; else the pair fails on chain |
| Resting-order privacy | not gossiped by default; fills are public on chain as for any trade |
| Venue fee to an ineligible recipient | fails on chain; the venue attests its fee Safe `ELIGIBLE_CONTRACT` |
| Wash trades by the venue | out of scope of the contract (venue licence, surveillance); every fill is on chain |

Tests (node, `cargo test`): intake refusals per reason; drop on `AccountFrozen`/`Paused`/revocation; pre-settle
re-check; unbound refusal; gossip refusal and admin-trust-only listing. Forge: one managed-market e2e with a
regulated equity and an unregulated stablecoin (frozen maker, ineligible taker, eligible pair settles).

---

## 9. Node, ERP and app touchpoints (summary)

### 9.1 Node (`scaas-node`)

- Event normaliser (`SCaaS` §7.8) adds: `OrderRecorded`, `OrderRevoked`, `AccountFrozen`, `AccountUnfrozen`,
  `ForcedTransfer`, `Paused`, `Unpaused`, `RoleRenounced`, `Attested`, `AttesterSet`, `GrantCreated`, `Released`,
  `Revoked`, `RevocationRenounced`, `MilestoneApproved`, `ExcessSwept`, `DistributionCreated`, `Claimed`,
  `Cancelled`, `Swept`, `OfferCreated`, `Exchanged`, `Closed`; `TieredTokenDeployed` with the three new kinds.
- Token table: `kind` gains `meta_none_reg`, `meta_single_reg`, `meta_multi_reg`; cached `controls`, roles,
  registry (immutable, read once).
- Intake: the receiver-attestation expiry rule (§3.8); grief-score exemptions for authority-caused reverts.
- Snapshots (§5.4) and managed-market rules (§8). Alerts: any `OrderRecorded`, `ForcedTransfer`, `Paused`,
  `AttesterSet`, and a role contract's code hash change.
- Control actions are submitted as ordinary `call` jobs (a Safe's `execTransaction` with its owners' signatures, or a
  `SubjectAccount.executeAsOwner`); the node holds no role key.

### 9.2 ERP (Odoo `dms_blockchain`, new addon `dms_blockchain_assets`, PLANNED with stream AS8)

Asset register (kind, template, terms document, `termsHash`), cap table mirror from the feed, compliance cases
(order id, document stored in the ERP, `documentHash`, records, freezes, forced transfers), attestation sync (the ERP
KYC process is the system of record; it pushes `attest` `call` jobs signed by the attester contract's owners),
grants, distributions (payables), offers (redemptions, buybacks). Personal data never goes on chain (`SCaaS` §11).

### 9.3 App (`app/`, per the app spec)

Issuer wizard (templates, inputs, human-rate preview, mandatory disclosure §3.9), compliance console that **builds**
Safe transactions for orders, freezes, forced transfers and pauses (signed by the user's own Safe owner key; the app
never holds a role key), holder pages (regulated status, vesting, claimable distributions, open offers, managed
markets).

---

## 10. Per-family availability

| Component | EVM | Hedera | Cosmos | Soroban (Stellar, Pi) | Move (Aptos, Sui) | TON | Solana |
|---|---|---|---|---|---|---|---|
| Regulated module | this spec | this spec (HSCS contracts + HIP-632; HTS-native tokens not used, R63) | PLANNED: CW20 variant with the same rulings | PLANNED: SEP-41 variant; candidate native flags (auth-required, clawback) to be assessed | PLANNED: candidate native mechanisms (Aptos FA `TransferRef` freeze/transfer; Sui regulated coin deny list) | PLANNED: jetton master + wallet with order records | PLANNED: candidate Token-2022 extensions (permanent delegate, default frozen state, transfer hook) |
| ComplianceRegistry | this spec | this spec | PLANNED | PLANNED | PLANNED | PLANNED | PLANNED |
| VestingGrant, Distribution, ExchangeOffer | this spec | this spec | PLANNED | PLANNED | PLANNED (subject account holds any asset; contracts as Move modules) | PLANNED | PLANNED |
| Snapshot builder | this spec | this spec (Mirror-node free; same indexer) | with each family's token | 〃 | 〃 | 〃 | 〃 |
| Managed markets | this spec | this spec | where an order book exists | — | — | — | — |

"When": each non-EVM family gets its own short spec after EVM+Hedera build (streams AS1–AS7) and after that family's
TW2 wrapper work (R145 order); every family spec must satisfy R201–R216 or amend them explicitly. Candidate native
mechanisms are named for that assessment only; none is relied on here.

---

## 11. Factory and catalogue changes (R200)

```solidity
enum TokenKind { META, ZETHER, META_NONE, META_SINGLE, META_MULTI, META_NONE_REG, META_SINGLE_REG, META_MULTI_REG }
```

| Rule | Detail |
|---|---|
| Kind ⇒ count | `*_REG` as their base tier (0 / 1 / 2–8) |
| Tiered entry points | `createTiered*` accept the three new kinds; v1 entry points refuse them (as today) |
| Registration | `tokenKind()` and `factory()` checks unchanged (`VersionKindMismatch`, `ImplementationFactoryMismatch`) |
| Provenance | unchanged; wallets read `versionOf(token).kind` and, for `*_REG`, the §3.3 views |
| `AssetFactory` | separate contract (not the token factory: action contracts are not tokens): `predictGrant/createGrant`, `predictDistribution/createDistribution`, `predictOffer/createOffer`; CREATE2 salt `keccak256(abi.encode(kindTag, params))`; implementations immutable in the constructor, no registrar, no catalogue (a new implementation = a new `AssetFactory`); events `GrantCreated`, `DistributionCreated`, `OfferCreated` |

Deploy script: factory v2 (with the appended kinds) registers the six regulated implementations as version 1 of
their kinds; `AssetFactory` and one `ComplianceRegistry` per operator are deployed separately.

---

## 12. Storage layout pins

New implementations get `test/as/layout/*.json` pins (as TW2 I7). Regulated children: TW2 slots 0–15 identical to
their base tier (asserted) plus the ERC-7201 namespace; `VestingGrant`, `Distribution`, `ExchangeOffer` pinned in
full. Indexers that read `reserve` by slot keep working on regulated wrappers.

---

## 13. Work breakdown

One heavy forge job at a time (`forge test --match-path test/as/<step>*` for the step; the full suite once at the
end); at most three sub-agents; reviews by Claude sub-agents.

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| AS1 | `RegulatedControls`, three EVM regulated children, `ComplianceRegistry`, factory v2 kinds, TW2 keyword changes | — | `test/as/Regulated*.t.sol`, `Registry.t.sol`, TW2 v2 suite green with identical gas/layout, sizes ≤ 24 576 |
| AS2 | `HederaRegulated*` | AS1 | `test/hedera/*Reg*.t.sol` |
| AS3 | `AssetFactory` + `VestingGrant` | — (regulated cases need AS1) | `test/as/Vesting*.t.sol` |
| AS4 | `Distribution` + `merkle_dist_vectors.json` | AS3 (factory) | `test/as/Distribution*.t.sol` |
| AS5 | `ExchangeOffer` + trade-leg library shared with `MetaTxDex` | AS3 | `test/as/Offer*.t.sol`, `MetaTxDex` tests unchanged |
| AS6 | Invariant suites (regulated I1–I6, grant, distribution, offer), gas tables, layout pins, managed-market forge e2e | AS1–AS5 | `test/as/*Invariant*.t.sol`, `*Gas.t.sol` |
| AS7 | Node: normaliser, token kinds, intake rules, grief exemptions, alerts, snapshot builder + API + CLI + vectors, managed markets (after P7/G3 for the gossip part) | AS1, AS4 | node `cargo test` (one heavy cargo job at a time, never in parallel with forge) |
| AS8 | `sdk/asset_templates.json` + vectors, ERP addon, app screens (per the app spec) | AS7 | SDK vector test; Odoo unit tests |
| AS9 | Docs: `SCaaS` §4/§14/§15 texts and statuses to BUILT, `integration.md` | per stream | — |

---

## 14. Open questions (owner)

1. **HTS-native regulated tokens on Hedera.** This spec uses HSCS contracts on Hedera (R63: HTS only behind a
   wrapper). Some Hedera issuers want HTS-native tokens with KYC/freeze/wipe keys held by a contract, for native
   wallet and explorer support. Wanted as a separate variant, or HSCS only?
2. **Pause cooldown value.** R205 fixes 7 days on, 7 days cooldown (arbitrary, chosen so a pause is never more than
   half of any period). A supervisor may require back-to-back pauses for an incident on a tier-1 regulated token
   (no exit exists there). Keep, or allow a longer cooldown-free pause only when `issuer` and `compliance` are
   separate contracts and both sign?
