# Open Asset Suite: regulated module, vesting, asset templates, distributions, corporate actions, managed markets

Status: draft rev 1.1, 2026-10-06. Rev 1.1 folds in independent review 1 (FIX-THEN-GO: H1–H5, M1–M10, L1–L10,
over-engineering cuts); disposition §15. Component spec **A** of the asset roadmap. Code: none yet (contracts under
`smartcontracts/evm/src` at `scaas` `main` 9737ef3 are the base). Short name **AS**.
Rulings: **R200–R217** (§2). R150–R172 belong to the app spec and R180–R199 to spec B. Owner rulings of 2026-10-06
(six items) are folded in and marked `(owner)`; everything else is a decision of this spec that amends PLANNED text
in `SCaaS.md`.

Amends:

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §4.1, §4.5, §4.6, §4.8, §4.9, §14.6, §14.8, §15.1 row 23: status PLANNED → SPECIFIED with a link (done). Text updates at stream AS9 (§13): §4.5 rules 3–5 and `courtOrderBurn` (R203–R205), §4.6 vault shape (R209), §4.8 `CouponPayer` (R210), §14.5 `attributes(UA)` proposal withdrawn (R206), §14.6 and §14.8 replaced by §3.3 and §4.2 here, §15.2 q8 answered (R200) |
| TW2 | `2026-10-06-token-wrappers-v2.md` | R142 gets a third creation-time exception (R201); `IOpenFactoryV2.TokenKind` appends three kinds and `OpenFactoryV2` gets a count-map code change (R200); `virtual` added to `MetaTokenBase._checkOp`, `MetaTokenBase.payWithFee`, `NoUnderlyingToken.tokenKind/_init`, `MultiUnderlyingToken.tokenKind/_init` (R207; no behaviour change) |
| A2 | `2026-10-06-mesh-gossip-amendment.md` | R124/R128: a `managed` market is home-bound only, not gossiped by default, admin-trusted homes only (R214) |
| DEX | `2026-10-03-dex-design.md` | none in the contract; node intake gains the managed-market checks (§8) |

Inputs: `SCaaS.md` §4 (tokens; §10 tender is separate and untouched), TW2 (R129–R149, storage §10.1, factory §9),
DEX design (RS5-*), A2 R124/R128, research `01-token-factory.md` §1.10–1.11, `02-account-registry.md`,
`09-payment-modes.md` M8/M9/M17/M18, the SRS drafts (architecture §3.5–3.7, §9.6; integration §4.7–4.8; reference
only, never edited), and the code: `metatx/MetaTxCore.sol`, `metatx/MetaTokenBase.sol`, the three tiers,
`hedera/HederaTokensV2.sol`, `factory/OpenFactoryV2.sol`, `registry/UniversalAccountRegistry.sol`,
`dex/OrderBookDex.sol`, `dex/MetaTxDex.sol`. Measured runtime sizes (review 1, existing artifacts): `SingleUnderlyingToken`
21 637, `MultiUnderlyingToken` 22 561, `HederaMultiUnderlyingToken` 23 885 bytes.

---

## 1. Scope

### 1.1 What this spec adds

```
EVM / Hedera (Solidity), all clones of never-upgraded implementations:

MetaTokenBase v2 tiers (TW2, BUILT)            + RegulatedControls (ERC-7201 storage) + RegulatedLib (linked, §3.1)
 ├── NoUnderlyingToken      META_NONE            → RegulatedNoUnderlyingToken      META_NONE_REG   (5)
 ├── SingleUnderlyingToken  META_SINGLE          → RegulatedSingleUnderlyingToken  META_SINGLE_REG (6)
 └── MultiUnderlyingToken   META_MULTI           → RegulatedMultiUnderlyingToken   META_MULTI_REG  (7)
     (+ Hedera children of each regulated tier: HederaRegulated*)

ComplianceRegistry          address-keyed attestations (flags, validUntil, attester); no personal data (§3.7)
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
- HTS-native regulated tokens on Hedera (owner: HSCS contracts only).
- Any country-specific rule. Eligibility is expressed as attestation flags whose meaning the issuer defines.
- A new DEX contract. Managed markets are node policy over `OrderBookDex` plus token-level enforcement (R214).

---

## 2. Rulings

Format: **ruling — reason — cost if wrong.**

- **R200** (owner: optional module at creation on any tier) The regulated module is **separate implementations**,
  one per tier, each a child of its TW2 tier plus `RegulatedControls`; factory kinds are **appended**:
  `META_NONE_REG = 5`, `META_SINGLE_REG = 6`, `META_MULTI_REG = 7`. `OpenFactoryV2` gets a **code change**, not
  only an enum change: the underlying-count map becomes a function of the base kind (`_baseOf(kind)`; today's
  `_createTiered` ternary would put `META_NONE_REG`/`META_SINGLE_REG` into the 2–8 branch). Unregulated
  implementations carry no control code and no runtime flag. The change lands **before the first production
  deployment** of factory v2 (operator step O3; `deployments/` is gitignored, so O3 confirms on the operator hosts
  that no v2 factory or implementation is live); otherwise it ships as factory v2.1, never as an edit of a deployed
  one. Node and ERP decoders of `versionOf().kind` must know 5–7 before the first `*_REG` create. Answers `SCaaS`
  §15.2 q8 — research §1.10 (the choice must be visible in `versionOf()`, not in a storage flag) — if wrong: one
  more catalogue line per tier; wallets read `kind` either way.
- **R201** (owner) **Third exception to R142.** "Nobody alters a deployed token" now has three creation-time,
  visible exceptions: the R135 rate admin, the R136 guardian, and the **regulated module** of a `*_REG` token.
  The module's powers are the bits of `controls()` (`FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`), set at creation; bits
  can only be **cleared** later (renounce, `disableControls`), never set. `termsHash` (non-zero) commits to the
  issuer's disclosure document. Disclosure is **mandatory** (§3.9). No regulated power can mint, change a rate,
  touch the token's own reserve or add a power — if wrong: holders would have to read code to learn a token can be
  seized.
- **R202** (owner: issuer + compliance roles) Two roles, set at creation, each **a contract** (a multisig with an
  external seat is recommended, default 3-of-5 as `SCaaS` §4.5 rule 2, which the contract cannot prove): `issuer`
  executes (freeze, unfreeze, forced transfer, pause, unpause, `disableControls`); `compliance` records and revokes
  orders. Neither role is transferable; each can renounce one-way, and renouncing **relaxes**: `issuer` renounce
  clears `FREEZE|FORCE|PAUSE` (every freeze and pause ends at once), `compliance` renounce clears `FORCE`. Wallets
  compare `issuer()` and `compliance()` to show whether the roles are separated — if wrong: a renounced or dead
  issuer would leave frozen balances frozen forever (review H2).
- **R203** (owner: forced transfer only against a recorded order) `compliance` records an **order record**
  `{subject, beneficiary, maxAmount, freezeUntil}` under `recordId = keccak256(abi.encode(orderId, subject,
  beneficiary))` (`orderId` = keccak256 of the authority's canonical order identifier; `documentHash` = hash of the
  order document, kept off chain; both only in the event). `issuer` may force-transfer only (a) against a live
  record, (b) **from the recorded subject while it is frozen**, (c) **to the recorded beneficiary**, (d)
  cumulatively ≤ `maxAmount`. There is **no `courtOrderBurn`** (`SCaaS` §4.5/§14.6 amended): a burn is a forced
  transfer to a beneficiary that burns (tier 1) or unwraps (wrapper tiers) itself — if wrong: one extra power, one
  extra audit path, no extra capability.
- **R204** Freeze semantics: a frozen account cannot send (transfer, `transferFrom`, burn, unwrap), cannot be the
  `from` of any meta-tx op, and cannot receive a relayer fee (owner). It **can** receive this token (credits are
  never refused because of a freeze). The **unwrap recipient is not checked** (review H5): it receives a different
  asset, and an unfrozen holder could unwrap to itself and forward it anyway. **Duration** (review H3; the owner set
  none): the issuer alone may freeze an account for ≤ 30 days, extendable within the same episode to ≤ 60 days from
  its start, and may not start another issuer-only episode on that account until 30 days after the last one ended;
  a longer or open-ended freeze needs a live compliance record naming the account, lasts until that record's
  `freezeUntil`, and ends when the record is revoked. Every freeze/unfreeze carries a non-zero `ref` — if wrong: a
  compromised issuer alone could freeze every holder with no end date.
- **R205** (owner: global pause 7 d / 7 d) `pause(ref, until)`: `until ≤ now + 7 days`, no extension while paused,
  and a **cooldown of 7 days** after any pause ends before the next may start. Paused: transfers,
  `transferFrom`, mints, wraps, every meta-tx op except a **fee-less** unwrap op, and therefore every
  `ExchangeOffer` exchange into the token (redemptions, buybacks, split migration). **Never paused:** unwrap
  (direct, or R148 op with fee `NONE`, which the node sponsors during a pause), holder burn, forced transfer.
  Replaces `SCaaS` §4.5 rule 5's "reopen redeem automatically" — if wrong: back-to-back pauses would be an indefinite
  freeze of everyone.
- **R206** Allowlist through a new **`ComplianceRegistry`** (address → `{uint64 flags, uint64 validUntil, uint32
  attesterId}` in one slot; an immutable `admin` contract manages attesters; disabling an attester voids its
  attestations at once; no personal data). The UA registry is **not** extended (a Zether key registry, no admin by
  design, dev-chain only, RS2-1); the `SCaaS` §14.5 `attributes(UA)` proposal is withdrawn and its flag bits reused.
  A regulated token pins one registry and one `requiredFlags` mask at creation. **Only receivers of this token are
  checked** (`to` of a transfer or mint, fee recipient): a holder whose attestation lapsed can still send to an
  eligible party, burn and unwrap. `issuer` may `disableControls(ALLOWLIST)` one-way, so a dead registry never
  locks a tier-1 token (review M10) — if wrong: a sender-side check would trap holders when an attester is slow.
- **R207** (owner: interaction with meta-tx) Checks run at **step 6** through an override of `_checkOp` (TW2 §3.2),
  so a failing intent costs the relayer only the cheap prefix; the same rules are enforced again in an `_update`
  override for every direct path. A frozen `from` reverts every op, including `approve`; a frozen or ineligible
  resolved fee recipient reverts (also on `payWithFee`, whose override copies the base body, since an external
  function cannot call `super`; an event-equality test pins it). R26 is unchanged and orthogonal. Regulated
  templates default to `MODE_FEE_NONE` (sponsored), because a fee-earning relayer would itself need an attestation.
  Keyword changes to built code: `virtual` on `MetaTokenBase._checkOp`, `MetaTokenBase.payWithFee`,
  `NoUnderlyingToken.tokenKind`, `NoUnderlyingToken._init`, `MultiUnderlyingToken.tokenKind`,
  `MultiUnderlyingToken._init`; the module's code-check hook is named `_regIsContract` (implemented by the child as
  `_isContract(a)`) to avoid a clash with the non-virtual `MetaTxCore._isContract`. Every source edit changes the
  CBOR metadata hash of all v2 implementations, acceptable only because none is deployed (R200) — if wrong:
  failures surface at step 7/8 at full gas.
- **R208** (owner: Multi reserves/unwrap) No regulated power touches **the token's own** `reserve_i`, rates or legs;
  forced transfer moves wrapped units only, so its `collateralValue() ≥ totalSupply()` is untouched. A frozen holder
  **cannot unwrap**; the beneficiary of a forced transfer can. Unwrap is open during a pause. Guardian and rate
  admin keep exactly their TW2 powers. A `*_REG` token used as the **underlying** of a TW2 wrapper is refused by the
  wizard (blocking warning when forced): the regulated issuer could freeze or seize that wrapper's leg (breaking
  TW2 R134 for that wrapper), and an attested wrapper would let its units bypass the allowlist (review M4) — if
  wrong: a seizure could drain a leg other holders rely on.
- **R209** (owner: vesting) **One EIP-1167 clone per grant** (`VestingGrant`), not a vault. Funding is
  **counterfactual**: the clone address is `CREATE2(keccak256(abi.encode(params)))`; `predictGrant(p)` **reverts**
  unless `p` passes every state-independent check, and clients fund only an address `predict*` returned; the grantor
  funds it with an ordinary (gasless) transfer or `pay` op; anyone then deploys it, and init can revert only with
  `Underfunded` (fixed by a top-up). Schedules: linear with cliff and optional step `interval`, or ≤ 16 tranches,
  optionally gated per tranche by an `approver` (milestones). Revocable option (grantor reclaims the unvested
  part). Claim is a permissionless `release()` that pays only the beneficiary: gasless through any relayer, no
  signature, no nonce. Supersedes the `SCaaS` §4.6 `VestingVault` shape: per-grant isolation makes freeze and
  forced transfer of a regulated grant address-exact and needs no allowance, for ≈ 15 k gas (≈ 11 %) more per
  grant once (§4.7) — if wrong: payroll-scale streams cost a little more to create.
- **R210** (owner: distributions) **Merkle distribution off a node-indexed snapshot**, no balance checkpoints in
  tokens. One clone per distribution, counterfactual funding with `predict*` validation as R209; init never reverts
  on time: claims open at `opensAt = max(claimStart, createdAt + 1 hour)` and `admin` may `cancel` until then, so a
  late deploy shortens nothing below one hour of review. Permissionless claims pay only the leaf's account;
  `sweep()` of the remainder to `sweepTo` after `expiry` (or never). The snapshot is deterministic (§5.4), must
  classify every contract leaf, and is recomputable by anyone. Supersedes the `SCaaS` §4.8 `CouponPayer` — if
  wrong: a wrong root can be published; the review window, recomputation and `cancel` bound it.
- **R211** (owner: corporate actions; TW2 "balances never rebase") Split and reverse split are a **migration to a
  new token** through an `ExchangeOffer`. A scaled view is rejected: every integrator (DEX limits, vesting totals,
  Merkle leaves, allowances, ERP books) holds raw amounts. Bond redemption at maturity and fixed-price buybacks are
  `ExchangeOffer`s too (§6); a buyback at market is a DEX bid — if wrong: every holder acts once (gasless); dust
  stays in the old token, buyable by a cash offer.
- **R212** `ExchangeOffer` is gasless through a `trade` op leg exactly as `MetaTxDex`, plus a direct `transferFrom`
  path. Exact multiples only (`in·num % den == 0`, else `NotExactMultiple`). A **non-closable** offer must burn what
  it receives, requires `tokenIn.minter() == 0` at exchange time, and its `sweep()` never takes `tokenOut` below the
  live obligation `quote(tokenIn.totalSupply())` before `closesAt`; a non-zero `closesAt` on it is
  ≥ `opensAt + 365 days` (prescription is the issuer's terms, disclosed with a blocking notice) — if wrong: a short
  window or a live minter would let the issuer take unexchanged holders' new shares or redemption money (review H4).
- **R213** (owner: templates) Templates are **off-chain presets** (versioned JSON in the SDK and wizard) that map to
  one `createTiered` call plus optional action contracts; there is no on-chain preset factory (§7) — if wrong: a
  preset contract would freeze defaults that issuers must be able to change.
- **R214** (owner: managed markets, R124/R128) A **managed market** is a market on an `OrderBookDex` instance whose
  `admin` is the licensed venue operator's multisig and whose node policy has `managed = 1`: **home-bound only**
  (relayer-unbound orders refused at intake and never signed by our wallets), relayer fee mode `NONE` on regulated
  legs, node intake checks eligibility of both parties on every regulated leg, the book is **not gossiped by
  default**, and with gossip on only admin pre-trusted homes are listed (R128 automatic trust disabled). On chain
  the regulated token is the arbiter (its checks run inside `transferFrom`), so a pair with an ineligible party
  fails (`MatchFailed`) whoever settles it — if wrong: unbound orders would let unlicensed parties execute
  regulated trades.
- **R215** Families: **EVM and Hedera** in this spec (same Solidity; Hedera children add HIP-632 and the HTS
  fail-closed underlying checks). Cosmos, Soroban, Move, TON and Solana are PLANNED per family spec after their v2
  wrapper work (TW2 R145), mapping the same rulings onto native mechanisms (§10) — if wrong: nothing to undo.
- **R216** Action contracts (grants, distributions, offers) have **no owner and no upgrade**; their only privileged
  calls are `revoke`/`renounceRevocation` (grantor, if chosen), `approveMilestone` (approver, if chosen), `cancel`
  before `opensAt` (distribution admin), `close` (offer admin, only if `closable`). Remainders and stray tokens
  (`rescue(token)` for any token other than the contract's own) go only to a creation-time `sweepTo`/grantor, never
  to the caller. Every payout follows CEI (bit, `released` or `filledIn` written before the transfer) — if wrong: a
  permissionless sweep could redirect funds.
- **R217** `ELIGIBLE_CONTRACT` (registry flag that satisfies any `requiredFlags`) may be set **only by the registry
  admin**, only on **pass-through** contracts whose every outflow is re-checked by the token or goes only to a
  committed party (`VestingGrant`, `Distribution`, `ExchangeOffer` clones, `MetaTxDex`), with `validUntil =
  type(uint64).max`. Never on a TW2 wrapper, a Safe, a venue fee recipient or an EOA: those get ordinary flags
  for their controller — if wrong: one attestation would be a master key across every token on the registry
  (review M5).

---

## 3. Regulated module

### 3.1 Shape (library split is the base design, review M3)

The base tiers leave 2.9 k (Single), 2.0 k (Multi) and 0.7 k (Hedera Multi) bytes of headroom, less than the control
surface. So the module is split:

- **In the token** (per tier child): `tokenKind()`, `_init`, the overrides of `_update`, `_checkOp` and
  `payWithFee`, `forceTransfer` (it needs `ERC20._update`, internal to the token), the cheap getters, and one-line
  external stubs for every control function.
- **`RegulatedLib`** (linked library, external functions, deployed once per chain, linked in `Deploy.s.sol` and the
  Hedera deploy script): `recordOrder`, `revokeOrder`, `freeze`, `unfreeze`, `pause`, `unpause`, `renounceRole`,
  `disableControls`, `canReceive`. Each stub `DELEGATECALL`s it (Solidity external library call), so it runs on the
  clone's storage.
- **`RegulatedControls`** (abstract, no base contract): the ERC-7201 namespace
  (`keccak256(abi.encode(uint256(keccak256("scaas.regulated.v1")) - 1)) & ~0xff`), so the TW2 slot pins (slots 0–15)
  of every tier stay valid; the hooks `_forceMove(from, to, amount)` and `_regIsContract(a)`, implemented by the
  child (`_forceMove` calls `ERC20._update` directly, bypassing the overrides).
- Hedera: `HederaRegulatedNo/Single/MultiUnderlyingToken` add the signature override through `HederaV2Lib` (TW2 I3)
  **and** re-add the `_checkUnderlying` override with the fail-closed HTS checks (R144); both live in the sibling
  Hedera tier contracts today, not in the regulated parents (review L2).
- AS1 and AS2 gate on `forge build --sizes` ≤ 24 576 for all six regulated implementations.

### 3.2 Configuration and init

`initData = abi.encode(<the tier's TW2 fields…>, RegulatedConfig cfg)`: the tier fields decode as today (ABI
decoding ignores the extra trailing head word; a test pins this). **Order:** the child stores and validates
`RegulatedConfig` **first**, then runs the tier init, so a tier-1 `initialSupply` mint already sees the allowlist
(review L3). The initial supply goes to `creator`, the factory caller: an issuer whose treasury is a Safe makes the
Safe call `createTiered`.

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
| `issuer`, `compliance` have code (`_regIsContract`; 7702 designators are EOAs) | `RoleNotContract(a)` |
| `ALLOWLIST` ⇔ `registry ≠ 0 && requiredFlags ≠ 0`; registry has code | `RegulatedConfigInvalid()` |
| `termsHash ≠ 0` | `RegulatedConfigInvalid()` |
| tier-1 `initialSupply` recipient (`creator`) passes the receiver check | `NotEligible(creator, reason)` |

Storage (namespace): **hot slot** `registry (20) ‖ controls u8 ‖ pausedUntil u64` (29 bytes, read on every
transfer); `requiredFlags u64 ‖ cooldownUntil u64`; `issuer`; `compliance`; `termsHash`;
`mapping(address ⇒ FreezeState)`, `FreezeState = {slot a: until u64 ‖ episodeStart u64 ‖ issuerCooldownUntil u64;
slot b: recordId bytes32}` (the hot path reads slot a only); `mapping(bytes32 ⇒ OrderRecord)`.

### 3.3 Interface (replaces the `SCaaS` §14.6 proposal)

```solidity
interface IRegulatedToken {
    struct OrderRecord { address subject; address beneficiary; uint64 freezeUntil; bool revoked;
                         uint256 maxAmount; uint256 executed; }
    // recordId = keccak256(abi.encode(orderId, subject, beneficiary))
    event OrderRecorded(bytes32 indexed recordId, bytes32 indexed orderId, address indexed subject,
                        address beneficiary, uint256 maxAmount, uint64 freezeUntil, bytes32 documentHash);
    event OrderRevoked(bytes32 indexed recordId, bytes32 reasonRef);
    event AccountFrozen(address indexed account, bytes32 indexed ref, bytes32 recordId, uint64 until);
    event AccountUnfrozen(address indexed account, bytes32 indexed ref);
    event ForcedTransfer(bytes32 indexed recordId, address indexed from, address indexed to, uint256 amount);
    event Paused(bytes32 indexed ref, uint64 until);
    event Unpaused(bytes32 indexed ref);
    event ControlsDisabled(uint8 bits, uint8 remaining);
    event RoleRenounced(uint8 role);                              // 1 issuer, 2 compliance

    error Frozen(address account);
    error TokenPaused(uint64 until);
    error NotEligible(address account, uint8 reason);             // 1 not attested/flags missing, 2 expired, 3 attester disabled
    error FeeRecipientFrozen(address account);
    error NotIssuer(); error NotCompliance(); error ControlDisabled(uint8 control);
    error RefRequired(); error RoleNotContract(address a); error RegulatedConfigInvalid();
    error OrderExists(bytes32 recordId); error OrderUnknown(bytes32 recordId); error OrderInactive(bytes32 recordId);
    error SubjectNotFrozen(address subject); error OrderExceeded(uint256 remaining);
    error FreezeTooLong(uint64 maxUntil); error FreezeCooldown(uint64 until); error NotFrozen(address a);
    error PauseTooLong(uint64 until); error PauseCooldown(uint64 until);

    // views
    function controls() external view returns (uint8);
    function issuer() external view returns (address);
    function compliance() external view returns (address);
    function registry() external view returns (address);
    function requiredFlags() external view returns (uint64);
    function termsHash() external view returns (bytes32);
    function frozenUntil(address account) external view returns (uint64); // > now ⇔ frozen (and CTRL_FREEZE set)
    function isFrozen(address account) external view returns (bool);
    function pausedUntil() external view returns (uint64);
    function pauseCooldownUntil() external view returns (uint64);
    function canReceive(address account) external view returns (bool ok, uint8 reason);
    function order(bytes32 recordId) external view returns (OrderRecord memory);

    // compliance role
    function recordOrder(bytes32 orderId, bytes32 documentHash, address subject, address beneficiary,
                         uint256 maxAmount, uint64 freezeUntil) external returns (bytes32 recordId);
    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;   // ends a freeze backed by this record
    // issuer role
    function freeze(address account, bytes32 ref, bytes32 recordId) external; // recordId 0 ⇒ issuer-only (≤ 30 d)
    function unfreeze(address account, bytes32 ref) external;
    function forceTransfer(bytes32 recordId, uint256 amount) external;
    function pause(bytes32 ref, uint64 until) external;
    function unpause(bytes32 ref) external;
    function disableControls(uint8 bits) external;                        // one-way relaxation
    // either role, for itself, one-way (R202 relaxations)
    function renounceRole() external;
}
```

The node, venue and wallet compose a transfer pre-check from `isFrozen`, `canReceive`, `pausedUntil` and
`balanceOf` (one table of reason codes in the node: `1`/`2`/`3` receiver, `4` sender frozen, `5` paused, `6`
balance); there is no on-chain `checkTransfer` (size, §3.1).

### 3.4 Semantics per path

`R(a)` = receiver check (`ALLOWLIST` off ⇒ true; else `registry.hasFlags(a, requiredFlags)`, §3.7). `F(a)` =
`CTRL_FREEZE` set and `frozenUntil(a) > now`. `P` = `CTRL_PAUSE` set and `pausedUntil > now`.

| Path | Reverts when |
|---|---|
| `transfer`, `transferFrom` (incl. DEX settle), meta-tx transfer / `pay` / `trade` | `P`; `F(from)`; `!R(to)` |
| meta-tx `approve` op | `P`; `F(from)` (direct `approve` is unrestricted: `transferFrom` checks `F(from)`) |
| relayer fee (meta-tx step 7, `payWithFee`) | `F(feeRecipient)` ⇒ `FeeRecipientFrozen`; `!R(feeRecipient)` |
| mint (tier-1 `minter`, wrap) | `P`; `!R(to)` |
| holder `burn` (tier 1), the burn inside unwrap | `F(from)` (not `P`) |
| unwrap (direct, Multi, R148 op) | `F(from)` via the burn row; R148 op with a fee during `P` refused at step 6 (`TokenPaused`), because its fee leg is a transfer; the recipient is not checked (R204) |
| `forceTransfer` | §3.5 only (not `P`, not `F(from)`) |
| `addReserve` (wrapper tiers) | unchanged |

Step-6 placement (R207): the `_checkOp` override computes the resolved fee recipient and fee amount exactly as step 6
does (`m.feeRecipient == 0 ? msg.sender : m.feeRecipient`, `FeePolicy.compute`), applies the table for the op in
`m.data`, then calls `super._checkOp(m)`. The `_update` override re-applies the transfer/mint/burn rows for direct
paths; on the meta-tx path its reads are warm. Step 8 still cannot fail for a reason step 6 did not check (same
state in one transaction).

### 3.5 Freeze, order records and forced transfer

```
issuer:     freeze(account, ref, 0)            issuer-only episode: ref ≠ 0; not frozen ⇒ now ≥ issuerCooldownUntil
                                               (FreezeCooldown), episodeStart = now; until = min(now + 30 d,
                                               episodeStart + 60 d) (FreezeTooLong when no extension is left)
compliance: recordOrder(orderId, docHash, subject, beneficiary, maxAmount, freezeUntil)
                                               orderId, docHash ≠ 0; subject ≠ beneficiary, both ≠ 0; maxAmount > 0
                                               (0 allowed only with freezeUntil > now: a freeze-only order);
                                               recordId unused (OrderExists)
issuer:     freeze(subject, ref, recordId)     record live and names `subject`: until = record.freezeUntil
                                               (type(uint64).max = open-ended), FreezeState.recordId = recordId
issuer:     forceTransfer(recordId, amount)    CTRL_FORCE; record live (OrderUnknown/OrderInactive); F(subject)
                                               (SubjectNotFrozen); executed + amount ≤ maxAmount (OrderExceeded);
                                               !F(beneficiary), R(beneficiary); executed += amount, then _forceMove
issuer:     unfreeze(account, ref)             until = now; an issuer-only episode sets issuerCooldownUntil = now + 30 d
compliance: revokeOrder(recordId, reasonRef)   revoked = true; if FreezeState(subject).recordId == recordId the
                                               freeze ends now (issuer cooldown starts as above)
```

- Episode end by expiry is passive (`until ≤ now`); `issuerCooldownUntil` is written when the episode is set
  (`until + 30 d`) and refreshed on unfreeze, so no transaction is needed for the cooldown either.
- An amended order is a new `orderId`; a record is never edited. One order against several accounts = several
  records.
- Seizing a wrapper's backing: force-transfer wrapped units to a beneficiary, which unwraps (R208). Seizing to
  destroy: a beneficiary that burns or unwraps (R203).
- Contract holders are subjects like any other: a grant, distribution or offer clone can be frozen and seized from
  exactly; §4.4 and §5.2 define how those clones degrade (review M6).

### 3.6 Pause

```
pause(ref, until)   issuer; CTRL_PAUSE; ref ≠ 0; now < until ≤ now + 7 days (PauseTooLong);
                    now ≥ cooldownUntil (PauseCooldown; this also refuses a pause while paused)
                    pausedUntil = until; cooldownUntil = until + 7 days; Paused(ref, until)
unpause(ref)        issuer; paused; pausedUntil = now; cooldownUntil = now + 7 days; Unpaused(ref)
```

Expiry is passive. Integrators read `pausedUntil()` (research §1.10.2).

### 3.7 `ComplianceRegistry`

```solidity
interface IComplianceRegistry {
    event AttesterSet(address indexed attester, uint32 indexed attesterId, bool enabled);
    event Attested(address indexed account, uint64 flags, uint64 validUntil, uint32 indexed attesterId);
    error NotAdmin(); error NotAttester(); error AdminNotContract(address a); error LengthMismatch();
    error EligibleContractAdminOnly();

    function admin() external view returns (address);                 // immutable, a contract (multisig recommended)
    function setAttester(address attester, bool enabled) external;     // admin; ids assigned once, never reused
    function attesterId(address attester) external view returns (uint32);
    function attesterEnabled(uint32 id) external view returns (bool);
    function attest(address[] calldata accounts, uint64[] calldata flags, uint64[] calldata validUntil) external;
        // enabled attester, or admin (id 0); flags 0 = revoke; ELIGIBLE_CONTRACT only by admin (R217)
    function attestationOf(address account) external view returns (uint64 flags, uint64 validUntil, uint32 attesterId);
    function hasFlags(address account, uint64 required) external view returns (bool);
        // attesterEnabled(id) && validUntil ≥ now && ((flags & required) == required || flags & ELIGIBLE_CONTRACT != 0)
}
```

Flag bits (reused from the withdrawn `SCaaS` §14.5 proposal; meaning set by the issuer's policy, market-neutral):
`KYC_DONE = 1`, `ACCREDITED = 2`, `SANCTIONS_CLEAR = 4`, `ELIGIBLE_CONTRACT = 8` (R217); bits 16–63 issuer-defined.
One registry may serve many tokens; anyone may deploy one (plain deployment). Disabling an attester voids every
attestation it made in the same block (one extra SLOAD per check, `attesterEnabled`). The registry holds no personal
data: the ERP is the system of record for identity evidence and pushes only flags (§9.2). The node alerts 30 days
before any protocol clone's attestation would expire (it should not: R217 mandates `type(uint64).max`).

### 3.8 Interactions

| With | Rule |
|---|---|
| Meta-tx pipeline | §3.4 at step 6; step order, digest, typehash, nonces, named functions and `mtxBatch` unchanged; a failing batch item reverts the batch (TW2 R140), so the node re-checks the parties of every regulated item it batches |
| Node simulation and grief score | a post-simulation revert with `Frozen`, `TokenPaused`, `NotEligible` or `FeeRecipientFrozen` is exempt from the origin's grief score only if the node's re-simulation at the inclusion block's **parent** succeeds and the inclusion block contains a transaction from the token's `issuer`/`compliance` or from the registry (admin or attester) touching the failing account; attester-caused exemptions are capped at 3 per origin per day (a colluding attester buys at most that). The node refuses at intake intents whose `validUntil` exceeds the receiver's attestation `validUntil` |
| R26 lockdown | unchanged: spenders are contracts; the regulated check binds `from`/`to`, so an allowance to any contract cannot move tokens to an ineligible party |
| Single/Multi wrappers (own reserves) | R208; `wrap` is a mint (paused ⇒ refused; receiver check on `msg.sender`); `disableWrap` and the rate timelock unchanged; a pending rate change and a pause can overlap; fee-less unwrap stays open in both |
| `*_REG` as an underlying | refused by the wizard (R208); if forced, freezing the wrapper blocks only that leg and a seizure breaks that wrapper's R134 (AS6 test documents it) |
| `OrderBookDex` | settle's `transferFrom` runs the regulated check per leg; a failing leg fails only its pair (`MatchFailed`); `checkOrder` does not see freezes or eligibility, so the venue adds the §3.3 pre-check (§8.2); market fee recipients on a regulated leg need `R` |
| `MetaTxDex` | the `to` of every `trade` leg: attested `ELIGIBLE_CONTRACT` by the registry admin (R217) |
| `MandateWallet` | it calls `payWithFee`; the wallet is the `from` and must not be frozen; payees need `R` |
| Vesting / distribution / offer clones | holders like any other; attested `ELIGIBLE_CONTRACT` before funding (the address is known in advance, R209) |
| Zether | none (non-goal) |

### 3.9 Disclosure (mandatory, R201)

The wizard refuses to create, and wallets show a blocking notice before a first receive, with: kind (`*_REG`),
each enabled control in plain words, `issuer`, `compliance` and whether they are the same contract, the registry,
its admin and `requiredFlags`, `termsHash` with a link to the document, and these statements, kept to the enabled
bits:

- *"The issuer can freeze any account for up to 30 days, extendable to 60, and not again for 30 days after. Longer
  or open-ended freezes require an order recorded by the compliance role, and end when that order is revoked."*
- *"With a recorded order naming an account, the issuer can move tokens out of that frozen account to the
  beneficiary named in the order, up to the recorded amount."*
- Wrapper tiers: *"The issuer can pause transfers for up to 7 days at a time, with at least 7 days between pauses.
  Unwrapping is never paused, and frozen accounts cannot unwrap."* Tier 1: *"The issuer can pause transfers for up
  to 7 days at a time, with at least 7 days between pauses. Redemption, buyback and exchange offers are paused too;
  only burning stays open."*
- *"Receiving requires an attestation from the registry above; its admin chooses the attesters. The issuer can
  switch this check off for good, never on."*
- *"The issuer cannot mint outside the minter rules, change rates beyond the rate rules, or touch the reserve."*

Wallets mark accounts named in a live `OrderRecorded`.

### 3.10 Security analysis

Invariants (each an invariant test, §3.12):

- I1 `Σ balances == totalSupply` (forced transfer is a move); wrapper tiers keep TW2's `collateralValue() ≥
  totalSupply()` and per-leg conservation across every regulated call.
- I2 Every `ForcedTransfer` has a live record, a subject frozen at execution, `to == beneficiary`, and cumulative
  `executed ≤ maxAmount`.
- I3 No balance of a frozen account decreases except by `ForcedTransfer`.
- I4 While paused, no transfer, mint or meta-tx op other than a fee-less unwrap succeeds; unwrap and burn always do
  (absent freeze and TW2 limits); no two pauses are closer than 7 days; no pause exceeds 7 days.
- I5 Every receiver of a balance increase passed `R` at that block, while `ALLOWLIST` is on.
- I6 No regulated call changes the token's own `reserve_i`, `num_i/den_i`, `wrapEnabled_i` or `minter`;
  `controls()` only loses bits.
- I7 No issuer-only freeze episode exceeds 60 days, and two issuer-only episodes on one account are ≥ 30 days apart.

| # | Abuse | Outcome |
|---|---|---|
| A1 | Compromised `issuer` alone | freezes anyone for ≤ 60 days (then a 30-day gap), pauses ≤ 7 of every 14 days, disables controls (relaxations only); **cannot move funds or freeze longer** without a compliance record. Every call emits |
| A2 | Compromised `compliance` alone | records fake orders; cannot execute. Node/ERP alert on every `OrderRecorded` |
| A3 | Both compromised, or `issuer == compliance` | open-ended freezes and seizure up to recorded amounts: the nature of a regulated token. Mitigation: separate multisigs with an external seat, alerts, disclosure |
| A4 | Subject front-runs a freeze | moves funds first. Mitigation: private submission (as the TW2 guardian, §8.4); moot on private chains |
| A5 | Replay / over-execution of an order | cumulative `executed ≤ maxAmount`; records immutable; revocation stops it |
| A6 | Wrong beneficiary | impossible without a new record by `compliance` |
| A7 | Registry admin compromised | attests anyone (allowlist bypass) or voids attesters (receives fail); no fund movement; the issuer can `disableControls(ALLOWLIST)`. Disclosed; registry pinned at creation |
| A8 | Attestation lapse | receivers fail; holders still send to eligible parties, burn and unwrap (R206) |
| A9 | Fee griefing with a frozen/ineligible fee recipient | fails at step 6 (cheap) |
| A10 | Unwrap to a frozen accomplice | out of scope: the underlying is a different asset; the holder itself must be unfrozen to unwrap (R204) |
| A11 | Rolling pauses | bounded by the cooldown; wrapper exits stay open; tier-1 regulated tokens are disclosed as pausable half of the time, offers included |
| A12 | Frozen holder escapes via DEX | `transferFrom` checks `F(from)`; the pair fails; the venue drops the maker's orders on `AccountFrozen` |
| A13 | Forced transfer from a protocol clone | address-exact; the clone degrades as §4.4/§5.2 define |
| A14 | Renounced or dead issuer | `issuer` renounce clears `FREEZE|FORCE|PAUSE` (all freezes end); a dead issuer multisig leaves issuer-only freezes ending within 60 days and record-backed ones at `freezeUntil` or when compliance revokes |
| A15 | Dead registry | `disableControls(ALLOWLIST)` by the issuer; migration offers then work again |

### 3.11 Gas (estimates; measured numbers replace them in `test/as/RegulatedGas.t.sol`)

Per transfer on top of the TW2 row: hot-slot SLOAD (2 100 cold) + `FreezeState(from)` slot a (2 100 cold) ≈
**+4.3 k** without allowlist; with allowlist, per checked receiver a registry call (cold account 2 600 + attestation
slot 2 100 + `attesterEnabled` 2 100 + call overhead) ≈ **+8 k**; a meta-tx with a fee checks two receivers ≈ +16 k.
The `_update` re-check on the meta-tx path is warm (≈ +0.5 k). Control calls add one library `DELEGATECALL`
(≈ 2.6 k cold). Unregulated kinds: **0** (R200). `recordOrder` ≈ 95 k (4 new slots), `forceTransfer` ≈ 60 k,
`freeze` ≈ 27–50 k.

### 3.12 Tests (`test/as/`)

| Area | Tests |
|---|---|
| Init | every refusal of §3.2; EOA and 7702 roles refused; `FORCE` without `FREEZE`; tier fields decode unchanged with the trailing config; config stored before the tier-1 mint (allowlist refuses an unattested `creator`) |
| Factory (AS1 gate) | `FactoryV2.t.sol`: each `*_REG` kind with counts 0/1/2/8/9; REG↔base kind mismatch at registration and at `createTieredUnregistered`; v1 entry points refuse 5–7 |
| Paths | each row of §3.4 on all three tiers, direct and meta-tx (generic, named, `mtxBatch`), refused at step 6 (gas of a refused intent < 40 k); `payWithFee` override emits exactly the base events |
| Freeze | issuer-only 30 d, extension to 60 d from episode start, `FreezeTooLong`, `FreezeCooldown` after expiry and after unfreeze, record-backed freeze to `freezeUntil`, ended by `revokeOrder`, open-ended record |
| Orders | record/revoke/execute; `SubjectNotFrozen`; `OrderExceeded` at the exact edge; beneficiary frozen/ineligible; same `orderId` with two subjects |
| Pause | 7-day bound, cooldown from actual end, passive expiry, refused while paused (`PauseCooldown`), fee-less unwrap op and burn during pause, fee-bearing unwrap op refused at step 6, forced transfer during pause |
| Relaxations | freeze then `issuer` renounce ⇒ holder transfers and unwraps; `compliance` renounce clears `FORCE`; `disableControls(ALLOWLIST)` with a reverting registry |
| Wrappers | frozen holder unwrap refused (direct, Multi, R148 op); a holder with a lapsed attestation unwraps; unwrap works while the registry reverts; reserves untouched by every regulated call; guardian/rate flows unchanged; `*_REG` as an underlying: freezing the wrapper blocks only that leg |
| DEX | `OrderBookDex.settle` with a frozen maker, an ineligible taker, an ineligible market fee recipient: only that pair fails |
| Keywords | TW2 v2 gas table and layout pins identical after the `virtual` changes |
| Registry | admin contract only; attester add/remove; disable voids its attestations; batch attest; revoke by flags 0; expiry; `ELIGIBLE_CONTRACT` by admin only |
| Hedera | each `HederaRegulated*` signs via HIP-632; HTS fail-closed checks and association on Single/Multi regulated children; layout pins for all three |
| Sizes | `--sizes` ≤ 24 576 for the six regulated implementations |
| Invariant | handlers: transfers, meta-tx with fees, wraps/unwraps, freezes (both kinds), records, forced transfers, pauses with `warp`, renounces, `disableControls`, attester disable and attestation expiry by the registry admin; invariants I1–I7 |

---

## 4. Vesting and streaming (R209)

### 4.1 Roles and flow

`grantor` (funds, may revoke if `revocable`), `beneficiary` (receives; should be a `SubjectAccount` so a lost key is
recoverable, `SCaaS` §9.4), `approver` (optional, milestones only; a Safe or `SubjectAccount` approves through a
sponsored call), relayer (submits anything; earns nothing on chain).

```
1. client builds GrantParams p; grant = AssetFactory.predictGrant(p)    // reverts on any invalid p (R209)
2. grantor signs a gasless transfer (or pay op with entryRef = p.ref) of p.total to `grant`; relayer submits
   (regulated token: registry admin attests `grant` ELIGIBLE_CONTRACT first, R217)
3. anyone: AssetFactory.createGrant(p) → clone at `grant`; init reverts only Underfunded(balance, total)
4. over time: anyone calls release() → pays releasable() to beneficiary
5. milestones: approver calls approveMilestone(i, ref)
6. optional: grantor revoke() → unvested part to grantor; vested part stays releasable
```

### 4.2 Interface (replaces the `SCaaS` §14.8 proposal)

```solidity
interface IVestingGrant {
    struct Tranche { uint64 at; uint192 amount; }
    struct GrantParams {
        address token; address grantor; address beneficiary; uint256 total;
        uint64 start; uint64 cliff; uint64 end; uint32 interval;   // linear; all zero when tranches are used
        Tranche[] tranches;                                         // ≤ 16, Σ amount == total; `at` strictly
                                                                    //   increasing without approver, non-decreasing with one
        address approver;                                           // tranches only; 0 ⇒ time-only tranches
        bool revocable;
        bytes32 ref;                                                // grant id in the ERP (salt and reconciliation)
    }
    event Released(uint256 amount, uint256 releasedTotal);
    event Revoked(uint256 vestedAtRevoke, uint256 returned);
    event RevocationRenounced();
    event MilestoneApproved(uint8 indexed index, bytes32 ref);
    event ExcessSwept(uint256 amount);
    event Rescued(address indexed token, uint256 amount);
    error Underfunded(uint256 balance, uint256 total); error ScheduleInvalid(); error NotGrantor();
    error NotRevocable(); error AlreadyRevoked(); error NotApprover(); error AlreadyApproved(); error NothingToRelease();
    error OwnToken();

    function release() external returns (uint256 amount);              // anyone
    function revoke() external;                                         // grantor, if revocable
    function renounceRevocation() external;                             // grantor, one-way
    function approveMilestone(uint8 index, bytes32 ref) external;       // approver, one-way
    function sweepExcess() external returns (uint256);                  // anyone; pays grantor
    function rescue(address token) external returns (uint256);          // anyone; any token ≠ p.token, to grantor
    function vestedAmount(uint64 at) external view returns (uint256);
    function releasable() external view returns (uint256);
    function params() external view returns (GrantParams memory);
    function released() external view returns (uint256);
}
```

`AssetFactory.predictGrant(p)` runs every check of §4.3 and `token ≠ 0`, `grantor ≠ 0`, `beneficiary ∉ {0, grant}`,
`total > 0`, and reverts `ScheduleInvalid` otherwise; `createGrant` runs the same checks.

### 4.3 Schedule math

Linear (`tranches` empty): `start ≤ cliff ≤ end`, `start < end`, `interval ≤ end − start`, `approver == 0`.

```
vested(t) = 0                                   if t < cliff
          = total                               if t ≥ end
          = mulDiv(total, e, end − start)       otherwise, e = interval == 0 ? t − start
                                                                   : ⌊(t − start)/interval⌋ · interval
```

Tranches: `vested(t) = Σ amount_i` over tranches with `at_i ≤ t` and (no approver or approved_i). "Fixed periods"
are tranches without an approver, "milestones" tranches with one (`at` = earliest date, may be 0). After `revoke()`,
`vested(t) = cap` (the value at revocation) for all `t`. `releasable() = min(vested(now) − released, balance)`.

### 4.4 Revocation, approval, excess, seizure

- `revoke()`: `cap = vested(now)`; returns `min(total − cap, balance)` to `grantor`; the vested remainder stays
  releasable (pull-style for the beneficiary). The grantor can front-run a pending milestone approval with a revoke
  (that milestone is then unvested): disclosed as part of the revocable bargain. A frozen grantor (regulated token
  `F(grant)` is what matters, not the grantor) does not block revoke; a frozen grant blocks every outflow.
- `renounceRevocation()`: one-way; turns a revocable grant into an irrevocable one.
- `approveMilestone`: approver only, one-way (`AlreadyApproved` on repeat). Approvers that are agents use a
  `SubjectAccount` or `MandateWallet`-style contract and a sponsored call job; no grant-level signature type.
- `sweepExcess()`: pays the grantor `balance − (obligation − released)`, saturating at 0 (`obligation = cap` after
  revoke, else `total`).
- **After a seizure** (forced transfer from the grant, §3.5): the **beneficiary bears it first** — `release` pays
  `min(releasable, balance)` and, at revocation, the grantor is paid its unvested part from what is left. Rationale:
  a court order names the grant address because of the beneficiary's entitlement. (Review M6's suggested revoke
  formula reserved the vested part for the beneficiary, which contradicts its own "beneficiary-first" principle; this
  spec takes the principle.) No path reverts on a short balance.
- CEI: `released` and `cap` are written before every transfer; tests use a token with a transfer hook.

### 4.5 Meta-tx, node, ERP, app

- No new typehash anywhere. Funding uses existing gasless transfer/`pay` (an `entryRef` = `p.ref` lets the ERP
  reconcile the funding as a normal payment, R9). `release()`, `createGrant`, `approveMilestone` (through the
  approver's account contract) are sponsored `call` jobs (NI job API).
- Node: normaliser events `GrantCreated`, `Released`, `Revoked`, `RevocationRenounced`, `MilestoneApproved`,
  `ExcessSwept`, `Rescued`; "release every N days" is an ERP-pushed `call` job, not node logic.
- ERP: grant register (beneficiary, schedule, vested/released mirrors), funding as a payment, revocation as a
  journal reversal of the unvested part.
- App: beneficiary page (schedule chart, releasable, release button that posts a sponsored job), grantor page.

### 4.6 Security

Invariants: `released ≤ vested(now) ≤ total` (or `≤ cap`); without seizure `token.balanceOf(grant) ≥ obligation −
released` for a well-behaved token; only the beneficiary receives `release`; only the grantor receives
`revoke`/`sweepExcess`/`rescue`; `vested` is monotone in `t`; no call reverts because the balance is short.

| Abuse | Outcome |
|---|---|
| Someone deploys a different grant at the funded address | impossible: the address commits to every parameter |
| Funds sent to an address for invalid params | `predictGrant` refuses invalid `p`; the SDK funds only returned addresses |
| Funds sent, never deployed / partial funding | anyone can deploy; `Underfunded` until topped up |
| Third party calls `release()` early | pays the beneficiary what is vested; nothing else |
| Approver compromised | approves milestones whose date has passed; cannot redirect funds |
| Grantor revokes before the cliff or ahead of an approval | the revocable bargain; disclosed |
| Stray tokens (a dividend paid to the grant) | `rescue` to the grantor; the snapshot policy attributes grants anyway (§5.4) |
| Token with transfer fee / rebasing | unsupported (v2 tokens have neither); the wizard refuses non-v2 tokens without an override flag |

### 4.7 Gas (estimates)

| Operation | Grant clone (chosen) | Vault (rejected) |
|---|---|---|
| create | clone ≈ 41 k + init ≈ 5 slots × 22.1 k ≈ 110 k (+22 k per tranche) ⇒ ≈ 155 k | ≈ 110 k + `transferFrom` ≈ 30 k ⇒ ≈ 140 k, plus an allowance first |
| fund | one transfer (≈ 35–60 k as meta-tx) | inside create |
| release | ≈ 45–60 k (token transfer + 1 SSTORE) | similar |

≈ +15 k (≈ 11 %) per grant once. Streaming payroll per short pay period is cheaper as `mtxBatch` of `pay` ops (TW2
§7.4); grants suit periods of a quarter or more and incentive vesting.

### 4.8 Tests

Unit: schedule edges (`t = cliff − 1, cliff, end`), interval steps, tranche ordering (strict vs non-decreasing) and
Σ checks, `predictGrant` refusing every invalid shape, approver gating, revoke before/after cliff and after full
vesting, `renounceRevocation`, `sweepExcess` saturation, `rescue` (refuses `p.token`), counterfactual funding then
deploy, `Underfunded`, regulated token (grant frozen ⇒ release reverts; beneficiary frozen ⇒ release credits, R204;
seize half, then release, revoke and sweep), hook token (CEI). Fuzz: `vested` monotone and ≤ total;
`Σ released + returned + swept ≤ funded`. Invariant: handlers release/revoke/approve/warp/stray transfers/seizure.

---

## 5. Dividend and coupon distribution (R210)

### 5.1 Flow

```
1. issuer picks recordToken, recordBlock (final), payout pool and policy (exclusions, protocol-clone attribution)
2. node builds the snapshot (§5.4) → root, total, leafCount, leaves; anyone can recompute
3. client builds DistParams p; dist = AssetFactory.predictDistribution(p) (reverts on invalid p); issuer funds `dist`
4. anyone: AssetFactory.createDistribution(p) → init reverts only Underfunded; opensAt = max(claimStart, now + 1 h)
5. review window [createdAt, opensAt): admin may cancel() → all funds to sweepTo
6. claims from opensAt: anyone submits claim(index, account, amount, proof) → pays `account`
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
    event Rescued(address indexed token, uint256 amount);
    error NotOpen(uint64 opensAt); error ClaimsClosed(uint64 expiry); error AlreadyClaimed(uint256 index);
    error BadProof(); error NotAdmin(); error ReviewOver(); error NotExpired(); error IndexOutOfRange();
    error TotalExceeded(); error OwnToken(); error ParamsInvalid();

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external;
    function claimMany(Claim[] calldata cs) external;  // skips already-claimed items, reverts on a bad proof
    function cancel() external;                          // admin, now < opensAt
    function sweep() external;                           // anyone, expiry ≠ 0 && now > expiry
    function rescue(address token) external returns (uint256); // anyone; any token ≠ payoutToken, to sweepTo
    function opensAt() external view returns (uint64);
    function isClaimed(uint256 index) external view returns (bool);
    function claimedTotal() external view returns (uint256);
}
```

`predictDistribution` checks (state-independent, `ParamsInvalid`): `root ≠ 0`, `total > 0`, `leafCount > 0`,
`expiry == 0 || expiry ≥ claimStart + 30 days`, `sweepTo ≠ 0`, `payoutToken ≠ 0`. Init adds only the balance check.
A distribution deployed after its `expiry` opens and is immediately sweepable: funds return to `sweepTo`, never
lost. Claimed bitmap `mapping(uint256 ⇒ uint256)`; the bit is set before the transfer (CEI). `claimedTotal ≤ total`
is checked on every claim (`TotalExceeded`), so a root whose leaves exceed `total` never overpays. **After a
seizure** from the distribution clone, claims are first-come until the balance runs out; the last claimants lose
(disclosed; the order names the clone, so the issuer refunds off chain).

### 5.3 Coupons and dividends

- Dividend: pool `D` over eligible balance `S`: `amount_i = ⌊D·b_i/S⌋`; dust stays and is swept.
- Coupon: per-unit amount `num/den` (payout raw units per bond raw unit): `amount_i = ⌊b_i·num/den⌋`;
  `total = Σ amount_i`.
- One distribution per payment date; the ERP schedules them from the bond terms. Funding remains the issuer's
  obligation: the contracts make payment automatic **once funded** (corrects the SRS §3.6 wording).

### 5.4 Snapshot (node, deterministic)

Input: `(chain_key, recordToken, recordBlock, policy)` with `recordBlock` final under the chain's finality gate.
Balances = replay of every finalized `Transfer` of `recordToken` from its creation block (node indexer watch list,
NI P4) to the end of `recordBlock`; must equal `balanceOf(a)` at `recordBlock` for a sampled set (archive RPC
quorum) or the build fails.

Policy (canonical JSON, `policyHash = keccak256` of its RFC 8785 bytes): excluded addresses (issuer treasury, DEX,
offers) and attribution of protocol clones (`VestingGrant` balances to their beneficiary, to the grantor, or
excluded — issuer's choice). The builder **must** classify every leaf that has code: every `AssetFactory` clone
(known from its events, including counterfactual grant addresses funded before `GrantCreated`, detected by
`predictGrant` of pending ERP grants) and the token's own address are excluded or attributed, and any other
contract leaf **fails the build** unless the policy lists it (review M8). Frozen holders stay in (a freeze does not
seize entitlement; payment credits them, R204).

Tree (review L1): **OZ `StandardMerkleTree` v1** with leaf encoding `["uint256","address","uint256"]` =
`(index, account, amount)`, leaf = `keccak256(bytes.concat(keccak256(abi.encode(index, account, amount))))`,
`sortLeaves = true` (the tree's own hash order), complete-tree array layout, commutative (sorted-pair) node hashing
as `MerkleProof.verify`. `index` is the position in the list sorted by `account` ascending with zero amounts
dropped; it appears only inside the leaf. Vectors `test/vectors/merkle_dist_vectors.json` (Solidity, Rust node,
Python ERP) include 1, 2, 3, 7 and 2¹⁰ + 1 leaves.

Output: root, total, leafCount, leaves file (CSV + JSON), proofs. Node API (NI job-API conventions,
namespace-scoped): `POST /v1/snapshots {chain, token, block, policy}` → `{id}`; `GET /v1/snapshots/{id}` →
`{state, root, total, leaf_count, policy_hash}`; `GET /v1/snapshots/{id}/leaves`; `GET
/v1/snapshots/{id}/proof?account=` (public data). CLI `scaas-node snapshot verify <file>` recomputes a root from chain
without trusting the store. The node is not trusted for the root (NI T7): the review window and independent
recomputation are the control.

### 5.5 Meta-tx, ERP, app

Claims and `claimMany` are sponsored `call` jobs (≤ 100 claims per tx); no signature is needed because a claim pays
only the leaf's account. ERP: a declared distribution is a payable; `Claimed` reduces it; `Cancelled`/`Swept`
reverse the remainder. App: holder page lists claimable distributions with a claim button.

### 5.6 Security

Invariants: each index paid once; `claimedTotal ≤ total ≤ funded`; nothing leaves except to a leaf account
(claims) or `sweepTo` (cancel before `opensAt`, sweep after `expiry`, rescue of foreign tokens).

| Abuse | Outcome |
|---|---|
| Wrong root (issuer or node error, lying node) | ≥ 1 h review + recompute + `cancel`; after `opensAt` the `total` cap bounds the loss to the pool |
| Funds sent to an address for invalid params / deploy after `claimStart` | `predict*` refuses invalid `p`; init never reverts on time (R210) |
| Second-preimage of an inner node as a leaf | double-hashed leaves |
| Admin cancels after claims open | `ReviewOver` |
| Early sweep | `NotExpired`; with `expiry = 0` never |
| Griefing claims | pay the rightful account only |
| Leaf that is a protocol clone (cannot move `payoutToken`) | build fails unless classified; `rescue` recovers stray payouts to grants/offers |

### 5.7 Gas and tests

Claim ≈ 30 k + 0.4 k × ⌈log₂ leafCount⌉ + the payout transfer (≈ 30–55 k): ≈ 65–95 k for 10⁵ holders;
`claimMany` saves the 21 k intrinsic per item. Create ≈ clone 41 k + 6 slots ≈ 175 k. Tests: proof vectors (odd
counts), duplicate index, bad proof, `claimMany` skip semantics, `predictDistribution` refusals, deploy after
`claimStart` (opens at `now + 1 h`) and after `expiry`, time edges, cancel window, sweep, over-`total` root, rescue,
seizure then claims (first-come), hook token (CEI), regulated payout token (frozen account credited, ineligible
account refused — the policy must exclude or the issuer attest), fuzz over random trees (≤ 2¹⁰ leaves), invariant
handlers claim/cancel/sweep/warp.

---

## 6. Corporate actions: `ExchangeOffer` (R211, R212)

### 6.1 One contract, four uses

| Use | `tokenIn` | `tokenOut` | `num/den` | Window | `closable` | `sink` |
|---|---|---|---|---|---|---|
| Bond redemption at maturity | bond (tier-1 REG, minter renounced) | payout stablecoin | face value per unit | `opensAt = maturity`, `closesAt = 0` or ≥ `opensAt + 365 d` per the terms | no | 0 (burn) |
| Buyback (tender at a fixed price) | equity | stablecoin | price | issuer's choice, `capIn` | yes | issuer treasury or 0 |
| Split `1 : k` | old equity (minter renounced) | new equity (pre-minted `k × supply` to the offer) | `k/1` | `closesAt = 0` (default) or ≥ 365 d | no | 0 (burn) |
| Reverse split `k : 1` | old equity (minter renounced) | new equity | `1/k` | as split | no | 0 (burn) |

A buyback at market is a bid on a managed market (§8), not an offer. Wrapper tokens are not split (an
adjustable-rate token re-pegs through TW2 §6).

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
    event Rescued(address indexed token, uint256 amount);
    error NotOpen(); error ClosedOffer(); error CapExceeded(uint256 remaining); error NotExactMultiple();
    error InsufficientOut(uint256 have, uint256 need); error NotATradeLeg(); error LegNotRoutedHere();
    error CounterTokenMismatch(); error PriceNotMet(uint256 out, uint256 min); error FeeWouldStick();
    error DeltaMismatch(uint256 got, uint256 expected); error NotAdmin(); error NotClosable(); error SinkRequired();
    error MinterLive(address minter); error ParamsInvalid(); error OwnToken();

    function exchange(MetaTxLib.MetaTransaction calldata leg, bytes calldata sig) external returns (uint256 out);
    function exchangeDirect(uint256 amountIn, uint256 minOut) external returns (uint256 out);
    function close() external;                 // admin, only if closable
    function sweep() external returns (uint256); // anyone; tokenOut → sweepTo, bounded by the obligation (below)
    function rescue(address token) external returns (uint256); // any token ∉ {tokenIn, tokenOut}, to sweepTo
    function quote(uint256 amountIn) external view returns (uint256 out);
    function obligation() external view returns (uint256); // non-closable, before closesAt: quote(tokenIn.totalSupply())
    function filledIn() external view returns (uint256);
}
```

`exchange` (gasless): `leg` is a `trade` op on `tokenIn` signed by the holder with `data = trade(tokenOut,
minCounterValue, counterparty ∈ {0, this})`, `to = relayer = this`, `MODE_RESTRICT_RELAYER`, fee `NONE` or a bound
`feeRecipient ∉ {0, this}` — the `MetaTxDex._terms`/`_checkRouting`/`_pull` checks verbatim (shared library
extracted from `MetaTxDex`, no behaviour change there). The offer calls `tokenIn.executeMetaTransaction(leg, sig)`,
requires the measured delta `== leg.value`, computes `out`, requires `out ≥ minCounterValue`, `filledIn + in ≤ capIn`,
the window open, non-closable ⇒ `tokenIn.minter() == 0` (`MinterLive`), and `tokenOut.balanceOf(this) ≥ out`; writes
`filledIn` (CEI), burns (`NoUnderlyingToken.burn`) or forwards to `sink`, then pays `out` to `leg.from`.
`exchangeDirect`: same checks with `transferFrom(msg.sender)` (the holder approved this contract, R26).

`predictOffer` checks (`ParamsInvalid`/`SinkRequired`): `num, den ∈ [1, 2⁹⁶)`; `tokenIn ≠ tokenOut`; `closesAt == 0 ||
closesAt > opensAt`; `sweepTo ≠ 0`; `closable == false` ⇒ `sink == 0` and (`closesAt == 0 || closesAt ≥ opensAt +
365 days`); `sink == 0` ⇒ `tokenIn.tokenKind() ∈ {META_NONE, META_NONE_REG}`. Offers need not be funded at creation
(a redemption offer is created at issuance and funded at maturity); an exchange that cannot be paid reverts
`InsufficientOut`.

`sweep()`: closable offer after `close()` or `closesAt` — all `tokenOut` to `sweepTo`. Non-closable offer — before
`closesAt` (or forever with `closesAt == 0`) only `balance − obligation()` (saturating); after `closesAt` all of it.
With a burn sink, `tokenIn.totalSupply()` is exactly the unexchanged supply, so no holder's entitlement can be
swept before the disclosed prescription date. A seizure is not possible from the offer's `tokenOut` balance without
a forced transfer by `tokenOut`'s own issuer, which then reduces what late holders get (first-come).

### 6.3 Splits in practice

1. Issuer renounces the old token's minter, creates the new token with the same template (same regulated config;
   new `termsHash` referencing the action) and `initialSupply = ⌈S_old·num/den⌉` to itself, then transfers it to
   the offer (or funds the counterfactual address).
2. Holders exchange (gasless) multiples of `den/gcd(num, den)`; the wallet computes the amount and shows the dust.
3. Dust stays in the old token; a buyback offer (cash in lieu) can absorb it.
4. The old token remains valid. A pause of the old token also pauses the exchange (R205), so issuers do not pause
   during the window. Unexchanged holders keep their claim until `closesAt` (never, by default).
5. DEX: the venue delists the old market and lists the new one; resting orders on the old token expire or are
   cancelled.

### 6.4 Security, gas, tests

Invariants: `filledIn ≤ capIn`; every `Exchanged` paid exactly `in·num/den`; no `tokenOut` leaves except to a holder
or to `sweepTo` within the sweep rule; a non-closable offer's balance never drops below `obligation()` through
`sweep` before `closesAt`; `tokenIn` is burned or at `sink`. Abuse: a leg replayed (token nonce), a leg routed to
another offer (`LegNotRoutedHere`), a fake token delta (measured), reentrancy via hooks (transient guard, CEI), early
close of a non-closable redemption (`NotClosable`), issuer sweeping unexchanged entitlement (bounded by
`obligation`), a live minter diluting the pool (`MinterLive`), rate typo (bounded by the funded balance; the wizard
shows the human rate). Gas: ≈ MetaTxDex leg (≈ 60 k) + burn (≈ 8 k) + minter read (2.1 k) + payout (≈ 30–55 k) ≈
110–130 k. Tests: both paths, exact-multiple edges, cap edge, window edges, sink vs burn, `predictOffer` refusals,
`SinkRequired` for wrapper `tokenIn`, `MinterLive`, sweep bounded by `obligation` before `closesAt` and full after,
rescue, regulated `tokenIn` (offer `ELIGIBLE_CONTRACT`; frozen holder refused at step 6; paused ⇒ refused) and
regulated `tokenOut` (ineligible holder refused), fuzz `num/den` ∈ [1, 2⁹⁶) with the TW2 rate vectors' edge set.

---

## 7. Asset templates (R213)

Presets live in `sdk/asset_templates.json` (versioned; the wizard, the app and the ERP read the same file) with a
vector per preset (`initData` bytes for given inputs). Each preset names its kind, `initData` builder, required
inputs, defaults, follow-up actions and disclosure text.

| Template | Kind | Defaults | Follow-ups |
|---|---|---|---|
| **Equity** (shares, units of a fund) | `META_NONE_REG` | `decimals 0`; `initialSupply` to the issuer treasury Safe (the Safe calls `createTiered`, §3.2); `minter` = issuance multisig or 0 (fixed); `controls = FREEZE|FORCE|PAUSE|ALLOWLIST`; `requiredFlags = KYC_DONE|SANCTIONS_CLEAR` (+ `ACCREDITED` for restricted offerings); fee `NONE` | dividends (§5), splits/buybacks (§6), managed market (§8), vesting of employee grants (§4) |
| **Bond** | `META_NONE_REG` | `decimals 0` (1 unit = 1 denomination); supply minted at issuance, **minter renounced** after (required by the redemption offer); controls as equity; `termsHash` covers face, coupon dates and rate, maturity, redemption offer address and any prescription date | one `Distribution` per coupon date; one `ExchangeOffer` (redemption, burn, `opensAt = maturity`) created at issuance |
| **Loyalty points** | `META_NONE` | `decimals 0`; `minter` = the issuer's mint contract (rate limits live there, TW2 §4); fee `NONE`; no regulated module. Prepaid points: `META_SINGLE` with a rate (TW2 §6.4 example, 1 USDC → 100 points) | campaigns as `Distribution` of points; redemption = `pay` to the merchant |
| **Voucher** (gift card, coupon) | `META_NONE` (or `META_SINGLE` for prepaid value) | `decimals 0`, 1 unit = 1 voucher of the stated face value; issuer minter; validity = the redemption offer's window | issuance by mint or `Distribution` (campaign); merchants accept by `pay`; issuer redeems merchants' vouchers by a **closable** `ExchangeOffer` (voucher → payout, burn) whose `closesAt` is the expiry |

Points and vouchers do not expire on chain (balances never change, TW2); expiry is the end of the issuer's
redemption offer, disclosed as such. A loyalty or voucher issuer who needs freeze or allowlist picks the `*_REG`
kind of the same tier; the wizard then applies §3.9. The wizard refuses a `*_REG` token as the underlying of any
wrapper template (R208).

---

## 8. Managed DEX markets (R214)

### 8.1 Venue

- The licensed operator deploys its own `OrderBookDex` instance (`admin` immutable = its multisig, RS5-1) and lists
  only managed pairs; its listing power covers only its venue. Contract unchanged.
- Node config per market: `dex_market.managed = 1`, `unbound = 0` (forced), `gossip = 0` (default),
  `eligibility_tokens` (the regulated legs; read from `versionOf(token).kind`). A venue-level registry for pairs of
  two unregulated tokens is PLANNED only (no requester).
- Wallets show managed markets with the venue name, the regulated legs' disclosures (§3.9) and the eligibility
  result for the user before signing.

### 8.2 Intake and matching (node, DEX §3.4 additions)

| Point | Check | Refusal |
|---|---|---|
| Order intake | `relayer == our lane` (RS5-9, mandatory for managed); relayer `feeMode == NONE` on regulated legs (the relayer fee recipient would need `R`, review L5); for each regulated leg: maker not frozen, `canReceive(maker)` for the token the maker buys, token not paused | `NOT_ELIGIBLE {reason}`, `UNBOUND_FORBIDDEN`, `FEE_FORBIDDEN`, `PAUSED` |
| Expiry | `expiry ≤ min(now + 30 d, receiver attestation validUntil)` | `ATTESTATION_SHORTER` |
| Before each settle simulation | the §3.3 pre-check for maker → taker and taker → maker on each regulated leg; market fee recipient `canReceive` | pair dropped, both orders re-checked |
| Events | `AccountFrozen` (maker ⇒ drop the maker's orders), `Paused` (stop matching the market until `pausedUntil`), `Attested` with flags 0 or `AttesterSet(…, false)` (drop affected makers) | — |

On chain the token is the arbiter regardless (§3.8): a pair that slipped through fails alone (`MatchFailed`).

### 8.3 Gossip (A2 §11 amendments)

- Managed markets are **not gossiped** by default: wallets post to the venue's gateway; `route_order` for a managed
  market is refused (`MANAGED_LOCAL`).
- If the operator enables gossip (`gossip = 1`): home-bound replicas only (R124 bound mode), listed only for homes
  with `gossip_trusted.dex = 1` (admin pre-trust); R128 automatic trust is not computed for managed markets (a
  settle history is not a licence); depth is indicative; `unbound` stays 0.
- Private-profile chains: managed markets follow A2 §12 (never on gossip).

### 8.4 Security

| Abuse | Outcome |
|---|---|
| Third party settles two eligible makers' signed unbound orders | our wallets never sign `relayer = 0` for managed markets and intake refuses them; a maker who signs one elsewhere accepts it (A2 §11.6 item 6); the token still enforces eligibility |
| KYC revoked between intake and settle | pre-settle re-check; else the pair fails on chain |
| Resting-order privacy | not gossiped by default; fills are public on chain as for any trade |
| Venue or relayer fee to an ineligible recipient | relayer fees `NONE` on regulated legs; the venue's market fee Safe carries ordinary flags for its operator (R217) |
| Wash trades by the venue | out of scope of the contract (venue licence, surveillance); every fill is on chain |

Tests (node, `cargo test`): intake refusals per reason; drop on `AccountFrozen`/`Paused`/revocation/attester
disable; pre-settle re-check; unbound and fee refusals; gossip refusal and admin-trust-only listing. Forge: one
managed-market e2e with a regulated equity and an unregulated stablecoin (frozen maker, ineligible taker, relayer
fee on the regulated leg, eligible pair settles).

---

## 9. Node, ERP and app touchpoints (summary)

### 9.1 Node (`scaas-node`)

- Event normaliser (`SCaaS` §7.8) adds: `OrderRecorded`, `OrderRevoked`, `AccountFrozen`, `AccountUnfrozen`,
  `ForcedTransfer`, `Paused`, `Unpaused`, `ControlsDisabled`, `RoleRenounced`, `Attested`, `AttesterSet`,
  `GrantCreated`, `Released`, `Revoked`, `RevocationRenounced`, `MilestoneApproved`, `ExcessSwept`,
  `DistributionCreated`, `Claimed`, `Cancelled`, `Swept`, `OfferCreated`, `Exchanged`, `Closed`, `Rescued`;
  `TieredTokenDeployed` with kinds 5–7 (decoders ship before the first `*_REG` create, R200).
- Token table: `kind` gains `meta_none_reg`, `meta_single_reg`, `meta_multi_reg`; cached `controls` (refreshed on
  `ControlsDisabled`/`RoleRenounced`), roles, registry.
- Intake: the receiver-attestation expiry rule and the grief-score exemption test (§3.8); during a pause the node
  sponsors fee-less unwrap ops.
- Snapshots (§5.4) and managed-market rules (§8). Alerts: any `OrderRecorded`, `ForcedTransfer`, `Paused`,
  `ControlsDisabled`, `AttesterSet`, a role contract's code-hash change, and a protocol clone's attestation within
  30 days of expiry.
- Control actions are ordinary `call` jobs (a Safe's `execTransaction` with its owners' signatures, or a
  `SubjectAccount.executeAsOwner`); the node holds no role key.

### 9.2 ERP (Odoo `dms_blockchain`, new addon `dms_blockchain_assets`, PLANNED with stream AS8)

Asset register (kind, template, terms document, `termsHash`), cap table mirror from the feed, compliance cases
(order id, document stored in the ERP, `documentHash`, records, freezes with their end dates, forced transfers),
attestation sync (the ERP KYC process is the system of record; it pushes `attest` `call` jobs signed by the attester
contract's owners), grants, distributions (payables), offers (redemptions, buybacks). Personal data never goes on
chain (`SCaaS` §11).

### 9.3 App (`app/`, per the app spec)

Issuer wizard (templates, inputs, human-rate preview, mandatory disclosure §3.9), compliance console that **builds**
Safe transactions for orders, freezes, forced transfers, pauses and relaxations (signed by the user's own Safe owner
key; the app never holds a role key), holder pages (regulated status with freeze end dates, vesting, claimable
distributions, open offers with their prescription dates, managed markets).

---

## 10. Per-family availability

| Component | EVM | Hedera | Cosmos | Soroban (Stellar, Pi) | Move (Aptos, Sui) | TON | Solana |
|---|---|---|---|---|---|---|---|
| Regulated module | this spec | this spec (HSCS contracts + HIP-632 + HTS fail-closed underlying checks; HTS-native tokens not used, owner) | PLANNED: CW20 variant with the same rulings | PLANNED: SEP-41 variant; candidate native flags (auth-required, clawback) to be assessed | PLANNED: candidate native mechanisms (Aptos FA `TransferRef` freeze/transfer; Sui regulated coin deny list) | PLANNED: jetton master + wallet with order records | PLANNED: candidate Token-2022 extensions (permanent delegate, default frozen state, transfer hook) |
| ComplianceRegistry | this spec | this spec | PLANNED | PLANNED | PLANNED | PLANNED | PLANNED |
| VestingGrant, Distribution, ExchangeOffer | this spec | this spec | PLANNED | PLANNED | PLANNED (subject account holds any asset; contracts as Move modules) | PLANNED | PLANNED |
| Snapshot builder | this spec | this spec (same indexer) | with each family's token | 〃 | 〃 | 〃 | 〃 |
| Managed markets | this spec | this spec | where an order book exists | — | — | — | — |

"When": each non-EVM family gets its own short spec after the EVM+Hedera build (streams AS1–AS7) and after that
family's TW2 wrapper work (R145 order); every family spec must satisfy R201–R217 or amend them explicitly. Candidate
native mechanisms are named for that assessment only; none is relied on here.

---

## 11. Factory and catalogue changes (R200)

```solidity
enum TokenKind { META, ZETHER, META_NONE, META_SINGLE, META_MULTI, META_NONE_REG, META_SINGLE_REG, META_MULTI_REG }

function _baseOf(TokenKind k) private pure returns (TokenKind) {   // REG → its tier
    return k == TokenKind.META_NONE_REG ? TokenKind.META_NONE
         : k == TokenKind.META_SINGLE_REG ? TokenKind.META_SINGLE
         : k == TokenKind.META_MULTI_REG ? TokenKind.META_MULTI : k;
}
// _createTiered: TokenKind b = _baseOf(kind); count rule of b (0 / 1 / 2–8)
```

| Rule | Detail |
|---|---|
| Kind ⇒ count | through `_baseOf` (code change in `OpenFactoryV2._createTiered`) |
| Tiered entry points | `_isTiered` (`kind ≥ META_NONE`) already admits 5–7; v1 entry points refuse them (as today) |
| Registration | `tokenKind()` and `factory()` checks unchanged (`VersionKindMismatch`, `ImplementationFactoryMismatch`) |
| Provenance | unchanged; wallets read `versionOf(token).kind` and, for `*_REG`, the §3.3 views |
| `AssetFactory` | separate contract (action contracts are not tokens): `predictGrant/createGrant`, `predictDistribution/createDistribution`, `predictOffer/createOffer`; each `predict*` reverts on invalid params; CREATE2 salt `keccak256(abi.encode(kindTag, params))`; implementations immutable in the constructor, no registrar, no catalogue (a new implementation = a new `AssetFactory`); events `GrantCreated`, `DistributionCreated`, `OfferCreated` |

Deploy scripts: `RegulatedLib` deployed and linked per chain; factory v2 (with the appended kinds) registers the six
regulated implementations as version 1 of their kinds; `AssetFactory` and one `ComplianceRegistry` per operator are
deployed separately.

---

## 12. Storage layout pins

New implementations get `test/as/layout/*.json` pins (as TW2 I7). Regulated children (EVM and Hedera): TW2 slots
0–15 identical to their base tier (asserted) plus the ERC-7201 namespace; `VestingGrant`, `Distribution`,
`ExchangeOffer` pinned in full. Indexers that read `reserve` by slot keep working on regulated wrappers.

---

## 13. Work breakdown

One heavy forge job at a time (`forge test --match-path test/as/<step>*` for the step; the full suite once at the
end); at most three sub-agents; reviews by Claude sub-agents.

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| AS1 | `RegulatedControls`, `RegulatedLib`, three EVM regulated children, `ComplianceRegistry`, factory v2 kinds + `_baseOf`, TW2 keyword changes | — | `test/as/Regulated*.t.sol`, `Registry.t.sol`, `FactoryV2.t.sol` REG cases, TW2 v2 suite green with identical gas/layout, `--sizes` ≤ 24 576 |
| AS2 | `HederaRegulated*` (signature + HTS overrides) | AS1 | `test/hedera/*Reg*.t.sol`, sizes, layout pins |
| AS3 | `AssetFactory` (with `predict*` validation) + `VestingGrant` | — (regulated cases need AS1) | `test/as/Vesting*.t.sol` |
| AS4 | `Distribution` + `merkle_dist_vectors.json` | AS3 (factory) | `test/as/Distribution*.t.sol` |
| AS5 | `ExchangeOffer` + trade-leg library shared with `MetaTxDex` | AS3 | `test/as/Offer*.t.sol`, `MetaTxDex` tests unchanged |
| AS6 | Invariant suites (regulated I1–I7, grant, distribution, offer obligation), gas tables, layout pins, managed-market forge e2e, `*_REG`-as-underlying test | AS1–AS5 | `test/as/*Invariant*.t.sol`, `*Gas.t.sol` |
| AS7 | Node: normaliser, token kinds (before the first `*_REG` create), intake rules, grief exemption test, alerts, snapshot builder + API + CLI + vectors, managed markets (gossip part after P7/G3) | AS1, AS4 | node `cargo test` (one heavy cargo job at a time, never in parallel with forge) |
| AS8 | `sdk/asset_templates.json` + vectors, ERP addon, app screens (per the app spec) | AS7 | SDK vector test; Odoo unit tests |
| AS9 | Docs: `SCaaS` §4/§14/§15 texts and statuses to BUILT, `integration.md`, `TODO.md` | per stream | — |

---

## 14. Open questions (owner)

None. The rev-1 questions were settled on 2026-10-06: Hedera stays HSCS only (no HTS-native regulated variant), and
the pause stays 7 days on / 7 days cooldown (R205).

---

## 15. Review disposition (independent review 1 of rev 1, FIX-THEN-GO)

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Counterfactual funding into an undeployable address | **Accepted**: `predict*` reverts on invalid params; init reverts only `Underfunded`; distributions open at `max(claimStart, createdAt + 1 h)` | R209, R210, §4.2, §5.1–5.2, §6.2, §11 |
| H2 | Renounce or dead issuer leaves freezes forever | **Accepted**: renounce clears `FREEZE|FORCE|PAUSE` (issuer) / `FORCE` (compliance); `controls()` only loses bits | R201, R202, §3.10 I6/A14 |
| H3 | Issuer alone freezes everyone forever | **Accepted** (within owner rulings): issuer-only ≤ 30 d, ≤ 60 d per episode, 30 d gap; longer needs a record (`freezeUntil`, ended by revocation); one hot SLOAD kept | R204, §3.2, §3.3, §3.5, §3.9, I7 |
| H4 | Offer sweep takes unexchanged entitlement; live minter dilutes | **Accepted**: non-closable ⇒ burn sink, sweep bounded by `obligation()` before `closesAt`, `closesAt ≥ opensAt + 365 d`, `MinterLive` at exchange | R212, §6.1–6.4, §7 |
| H5 | Unwrap-recipient allowlist closes exits | **Accepted**: no recipient checks (neither `R` nor `F`); `_checkRecipient` change dropped; A10 restated | R204, R208, §3.4, §3.10 |
| M1 | Keyword list incomplete; `_isContract` clash; `payWithFee` cannot `super` | **Accepted**: four more `virtual`; hook renamed `_regIsContract`; `payWithFee` override copies the body + event test; CBOR note | R207, §3.1 |
| M2 | Enum append misroutes counts in `_createTiered` | **Accepted** (verified at `OpenFactoryV2.sol` l.248): `_baseOf`; factory tests in the AS1 gate; decoders before first create | R200, §11, §13 |
| M3 | Single/Multi children exceed 24 576 | **Accepted**: library split is the base design; `forceTransfer` and overrides stay in the token | §3.1, §11, §13 |
| M4 | `*_REG` as a wrapper underlying | **Accepted**: wizard refuses; R208 narrowed to own reserves; AS6 test | R208, R217, §3.8, §7 |
| M5 | `ELIGIBLE_CONTRACT` master key | **Accepted**: admin-only, pass-through contracts only, `validUntil` max, `MetaTxDex` included; node alert | R217, §3.7, §3.8 |
| M6 | Seizure from a grant breaks its math | **Accepted with a change**: no short-balance revert anywhere; beneficiary bears a seizure first (the review's revoke formula protected the beneficiary, contradicting its own principle); distribution first-come stated | §4.3, §4.4, §5.2 |
| M7 | Pause vs redemptions and fee-bearing unwrap; misleading disclosure | **Accepted**: per-tier disclosure; fee-bearing unwrap op refused at step 6 during a pause, node sponsors fee-less exits (a transient flag is not possible from the `view` `_checkOp`) | R205, §3.4, §3.9, §9.1 |
| M8 | Dividends to protocol-clone leaves stuck | **Accepted**: builder must classify contract leaves; `rescue(token)` on all action contracts | R216, §5.4, §4.2, §5.2, §6.2 |
| M9 | Disabled attester's attestations survive | **Accepted**: `attesterId` packed in the slot, checked on every `hasFlags` | R206, §3.7 |
| M10 | Dead registry locks tier-1 tokens | **Accepted**: `disableControls(ALLOWLIST)` by the issuer (relaxation); registry admin multisig disclosed | R206, §3.3, §3.9 |
| L1 | Merkle tree shape unpinned | **Accepted**: OZ `StandardMerkleTree` v1, encoding, sort and odd-count vectors named | §5.4 |
| L2 | Hedera regulated children miss HTS checks | **Accepted** (verified in `HederaTokensV2.sol`): `_checkUnderlying` override re-added; layout pins | §3.1, §3.12 |
| L3 | Init order under the allowlist; supply to the factory caller | **Accepted**: config first; Safe calls `createTiered` | §3.2, §7 |
| L4 | Strict `at` vs undated milestones | **Accepted**: non-decreasing with an approver | §4.2 |
| L5 | Relayer fee recipient on managed regulated legs | **Accepted**: relayer `feeMode = NONE` on regulated legs at intake | R214, §8.2 |
| L6 | Grantor front-runs approval; push revoke | **Accepted**: disclosed; push to the grantor kept (only `F(grant)` blocks it) | §4.4 |
| L7 | Inconsistent grant gas numbers | **Accepted**: ≈ +15 k (≈ 11 %) everywhere | R209, §4.7 |
| L8 | Grief exemption untestable | **Accepted**: parent-block re-simulation + role/attester tx in the block; cap 3/day for attester-caused | §3.8 |
| L9 | `AlreadyPaused` unreachable | **Accepted**: deleted | §3.3, §3.6 |
| L10 | CEI for distribution and grant | **Accepted**: R216; hook-token tests | R216, §4.4, §5.2, tests |
| OE | Cuts: unwrap recipient checks; `orderId`/`documentHash`/`recordedAt` in storage; on-chain `checkTransfer`; `rolesSeparated()`; `approveMilestoneWithSig`; venue-level registry; `AlreadyPaused` | **All done** (venue-level registry → PLANNED) | §3.3, §3.4, §4.2, §4.4, §8.1 |
| (4) | `TODO.md` still shows TW2 rev 1.1 | Deferred to AS9 (this commit touches only the spec) | §13 |
