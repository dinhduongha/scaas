> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance matrix: inventory (2026-10-20)

Read-only inventory for TODO.md §0 "Governance matrix for factory-made contracts". Code is **Z2** (`rev2-zether-z2`,
head `fd672de9`) unless a row says **main**. Where Z2 and main differ, both are given.

Path prefixes:
- `Z2:` = `.claude/worktrees/rev2-zether-z2/smartcontracts/evm/src/`
- `main:` = `smartcontracts/evm/src/`
- `spec:` = `docs/contracts/` (anchor in `#…`)

Source column:
- **IMPL**: fixed by the implementation (constructor, immutable, `Env`, constant, bytecode).
- **INIT**: set per instance at creation (`initArgs` / `TokenConfig` / `DexConfig` / constructor args of a non-clone).
- **POST**: can be changed after deployment.

"Lock" column: whether the power can be removed forever, and how.

## 1. OpenFactory (the factory itself)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| `registrar` address | IMPL | — | — | constructor arg, not checked against 0 | no setter, no transfer, no renounce. A contract registrar (Safe / UA msig) can rotate its signers internally; otherwise you need a new factory | Z2:factory/OpenFactory.sol:33,52-57 (main:…:38) |
| `chainUid` | IMPL | — | — | ≠ 0 | immutable | Z2:…OpenFactory.sol:34,53 |
| `noticePeriod` (**Z2 only**) | IMPL | — | — | any `uint64`. HANDOFF: 10 min on the SCaaS testnet, 3 days on 22776, 0 on dev/tests | immutable | Z2:…OpenFactory.sol:35,51; IOpenFactory.sol:92-94 |
| `MAX_LEGS = 8` (index) | IMPL | — | — | constant | — | Z2:…OpenFactory.sol:30,331 |
| `publishEnv(kind, v, Env)` / `publishDexEnv` (**Z2**) | POST | registrar | **none** (the delay only applies to a release built on the env) | `v ≥ 1`, append-only, never changed; `env.factory == this`, `env.chainUid == chainUid`, `libs.length == libCodeHashes.length`; kinds 0–5 only | an env cannot be revoked or deprecated; the registrar cannot be removed | Z2:…OpenFactory.sol:66-73,253-264 |
| Content of an `Env` (registry, `smartKeyAccountImpl`, `hedera`, `deps[]` = Zether/PQZ verifiers and disclosure, `libs[]` + code hashes) | POST (by the registrar, per env version) → becomes IMPL of every release built on it | registrar | none on publish | no semantic check: Zether/PQZ constructors check `deps` (see §5, §6) | permanent per version | Z2:factory/IFactoryToken.sol:8-12,29-38 |
| Confidential verifiers (**main**) | IMPL of the factory | — | — | `Canonical` set (2 Zether curves + disclosure, 2 PQZ proof systems) fixed in the factory constructor; a release is registered only on one of them | immutable; changing it needs a new factory | main:factory/OpenFactory.sol:53-67 |
| `deployImplementation(kind, version, initcode, implArgs)` (**Z2**). main: `registerImplementation(kind, version, addr)` | POST | registrar | **`usableFrom = now + noticePeriod`** (Z2); none in main | `version ≠ 0`, unique; binds the kind's **latest** env (no choice: owner said "No, to be discussed"); lib code hashes checked; `kind()`, `factory()`, `chainUid()` checked | append-only: a release cannot be removed, only deprecated | Z2:…OpenFactory.sol:89-103,268-304; main:…:82-92 |
| `deployDexImplementation` / main `registerDexImplementation` | POST | registrar | `noticePeriod` (Z2) | as above, DEX domain (`DEX_DOMAIN = 255`) | append-only | Z2:…OpenFactory.sol:197-214 |
| `deprecate(kind, v, reason)` / `deprecateDex` | POST | registrar | **immediate** | — | one-way (there is no un-deprecate). Existing tokens and DEXes are untouched; `createToken` / `createDex` refuse | Z2:…OpenFactory.sol:105-109,222-226 |
| Kind enable: **Z2** `setKindEnabled(kind, on)` | POST | registrar | immediate | kinds 0–5. Plain kinds start **on** (`_enabled = 3`), confidential ones off. No chain gate at the switch (the gate moved into token `init`) | reversible both ways, not lockable. Also gates `createTokenUnregistered` | Z2:…OpenFactory.sol:45,111-118,322 |
| Kind enable: **main** `setZetherEnabled` / `setPqzEnabled` | POST | registrar | immediate | `on` needs a dev chain (Zether), or the allowed chain + precompile self-test (PQZ). Plain kinds **cannot** be disabled | reversible | main:…OpenFactory.sol:113-127 |
| `createToken(kind, version, initArgs, salt)` | — | anyone | — | release exists, not deprecated, `≥ usableFrom`, kind enabled; salt scoped by creator; ≤ 8 underlyings | — | Z2:…OpenFactory.sol:136-145,319-338 |
| `createTokenUnregistered(kind, impl, initArgs, salt)` | — | anyone | — | plain kinds only; any implementation answering `kind()`, `factory()`, `chainUid()`; recorded `version = 0`; kind enabled | the code is unvetted, so its governance is whatever that code holds (`isRegisteredToken` false; DEX classifies it OUTSIDE) | Z2:…OpenFactory.sol:147-153,163-165 |
| `createDex(version, initArgs, salt)` | — | anyone | — | release exists, not deprecated, `≥ usableFrom`. **No enable switch** for the DEX, and no unregistered path | — | Z2:…OpenFactory.sol:232-245 |
| Upgrade of the factory | — | — | — | not a proxy; every release holds `FACTORY` as an immutable | a new factory means new releases; old tokens keep the old factory | Z2:metatx/MetaTokenBase.sol:36,59 |

## 2. Registrar (role)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Holder of the role | IMPL (factory immutable) | — | — | one address | no transfer and no renounce. "Trust root for code: a multisig / UA msig before mainnet" | Z2:…OpenFactory.sol:20-21,33 |
| Powers | POST | registrar | see §1 | publish env, deploy release, deprecate, enable/disable kind | **no power over any existing token or DEX** (no call into instances) | Z2:…OpenFactory.sol:11-15 |

## 3. Every token kind (MetaTokenBase / AdminLib / ERC20MetaTx), the six kinds NONE, UNDERLYING, NONE_ZETHER, UNDERLYING_ZETHER, NONE_PQZ, UNDERLYING_PQZ

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Code / implementation | IMPL | — | — | EIP-1167 clone of a release. **No proxy, no upgrade**; external libraries linked by address (`Env.libs`, code-hash pinned) | permanent; no migration path | Z2:metatx/MetaTokenBase.sol:21,53-66; spec:token-wrappers.md#CTR-TOK-25 |
| `kind()` | IMPL | — | — | pure constant | — | Z2:metatx/NoUnderlyingToken.sol:18-20 |
| `FACTORY`, `CHAIN_UID` (EIP-712 salt) | IMPL (Env) | — | — | — | — | Z2:metatx/MetaTokenBase.sol:56-60 |
| UA registry `_REGISTRY` (UA ledger on/off, 0 = off) | IMPL (Env.registry) | — | — | must name this chain's `chainUid` (checked at `initialize`) | a new registry generation needs a new env + release; existing tokens stay on theirs | Z2:metatx/ERC20MetaTx.sol:32-33; MetaTokenBase.sol:72-75 |
| `SMART_KEY_ACCOUNT_IMPL` (ERC-1271 gas 400k for its clones, 50k otherwise) | IMPL (Env) | — | — | constants 400k / 50k | — | Z2:…MetaTokenBase.sol:40-41,418-421 |
| `IS_HEDERA` (HIP-632 path) | IMPL (Env.hedera) | — | — | Zether/PQZ refuse `hedera = true` | — | Z2:…MetaTokenBase.sol:45,64 |
| `creator`, `version` | INIT (supplied by the factory) | — | — | — | never change | Z2:…MetaTokenBase.sol:70-82 |
| `name`, `symbol`, `decimals` | INIT | — | — | none (`decimals` not checked against legs) | **no setter** | Z2:…MetaTokenBase.sol:103-112; UnderlyingLib.sol:83-86 |
| `features` (bit set) | INIT, then POST (clear only) | owner (`disableFeature`) | immediate | only a set bit outside `lockedFeatures` and outside `ALWAYS_LOCKED`; must be valid for the kind; bits 5–8 refused `FeatureNotBuilt` | one-way: a bit can never be set again. Removes the power forever | Z2:metatx/AdminLib.sol:77-85,121-128,193-201 |
| `lockedFeatures` | INIT | — | — | `⊆ features`; `PAYABLE` and `BURNABLE` are forced locked | never changes. Note: "locked" means the **power exists forever**, not that it is switched off | Z2:…AdminLib.sol:81,85; spec:token-wrappers.md#CTR-TOK-22 |
| Bit 0 `PAYABLE`: gates `mtxPay`, `uaPay`, `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`, `uaPayReceiverFee`, `supportsInterface(IERC20Payment)`. A `MetaTransfer` is never gated | INIT | — | — | all kinds | always locked (no role) | Z2:…MetaTokenBase.sol:149,210,272,321,345,378,396 |
| Bit 1 `MINTABLE` → `mint`, `mintToUA` | INIT flag; POST action | `minter` role | immediate | **no cap, no rate limit** (spec: the cap belongs in the minter contract); public balance only | `disableFeature` if unlocked; otherwise revoke every minter and renounce the owner | Z2:metatx/NoUnderlyingToken.sol:29-39 |
| Bit 2 `BURNABLE` → holder `burn` (own balance) | INIT | holder | — | `NONE*` kinds | always locked | Z2:…NoUnderlyingToken.sol:41-45 |
| Bit 3 `RATE_ADJUSTABLE`, bit 4 `WRAP_DISABLEABLE` | INIT | see §5 | | `UNDERLYING*` kinds | owner may `disableFeature` if unlocked | Z2:…AdminLib.sol:18-19,195 |
| Bits 5 `FREEZE`, 6 `FORCE`, 7 `PAUSE`, 8 `ALLOWLIST` (regulated) | IMPL: refused | — | — | `FeatureNotBuilt` on the plain kinds, `FeatureInvalidForKind` on the confidential ones | not built | Z2:…AdminLib.sol:20-23,33-34,80; spec:asset-suite.md#CTR-AS-17 |
| `owner` | INIT (`TokenConfig.owner`; 0 = no administration ever) | — | — | — | — | Z2:…AdminLib.sol:91-94 |
| `transferOwnership` → `acceptOwnership` | POST | owner, then the new owner | **no delay** (two-step only) | `transferOwnership(0)` cancels the pending transfer | — | Z2:…AdminLib.sol:130-143 |
| `renounceOwnership` | POST | owner | immediate | — | owner = 0 forever; **role holders keep their roles** | Z2:…AdminLib.sol:145-151 |
| `grantRole(bit, acct)` / `revokeRole` | POST | owner | **immediate** | role bits 1, 3, 4 only; the flag must be set; several holders allowed; the `RATE_ADJUSTABLE` role must be a contract. The owner may grant itself a role | ends with `renounceOwnership` | Z2:…AdminLib.sol:99-110,176-184 |
| `renounceRole(bit)` | POST | the holder | immediate | — | — | Z2:…AdminLib.sol:113-118 |
| Initial roles (`minter`, `rateAdmin`, `guardian`) | INIT | — | — | each only for a set flag; `issuer` and `compliance` must be 0 | — | Z2:…AdminLib.sol:40-46,86-90 |
| Meta-tx selector allowlist (`mtxSelectors`, `_mtxRule`, fee class) | IMPL (pure, per kind) | — | — | base `cancelNonce`; NONE adds `burn`; UNDERLYING adds wrap/unwrap/addReserve/…ToUA; Zether/PQZ add their ops | — | Z2:metatx/MetaTxBase.sol:89-100,229-231; NoUnderlyingToken.sol:47-66; UnderlyingToken.sol:177-213 |
| UA allowlist (`_uaAllowed`) | IMPL | — | — | none on the base; `burn` / `unwrap`s | — | Z2:metatx/ERC20MetaTx.sol:456-462 |
| Meta-tx fee (`mtxTransferWithFee`, `mtxExecuteWithFee`, pay) | per intent (signed) | signer | — | `MAX_FEE_PPM = 10_000` (1%) hard cap, PERCENT and FIXED alike; **no token-level fee setter, no protocol fee** | — | Z2:common/FeePolicy.sol:16-50; spec:metatx.md#CTR-MTX-08 |
| Receiver fee | per payment (co-signed by the payee) | payee | — | `0 < fee ≤ value` | — | Z2:…MetaTokenBase.sol:317-334 |
| Trade fee (`mtxTrade`, `TradeOrder.fee`) | per order (signed) | signer | — | `≤ 1%` (`TradeLib.MAX_FEE_PPM`) | — | Z2:trade/TradeLib.sol:36,97 |
| Pause / freeze / blacklist / clawback / rescue / sweep | — | — | — | **absent** (no such function; `_uaMove` comment: the regulated hooks are not built) | — | Z2:metatx/ERC20MetaTx.sol:464-468 |

## 4. Supply of the NONE* kinds (NONE, NONE_ZETHER, NONE_PQZ)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| `initialSupply`, `initialHolder` | INIT | — | — | `NONE*` only (other kinds: `ConfigFieldForOtherKind(1)`); supply 0 ⇒ holder ignored | — | Z2:metatx/NoUnderlyingToken.sol:26; MetaTokenBase.sol:92-101 |
| Further supply | POST | `minter` (bit 1) | immediate | unbounded; public units only (the Zether/PQZ minter never mints shielded value) | as bit 1 | Z2:zether/NoUnderlyingZetherToken.sol:16-17; pqz/NoUnderlyingPqzToken.sol:15-17 |

## 5. Legs, rates and wrap of the UNDERLYING* kinds (UNDERLYING, UNDERLYING_ZETHER, UNDERLYING_PQZ)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Legs (`underlying`, order) | INIT | — | — | 1–8, no duplicate, ERC-20 with readable decimals or native (`address(0)`, 18 or 8 decimals on Hedera); Hedera associates | **never added or removed** | Z2:metatx/UnderlyingLib.sol:80-127 |
| Rate `num/den` per leg | INIT; POST with bit 3 | `rateAdmin` role (a contract): `proposeRate` → `executeRate` (the rate admin only); `cancelRate` | **timelock `rateDelay`**, then a 7-day execution window (`RATE_WINDOW`) | one pending change at a time; `|Δ| ≤ maxRateStepBps` against the current rate; `num, den ∈ [1, 2^96)`; `executeRate` needs collateral `≥ totalSupply (+ totalShielded·shieldScale)`; a decrease is refused if any leg has wrap disabled | `disableFeature(RATE_ADJUSTABLE)` (owner, if unlocked) fixes the rates and drops the pending change; or revoke the rate admin and renounce the owner | Z2:…UnderlyingLib.sol:308-369; UnderlyingToken.sol:157-173; UnderlyingZetherToken.sol:99-107; UnderlyingPqzToken.sol:101-108; spec:token-wrappers.md#CTR-TOK-06 |
| `rateDelay` | INIT | — | — | 2–30 days with bit 3, else 0 | never changes | Z2:…UnderlyingLib.sol:91-98; IFactoryToken.sol:49-53 |
| `maxRateStepBps` | INIT | — | — | 1–1000 bps (≤ 10% per change) with bit 3, else 0 | never changes | same |
| `RATE_WINDOW = 7 days` | IMPL | — | — | constant | — | Z2:…UnderlyingLib.sol:68-69 |
| Wrap pause while a rate change is pending | POST (side effect) | `rateAdmin` | lasts until execute/cancel or `eta + 7 days` | applies to **every** adjustable leg (`wrap`, `wrapToUA`, `mtxWrap`/`uaWrap`, `zether`/`pqz` wrap-shield), not only the pending leg; unwrap is never paused | can be renewed indefinitely (cancel, re-propose); ends with bit 3 | Z2:…UnderlyingLib.sol:139-140,206-207,432-435 |
| `disableWrap(leg, reason)` | POST (bit 4) | `guardian` role | immediate | per leg; blocks `wrap` and `addReserve` on that leg; unwrap stays open | **one-way per leg** (no re-enable); the flag itself is cleared by the owner if unlocked | Z2:…UnderlyingLib.sol:293-304 |
| `addReserve` | — | anyone | — | no mint; leg must have wrap enabled | — | Z2:metatx/UnderlyingToken.sol:91-95 |
| `mtxWrap` / `uaWrap` fee to the submitter | per order (signed) | signer | — | `≤ 1%` | — | Z2:…UnderlyingToken.sol:97-126 |
| Stray underlying above `reserve` (sent without `wrap`) | — | — | — | **no skim or rescue**: stays locked | — | Z2:…UnderlyingLib.sol (`_pull` measures the delta only) |

## 6. Zether layer (NONE_ZETHER, UNDERLYING_ZETHER)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Transfer, burn and inner-product verifiers, `ZetherDisclosure` | IMPL (Z2: `Env.deps[0..3]`, published by the registrar; main: the factory's canonical set) | — | — | `deps.length == 4`; code present; one proof system; both verifiers bound to the one inner-product verifier; registry has code; not Hedera | fixed per release; a new verifier means a new env + release | Z2:zether/ZetherLayer.sol:30-55; factory/IFactoryToken.sol:8-11 |
| Curve | IMPL (via the verifier) | — | — | BN254 / BLS12-381 | — | Z2:…ZetherLayer.sol:64 |
| Chain gate (31337, 1337) | IMPL constant | — | — | checked in `init` (Z2; main: at the factory's enable and create) | adding a chain is a code change | Z2:zether/ZetherSafety.sol:11-18; ZetherLib.sol:148 |
| Verifier runs on this chain (`isSupportedOnThisChain`) | checked at INIT (Z2) | — | — | — | — | Z2:zether/ZetherLib.sol:149-154 |
| `shieldScale` | INIT | — | — | > 0 | never changes | Z2:…ZetherLib.sol:157,172 |
| `maxShielded` (total cap) | INIT | — | — | `≤ 2^54` | never changes | Z2:…ZetherLib.sol:132,157-162 |
| `confidentialFee` (inner fee, to the named beneficiary) | INIT | — | — | `< 2^64`, `< maxShielded` | never changes | Z2:…ZetherLib.sol:158,174,384,582 |
| `minDecoyFee` (was `multiLegFee`; the least per-leg `decoyFee`, 5h) | INIT | — | — | `< 2^64`; `confidentialFee + 16 · minDecoyFee` `< 2^64` and `< maxShielded` | never changes | 5h:…ZetherLib.sol `init` |
| `auditorKey` | INIT | — | — | empty or a valid G1 point, not O | **no rotation** | Z2:…ZetherLib.sol:156-161,175 |
| `auditorMode` NONE / FULL / OPTIONAL | INIT | — | — | key present ⇔ mode ≠ NONE | never changes | Z2:…ZetherLib.sol:164-171; spec:zether.md#CTR-ZTH-42 |
| `disclosureMode` (storage mode) BUNDLE / COMPACT | INIT | — | — | ≤ 1 | never changes | Z2:…ZetherLib.sol:163,170; spec:zether.md#CTR-ZTH-38 |
| Rollover mode PUBLIC / OWNER_ONLY | POST | the account (its Zether key or `authRef` authority, signed) | immediate | per account; `modeNonce`, `validUntilBlock` | reversible | Z2:…ZetherLib.sol:318-367; ZetherTypes.sol:26-29 |
| Regulated flags | IMPL | — | — | refused (`FeatureInvalidForKind`) | — | Z2:metatx/AdminLib.sol:198-199; spec:zether.md#CTR-ZTH-47 |

## 7. PQZ layer (NONE_PQZ, UNDERLYING_PQZ)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| `UAPqzVerifier` | IMPL (Z2: `Env.deps[0]`; main: canonical) | — | — | `deps.length == 1`, code present, not Hedera; registry has code | fixed per release | Z2:pqz/PqzLayer.sol:23-27; pqz/NoUnderlyingPqzToken.sol:21-26 |
| Precompile and proof system | INIT (read from the verifier) but pinned by IMPL constants | — | — | exactly `PQZ = 0x5caA…0F01`, PQZL or PQZH id, self-test passes now | — | Z2:pqz/PqzLib.sol:164-168; pqz/PqzSafety.sol:9-15,55-58 |
| Chain gate (31337, 1337, 7622) | IMPL constant | — | — | checked in `init` | code change | Z2:pqz/PqzSafety.sol:22-28; PqzLib.sol:149 |
| `shieldScale`, `maxShielded` | INIT | — | — | `maxShielded ≤ 2^62` (**Zether: 2^54**) | never change | Z2:pqz/PqzLib.sol:126,151-154 |
| `confidentialFee`, `multiLegFee` (per listed leg, op 7) | INIT | — | — | `confidentialFee + 8·multiLegFee < 2^64` and `< maxShielded` | never change | Z2:…PqzLib.sol:152-153,175,350 |
| Auditor (`auditorUA`: a registered 32-byte UA) | INIT | — | — | must be registered at init | no rotation | Z2:…PqzLib.sol:154,162-163,176 |
| `auditorMode`, `disclosureMode` | INIT | — | — | as Zether | never change | Z2:…PqzLib.sol:157-161,170-171 |
| Rollover | — | **anyone** (no per-account mode, unlike Zether) | — | 1–16 credits | — | Z2:…PqzLib.sol:580-581 |

## 8. SCaaSDex (clone by `createDex`)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Code; `FACTORY`; EIP-712 domain (`chainUid`); `SMART_KEY_ACCOUNT_IMPL` | IMPL (Env) | — | — | EIP-1167 clone, no proxy, no upgrade | permanent | Z2:dex/SCaaSDex.sol:85-89,118-128 |
| `admin` | INIT (`DexConfig.admin`) | — | — | **0 accepted** (= no admin ever) | **no setter, no transfer, no renounce** (a Safe rotates its own signers) | Z2:…SCaaSDex.sol:135-146; spec:dex.md#CTR-DEX-03 |
| `relayerSharePpm`, `treasury` | INIT + POST | admin (`setFeeSplit`) | **immediate** | `ppm ≤ 10^6`; `treasury ∉ {0, DEX}` unless the share is 100% | while an admin exists | Z2:…SCaaSDex.sol:166-168,182-187 |
| DEX fee **amount** | per order (signed) | signer | — | `⌈receiveFill·fee/10^6⌉`, `fee ≤ 1%` (`TradeLib.MAX_FEE_PPM`); the admin never sets an amount | — | Z2:trade/TradeLib.sol:36,97,126 |
| Markets (`setMarket`) | POST | admin | immediate | also records each token's kind **at that call**: SCaaS iff registered and not deprecated. A later deprecation only takes effect at the next `setMarket` | — | Z2:…SCaaSDex.sol:148-164,195-200 |
| Exchange targets / executors (`setExchangeTarget`) | POST | admin | immediate | — | — | Z2:…SCaaSDex.sol:170-175 |
| `listedOnly` | INIT + POST | admin (`setListedOnly`) | immediate | reversible; a leg's `LISTED_POOLS` asks the same | — | Z2:…SCaaSDex.sol:142,177-180 |
| Forbidden interactions (the DEX, the puller, `mtxTrade`/`uaTrade`, `increaseAllowance`, Permit2 `approve`) | IMPL | — | — | constants | — | Z2:…SCaaSDex.sol:56-57,538-548 |
| `DexPuller` | INIT (deployed by `initialize`) | — | — | no admin | — | Z2:…SCaaSDex.sol:143; dex/DexPuller.sol:23 |
| Pause / sweep / upgrade / access to funds | — | — | — | **absent** (spec: "no timelock: nothing to wait for") | — | spec:dex.md#CTR-DEX-03 |

## 9. MandateWallet / HederaMandateWallet (not made by OpenFactory: deployed directly with `new`, no factory in src)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| `owner` | IMPL (constructor immutable) | — | — | ≠ 0 | **no transfer**; a new wallet is needed | Z2:wallet/MandateWallet.sol:33,66-69 |
| `chainUid` (domain) | IMPL | — | — | — | — | same |
| Mandate per token (`delegate`, `maxPerPayment`, `maxPerPeriod`, `periodSeconds`, `expiry`) | POST | owner (direct or signed self-call) | immediate; bumps `epoch` | `delegate ≠ 0`, `period > 0`, `0 < maxPerPayment ≤ maxPerPeriod`; at most `2·maxPerPeriod` across a boundary | revoke | Z2:…MandateWallet.sol:75-88 |
| Payee allowlist per token | POST | owner | immediate | — | — | Z2:…MandateWallet.sol:90-93 |
| Revoke | POST | owner, or the delegate (epoch-bound kill switch) | immediate | — | — | Z2:…MandateWallet.sol:95-97,141-148 |
| `execute(target, value, data)` | POST | owner | immediate | arbitrary call (full custody) | — | Z2:…MandateWallet.sol:99-106 |
| Pay under mandate | — | delegate | — | caps, approved payee, unused `entryRef`, fee mode `NONE` | — | Z2:…MandateWallet.sol:115-138 |

## 10. SmartKeyAccount (+ SmartKeyAccountFactory)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Implementation, `chainUid`, `FACTORY` | IMPL | — | — | one implementation per `SmartKeyAccountFactory`, built in its constructor; **no versioning, no registrar** | — | Z2:account/SmartKeyAccountFactory.sol:14-20; SmartKeyAccount.sol:46,82-85 |
| First key, guardian | INIT (both in the CREATE2 salt; deploy is permissionless) | — | — | — | — | Z2:…SmartKeyAccountFactory.sol:27-41; SmartKeyAccount.sol:88-97 |
| `addKey` / `removeKey` / `rotateKey` | POST | the account itself (a key signs a self-call) | immediate | never zero keys | — | Z2:…SmartKeyAccount.sol:123-135 |
| `setGuardian` (0 = none) | POST | self | immediate | also cancels a pending recovery | — | Z2:…SmartKeyAccount.sol:137-142 |
| Recovery (adds a key) | POST | guardian initiates; anyone completes | **`RECOVERY_DELAY = 2 days`** (IMPL); the account may `cancelRecovery`; the guardian may restart the clock | adds only, never removes | `setGuardian(0)` | Z2:…SmartKeyAccount.sol:41,144-180 |
| `execute` | POST | self | immediate | arbitrary call | — | Z2:…SmartKeyAccount.sol:149-157 |
| Owner / admin | — | — | — | **none** | — | Z2:…SmartKeyAccount.sol:39 |

## 11. UARegistry (not factory-made; deployed per chain, referenced by `Env.registry`)

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| `chainUid`, `generation` / `predecessor`, `hederaNative`, `verifyBudget`, `smartKeyAccountImpl`, `msig` on/off, kind table (verifier + cap per kind, 0 = disabled) | IMPL (constructor immutables) | — | — | caps `≤ verifyBudget`; gen 2 checks gen 1's chain and profile | **admin-free**: no owner, no setter | Z2:ua/UARegistry.sol:18-30,87-115,130-160; spec:accounts.md#CTR-UA-15 |
| `register` / `cacheExpandedKey` | — | anyone | — | every field derived from `keyData`; a record never changes | — | Z2:…UARegistry.sol:299,330-362 |
| Upgrade path | IMPL | — | — | a new generation contract with `predecessor`; tokens see it only through a new `Env` + release | existing tokens keep their registry | Z2:…UARegistry.sol:52-54 |

## 12. Cross-cutting: upgrade path and emergency powers

| Property / power | Src | Who | Delay | Bounds | Lock / renounce | Ref |
|---|---|---|---|---|---|---|
| Instances (tokens, DEX, SmartKeyAccount) | IMPL | — | — | EIP-1167 clones; the implementation locks itself in its constructor | no proxy, no `delegatecall` to a mutable target, no `selfdestruct`. An existing instance never changes code | Z2:metatx/MetaTokenBase.sol:53-66; dex/SCaaSDex.sol:117-128 |
| Linked libraries (`AdminLib`, `UnderlyingLib`, `ZetherLib`, `PqzLib`, `HederaLib`, …) | IMPL (link-time addresses, `Env.libs` code hashes checked at release deploy) | — | — | — | immutable code | Z2:…OpenFactory.sol:266-277 |
| "Upgrade" | POST (new release) | registrar | `noticePeriod` | affects **new** creations only | old releases: deprecate only | Z2:…OpenFactory.sol:89-109 |
| Emergency pause / rescue / sweep / force | — | — | — | none anywhere (searched `src/`: no `pause`, `rescue`, `sweep`, `skim`, `recover`, `upgrade`) | — | — |

## Absent powers (present in comparable systems)

- **Blacklist / freeze** (absent): specced as flag 5 `FREEZE` (CTR-AS-05), refused `FeatureNotBuilt`.
- **Forced transfer / clawback / confiscation** (absent): flag 6 `FORCE` specced, not built. Never allowed on confidential kinds.
- **Global pause of a token** (absent): flag 7 `PAUSE` specced, not built. The DEX has no pause either (delisting a market is the only stop).
- **Receiver allowlist / KYC** (absent): flag 8 `ALLOWLIST` specced, not built.
- **Supply cap / mint rate limit** (absent): left to the minter contract (NoUnderlyingToken.sol:10-11).
- **Rescue / sweep / skim of stray tokens** (absent): on tokens, the DEX and the wallets (the wallets' owner can `execute`).
- **Upgradeable proxy / migration** (absent): clones only.
- **Delayed ownership transfer / timelock on owner actions** (absent): spec CTR-TOK-22 names `AccessControlDefaultAdminRules` (delayed two-step) as the candidate, but the code has a two-step transfer with no delay.
- **Registrar rotation, DEX admin rotation or renounce, MandateWallet owner transfer** (absent).
- **Un-deprecate, Env revocation, DEX enable switch** (absent).
- **Auditor key rotation (Zether/PQZ), metadata change, leg add/remove, wrap re-enable** (absent).
- **Protocol / issuer fee on transfers** (absent): every fee is signed per intent and capped at 1%.
