> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance-matrix survey: how existing systems split "fixed / set at creation / changeable later"

Date: 2026-10-20. Purpose: input for the factory governance matrix (tokens, wrapped tokens with a rate, confidential tokens, DEX, later lending).

**Evidence tags**
- **[F]**: fact, confirmed this session from the cited official doc or source.
- **[M]**: fact from my prior knowledge of the official source code or docs, not re-fetched this session. Re-check before relying on it.
- **[I]**: my inference or interpretation.

Column legend used in every table:
- **Fixed**: set by the implementation (code, constants, immutables) or the platform.
- **Init**: per-instance value chosen at creation.
- **Post**: can change after deployment. The cell says who can change it, with what delay and bounds, and whether the power can be removed.

---

## 1. Token issuers (EVM, contract-level)

### 1.1 Circle USDC (FiatToken v2.2)

| Role | Powers | Who reassigns it |
|---|---|---|
| owner | Reassigns masterMinter, pauser, blacklister, rescuer, and itself. Cannot touch the proxy admin. [F] | owner (`transferOwnership`, single step) [M] |
| masterMinter | `configureMinter(minter, allowance)` and `removeMinter`. [F] | owner [F] |
| minter (many) | Mints up to its own `minterAllowance`. Each mint lowers the allowance and burning does not restore it. A minter can burn only tokens it holds. [F] | masterMinter [F] |
| pauser | Pauses or unpauses globally. While paused: no transfer, mint, burn, or configureMinter. Blacklisting, role changes, and upgrades still work. [F] | owner [F] |
| blacklister | Blacklists addresses (no transfer, mint, or burn). [F] | owner [F] |
| rescuer | Moves ERC-20 tokens that were sent to the contract by mistake. [F] | owner [F] |
| proxy admin | `upgradeTo`, `upgradeToAndCall`, `changeAdmin`. Separate from owner. [F] | itself [F] |

- **Fixed:** the implementation logic, but only until the next upgrade.
- **Init:** `initialize(name, symbol, currency, decimals, masterMinter, pauser, blacklister, owner)`. Decimals are effectively fixed after this call. [M]
- **Post:** every role is reassignable. Allowances are re-set periodically off-chain by Circle (operational policy, not code). [F]
- **Renounce or lock:** no built-in path. The proxy admin can always replace all logic. [I]
- **Delays:** none on-chain. [M]
- **Pattern worth copying:** a two-tier mint authority (masterMinter → minter with a per-minter allowance) caps the blast radius of one compromised minter key. [F/I]
- Source: https://github.com/circlefin/stablecoin-evm/blob/master/doc/tokendesign.md

### 1.2 Paxos (USDP / PYUSD / PAXG)

| Role | Powers |
|---|---|
| DEFAULT_ADMIN_ROLE | Grants and revokes roles. [F] |
| SUPPLY_CONTROLLER_MANAGER_ROLE | Manages supply controllers in a separate `SupplyControl` contract. [F] |
| SUPPLY_CONTROLLER_ROLE | Mint and burn, with optional rate limits per time window. Can still mint and burn while the token is paused. [F] |
| PAUSE_ROLE | Pause. [F] |
| ASSET_PROTECTION_ROLE | Freeze and unfreeze; wipe a frozen address's balance (seizure). [F] |
| proxy admin | `AdminUpgradeabilityProxy` upgrades. Must be a different address from DEFAULT_ADMIN. [F] |

- New implementations start paused through their constructor, as a safety guard. [F]
- Note: the README roles table sits in the PAXG section, so applying it to PYUSD is my reading. [I]
- Source: https://github.com/paxosglobal/paxos-token-contracts/blob/master/README.md

### 1.3 Tether USDT (Ethereum `TetherToken`) [M]

- **owner can:** issue, redeem, pause, `addBlackList`, `destroyBlackFunds` (burns a blacklisted balance), `deprecate(newAddress)` (forwards all calls to a new contract, a hand-rolled upgrade), and `setParams(basisPoints, maxFee)`.
- **Hard caps on fees:** `basisPoints < 20` and `maxFee < 50` (whole tokens). This is an early example of **bounded parameter setting**. Fees were never switched on.
- Source: https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7#code

---

## 2. Native token frameworks with explicit authority models

### 2.1 Hedera Token Service (HTS)

Keys are all optional and set in `TokenCreateTransaction`: admin, KYC, freeze, wipe, supply, pause, fee schedule, metadata. [F]

| Key | Power (role meaning is [M] unless the doc says otherwise) |
|---|---|
| admin | Updates token properties and other keys. Can delete the token. Under HIP-540 it "changes or permanently removes any key". [F] |
| KYC | Grants or revokes KYC per account. [M] |
| freeze | Freezes or unfreezes an account. Interacts with `freezeDefault`. [M] |
| wipe | Burns a balance from an account. [M] |
| supply | Mints and burns from the treasury. [M] |
| pause | Pauses the whole token. [M] |
| fee schedule | Changes custom fees (fixed, fractional, royalty). [M] |
| metadata | Updates token or NFT metadata (HIP-646/657). [M] |

- **Capability exists only if set at creation.** "If any of the token key types … are not set during the creation of the token, you will not be able to update the token and add them in the future." [F]
- **Before HIP-540:** keys could not be removed. Now an admin-signed update removes any key permanently. [F]
- **Lower keys can self-replace:** any non-admin key can change itself to another valid key or to the "unusable" all-zeros Ed25519 key. [F]
- **Signature rule:** a new key must sign the update unless the admin key signs (`NO_VALIDATION` mode). [F]
- **No admin key does not mean frozen:** a missing admin key does *not* by itself make the token fully immutable. A live supply key still works and can still rotate itself. Supply becomes immutable only when both the supply key and the admin key are unusable. [F]
- **Fixed at creation:** decimals, supply type (finite or infinite), max supply, and token type. [M]
- Sources:
  - https://docs.hedera.com/hedera/sdks-and-apis/sdks/token-service/define-a-token
  - https://hedera.com/blog/announcing-hip-540-enhanced-token-key-management-on-hedera/
  - https://hips.hedera.com/hip/hip-540

### 2.2 Solana SPL Token-2022

Base mint authorities:
- **mint authority:** `SetAuthority` to `None` fixes supply forever. [M]
- **freeze authority:** `None` means accounts can never be frozen. [M]

Extension authorities: [F unless marked]

| Extension | Authority | Notes |
|---|---|---|
| Transfer fee | transfer-fee-config authority (changes the fee); withdraw-withheld authority (collects fees) | A new fee takes effect **2 epochs later**: the mint stores `older_transfer_fee` and `newer_transfer_fee`. Bounded by bps ≤ 10 000 plus an absolute `maximum_fee`. [M for the bound] |
| Permanent delegate | permanent delegate | "unlimited delegate privileges over any account for that mint" (transfer or burn). Confidential balances can evade it unless auto-approve is off or accounts are frozen. |
| Confidential transfer | CT authority; `auto_approve_new_accounts`; optional auditor ElGamal pubkey | "you must configure your mint with confidential transfers at creation, and cannot add it later." The authority can update auto-approve and the auditor key; setting the auditor to `none` removes it. |
| Confidential mint/burn | (separate extension, not covered this session) | |
| Default account state | freeze authority | Updates the default (initialized or frozen). |
| Interest-bearing | rate authority | "may update the interest rate on the mint at any time." |
| Scaled UI amount | multiplier authority | "may update the multiplier … at any time." Directly analogous to a **wrapped-token conversion rate**. |
| Transfer hook | hook authority | Can change the hook program. |
| Pausable | pause authority | Pausing aborts all transfers, mints, and burns. |
| Permissioned burn | burn authority | Setting it to `None` restores normal burns. |
| Mint close | close authority | Must be initialized before the mint. |
| Metadata / group pointers | update authority | Pointer set during mint creation. |
| Non-transferable, immutable owner | none | Pure capability flags, fixed. |

- **Rule:** mint extensions must be initialized **before `InitializeMint`** and cannot be added later. Mint close and confidential transfer are explicitly documented this way; for the rest it is the general program rule. [M]
- **Rule:** almost every authority is an `OptionalNonZeroPubkey`. Setting it to `None` permanently disables that power, because nothing can re-set it. [M]
- **Result:** the authority model is one key per power, the capability set is chosen at creation, and each power is individually renounceable. [I]
- Sources:
  - https://www.solana-program.com/docs/token-2022/extensions
  - https://www.solana-program.com/docs/confidential-balances
  - https://solana.com/docs/tokens/extensions/transfer-fees

### 2.3 Stellar classic assets and the Stellar Asset Contract (SAC)

Issuer account flags: [F]

| Flag | Effect |
|---|---|
| AUTH_REQUIRED | The issuer must authorize each trustline before it can hold the asset. |
| AUTH_REVOCABLE | The issuer can revoke authorization, which freezes the balance and cancels offers. |
| AUTH_CLAWBACK_ENABLED | Requires REVOCABLE. Applies only to trustlines created *after* the flag is set, and is copied onto each trustline. |
| AUTH_IMMUTABLE | REQUIRED and REVOCABLE can no longer be changed, and the issuer account cannot be merged. |

- **Fixed supply:** set the issuer's master weight to 0, which locks the account forever. "you'll never be able to do anything with it ever again." [F]
- **SAC:** the initial admin is the issuer. `set_admin` can move admin to another address, after which that admin can mint even if the issuer is locked. The docs explicitly warn about this, so "lock" must cover every authority path. [F]
- **SAC admin functions:** `mint`, `clawback`, `set_authorized`. These are bounded by the classic flags (for example, revocation needs AUTH_REVOCABLE). [F]
- **Grandfathering:** a capability flag applies only to holder relationships created after it is set, so existing holders keep their prior terms. [I]
- Sources:
  - https://developers.stellar.org/docs/tokens/control-asset-access
  - https://developers.stellar.org/docs/tokens/stellar-asset-contract

### 2.4 Algorand ASA

- **Fixed at creation:** total supply, decimals, defaultFrozen, name, unit, URL, and metadata hash. "All other parameters like total supply and decimals are immutable." [F]
- **Post:** four addresses, which only the manager can change. [F]

| Address | Power |
|---|---|
| manager | Changes the four addresses and destroys the asset. [F; destroy is M] |
| reserve | Holds uncirculated supply. Informational, no protocol power. [F] |
| freeze | Freezes or unfreezes holdings per account. [F] |
| clawback | Moves assets out of any account. [F] |

- **Permanent removal:** "Setting any control address to empty permanently removes that capability from the asset … with no way to restore it." [F]
- Source: https://dev.algorand.co/concepts/assets/asset-operations/

### 2.5 Sui Coin and the regulated coin

| Capability object | Power |
|---|---|
| `TreasuryCap<T>` | Mint and burn. Transferable. Also needed for `CoinMetadata` updates. [F] |
| `DenyCapV2<T>` | Adds and removes deny-list entries. If `allow_global_pause`, it can also pause globally. [F] |

- **DenyCap at creation:** `DenyCapV2` comes only from `create_regulated_currency_v2` at creation, so regulation is opt-in at birth. [I]
- **Deny-list timing:**
  - A deny takes effect immediately for spending and from the next epoch (~24 h) for receiving. [F]
  - Unpause restores spending immediately and receiving next epoch. [F]
- **Lock:** freezing `CoinMetadata` makes the metadata immutable. The docs warn "never freeze or share the TreasuryCap". [F]
- **Newer `coin_registry`:** the `Currency` standard replaces `CoinMetadata`. [F] I believe it adds explicit fixed-supply and burn-only modes. [M, verify]
- **Model:** capability = owned object. Wrapping or destroying the object is how a power is removed or constrained. [I]
- Source: https://docs.sui.io/standards/coin

### 2.6 Aptos Fungible Asset (FA)

- **Refs only at construction:** `MintRef`, `BurnRef`, `TransferRef` (freeze, force-move), `ExtendRef`, `DeleteRef` are generated from the `ConstructorRef`. "All Refs must be generated when the Object is created". The `ConstructorRef` "cannot be stored and is destroyed by the end of the transaction". [F]
- **Consequence:** a power not minted at birth can never exist. [F/I]
- **Removal:** drop or destroy a stored Ref, or never store it. [I]
- **Fixed at creation:** `maximum_supply`, passed to `create_primary_store_enabled_fungible_asset`. [F] Immutability after creation is my reading. [I]
- **Dispatchable FA:** withdraw, deposit, and balance hooks are registered with the constructor ref, so they too are creation-time only. [F]
- Source: https://aptos.dev/build/smart-contracts/fungible-asset

### 2.7 Cosmos x/tokenfactory (Osmosis)

- **Denom name:** `factory/{creator}/{subdenom}`, which needs no collision registry. [F]
- **Single admin:** mint, burn from any account, transfer between any accounts, set metadata, change admin. [F]
- **Renounce:** setting the admin to empty means "no account has admin privileges", so supply and metadata become permanently unchangeable. [F]
- **Chain-level params (governance):** the creation fee and gas. One contract per denom can be registered as a before-send hook. [F]
- Source: https://github.com/osmosis-labs/osmosis/blob/main/x/tokenfactory/README.md

---

## 3. Security tokens: ERC-3643 (T-REX)

| Role | Powers |
|---|---|
| owner | `setIdentityRegistry`, `setCompliance`, `setOnchainID`, `setName`, `setSymbol`. [F] Adds and removes agents. [M] |
| agent (many) | mint, burn, `forcedTransfer` (between verified addresses, bypasses compliance), `setAddressFrozen`, `freezePartialTokens`, pause/unpause, `recoveryAddress`, plus batch variants. [F] |
| agent restrictions | `setAgentRestrictions` with flags disableMint, disableBurn, disableAddressFreeze, disableForceTransfer, disablePartialFreeze, disablePause, disableRecovery. **Default: an agent can do everything.** [F, Tokeny docs] |
| ModularCompliance owner | Binds and unbinds compliance modules (country restrictions, max holders, time locks…). Each module's parameters are set by the compliance owner. [M] |
| IdentityRegistry, ClaimTopicsRegistry, TrustedIssuersRegistry | Each is owner-administered. Registry agents add or remove investor identities. [M] |

- **Upgrades:** suites are deployed by `TREXFactory`, and proxies resolve their implementation through a shared `TREXImplementationAuthority` (beacon-like, so one upgrade covers many tokens). [M]
- **Delays and lock:** no timelocks and no renounce path in the reference design. Compliance is meant to be mutable forever. [M/I]
- Sources:
  - https://docs.erc3643.org/erc-3643/smart-contracts-library/permissioned-tokens/tokens-interface
  - https://docs.tokeny.com/docs/roles-and-permissions
  - https://ercs.ethereum.org/ERCS/erc-3643

---

## 4. DeFi

### 4.1 Uniswap v3

| Item | Fixed | Init | Post |
|---|---|---|---|
| Pool code | Non-upgradeable, CREATE2 from the factory [M] | – | – |
| token0, token1, fee, tickSpacing | – | Per pool, from an enabled fee tier [M] | Never |
| Fee tiers | – | – | Factory owner `enableFeeAmount(fee, tickSpacing)`, requiring fee < 1e6 and 0 < tickSpacing < 16384. **Additive only: a tier cannot be disabled or changed.** [F] |
| Protocol fee | – | Starts at 0 | Factory owner `setFeeProtocol` per pool. The value is 0 or 1/4…1/10 of the LP fee, so it is bounded. [M] |
| Factory owner | – | – | `setOwner`, single step [F]. Held by Uniswap governance Timelock. [M] |

- Source: https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Factory.sol

### 4.2 Uniswap v4

- **PoolKey is immutable per pool:** currency0, currency1, fee, tickSpacing, hooks. The hook address is part of the pool ID. [M]
- **Hook permissions are encoded in the hook address's low bits,** so they are fixed by code and address. [M]
- **Dynamic fee is a creation-time flag:** LP fee `0x800000`. Only the pool's hook can update the fee, and only if the flag was set. [F]
- **Protocol fee:** set through a `protocolFeeController` chosen by the PoolManager owner. Max 1000 pips (0.1%) per direction. [F]
- **Model:** fixed core with no upgrade, creation-time customization by choosing a hook, and a single bounded global knob. [I]
- Sources:
  - https://docs.uniswap.org/contracts/v4/concepts/fee%20structure
  - https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol

### 4.3 Aave v3

Role registry: `ACLManager`. Its DEFAULT_ADMIN_ROLE is held by the ACL admin, which is set in `PoolAddressesProvider`. [F]

| Role | Can | Cannot |
|---|---|---|
| POOL_ADMIN | Everything RISK_ADMIN and ASSET_LISTING_ADMIN can, plus `dropReserve`, upgrade aToken and debt-token implementations, `setReserveActive`, flash-loan premiums, IRM, `rescueTokens`, sequencer oracle. [F] | |
| RISK_ADMIN | Reserve factor, borrow and supply caps, debt ceiling, LTV, liquidation threshold and bonus, freeze, eMode categories (not 0), liquidation protocol fee, oracle-sentinel grace period. [F] | Pause or activate reserves. [F] |
| EMERGENCY_ADMIN | `setPoolPause`, `setReservePause`, `setReserveFreeze`, `setReserveActive`. [F] | |
| ASSET_LISTING_ADMIN | Oracle sources, fallback oracle, `initReserves`. [F] | |
| FLASH_BORROWER | Premium waived. [F] | |
| BRIDGE | Bridge-related; few powers. [F] | |

- **Per-reserve config:** a packed bitmap per asset, set at `initReserves` and mutable later by the roles above. [M]
- **Upgrade:** `PoolAddressesProvider` owner (governance) swaps Pool and Configurator implementations. [M]
- **Governance v3:**
  - Payloads execute through immutable Executors, Level 1 (short) and Level 2 (long, for governance-critical changes), after a timelock in `PayloadsController`. [F]
  - The Guardian (Security Council) can cancel proposals and cancel not-yet-executed payloads. [F]
  - Delay numbers were not confirmed this session. [M: ~1 day payload delay]
- **Risk Stewards, the key pattern:** contracts that hold RISK_ADMIN but enforce, per parameter:
  - a max relative or absolute change per step (for example, supply cap ±50%; LTV ±0.25 pp absolute);
  - a minimum delay between changes (for example, 3 days). [F]
  - Operated by risk providers (Chaos Labs etc.). AGRS and Phase 2/3 widen the scope.
- Sources:
  - https://aave.com/docs/aave-v3/smart-contracts/acl-manager
  - https://github.com/aave-dao/aave-governance-v3/blob/main/docs/overview.md
  - https://governance.aave.com/t/arfc-aave-generalized-risk-stewards-agrs-activation/19178
  - https://governance.aave.com/t/arfc-bgd-risk-steward-phase-2-risksteward/16204

### 4.4 Compound v3 (Comet)

- **Config is baked into the implementation as immutables:** "Each time an immutable parameter is set via governance proposal, a new Comet implementation must be deployed by the Comet factory." [F]
  - Flow: Timelock calls Configurator setters (which only store the *pending* config), then `CometProxyAdmin.deployAndUpgradeTo`. [F]
  - So "fixed in code" and "changeable by governance" coexist. Config is fixed per implementation, and changing it is a full code upgrade. [I]
- **Roles:**
  - Governor = Timelock under GovernorBravo with COMP voting. [F]
  - Delay: 2 days on mainnet [M]. Other chains add a local timelock delay through a bridge receiver. [F]
  - pauseGuardian (community multisig) can pause supply, transfer, withdraw, absorb, buyCollateral. Only Governor and pauseGuardian can pause. [F]
- **Configurable through governance:** IRM kinks and slopes, rewards speeds, minimum borrow, target reserves, per-asset price feed, collateral factors, liquidation factor, supply cap, pauseGuardian, factory, extension delegate. [F]
- Source: https://docs.compound.xyz/governance/

### 4.5 Morpho Blue and the Morpho vaults

**Morpho Blue core:** immutable, non-upgradeable singleton. [M]

| Owner power | Bound |
|---|---|
| `enableIrm` | Additive only, never disabled. [F] |
| `enableLltv` | Additive only, must be < 1. [F] |
| `setFee(market)` | Fee ≤ MAX_FEE [F]; MAX_FEE = 25%. [M] |
| `setFeeRecipient`, `setOwner` | Owner transfer is single step. [F] |

- **Markets:** permissionless `createMarket(MarketParams{loanToken, collateralToken, oracle, irm, lltv})`. The params are stored once and nothing can modify them. [F]
- **Model:** global allow-lists that only grow, with per-instance parameters frozen at creation. [I]

**MetaMorpho (Vault V1):**
- **owner:** sets curator, allocators, fee (≤ 50%), fee recipient. Can increase the timelock immediately; decreasing it is timelocked. Sets the guardian (timelocked if a guardian already exists). Holds curator and guardian powers. Can renounce. [F]
- **curator:** decreases caps immediately, increases caps on a timelock, submits forced market removal (timelocked). [F]
- **allocator(s):** supply and withdraw queues, `reallocate` within caps. [F]
- **guardian:** revokes pending timelock, guardian, cap, and removal changes. Cannot revoke a fee. [F]
- **Timelock:** ≥ 24 h [F], ≤ 2 weeks [M]. Anyone executes after expiry. [F]

**Morpho Vault V2:**
- **Per-function timelocks** keyed by selector. [F]
- **Asymmetry:**
  - `increaseTimelock` is timelocked by the current duration. [F]
  - `decreaseTimelock` is timelocked by the timelock of the function being decreased. [F]
  - Risk-reducing actions (decreasing caps) are instant. [F]
- **`abdicate(selector)`** irreversibly disables a timelocked action, giving per-power renounce. [F]
- **Sentinel** (many): can only reduce risk (deallocate, decrease caps, revoke pending). "A compromised Sentinel can only take actions that reduce risk." [F]
- **Owner** in V2 does *not* inherit other roles' powers. It only appoints the curator and sentinels and sets metadata. [F]
- **Gates** (shares, receive, send): compliance hooks, timelocked to set, abdicable. [F]

Sources:
- https://github.com/morpho-org/morpho-blue/blob/main/src/Morpho.sol
- https://github.com/morpho-org/metamorpho/blob/main/README.md
- https://docs.morpho.org/curate/concepts/roles/

### 4.6 Euler v2 (Euler Vault Kit)

- **Per-vault governor:** the creator at init. Sets LTVs (with liquidation-LTV ramping over time), caps, IRM, hooks, interest fee, fee receiver, liquidation params, config flags. Can be a limited-power contract. [F]
- **Fixed at creation:** asset, oracle ("immutable and cannot be changed, even by the vault governor"), unit of account, name, symbol. Use a governed `EulerRouter` if price routing must change. [F]
- **Finalize:** set the governor to `address(0)`. "No more governance changes can happen on this vault." [F]
- **Upgradeability is chosen per instance:** upgradeable = beacon proxy following the factory's `upgradeAdmin`; non-upgradeable = MetaProxy pinned to the implementation at creation. [F]
- **Risk matrix** from the whitepaper:

  | | Governed | Finalised |
  |---|---|---|
  | Upgradeable | factory admin + governor | factory admin |
  | Immutable | governor | none |

- **ProtocolConfig (DAO):** fee share ≤ 50%, interest fee kept within 10–100%. For non-upgradeable vaults the bounds are "enforced permanently". [F]
- Source: https://github.com/euler-xyz/euler-vault-kit/blob/master/docs/whitepaper.md

### 4.7 MakerDAO / Sky

- **Executive spells:** MKR/SKY approval voting in DSChief, then the **GSM Pause Delay** in DSPause before execution. [F]
- **Delay value has varied:** 16 h → 48 h (2023) → 16 h → 30 h (2024) → 18 h (Feb 2025), then raised again in Apr 2025. The current value was not confirmed this session. [F for history]
- **Purpose of the delay:** time to react, including firing the **Emergency Shutdown Module (ESM)** by depositing a threshold of governance tokens. [F]
- **Standby spells:** pre-approved emergency spells that bypass the GSM delay, for narrow risk-reducing actions such as halting a module (`EMSP_*`). [F]
- **Pattern:** the delay is the default, and only pre-vetted, narrow, risk-reducing actions get an instant path. [I]
- Sources:
  - https://community-development.makerdao.com/en/learn/governance/param-gsm-pause-delay
  - https://v2.vote.makerdao.com/executive/template-executive-vote-star2-allocation-system-updates-increase-gsm-pause-delay-add-emergency-spell-to-chainlog-top-up-of-the-integration-boost-launch-project-funding-spark-proxy-spell-star2-proxy-spell-april-30-2025

---

## 5. Generic building blocks (OpenZeppelin, proxies)

| Block | Model |
|---|---|
| Ownable | Single owner, `renounceOwnership()` sets it to 0, which locks forever. [M] |
| Ownable2Step | The new owner must `acceptOwnership`, which protects against typos and dead addresses. [F] |
| AccessControl | bytes32 roles, each with an admin role. [M] |
| AccessControlDefaultAdminRules | A single default admin with "a 2-step transfer procedure with a delay between steps". [F] |
| AccessManager | Central for many targets. uint64 roles; the (target, selector) → role mapping. [F] Detail below. |
| TimelockController | PROPOSER, EXECUTOR, CANCELLER roles. `minDelay` can change only through the timelock itself. EXECUTOR can be open (address(0)). [M] |
| Governor + TimelockControl | Token voting, then the timelock queue. [M] |

AccessManager detail: [F unless marked]
- **Grant delay:** per role.
- **Execution delay:** per member. A delayed call is scheduled, then executed.
- **Guardian:** a per-role guardian can cancel scheduled operations.
- **Closed targets:** `setTargetClosed` shuts every restricted function of a target, a kill-switch that keeps permissions intact.
- **Target admin delay:** delays reconfiguring a target.
- **minSetback = 5 days:** applies when a delay is reduced. [F value from source]
- **Locked metadata:** ADMIN_ROLE's admin, guardian, and label cannot be changed.

Proxies and clones: [M]
- **Transparent proxy:** a ProxyAdmin upgrades; the admin cannot call the implementation.
- **UUPS:** upgrade logic lives in the implementation. Upgrading to an implementation without `upgradeTo` **permanently freezes** the code, a lock-by-upgrade.
- **Beacon:** many instances follow one beacon, so one upgrade changes all instances (T-REX, upgradeable Euler vaults).
- **ERC-1167 / MetaProxy clones:** code fixed forever; per-instance config through an `initialize` call (guard with `initializer`) or through immutable args appended to the clone bytecode (`Clones.cloneWithImmutableArgs`, OZ ≥ 5.1; EIP-3448 MetaProxy).

This gives three ways to express "implementation fixed, instance configured": [I]
1. Immutables in a per-instance deployment (Compound bakes them into an implementation; Uniswap pools use CREATE2 with immutables).
2. Clone + init storage (EVK non-upgradeable).
3. Clone with immutable args.

Sources:
- https://docs.openzeppelin.com/contracts/5.x/access-control
- https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/manager/AccessManager.sol
- https://docs.openzeppelin.com/contracts/5.x/api/proxy

---

## 6. Published taxonomies and frameworks for admin power

### L2BEAT Stages [F]

| Stage | Requirements |
|---|---|
| 0 | State roots and DA on L1, reconstructible state, a proof system. |
| 1 | Only ≥ 75% of the **Security Council** can block or force invalid messages. Upgrades by anyone other than the SC need **≥ 7 day exit window**. |
| 2 | Permissionless proofs. **≥ 30 day exit window** for all upgrades, including DAO ones. SC limited to "adjudicable onchain bugs". |

- **Takeaway:** the framework grades the delay relative to the user's ability to exit, plus how narrowly scoped the emergency actor is. [I]
- Source: https://l2beat.com/stages

### DeFiSafety Process Quality Review, admin-controls questions [F]

- **Scored items:** is admin info findable; are contracts labelled upgradeable or immutable; ownership type; which changes are possible; is it understandable; are pause control and timelock documented; timelock length.
- **Scoring examples:** a 24 h timelock scored 50% in one review. A project scores full marks for "no pause" when that is documented and justified.
- Example review: https://www.defisafety.com/app/pqrs/530

### CertiK centralization risk [F]

- Defined as a single point of failure in privileged roles.
- Skynet groups findings as Privilege, Distribution, Upgrade, Other.
- Recommended mitigations: multisig, timelock, DAO.
- Sources:
  - https://www.certik.com/blog/What-is-centralization-risk
  - https://www.certik.com/ko/blog/skynet-puts-centralization-risks-front-and-center

### Recon "Right way to multisig" (third party) [F]

- Tiers actions as low, medium, or high risk.
- Each tier gets a matching signer threshold and timelock length.
- Source: https://getrecon.substack.com/p/the-right-way-to-multisig

### Risk-parameter operators (Chaos Labs, Gauntlet)

- They operate **through bounded steward contracts**, not raw admin: the Aave Risk Stewards in 4.3. [F]

---

## 7. Cross-system synthesis

### 7.1 Recurring power categories, and where each system puts them

| Category | Fixed or code | Init only | Post-deploy (typical holder, guard) |
|---|---|---|---|
| **Supply** (mint, burn, max supply) | Algorand total; Aptos max_supply; Hedera supply type and max | Aptos MintRef must be created at birth; Hedera supply key must be set at birth | USDC masterMinter→minter allowance; Paxos rate-limited controller; SPL mint auth (→ None); tokenfactory admin (→ empty) |
| **Transfer control / compliance** (freeze, deny, KYC, clawback, force transfer, permanent delegate, gates) | Token-2022 non-transferable; Stellar AUTH_IMMUTABLE | Stellar clawback (new trustlines only); Token-2022 CT, permanent delegate, hook; Sui DenyCap; Hedera KYC/freeze/wipe keys; ASA defaultFrozen | USDC blacklister; Paxos asset protector (freeze + wipe); T-REX agents and compliance modules; Hedera keys (→ zero key); ASA freeze/clawback (→ empty); Morpho V2 gates (abdicable) |
| **Fees** | v4 MAX protocol fee 0.1%; Morpho MAX_FEE; Tether bps < 20; EVK 10–100% | Uniswap pool fee tier; v4 dynamic-fee flag | v3 protocol fee 1/4…1/10; Token-2022 fee (2-epoch delay); MetaMorpho fee ≤ 50%; Hedera fee schedule key |
| **Parameters / risk** (caps, LTV, IRM, oracle, rate) | Morpho market params; EVK oracle; Comet immutables | Morpho market; EVK asset, oracle, UoA; Uniswap tickSpacing | Aave RISK_ADMIN (via stewards with step bounds); Morpho curator (cap↑ timelocked, cap↓ instant); EVK governor with LTV ramp; Token-2022 interest rate and multiplier authority |
| **Pause / emergency** | – | Sui `allow_global_pause` | USDC pauser; Aave EMERGENCY_ADMIN; Comet pauseGuardian (per action); Token-2022 pausable; AccessManager closed target; Maker ESM and standby spells |
| **Upgrade / code** | Uniswap, Morpho Blue, ERC-1167 clones = none | EVK chooses upgradeable or immutable per vault | Transparent/UUPS proxy admin; beacon (T-REX, EVK); Comet deployAndUpgradeTo via timelock |
| **Admin succession** | – | Initial owner and keys | Ownable2Step; DefaultAdminRules (delay); Hedera self-rotation with new-key signature; renounce to 0, None, or empty |

### 7.2 Common patterns

1. **Capability only at creation; absent means impossible forever.** [F]
   - Systems: Hedera keys, Token-2022 extensions and confidential transfer, Aptos Refs, Sui DenyCap, Stellar clawback (prospective only), Uniswap v4 hooks and dynamic-fee flag.
   - What it buys: holders can read the risk surface once at creation.
2. **Set to None/empty/zero = permanent removal, one power at a time.** [F]
   - Systems: SPL authorities, ASA addresses, tokenfactory admin, Hedera unusable key, EVK governor = 0, Ownable renounce, Morpho V2 `abdicate(selector)`.
   - Best version: per-power, not all-or-nothing (Morpho V2, Token-2022, ASA). [I]
3. **One key or role per power, with a hierarchy.** [F]
   - Examples: USDC owner → role keys; Aave ACL admin → POOL > RISK, LISTING, EMERGENCY; T-REX agent with restriction flags.
   - The reassigning power sits one level above the operating power.
4. **Timelock with guardian veto.** [F]
   - Systems: MetaMorpho (guardian revokes pending), Aave Governance (Guardian cancels payload), AccessManager (role guardian cancels), Maker (GSM delay + ESM).
5. **Asymmetric delays: risk-reducing changes are instant, risk-increasing ones are timelocked.** [F]
   - Instant: cap ↓, timelock ↑ (MetaMorpho V1). Timelocked: cap ↑, timelock ↓, new market.
   - Morpho V2 also timelocks `increaseTimelock` (by its current value); only `decreaseTimelock` uses the target function's timelock.
   - AccessManager applies a 5-day `minSetback` when a delay is reduced.
6. **Bounded parameter steps.** [F]
   - Absolute caps: Tether, Uniswap v3 protocol fee, v4 0.1% cap, Morpho MAX_FEE, EVK fee bounds.
   - Rate limits per step and per time: Aave Risk Stewards, Paxos mint rate limits.
   - Change spread over time: EVK liquidation-LTV ramp.
   - Change scheduled ahead: Token-2022 fee takes effect 2 epochs later.
7. **Additive-only global allow-lists.** [F]
   - Uniswap fee tiers and Morpho IRM/LLTV can be enabled, never disabled.
   - Because of this, existing instances can never be broken by the global admin.
8. **Two-step ownership transfer**, optionally with a delay (Ownable2Step, DefaultAdminRules). [F]
9. **A separate emergency role that can only reduce risk.** [F]
   - Morpho V2 sentinel, Aave EMERGENCY_ADMIN (cannot list or raise caps), Comet pauseGuardian, Maker standby spells.
   - Best version explicitly lacks unpause or loosening powers; Comet and USDC do allow unpause by the same role. [I]
10. **Code upgradeability chosen per instance; governance and upgrade risk as separate axes** (Euler 2×2 matrix). [F]
11. **Config fixed per implementation, changed by redeploying the implementation** (Compound). This is a variant of "immutable instance, mutable pointer". [F]
12. **Delay graded against an exit window** (L2BEAT 7 d / 30 d). [F]

### 7.3 Anti-patterns (my inference, illustrated by the systems above)

- **Upgrade key trumps everything.** If a proxy admin can replace the code, every "fixed" or "renounced" property is reversible. USDC, Paxos, and T-REX beacons work this way. A matrix must show "fixed (unless upgraded by X)".
- **Hidden second authority path.** Example: a Stellar SAC admin moved by `set_admin` can still mint after the issuer is locked. Renouncing one key while another path to the same power survives is a false lock.
- **Over-broad default roles.** T-REX agents can do everything by default. Aave POOL_ADMIN is a superset of the other roles. ADMIN_ROLE in AccessManager is default admin and guardian for all roles.
- **Single-step owner transfer** (USDC, Morpho Blue `setOwner`, Uniswap `setOwner`).
- **Instant risk-increasing changes:** no timelock on raising caps or fees, or on adding a minter.
- **A pause that also blocks exits or seizes funds, held by one key:** Paxos wipe; the pause role being able to unpause and also do other things.
- **Undocumented, unscored delays.** DeFiSafety and L2BEAT penalize delays shorter than the user's realistic reaction or exit time.
- **Global allow-lists that can be removed** would break existing instances. Systems avoid this by making them additive-only.
- **Transfer-fee changes applied mid-flight.** Token-2022 avoids this with a 2-epoch lag.

### 7.4 Notes for SCaaS factory instances (inference only, not decisions)

These are mappings from the patterns above onto the factory's instance types, for the matrix authors to weigh.

- **Wrapped token with a conversion rate** has two close analogues: Token-2022 scaled-UI multiplier authority, and the interest-bearing rate authority. Each is one dedicated key, changeable "at any time". The Aave and EVK patterns suggest adding:
  - a step bound,
  - a minimum interval,
  - or a ramp,
  - or fixing the rate at creation.
- **Confidential token:** Solana fixes the CT capability at creation. The authority can change auto-approve and the auditor key, and the auditor can be set to none. Also note that the permanent delegate can be evaded by confidential balances unless approvals are manual. This is a cross-power interaction the matrix should record.
- **DEX:** the Uniswap and Morpho shape is per-pool params immutable, global admin additive-only, and a single bounded fee knob.
- **Lending:** use Morpho V2 / MetaMorpho asymmetry plus a sentinel, and Euler's per-instance "upgradeable × governed" choice with finalize-by-zero.
- **A useful matrix column set:**
  - Fixed (code);
  - Init (per instance);
  - Post: holder role, delay, bound;
  - Revocable by whom;
  - Renounceable (per power, irreversible);
  - Overridable by upgrade? (Y/N);
  - Risk direction (reduce = may be instant; increase = needs timelock).
