> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance-matrix survey 2: other widely used contracts

Date: 2026-10-20. Scope: Curve, Balancer v2/v3, Lido, Chainlink feeds, Safe, Seaport/Liquity (immutable by design), ENS, Yearn v3, LayerZero OFT, Wormhole NTT, Ethena, EigenLayer, GMX v2, Pendle, Arbitrum/Optimism security councils. The excluded set (USDC/Paxos/Tether, HTS, Token-2022, Stellar, Algorand, Sui, Aptos, tokenfactory, ERC-3643, Uniswap, Aave, Compound, Morpho, Euler, Maker/Sky, OZ, L2BEAT frameworks) is covered by the other agent.

Evidence tags:
- **[F]**: fact read from source code or official docs during this session (URL given).
- **[F2]**: fact from a secondary source (news, forum, third-party blog) seen this session.
- **[M]**: from prior knowledge, not re-fetched this session. Treat as likely but unverified.
- **[I]**: inference or interpretation.

Matrix axes used below: **Fixed** = fixed by the implementation (code or immutable). **Init** = set per instance at creation and never changeable after. **Mutable** = changeable after deployment (who, delay, bounds, and whether it can be renounced or locked forever).

---

## 1. Curve

### 1a. Classic StableSwap (e.g. 3pool), owner-administered
Source: [StableSwap3Pool.vy](https://raw.githubusercontent.com/curvefi/curve-contract/master/contracts/pools/3pool/StableSwap3Pool.vy) [F]

| Power | Who | Delay | Bounds | Renounce / lock |
|---|---|---|---|---|
| `ramp_A(future_A, future_time)` | owner | Ramp lasts at least `MIN_RAMP_TIME` = 1 day. A new ramp can only start 1 day after the previous ramp started. | `0 < A < MAX_A` = 10^6. Change at most ×10 or ÷10 (`MAX_A_CHANGE` = 10). A is linearly interpolated. | none |
| `stop_ramp_A` | owner | immediate | Freezes A at its current interpolated value. | n/a |
| `commit_new_fee` then `apply_new_fee` | owner | `ADMIN_ACTIONS_DELAY` = 3 days. `revert_new_parameters` cancels. | fee ≤ `MAX_FEE` (50%). admin_fee ≤ `MAX_ADMIN_FEE` (100% of fee). | none |
| `commit_transfer_ownership` then `apply_transfer_ownership` | owner | 3 days, cancellable | n/a | none |
| `kill_me` / `unkill_me` | owner | `kill_me` only works before `kill_deadline` = deploy + ~60 days (`KILL_DEADLINE_DT`). `unkill_me` works at any time. | Kill blocks `exchange`, `add_liquidity`, imbalanced and one-coin withdraws. Proportional `remove_liquidity` always stays open. | **The kill power expires on its own.** |
| `withdraw_admin_fees` / `donate_admin_fees` | owner | immediate | Only touches the surplus over tracked balances. | n/a |

- **Fixed or Init:** coins, N, rate multipliers, LP token.
- **Mutable:** A (ramped), fee and admin fee (timelocked), owner (timelocked).
- **Upgradeability:** none.

### 1b. StableSwap-NG (factory pools)
Source: [CurveStableSwapNG.vy](https://raw.githubusercontent.com/curvefi/stableswap-ng/main/contracts/main/CurveStableSwapNG.vy) [F]

- **Admin is not stored in the pool.** Every admin check reads `msg.sender == factory.admin()`, so one factory admin (the Curve DAO ownership agent [M]) governs every pool the factory creates. The pool creator gets **no** admin powers. [F, I]
- **`ramp_A` / `stop_ramp_A`:** same rules as classic (1 day minimum, ×10 maximum, `MAX_A` 10^6). [F]
- **`set_new_fee(fee, offpeg_fee_multiplier)`:** immediate. Bounds: fee ≤ `MAX_FEE` (50%) and `offpeg_fee_multiplier × fee ≤ MAX_FEE × FEE_DENOMINATOR`. The NG design dropped the commit/apply delay. [F]
- **`set_ma_exp_time`:** immediate. Both values must be nonzero. [F]
- **Admin fee:** a **constant** 50% of the swap fee. Nobody can change it. [F]
- **`withdraw_admin_fees`:** permissionless. It pays `factory.fee_receiver()`, which is read at call time, so the receiver is a single factory-level knob. [F]
- **No kill switch and no pause.** [F]
- **Init-immutable:** `coins`, `N_COINS`, `asset_types` (plain / rate-oracle / rebasing / ERC4626), `rate_oracles` (oracle address + selector), `rate_multipliers`, `call_amount`, `scale_factor`, name, symbol, EIP-712 data. [F]
- **Init but mutable later:** A, fee, offpeg multiplier, MA time. [F]
- **Implementation selection:** the factory picks the implementation from an index (blueprints). The pool is not upgradeable. [M]

### 1c. Crypto pools (Tricrypto-NG / Twocrypto-NG)
Source: [Twocrypto.vy](https://raw.githubusercontent.com/curvefi/twocrypto-ng/main/contracts/main/Twocrypto.vy) [F, partial]. The `params` module was not fetched [M].

- `ADMIN_FEE` = 50% constant. [F]
- Admin fees are claimed internally at most once per day (`MIN_ADMIN_FEE_CLAIM_INTERVAL` = 86400). The claim is skipped while a ramp is in progress. [F]
- No kill switch. [F]
- Admin is the factory admin. `ramp_A_gamma` ramps A and gamma together with a minimum ramp time and a maximum change ratio. `apply_new_parameters` sets fees and rebalancing parameters immediately within hard-coded bounds. [M]
- Coins, precisions and math are fixed at deploy. [F]

### 1d. Curve DAO layer
Sources: [Curve governance docs](https://docs.curve.finance/governance/overview), [curve.readthedocs dao-ownership](https://curve.readthedocs.io/dao-ownership.html) [F2]

- **Three Aragon agents.**
  - The **ownership agent** handles critical changes. Its votes need 30% quorum and 51% support.
  - The **parameter agent** handles pool parameters. Its votes need 15% quorum. The support threshold differs by source (51% or 60%).
  - The **emergency agent** is controlled by the **Emergency DAO**, a 9-member multisig. It can kill gauges and pools inside their kill windows.
- Ownership and parameter votes run 1 week before execution.
- The DAO can add or remove Emergency DAO members and override a kill. [F2]
- veCRV `VotingEscrow` uses commit/apply for both the admin and the `smart_wallet_checker`. [F]

---

## 2. Balancer v2 / v3

### 2a. Balancer v2
Sources: [TemporarilyPausable.sol](https://raw.githubusercontent.com/balancer/balancer-v2-monorepo/master/pkg/solidity-utils/contracts/helpers/TemporarilyPausable.sol), [TimelockAuthorizer.sol](https://raw.githubusercontent.com/balancer/balancer-v2-monorepo/master/pkg/vault/contracts/authorizer/TimelockAuthorizer.sol) [F]

- **Authorizer.** Every permissioned function on the Vault and on pools calls `authorizer.canPerform(actionId, account, where)`.
  - The action ID is `keccak(disambiguator, selector)`. The disambiguator is per factory, so permissions can be granted for one function across all pools of one factory, or for one pool (`where`). [M]
  - The Authorizer itself can be replaced by `setAuthorizer` (governed). [M]
- **TimelockAuthorizer** [F]:
  - Root role with a delayed root transfer.
  - Per-action execution delays, capped by `MAX_DELAY` = 2 years.
  - Any change to a delay waits at least 5 days (`MINIMUM_CHANGE_DELAY_EXECUTION_DELAY`). Reducing a delay also waits the difference between the old and new delay.
  - No action's delay may exceed the `setAuthorizer` delay.
  - Per-action grant and revoke delays.
  - Granters and revokers are scoped per action and per `where` (or `EVERYWHERE`).
  - Whoever schedules an execution becomes a canceler for it. Root is a global canceler.
- **Pause window and buffer period.**
  - Each pool or Vault has a pause window that starts at deploy. During the window it may be paused and unpaused any number of times.
  - After the window, pausing is impossible forever. If the contract was paused when the window ended, it stays paused until the buffer period ends, then becomes permanently unpaused.
  - Current code caps the window at **4 years** (`MAX_PAUSE_WINDOW_DURATION`) and the buffer at **180 days** (`MAX_BUFFER_PERIOD_DURATION`). [F]
  - Original 2021 deployments used shorter values (90-day vault window and 30-day buffer) [M].
  - The pause window is set **per factory**: each pool gets `min(remaining factory window, …)`. [M]
- **Per-pool owner.**
  - The owner is set at creation. Using the delegate-owner sentinel `0xBA1BA1…` means Balancer governance instead of a pool-specific owner.
  - The owner can call "owner-only" actions such as `setSwapFeePercentage` and the amplification ramp on stable pools. [M]
  - The swap fee is bounded (v2 stable minimum 0.0001%, maximum 10%) [F, from v3 docs "same as v2"].
- **Amplification ramp (stable pools):** minimum 1-day duration and at most ×2 per day. [M]
- **Recovery mode.** It is enabled through the Authorizer, not the owner. It turns on a simple proportional exit that avoids complex math and oracles, and it switches off protocol fees. The pool keeps operating. [F2: [0xSkly](https://medium.com/@0xSkly/inside-balancer-code-recoverymode-9af34ce5ab72)]
- **Rate providers:** fixed per pool at creation. [M]
- **Upgradeability:** none. The Vault and pools are immutable. Only the Authorizer can be swapped. [M]
- **Real-world consequence (2025-11-03 exploit, Composable Stable Pools)** [F2: [Balancer post-mortem](https://medium.com/balancer-protocol/nov-3-exploit-post-mortem-51dcbeb6b020)]:
  - Newer pools that were still inside their pause window were paused within minutes and put into recovery mode.
  - Older pools were **outside their pause window and could not be paused**. They accounted for most of the losses.
  - **This is the main empirical lesson about expiring pause rights.**

### 2b. Balancer v3
Sources: [VaultAdmin.sol](https://raw.githubusercontent.com/balancer/balancer-v3-monorepo/main/pkg/vault/contracts/VaultAdmin.sol), [vault-config docs](https://docs.balancer.fi/developer-reference/contracts/vault-config.html) [F]

- **Vault pause:** the Vault pause window is 4 years and the Vault buffer is 180 days, both deployed at the maximum. `pauseVault` reverts after the window. Pools may have longer windows, set per factory. [F]
- **`PoolRoleAccounts`, set at registration:**

| Role | Power | Notes |
|---|---|---|
| `pauseManager` | `pausePool` / `unpausePool` | Governance can **also** act (the check falls through to the Authorizer). Pausing is allowed only within the pool's pause window. [F] |
| `swapFeeManager` | `setStaticSwapFeePercentage` | **Exclusive role.** If one is set, governance can **not** override it. If zero, governance controls the fee. The pool must be unpaused. [F] |
| `poolCreator` | Receives the creator fee (≤ 99.999%) | **Fixed at registration and cannot change.** [F2: [pool-creator-fee docs](https://docs.balancer.fi/concepts/core-concepts/pool-creator-fee.html)] |

- **Recovery mode:** `enableRecoveryMode` is **permissionless whenever the pool or the Vault is paused**. Otherwise it needs governance. `disableRecoveryMode` needs governance. The stated purpose is that governance cannot lock funds by pausing. [F]
- **Aggregate protocol fees:** set only through the `ProtocolFeeController`. Protocol swap fee ≤ 50% and protocol yield fee ≤ 50%. [F]
- **Vault buffers:** a pause blocks init and add-liquidity but **not** removal. [F]
- **Init-immutable per pool** [M/I]: token configuration (token, token type STANDARD/WITH_RATE, rate provider, `paysYieldFees`), hooks contract, liquidity-management flags, pool-creator address, pause-window end.
- **Wind-down (2026)** [F2: [KuCoin news](https://www.kucoin.com/news/flash/balancer-community-approves-orderly-shutdown-proposal-fork-proposal-rejected), [Crowdfund Insider](https://www.crowdfundinsider.com/2026/09/310346-defi-protocol-balancer-proposes-orderly-shutdown-plans-to-return-9m-treasury-to-bal-token-holders/)]:
  - BIP-928 (orderly shutdown) passed. On Oct 30, 2026, "pools that are structurally able to" switch to withdrawals only. The v3 Vault is paused Nov 30, 2026.
  - The pause, permissionless-recovery and proportional-exit design is the shutdown mechanism.

---

## 3. Lido

Sources: [GateSeal.vy](https://raw.githubusercontent.com/lidofinance/gate-seals/main/contracts/GateSeal.vy), [DG spec](https://raw.githubusercontent.com/lidofinance/dual-governance/main/docs/specification.md), [deployed contracts](https://docs.lido.fi/deployed-contracts/), [LIP-28 thread](https://research.lido.fi/t/lip-28-dual-governance/10032/18), [hash consensus](https://docs.lido.fi/contracts/hash-consensus) [F]

| Role / mechanism | Power | Delay / bounds | Expiry / renounce |
|---|---|---|---|
| Aragon Voting (LDO) | Owns everything through ACL roles, and since July 2025 acts through Dual Governance. | Aragon vote (~5 days with an objection phase [M]), then the DG timelock. | n/a |
| **Dual Governance** | stETH holders can delay and block DAO proposals. | Veto escrow: **1% first seal** puts the system into VetoSignalling (dynamic timelock **5 → 45 days**). **10% second seal** triggers RageQuit: escrowed stETH is withdrawn and new proposals cannot be scheduled. Bounds are hard-coded (`MIN_EXECUTION_DELAY`, `MAX_AFTER_SUBMIT_DELAY`, `MAX_AFTER_SCHEDULE_DELAY`, …). | Mechanism is permanent. [F spec; F2 numbers from [analytics note](https://research.lido.fi/t/dual-governance-analytics-note-on-parameters-values/9905)] |
| Emergency Activation Committee (4/7) | Activates Emergency Mode **once**. After that, only the execution committee can execute. | `EmergencyModeDuration` ≤ `MAX_EMERGENCY_MODE_DURATION`. After it ends, anyone can deactivate. | **Self-disables** after use or at `EmergencyProtectionEndDate`. The end date was 2026-06-20. A one-year extension to 2027-06-20 was proposed in April 2026; enactment was not verified. [F] |
| Emergency Execution Committee (5/7) | `emergencyExecute`. `emergencyReset` hands governance to the fallback `TimelockedGovernance` and cancels pending proposals. | Only during Emergency Mode. | Same expiry. [F] |
| Tiebreaker committee (3 sub-committees) | Schedules proposals or resumes sealables when DG is deadlocked. | Only after Tiebreaker Condition A or B **and** `tiebreakerActivationTimeout`, which is within a MIN–MAX range. | [F] |
| **GateSeal** (sealing committee multisig) | `seal()` calls `pauseFor(duration)` on up to 8 sealables (WithdrawalQueue, ValidatorExitBus, …). | Seal duration is a constructor parameter within **4–14 days**. Expiry is ≤ **365 days** after deploy. | **One-shot:** `seal()` sets expiry to now, so it cannot be reused. It also expires unused at the deadline. There is no reset; a new GateSeal must be deployed by DAO vote. Committee, duration and sealables are all immutable. [F] |
| Reseal committee / ResealManager | While DG is not Normal, can turn a GateSeal pause into an indefinite pause. Resuming is governance-only. | | [F] |
| Oracle committee (HashConsensus) | Reports consensus: CL balances, withdrawals finalization, exits. | Quorum **5 of 9**. Members are added and removed by DAO vote. | [F2] |
| stETH (Lido app) roles | `PAUSE_ROLE` / `RESUME_ROLE`, `STAKING_PAUSE_ROLE`, `STAKING_CONTROL_ROLE` (stake-rate limit). | Aragon ACL. | [M] |

- **Upgradeability:** core contracts are Aragon or OZ proxies, upgradeable by DAO vote through the DG timelock. [M]
- **Pattern:** GateSeal separates "who can pause" (a small committee, fast) from "who decides" (DAO, slow). It enforces this with **a single use, a bounded duration, and an expiry**.

---

## 4. Chainlink price feeds
Sources: [AggregatorProxy.sol](https://github.com/smartcontractkit/chainlink/blob/v1.0.0/contracts/src/v0.7/dev/AggregatorProxy.sol) [F]; [Ackee blog](https://ackee.xyz/blog/chainlink-data-feeds/) [F2]; [Flags registry](https://docs.chain.link/data-feeds/contract-registry) [F]

| Power | Who | Delay | Notes |
|---|---|---|---|
| `proposeAggregator(addr)` then `confirmAggregator(addr)` | Proxy owner (`ConfirmedOwner`, two-step transfer) | **No timelock.** Confirm takes effect in the same transaction. | Consumers can preview `proposedLatestRoundData()`. Each confirm starts a new phase: round IDs are `phaseId << 64 \| aggregatorRoundId`, and `phaseAggregators` keeps history. [F] |
| OCR aggregator `setConfig` (signers, transmitters, f), billing, access controllers | Aggregator owner | none [M] | |
| Owner identity | A Chainlink-operated Safe, seen once as **4-of-9** | n/a | Third-party snapshot. [F2] |

- **Fixed per feed:** decimals and description of the aggregator. The proxy address is stable; that is the point of the design.
- **Mutable:** the underlying aggregator and its node set.
- **Pattern:** a stable address with a hot-swappable implementation and **no** timelock; trust rests entirely on the multisig. Users are expected to verify ownership with the Flags registry.

---

## 5. Safe (self-governed account)
Sources: [OwnerManager.sol](https://raw.githubusercontent.com/safe-global/safe-smart-account/main/contracts/base/OwnerManager.sol) [F]; [Safe v1.5.0 blog](https://safe.global/blog/introducing-safe-v1-5-0-module-guards-enhanced-smart-account-features), [setModuleGuard docs](https://docs.safe.global/reference-smart-account/guards/setModuleGuard) [F2/F]

- **Every admin function is `authorized`**, meaning it can only be called by the Safe itself through a threshold-signed `execTransaction`. The functions are add, remove and swap owner; change threshold; enable/disable module; set guard; set module guard (v1.5); set fallback handler. [F, plus M for the modifier body: `msg.sender == address(this)`]
- **Threshold bounds:** `1 ≤ threshold ≤ ownerCount`. [F]
- **Modules:** `execTransactionFromModule` bypasses signatures entirely. Before v1.5 it also bypassed guards. v1.5.0 (July 2025) added **Module Guards**. [F2]
- **Guards** can veto transactions, and a buggy guard can brick the Safe. [F]
- **Fallback handler** extends the interface, e.g. EIP-1271 and the Extensible Fallback Handler.
- **Upgradeability:** the proxy's singleton is in storage slot 0. A `delegatecall` transaction (e.g. a migration contract) can change it, so the owners can upgrade or rewrite anything. **No external admin.** [M]
- **Pattern:** "governance = the instance's own multisig". There is no separate admin, and everything is changeable by threshold. A natural default owner for the per-instance admin of factory-made contracts.

---

## 6. Immutable by design: Seaport, Liquity v2 (and Liquity v1)

- **Seaport:**
  - No owner, pauser or upgrade path in Seaport itself [M; docs are silent [F]].
  - The `ConduitController` has **no global admin** [F: [ConduitController.sol](https://raw.githubusercontent.com/ProjectOpenSea/seaport-core/main/src/conduit/ConduitController.sol)]. Anyone creates a conduit whose `conduitKey` starts with the creator's 20-byte address; the address comes from CREATE2.
  - Each conduit has its own owner (two-step transfer, cancellable). The owner opens and closes **channels**, i.e. which contracts may move tokens approved to the conduit.
  - **Pattern:** admin power exists only per instance and only over that instance's own approvals.
- **Liquity v2 (BOLD)** [F: [docs llms-full](https://docs.liquity.org/llms-full.txt)]:
  - Contracts are immutable and not upgradeable. There is no pause, freeze or manual shutdown.
  - Governance only directs protocol liquidity incentives (25% of revenue).
  - Per collateral **branch**, thresholds are fixed at deployment: e.g. SCR 110% for ETH and 120% for LSTs, CCR 150% / 160%.
  - **Algorithmic branch shutdown** happens if TCR < SCR or the oracle fails. It is **permanent and irreversible**, and starts urgent redemptions at 0% fee with a 2% bonus. A branch cannot be added or removed.
- **Liquity v1:** the deployer called `setAddresses` and then **renounced ownership**. Zero admin. [M]
- **Pattern:** "no admin, automatic circuit breakers". Code-defined triggers replace a guardian.

---

## 7. ENS
Sources: [fuses docs](https://docs.ens.domains/wrapper/fuses), [INameWrapper.sol](https://raw.githubusercontent.com/ensdomains/ens-contracts/staging/contracts/wrapper/INameWrapper.sol), [Root.sol](https://raw.githubusercontent.com/ensdomains/ens-contracts/staging/contracts/root/Root.sol), [security controllers proposal](https://discuss.ens.domains/t/executable-enable-root-and-registrar-security-controllers/21872), [ENS proposal 6.48/6.49](https://docs.ens.domains/dao/proposals/6.49/) [F]

### Root and registry
- `Root` is owned by the ENS DAO (wallet/timelock [M]). Controllers can `setSubnodeOwner` for TLDs **unless the TLD is locked**.
- `lock(label)` is owner-only and **one-way**: no code path unlocks. [F]
- **Pattern:** a per-child irrevocable lock held by the parent.
- **Security Council veto:** limited in time (EP 5.13: anyone can revoke it after 2 years). It **expired on 24 July 2026**, and the renewal (6.48) was defeated. [F2]
- **February 2026 executable:** proposes `RootSecurityController` (`disableTLD`) and `RegistrarSecurityController` (disable a .eth registrar controller) owned by the Council. These are break-glass powers that only disable, and they are explicitly **not** time-limited. Execution was not confirmed. [F]

### NameWrapper fuses: irrevocable, expiring permission burning [F]

| Fuse | Bit | Controlled by |
|---|---|---|
| `CANNOT_UNWRAP` | 1 | owner |
| `CANNOT_BURN_FUSES` | 2 | owner |
| `CANNOT_TRANSFER` | 4 | owner |
| `CANNOT_SET_RESOLVER` | 8 | owner |
| `CANNOT_SET_TTL` | 16 | owner |
| `CANNOT_CREATE_SUBDOMAIN` | 32 | owner |
| `CANNOT_APPROVE` | 64 | owner |
| bits 7–15 | custom | owner |
| `PARENT_CANNOT_CONTROL` | 1<<16 | parent |
| `IS_DOT_ETH` | 1<<17 | internal |
| `CAN_EXTEND_EXPIRY` | 1<<18 | parent |
| remaining parent bits | custom | parent |

- **Ordering rules:**
  1. The parent must be **Locked** (CU burned) before it can burn PCC on a child.
  2. PCC must be burned before any owner fuse can be burned.
  3. CU must be burned before the other owner fuses.
- `CANNOT_BURN_FUSES` freezes the fuse set itself.
- Fuses are **one-way** (burn only). They reset **only at expiry**. For .eth names, expiry is the end of the 90-day grace period.
- A parent can grant `CAN_EXTEND_EXPIRY`, so the child keeps its guarantees for as long as it renews.
- **Pattern:** a monotone permission bitmask with dependency ordering and a time bound. "Emancipated" means the parent has given up control. "Locked" means the name can no longer escape the rules.

---

## 8. Yearn v3 vaults
Sources: [VaultV3.vy](https://raw.githubusercontent.com/yearn/yearn-vaults-v3/master/contracts/VaultV3.vy), [VaultFactory.vy](https://raw.githubusercontent.com/yearn/yearn-vaults-v3/master/contracts/VaultFactory.vy) (master, API 3.1.1) [F]

| Power | Who | Delay | Bounds | Irreversible? |
|---|---|---|---|---|
| Grant roles (`set_role` / `add_role` / `remove_role`) | `role_manager` | none | **14 bitmask roles:** ADD_STRATEGY, REVOKE_STRATEGY, FORCE_REVOKE, ACCOUNTANT, QUEUE, REPORTING, DEBT, MAX_DEBT, DEPOSIT_LIMIT, WITHDRAW_LIMIT, MINIMUM_IDLE, PROFIT_UNLOCK, DEBT_PURCHASER, EMERGENCY | n/a |
| `role_manager` transfer | role_manager, then the new address accepts | two-step | | n/a |
| `shutdown_vault` | EMERGENCY_MANAGER | none | Sets deposit_limit 0, removes the deposit hook, grants the caller DEBT_MANAGER, forces debt targets to 0. | **Yes, permanent.** |
| Deposit limit or deposit hook; withdraw hook; transfer hook | DEPOSIT_LIMIT_MANAGER / WITHDRAW_LIMIT_MANAGER | none | Limit and hook are mutually exclusive unless overridden. | |
| Accountant (fee logic, external) | ACCOUNTANT_MANAGER | none | Fees are minted as shares. | |
| Profit max unlock time | PROFIT_UNLOCK_MANAGER | none | ≤ 1 year (31,556,952 s). | |
| Factory protocol fee | factory `governance` | none | ≤ 50% of fees (`MAX_FEE_BPS` 5000), default or per vault. | |
| `shutdown_factory` | factory governance | none | Blocks new vaults only; existing vaults are unaffected. | **Yes.** |

- **Init-immutable:** `asset`, `decimals`, `factory`. Name and symbol are settable later. [F]
- **Deployment:** vaults are **minimal-proxy clones** (`create_minimal_proxy_to`) of a fixed original, with salt = (deployer, asset, name, symbol). Clones are **not upgradeable**: the target is fixed. [F]
- **Open roles:** older 3.0.x had `set_open_role` (a role usable by anyone) [M]; it is absent in 3.1.1.
- **Pattern:** a per-instance bitmask role manager, and a factory-level fee whose bound is set in code.

---

## 9. Cross-chain token bridges

### 9a. LayerZero v2 OFT / OApp
Sources: [OAppCore.sol](https://raw.githubusercontent.com/LayerZero-Labs/devtools/main/packages/oapp-evm/contracts/oapp/OAppCore.sol) [F]; [integration checklist](https://docs.layerzero.network/v2/tools/integration-checklist), [L2BEAT OFT](https://l2beat.com/bridges/projects/layerzerov2oft) [F2]

- The `endpoint` is immutable. [F]
- **Owner (OZ `Ownable`, renounceable):** `setPeer(eid, peer)`, `setDelegate`, enforced options, message inspector, pre-crime. [F/M]
- The **delegate** sets endpoint configuration: send and receive libraries, DVNs, executor, confirmations. [F]
- **Trap:** if libraries or configuration are not pinned explicitly, the OApp follows **LayerZero's defaults**. Those are set by the EndpointV2 owner, a 2/4 Safe according to L2BEAT, and may change. Renouncing the OApp owner does **not** freeze the delegate. [F2, I]
- **To be truly immutable:** pin libraries and DVN configuration explicitly, then remove the delegate and owner. [I]
- **Rate limiting:** opt-in (`RateLimiter`) and not part of the base OFT. [M]

### 9b. Wormhole NTT
Sources: [ManagerBase.sol](https://raw.githubusercontent.com/wormhole-foundation/native-token-transfers/main/evm/src/NttManager/ManagerBase.sol), [NttManager.sol](https://raw.githubusercontent.com/wormhole-foundation/native-token-transfers/main/evm/src/NttManager/NttManager.sol), [RateLimiter.sol](https://raw.githubusercontent.com/wormhole-foundation/native-token-transfers/main/evm/src/libraries/RateLimiter.sol), [PausableOwnable.sol](https://raw.githubusercontent.com/wormhole-foundation/native-token-transfers/main/evm/src/libraries/PausableOwnable.sol) [F]

| Power | Who | Delay | Notes |
|---|---|---|---|
| `pause` | owner **or pauser** | none | |
| `unpause` | **owner only** | none | |
| `transferPauserCapability` | owner or pauser | none | |
| `setPeer` (with decimals and inbound limit), `setOutboundLimit`, `setInboundLimit(chain)` | owner | **immediate** | Limits are capacities that refill linearly over `rateLimitDuration`. |
| Transceivers and threshold (`setTransceiver`, `removeTransceiver`, `setThreshold`) | owner | immediate | Invariants: threshold ≥ 1 and ≤ number of enabled transceivers. |
| `upgrade(impl)` | owner | immediate | **`_checkImmutables`** reverts unless `token`, `mode` and `chainId` (and `rateLimitDuration`) are unchanged across the upgrade. |
| Complete a queued over-limit transfer | **anyone**, after `rateLimitDuration` | | The sender can cancel an outbound queued transfer. |

- **Init-immutable:** `mode` (LOCKING or BURNING), `token`, `chainId`, `rateLimitDuration` (0 means rate limiting is off, enforced together with `skipRateLimiting`). [F]
- **Pattern:** (a) the **upgrade carries invariants**: identity-defining fields must survive the upgrade; (b) **queue-don't-reject** rate limiting, where users are delayed rather than blocked.

---

## 10. Ethena (USDe / EthenaMinting / StakedUSDe)
Sources: [USDe.sol](https://raw.githubusercontent.com/ethena-labs/bbp-public-assets/main/contracts/contracts/USDe.sol), [EthenaMinting.sol](https://raw.githubusercontent.com/ethena-labs/bbp-public-assets/main/contracts/contracts/EthenaMinting.sol), [StakedUSDe.sol](https://raw.githubusercontent.com/ethena-labs/bbp-public-assets/main/contracts/contracts/StakedUSDe.sol), [StakedUSDeV2.sol](https://raw.githubusercontent.com/ethena-labs/bbp-public-assets/main/contracts/contracts/StakedUSDeV2.sol), [SingleAdminAccessControl.sol](https://raw.githubusercontent.com/ethena-labs/bbp-public-assets/main/contracts/contracts/SingleAdminAccessControl.sol) [F]

| Contract | Role | Power | Bounds / notes |
|---|---|---|---|
| USDe | owner (Ownable2Step) | `setMinter`: exactly **one** minter address | **`renounceOwnership` reverts.** Not upgradeable. |
| EthenaMinting | DEFAULT_ADMIN (single, two-step, **cannot renounce or be revoked**) | max mint and redeem per **block**, supported assets, custodians | No upper bound in code. |
| | MINTER / REDEEMER | Execute EIP-712-signed user orders | Routes may only go to registered custodians, and ratios must sum to 10,000. |
| | **GATEKEEPER** | `disableMintRedeem` sets both per-block limits to 0, and removes minter / redeemer / collateral-manager roles | **Can only reduce.** It cannot re-enable anything or grant roles; only the admin can. |
| StakedUSDe(V2) | BLACKLIST_MANAGER | Soft restriction (no deposit) or full restriction (no transfer or withdraw) | The owner cannot be blacklisted. |
| | DEFAULT_ADMIN | `redistributeLockedAmount(from, to)` burns a fully restricted holder's shares and re-mints them to `to`, or vests them to stakers | **Confiscation power.** |
| | DEFAULT_ADMIN | `setCooldownDuration` | ≤ 90 days. 0 means plain ERC-4626. |
| | REWARDER | `transferInRewards` | Vests over 8 h. |
| | everyone | `renounceRole` | **Always reverts.** Users cannot drop a restriction. |

- **Patterns:**
  - "Gatekeeper can only reduce risk": brakes are separate from re-enabling.
  - Per-block caps.
  - An admin that **cannot** be renounced. This is deliberately the opposite of burnable power.

---

## 11. EigenLayer
Sources: [Pausable.sol](https://raw.githubusercontent.com/Layr-Labs/eigenlayer-contracts/main/src/contracts/permissions/Pausable.sol), [PauserRegistry.sol](https://raw.githubusercontent.com/Layr-Labs/eigenlayer-contracts/main/src/contracts/permissions/PauserRegistry.sol) [F]; [multisig governance](https://docs.eigenlayer.xyz/eigenlayer/security/multisig-governance), [Eigen Foundation architecture](https://docs.eigenfoundation.org/protocol-governance/technical-architecture) [F2]

- **PauserRegistry:** a set of `isPauser` addresses plus **one** `unpauser`. Only the unpauser can change pausers or the unpauser. [F]
- **Pausable (per contract):**
  - The paused state is a **256-bit flag word**.
  - `pause(new)`, by any pauser, may only **add** bits.
  - `pauseAll()` sets all bits.
  - `unpause(new)`, by the unpauser only, may only **remove** bits.
  - Each function is guarded with `onlyWhenNotPaused(index)`.
  - `pauserRegistry` is **immutable** in the contract. [F]
- **Governance:**
  - Ops multisig (3-of-6) and Protocol Council (3-of-5) queue upgrades through a timelock with at least **10 days** delay.
  - The **Community multisig (9-of-13)** can bypass it in emergencies.
  - The Pauser multisig is **1-of-N** (sources say 8 or 14; currently unknown).
  - Contracts are upgradeable proxies. [F2]
- **Pattern:** the cheapest possible pause (1-of-N, granular bits) with an expensive unpause. Pausers cannot escalate.

---

## 12. GMX v2 (gmx-synthetics)
Sources: [Role.sol](https://raw.githubusercontent.com/gmx-io/gmx-synthetics/main/contracts/role/Role.sol), [TimelockConfig.sol](https://raw.githubusercontent.com/gmx-io/gmx-synthetics/main/contracts/config/TimelockConfig.sol), [Config.sol](https://raw.githubusercontent.com/gmx-io/gmx-synthetics/main/contracts/config/Config.sol), [README](https://raw.githubusercontent.com/gmx-io/gmx-synthetics/main/README.md) [F]

- **RoleStore:** one store with ~20 roles: ROLE_ADMIN, TIMELOCK_ADMIN, TIMELOCK_MULTISIG, CONFIG_KEEPER, LIMITED_CONFIG_KEEPER, CONTROLLER, MARKET_KEEPER, ORDER_KEEPER, LIQUIDATION_KEEPER, ADL_KEEPER, FEE_KEEPER, and others. Only the Timelock should hold ROLE_ADMIN. [F]
- **DataStore** is a generic key-value store. All market parameters are keys, e.g. `keccak(FUNDING_FACTOR, market)`. [F]
- **Config (CONFIG_KEEPER, immediate):**
  - Can write only **whitelisted base keys** (`allowedBaseKeys`, fixed at construction).
  - `setUint` values are range-checked (`ConfigUtils.validateRange`).
  - LIMITED_CONFIG_KEEPER has a much smaller whitelist: gas, funding rates, max pool or OI caps.
  - Oracle provider changes are rate-limited (`ORACLE_PROVIDER_MIN_CHANGE_DELAY`). [F]
- **TimelockConfig:**
  - Uses a **signal, then execute** flow through `ConfigTimelockController`. It covers role grants, oracle signers and providers, price feeds, fee receiver, holding address, and withdrawals from impact pools.
  - The delay can only be **increased**, up to `MAX_TIMELOCK_DELAY` = **5 days**.
  - `revokeRole` by TIMELOCK_MULTISIG is **immediate**: removing power is fast, adding power is slow. [F]
- **Upgrades:** handlers are redeployed and granted CONTROLLER. RoleStore and DataStore persist. [F]
- **Patterns:**
  - Three tiers for parameters: keeper (fast, whitelisted, range-bounded), limited keeper (narrower), timelock (slow).
  - Asymmetric grant and revoke.
  - Per-market parameters live as keys in one store, which fits a factory well.

---

## 13. Pendle v2
Sources: [PendleMarketFactoryV7Upg.sol](https://raw.githubusercontent.com/pendle-finance/pendle-core-v2-public/main/contracts/core/Market/PendleMarketFactoryV7Upg.sol) [F]; [Aave ARFC](https://governance.aave.com/t/arfc-onboard-pendle-pt-tokens-to-aave-v3-core-instance/20541/5), [Blockworks filing](https://blockworks.com/token-transparency/filing/pendle) [F2]

- **`createNewMarket(PT, scalarRoot, initialAnchor, lnFeeRateRoot)`:**
  - Permissionless [M].
  - The PT must be valid and unexpired. `initialAnchor ≥ 1`. `lnFeeRateRoot ≤ maxLnFeeRateRoot = ln(1.05)` (immutable).
  - Duplicates of the same (PT, scalar, anchor, fee) are rejected.
  - Deployed with CREATE2 from split code.
  - **Curve parameters and expiry are fixed per market and cannot be changed.** [F]
- **Factory owner:**
  - Sets treasury and `reserveFeePercent` (≤ 100).
  - `setOverriddenFee(router, market, fee)` can only **lower** the fee below the market's own base fee. [F]
- **Factory and SY upgradeability:** the factory is an upgradeable proxy (the `Upg` suffix plus `initialize`) [I]. Markets are immutable. Newer SY wrappers are upgradeable proxies with an owner-pausable function (Pendle governance or deployer). [F2]
- **Governance:** Pendle uses a governance proxy contract (access-control router) as owner of factories and SYs. Details were not verified this session. [M]
- **Pattern:** per-instance economics fixed at birth. The protocol keeps only a "**discount-only override**" and the fee split.

---

## 14. Arbitrum / Optimism security councils
Sources: [Arbitrum constitution](https://docs.arbitrum.foundation/dao-constitution) [F]; [OP Stage-1 spec](https://specs.optimism.io/protocol/stage-1.html) [F]

- **Arbitrum Security Council:**
  - 12 members in 2 cohorts of 6, elected yearly.
  - **Emergency actions:** 9/12, no delay. A transparency report is required afterward.
  - **Non-emergency actions:** 9/12, then they go through AIP phases 4–7. That means an L2 timelock (3 days for treasury actions, 8 days for an L2→L1 message), the rollup challenge period, and an L1 timelock of 3 days.
  - Constitutional DAO proposals follow the same delay pipeline. [F]
- **Optimism Stage 1:**
  - The **Guardian** is the Security Council's 1/1 Safe. It can pause, unpause and reset the pause, and blacklist or retire dispute games.
  - A pause **expires automatically after 3 months**. Chaining a local and a global pause reaches at most 6 months.
  - An optional **Pause Deputy** can pause but **cannot unpause or reset**.
  - **ProxyAdmin owner** is a 2-of-2 of the Security Council and the Optimism Foundation, so every upgrade needs Security Council sign-off.
  - The Security Council safety threshold is 75%. A Liveness Module and Guard handle inactive signers. [F]
- **Patterns:**
  - Emergency and non-emergency paths sit in the same body with different delays.
  - A pause with automatic expiry.
  - A deputy that can only pause.
  - Upgrades need dual consent.

---

## 15. Synthesis

### 15.1 Patterns beyond plain owner / timelock / pause

| # | Pattern | Seen in | Property it gives | Suits a per-instance factory? |
|---|---|---|---|---|
| P1 | **Irrevocable, ordered permission burning (fuses)** | ENS NameWrapper; ENS Root `lock` | Each power is a bit that can only move from "allowed" to "burned". Ordering rules (parent emancipates the child, CU before others, CANNOT_BURN_FUSES freezes the set) give clear states: Locked, Emancipated, Frozen. Optional expiry. | **Excellent.** One `uint256 fuses` per instance, plus a factory-level "parent cannot control" fuse. Holders and integrators can check the guarantees on-chain. [I] |
| P2 | **Expiring pause window + buffer** | Balancer v2/v3 | Emergency power exists only while the code is young. It ends automatically, with no governance needed. | Good, but the 2025 exploit shows the downside: old instances cannot be braked. Pair it with an **auto-recovery path** (P3) or a renewable window that needs consent. [F2, I] |
| P3 | **Permissionless recovery when paused** | Balancer v3 | A pause can never trap funds: anyone can switch on proportional exit. | **Excellent** for DEX and lending instances. It makes guardian power non-custodial. [I] |
| P4 | **One-shot, bounded-duration, expiring seal** | Lido GateSeal | A fast committee gets **one** pause of 4–14 days, usable within 1 year. Renewal needs slow governance to deploy a new seal. | **Very good** as a factory-wide emergency brake over many instances (a sealables list of ≤ N). [I] |
| P5 | **Pauser / unpauser split; add-only vs remove-only bitmask** | EigenLayer, Wormhole NTT, OP Pause Deputy, Ethena gatekeeper | Cheap, many-signer brake. Expensive, high-threshold release. Pausers cannot escalate. | **Excellent.** The bitmask lets one instance pause features one by one (mint, redeem, transfer, borrow). |
| P6 | **"Can only reduce risk" roles** | Ethena GATEKEEPER, Pendle `setOverriddenFee` (fee can only go down), GMX immediate `revokeRole`, ENS security controllers (only disable) | Fast power whose worst case is a denial of service, never theft. | **Excellent**, and the basis of a guardian tier. [I] |
| P7 | **Parameter ramps with minimum time and maximum ratio** | Curve A (≥ 1 day, ×10), Curve crypto A/gamma, Balancer amp (×2/day) | A change cannot be sudden enough to exploit within a block. No timelock contract is needed. | **Good** for any curve or risk parameter per instance (fees, LTV, caps). [I] |
| P8 | **Expiring kill switch** | Curve classic `kill_me` (~60 days) | Launch-period safety that disappears. | Good: simpler than P2, but weaker because unkill is unbounded. |
| P9 | **Commit/apply delay inside the instance** | Curve classic (3 days), veCRV | Timelock without an external timelock. | Good. Note that NG removed it in favour of factory-admin-only control. [F] |
| P10 | **Factory-admin indirection** | Curve NG (`factory.admin()`, `factory.fee_receiver()`), Yearn protocol fee, Pendle | One switch governs N instances. Creators get no power. | **Excellent** for scale, but it is one point of control. Combine it with P1 so an instance can opt out (burn "factory can change X"). [I] |
| P11 | **Exclusive per-instance role vs governance fallback** | Balancer v3 `swapFeeManager` (exclusive), `pauseManager` (shared with governance), `poolCreator` (fixed) | Each power declares whether governance can override the instance delegate. | **Excellent.** This is exactly a per-cell matrix choice. |
| P12 | **Bitmask role manager per instance** | Yearn v3 (14 roles), EigenLayer flags | Cheap storage, composable roles, one `role_manager` with two-step transfer. | **Excellent.** |
| P13 | **Whitelisted key set + range validation + tiered keepers** | GMX Config / TimelockConfig | Fast operational tuning that cannot touch dangerous keys. Dangerous keys need the timelock. The timelock can only be **increased** (≤ 5 days). | **Excellent** for many markets in one DataStore. |
| P14 | **Upgrade with invariant checks** | Wormhole NTT `_checkImmutables` | Even the owner cannot change identity fields (token, mode, chain) through an upgrade. | Good if instances are proxies. [I] |
| P15 | **Queue, don't reject (rate limits)** | Wormhole NTT | Excess flow is delayed for one window and released permissionlessly. | Good for mint and bridge caps. |
| P16 | **Self-governance (instance = multisig)** | Safe | No external admin, so `owner = instance's own Safe` is a natural default. | Neutral: a choice of owner, not a mechanism. |
| P17 | **No admin + algorithmic circuit breaker** | Liquity v2 branch shutdown, Seaport | Zero governance risk. Failure handling is in code and permanent. | Good as a **"fully burned" endpoint** of P1. |
| P18 | **Time-limited emergency committees** | Lido DG emergency protection (end date), ENS Security Council veto (2-year sunset, expired 2026-07-24), OP 3-month pause | Emergency powers carry a sunset. Extending them needs governance. | Good; the factory-level analogue of P2. |
| P19 | **Holder veto / dynamic timelock** | Lido Dual Governance (1% → 5–45 days; 10% → rage quit) | Users of an instance can delay governance in proportion to stake. | Heavy for per-instance use. Fits only a factory-wide governor. [I] |
| P20 | **Non-renounceable admin** | Ethena (DEFAULT_ADMIN, USDe owner) | Prevents accidental loss of compliance powers. | The opposite of P1. Use it only for regulated-asset templates. [I] |
| P21 | **Default-inheritance trap** | LayerZero OApp (unpinned configuration follows the endpoint owner) | The real admin is upstream. Renouncing locally is insufficient. | A warning: the matrix must record **inherited** powers, not only local ones. [I] |

### 15.2 Recommendations for a factory issuing many token / DEX / lending instances [I]

1. **Represent each power as one matrix cell with three attributes:**
   - **Holder:** factory governance, instance admin, guardian, anyone, or nobody.
   - **Change path:** immediate, ramp (P7), commit/apply (P9), or timelock.
   - **Burn state:** a P1 fuse that is one-way and optionally expiring.

   Store fuses as a `uint256` in the instance. Expose `fuses()` so wallets and indexers can show "this pool's fee can never change".
2. **Layer the tiers:**
   - **Guardian:** can only reduce. Pause bits only (P5/P6), and a pause makes recovery permissionless (P3).
   - **Operator:** whitelisted keys, range-bounded, ramped (P7/P13).
   - **Governor:** timelocked; can only increase delays (P13).
   - **Fuse burn:** irreversible (P1).
3. **Fix at creation:** identity and economics that integrators depend on. Examples: asset or tokens, mode (lock/burn, rebasing), rate oracle, curve shape and expiry (Pendle, Curve NG), and the creator fee recipient (Balancer v3).
4. **Emergency power should expire or be one-shot** (P2/P4/P18), with an explicit renewal path. The Balancer 2025 incident argues for **renewable-with-consent** rather than pure expiry for long-lived instances.
5. **Factory-level switches** (P10), such as a protocol fee recipient or fee cap, a "shutdown factory" (new deployments only, as in Yearn), or a global seal (P4). They should be **bounded in code** (Yearn ≤ 50%, Balancer ≤ 50%), and instances may burn opt-outs.
6. **Record inherited or upstream powers in the matrix** (P21): oracles (Chainlink proxy owner, no timelock), bridges (LayerZero endpoint defaults), proxy admins.

### 15.3 Open items, not verified this session
- Curve crypto-pool `params` module bounds; Balancer v2 amp-ramp constants.
- Pendle governance proxy roles.
- Lido DG mainnet numeric delays, and whether the emergency-protection extension to 2027-06-20 was enacted.
- Whether the ENS security controllers executable passed.
- The current EigenLayer pauser multisig size.
