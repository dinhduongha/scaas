> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# The governance model against other systems (2026-11-02)

The model compared is the one decided on 2026-11-02: `GovernanceBase`, the bit bands, `Grant`, the two-call delay, the lock, D1-D9
([CTR-GOV-01 to -10](../../decisions.md#ctr-gov-01--governancebase-on-every-token-kind-and-the-dex)), plus the UA holder and the relay rule of [permission-model-gaps.md](permission-model-gaps.md).
**Almost none of it is built.** A prototype of D1 and D2 exists on branch `governance`; what is built on `main` is `features`, `lockedFeatures`, one `owner`
and flat roles. Everything cryptographic is `UNAUDITED`. Most systems below are live with real value and years of incidents behind them, and SCaaS is
not. Read every comparison with that in mind.

**Tags.** **[F]** read from the source this session or in the surveys, **[M]** from memory, not re-checked, **[I]** inferred, **[V]** read in this repository at
`2a864638`, **[meas]** measured on the prototype, [prototype/RESULTS.md](prototype/RESULTS.md); an estimate says so. Rows reuse
[gov-survey.md](gov-survey.md), [gov-survey-2.md](gov-survey-2.md) and v2 §5, with their tags; §3 lists what was re-checked. OpenZeppelin was read in the local checkout at commit
`fda6b85f` (2025-03-13, after v5.2.0, before v5.3.0), the commit SCaaS pins.

## 1. The table

Columns are fixed. A dash means the system has nothing for that column.

| System | Who holds a power | Scope and limits | Delegation, and does it narrow | Delay | Lock or renounce | Emergency, rescue | Regulated controls | Gasless or relayed admin | Threshold, PQ holder | Confidential tokens | Cross-chain sameness | Upgrades |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **SCaaS, as decided** (not built) | one `owner` (address); holders per bit, per contract; a UA through a holder contract | bit, then `Grant`: `min`/`max` on the acted number, `total`, `perWindow`, `validUntil`, `maxUses`, `scope`. Limit lives in the target | two levels, on chain, narrowing checked at grant, parent debited at use, epoch kill | two-call `grantDelay` on grants only; `operatorDelay` proposed; a use of a power is never delayed | bit cleared one-way; a locked bit stays forever; renounce refused while an unlocked bit has holders | none built; `RESCUABLE` by anyone to an immutable `rescueTo`; no pause until flags 5-8 | flags 5-8 SPECIFIED, refused today; one regulated implementation per kind | through the holder, typed `mtx*` / `ua*`, fee 0 allowed | `msig` of PQ members through the holder, within `verifyBudget`: 2 ML-DSA-44, 1 ML-DSA-65, 4 FN-DSA-512, 8 SLH-DSA without a precompile [I from `_membersWorst`] | classical Zether and PQZ, both `UNAUDITED`; regulated forms **open, owner, not designed** | one sentence per family; EVM only in code; Soroban and NEAR write-once admin today | none: immutable clones, new release for new instances only |
| **SCaaS, built today** [V] | `owner`, flat holders of bits 1, 3, 4; DEX `admin` with no transfer | bit only; rate step and delay in `WrappedLib` | — | rate change: `rateDelay`, 7-day window | `disableFeature`, `lockedFeatures`, `renounceOwnership` | none | refused | `SmartKeyAccount` owner only (`mtxExecute`) | a Safe as the owner address, or a `SmartKeyAccount` (any one key); **no PQ owner** | as above | per family, differs | none |
| **OZ Ownable2Step** [F local] | one owner | whole contract | — | none; new owner must accept | `renounceOwnership` | — | — | — | whatever the address is | — | EVM | none itself |
| **OZ AccessControl**, `DefaultAdminRules` [F local] | `bytes32` role members, each role with an admin role | role only | admin role grants; no narrowing | `DefaultAdminRules`: two-step with a delay on the admin transfer; no delay on other grants | `renounceRole`; default admin renounce runs through the same delay | — | — | — | whatever the address is | — | EVM | none itself |
| **OZ AccessManager** [F local] | one manager for many targets; `uint64` roles; `(target, selector) → role` | role only, per function | `setRoleAdmin`; no narrowing | per-role grant delay, per-member execution delay, target admin delay, scheduled ops expire after 1 week, delay reductions wait `minSetback` 5 days | `renounceRole`; `setTargetClosed` | role guardian cancels; `setTargetClosed` closes a target, permissions intact | — | — | whatever the address is | — | EVM | none itself; can govern a proxy's admin |
| **Safe** [F] | n owners with a threshold, self-governed; modules | none in core; guards veto; modules bypass signatures | modules; no narrowing in core | none in core | owners change by threshold; no renounce concept | a guard can veto, and can brick | — | **yes, built:** anyone submits `execTransaction`, signatures authorize, refund in native or a token | threshold ≤ owners; ECDSA, EIP-1271, approved hash, secp256r1; no PQ kind in core | — | deployed per chain, owners per chain | owners can change the singleton by `delegatecall` [M] |
| **USDC FiatToken** [F] | owner → masterMinter, pauser, blacklister, rescuer; separate proxy admin | per-minter allowance, spent down, no window | masterMinter → minter, one level | none | none: proxy admin can replace all logic | pauser; rescuer moves stuck ERC-20 to a chosen address | blacklist, pause; **no forced transfer** | — | contract owners off chain | — | separate deployment per chain | **proxy**: every property reversible by the admin |
| **ERC-3643** [F] | owner adds agents (`onlyOwner`, checked); agents mint, burn, force, freeze, pause | per-agent restriction flags [F, Tokeny]; default all; partial freeze by amount | agents; no narrowing | none in the token | owner `Ownable` | agent `pause`, `recoveryAddress` | **fullest built:** identity registry, compliance modules, forced transfer between verified addresses, partial freeze | — | — | — | EVM | proxy, implementation authority [M] |
| **Token-2022** [F] | one key per extension, on the mint | fee bounded by bps and `maximum_fee` [F]; others whole | none in the program | fee change takes effect 2 epochs later | authority `None`, per power | pausable; no rescue | permanent delegate, freeze, default frozen, transfer hook | native fee payer [M] | SPL multisig [M]; no PQ | **yes, confidential transfers** with auditor; a permanent delegate cannot reach them unless auto-approve is off or accounts are frozen | Solana only | program is shared and upgradeable by its authority [M] |
| **Hedera token keys** [F, roles M] | one key per power: admin, KYC, freeze, wipe, supply, pause, fee, metadata | whole | a lower key replaces itself | none | a key absent at creation can never be added; HIP-540 removes a key [F survey; the docs page read now still warns against removal] | pause, wipe | KYC, freeze, wipe, pause, native | native payer accounts [M] | threshold keys [M]; no PQ | — | Hedera only | token is a ledger object |
| **Stellar classic, SAC** [F] | issuer flags; SAC `admin`, movable by `set_admin` | whole | — | none | master weight 0 locks; the docs warn a moved admin survives | clawback, revoke | `AUTH_REQUIRED`, `REVOCABLE`, `CLAWBACK`; clawback on new trustlines only | fee bump [M] | account signer weights [M]; no PQ | — | Stellar only | protocol |
| **Algorand ASA** [F] | manager, freeze, clawback addresses | whole | manager reassigns | none | address set empty: gone forever, per power | clawback, freeze | freeze, clawback, `defaultFrozen` | atomic groups [M] | multisig addresses [M] | — | Algorand only | protocol |
| **Sui Coin** [F] | owned objects: `TreasuryCap`, `DenyCapV2` | whole | transfer the object, or wrap it in your own module | deny for receiving from the next epoch | destroy or wrap the object; docs warn never to freeze `TreasuryCap` | global pause if allowed at creation | deny list, pause, from creation | sponsored transactions [M] | native multisig [M] | — | Sui only | package policy |
| **Aptos FA** [F] | `MintRef`, `BurnRef`, `TransferRef` values, generated only at creation | whole, unless a module wraps a Ref | a resource holding a Ref | none | drop the Ref | — | `TransferRef` freeze and force-move | fee payer [M] | native multisig [M] | — | Aptos only | package policy |
| **Uniswap v3, v4** [F] | factory owner, in practice governance [M] | protocol fee 0 or 1/4-1/10 (v3); ≤ 0.1 % (v4); additive tiers | — | governance timelock [M] | owner only | none | — | — | governance | — | per chain | none: pools immutable |
| **Aave v3** [F] | `ACLManager` roles under an ACL admin; POOL, RISK, LISTING, EMERGENCY | risk stewards bound each change by step and interval | stewards hold `RISK_ADMIN` and enforce bounds; a hierarchy, not narrowing | payload timelock, two levels [F]; figures not confirmed | — | `EMERGENCY_ADMIN` pauses; `POOL_ADMIN` `rescueTokens` | — | — | governance + Guardian | — | per chain, cross-chain governance | proxies, by governance |
| **Compound v3** [F] | Governor + Timelock; pause guardian | bounded by the implementation | — | Timelock; local timelock on other chains [F]; the 2-day figure [M] | — | pause guardian: five actions | — | — | governance + multisig | — | per chain | proxy: config baked into implementations |
| **Morpho Blue, vaults** [F] | Blue: one owner, additive; Vault V2: owner appoints curator, sentinels | per-market immutable params; caps | curator, allocators; no narrowing | per-function timelock, asymmetric: risk-reducing instant; MetaMorpho 1 day to 2 weeks [F] | Vault V2 `abdicate(selector)` per power | sentinel reduces risk only; guardian revokes pendings | gates, abdicable | — | — | — | per chain | Blue none |
| **Maker, Sky** [F] | governance token, executive spells | module-level | — | GSM pause delay; value varied, current value not confirmed | ESM shutdown | ESM; standby spells for narrow risk-reducing acts | — | — | governance | — | Ethereum first | spells replace modules |
| **ERC-7710, MetaMask DF** [F v2 §5] | delegator signs, off chain | 38 caveat enforcers over calldata and balance deltas | **any depth**; caveats accumulate along the chain, each hop enforces its own | as a caveat | `disableDelegation` on chain | — | — | **yes**, redeemer submits | whatever signs | — | EVM | framework-level |
| **Zodiac Roles** [F v2 §5] | role members on a Safe | condition trees over calldata, allowances | none between roles | — | — | — | — | through the Safe | Safe | — | EVM | module |

## 2. Notes, column by column

**Who holds a power.** SCaaS is per contract: one owner on one contract. OpenZeppelin's AccessManager governs many targets from one place, Aave's `ACLManager` a whole
market. A SCaaS issuer with fifty tokens makes fifty calls, and the holder has no batch for them. **AccessManager does this better.** What SCaaS gains is that
a wallet reads one token alone, and a global table gives a bit the same meaning everywhere, which no system below does: OZ roles are opaque hashes.

**Scope and limits.** The `Grant` is the strongest part of the design and the costliest. USDC's allowance is one storage word; a SCaaS grant measured **812,687 gas to set** on a
fresh holder with every field [meas], against v2's 90-110 k estimate, because six new slots pay Amsterdam's state gas. A limited mint measured 99,778 gas against 54,498 whole-shape
[meas]. Calldata condition systems (Zodiac, MetaMask) express far more; v2 rejects them
because calldata is not effect, a fair reason, but Zodiac and MetaMask bind things a `Grant` cannot: no general "at most x % per step" exists in SCaaS outside `maxRateStepBps`, and **Aave's risk stewards do that better**,
as does Curve's ramp.

**Delegation.** Two levels, on chain. MetaMask's is any depth, signed off chain, and costs nothing until used; Safe modules are unbounded. SCaaS narrows at grant and debits at use, which a wallet can
print without walking a chain; it is rigid, and a third level means a holder contract. Revoking a leaf by its grantor is the prototype's addition; v2 did not state it.

**Delay.** **SCaaS is plainly weaker here.** D4 delays one thing: a grant. It does not delay using a power, transferring ownership (C1 kept that), clearing a feature or
revoking. There is no execution delay per member, no guardian who can cancel a pending, no way to raise a delay after creation. AccessManager has all of these, with an expiry and a `minSetback`; Morpho's
vaults have per-function timelocks that are asymmetric by risk. Grant delay in SCaaS is immutable: simple, and it cannot be tightened when a token grows up.

**Lock or renounce.** Close to the best of the field. A bit that only loses itself is Token-2022's `None`, ASA's empty address, Morpho's `abdicate`, and capability-only-at-creation is
Hedera's and Aptos's rule. The renounce refusal (F12) is stricter than any of them: USDC has no path at all, Stellar's SAC leaves the false lock its docs warn about. The word "locked" reads oddly: on SCaaS it means
the power exists forever, the reverse of what `lock` means in most systems. A wallet must say so.

**Emergency and rescue.** **SCaaS has nothing built.** No pause on a token, none on the DEX, no guardian, no shutdown, and contracts cannot be patched. USDC, Aave, Compound, Maker,
Token-2022, Sui and Hedera all have a stop. If a SCaaS token has a bug, holders can only leave, and a holder of a confidential balance leaves through a proof. Flags 5-8 are specified but refused today. Patterns SCaaS lacks and the surveys found:
a pauser separate from the unpauser (EigenLayer, Wormhole), a one-shot expiring seal (Lido), permissionless recovery while paused (Balancer v3). `RESCUABLE` is better in one way: nobody picks the destination, where USDC's rescuer and Aave's `POOL_ADMIN` do. It is weaker in another: on the DEX a
stray goes to the first submitter, and on `WrappedPqzToken` it may not fit.

**Regulated controls.** **ERC-3643, Hedera and Token-2022 are live and SCaaS is a specification.** ERC-3643 has identity, modular compliance and partial freeze. SCaaS's spec is narrower in a way worth
keeping: a forced transfer needs a recorded order, a frozen subject and a recorded beneficiary, and freezes and pauses are time-bound (CTR-AS-04, CTR-AS-05). None of that has run. Regulated versions of `WrappedPqzToken` and
`WrappedZetherToken` are open, owner, not designed; the room measured for them is in §4.

**Gasless or relayed admin.** Safe has had this for years: anyone submits, signatures authorize, the Safe refunds in a token. SCaaS's holder is a design. Native fee payers on Solana, Aptos, Sui and Hedera solve the gas half with no contract
at all, though not the asynchronous half. MetaMask's redeemer is the closest in spirit. SCaaS's rule puts typed entries in one contract, so a wallet shows fields; a Safe transaction shows `data` unless the wallet decodes it.

**Threshold and PQ holder.** This is the one column where SCaaS has no peer in the sources read: nothing above offers a threshold of post-quantum signers as an owner. It is also unbuilt and unaudited, the
verifiers are home-written, and the bound is tight: two ML-DSA-65 signers do not register on a chain without a precompile. A Safe with an ERC-1271 PQ owner is possible in principle, and it would hit a gas cap of its own that nobody has measured here [I]. Key
rotation is the other gap: members of an `msig` cannot change, and the holder's rotation is a proposal.

**Confidential tokens.** Solana's confidential transfers are the only comparable live system in the table, and its docs state the same interaction SCaaS met: a permanent delegate does not reach a confidential balance. Solana has an auditor key the
authority can rotate or remove; SCaaS's Zether and PQZ auditor is fixed at creation, with no rotation. PQZ has no equivalent anywhere above. Both SCaaS lines are `UNAUDITED`.

**Cross-chain sameness.** Nothing else above tries it: each system is one chain, or one deployment per chain. That is a claim, not a result. Today Soroban and NEAR have a write-once admin, Algorand too, Sui's `AdminCap`
cannot move, and the EVM model is the only one prototyped. "One rule on every chain" costs a design per family, and bridges (LayerZero, Wormhole) show how inherited powers undo sameness.

**Upgrades.** Same camp as Uniswap pools and Morpho Blue: immutable. **USDC, Aave, Compound and ERC-3643 can fix a live bug in an hour and SCaaS cannot.** SCaaS's position removes an admin key over balances at the price of no hotfix; Euler
lets each vault choose. Wormhole's upgrade with invariant checks is a middle SCaaS has rejected by rule, not by finding it wrong.

## 3. What was re-checked

| Row | Claim | Result |
|---|---|---|
| USDC | owner transfer is single-step, no delay | [F] `stablecoin-evm` `Ownable.sol` |
| Uniswap v3 | protocol fee bound, pool fee immutable, no pause, no upgrade | [F] `UniswapV3Pool.sol` |
| Morpho | `MAX_FEE` 25 % (Blue); MetaMorpho timelock 1 day to 2 weeks, `MAX_FEE` 50 % | [F] both `ConstantsLib.sol` |
| ERC-3643 | owner adds agents; agent-only list; no timelock in the token; meant for a proxy | [F] `Token.sol`, `AgentRole.sol` |
| Safe | anyone submits; refund in native or token; signature types include secp256r1 | [F] `Safe.sol`. Upgrade by `delegatecall` stays [M] |
| Token-2022 | permanent delegate, pausable, hook, confidential interaction | [F] extensions page. "Every extension before `InitializeMint`" as a general rule stays [M]; the page states it for some |
| Sui | `TreasuryCap`, `DenyCapV2`, pause timing | [F]. Fixed-supply modes of `coin_registry`: not on that page, left out |
| Hedera | key roles and fixed properties | the page fetched does not describe them: roles stay [M]. It says a key "cannot be removed"; the survey read HIP-540 as allowing removal; `hips.hedera.com` refused the fetch (403). **Unsettled** |
| Aave | `EMERGENCY_ADMIN` pauses; `POOL_ADMIN` alone rescues; `BRIDGE` deprecated | [F] `ACLManager` page |
| Compound | pause guardian's five actions; `deployAndUpgradeTo` | [F]. The 2-day delay is not on the page: stays [M] |
| Stellar | `set_admin` | [F] |
| OpenZeppelin | `minSetback` 5 days, `expiration` 1 week, `setTargetClosed`, grant and execution delays, `DefaultAdminRules` | [F] local checkout |

Left at their tags, not re-checked: Uniswap governance timelock; fee-payer and multisig cells for Solana, Hedera, Stellar, Algorand, Sui and Aptos. Nothing in this note depends on them for a conclusion, and they
are not stated as fact.

## 4. Figures quoted

All from [prototype/RESULTS.md](prototype/RESULTS.md). The two tightest contracts, the bytes left to the 64,500 B stop line, which is also the room a regulated form of each would have, before D4 and D6: as designed `WrappedPqzToken` is 1,020 B over and `WrappedZetherToken` has 216 B; with the fallback, 485 B and 1,725 B. That is too little. The `msig` limits in §1 are computed from the registry's bound and its gen-1 caps, not measured on a chain. No figure in this note is an estimate except where it says so.
