# Contracts — common rules

This folder specifies the on-chain programs of SCaaS: the meta-transaction layer every token carries, the token
tiers and their factory, subject accounts and mandates, the order-book DEX, the sealed-bid tender, the asset suite,
classical and post-quantum confidential tokens (Zether), and the Universal Account (UA) registry. This page holds
the rules every one of them shares. Status tags (**BUILT**, **SPECIFIED**, **PLANNED**) follow the convention of
[docs/README.md](../README.md).

| File | Covers | Status |
|---|---|---|
| [accounts.md](accounts.md) | the three account forms; Universal Account (ids, kinds, registry, verifiers, credentials, migration); passkeys on chain; the optional `SubjectAccount` smart account and its factory, guardians | UA **SPECIFIED**; `SubjectAccount` **BUILT** |
| [metatx.md](metatx.md) | the one base `ERC20MetaTx`: `MetaTransaction` struct, typehash, `mode`, 2D nonces, `mtxExecute` (generic self-call, ticket, selector allowlist, fee classes), `mtx` names, pay references and the pay-once horizon, receiver-pays | **SPECIFIED** (built as the v1/v2 lines) |
| [token-wrappers.md](token-wrappers.md) | three token tiers, conversion rates, multi-underlying wrappers, signature wrap, the one `OpenFactory`, allowance rule | tiers **BUILT** (EVM, Hedera); one base and factory **SPECIFIED** |
| [dex.md](dex.md) | `OrderBookDex` with token-verified `TradeOrder`s, outside-token legs, managed-market venue contract | **SPECIFIED** (built with DEX-signed orders over allowances) |
| [tender.md](tender.md) | `SealedBidTender` | **SPECIFIED** |
| [asset-suite.md](asset-suite.md) | regulated module, vesting, distributions, corporate actions, templates | **SPECIFIED** |
| [zether.md](zether.md) | classical Zether, byte-exact; limits; decryption bound | **BUILT, UNAUDITED** (dev chains) |
| [pq-zether.md](pq-zether.md) | post-quantum Zether on private/PoA chains | **SPECIFIED, UNAUDITED** |
| [mandates.md](mandates.md) | `MandateWallet`: delegated, capped payment from the payer's own wallet; auto-pay client integration | **BUILT**; revocation epoch **SPECIFIED** |

The node that relays these contracts is specified in [docs/node/](../node/README.md); the per-family programs
(Hedera, Cosmos, Soroban, Sui, Aptos, Solana, TON) in [docs/networks/](../networks/README.md).

## Conventions

Built interfaces are quoted from `smartcontracts/evm/src` (Solidity 0.8.28, OpenZeppelin 5.2). Proposed interfaces
are normative targets for future versions and keep the built conventions: custom errors, EIP-712 domains on the
contract itself, lane nonces, contract-only allowances, no proxy upgrades.

EIP-712 domains: name per implementation (`"SCaaS MetaToken"`, `"SCaaS ZetherToken"`, `"SCaaS MandateWallet"`,
`"SCaaS SubjectAccount"`, `"SCaaS OrderBookDex"`, `"SCaaS PqzToken"`, `"SCaaS UARegistry"`), version `"1"` (the UA
registry: its generation), `chainId`,
`verifyingContract` = the clone or contract itself, `salt` = the chain's `chain_uid` ([CTR-GEN-05](#CTR-GEN-05)). All
clones of one implementation share the name; replay safety comes from `verifyingContract` and the salt
([CTR-MTX-02](metatx.md#CTR-MTX-02)). Clients read `eip712Domain()` (ERC-5267), never a constant.

<a id="CTR-GEN-05"></a>**CTR-GEN-05** — **`salt = chain_uid` in every EIP-712 domain of a SCaaS contract and in every
chain-bound non-EIP-712 digest** (owner). Every domain is `(name, version, chainId, verifyingContract, salt =
chain_uid)` and `eip712Domain()` returns fields `0x1f`; one helper, `SaltedEIP712` (OpenZeppelin `EIP712` has no salt),
serves every contract and rebuilds the separator whenever `address(this)` differs from the cached one (clones share
the implementation's immutables). `chain_uid` is the chain's genesis block hash as its RPC reports it
([NET-ALL-22](../networks/README.md#NET-ALL-22)). Where it comes from:

| Contract | Source of `chain_uid` |
|---|---|
| token implementations (the tiers, their Hedera children, `ZetherToken`) | constructor immutable of the **implementation**; a clone runs its code by `DELEGATECALL`, so it uses the value with no storage and no `initialize` argument and cannot declare another one |
| `OpenFactory` | constructor immutable; `registerImplementation` refuses an implementation whose `chainUid()` differs ([CTR-TOK-03](token-wrappers.md#CTR-TOK-03)) |
| `SubjectAccount` | the factory's constructor argument, passed to `new SubjectAccount(chainUid)` |
| `MandateWallet`, `HederaMandateWallet` | constructor argument from the chain profile; the node checks it before relaying for that wallet |
| `OrderBookDex` | constructor argument |
| built `UniversalAccountRegistry` | constructor immutable, in its PoP challenge; it checks raw digests, so every caller's digest carries `chainUid` ([CTR-ZTH-36](zether.md#CTR-ZTH-36)) |
| `UARegistry` | constructor immutable ([CTR-UA-07](accounts.md#CTR-UA-07)) |
| any later contract with a signature (tender, asset suite) | the same helper, constructor argument |

The deploy script reads the genesis hash from the RPC; the deploy gate and the node, at chain activation and every
start, require each contract's `chainUid()` = the RPC's genesis hash = the chain profile, and refuse a mismatch (the node
also refuses to relay for a wallet or account whose `chainUid()` differs). A contract cannot read its own genesis hash
after block 256, so this is checked off chain. A wrong value makes correct signatures fail; it is unsafe only if it
equals **another** chain's `chain_uid`, which the per-contract check against the RPC excludes. Signing clients fill
`domain.salt` from the chain profile (works offline) or from `eip712Domain()` (read once, cached); wallets such as
MetaMask sign the domain they are given and check only `chainId`, and clientkeys refuses a `salt` that differs from the
profile. What protects is the contract: on chain B the digest uses B's `chain_uid`, so a signature for chain A reverts
there, whichever wallet produced it. **Limit:** a genesis hash separates chains with different genesis blocks that
share a chain id (another network on 7622, a private chain re-created with a new genesis). It does not separate two
branches of a fork (they share genesis) nor a PoA chain re-created from the **same** genesis file. The second is closed
by the deploy gate: every private chain's genesis carries a unique `extraData` nonce, and a genesis hash already
present in any chain profile is refused. The first is ruled by the owner: a fork of a chain we run is a **new chain** —
new chain id and `chain_key` — enforced by the deploy gate; on public chains, where a fork without a chain-id change
replays on both branches, it is a documented residual. On Hedera `chain_uid` is the relay's block-0 hash, fixed only
after the Hedera profile confirms it is stable across mirror-node and relay restarts. **Transitional (BUILT):** only
the UA registry design carries the salt; built token, wallet, account and DEX domains have none.

## Immutable at deploy

<a id="CTR-GEN-02"></a>**CTR-GEN-02** — **Every program that holds subject value is immutable from the moment it is
deployed.** There are no proxy upgrades anywhere (no UUPS, Transparent, Beacon or Diamond proxy). A bug fix is a new
deployment at a new address plus voluntary migration by the owners of the balances, never an in-place upgrade.
Versions live in the factory, immutability lives in the token:

| | Who can change it | Affects |
|---|---|---|
| Version catalogue in the factory | the registrar can add a version | only tokens deployed **after** that |
| A deployed token | **nobody** | — |

Three catalogue invariants: (1) **append-only** — a registered `(kind, version)` never points elsewhere
(`VersionAlreadyRegistered`), so "I want v1" is never a moving target; (2) **`deprecate()` marks, never blocks** —
`createUnregistered` bypasses the catalogue anyway, so a block would buy only the power to stop others from
deploying; the real job is a signal (event, wallet warning, indexer flag); (3) **`createUnregistered` exists** — a
token created this way has `version() == 0`, visibly, so wallets can tell "runs published v2" from "runs code its
creator brought". A bug in v1 is permanent for every v1 token; the only remedy is migration (unwrap v1, wrap v2),
one holder at a time, nobody forced. With EIP-1167 clones the `init_code` depends only on the implementation, so
`predictAddress` is fully determined and computable off chain.

The same rule on every family:

| Family | How immutability is reached at deploy |
|---|---|
| EVM, Hedera | 45-byte EIP-1167 clones of never-upgraded implementations; no proxy |
| Aptos | `Move.toml` `upgrade_policy = "immutable"`; the package registry at the package address reports policy immutable |
| Sui | `0x2::package::make_immutable(UpgradeCap)` in the same deploy run, right after `sui client publish`; the `UpgradeCap` object no longer exists |
| Solana | deploy with a temporary authority, run `initialize` (its `Initialize` accounts require the upgrade authority, `account.rs:16-26`; it takes no `network` argument, the network is a build-time constant), then `solana program set-upgrade-authority <id> --final`; `solana program show <id>` reports `Authority: none`; the `Config` PDA cannot be re-created afterwards (PDA `init` + no authority) |
| Cosmos | instantiate with `--no-admin` ("no proxy upgrade on any contract that holds value") |
| TON, Soroban | immutable as built |

- **Deploy-script gate.** `smartcontracts/scripts/deploy.sh` (aptos, sui) and `solana/scripts/deploy.sh` end with a
  check that fails the run (non-zero exit) if the deployed program is still upgradeable — Aptos registry policy ≠
  immutable, Sui `UpgradeCap` still present, Solana `Authority` ≠ none, Cosmos contract admin ≠ empty. Local test
  validators are not exempt (the gate is the same everywhere, so tests exercise it).
- **Existing dev deployments** that are still upgradeable (single key) are abandoned and redeployed immutable; node
  chain profiles and client chain data get the new package/program ids (dev funds only).
- **Node check.** The node reads upgradeability per chain and halts a chain whose program is upgradeable
  ([NODE-STO-07](../node/store.md#NODE-STO-07)).
- Why it matters: a held upgrade key lets one server-side key publish a `drain` entry over the stored
  `ExtendRef`/PDA seeds for every subject on that chain — the failure mode of hosted node and wallet services that
  SCaaS exists to remove.
- Tests: each deploy script run against its local network ends green only when the gate passes; a negative test
  (skip the freeze step) makes the gate fail; a Solana `initialize` after `--final` fails.

Status: EVM, Hedera, TON, Soroban **BUILT**; Aptos, Sui, Solana freeze steps, Cosmos `--no-admin` and the
deploy-script gate **SPECIFIED**.

## Admin powers (complete list)

"Your key, your funds" holds for every value-holding contract except the powers listed here. Each is fixed at
creation or deployment, public on chain, and none can mint arbitrarily, move a balance, touch a reserve, pause an
exit or upgrade code.

| Contract | Holder | Powers | Rule |
|---|---|---|---|
| `OpenFactory` | `registrar` (immutable; an EOA by default — the deployer — and a multisig before mainnet) | `registerImplementation`, `deprecate`, `setZetherEnabled` (dev chains only); none over any token | [token-wrappers](token-wrappers.md#factory) |
| `SingleUnderlyingToken` / `MultiUnderlyingToken` with an adjustable rate | `rateAdmin` (has code; chosen at creation) | propose / cancel / execute a bounded, timelocked rate change; renounce | [CTR-TOK-06](token-wrappers.md#CTR-TOK-06) |
| `MultiUnderlyingToken` | `guardian` (optional, chosen at creation) | `disableWrap(underlying)`, one-way; renounce | [CTR-TOK-07](token-wrappers.md#CTR-TOK-07) |
| `NoUnderlyingToken` | `minter` (optional; `0` = fixed supply) | `mint`, `renounceMinter` | [CTR-TOK-09](token-wrappers.md#CTR-TOK-09) |
| `OrderBookDex` | immutable `admin` (a multisig in production; the venue operator's multisig for a managed market) | `setMarket` (list or delist a pair), `setFeeSplit` (relayer share and treasury of the signed fee; never the amount) | [CTR-DEX-03](dex.md#CTR-DEX-03) |
| Regulated tokens (kinds 5–7) | `issuer`, `compliance` (contracts, fixed at creation) | the `controls()` bits set at creation: freeze, forced transfer against a recorded order, bounded pause, allowlist; bits can only be cleared | [CTR-AS-03](asset-suite.md#CTR-AS-03) |
| `ZetherToken` | none after `initialize` (the auditor key is immutable) | — | [CTR-ZTH-09](zether.md#CTR-ZTH-09) |
| `SealedBidTender`, `VestingGrant`, `Distribution`, `ExchangeOffer`, `UARegistry` | none | — | per file |
| Non-EVM DEX programs | market admin | set markets only; no sweep of user funds, no admin refund of bounced payouts ([NET-TON-03](../networks/ton.md#NET-TON-03)) | [networks/](../networks/README.md) |

## Production gates (UNAUDITED)

<a id="unaudited"></a>

No contract of this repository has had a third-party audit. Every value-holding contract family (Solidity, Move,
Soroban, CosmWasm, Tact, Solana) needs an independent audit before it holds real funds; the factory registrar moves
to a multisig before mainnet; real deployments are recorded in `deployments/<chain>.json`. The confidential-token
families carry stronger gates, enforced in code:

| Gate | Rule | Status |
|---|---|---|
| Classical Zether dev gate | `ZetherSafety.isDevChain()`: `chainid ∈ {31337 (anvil/hardhat), 1337 (geth --dev)}`, a hard-coded allowlist; `OpenFactory.zetherEnabled` defaults to `false`; `setZetherEnabled(true)` (registrar) reverts outside a dev chain; `createZetherToken`/`createUnregistered(ZETHER)` revert when the flag is off **or** the chain is not a dev chain; `ZetherToken.initialize`, both verifier constructors and the built `UniversalAccountRegistry` revert outside a dev chain too, so a manual deploy cannot bypass it ([CTR-ZTH-02](zether.md#CTR-ZTH-02)) | **BUILT** |
| Adding a chain to the classical allowlist | a code change of `ZetherSafety` plus a new deployment, after the cryptographic audit | — |
| Chain 7622 as a classical Zether dev chain | whether chain 7622 counts as "dev": not a dev chain until the owner decides ([CTR-ZTH-33](zether.md#CTR-ZTH-33)) | open |
| Production curve for classical Zether | bn254 vs BLS12-381; BLS12-381 is more secure and **not** cheaper ([CTR-ZTH-32](zether.md#CTR-ZTH-32)) | open |
| Cryptographic audit | independent audit of the Σ-Bulletproofs protocol, the transcript, the inner-product argument and the registry PoP **before** any dev gate is lifted | open |
| Gas before public chains | the bn254 transfer (3.29 M execution gas) exceeds the 2.5 M per-transfer kill criterion; optimization is required before a public chain | open |
| PQ Zether gate | hard-coded allowlist (31337, 1337 and the private chain 7622) **and** a constructor precompile self-test; `OpenFactory.pqzEnabled = false` by default; release gates: licences/patents and audit ([CTR-PQZ-01](pq-zether.md#CTR-PQZ-01)) | **SPECIFIED** |
| Clients | every Zether and PQ Zether contract carries **UNAUDITED — NOT FOR PRODUCTION FUNDS** in its NatSpec; client chain/token screens show an UNAUDITED warning | **BUILT** (NatSpec) |

## Build, CI and pins

<a id="build-pins"></a>

<a id="CTR-GEN-01"></a>**CTR-GEN-01** — Contracts have their own CI workflow (`.github/workflows/blockchain-ci.yml`),
run on every PR/push that touches `smartcontracts/**` or `scaas-node/**`: (a) forge (foundry-toolchain) with
`lib/` installed by `forge install` at pinned tags — OpenZeppelin `v5.2.0`, forge-std `v1.16.2` — because `lib/` is
not committed; both profiles; (b) cargo test + clippy `-D warnings` + the anvil end-to-end tests; (c) each family's
own job (Move test, Soroban, CosmWasm, Tact, Solana) as the family is added.

| Pin | Value |
|---|---|
| Solidity | `solc_version = "0.8.28"`, `optimizer_runs = 200`, `via_ir = false` (the 13-parameter named function is decoded by hand instead, see [metatx.md](metatx.md#named-functions)) |
| OpenZeppelin, forge-std | `v5.2.0`, `v1.16.2` |
| EVM profiles | `private7622` = `evm_version = "prague"` (the private reference chain, [NET-EVM-02](../networks/evm.md#NET-EVM-02)); `zether` = Prague (BLS12-381 needs EIP-2537); test chains run anvil `--hardfork prague` |
| Invariant runs | `[invariant] runs = 64, depth = 32, fail_on_revert = true` |
| Storage layout | `extra_output = ["storageLayout"]`; the v2 layout is pinned by `test_storageLayoutIsPinned` against committed JSON |
| Size | CI fails if any implementation exceeds 24 576 bytes (`forge build --sizes`, EIP-170) |
| EIP-1153 | `TLOAD`/`TSTORE` is a prerequisite of every token (transient reentrancy guard); a chain without it cannot hold an eligible token |

<a id="deploy"></a>Deploy (EVM): `script/Deploy.s.sol` (forge script; env `PRIVATE_KEY` = deployer and default registrar,
`REGISTRAR` optional, `DEMO_SUPPLY`/`DEMO_HOLDER` optional) reads the genesis hash from the RPC and deploys, through
the CREATE2 deployer ([CTR-GEN-06](#CTR-GEN-06)), `SubjectAccountFactory`, `OpenFactory` with the three tier
implementations (each taking the factory address and `chain_uid`) registered as version 1 of their kinds, and
`OrderBookDex(registrar, chainUid)`; optionally a tier-1 demo token (**SPECIFIED**). It writes
`deployments/<chainid>.json` to seed the node's chain configuration and client chain data. Production: every contract
owner/admin is a Safe from the first block, and deployer keys come from a hardware wallet or KMS. **Transitional
(BUILT):** the script deploys with `new` and also deploys factory v1 with the `MetaToken` implementation
(`registerImplementation(META, 1)` when the registrar is the deployer) and the legacy `MetaTxDex`.

<a id="CTR-GEN-06"></a>**CTR-GEN-06** — **Every SCaaS EVM contract is deployed through a deterministic CREATE2
deployer with a fixed salt** (owner): implementations, factories, registries and the DEX, instead of `new` (CREATE,
address = f(deployer, nonce)). A contract whose constructor takes `chain_uid` (implementations, factories,
`SubjectAccountFactory`, `OrderBookDex`, the registries) gets a **different address on each chain**, because its init
code differs; so does every clone, whose CREATE2 address depends on the implementation and the factory, and so does a
user's `SubjectAccount` (the node and app predict it per chain). A contract with no chain-specific constructor
argument gets the **same address on every chain**. Safety never rests on the address: the salt is in every digest
([CTR-GEN-05](#CTR-GEN-05)).

<a id="CTR-GEN-03"></a>**CTR-GEN-03** — On-chain code lives in its own tree at the repository root, one directory
per network family, each with its native layout and tool; `smartcontracts/scripts/` is the one place to build,
test, deploy and run a devnet:

```text
smartcontracts/
├── evm/          Foundry (forge): src/ test/ script/; real EVM chains = FOUNDRY_PROFILE
│                 (private7622, gnosis, celo); Hedera lives here too (src|test|script/hedera)
├── move/aptos/   Aptos Move package `scaas`
├── move/sui/     Sui Move package `scaas`
├── soroban/      Stellar Soroban cargo workspace (contracts/*)
├── cosmos/       CosmWasm cargo workspace
├── ton/          Tact + jest
├── solana/       cargo workspace (programs/*), LiteSVM tests
└── scripts/      build.sh, test.sh, deploy.sh, devnet.sh
```

Shared cross-implementation vectors live in `evm/test/vectors/` (contracts, node, clients) and per family.

## Issuer choices are not protocol decisions

<a id="CTR-GEN-04"></a>**CTR-GEN-04** — SCaaS deploys a protocol (an open factory), not tokens. Choices that belong to
whoever creates a token are not made by the protocol: the curve of a confidential token (chosen by its security
horizon), the ring size of a verifier (ring 2 reveals identities by design), whether a loyalty balance needs to be
confidential, which chain and archetype a loyalty programme uses, whether a confidential token has an auditor key
(optional per token), and any compliance profile (a property of the client system that chooses which tokens it
interacts with, not of the contract). The protocol provides the switches; the creator sets them and carries them.

## Availability

Per-family availability of every contract area is one matrix in
[networks/README.md](../networks/README.md#availability) ([NET-ALL-17](../networks/README.md#NET-ALL-17),
[NET-ALL-18](../networks/README.md#NET-ALL-18), [NET-ALL-19](../networks/README.md#NET-ALL-19)). In short: v2 token
tiers, receiver-pays, the tender and the asset suite are EVM and Hedera first; classical Zether is EVM only (dev
chains); PQ Zether is the private EVM chain only; the meta-transaction model itself exists natively on every family.
