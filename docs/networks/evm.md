# EVM chains

Common rules for every family: [networks/README](README.md). Contracts: [contracts/](../contracts/README.md).
Status: **BUILT** on the private chain 7622 and anvil; public chains are seeded as `draft` profiles.

**Contents**

1. [Chains](#1-chains)
2. [Private reference chain 7622](#2-private-reference-chain-7622)
3. [Precompiles](#3-precompiles)
4. [Deployment](#4-deployment)
5. [EIP-7702 accounts](#5-eip-7702-accounts)
6. [Limitations](#6-limitations)

## 1. Chains

<a id="chains"></a>

| Chain | Chain id | Profile | Gas | Finality gate | Status |
|---|---|---|---|---|---|
| Private reference chain | 7622 | `private7622` (Solidity `osaka`) | free (base fee 0) | depth 1, quorum 1 | BUILT, first target |
| Anvil (tests) | 31337 (also 1337) | — | — | depth | BUILT (dev only) |
| Gnosis Chain | 100 | `gnosis` (`osaka`; Pectra since 2025-04-30, then Fusaka) | native xDAI (stable value) | `tag finalized` (~160–240 s), quorum ≥ 2 independent RPCs | seeded `draft` until the operator gate passes |
| Celo | 42220 | `celo` (`osaka`, owner 2026-10-11; the chain's fork level is not re-measured) | CELO; fee currencies optional | `l1_batch` (PLANNED) | seeded `draft` |
| BNB Smart Chain | 56 | `bsc` (`osaka`; Mendel = Osaka since 2026-04-28) | BNB (~0.05 gwei) | `tag finalized` (BEP-126 fast finality, ~1 s), quorum ≥ 2 | seeded `draft` |
| Polygon PoS | 137 | `polygon` (`osaka` opcode set; no named Osaka fork) | POL (~250–300 gwei) | `tag finalized` (milestones, ~3–6 s); `safe` unsupported | seeded `draft` |
| Base | 8453 | `base` (`osaka`; Azul since 2026-05-28) | ETH (~0.005 gwei) + L1 data fee | `l1_batch`: `safe` ~90 s, `finalized` ~16 min | seeded `draft` |

- **Gnosis Chain (100)** is the recommended public chain for B2B: native gas is xDAI, a stable-value coin, so gas
  costs are predictable in unit, though their size still follows the gas price (the often-quoted < $0.001/tx is not a
  measurement). Hard finality is ~160–240 s, not 12.8 min: the Gnosis beacon chain uses 16 slots × 5 s =
  80 s per epoch, and finalization takes two epochs (≈ 160 s); the profile records 240 s. The switch from `draft`
  to `enabled` needs a measured p99 of the `latest` → `finalized` gap over 7 days on mainnet. EIP-2537
  (BLS12-381) is live (below).
- **Celo (42220)** has been an Ethereum L2 on the OP Stack since March 2025; every older assumption (Istanbul BFT,
  5-second blocks, immediate finality) is void, and its finality figures must be measured again. Finality mode
  `l1_batch` is PLANNED. Celo's native fee abstraction (**CIP-64**, transaction type `0x7b` with a `feeCurrency`
  field; the allowed currencies are listed in the fee-currency directory of CIP-52) lets a sender pay gas in an
  allowed ERC-20; SCaaS does not depend on it (relayers pay CELO), and clients that use CIP-64 must add ≈ 50 000
  intrinsic gas for the fee currency. Foundry (`cast`/`forge`) cannot encode a `0x7b` transaction, so CIP-64 cannot
  be tested with it. Paying fees in a stablecoin does not make the cost fully predictable: the fee is paid in that
  token but still priced by the network.
- <a id="NET-EVM-01"></a>**NET-EVM-01** — **Celo fee-currency support (CIP-64) for relayer lanes is an open owner
  requirement.** Lanes pay native CELO; paying gas in an allowed stablecoin is a seam, not specified. Status `open`.

- **BNB Smart Chain (56), Polygon PoS (137), Base (8453)** are seeded `draft` (owner 2026-10-11) from a sourced and
  RPC-probed survey of 2026-10-11 (live `eth_call`/`eth_estimateGas` probes): EIP-2537 (`0x0b`–`0x11`), EIP-7702 and
  P-256 at `0x100` (EIP-7951) are live on all three, and the deterministic CREATE2 deployer `0x4e59…956c` exists on each
  mainnet and its main testnet (97, 80002, 84532). Differences that matter: **Polygon** allows 32,768-byte contracts
  (chain-specific, since Ahmedabad 2024-09-26) and a 33,554,432 per-transaction gas cap (2^25), while BSC and Base keep
  24,576 and 16,777,216 — SCaaS stays within the smaller values so CREATE2 addresses and transactions are the same
  everywhere; Polygon has no `safe` tag and its 2025 history includes milestone stalls and reorgs, so a stalled
  `finalized` pauses crediting instead of falling back to a shallow depth; **Base** has a single sequencer whose
  `latest`/Flashblocks confirmations are preconfirmations only, and its fee adds an L1 data fee that `eth_estimateGas`
  does not include (relayers budget it from calldata size); **BSC** blocks come almost entirely from two builders
  (BEP-322 PBS), so private submission goes through builder RPCs. Public RPCs that worked on 2026-10-11:
  `bsc-dataseed.bnbchain.org`, `bsc-rpc.publicnode.com`; `polygon-bor-rpc.publicnode.com`, `polygon.drpc.org`
  (`polygon-rpc.com` answered 401/403); `mainnet.base.org` (rate-limited), `base-rpc.publicnode.com`. The switch to
  `enabled` follows the same operator gate as Gnosis (measured finality p99 over 7 days, RPC quorum, a passing deployment).

Other EVM chains (Ethereum L1, Arbitrum, Optimism, Avalanche, Linea) are **unsupported until
configured**: no profile, no finality gate, no tested deployment. A chain becomes supported only through a chain
profile with a measured finality gate, an RPC quorum and a passing deployment. Reference values for such a profile,
to be re-measured before use: Ethereum L1 12-s slots, finality = 2 epochs (~12.8 min); Arbitrum One / Base sequencer
confirmation ~1 s (soft) vs L1 batch finalization ~15 min (hard); Polygon PoS checkpoint ~25–30 min. A finality gate
is always the hard value. Gas is never assumed: Zether-sized transactions do not fit every L2 block.

## 2. Private reference chain 7622

<a id="private-chain"></a><a id="private-7622"></a>

<a id="NET-EVM-02"></a>**NET-EVM-02** — **The private reference chain is chain id 7622; its identity is the pair
(chain id 7622, genesis hash `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`), profile
`private7622`.** Owner ruling 2026-10-07. Chain id `0x1dc6`; the chain was reset with a new genesis when it moved
from 9000, which is also Evmos Testnet — replay protection is only as good as the chain id, so every signer and node
also binds the genesis hash ([NET-ALL-22](README.md#NET-ALL-22)). Genesis hashes of the live EVM chains, two sources each, are in [`chain-uids.json`](../../smartcontracts/evm/chain-uids.json). Nodes bind the profile to the genesis hash, not to
the chain id alone. The profile, seeds, environment variable names and test vectors use `private7622`; the chain's
directory is `src/chains/private7622`.

<a id="NET-EVM-03"></a>**NET-EVM-03** — **The first target chain is the private PoA chain; public chains follow, and
CI builds the `private7622` profile.** Owner decision. Gas is free there, so gas is not a constraint for the first
deployments (confidential payments run there first), and precompile measurements need no faucet.

<a id="NET-EVM-04"></a>**NET-EVM-04** — **A single-signer PoA chain is named honestly.** With one Clique signer the
chain is not a decentralized blockchain in any sense — it is a hashed, signed database: fine for demos and internal
operation, but product material never calls it decentralized, the threat model lists the single signer (one point
of censorship and of failure), and partners running real B2B on it are told who controls the signer. Owner decision.

Parameters:

| Parameter | Value |
|---|---|
| Client | Nethermind 1.39 |
| Consensus | Clique PoA, one signer, `period` 5 s, `epoch` 30000 |
| Forks | live through Fusaka + BPO2: EIP-2537 (BLS12-381), EIP-7951 P-256 at `0x100`, EIP-7825 per-transaction gas cap 16,777,216, EIP-7623, EIP-7934 |
| Base fee | 0 (gas free; `MinGasPrice` 0) |
| Contract code size | 64 KiB (`maxCodeSize` `0x10000`, `maxCodeSizeTransition` 6432) since 2026-10-11, owner, ahead of Glamsterdam (cf. EIP-7954); 24,576 before. Probed at block 6434: 65,536 B code deploys (13.27 M gas), 65,537 B is refused, a 50,005 B init code is accepted (the init-code limit follows `maxCodeSize`). Public chains keep 24,576 |
| Block gas limit | 16,777,216 today (`0x1000000`); 80 M `TargetBlockGasLimit` target for post-quantum Zether ([CTR-PQZ-11](../contracts/pq-zether.md#CTR-PQZ-11)) (SPECIFIED) |
| Finality | depth 1, quorum 1 (single-provider trust, reported as such) |
| Classical Zether | not on the dev-chain allowlist ({31337, 1337}, [CTR-ZTH-02](../contracts/zether.md#CTR-ZTH-02)); whether 7622 becomes a dev chain for it is an open owner question |
| Post-quantum Zether | the only PQZ chain: precompile in our client image ([chain integration](../contracts/pq-zether.md#chain-integration)) |

Operator trap, measured on the earlier chain: **a Nethermind chainspec silently ignores Geth-style keys.** With
`pragueBlock: 0` (and `londonBlock`, `cancunBlock`) in Geth form, the chain ran pre-London without a warning: the
BLS12-381 precompiles `0x0b`/`0x0c`/`0x0f`/`0x10` were empty while `alt_bn128` `0x06`/`0x07` answered; headers had no
`baseFeePerGas` (no EIP-1559), no `withdrawalsRoot` (no Shanghai), no `blobGasUsed`/`excessBlobGas` (no Cancun).
Forks must be written with Nethermind's own keys (`eip1559TransitionTimestamp`, `eip2537TransitionTimestamp`, …),
and changing them changes the genesis hash (chain reset). The only detection is to inspect a block header or call
the precompile — the deployment checklist does both. The chainspec was fixed on 2026-08-31 before the reset to
7622. The 16,777,216 block gas limit admits only ~5 classical confidential transfers per block (3.29 M gas each,
measured); post-quantum Zether raises the target to 80 M ([CTR-PQZ-11](../contracts/pq-zether.md#CTR-PQZ-11)).

## 3. Precompiles

<a id="precompiles"></a>

- **EIP-2537 (BLS12-381) is live on Gnosis and Celo.** Measured 2026-08-30 with real `eth_call` to public RPCs,
  all-zero inputs valid under EIP-2537 (G1ADD 256 B, G1MSM 160 B, PAIRING 384 B, MAP_FP 64 B), control `alt_bn128
  ecAdd` (`0x06`) returning 64 B on both:

  | Precompile | Address | Gnosis | Celo |
  |---|---|---|---|
  | `BLS12_G1ADD` | `0x0b` | live (128 B) | live (128 B) |
  | `BLS12_G1MSM` | `0x0c` | live (128 B) | live (128 B) |
  | `BLS12_PAIRING_CHECK` | `0x0f` | live (32 B) | live (32 B) |
  | `BLS12_MAP_FP_TO_G1` | `0x10` | live (128 B) | live (128 B) |

  A missing precompile returns empty `0x`; an input-length error (`invalid input length` on Celo, `PrecompileError`
  on Gnosis) also proves the code exists. Live is not cheap: measured costs are in
  [contracts/zether](../contracts/zether.md).
- **P-256** (RIP-7212 / EIP-7951 at `0x100`): present on 7622; probed per chain (`has_p256_precompile`); without it
  OpenZeppelin's Solidity verifier costs ~200–330 k gas ([passkeys](README.md#webauthn)).

## 4. Deployment

<a id="deployments"></a>

<a id="NET-EVM-05"></a>**NET-EVM-05** — **SCaaS contracts are deployed through a deterministic CREATE2 deployer with
a fixed salt, with `chain_uid` read from the RPC, and the deploy gate checks every `chainUid()`.** Owner ruling
2026-10-07; status **SPECIFIED**. The deploy script reads the chain's genesis block hash from the RPC (from ≥ the
profile's RPC quorum) and passes it as the `chain_uid` constructor argument of every contract that takes one
([NET-ALL-22](README.md#NET-ALL-22)): the token implementations, the factory, `SmartKeyAccountFactory`, `SCaaSDex`,
the Universal Account registry, and any later contract that checks a signature. Every deployment — implementations,
factories, registry, DEX — goes through one deterministic CREATE2 deployer with a fixed per-contract salt, so an
address depends only on the init code: a contract whose constructor takes `chain_uid` (and every clone of it) has a
different address on each chain, one without a chain-specific argument the same address on every chain. Before the
run passes, the deploy gate requires, for each deployed contract, `chainUid()` = the RPC's genesis hash = the chain
profile's `chain_uid`; refuses a genesis hash already present in another chain profile
([NET-ALL-25](README.md#NET-ALL-25)); and requires the factory to have registered only implementations whose
`chainUid()` equals its own. The run writes `chain_uid` and the DEX list into `deployments/<chainid>.json`, which seeds
the chain profiles of the node and the clients ([NET-ALL-24](README.md#NET-ALL-24)). Why: a CREATE address depends on
the deployer's nonce, so the same contract lands at unrelated addresses on each chain and a missed transaction shifts
every later address; with CREATE2 the address follows from what was deployed. Cost: a fixed-salt deployer must exist on
each chain before the first deployment, and a redeploy with the same init code collides with the first (a new
version needs a new salt or new code).

Runbook notes: (1) read the genesis hash from every configured RPC and stop if they differ; (2) on a private chain,
confirm the genesis carries its unique `extraData` nonce before deploying; (3) deploy the CREATE2 deployer once per
chain, then the implementations, the factory, the subject-account factory, the registry and the DEX; (4) run the gate;
(5) publish the profile update (`chain_uid`, contract addresses, DEX list) to the node's chain row and the clients'
pinned profiles in the same release; the node re-checks every `chainUid()` at activation and every start
([NODE-GW-07](../node/gateway.md#NODE-GW-07)).

Transitional (BUILT, P1e): `smartcontracts/scripts/deploy.sh evm <rpc>` runs the forge script `script/Deploy.s.sol` (reads
`PRIVATE_KEY`, `REGISTRAR`, `DEPLOY_SALT`, `CHAIN_UID`) through the deterministic deployer at
`0x4e59b44847b379578588920ca78fbf26c0b4956c` (`new X{salt: DEPLOY_SALT}`; default salt `keccak256("scaas.deploy.v1")`) and
the gate of `DeployBase.sol`: `chainUid()` of the factory and of each implementation equals `chain_uid` (`CHAIN_UID` or
block 0's hash; past block 256 `CHAIN_UID` is required). The script stops when the deployer has no code: on such a
chain, deploy it first (the keyless presigned deployment transaction of that proxy, funded by a transfer to its signer)
and re-run. `forge script … --broadcast` needs `--sender <deployer address>`, which `deploy.sh` and the e2e pass; forge
places the linked libraries from that sender, not by CREATE2. It deploys `OpenFactory` with `NoUnderlyingToken` as
version 1 of `NONE` (`UnderlyingToken` is over EIP-170 and is not deployed until the size work) and, for the node until
P5, the v1 line (`OpenFactoryV1` with `MetaToken` as version 1 of `META`, `MetaTxDex`), `SubjectAccountFactory` and
`SCaaSDexV1` (plus the `SCaaSDex` implementation, registered as DEX version 1 on the factory), optionally a tier-1 demo token ([deploy](../contracts/README.md#build-ci-and-pins)). It writes
`deployments/<chainid>.json` (`factory`, `implementation`, `dex`, `subject_account_factory`,
`subject_account_implementation`, `scaas_dex`, `demo_token`, and `token_factory`, `implementation_none`, `dex_implementation`, `chain_uid`),
which seeds the client and the node configuration. Zether and the registry are not in the deploy script (dev chains only). Integration tests use `anvil --hardfork osaka --gas-limit 16777216 --code-size-limit 65536` (64 KiB code, as EIP-7954 proposes; owner 2026-10-11 — real chains keep 24,576, so a contract that only fits this anvil still cannot be deployed there).

Every contract is a non-upgradeable clone or a fixed deployment ([CTR-GEN-02](../contracts/README.md#CTR-GEN-02)):
upgradeable proxies (UUPS / ERC-1822) are not used, and a fix is a new implementation version registered on the factory
plus a voluntary migration.

## 5. EIP-7702 accounts

<a id="eip7702"></a>

An EOA that delegated its code through EIP-7702 is still a native account: SCaaS classifies `from` by its code
([CTR-UA-24](../contracts/accounts.md#CTR-UA-24)).

## 6. Limitations

<a id="limitations"></a>

- Celo `l1_batch` finality and CIP-64 lanes: PLANNED / open ([NET-EVM-01](#NET-EVM-01)).
- Public profiles stay `draft` until their finality gate is measured and an RPC quorum ≥ 2 is configured.
- Chain 7622 has one signer and one RPC provider (the node's quorum is 1); its threat profile is in
  [NET-EVM-04](#NET-EVM-04).
