# EVM chains

Common rules for every family: [networks/README](README.md). Contracts: [contracts/](../contracts/README.md).
Status: **BUILT** on the SCaaS testnet and anvil; public chains are seeded as `draft` profiles.

**Contents**

1. [Chains](#1-chains)
2. [Private SCaaS testnet](#2-private-scaas-testnet)
3. [Precompiles](#3-precompiles)
4. [Deployment](#4-deployment)
5. [EIP-7702 accounts](#5-eip-7702-accounts)
6. [Limitations](#6-limitations)

## 1. Chains

<a id="chains"></a>

| Chain | Chain id | Profile | Gas | Finality gate | Status |
|---|---|---|---|---|---|
| SCaaS testnet (private reference chain) | 7622 | `private7622` (Solidity `amsterdam`, [NET-EVM-06](#NET-EVM-06)) | free (base fee 0) | depth 1, quorum 1 | BUILT, first target |
| Anvil (tests) | 31337 (also 1337) | — | — | depth | BUILT (dev only) |
| Gnosis Chain | 100 | `gnosis` (`amsterdam`; Pectra since 2025-04-30, then Fusaka; deploy after its Glamsterdam fork) | native xDAI (stable value) | `tag finalized` (~160–240 s), quorum ≥ 2 independent RPCs | seeded `draft` until the operator gate passes |
| Celo | 42220 | `celo` (`amsterdam`; the chain's fork level is not re-measured; deploy after its Glamsterdam fork) | CELO; fee currencies optional | `l1_batch` (PLANNED) | seeded `draft` |
| BNB Smart Chain | 56 | `bsc` (`amsterdam`; Mendel = Osaka since 2026-04-28; deploy after its Glamsterdam fork) | BNB (~0.05 gwei) | `tag finalized` (BEP-126 fast finality, ~1 s), quorum ≥ 2 | seeded `draft` |
| Polygon PoS | 137 | `polygon` (`amsterdam`; runs the Osaka opcode set today; deploy after its Glamsterdam fork) | POL (~250–300 gwei) | `tag finalized` (milestones, ~3–6 s); `safe` unsupported | seeded `draft` |
| Base | 8453 | `base` (`amsterdam`; Azul since 2026-05-28; deploy after its Glamsterdam fork) | ETH (~0.005 gwei) + L1 data fee | `l1_batch`: `safe` ~90 s, `finalized` ~16 min | seeded `draft` |

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
  P-256 at `0x100` (EIP-7951) are live on all three (7702 accounts follow [§5](#5-eip-7702-accounts)), and the deterministic CREATE2 deployer `0x4e59…956c` exists on each
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

## 2. Private SCaaS testnet

<a id="private-chain"></a><a id="private-7622"></a>

<a id="NET-EVM-02"></a>**NET-EVM-02** — **The private reference chain is chain id 7622; its identity is the pair
(chain id 7622, genesis hash `0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164` since the 2026-10-31 reset (fs3 Task 13: the CREATE2 deployer in the genesis alloc, EIP-7702 off; `0xa17faef4…2ac2` from 2026-10-22, genesis gas limit 200 M); the client test vectors keep
the earlier `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464` as a fixed constant), profile
`private7622`.** Owner ruling 2026-10-07. Chain id `0x1dc6`; the chain was reset with a new genesis when it moved
from 9000, which is also Evmos Testnet — replay protection is only as good as the chain id, so every signer and node
also binds the genesis hash ([NET-ALL-22](README.md#NET-ALL-22)). Genesis hashes of the live EVM chains, two sources each (7622: one, its own local RPC), are in [`chain-uids.json`](../../smartcontracts/evm/chain-uids.json). Nodes bind the profile to the genesis hash, not to
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
| Client | Nethermind 2.2.0 |
| Consensus | Clique PoA, one signer, `period` 5 s, `epoch` 30000 |
| Forks | live through Fusaka + BPO2, and Amsterdam from block 1 on Nethermind 2.2.0 ([NET-EVM-06](#NET-EVM-06)); Fusaka: EIP-2537 (BLS12-381), EIP-7951 P-256 at `0x100`, EIP-7825 per-transaction gas cap 16,777,216, EIP-7623, EIP-7934 |
| Base fee | 0 (gas free; `MinGasPrice` 0) |
| Contract code size | 64 KiB (`maxCodeSize` `0x10000`, `maxCodeSizeTransition` 6432) since 2026-10-11, owner, ahead of Glamsterdam (cf. EIP-7954); 24,576 before. Probed at block 6434: 65,536 B code deploys (13.27 M gas), 65,537 B is refused, a 50,005 B init code is accepted (the init-code limit follows `maxCodeSize`). Public chains keep 24,576 |
| Block gas limit | 200,000,000 from genesis (`0xbebc200`, reset 2026-10-22, owner; `TargetBlockGasLimit` 200 M); 16,777,216 before. Per tx: regular gas ≤ 2^24 (EIP-7825), node `max_gas_per_tx` 64 M (owner 2026-10-22) |
| Finality | depth 1, quorum 1 (single-provider trust, reported as such) |
| Classical Zether | open (EIP-2537 live, [CTR-ZTH-52](../contracts/zether.md#CTR-ZTH-52), owner ruling 2026-10-31); deployed with `DEPLOY_ZETHER=1`, kinds enabled by the registrar |
| Post-quantum Zether | the only PQZ chain: `PQZ` `0x5caa500000000000000000000000000000000f01`, `MLDSA44` `…0012`, `MLDSA65` `…0013` from the plugin in image `scaas/nethermind-pqz:1.39.0-pqz1` (local, never pushed), chainspec `engine.Pqz` ([chain integration](../contracts/pq-zero-knowledge.md#chain-integration), [§3](#precompiles)) |

Operator trap, measured on the earlier chain: **a Nethermind chainspec silently ignores Geth-style keys.** With
`pragueBlock: 0` (and `londonBlock`, `cancunBlock`) in Geth form, the chain ran pre-London without a warning: the
BLS12-381 precompiles `0x0b`/`0x0c`/`0x0f`/`0x10` were empty while `alt_bn128` `0x06`/`0x07` answered; headers had no
`baseFeePerGas` (no EIP-1559), no `withdrawalsRoot` (no Shanghai), no `blobGasUsed`/`excessBlobGas` (no Cancun).
Forks must be written with Nethermind's own keys (`eip1559TransitionTimestamp`, `eip2537TransitionTimestamp`, …),
and changing them changes the genesis hash (chain reset). The only detection is to inspect a block header or call
the precompile — the deployment checklist does both. The chainspec was fixed on 2026-08-31 before the reset to
the SCaaS testnet. The earlier 16,777,216 block gas limit admitted only ~5 classical confidential transfers per block (3.33 M gas each,
measured); the 2026-10-22 reset starts at 200 M ([CTR-PQZ-11](../contracts/pq-zero-knowledge.md#CTR-PQZ-11)).

Further operator traps, found on the P6f copy of the SCaaS testnet (2026-10-15, `pqz-core/nethermind/runs/2026-10-15-copy-*.txt`):
**no follower can sync 7622's chainspec as it is** — `eip4844TransitionTimestamp` 0 without
`eip4895TransitionTimestamp` makes a syncing peer reject every block (`InvalidWithdrawalsRoot`: the header has no
`withdrawalsRoot`, its wire slot is a zero hash), and without `maximumExtraDataSize` (default 32 B) it rejects every
Clique header (97 B `extraData`; Nethermind's own Clique chainspecs set `0xffff`). A single signer never validates
its own blocks that way, so the live node never showed it. **Zero gas price does not stick:** after the first block
above the EIP-1559 target the base fee is 1 wei for good (the decrease rounds to 0), and the config key
`Mining.MinGasPrice` is not a Nethermind key (reported as an invalid setting; `Blocks.MinGasPrice` is, default 1 wei),
so a transaction priced at 1 wei is never mined; clients price at least `baseFee + 1`.

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
- **PQ precompiles on the SCaaS testnet** (P6f, plugin `Nethermind.Pqz`, [CTR-PQZ-10](../contracts/pq-zero-knowledge.md#CTR-PQZ-10)):
  `PQZ` `0x5caa500000000000000000000000000000000f01` (PQZL and PQZH proofs, per-row gas 2.57–5.41 M + 3 per word),
  `MLDSA44` `0x5caa500000000000000000000000000000000012` (49,000 + 6 per message word) and `MLDSA65`
  `0x5caa500000000000000000000000000000000013` (68,000 + 6 per word), EIP-8355 layout, empty context; prices frozen in
  the chainspec's `engine.Pqz` ([CTR-PQZ-11](../contracts/pq-zero-knowledge.md#CTR-PQZ-11)). The next image moves them to the
  32-bit form `0x000000000000000000000000000000005caa0f01` / `…5caa0012` / `…5caa0013` (spec 2026-10-20 §12 item 9; plugin built in plan 5h
  Task 8d part 1, not yet rolled out). A stock Nethermind image ignores
  that section and the addresses stay empty accounts (shown on the copy), so contracts self-test and nodes probe.
  Runbook: `pqz-core/nethermind/chain/RUNBOOK.md`.
- **P-256** (RIP-7212 / EIP-7951 at `0x100`): present on the SCaaS testnet; probed per chain (`has_p256_precompile`); without it
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
different address on each chain, one without a chain-specific argument the same address on every chain.

Before the
run passes, the deploy gate requires, for each deployed contract, `chainUid()` = the RPC's genesis hash = the chain
profile's `chain_uid`; refuses a genesis hash already present in another chain profile
([NET-ALL-25](README.md#NET-ALL-25)); and requires the factory to have registered only implementations whose
`chainUid()` equals its own. The run writes `chain_uid` and the DEX list into `deployments/<chainid>.json`, which seeds
the chain profiles of the node and the clients ([NET-ALL-24](README.md#NET-ALL-24)). Why: a CREATE address depends on
the deployer's nonce, so the same contract lands at unrelated addresses on each chain and a missed transaction shifts
every later address; with CREATE2 the address follows from what was deployed. Cost: a fixed-salt deployer must exist on
each chain before the first deployment, and a redeploy with the same init code collides with the first (a new
version needs a new salt or new code). On the SCaaS testnet the deployer is in the genesis `alloc` (owner ruling
2026-10-30 for the 7622 reset): 7622 carries the deterministic deployment proxy's runtime code at
`0x4e59b44847b379578588920cA78FbF26c0B4956C` from its 2026-10-31 reset (its keyless pre-EIP-155 deploy transaction, a
fixed 100,000 gas, cannot pay Amsterdam's code-deposit state gas). The same alloc is proposed for mainnet 22776; the
owner decides at the 22776 launch.

<a id="NET-EVM-06"></a>**NET-EVM-06** — **Every Foundry profile compiles for the `amsterdam` EVM: every chain that runs these contracts
requires Glamsterdam, and a public chain is deployed only after its own fork.** Owner ruling 2026-10-21; status **BUILT**.
The SCaaS testnet (7622) runs Nethermind 2.2.0 with Amsterdam from block 1, and the test suite runs on Foundry 1.8.5,
which needs `experimental = true` for `evm_version = "amsterdam"`; the profiles `default`, `private7622`, `zether`,
`gnosis`, `celo`, `bsc`, `polygon` and `base` all set it, with one set of gas bounds. No contract reads `block.slotnum`
(EIP-7843): Clique has no slot, so the opcode is off on the testnet. The bytecode equals the earlier `osaka` build apart
from the metadata; the gas bounds of the tests moved with Amsterdam's prices (EIP-8037 state gas, EIP-8038 storage writes,
EIP-7976 calldata floor, EIP-2780 intrinsic), each re-pin names its EIP in the test. The flows' total gas (regular + EIP-8037
state gas) exceeds 2^24, up to ~111 M for the largest implementation deploy (`WRAPPED_PQZ`, 110.3 M, table below), so the SCaaS testnet runs a 200 M block gas limit
(genesis `gasLimit` `0xbebc200`, reset 2026-10-22; `TargetBlockGasLimit` 200,000,000).

**Minimum block gas limit per release kind (review C5-1; controller proposal, owner may override; no code-size work before
Glamsterdam).** A release is one `CREATE2` of the whole implementation in the registrar's transaction. Under EIP-8037 the
code deposit is state gas at 1,530 per byte of runtime, EIP-7825 caps only the regular gas at 2^24 = 16,777,216, and the
transaction's gas may not exceed the block gas limit, so a release needs `runtime × 1,530 + 16,777,216` of block gas limit
(the 2^24 term is the regular-gas bound, not the measured figure: `WrappedPqzToken` measures about 4.1 M regular). Runtime
sizes are `smartcontracts/evm/size-baseline.json`'s (re-measured after the metatx split at T8 `69fce983`; the split took 269-456 B off each kind):

| Kind (contract) | Runtime | State gas | Needs |
|---|---|---|---|
| `NORMAL` (`NormalToken`) | 38,195 B | 58.4 M | **75.2 M** |
| `WRAPPED` (`WrappedToken`) | 48,068 B | 73.5 M | 90.3 M |
| `NORMAL_ZETHER` (`NormalZetherToken`) | 48,313 B | 73.9 M | 90.7 M |
| `NORMAL_PQZ` (`NormalPqzToken`) | 49,067 B | 75.1 M | 91.8 M |
| `WRAPPED_ZETHER` (`WrappedZetherToken`) | 60,282 B | 92.2 M | 109.0 M |
| `WRAPPED_PQZ` (`WrappedPqzToken`) | 61,137 B | 93.5 M | **110.3 M** |
| information: `MtxPipelineLib` (linked library of every release) | 8,106 B | 12.4 M | 29.2 M |
| information: `MtxRelayFee` (CTR-MTX-27 router; its `MtxRelayExecutor` 554 B) | 2,908 B | 4.4 M | 21.2 M |

The two information rows (`forge build src --sizes`, `smartcontracts/evm/runs/2026-10-28-metatx-split-fixwave-sizes.txt`, `MtxPipelineLib` re-measured after the EIP-7702 owner ruling in `runs/2026-10-28-metatx-split-7702-sizes.txt`; both under 24,576 B, so not in the baseline) have no gate of their own: the library is smaller than every implementation that links it, so the implementation's gate binds (spec §4, controller call). So about 75 M for the plain kinds and about 110 M for the confidential ones; the DEX release (under 24,576 B) needs at
most 54.4 M. A chain with an Ethereum-like 60 M block holds none of the confidential kinds and only the smallest plain
one; it needs a raised block gas limit (no gas price or limit is assumed: the check below reads the chain's actual
value). **Deploy gate:** `DeployBase._requireReleaseGas(contract)` (called before each `deployImplementation` /
`deployDexImplementation`) and `script/pqz/e2e.py` read `block.gaslimit` (`eth_getBlockByNumber`) and refuse before
sending when it is below the kind's need; the sizes come from the baseline file at run time, so the figures follow the
ratchet. The deploy tests assert regular + state gas against the same budget next to the 2^24 check.

Runbook notes: (1) read the genesis hash from every configured RPC and stop if they differ; (2) on a private chain,
confirm the genesis carries its unique `extraData` nonce before deploying; (3) deploy the CREATE2 deployer once per
chain, then the implementations, the factory, the `SmartKeyAccountFactory`, the registry and the DEX; (4) run the gate;
(5) publish the profile update (`chain_uid`, contract addresses, DEX list) to the node's chain row and the clients'
pinned profiles in the same release; the node re-checks every `chainUid()` at activation and every start
([NODE-GW-07](../node/gateway.md#NODE-GW-07)).

Transitional (BUILT, P1e): `smartcontracts/scripts/deploy.sh evm <rpc>` runs the forge script `script/Deploy.s.sol` (reads
`PRIVATE_KEY`, `REGISTRAR`, `DEPLOY_SALT`, `CHAIN_UID`, `NOTICE_PERIOD`) through the deterministic deployer at
`0x4e59b44847b379578588920ca78fbf26c0b4956c` (`new X{salt: DEPLOY_SALT}`; default salt `keccak256("scaas.deploy.v1")`) and
the gate of `DeployBase.sol`: `chainUid()` of the factory and of each implementation equals `chain_uid` (`CHAIN_UID` or
block 0's hash; past block 256 `CHAIN_UID` is required). The script stops when the deployer has no code: on such a
chain, deploy it first (the keyless presigned deployment transaction of that proxy, funded by a transfer to its signer)
and re-run. `forge script … --broadcast` needs `--sender <deployer address>`, which `deploy.sh` and the e2e pass; forge
places the linked libraries from that sender, not by CREATE2. It deploys `OpenFactory` (notice period `NOTICE_PERIOD`
seconds; owner ruling 2026-10-20: every mainnet — any chain outside `DeployBase._isTestChain`'s fixed list of test /
dev chains, so 22776, Hedera 295 and an unknown chain too — defaults to and may not go below 3 days; the SCaaS testnet defaults to 10
minutes, the other listed test / dev chains to 0; at most 30 days, the factory's `MAX_NOTICE_PERIOD`; `DEMO_SUPPLY`
needs 0) and, when
the deployer is the registrar, publishes env 1 of `NORMAL` and of the DEX (the factory, `chain_uid`, the UA registry, the
`SmartKeyAccount` implementation, Hedera, the linked libraries with their code hashes) and has the factory deploy
(plan 5g-Z2, [CTR-TOK-03](../contracts/token-wrappers.md#release-env)) `NormalToken` as
version 1 of `NORMAL` on the UA registry (since UA-4 every token implementation carries the UA ledger and is over
EIP-170, so `deploy.sh` always passes `--code-size-limit 65536` (and `--slow`: one tx per block, because forge's parallel broadcast can strand a deploy tx that doesn't fit the block's remaining gas) and the chain needs 64 KiB code; `WrappedToken` is not
deployed until the size work), the `SCaaSDex`
implementation as DEX version 1 (a DEX is a `createDex` clone) and `SmartKeyAccountFactory` (P4); with `DEMO_SUPPLY`, two
kind-`NORMAL` demo tokens; the v1 line left the deploy in P5 (`legacy/p5/`) ([deploy](../contracts/README.md#build-ci-and-pins)).
Since UA-3 it also deploys the UA registry generation 1 with its verifiers on every chain (first, since UA-4: the token implementations take its address; `_deployUARegistry`; budget
12 M, Hedera 10.5 M): the EIP-2537 kinds and `bls-bn254-minsig` only where `script/UAPrecompileProbe.sol`, asked
through an `eth_call` with no `to` (the node's own precompiles), passes (the Zether kind `zether-bls12381` among them, on every chain but Hedera); no chain-id lock for any kind (owner ruling 2026-10-31); the PQ signing kinds (P6c, unaudited) wherever the kind's cap is ≤ 66 % of the budget (owner ruling 2026-10-31; all four at 12 M and on Hedera's 10.5 M), ML-DSA in
Solidity on the registry's expanded-key cache: an ML-DSA UA's cache parts (`cacheExpandedKey`, one transaction each,
≤ 13.5 M gas) come before its `register` ([accounts.md §1.9](../contracts/accounts.md#verifiers)).

It writes
`deployments/<chainid>.json` (`token_factory`, `implementation_normal`, `dex_implementation`, `ua_registry`, `chain_uid`, `smart_key_account_factory`,
`smart_key_account_implementation`, `demo_token`, `demo_token_2`; `factory`, `implementation`, `dex`, `scaas_dex` are gone with v1),
which seeds the client and the node configuration. forge writes it during the simulation, before the broadcast; `deploy.sh` puts the previous file back (or removes the new one) when the broadcast fails.
Zether (built, P3; UNAUDITED; any chain with EIP-2537, owner ruling 2026-10-31): opt in with `DEPLOY_ZETHER=1` (default off; on Hedera, or where the precompile probe finds no EIP-2537, the script refuses before deploying anything). It deploys `ZetherStatements`, `ZetherDisclosure` and per curve the inner-product, transfer and burn verifiers; when the deployer is the registrar it publishes per curve an env of `NORMAL_ZETHER` and `WRAPPED_ZETHER` (the UA registry, whose Zether kinds it enables there; `deps` = transfer, burn, inner-product verifier, disclosure, [CTR-ZTH-20](../contracts/zether.md#CTR-ZTH-20); env 1, BLS12-381), has the factory deploy the two confidential implementations on it (BLS12-381 as version 1 of each kind; the curve is the release's `curve()`) and enables both kinds, with the keys `zether_registry` (= `ua_registry`), `zether_disclosure`, `zether_statements`, `zether_inner_product_verifier_<curve>`, `zether_verifier_<curve>` (transfer), `zether_burn_verifier_<curve>`, `implementation_normal_zether_<curve>`, `implementation_wrapped_zether_<curve>` (`<curve>` = `bls12381`; plan 5g-Z1). The implementations exceed 24,576 B and the BLS inner-product verifier's deploy (the generators) uses ~14 M gas, so `deploy.sh` always passes `--gas-estimate-multiplier 105` to `forge script` (the default ×1.30 exceeds the Osaka per-transaction cap of 16,777,216, EIP-7825; ×1.13 or more fails; the largest implementation, `WrappedPqzToken`, 13,467,833 gas measured through `deployImplementation` (plan 5g-Z2; 63,975 B of init code with the env), is deployed by `script/pqz/e2e.py`, which sets its own limit) and the anvil needs `--code-size-limit 65536`; `ZetherDeploy.t` checks each deploy fits. `scripts/e2e-zether.sh` runs the
dev-chain e2e (UA-3, rewritten for UA-8): a fresh anvil 31337, this deploy, one BLS12-381 Zether UA registered through a relayer
with the clientkeys portable PoP (no chain id, chain uid or registry in it; all attributes absent), and a `NORMAL_ZETHER` token
shielding to it (`script/ZetherE2E.s.sol`).
Integration tests use `anvil --hardfork osaka --gas-limit 16777216 --code-size-limit 65536` (64 KiB code, as EIP-7954 proposes; owner 2026-10-11 — real chains keep 24,576, so a contract that only fits this anvil still cannot be deployed there).

Every contract is a non-upgradeable clone or a fixed deployment ([CTR-GEN-02](../contracts/README.md#CTR-GEN-02)):
upgradeable proxies (UUPS / ERC-1822) are not used, and a fix is a new implementation version deployed by the factory
plus a voluntary migration.

## 5. EIP-7702 accounts

<a id="eip7702"></a>

An EOA that delegated its code through EIP-7702 is still an EOA for SCaaS, on every path
([CTR-UA-24](../contracts/accounts.md#CTR-UA-24), owner rulings D1–D5 of 2026-10-30, which supersede the 2026-10-28 ruling):
it signs by ECDSA with its own key only, never through the delegate's ERC-1271; it cannot call SCaaS contracts directly
while delegated (`CallerDelegated`; it uses relayed `mtx*` signed by its key, fee may be 0, or clears its delegation); and
SCaaS never calls into it as a relay target or a native-coin unwrap recipient.

<a id="NET-EVM-07"></a>**NET-EVM-07** — **EIP-7702 is off on SCaaS's own chains** (owner ruling 2026-10-30): EIP-7702 is **off** on the SCaaS testnet 7622 from its next reset (fs3 Task 13;
the chainspec `eip7702TransitionTimestamp` line is removed, and a reset must start from that chainspec, never from an older
genesis copy) and on the mainnet 22776 from its launch. A throwaway node with the new chainspec refused a type-4
transaction (`InvalidTxType`) while legacy and EIP-1559 transfers mined (the check is the Source of NET-EVM-07 in
[decisions.md](../decisions.md)). Customer chains (Ethereum and most L2s since Pectra, BSC,
Polygon, Base, …) keep 7702, so the contract rule above applies on every chain; the forge tests are its proof, since the
SCaaS testnet can no longer exercise 7702 after the reset. Verified on 7622 after the 2026-10-31 reset: a type-4 transaction is refused with `-32000 InvalidTxType`.

<a id="NET-EVM-08"></a>**NET-EVM-08** — **The SCaaS testnet's node never signs for an RPC caller** (owner ruling 2026-10-31):
since the node split ([NET-EVM-10](#NET-EVM-10)) the endpoints below are on the key-less `rpc` node and the sealer
answers only on its own container loopback; before it, one node (the Clique sealer) with three JSON-RPC endpoints — public `8545` / `8546` (`Eth`, `Net`, `Web3`, `Subscribe`;
request limits `MaxBatchSize` 100, `MaxRequestBodySize` 4 MiB, `GasCap` = the block gas limit, `Timeout` 20 s,
`RequestQueueLimit` 500), the operator's `8550` bound to the node container's own loopback and not published
(`Admin`, `Clique`, `Debug`, `Trace`, `Parity`, `TxPool`, `Eth`, `Net`, `Web3`; reached from the host through a
sidecar container in the node's network namespace, so no other container reaches it), and `8547` on the Docker
network only (`Eth`, `Net`, `Web3`, `TxPool`, for the explorer; not the `scaas-node` gateway port) — `Personal` nowhere, and a calls filter that refuses `eth_sendTransaction`, `eth_sign`,
`eth_signTransaction` and `eth_signTypedData*` on every endpoint (Nethermind 2.2.0 needs the sealer account in
`UnlockAccounts` to read its key, so the wallet methods are refused instead). Layout, checks and rollback:
[RUNBOOK](../../pqz-core/nethermind/chain/RUNBOOK.md) § 7622 node layout and access. Mainnet 22776 additionally gets a
TLS reverse proxy with rate limits and keeps the sealer key out of the RPC node.

<a id="NET-EVM-09"></a>**NET-EVM-09** — **Blockscout runs on the SCaaS testnet, lean and capped** (owner ruling
2026-10-31): `explorer-db` 1 GiB / 1 CPU, `explorer-backend` 2 GiB / 1.5 CPU, `explorer-frontend` 512 MiB / 0.5 CPU, no
restart policy, started by hand after the node; it reads the node over the Docker-network endpoint only; internal
transactions, block rewards, token-instance metadata and market data are off; pending transactions and address coin
balances are on (owner 2026-10-31: with the coin-balance fetcher disabled, Blockscout 9.0.2's live import crashes
after every block and the home-page block list stops; on the pruned node its catch-up retried old-block balances
forever, about 1.5 CPU, until a one-off cleanup of those rows, `blockscout-code-backfill.py --prune-coin-balances`,
rerun after an outage longer than the pruning window; archive mode at the sealer / RPC node split is the root fix);
the UI is published on host port 8558 (owner 2026-10-31: not 3000) and the API on 4000; the frontend image is pinned
by digest; one-line stop in the RUNBOOK. Since the node split ([NET-EVM-10](#NET-EVM-10)) it reads the archive `rpc`
node, and neither the code backfill nor the coin-balance cleanup is needed. Contract verification (owner ruling 2026-10-31): a local
`smart-contract-verifier` (v1.11.1, pinned by digest, 512 MiB / 1 CPU, `mba-net` only, Solidity only, solc from
binaries.soliditylang.org, never Blockscout's hosted service) backs the backend, and
`smartcontracts/evm/script/verify-blockscout.sh` verifies every `Deploy.s.sol` contract after each reset or deploy;
blocked for now: v1.11.1 rejects `evmVersion` `amsterdam` (NET-EVM-06), so 0 of 31 contracts verify (RUNBOOK
§ Contract verification).

<a id="NET-EVM-10"></a>**NET-EVM-10** — **The SCaaS testnet runs two nodes: a `sealer` and a public `rpc`** (owner
ruling 2026-10-31): in the stack's one `docker-compose.yml`, both on the PQZ image. `sealer` holds the Clique key
(keystore + `UnlockAccounts`, Mining on), stays pruned and small (1 GiB cap; 768 MiB proved too tight under the PQZ e2e), publishes no port, serves JSON-RPC only
on its container loopback (admin through a sidecar) and sits on an internal Docker network shared with `rpc` alone
(no gateway, no host address), its one static peer. `rpc` has no key and no unlocked account, Mining off, runs
archive (`Pruning.Mode` `None` on the patricia backend, `FlatDb.Enabled` false), full-syncs from `sealer`, carries
the public 8545 / 8546, the Docker-only 8547 for Blockscout and its own loopback 8550, and the P2P port 30303:
**external nodes connect to `rpc` (the sentry), never to the sealer**; both nodes have fixed node keys. The sealer runs `TxPool.AcceptTxWhenNotSynced` true: as the sole signer it has no
peer ahead of it, its sync mode turns `Disconnected` about 10 minutes after each session starts, and Nethermind then
drops every transaction gossiped by `rpc` while blocks keep flowing. Both nodes run `TxPool.MaxTxSize` 2 MiB (owner
ruling 2026-10-31: the 4 MiB request body carries at most a 2 MiB raw transaction as hex; the PQZH M = 16 auditor-on
proof is 544 KB), although Amsterdam's per-transaction gas cap already limits a transaction to about 262 KB of calldata. Why: the key
leaves the process that answers RPC; peers and callers that misbehave reach only `rpc`; Blockscout gets the old-block
state a pruned node lacks. Topology, enodes, start / stop order and recovery: [RUNBOOK](../../pqz-core/nethermind/chain/RUNBOOK.md)
§ Node split. Mainnet 22776: the same topology is proposed; the owner decides at launch.

## 6. Limitations

<a id="limitations"></a>

- Celo `l1_batch` finality and CIP-64 lanes: PLANNED / open ([NET-EVM-01](#NET-EVM-01)).
- Public profiles stay `draft` until their finality gate is measured and an RPC quorum ≥ 2 is configured.
- The SCaaS testnet has one signer and one RPC provider (the node's quorum is 1); its threat profile is in
  [NET-EVM-04](#NET-EVM-04).

## <a id="paymeta-relayfee"></a>Pay-meta and relay fee (metatx split)

Spec `docs/superpowers/specs/2026-10-27-metatx-split-design.md` §6.2 / §7.2; rules [CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) and [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27); decisions CTR-MTX-26 / -27 (commit per family below). Status BUILT unless a line says owed.

Mermaid, the relay-fee flow (`MtxRelayFee.relay`, one transaction, all or nothing):

```mermaid
sequenceDiagram
  participant R as Relayer
  participant F as MtxRelayFee (router)
  participant X as MtxRelayExecutor
  participant T as Target
  participant K as Token
  R->>F: relay(target, callData, token, t, sig)
  F->>F: ref = keccak256("scaas.relayfee", chainUid, target, keccak256(callData)); t.entryRef == ref, lane == payLane(ref), nonce 0, relayer == router
  F->>X: exec(target, callData)
  X->>T: call (msg.sender = executor, no value)
  F->>K: mtxExecuteTransfer(t, sig) (payment bound to the router)
  F->>R: open mode: token.transfer(msg.sender, value)
  F-->>R: RelayFeePaid(ref, target, token, payer, payee, amount)
```

- **Pay-meta.** `mtxPayMeta` / `uaPayMeta` on every `MetaTokenBase` kind: `payId = metaPayId(salt, meta)`, `PaymentMeta(payId, meta)`
  then exactly `mtxPay` / `uaPay` (lane `payLane(payId)`, nonce 0). `meta` is hashed and logged, never parsed. Body encodings
  (schemas 1-3) and the shared vectors `smartcontracts/vectors/metatx/paymeta.json`: decisions CTR-MTX-26 (T7 fix 1). The
  contract has no length cap; the node caps by policy (`max_pay_meta_bytes`, 2,048).
- **Relay fee.** `src/metatx/MtxRelayFee.sol` (router) and its one-shot `MtxRelayExecutor`, deployed by `DeployBase` CREATE2;
  `relay` (address payer) and `uaRelay` (UA payer). The router refuses `t.to == EXECUTOR` (UA: `pad(EXECUTOR)`), a target with
  no code or an EIP-7702 designator (`RelayTargetNoCode`), and re-entry (a transient flag); it holds no balance after a call. `RelayFeePaid.payee` is
  `bytes32`. Clients: never pay or approve the executor; if the inner call is an mtx envelope with `MODE_RESTRICT_RELAYER`,
  its relayer is the executor or open.
- **Split.** The relayed token paths run on `MtxPipelineLib` (DELEGATECALL to a linked library, ABI and digests unchanged).
  Measured cost, execution gas, `runs/2026-10-27-metatx-split-overhead-final.txt`: +7.4 k to +7.6 k on the warm/cold
  `MetaTxGasV2` rows (+8.9 k `unwrap`; cancel 0), data-size bound 7.9-9.1 k small and 8.9-11.5 k largest envelope
  (`runs/2026-10-27-metatx-split-overhead.txt`). Node: `guard::erc1271_floor(len)` for a contract signer.
- **UA payers in the node** (BUILT, node-ua-jobs 2026-10-30): the `ua_metatx` job kind relays `uaExecute`,
  `uaExecuteTransfer` and `uaPayMeta`; `MtxRelayFee.uaRelay` is a `call` job with its own call-table row, priced at
  `params.relay_fee.min_wei_value` against the quote (gas limit × 2 × the first max fee per gas, + the L1 data fee on an
  OP-stack chain with `params.l1_fee = "op-stack"`, e.g. Base and Celo); the indexer reads `UAPaymentSettled` as a
  `PaymentSettled` row, a derived UA as `UA_POOL` + `from_ua` / `to_ua` ([job-api.md](../node/job-api.md#paymeta-relayfee-jobs)).
