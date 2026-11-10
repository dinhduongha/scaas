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
| SCaaS testnet (private reference chain) | 7622 | `scaas-testnet` (Solidity `amsterdam`, [NET-EVM-06](#NET-EVM-06)) | free (base fee 0) | depth 1, quorum 1 | BUILT, first target |
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
`scaas-testnet`.** Owner ruling 2026-10-07; the name `scaas-testnet` is owner ruling 2026-10-31 (it replaces the
2026-10-07 name). Chain id `0x1dc6`; the chain was reset with a new genesis when it moved
from 9000, which is also Evmos Testnet — replay protection is only as good as the chain id, so every signer and node
also binds the genesis hash ([NET-ALL-22](README.md#NET-ALL-22)). Genesis hashes of the live EVM chains, two sources each (7622: one, its own local RPC), are in [`chain-uids.json`](../../smartcontracts/evm/chain-uids.json). Nodes bind the profile to the genesis hash, not to
the chain id alone. The profile, seeds, environment variable names and test vectors use `scaas-testnet`; the chain's
directory is `src/chains/scaas-testnet`. In prose the chain is "the SCaaS testnet". The future mainnet, chain id 22776,
will be `scaas-mainnet`.

<a id="NET-EVM-03"></a>**NET-EVM-03** — **The first target chain is the private PoA chain; public chains follow, and
CI builds the `scaas-testnet` profile.** Owner decision. Gas is free there, so gas is not a constraint for the first
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
| Forks | live through Fusaka + BPO2, and Amsterdam from block 1 on Nethermind 2.2.0 ([NET-EVM-06](#NET-EVM-06)); at the next reset (prepared, not executed; the controller's) Amsterdam from block 1 with EIP-7954 left out (NET-EVM-06's Change, [CTR-GOV-19](../decisions.md#ctr-gov-19--build-first-on-the-scaas-testnet-at-a-higher-code-size-ceiling-reduce-later)); Fusaka: EIP-2537 (BLS12-381), EIP-7951 P-256 at `0x100`, EIP-7825 per-transaction gas cap 16,777,216, EIP-7623, EIP-7934 |
| Base fee | 0 (gas free; `MinGasPrice` 0) |
| Contract code size | 64 KiB (`maxCodeSize` `0x10000`, `maxCodeSizeTransition` 6432) since 2026-10-11, owner, ahead of Glamsterdam (cf. EIP-7954); 24,576 before. Probed at block 6434: 65,536 B code deploys (13.27 M gas), 65,537 B is refused, a 50,005 B init code is accepted (the init-code limit follows `maxCodeSize`). Public chains keep 24,576. **Since reset 1 (2026-11-04, executed:** `pqz-core/nethermind/chain/RUNBOOK.md` "Code size 128 KiB on the SCaaS testnet: reset 1", `patch-chainspec.py --testnet-reset`; governance T16): `maxCodeSize` `0x20000` (131,072 B) with EIP-7954 left out, since with EIP-7954 active the limit is 65,536 B whatever `maxCodeSize` says. Measured on throwaway copies (`pqz-core/nethermind/runs/2026-11-03-code-size-probe.txt`, arms C and D; governance T0 `687afdb3`, T0b `dc14ebbe`): 131,072 B deploys, 131,073 B is refused; the init code limit is 262,144 B (2 × `maxCodeSize`), and about 261,768 B is the largest init that fits under the calldata floor [est.]; the largest `.init` row of `size-baseline.json` is 74,825 B (`WrappedPqzToken`) |
| Block gas limit | 200,000,000 from genesis (`0xbebc200`, reset 2026-10-22, owner; `TargetBlockGasLimit` 200 M); 16,777,216 before. Per tx: regular gas ≤ 2^24 (EIP-7825), node `max_gas_per_tx` 64 M (owner 2026-10-22) |
| Finality | depth 1, quorum 1 (single-provider trust, reported as such) |
| Classical Zether | open (EIP-2537 live, [CTR-ZTH-52](../contracts/zether.md#CTR-ZTH-52), owner ruling 2026-10-31); **deployed 2026-10-31** with `DEPLOY_ZETHER=1` as part of the salt-v2 set (`DEPLOY_SALT` = `keccak256("scaas.deploy.v2")`: UA registry with `zether-bls12381`, OpenFactory with `NORMAL_ZETHER` / `WRAPPED_ZETHER` enabled), e2e passed; addresses and re-run steps in the [RUNBOOK](../../pqz-core/nethermind/chain/RUNBOOK.md#zether-on-the-scaas-testnet-executed-2026-10-31). The phase C set of the same day (salt v1, registry without `zether-bls12381`) is superseded, kept on chain |
| Post-quantum Zether | the only PQZ chain: `PQZ` `0x5caa500000000000000000000000000000000f01`, `MLDSA44` `…0012`, `MLDSA65` `…0013` from the plugin in image `scaas/nethermind-pqz:1.39.0-pqz1` (local, never pushed), chainspec `engine.Pqz` ([chain integration](../contracts/pq-zero-knowledge.md#chain-integration), [§3](#precompiles)) |

Operator trap, measured on the earlier chain: **a Nethermind chainspec silently ignores Geth-style keys.** With
`pragueBlock: 0` (and `londonBlock`, `cancunBlock`) in Geth form, the chain ran pre-London without a warning: the
BLS12-381 precompiles `0x0b`/`0x0c`/`0x0f`/`0x10` were empty while `alt_bn128` `0x06`/`0x07` answered; headers had no
`baseFeePerGas` (no EIP-1559), no `withdrawalsRoot` (no Shanghai), no `blobGasUsed`/`excessBlobGas` (no Cancun).
Forks must be written with Nethermind's own keys (`eip1559TransitionTimestamp`, `eip2537TransitionTimestamp`, …),
and changing them changes the genesis hash (chain reset). The only detection is to inspect a block header or call
the precompile — the deployment checklist does both, and for classical Zether it adds the two subgroup vectors of
[§3](#3-precompiles). The chainspec was fixed on 2026-08-31 before the reset to
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
- **`BLS12_G1MSM` must check the subgroup, and presence does not show it** ([CTR-ZTH-53](../contracts/zether.md#CTR-ZTH-53)).
  The merged Zether check rests on it, and the official EIP-2537 vectors pin neither a zero scalar nor `k = 1` on a point
  outside the subgroup. With `T` = `(0, 2)`, a point of order 3, encoded `be64(0) ‖ be64(2)`, both of these `eth_call`s to `0x0c`
  must **fail** before a chain runs classical Zether:

  | Input | A chain that skips the check answers |
  |---|---|
  | `T ‖ be32(1)` | `T` |
  | `G ‖ be32(1) ‖ T ‖ be32(0)` | `G` |

  `G1ADD` takes `T`, which is correct: it has no subgroup check. A failure counts only if the same shape succeeds: `G ‖
  be32(2)` must answer `[2]G` and `G ‖ be32(1) ‖ G ‖ be32(0)` must answer `G`, under the same gas, or the failure may be out of
  gas. `isSupportedOnThisChain()` runs all four under a cap of 100,000 gas each (EIP-2537 prices them at 12,000 and 21,312), so
  a token's `initialize` refuses such a chain, and one pricing G1MSM above the cap. The SCaaS testnet's Nethermind 2.2.0 answers
  all four as required at that gas, the two failures as subgroup errors (read-only `eth_call`, 2026-11-01).
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
which needs `experimental = true` for `evm_version = "amsterdam"`; the profiles `default`, `scaas-testnet`, `zether`,
`gnosis`, `celo`, `bsc`, `polygon` and `base` all set it, with one set of gas bounds. No contract reads `block.slotnum`
(EIP-7843): Clique has no slot, so the opcode is off on the testnet. The bytecode equals the earlier `osaka` build apart
from the metadata; the gas bounds of the tests moved with Amsterdam's prices (EIP-8037 state gas, EIP-8038 storage writes,
EIP-7976 calldata floor, EIP-2780 intrinsic), each re-pin names its EIP in the test. The flows' total gas (regular + EIP-8037
state gas) exceeds 2^24, up to about 115.7 M simulated for the largest implementation deploy (`WRAPPED_PQZ`, 121.4 M at × 1.05, table below), so the SCaaS testnet runs a 200 M block gas limit
(genesis `gasLimit` `0xbebc200`, reset 2026-10-22; `TargetBlockGasLimit` 200,000,000).

**Change (owner 2026-11-03, [CTR-GOV-19](../decisions.md#ctr-gov-19--build-first-on-the-scaas-testnet-at-a-higher-code-size-ceiling-reduce-later)):** the SCaaS testnet runs every Amsterdam EIP but EIP-7954, by removing `eip7954TransitionTimestamp` from its chainspec, because with EIP-7954 active the code limit is 65,536 B whatever `maxCodeSize` says (`pqz-core/nethermind/runs/2026-11-03-code-size-probe.txt`). `maxCodeSize` is `0x20000` (131,072 B); the init code limit is then 262,144 B, measured. 22776 stays the owner's at launch. Every other chain keeps the rule above. Status: **BUILT, executed 2026-11-04** (SCaaS testnet reset 1, owner's go; `patch-chainspec.py --testnet-reset`, governance T16 `52ef7d22`, `55a97e0e`, refusing every chain but 7622): image `2.2.0-pqz7`, genesis unchanged `0xf1f491ab…3164`; 65,537 B and 119,800 B deploy at a 200 M block, `WrappedPqzToken` (72,160 B) is deployed; `pqz-core/nethermind/chain/RUNBOOK.md` "Code size 128 KiB on the SCaaS testnet: reset 1", `smartcontracts/evm/runs/2026-11-04-testnet-reset1-7622.txt`.

**Minimum block gas limit per release kind (review C5-1; controller proposal, owner may override; no code-size work before
Glamsterdam).** A release is one `CREATE2` of the whole implementation in the registrar's transaction. Under EIP-8037 the
code deposit is state gas at 1,530 per byte of runtime, EIP-7825 caps only the regular gas at 2^24 = 16,777,216, and the
transaction's gas may not exceed the block gas limit, so a release needs `runtime × 1,530 + 16,777,216` of block gas limit
(the 2^24 term is the regular-gas bound, not the measured figure: `WrappedPqzToken` simulates at 4.97 M regular).
Runtime sizes are `smartcontracts/evm/size-baseline.json`'s and the figures below are forge's simulated Amsterdam gas of each
release's creation as one transaction, not real receipts, measured on branch `governance` (T16, `52ef7d22`;
`smartcontracts/evm/runs/2026-11-03-governance-deploy-gas.txt`, `test/governance/GovDeploy.t.sol`
`test_releaseGasPerKind`, `test_everyKindsReleaseFitsTwoHundredMillion`): regular gas (the frame's `gasTotalUsed` × 64/63) and
EIP-8037 state gas (the code deposit at 1,530 per byte and the new account), their total, and that total × 1.05
(the explicit gas limit `deploy.sh` sends, [NET-EVM-11](#NET-EVM-11)), the gas the transaction asks of the block. The factory's `deployTokenImplementation`
adds its own frame and a slot or two. A kind fits when regular × 1.05 < 2^24 (EIP-7825) and total × 1.05 ≤ 200,000,000. Anvil's
own `gasUsed` does not charge EIP-8037, so it says nothing here; the one run over a real client (7622, Nethermind, the pre-round
sizes, `runs/2026-10-31-fs3-t13-pqz-7622-public-rpc.txt`) gave `UARegistry` 58.1 M, `NormalToken` 61.1 M, `WrappedPqzToken` 96.5 M.

| Kind (contract) | Runtime | Init | Deploy gate need | Regular | State | Total | Total × 1.05 | 200 M block |
|---|---|---|---|---|---|---|---|---|
| `NORMAL` (`NormalToken`) | 40,853 B | 43,899 B | 79.3 M | 2.88 M | 62.79 M | 65.66 M | 68.9 M | fits |
| `WRAPPED` (`WrappedToken`) | 52,297 B | 55,414 B | 96.8 M | 3.63 M | 80.30 M | 83.92 M | 88.1 M | fits |
| `NORMAL_ZETHER` (`NormalZetherToken`) | 50,547 B | 55,106 B | 94.1 M | 3.61 M | 77.62 M | 81.22 M | 85.3 M | fits |
| `WRAPPED_ZETHER` (`WrappedZetherToken`) | 62,472 B | 67,169 B | 112.4 M | 4.39 M | 95.86 M | 100.25 M | 105.3 M | fits |
| `NORMAL_PQZ` (`NormalPqzToken`) | 56,191 B | 59,900 B | 102.7 M | 3.92 M | 86.25 M | 90.17 M | 94.7 M | fits |
| `WRAPPED_PQZ` (`WrappedPqzToken`) | 72,160 B | 76,009 B | **127.2 M** | 4.97 M | 110.69 M | 115.65 M | **121.4 M** | fits; above 65,536 B: needs `CHAIN_CODE_LIMIT=131072` and a chain without EIP-7954 |
| the DEX (`SCaaSDex`) | 33,574 B | 35,928 B | 68.1 M | 2.36 M | 51.65 M | 54.01 M | 56.7 M | fits |
| `GovernanceRouter` (one per chain and UA registry, not a release) | 20,073 B | 21,126 B | none (under EIP-170) | 1.40 M | 30.90 M | 32.29 M | 33.9 M | fits |
| `UARegistry` (split; with `mldsa87` / `fndsa1024`, merge of main 9c760b4a) | 29,710 B | | 62.2 M | | | | | |
| `UARegistryLib` (linked library of the registry; likewise) | 36,192 B | | **72.2 M** | | | | | |

"Deploy gate need" is the formula `runtime × 1,530 + 2^24` applied to `size-baseline.json` (`DeployBase._releaseGasNeed`,
arithmetic, not a measurement); it is the higher figure in every row, since it charges the 2^24 regular cap whole. The
largest runtime the gate admits at a 200 M block is **119,753 B**, below the 131,072 B `maxCodeSize` of the next reset. The
registry rows were not simulated in this run; the registry-split simulation (`runs/2026-11-01-typed-signing-r2-deploy.txt`,
whole transactions, at the sizes of the split) gave `UARegistry` 46.5 M and `UARegistryLib` 54.7 M. The registry has two gates
(owner ruling 2026-11-01; `_requireReleaseGas("UARegistry")` and `_requireReleaseGas("UARegistryLib")`, `require_release_gas` in
`e2e.py`, `test_registryDeployGate`): a plain stack (`Deploy.s.sol`: `NormalToken`, the DEX, the registry and its library) is held
by `NormalToken`'s 79.3 M, the full stack by `WrappedPqzToken`'s 127.2 M gate. **The gate over-refuses:** it reserves all of
2^24 for regular gas, but a deployment's regular gas is far below it (at most 4.97 M in the table), so a chain whose block limit
sits between the two refuses a stack that would deploy. The formula is the owner's and stays; this sentence records the margin. A
chain with an Ethereum-like 60 M block holds no kind at all: the `UARegistryLib` gate (72.2 M) and `NormalToken`'s (79.3 M)
refuse, and nothing is sent. Such a chain needs a raised block gas limit (no gas price or limit is assumed: the check below reads
the chain's actual value).

**Declared code limit (GD-4, CTR-GOV-19; BUILT on branch `governance`, T2 `7edcad34`, T16 `52ef7d22`).** `DeployBase` refuses a
release whose runtime exceeds `CHAIN_CODE_LIMIT` (env, default 65,536, the value of EIP-7954), naming the contract, before
anything is sent. The limit is declared, never derived from a chain id: one rule on every chain. The SCaaS testnet's
runbook sets 131,072 after the next reset. A chain's own limit stays the last word: a deploy it refuses fails closed.

**What the block limit bounds (EIP-8037).** A transaction is included only if its `tx.gas`, which covers regular plus state gas, fits the block gas limit; EIP-7825's 2^24 caps only the regular part. The block's `gas_used` is `max(Σ regular, Σ state)` and is accounting, not an inclusion test. The sender pays `max(total, floor)` where `total` is execution plus state gas and `floor` the EIP-7976 calldata floor; below the floor the sum of the two gas columns overstates the charge. A deployment such as `storePqzPop` at `n2816-kmax65536` (60.11 M regular + state in the registry-split measurement) therefore does not fit a 60 M block.
**Deploy gate:** `DeployBase._requireReleaseGas(contract)` (called before the `UARegistry` creation and each `deployTokenImplementation` /
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
needs 0), first the `GovernanceRouter` (CREATE2, after the UA registry and before every release, JSON `governance_router`;
every release's `Env.govRouter` names it, [CTR-GOV-15](../decisions.md#ctr-gov-15--no-operator-delay-on-a-governance-holder)), and, when
the deployer is the registrar, publishes env 1 of `NORMAL` and of the DEX (the factory, `chain_uid`, the UA registry, the
`SmartKeyAccount` implementation, Hedera, the linked libraries with their code hashes) and has the factory deploy
(plan 5g-Z2, [CTR-TOK-03](../contracts/token-wrappers.md#release-env)) `NormalToken` as
version 1 of `NORMAL` on the UA registry (since UA-4 every token implementation carries the UA ledger and is over
EIP-170, so `deploy.sh` always passes `--disable-code-size-limit` (forge applies EIP-3860 to the script contract itself; the chain
enforces its own limit) and `--slow` (one tx per block, because forge's parallel broadcast can strand a deploy tx that doesn't fit the block's remaining gas), and the chain needs 64 KiB code;
with `DEPLOY_WRAPPED=1` also `WrappedToken` as version 1 of `WRAPPED`, gated the same way, JSON `implementation_wrapped`, governance T16, GD-12), the `SCaaSDex`
implementation as DEX version 1 (a DEX is a `createDex` clone) and `SmartKeyAccountFactory` (P4); with `DEMO_SUPPLY`, two
kind-`NORMAL` demo tokens; the v1 line left the deploy in P5 (`legacy/p5/`) ([deploy](../contracts/README.md#build-ci-and-pins)).
Since UA-3 it also deploys the UA registry generation 1 with its verifiers on every chain (first, since UA-4: the token implementations take its address; `_deployUARegistry`; budget
12 M, Hedera 10.5 M): the EIP-2537 kinds and `bls-bn254-minsig` only where `script/UAPrecompileProbe.sol`, asked
through an `eth_call` with no `to` (the node's own precompiles), passes (the Zether kind `zether-bls12381` among them, on every chain but Hedera); no chain-id lock for any kind (owner ruling 2026-10-31); the PQ signing kinds (P6c, unaudited) wherever the kind's cap is ≤ 66 % of the budget (owner ruling 2026-10-31; all four at 12 M and on Hedera's 10.5 M), ML-DSA in
Solidity on the registry's expanded-key cache: an ML-DSA UA's cache parts (`cacheExpandedKey`, one transaction each,
≤ 13.5 M gas) come before its `register` ([accounts.md §1.9](../contracts/accounts.md#verifiers)). `mldsa87` (0x0134) only where
an ML-DSA-87 precompile answers its EIP-8355 probe (`0x14`, or the SCaaS testnet's `0x…5caa0014`): elsewhere it has no verifier and
is not registrable ([CTR-UA-39](../contracts/accounts.md#CTR-UA-39); BUILT on branch `mldsa87`; the cap 250,000 is a provisional
estimate). `fndsa1024` (0x0135) on every chain whose budget holds its cap 5,250,000 at ≤ 66 % (every EVM budget ≥ 7,954,546;
pure Solidity, no precompile; [CTR-UA-40](../contracts/accounts.md#CTR-UA-40); BUILT on branch `mldsa87`; the cap is provisional until
T-GAS). The other families refuse `0x0135` until their own round; Algorand's `falcon_verify` is deterministic Falcon-1024 (a fixed
salt) and cannot verify this kind's randomized round-3 signatures.

It writes
`deployments/<chainid>.json` (`token_factory`, `implementation_normal`, `implementation_wrapped` (with `DEPLOY_WRAPPED`), `dex_implementation`, `ua_registry`, `governance_router`, `chain_uid`, `smart_key_account_factory`,
`smart_key_account_implementation`, `demo_token`, `demo_token_2`; `factory`, `implementation`, `dex`, `scaas_dex` are gone with v1),
which seeds the client and the node configuration. forge writes it during the simulation, before the broadcast; `deploy.sh` puts the previous file back (or removes the new one) when the broadcast fails.
Zether (built, P3; UNAUDITED; any chain with EIP-2537, owner ruling 2026-10-31): opt in with `DEPLOY_ZETHER=1` (default off; on Hedera, or where the precompile probe finds no EIP-2537, the script refuses before deploying anything). It deploys `ZetherStatements`, `ZetherDisclosure` and per curve the inner-product, transfer and burn verifiers; when the deployer is the registrar it publishes per curve an env of `NORMAL_ZETHER` and `WRAPPED_ZETHER` (the UA registry, whose Zether kinds it enables there; `deps` = transfer, burn, inner-product verifier, disclosure, [CTR-ZTH-20](../contracts/zether.md#CTR-ZTH-20); env 1, BLS12-381), has the factory deploy the two confidential implementations on it (BLS12-381 as version 1 of each kind; the curve is the release's `curve()`) and enables both kinds, with the keys `zether_registry` (= `ua_registry`), `zether_disclosure`, `zether_statements`, `zether_inner_product_verifier_<curve>`, `zether_verifier_<curve>` (transfer), `zether_burn_verifier_<curve>`, `implementation_normal_zether_<curve>`, `implementation_wrapped_zether_<curve>` (`<curve>` = `bls12381`; plan 5g-Z1). The implementations exceed 24,576 B and the BLS inner-product verifier's deploy (the generators) uses ~14 M gas, so each of its transactions carries an explicit gas limit ([NET-EVM-11](#NET-EVM-11); forge's default estimate ×1.30 exceeded the Osaka per-transaction cap of 16,777,216, EIP-7825; the largest implementation, `WrappedPqzToken`, 13,467,833 gas measured through `deployTokenImplementation` (plan 5g-Z2; 63,975 B of init code with the env), is deployed by `script/pqz/e2e.py`, which sets its own limit; at 72,160 B it needs `CHAIN_CODE_LIMIT=131072` and a chain without EIP-7954) and the anvil needs `--code-size-limit 131072` (`scripts/e2e-zether.sh`); `ZetherDeploy.t` checks each deploy fits. `scripts/e2e-zether.sh` runs the
e2e (UA-3, rewritten for UA-8; the full lifecycle since 2026-10-31): by default a fresh anvil 31337 (200 M gas: the
`WRAPPED_ZETHER` release asks about 105 M) and this deploy, or with `RPC` + `PRIVATE_KEY` a chain already deployed (the SCaaS
testnet); `script/ZetherE2E.s.sol` through `--ffi` registers six BLS12-381 Zether UAs with the clientkeys portable PoP (no
chain id, chain uid or registry in it; all attributes absent; relayed by the deployer), then on a `NORMAL_ZETHER` token
shield, roll-over, a single transfer, a multi-recipient Compact M = 4 and BUNDLE M = 2 transfer with decoys, unshield and the
disclosure view (`SENDER_S`), and on a `WRAPPED_ZETHER` token over a test ERC-20 wrap-shield and roll-over, proofs from
`zether-cli` (the Rust prover), every balance checked by decryption in the simulation and again on chain (`check()`); it
prints gasUsed per transaction from the receipts.
Integration tests use `anvil --hardfork amsterdam --gas-limit 200000000 --code-size-limit 65536` (`scaas-node/tests/e2e.rs`, `e2e_hedera.rs`: neither deploys a kind above 64 KiB) and `--code-size-limit 131072` (`scripts/e2e-zether.sh`, the limit of the SCaaS testnet's next reset), each at the SCaaS testnet's 200 M block gas limit ([NET-EVM-06](#NET-EVM-06)); owner 2026-10-11 — real chains keep 24,576, so a contract that only fits this anvil still cannot be deployed there.

<a id="body-module-releases"></a>**Operator note: releases with body modules** (T66b, [CTR-TOK-30](../contracts/token-wrappers.md#CTR-TOK-30);
BUILT on branch `ua-mtx-merge`, UNAUDITED).

- **Deploy order.** The registry trio first: `UARegistryCoreLib`, then `UARegistryAuxLib` (it links the core), then
  `UARegistry` (it names both). Then per release: its libraries, its body modules, each its own CREATE2 transaction through
  the deterministic deployer with `DEPLOY_SALT` and its own gate (a module already at its address is reused), the env with
  the modules pinned after the libraries, then the implementation through `deployTokenImplementation`; the DEX the same, its
  admin module D first, then `deployDexImplementation`. `DeployBase`, `deploy.sh evm` and `script/pqz/e2e.py` follow it.
- **`releases.json`** gets a row per module: class 0 (no factory class), the token kind (0 for the DEX's D), version 1, its
  address, the init-code hash and the hash of its constructor arguments. A module holds no chain value and has no
  `chainUid()`: it lands at the same address on every chain, and its code hash is the release's pin.
- **Gas per transaction.** Every contract deploys in one transaction of at most 60 M asked (`(regular + state) × 1.05`,
  regular × 1.05 < 2^24): the largest are `UARegistryCoreLib` 56.64 M, `SCaaSDex` 55.70 M and the module `NormalPqzRegulatedTokenQ`
  54.76 M; a token release asks 23.53–47.02 M plus the factory frame of 0.31 M (93 contracts in all, the table in
  `smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b-build/summary.txt`).
- **Modules by function (owner 2026-11-10, group 3p, [CTR-TOK-30](../contracts/token-wrappers.md#CTR-TOK-30)).** A release of
  kind 9, 11 or 13 deploys one more module (W and R, each its own CREATE2 transaction and gate); 8, 10, 12 deploy R where W
  was, 5 and 13 S where Q2 was; `releases.json` names the rows so (`WrappedPqzRegulatedTokenR`, …). Measured asked gas
  (`(regular + state) × 1.05`, `smartcontracts/evm/runs/2026-11-10-ua-mtx-3p/summary.txt`): R 20.17–20.62 M, W of 9, 11, 13
  46.07 / 47.73 / 48.05 M, S 30.95 / 32.34 M, the faces of 9, 11, 13 39.52 / 45.80 / 50.51 M plus the factory frame; every
  module of every kind within 60 M, regular × 1.05 < 2^24.
- <a id="NET-EVM-11"></a>**NET-EVM-11 — Every deploy transaction carries an explicit gas limit within the block.** `deploy.sh evm`
  simulates `Deploy.s.sol` (nothing sent), then `script/DeploySend.s.sol` sends its plan in order, each transaction's limit
  `(regular + state) × 1.05` measured on the RPC's fork and capped at the RPC's block gas limit; one that needs more refuses
  the plan by name (`TxGasOverBlockLimit`) before anything is sent. Forge's estimate × 1.05 had sent `UARegistryCoreLib` with
  61,800,392 (52,317,793 used on 7622), over a 60 M block; now 56,629,029, and the full deploy (104 transactions) runs on a
  60 M anvil (`smartcontracts/evm/runs/2026-11-10-ua-mtx-merge-t66b-followup-gas.txt`).
- <a id="NET-EVM-12"></a>**NET-EVM-12 — Every contract a remote deploy leaves on a chain is source-verified on that chain's
  explorer** (owner ruling 2026-11-10; BUILT on branch `ua-mtx-merge`: `smartcontracts/evm/script/onchain/verify.sh` and
  `vcheck.py`, offline tests in `test_vcheck.py`; the Etherscan and Sourcify request shapes are tested offline only, no public
  explorer has been called). `deploy.sh evm` runs the step after a remote deploy (`VERIFY_TARGET` names the target; chain
  31337 or `VERIFY_TARGET=local` is local, not verified) and `matrix.sh` after each group of a remote target. The explorer
  comes from the environment, never from a chain id: `VERIFY_EXPLORER` `blockscout`, `etherscan` (the v2 API, the chain by
  `chainid`) or `sourcify`, `VERIFY_URL` its API, `VERIFY_RPC` the chain's RPC and `VERIFY_API_KEY_ENV`, the **name** of the
  env var that holds the API key (required for Etherscan; the key reaches forge in its environment only, never in a file or
  an argument). A remote target without an explorer fails by name, `VERIFY_NOT_CONFIGURED`; only `VERIFY=none` with a
  `VERIFY_REASON` skips the step, and the run prints the reason. Discovery: the deployment books, every broadcast of the
  chain and the getters that name a child (an EIP-1167 clone's implementation, `puller()`, `EXECUTOR()`, `modules()`, a
  factory's releases, envs and `contractsPage`); on a chain of ours (`VERIFY_SCAN=1`) also a block scan of the whole
  chain (every creation, every transaction's `to`, every log's emitter and address words). Each address with code ends
  **verified** (a full match), a **linked clone** (on Blockscout its proxy link to the verified implementation; Etherscan
  and Sourcify have no link this check can read, so there the clone's own code is the link), SSTORE2 **data** or the
  8-byte **CREATE3 proxy** of `Create3.sol`; anything else is a fail row and the step exits 1. A contract's name comes from
  the metadata hash at the end of its runtime code, matched against the artifacts of source snapshots (`git archive` of a
  commit plus the pinned `lib/`, compiled once under `scripts/capped` with the deploy's profile), never from a broadcast
  label; each `forge verify-contract` runs in its snapshot outside `capped` in a 1 GiB scope, one at a time, bounded by
  `VERIFY_TIMEOUT`, and a forge run that compiles aborts the step. The explorer's own answer decides, never forge's exit
  code: forge 1.8.5 exits 0 on Blockscout's `Fail - Unable to verify`, so such a contract is submitted once more. The SCaaS testnet's explorer and its first full run:
  [NET-EVM-09](#NET-EVM-09).
- **The relayer's gas share.** A relayed op crosses more call frames (a PQZ op: clone, implementation, P, the self-call,
  clone, implementation, Q, its library, the precompile: 7 frames against 5), and each frame keeps 1/64 of the gas it passes
  on, about 10.4 % of the gas sent against 7.6 % before. A relayer that sets its limit from `eth_estimateGas` changes nothing;
  a figure hard-coded for an op grows by about 3 %. The node reads nothing from `releases.json` and filters every log by the
  configured contract addresses, so a module body run under another contract's `DELEGATECALL` (its log carries that
  contract's address) is never taken for a token's.


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
2026-10-31): `explorer-db` 1 GiB / 1 CPU, `explorer-backend` 2 GiB / 1.5 CPU, `explorer-frontend` 512 MiB / 0.5 CPU,
`restart: unless-stopped` like every service of the stack (owner ruling 2026-10-31, [NET-EVM-10](#NET-EVM-10)), started
after the node; it reads the node over the Docker-network endpoint only; internal
transactions, block rewards, token-instance metadata and market data are off; pending transactions and address coin
balances are on (owner 2026-10-31: with the coin-balance fetcher disabled, Blockscout 9.0.2's live import crashes
after every block and the home-page block list stops; on the pruned node its catch-up retried old-block balances
forever, about 1.5 CPU, until a one-off cleanup of those rows, `blockscout-code-backfill.py --prune-coin-balances`,
rerun after an outage longer than the pruning window; archive mode at the sealer / RPC node split is the root fix);
the UI is published on host port 8558 (owner 2026-10-31: not 3000) and the API on 4000; the frontend image is pinned
by digest; one-line stop in the RUNBOOK. Since the node split ([NET-EVM-10](#NET-EVM-10)) it reads the archive `rpc`
node, and neither the code backfill nor the coin-balance cleanup is needed. Contract verification (owner ruling 2026-10-31): a local
`smart-contract-verifier` (v1.11.1, 768 MiB since 2026-10-31: the patched 31-contract run hit 512 MiB; 1 CPU, `mba-net` only, Solidity only, solc from
binaries.soliditylang.org, never Blockscout's hosted service) backs the backend, and
every contract on the chain is verified by the step of [NET-EVM-12](#NET-EVM-12), `sh script/onchain/verify.sh
scaas-testnet` (this Blockscout's API `http://127.0.0.1:4000/api` and the RPC `http://127.0.0.1:8545`, both on the host's
loopback: the earlier LAN address is gone; the whole-chain scan on; the older per-broadcast `verify-blockscout.sh` stays);
upstream v1.11.1 rejects `evmVersion` `amsterdam` (NET-EVM-06), so the live stack uses a locally patched verifier
image (built outside the repo, `~dockers/mba-chain-nethermind/sc-verifier/`), temporary until upstream supports
Amsterdam (owner ruling 2026-10-31 option (a)): the 31 `Deploy.s.sol` contracts and the PQZ e2e contracts verified, full match; the e2e tokens are EIP-1167 clones Blockscout links to their verified implementations (RUNBOOK § Contract verification).
First whole-chain run, 2026-11-10 (BUILT, after the T66b Step 5 deploy had only its 7 linked libraries verified): of 345
contracts with code, 255 verified (full match), 8 linked clones, 35 CREATE3 proxies, 1 genesis predeploy, plus 90 SSTORE2 data
contracts; sources from four snapshots (`6df89135`: Step 5, PqChat, the tokens harness; `11349728`: the dex harness;
`bf6f3d04`: the 2026-11-04 reset's PQZ e2e `GovernanceRouter`); **46 open, closed by the owner's rulings of 2026-11-10**
(BUILT): 43 EIP-1167 clones carrying 95–175 bytes of appended data (the chain values `IFactoryToken.ChainEnv` the factory appends;
PqChat instances), which Blockscout 9.0.2 does not link (`proxy_type` `unknown`) although each implementation is verified:
`script/onchain/vcheck.py` links them itself, state `linked (clone, appended data)`, when the first 45 bytes are exactly the
EIP-1167 proxy naming a fully verified implementation (Blockscout's own link stays `linked clone`); and the 3 tokens-group
`OnchainFwd` harness contracts, which `sc-verifier` refused (`Fail - Unable to verify`) while their init and runtime code match the
snapshot byte for byte (bar the immutable): their standard JSON was 1.72 MB, above every verified one (largest 1.26 MB), and a
flattened file was refused too, the whole `Tokens.s.sol` (1.65 MB) and the forwarder alone (1,011 B; the single-file form carries
no `experimental` setting, which Amsterdam needs: likely, not confirmed). A standard JSON of the forwarder's source alone
(1,784 B) verified all 3, a partial match (only the metadata hash differs): state `verified (partial, harness)`, a partial match
accepted only where the code's metadata hash names a `script/` artifact of a source snapshot and the explorer's name matches.
Later deploys get a full match: the forwarder is `OnchainForwarder` (`forwardCall(address,bytes)`, was `OnchainFwd.exec`) in
`script/onchain/OnchainForwarder.sol`, no imports, a 2,048 B standard JSON. Read-only pass after: 255 verified, 3 verified
(partial, harness), 8 linked clones, 43 linked (clone, appended data), 35 CREATE3 proxies, 1 genesis, 90 data, 0 unverified.
Rows: `smartcontracts/evm/runs/2026-11-10-ua-mtx-merge-t66b-step5b/verify-scaas-testnet.txt`.

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
ruling 2026-10-31: it matches the 4 MiB `MaxRequestBodySize`, which carries at most a 2 MiB raw transaction as hex);
it is harmless headroom, not a calldata enabler: on Amsterdam Nethermind 2.2.0 caps a transaction's regular gas
(intrinsic, the EIP-7976 calldata floor 15,000 + 64 per byte, execution) at 2^24, while its gasLimit may reach 2^32 − 1
within the block gas limit (200 M here) and gas above 2^24 pays only state gas, so the floor refuses more than 261,909 B of calldata at pool admission
([CTR-PQZ-11](../contracts/pq-zero-knowledge.md#CTR-PQZ-11); decisions CTR-PQZ-06 Change 2026-10-21, the Amsterdam re-plan);
the largest PQZ e2e transaction is 107,268 B. Why: the key
leaves the process that answers RPC; peers and callers that misbehave reach only `rpc`; Blockscout gets the old-block
state a pruned node lacks. Topology, enodes, start / stop order and recovery: [RUNBOOK](../../pqz-core/nethermind/chain/RUNBOOK.md)
§ Node split. Every service runs `restart: unless-stopped` (owner ruling 2026-10-31): Docker restarts a node after a
`PQZ-NODE-FAULT` exit 120; a fault caused by a pooled transaction can loop on the sealer (`rpc` gossips it again), so
`watch.sh` reports `RestartCount`; after a reboot Docker starts every service at once. Live configs (no secrets):
`pqz-core/nethermind/chain/scaas-testnet/`. Mainnet 22776: the same topology is proposed; the owner decides at launch.

## 6. Limitations

<a id="limitations"></a>

- Celo `l1_batch` finality and CIP-64 lanes: PLANNED / open ([NET-EVM-01](#NET-EVM-01)).
- Public profiles stay `draft` until their finality gate is measured and an RPC quorum ≥ 2 is configured.
- The SCaaS testnet has one signer and one RPC provider (the node's quorum is 1); its threat profile is in
  [NET-EVM-04](#NET-EVM-04).

## <a id="paymeta-relayfee"></a>Pay-meta and relay fee (metatx split)

Spec `docs/superpowers/specs/2026-10-27-metatx-split-design.md` §6.2 / §7.2; rules [CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) and [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27); decisions CTR-MTX-26 / -27 (commit per family below). Status BUILT unless a line says owed.

Mermaid, the relay-fee flow (`RelayFeeRouter.relay`, one transaction, all or nothing):

```mermaid
sequenceDiagram
  participant R as Relayer
  participant F as RelayFeeRouter
  participant X as RelayFeeExecutor
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
- **Relay fee.** `src/metatx/RelayFeeRouter.sol` (router) and its one-shot `RelayFeeExecutor`, deployed by `DeployBase` CREATE2;
  `relay` (address payer) and `uaRelay` (UA payer). The router refuses `t.to == EXECUTOR` (UA: `pad(EXECUTOR)`), a target with
  no code or an EIP-7702 designator (`RelayTargetNoCode`), and re-entry (a transient flag); it holds no balance after a call. `RelayFeePaid.payee` is
  `bytes32`. Clients: never pay or approve the executor; if the inner call is an mtx envelope with `MODE_RESTRICT_RELAYER`,
  its relayer is the executor or open.
- **Split.** The relayed token paths run on `MtxPipelineLib` (DELEGATECALL to a linked library, ABI and digests unchanged).
  Measured cost, execution gas, `runs/2026-10-27-metatx-split-overhead-final.txt`: +7.4 k to +7.6 k on the warm/cold
  `MetaTxGasV2` rows (+8.9 k `unwrap`; cancel 0), data-size bound 7.9-9.1 k small and 8.9-11.5 k largest envelope
  (`runs/2026-10-27-metatx-split-overhead.txt`). Node: `guard::erc1271_floor(len)` for a contract signer.
- **UA payers in the node** (BUILT, node-ua-jobs 2026-10-30): the `ua_metatx` job kind relays `uaExecute`,
  `uaExecuteTransfer` and `uaPayMeta`; `RelayFeeRouter.uaRelay` is a `call` job with its own call-table row, priced at
  `params.relay_fee.min_wei_value` against the quote (gas limit × 2 × the first max fee per gas, + the L1 data fee on an
  OP-stack chain with `params.l1_fee = "op-stack"`, e.g. Base and Celo); the indexer reads `UAPaymentSettled` as a
  `PaymentSettled` row, a derived UA as `UA_POOL` + `from_ua` / `to_ua` ([job-api.md](../node/job-api.md#paymeta-relayfee-jobs)).
