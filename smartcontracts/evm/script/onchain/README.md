# The on-chain matrix

Every external entry of every deployed contract, called on a real node. One run targets exactly one chain: **local**
(fresh chains of its own), the **SCaaS testnet** (its RPC only), or **another testnet** (its RPC only); nothing is read
from another target's run. Plan: [ua-mtx-merge](../../../../docs/superpowers/plans/2026-11-04-ua-mtx-merge.md) T66b Step 5b;
deploy and layout: [T66b spec](../../../../docs/superpowers/specs/2026-11-09-t66b-library-organisation.md) §12. Results: the
runs notes `runs/2026-11-10-ua-mtx-merge-t66b-step5b-<target>.txt` and
[records, coverage.json](../../runs/2026-11-10-ua-mtx-merge-t66b-step5b/). Test chains only. **UNAUDITED.**

## Groups

`coverage.json` lists every contract of [groups.json](groups.json) with its entries (signature, selector, state-changing or
view; a token kind's body module). Each group is one script with its own book (address -> contract label):

| group | script | what |
|---|---|---|
| tokens | `Tokens.s.sol` | kinds 0-3, 8-11: ERC-20, pay, relay fee, wrapped, tax, owner governance, an ML-DSA-65 signer |
| gov | `Gov.s.sol` | GovernanceRouter by UA signature, regulated powers, SmartKeyAccount, ComplianceRegistry |
| dex | `Dex.s.sol` | SCaaSDex and its module D, the token trade entries |
| liquidity | `Liquidity.s.sol` | `mtxLiquidity` (CTR-DEX-30): a v2-style pair created in the plan, adds, a withdraw, a v4-style position minted through its reader, a partial and a whole withdraw; the views and negatives of spec 2026-11-10-dex-liquidity.md §15 |
| misc | `Misc.s.sol` | registry (every vector UA kind), own factory's release paths, MandateWallet, RefServiceEscrow |
| zether | `zether.sh` | `script/ZetherE2E.s.sol`, `ZetherMore.s.sol` and their regulated twins (kinds 2, 3, 10, 11) |
| pq | `pq.py` | `script/pqz/e2e.py` (its own deploy) + kinds 12, 13 + the public entries signed by ML-DSA-65 (PRECOMPILE mode) |
| pqoff | `pq.py --offchain` | the PQZ `OFFCHAIN` verify mode: fixed / transferable verifier UA, the change through GovernanceRouter, negatives |
| verifiers, views | `verifiers.py`, `coverage.py views` | every verifier with the vectors; every static-argument view |
| pqchat | (slot) | PqChat (plan UA-7): `groups.json` holds the slot; its script plugs in as below |
| wraplimits | `WrapLimits.s.sol` through `wraplimits.sh` | the wrap and unwrap limits (group 3l, spec 2026-11-10-wrap-limits.md §11) on hybrids of kinds 1, 5, 13 of its own factory (`noticePeriod()` 1 hour; the PQZ kinds `OFFCHAIN`): windows per user and token-wide, the net rule and its decay at day 0, H/2, H, the redeemer's budget, the lists, the router's setters at once and after the notice, the named refusals, the pure-wrap refusal of bits 25-27. Seven forge runs, the chain's clock set between them (local only; last in the default order: it moves the clock two days); its outputs in `runs/2026-11-10-ua-mtx-merge-3l-onchain/` |

## Before any target

From `smartcontracts/evm`: Foundry 1.8.5 on `PATH`, python3, node with `clients/clientkeys/node_modules`, a built
`zether-cli` and `pqz_prove` (their READMEs), `lib/` (`../scripts/evm_libs.sh install`), and for the PQ groups a build at
the default set in `EVM_OUT` (default `out/t66b-e2e`; never while `src/pqz/PqzSet.sol` is modified by an at-set run).
Run `matrix.sh` itself in the foreground, never inside `timeout`, and outside `scripts/capped`: it puts a local target
wholly under `capped`; a remote target (the SCaaS testnet, another testnet) compiles under `capped` first, then runs its
broadcasts without a slot under a memory scope (`MATRIX_REMOTE_MEM`, default 1G, no swap), where forge must print "No
files changed, compilation skipped" or the step fails (owner 2026-11-10).

## Local

Fresh chains only; no other RPC is read (`RPC_7622` may point nowhere):

```sh
cd smartcontracts/evm
RPC_7622=http://127.0.0.1:9 COPY=$PWD/../../scratchpad/onchain-copy sh script/onchain/matrix.sh local
```

- a fresh anvil (chain 31337, Amsterdam, 200 M block gas, 128 KiB code) with anvil's dev keys, `deploy.sh evm` on it with
  every option (wrapped, regulated, Zether; `DEPLOY_NAME=local-31337-testnet`: `deployments/local-31337-testnet.json`,
  `local-31337-testnet-releases.json`, NET-EVM-13), then tokens, gov, dex, misc,
  zether, verifiers, views, wraplimits;
- a fresh Nethermind copy under `COPY` (git-ignored; `copy.sh init`, `genesis0 engine-pqz.json`, `copygen.py`: the
  Amsterdam transitions `init`'s chainspec lacks, test keys 0x…01-0x…03, the CREATE2 deployer; then `up`) for pq and
  pqoff, which need its PQZ and ML-DSA precompiles; e2e.py signs for chain id 7622, so the copy keeps it. Its compose
  file caps each container (1700 MB per node, 64 MB nginx); `matrix.sh` stops it after (`copy.sh down`).
- Without `COPY`: `LOCAL_PQ_RPC` names a copy already up, or the PQ groups are listed as not run.

## SCaaS testnet

Its RPC only; never its containers, config or port. It builds on the Step 5 deploy (`deployments/scaas-testnet.json`,
`scaas-testnet-t66b-releases.json`, the Step 5 runs note's deploy rows); test keys 0x…01-0x…03 sign (genesis-funded):

```sh
cd smartcontracts/evm
RPC_7622=http://127.0.0.1:8545 sh script/onchain/matrix.sh scaas-testnet
```

`MATRIX_GROUPS="tokens misc"` runs some groups; groups run one after another (one set of keys and nonces).

## Several targets in one call

Each target in turn, in its own process (its env, temp dir, anvil / copy, teardown); one that fails does not stop the
next; a summary (target | group | ok / fail / not run) at the end, exit non-zero if any target failed. Local, then the
SCaaS testnet:

```sh
cd smartcontracts/evm
RPC_7622=http://127.0.0.1:8545 COPY=$PWD/../../scratchpad/onchain-copy \
  sh script/onchain/matrix.sh local scaas-testnet
```

A named target `<name>` reads `ONCHAIN_RPC_<NAME>`, `PRIVATE_KEY_<NAME>`, `ONCHAIN_K1_<NAME>`… (upper case, `-` as
`_`); the plain names only when it is the only named target; else the mnemonic file as below.

## Another testnet through RPC

- **The chain must have:** the Amsterdam rules (NET-EVM-06, EIP-8037 included); a code size limit and a block gas limit
  that take the releases (`CHAIN_CODE_LIMIT`, default 131072; a release is one transaction, regular + state gas within
  the block, NET-EVM-11), and every transaction here asks at most 60 M; the deterministic CREATE2 deployer
  `0x4e59b44847b379578588920cA78FbF26c0B4956C` (NET-EVM-05); its `chain_uid` profile (a `chain-uids.json` row, or
  `CHAIN_UID` for `deploy.sh`); funded accounts.
- **Deploy first:** `MATRIX_DEPLOY=1` runs `deploy.sh evm` as for local when `deployments/<key>.json` is missing (a chain not in `chain-uids.json`
  needs `DEPLOY_NAME`).
- **Keys:** `PRIVATE_KEY_<NAME>` (the deployer) and `ONCHAIN_K1_<NAME>..K3` (the plain names when it is the only named
  target), or else indices 0-3 of the testnet-only mnemonic in
  `SCAAS_TESTNET_MNEMONIC_FILE` (`source ~/.profile`): `matrix.sh` copies its `mnemonic:` line into its private temp dir
  for `cast` and keeps the keys in its own environment; never printed, never written into the repo. Fund the four first.
- **PQZ:** with the PQZ precompile, PRECOMPILE mode (`ONCHAIN_PQZ=precompile`: pq and pqoff); without it, a PQZ token runs
  only in the `OFFCHAIN` verify mode (`pqzVerifyMode` 1: a verifier UA signs a `PqzVerdict` per proof, the releases on
  deps `[0x0]`; `ONCHAIN_PQZ=offchain` runs pqoff alone). Today `pq.py` (through e2e.py) still needs the precompile for
  the holders' registration proofs and signs for chain id 7622, so another chain takes the fallback, the default:
  `ONCHAIN_PQZ=off`, PQZ left out, its contracts at 0 in the table; record why in the runs note.

```sh
cd smartcontracts/evm
source ~/.profile
ONCHAIN_RPC_SEPOLIA=https://<rpc> MATRIX_DEPLOY=1 sh script/onchain/matrix.sh sepolia
```

## Gas

Forge asks each transaction's limit as its simulated gasUsed × `ONCHAIN_GAS_MULTIPLIER` / 100. That gasUsed is after
the storage refund, so a call that frees storage needs headroom above it: 130 (× 1.30, the default; at 1.10 the
GovernanceRouter's `mtxCancelGrant` ran out of gas on chain). `matrix.sh` uses 200 for tokens (anvil's Amsterdam
simulation undershot a CREATE by 19 % and a relay at 1.30); a call that would ask more than 60 M, or that frees storage
in the scripts' own runs, carries a fixed `{gas: …}` (Misc's `REFUND_GAS`, `DEX_RELEASE_GAS`; Tokens' ML-DSA key cache).
`pq.py` asks Nethermind's estimate × 1.5 + 300 k, at most 60 M and the block's limit (e2e.py's own × 1.15 + 50 k left an
ML-DSA-signed `mtxShield` short: 448 k asked, 453 k needed).

## Outputs

Stdout is never silent and stays short: one line per event, `[target] start` (chain id, PQZ mode), anvil / copy up and
down, `[target] deploy …` / `deploy ok N txs`, `[target/group] start`, then `ok N/M txs, negatives n/m (Xs)` or
`FAIL <entry>: <named error>`, and a heartbeat every 30 s (`[target/group] … 42 txs, 95s`). Public ids only (chain id,
addresses, tx hashes), never a key or a mnemonic; forge's and every step's full output go to the git-ignored
`runs/…/matrix-<target>.log` and `<group>-<target>.log`.

Named by target: `runs/2026-11-10-ua-mtx-merge-t66b-step5b/records-<target>-<group>.jsonl` (one line per transaction:
contract, selector, tx hash, gasUsed, status; a negative with the error expected and got), `table-<target>.txt`,
`coverage.json`; books `deployments/onchain-<target>-<group>.json` (git-ignored). Logs are git-ignored `.log`. No key,
no machine path. `python3 -I script/onchain/coverage.py note --net <target>` prints the runs note's body: the table,
every state-changing entry not called with its reason (`notrun.json`), the negatives, the heaviest transactions.

## One group by hand

`ONCHAIN_RPC=<url> DEPLOY_JSON=deployments/<key>.json ../../scripts/capped script/onchain/run.sh <target> <Group>
--tc <Group>`; without `ONCHAIN_RPC`, `run.sh local` forks `FORK_RPC` on `PORT` for that run. `zether.sh` (`NET`, `RPC`,
`PRIVATE_KEY`, `ZETHER_PARTS`) and `pq.py --net <target> --rpc <url> [--offchain] [--extra-only]` print their usage at the
top of the file.

## Adding a group

Add the contracts under a group name in `groups.json` (`pqchat` is the slot), `coverage.py gen`; write `<Group>.s.sol` on
`OnchainBase` (`_init("<group>")`, `_book` every address, `_neg` the refusals, `_negData` where the whole revert data is
fixed, `_writeBook`), add it to `matrix.sh`'s groups and run it with `run.sh`; add a reason to `notrun.json` for each
entry it cannot call.

## Safety

Test chains only. Never the live stack's containers, config or port: RPC only. A contract bug stops the run: report it,
do not fix `src/` here.
