# P6f runbook — the copy (executed) and the live roll-out on chain 7622 (Task 10, not executed by Tasks 1–9)

Plan: [P6f](../../../docs/superpowers/plans/2026-10-14-p6f-precompiles.md) Tasks 7, 8, 10; spec:
[pq-zether.md §10](../../../docs/contracts/pq-zether.md#chain-integration). Every command below was executed on the
copy except where a step says *live only*. Logs of the executed runs: [`../runs/`](../runs/).

Chain roles (owner 2026-10-15): **7622 is the testnet** (its data may be reset); **22776 is the future mainnet** (not
built). 22776 gets the precompiles only after the production gates — the external audit and G-LIC written
clearance ([pq-zether.md CTR-PQZ-01](../../../docs/contracts/pq-zether.md), the licence inventory) — with
`engine.Pqz` in its genesis from block 0 and the same addresses.

## Two activation paths (both tested on the copy)

| Path | When | chainspec | Data |
|---|---|---|---|
| **A. Transition timestamp** (an upgrade of a running chain) | 22776 later, any chain upgrade, a re-price or op 7 (a second schedule) | `engine.Pqz.schedules[0].timestamp` = T in the future; history before T is unchanged | kept |
| **B. From genesis** (a new chain, the 7622 testnet reset, owner 2026-10-15) | Task 10 on 7622 may use it | `engine.Pqz` with the first timestamp = the genesis timestamp (0 on 7622): active in every block | fresh (the old data dir is backed up, not used) |

The plugin refuses a first timestamp *before* genesis; a timestamp equal to genesis is path B.

## The copy (Tasks 7–8)

The copy is a **replica** of chain 7622: the live chainspec's parameters, engine and genesis header
(`../Nethermind.Pqz.Test/chainspecs/genesis-7622.json`) with a throwaway signer key in `extraData`; the stock image
first produces its history. The live directory is never read (brief: read-only `cat` / `ls` / `docker image inspect`
only; no copy of the live data or key material). Consequence: its genesis hash is the replica's own, not 7622's
`0x24e43dcb…c464`; on the live chain step 2 checks the live hash.

```sh
C=pqz-core/nethermind/chain
E=pqz-core/nethermind/chain/engine-pqz.json           # the calibrated schedule (Task 6), timestamp patched below
$C/copy.sh init                                         # key, password, genesis.stock.json, configs (scratchpad/p6f-copy)
$C/copy.sh up nethermind/nethermind:1.39.0 genesis.stock.json      # history with the stock image
python3 -I $C/e2e.py head
$C/copy.sh down && $C/copy.sh backup pre                # the rollback point (data dirs, chainspecs, configs)
# G2 demonstration: the stock image with engine.Pqz ignores it
$C/copy.sh patch $E $(( $(date +%s) + 120 ))
$C/copy.sh up nethermind/nethermind:1.39.0 genesis.pqz.json   # after T:
python3 -I $C/e2e.py stock --engine $C/../../../scratchpad/p6f-copy/genesis.pqz.json  # the probe FAILS (recorded)
$C/copy.sh down && $C/copy.sh restore pre
# Path A: step 1 (image, future T), before-T probe, step 2 after T, e2e
$C/copy.sh patch $E $(( $(date +%s) + 600 ))
$C/copy.sh up scaas/nethermind-pqz:1.39.0-pqz1 genesis.pqz.json
docker logs pqzcopy-signer 2>&1 | grep PQZ-START
BEFORE=1 $C/probe.sh $E
$C/probe.sh $E                                           # after T
python3 -I $C/e2e.py e2e --engine $E --key <throwaway key>
# Path B: a fresh chain with engine.Pqz from block 0
$C/copy.sh down && $C/copy.sh backup pathA && $C/copy.sh wipe
$C/copy.sh genesis0 $E && $C/copy.sh up scaas/nethermind-pqz:1.39.0-pqz1 genesis.pqz0.json
$C/probe.sh $E && python3 -I $C/e2e.py e2e --engine $E --key <throwaway key>
```

Task 8 (rehearsal, gate): step 5 (`e2e.py burst`), the 80 M ramp (`watch.sh` until `gasLimit` = 80,000,000, then
`e2e.py fill`), the kill drill (`docker kill -s KILL pqzcopy-signer` during `e2e.py fill`, restart, hashes agree),
the rollback rehearsal (`copy.sh down`, `copy.sh restore pre`, stock image, head = the recorded head). Results:
`../runs/*-copy-*.txt`, `../runs/*-rehearsal.txt`.

## Live roll-out on chain 7622 (Task 10 — *live only*, owner grant 2026-10-14; NOT run by Tasks 1–9)

Preconditions: the gate passed (`../runs/*-rehearsal.txt`); `docker image inspect scaas/nethermind-pqz:1.39.0-pqz1
--format '{{.Id}}'` = the id the gate used; the live container stopped (`docker inspect -f '{{.State.Status}}'
mba_chain_node_nethermind` = `exited`); bamboo-dms / scaas-node told the chain is stopped meanwhile. Every command
and its output goes into `pqz-core/nethermind/runs/<date>-live.txt`.

```sh
L=/home/dockers/mba-chain-nethermind
C=/home/ha/work/ainative/scaas/pqz-core/nethermind/chain
E=$C/engine-pqz.json
TS=$(date +%Y%m%d-%H%M%S)
cd $L

# 1. Backups (all four, timestamped; kept until the owner deletes them)
cp -p genesis.json genesis.json.bak-pqz-$TS
cp -p config.json config.json.bak-pqz-$TS
cp -p docker-compose.yml docker-compose.yml.bak-pqz-$TS
docker run --rm --memory 256m -v $L/data:/d alpine:3 cp -a /d/nethermind_data /d/nethermind_data.bak-pqz-$TS
sha256sum genesis.json* config.json* docker-compose.yml*
docker run --rm -v $L/data:/d alpine:3 du -s /d/nethermind_data /d/nethermind_data.bak-pqz-$TS
# the rollback head: start nothing; read it from the last run's log, or after step 3 from block 0..head (recorded)

# 2. Edits (diff of each against its backup into the log)
#    Path B (testnet reset, owner 2026-10-15): engine.Pqz from block 0, fresh data dir (the old one stays as the backup)
python3 -I $C/patch-chainspec.py genesis.json.bak-pqz-$TS $E 0 genesis.json
docker run --rm -v $L/data:/d alpine:3 sh -c 'rm -rf /d/nethermind_data && mkdir /d/nethermind_data'
#    Path A instead (keep history): T = start + 15 min
#    python3 -I $C/patch-chainspec.py genesis.json.bak-pqz-$TS $E $(( $(date +%s) + 900 )) genesis.json
python3 -I - config.json <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c.setdefault("TxPool", {})["MaxTxSize"] = 1048576
c.setdefault("Blocks", {})["TargetBlockGasLimit"] = 80000000
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
sed -i 's#image: nethermind/nethermind:1.39.0#image: scaas/nethermind-pqz:1.39.0-pqz1#' docker-compose.yml
diff genesis.json.bak-pqz-$TS genesis.json; diff config.json.bak-pqz-$TS config.json; diff docker-compose.yml.bak-pqz-$TS docker-compose.yml

# 3. Start and health
docker compose up -d blockchain-node
docker logs mba_chain_node_nethermind 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE'      # sha256 = image label, selftest, schedule, addresses
$C/watch.sh mba_chain_node_nethermind http://127.0.0.1:8545 10m                  # new block every 5 s
curl -s -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' http://127.0.0.1:8545
#    Path A only, before T: BEFORE=1 $C/probe.sh $E http://127.0.0.1:8545

# 4. Probes and e2e (after T; path B: at once). Genesis hash of 7622: 0x24e43dcb…c464 (the full hash from step 3)
$C/probe.sh $E http://127.0.0.1:8545 <genesis hash>
python3 -I $C/e2e.py e2e --engine $E --rpc http://127.0.0.1:8545 --key <a funded 7622 test key>

# 5. Watch: hourly for 24 h (cron line or manual), until gasLimit = 80,000,000
$C/watch.sh mba_chain_node_nethermind http://127.0.0.1:8545 1h

# Rollback (only on a failed check): back to the four backups and the stock image
docker compose down
cp -p genesis.json.bak-pqz-$TS genesis.json
cp -p config.json.bak-pqz-$TS config.json
cp -p docker-compose.yml.bak-pqz-$TS docker-compose.yml
docker run --rm -v $L/data:/d alpine:3 sh -c "rm -rf /d/nethermind_data && cp -a /d/nethermind_data.bak-pqz-$TS /d/nethermind_data"
docker compose up -d blockchain-node      # head hash = the recorded rollback head
```

Health checks after any restart: `PQZ-START` present, no `PQZ-REFUSE` / `PQZ-NODE-FAULT`; head advancing every 5 s;
`eth_chainId` = `0x1dc6`; `OP_SELFTEST` = `ed910a2c…d205`. A node fault (D4) stops the node with exit code 120 and the
tag `PQZ-NODE-FAULT` in its log: the block in progress is never sealed; restart (`docker compose up -d
blockchain-node`) re-processes it. There is no restart policy (owner step 3).

Owner steps outside this runbook: the follower + rate-limited public RPC on 7622 (the copy's
`docker-compose.copy.yml`, `config.follower.json` and `nginx-rpc.conf` are the rehearsed configs); a restart policy;
when to delete the `*.bak-pqz-*` backups.
