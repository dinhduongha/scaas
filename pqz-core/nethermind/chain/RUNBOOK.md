# P6f runbook — the copy (executed) and the live roll-out on chain 7622 (Task 10)

Plan: [P6f](../../../docs/superpowers/plans/2026-10-14-p6f-precompiles.md) Tasks 7, 8, 10; spec:
[pq-zero-knowledge.md §10](../../../docs/contracts/pq-zero-knowledge.md#chain-integration). Every command below was executed on the
copy except where a step says *live only*. Logs of the executed runs: [`../runs/`](../runs/).

Chain roles (owner 2026-10-15): **7622 is the testnet** (its data may be reset); **22776 is the future mainnet** (not
built). 22776 gets the precompiles only after the production gates — the external audit and G-LIC written
clearance ([pq-zero-knowledge.md CTR-PQZ-01](../../../docs/contracts/pq-zero-knowledge.md), the licence inventory) — with
`engine.Pqz` in its genesis from block 0 and the same addresses.

## Two activation paths (both tested on the copy)

| Path | When | chainspec | Data |
|---|---|---|---|
| **A. Transition timestamp** (an upgrade of a running chain) | 22776 later, any chain upgrade, a re-price or a new op such as op 7, the multi-recipient transfer (a second schedule) | `engine.Pqz.schedules[0].timestamp` = T in the future; history before T is unchanged | kept |
| **B. From genesis** (a new chain, the 7622 testnet reset, owner 2026-10-15) | Task 10 on 7622 may use it | `engine.Pqz` with the first timestamp = the genesis timestamp (0 on 7622): active in every block | fresh (the old data dir is backed up, not used) |

The plugin refuses a first timestamp *before* genesis; a timestamp equal to genesis is path B.

## The copy (Tasks 7–8)

The copy is a **replica** of chain 7622: the live chainspec's parameters, engine and genesis header
(`../Nethermind.Pqz.Test/chainspecs/genesis-7622.json`) with a throwaway signer key in `extraData`; the stock image
first produces its history. The live directory is never read (brief: read-only `cat` / `ls` / `docker image inspect`
only; no copy of the live data or key material). Consequence: its genesis hash is the replica's own, not 7622's
`0x24e43dcb…c464`; on the live chain step 2 checks the live hash.

Copy deviations found necessary (runs `2026-10-1[56]-copy-*.txt`): the history chainspec `genesis.stock.json` adds
`eip4895TransitionTimestamp` 0 and `maximumExtraDataSize` `0xffff` (with 7622's params as they are no follower can
sync); path B starts from the faithful replica `genesis.faithful.json` with `--testnet-reset`, exactly as Task 10;
both node configs set `Network.FilterPeersByRecentIp` false (a restarted follower was refused for minutes);
`copy.sh up` starts the signer first.

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

## Live roll-out on chain 7622 (Task 10 — *live only*; owner 2026-10-15: back up, then reset 7622 with `engine.Pqz` from block 0)

Owner 2026-10-15 (TODO.md, explicit): once the copy gate (Tasks 7–9) passes, back up the current 7622 chain data, then
**reset** 7622 with a fresh genesis carrying the precompiles from block 0 (path B), keeping chain id 7622, the gas limit
16,777,216, the ports and the signer. The genesis **block** stays byte-identical, so the genesis hash stays
`0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464` (it is pinned in tests, vectors and
`chain-uids.json`): `engine.Pqz` and the three `--testnet-reset` params (`eip4895TransitionTimestamp` 1,
`maximumExtraDataSize` `0xffff`, `maxCodeSizeTransition` 0 — rehearsed as path B on the copy) are not part of the
genesis header. The history is discarded (kept in the backup). Every command and its output goes into
`pqz-core/nethermind/runs/<date>-live.txt`. If any step fails: the rollback below, then report — no improvising.

Preconditions: the gate passed (`../runs/*-rehearsal.txt`); `docker image inspect scaas/nethermind-pqz:1.39.0-pqz1
--format '{{.Id}}'` = the id the gate used; the live container stopped (`docker inspect -f '{{.State.Status}}'
mba_chain_node_nethermind` = `exited`; stop it with `docker compose stop -t 120 blockchain-node` if not).

```sh
L=/home/dockers/mba-chain-nethermind
C=<repo>/pqz-core/nethermind/chain
E=$C/engine-pqz.json
TS=$(date +%Y%m%d-%H%M%S)
B=/home/dockers/mba-chain-nethermind-backups/pqz-$TS          # dated, outside the repo and outside $L
A="docker run --rm --memory 512m -v $L:/l -v $(dirname $B):/b alpine:3"
cd $L

# 1. Backup: chainspec, config, compose, password, keystore (keys), data dir; kept until the owner deletes it
mkdir -p $B && cp -p genesis.json config.json docker-compose.yml password.txt $B/
$A sh -c "cp -a /l/keystore /l/data/nethermind_data /b/pqz-$TS/"
#    readable and identical: sha256 manifests of every file, live vs backup (paths relative), then sizes
$A sh -c "cd /l/data/nethermind_data && find . -type f | sort | xargs sha256sum" > $B.live-data.sha256
$A sh -c "cd /b/pqz-$TS/nethermind_data && find . -type f | sort | xargs sha256sum" > $B.backup-data.sha256
cmp $B.live-data.sha256 $B.backup-data.sha256 && echo "data backup identical: $(wc -l < $B.live-data.sha256) files"
(cd $B && sha256sum genesis.json config.json docker-compose.yml password.txt) ; diff <(cd $L && sha256sum genesis.json config.json docker-compose.yml password.txt) <(cd $B && sha256sum genesis.json config.json docker-compose.yml password.txt)
$A du -s /l/data/nethermind_data /b/pqz-$TS/nethermind_data /b/pqz-$TS/keystore
#    the rollback head, read from a scratch copy of the BACKUP by the stock image (no mining, no keys, no peers):
#    also proves the backup opens
S=<repo>/scratchpad/p6f-livecheck && mkdir -p $S
docker run --rm --memory 512m -v $(dirname $B):/b -v $S:/s alpine:3 cp -a /b/pqz-$TS/nethermind_data /s/data
python3 -I - $L/config.json $S/config.json <<'PY2'
import json, sys
c = json.load(open(sys.argv[1])); c["Init"]["IsMining"] = False; c["Mining"] = {"Enabled": False}; c.pop("KeyStore")
c["JsonRpc"].pop("AdditionalRpcUrls", None); c["Network"] = {"MaxActivePeers": 0}
json.dump(c, open(sys.argv[2], "w"), indent=2)
PY2
docker run -d --name p6f-livecheck --memory 2g -p 127.0.0.1:18547:8545 -v $S/data:/nethermind/nethermind_datadir \
  -v $B/genesis.json:/nethermind/genesis.json:ro -v $S/config.json:/nethermind/config.json:ro \
  nethermind/nethermind:1.39.0 --config /nethermind/config.json --datadir /nethermind/nethermind_datadir
# (after ~30 s) the head of the old history = the rollback head; genesis hash = 0x24e43dcb…c464
python3 -I $C/e2e.py head --rpc http://127.0.0.1:18547
docker rm -f p6f-livecheck && docker run --rm -v $S:/s alpine:3 rm -rf /s/data

# 2. Edits (diff of each against its backup into the log)
python3 -I $C/patch-chainspec.py $B/genesis.json $E 0 $L/genesis.json --testnet-reset
python3 -I - config.json <<'PY2'
import json, sys
c = json.load(open(sys.argv[1]))
c.setdefault("TxPool", {})["MaxTxSize"] = 1048576
c.setdefault("Blocks", {})["TargetBlockGasLimit"] = 80000000
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY2
sed -i 's#image: nethermind/nethermind:1.39.0#image: scaas/nethermind-pqz:1.39.0-pqz1\n    mem_limit: 4g#' docker-compose.yml
diff $B/genesis.json genesis.json; diff $B/config.json config.json; diff $B/docker-compose.yml docker-compose.yml
$A sh -c 'rm -rf /l/data/nethermind_data && mkdir /l/data/nethermind_data'     # fresh chain; the old data is in $B

# 3. Start and health
docker compose up -d blockchain-node
docker logs mba_chain_node_nethermind 2>&1 | grep -E '^PQZ-START|PQZ-REFUSE'   # sha256 = image label, selftest, schedule ts 0x0, addresses
$C/watch.sh mba_chain_node_nethermind http://127.0.0.1:8545 10m                 # head advancing every 5 s
python3 -I $C/e2e.py head --rpc http://127.0.0.1:8545

# 4. Probes and e2e (path B: at once). Genesis hash unchanged: 0x24e43dcb…c464
$C/probe.sh $E http://127.0.0.1:8545 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464
python3 -I $C/e2e.py e2e --engine $E --rpc http://127.0.0.1:8545 --key <a test key funded in genesis> --no-ua

# 5. Watch: hourly for 24 h (cron line or manual), until gasLimit = 80,000,000
$C/watch.sh mba_chain_node_nethermind http://127.0.0.1:8545 1h

# Rollback (on any failed check): back to the backup and the stock image, the old history
docker compose down
cp -p $B/genesis.json $B/config.json $B/docker-compose.yml $L/
$A sh -c "rm -rf /l/data/nethermind_data && cp -a /b/pqz-$TS/nethermind_data /l/data/nethermind_data"
docker compose up -d blockchain-node      # head hash = the rollback head of step 1
```

Health checks after any restart: `PQZ-START` present, no `PQZ-REFUSE` / `PQZ-NODE-FAULT`; head advancing every 5 s;
`eth_chainId` = `0x1dc6`; `OP_SELFTEST` = `ed910a2c…d205`. A node fault (D4) stops the node with exit code 120 and the
tag `PQZ-NODE-FAULT` in its log: the block in progress is never sealed; restart (`docker compose up -d
blockchain-node`) re-processes it. There is no restart policy (owner step 3).

Owner steps outside this runbook: the follower + rate-limited public RPC on 7622 (the copy's
`docker-compose.copy.yml`, `config.follower.json` and `nginx-rpc.conf` are the rehearsed configs); a restart policy;
when to delete the `*.bak-pqz-*` backups.

## The multi-recipient transfer (op 7) on chain 7622 (P6-ANON S8, path A — *live only*, executed 2026-10-17)

A second `engine.Pqz` schedule at a future timestamp T: the live rows unchanged plus one row per built multi-recipient shape
`(proofSystemId, M, auditorOn)` (plugin rows with `legs` / `auditorOn`, plan D19), from the multi-recipient calibration
(`../runs/2026-10-17-calib-ops7*`); the image moves to `scaas/nethermind-pqz:1.39.0-pqz2` (the plugin that reads the multi-recipient transfer's
header words) before T; the chain data is kept. Rehearsed on a fresh copy first (`../runs/2026-10-17-s8-copy-*`:
pqz1 → pqz2 with the data kept, before T every multi-recipient inputs a miss, after T every built shape `…01`, e2e 86 ok). Log:
`../runs/2026-10-17-s8-live*.txt`.

```sh
L=/home/dockers/mba-chain-nethermind; C=<repo>/pqz-core/nethermind/chain
TS=$(date +%Y%m%d-%H%M%S); B=/home/dockers/mba-chain-nethermind-backups/op7-$TS
A="docker run --rm --memory 512m -v $L:/l -v $(dirname $B):/b alpine:3"
cd $L && docker compose stop -t 120 blockchain-node
# 1. backup as in Task 10 step 1 (chainspec, config, compose, password, keystore, data; sha256 manifests compared)
# 2. the second schedule (refuses a T less than 5 minutes ahead) and the image
T=$(( $(date +%s) + 900 ))
python3 -I $C/add-schedule.py $B/genesis.json <repo>/pqz-core/nethermind/runs/2026-10-17-calib-ops7-engine-pqz.json $T $L/genesis.json
sed -i 's#scaas/nethermind-pqz:1.39.0-pqz1#scaas/nethermind-pqz:1.39.0-pqz2#' docker-compose.yml
docker compose up -d blockchain-node      # PQZ-START: library 4fc1a6a2…, self-test ed910a2c…, two schedules
python3 -I -c "import json; json.dump(json.load(open('$L/genesis.json'))['engine']['Pqz'], open('$C/engine-pqz.json', 'w'), indent=2)"
# 3. before T: every multi-recipient inputs a miss (smallest row, …00, no FFI call)
python3 -I $C/e2e.py probe --engine $C/engine-pqz.json --schedule 0 --rpc http://127.0.0.1:8545 --genesis-hash 0x24e43dcb…c464
# 4. after T: every built shape …01 at its row, negatives …00; transactions with the test key 0x…04
python3 -I $C/e2e.py probe --engine $C/engine-pqz.json --rpc http://127.0.0.1:8545 --genesis-hash 0x24e43dcb…c464
python3 -I $C/e2e.py e2e --engine $C/engine-pqz.json --rpc http://127.0.0.1:8545 --key <test key 0x…04> --no-ua
# Rollback before T: stop, restore genesis.json + docker-compose.yml from $B (pqz1, one schedule), start; the data
# needs no restore (no block used the second schedule). After T: Task 10's rollback with $B's data.
```
