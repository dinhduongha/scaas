# r01b fix-round start-up runs: the script as run from scratchpad/startup/ (git-ignored; record only). Inputs as in
# 2026-10-26-r01b-startup.sh (genesis-live.json, genesis-new.json, config.json), plus:
#   genesis-earlier-foreign.json = genesis-new.json with engine.Pqz.schedules = [genesis-live.json's schedule (0x0, PQZL v4 / PQZH v2),
#   genesis-new.json's schedule moved to 0x65000000 (2023-09-12T06:06:56Z, before the wall clock)]
# plugin: dotnet build -c Release -p:PqzSet=n2304-kmax4096 in the SDK image (commit bd248bb5)
#!/bin/sh
# r01b fix-round start-up runs (review of fix part b, I-1: the id check from the block tree head): throwaway containers of image 2.2.0-pqz4 with this branch's plugin (n2304-kmax4096) and the
# reviewed library (Dockerfile ffi stage) bind-mounted over the image's; --memory 2g, one at a time, no ports, no peers,
# mining and RPC off, a fresh data dir on /home (the host root fs is below Nethermind's 6.68 GB free-space check), emptied after each run.
cd "$(dirname "$0")"
S=$(pwd)
R=$(cd ../.. && pwd)
IMG=scaas/nethermind-pqz:2.2.0-pqz4
LIB=$R/pqz-core/nethermind/bin/ffi-out-n2304-kmax4096/libpqz_ffi.so
OK=$R/pqz-core/nethermind/Nethermind.Pqz/bin/Release/net10.0/Nethermind.Pqz.dll
echo "# r01b fix-round start-up runs, $(date -u +%FT%TZ), commit $(git -C $R rev-parse --short HEAD); image $IMG ($(docker image inspect $IMG --format '{{.Id}}' | cut -c8-19))"
echo "# library $(sha256sum $LIB | cut -c1-64) (the reviewed n2304-kmax4096 build, SelfTest.ExpectedLibrarySha256)"
echo "# plugin $(sha256sum $OK | cut -c1-64) (pqz-core/nethermind/Nethermind.Pqz, -p:PqzSet=n2304-kmax4096)"
run() {
  name=$1 genesis=$2 dll=$3 what=$4
  :
  cp $S/$genesis $S/genesis.json
  echo
  echo "## $name: $what"
  echo "genesis $genesis: engine.Pqz schedule ids $(python3 -c "
import json;g=json.load(open('$S/genesis.json'));print('; '.join(s['timestamp']+': '+','.join(sorted({r['id'][:10] for r in s['pqz']})) for s in g['engine']['Pqz']['schedules']))")"
  mkdir -p $S/db
  C=$(docker run -d --name r01b-fix-startup-$name --memory 2g --cpus 2 -v $S/db:/nethermind/r01b_db \
      -v $S/config.json:/x/config.json:ro -v $S/genesis.json:/x/genesis.json:ro \
      -v $dll:/nethermind/plugins/Nethermind.Pqz.dll:ro -v $LIB:/nethermind/plugins/libpqz_ffi.so:ro \
      $IMG --config /x/config.json)
  for i in $(seq 1 60); do
    st=$(docker inspect -f '{{.State.Status}}' $C)
    [ "$st" = exited ] && break
    docker logs $C 2>&1 | grep -q "PQZ-START" && [ $i -ge 20 ] && break
    sleep 0.5
  done
  echo "state: $(docker inspect -f '{{.State.Status}} exit {{.State.ExitCode}} started {{.State.StartedAt}} finished {{.State.FinishedAt}}' $C)"
  echo "\$ docker logs | grep -E 'PQZ-|Block tree|Genesis|Exit'"
  docker logs $C 2>&1 | grep -E "PQZ-|Block tree initialized|enesis|xiting" | grep -v "^ *at " | cut -c1-900
  docker rm -f $C > /dev/null
  docker run --rm -v $S/db:/d --entrypoint sh $IMG -c 'rm -rf /d/* /d/.[!.]*' && rmdir $S/db
}
run normal genesis-new.json $OK "the set's own ids (engine-pqz-provisional-n2304.json, timestamp 0x0), fresh database: a normal start"
run earlier-foreign genesis-earlier-foreign.json $OK "the live testnet's schedule (PQZL v4 / PQZH v2) from 0x0, the set's own ids from 0x65000000 (2023-09-12, before the wall clock), fresh database (head = genesis 0x0): PQZ-REFUSE (the wall-clock rule of part b started here)"
run foreign-live genesis-live.json $OK "the live SCaaS testnet's schedule (plan 5h Task 8d ids PQZL v4 / PQZH v2, in force from 0x0): PQZ-REFUSE"
rm -f $S/genesis.json
echo
echo "# $(date -u +%FT%TZ) containers removed, data dirs deleted"
