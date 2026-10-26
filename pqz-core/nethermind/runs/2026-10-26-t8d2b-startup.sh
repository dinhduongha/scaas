#!/bin/sh
# t8d2b start-up run (plan 5h Task 8d part 2b, open item (c): PQZ-START logs the head timestamp the id check used).
# Inputs (git-ignored, copied from the r01b runs' scratchpad/startup/): config.json (no ports / peers / mining / RPC),
# genesis-new.json (engine-pqz-provisional-n2304.json's schedule at 0x0, the set's own ids). The image 2.2.0-pqz5 (its
# reviewed n2304 library dd0e7668…) with this branch's plugin (built -p:PqzSet=n2304-kmax4096 in the SDK image)
# bind-mounted; --memory 2g, one container at a time; one throwaway docker volume as the data dir, used twice: an empty
# database (the id check reads the genesis timestamp), then the database the first start initialised (head = block 0);
# the volume is removed after.
#   sh runs/2026-10-26-t8d2b-startup.sh <inputs dir> <plugin dll>   -> stdout (runs/2026-10-26-t8d2b-startup-n2304-kmax4096.txt)
set -eu
S=$1 DLL=$2
IMG=scaas/nethermind-pqz:2.2.0-pqz5
V=t8d2b-startup-db
echo "# t8d2b start-up runs, $(date -u +%FT%TZ), commit $(git rev-parse --short HEAD); image $IMG ($(docker image inspect $IMG --format '{{.Id}}' | cut -c8-19))"
echo "# plugin $(sha256sum "$DLL" | cut -c1-64) (-p:PqzSet=n2304-kmax4096)"
docker volume create $V > /dev/null
run() {
  echo
  echo "## $1"
  C=$(docker run -d --name t8d2b-startup --memory 2g --cpus 2 -v $V:/nethermind/r01b_db \
      -v "$S/config.json":/x/config.json:ro -v "$S/genesis-new.json":/x/genesis.json:ro \
      -v "$DLL":/nethermind/plugins/Nethermind.Pqz.dll:ro $IMG --config /x/config.json)
  for i in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Status}}' "$C")" = exited ] && break
    docker logs "$C" 2>&1 | grep -q "PQZ-START" && [ "$i" -ge 20 ] && break
    sleep 0.5
  done
  echo "state: $(docker inspect -f '{{.State.Status}} exit {{.State.ExitCode}}' "$C")"
  docker logs "$C" 2>&1 | grep -E "PQZ-|Block tree initialized|enesis" | grep -v "^ *at " | cut -c1-700
  docker rm -f "$C" > /dev/null
}
run "empty database: the id check reads the genesis timestamp"
run "restart on the database the first start initialised: the id check reads the head (block 0)"
docker volume rm $V > /dev/null
echo
echo "# $(date -u +%FT%TZ) container and volume removed"
