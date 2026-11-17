#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T68 / spec §8's script test on two anvils: Deploy.s.sol on chain A (31951, writes the release list) and chain B (31952,
# another genesis: reads it), the demo tokens and the DEX by the same deployer and salts; then the same factory, release
# and instance addresses, each chain's own chainUid() and instance code. Both anvils stopped at the end (trap).
set -u
cd "$(dirname "$0")/../.." # smartcontracts/evm
export PATH="$HOME/.foundry/bin:$PATH"
# anvil's own account 0, read from its --config-out file at run time (a local test key; none is written here)
CFG=./deployments/t68-anvil-a.json
LIST=./deployments/t68-releases.json
rm -f "$LIST"
anvil --chain-id 31951 --port 31951 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 65536 --silent \
  --config-out $CFG &
A=$!
anvil --chain-id 31952 --port 31952 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 65536 --silent \
  --timestamp 1800000000 &
B=$!
trap 'kill $A $B 2>/dev/null; wait $A $B 2>/dev/null' EXIT
sleep 3 # one fixed start-up wait, then each anvil must answer
for p in 31951 31952; do cast chain-id --rpc-url http://127.0.0.1:$p >/dev/null || { echo "anvil $p not up"; exit 1; }; done
PK=$(python3 -c "import json; print(json.load(open('$CFG'))['private_keys'][0])")
FROM=$(cast wallet address --private-key $PK)
run() { # chain port, write
  PRIVATE_KEY=$PK DEMO_SUPPLY=1000000 RELEASES_JSON=$LIST RELEASES_WRITE=$2 \
    forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:$1 --broadcast --slow --silent --disable-code-size-limit \
    --sender $FROM > "runs/2026-11-08-ua-mtx-merge-t68-anvil-$1.log" 2>&1
  echo "deploy $1 rc=$?"
}
run 31951 true
run 31952 false
j() { python3 -c "import json,sys; print(json.load(open('deployments/$1.json'))['$2'])"; }
ok=0
for k in token_factory implementation_normal dex_implementation demo_token demo_token_2; do
  a=$(j 31951 $k); b=$(j 31952 $k)
  [ "$a" = "$b" ] && echo "same $k $a" || { echo "DIFF $k $a $b"; ok=1; }
done
for p in 31951 31952; do
  f=$(j $p token_factory); t=$(j $p demo_token)
  g=$(cast block 0 --field hash --rpc-url http://127.0.0.1:$p)
  u=$(cast call $f "chainUid()(bytes32)" --rpc-url http://127.0.0.1:$p)
  ut=$(cast call $t "chainUid()(bytes32)" --rpc-url http://127.0.0.1:$p)
  ch=$(cast keccak $(cast code $t --rpc-url http://127.0.0.1:$p))
  [ "$g" = "$u" ] && [ "$g" = "$ut" ] && echo "chain $p: genesis $g = factory and instance chainUid(); instance code $ch" \
    || { echo "chain $p: genesis $g factory $u instance $ut"; ok=1; }
done
python3 -c "import json; d=json.load(open('$LIST')); print('release list rows:', len(d), sorted(d)[:6])"
# plan T68 step 2 on chain A: a DEX, the test kind NoteKind (class 4) registered and one instance, read back by owner / creator
R=http://127.0.0.1:31951
F=$(j 31951 token_factory)
ME=0x000000000000000000000000${FROM:2}
cast send $F "createDex(uint64,bytes,bytes32)" 1 $(cast abi-encode "f((bytes32,uint32,address,bool,uint64,address))" "($ME,0,$FROM,false,0,0x0000000000000000000000000000000000000000)")   0x6465780000000000000000000000000000000000000000000000000000000000 --private-key $PK --rpc-url $R > /dev/null   && echo "createDex ok" || { echo "createDex failed"; ok=1; }
ENV="(0x0000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000,false,[],[],[],[])"
cast send $F "publishClassEnv(uint16,uint16,uint16,(address,address,bool,address[],bytes32[],address[],bytes32[]))" 4 0 1 "$ENV"   --private-key $PK --rpc-url $R > /dev/null && echo "publishClassEnv ok" || { echo "publishClassEnv failed"; ok=1; }
CODE=$(python3 -c "import json; print(json.load(open('out/GenericKinds.sol/NoteKind.json'))['bytecode']['object'])")
SEL=$(cast sig "initialize(bytes32,string)")
IFACE=$(printf '0x%08x' $(( $(cast sig "initialize(bytes32,string)") ^ $(cast sig "note()") )))
cast send $F "deployRelease((uint16,uint16,uint64),uint16,bytes4,bytes4,bytes,bytes)" "(4,0,1)" 1 $SEL $IFACE $CODE 0x   --private-key $PK --rpc-url $R --gas-limit 30000000 > /dev/null && echo "deployRelease ok" || { echo "deployRelease failed"; ok=1; }
cast send $F "setClassKindEnabled(uint16,uint16,bool)" 4 0 true --private-key $PK --rpc-url $R > /dev/null
INIT=$(cast calldata "initialize(bytes32,string)" $ME "anvil dry run")
cast send $F "createInstance((uint16,uint16,uint64),bytes32,bytes)" "(4,0,1)" 0x6e6f746500000000000000000000000000000000000000000000000000000000 $INIT   --private-key $PK --rpc-url $R --gas-limit 30000000 > /dev/null && echo "createInstance ok" || { echo "createInstance failed"; ok=1; }
for c in 1 2 4; do
  echo "class $c by creator: $(cast call $F "contractsOfCreator(bytes32,uint16,uint256,uint256)((address,bytes32,bytes32,uint16,uint16,uint64,uint64,uint64)[],uint256)" $ME $c 0 10 --rpc-url $R | tail -1)"
  echo "class $c by owner:   $(cast call $F "contractsOfOwner(bytes32,uint16,uint256,uint256)((address,bytes32,bytes32,uint16,uint16,uint64,uint64,uint64)[],uint256)" $ME $c 0 10 --rpc-url $R | tail -1)"
done
# plan T68 step 3: the factory's deterministic address in no vector or KAT
cd ..
hits=$(grep -rli "${F:2}" vectors evm/test/vectors 2>/dev/null | grep -v legacy || true)
[ -z "$hits" ] && echo "factory $F in no vector" || { echo "factory address in: $hits"; ok=1; }
cd evm
rm -f "$CFG"
echo "t68-anvil ok=$ok"
