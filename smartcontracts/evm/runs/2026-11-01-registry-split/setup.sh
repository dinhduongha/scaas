#!/bin/bash
# usage (from variants/): levers/setup.sh <store|r1|r2|r1r2>  - a variant tree from the built baseline, with the lever applied
set -e
v=$1
rm -rf "$v/smartcontracts/evm/src/ua/UARegistry.sol.tmp"
if [ ! -d "$v" ]; then
  mkdir "$v"; cp -a baseline/clients baseline/scripts "$v/"
  mkdir "$v/smartcontracts"; cp -a baseline/smartcontracts/evm "$v/smartcontracts/"
  cp -al baseline/smartcontracts/vectors "$v/smartcontracts/vectors"
fi
e="$v/smartcontracts/evm/src/ua"
cp levers/UAStore.sol "$e/"
case $v in store|r1) rm -f "$e/UARegisterLib.sol";; *) cp levers/UARegisterLib.sol "$e/";; esac
case $v in store|r2|one) rm -f "$e/UAViewLib.sol";; *) cp levers/UAViewLib.sol "$e/";; esac
[ "$v" = one ] && python3 levers/merge.py levers/UARegisterLib.sol levers/UAViewLib.sol "$e/UARegisterLib.sol"
python3 levers/make.py "$v" baseline/smartcontracts/evm/src/ua/UARegistry.sol "$e/UARegistry.sol"
