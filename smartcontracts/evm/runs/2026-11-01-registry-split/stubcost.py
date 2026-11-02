#!/usr/bin/env python3
"""Marginal bytes per stub: on the R1′+R2 registry (libraries replaced by a selector-only dummy), each view's interface line and
stub removed, the registry rebuilt, the size difference. A coder shared with another view stays, so this is the stub's own cost.
usage (from f9/smartcontracts/evm): stubcost.py"""
import json, re, subprocess
E = 'src/ua/'
reg0, itf0 = open(E + 'UARegistry.sol').read(), open(E + 'IUARegistry.sol').read()
open(E + 'UAViewLib.sol', 'w').write('''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IUARegistry} from "./IUARegistry.sol";
library UAViewLib {
    function kemRecordHash(bytes32, uint64, IUARegistry.KemKey calldata) external pure returns (bytes32) {}
    function kemRecordDigest(bytes32, uint64, IUARegistry.KemKey calldata) external pure returns (bytes32) {}
}
''')
open(E + 'UARegisterLib.sol', 'w').write('''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IUARegistry} from "./IUARegistry.sol";
library UARegisterLib {
    function cacheExpandedKey(uint16, bytes calldata, uint256) external {}
    function register(uint16, bytes calldata, IUARegistry.UAAttrs calldata, bytes calldata, bytes calldata) external {}
    function registerWebAuthn(IUARegistry.WebAuthnKey calldata, IUARegistry.UAAttrs calldata, bytes calldata, bytes calldata) external {}
    function registerMuSig2(uint16, IUARegistry.MuSig2Key calldata, IUARegistry.UAAttrs calldata, bytes calldata, bytes calldata) external {}
    function registerFrost(uint16, IUARegistry.FrostKey calldata, IUARegistry.UAAttrs calldata, bytes calldata, bytes calldata) external {}
    function registerMsig(IUARegistry.MsigStructure calldata, IUARegistry.UAAttrs calldata, IUARegistry.MemberSig[] calldata, bytes calldata) external {}
    function storePqzPop(bytes32, bytes calldata) external {}
    function setPqzKey(bytes32, bytes calldata, bytes32, IUARegistry.UASig calldata) external {}
    function setKemKey(bytes32, uint64, IUARegistry.KemKey calldata, IUARegistry.UASig calldata) external {}
}
''')
def size():
    r = subprocess.run(['forge', 'build', 'src/ua/UARegistry.sol', '--no-cache'], capture_output=True, text=True)
    if r.returncode: raise SystemExit(r.stdout[-800:] + r.stderr[-800:])
    return len(json.load(open('out/UARegistry.sol/UARegistry.json'))['deployedBytecode']['object']) // 2 - 1
base = size()
print('base', base)
views = ['uaOf','keyHashOf','kindName','portableRecordDigest','registrationDigest','pqzKeyDigest','pqzKeyRecordDigest','uaMessage','recordOf','registrationOf','popOf','msigOf','webAuthnKeyOf','muSig2KeyOf','frostKeyOf','pqzPopOf','pqzKeySigOf','kemKeyOf','kemKeyAt','keyOf','uaCount','uaAt','uaPage','uaIndex','expandedKeyOf','kemRecordHash','kemRecordDigest']
for v in views:
    itf = re.sub(r'^    function ' + v + r'\(.*?;', '', itf0, count=1, flags=re.M | re.S)
    reg = re.sub(r'^    function ' + v + r'\(.*?\{ _view.*?\}\n', '', reg0, count=1, flags=re.M | re.S)
    assert itf != itf0 and reg != reg0, v
    open(E + 'IUARegistry.sol', 'w').write(itf); open(E + 'UARegistry.sol', 'w').write(reg)
    print(v, base - size(), flush=True)
open(E + 'IUARegistry.sol', 'w').write(itf0); open(E + 'UARegistry.sol', 'w').write(reg0)
