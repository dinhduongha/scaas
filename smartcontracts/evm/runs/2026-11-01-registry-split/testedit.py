#!/usr/bin/env python3
"""R2 variants only: `_sigOk` left UARegistry, so the harness calls the library's internal copy with the kind's cfg word.
usage: testedit.py <evm dir>"""
import sys
p = sys.argv[1] + '/test/ua/UARegistryUA8.t.sol'
s = open(p).read()
a = 'return _sigOk(kind, d, ua, purpose, digest, sig, new IUARegistry.MemberSig[](0));'
b = 'return UARegisterLib._sigOk(uint256(uint160(k0)) | uint256(cap0) << 160, kind, d, ua, purpose, digest, sig,\n            new IUARegistry.MemberSig[](0));'
assert a in s
s = s.replace(a, b)
a = '''        UARegistry(uid, address(0), false, budget, address(0), true, k)
    {}

    function sigOk('''
b = '''        UARegistry(uid, address(0), false, budget, address(0), true, k)
    {
        (k0, cap0) = (k[0].verifier, k[0].cap);
    }

    address internal immutable k0;
    uint64 internal immutable cap0;

    function sigOk('''
assert a in s
s = s.replace(a, b)
a = 'import {UARegistry} from "../../src/ua/UARegistry.sol";\n'
assert a in s
s = s.replace(a, a + 'import {UARegisterLib} from "../../src/ua/UARegisterLib.sol";\n', 1)
open(p, 'w').write(s)
