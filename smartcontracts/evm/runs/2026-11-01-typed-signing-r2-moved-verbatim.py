#!/usr/bin/env python3
"""typed-signing R2: is `UARegistryLib` the frozen pre-split code? Comments dropped, `IUARegistry.` / `UAStore.` prefixes and the
library's renames undone, statement by statement: prints each statement of the library that is not in the frozen source.
  python3 -I runs/2026-11-01-typed-signing-r2-moved-verbatim.py"""
import re

def norm(t):
    t = re.sub(r'^\s*///.*\n', '', t, flags=re.M)
    t = re.sub(r'\s+//[^"\n]*$', '', t, flags=re.M)
    t = t.replace('IUARegistry.', '').replace('UAStore.', '')
    t = re.sub(r'\bs\.(records|keyOwner|pqzKey|ekPtr|uaCount|uaAt|regPqzKey|regPqzPopHash|reg|pqzPopHash|pqzPop|pqzKeySig|kem|kemMax|kemCommit)\[',
               lambda m: '_' + m[1] + '[', t)
    t = re.sub(r'\b(word|u16|cut|vkLength|isPq|checked|registration|keyRest|kemAt|expanded|capped)\(', lambda m: '_' + m[1] + '(', t)
    t = t.replace('        Layout storage s = layout();\n', '')
    for a, b in (('_cfgKind()', '_cfg(kind)'), ('_cfgPqz()', '_cfg(UAKinds.PQZ_MLWE)'), ('_pred()', 'predecessor'), ('_kindOf(', 'kindOf('),
                 ('_keyOwner(', 'keyOwner('), ('IUARegistry(address(this)).hederaNative()', 'hederaNative'),
                 ('IUARegistry(address(this)).verifyBudget()', 'verifyBudget')):
        t = t.replace(a, b)
    return re.sub(r'\s+', ' ', t).replace('{ ', '{\n').replace('; ', ';\n').replace('} ', '}\n').splitlines()

old = set(norm(open('legacy/typed-signing/UARegistryPreSplit.sol').read()))
lib = norm(open('src/ua/UARegistryLib.sol').read())
new = [l for l in lib if l not in old]
print(f'{len(lib)} statements, {len(new)} not in the frozen source:')
for l in new:
    print(' ', l[:170])
