# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b 3.1b research harness (kept): the split of UARegistryLib into two libraries by domain, measured per variant
# (the library names of the run: UARegistryLib / the second library; renamed UARegistryCoreLib / UARegistryAuxLib after).
# usage: split2.py <SecondLib> <moved names...>   (from smartcontracts/evm; starts from HEAD's UARegistryLib / UARegistry)
import re, subprocess, sys
lib2, names = sys.argv[1], sys.argv[2:]
head = lambda f: subprocess.run(['git','show','HEAD:smartcontracts/evm/'+f],capture_output=True,text=True,check=True).stdout
L = head('src/ua/UARegistryLib.sol').split('\n')
def find(prefix):
    for i in range(len(L)):
        if L[i].startswith(prefix): return i
    raise SystemExit('no '+prefix)
def block(n):
    i=find('    function '+n+'('); s=i
    while L[s-1].startswith('    ///'): s-=1
    e=i
    while L[e]!='    }': e+=1
    return s,e
SECT={'cacheExpandedKey':'ML-DSA expanded-key cache (P6c; owner 2026-10-12)',
      'storePqzPop':'the PQZ proof later (UA8-D8, P8) and the PQZ key versions later (ruling A1-I1; group 3g)',
      'setKemKey':'KEM records (P4, P5, P7; UA8-D3–D5, D11, D12)','acceptMembership':'acceptance (CTR-UA-37)'}
blocks=[block(n) for n in names]
moved=[]
for n,(s,e) in zip(names,blocks):
    t='\n'.join(L[s:e+1])
    if n in SECT: t='    // ----- '+SECT[n]+' -----\n\n'+t
    moved.append(t)
keep=set(range(len(L)))
for s,e in blocks:
    for k in range(s,e+1): keep.discard(k)
    if L[e+1]=='': keep.discard(e+1)
src='\n'.join(L[i] for i in range(len(L)) if i in keep)
for n,h in SECT.items():
    if n in names:
        src=src.replace('    // ----- '+h+' -----\n\n','')
src=re.sub(r'\) private( view| pure)?(\s*\{| returns| \n)', lambda m: ') internal'+(m.group(1) or '')+m.group(2), src)
src=src.replace(') private\n',') internal\n')
open('src/ua/UARegistryLib.sol','w').write(src)
own={n for n in names if n.startswith('_')}
body='\n\n'.join(moved)
for h in sorted(set(re.findall(r'\b(_\w+)\(', body))-own):
    body=re.sub(r'(?<![\w.])'+h+r'\(', 'UARegistryLib.'+h+'(', body)
body=re.sub(r'(?<![\w.])(EMPTY_PROOF_HASH|TX_GAS_CAP)\b', r'UARegistryLib.\1', body)
hdr=open(sys.argv[0].replace('split2.py','lib2-head.sol')).read().replace('LIBNAME',lib2)
open(f'src/ua/{lib2}.sol','w').write(hdr+body+'\n}\n')
r=head('src/ua/UARegistry.sol')
r=r.replace('import {UARegistryLib} from "./UARegistryLib.sol";','import {UARegistryLib} from "./UARegistryLib.sol";\nimport {'+lib2+'} from "./'+lib2+'.sol";')
r=r.replace('''    function _lib(bytes4 sel, uint16 kind) private {
        address lib = address(UARegistryLib);
''','''    function _lib(address lib, bytes4 sel, uint16 kind) private {
''')
for sel in ['register','registerWebAuthn','registerMuSig2','registerFrost','registerMsig','cacheExpandedKey','storePqzPop','setPqzKey','setKemKey','acceptMembership']:
    a=f'_lib(UARegistryLib.{sel}.selector,'; assert r.count(a)==1,a
    L2 = lib2 if sel in names else 'UARegistryLib'
    r=r.replace(a, f'_lib(address({L2}), {L2}.{sel}.selector,')
r=r.replace('else _libView(UARegistryLib.requirePortable.selector,','else _libView(address(UARegistryLib), UARegistryLib.requirePortable.selector,')
a='''    function _libView(bytes4 sel, uint16 kind) private view {
        function(bytes4, uint16) f = _lib;
        function(bytes4, uint16) view v;
        assembly {
            v := f
        }
        v(sel, kind);'''
assert r.count(a)==1
r=r.replace(a,'''    function _libView(address lib, bytes4 sel, uint16 kind) private view {
        function(address, bytes4, uint16) f = _lib;
        function(address, bytes4, uint16) view v;
        assembly {
            v := f
        }
        v(lib, sel, kind);''')
a='        if (address(UARegistryLib).code.length == 0) revert UAConfig(0);'; assert r.count(a)==1
r=r.replace(a,'        if (address(UARegistryLib).code.length == 0 || address('+lib2+').code.length == 0) revert UAConfig(0);')
open('src/ua/UARegistry.sol','w').write(r)
print('moved', names)
