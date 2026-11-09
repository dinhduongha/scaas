# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b 3.1b research harness (kept): one registry view moved into a library behind `_libView`, measured one move at a time.
# usage: movev.py <view> <Lib>   move one registry view's body into <Lib> (UARegistryLib or UARegistryKeyLib), behind `_libView`
import re, sys
name, lib = sys.argv[1], sys.argv[2]
R='src/ua/UARegistry.sol'; r=open(R).read()
i=r.index('    function '+name+'(')
s=i
while r.rfind('\n',0,s-1)>=0 and r[r.rfind('\n',0,s-1)+1:s].startswith('    ///'): s=r.rfind('\n',0,s-1)+1
j=r.index('\n    }\n',i)+len('\n    }\n')
fn=r[s:j]
hdr_end=fn.index('{\n', fn.index('function '))
header, body = fn[:hdr_end], fn[hdr_end:]
STRUCTS=['Record','MuSig2Key','FrostKey','FrostMember','WebAuthnKey','UAAttrs','KemKey','MsigStructure','MsigMember','UASig','MemberSig']
def q(t):
    for st in STRUCTS: t=re.sub(r'(?<![\w.])'+st+r'\b','IUARegistry.'+st,t)
    return t
lh=q(header).replace(' external view returns',' external returns').replace(' public view returns',' external returns')
lh=re.sub(r'(\n\s*)view(\n\s*returns)', r'\1\2', lh).replace('        external\n        \n        returns','        external\n        returns')
lb=q(body)
lb=lb.replace('_s.','UAStore.layout().')
lb=re.sub(r'(?<![\w.])_elsewhere\(','UARegistryLib._elsewhere(',lb)
lb=re.sub(r'(?<![\w.])_listedHere\(kind\)','UARegistryLib._listedHere()',lb)
lb=re.sub(r'IUARegistry\(predecessor\)','IUARegistry(UARegistryLib._pred())',lb)
lb=re.sub(r'(?<![\w.])predecessor\b','UARegistryLib._pred()',lb)
lb=re.sub(r'revert (UAIndex|UANotIndexed)\(',r'revert IUARegistry.\1(',lb)
L=open(f'src/ua/{lib}.sol').read()
pre = 'UARegistryLib.' if lib!='UARegistryLib' else ''
if lib=='UARegistryLib': lb=lb.replace('UARegistryLib.','')
k = 'kind' if re.search(r'\buint16 kind\b', header) else '0'
L=L.rstrip()[:-1].rstrip()+'\n\n    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----\n\n'+lh+lb+'}\n'
open(f'src/ua/{lib}.sol','w').write(L)
stub=header+'{\n        _libView(address('+lib+'), '+lib+'.'+name+'.selector, '+k+');\n    }\n'
r=r[:s]+stub+r[j:]
open(R,'w').write(r)
print('moved',name,'->',lib)
