#!/usr/bin/env python3
"""Builds a variant's src/ua/UARegistry.sol from the baseline source. usage: make.py <r1|r2|r1r2|one|store> <in> <out>
store = the storage struct and helper moves alone (no lever)."""
import re, sys

def fn_span(src, name):
    m = re.search(r'^    function ' + re.escape(name) + r'\(', src, re.M)
    if not m: raise SystemExit('no function ' + name)
    start = m.start()
    # the doc comment above
    while True:
        p = src.rfind('\n', 0, start - 1) + 1
        if src[p:start].lstrip().startswith('///'):
            start = p
        else:
            break
    i = src.index('{', m.end())
    semi = src.find(';', m.end())
    depth, j = 0, i
    while True:
        c = src[j]
        depth += (c == '{') - (c == '}')
        if depth == 0: break
        j += 1
    end = j + 1
    while src[end] == '\n': end += 1
    return start, end

def drop(src, *names):
    for n in names:
        a, b = fn_span(src, n)
        src = src[:a] + src[b:]
    return src

def sub(src, name, text):
    a, b = fn_span(src, name)
    return src[:a] + text + '\n\n' + src[b:]

def thin(src, name, body):
    """`name` with its baseline header (parameter and return names stay in the JSON ABI), body replaced."""
    a, b = fn_span(src, name)
    m = re.search(r'^    function ' + re.escape(name) + r'\(', src, re.M)
    h = ' '.join(src[m.start():src.index('{', m.end())].split())
    return src[:a] + f'    {h} {{ {body} }}\n\n' + src[b:]

mode, inp, out = sys.argv[1:4]
FORM = sys.argv[4] if len(sys.argv) > 4 else 'raw'  # raw = the forwarding stub; high = a high-level library call (decode + encode)

def form(src, name, raw):
    if FORM == 'raw':
        return raw
    m = re.search(r'^    function ' + re.escape(name) + r'\((.*?)\)', src, re.M | re.S)
    args = [a.split()[-1] for a in m.group(1).split(',') if a.strip()]
    return f'return UAViewLib.{name}({", ".join(args)});'
src = open(inp).read()
R1 = mode in ('r1', 'r1r2', 'one')
R2 = mode in ('r2', 'r1r2', 'one')

# ----- the storage struct and shared helpers: every variant -----
a = src.index('    mapping(bytes32 ua => Record) private _records;')
b = src.index('    /// @param chainUid_ the chain')
src = src[:a] + '    UAStore.Layout private _s; // slot 0: the baseline\'s mappings, same order, same slots\n\n' + src[b:]
for old, new in [('_records', 'records'), ('_keyOwner', 'keyOwner'), ('_pqzKey', 'pqzKey'), ('_ekPtr', 'ekPtr'),
                 ('_uaCount', 'uaCount'), ('_uaAt', 'uaAt'), ('_regPqzKey', 'regPqzKey'), ('_regPqzPopHash', 'regPqzPopHash'),
                 ('_reg', 'reg'), ('_pqzPopHash', 'pqzPopHash'), ('_pqzPop', 'pqzPop'), ('_pqzKeySig', 'pqzKeySig'),
                 ('_kem', 'kem'), ('_kemMax', 'kemMax'), ('_kemCommit', 'kemCommit')]:
    src = re.sub(r'(?<![\w.])' + old + r'\[', '_s.' + new + '[', src)
src = re.sub(r'\bKemCommit memory\b', 'UAStore.KemCommit memory', src)
src = re.sub(r'\bKemCommit\(', 'UAStore.KemCommit(', src)
src = re.sub(r'\bPqzKey memory\b', 'UAStore.PqzKey memory', src)
src = re.sub(r'(?<![\w.])PqzKey\(SSTORE2', 'UAStore.PqzKey(SSTORE2', src)
src = drop(src, '_word', '_u16', '_cut', '_vkLength', '_isPq', '_checked', '_registration', '_keyRest', '_kemAt',
           '_expanded', '_capped')
for old, new in [('_word', 'word'), ('_u16', 'u16'), ('_cut', 'cut'), ('_vkLength', 'vkLength'), ('_isPq', 'isPq'),
                 ('_checked', 'checked'), ('_registration', 'registration'), ('_keyRest', 'keyRest'), ('_kemAt', 'kemAt'),
                 ('_expanded', 'expanded'), ('_capped', 'capped')]:
    src = re.sub(r'(?<![\w.])' + old + r'\(', 'UAStore.' + new + '(', src)
src = src.replace('import {SSTORE2} from "../common/SSTORE2.sol";\n',
                  'import {SSTORE2} from "../common/SSTORE2.sol";\nimport {UAStore} from "./UAStore.sol";\n')

# ----- R1′ -----
if R1:
    fwd = '''    // ----- R1′: the views live in `UAViewLib`; each stub forwards its calldata by DELEGATECALL and returns the raw bytes -----

    function _viewFwd(bytes4 sel) private {
        address lib = address(UAViewLib);
        assembly {
            mstore(0, sel)
            calldatacopy(4, 4, sub(calldatasize(), 4))
            let ok := delegatecall(gas(), lib, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if ok { return(0, returndatasize()) }
            revert(0, returndatasize())
        }
    }

    /// `pure` by a pointer cast: solc refuses DELEGATECALL in a `view` / `pure` function. The EVM keeps a static caller's
    /// static flag through DELEGATECALL, and `UAViewLib` writes nothing.
    function _viewAs(bytes4 sel) private pure {
        function(bytes4) internal f = _viewFwd;
        function(bytes4) internal pure g;
        assembly ("memory-safe") {
            g := f
        }
        g(sel);
    }

    function _view() private pure {
        _viewAs(msg.sig);
    }

'''
    for n in ('uaOf', 'keyHashOf', 'kindName', 'portableRecordDigest', 'registrationDigest', 'pqzKeyDigest', 'pqzKeyRecordDigest',
              'uaMessage', 'recordOf', 'registrationOf', 'popOf', 'msigOf', 'webAuthnKeyOf', 'muSig2KeyOf', 'frostKeyOf',
              'pqzPopOf', 'pqzKeySigOf', 'checkedOf', 'kemKeyOf', 'kemKeyAt', 'keyOf', 'uaCount', 'uaAt', 'uaPage', 'uaIndex',
              'expandedKeyOf'):
        src = thin(src, n, form(src, n, '_view();'))
    src = thin(src, 'kemRecordHash', form(src, 'kemRecordHash', '_viewAs(UAViewLib.kemRecordHash.selector);'))
    src = thin(src, 'kemRecordDigest', form(src, 'kemRecordDigest', '_viewAs(UAViewLib.kemRecordDigest.selector);'))
    src = drop(src, '_listedHere')
    src = src.replace('    // ----- views -----\n', fwd + '    // ----- views -----\n', 1)
    src = src.replace('import {UAStore} from "./UAStore.sol";\n', 'import {UAStore} from "./UAStore.sol";\nimport {UAViewLib} from "./UAViewLib.sol";\n')

# ----- R2 -----
if R2:
    lib = '''    // ----- R2: registration in `UARegisterLib`, by DELEGATECALL; the appended words are its only view of the immutables -----

    function _lib(bytes4 sel, uint16 kind) private {
        address lib = address(UARegisterLib);
        (uint256 a, uint256 b, bytes32 c) = (_cfg(kind), _CFG18, _SMART_KEY_CLONE_CODEHASH);
        assembly {
            mstore(0, sel)
            calldatacopy(4, 4, sub(calldatasize(), 4))
            let e := calldatasize()
            mstore(e, a)
            mstore(add(e, 32), b)
            mstore(add(e, 64), c)
            let ok := delegatecall(gas(), lib, 0, add(e, 96), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if ok { return(0, returndatasize()) }
            revert(0, returndatasize())
        }
    }

'''
    E = {'cacheExpandedKey': 'kind', 'register': 'kind', 'registerWebAuthn': 'UAKinds.WEBAUTHN_P256', 'registerMuSig2': 'kind',
         'registerFrost': 'kind', 'registerMsig': 'UAKinds.MSIG', 'storePqzPop': '0', 'setPqzKey': '_s.records[ua].kind',
         'setKemKey': '_s.records[ua].kind'}
    for n, kind in E.items():
        src = thin(src, n, f'_lib(UARegisterLib.{n}.selector, {kind});')
    src = drop(src, '_ekParts', '_frostMember', '_point', '_register', '_consent', '_record', '_identify', '_claim', '_attrs',
               '_holder', '_pqzHolder', '_pqzKeyHash', '_pqEligible', '_pqzAttach', '_pqzProof', '_registerKeyMessage',
               '_kemHash', '_host', '_portableOk', '_portableBytes', '_pqzKeyFree', '_sigOk', '_membersWorst', '_nativeCap',
               '_sort', '_checkKemPk', '_checkKemScheme', '_list')
    # `_msig`: the portable path left with `_sigOk`
    src = src.replace('''function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, MemberSig[] memory sigs, bool portable)''',
                      '''function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, MemberSig[] memory sigs)''')
    src = src.replace('        if (!portable) digest = 0; // from here: the typed digest a native member signs, on the portable path only\n', '')
    src = src.replace('if (!_memberOk(d, md, digest, s)) return false;', 'if (!_memberOk(d, md, s)) return false;')
    src = src.replace('_msig(ua, purposeTag, digest, UAStore.keyRest(ua), auth.members, false)', '_msig(ua, purposeTag, digest, UAStore.keyRest(ua), auth.members)')
    src = src.replace('function _memberOk(bytes memory d, bytes32 md, bytes32 typed, MemberSig memory s)', 'function _memberOk(bytes memory d, bytes32 md, MemberSig memory s)')
    src = src.replace('        if (typed != 0) return _byCode(address(uint160(uint256(id))), typed, s.sig);\n', '')
    # `_1271` / `_byCode` stay; the moved constants
    src = re.sub(r'    /// @notice EIP-7825 per-transaction gas cap.*?\n    uint256 internal constant TX_GAS_CAP = 1 << 24;\n', '', src, flags=re.S)
    src = re.sub(r'    /// @notice Registration bound for `msig`.*?uint256 internal constant MSIG_MEMBER_GAS = 45_000;\n', '', src, flags=re.S)
    src = re.sub(r'    /// `keccak256\(""\)`: the hash of an empty proof.*?EMPTY_PROOF_HASH = keccak256\(""\);\n', '', src, flags=re.S)
    src = src.replace('    // ----- views -----\n', lib + '    // ----- views -----\n', 1)
    src = src.replace('import {UAStore} from "./UAStore.sol";\n', 'import {UAStore} from "./UAStore.sol";\nimport {UARegisterLib} from "./UARegisterLib.sol";\n')
    src = src.replace('import {IUAKindVerifier, IUAPopVerifier} from "./IUAVerifier.sol";', 'import {IUAKindVerifier} from "./IUAVerifier.sol";')
    src = src.replace('import {PqzSet} from "../pqz/PqzSet.sol";\n', '')

if R1:
    src = drop(src, '_pqzElsewhere', '_hasKem')
if mode == 'one':  # one library: the views in UARegisterLib too
    src = src.replace('import {UAViewLib} from "./UAViewLib.sol";\n', '').replace('UAViewLib', 'UARegisterLib')
open(out, 'w').write(src)
