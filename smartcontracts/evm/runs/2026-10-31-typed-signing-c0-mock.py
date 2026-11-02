#!/usr/bin/env python3
"""typed-signing C0 Step 2: a compile-only size mock of the whole Part C entry list, for the projection.

Runs on a scratch copy of `smartcontracts/evm`, never on the branch (it refuses a tree on a branch): the token side of
C2 (static named entries, `mtxCancelNonce`, the removals), C3 and C4 (the typed direct ops, their Envelope and UA entries,
the typed statement views, `UASig`) and the relay-fee entries of C6. Library bodies are stubs: the libraries' own sizes
are not measured here, only what each entry costs the token (selector, ABI decoder, argument encoders, the call). The
result builds, it does not run.

Not mocked (about zero on the token): `ReceiverFee` / `WrapOrder` / nested cancels (their hashes are in `TradeLib`, the
entries keep their shape), `UACancelNonce` (same parameters), the UASig form of the generic `ua*` entries (`bytes auth`
stays there; each forwards one argument either way).

usage (from the scratch smartcontracts/evm):  python3 -I <this file> <spike|static|full> [l1 l2 l2b l3 bprime noproof ...]
    spike: the branch as it is; static: + C2 and the static ops; full: + C3, C4, the relay fee; then the levers of Step 2b
"""
import re
import subprocess
import sys

E = 'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient'
UASIG = 'IUARegistry.UASig calldata'


def sub(path, old, new, n=1):
    s = open(path).read()
    assert old in s, (path, old)
    open(path, 'w').write(s.replace(old, new) if n == 0 else s.replace(old, new, n))


def resub(path, pat, new, flags=re.S):
    s = open(path).read()
    s2, k = re.subn(pat, new, s, flags=flags)
    assert k, (path, pat)
    open(path, 'w').write(s2)


def between(path, a, b, new):
    s = open(path).read()
    i, j = s.index(a), s.index(b, s.index(a))
    open(path, 'w').write(s[:i] + new + s[j:])


def insert_before(path, marker, text):
    sub(path, marker, text + marker)


def imports(path, line):
    s = open(path).read()
    if line in s:
        return
    m = list(re.finditer(r'^import [^;]*;\n', s, re.M))[-1]
    open(path, 'w').write(s[:m.end()] + line + '\n' + s[m.end():])


def static(op, params, sel, ua=True, name=None):
    """`mtx<op>` (+ `ua<op>`) of a static-shape op, in the spike's pattern."""
    decl = ', '.join(f'{t} {n}' for t, n in params)
    names = ', '.join(n for _, n in params)
    fields = ','.join(f'{t} {n}' for t, n in params)
    st = name or op
    out = f'''
    bytes32 private constant _TH_{op} = keccak256("{st}(address from,{fields},{E})");
    function mtx{op}(MetaTxLib.Envelope calldata e, {decl}, bytes calldata sig) external nonReentrant returns (bytes memory) {{
        return _named(_TH_{op}, {sel}, e, abi.encode({names}), sig);
    }}
'''
    if ua:
        out += f'''
    bytes32 private constant _THU_{op} = keccak256("UA{st}(bytes32 from,{fields},{E})");
    function ua{op}(MetaTxLib.UAEnvelope calldata e, {decl}, {UASIG} auth) external nonReentrant returns (bytes memory) {{
        return _namedUA(_THU_{op}, {sel}, e, abi.encode({names}), auth);
    }}
'''
    return out


def c2():
    """The base, the public tokens, the static confidential ops, the `UASig` in the named `ua*` path."""
    # the general `_named` and its UA twin, `UASig` on the named UA path
    p = 'src/metatx/MetaTxBase.sol'
    sub(p, '''    function _named(bytes32 typehash, bytes4 sel, MetaTxLib.Envelope calldata e, bytes memory args, bytes calldata sig)
        internal virtual returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, abi.encodePacked(sel, args));
''', '''    function _named(bytes32 typehash, bytes4 sel, MetaTxLib.Envelope calldata e, bytes memory args, bytes calldata sig)
        internal returns (bytes memory)
    {
        return _namedCall(typehash, e, args, abi.encodePacked(sel, args), sig);
    }

    function _namedCall(bytes32 typehash, MetaTxLib.Envelope calldata e, bytes memory args, bytes memory call, bytes calldata sig)
        internal virtual returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, call);
''')
    insert_before(p, '    // ------------------------------------------------------------------ pipeline (CTR-MTX-17)',
                  static('CancelNonce', [('uint256', 'lane')], 'IMetaTx.cancelNonce.selector', ua=False))
    # the removals (TS-D14, controller call), the flat `uaUnwrap` replaced by the twin
    resub(p, r'    /// @notice EIP-1776 alias of `mtxExecute`.*?\n    }\n\n    /// @notice Atomic', '    /// @notice Atomic')
    resub('src/metatx/IMetaTx.sol', r'    function executeMetaTransaction\(.*?returns \(bool success\);\n', '')
    p = 'src/metatx/MetaTokenBase.sol'
    resub(p, r'    /// @notice `mtxExecute` that says "this intent pays a fee".*?\n    }\n\n', '')
    resub(p, r'    /// @notice `uaExecute\(UAMetaTransaction\{from, unwrap.*?return _uaExecute\(m, auth\);\n    }\n\n', '')
    resub('src/metatx/IMetaTokenV2.sol', r'    function uaUnwrap\(.*?returns \(bytes memory\);\n', '')
    s = open('src/metatx/IMetaTokenV2.sol').read()
    if 'mtxExecuteWithFee' in s:
        resub('src/metatx/IMetaTokenV2.sol', r'    function mtxExecuteWithFee\(.*?;\n', '')
    p = 'src/metatx/ERC20MetaTx.sol'
    sub(p, '''    function _named(bytes32 typehash, bytes4 sel, MetaTxLib.Envelope calldata e, bytes memory args, bytes calldata sig)
        internal override returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, abi.encodePacked(sel, args));
''', '''    function _namedCall(bytes32 typehash, MetaTxLib.Envelope calldata e, bytes memory args, bytes memory call, bytes calldata sig)
        internal override returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, call);
''')
    sub(p, '''    function _namedUA(bytes32 typehash, bytes4 sel, MetaTxLib.UAEnvelope calldata e, bytes memory args, bytes calldata auth)
        internal returns (bytes memory)
    {
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(e.from, abi.encodePacked(sel, args), e.batch,
''', f'''    function _namedUA(bytes32 typehash, bytes4 sel, MetaTxLib.UAEnvelope calldata e, bytes memory args, {UASIG} auth)
        internal returns (bytes memory)
    {{
        return _namedCallUA(typehash, e, args, abi.encodePacked(sel, args), auth);
    }}

    function _namedCallUA(bytes32 typehash, MetaTxLib.UAEnvelope calldata e, bytes memory args, bytes memory call, {UASIG} auth)
        internal returns (bytes memory)
    {{
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(e.from, call, e.batch,
''')
    sub(p, '''        return _uaSettle(m, MtxPipelineLib.preNamed(
            _mtxCtx(), typehash, _uaEnvelopeOf(m, 0), args, _callFacts(m.data, true), true, auth));
''', '''        return _uaSettle(m, MtxPipelineLib.preNamedUA(
            _mtxCtx(), typehash, _uaEnvelopeOf(m, 0), args, _callFacts(m.data, true), auth));
''')
    # uaCancelNonce on `UASig`: the shim leaves the token
    sub(p, 'function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes calldata auth) external nonReentrant {',
        f'function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, {UASIG} auth) external nonReentrant {{')
    sub(p, 'requireAuthorized(ua, UAKinds.PURPOSE_METATX_CANCEL, d, UAKinds.uaSig(ua, auth)); // R1 → C2',
        'requireAuthorized(ua, UAKinds.PURPOSE_METATX_CANCEL, d, auth);')
    sub('src/metatx/IUALedger.sol', 'function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes calldata auth)',
        f'function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, {UASIG} auth)')
    imports('src/metatx/IUALedger.sol', 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    insert_before('src/metatx/MtxPipelineLib.sol', '    // ------------------------------------------------------------------ internal (one source per rule)',
                  f'''    function preNamedUA(Ctx calldata c, bytes32 typehash, Envelope calldata e, bytes calldata args, CallFacts calldata f,
        {UASIG} auth) external returns (Out memory o) {{}}

''')
    # C6: the relay-fee path, as `mtxPay` on its own lane
    insert_before('src/metatx/MetaTokenBase.sol', '    /// @notice Payment `payId` on its own lane', f'''    function mtxRelayFee(address from, address target, bytes32 callDataHash, address payee, uint256 value, uint256 validUntil,
        bytes calldata sig) external nonReentrant returns (bool)
    {{
        bytes32 ref = keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, callDataHash));
        MetaTxLib.MetaTransfer memory t;
        (t.from, t.to, t.value, t.entryRef, t.batch, t.validUntil, t.relayer) =
            (from, payee, value, ref, payLane(ref), validUntil, msg.sender);
        t.mode = 1;
        _executeTransfer(t, sig);
        return true;
    }}

    function uaRelayFee(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value, uint256 validUntil,
        bytes calldata auth) external nonReentrant returns (bool)
    {{
        bytes32 ref = keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, callDataHash));
        MetaTxLib.UAMetaTransfer memory t;
        (t.from, t.to, t.value, t.entryRef, t.batch, t.validUntil, t.relayer) =
            (from, payee, value, ref, payLane(ref), validUntil, msg.sender);
        t.mode = 1;
        _uaExecuteTransfer(t, auth);
        return true;
    }}

''')
    # the public kinds
    insert_before('src/metatx/NormalToken.sol', '    /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.',
                  static('Burn', [('uint256', 'amount')], 'NormalToken.burn.selector'))
    imports('src/metatx/NormalToken.sol', 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    imports('src/metatx/NormalToken.sol', 'import {MetaTxLib} from "../common/MetaTxLib.sol";')
    p = 'src/metatx/WrappedToken.sol'
    imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    sub(p, 'SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE', 'SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE')  # anchor check
    text = ''.join([
        static('Wrap', [('uint256', 'amount')], 'SEL_WRAP', ua=False),
        static('WrapLeg', [('address', 'underlying_'), ('uint256', 'amount')], 'SEL_WRAP_LEG', ua=False),
        static('UnwrapLeg', [('address', 'underlying_'), ('uint256', 'wrapped'), ('address', 'recipient'), ('uint256', 'minOut')], 'SEL_UNWRAP_LEG'),
        static('AddReserve', [('address', 'underlying_'), ('uint256', 'amount')], 'SEL_ADD_RESERVE', ua=False),
        static('WrapToUA', [('address', 'underlying_'), ('uint256', 'amount'), ('bytes32', 'to')], 'SEL_WRAP_TO_UA', ua=False),
        static('UnwrapToUA', [('address', 'underlying_'), ('uint256', 'wrapped'), ('bytes32', 'to'), ('uint256', 'minOut')], 'SEL_UNWRAP_TO_UA'),
    ])
    text += f'''
    bytes32 private constant _THU_Unwrap = keccak256("UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,{E})");
    function uaUnwrap(MetaTxLib.UAEnvelope calldata e, uint256 wrapped, address recipient, uint256 minOut, {UASIG} auth)
        external nonReentrant returns (bytes memory)
    {{
        return _namedUA(_THU_Unwrap, SEL_UNWRAP_MIN, e, abi.encode(wrapped, recipient, minOut), auth);
    }}

'''
    insert_before(p, '    /// @notice Signature wrap of a SCaaS underlying (CTR-TOK-20)', text)
    # `mtxWrap(amount)` beside `mtxWrap(u, order, sig)`: the C6 rename is `mtxWrapOrder`
    sub(p, 'function mtxWrap(address u, TradeOrder calldata o, bytes calldata sig)', 'function mtxWrapOrder(address u, TradeOrder calldata o, bytes calldata sig)')
    resub('src/metatx/IWrappedToken.sol', r'function mtxWrap\(address', 'function mtxWrapOrder(address')
    # the shield twin on `UASig`
    for p in ('src/pqz/PqzLayer.sol', 'src/zether/ZetherLayer.sol'):
        imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')
        sub(p, 'function uaShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, bytes calldata auth)',
            f'function uaShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, {UASIG} auth)')
    # the static confidential ops; their direct ops get a selector constant (overloaded now)
    sels = {'mtxRollOver': 'mtxRollOver(bytes32,uint256)', 'mtxPrepareAcc': 'mtxPrepareAcc(bytes32,uint256)',
            'mtxWrapShield': 'mtxWrapShield(address,uint256,bytes32)'}
    consts = ''.join(f'    bytes4 internal constant SEL_{k} = bytes4(keccak256("{v}"));\n' for k, v in sels.items())
    sub('src/common/MetaTxLib.sol', '    uint32 internal constant MODE_OPEN ', consts + '    uint32 internal constant MODE_OPEN ')
    for p in ('src/pqz/PqzLayer.sol', 'src/zether/ZetherLayer.sol', 'src/pqz/NormalPqzToken.sol', 'src/zether/NormalZetherToken.sol',
              'src/pqz/WrappedPqzToken.sol', 'src/zether/WrappedZetherToken.sol'):
        s = open(p).read()
        s = re.sub(r'this\.(mtxRollOver|mtxPrepareAcc|mtxWrapShield)\.selector', r'MetaTxLib.SEL_\1', s)
        open(p, 'w').write(s)
    roll = static('RollOver', [('bytes32', 'ua'), ('uint256', 'n')], 'MetaTxLib.SEL_mtxRollOver')
    insert_before('src/pqz/PqzLayer.sol', '    // ------------------------------------------------------------------ internals', roll +
                  static('PrepareAcc', [('bytes32', 'ua'), ('uint256', 'half')], 'MetaTxLib.SEL_mtxPrepareAcc'))
    insert_before('src/zether/ZetherLayer.sol', '    // ------------------------------------------------------------------ internals', roll)
    ws = static('WrapShield', [('address', 'underlying'), ('uint256', 'amountIn'), ('bytes32', 'toUA')], 'MetaTxLib.SEL_mtxWrapShield', ua=False)
    insert_before('src/pqz/WrappedPqzToken.sol', '    // ------------------------------------------------------------------ the layer\'s hooks', ws)
    insert_before('src/zether/WrappedZetherToken.sol', '    // ------------------------------------------------------------------ the layer\'s hooks', ws)


# ---------------------------------------------------------------------------- C4 / C3: the typed confidential forms

PQZ_STRUCTS = '''
    struct PqzTransferArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 toUA; bytes32 beneficiaryUA;
        bytes16 salt; bytes u; bytes vTo; bytes vFrom; bytes vAuditor; bytes sealedMemo; }
    struct PqzLeg { bytes32 ua; bytes v; bytes vAuditor; }
    struct PqzMultiArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 beneficiaryUA; uint256 decoyFee;
        bytes16 salt; bytes[] u; PqzLeg[] legs; bytes vFrom; bytes sealedMemo; }
    struct PqzBurnArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; bytes32 beneficiaryUA; bytes u; bytes vFrom; }
    struct Payout { uint256 amount; bytes32 recipient; }
'''

ZETHER_STRUCTS = '''
    struct G1 { bytes32 x0; bytes32 x1; bytes32 y0; bytes32 y1; }
    struct ZetherSingle { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes16 salt; bytes32 beneficiaryUA;
        G1 yFrom; G1 yTo; G1 cOut; G1 dOut; G1 cDeb; G1 cAud; }
    struct ZetherLeg { G1 yTo; G1 cOut; G1 cAud; G1 dAud; }
    struct ZetherMulti { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes16 salt; bytes32 beneficiaryUA; uint256 decoyFee;
        G1 yFrom; G1 dOut; G1 cDeb; ZetherLeg[] legs; bytes sealedMemo; }
    struct ZetherBurn { uint64 accSeq; uint64 sendCounter; uint256 validUntilBlock; bytes32 beneficiaryUA; G1 yFrom; }
'''


def typed_shared():
    """The typed direct ops leave the shared interfaces (Appendix X.3); their selectors become constants."""
    p = 'src/confidential/IConfidentialToken.sol'
    for f in ('mtxConfidentialTransfer', 'mtxConfidentialTransferCompact', 'mtxConfidentialTransferSingle', 'mtxUnshield'):
        resub(p, r'    /// @notice [^\n]*(?:\n    ///[^\n]*)*\n    function ' + f + r'\(.*?\) external[^;]*;\n', '')
    resub(p, r'function mtxUnshieldUnwrap\(.*?\) external[^;]*;\n', 'function mtxShieldUnused() external;\n')
    sub(p, 'function mtxShieldUnused() external;\n', '')
    resub('src/pqz/IPqzToken.sol', r'    /// @notice Single-recipient, commit-reveal on every token\.\n    function mtxConfidentialTransferSingleCompact\(.*?\) external returns \(bytes32 entryRef\);\n', PQZ_STRUCTS)
    imports('src/pqz/IPqzToken.sol', 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    sels = ['mtxConfidentialTransfer', 'mtxConfidentialTransferCompact', 'mtxConfidentialTransferSingle',
            'mtxConfidentialTransferSingleCompact', 'mtxUnshield', 'mtxUnshieldUnwrap', 'mtxRollOverBatch',
            'mtxRollOverSigned', 'mtxSetRollOverMode']
    consts = ''.join(f'    bytes4 internal constant SEL_{k} = bytes4(keccak256("{k}(typed)"));\n' for k in sels)
    sub('src/common/MetaTxLib.sol', '    uint32 internal constant MODE_OPEN ', consts + '    uint32 internal constant MODE_OPEN ')
    for p in ('src/pqz/PqzLayer.sol', 'src/zether/ZetherLayer.sol', 'src/pqz/NormalPqzToken.sol', 'src/zether/NormalZetherToken.sol',
              'src/pqz/WrappedPqzToken.sol', 'src/zether/WrappedZetherToken.sol'):
        s = open(p).read()
        s = re.sub(r'this\.(' + '|'.join(sels) + r')\.selector', r'MetaTxLib.SEL_\1', s)
        open(p, 'w').write(s)


def pqz():
    p = 'src/pqz/PqzLayer.sol'
    s = open(p).read()
    new = '''    bytes32 private constant _PQZ_MULTI = keccak256("PqzTransfer(...)");
    bytes32 private constant _PQZ_MULTI_C = keccak256("PqzTransferCompact(...)");
    bytes32 private constant _PQZ_SINGLE = keccak256("PqzTransferSingle(...)");
    bytes32 private constant _PQZ_SINGLE_C = keccak256("PqzTransferSingleCompact(...)");
    bytes32 private constant _PQZ_BURN = keccak256("PqzUnshield(...)");
    bytes32 private constant _UAPQZ_MULTI = keccak256("UAPqzTransfer(...)");
    bytes32 private constant _UAPQZ_MULTI_C = keccak256("UAPqzTransferCompact(...)");
    bytes32 private constant _UAPQZ_SINGLE = keccak256("UAPqzTransferSingle(...)");
    bytes32 private constant _UAPQZ_SINGLE_C = keccak256("UAPqzTransferSingleCompact(...)");
    bytes32 private constant _UAPQZ_BURN = keccak256("UAPqzUnshield(...)");

'''
    for name, mode, typ, multi in (
        ('mtxConfidentialTransfer', '_defaultMode()', 'PqzMultiArgs', True),
        ('mtxConfidentialTransferCompact', 'ZetherTypes.TransferMode.HASH', 'PqzMultiArgs', True),
        ('mtxConfidentialTransferSingle', '_defaultMode()', 'PqzTransferArgs', False),
        ('mtxConfidentialTransferSingleCompact', 'ZetherTypes.TransferMode.HASH', 'PqzTransferArgs', False),
    ):
        fn = '_multiT' if multi else '_singleT'
        cl = '_callMulti' if multi else '_callSingle'
        ar = '_argsMulti' if multi else '_argsSingle'
        th = {'mtxConfidentialTransfer': 'MULTI', 'mtxConfidentialTransferCompact': 'MULTI_C',
              'mtxConfidentialTransferSingle': 'SINGLE', 'mtxConfidentialTransferSingleCompact': 'SINGLE_C'}[name]
        ua = 'ua' + name[3:]
        new += f'''    function {name}({typ} calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        external nonReentrant returns (bytes32)
    {{
        return {fn}(_envTransfer({mode}), t, proof, pqzAuth, accHint);
    }}

    function {name}(MetaTxLib.Envelope calldata e, {typ} calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint,
        bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_PQZ_{th}, e, {ar}(t, proof, accHint), {cl}(MetaTxLib.SEL_{name}, t, proof, pqzAuth, accHint), sig);
    }}

    function {ua}(MetaTxLib.UAEnvelope calldata e, {typ} calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint,
        {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAPQZ_{th}, e, {ar}(t, proof, accHint), {cl}(MetaTxLib.SEL_{name}, t, proof, pqzAuth, accHint), auth);
    }}

'''
    new += f'''    function _argsSingle(PqzTransferArgs calldata t, bytes calldata proof, bytes calldata accHint) private pure returns (bytes memory) {{
        return abi.encode(PqzArgsLib.hashSingle(t), keccak256(proof), keccak256(accHint));
    }}

    function _argsMulti(PqzMultiArgs calldata t, bytes calldata proof, bytes calldata accHint) private pure returns (bytes memory) {{
        return abi.encode(PqzArgsLib.hashMulti(t), keccak256(proof), keccak256(accHint));
    }}

    function _callSingle(bytes4 s, PqzTransferArgs calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encodeWithSelector(s, t, proof, pqzAuth, accHint);
    }}

    function _callMulti(bytes4 s, PqzMultiArgs calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encodeWithSelector(s, t, proof, pqzAuth, accHint);
    }}

    function _singleT(PqzCore.Env memory e, PqzTransferArgs calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private returns (bytes32 r)
    {{
        _pullShieldInT(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transferT(e, t, accHint, proof, pqzAuth);
        _fromPool(f.ben, f.fee - f.legs * f.decoyFee);
    }}

    function _multiT(PqzCore.Env memory e, PqzMultiArgs calldata t, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private returns (bytes32 r)
    {{
        _pullShieldInT(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transferMultiT(e, t, accHint, proof, pqzAuth);
        _fromPool(f.ben, f.fee - f.legs * f.decoyFee);
        if (f.decoyFee != 0) for (uint256 j; j < f.legs; ++j) _fromPool(t.legs[j].ua, f.decoyFee);
    }}

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    function mtxUnshield(PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes calldata proof, {UASIG} pqzAuth,
        bytes calldata accHint) external nonReentrant
    {{
        if (!UAKinds.inNativeSpace(recipient)) _requireDerivedReceiver(recipient);
        _burnT(_envBurn(amount, recipient), b, proof, pqzAuth, accHint);
        _fromPool(recipient, amount);
    }}

    /// @dev Appendix X.3's flat `amount, recipient` does not fit the legacy code generator's stack here: one calldata
    ///      struct, as `Unwrap` (the signed struct keeps both fields).
    function mtxUnshield(MetaTxLib.Envelope calldata e, PqzBurnArgs calldata b, Payout calldata x, bytes calldata proof,
        {UASIG} pqzAuth, bytes calldata accHint, bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_PQZ_BURN, e, _argsBurn(b, x, proof, accHint), _callBurn(b, x, proof, pqzAuth, accHint), sig);
    }}

    function uaUnshield(MetaTxLib.UAEnvelope calldata e, PqzBurnArgs calldata b, Payout calldata x, bytes calldata proof,
        {UASIG} pqzAuth, bytes calldata accHint, {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAPQZ_BURN, e, _argsBurn(b, x, proof, accHint), _callBurn(b, x, proof, pqzAuth, accHint), auth);
    }}

    function _argsBurn(PqzBurnArgs calldata b, Payout calldata x, bytes calldata proof, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encode(PqzArgsLib.hashBurn(b), x.amount, x.recipient, keccak256(proof), keccak256(accHint));
    }}

    function _callBurn(PqzBurnArgs calldata b, Payout calldata x, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshield, b, x.amount, x.recipient, proof, pqzAuth, accHint);
    }}

    /// @dev The burn / refresh debit (also `mtxUnshieldUnwrap`'s).
    function _burnT(PqzCore.Env memory e, PqzBurnArgs calldata b, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint) internal {{
        _pullShieldInT(b.shieldIn);
        PqzCore.Paid memory f = PqzBurnLib.unshieldT(e, b, accHint, proof, pqzAuth);
        _fromPool(f.ben, f.fee - f.legs * f.decoyFee);
    }}

    function _pullShieldInT(uint256 units) internal {{
        PqzCore.PqzStorage storage s = PqzCore.$();
        uint256 room = s.maxShielded - s.totalShielded;
        if (units > room) revert AmountOutOfRange(units, room);
        _toPool(units);
    }}

'''
    a = s.index('    /// @notice The multi-recipient transfer, op 7 `R_TXM`')
    b = s.index('    // ------------------------------------------------------------------ rollover (§7.6, plan 5h D8)')
    s = s[:a] + new + s[b:]
    open(p, 'w').write(s)
    # the old payload helpers go
    resub(p, r'    /// @dev C2-5 \(owner 2026-10-27, controller proposal\).*?    function _envBurn', '    function _envBurn')
    # the statement views on the same structs (Appendix X row 22)
    resub(p, r'    function transferStatement\(bytes calldata payload, bytes32 binding\).*?PqzViewLib\.statementOf\(7, _envOf\(binding\), payload\);',
          '    function transferStatement(PqzMultiArgs calldata t, bytes32 binding) external view returns (bytes memory) {\n'
          '        return PqzViewLib.statementOfMulti(_envOf(binding), t);')
    resub(p, r'    function transferSingleStatement\(bytes calldata payload, bytes32 binding\).*?PqzViewLib\.statementOf\(1, _envOf\(binding\), payload\);',
          '    function transferSingleStatement(PqzTransferArgs calldata t, bytes32 binding) external view returns (bytes memory) {\n'
          '        return PqzViewLib.statementOfSingle(_envOf(binding), t);')
    resub(p, r'function burnStatement\(bytes calldata payload, uint256 amount,', 'function burnStatement(PqzBurnArgs calldata b, uint256 amount,')
    sub(p, 'return PqzViewLib.statementOf(2, e, payload);', 'return PqzViewLib.statementOfBurn(e, b);')
    imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    imports(p, 'import {PqzArgsLib} from "./PqzArgsLib.sol";')
    open('src/pqz/PqzArgsLib.sol', 'w').write('''// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqzToken} from "./IPqzToken.sol";

library PqzArgsLib {
    function hashSingle(IPqzToken.PqzTransferArgs calldata t) public pure returns (bytes32) {}
    function hashMulti(IPqzToken.PqzMultiArgs calldata t) public pure returns (bytes32) {}
    function hashBurn(IPqzToken.PqzBurnArgs calldata t) public pure returns (bytes32) {}
}
''')
    # the library stubs
    insert_before('src/pqz/PqzTransferLib.sol', '    /// @notice One-recipient transfer:', f'''    function transferT(PqzCore.Env memory e, IPqzToken.PqzTransferArgs calldata t, bytes calldata hint, bytes calldata proof,
        {UASIG} authSig) public returns (bytes32 ref, PqzCore.Paid memory paid) {{}}

    function transferMultiT(PqzCore.Env memory e, IPqzToken.PqzMultiArgs calldata t, bytes calldata hint, bytes calldata proof,
        {UASIG} authSig) public returns (bytes32 ref, PqzCore.Paid memory paid) {{}}

''')
    imports('src/pqz/PqzTransferLib.sol', 'import {IPqzToken} from "./IPqzToken.sol";')
    imports('src/pqz/PqzTransferLib.sol', 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    insert_before('src/pqz/PqzBurnLib.sol', '    /// @notice `R_BURN`:', f'''    function unshieldT(PqzCore.Env memory e, IPqzToken.PqzBurnArgs calldata b, bytes calldata hint, bytes calldata proof,
        {UASIG} authSig) public returns (PqzCore.Paid memory paid) {{}}

''')
    imports('src/pqz/PqzBurnLib.sol', 'import {IPqzToken} from "./IPqzToken.sol";')
    imports('src/pqz/PqzBurnLib.sol', 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    s = open('src/pqz/PqzViewLib.sol').read()
    i = s.index('library PqzViewLib {') + len('library PqzViewLib {\n')
    s = s[:i] + '''    function statementOfMulti(PqzCore.Env memory e, IPqzToken.PqzMultiArgs calldata t) public view returns (bytes memory) {}
    function statementOfSingle(PqzCore.Env memory e, IPqzToken.PqzTransferArgs calldata t) public view returns (bytes memory) {}
    function statementOfBurn(PqzCore.Env memory e, IPqzToken.PqzBurnArgs calldata b) public view returns (bytes memory) {}

''' + s[i:]
    open('src/pqz/PqzViewLib.sol', 'w').write(s)
    imports('src/pqz/PqzViewLib.sol', 'import {IPqzToken} from "./IPqzToken.sol";')
    # the wrapped kind
    p = 'src/pqz/WrappedPqzToken.sol'
    between(p, '    function mtxUnshieldUnwrap(bytes calldata payload,', '    /// @notice The `envelopeBinding` word of a direct `mtxUnshieldUnwrap`', f'''    function mtxUnshieldUnwrap(PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        external nonReentrant
    {{
        _burnT(_envUnwrap(x, _ticketBinding()), b, proof, pqzAuth, accHint);
        uint256 wrapped = x.amount * PqzCore.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped);
        WrappedLib.payOutTo(WrappedLib.indexOf(x.underlying), x.recipient, wrapped, x.minOut);
    }}

    bytes32 private constant _PQZ_UNWRAP = keccak256("PqzUnshieldUnwrap(...)");
    bytes32 private constant _UAPQZ_UNWRAP = keccak256("UAPqzUnshieldUnwrap(...)");

    function mtxUnshieldUnwrap(MetaTxLib.Envelope calldata e, PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        {UASIG} pqzAuth, bytes calldata accHint, bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_PQZ_UNWRAP, e, _argsUnwrap(b, x, proof, accHint), _callUnwrap(b, x, proof, pqzAuth, accHint), sig);
    }}

    function uaUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof,
        {UASIG} pqzAuth, bytes calldata accHint, {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAPQZ_UNWRAP, e, _argsUnwrap(b, x, proof, accHint), _callUnwrap(b, x, proof, pqzAuth, accHint), auth);
    }}

    function _argsUnwrap(PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encode(PqzArgsLib.hashBurn(b), keccak256(abi.encode(x)), keccak256(proof), keccak256(accHint));
    }}

    function _callUnwrap(PqzBurnArgs calldata b, Unwrap calldata x, bytes calldata proof, {UASIG} pqzAuth, bytes calldata accHint)
        private pure returns (bytes memory)
    {{
        return abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshieldUnwrap, b, x, proof, pqzAuth, accHint);
    }}

''')
    sub(p, '''    function unshieldUnwrapStatement(bytes calldata payload, Unwrap calldata x, bytes32 binding)''',
        '''    function unshieldUnwrapStatement(PqzBurnArgs calldata b, Unwrap calldata x, bytes32 binding)''')
    sub(p, 'return PqzViewLib.statementOf(2, _envUnwrap(x, binding), payload);', 'return PqzViewLib.statementOfBurn(_envUnwrap(x, binding), b);')
    imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    imports(p, 'import {PqzArgsLib} from "./PqzArgsLib.sol";')


def zether():
    resub('src/zether/IZetherToken.sol', r'(interface IZetherToken is [^{]*\{\n)', lambda m: m.group(1) + ZETHER_STRUCTS)
    resub('src/zether/IZetherToken.sol', r'    function mtxRollOverSigned\(.*?;\n', '')
    s = open('src/zether/IZetherToken.sol').read()
    if 'function mtxSetRollOverMode' in s:
        resub('src/zether/IZetherToken.sol', r'    function mtxSetRollOverMode\(.*?;\n', '')
    p = 'src/zether/ZetherLayer.sol'
    s = open(p).read()
    new = '''    bytes32 private constant _Z_MULTI = keccak256("ZetherTransfer(...)");
    bytes32 private constant _Z_MULTI_C = keccak256("ZetherTransferCompact(...)");
    bytes32 private constant _Z_SINGLE = keccak256("ZetherTransferSingle(...)");
    bytes32 private constant _Z_BURN = keccak256("ZetherUnshield(...)");
    bytes32 private constant _UAZ_MULTI = keccak256("UAZetherTransfer(...)");
    bytes32 private constant _UAZ_MULTI_C = keccak256("UAZetherTransferCompact(...)");
    bytes32 private constant _UAZ_SINGLE = keccak256("UAZetherTransferSingle(...)");
    bytes32 private constant _UAZ_BURN = keccak256("UAZetherUnshield(...)");

'''
    for name, mode, th in (('mtxConfidentialTransfer', 'ZetherLib.defaultMode()', 'MULTI'),
                           ('mtxConfidentialTransferCompact', 'ZetherTypes.TransferMode.HASH', 'MULTI_C')):
        ua = 'ua' + name[3:]
        new += f'''    function {name}(ZetherMulti calldata t, bytes calldata proof) external nonReentrant returns (bytes32) {{
        return _multiT(t, proof, {mode});
    }}

    function {name}(MetaTxLib.Envelope calldata e, ZetherMulti calldata t, bytes calldata proof, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_{th}, e, abi.encode(ZetherArgsLib.hashMulti(t), keccak256(proof)), abi.encodeWithSelector(MetaTxLib.SEL_{name}, t, proof), sig);
    }}

    function {ua}(MetaTxLib.UAEnvelope calldata e, ZetherMulti calldata t, bytes calldata proof, {UASIG} auth)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_{th}, e, abi.encode(ZetherArgsLib.hashMulti(t), keccak256(proof)), abi.encodeWithSelector(MetaTxLib.SEL_{name}, t, proof), auth);
    }}

'''
    new += f'''    function mtxConfidentialTransferSingle(ZetherSingle calldata t, bytes calldata proof) external nonReentrant returns (bytes32) {{
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(t.beneficiaryUA);
        (bytes32 ref, uint256 fee) = ZetherLib.transferSingleT(t, proof, ben, _env());
        _fromPool(ben, fee);
        return ref;
    }}

    function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, ZetherSingle calldata t, bytes calldata proof, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_SINGLE, e, abi.encode(ZetherArgsLib.hashSingle(t), keccak256(proof)), abi.encodeWithSelector(MetaTxLib.SEL_mtxConfidentialTransferSingle, t, proof), sig);
    }}

    function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, ZetherSingle calldata t, bytes calldata proof, {UASIG} auth)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_SINGLE, e, abi.encode(ZetherArgsLib.hashSingle(t), keccak256(proof)), abi.encodeWithSelector(MetaTxLib.SEL_mtxConfidentialTransferSingle, t, proof), auth);
    }}

    // ------------------------------------------------------------------ unshield

    function mtxUnshield(ZetherBurn calldata b, uint256 amount, bytes32 recipient, bytes calldata proof) external nonReentrant {{
        _requireRecipient(recipient);
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(b.beneficiaryUA);
        uint256 fee = ZetherLib.unshieldT(b, proof, ben, amount, recipient, _env());
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), recipient, amount * ZetherLib.$().shieldScale);
        _fromPool(ben, fee);
    }}

    function mtxUnshield(MetaTxLib.Envelope calldata e, ZetherBurn calldata b, uint256 amount, bytes32 recipient, bytes calldata proof,
        bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_BURN, e, abi.encode(ZetherArgsLib.hashBurn(b), amount, recipient, keccak256(proof)),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshield, b, amount, recipient, proof), sig);
    }}

    function uaUnshield(MetaTxLib.UAEnvelope calldata e, ZetherBurn calldata b, uint256 amount, bytes32 recipient, bytes calldata proof,
        {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_BURN, e, abi.encode(ZetherArgsLib.hashBurn(b), amount, recipient, keccak256(proof)),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshield, b, amount, recipient, proof), auth);
    }}

'''
    a = s.index('    /// @notice The token\'s default: the record stored (`BUNDLE` token)')
    b = s.index('    // ------------------------------------------------------------------ roll-over (all four allowlisted')
    s = s[:a] + new + s[b:]
    # the roll-over owner ops
    a = s.index('    function mtxRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {')
    b = s.index('    // ------------------------------------------------------------------ internals')
    roll_marker = s.index('    bytes32 private constant _TH_RollOver')
    tail_static = s[roll_marker:b]
    s = s[:a] + f'''    bytes32 private constant _Z_RB = keccak256("RollOverBatch(...)");
    bytes32 private constant _Z_RS = keccak256("RollOverSigned(...)");
    bytes32 private constant _Z_SM = keccak256("SetRollOverMode(...)");
    bytes32 private constant _UAZ_RB = keccak256("UARollOverBatch(...)");
    bytes32 private constant _UAZ_RS = keccak256("UARollOverSigned(...)");
    bytes32 private constant _UAZ_SM = keccak256("UASetRollOverMode(...)");

    function mtxRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {{
        ZetherLib.rollOverBatch(uas);
    }}

    function mtxRollOverBatch(MetaTxLib.Envelope calldata e, ZetherTypes.UA[] calldata uas, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_RB, e, abi.encode(keccak256(abi.encodePacked(uas))), abi.encodeWithSelector(MetaTxLib.SEL_mtxRollOverBatch, uas), sig);
    }}

    function uaRollOverBatch(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA[] calldata uas, {UASIG} auth)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_RB, e, abi.encode(keccak256(abi.encodePacked(uas))), abi.encodeWithSelector(MetaTxLib.SEL_mtxRollOverBatch, uas), auth);
    }}

    function mtxRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, {UASIG} ownerSig)
        external nonReentrant
    {{
        ZetherLib.rollOverSignedT(ua, expectedPendingSeq, validUntilBlock, ownerSig, _env());
    }}

    function mtxRollOverSigned(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock,
        {UASIG} ownerSig, bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_RS, e, abi.encode(ua, expectedPendingSeq, validUntilBlock),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxRollOverSigned, ua, expectedPendingSeq, validUntilBlock, ownerSig), sig);
    }}

    function uaRollOverSigned(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock,
        {UASIG} ownerSig, {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_RS, e, abi.encode(ua, expectedPendingSeq, validUntilBlock),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxRollOverSigned, ua, expectedPendingSeq, validUntilBlock, ownerSig), auth);
    }}

    function mtxSetRollOverMode(ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock, {UASIG} ownerSig)
        external nonReentrant
    {{
        ZetherLib.setRollOverModeT(ua, mode, validUntilBlock, ownerSig, _env());
    }}

    function mtxSetRollOverMode(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock,
        {UASIG} ownerSig, bytes calldata sig) external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_SM, e, abi.encode(ua, mode, validUntilBlock),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxSetRollOverMode, ua, mode, validUntilBlock, ownerSig), sig);
    }}

    function uaSetRollOverMode(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock,
        {UASIG} ownerSig, {UASIG} auth) external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_SM, e, abi.encode(ua, mode, validUntilBlock),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxSetRollOverMode, ua, mode, validUntilBlock, ownerSig), auth);
    }}

''' + tail_static + s[b:]
    s = re.sub(r'    /// @dev The shared signature\'s `auth` and `accHint` are PQZ\'s.*?(    /// @dev A fee the library took out)',
               r'''    function _multiT(ZetherMulti calldata t, bytes calldata proof, ZetherTypes.TransferMode mode) private returns (bytes32 ref) {
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(t.beneficiaryUA);
        ZetherLib.Paid memory f;
        (ref, f) = ZetherLib.transferMultiT(t, proof, ben, mode, _env());
        _fromPool(ben, f.txFee);
        if (f.decoyFee != 0) for (uint256 j; j < f.legs.length; ++j) _fromPool(f.legs[j], f.decoyFee);
    }

\1''', s, flags=re.S)
    open(p, 'w').write(s)
    imports(p, 'import {ZetherArgsLib} from "./ZetherArgsLib.sol";')
    open('src/zether/ZetherArgsLib.sol', 'w').write('''// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IZetherToken} from "./IZetherToken.sol";

library ZetherArgsLib {
    function hashSingle(IZetherToken.ZetherSingle calldata t) public pure returns (bytes32) {}
    function hashMulti(IZetherToken.ZetherMulti calldata t) public pure returns (bytes32) {}
    function hashBurn(IZetherToken.ZetherBurn calldata t) public pure returns (bytes32) {}
}
''')
    p = 'src/zether/ZetherLib.sol'
    insert_before(p, '    function transferSingle(bytes calldata payload,', f'''    function transferSingleT(IZetherToken.ZetherSingle calldata t, bytes calldata proof, ZetherTypes.UA beneficiary, Env memory e)
        public returns (bytes32, uint256) {{}}

    function transferMultiT(IZetherToken.ZetherMulti calldata t, bytes calldata proof, ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode, Env memory e) public returns (bytes32, Paid memory) {{}}

    function unshieldT(IZetherToken.ZetherBurn calldata b, bytes calldata proof, ZetherTypes.UA beneficiary, uint256 amount,
        bytes32 recipient, Env memory e) public returns (uint256) {{}}

    function rollOverSignedT(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, {UASIG} sig, Env memory e) public {{}}

    function setRollOverModeT(ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock, {UASIG} sig, Env memory e) public {{}}

''')
    imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')
    p = 'src/zether/WrappedZetherToken.sol'
    between(p, '    /// @notice The unshield proof (`x.amount` and `x.recipient` in the statement;', '    /// @notice As `WrappedToken` (also cancels a pending rate change', f'''    function mtxUnshieldUnwrap(ZetherBurn calldata b, Unwrap calldata x, bytes calldata proof) external nonReentrant {{
        ZetherTypes.UA beneficiary = ZetherTypes.UA.wrap(b.beneficiaryUA);
        uint256 i = WrappedLib.indexOf(x.underlying);
        if (UAKinds.inNativeSpace(x.recipient)) _requirePayee(address(uint160(uint256(x.recipient))));
        ZetherLib.Env memory env = _envUnwrap(x.underlying, x.minOut);
        uint256 fee = ZetherLib.unshieldT(b, proof, beneficiary, x.amount, x.recipient, env);
        uint256 wrapped = x.amount * ZetherLib.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped); // D19: burn from the pool
        _fromPool(beneficiary, fee);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut);
    }}

    bytes32 private constant _Z_UNWRAP = keccak256("ZetherUnshieldUnwrap(...)");
    bytes32 private constant _UAZ_UNWRAP = keccak256("UAZetherUnshieldUnwrap(...)");

    function mtxUnshieldUnwrap(MetaTxLib.Envelope calldata e, ZetherBurn calldata b, Unwrap calldata x, bytes calldata proof, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCall(_Z_UNWRAP, e, abi.encode(ZetherArgsLib.hashBurn(b), keccak256(abi.encode(x)), keccak256(proof)),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshieldUnwrap, b, x, proof), sig);
    }}

    function uaUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, ZetherBurn calldata b, Unwrap calldata x, bytes calldata proof, {UASIG} auth)
        external nonReentrant returns (bytes memory)
    {{
        return _namedCallUA(_UAZ_UNWRAP, e, abi.encode(ZetherArgsLib.hashBurn(b), keccak256(abi.encode(x)), keccak256(proof)),
            abi.encodeWithSelector(MetaTxLib.SEL_mtxUnshieldUnwrap, b, x, proof), auth);
    }}

''')
    imports(p, 'import {ZetherArgsLib} from "./ZetherArgsLib.sol";')
    imports(p, 'import {IUARegistry} from "../ua/IUARegistry.sol";')


# ---------------------------------------------------------------------------- the levers of Step 2b (each alone)

def delete_fn(path, pattern):
    """Delete every function whose header matches `pattern`, its doc comment and its body (or `;` in an interface)."""
    s = open(path).read()
    hit = 0
    while True:
        m = re.search(r'^[ \t]*function ' + pattern, s, re.M)
        if not m:
            break
        lines = s[:m.start()].split('\n')
        while len(lines) > 1 and lines[-2].lstrip().startswith('///'):
            lines.pop(-2)
        start = len('\n'.join(lines))
        j = m.end()
        while s[j] not in '{;':
            j += 1
        if s[j] == ';':
            end = j + 1
        else:
            depth = 0
            while True:
                depth += {'{': 1, '}': -1}.get(s[j], 0)
                j += 1
                if depth == 0:
                    break
            end = j
        s = s[:start] + s[end + (s[end:end + 1] == '\n'):]
        hit += 1
    open(path, 'w').write(s)
    return hit


def lever2():
    """2: the modifier's body in one shared private function pair."""
    between('src/metatx/MetaTxBase.sol', '    modifier nonReentrant() {', '    // ------------------------------------------------------------------ views', '''    modifier nonReentrant() {
        bool outer = _enter();
        _;
        _exit(outer);
    }

    function _enter() private returns (bool outer) {
        outer = _tload(_GUARD) == 0;
        if (outer) {
            _tstore(_GUARD, 1);
        } else {
            if (msg.sender != address(this) || _tload(_TICKET) != 1) revert Reentrancy();
            _tstore(_TICKET, 2);
        }
    }

    function _exit(bool outer) private {
        if (outer) _tstore(_GUARD, 0);
    }

''')


def lever2b():
    """2 (variant): a static entry hands its arguments as the calldata slice they already are, no `abi.encode`."""
    def rep(m):
        return f'e, msg.data[260:{260 + 32 * (m.group(1).count(",") + 1)}]'
    for p in ('src/metatx/MetaTxBase.sol', 'src/metatx/NormalToken.sol', 'src/metatx/WrappedToken.sol', 'src/pqz/PqzLayer.sol',
              'src/zether/ZetherLayer.sol', 'src/pqz/WrappedPqzToken.sol', 'src/zether/WrappedZetherToken.sol', 'src/wallet/MandateWallet.sol'):
        s = open(p).read()
        s = re.sub(r'\be,\s*abi\.encode\(([^()]*)\)(?=, (?:sig|auth)\))', rep, s)
        open(p, 'w').write(s)


def lever1():
    """1: hot-path-free code behind external libraries on `WrappedPqzToken`, same selectors: the init path (the raw
    `initArgs` to the library, no `TokenConfig` coder in the token), the selector table."""
    sub('src/pqz/PqzStateLib.sol', '    function init(IFactoryToken.ConfidentialConfig memory c,', '''    function initWrapped(bytes calldata a, address registry, address verifier) public {
        IFactoryToken.TokenConfig memory cfg = abi.decode(a, (IFactoryToken.TokenConfig));
        if (cfg.initialSupply != 0 || cfg.initialHolder != address(0)) revert IFactoryToken.ConfigFieldForOtherKind(1);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_PQZ);
        init(cfg.conf, registry, verifier);
    }

    function init(IFactoryToken.ConfidentialConfig memory c,''')
    imports('src/pqz/PqzStateLib.sol', 'import {WrappedLib} from "../metatx/WrappedLib.sol";')
    imports('src/pqz/PqzStateLib.sol', 'import {AdminLib} from "../metatx/AdminLib.sol";')
    sub('src/metatx/MetaTokenBase.sol', '        _init(abi.decode(initArgs, (TokenConfig)));', '        _initRaw(initArgs);')
    sub('src/metatx/MetaTokenBase.sol', '    function underlyings() public view virtual returns', '''    function _initRaw(bytes calldata initArgs) internal virtual {
        _init(abi.decode(initArgs, (TokenConfig)));
    }

    function underlyings() public view virtual returns''')
    p = 'src/pqz/WrappedPqzToken.sol'
    between(p, '    function _init(TokenConfig memory cfg) internal override(WrappedToken, MetaTokenBase) {',
            '    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap', '''    function _init(TokenConfig memory) internal override(WrappedToken, MetaTokenBase) {}

    function _initRaw(bytes calldata a) internal override {
        PqzStateLib.initWrapped(a, _REGISTRY, PQZ_VERIFIER);
    }

''')
    s = open(p).read()
    m = re.search(r'        s = new bytes4\[\]\(18\);.*?\(s\[17\], c\[17\]\) = [^\n]*\n', s, re.S)
    body = m.group(0)
    open(p, 'w').write(s[:m.start()] + '        return PqzViewLib.wrappedSelectors();\n' + s[m.end():])
    sig = {'this.cancelNonce.selector': 'cancelNonce(uint256)', 'SEL_WRAP_TO_UA': 'wrapToUA(address,uint256,bytes32)',
           'SEL_UNWRAP_TO_UA': 'unwrapToUA(address,uint256,bytes32,uint256)', 'SEL_WRAP_LEG': 'wrap(address,uint256)',
           'SEL_UNWRAP_LEG': 'unwrap(address,uint256,address,uint256)', 'SEL_ADD_RESERVE': 'addReserve(address,uint256)',
           'SEL_UNWRAP_MIN': 'unwrap(uint256,address,uint256)', 'SEL_WRAP': 'wrap(uint256)'}
    for k in sorted(sig, key=len, reverse=True):
        body = re.sub(r'(?<![\w.])' + re.escape(k) + r'\b', f'bytes4(keccak256("{sig[k]}"))', body)
    body = body.replace('FEE_CLASS_ABSOLUTE', '1').replace('FEE_CLASS_AMOUNT', '2')
    fn = {'mtxConfidentialTransfer': '(bytes,bytes,bytes,bytes32,bytes)', 'mtxConfidentialTransferCompact': '(bytes,bytes,bytes,bytes32,bytes)',
          'mtxConfidentialTransferSingle': '(bytes,bytes,bytes,bytes32,bytes)', 'mtxConfidentialTransferSingleCompact': '(bytes,bytes,bytes,bytes32,bytes)',
          'mtxUnshield': '(bytes,bytes,bytes,bytes32,bytes,uint256,bytes32)', 'mtxWrapShield': '(address,uint256,bytes32)',
          'mtxUnshieldUnwrap': '(bytes,bytes,bytes,bytes32,bytes,(address,bytes32,uint256,uint256))',
          'mtxRollOver': '(bytes32,uint256)', 'mtxPrepareAcc': '(bytes32,uint256)'}
    body = re.sub(r'this\.(\w+)\.selector', lambda x: f'bytes4(keccak256("{x.group(1)}{fn[x.group(1)]}"))', body)
    q = 'src/pqz/PqzViewLib.sol'
    s = open(q).read()
    i = s.index('library PqzViewLib {') + len('library PqzViewLib {\n')
    open(q, 'w').write(s[:i] + '    function wrappedSelectors() public pure returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {\n' + body + '    }\n\n' + s[i:])
    imports(q, 'import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";')
    imports(q, 'import {MetaTxLib} from "../common/MetaTxLib.sol";')
    # the same on `WrappedZetherToken`, for the projection
    sub('src/zether/ZetherLib.sol', '    function init(', """    function initWrapped(bytes calldata a, IZetherVerifier v) public {
        IFactoryToken.TokenConfig memory cfg = abi.decode(a, (IFactoryToken.TokenConfig));
        if (cfg.initialSupply != 0 || cfg.initialHolder != address(0)) revert IFactoryToken.ConfigFieldForOtherKind(1);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_ZETHER);
        init(cfg.conf, v);
    }

    function init(""")
    imports('src/zether/ZetherLib.sol', 'import {WrappedLib} from "../metatx/WrappedLib.sol";')
    imports('src/zether/ZetherLib.sol', 'import {AdminLib} from "../metatx/AdminLib.sol";')
    p = 'src/zether/WrappedZetherToken.sol'
    between(p, '    function _init(TokenConfig memory cfg) internal override(WrappedToken, MetaTokenBase) {',
            '    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap', """    function _init(TokenConfig memory) internal override(WrappedToken, MetaTokenBase) {}

    function _initRaw(bytes calldata a) internal override {
        ZetherLib.initWrapped(a, TRANSFER_VERIFIER);
    }

""")
    s = open(p).read()
    m = re.search(r'        s = new bytes4\[\]\(19\);.*?\(s\[18\], c\[18\]\) = [^\n]*\n', s, re.S)
    body = m.group(0)
    open(p, 'w').write(s[:m.start()] + '        return ZetherLib.wrappedSelectors();\n' + s[m.end():])
    for k in sorted(sig, key=len, reverse=True):
        body = re.sub(r'(?<![\w.])' + re.escape(k) + r'\b', f'bytes4(keccak256("{sig[k]}"))', body)
    body = body.replace('FEE_CLASS_ABSOLUTE', '1').replace('FEE_CLASS_AMOUNT', '2')
    fn.update({'mtxRollOverBatch': '(bytes32[])', 'mtxRollOverSigned': '(bytes32,uint64,uint64,bytes)', 'mtxSetRollOverMode': '(bytes32,uint8,uint64,bytes)'})
    body = re.sub(r'this\.(\w+)\.selector', lambda x: f'bytes4(keccak256("{x.group(1)}{fn[x.group(1)]}"))', body)
    q = 'src/zether/ZetherLib.sol'
    sub(q, '    function initWrapped(', '    function wrappedSelectors() public pure returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {\n' + body + '    }\n\n    function initWrapped(')
    imports(q, 'import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";')
    imports(q, 'import {MetaTxLib} from "../common/MetaTxLib.sol";')


VIEWS = {
    'src/metatx/ERC20MetaTx.sol': ['mtxTransferDigest', 'uaDigest', 'uaTransferDigest'],
    'src/metatx/IERC20MetaTx.sol': ['mtxTransferDigest'],
    'src/metatx/IUALedger.sol': ['uaDigest', 'uaTransferDigest'],
    'src/metatx/MetaTokenBase.sol': ['factory', 'implementation', 'creator', 'version', 'pendingOwner', 'hasRole'],
    'src/metatx/IMetaTokenV2.sol': ['factory', 'implementation', 'creator', 'version', 'pendingOwner', 'hasRole'],
    'src/metatx/ITokenAdmin.sol': ['pendingOwner', 'hasRole'],
    'src/metatx/WrappedToken.sol': ['underlying', 'legOf', 'collateralValue', 'previewWrap', 'previewUnwrap', 'rateAdjustable', 'rateDelay',
                                    'maxRateStepBps', 'pendingRate', 'mtxSelectors'],
    'src/metatx/IWrappedToken.sol': ['underlying', 'legOf', 'collateralValue', 'previewWrap', 'previewUnwrap', 'rateAdjustable', 'rateDelay',
                                     'maxRateStepBps', 'pendingRate'],
    'src/metatx/NormalToken.sol': ['mtxSelectors'],
    'src/pqz/PqzLayer.sol': ['verifier', 'precompile', 'proofSystemId', 'maxShielded', 'confidentialFee', 'minDecoyFee', 'auditorUA', 'auditorMode',
                             'disclosureMode', 'totalShielded', 'pqzAccount', 'pqzPending', 'pqzAcc', 'pqzPendingCt', 'pqzEntryBlob',
                             'transferCiphertextHash', 'transferEntry', 'transferStatement', 'transferSingleStatement', 'burnStatement',
                             'disclosureStatement', 'verifyTransferAmount', 'envelopeBinding', 'uaEnvelopeBinding'],
    'src/pqz/IPqzToken.sol': ['pqzAccount', 'pqzPending', 'pqzAcc', 'pqzPendingCt', 'pqzEntryBlob'],
    'src/pqz/WrappedPqzToken.sol': ['unshieldUnwrapStatement', 'mtxSelectors'],
    'src/pqz/NormalPqzToken.sol': ['mtxSelectors'],
    'src/zether/ZetherLayer.sol': ['curve', 'totalShielded', 'transferMemo', 'sendCounter', 'registered', 'envelopeBinding', 'uaEnvelopeBinding'],
    'src/zether/IZetherToken.sol': ['curve', 'totalShielded', 'transferMemo', 'sendCounter', 'registered', 'envelopeBinding', 'uaEnvelopeBinding'],
    'src/zether/WrappedZetherToken.sol': ['mtxSelectors'],
    'src/zether/NormalZetherToken.sol': ['mtxSelectors'],
}

FALLBACK = '''
    /// the release's stateless module; a real one comes through `env.deps`
    address internal immutable _MODULE = address(0x10);

    fallback() external payable {
        address m = _MODULE;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), m, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
'''


def lever3():
    """3: the read-only surface behind the token's `fallback`, a stateless module of the release; the selectors stay on
    the token's address. Size only: the views are deleted and the fallback added, the module is not written. Views other
    contracts read on chain stay (DEX, factory, `ZetherStatements`, `ZetherDisclosure`). `mtxDigest` and the base's
    `mtxSelectors` stay (the wallets share them)."""
    for p, names in VIEWS.items():
        for n in names:
            delete_fn(p, n + r'\(')
    sub('src/metatx/MetaTokenBase.sol', 'abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, ITokenAdmin {\n',
        'abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, ITokenAdmin {\n' + FALLBACK)


def bprime(proof_only):
    """B' (TS-D18, open question 4): the confidential named entries behind the wrapped kinds' `fallback`; `proof_only`:
    instead of a module, no envelope entries for the ops whose authority is the proof or an inner signature (shield and
    wrap-shield keep theirs)."""
    conf = ['mtxConfidentialTransfer', 'mtxConfidentialTransferCompact', 'mtxConfidentialTransferSingle',
            'mtxConfidentialTransferSingleCompact', 'mtxUnshield', 'mtxUnshieldUnwrap', 'mtxRollOver', 'mtxRollOverBatch',
            'mtxRollOverSigned', 'mtxSetRollOverMode', 'mtxPrepareAcc']
    if not proof_only:
        conf += ['mtxShield', 'mtxWrapShield']
    for p in ('src/pqz/PqzLayer.sol', 'src/zether/ZetherLayer.sol', 'src/pqz/WrappedPqzToken.sol', 'src/zether/WrappedZetherToken.sol'):
        for c in conf:
            delete_fn(p, c + r'\(MetaTxLib\.Envelope')
            delete_fn(p, 'ua' + c[3:] + r'\(')
    if proof_only or 'fallback()' in open('src/metatx/MetaTokenBase.sol').read():
        return
    for p, c in (('src/pqz/WrappedPqzToken.sol', 'WrappedPqzToken is WrappedToken, PqzLayer, IConfidentialWrappedToken'),
                 ('src/zether/WrappedZetherToken.sol', 'WrappedZetherToken is WrappedToken, ZetherLayer, IConfidentialWrappedToken')):
        sub(p, f'contract {c} {{\n', f'contract {c} {{\n' + FALLBACK)


def main(argv):
    branch = subprocess.run(['git', 'symbolic-ref', '-q', 'HEAD'], capture_output=True, text=True).stdout.strip()
    if branch:
        sys.exit(f'refused: {branch} is a branch; this mock runs on a detached scratch copy only')
    base = argv[1] if len(argv) > 1 else 'full'
    if base in ('static', 'full'):
        c2()
    if base == 'full':
        typed_shared()
        pqz()
        zether()
    for l in argv[2:]:
        {'l1': lever1, 'l2': lever2, 'l2b': lever2b, 'l3': lever3, 'bprime': lambda: bprime(False), 'noproof': lambda: bprime(True)}[l]()


if __name__ == '__main__':
    main(sys.argv)
