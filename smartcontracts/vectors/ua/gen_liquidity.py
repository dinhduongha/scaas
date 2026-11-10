#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Liquidity-order vectors (spec docs/superpowers/specs/2026-11-10-dex-liquidity.md §4.2, §4.3, §12) -> `liquidity_kat.json`.

    python3 -I smartcontracts/vectors/ua/gen_liquidity.py [--check]

Every byte is computed here, independently of the contracts: EIP-712 (`hashToken`, `hashArray`, `hashOrder`, the DEX's
salted domain), the ABI (the `mtxLiquidity` calldata, the `mtxLiquidityPull` calldata each SCaaS input token receives, the
`liquidityOrderDigest` calldata of the tokens' capability check T7), and the signer's signature: a native signer's secp256k1
ECDSA over `h` (RFC 6979, low-s), a derived `p256` signer's over `uaMessage(p256, trade, h)` (`famvec.py`). `int24` is
sign-extended to 32 bytes (a negative-tick row). The forge KAT (`smartcontracts/evm/test/liquidity/LiquidityKat.t.sol`), the
node's typed KAT and `clientkeys` read the same rows; `ua-rs` reads them on its own round. `--check` compares the whole
file (drift fails). Rows: `v2_add`, `v2_withdraw`, `v4_mint_negative_tick`, `v4_withdraw_whole`, `v4_withdraw_partial`,
`derived_p256`, `eight_inputs`.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'metatx'))
import famvec as V  # noqa: E402

OUT = os.path.join(V.REPO, 'smartcontracts', 'vectors', 'ua', 'liquidity_kat.json')
CHAIN_ID = 7622                       # scaas-testnet
CHAIN_UID = V.unhx('0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464')   # the forge fixtures' UID_
DEX = V.unhx('0xd1d1000000000000000000000000000000000d1d')
TOKEN_A = V.unhx('0xa0a0000000000000000000000000000000000a0a')   # SCaaS
TOKEN_B = V.unhx('0xb0b0000000000000000000000000000000000b0b')   # SCaaS
LP = V.unhx('0x1b1b0000000000000000000000000000000001b1')       # an outside ERC-20 LP
POSM = V.unhx('0x7070000000000000000000000000000000000707')     # a position manager
READER = V.unhx('0x4e4e0000000000000000000000000000000004e4')   # its reader
RELAYER = V.unhx('0x000000000000000000000000000000000000beef')
RECIPIENT = V.unhx('0x00000000000000000000000000000000000c0ffe')
VALID_UNTIL = 1_800_000_300

LIQUIDITY_TOKEN = 'LiquidityToken(address token,uint256 amount)'
LIQUIDITY_ORDER = ('LiquidityOrder(bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,address positionManager,'
                   'address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,int24 tickUpper,'
                   'uint128 minLiquidity,bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,uint256 nonce,'
                   'uint256 validUntil)')
SALTED_DOMAIN = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)'
DEX_NAME, DEX_VERSION = 'SCaaS Dex', '1'
FIELDS = [('bytes32', 'from'), ('LiquidityToken[]', 'inputs'), ('LiquidityToken[]', 'outputs'),
          ('address', 'positionManager'), ('address', 'positionReader'), ('uint256', 'positionIn'), ('bytes32', 'positionPool'),
          ('int24', 'tickLower'), ('int24', 'tickUpper'), ('uint128', 'minLiquidity'), ('bytes32', 'recipient'),
          ('uint256', 'fee'), ('address', 'relayer'), ('uint8', 'flags'), ('uint256', 'batch'), ('uint256', 'nonce'),
          ('uint256', 'validUntil')]
TOKENS_T = '(address,uint256)[]'
ORDER_T = '(bytes32,' + TOKENS_T + ',' + TOKENS_T + ',address,address,uint256,bytes32,int24,int24,uint128,bytes32,uint256,' \
          'address,uint8,uint256,uint256,uint256)'
UASIG_T = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])'
PLAN_T = '(bytes32,' + ORDER_T + ',' + UASIG_T + ',uint256[],uint256,address[])'
INTERACTIONS_T = '(address,bytes)[]'
PURPOSE_TRADE = V.keccak256(b'scaas.ua.purpose.trade.v1')
MSG_TAG = V.keccak256(b'scaas.ua.msg.v1')
KIND_P256 = 0x0101


# ---------------------------------------------------------------- ABI (the subset the rows use; int types two's complement)
def _split(t):
    assert t.startswith('(') and t.endswith(')'), t
    out, depth, cur = [], 0, ''
    for ch in t[1:-1]:
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
            continue
        depth += ch == '('
        depth -= ch == ')'
        cur += ch
    return out + [cur] if cur else out


def _dynamic(t):
    if t.endswith('[]') or t in ('bytes', 'string'):
        return True
    return t.startswith('(') and any(_dynamic(x) for x in _split(t))


def _u(n):
    return int(n).to_bytes(32, 'big')


def _i(n, bits):
    assert -(2 ** (bits - 1)) <= n < 2 ** (bits - 1)
    return (n % 2 ** 256).to_bytes(32, 'big')


def abi_enc(t, v):
    if t.endswith('[]'):
        return _u(len(v)) + abi_seq([t[:-2]] * len(v), v)
    if t.startswith('('):
        return abi_seq(_split(t), v)
    if t in ('bytes', 'string'):
        b = v.encode() if t == 'string' else v
        return _u(len(b)) + b + bytes(-len(b) % 32)
    if t == 'address':
        assert len(v) == 20
        return bytes(12) + v
    if t.startswith('uint'):
        assert 0 <= v < 2 ** int(t[4:])
        return _u(v)
    if t.startswith('int'):
        return _i(v, int(t[3:]))
    if t.startswith('bytes'):
        assert len(v) == int(t[5:])
        return v + bytes(32 - len(v))
    raise ValueError(t)


def abi_seq(types, vals):
    assert len(types) == len(vals)
    off = 32 * len(types)  # every tuple here is dynamic or one word per static member
    for t in types:
        if not _dynamic(t) and t.startswith('('):
            off += 32 * (len(_split(t)) - 1)
    heads, tails = b'', b''
    for t, v in zip(types, vals):
        if _dynamic(t):
            e = abi_enc(t, v)
            heads += _u(off)
            tails += e
            off += len(e)
        else:
            heads += abi_enc(t, v)
    return heads + tails


def selector(sig):
    return V.keccak256(sig.encode())[:4]


# ---------------------------------------------------------------- EIP-712
def hash_token(t):
    return V.keccak256(V.keccak256(LIQUIDITY_TOKEN.encode()), bytes(12) + t['token'], _u(t['amount']))


def hash_array(ts):
    return V.keccak256(*[hash_token(t) for t in ts]) if ts else V.keccak256(b'')


def hash_order(o):
    words = [V.keccak256((LIQUIDITY_ORDER + LIQUIDITY_TOKEN).encode())]
    for ty, n in FIELDS:
        words.append(hash_array(o[n]) if ty == 'LiquidityToken[]' else abi_enc(ty, o[n]))
    return V.keccak256(*words)


def domain_separator(dex):
    return V.keccak256(V.keccak256(SALTED_DOMAIN.encode()), V.keccak256(DEX_NAME.encode()), V.keccak256(DEX_VERSION.encode()),
                       _u(CHAIN_ID), bytes(12) + dex, CHAIN_UID)


def digest(o, dex=DEX):
    return V.keccak256(b'\x19\x01', domain_separator(dex), hash_order(o))


# ---------------------------------------------------------------- JSON forms
def j_tokens(ts):
    return [{'token': V.hx(t['token']), 'amount': str(t['amount'])} for t in ts]


def j_order(o):
    out = {}
    for ty, n in FIELDS:
        v = o[n]
        if ty == 'LiquidityToken[]':
            out[n] = j_tokens(v)
        elif ty in ('int24', 'uint8'):
            out[n] = v
        elif ty.startswith('uint'):
            out[n] = str(v)
        else:
            out[n] = V.hx(v)
    return out


def typed_data(o):
    return {'domain': {'name': DEX_NAME, 'version': DEX_VERSION, 'chainId': CHAIN_ID, 'verifyingContract': V.hx(DEX),
                       'salt': V.hx(CHAIN_UID)},
            'types': {'EIP712Domain': [{'name': 'name', 'type': 'string'}, {'name': 'version', 'type': 'string'},
                                       {'name': 'chainId', 'type': 'uint256'}, {'name': 'verifyingContract', 'type': 'address'},
                                       {'name': 'salt', 'type': 'bytes32'}],
                      'LiquidityOrder': [{'name': n, 'type': ty} for ty, n in FIELDS],
                      'LiquidityToken': [{'name': 'token', 'type': 'address'}, {'name': 'amount', 'type': 'uint256'}]},
            'primaryType': 'LiquidityOrder', 'message': j_order(o)}


def order_tuple(o):
    return [[[t['token'], t['amount']] for t in o[n]] if ty == 'LiquidityToken[]' else o[n] for ty, n in FIELDS]


# ---------------------------------------------------------------- signers
NATIVE = V.Ecdsa('scaas.liquidity.signer', V.SECP256K1)
NATIVE_ADDR = V.keccak256(NATIVE.key)[12:]
P256 = V.Ecdsa('scaas.liquidity.p256', V.P256)
P256_UA = V.ua_of(KIND_P256, P256.key)


def pad(a):
    return bytes(12) + a


def ua_message(kind_name, purpose, h):
    return V.keccak256(MSG_TAG, V.keccak256(f'scaas.ua.{kind_name}.v1'.encode()), purpose, h)


def auth_for(o, h):
    if o['from'] == pad(NATIVE_ADDR):
        rs, v = NATIVE.sign(h)
        return (b'', rs + bytes([27 + v]), [])
    assert o['from'] == P256_UA
    rs, _ = P256.sign(V.sha256(ua_message('p256', PURPOSE_TRADE, h)))  # the registry's p256: sha256 of the message
    return (P256.key, rs, [])


def base(**kw):
    o = {'from': pad(NATIVE_ADDR), 'inputs': [], 'outputs': [], 'positionManager': bytes(20), 'positionReader': bytes(20),
         'positionIn': 0, 'positionPool': bytes(32), 'tickLower': 0, 'tickUpper': 0, 'minLiquidity': 0,
         'recipient': pad(RECIPIENT), 'fee': 3000, 'relayer': RELAYER, 'flags': 0, 'batch': 7, 'nonce': 0,
         'validUntil': VALID_UNTIL}
    o.update(kw)
    return o


def tk(token, amount):
    return {'token': token, 'amount': amount}


def row(name, o, pull, position_id=0, scaas=(TOKEN_A, TOKEN_B), note=''):
    h = digest(o)
    auth = auth_for(o, h)
    plan = [V.keccak256(('scaas.liquidity.ref.' + name).encode()), order_tuple(o), auth, pull, position_id, []]
    interactions = [[TOKEN_A, selector('transfer(address,uint256)') + abi_seq(['address', 'uint256'], [LP, 1])]]
    liq_sig = f'mtxLiquidity({PLAN_T},{INTERACTIONS_T})'
    pull_sig = f'mtxLiquidityPull({ORDER_T},{UASIG_T},uint256,address)'
    dig_sig = f'liquidityOrderDigest({ORDER_T})'
    pulls = []
    for i, t in enumerate(o['inputs']):
        if t['token'] in scaas:
            pulls.append({'token': V.hx(t['token']), 'amount': str(pull[i]),
                          'calldata': V.hx(selector(pull_sig) + abi_seq([ORDER_T, UASIG_T, 'uint256', 'address'],
                                                                        [order_tuple(o), auth, pull[i], RELAYER]))})
    return {
        'name': name, 'note': note,
        'domain': {'name': DEX_NAME, 'version': DEX_VERSION, 'chainId': CHAIN_ID, 'verifyingContract': V.hx(DEX),
                   'salt': V.hx(CHAIN_UID)},
        'domainSeparator': V.hx(domain_separator(DEX)),
        'typedData': typed_data(o), 'order': j_order(o),
        'hashInputs': [V.hx(hash_token(t)) for t in o['inputs']], 'hashOutputs': [V.hx(hash_token(t)) for t in o['outputs']],
        'hashArrayInputs': V.hx(hash_array(o['inputs'])), 'hashArrayOutputs': V.hx(hash_array(o['outputs'])),
        'hashOrder': V.hx(hash_order(o)), 'h': V.hx(h),
        'signer': V.hx(o['from']),
        'auth': {'keyData': V.hx(auth[0]), 'signature': V.hx(auth[1]), 'members': []},
        'plan': {'ref': V.hx(plan[0]), 'pull': [str(x) for x in pull], 'positionId': str(position_id), 'extraTokens': []},
        'interactions': [{'target': V.hx(t), 'data': V.hx(d)} for t, d in interactions],
        'mtxLiquidityCalldata': V.hx(selector(liq_sig) + abi_seq([PLAN_T, INTERACTIONS_T], [plan, interactions])),
        'mtxLiquidityPull': pulls,
        # the same, flat (readers without JSONPath wildcards over an empty list)
        'pullTokens': [p['token'] for p in pulls], 'pullAmounts': [p['amount'] for p in pulls],
        'pullCalldata': [p['calldata'] for p in pulls],
        'liquidityOrderDigestCalldata': V.hx(selector(dig_sig) + abi_seq([ORDER_T], [order_tuple(o)])),
    }


def build():
    V.selftest_primitives()
    assert selector('transfer(address,uint256)').hex() == 'a9059cbb'
    # the two selectors the contracts pin (ITradeToken.sol, ISCaaSDex.sol; cast sig)
    assert selector(f'mtxLiquidityPull({ORDER_T},{UASIG_T},uint256,address)').hex() == '85fdfd38'
    assert selector(f'liquidityOrderDigest({ORDER_T})').hex() == '436033f5'
    assert _i(-600, 24).hex() == 'f' * 61 + 'da8'
    pool = V.keccak256(b'scaas.liquidity.pool')
    rows = [
        row('v2_add', base(inputs=[tk(TOKEN_A, 100_000), tk(TOKEN_B, 100_000)], outputs=[tk(LP, 98_000)]),
            [100_000, 100_000], note='two SCaaS inputs, one LP output'),
        row('v2_withdraw', base(inputs=[tk(LP, 98_703)], outputs=[tk(TOKEN_A, 90_000), tk(TOKEN_B, 90_000)], recipient=bytes(32),
                                nonce=1), [98_703], note='one outside input, two outputs; recipient 0 = from'),
        row('v4_mint_negative_tick', base(inputs=[tk(TOKEN_A, 50_000), tk(TOKEN_B, 50_000)], positionManager=POSM,
                                          positionReader=READER, positionPool=pool, tickLower=-600, tickUpper=600,
                                          minLiquidity=40_000, nonce=2), [50_000, 50_000], position_id=1,
            note='a received position; tickLower sign-extended'),
        row('v4_withdraw_whole', base(outputs=[tk(TOKEN_A, 39_000), tk(TOKEN_B, 39_000)], positionManager=POSM, positionIn=1,
                                      nonce=3), [], note='empty inputs: keccak256(""); the given position spent whole'),
        row('v4_withdraw_partial', base(outputs=[tk(TOKEN_A, 9_000), tk(TOKEN_B, 9_000)], positionManager=POSM,
                                        positionReader=READER, positionIn=1, positionPool=pool, tickLower=-600, tickUpper=600,
                                        minLiquidity=30_000, nonce=4), [], position_id=1,
            note='a partial withdraw signed as the received position under the given id'),
        row('derived_p256', base(**{'from': P256_UA, 'inputs': [tk(TOKEN_A, 50_000), tk(TOKEN_B, 50_000)],
                                    'outputs': [tk(LP, 48_000)], 'batch': 3}), [50_000, 50_000],
            note='a derived p256 signer (uaMessage(p256, trade, h)), a native recipient'),
        row('eight_inputs', base(inputs=[tk(bytes(19) + bytes([0x10 + i]), 1_000 + i) for i in range(8)],
                                 outputs=[tk(LP, 1)], nonce=5), [1_000 + i for i in range(8)], scaas=(),
            note='the bound: eight inputs'),
    ]
    return {'spec': 'docs/superpowers/specs/2026-11-10-dex-liquidity.md §4.2, §4.3, §12 (UNAUDITED)',
            'generator': 'smartcontracts/vectors/ua/gen_liquidity.py', 'chainId': CHAIN_ID, 'chainUid': V.hx(CHAIN_UID),
            'dex': V.hx(DEX), 'tokenA': V.hx(TOKEN_A), 'tokenB': V.hx(TOKEN_B), 'lp': V.hx(LP),
            'liquidityTokenTypeHash': V.hx(V.keccak256(LIQUIDITY_TOKEN.encode())),
            'liquidityOrderTypeHash': V.hx(V.keccak256((LIQUIDITY_ORDER + LIQUIDITY_TOKEN).encode())),
            'selectors': {'mtxLiquidity': V.hx(selector(f'mtxLiquidity({PLAN_T},{INTERACTIONS_T})')),
                          'mtxLiquidityPull': '0x85fdfd38', 'liquidityOrderDigest': '0x436033f5'},
            'rows': rows}


if __name__ == '__main__':
    V.emit(OUT, build(), sys.argv)
