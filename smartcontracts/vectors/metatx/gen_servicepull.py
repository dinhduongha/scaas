#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Service-pull vectors (spec docs/superpowers/specs/2026-11-09-service-pull.md §10, §11; plan T78) -> `servicepull.json`.

    python3 -I smartcontracts/vectors/metatx/gen_servicepull.py [--check]

Every byte is computed here, independently of the contracts: EIP-712 (`encodeType`, `hashStruct`, the two domains), the
ABI (the entry's calldata, `servicePullEntries()` and `eip712Domain()` return data, the router's `relay` calldata), the
payer's ECDSA signature (secp256k1, RFC 6979, low-s; `famvec.py`). The forge cross-check
(`smartcontracts/evm/test/metatx/ServicePullVectors.t.sol`) lands each row on the reference service and a real token
clone etched at the row's addresses; `clientkeys` (test/servicepull.test.js), `ua-rs` and the node's typed KAT read the same
rows. `--check` compares the whole file (drift fails). Rows:

- `deposit_native`: `Deposit` (atomic fields), a native payer, the relay-fee wrap with the fee in the pulled token on the
  same lane (pull nonce n, fee n + 1, spec §2.4 (b)).
- `note_native`: `Note` (a `string` with multi-byte UTF-8 and a 33-byte `bytes`): EIP-712 hashes them as `keccak256(value)`,
  the ABI passes them raw (C3), with its relay-fee wrap.
- `deposit_unbound_fee_recipient`: `t.feeRecipient` non-zero with the recipient bit off: the digest zeroes it
  (`MetaTxLib.canon`), a client that forgets fails; the service refuses it at check 2 (N18), so no wrap.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import famvec as V  # noqa: E402

OUT = os.path.join(V.REPO, 'smartcontracts', 'vectors', 'metatx', 'servicepull.json')
CHAIN_ID = 7622                       # scaas-testnet
CHAIN_UID = V.unhx('0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464')   # TokenKat.t.sol's UID
TOKEN = V.unhx('0x7070000000000000000000000000000000007070')     # the pulled token (and the fee token F = T)
SERVICE = V.unhx('0x5e5e000000000000000000000000000000005e5e')   # RefServiceEscrow
ROUTER = V.unhx('0x6e5adad0b26e45d76250564dc569d2c05a082762')    # RelayFeeRouter, its CREATE2 address (GovDeploy pin)
EXECUTOR = V.unhx('0x5e65d1aa4f88e54d59f8974148b08bedf04408df')  # the router's CREATE at nonce 1
SERVICE_NAME, SERVICE_VERSION = 'SCaaS RefServiceEscrow', '1'
TOKEN_NAME = 'SCaaS MetaToken'
VALID_UNTIL = 1_800_000_300
FEE = 25
MODE_RESTRICT_RELAYER = 1

DEPOSIT_TYPE = 'Deposit(bytes32 payer,uint256 amount,uint64 releaseAfter,bytes32 salt)'
NOTE_TYPE = 'Note(bytes32 payer,uint256 amount,string memo,bytes commitment,bytes32 salt)'
UA_METATRANSFER = ('UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,'
                   'uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)')
UA_RELAY_FEE = ('UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,'
                'uint256 nonce,uint256 validUntil,address relayer)')
DOMAIN = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
SALTED_DOMAIN = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)'
T_TUPLE = '(bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)'
UASIG_TUPLE = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])'
T_FIELDS = ['from', 'to', 'value', 'entryRef', 'batch', 'nonce', 'validUntil', 'mode', 'relayer', 'fee', 'feeRecipient']


# ---------------------------------------------------------------- ABI (the subset the rows use)
def _split(t):
    """`(a,b,(c,d)[],e)` -> ['a', 'b', '(c,d)[]', 'e']."""
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


def _static_size(t):
    return sum(_static_size(x) for x in _split(t)) if t.startswith('(') and not t.endswith(']') else 32


def _u(n):
    return int(n).to_bytes(32, 'big')


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
    if t.startswith('bytes'):
        assert len(v) == int(t[5:])
        return v + bytes(32 - len(v))
    raise ValueError(t)


def abi_seq(types, vals):
    assert len(types) == len(vals)
    off = sum(32 if _dynamic(t) else _static_size(t) for t in types)
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
def parse_type(s):
    """`Name(type a,type b)` -> (Name, [(type, a), ...]): atomic, `bytes`, `string` only (C3)."""
    name, rest = s.split('(', 1)
    fields = [tuple(f.split(' ')) for f in rest[:-1].split(',')]
    for ty, _ in fields:
        assert ty in ('bytes', 'string', 'address', 'bool') or ty.startswith(('uint', 'int', 'bytes')), ty
    return name, fields


def eip712_word(ty, v):
    if ty == 'string':
        return V.keccak256(v.encode())
    if ty == 'bytes':
        return V.keccak256(v)
    return abi_enc(ty, v)


def hash_struct(type_string, values):
    _, fields = parse_type(type_string)
    return V.keccak256(V.keccak256(type_string.encode()), *(eip712_word(ty, values[n]) for ty, n in fields))


def service_domain():
    return V.keccak256(V.keccak256(DOMAIN.encode()), V.keccak256(SERVICE_NAME.encode()), V.keccak256(SERVICE_VERSION.encode()),
                       _u(CHAIN_ID), bytes(12) + SERVICE)


def token_domain():
    return V.keccak256(V.keccak256(SALTED_DOMAIN.encode()), V.keccak256(TOKEN_NAME.encode()), V.keccak256(b'1'),
                       _u(CHAIN_ID), bytes(12) + TOKEN, CHAIN_UID)


def typed(domain_sep, struct_hash):
    return V.keccak256(b'\x19\x01', domain_sep, struct_hash)


def transfer_struct(t, canon=True):
    relayer = t['relayer'] if not canon or t['mode'] & 1 else bytes(20)
    fee_recipient = t['feeRecipient'] if not canon or t['mode'] & 2 else bytes(20)
    return V.keccak256(V.keccak256(UA_METATRANSFER.encode()), t['from'], t['to'], _u(t['value']), t['entryRef'], _u(t['batch']),
                       _u(t['nonce']), _u(t['validUntil']), _u(t['mode']), bytes(12) + relayer, _u(t['fee']),
                       bytes(12) + fee_recipient)


# ---------------------------------------------------------------- JSON forms
def pad(a):
    return bytes(12) + a


def j_val(ty, v):
    if ty == 'string':
        return v
    if ty.startswith(('uint', 'int')):
        return str(v)
    return V.hx(v)


def j_t(t):
    return {k: (t[k] if k == 'mode' else j_val('uint256', t[k]) if isinstance(t[k], int) else V.hx(t[k])) for k in T_FIELDS}


def typed_data(type_string, values):
    name, fields = parse_type(type_string)
    return {'domain': {'name': SERVICE_NAME, 'version': SERVICE_VERSION, 'chainId': CHAIN_ID, 'verifyingContract': V.hx(SERVICE)},
            'types': {'EIP712Domain': [{'name': 'name', 'type': 'string'}, {'name': 'version', 'type': 'string'},
                                       {'name': 'chainId', 'type': 'uint256'}, {'name': 'verifyingContract', 'type': 'address'}],
                      name: [{'name': n, 'type': ty} for ty, n in fields]},
            'primaryType': name, 'message': {n: j_val(ty, values[n]) for ty, n in fields}}


ENTRIES = [('deposit', DEPOSIT_TYPE), ('note', NOTE_TYPE)]


def entry_sig(entry, type_string):
    _, fields = parse_type(type_string)
    return f"{entry}(({','.join(ty for ty, _ in fields)}),{T_TUPLE},{UASIG_TUPLE})"


def entries_return():
    sels = [selector(entry_sig(e, ty)) for e, ty in ENTRIES]
    return sels, abi_seq(['bytes4[]', 'string[]', 'address[]'], [sels, [ty for _, ty in ENTRIES], [TOKEN] * len(ENTRIES)])


def domain_return():
    return abi_seq(['bytes1', 'string', 'string', 'uint256', 'address', 'bytes32', 'uint256[]'],
                   [b'\x0f', SERVICE_NAME, SERVICE_VERSION, CHAIN_ID, SERVICE, bytes(32), []])


# ---------------------------------------------------------------- rows
PAYER = V.Ecdsa('scaas.servicepull.payer', V.SECP256K1)
PAYER_ADDR = V.keccak256(PAYER.key)[12:]


def sign(digest):
    rs, v = PAYER.sign(digest)
    return rs + bytes([27 + v])


def row(name, entry, type_string, op, batch, fee_recipient=bytes(20), wrap=True):
    _, fields = parse_type(type_string)
    op_hash = hash_struct(type_string, op)
    ref = typed(service_domain(), op_hash)
    t = {'from': pad(PAYER_ADDR), 'to': pad(SERVICE), 'value': op['amount'], 'entryRef': ref, 'batch': batch, 'nonce': 0,
         'validUntil': VALID_UNTIL, 'mode': MODE_RESTRICT_RELAYER, 'relayer': SERVICE, 'fee': 0, 'feeRecipient': fee_recipient}
    t_hash = transfer_struct(t)
    digest = typed(token_domain(), t_hash)
    sig = sign(digest)
    auth = (b'', sig, [])
    sig_text = entry_sig(entry, type_string)
    op_tuple = '(' + ','.join(ty for ty, _ in fields) + ')'
    calldata = selector(sig_text) + abi_seq([op_tuple, T_TUPLE, UASIG_TUPLE],
                                            [[op[n] for _, n in fields], [t[k] for k in T_FIELDS], auth])
    sels, entries_ret = entries_return()
    r = {
        'name': name, 'chainId': CHAIN_ID,
        'service': {'address': V.hx(SERVICE), 'domainSeparator': V.hx(service_domain()),
                    'entries': {'selectors': [V.hx(s) for s in sels], 'opTypes': [ty for _, ty in ENTRIES],
                                'tokens': [V.hx(TOKEN)] * len(ENTRIES)},
                    'entriesReturn': V.hx(entries_ret), 'domainReturn': V.hx(domain_return())},
        'token': {'address': V.hx(TOKEN), 'name': TOKEN_NAME, 'version': '1', 'salt': V.hx(CHAIN_UID),
                  'domainSeparator': V.hx(token_domain())},
        'entry': entry, 'abiSignature': sig_text, 'selector': V.hx(selector(sig_text)),
        'opType': type_string, 'typeHash': V.hx(V.keccak256(type_string.encode())), 'typedData': typed_data(type_string, op),
        'opStructHash': V.hx(op_hash), 'entryRef': V.hx(ref),
        't': j_t(t), 'transferTypeHash': V.hx(V.keccak256(UA_METATRANSFER.encode())), 'transferStructHash': V.hx(t_hash),
        'transferDigest': V.hx(digest), 'signer': V.hx(PAYER_ADDR),
        'auth': {'keyData': '0x', 'signature': V.hx(sig), 'members': []},
        'calldata': V.hx(calldata),
        'job': {'entry': entry, 'contract': 'service', 'token': V.hx(SERVICE),
                'args': {'op': typed_data(type_string, op)['message'], 'pullToken': V.hx(TOKEN), 't': j_t(t),
                         'auth': {'keyData': '0x', 'signature': V.hx(sig), 'members': []}}},
    }
    if fee_recipient != bytes(20):
        r['transferDigestUncanon'] = V.hx(typed(token_domain(), transfer_struct(t, canon=False)))
        r['serviceAccepts'] = False
        r['serviceRefusal'] = 'ServicePullShape(2)'
        assert r['transferDigestUncanon'] != r['transferDigest']
    else:
        r['serviceAccepts'] = True
    if wrap:
        cdh = V.keccak256(calldata)
        rref = V.keccak256(b'scaas.relayfee', _u(CHAIN_ID), SERVICE, cdh)
        f = {'from': pad(PAYER_ADDR), 'target': SERVICE, 'callDataHash': cdh, 'payee': pad(ROUTER), 'value': FEE,
             'batch': batch, 'nonce': 1, 'validUntil': VALID_UNTIL, 'relayer': ROUTER}
        f_hash = V.keccak256(V.keccak256(UA_RELAY_FEE.encode()), f['from'], pad(f['target']), cdh, f['payee'], _u(FEE),
                             _u(batch), _u(1), _u(VALID_UNTIL), pad(ROUTER))
        f_digest = typed(token_domain(), f_hash)
        f_sig = sign(f_digest)
        relay = selector('relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,' + UASIG_TUPLE + ')') + abi_seq(
            ['address', 'bytes', 'address', 'bytes32', 'bytes32', 'uint256', 'uint256', 'uint256', 'uint256', UASIG_TUPLE],
            [SERVICE, calldata, TOKEN, f['from'], f['payee'], FEE, batch, 1, VALID_UNTIL, (b'', f_sig, [])])
        r['relayFee'] = {'router': V.hx(ROUTER), 'executor': V.hx(EXECUTOR), 'feeToken': V.hx(TOKEN), 'payee': V.hx(pad(ROUTER)),
                         'value': str(FEE), 'batch': str(batch), 'nonce': '1', 'validUntil': str(VALID_UNTIL),
                         'callDataHash': V.hx(cdh), 'relayRef': V.hx(rref), 'typeHash': V.hx(V.keccak256(UA_RELAY_FEE.encode())),
                         'structHash': V.hx(f_hash), 'digest': V.hx(f_digest), 'signature': V.hx(f_sig),
                         'relayCalldata': V.hx(relay)}
    return r


def build():
    V.selftest_primitives()
    # the ABI encoder against two known answers: a selector and a dynamic tuple (solc's layout)
    assert selector('transfer(address,uint256)').hex() == 'a9059cbb'
    assert abi_seq(['(uint256,bytes)'], [[1, b'\xab']]).hex() == (
        '20'.rjust(64, '0') + '1'.rjust(64, '0') + '40'.rjust(64, '0') + '1'.rjust(64, '0') + 'ab'.ljust(64, '0'))
    salt = lambda s: V.keccak256(('scaas.servicepull.salt.' + s).encode())  # noqa: E731
    dep = {'payer': pad(PAYER_ADDR), 'amount': 1000, 'releaseAfter': 1_800_003_600, 'salt': salt('deposit')}
    note = {'payer': pad(PAYER_ADDR), 'amount': 2500, 'memo': 'Hóa đơn 42 – đặt cọc ✓',
            'commitment': V.keccak256(b'scaas.servicepull.commitment') + b'\x01', 'salt': salt('note')}
    unbound = dict(dep, salt=salt('unbound'))
    rows = [row('deposit_native', 'deposit', DEPOSIT_TYPE, dep, 7),
            row('note_native', 'note', NOTE_TYPE, note, 8),
            row('deposit_unbound_fee_recipient', 'deposit', DEPOSIT_TYPE, unbound, 9,
                fee_recipient=V.unhx('0x00000000000000000000000000000000000000fe'), wrap=False)]
    return {'spec': 'docs/superpowers/specs/2026-11-09-service-pull.md §10, §11 (UNAUDITED)',
            'generator': 'smartcontracts/vectors/metatx/gen_servicepull.py', 'rows': rows}


if __name__ == '__main__':
    V.emit(OUT, build(), sys.argv)
