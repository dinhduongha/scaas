"""Passkey clientDataJSON origin parity rows for Algorand (near-algorand T17 fix 1, controller ruling (a)).

`vectors/webauthn-origin.json` = the NEAR rows (smartcontracts/near/vectors/webauthn-origin.json) plus Algorand's own
edges, each with the origin the Algorand account app's `client_origin` (contracts/account.py) returns (null = it
asserts). The expectation is computed here by a line-for-line transcription of `client_origin` (8-byte words, the
padding, every assert); the AVM run of the same rows is tests/test_account.py::test_origin_parity_vectors (localnet, via
the test-only Probe app), and scaas-node's port is adapters::algorand::tests::origin_parity_vectors. A row where NEAR
answers otherwise carries `near` (NEAR's answer).

    python3 -I scripts/gen_origin_vectors.py           # check
    python3 -I scripts/gen_origin_vectors.py --write   # rewrite
"""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'vectors', 'webauthn-origin.json')
NEAR = os.path.join(ROOT, '..', 'near', 'vectors', 'webauthn-origin.json')

MAX_ORIGIN_LEN = 128
CD_TYPE = b'{"type":"webauthn.get","challenge":"'
CD_ORIGIN = b'","origin":"'
CD_CROSS = b',"crossOrigin":false'


class Refused(Exception):
    pass


def check(c):
    if not c:
        raise Refused()


def u64(b, i):
    return int.from_bytes(b[i:i + 8], 'big')


def zero_byte(x):
    return ((x - 0x0101010101010101) % 2**64) & ~x & 0x8080808080808080 != 0


def client_origin(cd, d):
    """account.py `client_origin`, transcribed (AVM `base64_decode URLEncoding` is strict: `decode` below)."""
    check(len(cd) > 91 and cd[0:36] == CD_TYPE and cd[79:91] == CD_ORIGIN)
    try:
        check(base64.b64decode(cd[36:79] + b'=', altchars=b'-_', validate=True) == d
              and base64.urlsafe_b64encode(d).rstrip(b'=') == cd[36:79])  # strict: canonical trailing bits
    except ValueError:
        raise Refused()
    padded = cd + bytes(8)
    i = 91
    while True:
        check(i < len(cd) and i <= 91 + MAX_ORIGIN_LEN)
        w = u64(padded, i)
        if zero_byte(w ^ 0x2222222222222222) or zero_byte(w ^ 0x5C5C5C5C5C5C5C5C):
            break
        i += 8
    while True:
        c = padded[i]
        if c == 0x22:
            break
        check(c != 0x5C)
        i += 1
    check(i > 91 and i <= 91 + MAX_ORIGIN_LEN)
    t = cd[i + 1:]
    if t != b'}' and t != CD_CROSS + b'}':
        n = len(t)
        check(n > 22 and t[0:21] == CD_CROSS + b',' and t[n - 1] == 0x7D)
        tp = t + bytes(8)
        for j in range(20, n, 8):
            if zero_byte(u64(tp, j) ^ 0x2222222222222222):
                for k in range(j, j + 8 if j + 8 < n else n):
                    if t[k] == 0x22:
                        if k + 11 <= n:
                            check(t[k:k + 11] != b'"topOrigin"')
                        if k + 13 <= n:
                            check(t[k:k + 13] != b'"crossOrigin"')
    return cd[91:i]


def origin(cd, d):
    try:
        return client_origin(cd, d).decode()
    except (Refused, UnicodeDecodeError):
        return None


def main():
    near = json.load(open(NEAR))['rows']
    ch = bytes(range(32))
    c = base64.urlsafe_b64encode(ch).rstrip(b'=').decode()
    pre = '{"type":"webauthn.get","challenge":"%s","origin":"' % c
    own = [
        ('origin_128', pre + 'https://' + 'a' * 120 + '","crossOrigin":false}'),
        ('origin_129', pre + 'https://' + 'a' * 121 + '","crossOrigin":false}'),
        ('origin_129_no_tail_member', pre + 'https://' + 'a' * 121 + '"}'),
        ('backslash_after_origin', pre + 'https://a.test","crossOrigin":false,"x":"\\\\"}'),
        ('quote_word_boundary', pre + 'https://abcdefgh"}'),
        ('top_origin_at_tail_end', pre + 'https://a.test","crossOrigin":false,"topOrigin"}'),
        ('cross_origin_split_word', pre + 'https://a.test","crossOrigin":false,"aaaa","crossOrigin":false}'),
        ('short_tail_member', pre + 'https://a.test","crossOrigin":false,x}'),
        ('non_canonical_challenge', pre[:36 + 42] + chr(ord(c[42]) + 1) + pre[36 + 43:] + 'https://a.test"}'),
    ]
    rows = []
    for r in near:
        d = bytes.fromhex(r['challenge'][2:])
        o = origin(r['clientDataJSON'].encode(), d)
        row = {'name': r['name'], 'challenge': r['challenge'], 'clientDataJSON': r['clientDataJSON'], 'origin': o}
        if o != r['origin']:
            row['near'] = r['origin']
        rows.append(row)
    for name, cd in own:
        rows.append({'name': name, 'challenge': '0x' + ch.hex(), 'clientDataJSON': cd, 'origin': origin(cd.encode(), ch)})
    out = {'note': __doc__.strip().split('\n\n')[0].replace('\n', ' '), 'rows': rows}
    text = json.dumps(out, indent=1, ensure_ascii=False) + '\n'
    if '--write' in sys.argv:
        open(OUT, 'w').write(text)
        print('wrote', OUT)
    elif not os.path.exists(OUT) or open(OUT).read() != text:
        sys.exit('vectors/webauthn-origin.json is stale: run gen_origin_vectors.py --write')
    else:
        print('ok', OUT)


if __name__ == '__main__':
    main()
