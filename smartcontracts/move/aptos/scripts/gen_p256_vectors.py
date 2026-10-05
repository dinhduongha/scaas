#!/usr/bin/env python3
"""Sinh `tests/p256_vectors.move`: Wycheproof ECDSA P-256/SHA-256 dạng P1363 (r‖s) + hai assertion WebAuthn
(vector ES256 chính thức của W3C WebAuthn L3 §16.7 và vector authenticator phần mềm của clientkeys).

    python3 smartcontracts/move/aptos/scripts/gen_p256_vectors.py [--check]

Kỳ vọng của mỗi vector = Wycheproof `valid` VÀ s ≤ n/2 (bamboo::p256 từ chối high-s). OpenSSL (`cryptography`)
kiểm lại từng kết quả Wycheproof trước khi ghi. Mỗi vector high-s còn được ghi thêm dạng low-s `(r, n−s)` (tcId +
10000, kỳ vọng = OpenSSL trên dạng đó): không thì 70 ca biên của Wycheproof chỉ chạm phép từ chối high-s (review M4).
Thêm các ca dựng tay (tcId 20001…): nhánh so `r + n` cả hai chiều, `u1·G + u2·Q = ∞`, nhân đôi điểm trong vòng Strauss.
"""
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'tests', 'p256_vectors.move')
WYCHE_URL = ('https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/'
             'testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json')
WYCHE_SHA256 = 'c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986'
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# W3C WebAuthn Level 3 (REC), §16.7 "Packed Attestation with ES256 Credential" — Authentication.
W3C = {
    'x': '1cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae5',
    'y': '59e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423',
    'challenge': 'b1106fa46a57bef1781511c0557dc898a03413d5f0f17d244630c194c7e1adb5',
    'ad': 'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000',
    'cd': ('7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446'
           '524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f'
           '2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c'
           '69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c'
           '647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d7567754'
           '64e7036723851227d'),
    'der': ('30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a9715'
            '2cd099c55bfb1477b29d900a49a64018314f9bfccda163'),
}


def wycheproof():
    cache = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'wycheproof-p256-p1363.json')
    if not os.path.exists(cache):
        urllib.request.urlretrieve(WYCHE_URL, cache)
    raw = open(cache, 'rb').read()
    if hashlib.sha256(raw).hexdigest() != WYCHE_SHA256:
        sys.exit('wycheproof file hash mismatch')
    return json.loads(raw)


def openssl_ok(pk, msg_hash, sig):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    if not (0 < r < N and 0 < s < N):
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        key.verify(utils.encode_dss_signature(r, s), msg_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def ec_add(a, b):
    """Affine P-256; None = điểm vô cực."""
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    lam = ((3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def ec_mul(k, pt):
    out = None
    for bit in bin(k % N)[2:]:
        out = ec_add(out, out)
        if bit == '1':
            out = ec_add(out, pt)
    return out


def ec_neg(pt):
    return pt[0], (-pt[1]) % P


def point_at(x):
    """Điểm có hoành độ x (nếu x nằm trên đường cong)."""
    rhs = (x ** 3 - 3 * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    return (x, y) if y * y % P == rhs else None


def enc(pt):
    return b'\x04' + pt[0].to_bytes(32, 'big') + pt[1].to_bytes(32, 'big')


def forged(r_target, x_of_r, u1, u2):
    """(pk, hash, sig) với R = u1·G + u2·Q có hoành độ `x_of_r`, chữ ký mang `r_target` (Q giải ngược, như Wycheproof)."""
    R = point_at(x_of_r)
    Q = ec_mul(pow(u2, -1, N), ec_add(R, ec_neg(ec_mul(u1, G))))
    s = r_target * pow(u2, -1, N) % N
    e = u1 * s % N
    s = min(s, N - s)        # (r, n−s) ⇔ −R: cùng hoành độ
    return enc(Q), e.to_bytes(32, 'big'), r_target.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def crafted():
    """(tag, pk, hash, sig, expected) — mỗi ca được OpenSSL xác nhận ở `main`."""
    out = []
    x = N                    # x(R) ≥ n đầu tiên trên đường cong: x(R) mod n = x − n
    while point_at(x) is None:
        x += 1
    out.append(('x(R) = r + n: wrap accepted', *forged(x - N, x, 0x1234567, 0x89abcdef), True))
    out.append(('x(R) = r + n + 1: wrap mismatch rejected', *forged(x - N - 1, x, 0x1234567, 0x89abcdef), False))
    r = P - N                # r ≥ p − n: r + n ≥ p không phải hoành độ; x(R) = r + n − p < n ≠ r
    while point_at(r + N - P) is None:
        r += 1
    out.append(('r >= p - n, x(R) = r + n - p: rejected', *forged(r, r + N - P, 0x55, 0x77), False))
    # u1·G + u2·Q = ∞: Q = −(e/r)·G
    rr, ss, e = 0x1111, 0x2222, 0x3333
    out.append(('u1*G + u2*Q = infinity', enc(ec_mul(-e * pow(rr, -1, N) % N, G)), e.to_bytes(32, 'big'),
                rr.to_bytes(32, 'big') + ss.to_bytes(32, 'big'), False))
    # Q = G, u1 = u2 = 1: vòng cuối cộng G vào tích luỹ đang bằng G ⇒ `madd` rơi vào nhánh nhân đôi; R = 2G
    r2 = ec_mul(2, G)[0] % N
    out.append(('Q = G, u1 = u2 = 1: doubling inside the Strauss loop', enc(G), r2.to_bytes(32, 'big'),
                r2.to_bytes(32, 'big') * 2, True))
    out.append(('Q = G, u1 = -u2: infinity', enc(G), (N - r2).to_bytes(32, 'big'), r2.to_bytes(32, 'big') * 2, False))
    return out


def der_rs(der):
    assert der[0] == 0x30
    i, out = 2, []
    for _ in range(2):
        assert der[i] == 2
        n = der[i + 1]
        out.append(int.from_bytes(der[i + 2:i + 2 + n], 'big'))
        i += 2 + n
    return out


def h(b):
    return 'x"%s"' % b.hex()


def main():
    d = wycheproof()
    cases, seen = [], set()
    for g in d['testGroups']:
        pk = bytes.fromhex(g['publicKey']['uncompressed'])
        for t in g['tests']:
            sig, msg_hash = bytes.fromhex(t['sig']), hashlib.sha256(bytes.fromhex(t['msg'])).digest()
            ok = openssl_ok(pk, msg_hash, sig)
            if ok != (t['result'] == 'valid'):
                sys.exit('OpenSSL disagrees with Wycheproof on tcId %d' % t['tcId'])
            low = len(sig) == 64 and int.from_bytes(sig[32:], 'big') <= N // 2
            key = (pk, msg_hash, sig)
            if key in seen:
                continue
            seen.add(key)
            cases.append((t['tcId'], pk, msg_hash, sig, ok and low))
            s_ = int.from_bytes(sig[32:], 'big') if len(sig) == 64 else 0
            if N // 2 < s_ < N:
                norm = sig[:32] + (N - s_).to_bytes(32, 'big')
                if (pk, msg_hash, norm) not in seen:
                    seen.add((pk, msg_hash, norm))
                    cases.append((10000 + t['tcId'], pk, msg_hash, norm, openssl_ok(pk, msg_hash, norm)))
    extra = []
    for i, (tag, pk, mh, sig, want) in enumerate(crafted()):
        if openssl_ok(pk, mh, sig) != want:
            sys.exit('OpenSSL disagrees with crafted case: ' + tag)
        extra.append((20001 + i, tag, pk, mh, sig, want))
    w = W3C
    pk = bytes.fromhex('04' + w['x'] + w['y'])
    ad, cd = bytes.fromhex(w['ad']), bytes.fromhex(w['cd'])
    r, s = der_rs(bytes.fromhex(w['der']))
    msg_hash = hashlib.sha256(ad + hashlib.sha256(cd).digest()).digest()
    high = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    low = r.to_bytes(32, 'big') + min(s, N - s).to_bytes(32, 'big')
    assert openssl_ok(pk, msg_hash, high) and openssl_ok(pk, msg_hash, low) and s > N // 2
    soft = json.load(open(os.path.join(HERE, '..', '..', '..', '..', 'smartcontracts', 'evm', 'test', 'vectors', 'webauthn_soft.json')))
    lines = [
        '// GENERATED by smartcontracts/move/aptos/scripts/gen_p256_vectors.py — do not edit.',
        '// Wycheproof ecdsa_secp256r1_sha256_p1363_test.json @ C2SP/wycheproof 3fa63dd (sha256 %s):' % WYCHE_SHA256[:16],
        '// %d distinct cases; expected = Wycheproof valid AND low-s (OpenSSL re-checked every case);' % len(cases),
        '// tcId 10000+k = low-s form (r, n-s) of high-s case k; 20001+ = crafted edge cases (see `crafted`).',
        '#[test_only]',
        'module bamboo::p256_vectors {',
        '    use bamboo::p256;',
        '',
        '    /// (tcId, public key, sha256(msg), r‖s, expected)',
        '    fun check(tc: u64, pk: vector<u8>, hash: vector<u8>, sig: vector<u8>, want: bool) {',
        '        assert!(p256::verify(&pk, &hash, &sig) == want, tc);',
        '    }',
        '',
    ]
    chunk = 40
    for k in range(0, len(cases), chunk):
        lines.append('    #[test]')
        lines.append('    fun wycheproof_%d() {' % (k // chunk))
        for tc, pk_, mh, sig, want in cases[k:k + chunk]:
            lines.append('        check(%d, %s, %s, %s, %s);' % (tc, h(pk_), h(mh), h(sig), 'true' if want else 'false'))
        lines.append('    }')
        lines.append('')
    lines.append('    #[test]')
    lines.append('    fun crafted_edges() {')
    for tc, tag, pk_, mh, sig, want in extra:
        lines.append('        // %s' % tag)
        lines.append('        check(%d, %s, %s, %s, %s);' % (tc, h(pk_), h(mh), h(sig), 'true' if want else 'false'))
    lines.append('    }')
    lines.append('')
    lines += [
        '    /// W3C WebAuthn L3 §16.7 ES256 assertion: the authenticator signs HIGH-s; the low-s form verifies.',
        '    public fun w3c_pk(): vector<u8> { %s }' % h(pk),
        '    public fun w3c_challenge(): vector<u8> { %s }' % h(bytes.fromhex(w['challenge'])),
        '    public fun w3c_authenticator_data(): vector<u8> { %s }' % h(ad),
        '    public fun w3c_client_data_json(): vector<u8> { %s }' % h(cd),
        '    public fun w3c_sig_low_s(): vector<u8> { %s }' % h(low),
        '    public fun w3c_sig_high_s(): vector<u8> { %s }' % h(high),
        '',
        '    #[test]',
        '    fun w3c_webauthn_es256() {',
        '        check(0, w3c_pk(), %s, w3c_sig_low_s(), true);' % h(msg_hash),
        '        check(0, w3c_pk(), %s, w3c_sig_high_s(), false);' % h(msg_hash),
        '        // a cached table (Account keys keep one) verifies the same; off-curve / malformed keys have none',
        '        let t = p256::table(&w3c_pk());',
        '        assert!(t.length() == 16 && p256::verify_with(&t, &%s, &w3c_sig_low_s()), 1);' % h(msg_hash),
        '        assert!(!p256::verify_with(&t, &%s, &w3c_sig_low_s()), 2);' % h(bytes(32)),
        '        assert!(p256::table(&%s).is_empty(), 3);' % h(pk[:-1] + bytes([pk[-1] ^ 1])),
        '        assert!(p256::table(&%s).is_empty() && p256::table(&x"04").is_empty(), 4);' % h(b'\x05' + pk[1:]),
        '    }',
    ]
    spk = b'\x04' + bytes.fromhex(soft['qx'][2:].rjust(64, '0') + soft['qy'][2:].rjust(64, '0'))
    sad, scd = bytes.fromhex(soft['authenticatorData'][2:]), soft['clientDataJSON'].encode()
    smh = hashlib.sha256(sad + hashlib.sha256(scd).digest()).digest()
    sr, ss = der_rs(bytes.fromhex(soft['signatureDer'][2:]))
    ssig = sr.to_bytes(32, 'big') + min(ss, N - ss).to_bytes(32, 'big')
    assert openssl_ok(spk, smh, ssig)
    lines += [
        '',
        '    // clientkeys software authenticator (smartcontracts/evm/test/vectors/webauthn_soft.json), low-s normalised.',
        '    #[test]',
        '    fun clientkeys_soft_authenticator() {',
        '        check(0, %s, %s, %s, true);' % (h(spk), h(smh), h(ssig)),
        '    }',
    ]
    lines.append('}')
    text = '\n'.join(lines) + '\n'
    if '--check' in sys.argv:
        if open(OUT).read() != text:
            sys.exit('tests/p256_vectors.move is stale: re-run gen_p256_vectors.py')
        print('ok')
        return
    open(OUT, 'w').write(text)
    print('wrote %d cases' % len(cases))


if __name__ == '__main__':
    main()
