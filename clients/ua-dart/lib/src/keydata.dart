// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
// Key-data validation (accounts.md §1.6 "Validation at registration") over BigInt: affine short Weierstrass
// arithmetic on y² = x³ + b over Fp and Fp2 (u² = -1) for curve and subgroup checks, twisted Edwards for ed25519.
// Public inputs only: nothing here is constant-time. Every length is checked before it is read.
import 'dart:typed_data';

import 'table.dart';

BigInt _hex(String h) => BigInt.parse(h, radix: 16);
BigInt _be(Uint8List b, int lo, int hi) {
  var v = BigInt.zero;
  for (var i = lo; i < hi; i++) {
    v = (v << 8) | BigInt.from(b[i]);
  }
  return v;
}

BigInt _inv(BigInt a, BigInt p) => (a % p).modInverse(p);

final _secpP = _hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
final _secpN = _hex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
final _p256P = _hex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
final _p256B = _hex('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
final _edP = (BigInt.one << 255) - BigInt.from(19);
final _edD = (BigInt.from(-121665) * _inv(BigInt.from(121666), _edP)) % _edP;
final _edSqrtM1 = BigInt.two.modPow((_edP - BigInt.one) ~/ BigInt.from(4), _edP);
final _bnP = _hex('30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47');
final _bnR = _hex('30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
final _blsP = _hex('1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab');
final _blsR = _hex('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

void _need(bool ok, String reason) {
  if (!ok) throw UAError('UAKeyData', reason);
}

/// Key data as bytes: a Uint8List or a hex String (optional 0x); anything else is UAKeyData 'type'.
Uint8List keyBytes(Object? v) {
  if (v is Uint8List) return v;
  if (v is String) {
    final h = v.startsWith('0x') || v.startsWith('0X') ? v.substring(2) : v;
    _need(h.length.isEven && RegExp(r'^[0-9a-fA-F]*$').hasMatch(h), 'hex');
    final o = Uint8List(h.length ~/ 2);
    for (var i = 0; i < o.length; i++) {
      o[i] = int.parse(h.substring(2 * i, 2 * i + 2), radix: 16);
    }
    return o;
  }
  throw UAError('UAKeyData', 'type');
}

// ----- Fp2 = Fp[u]/(u² + 1); points on y² = x³ + b (G1 uses a1 = 0) -----

class _F2 {
  final BigInt a0, a1;
  const _F2(this.a0, this.a1);
  @override
  bool operator ==(Object o) => o is _F2 && a0 == o.a0 && a1 == o.a1;
  @override
  int get hashCode => Object.hash(a0, a1);
  bool get isZero => a0 == BigInt.zero && a1 == BigInt.zero;
}

_F2 _add(_F2 a, _F2 b, BigInt p) => _F2((a.a0 + b.a0) % p, (a.a1 + b.a1) % p);
_F2 _sub(_F2 a, _F2 b, BigInt p) => _F2((a.a0 - b.a0) % p, (a.a1 - b.a1) % p);
_F2 _mul(_F2 a, _F2 b, BigInt p) => _F2((a.a0 * b.a0 - a.a1 * b.a1) % p, (a.a0 * b.a1 + a.a1 * b.a0) % p);
_F2 _inv2(_F2 a, BigInt p) {
  final n = _inv(a.a0 * a.a0 + a.a1 * a.a1, p);
  return _F2((a.a0 * n) % p, (-a.a1 * n) % p);
}

bool _onCurve(_F2 x, _F2 y, _F2 b, BigInt p) => _mul(y, y, p) == _add(_mul(_mul(x, x, p), x, p), b, p);

class _Pt {
  final _F2 x, y;
  const _Pt(this.x, this.y);
}

_Pt? _addPt(_Pt? a, _Pt? c, BigInt p) {
  if (a == null) return c;
  if (c == null) return a;
  _F2 l;
  if (a.x == c.x) {
    if (a.y != c.y || a.y.isZero) return null; // P + (-P), or doubling a 2-torsion point
    final x2 = _mul(a.x, a.x, p);
    l = _mul(_add(_add(x2, x2, p), x2, p), _inv2(_add(a.y, a.y, p), p), p);
  } else {
    l = _mul(_sub(c.y, a.y, p), _inv2(_sub(c.x, a.x, p), p), p);
  }
  final x3 = _sub(_sub(_mul(l, l, p), a.x, p), c.x, p);
  return _Pt(x3, _sub(_mul(l, _sub(a.x, x3, p), p), a.y, p));
}

/// [r]P == O by double-and-add.
bool _inSubgroup(_F2 x, _F2 y, BigInt r, BigInt p) {
  _Pt? acc;
  _Pt? q = _Pt(x, y);
  for (var k = r; k != BigInt.zero; k >>= 1) {
    if (k.isOdd) acc = _addPt(acc, q, p);
    q = _addPt(q, q, p);
  }
  return acc == null;
}

void _curveAndSubgroup(_F2 x, _F2 y, _F2 b, BigInt r, BigInt p) {
  _need(_onCurve(x, y, b, p), 'curve');
  _need(_inSubgroup(x, y, r, p), 'subgroup');
}

// ----- per-curve checks -----

void _secpX(Uint8List d, int lo) {
  final x = _be(d, lo, lo + 32);
  _need(x < _secpP, 'range');
  final rhs = (x * x * x + BigInt.from(7)) % _secpP;
  final y = rhs.modPow((_secpP + BigInt.one) ~/ BigInt.from(4), _secpP);
  _need((y * y) % _secpP == rhs, 'curve');
}

void _secpCompressed(Uint8List b, int o) {
  _need(b[o] == 2 || b[o] == 3, 'prefix');
  _secpX(b, o + 1);
}

void _p256Point(Uint8List b) {
  final x = _be(b, 0, 32), y = _be(b, 32, 64);
  _need(x < _p256P && y < _p256P, 'range');
  _need((y * y - (x * x * x - BigInt.from(3) * x + _p256B)) % _p256P == BigInt.zero, 'curve');
}

(BigInt, BigInt) _edAdd((BigInt, BigInt) a, (BigInt, BigInt) c) {
  final t = (_edD * a.$1 * c.$1 * a.$2 * c.$2) % _edP;
  return (
    ((a.$1 * c.$2 + c.$1 * a.$2) * _inv(BigInt.one + t, _edP)) % _edP,
    ((a.$2 * c.$2 + a.$1 * c.$1) * _inv(BigInt.one - t, _edP)) % _edP,
  );
}

void _ed25519(Uint8List b) {
  var v = BigInt.zero;
  for (var i = 31; i >= 0; i--) {
    v = (v << 8) | BigInt.from(b[i]);
  }
  final sign = (v >> 255).toInt();
  final y = v & ((BigInt.one << 255) - BigInt.one);
  _need(y < _edP, 'range');
  final x2 = ((y * y - BigInt.one) * _inv(_edD * y * y + BigInt.one, _edP)) % _edP;
  var x = x2.modPow((_edP + BigInt.from(3)) ~/ BigInt.from(8), _edP);
  if ((x * x - x2) % _edP != BigInt.zero) x = (x * _edSqrtM1) % _edP;
  _need((x * x - x2) % _edP == BigInt.zero, 'curve');
  _need(!(x == BigInt.zero && sign == 1), 'sign');
  if (x.isOdd != (sign == 1)) x = _edP - x;
  var pt = (x, y);
  for (var i = 0; i < 3; i++) {
    pt = _edAdd(pt, pt);
  }
  _need(!(pt.$1 == BigInt.zero && pt.$2 == BigInt.one), 'small-order');
}

void _bnG1(Uint8List b, int o) {
  final x = _be(b, o, o + 32), y = _be(b, o + 32, o + 64);
  _need(x < _bnP && y < _bnP, 'range');
  _need(!(x == BigInt.zero && y == BigInt.zero), 'identity');
  _need((y * y - x * x * x - BigInt.from(3)) % _bnP == BigInt.zero, 'curve');
}

final _bnB2v = _mul(_F2(BigInt.from(3), BigInt.zero), _inv2(_F2(BigInt.from(9), BigInt.one), _bnP), _bnP);

void _bnG2(Uint8List b) {
  final xi = _be(b, 0, 32), xr = _be(b, 32, 64), yi = _be(b, 64, 96), yr = _be(b, 96, 128);
  _need(xi < _bnP && xr < _bnP && yi < _bnP && yr < _bnP, 'range');
  _need(!(xi == BigInt.zero && xr == BigInt.zero && yi == BigInt.zero && yr == BigInt.zero), 'identity');
  _curveAndSubgroup(_F2(xr, xi), _F2(yr, yi), _bnB2v, _bnR, _bnP); // EIP-197: imaginary part first
}

BigInt _blsFp(Uint8List b, int o) {
  for (var i = o; i < o + 16; i++) {
    _need(b[i] == 0, 'padding');
  }
  final v = _be(b, o + 16, o + 64);
  _need(v < _blsP, 'range');
  return v;
}

void _blsG1(Uint8List b) {
  final x = _blsFp(b, 0), y = _blsFp(b, 64);
  _need(!(x == BigInt.zero && y == BigInt.zero), 'identity');
  _curveAndSubgroup(_F2(x, BigInt.zero), _F2(y, BigInt.zero), _F2(BigInt.from(4), BigInt.zero), _blsR, _blsP);
}

void _blsG2(Uint8List b) {
  final x0 = _blsFp(b, 0), x1 = _blsFp(b, 64), y0 = _blsFp(b, 128), y1 = _blsFp(b, 192);
  _need(!(x0 == BigInt.zero && x1 == BigInt.zero && y0 == BigInt.zero && y1 == BigInt.zero), 'identity');
  _curveAndSubgroup(_F2(x0, x1), _F2(y0, y1), _F2(BigInt.from(4), BigInt.from(4)), _blsR, _blsP); // EIP-2537: c0 first
}

// ----- layouts -----

int _u16(Uint8List d, int o) {
  _need(d.length >= o + 2, 'length');
  return d[o] << 8 | d[o + 1];
}

/// Lexicographic compare of d[a..a+n) and d[b..b+n).
int _cmp(Uint8List d, int a, int b, int n) {
  for (var i = 0; i < n; i++) {
    if (d[a + i] != d[b + i]) return d[a + i] < d[b + i] ? -1 : 1;
  }
  return 0;
}

void _musig2(Uint8List d, void Function(Uint8List, int) point, int size) {
  final n = _u16(d, size);
  _need(n >= 2 && n <= 16, 'n');
  _need(d.length == size + 2 + n * size, 'length');
  point(d, 0);
  for (var i = 0; i < n; i++) {
    final o = size + 2 + i * size;
    point(d, o);
    if (i > 0) _need(_cmp(d, o - size, o, size) < 0, 'order');
  }
}

void _frost(Uint8List d, void Function(Uint8List, int) point, int size, BigInt order) {
  final t = _u16(d, size), n = _u16(d, size + 2);
  _need(t >= 2 && t <= n && n <= 16, 'threshold');
  final per = (t + 1) * size + 32;
  _need(d.length == size + 4 + n * per, 'length');
  point(d, 0);
  for (var i = 0; i < n; i++) {
    final o = size + 4 + i * per;
    for (var j = 0; j <= t; j++) {
      point(d, o + j * size); // t commitments, then R_i
    }
    _need(_be(d, o + (t + 1) * size, o + (t + 1) * size + 32) < order, 'scalar');
  }
}

void _msig(Uint8List d, bool hederaNative) {
  final threshold = _u16(d, 0), count = _u16(d, 2);
  _need(count >= 1 && count <= 16, 'count');
  _need(d.length == 4 + 36 * count, 'length');
  var total = 0;
  for (var i = 0; i < count; i++) {
    final o = 4 + 36 * i;
    final kind = _u16(d, o), weight = _u16(d, o + 34);
    _need(isMember(kind, hederaNative), 'member-kind');
    _need(weight >= 1, 'weight');
    var zero = true;
    for (var j = 0; j < 12; j++) {
      if (d[o + 2 + j] != 0) zero = false;
    }
    _need(isNative(kind) == zero, 'member-id');
    if (i > 0) _need(_cmp(d, o - 34, o + 2, 32) < 0, 'order');
    total += weight;
  }
  _need(threshold >= 1 && threshold <= total, 'threshold');
}

void _fndsa(Uint8List d) {
  _need(d[0] == 0x09, 'header');
  for (var i = 0; i < 512; i++) {
    var v = 0;
    for (var j = 0; j < 14; j++) {
      final k = i * 14 + j;
      v = v << 1 | (d[1 + k ~/ 8] >> (7 - k % 8)) & 1;
    }
    _need(v < 12289, 'coefficient');
  }
}

/// Throws UAError('UAKeyData') unless [keyData] (Uint8List or hex String) is the unique canonical encoding of a valid
/// key or structure of [kind].
void validateKeyData(int kind, Object? keyData, {bool hederaNative = false}) {
  final k = kindInfo(kind);
  if (k.native) throw UAError('UAKindNotDerived', k.name);
  final d = keyBytes(keyData);
  if (k.lengths.isNotEmpty) _need(k.lengths.contains(d.length), 'length');
  switch (kind) {
    case 0x0100 || 0x0101:
      _p256Point(d);
    case 0x0102:
      _ed25519(d);
    case 0x0103:
      _secpX(d, 0);
    case 0x0104 || 0x0140:
      _bnG1(d, 0);
    case 0x0105 || 0x0141:
      _blsG1(d);
    case 0x0106:
      _blsG2(d);
    case 0x0107:
      _bnG2(d);
    case 0x0110:
      _musig2(d, _secpCompressed, 33);
    case 0x0111:
      _frost(d, _secpCompressed, 33, _secpN);
    case 0x0112:
      _musig2(d, _bnG1, 64);
    case 0x0113:
      _frost(d, _bnG1, 64, _bnR);
    case 0x0120:
      _msig(d, hederaNative);
    case 0x0132:
      _fndsa(d);
    default:
      break; // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
  }
}
