// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
import 'dart:typed_data';

// Keccak-256 (original 0x01 padding, not SHA3's 0x06). Lanes are kept as two 32-bit halves so the code is exact when
// compiled to JS, where `int` is a double and bit operations are 32-bit.
const int _m = 0xFFFFFFFF;

final List<int> _rcLo = List.filled(24, 0), _rcHi = List.filled(24, 0);
final List<int> _rho = List.filled(25, 0);

bool _init = _setup();
bool _setup() {
  int bit(int t) {
    var r = 1;
    for (var i = 0; i < t % 255; i++) {
      r <<= 1;
      if (r & 0x100 != 0) r ^= 0x171;
    }
    return r & 1;
  }

  for (var ir = 0; ir < 24; ir++) {
    for (var j = 0; j < 7; j++) {
      if (bit(j + 7 * ir) == 1) {
        final pos = (1 << j) - 1; // bit position in the 64-bit lane
        if (pos < 32) {
          _rcLo[ir] |= 1 << pos;
        } else {
          _rcHi[ir] |= 1 << (pos - 32);
        }
      }
    }
  }
  var x = 1, y = 0;
  for (var t = 0; t < 24; t++) {
    _rho[x + 5 * y] = ((t + 1) * (t + 2) ~/ 2) % 64;
    final nx = y;
    y = (2 * x + 3 * y) % 5;
    x = nx;
  }
  return true;
}

void _f(Uint32List s) {
  final c = Uint32List(10), b = Uint32List(50);
  for (var round = 0; round < 24; round++) {
    for (var x = 0; x < 5; x++) {
      var lo = 0, hi = 0;
      for (var y = 0; y < 25; y += 5) {
        lo ^= s[2 * (x + y)];
        hi ^= s[2 * (x + y) + 1];
      }
      c[2 * x] = lo;
      c[2 * x + 1] = hi;
    }
    for (var x = 0; x < 5; x++) {
      final p = (x + 4) % 5, n = (x + 1) % 5;
      final nl = c[2 * n], nh = c[2 * n + 1];
      // rotl64(C[n], 1)
      final rl = ((nl << 1) | (nh >>> 31)) & _m,
          rh = ((nh << 1) | (nl >>> 31)) & _m;
      final dl = (c[2 * p] ^ rl) & _m, dh = (c[2 * p + 1] ^ rh) & _m;
      for (var y = 0; y < 25; y += 5) {
        s[2 * (x + y)] ^= dl;
        s[2 * (x + y) + 1] ^= dh;
      }
    }
    // rho + pi: B[y, 2x+3y] = rotl(A[x, y], rho)
    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        var lo = s[2 * (x + 5 * y)], hi = s[2 * (x + 5 * y) + 1];
        var n = _rho[x + 5 * y];
        if (n >= 32) {
          final t = lo;
          lo = hi;
          hi = t;
          n -= 32;
        }
        if (n > 0) {
          final nl = ((lo << n) | (hi >>> (32 - n))) & _m,
              nh = ((hi << n) | (lo >>> (32 - n))) & _m;
          lo = nl;
          hi = nh;
        }
        final d = y + 5 * ((2 * x + 3 * y) % 5);
        b[2 * d] = lo;
        b[2 * d + 1] = hi;
      }
    }
    // chi
    for (var y = 0; y < 25; y += 5) {
      for (var x = 0; x < 5; x++) {
        final a = 2 * (y + x),
            n1 = 2 * (y + (x + 1) % 5),
            n2 = 2 * (y + (x + 2) % 5);
        s[a] = (b[a] ^ ((~b[n1] & _m) & b[n2])) & _m;
        s[a + 1] = (b[a + 1] ^ ((~b[n1 + 1] & _m) & b[n2 + 1])) & _m;
      }
    }
    s[0] ^= _rcLo[round];
    s[1] ^= _rcHi[round];
  }
}

/// keccak-256 of the concatenation of [parts].
Uint8List keccak256(List<Uint8List> parts) {
  if (!_init) throw StateError('keccak tables');
  const rate = 136;
  var len = 0;
  for (final p in parts) {
    len += p.length;
  }
  final padded = Uint8List(((len ~/ rate) + 1) * rate);
  var o = 0;
  for (final p in parts) {
    padded.setRange(o, o + p.length, p);
    o += p.length;
  }
  padded[len] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  final s = Uint32List(50);
  for (var off = 0; off < padded.length; off += rate) {
    for (var i = 0; i < rate ~/ 4; i++) {
      final k = off + 4 * i;
      s[i] ^=
          padded[k] |
          padded[k + 1] << 8 |
          padded[k + 2] << 16 |
          padded[k + 3] << 24;
    }
    _f(s);
  }
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = (s[i ~/ 4] >>> (8 * (i % 4))) & 0xFF;
  }
  return out;
}
