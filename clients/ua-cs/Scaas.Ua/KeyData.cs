// Key-data validation (accounts.md §1.6 "Validation at registration") over System.Numerics.BigInteger: affine short
// Weierstrass arithmetic on y² = x³ + b over Fp and Fp2 (u² = −1) for curve and subgroup checks, twisted Edwards for
// ed25519. Public inputs only: nothing here is constant-time. Never indexes past the key data: every length is checked.
using System.Globalization;
using System.Numerics;

namespace Scaas.Ua;

public static partial class UA
{
    static BigInteger Hex(string h) => BigInteger.Parse("0" + h, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    static BigInteger Be(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: true);
    static BigInteger Mod(BigInteger a, BigInteger p) { var r = a % p; return r.Sign < 0 ? r + p : r; }
    static BigInteger Inv(BigInteger a, BigInteger p) => BigInteger.ModPow(Mod(a, p), p - 2, p);

    static readonly BigInteger SecpP = Hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    static readonly BigInteger SecpN = Hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    static readonly BigInteger P256P = Hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    static readonly BigInteger P256B = Hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    static readonly BigInteger EdP = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger EdD = Mod(-121665 * Inv(121666, EdP), EdP);
    static readonly BigInteger EdSqrtM1 = BigInteger.ModPow(2, (EdP - 1) / 4, EdP);
    static readonly BigInteger BnP = Hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    static readonly BigInteger BnR = Hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    static readonly BigInteger BlsP = Hex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    static readonly BigInteger BlsR = Hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    static void Need(bool ok, string reason)
    {
        if (!ok) throw new UAException("UAKeyData", reason);
    }

    // ----- Fp2 = Fp[u]/(u² + 1), points on y² = x³ + b (G1 uses A1 = 0) -----

    readonly record struct Fp2(BigInteger A0, BigInteger A1);

    sealed record Pt(Fp2 X, Fp2 Y);

    static Fp2 Add(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 + b.A0, p), Mod(a.A1 + b.A1, p));
    static Fp2 Sub(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 - b.A0, p), Mod(a.A1 - b.A1, p));
    static Fp2 Mul(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 * b.A0 - a.A1 * b.A1, p), Mod(a.A0 * b.A1 + a.A1 * b.A0, p));
    static Fp2 Inv2(Fp2 a, BigInteger p)
    {
        var n = Inv(a.A0 * a.A0 + a.A1 * a.A1, p);
        return new(Mod(a.A0 * n, p), Mod(-a.A1 * n, p));
    }

    static bool OnCurve(Fp2 x, Fp2 y, Fp2 b, BigInteger p) => Mul(y, y, p) == Add(Mul(Mul(x, x, p), x, p), b, p);

    static Pt? AddPt(Pt? a, Pt? c, BigInteger p)
    {
        if (a is null) return c;
        if (c is null) return a;
        Fp2 l;
        if (a.X == c.X)
        {
            if (a.Y != c.Y || (a.Y.A0.IsZero && a.Y.A1.IsZero)) return null; // P + (−P), or doubling a 2-torsion point
            var x2 = Mul(a.X, a.X, p);
            l = Mul(Add(Add(x2, x2, p), x2, p), Inv2(Add(a.Y, a.Y, p), p), p);
        }
        else
        {
            l = Mul(Sub(c.Y, a.Y, p), Inv2(Sub(c.X, a.X, p), p), p);
        }
        var x3 = Sub(Sub(Mul(l, l, p), a.X, p), c.X, p);
        return new Pt(x3, Sub(Mul(l, Sub(a.X, x3, p), p), a.Y, p));
    }

    /// <summary>[r]P == O by double-and-add.</summary>
    static bool InSubgroup(Fp2 x, Fp2 y, BigInteger r, BigInteger p)
    {
        Pt? acc = null, q = new Pt(x, y);
        for (var k = r; !k.IsZero; k >>= 1)
        {
            if (!k.IsEven) acc = AddPt(acc, q, p);
            q = AddPt(q, q, p);
        }
        return acc is null;
    }

    static void CurveAndSubgroup(Fp2 x, Fp2 y, Fp2 b, BigInteger r, BigInteger p)
    {
        Need(OnCurve(x, y, b, p), "curve");
        Need(InSubgroup(x, y, r, p), "subgroup");
    }

    // ----- per-curve checks -----

    static void SecpXY(ReadOnlySpan<byte> d)
    {
        var (x, y) = (Be(d[..32]), Be(d[32..64]));
        Need(x < SecpP && y < SecpP, "range");
        Need(Mod(y * y, SecpP) == Mod(x * x * x + 7, SecpP), "curve");
    }

    static void SecpX(ReadOnlySpan<byte> xb)
    {
        var x = Be(xb);
        Need(x < SecpP, "range");
        var rhs = Mod(x * x * x + 7, SecpP);
        var y = BigInteger.ModPow(rhs, (SecpP + 1) / 4, SecpP);
        Need(Mod(y * y, SecpP) == rhs, "curve");
    }

    static void SecpCompressed(ReadOnlySpan<byte> b)
    {
        Need(b[0] is 2 or 3, "prefix");
        SecpX(b[1..33]);
    }

    static void P256Point(ReadOnlySpan<byte> xy)
    {
        BigInteger x = Be(xy[..32]), y = Be(xy[32..64]);
        Need(x < P256P && y < P256P, "range");
        Need(Mod(y * y - (x * x * x - 3 * x + P256B), P256P).IsZero, "curve");
    }

    static (BigInteger, BigInteger) EdAdd((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) c)
    {
        var t = Mod(EdD * a.X * c.X * a.Y * c.Y, EdP);
        return (Mod((a.X * c.Y + c.X * a.Y) * Inv(1 + t, EdP), EdP), Mod((a.Y * c.Y + a.X * c.X) * Inv(1 - t, EdP), EdP));
    }

    static void Ed25519(ReadOnlySpan<byte> b)
    {
        var v = new BigInteger(b, isUnsigned: true, isBigEndian: false);
        var sign = (int)(v >> 255);
        var y = v & ((BigInteger.One << 255) - 1);
        Need(y < EdP, "range");
        var x2 = Mod((y * y - 1) * Inv(EdD * y * y + 1, EdP), EdP);
        var x = BigInteger.ModPow(x2, (EdP + 3) / 8, EdP);
        if (Mod(x * x - x2, EdP) != 0) x = Mod(x * EdSqrtM1, EdP);
        Need(Mod(x * x - x2, EdP).IsZero, "curve");
        Need(!(x.IsZero && sign == 1), "sign");
        if ((int)(x & 1) != sign) x = EdP - x;
        (BigInteger, BigInteger) pt = (x, y);
        for (var i = 0; i < 3; i++) pt = EdAdd(pt, pt);
        Need(pt != (BigInteger.Zero, BigInteger.One), "small-order");
    }

    static void BnG1(ReadOnlySpan<byte> b)
    {
        BigInteger x = Be(b[..32]), y = Be(b[32..64]);
        Need(x < BnP && y < BnP, "range");
        Need(!(x.IsZero && y.IsZero), "identity");
        Need(Mod(y * y - x * x * x - 3, BnP).IsZero, "curve");
    }

    static readonly Fp2 BnB2 = Mul(new Fp2(3, 0), Inv2(new Fp2(9, 1), BnP), BnP);

    static void BnG2(ReadOnlySpan<byte> b)
    {
        BigInteger xi = Be(b[..32]), xr = Be(b[32..64]), yi = Be(b[64..96]), yr = Be(b[96..128]);
        Need(xi < BnP && xr < BnP && yi < BnP && yr < BnP, "range");
        Need(!(xi.IsZero && xr.IsZero && yi.IsZero && yr.IsZero), "identity");
        CurveAndSubgroup(new Fp2(xr, xi), new Fp2(yr, yi), BnB2, BnR, BnP); // EIP-197: imaginary part first
    }

    static BigInteger BlsFp(ReadOnlySpan<byte> b)
    {
        Need(b[..16].IndexOfAnyExcept((byte)0) < 0, "padding");
        var v = Be(b[16..64]);
        Need(v < BlsP, "range");
        return v;
    }

    static void BlsG1(ReadOnlySpan<byte> b)
    {
        BigInteger x = BlsFp(b[..64]), y = BlsFp(b[64..128]);
        Need(!(x.IsZero && y.IsZero), "identity");
        CurveAndSubgroup(new Fp2(x, 0), new Fp2(y, 0), new Fp2(4, 0), BlsR, BlsP);
    }

    static void BlsG2(ReadOnlySpan<byte> b)
    {
        BigInteger x0 = BlsFp(b[..64]), x1 = BlsFp(b[64..128]), y0 = BlsFp(b[128..192]), y1 = BlsFp(b[192..256]);
        Need(!(x0.IsZero && x1.IsZero && y0.IsZero && y1.IsZero), "identity");
        CurveAndSubgroup(new Fp2(x0, x1), new Fp2(y0, y1), new Fp2(4, 4), BlsR, BlsP); // EIP-2537: c0 first
    }

    // ----- layouts -----

    delegate void PointCheck(ReadOnlySpan<byte> b);

    static int U16(ReadOnlySpan<byte> d, int o)
    {
        Need(d.Length >= o + 2, "length");
        return d[o] << 8 | d[o + 1];
    }

    static void Musig2(ReadOnlySpan<byte> d, PointCheck point, int size)
    {
        var n = U16(d, size);
        Need(n is >= 2 and <= 16, "n");
        Need(d.Length == size + 2 + n * size, "length");
        point(d[..size]);
        for (var i = 0; i < n; i++)
        {
            var o = size + 2 + i * size;
            point(d.Slice(o, size));
            if (i > 0) Need(d.Slice(o - size, size).SequenceCompareTo(d.Slice(o, size)) < 0, "order");
        }
    }

    static void Frost(ReadOnlySpan<byte> d, PointCheck point, int size, BigInteger order)
    {
        int t = U16(d, size), n = U16(d, size + 2);
        Need(t >= 2 && t <= n && n <= 16, "threshold");
        var per = (t + 1) * size + 32;
        Need(d.Length == size + 4 + n * per, "length");
        point(d[..size]);
        for (var i = 0; i < n; i++)
        {
            var o = size + 4 + i * per;
            for (var j = 0; j <= t; j++) point(d.Slice(o + j * size, size)); // t commitments, then R_i
            Need(Be(d.Slice(o + (t + 1) * size, 32)) < order, "scalar");
        }
    }

    static void Msig(ReadOnlySpan<byte> d, bool hederaNative)
    {
        int threshold = U16(d, 0), count = U16(d, 2);
        Need(count is >= 1 and <= 16, "count");
        Need(d.Length == 4 + 36 * count, "length");
        var total = 0;
        for (var i = 0; i < count; i++)
        {
            var o = 4 + 36 * i;
            var kind = (ushort)U16(d, o);
            var id = d.Slice(o + 2, 32);
            var weight = U16(d, o + 34);
            Need(IsMember(kind, hederaNative), "member-kind");
            Need(weight >= 1, "weight");
            Need(IsNative(kind) == (id[..12].IndexOfAnyExcept((byte)0) < 0), "member-id");
            if (i > 0) Need(d.Slice(o - 34, 32).SequenceCompareTo(id) < 0, "order");
            total += weight;
        }
        Need(threshold >= 1 && threshold <= total, "threshold");
    }

    static void Fndsa(ReadOnlySpan<byte> d)
    {
        Need(d[0] == 0x09, "header");
        for (var i = 0; i < 512; i++)
        {
            var v = 0;
            for (var j = 0; j < 14; j++)
            {
                var k = i * 14 + j;
                v = v << 1 | (d[1 + k / 8] >> (7 - k % 8)) & 1;
            }
            Need(v < 12289, "coefficient");
        }
    }

    /// <summary>Throws <c>UAException("UAKeyData")</c> unless the key data is the unique canonical encoding of a valid
    /// key or structure of <paramref name="kind"/>.</summary>
    public static void ValidateKeyData(ushort kind, byte[] keyData, bool hederaNative = false)
    {
        var k = Derived(kind);
        ReadOnlySpan<byte> d = keyData;
        if (k.Lengths.Length > 0) Need(Array.IndexOf(k.Lengths, d.Length) >= 0, "length");
        switch (kind)
        {
            case 0x0100: P256Point(d[..64]); break;
            case 0x0101: P256Point(d); break;
            case 0x0102: Ed25519(d); break;
            case 0x0103: SecpX(d); break;
            case 0x0104 or 0x0140: BnG1(d); break;
            case 0x0105 or 0x0141: BlsG1(d); break;
            case 0x0106: BlsG2(d); break;
            case 0x0107: BnG2(d); break;
            case 0x0108: SecpXY(d); break;
            case 0x0110: Musig2(d, SecpCompressed, 33); break;
            case 0x0111: Frost(d, SecpCompressed, 33, SecpN); break;
            case 0x0112: Musig2(d, BnG1, 64); break;
            case 0x0113: Frost(d, BnG1, 64, BnR); break;
            case 0x0120: Msig(d, hederaNative); break;
            case 0x0132: Fndsa(d); break;
            default: break; // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
        }
    }
}
