// The registry's explicit arguments (typed-signing R1 / R1b: TS-D10 … TS-D13; owner KEM rulings 2026-10-31), as clientkeys
// registrationArgs and ua-rs registration_args. RegistryJson gives the named JSON of clientkeys and the node job API.
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Scaas.Ua;

public static partial class UA
{
    /// <summary>The largest calldata whose EIP-7976 floor (15,000 + 64 per byte) fits the EIP-7825 cap 2^24: 261,909 B.</summary>
    public const int RegisterCalldataLimit = ((1 << 24) - 15_000) / 64;

    /// <summary><c>kemPk = Scheme ‖ MlkemEk ‖ X25519</c> (TS-D11); the empty key is scheme 0, no ek, x25519 0.</summary>
    public sealed record KemKey(byte Scheme, byte[] MlkemEk, byte[] X25519);
    /// <summary>The registration's attributes: <c>KemPkHash</c> non-zero is the KEM hash commit (<c>Kem</c> = the scheme only).</summary>
    public sealed record UAAttrs(byte[] PqzKey, byte[] PqzPopHash, KemKey Kem, byte[] KemPkHash);
    public sealed record MsigMember(ushort Kind, byte[] Id, ushort Weight);
    /// <summary>CTR-UA-09 key data, typed (TS-D10).</summary>
    public sealed record MsigStructure(ushort Threshold, MsigMember[] Members);
    public sealed record WebAuthnKey(byte[] X, byte[] Y, byte[] RpIdHash);
    public sealed record MuSig2Key(byte[] AggKey, byte[][] MemberKeys);
    public sealed record FrostMember(byte[][] Commitments, byte[] R, byte[] Z);
    public sealed record FrostKey(byte[] GroupKey, ushort Threshold, FrostMember[] Members);
    /// <summary>One msig member's signature (<c>KeyData</c> empty for a stored kind).</summary>
    public sealed record MemberSig(ushort Index, byte[] KeyData, byte[] Sig);

    /// <summary><c>UASig</c> of requireAuthorized / setKemKey / setPqzKey (TS-D12): native — signature; a derived single key — keyData
    /// (empty for the stored kinds) + signature; an msig — members. A portable record's signature never has keyData.</summary>
    public sealed class UASig(byte[]? keyData = null, byte[]? signature = null, MemberSig[]? members = null)
    {
        public byte[] KeyData { get; } = keyData ?? [];
        public byte[] Signature { get; } = signature ?? [];
        public MemberSig[] Members { get; } = members ?? [];
    }

    public sealed record SetKemKeyArgs(byte[] UA, ulong Version, KemKey Kem, UASig Sig)
    {
        /// <summary>The ABI calldata length of setKemKey (selector included).</summary>
        public int CalldataLength() => 4 + 128 + KemLen(Kem) + 96 + TailLen(Sig.KeyData) + TailLen(Sig.Signature) + MemberSigsLen(Sig.Members);
    }

    public sealed record SetPqzKeyArgs(byte[] UA, byte[] PqzKey, byte[] PqzPopHash, UASig Sig);

    /// <summary>One registry call: register (Kind, KeyData), registerMsig (Structure), registerWebAuthn (Key) or registerMuSig2 /
    /// registerFrost (Kind, Key). <c>Pop</c>: byte[], or MemberSig[] for registerMsig.</summary>
    public sealed record RegisterArgs(string Entry, ushort? Kind, byte[]? KeyData, MsigStructure? Structure, object? Key, UAAttrs Attrs, byte[] PqzPop, object Pop)
    {
        /// <summary>The ABI calldata length of the call (selector included), as clientkeys registryCalldataLength.</summary>
        public int CalldataLength()
        {
            var rest = AttrsLen(Attrs) + TailLen(PqzPop);
            if (Pop is MemberSig[] ms) return 4 + 128 + 96 + 96 * Structure!.Members.Length + rest + MemberSigsLen(ms);
            rest += TailLen((byte[])Pop);
            return Key switch
            {
                WebAuthnKey => 4 + 192 + rest,
                MuSig2Key k => 4 + 160 + 64 + TailLen(k.AggKey) + BytesArrLen(k.MemberKeys) + rest,
                FrostKey k => 4 + 160 + 96 + TailLen(k.GroupKey) + 32 + k.Members.Sum(m => 32 + 96 + BytesArrLen(m.Commitments) + TailLen(m.R)) + rest,
                _ => 4 + 160 + TailLen(KeyData!) + rest,
            };
        }
    }

    static int TailLen(byte[] b) => 32 + (b.Length + 31) / 32 * 32; // a `bytes` tail: length word + padded data
    static int BytesArrLen(byte[][] xs) => 32 + xs.Sum(x => 32 + TailLen(x));
    static int KemLen(KemKey k) => 96 + TailLen(k.MlkemEk);
    static int AttrsLen(UAAttrs a) => 128 + TailLen(a.PqzKey) + KemLen(a.Kem);
    static int MemberSigsLen(MemberSig[] ms) => 32 + ms.Sum(m => 32 + 96 + TailLen(m.KeyData) + TailLen(m.Sig));

    sealed class HexConverter : JsonConverter<byte[]>
    {
        public override byte[] Read(ref Utf8JsonReader r, Type t, JsonSerializerOptions o) => Convert.FromHexString(r.GetString()![2..]);
        public override void Write(Utf8JsonWriter w, byte[] v, JsonSerializerOptions o) => w.WriteStringValue("0x" + Convert.ToHexStringLower(v));
    }

    static readonly JsonSerializerOptions RegistryJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new HexConverter() },
    };

    /// <summary>The named JSON of any value here: bytes as 0x-hex, numbers as numbers.</summary>
    public static string RegistryJson(object args) => JsonSerializer.Serialize(args, args.GetType(), RegistryJsonOptions);

    /// <summary>Splits an assembled <c>kemPk</c>; null / empty = the empty key.</summary>
    public static KemKey KemKeyOf(byte[]? kemPk)
    {
        var pk = kemPk ?? [];
        if (pk.Length == 0) return new(0, [], new byte[32]);
        if (pk.Length < 33) throw new UAException("UAKemKeyLength", pk.Length.ToString(CultureInfo.InvariantCulture));
        return new(pk[0], pk[1..^32], pk[^32..]);
    }

    /// <summary>Msig key data as its typed structure.</summary>
    public static MsigStructure MsigStructureOf(byte[] keyData)
    {
        var d = keyData;
        Need(d.Length >= 4 && d.Length == 4 + 36 * U16(d, 2), "length");
        return new((ushort)U16(d, 0), [.. Enumerable.Range(0, U16(d, 2)).Select(i => 4 + 36 * i)
            .Select(o => new MsigMember((ushort)U16(d, o), d[(o + 2)..(o + 34)], (ushort)U16(d, o + 34)))]);
    }

    /// <summary>R1b (TS-D13): the typed key of packed key data — WebAuthnKey, MuSig2Key or FrostKey (points of 33 B on secp256k1, 64 B
    /// on bn254); null for any other kind. The registry assembles the same bytes (same id).</summary>
    public static object? TypedKey(ushort kind, byte[] keyData)
    {
        var d = keyData;
        if (kind == 0x0100)
        {
            Need(d.Length == 96, "length");
            return new WebAuthnKey(d[..32], d[32..64], d[64..]);
        }
        var s = kind switch { 0x0110 or 0x0111 => 33, 0x0112 or 0x0113 => 64, _ => 0 };
        if (s == 0) return null;
        if (kind is 0x0110 or 0x0112)
        {
            var c = U16(d, s);
            Need(d.Length == s + 2 + c * s, "length");
            return new MuSig2Key(d[..s], [.. Enumerable.Range(0, c).Select(i => d[(s + 2 + i * s)..(s + 2 + (i + 1) * s)])]);
        }
        int t = U16(d, s), n = U16(d, s + 2);
        var per = (t + 1) * s + 32;
        Need(d.Length == s + 4 + n * per, "length");
        return new FrostKey(d[..s], (ushort)t, [.. Enumerable.Range(0, n).Select(i => s + 4 + i * per).Select(o => new FrostMember(
            [.. Enumerable.Range(0, t).Select(j => d[(o + j * s)..(o + (j + 1) * s)])], d[(o + t * s)..(o + (t + 1) * s)], d[(o + (t + 1) * s)..(o + per)]))]);
    }

    /// <summary><c>setKemKey(ua, version, kem, sig)</c>; <paramref name="sig"/> empty for the version-0 hash-commit fill.</summary>
    public static SetKemKeyArgs NewSetKemKeyArgs(byte[] ua, ulong version, byte[]? kemPk, UASig sig) => new(Sized(ua, 32, "ua"), version, KemKeyOf(kemPk), sig);

    /// <summary><c>setPqzKey(ua, pqzKey, pqzPopHash, sig)</c>.</summary>
    public static SetPqzKeyArgs NewSetPqzKeyArgs(byte[] ua, byte[] pqzKey, byte[] pqzPopHash, UASig sig) =>
        new(Sized(ua, 32, "ua"), pqzKey, Sized(pqzPopHash, 32, "pqzPopHash"), sig);

    /// <summary>The registry call of a registration (TS-D10 … TS-D13), as clientkeys registrationArgs. The KEM key is version 0 (owner
    /// 2026-10-31): in full, or, only when the full call is over <see cref="RegisterCalldataLimit"/> (X0: PQZH n2560-kmax16384 with a PQZ
    /// key) or <paramref name="kemCommit"/> is true, the hash commit (kem = {scheme, empty, 0}, kemPkHash = keccak256(kemPk)) plus
    /// <c>KemFill</c> = setKemKey(ua, 0, kem, UASig()), open to anyone (the pop signed the same record). <paramref name="kemCommit"/>
    /// false forces the full key. <paramref name="pop"/>: the signer's signature; <paramref name="members"/>: an msig's.</summary>
    public static (RegisterArgs Args, SetKemKeyArgs? KemFill) RegistrationArgs(ushort kind, byte[] keyData, byte[]? pqzKey = null, byte[]? pqzPopHash = null,
        byte[]? pqzPop = null, byte[]? kemPk = null, byte[]? pop = null, MemberSig[]? members = null, bool? kemCommit = null)
    {
        byte[] Or(byte[]? b) => b ?? [];
        var popHash = pqzKey is { Length: > 0 } || pqzPopHash is { Length: > 0 } ? ProofHashOf(pqzPop, pqzPopHash) : new byte[32];
        var attrs = new UAAttrs(Or(pqzKey), popHash, KemKeyOf(kemPk), new byte[32]);
        var key = TypedKey(kind, keyData);
        var (entry, withKind) = kind switch
        {
            0x0120 => ("registerMsig", false),
            0x0100 => ("registerWebAuthn", false),
            0x0110 or 0x0112 => ("registerMuSig2", true),
            0x0111 or 0x0113 => ("registerFrost", true),
            _ => ("register", true),
        };
        var msig = kind == 0x0120;
        var args = new RegisterArgs(entry, withKind ? kind : null, entry == "register" ? keyData : null, msig ? MsigStructureOf(keyData) : null, key,
            attrs, Or(pqzPop), msig ? members ?? [] : Or(pop));
        var full = Or(kemPk);
        if (full.Length == 0 || !(kemCommit ?? args.CalldataLength() > RegisterCalldataLimit)) return (args, null);
        args = args with { Attrs = attrs with { Kem = new(full[0], [], new byte[32]), KemPkHash = Keccak256(full) } };
        return (args, NewSetKemKeyArgs(UAOf(kind, keyData), 0, full, new UASig()));
    }
}
