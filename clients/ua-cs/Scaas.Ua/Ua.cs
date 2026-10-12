// SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for .NET client systems: the kind table, ids, keyHash,
// purpose tags, ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data validation.
// The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Python and Go;
// smartcontracts/vectors/ua pins all six. UNAUDITED.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Digests;

namespace Scaas.Ua;

/// <summary>An error whose <see cref="Code"/> every implementation and the vector files share.</summary>
public sealed class UAException(string code, string? reason = null)
    : Exception(reason is null ? code : $"{code}: {reason}")
{
    public string Code { get; } = code;
    public string? Reason { get; } = reason;
}

/// <summary>One row of the kind table; <c>Lengths</c> empty = variable-length key data; <c>Group</c> null = none.</summary>
public sealed record Kind(ushort Number, string Name, bool Native, int[] Lengths, string? Group);

public static partial class UA
{
    public static readonly Kind[] Kinds =
    [
        new(0x0001, "evm-eoa", true, [20], null),
        new(0x0002, "evm-contract", true, [20], null),
        new(0x0003, "hedera-native", true, [20], null),
        new(0x0010, "solana-ed25519", true, [32], null),
        new(0x0011, "stellar-account", true, [32], null),
        new(0x0012, "soroban-contract", true, [32], null),
        new(0x0013, "aptos-account", true, [32], null),
        new(0x0014, "sui-address", true, [32], null),
        new(0x0015, "cosmos-account", true, [20, 32], null),
        new(0x0016, "ton-wallet", true, [32], null),
        new(0x0100, "webauthn-p256", false, [96], "p256"),
        new(0x0101, "p256", false, [64], "p256"),
        new(0x0102, "ed25519", false, [32], "ed25519"),
        new(0x0103, "bip340", false, [32], "secp256k1"),
        new(0x0104, "schnorr-bn254", false, [64], "bn254-g1"),
        new(0x0105, "schnorr-bls12381", false, [128], "bls12381-g1"),
        new(0x0106, "bls12381-minsig", false, [256], "bls12381-g2"),
        new(0x0107, "bls-bn254-minsig", false, [128], "bn254-g2"),
        new(0x0110, "musig2-secp256k1", false, [], "secp256k1"),
        new(0x0111, "frost-secp256k1", false, [], "secp256k1"),
        new(0x0112, "musig2-bn254", false, [], "bn254-g1"),
        new(0x0113, "frost-bn254", false, [], "bn254-g1"),
        new(0x0120, "msig", false, [], null),
        new(0x0130, "mldsa44", false, [1312], "mldsa44"),
        new(0x0131, "mldsa65", false, [1952], "mldsa65"),
        new(0x0132, "fndsa512", false, [897], "fndsa512"),
        new(0x0133, "slhdsa128s", false, [32], "slhdsa128s"),
        new(0x0140, "zether-bn254", false, [64], "bn254-g1"),
        new(0x0141, "zether-bls12381", false, [128], "bls12381-g1"),
        new(0x0142, "pqz-mlwe", false, [16384], "pqz-mlwe"),
    ];

    public static readonly string[] Groups =
        ["p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44", "mldsa65",
         "fndsa512", "slhdsa128s", "pqz-mlwe"];

    public static readonly string[] Purposes =
        ["pop", "authref", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop", "receiver-fee", "vp",
         "vc-anchor"];

    public const string DomainType =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
    public const string UAAuthType = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)";
    public const string RegistryName = "SCaaS UARegistry";

    public static byte[] Keccak256(params byte[][] parts)
    {
        var d = new KeccakDigest(256);
        foreach (var p in parts) d.BlockUpdate(p, 0, p.Length);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static readonly byte[] MsgTag = Keccak256(Utf8("scaas.ua.msg.v1"));

    public static Kind KindInfo(ushort kind) =>
        Array.Find(Kinds, k => k.Number == kind) ?? throw new UAException("UAKindUnknown", $"0x{kind:x4}");

    static Kind Derived(ushort kind)
    {
        var k = KindInfo(kind);
        return k.Native ? throw new UAException("UAKindNotDerived", k.Name) : k;
    }

    static bool SingleSigning(ushort k) => k is (>= 0x0100 and <= 0x0107) or (>= 0x0110 and <= 0x0113) or (>= 0x0130 and <= 0x0133);
    public static bool IsNative(ushort kind) => Array.Exists(Kinds, k => k.Number == kind && k.Native);
    public static bool IsZether(ushort kind) => kind is >= 0x0140 and <= 0x0142;
    public static bool IsSigning(ushort kind) => kind == 0x0120 || SingleSigning(kind);
    public static bool IsMember(ushort kind, bool hederaNative = false) =>
        SingleSigning(kind) || kind is 0x0001 or 0x0002 || (hederaNative && kind == 0x0003);

    public static string KindTagString(ushort kind) => $"scaas.ua.{Derived(kind).Name}.v1";
    public static byte[] Tag(ushort kind) => Keccak256(Utf8(KindTagString(kind)));

    public static string GroupTagString(string group) =>
        Array.IndexOf(Groups, group) >= 0 ? $"scaas.ua.group.{group}.v1" : throw new ArgumentException($"unknown keyHash group {group}");
    public static byte[] GroupTag(string group) => Keccak256(Utf8(GroupTagString(group)));

    public static byte[] PurposeTag(string purpose) =>
        Array.IndexOf(Purposes, purpose) >= 0 ? Keccak256(Utf8($"scaas.ua.purpose.{purpose}.v1")) : throw new UAException("UAPurposeUnknown", purpose);

    static byte[] Sized(byte[] b, int n, string what) => b.Length == n ? b : throw new ArgumentException($"{what} must be {n} bytes");

    /// <summary><c>keccak256(TAG(kind) ‖ keyData)</c>; no validation (see <see cref="DeriveUA"/>).</summary>
    public static byte[] UAOf(ushort kind, byte[] keyData) => Keccak256(Tag(kind), keyData);

    public static bool InNativeSpace(byte[] id) => Sized(id, 32, "id").AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0;

    /// <summary>Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03).</summary>
    public static byte[] DeriveUA(ushort kind, byte[] keyData, bool hederaNative = false)
    {
        ValidateKeyData(kind, keyData, hederaNative);
        var ua = UAOf(kind, keyData);
        return InNativeSpace(ua) ? throw new UAException("UAIdInNativeSpace", Convert.ToHexStringLower(ua)) : ua;
    }

    /// <summary>A native id left-padded to 32 bytes.</summary>
    public static byte[] NativeId(ushort kind, byte[] raw)
    {
        var k = KindInfo(kind);
        if (!k.Native) throw new UAException("UAKindNotNative", k.Name);
        if (Array.IndexOf(k.Lengths, raw.Length) < 0) throw new UAException("UAKeyData", "length");
        var id = new byte[32];
        raw.CopyTo(id, 32 - raw.Length);
        return id;
    }

    /// <summary><c>keccak256(GROUP(g) ‖ canonical pubkey)</c>, null for structures. Call on validated key data.</summary>
    public static byte[]? KeyHashOf(ushort kind, byte[] keyData)
    {
        var k = Derived(kind);
        if (k.Group is null) return null;
        var (lo, hi) = kind switch
        {
            0x0100 or 0x0101 => (0, 32),
            0x0110 or 0x0111 => (1, 33),
            0x0112 or 0x0113 => (0, 64),
            _ => (0, keyData.Length),
        };
        if (keyData.Length < hi) throw new UAException("UAKeyData", "length");
        return Keccak256(GroupTag(k.Group), keyData[lo..hi]);
    }

    public static byte[] UAMessage(ushort kind, byte[] purpose, byte[] digest) =>
        Keccak256(MsgTag, Tag(kind), Sized(purpose, 32, "purposeTag"), Sized(digest, 32, "digest"));

    public static byte[] ChainKeyHash(ulong chainId) => Keccak256(Utf8("evm:" + chainId.ToString(CultureInfo.InvariantCulture)));

    static byte[] Word(ulong v)
    {
        var w = new byte[32];
        for (var i = 0; i < 8; i++) w[31 - i] = (byte)(v >> (8 * i));
        return w;
    }

    static byte[] AddressWord(byte[] a)
    {
        var w = new byte[32];
        Sized(a, 20, "registry").CopyTo(w, 12);
        return w;
    }

    /// <summary><c>pop_digest</c> (CTR-UA-07).</summary>
    public static byte[] PopDigest(ulong chainId, byte[] chainUid, byte[] registry, byte[] ua, byte[] authRef) =>
        Keccak256(PurposeTag("pop"), ChainKeyHash(chainId), Sized(chainUid, 32, "chainUid"), AddressWord(registry),
            Sized(ua, 32, "ua"), Sized(authRef, 32, "authRef"));

    /// <summary>The registry's EIP-712 domain ("SCaaS UARegistry", "&lt;generation&gt;", chainId, registry, salt = chainUid).</summary>
    public sealed record Domain(uint Generation, ulong ChainId, byte[] Registry, byte[] ChainUid);

    public static byte[] UAAuthDomainSeparator(Domain d) =>
        Keccak256(Keccak256(Utf8(DomainType)), Keccak256(Utf8(RegistryName)),
            Keccak256(Utf8(d.Generation.ToString(CultureInfo.InvariantCulture))), Word(d.ChainId), AddressWord(d.Registry),
            Sized(d.ChainUid, 32, "chainUid"));

    /// <summary>EIP-712 digest of <c>UAAuth(ua, purpose, digest)</c>: what native signers behind the registry sign.</summary>
    public static byte[] UAAuthDigest(Domain d, byte[] ua, byte[] purpose, byte[] digest) =>
        Keccak256(new byte[] { 0x19, 0x01 }, UAAuthDomainSeparator(d),
            Keccak256(Keccak256(Utf8(UAAuthType)), Sized(ua, 32, "ua"), Sized(purpose, 32, "purposeTag"), Sized(digest, 32, "digest")));

    public static byte[] MemberDigest(byte[] structureUa, byte[] uaMsg) =>
        Keccak256(Sized(structureUa, 32, "structureUa"), Sized(uaMsg, 32, "uaMsg"));

    [GeneratedRegex(@"\A0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\z")]
    private static partial Regex IdPattern();

    /// <summary>Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03).</summary>
    public static string CanonicalId(string text)
    {
        var m = IdPattern().Match(text);
        if (!m.Success) throw new UAException("UAIdFormat", text);
        var h = m.Groups[1].Value.ToLowerInvariant();
        return "0x" + (h.Length == 64 && h.StartsWith(new string('0', 24), StringComparison.Ordinal) ? h[24..] : h);
    }

    /// <summary><c>u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)</c>.</summary>
    public static byte[] EncodeMsig(ushort threshold, IReadOnlyList<(ushort Kind, byte[] Id, ushort Weight)> members)
    {
        var o = new List<byte> { (byte)(threshold >> 8), (byte)threshold, (byte)(members.Count >> 8), (byte)members.Count };
        foreach (var (kind, id, weight) in members)
        {
            o.Add((byte)(kind >> 8));
            o.Add((byte)kind);
            o.AddRange(Sized(id, 32, "member id"));
            o.Add((byte)(weight >> 8));
            o.Add((byte)weight);
        }
        return [.. o];
    }
}
