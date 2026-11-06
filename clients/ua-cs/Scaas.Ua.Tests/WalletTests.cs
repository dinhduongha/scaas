// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Scaas.Ua's P/Invoke binding (Wallet.cs) against smartcontracts/vectors/ua/{keys,sign,kem,seal,vault,zether}.json,
// clients/zether-prover/vectors/ and the PQZ facade; the load check, handle freeing and secret wiping of the binding itself.
// Needs libscaas_ua_c (cargo build --release in clients/ua-c, or SCAAS_UA_C_LIB). dotnet test Scaas.Ua.Tests
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Xunit;

namespace Scaas.Ua.Tests;

// one collection: the load test swaps the ABI hook, which every other test's constructor reads
[CollectionDefinition("wallet", DisableParallelization = true)]
public class WalletCollection { }

[Collection("wallet")]
public class WalletTests : IDisposable
{
    static readonly string Root = FindRoot();
    static readonly JsonElement Keys = Load("smartcontracts/vectors/ua/keys.json"), Sign = Load("smartcontracts/vectors/ua/sign.json"),
        Kem = Load("smartcontracts/vectors/ua/kem.json"), SealV = Load("smartcontracts/vectors/ua/seal.json"),
        Vault = Load("smartcontracts/vectors/ua/vault.json"), Zj = Load("smartcontracts/vectors/ua/zether.json");
    static readonly HashSet<ushort> Deterministic = [0x0101, 0x0102, 0x0106, 0x0107, 0x0108];
    const string Pqzl2304 = "0xef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e";
    const string Pqzl2048 = "0xc752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe";

    static string FindRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "smartcontracts", "vectors", "ua", "keys.json"))) return d.FullName;
        throw new FileNotFoundException("smartcontracts/vectors/ua not found above the test binary");
    }

    static JsonElement Load(string p) => JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, p))).RootElement;
    static byte[] B(JsonElement e) => B(e.GetString()!);
    static byte[] B(string s) => Convert.FromHexString(s.StartsWith("0x") ? s[2..] : s);
    static string Hx(byte[] b) => "0x" + Convert.ToHexStringLower(b);
    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    static string S(JsonElement e, string k) => e.GetProperty(k).GetString()!;
    static uint U(JsonElement e, string k) => e.GetProperty(k).GetUInt32();
    static bool Has(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null;
    static string? J(JsonElement e, string k) => Has(e, k) ? e.GetProperty(k).GetRawText() : null;
    static IEnumerable<JsonElement> Rows(JsonElement e, string k) => e.GetProperty(k).EnumerateArray();

    /// <summary>The status name a call throws, "" if it returns.</summary>
    static string Code(Action a)
    {
        try { a(); return ""; }
        catch (WalletException e) { return e.Code; }
    }

    readonly List<IDisposable> _keep = [];
    readonly Dictionary<string, Wallet> _ws = [];
    static readonly Dictionary<string, JsonElement> Mn = Rows(Keys, "mnemonics").ToDictionary(m => S(m, "id"));

    public void Dispose()
    {
        for (var i = _keep.Count - 1; i >= 0; i--) _keep[i].Dispose();
    }

    T Keep<T>(T x) where T : IDisposable { _keep.Add(x); return x; }

    Wallet Fresh(string mid) => Keep(Wallet.FromMnemonic(Utf8(S(Mn[mid], "words")), Utf8(S(Mn[mid], "passphrase"))));
    Wallet W(string mid) => _ws.TryGetValue(mid, out var w) ? w : _ws[mid] = Fresh(mid);
    WalletKey Key(Wallet w, JsonElement r) => Keep(w.UAKey(r.GetProperty("kind").GetUInt16(), U(r, "account"), U(r, "index")));
    WalletKey Key(Wallet w, ushort kind, uint account = 0, uint index = 0) => Keep(w.UAKey(kind, account, index));
    WalletKey Native(string mid, string net = "evm", uint index = 0, uint coin = UaLib.CoinDefault) =>
        Keep(W(mid).NativeKey((uint)Array.IndexOf(UaLib.Networks, net), index, coin));
    KemKey KemOf(JsonElement r, Wallet? w = null) =>
        Keep(Key(w ?? W(Has(r, "mnemonic") ? S(r, "mnemonic") : "pq_kat"), r).KemKey(ulong.Parse(r.GetProperty("version").GetRawText().Trim('"'))));

    // --- the binding's own checks ---

    [Fact]
    public void LoadRefusesWrongAbiOrFeatures()
    {
        UaLib.Load();
        UaLib.AbiVersionHook = _ => 5;
        UaLib.ResetLoad();
        try
        {
            Assert.Throws<LibraryMismatchException>(UaLib.Load);
            Assert.Throws<LibraryMismatchException>(() => Wallet.FromMnemonic(Utf8("abandon")));
            Assert.Throws<LibraryMismatchException>(() => KemKey.Ephemeral());
        }
        finally
        {
            UaLib.AbiVersionHook = v => v;
        }
        UaLib.Load();
        const ulong good = UaLib.FeatureWallet | UaLib.FeaturePq | UaLib.FeaturePqz | UaLib.FeaturePqzSetN2304Kmax4096;
        UaLib.CheckBuild(6, good);
        UaLib.CheckBuild(6, UaLib.FeatureWallet | UaLib.FeaturePq);
        foreach (var (abi, f) in new (uint, ulong)[] { (5, good), (7, good), (6, good & ~UaLib.FeatureWallet), (6, good & ~UaLib.FeaturePq), (6, good | 1UL << 12), (6, good | UaLib.FeatureVectors),
                     (6, good | UaLib.FeaturePqzSetN2048Kmax1024), (6, UaLib.FeatureWallet | UaLib.FeaturePq | UaLib.FeaturePqz),
                     (6, UaLib.FeatureWallet | UaLib.FeaturePq | UaLib.FeaturePqzSetN2304Kmax4096) })
            Assert.Throws<LibraryMismatchException>(() => UaLib.CheckBuild(abi, f));
    }

    [Fact]
    public void AbiVersionIs6AndFeatures()
    {
        Assert.Equal(6u, UaLib.AbiVersion());
        var f = UaLib.Features();
        Assert.True((f & UaLib.FeatureWallet) != 0 && (f & UaLib.FeaturePq) != 0 && (f & UaLib.FeatureExternal) == 0 && (f & UaLib.FeatureVectors) == 0);
        Assert.Equal("UAKindUnavailable", Code(() => UaLib.ExternalKeyNew("{\"kind\":257,\"keyData\":\"0x\"}")));
        Assert.Equal("UAPqzSetMismatch", UaLib.StatusName(40));
    }

    sealed class CountingHandle(int[] count) : UaHandle(new IntPtr(1234))
    {
        protected override void Free(IntPtr p) => count[0]++;
    }

    [Fact]
    public void HandleFreedExactlyOnce()
    {
        var n = new int[1];
        var h = new CountingHandle(n);
        h.Dispose();
        h.Dispose();
        h.Close();
        Assert.Equal(1, n[0]);
        Make(n);
        for (var i = 0; i < 50 && n[0] < 2; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
        Assert.Equal(2, n[0]);
        // a handle referenced by a call in flight is freed when the call releases it, not before
        var g = new CountingHandle(n);
        var added = false;
        g.DangerousAddRef(ref added);
        g.Dispose();
        Assert.Equal(2, n[0]);
        g.DangerousRelease();
        Assert.Equal(3, n[0]);
    }

    static void Make(int[] n) => _ = new CountingHandle(n);

    [Fact]
    public void UseAfterDisposeNeverReachesTheLibrary()
    {
        var w = Wallet.FromMnemonic(Utf8(S(Mn["pq_kat"], "words")));
        var k = w.UAKey(0x0102, 0, 0);
        k.Dispose();
        w.Dispose();
        Assert.Throws<ObjectDisposedException>(() => k.KeyData());
        Assert.Throws<ObjectDisposedException>(() => w.UAKey(0x0102, 0, 0));
    }

    [Fact]
    public void SecretBufferWipedAfterCall()
    {
        var seen = new List<byte[]>();
        var real = UaLib.SecretBuf;
        UaLib.SecretBuf = n => { var x = real(n); seen.Add(x); return x; };
        void Through(string label, Action a)
        {
            var n = seen.Count;
            a();
            Assert.True(seen.Count > n, label + ": no secret buffer");
            foreach (var x in seen.Skip(n)) Assert.True(x.All(c => c == 0), label + ": not wiped");
        }
        try
        {
            var m = Mn["pq_kat"];
            Wallet w = null!;
            Through("FromMnemonic", () => w = Keep(Wallet.FromMnemonic(Utf8(S(m, "words")), Utf8(S(m, "passphrase")))));
            string v = "";
            Through("SealVault", () => v = w.SealVault(Utf8("correct horse 9")));
            Through("OpenVault", () => Keep(Wallet.OpenVault(v, Utf8("correct horse 9"))));
            Through("Unlock", () => { var w2 = Fresh("pq_kat"); w2.Lock(); w2.Unlock(v, Utf8("correct horse 9")); });
            string v2 = "";
            Through("VaultRewrapPin", () => v2 = UaLib.VaultRewrapPin(v, Utf8("correct horse 9"), Utf8("battery staple 7")));
            Through("VaultEnablePrf", () => UaLib.VaultEnablePrf(v2, Utf8("battery staple 7"), new byte[32], "c", Utf8("s")));
            Through("SealLabelVault", () =>
            {
                Keep(w.ImportNativeKey(0, Enumerable.Repeat((byte)1, 32).ToArray()));
                w.SealLabelVault("native-import:evm:0", Utf8("correct horse 9"));
            });
            Through("Verify", () =>
            {
                var (g, sb) = Wallet.Generate();
                Keep(g);
                Keep(sb);
                var words = sb.Reveal();
                var ws = Encoding.UTF8.GetString(words).Split(' ');
                var pos = sb.Challenge();
                Assert.True(sb.Verify(pos.Select(i => Utf8(ws[i - 1])).ToArray()));
                var e = sb.Take()!;
                Assert.Equal(32, e.Length);
                UaLib.Wipe(words);
                UaLib.Wipe(e);
                Assert.True(e.All(c => c == 0) && words.All(c => c == 0));
            });
            var leaf = w.ExportPqzLeafRaw(0, 0);
            Assert.Contains(leaf, c => c != 0);
            UaLib.Wipe(leaf);
            Assert.True(leaf.All(c => c == 0));
        }
        finally
        {
            UaLib.SecretBuf = real;
        }
    }

    [Fact]
    public void FixedSizeAndShortSecretsAreRefused()
    {
        Assert.Equal("UAKeyData", Code(() => W("pq_kat").Unlock("{}", null, new byte[31])));
        Assert.Equal("UAKeyData", Code(() => UaLib.AeadSeal(1, new byte[31], new byte[12], [], Utf8("x"))));
        Assert.Equal("UAKeyData", Code(() => UaLib.AeadOpen(1, new byte[32], new byte[11], [], new byte[20])));
        Assert.Equal("UAKeyData", Code(() => Key(W("pq_kat"), 0x0101).SignUA(new byte[31], new byte[32])));
    }

    // --- keys.json ---

    [Fact]
    public void KeysJson()
    {
        var falcon = (UaLib.Features() & UaLib.FeatureFalcon) != 0;
        var n = 0;
        foreach (var r in Rows(Keys, "ua"))
        {
            var kind = r.GetProperty("kind").GetUInt16();
            if (kind is 0x0132 or 0x0135 && !falcon) continue;
            var kd = Key(W(S(r, "mnemonic")), r).KeyData();
            Assert.Equal(S(r, "keyData"), Hx(kd));
            if (Has(r, "ua")) Assert.Equal(S(r, "ua"), Hx(UA.DeriveUA(kind, kd)));
            n++;
        }
        Assert.True(n >= 184, n.ToString());
        foreach (var r in Rows(Keys, "native"))
        {
            var coin = Has(r, "coinType") ? U(r, "coinType") : UaLib.CoinDefault;
            Assert.Equal(S(r, "publicKey").Replace("0x", ""), Convert.ToHexStringLower(Native(S(r, "mnemonic"), S(r, "network"), U(r, "index"), coin).KeyData()));
        }
        foreach (var r in Rows(Keys, "refusals"))
        {
            var w = W(S(r, "mnemonic"));
            var c = S(r, "what") == "ua"
                ? Code(() => Keep(w.UAKey(r.GetProperty("kind").GetUInt16(), U(r, "account"), U(r, "index"))))
                : Code(() => Keep(w.NativeKey((uint)Array.IndexOf(UaLib.Networks, S(r, "network")), U(r, "index"),
                    Has(r, "coinType") ? U(r, "coinType") : UaLib.CoinDefault)));
            Assert.Equal("UA" + S(r, "error"), c);
        }
    }

    // --- sign.json ---

    [Fact]
    public void SignJsonUAAndMember()
    {
        var falcon = (UaLib.Features() & UaLib.FeatureFalcon) != 0;
        var exact = 0;
        foreach (var r in Rows(Sign, "ua"))
        {
            var kind = r.GetProperty("kind").GetUInt16();
            if (kind is 0x0132 or 0x0135 && !falcon) continue;
            var sig = Key(W(S(r, "mnemonic")), r).SignUA(B(r.GetProperty("purposeTag")), B(r.GetProperty("digest")));
            if (Deterministic.Contains(kind)) { Assert.Equal(S(r, "signature"), Hx(sig)); exact++; }
            else if (kind is not (0x0132 or 0x0135)) Assert.Equal(B(r.GetProperty("signature")).Length, sig.Length);
        }
        Assert.True(exact >= 10);
        foreach (var r in Rows(Sign, "member"))
        {
            var sig = Key(W(S(r, "mnemonic")), r).SignMember(B(r.GetProperty("structureUa")), B(r.GetProperty("structureUaMsg")));
            if (Deterministic.Contains(r.GetProperty("kind").GetUInt16())) Assert.Equal(S(r, "signature"), Hx(sig));
            else Assert.Equal(B(r.GetProperty("signature")).Length, sig.Length);
        }
    }

    [Fact]
    public void SignJsonPolicyTypedTx()
    {
        var k = Native("pq_kat");
        int signed = 0, refused = 0;
        foreach (var r in Rows(Sign, "policy"))
        {
            if (Has(r, "refused")) { Assert.Equal("UAPolicyRefused", Code(() => k.SignTyped(J(r, "td")!, J(r, "expect")!))); refused++; }
            else { Assert.Equal(k.SignDigestRaw(B(r.GetProperty("digest"))), k.SignTyped(J(r, "td")!, J(r, "expect")!)); signed++; }
        }
        Assert.Equal((10, 14), (signed, refused));
        var typed = Sign.GetProperty("typed");
        foreach (var r in Rows(typed, "generic")) Assert.Equal(k.SignDigestRaw(B(r.GetProperty("digest"))), k.SignTypedAny(J(r, "td")!));
        foreach (var r in Rows(typed, "refusals")) Assert.Equal("UAArgument", Code(() => k.SignTypedAny(J(r, "td")!)));
        var tx = Sign.GetProperty("tx");
        foreach (var r in Rows(tx, "rows"))
        {
            var s = r.GetProperty("signer");
            Assert.Equal(S(r, "raw"), Hx(Native(S(s, "mnemonic"), S(s, "network"), U(s, "index")).SignTransaction(J(r, "tx")!)));
        }
        foreach (var r in Rows(tx, "refusals")) Assert.Equal("UAArgument", Code(() => k.SignTransaction(J(r, "tx")!)));
        Assert.Equal("UARawDigestRefused", Code(() => Key(W("pq_kat"), 0x0108).SignDigestRaw(new byte[32])));
        Assert.Equal(65, k.SignKeyProof(Utf8("challenge")).Length);
        Assert.Equal("UAArgument", Code(() => Key(W("pq_kat"), 0x0101).SignKeyProof(Utf8("challenge"))));
    }

    [Fact]
    public void SignJsonWebAuthn()
    {
        var wa = Sign.GetProperty("webauthn");
        foreach (var r in Rows(wa, "accepted"))
        {
            var ch = UaLib.WebAuthnChallenge(B(r.GetProperty("purposeTag")), B(r.GetProperty("digest")));
            Assert.Equal(S(r, "expectedChallenge"), Hx(ch));
            Assert.Equal(UA.UAMessage(0x0100, B(r.GetProperty("purposeTag")), B(r.GetProperty("digest"))), ch);
        }
        foreach (var r in Rows(wa, "accepted").Concat(Rows(wa, "refusals")))
        {
            byte[]? got = null;
            var c = Code(() => got = UaLib.WebAuthnAssertion(B(r.GetProperty("keyData")), B(r.GetProperty("expectedChallenge")), B(r.GetProperty("authData")),
                B(r.GetProperty("clientDataJSON")), B(r.GetProperty("r")), B(r.GetProperty("s"))));
            if (Has(r, "error")) Assert.Equal("UA" + S(r, "error"), c);
            else Assert.Equal(S(r, "assertion"), Hx(got!));
        }
    }

    static byte[] Word(BigInteger x) => x.ToByteArray(isUnsigned: true, isBigEndian: true) is var b && b.Length <= 32 ? new byte[32 - b.Length].Concat(b).ToArray() : throw new ArgumentException();
    static byte[] AbiBytes(byte[] x) => Word(x.Length).Concat(x).Concat(new byte[(32 - x.Length % 32) % 32]).ToArray();
    static byte[] AbiList(List<byte[]> items)
    {
        var o = new List<byte>(Word(items.Count));
        var off = 32 * items.Count;
        foreach (var it in items) { o.AddRange(Word(off)); off += it.Length; }
        foreach (var it in items) o.AddRange(it);
        return [.. o];
    }

    /// <summary>abi.encode(MemberSig[]) of a UASig JSON's members (ua8.rs encode_member_sigs).</summary>
    static byte[] MemberSigs(JsonElement ms)
    {
        if (ms.GetArrayLength() == 0) return [];
        var slots = new List<byte[]>();
        foreach (var m in ms.EnumerateArray())
        {
            var inner = m.GetProperty("members").EnumerateArray()
                .Select(x => Word(x.GetProperty("index").GetInt32()).Concat(Word(64)).Concat(AbiBytes(B(x.GetProperty("sig"))))
                .ToArray()).ToList();
            var lst = AbiList(inner);
            slots.Add([.. Word(m.GetProperty("index").GetInt32()), .. Word(96), .. Word(96 + lst.Length), .. lst, .. AbiBytes(B(m.GetProperty("sig")))]);
        }
        return [.. Word(32), .. AbiList(slots)];
    }

    [Fact]
    public void SignJsonMsigThroughUASig()
    {
        int built = 0, refused = 0;
        foreach (var r in Rows(Sign, "msig"))
        {
            var keys = new List<WalletKey>();
            int Pos(JsonElement x)
            {
                var k = x.GetProperty("key");
                keys.Add(Key(W(S(k, "mnemonic")), k));
                return keys.Count - 1;
            }
            var slots = new JsonArray();
            foreach (var s in Rows(r, "slots"))
            {
                if (s.TryGetProperty("members", out var ms))
                    slots.Add(new JsonObject { ["index"] = s.GetProperty("index").GetInt32(), ["members"] = new JsonArray(ms.EnumerateArray()
                        .Select(x => (JsonNode)new JsonObject { ["index"] = x.GetProperty("index").GetInt32(), ["key"] = Pos(x) }).ToArray()) });
                else slots.Add(new JsonObject { ["index"] = s.GetProperty("index").GetInt32(), ["key"] = Pos(s) });
            }
            var m = new JsonObject { ["keyData"] = S(r, "keyData"), ["slots"] = slots };
            if (Has(r, "inner")) m["inner"] = JsonNode.Parse(J(r, "inner")!);
            var req = new JsonObject { ["purpose"] = S(r, "purposeTag"), ["digest"] = S(r, "digest"), ["msig"] = m }.ToJsonString();
            if (Has(r, "refused")) { Assert.Equal(S(r, "refused"), Code(() => UaLib.UASig(req, keys))); refused++; continue; }
            var sig = JsonDocument.Parse(UaLib.UASig(req, keys)).RootElement;
            Assert.Equal(S(r, "memberSigs"), Hx(MemberSigs(sig.GetProperty("members"))));
            built++;
        }
        Assert.Equal((3, 4), (built, refused));
    }

    // --- kem.json ---

    [Fact]
    public void KemJson()
    {
        foreach (var r in Rows(Kem, "keys")) Assert.Equal(S(r, "kemPk"), Hx(KemOf(r).KemPk()));
        foreach (var r in Rows(Kem, "refusals"))
        {
            if (!Has(r, "mnemonic") || r.GetProperty("version").ValueKind != JsonValueKind.Number || !r.GetProperty("version").TryGetUInt64(out var ver))
                continue; // the msig row; 2^64 is not a ulong
            var k = Key(W(S(r, "mnemonic")), r);
            Assert.Equal("UA" + S(r, "error"), Code(() => Keep(k.KemKey(ver))));
        }
        foreach (var r in Rows(Kem, "encapsRefusals")) Assert.Equal("UA" + S(r, "error"), Code(() => UaLib.KemEncaps(B(r.GetProperty("kemPk")))));
        var k0 = Rows(Kem, "keys").First();
        var (ct, e, ss) = UaLib.KemEncaps(B(k0.GetProperty("kemPk")));
        Assert.Equal(ss, KemOf(k0).Decaps(ct, e));
        foreach (var r in Rows(Kem, "decaps"))
        {
            if (B(r.GetProperty("x25519Eph")).Length != 32) continue; // a 31-byte E: refused before the library (FixedSize...)
            byte[]? got = null;
            var c = Code(() => got = KemOf(r.GetProperty("key")).Decaps(B(r.GetProperty("mlkemCt")), B(r.GetProperty("x25519Eph"))));
            if (Has(r, "error") && S(r, "error") != "") Assert.Equal("UA" + S(r, "error"), c);
            else Assert.Equal(S(r, "ss"), Hx(got!));
        }
        Assert.Equal(1, Keep(KemKey.Ephemeral()).KemPk()[0]);
    }

    // --- seal.json ---

    KemKey Opener(JsonElement r) => KemOf(r.GetProperty("opener").GetProperty("kem"));

    [Fact]
    public void SealJsonRowsAndRefusals()
    {
        foreach (var r in Rows(SealV, "seal"))
        {
            if (!Has(r.GetProperty("recipient"), "kind")) continue; // an ephemeral recipient from a fixed seed: under `vectors` only
            var kk = KemOf(r.GetProperty("recipient"));
            var pt = kk.Open(S(r, "purpose"), B(r.GetProperty("aad")), B(r.GetProperty("mlkemCt")), B(r.GetProperty("x25519Eph")), B(r.GetProperty("ciphertext")));
            Assert.Equal(S(r, "pt"), Hx(pt));
            var (mct, e, ct) = UaLib.Seal(B(r.GetProperty("kemPk")), S(r, "purpose"), B(r.GetProperty("aad")), pt);
            Assert.Equal((UaLib.KemCtLen, pt.Length + 16), (mct.Length, ct.Length));
            Assert.Equal(pt, kk.Open(S(r, "purpose"), B(r.GetProperty("aad")), mct, e, ct));
        }
        var rf = SealV.GetProperty("refusals");
        var b = Rows(SealV, "seal").First(x => S(x, "id") == S(rf, "base"));
        const int n = UaLib.KemCtLen;
        foreach (var r in Rows(rf, "rows"))
        {
            var wire = B(Has(r, "wire") ? r.GetProperty("wire") : b.GetProperty("wire"));
            if (wire[0] != 1 || wire[1] != 1) continue; // version or scheme 2: the named fields carry neither
            var kk = KemOf(Has(r, "key") ? r.GetProperty("key") : rf.GetProperty("key"));
            var aad = B(Has(r, "aad") ? r.GetProperty("aad") : b.GetProperty("aad"));
            var purpose = Has(r, "purpose") ? S(r, "purpose") : S(b, "purpose");
            Assert.Equal("UA" + S(r, "error"), Code(() => kk.Open(purpose, aad, wire[2..(2 + n)], wire[(2 + n)..(2 + n + 32)], wire[(2 + n + 32)..])));
        }
        var pk = B(Rows(SealV, "seal").First().GetProperty("kemPk"));
        foreach (var r in Rows(SealV, "argumentRefusals"))
            Assert.Equal("UA" + S(r, "error"), Code(() => UaLib.Seal(pk, S(r, "purpose"), [], new byte[r.GetProperty("ptLength").GetInt32()])));
    }

    [Fact]
    public void SealJsonContainersAndAcceptance()
    {
        var n = 0;
        foreach (var r in Rows(SealV, "containers"))
        {
            if (Has(r.GetProperty("opener"), "session")) continue; // a link container opens only through its session
            Assert.Equal(S(r, "pt"), Hx(Opener(r).OpenContainer(J(r, "container")!, J(r, "expect")!, J(r, "members"), J(r, "accepted"))));
            if (Has(r, "accepted"))
                Assert.Equal("UAContainerSender", Code(() => Opener(r).OpenContainer(J(r, "container")!, J(r, "expect")!, J(r, "members"), null)));
            n++;
        }
        Assert.Equal(3, n);
        n = 0;
        foreach (var r in Rows(SealV, "acceptance"))
        {
            if (Has(r, "link")) continue; // a fixed session exists under `vectors` only
            var kk = Opener(r);
            var c = Has(r, "restore") && r.GetProperty("restore").GetBoolean()
                ? Code(() => Wallet.RestoreBackup(kk, J(r, "container")!, J(r, "expect")!, J(r, "members"), J(r, "accepted"))?.Dispose())
                : Code(() => kk.OpenContainer(J(r, "container")!, J(r, "expect")!, J(r, "members"), J(r, "accepted")));
            Assert.Equal(Has(r, "error") && S(r, "error") != "" ? "UA" + S(r, "error") : "", c);
            n++;
        }
        Assert.Equal(28, n);
    }

    string UaOf(ushort kind, WalletKey k) => Hx(UA.DeriveUA(kind, k.KeyData()));

    [Fact]
    public void SealJsonReplayBackupRows()
    {
        var pk = B(Rows(Kem, "keys").First().GetProperty("kemPk"));
        var n = 0;
        foreach (var r in Rows(SealV, "replay"))
        {
            if (S(r, "kind") != "backup") continue; // link windows: a session starts now in a release build
            Wallet? cur = null;
            if (Has(r, "current"))
            {
                var c = r.GetProperty("current");
                cur = Fresh(UaOf(0x0102, Key(W("twelve_words"), 0x0102)) == S(c, "ua") ? "twelve_words" : "pq_kat");
                var k = Key(cur, 0x0102);
                var rk = Key(W("pq_kat"), 0x0130).KeyData();
                for (var i = 0; i < c.GetProperty("generation").GetInt32(); i++)
                    cur.BackupSeal(k, [new Recipient(0x0130, rk, 0, pk)]);
            }
            var rollback = Has(r, "allowRollback") && r.GetProperty("allowRollback").GetBoolean();
            Wallet? got = null;
            var code = Code(() => got = rollback
                ? Wallet.RestoreBackupRollback(Opener(r), J(r, "container")!, J(r, "expect")!, null, null, cur)
                : Wallet.RestoreBackup(Opener(r), J(r, "container")!, J(r, "expect")!, null, null, cur));
            if (Has(r, "error") && S(r, "error") != "") Assert.Equal("UA" + S(r, "error"), code);
            else Assert.Equal(("", r.GetProperty("install").GetBoolean()), (code, got is not null));
            got?.Dispose();
            n++;
        }
        Assert.Equal(6, n);
    }

    [Fact]
    public void BackupSealRestoresAWallet()
    {
        var w = Fresh("twelve_words");
        var sender = Key(w, 0x0102);
        Key(w, 0x0101, 0, 1);
        var k0 = Rows(Kem, "keys").First();
        var rkey = Key(W("pq_kat"), 0x0130);
        var (rk, pk) = (rkey.KeyData(), B(k0.GetProperty("kemPk")));
        var cs = JsonDocument.Parse(w.BackupSeal(sender, [new Recipient(0x0130, rk, 0, pk), new Recipient(0, [], 0, pk, Ephemeral: true)])).RootElement;
        Assert.Equal(2, cs.GetArrayLength());
        var expect = new JsonObject { ["purpose"] = "scaas/backup/v1", ["sender"] = new JsonObject { ["ua"] = UaOf(0x0102, sender) },
            ["recipient"] = new JsonObject { ["ua"] = UaOf(0x0130, rkey), ["version"] = 0 } }.ToJsonString();
        var o = Keep(Wallet.RestoreBackup(KemOf(k0), cs[0].GetRawText(), expect)!);
        Assert.Equal(sender.KeyData(), Key(o, 0x0102).KeyData());
        var m = JsonDocument.Parse(o.ManifestJson()).RootElement;
        Assert.Equal((1, 2), (m.GetProperty("backupGeneration").GetInt32(), m.GetProperty("entries").GetArrayLength()));
        Assert.Equal("UAArgument", Code(() => w.BackupSeal(sender, [])));
    }

    [Fact]
    public void LinkSessionAndLinkSeal()
    {
        var s = Keep(LinkSession.New());
        var pk = s.KemPk();
        Assert.Matches(new Regex("^[0-9]{8}$"), s.ShortCode());
        var r = Rows(SealV, "containers").First(x => Has(x.GetProperty("opener"), "session"));
        var expect = JsonNode.Parse(J(r, "expect")!)!.AsObject();
        expect["recipient"] = new JsonObject { ["kemPkHash"] = Hx(UA.Keccak256(pk)) };
        Assert.Equal("UAContainerReplay", Code(() => Wallet.FromLink(s, J(r, "container")!, expect.ToJsonString())));
        Assert.Equal("UAKeyRevoked", Code(() => Wallet.FromLink(s, J(r, "container")!, expect.ToJsonString())));
        var w = Fresh("twelve_words");
        var key = Key(w, 0x0102);
        Keep(w.ImportNativeKey(0, Enumerable.Repeat((byte)3, 32).ToArray()));
        foreach (var wrong in new[] { false, true })
        {
            var ls = Keep(LinkSession.New());
            var (lpk, sc) = (ls.KemPk(), ls.ShortCode());
            if (wrong) sc = sc == "00000000" ? "00000001" : "00000000";
            var c = w.LinkSeal(key, lpk, sc);
            var ex = new JsonObject { ["purpose"] = "scaas/link/v1", ["sender"] = new JsonObject { ["ua"] = UaOf(0x0102, key) },
                ["recipient"] = new JsonObject { ["kemPkHash"] = Hx(UA.Keccak256(lpk)) } }.ToJsonString();
            if (wrong) { Assert.Equal("UASealOpen", Code(() => Wallet.FromLink(ls, c, ex))); continue; }
            var o = Keep(Wallet.FromLink(ls, c, ex));
            Assert.Equal(key.KeyData(), Key(o, 0x0102).KeyData());
            Assert.Contains("\"imports\":[{\"network\":\"evm\",\"n\":0}]", o.ManifestJson());
        }
        Assert.Equal("UAKemCheck", Code(() => w.LinkSeal(key, pk[..^1], "12345678")));
    }

    // --- vault.json ---

    static (byte[]? pin, byte[]? prf) UnlockOf(JsonElement u) =>
        (Has(u, "pin") ? Utf8(S(u, "pin")) : null, Has(u, "prfOutput") ? B(u.GetProperty("prfOutput")) : null);

    [Fact]
    public void VaultJson()
    {
        var byEntropy = Mn.Values.Where(m => S(m, "passphrase") == "").ToDictionary(m => S(m, "entropy"), m => S(m, "id"));
        foreach (var r in Rows(Vault, "vaults"))
        {
            var (pin, prf) = UnlockOf(r.GetProperty("unlock"));
            var w = Keep(Wallet.OpenVault(J(r, "vault")!, pin, prf));
            Assert.Equal(Key(W(byEntropy[S(r, "plaintext")]), 0x0102).KeyData(), Key(w, 0x0102).KeyData());
        }
        foreach (var r in Rows(Vault, "refusals"))
        {
            var (pin, prf) = UnlockOf(r.GetProperty("unlock"));
            Assert.Equal("UA" + S(r, "error"), Code(() => Wallet.OpenVault(J(r, "vault")!, pin, prf).Dispose()));
        }
        Assert.Equal("UAArgument", Code(() => Wallet.OpenVault(J(Rows(Vault, "vaults").First(), "vault")!, null, null)));
        var tw = W("twelve_words");
        var v1 = tw.SealVault(Utf8("correct horse 9"));
        Assert.Equal("UAArgument", Code(() => tw.SealVault(Utf8("12345678"))));
        Assert.False(UaLib.VaultNeedsRewrap(v1));
        var v2 = UaLib.VaultRewrapPin(v1, Utf8("correct horse 9"), Utf8("battery staple 7"));
        var prf32 = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var v3 = UaLib.VaultEnablePrf(v2, Utf8("battery staple 7"), prf32, "cred-1", Utf8("salt"));
        var want = Key(tw, 0x0102).KeyData();
        foreach (var (v, pin, prf) in new (string, byte[]?, byte[]?)[] { (v1, Utf8("correct horse 9"), null), (v2, Utf8("battery staple 7"), null), (v3, null, prf32) })
            Assert.Equal(want, Key(Keep(Wallet.OpenVault(v, pin, prf)), 0x0102).KeyData());
        Assert.Equal("UAVaultOpen", Code(() => Wallet.OpenVault(v2, Utf8("correct horse 9"))));
    }

    // --- custody ---

    [Fact]
    public void Custody()
    {
        var w = Fresh("twelve_words");
        var v = w.SealVault(Utf8("correct horse 9"));
        var k = Key(w, 0x0101);
        var tag = UA.PurposeTag("metatx");
        var before = k.SignUA(tag, new byte[32]);
        var imp = Keep(w.ImportNativeKey(0, Enumerable.Repeat((byte)1, 32).ToArray()));
        var d9 = new byte[32];
        d9[0] = 9;
        var rawBefore = imp.SignDigestRaw(d9);
        var label = w.SealLabelVault("native-import:evm:0", Utf8("correct horse 9"));
        w.Lock();
        Assert.Equal("UAKeyRevoked", Code(() => k.SignUA(tag, new byte[32])));
        Assert.Equal("UAWalletLocked", Code(() => w.UAKey(0x0101, 0, 0)));
        Assert.Equal(new MemoryProtection(0, 0, 0), w.MemoryProtection());
        w.Unlock(v, Utf8("correct horse 9"));
        Assert.Equal("UAKeyRevoked", Code(() => k.SignUA(tag, new byte[32])));
        Assert.Equal(before, Key(w, 0x0101).SignUA(tag, new byte[32]));
        Assert.Equal("UAArgument", Code(() => w.ImportedKey(0, 0)));
        Assert.Equal("UAVaultOpen", Code(() => w.OpenLabelVault(label, Utf8("wrong horse 9"))));
        w.OpenLabelVault(label, Utf8("correct horse 9"));
        Assert.Equal(rawBefore, Keep(w.ImportedKey(0, 0)).SignDigestRaw(d9));
        Assert.Equal("UAArgument", Code(() => w.ImportedKey(1, 0)));
        var other = W("pq_kat").SealVault(Utf8("correct horse 9"));
        w.Lock();
        Assert.Equal("UAWalletMismatch", Code(() => w.Unlock(other, Utf8("correct horse 9"))));
        var cands = JsonDocument.Parse(W("pq_kat").DiscoverCandidates(0x0102, 0, 3)).RootElement;
        Assert.Equal(3, cands.GetArrayLength());
        var mp = W("pq_kat").MemoryProtection();
        Assert.True(mp.Chunks >= 1 && ((UaLib.Features() & UaLib.FeatureMlock) == 0 || mp.NoDump == mp.Chunks));
    }

    [Fact]
    public void ChildHandleAfterWalletFreeIsKeyRevoked()
    {
        var w = Wallet.FromMnemonic(Utf8(S(Mn["pq_kat"], "words")));
        var k = Keep(w.UAKey(0x0130, 0, 0));
        var kk = Keep(k.KemKey(0));
        var n = Keep(w.NativeKey(0, 0, UaLib.CoinDefault));
        w.Dispose();
        Assert.Equal("UAKeyRevoked", Code(() => k.SignUA(UA.PurposeTag("metatx"), new byte[32])));
        Assert.Equal("UAKeyRevoked", Code(() => n.SignDigestRaw(new byte[32])));
        var e = new byte[32];
        e[0] = 1;
        Assert.Equal("UAKeyRevoked", Code(() => kk.Decaps(new byte[UaLib.KemCtLen], e)));
        Assert.Equal(1312, k.KeyData().Length);
    }

    [Fact]
    public void SeedBackupSequence()
    {
        var (w, sb) = Wallet.Generate();
        Keep(w);
        Keep(sb);
        var words = sb.Reveal();
        var ws = Encoding.UTF8.GetString(words).Split(' ');
        Assert.Equal(24, ws.Length);
        Assert.Equal("UAArgument", Code(() => sb.Reveal()));
        var pos = sb.Challenge();
        Assert.True(pos[0] >= 1 && pos[0] < pos[1] && pos[1] < pos[2] && pos[2] <= 24);
        Assert.Null(sb.Take());
        Assert.False(sb.Verify([Utf8("x"), Utf8("y"), Utf8("z")]));
        pos = sb.Challenge();
        Assert.True(sb.Verify(pos.Select(i => Utf8(ws[i - 1])).ToArray()));
        Assert.Equal(32, sb.Take()!.Length);
        Assert.Null(sb.Take());
        var w2 = Keep(Wallet.FromMnemonic(words));
        Assert.Equal(Key(w, 0x0102).KeyData(), Key(w2, 0x0102).KeyData());
    }

    // --- errors carry no input ---

    [Fact]
    public void ErrorStringsNeverContainAnInput()
    {
        string[] secrets = ["zebrasecretword", "Pa55-word-Secret", "SECRETvalue0xdead", "deadbeefcafe1234"];
        var w = W("pq_kat");
        var evm = Native("pq_kat");
        var kk = KemOf(Rows(Kem, "keys").First());
        var qk = Keep(w.PqzKey(0, 0));
        var zk = Keep(w.ZetherKey(60, 0, 7));
        var words = string.Join(' ', S(Mn["pq_kat"], "words").Split(' ')[..23].Append("zebrasecretword"));
        const string td = "{\"types\":{\"EIP712Domain\":[]},\"primaryType\":\"SECRETvalue0xdead\",\"domain\":{},\"message\":{\"v\":\"SECRETvalue0xdead\"}}";
        var vault = J(Rows(Vault, "vaults").First(), "vault")!;
        Action[] calls =
        [
            () => Wallet.FromMnemonic(Utf8(words), Utf8("Pa55-word-Secret")),
            () => Wallet.OpenVault(vault, Utf8("Pa55-word-Secret"), null, Utf8("zebrasecretword")),
            () => evm.SignTyped(td, "{\"check\":\"Payment\",\"account\":\"0xdeadbeefcafe1234\",\"payee\":\"Pa55-word-Secret\"}"),
            () => evm.SignTransaction("{\"type\":2,\"chainId\":\"SECRETvalue0xdead\"}"),
            () => kk.OpenContainer("{\"v\":\"Pa55-word-Secret\"}", "{\"purpose\":\"zebrasecretword\"}", null, null),
            () => qk.Call("zebrasecretword", "{}"),
            () => qk.Call("dec", "{\"ct\":\"0xdeadbeefcafe1234\",\"window\":\"SECRETvalue0xdead\"}"),
            () => zk.Call("proveTransfer", "{\"key\":{\"mnemonic\":\"zebrasecretword Pa55-word-Secret\"}}"),
            () => UaLib.VaultRewrapPin(vault, Utf8("Pa55-word-Secret"), Utf8("zebrasecretword")),
        ];
        foreach (var c in calls)
        {
            var e = Assert.Throws<WalletException>(c);
            foreach (var s in secrets)
                for (var j = 0; j + 6 <= s.Length; j++)
                    Assert.DoesNotContain(s[j..(j + 6)], e.Message);
        }
    }

    [Fact]
    public void AeadHkdfHmac()
    {
        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            Convert.ToHexStringLower(UaLib.HmacSha256(Enumerable.Repeat((byte)0x0b, 20).ToArray(), Utf8("Hi There"))));
        Assert.Equal("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Convert.ToHexStringLower(UaLib.HkdfSha256(Enumerable.Repeat((byte)0x0b, 22).ToArray(), Enumerable.Range(0, 13).Select(i => (byte)i).ToArray(),
                Enumerable.Range(0xf0, 10).Select(i => (byte)i).ToArray(), 42)));
        var (key, nonce) = (Enumerable.Repeat((byte)5, 32).ToArray(), new byte[12]);
        foreach (var alg in new uint[] { UaLib.AeadAes256Gcm, UaLib.AeadAes256GcmSiv })
        {
            var ct = UaLib.AeadSeal(alg, key, nonce, Utf8("aad"), Utf8("plaintext"));
            Assert.Equal(Utf8("plaintext"), UaLib.AeadOpen(alg, key, nonce, Utf8("aad"), ct));
            ct[^1] ^= 1;
            Assert.Equal("UAAead", Code(() => UaLib.AeadOpen(alg, key, nonce, Utf8("aad"), ct)));
        }
        Assert.Equal("UAArgument", Code(() => UaLib.AeadSeal(3, key, nonce, [], Utf8("x"))));
    }

    // --- the Zether facade ---

    [Fact]
    public void Zether()
    {
        var r33 = Load("clients/zether-prover/vectors/r33_keys.json");
        var w = Keep(Wallet.FromMnemonic(Utf8(S(r33, "mnemonic"))));
        var bls = r33.GetProperty("bls12381");
        foreach (var r in Rows(bls, "keys"))
        {
            var p = S(r, "path").Split('/');
            var (y, ua) = Keep(w.ZetherKey(uint.Parse(p[2]), uint.Parse(p[3]), uint.Parse(p[4]))).Public();
            Assert.Equal((S(r, "Y"), S(r, "UA")), (Hx(y), Hx(ua)));
        }
        Assert.Equal("UAArgument", Code(() => w.ZetherKey(60, 0, 9)));
        var k = Keep(w.ZetherKey(60, 0, 7));
        var pop = JsonDocument.Parse(k.Call("pop", "{\"curve\":\"bls12381\"}")).RootElement;
        var want = Rows(bls, "keys").First().GetProperty("pop");
        foreach (var f in new[] { "popDigest", "registrationDigest", "uaMsg" }) Assert.Equal(S(want, f), S(pop, f));
        var tv = Load("clients/zether-prover/vectors/transfer_bls12381.json");
        var req = JsonNode.Parse(tv.GetProperty("request").GetRawText())!.AsObject();
        req.Remove("key");
        req.Remove("includeWitness");
        // ARCH-POS-13 (T15c, T14b): no command of a release build decrypts a caller's ciphertext (the words commands: below)
        Assert.Equal("UAArgument", Code(() => k.Call("checkBalance", new JsonObject { ["acc"] = req["acc"]!.DeepClone(), ["balance"] = req["balance"]!.DeepClone() }.ToJsonString())));
        Assert.Equal("UAArgument", Code(() => k.Call("proveTransfer", req.ToJsonString())));
        Assert.Equal("UAArgument", Code(() => k.Call("pop", "{\"key\":{\"seed\":\"0x11\"}}")));
        foreach (var r in Rows(Zj, "cacheBox"))
        {
            var zk = Keep(Fresh(S(r, "mnemonic")).ZetherKey(U(r, "coin"), U(r, "account"), U(r, "use")));
            var pt = zk.OpenBalanceCache(J(r, "box")!);
            Assert.Equal(S(r, "plaintext"), Hx(pt));
            Assert.Equal(pt, zk.OpenBalanceCache(zk.SealBalanceCache(pt)));
        }
        foreach (var r in Rows(Zj, "cacheRefusals"))
        {
            var zk = Keep(Fresh(S(r, "mnemonic")).ZetherKey(U(r, "coin"), U(r, "account"), U(r, "use")));
            Assert.Equal("UAAead", Code(() => zk.OpenBalanceCache(J(r, "box")!)));
        }
        var (y0, _) = k.Public();
        w.Lock();
        Assert.Equal("UAKeyRevoked", Code(() => k.Call("pop", "{}")));
        Assert.Equal(y0, k.Public().Y);
    }

    /// <summary>scaas-ua <c>facade::&lt;name&gt;::COMMANDS</c> read from its source (T15g): the release commands and the
    /// <c>vectors</c>-only raw forms. A test asserts that a command is in it, never that it equals a list (spec
    /// no-decryption-oracle §4.13).</summary>
    static (List<string> Release, List<string> Raw) Commands(string name)
    {
        var src = File.ReadAllText(Path.Combine(Root, "clients", "ua-rs", "src", "facade", name + ".rs"));
        var body = src[src.IndexOf("pub const COMMANDS: &[&str] = &[", StringComparison.Ordinal)..];
        (List<string> Release, List<string> Raw) res = ([], []);
        var gated = false;
        foreach (var l in body[..body.IndexOf("];", StringComparison.Ordinal)].Split('\n').Skip(1).Select(x => x.Trim()))
        {
            if (l == "#[cfg(feature = \"vectors\")]") gated = true;
            else if (l.StartsWith('"'))
            {
                (gated ? res.Raw : res.Release).Add(l.Trim('"', ','));
                gated = false;
            }
        }
        return res;
    }

    /// <summary>T15g (ARCH-POS-13): the words commands on the forge rows (smartcontracts/vectors/zether/state.json; the holders
    /// are r33_keys.json's): each in COMMANDS, the balances the contract's; another holder's words refused before the key (ua-rs
    /// tests/facade_zether_state.rs counts the key's uses); every <c>vectors</c>-only raw form refused by the release library.</summary>
    [Fact]
    public void ZetherWordsOnTheForgeRows()
    {
        var (release, raw) = Commands("zether");
        Assert.Contains("balance", release);
        Assert.Contains("pendingBalance", release);
        Assert.Contains("decrypt", raw);
        Assert.Contains("decryptPending", raw);
        var st = Load("smartcontracts/vectors/zether/state.json");
        var row = Rows(st, "accounts").ToDictionary(r => S(r, "name").Split(':')[0]);
        string Words(string name)
        {
            var o = new JsonObject { ["tableBits"] = 18, ["boundBits"] = 20 };
            foreach (var f in new[] { "family", "chainId", "chainUid", "token", "block", "psid" }) o[f] = JsonNode.Parse(st.GetProperty(f).GetRawText());
            foreach (var f in new[] { "ua", "account", "accountData" }) o[f] = JsonNode.Parse(row[name].GetProperty(f).GetRawText());
            return o.ToJsonString();
        }
        var r33 = Load("clients/zether-prover/vectors/r33_keys.json");
        var w = Keep(Wallet.FromMnemonic(Utf8(S(r33, "mnemonic"))));
        var (alice, bob) = (Keep(w.ZetherKey(60, 0, 7)), Keep(w.ZetherKey(60, 1, 7)));
        string Amount(ZetherKey k, string cmd, string name) => S(JsonDocument.Parse(k.Call(cmd, Words(name))).RootElement, "amount");
        Assert.Equal(row["alice"].GetProperty("balance").GetRawText(), Amount(alice, "balance", "alice"));
        Assert.Equal(row["bob"].GetProperty("pending").GetRawText(), Amount(bob, "pendingBalance", "bob"));
        Assert.Equal("UAArgument", Code(() => bob.Call("balance", Words("alice"))));
        foreach (var c in raw) Assert.Equal("UAArgument", Code(() => alice.Call(c, "{}")));
    }

    /// <summary>T15g (ARCH-POS-13): <c>balance</c> on a forge row (smartcontracts/vectors/pqz/n2304-kmax4096/state.json): in
    /// COMMANDS; the forge keys are mocked, so the words bind to no wallet key and are refused (UAArgument), with the other set's
    /// psid UAPqzSetMismatch, both before the key (ua-rs tests/facade_pqz_state.rs counts the key's uses); every
    /// <c>vectors</c>-only raw form refused.</summary>
    [Fact]
    public void PqzWordsOnTheForgeRows()
    {
        var (release, raw) = Commands("pqz");
        Assert.Contains("balance", release);
        Assert.Contains("dec", raw);
        var st = Load("smartcontracts/vectors/pqz/n2304-kmax4096/state.json");
        var a = Rows(st, "accounts").First();
        var words = new JsonObject();
        foreach (var f in new[] { "chainUid", "token", "psid" }) words[f] = JsonNode.Parse(st.GetProperty(f).GetRawText());
        foreach (var f in new[] { "ua", "block", "account", "pending", "accWords", "blobs", "keyRecord" }) words[f] = JsonNode.Parse(a.GetProperty(f).GetRawText());
        var k = Keep(Fresh("pq_kat").PqzKey(0, 0));
        Assert.Equal("UAArgument", Code(() => k.Call("balance", words.ToJsonString())));
        words["psid"] = Pqzl2048;
        Assert.Equal("UAPqzSetMismatch", Code(() => k.Call("balance", words.ToJsonString())));
        foreach (var c in raw) Assert.Equal("UAArgument", Code(() => k.Call(c, "{}")));
    }

    // --- the PQZ facade ---

    [Fact]
    public void Pqz()
    {
        Assert.True((UaLib.Features() & UaLib.FeaturePqz) != 0 && (UaLib.Features() & UaLib.FeaturePqzSetN2304Kmax4096) != 0);
        var s = JsonNode.Parse(UaLib.PqzSet())!.AsObject();
        Assert.Equal(("n2304-kmax4096", Pqzl2304), ((string)s["set"]!, (string)s["pqzlId"]!));
        UaLib.PqzCheckSet(s.ToJsonString());
        s["set"] = "n2048-kmax1024";
        Assert.Equal("UAPqzSetMismatch", Code(() => UaLib.PqzCheckSet(s.ToJsonString())));
        var m = Mn["pq_kat"];
        var seed = Rfc2898DeriveBytes.Pbkdf2(Utf8(S(m, "words")), Utf8("mnemonic" + S(m, "passphrase")), 2048, HashAlgorithmName.SHA512, 64);
        var prk = HMACSHA256.HashData(Utf8("scaas.ua.pq.v1"), seed);
        var w = Fresh("pq_kat");
        foreach (var (a, i) in new (uint, uint)[] { (0, 0), (1, 2) })
        {
            var info = Utf8("scaas.ua.pqz-mlwe.v1").Concat(BitConverter.GetBytes(a).Reverse()).Concat(BitConverter.GetBytes(i).Reverse()).Append((byte)1).ToArray();
            var leaf = w.ExportPqzLeafRaw(a, i);
            Assert.Equal(HMACSHA256.HashData(prk, info), leaf);
            UaLib.Wipe(leaf);
        }
        Assert.Equal("UAArgument", Code(() => w.ExportPqzLeafRaw(1u << 31, 0)));
        var k = Keep(w.PqzKey(0, 0));
        var pk = k.PublicKey();
        Assert.Equal(18432, pk.Length);
        var req = new JsonObject { ["proofSystemId"] = Pqzl2304, ["kind"] = 0x0131, ["ua"] = "0x" + string.Concat(Enumerable.Repeat("11", 32)) };
        Assert.Equal(pk, B(S(JsonDocument.Parse(k.Call("proveRegister", req.ToJsonString())).RootElement, "stmt"))[96..]);
        req["proofSystemId"] = Pqzl2048;
        Assert.Equal("UAPqzSetMismatch", Code(() => k.Call("proveRegister", req.ToJsonString())));
        req["proofSystemId"] = Pqzl2304;
        req["seed32"] = "0x" + string.Concat(Enumerable.Repeat("11", 32));
        Assert.Equal("UAArgument", Code(() => k.Call("proveRegister", req.ToJsonString())));
        req.Remove("seed32");
        var e = JsonDocument.Parse(k.Call("enc", new JsonObject { ["pks"] = new JsonArray(Hx(pk)), ["values"] = new JsonArray(123456) }.ToJsonString())).RootElement;
        // ARCH-POS-13 (T15c): a release build has no raw decrypt; a well-formed `dec` is an unknown command
        Assert.Equal("UAArgument", Code(() => k.Call("dec", new JsonObject { ["ct"] = S(e, "u") + e.GetProperty("vs")[0].GetString()![2..] }.ToJsonString())));
        var box = k.SealBalanceCache(Utf8("{\"v\":1}"));
        Assert.Equal(Utf8("{\"v\":1}"), k.OpenBalanceCache(box));
        Assert.Equal("UAAead", Code(() => Keep(w.PqzKey(0, 1)).OpenBalanceCache(box)));
        w.Lock();
        Assert.Equal("UAKeyRevoked", Code(() => k.Call("proveRegister", req.ToJsonString())));
        Assert.Equal(pk, k.PublicKey());
        Assert.Equal("UAWalletLocked", Code(() => w.ExportPqzLeafRaw(0, 0)));
    }
}
