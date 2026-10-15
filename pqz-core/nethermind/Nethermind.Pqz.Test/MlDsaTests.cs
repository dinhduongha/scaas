using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using NUnit.Framework;

namespace Nethermind.Pqz.Test;

/// <summary>P6f Task 3: ML-DSA-44 / -65 in the EIP-8355 layout through .NET 10's MLDsa (OpenSSL), D5 / R4.</summary>
public class MlDsaTests
{
    private static JsonObject Ext => JsonNode.Parse(File.ReadAllText(Repo.Path_("smartcontracts", "vectors", "ua", "pq_external.json")))!.AsObject();
    private static JsonObject Sigs => JsonNode.Parse(File.ReadAllText(Repo.Path_("smartcontracts", "vectors", "ua", "pq_signatures.json")))!.AsObject();

    private static bool Valid(JsonNode? v) => v!.GetValueKind() == System.Text.Json.JsonValueKind.String ? bool.Parse((string)v!) : (bool)v!;

    public static (MLDsaAlgorithm alg, int pk, int sig, Func<byte[], byte[]> run) Level(int pkLen) => pkLen switch
    {
        MlDsa.Pk44 => (MLDsaAlgorithm.MLDsa44, MlDsa.Pk44, MlDsa.Sig44, i => MlDsa44Precompile.Instance.Run(i, null!).Data!),
        MlDsa.Pk65 => (MLDsaAlgorithm.MLDsa65, MlDsa.Pk65, MlDsa.Sig65, i => MlDsa65Precompile.Instance.Run(i, null!).Data!),
        _ => throw new ArgumentException($"pk length {pkLen}"),
    };

    private static byte[] Word(bool b) => [.. new byte[31], (byte)(b ? 1 : 0)];

    [Test]
    public void Supported_and_runtime_recorded()
    {
        TestContext.Progress.WriteLine($"MLDsa.IsSupported={MLDsa.IsSupported} runtime={Environment.Version} os={System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        Assert.That(MLDsa.IsSupported);
    }

    [Test]
    public void Acvp_sigver_cases()
    {
        List<string> bad = [], skipped = [];
        int ext = 0, intl = 0, viaPrecompile = 0;
        foreach (JsonObject c in Ext["acvp_mldsa"]!["cases"]!.AsArray().Select(x => x!.AsObject()))
        {
            byte[] pk = Hex.B((string)c["pk"]!), sig = Hex.B((string)c["sig"]!), mp = Hex.B((string)c["mprime"]!);
            bool want = Valid(c["valid"]);
            var (alg, _, _, run) = Level(pk.Length);
            using MLDsa key = MLDsa.ImportMLDsaPublicKey(alg, pk);
            string id = $"{c["set"]} tc {c["tc"]} {c["iface"]}";
            if ((string)c["iface"]! == "external")
            {
                // M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M (pure ML-DSA)
                if (mp[0] != 0) { skipped.Add(id + " (pre-hash)"); continue; }
                byte[] ctx = mp[2..(2 + mp[1])], msg = mp[(2 + mp[1])..];
                ext++;
                if (key.VerifyData(msg, sig, ctx) != want) bad.Add(id);
                if (ctx.Length == 0)
                {
                    viaPrecompile++;
                    if (!run([.. pk, .. sig, .. msg]).AsSpan().SequenceEqual(Word(want))) bad.Add(id + " via the precompile");
                }
            }
            else
            {
                // μ = SHAKE256(tr ‖ M', 64), tr = SHAKE256(pk, 64); the external-μ API
                byte[] mu = Shake256.HashData([.. Shake256.HashData(pk, 64), .. mp], 64);
                try
                {
                    intl++;
#pragma warning disable SYSLIB5006 // external-μ verify is [Experimental] in .NET 10 (test only; the plugin uses VerifyData)
                    if (key.VerifyMu(mu, sig) != want) bad.Add(id);
#pragma warning restore SYSLIB5006
                }
                catch (Exception e) when (e is PlatformNotSupportedException or CryptographicException)
                {
                    intl--;
                    skipped.Add($"{id} ({e.GetType().Name})");
                }
            }
        }
        TestContext.Progress.WriteLine($"ACVP ML-DSA sigVer: external {ext} (of them {viaPrecompile} with the empty context also through the precompile), internal via VerifyMu {intl}, skipped {skipped.Count}: [{string.Join("; ", skipped)}]");
        Assert.That(bad, Is.Empty);
        Assert.That(ext + intl, Is.EqualTo(60 - skipped.Count));
    }

    [Test]
    public void Eip8355_cases()
    {
        foreach (JsonObject c in Ext["eip8355"]!["cases"]!.AsArray().Select(x => x!.AsObject()))
        {
            byte[] input = Hex.B((string)c["input"]!);
            bool want = Valid(c["valid"]);
            foreach (Func<byte[], byte[]> run in c["pk"] is null
                         ? new Func<byte[], byte[]>[] { Level(MlDsa.Pk44).run, Level(MlDsa.Pk65).run }
                         : [Level(Hex.B((string)c["pk"]!).Length).run])
                Assert.That(run(input), Is.EqualTo(Word(want)), (string)c["name"]!);
        }
    }

    public static IEnumerable<(string name, byte[] input, bool valid)> UaRows()
    {
        JsonObject d = Sigs;
        IEnumerable<JsonObject> keys = d["kinds"]!.AsArray().Concat(d["extraKeys"]!.AsArray()).Select(k => k!.AsObject())
            .Where(k => (string)k["name"]! is "mldsa44" or "mldsa65");
        foreach (JsonObject k in keys)
        {
            byte[] pk = Hex.B((string)k["keyData"]!);
            byte[] tag = Keccak.Compute(Encoding.ASCII.GetBytes($"scaas.ua.{k["name"]}.v1")).BytesToArray();
            byte[] In(JsonNode s) => [.. pk, .. Hex.B((string)s["sig"]!), .. Keccak.Compute([.. tag, .. Hex.B((string)s["message"]!)]).BytesToArray()];
            foreach (string p in new[] { "pop", "popOther" }) if (k[p] is { } s) yield return ($"{k["name"]} {p}", In(s), true);
            if (k["sigs"] is JsonArray sigs) foreach (JsonNode? s in sigs) yield return ($"{k["name"]} {s!["purpose"]}", In(s), true);
            // (the file's negatives are UA-level rejections — other chain, other registry — whose raw signatures can be
            // valid; the invalid side is Every_length_and_one_bit_flips)
        }
    }

    [Test]
    public void Ua_pq_signatures_rows()
    {
        List<string> bad = [];
        int n = 0;
        foreach (var (name, input, valid) in UaRows())
        {
            n++;
            if (!Level(input.Length == MlDsa.Pk44 + MlDsa.Sig44 + 32 ? MlDsa.Pk44 : MlDsa.Pk65).run(input).AsSpan().SequenceEqual(Word(valid)))
                bad.Add(name);
        }
        TestContext.Progress.WriteLine($"pq_signatures ML-DSA rows through the precompile: {n}");
        Assert.That(bad, Is.Empty);
    }

    [Test]
    public void Every_length_and_one_bit_flips()
    {
        foreach (int pkLen in new[] { MlDsa.Pk44, MlDsa.Pk65 })
        {
            var (_, pk, sigLen, run) = Level(pkLen);
            byte[] good = UaRows().First(r => r.valid && r.input.Length == pk + sigLen + 32).input;
            Assert.That(run(good), Is.EqualTo(Word(true)));
            for (int l = 0; l <= pk + sigLen + 33; l++)
            {
                byte[] x = l <= good.Length ? good[..l] : [.. good, 0];
                byte[] o = run(x);
                Assert.That(o.Length, Is.EqualTo(32));
                if (l < pk + sigLen) Assert.That(o, Is.EqualTo(Word(false)), $"L = {l} < PK + SIG");
                else if (l != good.Length) Assert.That(o, Is.EqualTo(Word(false)), $"L = {l}");
            }
            foreach (int at in new[] { 0, pk / 2, pk - 1, pk, pk + sigLen / 2, pk + sigLen - 1, pk + sigLen, good.Length - 1 })
            {
                byte[] f = (byte[])good.Clone();
                f[at] ^= 1;
                Assert.That(run(f), Is.EqualTo(Word(false)), $"flip at {at}");
            }
        }
    }

    [Test]
    public void Gas_is_eip8355_at_minimum()
    {
        Assert.That(MlDsa.Gas(0, MlDsa.Pk44, MlDsa.Sig44, MlDsa.Base44), Is.EqualTo(6500));
        Assert.That(MlDsa.Gas(MlDsa.Pk44 + MlDsa.Sig44 + 32, MlDsa.Pk44, MlDsa.Sig44, MlDsa.Base44), Is.EqualTo(6506));
        Assert.That(MlDsa.Gas(MlDsa.Pk65 + MlDsa.Sig65 + 33, MlDsa.Pk65, MlDsa.Sig65, MlDsa.Base65), Is.EqualTo(9012));
        PqzSchedule s = PqzPrecompileTests.Schedule();
        IReleaseSpecStub spec = new(s);
        Assert.That(MlDsa44Precompile.Instance.DataGasCost(new byte[MlDsa.Pk44 + MlDsa.Sig44 + 32], spec.Spec), Is.EqualTo(s.MlDsa44Gas + 6));
    }
}

/// <summary>A release spec whose precompile set carries <paramref name="s"/> (through PqzReleaseSpec).</summary>
public sealed class IReleaseSpecStub(PqzSchedule s)
{
    public Nethermind.Core.Specs.IReleaseSpec Spec { get; } = new PqzReleaseSpec { ActiveSchedule = s };
}
