using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Nethermind.Core;
using Nethermind.Serialization.Json;
using NUnit.Framework;

namespace Nethermind.Pqz.Test;

/// <summary>P6f Task 2: every PQZ vector through the C# class (P/Invoke into the production cdylib), the gas rows
/// (D6), the status mapping (D4).</summary>
public class PqzPrecompileTests
{
    public static PqzSchedule Schedule(JsonArray? rows = null)
    {
        JsonObject s = SpecTests.Schedule(1);
        if (rows is not null) s["pqz"] = rows;
        PqzSchedule p = new EthereumJsonSerializer().Deserialize<PqzSchedule>(s.ToJsonString());
        p.Validate();
        return p;
    }

    private static readonly byte[] Zero = new byte[32];
    private static readonly byte[] One = [.. new byte[31], 1];

    private static string Show(Result<byte[]> r) => r.IsSuccess ? Convert.ToHexStringLower(r.Data!) : "fail:" + r.Error;

    [Test]
    public void Every_corpus_input_gives_its_expected_output()
    {
        PqzSchedule s = Schedule();
        List<string> bad = [];
        Dictionary<string, int> n = [];
        foreach (CorpusRow r in Corpus.Rows)
        {
            Result<byte[]> got = PqzPrecompile.Run(r.Input, s);
            string want = r.Expect switch { "1" => Convert.ToHexStringLower(One), "0" => Convert.ToHexStringLower(Zero), "revert" => "fail:PQZ: input over MAX_INPUT", var h => h };
            if (Show(got) != want) bad.Add($"{r.Kind} {r.Name} ({r.Id}): {Show(got)} != {want}");
            n[r.Kind + "/" + r.Expect[..Math.Min(6, r.Expect.Length)]] = n.GetValueOrDefault(r.Kind + "/" + r.Expect[..Math.Min(6, r.Expect.Length)]) + 1;
        }
        TestContext.Progress.WriteLine("corpus through PqzPrecompile.Run: " + string.Join(", ", n.OrderBy(x => x.Key).Select(x => $"{x.Key} {x.Value}")));
        Assert.That(bad, Is.Empty);
    }

    [Test]
    public void Selftest_constant_equals_the_vector_file()
    {
        JsonObject st = JsonNode.Parse(File.ReadAllText(Repo.Path_("smartcontracts", "vectors", "pqz", "selftest.json")))!.AsObject();
        Assert.That((string)st["hash"]!, Is.EqualTo(SelfTest.ExpectedHash));
        Assert.That(SelfTest.Run(), Is.EqualTo(SelfTest.ExpectedHash));
    }

    [Test]
    public void Gas_is_the_row_plus_the_length_term_and_never_depends_on_validity()
    {
        PqzSchedule s = Schedule();
        Dictionary<(int, string, long), long> rowGas = Corpus.Rows12().Select(o => o!.AsObject())
            .ToDictionary(o => ((int)o["op"]!, ((string)o["id"]!)[2..], (long)o["stmtLen"]!), o => (long)o["gas"]!);
        foreach (CorpusRow r in Corpus.Rows.Where(r => r.Kind is "honest" or "flip" or "fee0"))
        {
            long want = rowGas[(r.Op, Corpus.Ids[r.Id], r.StmtLen)] + 3 * ((r.Input.Length + 31) / 32);
            Assert.That(PqzPrecompile.Gas(r.Input, s), Is.EqualTo(want), r.Name);
        }
        // valid and invalid inputs of the same row and length: equal gas (the flip keeps the length)
        foreach (CorpusRow h in Corpus.Rows.Where(r => r.Kind == "honest"))
        {
            CorpusRow f = Corpus.Rows.Single(r => r.Kind == "flip" && r.Id == h.Id && r.Form == h.Form);
            Assert.That(f.Input.Length, Is.EqualTo(h.Input.Length));
            Assert.That(PqzPrecompile.Gas(f.Input, s), Is.EqualTo(PqzPrecompile.Gas(h.Input, s)), h.Name);
        }
        // misses: the smallest row + the length term; op 6: selftestGas, fixed
        long min = rowGas.Values.Min();
        byte[] h0 = Corpus.Rows.First(r => r.Kind == "honest").Input;
        byte[] unknownId = (byte[])h0.Clone();
        unknownId[40] ^= 1;
        Assert.That(PqzPrecompile.Gas(unknownId, s), Is.EqualTo(min + 3 * ((h0.Length + 31) / 32)));
        Assert.That(PqzPrecompile.Gas([], s), Is.EqualTo(min));
        Assert.That(PqzPrecompile.Gas([1, 0, 0], s), Is.EqualTo(min + 3));
        Assert.That(PqzPrecompile.Gas(new byte[68], s), Is.EqualTo(min + 9));
        Assert.That(PqzPrecompile.Gas([6, 0, 0, 0, 0], s), Is.EqualTo(s.SelftestGas));
        Assert.That(PqzPrecompile.Gas(new byte[] { 6 }.Concat(new byte[100_000]).ToArray(), s), Is.EqualTo(s.SelftestGas));
        Assert.That(PqzPrecompile.Gas(h0, null), Is.EqualTo(long.MaxValue), "no schedule: out of gas (fail closed)");
    }

    [Test]
    public void A_row_absent_from_the_schedule_is_zero_without_an_ffi_call()
    {
        // only the PQZL rows: every PQZH honest input is now a miss
        JsonArray pqzl = new(Corpus.Rows12().Where(o => ((string)o!["id"]!).EndsWith(Corpus.Ids["pqzl"])).Select(o => o!.DeepClone()).ToArray());
        PqzSchedule s = Schedule(pqzl);
        foreach (CorpusRow h in Corpus.Rows.Where(r => r.Kind == "honest" && r.Id == "pqzh"))
        {
            long before = PqzPrecompile.FfiCalls;
            Assert.That(PqzPrecompile.Run(h.Input, s).Data, Is.EqualTo(Zero), h.Name);
            Assert.That(PqzPrecompile.FfiCalls, Is.EqualTo(before), "no FFI call for a miss");
        }
        CorpusRow l = Corpus.Rows.First(r => r.Kind == "honest" && r.Id == "pqzl");
        long b = PqzPrecompile.FfiCalls;
        Assert.That(PqzPrecompile.Run(l.Input, s).Data, Is.EqualTo(One));
        Assert.That(PqzPrecompile.FfiCalls, Is.EqualTo(b + 1));
        Assert.That(PqzPrecompile.Run(l.Input, null).IsError, "no schedule: failed call");
    }

    [Test]
    public void Boundary_lengths()
    {
        PqzSchedule s = Schedule();
        byte[] h = Corpus.Rows.First(r => r.Kind == "honest" && r.Form == "TRANSFER" && r.Id == "pqzl").Input;
        byte[] max = new byte[PqzNative.MaxInput];
        h.CopyTo(max, 0);
        Assert.That(PqzPrecompile.Run(max, s).Data, Is.EqualTo(Zero), "len = MAX_INPUT (row present, proof too long): …00");
        byte[] over = new byte[PqzNative.MaxInput + 1];
        h.CopyTo(over, 0);
        Assert.That(PqzPrecompile.Run(over, s).IsError, "len = MAX_INPUT + 1: failed call");
        Assert.That(PqzPrecompile.Run([], s).Data, Is.EqualTo(Zero), "len = 0");
        Assert.That(PqzNative.Call([], new byte[32]), Is.EqualTo(PqzNative.Ok), "len = 0 through the ABI (null pointer)");
        Assert.That(PqzPrecompile.Run([6], s).Data, Is.EqualTo(Zero), "op 6 with a short input: …00 from pqz-ffi");
    }

    [Test]
    public void Node_fault_exits_120_with_the_tag()
    {
        string hooks = Path.Combine(Repo.HooksDir, "libpqz_ffi.so");
        Assert.That(File.Exists(hooks), $"{hooks} (fault-hooks build, run.sh)");
        string harness = Path.Combine(AppContext.BaseDirectory, "Harness.dll");
        ProcessStartInfo psi = new("dotnet", [harness, "fault", Repo.HooksDir, Repo.CorpusPath]) { RedirectStandardError = true, RedirectStandardOutput = true };
        using Process p = Process.Start(psi)!;
        string err = p.StandardError.ReadToEnd();
        string outp = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        TestContext.Progress.WriteLine($"fault child: exit {p.ExitCode}; stdout: {outp.Trim()}; stderr: {err.Trim()}");
        Assert.That(p.ExitCode, Is.EqualTo(120));
        Assert.That(err, Does.Contain("PQZ-NODE-FAULT status=4"));
    }
}
