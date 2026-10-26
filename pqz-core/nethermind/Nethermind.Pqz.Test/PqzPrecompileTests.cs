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
        PqzSchedule p = new EthereumJsonSerializer().Deserialize<PqzSchedule>(s.ToJsonString())!;
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
        Assert.That(SelfTest.Set, Is.EqualTo(Repo.Set), "plugin built for another set (-p:PqzSet) than PQZ_SET");
        JsonObject st = JsonNode.Parse(File.ReadAllText(Path.Combine(Repo.VectorDir, "selftest.json")))!.AsObject();
        Assert.That((string)st["hash"]!, Is.EqualTo(SelfTest.ExpectedHash));
        Assert.That(SelfTest.Run(), Is.EqualTo(SelfTest.ExpectedHash));
    }

    [Test]
    public void Library_sha256_is_compared_with_the_reviewed_value()
    {
        // review W-G (2026-10-19): the plugin refuses a library whose SHA-256 is not the reviewed one; build-image.sh
        // reads the same constant from SelfTest.cs with this pattern
        Assert.That(SelfTest.CheckedLibrarySha256(SelfTest.LibrarySha256()), Is.EqualTo(SelfTest.LibrarySha256()));
        Exception? e = Assert.Throws<InvalidOperationException>(() => SelfTest.CheckedLibrarySha256(new string('0', 64)));
        Assert.That(e!.Message, Does.Contain("!= the reviewed " + new string('0', 64)));
        string src = File.ReadAllText(Repo.Path_("pqz-core", "nethermind", "Nethermind.Pqz", "SelfTest.cs"));
        // one reviewed value per set (R0 review fix part b), on the set's line, as build-image.sh reads it
        var m = System.Text.RegularExpressions.Regex.Matches(src, @"Set = ""([a-z0-9-]+)"", ExpectedHash = ""[0-9a-f]{64}"", ExpectedLibrarySha256 = ""([0-9a-f]{64})"";");
        Assert.That(m.Select(x => x.Groups[1].Value), Is.EqualTo(new[] { "n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536" }));
        Assert.That(m.Single(x => x.Groups[1].Value == SelfTest.Set).Groups[2].Value, Is.EqualTo(SelfTest.ExpectedLibrarySha256));
        Assert.That(m.Select(x => x.Groups[2].Value).Distinct().Count(), Is.EqualTo(4), "a library per set");
        Assert.That(File.ReadAllText(Repo.Path_("pqz-core", "nethermind", "build-image.sh")), Does.Contain(@"ExpectedLibrarySha256 = ""\([0-9a-f]\{64\}\)"";"));
    }

    [Test]
    public void Gas_is_the_row_plus_the_length_term_and_never_depends_on_validity()
    {
        PqzSchedule s = Schedule();
        Dictionary<(int, string, long, int, int), long> rowGas = Corpus.ScheduleRows().Select(o => o!.AsObject())
            .ToDictionary(o => ((int)o["op"]!, ((string)o["id"]!)[2..], (long)o["stmtLen"]!, (int?)o["legs"] ?? 0, (int?)o["auditorOn"] ?? 0), o => (long)o["gas"]!);
        foreach (CorpusRow r in Corpus.Rows.Where(r => r.Kind is "honest" or "flip" or "fee0"))
        {
            var (m, a) = Corpus.Shape(r.Input);
            long want = rowGas[(r.Op, Corpus.Ids[r.Id], r.StmtLen, m, a)] + 3 * ((r.Input.Length + 31) / 32);
            Assert.That(PqzPrecompile.Gas(r.Input, s), Is.EqualTo(want), r.Name);
        }
        // valid and invalid inputs of the same row and length: equal gas (the flip keeps the statement and the length)
        foreach (CorpusRow h in Corpus.Rows.Where(r => r.Kind == "honest"))
        {
            int stmtEnd = 5 + (int)h.StmtLen;
            CorpusRow? f = Corpus.Rows.FirstOrDefault(r => r.Kind == "flip" && r.Id == h.Id && r.Input.Length == h.Input.Length
                && r.Input.AsSpan(0, stmtEnd).SequenceEqual(h.Input.AsSpan(0, stmtEnd)));
            // no flip: op 7 rows, and the op 7 disclosures (op 5 rows named by their case, R0 review fix): same row and
            // length as their form's honest input, which has one. Name-based on purpose (review m11, kept): corpus.py
            // names an honest row "<form> <id>" and only the vectors' op 7 disclosures "<case> <id>", the one marker the
            // corpus carries; a new honest op 1-5 row with a case name would skip this check, so give it a flip row
            bool ofMulti = h.Op == PqzSchedule.OpMulti || !h.Name.StartsWith(h.Form + " ");
            if (f is null) { Assert.That(ofMulti, Is.True, $"every op 1-5 honest input has a flip: {h.Name}"); continue; }
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
        Assert.That(PqzPrecompile.Gas(h0, null), Is.EqualTo(ulong.MaxValue), "no schedule: out of gas (fail closed)");
    }

    [Test]
    public void Op7_rows_are_keyed_by_the_M_and_auditorOn_words()
    {
        PqzSchedule s = Schedule();
        // (1, on) and (2, off) have the same length (83,072 B) and get their own rows
        CorpusRow on1 = Corpus.Rows.First(r => r.Kind == "honest" && r.Id == "pqzl" && Corpus.Shape(r.Input) == (1, 1));
        CorpusRow off2 = Corpus.Rows.First(r => r.Kind == "honest" && r.Id == "pqzl" && Corpus.Shape(r.Input) == (2, 0));
        Assert.That(on1.StmtLen, Is.EqualTo(off2.StmtLen));
        Assert.That(s.RowGas(on1.Input), Is.Not.EqualTo(s.RowGas(off2.Input)));
        Assert.That(PqzPrecompile.Run(on1.Input, s).Data, Is.EqualTo(One));
        Assert.That(PqzPrecompile.Run(off2.Input, s).Data, Is.EqualTo(One));
        // an M or auditorOn word outside the rows (or not a small integer): a miss — smallest row, …00, no FFI call
        foreach ((int at, byte v) in new[] { (5 + 351, (byte)3), (5 + 479, (byte)2), (5 + 320, (byte)1), (5 + 448, (byte)1) })
        {
            byte[] x = (byte[])on1.Input.Clone();
            x[at] = v;
            long before = PqzPrecompile.FfiCalls;
            Assert.That(s.RowGas(x), Is.Null, $"byte {at} = {v}");
            Assert.That(PqzPrecompile.Gas(x, s), Is.EqualTo(s.MinGas + 3 * ((x.Length + 31) / 32)));
            Assert.That(PqzPrecompile.Run(x, s).Data, Is.EqualTo(Zero));
            Assert.That(PqzPrecompile.FfiCalls, Is.EqualTo(before));
        }
        // an op 7 input too short to hold the auditorOn word: a miss
        Assert.That(s.RowGas(on1.Input.AsSpan(0, 5 + 479).ToArray()), Is.Null);
    }

    [Test]
    public void A_row_absent_from_the_schedule_is_zero_without_an_ffi_call()
    {
        // only the PQZL rows: every PQZH honest input is now a miss
        JsonArray pqzl = new(Corpus.ScheduleRows().Where(o => ((string)o!["id"]!).EndsWith(Corpus.Ids["pqzl"])).Select(o => o!.DeepClone()).ToArray());
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

    /// <summary>Review R4-C6: <c>PqzNative</c>'s status constants are pqz_ffi.h's <c>#define PQZ_FFI_*</c> (a renumbered
    /// status would otherwise land in <c>default:</c>, exit 120 on every node).</summary>
    [Test]
    public void Status_constants_are_the_header_s()
    {
        string h = File.ReadAllText(Repo.Path_("pqz-core", "ffi", "pqz_ffi.h"));
        int Def(string n) => int.Parse(System.Text.RegularExpressions.Regex.Match(h, $@"^#define {n} (\d+)", System.Text.RegularExpressions.RegexOptions.Multiline) is { Success: true } m ? m.Groups[1].Value : throw new AssertionException(n));
        Assert.That((Def("PQZ_FFI_OK"), Def("PQZ_FFI_REVERT"), Def("PQZ_FFI_BAD_ARGS"), Def("PQZ_FFI_INTERNAL"), Def("PQZ_FFI_NODE_FAULT")),
            Is.EqualTo((PqzNative.Ok, PqzNative.Revert, PqzNative.BadArgs, PqzNative.InputPanic, PqzNative.NodeFault)));
        Assert.That(Def("PQZ_FFI_OUT_BYTES"), Is.EqualTo(32));
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
