using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using NUnit.Framework;

namespace Nethermind.Pqz.Test;

/// <summary>Paths and the shared vectors: the flat PQZ corpus (corpus.py over the parameter set's vectors), the UA
/// ML-DSA vectors, and the library under test (PQZ_FFI_DIR, default pqz-core/ffi/target/release, pqz-ffi's default
/// set). The set: PQZ_SET, default n2304-kmax4096 (pqz-ffi's default feature, plan 5h Task 8d).</summary>
public static class Repo
{
    public static readonly string Root = Find();

    private static string Find()
    {
        for (DirectoryInfo? d = new(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (Directory.Exists(Path.Combine(d.FullName, "pqz-core", "nethermind"))) return d.FullName;
        throw new DirectoryNotFoundException("repo root (pqz-core/nethermind) above " + AppContext.BaseDirectory);
    }

    public static string Path_(params string[] parts) => Path.Combine([Root, .. parts]);
    public static string Set => Environment.GetEnvironmentVariable("PQZ_SET") ?? "n2304-kmax4096";
    /// <summary>the set's vectors: smartcontracts/vectors/pqz/&lt;set&gt;/ (n2048-kmax1024: smartcontracts/vectors/pqz/)</summary>
    public static string VectorDir => Set == "n2048-kmax1024" ? Path_("smartcontracts", "vectors", "pqz") : Path_("smartcontracts", "vectors", "pqz", Set);
    public static string FfiDir => Environment.GetEnvironmentVariable("PQZ_FFI_DIR") ?? Path_("pqz-core", "ffi", "target", "release");
    public static string HooksDir => Path_("pqz-core", "nethermind", "bin", "test-hooks");
    public static string CorpusPath => Environment.GetEnvironmentVariable("PQZ_CORPUS") ?? Path_("pqz-core", "nethermind", "bin", "corpus.jsonl");
}

public sealed record CorpusRow(string Kind, string Name, string Id, string Form, int Op, long StmtLen, byte[] Input, string Expect);

public static class Corpus
{
    private static List<CorpusRow>? _rows;

    public static List<CorpusRow> Rows => _rows ??= File.ReadLines(Repo.CorpusPath).Select(l =>
    {
        JsonObject o = JsonNode.Parse(l)!.AsObject();
        return new CorpusRow((string)o["kind"]!, (string)o["name"]!, (string)o["id"]!, (string)o["form"]!, (int)o["op"]!,
            (long)o["stmt_len"]!, Convert.FromHexString((string)o["input"]!), (string)o["expect"]!);
    }).ToList();

    private static Dictionary<string, string>? _ids;

    /// <summary>The proofSystemIds by name (pqzl, pqzh): statement bytes 32..63 of the honest inputs (the set's own ids,
    /// plan 5h Task 8d).</summary>
    public static Dictionary<string, string> Ids => _ids ??= Rows.Where(r => r.Kind == "honest").GroupBy(r => r.Id)
        .ToDictionary(g => g.Key, g => Convert.ToHexStringLower(g.First().Input.AsSpan(37, 32)));

    /// <summary>op 7's (M, auditorOn) from header words 320 / 448 (plan D19); (0, 0) for the other ops.</summary>
    public static (int Legs, int Aud) Shape(byte[] input) =>
        input.Length > 485 && input[0] == PqzSchedule.OpMulti ? (input[5 + 351], input[5 + 479]) : (0, 0);

    /// <summary>One row per distinct (op, id, stmtLen[, M, auditorOn]) of the honest inputs: pqz1's 12 rows (D12) plus
    /// one per op 7 shape of both ids (S8), with gas 1,000,000 + 1,000 · index (distinct, so a wrong lookup shows).</summary>
    public static JsonArray ScheduleRows()
    {
        JsonArray a = [];
        int i = 0;
        foreach (var g in Rows.Where(r => r.Kind == "honest").GroupBy(r => (r.Op, r.Id, r.StmtLen, Shape(r.Input))).OrderBy(g => g.Key))
        {
            JsonObject o = new() { ["op"] = g.Key.Op, ["id"] = "0x" + Ids[g.Key.Id], ["stmtLen"] = g.Key.StmtLen, ["gas"] = 1_000_000L + 1_000L * i++ };
            if (g.Key.Op == PqzSchedule.OpMulti) { o["legs"] = g.Key.Item4.Legs; o["auditorOn"] = g.Key.Item4.Aud; }
            a.Add(o);
        }
        return a;
    }
}

public static class Hex
{
    public static byte[] B(string s) => Convert.FromHexString(s.StartsWith("0x") ? s[2..] : s);
}

[SetUpFixture]
public class Setup
{
    [OneTimeSetUp]
    public void Library()
    {
        // the node loads Clique as a plugin before the chainspec; here TypeDiscovery must see it too
        _ = typeof(Nethermind.Consensus.Clique.CliqueChainSpecEngineParameters).Assembly;
        PqzNative.LibraryDirectory = Repo.FfiDir;
        TestContext.Progress.WriteLine($"libpqz_ffi.so: {PqzNative.LibraryPath} sha256 {SelfTest.LibrarySha256()}");
    }
}
