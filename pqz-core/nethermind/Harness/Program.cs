using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Logging;
using Nethermind.Pqz;
using Nethermind.Serialization.Json;

// P6f Task 4: the P/Invoke boundary harness (CTR-PQZ-10 "P/Invoke harness under the .NET host"), through
// PqzPrecompile.Run / MlDsa*Precompile.Run, never the C ABI directly.
//   Harness run   <ffiDir> <corpus.jsonl> <repoRoot> [--minutes N] [--threads 8] [--seed S]
//   Harness fault <hooksDir> <corpus.jsonl>        (test child: status 4 through PqzPrecompile.Run ⇒ exit 120)
return args.Length > 0 && args[0] == "fault" ? Fault.Exec(args) : Run.Exec(args);

static class Shared
{
    public static List<(string kind, string id, byte[] input, string expect)> Corpus(string path) =>
        File.ReadLines(path).Select(l => JsonNode.Parse(l)!.AsObject()).Select(o =>
            ((string)o["kind"]!, (string)o["id"]!, Convert.FromHexString((string)o["input"]!), (string)o["expect"]!)).ToList();

    public static readonly Dictionary<string, string> Ids = new()
    {
        ["pqzl"] = "2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f",
        ["pqzh"] = "0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4",
    };

    /// <summary>The pqz1 rows (every distinct (op, id, stmtLen) of the honest inputs), gas 1,000,000.</summary>
    public static PqzSchedule Schedule(IEnumerable<(string kind, string id, byte[] input, string expect)> corpus)
    {
        JsonArray rows = [];
        foreach (var k in corpus.Where(r => r.kind == "honest")
                     .Select(r => (op: (int)r.input[0], r.id, len: r.input[1] << 24 | r.input[2] << 16 | r.input[3] << 8 | r.input[4])).Distinct())
            rows.Add(new JsonObject { ["op"] = k.op, ["id"] = "0x" + Ids[k.id], ["stmtLen"] = k.len, ["gas"] = 1_000_000 });
        JsonObject s = new() { ["timestamp"] = 1, ["pqz"] = rows, ["selftestGas"] = 1_000_000, ["mldsa44Gas"] = 6500, ["mldsa65Gas"] = 9000 };
        PqzSchedule p = new EthereumJsonSerializer().Deserialize<PqzSchedule>(s.ToJsonString());
        p.Validate();
        return p;
    }
}

static class Fault
{
    [DllImport("libdl.so.2")] private static extern IntPtr dlopen(string file, int mode);

    public static int Exec(string[] a)
    {
        PqzNative.LibraryDirectory = a[1];
        var corpus = Shared.Corpus(a[2]);
        PqzSchedule s = Shared.Schedule(corpus);
        byte[] input = corpus.First(r => r.kind == "honest" && r.id == "pqzl").input;
        Console.WriteLine($"fault child: before the hook {Convert.ToHexStringLower(PqzPrecompile.Run(input, s).Data!)}");
        IntPtr lib = NativeLibrary.Load(PqzNative.LibraryPath);
        unsafe
        {
            var fail = (delegate* unmanaged<byte, void>)NativeLibrary.GetExport(lib, "pqz_test_fail_worker");
            fail(1);
        }
        Console.WriteLine("fault child: TEST_FAIL_WORKER on");
        PqzPrecompile.Run(input, s);
        Console.WriteLine("fault child: returned (must not happen)");
        return 1;
    }
}

/// <summary>Counts PQZ-INPUT-PANIC (status 3) warnings.</summary>
sealed class CountingLogger : InterfaceLogger
{
    public long Panics;
    public void Info(string text) { }
    public void Warn(string text) { if (text.StartsWith("PQZ-INPUT-PANIC")) Interlocked.Increment(ref Panics); Console.Error.WriteLine(text); }
    public void Debug(string text) { }
    public void Trace(string text) { }
    public void Error(string text, Exception? ex = null) => Console.Error.WriteLine(text);
    public bool IsInfo => false;
    public bool IsWarn => true;
    public bool IsDebug => false;
    public bool IsTrace => false;
    public bool IsError => true;
}

static class Run
{
    const int MaxInput = PqzNative.MaxInput;

    public static int Exec(string[] a)
    {
        PqzNative.LibraryDirectory = a[1];
        var corpus = Shared.Corpus(a[2]);
        string root = a[3];
        double minutes = Arg(a, "--minutes", 10);
        int threads = (int)Arg(a, "--threads", 8);
        int seed = (int)Arg(a, "--seed", 7622);
        CountingLogger counter = new();
        PqzPrecompile.Log = new ILogger(counter);
        PqzSchedule sched = Shared.Schedule(corpus);
        string selftest = SelfTest.ExpectedHash;

        // PQZ bases: every corpus input; the honest ones (honest, fee0) are the only valid unedited inputs
        byte[][] pqz = corpus.Select(r => r.input).ToArray();
        bool[] pqzValid = corpus.Select(r => r.expect == "1").ToArray();
        // an edit can turn a negative row back into its honest input (op, id, length edits undo the row's own edit):
        // the oracle is "valid iff byte-equal to a valid corpus input", by SHA-256
        HashSet<string> validSet = corpus.Where(r => r.expect == "1").Select(r => Convert.ToHexString(SHA256.HashData(r.input))).ToHashSet();
        // ML-DSA bases (EIP-8355 layout): eip8355, the ACVP external cases as pk ‖ sig ‖ msg, the UA rows
        var ml = MlDsaBases(root);

        Console.WriteLine($"runtime .NET {Environment.Version}, {RuntimeInformation.OSDescription}, MLDsa.IsSupported={MLDsa.IsSupported}");
        Console.WriteLine($"harness: ffi {PqzNative.LibraryPath} sha256 {SelfTest.LibrarySha256()}; corpus {pqz.Length} PQZ inputs ({pqzValid.Count(v => v)} valid), {ml.Count} ML-DSA inputs ({ml.Count(m => m.valid)} valid); {threads} threads (1 MiB stacks) + 1 GC-pressure thread; {minutes} min; seed {seed}");

        long deadline = Stopwatch.GetTimestamp() + (long)(minutes * 60 * Stopwatch.Frequency);
        ConcurrentDictionary<string, long> counts = new();
        ConcurrentQueue<string> failures = new();
        long[] perThread = new long[threads];
        void Count(string k) => counts.AddOrUpdate(k, 1, (_, v) => v + 1);
        void Fail(string what, byte[] input)
        {
            if (failures.Count < 50) failures.Enqueue($"{what} len={input.Length} keccak={Keccak.Compute(input)}");
            Count("FAIL");
        }

        bool stop = false;
        Thread gc = new(() =>
        {
            List<byte[]> hold = [];
            Random r = new(seed ^ 0x5a5a);
            while (!Volatile.Read(ref stop))
            {
                hold.Add(new byte[r.Next(1, 4 << 20)]);
                if (hold.Count > 16) hold.RemoveRange(0, 8);
                GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
                Thread.Sleep(r.Next(0, 3));
            }
        }) { IsBackground = true };
        gc.Start();

        Thread[] ts = new Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            int tid = t;
            ts[t] = new Thread(() =>
            {
                Random r = new(seed * 1000 + tid);
                while (Stopwatch.GetTimestamp() < deadline)
                {
                    perThread[tid]++;
                    if (r.Next(8) == 0) OneMlDsa(r);
                    else OnePqz(r);
                }
            }, maxStackSize: 1 << 20);
            ts[t].Start();
        }

        void OnePqz(Random r)
        {
            string gen;
            byte[] x;
            bool unedited = false;
            int pick = r.Next(pqz.Length);
            int g = r.Next(100);
            if (g < 4) { gen = "unedited"; x = pqz[pick]; unedited = true; }
            else if (g < 7) { gen = "random"; x = new byte[r.Next(0, r.Next(8) == 0 ? MaxInput + 2 : 4096)]; r.NextBytes(x); }
            else { (gen, x) = Edit(r, pqz[pick]); if (x.AsSpan().SequenceEqual(pqz[pick])) { gen = "unedited"; unedited = true; } }
            Count("pqz gen " + gen);
            bool honest = validSet.Contains(Convert.ToHexString(SHA256.HashData(x)));
            if (honest && !unedited) Count("pqz edit restored an honest input");
            Result<byte[]> o1, o2;
            long g1, g2;
            try
            {
                g1 = PqzPrecompile.Gas(x, sched);
                o1 = PqzPrecompile.Run(x, sched);
                g2 = PqzPrecompile.Gas(x, sched);
                o2 = PqzPrecompile.Run(x, sched);
            }
            catch (Exception e) { Fail($"pqz exception {e.GetType().Name}: {e.Message}", x); return; }
            if (g1 != g2) Fail("pqz gas differs", x);
            if (o1.IsSuccess != o2.IsSuccess || (o1.IsSuccess && !o1.Data!.AsSpan().SequenceEqual(o2.Data))) Fail("pqz output differs", x);
            if (o1.IsError)
            {
                if (x.Length > MaxInput) Count("pqz out revert"); else Fail($"pqz failed call at len {x.Length}: {o1.Error}", x);
                return;
            }
            byte[] o = o1.Data!;
            string h = Convert.ToHexStringLower(o);
            if (o.Length != 32) { Fail("pqz output length", x); return; }
            if (x.Length > MaxInput) { Fail("pqz over MAX_INPUT without revert", x); return; }
            if (h == selftest) { Count("pqz out selftest"); if (!(x.Length == 5 && x[0] == 6 && x[1..].All(b => b == 0))) Fail("selftest hash for another input", x); return; }
            if (o.AsSpan(0, 31).ContainsAnyExcept((byte)0) || o[31] > 1) { Fail("pqz output not …00 / …01 / selftest", x); return; }
            if (o[31] == 1)
            {
                Count("pqz out 01");
                if (honest) Count("pqz 01 honest"); else Fail("a non-honest input is valid", x);
                return;
            }
            Count("pqz out 00");
            if (honest) Fail("an honest input is invalid", x);
        }

        void OneMlDsa(Random r)
        {
            int pick = r.Next(ml.Count);
            var (lvl, bx, valid) = ml[pick];
            string gen;
            byte[] x;
            bool unedited = false;
            int g = r.Next(10);
            if (g < 2) { gen = "unedited"; x = bx; unedited = true; }
            else { (gen, x) = EditMl(r, bx); if (x.AsSpan().SequenceEqual(bx)) { gen = "unedited"; unedited = true; } }
            Count($"mldsa{lvl} gen {gen}");
            byte[] o1, o2;
            try
            {
                o1 = (lvl == 44 ? MlDsa44Precompile.Instance.Run(x, null!) : MlDsa65Precompile.Instance.Run(x, null!)).Data!;
                o2 = (lvl == 44 ? MlDsa44Precompile.Instance.Run(x, null!) : MlDsa65Precompile.Instance.Run(x, null!)).Data!;
            }
            catch (Exception e) { Fail($"mldsa{lvl} exception {e.GetType().Name}: {e.Message}", x); return; }
            if (o1.Length != 32 || !o1.AsSpan().SequenceEqual(o2) || o1.AsSpan(0, 31).ContainsAnyExcept((byte)0) || o1[31] > 1) { Fail($"mldsa{lvl} output", x); return; }
            Count($"mldsa{lvl} out 0{o1[31]}");
            if (o1[31] == 1 && !(unedited && valid)) Fail($"mldsa{lvl}: an edited / invalid input is valid", x);
            if (o1[31] == 0 && unedited && valid) Fail($"mldsa{lvl}: a valid input is invalid", x);
            if (o1[31] == 1) Count($"mldsa{lvl} 01 unedited-valid");
        }

        Stopwatch sw = Stopwatch.StartNew();
        foreach (Thread t in ts) t.Join();
        Volatile.Write(ref stop, true);
        gc.Join();

        long total = perThread.Sum();
        Console.WriteLine($"elapsed {sw.Elapsed.TotalMinutes:F1} min; inputs {total} ({total / sw.Elapsed.TotalSeconds:F0}/s); per thread [{string.Join(", ", perThread)}]");
        foreach (var kv in counts.OrderBy(k => k.Key)) Console.WriteLine($"  {kv.Key,-36} {kv.Value}");
        Console.WriteLine($"  status 3 (PQZ-INPUT-PANIC)            {counter.Panics}");
        Console.WriteLine($"  GC collections gen0/1/2               {GC.CollectionCount(0)}/{GC.CollectionCount(1)}/{GC.CollectionCount(2)}");
        long ok01 = counts.GetValueOrDefault("pqz out 01"), unedited01 = counts.GetValueOrDefault("pqz 01 honest");
        Console.WriteLine($"  …01 = inputs byte-equal to an honest input: {ok01} = {unedited01}: {(ok01 == unedited01 ? "yes" : "NO")}");
        foreach (string f in failures) Console.WriteLine("FAILURE " + f);
        bool clean = !counts.ContainsKey("FAIL") && counter.Panics == 0 && ok01 == unedited01;
        Console.WriteLine(clean ? "harness: CLEAN" : "harness: FAILED");
        return clean ? 0 : 1;
    }

    static double Arg(string[] a, string name, double def)
    {
        int i = Array.IndexOf(a, name);
        return i >= 0 ? double.Parse(a[i + 1]) : def;
    }

    static (string, byte[]) Edit(Random r, byte[] b)
    {
        byte[] x = (byte[])b.Clone();
        switch (r.Next(9))
        {
            case 0:
                {
                    int n = 1 + r.Next(8);
                    for (int i = 0; i < n && x.Length > 0; i++) x[r.Next(x.Length)] ^= (byte)(1 << r.Next(8));
                    return ("bitflips", x);
                }
            case 1:
                {
                    if (x.Length == 0) return ("byterun", x);
                    int at = r.Next(x.Length), n = Math.Min(x.Length - at, 1 + r.Next(256));
                    byte v = (byte)r.Next(3) switch { 0 => 0, 1 => 0xff, _ => (byte)r.Next(256) };
                    x.AsSpan(at, n).Fill(v);
                    return ("byterun", x);
                }
            case 2: return ("truncate", x[..r.Next(x.Length + 1)]);
            case 3:
                {
                    byte[] ext = new byte[r.Next(1, r.Next(4) == 0 ? 70_000 : 64)];
                    if (r.Next(2) == 0) r.NextBytes(ext);
                    return ("extend", [.. x, .. ext]);
                }
            case 4:
                {
                    if (x.Length < 5) return ("lenfield", x);
                    uint len = (uint)(x[1] << 24 | x[2] << 16 | x[3] << 8 | x[4]);
                    uint nl = r.Next(5) switch { 0 => len + 1, 1 => len - 1, 2 => 0, 3 => uint.MaxValue, _ => (uint)r.Next() };
                    x[1] = (byte)(nl >> 24); x[2] = (byte)(nl >> 16); x[3] = (byte)(nl >> 8); x[4] = (byte)nl;
                    return ("lenfield", x);
                }
            case 5:
                if (x.Length > 0) x[0] = (byte)r.Next(0, 9);
                return ("opswap", x);
            case 6:
                {
                    if (x.Length < 69) return ("idswap", x);
                    string id = Convert.ToHexStringLower(x.AsSpan(37, 32));
                    byte[] other = r.Next(3) == 0 ? RandomNumberGenerator.GetBytes(32)
                        : Convert.FromHexString(id == Shared.Ids["pqzl"] ? Shared.Ids["pqzh"] : Shared.Ids["pqzl"]);
                    other.CopyTo(x, 37);
                    return ("idswap", x);
                }
            case 7:
                {
                    // the proof's tail (the last check's region) flipped
                    if (x.Length < 70) return ("tailflip", x);
                    x[x.Length - 1 - r.Next(Math.Min(4096, x.Length - 69))] ^= (byte)(1 << r.Next(8));
                    return ("tailflip", x);
                }
            default:
                {
                    // the statement region (after the id word) flipped: decodes, fails at verify for most bits
                    if (x.Length < 80) return ("stmtflip", x);
                    x[69 + r.Next(Math.Max(1, Math.Min(x.Length - 69, 83_072)))] ^= (byte)(1 << r.Next(8));
                    return ("stmtflip", x);
                }
        }
    }

    static (string, byte[]) EditMl(Random r, byte[] b)
    {
        byte[] x = (byte[])b.Clone();
        switch (r.Next(4))
        {
            case 0:
                for (int i = 1 + r.Next(4); i > 0 && x.Length > 0; i--) x[r.Next(x.Length)] ^= (byte)(1 << r.Next(8));
                return ("bitflips", x);
            case 1: return ("truncate", x[..r.Next(x.Length + 1)]);
            case 2: { byte[] e = new byte[r.Next(1, 200)]; r.NextBytes(e); return ("extend", [.. x, .. e]); }
            default: { byte[] y = new byte[r.Next(0, 6000)]; r.NextBytes(y); return ("random", y); }
        }
    }

    static List<(int lvl, byte[] input, bool valid)> MlDsaBases(string root)
    {
        static bool V(JsonNode? v) => v!.GetValueKind() == System.Text.Json.JsonValueKind.String ? bool.Parse((string)v!) : (bool)v!;
        static byte[] H(string s) => Convert.FromHexString(s.StartsWith("0x") ? s[2..] : s);
        static int Lvl(int pk) => pk == MlDsa.Pk44 ? 44 : 65;
        List<(int, byte[], bool)> l = [];
        JsonObject ext = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "smartcontracts/vectors/ua/pq_external.json")))!.AsObject();
        foreach (JsonNode? c in ext["eip8355"]!["cases"]!.AsArray())
            if (c!["pk"] is not null) l.Add((Lvl(H((string)c["pk"]!).Length), H((string)c["input"]!), V(c["valid"])));
        foreach (JsonNode? c in ext["acvp_mldsa"]!["cases"]!.AsArray())
        {
            if ((string)c!["iface"]! != "external") continue;
            byte[] pk = H((string)c["pk"]!), mp = H((string)c["mprime"]!);
            byte[] msg = mp[(2 + mp[1])..];
            l.Add((Lvl(pk.Length), [.. pk, .. H((string)c["sig"]!), .. msg], mp[1] == 0 && V(c["valid"])));
        }
        JsonObject sigs = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "smartcontracts/vectors/ua/pq_signatures.json")))!.AsObject();
        foreach (JsonObject k in sigs["kinds"]!.AsArray().Concat(sigs["extraKeys"]!.AsArray()).Select(k => k!.AsObject()).Where(k => (string)k["name"]! is "mldsa44" or "mldsa65"))
        {
            byte[] pk = H((string)k["keyData"]!);
            byte[] tag = Keccak.Compute(Encoding.ASCII.GetBytes($"scaas.ua.{k["name"]}.v1")).BytesToArray();
            foreach (string p in new[] { "pop", "popOther" })
                if (k[p] is { } s) l.Add((Lvl(pk.Length), [.. pk, .. H((string)s["sig"]!), .. Keccak.Compute([.. tag, .. H((string)s["message"]!)]).BytesToArray()], true));
        }
        return l;
    }
}
