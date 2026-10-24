using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nethermind.Core.Crypto;
using Nethermind.Evm.Precompiles;
using Nethermind.Pqz;

// P6f Task 6 (D6, D7): gas calibration inside the built image, on the chain host.
//   Calibrate run <corpus.jsonl> <fresh.jsonl> <ua vectors dir> <out dir> [--n 1000] [--cold 200] [--label L] [--ops 7]
// --ops: only the rows of these ops (comma list; P6-ANON S8 calibrates op 7 alone, the other rows stay as calibrated).
//   Calibrate cold                         (child: one cold OP_SELFTEST, prints its milliseconds)
// t_ecMul = median of Nethermind's own BN254MulPrecompile.Run (EIP-196 vector, same process and JIT); per row
// t_row = max(p99 over n calls on the row's valid inputs (vectors + fresh proofs), p99 over n distinct adversarial
// inputs); gas = 1000·⌈6000·t_row / t_ecMul / 1000⌉ (D6). Everything through PqzPrecompile.Run / MlDsa*.Run.
if (args[0] == "cold")
{
    long t0 = Stopwatch.GetTimestamp();
    string h = SelfTest.Run();
    double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
    Console.WriteLine(FormattableString.Invariant($"{ms:F3} {h}"));
    return h == SelfTest.ExpectedHash ? 0 : 1;
}
return Cal.Exec(args);

static class Cal
{
    static int N = 1000;
    static readonly StringBuilder Log = new();

    static void W(string s)
    {
        Console.WriteLine(s);
        Log.AppendLine(s);
    }

    static string F(double v) => v.ToString("F3", System.Globalization.CultureInfo.InvariantCulture);

    static double Pct(List<double> v, double p)
    {
        v.Sort();
        return v[(int)Math.Round((v.Count - 1) * p)];
    }

    static List<double> Time(IReadOnlyList<byte[]> inputs, int n, Func<byte[], bool> f)
    {
        foreach (byte[] x in inputs.Take(Math.Min(inputs.Count, 20))) f(x); // warm (relation keys, tables, JIT)
        List<double> t = new(n);
        for (int i = 0; i < n; i++)
        {
            byte[] x = inputs[i % inputs.Count];
            long t0 = Stopwatch.GetTimestamp();
            bool ok = f(x);
            t.Add(Stopwatch.GetElapsedTime(t0).TotalMilliseconds);
            if (!ok) throw new InvalidOperationException("unexpected result while timing");
        }
        return t;
    }

    public static int Exec(string[] a)
    {
        string corpusPath = a[1], freshPath = a[2], uaDir = a[3], outDir = a[4];
        int Arg(string name, int def) { int i = Array.IndexOf(a, name); return i >= 0 ? int.Parse(a[i + 1]) : def; }
        N = Arg("--n", 1000);
        int cold = Arg("--cold", 200);
        string label = Array.IndexOf(a, "--label") is var li and >= 0 ? a[li + 1] : "calib";
        HashSet<int>? ops = Array.IndexOf(a, "--ops") is var oi and >= 0 ? a[oi + 1].Split(',').Select(int.Parse).ToHashSet() : null;
        Directory.CreateDirectory(outDir);

        W($"# P6f calibration ({label}) {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z  host {Environment.MachineName}  cpus {Environment.ProcessorCount}  .NET {Environment.Version}");
        W($"# libpqz_ffi.so {PqzNative.LibraryPath} sha256 {SelfTest.LibrarySha256()}; n = {N} per set; cold self-test {cold} processes");
        W($"# {File.ReadAllText("/proc/cpuinfo").Split('\n').FirstOrDefault(l => l.StartsWith("model name"))}");

        // t_ecMul: EIP-196 vector (bn256ScalarMul_chfast1), priced 6,000 (EIP-1108)
        byte[] mulIn = Convert.FromHexString("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2");
        string mulOut = "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc";
        if (Convert.ToHexStringLower(BN254MulPrecompile.Instance.Run(mulIn, null!).Data!) != mulOut) throw new InvalidOperationException("BN254 mul vector");
        List<double> ec = Time([mulIn], Math.Max(N * 10, 10_000), x => BN254MulPrecompile.Instance.Run(x, null!).IsSuccess);
        double tEc = Pct(ec, 0.5);
        W($"t_ecMul median {F(tEc)} ms (p99 {F(Pct(ec, 0.99))}, n {ec.Count}) ⇒ {F(6000 / tEc / 1e6)} M gas per ms");

        var corpus = File.ReadLines(corpusPath).Select(l => JsonNode.Parse(l)!.AsObject()).Select(o =>
            (kind: (string)o["kind"]!, name: (string)o["name"]!, id: (string)o["id"]!, form: (string)o["form"]!, input: Convert.FromHexString((string)o["input"]!), expect: (string)o["expect"]!)).ToList();
        var fresh = File.ReadLines(freshPath).Select(l => JsonNode.Parse(l)!.AsObject())
            .Select(o => (id: (string)o["id"]!, input: Convert.FromHexString((string)o["input"]!))).ToList();
        // op 7: (M, auditorOn) from header words 320 / 448 (plan D19; the low byte, as the corpus' shapes are small)
        static (int op, uint len, string idHex, int legs, int aud) Key(byte[] x) =>
            (x[0], (uint)(x[1] << 24 | x[2] << 16 | x[3] << 8 | x[4]), Convert.ToHexStringLower(x.AsSpan(37, 32)),
             x[0] == PqzSchedule.OpMulti && x.Length > 485 ? x[5 + 351] : 0, x[0] == PqzSchedule.OpMulti && x.Length > 485 ? x[5 + 479] : 0);
        static JsonObject Row((int op, uint len, string idHex, int legs, int aud) k, long gas)
        {
            JsonObject o = new() { ["op"] = k.op, ["id"] = "0x" + k.idHex, ["stmtLen"] = k.len, ["gas"] = gas };
            if (k.op == PqzSchedule.OpMulti) { o["legs"] = k.legs; o["auditorOn"] = k.aud; }
            return o;
        }

        // every row of pqz-ffi's forms (D12): the distinct keys of the honest inputs; one schedule admitting all
        var keys = corpus.Where(r => r.kind == "honest").Select(r => (k: Key(r.input), r.id)).Distinct().OrderBy(r => r.k.op).ThenBy(r => r.id).ThenByDescending(r => r.k.len).ThenBy(r => r.k.legs).ThenBy(r => r.k.aud).ToList();
        JsonArray rows0 = new(keys.Select(k => (JsonNode)Row(k.k, 1)).ToArray());
        if (ops is not null) keys = keys.Where(k => ops.Contains(k.k.op)).ToList();
        PqzSchedule sched = Sched(rows0, 1, 6500, 9000);
        byte[] One = [.. new byte[31], 1], Zero = new byte[32];
        bool Is(byte[] x, byte[] want) => PqzPrecompile.Run(x, sched) is { IsSuccess: true } r && r.Data!.AsSpan().SequenceEqual(want);

        Random rng = new(7622);
        JsonArray rowsOut = [];
        W("");
        W("| op | id | stmtLen [M, auditorOn] | forms | valid n | p50 valid ms | p99 valid ms | p99 adversarial ms | worst adversarial set | t_row ms | gas | + calldata floor of the largest honest input (direct tx) |");
        W("|---|---|---|---|---|---|---|---|---|---|---|---|");
        long minGas = long.MaxValue;
        List<string> notes = [];
        foreach (var (k, id) in keys)
        {
            bool Mine(byte[] x) => x.Length >= 69 && Key(x) == k;
            var valid = corpus.Where(r => r.expect == "1" && Mine(r.input)).Select(r => r.input).Concat(fresh.Where(f => Mine(f.input)).Select(f => f.input)).ToList();
            string forms = string.Join("+", corpus.Where(r => r.kind == "honest" && Mine(r.input)).Select(r => r.form));
            int freshN = fresh.Count(f => Mine(f.input));
            List<double> tv = Time(valid, N, x => Is(x, One));

            // adversarial sets: (1) N distinct one-bit proof flips of the honest / fresh inputs that decode and fail;
            // (2) the negative.json rows of this key (decoder- or verifier-rejected); (3) PQZH: the honest proof under
            // the statement with its last word changed
            List<byte[]> flips = [];
            HashSet<string> seen = [];
            while (flips.Count < N)
            {
                byte[] b = valid[rng.Next(valid.Count)];
                int stmtEnd = 5 + (int)k.len;
                byte[] x = (byte[])b.Clone();
                int at = stmtEnd + rng.Next(x.Length - stmtEnd);
                x[at] ^= (byte)(1 << rng.Next(8));
                if (seen.Add(Convert.ToHexString(Keccak.Compute(x).Bytes))) flips.Add(x);
            }
            var negs = corpus.Where(r => r.kind is "negative" or "flip" && r.expect == "0" && Mine(r.input) && r.input.Length <= PqzNative.MaxInput).Select(r => r.input).ToList();
            List<byte[]> lastWord = valid.Take(Math.Min(valid.Count, 50)).Select(b =>
            {
                byte[] x = (byte[])b.Clone();
                x[5 + (int)k.len - 1] ^= 1;
                return x;
            }).ToList();
            var sets = new List<(string name, List<byte[]> inputs)> { ("proof bit flips", flips), ("negative.json", negs), ("stmt last word", lastWord) };
            double pAdv = 0;
            string worst = "";
            foreach (var (name, inputs) in sets.Where(s => s.inputs.Count > 0))
            {
                double p = Pct(Time(inputs, N, x => Is(x, Zero)), 0.99);
                if (p > pAdv) { pAdv = p; worst = $"{name} ({inputs.Count})"; }
            }
            double p99v = Pct(tv, 0.99), tRow = Math.Max(p99v, pAdv);
            long gas = 1000L * (long)Math.Ceiling(6000 * tRow / tEc / 1000);
            minGas = Math.Min(minGas, gas);
            byte[] big = valid.MaxBy(x => x.Length)!;
            long direct = DirectTx(big, gas);
            long maxProof = id == "pqzl" ? 98_304 : 262_144;
            long directMax = DirectTx(new byte[5 + k.len + maxProof].Select((_, i) => (byte)(i % 251 + 1)).ToArray(), gas);
            W($"| {k.op} | {id} | {k.len}{(k.op == PqzSchedule.OpMulti ? $" [{k.legs}, {k.aud}]" : "")} | {forms} | {valid.Count} ({freshN} fresh) | {F(Pct(tv, 0.5))} | {F(p99v)} | {F(pAdv)} | {worst} | {F(tRow)} | {gas:N0} | {direct:N0} ({big.Length:N0} B){(direct > 16_777_216 ? " **> EIP-7825**" : "")} |");
            if (tRow > 60) notes.Add($"op {k.op} {id} {k.len}: t_row {F(tRow)} ms > 60 ms (CTR-PQZ-09)");
            if (directMax > 16_777_216) notes.Add($"op {k.op} {id} stmtLen {k.len}: an input at MAX_PROOF ({5 + k.len + maxProof:N0} B, all non-zero) as a direct tx needs {directMax:N0} gas > 16,777,216 (P6g note; honest proofs: {direct:N0})");
            rowsOut.Add(Row(k, gas));
        }

        // cold OP_SELFTEST: fresh processes (R3: the plugin computes it at start-up; recorded, not priced)
        List<double> coldMs = [];
        string self = Environment.ProcessPath!, dll = typeof(Cal).Assembly.Location;
        for (int i = 0; i < cold; i++)
        {
            ProcessStartInfo psi = new(self, [dll, "cold"]) { RedirectStandardOutput = true };
            using Process p = Process.Start(psi)!;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            if (p.ExitCode != 0) throw new InvalidOperationException("cold self-test: " + o);
            coldMs.Add(double.Parse(o.Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture));
        }
        List<double> warm = Time([[6, 0, 0, 0, 0]], N, x => PqzPrecompile.Run(x, sched).Data!.AsSpan().SequenceEqual(Convert.FromHexString(SelfTest.ExpectedHash)));
        W("");
        if (cold > 0) W($"OP_SELFTEST cold (first call in a fresh process, {coldMs.Count} processes): p50 {F(Pct(coldMs, 0.5))} ms, p99 {F(Pct(coldMs, 0.99))} ms ⇒ cold price would be {1000L * (long)Math.Ceiling(6000 * Pct(coldMs, 0.99) / tEc / 1000):N0} gas");
        W($"OP_SELFTEST warm (cached): p50 {F(Pct(warm, 0.5))} ms, p99 {F(Pct(warm, 0.99))} ms; selftestGas = the smallest row = {minGas:N0} (D6, R3)");

        // ML-DSA: ACVP external cases (pk ‖ sig ‖ msg: valid only with the empty context), EIP-8355 and the UA rows
        JsonObject ext = JsonNode.Parse(File.ReadAllText(Path.Combine(uaDir, "pq_external.json")))!.AsObject();
        long[] mlGas = new long[2];
        foreach (var (lvl, pk, sig, bas) in new[] { (44, MlDsa.Pk44, MlDsa.Sig44, MlDsa.Base44), (65, MlDsa.Pk65, MlDsa.Sig65, MlDsa.Base65) })
        {
            List<byte[]> ins = [];
            foreach (JsonNode? c in ext["acvp_mldsa"]!["cases"]!.AsArray())
            {
                if ((string)c!["iface"]! != "external") continue;
                byte[] p = Convert.FromHexString(((string)c["pk"]!)[2..]), m = Convert.FromHexString(((string)c["mprime"]!)[2..]);
                if (p.Length != pk) continue;
                ins.Add([.. p, .. Convert.FromHexString(((string)c["sig"]!)[2..]), .. m[(2 + m[1])..]]);
            }
            List<double> t = Time(ins, N, x => (lvl == 44 ? MlDsa44Precompile.Instance.Run(x, null!) : MlDsa65Precompile.Instance.Run(x, null!)).IsSuccess);
            double p99 = Pct(t, 0.99);
            long cal = 1000L * (long)Math.Ceiling(6000 * p99 / tEc / 1000);
            mlGas[lvl == 44 ? 0 : 1] = Math.Max(bas, cal);
            W($"ML-DSA-{lvl}: {ins.Count} ACVP inputs, p50 {F(Pct(t, 0.5))} ms, p99 {F(p99)} ms ⇒ calibrated {cal:N0}, EIP-8355 BASE {bas:N0} ⇒ mldsa{lvl}Gas {Math.Max(bas, cal):N0}");
        }

        W("");
        foreach (string n in notes) W("NOTE " + n);
        if (notes.Count == 0) W("sanity: every t_row ≤ 60 ms; every honest and MAX_PROOF input fits a direct transaction");

        JsonObject engine = new()
        {
            ["schedules"] = new JsonArray(new JsonObject
            {
                ["timestamp"] = "0x0", // filled in by patch-chainspec.py / the runbook
                ["pqz"] = rowsOut,
                ["selftestGas"] = minGas,
                ["mldsa44Gas"] = mlGas[0],
                ["mldsa65Gas"] = mlGas[1],
            }),
        };
        File.WriteAllText(Path.Combine(outDir, $"{label}-engine-pqz.json"), engine.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
        File.WriteAllText(Path.Combine(outDir, $"{label}.txt"), Log.ToString());
        return 0;
    }

    static PqzSchedule Sched(JsonArray rows, long self, long m44, long m65)
    {
        JsonObject s = new() { ["timestamp"] = 1, ["pqz"] = rows.DeepClone(), ["selftestGas"] = self, ["mldsa44Gas"] = m44, ["mldsa65Gas"] = m65 };
        PqzSchedule p = new Nethermind.Serialization.Json.EthereumJsonSerializer().Deserialize<PqzSchedule>(s.ToJsonString())!;
        p.Validate();
        return p;
    }

    /// <summary>Gas of a transaction sent straight to PQZ with <paramref name="input"/> as calldata: max(standard,
    /// EIP-7623 floor) with the precompile's gas as execution.</summary>
    static long DirectTx(byte[] input, long rowGas)
    {
        long zeros = input.Count(b => b == 0), nonzero = input.Length - zeros;
        long tokens = zeros + 4 * nonzero;
        long standard = 21_000 + 4 * tokens + rowGas + 3 * ((input.Length + 31) / 32);
        long floor = 21_000 + 10 * tokens;
        return Math.Max(standard, floor);
    }
}
