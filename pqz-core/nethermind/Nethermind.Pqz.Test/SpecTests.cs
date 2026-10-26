using System;
using System.Collections.Frozen;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Logging;
using Nethermind.Serialization.Json;
using Nethermind.Specs.ChainSpecStyle;
using NUnit.Framework;

namespace Nethermind.Pqz.Test;

/// <summary>P6f Task 1: the chainspec section (D2), the release spec and both providers (D1, R2).</summary>
public class SpecTests
{
    private const ulong T1 = 1_000_000, T2 = 2_000_000;

    public static JsonObject Schedule(ulong ts, long selftestGas = 1000) => new()
    {
        ["timestamp"] = "0x" + ts.ToString("x"),
        ["pqz"] = Corpus.ScheduleRows(),
        ["selftestGas"] = selftestGas,
        ["mldsa44Gas"] = 6500,
        ["mldsa65Gas"] = 9000,
    };

    public static ChainSpec Load(Action<JsonObject>? edit = null)
    {
        JsonObject g = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "chainspecs", "genesis-7622.json")))!.AsObject();
        edit?.Invoke(g);
        return new ChainSpecLoader(new EthereumJsonSerializer(), LimboLogs.Instance).Load(new MemoryStream(Encoding.UTF8.GetBytes(g.ToJsonString())));
    }

    public static ChainSpec WithPqz(params JsonObject[] schedules) =>
        Load(g => g["engine"]!["Pqz"] = new JsonObject { ["schedules"] = new JsonArray(schedules.Select(s => (JsonNode)s).ToArray()) });

    public static ISpecProvider Provider(ChainSpec cs) => new PqzChainSpecBasedSpecProvider(cs, LimboLogs.Instance);

    private static FrozenSet<AddressAsKey> Set(ISpecProvider p, ulong ts) => p.GetSpec(new ForkActivation(10_000, ts)).Precompiles;

    private static readonly AddressAsKey[] Three = [PqzAddresses.Pqz, PqzAddresses.MlDsa44, PqzAddresses.MlDsa65];

    [Test]
    public void Before_T_stock_set_from_T_three_more()
    {
        ISpecProvider stock = new ChainSpecBasedSpecProvider(Load(), LimboLogs.Instance);
        ISpecProvider pqz = Provider(WithPqz(Schedule(T1)));
        Assert.That(Set(pqz, T1 - 1).SetEquals(Set(stock, T1 - 1)), "before T: the stock set");
        Assert.That(Set(pqz, 0).SetEquals(Set(stock, 0)), "genesis: the stock set");
        foreach (ulong ts in new[] { T1, T1 + 1, T2 * 10 })
        {
            FrozenSet<AddressAsKey> s = Set(pqz, ts);
            Assert.That(s.Except(Set(stock, ts)).OrderBy(a => a.Value.ToString()), Is.EqualTo(Three.OrderBy(a => a.Value.ToString())), $"at {ts}");
            Assert.That(Set(stock, ts).All(s.Contains));
        }
        Assert.That(PqzReleaseSpec.ScheduleOf(pqz.GetSpec(new ForkActivation(10_000, T1 - 1))), Is.Null);
        Assert.That(PqzReleaseSpec.ScheduleOf(pqz.GetSpec(new ForkActivation(10_000, T1)))!.Timestamp, Is.EqualTo(T1));
    }

    [Test]
    public void Genesis_activation_from_block_0()
    {
        // a new chain (the 7622 testnet reset, owner 2026-10-15): the schedule at the genesis timestamp is active in
        // every block, genesis included; not a fork transition
        ISpecProvider stock = new ChainSpecBasedSpecProvider(Load(), LimboLogs.Instance);
        ISpecProvider p = Provider(WithPqz(Schedule(0)));
        foreach (var (b, ts) in new[] { (0UL, 0UL), (1UL, 5UL), (10_000UL, T1) })
        {
            FrozenSet<AddressAsKey> s = Set(p, ts);
            Assert.That(s.Except(Set(stock, ts)).Count(), Is.EqualTo(3), $"block {b}");
            Assert.That(PqzReleaseSpec.ScheduleOf(p.GetSpec(new ForkActivation(b, ts))), Is.Not.Null);
        }
        Assert.That(PqzReleaseSpec.ScheduleOf(p.GenesisSpec), Is.Not.Null, "genesis spec");
        Assert.That(p.TransitionActivations.Select(a => a.Timestamp), Does.Not.Contain((ulong?)0));
    }

    [Test]
    public void Two_schedules_switch_at_the_second_timestamp_and_are_fork_transitions()
    {
        ISpecProvider p = Provider(WithPqz(Schedule(T1, 1000), Schedule(T2, 2000)));
        Assert.That(PqzReleaseSpec.ScheduleOf(p.GetSpec(new ForkActivation(1, T2 - 1)))!.SelftestGas, Is.EqualTo(1000));
        Assert.That(PqzReleaseSpec.ScheduleOf(p.GetSpec(new ForkActivation(1, T2)))!.SelftestGas, Is.EqualTo(2000));
        ulong?[] ts = p.TransitionActivations.Select(a => a.Timestamp).ToArray();
        Assert.That(ts, Does.Contain(T1).And.Contain(T2), "fork-id transitions include every schedule timestamp");
    }

    /// <summary>Review W-D (2026-10-19): a release spec built for a block-number transition keeps the PQZ schedule.
    /// Nethermind 1.39.0's <c>ChainSpecBasedSpecProvider.CreateTransitions</c> builds every block-number release with
    /// the genesis timestamp (never null) and every timestamp release at the last block transition;
    /// <c>SpecProviderBase.GetSpec</c> searches the timestamp releases by timestamp alone from the first timestamp
    /// transition on. The test genesis has <c>maxCodeSizeTransition</c> 6432 (a block-number transition reached
    /// after <see cref="T1"/> here) and no other transition above 0.</summary>
    [Test]
    public void A_block_number_transition_keeps_the_schedule()
    {
        const ulong B = 6432;
        Assert.That(Load().Parameters.MaxCodeSizeTransition, Is.EqualTo(B), "the test genesis' block-number transition");
        // (block, timestamp, schedule's selftestGas or null, EIP-170 on = the release of block B or later)
        (ulong b, ulong ts, long? gas, bool eip170)[] genesisAndT1 =
        [
            (0, 0, 1000, false), (1, 5, 1000, false), (B - 1, T1 - 1, 1000, false), (B, T1 - 1, 1000, true), (B + 1, T1 - 1, 1000, true),
            (1, T1, 2000, true), (B - 1, T1, 2000, true), (B, T1, 2000, true), (B + 100, T1 + 100, 2000, true),
        ];
        (ulong b, ulong ts, long? gas, bool eip170)[] onlyT1 =
        [
            (0, 0, null, false), (B - 1, T1 - 1, null, false), (B, T1 - 1, null, true), (B + 1, T1 - 1, null, true),
            (1, T1, 2000, true), (B - 1, T1, 2000, true), (B, T1, 2000, true), (B + 100, T1 + 100, 2000, true),
        ];
        ISpecProvider stock = new ChainSpecBasedSpecProvider(Load(), LimboLogs.Instance);
        foreach (var (name, p, cases) in new[]
                 {
                     ("genesis schedule + T1", Provider(WithPqz(Schedule(0, 1000), Schedule(T1, 2000))), genesisAndT1),
                     ("T1 only", Provider(WithPqz(Schedule(T1, 2000))), onlyT1),
                 })
        {
            foreach (var (b, ts, gas, eip170) in cases)
            {
                string at = $"{name}: block {b} timestamp {ts}";
                IReleaseSpec spec = p.GetSpec(new ForkActivation(b, ts));
                Assert.That(spec.IsEip170Enabled, Is.EqualTo(eip170), at + ": the release of the block-number transition");
                Assert.That(PqzReleaseSpec.ScheduleOf(spec)?.SelftestGas, Is.EqualTo(gas), at + ": schedule");
                FrozenSet<AddressAsKey> extra = spec.Precompiles.Except(stock.GetSpec(new ForkActivation(b, ts)).Precompiles).ToFrozenSet();
                Assert.That(extra.SetEquals(gas is null ? [] : Three), at + ": the three addresses iff a schedule");
            }
            // a lookup by block number alone (no timestamp) is the block-number release: the genesis schedule or none
            Assert.That(PqzReleaseSpec.ScheduleOf(p.GetSpec(new ForkActivation(B)))?.SelftestGas, Is.EqualTo(cases[0].gas), name + ": block B alone");
            Assert.That(p.TransitionActivations, Does.Contain(new ForkActivation(B)).And.Contain(new ForkActivation(B, T1)), name + ": both transitions");
        }
    }

    [Test]
    public void The_schedule_is_found_through_a_decorator()
    {
        IReleaseSpec spec = Provider(WithPqz(Schedule(T1))).GetSpec(new ForkActivation(1, T1));
        IReleaseSpec wrapped = new ReleaseSpecDecorator(spec);
        Assert.That(PqzReleaseSpec.ScheduleOf(wrapped), Is.SameAs(PqzReleaseSpec.ScheduleOf(spec)));
    }

    /// <summary>Nethermind 2.2.0: <c>IsPrecompile</c> (what the VM, the gas policy and the code-info repositories ask)
    /// finds the three 0x5caa5… addresses from T on, directly and through a decorator, and keeps the stock ones.</summary>
    [Test]
    public void IsPrecompile_finds_the_three_from_T()
    {
        ISpecProvider p = Provider(WithPqz(Schedule(T1)));
        IReleaseSpec before = p.GetSpec(new ForkActivation(1, T1 - 1)), after = p.GetSpec(new ForkActivation(1, T1));
        foreach (AddressAsKey a in Three)
        {
            Assert.That(before.IsPrecompile(a), Is.False, $"{a.Value} before T");
            Assert.That(after.IsPrecompile(a), Is.True, $"{a.Value} from T");
            Assert.That(((IReleaseSpec)new ReleaseSpecDecorator(after)).IsPrecompile(a), Is.True, $"{a.Value} through a decorator");
        }
        foreach (IReleaseSpec s in new[] { before, after })
        {
            Assert.That(s.IsPrecompile(Nethermind.Core.Precompiles.PrecompiledAddresses.ECRecover), Is.True);
            Assert.That(s.IsPrecompile(new Address("0x5caa500000000000000000000000000000000f02")), Is.False);
        }
    }

    private static JsonObject Without(JsonObject s, string key) { s.Remove(key); return s; }

    private static JsonObject With(JsonObject s, string key, JsonNode v) { s[key] = v; return s; }

    public static readonly (string, Func<ChainSpec>)[] Bad =
    [
        ("unknown key in a schedule", () => WithPqz(With(Schedule(T1), "mldsa87Gas", 1))),
        ("unknown key at the top", () => Load(g => g["engine"]!["Pqz"] = new JsonObject { ["schedules"] = new JsonArray(Schedule(T1)), ["x"] = 1 })),
        ("unknown key in a row", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 1, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 83072, ["gas"] = 1, ["x"] = 1 })))),
        ("missing selftestGas", () => WithPqz(Without(Schedule(T1), "selftestGas"))),
        ("missing timestamp", () => WithPqz(Without(Schedule(T1), "timestamp"))),
        ("missing pqz", () => WithPqz(Without(Schedule(T1), "pqz"))),
        ("missing schedules", () => Load(g => g["engine"]!["Pqz"] = new JsonObject())),
        ("no schedules", () => WithPqz()),
        ("empty rows", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray()))),
        ("unsorted", () => WithPqz(Schedule(T2), Schedule(T1))),
        ("duplicate timestamp", () => WithPqz(Schedule(T1), Schedule(T1))),
        ("timestamp before genesis", () => Load(g =>
        {
            g["genesis"]!["timestamp"] = "0x10";
            g["engine"]!["Pqz"] = new JsonObject { ["schedules"] = new JsonArray(Schedule(5)) };
        })),
        ("duplicate row", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(Corpus.ScheduleRows()[0]!.DeepClone(), Corpus.ScheduleRows()[0]!.DeepClone())))),
        ("op 6 row", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 6, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 0, ["gas"] = 1 })))),
        ("id of 31 bytes", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 1, ["id"] = "0x" + Corpus.Ids["pqzl"][2..], ["stmtLen"] = 1, ["gas"] = 1 })))),
        ("op 7 row without legs / auditorOn", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 7, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 83072, ["gas"] = 1 })))),
        ("op 7 row with auditorOn 2", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 7, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 83072, ["gas"] = 1, ["legs"] = 1, ["auditorOn"] = 2 })))),
        ("op 7 row with legs 0", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 7, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 83072, ["gas"] = 1, ["legs"] = 0, ["auditorOn"] = 1 })))),
        ("op 1 row with legs", () => WithPqz(With(Schedule(T1), "pqz", new JsonArray(new JsonObject { ["op"] = 1, ["id"] = "0x" + Corpus.Ids["pqzl"], ["stmtLen"] = 83072, ["gas"] = 1, ["legs"] = 1, ["auditorOn"] = 1 })))),
        ("mldsa44Gas below EIP-8355", () => WithPqz(With(Schedule(T1), "mldsa44Gas", 6499))),
        ("mldsa65Gas below EIP-8355", () => WithPqz(With(Schedule(T1), "mldsa65Gas", 8999))),
    ];

    [TestCaseSource(nameof(Bad))]
    public void Strict_section_is_a_start_up_error((string name, Func<ChainSpec> make) c)
    {
        Exception? e = Assert.Throws(Is.InstanceOf<Exception>(), () => Provider(c.make()), c.name);
        string m = e!.ToString();
        TestContext.Progress.WriteLine($"{c.name}: {e.GetType().Name}: {(e.InnerException ?? e).Message}");
        Assert.That(m, Does.Not.Contain("Could not load file").And.Not.Contain("No seal engine"), "fails for the section, not for the test set-up");
    }

    /// <summary>Review R4-C3: the schedule in force at the next block (head + 1) and every later one carry only the
    /// library's ids (compiled in, <see cref="PqzSetIds"/> = gen_set.py's set.json); a schedule the node never executes
    /// again may keep another.</summary>
    [Test]
    public void Schedule_ids_are_the_library_ids_from_the_current_schedule_on()
    {
        JsonObject st = JsonNode.Parse(File.ReadAllText(Repo.Path_("pqz-core", "params", "sets", Repo.Set, "set.json")))!.AsObject();
        Assert.That(PqzSetIds.PqzlId, Is.EqualTo((string)st["pqzl_id"]!), "compiled-in PQZL id = set.json");
        Assert.That(PqzSetIds.PqzhId, Is.EqualTo((string?)st["pqzh_id"] ?? ""), "compiled-in PQZH id = set.json (empty: no PQZH)");
        Assert.That(Corpus.Ids["pqzl"], Is.EqualTo(PqzSetIds.PqzlId), "the corpus' honest PQZL id");
        string[] lib = PqzSetIds.PqzhId == "" ? [PqzSetIds.PqzlId] : [PqzSetIds.PqzlId, PqzSetIds.PqzhId];
        JsonObject Foreign(ulong ts)
        {
            JsonObject s = Schedule(ts);
            JsonArray rows = s["pqz"]!.AsArray();
            rows[0]!["id"] = "0x" + Convert.ToHexStringLower(new byte[32]).Remove(0, 2) + "01"; // not a library id
            return s;
        }
        PqzChainSpecEngineParameters P(params JsonObject[] s) =>
            WithPqz(s).EngineChainSpecParametersProvider.GetChainSpecParameters<PqzChainSpecEngineParameters>();
        // head semantics (owner 2026-10-26, review of fix part b I-1): the schedule in force at head + 1 and every later one
        Assert.DoesNotThrow(() => P(Schedule(T1)).CheckIds(T1, lib));
        Assert.DoesNotThrow(() => P(Foreign(T1), Schedule(T2)).CheckIds(T2 - 1, lib), "head T2 - 1: the next block is at T2 or later, S2 only");
        Exception? e = Assert.Throws<ArgumentException>(() => P(Foreign(T1), Schedule(T2)).CheckIds(T2 - 2, lib), "head T2 - 2: the next block may be before T2, under the foreign S1");
        Assert.That(e!.Message, Does.Contain($"schedule {T1}: row op"));
        Assert.DoesNotThrow(() => P(Foreign(T1), Schedule(T2)).CheckIds(T2 + 5, lib), "head past T2: the foreign S1 is never executed again");
        Assert.Throws<ArgumentException>(() => P(Foreign(T1), Schedule(T2)).CheckIds(T1, lib), "a fresh database (head = genesis T1) would execute S1");
        e = Assert.Throws<ArgumentException>(() => P(Foreign(T1)).CheckIds(T1 + 5, lib), "in force");
        Assert.That(e!.Message, Does.Contain("is not the library's"));
        Assert.Throws<ArgumentException>(() => P(Schedule(T1), Foreign(T2)).CheckIds(T1, lib), "a later schedule");
        Assert.Throws<ArgumentException>(() => P(Foreign(T1)).CheckIds(T1 - 1, lib), "head T1 - 1: S1 in force at the next block");
        Assert.Throws<ArgumentException>(() => P(Foreign(T1)).CheckIds(T1 - 2, lib), "every schedule still ahead");
        Assert.Throws<ArgumentException>(() => P(Schedule(T1)).CheckIds(T1, [PqzSetIds.PqzlId[..62] + "00"]), "another library");
    }

    /// <summary>Plan 5h Task 8d part 2b: the head timestamp the id check reads (and <c>PQZ-START</c> logs) is the block
    /// tree head's when there is one, else the genesis timestamp (empty database), else 0.</summary>
    [Test]
    public void Id_check_head_is_the_block_tree_head_else_the_genesis()
    {
        Assert.That(PqzStartupCheck.IdCheckHead(T2, 7, T1), Is.EqualTo((T2, "block 7")));
        Assert.That(PqzStartupCheck.IdCheckHead(null, null, T1), Is.EqualTo((T1, "genesis, empty database")));
        Assert.That(PqzStartupCheck.IdCheckHead(null, null, null), Is.EqualTo((0UL, "genesis, empty database")));
    }

    [Test]
    public void Stock_provider_with_the_section_fails_closed()
    {
        ChainSpec cs = WithPqz(Schedule(T1));
        Exception? e = Assert.Throws(Is.InstanceOf<Exception>(), () => new ChainSpecBasedSpecProvider(cs, LimboLogs.Instance));
        Assert.That(e!.ToString(), Does.Contain("not PqzReleaseSpec"));
    }

    [Test]
    public void Plugin_enabled_iff_the_section_is_present()
    {
        Assert.That(new PqzPlugin(Load()).Enabled, Is.False);
        Assert.That(new PqzPlugin(WithPqz(Schedule(T1))).Enabled, Is.True);
        Assert.DoesNotThrow(() => new ChainSpecBasedSpecProvider(Load(), LimboLogs.Instance), "without engine.Pqz the stock provider is untouched");
    }

    /// <summary>Nethermind 2.x calls no plugin <c>Init</c>: the start-up checks (R3) must be a registered step that
    /// runs before the genesis block (on 2.2.0 an <c>Init</c> method compiled and was silently never called).</summary>
    [Test]
    public void Startup_checks_are_a_step_before_genesis()
    {
        Autofac.ContainerBuilder b = new();
        Autofac.ModuleRegistrationExtensions.RegisterModule(b, new PqzModule());
        using Autofac.IContainer c = b.Build();
        Assert.That(Autofac.ResolutionExtensions.Resolve<System.Collections.Generic.IEnumerable<Nethermind.Api.Steps.StepInfo>>(c)
            .Select(i => i.StepType), Does.Contain(typeof(PqzStartupCheck)));
        Nethermind.Api.Steps.RunnerStepDependenciesAttribute a = typeof(PqzStartupCheck)
            .GetCustomAttributes(typeof(Nethermind.Api.Steps.RunnerStepDependenciesAttribute), false)
            .Cast<Nethermind.Api.Steps.RunnerStepDependenciesAttribute>().Single();
        Assert.That(a.Dependents, Does.Contain(typeof(Nethermind.Init.Steps.LoadGenesisBlock)));
        Assert.That(typeof(PqzPlugin).GetMethod("Init"), Is.Null, "no dead Init hook");
    }
}

public class AssemblyTests
{
    [Test]
    public void Plugin_references_only_base_image_assemblies_and_the_framework()
    {
        string refDir = Repo.Path_("pqz-core", "nethermind", "ref");
        string fw = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var refs = typeof(PqzPlugin).Assembly.GetReferencedAssemblies().Select(a => a.Name!).OrderBy(n => n).ToList();
        TestContext.Progress.WriteLine("Nethermind.Pqz.dll references: " + string.Join(", ", refs));
        foreach (string n in refs)
            Assert.That(File.Exists(Path.Combine(refDir, n + ".dll")) || File.Exists(Path.Combine(fw, n + ".dll")), n);
        string outDir = Path.GetDirectoryName(typeof(PqzPlugin).Assembly.Location)!;
        Assert.That(File.Exists(Path.Combine(Repo.Path_("pqz-core", "nethermind", "Nethermind.Pqz", "bin", "Release", "net10.0"), "Nethermind.Core.dll")), Is.False, "nothing of Nethermind in the plugin's own output");
    }
}
