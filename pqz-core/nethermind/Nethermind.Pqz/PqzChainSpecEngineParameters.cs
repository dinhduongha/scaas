using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using Nethermind.Specs;
using Nethermind.Specs.ChainSpecStyle;

namespace Nethermind.Pqz;

/// <summary>
/// The chainspec section <c>engine.Pqz</c> (P6f D2), strict: a missing or unknown key, an empty or unsorted schedule
/// list, a duplicate timestamp or row, or a price below EIP-8355's ⇒ start-up error. Not a seal engine
/// (<see cref="SealEngineType"/> null). Nethermind instantiates this class for any chainspec whose <c>engine</c> has a
/// <c>Pqz</c> key, whichever spec provider wins; <see cref="ApplyToReleaseSpec"/> then fails closed unless the spec is
/// a <see cref="PqzReleaseSpec"/>.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public class PqzChainSpecEngineParameters : IChainSpecEngineParameters
{
    public const string Engine = "Pqz";

    [JsonIgnore] public string EngineName => Engine;
    [JsonIgnore] public string? SealEngineType => null;

    public required List<PqzSchedule> Schedules { get; init; }

    private bool _valid;

    /// <summary>Structure checks (no genesis needed); idempotent.</summary>
    public void Validate()
    {
        if (_valid) return;
        if (Schedules is null || Schedules.Count == 0) throw new ArgumentException("engine.Pqz: no schedules");
        for (int i = 0; i < Schedules.Count; i++)
        {
            PqzSchedule s = Schedules[i] ?? throw new ArgumentException($"engine.Pqz: schedule {i} is null");
            if (i > 0 && s.Timestamp <= Schedules[i - 1].Timestamp)
                throw new ArgumentException($"engine.Pqz: schedule timestamps must increase strictly ({Schedules[i - 1].Timestamp} then {s.Timestamp})");
            s.Validate();
        }
        _valid = true;
    }

    /// <summary>The first timestamp is either the genesis timestamp (a new chain: active from block 0, owner
    /// 2026-10-15 for the 7622 testnet reset) or after it (an upgrade: history before it is unchanged); before genesis
    /// is an error.</summary>
    public void ValidateGenesis(ulong genesisTimestamp)
    {
        Validate();
        if (Schedules[0].Timestamp < genesisTimestamp)
            throw new ArgumentException($"engine.Pqz: first timestamp {Schedules[0].Timestamp} is before genesis ({genesisTimestamp})");
    }

    /// <summary>The schedule in force at <paramref name="timestamp"/>: the last one whose timestamp is ≤ it; null before
    /// the first.</summary>
    public PqzSchedule? ScheduleAt(ulong? timestamp)
    {
        Validate();
        PqzSchedule? active = null;
        foreach (PqzSchedule s in Schedules)
            if (timestamp is { } t && s.Timestamp <= t) active = s;
        return active;
    }

    public void AddTransitions(SortedSet<long> blockNumbers, SortedSet<ulong> timestamps)
    {
        Validate();
        // a 0 timestamp (active from a genesis at time 0) is not a fork (EIP-2124; Taiko does the same)
        foreach (PqzSchedule s in Schedules)
            if (s.Timestamp > 0) timestamps.Add(s.Timestamp);
    }

    public void ApplyToReleaseSpec(ReleaseSpec spec, long startBlock, ulong? startTimestamp)
    {
        if (spec is not PqzReleaseSpec pqz)
            throw new InvalidOperationException(
                $"engine.Pqz is present but the release spec is {spec.GetType().FullName}, not PqzReleaseSpec: another ISpecProvider won the registration (fail closed)");
        pqz.ActiveSchedule = ScheduleAt(startTimestamp);
    }
}

/// <summary>One gas schedule (P6f D2 / D6): from <see cref="Timestamp"/> on, the PQZ rows are the allowlist.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public class PqzSchedule
{
    public required ulong Timestamp { get; init; }
    public required List<PqzRow> Pqz { get; init; }
    public required long SelftestGas { get; init; }
    public required long MlDsa44Gas { get; init; }
    public required long MlDsa65Gas { get; init; }

    private Dictionary<(byte, uint, string), long>? _rows;

    /// <summary>The smallest row's gas: the price of a miss (D6).</summary>
    [JsonIgnore] public long MinGas { get; private set; }

    public void Validate()
    {
        if (Pqz is null || Pqz.Count == 0) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: no pqz rows");
        Dictionary<(byte, uint, string), long> rows = [];
        foreach (PqzRow r in Pqz)
        {
            if (r is null) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: null row");
            if (r.Op is < 1 or > 255 || r.Op == 6) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: op {r.Op} (1..255, not 6)");
            if (r.Id is null || r.Id.Length != 32) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: id must be 32 bytes");
            if (r.StmtLen <= 0) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: stmtLen {r.StmtLen}");
            if (r.Gas <= 0) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: gas {r.Gas}");
            if (!rows.TryAdd(Key((byte)r.Op, (uint)r.StmtLen, r.Id), r.Gas))
                throw new ArgumentException($"engine.Pqz schedule {Timestamp}: duplicate row op {r.Op} stmtLen {r.StmtLen} id {Convert.ToHexString(r.Id)}");
        }
        if (SelftestGas <= 0) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: selftestGas {SelftestGas}");
        if (MlDsa44Gas < MlDsa.Base44) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: mldsa44Gas {MlDsa44Gas} < EIP-8355's {MlDsa.Base44}");
        if (MlDsa65Gas < MlDsa.Base65) throw new ArgumentException($"engine.Pqz schedule {Timestamp}: mldsa65Gas {MlDsa65Gas} < EIP-8355's {MlDsa.Base65}");
        MinGas = Pqz.Min(r => r.Gas);
        _rows = rows;
    }

    private static (byte, uint, string) Key(byte op, uint stmtLen, ReadOnlySpan<byte> id) => (op, stmtLen, Convert.ToHexString(id));

    /// <summary>The row of <paramref name="input"/> = (op = input[0], stmtLen = be32(input[1..5]), id = input[37..69]),
    /// or null (short input, or no such row). Reads nothing else; never throws.</summary>
    public long? RowGas(ReadOnlySpan<byte> input)
    {
        if (input.Length < 69 || _rows is null) return null;
        uint len = (uint)(input[1] << 24 | input[2] << 16 | input[3] << 8 | input[4]);
        return _rows.TryGetValue(Key(input[0], len, input[37..69]), out long g) ? g : null;
    }

    public override string ToString() =>
        $"{{ts {Timestamp}, rows {Pqz.Count} [{string.Join(", ", Pqz.Select(r => $"op{r.Op}/{Convert.ToHexString(r.Id)[..8].ToLowerInvariant()}/{r.StmtLen}={r.Gas}"))}], selftest {SelftestGas}, mldsa44 {MlDsa44Gas}, mldsa65 {MlDsa65Gas}}}";
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public class PqzRow
{
    public required int Op { get; init; }
    public required byte[] Id { get; init; }
    public required int StmtLen { get; init; }
    public required long Gas { get; init; }
}
