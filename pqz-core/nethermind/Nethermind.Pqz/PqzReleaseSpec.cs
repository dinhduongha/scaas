using System.Collections.Frozen;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Specs;

namespace Nethermind.Pqz;

/// <summary>P6f D1 / R2: the release spec with the active PQZ schedule; from the first schedule's timestamp the three
/// addresses join the precompile set together.</summary>
public class PqzReleaseSpec : ReleaseSpec
{
    /// <summary>Null before the first schedule's timestamp.</summary>
    public PqzSchedule? ActiveSchedule { get; set; }

    // every precompile set built here, keyed by the set object, so the precompiles find the schedule through any
    // ReleaseSpecDecorator (they forward Precompiles unchanged, but are not PqzReleaseSpec)
    private static readonly ConditionalWeakTable<FrozenSet<AddressAsKey>, PqzSchedule> BySet = new();

    public override FrozenSet<AddressAsKey> BuildPrecompilesCache()
    {
        FrozenSet<AddressAsKey> stock = base.BuildPrecompilesCache();
        if (ActiveSchedule is null) return stock;
        HashSet<AddressAsKey> set = [.. stock, PqzAddresses.Pqz, PqzAddresses.MlDsa44, PqzAddresses.MlDsa65];
        FrozenSet<AddressAsKey> frozen = set.ToFrozenSet();
        BySet.AddOrUpdate(frozen, ActiveSchedule);
        return frozen;
    }

    /// <summary>The schedule a precompile runs under; null ⇒ the precompile fails closed (never happens when the
    /// address is in the set, which only this class adds).</summary>
    public static PqzSchedule? ScheduleOf(IReleaseSpec spec) =>
        spec is PqzReleaseSpec p ? p.ActiveSchedule : BySet.TryGetValue(spec.Precompiles, out PqzSchedule? s) ? s : null;
}
