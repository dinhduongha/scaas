using System.Collections.Frozen;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Specs;

namespace Nethermind.Pqz;

/// <summary>P6f D1 / R2: the release spec with the active PQZ schedule; from the first schedule's timestamp the three
/// addresses join the precompile set together.</summary>
// re-listing IReleaseSpec re-maps all of its members; the compiler then reports nullability mismatches inside Nethermind's
// own ReleaseSpec (UInt256 fee members), not in this file
#pragma warning disable CS8613, CS8766
public class PqzReleaseSpec : ReleaseSpec, IReleaseSpec
#pragma warning restore CS8613, CS8766
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

    // Nethermind 2.2.0's ReleaseSpec indexes its precompiles by number and throws for an address with a non-zero byte
    // above its low 32 bits ("a precompile number must fit 32 bits"), which the 0x5caa5… addresses (D3) have. This
    // class re-implements the two IReleaseSpec members over its own set instead; every caller in Nethermind (the VM,
    // the gas policy, the code-info repositories, ReleaseSpecDecorator) reaches them through the interface, and a
    // number it cannot index falls back to the precompile provider's dictionary (PqzPrecompileProvider).
    private FrozenSet<AddressAsKey>? _precompiles;
    FrozenSet<AddressAsKey> IReleaseSpec.Precompiles => _precompiles ??= BuildPrecompilesCache();
    bool IReleaseSpec.IsPrecompile(Address address) => ((IReleaseSpec)this).Precompiles.Contains(address);

    /// <summary>The schedule a precompile runs under; null ⇒ the precompile fails closed (never happens when the
    /// address is in the set, which only this class adds).</summary>
    public static PqzSchedule? ScheduleOf(IReleaseSpec spec) =>
        spec is PqzReleaseSpec p ? p.ActiveSchedule : BySet.TryGetValue(spec.Precompiles, out PqzSchedule? s) ? s : null;
}
