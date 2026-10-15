using Nethermind.Logging;
using Nethermind.Specs;
using Nethermind.Specs.ChainSpecStyle;

namespace Nethermind.Pqz;

/// <summary>P6f D1: the Taiko pattern — the stock provider with <see cref="PqzReleaseSpec"/> as the empty spec;
/// <see cref="PqzChainSpecEngineParameters.ApplyToReleaseSpec"/> sets the schedule.</summary>
public class PqzChainSpecBasedSpecProvider(ChainSpec chainSpec, ILogManager logManager)
    : ChainSpecBasedSpecProvider(chainSpec, logManager)
{
    protected override ReleaseSpec CreateEmptyReleaseSpec() => new PqzReleaseSpec();

    protected override ReleaseSpec CreateReleaseSpec(ChainSpec spec, long releaseStartBlock, ulong? releaseStartTimestamp = null)
    {
        spec.EngineChainSpecParametersProvider.GetChainSpecParameters<PqzChainSpecEngineParameters>()
            .ValidateGenesis(spec.Genesis?.Timestamp ?? 0);
        return base.CreateReleaseSpec(spec, releaseStartBlock, releaseStartTimestamp);
    }
}
