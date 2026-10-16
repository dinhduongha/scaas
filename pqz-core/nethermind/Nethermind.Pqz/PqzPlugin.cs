using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Autofac;
using Autofac.Core;
using Nethermind.Api;
using Nethermind.Api.Extensions;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Evm;
using Nethermind.Logging;
using Nethermind.Specs.ChainSpecStyle;

namespace Nethermind.Pqz;

/// <summary>
/// P6f D1: <c>Nethermind.Pqz</c> — enabled iff the chainspec has <c>engine.Pqz</c>; registers the PQZ spec and
/// precompile providers; at start-up (R3) checks that both registrations won, that .NET's ML-DSA is supported, and
/// that <c>OP_SELFTEST</c> equals the compiled-in hash, then logs <c>PQZ-START</c> (library SHA-256, self-test,
/// schedules, addresses). Any failure: <c>PQZ-REFUSE</c> and exit 120.
/// </summary>
public class PqzPlugin(ChainSpec chainSpec) : INethermindPlugin
{
    public string Name => "Pqz";
    public string Description => "SCaaS PQZ (PQZL + PQZH) and ML-DSA-44 / -65 precompiles (pq-zero-knowledge.md CTR-PQZ-10)";
    public string Author => "SCaaS";
    public bool MustInitialize => true;

    public bool Enabled =>
        chainSpec.EngineChainSpecParametersProvider?.AllChainSpecParameters.OfType<PqzChainSpecEngineParameters>().Any() == true;

    public IModule Module => new PqzModule();

    public Task Init(INethermindApi api)
    {
        ILogger log = api.LogManager.GetClassLogger<PqzPlugin>();
        PqzPrecompile.Log = api.LogManager.GetClassLogger<PqzPrecompile>();
        try
        {
            ISpecProvider sp = api.Context.Resolve<ISpecProvider>();
            if (sp is not PqzChainSpecBasedSpecProvider) throw new InvalidOperationException($"ISpecProvider is {sp.GetType().FullName}, not PqzChainSpecBasedSpecProvider");
            IPrecompileProvider pp = api.Context.Resolve<IPrecompileProvider>();
            if (pp is not PqzPrecompileProvider) throw new InvalidOperationException($"IPrecompileProvider is {pp.GetType().FullName}, not PqzPrecompileProvider");
            if (!MLDsa.IsSupported) throw new InvalidOperationException("System.Security.Cryptography.MLDsa is not supported (OpenSSL >= 3.5 needed)");
            PqzChainSpecEngineParameters p = chainSpec.EngineChainSpecParametersProvider.GetChainSpecParameters<PqzChainSpecEngineParameters>();
            p.ValidateGenesis(chainSpec.Genesis?.Timestamp ?? 0);
            string sha = SelfTest.LibrarySha256();
            string st = SelfTest.Run();
            if (st != SelfTest.ExpectedHash) throw new InvalidOperationException($"OP_SELFTEST {st} != {SelfTest.ExpectedHash}");
            string msg = $"PQZ-START sha256={sha} selftest={st} addresses=PQZ:{PqzAddresses.Pqz},MLDSA44:{PqzAddresses.MlDsa44},MLDSA65:{PqzAddresses.MlDsa65} schedules=[{string.Join("; ", p.Schedules)}]";
            Console.Error.WriteLine(msg);
            if (log.IsInfo) log.Info(msg);
        }
        catch (Exception e)
        {
            string msg = $"PQZ-REFUSE {e.GetType().Name}: {e.Message}; exit {PqzPrecompile.ExitCode}";
            Console.Error.WriteLine(msg);
            Console.Error.Flush();
            if (log.IsError) log.Error(msg, e);
            Environment.Exit(PqzPrecompile.ExitCode);
        }
        return Task.CompletedTask;
    }
}

public class PqzModule : Module
{
    protected override void Load(ContainerBuilder builder)
    {
        base.Load(builder);
        builder
            .AddSingleton<ISpecProvider, PqzChainSpecBasedSpecProvider>()
            .AddSingleton<IPrecompileProvider, PqzPrecompileProvider>();
    }
}
