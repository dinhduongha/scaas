using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Autofac;
using Autofac.Core;
using Nethermind.Api.Extensions;
using Nethermind.Api.Steps;
using Nethermind.Blockchain;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Evm;
using Nethermind.Init.Steps;
using Nethermind.Logging;
using Nethermind.Specs.ChainSpecStyle;

namespace Nethermind.Pqz;

/// <summary>
/// P6f D1: <c>Nethermind.Pqz</c> — enabled iff the chainspec has <c>engine.Pqz</c>; registers the PQZ spec and
/// precompile providers; at start-up (R3) checks that both registrations won, that .NET's ML-DSA is supported and
/// gives the compiled-in known answers (review R4-C4, <see cref="MlDsaKat"/>), that the library's SHA-256 equals the
/// reviewed one (review W-G), that <c>OP_SELFTEST</c> equals the compiled-in hash and that the schedule in force and
/// every later one (from the block tree head on) carry only the library's proofSystemIds (review R4-C3, <see cref="PqzSetIds"/>), then logs
/// <c>PQZ-START</c> (library SHA-256, self-test, input limit <c>max_input</c>, OpenSSL version, ML-DSA KAT, schedules,
/// addresses). Any failure: <c>PQZ-REFUSE</c> and exit 120. The checks run in <see cref="PqzStartupCheck"/>.
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
}

/// <summary>R3, the start-up checks (Nethermind 2.x retired the plugin <c>Init</c> hook for init steps, #12326): after
/// the block tree, before the genesis block runs any EVM code (the Taiko pattern; block production, sync and RPC
/// execution all come after <see cref="LoadGenesisBlock"/>). Any failure: <c>PQZ-REFUSE</c> and exit 120.</summary>
[RunnerStepDependencies(dependencies: [typeof(InitializeBlockTree)], dependents: [typeof(LoadGenesisBlock)])]
public class PqzStartupCheck(ChainSpec chainSpec, ISpecProvider sp, IPrecompileProvider pp, IBlockTree blockTree, ILogManager logManager) : IStep
{
    public Task Execute(CancellationToken cancellationToken)
    {
        ILogger log = logManager.GetClassLogger<PqzPlugin>();
        PqzPrecompile.Log = logManager.GetClassLogger<PqzPrecompile>();
        try
        {
            if (sp is not PqzChainSpecBasedSpecProvider) throw new InvalidOperationException($"ISpecProvider is {sp.GetType().FullName}, not PqzChainSpecBasedSpecProvider");
            if (pp is not PqzPrecompileProvider) throw new InvalidOperationException($"IPrecompileProvider is {pp.GetType().FullName}, not PqzPrecompileProvider");
            if (!MLDsa.IsSupported) throw new InvalidOperationException("System.Security.Cryptography.MLDsa is not supported (OpenSSL >= 3.5 needed)");
            string kat = MlDsaKat.Run();
            if (kat != MlDsaKat.ExpectedHash) throw new InvalidOperationException($"ML-DSA known-answer verdicts {kat} != {MlDsaKat.ExpectedHash}");
            PqzChainSpecEngineParameters p = chainSpec.EngineChainSpecParametersProvider.GetChainSpecParameters<PqzChainSpecEngineParameters>();
            p.ValidateGenesis(chainSpec.Genesis?.Timestamp ?? 0);
            // R4-C3 from the block tree, not the wall clock (owner 2026-10-26, review of fix part b I-1): the head's
            // timestamp; on an empty database (no head yet: this step runs before LoadGenesisBlock) the genesis one
            ulong head = blockTree.Head?.Timestamp ?? chainSpec.Genesis?.Timestamp ?? 0;
            p.CheckIds(head, PqzSetIds.PqzhId == "" ? [PqzSetIds.PqzlId] : [PqzSetIds.PqzlId, PqzSetIds.PqzhId]);
            string sha = SelfTest.CheckedLibrarySha256();
            string st = SelfTest.Run();
            if (st != SelfTest.ExpectedHash) throw new InvalidOperationException($"OP_SELFTEST {st} != {SelfTest.ExpectedHash}");
            // the library's input limit (pqz_max_input) read here, not first on the consensus path: a missing symbol or
            // an overflow is PQZ-REFUSE at start-up (review 8d1 M1)
            int maxInput = PqzNative.MaxInput;
            if (maxInput <= 0) throw new InvalidOperationException($"pqz_max_input() = {maxInput}");
            string msg = $"PQZ-START sha256={sha} selftest={st} max_input={maxInput} openssl={MlDsaKat.OpenSslVersion} mldsa_kat={kat} set={SelfTest.Set} addresses=PQZ:{PqzAddresses.Pqz},MLDSA44:{PqzAddresses.MlDsa44},MLDSA65:{PqzAddresses.MlDsa65} schedules=[{string.Join("; ", p.Schedules)}]";
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
            .AddSingleton<IPrecompileProvider, PqzPrecompileProvider>()
            .AddStep(typeof(PqzStartupCheck));
    }
}
