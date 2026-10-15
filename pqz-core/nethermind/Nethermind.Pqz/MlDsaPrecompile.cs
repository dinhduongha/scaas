using System;
using System.Security.Cryptography;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Evm.Precompiles;

namespace Nethermind.Pqz;

/// <summary>ML-DSA in the EIP-8355 layout (P6f D5, R4): input <c>pk ‖ sig ‖ msg</c>, FIPS 204 pure ML-DSA with the
/// empty context; <c>L &lt; PK + SIG</c> ⇒ 32 zero bytes, never a revert; output exactly 32 bytes. Gas = the
/// schedule's price (≥ EIP-8355's BASE) + 6·⌈max(0, L − PK − SIG)/32⌉. No catch here: an exception would be a failed
/// call (Nethermind's handler); the harness shows no input reaches one.</summary>
public static class MlDsa
{
    public const long Base44 = 6_500, Base65 = 9_000;
    public const int Pk44 = 1312, Sig44 = 2420, Pk65 = 1952, Sig65 = 3309;

    public static long Gas(int len, int pk, int sig, long price) => price + 6L * ((Math.Max(0, len - pk - sig) + 31L) / 32);

    public static byte[] Verify(MLDsaAlgorithm alg, int pk, int sig, ReadOnlySpan<byte> input)
    {
        byte[] output = new byte[32];
        if (input.Length < pk + sig) return output;
        using MLDsa key = MLDsa.ImportMLDsaPublicKey(alg, input[..pk]);
        if (key.VerifyData(input[(pk + sig)..], input.Slice(pk, sig), ReadOnlySpan<byte>.Empty)) output[31] = 1;
        return output;
    }
}

public sealed class MlDsa44Precompile : IPrecompile<MlDsa44Precompile>
{
    public static MlDsa44Precompile Instance { get; } = new();
    public static Address Address => PqzAddresses.MlDsa44;
    public static string Name => "MLDSA44";
    public long BaseGasCost(IReleaseSpec releaseSpec) => 0L;

    public long DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        PqzReleaseSpec.ScheduleOf(releaseSpec) is { } s ? MlDsa.Gas(inputData.Length, MlDsa.Pk44, MlDsa.Sig44, s.MlDsa44Gas) : long.MaxValue;

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        MlDsa.Verify(MLDsaAlgorithm.MLDsa44, MlDsa.Pk44, MlDsa.Sig44, inputData.Span);
}

public sealed class MlDsa65Precompile : IPrecompile<MlDsa65Precompile>
{
    public static MlDsa65Precompile Instance { get; } = new();
    public static Address Address => PqzAddresses.MlDsa65;
    public static string Name => "MLDSA65";
    public long BaseGasCost(IReleaseSpec releaseSpec) => 0L;

    public long DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        PqzReleaseSpec.ScheduleOf(releaseSpec) is { } s ? MlDsa.Gas(inputData.Length, MlDsa.Pk65, MlDsa.Sig65, s.MlDsa65Gas) : long.MaxValue;

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        MlDsa.Verify(MLDsaAlgorithm.MLDsa65, MlDsa.Pk65, MlDsa.Sig65, inputData.Span);
}
