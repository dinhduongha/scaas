using System;
using System.Security.Cryptography;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Evm.Precompiles;

namespace Nethermind.Pqz;

/// <summary>ML-DSA in the EIP-8355 layout (P6f D5, R4): input <c>pk ‖ sig ‖ msg</c>, FIPS 204 pure ML-DSA with the
/// empty context; <c>L &lt; PK + SIG</c> ⇒ 32 zero bytes, never a revert; output exactly 32 bytes. Gas = the
/// schedule's price (≥ EIP-8355's BASE) + 6·⌈max(0, L − PK − SIG)/32⌉. A <see cref="CryptographicException"/> from the
/// import or the verify is 32 zero bytes too (review W-R, 2026-10-19: EIP-8355 never reverts; no input is known to
/// raise one, the harness reached none); every other exception stays a failed call (Nethermind's handler).</summary>
public static class MlDsa
{
    public const long Base44 = 6_500, Base65 = 9_000;
    public const int Pk44 = 1312, Sig44 = 2420, Pk65 = 1952, Sig65 = 3309;

    public static long Gas(int len, int pk, int sig, long price) => price + 6L * ((Math.Max(0, len - pk - sig) + 31L) / 32);

    public delegate bool VerifyFn(MLDsaAlgorithm alg, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> msg);

    public static byte[] Verify(MLDsaAlgorithm alg, int pk, int sig, ReadOnlySpan<byte> input) => Verify(alg, pk, sig, input, VerifyPure);

    /// <summary><paramref name="verify"/> is the seam the tests use to raise a <see cref="CryptographicException"/>.</summary>
    public static byte[] Verify(MLDsaAlgorithm alg, int pk, int sig, ReadOnlySpan<byte> input, VerifyFn verify)
    {
        byte[] output = new byte[32];
        if (input.Length < pk + sig) return output;
        try
        {
            if (verify(alg, input[..pk], input.Slice(pk, sig), input[(pk + sig)..])) output[31] = 1;
        }
        catch (CryptographicException e)
        {
            if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={input.Length}: {e.Message}: …00");
        }
        return output;
    }

    private static bool VerifyPure(MLDsaAlgorithm alg, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> msg)
    {
        using MLDsa key = MLDsa.ImportMLDsaPublicKey(alg, pk);
        return key.VerifyData(msg, sig, ReadOnlySpan<byte>.Empty);
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
