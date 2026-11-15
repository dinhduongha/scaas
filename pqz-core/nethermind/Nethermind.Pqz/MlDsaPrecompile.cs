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
/// raise one, the harness reached none). Any other exception is a fault of this node, never a verdict (D4, review 3w
/// T-16): <see cref="PqzPrecompile.NodeFault(string, Exception, ReadOnlySpan{byte})"/>, exit 120. The whole operation,
/// the output allocation included, is inside that boundary; the zero word's warning cannot change the word (review
/// 3w-delta U3h-2).</summary>
public static class MlDsa
{
    public const long Base44 = 6_500, Base65 = 9_000, Base87 = 13_500;
    public const int Pk44 = 1312, Sig44 = 2420, Pk65 = 1952, Sig65 = 3309, Pk87 = 2592, Sig87 = 4627;
    /// <summary>Calibrated <c>mldsa87Gas</c> (CTR-UA-39 Q4; TODO 3zd, owner 2026-11-15): <c>Calibrate</c> in the calib image,
    /// two passes, p99 0.358 / 0.328 ms at t_ecMul 0.016 ms ⇒ 135,000 / 123,000, the larger
    /// (<c>runs/2026-11-15-mldsa87-calib.txt</c>; was the PROVISIONAL estimate 102,000). The value <c>add-schedule.py --mldsa87</c>
    /// writes; the plugin itself prices from the schedule, never from this.</summary>
    public const long Calibrated87Gas = 135_000;
    /// <summary>Calibrated <c>mldsa44Gas</c> from the same two passes (owner 2026-11-15: the higher pass), 59,000 / 58,000
    /// (was 49,000, P6f 2026-10-15). The value <c>add-schedule.py --mldsa</c> writes; the plugin prices from the schedule.</summary>
    public const long Calibrated44Gas = 59_000;

    public static long Gas(int len, int pk, int sig, long price) => price + 6L * ((Math.Max(0, len - pk - sig) + 31L) / 32);

    public delegate bool VerifyFn(MLDsaAlgorithm alg, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> msg);

    public static byte[] Verify(MLDsaAlgorithm alg, int pk, int sig, ReadOnlySpan<byte> input) => Verify(alg, pk, sig, input, VerifyPure);

    /// <summary><paramref name="verify"/> is the seam the tests use to raise an exception.</summary>
    public static byte[] Verify(MLDsaAlgorithm alg, int pk, int sig, ReadOnlySpan<byte> input, VerifyFn verify)
    {
        try
        {
            byte[] output = new byte[32];
            if (input.Length < pk + sig) return output;
            try
            {
                if (verify(alg, input[..pk], input.Slice(pk, sig), input[(pk + sig)..])) output[31] = 1;
            }
            catch (CryptographicException e)
            {
                WarnCrypto(alg, input.Length, e); // W-R: the zero word
            }
            return output;
        }
        catch (Exception e)
        {
            PqzPrecompile.NodeFault(alg.Name + " ", e, input);
            throw; // not reached (NodeFault exits); a failed call, never a verdict
        }
    }

    /// <summary>W-R's warning, best effort: a logger (or a <c>Message</c>) that throws is swallowed, so the word stays
    /// the zero word on every node (it does not depend on the log; review 3w-delta U3h-2).</summary>
    private static void WarnCrypto(MLDsaAlgorithm alg, int len, CryptographicException e)
    {
        try
        {
            if (PqzPrecompile.Log.IsWarn) PqzPrecompile.Log.Warn($"MLDSA-CRYPTO-EXCEPTION {alg.Name} len={len}: {e.Message}: …00");
        }
        catch
        {
            // the word is the zero word regardless
        }
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
    public ulong BaseGasCost(IReleaseSpec releaseSpec) => 0UL;

    public ulong DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        PqzReleaseSpec.ScheduleOf(releaseSpec) is { } s ? (ulong)MlDsa.Gas(inputData.Length, MlDsa.Pk44, MlDsa.Sig44, s.MlDsa44Gas) : ulong.MaxValue;

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        MlDsa.Verify(MLDsaAlgorithm.MLDsa44, MlDsa.Pk44, MlDsa.Sig44, inputData.Span);
}

public sealed class MlDsa65Precompile : IPrecompile<MlDsa65Precompile>
{
    public static MlDsa65Precompile Instance { get; } = new();
    public static Address Address => PqzAddresses.MlDsa65;
    public static string Name => "MLDSA65";
    public ulong BaseGasCost(IReleaseSpec releaseSpec) => 0UL;

    public ulong DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        PqzReleaseSpec.ScheduleOf(releaseSpec) is { } s ? (ulong)MlDsa.Gas(inputData.Length, MlDsa.Pk65, MlDsa.Sig65, s.MlDsa65Gas) : ulong.MaxValue;

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        MlDsa.Verify(MLDsaAlgorithm.MLDsa65, MlDsa.Pk65, MlDsa.Sig65, inputData.Span);
}

/// <summary>ML-DSA-87 (CTR-UA-39, owner 2026-11-04): the same EIP-8355 path at <see cref="PqzAddresses.MlDsa87"/>. Its key
/// <c>mldsa87Gas</c> is optional per schedule: a schedule without it leaves the address out of the precompile set
/// (<see cref="PqzReleaseSpec"/>) and prices it as no schedule does (<c>ulong.MaxValue</c>).</summary>
public sealed class MlDsa87Precompile : IPrecompile<MlDsa87Precompile>
{
    public static MlDsa87Precompile Instance { get; } = new();
    public static Address Address => PqzAddresses.MlDsa87;
    public static string Name => "MLDSA87";
    public ulong BaseGasCost(IReleaseSpec releaseSpec) => 0UL;

    public ulong DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        PqzReleaseSpec.ScheduleOf(releaseSpec) is { MlDsa87Gas: { } g } ? (ulong)MlDsa.Gas(inputData.Length, MlDsa.Pk87, MlDsa.Sig87, g) : ulong.MaxValue;

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        MlDsa.Verify(MLDsaAlgorithm.MLDsa87, MlDsa.Pk87, MlDsa.Sig87, inputData.Span);
}
