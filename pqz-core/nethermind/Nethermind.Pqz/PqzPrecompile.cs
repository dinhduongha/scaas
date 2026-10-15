using System;
using System.Threading;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Specs;
using Nethermind.Evm.Precompiles;
using Nethermind.Logging;

namespace Nethermind.Pqz;

/// <summary>
/// The one <c>PQZ</c> precompile (pq-zether.md §9.1, CTR-PQZ-10) at <see cref="PqzAddresses.Pqz"/>: both proof systems
/// through <c>pqz_precompile</c>. Gas (P6f D6) = the active schedule's row (op, id, stmtLen) + 3·⌈len/32⌉, a miss at
/// the smallest row (and <c>…00</c> without calling pqz-ffi: the rows are the allowlist), op 6 at the fixed
/// <c>selftestGas</c>. Statuses (D4): 0 ⇒ the 32 bytes; 1 ⇒ failed call (all gas); 3 ⇒ <c>…00</c> + Warn
/// <c>PQZ-INPUT-PANIC</c>; anything else ⇒ <c>PQZ-NODE-FAULT</c> and exit 120 (never a verdict).
/// </summary>
public sealed class PqzPrecompile : IPrecompile<PqzPrecompile>
{
    public static PqzPrecompile Instance { get; } = new();
    public static Address Address => PqzAddresses.Pqz;
    public static string Name => "PQZ";

    public static ILogger Log { get; set; } = LimboLogs.Instance.GetClassLogger<PqzPrecompile>();

    private static long _ffiCalls;
    /// <summary>Calls that reached pqz-ffi (tests: a miss must not).</summary>
    public static long FfiCalls => Interlocked.Read(ref _ffiCalls);

    public long BaseGasCost(IReleaseSpec releaseSpec) => 0L;

    public long DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        Gas(inputData.Span, PqzReleaseSpec.ScheduleOf(releaseSpec));

    /// <summary>D6; a function of the bytes only. No schedule ⇒ long.MaxValue (out of gas: fail closed).</summary>
    public static long Gas(ReadOnlySpan<byte> input, PqzSchedule? s)
    {
        if (s is null) return long.MaxValue;
        if (input.Length > 0 && input[0] == 6) return s.SelftestGas;
        return (s.RowGas(input) ?? s.MinGas) + 3L * ((input.Length + 31L) / 32);
    }

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        Run(inputData.Span, PqzReleaseSpec.ScheduleOf(releaseSpec));

    public static Result<byte[]> Run(ReadOnlySpan<byte> input, PqzSchedule? s)
    {
        if (s is null) return Result<byte[]>.Fail("PQZ: no active schedule");
        if (input.Length > PqzNative.MaxInput) return Result<byte[]>.Fail("PQZ: input over MAX_INPUT");
        bool selftest = input.Length > 0 && input[0] == 6;
        if (!selftest && s.RowGas(input) is null) return new byte[32];
        byte[] output = new byte[32];
        Interlocked.Increment(ref _ffiCalls);
        int status = PqzNative.Call(input, output);
        switch (status)
        {
            case PqzNative.Ok:
                return output;
            case PqzNative.Revert:
                return Result<byte[]>.Fail("PQZ: input over MAX_INPUT");
            case PqzNative.InputPanic:
                if (Log.IsWarn) Log.Warn($"PQZ-INPUT-PANIC keccak={Keccak.Compute(input)} len={input.Length}: a caught panic in the decoder / verifier (input-caused): …00");
                return new byte[32];
            default:
                NodeFault(status, input);
                return Result<byte[]>.Fail("unreachable");
        }
    }

    /// <summary>D4: a fault of this node is never a verdict; stop the process (the block is never sealed or imported,
    /// nothing is marked invalid; a restart re-processes). The same exit path Nethermind takes for a missing
    /// precompile library (110), here 120.</summary>
    public static void NodeFault(int status, ReadOnlySpan<byte> input)
    {
        string msg = $"PQZ-NODE-FAULT status={status} keccak={Keccak.Compute(input)} len={input.Length}: a fault of this node, not of the input; exit 120";
        Console.Error.WriteLine(msg);
        Console.Error.Flush();
        if (Log.IsError) Log.Error(msg);
        Environment.Exit(ExitCode);
    }

    public const int ExitCode = 120;
}
