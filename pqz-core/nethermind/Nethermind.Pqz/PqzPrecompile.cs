using System;
using System.Threading;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Specs;
using Nethermind.Evm.Precompiles;
using Nethermind.Logging;

namespace Nethermind.Pqz;

/// <summary>
/// The one <c>PQZ</c> precompile (pq-zero-knowledge.md §9.1, CTR-PQZ-10) at <see cref="PqzAddresses.Pqz"/>: both proof systems
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

    public ulong BaseGasCost(IReleaseSpec releaseSpec) => 0UL;

    public ulong DataGasCost(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        Gas(inputData.Span, PqzReleaseSpec.ScheduleOf(releaseSpec));

    /// <summary>D6; a function of the bytes only. No schedule ⇒ ulong.MaxValue (out of gas: fail closed; Nethermind 2.x
    /// prices precompiles in ulong).</summary>
    public static ulong Gas(ReadOnlySpan<byte> input, PqzSchedule? s)
    {
        if (s is null) return ulong.MaxValue;
        if (input.Length > 0 && input[0] == 6) return (ulong)s.SelftestGas;
        return (ulong)((s.RowGas(input) ?? s.MinGas) + 3L * ((input.Length + 31L) / 32));
    }

    public Result<byte[]> Run(ReadOnlyMemory<byte> inputData, IReleaseSpec releaseSpec) =>
        Run(inputData.Span, PqzReleaseSpec.ScheduleOf(releaseSpec));

    /// <summary>A managed exception on this path (outside the library's statuses: loading or binding the library, the
    /// log line) is a fault of this node (D4, review 3w T-16): <see cref="NodeFault(string, Exception, ReadOnlySpan{byte})"/>,
    /// never Nethermind's failed call. <see cref="DllNotFoundException"/> stays Nethermind's own exit 110.</summary>
    public static Result<byte[]> Run(ReadOnlySpan<byte> input, PqzSchedule? s)
    {
        try
        {
            return RunUnguarded(input, s);
        }
        catch (Exception e) when (e is not DllNotFoundException)
        {
            NodeFault("", e, input); // the cause is built inside the fault boundary (review 3w-delta U3h-2)
            throw; // not reached (NodeFault exits)
        }
    }

    private static Result<byte[]> RunUnguarded(ReadOnlySpan<byte> input, PqzSchedule? s)
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
    public static void NodeFault(int status, ReadOnlySpan<byte> input) => Fault(null, null, status, input);

    /// <summary>D4 for a managed exception in a PQZ or ML-DSA call; <paramref name="where"/> prefixes the cause
    /// (<c>e.GetType().Name: e.Message</c>), which is built here, inside the boundary.</summary>
    public static void NodeFault(string where, Exception e, ReadOnlySpan<byte> input) => Fault(where, e, 0, input);

    /// <summary>The fixed line written when building or writing the <c>PQZ-NODE-FAULT</c> diagnostic itself failed.</summary>
    public const string FallbackLine = "PQZ-NODE-FAULT (the diagnostic failed): a fault of this node, not of the input; exit 120";

    /// <summary>Review 3w-delta U3h-2 (owner 2026-11-15): termination is unconditional. The cause, the line (Keccak of
    /// the input), stderr and the logger are inside a <c>try</c>; any exception there is caught, the fixed
    /// <see cref="FallbackLine"/> is tried once, and <see cref="Terminate"/> runs from the <c>finally</c>.</summary>
    private static void Fault(string? where, Exception? e, int status, ReadOnlySpan<byte> input)
    {
        try
        {
            string cause = e is null ? $"status={status}" : $"{where}{e.GetType().Name}: {e.Message}";
            string msg = $"PQZ-NODE-FAULT {cause} keccak={Keccak.Compute(input)} len={input.Length}: a fault of this node, not of the input; exit 120";
            Console.Error.WriteLine(msg);
            Console.Error.Flush();
            if (Log.IsError) Log.Error(msg);
        }
        catch
        {
            try
            {
                Console.Error.WriteLine(FallbackLine);
                Console.Error.Flush();
            }
            catch
            {
                // nothing left to report through: terminate anyway
            }
        }
        finally
        {
            Terminate();
        }
    }

    /// <summary>The exit watchdog's bound: <see cref="Terminate"/>'s dedicated thread calls
    /// <see cref="Environment.FailFast(string)"/> if the process still runs this long after
    /// <see cref="Environment.Exit(int)"/> began (a ProcessExit handler blocked, e.g. on the faulting thread).</summary>
    public const int ExitWatchdogMs = 10_000;

    /// <summary>The watchdog's FailFast message.</summary>
    public const string WatchdogLine = "PQZ-NODE-FAULT exit watchdog: the process did not exit within the bound after exit 120; FailFast";

    /// <summary>Review 3w-delta U3h-2 + T-20 (owner 2026-11-15, "thêm watchdog"): start the watchdog (a dedicated
    /// background thread, not the thread pool), then <c>Environment.Exit(120)</c>; should Exit return or throw,
    /// FailFast at once. Never returns. The watchdog's FailFast ends the process with the runtime's abort status, not
    /// 120; a fault-handling path that hangs is the case it covers.</summary>
    public static void Terminate()
    {
        try
        {
            Thread w = new(() =>
            {
                Thread.Sleep(ExitWatchdogMs);
                Environment.FailFast(WatchdogLine);
            }) { IsBackground = true, Name = "pqz-exit-watchdog" };
            w.Start();
        }
        catch
        {
            // no watchdog thread: Exit below still runs
        }
        try
        {
            Environment.Exit(ExitCode);
        }
        finally
        {
            Environment.FailFast("PQZ-NODE-FAULT: Environment.Exit returned; FailFast");
        }
    }

    public const int ExitCode = 120;
}
