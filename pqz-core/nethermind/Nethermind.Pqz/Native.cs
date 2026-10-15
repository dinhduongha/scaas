using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Nethermind.Pqz;

/// <summary>P/Invoke into <c>pqz-ffi</c>'s C ABI (<c>pqz-core/ffi/pqz_ffi.h</c>). The resolver loads exactly
/// <c>&lt;LibraryDirectory&gt;/libpqz_ffi.so</c> (default: the plugin's own directory), no search path.</summary>
public static unsafe partial class PqzNative
{
    public const int MaxInput = 393216; // PQZ_FFI_MAX_INPUT (P6e D5)
    public const int Ok = 0, Revert = 1, BadArgs = 2, InputPanic = 3, NodeFault = 4;

    /// <summary>Set before the first call (tests, harness); the node uses the default.</summary>
    public static string LibraryDirectory { get; set; } = Path.GetDirectoryName(typeof(PqzNative).Assembly.Location)!;

    public static string LibraryPath => Path.Combine(LibraryDirectory, "libpqz_ffi.so");

    static PqzNative() => NativeLibrary.SetDllImportResolver(typeof(PqzNative).Assembly, Resolve);

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path) =>
        name == "pqz_ffi" ? NativeLibrary.Load(LibraryPath) : IntPtr.Zero;

    [LibraryImport("pqz_ffi")]
    private static partial int pqz_precompile(byte* input, nuint len, byte* output, nuint outLen);

    /// <summary>One call; <paramref name="output"/> must hold 32 bytes. The input is pinned for the call (an empty span
    /// is a null pointer with length 0, which the ABI allows).</summary>
    public static int Call(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < 32) throw new ArgumentException("output < 32 bytes");
        fixed (byte* i = input)
        fixed (byte* o = output)
            return pqz_precompile(i, (nuint)input.Length, o, 32);
    }
}
