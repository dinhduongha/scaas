using System;
using System.IO;
using System.Security.Cryptography;

namespace Nethermind.Pqz;

/// <summary>P6f R3: the plugin runs <c>OP_SELFTEST</c> at start-up and refuses to start unless it equals the hash of
/// the library's parameter set's <c>selftest.json</c> (P6e D13; a test pins this constant to the file). The set is the
/// MSBuild property <c>PqzSet</c> (Directory.Build.props; default <c>n2304-kmax4096</c>, pqz-ffi's default build, plan
/// 5h Task 8d): <c>-p:PqzSet=&lt;set&gt;</c> builds the plugin for the library of that set (plan 5h Task 8d part 1b).</summary>
public static class SelfTest
{
#if PQZ_SET_N2048_KMAX1024
    public const string Set = "n2048-kmax1024", ExpectedHash = "ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205";
#elif PQZ_SET_N2304_KMAX4096
    public const string Set = "n2304-kmax4096", ExpectedHash = "23d7a1db653449c52bfed0ebbfe664867bf2400261f8999406799dc1040c97c0";
#elif PQZ_SET_N2560_KMAX16384
    public const string Set = "n2560-kmax16384", ExpectedHash = "167c772ef4d0911d60d6b3d2fad256902e1be2dd4a8f0aa9d01d3b3ed8bb45e7";
#elif PQZ_SET_N2816_KMAX65536
    public const string Set = "n2816-kmax65536", ExpectedHash = "0aa1dfe291b81f0c8efa859405c9f14cdc0fa744584b4d5b30bd0a6472491882";
#else
#error "unknown PqzSet (MSBuild -p:PqzSet=<set>, a directory of pqz-core/params/sets)"
#endif

    /// <summary>Review W-G (2026-10-19): the SHA-256 of the reviewed <c>libpqz_ffi.so</c> (the Dockerfile's <c>ffi</c>
    /// stage, a reproducible build). The plugin refuses to start with any other library; <c>build-image.sh</c> reads
    /// this line and refuses an image whose freshly built library differs. A library change = a reviewed new value
    /// here. Today the library of image <c>2.2.0-pqz4</c> (2026-10-25, plan 5h Task 8d part 1, set n2304-kmax4096, built
    /// from 54c7c88e; reviewed: exports pqz_max_input / pqz_precompile only, no test hooks, no GMP / MPFR / HEXL,
    /// pqz_max_input() = 524,288).
    /// This value is the default set's library only: a plugin built with another <c>-p:PqzSet</c> (e.g.
    /// <c>n2816-kmax65536</c>) passes the tests but refuses to start a node until that set's library has its own reviewed
    /// hash here (customer-image work, plan 5h Task 8d part 1b review M4; not done).</summary>
    public const string ExpectedLibrarySha256 = "0894d1916b4e2f8270c5bac6e7f9a87a19137e51c6f7f93263d05b9756e64772";
    public static ReadOnlySpan<byte> Input => [6, 0, 0, 0, 0];

    public static string Run()
    {
        byte[] o = new byte[32];
        int st = PqzNative.Call(Input, o);
        if (st != PqzNative.Ok) throw new InvalidOperationException($"OP_SELFTEST status {st}");
        return Convert.ToHexStringLower(o);
    }

    public static string LibrarySha256() => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(PqzNative.LibraryPath)));

    /// <summary>The library's SHA-256 if it equals <paramref name="expected"/>, else an exception (the plugin's
    /// <c>PQZ-REFUSE</c>).</summary>
    public static string CheckedLibrarySha256(string expected = ExpectedLibrarySha256)
    {
        string sha = LibrarySha256();
        if (sha != expected) throw new InvalidOperationException($"{PqzNative.LibraryPath} sha256 {sha} != the reviewed {expected}");
        return sha;
    }
}
