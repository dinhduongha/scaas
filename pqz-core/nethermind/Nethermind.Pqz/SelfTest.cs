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
    public const string Set = "n2048-kmax1024", ExpectedHash = "37c45f201c3f7a8f4dd3c84df85176f85f574d31a0209435761b1056519bfa9d", ExpectedLibrarySha256 = "1800cae75eff24417c365b95959b3408bfbde3a811dcabca9a575a7497adeeb4";
#elif PQZ_SET_N2304_KMAX4096
    public const string Set = "n2304-kmax4096", ExpectedHash = "d6c01fbcda23be8d8dc72d0b245be63713bd37a5ffa58c4093b39c83d6c4f68d", ExpectedLibrarySha256 = "dd0e7668eeb70972c89ad1b0bbccd7aca8a48a4bbfadbdad6655c0464afe5601";
#elif PQZ_SET_N2560_KMAX16384
    public const string Set = "n2560-kmax16384", ExpectedHash = "fb14244dbd6a4ca4c44f673ef878937d2437f164246260ef45f427a9f98de1cb", ExpectedLibrarySha256 = "5d113f320504db1a2062649efee897a31fa6ebc2f3b80be6f5c7fd981a488cb6";
#elif PQZ_SET_N2816_KMAX65536
    public const string Set = "n2816-kmax65536", ExpectedHash = "1e69e3cd195ff67983e603a8ea969e73e6edcd70f4ac04fa4e5d75c09ddee740", ExpectedLibrarySha256 = "17947f64197cc6ba0818cfe5a5dc1acecf85a2d0d102d2510d3c145cc7158fb7";
#else
#error "unknown PqzSet (MSBuild -p:PqzSet=<set>, a directory of pqz-core/params/sets)"
#endif

    // ExpectedLibrarySha256 (review W-G, 2026-10-19; per set since the R0 review fix part b, 2026-10-26): the SHA-256 of
    // the set's reviewed libpqz_ffi.so, the Dockerfile's `ffi` stage with --build-arg PQZ_SET=<set> (a reproducible
    // build: features pqzl-rust + set-<set>, no prove, no test-hooks). The plugin refuses to start with any other
    // library; build-image.sh reads the set's line and refuses an image whose freshly built library differs. A library
    // change = a reviewed new value here. The values above: the R0 review fix part b tree (branch pqz-r01, logs
    // runs/2026-10-26-r01b-ffi-<set>.txt); before them one value for n2304-kmax4096 only (image 2.2.0-pqz4, 54c7c88e).
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
