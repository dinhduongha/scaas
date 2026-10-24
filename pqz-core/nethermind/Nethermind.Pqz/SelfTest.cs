using System;
using System.IO;
using System.Security.Cryptography;

namespace Nethermind.Pqz;

/// <summary>P6f R3: the plugin runs <c>OP_SELFTEST</c> at start-up and refuses to start unless it equals the hash of
/// the library's parameter set's <c>selftest.json</c> (P6e D13; a test pins this constant to the file): since plan 5h
/// Task 8d part 1 the default set <c>n2304-kmax4096</c>, <c>smartcontracts/vectors/pqz/n2304-kmax4096/selftest.json</c>
/// (the <c>n2048-kmax1024</c> library's was <c>ed910a2c…d205</c>).</summary>
public static class SelfTest
{
    public const string ExpectedHash = "23d7a1db653449c52bfed0ebbfe664867bf2400261f8999406799dc1040c97c0";

    /// <summary>Review W-G (2026-10-19): the SHA-256 of the reviewed <c>libpqz_ffi.so</c> (the Dockerfile's <c>ffi</c>
    /// stage, a reproducible build). The plugin refuses to start with any other library; <c>build-image.sh</c> reads
    /// this line and refuses an image whose freshly built library differs. A library change = a reviewed new value
    /// here. Today the library of image <c>pqz3</c> (2026-10-19); plan Task 13 sets <c>pqz4</c>'s.</summary>
    public const string ExpectedLibrarySha256 = "16dd99ce77d05a9bea9f54142979bc21511240aeff6d4442d784470a428c9caf";
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
