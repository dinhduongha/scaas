// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk spec §5, §16.1: the reference library's secret copy calls for C# (plan T20c; review B12). A secret's bytes cross
// only here, never through the generated codec: Write copies a buffer into the secret named by its id and zeroes the buffer,
// Read copies a secret out (the caller zeroes what it read once done), Dispose zeroes and frees a secret.
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Scaas.Sdk;

public static class CopyCall
{
    [DllImport("scaas_sdk_ffi", CallingConvention = CallingConvention.Cdecl)]
    static extern unsafe int scaas_sdk_secret_write(ulong id, byte* src, nuint len);

    [DllImport("scaas_sdk_ffi", CallingConvention = CallingConvention.Cdecl)]
    static extern unsafe long scaas_sdk_secret_read(ulong id, byte* dst, nuint cap);

    [DllImport("scaas_sdk_ffi", CallingConvention = CallingConvention.Cdecl)]
    static extern int scaas_sdk_secret_dispose(ulong id);

    /// <summary>`buf` into secret `id` (its length exactly), then `buf` zeroed (also on a refusal); false on a refusal.</summary>
    public static unsafe bool Write(ulong id, byte[] buf)
    {
        int r;
        fixed (byte* p = buf)
            r = scaas_sdk_secret_write(id, p, (nuint)buf.Length);
        CryptographicOperations.ZeroMemory(buf);
        return r == 0;
    }

    /// <summary>Secret `id` (at most `cap` bytes) out; null when refused.</summary>
    public static byte[]? Read(ulong id, int cap) => ReadVia(id, new byte[cap]);

    /// <summary>[`Read`] through the buffer `out_` (its capacity the cap): the secret's bytes are copied out of it, then it is
    /// zeroed, so no copy stays behind but the one returned (review T26 C-5).</summary>
    public static unsafe byte[]? ReadVia(ulong id, byte[] out_)
    {
        long n;
        fixed (byte* p = out_)
            n = scaas_sdk_secret_read(id, p, (nuint)out_.Length);
        var r = n < 0 ? null : out_[..(int)n];
        CryptographicOperations.ZeroMemory(out_);
        return r;
    }

    /// <summary>Secret `id` zeroed and freed; false when unknown.</summary>
    public static bool Dispose(ulong id) => scaas_sdk_secret_dispose(id) == 0;
}
