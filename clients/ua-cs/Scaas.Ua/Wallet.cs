// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The ua-rs wallet through libscaas_ua_c (clients/ua-c, C ABI v6) by P/Invoke (spec 2026-11-05-ua-rs-sign §9.2, plan T13f). The
// identity port (Ua.cs) stays this assembly's own code and the independent cross-check; signing, KEM, seal, vault, backup, link
// and the Zether and PQZ facades are the library's.
// Load: every entry point checks once that scaas_ua_abi_version() is 6 and scaas_ua_features() a build this binding knows
// (LibraryMismatchException otherwise). Secrets: secret inputs are byte[] (a string cannot be wiped); the NUL-terminated copy this
// binding makes of one is a pinned array zeroed by CryptographicOperations.ZeroMemory after the call; secret outputs are pinned
// byte[] the caller wipes with UaLib.Wipe. Handles: SafeHandle (freed exactly once; a call in flight holds a reference, so
// Dispose never frees under it). Library: SCAAS_UA_C_LIB, else clients/ua-c/target/release above the binary, else the default
// probing. UNAUDITED.
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("Scaas.Ua.Tests")]

namespace Scaas.Ua;

/// <summary>The library is not ABI 6, or its feature bits are not a build this binding knows.</summary>
public sealed class LibraryMismatchException(string message) : Exception(message);

/// <summary>A status of the library: <see cref="Code"/> is its name ("UASealOpen" ...), <see cref="Detail"/> its detail (never an input).</summary>
public sealed class WalletException(int status, string code, string detail) : Exception($"{code}: {detail}")
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public string Detail { get; } = detail;
}

/// <summary>The arena's chunks, of them mlocked, of them no-dump (all 0 while locked).</summary>
public readonly record struct MemoryProtection(ulong Chunks, ulong Locked, ulong NoDump);

/// <summary>A backup recipient: the KEM key <c>KemPk</c> of record <c>Version</c> of the UA of (<c>Kind</c>, <c>KeyData</c>), or an
/// ephemeral key (<c>Ephemeral</c>, the other fields unread).</summary>
public sealed record Recipient(ushort Kind, byte[] KeyData, ulong Version, byte[] KemPk, bool Ephemeral = false);

/// <summary>One library handle: SafeHandle frees it exactly once, never under a call that holds it.</summary>
internal abstract class UaHandle : SafeHandle
{
    protected UaHandle() : base(IntPtr.Zero, true) { }
    protected UaHandle(IntPtr p) : base(IntPtr.Zero, true) => SetHandle(p);
    public override bool IsInvalid => handle == IntPtr.Zero;
    protected abstract void Free(IntPtr p);

    protected override bool ReleaseHandle()
    {
        Free(handle);
        return true;
    }
}

internal sealed class WalletHandle : UaHandle
{
    internal static readonly WalletHandle None = new();
    protected override void Free(IntPtr p) => Native.scaas_ua_wallet_free(p);
}

internal sealed class KeyHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_key_free(p);
}

internal sealed class KemHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_kem_free(p);
}

internal sealed class LinkHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_link_session_free(p);
}

internal sealed class SeedBackupHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_seed_backup_free(p);
}

internal sealed class ZetherHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_zether_key_free(p);
}

internal sealed class PqzHandle : UaHandle
{
    protected override void Free(IntPtr p) => Native.scaas_ua_pqz_key_free(p);
}

[StructLayout(LayoutKind.Sequential)]
internal struct MemoryProtectionC
{
    public nuint Chunks, Locked, NoDump;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RecipientC
{
    public ushort Kind;
    public byte* KeyData;
    public nuint KeyDataLen;
    public ulong Version;
    public byte* KemPk;
    public nuint KemPkLen;
    public byte Ephemeral;
}

internal unsafe delegate int OutFn(byte* o, ref nuint n);

#pragma warning disable SYSLIB1054 // DllImport: SafeHandle marshalling (a reference held per call) is what the handle rules need
internal static unsafe class Native
{
    const string L = "scaas_ua_c";

    static Native() => NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);

    static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
    {
        if (name != L) return IntPtr.Zero;
        if (Environment.GetEnvironmentVariable("SCAAS_UA_C_LIB") is { Length: > 0 } env) return NativeLibrary.Load(env);
        var file = OperatingSystem.IsWindows() ? "scaas_ua_c.dll" : OperatingSystem.IsMacOS() ? "libscaas_ua_c.dylib" : "libscaas_ua_c.so";
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "clients", "ua-c", "target", "release", file);
            if (File.Exists(p)) return NativeLibrary.Load(p);
        }
        return IntPtr.Zero;
    }

    [DllImport(L)] internal static extern uint scaas_ua_abi_version();
    [DllImport(L)] internal static extern ulong scaas_ua_features();
    [DllImport(L)] internal static extern byte* scaas_ua_status_name(int s);
    [DllImport(L)] internal static extern byte* scaas_ua_last_error();
    [DllImport(L)] internal static extern int scaas_ua_wallet_generate(out WalletHandle w, out SeedBackupHandle b);
    [DllImport(L)] internal static extern int scaas_ua_wallet_from_mnemonic(byte* words, byte* bip39, out WalletHandle w);
    [DllImport(L)] internal static extern int scaas_ua_wallet_open_vault(byte* vault, byte* pass, byte* prf, byte* bip39, out WalletHandle w);
    [DllImport(L)] internal static extern int scaas_ua_wallet_unlock(WalletHandle w, byte* vault, byte* pass, byte* prf, byte* bip39);
    [DllImport(L)] internal static extern int scaas_ua_wallet_seal_vault(WalletHandle w, byte* pass, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_lock(WalletHandle w);
    [DllImport(L)] internal static extern void scaas_ua_wallet_free(IntPtr w);
    [DllImport(L)] internal static extern int scaas_ua_wallet_memory_protection(WalletHandle w, out MemoryProtectionC m);
    [DllImport(L)] internal static extern int scaas_ua_wallet_ua_key(WalletHandle w, ushort kind, uint account, uint index, out KeyHandle k);
    [DllImport(L)] internal static extern int scaas_ua_wallet_native_key(WalletHandle w, uint network, uint index, uint coin, out KeyHandle k);
    [DllImport(L)] internal static extern int scaas_ua_wallet_import_native_key(WalletHandle w, uint network, byte* secret, nuint len, out KeyHandle k);
    [DllImport(L)] internal static extern int scaas_ua_wallet_imported_key(WalletHandle w, uint network, uint n, out KeyHandle k);
    [DllImport(L)] internal static extern int scaas_ua_wallet_seal_label_vault(WalletHandle w, byte* label, byte* pass, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_open_label_vault(WalletHandle w, byte* vault, byte* pass, byte* prf);
    [DllImport(L)] internal static extern int scaas_ua_wallet_manifest_json(WalletHandle w, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_discover_candidates(WalletHandle w, ushort kind, uint account, uint gap, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_backup_seal(WalletHandle w, KeyHandle sender, RecipientC* rs, nuint n, byte* o, ref nuint len);
    [DllImport(L)] internal static extern int scaas_ua_wallet_restore_backup(KemHandle kk, byte* c, byte* e, byte* m, byte* a, WalletHandle cur, byte* bip39, out WalletHandle w, byte* installed);
    [DllImport(L)] internal static extern int scaas_ua_wallet_restore_backup_rollback(KemHandle kk, byte* c, byte* e, byte* m, byte* a, WalletHandle cur, byte* bip39, out WalletHandle w, byte* installed);
    [DllImport(L)] internal static extern int scaas_ua_wallet_link_seal(WalletHandle w, KeyHandle sender, byte* pk, nuint pkLen, byte* code, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_from_link(LinkHandle s, byte* c, byte* e, byte* m, byte* a, byte* bip39, out WalletHandle w);
    [DllImport(L)] internal static extern int scaas_ua_seed_backup_reveal(SeedBackupHandle b, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_seed_backup_challenge(SeedBackupHandle b, uint* out3);
    [DllImport(L)] internal static extern int scaas_ua_seed_backup_verify(SeedBackupHandle b, byte** answers, nuint n, byte* ok);
    [DllImport(L)] internal static extern int scaas_ua_seed_backup_take(SeedBackupHandle b, byte* o, ref nuint n, byte* taken);
    [DllImport(L)] internal static extern void scaas_ua_seed_backup_free(IntPtr b);
    [DllImport(L)] internal static extern void scaas_ua_key_free(IntPtr k);
    [DllImport(L)] internal static extern int scaas_ua_key_data(KeyHandle k, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_ua(KeyHandle k, byte* purpose, byte* digest, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_member(KeyHandle k, byte* ua, byte* msg, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_typed(KeyHandle k, byte* td, byte* expect, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_typed_any(KeyHandle k, byte* td, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_transaction(KeyHandle k, byte* tx, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_key_proof(KeyHandle k, byte* c, nuint len, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_sign_digest_raw(KeyHandle k, byte* d, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_uasig(byte* req, IntPtr* keys, nuint nKeys, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_external_key_new(byte* keyRef, IntPtr cb, out KeyHandle k);
    [DllImport(L)] internal static extern int scaas_ua_kem_key(KeyHandle k, ulong version, out KemHandle kk);
    [DllImport(L)] internal static extern int scaas_ua_kem_ephemeral(out KemHandle kk);
    [DllImport(L)] internal static extern void scaas_ua_kem_free(IntPtr kk);
    [DllImport(L)] internal static extern int scaas_ua_kem_pk(KemHandle kk, byte* o);
    [DllImport(L)] internal static extern int scaas_ua_kem_decaps(KemHandle kk, byte* ct, nuint ctLen, byte* eph, byte* ss);
    [DllImport(L)] internal static extern int scaas_ua_kem_encaps(byte* pk, nuint pkLen, byte* ct, byte* eph, byte* ss);
    [DllImport(L)] internal static extern int scaas_ua_seal(byte* pk, nuint pkLen, byte* purpose, byte* aad, nuint aadLen, byte* pt, nuint ptLen, byte* mct, ref nuint mctLen, byte* eph, byte* ct, ref nuint ctLen);
    [DllImport(L)] internal static extern int scaas_ua_open(KemHandle kk, byte* purpose, byte* aad, nuint aadLen, byte* mct, nuint mctLen, byte* eph, byte* ct, nuint ctLen, byte* pt, ref nuint ptLen);
    [DllImport(L)] internal static extern int scaas_ua_open_container(KemHandle kk, byte* c, byte* e, byte* m, byte* a, byte* pt, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_link_session_new(out LinkHandle s);
    [DllImport(L)] internal static extern int scaas_ua_link_session_kem_pk(LinkHandle s, byte* o);
    [DllImport(L)] internal static extern int scaas_ua_link_session_short_code(LinkHandle s, byte* o, ref nuint n);
    [DllImport(L)] internal static extern void scaas_ua_link_session_free(IntPtr s);
    [DllImport(L)] internal static extern int scaas_ua_vault_needs_rewrap(byte* vault, byte* o);
    [DllImport(L)] internal static extern int scaas_ua_vault_rewrap_pin(byte* vault, byte* old, byte* neu, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_vault_enable_prf(byte* vault, byte* pass, byte* prf, byte* cred, byte* salt, nuint saltLen, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_aead_seal(uint alg, byte* key, byte* nonce, byte* aad, nuint aadLen, byte* data, nuint dataLen, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_aead_open(uint alg, byte* key, byte* nonce, byte* aad, nuint aadLen, byte* data, nuint dataLen, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_hkdf_sha256(byte* ikm, nuint ikmLen, byte* salt, nuint saltLen, byte* info, nuint infoLen, byte* o, nuint len);
    [DllImport(L)] internal static extern int scaas_ua_hmac_sha256(byte* key, nuint keyLen, byte* data, nuint dataLen, byte* o);
    [DllImport(L)] internal static extern int scaas_ua_webauthn_challenge(byte* purpose, byte* digest, byte* o);
    [DllImport(L)] internal static extern int scaas_ua_webauthn_assertion(byte* kd, nuint kdLen, byte* ch, byte* ad, nuint adLen, byte* cd, nuint cdLen, byte* r, byte* s, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_zether_key(WalletHandle w, uint coin, uint account, uint use, out ZetherHandle k);
    [DllImport(L)] internal static extern void scaas_ua_zether_key_free(IntPtr k);
    [DllImport(L)] internal static extern int scaas_ua_zether_public(ZetherHandle k, byte* y, byte* ua);
    [DllImport(L)] internal static extern int scaas_ua_zether_call(ZetherHandle k, byte* cmd, byte* req, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_zether_seal_balance_cache(ZetherHandle k, byte* e, nuint len, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_zether_open_balance_cache(ZetherHandle k, byte* box, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_wallet_pqz_key(WalletHandle w, uint account, uint index, out PqzHandle k);
    [DllImport(L)] internal static extern void scaas_ua_pqz_key_free(IntPtr k);
    [DllImport(L)] internal static extern int scaas_ua_pqz_public(PqzHandle k, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_pqz_call(PqzHandle k, byte* cmd, byte* req, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_pqz_seal_balance_cache(PqzHandle k, byte* e, nuint len, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_pqz_open_balance_cache(PqzHandle k, byte* box, byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_pqz_set(byte* o, ref nuint n);
    [DllImport(L)] internal static extern int scaas_ua_pqz_check_set(byte* deployed);
    [DllImport(L)] internal static extern int scaas_ua_export_pqz_leaf_raw(WalletHandle w, uint account, uint index, byte* o);
}
#pragma warning restore SYSLIB1054

/// <summary>One call's arguments: caller arrays pinned in place, strings and secret copies in pinned arrays; secret copies zeroed
/// on Dispose.</summary>
internal sealed unsafe class Args : IDisposable
{
    readonly List<GCHandle> _pins = [];
    readonly List<byte[]> _wipes = [];

    static byte* Addr(byte[] a) => (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(a));

    /// <summary>A caller array pinned for the call; null or empty is NULL.</summary>
    public byte* Pin(byte[]? b)
    {
        if (b is null || b.Length == 0) return null;
        _pins.Add(GCHandle.Alloc(b, GCHandleType.Pinned));
        return Addr(b);
    }

    /// <summary>A public string, NUL-terminated; null is NULL.</summary>
    public byte* Str(string? s)
    {
        if (s is null) return null;
        var a = GC.AllocateArray<byte>(Encoding.UTF8.GetByteCount(s) + 1, pinned: true);
        Encoding.UTF8.GetBytes(s, a);
        _keep.Add(a);
        return Addr(a);
    }

    readonly List<byte[]> _keep = []; // pinned-heap arrays: alive (and in place) until the call returns

    /// <summary>A NUL-terminated copy of a secret (from the <see cref="UaLib.SecretBuf"/> hook), zeroed on Dispose; null is NULL.</summary>
    public byte* Secret(byte[]? b)
    {
        if (b is null) return null;
        var x = UaLib.SecretBuf(b.Length + 1);
        b.CopyTo(x, 0);
        _wipes.Add(x);
        return Addr(x);
    }

    /// <summary>A fixed-size input: anything else is UAKeyData before the library reads it.</summary>
    public byte* Sized(byte[]? b, int n, string what)
    {
        if (b is null || b.Length != n) throw new WalletException(UaLib.ErrKeyData, "UAKeyData", $"{what}: {n} bytes");
        return Pin(b);
    }

    public byte* OptSized(byte[]? b, int n, string what) => b is null ? null : Sized(b, n, what);

    public void Dispose()
    {
        foreach (var x in _wipes) CryptographicOperations.ZeroMemory(x);
        foreach (var h in _pins)
            if (h.IsAllocated) h.Free();
    }
}

/// <summary>The library's module-level calls, constants, the load check and the secret helpers.</summary>
public static unsafe class UaLib
{
    public const uint AbiVersionRequired = 6;
    public const ulong FeatureWallet = 1 << 0, FeaturePq = 1 << 1, FeatureFalcon = 1 << 2, FeatureZether = 1 << 3, FeaturePqz = 1 << 4,
        FeaturePqzSetN2048Kmax1024 = 1 << 5, FeaturePqzSetN2304Kmax4096 = 1 << 6, FeaturePqzSetN2560Kmax16384 = 1 << 7,
        FeaturePqzSetN2816Kmax65536 = 1 << 8, FeatureExternal = 1 << 9, FeatureMlock = 1 << 10;
    const ulong FeatureEnd = 1 << 11;
    const ulong FeatureSets = FeaturePqzSetN2048Kmax1024 | FeaturePqzSetN2304Kmax4096 | FeaturePqzSetN2560Kmax16384 | FeaturePqzSetN2816Kmax65536;
    public static readonly string[] Networks = ["evm", "cosmos", "hedera_ecdsa", "hedera_ed25519", "sui", "stellar", "ton", "aptos", "solana"];
    public const uint CoinDefault = 0xFFFFFFFF, AeadAes256Gcm = 1, AeadAes256GcmSiv = 2;
    public const int KemPkLen = 1601, KemCtLen = 1568, MnemonicMax = 256, EntropyMax = 32, ZetherYLen = 128;
    public const uint ZetherUseConf = 7, ZetherUseViewing = 8;
    /// <summary>SCAAS_UA_PQZ_OUT_MAX: a PQZ answer's buffer (never sized by a size query).</summary>
    public const int PqzOutMax = 1052672;
    internal const int ErrKeyData = 1, ErrBuffer = 9;

    static readonly Lock LoadLock = new();
    static bool _loaded;
    /// <summary>Test hook: maps the library's ABI version before the check.</summary>
    internal static Func<uint, uint> AbiVersionHook = v => v;
    /// <summary>Test hook (secret_buffer_wiped_after_call): every copy this binding makes of a secret comes from here.</summary>
    internal static Func<int, byte[]> SecretBuf = n => GC.AllocateArray<byte>(n, pinned: true);

    internal static void ResetLoad()
    {
        lock (LoadLock) _loaded = false;
    }

    /// <summary>Refuses a library of another ABI or an unknown feature set (the load check).</summary>
    public static void CheckBuild(uint abi, ulong features)
    {
        if (abi != AbiVersionRequired) throw new LibraryMismatchException($"libscaas_ua_c ABI {abi}, this binding needs {AbiVersionRequired}");
        const ulong need = FeatureWallet | FeaturePq;
        var sets = features & FeatureSets;
        if ((features & need) != need || features >= FeatureEnd || (sets & (sets - 1)) != 0 || (sets != 0) != ((features & FeaturePqz) != 0))
            throw new LibraryMismatchException($"libscaas_ua_c features 0x{features:x} are not a build this binding knows");
    }

    /// <summary>Checks the library once (every entry point calls it); a refused library stays refused.</summary>
    public static void Load()
    {
        lock (LoadLock)
        {
            if (_loaded) return;
            CheckBuild(AbiVersionHook(Native.scaas_ua_abi_version()), Native.scaas_ua_features());
            _loaded = true;
        }
    }

    public static uint AbiVersion() => Native.scaas_ua_abi_version();
    public static ulong Features() => Native.scaas_ua_features();
    public static string StatusName(int s) => Marshal.PtrToStringUTF8((IntPtr)Native.scaas_ua_status_name(s)) ?? "";

    /// <summary>Zeroizes a secret this binding returned (or the caller's own).</summary>
    public static void Wipe(byte[]? b)
    {
        if (b is not null) CryptographicOperations.ZeroMemory(b);
    }

    internal static void Check(int status)
    {
        if (status != 0)
            throw new WalletException(status, StatusName(status), Marshal.PtrToStringUTF8((IntPtr)Native.scaas_ua_last_error()) ?? "");
    }

    /// <summary>A variable output: one call into <paramref name="cap"/> bytes, again at the size asked for (a size query runs the call again).</summary>
    internal static byte[] Out(int cap, OutFn f)
    {
        var buf = new byte[cap + 1];
        var n = (nuint)cap;
        int st;
        fixed (byte* p = buf) st = f(p, ref n);
        if (st == ErrBuffer)
        {
            buf = new byte[(int)n + 1];
            fixed (byte* p = buf) st = f(p, ref n);
        }
        Check(st);
        return buf[..(int)n];
    }

    internal static string OutStr(int cap, OutFn f)
    {
        var b = Out(cap, f);
        return b.Length == 0 ? "" : Encoding.UTF8.GetString(b, 0, b.Length - 1); // *out_len counts the NUL
    }

    /// <summary>A secret variable output whose capacity the library checks first: the size, then the bytes, in a pinned array.</summary>
    internal static byte[] SecretOut(OutFn f)
    {
        nuint n = 0;
        var st = f(null, ref n);
        if (st != ErrBuffer) Check(st);
        var buf = GC.AllocateArray<byte>((int)n + 1, pinned: true);
        fixed (byte* p = buf) st = f(p, ref n);
        if (st != 0) Wipe(buf);
        Check(st);
        return Trim(buf, (int)n);
    }

    /// <summary>The first <paramref name="n"/> bytes of <paramref name="buf"/> in a new pinned array; <paramref name="buf"/> is wiped.</summary>
    internal static byte[] Trim(byte[] buf, int n)
    {
        var r = GC.AllocateArray<byte>(n, pinned: true);
        buf.AsSpan(0, n).CopyTo(r);
        Wipe(buf);
        return r;
    }

    // --- module-level calls ---

    /// <summary>The <c>UASig</c> JSON of <paramref name="request"/> (named fields; signing keys by position in <paramref name="keys"/>).</summary>
    public static string UASig(string request, IReadOnlyList<WalletKey> keys)
    {
        Load();
        var held = new bool[keys.Count];
        var ps = new IntPtr[keys.Count + 1];
        try
        {
            for (var i = 0; i < keys.Count; i++)
            {
                keys[i].H.DangerousAddRef(ref held[i]);
                ps[i] = keys[i].H.DangerousGetHandle();
            }
            using var a = new Args();
            var req = a.Str(request);
            fixed (IntPtr* p = ps)
            {
                var arr = p;
                return OutStr(1 << 16, (o, ref n) => Native.scaas_ua_uasig(req, arr, (nuint)keys.Count, o, ref n));
            }
        }
        finally
        {
            for (var i = 0; i < keys.Count; i++)
                if (held[i]) keys[i].H.DangerousRelease();
        }
    }

    /// <summary>Reserved (phase 2): no build of this round has an external key (UAKindUnavailable).</summary>
    public static WalletKey ExternalKeyNew(string keyRef)
    {
        Load();
        using var a = new Args();
        Check(Native.scaas_ua_external_key_new(a.Str(keyRef), IntPtr.Zero, out var k));
        return new WalletKey(k);
    }

    /// <summary>An encapsulation to <paramref name="kemPk"/>: the ciphertext, the ephemeral X25519 key, the shared secret (wipe it).</summary>
    public static (byte[] MlkemCt, byte[] X25519Eph, byte[] Ss) KemEncaps(byte[] kemPk)
    {
        Load();
        var (ct, e, ss) = (new byte[KemCtLen], new byte[32], GC.AllocateArray<byte>(32, pinned: true));
        using var a = new Args();
        Check(Native.scaas_ua_kem_encaps(a.Pin(kemPk), (nuint)kemPk.Length, a.Pin(ct), a.Pin(e), a.Pin(ss)));
        return (ct, e, ss);
    }

    /// <summary>A seal of <paramref name="pt"/> to <paramref name="kemPk"/> under purpose and aad (no sender authenticated).</summary>
    public static (byte[] MlkemCt, byte[] X25519Eph, byte[] Ct) Seal(byte[] kemPk, string purpose, byte[] aad, byte[] pt)
    {
        Load();
        var (mct, e, ct) = (new byte[KemCtLen], new byte[32], new byte[pt.Length + 16]);
        nuint nm = KemCtLen, nc = (nuint)ct.Length;
        using var a = new Args();
        Check(Native.scaas_ua_seal(a.Pin(kemPk), (nuint)kemPk.Length, a.Str(purpose), a.Pin(aad), (nuint)aad.Length, a.Pin(pt), (nuint)pt.Length,
            a.Pin(mct), ref nm, a.Pin(e), a.Pin(ct), ref nc));
        return (mct[..(int)nm], e, ct[..(int)nc]);
    }

    public static bool VaultNeedsRewrap(string vaultJson)
    {
        Load();
        byte r = 0;
        using var a = new Args();
        Check(Native.scaas_ua_vault_needs_rewrap(a.Str(vaultJson), &r));
        return r != 0;
    }

    /// <summary>The vault under a new pin envelope (same DEK).</summary>
    public static string VaultRewrapPin(string vaultJson, byte[] oldPassphrase, byte[] newPassphrase)
    {
        Load();
        using var a = new Args();
        var v = a.Str(vaultJson);
        var o1 = a.Secret(oldPassphrase);
        var n1 = a.Secret(newPassphrase);
        return OutStr(1 << 14, (o, ref n) => Native.scaas_ua_vault_rewrap_pin(v, o1, n1, o, ref n));
    }

    /// <summary>The vault with a PRF envelope, opened once by the passphrase.</summary>
    public static string VaultEnablePrf(string vaultJson, byte[] passphrase, byte[] prf32, string credentialId, byte[] salt)
    {
        Load();
        using var a = new Args();
        var v = a.Str(vaultJson);
        var p = a.Secret(passphrase);
        var prf = a.Sized(prf32, 32, "prf32");
        var c = a.Str(credentialId);
        var s = a.Pin(salt);
        return OutStr(1 << 14, (o, ref n) => Native.scaas_ua_vault_enable_prf(v, p, prf, c, s, (nuint)salt.Length, o, ref n));
    }

    static byte[] Aead(bool open, uint alg, byte[] key, byte[] nonce, byte[] aad, byte[] data)
    {
        Load();
        using var a = new Args();
        var k = a.Sized(key, 32, "key");
        var nn = a.Sized(nonce, 12, "nonce");
        var size = open ? Math.Max(data.Length - 16, 0) : data.Length + 16;
        var o = GC.AllocateArray<byte>(size + 1, pinned: true);
        var n = (nuint)size;
        var st = open
            ? Native.scaas_ua_aead_open(alg, k, nn, a.Pin(aad), (nuint)aad.Length, a.Pin(data), (nuint)data.Length, a.Pin(o), ref n)
            : Native.scaas_ua_aead_seal(alg, k, nn, a.Pin(aad), (nuint)aad.Length, a.Pin(data), (nuint)data.Length, a.Pin(o), ref n);
        Check(st);
        return Trim(o, (int)n);
    }

    /// <summary>ct || tag of data under the caller's 32-byte key and 12-byte nonce (nonce uniqueness is the caller's).</summary>
    public static byte[] AeadSeal(uint alg, byte[] key, byte[] nonce, byte[] aad, byte[] data) => Aead(false, alg, key, nonce, aad, data);

    /// <summary>The plaintext of ct || tag (UAAead for a bad tag); wipe it.</summary>
    public static byte[] AeadOpen(uint alg, byte[] key, byte[] nonce, byte[] aad, byte[] data) => Aead(true, alg, key, nonce, aad, data);

    /// <summary><paramref name="n"/> bytes of HKDF-SHA256 (key material: wipe it).</summary>
    public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int n)
    {
        Load();
        using var a = new Args();
        var o = GC.AllocateArray<byte>(n, pinned: true);
        Check(Native.scaas_ua_hkdf_sha256(a.Pin(ikm), (nuint)ikm.Length, a.Pin(salt), (nuint)salt.Length, a.Pin(info), (nuint)info.Length, a.Pin(o), (nuint)n));
        return o;
    }

    public static byte[] HmacSha256(byte[] key, byte[] data)
    {
        Load();
        using var a = new Args();
        var o = new byte[32];
        Check(Native.scaas_ua_hmac_sha256(a.Pin(key), (nuint)key.Length, a.Pin(data), (nuint)data.Length, a.Pin(o)));
        return o;
    }

    /// <summary>uaMessage(0x0100, purpose, digest).</summary>
    public static byte[] WebAuthnChallenge(byte[] purpose32, byte[] digest32)
    {
        Load();
        using var a = new Args();
        var o = new byte[32];
        Check(Native.scaas_ua_webauthn_challenge(a.Sized(purpose32, 32, "purpose"), a.Sized(digest32, 32, "digest"), a.Pin(o)));
        return o;
    }

    /// <summary>The webauthn-p256 signature of an assertion, verified with keyData against the expected challenge.</summary>
    public static byte[] WebAuthnAssertion(byte[] keyData, byte[] expectedChallenge32, byte[] authData, byte[] clientDataJson, byte[] r32, byte[] s32)
    {
        Load();
        using var a = new Args();
        var kd = a.Pin(keyData);
        var ch = a.Sized(expectedChallenge32, 32, "challenge");
        var ad = a.Pin(authData);
        var cd = a.Pin(clientDataJson);
        var r = a.Sized(r32, 32, "r");
        var s = a.Sized(s32, 32, "s");
        return Out(1024, (o, ref n) => Native.scaas_ua_webauthn_assertion(kd, (nuint)keyData.Length, ch, ad, (nuint)authData.Length, cd,
            (nuint)clientDataJson.Length, r, s, o, ref n));
    }

    /// <summary>This build's PQZ parameter set as JSON {set, pkLen, pqzlId, pqzhId}.</summary>
    public static string PqzSet()
    {
        Load();
        return OutStr(1024, (o, ref n) => Native.scaas_ua_pqz_set(o, ref n));
    }

    /// <summary>Throws UAPqzSetMismatch unless <paramref name="deployed"/> (a token's PqzSet JSON) is this build's set.</summary>
    public static void PqzCheckSet(string deployed)
    {
        Load();
        using var a = new Args();
        Check(Native.scaas_ua_pqz_check_set(a.Str(deployed)));
    }
}

/// <summary>A wallet: its secret store and manifest. Dispose locks and frees it; its children stay valid and answer UAKeyRevoked.</summary>
public sealed unsafe class Wallet : IDisposable
{
    internal readonly WalletHandle H;
    internal Wallet(WalletHandle h) => H = h;
    public void Dispose() => H.Dispose();

    /// <summary>A new 24-word wallet and its seed backup.</summary>
    public static (Wallet Wallet, SeedBackup Backup) Generate()
    {
        UaLib.Load();
        UaLib.Check(Native.scaas_ua_wallet_generate(out var w, out var b));
        return (new Wallet(w), new SeedBackup(b));
    }

    /// <summary>The wallet of a 12- to 24-word English mnemonic and its BIP-39 passphrase (null = empty).</summary>
    public static Wallet FromMnemonic(byte[] words, byte[]? bip39Passphrase = null)
    {
        UaLib.Load();
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_from_mnemonic(a.Secret(words), a.Secret(bip39Passphrase), out var w));
        return new Wallet(w);
    }

    /// <summary>The wallet of a seed vault: exactly one of the passphrase and prf32 (both: the PRF secret).</summary>
    public static Wallet OpenVault(string vaultJson, byte[]? passphrase = null, byte[]? prf32 = null, byte[]? bip39Passphrase = null)
    {
        UaLib.Load();
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_open_vault(a.Str(vaultJson), a.Secret(passphrase), a.OptSized(prf32, 32, "prf32"), a.Secret(bip39Passphrase), out var w));
        return new Wallet(w);
    }

    /// <summary>Reopens a locked wallet from its seed vault; earlier handles stay revoked.</summary>
    public void Unlock(string vaultJson, byte[]? passphrase = null, byte[]? prf32 = null, byte[]? bip39Passphrase = null)
    {
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_unlock(H, a.Str(vaultJson), a.Secret(passphrase), a.OptSized(prf32, 32, "prf32"), a.Secret(bip39Passphrase)));
    }

    /// <summary>The seed vault JSON of this wallet under the passphrase (a new vault each call).</summary>
    public string SealVault(byte[] passphrase)
    {
        using var a = new Args();
        var p = a.Secret(passphrase);
        return UaLib.OutStr(1 << 14, (o, ref n) => Native.scaas_ua_wallet_seal_vault(H, p, o, ref n));
    }

    /// <summary>Waits for calls in flight, wipes the secrets and revokes every child handle.</summary>
    public void Lock() => UaLib.Check(Native.scaas_ua_wallet_lock(H));

    public MemoryProtection MemoryProtection()
    {
        UaLib.Check(Native.scaas_ua_wallet_memory_protection(H, out var m));
        return new MemoryProtection(m.Chunks, m.Locked, m.NoDump);
    }

    public WalletKey UAKey(ushort kind, uint account, uint index)
    {
        UaLib.Check(Native.scaas_ua_wallet_ua_key(H, kind, account, index, out var k));
        return new WalletKey(k);
    }

    /// <summary>Key <paramref name="index"/> of <paramref name="network"/> (an index of <see cref="UaLib.Networks"/>).</summary>
    public WalletKey NativeKey(uint network, uint index, uint coinType = UaLib.CoinDefault)
    {
        UaLib.Check(Native.scaas_ua_wallet_native_key(H, network, index, coinType, out var k));
        return new WalletKey(k);
    }

    /// <summary>Imports a 32-byte key of the network; the caller wipes <paramref name="secret"/>.</summary>
    public WalletKey ImportNativeKey(uint network, byte[] secret)
    {
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_import_native_key(H, network, a.Pin(secret), (nuint)secret.Length, out var k));
        return new WalletKey(k);
    }

    public WalletKey ImportedKey(uint network, uint n)
    {
        UaLib.Check(Native.scaas_ua_wallet_imported_key(H, network, n, out var k));
        return new WalletKey(k);
    }

    /// <summary>A vault of label "manifest" or "native-import:&lt;network&gt;:&lt;n&gt;" under the passphrase.</summary>
    public string SealLabelVault(string label, byte[] passphrase)
    {
        using var a = new Args();
        var l = a.Str(label);
        var p = a.Secret(passphrase);
        return UaLib.OutStr(1 << 14, (o, ref n) => Native.scaas_ua_wallet_seal_label_vault(H, l, p, o, ref n));
    }

    public void OpenLabelVault(string vaultJson, byte[]? passphrase = null, byte[]? prf32 = null)
    {
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_open_label_vault(H, a.Str(vaultJson), a.Secret(passphrase), a.OptSized(prf32, 32, "prf32")));
    }

    public string ManifestJson() => UaLib.OutStr(1 << 14, (o, ref n) => Native.scaas_ua_wallet_manifest_json(H, o, ref n));

    public string DiscoverCandidates(ushort kind, uint account, uint gap) =>
        UaLib.OutStr(1 << 17, (o, ref n) => Native.scaas_ua_wallet_discover_candidates(H, kind, account, gap, o, ref n));

    /// <summary>One scaas/backup/v1 container per recipient (a JSON array), signed by <paramref name="sender"/>; raises the backup
    /// generation (once per call into the 4 MiB first buffer).</summary>
    public string BackupSeal(WalletKey sender, IReadOnlyList<Recipient> recipients)
    {
        using var a = new Args();
        var rs = new RecipientC[recipients.Count + 1];
        for (var i = 0; i < recipients.Count; i++)
        {
            var r = recipients[i];
            rs[i] = new RecipientC { Kind = r.Kind, KeyData = a.Pin(r.KeyData), KeyDataLen = (nuint)r.KeyData.Length, Version = r.Version,
                KemPk = a.Pin(r.KemPk), KemPkLen = (nuint)r.KemPk.Length, Ephemeral = (byte)(r.Ephemeral ? 1 : 0) };
        }
        fixed (RecipientC* p = rs)
        {
            var arr = recipients.Count > 0 ? p : null;
            return UaLib.OutStr(4 << 20, (o, ref n) => Native.scaas_ua_wallet_backup_seal(H, sender.H, arr, (nuint)recipients.Count, o, ref n));
        }
    }

    /// <summary>The existing device's link container to a new device's session (its KEM key and short code), signed by <paramref name="sender"/>.</summary>
    public string LinkSeal(WalletKey sender, byte[] sessionKemPk, string shortCode)
    {
        using var a = new Args();
        var pk = a.Pin(sessionKemPk);
        var c = a.Str(shortCode);
        return UaLib.OutStr(1 << 20, (o, ref n) => Native.scaas_ua_wallet_link_seal(H, sender.H, pk, (nuint)sessionKemPk.Length, c, o, ref n));
    }

    public ZetherKey ZetherKey(uint coin, uint account, uint use)
    {
        UaLib.Check(Native.scaas_ua_wallet_zether_key(H, coin, account, use, out var k));
        return new ZetherKey(k);
    }

    public PqzKey PqzKey(uint account, uint index)
    {
        UaLib.Check(Native.scaas_ua_wallet_pqz_key(H, account, index, out var k));
        return new PqzKey(k);
    }

    /// <summary>WARNING: a secret in the clear, the 32-byte PQZ leaf seed32 (a pinned array): wipe it with <see cref="UaLib.Wipe"/>.</summary>
    public byte[] ExportPqzLeafRaw(uint account, uint index)
    {
        var leaf = GC.AllocateArray<byte>(32, pinned: true);
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_export_pqz_leaf_raw(H, account, index, a.Pin(leaf)));
        return leaf;
    }

    static Wallet? Restore(bool rollback, KemKey kk, string container, string expect, string? members, string? accepted, Wallet? current, byte[]? bip39Passphrase)
    {
        using var a = new Args();
        byte installed = 0;
        var c = a.Str(container);
        var e = a.Str(expect);
        var m = a.Str(members);
        var ac = a.Str(accepted);
        var bp = a.Secret(bip39Passphrase);
        var cur = current?.H ?? WalletHandle.None;
        WalletHandle w;
        var st = rollback
            ? Native.scaas_ua_wallet_restore_backup_rollback(kk.H, c, e, m, ac, cur, bp, out w, &installed)
            : Native.scaas_ua_wallet_restore_backup(kk.H, c, e, m, ac, cur, bp, out w, &installed);
        UaLib.Check(st);
        return installed != 0 ? new Wallet(w) : null;
    }

    /// <summary>The wallet a backup container carries, or null when <paramref name="current"/> holds that generation already (an older one
    /// is UABackupRollback).</summary>
    public static Wallet? RestoreBackup(KemKey kk, string container, string expect, string? members = null, string? accepted = null,
        Wallet? current = null, byte[]? bip39Passphrase = null) => Restore(false, kk, container, expect, members, accepted, current, bip39Passphrase);

    /// <summary><see cref="RestoreBackup"/> that may install an older backup: only after the user confirmed the rollback.</summary>
    public static Wallet? RestoreBackupRollback(KemKey kk, string container, string expect, string? members = null, string? accepted = null,
        Wallet? current = null, byte[]? bip39Passphrase = null) => Restore(true, kk, container, expect, members, accepted, current, bip39Passphrase);

    /// <summary>The wallet a link container carries to <paramref name="session"/> (which it consumes).</summary>
    public static Wallet FromLink(LinkSession session, string container, string expect, string? members = null, string? accepted = null,
        byte[]? bip39Passphrase = null)
    {
        using var a = new Args();
        UaLib.Check(Native.scaas_ua_wallet_from_link(session.H, a.Str(container), a.Str(expect), a.Str(members), a.Str(accepted), a.Secret(bip39Passphrase), out var w));
        return new Wallet(w);
    }
}

/// <summary>The recovery phrase of <see cref="Wallet.Generate"/>: reveal once, challenge, verify, take.</summary>
public sealed unsafe class SeedBackup : IDisposable
{
    internal readonly SeedBackupHandle H;
    internal SeedBackup(SeedBackupHandle h) => H = h;
    public void Dispose() => H.Dispose();

    /// <summary>The recovery phrase, once (a pinned array: wipe it).</summary>
    public byte[] Reveal()
    {
        var buf = GC.AllocateArray<byte>(UaLib.MnemonicMax, pinned: true);
        nuint n = UaLib.MnemonicMax;
        fixed (byte* p = buf) UaLib.Check(Native.scaas_ua_seed_backup_reveal(H, p, ref n));
        var r = GC.AllocateArray<byte>((int)n - 1, pinned: true);
        buf.AsSpan(0, r.Length).CopyTo(r);
        UaLib.Wipe(buf);
        return r;
    }

    /// <summary>Three word positions to ask, 1-based and ascending.</summary>
    public uint[] Challenge()
    {
        var pos = new uint[3];
        fixed (uint* p = pos) UaLib.Check(Native.scaas_ua_seed_backup_challenge(H, p));
        return pos;
    }

    public bool Verify(IReadOnlyList<byte[]> answers)
    {
        using var a = new Args();
        var ws = new IntPtr[answers.Count + 1];
        for (var i = 0; i < answers.Count; i++) ws[i] = (IntPtr)a.Secret(answers[i]);
        byte ok = 0;
        fixed (IntPtr* p = ws) UaLib.Check(Native.scaas_ua_seed_backup_verify(H, (byte**)p, (nuint)answers.Count, &ok));
        return ok != 0;
    }

    /// <summary>The entropy once the words were confirmed (a pinned array: wipe it), else null.</summary>
    public byte[]? Take()
    {
        var buf = GC.AllocateArray<byte>(UaLib.EntropyMax, pinned: true);
        nuint n = UaLib.EntropyMax;
        byte taken = 0;
        fixed (byte* p = buf) UaLib.Check(Native.scaas_ua_seed_backup_take(H, p, ref n, &taken));
        if (taken == 0) return null;
        return (int)n == buf.Length ? buf : UaLib.Trim(buf, (int)n);
    }
}

/// <summary>A UA key or a native key of a wallet.</summary>
public sealed unsafe class WalletKey : IDisposable
{
    internal readonly KeyHandle H;
    internal WalletKey(KeyHandle h) => H = h;
    public void Dispose() => H.Dispose();

    /// <summary>A UA key's key data, or a native key's public key (readable after its wallet is locked).</summary>
    public byte[] KeyData() => UaLib.Out(4096, (o, ref n) => Native.scaas_ua_key_data(H, o, ref n));

    public byte[] SignUA(byte[] purpose32, byte[] digest32)
    {
        using var a = new Args();
        var p = a.Sized(purpose32, 32, "purpose");
        var d = a.Sized(digest32, 32, "digest");
        return UaLib.Out(8192, (o, ref n) => Native.scaas_ua_sign_ua(H, p, d, o, ref n));
    }

    public byte[] SignMember(byte[] structureUa32, byte[] structureUaMsg32)
    {
        using var a = new Args();
        var u = a.Sized(structureUa32, 32, "structure ua");
        var m = a.Sized(structureUaMsg32, 32, "structure ua_msg");
        return UaLib.Out(8192, (o, ref n) => Native.scaas_ua_sign_member(H, u, m, o, ref n));
    }

    /// <summary>A native EVM key's EIP-712 signature of the typed data, only if <paramref name="expect"/> says the user confirmed it.</summary>
    public byte[] SignTyped(string typedData, string expect)
    {
        using var a = new Args();
        var t = a.Str(typedData);
        var e = a.Str(expect);
        return UaLib.Out(128, (o, ref n) => Native.scaas_ua_sign_typed(H, t, e, o, ref n));
    }

    /// <summary><see cref="SignTyped"/> with no SCaaS check (the general EVM wallet's opt-in by this name).</summary>
    public byte[] SignTypedAny(string typedData)
    {
        using var a = new Args();
        var t = a.Str(typedData);
        return UaLib.Out(128, (o, ref n) => Native.scaas_ua_sign_typed_any(H, t, o, ref n));
    }

    public byte[] SignTransaction(string tx)
    {
        using var a = new Args();
        var t = a.Str(tx);
        return UaLib.Out(1 << 15, (o, ref n) => Native.scaas_ua_sign_transaction(H, t, o, ref n));
    }

    public byte[] SignKeyProof(byte[] challenge)
    {
        using var a = new Args();
        var c = a.Pin(challenge);
        return UaLib.Out(128, (o, ref n) => Native.scaas_ua_sign_key_proof(H, c, (nuint)challenge.Length, o, ref n));
    }

    public byte[] SignDigestRaw(byte[] digest32)
    {
        using var a = new Args();
        var d = a.Sized(digest32, 32, "digest");
        return UaLib.Out(128, (o, ref n) => Native.scaas_ua_sign_digest_raw(H, d, o, ref n));
    }

    /// <summary>The UA's KEM key of record <paramref name="version"/> (0 = the register key).</summary>
    public KemKey KemKey(ulong version)
    {
        UaLib.Check(Native.scaas_ua_kem_key(H, version, out var kk));
        return new KemKey(kk);
    }
}

/// <summary>A KEM key pair: a UA's or an ephemeral one.</summary>
public sealed unsafe class KemKey : IDisposable
{
    internal readonly KemHandle H;
    internal KemKey(KemHandle h) => H = h;
    public void Dispose() => H.Dispose();

    public static KemKey Ephemeral()
    {
        UaLib.Load();
        UaLib.Check(Native.scaas_ua_kem_ephemeral(out var kk));
        return new KemKey(kk);
    }

    public byte[] KemPk()
    {
        var pk = new byte[UaLib.KemPkLen];
        fixed (byte* p = pk) UaLib.Check(Native.scaas_ua_kem_pk(H, p));
        return pk;
    }

    /// <summary>The 32-byte shared secret (a pinned array: wipe it).</summary>
    public byte[] Decaps(byte[] mlkemCt, byte[] x25519Eph32)
    {
        using var a = new Args();
        var ss = GC.AllocateArray<byte>(32, pinned: true);
        UaLib.Check(Native.scaas_ua_kem_decaps(H, a.Pin(mlkemCt), (nuint)mlkemCt.Length, a.Sized(x25519Eph32, 32, "x25519 key"), a.Pin(ss)));
        return ss;
    }

    /// <summary>The plaintext of a seal (a pinned array: wipe it).</summary>
    public byte[] Open(string purpose, byte[] aad, byte[] mlkemCt, byte[] x25519Eph32, byte[] ct)
    {
        using var a = new Args();
        var pu = a.Str(purpose);
        var ad = a.Pin(aad);
        var mc = a.Pin(mlkemCt);
        var e = a.Sized(x25519Eph32, 32, "x25519 key");
        var c = a.Pin(ct);
        return UaLib.SecretOut((o, ref n) => Native.scaas_ua_open(H, pu, ad, (nuint)aad.Length, mc, (nuint)mlkemCt.Length, e, c, (nuint)ct.Length, o, ref n));
    }

    /// <summary>The plaintext of a sealed container accepted as <paramref name="expect"/> says (a pinned array: wipe it).</summary>
    public byte[] OpenContainer(string container, string expect, string? members = null, string? accepted = null)
    {
        using var a = new Args();
        var c = a.Str(container);
        var e = a.Str(expect);
        var m = a.Str(members);
        var ac = a.Str(accepted);
        return UaLib.SecretOut((o, ref n) => Native.scaas_ua_open_container(H, c, e, m, ac, o, ref n));
    }
}

/// <summary>A device-link session of the new device.</summary>
public sealed unsafe class LinkSession : IDisposable
{
    internal readonly LinkHandle H;
    internal LinkSession(LinkHandle h) => H = h;
    public void Dispose() => H.Dispose();

    public static LinkSession New()
    {
        UaLib.Load();
        UaLib.Check(Native.scaas_ua_link_session_new(out var s));
        return new LinkSession(s);
    }

    public byte[] KemPk()
    {
        var pk = new byte[UaLib.KemPkLen];
        fixed (byte* p = pk) UaLib.Check(Native.scaas_ua_link_session_kem_pk(H, p));
        return pk;
    }

    public string ShortCode() => UaLib.OutStr(16, (o, ref n) => Native.scaas_ua_link_session_short_code(H, o, ref n));
}

/// <summary>A Zether key: <c>x</c> stays in the wallet's store.</summary>
public sealed unsafe class ZetherKey : IDisposable
{
    internal readonly ZetherHandle H;
    internal ZetherKey(ZetherHandle h) => H = h;
    public void Dispose() => H.Dispose();

    /// <summary>The key's Y (128 bytes) and UA (readable after lock).</summary>
    public (byte[] Y, byte[] UA) Public()
    {
        var (y, ua) = (new byte[UaLib.ZetherYLen], new byte[32]);
        fixed (byte* py = y, pu = ua) UaLib.Check(Native.scaas_ua_zether_public(H, py, pu));
        return (y, ua);
    }

    /// <summary>zether-prover's command <paramref name="cmd"/> on the request (named fields) with this key: its JSON answer.</summary>
    public string Call(string cmd, string request)
    {
        using var a = new Args();
        var c = a.Str(cmd);
        var r = a.Str(request);
        return UaLib.OutStr(1 << 20, (o, ref n) => Native.scaas_ua_zether_call(H, c, r, o, ref n));
    }

    public string SealBalanceCache(byte[] entries)
    {
        using var a = new Args();
        var e = a.Pin(entries);
        return UaLib.OutStr(entries.Length + 256, (o, ref n) => Native.scaas_ua_zether_seal_balance_cache(H, e, (nuint)entries.Length, o, ref n));
    }

    /// <summary>The cache entries of a box (a pinned array: wipe it).</summary>
    public byte[] OpenBalanceCache(string box)
    {
        using var a = new Args();
        var b = a.Str(box);
        return UaLib.SecretOut((o, ref n) => Native.scaas_ua_zether_open_balance_cache(H, b, o, ref n));
    }
}

/// <summary>A PQZ key: <c>seed32</c> stays in the wallet's store.</summary>
public sealed unsafe class PqzKey : IDisposable
{
    internal readonly PqzHandle H;
    internal PqzKey(PqzHandle h) => H = h;
    public void Dispose() => H.Dispose();

    public byte[] PublicKey() => UaLib.Out(32 << 10, (o, ref n) => Native.scaas_ua_pqz_public(H, o, ref n));

    /// <summary>PQZ command <paramref name="cmd"/> on the request with this key: its JSON answer, in one call into
    /// <see cref="UaLib.PqzOutMax"/> bytes (a size query would prove again, and a proof's length varies).</summary>
    public string Call(string cmd, string request)
    {
        using var a = new Args();
        var buf = new byte[UaLib.PqzOutMax];
        nuint n = UaLib.PqzOutMax;
        fixed (byte* o = buf) UaLib.Check(Native.scaas_ua_pqz_call(H, a.Str(cmd), a.Str(request), o, ref n));
        return Encoding.UTF8.GetString(buf, 0, (int)n - 1);
    }

    public string SealBalanceCache(byte[] entries)
    {
        using var a = new Args();
        var e = a.Pin(entries);
        return UaLib.OutStr(entries.Length + 256, (o, ref n) => Native.scaas_ua_pqz_seal_balance_cache(H, e, (nuint)entries.Length, o, ref n));
    }

    /// <summary>The cache entries of a box (a pinned array: wipe it).</summary>
    public byte[] OpenBalanceCache(string box)
    {
        using var a = new Args();
        var b = a.Str(box);
        return UaLib.SecretOut((o, ref n) => Native.scaas_ua_pqz_open_balance_cache(H, b, o, ref n));
    }
}
