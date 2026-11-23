// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20c: the C# binding (spec §16.1) over the async API, through uniffi-bindgen-cs's output. Rows:
// smartcontracts/vectors/keystore/keystore.json, each container the C# store's `keystore`: valid rows list their seeds and every
// seed opens with the rows' passphrase (its accounts listed); refused rows fail with their named error. Then: a C# async
// authenticator's PRF through the copy call (passkey unlock), `Next` on the subscription, a panic as Internal, a C# exception in
// the store and in the authenticator (Unexpected on the Rust side: the SDK's error, no panic), the load check. Secrets go in
// only by the copy call.
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using uniffi.scaas_sdk;
using uniffi.scaas_sdk_ffi;
using Xunit;

namespace Scaas.Sdk.Smoke;

static class Native
{
    /// <summary>A secret holding `v`, by the copy call (its buffer zeroed by it; asserted).</summary>
    public static SecretBytes Secret(string v)
    {
        var b = Encoding.UTF8.GetBytes(v);
        var s = ScaasSdkMethods.SecretNew((uint)b.Length);
        if (!Scaas.Sdk.CopyCall.Write(ScaasSdkMethods.SecretId(s), b))
            throw new InvalidOperationException("copy call");
        Assert.True(b.All(x => x == 0), "the copy call zeroes the caller's buffer");
        return s;
    }
}

class MemStore : ForeignStore
{
    public readonly ConcurrentDictionary<string, byte[]> Items = new();
    public volatile bool Throws;
    readonly object m = new();

    public Task<StoredItem?> Get(string name, string reason)
    {
        if (Throws)
            throw new InvalidOperationException("the app's store threw");
        return Task.FromResult(Items.TryGetValue(name, out var b) ? new StoredItem(b, ScaasSdkMethods.RevOf(b)) : null);
    }

    public Task PutIf(string name, ulong? prevRev, byte[] bytes, StorePolicy policy)
    {
        lock (m)
        {
            ulong? have = Items.TryGetValue(name, out var b) ? ScaasSdkMethods.RevOf(b) : null;
            if (have != prevRev)
                throw new StoreException.Conflict();
            Items[name] = bytes;
        }
        return Task.CompletedTask;
    }

    public Task Delete(string name)
    {
        Items.TryRemove(name, out _);
        return Task.CompletedTask;
    }

    // one caller at a time here: no lock to hold
    public Task<ulong> Lock(string name) => Task.FromResult(1UL);

    public Task Unlock(ulong token) => Task.CompletedTask;
}

// A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into the secret `prfOut` names.
class FakeAuth : ForeignAuthenticator
{
    public volatile bool Throws;

    public Task<PasskeyCreated> CreatePasskey(string rpId, string userName, byte[][] exclude) =>
        throw new AuthException.Unavailable();

    public async Task<Assertion> GetAssertion(AssertionRequest req, ulong prfOut)
    {
        await Task.Yield();
        if (Throws)
            throw new InvalidOperationException("the app's authenticator threw");
        if (req.PrfSalt is not { } salt)
            throw new AuthException.Refused();
        var o = new byte[32];
        for (var i = 0; i < 32; i++)
            o[i] = (byte)(salt[i % salt.Length] ^ 0x5a ^ i);
        if (!Scaas.Sdk.CopyCall.Write(prfOut, o))
            throw new AuthException.Refused();
        return new Assertion([0xc1, 0xed], new byte[37], [], new byte[64], true);
    }

    public Task PlatformSecret(string keyHandle, byte[] salt, string reason, KeyPolicy? policy, ulong @out) =>
        throw new AuthException.Unavailable();

    public Task<SePublic> P256Generate(KeyPolicy policy) => throw new AuthException.Unavailable();

    public Task<byte[]> P256Sign(string keyHandle, byte[] uaMsg, string reason) => throw new AuthException.Unavailable();
}

public class SmokeTests
{
    const string Repo =
        "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
    const string Pass = "river-otter-7 ünï";

    static Task<uniffi.scaas_sdk.Sdk> Open(MemStore st, FakeAuth? auth = null) =>
        ScaasSdkMethods.Open(new BindingConfig(1, ScaasSdkMethods.Features(), [], "wallet.example", ScaasSdkMethods.LimitsDefault(), []), st, auth ?? new FakeAuth());

    static Task<uniffi.scaas_sdk.Sdk> Over(string text)
    {
        var st = new MemStore();
        st.Items["keystore"] = Encoding.UTF8.GetBytes(text);
        return Open(st);
    }

    // the error's code (its text: `Display` is the code), or "Ok"
    static async Task<string> Failure(Func<Task> f)
    {
        try
        {
            await f();
            return "Ok";
        }
        catch (SdkException e)
        {
            return e.Message;
        }
    }

    static JsonElement Rows()
    {
        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "smartcontracts/vectors/keystore/keystore.json")))
            dir = Path.GetDirectoryName(dir) ?? throw new FileNotFoundException("keystore.json");
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "smartcontracts/vectors/keystore/keystore.json"))).RootElement;
    }

    [Fact]
    public async Task LoadCheck()
    {
        Assert.Equal(1u, ScaasSdkMethods.ApiVersion());
        // the opening refuses a library of another api_version or without a needed feature (spec §16.3)
        var limits = ScaasSdkMethods.LimitsDefault();
        Assert.Equal("AbiMismatch", await Failure(() => ScaasSdkMethods.Open(new BindingConfig(2, ScaasSdkMethods.Features(), [], null, limits, []), new MemStore(), null)));
        Assert.Equal("AbiMismatch", await Failure(() => ScaasSdkMethods.Open(new BindingConfig(1, 1UL << 62, [], null, limits, []), new MemStore(), null)));
        // control: this library's
        await ScaasSdkMethods.Open(new BindingConfig(1, ScaasSdkMethods.Features(), [], null, limits, []), new MemStore(), null);
    }

    [Fact]
    public async Task CopyCallsRevealDispose()
    {
        var sdk = await Open(new MemStore());
        var fresh = await sdk.Vault().Generate(new Generate("Fresh", Native.Secret(Pass)));
        var words = fresh.Backup.Reveal();
        var id = ScaasSdkMethods.SecretId(words);
        var text = Scaas.Sdk.CopyCall.Read(id, (int)ScaasSdkMethods.SecretLen(words));
        Assert.NotNull(text);
        Assert.Equal(24, Encoding.UTF8.GetString(text!).Split(' ').Length);
        Array.Clear(text!);
        // review T26 C-5: the read's own buffer is zeroed once the copy is out
        var via = new byte[(int)ScaasSdkMethods.SecretLen(words)];
        var again = Scaas.Sdk.CopyCall.ReadVia(id, via);
        Assert.Equal(24, Encoding.UTF8.GetString(again!).Split(' ').Length);
        Array.Clear(again!);
        Assert.True(via.All(x => x == 0), "the copy call zeroes its read buffer");
        Assert.True(Scaas.Sdk.CopyCall.Dispose(id));
        Assert.Null(Scaas.Sdk.CopyCall.Read(id, 1));
    }

    [Fact]
    public async Task KeystoreRows()
    {
        var d = Rows();
        var pass = d.GetProperty("passphrase").GetString()!;
        int valid = 0, opened = 0, refused = 0;
        foreach (var r in d.GetProperty("valid").EnumerateArray())
        {
            var id = r.GetProperty("id").GetString();
            var text = r.GetProperty("text").GetString()!;
            var want = JsonDocument.Parse(text).RootElement.GetProperty("seeds").EnumerateArray().ToArray();
            var sdk = await Over(text);
            var got = await sdk.Vault().Seeds();
            Assert.True(got.Length == want.Length, $"{id}: {got.Length} seeds");
            for (var i = 0; i < want.Length; i++)
            {
                var w = want[i];
                Assert.Equal(w.GetProperty("id").GetString(), got[i].Id);
                Assert.Equal(w.GetProperty("label").GetString(), got[i].Label);
                Assert.Equal(w.GetProperty("words").GetUInt32(), got[i].Words);
                Assert.Equal(w.GetProperty("backup").GetString(), got[i].Backup);
                Assert.False(got[i].Unlocked);
            }
            foreach (var w in want)
            {
                var seed = w.GetProperty("id").GetString()!;
                await sdk.Vault().Unlock(seed, new Unlock.Passphrase(Native.Secret(pass)));
                Assert.True((await sdk.Vault().Seed(seed)).Unlocked, $"{id} {seed} unlocked");
                var accounts = (await sdk.Account().Accounts(seed)).Select(a => a.Id).ToArray();
                var wantAccounts = w.GetProperty("accounts").EnumerateArray().Select(a => a.GetProperty("id").GetString()).ToArray();
                Assert.Equal(wantAccounts, accounts);
                opened++;
            }
            if (want.Length > 0)
            {
                var first = want[0].GetProperty("id").GetString()!;
                await sdk.Vault().Lock(first);
                var e = await Failure(() => sdk.Vault().Unlock(first, new Unlock.Passphrase(Native.Secret("not the one 9"))));
                Assert.True(e == "VaultOpen", $"{id}: a wrong passphrase is {e}");
            }
            valid++;
        }
        foreach (var r in d.GetProperty("refused").EnumerateArray())
        {
            var id = r.GetProperty("id").GetString();
            var e = await Failure(async () => await (await Over(r.GetProperty("text").GetString()!)).Vault().Seeds());
            Assert.True(e == r.GetProperty("error").GetString(), $"{id}: {e}, want {r.GetProperty("error").GetString()}");
            refused++;
        }
        // control: the rows were read and the seeds opened
        Assert.True(valid >= 5 && opened >= 5 && refused >= 19, $"{valid} valid, {opened} opened, {refused} refused");
    }

    [Fact]
    public async Task StoreAuthenticatorPanicAndExceptions()
    {
        var st = new MemStore();
        var auth = new FakeAuth();
        var sdk = await Open(st, auth);
        var sub = sdk.Subscribe();
        Assert.Null(await sub.Next(50));
        var id = (await sdk.Vault().ImportWords(new ImportWords("Main", Native.Secret(Repo), Native.Secret(Pass)))).Id;
        var changed = false;
        while (await sub.Next(200) is { } ev)
            changed |= ev is Event.KeystoreChanged;
        Assert.True(changed, "Next: KeystoreChanged");

        // the PRF return: a C# authenticator writes it by the copy call; the passkey unlock opens the seed with it
        await sdk.Vault().EnablePasskeyUnlock(id, Native.Secret(Pass));
        await sdk.Vault().Lock(id);
        await sdk.Vault().Unlock(id, new Unlock.Passkey());
        Assert.True((await sdk.Vault().Seed(id)).Unlocked, "passkey unlock by the PRF");

        // a C# exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
        await sdk.Vault().Lock(id);
        auth.Throws = true;
        var ea = await Failure(() => sdk.Vault().Unlock(id, new Unlock.Passkey()));
        Assert.Equal("AuthenticatorRefused", ea);
        auth.Throws = false;
        // a C# exception in the store: Unexpected, the store's failure (VaultIo)
        st.Throws = true;
        Assert.Equal("VaultIo", await Failure(() => sdk.Vault().Seeds()));
        st.Throws = false;
        Assert.Single(await sdk.Vault().Seeds());

        // a panic inside a call (the reference library's hook): Internal, the SDK goes on
        Assert.Equal("Internal", await Failure(() => ScaasSdkFfiMethods.PanicInCall(sdk)));
        Assert.Single(await sdk.Vault().Seeds());
    }
}
