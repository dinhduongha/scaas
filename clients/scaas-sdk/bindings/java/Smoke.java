// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20e2: the Java binding (spec §16.1) over the async API (CompletableFuture), through uniffi-bindgen-java's
// output (generated/, Java's FFM API). Rows: smartcontracts/vectors/keystore/keystore.json as ../rows.py writes them (args[0]);
// each container is the Java store's `keystore`. Valid rows list their seeds and every seed opens with the rows' passphrase
// (its accounts listed); refused rows fail with their named error. Then: a Java async authenticator's PRF through the copy call
// (passkey unlock), `next` on the subscription, a panic as Internal, a Java exception in the store and in the authenticator
// (Unexpected on the Rust side: the SDK's error, no panic), the load check. Secrets go in only by the copy call. Run by
// ./run.sh (gate `bind-java`).
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import uniffi.scaas_sdk.*;
import uniffi.scaas_sdk_ffi.ScaasSdkFfi;

public final class Smoke {
    static int bad = 0;

    static void check(boolean c, String what) {
        if (!c) {
            System.out.println("FAIL: " + what);
            bad++;
        }
    }

    static final MethodHandle SECRET_WRITE = Linker.nativeLinker().downcallHandle(
            SymbolLookup.libraryLookup(System.getProperty("scaas.lib"), Arena.global())
                    .find("scaas_sdk_secret_write").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    static int write(long id, byte[] b) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(Math.max(1, b.length));
            MemorySegment.copy(b, 0, m, ValueLayout.JAVA_BYTE, 0, b.length);
            int r = (int) SECRET_WRITE.invokeExact(id, m, (long) b.length);
            m.fill((byte) 0);
            return r;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    static SecretBytes secret(String v) throws SdkException {
        byte[] b = v.getBytes(StandardCharsets.UTF_8);
        SecretBytes s = ScaasSdk.secretNew(b.length);
        check(write(ScaasSdk.secretId(s), b) == 0, "copy call");
        return s;
    }

    static String unhex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return new String(b, StandardCharsets.UTF_8);
    }

    /** The SDK's store contract over a map: `putIf` refuses another revision with `Conflict`. */
    static final class MemStore implements ForeignStore {
        final Map<String, byte[]> items = new ConcurrentHashMap<>();
        volatile boolean throwsNow = false;

        public CompletableFuture<StoredItem> get(String name, String reason) {
            if (throwsNow) return CompletableFuture.failedFuture(new IllegalStateException("the app's store threw"));
            byte[] b = items.get(name);
            return CompletableFuture.completedFuture(b == null ? null : new StoredItem(b, ScaasSdk.revOf(b)));
        }

        public synchronized CompletableFuture<Void> putIf(String name, Long prevRev, byte[] bytes, StorePolicy policy) {
            byte[] have = items.get(name);
            Long rev = have == null ? null : ScaasSdk.revOf(have);
            if (rev == null ? prevRev != null : !rev.equals(prevRev))
                return CompletableFuture.failedFuture(new StoreException.Conflict());
            items.put(name, bytes);
            return CompletableFuture.completedFuture(null);
        }

        public CompletableFuture<Void> delete(String name) {
            items.remove(name);
            return CompletableFuture.completedFuture(null);
        }

        // one caller at a time here: no lock to hold
        public CompletableFuture<Long> lock(String name) {
            return CompletableFuture.completedFuture(1L);
        }

        public CompletableFuture<Void> unlock(long token) {
            return CompletableFuture.completedFuture(null);
        }
    }

    /** A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into `prfOut`'s secret. */
    static final class FakeAuth implements ForeignAuthenticator {
        volatile boolean throwsNow = false;

        public CompletableFuture<PasskeyCreated> createPasskey(String rpId, String userName, List<byte[]> exclude) {
            return CompletableFuture.failedFuture(new AuthException.Unavailable());
        }

        public CompletableFuture<Assertion> getAssertion(AssertionRequest req, long prfOut) {
            if (throwsNow) return CompletableFuture.failedFuture(new IllegalStateException("the app's authenticator threw"));
            byte[] salt = req.prfSalt();
            if (salt == null) return CompletableFuture.failedFuture(new AuthException.Refused());
            byte[] out = new byte[32];
            for (int i = 0; i < 32; i++) out[i] = (byte) (salt[i % salt.length] ^ 0x5a ^ i);
            if (write(prfOut, out) != 0) return CompletableFuture.failedFuture(new AuthException.Refused());
            return CompletableFuture.completedFuture(
                    new Assertion(new byte[] {(byte) 0xc1, (byte) 0xed}, new byte[37], new byte[0], new byte[64], true));
        }

        public CompletableFuture<Void> platformSecret(String keyHandle, byte[] salt, String reason, KeyPolicy policy, long out) {
            return CompletableFuture.failedFuture(new AuthException.Unavailable());
        }

        public CompletableFuture<SePublic> p256Generate(KeyPolicy policy) {
            return CompletableFuture.failedFuture(new AuthException.Unavailable());
        }

        public CompletableFuture<byte[]> p256Sign(String keyHandle, byte[] uaMsg, String reason) {
            return CompletableFuture.failedFuture(new AuthException.Unavailable());
        }
    }

    static BindingConfig config() {
        return new BindingConfig(List.of(), "wallet.example", ScaasSdk.limitsDefault(), List.of());
    }

    static Sdk start(MemStore st, FakeAuth auth) throws Exception {
        return ScaasSdk.open(config(), st, auth).get();
    }

    static Sdk over(String text) throws Exception {
        MemStore st = new MemStore();
        st.items.put("keystore", text.getBytes(StandardCharsets.UTF_8));
        return start(st, new FakeAuth());
    }

    interface Call {
        Object run() throws Exception;
    }

    /** The error's code (its message: `Display` is the code), or "Ok". */
    static String failure(Call f) {
        try {
            Object r = f.run();
            if (r instanceof CompletableFuture<?> c) c.join();
            return "Ok";
        } catch (CompletionException | ExecutionException e) {
            return e.getCause() instanceof SdkException s ? s.getMessage() : "not an SdkException: " + e.getCause();
        } catch (SdkException e) {
            return e.getMessage();
        } catch (Exception e) {
            return "not an SdkException: " + e;
        }
    }

    static final String REPO =
            "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
    static final String PASS = "river-otter-7 ünï";

    record Seed(String id, String label, int words, String backup, List<String> accounts) {}

    record Valid(String id, String text, List<Seed> seeds) {}

    static void rows(String path) throws Exception {
        String pass = "";
        List<Valid> valid = new ArrayList<>();
        List<String[]> refused = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(path))) {
            String[] f = line.split("\t", -1);
            switch (f[0]) {
                case "pass" -> pass = unhex(f[1]);
                case "valid" -> valid.add(new Valid(unhex(f[1]), unhex(f[2]), new ArrayList<>()));
                case "seed" -> valid.get(valid.size() - 1).seeds().add(new Seed(f[1], unhex(f[2]), Integer.parseInt(f[3]), f[4],
                        f[5].isEmpty() ? List.of() : Arrays.asList(f[5].split(","))));
                case "refused" -> refused.add(new String[] {unhex(f[1]), f[2], unhex(f[3])});
                default -> {}
            }
        }
        check(valid.size() >= 5 && refused.size() >= 19, "control: rows read");
        int opened = 0;
        for (Valid r : valid) {
            Sdk sdk = over(r.text());
            List<SeedInfo> got = sdk.vault().seeds().get();
            check(got.size() == r.seeds().size(), r.id() + ": " + got.size() + " seeds");
            for (int i = 0; i < Math.min(got.size(), r.seeds().size()); i++) {
                SeedInfo g = got.get(i);
                Seed w = r.seeds().get(i);
                check(g.id().equals(w.id()) && g.label().equals(w.label()) && g.words() == w.words()
                        && g.backup().equals(w.backup()) && !g.unlocked(), r.id() + ": seed " + w.id());
            }
            for (Seed w : r.seeds()) {
                sdk.vault().unlock(w.id(), new Unlock.Passphrase(secret(pass))).get();
                check(sdk.vault().seed(w.id()).get().unlocked(), r.id() + " " + w.id() + " unlocked");
                List<String> ids = sdk.account().accounts(w.id()).get().stream().map(AccountInfo::id).toList();
                check(ids.equals(w.accounts()), r.id() + " " + w.id() + " accounts");
                opened++;
            }
            if (!r.seeds().isEmpty()) {
                String first = r.seeds().get(0).id();
                sdk.vault().lock(first).get();
                String e = failure(() -> sdk.vault().unlock(first, new Unlock.Passphrase(secret("not the one 9"))));
                check(e.equals("VaultOpen"), r.id() + ": a wrong passphrase is " + e);
            }
        }
        check(opened >= 5, "control: seeds were opened (" + opened + ")");
        System.out.println("ok rows: " + valid.size() + " valid (" + opened + " seeds opened)");
        for (String[] r : refused) {
            String e = failure(() -> over(r[2]).vault().seeds());
            check(e.equals(r[1]), r[0] + ": " + e + ", want " + r[1]);
        }
        System.out.println("ok rows: " + refused.size() + " refused by name");
    }

    public static void main(String[] args) {
        try {
            smoke(args);
        } catch (Exception e) {
            check(false, "unexpected exception: " + (e.getCause() != null ? e.getCause() : e));
        }
        System.out.println(bad == 0 ? "RESULT java: PASS (0 failures)" : "RESULT java: FAIL (" + bad + " failures)");
        System.exit(bad == 0 ? 0 : 1);
    }

    static void smoke(String[] args) throws Exception {
        check(ScaasSdk.apiVersion() == 1, "load check: apiVersion " + ScaasSdk.apiVersion());
        rows(args[0]);

        MemStore st = new MemStore();
        FakeAuth auth = new FakeAuth();
        Sdk sdk = start(st, auth);
        Subscription sub = sdk.subscribe();
        check(sub.next(50).get() == null, "next: nothing yet");
        String id = sdk.vault().importWords(new ImportWords("Main", secret(REPO), secret(PASS))).get().id();
        boolean changed = false;
        for (Event ev; (ev = sub.next(200).get()) != null; ) changed |= ev instanceof Event.KeystoreChanged;
        check(changed, "next: KeystoreChanged");

        // the PRF return: a Java authenticator writes it by the copy call; the passkey unlock opens the seed with it
        sdk.vault().enablePasskeyUnlock(id, secret(PASS)).get();
        sdk.vault().lock(id).get();
        sdk.vault().unlock(id, new Unlock.Passkey()).get();
        check(sdk.vault().seed(id).get().unlocked(), "passkey unlock by the PRF");
        System.out.println("ok Java store and authenticator: import, PRF by the copy call, passkey unlock, next");

        // a Java exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
        sdk.vault().lock(id).get();
        auth.throwsNow = true;
        String ea = failure(() -> sdk.vault().unlock(id, new Unlock.Passkey()));
        check(!ea.equals("Ok") && !ea.equals("Internal"), "authenticator exception: " + ea);
        auth.throwsNow = false;
        // a Java exception in the store: Unexpected, the store's failure (VaultIo)
        st.throwsNow = true;
        String es = failure(() -> sdk.vault().seeds());
        check(es.equals("VaultIo"), "store exception: " + es);
        st.throwsNow = false;
        check(sdk.vault().seeds().get().size() == 1, "control: the store again");
        System.out.println("ok Java exceptions: authenticator " + ea + ", store " + es);

        // a panic inside a call (the reference library's hook): Internal, the SDK goes on
        String ep = failure(() -> ScaasSdkFfi.panicInCall(sdk));
        check(ep.equals("Internal"), "panic: " + ep);
        check(sdk.vault().seeds().get().size() == 1, "control: after the panic");
        System.out.println("ok panic " + ep);
    }
}
