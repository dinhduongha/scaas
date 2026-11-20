package uniffi.scaas_sdk;

/**
 * The app's authenticator (spec §6.10) as a foreign async interface. A PRF output or platform secret is written by the app
 * through the copy calls into the secret whose id it is given (`prf_out`, `out`). A foreign exception arrives as
 * `AuthError::Unexpected`.
 */
public interface ForeignAuthenticator {
    public java.util.concurrent.CompletableFuture<PasskeyCreated> createPasskey(java.lang.String rpId, java.lang.String userName, java.util.List<byte[]> exclude) ;
    public java.util.concurrent.CompletableFuture<Assertion> getAssertion(AssertionRequest req, long prfOut) ;
    
    /**
     * `key_handle`: the platform key's handle (the Rust trait's `handle`; named apart from the generated callbacks' own local
     * `handle`, which uniffi-bindgen-cs and -go do not rename)
     */public java.util.concurrent.CompletableFuture<java.lang.Void> platformSecret(java.lang.String keyHandle, byte[] salt, java.lang.String reason, KeyPolicy policy, long out) ;
    public java.util.concurrent.CompletableFuture<SePublic> p256Generate(KeyPolicy policy) ;
    public java.util.concurrent.CompletableFuture<byte[]> p256Sign(java.lang.String keyHandle, byte[] uaMsg, java.lang.String reason) ;
    
}

