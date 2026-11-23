package uniffi.scaas_sdk;

/**
 * Seeds (spec §6).
 */
public interface VaultInterface {
    public java.util.concurrent.CompletableFuture<java.lang.Void> acceptRollback() ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> changePassphrase(java.lang.String seed, SecretBytes old, SecretBytes _new) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> confirmBackup(java.lang.String seed) ;
    public java.util.concurrent.CompletableFuture<NewSeed> deriveChild(DeriveChild req) ;
    public java.util.concurrent.CompletableFuture<NewSeed> deriveFromKey(DeriveFromKey req) ;
    public java.util.concurrent.CompletableFuture<NewSeed> deriveFromSignature(DeriveFromSignature req) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> disablePrfUnlock(java.lang.String seed) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> enablePasskeyUnlock(java.lang.String seed, SecretBytes vaultPassphrase) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> enablePlatformUnlock(java.lang.String seed, SecretBytes vaultPassphrase, KeyPolicy policy) ;
    public java.util.concurrent.CompletableFuture<NewSeed> generate(Generate req) ;
    public java.util.concurrent.CompletableFuture<ImportedKey> importKey(ImportKey req) ;
    public java.util.concurrent.CompletableFuture<SeedInfo> importWords(ImportWords req) ;
    
    /**
     * Root (c)'s typed data for the account `account_hex` and set `set` (spec §6.6).
     */public java.lang.String keyDerivationTypedData(java.lang.String accountHex, int set) throws SdkException;
    public java.util.concurrent.CompletableFuture<java.lang.Boolean> keystoreRollback() ;
    
    /**
     * Locks `seed`: the ids of the hidden sets abandoned with it. A failed call is its error (`Internal`), never an empty
     * answer: the seed is then not known locked.
     */public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lock(java.lang.String seed) ;
    
    /**
     * Locks every seed (a failed call is its error, as `lock`).
     */public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lockAll() ;
    
    /**
     * The memory protection of an unlocked seed's arena.
     */public MemoryProtection memoryProtection(java.lang.String seed) throws SdkException;
    public java.util.concurrent.CompletableFuture<SessionSet> openHidden(java.lang.String seed, Unlock unlock, SecretBytes bip39Passphrase) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> remove(Remove req) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> rename(java.lang.String seed, java.lang.String label) ;
    public java.util.concurrent.CompletableFuture<SeedInfo> seed(java.lang.String seed) ;
    public java.util.concurrent.CompletableFuture<java.util.List<SeedInfo>> seeds() ;
    
    /**
     * A 65-byte signature from its compact form (a secret in, a secret out).
     */public SecretBytes signatureFromCompact(SecretBytes sig) throws SdkException;
    public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(java.lang.String seed, Unlock unlock) ;
    
    /**
     * Whether a word (a secret) is on the BIP-39 list.
     */public boolean wordInList(SecretBytes word);
    
}

