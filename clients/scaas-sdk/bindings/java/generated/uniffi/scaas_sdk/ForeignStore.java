package uniffi.scaas_sdk;

/**
 * The app's store (spec §6.9) as a foreign async interface: `lock` answers a token that `unlock` releases when the SDK drops
 * the lock. A foreign exception arrives as `StoreError::Unexpected`.
 */
public interface ForeignStore {
    public java.util.concurrent.CompletableFuture<StoredItem> get(java.lang.String name, java.lang.String reason) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> putIf(java.lang.String name, java.lang.Long prevRev, byte[] bytes, StorePolicy policy) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> delete(java.lang.String name) ;
    public java.util.concurrent.CompletableFuture<java.lang.Long> lock(java.lang.String name) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(long token);
    
}

