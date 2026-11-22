package uniffi.scaas_sdk;

/**
 * The SDK (spec §4): the module accessors, events, watching.
 */
public interface SdkInterface {
    
    /**
     * The account module (spec §7).
     */public Account account();
    
    /**
     * The admin module (spec §11).
     */public Admin admin();
    
    /**
     * The confidential module (spec §9).
     */public Confidential confidential();
    
    /**
     * The DEX module (spec §10).
     */public Dex dex();
    
    /**
     * The limits in force.
     */public Limits limits();
    
    /**
     * The operations module (spec §13).
     */public Op op();
    public java.util.concurrent.CompletableFuture<java.lang.Long> stateRev() ;
    
    /**
     * A subscription to the SDK's events (spec §14).
     */public Subscription subscribe();
    
    /**
     * The seed module (spec §6).
     */public Vault vault();
    
    /**
     * The wallet module (spec §8).
     */public Wallet wallet();
    public java.util.concurrent.CompletableFuture<java.lang.Void> watch(java.lang.String account, java.util.List<java.lang.String> chains) ;
    
}

