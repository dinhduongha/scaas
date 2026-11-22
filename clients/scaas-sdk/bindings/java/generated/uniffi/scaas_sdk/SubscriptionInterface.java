package uniffi.scaas_sdk;

/**
 * A subscription to the SDK's events (spec §14): a bounded queue, `Lagged { missed }` for a slow reader.
 */
public interface SubscriptionInterface {
    
    /**
     * The next event, or `None` within `timeout_ms`.
     */public java.util.concurrent.CompletableFuture<Event> next(long timeoutMs) ;
    
}

