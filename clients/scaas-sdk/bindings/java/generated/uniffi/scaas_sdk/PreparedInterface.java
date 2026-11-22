package uniffi.scaas_sdk;

/**
 * A prepared operation (spec §13.1): opaque, kept in the SDK's table; it holds no secret and nothing signed.
 */
public interface PreparedInterface {
    public java.lang.String chain();
    
    /**
     * The contract function: `mtxPay`, `mtxCancelNonce`, …
     */public java.lang.String entry();
    
    /**
     * The operation's `validUntil` (`u64::MAX`: none).
     */public long expiresAt();
    
    /**
     * The typed digest, the node's in-flight key too.
     */public java.lang.String id();
    
    /**
     * An undecoded call under `AllowOpaqueCall` (§13.2).
     */public boolean opaque();
    public java.util.List<ReviewField> review();
    public KeyRef signer();
    
}

