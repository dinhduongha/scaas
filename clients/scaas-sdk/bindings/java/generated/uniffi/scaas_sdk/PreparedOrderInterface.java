package uniffi.scaas_sdk;

/**
 * An order prepared (a trade order or a liquidity order): opaque, holding nothing signed.
 */
public interface PreparedOrderInterface {
    public java.lang.String chain();
    
    /**
     * The order's hash (its typed digest).
     */public java.lang.String id();
    public java.util.List<ReviewField> review();
    public KeyRef signer();
    
}

