package uniffi.scaas_sdk;

/**
 * A signed order: its hash, the order as signed (named-field JSON) and its signature (a `UASig` JSON for a 32-byte `from`,
 * else `0x` hex).
 */
public class SignedOrder {
    private java.lang.String orderHash;
    private java.lang.String order;
    private java.lang.String signature;

    public SignedOrder(
        java.lang.String orderHash, 
        java.lang.String order, 
        java.lang.String signature
    ) {
        
        this.orderHash = orderHash;
        
        this.order = order;
        
        this.signature = signature;
    }
    
    public java.lang.String orderHash() {
        return this.orderHash;
    }
    
    public java.lang.String order() {
        return this.order;
    }
    
    public java.lang.String signature() {
        return this.signature;
    }
    public void setOrderHash(java.lang.String orderHash) {
        this.orderHash = orderHash;
    }
    public void setOrder(java.lang.String order) {
        this.order = order;
    }
    public void setSignature(java.lang.String signature) {
        this.signature = signature;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SignedOrder) {
            SignedOrder t = (SignedOrder) other;
            return (
              java.util.Objects.equals(orderHash, t.orderHash) && 
              
              java.util.Objects.equals(order, t.order) && 
              
              java.util.Objects.equals(signature, t.signature)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(orderHash);
        result = 31 * result + java.util.Objects.hashCode(order);
        result = 31 * result + java.util.Objects.hashCode(signature);
        return result;
    }

    
    
    

}


