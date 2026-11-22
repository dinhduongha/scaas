package uniffi.scaas_sdk;

/**
 * The cancel of one order (`CancelUAOrder` on its SCaaS sell token, `CancelDexOrder` on the DEX for an outside token's).
 */
public class CancelOrder {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String sellToken;
    private OrderTerms order;

    public CancelOrder(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String sellToken, 
        OrderTerms order
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.sellToken = sellToken;
        
        this.order = order;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String sellToken() {
        return this.sellToken;
    }
    
    public OrderTerms order() {
        return this.order;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setSellToken(java.lang.String sellToken) {
        this.sellToken = sellToken;
    }
    public void setOrder(OrderTerms order) {
        this.order = order;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof CancelOrder) {
            CancelOrder t = (CancelOrder) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(sellToken, t.sellToken) && 
              
              java.util.Objects.equals(order, t.order)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(sellToken);
        result = 31 * result + java.util.Objects.hashCode(order);
        return result;
    }

    
    
    

}


