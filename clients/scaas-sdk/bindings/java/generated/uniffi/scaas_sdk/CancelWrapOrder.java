package uniffi.scaas_sdk;

/**
 * The cancel of one wrap order (`CancelUAWrapOrder` on the underlying `token`).
 */
public class CancelWrapOrder {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private WrapOrderTerms order;

    public CancelWrapOrder(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        WrapOrderTerms order
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.order = order;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public WrapOrderTerms order() {
        return this.order;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setOrder(WrapOrderTerms order) {
        this.order = order;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof CancelWrapOrder) {
            CancelWrapOrder t = (CancelWrapOrder) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(order);
        return result;
    }

    
    
    

}


