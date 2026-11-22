package uniffi.scaas_sdk;

/**
 * `accept_membership` (CTR-UA-37): slot `slot` of the `msig` `ua` accepts on `chain`, sent by `payer`.
 */
public class AcceptMembership {
    private java.lang.String chain;
    private java.lang.String ua;
    private MsigSlot slot;
    private KeyRef payer;

    public AcceptMembership(
        java.lang.String chain, 
        java.lang.String ua, 
        MsigSlot slot, 
        KeyRef payer
    ) {
        
        this.chain = chain;
        
        this.ua = ua;
        
        this.slot = slot;
        
        this.payer = payer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public MsigSlot slot() {
        return this.slot;
    }
    
    public KeyRef payer() {
        return this.payer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setSlot(MsigSlot slot) {
        this.slot = slot;
    }
    public void setPayer(KeyRef payer) {
        this.payer = payer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AcceptMembership) {
            AcceptMembership t = (AcceptMembership) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(ua, t.ua) && 
              
              java.util.Objects.equals(slot, t.slot) && 
              
              java.util.Objects.equals(payer, t.payer)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.util.Objects.hashCode(slot);
        result = 31 * result + java.util.Objects.hashCode(payer);
        return result;
    }

    
    
    

}


