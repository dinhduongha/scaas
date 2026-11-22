package uniffi.scaas_sdk;

/**
 * The payment a payee fee co-signs (the contract's shape: fee none, relayer bound).
 */
public class Payment {
    private java.lang.String from;
    private java.lang.String to;
    private java.lang.String value;
    private long validUntil;
    private java.lang.String relayer;

    public Payment(
        java.lang.String from, 
        java.lang.String to, 
        java.lang.String value, 
        long validUntil, 
        java.lang.String relayer
    ) {
        
        this.from = from;
        
        this.to = to;
        
        this.value = value;
        
        this.validUntil = validUntil;
        
        this.relayer = relayer;
    }
    
    public java.lang.String from() {
        return this.from;
    }
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public long validUntil() {
        return this.validUntil;
    }
    
    public java.lang.String relayer() {
        return this.relayer;
    }
    public void setFrom(java.lang.String from) {
        this.from = from;
    }
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }
    public void setRelayer(java.lang.String relayer) {
        this.relayer = relayer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Payment) {
            Payment t = (Payment) other;
            return (
              java.util.Objects.equals(from, t.from) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              validUntil == t.validUntil && 
              
              java.util.Objects.equals(relayer, t.relayer)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(from);
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        return result;
    }

    
    
    

}


