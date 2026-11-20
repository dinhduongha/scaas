package uniffi.scaas_sdk;

/**
 * `pqz_wrap_shield` (`WrapShield` on a PQZ token): wrap `amount_in` of `underlying` and shield it to `to_ua`.
 */
public class PqzWrapShield {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.lang.String underlying;
    private java.lang.String amountIn;
    private java.lang.String toUa;
    private Envelope envelope;

    public PqzWrapShield(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.lang.String underlying, 
        java.lang.String amountIn, 
        java.lang.String toUa, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.underlying = underlying;
        
        this.amountIn = amountIn;
        
        this.toUa = toUa;
        
        this.envelope = envelope;
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
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String underlying() {
        return this.underlying;
    }
    
    public java.lang.String amountIn() {
        return this.amountIn;
    }
    
    public java.lang.String toUa() {
        return this.toUa;
    }
    
    public Envelope envelope() {
        return this.envelope;
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
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setUnderlying(java.lang.String underlying) {
        this.underlying = underlying;
    }
    public void setAmountIn(java.lang.String amountIn) {
        this.amountIn = amountIn;
    }
    public void setToUa(java.lang.String toUa) {
        this.toUa = toUa;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzWrapShield) {
            PqzWrapShield t = (PqzWrapShield) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(underlying, t.underlying) && 
              
              java.util.Objects.equals(amountIn, t.amountIn) && 
              
              java.util.Objects.equals(toUa, t.toUa) && 
              
              java.util.Objects.equals(envelope, t.envelope)
              
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
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(underlying);
        result = 31 * result + java.util.Objects.hashCode(amountIn);
        result = 31 * result + java.util.Objects.hashCode(toUa);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


