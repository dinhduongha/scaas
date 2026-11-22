package uniffi.scaas_sdk;

/**
 * `pqz_shield` (`UAShield` on a PQZ token): `amount` of the signer's public balance into `to_ua`'s pending window.
 */
public class PqzShield {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.lang.String toUa;
    private java.lang.String amount;
    private Envelope envelope;

    public PqzShield(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.lang.String toUa, 
        java.lang.String amount, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.toUa = toUa;
        
        this.amount = amount;
        
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
    
    public java.lang.String toUa() {
        return this.toUa;
    }
    
    public java.lang.String amount() {
        return this.amount;
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
    public void setToUa(java.lang.String toUa) {
        this.toUa = toUa;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzShield) {
            PqzShield t = (PqzShield) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(toUa, t.toUa) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(toUa);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


