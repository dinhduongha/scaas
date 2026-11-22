package uniffi.scaas_sdk;

/**
 * The transfer on ids (`UAMetaTransfer`, entry `mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6): a plain
 * transfer, `entryRef = 0` on the lane `batch` the caller names, its nonce read, signed under `Expect::Transfer` (owner
 * 2026-11-19, ruling D): not recorded on chain as a payment, and a retry of the same request reads the same lane nonce.
 */
public class Transfer {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    /**
     * the receiver's 32-byte id (a native address zero-padded, or a UA)
     */
    private java.lang.String to;
    private java.lang.String value;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private Envelope envelope;

    public Transfer(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String to, 
        java.lang.String value, 
        java.lang.String batch, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.to = to;
        
        this.value = value;
        
        this.batch = batch;
        
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
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public java.lang.String batch() {
        return this.batch;
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
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Transfer) {
            Transfer t = (Transfer) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


