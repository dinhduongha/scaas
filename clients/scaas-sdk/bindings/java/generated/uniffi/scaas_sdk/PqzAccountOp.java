package uniffi.scaas_sdk;

/**
 * `UAPrepareAcc` (`half` 0 or 1 of the materialisation) and `UAPqzRollOver` (`n` pending entries) of `ua`'s account at key
 * version `key_version`.
 */
public class PqzAccountOp {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.lang.String ua;
    private long keyVersion;
    /**
     * `half` for `UAPrepareAcc`, `n` for `UAPqzRollOver`
     */
    private java.lang.String value;
    private Envelope envelope;

    public PqzAccountOp(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.lang.String ua, 
        long keyVersion, 
        java.lang.String value, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.ua = ua;
        
        this.keyVersion = keyVersion;
        
        this.value = value;
        
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
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public long keyVersion() {
        return this.keyVersion;
    }
    
    public java.lang.String value() {
        return this.value;
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
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setKeyVersion(long keyVersion) {
        this.keyVersion = keyVersion;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzAccountOp) {
            PqzAccountOp t = (PqzAccountOp) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(ua, t.ua) && 
              
              keyVersion == t.keyVersion && 
              
              java.util.Objects.equals(value, t.value) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.lang.Long.hashCode(keyVersion);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


