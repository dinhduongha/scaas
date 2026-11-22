package uniffi.scaas_sdk;

/**
 * `UAPqzUnshieldUnwrap` (`WRAPPED_PQZ`): `amount` out, unwrapped by leg `underlying` to `recipient`, at least `min_out`.
 */
public class PqzUnshieldUnwrap {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private long keyVersion;
    private java.lang.String underlying;
    private java.lang.String recipient;
    private java.lang.String amount;
    private java.lang.String minOut;
    private long validUntilBlock;
    private Envelope envelope;

    public PqzUnshieldUnwrap(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        long keyVersion, 
        java.lang.String underlying, 
        java.lang.String recipient, 
        java.lang.String amount, 
        java.lang.String minOut, 
        long validUntilBlock, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.keyVersion = keyVersion;
        
        this.underlying = underlying;
        
        this.recipient = recipient;
        
        this.amount = amount;
        
        this.minOut = minOut;
        
        this.validUntilBlock = validUntilBlock;
        
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
    
    public long keyVersion() {
        return this.keyVersion;
    }
    
    public java.lang.String underlying() {
        return this.underlying;
    }
    
    public java.lang.String recipient() {
        return this.recipient;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public java.lang.String minOut() {
        return this.minOut;
    }
    
    public long validUntilBlock() {
        return this.validUntilBlock;
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
    public void setKeyVersion(long keyVersion) {
        this.keyVersion = keyVersion;
    }
    public void setUnderlying(java.lang.String underlying) {
        this.underlying = underlying;
    }
    public void setRecipient(java.lang.String recipient) {
        this.recipient = recipient;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setMinOut(java.lang.String minOut) {
        this.minOut = minOut;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzUnshieldUnwrap) {
            PqzUnshieldUnwrap t = (PqzUnshieldUnwrap) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              keyVersion == t.keyVersion && 
              
              java.util.Objects.equals(underlying, t.underlying) && 
              
              java.util.Objects.equals(recipient, t.recipient) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(minOut, t.minOut) && 
              
              validUntilBlock == t.validUntilBlock && 
              
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
        result = 31 * result + java.lang.Long.hashCode(keyVersion);
        result = 31 * result + java.util.Objects.hashCode(underlying);
        result = 31 * result + java.util.Objects.hashCode(recipient);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(minOut);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


