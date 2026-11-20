package uniffi.scaas_sdk;

/**
 * `UAPqzUnshield`: `amount` out of the holder's account to `recipient` (a 32-byte id: a padded address or a registered UA).
 */
public class PqzUnshield {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private long keyVersion;
    private java.lang.String recipient;
    private java.lang.String amount;
    private long validUntilBlock;
    private Envelope envelope;

    public PqzUnshield(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        long keyVersion, 
        java.lang.String recipient, 
        java.lang.String amount, 
        long validUntilBlock, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.keyVersion = keyVersion;
        
        this.recipient = recipient;
        
        this.amount = amount;
        
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
    
    public java.lang.String recipient() {
        return this.recipient;
    }
    
    public java.lang.String amount() {
        return this.amount;
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
    public void setRecipient(java.lang.String recipient) {
        this.recipient = recipient;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzUnshield) {
            PqzUnshield t = (PqzUnshield) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              keyVersion == t.keyVersion && 
              
              java.util.Objects.equals(recipient, t.recipient) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(recipient);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


