package uniffi.scaas_sdk;

/**
 * The part every `SmartKeyAccount` entry shares: the account (`0x` + 40 hex), the key of it that signs, the lane, the envelope.
 * `key_index` (decimal) is the signer's index in the account; `None`: read from the account (S3).
 */
public class SmartOp {
    private KeyRef signer;
    private java.lang.String keyIndex;
    private java.lang.String chain;
    private java.lang.String account;
    private java.lang.String batch;
    private Envelope envelope;

    public SmartOp(
        KeyRef signer, 
        java.lang.String keyIndex, 
        java.lang.String chain, 
        java.lang.String account, 
        java.lang.String batch, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.keyIndex = keyIndex;
        
        this.chain = chain;
        
        this.account = account;
        
        this.batch = batch;
        
        this.envelope = envelope;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String keyIndex() {
        return this.keyIndex;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String account() {
        return this.account;
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
    public void setKeyIndex(java.lang.String keyIndex) {
        this.keyIndex = keyIndex;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setAccount(java.lang.String account) {
        this.account = account;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SmartOp) {
            SmartOp t = (SmartOp) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(keyIndex, t.keyIndex) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(account, t.account) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(keyIndex);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(account);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


