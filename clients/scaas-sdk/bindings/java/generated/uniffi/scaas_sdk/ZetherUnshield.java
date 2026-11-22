package uniffi.scaas_sdk;

/**
 * `UAZetherUnshield`: `amount` out of the holder's Zether account to `recipient` (a 32-byte id).
 */
public class ZetherUnshield {
    private java.lang.String seed;
    private int account;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.lang.String recipient;
    private java.lang.String amount;
    private long validUntilBlock;
    private Envelope envelope;
    private java.lang.Integer tableBits;
    private java.lang.Integer boundBits;

    public ZetherUnshield(
        java.lang.String seed, 
        int account, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.lang.String recipient, 
        java.lang.String amount, 
        long validUntilBlock, 
        Envelope envelope, 
        java.lang.Integer tableBits, 
        java.lang.Integer boundBits
    ) {
        
        this.seed = seed;
        
        this.account = account;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.recipient = recipient;
        
        this.amount = amount;
        
        this.validUntilBlock = validUntilBlock;
        
        this.envelope = envelope;
        
        this.tableBits = tableBits;
        
        this.boundBits = boundBits;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public int account() {
        return this.account;
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
    
    public java.lang.Integer tableBits() {
        return this.tableBits;
    }
    
    public java.lang.Integer boundBits() {
        return this.boundBits;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setAccount(int account) {
        this.account = account;
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
    public void setTableBits(java.lang.Integer tableBits) {
        this.tableBits = tableBits;
    }
    public void setBoundBits(java.lang.Integer boundBits) {
        this.boundBits = boundBits;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherUnshield) {
            ZetherUnshield t = (ZetherUnshield) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              account == t.account && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(recipient, t.recipient) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              validUntilBlock == t.validUntilBlock && 
              
              java.util.Objects.equals(envelope, t.envelope) && 
              
              java.util.Objects.equals(tableBits, t.tableBits) && 
              
              java.util.Objects.equals(boundBits, t.boundBits)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.lang.Integer.hashCode(account);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(recipient);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        result = 31 * result + java.util.Objects.hashCode(tableBits);
        result = 31 * result + java.util.Objects.hashCode(boundBits);
        return result;
    }

    
    
    

}


