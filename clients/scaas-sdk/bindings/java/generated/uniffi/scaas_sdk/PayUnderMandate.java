package uniffi.scaas_sdk;

/**
 * `UAPayUnderMandate`: the delegate's payment from the mandate wallet, its `entryRef` `metaPayId(meta)`.
 */
public class PayUnderMandate {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String wallet;
    private java.lang.String token;
    private java.lang.String payee;
    private java.lang.String amount;
    private java.lang.String epoch;
    private java.lang.String batch;
    private PayMeta meta;
    private Envelope envelope;

    public PayUnderMandate(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String wallet, 
        java.lang.String token, 
        java.lang.String payee, 
        java.lang.String amount, 
        java.lang.String epoch, 
        java.lang.String batch, 
        PayMeta meta, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.wallet = wallet;
        
        this.token = token;
        
        this.payee = payee;
        
        this.amount = amount;
        
        this.epoch = epoch;
        
        this.batch = batch;
        
        this.meta = meta;
        
        this.envelope = envelope;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String wallet() {
        return this.wallet;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public java.lang.String payee() {
        return this.payee;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public java.lang.String epoch() {
        return this.epoch;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public PayMeta meta() {
        return this.meta;
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
    public void setWallet(java.lang.String wallet) {
        this.wallet = wallet;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setPayee(java.lang.String payee) {
        this.payee = payee;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setEpoch(java.lang.String epoch) {
        this.epoch = epoch;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setMeta(PayMeta meta) {
        this.meta = meta;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PayUnderMandate) {
            PayUnderMandate t = (PayUnderMandate) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(wallet, t.wallet) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(payee, t.payee) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(epoch, t.epoch) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(meta, t.meta) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(wallet);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(payee);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(epoch);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(meta);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


