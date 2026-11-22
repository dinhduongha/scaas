package uniffi.scaas_sdk;

public class SetMandate {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    private java.lang.String contract;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String token;
    private java.lang.String delegate;
    private java.lang.String maxPerPayment;
    private java.lang.String maxPerPeriod;
    private java.lang.String periodSeconds;
    private java.lang.String expiry;
    private Envelope envelope;

    public SetMandate(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String contract, 
        java.lang.String batch, 
        java.lang.String token, 
        java.lang.String delegate, 
        java.lang.String maxPerPayment, 
        java.lang.String maxPerPeriod, 
        java.lang.String periodSeconds, 
        java.lang.String expiry, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.contract = contract;
        
        this.batch = batch;
        
        this.token = token;
        
        this.delegate = delegate;
        
        this.maxPerPayment = maxPerPayment;
        
        this.maxPerPeriod = maxPerPeriod;
        
        this.periodSeconds = periodSeconds;
        
        this.expiry = expiry;
        
        this.envelope = envelope;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String contract() {
        return this.contract;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public java.lang.String delegate() {
        return this.delegate;
    }
    
    public java.lang.String maxPerPayment() {
        return this.maxPerPayment;
    }
    
    public java.lang.String maxPerPeriod() {
        return this.maxPerPeriod;
    }
    
    public java.lang.String periodSeconds() {
        return this.periodSeconds;
    }
    
    public java.lang.String expiry() {
        return this.expiry;
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
    public void setContract(java.lang.String contract) {
        this.contract = contract;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setDelegate(java.lang.String delegate) {
        this.delegate = delegate;
    }
    public void setMaxPerPayment(java.lang.String maxPerPayment) {
        this.maxPerPayment = maxPerPayment;
    }
    public void setMaxPerPeriod(java.lang.String maxPerPeriod) {
        this.maxPerPeriod = maxPerPeriod;
    }
    public void setPeriodSeconds(java.lang.String periodSeconds) {
        this.periodSeconds = periodSeconds;
    }
    public void setExpiry(java.lang.String expiry) {
        this.expiry = expiry;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SetMandate) {
            SetMandate t = (SetMandate) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(contract, t.contract) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(delegate, t.delegate) && 
              
              java.util.Objects.equals(maxPerPayment, t.maxPerPayment) && 
              
              java.util.Objects.equals(maxPerPeriod, t.maxPerPeriod) && 
              
              java.util.Objects.equals(periodSeconds, t.periodSeconds) && 
              
              java.util.Objects.equals(expiry, t.expiry) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(contract);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(delegate);
        result = 31 * result + java.util.Objects.hashCode(maxPerPayment);
        result = 31 * result + java.util.Objects.hashCode(maxPerPeriod);
        result = 31 * result + java.util.Objects.hashCode(periodSeconds);
        result = 31 * result + java.util.Objects.hashCode(expiry);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


