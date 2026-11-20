package uniffi.scaas_sdk;

public class UnwrapToUa {
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
    private java.lang.String underlying;
    private java.lang.String wrapped;
    private java.lang.String to;
    private java.lang.String minOut;
    private Envelope envelope;

    public UnwrapToUa(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String contract, 
        java.lang.String batch, 
        java.lang.String underlying, 
        java.lang.String wrapped, 
        java.lang.String to, 
        java.lang.String minOut, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.contract = contract;
        
        this.batch = batch;
        
        this.underlying = underlying;
        
        this.wrapped = wrapped;
        
        this.to = to;
        
        this.minOut = minOut;
        
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
    
    public java.lang.String underlying() {
        return this.underlying;
    }
    
    public java.lang.String wrapped() {
        return this.wrapped;
    }
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String minOut() {
        return this.minOut;
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
    public void setUnderlying(java.lang.String underlying) {
        this.underlying = underlying;
    }
    public void setWrapped(java.lang.String wrapped) {
        this.wrapped = wrapped;
    }
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setMinOut(java.lang.String minOut) {
        this.minOut = minOut;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UnwrapToUa) {
            UnwrapToUa t = (UnwrapToUa) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(contract, t.contract) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(underlying, t.underlying) && 
              
              java.util.Objects.equals(wrapped, t.wrapped) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(minOut, t.minOut) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(underlying);
        result = 31 * result + java.util.Objects.hashCode(wrapped);
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(minOut);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


