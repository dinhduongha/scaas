package uniffi.scaas_sdk;

public class SetPayee {
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
    private java.lang.String payee;
    private boolean allowed;
    private Envelope envelope;

    public SetPayee(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String contract, 
        java.lang.String batch, 
        java.lang.String token, 
        java.lang.String payee, 
        boolean allowed, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.contract = contract;
        
        this.batch = batch;
        
        this.token = token;
        
        this.payee = payee;
        
        this.allowed = allowed;
        
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
    
    public java.lang.String payee() {
        return this.payee;
    }
    
    public boolean allowed() {
        return this.allowed;
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
    public void setPayee(java.lang.String payee) {
        this.payee = payee;
    }
    public void setAllowed(boolean allowed) {
        this.allowed = allowed;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SetPayee) {
            SetPayee t = (SetPayee) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(contract, t.contract) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(payee, t.payee) && 
              
              allowed == t.allowed && 
              
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
        result = 31 * result + java.util.Objects.hashCode(payee);
        result = 31 * result + java.lang.Boolean.hashCode(allowed);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


