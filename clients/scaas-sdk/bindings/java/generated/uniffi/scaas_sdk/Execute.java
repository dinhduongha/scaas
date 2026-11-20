package uniffi.scaas_sdk;

/**
 * `UAExecute` on a mandate wallet: the owner's call, decoded only.
 */
public class Execute {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String wallet;
    private ExecuteCall call;
    private java.lang.String batch;
    private Envelope envelope;

    public Execute(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String wallet, 
        ExecuteCall call, 
        java.lang.String batch, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.wallet = wallet;
        
        this.call = call;
        
        this.batch = batch;
        
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
    
    public ExecuteCall call() {
        return this.call;
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
    public void setWallet(java.lang.String wallet) {
        this.wallet = wallet;
    }
    public void setCall(ExecuteCall call) {
        this.call = call;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Execute) {
            Execute t = (Execute) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(wallet, t.wallet) && 
              
              java.util.Objects.equals(call, t.call) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(wallet);
        result = 31 * result + java.util.Objects.hashCode(call);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


