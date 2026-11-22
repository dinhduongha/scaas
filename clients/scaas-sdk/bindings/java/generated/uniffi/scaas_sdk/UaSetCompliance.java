package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetCompliance
 */
public class UaSetCompliance {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.util.List<java.lang.String> accounts;
    private java.util.List<java.lang.String> flags;
    private java.util.List<java.lang.String> until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaSetCompliance(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.util.List<java.lang.String> accounts, 
        java.util.List<java.lang.String> flags, 
        java.util.List<java.lang.String> until, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.accounts = accounts;
        
        this.flags = flags;
        
        this.until = until;
        
        this.chainUid = chainUid;
        
        this.envelope = envelope;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String target() {
        return this.target;
    }
    
    public java.util.List<java.lang.String> accounts() {
        return this.accounts;
    }
    
    public java.util.List<java.lang.String> flags() {
        return this.flags;
    }
    
    public java.util.List<java.lang.String> until() {
        return this.until;
    }
    
    public java.lang.String chainUid() {
        return this.chainUid;
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
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setTarget(java.lang.String target) {
        this.target = target;
    }
    public void setAccounts(java.util.List<java.lang.String> accounts) {
        this.accounts = accounts;
    }
    public void setFlags(java.util.List<java.lang.String> flags) {
        this.flags = flags;
    }
    public void setUntil(java.util.List<java.lang.String> until) {
        this.until = until;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaSetCompliance) {
            UaSetCompliance t = (UaSetCompliance) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(accounts, t.accounts) && 
              
              java.util.Objects.equals(flags, t.flags) && 
              
              java.util.Objects.equals(until, t.until) && 
              
              java.util.Objects.equals(chainUid, t.chainUid) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(target);
        result = 31 * result + java.util.Objects.hashCode(accounts);
        result = 31 * result + java.util.Objects.hashCode(flags);
        result = 31 * result + java.util.Objects.hashCode(until);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


