package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPublishClassEnv
 */
public class UaPublishClassEnv {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.lang.String contractClass;
    private java.lang.String kind;
    private java.lang.String envVersion;
    private java.lang.String env;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaPublishClassEnv(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.lang.String contractClass, 
        java.lang.String kind, 
        java.lang.String envVersion, 
        java.lang.String env, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.contractClass = contractClass;
        
        this.kind = kind;
        
        this.envVersion = envVersion;
        
        this.env = env;
        
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
    
    public java.lang.String contractClass() {
        return this.contractClass;
    }
    
    public java.lang.String kind() {
        return this.kind;
    }
    
    public java.lang.String envVersion() {
        return this.envVersion;
    }
    
    public java.lang.String env() {
        return this.env;
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
    public void setContractClass(java.lang.String contractClass) {
        this.contractClass = contractClass;
    }
    public void setKind(java.lang.String kind) {
        this.kind = kind;
    }
    public void setEnvVersion(java.lang.String envVersion) {
        this.envVersion = envVersion;
    }
    public void setEnv(java.lang.String env) {
        this.env = env;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaPublishClassEnv) {
            UaPublishClassEnv t = (UaPublishClassEnv) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(contractClass, t.contractClass) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              java.util.Objects.equals(envVersion, t.envVersion) && 
              
              java.util.Objects.equals(env, t.env) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(contractClass);
        result = 31 * result + java.util.Objects.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(envVersion);
        result = 31 * result + java.util.Objects.hashCode(env);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


