package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAApproveDexRelease
 */
public class UaApproveDexRelease {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.lang.String version;
    private java.lang.String envVersion;
    private java.lang.String initcodeHash;
    private java.lang.String implArgsHash;
    private java.lang.String factory;
    private java.lang.String adminGeneration;
    private java.lang.String until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaApproveDexRelease(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.lang.String version, 
        java.lang.String envVersion, 
        java.lang.String initcodeHash, 
        java.lang.String implArgsHash, 
        java.lang.String factory, 
        java.lang.String adminGeneration, 
        java.lang.String until, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.version = version;
        
        this.envVersion = envVersion;
        
        this.initcodeHash = initcodeHash;
        
        this.implArgsHash = implArgsHash;
        
        this.factory = factory;
        
        this.adminGeneration = adminGeneration;
        
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
    
    public java.lang.String version() {
        return this.version;
    }
    
    public java.lang.String envVersion() {
        return this.envVersion;
    }
    
    public java.lang.String initcodeHash() {
        return this.initcodeHash;
    }
    
    public java.lang.String implArgsHash() {
        return this.implArgsHash;
    }
    
    public java.lang.String factory() {
        return this.factory;
    }
    
    public java.lang.String adminGeneration() {
        return this.adminGeneration;
    }
    
    public java.lang.String until() {
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
    public void setVersion(java.lang.String version) {
        this.version = version;
    }
    public void setEnvVersion(java.lang.String envVersion) {
        this.envVersion = envVersion;
    }
    public void setInitcodeHash(java.lang.String initcodeHash) {
        this.initcodeHash = initcodeHash;
    }
    public void setImplArgsHash(java.lang.String implArgsHash) {
        this.implArgsHash = implArgsHash;
    }
    public void setFactory(java.lang.String factory) {
        this.factory = factory;
    }
    public void setAdminGeneration(java.lang.String adminGeneration) {
        this.adminGeneration = adminGeneration;
    }
    public void setUntil(java.lang.String until) {
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
        if (other instanceof UaApproveDexRelease) {
            UaApproveDexRelease t = (UaApproveDexRelease) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(version, t.version) && 
              
              java.util.Objects.equals(envVersion, t.envVersion) && 
              
              java.util.Objects.equals(initcodeHash, t.initcodeHash) && 
              
              java.util.Objects.equals(implArgsHash, t.implArgsHash) && 
              
              java.util.Objects.equals(factory, t.factory) && 
              
              java.util.Objects.equals(adminGeneration, t.adminGeneration) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(version);
        result = 31 * result + java.util.Objects.hashCode(envVersion);
        result = 31 * result + java.util.Objects.hashCode(initcodeHash);
        result = 31 * result + java.util.Objects.hashCode(implArgsHash);
        result = 31 * result + java.util.Objects.hashCode(factory);
        result = 31 * result + java.util.Objects.hashCode(adminGeneration);
        result = 31 * result + java.util.Objects.hashCode(until);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


