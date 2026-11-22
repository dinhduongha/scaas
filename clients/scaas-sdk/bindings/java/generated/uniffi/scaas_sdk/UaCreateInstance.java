package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACreateInstance
 */
public class UaCreateInstance {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.lang.String contractClass;
    private java.lang.String kind;
    private java.lang.String version;
    private java.lang.String salt;
    private java.lang.String initCall;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaCreateInstance(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.lang.String contractClass, 
        java.lang.String kind, 
        java.lang.String version, 
        java.lang.String salt, 
        java.lang.String initCall, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.contractClass = contractClass;
        
        this.kind = kind;
        
        this.version = version;
        
        this.salt = salt;
        
        this.initCall = initCall;
        
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
    
    public java.lang.String version() {
        return this.version;
    }
    
    public java.lang.String salt() {
        return this.salt;
    }
    
    public java.lang.String initCall() {
        return this.initCall;
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
    public void setVersion(java.lang.String version) {
        this.version = version;
    }
    public void setSalt(java.lang.String salt) {
        this.salt = salt;
    }
    public void setInitCall(java.lang.String initCall) {
        this.initCall = initCall;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaCreateInstance) {
            UaCreateInstance t = (UaCreateInstance) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(contractClass, t.contractClass) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              java.util.Objects.equals(version, t.version) && 
              
              java.util.Objects.equals(salt, t.salt) && 
              
              java.util.Objects.equals(initCall, t.initCall) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(version);
        result = 31 * result + java.util.Objects.hashCode(salt);
        result = 31 * result + java.util.Objects.hashCode(initCall);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


