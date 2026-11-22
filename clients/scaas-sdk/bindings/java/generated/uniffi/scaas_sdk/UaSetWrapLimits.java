package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetWrapLimits
 */
public class UaSetWrapLimits {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.lang.String legs;
    private boolean netUnwrap;
    private boolean wrapList;
    private boolean unwrapList;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaSetWrapLimits(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.lang.String legs, 
        boolean netUnwrap, 
        boolean wrapList, 
        boolean unwrapList, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.legs = legs;
        
        this.netUnwrap = netUnwrap;
        
        this.wrapList = wrapList;
        
        this.unwrapList = unwrapList;
        
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
    
    public java.lang.String legs() {
        return this.legs;
    }
    
    public boolean netUnwrap() {
        return this.netUnwrap;
    }
    
    public boolean wrapList() {
        return this.wrapList;
    }
    
    public boolean unwrapList() {
        return this.unwrapList;
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
    public void setLegs(java.lang.String legs) {
        this.legs = legs;
    }
    public void setNetUnwrap(boolean netUnwrap) {
        this.netUnwrap = netUnwrap;
    }
    public void setWrapList(boolean wrapList) {
        this.wrapList = wrapList;
    }
    public void setUnwrapList(boolean unwrapList) {
        this.unwrapList = unwrapList;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaSetWrapLimits) {
            UaSetWrapLimits t = (UaSetWrapLimits) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(legs, t.legs) && 
              
              netUnwrap == t.netUnwrap && 
              
              wrapList == t.wrapList && 
              
              unwrapList == t.unwrapList && 
              
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
        result = 31 * result + java.util.Objects.hashCode(legs);
        result = 31 * result + java.lang.Boolean.hashCode(netUnwrap);
        result = 31 * result + java.lang.Boolean.hashCode(wrapList);
        result = 31 * result + java.lang.Boolean.hashCode(unwrapList);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


