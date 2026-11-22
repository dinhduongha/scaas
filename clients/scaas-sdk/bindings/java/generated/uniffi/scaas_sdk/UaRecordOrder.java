package uniffi.scaas_sdk;

/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARecordOrder
 */
public class UaRecordOrder {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the lane, decimal
     */
    private java.lang.String batch;
    private java.lang.String target;
    private java.lang.String orderId;
    private java.lang.String documentHash;
    private java.lang.String subject;
    private java.lang.String beneficiary;
    private java.lang.String maxAmount;
    private java.lang.String freezeUntil;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    private java.lang.String chainUid;
    private Envelope envelope;

    public UaRecordOrder(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String batch, 
        java.lang.String target, 
        java.lang.String orderId, 
        java.lang.String documentHash, 
        java.lang.String subject, 
        java.lang.String beneficiary, 
        java.lang.String maxAmount, 
        java.lang.String freezeUntil, 
        java.lang.String chainUid, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.batch = batch;
        
        this.target = target;
        
        this.orderId = orderId;
        
        this.documentHash = documentHash;
        
        this.subject = subject;
        
        this.beneficiary = beneficiary;
        
        this.maxAmount = maxAmount;
        
        this.freezeUntil = freezeUntil;
        
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
    
    public java.lang.String orderId() {
        return this.orderId;
    }
    
    public java.lang.String documentHash() {
        return this.documentHash;
    }
    
    public java.lang.String subject() {
        return this.subject;
    }
    
    public java.lang.String beneficiary() {
        return this.beneficiary;
    }
    
    public java.lang.String maxAmount() {
        return this.maxAmount;
    }
    
    public java.lang.String freezeUntil() {
        return this.freezeUntil;
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
    public void setOrderId(java.lang.String orderId) {
        this.orderId = orderId;
    }
    public void setDocumentHash(java.lang.String documentHash) {
        this.documentHash = documentHash;
    }
    public void setSubject(java.lang.String subject) {
        this.subject = subject;
    }
    public void setBeneficiary(java.lang.String beneficiary) {
        this.beneficiary = beneficiary;
    }
    public void setMaxAmount(java.lang.String maxAmount) {
        this.maxAmount = maxAmount;
    }
    public void setFreezeUntil(java.lang.String freezeUntil) {
        this.freezeUntil = freezeUntil;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaRecordOrder) {
            UaRecordOrder t = (UaRecordOrder) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(target, t.target) && 
              
              java.util.Objects.equals(orderId, t.orderId) && 
              
              java.util.Objects.equals(documentHash, t.documentHash) && 
              
              java.util.Objects.equals(subject, t.subject) && 
              
              java.util.Objects.equals(beneficiary, t.beneficiary) && 
              
              java.util.Objects.equals(maxAmount, t.maxAmount) && 
              
              java.util.Objects.equals(freezeUntil, t.freezeUntil) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(orderId);
        result = 31 * result + java.util.Objects.hashCode(documentHash);
        result = 31 * result + java.util.Objects.hashCode(subject);
        result = 31 * result + java.util.Objects.hashCode(beneficiary);
        result = 31 * result + java.util.Objects.hashCode(maxAmount);
        result = 31 * result + java.util.Objects.hashCode(freezeUntil);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


