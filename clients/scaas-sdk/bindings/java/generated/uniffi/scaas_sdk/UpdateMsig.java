package uniffi.scaas_sdk;

/**
 * `update_msig` (CTR-UA-44): the `msig` `ua` on `chain`'s registry becomes `structure` (every slot, the stored ones unchanged,
 * new members appended), `enabled` the slots that count, valid to block `valid_until_block`; signed by `slots` of the
 * **stored** structure, sent by `payer`.
 */
public class UpdateMsig {
    private java.lang.String chain;
    private java.lang.String ua;
    private MsigStructureArgs structure;
    private short[] enabled;
    private long validUntilBlock;
    private java.util.List<MsigSlot> slots;
    private KeyRef payer;
    /**
     * the caller's facts for `plan_msig_update` (M4, owner 2026-11-19): a token names this `msig` as its PQZ verifier; the UA is
     * in use on a family with no `msig` update yet. Whether it holds a PQZ key is read (`pqzKeyAt(ua, 0)`).
     */
    private boolean verifier;
    private boolean familyWithoutUpdate;

    public UpdateMsig(
        java.lang.String chain, 
        java.lang.String ua, 
        MsigStructureArgs structure, 
        short[] enabled, 
        long validUntilBlock, 
        java.util.List<MsigSlot> slots, 
        KeyRef payer, 
        boolean verifier, 
        boolean familyWithoutUpdate
    ) {
        
        this.chain = chain;
        
        this.ua = ua;
        
        this.structure = structure;
        
        this.enabled = enabled;
        
        this.validUntilBlock = validUntilBlock;
        
        this.slots = slots;
        
        this.payer = payer;
        
        this.verifier = verifier;
        
        this.familyWithoutUpdate = familyWithoutUpdate;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public MsigStructureArgs structure() {
        return this.structure;
    }
    
    public short[] enabled() {
        return this.enabled;
    }
    
    public long validUntilBlock() {
        return this.validUntilBlock;
    }
    
    public java.util.List<MsigSlot> slots() {
        return this.slots;
    }
    
    public KeyRef payer() {
        return this.payer;
    }
    
    public boolean verifier() {
        return this.verifier;
    }
    
    public boolean familyWithoutUpdate() {
        return this.familyWithoutUpdate;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setStructure(MsigStructureArgs structure) {
        this.structure = structure;
    }
    public void setEnabled(short[] enabled) {
        this.enabled = enabled;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }
    public void setSlots(java.util.List<MsigSlot> slots) {
        this.slots = slots;
    }
    public void setPayer(KeyRef payer) {
        this.payer = payer;
    }
    public void setVerifier(boolean verifier) {
        this.verifier = verifier;
    }
    public void setFamilyWithoutUpdate(boolean familyWithoutUpdate) {
        this.familyWithoutUpdate = familyWithoutUpdate;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UpdateMsig) {
            UpdateMsig t = (UpdateMsig) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(ua, t.ua) && 
              
              java.util.Objects.equals(structure, t.structure) && 
              
              java.util.Objects.equals(enabled, t.enabled) && 
              
              validUntilBlock == t.validUntilBlock && 
              
              java.util.Objects.equals(slots, t.slots) && 
              
              java.util.Objects.equals(payer, t.payer) && 
              
              verifier == t.verifier && 
              
              familyWithoutUpdate == t.familyWithoutUpdate
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.util.Objects.hashCode(structure);
        result = 31 * result + java.util.Objects.hashCode(enabled);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(slots);
        result = 31 * result + java.util.Objects.hashCode(payer);
        result = 31 * result + java.lang.Boolean.hashCode(verifier);
        result = 31 * result + java.lang.Boolean.hashCode(familyWithoutUpdate);
        return result;
    }

    
    
    

}


