package uniffi.scaas_sdk;

/**
 * `prepare_msig_register`: the `msig` `structure` registered on `chain` (`registerMsig`), its `pop` signed by `slots` (a
 * minimal set, CTR-UA-07; none: an empty `pop`, a classical-dominant `msig`'s), sent by `payer`.
 */
public class MsigRegister {
    private java.lang.String chain;
    private MsigStructureArgs structure;
    private java.util.List<MsigSlot> slots;
    private KeyRef payer;

    public MsigRegister(
        java.lang.String chain, 
        MsigStructureArgs structure, 
        java.util.List<MsigSlot> slots, 
        KeyRef payer
    ) {
        
        this.chain = chain;
        
        this.structure = structure;
        
        this.slots = slots;
        
        this.payer = payer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public MsigStructureArgs structure() {
        return this.structure;
    }
    
    public java.util.List<MsigSlot> slots() {
        return this.slots;
    }
    
    public KeyRef payer() {
        return this.payer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setStructure(MsigStructureArgs structure) {
        this.structure = structure;
    }
    public void setSlots(java.util.List<MsigSlot> slots) {
        this.slots = slots;
    }
    public void setPayer(KeyRef payer) {
        this.payer = payer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigRegister) {
            MsigRegister t = (MsigRegister) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(structure, t.structure) && 
              
              java.util.Objects.equals(slots, t.slots) && 
              
              java.util.Objects.equals(payer, t.payer)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(structure);
        result = 31 * result + java.util.Objects.hashCode(slots);
        result = 31 * result + java.util.Objects.hashCode(payer);
        return result;
    }

    
    
    

}


