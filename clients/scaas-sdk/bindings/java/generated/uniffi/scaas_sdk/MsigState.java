package uniffi.scaas_sdk;

/**
 * An `msig` on the profile's registry (`msig_state`).
 */
public class MsigState {
    private java.lang.String ua;
    /**
     * the structure the id derives from (`registrationOf`)
     */
    private MsigStructureArgs first;
    /**
     * the current threshold (`msigOf`)
     */
    private short threshold;
    /**
     * the current slots, disabled ones included
     */
    private java.util.List<MsigSlotState> slots;
    /**
     * `msigStateOf`'s update counter (0: never updated here)
     */
    private long version;
    /**
     * the weight of the slots enabled and accepted
     */
    private int activeWeight;
    /**
     * that weight reaches the threshold: until then the `msig` authorizes nothing (CTR-UA-37)
     */
    private boolean active;

    public MsigState(
        java.lang.String ua, 
        MsigStructureArgs first, 
        short threshold, 
        java.util.List<MsigSlotState> slots, 
        long version, 
        int activeWeight, 
        boolean active
    ) {
        
        this.ua = ua;
        
        this.first = first;
        
        this.threshold = threshold;
        
        this.slots = slots;
        
        this.version = version;
        
        this.activeWeight = activeWeight;
        
        this.active = active;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public MsigStructureArgs first() {
        return this.first;
    }
    
    public short threshold() {
        return this.threshold;
    }
    
    public java.util.List<MsigSlotState> slots() {
        return this.slots;
    }
    
    public long version() {
        return this.version;
    }
    
    public int activeWeight() {
        return this.activeWeight;
    }
    
    public boolean active() {
        return this.active;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setFirst(MsigStructureArgs first) {
        this.first = first;
    }
    public void setThreshold(short threshold) {
        this.threshold = threshold;
    }
    public void setSlots(java.util.List<MsigSlotState> slots) {
        this.slots = slots;
    }
    public void setVersion(long version) {
        this.version = version;
    }
    public void setActiveWeight(int activeWeight) {
        this.activeWeight = activeWeight;
    }
    public void setActive(boolean active) {
        this.active = active;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigState) {
            MsigState t = (MsigState) other;
            return (
              java.util.Objects.equals(ua, t.ua) && 
              
              java.util.Objects.equals(first, t.first) && 
              
              threshold == t.threshold && 
              
              java.util.Objects.equals(slots, t.slots) && 
              
              version == t.version && 
              
              activeWeight == t.activeWeight && 
              
              active == t.active
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.util.Objects.hashCode(first);
        result = 31 * result + java.lang.Short.hashCode(threshold);
        result = 31 * result + java.util.Objects.hashCode(slots);
        result = 31 * result + java.lang.Long.hashCode(version);
        result = 31 * result + java.lang.Integer.hashCode(activeWeight);
        result = 31 * result + java.lang.Boolean.hashCode(active);
        return result;
    }

    
    
    

}


