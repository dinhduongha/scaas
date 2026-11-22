package uniffi.scaas_sdk;

/**
 * One slot of an `msig` as the registry holds it now.
 */
public class MsigSlotState {
    private short kind;
    private java.lang.String id;
    private short weight;
    private boolean enabled;
    /**
     * accepted (CTR-UA-37; never cleared, whether enabled or not)
     */
    private boolean accepted;
    /**
     * `memberSigHashOf(ua, i)` (`0x` + 64 hex; zero for a slot not accepted): what a copy to another registry checks
     */
    private java.lang.String sigHash;

    public MsigSlotState(
        short kind, 
        java.lang.String id, 
        short weight, 
        boolean enabled, 
        boolean accepted, 
        java.lang.String sigHash
    ) {
        
        this.kind = kind;
        
        this.id = id;
        
        this.weight = weight;
        
        this.enabled = enabled;
        
        this.accepted = accepted;
        
        this.sigHash = sigHash;
    }
    
    public short kind() {
        return this.kind;
    }
    
    public java.lang.String id() {
        return this.id;
    }
    
    public short weight() {
        return this.weight;
    }
    
    public boolean enabled() {
        return this.enabled;
    }
    
    public boolean accepted() {
        return this.accepted;
    }
    
    public java.lang.String sigHash() {
        return this.sigHash;
    }
    public void setKind(short kind) {
        this.kind = kind;
    }
    public void setId(java.lang.String id) {
        this.id = id;
    }
    public void setWeight(short weight) {
        this.weight = weight;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    public void setAccepted(boolean accepted) {
        this.accepted = accepted;
    }
    public void setSigHash(java.lang.String sigHash) {
        this.sigHash = sigHash;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigSlotState) {
            MsigSlotState t = (MsigSlotState) other;
            return (
              kind == t.kind && 
              
              java.util.Objects.equals(id, t.id) && 
              
              weight == t.weight && 
              
              enabled == t.enabled && 
              
              accepted == t.accepted && 
              
              java.util.Objects.equals(sigHash, t.sigHash)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Short.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(id);
        result = 31 * result + java.lang.Short.hashCode(weight);
        result = 31 * result + java.lang.Boolean.hashCode(enabled);
        result = 31 * result + java.lang.Boolean.hashCode(accepted);
        result = 31 * result + java.util.Objects.hashCode(sigHash);
        return result;
    }

    
    
    

}


