package uniffi.scaas_sdk;

/**
 * One member of an `msig` structure (CTR-UA-09): its kind, its id (`0x` + 64 hex), its weight.
 */
public class MsigMemberArgs {
    private short kind;
    private java.lang.String id;
    private short weight;

    public MsigMemberArgs(
        short kind, 
        java.lang.String id, 
        short weight
    ) {
        
        this.kind = kind;
        
        this.id = id;
        
        this.weight = weight;
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
    public void setKind(short kind) {
        this.kind = kind;
    }
    public void setId(java.lang.String id) {
        this.id = id;
    }
    public void setWeight(short weight) {
        this.weight = weight;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigMemberArgs) {
            MsigMemberArgs t = (MsigMemberArgs) other;
            return (
              kind == t.kind && 
              
              java.util.Objects.equals(id, t.id) && 
              
              weight == t.weight
              
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
        return result;
    }

    
    
    

}


