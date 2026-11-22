package uniffi.scaas_sdk;

/**
 * An `msig` structure: the threshold and the members, in slot order.
 */
public class MsigStructureArgs {
    private short threshold;
    private java.util.List<MsigMemberArgs> members;

    public MsigStructureArgs(
        short threshold, 
        java.util.List<MsigMemberArgs> members
    ) {
        
        this.threshold = threshold;
        
        this.members = members;
    }
    
    public short threshold() {
        return this.threshold;
    }
    
    public java.util.List<MsigMemberArgs> members() {
        return this.members;
    }
    public void setThreshold(short threshold) {
        this.threshold = threshold;
    }
    public void setMembers(java.util.List<MsigMemberArgs> members) {
        this.members = members;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigStructureArgs) {
            MsigStructureArgs t = (MsigStructureArgs) other;
            return (
              threshold == t.threshold && 
              
              java.util.Objects.equals(members, t.members)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Short.hashCode(threshold);
        result = 31 * result + java.util.Objects.hashCode(members);
        return result;
    }

    
    
    

}


