package uniffi.scaas_sdk;

/**
 * One of the account's operations in `sdk.state` (spec §13.4).
 */
public class OpItem {
    private java.lang.String op;
    private java.lang.String entry;
    /**
     * `signed`, `sent`, `landed`, `reverted`, `consumed`, `expired`
     */
    private java.lang.String state;
    private java.lang.Long landedBlock;

    public OpItem(
        java.lang.String op, 
        java.lang.String entry, 
        java.lang.String state, 
        java.lang.Long landedBlock
    ) {
        
        this.op = op;
        
        this.entry = entry;
        
        this.state = state;
        
        this.landedBlock = landedBlock;
    }
    
    public java.lang.String op() {
        return this.op;
    }
    
    public java.lang.String entry() {
        return this.entry;
    }
    
    public java.lang.String state() {
        return this.state;
    }
    
    public java.lang.Long landedBlock() {
        return this.landedBlock;
    }
    public void setOp(java.lang.String op) {
        this.op = op;
    }
    public void setEntry(java.lang.String entry) {
        this.entry = entry;
    }
    public void setState(java.lang.String state) {
        this.state = state;
    }
    public void setLandedBlock(java.lang.Long landedBlock) {
        this.landedBlock = landedBlock;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof OpItem) {
            OpItem t = (OpItem) other;
            return (
              java.util.Objects.equals(op, t.op) && 
              
              java.util.Objects.equals(entry, t.entry) && 
              
              java.util.Objects.equals(state, t.state) && 
              
              java.util.Objects.equals(landedBlock, t.landedBlock)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(op);
        result = 31 * result + java.util.Objects.hashCode(entry);
        result = 31 * result + java.util.Objects.hashCode(state);
        result = 31 * result + java.util.Objects.hashCode(landedBlock);
        return result;
    }

    
    
    

}


