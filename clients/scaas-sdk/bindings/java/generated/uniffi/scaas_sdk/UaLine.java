package uniffi.scaas_sdk;

/**
 * Where a UA's record and its PQZ attachment live, as the bound registry's one walk answers (`holderOf`, §11.1).
 */
public class UaLine {
    /**
     * the generation holding the record (`0x` + 40 hex): the target of a key write, where its record is read
     */
    private java.lang.String holder;
    private short kind;
    /**
     * the record's PQZ home (§11.2): the target of a PQZ write, where its attachment is read; `None`: no home on the walk
     */
    private java.lang.String pqzHome;

    public UaLine(
        java.lang.String holder, 
        short kind, 
        java.lang.String pqzHome
    ) {
        
        this.holder = holder;
        
        this.kind = kind;
        
        this.pqzHome = pqzHome;
    }
    
    public java.lang.String holder() {
        return this.holder;
    }
    
    public short kind() {
        return this.kind;
    }
    
    public java.lang.String pqzHome() {
        return this.pqzHome;
    }
    public void setHolder(java.lang.String holder) {
        this.holder = holder;
    }
    public void setKind(short kind) {
        this.kind = kind;
    }
    public void setPqzHome(java.lang.String pqzHome) {
        this.pqzHome = pqzHome;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof UaLine) {
            UaLine t = (UaLine) other;
            return (
              java.util.Objects.equals(holder, t.holder) && 
              
              kind == t.kind && 
              
              java.util.Objects.equals(pqzHome, t.pqzHome)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(holder);
        result = 31 * result + java.lang.Short.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(pqzHome);
        return result;
    }

    
    
    

}


