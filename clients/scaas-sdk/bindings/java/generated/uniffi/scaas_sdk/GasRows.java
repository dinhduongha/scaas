package uniffi.scaas_sdk;

/**
 * The rows of a gas table: base and verify, looked up independently (spec §13.3). The quote's figure is base + verify.
 */
public class GasRows {
    private java.util.List<GasBase> base;
    private java.util.List<GasVerify> verify;

    public GasRows(
        java.util.List<GasBase> base, 
        java.util.List<GasVerify> verify
    ) {
        
        this.base = base;
        
        this.verify = verify;
    }
    
    public java.util.List<GasBase> base() {
        return this.base;
    }
    
    public java.util.List<GasVerify> verify() {
        return this.verify;
    }
    public void setBase(java.util.List<GasBase> base) {
        this.base = base;
    }
    public void setVerify(java.util.List<GasVerify> verify) {
        this.verify = verify;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasRows) {
            GasRows t = (GasRows) other;
            return (
              java.util.Objects.equals(base, t.base) && 
              
              java.util.Objects.equals(verify, t.verify)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(base);
        result = 31 * result + java.util.Objects.hashCode(verify);
        return result;
    }

    
    
    

}


