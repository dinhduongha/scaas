package uniffi.scaas_sdk;

/**
 * A prepared update: its write and `scaas-ua`'s warnings (`plan_msig_update`, none a refusal), in their `Debug` form.
 */
public class MsigUpdatePlan implements AutoCloseable{
    private RegistryWrite write;
    private java.util.List<java.lang.String> warnings;

    public MsigUpdatePlan(
        RegistryWrite write, 
        java.util.List<java.lang.String> warnings
    ) {
        
        this.write = write;
        
        this.warnings = warnings;
    }
    
    public RegistryWrite write() {
        return this.write;
    }
    
    public java.util.List<java.lang.String> warnings() {
        return this.warnings;
    }
    public void setWrite(RegistryWrite write) {
        this.write = write;
    }
    public void setWarnings(java.util.List<java.lang.String> warnings) {
        this.warnings = warnings;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.write, 
        this.warnings);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigUpdatePlan) {
            MsigUpdatePlan t = (MsigUpdatePlan) other;
            return (
              java.util.Objects.equals(write, t.write) && 
              
              java.util.Objects.equals(warnings, t.warnings)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(write);
        result = 31 * result + java.util.Objects.hashCode(warnings);
        return result;
    }

    
    
    

}


