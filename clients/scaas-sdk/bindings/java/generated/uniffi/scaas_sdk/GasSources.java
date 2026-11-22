package uniffi.scaas_sdk;

/**
 * The sources of a quote's figure: its base row's and its verify row's (owner 2026-11-19, part 3b). An app's figure, one
 * total, is `App` for both; a native send's estimate `Estimate` for both.
 */
public class GasSources {
    private GasFrom base;
    private GasFrom verify;

    public GasSources(
        GasFrom base, 
        GasFrom verify
    ) {
        
        this.base = base;
        
        this.verify = verify;
    }
    
    public GasFrom base() {
        return this.base;
    }
    
    public GasFrom verify() {
        return this.verify;
    }
    public void setBase(GasFrom base) {
        this.base = base;
    }
    public void setVerify(GasFrom verify) {
        this.verify = verify;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasSources) {
            GasSources t = (GasSources) other;
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


