package uniffi.scaas_sdk;

/**
 * One chain's native cost cap (`Limits::max_native_cost`).
 */
public class NativeCap {
    /**
     * the profile's key
     */
    private java.lang.String chain;
    /**
     * decimal, the chain's smallest unit (stroops on Soroban)
     */
    private java.lang.String max;

    public NativeCap(
        java.lang.String chain, 
        java.lang.String max
    ) {
        
        this.chain = chain;
        
        this.max = max;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String max() {
        return this.max;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setMax(java.lang.String max) {
        this.max = max;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NativeCap) {
            NativeCap t = (NativeCap) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(max, t.max)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(max);
        return result;
    }

    
    
    

}


