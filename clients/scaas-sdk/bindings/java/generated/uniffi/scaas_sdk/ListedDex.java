package uniffi.scaas_sdk;

/**
 * A DEX of the chain profile (NET-ALL-24): its address, its liquidity mark (a module of group 11 among its `modules()`,
 * CTR-DEX-30) and the position readers reviewed for it, each beside its position manager.
 */
public class ListedDex {
    /**
     * `0x` + 40 hex
     */
    private java.lang.String address;
    private boolean liquidity;
    private java.util.List<PositionReader> positionReaders;

    public ListedDex(
        java.lang.String address, 
        boolean liquidity, 
        java.util.List<PositionReader> positionReaders
    ) {
        
        this.address = address;
        
        this.liquidity = liquidity;
        
        this.positionReaders = positionReaders;
    }
    
    public java.lang.String address() {
        return this.address;
    }
    
    public boolean liquidity() {
        return this.liquidity;
    }
    
    public java.util.List<PositionReader> positionReaders() {
        return this.positionReaders;
    }
    public void setAddress(java.lang.String address) {
        this.address = address;
    }
    public void setLiquidity(boolean liquidity) {
        this.liquidity = liquidity;
    }
    public void setPositionReaders(java.util.List<PositionReader> positionReaders) {
        this.positionReaders = positionReaders;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ListedDex) {
            ListedDex t = (ListedDex) other;
            return (
              java.util.Objects.equals(address, t.address) && 
              
              liquidity == t.liquidity && 
              
              java.util.Objects.equals(positionReaders, t.positionReaders)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(address);
        result = 31 * result + java.lang.Boolean.hashCode(liquidity);
        result = 31 * result + java.util.Objects.hashCode(positionReaders);
        return result;
    }

    
    
    

}


