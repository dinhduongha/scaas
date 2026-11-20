package uniffi.scaas_sdk;

/**
 * A row's per-item part (owner 2026-11-19, I1), on a base or a verify row: `gas` (whole gas, the measured slope rounded
 * up) for each counted `item` of the operation, one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`,
 * `env_items`, `orders`). The row's own `gas` is its figure at a count of 0 (the line's intercept; the file states
 * `"base_count": 0`), so the quote adds `gas × count` with no offset.
 */
public class GasPerItem {
    private java.lang.String item;
    private long gas;
    /**
     * the regular part of `gas` (EIP-8037), on a base row with a `regular` figure only
     */
    private java.lang.Long regular;
    /**
     * the largest count the row was measured at (`gas/generate.py`); a count above it is `GasCountUnknown`, never a line
     * extrapolated past its points (merged-tree review M18, 2026-11-20); `None`: a row that names none (the chain's own)
     */
    private java.lang.Long measuredMax;

    public GasPerItem(
        java.lang.String item, 
        long gas, 
        java.lang.Long regular, 
        java.lang.Long measuredMax
    ) {
        
        this.item = item;
        
        this.gas = gas;
        
        this.regular = regular;
        
        this.measuredMax = measuredMax;
    }
    
    public java.lang.String item() {
        return this.item;
    }
    
    public long gas() {
        return this.gas;
    }
    
    public java.lang.Long regular() {
        return this.regular;
    }
    
    public java.lang.Long measuredMax() {
        return this.measuredMax;
    }
    public void setItem(java.lang.String item) {
        this.item = item;
    }
    public void setGas(long gas) {
        this.gas = gas;
    }
    public void setRegular(java.lang.Long regular) {
        this.regular = regular;
    }
    public void setMeasuredMax(java.lang.Long measuredMax) {
        this.measuredMax = measuredMax;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasPerItem) {
            GasPerItem t = (GasPerItem) other;
            return (
              java.util.Objects.equals(item, t.item) && 
              
              gas == t.gas && 
              
              java.util.Objects.equals(regular, t.regular) && 
              
              java.util.Objects.equals(measuredMax, t.measuredMax)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(item);
        result = 31 * result + java.lang.Long.hashCode(gas);
        result = 31 * result + java.util.Objects.hashCode(regular);
        result = 31 * result + java.util.Objects.hashCode(measuredMax);
        return result;
    }

    
    
    

}


