package uniffi.scaas_sdk;

/**
 * A token of a profile's reviewed list (spec §8.2).
 */
public class ListedToken {
    /**
     * EVM: `0x` + 40 hex; another family: its token id as text, checked by the family's form (spec §8.7; a NEAR account)
     */
    private java.lang.String address;
    private java.lang.String symbol;
    private byte decimals;

    public ListedToken(
        java.lang.String address, 
        java.lang.String symbol, 
        byte decimals
    ) {
        
        this.address = address;
        
        this.symbol = symbol;
        
        this.decimals = decimals;
    }
    
    public java.lang.String address() {
        return this.address;
    }
    
    public java.lang.String symbol() {
        return this.symbol;
    }
    
    public byte decimals() {
        return this.decimals;
    }
    public void setAddress(java.lang.String address) {
        this.address = address;
    }
    public void setSymbol(java.lang.String symbol) {
        this.symbol = symbol;
    }
    public void setDecimals(byte decimals) {
        this.decimals = decimals;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ListedToken) {
            ListedToken t = (ListedToken) other;
            return (
              java.util.Objects.equals(address, t.address) && 
              
              java.util.Objects.equals(symbol, t.symbol) && 
              
              decimals == t.decimals
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(address);
        result = 31 * result + java.util.Objects.hashCode(symbol);
        result = 31 * result + java.lang.Byte.hashCode(decimals);
        return result;
    }

    
    
    

}


