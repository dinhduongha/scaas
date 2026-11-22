package uniffi.scaas_sdk;

/**
 * A token as the wallet shows it.
 */
public class TokenInfo {
    /**
     * `0x` + 40 hex, lower case
     */
    private java.lang.String address;
    private java.lang.String name;
    private java.lang.String symbol;
    private byte decimals;
    /**
     * on the profile's reviewed list
     */
    private boolean listed;
    /**
     * what a screen shows: the symbol, with `[unlisted]` before an unlisted one's
     */
    private java.lang.String display;

    public TokenInfo(
        java.lang.String address, 
        java.lang.String name, 
        java.lang.String symbol, 
        byte decimals, 
        boolean listed, 
        java.lang.String display
    ) {
        
        this.address = address;
        
        this.name = name;
        
        this.symbol = symbol;
        
        this.decimals = decimals;
        
        this.listed = listed;
        
        this.display = display;
    }
    
    public java.lang.String address() {
        return this.address;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public java.lang.String symbol() {
        return this.symbol;
    }
    
    public byte decimals() {
        return this.decimals;
    }
    
    public boolean listed() {
        return this.listed;
    }
    
    public java.lang.String display() {
        return this.display;
    }
    public void setAddress(java.lang.String address) {
        this.address = address;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setSymbol(java.lang.String symbol) {
        this.symbol = symbol;
    }
    public void setDecimals(byte decimals) {
        this.decimals = decimals;
    }
    public void setListed(boolean listed) {
        this.listed = listed;
    }
    public void setDisplay(java.lang.String display) {
        this.display = display;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof TokenInfo) {
            TokenInfo t = (TokenInfo) other;
            return (
              java.util.Objects.equals(address, t.address) && 
              
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(symbol, t.symbol) && 
              
              decimals == t.decimals && 
              
              listed == t.listed && 
              
              java.util.Objects.equals(display, t.display)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(address);
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(symbol);
        result = 31 * result + java.lang.Byte.hashCode(decimals);
        result = 31 * result + java.lang.Boolean.hashCode(listed);
        result = 31 * result + java.util.Objects.hashCode(display);
        return result;
    }

    
    
    

}


