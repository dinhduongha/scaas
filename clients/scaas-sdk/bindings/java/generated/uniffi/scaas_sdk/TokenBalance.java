package uniffi.scaas_sdk;

/**
 * One token's balance.
 */
public class TokenBalance {
    private java.lang.String address;
    private java.lang.String display;
    private byte decimals;
    /**
     * the smallest unit, decimal; empty when `unknown` is set
     */
    private java.lang.String amount;
    /**
     * set when the balance cannot be read, with its reason (owner 2026-11-23, T26 B2-15: a frozen TON jetton wallet,
     * `frozen`): the amount is unknown, never a false 0
     */
    private java.lang.String unknown;

    public TokenBalance(
        java.lang.String address, 
        java.lang.String display, 
        byte decimals, 
        java.lang.String amount, 
        java.lang.String unknown
    ) {
        
        this.address = address;
        
        this.display = display;
        
        this.decimals = decimals;
        
        this.amount = amount;
        
        this.unknown = unknown;
    }
    
    public java.lang.String address() {
        return this.address;
    }
    
    public java.lang.String display() {
        return this.display;
    }
    
    public byte decimals() {
        return this.decimals;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public java.lang.String unknown() {
        return this.unknown;
    }
    public void setAddress(java.lang.String address) {
        this.address = address;
    }
    public void setDisplay(java.lang.String display) {
        this.display = display;
    }
    public void setDecimals(byte decimals) {
        this.decimals = decimals;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setUnknown(java.lang.String unknown) {
        this.unknown = unknown;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof TokenBalance) {
            TokenBalance t = (TokenBalance) other;
            return (
              java.util.Objects.equals(address, t.address) && 
              
              java.util.Objects.equals(display, t.display) && 
              
              decimals == t.decimals && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(unknown, t.unknown)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(address);
        result = 31 * result + java.util.Objects.hashCode(display);
        result = 31 * result + java.lang.Byte.hashCode(decimals);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(unknown);
        return result;
    }

    
    
    

}


