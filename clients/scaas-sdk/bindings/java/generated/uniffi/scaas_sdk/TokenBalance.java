package uniffi.scaas_sdk;

/**
 * One token's balance.
 */
public class TokenBalance {
    private java.lang.String address;
    private java.lang.String display;
    private byte decimals;
    /**
     * the smallest unit, decimal
     */
    private java.lang.String amount;

    public TokenBalance(
        java.lang.String address, 
        java.lang.String display, 
        byte decimals, 
        java.lang.String amount
    ) {
        
        this.address = address;
        
        this.display = display;
        
        this.decimals = decimals;
        
        this.amount = amount;
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

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof TokenBalance) {
            TokenBalance t = (TokenBalance) other;
            return (
              java.util.Objects.equals(address, t.address) && 
              
              java.util.Objects.equals(display, t.display) && 
              
              decimals == t.decimals && 
              
              java.util.Objects.equals(amount, t.amount)
              
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
        return result;
    }

    
    
    

}


