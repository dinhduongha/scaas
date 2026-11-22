package uniffi.scaas_sdk;

/**
 * A token and an amount of a liquidity order's plan.
 */
public class LiquidityToken {
    private java.lang.String token;
    private java.lang.String amount;

    public LiquidityToken(
        java.lang.String token, 
        java.lang.String amount
    ) {
        
        this.token = token;
        
        this.amount = amount;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof LiquidityToken) {
            LiquidityToken t = (LiquidityToken) other;
            return (
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(amount, t.amount)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(amount);
        return result;
    }

    
    
    

}


