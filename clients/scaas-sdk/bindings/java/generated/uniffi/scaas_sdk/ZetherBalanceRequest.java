package uniffi.scaas_sdk;

/**
 * A balance read (spec §9.4).
 */
public class ZetherBalanceRequest {
    private java.lang.String seed;
    private int account;
    private java.lang.String chain;
    /**
     * the token, `0x` + 40 hex
     */
    private java.lang.String token;
    /**
     * the pending balance (received, not rolled over) instead of the spendable one
     */
    private boolean pending;
    /**
     * the BSGS table and bound bits (`None`: the facade's defaults for this target)
     */
    private java.lang.Integer tableBits;
    private java.lang.Integer boundBits;

    public ZetherBalanceRequest(
        java.lang.String seed, 
        int account, 
        java.lang.String chain, 
        java.lang.String token, 
        boolean pending, 
        java.lang.Integer tableBits, 
        java.lang.Integer boundBits
    ) {
        
        this.seed = seed;
        
        this.account = account;
        
        this.chain = chain;
        
        this.token = token;
        
        this.pending = pending;
        
        this.tableBits = tableBits;
        
        this.boundBits = boundBits;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public int account() {
        return this.account;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public boolean pending() {
        return this.pending;
    }
    
    public java.lang.Integer tableBits() {
        return this.tableBits;
    }
    
    public java.lang.Integer boundBits() {
        return this.boundBits;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setAccount(int account) {
        this.account = account;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setPending(boolean pending) {
        this.pending = pending;
    }
    public void setTableBits(java.lang.Integer tableBits) {
        this.tableBits = tableBits;
    }
    public void setBoundBits(java.lang.Integer boundBits) {
        this.boundBits = boundBits;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherBalanceRequest) {
            ZetherBalanceRequest t = (ZetherBalanceRequest) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              account == t.account && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              pending == t.pending && 
              
              java.util.Objects.equals(tableBits, t.tableBits) && 
              
              java.util.Objects.equals(boundBits, t.boundBits)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.lang.Integer.hashCode(account);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.lang.Boolean.hashCode(pending);
        result = 31 * result + java.util.Objects.hashCode(tableBits);
        result = 31 * result + java.util.Objects.hashCode(boundBits);
        return result;
    }

    
    
    

}


