package uniffi.scaas_sdk;

/**
 * The owner's roll-over mode (`ZetherSetRollOverMode`; or `UASetRollOverMode`): `mode` 0 PUBLIC, 1 OWNER_ONLY.
 */
public class ZetherOwnerSetMode {
    private java.lang.String seed;
    private int account;
    private java.lang.String chain;
    private java.lang.String token;
    private byte mode;
    private long validUntilBlock;

    public ZetherOwnerSetMode(
        java.lang.String seed, 
        int account, 
        java.lang.String chain, 
        java.lang.String token, 
        byte mode, 
        long validUntilBlock
    ) {
        
        this.seed = seed;
        
        this.account = account;
        
        this.chain = chain;
        
        this.token = token;
        
        this.mode = mode;
        
        this.validUntilBlock = validUntilBlock;
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
    
    public byte mode() {
        return this.mode;
    }
    
    public long validUntilBlock() {
        return this.validUntilBlock;
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
    public void setMode(byte mode) {
        this.mode = mode;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherOwnerSetMode) {
            ZetherOwnerSetMode t = (ZetherOwnerSetMode) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              account == t.account && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              mode == t.mode && 
              
              validUntilBlock == t.validUntilBlock
              
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
        result = 31 * result + java.lang.Byte.hashCode(mode);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        return result;
    }

    
    
    

}


