package uniffi.scaas_sdk;

/**
 * An account's balances at one block.
 */
public class Balances {
    private long block;
    /**
     * the native balance of an address or a native id (`None` for a derived UA: it holds no native coin)
     */
    private java.lang.String _native;
    private java.util.List<TokenBalance> tokens;

    public Balances(
        long block, 
        java.lang.String _native, 
        java.util.List<TokenBalance> tokens
    ) {
        
        this.block = block;
        
        this._native = _native;
        
        this.tokens = tokens;
    }
    
    public long block() {
        return this.block;
    }
    
    public java.lang.String _native() {
        return this._native;
    }
    
    public java.util.List<TokenBalance> tokens() {
        return this.tokens;
    }
    public void setBlock(long block) {
        this.block = block;
    }
    public void setNative(java.lang.String _native) {
        this._native = _native;
    }
    public void setTokens(java.util.List<TokenBalance> tokens) {
        this.tokens = tokens;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Balances) {
            Balances t = (Balances) other;
            return (
              block == t.block && 
              
              java.util.Objects.equals(_native, t._native) && 
              
              java.util.Objects.equals(tokens, t.tokens)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(block);
        result = 31 * result + java.util.Objects.hashCode(_native);
        result = 31 * result + java.util.Objects.hashCode(tokens);
        return result;
    }

    
    
    

}


