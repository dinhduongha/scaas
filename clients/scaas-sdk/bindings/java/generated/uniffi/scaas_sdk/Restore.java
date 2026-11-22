package uniffi.scaas_sdk;

/**
 * `restore`: seed `seed` on chain `chain` (a profile key): the UA keys `kinds` of wallet `account`, `gap` (at most 1024, the
 * usual 20) past the last registered index.
 */
public class Restore {
    private java.lang.String seed;
    private java.lang.String chain;
    private short[] kinds;
    private int account;
    private int gap;

    public Restore(
        java.lang.String seed, 
        java.lang.String chain, 
        short[] kinds, 
        int account, 
        int gap
    ) {
        
        this.seed = seed;
        
        this.chain = chain;
        
        this.kinds = kinds;
        
        this.account = account;
        
        this.gap = gap;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public short[] kinds() {
        return this.kinds;
    }
    
    public int account() {
        return this.account;
    }
    
    public int gap() {
        return this.gap;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setKinds(short[] kinds) {
        this.kinds = kinds;
    }
    public void setAccount(int account) {
        this.account = account;
    }
    public void setGap(int gap) {
        this.gap = gap;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Restore) {
            Restore t = (Restore) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(kinds, t.kinds) && 
              
              account == t.account && 
              
              gap == t.gap
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(kinds);
        result = 31 * result + java.lang.Integer.hashCode(account);
        result = 31 * result + java.lang.Integer.hashCode(gap);
        return result;
    }

    
    
    

}


