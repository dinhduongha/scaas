package uniffi.scaas_sdk;

/**
 * A decrypted balance, for the holder only.
 */
public class ZetherBalance {
    /**
     * the smallest unit, decimal
     */
    private java.lang.String amount;
    /**
     * the final block the words were read at
     */
    private long block;
    /**
     * the account's `accSeq` at that block (what a balance cache stores)
     */
    private long accSeq;

    public ZetherBalance(
        java.lang.String amount, 
        long block, 
        long accSeq
    ) {
        
        this.amount = amount;
        
        this.block = block;
        
        this.accSeq = accSeq;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public long block() {
        return this.block;
    }
    
    public long accSeq() {
        return this.accSeq;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setBlock(long block) {
        this.block = block;
    }
    public void setAccSeq(long accSeq) {
        this.accSeq = accSeq;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherBalance) {
            ZetherBalance t = (ZetherBalance) other;
            return (
              java.util.Objects.equals(amount, t.amount) && 
              
              block == t.block && 
              
              accSeq == t.accSeq
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.lang.Long.hashCode(block);
        result = 31 * result + java.lang.Long.hashCode(accSeq);
        return result;
    }

    
    
    

}


