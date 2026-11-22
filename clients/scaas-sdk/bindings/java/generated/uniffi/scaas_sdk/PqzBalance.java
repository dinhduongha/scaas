package uniffi.scaas_sdk;

/**
 * A decrypted PQZ balance, for the holder only.
 */
public class PqzBalance {
    /**
     * the smallest unit, decimal: what a debit at this block may spend (the account and the window `[rolled, p)`)
     */
    private java.lang.String amount;
    /**
     * the final block the words were read at
     */
    private long block;
    /**
     * the window's end and the UA's `sendCounter` at that block
     */
    private long p;
    private long sendCounter;

    public PqzBalance(
        java.lang.String amount, 
        long block, 
        long p, 
        long sendCounter
    ) {
        
        this.amount = amount;
        
        this.block = block;
        
        this.p = p;
        
        this.sendCounter = sendCounter;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public long block() {
        return this.block;
    }
    
    public long p() {
        return this.p;
    }
    
    public long sendCounter() {
        return this.sendCounter;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setBlock(long block) {
        this.block = block;
    }
    public void setP(long p) {
        this.p = p;
    }
    public void setSendCounter(long sendCounter) {
        this.sendCounter = sendCounter;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzBalance) {
            PqzBalance t = (PqzBalance) other;
            return (
              java.util.Objects.equals(amount, t.amount) && 
              
              block == t.block && 
              
              p == t.p && 
              
              sendCounter == t.sendCounter
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.lang.Long.hashCode(block);
        result = 31 * result + java.lang.Long.hashCode(p);
        result = 31 * result + java.lang.Long.hashCode(sendCounter);
        return result;
    }

    
    
    

}


