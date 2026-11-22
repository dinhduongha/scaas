package uniffi.scaas_sdk;

/**
 * A position in a chain's logs: a page holds items strictly older than it.
 */
public class Cursor {
    private long block;
    private long logIndex;

    public Cursor(
        long block, 
        long logIndex
    ) {
        
        this.block = block;
        
        this.logIndex = logIndex;
    }
    
    public long block() {
        return this.block;
    }
    
    public long logIndex() {
        return this.logIndex;
    }
    public void setBlock(long block) {
        this.block = block;
    }
    public void setLogIndex(long logIndex) {
        this.logIndex = logIndex;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Cursor) {
            Cursor t = (Cursor) other;
            return (
              block == t.block && 
              
              logIndex == t.logIndex
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(block);
        result = 31 * result + java.lang.Long.hashCode(logIndex);
        return result;
    }

    
    
    

}


