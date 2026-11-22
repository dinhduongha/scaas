package uniffi.scaas_sdk;

/**
 * A seed's memory protection (`scaas-ua`'s, its counts as `u64`).
 */
public class MemoryProtection {
    /**
     * the arena's chunks (16 KiB each)
     */
    private long chunks;
    /**
     * chunks locked in RAM (`mlock`)
     */
    private long locked;
    /**
     * chunks excluded from core dumps
     */
    private long noDump;

    public MemoryProtection(
        long chunks, 
        long locked, 
        long noDump
    ) {
        
        this.chunks = chunks;
        
        this.locked = locked;
        
        this.noDump = noDump;
    }
    
    public long chunks() {
        return this.chunks;
    }
    
    public long locked() {
        return this.locked;
    }
    
    public long noDump() {
        return this.noDump;
    }
    public void setChunks(long chunks) {
        this.chunks = chunks;
    }
    public void setLocked(long locked) {
        this.locked = locked;
    }
    public void setNoDump(long noDump) {
        this.noDump = noDump;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MemoryProtection) {
            MemoryProtection t = (MemoryProtection) other;
            return (
              chunks == t.chunks && 
              
              locked == t.locked && 
              
              noDump == t.noDump
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(chunks);
        result = 31 * result + java.lang.Long.hashCode(locked);
        result = 31 * result + java.lang.Long.hashCode(noDump);
        return result;
    }

    
    
    

}


