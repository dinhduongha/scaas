package uniffi.scaas_sdk;

/**
 * An item and its revision (its JSON `rev`; `u64::MAX` when the bytes hold none, so no `put_if` matches it).
 */
public class StoredItem {
    private byte[] bytes;
    private long rev;

    public StoredItem(
        byte[] bytes, 
        long rev
    ) {
        
        this.bytes = bytes;
        
        this.rev = rev;
    }
    
    public byte[] bytes() {
        return this.bytes;
    }
    
    public long rev() {
        return this.rev;
    }
    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }
    public void setRev(long rev) {
        this.rev = rev;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof StoredItem) {
            StoredItem t = (StoredItem) other;
            return (
              java.util.Objects.equals(bytes, t.bytes) && 
              
              rev == t.rev
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(bytes);
        result = 31 * result + java.lang.Long.hashCode(rev);
        return result;
    }

    
    
    

}


