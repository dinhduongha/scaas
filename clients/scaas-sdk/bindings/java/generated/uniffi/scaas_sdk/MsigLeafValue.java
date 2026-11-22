package uniffi.scaas_sdk;

/**
 * A slot of an inner `msig`: its index there and its key.
 */
public class MsigLeafValue {
    private short index;
    private SlotKey key;

    public MsigLeafValue(
        short index, 
        SlotKey key
    ) {
        
        this.index = index;
        
        this.key = key;
    }
    
    public short index() {
        return this.index;
    }
    
    public SlotKey key() {
        return this.key;
    }
    public void setIndex(short index) {
        this.index = index;
    }
    public void setKey(SlotKey key) {
        this.key = key;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof MsigLeafValue) {
            MsigLeafValue t = (MsigLeafValue) other;
            return (
              index == t.index && 
              
              java.util.Objects.equals(key, t.key)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Short.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(key);
        return result;
    }

    
    
    

}


