package uniffi.scaas_sdk;

/**
 * An imported key's place: its network and its number `n` (the vault `native-import:<network>:<n>`).
 */
public class ImportedKey {
    private java.lang.String network;
    private int index;

    public ImportedKey(
        java.lang.String network, 
        int index
    ) {
        
        this.network = network;
        
        this.index = index;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public int index() {
        return this.index;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setIndex(int index) {
        this.index = index;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ImportedKey) {
            ImportedKey t = (ImportedKey) other;
            return (
              java.util.Objects.equals(network, t.network) && 
              
              index == t.index
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.lang.Integer.hashCode(index);
        return result;
    }

    
    
    

}


