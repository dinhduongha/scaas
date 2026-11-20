package uniffi.scaas_sdk;

/**
 * `add_native`: the native key of `network` (a `scaas-ua` network name) at `index`.
 */
public class AddNative {
    private java.lang.String seed;
    private java.lang.String network;
    private int index;
    private java.lang.String name;

    public AddNative(
        java.lang.String seed, 
        java.lang.String network, 
        int index, 
        java.lang.String name
    ) {
        
        this.seed = seed;
        
        this.network = network;
        
        this.index = index;
        
        this.name = name;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public int index() {
        return this.index;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setIndex(int index) {
        this.index = index;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AddNative) {
            AddNative t = (AddNative) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(network, t.network) && 
              
              index == t.index && 
              
              java.util.Objects.equals(name, t.name)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.lang.Integer.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(name);
        return result;
    }

    
    
    

}


