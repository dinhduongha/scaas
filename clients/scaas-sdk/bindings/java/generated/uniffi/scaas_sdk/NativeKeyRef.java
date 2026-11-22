package uniffi.scaas_sdk;

/**
 * A seed's native key by its derivation: `network` a `scaas-ua` name; Bitcoin's `change` chain (0 receive, 1 change); a
 * `coin_type` in place of the network's (Bitcoin 0 / 1, Stellar's Pi Network); Polkadot's junction `path` (`//hard/soft`).
 *
 * Without the feature `raw-native` the raw entry does not exist (spec §8.6: no build without it can reach it):
 * ```compile_fail
 * let _ = scaas_sdk::wallet::AllowRawNative::new();
 * ```
 */
public class NativeKeyRef {
    private java.lang.String seed;
    private java.lang.String network;
    private int index;
    private java.lang.Integer change;
    private java.lang.Integer coinType;
    private java.lang.String path;

    public NativeKeyRef(
        java.lang.String seed, 
        java.lang.String network, 
        int index, 
        java.lang.Integer change, 
        java.lang.Integer coinType, 
        java.lang.String path
    ) {
        
        this.seed = seed;
        
        this.network = network;
        
        this.index = index;
        
        this.change = change;
        
        this.coinType = coinType;
        
        this.path = path;
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
    
    public java.lang.Integer change() {
        return this.change;
    }
    
    public java.lang.Integer coinType() {
        return this.coinType;
    }
    
    public java.lang.String path() {
        return this.path;
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
    public void setChange(java.lang.Integer change) {
        this.change = change;
    }
    public void setCoinType(java.lang.Integer coinType) {
        this.coinType = coinType;
    }
    public void setPath(java.lang.String path) {
        this.path = path;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NativeKeyRef) {
            NativeKeyRef t = (NativeKeyRef) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(network, t.network) && 
              
              index == t.index && 
              
              java.util.Objects.equals(change, t.change) && 
              
              java.util.Objects.equals(coinType, t.coinType) && 
              
              java.util.Objects.equals(path, t.path)
              
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
        result = 31 * result + java.util.Objects.hashCode(change);
        result = 31 * result + java.util.Objects.hashCode(coinType);
        result = 31 * result + java.util.Objects.hashCode(path);
        return result;
    }

    
    
    

}


