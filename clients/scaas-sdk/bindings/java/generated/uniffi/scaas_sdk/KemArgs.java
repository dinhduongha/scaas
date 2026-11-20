package uniffi.scaas_sdk;

/**
 * `KemKey`, named.
 */
public class KemArgs {
    private byte scheme;
    private java.lang.String mlkemEk;
    private java.lang.String x25519;

    public KemArgs(
        byte scheme, 
        java.lang.String mlkemEk, 
        java.lang.String x25519
    ) {
        
        this.scheme = scheme;
        
        this.mlkemEk = mlkemEk;
        
        this.x25519 = x25519;
    }
    
    public byte scheme() {
        return this.scheme;
    }
    
    public java.lang.String mlkemEk() {
        return this.mlkemEk;
    }
    
    public java.lang.String x25519() {
        return this.x25519;
    }
    public void setScheme(byte scheme) {
        this.scheme = scheme;
    }
    public void setMlkemEk(java.lang.String mlkemEk) {
        this.mlkemEk = mlkemEk;
    }
    public void setX25519(java.lang.String x25519) {
        this.x25519 = x25519;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof KemArgs) {
            KemArgs t = (KemArgs) other;
            return (
              scheme == t.scheme && 
              
              java.util.Objects.equals(mlkemEk, t.mlkemEk) && 
              
              java.util.Objects.equals(x25519, t.x25519)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Byte.hashCode(scheme);
        result = 31 * result + java.util.Objects.hashCode(mlkemEk);
        result = 31 * result + java.util.Objects.hashCode(x25519);
        return result;
    }

    
    
    

}


