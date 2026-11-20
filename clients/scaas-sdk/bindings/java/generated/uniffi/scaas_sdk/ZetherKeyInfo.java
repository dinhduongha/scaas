package uniffi.scaas_sdk;

/**
 * A Zether key's public parts.
 */
public class ZetherKeyInfo {
    /**
     * the UA of kind `zether-bls12381` (0x0141), `0x` + 64 hex
     */
    private java.lang.String ua;
    /**
     * `Y = [x]G`, 128 bytes, `0x` hex
     */
    private java.lang.String y;

    public ZetherKeyInfo(
        java.lang.String ua, 
        java.lang.String y
    ) {
        
        this.ua = ua;
        
        this.y = y;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public java.lang.String y() {
        return this.y;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setY(java.lang.String y) {
        this.y = y;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherKeyInfo) {
            ZetherKeyInfo t = (ZetherKeyInfo) other;
            return (
              java.util.Objects.equals(ua, t.ua) && 
              
              java.util.Objects.equals(y, t.y)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.util.Objects.hashCode(y);
        return result;
    }

    
    
    

}


