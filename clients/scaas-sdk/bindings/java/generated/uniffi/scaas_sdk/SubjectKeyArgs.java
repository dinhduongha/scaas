package uniffi.scaas_sdk;

/**
 * A `SubjectKey` by name: `kind` 1 a passkey (`x`, `y` P-256, `rpIdHash`, `originHash`), 2 a secp256k1 key (`x` its address
 * right-aligned, the rest 0); words as `0x` + 64 hex.
 */
public class SubjectKeyArgs {
    private byte kind;
    private java.lang.String x;
    private java.lang.String y;
    private java.lang.String rpIdHash;
    private java.lang.String originHash;

    public SubjectKeyArgs(
        byte kind, 
        java.lang.String x, 
        java.lang.String y, 
        java.lang.String rpIdHash, 
        java.lang.String originHash
    ) {
        
        this.kind = kind;
        
        this.x = x;
        
        this.y = y;
        
        this.rpIdHash = rpIdHash;
        
        this.originHash = originHash;
    }
    
    public byte kind() {
        return this.kind;
    }
    
    public java.lang.String x() {
        return this.x;
    }
    
    public java.lang.String y() {
        return this.y;
    }
    
    public java.lang.String rpIdHash() {
        return this.rpIdHash;
    }
    
    public java.lang.String originHash() {
        return this.originHash;
    }
    public void setKind(byte kind) {
        this.kind = kind;
    }
    public void setX(java.lang.String x) {
        this.x = x;
    }
    public void setY(java.lang.String y) {
        this.y = y;
    }
    public void setRpIdHash(java.lang.String rpIdHash) {
        this.rpIdHash = rpIdHash;
    }
    public void setOriginHash(java.lang.String originHash) {
        this.originHash = originHash;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SubjectKeyArgs) {
            SubjectKeyArgs t = (SubjectKeyArgs) other;
            return (
              kind == t.kind && 
              
              java.util.Objects.equals(x, t.x) && 
              
              java.util.Objects.equals(y, t.y) && 
              
              java.util.Objects.equals(rpIdHash, t.rpIdHash) && 
              
              java.util.Objects.equals(originHash, t.originHash)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Byte.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(x);
        result = 31 * result + java.util.Objects.hashCode(y);
        result = 31 * result + java.util.Objects.hashCode(rpIdHash);
        result = 31 * result + java.util.Objects.hashCode(originHash);
        return result;
    }

    
    
    

}


