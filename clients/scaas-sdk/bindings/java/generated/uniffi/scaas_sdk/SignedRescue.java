package uniffi.scaas_sdk;

/**
 * A signed rescue-vault operation: its typed digest and the admin's 65-byte signature, both `0x` hex.
 */
public class SignedRescue {
    private java.lang.String digest;
    private java.lang.String signature;

    public SignedRescue(
        java.lang.String digest, 
        java.lang.String signature
    ) {
        
        this.digest = digest;
        
        this.signature = signature;
    }
    
    public java.lang.String digest() {
        return this.digest;
    }
    
    public java.lang.String signature() {
        return this.signature;
    }
    public void setDigest(java.lang.String digest) {
        this.digest = digest;
    }
    public void setSignature(java.lang.String signature) {
        this.signature = signature;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SignedRescue) {
            SignedRescue t = (SignedRescue) other;
            return (
              java.util.Objects.equals(digest, t.digest) && 
              
              java.util.Objects.equals(signature, t.signature)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(digest);
        result = 31 * result + java.util.Objects.hashCode(signature);
        return result;
    }

    
    
    

}


