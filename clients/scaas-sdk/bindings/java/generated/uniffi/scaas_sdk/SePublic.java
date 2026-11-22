package uniffi.scaas_sdk;

/**
 * A secure-element key's handle and public key data (`p256` 0x0101).
 */
public class SePublic {
    private java.lang.String handle;
    private byte[] keyData;

    public SePublic(
        java.lang.String handle, 
        byte[] keyData
    ) {
        
        this.handle = handle;
        
        this.keyData = keyData;
    }
    
    public java.lang.String handle() {
        return this.handle;
    }
    
    public byte[] keyData() {
        return this.keyData;
    }
    public void setHandle(java.lang.String handle) {
        this.handle = handle;
    }
    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SePublic) {
            SePublic t = (SePublic) other;
            return (
              java.util.Objects.equals(handle, t.handle) && 
              
              java.util.Objects.equals(keyData, t.keyData)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(handle);
        result = 31 * result + java.util.Objects.hashCode(keyData);
        return result;
    }

    
    
    

}


