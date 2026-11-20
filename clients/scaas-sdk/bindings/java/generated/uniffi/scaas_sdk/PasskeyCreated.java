package uniffi.scaas_sdk;

/**
 * A new passkey: its credential id and its key data (`webauthn-p256` 0x0100).
 */
public class PasskeyCreated {
    private byte[] credentialId;
    private byte[] keyData;

    public PasskeyCreated(
        byte[] credentialId, 
        byte[] keyData
    ) {
        
        this.credentialId = credentialId;
        
        this.keyData = keyData;
    }
    
    public byte[] credentialId() {
        return this.credentialId;
    }
    
    public byte[] keyData() {
        return this.keyData;
    }
    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }
    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PasskeyCreated) {
            PasskeyCreated t = (PasskeyCreated) other;
            return (
              java.util.Objects.equals(credentialId, t.credentialId) && 
              
              java.util.Objects.equals(keyData, t.keyData)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(credentialId);
        result = 31 * result + java.util.Objects.hashCode(keyData);
        return result;
    }

    
    
    

}


