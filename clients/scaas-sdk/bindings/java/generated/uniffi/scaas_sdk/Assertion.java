package uniffi.scaas_sdk;

/**
 * A WebAuthn assertion as the platform returns it; `prf` says whether a PRF output was written.
 */
public class Assertion {
    private byte[] credentialId;
    private byte[] authenticatorData;
    private byte[] clientDataJson;
    private byte[] signature;
    private boolean prf;

    public Assertion(
        byte[] credentialId, 
        byte[] authenticatorData, 
        byte[] clientDataJson, 
        byte[] signature, 
        boolean prf
    ) {
        
        this.credentialId = credentialId;
        
        this.authenticatorData = authenticatorData;
        
        this.clientDataJson = clientDataJson;
        
        this.signature = signature;
        
        this.prf = prf;
    }
    
    public byte[] credentialId() {
        return this.credentialId;
    }
    
    public byte[] authenticatorData() {
        return this.authenticatorData;
    }
    
    public byte[] clientDataJson() {
        return this.clientDataJson;
    }
    
    public byte[] signature() {
        return this.signature;
    }
    
    public boolean prf() {
        return this.prf;
    }
    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }
    public void setAuthenticatorData(byte[] authenticatorData) {
        this.authenticatorData = authenticatorData;
    }
    public void setClientDataJson(byte[] clientDataJson) {
        this.clientDataJson = clientDataJson;
    }
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
    public void setPrf(boolean prf) {
        this.prf = prf;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Assertion) {
            Assertion t = (Assertion) other;
            return (
              java.util.Objects.equals(credentialId, t.credentialId) && 
              
              java.util.Objects.equals(authenticatorData, t.authenticatorData) && 
              
              java.util.Objects.equals(clientDataJson, t.clientDataJson) && 
              
              java.util.Objects.equals(signature, t.signature) && 
              
              prf == t.prf
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(credentialId);
        result = 31 * result + java.util.Objects.hashCode(authenticatorData);
        result = 31 * result + java.util.Objects.hashCode(clientDataJson);
        result = 31 * result + java.util.Objects.hashCode(signature);
        result = 31 * result + java.lang.Boolean.hashCode(prf);
        return result;
    }

    
    
    

}


