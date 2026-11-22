package uniffi.scaas_sdk;

/**
 * A WebAuthn get-assertion request: the RP ID (the deployment's), a 32-byte challenge, the allowed credentials, the PRF salt.
 */
public class AssertionRequest {
    private java.lang.String rpId;
    private byte[] challenge;
    private java.util.List<byte[]> allow;
    private byte[] prfSalt;

    public AssertionRequest(
        java.lang.String rpId, 
        byte[] challenge, 
        java.util.List<byte[]> allow, 
        byte[] prfSalt
    ) {
        
        this.rpId = rpId;
        
        this.challenge = challenge;
        
        this.allow = allow;
        
        this.prfSalt = prfSalt;
    }
    
    public java.lang.String rpId() {
        return this.rpId;
    }
    
    public byte[] challenge() {
        return this.challenge;
    }
    
    public java.util.List<byte[]> allow() {
        return this.allow;
    }
    
    public byte[] prfSalt() {
        return this.prfSalt;
    }
    public void setRpId(java.lang.String rpId) {
        this.rpId = rpId;
    }
    public void setChallenge(byte[] challenge) {
        this.challenge = challenge;
    }
    public void setAllow(java.util.List<byte[]> allow) {
        this.allow = allow;
    }
    public void setPrfSalt(byte[] prfSalt) {
        this.prfSalt = prfSalt;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AssertionRequest) {
            AssertionRequest t = (AssertionRequest) other;
            return (
              java.util.Objects.equals(rpId, t.rpId) && 
              
              java.util.Objects.equals(challenge, t.challenge) && 
              
              java.util.Objects.equals(allow, t.allow) && 
              
              java.util.Objects.equals(prfSalt, t.prfSalt)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(rpId);
        result = 31 * result + java.util.Objects.hashCode(challenge);
        result = 31 * result + java.util.Objects.hashCode(allow);
        result = 31 * result + java.util.Objects.hashCode(prfSalt);
        return result;
    }

    
    
    

}


