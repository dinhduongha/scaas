package uniffi.scaas_sdk;

/**
 * A `registerWebAuthn` key, named.
 */
public class WebAuthnArgs {
    private java.lang.String x;
    private java.lang.String y;
    private java.lang.String rpIdHash;

    public WebAuthnArgs(
        java.lang.String x, 
        java.lang.String y, 
        java.lang.String rpIdHash
    ) {
        
        this.x = x;
        
        this.y = y;
        
        this.rpIdHash = rpIdHash;
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
    public void setX(java.lang.String x) {
        this.x = x;
    }
    public void setY(java.lang.String y) {
        this.y = y;
    }
    public void setRpIdHash(java.lang.String rpIdHash) {
        this.rpIdHash = rpIdHash;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof WebAuthnArgs) {
            WebAuthnArgs t = (WebAuthnArgs) other;
            return (
              java.util.Objects.equals(x, t.x) && 
              
              java.util.Objects.equals(y, t.y) && 
              
              java.util.Objects.equals(rpIdHash, t.rpIdHash)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(x);
        result = 31 * result + java.util.Objects.hashCode(y);
        result = 31 * result + java.util.Objects.hashCode(rpIdHash);
        return result;
    }

    
    
    

}


