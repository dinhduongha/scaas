package uniffi.scaas_sdk;

/**
 * A platform key's access policy (biometry of the current enrollment, invalidated by a new one: research decision 8).
 */
public class KeyPolicy {
    private boolean biometryCurrentSet;
    private boolean invalidatedByEnrollment;

    public KeyPolicy(
        boolean biometryCurrentSet, 
        boolean invalidatedByEnrollment
    ) {
        
        this.biometryCurrentSet = biometryCurrentSet;
        
        this.invalidatedByEnrollment = invalidatedByEnrollment;
    }
    
    public boolean biometryCurrentSet() {
        return this.biometryCurrentSet;
    }
    
    public boolean invalidatedByEnrollment() {
        return this.invalidatedByEnrollment;
    }
    public void setBiometryCurrentSet(boolean biometryCurrentSet) {
        this.biometryCurrentSet = biometryCurrentSet;
    }
    public void setInvalidatedByEnrollment(boolean invalidatedByEnrollment) {
        this.invalidatedByEnrollment = invalidatedByEnrollment;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof KeyPolicy) {
            KeyPolicy t = (KeyPolicy) other;
            return (
              biometryCurrentSet == t.biometryCurrentSet && 
              
              invalidatedByEnrollment == t.invalidatedByEnrollment
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Boolean.hashCode(biometryCurrentSet);
        result = 31 * result + java.lang.Boolean.hashCode(invalidatedByEnrollment);
        return result;
    }

    
    
    

}


