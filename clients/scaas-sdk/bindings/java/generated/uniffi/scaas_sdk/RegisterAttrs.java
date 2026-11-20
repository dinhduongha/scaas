package uniffi.scaas_sdk;

/**
 * What a registration carries besides the key (spec §7): the PQZ key with its `R_REG` proof, the KEM key (version 0).
 */
public class RegisterAttrs {
    private boolean pqzKey;
    private boolean kem;

    public RegisterAttrs(
        boolean pqzKey, 
        boolean kem
    ) {
        
        this.pqzKey = pqzKey;
        
        this.kem = kem;
    }
    
    public boolean pqzKey() {
        return this.pqzKey;
    }
    
    public boolean kem() {
        return this.kem;
    }
    public void setPqzKey(boolean pqzKey) {
        this.pqzKey = pqzKey;
    }
    public void setKem(boolean kem) {
        this.kem = kem;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RegisterAttrs) {
            RegisterAttrs t = (RegisterAttrs) other;
            return (
              pqzKey == t.pqzKey && 
              
              kem == t.kem
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Boolean.hashCode(pqzKey);
        result = 31 * result + java.lang.Boolean.hashCode(kem);
        return result;
    }

    
    
    

}


