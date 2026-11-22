package uniffi.scaas_sdk;

/**
 * A registration as the registry holds it (`registration_of`).
 */
public class RegistrationState {
    private boolean registered;
    /**
     * the hash commit of the KEM key (`attrs.kemPkHash`, `0x` + 64 hex; all zero: none)
     */
    private java.lang.String kemPkHash;
    /**
     * the KEM key of version 0 is stored (a commit filled, or the full key given at `register`)
     */
    private boolean kemStored;
    /**
     * the PQZ key of version 0 has its proof stored (`pqzPopOf`; owner 2026-11-19, S2)
     */
    private boolean pqzPopStored;
    /**
     * and a PoP verifier checked it (`pqzKeyAt(…).proven`; false on a chain with none)
     */
    private boolean pqzProven;

    public RegistrationState(
        boolean registered, 
        java.lang.String kemPkHash, 
        boolean kemStored, 
        boolean pqzPopStored, 
        boolean pqzProven
    ) {
        
        this.registered = registered;
        
        this.kemPkHash = kemPkHash;
        
        this.kemStored = kemStored;
        
        this.pqzPopStored = pqzPopStored;
        
        this.pqzProven = pqzProven;
    }
    
    public boolean registered() {
        return this.registered;
    }
    
    public java.lang.String kemPkHash() {
        return this.kemPkHash;
    }
    
    public boolean kemStored() {
        return this.kemStored;
    }
    
    public boolean pqzPopStored() {
        return this.pqzPopStored;
    }
    
    public boolean pqzProven() {
        return this.pqzProven;
    }
    public void setRegistered(boolean registered) {
        this.registered = registered;
    }
    public void setKemPkHash(java.lang.String kemPkHash) {
        this.kemPkHash = kemPkHash;
    }
    public void setKemStored(boolean kemStored) {
        this.kemStored = kemStored;
    }
    public void setPqzPopStored(boolean pqzPopStored) {
        this.pqzPopStored = pqzPopStored;
    }
    public void setPqzProven(boolean pqzProven) {
        this.pqzProven = pqzProven;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RegistrationState) {
            RegistrationState t = (RegistrationState) other;
            return (
              registered == t.registered && 
              
              java.util.Objects.equals(kemPkHash, t.kemPkHash) && 
              
              kemStored == t.kemStored && 
              
              pqzPopStored == t.pqzPopStored && 
              
              pqzProven == t.pqzProven
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Boolean.hashCode(registered);
        result = 31 * result + java.util.Objects.hashCode(kemPkHash);
        result = 31 * result + java.lang.Boolean.hashCode(kemStored);
        result = 31 * result + java.lang.Boolean.hashCode(pqzPopStored);
        result = 31 * result + java.lang.Boolean.hashCode(pqzProven);
        return result;
    }

    
    
    

}


