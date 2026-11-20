package uniffi.scaas_sdk;

/**
 * `UAAttrs`, named.
 */
public class AttrsArgs {
    private java.lang.String pqzKey;
    private java.lang.String pqzPopHash;
    private KemArgs kem;
    private java.lang.String kemPkHash;

    public AttrsArgs(
        java.lang.String pqzKey, 
        java.lang.String pqzPopHash, 
        KemArgs kem, 
        java.lang.String kemPkHash
    ) {
        
        this.pqzKey = pqzKey;
        
        this.pqzPopHash = pqzPopHash;
        
        this.kem = kem;
        
        this.kemPkHash = kemPkHash;
    }
    
    public java.lang.String pqzKey() {
        return this.pqzKey;
    }
    
    public java.lang.String pqzPopHash() {
        return this.pqzPopHash;
    }
    
    public KemArgs kem() {
        return this.kem;
    }
    
    public java.lang.String kemPkHash() {
        return this.kemPkHash;
    }
    public void setPqzKey(java.lang.String pqzKey) {
        this.pqzKey = pqzKey;
    }
    public void setPqzPopHash(java.lang.String pqzPopHash) {
        this.pqzPopHash = pqzPopHash;
    }
    public void setKem(KemArgs kem) {
        this.kem = kem;
    }
    public void setKemPkHash(java.lang.String kemPkHash) {
        this.kemPkHash = kemPkHash;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AttrsArgs) {
            AttrsArgs t = (AttrsArgs) other;
            return (
              java.util.Objects.equals(pqzKey, t.pqzKey) && 
              
              java.util.Objects.equals(pqzPopHash, t.pqzPopHash) && 
              
              java.util.Objects.equals(kem, t.kem) && 
              
              java.util.Objects.equals(kemPkHash, t.kemPkHash)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(pqzKey);
        result = 31 * result + java.util.Objects.hashCode(pqzPopHash);
        result = 31 * result + java.util.Objects.hashCode(kem);
        result = 31 * result + java.util.Objects.hashCode(kemPkHash);
        return result;
    }

    
    
    

}


