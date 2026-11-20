package uniffi.scaas_sdk;

/**
 * The KEM key of version 0 a hash-commit registration carries beside its arguments.
 */
public class KemRecord {
    private long version;
    /**
     * `0x` hex: `mlkemEk ‖ x25519` (`scaas-ua` `kem_pk`)
     */
    private java.lang.String kemPk;

    public KemRecord(
        long version, 
        java.lang.String kemPk
    ) {
        
        this.version = version;
        
        this.kemPk = kemPk;
    }
    
    public long version() {
        return this.version;
    }
    
    public java.lang.String kemPk() {
        return this.kemPk;
    }
    public void setVersion(long version) {
        this.version = version;
    }
    public void setKemPk(java.lang.String kemPk) {
        this.kemPk = kemPk;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof KemRecord) {
            KemRecord t = (KemRecord) other;
            return (
              version == t.version && 
              
              java.util.Objects.equals(kemPk, t.kemPk)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(version);
        result = 31 * result + java.util.Objects.hashCode(kemPk);
        return result;
    }

    
    
    

}


