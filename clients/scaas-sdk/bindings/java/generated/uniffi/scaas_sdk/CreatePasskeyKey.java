package uniffi.scaas_sdk;

/**
 * `create_passkey_key`: a new passkey of the deployment's RP ID (`SdkConfig::rp_id`), named `name` beside seed `seed`.
 */
public class CreatePasskeyKey {
    private java.lang.String seed;
    private java.lang.String name;

    public CreatePasskeyKey(
        java.lang.String seed, 
        java.lang.String name
    ) {
        
        this.seed = seed;
        
        this.name = name;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof CreatePasskeyKey) {
            CreatePasskeyKey t = (CreatePasskeyKey) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(name, t.name)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(name);
        return result;
    }

    
    
    

}


