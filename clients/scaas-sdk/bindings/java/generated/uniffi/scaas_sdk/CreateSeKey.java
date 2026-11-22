package uniffi.scaas_sdk;

/**
 * `create_se_key`: a new secure-element P-256 key under `policy`, named `name` beside seed `seed`.
 */
public class CreateSeKey {
    private java.lang.String seed;
    private java.lang.String name;
    private KeyPolicy policy;

    public CreateSeKey(
        java.lang.String seed, 
        java.lang.String name, 
        KeyPolicy policy
    ) {
        
        this.seed = seed;
        
        this.name = name;
        
        this.policy = policy;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public KeyPolicy policy() {
        return this.policy;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setPolicy(KeyPolicy policy) {
        this.policy = policy;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof CreateSeKey) {
            CreateSeKey t = (CreateSeKey) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(policy, t.policy)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(policy);
        return result;
    }

    
    
    

}


