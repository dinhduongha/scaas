package uniffi.scaas_sdk;

/**
 * `add_ua`: the UA key `kind` of wallet `account` at `index`.
 */
public class AddUa {
    private java.lang.String seed;
    private short kind;
    private int account;
    private int index;
    private java.lang.String name;

    public AddUa(
        java.lang.String seed, 
        short kind, 
        int account, 
        int index, 
        java.lang.String name
    ) {
        
        this.seed = seed;
        
        this.kind = kind;
        
        this.account = account;
        
        this.index = index;
        
        this.name = name;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public short kind() {
        return this.kind;
    }
    
    public int account() {
        return this.account;
    }
    
    public int index() {
        return this.index;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setKind(short kind) {
        this.kind = kind;
    }
    public void setAccount(int account) {
        this.account = account;
    }
    public void setIndex(int index) {
        this.index = index;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AddUa) {
            AddUa t = (AddUa) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              kind == t.kind && 
              
              account == t.account && 
              
              index == t.index && 
              
              java.util.Objects.equals(name, t.name)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.lang.Short.hashCode(kind);
        result = 31 * result + java.lang.Integer.hashCode(account);
        result = 31 * result + java.lang.Integer.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(name);
        return result;
    }

    
    
    

}


