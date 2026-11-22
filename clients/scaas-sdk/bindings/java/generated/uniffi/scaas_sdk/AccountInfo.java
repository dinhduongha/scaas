package uniffi.scaas_sdk;

/**
 * One account row as the app shows it.
 */
public class AccountInfo {
    private java.lang.String id;
    /**
     * The seed the row belongs to (R2).
     */
    private java.lang.String seed;
    private java.lang.String name;
    /**
     * `ua`, `native`, `key` or `watch`.
     */
    private java.lang.String shape;
    private java.lang.Short kind;
    private java.lang.Integer account;
    private java.lang.Integer index;
    private java.lang.String network;
    /**
     * A UA row's or a key row's UA, a native row's address, a watch row's id.
     */
    private java.lang.String idText;
    /**
     * The seed is unlocked and its index MAC verified at unlock (spec §6.2); a locked seed's rows are unverified.
     */
    private boolean verified;
    /**
     * An EVM row whose code is an EIP-7702 designator (`0xef0100…`), from [`Account::marks`]; the SDK builds no type-4
     * transaction, so it cannot offer to clear it (CLI-SDK-31).
     */
    private boolean delegated;

    public AccountInfo(
        java.lang.String id, 
        java.lang.String seed, 
        java.lang.String name, 
        java.lang.String shape, 
        java.lang.Short kind, 
        java.lang.Integer account, 
        java.lang.Integer index, 
        java.lang.String network, 
        java.lang.String idText, 
        boolean verified, 
        boolean delegated
    ) {
        
        this.id = id;
        
        this.seed = seed;
        
        this.name = name;
        
        this.shape = shape;
        
        this.kind = kind;
        
        this.account = account;
        
        this.index = index;
        
        this.network = network;
        
        this.idText = idText;
        
        this.verified = verified;
        
        this.delegated = delegated;
    }
    
    public java.lang.String id() {
        return this.id;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public java.lang.String shape() {
        return this.shape;
    }
    
    public java.lang.Short kind() {
        return this.kind;
    }
    
    public java.lang.Integer account() {
        return this.account;
    }
    
    public java.lang.Integer index() {
        return this.index;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public java.lang.String idText() {
        return this.idText;
    }
    
    public boolean verified() {
        return this.verified;
    }
    
    public boolean delegated() {
        return this.delegated;
    }
    public void setId(java.lang.String id) {
        this.id = id;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setShape(java.lang.String shape) {
        this.shape = shape;
    }
    public void setKind(java.lang.Short kind) {
        this.kind = kind;
    }
    public void setAccount(java.lang.Integer account) {
        this.account = account;
    }
    public void setIndex(java.lang.Integer index) {
        this.index = index;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setIdText(java.lang.String idText) {
        this.idText = idText;
    }
    public void setVerified(boolean verified) {
        this.verified = verified;
    }
    public void setDelegated(boolean delegated) {
        this.delegated = delegated;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AccountInfo) {
            AccountInfo t = (AccountInfo) other;
            return (
              java.util.Objects.equals(id, t.id) && 
              
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(shape, t.shape) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              java.util.Objects.equals(account, t.account) && 
              
              java.util.Objects.equals(index, t.index) && 
              
              java.util.Objects.equals(network, t.network) && 
              
              java.util.Objects.equals(idText, t.idText) && 
              
              verified == t.verified && 
              
              delegated == t.delegated
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(id);
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(shape);
        result = 31 * result + java.util.Objects.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(account);
        result = 31 * result + java.util.Objects.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.util.Objects.hashCode(idText);
        result = 31 * result + java.lang.Boolean.hashCode(verified);
        result = 31 * result + java.lang.Boolean.hashCode(delegated);
        return result;
    }

    
    
    

}


