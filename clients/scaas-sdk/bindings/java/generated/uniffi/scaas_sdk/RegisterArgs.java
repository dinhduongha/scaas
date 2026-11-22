package uniffi.scaas_sdk;

/**
 * A single-key registration's arguments by name, as `scaas-ua`'s `registration_args` gives them: `register` (`kind`,
 * `keyData`) or `registerWebAuthn` (`key`); bytes as `0x` hex.
 */
public class RegisterArgs {
    private java.lang.String entry;
    private java.lang.Short kind;
    private java.lang.String keyData;
    private WebAuthnArgs key;
    private AttrsArgs attrs;
    private java.lang.String pqzPop;
    private java.lang.String pop;

    public RegisterArgs(
        java.lang.String entry, 
        java.lang.Short kind, 
        java.lang.String keyData, 
        WebAuthnArgs key, 
        AttrsArgs attrs, 
        java.lang.String pqzPop, 
        java.lang.String pop
    ) {
        
        this.entry = entry;
        
        this.kind = kind;
        
        this.keyData = keyData;
        
        this.key = key;
        
        this.attrs = attrs;
        
        this.pqzPop = pqzPop;
        
        this.pop = pop;
    }
    
    public java.lang.String entry() {
        return this.entry;
    }
    
    public java.lang.Short kind() {
        return this.kind;
    }
    
    public java.lang.String keyData() {
        return this.keyData;
    }
    
    public WebAuthnArgs key() {
        return this.key;
    }
    
    public AttrsArgs attrs() {
        return this.attrs;
    }
    
    public java.lang.String pqzPop() {
        return this.pqzPop;
    }
    
    public java.lang.String pop() {
        return this.pop;
    }
    public void setEntry(java.lang.String entry) {
        this.entry = entry;
    }
    public void setKind(java.lang.Short kind) {
        this.kind = kind;
    }
    public void setKeyData(java.lang.String keyData) {
        this.keyData = keyData;
    }
    public void setKey(WebAuthnArgs key) {
        this.key = key;
    }
    public void setAttrs(AttrsArgs attrs) {
        this.attrs = attrs;
    }
    public void setPqzPop(java.lang.String pqzPop) {
        this.pqzPop = pqzPop;
    }
    public void setPop(java.lang.String pop) {
        this.pop = pop;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RegisterArgs) {
            RegisterArgs t = (RegisterArgs) other;
            return (
              java.util.Objects.equals(entry, t.entry) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              java.util.Objects.equals(keyData, t.keyData) && 
              
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(attrs, t.attrs) && 
              
              java.util.Objects.equals(pqzPop, t.pqzPop) && 
              
              java.util.Objects.equals(pop, t.pop)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(entry);
        result = 31 * result + java.util.Objects.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(keyData);
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(attrs);
        result = 31 * result + java.util.Objects.hashCode(pqzPop);
        result = 31 * result + java.util.Objects.hashCode(pop);
        return result;
    }

    
    
    

}


