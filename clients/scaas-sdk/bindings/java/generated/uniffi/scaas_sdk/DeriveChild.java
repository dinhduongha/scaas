package uniffi.scaas_sdk;

/**
 * `vault.derive_child`'s request: a stored seed (never a hidden set), the child's label and vault passphrase.
 */
public class DeriveChild implements AutoCloseable{
    private java.lang.String parent;
    private java.lang.String label;
    private SecretBytes vaultPassphrase;

    public DeriveChild(
        java.lang.String parent, 
        java.lang.String label, 
        SecretBytes vaultPassphrase
    ) {
        
        this.parent = parent;
        
        this.label = label;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String parent() {
        return this.parent;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
    }
    public void setParent(java.lang.String parent) {
        this.parent = parent;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setVaultPassphrase(SecretBytes vaultPassphrase) {
        this.vaultPassphrase = vaultPassphrase;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.parent, 
        this.label, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof DeriveChild) {
            DeriveChild t = (DeriveChild) other;
            return (
              java.util.Objects.equals(parent, t.parent) && 
              
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(parent);
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


