package uniffi.scaas_sdk;

/**
 * `vault.generate`'s request: the seed's label and its new vault passphrase (vault v1's rule).
 */
public class Generate implements AutoCloseable{
    private java.lang.String label;
    private SecretBytes vaultPassphrase;

    public Generate(
        java.lang.String label, 
        SecretBytes vaultPassphrase
    ) {
        
        this.label = label;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
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
        this.label, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Generate) {
            Generate t = (Generate) other;
            return (
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


