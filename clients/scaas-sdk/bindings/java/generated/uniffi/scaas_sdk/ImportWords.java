package uniffi.scaas_sdk;

/**
 * `vault.import_words`'s request: 12 to 24 English words as a secret.
 */
public class ImportWords implements AutoCloseable{
    private java.lang.String label;
    private SecretBytes words;
    private SecretBytes vaultPassphrase;

    public ImportWords(
        java.lang.String label, 
        SecretBytes words, 
        SecretBytes vaultPassphrase
    ) {
        
        this.label = label;
        
        this.words = words;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public SecretBytes words() {
        return this.words;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setWords(SecretBytes words) {
        this.words = words;
    }
    public void setVaultPassphrase(SecretBytes vaultPassphrase) {
        this.vaultPassphrase = vaultPassphrase;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.label, 
        this.words, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ImportWords) {
            ImportWords t = (ImportWords) other;
            return (
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(words, t.words) && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(words);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


