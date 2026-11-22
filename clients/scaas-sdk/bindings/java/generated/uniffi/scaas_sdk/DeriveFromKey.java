package uniffi.scaas_sdk;

/**
 * `vault.derive_from_key`'s request (root (d)): a 32-byte key of `network` (`evm` only: `Argument` otherwise), the derivation
 * passphrase (empty, or ≥ 10 code points), the seed-set number `index`, the new seed's label and vault passphrase.
 */
public class DeriveFromKey implements AutoCloseable{
    private java.lang.String label;
    private java.lang.String network;
    private SecretBytes key;
    private SecretBytes derivationPassphrase;
    private int index;
    private SecretBytes vaultPassphrase;

    public DeriveFromKey(
        java.lang.String label, 
        java.lang.String network, 
        SecretBytes key, 
        SecretBytes derivationPassphrase, 
        int index, 
        SecretBytes vaultPassphrase
    ) {
        
        this.label = label;
        
        this.network = network;
        
        this.key = key;
        
        this.derivationPassphrase = derivationPassphrase;
        
        this.index = index;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public SecretBytes key() {
        return this.key;
    }
    
    public SecretBytes derivationPassphrase() {
        return this.derivationPassphrase;
    }
    
    public int index() {
        return this.index;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setKey(SecretBytes key) {
        this.key = key;
    }
    public void setDerivationPassphrase(SecretBytes derivationPassphrase) {
        this.derivationPassphrase = derivationPassphrase;
    }
    public void setIndex(int index) {
        this.index = index;
    }
    public void setVaultPassphrase(SecretBytes vaultPassphrase) {
        this.vaultPassphrase = vaultPassphrase;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.label, 
        this.network, 
        this.key, 
        this.derivationPassphrase, 
        this.index, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof DeriveFromKey) {
            DeriveFromKey t = (DeriveFromKey) other;
            return (
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(network, t.network) && 
              
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(derivationPassphrase, t.derivationPassphrase) && 
              
              index == t.index && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(derivationPassphrase);
        result = 31 * result + java.lang.Integer.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


