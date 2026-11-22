package uniffi.scaas_sdk;

/**
 * `vault.derive_from_signature`'s request (root (c)): the external wallet's account and the seed-set number `set` it signed
 * for, its two signatures of [`Vault::key_derivation_typed_data`] (65 bytes each; a 64-byte EIP-2098 one goes through
 * [`Vault::signature_from_compact`] first), the derivation passphrase (≥ 10 code points), the new seed's label and vault
 * passphrase.
 */
public class DeriveFromSignature implements AutoCloseable{
    private java.lang.String label;
    /**
     * `0x` and 40 hex digits, any case
     */
    private java.lang.String account;
    private int set;
    private SecretBytes signature1;
    private SecretBytes signature2;
    private SecretBytes derivationPassphrase;
    private SecretBytes vaultPassphrase;

    public DeriveFromSignature(
        java.lang.String label, 
        java.lang.String account, 
        int set, 
        SecretBytes signature1, 
        SecretBytes signature2, 
        SecretBytes derivationPassphrase, 
        SecretBytes vaultPassphrase
    ) {
        
        this.label = label;
        
        this.account = account;
        
        this.set = set;
        
        this.signature1 = signature1;
        
        this.signature2 = signature2;
        
        this.derivationPassphrase = derivationPassphrase;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public java.lang.String account() {
        return this.account;
    }
    
    public int set() {
        return this.set;
    }
    
    public SecretBytes signature1() {
        return this.signature1;
    }
    
    public SecretBytes signature2() {
        return this.signature2;
    }
    
    public SecretBytes derivationPassphrase() {
        return this.derivationPassphrase;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setAccount(java.lang.String account) {
        this.account = account;
    }
    public void setSet(int set) {
        this.set = set;
    }
    public void setSignature1(SecretBytes signature1) {
        this.signature1 = signature1;
    }
    public void setSignature2(SecretBytes signature2) {
        this.signature2 = signature2;
    }
    public void setDerivationPassphrase(SecretBytes derivationPassphrase) {
        this.derivationPassphrase = derivationPassphrase;
    }
    public void setVaultPassphrase(SecretBytes vaultPassphrase) {
        this.vaultPassphrase = vaultPassphrase;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.label, 
        this.account, 
        this.set, 
        this.signature1, 
        this.signature2, 
        this.derivationPassphrase, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof DeriveFromSignature) {
            DeriveFromSignature t = (DeriveFromSignature) other;
            return (
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(account, t.account) && 
              
              set == t.set && 
              
              java.util.Objects.equals(signature1, t.signature1) && 
              
              java.util.Objects.equals(signature2, t.signature2) && 
              
              java.util.Objects.equals(derivationPassphrase, t.derivationPassphrase) && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(account);
        result = 31 * result + java.lang.Integer.hashCode(set);
        result = 31 * result + java.util.Objects.hashCode(signature1);
        result = 31 * result + java.util.Objects.hashCode(signature2);
        result = 31 * result + java.util.Objects.hashCode(derivationPassphrase);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


