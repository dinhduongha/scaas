package uniffi.scaas_sdk;

/**
 * `vault.import_key`'s request (spec §6.7): a classical private key of `network` (32 bytes) as a leaf of a seed, sealed as the
 * new label vault `native-import:<network>:<n>` under the seed's vault passphrase.
 */
public class ImportKey implements AutoCloseable{
    private java.lang.String seed;
    /**
     * `ua-rs`'s network name (`evm`, `cosmos`, `hedera_ecdsa`, `hedera_ed25519`, `sui`, `stellar`, `ton`, `aptos`, `solana`)
     */
    private java.lang.String network;
    private SecretBytes secret;
    private SecretBytes vaultPassphrase;

    public ImportKey(
        java.lang.String seed, 
        java.lang.String network, 
        SecretBytes secret, 
        SecretBytes vaultPassphrase
    ) {
        
        this.seed = seed;
        
        this.network = network;
        
        this.secret = secret;
        
        this.vaultPassphrase = vaultPassphrase;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public SecretBytes secret() {
        return this.secret;
    }
    
    public SecretBytes vaultPassphrase() {
        return this.vaultPassphrase;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setSecret(SecretBytes secret) {
        this.secret = secret;
    }
    public void setVaultPassphrase(SecretBytes vaultPassphrase) {
        this.vaultPassphrase = vaultPassphrase;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.seed, 
        this.network, 
        this.secret, 
        this.vaultPassphrase);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ImportKey) {
            ImportKey t = (ImportKey) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(network, t.network) && 
              
              java.util.Objects.equals(secret, t.secret) && 
              
              java.util.Objects.equals(vaultPassphrase, t.vaultPassphrase)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.util.Objects.hashCode(secret);
        result = 31 * result + java.util.Objects.hashCode(vaultPassphrase);
        return result;
    }

    
    
    

}


