package uniffi.scaas_sdk;

/**
 * A PQZ balance read (spec §9.2, §9.4): the account of the UA key `signer` (a PQZ-capable kind, `KeyRef::Ua`) at key
 * version `key_version`, whose PQZ key is the wallet's `pqz_key_version(account, index, key_version)` of the same account and
 * index (spec §7).
 */
public class PqzBalanceRequest {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * the token, `0x` + 40 hex
     */
    private java.lang.String token;
    private long keyVersion;

    public PqzBalanceRequest(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        long keyVersion
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.keyVersion = keyVersion;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public long keyVersion() {
        return this.keyVersion;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setKeyVersion(long keyVersion) {
        this.keyVersion = keyVersion;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzBalanceRequest) {
            PqzBalanceRequest t = (PqzBalanceRequest) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              keyVersion == t.keyVersion
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.lang.Long.hashCode(keyVersion);
        return result;
    }

    
    
    

}


