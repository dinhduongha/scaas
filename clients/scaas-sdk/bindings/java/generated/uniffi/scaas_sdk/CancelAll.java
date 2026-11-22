package uniffi.scaas_sdk;

/**
 * The cancel of every order of one lane below `min_nonce` (`POST /v1/dex/cancel-all`).
 */
public class CancelAll {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String sellToken;
    /**
     * the DEX whose factory names the sell token's form; on the profile's list
     */
    private java.lang.String dex;
    private java.lang.String batch;
    /**
     * `None`: the lane's floor read now plus one (every order signed at the floor)
     */
    private java.lang.String minNonce;

    public CancelAll(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String sellToken, 
        java.lang.String dex, 
        java.lang.String batch, 
        java.lang.String minNonce
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.sellToken = sellToken;
        
        this.dex = dex;
        
        this.batch = batch;
        
        this.minNonce = minNonce;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String sellToken() {
        return this.sellToken;
    }
    
    public java.lang.String dex() {
        return this.dex;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String minNonce() {
        return this.minNonce;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setSellToken(java.lang.String sellToken) {
        this.sellToken = sellToken;
    }
    public void setDex(java.lang.String dex) {
        this.dex = dex;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setMinNonce(java.lang.String minNonce) {
        this.minNonce = minNonce;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof CancelAll) {
            CancelAll t = (CancelAll) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(sellToken, t.sellToken) && 
              
              java.util.Objects.equals(dex, t.dex) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(minNonce, t.minNonce)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(sellToken);
        result = 31 * result + java.util.Objects.hashCode(dex);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(minNonce);
        return result;
    }

    
    
    

}


