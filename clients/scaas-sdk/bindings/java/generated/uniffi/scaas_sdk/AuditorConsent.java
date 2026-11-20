package uniffi.scaas_sdk;

/**
 * The new auditor's consent to a set-auditor (spec 2026-11-18 set-auditor §5.2): `AuditorConsent(token, auditor, epoch,
 * chainUid)` in the confidential token's domain.
 */
public class AuditorConsent {
    /**
     * PQZ: the auditor's UA key; Zether: the auditor's Zether UA (`kind` 0x0141)
     */
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private int epoch;

    public AuditorConsent(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        int epoch
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.epoch = epoch;
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
    
    public int epoch() {
        return this.epoch;
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
    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AuditorConsent) {
            AuditorConsent t = (AuditorConsent) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              epoch == t.epoch
              
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
        result = 31 * result + java.lang.Integer.hashCode(epoch);
        return result;
    }

    
    
    

}


