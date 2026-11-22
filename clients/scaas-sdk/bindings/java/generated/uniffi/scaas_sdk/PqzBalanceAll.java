package uniffi.scaas_sdk;

/**
 * Every key version's balance of `signer` on `token` and their sum (P-T16-5): versions `0..=latest`, `latest` the registry's
 * `pqzVersions` word read with version 0's words; each version a [`super::Confidential::pqz_balance`] read of its own fixed
 * word set (R1 to R7), decrypted by its own key.
 */
public class PqzBalanceAll {
    /**
     * the sum, decimal
     */
    private java.lang.String amount;
    /**
     * version `i`'s balance at index `i`
     */
    private java.util.List<PqzBalance> versions;

    public PqzBalanceAll(
        java.lang.String amount, 
        java.util.List<PqzBalance> versions
    ) {
        
        this.amount = amount;
        
        this.versions = versions;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public java.util.List<PqzBalance> versions() {
        return this.versions;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setVersions(java.util.List<PqzBalance> versions) {
        this.versions = versions;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzBalanceAll) {
            PqzBalanceAll t = (PqzBalanceAll) other;
            return (
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(versions, t.versions)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(versions);
        return result;
    }

    
    
    

}


