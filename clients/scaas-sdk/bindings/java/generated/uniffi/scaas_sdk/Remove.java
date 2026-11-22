package uniffi.scaas_sdk;

/**
 * `vault.remove`'s request.
 */
public class Remove {
    private java.lang.String seed;
    private ConfirmRemove confirm;
    private ConfirmRemoveUnbacked unbacked;

    public Remove(
        java.lang.String seed, 
        ConfirmRemove confirm, 
        ConfirmRemoveUnbacked unbacked
    ) {
        
        this.seed = seed;
        
        this.confirm = confirm;
        
        this.unbacked = unbacked;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public ConfirmRemove confirm() {
        return this.confirm;
    }
    
    public ConfirmRemoveUnbacked unbacked() {
        return this.unbacked;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setConfirm(ConfirmRemove confirm) {
        this.confirm = confirm;
    }
    public void setUnbacked(ConfirmRemoveUnbacked unbacked) {
        this.unbacked = unbacked;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Remove) {
            Remove t = (Remove) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(confirm, t.confirm) && 
              
              java.util.Objects.equals(unbacked, t.unbacked)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(confirm);
        result = 31 * result + java.util.Objects.hashCode(unbacked);
        return result;
    }

    
    
    

}


