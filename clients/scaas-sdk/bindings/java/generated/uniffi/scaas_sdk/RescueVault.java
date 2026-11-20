package uniffi.scaas_sdk;

/**
 * The rescue vault's signature request: the vault's admin key (a native EVM key) and the operation.
 */
public class RescueVault {
    private KeyRef signer;
    private java.lang.String vault;
    private RescueOp op;

    public RescueVault(
        KeyRef signer, 
        java.lang.String vault, 
        RescueOp op
    ) {
        
        this.signer = signer;
        
        this.vault = vault;
        
        this.op = op;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String vault() {
        return this.vault;
    }
    
    public RescueOp op() {
        return this.op;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setVault(java.lang.String vault) {
        this.vault = vault;
    }
    public void setOp(RescueOp op) {
        this.op = op;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RescueVault) {
            RescueVault t = (RescueVault) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(vault, t.vault) && 
              
              java.util.Objects.equals(op, t.op)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.util.Objects.hashCode(vault);
        result = 31 * result + java.util.Objects.hashCode(op);
        return result;
    }

    
    
    

}


