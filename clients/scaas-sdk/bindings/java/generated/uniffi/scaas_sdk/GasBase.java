package uniffi.scaas_sdk;

/**
 * A base row (gas table v2, owner 2026-11-19): the execution gas of `entry` (`mtxCancelNonce`, `mtxExecuteTransfer`, …) on a
 * contract of domain kind `kind` (`token`, `zether`, `pqz`, `wallet`, `account`, `dex`, `gov_router`), on a lane whose nonce
 * is 0 (`fresh`) or above, signed by the reference signer, a native EVM key (its path makes no registry call).
 */
public class GasBase {
    private java.lang.String entry;
    private java.lang.String kind;
    private boolean fresh;
    private long gas;
    /**
     * the part that grows with an input's length (owner 2026-11-19, ruling B)
     */
    private GasPerByte perByte;
    /**
     * the fixed gas added when the operation saves its `PayMeta` record (owner 2026-11-19, ruling 1)
     */
    private java.lang.Long save;
    /**
     * the gas added when the operation's fee is > 0, measured paying a recipient holding nothing (owner 2026-11-19, ruling 3)
     */
    private java.lang.Long feeExtra;
    /**
     * the regular gas a derived-UA signer adds on this entry over the native reference signer, beyond its verify row (owner
     * 2026-11-19, A1: a derived id's ledger debit); added when the signer is a derived UA. `None`: nothing added
     */
    private java.lang.Long uaExtra;
    /**
     * the part that grows with a count the operation names (owner 2026-11-19, I1); `None`: no count, nothing added
     */
    private GasPerItem perItem;
    /**
     * the row's regular gas, its figure's part EIP-7825's per-transaction cap holds under EIP-8037 (controller call, owner
     * auto-run 2026-11-19; at a count of 0 on a counted row, whose `per_item` then carries its slope); `None`: the whole
     * figure is held to the cap
     */
    private java.lang.Long regular;

    public GasBase(
        java.lang.String entry, 
        java.lang.String kind, 
        boolean fresh, 
        long gas, 
        GasPerByte perByte, 
        java.lang.Long save, 
        java.lang.Long feeExtra, 
        java.lang.Long uaExtra, 
        GasPerItem perItem, 
        java.lang.Long regular
    ) {
        
        this.entry = entry;
        
        this.kind = kind;
        
        this.fresh = fresh;
        
        this.gas = gas;
        
        this.perByte = perByte;
        
        this.save = save;
        
        this.feeExtra = feeExtra;
        
        this.uaExtra = uaExtra;
        
        this.perItem = perItem;
        
        this.regular = regular;
    }
    
    public java.lang.String entry() {
        return this.entry;
    }
    
    public java.lang.String kind() {
        return this.kind;
    }
    
    public boolean fresh() {
        return this.fresh;
    }
    
    public long gas() {
        return this.gas;
    }
    
    public GasPerByte perByte() {
        return this.perByte;
    }
    
    public java.lang.Long save() {
        return this.save;
    }
    
    public java.lang.Long feeExtra() {
        return this.feeExtra;
    }
    
    public java.lang.Long uaExtra() {
        return this.uaExtra;
    }
    
    public GasPerItem perItem() {
        return this.perItem;
    }
    
    public java.lang.Long regular() {
        return this.regular;
    }
    public void setEntry(java.lang.String entry) {
        this.entry = entry;
    }
    public void setKind(java.lang.String kind) {
        this.kind = kind;
    }
    public void setFresh(boolean fresh) {
        this.fresh = fresh;
    }
    public void setGas(long gas) {
        this.gas = gas;
    }
    public void setPerByte(GasPerByte perByte) {
        this.perByte = perByte;
    }
    public void setSave(java.lang.Long save) {
        this.save = save;
    }
    public void setFeeExtra(java.lang.Long feeExtra) {
        this.feeExtra = feeExtra;
    }
    public void setUaExtra(java.lang.Long uaExtra) {
        this.uaExtra = uaExtra;
    }
    public void setPerItem(GasPerItem perItem) {
        this.perItem = perItem;
    }
    public void setRegular(java.lang.Long regular) {
        this.regular = regular;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasBase) {
            GasBase t = (GasBase) other;
            return (
              java.util.Objects.equals(entry, t.entry) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              fresh == t.fresh && 
              
              gas == t.gas && 
              
              java.util.Objects.equals(perByte, t.perByte) && 
              
              java.util.Objects.equals(save, t.save) && 
              
              java.util.Objects.equals(feeExtra, t.feeExtra) && 
              
              java.util.Objects.equals(uaExtra, t.uaExtra) && 
              
              java.util.Objects.equals(perItem, t.perItem) && 
              
              java.util.Objects.equals(regular, t.regular)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(entry);
        result = 31 * result + java.util.Objects.hashCode(kind);
        result = 31 * result + java.lang.Boolean.hashCode(fresh);
        result = 31 * result + java.lang.Long.hashCode(gas);
        result = 31 * result + java.util.Objects.hashCode(perByte);
        result = 31 * result + java.util.Objects.hashCode(save);
        result = 31 * result + java.util.Objects.hashCode(feeExtra);
        result = 31 * result + java.util.Objects.hashCode(uaExtra);
        result = 31 * result + java.util.Objects.hashCode(perItem);
        result = 31 * result + java.util.Objects.hashCode(regular);
        return result;
    }

    
    
    

}


