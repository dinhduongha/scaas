package uniffi.scaas_sdk;

/**
 * A verify row (gas table v2): what a signer of UA kind `signer` (`0`: a native EVM key, the reference) adds over the
 * reference signer's execution gas.
 */
public class GasVerify {
    private short signer;
    private long gas;
    /**
     * the signer kind's signature length in calldata, `UASig` key data and signature ABI-padded (owner 2026-11-19, ruling
     * 2; for an `msig`, per member); the quote adds 64 gas a byte of it. Required in every row (owner 2026-11-19, A4); a
     * variable-length kind's longest (A5)
     */
    private long sigBytes;
    /**
     * a safety margin added to the row's gas, where the kind's worst case cannot be determined and the row is the most
     * expensive of many measurements (owner 2026-11-19, the sampled check's ruling 2 (b)); 0 when absent
     */
    private long margin;
    /**
     * the part that grows with a count of the signer's (owner 2026-11-19, I1: `members`, a `0x0121` UA's n); `None`: none
     */
    private GasPerItem perItem;
    /**
     * the registry line's columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65); all absent: the holder's own
     * check on any registry (every row before the line)
     */
    private GasLine line;

    public GasVerify(
        short signer, 
        long gas, 
        long sigBytes, 
        long margin, 
        GasPerItem perItem, 
        GasLine line
    ) {
        
        this.signer = signer;
        
        this.gas = gas;
        
        this.sigBytes = sigBytes;
        
        this.margin = margin;
        
        this.perItem = perItem;
        
        this.line = line;
    }
    
    public short signer() {
        return this.signer;
    }
    
    public long gas() {
        return this.gas;
    }
    
    public long sigBytes() {
        return this.sigBytes;
    }
    
    public long margin() {
        return this.margin;
    }
    
    public GasPerItem perItem() {
        return this.perItem;
    }
    
    public GasLine line() {
        return this.line;
    }
    public void setSigner(short signer) {
        this.signer = signer;
    }
    public void setGas(long gas) {
        this.gas = gas;
    }
    public void setSigBytes(long sigBytes) {
        this.sigBytes = sigBytes;
    }
    public void setMargin(long margin) {
        this.margin = margin;
    }
    public void setPerItem(GasPerItem perItem) {
        this.perItem = perItem;
    }
    public void setLine(GasLine line) {
        this.line = line;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasVerify) {
            GasVerify t = (GasVerify) other;
            return (
              signer == t.signer && 
              
              gas == t.gas && 
              
              sigBytes == t.sigBytes && 
              
              margin == t.margin && 
              
              java.util.Objects.equals(perItem, t.perItem) && 
              
              java.util.Objects.equals(line, t.line)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Short.hashCode(signer);
        result = 31 * result + java.lang.Long.hashCode(gas);
        result = 31 * result + java.lang.Long.hashCode(sigBytes);
        result = 31 * result + java.lang.Long.hashCode(margin);
        result = 31 * result + java.util.Objects.hashCode(perItem);
        result = 31 * result + java.util.Objects.hashCode(line);
        return result;
    }

    
    
    

}


