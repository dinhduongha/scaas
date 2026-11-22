package uniffi.scaas_sdk;

/**
 * The envelope's terms the user chooses (the lane's nonce is read; a pay's lane is its `payLane(entryRef)`).
 */
public class Envelope {
    /**
     * unix seconds on the chain's clock
     */
    private long validUntil;
    /**
     * the fee mode: bit 0 binds `relayer`, bit 1 binds `fee_recipient` (an unbound one is 0 in what is signed), the fee kind
     * above
     */
    private int mode;
    private java.lang.String relayer;
    /**
     * the fee to the relayer in the token's smallest unit, decimal; 0 is a value
     */
    private java.lang.String fee;
    private java.lang.String feeRecipient;

    public Envelope(
        long validUntil, 
        int mode, 
        java.lang.String relayer, 
        java.lang.String fee, 
        java.lang.String feeRecipient
    ) {
        
        this.validUntil = validUntil;
        
        this.mode = mode;
        
        this.relayer = relayer;
        
        this.fee = fee;
        
        this.feeRecipient = feeRecipient;
    }
    
    public long validUntil() {
        return this.validUntil;
    }
    
    public int mode() {
        return this.mode;
    }
    
    public java.lang.String relayer() {
        return this.relayer;
    }
    
    public java.lang.String fee() {
        return this.fee;
    }
    
    public java.lang.String feeRecipient() {
        return this.feeRecipient;
    }
    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }
    public void setMode(int mode) {
        this.mode = mode;
    }
    public void setRelayer(java.lang.String relayer) {
        this.relayer = relayer;
    }
    public void setFee(java.lang.String fee) {
        this.fee = fee;
    }
    public void setFeeRecipient(java.lang.String feeRecipient) {
        this.feeRecipient = feeRecipient;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Envelope) {
            Envelope t = (Envelope) other;
            return (
              validUntil == t.validUntil && 
              
              mode == t.mode && 
              
              java.util.Objects.equals(relayer, t.relayer) && 
              
              java.util.Objects.equals(fee, t.fee) && 
              
              java.util.Objects.equals(feeRecipient, t.feeRecipient)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        result = 31 * result + java.lang.Integer.hashCode(mode);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        result = 31 * result + java.util.Objects.hashCode(fee);
        result = 31 * result + java.util.Objects.hashCode(feeRecipient);
        return result;
    }

    
    
    

}


