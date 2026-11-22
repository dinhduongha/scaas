package uniffi.scaas_sdk;

/**
 * A pay's `PayMeta` v3 (CTR-MTX-26): committed to by the signed `entryRef` (`metaPayId`).
 */
public class PayMeta {
    /**
     * `0x` + 64 hex; `None`: 32 random bytes
     */
    private java.lang.String salt;
    /**
     * a UUIDv7 in its text form, or `0x` + 64 hex; `None`: no number
     */
    private java.lang.String payNo;
    /**
     * store the payment's record under `pay_no` on chain
     */
    private boolean save;
    private PayBody body;

    public PayMeta(
        java.lang.String salt, 
        java.lang.String payNo, 
        boolean save, 
        PayBody body
    ) {
        
        this.salt = salt;
        
        this.payNo = payNo;
        
        this.save = save;
        
        this.body = body;
    }
    
    public java.lang.String salt() {
        return this.salt;
    }
    
    public java.lang.String payNo() {
        return this.payNo;
    }
    
    public boolean save() {
        return this.save;
    }
    
    public PayBody body() {
        return this.body;
    }
    public void setSalt(java.lang.String salt) {
        this.salt = salt;
    }
    public void setPayNo(java.lang.String payNo) {
        this.payNo = payNo;
    }
    public void setSave(boolean save) {
        this.save = save;
    }
    public void setBody(PayBody body) {
        this.body = body;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PayMeta) {
            PayMeta t = (PayMeta) other;
            return (
              java.util.Objects.equals(salt, t.salt) && 
              
              java.util.Objects.equals(payNo, t.payNo) && 
              
              save == t.save && 
              
              java.util.Objects.equals(body, t.body)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(salt);
        result = 31 * result + java.util.Objects.hashCode(payNo);
        result = 31 * result + java.lang.Boolean.hashCode(save);
        result = 31 * result + java.util.Objects.hashCode(body);
        return result;
    }

    
    
    

}


