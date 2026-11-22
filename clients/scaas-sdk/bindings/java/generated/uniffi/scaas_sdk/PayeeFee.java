package uniffi.scaas_sdk;

/**
 * `UAPayeeFee` (CTR-MTX-86): the payee's co-signature of its fee over the payment it expects; signed by the payee.
 */
public class PayeeFee {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private Payment payment;
    private PayMeta meta;
    private PayerAuth payerAuth;
    private java.lang.String fee;
    private java.lang.String feeRecipient;
    private long validUntil;

    public PayeeFee(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        Payment payment, 
        PayMeta meta, 
        PayerAuth payerAuth, 
        java.lang.String fee, 
        java.lang.String feeRecipient, 
        long validUntil
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.payment = payment;
        
        this.meta = meta;
        
        this.payerAuth = payerAuth;
        
        this.fee = fee;
        
        this.feeRecipient = feeRecipient;
        
        this.validUntil = validUntil;
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
    
    public Payment payment() {
        return this.payment;
    }
    
    public PayMeta meta() {
        return this.meta;
    }
    
    public PayerAuth payerAuth() {
        return this.payerAuth;
    }
    
    public java.lang.String fee() {
        return this.fee;
    }
    
    public java.lang.String feeRecipient() {
        return this.feeRecipient;
    }
    
    public long validUntil() {
        return this.validUntil;
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
    public void setPayment(Payment payment) {
        this.payment = payment;
    }
    public void setMeta(PayMeta meta) {
        this.meta = meta;
    }
    public void setPayerAuth(PayerAuth payerAuth) {
        this.payerAuth = payerAuth;
    }
    public void setFee(java.lang.String fee) {
        this.fee = fee;
    }
    public void setFeeRecipient(java.lang.String feeRecipient) {
        this.feeRecipient = feeRecipient;
    }
    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PayeeFee) {
            PayeeFee t = (PayeeFee) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(payment, t.payment) && 
              
              java.util.Objects.equals(meta, t.meta) && 
              
              java.util.Objects.equals(payerAuth, t.payerAuth) && 
              
              java.util.Objects.equals(fee, t.fee) && 
              
              java.util.Objects.equals(feeRecipient, t.feeRecipient) && 
              
              validUntil == t.validUntil
              
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
        result = 31 * result + java.util.Objects.hashCode(payment);
        result = 31 * result + java.util.Objects.hashCode(meta);
        result = 31 * result + java.util.Objects.hashCode(payerAuth);
        result = 31 * result + java.util.Objects.hashCode(fee);
        result = 31 * result + java.util.Objects.hashCode(feeRecipient);
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        return result;
    }

    
    
    

}


