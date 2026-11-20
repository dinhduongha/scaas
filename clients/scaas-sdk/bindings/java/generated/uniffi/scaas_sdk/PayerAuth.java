package uniffi.scaas_sdk;

/**
 * The payer's `UASig` over the payment (no members).
 */
public class PayerAuth {
    /**
     * `0x` hex; `0x` for a native id
     */
    private java.lang.String keyData;
    private java.lang.String signature;

    public PayerAuth(
        java.lang.String keyData, 
        java.lang.String signature
    ) {
        
        this.keyData = keyData;
        
        this.signature = signature;
    }
    
    public java.lang.String keyData() {
        return this.keyData;
    }
    
    public java.lang.String signature() {
        return this.signature;
    }
    public void setKeyData(java.lang.String keyData) {
        this.keyData = keyData;
    }
    public void setSignature(java.lang.String signature) {
        this.signature = signature;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PayerAuth) {
            PayerAuth t = (PayerAuth) other;
            return (
              java.util.Objects.equals(keyData, t.keyData) && 
              
              java.util.Objects.equals(signature, t.signature)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(keyData);
        result = 31 * result + java.util.Objects.hashCode(signature);
        return result;
    }

    
    
    

}


