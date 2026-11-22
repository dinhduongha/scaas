package uniffi.scaas_sdk;

/**
 * `UAPayWithTax` (regulated kinds): the payer's payment and its tax.
 */
public class PayWithTax {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String to;
    private java.lang.String value;
    private PayMeta meta;
    private byte taxMode;
    private java.lang.String tax;
    private Envelope envelope;

    public PayWithTax(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String to, 
        java.lang.String value, 
        PayMeta meta, 
        byte taxMode, 
        java.lang.String tax, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.to = to;
        
        this.value = value;
        
        this.meta = meta;
        
        this.taxMode = taxMode;
        
        this.tax = tax;
        
        this.envelope = envelope;
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
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public PayMeta meta() {
        return this.meta;
    }
    
    public byte taxMode() {
        return this.taxMode;
    }
    
    public java.lang.String tax() {
        return this.tax;
    }
    
    public Envelope envelope() {
        return this.envelope;
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
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setMeta(PayMeta meta) {
        this.meta = meta;
    }
    public void setTaxMode(byte taxMode) {
        this.taxMode = taxMode;
    }
    public void setTax(java.lang.String tax) {
        this.tax = tax;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PayWithTax) {
            PayWithTax t = (PayWithTax) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(meta, t.meta) && 
              
              taxMode == t.taxMode && 
              
              java.util.Objects.equals(tax, t.tax) && 
              
              java.util.Objects.equals(envelope, t.envelope)
              
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
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(meta);
        result = 31 * result + java.lang.Byte.hashCode(taxMode);
        result = 31 * result + java.util.Objects.hashCode(tax);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


