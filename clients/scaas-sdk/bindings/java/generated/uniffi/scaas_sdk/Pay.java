package uniffi.scaas_sdk;

/**
 * `mtxPay`: a `UAMetaTransfer` whose `entryRef` is `metaPayId(meta)`, on its pay lane, signed under `Expect::PayMeta`.
 */
public class Pay {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String to;
    private java.lang.String value;
    private PayMeta meta;
    private Envelope envelope;

    public Pay(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String to, 
        java.lang.String value, 
        PayMeta meta, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.to = to;
        
        this.value = value;
        
        this.meta = meta;
        
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
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Pay) {
            Pay t = (Pay) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(meta, t.meta) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


