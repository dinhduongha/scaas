package uniffi.scaas_sdk;

/**
 * `UARollOver`: roll `ua`'s pending balance over (`n`: the entries to take).
 */
public class ZetherRollOver {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.lang.String ua;
    private java.lang.String n;
    private Envelope envelope;

    public ZetherRollOver(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.lang.String ua, 
        java.lang.String n, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.ua = ua;
        
        this.n = n;
        
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
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public java.lang.String n() {
        return this.n;
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
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setN(java.lang.String n) {
        this.n = n;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherRollOver) {
            ZetherRollOver t = (ZetherRollOver) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(ua, t.ua) && 
              
              java.util.Objects.equals(n, t.n) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.util.Objects.hashCode(n);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


