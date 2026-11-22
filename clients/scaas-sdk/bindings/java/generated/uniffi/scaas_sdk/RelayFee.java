package uniffi.scaas_sdk;

/**
 * `UARelayFee` (CTR-MTX-27): a fee to `payee` for relaying the operation `call`, bound by the hash of its signed calldata; the
 * gateway job carries that operation as its `call` (`scaas-ua` `relay_fee_op`; owner 2026-11-19, ruling F).
 */
public class RelayFee {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    /**
     * the operation paid for: an operation id of this SDK (`Op::submit`'s), signed, on this chain, with a gateway job form;
     * its contract is the signed `target`
     */
    private java.lang.String call;
    private java.lang.String payee;
    private java.lang.String value;
    private java.lang.String batch;
    private long validUntil;
    private java.lang.String relayer;

    public RelayFee(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String call, 
        java.lang.String payee, 
        java.lang.String value, 
        java.lang.String batch, 
        long validUntil, 
        java.lang.String relayer
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.call = call;
        
        this.payee = payee;
        
        this.value = value;
        
        this.batch = batch;
        
        this.validUntil = validUntil;
        
        this.relayer = relayer;
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
    
    public java.lang.String call() {
        return this.call;
    }
    
    public java.lang.String payee() {
        return this.payee;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public long validUntil() {
        return this.validUntil;
    }
    
    public java.lang.String relayer() {
        return this.relayer;
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
    public void setCall(java.lang.String call) {
        this.call = call;
    }
    public void setPayee(java.lang.String payee) {
        this.payee = payee;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }
    public void setRelayer(java.lang.String relayer) {
        this.relayer = relayer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RelayFee) {
            RelayFee t = (RelayFee) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(call, t.call) && 
              
              java.util.Objects.equals(payee, t.payee) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              validUntil == t.validUntil && 
              
              java.util.Objects.equals(relayer, t.relayer)
              
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
        result = 31 * result + java.util.Objects.hashCode(call);
        result = 31 * result + java.util.Objects.hashCode(payee);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        return result;
    }

    
    
    

}


