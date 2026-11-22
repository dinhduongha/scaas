package uniffi.scaas_sdk;

/**
 * `UAPqzTransfer` / `UAPqzTransferCompact`: the `legs` (their count one the set builds, 1, 2, 4 or 8), `decoy_fee` the per-leg
 * fee (decimal; at least the token's `minDecoyFee`, the contract's check).
 */
public class PqzTransferMulti {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private long keyVersion;
    private java.util.List<PqzLeg> legs;
    private java.lang.String decoyFee;
    private long validUntilBlock;
    private Envelope envelope;

    public PqzTransferMulti(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        long keyVersion, 
        java.util.List<PqzLeg> legs, 
        java.lang.String decoyFee, 
        long validUntilBlock, 
        Envelope envelope
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.keyVersion = keyVersion;
        
        this.legs = legs;
        
        this.decoyFee = decoyFee;
        
        this.validUntilBlock = validUntilBlock;
        
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
    
    public long keyVersion() {
        return this.keyVersion;
    }
    
    public java.util.List<PqzLeg> legs() {
        return this.legs;
    }
    
    public java.lang.String decoyFee() {
        return this.decoyFee;
    }
    
    public long validUntilBlock() {
        return this.validUntilBlock;
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
    public void setKeyVersion(long keyVersion) {
        this.keyVersion = keyVersion;
    }
    public void setLegs(java.util.List<PqzLeg> legs) {
        this.legs = legs;
    }
    public void setDecoyFee(java.lang.String decoyFee) {
        this.decoyFee = decoyFee;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzTransferMulti) {
            PqzTransferMulti t = (PqzTransferMulti) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              keyVersion == t.keyVersion && 
              
              java.util.Objects.equals(legs, t.legs) && 
              
              java.util.Objects.equals(decoyFee, t.decoyFee) && 
              
              validUntilBlock == t.validUntilBlock && 
              
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
        result = 31 * result + java.lang.Long.hashCode(keyVersion);
        result = 31 * result + java.util.Objects.hashCode(legs);
        result = 31 * result + java.util.Objects.hashCode(decoyFee);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


