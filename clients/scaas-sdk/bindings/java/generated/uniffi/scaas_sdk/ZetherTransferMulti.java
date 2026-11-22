package uniffi.scaas_sdk;

/**
 * `UAZetherTransfer` / `UAZetherTransferCompact`: the real `recipients` and `decoys` legs of amount 0 drawn uniformly from
 * the registry's `0x0141` list (CTR-UA-29, the default), every leg's position shuffled. `decoy_fee`: the per-leg fee the
 * token pays (decimal, `"0"` none; the token's `minDecoyFee` is the contract's check). `ua_signer_gas`: the Zether UA's
 * verify gas the prover's gas-cap check adds for the relayed build (zether-prover `uaSignerGas`), the app's figure: a verify
 * row for `0x0141` in the gas tables (chain → module → reference) wins over it (owner 2026-11-19, P1).
 */
public class ZetherTransferMulti {
    private java.lang.String seed;
    private int account;
    private java.lang.String chain;
    private java.lang.String token;
    private java.lang.String batch;
    private java.util.List<ZetherLeg> recipients;
    private int decoys;
    private java.lang.String decoyFee;
    private long uaSignerGas;
    private long validUntilBlock;
    private Envelope envelope;
    private java.lang.Integer tableBits;
    private java.lang.Integer boundBits;

    public ZetherTransferMulti(
        java.lang.String seed, 
        int account, 
        java.lang.String chain, 
        java.lang.String token, 
        java.lang.String batch, 
        java.util.List<ZetherLeg> recipients, 
        int decoys, 
        java.lang.String decoyFee, 
        long uaSignerGas, 
        long validUntilBlock, 
        Envelope envelope, 
        java.lang.Integer tableBits, 
        java.lang.Integer boundBits
    ) {
        
        this.seed = seed;
        
        this.account = account;
        
        this.chain = chain;
        
        this.token = token;
        
        this.batch = batch;
        
        this.recipients = recipients;
        
        this.decoys = decoys;
        
        this.decoyFee = decoyFee;
        
        this.uaSignerGas = uaSignerGas;
        
        this.validUntilBlock = validUntilBlock;
        
        this.envelope = envelope;
        
        this.tableBits = tableBits;
        
        this.boundBits = boundBits;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public int account() {
        return this.account;
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
    
    public java.util.List<ZetherLeg> recipients() {
        return this.recipients;
    }
    
    public int decoys() {
        return this.decoys;
    }
    
    public java.lang.String decoyFee() {
        return this.decoyFee;
    }
    
    public long uaSignerGas() {
        return this.uaSignerGas;
    }
    
    public long validUntilBlock() {
        return this.validUntilBlock;
    }
    
    public Envelope envelope() {
        return this.envelope;
    }
    
    public java.lang.Integer tableBits() {
        return this.tableBits;
    }
    
    public java.lang.Integer boundBits() {
        return this.boundBits;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setAccount(int account) {
        this.account = account;
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
    public void setRecipients(java.util.List<ZetherLeg> recipients) {
        this.recipients = recipients;
    }
    public void setDecoys(int decoys) {
        this.decoys = decoys;
    }
    public void setDecoyFee(java.lang.String decoyFee) {
        this.decoyFee = decoyFee;
    }
    public void setUaSignerGas(long uaSignerGas) {
        this.uaSignerGas = uaSignerGas;
    }
    public void setValidUntilBlock(long validUntilBlock) {
        this.validUntilBlock = validUntilBlock;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }
    public void setTableBits(java.lang.Integer tableBits) {
        this.tableBits = tableBits;
    }
    public void setBoundBits(java.lang.Integer boundBits) {
        this.boundBits = boundBits;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ZetherTransferMulti) {
            ZetherTransferMulti t = (ZetherTransferMulti) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              account == t.account && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(recipients, t.recipients) && 
              
              decoys == t.decoys && 
              
              java.util.Objects.equals(decoyFee, t.decoyFee) && 
              
              uaSignerGas == t.uaSignerGas && 
              
              validUntilBlock == t.validUntilBlock && 
              
              java.util.Objects.equals(envelope, t.envelope) && 
              
              java.util.Objects.equals(tableBits, t.tableBits) && 
              
              java.util.Objects.equals(boundBits, t.boundBits)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.lang.Integer.hashCode(account);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(recipients);
        result = 31 * result + java.lang.Integer.hashCode(decoys);
        result = 31 * result + java.util.Objects.hashCode(decoyFee);
        result = 31 * result + java.lang.Long.hashCode(uaSignerGas);
        result = 31 * result + java.lang.Long.hashCode(validUntilBlock);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        result = 31 * result + java.util.Objects.hashCode(tableBits);
        result = 31 * result + java.util.Objects.hashCode(boundBits);
        return result;
    }

    
    
    

}


