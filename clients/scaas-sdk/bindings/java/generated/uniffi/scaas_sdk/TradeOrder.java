package uniffi.scaas_sdk;

/**
 * A trade order (`TradeOrder`'s named fields, CTR-DEX-15): sold `amount` of `sell_token` for at least `receive_amount` of
 * `receive_token`, each settlement at least `min_fill` unless it closes the order.
 */
public class TradeOrder {
    private KeyRef signer;
    private java.lang.String chain;
    private java.lang.String sellToken;
    /**
     * a DEX of the profile's list (CLI-SGN-35)
     */
    private java.lang.String dex;
    private java.lang.String receiveToken;
    private java.lang.String amount;
    private java.lang.String receiveAmount;
    private java.lang.String minFill;
    /**
     * the DEX fee rate the order accepts on what it receives, in millionths (at most 10,000)
     */
    private java.lang.String fee;
    private java.lang.String relayer;
    /**
     * `None`: 0 (the signer receives)
     */
    private java.lang.String destination;
    /**
     * 1 IOC, 2 ESCROW (with IOC, SCaaS sell tokens only), 4 reserved by the venue
     */
    private byte flags;
    /**
     * the order lane, decimal (not an envelope's lane)
     */
    private java.lang.String batch;
    /**
     * `None`: the lane's floor (`minNonce(from, batch)` on the sell token, or on the DEX for an outside token) read now
     */
    private java.lang.String nonce;
    /**
     * unix seconds on the chain's clock
     */
    private long validUntil;

    public TradeOrder(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String sellToken, 
        java.lang.String dex, 
        java.lang.String receiveToken, 
        java.lang.String amount, 
        java.lang.String receiveAmount, 
        java.lang.String minFill, 
        java.lang.String fee, 
        java.lang.String relayer, 
        java.lang.String destination, 
        byte flags, 
        java.lang.String batch, 
        java.lang.String nonce, 
        long validUntil
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.sellToken = sellToken;
        
        this.dex = dex;
        
        this.receiveToken = receiveToken;
        
        this.amount = amount;
        
        this.receiveAmount = receiveAmount;
        
        this.minFill = minFill;
        
        this.fee = fee;
        
        this.relayer = relayer;
        
        this.destination = destination;
        
        this.flags = flags;
        
        this.batch = batch;
        
        this.nonce = nonce;
        
        this.validUntil = validUntil;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String sellToken() {
        return this.sellToken;
    }
    
    public java.lang.String dex() {
        return this.dex;
    }
    
    public java.lang.String receiveToken() {
        return this.receiveToken;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    
    public java.lang.String receiveAmount() {
        return this.receiveAmount;
    }
    
    public java.lang.String minFill() {
        return this.minFill;
    }
    
    public java.lang.String fee() {
        return this.fee;
    }
    
    public java.lang.String relayer() {
        return this.relayer;
    }
    
    public java.lang.String destination() {
        return this.destination;
    }
    
    public byte flags() {
        return this.flags;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public java.lang.String nonce() {
        return this.nonce;
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
    public void setSellToken(java.lang.String sellToken) {
        this.sellToken = sellToken;
    }
    public void setDex(java.lang.String dex) {
        this.dex = dex;
    }
    public void setReceiveToken(java.lang.String receiveToken) {
        this.receiveToken = receiveToken;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }
    public void setReceiveAmount(java.lang.String receiveAmount) {
        this.receiveAmount = receiveAmount;
    }
    public void setMinFill(java.lang.String minFill) {
        this.minFill = minFill;
    }
    public void setFee(java.lang.String fee) {
        this.fee = fee;
    }
    public void setRelayer(java.lang.String relayer) {
        this.relayer = relayer;
    }
    public void setDestination(java.lang.String destination) {
        this.destination = destination;
    }
    public void setFlags(byte flags) {
        this.flags = flags;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setNonce(java.lang.String nonce) {
        this.nonce = nonce;
    }
    public void setValidUntil(long validUntil) {
        this.validUntil = validUntil;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof TradeOrder) {
            TradeOrder t = (TradeOrder) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(sellToken, t.sellToken) && 
              
              java.util.Objects.equals(dex, t.dex) && 
              
              java.util.Objects.equals(receiveToken, t.receiveToken) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(receiveAmount, t.receiveAmount) && 
              
              java.util.Objects.equals(minFill, t.minFill) && 
              
              java.util.Objects.equals(fee, t.fee) && 
              
              java.util.Objects.equals(relayer, t.relayer) && 
              
              java.util.Objects.equals(destination, t.destination) && 
              
              flags == t.flags && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(nonce, t.nonce) && 
              
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
        result = 31 * result + java.util.Objects.hashCode(sellToken);
        result = 31 * result + java.util.Objects.hashCode(dex);
        result = 31 * result + java.util.Objects.hashCode(receiveToken);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(receiveAmount);
        result = 31 * result + java.util.Objects.hashCode(minFill);
        result = 31 * result + java.util.Objects.hashCode(fee);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        result = 31 * result + java.util.Objects.hashCode(destination);
        result = 31 * result + java.lang.Byte.hashCode(flags);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(nonce);
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        return result;
    }

    
    
    

}


