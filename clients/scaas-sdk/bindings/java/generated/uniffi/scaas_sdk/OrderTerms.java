package uniffi.scaas_sdk;

/**
 * An order as it was signed: a `TradeOrder`'s 13 named fields, `from` and `destination` 32-byte ids for a SCaaS sell token's
 * `UATradeOrder`, addresses for an outside token's.
 */
public class OrderTerms {
    private java.lang.String from;
    private java.lang.String receiveToken;
    private java.lang.String amount;
    private java.lang.String receiveAmount;
    private java.lang.String minFill;
    private java.lang.String fee;
    private java.lang.String relayer;
    private java.lang.String dex;
    private java.lang.String destination;
    private byte flags;
    private java.lang.String batch;
    private java.lang.String nonce;
    private java.lang.String validUntil;

    public OrderTerms(
        java.lang.String from, 
        java.lang.String receiveToken, 
        java.lang.String amount, 
        java.lang.String receiveAmount, 
        java.lang.String minFill, 
        java.lang.String fee, 
        java.lang.String relayer, 
        java.lang.String dex, 
        java.lang.String destination, 
        byte flags, 
        java.lang.String batch, 
        java.lang.String nonce, 
        java.lang.String validUntil
    ) {
        
        this.from = from;
        
        this.receiveToken = receiveToken;
        
        this.amount = amount;
        
        this.receiveAmount = receiveAmount;
        
        this.minFill = minFill;
        
        this.fee = fee;
        
        this.relayer = relayer;
        
        this.dex = dex;
        
        this.destination = destination;
        
        this.flags = flags;
        
        this.batch = batch;
        
        this.nonce = nonce;
        
        this.validUntil = validUntil;
    }
    
    public java.lang.String from() {
        return this.from;
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
    
    public java.lang.String dex() {
        return this.dex;
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
    
    public java.lang.String validUntil() {
        return this.validUntil;
    }
    public void setFrom(java.lang.String from) {
        this.from = from;
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
    public void setDex(java.lang.String dex) {
        this.dex = dex;
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
    public void setValidUntil(java.lang.String validUntil) {
        this.validUntil = validUntil;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof OrderTerms) {
            OrderTerms t = (OrderTerms) other;
            return (
              java.util.Objects.equals(from, t.from) && 
              
              java.util.Objects.equals(receiveToken, t.receiveToken) && 
              
              java.util.Objects.equals(amount, t.amount) && 
              
              java.util.Objects.equals(receiveAmount, t.receiveAmount) && 
              
              java.util.Objects.equals(minFill, t.minFill) && 
              
              java.util.Objects.equals(fee, t.fee) && 
              
              java.util.Objects.equals(relayer, t.relayer) && 
              
              java.util.Objects.equals(dex, t.dex) && 
              
              java.util.Objects.equals(destination, t.destination) && 
              
              flags == t.flags && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(nonce, t.nonce) && 
              
              java.util.Objects.equals(validUntil, t.validUntil)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(from);
        result = 31 * result + java.util.Objects.hashCode(receiveToken);
        result = 31 * result + java.util.Objects.hashCode(amount);
        result = 31 * result + java.util.Objects.hashCode(receiveAmount);
        result = 31 * result + java.util.Objects.hashCode(minFill);
        result = 31 * result + java.util.Objects.hashCode(fee);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        result = 31 * result + java.util.Objects.hashCode(dex);
        result = 31 * result + java.util.Objects.hashCode(destination);
        result = 31 * result + java.lang.Byte.hashCode(flags);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(nonce);
        result = 31 * result + java.util.Objects.hashCode(validUntil);
        return result;
    }

    
    
    

}


