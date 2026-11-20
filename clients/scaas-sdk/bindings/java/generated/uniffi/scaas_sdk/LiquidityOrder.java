package uniffi.scaas_sdk;

/**
 * A liquidity order (`LiquidityOrder`, CTR-DEX-30; dex-liquidity spec §4.2), signed in its DEX's domain.
 */
public class LiquidityOrder {
    private KeyRef signer;
    private java.lang.String chain;
    /**
     * a DEX of the profile's list with its liquidity mark
     */
    private java.lang.String dex;
    private java.util.List<LiquidityToken> inputs;
    private java.util.List<LiquidityToken> outputs;
    private java.lang.String positionManager;
    private java.lang.String positionReader;
    private java.lang.String positionIn;
    /**
     * `0x` + 64 hex; `None`: no position received
     */
    private java.lang.String positionPool;
    private int tickLower;
    private int tickUpper;
    private java.lang.String minLiquidity;
    /**
     * a 32-byte id; `None`: the signer
     */
    private java.lang.String recipient;
    private java.lang.String fee;
    private java.lang.String relayer;
    private byte flags;
    private java.lang.String batch;
    /**
     * the order's nonce (the planner's; no lane is read)
     */
    private java.lang.String nonce;
    private long validUntil;
    /**
     * tokens the plan counts beside its inputs and outputs (at most eight)
     */
    private java.util.List<java.lang.String> extraTokens;
    /**
     * a partial withdraw or fee collect (it must receive the position back)
     */
    private boolean partial;

    public LiquidityOrder(
        KeyRef signer, 
        java.lang.String chain, 
        java.lang.String dex, 
        java.util.List<LiquidityToken> inputs, 
        java.util.List<LiquidityToken> outputs, 
        java.lang.String positionManager, 
        java.lang.String positionReader, 
        java.lang.String positionIn, 
        java.lang.String positionPool, 
        int tickLower, 
        int tickUpper, 
        java.lang.String minLiquidity, 
        java.lang.String recipient, 
        java.lang.String fee, 
        java.lang.String relayer, 
        byte flags, 
        java.lang.String batch, 
        java.lang.String nonce, 
        long validUntil, 
        java.util.List<java.lang.String> extraTokens, 
        boolean partial
    ) {
        
        this.signer = signer;
        
        this.chain = chain;
        
        this.dex = dex;
        
        this.inputs = inputs;
        
        this.outputs = outputs;
        
        this.positionManager = positionManager;
        
        this.positionReader = positionReader;
        
        this.positionIn = positionIn;
        
        this.positionPool = positionPool;
        
        this.tickLower = tickLower;
        
        this.tickUpper = tickUpper;
        
        this.minLiquidity = minLiquidity;
        
        this.recipient = recipient;
        
        this.fee = fee;
        
        this.relayer = relayer;
        
        this.flags = flags;
        
        this.batch = batch;
        
        this.nonce = nonce;
        
        this.validUntil = validUntil;
        
        this.extraTokens = extraTokens;
        
        this.partial = partial;
    }
    
    public KeyRef signer() {
        return this.signer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String dex() {
        return this.dex;
    }
    
    public java.util.List<LiquidityToken> inputs() {
        return this.inputs;
    }
    
    public java.util.List<LiquidityToken> outputs() {
        return this.outputs;
    }
    
    public java.lang.String positionManager() {
        return this.positionManager;
    }
    
    public java.lang.String positionReader() {
        return this.positionReader;
    }
    
    public java.lang.String positionIn() {
        return this.positionIn;
    }
    
    public java.lang.String positionPool() {
        return this.positionPool;
    }
    
    public int tickLower() {
        return this.tickLower;
    }
    
    public int tickUpper() {
        return this.tickUpper;
    }
    
    public java.lang.String minLiquidity() {
        return this.minLiquidity;
    }
    
    public java.lang.String recipient() {
        return this.recipient;
    }
    
    public java.lang.String fee() {
        return this.fee;
    }
    
    public java.lang.String relayer() {
        return this.relayer;
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
    
    public java.util.List<java.lang.String> extraTokens() {
        return this.extraTokens;
    }
    
    public boolean partial() {
        return this.partial;
    }
    public void setSigner(KeyRef signer) {
        this.signer = signer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setDex(java.lang.String dex) {
        this.dex = dex;
    }
    public void setInputs(java.util.List<LiquidityToken> inputs) {
        this.inputs = inputs;
    }
    public void setOutputs(java.util.List<LiquidityToken> outputs) {
        this.outputs = outputs;
    }
    public void setPositionManager(java.lang.String positionManager) {
        this.positionManager = positionManager;
    }
    public void setPositionReader(java.lang.String positionReader) {
        this.positionReader = positionReader;
    }
    public void setPositionIn(java.lang.String positionIn) {
        this.positionIn = positionIn;
    }
    public void setPositionPool(java.lang.String positionPool) {
        this.positionPool = positionPool;
    }
    public void setTickLower(int tickLower) {
        this.tickLower = tickLower;
    }
    public void setTickUpper(int tickUpper) {
        this.tickUpper = tickUpper;
    }
    public void setMinLiquidity(java.lang.String minLiquidity) {
        this.minLiquidity = minLiquidity;
    }
    public void setRecipient(java.lang.String recipient) {
        this.recipient = recipient;
    }
    public void setFee(java.lang.String fee) {
        this.fee = fee;
    }
    public void setRelayer(java.lang.String relayer) {
        this.relayer = relayer;
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
    public void setExtraTokens(java.util.List<java.lang.String> extraTokens) {
        this.extraTokens = extraTokens;
    }
    public void setPartial(boolean partial) {
        this.partial = partial;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof LiquidityOrder) {
            LiquidityOrder t = (LiquidityOrder) other;
            return (
              java.util.Objects.equals(signer, t.signer) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(dex, t.dex) && 
              
              java.util.Objects.equals(inputs, t.inputs) && 
              
              java.util.Objects.equals(outputs, t.outputs) && 
              
              java.util.Objects.equals(positionManager, t.positionManager) && 
              
              java.util.Objects.equals(positionReader, t.positionReader) && 
              
              java.util.Objects.equals(positionIn, t.positionIn) && 
              
              java.util.Objects.equals(positionPool, t.positionPool) && 
              
              tickLower == t.tickLower && 
              
              tickUpper == t.tickUpper && 
              
              java.util.Objects.equals(minLiquidity, t.minLiquidity) && 
              
              java.util.Objects.equals(recipient, t.recipient) && 
              
              java.util.Objects.equals(fee, t.fee) && 
              
              java.util.Objects.equals(relayer, t.relayer) && 
              
              flags == t.flags && 
              
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(nonce, t.nonce) && 
              
              validUntil == t.validUntil && 
              
              java.util.Objects.equals(extraTokens, t.extraTokens) && 
              
              partial == t.partial
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(dex);
        result = 31 * result + java.util.Objects.hashCode(inputs);
        result = 31 * result + java.util.Objects.hashCode(outputs);
        result = 31 * result + java.util.Objects.hashCode(positionManager);
        result = 31 * result + java.util.Objects.hashCode(positionReader);
        result = 31 * result + java.util.Objects.hashCode(positionIn);
        result = 31 * result + java.util.Objects.hashCode(positionPool);
        result = 31 * result + java.lang.Integer.hashCode(tickLower);
        result = 31 * result + java.lang.Integer.hashCode(tickUpper);
        result = 31 * result + java.util.Objects.hashCode(minLiquidity);
        result = 31 * result + java.util.Objects.hashCode(recipient);
        result = 31 * result + java.util.Objects.hashCode(fee);
        result = 31 * result + java.util.Objects.hashCode(relayer);
        result = 31 * result + java.lang.Byte.hashCode(flags);
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(nonce);
        result = 31 * result + java.lang.Long.hashCode(validUntil);
        result = 31 * result + java.util.Objects.hashCode(extraTokens);
        result = 31 * result + java.lang.Boolean.hashCode(partial);
        return result;
    }

    
    
    

}


