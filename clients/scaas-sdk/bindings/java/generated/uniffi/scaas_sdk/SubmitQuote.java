package uniffi.scaas_sdk;

/**
 * A quote the user confirms (spec §13.3); `submit` takes exactly it. Amounts are decimal strings of wei.
 */
public class SubmitQuote {
    /**
     * `Gateway` or `SelfRelay`, never `Auto`
     */
    private SubmitPath path;
    /**
     * the payer's address (a self-relay): linked on chain to the subject
     */
    private java.lang.String payer;
    /**
     * the self-relay transaction's gas limit (`gas`); 0 on the gateway path, where the holder sends no transaction
     */
    private long gasLimit;
    /**
     * the bound of `gas_limit`'s regular part, with the margin (EIP-8037; controller call, owner auto-run 2026-11-19): the part
     * held to the profile's `tx_gas_cap` (EIP-7825 caps the regular gas only), the whole `gas_limit` where the split is not
     * known (a native send's estimate, an app's figure); 0 on the gateway path
     */
    private long regularGas;
    /**
     * what the operation costs in gas, with the margin, on every path (owner 2026-11-19): on a relayed path for the user and
     * the app only, to choose the token fee; it is not sent to the gateway. `None`: unquoted (no figure anywhere)
     */
    private java.lang.Long gas;
    /**
     * where `gas` came from, its base part and its verify part each (owner 2026-11-19, part 3b): the chain's measured rows,
     * a module table, the reference table; the app's figure or a native send's estimate for both
     */
    private GasSources gasFrom;
    private java.lang.String maxFeePerGas;
    private java.lang.String maxPriorityFeePerGas;
    private java.lang.String maxCost;
    /**
     * the operation's own fee to its relayer, as signed
     */
    private java.lang.String feeToRelayer;
    /**
     * the gateways the body goes to, by index in the profile's list
     */
    private int[] gateways;
    /**
     * the payer's transaction nonce
     */
    private long txNonce;
    /**
     * a self-relay's EIP-2718 type: 2 where the chain's head has a base fee, else 0 (owner 2026-11-18, ruling 3)
     */
    private byte txType;

    public SubmitQuote(
        SubmitPath path, 
        java.lang.String payer, 
        long gasLimit, 
        long regularGas, 
        java.lang.Long gas, 
        GasSources gasFrom, 
        java.lang.String maxFeePerGas, 
        java.lang.String maxPriorityFeePerGas, 
        java.lang.String maxCost, 
        java.lang.String feeToRelayer, 
        int[] gateways, 
        long txNonce, 
        byte txType
    ) {
        
        this.path = path;
        
        this.payer = payer;
        
        this.gasLimit = gasLimit;
        
        this.regularGas = regularGas;
        
        this.gas = gas;
        
        this.gasFrom = gasFrom;
        
        this.maxFeePerGas = maxFeePerGas;
        
        this.maxPriorityFeePerGas = maxPriorityFeePerGas;
        
        this.maxCost = maxCost;
        
        this.feeToRelayer = feeToRelayer;
        
        this.gateways = gateways;
        
        this.txNonce = txNonce;
        
        this.txType = txType;
    }
    
    public SubmitPath path() {
        return this.path;
    }
    
    public java.lang.String payer() {
        return this.payer;
    }
    
    public long gasLimit() {
        return this.gasLimit;
    }
    
    public long regularGas() {
        return this.regularGas;
    }
    
    public java.lang.Long gas() {
        return this.gas;
    }
    
    public GasSources gasFrom() {
        return this.gasFrom;
    }
    
    public java.lang.String maxFeePerGas() {
        return this.maxFeePerGas;
    }
    
    public java.lang.String maxPriorityFeePerGas() {
        return this.maxPriorityFeePerGas;
    }
    
    public java.lang.String maxCost() {
        return this.maxCost;
    }
    
    public java.lang.String feeToRelayer() {
        return this.feeToRelayer;
    }
    
    public int[] gateways() {
        return this.gateways;
    }
    
    public long txNonce() {
        return this.txNonce;
    }
    
    public byte txType() {
        return this.txType;
    }
    public void setPath(SubmitPath path) {
        this.path = path;
    }
    public void setPayer(java.lang.String payer) {
        this.payer = payer;
    }
    public void setGasLimit(long gasLimit) {
        this.gasLimit = gasLimit;
    }
    public void setRegularGas(long regularGas) {
        this.regularGas = regularGas;
    }
    public void setGas(java.lang.Long gas) {
        this.gas = gas;
    }
    public void setGasFrom(GasSources gasFrom) {
        this.gasFrom = gasFrom;
    }
    public void setMaxFeePerGas(java.lang.String maxFeePerGas) {
        this.maxFeePerGas = maxFeePerGas;
    }
    public void setMaxPriorityFeePerGas(java.lang.String maxPriorityFeePerGas) {
        this.maxPriorityFeePerGas = maxPriorityFeePerGas;
    }
    public void setMaxCost(java.lang.String maxCost) {
        this.maxCost = maxCost;
    }
    public void setFeeToRelayer(java.lang.String feeToRelayer) {
        this.feeToRelayer = feeToRelayer;
    }
    public void setGateways(int[] gateways) {
        this.gateways = gateways;
    }
    public void setTxNonce(long txNonce) {
        this.txNonce = txNonce;
    }
    public void setTxType(byte txType) {
        this.txType = txType;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SubmitQuote) {
            SubmitQuote t = (SubmitQuote) other;
            return (
              java.util.Objects.equals(path, t.path) && 
              
              java.util.Objects.equals(payer, t.payer) && 
              
              gasLimit == t.gasLimit && 
              
              regularGas == t.regularGas && 
              
              java.util.Objects.equals(gas, t.gas) && 
              
              java.util.Objects.equals(gasFrom, t.gasFrom) && 
              
              java.util.Objects.equals(maxFeePerGas, t.maxFeePerGas) && 
              
              java.util.Objects.equals(maxPriorityFeePerGas, t.maxPriorityFeePerGas) && 
              
              java.util.Objects.equals(maxCost, t.maxCost) && 
              
              java.util.Objects.equals(feeToRelayer, t.feeToRelayer) && 
              
              java.util.Objects.equals(gateways, t.gateways) && 
              
              txNonce == t.txNonce && 
              
              txType == t.txType
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(path);
        result = 31 * result + java.util.Objects.hashCode(payer);
        result = 31 * result + java.lang.Long.hashCode(gasLimit);
        result = 31 * result + java.lang.Long.hashCode(regularGas);
        result = 31 * result + java.util.Objects.hashCode(gas);
        result = 31 * result + java.util.Objects.hashCode(gasFrom);
        result = 31 * result + java.util.Objects.hashCode(maxFeePerGas);
        result = 31 * result + java.util.Objects.hashCode(maxPriorityFeePerGas);
        result = 31 * result + java.util.Objects.hashCode(maxCost);
        result = 31 * result + java.util.Objects.hashCode(feeToRelayer);
        result = 31 * result + java.util.Objects.hashCode(gateways);
        result = 31 * result + java.lang.Long.hashCode(txNonce);
        result = 31 * result + java.lang.Byte.hashCode(txType);
        return result;
    }

    
    
    

}


