package uniffi.scaas_sdk;

/**
 * The DEX (spec §10).
 */
public interface DexInterface {
    public java.util.concurrent.CompletableFuture<java.lang.String> cancelAll(CancelAll req) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> depth(java.lang.String chain, long market, java.lang.Integer levels) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> markets(java.lang.String chain) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> orders(java.lang.String chain, java.lang.String maker) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> place(PreparedOrder order) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareCancelOrder(CancelOrder req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareCancelWrapOrder(CancelWrapOrder req) ;
    public java.util.concurrent.CompletableFuture<PreparedOrder> prepareLiquidityOrder(LiquidityOrder req) ;
    public java.util.concurrent.CompletableFuture<PreparedOrder> prepareTradeOrder(TradeOrder req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareWrapOrder(WrapOrder req) ;
    public java.util.concurrent.CompletableFuture<SignedOrder> signOrder(PreparedOrder order) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> ticker(java.lang.String chain, long market) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> trades(java.lang.String chain, long market) ;
    
}

