package uniffi.scaas_sdk;

/**
 * Tokens, balances, payments (spec §8).
 */
public interface WalletInterface {
    public java.util.concurrent.CompletableFuture<Balances> balances(java.lang.String id, java.lang.String chain) ;
    public java.util.concurrent.CompletableFuture<HistoryPage> history(java.lang.String account, java.lang.String chain, Cursor before, int limit) ;
    public java.util.concurrent.CompletableFuture<NativeAddress> nativeAddress(NativeKeyRef key, java.lang.Short ss58Prefix) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareAddReserve(AddReserve req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareBurn(Burn req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareCancelNonce(CancelNonce req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareDelegateRevoke(DelegateRevoke req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareExecute(Execute req) ;
    public java.util.concurrent.CompletableFuture<NativeQuote> prepareNativeSend(NativeSend req) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePay(Pay req) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePayUnderMandate(PayUnderMandate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePayWithTax(PayWithTax req) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePayeeFee(PayeeFee req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareRelayFee(RelayFee req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareRevokeMandate(RevokeMandate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSetMandate(SetMandate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSetPayee(SetPayee req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareTransfer(Transfer req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareUnwrap(Unwrap req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareUnwrapLeg(UnwrapLeg req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareUnwrapToUa(UnwrapToUa req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareWrap(Wrap req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareWrapLeg(WrapLeg req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareWrapToUa(WrapToUa req) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> submitNativeSend(NativeQuote q) ;
    public java.util.concurrent.CompletableFuture<java.util.List<TokenInfo>> tokens(java.lang.String chain, boolean withIndex) ;
    
}

