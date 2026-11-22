package uniffi.scaas_sdk;

/**
 * Operations: quote, submit, follow (spec §13).
 */
public interface OpInterface {
    public java.util.concurrent.CompletableFuture<BlsMultiPart> blsMultiPart(Prepared prepared, KeyRef member) ;
    
    /**
     * Whether `part` is a valid partial of `prepared`'s group on it (`bls12381-multi`, spec §5.4).
     */public boolean blsMultiPartOk(Prepared prepared, BlsMultiPart part);
    
    /**
     * Member `member`'s PoP part for its group's registration.
     */public BlsMultiPart blsMultiPopPart(KeyRef member) throws SdkException;
    
    /**
     * Whether `part` is a valid PoP part of the group `key_data` (`0x` hex).
     */public boolean blsMultiPopPartOk(java.lang.String keyData, BlsMultiPart part);
    public java.util.concurrent.CompletableFuture<SignedOpBlob> handOff(Prepared prepared) ;
    public java.util.concurrent.CompletableFuture<Prepared> importSigned(SignedOpBlob blob, ImportExpect expect) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> memberSign(Prepared prepared) ;
    public java.util.concurrent.CompletableFuture<SubmitQuote> quote(Prepared prepared, SubmitPath path) ;
    public java.util.concurrent.CompletableFuture<SubmitQuote> quoteRegisterBlsMulti(java.lang.String chain, java.lang.String keyData, KeyRef payer) ;
    public java.util.concurrent.CompletableFuture<SubmitQuote> quoteWithGas(Prepared prepared, SubmitPath path, long gas) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> registerBlsMulti(java.lang.String chain, java.lang.String keyData, java.util.List<BlsMultiPart> parts, SubmitQuote quote) ;
    public java.util.concurrent.CompletableFuture<java.lang.Void> resend(java.lang.String op, SubmitQuote quote) ;
    public java.util.concurrent.CompletableFuture<java.lang.Integer> resume() ;
    public java.util.concurrent.CompletableFuture<OpState> state(java.lang.String op) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> submit(Prepared prepared, SubmitQuote quote) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> submitBlsMulti(Prepared prepared, SubmitQuote quote, java.util.List<BlsMultiPart> parts, boolean surplus) ;
    
}

