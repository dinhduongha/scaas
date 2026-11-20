package uniffi.scaas_sdk;

/**
 * Zether and PQZ (spec §9).
 */
public interface ConfidentialInterface {
    public java.util.concurrent.CompletableFuture<PqzBalance> pqzBalance(PqzBalanceRequest r) ;
    public java.util.concurrent.CompletableFuture<PqzBalanceAll> pqzBalanceAll(PqzBalanceRequest r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzPrepareAcc(PqzAccountOp r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzRollOver(PqzAccountOp r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzShield(PqzShield r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransfer(PqzTransfer r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferCompact(PqzTransfer r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMulti(PqzTransferMulti r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMultiCompact(PqzTransferMulti r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshield(PqzUnshield r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshieldUnwrap(PqzUnshieldUnwrap r) ;
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzWrapShield(PqzWrapShield r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerRollOver(ZetherOwnerRollOver r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerSetMode(ZetherOwnerSetMode r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOver(ZetherRollOver r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverBatch(ZetherRollOverBatch r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverSigned(ZetherOwnerRollOver r, OwnerRelay relay) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherSetRollOverMode(ZetherOwnerSetMode r, OwnerRelay relay) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherShield(ZetherShield r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransfer(ZetherTransfer r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferCompact(ZetherTransferMulti r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferMulti(ZetherTransferMulti r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshield(ZetherUnshield r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshieldUnwrap(ZetherUnshieldUnwrap r) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherWrapShield(ZetherWrapShield r) ;
    public java.util.concurrent.CompletableFuture<Value> requestVerdict(PqzVerdictRequest r) ;
    public java.util.concurrent.CompletableFuture<ZetherBalance> zetherBalance(ZetherBalanceRequest req) ;
    public java.util.concurrent.CompletableFuture<ZetherKeyInfo> zetherKey(java.lang.String seed, int account) ;
    
}

