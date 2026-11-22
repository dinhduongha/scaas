package uniffi.scaas_sdk;

/**
 * Accounts (spec §7).
 */
public interface AccountInterface {
    public java.util.concurrent.CompletableFuture<java.util.List<AccountInfo>> accounts(java.lang.String seed) ;
    public java.util.concurrent.CompletableFuture<AccountInfo> addNative(AddNative req) ;
    public java.util.concurrent.CompletableFuture<AccountInfo> addUa(AddUa req) ;
    public java.util.concurrent.CompletableFuture<AccountInfo> addWatch(AddWatch req) ;
    public java.util.concurrent.CompletableFuture<KeyRef> createPasskeyKey(CreatePasskeyKey req) ;
    public java.util.concurrent.CompletableFuture<KeyRef> createSeKey(CreateSeKey req) ;
    public java.util.concurrent.CompletableFuture<java.util.List<AccountInfo>> marks(java.lang.String seed, java.lang.String chain) ;
    public java.util.concurrent.CompletableFuture<MsigState> msigState(java.lang.String chain, java.lang.String ua) ;
    public java.util.concurrent.CompletableFuture<java.lang.Integer> nextAccount(java.lang.String seed) ;
    public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> pqzDecoyCandidates(java.lang.String chain) ;
    public java.util.concurrent.CompletableFuture<RegistryWrite> prepareAcceptMembership(AcceptMembership req) ;
    public java.util.concurrent.CompletableFuture<NativeQuote> prepareCompleteRecovery(KeyRef key, java.lang.String chain, java.lang.String account, SubjectKeyArgs newKey) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareInitiateRecovery(SmartOp op, java.lang.String account, SubjectKeyArgs newKey) ;
    public java.util.concurrent.CompletableFuture<RegistryWrite> prepareKemRepair(KeyRef key, java.lang.String chain, KeyRef payer) ;
    public java.util.concurrent.CompletableFuture<java.util.List<RegistryWrite>> prepareMsigRegister(MsigRegister req) ;
    public java.util.concurrent.CompletableFuture<java.util.List<RegistryWrite>> prepareRegister(Register req) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartAddKey(SmartOp op, SubjectKeyArgs key) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartCancelNonce(SmartOp op, java.lang.String lane) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartCancelRecovery(SmartOp op) ;
    public java.util.concurrent.CompletableFuture<NativeQuote> prepareSmartDeploy(KeyRef key, java.lang.String chain, java.lang.String factory, SubjectKeyArgs firstKey, java.lang.String guardian) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartExecute(SmartOp op, SmartCall call) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartRemoveKey(SmartOp op, java.lang.String index) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartRotateKey(SmartOp op, java.lang.String index, SubjectKeyArgs key) ;
    public java.util.concurrent.CompletableFuture<Prepared> prepareSmartSetGuardian(SmartOp op, java.lang.String guardian) ;
    public java.util.concurrent.CompletableFuture<java.util.List<RegistryWrite>> prepareSubmitRegistration(RegistrationBlob blob, java.lang.String chain, java.lang.String expectedUa, KeyRef payer) ;
    public java.util.concurrent.CompletableFuture<MsigUpdatePlan> prepareUpdateMsig(UpdateMsig req) ;
    public java.util.concurrent.CompletableFuture<SubmitQuote> quoteRegistryWrite(RegistryWrite write) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> registerTarget(java.lang.String chain, short kind) ;
    public java.util.concurrent.CompletableFuture<RegistrationBlob> registrationBlob(KeyRef key, RegisterAttrs attrs) ;
    public java.util.concurrent.CompletableFuture<RegistrationState> registrationOf(java.lang.String chain, java.lang.String ua) ;
    public java.util.concurrent.CompletableFuture<java.util.List<AccountInfo>> restore(Restore req) ;
    public java.util.concurrent.CompletableFuture<java.lang.Boolean> signs(java.lang.String seed, java.lang.String id) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> submitRegistryWrite(RegistryWrite write, SubmitQuote quote) ;
    public java.util.concurrent.CompletableFuture<UaLine> uaLine(java.lang.String chain, java.lang.String ua) ;
    
}

