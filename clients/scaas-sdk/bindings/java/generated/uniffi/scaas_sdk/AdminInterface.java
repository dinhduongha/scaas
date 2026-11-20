package uniffi.scaas_sdk;

/**
 * Governance and admin rows (spec §11).
 */
public interface AdminInterface {
    public java.util.concurrent.CompletableFuture<Prepared> adminUaAcceptAdmin(UaAcceptAdmin req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveDexRelease(UaApproveDexRelease req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveRelease(UaApproveRelease req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveTokenRelease(UaApproveTokenRelease req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelGrant(UaCancelGrant req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelNonce(UaCancelNonce req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelRate(UaCancelRate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateDex(UaCreateDex req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateInstance(UaCreateInstance req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateToken(UaCreateToken req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateDex(UaDeprecateDex req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateRelease(UaDeprecateRelease req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateToken(UaDeprecateToken req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableFeature(UaDisableFeature req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableWrap(UaDisableWrap req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaEnableFeature(UaEnableFeature req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaExecuteRate(UaExecuteRate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaForceTransfer(UaForceTransfer req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaFreeze(UaFreeze req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaGrantRole(UaGrantRole req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaMint(UaMint req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaMintToUa(UaMintToUa req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaOperatorTransfer(UaOperatorTransfer req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPause(UaPause req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzCancelVerifier(UaPqzCancelVerifier req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzRevokeVerifier(UaPqzRevokeVerifier req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzSetVerifier(UaPqzSetVerifier req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaProposeRate(UaProposeRate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishClassEnv(UaPublishClassEnv req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishDexEnv(UaPublishDexEnv req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishTokenEnv(UaPublishTokenEnv req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRecordOrder(UaRecordOrder req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceAdmin(UaRenounceAdmin req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceRole(UaRenounceRole req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeApproval(UaRevokeApproval req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeOrder(UaRevokeOrder req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeRole(UaRevokeRole req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAllowed(UaSetAllowed req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorKey(UaSetAuditorKey req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorUa(UaSetAuditorUa req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetChainEntries(UaSetChainEntries req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetClassKindEnabled(UaSetClassKindEnabled req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetCompliance(UaSetCompliance req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetDenied(UaSetDenied req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetExchangeTarget(UaSetExchangeTarget req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetFeeSplit(UaSetFeeSplit req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetGrant(UaSetGrant req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetKycProvider(UaSetKycProvider req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetListedOnly(UaSetListedOnly req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMarket(UaSetMarket req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxSupply(UaSetMaxSupply req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxWrapSupply(UaSetMaxWrapSupply req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetProofStore(UaSetProofStore req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRate(UaSetTaxRate req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRecipient(UaSetTaxRecipient req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTokenKindEnabled(UaSetTokenKindEnabled req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetVerifierFee(UaSetVerifierFee req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapLimits(UaSetWrapLimits req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapMember(UaSetWrapMember req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaTransferAdmin(UaTransferAdmin req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaUnfreeze(UaUnfreeze req) ;
    public java.util.concurrent.CompletableFuture<Prepared> adminUaUnpause(UaUnpause req) ;
    
    /**
     * A creation's CREATE3 addresses (`scaas-ua` `create3_address`).
     */public Create3Preview create3Address(java.lang.String factory, java.lang.String creatorId, short contractClass, short kind, java.lang.String salt) throws SdkException;
    public java.util.concurrent.CompletableFuture<java.util.List<DelaySentence>> governanceDelay(java.lang.String chain, java.lang.String token, short bit, HolderKind holder) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> signPqzAuditorConsent(AuditorConsent req) ;
    public java.util.concurrent.CompletableFuture<SignedRescue> signRescueVault(RescueVault req) ;
    public java.util.concurrent.CompletableFuture<java.lang.String> signZetherAuditorConsent(AuditorConsent req) ;
    
}

