package uniffi.scaas_sdk;



/**
 * An SDK error. `Display` is the code; no variant carries an input, a URL, a body, a key or a ciphertext.
 */
public class SdkException extends java.lang.Exception {
    private SdkException(java.lang.String message) {
      super(message);
    }

    
    /**
     * A malformed input or configuration (the meaning `scaas-ua` and `scaas-rpc` give the same name).
     */
    public static class Argument extends SdkException {
      public Argument(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * The keystore's `format` or `v` is not `scaas.keystore` / 1 (the meaning of `scaas-ua`'s vault `VaultVersion`).
     */
    public static class VaultVersion extends SdkException {
      public VaultVersion(java.lang.String message) {
        super(message);
      }
    }
    
    public static class VaultFormat extends SdkException {
      public VaultFormat(java.lang.String message) {
        super(message);
      }
    }
    
    public static class VaultIo extends SdkException {
      public VaultIo(java.lang.String message) {
        super(message);
      }
    }
    
    public static class StoreConflict extends SdkException {
      public StoreConflict(java.lang.String message) {
        super(message);
      }
    }
    
    public static class KeystoreMismatch extends SdkException {
      public KeystoreMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    public static class KeystoreRollback extends SdkException {
      public KeystoreRollback(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AccountUnverified extends SdkException {
      public AccountUnverified(java.lang.String message) {
        super(message);
      }
    }
    
    public static class SeedUnknown extends SdkException {
      public SeedUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    public static class SeedExists extends SdkException {
      public SeedExists(java.lang.String message) {
        super(message);
      }
    }
    
    public static class LabelTaken extends SdkException {
      public LabelTaken(java.lang.String message) {
        super(message);
      }
    }
    
    public static class ConfirmationMissing extends SdkException {
      public ConfirmationMissing(java.lang.String message) {
        super(message);
      }
    }
    
    public static class MnemonicInvalid extends SdkException {
      public MnemonicInvalid(java.lang.String message) {
        super(message);
      }
    }
    
    public static class VaultPassphraseWeak extends SdkException {
      public VaultPassphraseWeak(java.lang.String message) {
        super(message);
      }
    }
    
    public static class DerivationPassphraseShort extends SdkException {
      public DerivationPassphraseShort(java.lang.String message) {
        super(message);
      }
    }
    
    public static class OriginSignature extends SdkException {
      public OriginSignature(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AuthenticatorRefused extends SdkException {
      public AuthenticatorRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class ChainUnknown extends SdkException {
      public ChainUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    public static class ProfileMismatch extends SdkException {
      public ProfileMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    public static class FeatureMissing extends SdkException {
      public FeatureMissing(java.lang.String message) {
        super(message);
      }
    }
    
    public static class PreparedStale extends SdkException {
      public PreparedStale(java.lang.String message) {
        super(message);
      }
    }
    
    public static class PreparedUnknown extends SdkException {
      public PreparedUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    public static class OpaqueCallRefused extends SdkException {
      public OpaqueCallRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class FeeAboveCap extends SdkException {
      public FeeAboveCap(java.lang.String message) {
        super(message);
      }
    }
    
    public static class GasAboveTxCap extends SdkException {
      public GasAboveTxCap(java.lang.String message) {
        super(message);
      }
    }
    
    public static class PayerDelegated extends SdkException {
      public PayerDelegated(java.lang.String message) {
        super(message);
      }
    }
    
    public static class SubmitPathNone extends SdkException {
      public SubmitPathNone(java.lang.String message) {
        super(message);
      }
    }
    
    public static class VerdictRefused extends SdkException {
      public VerdictRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class TxTypeRefused extends SdkException {
      public TxTypeRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class RawDigestRefused extends SdkException {
      public RawDigestRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppDomainRefused extends SdkException {
      public AppDomainRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppPurposeRefused extends SdkException {
      public AppPurposeRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppSaltMismatch extends SdkException {
      public AppSaltMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppHandleForeign extends SdkException {
      public AppHandleForeign(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppLabelRefused extends SdkException {
      public AppLabelRefused(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppKeyUsage extends SdkException {
      public AppKeyUsage(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AppArenaFull extends SdkException {
      public AppArenaFull(java.lang.String message) {
        super(message);
      }
    }
    
    public static class KemKeyGone extends SdkException {
      public KemKeyGone(java.lang.String message) {
        super(message);
      }
    }
    
    public static class ReceiverUnregistered extends SdkException {
      public ReceiverUnregistered(java.lang.String message) {
        super(message);
      }
    }
    
    public static class RegistrationUaMismatch extends SdkException {
      public RegistrationUaMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    public static class RegistrationKindDisabled extends SdkException {
      public RegistrationKindDisabled(java.lang.String message) {
        super(message);
      }
    }
    
    public static class RegistrationPopInvalid extends SdkException {
      public RegistrationPopInvalid(java.lang.String message) {
        super(message);
      }
    }
    
    public static class RegistrationKemMissing extends SdkException {
      public RegistrationKemMissing(java.lang.String message) {
        super(message);
      }
    }
    
    public static class AbiMismatch extends SdkException {
      public AbiMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * No better name (a failed task included); carries nothing.
     */
    public static class Internal extends SdkException {
      public Internal(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * An account row whose key (the same UA, native key or watched id) the seed lists already (owner 2026-11-18, Q1).
     */
    public static class AccountExists extends SdkException {
      public AccountExists(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A relayed operation's quote found no row of the gas table for its key (entry, domain kind, signer kind, fresh lane;
     * owner 2026-11-18, ruling 1; owner 2026-11-19, ruling B).
     */
    public static class GasUnquoted extends SdkException {
      public GasUnquoted(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * An operation's `validUntil` already past on the SDK's clock, or further ahead than the chain's window (owner 2026-11-19,
     * T13b ruling 1).
     */
    public static class ValidUntilRefused extends SdkException {
      public ValidUntilRefused(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A confidential token the profile's factory does not catalogue as a token of the family, or whose code is not the
     * factory's clone (spec §9.4 R5; owner 2026-11-19, C4).
     */
    public static class TokenUncatalogued extends SdkException {
      public TokenUncatalogued(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A UA whose registry record does not hold the key the read expects: the holder's leg not the handle's key, or a recipient's
     * record not its UA's key (spec §9.4 R6; owner 2026-11-19, C4).
     */
    public static class LegKeyMismatch extends SdkException {
      public LegKeyMismatch(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A `SmartKeyAccount` entry's signer that is not a key of the account (owner 2026-11-19, P2).
     */
    public static class SignerNotAccountKey extends SdkException {
      public SignerNotAccountKey(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A PQZ token with the sealed opening (`proofSystemId` `PQZL_SPLIT_ID`, CTR-PQZ-38): its keys and debits are the `pqz3k`
     * handles', not built in the SDK yet (P-T16-4, controller call 2026-11-19).
     */
    public static class PqzOpeningUnsupported extends SdkException {
      public PqzOpeningUnsupported(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * An `msig` slot (or an inner leaf) that is not both enabled and accepted: it cannot sign (spec §15; M2, owner 2026-11-19).
     */
    public static class MsigSlotInactive extends SdkException {
      public MsigSlotInactive(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A gas table's verify row without `sig_bytes` (owner 2026-11-19, A4): every verify row states its signature's length.
     */
    public static class GasSigBytesMissing extends SdkException {
      public GasSigBytesMissing(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A self-relay whose gas, recomputed after signing from the signed calldata (the real signature's length; owner
     * 2026-11-19, G3), exceeds `Limits::max_gas`: nothing written or sent.
     */
    public static class SignedGasAboveCap extends SdkException {
      public SignedGasAboveCap(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A gas table's row with `per_item` but no `item`, or the reverse (owner 2026-11-19, I1).
     */
    public static class GasItemUnpaired extends SdkException {
      public GasItemUnpaired(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A gas table's row whose `item` names no count the SDK reads (owner 2026-11-19, I1).
     */
    public static class GasItemUnknown extends SdkException {
      public GasItemUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * An operation whose gas row grows with a count (`per_item`) that the SDK cannot read from the operation, or above
     * 65,536 (owner 2026-11-19, I1): refused, never quoted without it.
     */
    public static class GasCountUnknown extends SdkException {
      public GasCountUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * bls12381-multi (plan Task 17): the valid partials' weight is below the group's threshold
     */
    public static class BlsMultiBelowThreshold extends SdkException {
      public BlsMultiBelowThreshold(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A gas table with a key outside the format, at the top, on a row or inside a row's part (PR A review, finding 1): an
     * unknown part is refused, never dropped from a quote.
     */
    public static class GasFieldUnknown extends SdkException {
      public GasFieldUnknown(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * An order, a cancel or a liquidity order naming a DEX that is not on the chain profile's list, or a wrap order whose
     * wrapped token is not on its wrapper list (CLI-SGN-35): refused before anything is signed (plan T17).
     */
    public static class DexNotListed extends SdkException {
      public DexNotListed(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A PQZ auditor consent whose auditor is a native (address) key (controller call, owner auto-run 2026-11-19): a native id
     * holds no PQZ key (CTR-UA-32), so the token refuses it on chain anyway; refused before anything is read or signed.
     */
    public static class PqzAuditorNative extends SdkException {
      public PqzAuditorNative(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * a `*_blocking` call whose cancel token fired (spec §16.1, feature `sync-api`); the work goes on as a dropped future
     */
    public static class Cancelled extends SdkException {
      public Cancelled(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A `scaas-ua` wallet error, by its own code.
     */
    public static class Ua extends SdkException {
      public Ua(java.lang.String message) {
        super(message);
      }
    }
    
    /**
     * A `scaas-rpc` error, by its own code (its text redacted by `scaas-rpc`, CLI-RPC-11).
     */
    public static class Rpc extends SdkException {
      public Rpc(java.lang.String message) {
        super(message);
      }
    }
    
}

