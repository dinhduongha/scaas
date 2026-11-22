package uniffi.scaas_sdk;

/**
 * The words of a seed made here: revealed once, a three-word check, then forgotten (`scaas-ua`'s `SeedBackup`, CLI-SGN-11).
 */
public interface SeedBackupInterface {
    
    /**
     * Three positions to ask (1-based).
     */public int[] challenge() throws SdkException;
    
    /**
     * The words, once (`Argument` after), as a secret read through the copy call.
     */public SecretBytes reveal() throws SdkException;
    
    /**
     * The user's three words (a secret) against the challenge.
     */public boolean verify(SecretBytes answers) throws SdkException;
    
}

