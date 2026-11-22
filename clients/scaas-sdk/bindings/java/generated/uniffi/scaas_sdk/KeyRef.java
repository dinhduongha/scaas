package uniffi.scaas_sdk;

/**
 * A key the SDK signs with, by reference (spec §5): the seed's open wallet holds it, or, for [`KeyRef::Key`], the platform's
 * authenticator (a passkey or a secure-element key, a row of the seed: owner 2026-11-19, S1).
 */
public sealed interface KeyRef {
  
  record Ua(
    java.lang.String seed, 
    java.lang.Short kind, 
    java.lang.Integer account, 
    java.lang.Integer index) implements KeyRef {
    
    
    

  }
  
  record Native(
    java.lang.String seed, 
        /**
         * a `scaas-ua` network name (`evm` for a payer)
         */
    java.lang.String network, 
    java.lang.Integer index) implements KeyRef {
    
    
    

  }
  
    /**
     * an imported classical key (spec §6.7, `vault.import_key`): the seed's vault `native-import:<network>:<index>`
     */
  record Imported(
    java.lang.String seed, 
    java.lang.String network, 
    java.lang.Integer index) implements KeyRef {
    
    
    

  }
  
    /**
     * the stored key row `id` of seed `seed` (`AccountRow::Key`: a passkey `webauthn-p256` with its credential id, a
     * secure-element `p256` key with its handle), signing through the `Authenticator` (`external`)
     */
  record Key(
    java.lang.String seed, 
    java.lang.String id) implements KeyRef {
    
    
    

  }
  
    /**
     * the `msig` UA `ua` (`0x` + 64 hex) of the profile's registry, signing by the member slots named (CTR-UA-09, CTR-UA-38),
     * each slot's key one this SDK holds; a minimal set of enabled and accepted slots of its current structure (CTR-UA-07,
     * CTR-UA-37, CTR-UA-44). A slot's key is never an `Msig` itself (`Argument`).
     */
  record Msig(
    java.lang.String ua, 
    java.util.List<uniffi.scaas_sdk.MsigSlot> slots) implements KeyRef {
    
    
    

  }
  
    /**
     * a `bls12381-multi` (`0x0121`) group (plan Task 17): the seed's member key `ua_key(0x0121, account, index)` (EIP-2333:
     * index 0) and the group's key data `d` (`0x` hex, spec 2026-11-19-bls12381-multi §2); the signer's id is the group's
     * UA, its signature the members' aggregate ([`Op::submit_bls_multi`])
     */
  record BlsMulti(
    java.lang.String seed, 
    java.lang.Integer account, 
    java.lang.Integer index, 
    java.lang.String keyData) implements KeyRef {
    
    
    

  }
  
    /**
     * an operation another party signed and handed off (`Op::import_signed`, spec §27.5 (c)): its signer's subject id (`0x`
     * hex); nothing in this SDK signs for it
     */
  record Signed(
    java.lang.String signer) implements KeyRef {
    
    
    

  }
  

  
}

