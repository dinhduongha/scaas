package uniffi.scaas_sdk;

/**
 * How an operation reaches the chain (spec §13.3).
 */
public sealed interface SubmitPath {
  
    /**
     * a gateway when the profile has one and the entry is one a gateway takes (door A), else a self-relay by `payer` when
     * given, else `SubmitPathNone`
     */
  record Auto(
    uniffi.scaas_sdk.KeyRef payer) implements SubmitPath {
    
    
    

  }
  
    /**
     * the profile's gateways, the same body to each
     */
  record Gateway() implements SubmitPath {
    
    
    

  }
  
  
    /**
     * an EIP-1559 transaction from the holder's own native EVM key, which pays the gas
     */
  record SelfRelay(
    uniffi.scaas_sdk.KeyRef payer) implements SubmitPath {
    
    
    

  }
  

  
}

