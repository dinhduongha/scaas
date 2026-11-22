package uniffi.scaas_sdk;

/**
 * The call of a `SmartKeyAccount`'s `Execute` (spec §13.2): decoded, or opaque under the marker.
 */
public sealed interface SmartCall {
  
    /**
     * an ERC-20 `transfer(to, amount)` of `token` held by the account
     */
  record Transfer(
    java.lang.String token, 
    java.lang.String to, 
    java.lang.String amount) implements SmartCall {
    
    
    

  }
  
    /**
     * `account.initiateRecovery(key)`: the signer's account is `account`'s guardian (CTR-ACC-03)
     */
  record InitiateRecovery(
    java.lang.String account, 
    uniffi.scaas_sdk.SubjectKeyArgs key) implements SmartCall {
    
    
    

  }
  
    /**
     * any other call: `OpaqueCallRefused` without the marker
     */
  record Opaque(
    java.lang.String target, 
    java.lang.String value, 
    java.lang.String data, 
    uniffi.scaas_sdk.AllowOpaqueCall allow) implements SmartCall {
    
    
    

  }
  

  
}

