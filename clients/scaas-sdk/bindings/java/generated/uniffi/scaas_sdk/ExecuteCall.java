package uniffi.scaas_sdk;

/**
 * A mandate wallet's call (spec §13.2): decoded, or opaque under the marker.
 */
public sealed interface ExecuteCall {
  
    /**
     * an ERC-20 `transfer(to, amount)` of `token` held by the wallet
     */
  record Transfer(
    java.lang.String token, 
    java.lang.String to, 
    java.lang.String amount) implements ExecuteCall {
    
    
    

  }
  
    /**
     * any other call: `OpaqueCallRefused` without the marker
     */
  record Opaque(
    java.lang.String target, 
    java.lang.String value, 
    java.lang.String data, 
    uniffi.scaas_sdk.AllowOpaqueCall allow) implements ExecuteCall {
    
    
    

  }
  

  
}

