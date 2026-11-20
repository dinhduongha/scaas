package uniffi.scaas_sdk;

public sealed interface EndpointAuth {
  
  record Bearer(
    uniffi.scaas_sdk.Secret v1) implements EndpointAuth {
    
    
    

  }
  
  record Hmac(
    uniffi.scaas_sdk.Secret v1) implements EndpointAuth {
    
    
    

  }
  
  record Header(
    java.lang.String name, 
    uniffi.scaas_sdk.Secret value) implements EndpointAuth {
    
    
    

  }
  

  
}

