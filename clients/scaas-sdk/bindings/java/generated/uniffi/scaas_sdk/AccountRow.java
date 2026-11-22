package uniffi.scaas_sdk;

/**
 * An account row, by shape (spec §6.1), each with its fields in the written order.
 */
public sealed interface AccountRow {
  
  record Ua(
    java.lang.String id, 
    java.lang.String name, 
    java.lang.Long kind, 
    java.lang.Long account, 
    java.lang.Long index, 
    java.lang.String ua) implements AccountRow {
    
    
    

  }
  
  record Native(
    java.lang.String id, 
    java.lang.String name, 
    java.lang.String network, 
    java.lang.Long index, 
    java.lang.Long coinType, 
    java.lang.Long change, 
    java.lang.String path, 
    java.lang.Long ss58Prefix, 
    java.lang.String address) implements AccountRow {
    
    
    

  }
  
  record Key(
    java.lang.String id, 
    java.lang.String name, 
    java.lang.Long kind, 
    java.lang.String keyData, 
    java.lang.String credentialId, 
    java.lang.String handle, 
    java.lang.String ua) implements AccountRow {
    
    
    

  }
  
  record Watch(
    java.lang.String id, 
    java.lang.String name, 
    java.lang.String watch) implements AccountRow {
    
    
    

  }
  

  
}

