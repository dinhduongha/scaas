package uniffi.scaas_sdk;

/**
 * The `PayMeta` body by schema (pay-meta-tax spec §7.1), named.
 */
public sealed interface PayBody {
  
  record None() implements PayBody {
    
    
    

  }
  
  
  record Note(
    java.lang.String note) implements PayBody {
    
    
    

  }
  
  record CreditorRef(
    java.lang.String creditorRef, 
    java.lang.Long dueDate) implements PayBody {
    
    
    

  }
  
  record BoundCall(
    java.lang.String chainId, 
    java.lang.String target, 
    java.lang.String callHash) implements PayBody {
    
    
    

  }
  
  record Ciphertext(
    java.lang.String ciphertext) implements PayBody {
    
    
    

  }
  

  
}

