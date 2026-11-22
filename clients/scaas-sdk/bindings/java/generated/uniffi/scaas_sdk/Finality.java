package uniffi.scaas_sdk;

/**
 * The block of every decisive and decryption read (§9.4 requirement 3).
 */
public sealed interface Finality {
  
  record Finalized() implements Finality {
    
    
    

  }
  
  
  record Depth(
    java.lang.Long v1) implements Finality {
    
    
    

  }
  

  
}

