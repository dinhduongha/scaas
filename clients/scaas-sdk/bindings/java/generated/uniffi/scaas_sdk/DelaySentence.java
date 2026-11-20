package uniffi.scaas_sdk;

/**
 * One delay sentence of a power bit, by name.
 */
public sealed interface DelaySentence {
  
    /**
     * `atOnce`: the delay is 0, a holder's change applies at once
     */
  record AtOnce() implements DelaySentence {
    
    
    

  }
  
  
    /**
     * the change applies after `delay` seconds, the longer of the factory's notice period and the token's grant delay
     */
  record After(
    java.lang.Long delay) implements DelaySentence {
    
    
    

  }
  
    /**
     * `singleKey`: the holder is a single key
     */
  record SingleKey() implements DelaySentence {
    
    
    

  }
  
  
    /**
     * `locked`: the bit is locked and the admin is gone; nobody can revoke its holders
     */
  record Locked() implements DelaySentence {
    
    
    

  }
  
  
    /**
     * a bit of the table without delay sentences
     */
  record NoDelay() implements DelaySentence {
    
    
    

  }
  
  
    /**
     * a bit the table does not know
     */
  record Unknown() implements DelaySentence {
    
    
    

  }
  
  

  
}

