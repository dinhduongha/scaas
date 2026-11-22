package uniffi.scaas_sdk;

/**
 * An SDK event (appended only).
 */
public sealed interface Event {
  
  record SeedUnlocked(
    java.lang.String seed) implements Event {
    
    
    

  }
  
  record SeedLocked(
    java.lang.String seed) implements Event {
    
    
    

  }
  
  record KeystoreChanged(
    java.lang.Long rev) implements Event {
    
    
    

  }
  
  record KeystoreMismatch(
    java.lang.String seed) implements Event {
    
    
    

  }
  
  record KeystoreRollback() implements Event {
    
    
    

  }
  
  
  record HiddenOpsAbandoned(
    java.lang.Integer count) implements Event {
    
    
    

  }
  
    /**
     * The subscriber's queue overflowed: `missed` events were dropped for it
     */
  record Lagged(
    java.lang.Long missed) implements Event {
    
    
    

  }
  
    /**
     * An operation's state changed (spec §13.4, §13.5): every send result after `submit` arrives here, never as its error.
     */
  record OpState(
    java.lang.String op, 
    uniffi.scaas_sdk.OpState state) implements Event {
    
    
    

  }
  
    /**
     * A watched token's balance moved at the profile's final block (spec §14).
     */
  record BalanceChanged(
    java.lang.String account, 
    java.lang.String chain, 
    java.lang.String token) implements Event {
    
    
    

  }
  
    /**
     * A watched account's new history items (spec §8.4), newest first.
     */
  record HistoryAdded(
    java.lang.String account, 
    java.lang.String chain, 
    java.util.List<uniffi.scaas_sdk.HistoryItem> items) implements Event {
    
    
    

  }
  
    /**
     * Another process changed `sdk.state` (R17): its `rev` now.
     */
  record StateChanged(
    java.lang.Long rev) implements Event {
    
    
    

  }
  

  
}

