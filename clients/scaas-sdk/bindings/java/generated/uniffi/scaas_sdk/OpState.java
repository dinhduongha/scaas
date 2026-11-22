package uniffi.scaas_sdk;

/**
 * An operation's state (spec §13.5, CLI-SDK-18): terminal only on a chain fact from a decisive read at the profile's final
 * block.
 */
public sealed interface OpState {
  
    /**
     * the executed event of the operation's digest at or below the final block
     */
  record Landed(
    java.lang.Long block, 
    java.lang.String hash) implements OpState {
    
    
    

  }
  
    /**
     * the lane's nonce spent at the final block without that event; a replaced native send
     */
  record Consumed() implements OpState {
    
    
    

  }
  
  
    /**
     * an EVM native send final at or below the final block and reverted (owner 2026-11-18, ruling 4; the node's `reverted`)
     */
  record Reverted(
    java.lang.Long block, 
    java.lang.String hash) implements OpState {
    
    
    

  }
  
    /**
     * `validUntil` below the final block's timestamp while the nonce is unspent
     */
  record Expired() implements OpState {
    
    
    

  }
  
  
    /**
     * anything else, with what is known (never an end)
     */
  record InFlight(
    uniffi.scaas_sdk.InFlight detail) implements OpState {
    
    
    

  }
  

  
}

