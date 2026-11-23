package uniffi.scaas_sdk;

/**
 * Where a part of a quote's gas figure came from (owner 2026-11-19), so the app and the operator see a figure not measured on
 * the chain.
 */
public sealed interface GasFrom {
  
    /**
     * a row of the chain profile, measured on that chain
     */
  record Chain() implements GasFrom {
    
    
    

  }
  
  
    /**
     * a row of the named module table, the profile having opted in
     */
  record Module(
    java.lang.String v1) implements GasFrom {
    
    
    

  }
  
    /**
     * a row of the SCaaS reference table, the profile having opted in; not measured on this chain
     */
  record Reference() implements GasFrom {
    
    
    

  }
  
  
    /**
     * the figure the app passed on the call
     */
  record App() implements GasFrom {
    
    
    

  }
  
  
    /**
     * a native send's own estimate (`eth_estimateGas`, a plain transfer's too)
     */
  record Estimate() implements GasFrom {
    
    
    

  }
  
  

  
}

