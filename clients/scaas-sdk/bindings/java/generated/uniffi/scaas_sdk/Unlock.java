package uniffi.scaas_sdk;

/**
 * How a seed opens (spec §6.10). `Passkey` and `Platform` go through the seed's PRF envelope (plan T7).
 */
public sealed interface Unlock extends AutoCloseable {
  
  record Passphrase(
    uniffi.scaas_sdk.SecretBytes v1) implements Unlock {
    
    @Override
    public void close() {
      
    AutoCloseableHelper.close(
        this.v1);
    }
    
    
    

  }
  
  record Passkey() implements Unlock {
    
    @Override
    public void close() {
      // Nothing to destroy
    }
    
    
    

  }
  
  
  record Platform() implements Unlock {
    
    @Override
    public void close() {
      // Nothing to destroy
    }
    
    
    

  }
  
  

  
}

