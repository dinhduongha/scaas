package uniffi.scaas_sdk;

/**
 * A slot's key: `KeyRef` without the slots of an `msig` (a slot's key is never one, spec §7).
 */
public sealed interface SlotKey {
  
  record Ua(
    java.lang.String seed, 
    java.lang.Short kind, 
    java.lang.Integer account, 
    java.lang.Integer index) implements SlotKey {
    
    
    

  }
  
  record Native(
    java.lang.String seed, 
    java.lang.String network, 
    java.lang.Integer index) implements SlotKey {
    
    
    

  }
  
  record Imported(
    java.lang.String seed, 
    java.lang.String network, 
    java.lang.Integer index) implements SlotKey {
    
    
    

  }
  
  record Key(
    java.lang.String seed, 
    java.lang.String id) implements SlotKey {
    
    
    

  }
  
    /**
     * refused at signing (`Argument`)
     */
  record Msig(
    java.lang.String ua) implements SlotKey {
    
    
    

  }
  
    /**
     * a `bls12381-multi` group's member key (as `KeyRef::BlsMulti`)
     */
  record BlsMulti(
    java.lang.String seed, 
    java.lang.Integer account, 
    java.lang.Integer index, 
    java.lang.String keyData) implements SlotKey {
    
    
    

  }
  
    /**
     * another party's signer (as `KeyRef::Signed`, a hand-off): never a slot's key, refused at signing
     */
  record Signed(
    java.lang.String signer) implements SlotKey {
    
    
    

  }
  

  
}

