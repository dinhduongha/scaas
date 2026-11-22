package uniffi.scaas_sdk;

/**
 * A rescue vault's admin operation (CTR-GOV-25): `seq` the vault's shared order, from 1.
 */
public sealed interface RescueOp {
  
    /**
     * `setRescuer(seq, newRescuer)`, `new_rescuer` an address (not 0)
     */
  record SetRescuer(
    java.lang.Long seq, 
    java.lang.String newRescuer) implements RescueOp {
    
    
    

  }
  
    /**
     * `rotateAdmin(seq, newAdmin)`, `new_admin` a native UA (not 0)
     */
  record RotateAdmin(
    java.lang.Long seq, 
    java.lang.String newAdmin) implements RescueOp {
    
    
    

  }
  

  
}

