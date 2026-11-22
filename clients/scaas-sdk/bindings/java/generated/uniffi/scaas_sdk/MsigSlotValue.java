package uniffi.scaas_sdk;

/**
 * One slot of an `msig` signature (`KeyRef::Msig`), as `MsigSlot`.
 */
public sealed interface MsigSlotValue {
  
    /**
     * the signing (or native) member at `index` signs with `key`
     */
  record Member(
    java.lang.Short index, 
    uniffi.scaas_sdk.SlotKey key) implements MsigSlotValue {
    
    
    

  }
  
    /**
     * the `msig` member at `index` signs by its own slots, one level down
     */
  record Msig(
    java.lang.Short index, 
    java.util.List<uniffi.scaas_sdk.MsigLeafValue> members) implements MsigSlotValue {
    
    
    

  }
  
    /**
     * the slot at `index` already signed on another device: its `MemberSig` JSON as `Op::member_sign` returned it
     */
  record Signed(
    java.lang.Short index, 
    java.lang.String member) implements MsigSlotValue {
    
    
    

  }
  

  
}

