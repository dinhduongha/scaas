package uniffi.scaas_sdk;


/**
 * Where a reviewed value comes from (spec §13.1).
 */

public enum Source {
    /**
     * a field of the signed struct (or committed to by it, as a pay's `PayMeta`), decoded
     */
  SIGNED,
    /**
     * what the request named and the signed struct holds only in encrypted form (a confidential amount, recipient)
     */
  REQUEST,
    /**
     * what the SDK chose or read: the contract, every token or market touched with its mark
     */
  DERIVED;

  
  
  

}


