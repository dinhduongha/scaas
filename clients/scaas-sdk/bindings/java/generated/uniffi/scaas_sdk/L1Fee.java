package uniffi.scaas_sdk;


/**
 * An L1 data fee model (plan T38).
 */

public enum L1Fee {
    /**
     * OP Stack: `GasPriceOracle.getL1Fee(bytes)` (`0x4200…000F`) over the unsigned transaction, read at the quote's block
     */
  OP_STACK,
    /**
     * the L1 cost charged as gas (Arbitrum, the profile's `in-estimate`): a table-quoted transaction's gas limit adds
     * `NodeInterface.gasEstimateL1Component` (`0x…C8`) over its calldata, with the margin; an estimate holds it already
     */
  IN_ESTIMATE,
    /**
     * the L1 cost carried by the priority fee (Linea, the profile's `linea`): the fees are `linea_estimateGas`'s over the
     * transaction, never below the chain's own
     */
  LINEA;

  
  
  

}


