package uniffi.scaas_sdk;


/**
 * What is known of an operation in flight (spec §13.5): none of it ends the operation.
 */

public enum InFlight {
    /**
     * signed and written, not sent yet
     */
  SIGNED,
    /**
     * a gateway queued it
     */
  QUEUED,
    /**
     * every gateway it went to refused it or could not be reached (one node's `dead` covers its own sends only)
     */
  GIVEN_UP_BY_EVERY_NODE,
    /**
     * the self-relay transaction was accepted by an endpoint
     */
  SENT,
    /**
     * no endpoint accepted the self-relay transaction (`BroadcastRejected`, an outcome, never final)
     */
  BROADCAST_REJECTED,
    /**
     * the self-relay transaction is in a block, not final, or final and successful while the event is not read yet
     */
  TX_INCLUDED,
    /**
     * the self-relay transaction is final and failed: the signed operation may still land by another relayer
     */
  TX_FINAL_FAILED,
    /**
     * the self-relay transaction was replaced
     */
  TX_REPLACED,
    /**
     * the signed operation's simulation from the payer reverted, failed or needed more gas than the confirmed quote: not sent
     * by this SDK (owner 2026-11-19, ruling A). It is signed and may still land by another relayer until its nonce is spent or
     * `validUntil` passes; `resend` tries again, a cancel of the lane's nonce ends it.
     */
  SIM_REFUSED;

  
  
  

}


