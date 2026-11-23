package uniffi.scaas_sdk;


/**
 * What a `Consumed` or `Expired` rests on (CLI-RPC-09, owner 2026-11-17, T13 S7; review T26 B-14): the strict majority's agreed
 * read at the `finalized` block, or endpoint 0's alone under `failover`.
 */

public enum Basis {
  MAJORITY,
  ONE_ENDPOINT;

  
  
  

}


