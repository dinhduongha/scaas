package uniffi.scaas_sdk;

/**
 * A family's own profile data (spec §8.7 rule 2; decisions CLI-SDK-15's Changes of 2026-11-21).
 */
public sealed interface FamilyParams {
  
    /**
     * Cosmos: the chain id the gateways' `node_info` must name (the identity a Cosmos node answers; `chain_uid` stays the
     * profile's 32-byte network id), the REST gateways with their policy (the profile's `rpc` are the CometBFT endpoints),
     * the native denom and the bech32 prefix of the chain's addresses
     */
  record Cosmos(
    java.lang.String chainId, 
    java.util.List<uniffi.scaas_sdk.EndpointConfig> rest, 
    uniffi.scaas_sdk.Policy restPolicy, 
    java.lang.String denom, 
    java.lang.String prefix) implements FamilyParams {
    
    
    

  }
  
    /**
     * Aptos: the chain id ledger info must name (`aptos_framework::chain_id`, 1 to 255; the identity an Aptos node answers)
     * and the `scaas` package's address, whose view `meta::account_of(owner)` gives the Account an owner's tokens are in
     * (NET-APT-05), as `0x` + 64 lowercase hex (AIP-40's long form)
     */
  record Aptos(
    java.lang.Byte chainId, 
    java.lang.String _package) implements FamilyParams {
    
    
    

  }
  
    /**
     * Solana: the `scaas` program's id (base58 of 32 bytes), under which an owner's SCaaS Account is the `["acct", owner]`
     * program address (`ua-rs` `families::solana`); the cluster's identity is its genesis hash, `chain_uid`'s 32 bytes
     */
  record Solana(
    java.lang.String program) implements FamilyParams {
    
    
    

  }
  
    /**
     * Soroban: the network passphrase its RPC endpoints name (`getNetwork`; its SHA-256 is `chain_uid`, checked at `Sdk::open`)
     * and the XLM SAC contract (`C…`), pinned, whose balance entry is a `C…` holder's native XLM (never derived here)
     */
  record Soroban(
    java.lang.String passphrase, 
    java.lang.String xlmSac) implements FamilyParams {
    
    
    

  }
  
    /**
     * Sui: the GraphQL endpoints the reads go to, with their policy (public fullnodes refuse JSON-RPC, docs/networks/sui.md
     * §14; the profile's `rpc` are the JSON-RPC endpoints), each named by `chain_uid`, the genesis checkpoint's digest, whose
     * 32 bytes in base58 `chainIdentifier` must answer
     */
  record Sui(
    java.util.List<uniffi.scaas_sdk.EndpointConfig> graphql, 
    uniffi.scaas_sdk.Policy graphqlPolicy) implements FamilyParams {
    
    
    

  }
  
    /**
     * Polkadot Hub's Substrate side on its EVM profile (decisions CLI-SDK-32's Change of 2026-11-22, plan T32's read part): the
     * Substrate JSON-RPC endpoints with their policy, each named by `genesis` (`0x` + 64 hex, `chain_getBlockHash(0)`), and the
     * SS58 prefix of the chain's addresses (0 to 16,383, not 46 or 47); `balances` of an SS58 id reads its `System.Account`
     * there. The same params serve the relay chain's Substrate side
     */
  record Substrate(
    java.util.List<uniffi.scaas_sdk.EndpointConfig> rpc, 
    uniffi.scaas_sdk.Policy rpcPolicy, 
    java.lang.String genesis, 
    java.lang.Short ss58Prefix) implements FamilyParams {
    
    
    

  }
  

  
}

