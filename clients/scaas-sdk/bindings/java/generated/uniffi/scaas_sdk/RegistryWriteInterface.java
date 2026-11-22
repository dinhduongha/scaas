package uniffi.scaas_sdk;

/**
 * A registry write as the user reviews it (spec §7, §13.1): opaque, kept in the SDK's table; it holds public data only
 * (the PoP binds no caller). `submit_registry_write` sends exactly its calldata to the profile's registry.
 */
public interface RegistryWriteInterface {
    public java.lang.String calldata();
    public java.lang.String chain();
    public java.lang.String entry();
    public java.lang.String id();
    public KeyRef payer();
    
    /**
     * A registration carrying its PQZ key's proof: one transaction or two, each step's gas (owner 2026-11-20).
     */public RegistrationGas registrationGas();
    public java.util.List<ReviewField> review();
    public java.lang.String ua();
    
}

