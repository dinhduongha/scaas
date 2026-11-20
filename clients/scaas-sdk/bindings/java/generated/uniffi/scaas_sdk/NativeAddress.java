package uniffi.scaas_sdk;

/**
 * A native key's public parts.
 */
public class NativeAddress {
    private java.lang.String network;
    /**
     * hex, no `0x`
     */
    private java.lang.String publicKey;
    /**
     * as the network prints it; `None` for `ton` and `hedera_ed25519`
     */
    private java.lang.String address;
    /**
     * a Polkadot key's SS58 address at the prefix asked
     */
    private java.lang.String ss58;
    /**
     * a Bitcoin key's witness program: its version and program (hex, no `0x`)
     */
    private java.lang.Byte witnessVersion;
    private java.lang.String witnessProgram;

    public NativeAddress(
        java.lang.String network, 
        java.lang.String publicKey, 
        java.lang.String address, 
        java.lang.String ss58, 
        java.lang.Byte witnessVersion, 
        java.lang.String witnessProgram
    ) {
        
        this.network = network;
        
        this.publicKey = publicKey;
        
        this.address = address;
        
        this.ss58 = ss58;
        
        this.witnessVersion = witnessVersion;
        
        this.witnessProgram = witnessProgram;
    }
    
    public java.lang.String network() {
        return this.network;
    }
    
    public java.lang.String publicKey() {
        return this.publicKey;
    }
    
    public java.lang.String address() {
        return this.address;
    }
    
    public java.lang.String ss58() {
        return this.ss58;
    }
    
    public java.lang.Byte witnessVersion() {
        return this.witnessVersion;
    }
    
    public java.lang.String witnessProgram() {
        return this.witnessProgram;
    }
    public void setNetwork(java.lang.String network) {
        this.network = network;
    }
    public void setPublicKey(java.lang.String publicKey) {
        this.publicKey = publicKey;
    }
    public void setAddress(java.lang.String address) {
        this.address = address;
    }
    public void setSs58(java.lang.String ss58) {
        this.ss58 = ss58;
    }
    public void setWitnessVersion(java.lang.Byte witnessVersion) {
        this.witnessVersion = witnessVersion;
    }
    public void setWitnessProgram(java.lang.String witnessProgram) {
        this.witnessProgram = witnessProgram;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NativeAddress) {
            NativeAddress t = (NativeAddress) other;
            return (
              java.util.Objects.equals(network, t.network) && 
              
              java.util.Objects.equals(publicKey, t.publicKey) && 
              
              java.util.Objects.equals(address, t.address) && 
              
              java.util.Objects.equals(ss58, t.ss58) && 
              
              java.util.Objects.equals(witnessVersion, t.witnessVersion) && 
              
              java.util.Objects.equals(witnessProgram, t.witnessProgram)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(network);
        result = 31 * result + java.util.Objects.hashCode(publicKey);
        result = 31 * result + java.util.Objects.hashCode(address);
        result = 31 * result + java.util.Objects.hashCode(ss58);
        result = 31 * result + java.util.Objects.hashCode(witnessVersion);
        result = 31 * result + java.util.Objects.hashCode(witnessProgram);
        return result;
    }

    
    
    

}


