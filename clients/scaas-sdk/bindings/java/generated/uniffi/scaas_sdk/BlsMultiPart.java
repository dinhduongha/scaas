package uniffi.scaas_sdk;

/**
 * A member's part (spec §5.4, §4): its index in the group's key data and its partial `σ_i` (or PoP part `π_i`), 128 bytes,
 * `0x` hex.
 */
public class BlsMultiPart {
    private byte index;
    private java.lang.String signature;

    public BlsMultiPart(
        byte index, 
        java.lang.String signature
    ) {
        
        this.index = index;
        
        this.signature = signature;
    }
    
    public byte index() {
        return this.index;
    }
    
    public java.lang.String signature() {
        return this.signature;
    }
    public void setIndex(byte index) {
        this.index = index;
    }
    public void setSignature(java.lang.String signature) {
        this.signature = signature;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof BlsMultiPart) {
            BlsMultiPart t = (BlsMultiPart) other;
            return (
              index == t.index && 
              
              java.util.Objects.equals(signature, t.signature)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Byte.hashCode(index);
        result = 31 * result + java.util.Objects.hashCode(signature);
        return result;
    }

    
    
    

}


