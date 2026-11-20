package uniffi.scaas_sdk;

/**
 * `prepare_native_send`'s request.
 */
public class NativeSend {
    /**
     * a native `evm` key
     */
    private KeyRef key;
    private java.lang.String chain;
    /**
     * `0x` + 40 hex
     */
    private java.lang.String to;
    /**
     * wei, decimal
     */
    private java.lang.String value;
    /**
     * `0x` hex calldata, or none
     */
    private java.lang.String data;
    /**
     * the EIP-2718 type asked: 0, 1 or 2 (2 only where the chain has a base fee); `None`: 2 where it has one, else 0.
     * `TxTypeRefused` otherwise (3 and 4 never)
     */
    private java.lang.Byte txType;

    public NativeSend(
        KeyRef key, 
        java.lang.String chain, 
        java.lang.String to, 
        java.lang.String value, 
        java.lang.String data, 
        java.lang.Byte txType
    ) {
        
        this.key = key;
        
        this.chain = chain;
        
        this.to = to;
        
        this.value = value;
        
        this.data = data;
        
        this.txType = txType;
    }
    
    public KeyRef key() {
        return this.key;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public java.lang.String data() {
        return this.data;
    }
    
    public java.lang.Byte txType() {
        return this.txType;
    }
    public void setKey(KeyRef key) {
        this.key = key;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setData(java.lang.String data) {
        this.data = data;
    }
    public void setTxType(java.lang.Byte txType) {
        this.txType = txType;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NativeSend) {
            NativeSend t = (NativeSend) other;
            return (
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(data, t.data) && 
              
              java.util.Objects.equals(txType, t.txType)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(data);
        result = 31 * result + java.util.Objects.hashCode(txType);
        return result;
    }

    
    
    

}


