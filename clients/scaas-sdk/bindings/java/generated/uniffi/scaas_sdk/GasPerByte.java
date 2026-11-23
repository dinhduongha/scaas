package uniffi.scaas_sdk;

/**
 * A base row's per-byte part (owner 2026-11-19, ruling B): `gas` (whole gas, rounded up) for each byte of the operation's
 * variable-length `input`: `meta.body` (a pay entry's `PayMeta` body, as encoded), `data` (`mtxExecute`'s call data) or
 * `calldata` (the transaction row's, entry `transaction` kind `evm`: the price of a byte of the transaction's calldata).
 */
public class GasPerByte {
    private java.lang.String input;
    private long gas;

    public GasPerByte(
        java.lang.String input, 
        long gas
    ) {
        
        this.input = input;
        
        this.gas = gas;
    }
    
    public java.lang.String input() {
        return this.input;
    }
    
    public long gas() {
        return this.gas;
    }
    public void setInput(java.lang.String input) {
        this.input = input;
    }
    public void setGas(long gas) {
        this.gas = gas;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasPerByte) {
            GasPerByte t = (GasPerByte) other;
            return (
              java.util.Objects.equals(input, t.input) && 
              
              gas == t.gas
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(input);
        result = 31 * result + java.lang.Long.hashCode(gas);
        return result;
    }

    
    
    

}


