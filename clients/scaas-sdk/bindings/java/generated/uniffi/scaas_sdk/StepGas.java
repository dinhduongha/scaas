package uniffi.scaas_sdk;

/**
 * One step of a registration carrying its PQZ key's proof as quoted at prepare (owner 2026-11-20).
 */
public class StepGas {
    /**
     * `register` (or `registerWebAuthn`, `registerMsig`), with or without the proof, or `storePqzPop`
     */
    private java.lang.String entry;
    /**
     * the step's gas limit: max(the node's estimate, the gas table's figure), the table's with the intrinsic cost, the
     * calldata and the margin; `None` where neither is known yet (a later step is not estimated before the one before it
     * landed)
     */
    private java.lang.Long gas;
    /**
     * the bound of its regular part (EIP-8037): the table's; the estimate, whole, where the table has no row
     */
    private java.lang.Long regularGas;

    public StepGas(
        java.lang.String entry, 
        java.lang.Long gas, 
        java.lang.Long regularGas
    ) {
        
        this.entry = entry;
        
        this.gas = gas;
        
        this.regularGas = regularGas;
    }
    
    public java.lang.String entry() {
        return this.entry;
    }
    
    public java.lang.Long gas() {
        return this.gas;
    }
    
    public java.lang.Long regularGas() {
        return this.regularGas;
    }
    public void setEntry(java.lang.String entry) {
        this.entry = entry;
    }
    public void setGas(java.lang.Long gas) {
        this.gas = gas;
    }
    public void setRegularGas(java.lang.Long regularGas) {
        this.regularGas = regularGas;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof StepGas) {
            StepGas t = (StepGas) other;
            return (
              java.util.Objects.equals(entry, t.entry) && 
              
              java.util.Objects.equals(gas, t.gas) && 
              
              java.util.Objects.equals(regularGas, t.regularGas)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(entry);
        result = 31 * result + java.util.Objects.hashCode(gas);
        result = 31 * result + java.util.Objects.hashCode(regularGas);
        return result;
    }

    
    
    

}


