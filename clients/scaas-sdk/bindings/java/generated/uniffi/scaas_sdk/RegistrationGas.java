package uniffi.scaas_sdk;

/**
 * A registration carrying its PQZ key's proof as the SDK quoted it at prepare (owner 2026-11-20): one transaction, or two
 * (`register` without the proof, then `storePqzPop`, F22's restart-safe flow) when the one transaction's gas is above half
 * the chain's block gas limit or its regular gas above the per-transaction cap; each step's gas and the total.
 */
public class RegistrationGas {
    /**
     * 1 or 2
     */
    private int transactions;
    /**
     * the steps prepared, in the order they land (after a restart between the two, the second alone)
     */
    private java.util.List<StepGas> steps;
    /**
     * the steps' gas added; `None` when a step's is not known
     */
    private java.lang.Long totalGas;

    public RegistrationGas(
        int transactions, 
        java.util.List<StepGas> steps, 
        java.lang.Long totalGas
    ) {
        
        this.transactions = transactions;
        
        this.steps = steps;
        
        this.totalGas = totalGas;
    }
    
    public int transactions() {
        return this.transactions;
    }
    
    public java.util.List<StepGas> steps() {
        return this.steps;
    }
    
    public java.lang.Long totalGas() {
        return this.totalGas;
    }
    public void setTransactions(int transactions) {
        this.transactions = transactions;
    }
    public void setSteps(java.util.List<StepGas> steps) {
        this.steps = steps;
    }
    public void setTotalGas(java.lang.Long totalGas) {
        this.totalGas = totalGas;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RegistrationGas) {
            RegistrationGas t = (RegistrationGas) other;
            return (
              transactions == t.transactions && 
              
              java.util.Objects.equals(steps, t.steps) && 
              
              java.util.Objects.equals(totalGas, t.totalGas)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Integer.hashCode(transactions);
        result = 31 * result + java.util.Objects.hashCode(steps);
        result = 31 * result + java.util.Objects.hashCode(totalGas);
        return result;
    }

    
    
    

}


