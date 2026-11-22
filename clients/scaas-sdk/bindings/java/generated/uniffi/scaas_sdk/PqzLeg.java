package uniffi.scaas_sdk;

/**
 * One leg of an op 7: a registered PQZ holder and its amount (`"0"`: a decoy).
 */
public class PqzLeg {
    private java.lang.String toUa;
    private java.lang.String amount;

    public PqzLeg(
        java.lang.String toUa, 
        java.lang.String amount
    ) {
        
        this.toUa = toUa;
        
        this.amount = amount;
    }
    
    public java.lang.String toUa() {
        return this.toUa;
    }
    
    public java.lang.String amount() {
        return this.amount;
    }
    public void setToUa(java.lang.String toUa) {
        this.toUa = toUa;
    }
    public void setAmount(java.lang.String amount) {
        this.amount = amount;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzLeg) {
            PqzLeg t = (PqzLeg) other;
            return (
              java.util.Objects.equals(toUa, t.toUa) && 
              
              java.util.Objects.equals(amount, t.amount)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(toUa);
        result = 31 * result + java.util.Objects.hashCode(amount);
        return result;
    }

    
    
    

}


