package uniffi.scaas_sdk;

/**
 * What the payee expects of an imported operation: its chain, its own ids (`0x` + 64 hex: a pay or transfer must name one as
 * `to`), and the native key that will submit it (`SubmitPath::SelfRelay`).
 */
public class ImportExpect {
    private java.lang.String chain;
    private java.util.List<java.lang.String> payee;
    private KeyRef payer;

    public ImportExpect(
        java.lang.String chain, 
        java.util.List<java.lang.String> payee, 
        KeyRef payer
    ) {
        
        this.chain = chain;
        
        this.payee = payee;
        
        this.payer = payer;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.util.List<java.lang.String> payee() {
        return this.payee;
    }
    
    public KeyRef payer() {
        return this.payer;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setPayee(java.util.List<java.lang.String> payee) {
        this.payee = payee;
    }
    public void setPayer(KeyRef payer) {
        this.payer = payer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ImportExpect) {
            ImportExpect t = (ImportExpect) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(payee, t.payee) && 
              
              java.util.Objects.equals(payer, t.payer)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(payee);
        result = 31 * result + java.util.Objects.hashCode(payer);
        return result;
    }

    
    
    

}


