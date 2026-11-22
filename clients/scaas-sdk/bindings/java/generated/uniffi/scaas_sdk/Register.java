package uniffi.scaas_sdk;

/**
 * `prepare_register`: the UA key `key` (a seed's `KeyRef::Ua`) registered on `chain`, its writes self-relayed by `payer` (a
 * native `evm` key).
 */
public class Register {
    private KeyRef key;
    private java.lang.String chain;
    private RegisterAttrs attrs;
    private KeyRef payer;

    public Register(
        KeyRef key, 
        java.lang.String chain, 
        RegisterAttrs attrs, 
        KeyRef payer
    ) {
        
        this.key = key;
        
        this.chain = chain;
        
        this.attrs = attrs;
        
        this.payer = payer;
    }
    
    public KeyRef key() {
        return this.key;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public RegisterAttrs attrs() {
        return this.attrs;
    }
    
    public KeyRef payer() {
        return this.payer;
    }
    public void setKey(KeyRef key) {
        this.key = key;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setAttrs(RegisterAttrs attrs) {
        this.attrs = attrs;
    }
    public void setPayer(KeyRef payer) {
        this.payer = payer;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Register) {
            Register t = (Register) other;
            return (
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(attrs, t.attrs) && 
              
              java.util.Objects.equals(payer, t.payer)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(attrs);
        result = 31 * result + java.util.Objects.hashCode(payer);
        return result;
    }

    
    
    

}


