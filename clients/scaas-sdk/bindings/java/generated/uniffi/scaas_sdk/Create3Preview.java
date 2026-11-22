package uniffi.scaas_sdk;

/**
 * A creation's CREATE3 addresses (`scaas-ua` `create3_address`): the salt `s`, the proxy, the instance.
 */
public class Create3Preview {
    private java.lang.String s;
    private java.lang.String proxy;
    private java.lang.String instance;

    public Create3Preview(
        java.lang.String s, 
        java.lang.String proxy, 
        java.lang.String instance
    ) {
        
        this.s = s;
        
        this.proxy = proxy;
        
        this.instance = instance;
    }
    
    public java.lang.String s() {
        return this.s;
    }
    
    public java.lang.String proxy() {
        return this.proxy;
    }
    
    public java.lang.String instance() {
        return this.instance;
    }
    public void setS(java.lang.String s) {
        this.s = s;
    }
    public void setProxy(java.lang.String proxy) {
        this.proxy = proxy;
    }
    public void setInstance(java.lang.String instance) {
        this.instance = instance;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Create3Preview) {
            Create3Preview t = (Create3Preview) other;
            return (
              java.util.Objects.equals(s, t.s) && 
              
              java.util.Objects.equals(proxy, t.proxy) && 
              
              java.util.Objects.equals(instance, t.instance)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(s);
        result = 31 * result + java.util.Objects.hashCode(proxy);
        result = 31 * result + java.util.Objects.hashCode(instance);
        return result;
    }

    
    
    

}


