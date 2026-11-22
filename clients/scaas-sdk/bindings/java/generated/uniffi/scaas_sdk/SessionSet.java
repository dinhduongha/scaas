package uniffi.scaas_sdk;

/**
 * A hidden set: its own session id, used in every reference to it; never written.
 */
public class SessionSet {
    private java.lang.String id;

    public SessionSet(
        java.lang.String id
    ) {
        
        this.id = id;
    }
    
    public java.lang.String id() {
        return this.id;
    }
    public void setId(java.lang.String id) {
        this.id = id;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SessionSet) {
            SessionSet t = (SessionSet) other;
            return (
              java.util.Objects.equals(id, t.id)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(id);
        return result;
    }

    
    
    

}


