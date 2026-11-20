package uniffi.scaas_sdk;

/**
 * One endpoint of a profile's RPC or gateway list (CLI-RPC-02): `{url, class, label, auth}`; `auth` belongs to this endpoint
 * only and is built by the app from its own secret source.
 */
public class EndpointConfig {
    private java.lang.String url;
    private Class _class;
    private java.lang.String label;
    private EndpointAuth auth;

    public EndpointConfig(
        java.lang.String url, 
        Class _class, 
        java.lang.String label, 
        EndpointAuth auth
    ) {
        
        this.url = url;
        
        this._class = _class;
        
        this.label = label;
        
        this.auth = auth;
    }
    
    public java.lang.String url() {
        return this.url;
    }
    
    public Class _class() {
        return this._class;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public EndpointAuth auth() {
        return this.auth;
    }
    public void setUrl(java.lang.String url) {
        this.url = url;
    }
    public void setClass(Class _class) {
        this._class = _class;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setAuth(EndpointAuth auth) {
        this.auth = auth;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof EndpointConfig) {
            EndpointConfig t = (EndpointConfig) other;
            return (
              java.util.Objects.equals(url, t.url) && 
              
              java.util.Objects.equals(_class, t._class) && 
              
              java.util.Objects.equals(label, t.label) && 
              
              java.util.Objects.equals(auth, t.auth)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(url);
        result = 31 * result + java.util.Objects.hashCode(_class);
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.util.Objects.hashCode(auth);
        return result;
    }

    
    
    

}


