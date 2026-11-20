package uniffi.scaas_sdk;

/**
 * The sponsored registration's blob (spec §7.1; owner 2026-11-19, R2): public data only, every field named. Its text form is
 * clientkeys' `registrationBlob` (`smartcontracts/vectors/ua/registration_blobs.json`).
 */
public class RegistrationBlob {
    private int v;
    private java.lang.String ua;
    private short kind;
    private RegisterArgs args;
    private KemRecord kem;

    public RegistrationBlob(
        int v, 
        java.lang.String ua, 
        short kind, 
        RegisterArgs args, 
        KemRecord kem
    ) {
        
        this.v = v;
        
        this.ua = ua;
        
        this.kind = kind;
        
        this.args = args;
        
        this.kem = kem;
    }
    
    public int v() {
        return this.v;
    }
    
    public java.lang.String ua() {
        return this.ua;
    }
    
    public short kind() {
        return this.kind;
    }
    
    public RegisterArgs args() {
        return this.args;
    }
    
    public KemRecord kem() {
        return this.kem;
    }
    public void setV(int v) {
        this.v = v;
    }
    public void setUa(java.lang.String ua) {
        this.ua = ua;
    }
    public void setKind(short kind) {
        this.kind = kind;
    }
    public void setArgs(RegisterArgs args) {
        this.args = args;
    }
    public void setKem(KemRecord kem) {
        this.kem = kem;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof RegistrationBlob) {
            RegistrationBlob t = (RegistrationBlob) other;
            return (
              v == t.v && 
              
              java.util.Objects.equals(ua, t.ua) && 
              
              kind == t.kind && 
              
              java.util.Objects.equals(args, t.args) && 
              
              java.util.Objects.equals(kem, t.kem)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Integer.hashCode(v);
        result = 31 * result + java.util.Objects.hashCode(ua);
        result = 31 * result + java.lang.Short.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(args);
        result = 31 * result + java.util.Objects.hashCode(kem);
        return result;
    }

    
    
    

}


