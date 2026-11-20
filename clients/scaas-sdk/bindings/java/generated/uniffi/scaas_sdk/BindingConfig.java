package uniffi.scaas_sdk;

/**
 * A binding's configuration (spec §4): the profiles, the passkey RP ID, the limits, the module gas tables; the runtime is the
 * SDK's own (`RuntimeChoice::Own`) and the clock the device's. `expect_api` and `need_features` are the binding's load check
 * (spec §16.3): the `api_version` it was generated against and the feature bits it needs; the opening refuses another
 * library with `AbiMismatch`.
 */
public class BindingConfig {
    private int expectApi;
    private long needFeatures;
    private java.util.List<ChainProfile> profiles;
    private java.lang.String rpId;
    private Limits limits;
    private java.util.List<GasTable> gasTables;

    public BindingConfig(
        int expectApi, 
        long needFeatures, 
        java.util.List<ChainProfile> profiles, 
        java.lang.String rpId, 
        Limits limits, 
        java.util.List<GasTable> gasTables
    ) {
        
        this.expectApi = expectApi;
        
        this.needFeatures = needFeatures;
        
        this.profiles = profiles;
        
        this.rpId = rpId;
        
        this.limits = limits;
        
        this.gasTables = gasTables;
    }
    
    public int expectApi() {
        return this.expectApi;
    }
    
    public long needFeatures() {
        return this.needFeatures;
    }
    
    public java.util.List<ChainProfile> profiles() {
        return this.profiles;
    }
    
    public java.lang.String rpId() {
        return this.rpId;
    }
    
    public Limits limits() {
        return this.limits;
    }
    
    public java.util.List<GasTable> gasTables() {
        return this.gasTables;
    }
    public void setExpectApi(int expectApi) {
        this.expectApi = expectApi;
    }
    public void setNeedFeatures(long needFeatures) {
        this.needFeatures = needFeatures;
    }
    public void setProfiles(java.util.List<ChainProfile> profiles) {
        this.profiles = profiles;
    }
    public void setRpId(java.lang.String rpId) {
        this.rpId = rpId;
    }
    public void setLimits(Limits limits) {
        this.limits = limits;
    }
    public void setGasTables(java.util.List<GasTable> gasTables) {
        this.gasTables = gasTables;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof BindingConfig) {
            BindingConfig t = (BindingConfig) other;
            return (
              expectApi == t.expectApi && 
              
              needFeatures == t.needFeatures && 
              
              java.util.Objects.equals(profiles, t.profiles) && 
              
              java.util.Objects.equals(rpId, t.rpId) && 
              
              java.util.Objects.equals(limits, t.limits) && 
              
              java.util.Objects.equals(gasTables, t.gasTables)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Integer.hashCode(expectApi);
        result = 31 * result + java.lang.Long.hashCode(needFeatures);
        result = 31 * result + java.util.Objects.hashCode(profiles);
        result = 31 * result + java.util.Objects.hashCode(rpId);
        result = 31 * result + java.util.Objects.hashCode(limits);
        result = 31 * result + java.util.Objects.hashCode(gasTables);
        return result;
    }

    
    
    

}


