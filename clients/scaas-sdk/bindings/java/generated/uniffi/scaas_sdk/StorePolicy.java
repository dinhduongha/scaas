package uniffi.scaas_sdk;

/**
 * How an item is kept: on this device only, out of cloud backups, behind user presence.
 */
public class StorePolicy {
    private boolean deviceOnly;
    private boolean noCloudBackup;
    private Presence userPresence;

    public StorePolicy(
        boolean deviceOnly, 
        boolean noCloudBackup, 
        Presence userPresence
    ) {
        
        this.deviceOnly = deviceOnly;
        
        this.noCloudBackup = noCloudBackup;
        
        this.userPresence = userPresence;
    }
    
    public boolean deviceOnly() {
        return this.deviceOnly;
    }
    
    public boolean noCloudBackup() {
        return this.noCloudBackup;
    }
    
    public Presence userPresence() {
        return this.userPresence;
    }
    public void setDeviceOnly(boolean deviceOnly) {
        this.deviceOnly = deviceOnly;
    }
    public void setNoCloudBackup(boolean noCloudBackup) {
        this.noCloudBackup = noCloudBackup;
    }
    public void setUserPresence(Presence userPresence) {
        this.userPresence = userPresence;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof StorePolicy) {
            StorePolicy t = (StorePolicy) other;
            return (
              deviceOnly == t.deviceOnly && 
              
              noCloudBackup == t.noCloudBackup && 
              
              java.util.Objects.equals(userPresence, t.userPresence)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Boolean.hashCode(deviceOnly);
        result = 31 * result + java.lang.Boolean.hashCode(noCloudBackup);
        result = 31 * result + java.util.Objects.hashCode(userPresence);
        return result;
    }

    
    
    

}


