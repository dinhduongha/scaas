package uniffi.scaas_sdk;

/**
 * A new seed and its one reveal.
 */
public class NewSeed implements AutoCloseable{
    private SeedInfo info;
    private SeedBackup backup;

    public NewSeed(
        SeedInfo info, 
        SeedBackup backup
    ) {
        
        this.info = info;
        
        this.backup = backup;
    }
    
    public SeedInfo info() {
        return this.info;
    }
    
    public SeedBackup backup() {
        return this.backup;
    }
    public void setInfo(SeedInfo info) {
        this.info = info;
    }
    public void setBackup(SeedBackup backup) {
        this.backup = backup;
    }

    
    @Override
    public void close() {
        
    AutoCloseableHelper.close(
        this.info, 
        this.backup);
    }
    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NewSeed) {
            NewSeed t = (NewSeed) other;
            return (
              java.util.Objects.equals(info, t.info) && 
              
              java.util.Objects.equals(backup, t.backup)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(info);
        result = 31 * result + java.util.Objects.hashCode(backup);
        return result;
    }

    
    
    

}


