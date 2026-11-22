package uniffi.scaas_sdk;

/**
 * A seed as listed: public fields of the container entry, and whether it is unlocked (its MAC checked) in this session.
 */
public class SeedInfo {
    private java.lang.String id;
    private java.lang.String label;
    private int words;
    private java.lang.String origin;
    private java.lang.String _class;
    private java.util.List<java.lang.String> warnings;
    private java.lang.String backup;
    private boolean unlocked;
    /**
     * the index MAC of this entry was checked in this session (spec §6.2)
     */
    private boolean verified;

    public SeedInfo(
        java.lang.String id, 
        java.lang.String label, 
        int words, 
        java.lang.String origin, 
        java.lang.String _class, 
        java.util.List<java.lang.String> warnings, 
        java.lang.String backup, 
        boolean unlocked, 
        boolean verified
    ) {
        
        this.id = id;
        
        this.label = label;
        
        this.words = words;
        
        this.origin = origin;
        
        this._class = _class;
        
        this.warnings = warnings;
        
        this.backup = backup;
        
        this.unlocked = unlocked;
        
        this.verified = verified;
    }
    
    public java.lang.String id() {
        return this.id;
    }
    
    public java.lang.String label() {
        return this.label;
    }
    
    public int words() {
        return this.words;
    }
    
    public java.lang.String origin() {
        return this.origin;
    }
    
    public java.lang.String _class() {
        return this._class;
    }
    
    public java.util.List<java.lang.String> warnings() {
        return this.warnings;
    }
    
    public java.lang.String backup() {
        return this.backup;
    }
    
    public boolean unlocked() {
        return this.unlocked;
    }
    
    public boolean verified() {
        return this.verified;
    }
    public void setId(java.lang.String id) {
        this.id = id;
    }
    public void setLabel(java.lang.String label) {
        this.label = label;
    }
    public void setWords(int words) {
        this.words = words;
    }
    public void setOrigin(java.lang.String origin) {
        this.origin = origin;
    }
    public void setClass(java.lang.String _class) {
        this._class = _class;
    }
    public void setWarnings(java.util.List<java.lang.String> warnings) {
        this.warnings = warnings;
    }
    public void setBackup(java.lang.String backup) {
        this.backup = backup;
    }
    public void setUnlocked(boolean unlocked) {
        this.unlocked = unlocked;
    }
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SeedInfo) {
            SeedInfo t = (SeedInfo) other;
            return (
              java.util.Objects.equals(id, t.id) && 
              
              java.util.Objects.equals(label, t.label) && 
              
              words == t.words && 
              
              java.util.Objects.equals(origin, t.origin) && 
              
              java.util.Objects.equals(_class, t._class) && 
              
              java.util.Objects.equals(warnings, t.warnings) && 
              
              java.util.Objects.equals(backup, t.backup) && 
              
              unlocked == t.unlocked && 
              
              verified == t.verified
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(id);
        result = 31 * result + java.util.Objects.hashCode(label);
        result = 31 * result + java.lang.Integer.hashCode(words);
        result = 31 * result + java.util.Objects.hashCode(origin);
        result = 31 * result + java.util.Objects.hashCode(_class);
        result = 31 * result + java.util.Objects.hashCode(warnings);
        result = 31 * result + java.util.Objects.hashCode(backup);
        result = 31 * result + java.lang.Boolean.hashCode(unlocked);
        result = 31 * result + java.lang.Boolean.hashCode(verified);
        return result;
    }

    
    
    

}


