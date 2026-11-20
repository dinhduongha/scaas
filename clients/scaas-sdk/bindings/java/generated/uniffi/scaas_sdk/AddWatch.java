package uniffi.scaas_sdk;

/**
 * `add_watch`: an id to watch (a `0x` 32-byte UA or a `0x` 20-byte address); no key.
 */
public class AddWatch {
    private java.lang.String seed;
    private java.lang.String watch;
    private java.lang.String name;

    public AddWatch(
        java.lang.String seed, 
        java.lang.String watch, 
        java.lang.String name
    ) {
        
        this.seed = seed;
        
        this.watch = watch;
        
        this.name = name;
    }
    
    public java.lang.String seed() {
        return this.seed;
    }
    
    public java.lang.String watch() {
        return this.watch;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    public void setSeed(java.lang.String seed) {
        this.seed = seed;
    }
    public void setWatch(java.lang.String watch) {
        this.watch = watch;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof AddWatch) {
            AddWatch t = (AddWatch) other;
            return (
              java.util.Objects.equals(seed, t.seed) && 
              
              java.util.Objects.equals(watch, t.watch) && 
              
              java.util.Objects.equals(name, t.name)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(seed);
        result = 31 * result + java.util.Objects.hashCode(watch);
        result = 31 * result + java.util.Objects.hashCode(name);
        return result;
    }

    
    
    

}


