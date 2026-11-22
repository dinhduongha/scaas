package uniffi.scaas_sdk;

/**
 * A verify row's registry-line columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65; §13 Gas): the row is
 * keyed by chain (the table it is in), registry address and signer kind; the verify path, the depth and the write path are
 * columns. Within one table no two verify rows share signer, registry, path, depth and write.
 */
public class GasLine {
    /**
     * the registry the row was measured through (`0x` + 40 hex): a quote bound to it takes it first; `None`: a row of no one
     * registry
     */
    private java.lang.String registry;
    /**
     * `cache`, `precompile` or `fallback` (the holder's verdict after the verify-only verifier gave no answer, §5); `None`:
     * the holder's own check
     */
    private java.lang.String path;
    /**
     * the generations between the registry asked and the holder (0: the registry holds the record), at most 15
     */
    private byte depth;
    /**
     * the write path of W1 (a registry write whose signature the holder checks), never a consumer operation's quote
     */
    private boolean write;

    public GasLine(
        java.lang.String registry, 
        java.lang.String path, 
        byte depth, 
        boolean write
    ) {
        
        this.registry = registry;
        
        this.path = path;
        
        this.depth = depth;
        
        this.write = write;
    }
    
    public java.lang.String registry() {
        return this.registry;
    }
    
    public java.lang.String path() {
        return this.path;
    }
    
    public byte depth() {
        return this.depth;
    }
    
    public boolean write() {
        return this.write;
    }
    public void setRegistry(java.lang.String registry) {
        this.registry = registry;
    }
    public void setPath(java.lang.String path) {
        this.path = path;
    }
    public void setDepth(byte depth) {
        this.depth = depth;
    }
    public void setWrite(boolean write) {
        this.write = write;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasLine) {
            GasLine t = (GasLine) other;
            return (
              java.util.Objects.equals(registry, t.registry) && 
              
              java.util.Objects.equals(path, t.path) && 
              
              depth == t.depth && 
              
              write == t.write
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(registry);
        result = 31 * result + java.util.Objects.hashCode(path);
        result = 31 * result + java.lang.Byte.hashCode(depth);
        result = 31 * result + java.lang.Boolean.hashCode(write);
        return result;
    }

    
    
    

}


