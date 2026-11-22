package uniffi.scaas_sdk;

/**
 * A reviewed position reader of a position manager (a liquidity order that receives a position names one).
 */
public class PositionReader {
    private java.lang.String manager;
    private java.lang.String reader;

    public PositionReader(
        java.lang.String manager, 
        java.lang.String reader
    ) {
        
        this.manager = manager;
        
        this.reader = reader;
    }
    
    public java.lang.String manager() {
        return this.manager;
    }
    
    public java.lang.String reader() {
        return this.reader;
    }
    public void setManager(java.lang.String manager) {
        this.manager = manager;
    }
    public void setReader(java.lang.String reader) {
        this.reader = reader;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PositionReader) {
            PositionReader t = (PositionReader) other;
            return (
              java.util.Objects.equals(manager, t.manager) && 
              
              java.util.Objects.equals(reader, t.reader)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(manager);
        result = 31 * result + java.util.Objects.hashCode(reader);
        return result;
    }

    
    
    

}


