package uniffi.scaas_sdk;

/**
 * One reviewed value: its name (a path for a nested field, `payment.value`), the value as signed, its display form.
 */
public class ReviewField {
    private java.lang.String name;
    private java.lang.String value;
    private java.lang.String display;
    private Source source;

    public ReviewField(
        java.lang.String name, 
        java.lang.String value, 
        java.lang.String display, 
        Source source
    ) {
        
        this.name = name;
        
        this.value = value;
        
        this.display = display;
        
        this.source = source;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public java.lang.String display() {
        return this.display;
    }
    
    public Source source() {
        return this.source;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setDisplay(java.lang.String display) {
        this.display = display;
    }
    public void setSource(Source source) {
        this.source = source;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ReviewField) {
            ReviewField t = (ReviewField) other;
            return (
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(display, t.display) && 
              
              java.util.Objects.equals(source, t.source)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(display);
        result = 31 * result + java.util.Objects.hashCode(source);
        return result;
    }

    
    
    

}


