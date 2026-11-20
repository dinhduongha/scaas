package uniffi.scaas_sdk;

/**
 * A page of history.
 */
public class HistoryPage {
    private java.util.List<HistoryItem> items;
    /**
     * on the first page (`before` none) only
     */
    private java.util.List<OpItem> ops;
    /**
     * where the next page starts; `None` after block 0
     */
    private Cursor next;

    public HistoryPage(
        java.util.List<HistoryItem> items, 
        java.util.List<OpItem> ops, 
        Cursor next
    ) {
        
        this.items = items;
        
        this.ops = ops;
        
        this.next = next;
    }
    
    public java.util.List<HistoryItem> items() {
        return this.items;
    }
    
    public java.util.List<OpItem> ops() {
        return this.ops;
    }
    
    public Cursor next() {
        return this.next;
    }
    public void setItems(java.util.List<HistoryItem> items) {
        this.items = items;
    }
    public void setOps(java.util.List<OpItem> ops) {
        this.ops = ops;
    }
    public void setNext(Cursor next) {
        this.next = next;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof HistoryPage) {
            HistoryPage t = (HistoryPage) other;
            return (
              java.util.Objects.equals(items, t.items) && 
              
              java.util.Objects.equals(ops, t.ops) && 
              
              java.util.Objects.equals(next, t.next)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(items);
        result = 31 * result + java.util.Objects.hashCode(ops);
        result = 31 * result + java.util.Objects.hashCode(next);
        return result;
    }

    
    
    

}


