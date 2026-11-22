package uniffi.scaas_sdk;

/**
 * One log naming the account in an indexed field.
 */
public class HistoryItem {
    private long block;
    private java.lang.String txHash;
    private long logIndex;
    /**
     * the token that emitted it, `0x` + 40 hex lower case
     */
    private java.lang.String contract;
    /**
     * `UATransfer`, `Transfer`, `PaymentSettled`, `Wrapped`, `Unwrapped`, `UnwrappedToUA`, else `unknown`
     */
    private java.lang.String event;
    private java.util.List<java.lang.String> topics;
    private java.lang.String data;

    public HistoryItem(
        long block, 
        java.lang.String txHash, 
        long logIndex, 
        java.lang.String contract, 
        java.lang.String event, 
        java.util.List<java.lang.String> topics, 
        java.lang.String data
    ) {
        
        this.block = block;
        
        this.txHash = txHash;
        
        this.logIndex = logIndex;
        
        this.contract = contract;
        
        this.event = event;
        
        this.topics = topics;
        
        this.data = data;
    }
    
    public long block() {
        return this.block;
    }
    
    public java.lang.String txHash() {
        return this.txHash;
    }
    
    public long logIndex() {
        return this.logIndex;
    }
    
    public java.lang.String contract() {
        return this.contract;
    }
    
    public java.lang.String event() {
        return this.event;
    }
    
    public java.util.List<java.lang.String> topics() {
        return this.topics;
    }
    
    public java.lang.String data() {
        return this.data;
    }
    public void setBlock(long block) {
        this.block = block;
    }
    public void setTxHash(java.lang.String txHash) {
        this.txHash = txHash;
    }
    public void setLogIndex(long logIndex) {
        this.logIndex = logIndex;
    }
    public void setContract(java.lang.String contract) {
        this.contract = contract;
    }
    public void setEvent(java.lang.String event) {
        this.event = event;
    }
    public void setTopics(java.util.List<java.lang.String> topics) {
        this.topics = topics;
    }
    public void setData(java.lang.String data) {
        this.data = data;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof HistoryItem) {
            HistoryItem t = (HistoryItem) other;
            return (
              block == t.block && 
              
              java.util.Objects.equals(txHash, t.txHash) && 
              
              logIndex == t.logIndex && 
              
              java.util.Objects.equals(contract, t.contract) && 
              
              java.util.Objects.equals(event, t.event) && 
              
              java.util.Objects.equals(topics, t.topics) && 
              
              java.util.Objects.equals(data, t.data)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Long.hashCode(block);
        result = 31 * result + java.util.Objects.hashCode(txHash);
        result = 31 * result + java.lang.Long.hashCode(logIndex);
        result = 31 * result + java.util.Objects.hashCode(contract);
        result = 31 * result + java.util.Objects.hashCode(event);
        result = 31 * result + java.util.Objects.hashCode(topics);
        result = 31 * result + java.util.Objects.hashCode(data);
        return result;
    }

    
    
    

}


