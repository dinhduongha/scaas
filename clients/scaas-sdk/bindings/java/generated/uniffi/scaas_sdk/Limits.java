package uniffi.scaas_sdk;

/**
 * The SDK's caps and queues (spec §4). The fee caps are the app's to set for its chains; the defaults below are a floor
 * against a runaway quote, never a value assumed of a chain.
 */
public class Limits {
    /**
     * decimal wei
     */
    private java.lang.String maxFeePerGas;
    private long maxGas;
    /**
     * decimal wei
     */
    private java.lang.String maxCost;
    private long watchPollMs;
    /**
     * accounts × chains × tokens per poll
     */
    private int maxWatch;
    /**
     * scrypt, Argon2id, proofs, slow key generation at once
     */
    private int maxConcurrentHeavy;
    /**
     * the longest an operation's `validUntil` may lie ahead of the SDK's clock, in seconds (the signing check's window), where
     * a profile names none
     */
    private long maxValidSecs;
    private int eventQueue;
    /**
     * how long a terminal operation row stays in `sdk.state` after it ended, in seconds (default 90 days); a non-terminal row
     * is never pruned (owner 2026-11-19, T13b ruling 2)
     */
    private long stateRetentionSecs;

    public Limits(
        java.lang.String maxFeePerGas, 
        long maxGas, 
        java.lang.String maxCost, 
        long watchPollMs, 
        int maxWatch, 
        int maxConcurrentHeavy, 
        long maxValidSecs, 
        int eventQueue, 
        long stateRetentionSecs
    ) {
        
        this.maxFeePerGas = maxFeePerGas;
        
        this.maxGas = maxGas;
        
        this.maxCost = maxCost;
        
        this.watchPollMs = watchPollMs;
        
        this.maxWatch = maxWatch;
        
        this.maxConcurrentHeavy = maxConcurrentHeavy;
        
        this.maxValidSecs = maxValidSecs;
        
        this.eventQueue = eventQueue;
        
        this.stateRetentionSecs = stateRetentionSecs;
    }
    
    public java.lang.String maxFeePerGas() {
        return this.maxFeePerGas;
    }
    
    public long maxGas() {
        return this.maxGas;
    }
    
    public java.lang.String maxCost() {
        return this.maxCost;
    }
    
    public long watchPollMs() {
        return this.watchPollMs;
    }
    
    public int maxWatch() {
        return this.maxWatch;
    }
    
    public int maxConcurrentHeavy() {
        return this.maxConcurrentHeavy;
    }
    
    public long maxValidSecs() {
        return this.maxValidSecs;
    }
    
    public int eventQueue() {
        return this.eventQueue;
    }
    
    public long stateRetentionSecs() {
        return this.stateRetentionSecs;
    }
    public void setMaxFeePerGas(java.lang.String maxFeePerGas) {
        this.maxFeePerGas = maxFeePerGas;
    }
    public void setMaxGas(long maxGas) {
        this.maxGas = maxGas;
    }
    public void setMaxCost(java.lang.String maxCost) {
        this.maxCost = maxCost;
    }
    public void setWatchPollMs(long watchPollMs) {
        this.watchPollMs = watchPollMs;
    }
    public void setMaxWatch(int maxWatch) {
        this.maxWatch = maxWatch;
    }
    public void setMaxConcurrentHeavy(int maxConcurrentHeavy) {
        this.maxConcurrentHeavy = maxConcurrentHeavy;
    }
    public void setMaxValidSecs(long maxValidSecs) {
        this.maxValidSecs = maxValidSecs;
    }
    public void setEventQueue(int eventQueue) {
        this.eventQueue = eventQueue;
    }
    public void setStateRetentionSecs(long stateRetentionSecs) {
        this.stateRetentionSecs = stateRetentionSecs;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof Limits) {
            Limits t = (Limits) other;
            return (
              java.util.Objects.equals(maxFeePerGas, t.maxFeePerGas) && 
              
              maxGas == t.maxGas && 
              
              java.util.Objects.equals(maxCost, t.maxCost) && 
              
              watchPollMs == t.watchPollMs && 
              
              maxWatch == t.maxWatch && 
              
              maxConcurrentHeavy == t.maxConcurrentHeavy && 
              
              maxValidSecs == t.maxValidSecs && 
              
              eventQueue == t.eventQueue && 
              
              stateRetentionSecs == t.stateRetentionSecs
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(maxFeePerGas);
        result = 31 * result + java.lang.Long.hashCode(maxGas);
        result = 31 * result + java.util.Objects.hashCode(maxCost);
        result = 31 * result + java.lang.Long.hashCode(watchPollMs);
        result = 31 * result + java.lang.Integer.hashCode(maxWatch);
        result = 31 * result + java.lang.Integer.hashCode(maxConcurrentHeavy);
        result = 31 * result + java.lang.Long.hashCode(maxValidSecs);
        result = 31 * result + java.lang.Integer.hashCode(eventQueue);
        result = 31 * result + java.lang.Long.hashCode(stateRetentionSecs);
        return result;
    }

    
    
    

}


