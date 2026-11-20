package uniffi.scaas_sdk;

/**
 * A native send as the user reviews it: the transaction's fields and the quote; `submit_native_send` signs exactly these.
 */
public class NativeQuote {
    private KeyRef key;
    private java.lang.String chain;
    private java.lang.String from;
    private java.lang.String to;
    private java.lang.String value;
    private java.lang.String data;
    private SubmitQuote quote;
    /**
     * the sender's code is an EIP-7702 designator (`0xef0100…`, the account's delegation mark, T9): the send is the EOA's own
     * transaction and stays allowed; the app can warn (owner 2026-11-18, ruling 5)
     */
    private boolean delegated;

    public NativeQuote(
        KeyRef key, 
        java.lang.String chain, 
        java.lang.String from, 
        java.lang.String to, 
        java.lang.String value, 
        java.lang.String data, 
        SubmitQuote quote, 
        boolean delegated
    ) {
        
        this.key = key;
        
        this.chain = chain;
        
        this.from = from;
        
        this.to = to;
        
        this.value = value;
        
        this.data = data;
        
        this.quote = quote;
        
        this.delegated = delegated;
    }
    
    public KeyRef key() {
        return this.key;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String from() {
        return this.from;
    }
    
    public java.lang.String to() {
        return this.to;
    }
    
    public java.lang.String value() {
        return this.value;
    }
    
    public java.lang.String data() {
        return this.data;
    }
    
    public SubmitQuote quote() {
        return this.quote;
    }
    
    public boolean delegated() {
        return this.delegated;
    }
    public void setKey(KeyRef key) {
        this.key = key;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setFrom(java.lang.String from) {
        this.from = from;
    }
    public void setTo(java.lang.String to) {
        this.to = to;
    }
    public void setValue(java.lang.String value) {
        this.value = value;
    }
    public void setData(java.lang.String data) {
        this.data = data;
    }
    public void setQuote(SubmitQuote quote) {
        this.quote = quote;
    }
    public void setDelegated(boolean delegated) {
        this.delegated = delegated;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof NativeQuote) {
            NativeQuote t = (NativeQuote) other;
            return (
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(from, t.from) && 
              
              java.util.Objects.equals(to, t.to) && 
              
              java.util.Objects.equals(value, t.value) && 
              
              java.util.Objects.equals(data, t.data) && 
              
              java.util.Objects.equals(quote, t.quote) && 
              
              delegated == t.delegated
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(from);
        result = 31 * result + java.util.Objects.hashCode(to);
        result = 31 * result + java.util.Objects.hashCode(value);
        result = 31 * result + java.util.Objects.hashCode(data);
        result = 31 * result + java.util.Objects.hashCode(quote);
        result = 31 * result + java.lang.Boolean.hashCode(delegated);
        return result;
    }

    
    
    

}


