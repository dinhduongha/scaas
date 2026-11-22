package uniffi.scaas_sdk;

/**
 * The envelope of an owner statement's relayed form (`UARollOverSigned`, `UASetRollOverMode`): the Zether UA's own lane.
 */
public class OwnerRelay {
    private java.lang.String batch;
    private Envelope envelope;

    public OwnerRelay(
        java.lang.String batch, 
        Envelope envelope
    ) {
        
        this.batch = batch;
        
        this.envelope = envelope;
    }
    
    public java.lang.String batch() {
        return this.batch;
    }
    
    public Envelope envelope() {
        return this.envelope;
    }
    public void setBatch(java.lang.String batch) {
        this.batch = batch;
    }
    public void setEnvelope(Envelope envelope) {
        this.envelope = envelope;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof OwnerRelay) {
            OwnerRelay t = (OwnerRelay) other;
            return (
              java.util.Objects.equals(batch, t.batch) && 
              
              java.util.Objects.equals(envelope, t.envelope)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(batch);
        result = 31 * result + java.util.Objects.hashCode(envelope);
        return result;
    }

    
    
    

}


