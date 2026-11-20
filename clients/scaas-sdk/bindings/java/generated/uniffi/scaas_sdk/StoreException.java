package uniffi.scaas_sdk;



/**
 * A store's failure; `Unexpected` is a foreign exception inside an app's implementation.
 */
public class StoreException extends java.lang.Exception {
    private StoreException(java.lang.String message) {
      super(message);
    }

    
    /**
     * `put_if`: the stored revision is not the expected one
     */
    public static class Conflict extends StoreException {
      public Conflict() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Io extends StoreException {
      public Io() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Unavailable extends StoreException {
      public Unavailable() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Unexpected extends StoreException {
      public Unexpected() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
     
}

