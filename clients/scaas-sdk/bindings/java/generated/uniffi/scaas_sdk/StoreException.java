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
    
    /**
     * user-profiles spec §7.2 "Errors" (each the `SdkError` of its name): a sealed item that does not open, or a plain item in
     * a protected profile
     */
    public static class VaultFormat extends StoreException {
      public VaultFormat() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class ProfileLocked extends StoreException {
      public ProfileLocked() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class ProfilePassphraseRequired extends StoreException {
      public ProfilePassphraseRequired() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class ProfileRollback extends StoreException {
      public ProfileRollback() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class ProfileDamaged extends StoreException {
      public ProfileDamaged() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
     
}

