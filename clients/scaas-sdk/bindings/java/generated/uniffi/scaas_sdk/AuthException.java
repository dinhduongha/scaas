package uniffi.scaas_sdk;



/**
 * An authenticator's failure; `Unexpected` is a foreign exception inside the app's implementation.
 */
public class AuthException extends java.lang.Exception {
    private AuthException(java.lang.String message) {
      super(message);
    }

    
    public static class Refused extends AuthException {
      public Refused() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Cancelled extends AuthException {
      public Cancelled() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Unavailable extends AuthException {
      public Unavailable() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
    
    public static class Unexpected extends AuthException {
      public Unexpected() {
        super(new StringBuilder()
        .toString());
        }

      
      
      
    }
     
}

