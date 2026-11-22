package uniffi.scaas_sdk;


public enum FfiConverterTypeAuthError implements FfiConverterRustBuffer<AuthException> {
    INSTANCE;

    @Override
    public AuthException read(java.nio.ByteBuffer buf) {

        return switch(buf.getInt()) {
            case 1 -> new AuthException.Refused();
            case 2 -> new AuthException.Cancelled();
            case 3 -> new AuthException.Unavailable();
            case 4 -> new AuthException.Unexpected();
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }

    @Override
    public long allocationSize(AuthException value) {
        return switch(value) {
            case AuthException.Refused x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case AuthException.Cancelled x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case AuthException.Unavailable x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case AuthException.Unexpected x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }

    @Override
    public void write(AuthException value, java.nio.ByteBuffer buf) {
        switch(value) {
            case AuthException.Refused x -> {
                buf.putInt(1);
            }
            case AuthException.Cancelled x -> {
                buf.putInt(2);
            }
            case AuthException.Unavailable x -> {
                buf.putInt(3);
            }
            case AuthException.Unexpected x -> {
                buf.putInt(4);
            }
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }
}



