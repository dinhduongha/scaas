package uniffi.scaas_sdk;


public enum FfiConverterTypeStoreError implements FfiConverterRustBuffer<StoreException> {
    INSTANCE;

    @Override
    public StoreException read(java.nio.ByteBuffer buf) {

        return switch(buf.getInt()) {
            case 1 -> new StoreException.Conflict();
            case 2 -> new StoreException.Io();
            case 3 -> new StoreException.Unavailable();
            case 4 -> new StoreException.Unexpected();
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }

    @Override
    public long allocationSize(StoreException value) {
        return switch(value) {
            case StoreException.Conflict x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.Io x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.Unavailable x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.Unexpected x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }

    @Override
    public void write(StoreException value, java.nio.ByteBuffer buf) {
        switch(value) {
            case StoreException.Conflict x -> {
                buf.putInt(1);
            }
            case StoreException.Io x -> {
                buf.putInt(2);
            }
            case StoreException.Unavailable x -> {
                buf.putInt(3);
            }
            case StoreException.Unexpected x -> {
                buf.putInt(4);
            }
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }
}



