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
            case 5 -> new StoreException.VaultFormat();
            case 6 -> new StoreException.ProfileLocked();
            case 7 -> new StoreException.ProfilePassphraseRequired();
            case 8 -> new StoreException.ProfileRollback();
            case 9 -> new StoreException.ProfileDamaged();
            case 10 -> new StoreException.ProfileBusy();
            case 11 -> new StoreException.ProfilePartFull();
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
            case StoreException.VaultFormat x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfileLocked x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfilePassphraseRequired x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfileRollback x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfileDamaged x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfileBusy x -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4L
            );
            case StoreException.ProfilePartFull x -> (
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
            case StoreException.VaultFormat x -> {
                buf.putInt(5);
            }
            case StoreException.ProfileLocked x -> {
                buf.putInt(6);
            }
            case StoreException.ProfilePassphraseRequired x -> {
                buf.putInt(7);
            }
            case StoreException.ProfileRollback x -> {
                buf.putInt(8);
            }
            case StoreException.ProfileDamaged x -> {
                buf.putInt(9);
            }
            case StoreException.ProfileBusy x -> {
                buf.putInt(10);
            }
            case StoreException.ProfilePartFull x -> {
                buf.putInt(11);
            }
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }
}



