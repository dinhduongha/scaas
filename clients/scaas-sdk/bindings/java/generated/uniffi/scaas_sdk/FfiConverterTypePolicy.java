package uniffi.scaas_sdk;


public enum FfiConverterTypePolicy implements FfiConverterRustBuffer<Policy> {
    INSTANCE;

    @Override
    public Policy read(java.nio.ByteBuffer buf) {
        try {
            return Policy.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Policy value) {
        return 4L;
    }

    @Override
    public void write(Policy value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





