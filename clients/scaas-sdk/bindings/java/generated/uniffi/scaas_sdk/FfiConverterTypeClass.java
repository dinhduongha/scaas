package uniffi.scaas_sdk;


public enum FfiConverterTypeClass implements FfiConverterRustBuffer<Class> {
    INSTANCE;

    @Override
    public Class read(java.nio.ByteBuffer buf) {
        try {
            return Class.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Class value) {
        return 4L;
    }

    @Override
    public void write(Class value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





