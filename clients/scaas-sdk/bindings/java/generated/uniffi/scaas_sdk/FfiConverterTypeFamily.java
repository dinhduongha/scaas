package uniffi.scaas_sdk;


public enum FfiConverterTypeFamily implements FfiConverterRustBuffer<Family> {
    INSTANCE;

    @Override
    public Family read(java.nio.ByteBuffer buf) {
        try {
            return Family.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Family value) {
        return 4L;
    }

    @Override
    public void write(Family value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





