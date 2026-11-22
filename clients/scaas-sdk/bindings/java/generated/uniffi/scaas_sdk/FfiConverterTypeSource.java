package uniffi.scaas_sdk;


public enum FfiConverterTypeSource implements FfiConverterRustBuffer<Source> {
    INSTANCE;

    @Override
    public Source read(java.nio.ByteBuffer buf) {
        try {
            return Source.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Source value) {
        return 4L;
    }

    @Override
    public void write(Source value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}




