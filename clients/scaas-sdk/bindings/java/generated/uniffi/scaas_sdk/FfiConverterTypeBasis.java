package uniffi.scaas_sdk;


public enum FfiConverterTypeBasis implements FfiConverterRustBuffer<Basis> {
    INSTANCE;

    @Override
    public Basis read(java.nio.ByteBuffer buf) {
        try {
            return Basis.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Basis value) {
        return 4L;
    }

    @Override
    public void write(Basis value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





