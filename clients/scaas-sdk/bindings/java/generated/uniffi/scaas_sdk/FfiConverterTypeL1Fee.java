package uniffi.scaas_sdk;


public enum FfiConverterTypeL1Fee implements FfiConverterRustBuffer<L1Fee> {
    INSTANCE;

    @Override
    public L1Fee read(java.nio.ByteBuffer buf) {
        try {
            return L1Fee.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(L1Fee value) {
        return 4L;
    }

    @Override
    public void write(L1Fee value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





