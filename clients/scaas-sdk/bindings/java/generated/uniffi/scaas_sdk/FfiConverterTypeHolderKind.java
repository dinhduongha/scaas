package uniffi.scaas_sdk;


public enum FfiConverterTypeHolderKind implements FfiConverterRustBuffer<HolderKind> {
    INSTANCE;

    @Override
    public HolderKind read(java.nio.ByteBuffer buf) {
        try {
            return HolderKind.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(HolderKind value) {
        return 4L;
    }

    @Override
    public void write(HolderKind value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





