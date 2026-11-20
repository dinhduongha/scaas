package uniffi.scaas_sdk;


public enum FfiConverterTypePresence implements FfiConverterRustBuffer<Presence> {
    INSTANCE;

    @Override
    public Presence read(java.nio.ByteBuffer buf) {
        try {
            return Presence.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(Presence value) {
        return 4L;
    }

    @Override
    public void write(Presence value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





