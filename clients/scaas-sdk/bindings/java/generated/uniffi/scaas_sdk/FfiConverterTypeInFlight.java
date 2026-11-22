package uniffi.scaas_sdk;


public enum FfiConverterTypeInFlight implements FfiConverterRustBuffer<InFlight> {
    INSTANCE;

    @Override
    public InFlight read(java.nio.ByteBuffer buf) {
        try {
            return InFlight.values()[buf.getInt() - 1];
        } catch (java.lang.IndexOutOfBoundsException e) {
            throw new java.lang.RuntimeException("invalid enum value, something is very wrong!!", e);
        }
    }

    @Override
    public long allocationSize(InFlight value) {
        return 4L;
    }

    @Override
    public void write(InFlight value, java.nio.ByteBuffer buf) {
        buf.putInt(value.ordinal() + 1);
    }
}





