package uniffi.scaas_sdk;


public enum FfiConverterTypeWallet implements FfiConverter<Wallet, java.lang.Long> {
    INSTANCE;

    @Override
    public java.lang.Long lower(Wallet value) {
        return value.uniffiCloneHandle();
    }

    @Override
    public Wallet lift(java.lang.Long value) {
        return new Wallet(UniffiWithHandle.INSTANCE, value);
    }

    @Override
    public Wallet read(java.nio.ByteBuffer buf) {
        // The Rust code always writes handles as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong());
    }

    @Override
    public long allocationSize(Wallet value) {
        return 8L;
    }

    @Override
    public void write(Wallet value, java.nio.ByteBuffer buf) {
        // The Rust code always expects handles written as 8 bytes,
        // and will fail to compile if they don't fit.
        buf.putLong(lower(value));
    }
}



