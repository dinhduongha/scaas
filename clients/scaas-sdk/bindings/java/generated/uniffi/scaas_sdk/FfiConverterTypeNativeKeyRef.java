package uniffi.scaas_sdk;


public enum FfiConverterTypeNativeKeyRef implements FfiConverterRustBuffer<NativeKeyRef> {
  INSTANCE;

  @Override
  public NativeKeyRef read(java.nio.ByteBuffer buf) {
    return new NativeKeyRef(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NativeKeyRef value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.index()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.change()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.coinType()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.path())
      );
  }

  @Override
  public void write(NativeKeyRef value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterInteger.INSTANCE.write(value.index(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.change(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.coinType(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.path(), buf);
  }
}



