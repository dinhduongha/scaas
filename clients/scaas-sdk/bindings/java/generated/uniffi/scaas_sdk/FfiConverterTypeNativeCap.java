package uniffi.scaas_sdk;


public enum FfiConverterTypeNativeCap implements FfiConverterRustBuffer<NativeCap> {
  INSTANCE;

  @Override
  public NativeCap read(java.nio.ByteBuffer buf) {
    return new NativeCap(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NativeCap value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.max())
      );
  }

  @Override
  public void write(NativeCap value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.max(), buf);
  }
}



