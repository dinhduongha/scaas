package uniffi.scaas_sdk;


public enum FfiConverterTypeSePublic implements FfiConverterRustBuffer<SePublic> {
  INSTANCE;

  @Override
  public SePublic read(java.nio.ByteBuffer buf) {
    return new SePublic(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SePublic value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.handle()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.keyData())
      );
  }

  @Override
  public void write(SePublic value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.handle(), buf);
      FfiConverterByteArray.INSTANCE.write(value.keyData(), buf);
  }
}



