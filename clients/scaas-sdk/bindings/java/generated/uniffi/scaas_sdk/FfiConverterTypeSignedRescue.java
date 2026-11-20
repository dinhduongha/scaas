package uniffi.scaas_sdk;


public enum FfiConverterTypeSignedRescue implements FfiConverterRustBuffer<SignedRescue> {
  INSTANCE;

  @Override
  public SignedRescue read(java.nio.ByteBuffer buf) {
    return new SignedRescue(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SignedRescue value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.digest()) +
            FfiConverterString.INSTANCE.allocationSize(value.signature())
      );
  }

  @Override
  public void write(SignedRescue value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.digest(), buf);
      FfiConverterString.INSTANCE.write(value.signature(), buf);
  }
}



