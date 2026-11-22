package uniffi.scaas_sdk;


public enum FfiConverterTypeDeriveChild implements FfiConverterRustBuffer<DeriveChild> {
  INSTANCE;

  @Override
  public DeriveChild read(java.nio.ByteBuffer buf) {
    return new DeriveChild(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(DeriveChild value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.parent()) +
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(DeriveChild value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.parent(), buf);
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



