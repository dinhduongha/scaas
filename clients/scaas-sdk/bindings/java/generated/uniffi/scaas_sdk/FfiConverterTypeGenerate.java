package uniffi.scaas_sdk;


public enum FfiConverterTypeGenerate implements FfiConverterRustBuffer<Generate> {
  INSTANCE;

  @Override
  public Generate read(java.nio.ByteBuffer buf) {
    return new Generate(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Generate value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(Generate value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



