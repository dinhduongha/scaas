package uniffi.scaas_sdk;


public enum FfiConverterTypeDeriveFromKey implements FfiConverterRustBuffer<DeriveFromKey> {
  INSTANCE;

  @Override
  public DeriveFromKey read(java.nio.ByteBuffer buf) {
    return new DeriveFromKey(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(DeriveFromKey value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.key()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.derivationPassphrase()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.index()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(DeriveFromKey value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.key(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.derivationPassphrase(), buf);
      FfiConverterInteger.INSTANCE.write(value.index(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



