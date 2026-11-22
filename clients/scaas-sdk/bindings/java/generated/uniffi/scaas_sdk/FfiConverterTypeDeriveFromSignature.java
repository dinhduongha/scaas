package uniffi.scaas_sdk;


public enum FfiConverterTypeDeriveFromSignature implements FfiConverterRustBuffer<DeriveFromSignature> {
  INSTANCE;

  @Override
  public DeriveFromSignature read(java.nio.ByteBuffer buf) {
    return new DeriveFromSignature(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(DeriveFromSignature value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterString.INSTANCE.allocationSize(value.account()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.set()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.signature1()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.signature2()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.derivationPassphrase()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(DeriveFromSignature value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterString.INSTANCE.write(value.account(), buf);
      FfiConverterInteger.INSTANCE.write(value.set(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.signature1(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.signature2(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.derivationPassphrase(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



