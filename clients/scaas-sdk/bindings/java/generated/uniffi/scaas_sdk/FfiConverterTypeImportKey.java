package uniffi.scaas_sdk;


public enum FfiConverterTypeImportKey implements FfiConverterRustBuffer<ImportKey> {
  INSTANCE;

  @Override
  public ImportKey read(java.nio.ByteBuffer buf) {
    return new ImportKey(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ImportKey value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.secret()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(ImportKey value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.secret(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



