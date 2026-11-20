package uniffi.scaas_sdk;


public enum FfiConverterTypeImportWords implements FfiConverterRustBuffer<ImportWords> {
  INSTANCE;

  @Override
  public ImportWords read(java.nio.ByteBuffer buf) {
    return new ImportWords(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf),
      FfiConverterTypeSecretBytes.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ImportWords value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.words()) +
            FfiConverterTypeSecretBytes.INSTANCE.allocationSize(value.vaultPassphrase())
      );
  }

  @Override
  public void write(ImportWords value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.words(), buf);
      FfiConverterTypeSecretBytes.INSTANCE.write(value.vaultPassphrase(), buf);
  }
}



