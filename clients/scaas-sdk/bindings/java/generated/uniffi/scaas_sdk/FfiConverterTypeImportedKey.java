package uniffi.scaas_sdk;


public enum FfiConverterTypeImportedKey implements FfiConverterRustBuffer<ImportedKey> {
  INSTANCE;

  @Override
  public ImportedKey read(java.nio.ByteBuffer buf) {
    return new ImportedKey(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ImportedKey value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.index())
      );
  }

  @Override
  public void write(ImportedKey value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterInteger.INSTANCE.write(value.index(), buf);
  }
}



