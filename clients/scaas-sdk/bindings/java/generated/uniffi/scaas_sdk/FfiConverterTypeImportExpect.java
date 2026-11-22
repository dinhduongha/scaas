package uniffi.scaas_sdk;


public enum FfiConverterTypeImportExpect implements FfiConverterRustBuffer<ImportExpect> {
  INSTANCE;

  @Override
  public ImportExpect read(java.nio.ByteBuffer buf) {
    return new ImportExpect(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterTypeKeyRef.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ImportExpect value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.payee()) +
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.payer())
      );
  }

  @Override
  public void write(ImportExpect value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.payee(), buf);
      FfiConverterTypeKeyRef.INSTANCE.write(value.payer(), buf);
  }
}



