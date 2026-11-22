package uniffi.scaas_sdk;


public enum FfiConverterTypeNewSeed implements FfiConverterRustBuffer<NewSeed> {
  INSTANCE;

  @Override
  public NewSeed read(java.nio.ByteBuffer buf) {
    return new NewSeed(
      FfiConverterTypeSeedInfo.INSTANCE.read(buf),
      FfiConverterTypeSeedBackup.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NewSeed value) {
      return (
            FfiConverterTypeSeedInfo.INSTANCE.allocationSize(value.info()) +
            FfiConverterTypeSeedBackup.INSTANCE.allocationSize(value.backup())
      );
  }

  @Override
  public void write(NewSeed value, java.nio.ByteBuffer buf) {
      FfiConverterTypeSeedInfo.INSTANCE.write(value.info(), buf);
      FfiConverterTypeSeedBackup.INSTANCE.write(value.backup(), buf);
  }
}



