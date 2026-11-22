package uniffi.scaas_sdk;


public enum FfiConverterTypeAttrsArgs implements FfiConverterRustBuffer<AttrsArgs> {
  INSTANCE;

  @Override
  public AttrsArgs read(java.nio.ByteBuffer buf) {
    return new AttrsArgs(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeKemArgs.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AttrsArgs value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.pqzKey()) +
            FfiConverterString.INSTANCE.allocationSize(value.pqzPopHash()) +
            FfiConverterTypeKemArgs.INSTANCE.allocationSize(value.kem()) +
            FfiConverterString.INSTANCE.allocationSize(value.kemPkHash())
      );
  }

  @Override
  public void write(AttrsArgs value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.pqzKey(), buf);
      FfiConverterString.INSTANCE.write(value.pqzPopHash(), buf);
      FfiConverterTypeKemArgs.INSTANCE.write(value.kem(), buf);
      FfiConverterString.INSTANCE.write(value.kemPkHash(), buf);
  }
}



