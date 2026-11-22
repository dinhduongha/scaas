package uniffi.scaas_sdk;


public enum FfiConverterTypeRegistrationBlob implements FfiConverterRustBuffer<RegistrationBlob> {
  INSTANCE;

  @Override
  public RegistrationBlob read(java.nio.ByteBuffer buf) {
    return new RegistrationBlob(
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterTypeRegisterArgs.INSTANCE.read(buf),
      FfiConverterOptionalTypeKemRecord.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RegistrationBlob value) {
      return (
            FfiConverterInteger.INSTANCE.allocationSize(value.v()) +
            FfiConverterString.INSTANCE.allocationSize(value.ua()) +
            FfiConverterShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterTypeRegisterArgs.INSTANCE.allocationSize(value.args()) +
            FfiConverterOptionalTypeKemRecord.INSTANCE.allocationSize(value.kem())
      );
  }

  @Override
  public void write(RegistrationBlob value, java.nio.ByteBuffer buf) {
      FfiConverterInteger.INSTANCE.write(value.v(), buf);
      FfiConverterString.INSTANCE.write(value.ua(), buf);
      FfiConverterShort.INSTANCE.write(value.kind(), buf);
      FfiConverterTypeRegisterArgs.INSTANCE.write(value.args(), buf);
      FfiConverterOptionalTypeKemRecord.INSTANCE.write(value.kem(), buf);
  }
}



