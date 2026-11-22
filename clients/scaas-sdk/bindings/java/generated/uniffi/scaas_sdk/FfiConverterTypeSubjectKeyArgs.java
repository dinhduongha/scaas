package uniffi.scaas_sdk;


public enum FfiConverterTypeSubjectKeyArgs implements FfiConverterRustBuffer<SubjectKeyArgs> {
  INSTANCE;

  @Override
  public SubjectKeyArgs read(java.nio.ByteBuffer buf) {
    return new SubjectKeyArgs(
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SubjectKeyArgs value) {
      return (
            FfiConverterByte.INSTANCE.allocationSize(value.kind()) +
            FfiConverterString.INSTANCE.allocationSize(value.x()) +
            FfiConverterString.INSTANCE.allocationSize(value.y()) +
            FfiConverterString.INSTANCE.allocationSize(value.rpIdHash()) +
            FfiConverterString.INSTANCE.allocationSize(value.originHash())
      );
  }

  @Override
  public void write(SubjectKeyArgs value, java.nio.ByteBuffer buf) {
      FfiConverterByte.INSTANCE.write(value.kind(), buf);
      FfiConverterString.INSTANCE.write(value.x(), buf);
      FfiConverterString.INSTANCE.write(value.y(), buf);
      FfiConverterString.INSTANCE.write(value.rpIdHash(), buf);
      FfiConverterString.INSTANCE.write(value.originHash(), buf);
  }
}



