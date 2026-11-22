package uniffi.scaas_sdk;


public enum FfiConverterTypeSeedInfo implements FfiConverterRustBuffer<SeedInfo> {
  INSTANCE;

  @Override
  public SeedInfo read(java.nio.ByteBuffer buf) {
    return new SeedInfo(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SeedInfo value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.id()) +
            FfiConverterString.INSTANCE.allocationSize(value.label()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.words()) +
            FfiConverterString.INSTANCE.allocationSize(value.origin()) +
            FfiConverterString.INSTANCE.allocationSize(value._class()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.warnings()) +
            FfiConverterString.INSTANCE.allocationSize(value.backup()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.unlocked()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.verified())
      );
  }

  @Override
  public void write(SeedInfo value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.id(), buf);
      FfiConverterString.INSTANCE.write(value.label(), buf);
      FfiConverterInteger.INSTANCE.write(value.words(), buf);
      FfiConverterString.INSTANCE.write(value.origin(), buf);
      FfiConverterString.INSTANCE.write(value._class(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.warnings(), buf);
      FfiConverterString.INSTANCE.write(value.backup(), buf);
      FfiConverterBoolean.INSTANCE.write(value.unlocked(), buf);
      FfiConverterBoolean.INSTANCE.write(value.verified(), buf);
  }
}



