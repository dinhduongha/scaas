package uniffi.scaas_sdk;


public enum FfiConverterTypeOpItem implements FfiConverterRustBuffer<OpItem> {
  INSTANCE;

  @Override
  public OpItem read(java.nio.ByteBuffer buf) {
    return new OpItem(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(OpItem value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.op()) +
            FfiConverterString.INSTANCE.allocationSize(value.entry()) +
            FfiConverterString.INSTANCE.allocationSize(value.state()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.landedBlock())
      );
  }

  @Override
  public void write(OpItem value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.op(), buf);
      FfiConverterString.INSTANCE.write(value.entry(), buf);
      FfiConverterString.INSTANCE.write(value.state(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.landedBlock(), buf);
  }
}



