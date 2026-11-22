package uniffi.scaas_sdk;


public enum FfiConverterTypeGasPerItem implements FfiConverterRustBuffer<GasPerItem> {
  INSTANCE;

  @Override
  public GasPerItem read(java.nio.ByteBuffer buf) {
    return new GasPerItem(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasPerItem value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.item()) +
            FfiConverterLong.INSTANCE.allocationSize(value.gas()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.regular()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.measuredMax())
      );
  }

  @Override
  public void write(GasPerItem value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.item(), buf);
      FfiConverterLong.INSTANCE.write(value.gas(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.regular(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.measuredMax(), buf);
  }
}



