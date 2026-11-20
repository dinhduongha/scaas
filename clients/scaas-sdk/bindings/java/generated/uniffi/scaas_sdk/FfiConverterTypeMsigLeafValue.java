package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigLeafValue implements FfiConverterRustBuffer<MsigLeafValue> {
  INSTANCE;

  @Override
  public MsigLeafValue read(java.nio.ByteBuffer buf) {
    return new MsigLeafValue(
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterTypeSlotKey.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigLeafValue value) {
      return (
            FfiConverterShort.INSTANCE.allocationSize(value.index()) +
            FfiConverterTypeSlotKey.INSTANCE.allocationSize(value.key())
      );
  }

  @Override
  public void write(MsigLeafValue value, java.nio.ByteBuffer buf) {
      FfiConverterShort.INSTANCE.write(value.index(), buf);
      FfiConverterTypeSlotKey.INSTANCE.write(value.key(), buf);
  }
}



