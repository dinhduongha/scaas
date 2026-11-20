package uniffi.scaas_sdk;


public enum FfiConverterTypeHistoryPage implements FfiConverterRustBuffer<HistoryPage> {
  INSTANCE;

  @Override
  public HistoryPage read(java.nio.ByteBuffer buf) {
    return new HistoryPage(
      FfiConverterSequenceTypeHistoryItem.INSTANCE.read(buf),
      FfiConverterSequenceTypeOpItem.INSTANCE.read(buf),
      FfiConverterOptionalTypeCursor.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(HistoryPage value) {
      return (
            FfiConverterSequenceTypeHistoryItem.INSTANCE.allocationSize(value.items()) +
            FfiConverterSequenceTypeOpItem.INSTANCE.allocationSize(value.ops()) +
            FfiConverterOptionalTypeCursor.INSTANCE.allocationSize(value.next())
      );
  }

  @Override
  public void write(HistoryPage value, java.nio.ByteBuffer buf) {
      FfiConverterSequenceTypeHistoryItem.INSTANCE.write(value.items(), buf);
      FfiConverterSequenceTypeOpItem.INSTANCE.write(value.ops(), buf);
      FfiConverterOptionalTypeCursor.INSTANCE.write(value.next(), buf);
  }
}



